//! `aitm-plugin-maprules` — the Map Local / Map Remote feature (M6 spec §5).
//!
//! One first-party plugin registers the unified `map.*` command set
//! (`map.add`/`map.list`/`map.remove`) over a shared rule table, and — for Map
//! Local — serves a confined local file as the response for matching requests.
//!
//! **Map Local** (this crate): on a request event, a matching `local` rule reads
//! a file (confined to the constructor-supplied map root), builds an
//! [`HttpResponse`] (default status 200, content-type inferred from the
//! extension unless the rule overrides it), calls [`FlowCtx::set_response`] and
//! returns [`Verdict::Halt`] — a pure short-circuit: **no upstream call, no scope
//! guard** (Map Local performs no egress). Path confinement is enforced at
//! `map.add` (the path is canonicalized and must stay under the map root), the
//! confinement analog of the SSRF guard.
//!
//! **Map Remote** ([`MapAction::Remote`]/[`RemoteTarget`]): on a request event, a
//! matching `remote` rule rewrites the request's scheme/authority/path (and the
//! `Host` header) in place so it goes upstream to a different host. Because that is
//! active egress to a (possibly new) host, the plugin **must** pass the rewritten
//! authority through [`ScopeRateGuard::check_active`] *before* altering the request
//! — the deny-by-default point for Map Remote. An out-of-scope target is refused:
//! the request is left untouched and the flow is short-circuited with an error
//! response, so the original is not forwarded to the new host (or the old one).
//! `FlowCtx` does not carry the guard, so the plugin holds its own
//! constructor-injected handle.
//!
//! **Agent gate:** `map.add`/`map.remove` shape live traffic, so an agent
//! (`Frontend::Mcp`) frontend is refused unless `maps.allow_agent_authoring` is
//! set (default off, via the constructor), mirroring `scope.allow_agent_widen`.
//! `map.list` is read-only and never gated.

pub mod action;

pub use action::{MapAction, MapKind, RemoteTarget};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use aitm_core::{
    Authority, Body, Command, CommandHost, Event, Flow, FlowCtx, Frontend, HeaderMap, HttpResponse,
    HttpVersion, ParamDef, ParamSchema, Params, Plugin, Registry, ScopeRateGuard, TypeDesc, Value,
    Verdict,
};
use aitm_rules::{compile, CompiledRule, Phase, Rule};

use crate::action::{action_to_value, condition_to_value, content_type_for, parse_map};

/// Flow mark set once a Map Remote rewrite has been applied to a request. The proxy
/// fires both `Event::RequestHeaders` and `Event::Request` for one request; a
/// URL/path-matched remote rule still matches the (path-unchanged) flow on the
/// second event, so without this mark its rewritten authority would pass
/// [`ScopeRateGuard::check_active`] twice — double-charging the rate budget. The
/// mark makes the guard consultation idempotent: once marked, the flow is skipped.
const MAP_REMOTE_MARK: &str = "map-remote";

/// Cap on a Map Local file served as a response body. A larger file is refused
/// (502) before it is read, so a mapped file cannot exhaust memory per request —
/// mirrors the default message-body cap ([`aitm_core::LimitConfig::max_body_bytes`]).
const MAX_MAP_LOCAL_BYTES: u64 = 10 * 1024 * 1024;

/// One stored Map rule: its id, kind, compiled match condition, action, and —
/// for a `local` rule — the resolved, confinement-checked file path.
struct MapEntry {
    id: String,
    kind: MapKind,
    rule: CompiledRule,
    action: MapAction,
    /// The canonical file path a `local` rule serves (confined at `map.add`).
    local_file: Option<PathBuf>,
}

/// State the plugin (which serves Map Local and Map Remote on events) shares with
/// its commands (which author the rules). The map root, agent gate and scope guard
/// are fixed at construction.
struct Shared {
    maps: Mutex<Vec<MapEntry>>,
    map_root: PathBuf,
    allow_agent_authoring: bool,
    /// Cap on a Map Local file served as a response body (default
    /// [`MAX_MAP_LOCAL_BYTES`]); a larger file is refused with a 502 before it is
    /// read, so a mapped file cannot exhaust memory per request.
    max_local_bytes: u64,
    next_id: AtomicU64,
    /// The one scope/rate guard every active egress passes. Map Remote redirects
    /// to a new host, so it calls [`ScopeRateGuard::check_active`] on the rewritten
    /// authority before touching the request. `FlowCtx` does not carry the guard,
    /// so the plugin holds its own constructor-injected handle.
    guard: Arc<dyn ScopeRateGuard>,
}

impl Shared {
    fn lock_maps(&self) -> std::sync::MutexGuard<'_, Vec<MapEntry>> {
        self.maps.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn mint_id(&self) -> String {
        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        format!("map-{n}")
    }
}

/// The Map plugin: registers `map.add`/`map.list`/`map.remove` and serves Map
/// Local on request events.
pub struct MapRulesPlugin {
    shared: Arc<Shared>,
}

impl MapRulesPlugin {
    /// Build the plugin over `map_root` (the directory Map Local files are
    /// confined to) with the agent-authoring gate `allow_agent_authoring`
    /// (default off at the call site) and the shared scope `guard` Map Remote
    /// redirects pass. `Config.maps` and the proxy's `guard()` supply all three.
    pub fn new(
        map_root: PathBuf,
        allow_agent_authoring: bool,
        guard: Arc<dyn ScopeRateGuard>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                maps: Mutex::new(Vec::new()),
                map_root,
                allow_agent_authoring,
                max_local_bytes: MAX_MAP_LOCAL_BYTES,
                next_id: AtomicU64::new(1),
                guard,
            }),
        }
    }

    /// Set the maximum size of a Map Local file served as a response body (default
    /// [`MAX_MAP_LOCAL_BYTES`]).
    pub fn with_max_local_bytes(mut self, max: u64) -> Self {
        // The plugin is not shared yet at construction, so this unwrap is infallible.
        Arc::get_mut(&mut self.shared)
            .expect("plugin not yet shared")
            .max_local_bytes = max;
        self
    }
}

impl Plugin for MapRulesPlugin {
    fn name(&self) -> &str {
        "maprules"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(MapAdd {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(MapList {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(MapRemove {
            shared: self.shared.clone(),
        }));
    }

    /// Serve Map Local and Map Remote. On a request event the first matching rule
    /// wins: a `local` rule answers the client from its file and halts the chain
    /// (no upstream, no guard); a `remote` rule rewrites the request target after
    /// its rewritten authority passes the scope guard, then lets it continue
    /// upstream — or, when the target is out of scope, refuses it with an error
    /// response (the request is left untouched and not forwarded). Idempotent: once
    /// a response is present (this plugin's or another's) nothing is re-served.
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if !matches!(ev, Event::RequestHeaders(_) | Event::Request(_)) {
            return Verdict::Continue;
        }
        match ctx.flow() {
            // A fresh HTTP flow with no response yet, not already rewritten. Once a
            // Map Remote rewrite has marked the flow, skip it: re-matching on the
            // second request event would charge the scope guard a second time.
            Flow::Http(f)
                if f.response.is_none()
                    && !f.metadata.marks.iter().any(|m| m == MAP_REMOTE_MARK) => {}
            // A non-HTTP flow, one already answered, or one already rewritten.
            _ => return Verdict::Continue,
        }

        let guard = self.shared.guard.as_ref();
        let maps = self.shared.lock_maps();
        let decision = maps.iter().find_map(|entry| {
            if !entry.rule.matches(ctx.flow(), Phase::Request, None) {
                return None;
            }
            Some(match &entry.action {
                MapAction::Local { .. } => Decision::Serve(local_response(
                    &self.shared.map_root,
                    self.shared.max_local_bytes,
                    entry,
                )),
                MapAction::Remote { to } => decide_remote(to, guard),
            })
        });
        drop(maps);

        match decision {
            // Map Local, or a refused Map Remote: answer and halt, no upstream.
            Some(Decision::Serve(resp)) => {
                ctx.set_response(resp);
                Verdict::Halt
            }
            // An in-scope Map Remote: rewrite the target and continue upstream.
            Some(Decision::Rewrite(plan)) => {
                apply_remote(ctx.flow_mut(), &plan);
                Verdict::Continue
            }
            None => Verdict::Continue,
        }
    }
}

/// What a matched rule resolves to once the guard has (for Map Remote) had its say.
enum Decision {
    /// Answer the client with this response and halt — no upstream. Used by Map
    /// Local and by a Map Remote refusal.
    Serve(HttpResponse),
    /// Rewrite the request target in place, then let it continue upstream (an
    /// allowed Map Remote redirect).
    Rewrite(RemotePlan),
}

/// A computed Map Remote rewrite. A `None` field keeps the request's original
/// value; `authority` is always replaced (and is what the scope guard checks).
struct RemotePlan {
    scheme: Option<String>,
    authority: String,
    path: Option<String>,
}

/// Resolve a `remote` rule: compute the rewrite, then gate it on the scope guard.
/// A malformed target, or a target the guard refuses, becomes a visible error
/// response (the request is never rewritten, so it is not forwarded to that host).
fn decide_remote(to: &RemoteTarget, guard: &dyn ScopeRateGuard) -> Decision {
    let plan = match plan_remote(to) {
        Ok(plan) => plan,
        Err(err) => return Decision::Serve(text_response(502, &format!("map remote: {err}"))),
    };
    // Deny-by-default: the rewritten authority is active egress to a new host, so
    // it must pass the one guard. The permit is only a pre-flight — the real
    // egress later takes its own slot — so we drop it immediately.
    match guard.check_active(&plan.authority) {
        Ok(_) => Decision::Rewrite(plan),
        Err(err) => Decision::Serve(text_response(
            502,
            &format!("map remote: refused redirect to {} — {err}", plan.authority),
        )),
    }
}

/// Compute the rewrite a Map Remote target describes, validating the new authority
/// (a malformed target is refused rather than redirected). The target fully
/// determines the rewrite, so the original request is not consulted here.
fn plan_remote(to: &RemoteTarget) -> anyhow::Result<RemotePlan> {
    match to {
        RemoteTarget::Host { authority, scheme } => {
            validate_authority(authority)?;
            Ok(RemotePlan {
                scheme: scheme.clone(),
                authority: authority.clone(),
                // A bare host swap keeps the original path.
                path: None,
            })
        }
        RemoteTarget::Url(url) => {
            let (scheme, authority, path) = split_url(url)?;
            Ok(RemotePlan {
                scheme: Some(scheme),
                authority,
                path: Some(path),
            })
        }
    }
}

/// Validate a redirect authority (`host[:port]`); the guard-checked, request-bound
/// value must be a well-formed authority.
fn validate_authority(authority: &str) -> anyhow::Result<()> {
    Authority::parse_with_default(authority, 0)
        .map_err(|err| anyhow::anyhow!("invalid redirect authority {authority:?}: {err}"))?;
    Ok(())
}

/// Split an absolute `scheme://authority/path` redirect URL into its parts. The
/// target is operator-supplied (CLI/config), so a minimal split suffices; the
/// authority is validated so a malformed URL is refused rather than redirected.
fn split_url(url: &str) -> anyhow::Result<(String, String, String)> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        anyhow::anyhow!("redirect url {url:?} must be absolute (scheme://host/path)")
    })?;
    if scheme.is_empty() {
        anyhow::bail!("redirect url {url:?} is missing a scheme");
    }
    // Map Remote redirects to another HTTP origin; restrict the scheme so a
    // non-web scheme (e.g. `file`, `gopher`) cannot be forwarded upstream.
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        anyhow::bail!("redirect url {url:?} scheme must be http or https, got {scheme:?}");
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    validate_authority(authority)?;
    // The rewritten path reaches the upstream request line verbatim (the wire
    // encoder formats `"{method} {path} HTTP/1.1"` with no CR/LF strip), so a
    // space or control byte in it would smuggle a header or a second request.
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        anyhow::bail!(
            "redirect url {url:?} has a space or control character in its path; percent-encode it"
        );
    }
    Ok((scheme.to_string(), authority.to_string(), path.to_string()))
}

/// Apply a computed rewrite to the request in place, keeping the `Host` header in
/// step with the new authority so the new upstream routes the redirected request.
fn apply_remote(flow: &mut Flow, plan: &RemotePlan) {
    let Flow::Http(f) = flow else {
        return;
    };
    if let Some(scheme) = &plan.scheme {
        f.request.scheme = scheme.clone();
    }
    f.request.authority = plan.authority.clone();
    if let Some(path) = &plan.path {
        f.request.path = path.clone();
    }
    // `HeaderMap::set` appends (multimap semantics), so drop the stale `Host`
    // first to replace it rather than leave the old host ahead of the new one.
    f.request.headers.remove("host");
    f.request.headers.set("host", &plan.authority);
    // Mark the rewrite so the next request event does not re-match and re-charge
    // the scope guard for this same request.
    if !f.metadata.marks.iter().any(|m| m == MAP_REMOTE_MARK) {
        f.metadata.marks.push(MAP_REMOTE_MARK.to_string());
    }
}

/// Build the response a `local` rule serves. Re-confines the file and caps its
/// size at serve time (not just at `map.add`), then reads it; any failure still
/// short-circuits (Map Local never falls through to upstream) with a 502 so the
/// miss is visible rather than silently leaking the request egress.
fn local_response(map_root: &Path, max_bytes: u64, entry: &MapEntry) -> HttpResponse {
    let (status, headers) = match &entry.action {
        MapAction::Local {
            status, headers, ..
        } => (status.unwrap_or(200), headers.as_slice()),
        // `find_map` only calls this for `MapKind::Local` entries.
        MapAction::Remote { .. } => unreachable!("local_response called for a remote map"),
    };
    let path = entry
        .local_file
        .as_deref()
        .expect("a local map always resolves a file at map.add");

    match read_confined(map_root, max_bytes, path) {
        Ok(bytes) => http_response(status, headers, path, bytes),
        Err(err) => text_response(502, &format!("map local: {err}")),
    }
}

/// Re-confine and size-cap a Map Local file at serve time, then read it. The path
/// was confined at `map.add`, but the file it names could since have been replaced
/// by a symlink escaping the root (a TOCTOU window), so re-canonicalize and re-check
/// `starts_with` the map root on every serve; refuse a file over the size cap before
/// reading it.
fn read_confined(map_root: &Path, max_bytes: u64, path: &Path) -> anyhow::Result<Vec<u8>> {
    let root = map_root.canonicalize().map_err(|err| {
        anyhow::anyhow!("map root {} is not accessible: {err}", map_root.display())
    })?;
    let canonical = path
        .canonicalize()
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", path.display()))?;
    if !canonical.starts_with(&root) {
        anyhow::bail!(
            "{} escapes the map root {}",
            canonical.display(),
            root.display()
        );
    }
    let len = std::fs::metadata(&canonical)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", canonical.display()))?
        .len();
    if len > max_bytes {
        anyhow::bail!(
            "{} is {len} bytes, over the {max_bytes}-byte serve limit",
            canonical.display()
        );
    }
    std::fs::read(&canonical)
        .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", canonical.display()))
}

/// A plain-text response, used for a Map Local read miss and a Map Remote scope
/// refusal, so the failure is visible to the client rather than silently leaking
/// or forwarding the request.
fn text_response(status: u16, message: &str) -> HttpResponse {
    http_response(
        status,
        &[(
            "content-type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        Path::new("error.txt"),
        message.as_bytes().to_vec(),
    )
}

/// Assemble an [`HttpResponse`] from a status, the rule's header overrides, the
/// served file (for content-type inference), and the body bytes.
fn http_response(
    status: u16,
    overrides: &[(String, String)],
    path: &Path,
    bytes: Vec<u8>,
) -> HttpResponse {
    let mut headers = HeaderMap::new();
    let overrides_content_type = overrides
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    if !overrides_content_type {
        headers.set("content-type", content_type_for(path));
    }
    for (name, value) in overrides {
        headers.set(name, value);
    }
    headers.set("content-length", &bytes.len().to_string());
    HttpResponse {
        status,
        version: HttpVersion::Http11,
        headers,
        trailers: HeaderMap::new(),
        body: Body::Bytes(bytes),
        timestamp: SystemTime::now(),
    }
}

/// Refuse an authoring command from an agent frontend unless the gate is open.
/// `map.add`/`map.remove` shape live traffic, so they mirror `scope.add`'s gate.
fn check_agent_gate(host: &CommandHost, allow_agent_authoring: bool) -> anyhow::Result<()> {
    if host.frontend() != Frontend::Cli && !allow_agent_authoring {
        anyhow::bail!(
            "map authoring refused: adding or removing maps from an agent frontend is disabled. \
             Set maps.allow_agent_authoring = true in the aitmproxy config to allow it, or author \
             the map from the human CLI."
        );
    }
    Ok(())
}

/// Resolve `rel` against `map_root` and confine it: the canonical target must
/// stay under the canonical map root, else the add is refused (no file is
/// served from outside the root). Checked at `map.add`, not at serve time.
fn confine(map_root: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    let root = map_root.canonicalize().map_err(|err| {
        anyhow::anyhow!(
            "map.add refused: the map root {} is not accessible: {err}",
            map_root.display()
        )
    })?;
    // `join` with an absolute `rel` replaces `root`; the prefix check below then
    // rejects it, so an absolute escaping path is refused too.
    let target = root.join(rel);
    let canonical = target.canonicalize().map_err(|err| {
        anyhow::anyhow!(
            "map.add refused: {rel:?} does not resolve to a readable file under the map root: {err}"
        )
    })?;
    if !canonical.starts_with(&root) {
        anyhow::bail!(
            "map.add refused: path {rel:?} escapes the map root {}",
            root.display()
        );
    }
    Ok(canonical)
}

/// The condition + action object params `map.add` declares.
fn map_object_param(name: &str, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
        required: true,
        description: description.to_string(),
    }
}

/// `map.add {kind, condition, action}` → `{id}`.
struct MapAdd {
    shared: Arc<Shared>,
}

impl Command for MapAdd {
    fn name(&self) -> &str {
        "map.add"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add a Map rule. kind \"local\" serves a confined local file as the \
                          response (a mock); kind \"remote\" rewrites the request target before \
                          upstream. Refused from an agent frontend unless \
                          maps.allow_agent_authoring is set."
                .into(),
            params: vec![
                ParamDef {
                    name: "kind".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "\"local\" or \"remote\".".into(),
                },
                map_object_param(
                    "condition",
                    "The shared match condition: {url:{wildcard|regex}, method, \
                     host:{exact|wildcard}, phase}. url is matched against the full request \
                     URL (scheme://host[:port]/path?query) and against the path alone; host \
                     against the authority.",
                ),
                map_object_param(
                    "action",
                    "local: {path, status?, headers?}. remote: {to:{url}|{authority, scheme?}}.",
                ),
            ],
            result: TypeDesc::Object(vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The stable id for map.remove.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        check_agent_gate(host, self.shared.allow_agent_authoring)?;

        let kind = args.get_str("kind")?;
        let condition = args.get_object("condition")?;
        let action = args.get_object("action")?;
        let parsed = parse_map(kind, condition, action)?;

        // Confine a local file at add time (no file is read from outside the root).
        let local_file = match &parsed.action {
            MapAction::Local { path, .. } => Some(confine(&self.shared.map_root, path)?),
            MapAction::Remote { .. } => None,
        };

        let id = self.shared.mint_id();
        // Compile the shared condition; a bad regex surfaces as this command's error.
        let rule = compile(Rule {
            id: id.clone(),
            name: None,
            enabled: true,
            condition: parsed.condition,
        })?;

        self.shared.lock_maps().push(MapEntry {
            id: id.clone(),
            kind: parsed.kind,
            rule,
            action: parsed.action,
            local_file,
        });

        Ok(Value::Object(
            [("id".to_string(), Value::Str(id))].into_iter().collect(),
        ))
    }
}

/// `map.list {}` → `{maps: [{id, kind, condition, action}]}`.
struct MapList {
    shared: Arc<Shared>,
}

impl Command for MapList {
    fn name(&self) -> &str {
        "map.list"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the configured Map rules.".into(),
            params: vec![],
            result: TypeDesc::Object(vec![ParamDef {
                name: "maps".into(),
                ty: TypeDesc::Array(Box::new(TypeDesc::Map(Box::new(TypeDesc::Any)))),
                required: true,
                description: "Each: {id, kind, condition, action}.".into(),
            }]),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let maps = self
            .shared
            .lock_maps()
            .iter()
            .map(|entry| {
                Value::Object(
                    [
                        ("id".to_string(), Value::Str(entry.id.clone())),
                        (
                            "kind".to_string(),
                            Value::Str(entry.kind.as_str().to_string()),
                        ),
                        (
                            "condition".to_string(),
                            condition_to_value(&entry.rule.rule().condition),
                        ),
                        ("action".to_string(), action_to_value(&entry.action)),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
            .collect();
        Ok(Value::Object(
            [("maps".to_string(), Value::Array(maps))]
                .into_iter()
                .collect(),
        ))
    }
}

/// `map.remove {id}` → `ok`.
struct MapRemove {
    shared: Arc<Shared>,
}

impl Command for MapRemove {
    fn name(&self) -> &str {
        "map.remove"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove a Map rule by id. Refused from an agent frontend unless \
                          maps.allow_agent_authoring is set."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The map id from map.add/map.list.".into(),
            }],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        check_agent_gate(host, self.shared.allow_agent_authoring)?;
        let id = args.get_str("id")?;
        let mut maps = self.shared.lock_maps();
        let before = maps.len();
        maps.retain(|entry| entry.id != id);
        if maps.len() == before {
            anyhow::bail!("map.remove: no map with id {id:?}");
        }
        Ok(Value::Str("ok".into()))
    }
}
