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
//! **Map Remote** ([`MapAction::Remote`]/[`RemoteTarget`]) is defined here so its
//! serve-side (the scope-guarded host rewrite) lands additively in Task 13; this
//! crate does not act on `remote` entries.
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
    Body, Command, CommandHost, Event, Flow, FlowCtx, Frontend, HeaderMap, HttpResponse,
    HttpVersion, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc, Value, Verdict,
};
use aitm_rules::{compile, CompiledRule, Phase, Rule};

use crate::action::{action_to_value, condition_to_value, content_type_for, parse_map};

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

/// State the plugin (which serves Map Local on events) shares with its commands
/// (which author the rules). The map root and agent gate are fixed at construction.
struct Shared {
    maps: Mutex<Vec<MapEntry>>,
    map_root: PathBuf,
    allow_agent_authoring: bool,
    next_id: AtomicU64,
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
    /// (default off at the call site). `Config.maps` wires both in Task 14.
    pub fn new(map_root: PathBuf, allow_agent_authoring: bool) -> Self {
        Self {
            shared: Arc::new(Shared {
                maps: Mutex::new(Vec::new()),
                map_root,
                allow_agent_authoring,
                next_id: AtomicU64::new(1),
            }),
        }
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

    /// Serve Map Local. On a request event, the first matching `local` rule
    /// answers the client from its file and halts the chain — no upstream, no
    /// guard. `remote` rules are left for Task 13. Idempotent: once a response is
    /// present (this plugin's or another's) nothing is re-served.
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if !matches!(ev, Event::RequestHeaders(_) | Event::Request(_)) {
            return Verdict::Continue;
        }
        match ctx.flow() {
            Flow::Http(f) if f.response.is_none() => {}
            // A non-HTTP flow or one already answered: nothing to serve.
            _ => return Verdict::Continue,
        }

        let maps = self.shared.lock_maps();
        let response = maps.iter().find_map(|entry| match entry.kind {
            MapKind::Local if entry.rule.matches(ctx.flow(), Phase::Request, None) => {
                Some(local_response(entry))
            }
            // Map Remote serve-side is Task 13; `remote` rules are inert here.
            _ => None,
        });
        drop(maps);

        match response {
            Some(resp) => {
                ctx.set_response(resp);
                Verdict::Halt
            }
            None => Verdict::Continue,
        }
    }
}

/// Build the response a `local` rule serves. Reads the confined file; a read
/// failure still short-circuits (Map Local never falls through to upstream) with
/// a 502 so the miss is visible rather than silently leaking the request egress.
fn local_response(entry: &MapEntry) -> HttpResponse {
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

    match std::fs::read(path) {
        Ok(bytes) => http_response(status, headers, path, bytes),
        Err(err) => http_response(
            502,
            &[(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            Path::new("error.txt"),
            format!("map local: cannot read {}: {err}", path.display()).into_bytes(),
        ),
    }
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
                     host:{exact|wildcard}, phase}. Matches the request target path and authority.",
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
