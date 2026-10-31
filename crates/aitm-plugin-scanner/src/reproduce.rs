//! Reproduce + record: turn a confirmed injection into a parameterized PoC
//! (`build_poc`) and persist a `FindingRecord` to the configured findings
//! store (`record_finding`).
//!
//! `build_poc` builds the PoC from the *mutated* request — the captured request
//! with the payload applied at the injection point — so replaying the PoC sends
//! the payload and can trigger `CheckDefinition::success_assertion`, the exact
//! assertion the live `confirm` judged the hit against. A recorded PoC and the
//! inject engine's own notion of "triggered" can therefore never drift apart.
//!
//! A PoC is shareable, so it must never carry a credential from the captured
//! request. [`StdPocBuilder`] masks credential headers and runs a text scrub
//! over the step's URL and body — a scrub that erases the inject payload at a
//! secret-named point and corrupts a JSON body — so `build_poc` re-derives the
//! URL and body from the mutated request and scrubs them, and the rest of what
//! it copies, itself (see `Scrubber`): every secret-named
//! header, query parameter, form field and JSON key becomes a required `{{var}}`
//! placeholder the runner must be given at run time, and every other value is
//! passed through `scrub_embedded` — URL userinfo stripped, then
//! [`aitm_core::redact::scrub_text_wide`], the wide reading of the same
//! vocabulary [`is_secret_name`] applies to a name, so a credential embedded in
//! an innocuously named value cannot slip past a narrower list.
//! `record_finding` is a thin
//! wrapper over [`aitm_findings::DiskFindingStore`]: the store itself scrubs
//! `title`/`notes` of credential material before anything reaches disk, and the
//! record's `target` is scrubbed here.

use std::collections::HashSet;

use aitm_core::redact::{scrub_text, scrub_text_wide};
use aitm_core::{Body, CommandHost, HttpFlow, HttpRequest};
use aitm_findings::{DiskFindingStore, FindingRecord, FindingStore};
use aitm_poc::{
    HttpStep, Poc, PocBuilder, PocInfo, PocSpec, Severity, StdPocBuilder, Step, Variable,
};

use crate::checks::{CheckDefinition, Payload, CLASS_OPEN_REDIRECT, CLASS_REFLECTED_XSS};
use crate::crawl::strip_userinfo;
use crate::discover::{is_secret_name, InjectionPoint};

/// Characters of the (network-supplied) injection-point name that feed the PoC
/// name and, through its slug, the PoC id. Bounded so the id always fits
/// `aitm_poc`'s 64-character limit: `<class> via <name>` is at most
/// `13 + 5 + 32` characters.
const MAX_POINT_NAME_CHARS: usize = 32;

/// Characters kept of a header / parameter name when it becomes a variable name.
const MAX_VAR_NAME_CHARS: usize = 48;

/// Distinct secret-named variables one PoC may declare. A hostile captured body
/// can carry a huge number of distinct `tokenN=` keys; past this many, every
/// further secret folds into the single [`CATCH_ALL_VAR`] instead of minting a
/// variable each (so a PoC carries at most `MAX_SECRET_VARS + 1` secret
/// variables, plus `target`).
const MAX_SECRET_VARS: usize = 64;

/// The one variable every secret past [`MAX_SECRET_VARS`] shares. Not a secret
/// name itself, so no real key can claim it before the cap is reached.
const CATCH_ALL_VAR: &str = "redacted";

/// Total percent-decode iterations applied to a form value before it is
/// scrubbed: the first is `form_urlencoded`'s own parse, the rest catch a secret
/// that was encoded more than once (`next=%252Fcb%253Fsid%253D…`).
const MAX_DECODE_PASSES: usize = 3;

/// The first `max` characters of `s`.
fn cap_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The request's URL with its concrete `scheme://authority` replaced by
/// `{{target}}` — the same parameterization [`StdPocBuilder`] applies when the
/// `target` variable is declared, so the PoC reproduces against any host. Path
/// and query are untouched (the caller scrubs them).
fn target_url(request: &HttpRequest) -> String {
    let url = format!("{}://{}{}", request.scheme, request.authority, request.path);
    let prefix = format!("{}://{}", request.scheme, request.authority);
    url.replacen(&prefix, "{{target}}", 1)
}

/// A buffered, non-empty request body as text (invalid UTF-8 replaced, never an
/// error); `None` for no body or one still streaming — what [`StdPocBuilder`]
/// puts in a step.
fn body_text(body: &Body) -> Option<String> {
    match body {
        Body::Bytes(bytes) if !bytes.is_empty() => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    }
}

/// The severity a built PoC carries for `class`: reflected-XSS is `Medium`,
/// open-redirect is `Low`. `None` for a class this mapping does not cover, so
/// [`build_poc`] chooses the default instead of this function inventing one; a
/// test pins that every `CheckDefinition::registered_classes` entry is covered.
fn severity_for(class: &str) -> Option<Severity> {
    match class {
        CLASS_REFLECTED_XSS => Some(Severity::Medium),
        CLASS_OPEN_REDIRECT => Some(Severity::Low),
        _ => None,
    }
}

/// Build a reproducible, credential-free PoC for one confirmed
/// `(point, payload)` hit.
///
/// The PoC is built from a clone of `flow` whose request has `payload` applied
/// at `point` (`crate::inject::mutate_request`), so the step carries the
/// payload and replaying it can satisfy `success`. `success` is `def`'s own
/// confirming assertion for `payload` — never re-derived. Declaring the
/// `target` variable up front makes `StdPocBuilder` replace the flow's concrete
/// scheme+authority with `{{target}}` in the step URL, so the PoC reproduces
/// against any host, not just the one it was captured from.
///
/// Errors when `point` is no longer present in `flow`'s request.
pub fn build_poc(
    flow: &HttpFlow,
    def: &CheckDefinition,
    point: &InjectionPoint,
    payload: &Payload,
) -> anyhow::Result<Poc> {
    let point_name = cap_chars(&point.name, MAX_POINT_NAME_CHARS);
    let request =
        crate::inject::mutate_request(&flow.request, point, &payload.value).ok_or_else(|| {
            anyhow::anyhow!(
                "build_poc: injection point `{point_name}` is not present in the flow's request"
            )
        })?;
    let mut mutated = flow.clone();
    mutated.request = request;

    let spec = PocSpec {
        info: PocInfo {
            name: format!("{} via {point_name}", def.class),
            // An unmapped class (none exists today: a test pins every
            // registered class) is `Info` rather than an invented severity.
            severity: severity_for(def.class).unwrap_or(Severity::Info),
            references: Vec::new(),
            tags: vec![def.class.to_string()],
            cwe: None,
            description: None,
            author: None,
            metadata: None,
        },
        variables: vec![Variable {
            name: "target".to_string(),
            default: None,
            description: "Base URL of the target".to_string(),
            required: true,
        }],
        success: def.success_assertion(payload),
    };
    let mut poc = StdPocBuilder.build(&mutated, spec)?;

    let mut scrubber = Scrubber::new(&payload.value);
    for step in &mut poc.steps {
        if let Step::Http(http) = step {
            scrubber.scrub_step(http, &mutated.request);
        }
    }
    // A name the builder already declared (a credential header it templated) is
    // not declared twice. O(1) per secret: a linear scan here would be quadratic
    // in the number of secret-named keys the captured request controls.
    let mut declared: HashSet<String> = poc.variables.iter().map(|v| v.name.clone()).collect();
    for var in scrubber.secrets {
        if declared.insert(var.name.clone()) {
            poc.variables.push(var);
        }
    }
    Ok(poc)
}

/// Strips request credentials out of a built [`HttpStep`].
///
/// Three layers, outermost first:
/// 1. a header, query parameter, form field or JSON key whose *name* reads as a
///    secret ([`is_secret_name`]) has its value replaced by a `{{var}}`
///    placeholder, and the variable is recorded in `secrets` (required, no
///    default) so the runner must be handed the credential at run time;
/// 2. every other value is decoded (repeatedly, for a form value) and passed
///    through [`scrub_embedded`], which catches a credential embedded in an
///    innocuously named value (`next=%2Fcb%3Fsid%3D…`, `X-Return-To: …?jwt=…`,
///    `Bearer …`) under the *same* name vocabulary layer 1 uses;
/// 3. a body that is neither a form nor JSON is passed through
///    [`scrub_embedded`] whole, and a `Referer` / `Referrer` header is cut back
///    to origin + path first (a PoC does not need its query).
///
/// `scrub_embedded` is applied per decoded component, never over the finished
/// string: a whole-string pass would corrupt the `{{var}}` placeholders
/// (`access_token={{access_token}}` reads as a `key=value` credential) and mask
/// the injected payload at a secret-named point.
///
/// `payload` is the scanner's own inert constant, never a request secret, so a
/// value equal to it is left alone — a redirect parameter named `return_token`
/// must still carry the payload or the PoC could not reproduce.
///
/// Distinct secret variables are tracked in `seen` (O(1) dedupe) and capped at
/// [`MAX_SECRET_VARS`]; see [`Scrubber::placeholder`].
struct Scrubber<'a> {
    payload: &'a str,
    secrets: Vec<Variable>,
    /// Names already declared in `secrets`.
    seen: HashSet<String>,
}

impl<'a> Scrubber<'a> {
    fn new(payload: &'a str) -> Self {
        Self {
            payload,
            secrets: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Scrub `step`, the [`StdPocBuilder`] step built from `request` (the
    /// mutated request).
    ///
    /// The step's `url` and `body` are *re-derived from `request`*, not read
    /// from `step`: the builder has already run [`scrub_text`] over both, and
    /// that text pass is unsafe here. It reads `return_token=<payload>` as a
    /// credential and erases the injected payload, and its `Bearer\s+\S+` rule
    /// swallows the closing `"}` of a JSON string value, leaving a body no JSON
    /// parser accepts. Re-deriving the two lets this scrubber do it
    /// structurally instead (payload exempt, JSON kept valid). The headers are
    /// the builder's own — it has already placeholdered the credential ones —
    /// and are scrubbed further below.
    fn scrub_step(&mut self, step: &mut HttpStep, request: &HttpRequest) {
        let content_type = request
            .headers
            .get("content-type")
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        step.url = self.scrub_url(&target_url(request));
        for (name, value) in &mut step.headers {
            *value = if is_secret_name(name) {
                self.placeholder(name)
            } else if name.eq_ignore_ascii_case("referer") || name.eq_ignore_ascii_case("referrer")
            {
                // A PoC does not need the Referer's query (or fragment), and it
                // is exactly where a session id rides along: keep origin + path.
                scrub_embedded(origin_and_path(value))
            } else {
                scrub_embedded(value)
            };
        }
        step.body = body_text(&request.body).map(|body| self.scrub_body(&body, &content_type));
    }

    /// The `{{var}}` placeholder for a redacted `key`, recording its variable.
    ///
    /// Dedupe is a `HashSet` lookup, not a scan of `secrets`. Once
    /// [`MAX_SECRET_VARS`] distinct names are declared, a *new* name reuses the
    /// single [`CATCH_ALL_VAR`] placeholder instead of minting a variable — an
    /// already-declared name still gets its own placeholder back.
    fn placeholder(&mut self, key: &str) -> String {
        let mut name = secret_var_name(key);
        if !self.seen.contains(&name) && self.secrets.len() >= MAX_SECRET_VARS {
            name = CATCH_ALL_VAR.to_string();
        }
        if self.seen.insert(name.clone()) {
            let description = if name == CATCH_ALL_VAR {
                format!(
                    "Credentials redacted from the captured request beyond the first {MAX_SECRET_VARS} distinct names (not stored in the PoC)"
                )
            } else {
                format!(
                    "Credential redacted from the captured request: `{name}` (not stored in the PoC)"
                )
            };
            self.secrets.push(Variable {
                name: name.clone(),
                default: None,
                description,
                required: true,
            });
        }
        format!("{{{{{name}}}}}")
    }

    fn scrub_url(&mut self, url: &str) -> String {
        match url.split_once('?') {
            Some((base, query)) => format!("{}?{}", scrub_text(base), self.scrub_pairs(query)),
            None => scrub_text(url),
        }
    }

    /// Scrub a `k=v&k=v` string (a query string or a form body), preserving the
    /// order and the parameters themselves.
    fn scrub_pairs(&mut self, input: &str) -> String {
        let mut out = Vec::new();
        for segment in input.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = url::form_urlencoded::parse(segment.as_bytes())
                .next()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .unwrap_or_default();
            if !segment.contains('=') {
                // A key-only segment is not a pair. A body labelled as a form
                // that is not one (a JSON document, a bare token) arrives here
                // whole, so its "key" is scrubbed as free text.
                out.push(form_encode(&scrub_decoded(&key)));
                continue;
            }
            let is_payload = value == self.payload;
            if is_secret_name(&key) && !value.is_empty() && !is_payload {
                out.push(format!("{}={}", form_encode(&key), self.placeholder(&key)));
                continue;
            }
            let value = if is_payload {
                value
            } else {
                scrub_decoded(&value)
            };
            out.push(format!("{}={}", form_encode(&key), form_encode(&value)));
        }
        out.join("&")
    }

    fn scrub_body(&mut self, body: &str, content_type: &str) -> String {
        if content_type.contains("application/x-www-form-urlencoded") {
            return self.scrub_pairs(body);
        }
        if content_type.contains("json") {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
                self.scrub_json(&mut json);
                if let Ok(text) = serde_json::to_string(&json) {
                    return text;
                }
            }
        }
        scrub_embedded(body)
    }

    fn scrub_json(&mut self, value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let is_payload = matches!(child, Value::String(s) if s == self.payload);
                    if is_secret_name(key) && !is_payload {
                        *child = Value::String(self.placeholder(key));
                    } else {
                        self.scrub_json(child);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.scrub_json(item);
                }
            }
            Value::String(text) => {
                if text != self.payload {
                    *text = scrub_embedded(text);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// Mask credential material embedded in a value that is *not* itself under a
/// secret name, using the one vocabulary the name scrub uses.
///
/// URL userinfo is stripped first ([`strip_userinfo`]: `//user:pw@host` →
/// `//host`), so a `user:pw@` prefix cannot make the scan swallow the host. Then
/// [`scrub_text_wide`] masks every `key=value` / `key: value` pair whose key
/// reads as a secret under the wide reading, the same reading [`is_secret_name`]
/// applies to the *name* of a header or parameter. A `sid=`, `auth=` or `author=`
/// pair embedded in a `Referer`-style or URL-valued value is therefore masked
/// exactly as it would be under a name, and the two scrubs cannot disagree about
/// which names are secret.
fn scrub_embedded(text: &str) -> String {
    scrub_text_wide(&strip_userinfo(text))
}

/// `value` with a `Referer` / `Referrer` header cut back to origin + path: the
/// query and the fragment, where a session id or token rides along, are dropped.
fn origin_and_path(value: &str) -> &str {
    let end = value.find(['?', '#']).unwrap_or(value.len());
    &value[..end]
}

/// [`scrub_embedded`] for a form value (or key-only segment) that
/// `form_urlencoded` has already decoded once. A decoded value that still
/// carries an encoded `=` / `:` is a secret hidden under a second layer of
/// encoding (`next=%252Fcb%253Fsid%253D…` decodes to `%2Fcb%3Fsid%3D…`, which no
/// `key=value` scan can see), so it is decoded again — [`MAX_DECODE_PASSES`]
/// iterations in total, counting the first.
fn scrub_decoded(decoded: &str) -> String {
    let mut text = decoded.to_string();
    for _ in 1..MAX_DECODE_PASSES {
        if !has_encoded_separator(&text) {
            break;
        }
        text = percent_decode(&text);
    }
    scrub_embedded(&text)
}

/// Whether `s` contains a percent-encoded `=` (`%3D`) or `:` (`%3A`), in either
/// hex case.
fn has_encoded_separator(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'3' && matches!(w[2], b'D' | b'd' | b'A' | b'a'))
}

/// Percent-decode `s`: each valid `%XX` becomes its byte; a malformed or
/// truncated sequence and every other byte (including `+`, which is a literal
/// plus here, not a space) is kept as written. Invalid UTF-8 in the result is
/// replaced, never an error.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| {
                char::from(b)
                    .to_digit(16)
                    .and_then(|d| u8::try_from(d).ok())
            };
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `application/x-www-form-urlencoded` percent-encoding, the same serializer
/// `inject::mutate_query` writes the payload with.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// A template-variable name for a redacted header / parameter / key: lowercase
/// ASCII, every other character `_`, led by a letter or `_` (`X-API-Key` →
/// `x_api_key`, the same name `aitm_poc`'s builder gives its credential headers).
fn secret_var_name(key: &str) -> String {
    let mut name: String = key
        .chars()
        .take(MAX_VAR_NAME_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if !name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
        name.insert_str(0, "v_");
    }
    name
}

/// Persist `rec` to the configured findings store, returning its id.
///
/// Errors when no `findings.dir` is configured — the same refusal the
/// `findings.record` command gives — rather than reporting an empty id as a
/// successful record while persisting nothing. The record's `target` is scrubbed
/// (`crate::crawl::safe_target`: userinfo removed, credential material masked)
/// before it is written. [`DiskFindingStore::record`] scrubs `title`/`notes` of
/// credential material at the persistence boundary regardless of what the
/// caller put there.
pub fn record_finding(host: &CommandHost<'_>, mut rec: FindingRecord) -> anyhow::Result<String> {
    let Some(dir) = host.config().and_then(|c| c.findings.dir.clone()) else {
        anyhow::bail!("record_finding: no findings directory is configured");
    };
    rec.target = crate::crawl::safe_target(&rec.target);
    DiskFindingStore::new(dir).record(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, Config, ConnInfo, FindingsConfig, FlowId, FlowMeta, Frontend, HeaderMap, HttpFlow,
        HttpRequest, HttpVersion, InterceptState, MemFlowStore, ProxyClient, StdGuard,
    };
    use aitm_findings::{FindingArtifacts, Reproduction};
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::discover::Location;

    /// A `ProxyClient` these helpers must never reach: building/recording a PoC
    /// issues no traffic.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("reproduce:: helpers must not send through the proxy client: {req:?}");
        }
    }

    /// A scratch directory, removed when dropped.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("aitm-scanner-reproduce-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn flow_with_query(path: &str) -> HttpFlow {
        flow_with("GET", path, &[], None)
    }

    /// A captured flow with an explicit method, headers and (optional) body.
    fn flow_with(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> HttpFlow {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: method.into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: map,
                body: body.map_or(Body::Empty, |b| Body::Bytes(b.as_bytes().to_vec())),
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    fn point(flow: &HttpFlow, location: Location, name: &str, example: &str) -> InjectionPoint {
        InjectionPoint {
            flow: flow.id,
            location,
            name: name.to_string(),
            example: example.to_string(),
        }
    }

    /// The single http step of a built PoC.
    fn http_step(poc: &Poc) -> &aitm_poc::HttpStep {
        let aitm_poc::Step::Http(step) = &poc.steps[0] else {
            panic!("the PoC carries one http step: {:?}", poc.steps);
        };
        step
    }

    /// Run `f` against a host wired with the given config (or none at all).
    fn with_host<R>(config: Option<Config>, f: impl FnOnce(&CommandHost<'_>) -> R) -> R {
        let store = MemFlowStore::new();
        let client = NoSendClient;
        let guard = StdGuard::default();
        let mut host = CommandHost::new(&store, &client, &guard, None);
        if let Some(config) = config {
            host = host.with_config(Arc::new(config));
        }
        f(&host)
    }

    fn config_with_dir(dir: &Path) -> Config {
        Config {
            findings: FindingsConfig {
                dir: Some(dir.to_path_buf()),
            },
            ..Config::default()
        }
    }

    fn base_record(id: &str) -> FindingRecord {
        FindingRecord {
            id: id.to_string(),
            title: "Reflected XSS in q".to_string(),
            class: "reflected-xss".to_string(),
            severity: Severity::High,
            target: "http://target.test/".to_string(),
            discovered_at: SystemTime::now(),
            origin: Frontend::Mcp,
            client_label: None,
            poc_ref: "reflected-xss-q".to_string(),
            reproduction: Reproduction {
                passed: true,
                control_passed: Some(false),
                run_at: SystemTime::now(),
            },
            artifacts: FindingArtifacts {
                finding_capture: FlowId::new(),
                poc_path: "poc.yaml".to_string(),
                screenshot_path: String::new(),
            },
            flows: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn build_poc_sets_success_assertion() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let point = InjectionPoint {
            flow: flow.id,
            location: Location::Query,
            name: "q".to_string(),
            example: "hello".to_string(),
        };

        let poc = build_poc(&flow, &def, &point, payload).expect("poc builds");

        assert_eq!(
            poc.success,
            def.success_assertion(payload),
            "the recorded PoC must assert exactly what `confirm` judged the hit against"
        );

        let aitm_poc::Step::Http(step) = &poc.steps[0] else {
            panic!("the PoC carries one http step: {:?}", poc.steps);
        };
        assert!(
            step.url.contains("{{target}}"),
            "the step URL must be parameterized to {{target}}: {}",
            step.url
        );

        // Round-trips via `aitm_poc`'s own serde: the crate's custom
        // `Step`/`Assertion` impls build a generic serde-data-model tree, not
        // raw YAML text, so `serde_json` (already a dependency here) exercises
        // the same code path without a new one.
        let json = serde_json::to_string(&poc).expect("poc serializes");
        let back: Poc = serde_json::from_str(&json).expect("poc deserializes");
        assert_eq!(back.success, poc.success);
    }

    /// A built PoC carries the pinned severity for its class: reflected-XSS is
    /// `Medium`, open-redirect is `Low`, and a class the mapping does not know
    /// falls back to `Info` — never a silent over-statement.
    #[test]
    fn build_poc_severity_follows_the_class_mapping() {
        let flow = flow_with_query("/search?q=hello");
        let q = point(&flow, Location::Query, "q", "hello");

        let xss = CheckDefinition::reflected_xss();
        let poc = build_poc(&flow, &xss, &q, &xss.payloads[0]).expect("xss poc builds");
        assert_eq!(poc.info.severity, Severity::Medium);

        let redirect_flow = flow_with_query("/go?next=http%3A%2F%2Fapp.test%2F");
        let next = point(
            &redirect_flow,
            Location::Redirect,
            "next",
            "http://app.test/",
        );
        let open = CheckDefinition::open_redirect();
        let poc = build_poc(&redirect_flow, &open, &next, &open.payloads[0])
            .expect("open-redirect poc builds");
        assert_eq!(poc.info.severity, Severity::Low);

        // A hand-built definition for a class no mapping covers.
        let unmapped = CheckDefinition {
            class: "not-a-registered-class",
            locations: &[Location::Query],
            payloads: vec![Payload {
                value: "aitm-unmapped".to_string(),
                marker: None,
            }],
            mode: crate::checks::AttackMode::BatteringRam,
        };
        let poc = build_poc(&flow, &unmapped, &q, &unmapped.payloads[0])
            .expect("unmapped-class poc builds");
        assert_eq!(poc.info.severity, Severity::Info);
    }

    /// Every class `checks::registered_classes` lists has a severity, so a new
    /// class cannot ship and silently build as `Info`.
    #[test]
    fn severity_mapping_covers_every_registered_class() {
        for class in CheckDefinition::registered_classes() {
            assert!(
                severity_for(class).is_some(),
                "`{class}` is registered but has no severity mapping"
            );
        }
        assert_eq!(severity_for("reflected-xss"), Some(Severity::Medium));
        assert_eq!(severity_for("open-redirect"), Some(Severity::Low));
        assert_eq!(severity_for("nope"), None);
    }

    #[test]
    fn record_round_trips() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let rec = base_record("reflected-xss-abc123de");

        let id = with_host(Some(config), |host| record_finding(host, rec.clone()))
            .expect("record_finding succeeds");
        assert_eq!(id, "reflected-xss-abc123de");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(stored.reproduction.passed);
        assert_eq!(stored.reproduction.control_passed, Some(false));
    }

    /// A careless caller might copy a source flow's raw `Authorization` header
    /// into free text; the store must still scrub it before it reaches disk.
    #[test]
    fn record_redacts_secret() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let mut rec = base_record("reflected-xss-secrettest");
        rec.title = "Authorization: Bearer abc123".to_string();
        rec.notes = Some("replayed request carried Authorization: Bearer abc123".to_string());

        let id =
            with_host(Some(config), |host| record_finding(host, rec)).expect("record succeeds");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(
            !stored.title.contains("abc123"),
            "title leaked the secret: {}",
            stored.title
        );
        assert!(
            !stored.notes.unwrap_or_default().contains("abc123"),
            "notes leaked the secret"
        );
    }

    // ---- Item 1: the PoC reproduces AND never leaks a request secret --------

    #[test]
    fn build_poc_reproduces_and_scrubs_secrets() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?access_token=QSECRET654&q=hello",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("X-Auth-Token", "HDRSECRET456"),
                ("X-CSRF-Token", "CSRFSECRET321"),
                ("Authorization", "Bearer abc123"),
            ],
            Some("username=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for secret in [
            "QSECRET654",
            "HDRSECRET456",
            "CSRFSECRET321",
            "abc123",
            "PWSECRET789",
        ] {
            assert!(
                !serialized.contains(secret),
                "the shareable PoC leaked `{secret}`: {serialized}"
            );
        }

        // It reproduces: the step carries the payload at `q`, not the benign
        // value, so replaying it can trigger the `success` assertion.
        let step = http_step(&poc);
        assert!(
            step.url.contains("q=%3Caitm-canary-0001%3E"),
            "the step URL must carry the payload at `q`: {}",
            step.url
        );
        assert!(
            !step.url.contains("q=hello"),
            "the benign value must be gone: {}",
            step.url
        );
        assert_eq!(poc.success, def.success_assertion(payload));

        // The non-secret structure survives; each secret became a placeholder.
        assert!(step.url.starts_with("{{target}}/search?"), "{}", step.url);
        assert!(
            step.url.contains("access_token={{access_token}}"),
            "{}",
            step.url
        );
        assert_eq!(
            step.body.as_deref(),
            Some("username=admin&password={{password}}&q=hello")
        );
        let header = |name: &str| {
            step.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("X-Auth-Token"), Some("{{x_auth_token}}"));
        assert_eq!(header("X-CSRF-Token"), Some("{{x_csrf_token}}"));
        assert_eq!(header("Authorization"), Some("{{authorization}}"));
        for var in [
            "target",
            "access_token",
            "password",
            "x_auth_token",
            "x_csrf_token",
            "authorization",
        ] {
            assert_eq!(
                poc.variables.iter().filter(|v| v.name == var).count(),
                1,
                "variable `{var}` must be declared exactly once: {:?}",
                poc.variables
            );
        }
    }

    #[test]
    fn build_poc_injects_into_a_form_body_point() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some("user=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::BodyParam, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("user=admin&password={{password}}&q=%3Caitm-canary-0001%3E")
        );
    }

    #[test]
    fn build_poc_scrubs_json_body_and_referer() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[
                ("Content-Type", "application/json"),
                ("Referer", "http://target.test/app?access_token=REFSECRET1"),
            ],
            Some(
                r#"{"user":"admin","password":"JSONPW1","nested":{"api_key":"JSONKEY2"},"note":"Bearer JSONBEARER3"}"#,
            ),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for secret in ["REFSECRET1", "JSONPW1", "JSONKEY2", "JSONBEARER3"] {
            assert!(
                !serialized.contains(secret),
                "leaked `{secret}`: {serialized}"
            );
        }
        let step = http_step(&poc);
        // Compare as parsed JSON, not as a byte string: serde_json's key order
        // depends on the `preserve_order` feature, which other workspace crates
        // enable, so the serialized order differs between an isolated and a
        // whole-workspace build. The structure is what matters.
        let body: serde_json::Value =
            serde_json::from_str(step.body.as_deref().expect("a json body")).expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "user": "admin",
                "password": "{{password}}",
                "nested": {"api_key": "{{api_key}}"},
                "note": "Bearer [redacted]",
            })
        );
        let referer = step
            .headers
            .iter()
            .find(|(n, _)| n == "Referer")
            .map(|(_, v)| v.as_str());
        // The Referer query is dropped outright (a PoC does not need it): only
        // origin + path survive, so nothing in the query can leak.
        assert_eq!(referer, Some("http://target.test/app"));
    }

    #[test]
    fn build_poc_scrubs_a_body_with_no_content_type() {
        // No declared type, so the body cannot be parsed as a form or JSON: the
        // whole-body `scrub_text` backstop still masks the credential.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[],
            Some("username=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("username=admin&password=[redacted]&q=hello")
        );
    }

    #[test]
    fn secret_names_match_the_shared_and_discover_vocabulary() {
        for name in [
            "access_token",
            "X-Auth-Token",
            "X-CSRF-Token",
            "csrf",
            "PHPSESSID",
            "sessionid",
            "sid",
            "jwt",
            "Authorization",
            "password",
            "x-api-key",
        ] {
            assert!(is_secret_name(name), "`{name}` must read as a secret");
        }
        for name in ["q", "page", "username", "next", "Content-Type", "Referer"] {
            assert!(!is_secret_name(name), "`{name}` is not a secret");
        }
    }

    #[test]
    fn secret_var_names_are_template_identifiers() {
        assert_eq!(secret_var_name("X-API-Key"), "x_api_key");
        assert_eq!(secret_var_name("access_token"), "access_token");
        assert_eq!(secret_var_name("1st-token"), "v_1st_token");
        assert_eq!(secret_var_name(""), "v_");
        assert_eq!(secret_var_name("tok\u{e9}n"), "tok_n");
        assert_eq!(secret_var_name(&"t".repeat(500)).len(), MAX_VAR_NAME_CHARS);
    }

    #[test]
    fn build_poc_scrubs_secret_embedded_in_a_param_value() {
        // A redirect-style value that itself carries a credential, percent-encoded
        // the way a browser would send it: the framing a raw-text scrub cannot see.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/go?q=hello&next=%2Fcb%3Faccess_token%3DNESTED999%26x%3D1");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(!url.contains("NESTED999"), "embedded secret leaked: {url}");
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
        assert!(
            url.contains("next=%2Fcb%3Faccess_token%3D%5Bredacted%5D%26x%3D1"),
            "{url}"
        );
    }

    #[test]
    fn build_poc_keeps_payload_at_a_secret_named_point() {
        // The scanner's own payload constant is not a secret; a redirect param
        // that happens to be named like one must still carry it, or the PoC
        // could never reproduce.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/cb?return_token=https%3A%2F%2Fapp.example%2F&sid=ZZSECRET");
        let p = point(
            &flow,
            Location::Redirect,
            "return_token",
            "https://app.example/",
        );

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(
            url.contains("return_token=https%3A%2F%2Faitm-scan-sentinel.invalid%2F"),
            "the payload must survive at the secret-named point: {url}"
        );
        assert!(!url.contains("ZZSECRET"), "{url}");
        assert!(url.contains("sid={{sid}}"), "{url}");
    }

    #[test]
    fn build_poc_keeps_payload_at_a_secret_named_json_body_point() {
        // The body half of the same rule: a JSON key named like a secret that is
        // the injection point still carries the payload, the neighbouring secret
        // is masked, and the document stays valid JSON.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/cb",
            &[("Content-Type", "application/json")],
            Some(r#"{"return_token":"https://app.example/","password":"JSONPW9"}"#),
        );
        let p = point(
            &flow,
            Location::Redirect,
            "return_token",
            "https://app.example/",
        );

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        let step = http_step(&poc);
        let body: serde_json::Value =
            serde_json::from_str(step.body.as_deref().expect("a json body")).expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "return_token": "https://aitm-scan-sentinel.invalid/",
                "password": "{{password}}",
            })
        );
        assert_eq!(step.url, "{{target}}/cb");
    }

    #[test]
    fn build_poc_gives_a_bodyless_request_no_body() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let step = http_step(&poc);
        assert_eq!(step.body, None);
        assert!(step.url.starts_with("{{target}}/search?q="), "{}", step.url);
    }

    #[test]
    fn build_poc_errs_when_the_point_is_absent_from_the_flow() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let gone = point(&flow, Location::Query, "missing", "x");

        let err = build_poc(&flow, &def, &gone, payload).expect_err("no such point");

        assert!(err.to_string().contains("missing"), "{err}");
    }

    // ---- Item 9: the PoC id stays valid whatever the point is called ---------

    #[test]
    fn build_poc_caps_point_name_to_a_valid_id() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let long = "a".repeat(500);
        let flow = flow_with_query(&format!("/search?{long}=hello"));
        let p = point(&flow, Location::Query, &long, "hello");

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        assert!(
            aitm_poc::runner::is_valid_poc_id(&poc.id),
            "an unbounded point name made an invalid PoC id: {:?}",
            poc.id
        );
        assert_eq!(poc.id, format!("reflected-xss-via-{}", "a".repeat(32)));
        assert_eq!(
            poc.info.name,
            format!("reflected-xss via {}", "a".repeat(32))
        );
    }

    #[test]
    fn build_poc_id_is_valid_for_hostile_point_names() {
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        for name in ["../../etc/passwd", "UPPER Case \u{e9}", "---", "\u{1F600}"] {
            let enc: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
            let flow = flow_with_query(&format!("/x?{enc}=https%3A%2F%2Fapp.example%2F"));
            let p = point(&flow, Location::Redirect, name, "x");

            let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

            assert!(
                aitm_poc::runner::is_valid_poc_id(&poc.id),
                "name {name:?} produced invalid id {:?}",
                poc.id
            );
        }
    }

    // ---- Item 2: no findings dir is an error, and the target is scrubbed -----

    #[test]
    fn record_finding_errs_without_dir() {
        let rec = base_record("reflected-xss-nodir");
        let no_config = with_host(None, |host| record_finding(host, rec.clone()));
        assert!(no_config.is_err(), "no config: {no_config:?}");

        let default_config = with_host(Some(Config::default()), |host| record_finding(host, rec));
        let err = default_config.expect_err("default config has no findings dir");
        assert!(
            err.to_string().contains("no findings directory"),
            "the error must say why: {err}"
        );
    }

    #[test]
    fn record_scrubs_target() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let mut rec = base_record("reflected-xss-targetscrub");
        rec.target = "http://user:USERPW1@target.test/p?access_token=TGTSECRET2".to_string();

        let id =
            with_host(Some(config), |host| record_finding(host, rec)).expect("record succeeds");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert_eq!(
            stored.target,
            "http://target.test/p?access_token=[redacted]"
        );
    }

    // ---- N1: the embedded-value scrub shares the name scrub's vocabulary -----

    /// A header value of `step`, by case-insensitive name.
    fn header_of<'a>(step: &'a aitm_poc::HttpStep, name: &str) -> Option<&'a str> {
        step.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The reviewer's measured leak: before PR 171 none of these names was in
    /// the shared set, so a `Referer` carrying them was emitted verbatim. The
    /// shared vocabulary now holds all of them, and the embedded-value scrub and
    /// the name scrub read it the same way.
    #[test]
    fn build_poc_drops_the_referer_query_and_leaks_no_session_id() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?access_token=QSECRET654&q=hello",
            &[
                (
                    "Referer",
                    "http://t/app?PHPSESSID=REFPHP1&sid=REFSID2&jwt=REFJWT3&auth=REFAUTH4&session=REFSESS5&csrf=REFCSRF6",
                ),
                ("Referrer", "http://t/cb#sid=FRAGSID7"),
            ],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for leaked in [
            "REFPHP1",
            "REFSID2",
            "REFJWT3",
            "REFAUTH4",
            "REFSESS5",
            "REFCSRF6",
            "FRAGSID7",
            "QSECRET654",
        ] {
            assert!(
                !serialized.contains(leaked),
                "the shareable PoC leaked `{leaked}`: {serialized}"
            );
        }
        let step = http_step(&poc);
        // Only origin + path survive: the query (and a fragment) is gone.
        assert_eq!(header_of(step, "Referer"), Some("http://t/app"));
        assert_eq!(header_of(step, "Referrer"), Some("http://t/cb"));
        // Controls: a token-named param is still masked and the PoC still
        // carries the payload, so it reproduces.
        assert!(
            step.url.contains("access_token={{access_token}}"),
            "{}",
            step.url
        );
        assert!(
            step.url.contains("q=%3Caitm-canary-0001%3E"),
            "the step URL must carry the payload at `q`: {}",
            step.url
        );
        assert_eq!(poc.success, def.success_assertion(payload));
    }

    /// The embedded-value scrub on its own: a non-`Referer` header whose name is
    /// not a secret, so only the embedded-value scrub can mask what it carries.
    #[test]
    fn build_poc_scrubs_session_ids_embedded_in_a_non_secret_header() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?q=hello",
            &[(
                "X-Return-To",
                "http://t/cb?PHPSESSID=HDRPHP1&sid=HDRSID2&jwt=HDRJWT3&auth=HDRAUTH4&session=HDRSESS5&csrf=HDRCSRF6&access_token=HDRTOK7&page=2",
            )],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            header_of(http_step(&poc), "X-Return-To"),
            Some(
                "http://t/cb?PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&access_token=[redacted]&page=2"
            )
        );
    }

    #[test]
    fn build_poc_scrubs_session_ids_embedded_in_a_redirect_param() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query(
            "/go?q=hello&next=%2Fcb%3Fsid%3DNEXTSID%26jwt%3DNEXTJWT%26session%3DNEXTSESS",
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        for leaked in ["NEXTSID", "NEXTJWT", "NEXTSESS"] {
            assert!(!url.contains(leaked), "embedded `{leaked}` leaked: {url}");
        }
        assert!(
            url.contains(
                "next=%2Fcb%3Fsid%3D%5Bredacted%5D%26jwt%3D%5Bredacted%5D%26session%3D%5Bredacted%5D"
            ),
            "{url}"
        );
        // Control: the payload is still injected.
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
    }

    #[test]
    fn build_poc_scrubs_session_ids_in_a_json_string_leaf() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[("Content-Type", "application/json")],
            Some(r#"{"redirect":"http://t/cb?sid=JSONSID1&jwt=JSONJWT2","msg":"csrf: JSONCSRF3"}"#),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let body: serde_json::Value =
            serde_json::from_str(http_step(&poc).body.as_deref().expect("a json body"))
                .expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "redirect": "http://t/cb?sid=[redacted]&jwt=[redacted]",
                "msg": "csrf: [redacted]",
            })
        );
    }

    #[test]
    fn build_poc_scrubs_session_ids_in_an_untyped_body() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[],
            Some("username=admin&sid=BODYSID1&jwt=BODYJWT2"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("username=admin&sid=[redacted]&jwt=[redacted]")
        );
    }

    /// A regression guard: the `Cookie` header is masked by name (it was before
    /// this change too), and a session cookie value never reaches the PoC.
    #[test]
    fn build_poc_masks_a_session_cookie_header() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?q=hello",
            &[("Cookie", "PHPSESSID=COOKIESID1; theme=dark")],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        assert!(!serialized.contains("COOKIESID1"), "{serialized}");
        assert_eq!(header_of(http_step(&poc), "Cookie"), Some("{{cookie}}"));
    }

    #[test]
    fn scrub_embedded_masks_every_shared_vocabulary_name() {
        assert_eq!(
            scrub_embedded("PHPSESSID=A&sid=B&jwt=C&auth=D&session=E&csrf=F&page=2"),
            "PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&page=2"
        );
        // `key: value` framing, with and without spacing.
        assert_eq!(scrub_embedded("X-CSRF: abc"), "X-CSRF: [redacted]");
        assert_eq!(scrub_embedded("sid:abc"), "sid:[redacted]");
        assert_eq!(scrub_embedded("sid = abc"), "sid = [redacted]");
        // JSON framing, including a quoted value that holds spaces.
        assert_eq!(
            scrub_embedded(r#"{"sid":"S1","jwt": "J2", "n":1}"#),
            r#"{"sid":"[redacted]","jwt": "[redacted]", "n":1}"#
        );
        assert_eq!(
            scrub_embedded(r#"{"session":"a b c","n":1}"#),
            r#"{"session":"[redacted]","n":1}"#
        );
        // The long words of the shared list apply in the same scan as the short
        // ones (one scan, one list).
        assert_eq!(
            scrub_embedded("access_token=T&sid=S"),
            "access_token=[redacted]&sid=[redacted]"
        );
        // URL userinfo is stripped.
        assert_eq!(
            scrub_embedded("go to http://user:pw@host/p?x=1"),
            "go to http://host/p?x=1"
        );
    }

    /// One vocabulary: the embedded-value scrub masks every short secret word
    /// `is_secret_name` matches. The list is spelled out here on purpose, so a
    /// word dropped from core's vocabulary fails this test instead of passing it.
    #[test]
    fn scrub_embedded_covers_every_segment_word() {
        for word in ["sid", "jwt", "csrf", "session", "auth"] {
            assert!(is_secret_name(word), "`{word}` is a secret name");
            assert_eq!(
                scrub_embedded(&format!("x_{word}_y=V1&z=2")),
                format!("x_{word}_y=[redacted]&z=2")
            );
            let upper = word.to_ascii_uppercase();
            assert_eq!(
                scrub_embedded(&format!("{upper}: V1")),
                format!("{upper}: [redacted]")
            );
        }
    }

    #[test]
    fn scrub_embedded_handles_quotes_and_escapes() {
        // An escaped quote inside a quoted value does not end it early.
        assert_eq!(
            scrub_embedded(r#"{"sid":"a\"b c","n":1}"#),
            r#"{"sid":"[redacted]","n":1}"#
        );
        // Single quotes, and a quote with blanks around the separator.
        assert_eq!(
            scrub_embedded("{'jwt' : 'a b','n':1}"),
            "{'jwt' : '[redacted]','n':1}"
        );
        // An opening quote that never closes falls back to the plain rule: the
        // value still ends at `&`, and the rest of the text survives.
        assert_eq!(scrub_embedded("sid=\"abc&x=1"), "sid=\"[redacted]&x=1");
        // An empty quoted value has nothing to redact.
        assert_eq!(scrub_embedded(r#"{"sid":"","n":1}"#), r#"{"sid":"","n":1}"#);
    }

    #[test]
    fn scrub_embedded_leaves_innocent_text_and_empty_values_alone() {
        for untouched in [
            "page=2&q=hello",
            "sid=&x=1",
            "session expired",
            "auth",
            "",
            "plain text with no pairs",
        ] {
            assert_eq!(scrub_embedded(untouched), untouched);
        }
        // Over-matching is deliberate (a leaked session id costs more than a
        // redacted `subsidiary`), as in `discover::is_secret_name`.
        assert_eq!(scrub_embedded("subsidiary=acme"), "subsidiary=[redacted]");
        // Non-ASCII around a match never panics on a char boundary.
        assert_eq!(
            scrub_embedded("h\u{e9}llo sid=w\u{f6}rld \u{fc}n\u{ef}"),
            "h\u{e9}llo sid=[redacted] \u{fc}n\u{ef}"
        );
    }

    // ---- M1: secret variables are deduped in O(1) and bounded ---------------

    #[test]
    fn build_poc_bounds_the_secret_variables_a_hostile_request_can_mint() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let mut path = String::from("/search?q=hello");
        for i in 0..200 {
            path.push_str(&format!("&token{i}=BULK{i:03}SECRET"));
        }
        // A name declared before the cap is hit keeps its own placeholder after
        // it; only a *new* name past the cap folds into the catch-all.
        path.push_str("&token3=AGAINSECRET");
        let flow = flow_with_query(&path);
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for i in 0..200 {
            let value = format!("BULK{i:03}SECRET");
            assert!(!serialized.contains(&value), "`{value}` leaked");
        }
        // `target` + 64 named secret variables + one catch-all.
        assert_eq!(poc.variables.len(), 66, "{:?}", poc.variables);
        let names: std::collections::HashSet<&str> =
            poc.variables.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names.len(), 66, "variable names must stay unique");
        assert!(names.contains("token0") && names.contains("token63"));
        assert!(!names.contains("token64"), "past the cap, no new variable");
        assert!(names.contains("redacted"), "the catch-all is declared");
        let redacted = poc
            .variables
            .iter()
            .find(|v| v.name == "redacted")
            .expect("catch-all variable");
        assert!(redacted.required && redacted.default.is_none());
        let url = &http_step(&poc).url;
        assert!(url.contains("token63={{token63}}"), "{url}");
        assert!(url.contains("token64={{redacted}}"), "{url}");
        assert!(url.contains("token199={{redacted}}"), "{url}");
        assert!(url.ends_with("&token3={{token3}}"), "{url}");
        assert!(!serialized.contains("AGAINSECRET"), "repeat value leaked");
    }

    // ---- M4: key-only segments and nested encodings --------------------------

    #[test]
    fn build_poc_scrubs_a_json_body_mislabelled_as_a_form() {
        // Not form data at all: the whole body is one key-only segment, which
        // used to be re-emitted unscrubbed.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(r#"{"password":"FORMJSONPW1"}"#),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let serialized = serde_json::to_string(&poc).expect("poc serializes");
        assert!(!serialized.contains("FORMJSONPW1"), "{serialized}");
        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("%7B%22password%22%3A%22%5Bredacted%5D%22%7D")
        );
    }

    #[test]
    fn build_poc_scrubs_a_double_encoded_embedded_secret() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/go?q=hello&next=%252Fcb%253Faccess_token%253DDBLSECRET1");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(
            !url.contains("DBLSECRET1"),
            "double-encoded secret leaked: {url}"
        );
        assert!(
            url.contains("next=%2Fcb%3Faccess_token%3D%5Bredacted%5D"),
            "{url}"
        );
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
    }

    #[test]
    fn percent_decode_decodes_valid_sequences_only() {
        assert_eq!(percent_decode("%2Fcb%3Fa%3dB%3A"), "/cb?a=B:");
        assert_eq!(percent_decode("%C3%A9"), "\u{e9}");
        // Malformed sequences and a trailing `%` stay as written; `+` is not a space.
        assert_eq!(percent_decode("100%zz%4"), "100%zz%4");
        assert_eq!(percent_decode("a+b%"), "a+b%");
        assert_eq!(percent_decode(""), "");
    }

    // ---- Pins taken before the embedded-value scrub and the name decisions merge ----

    /// A parameter whose name only contains one of the short secret words
    /// (`author` holds `auth`) is placeholdered in a PoC and never recorded.
    #[test]
    fn build_poc_placeholders_a_wide_only_parameter() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello&author=ALICE");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(url.contains("author={{author}}"), "{url}");
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
        let author = poc
            .variables
            .iter()
            .find(|v| v.name == "author")
            .expect("an `author` variable is declared");
        assert!(author.required, "{author:?}");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");
        assert!(!serialized.contains("ALICE"), "{serialized}");
    }

    /// The name decision and the embedded-value scrub agree on every ASCII key:
    /// `is_secret_name(key)` and "`scrub_embedded` masks `key=VALUE9`" both equal
    /// the literal expectation in the table. Keys hold only ASCII alphanumerics
    /// and `_ . -`; a key with a non-ASCII character glued to a secret word is
    /// not in the table.
    #[test]
    fn scrub_embedded_and_is_secret_name_agree_on_every_key() {
        let rows: &[(&str, bool)] = &[
            // Names that only contain one of the five short words.
            ("author", true),
            ("authority", true),
            ("authenticated", true),
            ("inside", true),
            ("side", true),
            ("sidebar", true),
            ("subsidiary", true),
            ("sessions", true),
            ("userSession", true),
            ("X-Authority", true),
            ("Author", true),
            ("rhai.allow_agent_authoring", true),
            // The five short words themselves.
            ("sid", true),
            ("jwt", true),
            ("csrf", true),
            ("session", true),
            ("auth", true),
            // The long distinctive words.
            ("Authorization", true),
            ("token", true),
            ("password", true),
            ("passwd", true),
            ("pwd", true),
            ("secret", true),
            ("cookie", true),
            ("api_key", true),
            ("apikey", true),
            ("api-key", true),
            ("bearer", true),
            ("credential", true),
            ("sessionid", true),
            ("phpsessid", true),
            // A short word as a whole segment of a longer key.
            ("x-auth", true),
            ("_csrf", true),
            ("connect.sid", true),
            ("ASP.NET_SessionId", true),
            // Not secret.
            ("path", false),
            ("host", false),
            ("body", false),
            ("note", false),
            ("method", false),
            ("page", false),
            ("q", false),
            ("username", false),
            ("next", false),
            ("Content-Type", false),
            ("Referer", false),
            ("Content-Length", false),
        ];
        assert!(rows.len() >= 40, "the table shrank: {} keys", rows.len());

        let mut bad = Vec::new();
        for &(key, is_secret) in rows {
            let pair = format!("{key}=VALUE9");
            let by_name = is_secret_name(key);
            let by_scrub = scrub_embedded(&pair) != pair;
            if by_name != is_secret || by_scrub != is_secret {
                bad.push((key, is_secret, by_name, by_scrub));
            }
        }
        assert!(
            bad.is_empty(),
            "(key, expected, is_secret_name, scrub_embedded masks it): {bad:?}"
        );
    }

    /// Rows recorded by running the old two-scan pipeline's `scrub_embedded` on
    /// `15009b2`, as `(input, output)`. The outputs are what that code printed,
    /// not what anyone expected, and each family is a shape a user can send.
    const RECORDED_SCRUB_EMBEDDED: &[(&str, &str)] = &[
        // (i) every string the existing scrub_embedded_* and build_poc_scrubs_* tests reach
        ("username=admin&password=PWSECRET789&q=hello", "username=admin&password=[redacted]&q=hello"),
        ("/cb?access_token=DBLSECRET1", "/cb?access_token=[redacted]"),
        ("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"),
        ("{\"password\":\"FORMJSONPW1\"}", "{\"password\":\"[redacted]\"}"),
        ("application/json", "application/json"),
        ("http://target.test/app", "http://target.test/app"),
        ("admin", "admin"),
        ("Bearer JSONBEARER3", "Bearer [redacted]"),
        ("/cb?access_token=NESTED999&x=1", "/cb?access_token=[redacted]&x=1"),
        ("http://t/cb?PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&access_token=[redacted]&page=2", "http://t/cb?PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&access_token=[redacted]&page=2"),
        ("/cb?sid=NEXTSID&jwt=NEXTJWT&session=NEXTSESS", "/cb?sid=[redacted]&jwt=[redacted]&session=[redacted]"),
        ("http://t/cb?sid=JSONSID1&jwt=JSONJWT2", "http://t/cb?sid=[redacted]&jwt=[redacted]"),
        ("csrf: JSONCSRF3", "csrf: [redacted]"),
        ("username=admin&sid=BODYSID1&jwt=BODYJWT2", "username=admin&sid=[redacted]&jwt=[redacted]"),
        ("x_sid_y=V1&z=2", "x_sid_y=[redacted]&z=2"),
        ("SID: V1", "SID: [redacted]"),
        ("x_jwt_y=V1&z=2", "x_jwt_y=[redacted]&z=2"),
        ("JWT: V1", "JWT: [redacted]"),
        ("x_csrf_y=V1&z=2", "x_csrf_y=[redacted]&z=2"),
        ("CSRF: V1", "CSRF: [redacted]"),
        ("x_session_y=V1&z=2", "x_session_y=[redacted]&z=2"),
        ("SESSION: V1", "SESSION: [redacted]"),
        ("x_auth_y=V1&z=2", "x_auth_y=[redacted]&z=2"),
        ("AUTH: V1", "AUTH: [redacted]"),
        ("{\"sid\":\"a\\\"b c\",\"n\":1}", "{\"sid\":\"[redacted]\",\"n\":1}"),
        ("{'jwt' : 'a b','n':1}", "{'jwt' : '[redacted]','n':1}"),
        ("sid=\"abc&x=1", "sid=\"[redacted]&x=1"),
        ("{\"sid\":\"\",\"n\":1}", "{\"sid\":\"\",\"n\":1}"),
        ("page=2&q=hello", "page=2&q=hello"),
        ("sid=&x=1", "sid=&x=1"),
        ("session expired", "session expired"),
        ("auth", "auth"),
        ("", ""),
        ("plain text with no pairs", "plain text with no pairs"),
        ("subsidiary=acme", "subsidiary=[redacted]"),
        ("h\u{e9}llo sid=w\u{f6}rld \u{fc}n\u{ef}", "h\u{e9}llo sid=[redacted] \u{fc}n\u{ef}"),
        ("PHPSESSID=A&sid=B&jwt=C&auth=D&session=E&csrf=F&page=2", "PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&page=2"),
        ("X-CSRF: abc", "X-CSRF: [redacted]"),
        ("sid:abc", "sid:[redacted]"),
        ("sid = abc", "sid = [redacted]"),
        ("{\"sid\":\"S1\",\"jwt\": \"J2\", \"n\":1}", "{\"sid\":\"[redacted]\",\"jwt\": \"[redacted]\", \"n\":1}"),
        ("{\"session\":\"a b c\",\"n\":1}", "{\"session\":\"[redacted]\",\"n\":1}"),
        ("access_token=T&sid=S", "access_token=[redacted]&sid=[redacted]"),
        ("go to http://user:pw@host/p?x=1", "go to http://host/p?x=1"),
        // (ii) quotes and escapes
        ("{\"token\":\"a\\\\b c\",\"n\":1}", "{\"token\":\"[redacted]\",\"n\":1}"),
        ("{\"sid\":\"S1\\\\\",\"n\":1}", "{\"sid\":\"[redacted]\",\"n\":1}"),
        ("{'sid':'it\\'s','n':1}", "{'sid':'[redacted]','n':1}"),
        ("{\"auth\":\"x\\\"y z\",\"n\":1}", "{\"auth\":\"[redacted]\",\"n\":1}"),
        ("{\"session\":\"tab\\there\\nnext\",\"n\":1}", "{\"session\":\"[redacted]\",\"n\":1}"),
        ("sid=\"a b\"&x=1", "sid=\"[redacted]\"&x=1"),
        ("password='a b' z=1", "password='[redacted]' z=1"),
        ("{\"sid\":\"a\",\"jwt\":\"b\",\"csrf\":\"c\"}", "{\"sid\":\"[redacted]\",\"jwt\":\"[redacted]\",\"csrf\":\"[redacted]\"}"),
        ("sid=\"abc", "sid=\"[redacted]"),
        ("sid='abc def", "sid='[redacted] def"),
        ("subsidiary=\"acme corp\"&x=1", "subsidiary=\"[redacted]\"&x=1"),
        ("{\"subsidiary\":\"a b\",\"n\":1}", "{\"subsidiary\":\"[redacted]\",\"n\":1}"),
        // (iii) pairs nested in a non-secret key's value
        ("next=/cb?sid=S1", "next=/cb?sid=[redacted]"),
        ("next=/cb?author=S1&x=1", "next=/cb?author=[redacted]&x=1"),
        ("next=/cb?sidebar=S1", "next=/cb?sidebar=[redacted]"),
        ("redirect=http://t/cb?jwt=J1&session=S2&page=3", "redirect=http://t/cb?jwt=[redacted]&session=[redacted]&page=3"),
        ("url=/a?x=1&password=P1&y=2", "url=/a?x=1&password=[redacted]&y=2"),
        ("back=/cb%3Fsid%3DS1", "back=/cb%3Fsid%3DS1"),
        ("ref=a?b=c&author=Z9;x=1", "ref=a?b=c&author=[redacted];x=1"),
        ("author=password=S3", "author=[redacted]"),
        ("msg=hello sid=S1 world", "msg=hello sid=[redacted] world"),
        // (iv) URL userinfo
        ("http://user:pw@host/p?sid=S1", "http://host/p?sid=[redacted]"),
        ("//auth:pw@host/x", "//host/x"),
        ("see http://user:pw@host:8080/p?x=1 now", "see http://host:8080/p?x=1 now"),
        ("a=//u1:p1@h1/x&b=//u2@h2", "a=//h1/x&b=//h2"),
        ("http://u:p@ss@host/x?author=Z", "http://host/x?author=[redacted]"),
        ("ftp://admin:hunter2@files.example.com/pub", "ftp://files.example.com/pub"),
        ("https://token:abc@api.example.com:8443/v1?session=S9", "https://api.example.com:8443/v1?session=[redacted]"),
        ("http://user:pw@host/a@b?e=me@x.com", "http://host/a@b?e=me@x.com"),
        // (v) empty values
        ("sid=", "sid="),
        ("subsidiary=&x=1", "subsidiary=&x=1"),
        ("token=&sid=&jwt=", "token=&sid=&jwt="),
        ("{\"sid\":\"\",\"jwt\":\"\",\"n\":1}", "{\"sid\":\"\",\"jwt\":\"\",\"n\":1}"),
        ("sid= &x=1", "sid= &x=1"),
        ("sid=&password=x", "sid=&password=[redacted]"),
        ("auth:", "auth:"),
        ("session=\"\"", "session=\"\""),
        // (vi) Authorization and Bearer
        ("Authorization: Bearer abc.def.ghi", "Authorization: [redacted]"),
        ("Authorization: Basic dXNlcjpwdw==", "Authorization: [redacted]"),
        ("authorization=Bearer abc", "authorization=[redacted]"),
        ("Bearer abc123 and more", "Bearer [redacted] and more"),
        ("curl -H \"Authorization: Bearer T0K3N\" http://t/x", "curl -H \"Authorization: [redacted]"),
        ("X-Auth: Bearer abc", "X-Auth: [redacted] [redacted]"),
        ("Proxy-Authorization: Basic Zm9v", "Proxy-Authorization: [redacted]"),
        ("{\"Authorization\":\"Bearer abc\"}", "{\"Authorization\":\"[redacted] [redacted]"),
        ("X-Api-Key: K1", "X-Api-Key: [redacted]"),
        // (vii) Referer-shaped values given directly
        ("http://t/app?PHPSESSID=REFPHP1&sid=REFSID2&jwt=REFJWT3&auth=REFAUTH4&session=REFSESS5&csrf=REFCSRF6", "http://t/app?PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]"),
        ("http://t/cb#sid=FRAGSID7", "http://t/cb#sid=[redacted]"),
        ("https://shop.example.com/cart?author=A1&page=2#session=S2", "https://shop.example.com/cart?author=[redacted]&page=2#session=[redacted]"),
        ("http://t/app", "http://t/app"),
        ("https://example.com:8443/path?next=/cb%3Fsid%3DS1", "https://example.com:8443/path?next=/cb%3Fsid%3DS1"),
        // (viii) percent-decoded values as scrub_decoded hands them over
        ("/cb?sid=NEXTSID&jwt=NEXTJWT", "/cb?sid=[redacted]&jwt=[redacted]"),
        ("/cb?author=A1&sidebar=S2&page=3", "/cb?author=[redacted]&sidebar=[redacted]&page=3"),
        ("/cb?next=/x?password=P1&sid=S1", "/cb?next=/x?password=[redacted]&sid=[redacted]"),
        ("/cb?redirect=http://t/x?token=T1&csrf=C2", "/cb?redirect=http://t/x?token=[redacted]&csrf=[redacted]"),
        ("/cb?q=a b&sid=S1", "/cb?q=a b&sid=[redacted]"),
        ("/cb?sid=a b c&x=1", "/cb?sid=[redacted] b c&x=1"),
        ("/cb?note=100%&sid=S1", "/cb?note=100%&sid=[redacted]"),
        ("/cb?subsidiary=a+b&sid=S1", "/cb?subsidiary=[redacted]&sid=[redacted]"),
        // (ix) host:port rows for the five words
        ("auth.example.com:8443", "auth.example.com:[redacted]"),
        ("sid.example.com:8443/x", "sid.example.com:[redacted]"),
        ("jwt.example.com:443", "jwt.example.com:[redacted]"),
        ("csrf.example.com:8080/", "csrf.example.com:[redacted]"),
        ("session.example.com:9000?x=1", "session.example.com:[redacted]"),
        ("https://auth.example.com:8443/login", "https://auth.example.com:[redacted]"),
        ("connect.sid.example.com:12345", "connect.sid.example.com:[redacted]"),
        ("sid:12345", "sid:[redacted]"),
        ("example.com:8443/x", "example.com:8443/x"),
        // (x) malformed families
        ("=", "="),
        (":", ":"),
        ("sid", "sid"),
        ("sid=\"", "sid=\""),
        ("sid=\\", "sid=[redacted]"),
        ("'", "'"),
        ("\"", "\""),
        ("auth==\"x\"", "auth=[redacted]\"x\""),
        ("sid=a=b=c", "sid=[redacted]"),
        ("&&&sid=1&&&", "&&&sid=[redacted]&&&"),
        ("sid:::abc", "sid:[redacted]"),
        ("sid=a;b,c", "sid=[redacted];b,c"),
        ("session=}", "session=}"),
        ("{{{\"sid\":", "{{{\"sid\":"),
        ("sid = ", "sid = "),
        ("sid\t=\tabc", "sid\t=\t[redacted]"),
        ("sid=a\0b", "sid=[redacted]"),
        ("sid=a\rb", "sid=[redacted]\rb"),
        ("sid=a\u{c}b", "sid=[redacted]\u{c}b"),
        ("sid:\nabc", "sid:\n[redacted]"),
        ("x=1&y=2&z=3", "x=1&y=2&z=3"),
        ("sid=\u{4e2d}\u{6587}&x=1", "sid=[redacted]&x=1"),
        // (xi) wide-only keys in well-formed framings
        ("author=bob&page=2", "author=[redacted]&page=2"),
        ("author: bob", "author: [redacted]"),
        ("authority=example.com", "authority=[redacted]"),
        ("authenticated=true&x=1", "authenticated=[redacted]&x=1"),
        ("inside=out", "inside=[redacted]"),
        ("side=left", "side=[redacted]"),
        ("sessions=3", "sessions=[redacted]"),
        ("userSession=abc&x=1", "userSession=[redacted]&x=1"),
        ("X-Authority: example", "X-Authority: [redacted]"),
        ("Author=Bob", "Author=[redacted]"),
        ("rhai.allow_agent_authoring=1", "rhai.allow_agent_authoring=[redacted]"),
        ("sidebar='x y' z=1", "sidebar='[redacted]' z=1"),
        ("{\"sidebar\":\"YWJj=\",\"user\":\"bob\"}", "{\"sidebar\":\"[redacted]\",\"user\":\"bob\"}"),
    ];

    /// The old pipeline's output, row by row: the embedded-value scrub still
    /// returns exactly what it returned before the scanner stopped keeping its
    /// own second scan.
    #[test]
    fn scrub_embedded_matches_the_recorded_pipeline_output() {
        assert!(
            RECORDED_SCRUB_EMBEDDED.len() >= 80,
            "the corpus shrank: {} rows",
            RECORDED_SCRUB_EMBEDDED.len()
        );
        let distinct: HashSet<&str> = RECORDED_SCRUB_EMBEDDED
            .iter()
            .map(|&(input, _)| input)
            .collect();
        assert!(
            distinct.len() == RECORDED_SCRUB_EMBEDDED.len(),
            "an input is listed twice"
        );

        let bad: Vec<(&str, &str, String)> = RECORDED_SCRUB_EMBEDDED
            .iter()
            .filter_map(|&(input, recorded)| {
                let actual = scrub_embedded(input);
                (actual != recorded).then_some((input, recorded, actual))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "rows that differ from the recorded output (input, recorded, actual): {bad:#?}"
        );
    }

    /// The deliberate output changes of the one-scan pipeline, one row per
    /// change (DC1 to DC6 of the spec), each with the old two-scan pipeline's
    /// output in a comment. These inputs are the only ones whose
    /// `scrub_embedded` output differs from what that pipeline printed; every
    /// row of [`RECORDED_SCRUB_EMBEDDED`] is unchanged. DC5 and DC6 mask less
    /// than before, and only on malformed input (a vertical tab or a non-ASCII
    /// space inside an unquoted value, a quote that never closes).
    #[test]
    fn scrub_embedded_deliberate_changes_are_exactly_these() {
        let rows: &[(&str, &str)] = &[
            // old pipeline: `xsid\u{e9}y=v`, unchanged (DC1)
            ("xsid\u{e9}y=v", "xsid\u{e9}y=[redacted]"),
            // old pipeline: `author:\nJohn`, unchanged (DC2)
            ("author:\nJohn", "author:\n[redacted]"),
            // old pipeline: `sidebar\u{a0}:\u{a0}v`, unchanged (DC2)
            ("sidebar\u{a0}:\u{a0}v", "sidebar\u{a0}:\u{a0}[redacted]"),
            // old pipeline: `token.example.com:8443/x`, unchanged (DC3)
            ("token.example.com:8443/x", "token.example.com:[redacted]"),
            // old pipeline: `sidebar='[redacted]'[redacted]'` (DC4)
            ("sidebar='abc def token='S3'", "sidebar='[redacted]'"),
            // old pipeline: `sid=[redacted]` (DC5)
            ("sid=abc\u{a0}def", "sid=[redacted]\u{a0}def"),
            // old pipeline: `sidebar=[redacted]` (DC5)
            ("sidebar=abc\u{b}def", "sidebar=[redacted]\u{b}def"),
            // old pipeline: `sid='[redacted]'[redacted]` (DC6)
            (
                "sid='abc def token='S3",
                "sid='[redacted] def token='[redacted]",
            ),
        ];
        assert!(rows.len() >= 8, "the table shrank: {} rows", rows.len());

        let bad: Vec<(&str, &str, String)> = rows
            .iter()
            .filter_map(|&(input, expected)| {
                let actual = scrub_embedded(input);
                (actual != expected).then_some((input, expected, actual))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "rows that differ from the new output (input, expected, actual): {bad:#?}"
        );
    }

    // ---- Edges of the embedded-value scrub: userinfo first, the ends of the text,
    // ---- non-ASCII boundaries, a text cut short, and the name call sites.

    /// URL userinfo goes first, so a username that reads as a secret word cannot
    /// make the scan swallow the host, and the password is gone from every output.
    #[test]
    fn scrub_embedded_strips_userinfo_before_it_scans() {
        let rows: &[(&str, &str)] = &[
            ("//auth:pw@host/x", "//host/x"),
            ("//sid:pw@host/x?q=1", "//host/x?q=1"),
            ("//author:pw@host:8443/x", "//host:8443/x"),
            (
                "//token:pw@host/x?sidebar=S1",
                "//host/x?sidebar=[redacted]",
            ),
            ("http://auth:pw@host", "http://host"),
            ("//auth:pw@", "//"),
            ("x=//auth:pw@h1/a&y=//sid:pw@h2/b", "x=//h1/a&y=//h2/b"),
            (
                "\u{e9}//auth:pw@h\u{f6}st/\u{fc}",
                "\u{e9}//h\u{f6}st/\u{fc}",
            ),
        ];
        let bad: Vec<(&str, &str, String)> = rows
            .iter()
            .filter_map(|&(input, expected)| {
                let actual = scrub_embedded(input);
                (actual != expected).then_some((input, expected, actual))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "rows that differ (input, expected, actual): {bad:#?}"
        );

        // Cut at every char boundary, as a dropped connection would leave it:
        // neither the password nor any canary value survives.
        let doc = "//auth:pw@host/x?sid=QQQQ&author=QQQQ";
        let mut bad: Vec<(usize, String)> = Vec::new();
        for cut in doc
            .char_indices()
            .map(|(at, _)| at)
            .chain(std::iter::once(doc.len()))
        {
            let out = scrub_embedded(&doc[..cut]);
            if out.contains('Q') || out.contains("pw") {
                bad.push((cut, out));
            }
        }
        assert!(
            bad.is_empty(),
            "a credential survived in a prefix: {bad:#?}"
        );
        assert_eq!(
            scrub_embedded(doc),
            "//host/x?sid=[redacted]&author=[redacted]"
        );
    }

    /// The ends of the text and the non-ASCII boundaries, as the one scan reads
    /// them. The non-ASCII rows are the shapes of DC1 and DC5 of the spec, pinned
    /// here as the new output.
    #[test]
    fn scrub_embedded_reads_the_edges_of_the_text() {
        let rows: &[(&str, &str)] = &[
            ("", ""),
            ("author", "author"),
            ("author:", "author:"),
            ("x=1&author=", "x=1&author="),
            ("x=1&author=v", "x=1&author=[redacted]"),
            ("sidebar=\u{e9}", "sidebar=[redacted]"),
            ("sidebar=v\u{a0}", "sidebar=[redacted]\u{a0}"),
            ("\u{e9}author=v", "\u{e9}author=[redacted]"),
            ("author\u{e9}", "author\u{e9}"),
            ("si\u{e9}d=v", "si\u{e9}d=v"),
        ];
        let bad: Vec<(&str, &str, String)> = rows
            .iter()
            .filter_map(|&(input, expected)| {
                let actual = scrub_embedded(input);
                (actual != expected).then_some((input, expected, actual))
            })
            .collect();
        assert!(
            bad.is_empty(),
            "rows that differ (input, expected, actual): {bad:#?}"
        );
    }

    /// A wide-only name is a placeholder wherever a PoC step carries a name: a
    /// header and a JSON key, which are `Scrubber` call sites that no other test
    /// reaches with a name outside the standard reading.
    #[test]
    fn build_poc_placeholders_a_wide_only_header_and_json_key() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[
                ("Content-Type", "application/json"),
                ("X-Authority", "HDRVAL1"),
            ],
            Some(
                r#"{"user":"admin","sidebar":"JSONVAL2","nested":{"subsidiary":"JSONVAL3"},"note":"ok"}"#,
            ),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let serialized = serde_json::to_string(&poc).expect("poc serializes");
        for secret in ["HDRVAL1", "JSONVAL2", "JSONVAL3"] {
            assert!(
                !serialized.contains(secret),
                "leaked `{secret}`: {serialized}"
            );
        }
        let step = http_step(&poc);
        assert_eq!(header_of(step, "X-Authority"), Some("{{x_authority}}"));
        let body: serde_json::Value =
            serde_json::from_str(step.body.as_deref().expect("a json body")).expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "user": "admin",
                "sidebar": "{{sidebar}}",
                "nested": {"subsidiary": "{{subsidiary}}"},
                "note": "ok",
            })
        );
        for name in ["x_authority", "sidebar", "subsidiary"] {
            let var = poc
                .variables
                .iter()
                .find(|v| v.name == name)
                .unwrap_or_else(|| panic!("no `{name}` variable: {:?}", poc.variables));
            assert!(var.required && var.default.is_none(), "{var:?}");
        }
    }

    /// Each of the five short words is read as a substring, by the name decision
    /// and by the embedded-value scrub alike, inside a key that is no whole
    /// segment (`myjwt2`, `JWTX`, `ajwt`). The expected output is literal.
    #[test]
    fn scrub_embedded_masks_a_key_that_merely_contains_each_segment_word() {
        let mut bad: Vec<(String, bool, String)> = Vec::new();
        for word in ["sid", "jwt", "csrf", "session", "auth"] {
            let upper = word.to_ascii_uppercase();
            for key in [
                format!("my{word}2"),
                format!("{upper}X"),
                format!("a{word}"),
            ] {
                let actual = scrub_embedded(&format!("{key}=VALUE9&page=2"));
                let expected = format!("{key}=[redacted]&page=2");
                let named = is_secret_name(&key);
                if !named || actual != expected {
                    bad.push((key, named, actual));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "(key, is_secret_name, scrub_embedded output): {bad:#?}"
        );
    }

    /// The part of a PoC URL before the `?` is free text and keeps the standard
    /// reading: a host:port in the path stays readable. The same text as a query
    /// value is an embedded value, read the wide way, so its port is masked.
    #[test]
    fn build_poc_reads_the_url_path_by_the_standard_reading() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/go/auth.example.com:8443/x?q=hello&u=auth.example.com:8443");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(
            url.starts_with("{{target}}/go/auth.example.com:8443/x?"),
            "{url}"
        );
        assert!(
            url.ends_with("&u=auth.example.com%3A%5Bredacted%5D"),
            "{url}"
        );
    }
}
