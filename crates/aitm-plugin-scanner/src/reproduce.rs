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
//! request. [`StdPocBuilder`] only masks four credential headers; `build_poc`
//! scrubs the rest of what it copies (see `Scrubber`): every secret-named
//! header, query parameter, form field and JSON key becomes a required `{{var}}`
//! placeholder the runner must be given at run time, and every other value is
//! passed through [`aitm_core::redact::scrub_text`]. `record_finding` is a thin
//! wrapper over [`aitm_findings::DiskFindingStore`]: the store itself scrubs
//! `title`/`notes` of credential material before anything reaches disk, and the
//! record's `target` is scrubbed here.

use aitm_core::redact::scrub_text;
use aitm_core::{CommandHost, HttpFlow};
use aitm_findings::{DiskFindingStore, FindingRecord, FindingStore};
use aitm_poc::{
    HttpStep, Poc, PocBuilder, PocInfo, PocSpec, Severity, StdPocBuilder, Step, Variable,
};

use crate::checks::{CheckDefinition, Payload};
use crate::discover::{is_secret_name, InjectionPoint};

/// Characters of the (network-supplied) injection-point name that feed the PoC
/// name and, through its slug, the PoC id. Bounded so the id always fits
/// `aitm_poc`'s 64-character limit: `<class> via <name>` is at most
/// `13 + 5 + 32` characters.
const MAX_POINT_NAME_CHARS: usize = 32;

/// Characters kept of a header / parameter name when it becomes a variable name.
const MAX_VAR_NAME_CHARS: usize = 48;

/// Severity assigned to a built PoC, keyed by class. A class with no mapping
/// here (a future `CheckDefinition::for_class` addition) defaults to `Medium`
/// rather than silently under- or over-stating it.
fn severity_for(class: &str) -> Severity {
    match class {
        "reflected-xss" => Severity::High,
        "open-redirect" => Severity::Medium,
        _ => Severity::Medium,
    }
}

/// The first `max` characters of `s`.
fn cap_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
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
            severity: severity_for(def.class),
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
            scrubber.scrub_step(http);
        }
    }
    for var in scrubber.secrets {
        if !poc.variables.iter().any(|v| v.name == var.name) {
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
/// 2. every other value is decoded and passed through [`scrub_text`], which
///    catches a credential embedded in an innocuously named value
///    (`next=%2Fcb%3Faccess_token%3D…`, `Referer: …?token=…`, `Bearer …`);
/// 3. a body that is neither a form nor JSON is passed through [`scrub_text`]
///    whole.
///
/// `scrub_text` is applied per decoded component, never over the finished
/// string: a whole-string pass would corrupt the `{{var}}` placeholders
/// (`access_token={{access_token}}` reads as a `key=value` credential) and mask
/// the injected payload at a secret-named point.
///
/// `payload` is the scanner's own inert constant, never a request secret, so a
/// value equal to it is left alone — a redirect parameter named `return_token`
/// must still carry the payload or the PoC could not reproduce.
struct Scrubber<'a> {
    payload: &'a str,
    secrets: Vec<Variable>,
}

impl<'a> Scrubber<'a> {
    fn new(payload: &'a str) -> Self {
        Self {
            payload,
            secrets: Vec::new(),
        }
    }

    fn scrub_step(&mut self, step: &mut HttpStep) {
        let content_type = step
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.to_ascii_lowercase())
            .unwrap_or_default();

        step.url = self.scrub_url(&step.url);
        for (name, value) in &mut step.headers {
            *value = if is_secret_name(name) {
                self.placeholder(name)
            } else {
                scrub_text(value)
            };
        }
        if let Some(body) = step.body.take() {
            step.body = Some(self.scrub_body(&body, &content_type));
        }
    }

    /// The `{{var}}` placeholder for a redacted `key`, recording its variable.
    fn placeholder(&mut self, key: &str) -> String {
        let name = secret_var_name(key);
        if !self.secrets.iter().any(|v| v.name == name) {
            self.secrets.push(Variable {
                name: name.clone(),
                default: None,
                description: format!(
                    "Credential redacted from the captured request: `{name}` (not stored in the PoC)"
                ),
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
            let is_payload = value == self.payload;
            if is_secret_name(&key) && !value.is_empty() && !is_payload {
                out.push(format!("{}={}", form_encode(&key), self.placeholder(&key)));
                continue;
            }
            let value = if is_payload {
                value
            } else {
                scrub_text(&value)
            };
            out.push(if segment.contains('=') {
                format!("{}={}", form_encode(&key), form_encode(&value))
            } else {
                form_encode(&key)
            });
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
        scrub_text(body)
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
                    *text = scrub_text(text);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
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
        assert_eq!(
            referer,
            Some("http://target.test/app?access_token=[redacted]")
        );
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
}
