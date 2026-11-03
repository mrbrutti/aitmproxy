//! T3 plan Task 15 — the four origin-scoped site-level audits
//! (`cors`, `headers`, `methods`, `paths`), exercised through the **real**
//! bridge: the shipped `scripts/bundled/active/*.rhai` file, the real
//! `RhaiLoader`, the real `reg.add_check`, the real `probe.*`, answered by the
//! model's own `RecordingHost` (decision D-2b-1).
//!
//! These four differ from every other bundled check in two ways, and both are
//! what this file is about. They declare `scope: "origin"`, so the engine runs
//! one of each per authority however many insertion points that authority has;
//! and three of them compose their own request with `probe.raw`, because no
//! insertion point carries an `Origin` header, an OPTIONS method or a
//! well-known path. The fourth sends nothing at all and reads the baseline.
//!
//! Inner loop only: canned replies, no network. Acceptance evidence is Task 17.

mod rhai_harness;

use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use aitm_poc::Severity;
use aitm_scan_model::point::{Payload, ProbeResponse, RawProbe};
use aitm_scan_model::profile::ScanProfile;
use aitm_scan_model::traits::{Check, ProbeHost};
use aitm_scan_model::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, Outcome, Technique,
};
use futures::future::BoxFuture;

use rhai_harness::{all_verdicts, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check, and therefore the one the
/// CORS canary is built from here.
const MARKER: &str = "aitm7f3a";

/// The canary Origin `check-cors.rhai` mints from that marker.
const CANARY: &str = "https://aitm7f3a.aitm-canary.example";

/// The origin every audit in this file is run against.
const ORIGIN: &str = "http://127.0.0.1:8081";

/// The point URL: a path *under* the origin, so a path audit that hung its
/// well-known list off the point's own path would be visible.
const POINT_URL: &str = "http://127.0.0.1:8081/item";

/// The query point all four audits are attached to. An origin-scoped check is
/// still scheduled through some point; which one must not change its answer.
fn origin_point() -> aitm_scan_model::point::InsertionPoint {
    point(InsertionKind::Query, "q", POINT_URL, Some("1"), &[])
}

/// The one check a shipped site-level script registers.
async fn audit(file: &str) -> Arc<dyn Check> {
    Loaded::load(file)
        .unwrap_or_else(|err| panic!("{file} loads: {err:#}"))
        .single()
        .unwrap_or_else(|err| panic!("{file}: {err:#}"))
}

// ---------------------------------------------------------------------------
// A probe host that records the whole raw request, not only its URL
// ---------------------------------------------------------------------------

/// What one `probe.raw` carried: `RecordingHost` keeps the URL, and a check
/// whose whole point is the *method* it asked with (`methods`) or the *header*
/// it sent (`cors`) needs the rest of the request to be observable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawSeen {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
}

/// A [`ProbeHost`] that answers one canned response and records every raw
/// request in full. `probe`/`baseline` are not what these three audits use and
/// error if one ever reaches for them.
struct RawLog {
    me: Weak<RawLog>,
    profile: ScanProfile,
    status: u16,
    headers: Vec<(String, String)>,
    seen: Mutex<Vec<RawSeen>>,
}

impl RawLog {
    fn new(status: u16, headers: &[(&str, &str)]) -> Arc<RawLog> {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        Arc::new_cyclic(|me| RawLog {
            me: me.clone(),
            profile: ScanProfile::default(),
            status,
            headers,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<RawSeen> {
        self.seen
            .lock()
            .expect("no test thread panics here")
            .clone()
    }
}

impl ProbeHost for RawLog {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("this audit must not take a baseline")) })
    }

    fn probe<'a>(&'a self, _payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("this audit must not payload the point")) })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        self.seen
            .lock()
            .expect("no test thread panics here")
            .push(RawSeen {
                method: req.method.clone(),
                url: req.url.clone(),
                headers: req.headers.clone(),
            });
        let response = ProbeResponse {
            status: Some(self.status),
            headers: self.headers.clone(),
            body: Vec::new(),
            elapsed_ms: 1,
            flow: None,
            ws_frames: None,
            l4: None,
        };
        Box::pin(async move { Ok(response) })
    }

    fn marker(&self) -> String {
        MARKER.to_string()
    }

    fn budget_left(&self) -> u32 {
        16
    }

    fn deadline(&self) -> Instant {
        Instant::now() + std::time::Duration::from_secs(60)
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn cancelled(&self) -> bool {
        false
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        Vec::new()
    }

    fn shared(&self) -> Option<Arc<dyn ProbeHost>> {
        self.me.upgrade().map(|host| host as Arc<dyn ProbeHost>)
    }

    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        Some(Arc::new(aitm_scan_model::testing::NullClient))
    }

    /// The log answers every probe itself; no captured flow built it.
    fn captured(&self) -> Option<aitm_core::HttpFlow> {
        None
    }

    /// Affordable up to `budget_left`, debiting nothing: the log holds no
    /// budget of its own.
    fn charge(&self, units: u32) -> bool {
        self.budget_left() >= units
    }
}

/// Run `check` against the origin point with every raw request logged.
async fn run_logged(check: &Arc<dyn Check>, host: &Arc<RawLog>) -> aitm_scan_model::check::Verdict {
    let point = origin_point();
    let probe_host: &dyn ProbeHost = host.as_ref();
    check.run(&point, probe_host).await
}

// ---------------------------------------------------------------------------
// check-cors.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cors_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-cors.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "cors");
    assert_eq!(meta.class, "cors");
    assert_eq!(meta.kinds, vec![InsertionKind::Query]);
    assert_eq!(meta.technique, Technique::Reflected);
    assert_eq!(meta.severity, Severity::Medium);
    assert_eq!(meta.intensity, Intensity::Light);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.cwe, Some(942));
    assert_eq!(
        meta.scope,
        CheckScope::Origin,
        "a CORS policy belongs to the authority, not to one parameter"
    );
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-cors.rhai"),
            "the bundled origin names the file, got {path}"
        ),
        other => panic!("a shipped script is Bundled, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cors_is_vulnerable_against_its_vulnerable_shape() {
    let check = audit("check-cors.rhai").await;
    let host = Replies::plain(200, "{}")
        .when_headers(
            POINT_URL,
            200,
            &[
                ("access-control-allow-origin", CANARY),
                ("access-control-allow-credentials", "true"),
            ],
            "{}",
        )
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some(CANARY),
        "the canary is built from the job's marker, so the table could name it"
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("access-control-allow-origin: https://aitm7f3a.aitm-canary.example")
    );
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item reflected an Origin nobody owns with credentials \
         allowed, so authenticated responses are readable cross-origin."
    );
    assert_eq!(
        host.raw_urls(),
        vec![POINT_URL.to_string()],
        "one request for the whole origin"
    );
    assert_eq!(host.payloads(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cors_is_clean_against_its_patched_shape() {
    let check = audit("check-cors.rhai").await;
    let host = Replies::plain(200, "{}")
        .when_headers(
            POINT_URL,
            200,
            &[("access-control-allow-origin", "https://app.example.test")],
            "{}",
        )
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item did not reflect the canary Origin \
         (Access-Control-Allow-Origin: https://app.example.test)."
    );
    assert_eq!(verdict.evidence.matched, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cors_audit_asks_the_origin_with_the_canary_origin_header() {
    // The oracle is a reflection, so the request has to carry the canary as a
    // real `Origin` header — not merely name it in the evidence.
    let check = audit("check-cors.rhai").await;
    let host = RawLog::new(200, &[("access-control-allow-origin", "*")]);
    let verdict = run_logged(&check, &host).await;

    assert_eq!(
        host.seen(),
        vec![RawSeen {
            method: "GET".to_string(),
            url: POINT_URL.to_string(),
            headers: vec![("origin".to_string(), CANARY.to_string())],
        }]
    );
    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "a wildcard cannot carry credentials; the passive headers audit owns it"
    );
}

// ---------------------------------------------------------------------------
// check-security-headers.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-security-headers.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "headers");
    assert_eq!(meta.class, "missing-security-headers");
    assert_eq!(meta.kinds, vec![InsertionKind::Query]);
    assert_eq!(meta.technique, Technique::Passive);
    assert_eq!(meta.severity, Severity::Low);
    assert_eq!(meta.intensity, Intensity::Passive);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.cwe, None, "the class maps to no single CWE");
    assert_eq!(meta.scope, CheckScope::Origin);
    assert!(
        meta.needs_baseline,
        "the audit reads the baseline and sends nothing of its own"
    );
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-security-headers.rhai"),
            "the bundled origin names the file, got {path}"
        ),
        other => panic!("a shipped script is Bundled, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_is_vulnerable_against_its_vulnerable_shape() {
    let check = audit("check-security-headers.rhai").await;
    let host = Replies::plain(200, "<html>hi</html>")
        .baseline_headers(&[("content-type", "text/html; charset=utf-8")])
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("GET http://127.0.0.1:8081/item")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some(
            "strict-transport-security, content-security-policy, x-content-type-options, \
             x-frame-options, referrer-policy"
        )
    );
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item (HTTP 200) is missing 5 security header(s): \
         strict-transport-security, content-security-policy, x-content-type-options, \
         x-frame-options, referrer-policy."
    );
    assert_eq!(
        host.raw_urls(),
        Vec::<String>::new(),
        "a passive audit composes no request"
    );
    assert_eq!(host.payloads(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_is_clean_against_its_patched_shape() {
    let check = audit("check-security-headers.rhai").await;
    let host = Replies::plain(200, "<html>hi</html>")
        .baseline_headers(&[
            ("strict-transport-security", "max-age=31536000"),
            ("content-security-policy", "default-src 'self'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ])
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "All five standard security headers are present on this origin's responses."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_counts_a_present_but_empty_header_as_missing() {
    // An empty `Content-Security-Policy` protects nothing, so the audit must
    // not read the name alone as a policy.
    let check = audit("check-security-headers.rhai").await;
    let host = Replies::plain(200, "<html>hi</html>")
        .baseline_headers(&[
            ("strict-transport-security", "max-age=31536000"),
            ("content-security-policy", ""),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
        ])
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("content-security-policy")
    );
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item (HTTP 200) is missing 1 security header(s): \
         content-security-policy."
    );
}

// ---------------------------------------------------------------------------
// check-http-methods.rhai
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn methods_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-http-methods.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "methods");
    assert_eq!(meta.class, "risky-http-methods");
    assert_eq!(meta.kinds, vec![InsertionKind::Query]);
    assert_eq!(meta.technique, Technique::Observe);
    assert_eq!(meta.severity, Severity::Info);
    assert_eq!(meta.intensity, Intensity::Light);
    assert_eq!(meta.cost, CheckCost::Light);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.cwe, None, "the class maps to no single CWE");
    assert_eq!(meta.scope, CheckScope::Origin);
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-http-methods.rhai"),
            "the bundled origin names the file, got {path}"
        ),
        other => panic!("a shipped script is Bundled, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn methods_is_vulnerable_against_its_vulnerable_shape() {
    let check = audit("check-http-methods.rhai").await;
    let host = Replies::plain(404, "not found")
        .when_headers(POINT_URL, 204, &[("allow", "GET, PUT, DELETE, TRACE")], "")
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("OPTIONS http://127.0.0.1:8081/item")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("allow: GET, PUT, DELETE, TRACE")
    );
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item advertises PUT, DELETE, TRACE in its Allow header \
         (GET, PUT, DELETE, TRACE); confirm each is intended."
    );
    assert_eq!(host.raw_urls(), vec![POINT_URL.to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn methods_is_clean_against_its_patched_shape() {
    let check = audit("check-http-methods.rhai").await;
    let host = Replies::plain(404, "not found")
        .when_headers(POINT_URL, 204, &[("allow", "GET, HEAD, POST, OPTIONS")], "")
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(
        verdict.detail,
        "http://127.0.0.1:8081/item advertises only safe methods (GET, HEAD, POST, OPTIONS)."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn methods_is_inconclusive_when_the_origin_advertises_nothing() {
    let check = audit("check-http-methods.rhai").await;
    let host = Replies::plain(204, "").build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(
        verdict.detail,
        "OPTIONS http://127.0.0.1:8081/item answered HTTP 204 with no Allow header, \
         so the origin advertises nothing."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_options_audit_asks_with_options() {
    // The whole check is "ask the origin what it will take": a GET would be a
    // different question, and `RecordingHost` keeps only the URL, so this runs
    // against the host that keeps the method too.
    let check = audit("check-http-methods.rhai").await;
    let host = RawLog::new(204, &[("allow", "GET, PUT")]);
    let verdict = run_logged(&check, &host).await;

    assert_eq!(
        host.seen(),
        vec![RawSeen {
            method: "OPTIONS".to_string(),
            url: POINT_URL.to_string(),
            headers: Vec::new(),
        }]
    );
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.evidence.matched.as_deref(), Some("allow: GET, PUT"));
}

// ---------------------------------------------------------------------------
// check-sensitive-paths.rhai
// ---------------------------------------------------------------------------

/// The seven well-known paths the shipped script asks for, in order.
const WELL_KNOWN: [&str; 7] = [
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/actuator/health",
    "/.well-known/security.txt",
    "/phpinfo.php",
    "/web.config",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_declares_one_check_with_valid_meta() {
    let loaded = Loaded::load("check-sensitive-paths.rhai").expect("the shipped script loads");
    let check = loaded.single().expect("exactly one check");
    let meta = check.meta();
    assert_eq!(meta.id, "paths");
    assert_eq!(meta.class, "exposed-path");
    assert_eq!(meta.kinds, vec![InsertionKind::Query]);
    assert_eq!(meta.technique, Technique::Observe);
    assert_eq!(meta.severity, Severity::Medium);
    assert_eq!(meta.intensity, Intensity::Light);
    assert_eq!(meta.cost, CheckCost::Medium);
    assert_eq!(meta.confidence_max, Confidence::Firm);
    assert_eq!(meta.wants_traits, None);
    assert_eq!(meta.cwe, Some(538));
    assert_eq!(meta.scope, CheckScope::Origin);
    match &meta.origin {
        CheckOrigin::Bundled { path } => assert!(
            path.ends_with("check-sensitive-paths.rhai"),
            "the bundled origin names the file, got {path}"
        ),
        other => panic!("a shipped script is Bundled, got {other:?}"),
    }
    assert_eq!(loaded.command_names(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_is_vulnerable_against_its_vulnerable_shape() {
    let check = audit("check-sensitive-paths.rhai").await;
    let host = Replies::plain(404, "Not found")
        .when("/.git/HEAD", 200, "ref: refs/heads/main\n")
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("GET http://127.0.0.1:8081/.git/HEAD")
    );
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("HTTP 200, 21 chars")
    );
    assert_eq!(
        verdict.detail,
        "/.git/HEAD answered 200 on http://127.0.0.1:8081; this well-known path should \
         not be served."
    );
    assert_eq!(
        verdict.location.as_ref().and_then(|l| l.path.as_deref()),
        Some("/.git/HEAD")
    );
    assert_eq!(verdict.more.len(), 0, "only one path answered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_is_clean_against_its_patched_shape() {
    let check = audit("check-sensitive-paths.rhai").await;
    let host = Replies::plain(404, "Not found").build();

    let verdict = run(&check, &origin_point(), &host).await;
    assert_eq!(all_verdicts(&verdict).len(), 1);
    assert_eq!(verdict.outcome, Outcome::Clean);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.location, None);
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("GET http://127.0.0.1:8081/.git/HEAD")
    );
    assert_eq!(
        verdict.detail,
        "None of the 7 well-known sensitive paths answered on http://127.0.0.1:8081."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sensitive_path_audit_probes_the_origin_not_the_point_url() {
    // The point's URL is `http://127.0.0.1:8081/item`; the probe must drop
    // `/item` and ask for the well-known path under the origin itself.
    let check = audit("check-sensitive-paths.rhai").await;
    let host = Replies::plain(404, "Not found").build();
    let _ = run(&check, &origin_point(), &host).await;

    assert_eq!(
        host.raw_urls(),
        WELL_KNOWN
            .iter()
            .map(|path| format!("{ORIGIN}{path}"))
            .collect::<Vec<String>>(),
        "the seven shipped paths, under the origin, and nothing else"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sensitive_path_audit_returns_one_verdict_per_exposed_path() {
    // Two well-known paths answer 200, so the audit returns an array of two
    // verdict maps: the bridge makes the first the root and the second its
    // `more` sibling, and the per-verdict `location.path` is what keeps the
    // two issues apart in the dedupe key.
    let check = audit("check-sensitive-paths.rhai").await;
    let host = Replies::plain(404, "Not found")
        .when("/.git/HEAD", 200, "ref: refs/heads/main\n")
        .when("/.env", 200, "DB_PASSWORD=hunter2\n")
        .build();

    let verdict = run(&check, &origin_point(), &host).await;
    let verdicts = all_verdicts(&verdict);
    assert_eq!(verdicts.len(), 2, "two paths answered");
    for found in &verdicts {
        assert_eq!(found.outcome, Outcome::Vulnerable);
        assert_eq!(found.confidence, Confidence::Firm);
    }
    assert_eq!(
        verdicts
            .iter()
            .map(|v| v.location.as_ref().and_then(|l| l.path.clone()))
            .collect::<Vec<Option<String>>>(),
        vec![Some("/.git/HEAD".to_string()), Some("/.env".to_string())],
        "each verdict locates its own path"
    );
    assert_eq!(
        verdicts[1].evidence.payload.as_deref(),
        Some("GET http://127.0.0.1:8081/.env")
    );
    assert_eq!(
        verdicts[1].evidence.matched.as_deref(),
        Some("HTTP 200, 20 chars")
    );
    assert_eq!(
        verdicts[1].detail,
        "/.env answered 200 on http://127.0.0.1:8081; this well-known path should not \
         be served."
    );
}

// ---------------------------------------------------------------------------
// What all four share
// ---------------------------------------------------------------------------

/// The four shipped files this task owns.
const SITE_LEVEL: [&str; 4] = [
    "check-cors.rhai",
    "check-security-headers.rhai",
    "check-http-methods.rhai",
    "check-sensitive-paths.rhai",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_level_audit_sends_one_request_for_the_whole_origin() {
    // `cors`, `headers` and `methods` are one request each, whatever point
    // carried them; `paths` is the bounded well-known list and nothing more.
    for (file, most) in [
        ("check-cors.rhai", 1),
        ("check-security-headers.rhai", 0),
        ("check-http-methods.rhai", 1),
        ("check-sensitive-paths.rhai", 7),
    ] {
        let check = audit(file).await;
        let host = Replies::plain(200, "{}")
            .baseline_headers(&[("content-type", "text/html")])
            .build();
        let _ = run(&check, &origin_point(), &host).await;
        assert_eq!(
            host.raw_urls().len(),
            most,
            "{file} composed {} requests, not the {most} it is allowed",
            host.raw_urls().len()
        );
        assert_eq!(
            host.payloads(),
            Vec::<String>::new(),
            "{file} is an origin audit: it payloads no insertion point"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_site_level_audits_carry_no_poc_hint() {
    // None of the four classes is a D6 must-hint class: there is no payload to
    // replay, so a hint would be a matcher against a request the PoC engine
    // cannot rebuild.
    let cases: [(&str, Arc<aitm_scan_model::testing::RecordingHost>); 4] = [
        (
            "check-cors.rhai",
            Replies::plain(200, "{}")
                .when_headers(
                    POINT_URL,
                    200,
                    &[("access-control-allow-origin", CANARY)],
                    "{}",
                )
                .build(),
        ),
        (
            "check-security-headers.rhai",
            Replies::plain(200, "hi").build(),
        ),
        (
            "check-http-methods.rhai",
            Replies::plain(200, "")
                .when_headers(POINT_URL, 204, &[("allow", "GET, DELETE")], "")
                .build(),
        ),
        (
            "check-sensitive-paths.rhai",
            Replies::plain(404, "Not found")
                .when("/.env", 200, "DB_PASSWORD=hunter2\n")
                .build(),
        ),
    ];
    for (file, host) in cases {
        let check = audit(file).await;
        let verdict = run(&check, &origin_point(), &host).await;
        assert_eq!(
            verdict.outcome,
            Outcome::Vulnerable,
            "{file} must reach its finding for this assertion to mean anything"
        );
        for found in all_verdicts(&verdict) {
            assert!(
                found.poc_hint.is_none(),
                "{file} supplied a poc_hint; its class is not a must-hint class"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_audit_on_a_point_with_no_url_concludes_nothing() {
    // `InsertionPoint::url` is an `Option`, so the bridge hands a check `()`
    // for a point no URL was recorded for, and an origin-scoped audit has no
    // origin to attribute an answer to. That must be a sentence an operator
    // can read, not a Rhai error about `index_of` on a unit.
    for file in SITE_LEVEL {
        let check = audit(file).await;
        let mut urlless = origin_point();
        urlless.url = None;
        let host = Replies::plain(200, "hi").build();

        let verdict = run(&check, &urlless, &host).await;
        assert_eq!(
            verdict.outcome,
            Outcome::Inconclusive,
            "{file} answered {:?}: {}",
            verdict.outcome,
            verdict.detail
        );
        assert_eq!(
            verdict.detail, "This insertion point carries no URL, so there is no origin to audit.",
            "{file} must say why it concluded nothing"
        );
        assert_eq!(
            host.raw_urls(),
            Vec::<String>::new(),
            "{file} must not compose a request without an origin"
        );
    }
}

#[test]
fn the_site_level_audits_never_call_sleep() {
    for file in SITE_LEVEL {
        let source = std::fs::read_to_string(rhai_harness::active_path(file))
            .unwrap_or_else(|err| panic!("{file}: {err}"));
        assert!(
            !source.contains("sleep("),
            "{file} calls sleep(); a check waits through the probe host"
        );
    }
}

#[test]
fn the_site_level_audits_use_probe_not_a_handbuilt_query() {
    for file in SITE_LEVEL {
        let source = std::fs::read_to_string(rhai_harness::active_path(file))
            .unwrap_or_else(|err| panic!("{file}: {err}"));
        assert!(
            source.contains("probe."),
            "{file} must reach the target through the probe host"
        );
        assert!(
            !source.contains("http.send"),
            "{file} sends outside the probe host"
        );
        assert!(
            !source.contains("url_encode(param)"),
            "{file} builds its own query string"
        );
        assert!(
            !source.contains("add_command"),
            "{file} is an active check, not a command"
        );
    }
}
