//! PR 3b, security Minor 1 — the shipped `check-nosqli-json.rhai` guards, run
//! under the **production** rhai feature set.
//!
//! Why this test lives in `crates/aitm` and not beside the script's other
//! tests: `aitm-plugin-rhai` builds rhai with `features = ["sync"]` in
//! production and with `["sync", "metadata"]` in its own dev-dependencies.
//! Those two builds give the script a *different* `parse_json`:
//!
//! * with `metadata` — the build every test in
//!   `crates/aitm-scan-checks-http/tests/rhai_new_scripts.rs` runs under —
//!   `parse_json` is `serde_json::from_str`;
//! * without it — what ships — `parse_json` is `Engine::parse_json`, which
//!   lexes the text, parses it as a global *expression* and evaluates it on
//!   the scripting engine. Malformed text there is a rhai `ErrorParsing`,
//!   which `try`/`catch` cannot catch, so the whole check ends as an `error`
//!   verdict.
//!
//! That is why the script judges a document *before* handing it over, with
//! `holds_a_bare_mask` and `is_whole_json_object`. This test pins those two
//! guards against the parser that actually ships: `cargo test -p aitm` builds
//! this crate's dependency graph with production features (a dependency's
//! dev-features are not unified into it), so the script here meets
//! `Engine::parse_json`. Under `cargo test --workspace`, cargo unifies
//! `metadata` on and the same assertions run against `serde_json` — every
//! assertion below is written to hold either way, so the test is stable under
//! both, and only `cargo test -p aitm` exercises the shipping parser.
//!
//! No socket is bound: every probe ends in [`CannedClient`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm::scripts::LateHandles;
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::redact::scrub_text_wide;
use aitm_core::{
    Body, BrowserDriver, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Plugin, ProxyClient,
    ScopeEntry, ScopeRateGuard,
};
use aitm_plugin_rhai::{wire, MemoryFindingSink, RhaiConfig, ScriptEntry, ScriptServices};
use aitm_plugin_scanner::worker::ArcHost;
use aitm_scan_model::check::Verdict;
use aitm_scan_model::ids::FlowRef;
use aitm_scan_model::point::InsertionPoint;
use aitm_scan_model::profile::ScanProfile;
use aitm_scan_model::session::SessionMaterial;
use aitm_scan_model::traits::{Check, JobCtx};
use aitm_scan_model::vocab::{Confidence, InsertionKind, LaneKind, Outcome, PointTrait};
use futures::future::BoxFuture;

/// The shipped script, loaded from the repository's own
/// `scripts/bundled/active/` — the file the release carries, not a fixture.
fn shipped_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
        .join("active")
        .join("check-nosqli-json.rhai")
}

/// The origin every point here addresses; the only entry in the scope.
const ORIGIN: &str = "ex.test";

/// The body the lane would hand a document check for a login request whose
/// password the scrub masked *in place*, quotes and all. Asserted below to be
/// the real scrubber's output rather than a guess.
const LOGIN_BODY: &str = r#"{"username":"alice","password":"[redacted]"}"#;

/// Probes one run of this harness may spend.
const BUDGET: u32 = 64;

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-rhai-nosqli-{tag}-{nanos}-{n}"))
}

/// Answers every send `401` with a short JSON body and records the request
/// body it was given, so a test can read exactly what the script put on the
/// wire. Nothing here reaches a socket.
struct CannedClient {
    bodies: Mutex<Vec<String>>,
}

impl CannedClient {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bodies: Mutex::new(Vec::new()),
        })
    }

    /// Every request body this client was asked to send, in order.
    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().expect("bodies lock").clone()
    }

    fn answer(&self, req: HttpRequest) -> HttpFlow {
        let text = match &req.body {
            Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            _ => String::new(),
        };
        self.bodies.lock().expect("bodies lock").push(text);
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "application/json");
        let conn = ConnInfo {
            peer: "127.0.0.1:0".parse().expect("loopback addr"),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        };
        HttpFlow {
            id: FlowId::new(),
            request: req,
            response: Some(HttpResponse {
                status: 401,
                version: HttpVersion::Http11,
                headers,
                trailers: HeaderMap::new(),
                body: Body::Bytes(br#"{"ok":false}"#.to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            }),
            client_conn: conn.clone(),
            server_conn: Some(conn),
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }
}

impl ProxyClient for CannedClient {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        let flow = self.answer(req);
        Box::pin(async move { Ok(flow) })
    }
}

/// The job a lane builds its probe host over. The engine's own `JobCtx` lives
/// behind `scan.start`; this one carries the same five handles and a budget,
/// which is all `HttpProbeHost` reads.
struct TestJob {
    profile: ScanProfile,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    deadline: Instant,
    budget: AtomicU32,
    markers: AtomicU32,
}

impl JobCtx for TestJob {
    fn job_id(&self) -> &str {
        "job-nosqli-json"
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn client(&self) -> Arc<dyn ProxyClient> {
        Arc::clone(&self.client)
    }

    fn store(&self) -> Arc<dyn FlowStore> {
        Arc::clone(&self.store)
    }

    fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        Arc::clone(&self.guard)
    }

    fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
        None
    }

    fn session(&self) -> Option<Arc<SessionMaterial>> {
        None
    }

    fn charge(&self, units: u32) -> bool {
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            if left < units {
                return false;
            }
            match self.budget.compare_exchange_weak(
                left,
                left - units,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(seen) => left = seen,
            }
        }
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::Relaxed)
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn cancelled(&self) -> bool {
        false
    }

    fn marker(&self) -> String {
        format!("m{:04x}", self.markers.fetch_add(1, Ordering::Relaxed))
    }
}

/// An `entire_body` point on a captured JSON `POST`, carrying `example`
/// verbatim.
///
/// The manual verb `check.nosqli-json` cannot stand in for this: it derives its
/// point from a synthesized `GET` and keeps only `InsertionKind::Query`
/// (`manual_check.rs`), so the document branch is unreachable through it. The
/// point is built here from the same public pieces the lane uses —
/// `aitm_scan_model::InsertionPoint`, a flow in the job's store, and
/// `Lane::probe_host_for` — so the check still meets a real `HttpProbeHost`.
fn body_point(flow: FlowId, example: &str) -> InsertionPoint {
    InsertionPoint {
        id: "p1".to_string(),
        lane: LaneKind::Http,
        kind: InsertionKind::EntireBody,
        name: "body".to_string(),
        path: None,
        example: Some(example.to_string()),
        flow: Some(FlowRef(flow)),
        site_node: None,
        traits: vec![PointTrait::Json, PointTrait::Structured],
        frequency: 1,
        method: Some("POST".to_string()),
        url: Some(format!("http://{ORIGIN}/api/login")),
    }
}

/// The captured login request the point is derived from.
fn captured_login_flow(body: &str) -> HttpFlow {
    let mut headers = HeaderMap::new();
    headers.set("Host", ORIGIN);
    headers.set("Content-Type", "application/json");
    let conn = ConnInfo {
        peer: "127.0.0.1:0".parse().expect("loopback addr"),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    };
    HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "http".into(),
            authority: ORIGIN.into(),
            path: "/api/login".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(body.as_bytes().to_vec()),
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn,
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }
}

/// The whole wiring, once: the scripting tier over the shipped script, the
/// proxy assembled with it (which is what runs each script's `load(reg)`), and
/// the HTTP lane the probe hosts come from.
struct Harness {
    check: Arc<dyn Check>,
    lane: Arc<dyn aitm_scan_model::Lane>,
    guard: Arc<dyn ScopeRateGuard>,
    ca_dir: PathBuf,
}

impl Harness {
    /// Run the shipped check against an `entire_body` point whose example is
    /// `example`, and report the verdict with every body the client saw.
    async fn run(&self, example: &str) -> (Verdict, Vec<String>) {
        let canned = CannedClient::new();
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let flow = captured_login_flow(example);
        let flow_id = flow.id;
        store.insert(Flow::Http(flow));

        let job: Arc<dyn JobCtx> = Arc::new(TestJob {
            profile: ScanProfile::default(),
            client: canned.clone(),
            store,
            guard: Arc::clone(&self.guard),
            deadline: Instant::now() + Duration::from_secs(30),
            budget: AtomicU32::new(BUDGET),
            markers: AtomicU32::new(0),
        });

        let point = body_point(flow_id, example);
        let host = ArcHost(Arc::from(
            self.lane
                .probe_host_for(&point, Arc::clone(&job))
                .expect("the http lane hosts an entire_body point"),
        ));
        let verdict = self.check.run(&point, &host).await;
        (verdict, canned.bodies())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ca_dir);
    }
}

fn harness() -> Harness {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir("nosqli-json");
    cfg.scope.entries.push(ScopeEntry {
        host: ORIGIN.to_string(),
    });

    let handles = LateHandles::new();
    let svc = ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: None,
        guard: handles.clone(),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    let tier = wire::build(
        RhaiConfig {
            scripts: vec![ScriptEntry::new(shipped_script())],
            ..RhaiConfig::default()
        },
        svc,
    )
    .expect("the scripting tier builds");
    assert!(
        tier.errors.is_empty(),
        "the shipped script compiles under the production feature set: {:?}",
        tier.errors
    );

    let checks = Arc::clone(&tier.checks);
    let assembled = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            // The host plugin's `register` is what runs `load(reg)`, and that
            // is where `reg.add_check` fills the registry below.
            plugins: vec![Box::new(tier.host) as Box<dyn Plugin>],
            commands: vec![Box::new(tier.commands)],
            script_checks: Some(Arc::clone(&checks)),
            ..ScriptWiring::default()
        },
    )
    .expect("assemble the proxy over the tier's checks");
    let Assembled { proxy, .. } = assembled;

    let snapshot = checks.snapshot();
    assert_eq!(
        snapshot.len(),
        1,
        "the shipped script registered exactly one check"
    );
    let check = Arc::clone(&snapshot[0]);
    assert_eq!(check.meta().id, "nosqli-json");
    // The verb is minted for it, as it is for every catalogue entry — but it
    // only ever builds a `query` point, so the document branch below is driven
    // through the lane instead.
    assert!(
        proxy.registry_arc().command("check.nosqli-json").is_some(),
        "the scanner minted the manual verb for the shipped check"
    );

    Harness {
        check,
        lane: aitm_scan_http::lane().expect("the http lane is built"),
        guard: proxy.guard(),
        ca_dir: cfg.ca.dir.clone(),
    }
}

/// The two guards that keep a captured body away from `parse_json`, and the
/// one body that is allowed through, all against the engine the binary ships.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shipped_nosqli_json_guards_hold_under_the_production_parser() {
    let harness = harness();

    // (1) A cut example. The lane shows a point's value up to a cap, so this
    // one ends inside a string: not a whole document, and `Engine::parse_json`
    // would die on it uncatchably.
    let (verdict, bodies) = harness
        .run(r#"{"username":"alice","password":"[redac"#)
        .await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{verdict:?}");
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(
        verdict.detail,
        "the JSON document is longer than the point's example; document-level \
         operators need the whole body"
    );
    assert_eq!(
        bodies,
        Vec::<String>::new(),
        "a cut example costs the job nothing, not even a baseline"
    );

    // (2) A body the real scrubber masked where the value was not quoted. The
    // example is built by `scrub_text_wide`, the same function
    // `aitm-scan-http::redact::example` applies, so the mask token is the
    // core's own and not a literal copied into this file.
    let masked = scrub_text_wide(r#"{"user":"a","api_key":12345}"#);
    assert_eq!(masked, r#"{"user":"a","api_key":[redacted]}"#);
    let (verdict, bodies) = harness.run(&masked).await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive, "{verdict:?}");
    assert_eq!(verdict.confidence, Confidence::Tentative);
    assert_eq!(
        verdict.detail,
        "a secret in this JSON body was masked before the check saw it; \
         document-level operators need the whole body"
    );
    assert_eq!(
        bodies,
        Vec::<String>::new(),
        "a masked example costs the job nothing either"
    );

    // (3) The ordinary case: the scrub left the mask inside the quotes, so the
    // body is still one whole JSON document. It reaches `parse_json` — the
    // real one, whichever is in this build — and the document branch places an
    // operator at each of the two string fields.
    assert_eq!(
        scrub_text_wide(r#"{"username":"alice","password":"hunter2"}"#),
        LOGIN_BODY,
        "the quoted-mask body is the scrubber's own output"
    );
    let (verdict, bodies) = harness.run(LOGIN_BODY).await;
    assert_eq!(
        verdict.outcome,
        Outcome::Clean,
        "every reply was 401, so nothing moved: {verdict:?}"
    );
    assert_eq!(
        bodies.len(),
        5,
        "one baseline and two operators at each of the two string fields: {bodies:?}"
    );
    assert_eq!(bodies[0], LOGIN_BODY, "the baseline is the captured body");
    let operator_bodies = &bodies[1..];
    assert!(
        operator_bodies
            .iter()
            .all(|body| body.contains(r#""$ne""#) || body.contains(r#""$gt""#)),
        "every probe after the baseline carries a one-key operator document: {operator_bodies:?}"
    );
    assert_eq!(
        operator_bodies
            .iter()
            .filter(|body| body.contains(r#""$ne""#))
            .count(),
        2,
        "`$ne` went to both string fields: {operator_bodies:?}"
    );
    assert!(
        operator_bodies
            .iter()
            .any(|body| body.contains(r#""password":{"$ne""#)),
        "the masked-but-quoted field is probed like any other string: {operator_bodies:?}"
    );
}
