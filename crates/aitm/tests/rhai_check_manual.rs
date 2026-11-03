//! Task 8 (amendment 70) — a Rhai-declared check, run by hand through the
//! binary's own wiring.
//!
//! Both plugins in one harness: the scripting tier declares a check with
//! `reg.add_check`, the scanner is registered over that same `CheckRegistry`
//! and mints `check.detail-echo`, and the manual verb runs the script closure
//! against a canned client. Three joins are proved at once that no single-crate
//! test can reach:
//!
//! * the amendment-62/75 precondition — the worker lends an *owning* shared
//!   host, so `probe.send` inside a script check resolves and actually sends
//!   (a bare host would make the bridge answer "ProbeHost::shared returned
//!   none" instead);
//! * amendment 67 — the bridge scrubs a verdict's `detail`, so a credential the
//!   script echoed comes back `[redacted]` on the bus;
//! * the manual path's private store — the operator's capture list does not
//!   grow a request nobody made.
//!
//! No socket is bound: every probe ends in [`CannedClient`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm::scripts::LateHandles;
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::{
    AgentPolicy, Body, CommandHost, Config, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, Params, Plugin, ProxyClient,
    ScopeEntry, Value,
};
use aitm_plugin_rhai::{wire, MemoryFindingSink, RhaiConfig, ScriptEntry, ScriptServices};
use aitm_plugin_scanner::jobs::ScanServices;
use futures::future::BoxFuture;

/// The one-check script this test wires in.
const CHECK_SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/check-detail-echo.rhai"
);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-rhai-check-{tag}-{nanos}-{n}"))
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Answers every send with `200 text/plain "ok"` over the request it was given,
/// and records the request path. Nothing in this test reaches a socket.
struct CannedClient {
    paths: Mutex<Vec<String>>,
}

impl CannedClient {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            paths: Mutex::new(Vec::new()),
        })
    }

    /// Every request path this client was asked for, in order.
    fn paths(&self) -> Vec<String> {
        self.paths.lock().expect("paths lock").clone()
    }

    fn answer(&self, req: HttpRequest) -> HttpFlow {
        self.paths
            .lock()
            .expect("paths lock")
            .push(req.path.clone());
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "text/plain");
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
                status: 200,
                version: HttpVersion::Http11,
                headers,
                trailers: HeaderMap::new(),
                body: Body::Bytes(b"ok".to_vec()),
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

/// The whole join, exactly as `main.rs` builds it: late handles, the scripting
/// tier over them, the proxy assembled with the tier's check registry, the
/// scanner's services bound to the proxy's handles, then `check.detail-echo`
/// invoked by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rhai_check_runs_by_hand_through_the_scanner_s_manual_verb() {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir("detail-echo");
    cfg.scope.entries.push(ScopeEntry {
        host: "ex.test".to_string(),
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
            scripts: vec![ScriptEntry::new(CHECK_SCRIPT)],
            ..RhaiConfig::default()
        },
        svc,
    )
    .expect("the scripting tier builds");
    assert!(
        tier.errors.is_empty(),
        "the fixture compiles and loads: {:?}",
        tier.errors
    );

    let checks = Arc::clone(&tier.checks);
    let assembled = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            // The one host plugin dispatches every loaded script from a single
            // chain position; its `register` is what runs each script's
            // `load(reg)`, and that is where `reg.add_check` fills the registry
            // below — so the host has to be wired, exactly as `main.rs` does.
            plugins: vec![Box::new(tier.host) as Box<dyn Plugin>],
            commands: vec![Box::new(tier.commands)],
            script_checks: Some(Arc::clone(&checks)),
            ..ScriptWiring::default()
        },
    )
    .expect("assemble the proxy over the tier's checks");
    assert_eq!(
        checks.len(),
        1,
        "the tier registered the fixture's check while loading"
    );
    let Assembled {
        proxy,
        scan_late,
        job_bus,
        ..
    } = assembled;

    let store = proxy.store();
    let guard = proxy.guard();
    let canned = CannedClient::new();
    let client: Arc<dyn ProxyClient> = canned.clone();

    // The scanner runs on the proxy's own handles (call B3), with the canned
    // client where the pipeline client would be.
    scan_late.bind(ScanServices {
        store: store.clone(),
        client: client.clone(),
        guard: guard.clone(),
        browser: None,
        egress: None,
        l4: None,
        jobs: job_bus.clone(),
        // The shipped default posture (`Config::default().mcp.policy`); the
        // manual verb is a direct registry invocation, so nothing here reads it.
        agent_policy: Arc::new(|| AgentPolicy::Auto),
        rt: tokio::runtime::Handle::current(),
        config: Arc::new(cfg.clone()),
    });
    handles.bind_proxy(store.clone(), client.clone(), guard.clone());

    let registry = proxy.registry_arc();
    let command = registry
        .command("check.detail-echo")
        .expect("the scanner minted `check.detail-echo` for the script's check");

    let flows_before = store.count();
    let host = CommandHost::new(store.as_ref(), canned.as_ref(), guard.as_ref(), None);
    let result = command
        .invoke(
            params(&[
                ("url", Value::Str("http://ex.test/search?q=1".into())),
                ("param", Value::Str("q".into())),
            ]),
            &host,
        )
        .expect("the manual run returns a verdict");

    let Value::Object(verdict) = &result else {
        panic!("the verdict is an object: {result:?}");
    };
    assert_eq!(
        verdict.get("outcome"),
        Some(&Value::Str("clean".into())),
        "the script's own outcome came back: {verdict:?}"
    );
    assert_eq!(
        verdict.get("detail"),
        Some(&Value::Str(
            "status 200 Authorization: [redacted]".to_string()
        )),
        "the probe reached the canned client (status 200) and the bridge \
         scrubbed `detail` (amendment 67): {verdict:?}"
    );

    assert_eq!(
        canned.paths(),
        vec!["/search?q=aitm-probe".to_string()],
        "exactly one probe, with the payload at the named parameter"
    );
    assert_eq!(
        store.count(),
        flows_before,
        "the manual path's synthetic request stays in its private store"
    );

    let _ = std::fs::remove_dir_all(&cfg.ca.dir);
}
