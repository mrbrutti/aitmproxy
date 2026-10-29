//! Task 8 — `ScriptPlugin` + hook dispatch: a compiled script is one `Plugin`
//! in the ordered chain. Its hook edits apply back through the effect model
//! (AC-M3-1), `halt()` short-circuits the chain like `Verdict::Halt` (AC-M3-2,
//! RF#3), a hook that errors leaves the flow untouched and surfaces an
//! `Event::Error` (AC-M3-12, RF#1), and a runaway hook is aborted by the
//! budget without stalling the chain (AC-M3-6).
//!
//! Every test drives the real `aitm_core::Chain` over a `Registry` holding the
//! script plugin followed by a probe plugin, so the short-circuit and the
//! chain's plugin locking are exercised as the proxy exercises them. Hooks run
//! under `block_in_place`, so every test runs on a multi-thread runtime.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, Chain, ConnInfo, Event, Flow, FlowCtx, FlowError, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, Plugin, ProxyClient,
    Registry, StdGuard, Verdict, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptMeta};
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::flow_api::register_flow_api;
use aitm_plugin_rhai::host_core::{
    FindingCapability, LogCapability, MemoryFindingSink, Options, ScriptCapability, ScriptServices,
};
use aitm_plugin_rhai::host_net::HttpCapability;
use aitm_plugin_rhai::plugin::{ErrorSink, ScriptHandle, ScriptPlugin};
use rhai::Engine;

/// A loop that never ends and does real work each turn, so the optimizer
/// cannot fold it away and every iteration costs operations.
const RUNAWAY_HOOK: &str = "fn on_request(flow) { let n = 0; loop { n += 1; } }";

/// A client that is never reached: no test sends.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// What the plugin registered after the script saw.
#[derive(Default)]
struct ProbeLog {
    events: Mutex<Vec<Event>>,
}

impl ProbeLog {
    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn errors(&self) -> Vec<FlowError> {
        self.events()
            .into_iter()
            .filter_map(|ev| match ev {
                Event::Error { kind, .. } => Some(kind),
                _ => None,
            })
            .collect()
    }
}

/// A native plugin registered *after* the script: records every event it is
/// handed, so a test can prove the script's `halt()` kept it from running.
struct Probe(Arc<ProbeLog>);

impl Plugin for Probe {
    fn name(&self) -> &str {
        "probe"
    }

    fn on_event(&mut self, ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        self.0
            .events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ev.clone());
        Verdict::Continue
    }
}

fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("addr"),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// `POST http://ex.test/admin/users` with one header and a small body.
fn http_flow() -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "ex.test");
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/admin/users".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(b"name=x".to_vec()),
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// A WebSocket flow holding one client→server text frame.
fn ws_flow() -> Flow {
    Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: vec![WsMessage {
            dir: WsDir::ClientToServer,
            opcode: WsOpcode::Text,
            data: b"secret".to_vec(),
            timestamp: SystemTime::now(),
            injected: false,
        }],
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn http(flow: &Flow) -> &HttpFlow {
    match flow {
        Flow::Http(f) => f,
        Flow::WebSocket(_) => panic!("expected an HTTP flow"),
    }
}

fn config(limits: RhaiLimits, hook_timeout: Duration) -> RhaiConfig {
    RhaiConfig {
        limits,
        hook_timeout,
        ..RhaiConfig::default()
    }
}

fn meta(name: &str) -> ScriptMeta {
    ScriptMeta {
        name: name.to_string(),
        api: "1".to_string(),
        path: format!("{name}.rhai").into(),
        hooks: Vec::new(),
    }
}

/// The services, a hardened engine with the flow API and the host core
/// registered, and the compiled script — what the loader (Task 9) will build.
struct Fixture {
    store: Arc<MemFlowStore>,
    services: ScriptServices,
    engine: Arc<Engine>,
    cfg: RhaiConfig,
}

impl Fixture {
    fn new(cfg: RhaiConfig) -> Self {
        let store = Arc::new(MemFlowStore::new());
        let services = ScriptServices {
            store: store.clone(),
            client: Arc::new(StubClient),
            browser: None,
            guard: Arc::new(StdGuard::default()),
            findings: Arc::new(MemoryFindingSink::new()),
            rt: tokio::runtime::Handle::current(),
        };
        let mut engine = build_engine(&cfg.limits, cfg.hook_timeout);
        register_flow_api(&mut engine);
        // `http` rides a never-reached client behind an empty-scope guard, so a
        // hook that calls it is always denied — the denial path under test.
        let providers: [&dyn ScriptCapability; 3] =
            [&LogCapability, &FindingCapability, &HttpCapability];
        for provider in providers {
            provider.register(&mut engine, &services);
        }
        Self {
            store,
            services,
            engine: Arc::new(engine),
            cfg,
        }
    }

    fn plugin(&self, name: &str, src: &str) -> ScriptPlugin {
        let ast = self.engine.compile(src).expect("the script compiles");
        ScriptPlugin::new(
            meta(name),
            Arc::clone(&self.engine),
            ast,
            self.services.clone(),
            Options::default(),
            &self.cfg,
        )
    }
}

/// The script plugin followed by the probe, in a real chain over the fixture's
/// store; the chain itself is the sink the script's `Event::Error`s go to, so
/// the probe sees them the way a native plugin would.
struct Harness {
    fixture: Fixture,
    chain: Arc<Chain>,
    probe: Arc<ProbeLog>,
    /// The script's shared handle, taken before the plugin is boxed away.
    handle: Arc<ScriptHandle>,
}

impl Harness {
    fn new(src: &str, cfg: RhaiConfig) -> Self {
        let fixture = Fixture::new(cfg);
        let errors = Arc::new(ErrorSink::default());
        let plugin = fixture
            .plugin("under-test", src)
            .with_error_sink(Arc::clone(&errors));
        let handle = plugin.handle();
        let probe = Arc::new(ProbeLog::default());

        let mut registry = Registry::new();
        registry.add_plugin(Box::new(plugin));
        registry.add_plugin(Box::new(Probe(Arc::clone(&probe))));
        let chain = Arc::new(Chain::new(Arc::new(registry), fixture.store.clone()));
        // The chain exists only once the plugins are registered, so the
        // script's error sink binds late — the wiring (Task 15) does the same.
        errors.bind(chain.clone());
        Self {
            fixture,
            chain,
            probe,
            handle,
        }
    }

    fn default(src: &str) -> Self {
        Self::new(src, config(RhaiLimits::default(), Duration::from_secs(5)))
    }

    fn insert(&self, flow: Flow) -> FlowId {
        self.fixture.store.insert(flow)
    }

    async fn dispatch(&self, ev: Event) -> Verdict {
        self.chain.dispatch(ev).await
    }

    fn flow(&self, id: FlowId) -> Flow {
        self.fixture
            .store
            .get(id)
            .expect("the flow is in the store")
    }

    /// Wait (bounded) for the asynchronously emitted `Event::Error`s to reach
    /// the probe.
    async fn wait_for_errors(&self, n: usize) -> Vec<FlowError> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let errors = self.probe.errors();
            if errors.len() >= n || Instant::now() >= deadline {
                return errors;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

fn script_error_message(err: &FlowError) -> &str {
    match err {
        FlowError::Protocol(msg) => msg,
        other => panic!("a script error reaches the bus as FlowError::Protocol, got {other:?}"),
    }
}

/// AC-M3-1: a hook's edit is applied to the live flow, and the chain goes on
/// to the next plugin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_request_adds_header() {
    let h = Harness::default(
        r#"fn on_request(flow) { flow.request.headers.set("X-Aitm", "1"); flow.mark("tagged"); }"#,
    );
    let id = h.insert(http_flow());

    let verdict = h.dispatch(Event::Request(id)).await;

    assert_eq!(verdict, Verdict::Continue);
    let flow = h.flow(id);
    let f = http(&flow);
    assert_eq!(f.request.headers.get("X-Aitm"), Some("1"));
    assert_eq!(
        f.request.headers.get("Host"),
        Some("ex.test"),
        "existing headers survive"
    );
    assert_eq!(f.metadata.marks, vec!["tagged".to_string()]);
    assert_eq!(
        h.probe.events(),
        vec![Event::Request(id)],
        "a hook that returns normally lets the next plugin run"
    );
}

/// AC-M3-2, RF#3: `set_response` + `halt()` — the client gets the response,
/// the chain returns `Halt`, and the plugin after the script never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_response_halt_short_circuits() {
    let h = Harness::default(
        r#"
        fn on_request(flow) {
            if flow.request.path.starts_with("/admin") && flow.request.method != "GET" {
                flow.set_response(403, #{ "Content-Type": "text/plain" }, "blocked by aitm");
                return halt();
            }
        }
        "#,
    );
    let id = h.insert(http_flow());

    let verdict = h.dispatch(Event::Request(id)).await;

    assert_eq!(verdict, Verdict::Halt);
    let flow = h.flow(id);
    let resp = http(&flow)
        .response
        .as_ref()
        .expect("the short-circuit response is on the flow");
    assert_eq!(resp.status, 403);
    assert_eq!(resp.headers.get("content-type"), Some("text/plain"));
    assert!(matches!(&resp.body, Body::Bytes(b) if b == b"blocked by aitm"));
    assert!(
        h.probe.events().is_empty(),
        "the plugin after the script must not run: {:?}",
        h.probe.events()
    );
}

/// AC-M3-12, RF#1: a hook that edits the flow and then throws leaves the flow
/// byte-for-byte unchanged, emits an `Event::Error`, and the chain continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errored_hook_discards_edits() {
    let h = Harness::default(
        r#"
        fn on_request(flow) {
            flow.request.headers.set("X-Aitm", "1");
            flow.request.method = "DELETE";
            flow.mark("seen");
            flow.set_response(500, #{}, "half-done");
            throw "boom";
        }
        "#,
    );
    let original = http_flow();
    let id = h.insert(original.clone());

    let verdict = h.dispatch(Event::Request(id)).await;

    assert_eq!(verdict, Verdict::Continue, "an errored hook is Continue");
    let flow = h.flow(id);
    let f = http(&flow);
    let before = http(&original);
    assert_eq!(f.request.method, before.request.method);
    assert_eq!(
        f.request.headers.get("X-Aitm"),
        None,
        "the edit was discarded"
    );
    assert_eq!(f.request.headers.get("Host"), Some("ex.test"));
    assert!(f.metadata.marks.is_empty(), "the mark was discarded");
    assert!(
        f.response.is_none(),
        "the set_response effect was discarded"
    );
    assert!(matches!(f.intercept, InterceptState::Observed));

    let errors = h.wait_for_errors(1).await;
    assert_eq!(errors.len(), 1, "exactly one Event::Error: {errors:?}");
    let msg = script_error_message(&errors[0]);
    assert!(msg.starts_with("script: "), "bus message: {msg}");
    assert!(msg.contains("under-test"), "names the script: {msg}");
    assert!(msg.contains("on_request"), "names the hook: {msg}");
    assert!(msg.contains("boom"), "carries what was thrown: {msg}");

    assert!(
        h.probe.events().contains(&Event::Request(id)),
        "the chain went on to the next plugin: {:?}",
        h.probe.events()
    );
}

/// Quality review (M3, Important): a `flow.response` write in `on_request` —
/// a plausible slip for `flow.request` — must not fabricate a status-0
/// response the proxy then serves as a short-circuit. It is a hook error: the
/// flow is forwarded with no response, the chain continues, and the bus says
/// what to use instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_write_in_the_request_phase_is_an_error_not_a_short_circuit() {
    let h = Harness::default(
        r#"fn on_request(flow) { flow.response.headers.set("X-Seen", "1"); flow.response.status = 204; }"#,
    );
    let id = h.insert(http_flow());

    let verdict = h.dispatch(Event::Request(id)).await;

    assert_eq!(verdict, Verdict::Continue);
    assert!(
        http(&h.flow(id)).response.is_none(),
        "no response was fabricated on the flow"
    );
    assert!(
        h.probe.events().contains(&Event::Request(id)),
        "the chain went on"
    );
    let errors = h.wait_for_errors(1).await;
    assert_eq!(errors.len(), 1, "{errors:?}");
    let msg = script_error_message(&errors[0]);
    assert!(
        msg.contains("no response yet") && msg.contains("set_response"),
        "the error names the fix: {msg}"
    );
}

/// Spec review (M3, Important): an uncaught guard refusal reaches the bus in
/// the spec's pinned *denial* format — capability, typed reason, and the
/// scope help line — not as a generic runtime error. A caught one is still a
/// value the script can render and inspect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_capability_reaches_the_bus_in_the_pinned_format() {
    let h =
        Harness::default(r#"fn on_request(flow) { http.send(#{ url: "http://evil.test/" }); }"#);
    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);

    let errors = h.wait_for_errors(1).await;
    assert_eq!(errors.len(), 1, "{errors:?}");
    let msg = script_error_message(&errors[0]);
    assert!(
        msg.contains("was denied capability 'http.send'"),
        "pinned denial line: {msg}"
    );
    assert!(
        msg.contains("reason: OutOfScope(\"evil.test\")"),
        "typed reason: {msg}"
    );
    assert!(msg.contains("scope.add"), "scope help line: {msg}");

    // Caught, the denial renders as text and exposes its parts.
    let h = Harness::default(
        r#"
        fn on_request(flow) {
            try { http.send(#{ url: "http://evil.test/" }); }
            catch (e) {
                flow.request.headers.set("X-Denied", "" + e);
                flow.request.headers.set("X-Denied-Capability", e.capability);
                flow.request.headers.set("X-Denied-Host", e.host);
            }
        }
        "#,
    );
    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    let flow = h.flow(id);
    let f = http(&flow);
    assert_eq!(
        f.request.headers.get("X-Denied"),
        Some("http.send to evil.test denied: host evil.test is out of scope")
    );
    assert_eq!(
        f.request.headers.get("X-Denied-Capability"),
        Some("http.send")
    );
    assert_eq!(f.request.headers.get("X-Denied-Host"), Some("evil.test"));
}

/// AC-M3-6, RF#4: a runaway hook is aborted by whichever budget it exhausts,
/// the error says which, and dispatch returns promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runaway_hook_aborts() {
    // A busy hook: small operation budget, generous clock.
    let limits = RhaiLimits {
        max_operations: 10_000,
        ..RhaiLimits::default()
    };
    let h = Harness::new(RUNAWAY_HOOK, config(limits, Duration::from_secs(30)));
    let id = h.insert(http_flow());

    let started = Instant::now();
    let verdict = h.dispatch(Event::Request(id)).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "dispatch stalled: {elapsed:?}"
    );
    assert_eq!(verdict, Verdict::Continue);
    let errors = h.wait_for_errors(1).await;
    assert_eq!(errors.len(), 1, "exactly one Event::Error: {errors:?}");
    let msg = script_error_message(&errors[0]);
    assert!(
        msg.contains("10000 operation budget"),
        "the error names the operation budget: {msg}"
    );
    assert_eq!(
        http(&h.flow(id)).request.headers.get("Host"),
        Some("ex.test"),
        "the flow is intact"
    );

    // A slow hook: effectively unlimited operations, a 50ms clock.
    let limits = RhaiLimits {
        max_operations: 1_000_000_000_000,
        ..RhaiLimits::default()
    };
    let h = Harness::new(RUNAWAY_HOOK, config(limits, Duration::from_millis(50)));
    let id = h.insert(http_flow());

    let started = Instant::now();
    let verdict = h.dispatch(Event::Request(id)).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "dispatch stalled: {elapsed:?}"
    );
    assert_eq!(verdict, Verdict::Continue);
    let errors = h.wait_for_errors(1).await;
    assert_eq!(errors.len(), 1, "exactly one Event::Error: {errors:?}");
    let msg = script_error_message(&errors[0]);
    assert!(
        msg.contains("time budget"),
        "the error names the time budget: {msg}"
    );
}

/// An `on_error` hook that itself throws must not emit another `Event::Error`
/// — that would loop forever through the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errored_on_error_hook_does_not_reemit() {
    let h = Harness::default(r#"fn on_error(flow, err) { throw "again: " + err; }"#);
    let id = h.insert(http_flow());

    let verdict = h
        .dispatch(Event::Error {
            flow: id,
            kind: FlowError::Timeout,
        })
        .await;

    assert_eq!(verdict, Verdict::Continue);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let errors = h.probe.errors();
    assert_eq!(
        errors,
        vec![FlowError::Timeout],
        "only the original error reached the chain"
    );
}

/// A hook the script does not define passes the event straight through, and a
/// two-argument hook gets the frame it is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undefined_hooks_pass_through_and_ws_hook_gets_the_frame() {
    let h = Harness::default(
        r#"
        fn on_ws_message(flow, msg) {
            if msg.direction == "c2s" && msg.text.contains("secret") {
                msg.set_text("[redacted]");
            }
        }
        "#,
    );

    // No `on_request`: nothing runs, nothing changes, the probe still sees it.
    let http_id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(http_id)).await, Verdict::Continue);
    assert_eq!(http(&h.flow(http_id)).request.method, "POST");
    assert_eq!(h.probe.events(), vec![Event::Request(http_id)]);

    let ws_id = h.insert(ws_flow());
    let ev = Event::WsMessage {
        flow: ws_id,
        index: 0,
    };
    assert_eq!(h.dispatch(ev).await, Verdict::Continue);
    match h.flow(ws_id) {
        Flow::WebSocket(w) => assert_eq!(w.messages[0].data, b"[redacted]".to_vec()),
        Flow::Http(_) => panic!("expected the WebSocket flow"),
    }
}

/// `meta()`/`name()` agree, and `reload` swaps the hooks live: the hot-reload
/// seam the loader and `script.reload` will drive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_swaps_the_hooks() {
    let fixture = Fixture::new(config(RhaiLimits::default(), Duration::from_secs(5)));
    let mut plugin = fixture.plugin(
        "tagger",
        r#"fn on_request(flow) { flow.request.headers.set("X-Version", "1"); }"#,
    );
    assert_eq!(plugin.meta().name, "tagger");
    assert_eq!(plugin.name(), "tagger");
    assert_eq!(plugin.meta().path, std::path::PathBuf::from("tagger.rhai"));

    let mut flow = http_flow();
    let id = flow.id();
    let verdict = plugin.on_event(&Event::Request(id), &mut FlowCtx::new(&mut flow));
    assert_eq!(verdict, Verdict::Continue);
    assert_eq!(http(&flow).request.headers.get("X-Version"), Some("1"));

    let next = fixture
        .engine
        .compile(r#"fn on_request(flow) { flow.request.headers.set("X-Version", "2"); halt(); }"#)
        .expect("compiles");
    plugin.reload(next, plugin.meta().clone());

    let mut flow = http_flow();
    let id = flow.id();
    let verdict = plugin.on_event(&Event::Request(id), &mut FlowCtx::new(&mut flow));
    assert_eq!(verdict, Verdict::Halt, "the new hook's halt() is honoured");
    assert_eq!(http(&flow).request.headers.get("X-Version"), Some("2"));
}

/// A disabled script's hooks do not fire; re-enabling restores them. The flag
/// is the handle's, shared with the command surface, and read live per event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_handle_skips_hooks_until_re_enabled() {
    let h = Harness::default(r#"fn on_request(flow) { flow.request.headers.set("X-Aitm", "1"); }"#);
    assert!(h.handle.is_enabled(), "a loaded script starts enabled");

    h.handle.set_enabled(false);
    assert!(!h.handle.is_enabled());
    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    assert_eq!(
        http(&h.flow(id)).request.headers.get("X-Aitm"),
        None,
        "a disabled script's on_request must not run"
    );
    assert_eq!(
        h.probe.events(),
        vec![Event::Request(id)],
        "the chain still reaches the next plugin"
    );

    h.handle.set_enabled(true);
    assert!(h.handle.is_enabled());
    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    assert_eq!(
        http(&h.flow(id)).request.headers.get("X-Aitm"),
        Some("1"),
        "re-enabled, the hook fires again"
    );
}

/// A disabled script that would `halt()` does not short-circuit the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_handle_does_not_halt_the_chain() {
    let h = Harness::default(r#"fn on_request(flow) { halt(); }"#);
    h.handle.set_enabled(false);
    let id = h.insert(http_flow());

    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    assert_eq!(h.probe.events(), vec![Event::Request(id)]);
}

/// `ScriptHandle::meta()` exposes the declared `api` and the hooks the script
/// defines, exactly as the loader parsed them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_meta_returns_the_parsed_api_and_hooks() {
    let fixture = Fixture::new(config(RhaiLimits::default(), Duration::from_secs(5)));
    let ast = fixture
        .engine
        .compile("fn on_request(flow) {} fn on_response(flow) {}")
        .expect("compiles");
    let declared = ScriptMeta {
        name: "declared".to_string(),
        api: "1".to_string(),
        path: "declared.rhai".into(),
        hooks: vec!["on_request".to_string(), "on_response".to_string()],
    };
    let plugin = ScriptPlugin::new(
        declared.clone(),
        Arc::clone(&fixture.engine),
        ast,
        fixture.services.clone(),
        Options::default(),
        &fixture.cfg,
    );

    let handle = plugin.handle();
    assert_eq!(*handle.meta(), declared);
    assert_eq!(handle.meta().api, "1");
    assert_eq!(
        handle.meta().hooks,
        vec!["on_request".to_string(), "on_response".to_string()]
    );
}
