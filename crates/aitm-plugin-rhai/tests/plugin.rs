//! `ScriptHost` + `LoadedScript` hook dispatch (F8 Option-B dispatch model):
//! one `ScriptHost` plugin owns a `ScriptSet` of compiled `LoadedScript`s and
//! dispatches each from a single chain position. A hook's edits apply back
//! through the effect model (AC-M3-1), `halt()` short-circuits the set and the
//! chain like `Verdict::Halt` (AC-M3-2, RF#3), a hook that errors leaves the
//! flow untouched and surfaces an `Event::Error` (AC-M3-12, RF#1), a runaway
//! hook is aborted by the budget without stalling the chain (AC-M3-6), and a
//! script appended to the set at runtime goes live with no rebuild (original
//! F8 AC4).
//!
//! Every test drives the real `aitm_core::Chain` over a `Registry` holding the
//! script host followed by a probe plugin, so the short-circuit and the chain's
//! plugin locking are exercised as the proxy exercises them. Hooks run under
//! `block_in_place`, so every test runs on a multi-thread runtime.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, CallerTrust, Chain, ConnInfo, Event, Flow, FlowCtx, FlowError, FlowId, FlowMeta,
    FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, Plugin,
    ProxyClient, Registry, StdGuard, Value, Verdict, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptMeta};
use aitm_plugin_rhai::engine::{build_engine, build_engine_with_languages};
use aitm_plugin_rhai::flow_api::register_flow_api;
use aitm_plugin_rhai::host_core::{
    FindingCapability, LogCapability, MemoryFindingSink, Options, ScriptCapability, ScriptServices,
};
use aitm_plugin_rhai::host_net::HttpCapability;
use aitm_plugin_rhai::plugin::{ErrorSink, LoadedScript, ScriptHandle, ScriptHost, ScriptSet};
use rhai::Engine;

/// A loop that never ends and does real work each turn, so the optimizer
/// cannot fold it away and every iteration costs operations.
const RUNAWAY_HOOK: &str = "fn on_request(flow) { let n = 0; loop { n += 1; } }";

/// A body cap larger than any test body, for the direct `LoadedScript::dispatch`
/// tests (the host supplies the proxy's configured cap in production).
const MAX_BODY: usize = 1 << 20;

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

    fn plugin(&self, name: &str, src: &str) -> LoadedScript {
        let ast = self.engine.compile(src).expect("the script compiles");
        LoadedScript::new(
            meta(name),
            Arc::clone(&self.engine),
            ast,
            self.services.clone(),
            Options::default(),
            &self.cfg,
        )
    }
}

/// The script host (one script loaded) followed by the probe, in a real chain
/// over the fixture's store; the chain itself is the sink the script's
/// `Event::Error`s go to, so the probe sees them the way a native plugin would.
/// The shared [`ScriptSet`] and error sink are kept so a test can append a new
/// script at runtime, exactly as `script.save` does.
struct Harness {
    fixture: Fixture,
    chain: Arc<Chain>,
    probe: Arc<ProbeLog>,
    /// The first script's shared handle, taken before the host is boxed away.
    handle: Arc<ScriptHandle>,
    /// The host's set, for appending a script live.
    set: ScriptSet,
    /// The shared error sink an appended script wires into.
    errors: Arc<ErrorSink>,
}

impl Harness {
    fn new(src: &str, cfg: RhaiConfig) -> Self {
        let fixture = Fixture::new(cfg);
        let errors = Arc::new(ErrorSink::default());
        let script = fixture
            .plugin("under-test", src)
            .with_error_sink(Arc::clone(&errors));
        let handle = script.handle();
        let probe = Arc::new(ProbeLog::default());

        let set = ScriptSet::new(vec![script]);
        let host = ScriptHost::new(set.clone());

        let mut registry = Registry::new();
        registry.add_plugin(Box::new(host));
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
            set,
            errors,
        }
    }

    /// Append a brand-new script to the running host's set and return its
    /// handle — the live-activation path `script.save` of a new name takes.
    fn append(&self, name: &str, src: &str) -> Arc<ScriptHandle> {
        let script = self
            .fixture
            .plugin(name, src)
            .with_error_sink(Arc::clone(&self.errors));
        let handle = script.handle();
        self.set.append(script);
        handle
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
    let plugin = fixture.plugin(
        "tagger",
        r#"fn on_request(flow) { flow.request.headers.set("X-Version", "1"); }"#,
    );
    assert_eq!(plugin.meta().name, "tagger");
    assert_eq!(plugin.name(), "tagger");
    assert_eq!(plugin.meta().path, std::path::PathBuf::from("tagger.rhai"));

    let mut flow = http_flow();
    let id = flow.id();
    let verdict = plugin.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
    assert_eq!(verdict, Verdict::Continue);
    assert_eq!(http(&flow).request.headers.get("X-Version"), Some("1"));

    let next = fixture
        .engine
        .compile(r#"fn on_request(flow) { flow.request.headers.set("X-Version", "2"); halt(); }"#)
        .expect("compiles");
    plugin.reload(next, plugin.meta().clone());

    let mut flow = http_flow();
    let id = flow.id();
    let verdict = plugin.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
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
    let plugin = LoadedScript::new(
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

/// F8 Option B / original AC4: a brand-new script appended to the running
/// host's set — exactly what `script.save` of a new name does — has its
/// `on_request` run on the NEXT event, with no chain rebuild and no restart.
/// The script already loaded keeps running, and the new one joins at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn appended_script_goes_live_without_rebuild() {
    // One script loaded at build time: it tags X-First.
    let h =
        Harness::default(r#"fn on_request(flow) { flow.request.headers.set("X-First", "1"); }"#);
    assert_eq!(h.set.len(), 1);

    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    let flow = h.flow(id);
    assert_eq!(http(&flow).request.headers.get("X-First"), Some("1"));
    assert_eq!(
        http(&flow).request.headers.get("X-Second"),
        None,
        "the second script is not loaded yet"
    );

    // Append a brand-new script to the SAME host — no rebuild, no restart.
    let appended = h.append(
        "appended",
        r#"fn on_request(flow) { flow.request.headers.set("X-Second", "2"); }"#,
    );
    assert_eq!(h.set.len(), 2, "the host now holds both scripts");
    assert!(appended.is_enabled(), "an appended script starts enabled");

    // The very next event runs BOTH, the original first then the appended.
    let id2 = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id2)).await, Verdict::Continue);
    let flow2 = h.flow(id2);
    assert_eq!(
        http(&flow2).request.headers.get("X-First"),
        Some("1"),
        "the originally-loaded script still runs"
    );
    assert_eq!(
        http(&flow2).request.headers.get("X-Second"),
        Some("2"),
        "the appended script's hook is live with no rebuild"
    );
    assert_eq!(
        h.probe.events(),
        vec![Event::Request(id), Event::Request(id2)],
        "the chain reached the trailing native plugin both times"
    );
}

/// An appended script joins at the END of the chain: when the script already
/// loaded `halt()`s, the appended one — and the native plugin after the host —
/// never run. This pins the order half of the append semantics (spec §8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn appended_script_runs_after_the_loaded_ones() {
    let h = Harness::default(
        r#"fn on_request(flow) { flow.set_response(403, #{}, "blocked"); halt(); }"#,
    );

    let tripwire = h.append(
        "tripwire",
        r#"fn on_request(flow) { flow.request.headers.set("X-Tripwire", "ran"); }"#,
    );
    assert!(tripwire.is_enabled());

    let id = h.insert(http_flow());
    assert_eq!(
        h.dispatch(Event::Request(id)).await,
        Verdict::Halt,
        "the first script's halt short-circuits the set"
    );
    let flow = h.flow(id);
    assert_eq!(
        http(&flow).request.headers.get("X-Tripwire"),
        None,
        "the appended script, being after the halting one, must not run"
    );
    assert!(
        h.probe.events().is_empty(),
        "the native plugin after the host must not run either: {:?}",
        h.probe.events()
    );
}

/// `append_if_absent` refuses a second script of the same brand-new name — the
/// race fix for two concurrent `script.save`s of one new name. The set holds
/// exactly one script by that name, and its hook runs once per event, not twice
/// (which would mean double traffic mutation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn append_if_absent_refuses_a_duplicate_name() {
    let h = Harness::default(r#"fn on_request(flow) { flow.mark("base"); }"#);
    assert_eq!(h.set.len(), 1);

    let first = h
        .fixture
        .plugin("dup", r#"fn on_request(flow) { flow.mark("dup"); }"#)
        .with_error_sink(Arc::clone(&h.errors));
    assert!(
        h.set.append_if_absent(first),
        "a brand-new name is appended"
    );
    assert_eq!(h.set.len(), 2);

    let second = h
        .fixture
        .plugin("dup", r#"fn on_request(flow) { flow.mark("dup"); }"#)
        .with_error_sink(Arc::clone(&h.errors));
    assert!(
        !h.set.append_if_absent(second),
        "a second script of the same name is refused"
    );
    assert_eq!(h.set.len(), 2, "no duplicate was added");

    let id = h.insert(http_flow());
    assert_eq!(h.dispatch(Event::Request(id)).await, Verdict::Continue);
    let flow = h.flow(id);
    let marks = &http(&flow).metadata.marks;
    assert_eq!(
        marks.iter().filter(|m| m.as_str() == "dup").count(),
        1,
        "the deduped hook ran exactly once: {marks:?}"
    );
}

// ===========================================================================
// Task 3 — every production invocation boundary seeds the caller trust before
// an eval can reach a seam host fn (fail-closed otherwise). A hook seeds the
// script's **authoring trust** (spec AC6); `load(reg)` seeds it too (AC3, the
// load boundary). The seam-namespace probe OBSERVES the seeded trust, since L4
// does not gate on trust until Task 4.
// ===========================================================================

/// A seam language whose `probe.note()` records the live `ctx.caller()` into a
/// shared log, so a test can observe exactly what trust the invocation boundary
/// seeded. Its guard admits every call (the observation, not the gate, is under
/// test here).
struct CapturingLanguage {
    seen: Arc<Mutex<Vec<CallerTrust>>>,
}

struct AdmitGuard;

impl GuardHandle for AdmitGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

impl ProtocolLanguage for CapturingLanguage {
    fn namespace(&self) -> &str {
        "probe"
    }

    fn api_version(&self) -> &str {
        "1"
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let seen = Arc::clone(&self.seen);
        let note: HostFn = Box::new(move |ctx: &HostCallCtx, _args: &[Value]| {
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ctx.caller());
            Ok(Value::Null)
        });
        reg.register("probe", "note", Guarded::new(Box::new(AdmitGuard), note))
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: "probe".to_string(),
            api_version: "1".to_string(),
            host_fns: vec![],
            poc_step: None,
            sources: vec![],
        }
    }
}

/// Minimal services for a seam-enabled `LoadedScript` under test.
fn seam_services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// Build a `LoadedScript` on an engine carrying the capturing seam language, with
/// the given authoring trust recorded on its handle.
fn seam_script(
    seen: &Arc<Mutex<Vec<CallerTrust>>>,
    src: &str,
    authoring: CallerTrust,
    reg_api: bool,
) -> LoadedScript {
    let lang = CapturingLanguage {
        seen: Arc::clone(seen),
    };
    let mut engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("the capturing seam language installs");
    if reg_api {
        aitm_plugin_rhai::command::register_reg_api(&mut engine);
    }
    let ast = engine.compile(src).expect("the script compiles");
    let cfg = config(RhaiLimits::default(), Duration::from_secs(5));
    LoadedScript::new(
        meta("probe-script"),
        Arc::new(engine),
        ast,
        seam_services(),
        Options::default(),
        &cfg,
    )
    .with_authoring_trust(authoring)
}

/// AC6: a plugin hook's seam host-fn call is gated on the script's **authoring
/// trust** — an operator-authored script observes `Operator`, an agent-authored
/// one `Operator` must never appear; it observes `Agent`. One shared engine, the
/// trust decided per script, not at build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_seeds_the_scripts_authoring_trust() {
    // Operator-authored: the hook's `probe.note()` sees Operator.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script = seam_script(
        &seen,
        r#"fn on_request(flow) { probe.note(); }"#,
        CallerTrust::Operator,
        false,
    );
    let mut flow = http_flow();
    let id = flow.id();
    let verdict = script.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
    assert_eq!(verdict, Verdict::Continue);
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Operator],
        "an operator-authored hook must seed Operator (and reach the seam at all)"
    );

    // Agent-authored: the same engine shape, the hook now sees Agent.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script = seam_script(
        &seen,
        r#"fn on_request(flow) { probe.note(); }"#,
        CallerTrust::Agent,
        false,
    );
    let mut flow = http_flow();
    let id = flow.id();
    let verdict = script.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
    assert_eq!(verdict, Verdict::Continue);
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Agent],
        "an agent-authored hook must seed Agent, never widen to Operator"
    );
}

/// AC3 (own verification): the hook boundary is actually seeded — a hook reaching
/// a seam fn is NEVER refused with "no caller context" (which would mean an
/// unseeded production path). The fail-closed dispatch error would drop the hook
/// (recording nothing); the recorded trust proves the boundary seeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_boundary_is_never_left_unseeded() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script = seam_script(
        &seen,
        r#"fn on_request(flow) { probe.note(); }"#,
        CallerTrust::Agent,
        false,
    );
    let mut flow = http_flow();
    let id = flow.id();
    script.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
    assert_eq!(
        seen.lock().unwrap_or_else(PoisonError::into_inner).len(),
        1,
        "the hook reached the seam fn (seeded); an unseeded boundary would fail \
         closed and record nothing"
    );
}

/// AC3 (load boundary): a script's `load(reg)` that reaches a seam host fn is
/// seeded with the script's authoring trust — `load` runs (installing nothing
/// here) and the seam call is observed, not refused "no caller context".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_boundary_seeds_authoring_trust() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script = seam_script(
        &seen,
        r#"fn load(reg) { probe.note(); }"#,
        CallerTrust::Agent,
        true,
    );
    let set = ScriptSet::new(vec![script]);
    let mut host = ScriptHost::new(set);
    let mut registry = Registry::new();
    host.load(&mut registry);
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Agent],
        "a load(reg) reaching the seam must be seeded with the authoring trust, \
         never refused for a missing caller context"
    );
}

/// A fresh `LoadedScript` whose authoring trust was never set defaults to the
/// most-restrictive `Agent` — fail-closed, never a silent `Operator`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authoring_trust_defaults_to_agent() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    // Build a script WITHOUT calling `with_authoring_trust`.
    let lang = CapturingLanguage {
        seen: Arc::clone(&seen),
    };
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(5), &[&lang])
            .expect("installs");
    let ast = engine
        .compile(r#"fn on_request(flow) { probe.note(); }"#)
        .expect("compiles");
    let cfg = config(RhaiLimits::default(), Duration::from_secs(5));
    let script = LoadedScript::new(
        meta("defaulted"),
        Arc::new(engine),
        ast,
        seam_services(),
        Options::default(),
        &cfg,
    );
    let mut flow = http_flow();
    let id = flow.id();
    script.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Agent],
        "an unset authoring trust must fail closed to Agent, never Operator"
    );
}
