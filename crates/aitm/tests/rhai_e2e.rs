//! M3 Task 15 — the converged tier, end to end through the binary's wiring.
//!
//! These prove the joins, not the parts (the parts have their own tests in
//! `aitm-plugin-rhai` and `aitm-poc`): that scripts loaded by the wiring take
//! their declared chain positions after the native plugins and a script
//! `halt()` stops a native one after it (AC-M3-10); that adding a script
//! changes the already-built binary's behaviour with no recompile (AC-M3-4);
//! that a script-registered command is a real MCP tool and CLI subcommand
//! (AC-M3-3); that the sandbox and the guards hold and one bad script never
//! takes the proxy down (AC-M3-5/7); that the worked-example PoC round-trips
//! (AC-M3-11); and — under a real engine — that Example 3 returns pass against
//! a vulnerable target and fail against a patched one (AC-M3-8).
//!
//! The example fixtures under `examples/` are the spec's normative shapes; a
//! couple of these tests load them, so a drift between spec and shipped
//! example fails the suite.

#[path = "../../aitm-browser/tests/support/engines.rs"]
mod engines;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm::wire::{assemble_with_scripts, Assembled, Features, Http1Sender, ScriptWiring};
use aitm_core::{
    Body, Chain, Config, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, McpTransport, MemFlowStore, PipelineClient,
    Plugin, ProxyClient, Registry, ScopeEntry, StdGuard, Verdict,
};
use aitm_plugin_rhai::{
    wire, MemoryFindingSink, RhaiConfig, ScriptEntry, ScriptPlugin, ScriptServices,
};

const TAGGER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/addons/tagger.rhai");
const GUARD_ADMIN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/addons/guard-admin-writes.rhai"
);
const XSS_POC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/poc/authed-stored-xss-notes.yaml"
);

/// A client that is never reached in the hermetic chain tests.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Services over a given store and guard, so a test can choose the scope the
/// script's `http.send` meets.
fn services(store: Arc<dyn FlowStore>, guard: Arc<StdGuard>) -> ScriptServices {
    ScriptServices {
        store,
        client: Arc::new(StubClient),
        browser: None,
        guard,
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

fn rhai_cfg(scripts: Vec<ScriptEntry>) -> RhaiConfig {
    RhaiConfig {
        scripts,
        ..RhaiConfig::default()
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

/// A request flow for `method path` on `ex.test`, put in the store.
fn insert_request(store: &dyn FlowStore, method: &str, path: &str) -> FlowId {
    let mut headers = HeaderMap::new();
    headers.set("Host", "ex.test");
    store.insert(Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: method.into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(Vec::new()),
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }))
}

fn http(flow: &Flow) -> &HttpFlow {
    match flow {
        Flow::Http(f) => f,
        _ => panic!("expected HTTP flow"),
    }
}

/// A native plugin that records every event it is handed; used to prove a
/// script's `halt()` kept a plugin *after* it from running (AC-M3-10).
#[derive(Default)]
struct ProbeLog {
    seen: Mutex<Vec<Event>>,
}
struct Probe(Arc<ProbeLog>);

impl Plugin for Probe {
    fn name(&self) -> &str {
        "probe"
    }
    fn on_event(&mut self, ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        self.0.seen.lock().unwrap().push(ev.clone());
        Verdict::Continue
    }
}

/// Drive the exact registration order the binary uses — native plugins, then
/// the tier's script plugins in declaration order — plus a trailing native
/// probe, over a real `Chain`.
fn chain_with(
    scripts: Vec<ScriptPlugin>,
    probe: Arc<ProbeLog>,
    store: Arc<dyn FlowStore>,
) -> Chain {
    let mut registry = Registry::new();
    // A native plugin ahead of the scripts (stands in for capture/scope/…).
    registry.add_plugin(Box::new(Probe(Arc::new(ProbeLog::default()))));
    for plugin in scripts {
        registry.add_plugin(Box::new(plugin));
    }
    // A native plugin after the scripts: a script halt() must stop it.
    registry.add_plugin(Box::new(Probe(probe)));
    Chain::new(Arc::new(registry), store)
}

/// AC-M3-10: a script `halt()` loaded through the tier stops a native plugin
/// registered after it; a normal return lets it run. The example
/// `guard-admin-writes.rhai` halts a POST /admin with no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chain_order_natives_then_scripts() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let tier = wire::build(
        rhai_cfg(vec![ScriptEntry::new(GUARD_ADMIN)]),
        services(store.clone(), guard),
    )
    .expect("tier builds");
    assert!(
        tier.errors.is_empty(),
        "example compiles: {:?}",
        tier.errors
    );

    let probe = Arc::new(ProbeLog::default());
    let chain = chain_with(tier.plugins, probe.clone(), store.clone());

    // A blocked admin write: the script set_response(403) + halt().
    let blocked = insert_request(store.as_ref(), "POST", "/admin/users");
    assert_eq!(chain.dispatch(Event::Request(blocked)).await, Verdict::Halt);
    assert!(
        !probe
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Request(id) if *id == blocked)),
        "the native plugin after the halting script must not run",
    );
    let flow = store.get(blocked).unwrap();
    assert_eq!(http(&flow).response.as_ref().map(|r| r.status), Some(403));

    // A GET is not an admin write: the script returns normally, the later
    // native plugin runs.
    let allowed = insert_request(store.as_ref(), "GET", "/admin/users");
    assert_eq!(
        chain.dispatch(Event::Request(allowed)).await,
        Verdict::Continue
    );
    assert!(
        probe
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Request(id) if *id == allowed)),
        "a non-halting script leaves the chain running",
    );
}

/// AC-M3-4: the *same* compiled binary-under-test gains behaviour when a script
/// is added — no recompile in the test body, just a second load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_added_without_rebuild() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());

    // No scripts: nothing tags the request.
    let bare = wire::build(rhai_cfg(vec![]), services(store.clone(), guard.clone()))
        .expect("bare tier builds");
    assert!(bare.plugins.is_empty());

    // Add the tagger by config entry — the running binary would do exactly this
    // from `scripts:` or `--script`, with no rebuild.
    let with_tagger = wire::build(
        rhai_cfg(vec![ScriptEntry::new(TAGGER)]),
        services(store.clone(), guard),
    )
    .expect("tier with tagger builds");

    let probe = Arc::new(ProbeLog::default());
    let chain = chain_with(with_tagger.plugins, probe, store.clone());
    let id = insert_request(store.as_ref(), "GET", "/");
    chain.dispatch(Event::Request(id)).await;

    let flow = store.get(id).unwrap();
    assert_eq!(
        http(&flow).request.headers.get("X-Aitm"),
        Some("seen-by-aitm"),
        "the added script's on_request now tags the flow",
    );
}

/// AC-M3-5/7: a script reaching the network out of scope is refused by the same
/// guard as Rust (deny-by-default: the empty-scope guard refuses every host),
/// the hook's error is isolated, and the chain keeps serving. The flow is
/// forwarded unchanged — the denied send never mutated it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_cannot_escape_or_exceed_scope() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default()); // no scope ⇒ every host refused
    let src = TempScript::new(
        "escape",
        r#"
        fn on_request(flow) {
            // Guard refusal (AC-M3-7): out-of-scope send, uncaught, aborts the hook.
            http.send(#{ method: "GET", url: "http://evil.test/" });
            flow.request.headers.set("X-Should-Not-Appear", "1");
        }
        "#,
    );
    let tier = wire::build(
        rhai_cfg(vec![ScriptEntry::new(src.path())]),
        services(store.clone(), guard),
    )
    .expect("tier builds");

    let probe = Arc::new(ProbeLog::default());
    let chain = chain_with(tier.plugins, probe, store.clone());
    let id = insert_request(store.as_ref(), "GET", "/");
    // The chain returns (no stall, no panic): the proxy keeps serving.
    assert_eq!(chain.dispatch(Event::Request(id)).await, Verdict::Continue);

    let flow = store.get(id).unwrap();
    assert_eq!(
        http(&flow).request.headers.get("X-Should-Not-Appear"),
        None,
        "an errored hook forwards the flow unchanged (effects discarded)",
    );
}

/// AC-M3-3: a script-registered command is enumerated by MCP `tools/list` and
/// returns the same result over MCP and over the CLI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_command_over_frontends() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let tier = wire::build(
        rhai_cfg(vec![ScriptEntry::new(TAGGER)]),
        services(store, guard),
    )
    .expect("tier builds");

    let mut cfg = Config::default();
    cfg.ca.dir = temp_dir("rhai-cmd");
    let Assembled { proxy, .. } = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            plugins: tier
                .plugins
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn Plugin>)
                .collect(),
            executor: Some(tier.executor.clone()),
        },
    )
    .expect("assemble with the tagger script");
    let registry = proxy.registry_arc();

    // MCP tools/list includes the script command.
    let server = aitm_mcp::McpServer::new(registry.clone(), McpTransport::Stdio).with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient) as Arc<dyn ProxyClient>,
        Arc::new(StdGuard::default()),
        None,
    );
    let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
    let resp: serde_json::Value =
        serde_json::from_str(&server.handle(&req.to_string()).expect("a response"))
            .expect("json response");
    let names: Vec<&str> = resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"tagger.ping"),
        "the script command is an MCP tool; got {names:?}",
    );

    // MCP tools/call returns "pong".
    let call = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"tagger.ping","arguments":{}}
    });
    let resp: serde_json::Value =
        serde_json::from_str(&server.handle(&call.to_string()).expect("a response"))
            .expect("json response");
    assert!(
        resp.to_string().contains("pong"),
        "MCP tools/call → pong; got {resp}",
    );

    // The CLI dispatch path returns the same.
    let client: Arc<dyn ProxyClient> = Arc::new(StubClient);
    let cli = aitm_cli::Cli::new(registry).with_services(
        Arc::new(MemFlowStore::new()),
        client,
        Arc::new(StdGuard::default()),
        None,
    );
    let out = cli
        .dispatch(&["tagger".to_string(), "ping".to_string()])
        .expect("cli tagger ping");
    let rendered = String::from_utf8(aitm::render::render_cli_value(&out)).unwrap();
    assert!(
        rendered.contains("pong"),
        "CLI tagger ping → pong; got {rendered}",
    );
}

/// AC-M3-11: the worked-example PoC deserializes into a `Poc` with a
/// `Step::Script` and re-serializes equal — the shipped example is a valid,
/// stable PoC document.
#[test]
fn worked_example_poc_round_trips() {
    use aitm_poc::{Poc, Step};
    let text = std::fs::read_to_string(XSS_POC).expect("read the example PoC");
    let poc: Poc = serde_yaml::from_str(&text).expect("the example PoC parses");
    assert!(
        poc.steps.iter().any(|s| matches!(s, Step::Script(_))),
        "the example carries a Rhai script step",
    );
    let again: Poc = serde_yaml::from_str(&serde_yaml::to_string(&poc).unwrap())
        .expect("re-serialized example parses");
    assert_eq!(poc, again, "the example round-trips through serde");
}

/// A throwaway script outside the repo, removed on drop.
struct TempScript(PathBuf);

impl TempScript {
    fn new(tag: &str, src: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("aitm-e2e-{}-{tag}-{n}.rhai", std::process::id()));
        std::fs::write(&path, src).expect("write temp script");
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("aitm-e2e-{tag}-{nanos}-{n}"))
}

// ---------------------------------------------------------------------------
// AC-M3-8: the PoC script step pass-vs-patched, under a real browser engine.
// Hermetic by default (inert when no engine is enabled); run it with
// AITM_OBSCURA=1 / AITM_CHROME=1 as e2e_reflected_xss.rs documents.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Mode {
    Vulnerable,
    Patched,
}

/// A minimal stored-notes target: `GET /login` serves a CSRF token, `POST
/// /login` and `POST /notes` store the last note body, `GET /notes` renders it
/// — unescaped (vulnerable) or escaped (patched).
async fn spawn_notes_target(mode: Mode) -> SocketAddr {
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let note = Arc::new(Mutex::new(String::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let note = note.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| {
                            let note = note.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let method = req.method().clone();
                                let body = {
                                    use http_body_util::BodyExt as _;
                                    req.into_body()
                                        .collect()
                                        .await
                                        .map(|b| b.to_bytes())
                                        .unwrap_or_default()
                                };
                                let text = String::from_utf8_lossy(&body).to_string();
                                let resp = match (method.as_str(), path.as_str()) {
                                    ("GET", "/login") => {
                                        r#"<form><input name="csrf" value="abc123"></form>"#
                                            .to_string()
                                    }
                                    ("POST", "/notes") => {
                                        let stored =
                                            text.strip_prefix("note=").unwrap_or(&text).to_string();
                                        *note.lock().unwrap() = stored;
                                        "stored".to_string()
                                    }
                                    ("GET", "/notes") => {
                                        let raw = note.lock().unwrap().clone();
                                        match mode {
                                            Mode::Vulnerable => format!("<div>{raw}</div>"),
                                            Mode::Patched => format!(
                                                "<div>{}</div>",
                                                raw.replace('<', "&lt;").replace('>', "&gt;")
                                            ),
                                        }
                                    }
                                    _ => "ok".to_string(),
                                };
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(resp))))
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a real browser engine; set AITM_OBSCURA=1 / AITM_CHROME=1"]
async fn poc_script_step_pass_vs_patched() {
    use aitm::scripts::LateHandles;
    use aitm_core::{BrowserDriver, Params, Value};

    for engine in engines::engines() {
        for (mode, want) in [(Mode::Vulnerable, true), (Mode::Patched, false)] {
            let target = spawn_notes_target(mode).await;
            let base = format!("http://{target}");

            let mut cfg = Config::default();
            cfg.ca.dir = temp_dir("rhai-xss");
            cfg.scope.entries.push(ScopeEntry {
                host: target.to_string(),
            });
            cfg.browser = engines::config_for(engine, cfg.browser.proxy_addr);

            // Exactly `main`'s path: build the tier against late-bound handles,
            // assemble the proxy with it, then bind the real handles and the
            // launched browser.
            let handles = LateHandles::new();
            let svc = ScriptServices {
                store: handles.clone(),
                client: handles.clone(),
                browser: Some(handles.clone()),
                guard: handles.clone(),
                findings: Arc::new(MemoryFindingSink::new()),
                rt: tokio::runtime::Handle::current(),
            };
            let tier = wire::build(rhai_cfg(vec![]), svc).expect("tier builds");

            let Assembled { proxy, ca } = assemble_with_scripts(
                &cfg,
                &Features::default(),
                ScriptWiring {
                    plugins: Vec::new(),
                    executor: Some(tier.executor.clone()),
                },
            )
            .expect("assemble proxy");

            let store = proxy.store();
            let guard = proxy.guard();
            let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
                store.clone(),
                guard.clone(),
                Arc::new(Http1Sender::new()),
            ));
            handles.bind_proxy(store.clone(), client.clone(), guard.clone());

            // Serve the browser-facing accept loop so the engine's navigations
            // reach the target through the proxy's guard (the http.send calls
            // use `client` directly). The registry outlives the spawned proxy.
            let registry = proxy.registry_arc();
            let browser_listen = cfg.browser.proxy_addr;
            tokio::spawn(async move {
                let _ = proxy.run_browser(browser_listen).await;
            });
            wait_listening(browser_listen).await;

            let browser: Arc<dyn BrowserDriver> =
                aitm_browser::launch(&cfg.browser, ca.cert_path())
                    .await
                    .unwrap_or_else(|e| panic!("[{engine:?}] launch: {e:#}"));
            handles.bind_browser(browser.clone());

            // poc.run blocks internally (block_on driving the browser), so run
            // it off the runtime thread; the reactor polls the browser futures.
            let run_host_store = store.clone();
            let run_client = client.clone();
            let run_guard = guard.clone();
            let run_browser = browser.clone();
            let out = tokio::task::spawn_blocking(move || {
                let host = aitm_core::CommandHost::new(
                    run_host_store.as_ref(),
                    run_client.as_ref(),
                    run_guard.as_ref(),
                    Some(run_browser.as_ref()),
                );
                let args = Params::new(
                    [
                        ("poc_path".to_string(), Value::Str(XSS_POC.to_string())),
                        ("target".to_string(), Value::Str(base.clone())),
                    ]
                    .into_iter()
                    .collect(),
                );
                registry
                    .command("poc.run")
                    .expect("poc.run")
                    .invoke(args, &host)
            })
            .await
            .expect("poc.run task")
            .expect("poc.run executes");

            let Value::Object(obj) = out else {
                panic!("poc.run returns an object");
            };
            assert_eq!(
                obj.get("passed"),
                Some(&Value::Bool(want)),
                "engine {engine:?}, vulnerable={}: expected passed={want}",
                matches!(mode, Mode::Vulnerable),
            );
        }
    }
}

/// Wait (bounded) for a listener to accept, so the browser can dial it.
async fn wait_listening(addr: SocketAddr) {
    use tokio::net::TcpStream;
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "listener never came up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
