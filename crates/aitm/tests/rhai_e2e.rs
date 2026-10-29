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
    AgentPolicy, AgentState, Body, Chain, Config, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta,
    FlowStore, Frontend, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState,
    McpTransport, MemFlowStore, PipelineClient, Plugin, ProxyClient, Registry, ScopeEntry,
    StdGuard, Verdict,
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

/// AC-M3-5/7: a script reaching for the filesystem fails with a clear
/// `ScriptError`; one reaching the network out of scope is refused by the
/// same guard as Rust (deny-by-default: the empty-scope guard refuses every
/// host); each hook's error is isolated — the flow is forwarded unchanged by
/// it, an `Event::Error` names the script and the cause — and *other scripts
/// are unaffected*: the third script's edit lands and the chain keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_cannot_escape_or_exceed_scope() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default()); // no scope ⇒ every host refused
    let reader = TempScript::new(
        "reader",
        r#"
        const NAME = "reader";
        fn on_request(flow) {
            // Sandbox denial (AC-M3-5): no such function exists for a script.
            open_file("/etc/passwd");
            flow.request.headers.set("X-Read", "1");
        }
        "#,
    );
    let escaper = TempScript::new(
        "escaper",
        r#"
        const NAME = "escaper";
        fn on_request(flow) {
            // Guard refusal (AC-M3-7): out-of-scope send, uncaught, aborts the hook.
            http.send(#{ method: "GET", url: "http://evil.test/" });
            flow.request.headers.set("X-Should-Not-Appear", "1");
        }
        "#,
    );
    let bystander = TempScript::new(
        "bystander",
        r#"
        const NAME = "bystander";
        fn on_request(flow) { flow.request.headers.set("X-Bystander", "1"); }
        "#,
    );
    let tier = wire::build(
        rhai_cfg(vec![
            ScriptEntry::new(reader.path()),
            ScriptEntry::new(escaper.path()),
            ScriptEntry::new(bystander.path()),
        ]),
        services(store.clone(), guard),
    )
    .expect("tier builds");
    assert!(tier.errors.is_empty(), "{:?}", tier.errors);

    let probe = Arc::new(ProbeLog::default());
    let chain = Arc::new(chain_with(tier.plugins, probe.clone(), store.clone()));
    // The chain is also where the scripts' `Event::Error`s go, so the trailing
    // probe sees them as a native plugin would.
    tier.error_sink.bind(chain.clone());

    let id = insert_request(store.as_ref(), "GET", "/");
    // The chain returns (no stall, no panic): the proxy keeps serving.
    assert_eq!(chain.dispatch(Event::Request(id)).await, Verdict::Continue);

    let flow = store.get(id).unwrap();
    let headers = &http(&flow).request.headers;
    assert_eq!(
        headers.get("X-Read"),
        None,
        "the sandbox-denied hook's edit was discarded"
    );
    assert_eq!(
        headers.get("X-Should-Not-Appear"),
        None,
        "the guard-denied hook's edit was discarded",
    );
    assert_eq!(
        headers.get("X-Bystander"),
        Some("1"),
        "a script after two failing ones still runs and its edit lands",
    );

    // Both failures reached the bus, each naming its script and its cause.
    let deadline = Instant::now() + Duration::from_secs(2);
    let errors = loop {
        let errors: Vec<String> = probe
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                Event::Error { kind, .. } => Some(kind.to_string()),
                _ => None,
            })
            .collect();
        if errors.len() >= 2 || Instant::now() >= deadline {
            break errors;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(
        errors.len(),
        2,
        "one Event::Error per failed hook: {errors:?}"
    );
    let reader_err = errors
        .iter()
        .find(|e| e.contains("reader"))
        .unwrap_or_else(|| panic!("an error names the reader script: {errors:?}"));
    assert!(
        reader_err.contains("open_file"),
        "the sandbox denial names the missing function: {reader_err}"
    );
    let escaper_err = errors
        .iter()
        .find(|e| e.contains("escaper"))
        .unwrap_or_else(|| panic!("an error names the escaper script: {errors:?}"));
    assert!(
        escaper_err.contains("was denied capability 'http.send'")
            && escaper_err.contains("evil.test"),
        "the guard refusal is the pinned denial naming the host: {escaper_err}"
    );
}

/// `(plugin name, X-Seq as that plugin saw it)`, in dispatch order.
type SeqLog = Arc<Mutex<Vec<(&'static str, Option<String>)>>>;

/// A native plugin that records, on each request, the `X-Seq` header *as it
/// stands when the plugin runs* — the observed ordering of AC-M3-10.
struct SeqProbe {
    name: &'static str,
    seen: SeqLog,
}

impl Plugin for SeqProbe {
    fn name(&self) -> &str {
        self.name
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if let (Event::Request(_), Flow::Http(f)) = (ev, ctx.flow()) {
            self.seen.lock().unwrap().push((
                self.name,
                f.request.headers.get("X-Seq").map(str::to_string),
            ));
        }
        Verdict::Continue
    }
}

/// A script that appends `tag` to the `X-Seq` header.
fn seq_script(tag: &str) -> String {
    format!(
        r#"
        const NAME = "seq-{tag}";
        fn on_request(flow) {{
            let seen = flow.request.headers.get("X-Seq");
            flow.request.headers.set("X-Seq", if seen == "" {{ "{tag}" }} else {{ seen + ",{tag}" }});
        }}
        "#
    )
}

/// AC-M3-10, the observed ordering: a native plugin ahead of the scripts sees
/// the flow before any script edit, the scripts run in declaration order, and
/// a native plugin after them sees both edits. Then the binary's own wiring
/// (`assemble_with_scripts`) is checked to place the scripts after every
/// native plugin that acts on a flow and before the command providers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn natives_and_scripts_run_in_registration_order() {
    let a = TempScript::new("seq-a", &seq_script("a"));
    let b = TempScript::new("seq-b", &seq_script("b"));
    let entries = || vec![ScriptEntry::new(a.path()), ScriptEntry::new(b.path())];

    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let tier = wire::build(
        rhai_cfg(entries()),
        services(store.clone(), Arc::new(StdGuard::default())),
    )
    .expect("tier builds");
    assert!(tier.errors.is_empty(), "{:?}", tier.errors);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Registry::new();
    registry.add_plugin(Box::new(SeqProbe {
        name: "lead",
        seen: seen.clone(),
    }));
    for plugin in tier.plugins {
        registry.add_plugin(Box::new(plugin));
    }
    registry.add_plugin(Box::new(SeqProbe {
        name: "trail",
        seen: seen.clone(),
    }));
    let chain = Chain::new(Arc::new(registry), store.clone());

    let id = insert_request(store.as_ref(), "GET", "/");
    assert_eq!(chain.dispatch(Event::Request(id)).await, Verdict::Continue);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("lead", None), ("trail", Some("a,b".to_string()))],
        "natives first, then scripts in declaration order, then the trailing native",
    );
    assert_eq!(
        http(&store.get(id).unwrap()).request.headers.get("X-Seq"),
        Some("a,b")
    );

    // The binary's placement: after the flow-acting natives, before the
    // command providers, in declaration order.
    let tier = wire::build(
        rhai_cfg(entries()),
        services(Arc::new(MemFlowStore::new()), Arc::new(StdGuard::default())),
    )
    .expect("tier builds");
    let mut cfg = Config::default();
    cfg.ca.dir = temp_dir("rhai-order");
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
            commands: Some(Box::new(tier.commands)),
        },
    )
    .expect("assemble");
    let names: Vec<String> = proxy
        .registry_arc()
        .plugins()
        .iter()
        .map(|p| p.lock().unwrap().name().to_string())
        .collect();
    let at = |name: &str| {
        names
            .iter()
            .position(|n| n == name)
            .unwrap_or_else(|| panic!("{name} is registered: {names:?}"))
    };
    assert_eq!(at("seq-b"), at("seq-a") + 1, "declaration order: {names:?}");
    for native in [
        "capture",
        "replay",
        "intercept",
        "mutate",
        "scope",
        "rate-limit",
    ] {
        assert!(
            at(native) < at("seq-a"),
            "{native} precedes the scripts: {names:?}"
        );
    }
    for provider in ["browser", "poc", "scripts"] {
        assert!(
            at("seq-b") < at(provider),
            "{provider} follows the scripts: {names:?}"
        );
    }
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
            commands: Some(Box::new(tier.commands)),
        },
    )
    .expect("assemble with the tagger script");
    let registry = proxy.registry_arc();

    // MCP tools/list includes the script command — and the tier's own three
    // (spec §3/§8: `script.validate`, `script.reload`, `findings.list`).
    // A Rhai-registered command declares no `sensitivity()`, so it is the
    // fail-closed `Sensitive` default with no per-command config gate. Under the
    // corrected policy (spec D2) the *agent* may not call such a command under any
    // policy — `All` runs a Sensitive command only if it carries a config gate. This
    // test is about reachability over the frontends, not the policy gate, so the
    // MCP `tools/call` below is made over an operator connection, which is never
    // policy-gated; the `All` agent state only affects the policy-free `tools/list`.
    let server = aitm_mcp::McpServer::new(registry.clone(), McpTransport::Stdio)
        .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)))
        .with_services(
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
    for tool in ["script.validate", "script.reload", "findings.list"] {
        assert!(
            names.contains(&tool),
            "{tool} is an MCP tool; got {names:?}"
        );
    }

    // MCP tools/call returns "pong" (over an operator connection — see above).
    let call = serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"tagger.ping","arguments":{}}
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_on(
                &aitm_mcp::ConnCtx::new(Frontend::Operator),
                &call.to_string(),
            )
            .expect("a response"),
    )
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

    // `aitm script validate --path <file>` is the CLI face of `script.validate`
    // (spec §8): the worked example validates and reports its hooks.
    let out = cli
        .dispatch(&[
            "script".to_string(),
            "validate".to_string(),
            "--path".to_string(),
            TAGGER.to_string(),
        ])
        .expect("cli script validate");
    let rendered = String::from_utf8(aitm::render::render_cli_value(&out)).unwrap();
    assert!(
        rendered.contains("tagger") && rendered.contains("on_request"),
        "CLI script validate reports the script's name and hooks; got {rendered}",
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

    // Spec review (M3): without an engine the loop body never runs and the
    // test would pass vacuously under `--ignored`; a run that proves nothing
    // must say so instead.
    let engines = engines::engines();
    assert!(
        !engines.is_empty(),
        "no browser engine is enabled: set AITM_OBSCURA=1 (with AITM_OBSCURA_BIN) or \
         AITM_CHROME=1 — this test proves AC-M3-8 only against a real engine"
    );
    for engine in engines {
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

            let Assembled { proxy, ca, .. } = assemble_with_scripts(
                &cfg,
                &Features::default(),
                ScriptWiring {
                    plugins: Vec::new(),
                    executor: Some(tier.executor.clone()),
                    commands: Some(Box::new(tier.commands)),
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
