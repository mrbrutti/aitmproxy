//! Task 4 — the Rhai scanner foundations.
//!
//! `http.send` returns a host-measured `elapsed_ms` (D4 "Timing without
//! `sleep`"); a thread-local client override ([`with_client`]) routes a check's
//! sends through the job's client (D9.3); `Budget::for_check` carries the
//! per-check wall budget and [`probe_budget`] caps a single probe at 30 s;
//! `ScriptError::CheckMeta` names the offending key; and the run kind is visible
//! to a seam guard through `HostCallCtx::run_kind`.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CallerTrust, Command, CommandHost, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    Registry, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallContextSource, HostCallCtx, HostError, HostFn, HostRunKind,
    NamespaceCatalog, PocStepHandler, ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::command::{register_reg_api, ScriptRegHandle};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{
    begin_run, build_engine, build_engine_with_languages, probe_budget, Budget, RunKind,
};
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::host_net::{with_client, HttpCapability};
use aitm_plugin_rhai::host_registry::seed_call_context;

/// A placeholder client connection for a locally-answered request.
fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("addr"),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// A client that answers `200` with a fixed body after an optional delay, and
/// records every request (with the default `SendOptions` of the `send` path) it
/// was asked to perform — so a test can prove which client a send reached.
struct StubClient {
    body: &'static [u8],
    delay: Duration,
    sent: Mutex<Vec<HttpRequest>>,
}

impl StubClient {
    fn new(body: &'static [u8], delay: Duration) -> Self {
        Self {
            body,
            delay,
            sent: Mutex::new(Vec::new()),
        }
    }
}

impl ProxyClient for StubClient {
    fn send(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async move {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.sent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(req.clone());
            Ok(HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    trailers: HeaderMap::new(),
                    body: Body::Bytes(self.body.to_vec()),
                    timestamp: SystemTime::now(),
                }),
                client_conn: conn(),
                server_conn: None,
                metadata: FlowMeta {
                    is_replay: true,
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            })
        })
    }
}

/// A client that is never reached: the `CommandHost` services are unused because
/// every network verb rides the `ScriptServices` client wired into the engine.
struct NeverClient;

impl ProxyClient for NeverClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("the command host client is never reached") })
    }
}

/// The script services a check reaches: a real store and `StdGuard` (scoped to
/// `scope`), plus `client`. The runtime handle is the test runtime.
fn services_with(client: Arc<dyn ProxyClient>, scope: &[&str]) -> ScriptServices {
    let guard = Arc::new(StdGuard::default());
    for host in scope {
        guard.add_scope(ScopeEntry {
            host: (*host).to_string(),
        });
    }
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client,
        browser: None,
        guard,
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// Build the engine (with the `http` namespace and the `load(reg)` bridge),
/// compile `src`, run its `load`, and return the platform `Registry` it filled.
fn registry_for(services: &ScriptServices, src: &str) -> Registry {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_reg_api(&mut engine);
    HttpCapability.register(&mut engine, services);
    let engine = Arc::new(engine);

    let mut ast = engine.compile(src).expect("script compiles");
    ast.set_source("t");
    let ast = Arc::new(ast);

    let mut registry = Registry::new();
    let mut handle = ScriptRegHandle::new(&mut registry);
    handle.run_load(&engine, &ast).expect("load runs");
    registry
}

/// Invoke a registered command with no arguments, through a throwaway host whose
/// own client is never reached.
fn invoke(cmd: &Arc<dyn Command>) -> Value {
    let store = MemFlowStore::new();
    let client = NeverClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    cmd.invoke(Params::default(), &host)
        .expect("command invokes")
}

/// D4: `http.send` returns the host-measured wall time as `elapsed_ms`. The stub
/// sleeps 20 ms; the measured figure is at least that and well under the command
/// budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_send_returns_elapsed_ms() {
    let client = Arc::new(StubClient::new(b"A", Duration::from_millis(20)));
    let services = services_with(client, &["ex.test"]);
    let registry = registry_for(
        &services,
        r#"fn load(reg) { reg.add_command("t.send", "d", |args| { let r = http.send(#{ method: "GET", url: "http://ex.test/" }); r.elapsed_ms }); }"#,
    );
    let cmd = registry.command("t.send").expect("t.send registered");

    match invoke(cmd) {
        Value::Int(n) => assert!(
            (20..5000).contains(&n),
            "elapsed_ms must be at least the server delay and under the budget, got {n}"
        ),
        other => panic!("elapsed_ms must be an integer, got {other:?}"),
    }
}

/// D9.3: inside `with_client(override, ..)` every `http.send` routes through the
/// override, and a plain send afterwards is back on the namespace's own client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_client_override_routes_http_send() {
    let stub_a = Arc::new(StubClient::new(b"A", Duration::ZERO));
    let stub_b: Arc<dyn ProxyClient> = Arc::new(StubClient::new(b"B", Duration::ZERO));
    let services = services_with(stub_a, &["ex.test"]);
    let registry = registry_for(
        &services,
        r#"fn load(reg) { reg.add_command("t.send", "d", |args| { http.send(#{ method: "GET", url: "http://ex.test/" }).body }); }"#,
    );
    let cmd = registry.command("t.send").expect("t.send registered");

    let routed = with_client(Arc::clone(&stub_b), || invoke(cmd));
    assert_eq!(
        routed,
        Value::Str("B".into()),
        "a send inside with_client must reach the override"
    );

    let plain = invoke(cmd);
    assert_eq!(
        plain,
        Value::Str("A".into()),
        "a send after with_client must be back on the namespace client"
    );
}

/// D4: a check's run budget is the per-check wall budget, not the hook budget;
/// every other field is inherited.
#[test]
fn budget_for_check_uses_the_check_timeout() {
    let budget = Budget::for_check(Budget::default(), Duration::from_secs(60));
    assert_eq!(budget.hook_timeout, Duration::from_secs(60));
    assert_eq!(budget.max_operations, Budget::default().max_operations);
}

/// D4: a single probe is capped at 30 s even when the check's wall budget leaves
/// far more.
#[test]
fn probe_budget_is_capped_at_30s() {
    let _run = begin_run(
        RunKind::Check,
        Budget::for_check(Budget::default(), Duration::from_secs(120)),
    );
    let budget = probe_budget().expect("a probe budget exists inside a check run");
    assert!(
        budget <= Duration::from_secs(30),
        "a probe is capped at 30 s, got {budget:?}"
    );
    assert!(
        budget > Duration::from_secs(29),
        "the cap, not a sliver of it, is what a fresh check gets: {budget:?}"
    );
}

/// D4: a `CheckMeta` load error names the offending key.
#[test]
fn check_meta_error_names_the_key() {
    let err = ScriptError::CheckMeta {
        script: "s".into(),
        check: None,
        key: "kinds".into(),
        message: "missing".into(),
    };
    assert!(
        err.to_string().contains("`kinds`"),
        "the error must name the key, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// The run-kind seam: a guard reads `ctx.run_kind()`, which answers the kind of
// the run driving the call (Command from a `reg.add_command` closure, Hook from
// a flow hook) and `None` over a source with the default method.
// ---------------------------------------------------------------------------

/// A guard that admits every call and records the run kind it observed.
struct RecordingGuard {
    seen: Arc<Mutex<Vec<Option<HostRunKind>>>>,
}

impl GuardHandle for RecordingGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }

    fn permit(&self, ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(ctx.run_kind());
        Ok(())
    }
}

/// A seam language whose guard records the run kind of every `probe.record()`.
struct RecordingLanguage {
    seen: Arc<Mutex<Vec<Option<HostRunKind>>>>,
}

impl ProtocolLanguage for RecordingLanguage {
    fn namespace(&self) -> &str {
        "probe"
    }

    fn api_version(&self) -> &str {
        "1"
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let record: HostFn = Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Null));
        reg.register(
            "probe",
            "record",
            Guarded::new(
                Box::new(RecordingGuard {
                    seen: Arc::clone(&self.seen),
                }),
                record,
            ),
        )
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

/// A call-context source that never tracks the run kind, so its `run_kind()` is
/// the trait default.
struct StubSource;

impl HostCallContextSource for StubSource {
    fn tag(&self) -> Option<Value> {
        None
    }

    fn call_source(&self) -> &str {
        "stub"
    }
}

/// Coordinator decision 5 (D8.3): `ctx.run_kind()` answers the kind of the run
/// driving the seam call — `Command` from a `reg.add_command` closure, `Hook`
/// from a flow hook — and `None` over a source whose method is the default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_kind_is_visible_to_a_seam_guard() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lang = RecordingLanguage {
        seen: Arc::clone(&seen),
    };
    let mut engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), &[&lang])
            .expect("the recording language installs");
    register_reg_api(&mut engine);
    let engine = Arc::new(engine);

    // From a command closure: the run is a Command.
    let mut ast = engine
        .compile(
            r#"fn load(reg) { reg.add_command("t.probe", "", |args| { probe.record(); "ok" }); }"#,
        )
        .expect("script compiles");
    ast.set_source("t");
    let ast = Arc::new(ast);
    let mut registry = Registry::new();
    {
        let mut handle = ScriptRegHandle::new(&mut registry);
        handle.run_load(&engine, &ast).expect("load runs");
    }
    let cmd = registry.command("t.probe").expect("t.probe registered");
    assert_eq!(invoke(cmd), Value::Str("ok".into()));
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![Some(HostRunKind::Command)],
        "a command closure's seam call reports Command"
    );

    // From a flow hook: the run is a Hook.
    seen.lock().unwrap_or_else(PoisonError::into_inner).clear();
    tokio::task::block_in_place(|| {
        let _run = begin_run(RunKind::Hook, Budget::default());
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        engine
            .run("probe.record();")
            .expect("probe.record under a hook run");
    });
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![Some(HostRunKind::Hook)],
        "a flow hook's seam call reports Hook"
    );

    // Over a source with the default method: None.
    let source = StubSource;
    let ctx = HostCallCtx::new(CallerTrust::Operator, &source);
    assert_eq!(
        ctx.run_kind(),
        None,
        "a source that cannot tell yields None"
    );
}
