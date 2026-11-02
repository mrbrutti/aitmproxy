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
use std::time::{Duration, Instant, SystemTime};

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
    begin_run, build_engine, build_engine_with_languages, probe_budget, AbortKind, Budget, RunKind,
    MAX_PROBE_TIMEOUT,
};
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::host_net::{with_client, HttpCapability};
use aitm_plugin_rhai::host_registry::seed_call_context;
use rhai::{Dynamic, Engine, EvalAltResult};

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
                    peer: None,
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

/// D4: a `CheckMeta` load error names the offending key — and, pinned in full,
/// the help line lists exactly the keys a script may omit (`origin` is the
/// host's, never the script's).
#[test]
fn check_meta_error_names_the_key() {
    let err = ScriptError::CheckMeta {
        script: "s".into(),
        check: None,
        key: "kinds".into(),
        message: "missing".into(),
    };
    assert_eq!(
        err.to_string(),
        "script `s`: reg.add_check `?`: `kinds`: missing\n  help: every key of `CheckMeta` is \
         required except `wants_traits`, `cwe`, `remediation`, `needs_baseline`, \
         `targets_session`, `scope`; `origin` is supplied by the host, not the script; see \
         docs/scanner.md"
    );
}

/// Wave-1 security review: a check timeout at the top of the range must not
/// panic the engine thread — `Instant + Duration::from_secs(u64::MAX)` would —
/// so the run opens with a far-future deadline and a probe still gets the cap.
#[test]
fn a_huge_check_timeout_does_not_panic() {
    let _run = begin_run(
        RunKind::Check,
        Budget::for_check(Budget::default(), Duration::from_secs(u64::MAX)),
    );
    assert!(probe_budget().is_some(), "a run is open");
    assert_eq!(probe_budget(), Some(MAX_PROBE_TIMEOUT));
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

// ---------------------------------------------------------------------------
// Tester additions (stage 5, T1b wave 1): the override's restore guarantees,
// the probe budget's edges, the Check run's own wall budget, the remaining
// run-kind mappings and the CheckMeta error's full shape.
// ---------------------------------------------------------------------------

/// An engine with the `http` namespace only — for evaluating `http.send` directly
/// under a run the test opens itself (a `reg.add_command` closure would open its
/// own `Command` run and hide the kind under test).
fn http_engine(services: &ScriptServices) -> Arc<Engine> {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    HttpCapability.register(&mut engine, services);
    Arc::new(engine)
}

/// Evaluate `src` the way the scanner's check dispatcher will: on the calling
/// thread, inside `block_in_place`, under a `Check` run with `check_timeout`.
fn eval_under_check<T: Clone + Send + Sync + 'static>(
    engine: &Engine,
    check_timeout: Duration,
    src: &str,
) -> Result<T, Box<EvalAltResult>> {
    tokio::task::block_in_place(|| {
        let _run = begin_run(
            RunKind::Check,
            Budget::for_check(Budget::default(), check_timeout),
        );
        engine.eval::<T>(src)
    })
}

/// Tester: `with_client` restores the previous client when `f` **unwinds**, so
/// a panicking check never leaves the job's client on the thread for the next
/// unrelated send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_client_restores_the_previous_client_after_a_panic() {
    let stub_a = Arc::new(StubClient::new(b"A", Duration::ZERO));
    let stub_b: Arc<dyn ProxyClient> = Arc::new(StubClient::new(b"B", Duration::ZERO));
    let services = services_with(stub_a, &["ex.test"]);
    let registry = registry_for(
        &services,
        r#"fn load(reg) { reg.add_command("t.send", "d", |args| { http.send(#{ method: "GET", url: "http://ex.test/" }).body }); }"#,
    );
    let cmd = registry.command("t.send").expect("t.send registered");

    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_client(Arc::clone(&stub_b), || -> Value {
            assert_eq!(invoke(cmd), Value::Str("B".into()), "the override is live");
            panic!("the check blew up");
        })
    }));
    std::panic::set_hook(hook);
    assert!(outcome.is_err(), "the closure panicked");

    assert_eq!(
        invoke(cmd),
        Value::Str("A".into()),
        "after the unwind the namespace client is back"
    );
}

/// Tester: overrides nest — an inner `with_client` wins while it lasts and the
/// outer override is restored when it returns, not cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_client_nests_and_restores_the_outer_override() {
    let stub_a = Arc::new(StubClient::new(b"A", Duration::ZERO));
    let stub_b: Arc<dyn ProxyClient> = Arc::new(StubClient::new(b"B", Duration::ZERO));
    let stub_c: Arc<dyn ProxyClient> = Arc::new(StubClient::new(b"C", Duration::ZERO));
    let services = services_with(stub_a, &["ex.test"]);
    let registry = registry_for(
        &services,
        r#"fn load(reg) { reg.add_command("t.send", "d", |args| { http.send(#{ method: "GET", url: "http://ex.test/" }).body }); }"#,
    );
    let cmd = registry.command("t.send").expect("t.send registered");

    with_client(Arc::clone(&stub_b), || {
        assert_eq!(
            with_client(Arc::clone(&stub_c), || invoke(cmd)),
            Value::Str("C".into()),
            "the inner override wins while it lasts"
        );
        assert_eq!(
            invoke(cmd),
            Value::Str("B".into()),
            "the outer override is restored, not cleared"
        );
    });
    assert_eq!(invoke(cmd), Value::Str("A".into()));
}

/// Tester: the override is thread-local — a send on another thread, with no
/// `with_client` of its own, uses the namespace client even while this thread
/// is inside one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_client_does_not_leak_to_other_threads() {
    let stub_a = Arc::new(StubClient::new(b"A", Duration::ZERO));
    let stub_b: Arc<dyn ProxyClient> = Arc::new(StubClient::new(b"B", Duration::ZERO));
    let services = services_with(stub_a, &["ex.test"]);
    let registry = Arc::new(registry_for(
        &services,
        r#"fn load(reg) { reg.add_command("t.send", "d", |args| { http.send(#{ method: "GET", url: "http://ex.test/" }).body }); }"#,
    ));
    let cmd = Arc::clone(registry.command("t.send").expect("t.send registered"));

    let rt = tokio::runtime::Handle::current();
    let elsewhere = with_client(Arc::clone(&stub_b), || {
        let cmd = Arc::clone(&cmd);
        let rt = rt.clone();
        std::thread::spawn(move || {
            let _enter = rt.enter();
            invoke(&cmd)
        })
        .join()
        .expect("the other thread's send completes")
    });
    assert_eq!(
        elsewhere,
        Value::Str("A".into()),
        "another thread never sees this thread's override"
    );
}

/// Tester: outside any run there is no probe budget (the host falls back to the
/// hook default), and under a run whose remainder is below the cap the probe
/// budget is that remainder — the cap is a ceiling, never a floor.
#[test]
fn probe_budget_is_none_outside_a_run_and_the_remainder_under_the_cap() {
    assert_eq!(probe_budget(), None, "no run, no probe budget");
    assert_eq!(MAX_PROBE_TIMEOUT, Duration::from_secs(30));

    let _run = begin_run(
        RunKind::Check,
        Budget::for_check(Budget::default(), Duration::from_millis(500)),
    );
    let budget = probe_budget().expect("inside a run");
    assert!(
        budget <= Duration::from_millis(500),
        "a short remainder is not raised to the cap: {budget:?}"
    );
    assert!(budget > Duration::from_millis(400), "{budget:?}");
}

/// Tester (D4 "not the 2 s hook budget"): under a `Check` run with a 5 s wall
/// budget, a probe the server holds for 2.3 s — longer than the default hook
/// budget — completes and reports its real `elapsed_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_run_send_outlives_the_hook_budget_and_measures_it() {
    let client = Arc::new(StubClient::new(b"slow", Duration::from_millis(2_300)));
    let services = services_with(client, &["ex.test"]);
    let engine = http_engine(&services);

    let elapsed: rhai::INT = eval_under_check(
        &engine,
        Duration::from_secs(5),
        r#"http.send(#{ method: "GET", url: "http://ex.test/" }).elapsed_ms"#,
    )
    .expect("a 2.3 s probe completes under a 5 s check budget");
    assert!(
        (2_300..5_000).contains(&elapsed),
        "elapsed_ms must cover the server's delay, got {elapsed}"
    );
}

/// Tester (D4 `min(remaining, 30 s)`): a probe that stalls past the check's
/// remaining budget aborts the run with the `Timeout` termination at that
/// remainder — a `Check` run is bounded too, not open-ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_run_stalled_probe_aborts_at_the_check_remainder() {
    let client = Arc::new(StubClient::new(b"never", Duration::from_secs(30)));
    let services = services_with(client, &["ex.test"]);
    let engine = http_engine(&services);

    let started = Instant::now();
    let err = eval_under_check::<Dynamic>(
        &engine,
        Duration::from_millis(300),
        r#"try { http.send(#{ method: "GET", url: "http://ex.test/" }); } catch(e) { "caught" }"#,
    )
    .expect_err("a stalled probe aborts the run, uncaught");
    let elapsed = started.elapsed();

    let kind = match &*err {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<AbortKind>(),
        _ => None,
    };
    assert_eq!(kind, Some(AbortKind::Timeout), "{err}");
    assert!(
        elapsed < Duration::from_secs(2),
        "the probe must end at the check remainder, got {elapsed:?}"
    );
}

/// Tester: `elapsed_ms` rides alongside the existing response keys — it is an
/// addition, not a replacement — and a zero-delay send reads as a small number.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_send_keeps_its_keys_and_adds_elapsed_ms() {
    let client = Arc::new(StubClient::new(b"A", Duration::ZERO));
    let services = services_with(client, &["ex.test"]);
    let engine = http_engine(&services);

    let map: rhai::Map = eval_under_check(
        &engine,
        Duration::from_secs(5),
        r#"http.send(#{ method: "GET", url: "http://ex.test/" })"#,
    )
    .expect("the send completes");
    for key in ["flow_id", "status", "body", "elapsed_ms"] {
        assert!(map.contains_key(key), "missing `{key}` in {map:?}");
    }
    assert_eq!(map["status"].as_int().expect("int"), 200);
    let elapsed = map["elapsed_ms"].as_int().expect("elapsed_ms is an INT");
    assert!((0..1_000).contains(&elapsed), "got {elapsed}");
}

/// Tester: the three remaining variants map one-for-one — `Check`, `Load` and
/// `PocStep` are what a seam guard sees under those runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_kind_maps_check_load_and_poc_step() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lang = RecordingLanguage {
        seen: Arc::clone(&seen),
    };
    let engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), &[&lang])
            .expect("the recording language installs");

    for (kind, expected) in [
        (RunKind::Check, HostRunKind::Check),
        (RunKind::Load, HostRunKind::Load),
        (RunKind::PocStep, HostRunKind::PocStep),
    ] {
        seen.lock().unwrap_or_else(PoisonError::into_inner).clear();
        tokio::task::block_in_place(|| {
            let _run = begin_run(kind, Budget::default());
            let _seed = seed_call_context(CallerTrust::Operator, None, None);
            engine.run("probe.record();").expect("probe.record runs");
        });
        assert_eq!(
            *seen.lock().unwrap_or_else(PoisonError::into_inner),
            vec![Some(expected)],
            "{kind:?} maps to {expected:?}"
        );
    }

    // And with no run open at all, the rhai source reports None.
    seen.lock().unwrap_or_else(PoisonError::into_inner).clear();
    tokio::task::block_in_place(|| {
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        engine
            .run("probe.record();")
            .expect("probe.record runs bare");
    });
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![None],
        "outside any run the source cannot tell"
    );
}

/// Tester: `Budget::for_check` changes `hook_timeout` only — the browser budget
/// and operation cap are the base's — and a zero check timeout is carried as
/// given (the engine, not this constructor, decides what zero means).
#[test]
fn budget_for_check_changes_only_the_hook_timeout() {
    let base = Budget::default();
    let check = Budget::for_check(base, Duration::from_secs(60));
    assert_eq!(check.browser_timeout, base.browser_timeout);
    assert_eq!(check.max_operations, base.max_operations);
    assert_eq!(check.hook_timeout, Duration::from_secs(60));
    assert_ne!(
        check.hook_timeout, base.hook_timeout,
        "a check is not a hook"
    );

    let zero = Budget::for_check(base, Duration::ZERO);
    assert_eq!(zero.hook_timeout, Duration::ZERO);
}

/// Tester: the full `CheckMeta` error shape — script, the check id when known
/// (`?` when not), the key, the message and the help line that lists the
/// optional keys — so an operator can fix the script from the message alone.
#[test]
fn check_meta_error_shows_script_check_key_message_and_help() {
    let known = ScriptError::CheckMeta {
        script: "custom/xss.rhai".into(),
        check: Some("xss-reflected".into()),
        key: "kinds".into(),
        message: "expected an array of insertion kinds".into(),
    }
    .to_string();
    assert!(known.starts_with(
        "script `custom/xss.rhai`: reg.add_check `xss-reflected`: `kinds`: expected an array of insertion kinds"
    ), "{known}");
    assert!(known.contains("help:"), "{known}");
    for optional in ["wants_traits", "cwe", "remediation", "needs_baseline"] {
        assert!(
            known.contains(optional),
            "help must list `{optional}`: {known}"
        );
    }
    assert!(known.contains("docs/scanner.md"), "{known}");

    let unknown = ScriptError::CheckMeta {
        script: "s".into(),
        check: None,
        key: "id".into(),
        message: "missing".into(),
    }
    .to_string();
    assert!(
        unknown.contains("reg.add_check `?`: `id`: missing"),
        "{unknown}"
    );
}
