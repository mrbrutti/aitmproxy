//! Task 14 — `RhaiScriptExecutor`: a PoC `script` step runs on the **same**
//! sandboxed engine and host surface as a scripted plugin (AC-M3-8, impl half).
//!
//! The engine under test is built exactly as the loader builds it: `build_engine`
//! plus every capability provider registered through the §6a seam, plus the
//! prelude — and then handed to the executor as an immutable `Arc`. Nothing is
//! registered for the PoC step that a plugin would not also see, except the
//! per-step `vars` handle. Every test runs on a multi-thread runtime because the
//! step runs under `block_in_place`.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, CallerTrust, CommandHost, ConnInfo, FlowId, FlowMeta, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeEntry,
    ScopeRateGuard, StdGuard, Value,
};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{build_engine, build_engine_with_languages};
use aitm_plugin_rhai::host_core::{
    FindingCapability, LogCapability, MemoryFindingSink, ScriptCapability, ScriptServices,
};
use aitm_plugin_rhai::host_net::{
    BrowserCapability, HttpCapability, ScopeCapability, StoreCapability,
};
use aitm_plugin_rhai::poc_step::{RhaiScriptExecutor, VarsCapability};
use aitm_plugin_rhai::prelude::register_prelude;
use aitm_poc::{ScriptStep, ScriptStepCtx, ScriptStepError, ScriptStepExecutor, ScriptVerdict};
use rhai::Engine;

/// Answers every request `200 pong` and records what it was asked to send, so a
/// test can prove a refused call never reached it.
#[derive(Default)]
struct StubClient {
    sent: Mutex<Vec<HttpRequest>>,
}

impl StubClient {
    fn sent(&self) -> Vec<HttpRequest> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ProxyClient for StubClient {
    fn send(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async move {
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
                    body: Body::Bytes(b"pong".to_vec()),
                    timestamp: SystemTime::now(),
                }),
                client_conn: ConnInfo {
                    peer: "127.0.0.1:0".parse().expect("addr"),
                    sni: None,
                    alpn: None,
                    tls: false,
                    established: SystemTime::now(),
                },
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

/// The shared services: a real store and a real `StdGuard` scoped to `ok.test`,
/// the stub client, no browser. The same handles back both the engine's host
/// verbs and the `CommandHost` the runner hands a step.
struct Harness {
    services: ScriptServices,
    client: Arc<StubClient>,
    guard: Arc<StdGuard>,
    store: Arc<MemFlowStore>,
}

impl Harness {
    fn new() -> Self {
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "ok.test".to_string(),
        });
        let client = Arc::new(StubClient::default());
        let store = Arc::new(MemFlowStore::new());
        let services = ScriptServices {
            store: store.clone(),
            client: client.clone(),
            browser: None,
            guard: guard.clone(),
            findings: Arc::new(MemoryFindingSink::new()),
            rt: tokio::runtime::Handle::current(),
        };
        Self {
            services,
            client,
            guard,
            store,
        }
    }

    /// The engine as the loader builds it: hardened, every provider registered
    /// through the seam, the prelude on top — then frozen behind an `Arc`.
    fn engine(&self, limits: &RhaiLimits) -> Arc<Engine> {
        let mut engine = build_engine(limits, Duration::from_secs(5));
        let providers: [&dyn ScriptCapability; 7] = [
            &LogCapability,
            &FindingCapability,
            &HttpCapability,
            &BrowserCapability::default(),
            &StoreCapability,
            &ScopeCapability::default(),
            &VarsCapability,
        ];
        for provider in providers {
            provider.register(&mut engine, &self.services);
        }
        register_prelude(&mut engine).expect("the prelude compiles");
        Arc::new(engine)
    }

    fn executor(&self) -> RhaiScriptExecutor {
        RhaiScriptExecutor::new(self.engine(&RhaiLimits::default()), self.services.clone())
    }

    /// Run one named step the way the runner does: a fresh `ScriptStepCtx` over
    /// the given bindings and a `CommandHost` on the same handles.
    fn run_step(
        &self,
        exec: &RhaiScriptExecutor,
        script: &str,
        vars: &mut aitm_poc::VarBindings,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        let host = CommandHost::new(
            self.store.as_ref(),
            self.client.as_ref(),
            self.guard.as_ref(),
            None,
        );
        let mut step_results = BTreeMap::new();
        let mut artifacts: Vec<PathBuf> = Vec::new();
        let mut ctx = ScriptStepCtx {
            vars,
            host: &host,
            step_results: &mut step_results,
            artifacts: &mut artifacts,
        };
        let step = ScriptStep {
            script: script.to_string(),
            name: Some("s".to_string()),
        };
        exec.run_step(&step, &mut ctx)
    }
}

fn str_var(vars: &aitm_poc::VarBindings, name: &str) -> Option<String> {
    match vars.get(name) {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

#[test]
fn vars_capability_names_its_namespace() {
    assert_eq!(VarsCapability.namespace(), "vars");
    assert_eq!(VarsCapability.min_api(), "1");
}

/// Plan: `vars.set("x", "1"); return pass;` → `Pass`, and `ctx.vars` has `x == "1"`.
/// Also reads a binding an earlier step left (spec §10 inputs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_and_sets_vars() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new().with("target", Value::Str("http://ok.test".into()));

    let verdict = h
        .run_step(
            &exec,
            r#"
            let base = vars.get("target");
            vars.set("x", "1");
            vars.set("url", base + "/notes");
            return pass;
            "#,
            &mut vars,
        )
        .expect("the step runs");

    assert_eq!(verdict, ScriptVerdict::Pass);
    assert_eq!(str_var(&vars, "x").as_deref(), Some("1"));
    assert_eq!(
        str_var(&vars, "url").as_deref(),
        Some("http://ok.test/notes"),
        "a read of an earlier binding must see the seeded value"
    );
    assert_eq!(
        str_var(&vars, "target").as_deref(),
        Some("http://ok.test"),
        "bindings the script did not touch are kept"
    );
}

/// `return fail` is `Fail`; falling off the end — or ending on a value that is
/// neither verdict — is `Neutral` (Review Focus #5); a read of an unbound var is
/// `()` and never aborts the step (option C).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_neutral_and_forgiving_read() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    let fail = h
        .run_step(
            &exec,
            r#"if vars.get("csrf") == () { return fail; } return pass;"#,
            &mut vars,
        )
        .expect("the step runs");
    assert_eq!(
        fail,
        ScriptVerdict::Fail,
        "an unbound var reads as () and the branch fails"
    );

    let neutral = h
        .run_step(&exec, r#"vars.set("seen", "yes");"#, &mut vars)
        .expect("the step runs");
    assert_eq!(neutral, ScriptVerdict::Neutral);
    assert_eq!(str_var(&vars, "seen").as_deref(), Some("yes"));

    let value_tail = h
        .run_step(&exec, r#"let n = 41; n + 1"#, &mut vars)
        .expect("the step runs");
    assert_eq!(
        value_tail,
        ScriptVerdict::Neutral,
        "a non-verdict value is neutral"
    );

    let bare_pass = h
        .run_step(&exec, r#"pass"#, &mut vars)
        .expect("the step runs");
    assert_eq!(
        bare_pass,
        ScriptVerdict::Pass,
        "the verdict may be the tail expression"
    );
}

/// Plan `guarded_call_enforced` (AC-M3-7/8): `http.send` to an out-of-scope host
/// with no `try`/`catch` is a `ScriptStepError` naming the host — the same guard
/// a plugin's call rides, not a panic and not a silent skip — and the client is
/// never reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guarded_call_enforced() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    let err = h
        .run_step(
            &exec,
            r#"http.send(#{ method: "GET", url: "http://evil.test/" }); return pass;"#,
            &mut vars,
        )
        .expect_err("an out-of-scope send must fail the step");

    let text = err.to_string();
    assert!(
        text.contains("evil.test"),
        "the error must name the host: {text}"
    );
    assert!(
        text.contains("denied"),
        "the error must say it was denied: {text}"
    );
    assert!(
        text.contains("error: s"),
        "the error must name the step: {text}"
    );
    assert!(
        h.client.sent().is_empty(),
        "a refused send never reaches the client"
    );
}

/// Plan `sandbox_denial_is_error` (AC-M3-5/8): a step that reaches for the
/// filesystem, `eval`, or a module import gets a `ScriptStepError`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandbox_denial_is_error() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    for script in [
        r#"open_file("/etc/passwd"); return pass;"#,
        r#"eval("1+1"); return pass;"#,
        r#"import "m" as m; return pass;"#,
    ] {
        let err = h
            .run_step(&exec, script, &mut vars)
            .expect_err("a disallowed op must fail the step");
        assert!(
            err.to_string().starts_with("error: s"),
            "the error carries the pinned format for {script}: {err}"
        );
    }
}

/// A step that errors after `vars.set(...)` leaves `ctx.vars` untouched — the
/// step is atomic, as a hook's edits are (Task 8's effect model).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errored_step_discards_var_writes() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new().with("keep", Value::Str("old".into()));

    h.run_step(
        &exec,
        r#"vars.set("keep", "new"); vars.set("fresh", "x"); throw "boom";"#,
        &mut vars,
    )
    .expect_err("a throw fails the step");

    assert_eq!(str_var(&vars, "keep").as_deref(), Some("old"));
    assert!(
        vars.get("fresh").is_none(),
        "a write before the error must not land"
    );
}

/// AC-M3-6 for a step: an infinite loop is cut by the operation budget, the error
/// names the budget, and the step returns promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runaway_step_hits_op_budget() {
    let h = Harness::new();
    let limits = RhaiLimits {
        max_operations: 10_000,
        ..RhaiLimits::default()
    };
    let exec = RhaiScriptExecutor::new(h.engine(&limits), h.services.clone());
    let mut vars = aitm_poc::VarBindings::new();

    let started = Instant::now();
    let err = h
        .run_step(&exec, r#"let i = 0; loop { i += 1; }"#, &mut vars)
        .expect_err("a runaway step must be aborted");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the abort must be prompt"
    );
    assert!(
        err.to_string().contains("10000 operation budget"),
        "the error must name the budget: {err}"
    );
}

/// Quality review (M3, Minor): a step that runs out of wall-clock names the
/// *configured* budget — the figure the operator set — not the elapsed time
/// it happened to measure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_step_names_the_configured_time_budget() {
    use aitm_plugin_rhai::engine::Budget;

    let h = Harness::new();
    let limits = RhaiLimits {
        max_operations: 0,
        ..RhaiLimits::default()
    };
    let budget = Budget {
        max_operations: 0,
        hook_timeout: Duration::from_millis(50),
        browser_timeout: Duration::from_secs(30),
    };
    let exec = RhaiScriptExecutor::new(h.engine(&limits), h.services.clone()).with_budget(budget);
    let mut vars = aitm_poc::VarBindings::new();

    let started = Instant::now();
    let err = h
        .run_step(&exec, r#"let i = 0; loop { i += 1; }"#, &mut vars)
        .expect_err("a slow step must be aborted");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        err.to_string().contains("50ms time budget"),
        "the error quotes the configured budget: {err}"
    );
}

/// Security review (M3, Important): a PoC step never widens the scope, even
/// where plugin scripts are allowed to — a PoC is a shared artifact that runs
/// inside the scope the operator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn step_cannot_widen_scope() {
    let h = Harness::new();
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(5));
    ScopeCapability::new(true).register(&mut engine, &h.services);
    VarsCapability.register(&mut engine, &h.services);
    let exec = RhaiScriptExecutor::new(Arc::new(engine), h.services.clone());
    let mut vars = aitm_poc::VarBindings::new();

    let err = h
        .run_step(&exec, r#"scope.add("evil.test"); return pass;"#, &mut vars)
        .expect_err("scope.add from a step must fail the step");
    assert!(err.to_string().contains("PoC"), "{err}");
    assert!(
        !h.guard.list_scope().iter().any(|e| e.host == "evil.test"),
        "the scope is unchanged"
    );
}

/// A script that does not parse is a positioned `ScriptStepError`, not a panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compile_error_is_step_error() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    let err = h
        .run_step(&exec, "let x = ;\nreturn pass;", &mut vars)
        .expect_err("a syntax error fails the step");
    assert!(
        err.to_string().starts_with("error: s:1:"),
        "the error must carry the line and column: {err}"
    );
}

/// The one-surface requirement: the step uses the identical host verbs and
/// prelude helpers a plugin does — an in-scope `http.send` goes through the stub
/// client, `contains_ci` comes from the prelude, `log` is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn step_shares_the_plugin_surface() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    let verdict = h
        .run_step(
            &exec,
            r#"
            log.info("probing");
            let r = http.send(#{ method: "POST", url: "http://ok.test/notes", body: "note=x" });
            vars.set("status", r.status);
            if contains_ci(r.body, "PONG") && ok(r) { return pass; }
            return fail;
            "#,
            &mut vars,
        )
        .expect("an in-scope send runs");

    assert_eq!(verdict, ScriptVerdict::Pass);
    assert_eq!(vars.get("status"), Some(&Value::Int(200)));
    let sent = h.client.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].authority, "ok.test");
}

/// The same executor serves many steps and many scripts without cross-talk; a
/// recompiled (cached) script still yields a fresh scope each run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_steps_do_not_leak_scope() {
    let h = Harness::new();
    let exec = h.executor();
    let mut vars = aitm_poc::VarBindings::new();

    let first = h
        .run_step(
            &exec,
            r#"let n = 1; vars.set("n", n); return pass;"#,
            &mut vars,
        )
        .expect("runs");
    assert_eq!(first, ScriptVerdict::Pass);

    // `n` from the first run must not be visible: this script reads a scope
    // variable that only exists if state leaked, so it must error.
    h.run_step(&exec, r#"vars.set("leak", n); return pass;"#, &mut vars)
        .expect_err("a leaked scope variable would make this pass");
    assert!(vars.get("leak").is_none());

    // The identical script text runs again (cache hit) and still works.
    let again = h
        .run_step(
            &exec,
            r#"let n = 1; vars.set("n", n); return pass;"#,
            &mut vars,
        )
        .expect("runs again");
    assert_eq!(again, ScriptVerdict::Pass);
}

// ===========================================================================
// Task 3 — a PoC `script:` step seeds the caller trust from the `poc.run`
// `CommandHost` frontend before the step evaluates, so a seam host fn the step
// calls observes the live trust (spec AC5 script face; AC3 poc-step boundary).
// ===========================================================================

/// A seam language whose `probe.trust()` returns the live `ctx.caller()` label.
struct ProbeLanguage;

struct AdmitGuard;

impl GuardHandle for AdmitGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }
    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

impl ProtocolLanguage for ProbeLanguage {
    fn namespace(&self) -> &str {
        "probe"
    }
    fn api_version(&self) -> &str {
        "1"
    }
    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let trust: HostFn = Box::new(|ctx: &HostCallCtx, _args: &[Value]| {
            let label = match ctx.caller() {
                CallerTrust::Operator => "operator",
                CallerTrust::Agent => "agent",
            };
            Ok(Value::Str(label.to_string()))
        });
        reg.register("probe", "trust", Guarded::new(Box::new(AdmitGuard), trust))
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

impl Harness {
    /// An engine carrying the probe seam language plus the `vars` handle, as the
    /// loader would build one with a protocol language installed.
    fn seam_engine(&self) -> Arc<Engine> {
        let mut engine = build_engine_with_languages(
            &RhaiLimits::default(),
            Duration::from_secs(5),
            &[&ProbeLanguage],
        )
        .expect("the probe seam language installs");
        VarsCapability.register(&mut engine, &self.services);
        Arc::new(engine)
    }

    /// Run `script` as a step under a `CommandHost` declaring `frontend`.
    fn run_step_as(
        &self,
        exec: &RhaiScriptExecutor,
        script: &str,
        vars: &mut aitm_poc::VarBindings,
        frontend: Frontend,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        let host = CommandHost::new(
            self.store.as_ref(),
            self.client.as_ref(),
            self.guard.as_ref(),
            None,
        )
        .with_frontend(frontend);
        let mut step_results = BTreeMap::new();
        let mut artifacts: Vec<PathBuf> = Vec::new();
        let mut ctx = ScriptStepCtx {
            vars,
            host: &host,
            step_results: &mut step_results,
            artifacts: &mut artifacts,
        };
        let step = ScriptStep {
            script: script.to_string(),
            name: Some("s".to_string()),
        };
        exec.run_step(&step, &mut ctx)
    }
}

/// AC5 (script face): a `script:` step in a PoC observes the `poc.run` frontend's
/// trust via `ctx.caller()` — `Agent` for an MCP agent, `Operator` for the human
/// CLI. AC3: the step boundary is seeded (never refused "no caller context").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_step_seeds_frontend_caller_trust() {
    let h = Harness::new();
    let exec = RhaiScriptExecutor::new(h.seam_engine(), h.services.clone());

    let mut vars = aitm_poc::VarBindings::new();
    let verdict = h
        .run_step_as(
            &exec,
            r#"vars.set("seen", probe.trust()); return pass;"#,
            &mut vars,
            Frontend::Mcp,
        )
        .expect("an agent-frontend step runs (seeded), not refused for missing context");
    assert_eq!(verdict, ScriptVerdict::Pass);
    assert_eq!(str_var(&vars, "seen").as_deref(), Some("agent"));

    let mut vars = aitm_poc::VarBindings::new();
    h.run_step_as(
        &exec,
        r#"vars.set("seen", probe.trust()); return pass;"#,
        &mut vars,
        Frontend::Cli,
    )
    .expect("a CLI-frontend step runs");
    assert_eq!(
        str_var(&vars, "seen").as_deref(),
        Some("operator"),
        "the human CLI frontend must seed Operator, never leave the step agent"
    );
}
