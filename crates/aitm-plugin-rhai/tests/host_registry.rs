//! Task 2 — the `ScriptHostRegistry` seam in the rhai engine.
//!
//! A protocol crate injects its `<ns>.*` host fns from its own crate; the engine
//! drives each registered `ProtocolLanguage::register_host_fns` and a script
//! calls `test.ping()` with **no edit to `aitm-plugin-rhai`** (AC1). Each fn is
//! `Guarded`, so a refusing guard stops the effect (AC2a); registering a
//! namespace twice is a hard collision, never last-wins (Review Focus). The
//! compile-time half of AC2 (an unguarded effectful fn fails to type-check) is a
//! `compile_fail` doctest on `aitm_plugin_rhai::host_registry`.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{CallerTrust, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard, Value};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::engine::build_engine_with_languages;
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::host_registry::seed_call_context;
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_proto_test::TestLanguage;
use rhai::Engine;

/// A hardened engine with the given languages installed through the seam.
fn engine_for(languages: &[&dyn ProtocolLanguage]) -> Engine {
    build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), languages)
        .expect("languages install")
}

/// AC1: a script calls `test.ping()`, registered only from `aitm-proto-test`.
#[test]
fn script_calls_test_ping_through_the_seam() {
    let lang = TestLanguage::new();
    let engine = engine_for(&[&lang]);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);
    let out: String = engine.eval("test.ping()").expect("ping evaluates");
    assert_eq!(out, "pong");
}

/// AC2a (admit): `test.effect()` runs and returns its value when the guard
/// permits.
#[test]
fn effect_runs_when_guard_admits() {
    let lang = TestLanguage::with_effect_allowed(true);
    let engine = engine_for(&[&lang]);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);
    let out: String = engine.eval("test.effect()").expect("effect evaluates");
    assert_eq!(out, "effected");
}

/// AC2a (refuse): `test.effect()` is a script error when the guard refuses — the
/// effect never runs.
#[test]
fn effect_refused_when_guard_refuses() {
    let lang = TestLanguage::with_effect_allowed(false);
    let engine = engine_for(&[&lang]);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);
    let err = engine
        .eval::<String>("test.effect()")
        .expect_err("effect refused");
    assert!(
        err.to_string().contains("guard refused"),
        "unexpected error: {err}"
    );
}

/// Review Focus: two languages owning namespace `test` collide on the first
/// shared fn — a hard error, never last-wins.
#[test]
fn registering_a_namespace_twice_collides() {
    let a = TestLanguage::new();
    let b = TestLanguage::new();
    let err =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), &[&a, &b])
            .expect_err("collision");
    assert_eq!(
        err,
        RegisterError::Collision {
            namespace: "test".to_string(),
            name: "ping".to_string(),
        }
    );
}

/// Review Focus: the same fn name in two different namespaces stays namespaced —
/// dispatch is by the receiver's namespace, not the bare method name.
#[test]
fn same_fn_name_in_two_namespaces_stays_namespaced() {
    let t = TestLanguage::new();
    let o = OtherLanguage;
    let engine = engine_for(&[&t, &o]);
    let _seed = seed_call_context(CallerTrust::Operator, None, None);
    let from_test: String = engine.eval("test.ping()").expect("test.ping");
    let from_other: i64 = engine.eval("other.ping()").expect("other.ping");
    assert_eq!(from_test, "pong");
    assert_eq!(from_other, 42);
}

// ===========================================================================
// Task 2 — per-eval caller context threads through `dispatch`, fail-closed when
// unseeded (spec AC1 / AC3; plan Review Focus "nested seam call keeps the tag").
// ===========================================================================

/// AC1: a seam host fn reads `ctx.caller()`; on **one** engine, two evals seeded
/// with different trust each observe their own — the context is per-invocation,
/// not per-engine or build-time.
#[test]
fn seam_fn_reads_seeded_caller_trust_per_eval() {
    let probe = ProbeLanguage;
    let engine = engine_for(&[&probe]);

    let as_agent: String = {
        let _seed = seed_call_context(CallerTrust::Agent, None, None);
        engine
            .eval("probe.trust()")
            .expect("probe.trust under an agent seed")
    };
    assert_eq!(as_agent, "agent");

    let as_operator: String = {
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        engine
            .eval("probe.trust()")
            .expect("probe.trust under an operator seed")
    };
    assert_eq!(as_operator, "operator");
}

/// AC3 (fail-closed, its own verification): an eval that reaches a seam host fn
/// with **no** seeded caller context is refused with a clear "no caller context"
/// error, and the effect never runs.
#[test]
fn seam_fn_fails_closed_without_seeded_context() {
    let probe = ProbeLanguage;
    let engine = engine_for(&[&probe]);

    // No `seed_call_context`: the eval reaches `probe.gated` with no context.
    let err = engine
        .eval::<String>("probe.gated()")
        .expect_err("an unseeded seam call must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("no caller context"),
        "the refusal must name the missing caller context, got: {msg}"
    );
    // The effect never ran: `probe.gated` returns "ran" only once admitted.
    assert!(
        !msg.contains("ran"),
        "fail-closed must refuse before the effect, got: {msg}"
    );
}

/// AC3: the fail-closed path is **not** silently treated as `Operator`. The same
/// `probe.gated` fn is guarded operator-only: seeded `Operator` it runs, seeded
/// `Agent` it is refused by the guard, and **unseeded** it is refused *before*
/// the guard — proving no operator default widens an un-seeded eval.
#[test]
fn unseeded_seam_call_is_not_treated_as_operator() {
    let probe = ProbeLanguage;
    let engine = engine_for(&[&probe]);

    // Seeded operator: the operator-only guard admits; the effect runs.
    let ran: String = {
        let _seed = seed_call_context(CallerTrust::Operator, None, None);
        engine
            .eval("probe.gated()")
            .expect("an operator seed admits the operator-only effect")
    };
    assert_eq!(ran, "ran");

    // Seeded agent: the operator-only guard refuses (its own message).
    {
        let _seed = seed_call_context(CallerTrust::Agent, None, None);
        let err = engine
            .eval::<String>("probe.gated()")
            .expect_err("an agent seed is refused by the operator-only guard");
        assert!(
            err.to_string().contains("operator-only"),
            "the guard refusal must surface, got: {err}"
        );
    }

    // Unseeded: refused before the guard — not run as an operator would be.
    let err = engine
        .eval::<String>("probe.gated()")
        .expect_err("an unseeded operator-only call must still be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("no caller context"),
        "an unseeded call must fail closed, never default to Operator, got: {msg}"
    );
}

/// Review Focus: the per-eval seed survives **nested** seam calls — a seam fn
/// reached through nested Rhai function calls still sees the seeded trust and
/// tag set once at the eval boundary.
#[test]
fn nested_seam_calls_keep_the_seeded_context() {
    let probe = ProbeLanguage;
    let engine = engine_for(&[&probe]);

    // One seed for the whole eval; the seam fn sits two frames deep.
    let _seed = seed_call_context(
        CallerTrust::Operator,
        Some(Value::Str("opts".to_string())),
        None,
    );

    let trust: String = engine
        .eval(
            r#"
            fn inner() { probe.trust() }
            fn outer() { inner() }
            outer()
            "#,
        )
        .expect("nested probe.trust evaluates");
    assert_eq!(trust, "operator", "the trust survives the nested calls");

    let tag: String = engine
        .eval(
            r#"
            fn inner() { probe.tag() }
            fn outer() { inner() }
            outer()
            "#,
        )
        .expect("nested probe.tag evaluates");
    assert_eq!(tag, "opts", "the seeded tag survives the nested calls");
}

/// An inline language whose fns read the per-invocation [`HostCallCtx`]:
/// `probe.trust()` returns the caller trust, `probe.tag()` the seeded tag, and
/// `probe.gated()` is guarded operator-only (for the fail-closed proofs).
struct ProbeLanguage;

/// A guard that admits every call (for the context-reading probes).
struct AdmitGuard;

impl GuardHandle for AdmitGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

/// A guard that admits only an [`CallerTrust::Operator`] caller — so an eval that
/// is wrongly treated as an operator would be *admitted*; fail-closed must refuse
/// it before this guard is even consulted.
struct OperatorOnlyGuard;

impl GuardHandle for OperatorOnlyGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }

    fn permit(&self, ctx: &HostCallCtx, fn_name: &str) -> Result<(), HostError> {
        match ctx.caller() {
            CallerTrust::Operator => Ok(()),
            CallerTrust::Agent => Err(HostError::GuardRefused {
                namespace: "probe".to_string(),
                reason: format!("`{fn_name}` is operator-only"),
            }),
        }
    }
}

/// The caller trust as the probe surfaces it to a script.
fn caller_label(ctx: &HostCallCtx) -> String {
    match ctx.caller() {
        CallerTrust::Operator => "operator".to_string(),
        CallerTrust::Agent => "agent".to_string(),
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
        let trust: HostFn =
            Box::new(|ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Str(caller_label(ctx))));
        reg.register("probe", "trust", Guarded::new(Box::new(AdmitGuard), trust))?;

        let tag: HostFn =
            Box::new(|ctx: &HostCallCtx, _args: &[Value]| Ok(ctx.tag().unwrap_or(Value::Null)));
        reg.register("probe", "tag", Guarded::new(Box::new(AdmitGuard), tag))?;

        let gated: HostFn =
            Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Str("ran".to_string())));
        reg.register(
            "probe",
            "gated",
            Guarded::new(Box::new(OperatorOnlyGuard), gated),
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

/// A second inline language with its own namespace and a same-named `ping` fn.
struct OtherLanguage;

/// A guard that admits every call (overriding the deny-by-default).
struct AllowGuard;

impl GuardHandle for AllowGuard {
    fn guard_name(&self) -> &str {
        "other"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

impl ProtocolLanguage for OtherLanguage {
    fn namespace(&self) -> &str {
        "other"
    }

    fn api_version(&self) -> &str {
        "1"
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let ping: HostFn = Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Int(42)));
        reg.register("other", "ping", Guarded::new(Box::new(AllowGuard), ping))
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: "other".to_string(),
            api_version: "1".to_string(),
            host_fns: vec![],
            poc_step: None,
            sources: vec![],
        }
    }
}

/// A client that is never reached: the Task 7 loader tests never send.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// The stub services the loader registers its host surface against.
fn services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// A default non-strict config with no scripts (the entries are loaded one at a
/// time via `load_one`).
fn config() -> RhaiConfig {
    RhaiConfig {
        hook_timeout: Duration::from_secs(5),
        ..RhaiConfig::default()
    }
}

/// A throwaway `.rhai` file outside the repo, named after the test so parallel
/// tests never collide; removed on drop.
struct TempScript(PathBuf);

impl TempScript {
    fn new(name: &str, src: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aitm-host-registry-{}-{name}.rhai",
            std::process::id()
        ));
        fs::write(&path, src).expect("the temp script is written");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Task 7 / AC9: a seam namespace's `api_version` is enforced by the loader's
/// version gate exactly like a built-in capability's `min_api`. The `test`
/// namespace is registered at version `2`; a script declaring an older
/// `const API` is refused the `test` namespace with the existing
/// `CapabilityDenied` error (naming the namespace and the required version),
/// while a script that meets the version loads and can call `test.ping()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seam_namespace_api_version_gates_scripts() {
    let lang = TestLanguage::with_api_version("2");
    let loader = RhaiLoader::new_with_languages(config(), services(), &[&lang])
        .expect("the loader builds with a protocol language");

    // Too-old: the script is refused the seam namespace, never silently run.
    let legacy = TempScript::new(
        "legacy",
        r#"const API = "1"; fn on_request(flow) { test.ping(); }"#,
    );
    let err = match loader.load_one(&ScriptEntry::new(legacy.path())) {
        Ok(_) => panic!("a lower-API script must be denied the seam namespace"),
        Err(err) => err,
    };
    match &err {
        ScriptError::CapabilityDenied {
            namespace,
            min_api,
            declared,
            ..
        } => {
            assert_eq!(namespace, "test");
            assert_eq!(min_api, "2");
            assert_eq!(declared, "1");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains("test"), "names the namespace: {text}");
    assert!(text.contains('2'), "names the required version: {text}");

    // Matching: the script loads and `test.ping()` is callable on the engine.
    let modern = TempScript::new(
        "modern",
        r#"const API = "2"; fn on_request(flow) { test.ping(); }"#,
    );
    loader
        .load_one(&ScriptEntry::new(modern.path()))
        .expect("an API-2 script meets the seam namespace version and loads");
    let _seed = seed_call_context(CallerTrust::Operator, None, None);
    let pong: String = loader
        .engine()
        .eval("test.ping()")
        .expect("test.ping runs on the loader engine");
    assert_eq!(pong, "pong");
}
