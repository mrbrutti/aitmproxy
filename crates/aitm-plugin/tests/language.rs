//! Task 1 seam proof: a `ProtocolLanguage` is implementable from outside the
//! language crates using only the `aitm_plugin` re-exports, and reports a
//! stable namespace, api_version, and catalog.
//!
//! The real consumer is `crates/aitm-proto-test` (a workspace member that
//! compiles). Here we use a tiny **inline** `impl ProtocolLanguage` so
//! `aitm-plugin`'s own test proves the trait is implementable without a
//! dev-dependency cycle (`aitm-proto-test` depends on `aitm-plugin`).

use std::sync::{Arc, Mutex};

use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallContextSource, HostCallCtx, HostError, HostFn, NamespaceCatalog,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin::{CallerTrust, Value};

/// A guard handle that admits everything — the inline test needs *some* guard
/// to build a `Guarded`, which is the point: there is no unguarded path.
struct AllowGuard;

impl GuardHandle for AllowGuard {
    fn guard_name(&self) -> &str {
        "test"
    }
}

/// An inline protocol contribution, mirroring `aitm-proto-test`'s `TestLanguage`.
struct Inline;

impl ProtocolLanguage for Inline {
    fn namespace(&self) -> &str {
        "test"
    }

    fn api_version(&self) -> &str {
        "0.1.0"
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let ping: HostFn = Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Null));
        reg.register("test", "ping", Guarded::new(Box::new(AllowGuard), ping))
    }

    fn poc_step(&self) -> Option<Box<dyn aitm_plugin::language::PocStepHandler>> {
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: "test".to_string(),
            api_version: "0.1.0".to_string(),
            host_fns: vec![aitm_plugin::language::HostFnSig {
                name: "ping".to_string(),
                params: vec![],
                returns: "null".to_string(),
                description: "A no-op liveness probe.".to_string(),
            }],
            poc_step: None,
            sources: vec![],
        }
    }
}

/// A registry that records what a language asks it to register, so the test can
/// assert the registration actually happened (not a no-op body).
#[derive(Default)]
struct CollectingRegistry {
    registered: Vec<(String, String)>,
}

impl ScriptHostRegistry for CollectingRegistry {
    fn register(&mut self, ns: &str, name: &str, _f: Guarded<HostFn>) -> Result<(), RegisterError> {
        if self.registered.iter().any(|(n, m)| n == ns && m == name) {
            return Err(RegisterError::Collision {
                namespace: ns.to_string(),
                name: name.to_string(),
            });
        }
        self.registered.push((ns.to_string(), name.to_string()));
        Ok(())
    }
}

#[test]
fn test_language_reports_namespace_and_version() {
    let lang = Inline;
    assert_eq!(lang.namespace(), "test");
    assert_eq!(lang.api_version(), "0.1.0");
}

#[test]
fn test_language_catalog_names_the_namespace() {
    let lang = Inline;
    let cat = lang.catalog();
    assert_eq!(cat.namespace, "test");
    assert_eq!(cat.api_version, "0.1.0");
    assert_eq!(cat.host_fns.len(), 1);
    assert_eq!(cat.host_fns[0].name, "ping");
}

#[test]
fn test_language_registers_its_host_fns() {
    let lang = Inline;
    let mut reg = CollectingRegistry::default();
    lang.register_host_fns(&mut reg)
        .expect("registration succeeds");
    assert_eq!(
        reg.registered,
        vec![("test".to_string(), "ping".to_string())]
    );
}

#[test]
fn test_language_has_no_poc_step_yet() {
    let lang = Inline;
    assert!(lang.poc_step().is_none());
}

/// A stub per-call source: carries a fixed tag/source so the ctx accessors can
/// be exercised without a rhai `NativeCallContext` (that concrete source lands
/// in Task 2).
struct StubSource;

impl HostCallContextSource for StubSource {
    fn tag(&self) -> Option<Value> {
        None
    }

    fn call_source(&self) -> &str {
        "test-source"
    }
}

/// A guard that records the caller trust `permit` was invoked with, proving the
/// per-invocation ctx reaches the guard and it can read `ctx.caller()`.
struct CallerRecordingGuard {
    seen: Arc<Mutex<Option<CallerTrust>>>,
}

impl GuardHandle for CallerRecordingGuard {
    fn guard_name(&self) -> &str {
        "rec"
    }

    fn permit(&self, ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        *self.seen.lock().expect("lock") = Some(ctx.caller());
        Ok(())
    }
}

/// The host fn and the guard both observe the per-invocation `HostCallCtx`: the
/// fn reads `ctx.caller()` to shape its result, and the guard's `permit` sees the
/// same caller through the ctx. This fails if `HostFn`/`permit` are not threaded
/// with a `HostCallCtx`.
#[test]
fn host_fn_and_guard_observe_caller_trust() {
    // A host fn whose output reflects the caller trust it was handed.
    let f: HostFn = Box::new(|ctx: &HostCallCtx, _args: &[Value]| {
        Ok(Value::Str(match ctx.caller() {
            CallerTrust::Agent => "agent".to_string(),
            CallerTrust::Operator => "operator".to_string(),
        }))
    });
    let seen = Arc::new(Mutex::new(None));
    let guard = CallerRecordingGuard { seen: seen.clone() };

    // `register` accepts only a `Guarded<HostFn>` — the guarded-by-construction
    // property. Simulate the engine's dispatch: permit, then call, both with the
    // ctx.
    let guarded = Guarded::new(Box::new(guard), f);
    let (g, func) = guarded.into_parts();

    let source = StubSource;
    let ctx = HostCallCtx::new(CallerTrust::Operator, &source);
    g.permit(&ctx, "ping").expect("recording guard admits");
    let out = func(&ctx, &[]).expect("host fn runs");

    assert_eq!(out, Value::Str("operator".to_string()));
    assert_eq!(*seen.lock().expect("lock"), Some(CallerTrust::Operator));
    assert_eq!(ctx.call_source(), "test-source");
    assert_eq!(ctx.tag(), None);
}

/// A guard that admits every call, overriding the deny-by-default `permit`, so
/// the backward-compat test can exercise the full permit-then-call path.
struct AdmitGuard;

impl GuardHandle for AdmitGuard {
    fn guard_name(&self) -> &str {
        "admit"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

/// AC10 (backward-compat): a host fn that ignores the per-invocation context is
/// still a single one-line closure — the `&HostCallCtx` parameter is purely
/// additive. The entire fn body here is `|_ctx, _args| Ok(Value::Null)`: it
/// names neither parameter and reads nothing from the ctx. We register it
/// through the seam's `register` (proving a context-ignoring one-liner still
/// satisfies `Guarded<HostFn>`) and run it through the full permit-then-call
/// path for both caller trusts, asserting it returns exactly `Value::Null`
/// either way. If the context stopped being additive (e.g. the signature forced
/// reading the ctx, or the closure's return were anything else), this test would
/// fail — it is not a tautology that survives deleting the closure body.
#[test]
fn context_ignoring_host_fn_is_still_a_one_line_closure() {
    // The whole function body — the backward-compat promise is this stays a
    // single context-ignoring line.
    let f: HostFn = Box::new(|_ctx, _args| Ok(Value::Null));

    // It still satisfies `register`'s `Guarded<HostFn>`-only contract (AC9) and
    // registers through a `ScriptHostRegistry` with no extra ceremony.
    let mut reg = CollectingRegistry::default();
    let reg_fn: HostFn = Box::new(|_ctx, _args| Ok(Value::Null));
    reg.register("test", "noop", Guarded::new(Box::new(AdmitGuard), reg_fn))
        .expect("context-ignoring one-liner registers through the seam");
    assert_eq!(
        reg.registered,
        vec![("test".to_string(), "noop".to_string())]
    );

    // And runs through the real permit-then-call path, identically for either
    // caller trust, because it reads nothing from the ctx.
    let guarded = Guarded::new(Box::new(AdmitGuard), f);
    let (g, func) = guarded.into_parts();
    let source = StubSource;
    for caller in [CallerTrust::Operator, CallerTrust::Agent] {
        let ctx = HostCallCtx::new(caller, &source);
        g.permit(&ctx, "noop").expect("admit guard permits");
        let out = func(&ctx, &[]).expect("context-ignoring host fn runs");
        assert_eq!(out, Value::Null);
    }
}

/// `CallerTrust::from(Frontend)` maps an agent iff `Frontend::Mcp`; the human
/// CLI and an operator-token connection are both `Operator`.
#[test]
fn caller_trust_from_frontend_agent_iff_mcp() {
    use aitm_plugin::Frontend;
    assert_eq!(CallerTrust::from(Frontend::Mcp), CallerTrust::Agent);
    assert_eq!(CallerTrust::from(Frontend::Cli), CallerTrust::Operator);
    assert_eq!(CallerTrust::from(Frontend::Operator), CallerTrust::Operator);
}

/// AC8: the seam stays rhai-free — `aitm-plugin`'s manifest declares no `rhai`
/// dependency. Reads this crate's own `Cargo.toml`.
#[test]
fn aitm_plugin_has_no_rhai_dependency() {
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).expect("read");
    for line in manifest.lines() {
        assert!(
            !line.trim_start().starts_with("rhai"),
            "aitm-plugin must not depend on rhai (AC8): found `{line}`"
        );
    }
}
