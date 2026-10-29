//! Task 2 — the `ScriptHostRegistry` seam in the rhai engine.
//!
//! A protocol crate injects its `<ns>.*` host fns from its own crate; the engine
//! drives each registered `ProtocolLanguage::register_host_fns` and a script
//! calls `test.ping()` with **no edit to `aitm-plugin-rhai`** (AC1). Each fn is
//! `Guarded`, so a refusing guard stops the effect (AC2a); registering a
//! namespace twice is a hard collision, never last-wins (Review Focus). The
//! compile-time half of AC2 (an unguarded effectful fn fails to type-check) is a
//! `compile_fail` doctest on `aitm_plugin_rhai::host_registry`.

use std::time::Duration;

use aitm_core::Value;
use aitm_plugin::language::{
    GuardHandle, Guarded, HostError, HostFn, NamespaceCatalog, PocStepHandler, ProtocolLanguage,
    RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine_with_languages;
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
    let out: String = engine.eval("test.ping()").expect("ping evaluates");
    assert_eq!(out, "pong");
}

/// AC2a (admit): `test.effect()` runs and returns its value when the guard
/// permits.
#[test]
fn effect_runs_when_guard_admits() {
    let lang = TestLanguage::with_effect_allowed(true);
    let engine = engine_for(&[&lang]);
    let out: String = engine.eval("test.effect()").expect("effect evaluates");
    assert_eq!(out, "effected");
}

/// AC2a (refuse): `test.effect()` is a script error when the guard refuses — the
/// effect never runs.
#[test]
fn effect_refused_when_guard_refuses() {
    let lang = TestLanguage::with_effect_allowed(false);
    let engine = engine_for(&[&lang]);
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
    let from_test: String = engine.eval("test.ping()").expect("test.ping");
    let from_other: i64 = engine.eval("other.ping()").expect("other.ping");
    assert_eq!(from_test, "pong");
    assert_eq!(from_other, 42);
}

/// A second inline language with its own namespace and a same-named `ping` fn.
struct OtherLanguage;

/// A guard that admits every call (overriding the deny-by-default).
struct AllowGuard;

impl GuardHandle for AllowGuard {
    fn guard_name(&self) -> &str {
        "other"
    }

    fn permit(&self, _fn_name: &str) -> Result<(), HostError> {
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
        let ping: HostFn = Box::new(|_args: &[Value]| Ok(Value::Int(42)));
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
