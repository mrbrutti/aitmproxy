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

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard, Value};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::engine::build_engine_with_languages;
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
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
    let pong: String = loader
        .engine()
        .eval("test.ping()")
        .expect("test.ping runs on the loader engine");
    assert_eq!(pong, "pong");
}
