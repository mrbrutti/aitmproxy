//! Task 1 seam proof: a `ProtocolLanguage` is implementable from outside the
//! language crates using only the `aitm_plugin` re-exports, and reports a
//! stable namespace, api_version, and catalog.
//!
//! The real consumer is `crates/aitm-proto-test` (a workspace member that
//! compiles). Here we use a tiny **inline** `impl ProtocolLanguage` so
//! `aitm-plugin`'s own test proves the trait is implementable without a
//! dev-dependency cycle (`aitm-proto-test` depends on `aitm-plugin`).

use aitm_plugin::language::{
    GuardHandle, Guarded, HostFn, NamespaceCatalog, ProtocolLanguage, RegisterError,
    ScriptHostRegistry,
};
use aitm_plugin::Value;

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
        let ping: HostFn = Box::new(|_args: &[Value]| Ok(Value::Null));
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
