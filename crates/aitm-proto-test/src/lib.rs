//! `aitm-proto-test` — the minimal consumer that proves the
//! [`ProtocolLanguage`] seam from **outside** the language crates, with no
//! edit to `aitm-plugin-rhai` or `aitm-poc`. Later tasks extend it: Task 2
//! wires `test.ping()`'s real call through the rhai engine, Task 3 adds a
//! `test:` PoC step, Task 4 asserts the catalog is assembled into the shared
//! defs.
//!
//! It is deliberately effect-free: `test.ping()` returns `null`.

use aitm_plugin::language::{
    GuardHandle, Guarded, HostFn, HostFnSig, NamespaceCatalog, PocStepHandler, ProtocolLanguage,
    RegisterError, ScriptHostRegistry,
};
use aitm_plugin::Value;

/// The namespace this crate contributes.
pub const NAMESPACE: &str = "test";

/// The test namespace's API version.
pub const API_VERSION: &str = "0.1.0";

/// The test protocol's language contribution.
pub struct TestLanguage;

/// A trivial guard that admits every call. Real protocols name their own guard
/// (HTTP's `ScopeRateGuard`, L4's `L4Guard`); the test namespace has no real
/// effect to gate, so its guard is a no-op — it still exists because the seam
/// has no unguarded registration path.
struct TestGuard;

impl GuardHandle for TestGuard {
    fn guard_name(&self) -> &str {
        NAMESPACE
    }
}

impl ProtocolLanguage for TestLanguage {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn api_version(&self) -> &str {
        API_VERSION
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        // `test.ping()` — a no-op liveness probe. Task 2 drives this through the
        // rhai engine so a script can call `test.ping()`; here it is a plain
        // `Value`-level fn that returns null.
        let ping: HostFn = Box::new(|_args: &[Value]| Ok(Value::Null));
        reg.register(NAMESPACE, "ping", Guarded::new(Box::new(TestGuard), ping))
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        // Task 3 returns a `test:` step handler here.
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: NAMESPACE.to_string(),
            api_version: API_VERSION.to_string(),
            host_fns: vec![HostFnSig {
                name: "ping".to_string(),
                params: vec![],
                returns: "null".to_string(),
                description: "A no-op liveness probe used by the seam tests.".to_string(),
            }],
            poc_step: None,
            sources: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry that records registrations so the test can assert the real
    /// `TestLanguage` body actually registers `test.ping` (not a no-op).
    #[derive(Default)]
    struct CollectingRegistry {
        registered: Vec<(String, String)>,
    }

    impl ScriptHostRegistry for CollectingRegistry {
        fn register(
            &mut self,
            ns: &str,
            name: &str,
            _f: Guarded<HostFn>,
        ) -> Result<(), RegisterError> {
            self.registered.push((ns.to_string(), name.to_string()));
            Ok(())
        }
    }

    #[test]
    fn namespace_is_test() {
        assert_eq!(TestLanguage.namespace(), "test");
        assert_eq!(TestLanguage.api_version(), "0.1.0");
    }

    #[test]
    fn catalog_describes_test_ping() {
        let cat = TestLanguage.catalog();
        assert_eq!(cat.namespace, "test");
        assert_eq!(cat.api_version, "0.1.0");
        assert_eq!(cat.host_fns.len(), 1);
        assert_eq!(cat.host_fns[0].name, "ping");
        assert_eq!(cat.host_fns[0].returns, "null");
    }

    #[test]
    fn registers_test_ping() {
        let mut reg = CollectingRegistry::default();
        TestLanguage
            .register_host_fns(&mut reg)
            .expect("registration succeeds");
        assert_eq!(
            reg.registered,
            vec![("test".to_string(), "ping".to_string())]
        );
    }

    #[test]
    fn no_poc_step_yet() {
        assert!(TestLanguage.poc_step().is_none());
    }
}
