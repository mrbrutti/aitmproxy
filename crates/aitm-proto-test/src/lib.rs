//! `aitm-proto-test` — the minimal consumer that proves the
//! [`ProtocolLanguage`] seam from **outside** the language crates, with no
//! edit to `aitm-plugin-rhai` or `aitm-poc`. It is the seam's test consumer,
//! not a real protocol: `test.ping()` is an effect-free liveness probe and
//! `test.effect()` is a stand-in for a guard-checked effect whose guard the
//! test configures to allow or refuse.
//!
//! - Task 2 drives `test.ping()` / `test.effect()` through the rhai engine so a
//!   script can call them, and uses [`TestLanguage::with_effect_allowed`] to
//!   prove a guard refusal stops the effect.
//! - Task 3 adds a `test:` PoC step.
//! - Task 4 asserts the catalog is assembled into the shared defs.

use aitm_plugin::language::{
    GuardHandle, Guarded, HostError, HostFn, HostFnSig, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin::Value;

/// The namespace this crate contributes.
pub const NAMESPACE: &str = "test";

/// The test namespace's API version.
pub const API_VERSION: &str = "0.1.0";

/// What `test.ping()` returns — a fixed liveness token.
pub const PING_REPLY: &str = "pong";

/// What `test.effect()` returns once its guard admits the call.
pub const EFFECT_REPLY: &str = "effected";

/// The test protocol's language contribution.
///
/// `effect_allowed` configures the guard behind `test.effect()` so a test can
/// exercise both the admit and the refuse path of the seam's guard check
/// (`test.ping()`'s guard always admits — it has no effect to gate).
pub struct TestLanguage {
    effect_allowed: bool,
}

impl TestLanguage {
    /// A language whose `test.effect()` guard admits the call.
    pub fn new() -> Self {
        Self {
            effect_allowed: true,
        }
    }

    /// A language whose `test.effect()` guard admits the call only when
    /// `allowed` is true; otherwise it refuses, so the effect never runs.
    pub fn with_effect_allowed(allowed: bool) -> Self {
        Self {
            effect_allowed: allowed,
        }
    }
}

impl Default for TestLanguage {
    fn default() -> Self {
        Self::new()
    }
}

/// A configurable stub guard. Real protocols name their own guard (HTTP's
/// `ScopeRateGuard`, L4's `L4Guard`); the test namespace supplies this so the
/// seam's deny-by-default guard check can be exercised both ways. It overrides
/// [`GuardHandle::permit`] because the trait default denies everything.
struct StubGuard {
    allow: bool,
}

impl GuardHandle for StubGuard {
    fn guard_name(&self) -> &str {
        NAMESPACE
    }

    fn permit(&self, fn_name: &str) -> Result<(), HostError> {
        if self.allow {
            Ok(())
        } else {
            Err(HostError::GuardRefused {
                namespace: NAMESPACE.to_string(),
                reason: format!("test stub guard refused `{fn_name}`"),
            })
        }
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
        // `test.ping()` — a liveness probe. Its guard always admits: there is
        // no effect to gate, but the seam still requires a `Guarded` wrapper.
        let ping: HostFn = Box::new(|_args: &[Value]| Ok(Value::Str(PING_REPLY.to_string())));
        reg.register(
            NAMESPACE,
            "ping",
            Guarded::new(Box::new(StubGuard { allow: true }), ping),
        )?;

        // `test.effect()` — a stand-in for a guard-checked effect. The guard
        // admits or refuses per `effect_allowed`; on a refusal the engine never
        // calls this fn.
        let effect: HostFn = Box::new(|_args: &[Value]| Ok(Value::Str(EFFECT_REPLY.to_string())));
        reg.register(
            NAMESPACE,
            "effect",
            Guarded::new(
                Box::new(StubGuard {
                    allow: self.effect_allowed,
                }),
                effect,
            ),
        )
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        // Task 3 returns a `test:` step handler here.
        None
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: NAMESPACE.to_string(),
            api_version: API_VERSION.to_string(),
            host_fns: vec![
                HostFnSig {
                    name: "ping".to_string(),
                    params: vec![],
                    returns: "string".to_string(),
                    description: "A no-op liveness probe used by the seam tests.".to_string(),
                },
                HostFnSig {
                    name: "effect".to_string(),
                    params: vec![],
                    returns: "string".to_string(),
                    description: "A guard-checked stand-in effect used by the seam tests."
                        .to_string(),
                },
            ],
            poc_step: None,
            sources: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry that records registrations so the test can assert the real
    /// `TestLanguage` body actually registers `test.ping` / `test.effect` (not a
    /// no-op).
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
        assert_eq!(TestLanguage::new().namespace(), "test");
        assert_eq!(TestLanguage::new().api_version(), "0.1.0");
    }

    #[test]
    fn catalog_describes_ping_and_effect() {
        let cat = TestLanguage::new().catalog();
        assert_eq!(cat.namespace, "test");
        assert_eq!(cat.api_version, "0.1.0");
        assert_eq!(cat.host_fns.len(), 2);
        assert_eq!(cat.host_fns[0].name, "ping");
        assert_eq!(cat.host_fns[1].name, "effect");
    }

    #[test]
    fn registers_ping_and_effect() {
        let mut reg = CollectingRegistry::default();
        TestLanguage::new()
            .register_host_fns(&mut reg)
            .expect("registration succeeds");
        assert_eq!(
            reg.registered,
            vec![
                ("test".to_string(), "ping".to_string()),
                ("test".to_string(), "effect".to_string()),
            ]
        );
    }

    #[test]
    fn no_poc_step_yet() {
        assert!(TestLanguage::new().poc_step().is_none());
    }
}
