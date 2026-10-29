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

use std::collections::BTreeMap;

use aitm_plugin::language::{
    GuardHandle, Guarded, HostError, HostFn, HostFnSig, NamespaceCatalog, PocStepHandler,
    PocStepInputs, PocStepOutcome, ProtocolLanguage, RegisterError, ScriptHostRegistry,
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

/// The source name the `test:` PoC step contributes: `op: echo` produces an
/// `echo` source (an object with a `value` field) a PoC `extract` reads.
pub const ECHO_SOURCE: &str = "echo";

/// The test protocol's language contribution.
///
/// `effect_allowed` configures the guard behind `test.effect()` so a test can
/// exercise both the admit and the refuse path of the seam's guard check
/// (`test.ping()`'s guard always admits — it has no effect to gate).
pub struct TestLanguage {
    effect_allowed: bool,
    /// The namespace's API version, surfaced through [`ProtocolLanguage::api_version`]
    /// and the catalog. Defaults to [`API_VERSION`]; a test overrides it with
    /// [`TestLanguage::with_api_version`] to exercise the loader's version gate
    /// (Task 7).
    api_version: String,
}

impl TestLanguage {
    /// A language whose `test.effect()` guard admits the call.
    pub fn new() -> Self {
        Self {
            effect_allowed: true,
            api_version: API_VERSION.to_string(),
        }
    }

    /// A language whose `test.effect()` guard admits the call only when
    /// `allowed` is true; otherwise it refuses, so the effect never runs.
    pub fn with_effect_allowed(allowed: bool) -> Self {
        Self {
            effect_allowed: allowed,
            api_version: API_VERSION.to_string(),
        }
    }

    /// A language that declares its `test` namespace at `api_version`, so a test
    /// can drive the loader's per-namespace version gate (Task 7): a script
    /// declaring an older `const API` is refused the namespace, a script meeting
    /// it loads.
    pub fn with_api_version(api_version: impl Into<String>) -> Self {
        Self {
            effect_allowed: true,
            api_version: api_version.into(),
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
        &self.api_version
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
        Some(Box::new(TestStepHandler))
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: NAMESPACE.to_string(),
            api_version: self.api_version.clone(),
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

/// The `test:` PoC step handler. A pure stand-in with one verb:
///
/// ```yaml
/// - test:
///     op: echo
///     value: "{{greeting}}"      # {{placeholder}}s resolve from PocStepInputs
///   extract:
///     - name: pulled
///       type: echo               # the source name
///       field: value             # tcp.flags-style field path into the source
/// ```
///
/// `op: echo` binds `echoed` directly to the (expanded) `value` and produces the
/// `echo` source `{ value: <expanded> }`, so a PoC proves both the direct-binding
/// and named-source-plus-field paths of the seam end to end.
pub struct TestStepHandler;

impl PocStepHandler for TestStepHandler {
    fn ns(&self) -> &str {
        NAMESPACE
    }

    fn sources(&self) -> Vec<String> {
        vec![ECHO_SOURCE.to_string()]
    }

    fn run(
        &self,
        body: &serde_yaml::Value,
        inputs: &PocStepInputs,
    ) -> Result<PocStepOutcome, HostError> {
        let op = body
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HostError::BadArgs("`test:` step missing `op`".to_string()))?;
        match op {
            "echo" => {
                let raw = body.get("value").and_then(|v| v.as_str()).ok_or_else(|| {
                    HostError::BadArgs("`test:` `echo` missing `value`".to_string())
                })?;
                let value = expand(raw, &inputs.vars);

                let mut sources = BTreeMap::new();
                let mut echo = BTreeMap::new();
                echo.insert("value".to_string(), Value::Str(value.clone()));
                sources.insert(ECHO_SOURCE.to_string(), Value::Object(echo));

                let mut bindings = BTreeMap::new();
                bindings.insert("echoed".to_string(), Value::Str(value));

                Ok(PocStepOutcome { sources, bindings })
            }
            other => Err(HostError::BadArgs(format!(
                "`test:` step: unknown op `{other}`"
            ))),
        }
    }
}

/// Expand a whole-string `{{name}}` placeholder from `vars`; any other input is
/// returned verbatim. Minimal on purpose — it only exists to prove the resolved
/// variables reach the handler through [`PocStepInputs`].
fn expand(input: &str, vars: &BTreeMap<String, Value>) -> String {
    let trimmed = input.trim();
    if let Some(name) = trimmed
        .strip_prefix("{{")
        .and_then(|s| s.strip_suffix("}}"))
    {
        if let Some(Value::Str(s)) = vars.get(name.trim()) {
            return s.clone();
        }
    }
    input.to_string()
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
    fn poc_step_is_the_test_handler() {
        let handler = TestLanguage::new()
            .poc_step()
            .expect("test namespace contributes a `test:` PoC step");
        assert_eq!(handler.ns(), "test");
        assert_eq!(handler.sources(), vec!["echo".to_string()]);
    }

    /// `op: echo` binds `echoed` and produces the `echo` source, expanding a
    /// whole-string `{{placeholder}}` from the step inputs.
    #[test]
    fn echo_step_binds_and_sources() {
        let body: serde_yaml::Value =
            serde_yaml::from_str("op: echo\nvalue: \"{{greeting}}\"").expect("body");
        let mut vars = BTreeMap::new();
        vars.insert("greeting".to_string(), Value::Str("hello".to_string()));

        let outcome = TestStepHandler
            .run(&body, &PocStepInputs { vars })
            .expect("echo runs");
        assert_eq!(
            outcome.bindings.get("echoed"),
            Some(&Value::Str("hello".to_string()))
        );
        let echo = outcome.sources.get("echo").expect("echo source");
        let Value::Object(fields) = echo else {
            panic!("echo source must be an object, got {echo:?}");
        };
        assert_eq!(fields.get("value"), Some(&Value::Str("hello".to_string())));
    }

    /// An unknown op is a clear `BadArgs`, not a panic.
    #[test]
    fn unknown_op_errors() {
        let body: serde_yaml::Value = serde_yaml::from_str("op: nope").expect("body");
        let err = TestStepHandler
            .run(&body, &PocStepInputs::default())
            .expect_err("unknown op errors");
        assert!(matches!(err, HostError::BadArgs(_)));
    }
}
