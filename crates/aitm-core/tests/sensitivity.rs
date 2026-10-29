//! M4 Task 1 (AC-M4-3, AC-M4-8b): the `Sensitivity` classifier, the derived
//! `mutates()`, and the `summarize()` default on the `Command` trait.
//!
//! These exercise the trait defaults directly. The exact per-command tiers of
//! the fully wired registry are asserted in `crates/aitm/tests/m4_sensitivity.rs`,
//! which can reach every plugin crate.

use aitm_core::{Command, CommandHost, ParamSchema, Params, Sensitivity, TypeDesc, Value};

fn schema() -> ParamSchema {
    ParamSchema {
        description: "stub".into(),
        params: vec![],
        result: TypeDesc::Str,
    }
}

/// A command that overrides nothing: it must fall through to the fail-closed
/// `Sensitive` default — the property that makes an unclassified command safe.
struct UndeclaredCmd;
impl Command for UndeclaredCmd {
    fn name(&self) -> &str {
        "demo.undeclared"
    }
    fn schema(&self) -> ParamSchema {
        schema()
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ok".into()))
    }
}

/// A command that declares an explicit tier.
struct TierCmd(Sensitivity);
impl Command for TierCmd {
    fn name(&self) -> &str {
        "demo.tier"
    }
    fn schema(&self) -> ParamSchema {
        schema()
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ok".into()))
    }
    fn sensitivity(&self) -> Sensitivity {
        self.0
    }
}

#[test]
fn undeclared_stub_is_sensitive() {
    // Fail-closed default: a command that does not declare a tier is `Sensitive`.
    assert_eq!(UndeclaredCmd.sensitivity(), Sensitivity::Sensitive);
}

#[test]
fn mutates_is_derived() {
    // `mutates()` is false for exactly the `Read` tier.
    assert!(!TierCmd(Sensitivity::Read).mutates());
    assert!(TierCmd(Sensitivity::Write).mutates());
    assert!(TierCmd(Sensitivity::Sensitive).mutates());
    // The fail-closed default mutates too.
    assert!(UndeclaredCmd.mutates());
}

#[test]
fn summarize_defaults_none() {
    let args = Params::default();
    let result = Value::Str("ignored".into());
    assert_eq!(UndeclaredCmd.summarize(&args, &result), None);
}
