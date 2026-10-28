//! Task 1 — foundational types: `ScriptError` Display (spec §8 pinned format)
//! and `RhaiLimits::default()`.

use aitm_core::GuardError;
use aitm_plugin_rhai::config::{RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::error::ScriptError;

#[test]
fn oplimit_display_names_script_hook_and_budget() {
    let err = ScriptError::OpLimit {
        script: "slow".into(),
        hook: "on_response".into(),
        operations: 2_000_000,
    };
    let text = err.to_string();
    assert!(text.contains("slow"), "missing script name in: {text}");
    assert!(text.contains("on_response"), "missing hook name in: {text}");
    assert!(text.contains("budget"), "missing 'budget' in: {text}");
}

#[test]
fn denied_display_has_help_line() {
    let err = ScriptError::Denied {
        script: "nosy".into(),
        hook: "on_request".into(),
        capability: "browser.navigate".into(),
        reason: GuardError::PrivateAddressBlocked("127.0.0.1".into()),
    };
    let text = err.to_string();
    assert!(
        text.contains("browser.navigate"),
        "missing capability in: {text}"
    );
    assert!(
        text.lines().any(|l| l.starts_with("  help:")),
        "no line starting with `  help:` in: {text}"
    );
}

#[test]
fn limits_default() {
    let limits = RhaiLimits::default();
    assert_eq!(limits.max_operations, 2_000_000);
    assert_eq!(limits.max_modules, 0);
}

#[test]
fn script_entry_defaults_enabled() {
    let entry = ScriptEntry::new("addons/tagger.rhai");
    assert!(entry.enabled);
    assert!(entry.options.is_empty());
}
