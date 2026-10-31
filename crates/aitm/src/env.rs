//! Environment overrides applied on top of `Config` (spec §D10).
//!
//! Runs after the config file, so `AITM_CA_ALLOW_AGENT_INSTALL` still works
//! as the bridge the `ca.*` refusal text names, and wins over the file. The
//! lookup is injected so tests never touch the process environment.
//!
//! `AITM_AUDIT_LOG` also wins over the file (`mcp.audit_log`), but it fails safe
//! where the `ALLOW_AGENT` family treats "anything else" as false: a value it
//! cannot read leaves the file's setting exactly as it was, so a typo such as
//! `AITM_AUDIT_LOG=ofd` cannot silently turn the audit trail off.

use std::path::{Path, PathBuf};

use aitm_core::{AuditLogSetting, Config};
use aitm_plugin_rhai::{RhaiConfig, ScriptEntry};
use aitm_proto_l4::config::L4Config;

/// Lets an agent frontend (MCP) run `ca.install` / `ca.uninstall`.
pub const CA_ALLOW_AGENT_INSTALL: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

/// Lets a runtime bus/MCP caller widen the deny-by-default L4 scope via
/// `l4.scope.add` (mirrors `AITM_CA_ALLOW_AGENT_INSTALL`).
pub const L4_ALLOW_AGENT_WIDEN: &str = "AITM_L4_ALLOW_AGENT_WIDEN";

/// Lets an agent frontend (MCP) drive `l4.inject` / `l4.send_recv`.
pub const L4_ALLOW_AGENT_INJECT: &str = "AITM_L4_ALLOW_AGENT_INJECT";

/// Lets an agent frontend (MCP) drive `l4.capture.start`.
pub const L4_ALLOW_AGENT_CAPTURE: &str = "AITM_L4_ALLOW_AGENT_CAPTURE";

/// Lets an agent frontend (MCP) drive the `l4.intercept.*` verdict verbs.
pub const L4_ALLOW_AGENT_INTERCEPT: &str = "AITM_L4_ALLOW_AGENT_INTERCEPT";

/// Lets an agent frontend (MCP) widen scope with `scope.add`.
pub const SCOPE_ALLOW_AGENT_WIDEN: &str = "AITM_SCOPE_ALLOW_AGENT_WIDEN";

/// Extra scripts to load, `PATH`-style (`a.rhai:b.rhai`), appended after the
/// file's so they take the chain positions after it.
pub const SCRIPTS: &str = "AITM_SCRIPTS";

/// Fail startup on a script that does not compile, instead of skipping it.
pub const SCRIPTS_STRICT: &str = "AITM_SCRIPTS_STRICT";

/// The durable audit log: `off|false|0|no` turns it off, `on|true|1|yes|default`
/// selects the default file, an absolute path names the file (overrides
/// `mcp.audit_log`).
pub const AUDIT_LOG: &str = "AITM_AUDIT_LOG";

/// Apply the environment to `cfg`. Each `AITM_*_ALLOW_AGENT_*`: `1`, `true`
/// or `yes` (case-insensitive) → `true`; any other value → `false`; unset →
/// `cfg` is left as it was.
///
/// `AITM_AUDIT_LOG` wins over the file's `mcp.audit_log` but does **not** follow
/// that rule: its spellings are in [`AUDIT_LOG`], matched ASCII
/// case-insensitively and not trimmed, and any other value (a typo, a relative
/// path, the empty string) leaves `cfg.mcp.audit_log` exactly as it was and logs
/// one warning, so the variable fails safe (stays on) rather than false.
pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(CA_ALLOW_AGENT_INSTALL) {
        cfg.ca.allow_agent_install = is_truthy(&raw);
    }
    if let Some(raw) = lookup(SCOPE_ALLOW_AGENT_WIDEN) {
        cfg.scope.allow_agent_widen = is_truthy(&raw);
    }
    if let Some(raw) = lookup(AUDIT_LOG) {
        match audit_log_from_env(&raw) {
            Some(setting) => cfg.mcp.audit_log = setting,
            None => tracing::warn!(
                target: "aitm::audit",
                "{AUDIT_LOG}={raw:?} is not off, on, default or an absolute path; \
                 the audit log setting is unchanged"
            ),
        }
    }
}

/// The setting `AITM_AUDIT_LOG=<raw>` asks for, or `None` when `raw` means
/// nothing (the caller then leaves the setting alone). `raw` is not trimmed.
fn audit_log_from_env(raw: &str) -> Option<AuditLogSetting> {
    match raw.to_ascii_lowercase().as_str() {
        "off" | "false" | "0" | "no" => Some(AuditLogSetting::Off),
        "on" | "true" | "1" | "yes" | "default" => Some(AuditLogSetting::Default),
        _ if Path::new(raw).is_absolute() => Some(AuditLogSetting::Path(PathBuf::from(raw))),
        _ => None,
    }
}

/// Apply the environment to the scripting tier's settings. `AITM_SCRIPTS`
/// appends entries in the order written, after whatever the file declared —
/// chain order stays "config entries, then flags" (spec §8).
/// `AITM_SCRIPTS_STRICT` follows the same truthiness rule as the CA bridge.
pub fn apply_rhai(cfg: &mut RhaiConfig, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(SCRIPTS) {
        cfg.scripts.extend(
            raw.split(':')
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(ScriptEntry::new),
        );
    }
    if let Some(raw) = lookup(SCRIPTS_STRICT) {
        cfg.strict = is_truthy(&raw);
    }
}

/// Apply the environment to the L4 module config, which rides alongside `Config`
/// (it lives outside `aitm-core`, AC19). `AITM_L4_ALLOW_AGENT_WIDEN` follows the
/// same truthiness rule as `AITM_CA_ALLOW_AGENT_INSTALL`; unset ⇒ `l4` is left
/// as the config file / default left it.
pub fn apply_l4(l4: &mut L4Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(L4_ALLOW_AGENT_WIDEN) {
        l4.allow_agent_widen = is_truthy(&raw);
    }
    if let Some(raw) = lookup(L4_ALLOW_AGENT_INJECT) {
        l4.allow_agent_inject = is_truthy(&raw);
    }
    if let Some(raw) = lookup(L4_ALLOW_AGENT_CAPTURE) {
        l4.allow_agent_capture = is_truthy(&raw);
    }
    if let Some(raw) = lookup(L4_ALLOW_AGENT_INTERCEPT) {
        l4.allow_agent_intercept = is_truthy(&raw);
    }
}

fn is_truthy(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AITM_L4_ALLOW_AGENT_WIDEN` flips `l4.allow_agent_widen` on a truthy value,
    /// forces it false on anything else, and leaves it untouched when unset — the
    /// same contract as `AITM_CA_ALLOW_AGENT_INSTALL`.
    #[test]
    fn l4_allow_agent_widen_env_override() {
        // Unset ⇒ left as the file/default left it (false by default).
        let mut l4 = L4Config::default();
        apply_l4(&mut l4, |_| None);
        assert!(!l4.allow_agent_widen);

        // Truthy ⇒ true.
        apply_l4(&mut l4, |k| {
            (k == L4_ALLOW_AGENT_WIDEN).then(|| "true".to_string())
        });
        assert!(l4.allow_agent_widen);

        // Any other value ⇒ false, even starting from true.
        apply_l4(&mut l4, |k| {
            (k == L4_ALLOW_AGENT_WIDEN).then(|| "off".to_string())
        });
        assert!(!l4.allow_agent_widen);
    }

    fn with(env: &[(&str, &str)]) -> Config {
        let mut cfg = Config::default();
        let map: std::collections::HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        apply(&mut cfg, |k| map.get(k).cloned());
        cfg
    }

    #[test]
    fn scope_widen_env_bridges_and_wins() {
        // Unset leaves the default (off).
        assert!(!with(&[]).scope.allow_agent_widen);
        // Truthy values turn it on; anything else turns it off.
        assert!(
            with(&[(SCOPE_ALLOW_AGENT_WIDEN, "true")])
                .scope
                .allow_agent_widen
        );
        assert!(
            with(&[(SCOPE_ALLOW_AGENT_WIDEN, "1")])
                .scope
                .allow_agent_widen
        );
        assert!(
            !with(&[(SCOPE_ALLOW_AGENT_WIDEN, "nope")])
                .scope
                .allow_agent_widen
        );
    }

    #[test]
    fn ca_install_env_still_bridges() {
        assert!(
            with(&[(CA_ALLOW_AGENT_INSTALL, "yes")])
                .ca
                .allow_agent_install
        );
        assert!(!with(&[]).ca.allow_agent_install);
    }
}
