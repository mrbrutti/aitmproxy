//! Environment overrides applied on top of `Config` (spec §D10).
//!
//! Runs after the config file, so `AITM_CA_ALLOW_AGENT_INSTALL` still works
//! as the bridge the `ca.*` refusal text names, and wins over the file. The
//! lookup is injected so tests never touch the process environment.

use aitm_core::Config;
use aitm_proto_l4::config::L4Config;

/// Lets an agent frontend (MCP) run `ca.install` / `ca.uninstall`.
pub const CA_ALLOW_AGENT_INSTALL: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

/// Lets a runtime bus/MCP caller widen the deny-by-default L4 scope via
/// `l4.scope.add` (mirrors `AITM_CA_ALLOW_AGENT_INSTALL`).
pub const L4_ALLOW_AGENT_WIDEN: &str = "AITM_L4_ALLOW_AGENT_WIDEN";

/// Apply the environment to `cfg`. `AITM_CA_ALLOW_AGENT_INSTALL`: `1`, `true`
/// or `yes` (case-insensitive) → `true`; any other value → `false`; unset →
/// `cfg` is left as it was.
pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(CA_ALLOW_AGENT_INSTALL) {
        cfg.ca.allow_agent_install = is_truthy(&raw);
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
}
