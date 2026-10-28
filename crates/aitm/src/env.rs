//! Environment overrides applied on top of `Config` (spec §D10).
//!
//! Runs after the config file, so `AITM_CA_ALLOW_AGENT_INSTALL` still works
//! as the bridge the `ca.*` refusal text names, and wins over the file. The
//! lookup is injected so tests never touch the process environment.

use aitm_core::Config;

/// Lets an agent frontend (MCP) run `ca.install` / `ca.uninstall`.
pub const CA_ALLOW_AGENT_INSTALL: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

/// Lets an agent frontend (MCP) widen scope with `scope.add`.
pub const SCOPE_ALLOW_AGENT_WIDEN: &str = "AITM_SCOPE_ALLOW_AGENT_WIDEN";

/// Apply the environment to `cfg`. Each `AITM_*_ALLOW_AGENT_*`: `1`, `true`
/// or `yes` (case-insensitive) → `true`; any other value → `false`; unset →
/// `cfg` is left as it was.
pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(CA_ALLOW_AGENT_INSTALL) {
        cfg.ca.allow_agent_install = is_truthy(&raw);
    }
    if let Some(raw) = lookup(SCOPE_ALLOW_AGENT_WIDEN) {
        cfg.scope.allow_agent_widen = is_truthy(&raw);
    }
}

fn is_truthy(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

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
