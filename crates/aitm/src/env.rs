//! Environment overrides applied on top of `Config` (spec §D10).
//!
//! Runs after the config file, so `AITM_CA_ALLOW_AGENT_INSTALL` still works
//! as the bridge the `ca.*` refusal text names, and wins over the file. The
//! lookup is injected so tests never touch the process environment.

use aitm_core::Config;

/// Lets an agent frontend (MCP) run `ca.install` / `ca.uninstall`.
pub const CA_ALLOW_AGENT_INSTALL: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

/// Apply the environment to `cfg`. `AITM_CA_ALLOW_AGENT_INSTALL`: `1`, `true`
/// or `yes` (case-insensitive) → `true`; any other value → `false`; unset →
/// `cfg` is left as it was.
pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(CA_ALLOW_AGENT_INSTALL) {
        cfg.ca.allow_agent_install = is_truthy(&raw);
    }
}

fn is_truthy(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}
