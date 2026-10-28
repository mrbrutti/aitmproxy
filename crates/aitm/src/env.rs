//! Environment overrides applied on top of `Config` (spec §D10).
//!
//! Runs after the config file, so `AITM_CA_ALLOW_AGENT_INSTALL` still works
//! as the bridge the `ca.*` refusal text names, and wins over the file. The
//! lookup is injected so tests never touch the process environment.

use aitm_core::Config;
use aitm_plugin_rhai::{RhaiConfig, ScriptEntry};

/// Lets an agent frontend (MCP) run `ca.install` / `ca.uninstall`.
pub const CA_ALLOW_AGENT_INSTALL: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

/// Extra scripts to load, `PATH`-style (`a.rhai:b.rhai`), appended after the
/// file's so they take the chain positions after it.
pub const SCRIPTS: &str = "AITM_SCRIPTS";

/// Fail startup on a script that does not compile, instead of skipping it.
pub const SCRIPTS_STRICT: &str = "AITM_SCRIPTS_STRICT";

/// Apply the environment to `cfg`. `AITM_CA_ALLOW_AGENT_INSTALL`: `1`, `true`
/// or `yes` (case-insensitive) → `true`; any other value → `false`; unset →
/// `cfg` is left as it was.
pub fn apply(cfg: &mut Config, lookup: impl Fn(&str) -> Option<String>) {
    if let Some(raw) = lookup(CA_ALLOW_AGENT_INSTALL) {
        cfg.ca.allow_agent_install = is_truthy(&raw);
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

fn is_truthy(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}
