//! Configuration: `RhaiConfig` (the `scripts:` list + `rhai:` section),
//! `ScriptEntry`, the sandbox `RhaiLimits`, and per-script `ScriptMeta`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use aitm_core::Value;

/// The whole scripting-tier configuration: which scripts to load and how the
/// shared engine is sandboxed.
#[derive(Debug, Clone, PartialEq)]
pub struct RhaiConfig {
    /// Scripts in declaration order (config entries, then `--script` flags);
    /// this order is their chain order (spec §8).
    pub scripts: Vec<ScriptEntry>,
    pub limits: RhaiLimits,
    /// Wall-clock budget per hook invocation.
    pub hook_timeout: Duration,
    pub hot_reload: bool,
    /// Fail fast on a compile error instead of skip-and-log.
    pub strict: bool,
}

/// One declared script and the options handed to it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptEntry {
    pub path: PathBuf,
    pub options: BTreeMap<String, Value>,
    pub enabled: bool,
}

impl ScriptEntry {
    /// An enabled entry with no options — the default an operator gets from a
    /// bare `- path: x.rhai` line.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            options: BTreeMap::new(),
            enabled: true,
        }
    }
}

/// Sandbox limits applied once to the shared engine (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiLimits {
    pub max_operations: u64,
    pub max_call_levels: usize,
    pub max_expr_depth: usize,
    pub max_function_expr_depth: usize,
    pub max_string_size: usize,
    pub max_array_size: usize,
    pub max_map_size: usize,
    /// `0` forbids `import` entirely.
    pub max_modules: usize,
}

impl Default for RhaiLimits {
    fn default() -> Self {
        Self {
            max_operations: 2_000_000,
            max_call_levels: 64,
            max_expr_depth: 128,
            max_function_expr_depth: 64,
            max_string_size: 65_536,
            max_array_size: 16_384,
            max_map_size: 16_384,
            max_modules: 0,
        }
    }
}

/// Declared metadata read from a compiled script (`NAME`, `API`, hooks present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptMeta {
    pub name: String,
    pub api: String,
    pub path: PathBuf,
    pub hooks: Vec<String>,
}
