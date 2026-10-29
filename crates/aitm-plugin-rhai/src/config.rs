//! Configuration: `RhaiConfig` (the `scripts:` list + `rhai:` section),
//! `ScriptEntry`, the sandbox `RhaiLimits`, and per-script `ScriptMeta`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use aitm_core::{SsrfPolicy, Value};

/// The whole scripting-tier configuration: which scripts to load and how the
/// shared engine is sandboxed.
#[derive(Debug, Clone)]
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
    /// Let plugin scripts call `scope.add(...)`. Off by default: widening the
    /// engagement scope lifts the SSRF block for the host named, so it is the
    /// operator's decision, not a script's. PoC steps never get it.
    pub allow_scope_add: bool,
    /// The SSRF posture `browser.navigate` checks a target against — the
    /// host's own policy (`browser.ssrf` in the main config), so a script's
    /// navigation and the `browser.navigate` command decide alike.
    pub ssrf: SsrfPolicy,
}

impl Default for RhaiConfig {
    /// No scripts, the shipped sandbox limits, a two-second hook budget,
    /// skip-and-log compile errors, no scope widening, and the deny-by-default
    /// SSRF policy — the posture an operator gets by writing nothing (spec §2
    /// rule 5, §7, §8).
    fn default() -> Self {
        Self {
            scripts: Vec::new(),
            limits: RhaiLimits::default(),
            hook_timeout: DEFAULT_HOOK_TIMEOUT,
            hot_reload: false,
            strict: false,
            allow_scope_add: false,
            ssrf: SsrfPolicy::default(),
        }
    }
}

/// The wall-clock budget one hook gets before it is aborted; the figure the
/// spec's pinned timeout message quotes.
pub const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_secs(2);

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
///
/// Rhai checks every value a script builds *and every value a host function
/// returns* against the size limits, and blob bytes count against
/// `max_array_size`. `max_string_size` and `max_array_size` therefore default
/// to the body cap the flow snapshot copies ([`SNAPSHOT_CAP`], the proxy's
/// default `limits.max_body_bytes`): a body the proxy buffered, a screenshot,
/// or a DOM is something a script can read whole. Set them at least as high
/// as the configured `max_body_bytes`, or scripts see large bodies fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiLimits {
    pub max_operations: u64,
    pub max_call_levels: usize,
    pub max_expr_depth: usize,
    pub max_function_expr_depth: usize,
    /// Longest string a script may hold or a host verb may return.
    pub max_string_size: usize,
    /// Most elements in an array — or bytes in a blob.
    pub max_array_size: usize,
    pub max_map_size: usize,
    /// `0` forbids `import` entirely.
    pub max_modules: usize,
}

/// The body cap the snapshot copies by default: `LimitConfig::default()
/// .max_body_bytes`, restated here so the two defaults cannot drift apart
/// unnoticed (`tests/types.rs::limits_default` pins the equality).
pub const SNAPSHOT_CAP: usize = 10 * 1024 * 1024;

/// The default operation budget. Nothing in Rhai bounds how deeply a value may
/// nest, and its recursive clone/size-check/drop overflow the worker stack a
/// few levels before a Rust abort kills the whole process. A script builds
/// nesting at ~4 operations per level (`let a=[]; for .. { a=[a]; }`), so this
/// budget caps the *reachable* nesting depth at `MAX_OPERATIONS / 4` ≈ 16 000 —
/// well under the ~45 000 levels that overflow the [`WORKER_STACK_SIZE`] (64
/// MiB) thread scripts run on. Raising it means sizing that stack to match
/// (`WORKER_STACK_SIZE`). See `aitm_plugin_rhai::engine::WORKER_STACK_SIZE`.
pub const MAX_OPERATIONS: u64 = 64_000;

impl Default for RhaiLimits {
    fn default() -> Self {
        Self {
            max_operations: MAX_OPERATIONS,
            max_call_levels: 64,
            max_expr_depth: 128,
            max_function_expr_depth: 64,
            max_string_size: SNAPSHOT_CAP,
            max_array_size: SNAPSHOT_CAP,
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
