//! `aitm-plugin-rhai` — the Rhai scripting tier for aitmproxy.
//!
//! One shared, sandboxed Rhai `Engine` is built once; each `.rhai` file compiles
//! to its own `AST` and becomes a first-class [`aitm_core::Plugin`] in the ordered
//! chain. The same engine and host surface back the PoC `script` step.
//!
//! Design: `docs/superpowers/specs/2026-10-27-aitmproxy-m3-rhai-scripting-design.md`.
//! Every module is declared here up front so later tasks never re-touch this file.

pub mod catalog_assembly;
pub mod check_bridge;
pub mod command;
pub mod commands;
pub mod config;
pub mod dsl;
pub mod engine;
pub mod error;
pub mod flow_api;
pub mod flow_state;
pub mod host_core;
pub mod host_net;
pub mod host_probe;
pub mod host_registry;
pub mod loader;
pub mod marshal;
pub mod plugin;
pub mod poc_step;
pub mod prelude;
pub mod wire;

// The curated surface a host program wires against (plan Task 15). The modules
// stay public for tests and for a capability provider in another crate; these
// are the names a binary needs.
pub use catalog_assembly::{
    assemble_namespaces, assemble_poc_steps, poc_face_drift, production_languages,
    vocabulary_consistent, AssembleError, PocFaceDrift,
};
pub use check_bridge::{meta_from_map, poc_hint_from_map, verdict_from_dynamic, ScriptCheck};
pub use command::{register_reg_api, ScriptCommand, ScriptRegHandle};
pub use commands::ScriptCommands;
pub use config::{RhaiConfig, RhaiLimits, ScriptEntry, ScriptMeta};
pub use dsl::{register_dsl, DslCapability};
pub use engine::{
    build_engine_with_languages, probe_budget, Budget, RunKind, MAX_PROBE_TIMEOUT,
    WORKER_STACK_SIZE,
};
pub use error::ScriptError;
pub use host_core::{
    Finding, FindingSink, MemoryFindingSink, Options, ScriptCapability, ScriptServices,
};
pub use host_net::with_client;
pub use host_probe::{levenshtein_ratio, timing_fit, CheckCtx, ProbeCapability, TimingFit};
pub use host_registry::{registered_host_fns, seed_call_context, CallContextGuard, HostRegistry};
pub use loader::{RhaiLoader, SUPPORTED_API};
pub use plugin::{ErrorSink, LoadedScript, ScriptHandle, ScriptHost, ScriptSet};
pub use poc_step::{RhaiScriptExecutor, ScriptVars, VarsCapability};
pub use prelude::PRELUDE_SRC;
pub use wire::{build, executor, load_scripts, ScriptTier};
