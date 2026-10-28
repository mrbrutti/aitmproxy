//! `aitm-plugin-rhai` — the Rhai scripting tier for aitmproxy.
//!
//! One shared, sandboxed Rhai `Engine` is built once; each `.rhai` file compiles
//! to its own `AST` and becomes a first-class [`aitm_core::Plugin`] in the ordered
//! chain. The same engine and host surface back the PoC `script` step.
//!
//! Design: `docs/superpowers/specs/2026-10-27-aitmproxy-m3-rhai-scripting-design.md`.
//! Every module is declared here up front so later tasks never re-touch this file.

pub mod command;
pub mod config;
pub mod engine;
pub mod error;
pub mod flow_api;
pub mod flow_state;
pub mod host_core;
pub mod host_net;
pub mod loader;
pub mod marshal;
pub mod plugin;
pub mod poc_step;
pub mod prelude;
