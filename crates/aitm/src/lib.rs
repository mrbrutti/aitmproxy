//! `aitm` — the binary's reusable assembly. `wire::assemble` turns a `Config`
//! into a running-ready `Proxy` plus the CA it serves with; `main` drives it.
//! `env` bridges the process environment into `Config`; `render` prints a
//! command's result for the CLI; `web` is the `aitm web` static host and
//! `/bus` WebSocket bridge (F15). Kept as a library so the wiring is testable
//! (AC-P3/AC-P4, CA-AC27) without the process entrypoint.

pub mod config_file;
pub mod env;
pub mod render;
pub mod scripts;
pub mod web;
pub mod wire;
