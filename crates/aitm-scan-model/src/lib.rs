//! `aitm-scan-model` — the scanner v2 shared data model.
//!
//! Owned by track T1a (the contract drop) of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, sections D1,
//! D2 and D3). Every other scanner track compiles against this crate: it holds the
//! wire vocabulary, the profile tree and its built-ins, the insertion-point, check,
//! job, issue and session types, the verb result types, and the `Check` / `ProbeHost`
//! / `Lane` / `JobCtx` traits. It is pure data and trait definitions — no I/O, no
//! engine, no check implementations — so a lane crate can depend on it without
//! pulling in the scanner engine.

#![forbid(unsafe_code)]

pub mod check;
pub mod ids;
pub mod issue;
pub mod job;
pub mod point;
pub mod profile;
pub mod results;
pub mod session;
pub mod traits;
pub mod vocab;

pub use check::*;
pub use ids::*;
pub use issue::*;
pub use job::*;
pub use point::*;
pub use profile::*;
pub use results::*;
pub use session::*;
pub use traits::*;
pub use vocab::*;
