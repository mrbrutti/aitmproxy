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

pub use ids::*;
pub use vocab::*;

// Tasks 4 to 8 of the T1a plan each own exactly one of the modules below and fill
// it in; until then the module is a doc line only, and a glob re-export of an empty
// module is an `unused_imports` warning (an error under the workspace's `-D
// warnings` gate). The glob list is the crate's final public surface, so the
// warning is silenced here rather than `lib.rs` being edited once per landing
// module. Each attribute becomes a no-op the moment its module exports anything.
#[allow(unused_imports)]
pub use check::*;
#[allow(unused_imports)]
pub use issue::*;
#[allow(unused_imports)]
pub use job::*;
#[allow(unused_imports)]
pub use point::*;
#[allow(unused_imports)]
pub use profile::*;
#[allow(unused_imports)]
pub use results::*;
#[allow(unused_imports)]
pub use session::*;
#[allow(unused_imports)]
pub use traits::*;
