//! `aitm-scan-ws` — the scanner v2 WebSocket lane and `ws.*` script language.
//!
//! Owned by track **T4** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.3**). The crate has two registration slots: [`lane`], called from
//! `crates/aitm/src/wire.rs`, and [`language`], called from `crates/aitm/src/main.rs`
//! with the guard from its `LateHandles` — the `ws.*` host fns are `Guarded`
//! through the scope guard, never ungated (D8.3, call A17).
//!
//! Track T1a handed over the skeleton; T4 fills it module by module. Both slot
//! bodies delegate to [`lane::build`] and [`language::build`], so flipping a
//! slot is an edit inside the module that owns it and this file is written once
//! (T4 plan call 11).

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_core::guard::ScopeRateGuard;
use aitm_plugin::language::ProtocolLanguage;
use aitm_scan_model::Lane;

pub mod checks;
pub mod dialer;
pub mod discover;
pub mod host;
pub mod lane;
pub mod language;
pub mod mutate;
pub mod payloads;
#[doc(hidden)]
pub mod testing;
pub mod transport;
pub mod types;

/// The WebSocket lane, or `None` while the lane is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and registers the lane
/// it gets back; a `None` lane makes `scan.start` refuse a `ws` lane with
/// `lane_unavailable`. The body delegates to [`lane::build`]; the signature is
/// final.
#[must_use]
pub fn lane() -> Option<Arc<dyn Lane>> {
    lane::build()
}

/// The `ws.*` protocol language, or `None` while the track is unimplemented.
///
/// `crates/aitm/src/main.rs` calls this with the scope/rate guard from its
/// `LateHandles` and registers what it gets back. Every `ws.*` host fn is
/// `Guarded` through `guard`, so a script cannot reach a host outside scope or
/// past the rate limit (D8.3, call A17). The body delegates to
/// [`language::build`]; the signature is final.
#[must_use]
pub fn language(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>> {
    language::build(guard)
}
