//! `aitm-scan-ws` — the scanner v2 WebSocket lane and `ws.*` script language.
//!
//! Owned by track **T4** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.3**). The crate has two registration slots: [`lane`], called from
//! `crates/aitm/src/wire.rs`, and [`language`], called from `crates/aitm/src/main.rs`
//! with the guard from its `LateHandles` — the `ws.*` host fns are `Guarded`
//! through the scope guard, never ungated (D8.3, call A17).
//!
//! Track T1a hands over this skeleton: both final signatures exist and return
//! `None`, so T4 flips the bodies and edits no shared file (spec D1).

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_core::guard::ScopeRateGuard;
use aitm_plugin::language::ProtocolLanguage;
use aitm_scan_model::Lane;

/// The WebSocket lane, or `None` while the lane is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and registers the lane
/// it gets back; a `None` lane makes `scan.start` refuse a `ws` lane with
/// `lane_unavailable`. Track T4 replaces the body with `Some(Arc::new(..))`;
/// the signature is final.
#[must_use]
pub fn lane() -> Option<Arc<dyn Lane>> {
    None
}

/// The `ws.*` protocol language, or `None` while the track is unimplemented.
///
/// `crates/aitm/src/main.rs` calls this with the scope/rate guard from its
/// `LateHandles` and registers what it gets back. Every `ws.*` host fn is
/// `Guarded` through `guard`, so a script cannot reach a host outside scope or
/// past the rate limit (D8.3, call A17). Track T4 replaces the body; the
/// signature is final.
#[must_use]
pub fn language(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>> {
    let _ = guard;
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn skeleton_returns_none() {
        assert!(crate::lane().is_none());
        assert!(crate::language(Arc::new(aitm_core::guard::StdGuard::default())).is_none());
    }
}
