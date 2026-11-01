//! `aitm-scan-http` — the scanner v2 HTTP lane.
//!
//! Owned by track **T2** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.1**). Track T1a hands over this skeleton: the crate exists, is a workspace
//! member, and exposes the final [`lane`] signature the binary already calls, so
//! T2 flips the body and edits no shared file (spec D1, "Registration without
//! shared files"). `crates/aitm/src/wire.rs` is frozen after T1a.

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_scan_model::Lane;

/// The HTTP lane, or `None` while the lane is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and registers the lane
/// it gets back; a `None` lane makes `scan.start` refuse an `http` lane with
/// `lane_unavailable`. Track T2 replaces the body with `Some(Arc::new(..))`;
/// the signature is final.
#[must_use]
pub fn lane() -> Option<Arc<dyn Lane>> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_returns_none() {
        assert!(crate::lane().is_none());
    }
}
