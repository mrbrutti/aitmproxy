//! `aitm-scan-checks-http` — scanner v2 native HTTP checks.
//!
//! Owned by track **T3** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.2**). This crate contributes native checks to the HTTP lane's catalogue,
//! not a second `http` lane, so its registration slot is [`checks`] rather than
//! `lane()` (spec amendment of 2026-10-31, recorded as A16).
//!
//! Track T1a hands over this skeleton: the crate exists, is a workspace member,
//! and exposes the final [`checks`] signature the binary already calls, so T3
//! flips the body and edits no shared file (spec D1).

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_scan_model::Check;

/// This crate's native HTTP checks, empty while the track is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and adds what it gets
/// back to the HTTP lane's catalogue. Track T3 replaces the body with the real
/// check list; the signature is final.
#[must_use]
pub fn checks() -> Vec<Arc<dyn Check>> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_returns_no_checks() {
        assert!(crate::checks().is_empty());
    }
}
