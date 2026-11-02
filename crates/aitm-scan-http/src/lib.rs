//! `aitm-scan-http` — the scanner v2 HTTP lane.
//!
//! Owned by track **T2** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.1**). Track T1a hands over this skeleton: the crate exists, is a workspace
//! member, and exposes the final [`lane`] signature the binary already calls, so
//! T2 flips the body and edits no shared file (spec D1, "Registration without
//! shared files"). `crates/aitm/src/wire.rs` is frozen after T1a.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use aitm_scan_model::Lane;

pub(crate) mod crawl;
pub(crate) mod hash;
pub(crate) mod host;
pub(crate) mod lane;
pub(crate) mod limits;
pub(crate) mod multipart;
pub(crate) mod mutate;
pub(crate) mod params;
pub(crate) mod points;
pub(crate) mod redact;
pub(crate) mod session;
pub(crate) mod sitemap;
pub(crate) mod template;
pub(crate) mod url_norm;
pub(crate) mod xml;

#[cfg(test)]
mod testutil;

/// The HTTP lane.
///
/// `crates/aitm/src/wire.rs` calls this once at startup and registers the lane
/// it gets back. The slot is an `Option` because a lane crate may ship before
/// its lane does — a `None` lane makes `scan.start` refuse an `http` lane with
/// `lane_unavailable` — but this one is now built (track T2, task 20), so the
/// binary prefers it over the interim lane (spec D1).
#[must_use]
pub fn lane() -> Option<Arc<dyn Lane>> {
    Some(Arc::new(lane::HttpLane::new()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use aitm_scan_model::LaneKind;

    /// The slot the binary reads is filled, is the HTTP lane, and ships no
    /// checks of its own (track T3 owns the HTTP checks).
    #[test]
    fn lane_slot_is_populated() {
        let lane = crate::lane().expect("the http lane is registered");

        assert_eq!(lane.lane(), LaneKind::Http);
        assert!(lane.checks().is_empty());
    }
}
