//! `aitm-scan-l4-packet` — the scanner v2 L4 packet lane.
//!
//! Owned by track **T5** of the scanner v2 design
//! (`docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`, section
//! **D8.4**). `crates/aitm/src/wire.rs` calls [`lane`] with the handles from
//! `Features::l4_shared`; both are `None` when L4 is disabled. A landed L4 lane
//! returns `Some` even then, so that `scan.start` refuses with `refused_l4`
//! rather than `lane_unavailable` (D3's refusal order, call A18).
//!
//! Track T1a hands over this skeleton: the final [`lane`] signature exists and
//! returns `None`, so T5 flips the body and edits no shared file (spec D1).

#![forbid(unsafe_code)]

use std::sync::Arc;

use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_scan_model::Lane;

/// The L4 packet lane, or `None` while the lane is unimplemented.
///
/// `crates/aitm/src/wire.rs` calls this once at startup with the handles from
/// `Features::l4_shared`; both are `None` when L4 is disabled. Track T5
/// replaces the body with a lane that is `Some` even when the handles are
/// `None`, so `scan.start` refuses with `refused_l4` rather than
/// `lane_unavailable` (D3's refusal order, call A18). The signature is final.
#[must_use]
pub fn lane(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
) -> Option<Arc<dyn Lane>> {
    let _ = (guard, store);
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_returns_none() {
        assert!(crate::lane(None, None).is_none());
    }
}
