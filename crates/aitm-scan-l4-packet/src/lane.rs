//! The `Lane` implementation and the slot body behind `crate::lane` — owned by
//! scanner v2 track T5, plan task 11.

use std::sync::Arc;

use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_scan_model::Lane;

/// Build the packet lane, or `None` while the lane is unimplemented.
///
/// Plan task 11 replaces this body with the real `PacketLane`, which is `Some`
/// even when both handles are `None` so that `scan.start` refuses with
/// `refused_l4` rather than `lane_unavailable` (D3's refusal order, call A18).
#[must_use]
pub fn build(
    guard: Option<Arc<L4Guard>>,
    store: Option<Arc<dyn L4FlowStore>>,
) -> Option<Arc<dyn Lane>> {
    let _ = (guard, store);
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn build_returns_none_until_task_11() {
        assert!(crate::lane(None, None).is_none());
    }
}
