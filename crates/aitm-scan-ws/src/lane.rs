//! The `WsLane` — written by task 17 of the T4 plan.

use std::sync::Arc;

use aitm_scan_model::Lane;

/// The WebSocket lane, or `None` while the lane is unimplemented.
///
/// `crate::lane()` delegates here, so flipping the slot is an edit inside this
/// module and `lib.rs` is written once (plan call 11). Task 17 replaces the
/// body with `Some(Arc::new(WsLane::new(..)))`.
#[must_use]
pub fn build() -> Option<Arc<dyn Lane>> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn slot_is_none_until_task_17() {
        assert!(crate::lane().is_none());
    }
}
