//! The `WsLanguage` and the `ws.*` namespace — written by task 8 of the T4 plan.

use std::sync::Arc;

use aitm_core::guard::ScopeRateGuard;
use aitm_plugin::language::ProtocolLanguage;

/// The `ws.*` protocol language, or `None` while the namespace is unimplemented.
///
/// `crate::language()` delegates here, so flipping the slot is an edit inside
/// this module and `lib.rs` is written once (plan call 11). Every `ws.*` host
/// fn task 8 adds is `Guarded` through `guard`.
#[must_use]
pub fn build(guard: Arc<dyn ScopeRateGuard>) -> Option<Box<dyn ProtocolLanguage>> {
    let _ = guard;
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::guard::StdGuard;

    #[test]
    fn slot_is_none_until_task_8() {
        assert!(crate::language(Arc::new(StdGuard::default())).is_none());
    }
}
