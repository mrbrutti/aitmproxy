//! Runtime egress-confinement posture for the browser-facing listener
//! (scanner finding S2). See the 2026-10-29 browser-egress-confinement spec.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Runtime egress-confinement posture for the browser-facing listener. When
/// confined, the `SsrfConnector` refuses an out-of-scope PUBLIC host (scanner
/// finding S2). Private/loopback handling is unaffected. Browser-path only —
/// the active-action guard (`check_active`) never consults this.
///
/// The posture is `base || holds > 0`: `base` is the config-seeded /
/// command-toggled standing posture, and each live [`ConfinementToken`] is one
/// temporary campaign hold on top of it. A refcount of holds (rather than a
/// save/restore bool) means overlapping campaigns compose and a dropped or
/// panicked campaign releases exactly its own hold, never a neighbour's.
#[derive(Debug)]
pub struct EgressConfinement {
    base: AtomicBool,
    holds: AtomicUsize,
}

impl EgressConfinement {
    /// Create the posture with its standing `base` value (from config at startup).
    pub fn new(base: bool) -> Self {
        Self {
            base: AtomicBool::new(base),
            holds: AtomicUsize::new(0),
        }
    }

    /// `true` when the browser-facing connector must refuse out-of-scope public
    /// hosts: the standing base is on, or at least one campaign hold is live.
    pub fn confined(&self) -> bool {
        self.base.load(Ordering::Acquire) || self.holds.load(Ordering::Acquire) > 0
    }

    /// Set the standing base posture (operator / `browser.confine` toggle).
    /// Does not touch live campaign holds.
    pub fn set_base(&self, on: bool) {
        self.base.store(on, Ordering::Release);
    }

    /// Take one campaign hold. The posture stays confined for as long as the
    /// returned token is alive; dropping it releases exactly this hold.
    #[must_use = "dropping the token immediately releases the hold"]
    pub fn confine(self: &Arc<Self>) -> ConfinementToken {
        self.holds.fetch_add(1, Ordering::AcqRel);
        ConfinementToken {
            posture: Arc::clone(self),
        }
    }
}

/// One campaign-scoped hold on an [`EgressConfinement`]. Dropping the token
/// releases the hold (crash-safe: an unwinding campaign still drops it).
#[derive(Debug)]
pub struct ConfinementToken {
    posture: Arc<EgressConfinement>,
}

impl Drop for ConfinementToken {
    fn drop(&mut self) {
        self.posture.holds.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrowserConfig;
    use std::sync::Arc;

    #[test]
    fn confinement_defaults_off_and_composes() {
        let c = Arc::new(EgressConfinement::new(false));
        assert!(!c.confined());

        c.set_base(true);
        assert!(c.confined());
        c.set_base(false);
        assert!(!c.confined());

        {
            let _t1 = c.confine();
            assert!(c.confined());
            {
                let _t2 = c.confine();
                assert!(c.confined());
            }
            // One hold released, one still live.
            assert!(c.confined());
        }
        // Both tokens dropped: posture falls back to the (off) base.
        assert!(!c.confined());
    }

    #[test]
    fn config_default_is_free() {
        assert!(!BrowserConfig::default().confine_egress_to_scope);
    }
}
