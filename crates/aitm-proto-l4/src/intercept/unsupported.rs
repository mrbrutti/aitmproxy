//! The non-Linux in-path backend (M5 Task 11).
//!
//! In-path packet interception is Linux-only: it relies on NFQUEUE, which has no
//! macOS/BSD equivalent (research note 09 — pf rejects `divert-to` and Apple's
//! packet filter provider can only allow/drop/delay, not reinject a mutated
//! packet). So on every non-Linux OS the backend is a fail-closed stub whose `open`
//! returns [`L4Error::Unavailable`] with a clear reason; capture / inject /
//! send-recv remain available. This keeps `l4.intercept.*` honest about what the
//! platform supports instead of panicking.

use super::{InterceptBackend, InterceptQueue};
use crate::backend::L4Error;

/// The in-path backend on a non-Linux OS: a fail-closed stub. `queue_num` is kept
/// for API parity with the Linux backend but is never bound.
#[derive(Debug, Clone, Copy)]
pub struct NfqueueBackend {
    #[allow(dead_code)]
    queue_num: u16,
}

impl NfqueueBackend {
    /// A backend for `nft` queue number `queue_num` — never actually bound on this
    /// OS.
    #[must_use]
    pub fn new(queue_num: u16) -> Self {
        Self { queue_num }
    }
}

impl InterceptBackend for NfqueueBackend {
    fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error> {
        Err(L4Error::Unavailable(
            "in-path packet interception is Linux-only (NFQUEUE); this OS has no equivalent"
                .to_string(),
        ))
    }
}
