//! The lane's one poison-recovering mutex lock helper — owned by scanner v2
//! track T5.
//!
//! Every `Mutex` the lane holds guards plain bookkeeping (a cached class, a
//! runner table, the per-job counters), so a panic elsewhere must not poison it
//! and take the whole lane down: a poisoned lock is recovered into its inner
//! guard rather than propagated (review finding M3 — the one copy for the crate).

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Take a lock, recovering a poisoned one into its inner guard.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
