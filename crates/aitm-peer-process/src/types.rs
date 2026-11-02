//! Shared value types: the connection tuple the core hands us, the (pid, start)
//! key that survives pid recycling, the resource limits, and the per-OS scanner
//! seam the coalescer drives.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The two ends of an accepted connection as the core sees them: the client's
/// loopback address (the remote peer of the accepted socket) and the proxy's
/// listener address (the accepted socket's local address).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Tuple {
    /// The client's `ip:port` (`peer_addr()` of the accepted stream).
    pub client: SocketAddr,
    /// The proxy's `ip:port` (`local_addr()` of the accepted stream).
    pub proxy: SocketAddr,
}

/// A process identity that a recycled pid cannot forge: the pid plus its start
/// time (macOS: microseconds since the epoch from `PROC_PIDTBSDINFO`; Linux: field
/// 22 of `/proc/<pid>/stat`, in clock ticks). `start == 0` when the OS would not
/// say.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcessKey {
    pub pid: u32,
    pub start: u64,
}

/// Resource limits of one resolver.
#[derive(Clone, Debug)]
pub struct Limits {
    /// How long one socket scan may run before it gives up on the tuples it has
    /// not found yet.
    pub scan_deadline: Duration,
    /// Token-bucket capacity: at most this many **full** scans in a burst. Warm
    /// probes (see [`SocketScanner::find_owners_among`]) are not charged.
    pub scan_tokens: u32,
    /// Token-bucket refill rate, full scans per second.
    pub scan_refill_per_s: u32,
    /// Capacity of the `ProcessKey → identity` cache (FIFO eviction).
    pub cache_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_deadline: Duration::from_millis(250),
            scan_tokens: 20,
            scan_refill_per_s: 20,
            cache_entries: 256,
        }
    }
}

/// The outcome of a targeted probe ([`SocketScanner::find_owners_among`]).
#[derive(Default, Debug)]
pub(crate) struct Probe {
    /// Owners found among the probed pids; tuples not found are absent.
    pub owners: HashMap<Tuple, ProcessKey>,
    /// Probed pids whose socket table could not be read or held no socket at
    /// all (exited, re-executed as another user, or simply idle): the coalescer
    /// drops them from its warm set.
    pub gone: Vec<u32>,
}

/// One operating system's way of finding socket owners and naming them. The
/// coalescer calls `find_owners_among` on its warm pids first, `find_owners`
/// (one full scan, one token) only for what that missed, and `identity` once per
/// `ProcessKey` cache miss.
pub(crate) trait SocketScanner: Send + Sync {
    /// Which process owns the client end of each wanted tuple, over every pid on
    /// the host. Tuples not found by `deadline` are absent from the map. Never
    /// errors: an unreadable pid is a skip.
    fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey>;

    /// The same match over **only** `pids`, in the order given (the caller passes
    /// them ascending so the lowest matching pid still wins). Reports which of
    /// them had no socket fds. Cost is one fd-table read per pid, so the
    /// coalescer runs it without taking a token.
    fn find_owners_among(&self, wanted: &[Tuple], deadline: Instant, pids: &[u32]) -> Probe;

    /// The raw, **unsanitised** identity of a process (bundle identifier or
    /// executable basename), or `None` if the OS would not say.
    fn identity(&self, key: ProcessKey) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::Limits;
    use std::time::Duration;

    /// Spec D3 as amended by F2 (2026-11-01): a 250 ms scan deadline, a bucket
    /// of 20 full scans refilled at 20/s, 256 cached identities. A knob that
    /// drifts from these numbers changes the proxy's worst-case CPU budget.
    #[test]
    fn default_limits_match_spec_d3() {
        let limits = Limits::default();
        assert_eq!(limits.scan_deadline, Duration::from_millis(250));
        assert_eq!(limits.scan_tokens, 20);
        assert_eq!(limits.scan_refill_per_s, 20);
        assert_eq!(limits.cache_entries, 256);
    }
}
