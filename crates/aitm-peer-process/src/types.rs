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
    /// Token-bucket capacity: at most this many scans in a burst.
    pub scan_tokens: u32,
    /// Token-bucket refill rate, scans per second.
    pub scan_refill_per_s: u32,
    /// Capacity of the `ProcessKey → identity` cache (FIFO eviction).
    pub cache_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_deadline: Duration::from_millis(250),
            scan_tokens: 10,
            scan_refill_per_s: 10,
            cache_entries: 256,
        }
    }
}

/// One operating system's way of finding socket owners and naming them. The
/// coalescer calls `find_owners` once per batch and `identity` once per
/// `ProcessKey` cache miss.
pub(crate) trait SocketScanner: Send + Sync {
    /// Which process owns the client end of each wanted tuple. Tuples not found by
    /// `deadline` are absent from the map. Never errors: an unreadable pid is a skip.
    fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey>;

    /// The raw, **unsanitised** identity of a process (bundle identifier or
    /// executable basename), or `None` if the OS would not say.
    fn identity(&self, key: ProcessKey) -> Option<String>;
}
