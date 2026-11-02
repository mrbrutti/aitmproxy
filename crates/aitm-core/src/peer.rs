//! Proxied client attribution (spec 2026-11-01-proxied-client-attribution).
//!
//! The acceptor knows the loopback `ip:port` of every client it accepts; the
//! process owning the other end can be named without privileges (macOS libproc,
//! Linux `/proc`). That lookup lives in the leaf crate `aitm-peer-process`; this
//! module holds the seam the acceptor drives it through:
//!
//! - [`PeerResolver`]: the blocking lookup, implemented outside `aitm-core`.
//! - [`is_loopback_peer`]: the gate (spec D1) — only a loopback peer is ever
//!   resolved; a LAN client is never attempted.
//! - [`start_attribution`] / [`finish_attribution`]: start on a blocking thread
//!   at accept, concurrently with the peek, and wait at most
//!   [`ATTRIBUTION_BUDGET`] after it (spec D3). A miss is `None`, never an error
//!   and never a placeholder; the connection is served exactly as before.
//!
//! The identity is data about a client — stored on the flow and shown — never a
//! scope, guard or routing input, and never logged above `debug`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Names the process owning the client end of an accepted connection.
///
/// `peer` is the client's address, `local` the accepted socket's own address.
/// Blocking: the acceptor calls it on a blocking thread
/// (`tokio::task::spawn_blocking`). `None` means unknown, never a placeholder.
pub trait PeerResolver: Send + Sync + 'static {
    fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String>;
}

/// How long the acceptor waits for the resolver **after** the peek completes
/// (spec D3): ~3.5× a measured full libproc scan, below human perception, an
/// order of magnitude under a TLS handshake.
pub const ATTRIBUTION_BUDGET: Duration = Duration::from_millis(25);

/// Spec D1: `127.0.0.0/8`, `::1`, or an IPv4-mapped `::ffff:127.0.0.0/8`.
pub fn is_loopback_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Start resolving the client of an accepted connection on a blocking thread.
///
/// Returns a task only when a resolver is set, the local address is known and
/// the peer is loopback; otherwise `None` and nothing is spawned (AC1).
pub(crate) fn start_attribution(
    resolver: Option<&Arc<dyn PeerResolver>>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> Option<JoinHandle<Option<String>>> {
    let resolver = resolver?.clone();
    let local = local?;
    if !is_loopback_peer(peer.ip()) {
        return None;
    }
    Some(tokio::task::spawn_blocking(move || {
        resolver.resolve(peer, local)
    }))
}

/// Wait at most `budget` for the attribution task and flatten its result:
/// `Some(identity)` only when the task finished in time with an identity;
/// timeout, join error, a missing task or `None` all give `None`.
///
/// On timeout the handle is dropped but the blocking task runs to completion in
/// the pool (bounded by the resolver's own scan deadline); its result still
/// warms the resolver's cache for the next connection.
pub(crate) async fn finish_attribution(
    task: Option<JoinHandle<Option<String>>>,
    budget: Duration,
) -> Option<String> {
    let task = task?;
    match tokio::time::timeout(budget, task).await {
        Ok(Ok(identity)) => identity,
        Ok(Err(_join_error)) => None,
        Err(_elapsed) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{finish_attribution, is_loopback_peer, start_attribution, PeerResolver};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip literal")
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("socket literal")
    }

    /// AC1: the eight literal classifications.
    #[test]
    fn loopback_classification() {
        assert!(is_loopback_peer(ip("127.0.0.1")));
        assert!(is_loopback_peer(ip("127.5.5.5")));
        assert!(is_loopback_peer(ip("::1")));
        assert!(is_loopback_peer(ip("::ffff:127.0.0.1")));
        assert!(!is_loopback_peer(ip("10.0.0.1")));
        assert!(!is_loopback_peer(ip("::ffff:10.0.0.1")));
        assert!(!is_loopback_peer(ip("2001:db8::1")));
        assert!(!is_loopback_peer(ip("0.0.0.0")));
    }

    /// Counts calls and answers with a fixed identity.
    struct CountingResolver {
        calls: AtomicUsize,
    }

    impl PeerResolver for CountingResolver {
        fn resolve(&self, _peer: SocketAddr, _local: SocketAddr) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Some("counted".to_string())
        }
    }

    /// AC1: a non-loopback peer never spawns a task (the counter stays 0); each
    /// loopback form spawns one, and awaiting all three drives the counter to 3.
    #[tokio::test]
    async fn non_loopback_peer_spawns_no_task() {
        let resolver = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
        });
        let dyn_resolver: Arc<dyn PeerResolver> = resolver.clone();
        let local = Some(addr("127.0.0.1:8080"));

        for peer in ["10.0.0.1:5000", "[2001:db8::1]:5000"] {
            let task = start_attribution(Some(&dyn_resolver), addr(peer), local);
            assert!(task.is_none(), "{peer} must not spawn a resolver task");
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

        // A resolver that is not set spawns nothing either, loopback or not.
        assert!(start_attribution(None, addr("127.0.0.1:5000"), local).is_none());
        // Nor does an unknown local address.
        assert!(start_attribution(Some(&dyn_resolver), addr("127.0.0.1:5000"), None).is_none());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

        let mut tasks = Vec::new();
        for peer in ["127.0.0.1:5000", "[::1]:5000", "[::ffff:127.0.0.1]:5000"] {
            let task = start_attribution(Some(&dyn_resolver), addr(peer), local);
            assert!(task.is_some(), "{peer} must spawn a resolver task");
            tasks.push(task);
        }
        for task in tasks {
            let got = finish_attribution(task, Duration::from_secs(5)).await;
            assert_eq!(got.as_deref(), Some("counted"));
        }
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
    }

    /// Sleeps for `delay`, then answers `identity`.
    struct SlowResolver {
        delay: Duration,
        identity: Option<String>,
    }

    impl PeerResolver for SlowResolver {
        fn resolve(&self, _peer: SocketAddr, _local: SocketAddr) -> Option<String> {
            std::thread::sleep(self.delay);
            self.identity.clone()
        }
    }

    /// D3: `finish_attribution` flattens the nested result — a prompt `Some("x")`
    /// comes through; a task that outlives the budget yields `None` promptly.
    #[tokio::test]
    async fn finish_within_budget_flattens() {
        let prompt: Arc<dyn PeerResolver> = Arc::new(SlowResolver {
            delay: Duration::ZERO,
            identity: Some("x".to_string()),
        });
        let task = start_attribution(
            Some(&prompt),
            addr("127.0.0.1:5000"),
            Some(addr("127.0.0.1:8080")),
        );
        assert_eq!(
            finish_attribution(task, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("x")
        );

        let slow: Arc<dyn PeerResolver> = Arc::new(SlowResolver {
            delay: Duration::from_millis(200),
            identity: Some("late".to_string()),
        });
        let task = start_attribution(
            Some(&slow),
            addr("127.0.0.1:5000"),
            Some(addr("127.0.0.1:8080")),
        );
        let started = Instant::now();
        let got = finish_attribution(task, Duration::from_millis(10)).await;
        let elapsed = started.elapsed();
        assert_eq!(got, None, "a task past the budget resolves None");
        assert!(
            elapsed < Duration::from_millis(100),
            "finish_attribution must return at the budget, took {elapsed:?}"
        );

        // No task at all: `None` without waiting.
        assert_eq!(finish_attribution(None, Duration::from_secs(5)).await, None);
    }
}
