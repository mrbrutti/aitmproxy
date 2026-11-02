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
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Semaphore;
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
    start_attribution_with(in_flight_slots(), resolver, peer, local)
}

/// How many attribution tasks may occupy the blocking pool at once (security
/// finding S1, 2026-11-01). Each one may sit for the resolver's full scan
/// deadline (250 ms) after the acceptor's 25 ms budget has dropped its handle,
/// so an unbounded flood of loopback connections could fill tokio's 512
/// blocking threads and stall the bus and MCP. The 65th concurrent connection
/// is simply not attributed (`None`); nothing else about it changes.
pub(crate) const MAX_IN_FLIGHT: usize = 64;

/// The process-wide slot pool behind [`start_attribution`].
fn in_flight_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT)))
}

/// [`start_attribution`] over an explicit slot pool (tests use their own so
/// parallel tests do not share the process-wide one). The permit travels into
/// the blocking task and is released when the task returns, however it ends.
fn start_attribution_with(
    slots: &Arc<Semaphore>,
    resolver: Option<&Arc<dyn PeerResolver>>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> Option<JoinHandle<Option<String>>> {
    let resolver = resolver?.clone();
    let local = local?;
    if !is_loopback_peer(peer.ip()) {
        return None;
    }
    let permit = Arc::clone(slots).try_acquire_owned().ok()?;
    Some(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // A resolver panic costs this connection its identity, nothing more;
        // say so once per occurrence (the identity itself is never logged
        // above `debug`; the loopback peer address names no process).
        match catch_unwind(AssertUnwindSafe(|| resolver.resolve(peer, local))) {
            Ok(identity) => identity,
            Err(_panic) => {
                tracing::warn!(%peer, "attribution task panicked; client identity dropped");
                None
            }
        }
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
        Ok(Err(join_error)) => {
            // Panics are caught inside the task; what is left is cancellation
            // (runtime shutdown), which is not worth more than a debug line.
            tracing::debug!(%join_error, "attribution task did not complete");
            None
        }
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

    /// Panics instead of answering.
    struct PanickingResolver;

    impl PeerResolver for PanickingResolver {
        fn resolve(&self, _peer: SocketAddr, _local: SocketAddr) -> Option<String> {
            panic!("resolver blew up");
        }
    }

    /// D1 ("nothing on this path can return an error to `handle_conn`"): a
    /// resolver that panics on its blocking thread costs the connection only its
    /// identity — the join error is flattened to `None`, never propagated.
    #[tokio::test]
    async fn a_panicking_resolver_yields_none_not_an_error() {
        let resolver: Arc<dyn PeerResolver> = Arc::new(PanickingResolver);
        let task = start_attribution(
            Some(&resolver),
            addr("127.0.0.1:5000"),
            Some(addr("127.0.0.1:8080")),
        );
        assert!(task.is_some(), "a loopback peer spawns the task");
        assert_eq!(finish_attribution(task, Duration::from_secs(5)).await, None);
    }

    /// Hands back exactly what it was asked about.
    struct EchoResolver;

    impl PeerResolver for EchoResolver {
        fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String> {
            Some(format!("{peer}->{local}"))
        }
    }

    /// The resolver sees the accepted socket's peer and local addresses as the
    /// acceptor saw them (client first, proxy second), and the answer reaches
    /// `finish_attribution` unchanged.
    #[tokio::test]
    async fn resolver_receives_the_peer_and_local_addresses_as_given() {
        let resolver: Arc<dyn PeerResolver> = Arc::new(EchoResolver);
        let task = start_attribution(
            Some(&resolver),
            addr("[::ffff:127.0.0.1]:50000"),
            Some(addr("127.0.0.1:8080")),
        );
        assert_eq!(
            finish_attribution(task, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("[::ffff:127.0.0.1]:50000->127.0.0.1:8080")
        );
    }

    /// D3: the acceptor waits the spec's 25 ms after the peek, no more.
    #[test]
    fn attribution_budget_is_the_spec_value() {
        assert_eq!(super::ATTRIBUTION_BUDGET, Duration::from_millis(25));
    }

    /// Parks every call until `release` is set, then answers.
    struct ParkingResolver {
        gate: std::sync::Mutex<bool>,
        cv: std::sync::Condvar,
        calls: AtomicUsize,
    }

    impl ParkingResolver {
        fn new() -> Self {
            Self {
                gate: std::sync::Mutex::new(false),
                cv: std::sync::Condvar::new(),
                calls: AtomicUsize::new(0),
            }
        }

        fn release(&self) {
            *self.gate.lock().expect("gate") = true;
            self.cv.notify_all();
        }
    }

    impl PeerResolver for ParkingResolver {
        fn resolve(&self, _peer: SocketAddr, _local: SocketAddr) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut open = self.gate.lock().expect("gate");
            while !*open {
                open = self.cv.wait(open).expect("gate");
            }
            Some("parked".to_string())
        }
    }

    /// Security finding S1 (2026-11-01): at most `MAX_IN_FLIGHT` attribution
    /// tasks occupy the blocking pool at once. With 64 parked, the 65th
    /// `start_attribution` is `None` at once and never reaches the resolver;
    /// once the parked tasks return, their permits are back and a new
    /// connection is attributed again.
    #[tokio::test]
    async fn the_sixty_fifth_concurrent_attribution_is_refused_without_a_spawn() {
        let resolver = Arc::new(ParkingResolver::new());
        let dyn_resolver: Arc<dyn PeerResolver> = resolver.clone();
        let slots = Arc::new(tokio::sync::Semaphore::new(super::MAX_IN_FLIGHT));
        let local = Some(addr("127.0.0.1:8080"));

        let mut tasks = Vec::new();
        for port in 0..64u16 {
            let peer = SocketAddr::new(ip("127.0.0.1"), 40_000 + port);
            let task = super::start_attribution_with(&slots, Some(&dyn_resolver), peer, local);
            assert!(task.is_some(), "connection {port} gets a slot");
            tasks.push(task);
        }
        let started = Instant::now();
        let refused = super::start_attribution_with(
            &slots,
            Some(&dyn_resolver),
            addr("127.0.0.1:50000"),
            local,
        );
        let elapsed = started.elapsed();
        let permits_while_full = slots.available_permits();
        // Release first: a failed assertion must not leave 64 parked blocking
        // threads for the runtime's teardown to wait on.
        resolver.release();
        assert!(
            refused.is_none(),
            "the 65th in-flight attribution is refused"
        );
        assert!(elapsed < Duration::from_millis(50));
        assert_eq!(permits_while_full, 0);
        for task in tasks {
            assert_eq!(
                finish_attribution(task, Duration::from_secs(5))
                    .await
                    .as_deref(),
                Some("parked")
            );
        }
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            64,
            "the refused call never ran"
        );
        assert_eq!(
            slots.available_permits(),
            64,
            "every permit came back with its task"
        );

        let again = super::start_attribution_with(
            &slots,
            Some(&dyn_resolver),
            addr("127.0.0.1:50001"),
            local,
        );
        assert_eq!(
            finish_attribution(again, Duration::from_secs(5))
                .await
                .as_deref(),
            Some("parked")
        );
    }

    /// S1: the production cap is 64, well under tokio's 512 blocking threads.
    #[test]
    fn in_flight_cap_is_sixty_four() {
        assert_eq!(super::MAX_IN_FLIGHT, 64);
    }
}
