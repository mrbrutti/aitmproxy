//! [`ProcessResolver`]: the one public type, the platform scanner behind the
//! coalescer, implementing `aitm_core::peer::PeerResolver` (spec D2, D3).

use std::net::SocketAddr;

use aitm_core::peer::PeerResolver;

use crate::coalesce::Coalescer;
use crate::types::{Limits, Tuple};

#[cfg(target_os = "macos")]
type PlatformScanner = crate::macos::scan::MacScanner;
#[cfg(target_os = "linux")]
type PlatformScanner = crate::linux::scan::LinuxScanner;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
type PlatformScanner = NoScanner;

/// The scanner on every other OS: finds nothing, names nothing.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct NoScanner;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl crate::types::SocketScanner for NoScanner {
    fn find_owners(
        &self,
        _wanted: &[Tuple],
        _deadline: std::time::Instant,
    ) -> std::collections::HashMap<Tuple, crate::types::ProcessKey> {
        std::collections::HashMap::new()
    }

    fn find_owners_among(
        &self,
        _wanted: &[Tuple],
        _deadline: std::time::Instant,
        _pids: &[u32],
    ) -> crate::types::Probe {
        crate::types::Probe::default()
    }

    fn identity(&self, _key: crate::types::ProcessKey) -> Option<String> {
        None
    }
}

/// The platform scanner with `skip_pid` never reported as an owner.
fn platform_scanner(skip_pid: Option<u32>) -> PlatformScanner {
    #[cfg(target_os = "macos")]
    {
        PlatformScanner { skip_pid }
    }
    #[cfg(target_os = "linux")]
    {
        let mut scanner = PlatformScanner::new();
        scanner.skip_pid = skip_pid;
        scanner
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = skip_pid;
        NoScanner
    }
}

/// Names the process behind an accepted loopback connection: one socket scan at
/// a time, a warm probe of recently matched pids before any full scan, a token
/// bucket of full scans, a per-process identity cache, sanitised output; `None`
/// on any miss, timeout or drained budget (spec D3). Our own pid
/// is skipped: the proxy's accepted socket is the mirror image of every tuple.
pub struct ProcessResolver {
    inner: Coalescer<PlatformScanner>,
}

impl ProcessResolver {
    /// `Limits::default()`, own pid skipped.
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// Custom limits, own pid skipped.
    pub fn with_limits(limits: Limits) -> Self {
        Self::build(limits, Some(std::process::id()))
    }

    /// Custom limits **and** skipped pid. Tests only: `skip_pid = None` lets a
    /// test resolve its own sockets; production never reports itself.
    #[doc(hidden)]
    pub fn for_tests(limits: Limits, skip_pid: Option<u32>) -> Self {
        Self::build(limits, skip_pid)
    }

    /// The one constructor behind both: the platform scanner with `skip_pid`
    /// never reported, under a coalescer with `limits`.
    fn build(limits: Limits, skip_pid: Option<u32>) -> Self {
        Self {
            inner: Coalescer::new(platform_scanner(skip_pid), limits),
        }
    }
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerResolver for ProcessResolver {
    fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String> {
        self.inner.resolve(Tuple {
            client: peer,
            proxy: local,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessResolver;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use crate::types::Limits;
    use aitm_core::peer::PeerResolver;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn accepted_pair() -> (
        std::net::TcpListener,
        std::net::TcpStream,
        std::net::TcpStream,
    ) {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let client = TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        (listener, client, accepted)
    }

    /// AC9 (Terminal: binds a loopback socket). With the own-pid skip lifted the
    /// resolver names this very process.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn resolve_names_this_process() {
        let (_l, _c, accepted) = accepted_pair();
        let resolver = ProcessResolver::for_tests(Limits::default(), None);
        let got = resolver.resolve(
            accepted.peer_addr().expect("peer"),
            accepted.local_addr().expect("local"),
        );
        let s = got.expect("an identity");
        assert!(s.starts_with("aitm_peer_process"), "identity = {s}");
    }

    /// AC9 (Terminal: binds a loopback socket). In production shape our own pid
    /// is skipped, and it is the only owner of this socket, so: `None`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn resolve_skips_own_pid_in_production_shape() {
        let (_l, _c, accepted) = accepted_pair();
        let resolver = ProcessResolver::new();
        assert_eq!(
            resolver.resolve(
                accepted.peer_addr().expect("peer"),
                accepted.local_addr().expect("local"),
            ),
            None
        );
    }

    /// Elsewhere the resolver is a stub: always `None`, no scan.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn non_macos_resolver_is_none() {
        let resolver = ProcessResolver::default();
        assert_eq!(
            resolver.resolve(
                "127.0.0.1:50000".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap()
            ),
            None
        );
    }
}
