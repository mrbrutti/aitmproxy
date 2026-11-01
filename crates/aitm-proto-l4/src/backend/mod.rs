//! The capture/inject backend seam and the crate's wire error (M5 Task 6).
//!
//! [`CaptureInjectBackend`] abstracts the two raw-packet primitives — open a
//! scoped capture and inject a link-layer frame — behind a trait so the wire
//! choke point ([`crate::wire::send_on_wire`]) and the capture task (M5 Task 7)
//! depend on behaviour, not on libpcap directly. The libpcap implementation is
//! [`pcap::PcapBackend`]; the privileged-helper implementation is
//! [`helper::HelperBackend`] (privilege plan P1b.13); every production caller
//! holds them behind [`routed::RoutedBackend`] (`PrivilegeState::backend()`,
//! privilege plan P1b.8), which routes each call on the live privilege report;
//! tests substitute an in-memory mock.
//!
//! **Fail-closed.** When libpcap or the capture/inject privilege is absent, a
//! backend returns [`L4Error::Unavailable`] rather than panicking — the spec's
//! `L4Unavailable` fail-closed contract (AC17, AC20).

pub mod helper;
pub mod pcap;
pub mod routed;

use std::fmt;
use std::time::Duration;

use crate::guard::L4GuardError;

/// An error from the L4 wire path: a guard refusal surfaced at the choke point,
/// an unavailable subsystem (no privilege / libpcap absent / OS-unsupported), or
/// a backend write failure. Mirrors the crate's hand-written `Display`/`Error`
/// style (no external derive crate), matching [`L4GuardError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Error {
    /// The guard refused this write: the permit's size/count budget was exhausted,
    /// or it is not an injection permit. Carries the typed [`L4GuardError`].
    Guard(L4GuardError),
    /// The L4 subsystem is unavailable here: no capture/inject privilege, libpcap
    /// missing, or the OS does not support the requested backend. Fail-closed.
    Unavailable(String),
    /// The backend accepted the request but failed to put the bytes on the wire.
    WireWrite(String),
}

impl fmt::Display for L4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L4Error::Guard(e) => write!(f, "{e}"),
            L4Error::Unavailable(why) => write!(f, "L4 unavailable: {why}"),
            L4Error::WireWrite(why) => write!(f, "wire write failed: {why}"),
        }
    }
}

impl std::error::Error for L4Error {}

impl From<L4GuardError> for L4Error {
    fn from(e: L4GuardError) -> Self {
        L4Error::Guard(e)
    }
}

/// A live capture source: blocking reads of raw link-layer frames, one at a time.
///
/// The read timeout is configured at [`CaptureInjectBackend::open_capture`] time
/// (libpcap's model), so `next_frame` returns `Ok(None)` when a poll elapses with
/// no frame — the capture task (M5 Task 7) uses that to stay responsive to
/// shutdown. The interface is intentionally minimal; Task 7 owns `capture.rs` and
/// may extend it.
pub trait CaptureSource {
    /// Block for up to the configured read timeout for the next link-layer frame.
    /// `Ok(None)` means the poll elapsed with no frame; `Err` is fail-closed.
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error>;
}

/// The raw-packet backend: open a scoped capture, or inject a link-layer frame.
///
/// Injection is reached **only** through [`crate::wire::send_on_wire`], which
/// requires an `L4Permit`; the trait itself carries no authorization, so no code
/// path reaches `inject` without first passing the guard.
pub trait CaptureInjectBackend: Send + Sync {
    /// Open a capture on `iface`, applying an optional BPF `filter` (derived from
    /// the L4 scope by the capture task). `read_timeout` bounds each `next_frame`
    /// poll. Fail-closed ([`L4Error::Unavailable`]) when libpcap/privilege is
    /// absent.
    fn open_capture(
        &self,
        iface: &str,
        filter: Option<&str>,
        read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error>;

    /// Inject raw link-layer `bytes` on `iface`. The buffer already includes the
    /// link-layer header (pcap `sendpacket` is L2). Fail-closed
    /// ([`L4Error::Unavailable`]) when libpcap/privilege is absent.
    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error>;
}
