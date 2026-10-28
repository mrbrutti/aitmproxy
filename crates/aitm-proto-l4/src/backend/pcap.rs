//! The libpcap capture/inject backend (M5 Task 6).
//!
//! [`PcapBackend`] implements [`CaptureInjectBackend`] over the `pcap` crate — the
//! same code path on macOS and Linux (research note 08). Injection is L2:
//! `Capture::sendpacket` writes a frame whose link-layer header the caller already
//! supplied. Capture opens a live handle with an optional BPF filter.
//!
//! **Fail-closed.** Every libpcap failure (no privilege, device missing, library
//! absent) is mapped to [`L4Error::Unavailable`] or [`L4Error::WireWrite`]; the
//! backend never panics. The `pcap` crate's internal `unsafe` stays inside the
//! dependency — this crate keeps `#![forbid(unsafe_code)]` (AC20).
//!
//! The backend is stateless: it opens a fresh handle per call, which keeps it
//! `Send + Sync` and free of interior mutability. Batched injection re-opens per
//! packet; caching a handle is a later optimization, out of scope for the choke
//! point itself.

use std::time::Duration;

use super::{CaptureInjectBackend, CaptureSource, L4Error};

/// The production capture/inject backend, backed by libpcap via the `pcap` crate.
#[derive(Debug, Clone, Default)]
pub struct PcapBackend;

impl PcapBackend {
    /// A fresh pcap backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Map a libpcap open/filter failure to a fail-closed [`L4Error::Unavailable`].
/// Permission denied, a missing device, and an absent library all reduce to "the
/// L4 wire is not reachable here" — the spec's `L4Unavailable` contract.
fn unavailable(context: &str, err: &::pcap::Error) -> L4Error {
    L4Error::Unavailable(format!("pcap {context}: {err}"))
}

impl CaptureInjectBackend for PcapBackend {
    fn open_capture(
        &self,
        iface: &str,
        filter: Option<&str>,
        read_timeout: Duration,
    ) -> Result<Box<dyn CaptureSource>, L4Error> {
        let timeout_ms = i32::try_from(read_timeout.as_millis()).unwrap_or(i32::MAX);
        let mut cap = ::pcap::Capture::from_device(iface)
            .and_then(|c| c.promisc(true).timeout(timeout_ms).open())
            .map_err(|e| unavailable("open", &e))?;
        if let Some(bpf) = filter {
            cap.filter(bpf, true)
                .map_err(|e| unavailable("filter", &e))?;
        }
        Ok(Box::new(PcapCaptureSource { cap }))
    }

    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        let mut cap = ::pcap::Capture::from_device(iface)
            .and_then(::pcap::Capture::open)
            .map_err(|e| unavailable("open", &e))?;
        cap.sendpacket(bytes)
            .map_err(|e| L4Error::WireWrite(format!("pcap sendpacket: {e}")))
    }
}

/// A live pcap capture, adapting `next_packet` to [`CaptureSource`].
struct PcapCaptureSource {
    cap: ::pcap::Capture<::pcap::Active>,
}

impl CaptureSource for PcapCaptureSource {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        match self.cap.next_packet() {
            Ok(packet) => Ok(Some(packet.data.to_vec())),
            // A timed-out poll is "no frame yet", not an error — the capture task
            // loops on it to stay responsive to shutdown.
            Err(::pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(L4Error::Unavailable(format!("pcap next_packet: {e}"))),
        }
    }
}
