//! The `serve` message loop: handshake, scope, capture, inject (spec §5.2,
//! §5.3; plan P2.7).
//!
//! After [`serve::startup`](crate::serve) has dropped to `CAP_NET_RAW` and
//! connected to the core's socket, [`serve_loop`] owns the session. It reads
//! one message at a time with the shared [`read_msg`] and answers over the
//! same socket. Everything that touches the wire goes through a [`Wire`]: the
//! real one, [`PcapWire`], is libpcap plus a raw IP socket for local
//! destinations (spec amendment S1, spike S7); the unit tests substitute a
//! recording fake, so the loop's refusals are proven without a privilege.
//!
//! # What the loop refuses, and how
//!
//! The helper trusts nothing the core says about a packet (spec §5.3). It
//! holds its own [`HelperGuard`] from the last `ScopeSet` and runs the same
//! guard the core runs:
//!
//! - **`Inject`** before any `ScopeSet` is a protocol violation and ends the
//!   session (`inject before scope`). After one, the interface name is
//!   checked, then the loop refuses an interface no `Inject`-capability
//!   entry of the current scope covers before the wire is asked anything
//!   (on the real wire, asking for the link type opens a pcap handle), then
//!   [`HelperGuard::check_inject`] parses the frame and decides; a refusal is
//!   an `InjectResult { error }` with the parser's or guard's text verbatim
//!   (plan A8) and the wire is never touched.
//! - **`CaptureOpen`** gets the filter from [`HelperGuard::capture_filter`]
//!   (the helper's own scope, never a string from the core); an interface no
//!   `Capture` entry covers, a malformed name, a duplicate id or a wire that
//!   will not open is a `CaptureClosed { reason }` and no capture exists.
//!   `read_timeout_ms` is floored at [`MIN_READ_TIMEOUT_MS`] so a poll
//!   always returns and a `CaptureClose` always takes effect.
//! - **`ScopeSet`** governs captures already open too: one whose interface
//!   the new scope no longer covers is stopped and reported as
//!   `CaptureClosed { reason: "scope changed" }`.
//! - **Protocol violations** end the session with [`ServeExit::Protocol`]:
//!   anything but `Hello` first, a `proto` other than [`PROTO`] (no reply is
//!   sent, so the core reports `version_mismatch`), a second `Hello`, a
//!   helper→core type arriving here, or any [`ProtoError`] but a clean
//!   `Eof`, which is the core closing and ends the loop with `Ok(())`.
//!
//! # Interface names
//!
//! Before libpcap sees one, an interface name must be non-empty, at most
//! [`MAX_IFACE_LEN`] bytes (`IFNAMSIZ - 1`) and made only of ASCII letters,
//! digits, `.`, `_` and `-`. Anything else is refused with a reason that
//! does not echo the bytes.
//!
//! # Threads
//!
//! The loop blocks in `read_msg`, so each open capture runs on its own
//! thread that owns the [`CaptureSource`] and writes `Frame`s through the
//! shared, locked writer. `CaptureClose` sets that capture's stop flag,
//! which the thread checks between polls (each poll returns within the
//! capture's read timeout); on any loop exit every flag is set by a drop
//! guard. Threads are not joined: the process exits right after the loop.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aitm_proto_l4::backend::{CaptureSource, L4Error};
use aitm_proto_l4::guard::interface_covers;
use aitm_proto_l4::helper::enforce::HelperGuard;
use aitm_proto_l4::helper::frame::{inject_target, LinkType};
use aitm_proto_l4::helper::proto::{encode, read_msg, Msg, ProtoError, ScopeSet, MAX_FRAME, PROTO};
use aitm_proto_l4::types::L4Capability;

/// `IFNAMSIZ - 1`: the longest interface name Linux accepts.
const MAX_IFACE_LEN: usize = 15;

/// The reason a capture reports when the core asked for it to close.
const REASON_CLOSED: &str = "closed";

/// The reason a capture reports when a new `ScopeSet` no longer covers its
/// interface.
const REASON_SCOPE_CHANGED: &str = "scope changed";

/// The least read timeout a capture is opened with. The core's
/// `read_timeout_ms` is clamped up to this before the wire opens: libpcap
/// treats `0` as "block until a packet arrives", and a thread blocked there
/// never sees its stop flag, so a `CaptureClose` would never take effect.
pub const MIN_READ_TIMEOUT_MS: u32 = 100;

/// The system calls the loop needs, so the loop can be tested against a
/// recording fake. [`PcapWire`] is the real one.
pub trait Wire: Send + Sync {
    /// Open a live capture on `iface` with the helper-built BPF `filter`;
    /// each `next_frame` poll returns within `timeout`.
    ///
    /// # Errors
    /// The wire's own text; the loop passes it through as the
    /// `CaptureClosed` reason.
    fn open(
        &self,
        iface: &str,
        filter: Option<&str>,
        timeout: Duration,
    ) -> Result<Box<dyn CaptureSource + Send>, String>;

    /// Put a link-layer frame the guard already admitted on `iface`. `link`
    /// is the framing the loop resolved with [`Wire::link`] for this inject
    /// and checked the frame under, so the wire need not look it up again.
    ///
    /// # Errors
    /// The wire's own text; the loop passes it through as `InjectResult.error`.
    fn inject(&self, iface: &str, link: LinkType, bytes: &[u8]) -> Result<(), String>;

    /// The link framing `iface` carries, which an inject frame must match.
    fn link(&self, iface: &str) -> LinkType;
}

/// Why the loop ended other than by the core closing cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeExit {
    /// The core broke the protocol (spec §5.2): the text says how.
    Protocol(String),
    /// Writing to the core failed.
    Io(String),
}

impl fmt::Display for ServeExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeExit::Protocol(why) => write!(f, "protocol violation: {why}"),
            ServeExit::Io(why) => write!(f, "socket write failed: {why}"),
        }
    }
}

impl std::error::Error for ServeExit {}

/// The outgoing half of the socket, shared with the capture threads. Every
/// message is encoded whole and written under the lock, so the core never
/// sees two messages interleaved.
struct Outbound<W> {
    writer: Mutex<W>,
}

impl<W: Write> Outbound<W> {
    fn send(&self, msg: &Msg) -> Result<(), ServeExit> {
        let bytes = encode(msg);
        let mut w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        w.write_all(&bytes)
            .and_then(|()| w.flush())
            .map_err(|e| ServeExit::Io(e.to_string()))
    }
}

/// The scope the core last sent and the guard built from it. The guard
/// decides frames and filters; the entries answer the one question the guard
/// does not expose, whether any `Inject` entry covers an interface at all.
struct Scope {
    set: ScopeSet,
    guard: HelperGuard,
}

impl Scope {
    fn new(set: ScopeSet) -> Self {
        let guard = HelperGuard::from_scope_set(&set);
        Self { set, guard }
    }

    /// Whether at least one `Inject`-capability entry covers `iface`
    /// (exactly, or by the `*` wildcard).
    fn inject_covers(&self, iface: &str) -> bool {
        self.set
            .scope
            .iter()
            .any(|e| e.capability == L4Capability::Inject && interface_covers(e, iface))
    }
}

/// One open capture: the flag its thread polls and the interface it is on
/// (so a new scope can be checked against it).
struct CaptureEntry {
    stop: Arc<AtomicBool>,
    interface: String,
}

/// The open captures by id. Shared with the threads so a capture that ends
/// on its own removes itself; a thread only ever removes its own entry
/// ([`Captures::finish`] checks the flag's identity), so an id freed and
/// reused by the loop is never removed by the thread that lost it.
#[derive(Default)]
struct Captures {
    open: Mutex<HashMap<u64, CaptureEntry>>,
}

impl Captures {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, CaptureEntry>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register `id` on `interface` with a fresh stop flag; `None` when it is
    /// already open.
    fn insert(&self, id: u64, interface: &str) -> Option<Arc<AtomicBool>> {
        let mut open = self.lock();
        if open.contains_key(&id) {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        open.insert(
            id,
            CaptureEntry {
                stop: Arc::clone(&stop),
                interface: interface.to_string(),
            },
        );
        Some(stop)
    }

    /// Ask `id`'s thread to stop; it reports `closed` and removes itself.
    fn stop(&self, id: u64) {
        if let Some(entry) = self.lock().get(&id) {
            entry.stop.store(true, Ordering::Release);
        }
    }

    /// Forget `id` outright (an open or a thread start that failed, before
    /// any thread owns the entry).
    fn remove(&self, id: u64) {
        self.lock().remove(&id);
    }

    /// A thread ending: remove `id` only if the entry is still this
    /// thread's (`stop` is the flag it was given). Returns whether it was,
    /// i.e. whether the thread owes the core a `CaptureClosed`.
    fn finish(&self, id: u64, stop: &Arc<AtomicBool>) -> bool {
        let mut open = self.lock();
        match open.get(&id) {
            Some(entry) if Arc::ptr_eq(&entry.stop, stop) => {
                open.remove(&id);
                true
            }
            _ => false,
        }
    }

    /// Stop and forget every capture whose interface `guard` no longer
    /// covers; the ids, in ascending order, for the loop to report as
    /// `scope changed`. Their threads find their entry gone and stay silent.
    fn stop_uncovered(&self, guard: &HelperGuard) -> Vec<u64> {
        let mut open = self.lock();
        let mut gone: Vec<u64> = open
            .iter()
            .filter(|(_, entry)| guard.capture_filter(&entry.interface).is_err())
            .map(|(id, _)| *id)
            .collect();
        gone.sort_unstable();
        for id in &gone {
            if let Some(entry) = open.remove(id) {
                entry.stop.store(true, Ordering::Release);
            }
        }
        gone
    }

    fn stop_all(&self) {
        for entry in self.lock().values() {
            entry.stop.store(true, Ordering::Release);
        }
    }
}

/// Sets every capture's stop flag when the loop returns, on every path.
struct StopAll(Arc<Captures>);

impl Drop for StopAll {
    fn drop(&mut self) {
        self.0.stop_all();
    }
}

/// Run one helper session over the split halves of the core's socket.
///
/// `caps` is the helper's effective capability set as the caller read it
/// (on Linux, `/proc/self/status` after the drop); it is echoed in
/// `HelloAck.caps` as given, never replaced by a literal (spec §5.2, S3).
///
/// Returns `Ok(())` when the core closes the socket at a message boundary.
///
/// # Errors
/// [`ServeExit::Protocol`] on any protocol violation (see the module doc),
/// [`ServeExit::Io`] when a reply cannot be written.
pub fn serve_loop<R: Read, W: Write + Send + 'static>(
    mut reader: R,
    writer: W,
    wire: Arc<dyn Wire>,
    version: &str,
    caps: Vec<String>,
) -> Result<(), ServeExit> {
    let out = Arc::new(Outbound {
        writer: Mutex::new(writer),
    });
    let captures = Arc::new(Captures::default());
    let _stop_all = StopAll(Arc::clone(&captures));

    // Handshake: the first message is `Hello` or the session is over.
    match read_msg(&mut reader) {
        Ok(Msg::Hello { proto, .. }) if proto == PROTO => {}
        Ok(Msg::Hello { proto, .. }) => {
            return Err(ServeExit::Protocol(format!(
                "version mismatch: peer proto {proto}, helper proto {PROTO}"
            )));
        }
        Ok(other) => {
            return Err(ServeExit::Protocol(format!(
                "expected Hello first, got {}",
                msg_name(&other)
            )));
        }
        Err(ProtoError::Eof) => return Ok(()),
        Err(e) => return Err(ServeExit::Protocol(e.to_string())),
    }
    out.send(&Msg::HelloAck {
        proto: PROTO,
        helper_version: version.to_string(),
        caps,
    })?;

    let mut scope: Option<Scope> = None;
    loop {
        let msg = match read_msg(&mut reader) {
            Ok(msg) => msg,
            Err(ProtoError::Eof) => return Ok(()),
            Err(e) => return Err(ServeExit::Protocol(e.to_string())),
        };
        match msg {
            Msg::ScopeSet(s) => {
                let next = Scope::new(s);
                // The new scope governs the captures already open: one on an
                // interface it no longer covers closes now (SEC-M4). The new
                // guard's rate buckets start fresh, so an inject budget the
                // old scope had spent is not carried over: accepted (spec S3),
                // since the core's own guard meters independently anyway.
                for id in captures.stop_uncovered(&next.guard) {
                    out.send(&Msg::CaptureClosed {
                        capture_id: id,
                        reason: REASON_SCOPE_CHANGED.to_string(),
                    })?;
                }
                scope = Some(next);
            }
            Msg::CaptureOpen {
                id,
                interface,
                direction: _,
                read_timeout_ms,
            } => {
                let timeout =
                    Duration::from_millis(u64::from(read_timeout_ms.max(MIN_READ_TIMEOUT_MS)));
                let guard = scope.as_ref().map(|s| &s.guard);
                match open_capture(guard, &*wire, &captures, id, &interface, timeout) {
                    Ok((source, stop)) => {
                        if let Err(e) =
                            spawn_capture(id, source, stop, Arc::clone(&out), Arc::clone(&captures))
                        {
                            // No thread owns the entry; free the id and say why.
                            captures.remove(id);
                            out.send(&Msg::CaptureClosed {
                                capture_id: id,
                                reason: format!("capture thread could not start: {e}"),
                            })?;
                        }
                    }
                    Err(reason) => out.send(&Msg::CaptureClosed {
                        capture_id: id,
                        reason,
                    })?,
                }
            }
            Msg::CaptureClose { id } => captures.stop(id),
            Msg::Inject {
                request_id,
                interface,
                bytes,
            } => {
                let Some(scope) = scope.as_ref() else {
                    return Err(ServeExit::Protocol("inject before scope".to_string()));
                };
                let error = inject(scope, &*wire, &interface, &bytes).err();
                out.send(&Msg::InjectResult { request_id, error })?;
            }
            other @ (Msg::Hello { .. }
            | Msg::HelloAck { .. }
            | Msg::Frame { .. }
            | Msg::CaptureClosed { .. }
            | Msg::InjectResult { .. }) => {
                return Err(ServeExit::Protocol(format!(
                    "unexpected {} after the handshake",
                    msg_name(&other)
                )));
            }
        }
    }
}

/// Decide and open one capture, returning the source and its stop flag;
/// `Err` is the `CaptureClosed` reason and means nothing was opened. Each
/// check runs before the next: scope present, interface name, scope coverage
/// and filter, duplicate id, then the wire.
fn open_capture(
    guard: Option<&HelperGuard>,
    wire: &dyn Wire,
    captures: &Captures,
    id: u64,
    interface: &str,
    timeout: Duration,
) -> Result<(Box<dyn CaptureSource + Send>, Arc<AtomicBool>), String> {
    let guard = guard.ok_or_else(|| "capture before scope: no scope set yet".to_string())?;
    check_interface_name(interface)?;
    let filter = guard.capture_filter(interface)?;
    let stop = captures
        .insert(id, interface)
        .ok_or_else(|| format!("capture {id} is already open"))?;
    match wire.open(interface, filter.as_deref(), timeout) {
        Ok(source) => Ok((source, stop)),
        Err(e) => {
            // An open that fails frees the id again.
            captures.remove(id);
            Err(e)
        }
    }
}

/// Decide one inject; `Err` is the `InjectResult.error` text and means the
/// wire was not touched. Interface name first; then whether any `Inject`
/// entry of the scope covers the interface at all, before the wire is asked
/// for its link type (on the real wire that opens a pcap handle; SEC-M2);
/// then the helper's own guard over the frame's bytes (plan A8: the parser's
/// text passes through); then the wire.
fn inject(scope: &Scope, wire: &dyn Wire, interface: &str, bytes: &[u8]) -> Result<(), String> {
    check_interface_name(interface)?;
    if !scope.inject_covers(interface) {
        return Err(format!("interface {interface} is out of L4 inject scope"));
    }
    let link = wire.link(interface);
    scope.guard.check_inject(interface, link, bytes)?;
    wire.inject(interface, link, bytes)
}

/// Stream frames from `source` on a thread of its own until the source fails
/// or the capture's flag is set. The thread reports `CaptureClosed` only
/// while the entry is still its own ([`Captures::finish`]); a capture the
/// loop already closed for a scope change stays silent.
///
/// # Errors
/// The thread could not be started (`EAGAIN` and the like); nothing runs
/// and the caller frees the id.
fn spawn_capture<W: Write + Send + 'static>(
    id: u64,
    mut source: Box<dyn CaptureSource + Send>,
    stop: Arc<AtomicBool>,
    out: Arc<Outbound<W>>,
    captures: Arc<Captures>,
) -> std::io::Result<()> {
    thread::Builder::new()
        .name(format!("capture-{id}"))
        .spawn(move || {
            let reason = loop {
                if stop.load(Ordering::Acquire) {
                    break REASON_CLOSED.to_string();
                }
                match source.next_frame() {
                    Ok(Some(bytes)) => {
                        let frame = Msg::Frame {
                            capture_id: id,
                            ts_us: now_us(),
                            bytes,
                        };
                        if out.send(&frame).is_err() {
                            // The core is gone; the main loop will see it too.
                            captures.finish(id, &stop);
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => break e.to_string(),
                }
            };
            if captures.finish(id, &stop) {
                // A failed write here has nowhere to be reported; the loop
                // exits on its own next read or write.
                let _ = out.send(&Msg::CaptureClosed {
                    capture_id: id,
                    reason,
                });
            }
        })
        .map(|_handle| ())
}

/// The name of a message's variant, for protocol-violation texts.
fn msg_name(msg: &Msg) -> &'static str {
    match msg {
        Msg::Hello { .. } => "Hello",
        Msg::HelloAck { .. } => "HelloAck",
        Msg::ScopeSet(_) => "ScopeSet",
        Msg::CaptureOpen { .. } => "CaptureOpen",
        Msg::CaptureClose { .. } => "CaptureClose",
        Msg::Frame { .. } => "Frame",
        Msg::CaptureClosed { .. } => "CaptureClosed",
        Msg::Inject { .. } => "Inject",
        Msg::InjectResult { .. } => "InjectResult",
    }
}

/// A sane device name, before libpcap sees it: non-empty, at most
/// [`MAX_IFACE_LEN`] bytes, only `[A-Za-z0-9._-]`. The reason never echoes
/// the peer's bytes.
fn check_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("interface name is empty".to_string());
    }
    if name.len() > MAX_IFACE_LEN {
        return Err(format!(
            "interface name of {} bytes exceeds {MAX_IFACE_LEN}",
            name.len()
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("interface name contains a character outside [A-Za-z0-9._-]".to_string());
    }
    Ok(())
}

/// Microseconds since the Unix epoch at frame receipt (the [`CaptureSource`]
/// trait carries no timestamp); `0` on a clock before 1970, never a panic.
fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
        })
}

// ---- the real wire ----------------------------------------------------------

/// `IPPROTO_RAW`: a raw IP socket whose caller supplies the IP header
/// (`IP_HDRINCL` is implied on Linux and set explicitly anyway).
const IPPROTO_RAW: i32 = 255;

/// The production [`Wire`]: libpcap for capture, link-type lookup and L2
/// inject on a real interface, and on Linux a raw IP socket for a frame
/// whose destination is a loopback address (spec S1: `pcap_inject` of an L2
/// frame on `lo` is a martian under default sysctls; `IPPROTO_RAW` with
/// `IP_HDRINCL` is routed and delivered, and needs only `CAP_NET_RAW`).
///
/// Stateless, like the core's `PcapBackend`: a fresh handle per call. The
/// FFI in `pcap` and `socket2` stays inside those crates; this crate keeps
/// the workspace forbid lint (see `main.rs`).
// TODO(p1b/p1a follow-up): wrap PcapBackend once CaptureInjectBackend returns
// Box<dyn CaptureSource + Send> (QP2-M2: `open`, `sendpacket` and the
// TimeoutExpired adapter below duplicate it only because of the missing
// `Send` bound and the `L4Error` type).
#[derive(Debug, Clone, Copy, Default)]
pub struct PcapWire;

impl Wire for PcapWire {
    fn open(
        &self,
        iface: &str,
        filter: Option<&str>,
        timeout: Duration,
    ) -> Result<Box<dyn CaptureSource + Send>, String> {
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut cap = pcap::Capture::from_device(iface)
            .and_then(|c| c.promisc(true).timeout(timeout_ms).open())
            .map_err(|e| format!("pcap open: {e}"))?;
        if let Some(bpf) = filter {
            cap.filter(bpf, true)
                .map_err(|e| format!("pcap filter: {e}"))?;
        }
        Ok(Box::new(PcapSource { cap }))
    }

    /// One handle at most: the loop already resolved `link`, so the frame is
    /// decoded under it here without opening the interface again, and the
    /// raw-IP path opens no pcap handle at all.
    fn inject(&self, iface: &str, link: LinkType, bytes: &[u8]) -> Result<(), String> {
        // The guard already admitted this frame; this decode only picks the
        // path, and refuses again rather than guess if it cannot.
        let target = inject_target(iface, link, bytes, MAX_FRAME).map_err(|e| e.to_string())?;
        let dst = target
            .dst
            .ok_or_else(|| "inject frame names no destination".to_string())?;
        if dst.is_loopback() {
            #[cfg(target_os = "linux")]
            {
                return raw_ip_inject(dst, strip_link(link, bytes)?);
            }
        }
        pcap_inject(iface, bytes)
    }

    /// The datalink libpcap reports for `iface`. `DLT_NULL`/`DLT_LOOP` are
    /// [`LinkType::Null`]; `DLT_RAW`, `DLT_IPV4`, `DLT_IPV6` are
    /// [`LinkType::Raw`]; `DLT_EN10MB` and, conservatively, anything else
    /// (including an interface that will not open) is [`LinkType::Ethernet`]:
    /// a frame parsed under the wrong framing is refused as not IP, never
    /// admitted.
    fn link(&self, iface: &str) -> LinkType {
        let Ok(cap) = pcap::Capture::from_device(iface).and_then(pcap::Capture::open) else {
            return LinkType::Ethernet;
        };
        match cap.get_datalink() {
            pcap::Linktype::NULL | pcap::Linktype::LOOP => LinkType::Null,
            pcap::Linktype::RAW | pcap::Linktype::IPV4 | pcap::Linktype::IPV6 => LinkType::Raw,
            _ => LinkType::Ethernet,
        }
    }
}

/// L2 inject through libpcap, as the core's `PcapBackend::inject` does.
fn pcap_inject(iface: &str, bytes: &[u8]) -> Result<(), String> {
    let mut cap = pcap::Capture::from_device(iface)
        .and_then(pcap::Capture::open)
        .map_err(|e| format!("pcap open: {e}"))?;
    cap.sendpacket(bytes)
        .map_err(|e| format!("pcap sendpacket: {e}"))
}

/// The IP packet behind the link header: 4 bytes for `DLT_NULL`, 14 for
/// Ethernet, none for raw.
fn strip_link(link: LinkType, bytes: &[u8]) -> Result<&[u8], String> {
    let header = match link {
        LinkType::Null => 4,
        LinkType::Ethernet => 14,
        LinkType::Raw => 0,
    };
    bytes
        .get(header..)
        .ok_or_else(|| "inject frame is truncated".to_string())
}

/// Send an IP packet (header included) to a local destination through a raw
/// IP socket (spec S1, plan A6). Compiled on every platform so it is checked
/// here; only the Linux build calls it (spike S8 covers macOS loopback), and
/// off Linux the module-level `allow(dead_code)` in `main.rs` covers it.
fn raw_ip_inject(dst: std::net::IpAddr, packet: &[u8]) -> Result<(), String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};

    let (socket, addr) = match dst {
        IpAddr::V4(v4) => {
            let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                .map_err(|e| format!("raw socket: {e}"))?;
            socket
                .set_header_included_v4(true)
                .map_err(|e| format!("raw socket IP_HDRINCL: {e}"))?;
            (socket, SockAddr::from(SocketAddrV4::new(v4, 0)))
        }
        IpAddr::V6(v6) => {
            let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
                .map_err(|e| format!("raw socket: {e}"))?;
            socket
                .set_header_included_v6(true)
                .map_err(|e| format!("raw socket IPV6_HDRINCL: {e}"))?;
            (socket, SockAddr::from(SocketAddrV6::new(v6, 0, 0, 0)))
        }
    };
    let sent = socket
        .send_to(packet, &addr)
        .map_err(|e| format!("raw socket send: {e}"))?;
    if sent != packet.len() {
        return Err(format!("raw socket sent {sent} of {} bytes", packet.len()));
    }
    Ok(())
}

/// A live pcap capture adapted to [`CaptureSource`], as the core's backend
/// does: a timed-out poll is `Ok(None)`, anything else fails closed.
struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
}

impl CaptureSource for PcapSource {
    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
        match self.cap.next_packet() {
            Ok(packet) => Ok(Some(packet.data.to_vec())),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(L4Error::Unavailable(format!("pcap next_packet: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::Ipv4Addr;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use aitm_proto_l4::backend::{CaptureSource, L4Error};
    use aitm_proto_l4::craft::{EtherSpec, Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use aitm_proto_l4::helper::enforce::HelperGuard;
    use aitm_proto_l4::helper::frame::LinkType;
    use aitm_proto_l4::helper::proto::{
        encode, read_msg, Msg, ProtoError, ScopeSet, MAX_FRAME, PROTO,
    };
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };

    use super::{serve_loop, ServeExit, Wire};

    /// The helper version every test hands the loop.
    const VERSION: &str = "0.5.9";
    /// The inject ceiling the `ScopeSet` below carries.
    const MAX_PACKET_BYTES: usize = 1500;

    // ---- scope and frames (the same shapes as `enforce::tests`) ----------

    fn entry(interface: &str, cap: L4Capability, pps: u32) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: Ipv4Addr::LOCALHOST.into(),
                prefix: 32,
            },
            ports: PortRange { lo: 9000, hi: 9999 },
            interface: interface.to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap { pps, burst: pps },
            source: L4ScopeSource::Config,
        }
    }

    /// `lo`, 127.0.0.1/32, 9000-9999, one Capture and one Inject entry.
    fn scope_set() -> ScopeSet {
        scope_set_on("lo")
    }

    fn scope_set_on(interface: &str) -> ScopeSet {
        ScopeSet {
            scope: vec![
                entry(interface, L4Capability::Capture, 10),
                entry(interface, L4Capability::Inject, 10),
            ],
            global_inject_pps: 100,
            max_packet_bytes: MAX_PACKET_BYTES,
            max_packets_per_call: 8,
            self_ports: Vec::new(),
        }
    }

    /// An Ethernet IPv4/UDP frame 127.0.0.1:40000 → 127.0.0.1:`dst_port`.
    fn eth_udp(dst_port: u16) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40_000),
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    fn hello() -> Msg {
        Msg::Hello {
            proto: PROTO,
            core_version: VERSION.to_string(),
        }
    }

    fn capture_open(id: u64, interface: &str) -> Msg {
        Msg::CaptureOpen {
            id,
            interface: interface.to_string(),
            direction: L4Direction::Outbound,
            read_timeout_ms: 250,
        }
    }

    fn inject(request_id: u64, interface: &str, bytes: Vec<u8>) -> Msg {
        Msg::Inject {
            request_id,
            interface: interface.to_string(),
            bytes,
        }
    }

    // ---- the in-memory duplex ---------------------------------------------

    /// The helper's outgoing half: every test decodes it afterwards.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedBuf {
        /// Every message written so far, decoded with the real `read_msg`.
        fn messages(&self) -> Vec<Msg> {
            let bytes = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let mut cur = Cursor::new(bytes);
            let mut out = Vec::new();
            loop {
                match read_msg(&mut cur) {
                    Ok(m) => out.push(m),
                    Err(ProtoError::Eof) => return out,
                    Err(e) => panic!("helper wrote a malformed message: {e}"),
                }
            }
        }

        /// Poll until `pred` holds over the decoded output, or fail after 5 s.
        fn wait_until(&self, what: &str, pred: impl Fn(&[Msg]) -> bool) -> Vec<Msg> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let msgs = self.messages();
                if pred(&msgs) {
                    return msgs;
                }
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for {what}: {msgs:?}"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A reader the test feeds one encoded message at a time; dropping the
    /// sender is the core closing the socket.
    struct ChanReader {
        rx: Receiver<Vec<u8>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl ChanReader {
        fn new() -> (Sender<Vec<u8>>, Self) {
            let (tx, rx) = channel();
            (
                tx,
                Self {
                    rx,
                    buf: Vec::new(),
                    pos: 0,
                },
            )
        }
    }

    impl Read for ChanReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos == self.buf.len() {
                match self.rx.recv() {
                    Ok(next) => {
                        self.buf = next;
                        self.pos = 0;
                    }
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.buf.len() - self.pos);
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    // ---- the recording fake wire ------------------------------------------

    /// A capture that yields its scripted frames once, then `Ok(None)` forever.
    struct ScriptedSource {
        frames: std::vec::IntoIter<Vec<u8>>,
    }

    impl CaptureSource for ScriptedSource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            match self.frames.next() {
                Some(f) => Ok(Some(f)),
                None => {
                    thread::sleep(Duration::from_millis(2));
                    Ok(None)
                }
            }
        }
    }

    #[derive(Default)]
    struct FakeWire {
        /// `(interface, filter, timeout)` of every `open`.
        opens: Mutex<Vec<(String, Option<String>, Duration)>>,
        /// `(interface, bytes)` of every `inject`.
        injects: Mutex<Vec<(String, Vec<u8>)>>,
        /// The link type the loop handed each `inject` (the one it resolved
        /// with `link`, so the real wire opens no second handle for it).
        inject_links: Mutex<Vec<LinkType>>,
        /// What the next scripted capture yields.
        frames: Mutex<Vec<Vec<u8>>>,
        /// Tester: frame lists for the opens after the first, in order.
        later_frames: Mutex<std::collections::VecDeque<Vec<Vec<u8>>>>,
        /// Tester: when set, every `open` is recorded, then fails with this.
        fail_open: Mutex<Option<String>>,
        /// Tester: when set, every `inject` is recorded, then fails with this.
        fail_inject: Mutex<Option<String>>,
        /// How many times the loop asked for an interface's link type (a real
        /// wire opens a pcap handle for that, so a refusal must come first).
        link_calls: Mutex<u32>,
    }

    impl FakeWire {
        fn with_frames(frames: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                frames: Mutex::new(frames),
                ..Self::default()
            })
        }
        /// Tester: one frame list per `open`, in order; later opens get none.
        fn with_scripted(lists: Vec<Vec<Vec<u8>>>) -> Arc<Self> {
            let mut lists = lists.into_iter();
            let first = lists.next().unwrap_or_default();
            Arc::new(Self {
                frames: Mutex::new(first),
                later_frames: Mutex::new(lists.collect()),
                ..Self::default()
            })
        }
        fn set_fail_open(&self, why: Option<&str>) {
            *self
                .fail_open
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = why.map(str::to_string);
        }
        fn set_fail_inject(&self, why: Option<&str>) {
            *self
                .fail_inject
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = why.map(str::to_string);
        }
        fn opens(&self) -> Vec<(String, Option<String>, Duration)> {
            self.opens
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
        fn injects(&self) -> Vec<(String, Vec<u8>)> {
            self.injects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
        fn link_calls(&self) -> u32 {
            *self
                .link_calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }
        fn inject_links(&self) -> Vec<LinkType> {
            self.inject_links
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl Wire for FakeWire {
        fn open(
            &self,
            iface: &str,
            filter: Option<&str>,
            timeout: Duration,
        ) -> Result<Box<dyn CaptureSource + Send>, String> {
            self.opens
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((iface.to_string(), filter.map(str::to_string), timeout));
            if let Some(why) = self
                .fail_open
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
            {
                return Err(why);
            }
            let frames = {
                let mut first = self.frames.lock().unwrap_or_else(PoisonError::into_inner);
                if first.is_empty() {
                    self.later_frames
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front()
                        .unwrap_or_default()
                } else {
                    std::mem::take(&mut *first)
                }
            };
            Ok(Box::new(ScriptedSource {
                frames: frames.into_iter(),
            }))
        }
        fn inject(&self, iface: &str, link: LinkType, bytes: &[u8]) -> Result<(), String> {
            self.injects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((iface.to_string(), bytes.to_vec()));
            self.inject_links
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(link);
            if let Some(why) = self
                .fail_inject
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
            {
                return Err(why);
            }
            Ok(())
        }
        fn link(&self, _iface: &str) -> LinkType {
            *self
                .link_calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner) += 1;
            LinkType::Ethernet
        }
    }

    /// Run the loop over pre-encoded `msgs` followed by a clean close.
    fn run(msgs: &[Msg], wire: Arc<FakeWire>) -> (Result<(), ServeExit>, Vec<Msg>) {
        let mut bytes = Vec::new();
        for m in msgs {
            bytes.extend(encode(m));
        }
        run_raw(bytes, wire)
    }

    fn run_raw(bytes: Vec<u8>, wire: Arc<FakeWire>) -> (Result<(), ServeExit>, Vec<Msg>) {
        let out = SharedBuf::default();
        let result = serve_loop(Cursor::new(bytes), out.clone(), wire, VERSION, caps());
        (result, out.messages())
    }

    /// The effective set a helper after the drop holds (what `main` reads
    /// from `/proc/self/status` on Linux); every test hands the loop this.
    fn caps() -> Vec<String> {
        vec!["CAP_NET_RAW".to_string()]
    }

    fn protocol_text(result: Result<(), ServeExit>) -> String {
        match result {
            Err(ServeExit::Protocol(text)) => text,
            other => panic!("expected a Protocol exit, got {other:?}"),
        }
    }

    // ---- tests --------------------------------------------------------------

    #[test]
    fn hello_gets_hello_ack_with_cap_net_raw() {
        let (result, out) = run(&[hello()], Arc::default());
        assert_eq!(result, Ok(()));
        assert_eq!(
            out,
            vec![Msg::HelloAck {
                proto: 1,
                helper_version: "0.5.9".to_string(),
                caps: vec!["CAP_NET_RAW".to_string()],
            }]
        );
    }

    #[test]
    fn proto_mismatch_exits_without_a_reply() {
        let (result, out) = run(
            &[Msg::Hello {
                proto: 2,
                core_version: VERSION.to_string(),
            }],
            Arc::default(),
        );
        assert_eq!(
            protocol_text(result),
            "version mismatch: peer proto 2, helper proto 1"
        );
        assert_eq!(out, Vec::<Msg>::new());
    }

    #[test]
    fn inject_out_of_scope_is_refused_before_the_wire() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                inject(41, "lo", eth_udp(8999)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        let Msg::InjectResult { request_id, error } = &out[1] else {
            panic!("expected an InjectResult, got {out:?}");
        };
        assert_eq!(*request_id, 41);
        let error = error.as_deref().expect("a refusal");
        assert!(error.contains("scope"), "{error}");
        assert_eq!(error, "target 127.0.0.1 is out of L4 scope");
        assert_eq!(wire.injects().len(), 0);
    }

    #[test]
    fn inject_in_scope_reaches_the_wire() {
        let wire: Arc<FakeWire> = Arc::default();
        let frame = eth_udp(9053);
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                inject(42, "lo", frame.clone()),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            out[1],
            Msg::InjectResult {
                request_id: 42,
                error: None
            }
        );
        assert_eq!(wire.injects(), vec![("lo".to_string(), frame)]);
        // The loop resolved the link once and handed that to `inject`
        // (QP2-M1: the real wire opens one handle, not three).
        assert_eq!(wire.link_calls(), 1);
        assert_eq!(wire.inject_links(), vec![LinkType::Ethernet]);
    }

    #[test]
    fn hello_ack_echoes_the_caps_it_is_given() {
        // SEC-M3 / SP-M1: `HelloAck.caps` is whatever `main` read as the
        // effective set, not a literal: an empty set is `[]`, two names come
        // back in the order given.
        for caps in [
            Vec::<String>::new(),
            vec!["CAP_NET_ADMIN".to_string(), "CAP_NET_RAW".to_string()],
        ] {
            let out = SharedBuf::default();
            let result = serve_loop(
                Cursor::new(encode(&hello())),
                out.clone(),
                Arc::new(FakeWire::default()) as Arc<dyn Wire>,
                VERSION,
                caps.clone(),
            );
            assert_eq!(result, Ok(()));
            assert_eq!(
                out.messages(),
                vec![Msg::HelloAck {
                    proto: 1,
                    helper_version: "0.5.9".to_string(),
                    caps,
                }]
            );
        }
    }

    #[test]
    fn oversized_length_exits() {
        // A valid Hello, then a header declaring 262 145 bytes (MAX_FRAME + 1).
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&262_145u32.to_be_bytes());
        bytes.extend_from_slice(&[0x03; 64]);
        let (result, out) = run_raw(bytes, Arc::default());
        let text = protocol_text(result);
        assert!(text.contains("262145"), "{text}");
        // The handshake had already been answered; nothing else was.
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Msg::HelloAck { .. }));
    }

    #[test]
    fn inject_before_scope_exits() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[hello(), inject(1, "lo", eth_udp(9053))],
            Arc::clone(&wire),
        );
        assert_eq!(protocol_text(result), "inject before scope");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(wire.injects().len(), 0);
    }

    #[test]
    fn capture_open_outside_scope_is_refused() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[hello(), Msg::ScopeSet(scope_set()), capture_open(7, "eth9")],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            out[1],
            Msg::CaptureClosed {
                capture_id: 7,
                reason: "interface eth9 is outside the capture scope".to_string(),
            }
        );
        assert!(matches!(&out[1], Msg::CaptureClosed { reason, .. } if reason.contains("scope")));
        assert_eq!(wire.opens().len(), 0);
    }

    #[test]
    fn capture_open_before_scope_is_refused() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(&[hello(), capture_open(3, "lo")], Arc::clone(&wire));
        assert_eq!(result, Ok(()));
        assert!(
            matches!(&out[1], Msg::CaptureClosed { capture_id: 3, reason } if reason.contains("scope")),
            "{out:?}"
        );
        assert_eq!(wire.opens().len(), 0);
    }

    #[test]
    fn filter_is_helper_built() {
        let s = ScopeSet {
            self_ports: vec![27431],
            ..scope_set()
        };
        let expected = HelperGuard::from_scope_set(&s)
            .capture_filter("lo")
            .expect("lo is in scope");
        let wire: Arc<FakeWire> = Arc::default();
        let (result, _) = run(
            &[hello(), Msg::ScopeSet(s), capture_open(9, "lo")],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            wire.opens(),
            vec![(
                "lo".to_string(),
                expected.clone(),
                Duration::from_millis(250)
            )]
        );
        // The literal libpcap gets, not `None == None`.
        assert_eq!(
            expected,
            Some("(host 127.0.0.1 and portrange 9000-9999) and not port 27431".to_string())
        );
    }

    #[test]
    fn frames_stream_then_close() {
        let frame_a = eth_udp(9001);
        let frame_b = eth_udp(9002);
        let wire = FakeWire::with_frames(vec![frame_a.clone(), frame_b.clone()]);
        let out = SharedBuf::default();
        let (tx, reader) = ChanReader::new();
        let loop_out = out.clone();
        let loop_wire: Arc<dyn Wire> = Arc::clone(&wire) as Arc<dyn Wire>;
        let handle =
            thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION, caps()));

        for m in [hello(), Msg::ScopeSet(scope_set()), capture_open(5, "lo")] {
            tx.send(encode(&m)).expect("loop is reading");
        }
        out.wait_until("two frames", |msgs| {
            msgs.iter()
                .filter(|m| matches!(m, Msg::Frame { .. }))
                .count()
                == 2
        });
        tx.send(encode(&Msg::CaptureClose { id: 5 }))
            .expect("loop is reading");
        let msgs = out.wait_until("CaptureClosed", |msgs| {
            msgs.iter().any(|m| matches!(m, Msg::CaptureClosed { .. }))
        });
        drop(tx);
        assert_eq!(handle.join().expect("loop thread"), Ok(()));

        let frames: Vec<(u64, Vec<u8>)> = msgs
            .iter()
            .filter_map(|m| match m {
                Msg::Frame {
                    capture_id, bytes, ..
                } => Some((*capture_id, bytes.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(frames, vec![(5, frame_a), (5, frame_b)]);
        let closed: Vec<&Msg> = msgs
            .iter()
            .filter(|m| matches!(m, Msg::CaptureClosed { .. }))
            .collect();
        assert_eq!(
            closed,
            vec![&Msg::CaptureClosed {
                capture_id: 5,
                reason: "closed".to_string()
            }]
        );
        assert_eq!(wire.opens().len(), 1);
    }

    #[test]
    fn helper_to_core_type_is_a_protocol_violation() {
        for (name, bad) in [
            (
                "HelloAck",
                Msg::HelloAck {
                    proto: PROTO,
                    helper_version: VERSION.to_string(),
                    caps: Vec::new(),
                },
            ),
            (
                "Frame",
                Msg::Frame {
                    capture_id: 1,
                    ts_us: 2,
                    bytes: vec![0; 4],
                },
            ),
            (
                "CaptureClosed",
                Msg::CaptureClosed {
                    capture_id: 1,
                    reason: "x".to_string(),
                },
            ),
            (
                "InjectResult",
                Msg::InjectResult {
                    request_id: 1,
                    error: None,
                },
            ),
        ] {
            let (result, out) = run(&[hello(), bad], Arc::default());
            let text = protocol_text(result);
            assert!(text.contains(name), "{name}: {text}");
            assert_eq!(out.len(), 1, "{name}: only the HelloAck");
        }
        // A second Hello is one too.
        let (result, _) = run(&[hello(), hello()], Arc::default());
        assert!(protocol_text(result).contains("Hello"));
        // And anything but Hello first.
        let (result, out) = run(&[Msg::ScopeSet(scope_set())], Arc::default());
        assert!(protocol_text(result).contains("Hello"));
        assert_eq!(out, Vec::<Msg>::new());
    }

    #[test]
    fn bad_interface_name_is_refused_before_the_wire() {
        // A wildcard scope would admit any interface name, so the refusal
        // below can only come from the name check.
        for bad in ["lo;rm", "abcdefghijklmnop", "", "eth0/1", "lo rm"] {
            let wire: Arc<FakeWire> = Arc::default();
            let (result, out) = run(
                &[
                    hello(),
                    Msg::ScopeSet(scope_set_on("*")),
                    capture_open(11, bad),
                    inject(12, bad, eth_udp(9053)),
                ],
                Arc::clone(&wire),
            );
            assert_eq!(result, Ok(()), "{bad:?}");
            assert!(
                matches!(&out[1], Msg::CaptureClosed { capture_id: 11, reason } if reason.contains("interface name")),
                "{bad:?}: {out:?}"
            );
            assert!(
                matches!(&out[2], Msg::InjectResult { request_id: 12, error: Some(e) } if e.contains("interface name")),
                "{bad:?}: {out:?}"
            );
            assert_eq!(wire.opens().len(), 0, "{bad:?}");
            assert_eq!(wire.injects().len(), 0, "{bad:?}");
        }
        // The 15-byte maximum itself, with every allowed character class, passes
        // the name check and reaches the wire.
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set_on("*")),
                inject(13, "br-1.2_abcdefgh", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            out[1],
            Msg::InjectResult {
                request_id: 13,
                error: None
            }
        );
        assert_eq!(wire.injects().len(), 1);
    }

    /// Plan amendments A1 and A10: an inject whose destination is a loopback
    /// address goes through the raw IP socket (spec S1) and reaches a UDP
    /// socket under the default sysctls (`route_localnet=0`), where
    /// `pcap_inject` of an L2 frame on `lo` is dropped as a martian. Needs
    /// `CAP_NET_RAW` on `lo`, so it is ignored by default; P2.8 runs it on
    /// the linux-ci rig with `cargo test -p aitm-l4-helper -- --ignored`.
    /// Written against the same `craft` shapes as `eth_udp` above; it cannot
    /// compile on macOS (plan A5) and first compiles on the rig.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs CAP_NET_RAW on lo; P2.8 runs it with --ignored on the linux-ci rig"]
    fn linux_loopback_inject_reaches_a_udp_socket_with_default_sysctls() {
        use super::PcapWire;
        use std::net::{IpAddr, UdpSocket};

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket on loopback");
        let port = socket.local_addr().expect("local address").port();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");

        // The same Ethernet/IPv4/UDP frame the loop tests use, aimed at the
        // bound port: 127.0.0.1:40000 -> 127.0.0.1:port, payload "probe".
        let frame = eth_udp(port);
        PcapWire
            .inject("lo", LinkType::Ethernet, &frame)
            .expect("raw IP inject of a loopback-bound frame");

        let mut buf = [0u8; 64];
        let (n, from) = socket
            .recv_from(&mut buf)
            .expect("the injected datagram arrives within 2 s");
        assert_eq!(&buf[..n], b"probe");
        assert_eq!(from.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(from.port(), 40_000);
    }

    // ---- Tester edge cases (stage 5, unit p2) ------------------------------

    /// A writer whose first `ok_left` writes succeed and every later one
    /// fails as a socket whose peer vanished.
    struct FlakyWriter {
        ok_left: usize,
    }

    impl Write for FlakyWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.ok_left == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "peer gone",
                ));
            }
            self.ok_left -= 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn inject_results(msgs: &[Msg]) -> Vec<(u64, Option<String>)> {
        msgs.iter()
            .filter_map(|m| match m {
                Msg::InjectResult { request_id, error } => Some((*request_id, error.clone())),
                _ => None,
            })
            .collect()
    }

    fn frames_of(id: u64, msgs: &[Msg]) -> Vec<Vec<u8>> {
        msgs.iter()
            .filter_map(|m| match m {
                Msg::Frame {
                    capture_id, bytes, ..
                } if *capture_id == id => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn tester_two_captures_stream_independently_and_closing_one_leaves_the_other() {
        let a1 = eth_udp(9001);
        let a2 = eth_udp(9002);
        let b1 = eth_udp(9011);
        let wire = FakeWire::with_scripted(vec![vec![a1.clone(), a2.clone()], vec![b1.clone()]]);
        let out = SharedBuf::default();
        let (tx, reader) = ChanReader::new();
        let loop_out = out.clone();
        let loop_wire: Arc<dyn Wire> = Arc::clone(&wire) as Arc<dyn Wire>;
        let handle =
            thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION, caps()));

        for m in [
            hello(),
            Msg::ScopeSet(scope_set()),
            capture_open(5, "lo"),
            capture_open(6, "lo"),
        ] {
            tx.send(encode(&m)).expect("loop is reading");
        }
        let msgs = out.wait_until("three frames", |msgs| {
            msgs.iter()
                .filter(|m| matches!(m, Msg::Frame { .. }))
                .count()
                == 3
        });
        assert_eq!(frames_of(5, &msgs), vec![a1, a2]);
        assert_eq!(frames_of(6, &msgs), vec![b1]);
        assert_eq!(wire.opens().len(), 2);

        // Close 5 only.
        tx.send(encode(&Msg::CaptureClose { id: 5 }))
            .expect("loop is reading");
        let msgs = out.wait_until("CaptureClosed 5", |msgs| {
            msgs.iter()
                .any(|m| matches!(m, Msg::CaptureClosed { capture_id: 5, .. }))
        });
        assert!(msgs.contains(&Msg::CaptureClosed {
            capture_id: 5,
            reason: "closed".to_string()
        }));
        // 6 is still open: it has not closed, re-opening 6 is a duplicate,
        // and id 5 is free again.
        thread::sleep(Duration::from_millis(50));
        assert!(
            !out.messages()
                .iter()
                .any(|m| matches!(m, Msg::CaptureClosed { capture_id: 6, .. })),
            "{:?}",
            out.messages()
        );
        tx.send(encode(&capture_open(6, "lo")))
            .expect("loop is reading");
        out.wait_until("duplicate refusal", |msgs| {
            msgs.contains(&Msg::CaptureClosed {
                capture_id: 6,
                reason: "capture 6 is already open".to_string(),
            })
        });
        assert_eq!(
            wire.opens().len(),
            2,
            "the duplicate never reached the wire"
        );
        tx.send(encode(&capture_open(5, "lo")))
            .expect("loop is reading");
        out.wait_until("third open", |_| wire.opens().len() == 3);

        // The core closes: the loop returns Ok and every remaining capture
        // is stopped and reports "closed".
        drop(tx);
        assert_eq!(handle.join().expect("loop thread"), Ok(()));
        out.wait_until("both remaining captures closed", |msgs| {
            msgs.iter()
                .filter(|m| matches!(m, Msg::CaptureClosed { reason, .. } if reason == "closed"))
                .count()
                == 3
        });
    }

    #[test]
    fn tester_capture_close_for_an_unknown_id_is_ignored_and_the_session_continues() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::CaptureClose { id: 99 },
                Msg::ScopeSet(scope_set()),
                Msg::CaptureClose { id: u64::MAX },
                Msg::CaptureClose { id: 0 },
                inject(1, "lo", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(
            out[1],
            Msg::InjectResult {
                request_id: 1,
                error: None
            }
        );
        assert_eq!(wire.injects().len(), 1);
    }

    #[test]
    fn tester_inject_on_an_interface_the_scope_does_not_cover_is_refused_before_the_wire() {
        // The scope covers `lo` only and the frame is in range: a valid name
        // on another interface is refused by the loop's own scope pre-check
        // (SEC-M2) before the wire is asked for the link type, which on the
        // real wire opens a pcap handle. Only the admitted inject asks.
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                inject(21, "eth0", eth_udp(9053)),
                inject(22, "lo0", eth_udp(9053)),
                inject(23, "lo", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            inject_results(&out),
            vec![
                (
                    21,
                    Some("interface eth0 is out of L4 inject scope".to_string())
                ),
                (
                    22,
                    Some("interface lo0 is out of L4 inject scope".to_string())
                ),
                (23, None),
            ]
        );
        assert_eq!(wire.injects(), vec![("lo".to_string(), eth_udp(9053))]);
        assert_eq!(wire.link_calls(), 1, "only the admitted inject asked");
    }

    #[test]
    fn read_timeout_is_floored_at_100_ms_before_the_wire_opens() {
        // Tester F5 / QP2-M4: `read_timeout_ms: 0` would be `pcap timeout(0)`,
        // a poll that never returns, so a CaptureClose could never take
        // effect. The loop clamps to MIN_READ_TIMEOUT_MS before `open`; a
        // value at or above it passes through unchanged.
        let open = |id: u64, read_timeout_ms: u32| Msg::CaptureOpen {
            id,
            interface: "lo".to_string(),
            direction: L4Direction::Outbound,
            read_timeout_ms,
        };
        let wire: Arc<FakeWire> = Arc::default();
        let (result, _) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                open(1, 0),
                open(2, 250),
                open(3, 99),
                open(4, 100),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        let timeouts: Vec<Duration> = wire.opens().into_iter().map(|(_, _, t)| t).collect();
        assert_eq!(
            timeouts,
            vec![
                Duration::from_millis(100),
                Duration::from_millis(250),
                Duration::from_millis(100),
                Duration::from_millis(100),
            ]
        );
    }

    #[test]
    fn scope_change_closes_a_capture_the_new_scope_no_longer_covers() {
        // SEC-M4: a new ScopeSet governs captures already open, not only new
        // ones. A capture on `lo` is stopped with reason "scope changed" when
        // the scope moves to `eth0`; its thread adds no second CaptureClosed;
        // a fresh CaptureOpen on `lo` is refused by the new scope; the id is
        // free again.
        let wire: Arc<FakeWire> = Arc::default();
        let out = SharedBuf::default();
        let (tx, reader) = ChanReader::new();
        let loop_out = out.clone();
        let loop_wire: Arc<dyn Wire> = Arc::clone(&wire) as Arc<dyn Wire>;
        let handle =
            thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION, caps()));

        for m in [hello(), Msg::ScopeSet(scope_set()), capture_open(5, "lo")] {
            tx.send(encode(&m)).expect("loop is reading");
        }
        out.wait_until("first open", |_| wire.opens().len() == 1);

        tx.send(encode(&Msg::ScopeSet(scope_set_on("eth0"))))
            .expect("loop is reading");
        out.wait_until("scope changed", |msgs| {
            msgs.contains(&Msg::CaptureClosed {
                capture_id: 5,
                reason: "scope changed".to_string(),
            })
        });

        tx.send(encode(&capture_open(6, "lo")))
            .expect("loop is reading");
        out.wait_until("refusal under the new scope", |msgs| {
            msgs.contains(&Msg::CaptureClosed {
                capture_id: 6,
                reason: "interface lo is outside the capture scope".to_string(),
            })
        });
        assert_eq!(
            wire.opens().len(),
            1,
            "the refused open never reached the wire"
        );

        // The stopped thread must not add a "closed" of its own.
        thread::sleep(Duration::from_millis(50));
        let closed_5: Vec<String> = out
            .messages()
            .iter()
            .filter_map(|m| match m {
                Msg::CaptureClosed {
                    capture_id: 5,
                    reason,
                } => Some(reason.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(closed_5, vec!["scope changed".to_string()]);

        // Id 5 is free again on an interface the new scope covers.
        tx.send(encode(&capture_open(5, "eth0")))
            .expect("loop is reading");
        out.wait_until("re-open on eth0", |_| wire.opens().len() == 2);
        assert_eq!(wire.opens()[1].0, "eth0");

        drop(tx);
        assert_eq!(handle.join().expect("loop thread"), Ok(()));
    }

    #[test]
    fn scope_change_keeps_a_capture_the_new_scope_still_covers() {
        // The counterpart: a new scope that still covers the interface leaves
        // the capture alone (no CaptureClosed until the session ends).
        let wire: Arc<FakeWire> = Arc::default();
        let out = SharedBuf::default();
        let (tx, reader) = ChanReader::new();
        let loop_out = out.clone();
        let loop_wire: Arc<dyn Wire> = Arc::clone(&wire) as Arc<dyn Wire>;
        let handle =
            thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION, caps()));

        for m in [hello(), Msg::ScopeSet(scope_set()), capture_open(5, "lo")] {
            tx.send(encode(&m)).expect("loop is reading");
        }
        out.wait_until("first open", |_| wire.opens().len() == 1);
        let wider = ScopeSet {
            scope: vec![
                entry("eth0", L4Capability::Capture, 10),
                entry("lo", L4Capability::Capture, 10),
            ],
            ..scope_set()
        };
        tx.send(encode(&Msg::ScopeSet(wider)))
            .expect("loop is reading");
        // Something the loop answers, so we know the ScopeSet was processed.
        tx.send(encode(&inject(1, "lo", eth_udp(9053))))
            .expect("loop is reading");
        let msgs = out.wait_until("inject answered", |msgs| !inject_results(msgs).is_empty());
        assert!(
            !msgs.iter().any(|m| matches!(m, Msg::CaptureClosed { .. })),
            "{msgs:?}"
        );
        drop(tx);
        assert_eq!(handle.join().expect("loop thread"), Ok(()));
        let msgs = out.wait_until("closed at session end", |msgs| {
            msgs.iter().any(|m| matches!(m, Msg::CaptureClosed { .. }))
        });
        let closed: Vec<&Msg> = msgs
            .iter()
            .filter(|m| matches!(m, Msg::CaptureClosed { .. }))
            .collect();
        assert_eq!(
            closed,
            vec![&Msg::CaptureClosed {
                capture_id: 5,
                reason: "closed".to_string()
            }]
        );
    }

    #[test]
    fn tester_a_second_scope_set_narrows_what_an_earlier_one_allowed() {
        let wire: Arc<FakeWire> = Arc::default();
        let narrow = ScopeSet {
            scope: vec![
                entry("lo", L4Capability::Capture, 10),
                L4ScopeEntry {
                    ports: PortRange { lo: 9100, hi: 9999 },
                    ..entry("lo", L4Capability::Inject, 10)
                },
            ],
            ..scope_set()
        };
        let empty = ScopeSet {
            scope: Vec::new(),
            ..scope_set()
        };
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                inject(31, "lo", eth_udp(9053)),
                Msg::ScopeSet(narrow),
                inject(32, "lo", eth_udp(9053)),
                inject(33, "lo", eth_udp(9150)),
                Msg::ScopeSet(empty),
                inject(34, "lo", eth_udp(9150)),
                capture_open(35, "lo"),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            inject_results(&out),
            vec![
                (31, None),
                // The Capture entry still covers 9053, so the guard names the
                // missing capability rather than the scope.
                (
                    32,
                    Some("scope matches but does not grant the Inject capability".to_string())
                ),
                (33, None),
                // The empty scope has no Inject entry for `lo`: the loop's
                // pre-check refuses before the wire is asked anything.
                (
                    34,
                    Some("interface lo is out of L4 inject scope".to_string())
                ),
            ]
        );
        assert_eq!(
            wire.link_calls(),
            3,
            "injects 31, 32 and 33 asked; 34 did not"
        );
        assert_eq!(wire.injects().len(), 2);
        // The empty scope governs captures too.
        assert!(out.contains(&Msg::CaptureClosed {
            capture_id: 35,
            reason: "interface lo is outside the capture scope".to_string(),
        }));
        assert_eq!(wire.opens().len(), 0);
    }

    #[test]
    fn tester_writer_failure_ends_the_loop_with_io() {
        // The very first write (the HelloAck) fails.
        let result = serve_loop(
            Cursor::new(encode(&hello())),
            FlakyWriter { ok_left: 0 },
            Arc::new(FakeWire::default()) as Arc<dyn Wire>,
            VERSION,
            caps(),
        );
        assert_eq!(result, Err(ServeExit::Io("peer gone".to_string())));
        assert_eq!(
            result.expect_err("io").to_string(),
            "socket write failed: peer gone"
        );
        // A later write fails (the first InjectResult): the inject itself
        // already happened, then the loop ends with Io instead of reading on.
        let wire: Arc<FakeWire> = Arc::default();
        let mut bytes = Vec::new();
        for m in [
            hello(),
            Msg::ScopeSet(scope_set()),
            inject(1, "lo", eth_udp(9053)),
            inject(2, "lo", eth_udp(9054)),
        ] {
            bytes.extend(encode(&m));
        }
        let result = serve_loop(
            Cursor::new(bytes),
            FlakyWriter { ok_left: 1 },
            Arc::clone(&wire) as Arc<dyn Wire>,
            VERSION,
            caps(),
        );
        assert_eq!(result, Err(ServeExit::Io("peer gone".to_string())));
        assert_eq!(wire.injects().len(), 1, "the second Inject was never read");
    }

    #[test]
    fn tester_second_hello_is_a_protocol_violation_with_the_literal_text() {
        let (result, out) = run(&[hello(), hello()], Arc::default());
        assert_eq!(
            protocol_text(result),
            "unexpected Hello after the handshake"
        );
        assert_eq!(out.len(), 1);
        // Even after a scope was set, and whatever proto it claims.
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                Msg::Hello {
                    proto: 2,
                    core_version: "x".to_string(),
                },
            ],
            Arc::default(),
        );
        assert_eq!(
            protocol_text(result),
            "unexpected Hello after the handshake"
        );
        assert_eq!(out.len(), 1);
        // The first-message texts name the message that arrived instead.
        let (result, out) = run(&[Msg::ScopeSet(scope_set())], Arc::default());
        assert_eq!(protocol_text(result), "expected Hello first, got ScopeSet");
        assert_eq!(out, Vec::<Msg>::new());
        let wire: Arc<FakeWire> = Arc::default();
        let (result, _) = run(&[inject(1, "lo", eth_udp(9053))], Arc::clone(&wire));
        assert_eq!(protocol_text(result), "expected Hello first, got Inject");
        assert_eq!(wire.injects().len(), 0);
        let (result, _) = run(&[capture_open(1, "lo")], Arc::clone(&wire));
        assert_eq!(
            protocol_text(result),
            "expected Hello first, got CaptureOpen"
        );
        assert_eq!(wire.opens().len(), 0);
    }

    #[test]
    fn tester_frame_length_exactly_max_frame_is_read_and_answered() {
        // An Inject whose declared length is exactly MAX_FRAME (262 144):
        // type byte + 8-byte id + 2-byte name length + "lo" + payload.
        let overhead = encode(&inject(7, "lo", Vec::new())).len() - 4;
        assert_eq!(overhead, 1 + 8 + 2 + 2);
        let payload = vec![0u8; MAX_FRAME - overhead];
        let msg = inject(7, "lo", payload);
        let encoded = encode(&msg);
        assert_eq!(
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
            262_144
        );
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                msg,
                inject(8, "lo", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        // The loop read it whole, the guard refused it against the ScopeSet's
        // 1500-byte ceiling, and the session went on.
        assert_eq!(result, Ok(()));
        assert_eq!(
            inject_results(&out),
            vec![
                (
                    7,
                    Some("inject frame of 262131 bytes exceeds the limit".to_string())
                ),
                (8, None),
            ]
        );
        assert_eq!(wire.injects().len(), 1);

        // One more byte in the declared length is the exit, with the literal
        // text, before any of the payload is read.
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&262_145_u32.to_be_bytes());
        bytes.extend_from_slice(&encoded[4..]);
        bytes.push(0);
        let (result, out) = run_raw(bytes, Arc::default());
        assert_eq!(
            protocol_text(result),
            "frame length 262145 exceeds the 262144-byte maximum"
        );
        assert_eq!(out.len(), 1);
        // And so is u32::MAX.
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            protocol_text(run_raw(bytes, Arc::default()).0),
            "frame length 4294967295 exceeds the 262144-byte maximum"
        );
    }

    #[test]
    fn tester_stream_cut_mid_message_is_a_protocol_exit_not_a_clean_close() {
        // The header promises 100 bytes, 10 arrive, then EOF: the core (or
        // the socket) went away in the middle of a message.
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&100_u32.to_be_bytes());
        bytes.extend_from_slice(&[0x03; 10]);
        let (result, out) = run_raw(bytes, Arc::default());
        let text = protocol_text(result);
        assert!(text.starts_with("helper socket I/O error: "), "{text}");
        assert_eq!(out.len(), 1);
        // Cut inside the 4-byte length header itself.
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&[0, 0]);
        let text = protocol_text(run_raw(bytes, Arc::default()).0);
        assert!(text.starts_with("helper socket I/O error: "), "{text}");
        // Cut inside the Hello itself: nothing is sent at all.
        let hello_bytes = encode(&hello());
        let (result, out) = run_raw(
            hello_bytes[..hello_bytes.len() - 1].to_vec(),
            Arc::default(),
        );
        assert!(
            protocol_text(result).starts_with("helper socket I/O error: "),
            "a truncated Hello is not a clean close"
        );
        assert_eq!(out, Vec::<Msg>::new());
        // A clean EOF before any Hello is Ok, and nothing is sent.
        let (result, out) = run_raw(Vec::new(), Arc::default());
        assert_eq!(result, Ok(()));
        assert_eq!(out, Vec::<Msg>::new());
    }

    #[test]
    fn tester_zero_length_unknown_type_and_malformed_json_each_end_the_session() {
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            protocol_text(run_raw(bytes, Arc::default()).0),
            "malformed binary message payload"
        );

        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.push(0x7f);
        assert_eq!(
            protocol_text(run_raw(bytes, Arc::default()).0),
            "unknown message type 0x7f"
        );

        // A ScopeSet with one unknown key (strict body, plan A7): take the
        // real encoding and splice a key in before the closing brace.
        let encoded = encode(&Msg::ScopeSet(scope_set()));
        let mut body = encoded[5..].to_vec();
        assert_eq!(body.last(), Some(&b'}'));
        body.pop();
        body.extend_from_slice(br#","extra":1}"#);
        let mut bytes = encode(&hello());
        bytes.extend_from_slice(&u32::try_from(body.len() + 1).expect("fits").to_be_bytes());
        bytes.push(encoded[4]);
        bytes.extend_from_slice(&body);
        let (result, out) = run_raw(bytes, Arc::default());
        let text = protocol_text(result);
        assert!(text.starts_with("malformed message JSON: "), "{text}");
        assert!(text.contains("extra"), "{text}");
        assert_eq!(out.len(), 1);

        // A Hello with an unknown key is tolerated (plan A7) and answered.
        let encoded = encode(&hello());
        let mut body = encoded[5..].to_vec();
        body.pop();
        body.extend_from_slice(br#","future":true}"#);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(body.len() + 1).expect("fits").to_be_bytes());
        bytes.push(encoded[4]);
        bytes.extend_from_slice(&body);
        let (result, out) = run_raw(bytes, Arc::default());
        assert_eq!(result, Ok(()));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Msg::HelloAck { .. }));
    }

    #[test]
    fn tester_wire_open_failure_is_a_capture_closed_and_frees_the_id() {
        let wire: Arc<FakeWire> = Arc::default();
        wire.set_fail_open(Some(
            "pcap open: lo: You don't have permission to capture on that device",
        ));
        let out = SharedBuf::default();
        let (tx, reader) = ChanReader::new();
        let loop_out = out.clone();
        let loop_wire: Arc<dyn Wire> = Arc::clone(&wire) as Arc<dyn Wire>;
        let handle =
            thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION, caps()));
        for m in [hello(), Msg::ScopeSet(scope_set()), capture_open(4, "lo")] {
            tx.send(encode(&m)).expect("loop is reading");
        }
        out.wait_until("wire refusal", |msgs| {
            msgs.contains(&Msg::CaptureClosed {
                capture_id: 4,
                reason: "pcap open: lo: You don't have permission to capture on that device"
                    .to_string(),
            })
        });
        assert_eq!(wire.opens().len(), 1, "the wire was asked once");
        // The id is free again: the same id opens once the wire allows it.
        wire.set_fail_open(None);
        tx.send(encode(&capture_open(4, "lo")))
            .expect("loop is reading");
        out.wait_until("second open", |_| wire.opens().len() == 2);
        thread::sleep(Duration::from_millis(20));
        assert!(
            !out.messages().iter().any(|m| matches!(
                m,
                Msg::CaptureClosed { capture_id: 4, reason } if reason == "capture 4 is already open"
            )),
            "{:?}",
            out.messages()
        );
        drop(tx);
        assert_eq!(handle.join().expect("loop thread"), Ok(()));
    }

    #[test]
    fn tester_wire_inject_failure_is_passed_through_as_the_inject_error() {
        let wire: Arc<FakeWire> = Arc::default();
        wire.set_fail_inject(Some("pcap sendpacket: send: Message too long"));
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set()),
                inject(5, "lo", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            inject_results(&out),
            vec![(
                5,
                Some("pcap sendpacket: send: Message too long".to_string())
            )]
        );
        assert_eq!(
            wire.injects().len(),
            1,
            "the guard admitted it; the wire refused it"
        );
    }

    #[test]
    fn tester_capture_only_scope_opens_the_capture_but_refuses_the_inject() {
        let wire: Arc<FakeWire> = Arc::default();
        let capture_only = ScopeSet {
            scope: vec![entry("lo", L4Capability::Capture, 10)],
            ..scope_set()
        };
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(capture_only),
                capture_open(1, "lo"),
                inject(2, "lo", eth_udp(9053)),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(wire.opens().len(), 1);
        // No Inject-capability entry covers `lo`: the loop's pre-check
        // refuses before the guard (and before any pcap handle).
        assert_eq!(
            inject_results(&out),
            vec![(
                2,
                Some("interface lo is out of L4 inject scope".to_string())
            )]
        );
        assert_eq!(wire.injects().len(), 0);
        assert_eq!(wire.link_calls(), 0);
    }

    #[test]
    fn tester_empty_frame_and_wildcard_name_are_refused_before_the_wire() {
        let wire: Arc<FakeWire> = Arc::default();
        let (result, out) = run(
            &[
                hello(),
                Msg::ScopeSet(scope_set_on("*")),
                inject(1, "lo", Vec::new()),
                inject(2, "*", eth_udp(9053)),
                inject(3, "lo", vec![0u8; 14]),
                inject(4, "lo", vec![0xffu8; 1500]),
                inject(5, "lo", vec![0u8; 1501]),
            ],
            Arc::clone(&wire),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            inject_results(&out),
            vec![
                (1, Some("inject frame is truncated".to_string())),
                (
                    2,
                    Some("interface name contains a character outside [A-Za-z0-9._-]".to_string())
                ),
                (3, Some("inject frame is truncated".to_string())),
                (4, Some("inject frame carries no IP packet".to_string())),
                (
                    5,
                    Some("inject frame of 1501 bytes exceeds the limit".to_string())
                ),
            ]
        );
        assert_eq!(wire.injects().len(), 0);
    }
}
