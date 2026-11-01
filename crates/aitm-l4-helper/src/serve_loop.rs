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
//!   checked, then [`HelperGuard::check_inject`] parses the frame and decides;
//!   a refusal is an `InjectResult { error }` with the parser's or guard's
//!   text verbatim (plan A8) and the wire is never touched.
//! - **`CaptureOpen`** gets the filter from [`HelperGuard::capture_filter`]
//!   (the helper's own scope, never a string from the core); an interface no
//!   `Capture` entry covers, a malformed name, a duplicate id or a wire that
//!   will not open is a `CaptureClosed { reason }` and no capture exists.
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
use aitm_proto_l4::helper::enforce::HelperGuard;
use aitm_proto_l4::helper::frame::{inject_target, LinkType};
use aitm_proto_l4::helper::proto::{encode, read_msg, Msg, ProtoError, MAX_FRAME, PROTO};

/// `IFNAMSIZ - 1`: the longest interface name Linux accepts.
const MAX_IFACE_LEN: usize = 15;

/// The capability the helper reports in `HelloAck.caps` (spec §5.1: it holds
/// exactly this one after start-up).
const CAP_NET_RAW: &str = "CAP_NET_RAW";

/// The reason a capture reports when the core asked for it to close.
const REASON_CLOSED: &str = "closed";

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

    /// Put a link-layer frame the guard already admitted on `iface`.
    ///
    /// # Errors
    /// The wire's own text; the loop passes it through as `InjectResult.error`.
    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), String>;

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

/// The open captures by id, each with the flag its thread polls. Shared with
/// the threads so a capture that ends on its own removes itself.
#[derive(Default)]
struct Captures {
    open: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

impl Captures {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<AtomicBool>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register `id` with a fresh stop flag; `None` when it is already open.
    fn insert(&self, id: u64) -> Option<Arc<AtomicBool>> {
        let mut open = self.lock();
        if open.contains_key(&id) {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        open.insert(id, Arc::clone(&stop));
        Some(stop)
    }

    fn stop(&self, id: u64) {
        if let Some(flag) = self.lock().get(&id) {
            flag.store(true, Ordering::Release);
        }
    }

    fn remove(&self, id: u64) {
        self.lock().remove(&id);
    }

    fn stop_all(&self) {
        for flag in self.lock().values() {
            flag.store(true, Ordering::Release);
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
        caps: vec![CAP_NET_RAW.to_string()],
    })?;

    let mut guard: Option<HelperGuard> = None;
    loop {
        let msg = match read_msg(&mut reader) {
            Ok(msg) => msg,
            Err(ProtoError::Eof) => return Ok(()),
            Err(e) => return Err(ServeExit::Protocol(e.to_string())),
        };
        match msg {
            Msg::ScopeSet(s) => guard = Some(HelperGuard::from_scope_set(&s)),
            Msg::CaptureOpen {
                id,
                interface,
                direction: _,
                read_timeout_ms,
            } => {
                let timeout = Duration::from_millis(u64::from(read_timeout_ms));
                match open_capture(guard.as_ref(), &*wire, &captures, id, &interface, timeout) {
                    Ok((source, stop)) => {
                        spawn_capture(id, source, stop, Arc::clone(&out), Arc::clone(&captures));
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
                let Some(guard) = guard.as_ref() else {
                    return Err(ServeExit::Protocol("inject before scope".to_string()));
                };
                let error = inject(guard, &*wire, &interface, &bytes).err();
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
        .insert(id)
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
/// wire was not touched. Interface name first, then the helper's own guard
/// over the frame's bytes (plan A8: the parser's text passes through), then
/// the wire.
fn inject(
    guard: &HelperGuard,
    wire: &dyn Wire,
    interface: &str,
    bytes: &[u8],
) -> Result<(), String> {
    check_interface_name(interface)?;
    guard.check_inject(interface, wire.link(interface), bytes)?;
    wire.inject(interface, bytes)
}

/// Stream frames from `source` until it fails or the capture's flag is set.
fn spawn_capture<W: Write + Send + 'static>(
    id: u64,
    mut source: Box<dyn CaptureSource + Send>,
    stop: Arc<AtomicBool>,
    out: Arc<Outbound<W>>,
    captures: Arc<Captures>,
) {
    thread::spawn(move || {
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
                        captures.remove(id);
                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => break e.to_string(),
            }
        };
        captures.remove(id);
        // A failed write here has nowhere to be reported; the loop exits on
        // its own next read or write.
        let _ = out.send(&Msg::CaptureClosed {
            capture_id: id,
            reason,
        });
    });
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

    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), String> {
        let link = self.link(iface);
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
/// here; only the Linux build calls it (spike S8 covers macOS loopback).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
    use aitm_proto_l4::helper::proto::{encode, read_msg, Msg, ProtoError, ScopeSet, PROTO};
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
        /// What the next scripted capture yields.
        frames: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeWire {
        fn with_frames(frames: Vec<Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                frames: Mutex::new(frames),
                ..Self::default()
            })
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
            let frames =
                std::mem::take(&mut *self.frames.lock().unwrap_or_else(PoisonError::into_inner));
            Ok(Box::new(ScriptedSource {
                frames: frames.into_iter(),
            }))
        }
        fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), String> {
            self.injects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((iface.to_string(), bytes.to_vec()));
            Ok(())
        }
        fn link(&self, _iface: &str) -> LinkType {
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
        let result = serve_loop(Cursor::new(bytes), out.clone(), wire, VERSION);
        (result, out.messages())
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
        let handle = thread::spawn(move || serve_loop(reader, loop_out, loop_wire, VERSION));

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
}
