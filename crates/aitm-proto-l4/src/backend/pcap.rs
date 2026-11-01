//! The libpcap capture/inject backend (M5 Task 6).
//!
//! [`PcapBackend`] implements [`CaptureInjectBackend`] over the `pcap` crate — the
//! same code path on macOS and Linux (research note 08). Injection is L2 except
//! on Linux loopback (below): `Capture::sendpacket` writes a frame whose
//! link-layer header the caller already supplied. Capture opens a live handle
//! with an optional BPF filter.
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
//!
//! **Linux loopback is injected at layer 3.** A frame written at L2 on Linux `lo`
//! is seen by sniffers but never handed to the IP stack: the 2026-11-01 rig probe
//! (`t5-inject-probe.py`, Ubuntu 24.04 aarch64) sent one correctly checksummed UDP
//! datagram both ways to a listener on 127.0.0.1 — `AF_PACKET` with an Ethernet
//! header was not delivered and drew no ICMP from a closed port, while `AF_INET`
//! `SOCK_RAW` with `IP_HDRINCL` was delivered and the closed port answered ICMP
//! type 3 code 3. So on Linux, for a device libpcap flags `IFF_LOOPBACK` (the
//! flag, never the name `lo`), [`PcapBackend::inject`] strips the link header and
//! writes the IP packet through a header-included raw socket — the workaround
//! scapy documents as `L3RawSocket`; every other interface and OS — macOS BPF
//! does process injected frames — keeps `sendpacket`. The capability required is
//! the same `CAP_NET_RAW`, so this widens no privilege.
//!
//! Linux loopback injection reads the frame as Ethernet-framed IP, which is what
//! libpcap reports for Linux `lo` (`DLT_EN10MB`); the destination it routes on is
//! compared with the guard's own parse of the same frame, so a buffer the guard
//! read differently — or could not decode at all — is refused rather than
//! injected. The path reaches only loopback destinations, on the bound device:
//! a destination outside `127.0.0.0/8` / `::1` is refused before any socket is
//! opened ([`loopback_destination`]), and the raw socket is bound to the named
//! device (`SO_BINDTODEVICE`) as defence in depth — rig run 4 (Ubuntu 24.04,
//! kernel 6.8) showed the kernel still *emits* a non-local destination on the
//! bound loopback device, where it dies unobserved, so the binding alone is not
//! a refusal. Residual, recorded in the plan and not on this path:
//! `L4Guard::admit_endpoints`, the capture-side decision whether a frame may be
//! *recorded*, admits an undecodable frame blindly (pre-existing); injection
//! refuses anything the admitting parser cannot decode.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

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

    /// Put one already-authorized frame on `iface`.
    ///
    /// **The destination is the packet's own.** On the Linux loopback path the
    /// address handed to the raw socket is read out of the frame's IP header, never
    /// from a parameter, so this fn cannot redirect a packet the guard admitted.
    /// **Both views are compared**: that header read is cross-checked against the
    /// destination the guard's own parse of the same bytes decodes
    /// ([`admitted_destination`]), and a disagreement — or a frame that parse
    /// cannot decode — is refused rather than sent. **Only loopback, on the
    /// operator's device**: a destination that is not a loopback address is
    /// refused before any socket is opened ([`loopback_destination`]) as a
    /// [`L4Error::WireWrite`], and the raw socket is bound to the named device
    /// (`SO_BINDTODEVICE`) besides, so the new path can reach only what
    /// `sendpacket` on that device could — never a packet out of the real NIC.
    /// **Privilege is reported as such**: `EPERM` from the raw socket is
    /// [`L4Error::Unavailable`], the same variant the `sendpacket` path returns.
    /// **No handle outlives a guard decision**: both the pcap handle and the raw
    /// socket are opened inside this call and dropped when it returns, so nothing
    /// is cached across `L4Guard` scope/rate/denylist checks — those stay upstream
    /// in [`crate::wire::send_on_wire`] and are untouched by this path.
    fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
        // Linux `lo` drops L2-injected frames on the floor (module docs): go
        // through a raw IP socket so the stack actually processes the packet.
        // The lookup is skipped off Linux, so no other OS changes behaviour.
        if cfg!(target_os = "linux") {
            let devices = capture_devices()?;
            if inject_path(true, iface, &devices) == InjectPath::RawIp {
                return inject_ip_packet(iface, bytes);
            }
        }
        let mut cap = ::pcap::Capture::from_device(iface)
            .and_then(::pcap::Capture::open)
            .map_err(|e| unavailable("open", &e))?;
        cap.sendpacket(bytes)
            .map_err(|e| L4Error::WireWrite(format!("pcap sendpacket: {e}")))
    }
}

/// A capture device reduced to what the inject-path selector needs: its libpcap
/// name and whether libpcap reported the `IFF_LOOPBACK` flag for it. The flag is
/// authoritative — a name like `lo` is not, and an interface can be loopback
/// under any name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceKind {
    /// The libpcap device name, as `inject`'s `iface` argument spells it.
    name: String,
    /// libpcap's `PCAP_IF_LOOPBACK` (`IFF_LOOPBACK`) flag for this device.
    loopback: bool,
}

/// Which primitive an injection goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectPath {
    /// A header-included raw IP socket: Linux loopback only.
    RawIp,
    /// `pcap_sendpacket` with the caller's link-layer header: everything else.
    LinkLayer,
}

/// Pure selector (no sockets): the raw-IP path is taken only on Linux and only
/// when `iface` is a device libpcap flagged `IFF_LOOPBACK`. Unknown devices and
/// every non-loopback device keep the unchanged `sendpacket` path.
fn inject_path(target_is_linux: bool, iface: &str, devices: &[DeviceKind]) -> InjectPath {
    let is_loopback = devices.iter().any(|d| d.name == iface && d.loopback);
    if target_is_linux && is_loopback {
        InjectPath::RawIp
    } else {
        InjectPath::LinkLayer
    }
}

/// libpcap's device list, reduced to [`DeviceKind`]. Fail-closed: a listing
/// failure is [`L4Error::Unavailable`], never a silent fallback to a path the
/// kernel would discard.
fn capture_devices() -> Result<Vec<DeviceKind>, L4Error> {
    let devices = ::pcap::Device::list().map_err(|e| unavailable("device list", &e))?;
    Ok(devices
        .into_iter()
        .map(|d| DeviceKind {
            name: d.name,
            loopback: d.flags.is_loopback(),
        })
        .collect())
}

/// The fail-closed refusal for a buffer that is neither an Ethernet frame
/// carrying IP nor an IP packet. Carries no payload bytes.
fn no_ip_packet() -> L4Error {
    L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string())
}

/// The IP packet inside an **Ethernet-framed** `frame`: the bytes after a 14-byte
/// Ethernet header, accepted only when the ethertype and the IP version nibble
/// behind it agree and that version's fixed header is present:
///
/// - ethertype `0x0800`, version 4, at least 20 bytes; or
/// - ethertype `0x86DD`, version 6, at least 40 bytes.
///
/// The whole remainder of the frame comes back.
///
/// **No length is policed here.** Only the fixed header has to be there —
/// enough for [`ip_destination`] to read the destination out of it. For IPv4
/// the lengths are the kernel's: Linux `raw_send_hdrinc` (`net/ipv4/raw.c`,
/// v6.8) unconditionally sets `iph->tot_len` to the number of bytes it was
/// handed and recomputes `iph->check` for `ihl >= 5`, so a total length or
/// header checksum that disagrees with the frame is overwritten before the
/// packet reaches the stack — the documented limitation of this path:
/// `ipv4.total_length` and `ipv4.checksum` mutations do not reach the stack on
/// Linux loopback. IPv6 is different in direction: `rawv6_send_hdrinc`
/// (`net/ipv6/raw.c`) sends the header **verbatim**, so an `ipv6.payload_length`
/// mutation does reach the stack (the IPv6 input path drops a bad one).
/// `IPV6_HDRINCL` needs Linux >= 4.5; a link-local destination with scope id 0
/// fails `EINVAL` at `send_to`, which is a `WireWrite`, fail-closed — only `::1`
/// is live-tested. Refusing a length here would turn the lane's first
/// `ipv4.total_length` / `ipv6.payload_length` mutation into a
/// `StopReason::WireWrite` job stop, and for IPv4 the check would be moot.
///
/// Anything else — including a buffer that already starts with an IP header — is
/// [`no_ip_packet`]. An L3-first buffer is refused, never guessed: bytes 12..14 of
/// an L3-first IPv4 packet are the top half of the source address, so sniffing
/// them for an ethertype misread a packet from `8.0.0.0/16` as Ethernet-framed
/// and routed it on padding (tester finding F1). Every producer in this repo
/// writes Ethernet framing for Linux `lo` (libpcap reports `DLT_EN10MB` there),
/// so nothing that worked is lost.
fn strip_link_header(frame: &[u8]) -> Result<&[u8], L4Error> {
    const ETHER_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    let Some(header) = frame.get(..ETHER_HEADER_LEN) else {
        return Err(no_ip_packet());
    };
    let packet = &frame[ETHER_HEADER_LEN..];
    let version = packet.first().map(|b| b >> 4);

    let well_formed = match (&header[12..14], version) {
        ([0x08, 0x00], Some(4)) => packet.len() >= IPV4_HEADER_LEN,
        ([0x86, 0xDD], Some(6)) => packet.len() >= IPV6_HEADER_LEN,
        _ => false,
    };
    well_formed.then_some(packet).ok_or_else(no_ip_packet)
}

/// The packet's own destination, read out of its IP header — IPv4 bytes 16..20,
/// IPv6 bytes 24..40. Port 0: a raw `IPPROTO_RAW` socket routes on the header it
/// is handed, the address only selects the route.
///
/// Called on the output of [`strip_link_header`], which guaranteed the ethertype,
/// the version nibble and the fixed header length; lengths are the kernel's. The
/// version and length guards here are a second, fail-closed line.
fn ip_destination(packet: &[u8]) -> Result<SocketAddr, L4Error> {
    let ip = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[16..20].try_into().map_err(|_| no_ip_packet())?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        Some(6) if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[24..40].try_into().map_err(|_| no_ip_packet())?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(no_ip_packet()),
    };
    Ok(SocketAddr::new(ip, 0))
}

/// Cross-check `dst` — the destination [`ip_destination`] read out of the IP
/// header — against **the guard's own view of the same frame**.
/// [`crate::guard::L4Guard::admit_endpoints`] authorises a frame over the
/// [`crate::craft::PacketSpec::endpoints`] parse; this path routes on the header
/// read. When those two parses disagree about where the packet is going, the
/// frame that was admitted is not the frame that would be sent: refuse,
/// fail-closed, with no payload bytes in the message. When the guard's parse
/// yields no destination at all — an undecodable buffer — nothing was
/// authorised, so that is refused too (security panel M3): every production
/// write path already turns away such a frame before the guard, because
/// [`crate::capture::packet_target`] is the same decode and yields `None`, so
/// this arm costs nothing that worked and closes the path against a future
/// caller that skips the upstream check. So amendment 49's "the destination
/// comes from the frame" holds by construction against the authorising parser.
fn admitted_destination(frame: &[u8], dst: IpAddr) -> Result<(), L4Error> {
    match crate::craft::PacketSpec::endpoints(frame).dst {
        Some(admitted) if admitted == dst => Ok(()),
        Some(_) => Err(L4Error::WireWrite(
            "linux loopback inject: destination disagrees with the admitted frame".to_string(),
        )),
        None => Err(L4Error::WireWrite(
            "linux loopback inject: destination not decodable by the admitting parser".to_string(),
        )),
    }
}

/// Refuse a destination that is not a loopback address (`127.0.0.0/8`, `::1`).
///
/// The layer-3 path exists only for a device libpcap flags `IFF_LOOPBACK`, and
/// the packet lane only ever targets loopback ([`crate::discover::resolve_target`]),
/// so a non-loopback destination here is never legitimate. The device binding
/// ([`bind_to_device`]) stays as defence in depth, but it is not a refusal: rig
/// run 4 (Ubuntu 24.04, kernel 6.8) showed the kernel *accepts* a `send_to` to
/// `10.255.255.254` on a socket bound to `lo` and emits the frame on `lo`, where
/// it dies — `send_to` returned `Ok`. So the refusal must be ours, deterministic
/// and before any socket is opened. Pure: no payload byte, no address, reaches
/// the message.
fn loopback_destination(dst: IpAddr) -> Result<(), L4Error> {
    if dst.is_loopback() {
        Ok(())
    } else {
        Err(L4Error::WireWrite(
            "linux loopback inject: destination is not a loopback address".to_string(),
        ))
    }
}

/// Classify a raw-socket failure on the Linux loopback path. `EPERM`
/// (`PermissionDenied`: no `CAP_NET_RAW`) is [`L4Error::Unavailable`], the
/// variant this crate documents for "no privilege" and the one the `sendpacket`
/// path returns for the same condition, so the lane stops with
/// `StopReason::Unavailable` and the privilege probe reads it correctly. Every
/// other kind is [`L4Error::WireWrite`]. The message carries the context and the
/// `io::Error` text only — never a payload byte.
fn socket_error(context: &str, e: &std::io::Error) -> L4Error {
    let message = format!("linux loopback inject: {context}: {e}");
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        L4Error::Unavailable(message)
    } else {
        L4Error::WireWrite(message)
    }
}

/// The [`socket_error`] context for a failed `SO_BINDTODEVICE`: names the
/// interface, nothing else.
fn bind_context(iface: &str) -> String {
    format!("bind to {iface} failed")
}

/// Bind the raw socket to `iface` (`SO_BINDTODEVICE`), so the kernel routes
/// only through the device the operator named: a destination with no route via
/// that device fails `ENETUNREACH` at `send_to` instead of leaving through
/// another NIC (security panel M1). socket2 exposes `bind_device` on Linux only.
#[cfg(target_os = "linux")]
fn bind_to_device(socket: &Socket, iface: &str) -> Result<(), L4Error> {
    socket
        .bind_device(Some(iface.as_bytes()))
        .map_err(|e| socket_error(&bind_context(iface), &e))
}

/// Off Linux this path is never selected ([`inject_path`] is Linux-only), and
/// `SO_BINDTODEVICE` is not available; if it were ever reached, fail closed
/// rather than send through an unbound socket.
#[cfg(not(target_os = "linux"))]
fn bind_to_device(_socket: &Socket, iface: &str) -> Result<(), L4Error> {
    Err(L4Error::Unavailable(format!(
        "linux loopback inject: {}: SO_BINDTODEVICE is Linux-only",
        bind_context(iface)
    )))
}

/// Write one IP packet through a header-included raw socket bound to `iface` —
/// the Linux loopback injection path (module docs). Fail-closed: `EPERM` is
/// [`L4Error::Unavailable`], every other socket error is [`L4Error::WireWrite`]
/// ([`socket_error`]), and no payload byte reaches the message.
fn inject_ip_packet(iface: &str, frame: &[u8]) -> Result<(), L4Error> {
    /// `IPPROTO_RAW`: the kernel sends the packet's own header verbatim.
    const IPPROTO_RAW: i32 = 255;

    let packet = strip_link_header(frame)?;
    let dst = ip_destination(packet)?;
    loopback_destination(dst.ip())?;
    admitted_destination(frame, dst.ip())?;

    let domain = if dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
        .map_err(|e| socket_error("raw socket", &e))?;
    if dst.is_ipv4() {
        socket
            .set_header_included_v4(true)
            .map_err(|e| socket_error("IP_HDRINCL", &e))?;
    } else {
        socket
            .set_header_included_v6(true)
            .map_err(|e| socket_error("IPV6_HDRINCL", &e))?;
    }
    bind_to_device(&socket, iface)?;

    let written = socket
        .send_to(packet, &SockAddr::from(dst))
        .map_err(|e| socket_error("send_to", &e))?;
    if written != packet.len() {
        return Err(L4Error::WireWrite(format!(
            "linux loopback inject: short write ({written} of {} bytes)",
            packet.len()
        )));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::craft::{EtherSpec, Ipv4Spec, Ipv6Spec, Layer, PacketSpec, UdpSpec};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// A real crafted `[Ether, Ipv4, Udp, Raw]` loopback frame — the exact shape
    /// `l4.send_recv` puts on the wire.
    fn ether_ipv4_udp_frame(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        ether_ipv4_udp_frame_to(Ipv4Addr::LOCALHOST, dst_port, payload)
    }

    /// The same crafted frame from `127.0.0.1` to an arbitrary `dst`.
    fn ether_ipv4_udp_frame_to(dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(dst),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("craft the loopback stimulus")
    }

    fn device(name: &str, loopback: bool) -> DeviceKind {
        DeviceKind {
            name: name.to_string(),
            loopback,
        }
    }

    /// Pinned: the path is chosen by the device's `IFF_LOOPBACK` flag, not by its
    /// name — a loopback device takes the raw-IP path, a non-loopback device and
    /// an unlisted name keep `sendpacket`, and off Linux everything keeps it.
    #[test]
    fn inject_path_follows_the_loopback_flag() {
        // A loopback device deliberately *not* named `lo`, and a non-loopback
        // device deliberately named with an `lo` prefix: only the flag decides.
        let devices = [device("lo-alias", true), device("lo9000", false)];

        assert_eq!(
            inject_path(true, "lo-alias", &devices),
            InjectPath::RawIp,
            "a flagged loopback device injects at layer 3 on Linux"
        );
        assert_eq!(
            inject_path(true, "lo9000", &devices),
            InjectPath::LinkLayer,
            "an unflagged device keeps pcap sendpacket even with an lo-ish name"
        );
        assert_eq!(
            inject_path(true, "eth0", &devices),
            InjectPath::LinkLayer,
            "an unlisted device keeps pcap sendpacket"
        );
        assert_eq!(
            inject_path(false, "lo-alias", &devices),
            InjectPath::LinkLayer,
            "off Linux (macOS BPF processes injected frames) nothing changes"
        );
    }

    /// Pinned: the Linux loopback L3 path strips the 14-byte Ethernet header, so
    /// the bytes handed to the raw socket start at the IPv4 version/IHL nibble.
    #[test]
    fn strip_link_header_for_loopback_inject() {
        let frame = ether_ipv4_udp_frame(40001, b"probe");
        assert_eq!(
            frame[12..14],
            [0x08, 0x00],
            "crafted frame is Ethernet/IPv4"
        );

        let packet = strip_link_header(&frame).expect("an Ethernet/IPv4 frame decodes");

        assert_eq!(packet[0], 0x45, "the IP packet starts at version 4 / IHL 5");
        assert_eq!(
            packet,
            &frame[14..],
            "exactly the 14-byte header is removed"
        );
        assert_eq!(packet.len(), frame.len() - 14);
    }

    /// Pinned (tester F1): a buffer that is already an IP packet is **refused**,
    /// not passed through. Every producer writes Ethernet framing for Linux `lo`
    /// (libpcap reports `DLT_EN10MB` there), so an L3-first buffer is not a
    /// shape the loopback path ever has to guess at — and guessing from bytes
    /// 12..14 is exactly what F1 broke.
    #[test]
    fn strip_link_header_refuses_an_l3_first_frame() {
        let frame = ether_ipv4_udp_frame(40001, b"probe");
        let l3 = frame[14..].to_vec();
        assert_eq!(
            l3[0], 0x45,
            "the L3-first buffer is a well-formed IPv4 packet"
        );

        assert_eq!(
            strip_link_header(&l3).expect_err("an L3-first buffer is refused, never guessed"),
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string())
        );
    }

    /// Tester F1, the exact vector, re-pinned for round 2: an L3-first IPv4
    /// packet of 48 bytes from `8.0.70.1` to `10.1.2.3` with a correct total
    /// length. Bytes 12..14 are `08 00` — the top half of the **source** address
    /// — so read as Ethernet (what libpcap reports for Linux `lo`, `DLT_EN10MB`)
    /// the buffer is a 34-byte IPv4 packet to `69.69.69.69`, an address read out
    /// of the padding. With the lengths left to the kernel nothing in
    /// `strip_link_header` can tell this buffer from a real frame; what refuses
    /// it is the **destination cross-check**: the guard's own parse falls back
    /// to an L3-first read and sees `10.1.2.3`, the two views disagree, and the
    /// injection fails closed before any socket is opened.
    #[test]
    fn an_l3_first_buffer_is_refused_by_the_destination_cross_check() {
        let mut packet = vec![0x45; 48];
        packet[2..4].copy_from_slice(&48u16.to_be_bytes()); // total length: all 48 bytes
        packet[12..16].copy_from_slice(&[8, 0, 70, 1]); // source 8.0.70.1
        packet[16..20].copy_from_slice(&[10, 1, 2, 3]); // destination 10.1.2.3
        assert_eq!(
            packet[12..14],
            [0x08, 0x00],
            "the source's top half is the IPv4 ethertype"
        );
        assert_eq!(
            packet[14] >> 4,
            4,
            "and the misread 'packet' has a valid version nibble"
        );

        let stripped = strip_link_header(&packet).expect("read as Ethernet-framed IPv4");
        assert_eq!(
            stripped.len(),
            34,
            "34 of the 48 bytes, behind a 14-byte 'link header'"
        );
        let dst = ip_destination(stripped).expect("the misread header's destination");
        assert_eq!(
            dst,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(69, 69, 69, 69)), 0),
            "the misread destination the tester observed"
        );
        assert_eq!(
            PacketSpec::endpoints(&packet).dst,
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            "the guard's parse reads the buffer L3-first and sees the real destination"
        );

        assert_eq!(
            admitted_destination(&packet, dst.ip()),
            Err(L4Error::WireWrite(
                "linux loopback inject: destination disagrees with the admitted frame".to_string()
            )),
            "fail-closed: the two views disagree, nothing is handed to send_to"
        );
    }

    /// Tester F1: an ethertype that contradicts the version nibble behind it is
    /// refused — `0x0800` over a version-6 header, `0x86DD` over a version-4
    /// header. Each half alone would pass its own length check.
    #[test]
    fn strip_link_header_refuses_an_ethertype_version_mismatch() {
        let refusal =
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string());

        let mut v6 = vec![0x60; 40];
        v6[4..6].copy_from_slice(&0u16.to_be_bytes()); // payload length 0: well-formed IPv6
        assert_eq!(
            strip_link_header(&ether_frame([0x86, 0xDD], &v6)).expect("IPv6 behind 0x86DD"),
            &v6[..]
        );
        assert_eq!(
            strip_link_header(&ether_frame([0x08, 0x00], &v6)).expect_err("IPv6 behind 0x0800"),
            refusal
        );

        let mut v4 = vec![0x45; 20];
        v4[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length 20: well-formed IPv4
        assert_eq!(
            strip_link_header(&ether_frame([0x08, 0x00], &v4)).expect("IPv4 behind 0x0800"),
            &v4[..]
        );
        assert_eq!(
            strip_link_header(&ether_frame([0x86, 0xDD], &v4)).expect_err("IPv4 behind 0x86DD"),
            refusal
        );
    }

    /// Tester F1 round 2: the loopback path does **not** police the IP length
    /// fields. For IPv4, Linux `raw_send_hdrinc` (`net/ipv4/raw.c`, v6.8)
    /// overwrites `iph->tot_len` with the number of bytes it was handed and
    /// recomputes `iph->check`, so a length that disagrees with the frame is the
    /// kernel's business, not ours; for IPv6 the header goes out verbatim and
    /// the stack's input path judges it. Refusing one here would turn the
    /// lane's first `ipv4.total_length` / `ipv6.payload_length` mutation into a
    /// `StopReason::WireWrite` job stop. Every total/payload length here is
    /// accepted and the whole remainder of the frame comes back.
    #[test]
    fn strip_link_header_leaves_lengths_to_the_kernel() {
        let mut packet = vec![0x45; 48];
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);

        // One past the end, far past the end, under the fixed header, and well
        // under the bytes present (Ethernet padding): all four are accepted.
        for total_length in [49u16, 1500, 19, 28, 48] {
            packet[2..4].copy_from_slice(&total_length.to_be_bytes());
            assert_eq!(
                strip_link_header(&ether_frame([0x08, 0x00], &packet))
                    .unwrap_or_else(|e| panic!("total length {total_length} is accepted: {e:?}")),
                &packet[..],
                "the whole 48-byte remainder comes back for total length {total_length}"
            );
        }

        let mut v6 = vec![0x60; 48];
        v6[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        // 40 + 9 = 49 runs one past the 48 bytes present; 0 leaves 8 bytes of
        // padding; 8 is exact. Unlike IPv4, the kernel sends the IPv6 header
        // verbatim (`rawv6_send_hdrinc`), so these reach the stack as written.
        for payload_length in [9u16, 0, 8] {
            v6[4..6].copy_from_slice(&payload_length.to_be_bytes());
            assert_eq!(
                strip_link_header(&ether_frame([0x86, 0xDD], &v6)).unwrap_or_else(|e| panic!(
                    "payload length {payload_length} is accepted: {e:?}"
                )),
                &v6[..],
                "the whole 48-byte remainder comes back for payload length {payload_length}"
            );
        }
    }

    /// Amendment 49, round 2: on a well-formed crafted frame the two reads of the
    /// destination agree — [`crate::craft::PacketSpec::endpoints`], the decode
    /// `L4Guard::admit_endpoints` authorises on, and the header read
    /// `inject_ip_packet` routes on.
    #[test]
    fn destination_cross_check_agrees_for_a_crafted_frame() {
        let frame = ether_ipv4_udp_frame(40001, b"probe");
        let dst = ip_destination(strip_link_header(&frame).expect("decode"))
            .expect("an IPv4 destination");

        assert_eq!(
            PacketSpec::endpoints(&frame).dst,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "the guard's parse routes the frame to 127.0.0.1"
        );
        assert_eq!(
            dst.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "and so does our own header read"
        );
        assert_eq!(admitted_destination(&frame, dst.ip()), Ok(()));
    }

    /// Rig run 4 (Ubuntu 24.04, kernel 6.8): with the raw socket bound to `lo`
    /// the kernel still *accepted* a datagram to `10.255.255.254` and emitted it
    /// on `lo`, where it died — confinement held, but `send_to` returned `Ok`.
    /// So the refusal of a non-loopback destination is ours, before any socket:
    /// `127.0.0.0/8` and `::1` pass, everything else is the one exact
    /// `WireWrite` literal.
    #[test]
    fn loopback_destination_accepts_127_and_v6_loopback_only() {
        let refused = Err(L4Error::WireWrite(
            "linux loopback inject: destination is not a loopback address".to_string(),
        ));

        for ok in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert_eq!(loopback_destination(ok), Ok(()), "{ok} is loopback");
        }

        for bad in [
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(loopback_destination(bad), refused, "{bad} is not loopback");
        }
    }

    /// The same rule through `inject_ip_packet` itself: a well-formed crafted
    /// frame to `10.255.255.254` — both destination reads agree, so the
    /// cross-check passes — is refused with the loopback literal. The refusal
    /// comes before `Socket::new`, which is why this runs unprivileged and on
    /// every OS (off Linux the socket step would fail differently, as
    /// `Unavailable` from [`bind_to_device`] or `EPERM`).
    #[test]
    fn inject_ip_packet_refuses_a_non_loopback_destination_before_any_socket() {
        let off_host = ether_ipv4_udp_frame_to(Ipv4Addr::new(10, 255, 255, 254), 40001, b"stray");
        assert_eq!(
            PacketSpec::endpoints(&off_host).dst,
            Some(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254))),
            "the guard's parse and the header read agree, so only the loopback rule refuses it"
        );

        assert_eq!(
            inject_ip_packet("lo", &off_host),
            Err(L4Error::WireWrite(
                "linux loopback inject: destination is not a loopback address".to_string()
            ))
        );
    }

    /// Amendment 49, round 2: when the guard's parser reads the same bytes as a
    /// *different* packet with a *different* destination, the injection is
    /// refused — the frame the guard admitted is not the frame we would send.
    ///
    /// The construction is a real disagreement, not a stubbed one: the inner
    /// total length (1500) runs past the 48 bytes present, so
    /// `SlicedPacket::from_ethernet` fails and `parse_frame` falls back to
    /// `from_ip` over the frame itself — whose first byte is a destination-MAC
    /// octet of `0x45`. That fallback reads the destination at frame bytes
    /// 16..20 (`5.220.69.69`), while the loopback path reads the inner header's
    /// 127.0.0.1.
    #[test]
    fn destination_cross_check_refuses_a_disagreeing_view() {
        let mut packet = vec![0x45; 48];
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes()); // past the end
        packet[9] = 253; // an experimental protocol: no transport to decode
        packet[12..16].copy_from_slice(&[10, 0, 0, 9]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);

        let mut frame = ether_frame([0x08, 0x00], &packet);
        frame[0] = 0x45; // version 4 / IHL 5 to the fallback parse
        frame[1] = 0x00;
        let outer_length = u16::try_from(frame.len()).expect("frame length");
        frame[2..4].copy_from_slice(&outer_length.to_be_bytes());
        frame[9] = 253;

        assert_eq!(
            PacketSpec::endpoints(&frame).dst,
            Some(IpAddr::V4(Ipv4Addr::new(5, 220, 69, 69))),
            "the guard's parse reads the frame L3-first and lands elsewhere"
        );
        let dst = ip_destination(strip_link_header(&frame).expect("Ethernet-framed IPv4"))
            .expect("our own header read");
        assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        assert_eq!(
            admitted_destination(&frame, dst.ip()),
            Err(L4Error::WireWrite(
                "linux loopback inject: destination disagrees with the admitted frame".to_string()
            )),
            "fail-closed: the two views of the destination must agree"
        );
    }

    /// Security panel M3 (amendment 49): a frame the admitting parser cannot
    /// decode at all is **refused**, never injected on our own header read. The
    /// frame here is Ethernet/IPv4 whose total length (1500) runs past the 48
    /// bytes present, so every [`crate::craft::PacketSpec::endpoints`] field is
    /// `None`. Every production write path already refuses such a frame before
    /// the guard (`capture::packet_target` is the same decode and yields `None`),
    /// so this arm is reachable only by calling the backend directly — and it
    /// fails closed there too, so a future caller that skips the upstream check
    /// cannot route a frame the authorising parser never saw.
    #[test]
    fn destination_cross_check_refuses_an_undecodable_guard_view() {
        let mut packet = vec![0x45; 48];
        packet[2..4].copy_from_slice(&1500u16.to_be_bytes());
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        let frame = ether_frame([0x08, 0x00], &packet);

        let view = PacketSpec::endpoints(&frame);
        assert_eq!(
            (view.dst, view.src, view.proto),
            (None, None, None),
            "a total length past the end of the frame leaves the guard's parse empty"
        );

        let dst = ip_destination(strip_link_header(&frame).expect("the loopback path accepts it"))
            .expect("our own header read");
        assert_eq!(dst.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            admitted_destination(&frame, dst.ip()),
            Err(L4Error::WireWrite(
                "linux loopback inject: destination not decodable by the admitting parser"
                    .to_string()
            )),
            "fail-closed: no admitted destination means nothing was authorised"
        );
    }

    /// Pinned fail-closed: a buffer too short to be either an Ethernet frame or an
    /// IP packet is a `WireWrite`, and the message carries no payload bytes.
    #[test]
    fn strip_link_header_rejects_a_short_buffer() {
        let err = strip_link_header(&[0x45; 10]).expect_err("10 bytes is not an IP packet");

        assert_eq!(
            err,
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string())
        );
    }

    /// Quality panel I2 + security panel M1: a raw-socket failure is classified
    /// by its `io::ErrorKind`. `PermissionDenied` (EPERM without `CAP_NET_RAW`)
    /// is [`L4Error::Unavailable`] — the documented "no privilege" variant the
    /// `sendpacket` path and the lane's `StopReason::Unavailable` already use —
    /// and every other kind is [`L4Error::WireWrite`]. A bind failure names the
    /// interface it tried to bind, and no message carries payload bytes.
    #[test]
    fn socket_error_classifies_eperm_as_unavailable_and_the_rest_as_wire_write() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            socket_error("raw socket", &Error::from(ErrorKind::PermissionDenied)),
            L4Error::Unavailable(
                "linux loopback inject: raw socket: permission denied".to_string()
            ),
            "EPERM is the privilege signal, not a broken send path"
        );
        assert_eq!(
            socket_error("send_to", &Error::from(ErrorKind::NetworkUnreachable)),
            L4Error::WireWrite("linux loopback inject: send_to: network unreachable".to_string()),
            "ENETUNREACH from the device-bound socket is a refused write"
        );
        assert_eq!(
            socket_error("IP_HDRINCL", &Error::other("boom")),
            L4Error::WireWrite("linux loopback inject: IP_HDRINCL: boom".to_string())
        );

        let bind = socket_error(
            &bind_context("lo-alias"),
            &Error::from(ErrorKind::PermissionDenied),
        );
        assert_eq!(
            bind,
            L4Error::Unavailable(
                "linux loopback inject: bind to lo-alias failed: permission denied".to_string()
            ),
            "the bind message names the interface and nothing else"
        );
    }

    /// An Ethernet header with `ethertype`, followed by `payload` verbatim — a
    /// frame a test can truncate below any IP header length.
    fn ether_frame(ethertype: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype);
        frame.extend_from_slice(payload);
        frame
    }

    /// Tester (T5 stage 5, edge cases): an Ethernet frame whose ethertype
    /// promises IP but whose payload is shorter than that version's fixed
    /// header is refused — fail-closed, no panic, no slice out of range, and no
    /// payload byte in the message. 19 bytes of IPv4 and 39 of IPv6 are the
    /// off-by-one below the boundary; 20 and 40 are accepted in
    /// [`strip_link_header_accepts_a_header_sized_packet`].
    #[test]
    fn strip_link_header_rejects_a_truncated_ip_payload_behind_an_ethertype() {
        let refusal =
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string());

        for len in 0..20usize {
            let frame = ether_frame([0x08, 0x00], &vec![0x45; len]);
            assert_eq!(
                strip_link_header(&frame).expect_err("an IPv4 payload under 20 bytes is refused"),
                refusal,
                "ethertype IPv4 with a {len}-byte payload"
            );
        }
        for len in 0..40usize {
            let frame = ether_frame([0x86, 0xDD], &vec![0x60; len]);
            assert_eq!(
                strip_link_header(&frame).expect_err("an IPv6 payload under 40 bytes is refused"),
                refusal,
                "ethertype IPv6 with a {len}-byte payload"
            );
        }
    }

    /// Tester (edge cases): every buffer from empty to 14 bytes — the Ethernet
    /// header length itself — is refused without panicking. 13 bytes is the
    /// brief's case: one short of a link header, and far short of any IP packet.
    #[test]
    fn strip_link_header_rejects_every_buffer_up_to_the_link_header_length() {
        for len in 0..=14usize {
            for fill in [0x00u8, 0x45, 0x60, 0xFF] {
                let buffer = vec![fill; len];
                assert!(
                    strip_link_header(&buffer).is_err(),
                    "a {len}-byte buffer of {fill:#04x} is not an IP packet"
                );
            }
        }
        assert_eq!(
            strip_link_header(&[0x45; 13]).expect_err("13 bytes is not an IP packet"),
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string())
        );
    }

    /// Tester (edge cases, re-pinned for F1): an Ethernet-framed packet of
    /// exactly the fixed header length — 20 bytes of IPv4, 40 of IPv6 — is
    /// accepted whole, and one byte less is refused. That boundary is what
    /// decides whether `ip_destination` can read bytes 16..20 / 24..40 at all.
    /// The same bytes without the Ethernet header are refused: the loopback
    /// path accepts Ethernet-framed IP only.
    #[test]
    fn strip_link_header_accepts_a_header_sized_packet() {
        let refusal =
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string());

        let mut v4 = vec![0x45; 20];
        v4[2..4].copy_from_slice(&20u16.to_be_bytes());
        v4[16..20].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(
            strip_link_header(&ether_frame([0x08, 0x00], &v4))
                .expect("a 20-byte IPv4 packet behind an Ethernet header is an IP packet"),
            &v4[..]
        );
        assert!(
            strip_link_header(&ether_frame([0x08, 0x00], &v4[..19])).is_err(),
            "19 bytes is one short of an IPv4 header"
        );
        assert_eq!(
            strip_link_header(&v4).expect_err("the same 20 bytes L3-first are refused"),
            refusal
        );

        let mut v6 = vec![0x60; 40];
        v6[4..6].copy_from_slice(&0u16.to_be_bytes());
        v6[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let framed = ether_frame([0x86, 0xDD], &v6);
        assert_eq!(
            strip_link_header(&framed)
                .expect("a 40-byte IPv6 packet behind an Ethernet header is an IP packet"),
            &v6[..]
        );
        assert_eq!(
            ip_destination(strip_link_header(&framed).expect("decode"))
                .expect("the IPv6 destination"),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
        );
        assert!(
            strip_link_header(&ether_frame([0x86, 0xDD], &v6[..39])).is_err(),
            "39 bytes is one short of an IPv6 header"
        );
        assert_eq!(
            strip_link_header(&v6).expect_err("the same 40 bytes L3-first are refused"),
            refusal
        );
    }

    /// Tester (edge cases): the destination sits at a fixed offset whatever the
    /// IHL says. A header with options (IHL 6, 24 bytes) still yields the
    /// address in bytes 16..20, never a byte read from the options area.
    #[test]
    fn ipv4_destination_ignores_the_options_an_ihl_above_five_adds() {
        let mut packet = vec![0u8; 32];
        packet[0] = 0x46; // version 4, IHL 6: a 24-byte header, 4 bytes of options
        packet[12..16].copy_from_slice(&[127, 0, 0, 1]); // source
        packet[16..20].copy_from_slice(&[10, 11, 12, 13]); // destination
        packet[20..24].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]); // the options
        packet[24..28].copy_from_slice(&[9, 9, 9, 9]); // payload, never an address

        let dst = ip_destination(&packet).expect("an IPv4 destination");

        assert_eq!(
            dst.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)), 0),
            "bytes 16..20 hold the destination whatever the IHL"
        );
        packet[2..4].copy_from_slice(&32u16.to_be_bytes());
        assert_eq!(
            strip_link_header(&ether_frame([0x08, 0x00], &packet))
                .expect("an Ethernet-framed packet with options"),
            &packet[..],
            "options change nothing about where the link header ends"
        );
    }

    /// Tester (edge cases): `ip_destination` on a buffer too short to hold the
    /// address it would read is the fail-closed refusal, not a panic — the
    /// slice indices sit inside a length check — and a version nibble that is
    /// neither 4 nor 6 is refused too.
    #[test]
    fn ip_destination_refuses_what_it_cannot_read() {
        let refusal =
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string());

        assert_eq!(ip_destination(&[]).expect_err("empty"), refusal);
        assert_eq!(ip_destination(&[0x45; 19]).expect_err("19 bytes"), refusal);
        assert_eq!(ip_destination(&[0x60; 39]).expect_err("39 bytes"), refusal);
        assert_eq!(
            ip_destination(&[0x55; 64]).expect_err("version 5 is neither IPv4 nor IPv6"),
            refusal
        );
        assert_eq!(ip_destination(&[0x00; 64]).expect_err("version 0"), refusal);
    }

    /// Tester finding F1 (fixed): the old `strip_link_header` guessed whether a
    /// buffer carried a link header by reading bytes 12..14 as an ethertype, and
    /// in an L3-first IPv4 packet those bytes are the first half of the **source
    /// address**. A packet from `8.0.x.x` therefore looked Ethernet to it. This
    /// vector happened to fail closed even then (byte 14 is `127`, no IP
    /// version); it stays refused now because every L3-first buffer is.
    #[test]
    fn an_l3_first_packet_whose_source_looks_like_an_ethertype_fails_closed() {
        let mut packet = vec![0x45; 28];
        packet[12..16].copy_from_slice(&[8, 0, 0, 1]); // source 8.0.0.1
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]); // destination 127.0.0.1

        assert_eq!(
            strip_link_header(&packet).expect_err("read as an Ethernet frame, then refused"),
            L4Error::WireWrite("linux loopback inject: frame carries no IP packet".to_string()),
            "a loopback destination makes the misread fail closed rather than ship"
        );
    }

    /// Pinned: the raw-socket destination is read out of the IPv4 header (bytes
    /// 16..20), not from the caller — the kernel routes on the header itself.
    #[test]
    fn ipv4_destination_is_read_from_the_header() {
        let frame = ether_ipv4_udp_frame(40001, b"probe");
        let packet = strip_link_header(&frame).expect("decode");

        let dst = ip_destination(packet).expect("an IPv4 destination");

        assert_eq!(dst, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    }

    /// Pinned: the IPv6 destination comes from bytes 24..40 of the IPv6 header.
    #[test]
    fn ipv6_destination_is_read_from_the_header() {
        let frame = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv6(Ipv6Spec {
                    src: Some(Ipv6Addr::LOCALHOST),
                    dst: Some(Ipv6Addr::LOCALHOST),
                    ..Ipv6Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(40001),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft an IPv6 loopback stimulus");
        assert_eq!(
            frame[12..14],
            [0x86, 0xDD],
            "crafted frame is Ethernet/IPv6"
        );

        let packet = strip_link_header(&frame).expect("decode");
        let dst = ip_destination(packet).expect("an IPv6 destination");

        assert_eq!(dst, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0));
    }

    /// The 2026-11-01 root-cause probe as a Rust test: a frame injected on Linux
    /// `lo` must be **processed by the IP stack**, not merely sniffable. Part one
    /// asserts a bound UDP socket receives the payload; part two re-injects to the
    /// now-closed port and asserts the kernel answers ICMP destination unreachable
    /// / port unreachable (type 3, code 3). Before this fix both halves were
    /// silent. Part three (security panel M1, rig run 4): a datagram to
    /// `10.255.255.254` — RFC 1918, not loopback — is refused as a `WireWrite`
    /// before any socket is opened ([`loopback_destination`]); the device-bound
    /// socket alone would have *emitted* it on `lo`, where it dies unobserved.
    /// Needs `CAP_NET_RAW`: unprivileged, the raw socket's `EPERM` is
    /// classified `L4Error::Unavailable` ([`socket_error`]) and the test skips
    /// through the crate's fail-closed path.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires raw-inject privilege (CAP_NET_RAW); run with AITM_L4_TESTS=1 and -- --ignored"]
    fn linux_loopback_inject_reaches_the_ip_stack() {
        use std::io::Read;
        use std::net::UdpSocket;
        use std::time::Instant;

        if std::env::var("AITM_L4_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind the probe listener");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("listener read timeout");
        let port = listener.local_addr().expect("listener address").port();

        let backend = PcapBackend::new();
        let frame = ether_ipv4_udp_frame(port, b"probe-l3");
        match backend.inject("lo", &frame) {
            Ok(()) => {}
            // No raw privilege here: the fail-closed contract, skip cleanly.
            Err(L4Error::Unavailable(_)) => return,
            Err(e) => panic!("unexpected inject error: {e:?}"),
        }

        let mut buf = [0u8; 2048];
        let (n, _from) = listener
            .recv_from(&mut buf)
            .expect("the injected datagram is delivered to the listening socket");
        assert_eq!(&buf[..n], b"probe-l3", "the payload arrives unchanged");

        // Part two: the same datagram to the now-closed port draws ICMP from the
        // stack. A raw ICMP socket on Linux hands back the IP header too, so the
        // ICMP type/code sit at the end of the (fixed, 20-byte) IPv4 header.
        drop(listener);
        let icmp = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .expect("open a raw ICMP socket");
        icmp.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("ICMP read timeout");
        backend
            .inject("lo", &frame)
            .expect("inject to the closed port");

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut seen = None;
        while Instant::now() < deadline && seen.is_none() {
            let mut icmp_buf = [0u8; 2048];
            let Ok(read) = (&icmp).read(&mut icmp_buf) else {
                continue;
            };
            if read >= 22 && icmp_buf[20] == 3 {
                seen = Some((icmp_buf[20], icmp_buf[21]));
            }
        }

        assert_eq!(
            seen,
            Some((3, 3)),
            "the closed port answers ICMP destination unreachable / port unreachable"
        );

        // Part three: the kernel would emit a non-loopback destination on the
        // bound device (rig run 4), so the injector refuses it before opening a
        // socket, fail-closed.
        let off_host = ether_ipv4_udp_frame_to(Ipv4Addr::new(10, 255, 255, 254), port, b"stray");
        let refusal = backend.inject("lo", &off_host);
        assert!(
            matches!(refusal, Err(L4Error::WireWrite(_))),
            "an off-host destination is refused before any socket is opened"
        );
        assert_eq!(
            refusal,
            Err(L4Error::WireWrite(
                "linux loopback inject: destination is not a loopback address".to_string()
            ))
        );
    }
}
