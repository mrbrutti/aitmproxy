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
            if inject_path(cfg!(target_os = "linux"), iface, &devices) == InjectPath::RawIp {
                return inject_ip_packet(bytes);
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

/// The IP packet inside `frame`: the bytes after a 14-byte Ethernet header whose
/// ethertype is IPv4 (`0x0800`) or IPv6 (`0x86DD`), or `frame` itself when it
/// already starts with an IP version nibble and is long enough to hold that
/// version's fixed header. Anything else is [`no_ip_packet`].
fn strip_link_header(frame: &[u8]) -> Result<&[u8], L4Error> {
    const IPV4_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    let is_ip_packet = |bytes: &[u8]| match bytes.first().map(|b| b >> 4) {
        Some(4) => bytes.len() >= IPV4_HEADER_LEN,
        Some(6) => bytes.len() >= IPV6_HEADER_LEN,
        _ => false,
    };

    if frame.len() > 14 && matches!(&frame[12..14], [0x08, 0x00] | [0x86, 0xDD]) {
        let packet = &frame[14..];
        return is_ip_packet(packet)
            .then_some(packet)
            .ok_or_else(no_ip_packet);
    }
    is_ip_packet(frame)
        .then_some(frame)
        .ok_or_else(no_ip_packet)
}

/// The packet's own destination, read out of its IP header — IPv4 bytes 16..20,
/// IPv6 bytes 24..40. Port 0: a raw `IPPROTO_RAW` socket routes on the header it
/// is handed, the address only selects the route.
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

/// Write one IP packet through a header-included raw socket — the Linux loopback
/// injection path (module docs). Fail-closed: every socket error becomes
/// [`L4Error::WireWrite`], and no payload byte reaches the message.
fn inject_ip_packet(frame: &[u8]) -> Result<(), L4Error> {
    /// `IPPROTO_RAW`: the kernel sends the packet's own header verbatim.
    const IPPROTO_RAW: i32 = 255;

    let packet = strip_link_header(frame)?;
    let dst = ip_destination(packet)?;

    let wire_write = |context: &str, e: &std::io::Error| {
        L4Error::WireWrite(format!("linux loopback inject: {context}: {e}"))
    };

    let domain = if dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))
        .map_err(|e| wire_write("raw socket", &e))?;
    if dst.is_ipv4() {
        socket
            .set_header_included_v4(true)
            .map_err(|e| wire_write("IP_HDRINCL", &e))?;
    } else {
        socket
            .set_header_included_v6(true)
            .map_err(|e| wire_write("IPV6_HDRINCL", &e))?;
    }

    let written = socket
        .send_to(packet, &SockAddr::from(dst))
        .map_err(|e| wire_write("send_to", &e))?;
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
        PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
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

    /// Pinned: a frame that is already an IP packet is passed through verbatim —
    /// the stripper keys on the ethertype, not on a fixed offset.
    #[test]
    fn strip_link_header_leaves_an_l3_first_frame_unchanged() {
        let frame = ether_ipv4_udp_frame(40001, b"probe");
        let l3 = frame[14..].to_vec();

        let packet = strip_link_header(&l3).expect("an L3-first frame decodes");

        assert_eq!(packet, &l3[..], "an L3-first frame is injected as it is");
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
    /// silent. Needs `CAP_NET_RAW`: unprivileged, `inject` is `L4Unavailable` and
    /// the test skips through the crate's fail-closed path.
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
    }
}
