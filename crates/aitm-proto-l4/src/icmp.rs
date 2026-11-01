//! Read-only packet views for the scanner's L4 packet lane (scanner v2 track
//! T5, spec D8.4), named for its first function.
//!
//! A captured or crafted [`L4Packet`] is wire-derived and therefore hostile:
//! every function here returns `None` / `false` on anything undecodable and
//! never panics, slices or does arithmetic that could. All parsing goes
//! through `crate::craft::parse_frame` (L3-first frames, Ethernet and the
//! BSD/macOS loopback address-family word) and `etherparse` slices, so
//! `etherparse` stays inside this crate.
//!
//! Nothing here sends, injects or needs privilege: these are views over bytes
//! the guarded capture path already produced.

use std::fmt;
use std::net::IpAddr;

use etherparse::TransportSlice;

use crate::craft::{endpoints_of, parse_frame};
use crate::flow::L4Packet;
use crate::types::L4Proto;

/// The ICMPv4 `(type, code)` of `pkt`, or `None` when its transport is not
/// ICMPv4 or the frame does not decode.
///
/// This is the oracle's reading of an `Other` reply: a closed UDP port's
/// port-unreachable is `(3, 3)`, so the lane records the pair in
/// `L4Evidence.oracle` (spec D8.4).
///
/// ICMPv6 yields `None` in v2 — the acceptance criterion covers IPv4 and no
/// caller classifies ICMPv6 type numbers yet.
#[must_use]
pub fn icmp_error(pkt: &L4Packet) -> Option<(u8, u8)> {
    match parse_frame(&pkt.bytes)?.transport? {
        TransportSlice::Icmpv4(icmp) => Some((icmp.type_u8(), icmp.code_u8())),
        _ => None,
    }
}

/// Whether `pkt` is a TCP segment with the `RST` flag set — a closed TCP
/// port's kernel reply, which the oracle classifies as `reset` (spec D8.4).
///
/// `false` for every other transport and for a frame that does not decode.
#[must_use]
pub fn tcp_rst(pkt: &L4Packet) -> bool {
    match parse_frame(&pkt.bytes).and_then(|frame| frame.transport) {
        Some(TransportSlice::Tcp(tcp)) => tcp.rst(),
        _ => false,
    }
}

/// A TCP or UDP packet's endpoints together with its transport payload: the
/// bytes above the transport header, borrowed from the packet.
///
/// `Debug` is hand-written and prints the payload as a length, never its
/// contents, so a captured payload cannot reach a log through a derived
/// formatter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportPayload<'a> {
    /// Network-layer source address.
    pub src: IpAddr,
    /// Transport source port.
    pub src_port: u16,
    /// Network-layer destination address.
    pub dst: IpAddr,
    /// Transport destination port.
    pub dst_port: u16,
    /// Transport the payload rides on: [`L4Proto::Tcp`] or [`L4Proto::Udp`].
    pub proto: L4Proto,
    /// The payload bytes above the transport header.
    pub payload: &'a [u8],
}

impl fmt::Debug for TransportPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportPayload")
            .field("src", &self.src)
            .field("src_port", &self.src_port)
            .field("dst", &self.dst)
            .field("dst_port", &self.dst_port)
            .field("proto", &self.proto)
            .field("payload", &format_args!("<{} bytes>", self.payload.len()))
            .finish()
    }
}

/// The endpoints and transport payload of a TCP or UDP packet, or `None` for
/// any other transport, a frame that does not decode, or one missing a
/// network layer.
///
/// [`PacketSpec::endpoints`](crate::craft::PacketSpec::endpoints) gives the
/// addresses and ports; the payload slice is what it lacks and what the lane
/// needs for captured-flow seeds and for reading a reply's bytes (spec D8.4).
#[must_use]
pub fn transport_payload(pkt: &L4Packet) -> Option<TransportPayload<'_>> {
    let frame = parse_frame(&pkt.bytes)?;
    let payload = match &frame.transport {
        Some(TransportSlice::Tcp(tcp)) => tcp.payload(),
        Some(TransportSlice::Udp(udp)) => udp.payload(),
        _ => return None,
    };
    let ends = endpoints_of(&frame);
    Some(TransportPayload {
        src: ends.src?,
        src_port: ends.src_port?,
        dst: ends.dst?,
        dst_port: ends.dst_port?,
        proto: ends.proto?,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use super::{icmp_error, tcp_rst, transport_payload, TransportPayload};
    use crate::craft::{IcmpSpec, Ipv4Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
    use crate::flow::L4Packet;
    use crate::types::{L4Direction, L4Proto};

    /// An inbound captured packet carrying `bytes`, the shape `send_recv`
    /// hands the lane.
    fn captured(bytes: Vec<u8>) -> L4Packet {
        L4Packet {
            dir: L4Direction::Inbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        }
    }

    /// An ICMPv4 destination-unreachable / port-unreachable frame, the kernel
    /// reply a closed UDP port gives (spec AC T5-2a).
    fn port_unreachable_bytes() -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(3),
                    code: Some(3),
                    rest_of_header: Some(0),
                    ..IcmpSpec::default()
                }),
                Layer::Raw(vec![0u8; 28]),
            ],
        }
        .build()
        .expect("craft builds the port-unreachable frame")
    }

    #[test]
    fn icmp_port_unreachable_yields_3_3() {
        let pkt = captured(port_unreachable_bytes());
        assert_eq!(icmp_error(&pkt), Some((3, 3)));
        assert!(!tcp_rst(&pkt));
    }

    #[test]
    fn icmp_behind_loopback_af_word() {
        let mut bytes = vec![2u8, 0, 0, 0];
        bytes.extend_from_slice(&port_unreachable_bytes());
        let pkt = captured(bytes);
        assert_eq!(icmp_error(&pkt), Some((3, 3)));
    }

    #[test]
    fn udp_is_not_icmp() {
        let bytes = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds the UDP frame");
        let pkt = captured(bytes);

        assert_eq!(icmp_error(&pkt), None);
        assert!(!tcp_rst(&pkt));
        assert_eq!(
            transport_payload(&pkt),
            Some(TransportPayload {
                src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                src_port: 40000,
                dst: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                dst_port: 9,
                proto: L4Proto::Udp,
                payload: b"probe",
            })
        );
    }

    #[test]
    fn tcp_rst_detects_reset() {
        let frame = |flags: u8| {
            captured(
                PacketSpec {
                    layers: vec![
                        Layer::Ipv4(Ipv4Spec::default()),
                        Layer::Tcp(TcpSpec {
                            flags: Some(flags),
                            ..TcpSpec::default()
                        }),
                    ],
                }
                .build()
                .expect("craft builds the TCP frame"),
            )
        };

        // RST|ACK — the kernel's reply to a SYN at a closed TCP port.
        let reset = frame(0x14);
        assert!(tcp_rst(&reset));
        assert_eq!(icmp_error(&reset), None);
        assert_eq!(
            transport_payload(&reset).map(|p| p.proto),
            Some(L4Proto::Tcp)
        );

        // SYN alone is not a reset.
        assert!(!tcp_rst(&frame(0x02)));
    }

    #[test]
    fn garbage_never_panics() {
        for bytes in [vec![], vec![0x45], vec![0xff; 60], vec![0x45; 20]] {
            let pkt = captured(bytes);
            assert_eq!(icmp_error(&pkt), None, "{:?}", pkt.bytes);
            assert!(!tcp_rst(&pkt), "{:?}", pkt.bytes);
            assert_eq!(transport_payload(&pkt), None, "{:?}", pkt.bytes);
        }
    }

    /// A hand-written 20-byte IPv4 header `127.0.0.1 -> 127.0.0.1` with the
    /// given `ihl` nibble, protocol and declared total length; the checksum is
    /// left zero (the parser does not verify it).
    fn ipv4_header(ihl: u8, protocol: u8, total_length: u16) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x40 | (ihl & 0x0f);
        h[2..4].copy_from_slice(&total_length.to_be_bytes());
        h[8] = 64;
        h[9] = protocol;
        h[12..16].copy_from_slice(&[127, 0, 0, 1]);
        h[16..20].copy_from_slice(&[127, 0, 0, 1]);
        h
    }

    /// Tester (stage 5): hostile reply frames — truncated ICMP, a header
    /// length that overruns the frame, a total length that lies both ways, an
    /// Ethernet header over nothing, an AF word over garbage — all read as
    /// "not decodable", never as a type/code or a payload, and never panic.
    #[test]
    fn hostile_frames_yield_none() {
        // IPv4 says ICMP, but only two ICMP bytes follow (ICMP needs eight).
        let mut truncated_icmp = ipv4_header(5, 1, 22);
        truncated_icmp.extend_from_slice(&[3, 3]);
        // `ihl` 15 claims a 60-byte header over a 20-byte frame.
        let mut long_ihl = ipv4_header(15, 17, 60);
        long_ihl.extend_from_slice(&[0u8; 40]);
        // Total length claims more bytes than the frame carries.
        let mut long_total = ipv4_header(5, 17, 200);
        long_total.extend_from_slice(&[0u8; 13]);
        // Total length claims fewer bytes than a UDP header needs.
        let mut short_total = ipv4_header(5, 17, 24);
        short_total
            .extend_from_slice(&[0x9c, 0x40, 0, 9, 0, 13, 0, 0, b'p', b'r', b'o', b'b', b'e']);
        // An Ethernet header announcing IPv4 over ten bytes.
        let mut ether_truncated = vec![0u8; 12];
        ether_truncated.extend_from_slice(&[0x08, 0x00]);
        ether_truncated.extend_from_slice(&[0x45; 10]);
        // The BSD loopback AF word in front of garbage.
        let mut af_garbage = vec![2u8, 0, 0, 0];
        af_garbage.extend_from_slice(&[0xff; 30]);
        // The AF word in front of a truncated IPv4 header.
        let mut af_truncated = vec![2u8, 0, 0, 0];
        af_truncated.extend_from_slice(&ipv4_header(5, 17, 33)[..12]);
        // An IPv4 header alone, protocol UDP, nothing after it.
        let bare_header = ipv4_header(5, 17, 20);

        for (name, bytes) in [
            ("truncated icmp", truncated_icmp),
            ("ihl 15 over 20 bytes", long_ihl),
            ("total_length > frame", long_total),
            ("total_length < udp header", short_total),
            ("ethernet over 10 bytes", ether_truncated),
            ("af word + garbage", af_garbage),
            ("af word + truncated ipv4", af_truncated),
            ("bare ipv4 header, protocol udp", bare_header),
            ("version nibble 7", vec![0x75; 40]),
            ("version nibble 0", vec![0x05; 40]),
        ] {
            let pkt = captured(bytes);
            assert_eq!(icmp_error(&pkt), None, "{name}");
            assert!(!tcp_rst(&pkt), "{name}");
            assert_eq!(transport_payload(&pkt), None, "{name}");
        }
    }

    /// Tester (stage 5): ICMPv6 is documented as `None` in v2 — a real
    /// `::1` port-unreachable (type 1, code 4) must not be mistaken for an
    /// IPv4 pair, and it carries no transport payload either.
    #[test]
    fn icmpv6_yields_none_in_v2() {
        let mut bytes = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        bytes.extend_from_slice(&[0u8; 15]);
        bytes.push(1); // src ::1
        bytes.extend_from_slice(&[0u8; 15]);
        bytes.push(1); // dst ::1
        bytes.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0]); // ICMPv6 dst-unreachable / port
        assert_eq!(bytes.len(), 48);
        assert_eq!(
            PacketSpec::summarize(&bytes).layers,
            vec!["IPv6".to_string(), "ICMPv6".to_string()],
            "the frame itself decodes as ICMPv6; only the v2 reading is None"
        );

        let pkt = captured(bytes);
        assert_eq!(icmp_error(&pkt), None);
        assert!(!tcp_rst(&pkt));
        assert_eq!(transport_payload(&pkt), None);
    }

    /// Tester (stage 5): a zero-length UDP datagram is a decodable packet with
    /// an empty payload — the shape an echo of an empty seed comes back as.
    #[test]
    fn zero_length_udp_has_an_empty_payload() {
        let bytes = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(9),
                    dst_port: Some(40000),
                    ..UdpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds the empty datagram");
        assert_eq!(bytes.len(), 28);

        let pkt = captured(bytes);
        assert_eq!(
            transport_payload(&pkt),
            Some(TransportPayload {
                src: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                src_port: 9,
                dst: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                dst_port: 40000,
                proto: L4Proto::Udp,
                payload: b"",
            })
        );
        assert_eq!(icmp_error(&pkt), None);
        assert!(!tcp_rst(&pkt));
        assert_eq!(
            format!("{:?}", transport_payload(&pkt).expect("decodes")),
            "TransportPayload { src: 127.0.0.1, src_port: 9, dst: 127.0.0.1, dst_port: 40000, proto: Udp, payload: <0 bytes> }"
        );
    }

    /// Tester (stage 5): the loopback AF word in front of a TCP reset and an
    /// Ethernet header in front of a UDP datagram both decode — the two link
    /// framings the lane sends on.
    #[test]
    fn link_framings_decode_for_every_view() {
        let rst = PacketSpec {
            layers: vec![
                Layer::Raw(vec![2, 0, 0, 0]),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(80),
                    dst_port: Some(40000),
                    flags: Some(0x14),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds the framed reset");
        let pkt = captured(rst);
        assert!(tcp_rst(&pkt));
        assert_eq!(
            transport_payload(&pkt).map(|t| (t.src_port, t.dst_port, t.payload.len())),
            Some((80, 40000, 0))
        );

        let udp = PacketSpec {
            layers: vec![
                Layer::Ether(crate::craft::EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(9),
                    dst_port: Some(40000),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"echo".to_vec()),
            ],
        }
        .build()
        .expect("craft builds the ethernet datagram");
        let pkt = captured(udp);
        assert_eq!(icmp_error(&pkt), None);
        assert_eq!(
            transport_payload(&pkt).map(|t| t.payload),
            Some(&b"echo"[..])
        );
    }
}
