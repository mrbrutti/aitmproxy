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
}
