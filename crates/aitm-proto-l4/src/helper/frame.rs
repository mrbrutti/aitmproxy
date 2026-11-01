//! Inject-frame target parser (spec §5.3, plan P1a.3).
//!
//! For every `Inject` the helper parses the frame **itself** and derives the
//! [`L4Target`] its guard checks from the bytes alone. It never trusts a
//! destination, port or protocol the peer claims, and the `interface` on the
//! target is the one the helper chose, never something read out of the frame.
//! Pure: no I/O, no system state, no panic on any input.
//!
//! # Order of checks
//!
//! 1. `frame.len() > max_len` is [`FrameError::Oversized`], decided on the
//!    length alone before a single byte is interpreted.
//! 2. A buffer too short to hold the link header **and** a minimal (20-byte)
//!    IPv4 header is [`FrameError::Truncated`], whatever its bytes say.
//! 3. The link header names the family ([`LinkType`]); anything but IPv4 or
//!    IPv6, or a family that disagrees with the IP version nibble behind it, is
//!    [`FrameError::NotIp`].
//! 4. The IP packet is decoded over the crate's one etherparse path (the same
//!    [`endpoints_of`] behind [`PacketSpec::endpoints`](crate::craft::PacketSpec::endpoints)).
//!    A header or transport header cut short — an IPv6 packet shorter than its
//!    40-byte header among them — is [`FrameError::Truncated`]; a header
//!    etherparse rejects is [`FrameError::NotIp`].
//! 5. A packet whose transport the guard cannot name (an unknown IP protocol,
//!    or a fragment whose transport header is in another packet) is
//!    [`FrameError::NoTransport`]. TCP and UDP yield a port; ICMP and ICMPv6
//!    are transports the guard names ([`L4Proto::Icmp`](crate::types::L4Proto::Icmp),
//!    [`L4Proto::IcmpV6`](crate::types::L4Proto::IcmpV6))
//!    and yield a target with no port.
//!
//! This is stricter than the core's own capture-side resolution, which files an
//! unnamed transport under [`L4Proto::Raw`](crate::types::L4Proto::Raw): on the
//! privilege boundary a frame the helper cannot place is refused, not guessed at.

use std::fmt;

use crate::craft::endpoints_of;
use crate::types::{L4Direction, L4Target};

/// The link-layer framing the helper will hand the frame to the kernel in,
/// which is the framing the frame must already carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// BSD/macOS loopback (`DLT_NULL`): a 4-byte host-order address-family
    /// word (`AF_INET` = 2, `AF_INET6` = 30 on macOS) before the IP header.
    Null,
    /// Ethernet II: a 14-byte header whose EtherType is IPv4 (`0x0800`) or
    /// IPv6 (`0x86DD`).
    Ethernet,
    /// No link header: the buffer starts at the IP version nibble.
    Raw,
}

/// Why an inject frame yields no target. Every variant is a refusal; none of
/// them is recoverable by the peer re-sending the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Too short for its link header, its IP header or its transport header.
    Truncated,
    /// Longer than the caller's `max_len`; carries the offending length.
    Oversized(usize),
    /// The link header or the version nibble names something other than IPv4
    /// or IPv6, or the IP header is malformed.
    NotIp,
    /// An IP packet whose transport the guard cannot name.
    NoTransport,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Truncated => f.write_str("inject frame is truncated"),
            FrameError::Oversized(len) => {
                write!(f, "inject frame of {len} bytes exceeds the limit")
            }
            FrameError::NotIp => f.write_str("inject frame carries no IP packet"),
            FrameError::NoTransport => {
                f.write_str("inject frame carries no transport the guard can name")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// `AF_INET` in a `DLT_NULL` address-family word.
const AF_INET: u32 = 2;
/// `AF_INET6` in a `DLT_NULL` address-family word, as macOS writes it.
const AF_INET6: u32 = 30;
/// Length of the `DLT_NULL` address-family word.
const NULL_HEADER_LEN: usize = 4;
/// Length of an Ethernet II header.
const ETHERNET_HEADER_LEN: usize = 14;
/// EtherType of IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType of IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// The smallest IPv4 header (no options). The smallest buffer the link header
/// can be followed by; an IPv6 header shorter than its fixed 40 bytes is the
/// decoder's `Len` error, [`FrameError::Truncated`].
const IPV4_MIN_HEADER_LEN: usize = 20;

/// The IP family a link header or version nibble names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// The family the IP version nibble of `first` names, if any.
    fn of_nibble(first: u8) -> Option<Self> {
        match first >> 4 {
            4 => Some(Family::V4),
            6 => Some(Family::V6),
            _ => None,
        }
    }
}

/// Derive the [`L4Target`] the helper's guard checks for an inject `frame` that
/// will go out on `interface` in `link` framing, or the reason it cannot be one.
///
/// `interface` is copied onto the target as given: the frame has no say in it.
/// `direction` is always [`L4Direction::Outbound`], an injection leaves the host.
///
/// # Errors
/// See [`FrameError`] and the module doc for the order the checks run in.
pub fn inject_target(
    interface: &str,
    link: LinkType,
    frame: &[u8],
    max_len: usize,
) -> Result<L4Target, FrameError> {
    if frame.len() > max_len {
        return Err(FrameError::Oversized(frame.len()));
    }
    let ip = strip_link(link, frame)?;
    let packet = etherparse::SlicedPacket::from_ip(ip).map_err(|e| match e {
        etherparse::err::packet::SliceError::Len(_) => FrameError::Truncated,
        _ => FrameError::NotIp,
    })?;
    let ep = endpoints_of(&packet);
    // unreachable by construction: `from_ip` yields only an IPv4 or IPv6 net
    // layer, and `endpoints_of` names a destination for both; the type still
    // carries an `Option`, and refusing is the right answer if that changed.
    let dst = ep.dst.ok_or(FrameError::NotIp)?;
    // TCP and UDP always come with their ports (`endpoints_of` reads both from
    // the same transport slice), so `dst_port` needs no check of its own.
    let proto = ep.proto.ok_or(FrameError::NoTransport)?;
    Ok(L4Target {
        interface: interface.to_string(),
        direction: L4Direction::Outbound,
        dst: Some(dst),
        dst_port: ep.dst_port,
        proto,
    })
}

/// The IP bytes behind `frame`'s link header, once the header is known to name
/// IPv4 or IPv6 and the version nibble behind it agrees. A buffer shorter than
/// the link header plus a minimal IPv4 header is [`FrameError::Truncated`]
/// before any byte of it is interpreted.
fn strip_link(link: LinkType, frame: &[u8]) -> Result<&[u8], FrameError> {
    let (claimed, ip) = match link {
        LinkType::Null => {
            let (af, ip) = split_header::<NULL_HEADER_LEN>(frame)?;
            let family = match u32::from_ne_bytes(*af) {
                AF_INET => Family::V4,
                AF_INET6 => Family::V6,
                _ => return Err(FrameError::NotIp),
            };
            (Some(family), ip)
        }
        LinkType::Ethernet => {
            let (header, ip) = split_header::<ETHERNET_HEADER_LEN>(frame)?;
            let family = match u16::from_be_bytes([header[12], header[13]]) {
                ETHERTYPE_IPV4 => Family::V4,
                ETHERTYPE_IPV6 => Family::V6,
                _ => return Err(FrameError::NotIp),
            };
            (Some(family), ip)
        }
        // No link header: the version nibble alone names the family.
        LinkType::Raw => (None, split_header::<0>(frame)?.1),
    };
    // `ip` holds at least a minimal IPv4 header, so its first byte is the
    // version nibble. A link header that disagrees with it means the kernel
    // would send something other than what we decoded: refused, not guessed.
    let nibble = ip
        .first()
        .copied()
        .and_then(Family::of_nibble)
        .ok_or(FrameError::NotIp)?;
    if claimed.is_some_and(|family| family != nibble) {
        return Err(FrameError::NotIp);
    }
    Ok(ip)
}

/// The first `N` bytes of `frame` as its link header and the rest as the IP
/// packet, or [`FrameError::Truncated`] when the buffer cannot hold the header
/// plus a minimal IPv4 header. Decided on lengths alone, before any byte is
/// interpreted.
fn split_header<const N: usize>(frame: &[u8]) -> Result<(&[u8; N], &[u8]), FrameError> {
    match frame.split_first_chunk::<N>() {
        Some((header, ip)) if ip.len() >= IPV4_MIN_HEADER_LEN => Ok((header, ip)),
        _ => Err(FrameError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{inject_target, FrameError, LinkType};
    use crate::craft::{EtherSpec, IcmpSpec, Ipv4Spec, Ipv6Spec, Layer, PacketSpec, UdpSpec};
    use crate::types::{L4Direction, L4Proto, L4Target};

    /// The inject ceiling every test below passes; a real `ScopeSet` carries
    /// `max_packet_bytes`, this is just a literal the tests can reason about.
    const MAX: usize = 1500;

    /// `ip` framed the way BSD/macOS `lo0` delivers it (`DLT_NULL`): a 4-byte
    /// host-order address-family word before the IP header.
    fn dlt_null(af: u32, ip: &[u8]) -> Vec<u8> {
        let mut out = af.to_ne_bytes().to_vec();
        out.extend_from_slice(ip);
        out
    }

    /// An IPv4/UDP packet 127.0.0.1:40000 → 127.0.0.1:`dst_port` with a 5-byte
    /// payload (no link header).
    fn v4_udp(dst_port: u16) -> Vec<u8> {
        PacketSpec {
            layers: vec![
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

    #[test]
    fn dlt_null_ipv4_udp_gives_the_literal_target() {
        let frame = dlt_null(2, &v4_udp(9053));
        assert_eq!(
            inject_target("lo0", LinkType::Null, &frame, MAX),
            Ok(L4Target {
                interface: "lo0".to_string(),
                direction: L4Direction::Outbound,
                dst: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                dst_port: Some(9053),
                proto: L4Proto::Udp,
            })
        );
    }

    #[test]
    fn ethernet_ipv6_udp_gives_the_v6_destination() {
        let frame = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv6(Ipv6Spec {
                    src: Some(Ipv6Addr::LOCALHOST),
                    dst: Some(Ipv6Addr::LOCALHOST),
                    ..Ipv6Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40_000),
                    dst_port: Some(9053),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds");
        let target = inject_target("lo", LinkType::Ethernet, &frame, MAX).expect("an IPv6 target");
        assert_eq!(target.dst, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(target.dst_port, Some(9053));
        assert_eq!(target.proto, L4Proto::Udp);
        assert_eq!(target.direction, L4Direction::Outbound);
        assert_eq!(target.interface, "lo");
    }

    #[test]
    fn raw_ipv4_udp_gives_the_target() {
        let target =
            inject_target("tun0", LinkType::Raw, &v4_udp(9053), MAX).expect("a raw IP target");
        assert_eq!(target.dst, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(target.dst_port, Some(9053));
        assert_eq!(target.proto, L4Proto::Udp);
    }

    #[test]
    fn ten_byte_buffer_is_truncated_under_every_link_type() {
        let ten = [0u8; 10];
        for link in [LinkType::Null, LinkType::Ethernet, LinkType::Raw] {
            assert_eq!(
                inject_target("lo0", link, &ten, MAX),
                Err(FrameError::Truncated),
                "{link:?}"
            );
        }
    }

    #[test]
    fn max_len_plus_one_is_oversized_before_anything_is_decoded() {
        // Oversized is decided on the length alone, before the link header or the
        // IP header is looked at: this buffer is also non-IP and would otherwise
        // be `NotIp`.
        let big = vec![0u8; MAX + 1];
        assert_eq!(
            inject_target("lo0", LinkType::Null, &big, MAX),
            Err(FrameError::Oversized(MAX + 1))
        );
        // Exactly `max_len` is not oversized; it fails later, on its content.
        let exact = vec![0u8; MAX];
        assert_eq!(
            inject_target("lo0", LinkType::Null, &exact, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn arp_ethernet_frame_is_not_ip() {
        // A 28-byte ARP body behind EtherType 0x0806 (bigger than a minimal IPv4
        // header, so this is refused on its EtherType, not on its length).
        let frame = PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec {
                    ethertype: Some(0x0806),
                    ..EtherSpec::default()
                }),
                Layer::Raw(vec![0u8; 28]),
            ],
        }
        .build()
        .expect("craft builds");
        assert_eq!(frame.len(), 42);
        assert_eq!(
            inject_target("en0", LinkType::Ethernet, &frame, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn dlt_null_unknown_family_is_not_ip() {
        // AF_UNIX (1) in front of a perfectly good IPv4 packet: the link header
        // says it is not IP, so it is not IP.
        let frame = dlt_null(1, &v4_udp(9053));
        assert_eq!(
            inject_target("lo0", LinkType::Null, &frame, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn dlt_null_family_disagreeing_with_the_version_nibble_is_not_ip() {
        // AF_INET6 (30 on macOS) in front of IPv4 bytes. The kernel would send
        // these as IPv6; whatever the bytes "decode" to is not what reaches the
        // wire, so the frame is refused rather than gated on a guess.
        let frame = dlt_null(30, &v4_udp(9053));
        assert_eq!(
            inject_target("lo0", LinkType::Null, &frame, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn raw_buffer_with_a_non_ip_version_nibble_is_not_ip() {
        let mut bytes = v4_udp(9053);
        bytes[0] = 0x75; // version 7
        assert_eq!(
            inject_target("tun0", LinkType::Raw, &bytes, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn dlt_null_icmp_is_a_target_without_a_port() {
        // ICMP is a transport the guard names (`L4Proto::Icmp`), so an echo
        // request is a target with no port, not `NoTransport`.
        let ip = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(8),
                    rest_of_header: Some(0x0001_0001),
                    ..IcmpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds");
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(2, &ip), MAX),
            Ok(L4Target {
                interface: "lo0".to_string(),
                direction: L4Direction::Outbound,
                dst: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                dst_port: None,
                proto: L4Proto::Icmp,
            })
        );
    }

    #[test]
    fn dlt_null_ipv4_with_a_truncated_udp_header_is_truncated() {
        // A full 20-byte IPv4 header, then only 4 of the 8 UDP header bytes.
        let whole = dlt_null(2, &v4_udp(9053));
        let cut = &whole[..4 + 20 + 4];
        assert_eq!(
            inject_target("lo0", LinkType::Null, cut, MAX),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn dlt_null_ipv4_with_an_unnamed_protocol_is_no_transport() {
        // IP protocol 253 (RFC 3692 experimental) over a payload: a network
        // layer the guard can place, but no transport it can name.
        let ip = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    protocol: Some(253),
                    ..Ipv4Spec::default()
                }),
                Layer::Raw(vec![0u8; 8]),
            ],
        }
        .build()
        .expect("craft builds");
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(2, &ip), MAX),
            Err(FrameError::NoTransport)
        );
    }

    #[test]
    fn interface_comes_from_the_caller_never_the_frame() {
        // Same bytes, two interfaces: the target names whichever the helper
        // chose, there is nothing in the frame that could override it.
        let frame = dlt_null(2, &v4_udp(9053));
        let a = inject_target("lo0", LinkType::Null, &frame, MAX).expect("a target");
        let b = inject_target("en0", LinkType::Null, &frame, MAX).expect("a target");
        assert_eq!(a.interface, "lo0");
        assert_eq!(b.interface, "en0");
        assert_eq!(a.dst, b.dst);
    }

    #[test]
    fn display_names_no_command() {
        for (err, text) in [
            (FrameError::Truncated, "inject frame is truncated"),
            (
                FrameError::Oversized(1501),
                "inject frame of 1501 bytes exceeds the limit",
            ),
            (FrameError::NotIp, "inject frame carries no IP packet"),
            (
                FrameError::NoTransport,
                "inject frame carries no transport the guard can name",
            ),
        ] {
            assert_eq!(err.to_string(), text);
        }
    }

    // ---- Tester edge cases (stage 5, unit p1a) ----------------------------
    //
    // Hand-built headers, so the fields a hostile peer controls (lengths,
    // IHL, flags, next-header chains) can lie in ways `craft` keeps honest.

    use crate::craft::TcpSpec;

    /// An IPv4 header 127.0.0.1 → 127.0.0.1 with `ihl` words (options padded
    /// with NOPs), the given `total_len`, `protocol` and flags/fragment word.
    /// The checksum is left zero: etherparse does not verify it.
    fn ipv4_header(ihl: u8, total_len: u16, protocol: u8, flags_frag: u16) -> Vec<u8> {
        let mut h = vec![0x40 | (ihl & 0x0f), 0x00];
        h.extend_from_slice(&total_len.to_be_bytes());
        h.extend_from_slice(&[0x00, 0x01]);
        h.extend_from_slice(&flags_frag.to_be_bytes());
        h.extend_from_slice(&[64, protocol, 0, 0]);
        h.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
        if ihl > 5 {
            h.extend(std::iter::repeat_n(0x01u8, (usize::from(ihl) - 5) * 4));
        }
        h
    }

    /// A UDP header with the given length field and a zero checksum.
    fn udp_header(src: u16, dst: u16, len: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(&src.to_be_bytes());
        h.extend_from_slice(&dst.to_be_bytes());
        h.extend_from_slice(&len.to_be_bytes());
        h.extend_from_slice(&[0, 0]);
        h
    }

    /// A fixed IPv6 header ::1 → ::1 with `next_header` and `payload_len`.
    fn ipv6_header(next_header: u8, payload_len: u16) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0];
        h.extend_from_slice(&payload_len.to_be_bytes());
        h.push(next_header);
        h.push(64);
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        h
    }

    /// `header` then a UDP header 40000 → `dst_port` with `udp_len` and the
    /// payload `probe`.
    fn with_udp(mut header: Vec<u8>, dst_port: u16, udp_len: u16) -> Vec<u8> {
        header.extend_from_slice(&udp_header(40_000, dst_port, udp_len));
        header.extend_from_slice(b"probe");
        header
    }

    fn udp_target(interface: &str, dst: IpAddr, port: u16) -> L4Target {
        L4Target {
            interface: interface.to_string(),
            direction: L4Direction::Outbound,
            dst: Some(dst),
            dst_port: Some(port),
            proto: L4Proto::Udp,
        }
    }

    const V4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const V6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    #[test]
    fn tester_hand_built_headers_match_the_crafted_ones() {
        // The builders above must agree with `craft` on a plain IPv4/UDP
        // packet, or every assertion below would be testing the builders.
        let hand = with_udp(ipv4_header(5, 33, 17, 0), 9053, 13);
        assert_eq!(hand.len(), v4_udp(9053).len());
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &hand, MAX),
            inject_target("lo0", LinkType::Raw, &v4_udp(9053), MAX)
        );
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &hand, MAX),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
    }

    #[test]
    fn tester_empty_buffer_is_truncated_and_max_len_zero_refuses_any_byte() {
        for link in [LinkType::Null, LinkType::Ethernet, LinkType::Raw] {
            assert_eq!(
                inject_target("lo0", link, &[], MAX),
                Err(FrameError::Truncated),
                "{link:?}"
            );
            // `max_packet_bytes: 0`: nothing with a byte in it passes.
            assert_eq!(
                inject_target("lo0", link, &[0x45], 0),
                Err(FrameError::Oversized(1)),
                "{link:?}"
            );
            assert_eq!(
                inject_target("lo0", link, &v4_udp(9053), 0),
                Err(FrameError::Oversized(33)),
                "{link:?}"
            );
            // An empty buffer under a zero ceiling is not oversized; it is
            // truncated.
            assert_eq!(
                inject_target("lo0", link, &[], 0),
                Err(FrameError::Truncated),
                "{link:?}"
            );
        }
    }

    #[test]
    fn tester_ipv4_total_length_lying_about_the_buffer() {
        // Shorter than its own header.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 10, 17, 0), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // Longer than the buffer.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 65_535, 17, 0), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // Header only, though UDP bytes follow: the transport is outside the
        // packet the header describes.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 20, 17, 0), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // IP says 28 bytes but UDP says 13: the transport header overruns.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 28, 17, 0), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // IP says 28 and UDP says 8: consistent; the 5 trailing bytes past
        // `total_len` are not part of the packet and are ignored.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 28, 17, 0), 9053, 8),
                MAX
            ),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
        // Trailing bytes after a crafted packet (Ethernet padding) are ignored.
        let mut padded = dlt_null(2, &v4_udp(9053));
        padded.extend_from_slice(&[0u8; 10]);
        assert_eq!(
            inject_target("lo0", LinkType::Null, &padded, MAX),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
    }

    #[test]
    fn tester_ipv4_options_ihl_above_five() {
        // IHL 6: a 24-byte header with four NOP options, then UDP.
        let ihl6 = with_udp(ipv4_header(6, 37, 17, 0), 9053, 13);
        assert_eq!(ihl6.len(), 37);
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(2, &ihl6), MAX),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
        // IHL 15: the largest header, 60 bytes.
        let ihl15 = with_udp(ipv4_header(15, 73, 17, 0), 9053, 13);
        assert_eq!(ihl15.len(), 73);
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &ihl15, MAX),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
        // IHL 15 over a buffer that only holds 28 bytes: the options overrun.
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &ihl15[..28], MAX),
            Err(FrameError::Truncated)
        );
        // IHL 4 is below the minimum header: malformed, not IP.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(4, 33, 17, 0), 9053, 13),
                MAX
            ),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn tester_ipv4_fragments_are_no_transport() {
        // More Fragments set, offset 0: the first fragment carries a UDP
        // header, but the helper refuses to name a transport for a fragment.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 33, 17, 0x2000), 9053, 13),
                MAX
            ),
            Err(FrameError::NoTransport)
        );
        // A later fragment (offset 185 x 8), no MF.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 33, 17, 0x00b9), 9053, 13),
                MAX
            ),
            Err(FrameError::NoTransport)
        );
        // Don't Fragment alone is not a fragment.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv4_header(5, 33, 17, 0x4000), 9053, 13),
                MAX
            ),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
    }

    #[test]
    fn tester_ipv6_hop_by_hop_header_before_udp_gives_the_target() {
        // IPv6 (next 0) → Hop-by-Hop (next 17, one PadN option) → UDP.
        let mut ip = ipv6_header(0, 8 + 13);
        ip.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        let ip = with_udp(ip, 9053, 13);
        assert_eq!(ip.len(), 40 + 8 + 13);
        let want = Ok(udp_target("lo0", V6_LOOPBACK, 9053));
        assert_eq!(inject_target("lo0", LinkType::Raw, &ip, MAX), want);
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(30, &ip), MAX),
            want
        );
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x86DDu16.to_be_bytes());
        eth.extend_from_slice(&ip);
        assert_eq!(inject_target("lo0", LinkType::Ethernet, &eth, MAX), want);
        // Two chained extension headers: Hop-by-Hop → Destination Options → UDP.
        let mut ip = ipv6_header(0, 8 + 8 + 13);
        ip.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
        ip.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &with_udp(ip, 9053, 13), MAX),
            want
        );
    }

    #[test]
    fn tester_ipv6_fragment_header_is_no_transport() {
        // Fragment header (44): next 17, reserved, offset 0 with M set, id.
        let mut ip = ipv6_header(44, 8 + 13);
        ip.extend_from_slice(&[17, 0, 0x00, 0x01, 0, 0, 0, 4]);
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &with_udp(ip, 9053, 13), MAX),
            Err(FrameError::NoTransport)
        );
        // A later fragment: offset 181, M clear.
        let mut ip = ipv6_header(44, 8 + 13);
        ip.extend_from_slice(&[17, 0, 0x05, 0xa8, 0, 0, 0, 4]);
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &with_udp(ip, 9053, 13), MAX),
            Err(FrameError::NoTransport)
        );
    }

    #[test]
    fn tester_ipv6_payload_length_lying_about_the_buffer() {
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv6_header(17, 65_535), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // Shorter than a UDP header.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv6_header(17, 4), 9053, 13),
                MAX
            ),
            Err(FrameError::Truncated)
        );
        // Consistent (8-byte UDP, no payload) with 5 trailing bytes ignored.
        assert_eq!(
            inject_target(
                "lo0",
                LinkType::Raw,
                &with_udp(ipv6_header(17, 8), 9053, 8),
                MAX
            ),
            Ok(udp_target("lo0", V6_LOOPBACK, 9053))
        );
    }

    #[test]
    fn tester_ipv6_shorter_than_its_fixed_header_is_truncated() {
        // Long enough for the link header plus a minimal IPv4 header, so
        // `strip_link` passes, but short of the 40 IPv6 bytes it names.
        let short = &ipv6_header(17, 13)[..30];
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(30, short), MAX),
            Err(FrameError::Truncated)
        );
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &ipv6_header(17, 13)[..39], MAX),
            Err(FrameError::Truncated)
        );
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x86DDu16.to_be_bytes());
        eth.extend_from_slice(&ipv6_header(17, 13)[..39]);
        assert_eq!(
            inject_target("lo0", LinkType::Ethernet, &eth, MAX),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn tester_icmpv6_echo_is_a_target_without_a_port() {
        let mut ip = ipv6_header(58, 8);
        ip.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(30, &ip), MAX),
            Ok(L4Target {
                interface: "lo0".to_string(),
                direction: L4Direction::Outbound,
                dst: Some(V6_LOOPBACK),
                dst_port: None,
                proto: L4Proto::IcmpV6,
            })
        );
    }

    #[test]
    fn tester_tcp_syn_gives_a_tcp_target() {
        let ip = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(40_000),
                    dst_port: Some(9053),
                    flags: Some(0x02),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds");
        assert_eq!(
            inject_target("lo0", LinkType::Null, &dlt_null(2, &ip), MAX),
            Ok(L4Target {
                interface: "lo0".to_string(),
                direction: L4Direction::Outbound,
                dst: Some(V4_LOOPBACK),
                dst_port: Some(9053),
                proto: L4Proto::Tcp,
            })
        );
        // The same packet with its TCP header cut to 10 of 20 bytes.
        let cut = &dlt_null(2, &ip)[..4 + 20 + 10];
        assert_eq!(
            inject_target("lo0", LinkType::Null, cut, MAX),
            Err(FrameError::Truncated)
        );
    }

    #[test]
    fn tester_vlan_tag_and_mismatched_ethertype_are_not_ip() {
        // 802.1Q: EtherType 0x8100, then a tag whose inner type is IPv4. The
        // helper does not look through tags; the kernel would send a VLAN frame.
        let mut vlan = vec![0u8; 12];
        vlan.extend_from_slice(&0x8100u16.to_be_bytes());
        vlan.extend_from_slice(&[0x00, 0x01, 0x08, 0x00]);
        vlan.extend_from_slice(&v4_udp(9053));
        assert_eq!(
            inject_target("en0", LinkType::Ethernet, &vlan, MAX),
            Err(FrameError::NotIp)
        );
        // EtherType IPv6 over IPv4 bytes, and IPv4 over IPv6 bytes.
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x86DDu16.to_be_bytes());
        eth.extend_from_slice(&v4_udp(9053));
        assert_eq!(
            inject_target("en0", LinkType::Ethernet, &eth, MAX),
            Err(FrameError::NotIp)
        );
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&with_udp(ipv6_header(17, 13), 9053, 13));
        assert_eq!(
            inject_target("en0", LinkType::Ethernet, &eth, MAX),
            Err(FrameError::NotIp)
        );
    }

    #[test]
    fn tester_udp_length_field_edge_cases() {
        let udp = |length: Option<u16>| {
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::LOCALHOST),
                        dst: Some(Ipv4Addr::LOCALHOST),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Udp(UdpSpec {
                        src_port: Some(40_000),
                        dst_port: Some(9053),
                        length,
                        ..UdpSpec::default()
                    }),
                    Layer::Raw(b"probe".to_vec()),
                ],
            }
            .build()
            .expect("craft builds")
        };
        // A UDP length past the packet overruns: truncated.
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &udp(Some(1000)), MAX),
            Err(FrameError::Truncated)
        );
        // Below the 8-byte header: truncated.
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &udp(Some(4)), MAX),
            Err(FrameError::Truncated)
        );
        // Zero (RFC 8085 UDP-Lite style): etherparse takes the slice length.
        assert_eq!(
            inject_target("lo0", LinkType::Raw, &udp(Some(0)), MAX),
            Ok(udp_target("lo0", V4_LOOPBACK, 9053))
        );
    }
}
