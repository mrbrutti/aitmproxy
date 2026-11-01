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
//!    [`FrameError::NotIp`]. An IPv6 packet shorter than its 40-byte header is
//!    [`FrameError::Truncated`].
//! 4. The IP packet is decoded over the crate's one etherparse path (the same
//!    [`endpoints_of`] behind [`PacketSpec::endpoints`](crate::craft::PacketSpec::endpoints)).
//!    A header or transport header cut short is [`FrameError::Truncated`]; a
//!    header etherparse rejects is [`FrameError::NotIp`].
//! 5. A packet whose transport the guard cannot name (an unknown IP protocol,
//!    or a fragment whose transport header is in another packet) is
//!    [`FrameError::NoTransport`]. TCP and UDP yield a port; ICMP and ICMPv6
//!    are transports the guard names ([`L4Proto::Icmp`], [`L4Proto::IcmpV6`])
//!    and yield a target with no port.
//!
//! This is stricter than the core's own capture-side resolution, which files an
//! unnamed transport under [`L4Proto::Raw`]: on the privilege boundary a frame
//! the helper cannot place is refused, not guessed at.

use std::fmt;

use crate::craft::endpoints_of;
use crate::types::{L4Direction, L4Proto, L4Target};

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
/// The smallest IPv4 header (no options).
const IPV4_MIN_HEADER_LEN: usize = 20;
/// The fixed IPv6 header.
const IPV6_HEADER_LEN: usize = 40;

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

    /// The smallest header this family can carry.
    fn min_header_len(self) -> usize {
        match self {
            Family::V4 => IPV4_MIN_HEADER_LEN,
            Family::V6 => IPV6_HEADER_LEN,
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
    let (family, ip) = strip_link(link, frame)?;
    // The link header named a family; the bytes behind it must agree, or what
    // the kernel sends is not what we decoded. (`strip_link` guarantees at
    // least a minimal IPv4 header is present, so the first byte exists.)
    if ip.first().copied().and_then(Family::of_nibble) != Some(family) {
        return Err(FrameError::NotIp);
    }
    if ip.len() < family.min_header_len() {
        return Err(FrameError::Truncated);
    }

    let packet = etherparse::SlicedPacket::from_ip(ip).map_err(|e| match e {
        etherparse::err::packet::SliceError::Len(_) => FrameError::Truncated,
        _ => FrameError::NotIp,
    })?;
    let ep = endpoints_of(&packet);
    let dst = ep.dst.ok_or(FrameError::NotIp)?;
    let proto = ep.proto.ok_or(FrameError::NoTransport)?;
    if matches!(proto, L4Proto::Tcp | L4Proto::Udp) && ep.dst_port.is_none() {
        return Err(FrameError::NoTransport);
    }
    Ok(L4Target {
        interface: interface.to_string(),
        direction: L4Direction::Outbound,
        dst: Some(dst),
        dst_port: ep.dst_port,
        proto,
    })
}

/// Split `frame` into the family its link header names and the IP bytes behind
/// it. A buffer shorter than the link header plus a minimal IPv4 header is
/// [`FrameError::Truncated`] before any of it is read.
fn strip_link(link: LinkType, frame: &[u8]) -> Result<(Family, &[u8]), FrameError> {
    let header_len = match link {
        LinkType::Null => NULL_HEADER_LEN,
        LinkType::Ethernet => ETHERNET_HEADER_LEN,
        LinkType::Raw => 0,
    };
    if frame.len() < header_len + IPV4_MIN_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    let (header, ip) = frame.split_at(header_len);
    let family = match link {
        LinkType::Null => {
            let af = u32::from_ne_bytes(header.try_into().map_err(|_| FrameError::Truncated)?);
            match af {
                AF_INET => Family::V4,
                AF_INET6 => Family::V6,
                _ => return Err(FrameError::NotIp),
            }
        }
        LinkType::Ethernet => {
            let ethertype = match header.get(12..14) {
                Some([hi, lo]) => u16::from_be_bytes([*hi, *lo]),
                _ => return Err(FrameError::Truncated),
            };
            match ethertype {
                ETHERTYPE_IPV4 => Family::V4,
                ETHERTYPE_IPV6 => Family::V6,
                _ => return Err(FrameError::NotIp),
            }
        }
        LinkType::Raw => ip
            .first()
            .copied()
            .and_then(Family::of_nibble)
            .ok_or(FrameError::NotIp)?,
    };
    Ok((family, ip))
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
}
