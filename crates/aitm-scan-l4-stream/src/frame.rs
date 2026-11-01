//! The hand-rolled transport payload extractor over captured `L4Packet` bytes (spec S8).
//!
//! A captured frame arrives in one of the three shapes `aitm_proto_l4::craft`'s
//! `parse_frame` handles: an Ethernet frame from a real NIC, a bare IP packet
//! (our own crafted frames start at L3), or a BSD/macOS loopback frame with a
//! 4-byte address-family word before the IP header. `PacketSummary.layers`
//! names the link layer when there is one, so `"Ethernet"` as the first layer
//! picks the Ethernet path and everything else is sniffed from the bytes.
//!
//! The corpus builder (spec S4) feeds this hostile input: bytes a target chose.
//! Every index goes through `get(..)` and every length arithmetic through
//! `checked_*`, so a truncated or self-inconsistent frame is `None` and never a
//! panic (child criterion C12). Only TCP and UDP payloads are seeds.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aitm_proto_l4::types::L4Proto;

/// Bytes of the Ethernet II header before the payload.
const ETHERNET_HEADER_LEN: usize = 14;
/// Offset of the EtherType field within an Ethernet II header.
const ETHERTYPE_OFFSET: usize = 12;
/// EtherType for IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Bytes of the BSD/macOS loopback (`DLT_NULL`/`DLT_LOOP`) address-family word.
const AF_WORD_LEN: usize = 4;
/// The address-family values a loopback capture writes: `AF_INET` and the
/// several platforms' `AF_INET6` (`craft.rs`'s loopback case).
const AF_WORDS: [u32; 4] = [2, 24, 28, 30];
/// Smallest legal IPv4 header (IHL 5).
const IPV4_MIN_HEADER_LEN: usize = 20;
/// The IPv6 header is fixed-size; anything else is an extension header.
const IPV6_HEADER_LEN: usize = 40;
/// Smallest legal TCP header (data offset 5).
const TCP_MIN_DATA_OFFSET: usize = 5;
/// The fixed UDP header length, included in the UDP length field.
const UDP_HEADER_LEN: usize = 8;
/// IP protocol number for TCP.
const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
const IPPROTO_UDP: u8 = 17;

/// The transport payload of one captured frame and where it was going.
///
/// `payload` borrows the captured frame: the corpus copies out of it only the
/// seeds it keeps. `Debug` prints the payload as its length, never its bytes
/// (spec S9, child criterion C11).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FramePayload<'a> {
    /// Destination address of the enclosing IP packet.
    pub dst: IpAddr,
    /// Destination port of the transport header.
    pub dst_port: u16,
    /// Source port of the transport header.
    pub src_port: u16,
    /// Transport protocol: only [`L4Proto::Tcp`] and [`L4Proto::Udp`] are built.
    pub proto: L4Proto,
    /// The transport payload, bounded by the frame's own declared lengths.
    pub payload: &'a [u8],
}

impl fmt::Debug for FramePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramePayload")
            .field("dst", &self.dst)
            .field("dst_port", &self.dst_port)
            .field("src_port", &self.src_port)
            .field("proto", &self.proto)
            .field("payload", &format_args!("<{} bytes>", self.payload.len()))
            .finish()
    }
}

/// Extract the TCP or UDP payload of one captured frame, or `None`.
///
/// `bytes` is `L4Packet.bytes` as captured and `layers` is the matching
/// `PacketSummary.layers`; only the first layer is read, to tell an Ethernet
/// frame from a bare IP or loopback one. `None` means "not a seed": a
/// non-IP frame, a protocol other than TCP/UDP, an IPv6 extension header, or
/// any truncation or inconsistency in the headers.
#[must_use]
pub fn transport_payload<'a>(bytes: &'a [u8], layers: &[String]) -> Option<FramePayload<'a>> {
    if layers.first().map(String::as_str) == Some("Ethernet") {
        let ethertype = u16::from_be_bytes([
            *bytes.get(ETHERTYPE_OFFSET)?,
            *bytes.get(ETHERTYPE_OFFSET.checked_add(1)?)?,
        ]);
        let rest = bytes.get(ETHERNET_HEADER_LEN..)?;
        return match ethertype {
            ETHERTYPE_IPV4 => ipv4_packet(rest),
            ETHERTYPE_IPV6 => ipv6_packet(rest),
            _ => None,
        };
    }
    // No link layer named: a BSD loopback AF word, else a bare IP packet.
    let rest = strip_af_word(bytes).unwrap_or(bytes);
    ip_packet(rest)
}

/// Strip a BSD/macOS loopback address-family word when one is present.
///
/// The word is an `AF_*` value in host byte order, so both orders are accepted;
/// to avoid eating the first four bytes of a bare IP packet, the byte after the
/// word must itself start an IP header (version nibble 4 or 6).
fn strip_af_word(bytes: &[u8]) -> Option<&[u8]> {
    let word: [u8; AF_WORD_LEN] = bytes.get(..AF_WORD_LEN)?.try_into().ok()?;
    let big = u32::from_be_bytes(word);
    let little = u32::from_le_bytes(word);
    if !AF_WORDS.contains(&big) && !AF_WORDS.contains(&little) {
        return None;
    }
    let rest = bytes.get(AF_WORD_LEN..)?;
    if is_ip_version_nibble(*rest.first()?) {
        Some(rest)
    } else {
        None
    }
}

/// Whether a byte's high nibble is an IP version this extractor reads.
fn is_ip_version_nibble(first: u8) -> bool {
    matches!(first >> 4, 4 | 6)
}

/// Dispatch a bare IP packet on its version nibble.
fn ip_packet(packet: &[u8]) -> Option<FramePayload<'_>> {
    match packet.first()? >> 4 {
        4 => ipv4_packet(packet),
        6 => ipv6_packet(packet),
        _ => None,
    }
}

/// IPv4: header length from IHL, payload bounded by the total length field.
fn ipv4_packet(packet: &[u8]) -> Option<FramePayload<'_>> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f).checked_mul(4)?;
    if header_len < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if total_len < header_len {
        return None;
    }
    let protocol = *packet.get(9)?;
    let dst = IpAddr::V4(Ipv4Addr::new(
        *packet.get(16)?,
        *packet.get(17)?,
        *packet.get(18)?,
        *packet.get(19)?,
    ));
    // Honour the declared total length when the capture holds that many bytes;
    // a short capture yields the bytes that are there, never a read past them.
    let end = total_len.min(packet.len());
    let segment = packet.get(header_len..end)?;
    transport(protocol, dst, segment)
}

/// IPv6: a fixed 40-byte header, payload bounded by the payload-length field.
/// A next header other than TCP or UDP (an extension header included) is `None`.
fn ipv6_packet(packet: &[u8]) -> Option<FramePayload<'_>> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
    let next_header = *packet.get(6)?;
    let raw: [u8; 16] = packet.get(24..IPV6_HEADER_LEN)?.try_into().ok()?;
    let dst = IpAddr::V6(Ipv6Addr::from(raw));
    let after_header = packet.get(IPV6_HEADER_LEN..)?;
    let end = payload_len.min(after_header.len());
    let segment = after_header.get(..end)?;
    transport(next_header, dst, segment)
}

/// Dispatch the transport header; only TCP and UDP carry seeds.
fn transport(protocol: u8, dst: IpAddr, segment: &[u8]) -> Option<FramePayload<'_>> {
    match protocol {
        IPPROTO_TCP => tcp_payload(dst, segment),
        IPPROTO_UDP => udp_payload(dst, segment),
        _ => None,
    }
}

/// TCP: header length from the data offset nibble (`>= 5` 32-bit words).
fn tcp_payload(dst: IpAddr, segment: &[u8]) -> Option<FramePayload<'_>> {
    let src_port = u16::from_be_bytes([*segment.first()?, *segment.get(1)?]);
    let dst_port = u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]);
    let data_offset = usize::from(segment.get(12)? >> 4);
    if data_offset < TCP_MIN_DATA_OFFSET {
        return None;
    }
    let header_len = data_offset.checked_mul(4)?;
    let payload = segment.get(header_len..)?;
    Some(FramePayload {
        dst,
        dst_port,
        src_port,
        proto: L4Proto::Tcp,
        payload,
    })
}

/// UDP: an 8-byte header whose length field is honoured when it fits.
fn udp_payload(dst: IpAddr, segment: &[u8]) -> Option<FramePayload<'_>> {
    let src_port = u16::from_be_bytes([*segment.first()?, *segment.get(1)?]);
    let dst_port = u16::from_be_bytes([*segment.get(2)?, *segment.get(3)?]);
    let declared = usize::from(u16::from_be_bytes([*segment.get(4)?, *segment.get(5)?]));
    let body = segment.get(UDP_HEADER_LEN..)?;
    // A length below the header size is self-inconsistent; a length past the
    // captured bytes is a short capture, so take what is there.
    let declared_body = declared.checked_sub(UDP_HEADER_LEN)?;
    let payload = body.get(..declared_body.min(body.len()))?;
    Some(FramePayload {
        dst,
        dst_port,
        src_port,
        proto: L4Proto::Udp,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use aitm_proto_l4::types::L4Proto;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    fn ethernet() -> Vec<String> {
        vec!["Ethernet".to_string()]
    }

    /// 14 (Ethernet) + 20 (IPv4) + 20 (TCP) + 5 bytes to `10.0.0.9:9000`.
    fn ethernet_ipv4_tcp_frame() -> Vec<u8> {
        vec![
            // Ethernet: dst MAC, src MAC, ethertype IPv4.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, //
            0x08, 0x00, //
            // IPv4: v4/IHL 5, DSCP, total length 45.
            0x45, 0x00, 0x00, 0x2d, //
            0x1c, 0x46, 0x40, 0x00, // id, flags
            0x40, 0x06, 0x00, 0x00, // ttl 64, proto 6 (TCP), checksum
            0xc0, 0xa8, 0x01, 0x05, // src 192.168.1.5
            0x0a, 0x00, 0x00, 0x09, // dst 10.0.0.9
            // TCP: src 51000, dst 9000.
            0xc7, 0x38, 0x23, 0x28, //
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x02, // ack
            0x50, 0x18, // data offset 5, PSH|ACK
            0x20, 0x00, // window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
            // Payload.
            b'h', b'e', b'l', b'l', b'o',
        ]
    }

    #[test]
    fn ethernet_ipv4_tcp() {
        let frame = ethernet_ipv4_tcp_frame();
        assert_eq!(frame.len(), 59);

        let got = transport_payload(&frame, &ethernet()).expect("frame is extractable");

        assert_eq!(got.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(got.dst_port, 9000);
        assert_eq!(got.src_port, 51000);
        assert_eq!(got.proto, L4Proto::Tcp);
        assert_eq!(got.payload, b"hello");
    }

    #[test]
    fn bare_ipv4_udp() {
        // 20 (IPv4) + 8 (UDP) + 3 bytes to `10.0.0.9:53`, no link layer.
        let frame: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x1f, // v4/IHL 5, total length 31
            0x00, 0x01, 0x00, 0x00, //
            0x40, 0x11, 0x00, 0x00, // ttl 64, proto 17 (UDP), checksum
            0x7f, 0x00, 0x00, 0x01, // src 127.0.0.1
            0x0a, 0x00, 0x00, 0x09, // dst 10.0.0.9
            0x9c, 0x40, 0x00, 0x35, // src 40000, dst 53
            0x00, 0x0b, 0x00, 0x00, // UDP length 11, checksum
            0xde, 0xad, 0xbe, // payload
        ];
        assert_eq!(frame.len(), 31);

        let got = transport_payload(&frame, &["IPv4".to_string(), "UDP".to_string()])
            .expect("frame is extractable");

        assert_eq!(got.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(got.dst_port, 53);
        assert_eq!(got.src_port, 40000);
        assert_eq!(got.proto, L4Proto::Udp);
        assert_eq!(got.payload, &[0xde, 0xad, 0xbe]);
    }

    #[test]
    fn bsd_loopback_ipv6_tcp() {
        // 4 (BSD AF word) + 40 (IPv6) + 20 (TCP) + 2 bytes to `[2001:db8::9]:7777`.
        let frame: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, // AF word, little-endian
            0x60, 0x00, 0x00, 0x00, // v6, traffic class, flow label
            0x00, 0x16, // payload length 22
            0x06, // next header 6 (TCP)
            0x40, // hop limit
            // src 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, //
            // dst 2001:db8::9
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09, //
            // TCP: src 1234, dst 7777.
            0x04, 0xd2, 0x1e, 0x61, //
            0x00, 0x00, 0x00, 0x03, // seq
            0x00, 0x00, 0x00, 0x04, // ack
            0x50, 0x10, // data offset 5, ACK
            0x20, 0x00, // window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
            0xfa, 0xce, // payload
        ];
        assert_eq!(frame.len(), 66);

        // A loopback capture has no link layer in `PacketSummary.layers`.
        let got = transport_payload(&frame, &["IPv6".to_string(), "TCP".to_string()])
            .expect("frame is extractable");

        assert_eq!(
            got.dst,
            IpAddr::V6("2001:db8::9".parse::<Ipv6Addr>().expect("literal address"))
        );
        assert_eq!(got.dst_port, 7777);
        assert_eq!(got.src_port, 1234);
        assert_eq!(got.proto, L4Proto::Tcp);
        assert_eq!(got.payload, &[0xfa, 0xce]);
    }

    #[test]
    fn arp_and_extension_headers_are_none() {
        // Ethernet + ARP (ethertype 0x0806): not an IP packet.
        let mut arp: Vec<u8> = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, //
            0x08, 0x06, // ethertype ARP
        ];
        arp.extend_from_slice(&[
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // ARP body
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x0a, 0x00, 0x00, 0x01, //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x09, //
        ]);
        assert_eq!(arp.len(), 42);
        assert!(transport_payload(&arp, &ethernet()).is_none());
        assert!(transport_payload(&arp, &[]).is_none());

        // IPv6 with a hop-by-hop extension header (next header 0) is unusable.
        let mut hbh: Vec<u8> = vec![
            0x60, 0x00, 0x00, 0x00, //
            0x00, 0x1c, // payload length 28
            0x00, // next header 0 (hop-by-hop)
            0x40, //
        ];
        hbh.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        hbh.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
        ]);
        hbh.extend_from_slice(&[
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hop-by-hop option
        ]);
        hbh.extend_from_slice(&[
            0x04, 0xd2, 0x1e, 0x61, 0, 0, 0, 3, 0, 0, 0, 4, 0x50, 0x10, 0x20, 0x00, 0, 0, 0, 0,
        ]);
        assert_eq!(hbh.len(), 68);
        assert!(transport_payload(&hbh, &["IPv6".to_string(), "TCP".to_string()]).is_none());
    }

    #[test]
    fn truncations_never_panic() {
        let frame = ethernet_ipv4_tcp_frame();
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            match transport_payload(prefix, &ethernet()) {
                None => {}
                Some(got) => assert!(
                    got.payload.len() < 5,
                    "prefix of {len} bytes yielded a full payload"
                ),
            }
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = ChaCha8Rng::seed_from_u64(0x5EED_5EED);
        let mut buf = [0u8; 128];
        for _ in 0..10_000 {
            let len = rng.random_range(0..=128usize);
            let bytes = &mut buf[..len];
            rng.fill_bytes(bytes);
            let _ = transport_payload(bytes, &ethernet());
            let _ = transport_payload(bytes, &[]);
        }
    }
}
