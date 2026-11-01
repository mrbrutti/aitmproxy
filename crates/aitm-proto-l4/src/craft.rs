//! Pure, sans-IO packet craft (M5 Task 2).
//!
//! A scapy-style layered [`PacketSpec`] compiles to on-wire bytes with
//! [`PacketSpec::build`]. Crafting is **pure**: no I/O, no privilege, no guard —
//! building bytes is not sending them (the guard gates the wire, M5 Tasks 4–6).
//!
//! Every per-layer `*Spec` field is an `Option`: `None` auto-completes the field
//! the way scapy does (checksums, lengths, next-protocol numbers are inferred),
//! while `Some(v)` is written **verbatim — including a deliberately-wrong value**.
//! That verbatim path is the whole point of an L4 fuzzing tool: a forced-bad
//! checksum or length must reach the wire unchanged, never "fixed" (M5-AC7).
//!
//! The builder uses `pnet_packet`'s mutable field-level views, which expose every
//! header field and therefore let malformed packets be expressed; [`summarize`]
//! uses `etherparse`'s structural parser to name the layers of a byte buffer.
//! The same [`PacketSpec`] is the YAML form used in PoCs/scripts and the shape the
//! Rhai `l4.*` verbs build — one layered model, learned once.
//!
//! [`summarize`]: PacketSpec::summarize

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// Hard ceiling on a crafted packet, independent of the guard's configurable
/// `max_packet_bytes` (which bounds *injection*, M5 Task 5). This is the pure
/// builder's own sanity cap, at the IPv4 total-length limit.
const MAX_PACKET_BYTES: usize = 65_535;

/// A scapy-style packet: an ordered stack of layers, outermost first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PacketSpec {
    /// Layers in wire order (e.g. `[Ipv4, Udp, Raw]`). The payload of a layer is
    /// everything stacked after it.
    pub layers: Vec<Layer>,
}

/// One layer of a [`PacketSpec`]. `Raw` places arbitrary bytes — an unnamed
/// protocol or an opaque payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Ethernet II frame header.
    Ether(EtherSpec),
    /// IPv4 network header.
    Ipv4(Ipv4Spec),
    /// IPv6 network header.
    Ipv6(Ipv6Spec),
    /// TCP transport header.
    Tcp(TcpSpec),
    /// UDP transport header.
    Udp(UdpSpec),
    /// ICMP (v4) header.
    Icmp(IcmpSpec),
    /// Arbitrary payload bytes / any unnamed protocol.
    Raw(Vec<u8>),
}

/// Ethernet II header. `None` fields auto-complete (ethertype from the next
/// layer; addresses default to all-zero).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EtherSpec {
    /// Source MAC.
    pub src: Option<[u8; 6]>,
    /// Destination MAC.
    pub dst: Option<[u8; 6]>,
    /// EtherType; `None` ⇒ inferred from the next layer.
    pub ethertype: Option<u16>,
}

/// IPv4 header. Every field is `Option`: `None` ⇒ computed/auto-completed,
/// `Some` ⇒ verbatim (**may be invalid** — that is intentional).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv4Spec {
    /// Source address; `None` ⇒ `0.0.0.0`.
    pub src: Option<Ipv4Addr>,
    /// Destination address; `None` ⇒ `0.0.0.0`.
    pub dst: Option<Ipv4Addr>,
    /// Time-to-live; `None` ⇒ `64`.
    pub ttl: Option<u8>,
    /// IP protocol number; `None` ⇒ inferred from the next layer.
    pub protocol: Option<u8>,
    /// Internet header length (32-bit words); `None` ⇒ `5`, `Some` ⇒ verbatim.
    pub ihl: Option<u8>,
    /// Differentiated-services codepoint.
    pub dscp: Option<u8>,
    /// Explicit-congestion-notification bits.
    pub ecn: Option<u8>,
    /// Identification field.
    pub identification: Option<u16>,
    /// Total length; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub total_length: Option<u16>,
    /// Flags (3 bits); `None` ⇒ `0`.
    pub flags: Option<u8>,
    /// Fragment offset.
    pub fragment_offset: Option<u16>,
    /// Header checksum; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub checksum: Option<u16>,
}

/// IPv6 header (no checksum at this layer).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv6Spec {
    /// Source address; `None` ⇒ `::`.
    pub src: Option<Ipv6Addr>,
    /// Destination address; `None` ⇒ `::`.
    pub dst: Option<Ipv6Addr>,
    /// Hop limit; `None` ⇒ `64`.
    pub hop_limit: Option<u8>,
    /// Next-header protocol number; `None` ⇒ inferred from the next layer.
    pub next_header: Option<u8>,
    /// Traffic class.
    pub traffic_class: Option<u8>,
    /// Flow label (20 bits).
    pub flow_label: Option<u32>,
    /// Payload length; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub payload_length: Option<u16>,
}

/// TCP header.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpSpec {
    /// Source port; `None` ⇒ `0`.
    pub src_port: Option<u16>,
    /// Destination port; `None` ⇒ `0`.
    pub dst_port: Option<u16>,
    /// Sequence number.
    pub seq: Option<u32>,
    /// Acknowledgement number.
    pub ack: Option<u32>,
    /// Data offset (32-bit words); `None` ⇒ `5`.
    pub data_offset: Option<u8>,
    /// Control flags; `None` ⇒ `0`.
    pub flags: Option<u8>,
    /// Window size.
    pub window: Option<u16>,
    /// Checksum; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub checksum: Option<u16>,
    /// Urgent pointer.
    pub urgent_ptr: Option<u16>,
}

/// UDP header.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpSpec {
    /// Source port; `None` ⇒ `0`.
    pub src_port: Option<u16>,
    /// Destination port; `None` ⇒ `0`.
    pub dst_port: Option<u16>,
    /// Length; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub length: Option<u16>,
    /// Checksum; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub checksum: Option<u16>,
}

/// ICMP (v4) header. The 4-byte rest-of-header can be set explicitly or carried
/// by a following `Raw` payload.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IcmpSpec {
    /// ICMP type; `None` ⇒ `0` (echo reply).
    pub icmp_type: Option<u8>,
    /// ICMP code; `None` ⇒ `0`.
    pub code: Option<u8>,
    /// Checksum; `None` ⇒ computed, `Some` ⇒ verbatim (may be wrong).
    pub checksum: Option<u16>,
    /// The 4-byte rest-of-header word; prepended to the payload when `Some`.
    pub rest_of_header: Option<u32>,
}

/// A human-readable summary of a byte buffer: the layer names it parses into and
/// its length.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PacketSummary {
    /// Layer names, outermost first (e.g. `["IPv4", "UDP"]`).
    pub layers: Vec<String>,
    /// Total byte length of the buffer.
    pub length: usize,
}

/// The endpoints a byte buffer decodes to: transport name, addresses and ports.
/// Every field is `None` when that layer is absent or undecodable, so the whole
/// value is [`PacketEndpoints::default`] for a buffer that is not a packet.
/// Field names match [`PacketSpec`]'s (`src_port` / `dst_port`), so a packet
/// read back from a flow can seed the craft editor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacketEndpoints {
    /// Transport name, the same names [`PacketSpec::summarize`] uses:
    /// `"TCP"`, `"UDP"`, `"ICMP"` or `"ICMPv6"`.
    pub proto: Option<&'static str>,
    /// Network-layer source address.
    pub src: Option<IpAddr>,
    /// Network-layer destination address.
    pub dst: Option<IpAddr>,
    /// Source port, TCP and UDP only.
    pub src_port: Option<u16>,
    /// Destination port, TCP and UDP only.
    pub dst_port: Option<u16>,
}

/// Errors from the pure craft path. No I/O, so these are structural only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CraftError {
    /// The crafted packet exceeds [`MAX_PACKET_BYTES`].
    #[error("crafted packet exceeds {max} bytes")]
    TooLarge {
        /// The ceiling that was exceeded.
        max: usize,
    },
    /// The layer stack is empty or ordered in a way the builder cannot encode.
    #[error("bad layer order: {0}")]
    BadLayerOrder(String),
}

impl PacketSpec {
    /// Compile the layered spec to on-wire bytes: auto-complete every `None`,
    /// preserve every `Some` verbatim, and return the frame. Pure — no I/O, no
    /// privilege, no guard. Size-capped by [`CraftError::TooLarge`].
    ///
    /// # Errors
    /// [`CraftError::BadLayerOrder`] if the stack is empty; [`CraftError::TooLarge`]
    /// if the result exceeds [`MAX_PACKET_BYTES`].
    pub fn build(&self) -> Result<Vec<u8>, CraftError> {
        if self.layers.is_empty() {
            return Err(CraftError::BadLayerOrder("empty packet spec".to_string()));
        }
        let ip_ctx = self.ip_context();
        let bytes = build_layers(&self.layers, ip_ctx)?;
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(CraftError::TooLarge {
                max: MAX_PACKET_BYTES,
            });
        }
        Ok(bytes)
    }

    /// The transport protocol this spec declares, read from its layer stack — the
    /// proto the guard uses for port matching and a `send_recv` reply must share.
    /// `Raw` when the spec declares no transport layer.
    #[must_use]
    pub fn transport_proto(&self) -> crate::types::L4Proto {
        use crate::types::L4Proto;
        for layer in &self.layers {
            match layer {
                Layer::Tcp(_) => return L4Proto::Tcp,
                Layer::Udp(_) => return L4Proto::Udp,
                Layer::Icmp(_) => return L4Proto::Icmp,
                _ => {}
            }
        }
        L4Proto::Raw
    }

    /// Parse `bytes` structurally and name its layers. Never fails: unparseable
    /// input yields an empty layer list with the correct length.
    #[must_use]
    pub fn summarize(bytes: &[u8]) -> PacketSummary {
        use etherparse::{NetSlice, TransportSlice};

        let mut layers = Vec::new();
        if let Some(p) = parse_frame(bytes) {
            if p.link.is_some() {
                layers.push("Ethernet".to_string());
            }
            match &p.net {
                Some(NetSlice::Ipv4(_)) => layers.push("IPv4".to_string()),
                Some(NetSlice::Ipv6(_)) => layers.push("IPv6".to_string()),
                _ => {}
            }
            match &p.transport {
                Some(TransportSlice::Tcp(_)) => layers.push("TCP".to_string()),
                Some(TransportSlice::Udp(_)) => layers.push("UDP".to_string()),
                Some(TransportSlice::Icmpv4(_)) => layers.push("ICMP".to_string()),
                Some(TransportSlice::Icmpv6(_)) => layers.push("ICMPv6".to_string()),
                _ => {}
            }
        }

        PacketSummary {
            layers,
            length: bytes.len(),
        }
    }

    /// Decode the addresses and ports of `bytes` over the same frame parser as
    /// [`summarize`](PacketSpec::summarize). Never fails and never panics: an
    /// undecodable buffer returns [`PacketEndpoints::default`].
    #[must_use]
    pub fn endpoints(bytes: &[u8]) -> PacketEndpoints {
        use etherparse::{NetSlice, TransportSlice};

        let mut out = PacketEndpoints::default();
        let Some(p) = parse_frame(bytes) else {
            return out;
        };
        match &p.net {
            Some(NetSlice::Ipv4(v4)) => {
                let h = v4.header();
                out.src = Some(IpAddr::V4(h.source_addr()));
                out.dst = Some(IpAddr::V4(h.destination_addr()));
            }
            Some(NetSlice::Ipv6(v6)) => {
                let h = v6.header();
                out.src = Some(IpAddr::V6(h.source_addr()));
                out.dst = Some(IpAddr::V6(h.destination_addr()));
            }
            _ => {}
        }
        match &p.transport {
            Some(TransportSlice::Tcp(t)) => {
                out.proto = Some("TCP");
                out.src_port = Some(t.source_port());
                out.dst_port = Some(t.destination_port());
            }
            Some(TransportSlice::Udp(u)) => {
                out.proto = Some("UDP");
                out.src_port = Some(u.source_port());
                out.dst_port = Some(u.destination_port());
            }
            Some(TransportSlice::Icmpv4(_)) => out.proto = Some("ICMP"),
            Some(TransportSlice::Icmpv6(_)) => out.proto = Some("ICMPv6"),
            _ => {}
        }
        out
    }

    /// The first network layer's addresses, used as the pseudo-header for
    /// transport checksums. Matches the defaults `build` writes, so an
    /// auto-completed transport checksum is computed over the bytes that ship.
    fn ip_context(&self) -> Option<IpCtx> {
        for layer in &self.layers {
            match layer {
                Layer::Ipv4(s) => {
                    return Some(IpCtx::V4 {
                        src: s.src.unwrap_or(Ipv4Addr::UNSPECIFIED),
                        dst: s.dst.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    });
                }
                Layer::Ipv6(s) => {
                    return Some(IpCtx::V6 {
                        src: s.src.unwrap_or(Ipv6Addr::UNSPECIFIED),
                        dst: s.dst.unwrap_or(Ipv6Addr::UNSPECIFIED),
                    });
                }
                _ => {}
            }
        }
        None
    }
}

/// Parse a frame whose link layer is not known in advance into an
/// [`etherparse::SlicedPacket`] carrying a network layer, or `None`.
///
/// Our own crafted frames start at L3 (IP); a real NIC delivers L2 Ethernet; BSD/
/// macOS loopback (`DLT_NULL`/`DLT_LOOP`) prepends a 4-byte address-family word
/// before the IP header. A first-byte nibble check alone misreads a real Ethernet
/// frame whose destination MAC starts with an IP-looking nibble (`0x4_`/`0x6_`) as
/// raw IP, so when the frame is Ethernet-plausible — its EtherType field names a known
/// L3 protocol — Ethernet is tried first; otherwise L3 IP, then plain Ethernet (an
/// uncommon EtherType), then the loopback form, keeping the first that yields a net
/// layer. (The ambiguity is only fully removable with the capture handle's datalink
/// type; this disambiguates on the EtherType field, which the reported first-nibble
/// collision ignored.)
pub(crate) fn parse_frame(frame: &[u8]) -> Option<etherparse::SlicedPacket<'_>> {
    use etherparse::SlicedPacket;
    let is_ip_nibble = |b: u8| matches!(b >> 4, 4 | 6);

    // Ethernet-plausible: at least a 14-byte header with a known L3 EtherType at
    // bytes 12..14 (IPv4 `0x0800`, IPv6 `0x86DD`, ARP `0x0806`).
    if frame.len() >= 14 {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if matches!(ethertype, 0x0800 | 0x86DD | 0x0806) {
            if let Ok(p) = SlicedPacket::from_ethernet(frame) {
                if p.net.is_some() {
                    return Some(p);
                }
            }
        }
    }
    // Our own crafted frames start at L3 (IP).
    if frame.first().copied().is_some_and(is_ip_nibble) {
        if let Ok(p) = SlicedPacket::from_ip(frame) {
            if p.net.is_some() {
                return Some(p);
            }
        }
    }
    // A real NIC frame with an uncommon EtherType, still Ethernet.
    if let Ok(p) = SlicedPacket::from_ethernet(frame) {
        if p.net.is_some() {
            return Some(p);
        }
    }
    // BSD/macOS loopback: a 4-byte AF word before the IP header.
    if frame.len() > 4 && is_ip_nibble(frame[4]) {
        if let Ok(p) = SlicedPacket::from_ip(&frame[4..]) {
            if p.net.is_some() {
                return Some(p);
            }
        }
    }
    None
}

/// The enclosing network-layer addresses, resolved once, for transport-layer
/// pseudo-header checksums.
#[derive(Debug, Clone, Copy)]
enum IpCtx {
    V4 { src: Ipv4Addr, dst: Ipv4Addr },
    V6 { src: Ipv6Addr, dst: Ipv6Addr },
}

/// Build a layer stack recursively: a layer's payload is every layer after it.
fn build_layers(layers: &[Layer], ip_ctx: Option<IpCtx>) -> Result<Vec<u8>, CraftError> {
    let (head, rest) = layers
        .split_first()
        .expect("build_layers is only called with a non-empty slice");
    let payload = if rest.is_empty() {
        Vec::new()
    } else {
        build_layers(rest, ip_ctx)?
    };
    build_layer(head, payload, rest.first(), ip_ctx)
}

/// Build one layer's header over its already-built payload.
fn build_layer(
    layer: &Layer,
    payload: Vec<u8>,
    next: Option<&Layer>,
    ip_ctx: Option<IpCtx>,
) -> Result<Vec<u8>, CraftError> {
    match layer {
        Layer::Raw(bytes) => {
            let mut out = bytes.clone();
            out.extend_from_slice(&payload);
            Ok(out)
        }
        Layer::Ether(s) => Ok(build_ether(s, &payload, next)),
        Layer::Ipv4(s) => build_ipv4(s, &payload, next),
        Layer::Ipv6(s) => build_ipv6(s, &payload, next),
        Layer::Tcp(s) => build_tcp(s, &payload, ip_ctx),
        Layer::Udp(s) => build_udp(s, &payload, ip_ctx),
        Layer::Icmp(s) => build_icmp(s, &payload),
    }
}

/// IP protocol number implied by the next layer, when a spec omits `protocol`.
fn ip_proto_for(next: Option<&Layer>) -> u8 {
    match next {
        Some(Layer::Tcp(_)) => 6,
        Some(Layer::Udp(_)) => 17,
        Some(Layer::Icmp(_)) => 1,
        Some(Layer::Ipv4(_)) => 4,  // IP-in-IP
        Some(Layer::Ipv6(_)) => 41, // IPv6 encapsulation
        Some(Layer::Ether(_)) | Some(Layer::Raw(_)) | None => 0,
    }
}

/// EtherType implied by the next layer, when a spec omits `ethertype`.
fn ethertype_for(next: Option<&Layer>) -> u16 {
    match next {
        Some(Layer::Ipv4(_)) => 0x0800,
        Some(Layer::Ipv6(_)) => 0x86DD,
        _ => 0,
    }
}

/// Ethernet II header. It has no computed field, so it is laid out directly;
/// `pnet_packet` is reserved for layers with checksums/lengths to auto-complete.
fn build_ether(s: &EtherSpec, payload: &[u8], next: Option<&Layer>) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&s.dst.unwrap_or([0u8; 6]));
    out.extend_from_slice(&s.src.unwrap_or([0u8; 6]));
    out.extend_from_slice(
        &s.ethertype
            .unwrap_or_else(|| ethertype_for(next))
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// IPv4 header: auto-complete total length / protocol / checksum unless the spec
/// pins them, in which case the pinned (possibly invalid) value ships verbatim.
fn build_ipv4(s: &Ipv4Spec, payload: &[u8], next: Option<&Layer>) -> Result<Vec<u8>, CraftError> {
    use pnet_packet::ip::IpNextHeaderProtocol;
    use pnet_packet::ipv4::{checksum, MutableIpv4Packet};

    let total = 20 + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut p = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer is >= 20 bytes");
        p.set_version(4);
        p.set_header_length(s.ihl.unwrap_or(5));
        p.set_dscp(s.dscp.unwrap_or(0));
        p.set_ecn(s.ecn.unwrap_or(0));
        p.set_total_length(s.total_length.unwrap_or(total as u16));
        p.set_identification(s.identification.unwrap_or(0));
        p.set_flags(s.flags.unwrap_or(0));
        p.set_fragment_offset(s.fragment_offset.unwrap_or(0));
        p.set_ttl(s.ttl.unwrap_or(64));
        p.set_next_level_protocol(IpNextHeaderProtocol(
            s.protocol.unwrap_or_else(|| ip_proto_for(next)),
        ));
        p.set_source(s.src.unwrap_or(Ipv4Addr::UNSPECIFIED));
        p.set_destination(s.dst.unwrap_or(Ipv4Addr::UNSPECIFIED));
        p.set_payload(payload);
        // `None` ⇒ computed over the header just written; `Some` ⇒ verbatim.
        let csum = s.checksum.unwrap_or_else(|| checksum(&p.to_immutable()));
        p.set_checksum(csum);
    }
    Ok(buf)
}

/// IPv6 header (no checksum at this layer).
fn build_ipv6(s: &Ipv6Spec, payload: &[u8], next: Option<&Layer>) -> Result<Vec<u8>, CraftError> {
    use pnet_packet::ip::IpNextHeaderProtocol;
    use pnet_packet::ipv6::MutableIpv6Packet;

    let total = 40 + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut p = MutableIpv6Packet::new(&mut buf).expect("ipv6 buffer is >= 40 bytes");
        p.set_version(6);
        p.set_traffic_class(s.traffic_class.unwrap_or(0));
        p.set_flow_label(s.flow_label.unwrap_or(0));
        p.set_payload_length(s.payload_length.unwrap_or(payload.len() as u16));
        p.set_next_header(IpNextHeaderProtocol(
            s.next_header.unwrap_or_else(|| ip_proto_for(next)),
        ));
        p.set_hop_limit(s.hop_limit.unwrap_or(64));
        p.set_source(s.src.unwrap_or(Ipv6Addr::UNSPECIFIED));
        p.set_destination(s.dst.unwrap_or(Ipv6Addr::UNSPECIFIED));
        p.set_payload(payload);
    }
    Ok(buf)
}

/// TCP header; checksum uses the enclosing IP pseudo-header when auto-completed.
fn build_tcp(s: &TcpSpec, payload: &[u8], ip_ctx: Option<IpCtx>) -> Result<Vec<u8>, CraftError> {
    use pnet_packet::tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket};

    let total = 20 + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut p = MutableTcpPacket::new(&mut buf).expect("tcp buffer is >= 20 bytes");
        p.set_source(s.src_port.unwrap_or(0));
        p.set_destination(s.dst_port.unwrap_or(0));
        p.set_sequence(s.seq.unwrap_or(0));
        p.set_acknowledgement(s.ack.unwrap_or(0));
        p.set_data_offset(s.data_offset.unwrap_or(5));
        p.set_flags(s.flags.unwrap_or(0));
        p.set_window(s.window.unwrap_or(0));
        p.set_urgent_ptr(s.urgent_ptr.unwrap_or(0));
        p.set_payload(payload);
        let csum = s.checksum.unwrap_or_else(|| match ip_ctx {
            Some(IpCtx::V4 { src, dst }) => ipv4_checksum(&p.to_immutable(), &src, &dst),
            Some(IpCtx::V6 { src, dst }) => ipv6_checksum(&p.to_immutable(), &src, &dst),
            None => 0,
        });
        p.set_checksum(csum);
    }
    Ok(buf)
}

/// UDP header; checksum uses the enclosing IP pseudo-header when auto-completed.
fn build_udp(s: &UdpSpec, payload: &[u8], ip_ctx: Option<IpCtx>) -> Result<Vec<u8>, CraftError> {
    use pnet_packet::udp::{ipv4_checksum, ipv6_checksum, MutableUdpPacket};

    let total = 8 + payload.len();
    let mut buf = vec![0u8; total];
    {
        let mut p = MutableUdpPacket::new(&mut buf).expect("udp buffer is >= 8 bytes");
        p.set_source(s.src_port.unwrap_or(0));
        p.set_destination(s.dst_port.unwrap_or(0));
        p.set_length(s.length.unwrap_or(total as u16));
        p.set_payload(payload);
        let csum = s.checksum.unwrap_or_else(|| match ip_ctx {
            Some(IpCtx::V4 { src, dst }) => ipv4_checksum(&p.to_immutable(), &src, &dst),
            Some(IpCtx::V6 { src, dst }) => ipv6_checksum(&p.to_immutable(), &src, &dst),
            None => 0,
        });
        p.set_checksum(csum);
    }
    Ok(buf)
}

/// ICMP (v4) header. The 4-byte rest-of-header word, when pinned, is prepended
/// to the payload the way scapy models it.
fn build_icmp(s: &IcmpSpec, payload: &[u8]) -> Result<Vec<u8>, CraftError> {
    use pnet_packet::icmp::{checksum, IcmpCode, IcmpType, MutableIcmpPacket};

    let mut body = Vec::with_capacity(4 + payload.len());
    if let Some(rest) = s.rest_of_header {
        body.extend_from_slice(&rest.to_be_bytes());
    }
    body.extend_from_slice(payload);

    let mut buf = vec![0u8; 4 + body.len()];
    {
        let mut p = MutableIcmpPacket::new(&mut buf).expect("icmp buffer is >= 4 bytes");
        p.set_icmp_type(IcmpType(s.icmp_type.unwrap_or(0)));
        p.set_icmp_code(IcmpCode(s.code.unwrap_or(0)));
        p.set_payload(&body);
        let csum = s.checksum.unwrap_or_else(|| checksum(&p.to_immutable()));
        p.set_checksum(csum);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M5-AC7: a deliberately-wrong `Some` field reaches the wire unchanged, and
    /// the corresponding `None` is auto-completed to the correct value. The two
    /// halves share one fixed input so the computed checksum is a literal.
    #[test]
    fn build_preserves_malformed_checksum() {
        // `[Ipv4{dst:127.0.0.1, checksum:Some(0x0000)}, Udp{dst_port:9}, Raw("probe")]`.
        let malformed = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    checksum: Some(0x0000),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        };
        let bytes = malformed.build().expect("craft builds");
        // IPv4 header checksum lives at bytes [10..12], big-endian.
        let csum = u16::from_be_bytes([bytes[10], bytes[11]]);
        assert_eq!(
            csum, 0x0000,
            "forced-malformed checksum must survive verbatim"
        );

        // Same packet, checksum auto-completed.
        let well_formed = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    checksum: None,
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        };
        let bytes = well_formed.build().expect("craft builds");
        let csum = u16::from_be_bytes([bytes[10], bytes[11]]);
        assert_eq!(
            csum, 0xFBCB,
            "omitted checksum must be auto-completed to the computed value"
        );
    }

    /// `summarize` names the layers of a crafted IPv4/UDP frame and reports its
    /// length — the parse half of the pure craft surface.
    #[test]
    fn summarize_names_crafted_layers() {
        let bytes = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds");

        let summary = PacketSpec::summarize(&bytes);
        assert_eq!(summary.length, bytes.len());
        assert_eq!(summary.layers, vec!["IPv4".to_string(), "UDP".to_string()]);
    }

    /// An empty spec is a structural error, not a panic or a zero-length frame.
    #[test]
    fn empty_spec_is_bad_layer_order() {
        let err = PacketSpec::default()
            .build()
            .expect_err("empty spec must error");
        assert!(matches!(err, CraftError::BadLayerOrder(_)));
    }

    /// A1: `endpoints` decodes the addresses and ports of a crafted IPv4/UDP
    /// frame — the pure half of `l4.flow.get`'s per-packet `proto/src/dst/
    /// src_port/dst_port` (L4PAR-AC1 groundwork).
    #[test]
    fn endpoints_of_crafted_ipv4_udp() {
        let bytes = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40000),
                    dst_port: Some(9053),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"hello-l4".to_vec()),
            ],
        }
        .build()
        .expect("craft builds");

        assert_eq!(
            PacketSpec::endpoints(&bytes),
            PacketEndpoints {
                proto: Some("UDP"),
                src: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                dst: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                src_port: Some(40000),
                dst_port: Some(9053),
            }
        );
    }

    /// A1: a buffer that decodes to no network layer yields the all-`None`
    /// default, never a panic.
    #[test]
    fn endpoints_of_undecodable_is_default() {
        assert_eq!(
            PacketSpec::endpoints(&[0xde, 0xad]),
            PacketEndpoints::default()
        );
    }

    /// A1: TCP carries ports, ICMP carries none, and IPv6 addresses are decoded
    /// — the proto names match `summarize`'s.
    #[test]
    fn endpoints_of_tcp_icmp_ipv6() {
        let tcp = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(10, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(10, 0, 0, 2)),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(1234),
                    dst_port: Some(80),
                    ..TcpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds");
        let e = PacketSpec::endpoints(&tcp);
        assert_eq!(e.proto, Some("TCP"));
        assert_eq!(e.src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(e.dst, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(e.src_port, Some(1234));
        assert_eq!(e.dst_port, Some(80));

        let icmp = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                // An echo request: type 8 with its id/seq word, so the ICMP
                // header is the 8 bytes every real ICMP message carries.
                Layer::Icmp(IcmpSpec {
                    icmp_type: Some(8),
                    rest_of_header: Some(0x0001_0001),
                    ..IcmpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds");
        let e = PacketSpec::endpoints(&icmp);
        assert_eq!(e.proto, Some("ICMP"));
        assert_eq!(e.dst, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(e.src_port, None);
        assert_eq!(e.dst_port, None);

        let v6 = PacketSpec {
            layers: vec![
                Layer::Ipv6(Ipv6Spec {
                    src: Some(Ipv6Addr::LOCALHOST),
                    dst: Some(Ipv6Addr::LOCALHOST),
                    ..Ipv6Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
            ],
        }
        .build()
        .expect("craft builds");
        let e = PacketSpec::endpoints(&v6);
        assert_eq!(e.proto, Some("UDP"));
        assert_eq!(e.src, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(e.dst, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(e.dst_port, Some(9));
    }
}
