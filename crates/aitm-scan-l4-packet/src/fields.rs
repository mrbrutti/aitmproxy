//! The field-path vocabulary, its pin table and the pure profile validator —
//! owned by scanner v2 track T5, plan task 2.
//!
//! A packet-lane point is one `(target, field path)` pair, so the field path is
//! the lane's whole vocabulary: it names what a case mutates, it is half of a
//! point id, and it decides the mutator table. Spec D8.4 pins the fields that
//! are **non-fuzzable by construction** — the destination, the source address
//! and the link layer (scapy's rule; source spoofing is refused) — and a
//! profile naming one of them is `invalid_profile`, which is why [`is_pinned`]
//! is checked before "unknown" in [`parse_field`].

use std::fmt;
use std::str::FromStr;

use aitm_scan_model::vocab::L4Transport;

/// Which IP version a target speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl IpVersion {
    /// The path prefix this version's fields carry (`ipv4` or `ipv6`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

/// The path prefix a transport's fields carry (`udp` or `tcp`).
const fn transport_name(transport: L4Transport) -> &'static str {
    match transport {
        L4Transport::Udp => "udp",
        L4Transport::Tcp => "tcp",
    }
}

/// A fuzzable IPv4 header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv4Field {
    /// Time to live.
    Ttl,
    /// Internet header length, in 32-bit words.
    Ihl,
    /// Total length, header included.
    TotalLength,
    /// The three-bit flags field (reserved, DF, MF).
    Flags,
    /// Fragment offset, in 8-byte units.
    FragmentOffset,
    /// Header checksum.
    Checksum,
    /// Transport protocol number.
    Protocol,
    /// Identification.
    Identification,
    /// Differentiated services code point.
    Dscp,
    /// Explicit congestion notification.
    Ecn,
}

impl Ipv4Field {
    /// Every IPv4 field, in the order the default table uses.
    pub const ALL: [Self; 10] = [
        Self::Ttl,
        Self::Ihl,
        Self::TotalLength,
        Self::Flags,
        Self::FragmentOffset,
        Self::Checksum,
        Self::Protocol,
        Self::Identification,
        Self::Dscp,
        Self::Ecn,
    ];

    /// The field's name inside the `ipv4.` path.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ttl => "ttl",
            Self::Ihl => "ihl",
            Self::TotalLength => "total_length",
            Self::Flags => "flags",
            Self::FragmentOffset => "fragment_offset",
            Self::Checksum => "checksum",
            Self::Protocol => "protocol",
            Self::Identification => "identification",
            Self::Dscp => "dscp",
            Self::Ecn => "ecn",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }
}

/// A fuzzable IPv6 header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ipv6Field {
    /// Hop limit (IPv6's TTL).
    HopLimit,
    /// Payload length.
    PayloadLength,
    /// Next header.
    NextHeader,
    /// Traffic class.
    TrafficClass,
    /// Flow label.
    FlowLabel,
}

impl Ipv6Field {
    /// Every IPv6 field, in the order the default table uses.
    pub const ALL: [Self; 5] = [
        Self::HopLimit,
        Self::PayloadLength,
        Self::NextHeader,
        Self::TrafficClass,
        Self::FlowLabel,
    ];

    /// The field's name inside the `ipv6.` path.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HopLimit => "hop_limit",
            Self::PayloadLength => "payload_length",
            Self::NextHeader => "next_header",
            Self::TrafficClass => "traffic_class",
            Self::FlowLabel => "flow_label",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }
}

/// A fuzzable UDP header field. `dst_port` is pinned, not listed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpField {
    /// Source port.
    SrcPort,
    /// Datagram length, header included.
    Length,
    /// Checksum.
    Checksum,
}

impl UdpField {
    /// Every UDP field, in the order the default table uses.
    pub const ALL: [Self; 3] = [Self::SrcPort, Self::Length, Self::Checksum];

    /// The field's name inside the `udp.` path.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SrcPort => "src_port",
            Self::Length => "length",
            Self::Checksum => "checksum",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }
}

/// A fuzzable TCP header field. `dst_port` is pinned, not listed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpField {
    /// Source port.
    SrcPort,
    /// Sequence number.
    Seq,
    /// Acknowledgement number.
    Ack,
    /// Data offset, in 32-bit words.
    DataOffset,
    /// The eight control flag bits.
    Flags,
    /// Window size.
    Window,
    /// Checksum.
    Checksum,
    /// Urgent pointer.
    UrgentPtr,
}

impl TcpField {
    /// Every TCP field, in the order the default table uses.
    pub const ALL: [Self; 8] = [
        Self::SrcPort,
        Self::Seq,
        Self::Ack,
        Self::DataOffset,
        Self::Flags,
        Self::Window,
        Self::Checksum,
        Self::UrgentPtr,
    ];

    /// The field's name inside the `tcp.` path.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SrcPort => "src_port",
            Self::Seq => "seq",
            Self::Ack => "ack",
            Self::DataOffset => "data_offset",
            Self::Flags => "flags",
            Self::Window => "window",
            Self::Checksum => "checksum",
            Self::UrgentPtr => "urgent_ptr",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }
}

/// What a case mutates: one header field, or the raw payload layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldPath {
    /// An IPv4 header field.
    Ipv4(Ipv4Field),
    /// An IPv6 header field.
    Ipv6(Ipv6Field),
    /// A UDP header field.
    Udp(UdpField),
    /// A TCP header field.
    Tcp(TcpField),
    /// The `Raw` payload layer of the seed `PacketSpec`.
    Raw,
}

/// How a field is mutated: the shape of its boundary table (plan task 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldClass {
    /// An eight-bit value.
    U8,
    /// A sixteen-bit value.
    U16,
    /// A thirty-two-bit value.
    U32,
    /// A header length counted in 32-bit words (`ihl`, `data_offset`).
    HeaderWords,
    /// A checksum, whose table inverts the computed value.
    Checksum,
    /// The IPv4 three-bit flags field.
    Ipv4Flags,
    /// The IPv4 fragment offset, mutated together with the MF flag.
    FragmentOffset,
    /// A hop count (`ttl`, `hop_limit`).
    Ttl,
    /// The TCP control flag bits.
    TcpFlags,
    /// The raw payload layer, mutated by the byte mutators.
    Raw,
}

impl FieldPath {
    /// The field's mutator class.
    #[must_use]
    pub const fn class(&self) -> FieldClass {
        match self {
            Self::Ipv4(field) => match field {
                Ipv4Field::Ttl => FieldClass::Ttl,
                Ipv4Field::Ihl => FieldClass::HeaderWords,
                Ipv4Field::TotalLength | Ipv4Field::Identification => FieldClass::U16,
                Ipv4Field::Flags => FieldClass::Ipv4Flags,
                Ipv4Field::FragmentOffset => FieldClass::FragmentOffset,
                Ipv4Field::Checksum => FieldClass::Checksum,
                Ipv4Field::Protocol | Ipv4Field::Dscp | Ipv4Field::Ecn => FieldClass::U8,
            },
            Self::Ipv6(field) => match field {
                Ipv6Field::HopLimit => FieldClass::Ttl,
                Ipv6Field::PayloadLength => FieldClass::U16,
                Ipv6Field::NextHeader | Ipv6Field::TrafficClass => FieldClass::U8,
                Ipv6Field::FlowLabel => FieldClass::U32,
            },
            Self::Udp(field) => match field {
                UdpField::SrcPort | UdpField::Length => FieldClass::U16,
                UdpField::Checksum => FieldClass::Checksum,
            },
            Self::Tcp(field) => match field {
                TcpField::SrcPort | TcpField::Window | TcpField::UrgentPtr => FieldClass::U16,
                TcpField::Seq | TcpField::Ack => FieldClass::U32,
                TcpField::DataOffset => FieldClass::HeaderWords,
                TcpField::Flags => FieldClass::TcpFlags,
                TcpField::Checksum => FieldClass::Checksum,
            },
            Self::Raw => FieldClass::Raw,
        }
    }

    /// Whether a case on this field still presents a readable transport header.
    ///
    /// Mutating a length, a header length, the fragmentation fields or the next
    /// protocol hides or garbles the transport header, so the case cannot pin
    /// `dst_port` for `send_recv`'s C3 port check (plan task 3).
    #[must_use]
    pub const fn preserves_transport(&self) -> bool {
        !matches!(
            self,
            Self::Ipv4(
                Ipv4Field::Ihl
                    | Ipv4Field::TotalLength
                    | Ipv4Field::Flags
                    | Ipv4Field::FragmentOffset
                    | Ipv4Field::Protocol
            ) | Self::Ipv6(Ipv6Field::PayloadLength | Ipv6Field::NextHeader)
                | Self::Udp(UdpField::Length)
                | Self::Tcp(TcpField::DataOffset)
        )
    }

    /// Whether the field exists on a target of this IP version and transport.
    #[must_use]
    pub const fn applies_to(&self, ip: IpVersion, transport: L4Transport) -> bool {
        match self {
            Self::Ipv4(_) => matches!(ip, IpVersion::V4),
            Self::Ipv6(_) => matches!(ip, IpVersion::V6),
            Self::Udp(_) => matches!(transport, L4Transport::Udp),
            Self::Tcp(_) => matches!(transport, L4Transport::Tcp),
            Self::Raw => true,
        }
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(field) => write!(f, "ipv4.{}", field.name()),
            Self::Ipv6(field) => write!(f, "ipv6.{}", field.name()),
            Self::Udp(field) => write!(f, "udp.{}", field.name()),
            Self::Tcp(field) => write!(f, "tcp.{}", field.name()),
            Self::Raw => f.write_str("raw"),
        }
    }
}

impl FromStr for FieldPath {
    type Err = FieldError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_pinned(s) {
            return Err(FieldError::Pinned(s.to_string()));
        }
        let parsed = if s == "raw" {
            Some(Self::Raw)
        } else {
            match s.split_once('.') {
                Some(("ipv4", rest)) => Ipv4Field::from_name(rest).map(Self::Ipv4),
                Some(("ipv6", rest)) => Ipv6Field::from_name(rest).map(Self::Ipv6),
                Some(("udp", rest)) => UdpField::from_name(rest).map(Self::Udp),
                Some(("tcp", rest)) => TcpField::from_name(rest).map(Self::Tcp),
                _ => None,
            }
        };
        parsed.ok_or_else(|| FieldError::Unknown(s.to_string()))
    }
}

/// The field paths that are non-fuzzable by construction (spec D8.4).
///
/// Spec D8.4: "`dst`, `dst_port`, `interface`, `ether.src/dst`,
/// `ipv4.src`/`ipv6.src` are **non-fuzzable by construction** (scapy's rule; a
/// plan naming them is `invalid_profile`)". The destination, the destination
/// port, the interface and the source address are pinned so the lane can never
/// send outside the admitted target, off the admitted interface, or spoof a
/// source. The plan's own `dst_port` and `interface` keys are named bare here
/// as well as under their `udp.`/`tcp.` prefixes, so a profile naming either
/// spelling is refused as a pin rather than as an unknown path. `ether.*` is
/// pinned by the prefix rule in [`is_pinned`] rather than by an entry here.
pub const PINNED: [&str; 10] = [
    "ipv4.src",
    "ipv4.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.dst_port",
    "tcp.dst_port",
    "dst",
    "src",
    "dst_port",
    "interface",
];

/// Whether a path names a pinned field: an exact [`PINNED`] entry, or any
/// `ether.` path.
#[must_use]
pub fn is_pinned(path: &str) -> bool {
    PINNED.contains(&path) || path.starts_with("ether.")
}

/// Why a field path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    /// The path names a pinned field.
    Pinned(String),
    /// The path is not a field path the lane knows.
    Unknown(String),
    /// The path is known but absent from this target's headers.
    NotApplicable {
        /// The requested path.
        path: String,
        /// The target it does not apply to, as `ipv4/udp`.
        target: String,
    },
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pinned(path) => write!(
                f,
                "invalid_profile: field path {path:?} is pinned and cannot be fuzzed"
            ),
            Self::Unknown(path) => write!(f, "invalid_profile: unknown field path {path:?}"),
            Self::NotApplicable { path, target } => write!(
                f,
                "invalid_profile: field path {path:?} does not apply to a {target} target"
            ),
        }
    }
}

impl std::error::Error for FieldError {}

/// Parse one field path, refusing pinned paths before unknown ones.
///
/// # Errors
///
/// [`FieldError::Pinned`] for a path in [`PINNED`] or under `ether.`, and
/// [`FieldError::Unknown`] for anything else the lane does not know.
pub fn parse_field(path: &str) -> Result<FieldPath, FieldError> {
    path.parse()
}

/// Every field the lane fuzzes on a target by default: the IP fields in enum
/// order, then the transport fields, then the raw payload.
#[must_use]
pub fn default_fields(ip: IpVersion, transport: L4Transport) -> Vec<FieldPath> {
    let mut out: Vec<FieldPath> = Vec::with_capacity(19);
    match ip {
        IpVersion::V4 => out.extend(Ipv4Field::ALL.into_iter().map(FieldPath::Ipv4)),
        IpVersion::V6 => out.extend(Ipv6Field::ALL.into_iter().map(FieldPath::Ipv6)),
    }
    match transport {
        L4Transport::Udp => out.extend(UdpField::ALL.into_iter().map(FieldPath::Udp)),
        L4Transport::Tcp => out.extend(TcpField::ALL.into_iter().map(FieldPath::Tcp)),
    }
    out.push(FieldPath::Raw);
    out
}

/// Validate an operator's requested field list against one target.
///
/// An empty request is the target's [`default_fields`] table. Otherwise each
/// entry is trimmed and parsed, must apply to the target's IP version and
/// transport, and duplicates are dropped keeping first-seen order. The first
/// failure wins and is returned as its [`FieldError`]'s rendering, so every
/// error string starts with `invalid_profile: ` and names the path.
///
/// # Errors
///
/// The rendered [`FieldError`] of the first entry that is pinned, unknown or
/// inapplicable to the target.
pub fn validate_fields(
    ip: IpVersion,
    transport: L4Transport,
    requested: &[String],
) -> Result<Vec<FieldPath>, String> {
    if requested.is_empty() {
        return Ok(default_fields(ip, transport));
    }
    let target = format!("{}/{}", ip.name(), transport_name(transport));
    let mut out: Vec<FieldPath> = Vec::with_capacity(requested.len());
    for entry in requested {
        let trimmed = entry.trim();
        let path = parse_field(trimmed).map_err(|err| err.to_string())?;
        if !path.applies_to(ip, transport) {
            return Err(FieldError::NotApplicable {
                path: trimmed.to_string(),
                target: target.clone(),
            }
            .to_string());
        }
        if !out.contains(&path) {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::vocab::L4Transport;

    use super::{
        default_fields, parse_field, validate_fields, FieldClass, FieldError, FieldPath, IpVersion,
        Ipv4Field, Ipv6Field, TcpField, UdpField,
    };

    #[test]
    fn default_table_sizes() {
        for (ip, transport, len) in [
            (IpVersion::V4, L4Transport::Udp, 14),
            (IpVersion::V4, L4Transport::Tcp, 19),
            (IpVersion::V6, L4Transport::Udp, 9),
            (IpVersion::V6, L4Transport::Tcp, 14),
        ] {
            let table = default_fields(ip, transport);
            assert_eq!(table.len(), len, "{ip:?}/{transport:?}");
            assert_eq!(table.last(), Some(&FieldPath::Raw), "{ip:?}/{transport:?}");
        }
    }

    #[test]
    fn pinned_paths_refused_by_name() {
        for p in [
            "ipv4.src",
            "ipv4.dst",
            "ipv6.src",
            "ipv6.dst",
            "udp.dst_port",
            "tcp.dst_port",
            "dst",
            "src",
            "dst_port",
            "interface",
            "ether.src",
            "ether.dst",
        ] {
            assert_eq!(
                parse_field(p),
                Err(FieldError::Pinned(p.to_string())),
                "{p}"
            );
            let err = validate_fields(IpVersion::V4, L4Transport::Udp, &[p.to_string()])
                .expect_err("pinned path must be refused");
            assert!(err.starts_with("invalid_profile:"), "{p}: {err}");
            assert!(err.contains(p), "{p}: {err}");
        }
    }

    #[test]
    fn unknown_path() {
        let err = validate_fields(IpVersion::V4, L4Transport::Udp, &["ipv4.bogus".into()])
            .expect_err("unknown path must be refused");
        assert!(err.contains("unknown field path \"ipv4.bogus\""), "{err}");
    }

    #[test]
    fn empty_request_is_the_default_table() {
        assert_eq!(
            validate_fields(IpVersion::V4, L4Transport::Udp, &[]),
            Ok(default_fields(IpVersion::V4, L4Transport::Udp))
        );
    }

    #[test]
    fn explicit_list_in_order() {
        let requested = [
            "ipv4.ttl".to_string(),
            " udp.length".to_string(),
            "raw".to_string(),
            "ipv4.ttl".to_string(),
        ];
        assert_eq!(
            validate_fields(IpVersion::V4, L4Transport::Udp, &requested),
            Ok(vec![
                FieldPath::Ipv4(Ipv4Field::Ttl),
                FieldPath::Udp(UdpField::Length),
                FieldPath::Raw,
            ])
        );
    }

    #[test]
    fn not_applicable() {
        for p in ["ipv6.hop_limit", "tcp.seq"] {
            let err = validate_fields(IpVersion::V4, L4Transport::Udp, &[p.to_string()])
                .expect_err("inapplicable path must be refused");
            assert!(err.contains("does not apply"), "{p}: {err}");
            assert!(err.contains(p), "{p}: {err}");
        }
    }

    #[test]
    fn first_error_wins() {
        let requested = [
            "raw".to_string(),
            "dst".to_string(),
            "ipv4.bogus".to_string(),
        ];
        let err = validate_fields(IpVersion::V4, L4Transport::Udp, &requested)
            .expect_err("the pinned path must be refused");
        assert_eq!(err, FieldError::Pinned("dst".to_string()).to_string());
    }

    #[test]
    fn display_parse_round_trip() {
        for ip in [IpVersion::V4, IpVersion::V6] {
            for transport in [L4Transport::Udp, L4Transport::Tcp] {
                for path in default_fields(ip, transport) {
                    let rendered = path.to_string();
                    assert_eq!(parse_field(&rendered), Ok(path), "{rendered}");
                }
            }
        }
    }

    #[test]
    fn preserves_transport_table() {
        assert!(FieldPath::Ipv4(Ipv4Field::Ttl).preserves_transport());
        assert!(!FieldPath::Ipv4(Ipv4Field::FragmentOffset).preserves_transport());
        assert!(!FieldPath::Udp(UdpField::Length).preserves_transport());
        assert!(!FieldPath::Tcp(TcpField::DataOffset).preserves_transport());
        assert!(FieldPath::Raw.preserves_transport());
        for path in [
            FieldPath::Ipv4(Ipv4Field::Ihl),
            FieldPath::Ipv4(Ipv4Field::TotalLength),
            FieldPath::Ipv4(Ipv4Field::Flags),
            FieldPath::Ipv4(Ipv4Field::Protocol),
            FieldPath::Ipv6(Ipv6Field::PayloadLength),
            FieldPath::Ipv6(Ipv6Field::NextHeader),
        ] {
            assert!(!path.preserves_transport(), "{path}");
        }
    }

    #[test]
    fn class_table() {
        assert_eq!(
            FieldPath::Ipv4(Ipv4Field::Ihl).class(),
            FieldClass::HeaderWords
        );
        assert_eq!(
            FieldPath::Udp(UdpField::Checksum).class(),
            FieldClass::Checksum
        );
        assert_eq!(FieldPath::Tcp(TcpField::Seq).class(), FieldClass::U32);
        assert_eq!(FieldPath::Ipv4(Ipv4Field::Dscp).class(), FieldClass::U8);
    }
}
