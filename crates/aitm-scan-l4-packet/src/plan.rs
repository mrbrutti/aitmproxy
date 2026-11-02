//! Link framing, seed `PacketSpec`s, target plan types and the `SendRecvSpec`
//! builder — owned by scanner v2 track T5, plan task 3.
//!
//! This module is **pure data**: it decides how a frame is framed on the link,
//! builds the seed packet a case mutates, names a point, and assembles the
//! `SendRecvSpec` the wire choke point consumes. It opens no handle and sends
//! nothing; every send goes through `send_recv` behind the `L4Guard`.
//!
//! Spec D8.4's `PacketFuzzPlan { seed, dst, dst_port, interface, fields,
//! expect }` lands here as [`TargetPlan`] plus [`send_recv_spec`]. The
//! destination, the source address and the link layer are **non-fuzzable by
//! construction** (the pin table lives in [`crate::fields`]), so nothing in
//! this module ever varies them.
//!
//! **Loopback only in v2.** [`link_framing`] knows two link layers: macOS's
//! BSD loopback AF word and Ethernet. A real NIC needs real MAC addresses and
//! a routable source address the lane cannot pin, so non-loopback NICs are out
//! of scope for v2 — the lane still frames them as Ethernet, but the operator
//! declares loopback targets.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use aitm_proto_l4::craft::{EtherSpec, Ipv4Spec, Ipv6Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
use aitm_proto_l4::sendrecv::{ReplyMatch, SendRecvSpec};
use aitm_scan_model::profile::ScanProfile;
use aitm_scan_model::vocab::L4Transport;

use crate::fields::{FieldPath, IpVersion};

/// The link layer a crafted frame carries in front of its IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkFraming {
    /// BSD loopback (`DLT_NULL`): a four-byte host-order address-family word.
    Null,
    /// Ethernet II: a fourteen-byte header.
    Ethernet,
}

/// The `AF_INET` word a `DLT_NULL` loopback frame carries.
const AF_INET: u8 = 2;
/// The `AF_INET6` word a `DLT_NULL` loopback frame carries (macOS's value).
const AF_INET6: u8 = 30;

impl LinkFraming {
    /// The layer that frames an IP packet of this version on this link.
    #[must_use]
    pub fn layer(&self, ip: IpVersion) -> Layer {
        match self {
            Self::Null => match ip {
                IpVersion::V4 => Layer::Raw(vec![AF_INET, 0, 0, 0]),
                IpVersion::V6 => Layer::Raw(vec![AF_INET6, 0, 0, 0]),
            },
            Self::Ethernet => Layer::Ether(EtherSpec::default()),
        }
    }

    /// How many bytes [`layer`](Self::layer) puts in front of the IP header.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        match self {
            Self::Null => 4,
            Self::Ethernet => 14,
        }
    }
}

/// The framing an interface's frames carry.
///
/// macOS's loopback (`lo0`) is `DLT_NULL`; everything else the lane can craft
/// for is Ethernet. Linux's `lo` carries an Ethernet header, so only macOS
/// loopback is special-cased.
#[must_use]
pub fn link_framing(interface: &str) -> LinkFraming {
    if cfg!(target_os = "macos") && interface.starts_with("lo") {
        LinkFraming::Null
    } else {
        LinkFraming::Ethernet
    }
}

/// The first source port the lane claims.
pub const SRC_PORT_BASE: u16 = 40000;

/// How many ports above [`SRC_PORT_BASE`] the lane's derived source ports span.
///
/// 16000 keeps every derived port in `40000..56000`, below the 60000 floor of
/// the ephemeral range the core and a loopback test target draw from, so a
/// derived port is less likely to collide with one already in use (amendment
/// 73 b).
pub const SRC_PORT_RANGE: u16 = 16000;

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// A stable, dependency-free FNV-1a 64 hash of `job_id`'s bytes.
///
/// The source port a job claims is derived from this, so it is deterministic
/// across runs: a replay and `send_recv`'s reply correlation both recompute the
/// same port (amendment 73 b).
#[must_use]
fn hash_job_id(job_id: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in job_id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The source port for `job_id`'s target at `target_index`, derived from the
/// job id so two **jobs** against one target never share the five-tuple
/// `send_recv` correlates a reply by: since amendment 66 a reply is the
/// reversed five-tuple, so a shared tuple lets one job's `send_recv` consume
/// another's reply and mask its silence (amendment 73 b). `target_index` is
/// folded in so two **targets** of one job also differ.
///
/// The result is `SRC_PORT_BASE + (hash(job_id) + target_index) % SRC_PORT_RANGE`.
/// The guard's self-port exclusion and the target-port exclusion (task 7,
/// applied by [`crate::discover::choose_src_port`]) reject a port that is one of
/// the core's own listeners or the target's own, so this is a starting point,
/// not a guarantee.
#[must_use]
pub fn src_port_for(job_id: &str, target_index: usize) -> u16 {
    let index = u64::try_from(target_index).unwrap_or(u64::MAX);
    // The modulo is `< SRC_PORT_RANGE` (16000), so the conversion is exact.
    let offset = (hash_job_id(job_id).wrapping_add(index) % u64::from(SRC_PORT_RANGE)) as u16;
    SRC_PORT_BASE + offset
}

/// A built seed: the unmutated packet a case starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSpec {
    /// The seed payload's id, carried into `L4Evidence.seed_id`.
    pub id: String,
    /// The layer stack, outermost first.
    pub spec: PacketSpec,
    /// How many payload bytes the `Raw` layer carries.
    pub payload_len: usize,
}

/// What went wrong building a plan or a seed.
///
/// Like [`FieldError`](crate::fields::FieldError) this renders bare: the
/// `invalid_profile` code is added once by the reporter (`DiscoverError`'s
/// `Display` at discovery, `PacketLane::probe_host_for` at host time), so no
/// message carries it twice (quality panel Minor, T5 live proof 4b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The local address and the target address are different IP versions.
    IpVersionMismatch,
    /// `PacketSpec::build` refused the seed (reported verbatim).
    Craft(String),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpVersionMismatch => {
                f.write_str("the local address and the target address are different IP versions")
            }
            Self::Craft(message) => write!(f, "cannot craft the seed packet: {message}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// Build the seed packet for one `target`: link framing, IP header with the
/// pinned source and destination, the transport header with the pinned
/// destination port, and `payload` as a `Raw` layer.
///
/// A TCP seed is a bare SYN (`flags: 0x02`) with a fixed initial sequence
/// number, so a case replays byte for byte. The destination, source address,
/// framing and transport all come from `target`, so no caller can vary a pinned
/// field by hand (review finding M6).
///
/// # Errors
/// [`PlanError::IpVersionMismatch`] when the target's `local_ip` and `ip` are
/// different IP versions; [`PlanError::Craft`] when the resulting stack does
/// not build (verified once, here, so no later wave crafts an unbuildable
/// case).
pub fn seed_spec(
    target: &ResolvedTarget,
    src_port: u16,
    payload: &[u8],
    seed_id: String,
) -> Result<SeedSpec, PlanError> {
    let (ip_version, ip_layer) = match (target.local_ip, target.ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (
            IpVersion::V4,
            Layer::Ipv4(Ipv4Spec {
                src: Some(src),
                dst: Some(dst),
                ..Ipv4Spec::default()
            }),
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => (
            IpVersion::V6,
            Layer::Ipv6(Ipv6Spec {
                src: Some(src),
                dst: Some(dst),
                ..Ipv6Spec::default()
            }),
        ),
        _ => return Err(PlanError::IpVersionMismatch),
    };

    let transport_layer = match target.proto {
        L4Transport::Udp => Layer::Udp(UdpSpec {
            src_port: Some(src_port),
            dst_port: Some(target.port),
            ..UdpSpec::default()
        }),
        L4Transport::Tcp => Layer::Tcp(TcpSpec {
            src_port: Some(src_port),
            dst_port: Some(target.port),
            flags: Some(0x02),
            seq: Some(0x0000_1000),
            ..TcpSpec::default()
        }),
    };

    let spec = PacketSpec {
        layers: vec![
            target.framing.layer(ip_version),
            ip_layer,
            transport_layer,
            Layer::Raw(payload.to_vec()),
        ],
    };
    spec.build().map_err(|e| PlanError::Craft(e.to_string()))?;

    Ok(SeedSpec {
        id: seed_id,
        spec,
        payload_len: payload.len(),
    })
}

/// One admitted L4 target, resolved against the scope entry that admits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The destination address (pinned; never mutated).
    pub ip: IpAddr,
    /// The destination port (pinned; never mutated).
    pub port: u16,
    /// The transport the target speaks.
    pub proto: L4Transport,
    /// The interface to inject on and capture the reply from.
    pub interface: String,
    /// The link framing [`link_framing`] chose for `interface`.
    pub framing: LinkFraming,
    /// The source address (pinned; source spoofing is refused).
    pub local_ip: IpAddr,
    /// The scope entry that admitted the target, recorded in evidence.
    pub scope_entry: String,
}

/// Where a seed's payload bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedOrigin {
    /// An operator seed from the profile (`hex`/`base64`).
    Profile,
    /// The payload of a captured L4 flow's packet.
    Captured,
    /// The lane's built-in default payload.
    Default,
}

/// One seed payload. `Debug` prints `bytes` as a length, never its contents.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedPayload {
    /// Stable id, carried into `L4Evidence.seed_id`.
    pub id: String,
    /// The payload bytes the `Raw` layer carries.
    pub bytes: Vec<u8>,
    /// Where the bytes came from.
    pub origin: SeedOrigin,
}

impl fmt::Debug for SeedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedPayload")
            .field("id", &self.id)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .field("origin", &self.origin)
            .finish()
    }
}

/// Everything the lane needs to fuzz one target: the target, the validated
/// field list, the seed corpus and the claimed source port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPlan {
    /// The resolved target.
    pub target: ResolvedTarget,
    /// The fields this job fuzzes, in order (one point each).
    pub fields: Vec<FieldPath>,
    /// The seed corpus, cycled case by case.
    pub seeds: Vec<SeedPayload>,
    /// The source port the lane claims for this target.
    pub src_port: u16,
}

impl TargetPlan {
    /// The target's key, `"<ip>:<port>/<proto>"` (IPv6 bracketed).
    #[must_use]
    pub fn key(&self) -> String {
        target_key(self.target.ip, self.target.port, self.target.proto)
    }

    /// The seed case `n` cycles to, or `None` for an empty corpus. The one
    /// place the corpus modulo is written, so every caller cycles the same
    /// way (review finding P2).
    pub(crate) fn seed_at(&self, n: usize) -> Option<&SeedPayload> {
        self.seeds.get(n % self.seeds.len().max(1))
    }

    /// The built seed for case `n`, cycling the corpus.
    ///
    /// # Errors
    /// [`PlanError::Craft`] when the plan carries no seed (nothing to send) or
    /// when the seed does not build.
    pub fn seed_spec(&self, n: usize) -> Result<SeedSpec, PlanError> {
        let seed = self
            .seed_at(n)
            .ok_or_else(|| PlanError::Craft("the target plan carries no seed".to_string()))?;
        seed_spec(&self.target, self.src_port, &seed.bytes, seed.id.clone())
    }
}

/// The wire name of a transport, as a point id, a target key and a scope entry
/// spell it. The one copy for the whole lane (review finding M3).
pub(crate) const fn transport_name(proto: L4Transport) -> &'static str {
    match proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    }
}

/// `"<ip>:<port>"`, IPv6 bracketed so the port stays unambiguous.
pub(crate) fn host_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// `"<ip>:<port>/<proto>"`, IPv6 bracketed so the port stays unambiguous. The
/// one copy for the whole lane (review finding M3).
pub(crate) fn target_key(ip: IpAddr, port: u16, proto: L4Transport) -> String {
    format!("{}/{}", host_port(ip, port), transport_name(proto))
}

/// The insertion-point id for one `(target, field)` pair:
/// `"l4:<ip>:<port>/<proto>/<path>"`.
#[must_use]
pub fn point_id(target: &ResolvedTarget, field: FieldPath) -> String {
    format!(
        "l4:{}/{field}",
        target_key(target.ip, target.port, target.proto)
    )
}

/// Read a point id back. `None` for anything that is not a packet-lane point
/// id, including an id naming a pinned field (which never parses, so a forged
/// id cannot reach a pinned field).
#[must_use]
pub fn parse_point_id(id: &str) -> Option<(IpAddr, u16, L4Transport, FieldPath)> {
    let rest = id.strip_prefix("l4:")?;
    let mut parts = rest.split('/');
    let addr_port = parts.next()?;
    let proto = parts.next()?;
    let path = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let (addr, port) = if let Some(after_bracket) = addr_port.strip_prefix('[') {
        let (addr, tail) = after_bracket.split_once(']')?;
        (addr, tail.strip_prefix(':')?)
    } else {
        addr_port.rsplit_once(':')?
    };

    let ip = IpAddr::from_str(addr).ok()?;
    let port = port.parse::<u16>().ok()?;
    let proto = match proto {
        "tcp" => L4Transport::Tcp,
        "udp" => L4Transport::Udp,
        _ => return None,
    };
    let field = FieldPath::from_str(path).ok()?;
    Some((ip, port, proto, field))
}

/// The `SendRecvSpec` for one case.
///
/// `dst_port` is pinned only when the mutated field leaves a readable
/// transport header: a case that garbles a length, a header length, the
/// fragmentation fields or the next protocol cannot present the port
/// `send_recv`'s C3 check compares, so the port is left unset and correlation
/// falls back to the host.
#[must_use]
pub fn send_recv_spec(
    target: &ResolvedTarget,
    spec: PacketSpec,
    field: FieldPath,
    timeout: Duration,
) -> SendRecvSpec {
    SendRecvSpec {
        packet: spec,
        dst: target.ip,
        dst_port: if field.preserves_transport() {
            Some(target.port)
        } else {
            None
        },
        interface: target.interface.clone(),
        timeout,
        expect: ReplyMatch::FiveTuple,
    }
}

/// Whether a crafted frame still decodes to an IP packet.
///
/// The lane's mirror of `send_recv`'s C3 precondition: a stimulus with no
/// decodable IP destination is refused there as `OutOfL4Scope`, so task 9
/// marks such a case unsendable before charging the budget for it.
#[must_use]
pub fn is_decodable(frame: &[u8]) -> bool {
    PacketSpec::summarize(frame)
        .layers
        .iter()
        .any(|layer| layer == "IPv4" || layer == "IPv6")
}

/// The field paths the profile asks for — the **only** place the lane reads
/// the profile for field selection (plan call C1).
///
/// The list is `L4Options.fields` verbatim (spec D2/D8.4): an empty list — the
/// default — means the lane's own full default field table, because
/// [`crate::fields::validate_fields`] reads an empty request as the defaults;
/// a path the lane pins or does not know makes `Lane::discover` fail with
/// `invalid_profile` before a point is minted.
pub(crate) fn requested_fields(profile: &ScanProfile) -> Vec<String> {
    profile.l4.fields.clone()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_proto_l4::backend::CaptureInjectBackend;
    use aitm_proto_l4::craft::{EtherSpec, Layer, PacketSpec};
    use aitm_proto_l4::sendrecv::ReplyMatch;
    use aitm_scan_model::profile::ScanProfile;
    use aitm_scan_model::vocab::L4Transport;
    use aitm_scan_model::Lane;

    use super::{
        is_decodable, link_framing, parse_point_id, point_id, requested_fields, seed_spec,
        send_recv_spec, LinkFraming, PlanError, ResolvedTarget, SeedOrigin, SeedPayload,
        TargetPlan,
    };
    use crate::fields::{FieldPath, IpVersion, Ipv4Field, Ipv6Field};
    use crate::lane::PacketLane;
    use crate::testing::{l4_profile, loopback_guard, udp_target, MockBackend, MockReply, TestJob};

    const LOCAL_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    const LOCAL_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    fn v4_target() -> ResolvedTarget {
        ResolvedTarget {
            ip: LOCAL_V4,
            port: 9,
            proto: L4Transport::Udp,
            interface: "lo0".to_string(),
            framing: LinkFraming::Null,
            local_ip: LOCAL_V4,
            scope_entry: "127.0.0.1:9/udp".to_string(),
        }
    }

    fn v6_target() -> ResolvedTarget {
        ResolvedTarget {
            ip: LOCAL_V6,
            port: 53,
            proto: L4Transport::Udp,
            interface: "lo0".to_string(),
            framing: LinkFraming::Null,
            local_ip: LOCAL_V6,
            scope_entry: "[::1]:53/udp".to_string(),
        }
    }

    /// Task 4a: the lane reads `L4Options.fields` and nothing else. An empty
    /// list stays empty, so discovery still reads it as the default table.
    #[test]
    fn requested_fields_are_the_profiles_l4_fields() {
        assert!(requested_fields(&ScanProfile::default()).is_empty());

        let mut profile = ScanProfile::default();
        profile.l4.fields = vec!["raw".to_string(), "udp.src_port".to_string()];
        assert_eq!(
            requested_fields(&profile),
            vec!["raw".to_string(), "udp.src_port".to_string()]
        );
    }

    /// The profile's list reaches `Lane::discover`: `fields: ["raw"]` mints the
    /// one `raw` point (the e2e cell's 105 frames ride on this), and a pinned
    /// path the lane refuses is `invalid_profile` before any point exists.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_honours_the_profiles_fields_list() {
        let backend: Arc<dyn CaptureInjectBackend> = MockBackend::new(MockReply::Echo);
        let lane = PacketLane::with_backend(loopback_guard("*", 1000), None, Arc::clone(&backend))
            .with_timing(crate::testing::harness::fast_timing());

        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.fields = vec!["raw".to_string()];
        let job = TestJob::new(profile.clone());
        let discovery = lane
            .discover(&profile.target, job.as_ref())
            .await
            .expect("raw is fuzzable");
        assert_eq!(discovery.points.len(), 1);
        assert_eq!(discovery.points[0].id, "l4:127.0.0.1:9/udp/raw");

        let mut pinned = l4_profile(vec![udp_target(9)], 10);
        pinned.l4.fields = vec!["ipv4.src".to_string()];
        let pinned_job = TestJob::new(pinned.clone());
        let err = lane
            .discover(&pinned.target, pinned_job.as_ref())
            .await
            .expect_err("a pinned field is refused");
        assert!(
            err.to_string().starts_with("invalid_profile:"),
            "D3 code first: {err}"
        );
    }

    #[test]
    fn null_framing_layers() {
        assert_eq!(
            LinkFraming::Null.layer(IpVersion::V4),
            Layer::Raw(vec![2, 0, 0, 0])
        );
        assert_eq!(
            LinkFraming::Null.layer(IpVersion::V6),
            Layer::Raw(vec![30, 0, 0, 0])
        );
        assert_eq!(
            LinkFraming::Ethernet.layer(IpVersion::V4),
            Layer::Ether(EtherSpec::default())
        );
        assert_eq!(LinkFraming::Null.header_len(), 4);
        assert_eq!(LinkFraming::Ethernet.header_len(), 14);
    }

    #[test]
    fn link_framing_decision() {
        assert_eq!(link_framing("en0"), LinkFraming::Ethernet);
        #[cfg(target_os = "macos")]
        assert_eq!(link_framing("lo0"), LinkFraming::Null);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(link_framing("lo"), LinkFraming::Ethernet);
    }

    #[test]
    fn seed_udp_builds_and_decodes() {
        let seed = seed_spec(
            &v4_target(),
            40000,
            b"probe",
            "127.0.0.1:9/udp#0".to_string(),
        )
        .expect("the seed spec builds");
        let bytes = seed.spec.build().expect("the seed packet crafts");
        assert_eq!(bytes.len(), 4 + 20 + 8 + 5);
        assert_eq!(bytes.len(), 37);
        assert_eq!(&bytes[0..4], &[2, 0, 0, 0]);
        assert!(is_decodable(&bytes));
        assert_eq!(PacketSpec::summarize(&bytes).layers, ["IPv4", "UDP"]);
        assert_eq!(seed.payload_len, 5);
        assert_eq!(seed.id, "127.0.0.1:9/udp#0");
    }

    #[test]
    fn seed_tcp_is_syn_with_ports() {
        let target = ResolvedTarget {
            ip: LOCAL_V4,
            port: 80,
            proto: L4Transport::Tcp,
            interface: "lo0".to_string(),
            framing: LinkFraming::Null,
            local_ip: LOCAL_V4,
            scope_entry: "127.0.0.1:80/tcp".to_string(),
        };
        let seed = seed_spec(&target, 40000, b"", "127.0.0.1:80/tcp#0".to_string())
            .expect("the seed spec builds");
        let tcp = seed
            .spec
            .layers
            .iter()
            .find_map(|layer| match layer {
                Layer::Tcp(spec) => Some(spec.clone()),
                _ => None,
            })
            .expect("the seed carries a TCP layer");
        assert_eq!(tcp.flags, Some(0x02));
        assert_eq!(tcp.src_port, Some(40000));
        assert_eq!(tcp.dst_port, Some(80));
    }

    #[test]
    fn version_mismatch_is_error() {
        // A target whose local source is IPv6 but whose destination is IPv4 is
        // the one mismatch `seed_spec` can still be handed through a
        // `ResolvedTarget` (review finding M6).
        let target = ResolvedTarget {
            ip: LOCAL_V4,
            port: 9,
            proto: L4Transport::Udp,
            interface: "lo0".to_string(),
            framing: LinkFraming::Null,
            local_ip: LOCAL_V6,
            scope_entry: String::new(),
        };
        let err = seed_spec(&target, 40000, b"probe", "mismatch".to_string())
            .expect_err("mixed IP versions are refused");
        assert_eq!(err, PlanError::IpVersionMismatch);
    }

    #[test]
    fn send_recv_spec_pins_port_only_when_transport_preserved() {
        let target = v4_target();
        let kept = send_recv_spec(
            &target,
            PacketSpec::default(),
            FieldPath::Raw,
            Duration::from_millis(500),
        );
        assert_eq!(kept.dst_port, Some(9));
        assert_eq!(kept.dst, LOCAL_V4);
        assert_eq!(kept.expect, ReplyMatch::FiveTuple);

        let dropped = send_recv_spec(
            &target,
            PacketSpec::default(),
            FieldPath::Ipv4(Ipv4Field::FragmentOffset),
            Duration::from_millis(500),
        );
        assert_eq!(dropped.dst_port, None);
        assert_eq!(dropped.dst, LOCAL_V4);
        assert_eq!(dropped.expect, ReplyMatch::FiveTuple);
    }

    #[test]
    fn point_id_round_trips() {
        let v4 = point_id(&v4_target(), FieldPath::Ipv4(Ipv4Field::Ttl));
        assert_eq!(v4, "l4:127.0.0.1:9/udp/ipv4.ttl");
        assert_eq!(
            parse_point_id(&v4),
            Some((
                LOCAL_V4,
                9,
                L4Transport::Udp,
                FieldPath::Ipv4(Ipv4Field::Ttl)
            ))
        );

        let v6 = point_id(&v6_target(), FieldPath::Ipv6(Ipv6Field::HopLimit));
        assert_eq!(v6, "l4:[::1]:53/udp/ipv6.hop_limit");
        assert_eq!(
            parse_point_id(&v6),
            Some((
                LOCAL_V6,
                53,
                L4Transport::Udp,
                FieldPath::Ipv6(Ipv6Field::HopLimit)
            ))
        );

        assert_eq!(parse_point_id("http:/x"), None);
        assert_eq!(parse_point_id("l4:127.0.0.1:9/udp/ipv4.src"), None);
    }

    #[test]
    fn target_plan_cycles_seeds() {
        let plan = TargetPlan {
            target: v4_target(),
            fields: vec![FieldPath::Raw],
            seeds: vec![
                SeedPayload {
                    id: "127.0.0.1:9/udp#0".to_string(),
                    bytes: b"probe".to_vec(),
                    origin: SeedOrigin::Default,
                },
                SeedPayload {
                    id: "127.0.0.1:9/udp#1".to_string(),
                    bytes: b"second".to_vec(),
                    origin: SeedOrigin::Profile,
                },
            ],
            src_port: 40000,
        };
        assert_eq!(plan.key(), "127.0.0.1:9/udp");
        assert_eq!(
            plan.seed_spec(0).expect("seed 0 builds").id,
            "127.0.0.1:9/udp#0"
        );
        assert_eq!(
            plan.seed_spec(3).expect("seed 3 wraps to seed 1").id,
            "127.0.0.1:9/udp#1"
        );
    }

    #[test]
    fn undecodable_detected() {
        assert!(!is_decodable(&[0u8; 40]));
        assert!(!is_decodable(&[]));
    }
}
