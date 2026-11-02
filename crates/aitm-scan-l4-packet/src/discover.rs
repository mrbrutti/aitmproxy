//! Target resolution and point discovery — owned by scanner v2 track T5, plan
//! task 7.
//!
//! Discovery is the lane's gate. It turns the operator-declared `l4` targets of
//! a profile into [`TargetPlan`]s, and it is the only place the lane decides
//! that a job may run at all: every refusal the packet lane can raise before a
//! case is built is minted here, prefixed with its D3 code
//! ([`DiscoverError`]).
//!
//! Four refusals, in the order [`resolve_target`] applies them: a target the
//! deny-by-default [`L4Guard`] does not admit with **both** `Inject` (outbound)
//! and `Capture` (inbound) is `out_of_scope:`; a non-loopback target is
//! `lane_unavailable:` (v2 crafts loopback frames only — a real NIC needs MAC
//! addresses and a routable source the lane cannot pin); a target on one of the
//! core's own listener ports is `invalid_profile:`, because `send_recv`'s reply
//! capture self-excludes those frames and the lane could never observe an
//! answer (call C25); and an unparseable address, an unknown or pinned field
//! path, or an undecodable seed is `invalid_profile:`.
//!
//! [`probe_privilege`] opens and immediately closes one capture handle per
//! distinct interface under a `Capture` permit, so a host with no pcap
//! privilege is refused as `lane_unavailable:` before a single case is minted
//! (call C11). Nothing in this module injects a frame.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use aitm_proto_l4::backend::{CaptureInjectBackend, L4Error};
use aitm_proto_l4::craft::Layer;
use aitm_proto_l4::flow::{L4FlowId, L4FlowStore};
use aitm_proto_l4::guard::{interface_covers, L4Guard, ANY_INTERFACE};
use aitm_proto_l4::icmp::transport_payload;
use aitm_proto_l4::types::{
    IpCidr, L4Action, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4Target,
};
use aitm_scan_model::ids::FlowRef;
use aitm_scan_model::point::InsertionPoint;
use aitm_scan_model::profile::{L4Options, L4Seed, L4TargetSpec, ProfileTarget, ScanProfile};
use aitm_scan_model::traits::Discovery;
use aitm_scan_model::vocab::{InsertionKind, L4Transport, LaneKind};

use crate::codec::{base64_decode, hex_decode, hex_encode, truncate_hex, CodecError};
use crate::fields::{validate_fields, FieldError, FieldPath, IpVersion};
use crate::mutate::declared_value;
use crate::plan::{
    host_port, link_framing, point_id, src_port_for, target_key, transport_name, PlanError,
    ResolvedTarget, SeedOrigin, SeedPayload, SeedSpec, TargetPlan,
};

/// Why discovery refused to plan a job, carrying its D3 refusal code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverError {
    /// The profile asks for something the lane cannot build: an unparseable
    /// address, a pinned or unknown field path, an undecodable seed, a target
    /// on one of the core's own listener ports.
    InvalidProfile(String),
    /// No L4 scope entry admits the target with the capabilities the lane needs.
    OutOfScope(String),
    /// The platform cannot run the lane here (no pcap privilege, non-loopback
    /// target).
    LaneUnavailable(String),
}

impl DiscoverError {
    /// The D3 refusal code this error renders with.
    #[must_use]
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProfile(_) => "invalid_profile",
            Self::OutOfScope(_) => "out_of_scope",
            Self::LaneUnavailable(_) => "lane_unavailable",
        }
    }

    /// The message behind the code.
    #[must_use]
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::InvalidProfile(m) | Self::OutOfScope(m) | Self::LaneUnavailable(m) => m,
        }
    }
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every variant stores the bare message (the code is stripped once at
        // construction, review finding M4), so `Display` is the one place the
        // code is prepended and it is never doubled.
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for DiscoverError {}

/// Strip a leading `invalid_profile: ` from a message a source already rendered
/// with it, so a `DiscoverError` stores the bare message and `Display` is the
/// single place the code is added (review finding M4).
fn bare_invalid_profile(message: String) -> String {
    match message.strip_prefix("invalid_profile: ") {
        Some(rest) => rest.to_string(),
        None => message,
    }
}

impl From<FieldError> for DiscoverError {
    fn from(err: FieldError) -> Self {
        // `FieldError` renders with its own `invalid_profile: ` prefix; strip it
        // once so the stored message is bare.
        Self::InvalidProfile(bare_invalid_profile(err.to_string()))
    }
}

impl From<PlanError> for DiscoverError {
    fn from(err: PlanError) -> Self {
        // `PlanError` renders with its own `invalid_profile: ` prefix; strip it
        // once so the stored message is bare.
        Self::InvalidProfile(bare_invalid_profile(err.to_string()))
    }
}

impl From<CodecError> for DiscoverError {
    fn from(err: CodecError) -> Self {
        Self::InvalidProfile(err.to_string())
    }
}

/// The loopback interface this platform names: `lo0` on macOS and the BSDs,
/// `lo` elsewhere.
#[must_use]
pub fn loopback_interface() -> &'static str {
    if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    }
}

/// Whether `ip` falls inside `cidr`; mixed address families never match.
///
/// `aitm_proto_l4` keeps its own copy private, so the lane carries this one
/// rather than widening that crate's surface.
#[must_use]
pub fn cidr_contains(cidr: &IpCidr, ip: IpAddr) -> bool {
    match (cidr.addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            mask_v4(host.into(), cidr.prefix) == mask_v4(net.into(), cidr.prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            mask_v6(host.into(), cidr.prefix) == mask_v6(net.into(), cidr.prefix)
        }
        _ => false,
    }
}

/// `bits` with everything below a `prefix`-bit network mask cleared.
const fn mask_v4(bits: u32, prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p if p >= 32 => bits,
        p => bits & (!0u32 << (32 - p)),
    }
}

/// [`mask_v4`] for IPv6.
const fn mask_v6(bits: u128, prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p if p >= 128 => bits,
        p => bits & (!0u128 << (128 - p)),
    }
}

/// The guard's protocol selector for a profile transport.
#[must_use]
pub const fn l4_proto(t: L4Transport) -> L4Proto {
    match t {
        L4Transport::Tcp => L4Proto::Tcp,
        L4Transport::Udp => L4Proto::Udp,
    }
}

/// The IP version of an address.
#[must_use]
pub const fn ip_version(ip: IpAddr) -> IpVersion {
    match ip {
        IpAddr::V4(_) => IpVersion::V4,
        IpAddr::V6(_) => IpVersion::V6,
    }
}

/// The id of the scope entry that admits injecting at this target, as the
/// `L4ScopeId`'s serde string (a UUID), for `L4Evidence.scope_entry`.
///
/// The first `Inject` + `Outbound` entry whose interface, CIDR and port range
/// cover the target wins — the same order [`L4Guard::check`] picks in.
#[must_use]
pub fn scope_entry_for(
    guard: &L4Guard,
    interface: &str,
    ip: IpAddr,
    port: u16,
    proto: L4Transport,
) -> Option<String> {
    // The guard applies an entry's port range to Tcp/Udp targets only; mirror
    // that here so the entry named in evidence is the entry that admitted us.
    let ports_apply = matches!(l4_proto(proto), L4Proto::Tcp | L4Proto::Udp);
    let covers = |entry: &L4ScopeEntry| {
        entry.capability == L4Capability::Inject
            && entry.direction == L4Direction::Outbound
            && interface_covers(entry, interface)
            && cidr_contains(&entry.cidr, ip)
            && (!ports_apply || (port >= entry.ports.lo && port <= entry.ports.hi))
    };
    let entry = guard.list_scope().into_iter().find(covers)?;
    serde_json::to_value(entry.id)
        .ok()?
        .as_str()
        .map(ToString::to_string)
}

/// The target of the `Inject` permit one case spends.
fn inject_target(interface: &str, ip: IpAddr, port: u16, proto: L4Transport) -> L4Target {
    L4Target {
        interface: interface.to_string(),
        direction: L4Direction::Outbound,
        dst: Some(ip),
        dst_port: Some(port),
        proto: l4_proto(proto),
    }
}

/// The target of the `Capture` permit a reply capture binds under: inbound on
/// the interface, no destination (the reply comes *from* the target).
fn capture_target(interface: &str) -> L4Target {
    L4Target {
        interface: interface.to_string(),
        direction: L4Direction::Inbound,
        dst: None,
        dst_port: None,
        proto: L4Proto::Raw,
    }
}

/// Whether any `Inject`/`Outbound` scope entry covers `ip:port` by CIDR and
/// port range, regardless of the interface it names (a `"*"` entry included).
///
/// This is the interface-independent half of the candidate search: a target no
/// such entry covers is `out_of_scope`, but a non-loopback target one *does*
/// cover is the v2 lane's own limit, `lane_unavailable` (review finding S2).
fn inject_covers(guard: &L4Guard, ip: IpAddr, port: u16) -> bool {
    guard.list_scope().into_iter().any(|entry| {
        entry.capability == L4Capability::Inject
            && entry.direction == L4Direction::Outbound
            && cidr_contains(&entry.cidr, ip)
            && port >= entry.ports.lo
            && port <= entry.ports.hi
    })
}

/// Resolve one declared target against the guard.
///
/// # Errors
///
/// [`DiscoverError::InvalidProfile`] for an address that does not parse or a
/// port that is one of the core's own listeners,
/// [`DiscoverError::OutOfScope`] when no entry grants both `Inject` (outbound)
/// and `Capture` (inbound) for it, and [`DiscoverError::LaneUnavailable`] for a
/// non-loopback target.
pub fn resolve_target(
    guard: &L4Guard,
    spec: &L4TargetSpec,
) -> Result<ResolvedTarget, DiscoverError> {
    let ip: IpAddr = spec.ip.parse().map_err(|_| {
        DiscoverError::InvalidProfile(format!(
            "target ip {:?} is not an IP address",
            spec.ip.as_str()
        ))
    })?;
    let (port, proto) = (spec.port, spec.proto);

    // A non-loopback target the scope covers at all — through a literal
    // interface or a `"*"` entry alike — is the v2 lane's own limit, not the
    // operator's scope: it is `lane_unavailable`, so a wildcard-covered remote
    // target is not mistaken for `out_of_scope` (plan C4; review finding S2).
    // A target no entry covers stays `out_of_scope`, decided below.
    if !ip.is_loopback() && inject_covers(guard, ip, port) {
        return Err(DiscoverError::LaneUnavailable(format!(
            "{ip}: the packet lane v2 sends on the loopback interface only"
        )));
    }

    // Candidate interfaces: every literal interface an `Inject`/`Outbound`
    // entry names for this target, in scope order, then this platform's
    // loopback. A `"*"` entry names no interface of its own, so it is admitted
    // through the loopback candidate (and only a loopback target has one).
    let mut candidates: Vec<String> = Vec::new();
    for entry in guard.list_scope() {
        if entry.capability != L4Capability::Inject
            || entry.direction != L4Direction::Outbound
            || entry.interface == ANY_INTERFACE
            || !cidr_contains(&entry.cidr, ip)
            || port < entry.ports.lo
            || port > entry.ports.hi
        {
            continue;
        }
        if !candidates.contains(&entry.interface) {
            candidates.push(entry.interface);
        }
    }
    if ip.is_loopback() {
        let lo = loopback_interface().to_string();
        if !candidates.contains(&lo) {
            candidates.push(lo);
        }
    }

    let mut chosen: Option<String> = None;
    for interface in candidates {
        // Both permits are minted and dropped here: `check` spends no rate
        // token, so this costs the job nothing and proves the lane could later
        // inject and capture on this interface.
        let inject = guard.check(
            L4Action::Inject,
            &inject_target(&interface, ip, port, proto),
        );
        let capture = guard.check(L4Action::Capture, &capture_target(&interface));
        let admitted = inject.is_ok() && capture.is_ok();
        drop(inject);
        drop(capture);
        if admitted {
            chosen = Some(interface);
            break;
        }
    }
    let Some(interface) = chosen else {
        return Err(DiscoverError::OutOfScope(format!(
            "{}: no L4 scope entry with Inject (outbound) and Capture (inbound) covers it",
            target_key(ip, port, proto)
        )));
    };

    if !ip.is_loopback() {
        return Err(DiscoverError::LaneUnavailable(format!(
            "{ip}: the packet lane v2 sends on the loopback interface only"
        )));
    }
    if guard.self_ports().contains(&port) {
        return Err(DiscoverError::InvalidProfile(format!(
            "{}: {} is one of the core's own listener ports; its replies are self-excluded and \
             cannot be observed",
            host_port(ip, port),
            port
        )));
    }

    let local_ip = match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    Ok(ResolvedTarget {
        ip,
        port,
        proto,
        framing: link_framing(&interface),
        scope_entry: scope_entry_for(guard, &interface, ip, port, proto).unwrap_or_default(),
        interface,
        local_ip,
    })
}

/// The source port the lane claims for the target at `target_index`: the first
/// of `40000 + index`, `+1`, `+2`, ... that is neither one of the core's own
/// listener ports — so the reply capture's self-exclusion never drops the
/// lane's own replies (call C25) — nor the target's own port `target_port`, so
/// a stimulus's direction is never ambiguous: `send_recv` recognises its own
/// looped-back frame by `src:src_port -> dst:dst_port`, and on loopback, where
/// both addresses are the same host, equal ports would make the echo service's
/// reply indistinguishable from the stimulus (T5 live proof).
#[must_use]
pub fn choose_src_port(guard: &L4Guard, target_index: usize, target_port: u16) -> u16 {
    let self_ports = guard.self_ports();
    let mut port = src_port_for(target_index);
    while self_ports.contains(&port) || port == target_port {
        let Some(next) = port.checked_add(1) else {
            break;
        };
        port = next;
    }
    port
}

/// At most this many payloads are taken from captured flows.
pub const MAX_CAPTURED_SEEDS: usize = 8;

/// How many bytes [`default_payload`] carries.
pub const DEFAULT_SEED_LEN: usize = 16;

/// The largest frame `PacketSpec::build` will craft: `aitm_proto_l4::craft`'s
/// own `MAX_PACKET_BYTES`, which that crate does not export. Pinned against
/// the builder by `max_payload_for_is_the_frame_the_builder_accepts`.
pub const MAX_FRAME_BYTES: usize = 65_535;

/// The IPv4 header the lane puts in front of a seed (never any options).
const IPV4_HEADER_BYTES: usize = 20;

/// The IPv6 header the lane puts in front of a seed (no extension headers).
const IPV6_HEADER_BYTES: usize = 40;

/// The UDP header the lane puts in front of a seed.
const UDP_HEADER_BYTES: usize = 8;

/// The TCP header the lane puts in front of a seed (never any options).
const TCP_HEADER_BYTES: usize = 20;

/// The framing-blind upper bound on a seed payload: [`MAX_FRAME_BYTES`] less
/// the 20-byte IPv4 and 8-byte UDP headers, and nothing for the link header.
/// No target can carry more than this, and most carry less, so it is the
/// cheap pre-check; [`max_payload_for`] is the ceiling a target really has.
pub const MAX_SEED_BYTES: usize = MAX_FRAME_BYTES - IPV4_HEADER_BYTES - UDP_HEADER_BYTES;

/// The largest seed payload `target`'s frames can actually carry: the
/// builder's frame ceiling less the link, IP and transport headers
/// [`crate::plan::seed_spec`] puts in front of every seed.
///
/// [`MAX_SEED_BYTES`] ignores the link header (4 bytes on a macOS loopback,
/// 14 on Ethernet) and assumes IPv4 and UDP, so it over-states what an IPv6
/// or a TCP target can carry. This is the number a refusal quotes, so
/// "the largest payload is <n>" is true on this host (tester finding T1).
#[must_use]
pub fn max_payload_for(target: &ResolvedTarget) -> usize {
    let ip = match target.ip {
        IpAddr::V4(_) => IPV4_HEADER_BYTES,
        IpAddr::V6(_) => IPV6_HEADER_BYTES,
    };
    let transport = match target.proto {
        L4Transport::Udp => UDP_HEADER_BYTES,
        L4Transport::Tcp => TCP_HEADER_BYTES,
    };
    MAX_FRAME_BYTES.saturating_sub(target.framing.header_len() + ip + transport)
}

/// The refusal for a seed the builder will not craft, naming the seed.
fn uncraftable_seed(id: &str, err: &PlanError) -> DiscoverError {
    let why = match err {
        PlanError::Craft(message) => message.clone(),
        other => bare_invalid_profile(other.to_string()),
    };
    DiscoverError::InvalidProfile(format!("seed {id} cannot be crafted: {why}"))
}

/// The lane's built-in seed payload: the job's marker, padded with spaces or
/// truncated to [`DEFAULT_SEED_LEN`] bytes, so every case is attributable to
/// the job that sent it and every plan carries at least one seed.
#[must_use]
pub fn default_payload(marker: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = marker
        .as_bytes()
        .iter()
        .copied()
        .take(DEFAULT_SEED_LEN)
        .collect();
    bytes.resize(DEFAULT_SEED_LEN, b' ');
    bytes
}

/// Whether a stored packet is one the lane may seed from for `target`: our own
/// outbound traffic to exactly this address, port and transport, and not a
/// frame aitmproxy itself injected (never fuzz our own stimuli back).
fn seeds_target(
    packet: &aitm_proto_l4::flow::L4Packet,
    target: &ResolvedTarget,
) -> Option<Vec<u8>> {
    if packet.dir != L4Direction::Outbound || packet.injected {
        return None;
    }
    let ends = transport_payload(packet)?;
    if ends.dst != target.ip || ends.dst_port != target.port || ends.proto != l4_proto(target.proto)
    {
        return None;
    }
    Some(ends.payload.to_vec())
}

/// The `L4FlowId` a profile seed's [`FlowRef`] names.
///
/// Both ids are UUID-backed and both render as the UUID string, so the ref
/// crosses between the scanner's vocabulary and the L4 store's through serde
/// rather than through a cast.
fn l4_flow_id(flow: FlowRef) -> Option<L4FlowId> {
    serde_json::from_value(serde_json::to_value(flow).ok()?).ok()
}

/// Gather the seed corpus for one target: the profile's own seeds, else the
/// payloads of captured flows to that target, else the default payload.
///
/// Captured flows contribute seeds only for a **declared** target: discovery
/// never invents a target from the store.
///
/// # Errors
///
/// [`DiscoverError::InvalidProfile`] for a seed that does not decode, a seed
/// flow that is not in the store, and a seed flow holding no packet to this
/// target.
pub fn seed_payloads(
    target: &ResolvedTarget,
    options: &L4Options,
    store: Option<&dyn L4FlowStore>,
    marker: &str,
) -> Result<Vec<SeedPayload>, DiscoverError> {
    let key = target_key(target.ip, target.port, target.proto);
    let mut out: Vec<SeedPayload> = Vec::new();
    let push = |bytes: Vec<u8>, origin: SeedOrigin, out: &mut Vec<SeedPayload>| {
        out.push(SeedPayload {
            id: format!("{key}#{}", out.len()),
            bytes,
            origin,
        });
    };

    // A seed the builder could never craft is the operator's mistake, so it is
    // refused here, by name, instead of overflowing a wire length at send time.
    let push_checked = |bytes: Vec<u8>,
                        origin: SeedOrigin,
                        out: &mut Vec<SeedPayload>|
     -> Result<(), DiscoverError> {
        if bytes.len() > MAX_SEED_BYTES {
            return Err(DiscoverError::InvalidProfile(format!(
                "seed {key}#{} is {} bytes; the largest payload is {}",
                out.len(),
                bytes.len(),
                max_payload_for(target)
            )));
        }
        push(bytes, origin, out);
        Ok(())
    };

    // (a) The operator's own seeds, in profile order.
    for seed in &options.seeds {
        match seed {
            L4Seed::Hex { hex } => push_checked(hex_decode(hex)?, SeedOrigin::Profile, &mut out)?,
            L4Seed::Base64 { base64 } => {
                push_checked(base64_decode(base64)?, SeedOrigin::Profile, &mut out)?;
            }
            L4Seed::Flow { flow } => {
                let found = l4_flow_id(*flow)
                    .zip(store)
                    .and_then(|(id, store)| store.get(id));
                let Some(captured) = found else {
                    return Err(DiscoverError::InvalidProfile(format!(
                        "seed flow {flow} is not a captured L4 flow"
                    )));
                };
                let payloads: Vec<Vec<u8>> = captured
                    .packets
                    .iter()
                    .filter_map(|packet| seeds_target(packet, target))
                    .collect();
                if payloads.is_empty() {
                    return Err(DiscoverError::InvalidProfile(format!(
                        "seed flow {flow} carries no outbound packet to {key}"
                    )));
                }
                for payload in payloads {
                    push_checked(payload, SeedOrigin::Captured, &mut out)?;
                }
            }
        }
    }

    // (b) Captured traffic to this target, de-duplicated, newest flow last.
    if out.is_empty() {
        if let Some(store) = store {
            let mut seen: Vec<Vec<u8>> = Vec::new();
            'flows: for id in store.list() {
                let Some(flow) = store.get(id) else { continue };
                for packet in &flow.packets {
                    let Some(payload) = seeds_target(packet, target) else {
                        continue;
                    };
                    if seen.contains(&payload) {
                        continue;
                    }
                    seen.push(payload.clone());
                    push(payload, SeedOrigin::Captured, &mut out);
                    if out.len() >= MAX_CAPTURED_SEEDS {
                        break 'flows;
                    }
                }
            }
        }
    }

    // (c) The default payload, so no plan is ever seedless.
    if out.is_empty() {
        push(default_payload(marker), SeedOrigin::Default, &mut out);
    }
    Ok(out)
}

/// The seed's payload bytes: the **last** `Raw` layer, because BSD loopback
/// framing puts an address-family `Raw` word in front of the IP header too.
fn raw_payload(seed: &SeedSpec) -> &[u8] {
    seed.spec
        .layers
        .iter()
        .rev()
        .find_map(|layer| match layer {
            Layer::Raw(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The `example` for a raw point. A captured seed is operator plaintext, so it
/// is shown only as a byte count; a profile or default seed is shown as hex,
/// cut at [`crate::codec::DETAIL_HEX_CHARS`] (review finding SEC3, spec D2).
fn raw_example(seed: &SeedSpec, origin: SeedOrigin) -> String {
    let payload = raw_payload(seed);
    match origin {
        SeedOrigin::Captured => format!("<{} bytes>", payload.len()),
        SeedOrigin::Profile | SeedOrigin::Default => truncate_hex(&hex_encode(payload)),
    }
}

/// One insertion point per field of this target, in field order.
///
/// `example` is the value the seed actually puts on the wire — decimal for a
/// header field, a bounded hex preview for the raw payload — so a UI shows what
/// a case starts from. A captured seed's payload is operator plaintext, so the
/// raw point shows only its byte count, never the bytes (spec D2 "`example`
/// redacted"; review finding SEC3); a profile or default seed shows its hex, cut
/// at [`crate::codec::DETAIL_HEX_CHARS`]. Every point is lane-local: no site node, no flow
/// (call C6).
#[must_use]
pub fn points_for(
    target: &ResolvedTarget,
    fields: &[FieldPath],
    seed: &SeedSpec,
    origin: SeedOrigin,
) -> Vec<InsertionPoint> {
    let link_len = target.framing.header_len();
    let url = format!(
        "{}://{}",
        transport_name(target.proto),
        host_port(target.ip, target.port)
    );
    fields
        .iter()
        .map(|field| {
            let name = field.to_string();
            let example = match field {
                FieldPath::Raw => Some(raw_example(seed, origin)),
                other => declared_value(&seed.spec, *other, link_len).map(|v| v.to_string()),
            };
            InsertionPoint {
                id: point_id(target, *field),
                lane: LaneKind::L4Packet,
                kind: InsertionKind::L4Field,
                path: Some(name.clone()),
                name,
                example,
                flow: None,
                site_node: None,
                traits: Vec::new(),
                frequency: 1,
                method: None,
                url: Some(url.clone()),
            }
        })
        .collect()
}

/// Prove the platform can capture on `interface` before any case is minted:
/// open one capture handle under a `Capture` permit and drop both at once
/// (call C11).
///
/// # Errors
///
/// [`DiscoverError::LaneUnavailable`] when the backend cannot open a capture —
/// no pcap privilege, no libpcap, an unsupported OS — and
/// [`DiscoverError::OutOfScope`] when the guard does not grant `Capture` here.
pub fn probe_privilege(
    guard: &L4Guard,
    backend: &dyn CaptureInjectBackend,
    interface: &str,
) -> Result<(), DiscoverError> {
    let permit = guard
        .check(L4Action::Capture, &capture_target(interface))
        .map_err(|err| DiscoverError::OutOfScope(format!("capture on {interface}: {err}")))?;
    let opened = backend.open_capture(interface, None, Duration::from_millis(1));
    drop(permit);
    let capture = opened.map_err(|err| {
        let why = match &err {
            L4Error::Unavailable(why) => why.clone(),
            other => other.to_string(),
        };
        DiscoverError::LaneUnavailable(format!("pcap on {interface}: {why}"))
    })?;
    drop(capture);
    Ok(())
}

/// Plan every declared L4 target of a profile, and mint the points the engine
/// schedules checks over.
///
/// `requested` is the operator's field list (`L4Options.fields`, read by
/// `crate::plan::requested_fields`), passed in by the lane rather than read
/// here, so this function stays pure of the profile type. An empty list is
/// the target's default field table.
///
/// # Errors
///
/// The first [`DiscoverError`] any target raises: resolution, field
/// validation, seeds, or the per-interface privilege probe — which runs
/// **before** any point is minted, so a privilege-less host refuses the job
/// rather than half-planning it.
pub fn discover_all(
    guard: &L4Guard,
    backend: &dyn CaptureInjectBackend,
    seed_store: Option<&dyn L4FlowStore>,
    target: &ProfileTarget,
    profile: &ScanProfile,
    requested: &[String],
    marker: &str,
) -> Result<(Vec<TargetPlan>, Discovery), DiscoverError> {
    let mut plans: Vec<TargetPlan> = Vec::with_capacity(target.l4.len());
    let mut points: Vec<InsertionPoint> = Vec::new();
    let mut probed: Vec<String> = Vec::new();

    for (index, spec) in target.l4.iter().enumerate() {
        let resolved = resolve_target(guard, spec)?;
        let fields = validate_fields(ip_version(resolved.ip), resolved.proto, requested)
            .map_err(|message| DiscoverError::InvalidProfile(bare_invalid_profile(message)))?;
        let seeds = seed_payloads(&resolved, &profile.l4, seed_store, marker)?;
        let src_port = choose_src_port(guard, index, resolved.port);

        if !probed.contains(&resolved.interface) {
            probe_privilege(guard, backend, &resolved.interface)?;
            probed.push(resolved.interface.clone());
        }

        let plan = TargetPlan {
            target: resolved,
            fields,
            seeds,
            src_port,
        };
        // Every seed is built, not just seed 0: the fuzz loop cycles through
        // the whole corpus, and a seed the frame cannot carry is the
        // operator's bytes — named here rather than ending a point's run in
        // silence at send time (tester finding T1). Only seed 0's spec is
        // kept; the rest are built to prove they build and dropped.
        let mut first: Option<SeedSpec> = None;
        for (n, payload) in plan.seeds.iter().enumerate() {
            let built = plan
                .seed_spec(n)
                .map_err(|err| uncraftable_seed(&payload.id, &err))?;
            if n == 0 {
                first = Some(built);
            }
        }
        // `seed_payloads` never returns an empty corpus, so case 0 always has
        // a seed; an empty one is refused rather than unwrapped.
        let Some(seed) = first else {
            return Err(DiscoverError::InvalidProfile(format!(
                "no seed for {}",
                plan.key()
            )));
        };
        let origin = plan
            .seeds
            .first()
            .map_or(SeedOrigin::Default, |payload| payload.origin);
        points.extend(points_for(&plan.target, &plan.fields, &seed, origin));
        plans.push(plan);
    }

    Ok((
        plans,
        Discovery {
            points,
            nodes: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use aitm_proto_l4::flow::{
        InMemoryL4FlowStore, L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet,
    };
    use aitm_proto_l4::guard::L4Guard;
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use aitm_scan_model::ids::FlowRef;
    use aitm_scan_model::profile::{L4Options, L4Seed};
    use aitm_scan_model::vocab::{InsertionKind, L4Transport, LaneKind};

    use super::{
        choose_src_port, default_payload, discover_all, loopback_interface, max_payload_for,
        points_for, probe_privilege, resolve_target, seed_payloads, DiscoverError, MAX_FRAME_BYTES,
        MAX_SEED_BYTES,
    };
    use crate::fields::{default_fields, FieldPath, IpVersion};
    use crate::plan::{link_framing, PlanError, SeedOrigin, SeedPayload, TargetPlan};
    use crate::testing::{
        fields, l4_profile, loopback_guard, tcp_target, udp_target, MockBackend, MockReply,
    };

    /// A guard over `addr/prefix` on `interface` granting exactly `caps`, built
    /// the way [`crate::testing::loopback_guard`] builds its entries
    /// (`Config`-sourced, so a loopback CIDR lifts the dangerous-destination
    /// denylist). `L4Guard::add_scope` is `#[cfg(test)]` in its own crate, so a
    /// guard with other CIDRs is constructed, not widened.
    fn guard_over(
        addr: IpAddr,
        prefix: u8,
        interface: &str,
        caps: &[(L4Direction, L4Capability)],
    ) -> Arc<L4Guard> {
        let scope = caps
            .iter()
            .map(|(direction, capability)| L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr { addr, prefix },
                ports: PortRange {
                    lo: 0,
                    hi: u16::MAX,
                },
                interface: interface.to_string(),
                direction: *direction,
                capability: *capability,
                inject_rate: RateCap {
                    pps: 100,
                    burst: 100,
                },
                source: L4ScopeSource::Config,
            })
            .collect();
        Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            scope,
            ..L4Config::default()
        }))
    }

    /// Both capabilities the lane needs, over one CIDR on one interface.
    const BOTH: [(L4Direction, L4Capability); 2] = [
        (L4Direction::Outbound, L4Capability::Inject),
        (L4Direction::Inbound, L4Capability::Capture),
    ];

    /// A stored UDP packet to `127.0.0.1:<dst_port>` carrying `payload`.
    fn udp_packet(dst_port: u16, payload: &[u8], dir: L4Direction, injected: bool) -> L4Packet {
        let bytes = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(50_000),
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("the stored UDP frame builds");
        L4Packet {
            dir,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected,
        }
    }

    /// A store holding one `Capture` flow with `packets`, and that flow's id.
    fn store_with(packets: Vec<L4Packet>) -> (InMemoryL4FlowStore, L4FlowId) {
        let store = InMemoryL4FlowStore::new();
        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind {
                interface: loopback_interface().to_string(),
                filter: None,
                queue: None,
            },
            packets: VecDeque::new(),
            metadata: L4Meta::default(),
        });
        for packet in packets {
            store.append_packet(id, packet);
        }
        (store, id)
    }

    /// The `FlowRef` a profile seed names for the stored flow `id`.
    fn flow_ref(id: L4FlowId) -> FlowRef {
        let text = serde_json::to_value(id).expect("a flow id serialises");
        serde_json::from_value(text).expect("a flow id's uuid string is a FlowRef")
    }

    #[test]
    fn resolves_loopback_udp_target() {
        let guard = loopback_guard("*", 100);
        let resolved =
            resolve_target(&guard, &udp_target(9)).expect("the loopback target resolves");

        assert_eq!(resolved.interface, loopback_interface());
        assert_eq!(resolved.local_ip, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(resolved.framing, link_framing(loopback_interface()));

        let inject_entry = guard
            .list_scope()
            .into_iter()
            .find(|entry| entry.capability == L4Capability::Inject)
            .expect("the loopback guard carries an Inject entry");
        let expected = serde_json::to_value(inject_entry.id)
            .expect("a scope id serialises")
            .as_str()
            .expect("as a uuid string")
            .to_string();
        assert_eq!(resolved.scope_entry, expected);
        assert_eq!(guard.in_flight(), 0);
    }

    #[test]
    fn literal_interface_entry_wins() {
        let guard = guard_over(IpAddr::from([127, 0, 0, 0]), 8, "lo0", &BOTH);
        let resolved = resolve_target(&guard, &udp_target(9)).expect("the literal entry resolves");
        assert_eq!(resolved.interface, "lo0");
    }

    #[test]
    fn out_of_scope_names_target() {
        let guard = guard_over(IpAddr::from([10, 0, 0, 0]), 8, "*", &BOTH);
        let err = resolve_target(&guard, &udp_target(9)).expect_err("127.0.0.1 is not in 10/8");

        let DiscoverError::OutOfScope(message) = &err else {
            panic!("expected out_of_scope, got {err:?}");
        };
        assert!(message.contains("127.0.0.1:9/udp"), "{message}");
        assert!(err.to_string().starts_with("out_of_scope:"), "{err}");
    }

    #[test]
    fn missing_capture_entry_is_out_of_scope() {
        let guard = guard_over(
            IpAddr::from([127, 0, 0, 0]),
            8,
            "*",
            &[(L4Direction::Outbound, L4Capability::Inject)],
        );
        let err = resolve_target(&guard, &udp_target(9)).expect_err("no Capture entry");

        let DiscoverError::OutOfScope(message) = &err else {
            panic!("expected out_of_scope, got {err:?}");
        };
        assert!(message.contains("Capture"), "{message}");
    }

    #[test]
    fn non_loopback_is_lane_unavailable() {
        let spec = |ip: &str| aitm_scan_model::profile::L4TargetSpec {
            ip: ip.to_string(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };

        // A literal-interface entry covers 10.1.2.3: lane_unavailable.
        let guard = guard_over(IpAddr::from([10, 0, 0, 0]), 8, "en0", &BOTH);
        let err = resolve_target(&guard, &spec("10.1.2.3")).expect_err("v2 is loopback only");
        let DiscoverError::LaneUnavailable(message) = &err else {
            panic!("expected lane_unavailable, got {err:?}");
        };
        assert!(message.contains("loopback"), "{message}");

        // A `"*"` entry covers it too, and is still lane_unavailable, not
        // out_of_scope (review finding S2).
        let wildcard = guard_over(IpAddr::from([10, 0, 0, 0]), 8, "*", &BOTH);
        let err = resolve_target(&wildcard, &spec("10.1.2.3")).expect_err("v2 is loopback only");
        assert!(
            matches!(err, DiscoverError::LaneUnavailable(_)),
            "a wildcard-covered remote target is lane_unavailable, got {err:?}"
        );
        assert!(err.to_string().starts_with("lane_unavailable:"), "{err}");

        // A non-loopback target no entry covers stays out_of_scope.
        let err =
            resolve_target(&wildcard, &spec("192.0.2.9")).expect_err("192.0.2.9 is outside 10/8");
        assert!(
            matches!(err, DiscoverError::OutOfScope(_)),
            "an uncovered remote target is out_of_scope, got {err:?}"
        );
    }

    #[test]
    fn bad_ip_is_invalid_profile() {
        let guard = loopback_guard("*", 100);
        let spec = aitm_scan_model::profile::L4TargetSpec {
            ip: "nope".to_string(),
            port: 9,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let err = resolve_target(&guard, &spec).expect_err("\"nope\" is not an address");

        assert!(matches!(err, DiscoverError::InvalidProfile(_)), "{err:?}");
        assert!(err.to_string().starts_with("invalid_profile:"), "{err}");
    }

    #[test]
    fn default_seed_is_the_padded_marker() {
        assert_eq!(default_payload("aitm7f3a"), b"aitm7f3a        ".to_vec());
        assert_eq!(default_payload("a-very-long-marker-value").len(), 16);
    }

    #[test]
    fn profile_seeds_decode_in_order() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let options = L4Options {
            seeds: vec![
                L4Seed::Hex {
                    hex: "0001".to_string(),
                },
                L4Seed::Base64 {
                    base64: "AAE=".to_string(),
                },
            ],
            ..L4Options::default()
        };

        let seeds = seed_payloads(&target, &options, None, "aitm7f3a").expect("both seeds decode");
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].bytes, vec![0, 1]);
        assert_eq!(seeds[1].bytes, vec![0, 1]);
        assert_eq!(seeds[0].id, "127.0.0.1:9/udp#0");
        assert_eq!(seeds[1].id, "127.0.0.1:9/udp#1");
        assert!(seeds.iter().all(|s| s.origin == SeedOrigin::Profile));

        let bad = L4Options {
            seeds: vec![L4Seed::Hex {
                hex: "zz".to_string(),
            }],
            ..L4Options::default()
        };
        let err = seed_payloads(&target, &bad, None, "aitm7f3a").expect_err("\"zz\" is not hex");
        assert!(matches!(err, DiscoverError::InvalidProfile(_)), "{err:?}");
    }

    /// A profile seed longer than [`MAX_SEED_BYTES`] cannot be crafted into a
    /// packet (the IPv4 `total_length` would overflow), so it is refused at
    /// discovery as the operator's mistake, naming the seed and the ceiling.
    ///
    /// The ceiling the message quotes is this host's, not [`MAX_SEED_BYTES`]:
    /// the frame carries a link header too (tester finding T1).
    #[test]
    fn oversize_seed_is_invalid_profile() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        // 65535 less this host's loopback link header, the IPv4 header and
        // the UDP header.
        let ceiling = 65_535 - link_framing(loopback_interface()).header_len() - 20 - 8;

        let at_ceiling = L4Options {
            seeds: vec![L4Seed::Hex {
                hex: "41".repeat(MAX_SEED_BYTES),
            }],
            ..L4Options::default()
        };
        let seeds =
            seed_payloads(&target, &at_ceiling, None, "aitm7f3a").expect("the ceiling itself fits");
        assert_eq!(seeds[0].bytes.len(), MAX_SEED_BYTES);

        let over = L4Options {
            seeds: vec![L4Seed::Hex {
                hex: "41".repeat(MAX_SEED_BYTES + 1),
            }],
            ..L4Options::default()
        };
        let err = seed_payloads(&target, &over, None, "aitm7f3a").expect_err("one byte too many");
        let DiscoverError::InvalidProfile(message) = &err else {
            panic!("expected invalid_profile, got {err:?}");
        };
        assert_eq!(
            message,
            &format!(
                "seed 127.0.0.1:9/udp#0 is {} bytes; the largest payload is {ceiling}",
                MAX_SEED_BYTES + 1
            )
        );
    }

    #[test]
    fn captured_seeds_dedupe_and_filter() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let (store, _) = store_with(vec![
            udp_packet(9, b"a", L4Direction::Outbound, false),
            udp_packet(9, b"a", L4Direction::Outbound, false),
            udp_packet(9, b"b", L4Direction::Outbound, false),
            udp_packet(10, b"c", L4Direction::Outbound, false),
            udp_packet(9, b"d", L4Direction::Outbound, true),
            udp_packet(9, b"e", L4Direction::Inbound, false),
        ]);

        let seeds = seed_payloads(
            &target,
            &L4Options::default(),
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect("captured seeds");
        let payloads: Vec<Vec<u8>> = seeds.iter().map(|s| s.bytes.clone()).collect();
        assert_eq!(payloads, vec![b"a".to_vec(), b"b".to_vec()]);
        assert!(seeds.iter().all(|s| s.origin == SeedOrigin::Captured));

        let many: Vec<L4Packet> = (0..10u8)
            .map(|n| udp_packet(9, &[n], L4Direction::Outbound, false))
            .collect();
        let (big, _) = store_with(many);
        let capped = seed_payloads(
            &target,
            &L4Options::default(),
            Some(&big as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect("captured seeds");
        assert_eq!(capped.len(), 8);
    }

    #[test]
    fn default_seed_when_nothing_else() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let seeds =
            seed_payloads(&target, &L4Options::default(), None, "aitm7f3a").expect("default seed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].bytes, default_payload("aitm7f3a"));
        assert_eq!(seeds[0].origin, SeedOrigin::Default);
        assert_eq!(seeds[0].id, "127.0.0.1:9/udp#0");
    }

    #[test]
    fn flow_seed_from_store() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let (store, id) = store_with(vec![
            udp_packet(9, b"one", L4Direction::Outbound, false),
            udp_packet(10, b"other", L4Direction::Outbound, false),
            udp_packet(9, b"two", L4Direction::Outbound, false),
        ]);
        let options = L4Options {
            seeds: vec![L4Seed::Flow { flow: flow_ref(id) }],
            ..L4Options::default()
        };

        let seeds = seed_payloads(
            &target,
            &options,
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect("the flow's payloads");
        let payloads: Vec<Vec<u8>> = seeds.iter().map(|s| s.bytes.clone()).collect();
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec()]);

        let unknown = L4FlowId::new();
        let uuid = serde_json::to_value(unknown)
            .expect("a flow id serialises")
            .as_str()
            .expect("as a uuid string")
            .to_string();
        let missing = L4Options {
            seeds: vec![L4Seed::Flow {
                flow: flow_ref(unknown),
            }],
            ..L4Options::default()
        };
        let err = seed_payloads(
            &target,
            &missing,
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect_err("the flow is not in the store");
        let DiscoverError::InvalidProfile(message) = &err else {
            panic!("expected invalid_profile, got {err:?}");
        };
        assert!(message.contains(&uuid), "{message}");
    }

    #[test]
    fn points_for_udp_target() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let seeds =
            seed_payloads(&target, &L4Options::default(), None, "aitm7f3a").expect("default seed");
        let plan = TargetPlan {
            target,
            fields: default_fields(IpVersion::V4, L4Transport::Udp),
            seeds,
            src_port: 40_000,
        };
        let seed = plan.seed_spec(0).expect("the seed builds");
        let points = points_for(&plan.target, &plan.fields, &seed, SeedOrigin::Default);

        assert_eq!(points.len(), 14);
        assert_eq!(points[0].id, "l4:127.0.0.1:9/udp/ipv4.ttl");
        assert_eq!(points[13].id, "l4:127.0.0.1:9/udp/raw");
        for point in &points {
            assert_eq!(point.lane, LaneKind::L4Packet);
            assert_eq!(point.kind, InsertionKind::L4Field);
            assert_eq!(point.path.as_deref(), Some(point.name.as_str()));
            assert_eq!(point.url.as_deref(), Some("udp://127.0.0.1:9"));
            assert_eq!(point.frequency, 1);
            assert!(point.flow.is_none());
            assert!(point.site_node.is_none());
            assert!(point.traits.is_empty());
            assert!(point.method.is_none());
        }

        let example = |name: &str| {
            points
                .iter()
                .find(|p| p.name == name)
                .and_then(|p| p.example.clone())
        };
        assert_eq!(example("ipv4.ttl").as_deref(), Some("64"));
        assert_eq!(example("udp.length").as_deref(), Some("24"));
        // 16 default-seed bytes = 32 hex characters, under the 64-char cut, so
        // the default seed's hex is shown verbatim (review finding SEC3).
        assert_eq!(
            example("raw").as_deref(),
            Some("6169746d376633612020202020202020")
        );

        // The same point built from a captured seed shows only the byte count,
        // never the captured plaintext (spec D2 "example redacted"; SEC3).
        let captured = points_for(&plan.target, &plan.fields, &seed, SeedOrigin::Captured);
        let captured_raw = captured
            .iter()
            .find(|p| p.name == "raw")
            .and_then(|p| p.example.clone());
        assert_eq!(captured_raw.as_deref(), Some("<16 bytes>"));
    }

    #[test]
    fn discover_all_shape() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9), tcp_target(80)], 100);

        let (plans, discovery) = discover_all(
            &guard,
            backend.as_ref(),
            None,
            &profile.target,
            &profile,
            &[],
            "aitm7f3a",
        )
        .expect("both targets resolve");

        assert_eq!(plans.len(), 2);
        assert_eq!(discovery.points.len(), 14 + 19);
        assert!(discovery.nodes.is_empty());
        assert_eq!(plans[1].src_port, 40_001);
        assert_eq!(guard.in_flight(), 0);
    }

    #[test]
    fn discover_all_refuses_pinned() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9), tcp_target(80)], 100);

        for pin in ["ipv4.src", "dst"] {
            let err = discover_all(
                &guard,
                backend.as_ref(),
                None,
                &profile.target,
                &profile,
                &fields(&[pin]),
                "aitm7f3a",
            )
            .expect_err("a pinned field is refused");
            let DiscoverError::InvalidProfile(message) = &err else {
                panic!("expected invalid_profile, got {err:?}");
            };
            // The stored message is bare; `Display` is the one place the code is
            // added, and it is never doubled (review finding M4).
            assert!(!message.starts_with("invalid_profile:"), "{message}");
            assert!(message.contains(pin), "{message}");
            let rendered = err.to_string();
            assert!(rendered.starts_with("invalid_profile:"), "{rendered}");
            assert!(
                !rendered.contains("invalid_profile: invalid_profile:"),
                "{rendered}"
            );
        }

        let (plans, discovery) = discover_all(
            &guard,
            backend.as_ref(),
            None,
            &profile.target,
            &profile,
            &fields(&["raw"]),
            "aitm7f3a",
        )
        .expect("raw is fuzzable");
        assert_eq!(plans.len(), 2);
        assert_eq!(discovery.points.len(), 2);
    }

    #[test]
    fn self_port_target_is_refused_and_src_port_skips_self_ports() {
        let guard = loopback_guard("*", 100);
        guard.set_self_ports([9, 40_000]);

        let err = resolve_target(&guard, &udp_target(9)).expect_err("port 9 is a self port");
        let DiscoverError::InvalidProfile(message) = &err else {
            panic!("expected invalid_profile, got {err:?}");
        };
        assert!(message.contains("own listener ports"), "{message}");

        assert_eq!(choose_src_port(&guard, 0, 9), 40_001);
    }

    /// T5 live proof: the source port never equals the target's own port, so
    /// the stimulus's direction (`src:src_port -> dst:dst_port`) is never
    /// symmetric and `send_recv` can tell its looped-back frame from the
    /// echo service's reply on loopback. Target port 40000 moves the source to
    /// 40001; a self port and the target port are both skipped; an unrelated
    /// target port leaves the default alone.
    #[test]
    fn src_port_skips_the_targets_own_port() {
        let guard = loopback_guard("*", 100);
        assert_eq!(choose_src_port(&guard, 0, 40_000), 40_001);
        assert_eq!(choose_src_port(&guard, 0, 9), 40_000);
        assert_eq!(choose_src_port(&guard, 1, 40_001), 40_002);

        guard.set_self_ports([40_000]);
        assert_eq!(choose_src_port(&guard, 0, 40_001), 40_002);

        // Through discovery: a target on the lane's default source port is
        // planned with the next one.
        let profile = l4_profile(vec![udp_target(40_000)], 10);
        let backend = MockBackend::new(MockReply::Echo);
        let (plans, _) = discover_all(
            &loopback_guard("*", 100),
            backend.as_ref(),
            None,
            &profile.target,
            &profile,
            &fields(&["raw"]),
            "aitm7f3a",
        )
        .expect("a loopback udp target discovers");
        assert_eq!(plans[0].src_port, 40_001);
        assert_eq!(plans[0].target.port, 40_000);
    }

    /// Tester (T5 stage 5): the search walks past a run of excluded ports and
    /// still never lands on the target's own, and it terminates — the loop is
    /// bounded by `checked_add`, so an exhausted range breaks instead of
    /// spinning. Every port the lane picks must also stay outside the core's
    /// own listeners (call C25), both rules at once.
    #[test]
    fn src_port_walks_past_a_run_of_excluded_ports() {
        let guard = loopback_guard("*", 100);
        guard.set_self_ports([40_000, 40_001, 40_002]);

        assert_eq!(
            choose_src_port(&guard, 0, 40_003),
            40_004,
            "three self ports and the target's own are all skipped"
        );
        assert_eq!(
            choose_src_port(&guard, 0, 9),
            40_003,
            "without the target in the way the first free port wins"
        );
        for index in 0..8usize {
            let target_port = 40_000 + u16::try_from(index).expect("a small index");
            let port = choose_src_port(&guard, index, target_port);
            assert_ne!(port, target_port, "index {index}");
            assert!(
                !guard.self_ports().contains(&port),
                "index {index}: {port} is a core listener"
            );
        }
    }

    #[test]
    fn probe_privilege_unavailable() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::unavailable();

        let direct = probe_privilege(&guard, backend.as_ref(), loopback_interface())
            .expect_err("no pcap privilege");
        assert!(
            matches!(direct, DiscoverError::LaneUnavailable(_)),
            "{direct:?}"
        );

        let profile = l4_profile(vec![udp_target(9)], 100);
        let through = discover_all(
            &guard,
            backend.as_ref(),
            None,
            &profile.target,
            &profile,
            &[],
            "aitm7f3a",
        )
        .expect_err("no pcap privilege");
        assert_eq!(through, direct);
        assert_eq!(backend.inject_count(), 0);
        assert_eq!(guard.in_flight(), 0);
    }

    #[test]
    fn probe_privilege_ok_releases_permit() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);

        probe_privilege(&guard, backend.as_ref(), loopback_interface()).expect("the probe opens");
        assert_eq!(guard.in_flight(), 0);
    }

    /// Tester (stage 5): a seed flow that exists but holds only our own
    /// injected stimuli, inbound replies or packets to another target is
    /// `invalid_profile` naming the flow and the target; the same store
    /// without a profile seed falls through to the default payload.
    #[test]
    fn flow_seed_with_no_usable_packet_is_invalid_profile() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let (store, id) = store_with(vec![
            udp_packet(9, b"ours", L4Direction::Outbound, true),
            udp_packet(9, b"reply", L4Direction::Inbound, false),
            udp_packet(10, b"elsewhere", L4Direction::Outbound, false),
        ]);
        let uuid = serde_json::to_value(id)
            .expect("a flow id serialises")
            .as_str()
            .expect("as a uuid string")
            .to_string();

        let options = L4Options {
            seeds: vec![L4Seed::Flow { flow: flow_ref(id) }],
            ..L4Options::default()
        };
        let err = seed_payloads(
            &target,
            &options,
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect_err("nothing in the flow may seed this target");
        let DiscoverError::InvalidProfile(message) = &err else {
            panic!("expected invalid_profile, got {err:?}");
        };
        assert_eq!(
            message,
            &format!("seed flow {uuid} carries no outbound packet to 127.0.0.1:9/udp")
        );
        assert_eq!(err.to_string(), format!("invalid_profile: {message}"));

        // A flow seed with no store at all is refused the same way.
        let err =
            seed_payloads(&target, &options, None, "aitm7f3a").expect_err("no store, no flow");
        assert!(
            err.to_string().contains("is not a captured L4 flow"),
            "{err}"
        );

        let fallback = seed_payloads(
            &target,
            &L4Options::default(),
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect("the default seed");
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].origin, SeedOrigin::Default);
        assert_eq!(fallback[0].bytes, default_payload("aitm7f3a"));
    }

    /// Tester (stage 5): an empty or whitespace-only hex seed is an empty
    /// payload, which still plans — one raw point with an empty example and a
    /// 28-byte seed datagram (link word + IPv4 + UDP, nothing after).
    #[test]
    fn empty_hex_seed_is_an_empty_payload_that_still_plans() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        for hex in ["", " \n\t"] {
            let mut profile = l4_profile(vec![udp_target(9)], 10);
            profile.l4.seeds.push(L4Seed::Hex {
                hex: hex.to_string(),
            });
            let (plans, discovery) = discover_all(
                &guard,
                backend.as_ref(),
                None,
                &profile.target,
                &profile,
                &fields(&["raw"]),
                "aitm7f3a",
            )
            .expect("an empty seed plans");
            assert_eq!(plans[0].seeds.len(), 1, "{hex:?}");
            assert_eq!(plans[0].seeds[0].bytes, Vec::<u8>::new(), "{hex:?}");
            assert_eq!(plans[0].seeds[0].origin, SeedOrigin::Profile, "{hex:?}");
            let seed = plans[0].seed_spec(0).expect("the empty seed builds");
            assert_eq!(seed.payload_len, 0);
            assert_eq!(
                seed.spec.build().expect("builds").len(),
                plans[0].target.framing.header_len() + 20 + 8
            );
            assert_eq!(discovery.points.len(), 1);
            assert_eq!(discovery.points[0].example.as_deref(), Some(""));
        }
    }

    /// Tester (stage 5): the second seed's error is still the first error the
    /// operator sees, with the codec's own message behind the code.
    #[test]
    fn bad_base64_seed_is_invalid_profile_with_the_codec_message() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let options = L4Options {
            seeds: vec![
                L4Seed::Hex {
                    hex: "00".to_string(),
                },
                L4Seed::Base64 {
                    base64: "AA=A".to_string(),
                },
            ],
            ..L4Options::default()
        };
        let err = seed_payloads(&target, &options, None, "aitm7f3a").expect_err("bad padding");
        assert_eq!(
            err,
            DiscoverError::InvalidProfile("invalid base64 padding".to_string())
        );
        assert_eq!(err.to_string(), "invalid_profile: invalid base64 padding");
    }

    /// Tester (stage 5): captured packets that do not decode are skipped, not
    /// seeds and not a panic.
    #[test]
    fn undecodable_captured_packets_are_skipped() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let garbage = L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&[0xff; 7]),
            bytes: vec![0xff; 7],
            injected: false,
        };
        let empty = L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&[]),
            bytes: Vec::new(),
            injected: false,
        };
        let (store, _) = store_with(vec![
            garbage,
            empty,
            udp_packet(9, b"real", L4Direction::Outbound, false),
        ]);
        let seeds = seed_payloads(
            &target,
            &L4Options::default(),
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect("captured seeds");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].bytes, b"real".to_vec());
        assert_eq!(seeds[0].id, "127.0.0.1:9/udp#0");
    }

    /// Tester (stage 5): an IPv6 loopback target resolves against a `::1/128`
    /// entry — local address `::1`, bracketed ids and url, the v6 default
    /// table — and a v4-only guard refuses it as out of scope.
    #[test]
    fn ipv6_loopback_target_resolves_with_a_v6_entry() {
        let v6 = aitm_scan_model::profile::L4TargetSpec {
            ip: "::1".to_string(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let err = resolve_target(&loopback_guard("*", 100), &v6).expect_err("v4 entries only");
        assert!(matches!(err, DiscoverError::OutOfScope(_)), "{err:?}");
        assert!(
            err.to_string().starts_with("out_of_scope: [::1]:53/udp"),
            "{err}"
        );

        let guard = guard_over(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128, "*", &BOTH);
        let resolved = resolve_target(&guard, &v6).expect("::1/128 admits ::1");
        assert_eq!(resolved.ip, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(resolved.local_ip, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(resolved.interface, loopback_interface());
        assert_eq!(guard.in_flight(), 0);

        let seeds = seed_payloads(&resolved, &L4Options::default(), None, "aitm7f3a")
            .expect("default seed");
        assert_eq!(seeds[0].id, "[::1]:53/udp#0");
        let plan = TargetPlan {
            target: resolved,
            fields: default_fields(IpVersion::V6, L4Transport::Udp),
            seeds,
            src_port: 40_000,
        };
        assert_eq!(plan.key(), "[::1]:53/udp");
        let seed = plan.seed_spec(0).expect("the v6 seed builds");
        assert_eq!(
            seed.spec.build().expect("builds").len(),
            plan.target.framing.header_len() + 40 + 8 + 16
        );
        let points = points_for(&plan.target, &plan.fields, &seed, SeedOrigin::Default);
        assert_eq!(points.len(), 9);
        assert_eq!(points[0].id, "l4:[::1]:53/udp/ipv6.hop_limit");
        assert_eq!(points[8].id, "l4:[::1]:53/udp/raw");
        assert!(points
            .iter()
            .all(|p| p.url.as_deref() == Some("udp://[::1]:53")));
        let example = |name: &str| {
            points
                .iter()
                .find(|p| p.name == name)
                .and_then(|p| p.example.clone())
        };
        assert_eq!(example("ipv6.hop_limit").as_deref(), Some("64"));
        assert_eq!(example("ipv6.payload_length").as_deref(), Some("24"));
        assert_eq!(example("ipv6.next_header").as_deref(), Some("17"));
        assert_eq!(example("udp.length").as_deref(), Some("24"));
    }

    /// Tester (stage 5): `cidr_contains` at the prefix extremes, in both
    /// families, and never across families.
    #[test]
    fn cidr_contains_edges() {
        use super::cidr_contains;
        let v4 = |addr: [u8; 4], prefix: u8| IpCidr {
            addr: IpAddr::from(addr),
            prefix,
        };
        assert!(cidr_contains(
            &v4([0, 0, 0, 0], 0),
            IpAddr::from([203, 0, 113, 7])
        ));
        assert!(cidr_contains(
            &v4([127, 0, 0, 1], 32),
            IpAddr::from([127, 0, 0, 1])
        ));
        assert!(!cidr_contains(
            &v4([127, 0, 0, 1], 32),
            IpAddr::from([127, 0, 0, 2])
        ));
        assert!(cidr_contains(
            &v4([127, 0, 0, 0], 8),
            IpAddr::from([127, 255, 255, 255])
        ));
        assert!(!cidr_contains(
            &v4([127, 0, 0, 0], 8),
            IpAddr::from([128, 0, 0, 0])
        ));
        // A prefix past the width is read as the full width.
        assert!(cidr_contains(
            &v4([10, 0, 0, 1], 200),
            IpAddr::from([10, 0, 0, 1])
        ));
        assert!(!cidr_contains(
            &v4([10, 0, 0, 1], 200),
            IpAddr::from([10, 0, 0, 2])
        ));
        // Never across families, in either direction.
        assert!(!cidr_contains(
            &v4([0, 0, 0, 0], 0),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        ));
        let v6 = IpCidr {
            addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            prefix: 0,
        };
        assert!(cidr_contains(
            &v6,
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        ));
        assert!(!cidr_contains(&v6, IpAddr::from([127, 0, 0, 1])));
        let exact = IpCidr {
            addr: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            prefix: 128,
        };
        assert!(cidr_contains(
            &exact,
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        ));
        assert!(!cidr_contains(
            &exact,
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        ));
    }

    /// Tester (fix rounds, review finding S2): with literal and wildcard Inject
    /// entries side by side, a non-loopback target any of them covers is
    /// `lane_unavailable` — whether the literal entry's port range reaches it
    /// or only the `"*"` entry does — and a non-loopback target none covers is
    /// still `out_of_scope`. The loopback target under the same guard resolves
    /// through its literal entry.
    #[test]
    fn mixed_literal_and_wildcard_entries_for_a_non_loopback_target() {
        let entry = |addr: [u8; 4], prefix: u8, lo: u16, hi: u16, interface: &str| {
            let interface = interface.to_string();
            BOTH.iter()
                .map(move |(direction, capability)| L4ScopeEntry {
                    id: L4ScopeId::new(),
                    cidr: IpCidr {
                        addr: IpAddr::from(addr),
                        prefix,
                    },
                    ports: PortRange { lo, hi },
                    interface: interface.clone(),
                    direction: *direction,
                    capability: *capability,
                    inject_rate: RateCap {
                        pps: 100,
                        burst: 100,
                    },
                    source: L4ScopeSource::Config,
                })
                .collect::<Vec<L4ScopeEntry>>()
        };
        let mut scope: Vec<L4ScopeEntry> = Vec::new();
        // A literal NIC entry over 10/8 for the low ports only.
        scope.extend(entry([10, 0, 0, 0], 8, 0, 100, "en0"));
        // A wildcard entry over 10/8 for every port.
        scope.extend(entry([10, 0, 0, 0], 8, 0, u16::MAX, "*"));
        // A literal loopback entry.
        scope.extend(entry([127, 0, 0, 0], 8, 0, u16::MAX, loopback_interface()));
        let guard = L4Guard::new(&L4Config {
            enabled: true,
            scope,
            ..L4Config::default()
        });
        let spec = |ip: &str, port: u16| aitm_scan_model::profile::L4TargetSpec {
            ip: ip.to_string(),
            port,
            proto: L4Transport::Udp,
            grammar: None,
        };

        // Covered by the literal entry and the wildcard: lane_unavailable.
        let err = resolve_target(&guard, &spec("10.1.2.3", 53)).expect_err("loopback only");
        assert_eq!(
            err,
            DiscoverError::LaneUnavailable(
                "10.1.2.3: the packet lane v2 sends on the loopback interface only".to_string()
            )
        );
        assert_eq!(
            err.to_string(),
            "lane_unavailable: 10.1.2.3: the packet lane v2 sends on the loopback interface only"
        );
        // Covered by the wildcard alone (the literal entry stops at port 100):
        // still lane_unavailable, never out_of_scope.
        let err = resolve_target(&guard, &spec("10.1.2.3", 5000)).expect_err("loopback only");
        assert!(matches!(err, DiscoverError::LaneUnavailable(_)), "{err:?}");
        // Covered by nothing: out_of_scope, naming the target.
        let err = resolve_target(&guard, &spec("192.0.2.9", 53)).expect_err("not in 10/8");
        assert_eq!(
            err,
            DiscoverError::OutOfScope(
                "192.0.2.9:53/udp: no L4 scope entry with Inject (outbound) and Capture (inbound) \
                 covers it"
                    .to_string()
            )
        );
        // The loopback target still resolves, through its literal entry.
        let resolved = resolve_target(&guard, &udp_target(9)).expect("loopback resolves");
        assert_eq!(resolved.interface, loopback_interface());
        assert_eq!(guard.in_flight(), 0);
    }

    /// Tester (fix rounds, review finding SEC1): the seed ceiling is enforced
    /// for a base64 seed and for a captured-flow seed exactly as for a hex one,
    /// at the same literal boundary, and the refusal names the seed's own
    /// index. The flow seed is an IPv6 datagram, the one family whose UDP
    /// payload can legitimately exceed the ceiling on the wire.
    #[test]
    fn seed_ceiling_holds_for_base64_and_flow_seeds() {
        let guard = loopback_guard("*", 100);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");

        // 65507 = 3 * 21835 + 2 zero bytes; 65508 = 3 * 21836.
        let at_ceiling = format!("{}AAA=", "AAAA".repeat(21_835));
        let over = "AAAA".repeat(21_836);
        let seeds = seed_payloads(
            &target,
            &L4Options {
                seeds: vec![L4Seed::Base64 { base64: at_ceiling }],
                ..L4Options::default()
            },
            None,
            "aitm7f3a",
        )
        .expect("the ceiling itself fits");
        assert_eq!(seeds[0].bytes.len(), MAX_SEED_BYTES);
        let err = seed_payloads(
            &target,
            &L4Options {
                seeds: vec![
                    L4Seed::Hex {
                        hex: "00".to_string(),
                    },
                    L4Seed::Base64 { base64: over },
                ],
                ..L4Options::default()
            },
            None,
            "aitm7f3a",
        )
        .expect_err("one byte too many");
        assert_eq!(
            err,
            DiscoverError::InvalidProfile(format!(
                "seed 127.0.0.1:9/udp#1 is 65508 bytes; the largest payload is {}",
                65_535 - link_framing(loopback_interface()).header_len() - 20 - 8
            ))
        );

        // A captured IPv6 UDP datagram carrying 65527 payload bytes (the
        // largest IPv6 payload_length allows), hand-assembled because the
        // crafter itself refuses to build one.
        let v6 = aitm_scan_model::profile::L4TargetSpec {
            ip: "::1".to_string(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let v6_guard = guard_over(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128, "*", &BOTH);
        let v6_target = resolve_target(&v6_guard, &v6).expect("::1 resolves");
        let payload_len = 65_527usize;
        let mut bytes: Vec<u8> = Vec::with_capacity(40 + 8 + payload_len);
        bytes.extend_from_slice(&[0x60, 0, 0, 0]);
        bytes.extend_from_slice(&u16::to_be_bytes(0xffff));
        bytes.push(17);
        bytes.push(64);
        bytes.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&50_000u16.to_be_bytes());
        bytes.extend_from_slice(&53u16.to_be_bytes());
        bytes.extend_from_slice(&u16::to_be_bytes(0xffff));
        bytes.extend_from_slice(&[0, 0]);
        bytes.resize(40 + 8 + payload_len, 0x41);
        let jumbo = L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        };
        let (store, id) = store_with(vec![jumbo]);
        let err = seed_payloads(
            &v6_target,
            &L4Options {
                seeds: vec![L4Seed::Flow { flow: flow_ref(id) }],
                ..L4Options::default()
            },
            Some(&store as &dyn L4FlowStore),
            "aitm7f3a",
        )
        .expect_err("a captured payload over the ceiling is refused by name");
        assert_eq!(
            err,
            DiscoverError::InvalidProfile(format!(
                "seed [::1]:53/udp#0 is 65527 bytes; the largest payload is {}",
                65_535 - link_framing(&v6_target.interface).header_len() - 40 - 8
            ))
        );
    }

    /// Tester (fix rounds, review finding SEC1 / M8): through `discover_all`
    /// the real boundary is the whole frame — link framing, IPv4 and UDP
    /// headers and the payload must fit 65535 bytes — so the largest seed that
    /// plans is `MAX_SEED_BYTES` less the link header, and one byte more is
    /// still an `invalid_profile` refusal at discovery (seed 0 is built there),
    /// never a send-time failure.
    #[test]
    fn discover_all_refuses_a_seed_the_frame_cannot_carry() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        let largest = MAX_SEED_BYTES - link_framing(loopback_interface()).header_len();
        for (n, fits) in [(largest, true), (largest + 1, false)] {
            let mut profile = l4_profile(vec![udp_target(9)], 10);
            profile.l4.seeds.push(L4Seed::Hex {
                hex: "41".repeat(n),
            });
            let planned = discover_all(
                &guard,
                backend.as_ref(),
                None,
                &profile.target,
                &profile,
                &fields(&["raw"]),
                "aitm7f3a",
            );
            if fits {
                let (plans, discovery) = planned.expect("the largest frame plans");
                assert_eq!(plans[0].seeds[0].bytes.len(), n);
                assert_eq!(
                    plans[0]
                        .seed_spec(0)
                        .expect("builds")
                        .spec
                        .build()
                        .expect("65535 bytes")
                        .len(),
                    65_535
                );
                assert_eq!(discovery.points.len(), 1);
            } else {
                let err = planned.expect_err("one byte over the frame");
                assert!(matches!(err, DiscoverError::InvalidProfile(_)), "{err:?}");
                assert!(err.to_string().starts_with("invalid_profile: "), "{err}");
            }
        }
        assert_eq!(backend.inject_count(), 0);
    }

    /// Tester finding T1: only seed 0 was built at discovery, so a later
    /// profile seed the frame cannot carry survived planning and the fuzz
    /// loop met it at send time, where `case_at` answered `None` and the loop
    /// broke in silence — no stop reason, no unsendable case, a `Clean` crash
    /// check over a point that stopped early. Every seed is built here, and
    /// the one that does not build is named.
    #[test]
    fn every_seed_is_built_at_discovery() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.seeds = vec![
            L4Seed::Hex {
                hex: "00".to_string(),
            },
            L4Seed::Hex {
                // Inside `MAX_SEED_BYTES`, so the framing-blind pre-check
                // passes it: only building it refuses it.
                hex: "41".repeat(MAX_SEED_BYTES),
            },
        ];

        let err = discover_all(
            &guard,
            backend.as_ref(),
            None,
            &profile.target,
            &profile,
            &fields(&["raw"]),
            "aitm7f3a",
        )
        .expect_err("seed 1 does not build");

        assert_eq!(
            err,
            DiscoverError::InvalidProfile(
                "seed 127.0.0.1:9/udp#1 cannot be crafted: crafted packet exceeds 65535 bytes"
                    .to_string()
            )
        );
        assert!(err.to_string().starts_with("invalid_profile: "), "{err}");
        assert_eq!(backend.inject_count(), 0);
    }

    /// Tester finding T1: the ceiling a refusal quotes has to be true on this
    /// host, so it is the builder's frame ceiling less this target's link, IP
    /// and transport headers. Pinned against the builder itself: a seed of
    /// exactly that many bytes crafts a full 65535-byte frame, and one byte
    /// more does not craft at all.
    #[test]
    fn max_payload_for_is_the_frame_the_builder_accepts() {
        let v4_guard = loopback_guard("*", 100);
        let v6_guard = guard_over(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128, "*", &BOTH);
        let v6_spec = aitm_scan_model::profile::L4TargetSpec {
            ip: "::1".to_string(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let targets = [
            resolve_target(&v4_guard, &udp_target(9)).expect("127.0.0.1 udp resolves"),
            resolve_target(&v4_guard, &tcp_target(80)).expect("127.0.0.1 tcp resolves"),
            resolve_target(&v6_guard, &v6_spec).expect("::1 udp resolves"),
        ];

        for target in targets {
            let ceiling = max_payload_for(&target);
            assert!(ceiling <= MAX_SEED_BYTES, "{ceiling} for {}", target.ip);
            let plan = |len: usize| TargetPlan {
                seeds: vec![SeedPayload {
                    id: "seed".to_string(),
                    bytes: vec![0x41; len],
                    origin: SeedOrigin::Profile,
                }],
                fields: vec![FieldPath::Raw],
                src_port: 40_000,
                target: target.clone(),
            };
            let frame = plan(ceiling)
                .seed_spec(0)
                .expect("the ceiling crafts")
                .spec
                .build()
                .expect("the ceiling builds");
            assert_eq!(frame.len(), MAX_FRAME_BYTES, "ceiling for {}", target.ip);
            assert_eq!(
                plan(ceiling + 1).seed_spec(0).expect_err("one byte over"),
                PlanError::Craft("crafted packet exceeds 65535 bytes".to_string()),
                "ceiling + 1 for {}",
                target.ip
            );
        }
    }

    /// Tester (round 3): the one framing/IP/transport combination
    /// `max_payload_for_is_the_frame_the_builder_accepts` did not pin, an IPv6
    /// TCP target, holds against the builder too: a seed of exactly the
    /// quoted ceiling crafts a full 65535-byte frame and one more byte does
    /// not craft. The ceiling is checked from the framing arithmetic (65535
    /// less the link header, the 40-byte IPv6 header and the 20-byte TCP
    /// header), never from `max_payload_for` itself, and against the literal
    /// per-host values of all four combinations.
    #[test]
    fn max_payload_for_holds_for_a_v6_tcp_target() {
        let v4_guard = loopback_guard("*", 100);
        let v6_guard = guard_over(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128, "*", &BOTH);
        let v6_spec = |proto: L4Transport, port: u16| aitm_scan_model::profile::L4TargetSpec {
            ip: "::1".to_string(),
            port,
            proto,
            grammar: None,
        };
        let target =
            resolve_target(&v6_guard, &v6_spec(L4Transport::Tcp, 80)).expect("::1 tcp resolves");
        let link = link_framing(&target.interface).header_len();

        let ceiling = max_payload_for(&target);
        assert_eq!(ceiling, 65_535 - link - 40 - 20);
        assert_eq!(
            ceiling,
            if cfg!(target_os = "macos") {
                65_471
            } else {
                65_461
            }
        );
        assert!(
            ceiling < MAX_SEED_BYTES,
            "the framing-blind pre-check must admit a seed only the build refuses"
        );

        let plan = |len: usize| TargetPlan {
            seeds: vec![SeedPayload {
                id: "seed".to_string(),
                bytes: vec![0x41; len],
                origin: SeedOrigin::Profile,
            }],
            fields: vec![FieldPath::Raw],
            src_port: 40_000,
            target: target.clone(),
        };
        let frame = plan(ceiling)
            .seed_spec(0)
            .expect("the ceiling crafts")
            .spec
            .build()
            .expect("the ceiling builds");
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        // IPv6 payload_length counts everything past the fixed header: the
        // TCP header plus the seed.
        assert_eq!(
            u16::from_be_bytes([frame[link + 4], frame[link + 5]]),
            u16::try_from(20 + ceiling).expect("fits the field")
        );
        assert_eq!(
            plan(ceiling + 1).seed_spec(0).expect_err("one byte over"),
            PlanError::Craft("crafted packet exceeds 65535 bytes".to_string())
        );

        // The four combinations, literally, so a header constant cannot
        // drift without a test noticing.
        let table = [
            (
                resolve_target(&v4_guard, &udp_target(9)).expect("v4 udp"),
                65_535 - link - 20 - 8,
                65_503,
            ),
            (
                resolve_target(&v4_guard, &tcp_target(80)).expect("v4 tcp"),
                65_535 - link - 20 - 20,
                65_491,
            ),
            (
                resolve_target(&v6_guard, &v6_spec(L4Transport::Udp, 53)).expect("v6 udp"),
                65_535 - link - 40 - 8,
                65_483,
            ),
            (target, 65_535 - link - 40 - 20, 65_471),
        ];
        for (target, from_framing, on_macos) in table {
            let got = max_payload_for(&target);
            assert_eq!(got, from_framing, "{}/{:?}", target.ip, target.proto);
            if cfg!(target_os = "macos") {
                assert_eq!(got, on_macos, "{}/{:?}", target.ip, target.proto);
            }
        }
    }

    /// Tester (round 3): with three profile seeds, the one that does not
    /// build is named by its own index — `#2`, not `#0` or `#1` — and the
    /// same corpus with the third seed exactly at this target's ceiling plans
    /// all three, the third as a full 65535-byte frame.
    #[test]
    fn the_third_of_three_seeds_is_refused_by_name() {
        let guard = loopback_guard("*", 100);
        let backend = MockBackend::new(MockReply::Echo);
        let target = resolve_target(&guard, &udp_target(9)).expect("resolves");
        let ceiling = max_payload_for(&target);
        let seeds = |third: usize| {
            vec![
                L4Seed::Hex {
                    hex: "00".to_string(),
                },
                L4Seed::Hex {
                    hex: "01".to_string(),
                },
                L4Seed::Hex {
                    hex: "41".repeat(third),
                },
            ]
        };
        let discover = |profile: &aitm_scan_model::ScanProfile| {
            discover_all(
                &guard,
                backend.as_ref(),
                None,
                &profile.target,
                profile,
                &fields(&["raw"]),
                "aitm7f3a",
            )
        };

        // At the ceiling every seed builds and the corpus is kept whole.
        let mut profile = l4_profile(vec![udp_target(9)], 10);
        profile.l4.seeds = seeds(ceiling);
        let (plans, discovery) = discover(&profile).expect("three seeds at the ceiling plan");
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0]
                .seeds
                .iter()
                .map(|seed| (seed.id.as_str(), seed.bytes.len(), seed.origin))
                .collect::<Vec<_>>(),
            vec![
                ("127.0.0.1:9/udp#0", 1, SeedOrigin::Profile),
                ("127.0.0.1:9/udp#1", 1, SeedOrigin::Profile),
                ("127.0.0.1:9/udp#2", ceiling, SeedOrigin::Profile),
            ]
        );
        assert_eq!(
            plans[0]
                .seed_spec(2)
                .expect("seed 2 builds")
                .spec
                .build()
                .expect("a full frame")
                .len(),
            65_535
        );
        assert_eq!(discovery.points.len(), 1);

        // One byte over: inside `MAX_SEED_BYTES`, so the framing-blind
        // pre-check passes it and only the build refuses it, by name.
        assert!(ceiling < MAX_SEED_BYTES);
        profile.l4.seeds = seeds(ceiling + 1);
        let err = discover(&profile).expect_err("seed 2 does not build");
        assert_eq!(
            err,
            DiscoverError::InvalidProfile(
                "seed 127.0.0.1:9/udp#2 cannot be crafted: crafted packet exceeds 65535 bytes"
                    .to_string()
            )
        );
        assert_eq!(
            err.to_string(),
            "invalid_profile: seed 127.0.0.1:9/udp#2 cannot be crafted: crafted packet exceeds 65535 bytes"
        );
        assert_eq!(backend.inject_count(), 0);
    }
}
