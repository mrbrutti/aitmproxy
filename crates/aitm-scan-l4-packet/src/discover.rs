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

use crate::codec::{base64_decode, hex_decode, hex_encode, CodecError};
use crate::fields::{validate_fields, FieldError, FieldPath, IpVersion};
use crate::mutate::declared_value;
use crate::plan::{
    link_framing, point_id, src_port_for, ResolvedTarget, SeedOrigin, SeedPayload, SeedSpec,
    TargetPlan,
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
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidProfile(_) => "invalid_profile",
            Self::OutOfScope(_) => "out_of_scope",
            Self::LaneUnavailable(_) => "lane_unavailable",
        }
    }

    /// The message behind the code.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidProfile(m) | Self::OutOfScope(m) | Self::LaneUnavailable(m) => m,
        }
    }
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (code, message) = (self.code(), self.message());
        // A message handed through verbatim from `FieldError` or `PlanError`
        // already carries the code (that is how the offending path keeps its
        // `invalid_profile: ` prefix), so print it once, never twice.
        if message
            .strip_prefix(code)
            .is_some_and(|rest| rest.starts_with(": "))
        {
            f.write_str(message)
        } else {
            write!(f, "{code}: {message}")
        }
    }
}

impl std::error::Error for DiscoverError {}

impl From<FieldError> for DiscoverError {
    fn from(err: FieldError) -> Self {
        // `FieldError`'s rendering already starts with `invalid_profile: ` and
        // names the offending path; keep it verbatim.
        Self::InvalidProfile(err.to_string())
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

/// `"<ip>:<port>"`, IPv6 bracketed so the port stays unambiguous.
fn host_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// The wire name of a transport, as a target key and a point id spell it.
const fn transport_name(proto: L4Transport) -> &'static str {
    match proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    }
}

/// `"<ip>:<port>/<proto>"` — the key a seed id and a refusal message name a
/// target by (`crate::plan` keeps its own private copy for `TargetPlan::key`).
fn target_key(ip: IpAddr, port: u16, proto: L4Transport) -> String {
    format!("{}/{}", host_port(ip, port), transport_name(proto))
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
/// of `40000 + index`, `+1`, `+2`, ... that is not one of the core's own
/// listener ports, so the reply capture's self-exclusion never drops the lane's
/// own replies (call C25).
#[must_use]
pub fn choose_src_port(guard: &L4Guard, target_index: usize) -> u16 {
    let self_ports = guard.self_ports();
    let mut port = src_port_for(target_index);
    while self_ports.contains(&port) {
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

    // (a) The operator's own seeds, in profile order.
    for seed in &options.seeds {
        match seed {
            L4Seed::Hex { hex } => push(hex_decode(hex)?, SeedOrigin::Profile, &mut out),
            L4Seed::Base64 { base64 } => {
                push(base64_decode(base64)?, SeedOrigin::Profile, &mut out);
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
                    push(payload, SeedOrigin::Captured, &mut out);
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

/// One insertion point per field of this target, in field order.
///
/// `example` is the value the seed actually puts on the wire — decimal for a
/// header field, hex for the raw payload — so a UI shows what a case starts
/// from. Every point is lane-local: no site node, no flow (call C6).
#[must_use]
pub fn points_for(
    target: &ResolvedTarget,
    fields: &[FieldPath],
    seed: &SeedSpec,
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
                FieldPath::Raw => Some(hex_encode(raw_payload(seed))),
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
/// `requested` is the operator's field list, passed in by the lane rather than
/// read here, so this function stays pure of the `L4Options.fields` integration
/// shim (`crate::plan::requested_fields`, call C1). An empty list is the
/// target's default field table.
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
            .map_err(DiscoverError::InvalidProfile)?;
        let seeds = seed_payloads(&resolved, &profile.l4, seed_store, marker)?;
        let src_port = choose_src_port(guard, index);

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
        // The seed corpus is never empty, so case 0 always has a seed; a seed
        // that does not build is the operator's bytes, and is refused here
        // rather than at send time.
        let seed = plan
            .seed_spec(0)
            .map_err(|err| DiscoverError::InvalidProfile(err.to_string()))?;
        points.extend(points_for(&plan.target, &plan.fields, &seed));
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
        choose_src_port, default_payload, discover_all, loopback_interface, points_for,
        probe_privilege, resolve_target, seed_payloads, DiscoverError,
    };
    use crate::fields::{default_fields, IpVersion};
    use crate::plan::{link_framing, SeedOrigin, TargetPlan};
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
        let guard = guard_over(IpAddr::from([10, 0, 0, 0]), 8, "en0", &BOTH);
        let spec = aitm_scan_model::profile::L4TargetSpec {
            ip: "10.1.2.3".to_string(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        };
        let err = resolve_target(&guard, &spec).expect_err("v2 is loopback only");

        let DiscoverError::LaneUnavailable(message) = &err else {
            panic!("expected lane_unavailable, got {err:?}");
        };
        assert!(message.contains("loopback"), "{message}");
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
        let points = points_for(&plan.target, &plan.fields, &seed);

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
        assert_eq!(
            example("raw").as_deref(),
            Some("6169746d376633612020202020202020")
        );
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
            assert!(message.starts_with("invalid_profile:"), "{message}");
            assert!(message.contains(pin), "{message}");
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

        assert_eq!(choose_src_port(&guard, 0), 40_001);
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
}
