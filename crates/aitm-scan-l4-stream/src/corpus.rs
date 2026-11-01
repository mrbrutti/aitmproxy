//! Seeds from captured flows, the profile and generation; the credential
//! filter; insertion points and the endpoint's site node (spec S5.2 steps
//! 2-5, S5.3).
//!
//! This module turns bytes into fuzzing material and nothing else: it opens no
//! socket, writes nothing to the wire and holds no state between calls. Three
//! sources feed one corpus — packets a capture already saw going to the
//! endpoint, seeds the operator wrote into the profile, and, when both are
//! empty, messages the grammar generates — de-duplicated by bytes and bounded
//! by [`MAX_SEEDS_PER_ENDPOINT`].
//!
//! Two rules here exist to keep credentials out of a scan. A seed the grammar
//! calls a credential message is stripped if the grammar knows how and
//! **dropped** if it does not, so an operator's captured `AUTH` never becomes a
//! mutation corpus; and a field that is `secret` in its grammar, or whose name
//! `aitm_core::redact::is_secret_key` recognises, reaches the site map as
//! `<redacted>` rather than as hex (spec C14, C16). [`Seed`]'s `Debug` prints
//! its bytes as a length, like every other byte-holding type in this crate
//! (spec S9, C11).

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use aitm_core::redact::is_secret_key;
use aitm_proto_l4::flow::{L4FlowId, L4FlowStore};
use aitm_proto_l4::types::{L4Direction, L4Proto};
use aitm_scan_model::{
    InsertionKind, InsertionPoint, L4Seed, L4Transport, LaneKind, ParamRef, PointTrait, SiteNode,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::codec::{decode_base64, decode_hex, encode_hex, fnv1a64, hex16};
use crate::frame::transport_payload;
use crate::grammar::{select_grammar, transport_of, Grammar, Selected, SelectionReason};
use crate::grammars::tlv;
use crate::infer::Counts;
use crate::spec::{Endian, FieldKind};
use crate::state::{
    proto_name, DiscoveredPoint, EndpointAddr, MAX_MESSAGE, MAX_POINTS_PER_ENDPOINT,
    MAX_REPEAT_INDEX, MAX_SEEDS_PER_ENDPOINT,
};
use crate::tree::Node;

/// Messages [`seeds_generated`] asks the grammar for (spec S5.2 (c)).
pub const GENERATED_SEEDS: usize = 8;

/// Bytes of a field's value an `example` shows before it is cut (spec S5.2
/// step 4: 32 bytes, so 64 hex characters).
pub const EXAMPLE_BYTES: usize = 32;

/// What an `example` says instead of a secret field's bytes.
pub const REDACTED: &str = "<redacted>";

/// One seed message and where it came from.
///
/// `Debug` prints `bytes` as a length: a seed is captured or operator-supplied
/// traffic and must never reach a log (spec S9, C11).
#[derive(Clone, PartialEq, Eq)]
pub struct Seed {
    /// `flow:<L4FlowId>#<packet index>`, `hex:<i>`, `base64:<i>` or `gen:<i>`.
    pub id: String,
    /// The message the campaign mutates.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seed")
            .field("id", &self.id)
            .field(
                "bytes",
                &format_args!("<{len} bytes>", len = self.bytes.len()),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// S5.2 (a): captured flows
// ---------------------------------------------------------------------------

/// Every distinct payload a captured flow sent to `ip:port` over `proto`
/// (spec S5.2 (a)).
///
/// The destination match is the real filter: a capture tags every packet of a
/// session with the session's direction, so the direction check only excludes
/// a capture declared inbound. An undecodable, empty or over-long payload is
/// skipped — [`transport_payload`] is total over hostile bytes (C12) — and the
/// result is capped at [`MAX_SEEDS_PER_ENDPOINT`].
#[must_use]
pub fn seeds_from_store(
    store: &dyn L4FlowStore,
    ip: IpAddr,
    port: u16,
    proto: L4Transport,
) -> Vec<Seed> {
    let mut seeds: Vec<Seed> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    for flow_id in store.list() {
        let Some(flow) = store.get(flow_id) else {
            continue;
        };
        for (index, packet) in flow.packets.iter().enumerate() {
            if seeds.len() >= MAX_SEEDS_PER_ENDPOINT {
                return seeds;
            }
            if packet.dir != L4Direction::Outbound {
                continue;
            }
            let Some(found) = transport_payload(&packet.bytes, &packet.decoded.layers) else {
                continue;
            };
            if found.dst != ip || found.dst_port != port || !proto_matches(found.proto, proto) {
                continue;
            }
            if found.payload.is_empty() || found.payload.len() > MAX_MESSAGE {
                continue;
            }
            if !seen.insert(found.payload.to_vec()) {
                continue;
            }
            seeds.push(Seed {
                id: format!(
                    "flow:{id}#{index}",
                    id = flow_id_text(flow_id),
                    index = index
                ),
                bytes: found.payload.to_vec(),
            });
        }
    }

    seeds
}

/// Whether a decoded frame's transport is the one the endpoint speaks.
fn proto_matches(found: L4Proto, wanted: L4Transport) -> bool {
    matches!(
        (found, wanted),
        (L4Proto::Tcp, L4Transport::Tcp) | (L4Proto::Udp, L4Transport::Udp)
    )
}

/// An [`L4FlowId`] as the string it carries on the bus.
///
/// `L4FlowId` has no `Display`, and the `aitm-proto-l4` helper that renders one
/// (`commands::flow_id_to_string`) is crate-private, so this goes through the
/// id's one wire form — its serde string — with the serialiser this crate
/// already depends on. An id that somehow does not serialise to a string gives
/// an empty component rather than a panic; the seed is still usable.
fn flow_id_text(id: L4FlowId) -> String {
    match serde_yaml::to_value(id) {
        Ok(serde_yaml::Value::String(text)) => text,
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// S5.2 (b): profile seeds
// ---------------------------------------------------------------------------

/// Decode the profile's `l4.seeds` (spec S5.2 (b)).
///
/// Returns the decoded seeds and one note per seed that was skipped: a `flow`
/// seed (an HTTP flow reference, which this lane cannot read), a seed that
/// decodes to nothing, one over [`MAX_MESSAGE`], and anything past
/// [`MAX_SEEDS_PER_ENDPOINT`]. The notes reach the verdict `detail`, so the
/// operator sees what their profile did not contribute.
///
/// # Errors
///
/// `scan: invalid_profile: l4.seeds[<i>]: <codec error>` when a `hex` or
/// `base64` seed does not decode. A mistyped seed fails discovery rather than
/// being silently dropped: the operator meant to send those bytes.
pub fn seeds_from_profile(seeds: &[L4Seed]) -> anyhow::Result<(Vec<Seed>, Vec<String>)> {
    let mut out: Vec<Seed> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    for (index, seed) in seeds.iter().enumerate() {
        let (id, bytes) = match seed {
            L4Seed::Hex { hex } => (
                format!("hex:{index}"),
                decode_hex(hex).map_err(|error| {
                    anyhow::anyhow!("scan: invalid_profile: l4.seeds[{index}]: {error}")
                })?,
            ),
            L4Seed::Base64 { base64 } => (
                format!("base64:{index}"),
                decode_base64(base64).map_err(|error| {
                    anyhow::anyhow!("scan: invalid_profile: l4.seeds[{index}]: {error}")
                })?,
            ),
            L4Seed::Flow { .. } => {
                skipped.push(format!(
                    "seed[{index}]: flow seeds are not L4 flows; the stream lane seeds from \
                     captured L4 packets, `hex` or `base64`"
                ));
                continue;
            }
        };

        if bytes.is_empty() {
            skipped.push(format!("seed[{index}]: decodes to no bytes"));
            continue;
        }
        if bytes.len() > MAX_MESSAGE {
            skipped.push(format!(
                "seed[{index}]: {len} bytes is over the {MAX_MESSAGE}-byte message ceiling",
                len = bytes.len()
            ));
            continue;
        }
        if out.len() >= MAX_SEEDS_PER_ENDPOINT {
            skipped.push(format!(
                "seed[{index}]: past the {MAX_SEEDS_PER_ENDPOINT}-seed ceiling for one endpoint"
            ));
            continue;
        }
        if !seen.insert(bytes.clone()) {
            continue;
        }
        out.push(Seed { id, bytes });
    }

    Ok((out, skipped))
}

// ---------------------------------------------------------------------------
// S5.2 (c): generated seeds
// ---------------------------------------------------------------------------

/// [`GENERATED_SEEDS`] messages from the grammar itself (spec S5.2 (c)).
///
/// The last resort when nothing was captured and the profile named no seed.
/// `tlv` and `raw` generate nothing, so for them this is empty and the endpoint
/// yields a node with no points, exactly as S5.2 says.
#[must_use]
pub fn seeds_generated(grammar: &dyn Grammar, rng_seed: u64) -> Vec<Seed> {
    let mut rng = ChaCha8Rng::seed_from_u64(rng_seed);
    let mut out: Vec<Seed> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();

    for index in 0..GENERATED_SEEDS {
        let bytes = grammar.generate(&mut rng);
        if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
            continue;
        }
        if !seen.insert(bytes.clone()) {
            continue;
        }
        out.push(Seed {
            id: format!("gen:{index}"),
            bytes,
        });
    }

    out
}

// ---------------------------------------------------------------------------
// C14: the credential filter
// ---------------------------------------------------------------------------

/// Strip or drop every credential-carrying seed (spec C14).
///
/// A grammar that can remove the credentials and leave a valid message (MQTT's
/// CONNECT) keeps its seed, with the credentials gone; one that cannot (a RESP
/// `AUTH`, an SMTP `AUTH`, an FTP `PASS`) loses the seed entirely. The stripped
/// message is checked again, so a strip that did not actually clear the
/// credential flags still drops the seed. The count is returned for the
/// discovery log line and the verdict `detail`.
#[must_use]
pub fn filter_credentials(grammar: &dyn Grammar, seeds: Vec<Seed>) -> (Vec<Seed>, u32) {
    let mut kept: Vec<Seed> = Vec::with_capacity(seeds.len());
    let mut dropped: u32 = 0;

    for seed in seeds {
        if !grammar.is_credential_message(&seed.bytes) {
            kept.push(seed);
            continue;
        }
        match grammar.strip_credentials(&seed.bytes) {
            Some(stripped) if !stripped.is_empty() && !grammar.is_credential_message(&stripped) => {
                kept.push(Seed {
                    id: seed.id,
                    bytes: stripped,
                });
            }
            _ => dropped = dropped.saturating_add(1),
        }
    }

    (kept, dropped)
}

// ---------------------------------------------------------------------------
// S5.3: identifiers
// ---------------------------------------------------------------------------

/// The site node's id for one endpoint: `l4s-<proto>-<ip>-<port>` with an
/// IPv6 address's colons replaced by `-` (spec S5.2 step 5).
#[must_use]
pub fn node_id(ip: IpAddr, port: u16, proto: L4Transport) -> String {
    format!(
        "l4s-{proto}-{ip}-{port}",
        proto = proto_name(proto),
        ip = ip.to_string().replace(':', "-"),
    )
}

/// A point's id: `l4s-` and 16 hex digits of FNV-1a 64 over
/// `<node id>|<seed id>|<path>` (spec S5.3).
///
/// Stable across runs for the same endpoint, seed and field, which is what
/// lets a finding be re-opened against the same point (C16). It is a label,
/// not a security primitive.
#[must_use]
pub fn point_id(node_id: &str, seed_id: &str, path: &str) -> String {
    let label = format!("{node_id}|{seed_id}|{path}");
    format!("l4s-{digest}", digest = hex16(fnv1a64(label.as_bytes())))
}

/// How a point's `url` names its endpoint: `<tcp|udp>://<ip>:<port>/<grammar>`,
/// an IPv6 address bracketed as a URL authority requires.
fn endpoint_url(endpoint: EndpointAddr, grammar_name: &str) -> String {
    let host = match endpoint.ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!(
        "{proto}://{host}:{port}/{grammar_name}",
        proto = proto_name(endpoint.proto),
        port = endpoint.port,
    )
}

/// Why a grammar was selected, as the evidence and the discovery line say it.
#[must_use]
pub fn selection_text(reason: &SelectionReason) -> String {
    match reason {
        SelectionReason::Named => "named".to_string(),
        SelectionReason::DefaultPort(port) => format!("default port {port}"),
        SelectionReason::Inferred(descriptor) => {
            let endian = match descriptor.endian {
                Endian::Be => "be",
                Endian::Le => "le",
            };
            let counts = match descriptor.counts {
                Counts::BodyOnly => "body only",
                Counts::Inclusive => "inclusive",
                Counts::Whole => "whole message",
            };
            let adjust = if descriptor.adjust == 0 {
                String::new()
            } else {
                format!(", adjust {adjust}", adjust = descriptor.adjust)
            };
            format!(
                "inferred {width}-byte {endian} length at offset {offset} counting {counts}{adjust}",
                width = descriptor.width,
                offset = descriptor.offset,
            )
        }
        SelectionReason::RawFallback(text) => format!("raw fallback: {text}"),
    }
}

// ---------------------------------------------------------------------------
// S5.2 step 4: points
// ---------------------------------------------------------------------------

/// One point per (seed, mutable leaf), in seed order then tree order
/// (spec S5.2 step 4).
///
/// Elements of a `repeat` past [`MAX_REPEAT_INDEX`] yield no points: a
/// thousand-element array would otherwise bury every other field, and the
/// mutators reach the later elements through the structure-aware set anyway.
/// A collapsed element is not a drop. Past [`MAX_POINTS_PER_ENDPOINT`] the
/// points really are dropped, and the returned count says how many.
#[must_use]
pub fn build_points(
    node_id: &str,
    endpoint: EndpointAddr,
    grammar: &dyn Grammar,
    seeds: &[Seed],
    scope_entry: &str,
    selection: &SelectionReason,
) -> (Vec<DiscoveredPoint>, u32) {
    let url = endpoint_url(endpoint, grammar.name());
    let selection = selection_text(selection);
    let mut points: Vec<DiscoveredPoint> = Vec::new();
    let mut dropped: u32 = 0;

    for seed in seeds {
        let Some(tree) = grammar.parse(&seed.bytes) else {
            continue;
        };
        for node in tree.mutable_leaves() {
            let path = node.path.as_str();
            if is_collapsed_element(path) {
                continue;
            }
            if points.len() >= MAX_POINTS_PER_ENDPOINT {
                dropped = dropped.saturating_add(1);
                continue;
            }
            let name = node.path.last().to_string();
            points.push(DiscoveredPoint {
                point: InsertionPoint {
                    id: point_id(node_id, &seed.id, path),
                    lane: LaneKind::L4Stream,
                    kind: InsertionKind::L4Field,
                    example: Some(example_of(node, &name)),
                    name,
                    path: Some(path.to_string()),
                    // An `L4FlowId` is not a `FlowId`: the seed id carries the
                    // provenance instead (spec S5.2 step 4).
                    flow: None,
                    site_node: Some(node_id.to_string()),
                    traits: traits_of(&node.kind),
                    frequency: 1,
                    method: Some("L4".to_string()),
                    url: Some(url.clone()),
                },
                node_id: node_id.to_string(),
                endpoint,
                grammar: grammar.kind(),
                seed_id: seed.id.clone(),
                seed_bytes: seed.bytes.clone(),
                scope_entry: scope_entry.to_string(),
                selection: selection.clone(),
            });
        }
    }

    (points, dropped)
}

/// Whether a path names an element of a `repeat` past [`MAX_REPEAT_INDEX`].
///
/// Reads every `[<n>]` component of the path, so `args[7].data` and
/// `questions[0].name.labels[9].text` are both collapsed. A bracket that holds
/// no number is not an index and does not collapse anything.
fn is_collapsed_element(path: &str) -> bool {
    let mut rest = path;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(']') else {
            return false;
        };
        if let Ok(index) = after[..close].parse::<usize>() {
            if index > MAX_REPEAT_INDEX {
                return true;
            }
        }
        rest = &after[close + 1..];
    }
    false
}

/// A field's `example`: lowercase hex bounded to [`EXAMPLE_BYTES`] bytes, or
/// [`REDACTED`] for a field the grammar marked `secret` or whose name
/// `aitm_core::redact::is_secret_key` recognises (spec S5.2 step 4, C14).
fn example_of(node: &Node, name: &str) -> String {
    if node.secret || is_secret_key(name) {
        return REDACTED.to_string();
    }
    let shown = node.bytes.get(..EXAMPLE_BYTES).unwrap_or(&node.bytes);
    let mut text = encode_hex(shown);
    if node.bytes.len() > EXAMPLE_BYTES {
        text.push_str("...");
    }
    text
}

/// What a field's value looks like to the scheduler: a number, or nothing we
/// can say (spec S5.2 step 4).
fn traits_of(kind: &FieldKind) -> Vec<PointTrait> {
    match kind {
        FieldKind::U8
        | FieldKind::U16 { .. }
        | FieldKind::U32 { .. }
        | FieldKind::Varint
        | FieldKind::Decimal => vec![PointTrait::Number],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// S5.2 step 5: the node
// ---------------------------------------------------------------------------

/// The endpoint's site-map node (spec S5.2 step 5).
///
/// `path_template` is `/<grammar>`, so a reader of the site map — and
/// `L4Location.grammar` — can see which grammar the lane spoke without
/// consulting the job.
#[must_use]
pub fn build_node(
    node_id: &str,
    endpoint: EndpointAddr,
    grammar_name: &str,
    points: &[DiscoveredPoint],
) -> SiteNode {
    let mut params: Vec<ParamRef> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for point in points {
        if seen.insert(point.point.name.as_str()) {
            params.push(ParamRef {
                kind: InsertionKind::L4Field,
                name: point.point.name.clone(),
            });
        }
    }

    SiteNode {
        id: node_id.to_string(),
        method: "L4".to_string(),
        scheme: proto_name(endpoint.proto).to_string(),
        host: endpoint.ip.to_string(),
        port: endpoint.port,
        path_template: format!("/{grammar_name}"),
        flows: Vec::new(),
        params,
        auth: false,
        points: u32::try_from(points.len()).unwrap_or(u32::MAX),
        audited: false,
    }
}

// ---------------------------------------------------------------------------
// S3: selection, with this crate's TLV inference wired in
// ---------------------------------------------------------------------------

/// [`select_grammar`] with the TLV inference closure already built.
///
/// Inference runs on the target's own transport, so a UDP TLV service gets a
/// liveness probe that insists on a reply where a TCP one may just stay open.
///
/// # Errors
///
/// `scan: invalid_profile: ...` when the profile names an unknown grammar, or
/// one that speaks a transport this endpoint does not.
pub fn select_for(
    named: Option<&str>,
    proto: L4Transport,
    port: u16,
    seeds: &[Seed],
) -> anyhow::Result<Selected> {
    let transport = transport_of(proto);
    let bytes: Vec<Vec<u8>> = seeds.iter().map(|seed| seed.bytes.clone()).collect();
    select_grammar(named, proto, port, &bytes, &|candidates| {
        tlv::from_seeds_on(candidates, transport).map_err(|refusal| refusal.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    use aitm_core::FlowId;
    use aitm_proto_l4::craft::PacketSummary;
    use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4Bind, L4Flow, L4FlowKind, L4Meta, L4Packet};
    use aitm_scan_model::FlowRef;

    use crate::grammar::{Exchange, Expect, ReplyClass};
    use crate::spec::{FieldSpec, GrammarKind, MessageSpec, Transport};
    use crate::tree::{FieldPath, Tree};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    fn endpoint() -> EndpointAddr {
        EndpointAddr {
            ip: LOCALHOST,
            port: 9000,
            proto: L4Transport::Tcp,
        }
    }

    // -----------------------------------------------------------------
    // Hand-built frames: Ethernet II + IPv4 + TCP, the shape `frame.rs`'s
    // own tests pin.
    // -----------------------------------------------------------------

    fn ethernet_ipv4_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_length = u16::try_from(20 + 20 + payload.len()).expect("a small test frame");
        let mut frame = vec![
            // Ethernet: dst MAC, src MAC, ethertype IPv4.
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, //
            0x08, 0x00, //
            // IPv4: v4/IHL 5, DSCP.
            0x45, 0x00,
        ];
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x01, 0x40, 0x00, // id, flags
            0x40, 0x06, 0x00, 0x00, // ttl 64, proto 6 (TCP), checksum
        ]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x02, // ack
            0x50, 0x18, // data offset 5, PSH|ACK
            0x20, 0x00, // window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent pointer
        ]);
        frame.extend_from_slice(payload);
        frame
    }

    fn outbound(bytes: Vec<u8>) -> L4Packet {
        let length = bytes.len();
        L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            bytes,
            decoded: PacketSummary {
                layers: vec![
                    "Ethernet".to_string(),
                    "IPv4".to_string(),
                    "TCP".to_string(),
                ],
                length,
            },
            injected: false,
        }
    }

    // -----------------------------------------------------------------
    // Test grammars: one driven by a `MessageSpec`, one handing back a
    // fixed wide tree no spec may declare (`MAX_FIELDS` is 256).
    // -----------------------------------------------------------------

    struct TestGrammar {
        spec: MessageSpec,
        fixed: Option<Tree>,
    }

    impl Grammar for TestGrammar {
        fn kind(&self) -> GrammarKind {
            GrammarKind::Raw
        }

        fn name(&self) -> &'static str {
            "testgram"
        }

        fn spec(&self) -> &MessageSpec {
            &self.spec
        }

        fn default_ports(&self) -> &'static [u16] {
            &[]
        }

        fn transport(&self) -> Transport {
            Transport::Tcp
        }

        fn parse(&self, bytes: &[u8]) -> Option<Tree> {
            match &self.fixed {
                Some(tree) => Some(tree.clone()),
                None => crate::tree::parse(&self.spec, bytes),
            }
        }

        fn generate(&self, _rng: &mut ChaCha8Rng) -> Vec<u8> {
            Vec::new()
        }

        fn classify_reply(&self, _reply: &[u8]) -> ReplyClass {
            ReplyClass::Unknown
        }

        fn reply_complete(&self, _buf: &[u8]) -> bool {
            true
        }

        fn liveness_probe(&self) -> Exchange {
            Exchange {
                send: Vec::new(),
                expect: Expect::AnyReply,
                after: None,
            }
        }

        fn prelude(&self) -> Vec<Vec<u8>> {
            Vec::new()
        }

        fn is_credential_message(&self, _bytes: &[u8]) -> bool {
            false
        }
    }

    /// A grammar over `payload` (100 bytes) then `password` (4 bytes).
    fn payload_password_grammar() -> TestGrammar {
        TestGrammar {
            spec: MessageSpec {
                grammar: "testgram".to_string(),
                transport: Transport::Tcp,
                message: vec![
                    FieldSpec {
                        name: "payload".to_string(),
                        kind: FieldKind::Bytes { size: Some(100) },
                        ..FieldSpec::default()
                    },
                    FieldSpec {
                        name: "password".to_string(),
                        kind: FieldKind::Bytes { size: Some(4) },
                        ..FieldSpec::default()
                    },
                ],
                ..MessageSpec::default()
            },
            fixed: None,
        }
    }

    /// A grammar whose every parse yields `leaves` mutable one-byte leaves.
    fn wide_grammar(leaves: usize) -> TestGrammar {
        let root = (0..leaves)
            .map(|i| Node {
                path: FieldPath::new(&format!("f{i}")),
                kind: FieldKind::Bytes { size: Some(1) },
                bytes: vec![0x41],
                children: Vec::new(),
                relation: None,
                mutable: true,
                secret: false,
                relation_broken: false,
            })
            .collect();
        TestGrammar {
            spec: MessageSpec {
                grammar: "testgram".to_string(),
                transport: Transport::Tcp,
                ..MessageSpec::default()
            },
            fixed: Some(Tree {
                grammar: "testgram".to_string(),
                root,
            }),
        }
    }

    // -----------------------------------------------------------------
    // The tests
    // -----------------------------------------------------------------

    #[test]
    fn store_seeds_match_destination_only() {
        let store = InMemoryL4FlowStore::new();
        let flow_id = store.insert(L4Flow {
            id: aitm_proto_l4::flow::L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind::default(),
            packets: VecDeque::from(vec![
                // To the endpoint: the only seed.
                outbound(ethernet_ipv4_tcp(
                    [127, 0, 0, 1],
                    [127, 0, 0, 1],
                    51000,
                    9000,
                    b"A",
                )),
                // From the endpoint back to the client: not a seed.
                outbound(ethernet_ipv4_tcp(
                    [127, 0, 0, 1],
                    [127, 0, 0, 1],
                    9000,
                    51000,
                    b"B",
                )),
                // To another port on the same host: not a seed.
                outbound(ethernet_ipv4_tcp(
                    [127, 0, 0, 1],
                    [127, 0, 0, 1],
                    51000,
                    9001,
                    b"C",
                )),
            ]),
            metadata: L4Meta::default(),
        });

        let seeds = seeds_from_store(&store, LOCALHOST, 9000, L4Transport::Tcp);

        assert_eq!(
            seeds.len(),
            1,
            "only the packet to 127.0.0.1:9000 is a seed"
        );
        assert_eq!(seeds[0].bytes, b"A".to_vec());
        assert_eq!(seeds[0].id, format!("flow:{}#0", flow_id_text(flow_id)));
        // The id really carries the flow's uuid and the packet's index.
        let uuid = seeds[0]
            .id
            .trim_start_matches("flow:")
            .trim_end_matches("#0");
        assert_eq!(uuid.len(), 36, "a uuid, not an empty or debug-wrapped id");
        assert_eq!(uuid.matches('-').count(), 4);
    }

    #[test]
    fn profile_seed_decoding() {
        let (seeds, skipped) = seeds_from_profile(&[
            L4Seed::Hex {
                hex: "00ff".to_string(),
            },
            L4Seed::Base64 {
                base64: "AAE=".to_string(),
            },
            L4Seed::Flow {
                flow: FlowRef(FlowId::new()),
            },
        ])
        .expect("two decodable seeds and one skipped flow seed");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].id, "hex:0");
        assert_eq!(seeds[0].bytes, vec![0x00, 0xff]);
        assert_eq!(seeds[1].id, "base64:1");
        assert_eq!(seeds[1].bytes, vec![0x00, 0x01]);
        assert_eq!(skipped.len(), 1);
        assert!(
            skipped[0].contains("flow seeds are not L4 flows"),
            "note was {note:?}",
            note = skipped[0]
        );
        assert!(skipped[0].contains("seed[2]"), "note names the index");

        let err = seeds_from_profile(&[L4Seed::Hex {
            hex: "zz".to_string(),
        }])
        .expect_err("a non-hex digit fails discovery");
        assert!(
            err.to_string()
                .starts_with("scan: invalid_profile: l4.seeds[0]"),
            "error was {err}"
        );
    }

    #[test]
    fn credential_filter_counts() {
        let resp = crate::grammars::resp::grammar();
        let (kept, dropped) = filter_credentials(
            resp.as_ref(),
            vec![
                Seed {
                    id: "hex:0".to_string(),
                    bytes: b"*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n".to_vec(),
                },
                Seed {
                    id: "hex:1".to_string(),
                    bytes: b"PING\r\n".to_vec(),
                },
            ],
        );
        assert_eq!(dropped, 1, "RESP cannot strip an AUTH, so it is dropped");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "hex:1");
        assert_eq!(kept[0].bytes, b"PING\r\n".to_vec());

        // A CONNECT with username `u` and password `p`.
        let connect = vec![
            0x10, 0x13, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0xc2, 0x00, 0x3c, 0x00, 0x01,
            0x63, 0x00, 0x01, 0x75, 0x00, 0x01, 0x70,
        ];
        let mqtt = crate::grammars::mqtt::grammar();
        let (kept, dropped) = filter_credentials(
            mqtt.as_ref(),
            vec![Seed {
                id: "hex:0".to_string(),
                bytes: connect.clone(),
            }],
        );
        assert_eq!(
            dropped, 0,
            "a CONNECT's credentials are stripped, not dropped"
        );
        assert_eq!(kept.len(), 1);
        assert_ne!(kept[0].bytes, connect);
        assert_eq!(
            kept[0].bytes,
            vec![
                0x10, 0x0d, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x01,
                0x63
            ]
        );
        assert!(!mqtt.is_credential_message(&kept[0].bytes));
    }

    #[test]
    fn point_ids_are_stable_and_examples_bounded() {
        let resp = crate::grammars::resp::grammar();
        let node = node_id(LOCALHOST, 9000, L4Transport::Tcp);
        let seeds = vec![Seed {
            id: "hex:0".to_string(),
            bytes: b"*2\r\n$4\r\nECHO\r\n$2\r\nhi\r\n".to_vec(),
        }];

        let (first, dropped) = build_points(
            &node,
            endpoint(),
            resp.as_ref(),
            &seeds,
            "127.0.0.1/32:9000/tcp",
            &SelectionReason::DefaultPort(6379),
        );
        let (again, _) = build_points(
            &node,
            endpoint(),
            resp.as_ref(),
            &seeds,
            "127.0.0.1/32:9000/tcp",
            &SelectionReason::DefaultPort(6379),
        );

        assert_eq!(dropped, 0);
        assert_eq!(first.len(), 13, "the 13 mutable leaves of a 2-arg array");
        let ids: Vec<&str> = first.iter().map(|p| p.point.id.as_str()).collect();
        let ids_again: Vec<&str> = again.iter().map(|p| p.point.id.as_str()).collect();
        assert_eq!(ids, ids_again, "ids are stable across runs (C16)");
        assert_eq!(
            point_id(&node, "hex:0", "array.star"),
            first[0].point.id,
            "the id is fnv1a64 over node|seed|path"
        );
        assert!(
            first[0].point.id.starts_with("l4s-") && first[0].point.id.len() == 20,
            "id was {id}",
            id = first[0].point.id
        );

        let data = first
            .iter()
            .find(|p| p.point.path.as_deref() == Some("args[1].data"))
            .expect("the second argument's data is a point");
        assert_eq!(data.point.name, "data");
        assert_eq!(data.point.lane, LaneKind::L4Stream);
        assert_eq!(data.point.kind, InsertionKind::L4Field);
        assert_eq!(data.point.example.as_deref(), Some("6869"));
        assert_eq!(data.point.flow, None);
        assert_eq!(data.point.site_node.as_deref(), Some(node.as_str()));
        assert_eq!(data.point.traits, Vec::new());
        assert_eq!(data.point.frequency, 1);
        assert_eq!(data.point.method.as_deref(), Some("L4"));
        assert_eq!(data.point.url.as_deref(), Some("tcp://127.0.0.1:9000/resp"));
        assert_eq!(data.node_id, node);
        assert_eq!(data.endpoint, endpoint());
        assert_eq!(data.grammar, GrammarKind::Resp);
        assert_eq!(data.seed_id, "hex:0");
        assert_eq!(data.seed_bytes, seeds[0].bytes);
        assert_eq!(data.scope_entry, "127.0.0.1/32:9000/tcp");
        assert_eq!(data.selection, "default port 6379");

        let len = first
            .iter()
            .find(|p| p.point.path.as_deref() == Some("args[1].len"))
            .expect("the second argument's length is a point");
        assert_eq!(len.point.traits, vec![PointTrait::Number]);

        // A 100-byte field is shown as 64 hex characters and an ellipsis; a
        // field whose name `is_secret_key` matches is not shown at all.
        let wide = payload_password_grammar();
        let mut message = vec![0xab; 100];
        message.extend_from_slice(b"hunt");
        let (points, _) = build_points(
            &node,
            endpoint(),
            &wide,
            &[Seed {
                id: "hex:0".to_string(),
                bytes: message,
            }],
            "127.0.0.1/32:9000/tcp",
            &SelectionReason::Named,
        );
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].point.name, "payload");
        let example = points[0]
            .point
            .example
            .clone()
            .expect("a payload field has an example");
        assert_eq!(example, format!("{}...", "ab".repeat(32)));
        assert_eq!(example.len(), 67);
        assert_eq!(points[1].point.name, "password");
        assert_eq!(points[1].point.example.as_deref(), Some("<redacted>"));
        assert_eq!(
            points[1].point.url.as_deref(),
            Some("tcp://127.0.0.1:9000/testgram")
        );
        assert_eq!(points[0].selection, "named");
    }

    #[test]
    fn point_cap_and_repeat_collapse() {
        let node = node_id(LOCALHOST, 9000, L4Transport::Tcp);

        // Ten arguments; only `args[0..=3]` yield points.
        let mut message = b"*10\r\n".to_vec();
        for _ in 0..10 {
            message.extend_from_slice(b"$1\r\nx\r\n");
        }
        let resp = crate::grammars::resp::grammar();
        let (points, dropped) = build_points(
            &node,
            endpoint(),
            resp.as_ref(),
            &[Seed {
                id: "hex:0".to_string(),
                bytes: message,
            }],
            "entry",
            &SelectionReason::Named,
        );
        assert_eq!(dropped, 0, "a collapsed repeat element is not a drop");
        assert_eq!(points.len(), 23, "3 array leaves + 4 elements x 5 leaves");
        for point in &points {
            let path = point.point.path.clone().unwrap_or_default();
            for index in 4..10 {
                assert!(
                    !path.contains(&format!("args[{index}]")),
                    "element {index} must collapse; path was {path}"
                );
            }
        }
        assert!(points
            .iter()
            .any(|p| p.point.path.as_deref() == Some("args[3].data")));

        // 300 mutable leaves, 256 points, the rest dropped and counted.
        let wide = wide_grammar(300);
        let (points, dropped) = build_points(
            &node,
            endpoint(),
            &wide,
            &[Seed {
                id: "gen:0".to_string(),
                bytes: b"x".to_vec(),
            }],
            "entry",
            &SelectionReason::Named,
        );
        assert_eq!(points.len(), MAX_POINTS_PER_ENDPOINT);
        assert_eq!(points.len(), 256);
        assert_eq!(dropped, 44);
    }

    #[test]
    fn node_shape() {
        let resp = crate::grammars::resp::grammar();
        let node = node_id(LOCALHOST, 9000, L4Transport::Tcp);
        let (points, _) = build_points(
            &node,
            endpoint(),
            resp.as_ref(),
            &[Seed {
                id: "hex:0".to_string(),
                bytes: b"*2\r\n$4\r\nECHO\r\n$2\r\nhi\r\n".to_vec(),
            }],
            "entry",
            &SelectionReason::DefaultPort(6379),
        );

        let site = build_node(&node, endpoint(), resp.name(), &points);

        assert_eq!(site.id, "l4s-tcp-127.0.0.1-9000");
        assert_eq!(site.method, "L4");
        assert_eq!(site.scheme, "tcp");
        assert_eq!(site.host, "127.0.0.1");
        assert_eq!(site.port, 9000);
        assert_eq!(site.path_template, "/resp");
        assert_eq!(site.flows, Vec::new());
        assert_eq!(site.points, 13);
        assert_eq!(site.points as usize, points.len());
        assert!(!site.auth);
        assert!(!site.audited);
        // One `ParamRef` per distinct field name, in first-seen order.
        let names: Vec<&str> = site.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["star", "count", "crlf", "dollar", "len", "data", "crlf2"]
        );
        assert!(site.params.iter().all(|p| p.kind == InsertionKind::L4Field));
    }

    #[test]
    fn select_for_infers_tlv_from_the_corpus() {
        // Port 1 is nobody's convention, so selection falls to inference.
        let seeds = vec![
            Seed {
                id: "hex:0".to_string(),
                bytes: vec![0x00, 0x02, 0xaa, 0xbb],
            },
            Seed {
                id: "hex:1".to_string(),
                bytes: vec![0x00, 0x01, 0xff],
            },
        ];
        let selected =
            select_for(None, L4Transport::Tcp, 1, &seeds).expect("selection never fails here");
        assert_eq!(selected.grammar.name(), "tlv");
        assert!(
            matches!(selected.reason, SelectionReason::Inferred(_)),
            "reason was {reason:?}",
            reason = selected.reason
        );

        // With one seed inference refuses and the lane falls back to `raw`.
        let selected =
            select_for(None, L4Transport::Tcp, 1, &seeds[..1]).expect("selection never fails here");
        assert_eq!(selected.grammar.name(), "raw");
        assert_eq!(
            selected.reason,
            SelectionReason::RawFallback("tlv inference refused: too_few_seeds".to_string())
        );
    }
}
