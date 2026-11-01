//! `l4.flow.list` / `.get` — query the l4-owned flow store.
//!
//! Sensitivity: **read-only**. These read the [`L4FlowStore`](crate::flow::L4FlowStore)
//! the capture / craft / send-recv / intercept paths populate; they never touch the
//! wire or the guard. They keep L4 flows first-class over MCP / CLI / Rhai without
//! an `aitm-core` edit (the store lives in `aitm-proto-l4`).

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use super::{epoch_ms, field};
use crate::craft::{PacketEndpoints, PacketSpec};
use crate::flow::{L4Flow, L4FlowStore};
use crate::gates::{AgentGate, L4AgentGates};

/// How many packets `l4.flow.get` returns when the caller gives no `limit`.
pub(crate) const FLOW_GET_DEFAULT_LIMIT: usize = 256;
/// The most packets one `l4.flow.get` reply carries; a larger `limit` is clamped.
pub(crate) const FLOW_GET_MAX_LIMIT: usize = 4096;
/// The most raw packet bytes one `l4.flow.get` reply carries when the caller sees
/// `bytes` (spec §2, L4PAR-AC36). 4 MiB raw is about 5.6 MiB of base64, and the
/// MCP server sends the value twice (`structuredContent` plus the `content`
/// text), so a full reply stays under the bus's 16 MiB message cap.
pub(crate) const FLOW_GET_MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// The `[offset, offset + limit)` slice of a flow's packet log that one
/// `l4.flow.get` reply carries (spec §2, L4PAR-AC2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacketWindow {
    /// Index of the first packet returned.
    pub(crate) offset: usize,
    /// How many packets to return at most; `0` returns none.
    pub(crate) limit: usize,
}

impl Default for PacketWindow {
    /// The window an argument-less call (or the Rhai `l4.flow.get`) gets: the
    /// first [`FLOW_GET_DEFAULT_LIMIT`] packets.
    fn default() -> Self {
        PacketWindow {
            offset: 0,
            limit: FLOW_GET_DEFAULT_LIMIT,
        }
    }
}

impl PacketWindow {
    /// Read `offset` / `limit` from a command's params: absent ⇒ the default,
    /// negative ⇒ an error naming the param, `limit` clamped to
    /// [`FLOW_GET_MAX_LIMIT`].
    pub(crate) fn from_params(args: &Params) -> anyhow::Result<PacketWindow> {
        Self::from_values(args.get("offset"), args.get("limit"))
    }

    /// The window from two optional values — the command's `offset` / `limit`
    /// params, or the Rhai `l4.flow.get(id, offset?, limit?)` positional
    /// arguments — so both faces parse it identically. `None` or `Null` ⇒ the
    /// default; a non-integer ⇒ an error naming the argument; negative ⇒ an error
    /// naming it; `limit` clamped to [`FLOW_GET_MAX_LIMIT`].
    pub(crate) fn from_values(
        offset: Option<&Value>,
        limit: Option<&Value>,
    ) -> anyhow::Result<PacketWindow> {
        let read = |name: &str, v: Option<&Value>, default: usize| -> anyhow::Result<usize> {
            match v {
                None | Some(Value::Null) => Ok(default),
                Some(Value::Int(i)) => usize::try_from(*i)
                    .map_err(|_| anyhow::anyhow!("`{name}` must be a non-negative integer")),
                Some(_) => Err(anyhow::anyhow!("`{name}` must be an integer")),
            }
        };
        let default = Self::default();
        let offset = read("offset", offset, default.offset)?;
        let limit = read("limit", limit, default.limit)?.min(FLOW_GET_MAX_LIMIT);
        Ok(PacketWindow { offset, limit })
    }
}

/// `l4.flow.list` → the ids of every stored L4 flow, oldest first.
pub struct FlowList {
    store: Arc<dyn L4FlowStore>,
}

impl FlowList {
    /// A command over the shared flow store.
    pub fn new(store: Arc<dyn L4FlowStore>) -> Self {
        Self { store }
    }
}

impl Command for FlowList {
    fn name(&self) -> &str {
        "l4.flow.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the ids of every captured / crafted / send-recv / intercepted L4 \
                          flow, oldest first (read-only)."
                .into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Str)),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            self.store
                .list()
                .into_iter()
                .map(|id| Value::Str(super::flow_id_to_string(id)))
                .collect(),
        ))
    }
}

/// `l4.flow.get {id}` → a summary of one L4 flow and its packets.
///
/// A packet's `bytes` reach only a trusted-control caller (operator, CLI) or an
/// agent holding the gate that could have produced **that packet** (spec §2.2 as
/// amended, L4PAR-AC35; see [`bytes_visible`]): an agent that could not have
/// obtained the bytes itself must not read them, and in particular must not read
/// the bus-token line off a loopback capture. Every other packet field is
/// reported to every caller.
pub struct FlowGet {
    store: Arc<dyn L4FlowStore>,
    gates: Arc<L4AgentGates>,
}

impl FlowGet {
    /// A command over the shared flow store, reading the shared agent gates to
    /// decide whether this caller sees packet bytes.
    pub fn new(store: Arc<dyn L4FlowStore>, gates: Arc<L4AgentGates>) -> Self {
        Self { store, gates }
    }
}

/// Whether a caller sees **one packet's** `bytes` (spec §2.2 as amended, decided
/// per packet, never per flow kind): trusted control always; an agent only while
/// it holds the gate that could have produced that packet — the Inject gate for an
/// `injected` packet (one the core put on the wire for it), the Capture gate for
/// every other (captured traffic, whatever flow recorded it: a capture, a
/// `send_recv` reply, an intercept-parked packet). An agent with that gate open
/// could have obtained the bytes itself, so this widens nothing; a gate for
/// another primitive (Intercept, Widen) reveals nothing. Shared by the command
/// path and the Rhai `l4.flow.get`, so the two faces cannot drift.
pub(crate) fn bytes_visible(
    caller_is_trusted_control: bool,
    injected: bool,
    gates: &L4AgentGates,
) -> bool {
    if caller_is_trusted_control {
        return true;
    }
    gates.allowed(if injected {
        AgentGate::Inject
    } else {
        AgentGate::Capture
    })
}

impl Command for FlowGet {
    fn name(&self) -> &str {
        "l4.flow.get"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Summarize one L4 flow: kind, bind, creation time, endpoints, and a \
                          window of its packets with bytes, time and addresses (read-only). \
                          `packet_count` is always the total; list polling should pass \
                          `limit: 0` and let only an inspector fetch a window. A reply \
                          carries at most 4 MiB of raw packet bytes; when that stops the \
                          window early, `truncated` is true and `next_offset` is where to \
                          resume."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The L4 flow id to summarize.".into(),
                },
                ParamDef {
                    name: "offset".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "First packet index to return (default 0).".into(),
                },
                ParamDef {
                    name: "limit".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "How many packets to return (default 256, at most 4096; 0 \
                                  returns none)."
                        .into(),
                },
            ],
            result: TypeDesc::Object(flow_fields()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id_str = args.get_str("id")?;
        let id = super::flow_id_from_str(id_str)?;
        let window = PacketWindow::from_params(&args)?;
        let flow = self
            .store
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no L4 flow with id {id_str}"))?;
        Ok(flow_to_value(
            &flow,
            window,
            host.caller_is_trusted_control(),
            &self.gates,
        ))
    }
}

/// The fields `l4.flow.get` reports.
fn flow_fields() -> Vec<ParamDef> {
    vec![
        field("id", TypeDesc::Str, true, "The flow id."),
        field(
            "kind",
            TypeDesc::Str,
            true,
            "`capture`, `craft`, `send_recv`, or `intercept`.",
        ),
        field("interface", TypeDesc::Str, true, "The bound interface."),
        field(
            "filter",
            TypeDesc::Str,
            false,
            "The capture BPF filter, if any.",
        ),
        field(
            "queue",
            TypeDesc::Int,
            false,
            "The NFQUEUE number, for intercept flows.",
        ),
        field(
            "started_at",
            TypeDesc::Int,
            true,
            "Flow creation time, milliseconds since the Unix epoch (UTC).",
        ),
        field(
            "proto",
            TypeDesc::Str,
            false,
            "`TCP`, `UDP`, `ICMP` or `ICMPv6` from the first decodable packet; null when none.",
        ),
        field(
            "src",
            TypeDesc::Str,
            false,
            "Source IP of the first decodable packet; null when none.",
        ),
        field(
            "dst",
            TypeDesc::Str,
            false,
            "Destination IP of the first decodable packet; null when none.",
        ),
        field(
            "src_port",
            TypeDesc::Int,
            false,
            "Source port of the first decodable TCP/UDP packet; null otherwise.",
        ),
        field(
            "dst_port",
            TypeDesc::Int,
            false,
            "Destination port of the first decodable TCP/UDP packet; null otherwise.",
        ),
        field(
            "packet_count",
            TypeDesc::Int,
            true,
            "Packets recorded so far (the whole log, not just this window).",
        ),
        field(
            "injected_count",
            TypeDesc::Int,
            true,
            "Of those, how many aitmproxy authored.",
        ),
        field(
            "offset",
            TypeDesc::Int,
            true,
            "Index in the log of the first packet in `packets` (the `offset` asked for).",
        ),
        field(
            "truncated",
            TypeDesc::Bool,
            true,
            "True when the 4 MiB per-reply byte budget stopped the window before `limit`; \
             fetch the rest from `next_offset`.",
        ),
        field(
            "next_offset",
            TypeDesc::Int,
            false,
            "Index in the log of the first packet not returned when `truncated`; null \
             otherwise.",
        ),
        field(
            "packets",
            TypeDesc::Array(Box::new(TypeDesc::Object(vec![
                field("dir", TypeDesc::Str, true, "`inbound` or `outbound`."),
                field("length", TypeDesc::Int, true, "The packet's byte length."),
                field(
                    "injected",
                    TypeDesc::Bool,
                    true,
                    "Whether aitmproxy sent it.",
                ),
                field(
                    "layers",
                    TypeDesc::Array(Box::new(TypeDesc::Str)),
                    true,
                    "Decoded layer names.",
                ),
                field(
                    "bytes",
                    TypeDesc::Bytes,
                    false,
                    "The on-wire bytes (padded base64). Present for trusted control (operator, \
             CLI); for an agent, per packet, only while it holds the gate that could \
             have produced that packet: the Inject gate for an `injected` packet, the \
             Capture gate for a captured one (a capture, a `send_recv` reply or an \
             intercept-parked packet alike), whatever the flow's kind; absent \
             otherwise.",
                ),
                field(
                    "timestamp",
                    TypeDesc::Int,
                    true,
                    "When the packet was seen or sent, milliseconds since the Unix epoch (UTC).",
                ),
                field(
                    "proto",
                    TypeDesc::Str,
                    false,
                    "`TCP`, `UDP`, `ICMP` or `ICMPv6`; null when undecodable.",
                ),
                field(
                    "src",
                    TypeDesc::Str,
                    false,
                    "Source IP; null when undecodable.",
                ),
                field(
                    "dst",
                    TypeDesc::Str,
                    false,
                    "Destination IP; null when undecodable.",
                ),
                field(
                    "src_port",
                    TypeDesc::Int,
                    false,
                    "Source port for TCP/UDP; null otherwise.",
                ),
                field(
                    "dst_port",
                    TypeDesc::Int,
                    false,
                    "Destination port for TCP/UDP; null otherwise.",
                ),
            ]))),
            true,
            "The `[offset, offset + limit)` window of the packet log, in arrival order, \
             cut short by the byte budget when `truncated`; empty past the end.",
        ),
    ]
}

/// Insert the §2 address fields (`proto`, `src`, `dst`, `src_port`, `dst_port`) of
/// `e` into `o`, each `Null` where the layer was absent or undecodable.
fn insert_endpoints(o: &mut BTreeMap<String, Value>, e: &PacketEndpoints) {
    o.insert(
        "proto".to_string(),
        e.proto
            .map_or(Value::Null, |p| Value::Str(p.wire_name().to_string())),
    );
    o.insert(
        "src".to_string(),
        e.src.map_or(Value::Null, |a| Value::Str(a.to_string())),
    );
    o.insert(
        "dst".to_string(),
        e.dst.map_or(Value::Null, |a| Value::Str(a.to_string())),
    );
    o.insert(
        "src_port".to_string(),
        e.src_port.map_or(Value::Null, |p| Value::Int(i64::from(p))),
    );
    o.insert(
        "dst_port".to_string(),
        e.dst_port.map_or(Value::Null, |p| Value::Int(i64::from(p))),
    );
}

/// An [`L4Flow`] as a transport-neutral object carrying the `window` slice of
/// its packet log. `packet_count`, `injected_count` and the flow-level endpoints
/// are over the whole log, so a `limit: 0` read still names the flow's target.
/// Each packet carries `bytes` only when [`bytes_visible`] says so for **that
/// packet** given the caller's trust and the agent `gates`.
pub(crate) fn flow_to_value(
    flow: &L4Flow,
    window: PacketWindow,
    caller_is_trusted_control: bool,
    gates: &L4AgentGates,
) -> Value {
    use crate::flow::L4FlowKind;
    use crate::types::L4Direction;

    let kind = match flow.kind {
        L4FlowKind::Capture => "capture",
        L4FlowKind::Craft => "craft",
        L4FlowKind::SendRecv => "send_recv",
        L4FlowKind::Intercept => "intercept",
    };
    let dir = |d: L4Direction| match d {
        L4Direction::Inbound => "inbound",
        L4Direction::Outbound => "outbound",
    };

    // Flow-level endpoints: the first packet in the whole log that decodes to a
    // transport, whatever window the caller asked for.
    let flow_endpoints = flow
        .packets
        .iter()
        .map(|p| PacketSpec::endpoints(&p.bytes))
        .find(|e| e.proto.is_some())
        .unwrap_or_default();
    // The window, stopped early by the byte budget (spec §2, L4PAR-AC36): packets
    // are added in order while the running sum of the raw lengths of those whose
    // `bytes` are emitted stays within `FLOW_GET_MAX_REPLY_BYTES`, always at
    // least one, so a caller can always advance past an oversized packet. A
    // packet whose bytes this caller does not see costs nothing.
    let mut packets: Vec<Value> = Vec::new();
    let mut raw_bytes = 0usize;
    let mut truncated = false;
    for p in flow.packets.iter().skip(window.offset).take(window.limit) {
        let with_bytes = bytes_visible(caller_is_trusted_control, p.injected, gates);
        if with_bytes
            && !packets.is_empty()
            && raw_bytes.saturating_add(p.bytes.len()) > FLOW_GET_MAX_REPLY_BYTES
        {
            truncated = true;
            break;
        }
        if with_bytes {
            raw_bytes = raw_bytes.saturating_add(p.bytes.len());
        }
        let endpoints = PacketSpec::endpoints(&p.bytes);
        let mut o = BTreeMap::new();
        o.insert("dir".to_string(), Value::Str(dir(p.dir).to_string()));
        o.insert("length".to_string(), Value::Int(p.bytes.len() as i64));
        o.insert("injected".to_string(), Value::Bool(p.injected));
        o.insert(
            "layers".to_string(),
            Value::Array(p.decoded.layers.iter().cloned().map(Value::Str).collect()),
        );
        if with_bytes {
            o.insert("bytes".to_string(), Value::Bytes(p.bytes.clone()));
        }
        o.insert("timestamp".to_string(), Value::Int(epoch_ms(p.timestamp)));
        insert_endpoints(&mut o, &endpoints);
        packets.push(Value::Object(o));
    }
    // The index of the first packet not returned, only when the budget (not the
    // window or the log's end) stopped the walk.
    let next_offset = truncated.then(|| window.offset.saturating_add(packets.len()));
    let injected = flow.packets.iter().filter(|p| p.injected).count();

    let mut obj = BTreeMap::new();
    obj.insert(
        "id".to_string(),
        Value::Str(super::flow_id_to_string(flow.id)),
    );
    obj.insert("kind".to_string(), Value::Str(kind.to_string()));
    obj.insert(
        "interface".to_string(),
        Value::Str(flow.bind.interface.clone()),
    );
    obj.insert(
        "filter".to_string(),
        flow.bind.filter.clone().map_or(Value::Null, Value::Str),
    );
    obj.insert(
        "queue".to_string(),
        flow.bind
            .queue
            .map_or(Value::Null, |q| Value::Int(i64::from(q))),
    );
    obj.insert(
        "started_at".to_string(),
        Value::Int(epoch_ms(flow.metadata.created)),
    );
    insert_endpoints(&mut obj, &flow_endpoints);
    obj.insert(
        "packet_count".to_string(),
        Value::Int(flow.packets.len() as i64),
    );
    obj.insert("injected_count".to_string(), Value::Int(injected as i64));
    obj.insert("offset".to_string(), Value::Int(window.offset as i64));
    obj.insert("truncated".to_string(), Value::Bool(truncated));
    obj.insert(
        "next_offset".to_string(),
        next_offset.map_or(Value::Null, |n| Value::Int(n as i64)),
    );
    obj.insert("packets".to_string(), Value::Array(packets));
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use aitm_core::{
        CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard,
    };
    use futures::future::BoxFuture;

    use super::*;
    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::{InMemoryL4FlowStore, L4Bind, L4FlowId, L4FlowKind, L4Meta, L4Packet};
    use crate::gates::{AgentGate, L4AgentGates};
    use crate::types::L4Direction;

    /// The l4 commands never reissue HTTP; the core host still requires a client.
    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    const CREATED_MS: u64 = 1_700_000_000_000;
    const PACKET_MS: u64 = 1_700_000_000_123;

    fn at_ms(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    /// The A1 crafted IPv4/UDP packet: 127.0.0.1:40000 → 127.0.0.1:9053, `hello-l4`.
    fn crafted_udp() -> Vec<u8> {
        PacketSpec {
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
        .expect("craft builds")
    }

    /// The one place these tests build an `L4Flow`: a flow of `kind` on `lo0`
    /// created at `CREATED_MS` holding `packets` in order, inserted into a fresh
    /// store. Returns the store and the flow id string `l4.flow.get` takes. Every
    /// other flow builder here is a one-line wrapper over this.
    fn flow_of_packets(kind: L4FlowKind, packets: Vec<L4Packet>) -> (Arc<dyn L4FlowStore>, String) {
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind,
            bind: L4Bind {
                interface: "lo0".into(),
                filter: None,
                queue: None,
            },
            packets: VecDeque::from(packets),
            metadata: L4Meta {
                marks: Vec::new(),
                comment: None,
                created: at_ms(CREATED_MS),
            },
        });
        (store, super::super::flow_id_to_string(id))
    }

    /// The `i`th packet of a flow: `bytes` seen at `PACKET_MS + i`, inbound and
    /// captured, or outbound and `injected` (one the core put on the wire).
    fn packet_at(i: usize, bytes: Vec<u8>, injected: bool) -> L4Packet {
        L4Packet {
            dir: if injected {
                L4Direction::Outbound
            } else {
                L4Direction::Inbound
            },
            timestamp: at_ms(PACKET_MS + i as u64),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected,
        }
    }

    /// A flow of `kind` holding one captured inbound packet per element of
    /// `packets`, in order.
    fn flow_of(kind: L4FlowKind, packets: Vec<Vec<u8>>) -> (Arc<dyn L4FlowStore>, String) {
        flow_of_packets(
            kind,
            packets
                .into_iter()
                .enumerate()
                .map(|(i, b)| packet_at(i, b, false))
                .collect(),
        )
    }

    /// One Capture flow holding one captured inbound packet of `bytes`.
    fn one_packet_flow(bytes: Vec<u8>) -> (Arc<dyn L4FlowStore>, String) {
        flow_of(L4FlowKind::Capture, vec![bytes])
    }

    /// [`one_packet_flow`] for a flow of `kind`.
    fn one_packet_flow_of(kind: L4FlowKind, bytes: Vec<u8>) -> (Arc<dyn L4FlowStore>, String) {
        flow_of(kind, vec![bytes])
    }

    /// A Capture flow of `n` undecodable captured packets of `size` bytes each.
    fn sized_packet_flow(n: usize, size: usize) -> (Arc<dyn L4FlowStore>, String) {
        flow_of(L4FlowKind::Capture, vec![vec![0xab_u8; size]; n])
    }

    /// The deny-by-default agent gates (every `l4.allow_agent_*` false).
    fn closed_gates() -> Arc<L4AgentGates> {
        L4AgentGates::from_config(&crate::config::L4Config::default())
    }

    /// Invoke `l4.flow.get {id}` over `store` as the operator and return the flow
    /// object and its first packet object.
    fn get(
        store: Arc<dyn L4FlowStore>,
        id: &str,
    ) -> (BTreeMap<String, Value>, BTreeMap<String, Value>) {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        let got = FlowGet::new(store, closed_gates())
            .invoke(Params::new(m), &host)
            .expect("flow.get ok");
        let Value::Object(flow) = got else {
            panic!("l4.flow.get returns an object, got {got:?}");
        };
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array: {flow:?}");
        };
        let Some(Value::Object(packet)) = packets.first() else {
            panic!("one packet object: {packets:?}");
        };
        (flow.clone(), packet.clone())
    }

    /// L4PAR-AC1 — a decodable packet reports its bytes, time and endpoints; the
    /// flow reports its creation time and the first decodable packet's endpoints.
    #[test]
    fn flow_get_reports_bytes_time_and_addresses() {
        let bytes = crafted_udp();
        let (store, id) = one_packet_flow(bytes.clone());
        let (flow, packet) = get(store, &id);

        assert_eq!(packet.get("proto"), Some(&Value::Str("UDP".into())));
        assert_eq!(packet.get("src"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(packet.get("dst"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(packet.get("src_port"), Some(&Value::Int(40000)));
        assert_eq!(packet.get("dst_port"), Some(&Value::Int(9053)));
        assert_eq!(packet.get("bytes"), Some(&Value::Bytes(bytes.clone())));
        assert_eq!(
            packet.get("timestamp"),
            Some(&Value::Int(1_700_000_000_123))
        );
        // The existing fields stay.
        assert_eq!(packet.get("dir"), Some(&Value::Str("inbound".into())));
        assert_eq!(packet.get("length"), Some(&Value::Int(bytes.len() as i64)));
        assert_eq!(packet.get("injected"), Some(&Value::Bool(false)));

        assert_eq!(flow.get("started_at"), Some(&Value::Int(1_700_000_000_000)));
        assert_eq!(flow.get("proto"), Some(&Value::Str("UDP".into())));
        assert_eq!(flow.get("src"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(flow.get("dst"), Some(&Value::Str("127.0.0.1".into())));
        assert_eq!(flow.get("src_port"), Some(&Value::Int(40000)));
        assert_eq!(flow.get("dst_port"), Some(&Value::Int(9053)));
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(1)));
    }

    /// L4PAR-AC1 — an undecodable packet still carries its bytes and time, with
    /// every address field `Null` on the packet and on the flow.
    #[test]
    fn flow_get_undecodable_packet_is_null_addressed() {
        let (store, id) = one_packet_flow(vec![0xde, 0xad]);
        let (flow, packet) = get(store, &id);

        for key in ["proto", "src", "dst", "src_port", "dst_port"] {
            assert_eq!(packet.get(key), Some(&Value::Null), "packet.{key}");
            assert_eq!(flow.get(key), Some(&Value::Null), "flow.{key}");
        }
        assert_eq!(packet.get("bytes"), Some(&Value::Bytes(vec![0xde, 0xad])));
        assert_eq!(
            packet.get("timestamp"),
            Some(&Value::Int(1_700_000_000_123))
        );
        assert_eq!(flow.get("started_at"), Some(&Value::Int(1_700_000_000_000)));
    }

    /// The schema advertises every field the reply carries, with the bytes typed
    /// as bytes (so the wire renders them base64) and the addresses optional.
    #[test]
    fn flow_get_schema_lists_the_new_fields() {
        let fields = flow_fields();
        let by_name = |n: &str| {
            fields
                .iter()
                .find(|f| f.name == n)
                .unwrap_or_else(|| panic!("flow field `{n}` in the schema"))
        };
        assert!(by_name("started_at").required);
        for n in ["proto", "src", "dst", "src_port", "dst_port"] {
            assert!(!by_name(n).required, "flow.{n} is optional");
        }
        let TypeDesc::Array(inner) = &by_name("packets").ty else {
            panic!("packets is an array");
        };
        let TypeDesc::Object(pf) = inner.as_ref() else {
            panic!("packets holds objects");
        };
        let pk = |n: &str| {
            pf.iter()
                .find(|f| f.name == n)
                .unwrap_or_else(|| panic!("packet field `{n}` in the schema"))
        };
        assert!(matches!(pk("bytes").ty, TypeDesc::Bytes), "bytes is Bytes");
        assert!(!pk("bytes").required, "bytes is optional (spec §2.2)");
        assert!(
            matches!(pk("timestamp").ty, TypeDesc::Int),
            "timestamp is Int"
        );
        assert!(pk("timestamp").required);
        for n in ["proto", "src", "dst", "src_port", "dst_port"] {
            assert!(!pk(n).required, "packet.{n} is optional");
        }
    }

    /// A pre-epoch time clamps to `0` rather than going negative or panicking.
    #[test]
    fn epoch_ms_clamps_pre_epoch_to_zero() {
        assert_eq!(epoch_ms(UNIX_EPOCH - Duration::from_secs(5)), 0);
        assert_eq!(epoch_ms(at_ms(1_700_000_000_123)), 1_700_000_000_123);
    }

    // ---- L4PAR-AC2: bounded packet window ----------------------------------

    /// A Capture flow of `n` crafted UDP packets, every other one injected.
    fn n_packet_flow(n: usize) -> (Arc<dyn L4FlowStore>, String) {
        flow_of_packets(
            L4FlowKind::Capture,
            (0..n)
                .map(|i| packet_at(i, crafted_udp(), i % 2 == 1))
                .collect(),
        )
    }

    /// Invoke `l4.flow.get` with `id` plus the given extra params, the way an
    /// operator bus caller does, returning the raw command result.
    fn get_window(
        store: Arc<dyn L4FlowStore>,
        id: &str,
        extra: &[(&str, i64)],
    ) -> anyhow::Result<Value> {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        for (k, v) in extra {
            m.insert((*k).to_string(), Value::Int(*v));
        }
        FlowGet::new(store, closed_gates()).invoke(Params::new(m), &host)
    }

    /// The flow object and the number of packets it carries.
    fn flow_and_count(v: Value) -> (BTreeMap<String, Value>, usize) {
        let Value::Object(flow) = v else {
            panic!("l4.flow.get returns an object, got {v:?}");
        };
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array: {flow:?}");
        };
        (flow.clone(), packets.len())
    }

    /// L4PAR-AC2 — no window params: the first 256 of 300 packets, totals intact,
    /// `offset 0` reported.
    #[test]
    fn window_default_returns_256_of_300() {
        let (store, id) = n_packet_flow(300);
        let (flow, n) = flow_and_count(get_window(store, &id, &[]).expect("flow.get ok"));
        assert_eq!(n, 256);
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(300)));
        assert_eq!(flow.get("injected_count"), Some(&Value::Int(150)));
        assert_eq!(flow.get("offset"), Some(&Value::Int(0)));
    }

    /// L4PAR-AC2 — `{offset 290, limit 50}` on 300 packets: the 10 that exist,
    /// `offset 290` echoed, and the slice starts at packet 290.
    #[test]
    fn window_offset_and_limit_slice_the_log() {
        let (store, id) = n_packet_flow(300);
        let got = get_window(store, &id, &[("offset", 290), ("limit", 50)]).expect("flow.get ok");
        let (flow, n) = flow_and_count(got);
        assert_eq!(n, 10);
        assert_eq!(flow.get("offset"), Some(&Value::Int(290)));
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(300)));
        assert_eq!(flow.get("injected_count"), Some(&Value::Int(150)));
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array");
        };
        let Some(Value::Object(first)) = packets.first() else {
            panic!("first packet is an object");
        };
        assert_eq!(
            first.get("timestamp"),
            Some(&Value::Int(PACKET_MS as i64 + 290)),
            "the window starts at packet 290"
        );
    }

    /// L4PAR-AC2 — `limit 0` (list polling): no packets, but the totals and the
    /// flow-level endpoints are still there so a list row can show its target.
    #[test]
    fn window_limit_zero_returns_no_packets() {
        let (store, id) = n_packet_flow(300);
        let (flow, n) =
            flow_and_count(get_window(store, &id, &[("limit", 0)]).expect("flow.get ok"));
        assert_eq!(n, 0);
        assert_eq!(flow.get("packets"), Some(&Value::Array(vec![])));
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(300)));
        assert_eq!(flow.get("injected_count"), Some(&Value::Int(150)));
        assert_eq!(flow.get("offset"), Some(&Value::Int(0)));
        assert_eq!(flow.get("proto"), Some(&Value::Str("UDP".into())));
        assert_eq!(flow.get("dst_port"), Some(&Value::Int(9053)));
    }

    /// L4PAR-AC2 — `limit 100000` on 5000 packets is clamped to exactly 4096.
    #[test]
    fn window_limit_is_clamped_to_max() {
        let (store, id) = n_packet_flow(5000);
        let (flow, n) =
            flow_and_count(get_window(store, &id, &[("limit", 100_000)]).expect("flow.get ok"));
        assert_eq!(n, 4096);
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(5000)));
    }

    /// L4PAR-AC2 — an offset past the end is an empty window, not an error.
    #[test]
    fn window_offset_past_end_is_empty() {
        let (store, id) = n_packet_flow(300);
        let (flow, n) =
            flow_and_count(get_window(store, &id, &[("offset", 400)]).expect("flow.get ok"));
        assert_eq!(n, 0);
        assert_eq!(flow.get("offset"), Some(&Value::Int(400)));
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(300)));
    }

    /// L4PAR-AC2 — negative window params are refused with a named error.
    #[test]
    fn window_negative_params_are_errors() {
        let (store, id) = n_packet_flow(3);
        let err = get_window(store.clone(), &id, &[("limit", -1)]).expect_err("negative limit");
        assert!(
            err.to_string()
                .contains("`limit` must be a non-negative integer"),
            "got: {err}"
        );
        let err = get_window(store, &id, &[("offset", -1)]).expect_err("negative offset");
        assert!(
            err.to_string()
                .contains("`offset` must be a non-negative integer"),
            "got: {err}"
        );
    }

    /// A15 (L4PAR-AC2) — the window an argument-less call and the Rhai
    /// `l4.flow.get` share is the type's `Default`.
    #[test]
    fn window_default() {
        assert_eq!(
            PacketWindow::default(),
            PacketWindow {
                offset: 0,
                limit: 256
            }
        );
    }

    /// L4PAR-AC2 — `PacketWindow::from_params` is the one place the window is read.
    #[test]
    fn window_from_params_defaults_and_clamps() {
        assert_eq!(
            PacketWindow::from_params(&Params::default()).expect("absent is default"),
            PacketWindow::default()
        );
        let mut m = BTreeMap::new();
        m.insert("offset".to_string(), Value::Int(7));
        m.insert("limit".to_string(), Value::Int(1_000_000));
        assert_eq!(
            PacketWindow::from_params(&Params::new(m)).expect("clamped"),
            PacketWindow {
                offset: 7,
                limit: 4096
            }
        );
    }

    /// L4PAR-AC2 — the schema offers `id`, then optional `offset` and `limit`, so
    /// a UI can detect the window from `tools/list`.
    #[test]
    fn window_schema_params_are_id_offset_limit() {
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let schema = FlowGet::new(store, closed_gates()).schema();
        let names: Vec<&str> = schema.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["id", "offset", "limit"]);
        let by = |n: &str| schema.params.iter().find(|p| p.name == n).expect(n);
        assert!(by("id").required);
        assert!(!by("offset").required);
        assert!(!by("limit").required);
        assert!(matches!(by("offset").ty, TypeDesc::Int));
        assert!(matches!(by("limit").ty, TypeDesc::Int));
        let TypeDesc::Object(fields) = &schema.result else {
            panic!("result is an object");
        };
        assert!(
            fields
                .iter()
                .any(|f| f.name == "offset" && matches!(f.ty, TypeDesc::Int)),
            "the reply schema lists `offset`"
        );
    }

    // ---- L4PAR-AC35: bytes only to trusted callers ---------------------------

    /// A TCP packet 127.0.0.1:51000 → 127.0.0.1:27431 (the bus port): the payload
    /// an agent must never read off a loopback capture.
    fn bus_bound_tcp() -> Vec<u8> {
        use crate::craft::TcpSpec;
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                    ..Ipv4Spec::default()
                }),
                Layer::Tcp(TcpSpec {
                    src_port: Some(51000),
                    dst_port: Some(27431),
                    ..TcpSpec::default()
                }),
                Layer::Raw(b"Authorization: Bearer secret-token".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    /// Invoke `l4.flow.get {id}` as `frontend` over `store` with the given gates,
    /// returning the first packet object.
    fn get_as(
        store: Arc<dyn L4FlowStore>,
        gates: Arc<L4AgentGates>,
        frontend: Frontend,
        id: &str,
    ) -> BTreeMap<String, Value> {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None).with_frontend(frontend);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        let got = FlowGet::new(store, gates)
            .invoke(Params::new(m), &host)
            .expect("flow.get ok");
        let Value::Object(flow) = got else {
            panic!("l4.flow.get returns an object, got {got:?}");
        };
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array: {flow:?}");
        };
        let Some(Value::Object(packet)) = packets.first() else {
            panic!("one packet object: {packets:?}");
        };
        packet.clone()
    }

    /// L4PAR-AC35, spec §2.2 as amended — `bytes_visible` is the one per-packet
    /// rule both faces share: trusted control always; an agent sees an injected
    /// packet's bytes only with the Inject gate open and a captured packet's only
    /// with the Capture gate open; Intercept and Widen open nothing. Literal truth
    /// table over (trusted, injected, open gate).
    #[test]
    fn bytes_visible_is_per_packet() {
        let gates = closed_gates();
        for injected in [false, true] {
            assert!(bytes_visible(true, injected, &gates), "trusted, all closed");
            assert!(!bytes_visible(false, injected, &gates), "agent, all closed");
        }
        only(&gates, &[AgentGate::Capture]);
        assert!(bytes_visible(false, false, &gates), "Capture → captured");
        assert!(!bytes_visible(false, true, &gates), "Capture ↛ injected");
        only(&gates, &[AgentGate::Inject]);
        assert!(!bytes_visible(false, false, &gates), "Inject ↛ captured");
        assert!(bytes_visible(false, true, &gates), "Inject → injected");
        for other in [AgentGate::Intercept, AgentGate::Widen] {
            only(&gates, &[other]);
            assert!(!bytes_visible(false, false, &gates), "{other:?} ↛ captured");
            assert!(!bytes_visible(false, true, &gates), "{other:?} ↛ injected");
        }
        only(&gates, &[AgentGate::Capture, AgentGate::Inject]);
        assert!(bytes_visible(false, false, &gates));
        assert!(bytes_visible(false, true, &gates));
    }

    /// Invoke `l4.flow.get {id}` as `frontend` over `store` with the given gates,
    /// returning every packet object in the window.
    fn packets_as(
        store: Arc<dyn L4FlowStore>,
        gates: Arc<L4AgentGates>,
        frontend: Frontend,
        id: &str,
    ) -> Vec<BTreeMap<String, Value>> {
        let (flow, _) = get_window_as(store, gates, frontend, id, &[]);
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array: {flow:?}");
        };
        packets
            .iter()
            .map(|p| match p {
                Value::Object(o) => o.clone(),
                other => panic!("a packet object, got {other:?}"),
            })
            .collect()
    }

    /// Open exactly `open` and close every other agent gate.
    fn only(gates: &L4AgentGates, open: &[AgentGate]) {
        for g in [
            AgentGate::Capture,
            AgentGate::Inject,
            AgentGate::Intercept,
            AgentGate::Widen,
        ] {
            gates.set(g, open.contains(&g));
        }
    }

    /// L4PAR-AC35, spec §2.2 as amended — through `FlowGet::invoke`, the bytes
    /// gate is decided **per packet**, not per flow kind: a `send_recv` flow holds
    /// an injected stimulus (authored: needs the Inject gate) and a captured reply
    /// (captured traffic: needs the Capture gate). An agent with only Inject reads
    /// the injected packet's bytes and not the reply's; with only Capture the
    /// reverse; with every gate closed, or only Widen, neither. An intercept-parked
    /// packet is captured traffic too, so the Intercept gate alone reveals nothing.
    /// The operator and the CLI always get every packet's bytes.
    #[test]
    fn flow_get_bytes_gate_is_per_packet() {
        let stimulus = vec![0xbe, 0xef, 0x01];
        let reply = vec![0xde, 0xad];
        let (store, id) = flow_of_packets(
            L4FlowKind::SendRecv,
            vec![
                packet_at(0, stimulus.clone(), true),
                packet_at(1, reply.clone(), false),
            ],
        );
        let gates = closed_gates();
        let bytes_of = |packets: &[BTreeMap<String, Value>]| -> Vec<Option<Value>> {
            packets.iter().map(|p| p.get("bytes").cloned()).collect()
        };

        // Agent, every gate closed: both packets' metadata, neither's bytes.
        let packets = packets_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].get("injected"), Some(&Value::Bool(true)));
        assert_eq!(packets[0].get("length"), Some(&Value::Int(3)));
        assert_eq!(packets[1].get("injected"), Some(&Value::Bool(false)));
        assert_eq!(packets[1].get("length"), Some(&Value::Int(2)));
        assert_eq!(bytes_of(&packets), vec![None, None], "all closed");

        // Only Inject: the authored packet's bytes, not the captured reply's.
        only(&gates, &[AgentGate::Inject]);
        let packets = packets_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert_eq!(
            bytes_of(&packets),
            vec![Some(Value::Bytes(stimulus.clone())), None],
            "Inject alone reveals the injected packet only"
        );

        // Only Capture: the captured reply's bytes, not the authored packet's.
        only(&gates, &[AgentGate::Capture]);
        let packets = packets_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert_eq!(
            bytes_of(&packets),
            vec![None, Some(Value::Bytes(reply.clone()))],
            "Capture alone reveals the captured packet only"
        );

        // Only Intercept, or only Widen: a gate for another primitive reveals nothing.
        for other in [AgentGate::Intercept, AgentGate::Widen] {
            only(&gates, &[other]);
            let packets = packets_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
            assert_eq!(bytes_of(&packets), vec![None, None], "{other:?} alone");
        }

        // Both: both.
        only(&gates, &[AgentGate::Inject, AgentGate::Capture]);
        let packets = packets_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert_eq!(
            bytes_of(&packets),
            vec![
                Some(Value::Bytes(stimulus.clone())),
                Some(Value::Bytes(reply.clone()))
            ]
        );

        // Trusted control, every gate closed: both, always.
        only(&gates, &[]);
        for frontend in [Frontend::Operator, Frontend::Cli] {
            let packets = packets_as(store.clone(), gates.clone(), frontend, &id);
            assert_eq!(
                bytes_of(&packets),
                vec![
                    Some(Value::Bytes(stimulus.clone())),
                    Some(Value::Bytes(reply.clone()))
                ],
                "{frontend:?}"
            );
        }

        // An intercept-parked packet is captured traffic: the Intercept gate alone
        // reveals nothing, the Capture gate does.
        let (store, id) = one_packet_flow_of(L4FlowKind::Intercept, vec![0xca, 0xfe]);
        let gates = closed_gates();
        only(&gates, &[AgentGate::Intercept]);
        let packet = get_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert!(
            !packet.contains_key("bytes"),
            "intercept flow, Intercept gate alone: no bytes, got {packet:?}"
        );
        only(&gates, &[AgentGate::Capture]);
        let packet = get_as(store.clone(), gates.clone(), Frontend::Mcp, &id);
        assert_eq!(packet.get("bytes"), Some(&Value::Bytes(vec![0xca, 0xfe])));
        only(&gates, &[]);
        let packet = get_as(store, gates, Frontend::Operator, &id);
        assert_eq!(packet.get("bytes"), Some(&Value::Bytes(vec![0xca, 0xfe])));

        // The bus-token line off a loopback capture, read as an agent whose Inject
        // and Intercept gates are open but not Capture: no bytes.
        let bytes = bus_bound_tcp();
        let (store, id) = one_packet_flow(bytes.clone());
        let gates = closed_gates();
        only(&gates, &[AgentGate::Inject, AgentGate::Intercept]);
        let packet = get_as(store, gates, Frontend::Mcp, &id);
        assert_eq!(packet.get("proto"), Some(&Value::Str("TCP".into())));
        assert_eq!(packet.get("src_port"), Some(&Value::Int(51000)));
        assert_eq!(packet.get("dst_port"), Some(&Value::Int(27431)));
        assert_eq!(packet.get("length"), Some(&Value::Int(bytes.len() as i64)));
        assert!(
            !packet.contains_key("bytes"),
            "an agent without the Capture gate must not read the bus-bound payload, got {packet:?}"
        );
    }

    /// L4PAR-AC36 with the per-packet gate: the reply byte budget counts only the
    /// packets whose `bytes` are emitted. A `send_recv` flow of two 3 MiB captured
    /// packets and a 2-byte injected one: an agent with only Inject gets all three
    /// (2 bytes counted, not truncated); with only Capture the second 3 MiB packet
    /// breaks the 4 MiB budget (`truncated`, `next_offset 1`); the operator, who
    /// sees everything, is cut at the same place.
    #[test]
    fn window_byte_budget_counts_only_emitted_bytes() {
        let big = 3 * 1024 * 1024;
        let (store, id) = flow_of_packets(
            L4FlowKind::SendRecv,
            vec![
                packet_at(0, vec![0xab; big], false),
                packet_at(1, vec![0xcd; big], false),
                packet_at(2, vec![0x01, 0x02], true),
            ],
        );
        let gates = closed_gates();

        only(&gates, &[AgentGate::Inject]);
        let (flow, n) = get_window_as(store.clone(), gates.clone(), Frontend::Mcp, &id, &[]);
        assert_eq!(n, 3, "no captured bytes are emitted, so none are counted");
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));

        only(&gates, &[AgentGate::Capture]);
        let (flow, n) = get_window_as(store.clone(), gates.clone(), Frontend::Mcp, &id, &[]);
        assert_eq!(n, 1, "3 MiB + 3 MiB breaks the 4 MiB budget");
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(1)));

        only(&gates, &[]);
        let (flow, n) = get_window_as(store, gates, Frontend::Operator, &id, &[]);
        assert_eq!(n, 1);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(1)));
    }

    /// L4PAR-AC35 — the schema says `bytes` is optional and why.
    #[test]
    fn flow_get_schema_bytes_is_optional_for_agents() {
        let fields = flow_fields();
        let packets = fields
            .iter()
            .find(|f| f.name == "packets")
            .expect("packets field");
        let TypeDesc::Array(inner) = &packets.ty else {
            panic!("packets is an array");
        };
        let TypeDesc::Object(pf) = inner.as_ref() else {
            panic!("packets holds objects");
        };
        let bytes = pf.iter().find(|f| f.name == "bytes").expect("bytes field");
        assert!(!bytes.required, "bytes is optional on the wire");
        for needle in [
            "Inject gate",
            "`injected`",
            "Capture gate",
            "whatever the flow's kind",
        ] {
            assert!(
                bytes.description.contains(needle),
                "the description states the per-packet rule ({needle}; spec §2.2 as amended), got {}",
                bytes.description
            );
        }
        assert!(
            !bytes.description.contains("Intercept gate"),
            "the Intercept gate opens no bytes, got {}",
            bytes.description
        );
    }

    // ---- L4PAR-AC36: reply byte budget ---------------------------------------

    /// Invoke `l4.flow.get` as `frontend` with the given gates and extra window
    /// params, returning the flow object and the number of packets it carries.
    fn get_window_as(
        store: Arc<dyn L4FlowStore>,
        gates: Arc<L4AgentGates>,
        frontend: Frontend,
        id: &str,
        extra: &[(&str, i64)],
    ) -> (BTreeMap<String, Value>, usize) {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None).with_frontend(frontend);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        for (k, v) in extra {
            m.insert((*k).to_string(), Value::Int(*v));
        }
        let got = FlowGet::new(store, gates)
            .invoke(Params::new(m), &host)
            .expect("flow.get ok");
        flow_and_count(got)
    }

    /// L4PAR-AC36 — 300 packets of 60,000 bytes with the default window: the
    /// operator gets 69 packets (69 × 60,000 = 4,140,000 ≤ 4 MiB; 70 would not
    /// fit), `truncated: true`, `next_offset: 69`; a 3-packet flow is not
    /// truncated and `next_offset` is null; an agent with the Capture gate closed
    /// gets no bytes, so the budget does not apply and the window alone (256)
    /// bounds the reply.
    #[test]
    fn window_byte_budget() {
        let (store, id) = sized_packet_flow(300, 60_000);
        let (flow, n) = get_window_as(store.clone(), closed_gates(), Frontend::Operator, &id, &[]);
        assert_eq!(n, 69, "69 × 60,000 fits the 4 MiB budget, 70 does not");
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(69)));
        assert_eq!(flow.get("offset"), Some(&Value::Int(0)));
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(300)));
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array");
        };
        let Some(Value::Object(first)) = packets.first() else {
            panic!("first packet is an object");
        };
        assert_eq!(
            first.get("bytes"),
            Some(&Value::Bytes(vec![0xab_u8; 60_000])),
            "the operator's packets carry their bytes"
        );

        // A small flow: nothing stopped the window early.
        let (small_store, small_id) = n_packet_flow(3);
        let (flow, n) = get_window_as(
            small_store,
            closed_gates(),
            Frontend::Operator,
            &small_id,
            &[],
        );
        assert_eq!(n, 3);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));

        // The same 300-packet flow as an agent with the gates closed: no bytes,
        // so only `offset`/`limit` apply.
        let gates = closed_gates();
        assert!(!gates.allowed(AgentGate::Capture), "gates start closed");
        let (flow, n) = get_window_as(store, gates, Frontend::Mcp, &id, &[]);
        assert_eq!(n, 256);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array");
        };
        let Some(Value::Object(first)) = packets.first() else {
            panic!("first packet is an object");
        };
        assert!(
            !first.contains_key("bytes"),
            "agent gets no bytes: {first:?}"
        );
    }

    /// L4PAR-AC36 — `next_offset` is an index into the log, not into the window:
    /// `{offset 100}` on the 300 × 60,000 flow returns packets 100..169 and
    /// `next_offset: 169`.
    #[test]
    fn window_byte_budget_next_offset_is_a_log_index() {
        let (store, id) = sized_packet_flow(300, 60_000);
        let (flow, n) = get_window_as(
            store,
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("offset", 100)],
        );
        assert_eq!(n, 69);
        assert_eq!(flow.get("offset"), Some(&Value::Int(100)));
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(169)));
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets is an array");
        };
        let Some(Value::Object(last)) = packets.last() else {
            panic!("last packet is an object");
        };
        assert_eq!(
            last.get("timestamp"),
            Some(&Value::Int(PACKET_MS as i64 + 168)),
            "the last packet returned is log index 168"
        );
    }

    /// L4PAR-AC36 — at least one packet is always returned when any remain in
    /// the window, even one larger than the whole budget; the budget never turns
    /// a non-empty window into an empty reply the caller could not advance past.
    #[test]
    fn window_byte_budget_returns_at_least_one_packet() {
        let (store, id) = sized_packet_flow(2, FLOW_GET_MAX_REPLY_BYTES + 1);
        let (flow, n) = get_window_as(store.clone(), closed_gates(), Frontend::Operator, &id, &[]);
        assert_eq!(n, 1);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(1)));

        // Advancing to `next_offset` fetches the last packet; the window is then
        // exhausted by the log, not the budget.
        let (flow, n) = get_window_as(
            store.clone(),
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("offset", 1)],
        );
        assert_eq!(n, 1);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));

        // `limit 0` returns nothing and is not a truncation.
        let (flow, n) = get_window_as(
            store,
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("limit", 0)],
        );
        assert_eq!(n, 0);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));
    }

    /// L4PAR-AC36 — the result schema lists `truncated` (required Bool) and
    /// `next_offset` (optional Int).
    #[test]
    fn window_byte_budget_schema_lists_truncated_and_next_offset() {
        let fields = flow_fields();
        let by_name = |n: &str| {
            fields
                .iter()
                .find(|f| f.name == n)
                .unwrap_or_else(|| panic!("flow field `{n}` in the schema"))
        };
        assert!(matches!(by_name("truncated").ty, TypeDesc::Bool));
        assert!(by_name("truncated").required);
        assert!(matches!(by_name("next_offset").ty, TypeDesc::Int));
        assert!(!by_name("next_offset").required);
    }

    // ---- Tester (stage 5): AC1 / AC2 / AC35 / AC36 edge cases ----------------

    /// Invoke `l4.flow.get` as the operator with exactly `params`.
    fn invoke_raw(
        store: Arc<dyn L4FlowStore>,
        params: Vec<(&str, Value)>,
    ) -> anyhow::Result<Value> {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);
        let m: BTreeMap<String, Value> = params
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        FlowGet::new(store, closed_gates()).invoke(Params::new(m), &host)
    }

    /// L4PAR-AC35 (tester): the CLI is trusted control and gets `bytes` with the
    /// gates closed, like the operator.
    #[test]
    fn flow_get_bytes_for_the_cli() {
        let (store, id) = one_packet_flow(vec![0xde, 0xad]);
        let packet = get_as(store, closed_gates(), Frontend::Cli, &id);
        assert_eq!(packet.get("bytes"), Some(&Value::Bytes(vec![0xde, 0xad])));
    }

    /// L4PAR-AC35 + AC36 (tester): an agent whose Capture gate is open sees
    /// bytes, so the byte budget applies to it exactly as to the operator.
    #[test]
    fn window_byte_budget_applies_to_an_agent_with_the_capture_gate_open() {
        let (store, id) = sized_packet_flow(300, 60_000);
        let gates = closed_gates();
        gates.set(AgentGate::Capture, true);
        let (flow, n) = get_window_as(store, gates, Frontend::Mcp, &id, &[]);
        assert_eq!(n, 69);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(69)));
    }

    /// L4PAR-AC36 (tester): "within the budget" includes equal to it. Five 1 MiB
    /// packets: the first four sum to exactly 4 MiB and are all returned, the
    /// fifth is cut (`truncated`, `next_offset 4`). With `limit 4` the window, not
    /// the budget, ends the walk: not truncated.
    #[test]
    fn window_byte_budget_exact_boundary() {
        let mib = 1024 * 1024;
        let (store, id) = sized_packet_flow(5, mib);
        let (flow, n) = get_window_as(store.clone(), closed_gates(), Frontend::Operator, &id, &[]);
        assert_eq!(n, 4, "4 × 1 MiB == the budget, which is within it");
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(4)));

        let (flow, n) = get_window_as(
            store,
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("limit", 4)],
        );
        assert_eq!(n, 4);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));
    }

    /// L4PAR-AC36 (tester): `truncated` means the budget stopped the window, not
    /// the limit. On the 300 × 60,000 flow, `limit 69` ends exactly where the
    /// budget would (not truncated); `limit 70` is cut to 69 by the budget.
    #[test]
    fn window_byte_budget_versus_limit() {
        let (store, id) = sized_packet_flow(300, 60_000);
        let (flow, n) = get_window_as(
            store.clone(),
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("limit", 69)],
        );
        assert_eq!(n, 69);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));

        let (flow, n) = get_window_as(
            store,
            closed_gates(),
            Frontend::Operator,
            &id,
            &[("limit", 70)],
        );
        assert_eq!(n, 69);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(true)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Int(69)));
    }

    /// L4PAR-AC1 / AC2 (tester): the flow-level endpoints come from the first
    /// *decodable* packet in the whole log, whatever the window: a leading
    /// undecodable packet is skipped, and `limit 0` or a window past the
    /// decodable packet still names the target.
    #[test]
    fn flow_endpoints_skip_an_undecodable_first_packet() {
        let (store, id) = flow_of(L4FlowKind::Capture, vec![vec![0xde, 0xad], crafted_udp()]);
        for extra in [
            vec![],
            vec![("limit", 0)],
            vec![("offset", 0), ("limit", 1)],
        ] {
            let (flow, _) =
                flow_and_count(get_window(store.clone(), &id, &extra).expect("flow.get ok"));
            assert_eq!(
                flow.get("proto"),
                Some(&Value::Str("UDP".into())),
                "{extra:?}"
            );
            assert_eq!(flow.get("src"), Some(&Value::Str("127.0.0.1".into())));
            assert_eq!(flow.get("dst_port"), Some(&Value::Int(9053)));
            assert_eq!(flow.get("src_port"), Some(&Value::Int(40000)));
        }
        // The window {0, 1} holds only the undecodable packet, null-addressed.
        let got = get_window(store, &id, &[("offset", 0), ("limit", 1)]).expect("flow.get ok");
        let Value::Object(flow) = got else {
            panic!("object");
        };
        let Some(Value::Array(packets)) = flow.get("packets") else {
            panic!("packets");
        };
        let Some(Value::Object(p0)) = packets.first() else {
            panic!("one packet");
        };
        assert_eq!(packets.len(), 1);
        assert_eq!(p0.get("proto"), Some(&Value::Null));
        assert_eq!(p0.get("bytes"), Some(&Value::Bytes(vec![0xde, 0xad])));
    }

    /// L4PAR-AC1 / AC2 / AC36 (tester): a flow with no packets yet (a capture
    /// that just started) answers with every flow field and an empty window.
    #[test]
    fn flow_get_empty_flow() {
        let (store, id) = flow_of(L4FlowKind::Capture, vec![]);
        let (flow, n) = flow_and_count(get_window(store, &id, &[]).expect("flow.get ok"));
        assert_eq!(n, 0);
        assert_eq!(flow.get("packet_count"), Some(&Value::Int(0)));
        assert_eq!(flow.get("injected_count"), Some(&Value::Int(0)));
        assert_eq!(flow.get("offset"), Some(&Value::Int(0)));
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
        assert_eq!(flow.get("next_offset"), Some(&Value::Null));
        assert_eq!(flow.get("started_at"), Some(&Value::Int(1_700_000_000_000)));
        for key in ["proto", "src", "dst", "src_port", "dst_port"] {
            assert_eq!(flow.get(key), Some(&Value::Null), "flow.{key}");
        }
    }

    /// L4PAR-AC2 (tester): malformed input is refused with an error, never
    /// answered with a default window or another flow: an unknown id, a non-uuid
    /// id, an empty id, a missing id, and window params of the wrong type.
    #[test]
    fn flow_get_refuses_malformed_input() {
        let (store, id) = one_packet_flow(vec![0xde, 0xad]);
        let unknown = super::super::flow_id_to_string(L4FlowId::new());
        let err = invoke_raw(store.clone(), vec![("id", Value::Str(unknown.clone()))])
            .expect_err("unknown id");
        assert!(
            err.to_string()
                .contains(&format!("no L4 flow with id {unknown}")),
            "got: {err}"
        );
        for bad in ["not-a-uuid", "", "00000000-0000-0000-0000"] {
            assert!(
                invoke_raw(store.clone(), vec![("id", Value::Str(bad.into()))]).is_err(),
                "id {bad:?} must be refused"
            );
        }
        assert!(invoke_raw(store.clone(), vec![]).is_err(), "missing id");
        assert!(
            invoke_raw(store.clone(), vec![("id", Value::Int(1))]).is_err(),
            "non-string id"
        );
        for (k, v) in [
            ("offset", Value::Str("10".into())),
            ("limit", Value::Bool(true)),
            ("limit", Value::Str("all".into())),
        ] {
            assert!(
                invoke_raw(
                    store.clone(),
                    vec![("id", Value::Str(id.clone())), (k, v.clone())]
                )
                .is_err(),
                "{k} = {v:?} must be refused"
            );
        }
        // A huge offset is an empty window, not an overflow.
        let (flow, n) = flow_and_count(
            invoke_raw(
                store,
                vec![("id", Value::Str(id)), ("offset", Value::Int(i64::MAX))],
            )
            .expect("i64::MAX offset answers"),
        );
        assert_eq!(n, 0);
        assert_eq!(flow.get("truncated"), Some(&Value::Bool(false)));
    }
}
