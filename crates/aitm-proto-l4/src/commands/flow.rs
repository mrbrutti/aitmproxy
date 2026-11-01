//! `l4.flow.list` / `.get` — query the l4-owned flow store.
//!
//! Sensitivity: **read-only**. These read the [`L4FlowStore`](crate::flow::L4FlowStore)
//! the capture / craft / send-recv / intercept paths populate; they never touch the
//! wire or the guard. They keep L4 flows first-class over MCP / CLI / Rhai without
//! an `aitm-core` edit (the store lives in `aitm-proto-l4`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::craft::{PacketEndpoints, PacketSpec};
use crate::flow::{L4Flow, L4FlowStore};

/// How many packets `l4.flow.get` returns when the caller gives no `limit`.
pub(crate) const FLOW_GET_DEFAULT_LIMIT: usize = 256;
/// The most packets one `l4.flow.get` reply carries; a larger `limit` is clamped.
pub(crate) const FLOW_GET_MAX_LIMIT: usize = 4096;

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
        let read = |name: &str, default: usize| -> anyhow::Result<usize> {
            if args.get(name).is_none() {
                return Ok(default);
            }
            let v = args.get_int(name)?;
            usize::try_from(v)
                .map_err(|_| anyhow::anyhow!("`{name}` must be a non-negative integer"))
        };
        let default = Self::default();
        let offset = read("offset", default.offset)?;
        let limit = read("limit", default.limit)?.min(FLOW_GET_MAX_LIMIT);
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
pub struct FlowGet {
    store: Arc<dyn L4FlowStore>,
}

impl FlowGet {
    /// A command over the shared flow store.
    pub fn new(store: Arc<dyn L4FlowStore>) -> Self {
        Self { store }
    }
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
                          `limit: 0` and let only an inspector fetch a window."
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

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id_str = args.get_str("id")?;
        let id = super::flow_id_from_str(id_str)?;
        let window = PacketWindow::from_params(&args)?;
        let flow = self
            .store
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no L4 flow with id {id_str}"))?;
        Ok(flow_to_value(&flow, window))
    }
}

/// The fields `l4.flow.get` reports.
fn flow_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
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
                    true,
                    "The on-wire bytes (base64 over MCP).",
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
            "The `[offset, offset + limit)` window of the packet log, in arrival order; \
             empty past the end.",
        ),
    ]
}

/// Milliseconds since the Unix epoch, UTC, the same clock HTTP `flow.get`'s
/// `started_at` uses. A pre-epoch time is `0`; a time past `i64::MAX` ms saturates.
fn epoch_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
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
pub(crate) fn flow_to_value(flow: &L4Flow, window: PacketWindow) -> Value {
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
    let packets: Vec<Value> = flow
        .packets
        .iter()
        .skip(window.offset)
        .take(window.limit)
        .map(|p| {
            let endpoints = PacketSpec::endpoints(&p.bytes);
            let mut o = BTreeMap::new();
            o.insert("dir".to_string(), Value::Str(dir(p.dir).to_string()));
            o.insert("length".to_string(), Value::Int(p.bytes.len() as i64));
            o.insert("injected".to_string(), Value::Bool(p.injected));
            o.insert(
                "layers".to_string(),
                Value::Array(p.decoded.layers.iter().cloned().map(Value::Str).collect()),
            );
            o.insert("bytes".to_string(), Value::Bytes(p.bytes.clone()));
            o.insert("timestamp".to_string(), Value::Int(epoch_ms(p.timestamp)));
            insert_endpoints(&mut o, &endpoints);
            Value::Object(o)
        })
        .collect();
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
    obj.insert("packets".to_string(), Value::Array(packets));
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use aitm_core::{CommandHost, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
    use futures::future::BoxFuture;

    use super::*;
    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::{InMemoryL4FlowStore, L4Bind, L4FlowId, L4FlowKind, L4Meta, L4Packet};
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

    /// One Capture flow created at `CREATED_MS` holding one inbound packet of
    /// `bytes` seen at `PACKET_MS`, inserted into a fresh store. Returns the store
    /// and the flow id string `l4.flow.get` takes.
    fn one_packet_flow(bytes: Vec<u8>) -> (Arc<dyn L4FlowStore>, String) {
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind {
                interface: "lo0".into(),
                filter: None,
                queue: None,
            },
            packets: VecDeque::from(vec![L4Packet {
                dir: L4Direction::Inbound,
                timestamp: at_ms(PACKET_MS),
                decoded: PacketSpec::summarize(&bytes),
                bytes,
                injected: false,
            }]),
            metadata: L4Meta {
                marks: Vec::new(),
                comment: None,
                created: at_ms(CREATED_MS),
            },
        });
        (store, super::super::flow_id_to_string(id))
    }

    /// Invoke `l4.flow.get {id}` over `store` and return the flow object and its
    /// first packet object.
    fn get(
        store: Arc<dyn L4FlowStore>,
        id: &str,
    ) -> (BTreeMap<String, Value>, BTreeMap<String, Value>) {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        let got = FlowGet::new(store)
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
        assert!(pk("bytes").required);
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

    /// A Capture flow of `n` crafted UDP packets, every other one injected, in a
    /// fresh store. Returns the store and the flow id string.
    fn n_packet_flow(n: usize) -> (Arc<dyn L4FlowStore>, String) {
        let bytes = crafted_udp();
        let decoded = PacketSpec::summarize(&bytes);
        let packets: VecDeque<L4Packet> = (0..n)
            .map(|i| L4Packet {
                dir: L4Direction::Inbound,
                timestamp: at_ms(PACKET_MS + i as u64),
                decoded: decoded.clone(),
                bytes: bytes.clone(),
                injected: i % 2 == 1,
            })
            .collect();
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Capture,
            bind: L4Bind {
                interface: "lo0".into(),
                filter: None,
                queue: None,
            },
            packets,
            metadata: L4Meta {
                marks: Vec::new(),
                comment: None,
                created: at_ms(CREATED_MS),
            },
        });
        (store, super::super::flow_id_to_string(id))
    }

    /// Invoke `l4.flow.get` with `id` plus the given extra params, the way a bus
    /// caller does, returning the raw command result.
    fn get_window(
        store: Arc<dyn L4FlowStore>,
        id: &str,
        extra: &[(&str, i64)],
    ) -> anyhow::Result<Value> {
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id.to_string()));
        for (k, v) in extra {
            m.insert((*k).to_string(), Value::Int(*v));
        }
        FlowGet::new(store).invoke(Params::new(m), &host)
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
        assert_eq!(n, FLOW_GET_DEFAULT_LIMIT);
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
        assert_eq!(n, FLOW_GET_MAX_LIMIT);
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
        assert_eq!(
            PacketWindow::default(),
            PacketWindow {
                offset: 0,
                limit: 256
            }
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
        let schema = FlowGet::new(store).schema();
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
}
