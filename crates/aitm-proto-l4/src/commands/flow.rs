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
            description: "Summarize one L4 flow: kind, bind, creation time, endpoints, and its \
                          packets with bytes, time and addresses (read-only)."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The L4 flow id to summarize.".into(),
            }],
            result: TypeDesc::Object(flow_fields()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id_str = args.get_str("id")?;
        let id = super::flow_id_from_str(id_str)?;
        let flow = self
            .store
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no L4 flow with id {id_str}"))?;
        Ok(flow_to_value(&flow))
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
            "Packets recorded so far.",
        ),
        field(
            "injected_count",
            TypeDesc::Int,
            true,
            "Of those, how many aitmproxy authored.",
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
            "The packet log, in arrival order.",
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
        e.proto.map_or(Value::Null, |p| Value::Str(p.to_string())),
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

/// An [`L4Flow`] as a transport-neutral object.
pub(crate) fn flow_to_value(flow: &L4Flow) -> Value {
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

    // Flow-level endpoints: the first packet that decodes to a transport.
    let mut flow_endpoints = PacketEndpoints::default();
    let packets: Vec<Value> = flow
        .packets
        .iter()
        .map(|p| {
            let endpoints = PacketSpec::endpoints(&p.bytes);
            if flow_endpoints.proto.is_none() && endpoints.proto.is_some() {
                flow_endpoints = endpoints.clone();
            }
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
}
