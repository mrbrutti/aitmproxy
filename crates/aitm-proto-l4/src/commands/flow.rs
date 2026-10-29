//! `l4.flow.list` / `.get` — query the l4-owned flow store.
//!
//! Sensitivity: **read-only**. These read the [`L4FlowStore`](crate::flow::L4FlowStore)
//! the capture / craft / send-recv / intercept paths populate; they never touch the
//! wire or the guard. They keep L4 flows first-class over MCP / CLI / Rhai without
//! an `aitm-core` edit (the store lives in `aitm-proto-l4`).

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, TypeDesc, Value};

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

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Summarize one L4 flow: kind, bind, and its packets (read-only).".into(),
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
            ]))),
            true,
            "The packet log, in arrival order.",
        ),
    ]
}

/// An [`L4Flow`] as a transport-neutral object.
fn flow_to_value(flow: &L4Flow) -> Value {
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

    let packets: Vec<Value> = flow
        .packets
        .iter()
        .map(|p| {
            let mut o = BTreeMap::new();
            o.insert("dir".to_string(), Value::Str(dir(p.dir).to_string()));
            o.insert("length".to_string(), Value::Int(p.bytes.len() as i64));
            o.insert("injected".to_string(), Value::Bool(p.injected));
            o.insert(
                "layers".to_string(),
                Value::Array(p.decoded.layers.iter().cloned().map(Value::Str).collect()),
            );
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
        "packet_count".to_string(),
        Value::Int(flow.packets.len() as i64),
    );
    obj.insert("injected_count".to_string(), Value::Int(injected as i64));
    obj.insert("packets".to_string(), Value::Array(packets));
    Value::Object(obj)
}
