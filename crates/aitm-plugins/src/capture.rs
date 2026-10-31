//! The capture plugin: read commands over the flow store.
//!
//! Capture itself is passive — the protocol modules insert flows as they drive
//! them. This plugin exposes `flow.list` and `flow.get` so every frontend can
//! retrieve what was captured through the one command bus.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    Body, Command, CommandHost, Flow, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc,
    Value,
};

/// Registers `flow.list` and `flow.get`. Observes no events.
pub struct CapturePlugin;

impl CapturePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CapturePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for CapturePlugin {
    fn name(&self) -> &str {
        "capture"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowList));
        reg.add_command(Arc::new(FlowGet));
        reg.add_command(Arc::new(FlowTable));
    }
}

/// `flow.list` → the ids of every stored flow, oldest first.
struct FlowList;

impl Command for FlowList {
    fn name(&self) -> &str {
        "flow.list"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the ids of every captured flow, oldest first.".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::FlowId)),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            host.store()
                .list()
                .into_iter()
                .map(|id| Value::Str(id.to_string()))
                .collect(),
        ))
    }
}

/// `flow.get {id}` → a summary object for one flow.
struct FlowGet;

impl Command for FlowGet {
    fn name(&self) -> &str {
        "flow.get"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Summarize one captured flow: kind, request line, status, state.".into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::FlowId,
                required: true,
                description: "The flow to summarize.".into(),
            }],
            result: TypeDesc::Object(summary_fields()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let flow = host
            .store()
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))?;
        Ok(summarize(&flow))
    }
}

/// The fields `summarize` emits. HTTP-only fields are optional: a WebSocket flow
/// reports `handshake` and `messages` instead of a request line.
fn summary_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field("id", TypeDesc::FlowId, true, "The flow id."),
        field("kind", TypeDesc::Str, true, "`http` or `websocket`."),
        field("intercept", TypeDesc::Str, true, "Interception state."),
        field(
            "is_replay",
            TypeDesc::Bool,
            true,
            "Whether a replay produced it.",
        ),
        field("method", TypeDesc::Str, false, "HTTP request method."),
        field("scheme", TypeDesc::Str, false, "HTTP request scheme."),
        field(
            "authority",
            TypeDesc::Str,
            false,
            "HTTP request host[:port].",
        ),
        field("path", TypeDesc::Str, false, "HTTP request path and query."),
        field(
            "status",
            TypeDesc::Int,
            false,
            "Response status; null until it arrives.",
        ),
        field(
            "handshake",
            TypeDesc::FlowId,
            false,
            "The WebSocket's upgrade flow.",
        ),
        field(
            "messages",
            TypeDesc::Int,
            false,
            "WebSocket frames captured so far.",
        ),
        field(
            "request_bytes",
            TypeDesc::Int,
            false,
            "HTTP request body size in bytes; null while it is still streaming.",
        ),
        field(
            "response_bytes",
            TypeDesc::Int,
            false,
            "HTTP response body size in bytes; null until the response arrives or while \
             it is still streaming.",
        ),
    ]
}

/// A buffered body's size in bytes, or `Null` while it is still streaming from the
/// wire and the size is not known yet. Lets a UI total the traffic it has seen
/// (the macOS status bar's ↑ / ↓ rate) without fetching a single body.
fn body_bytes(body: &Body) -> Value {
    match body {
        Body::Empty => Value::Int(0),
        Body::Bytes(bytes) => Value::Int(bytes.len() as i64),
        Body::Streamed(_) => Value::Null,
    }
}

/// A transport-neutral summary of a flow.
fn summarize(flow: &Flow) -> Value {
    let mut obj = BTreeMap::new();
    let mut put = |k: &str, v: Value| {
        obj.insert(k.to_string(), v);
    };
    put("id", Value::Str(flow.id().to_string()));
    match flow {
        Flow::Http(f) => {
            put("kind", Value::Str("http".into()));
            put("method", Value::Str(f.request.method.clone()));
            put("scheme", Value::Str(f.request.scheme.clone()));
            put("authority", Value::Str(f.request.authority.clone()));
            put("path", Value::Str(f.request.path.clone()));
            put(
                "status",
                f.response
                    .as_ref()
                    .map_or(Value::Null, |r| Value::Int(i64::from(r.status))),
            );
            put("request_bytes", body_bytes(&f.request.body));
            put(
                "response_bytes",
                f.response
                    .as_ref()
                    .map_or(Value::Null, |r| body_bytes(&r.body)),
            );
            put("is_replay", Value::Bool(f.metadata.is_replay));
            put("intercept", Value::Str(f.intercept.label().into()));
        }
        Flow::WebSocket(f) => {
            put("kind", Value::Str("websocket".into()));
            put("handshake", Value::Str(f.handshake.to_string()));
            put("messages", Value::Int(f.messages.len() as i64));
            put("is_replay", Value::Bool(f.metadata.is_replay));
            put("intercept", Value::Str(f.intercept.label().into()));
        }
    }
    Value::Object(obj)
}

/// `flow.table` → one summary row per stored flow, oldest first, for a flows
/// table: method, URL parts, status, duration, state, and marks. Read-only; no
/// headers or bodies, so the result stays small and model-safe.
struct FlowTable;

impl Command for FlowTable {
    fn name(&self) -> &str {
        "flow.table"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Per-flow summaries for a flows table: method, URL, status, \
                 duration, state, and marks, oldest first. Read-only."
                .into(),
            params: vec![],
            result: TypeDesc::Object(vec![ParamDef {
                name: "flows".into(),
                ty: TypeDesc::Array(Box::new(TypeDesc::Object(row_fields()))),
                required: true,
                description: "One summary row per captured flow, oldest first.".into(),
            }]),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let rows = host
            .store()
            .list()
            .into_iter()
            .filter_map(|id| host.store().get(id))
            .map(|flow| flow_row(&flow))
            .collect();
        let mut obj = BTreeMap::new();
        obj.insert("flows".to_string(), Value::Array(rows));
        Ok(Value::Object(obj))
    }
}

/// The fields `flow_row` emits. HTTP-only fields are nullable: a WebSocket row
/// reports `id`/`kind`/`state`/`marks` and leaves the HTTP fields null.
fn row_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field("id", TypeDesc::FlowId, true, "The flow id."),
        field("kind", TypeDesc::Str, true, "`http` or `websocket`."),
        field("state", TypeDesc::Str, true, "Interception state."),
        field(
            "marks",
            TypeDesc::Array(Box::new(TypeDesc::Str)),
            true,
            "Marks applied to the flow.",
        ),
        field("method", TypeDesc::Str, false, "HTTP request method."),
        field(
            "authority",
            TypeDesc::Str,
            false,
            "HTTP request host[:port].",
        ),
        field("path", TypeDesc::Str, false, "HTTP request path and query."),
        field(
            "status",
            TypeDesc::Int,
            false,
            "Response status; null until it arrives.",
        ),
        field(
            "duration_ms",
            TypeDesc::Int,
            false,
            "Flow duration in whole milliseconds; null if unknown.",
        ),
    ]
}

/// A single flows-table row: identity, state, marks, and (HTTP only) the request
/// line and response status. No headers, no bodies.
fn flow_row(flow: &Flow) -> Value {
    let mut obj = BTreeMap::new();
    let mut put = |k: &str, v: Value| {
        obj.insert(k.to_string(), v);
    };
    put("id", Value::Str(flow.id().to_string()));
    put("state", Value::Str(flow.intercept().label().into()));
    put(
        "marks",
        Value::Array(
            flow.metadata()
                .marks
                .iter()
                .map(|m| Value::Str(m.clone()))
                .collect(),
        ),
    );
    put(
        "duration_ms",
        flow.metadata().duration.map_or(Value::Null, |d| {
            Value::Int(d.as_millis().min(i64::MAX as u128) as i64)
        }),
    );
    match flow {
        Flow::Http(f) => {
            put("kind", Value::Str("http".into()));
            put("method", Value::Str(f.request.method.clone()));
            put("authority", Value::Str(f.request.authority.clone()));
            put("path", Value::Str(f.request.path.clone()));
            put(
                "status",
                f.response
                    .as_ref()
                    .map_or(Value::Null, |r| Value::Int(i64::from(r.status))),
            );
        }
        Flow::WebSocket(_) => {
            put("kind", Value::Str("websocket".into()));
            put("method", Value::Null);
            put("authority", Value::Null);
            put("path", Value::Null);
            put("status", Value::Null);
        }
    }
    Value::Object(obj)
}
