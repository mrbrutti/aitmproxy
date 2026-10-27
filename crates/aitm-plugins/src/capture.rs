//! The capture plugin: read commands over the flow store.
//!
//! Capture itself is passive — the protocol modules insert flows as they drive
//! them. This plugin exposes `flow.list` and `flow.get` so every frontend can
//! retrieve what was captured through the one command bus.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Flow, InterceptState, ParamDef, ParamSchema, Params, Plugin, Registry,
    TypeDesc, Value,
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
    }
}

/// `flow.list` → the ids of every stored flow, oldest first.
struct FlowList;

impl Command for FlowList {
    fn name(&self) -> &str {
        "flow.list"
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
    ]
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
            put("is_replay", Value::Bool(f.metadata.is_replay));
            put(
                "intercept",
                Value::Str(intercept_label(&f.intercept).into()),
            );
        }
        Flow::WebSocket(f) => {
            put("kind", Value::Str("websocket".into()));
            put("handshake", Value::Str(f.handshake.to_string()));
            put("messages", Value::Int(f.messages.len() as i64));
            put("is_replay", Value::Bool(f.metadata.is_replay));
            put(
                "intercept",
                Value::Str(intercept_label(&f.intercept).into()),
            );
        }
    }
    Value::Object(obj)
}

fn intercept_label(state: &InterceptState) -> &'static str {
    match state {
        InterceptState::Observed => "observed",
        InterceptState::Intercepted { .. } => "intercepted",
        InterceptState::Resumed => "resumed",
        InterceptState::Killed => "killed",
    }
}
