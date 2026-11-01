//! The capture plugin: read commands over the flow store.
//!
//! Capture itself is passive — the protocol modules insert flows as they drive
//! them. This plugin exposes `flow.list` and `flow.get` so every frontend can
//! retrieve what was captured through the one command bus.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    saturating_i64, Body, Command, CommandHost, Flow, FlowMeta, ParamDef, ParamSchema, Params,
    Plugin, Registry, TypeDesc, Value,
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

/// `flow.get {id}` → a summary object for one flow: kind, request line, status,
/// body sizes, timing (`started_at`, `duration_ms`), capture attribution
/// (`source_app`, `capture_interface`; null for a proxied flow), the per-host
/// decryption keys (`tunnel`, `tunnel_reason`, `bytes_up`, `bytes_down`, `passive`;
/// spec D7) and interception state.
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
/// reports `handshake` and `messages` instead of a request line. The per-host
/// decryption keys come from `tunnel_field_defs`, shared with `row_fields`.
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
        field(
            "started_at",
            TypeDesc::Int,
            false,
            "When the flow started, in milliseconds since the Unix epoch: the moment the \
             proxy created the flow (the request head for HTTP, the upgrade for \
             WebSocket); null if the clock is before the epoch.",
        ),
        field(
            "duration_ms",
            TypeDesc::Int,
            false,
            "Flow duration in whole milliseconds, from start to the end of the response, \
             or to the point a failed response was abandoned; null while in flight or \
             unknown.",
        ),
        field(
            "source_app",
            TypeDesc::Str,
            false,
            "Signing identifier of the app that opened the connection, as the capture \
             backend observed it; null for a proxied flow.",
        ),
        field(
            "capture_interface",
            TypeDesc::Str,
            false,
            "Capture backend that delivered the connection (`macos-ne`); null for a \
             proxied flow.",
        ),
    ]
    .into_iter()
    .chain(tunnel_field_defs())
    .collect()
}

/// The per-host decryption keys of spec D7, declared once for both `flow.get`
/// (`summary_fields`) and `flow.table` rows (`row_fields`) so the two schemas
/// cannot drift. The four tunnel keys are nullable; `passive` is always a boolean.
fn tunnel_field_defs() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field(
            "tunnel",
            TypeDesc::Str,
            false,
            "Outcome of a `CONNECT` tunnel row: `decrypted` (TLS terminated with the \
             proxy's leaf; the inner requests are their own rows), `passthrough` \
             (relayed byte for byte, the client saw the origin's certificate) or \
             `failed` (never established); null for a flow that is not a tunnel row.",
        ),
        field(
            "tunnel_reason",
            TypeDesc::Str,
            false,
            "Why the tunnel was not decrypted. Passthrough: `out_of_scope` or `pinned`. \
             Failed: `client_rejected_certificate`, `client_closed`, `client_tls_error`, \
             `upstream_unreachable`, `upstream_tls_failed` or `protocol_error`; null \
             for a decrypted tunnel and for a flow that is not a tunnel row.",
        ),
        field(
            "bytes_up",
            TypeDesc::Int,
            false,
            "Client-to-origin bytes a passthrough tunnel relayed, set when it closes; \
             null while it is open and for every other flow.",
        ),
        field(
            "bytes_down",
            TypeDesc::Int,
            false,
            "Origin-to-client bytes a passthrough tunnel relayed, set when it closes; \
             null while it is open and for every other flow.",
        ),
        field(
            "passive",
            TypeDesc::Bool,
            true,
            "Observed only, nothing acted on it: plain HTTP to a host outside Scope. No \
             intercept rule parks it, no script sees it, no scanner touches it; a \
             frontend renders it read-only. False for every tunnel row.",
        ),
    ]
}

/// The per-host decryption keys of spec D7 for one flow's metadata, in the order
/// `tunnel`, `tunnel_reason`, `bytes_up`, `bytes_down`, `passive`: the tunnel
/// outcome's wire codes (`TunnelMode::label`, `TunnelReason::label`) and byte
/// counts when the flow is a tunnel row, null otherwise; `passive` as stamped.
/// Shared by `summarize` and `flow_row` so the two verbs agree by construction.
fn tunnel_fields(meta: &FlowMeta) -> [(&'static str, Value); 5] {
    let tunnel = meta.tunnel.as_ref();
    [
        ("tunnel", opt_str(tunnel.map(|t| t.mode.label()))),
        (
            "tunnel_reason",
            opt_str(tunnel.and_then(|t| t.reason).map(|r| r.label())),
        ),
        (
            "bytes_up",
            opt_int(tunnel.and_then(|t| t.bytes_up).map(saturating_i64)),
        ),
        (
            "bytes_down",
            opt_int(tunnel.and_then(|t| t.bytes_down).map(saturating_i64)),
        ),
        ("passive", Value::Bool(meta.passive)),
    ]
}

/// A body's reported size ([`Body::buffered_len`]) as a `Value`: the byte count,
/// or `Null` while it is still streaming from the wire and the size is not known
/// yet. Lets a UI total the traffic it has seen (the macOS status bar's ↑ / ↓
/// rate) without fetching a single body.
fn body_bytes(body: &Body) -> Value {
    opt_int(body.buffered_len().map(|n| n as i64))
}

/// An optional count as a `Value`: the number, or `Null` when it is unknown. The
/// timing and size rules themselves live on the core types
/// (`FlowMeta::started_at_ms`, `FlowMeta::duration_ms`, `Body::buffered_len`);
/// this only renders their answer.
fn opt_int(n: Option<i64>) -> Value {
    n.map_or(Value::Null, Value::Int)
}

/// An optional attribution string as a `Value`: the text a capture backend
/// recorded (`FlowMeta::source_app`, `FlowMeta::capture_interface`), or `Null`
/// for a proxied flow. Never a placeholder: a UI must not show a fake app group.
fn opt_str(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |s| Value::Str(s.to_owned()))
}

/// A transport-neutral summary of a flow: identity, timing, capture attribution
/// (`source_app` / `capture_interface`, null on a proxied flow), and the per-kind
/// fields (request line, status and body sizes for HTTP; handshake and message
/// count for WebSocket). `started_at` is `metadata.created` for both kinds, so
/// `started_at + duration_ms` is the flow's end.
fn summarize(flow: &Flow) -> Value {
    let mut obj = BTreeMap::new();
    let mut put = |k: &str, v: Value| {
        obj.insert(k.to_string(), v);
    };
    put("id", Value::Str(flow.id().to_string()));
    put("started_at", opt_int(flow.metadata().started_at_ms()));
    put("duration_ms", opt_int(flow.metadata().duration_ms()));
    put("source_app", opt_str(flow.metadata().source_app.as_deref()));
    put(
        "capture_interface",
        opt_str(flow.metadata().capture_interface.as_deref()),
    );
    for (k, v) in tunnel_fields(flow.metadata()) {
        put(k, v);
    }
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
/// reports `id`/`kind`/`state`/`marks` and leaves the HTTP fields null. The
/// per-host decryption keys come from `tunnel_field_defs`, shared with
/// `summary_fields`.
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
        field(
            "source_app",
            TypeDesc::Str,
            false,
            "Signing identifier of the app that opened the connection, as the capture \
             backend observed it; null for a proxied flow.",
        ),
        field(
            "capture_interface",
            TypeDesc::Str,
            false,
            "Capture backend that delivered the connection (`macos-ne`); null for a \
             proxied flow.",
        ),
    ]
    .into_iter()
    .chain(tunnel_field_defs())
    .collect()
}

/// A single flows-table row: identity, state, marks, capture attribution
/// (`source_app` / `capture_interface`, null on a proxied flow), and (HTTP only)
/// the request line and response status. No headers, no bodies.
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
    put("duration_ms", opt_int(flow.metadata().duration_ms()));
    put("source_app", opt_str(flow.metadata().source_app.as_deref()));
    put(
        "capture_interface",
        opt_str(flow.metadata().capture_interface.as_deref()),
    );
    for (k, v) in tunnel_fields(flow.metadata()) {
        put(k, v);
    }
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
