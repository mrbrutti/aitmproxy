//! The detail plugin (F5): `flow.detail` — the full inspector shape for one flow.
//!
//! `flow.get` is a one-line summary; the inspector needs headers, bodies,
//! connection metadata, timing and edit state. `flow.detail {id, body}` returns
//! all of it. Bodies cross as `Bytes` (base64 on the bus); `body` selects whether
//! they are included (`inline`, the default), omitted (`none`), or sliced
//! (`range` with `offset`/`length`), so a surface can page a large body.
//!
//! The shape matches the surfaces' recorded expectation (ui-tui architecture note,
//! web FlowDetail): `request`/`response` objects for HTTP, `messages` for a
//! WebSocket, `client_conn`/`server_conn`, `meta`, `intercept` and `edited`.
//! Peer→process resolution and per-flow origin are deferred (Q6 / F2) and reported
//! as `null` rather than omitted, so a surface renders a stable shape.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, Command, CommandHost, ConnInfo, Flow, FlowMeta, HeaderMap, HttpResponse, HttpVersion,
    ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc, Value, WsMessage,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Registers `flow.detail`. Observes no events.
pub struct DetailPlugin;

impl DetailPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DetailPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for DetailPlugin {
    fn name(&self) -> &str {
        "detail"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowDetail));
    }
}

/// How `flow.detail` emits message bodies.
#[derive(Clone, Copy)]
enum BodyMode {
    /// Omit the bytes (keep `body_size`): list/summary scanning.
    None,
    /// The full body bytes.
    Inline,
    /// A `[offset, length)` slice of the body bytes.
    Range {
        offset: usize,
        length: Option<usize>,
    },
}

struct FlowDetail;

impl Command for FlowDetail {
    fn name(&self) -> &str {
        "flow.detail"
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Full detail for one flow: headers, bodies, connection info, timing and \
                          edit state. `body` selects none|inline|range (default inline)."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "The flow to inspect.".into(),
                },
                ParamDef {
                    name: "body".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Body mode: `none`, `inline` (default), or `range`.".into(),
                },
                ParamDef {
                    name: "offset".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Byte offset for `body: range` (default 0).".into(),
                },
                ParamDef {
                    name: "length".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Byte length for `body: range` (default: to the end).".into(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let mode = body_mode(&args)?;
        let flow = host
            .store()
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))?;
        Ok(detail(&flow, mode))
    }
}

/// Parse the `body` mode plus its `offset`/`length` (used only for `range`).
fn body_mode(args: &Params) -> anyhow::Result<BodyMode> {
    let mode = match args.get("body") {
        None => "inline",
        Some(_) => args.get_str("body")?,
    };
    match mode {
        "none" => Ok(BodyMode::None),
        "inline" => Ok(BodyMode::Inline),
        "range" => {
            let offset = match args.get("offset") {
                None => 0,
                Some(_) => usize::try_from(args.get_int("offset")?)
                    .map_err(|_| anyhow::anyhow!("`offset` must be non-negative"))?,
            };
            let length = match args.get("length") {
                None => None,
                Some(_) => Some(
                    usize::try_from(args.get_int("length")?)
                        .map_err(|_| anyhow::anyhow!("`length` must be non-negative"))?,
                ),
            };
            Ok(BodyMode::Range { offset, length })
        }
        other => anyhow::bail!("`body` must be none|inline|range, got `{other}`"),
    }
}

fn detail(flow: &Flow, mode: BodyMode) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("id".into(), Value::Str(flow.id().to_string()));
    match flow {
        Flow::Http(f) => {
            obj.insert("kind".into(), Value::Str("http".into()));
            let mut req = BTreeMap::new();
            req.insert("method".into(), Value::Str(f.request.method.clone()));
            req.insert("scheme".into(), Value::Str(f.request.scheme.clone()));
            req.insert("authority".into(), Value::Str(f.request.authority.clone()));
            req.insert("path".into(), Value::Str(f.request.path.clone()));
            req.insert(
                "version".into(),
                Value::Str(version(f.request.version).into()),
            );
            req.insert("headers".into(), headers(&f.request.headers));
            put_body(&mut req, &f.request.body, mode, false);
            obj.insert("request".into(), Value::Object(req));
            obj.insert(
                "response".into(),
                response(f.response.as_ref(), mode, f.metadata.truncated),
            );
            obj.insert("client_conn".into(), conn(&f.client_conn, true));
            obj.insert("server_conn".into(), opt_conn(f.server_conn.as_ref()));
            obj.insert("meta".into(), meta(&f.metadata));
            obj.insert("intercept".into(), Value::Str(f.intercept.label().into()));
            obj.insert("edited".into(), Value::Bool(f.metadata.edited));
        }
        Flow::WebSocket(f) => {
            obj.insert("kind".into(), Value::Str("websocket".into()));
            obj.insert("handshake".into(), Value::Str(f.handshake.to_string()));
            obj.insert(
                "messages".into(),
                Value::Array(f.messages.iter().map(|m| ws_message(m, mode)).collect()),
            );
            obj.insert("client_conn".into(), conn(&f.client_conn, true));
            obj.insert("server_conn".into(), opt_conn(f.server_conn.as_ref()));
            obj.insert("meta".into(), meta(&f.metadata));
            obj.insert("intercept".into(), Value::Str(f.intercept.label().into()));
            obj.insert("edited".into(), Value::Bool(f.metadata.edited));
        }
    }
    Value::Object(obj)
}

fn response(resp: Option<&HttpResponse>, mode: BodyMode, truncated: bool) -> Value {
    match resp {
        None => Value::Null,
        Some(r) => {
            let mut obj = BTreeMap::new();
            obj.insert("status".into(), Value::Int(i64::from(r.status)));
            obj.insert("version".into(), Value::Str(version(r.version).into()));
            obj.insert("headers".into(), headers(&r.headers));
            put_body(&mut obj, &r.body, mode, truncated);
            Value::Object(obj)
        }
    }
}

/// Emit `body`, `body_size`, and `body_truncated` into an object per the mode.
fn put_body(obj: &mut BTreeMap<String, Value>, body: &Body, mode: BodyMode, truncated: bool) {
    let bytes = body_bytes(body);
    let size = bytes.map(|b| b.len()).unwrap_or(0);
    obj.insert("body_size".into(), Value::Int(size as i64));
    obj.insert("body_truncated".into(), Value::Bool(truncated));
    let value = match (bytes, mode) {
        (_, BodyMode::None) | (None, _) => Value::Null,
        (Some(b), BodyMode::Inline) => Value::Bytes(b.to_vec()),
        (Some(b), BodyMode::Range { offset, length }) => {
            let start = offset.min(b.len());
            let end = match length {
                Some(len) => start.saturating_add(len).min(b.len()),
                None => b.len(),
            };
            Value::Bytes(b[start..end].to_vec())
        }
    };
    obj.insert("body".into(), value);
}

fn body_bytes(body: &Body) -> Option<&[u8]> {
    match body {
        Body::Bytes(b) => Some(b),
        // An empty body is zero bytes (so inline emits empty bytes, not null); a
        // still-streaming body has none buffered yet (emits null).
        Body::Empty => Some(&[]),
        Body::Streamed(_) => None,
    }
}

fn ws_message(m: &WsMessage, mode: BodyMode) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("dir".into(), Value::Str(ws_dir(m).into()));
    obj.insert("opcode".into(), Value::Str(ws_opcode(m).into()));
    obj.insert("length".into(), Value::Int(m.data.len() as i64));
    obj.insert("injected".into(), Value::Bool(m.injected));
    obj.insert("timestamp".into(), rfc3339(m.timestamp));
    let data = match mode {
        BodyMode::None => Value::Null,
        BodyMode::Inline => Value::Bytes(m.data.clone()),
        BodyMode::Range { offset, length } => {
            let start = offset.min(m.data.len());
            let end = match length {
                Some(len) => start.saturating_add(len).min(m.data.len()),
                None => m.data.len(),
            };
            Value::Bytes(m.data[start..end].to_vec())
        }
    };
    obj.insert("data".into(), data);
    Value::Object(obj)
}

fn ws_dir(m: &WsMessage) -> &'static str {
    use aitm_core::WsDir;
    match m.dir {
        WsDir::ClientToServer => "client_to_server",
        WsDir::ServerToClient => "server_to_client",
    }
}

fn ws_opcode(m: &WsMessage) -> &'static str {
    use aitm_core::WsOpcode;
    match m.opcode {
        WsOpcode::Text => "text",
        WsOpcode::Binary => "binary",
        WsOpcode::Ping => "ping",
        WsOpcode::Pong => "pong",
        WsOpcode::Close => "close",
    }
}

fn headers(h: &HeaderMap) -> Value {
    Value::Array(
        h.iter()
            .map(|(name, value)| {
                Value::Array(vec![
                    Value::Str(name.to_string()),
                    Value::Str(value.to_string()),
                ])
            })
            .collect(),
    )
}

fn conn(c: &ConnInfo, with_process: bool) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("peer".into(), Value::Str(c.peer.to_string()));
    obj.insert("sni".into(), opt_str(c.sni.as_deref()));
    obj.insert("alpn".into(), opt_str(c.alpn.as_deref()));
    obj.insert("tls".into(), Value::Bool(c.tls));
    obj.insert("established".into(), rfc3339(c.established));
    if with_process {
        // Peer→process (the Client column) is deferred (foundation Q6): a stable
        // null until core resolves the owning process.
        obj.insert("process".into(), Value::Null);
    }
    Value::Object(obj)
}

fn opt_conn(c: Option<&ConnInfo>) -> Value {
    match c {
        Some(c) => conn(c, false),
        None => Value::Null,
    }
}

fn meta(m: &FlowMeta) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert(
        "marks".into(),
        Value::Array(m.marks.iter().cloned().map(Value::Str).collect()),
    );
    obj.insert("comment".into(), opt_str(m.comment.as_deref()));
    obj.insert("is_replay".into(), Value::Bool(m.is_replay));
    obj.insert("created".into(), rfc3339(m.created));
    obj.insert(
        "duration_ms".into(),
        m.duration
            .map_or(Value::Null, |d| Value::Int(duration_ms(d))),
    );
    obj.insert("truncated".into(), Value::Bool(m.truncated));
    obj.insert("edited".into(), Value::Bool(m.edited));
    // Per-flow origin (human vs agent) is deferred to the audit work (F2).
    obj.insert("origin".into(), Value::Null);
    Value::Object(obj)
}

fn opt_str(s: Option<&str>) -> Value {
    s.map_or(Value::Null, |s| Value::Str(s.to_string()))
}

fn version(v: HttpVersion) -> &'static str {
    match v {
        HttpVersion::Http11 => "HTTP/1.1",
        HttpVersion::H2 => "HTTP/2",
    }
}

fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// A `SystemTime` as an RFC3339 UTC string, or `Null` for a time outside the
/// representable range (never a fabricated epoch timestamp).
fn rfc3339(t: SystemTime) -> Value {
    let nanos = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i128::try_from(d.as_nanos()).ok(),
        // Pre-epoch: negate the elapsed time back from zero.
        Err(e) => i128::try_from(e.duration().as_nanos())
            .ok()
            .and_then(|n| n.checked_neg()),
    };
    nanos
        .and_then(|n| OffsetDateTime::from_unix_timestamp_nanos(n).ok())
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::Str)
}
