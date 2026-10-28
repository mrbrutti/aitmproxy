//! `FlowState`: the pure snapshot of a flow's mutable surface that a hook edits,
//! applied back to the `FlowCtx` after the hook returns (plan Task 4).
//!
//! This is the effect model (spec §5, OQ10 option C). Before a hook runs the
//! host takes a [`FlowState::snapshot`]; the Rhai handles (Task 5) edit that
//! snapshot and push [`FlowEffect`]s onto it; when the hook returns `Ok` the
//! host calls [`FlowState::apply_to`], which writes the changed fields back
//! and replays the effects in order. When the hook errors the host simply
//! drops the `FlowState` and the live flow is untouched (Task 8).
//!
//! Nothing here touches Rhai: the type is plain data so the apply step is
//! testable on its own.

use std::time::SystemTime;

use aitm_core::{
    Body, Event, Flow, FlowCtx, FlowId, FlowKind, HeaderMap, HttpRequest, HttpResponse,
    HttpVersion, Verdict, WsDir, WsMessage, WsOpcode,
};

/// Owned mirror of a flow's mutable surface plus the control actions the
/// script requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowState {
    pub id: FlowId,
    pub kind: FlowKind,
    /// `Some` for HTTP flows.
    pub request: Option<RequestState>,
    /// `Some` for HTTP flows that already carry a response.
    pub response: Option<ResponseState>,
    /// `Some` for a `WsMessage` event: the frame the event is about.
    pub ws_message: Option<WsMessageState>,
    pub marks: Vec<String>,
    pub comment: Option<String>,
    pub is_replay: bool,
    /// Ordered control actions the script requested.
    pub effects: Vec<FlowEffect>,
}

/// The request as a script sees it. `url` is the whole URL; `path` is the path
/// alone and `query` its parsed pairs (both derived from `HttpRequest::path`,
/// which carries path plus query).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestState {
    pub method: String,
    pub url: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The response as a script sees it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponseState {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// One WebSocket frame as a script sees it: `direction` is `"c2s"` / `"s2c"`,
/// `opcode` is `"text"` / `"binary"` / `"ping"` / `"pong"` / `"close"`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsMessageState {
    pub direction: String,
    pub opcode: String,
    pub data: Vec<u8>,
}

/// Control actions a script may request; applied to the `FlowCtx` after the
/// hook returns, in the order they were requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowEffect {
    SetResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Intercept,
    Resume,
    Kill,
    Backup,
    Revert,
    Halt,
    DropWsMessage,
}

impl FlowState {
    /// Snapshot the mutable surface of a live flow before a hook runs. Bodies
    /// are copied up to `max_body` bytes. For a `WsMessage` event the frame at
    /// the event's index is carried as `ws_message`.
    pub fn snapshot(flow: &Flow, ev: &Event, max_body: usize) -> Self {
        match flow {
            Flow::Http(f) => Self {
                id: f.id,
                kind: FlowKind::Http,
                request: Some(RequestState::from_request(&f.request, max_body)),
                response: f
                    .response
                    .as_ref()
                    .map(|r| ResponseState::from_response(r, max_body)),
                ws_message: None,
                marks: f.metadata.marks.clone(),
                comment: f.metadata.comment.clone(),
                is_replay: f.metadata.is_replay,
                effects: Vec::new(),
            },
            Flow::WebSocket(w) => {
                let ws_message = match ev {
                    Event::WsMessage { index, .. } => w
                        .messages
                        .get(*index)
                        .map(|m| WsMessageState::from_message(m, max_body)),
                    _ => None,
                };
                Self {
                    id: w.id,
                    kind: FlowKind::WebSocket,
                    request: None,
                    response: None,
                    ws_message,
                    marks: w.metadata.marks.clone(),
                    comment: w.metadata.comment.clone(),
                    is_replay: w.metadata.is_replay,
                    effects: Vec::new(),
                }
            }
        }
    }

    /// Apply field edits and effects back to the live flow; returns the chain
    /// verdict: `Halt` iff a [`FlowEffect::Halt`] was recorded.
    ///
    /// Only fields that differ from the live flow are written, so an untouched
    /// snapshot leaves the flow byte-for-byte as it was (a streamed body stays
    /// streamed, a bare `?raw` query key is not rewritten as `raw=`). Effects
    /// replay after the field edits, in request order.
    pub fn apply_to(self, ctx: &mut FlowCtx<'_>) -> Verdict {
        let FlowState {
            request,
            response,
            ws_message,
            marks,
            comment,
            effects,
            ..
        } = self;

        let version = match ctx.flow_mut() {
            Flow::Http(f) => {
                if let Some(req) = request {
                    req.write_back(&mut f.request);
                }
                // A snapshot only ever carries a response the live flow already
                // had: the handles refuse to edit an absent one, and the only
                // way to *create* a response is the explicit `SetResponse`
                // effect below.
                if let (Some(resp), Some(live)) = (response, f.response.as_mut()) {
                    resp.write_back(live);
                }
                f.metadata.marks = marks;
                f.metadata.comment = comment;
                f.request.version
            }
            Flow::WebSocket(w) => {
                // The frame a `WsMessage` event is about is the newest one: the
                // WebSocket module appends it and dispatches in the same step,
                // and the chain holds the flow for the whole dispatch.
                if let (Some(msg), Some(live)) = (ws_message, w.messages.last_mut()) {
                    msg.write_back(live);
                }
                w.metadata.marks = marks;
                w.metadata.comment = comment;
                HttpVersion::Http11
            }
        };

        let mut verdict = Verdict::Continue;
        for effect in effects {
            match effect {
                FlowEffect::SetResponse {
                    status,
                    headers,
                    body,
                } => ctx.set_response(HttpResponse {
                    status,
                    version,
                    headers: header_map(headers),
                    body: Body::Bytes(body),
                    timestamp: SystemTime::now(),
                }),
                // The chain collects the parked receiver via `take_parked`; a
                // command resumes through the handle stored in the flow's
                // `InterceptState`, so the returned clone is not needed here.
                FlowEffect::Intercept => {
                    let _resume = ctx.intercept();
                }
                FlowEffect::Resume => ctx.resume(),
                FlowEffect::Kill => ctx.kill(),
                FlowEffect::Backup => ctx.backup(),
                FlowEffect::Revert => ctx.revert(),
                FlowEffect::Halt => verdict = Verdict::Halt,
                FlowEffect::DropWsMessage => {
                    if let Flow::WebSocket(w) = ctx.flow_mut() {
                        w.messages.pop();
                    }
                }
            }
        }
        verdict
    }
}

impl RequestState {
    fn from_request(req: &HttpRequest, max_body: usize) -> Self {
        let (path, query) = split_path_query(&req.path);
        Self {
            method: req.method.clone(),
            url: format!("{}://{}{}", req.scheme, req.authority, req.path),
            path: path.to_string(),
            headers: header_pairs(&req.headers),
            query,
            body: body_prefix(&req.body, max_body),
        }
    }

    /// Write the fields that changed back onto `live`. A changed whole `url`
    /// wins over `path`/`query` edits (it re-targets scheme, authority and
    /// path); otherwise a changed `path`/`query` is re-joined into
    /// `HttpRequest::path`.
    fn write_back(self, live: &mut HttpRequest) {
        let before = Self::from_request(live, usize::MAX);
        if self.method != before.method {
            live.method = self.method;
        }
        if self.url != before.url {
            let (origin, path) = split_url(&self.url);
            if let Some((scheme, authority)) = origin {
                live.scheme = scheme;
                live.authority = authority;
            }
            live.path = path;
        } else if self.path != before.path || self.query != before.query {
            live.path = join_path_query(&self.path, &self.query);
        }
        if self.headers != before.headers {
            live.headers = header_map(self.headers);
        }
        if body_changed(&self.body, &before.body) {
            live.body = Body::Bytes(self.body);
        }
    }
}

impl ResponseState {
    fn from_response(resp: &HttpResponse, max_body: usize) -> Self {
        Self {
            status: resp.status,
            headers: header_pairs(&resp.headers),
            body: body_prefix(&resp.body, max_body),
        }
    }

    fn write_back(self, live: &mut HttpResponse) {
        let before = Self::from_response(live, usize::MAX);
        if self.status != before.status {
            live.status = self.status;
        }
        if self.headers != before.headers {
            live.headers = header_map(self.headers);
        }
        if body_changed(&self.body, &before.body) {
            live.body = Body::Bytes(self.body);
        }
    }
}

impl WsMessageState {
    fn from_message(msg: &WsMessage, max_body: usize) -> Self {
        Self {
            direction: match msg.dir {
                WsDir::ClientToServer => "c2s",
                WsDir::ServerToClient => "s2c",
            }
            .to_string(),
            opcode: match msg.opcode {
                WsOpcode::Text => "text",
                WsOpcode::Binary => "binary",
                WsOpcode::Ping => "ping",
                WsOpcode::Pong => "pong",
                WsOpcode::Close => "close",
            }
            .to_string(),
            data: msg.data[..msg.data.len().min(max_body)].to_vec(),
        }
    }

    /// Write the frame back; an unrecognised `direction`/`opcode` string
    /// leaves the live value alone.
    fn write_back(self, live: &mut WsMessage) {
        live.dir = match self.direction.as_str() {
            "c2s" => WsDir::ClientToServer,
            "s2c" => WsDir::ServerToClient,
            _ => live.dir,
        };
        live.opcode = match self.opcode.as_str() {
            "text" => WsOpcode::Text,
            "binary" => WsOpcode::Binary,
            "ping" => WsOpcode::Ping,
            "pong" => WsOpcode::Pong,
            "close" => WsOpcode::Close,
            _ => live.opcode,
        };
        if body_changed(&self.data, &live.data) {
            live.data = self.data;
        }
    }
}

/// `(name, value)` pairs in wire order.
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Rebuild a `HeaderMap` from pairs. `HeaderMap::set` validates each entry,
/// so a script cannot smuggle a CRLF onto the wire: an invalid header is
/// dropped rather than written.
fn header_map(pairs: Vec<(String, String)>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.set(&k, &v);
    }
    map
}

/// The buffered bytes of a body, capped at `max_body`. A streamed body has no
/// bytes to copy and reads as empty.
fn body_prefix(body: &Body, max_body: usize) -> Vec<u8> {
    match body {
        Body::Bytes(b) => b[..b.len().min(max_body)].to_vec(),
        Body::Empty | Body::Streamed(_) => Vec::new(),
    }
}

/// Whether the script's body differs from the live one. A snapshot capped at
/// `max_body` is a strict prefix of the live body and counts as unchanged.
fn body_changed(new: &[u8], live: &[u8]) -> bool {
    new != live && !(live.len() > new.len() && live.starts_with(new))
}

/// Split `HttpRequest::path` (path plus query) into the path and the parsed
/// query pairs. A key without `=` gets an empty value.
fn split_path_query(path_and_query: &str) -> (&str, Vec<(String, String)>) {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let pairs = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        })
        .collect();
    (path, pairs)
}

/// The inverse of [`split_path_query`] for an edited path/query.
fn join_path_query(path: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return path.to_string();
    }
    let joined = query
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                k.clone()
            } else {
                format!("{k}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{joined}")
}

/// Split a whole URL into `Some((scheme, authority))` plus path-and-query. A
/// string without `://` is taken as a path-and-query alone (origin unchanged).
fn split_url(url: &str) -> (Option<(String, String)>, String) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (None, url.to_string());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    (
        Some((scheme.to_string(), authority.to_string())),
        path.to_string(),
    )
}
