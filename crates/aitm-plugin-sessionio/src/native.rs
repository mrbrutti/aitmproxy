//! The native `aitm` session format: a serde mirror of the flow model.
//!
//! `aitm-core`'s `Flow`/`HttpFlow`/`WsFlow`/`Body` deliberately do **not** derive
//! `Serialize`/`Deserialize` (and `Body::Streamed` cannot round-trip a live wire
//! handle), so this module defines a full-fidelity *mirror* of the model that does
//! derive serde and converts to/from `Flow`. Persisting the store this way keeps
//! `aitm-core` free of a serde derive — adding one would be a non-additive core
//! edit the milestone forbids.
//!
//! Two deliberate collapses on the way out (documented by the spec): a
//! `Body::Streamed` handle materializes to an empty body (its bytes were never
//! buffered), and `InterceptState` is dropped — a restored flow is always
//! `Observed`, never mid-interception.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
    HttpVersion, InterceptState, WsDir, WsFlow, WsMessage, WsOpcode,
};
use serde::{Deserialize, Serialize};

/// Schema tag stamped into — and required back out of — every native document.
/// Bumped when the mirror shape changes incompatibly.
pub const SCHEMA: &str = "aitm-session/1";

/// A whole captured session: the schema tag plus every flow, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDoc {
    pub schema: String,
    pub flows: Vec<FlowRecord>,
}

/// One flow, tagged by protocol so new protocols slot in without breaking old
/// documents.
// Mirrors `aitm_core::Flow`, which accepts the same size gap for the same
// reason: the Http variant holds the whole decoded exchange, and boxing it would
// only move the lint onto `WebSocket` (the response `trailers` field is what
// widened the gap past clippy's threshold).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowRecord {
    Http(HttpRec),
    WebSocket(WsRec),
}

/// Serde mirror of [`HttpFlow`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRec {
    pub id: String,
    pub request: ReqRec,
    pub response: Option<RespRec>,
    pub client_conn: ConnRec,
    pub server_conn: Option<ConnRec>,
    pub metadata: MetaRec,
}

/// Serde mirror of [`WsFlow`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsRec {
    pub id: String,
    pub handshake: String,
    pub messages: Vec<WsMsgRec>,
    pub client_conn: ConnRec,
    pub server_conn: Option<ConnRec>,
    pub metadata: MetaRec,
}

/// Serde mirror of [`HttpRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqRec {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub version: VersionRec,
    pub headers: Vec<(String, String)>,
    pub body: BodyRec,
    pub timestamp: SystemTime,
}

/// Serde mirror of [`HttpResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespRec {
    pub status: u16,
    pub version: VersionRec,
    pub headers: Vec<(String, String)>,
    /// Chunked trailers, in wire order. Additive and optional: a response
    /// without trailers writes no key (the document is byte-identical to one
    /// written before trailers existed), and a document without the key loads
    /// with none, so the `aitm-session/1` tag needs no bump.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trailers: Vec<(String, String)>,
    pub body: BodyRec,
    pub timestamp: SystemTime,
}

/// Serde mirror of [`HttpVersion`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionRec {
    Http11,
    H2,
}

/// Serde mirror of [`Body`]. A streamed handle collapses to `Empty`.
///
/// Externally tagged (not `#[serde(tag = ...)]`): an internally-tagged enum cannot
/// serialize a newtype variant wrapping a byte sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyRec {
    Empty,
    Bytes(Vec<u8>),
}

/// Serde mirror of [`ConnInfo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnRec {
    pub peer: SocketAddr,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls: bool,
    pub established: SystemTime,
}

/// Serde mirror of [`FlowMeta`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRec {
    pub marks: Vec<String>,
    pub comment: Option<String>,
    pub is_replay: bool,
    pub created: SystemTime,
    pub duration: Option<Duration>,
    pub truncated: bool,
    pub edited: bool,
}

/// Serde mirror of [`WsMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMsgRec {
    pub dir: WsDirRec,
    pub opcode: WsOpcodeRec,
    pub data: Vec<u8>,
    pub timestamp: SystemTime,
    pub injected: bool,
}

/// Serde mirror of [`WsDir`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsDirRec {
    ClientToServer,
    ServerToClient,
}

/// Serde mirror of [`WsOpcode`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsOpcodeRec {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// Mirror `flows` into a serializable [`SessionDoc`] tagged with [`SCHEMA`].
pub fn to_doc(flows: &[Flow]) -> SessionDoc {
    SessionDoc {
        schema: SCHEMA.to_string(),
        flows: flows.iter().map(flow_to_rec).collect(),
    }
}

/// Rebuild `Flow`s from a parsed [`SessionDoc`]. Restored flows are always
/// `InterceptState::Observed`; the conversion is infallible (an unparseable id is
/// replaced with a fresh one rather than dropping the flow).
pub fn from_doc(doc: &SessionDoc) -> Vec<Flow> {
    doc.flows.iter().map(rec_to_flow).collect()
}

fn flow_to_rec(flow: &Flow) -> FlowRecord {
    match flow {
        Flow::Http(f) => FlowRecord::Http(HttpRec {
            id: f.id.to_string(),
            request: req_to_rec(&f.request),
            response: f.response.as_ref().map(resp_to_rec),
            client_conn: conn_to_rec(&f.client_conn),
            server_conn: f.server_conn.as_ref().map(conn_to_rec),
            metadata: meta_to_rec(&f.metadata),
        }),
        Flow::WebSocket(f) => FlowRecord::WebSocket(WsRec {
            id: f.id.to_string(),
            handshake: f.handshake.to_string(),
            messages: f.messages.iter().map(ws_msg_to_rec).collect(),
            client_conn: conn_to_rec(&f.client_conn),
            server_conn: f.server_conn.as_ref().map(conn_to_rec),
            metadata: meta_to_rec(&f.metadata),
        }),
    }
}

fn rec_to_flow(rec: &FlowRecord) -> Flow {
    match rec {
        FlowRecord::Http(r) => Flow::Http(HttpFlow {
            id: parse_id(&r.id),
            request: rec_to_req(&r.request),
            response: r.response.as_ref().map(rec_to_resp),
            client_conn: rec_to_conn(&r.client_conn),
            server_conn: r.server_conn.as_ref().map(rec_to_conn),
            metadata: rec_to_meta(&r.metadata),
            intercept: InterceptState::Observed,
        }),
        FlowRecord::WebSocket(r) => Flow::WebSocket(WsFlow {
            id: parse_id(&r.id),
            handshake: parse_id(&r.handshake),
            messages: r.messages.iter().map(rec_to_ws_msg).collect(),
            client_conn: rec_to_conn(&r.client_conn),
            server_conn: r.server_conn.as_ref().map(rec_to_conn),
            metadata: rec_to_meta(&r.metadata),
            intercept: InterceptState::Observed,
        }),
    }
}

fn parse_id(s: &str) -> FlowId {
    s.parse::<FlowId>().unwrap_or_default()
}

fn req_to_rec(r: &HttpRequest) -> ReqRec {
    ReqRec {
        method: r.method.clone(),
        scheme: r.scheme.clone(),
        authority: r.authority.clone(),
        path: r.path.clone(),
        version: version_to_rec(r.version),
        headers: headers_to_rec(&r.headers),
        body: body_to_rec(&r.body),
        timestamp: r.timestamp,
    }
}

fn rec_to_req(r: &ReqRec) -> HttpRequest {
    HttpRequest {
        method: r.method.clone(),
        scheme: r.scheme.clone(),
        authority: r.authority.clone(),
        path: r.path.clone(),
        version: rec_to_version(r.version),
        headers: rec_to_headers(&r.headers),
        body: rec_to_body(&r.body),
        timestamp: r.timestamp,
    }
}

fn resp_to_rec(r: &HttpResponse) -> RespRec {
    RespRec {
        status: r.status,
        version: version_to_rec(r.version),
        headers: headers_to_rec(&r.headers),
        trailers: headers_to_rec(&r.trailers),
        body: body_to_rec(&r.body),
        timestamp: r.timestamp,
    }
}

fn rec_to_resp(r: &RespRec) -> HttpResponse {
    HttpResponse {
        status: r.status,
        version: rec_to_version(r.version),
        headers: rec_to_headers(&r.headers),
        trailers: rec_to_headers(&r.trailers),
        body: rec_to_body(&r.body),
        timestamp: r.timestamp,
    }
}

fn version_to_rec(v: HttpVersion) -> VersionRec {
    match v {
        HttpVersion::Http11 => VersionRec::Http11,
        HttpVersion::H2 => VersionRec::H2,
    }
}

fn rec_to_version(v: VersionRec) -> HttpVersion {
    match v {
        VersionRec::Http11 => HttpVersion::Http11,
        VersionRec::H2 => HttpVersion::H2,
    }
}

fn headers_to_rec(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn rec_to_headers(pairs: &[(String, String)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (n, v) in pairs {
        // `set` is the trusted-source path; it drops a name/value that could not
        // go on the wire. These pairs were captured off a live wire, so valid
        // headers round-trip; a corrupt document cannot smuggle a CRLF back in.
        h.set(n, v);
    }
    h
}

fn body_to_rec(b: &Body) -> BodyRec {
    match b {
        Body::Empty => BodyRec::Empty,
        Body::Bytes(v) => BodyRec::Bytes(v.clone()),
        // A still-streaming handle holds no buffered bytes to persist.
        Body::Streamed(_) => BodyRec::Empty,
    }
}

fn rec_to_body(b: &BodyRec) -> Body {
    match b {
        BodyRec::Empty => Body::Empty,
        BodyRec::Bytes(v) => Body::Bytes(v.clone()),
    }
}

fn conn_to_rec(c: &ConnInfo) -> ConnRec {
    ConnRec {
        peer: c.peer,
        sni: c.sni.clone(),
        alpn: c.alpn.clone(),
        tls: c.tls,
        established: c.established,
    }
}

fn rec_to_conn(c: &ConnRec) -> ConnInfo {
    ConnInfo {
        peer: c.peer,
        sni: c.sni.clone(),
        alpn: c.alpn.clone(),
        tls: c.tls,
        established: c.established,
    }
}

fn meta_to_rec(m: &FlowMeta) -> MetaRec {
    MetaRec {
        marks: m.marks.clone(),
        comment: m.comment.clone(),
        is_replay: m.is_replay,
        created: m.created,
        duration: m.duration,
        truncated: m.truncated,
        edited: m.edited,
    }
}

fn rec_to_meta(m: &MetaRec) -> FlowMeta {
    FlowMeta {
        marks: m.marks.clone(),
        comment: m.comment.clone(),
        is_replay: m.is_replay,
        created: m.created,
        duration: m.duration,
        truncated: m.truncated,
        edited: m.edited,
    }
}

fn ws_msg_to_rec(m: &WsMessage) -> WsMsgRec {
    WsMsgRec {
        dir: match m.dir {
            WsDir::ClientToServer => WsDirRec::ClientToServer,
            WsDir::ServerToClient => WsDirRec::ServerToClient,
        },
        opcode: match m.opcode {
            WsOpcode::Text => WsOpcodeRec::Text,
            WsOpcode::Binary => WsOpcodeRec::Binary,
            WsOpcode::Ping => WsOpcodeRec::Ping,
            WsOpcode::Pong => WsOpcodeRec::Pong,
            WsOpcode::Close => WsOpcodeRec::Close,
        },
        data: m.data.clone(),
        timestamp: m.timestamp,
        injected: m.injected,
    }
}

fn rec_to_ws_msg(m: &WsMsgRec) -> WsMessage {
    WsMessage {
        dir: match m.dir {
            WsDirRec::ClientToServer => WsDir::ClientToServer,
            WsDirRec::ServerToClient => WsDir::ServerToClient,
        },
        opcode: match m.opcode {
            WsOpcodeRec::Text => WsOpcode::Text,
            WsOpcodeRec::Binary => WsOpcode::Binary,
            WsOpcodeRec::Ping => WsOpcode::Ping,
            WsOpcodeRec::Pong => WsOpcode::Pong,
            WsOpcodeRec::Close => WsOpcode::Close,
        },
        data: m.data.clone(),
        timestamp: m.timestamp,
        injected: m.injected,
    }
}
