//! HAR 1.2 interchange: a lossy serde view over `Flow`.
//!
//! HAR holds request/response/timings per entry; fields our model carries that
//! HAR cannot (connection details, `FlowMeta`, `InterceptState`) are dropped on
//! export and defaulted on import. WebSocket frames ride on the Chrome/mitmproxy
//! `_webSocketMessages` entry extension. Bodies serialize as UTF-8 text when they
//! are valid UTF-8, else base64 with `encoding: "base64"` (JSON cannot hold raw
//! bytes), so every body round-trips.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
    HttpVersion, InterceptState, WsDir, WsFlow, WsMessage, WsOpcode,
};
use anyhow::Context as _;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The HAR 1.2 version literal, required out of every exported document.
const HAR_VERSION: &str = "1.2";

/// A HAR 1.2 document: a single `log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Har {
    pub log: HarLog,
}

/// The HAR `log`: version tag, creator, and the captured entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    pub entries: Vec<HarEntry>,
}

/// The tool that wrote the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

/// One request/response exchange (plus WS frames for an upgraded connection).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarEntry {
    pub started_date_time: String,
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(default)]
    pub cache: HarCache,
    pub timings: HarTimings,
    #[serde(
        rename = "_webSocketMessages",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub web_socket_messages: Vec<HarWsMessage>,
}

/// A HAR request. `url` is `scheme://authority/path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    #[serde(default)]
    pub query_string: Vec<HarNameValue>,
    #[serde(default)]
    pub cookies: Vec<HarNameValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

/// A HAR response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    #[serde(default)]
    pub cookies: Vec<HarNameValue>,
    pub content: HarContent,
    #[serde(default)]
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

/// A `name`/`value` pair (header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

/// A `name`/`value` pair (query string, cookie).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValue {
    pub name: String,
    pub value: String,
}

/// Request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarPostData {
    pub mime_type: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// Response body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarContent {
    pub size: i64,
    pub mime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// HAR `cache` object. We never populate it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarCache {}

/// HAR `timings`. We do not measure phases, so each is the HAR "unknown" value -1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarTimings {
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
}

/// One WebSocket frame, Chrome/mitmproxy `_webSocketMessages` shape. `data` is
/// always base64 (binary-safe); `type` is `send` (client→server) or `receive`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarWsMessage {
    #[serde(rename = "type")]
    pub kind: String,
    pub opcode: u8,
    pub data: String,
    pub time: f64,
    #[serde(rename = "_injected", default)]
    pub injected: bool,
}

/// Map a flow list into a HAR 1.2 document.
pub fn flows_to_har(flows: &[Flow]) -> Har {
    Har {
        log: HarLog {
            version: HAR_VERSION.to_string(),
            creator: HarCreator {
                name: "aitmproxy".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            entries: flows.iter().map(flow_to_entry).collect(),
        },
    }
}

/// Rebuild flows from a parsed HAR document. An entry carrying
/// `_webSocketMessages` becomes a `WsFlow`; every other entry an `HttpFlow`. A
/// body (or WS frame) that declares `encoding: "base64"` but cannot be decoded
/// is a corrupt document: the import fails rather than silently dropping bytes.
pub fn har_to_flows(har: &Har) -> anyhow::Result<Vec<Flow>> {
    har.log.entries.iter().map(entry_to_flow).collect()
}

fn flow_to_entry(flow: &Flow) -> HarEntry {
    match flow {
        Flow::Http(f) => http_to_entry(f),
        Flow::WebSocket(f) => ws_to_entry(f),
    }
}

fn http_to_entry(f: &HttpFlow) -> HarEntry {
    let started = f.request.timestamp;
    let response = f
        .response
        .as_ref()
        .map(resp_to_har)
        .unwrap_or_else(empty_response);
    HarEntry {
        started_date_time: iso8601(started),
        time: -1.0,
        request: req_to_har(&f.request),
        response,
        cache: HarCache::default(),
        timings: unknown_timings(),
        web_socket_messages: Vec::new(),
    }
}

fn ws_to_entry(f: &WsFlow) -> HarEntry {
    // A WS flow has no HTTP request of its own; synthesize the 101 upgrade so the
    // entry is well-formed and the frames have somewhere to live.
    let scheme = if f.client_conn.tls { "wss" } else { "ws" };
    let authority = f
        .client_conn
        .sni
        .clone()
        .unwrap_or_else(|| "websocket.invalid".to_string());
    HarEntry {
        started_date_time: iso8601(f.metadata.created),
        time: -1.0,
        request: HarRequest {
            method: "GET".to_string(),
            url: format!("{scheme}://{authority}/"),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            query_string: Vec::new(),
            cookies: Vec::new(),
            post_data: None,
            headers_size: -1,
            body_size: -1,
        },
        response: HarResponse {
            status: 101,
            status_text: "Switching Protocols".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
            cookies: Vec::new(),
            content: HarContent::default(),
            redirect_url: String::new(),
            headers_size: -1,
            body_size: -1,
        },
        cache: HarCache::default(),
        timings: unknown_timings(),
        web_socket_messages: f.messages.iter().map(ws_msg_to_har).collect(),
    }
}

fn entry_to_flow(entry: &HarEntry) -> anyhow::Result<Flow> {
    Ok(if entry.web_socket_messages.is_empty() {
        Flow::Http(entry_to_http(entry)?)
    } else {
        Flow::WebSocket(entry_to_ws(entry)?)
    })
}

fn entry_to_http(entry: &HarEntry) -> anyhow::Result<HttpFlow> {
    let (scheme, authority, path) = split_url(&entry.request.url);
    let request = HttpRequest {
        method: entry.request.method.clone(),
        scheme,
        authority,
        path,
        version: parse_version(&entry.request.http_version),
        headers: har_headers(&entry.request.headers),
        body: post_data_to_body(&entry.request.post_data)?,
        timestamp: UNIX_EPOCH,
    };
    let response = HttpResponse {
        status: entry.response.status,
        version: parse_version(&entry.response.http_version),
        headers: har_headers(&entry.response.headers),
        body: content_to_body(&entry.response.content)?,
        timestamp: UNIX_EPOCH,
    };
    Ok(HttpFlow {
        id: FlowId::new(),
        request,
        response: Some(response),
        client_conn: synth_conn(entry.request.url.starts_with("https")),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn entry_to_ws(entry: &HarEntry) -> anyhow::Result<WsFlow> {
    let tls = entry.request.url.starts_with("wss") || entry.request.url.starts_with("https");
    Ok(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: entry
            .web_socket_messages
            .iter()
            .map(har_to_ws_msg)
            .collect::<anyhow::Result<_>>()?,
        client_conn: synth_conn(tls),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn req_to_har(r: &HttpRequest) -> HarRequest {
    let (size, text, encoding) = encode_body(&r.body);
    let post_data = text.map(|text| HarPostData {
        mime_type: content_type(&r.headers),
        text,
        encoding,
    });
    HarRequest {
        method: r.method.clone(),
        url: format!("{}://{}{}", r.scheme, r.authority, r.path),
        http_version: version_str(r.version),
        headers: headers_to_har(&r.headers),
        query_string: Vec::new(),
        cookies: Vec::new(),
        post_data,
        headers_size: -1,
        body_size: size,
    }
}

fn resp_to_har(r: &HttpResponse) -> HarResponse {
    let (size, text, encoding) = encode_body(&r.body);
    HarResponse {
        status: r.status,
        status_text: reason(r.status),
        http_version: version_str(r.version),
        headers: headers_to_har(&r.headers),
        cookies: Vec::new(),
        content: HarContent {
            size,
            mime_type: content_type(&r.headers),
            text,
            encoding,
        },
        redirect_url: String::new(),
        headers_size: -1,
        body_size: size,
    }
}

fn empty_response() -> HarResponse {
    HarResponse {
        status: 0,
        status_text: String::new(),
        http_version: "HTTP/1.1".to_string(),
        headers: Vec::new(),
        cookies: Vec::new(),
        content: HarContent::default(),
        redirect_url: String::new(),
        headers_size: -1,
        body_size: -1,
    }
}

fn ws_msg_to_har(m: &WsMessage) -> HarWsMessage {
    HarWsMessage {
        kind: match m.dir {
            WsDir::ClientToServer => "send".to_string(),
            WsDir::ServerToClient => "receive".to_string(),
        },
        opcode: opcode_to_u8(m.opcode),
        data: STANDARD.encode(&m.data),
        time: -1.0,
        injected: m.injected,
    }
}

fn har_to_ws_msg(m: &HarWsMessage) -> anyhow::Result<WsMessage> {
    Ok(WsMessage {
        dir: if m.kind == "send" {
            WsDir::ClientToServer
        } else {
            WsDir::ServerToClient
        },
        opcode: u8_to_opcode(m.opcode),
        data: STANDARD
            .decode(&m.data)
            .context("HAR _webSocketMessages: frame data is not valid base64")?,
        timestamp: UNIX_EPOCH,
        injected: m.injected,
    })
}

fn headers_to_har(h: &HeaderMap) -> Vec<HarHeader> {
    h.iter()
        .map(|(n, v)| HarHeader {
            name: n.to_string(),
            value: v.to_string(),
        })
        .collect()
}

fn har_headers(headers: &[HarHeader]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for header in headers {
        // `set` is the trusted-source path; it drops a name/value that cannot go
        // on the wire, so a hostile HAR cannot smuggle a CRLF back in.
        h.set(&header.name, &header.value);
    }
    h
}

/// Case-insensitive Content-Type lookup; empty when absent.
fn content_type(h: &HeaderMap) -> String {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

/// A body as `(size, text, encoding)`. Valid UTF-8 serializes as plain text;
/// anything else as base64 with `encoding: "base64"`. An empty body has no text.
fn encode_body(b: &Body) -> (i64, Option<String>, Option<String>) {
    let bytes = match b {
        Body::Bytes(v) if !v.is_empty() => v.as_slice(),
        // A still-streaming handle holds no buffered bytes to serialize.
        _ => return (0, None, None),
    };
    match std::str::from_utf8(bytes) {
        Ok(s) => (bytes.len() as i64, Some(s.to_string()), None),
        Err(_) => (
            bytes.len() as i64,
            Some(STANDARD.encode(bytes)),
            Some("base64".to_string()),
        ),
    }
}

fn content_to_body(c: &HarContent) -> anyhow::Result<Body> {
    decode_text(c.text.as_deref(), c.encoding.as_deref())
}

fn post_data_to_body(p: &Option<HarPostData>) -> anyhow::Result<Body> {
    match p {
        Some(p) => decode_text(Some(&p.text), p.encoding.as_deref()),
        None => Ok(Body::Empty),
    }
}

fn decode_text(text: Option<&str>, encoding: Option<&str>) -> anyhow::Result<Body> {
    Ok(match text {
        None => Body::Empty,
        Some("") => Body::Empty,
        Some(t) => match encoding {
            // A body tagged base64 that will not decode is corrupt: fail the import
            // rather than silently storing the raw tag bytes as if they were the body.
            Some("base64") => Body::Bytes(
                STANDARD
                    .decode(t)
                    .context("HAR body declared encoding base64 but is not valid base64")?,
            ),
            _ => Body::Bytes(t.as_bytes().to_vec()),
        },
    })
}

fn version_str(v: HttpVersion) -> String {
    match v {
        HttpVersion::Http11 => "HTTP/1.1".to_string(),
        HttpVersion::H2 => "HTTP/2".to_string(),
    }
}

fn parse_version(s: &str) -> HttpVersion {
    if s.contains("/2") {
        HttpVersion::H2
    } else {
        HttpVersion::Http11
    }
}

fn opcode_to_u8(op: WsOpcode) -> u8 {
    match op {
        WsOpcode::Text => 1,
        WsOpcode::Binary => 2,
        WsOpcode::Close => 8,
        WsOpcode::Ping => 9,
        WsOpcode::Pong => 10,
    }
}

fn u8_to_opcode(n: u8) -> WsOpcode {
    match n {
        1 => WsOpcode::Text,
        8 => WsOpcode::Close,
        9 => WsOpcode::Ping,
        10 => WsOpcode::Pong,
        _ => WsOpcode::Binary,
    }
}

/// Split `scheme://authority/path` into its three parts. A url with no path
/// component yields `/`.
fn split_url(url: &str) -> (String, String, String) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    (scheme.to_string(), authority, path)
}

fn synth_conn(tls: bool) -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        sni: None,
        alpn: None,
        tls,
        established: UNIX_EPOCH,
    }
}

fn unknown_timings() -> HarTimings {
    HarTimings {
        send: -1.0,
        wait: -1.0,
        receive: -1.0,
    }
}

/// A minimal reason phrase for the common statuses; empty otherwise (HAR allows
/// an empty `statusText`).
fn reason(status: u16) -> String {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
    .to_string()
}

/// Format a `SystemTime` as an ISO 8601 / RFC 3339 UTC timestamp with millis.
/// Pre-epoch times clamp to the epoch (HAR has no use for them).
fn iso8601(ts: SystemTime) -> String {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Howard Hinnant's days-from-civil inverse: days since 1970-01-01 → (year,
/// month, day). Correct for the full proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}
