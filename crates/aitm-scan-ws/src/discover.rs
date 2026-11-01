//! Insertion points, point specs, traits and site nodes from captured conversations — written by task 3 of the T4 plan.
//!
//! One captured WebSocket conversation (a [`WsFlow`] plus the [`HttpFlow`] that
//! carries its upgrade handshake) becomes one [`SiteNode`] and a list of
//! [`InsertionPoint`]s: the handshake's interesting request headers, the JSON
//! leaves / form pairs / whole payloads of every client->server text frame, and
//! one point per binary frame (spec D8.3 "Insertion points", plan call 4).
//!
//! Nothing here dials anything. Discovery reads a capture and produces wire
//! types, so every observed value it carries out is redacted first: a point's
//! `example` is `<redacted>` when the point's name reads as a secret or it is a
//! `Cookie`/`Authorization` handshake header, and otherwise
//! [`aitm_core::redact::scrub_text`] of the value, bounded to
//! [`EXAMPLE_CHARS`] characters.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use aitm_core::redact::{is_secret_key, scrub_text};
use aitm_core::{FlowId, HttpFlow, WsDir, WsFlow, WsOpcode};
use aitm_scan_model::ids::FlowRef;
use aitm_scan_model::point::{InsertionPoint, ParamRef, SiteNode};
use aitm_scan_model::vocab::{InsertionKind, LaneKind, PointTrait};

use crate::types::{authority_with_port, default_port, Locator, PointSpec};

/// What a point's `example` reads when its value must never be recorded.
pub const REDACTED: &str = "<redacted>";

/// The longest `example` a point carries, in characters.
pub const EXAMPLE_CHARS: usize = 128;

/// Handshake request headers that always become an insertion point, whatever
/// else the skip list says (spec D8.3; `Origin`, `Cookie` and
/// `Sec-WebSocket-Protocol` are the three the spec names by hand).
const ALWAYS_POINT_HEADERS: &[&str] = &[
    "origin",
    "cookie",
    "authorization",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
];

/// Handshake request headers that never become an insertion point: the ones the
/// dialer regenerates per connection, and the ambient client headers that carry
/// nothing a target branches on.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-accept",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "pragma",
    "cache-control",
    "content-length",
];

/// Mints the `ws-<8 hex>` identifiers of one job's insertion points.
///
/// The id is a [`DefaultHasher`] digest of the job salt, the conversation's flow
/// id, the point's kind and its locator, so the same point of the same capture
/// keeps the same id for the life of the job (plan call 14; `blake3` is not in
/// the offline registry cache). Two points that happen to digest to the same
/// value get a `-2`, `-3`, ... suffix, so an id is unique by construction and
/// never silently shared.
#[derive(Debug, Clone)]
pub struct IdGen {
    salt: String,
    used: HashMap<String, u32>,
}

impl IdGen {
    /// An id generator salted with the job's identifier.
    #[must_use]
    pub fn new(job_salt: &str) -> Self {
        Self {
            salt: job_salt.to_string(),
            used: HashMap::new(),
        }
    }

    /// The id for one point of `ws_flow`, unique among the ids minted so far.
    pub fn id(&mut self, ws_flow: FlowId, locator: &Locator, kind: InsertionKind) -> String {
        let digest = digest(&[
            &self.salt,
            &ws_flow.to_string(),
            kind_token(kind),
            &locator_token(locator),
        ]);
        let base = format!("ws-{digest:08x}");
        let seen = self.used.entry(base.clone()).or_insert(0);
        *seen += 1;
        if *seen == 1 {
            base
        } else {
            format!("{base}-{seen}")
        }
    }
}

/// Everything one captured conversation yielded.
///
/// `points` is the wire form the site map renders; `specs` is the in-process
/// half the lane keeps in its registry so `probe_host_for` can re-drive a point
/// by id. The two are parallel: every `points[i].id` appears exactly once in
/// `specs`.
#[derive(Debug, Clone)]
pub struct Discovered {
    /// The insertion points, in discovery order: handshake headers, then the
    /// client->server frames in capture order.
    pub points: Vec<InsertionPoint>,
    /// `(point id, spec)` for every point, in the same order.
    pub specs: Vec<(String, PointSpec)>,
    /// The site-map node the whole conversation belongs to.
    pub node: SiteNode,
}

/// Whether the handshake's origin is one of the job target's origins.
///
/// Both sides are normalised the same way before comparing: `ws` becomes
/// `http` and `wss` becomes `https`, the scheme's default port is filled in
/// when the authority carries none, and the host is compared case-insensitively.
/// An origin string with no `://` matches nothing.
#[must_use]
pub fn origin_matches(handshake: &HttpFlow, origins: &[String]) -> bool {
    let request = &handshake.request;
    let target = canonical_origin(&request.scheme, &request.authority);
    origins
        .iter()
        .filter_map(|origin| parse_origin(origin))
        .any(|origin| origin == target)
}

/// What the observed value of a point looks like, in [`PointTrait`] enum order.
///
/// `Filename` is never inferred for a WebSocket point: nothing in a frame or a
/// handshake header names a file the way an HTTP path segment does.
#[must_use]
pub fn infer_traits(name: &str, value: &str) -> Vec<PointTrait> {
    let mut traits = Vec::new();
    if is_url(value) {
        traits.push(PointTrait::Url);
    }
    if value.parse::<f64>().is_ok_and(f64::is_finite) {
        traits.push(PointTrait::Number);
    }
    if is_email(value) {
        traits.push(PointTrait::Email);
    }
    if is_base64(value) {
        traits.push(PointTrait::Base64);
    }
    if is_json_container(value) {
        traits.push(PointTrait::Json);
    }
    if is_id(name, value) {
        traits.push(PointTrait::Id);
    }
    if is_secret_key(name) {
        traits.push(PointTrait::Session);
    }
    traits
}

/// The `example` a point carries for an observed `(name, value)` pair.
///
/// [`REDACTED`] when the name reads as a secret
/// ([`aitm_core::redact::is_secret_key`]) or `header` is set and the name is
/// `Cookie` or `Authorization`; otherwise [`aitm_core::redact::scrub_text`] of
/// the value, bounded to [`EXAMPLE_CHARS`] characters on a character boundary.
#[must_use]
pub fn redacted_example(name: &str, value: &str, header: bool) -> String {
    let secret_header = header
        && (name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("authorization"));
    if secret_header || is_secret_key(name) {
        return REDACTED.to_string();
    }
    scrub_text(value).chars().take(EXAMPLE_CHARS).collect()
}

/// Every insertion point and the site node of one captured conversation.
///
/// `handshake` must be the [`HttpFlow`] of `ws.handshake`; the caller (the lane)
/// resolves it from the flow store. Points are deduped per
/// `(kind, name, path)` across the conversation's frames: the first occurrence
/// wins and sets the spec's `frame_index`, and `frequency` counts the repeats.
pub fn discover_flow(ws: &WsFlow, handshake: &HttpFlow, ids: &mut IdGen) -> Discovered {
    let request = &handshake.request;
    let scheme = normalise_scheme(&request.scheme);
    let (host, port) = split_authority(&authority_with_port(&scheme, &request.authority), &scheme);
    let path_template = request
        .path
        .split('?')
        .next()
        .unwrap_or(&request.path)
        .to_string();
    let url = format!("{scheme}://{}{}", request.authority, request.path);
    let node_id = format!(
        "wsnode-{:08x}",
        digest(&[&scheme, &host, &port.to_string(), &path_template])
    );

    let mut drafts = Vec::new();

    // (1) Handshake request headers. Every header point is anchored to the
    // first client->server frame so a handshake check still replays the
    // authenticated conversation behind it (plan call 14).
    let first_client = ws
        .messages
        .iter()
        .position(|message| message.dir == WsDir::ClientToServer);
    for (name, value) in request.headers.iter() {
        if !header_is_point(name) {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        let mut traits = infer_traits(&lower, value);
        // A `Cookie` or `Authorization` point always carries session state,
        // whatever the value happens to look like (plan call 4).
        if is_session_header(&lower) && !traits.contains(&PointTrait::Session) {
            traits.push(PointTrait::Session);
        }
        drafts.push(Draft {
            kind: InsertionKind::WsHandshakeHeader,
            name: lower,
            path: None,
            example: Some(redacted_example(name, value, true)),
            traits,
            frame_index: first_client,
            locator: Locator::HandshakeHeader(name.to_string()),
        });
    }

    // (2) Client->server frames, in capture order.
    for (index, message) in ws.messages.iter().enumerate() {
        if message.dir != WsDir::ClientToServer {
            continue;
        }
        match message.opcode {
            WsOpcode::Text => drafts.extend(text_frame_drafts(&message.data, index)),
            WsOpcode::Binary => drafts.push(Draft {
                kind: InsertionKind::WsBinary,
                name: "binary".to_string(),
                path: None,
                example: None,
                traits: Vec::new(),
                frame_index: Some(index),
                locator: Locator::Binary,
            }),
            WsOpcode::Ping | WsOpcode::Pong | WsOpcode::Close => {}
        }
    }

    // (3) Dedupe per `(kind, name, path)`; first occurrence wins.
    let mut points: Vec<InsertionPoint> = Vec::new();
    let mut specs: Vec<(String, PointSpec)> = Vec::new();
    let mut seen: HashMap<(InsertionKind, String, Option<String>), usize> = HashMap::new();
    for draft in drafts {
        let key = (draft.kind, draft.name.clone(), draft.path.clone());
        if let Some(&at) = seen.get(&key) {
            if let Some(point) = points.get_mut(at) {
                point.frequency = point.frequency.saturating_add(1);
            }
            continue;
        }
        seen.insert(key, points.len());
        let id = ids.id(ws.id, &draft.locator, draft.kind);
        specs.push((
            id.clone(),
            PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: draft.frame_index,
                locator: draft.locator,
            },
        ));
        points.push(InsertionPoint {
            id,
            lane: LaneKind::Ws,
            kind: draft.kind,
            name: draft.name,
            path: draft.path,
            example: draft.example,
            flow: Some(FlowRef(ws.id)),
            site_node: Some(node_id.clone()),
            traits: draft.traits,
            frequency: 1,
            method: Some("GET".to_string()),
            url: Some(url.clone()),
        });
    }

    let node = SiteNode {
        id: node_id,
        method: "GET".to_string(),
        scheme,
        host,
        port,
        path_template,
        flows: vec![FlowRef(handshake.id), FlowRef(ws.id)],
        params: points
            .iter()
            .map(|point| ParamRef {
                kind: point.kind,
                name: point.name.clone(),
            })
            .collect(),
        auth: request.headers.has("cookie") || request.headers.has("authorization"),
        points: u32::try_from(points.len()).unwrap_or(u32::MAX),
        audited: false,
    };

    Discovered {
        points,
        specs,
        node,
    }
}

/// One candidate point before dedupe assigns it an id.
struct Draft {
    kind: InsertionKind,
    name: String,
    path: Option<String>,
    example: Option<String>,
    traits: Vec<PointTrait>,
    frame_index: Option<usize>,
    locator: Locator,
}

/// The points of one client->server text frame: JSON leaves when it parses as a
/// JSON object or array, form pairs when it is `key=value(&key=value)*`, else
/// the whole payload. A frame that is not valid UTF-8 is one whole-text point
/// with no example.
fn text_frame_drafts(data: &[u8], index: usize) -> Vec<Draft> {
    let Ok(text) = std::str::from_utf8(data) else {
        return vec![Draft {
            kind: InsertionKind::WsText,
            name: "text".to_string(),
            path: None,
            example: None,
            traits: Vec::new(),
            frame_index: Some(index),
            locator: Locator::WholeText,
        }];
    };

    if let Some(root) = parse_json_container(text) {
        return json_leaves(&root)
            .into_iter()
            .map(|leaf| Draft {
                kind: InsertionKind::WsJsonValue,
                example: Some(redacted_example(&leaf.name, &leaf.text, false)),
                traits: infer_traits(&leaf.name, &leaf.text),
                name: leaf.name,
                locator: Locator::JsonPath(leaf.path.clone()),
                path: Some(leaf.path),
                frame_index: Some(index),
            })
            .collect();
    }

    if let Some(pairs) = form_pairs(text) {
        return pairs
            .into_iter()
            .map(|(name, value)| Draft {
                kind: InsertionKind::WsFormParam,
                path: None,
                example: Some(redacted_example(&name, &value, false)),
                traits: infer_traits(&name, &value),
                locator: Locator::FormParam(name.clone()),
                name,
                frame_index: Some(index),
            })
            .collect();
    }

    vec![Draft {
        kind: InsertionKind::WsText,
        name: "text".to_string(),
        path: None,
        example: Some(redacted_example("text", text, false)),
        traits: infer_traits("text", text),
        frame_index: Some(index),
        locator: Locator::WholeText,
    }]
}

/// One leaf of a JSON frame: its dotted/bracket path, the last object key on
/// that path, and the leaf rendered as text.
struct JsonLeaf {
    path: String,
    name: String,
    text: String,
}

/// `text` as a JSON object or array, or `None` when it is anything else
/// (including a bare JSON scalar, which is not a container of insertion points).
fn parse_json_container(text: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    (value.is_object() || value.is_array()).then_some(value)
}

/// Every scalar leaf of `root`, depth first, in the order the parser holds it.
fn json_leaves(root: &serde_json::Value) -> Vec<JsonLeaf> {
    let mut out = Vec::new();
    collect_leaves(root, "", None, &mut out);
    out
}

/// Walk `value` at `path`, carrying the last object key seen on the way down.
fn collect_leaves(
    value: &serde_json::Value,
    path: &str,
    key: Option<&str>,
    out: &mut Vec<JsonLeaf>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (child_key, child) in map {
                let child_path = if path.is_empty() {
                    child_key.clone()
                } else {
                    format!("{path}.{child_key}")
                };
                collect_leaves(child, &child_path, Some(child_key), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (at, child) in items.iter().enumerate() {
                collect_leaves(child, &format!("{path}[{at}]"), key, out);
            }
        }
        leaf => out.push(JsonLeaf {
            // A leaf under no object key at all (an element of a root array) is
            // named after its own path, which is the only name it has.
            name: key.map_or_else(|| path.to_string(), ToString::to_string),
            path: path.to_string(),
            text: leaf_text(leaf),
        }),
    }
}

/// A scalar leaf as text: a JSON string contributes its characters, anything
/// else its compact JSON form (`42`, `true`, `null`).
fn leaf_text(leaf: &serde_json::Value) -> String {
    match leaf {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `text` as form-urlencoded pairs, or `None` when it is not that shape.
///
/// Every `&`-separated segment must carry a `=` with a non-empty name, so a
/// plain sentence or a half-encoded payload is left to the whole-text point
/// rather than silently read as one parameter.
fn form_pairs(text: &str) -> Option<Vec<(String, String)>> {
    if !text.contains('=') {
        return None;
    }
    let well_formed = text
        .split('&')
        .all(|segment| matches!(segment.split_once('='), Some((name, _)) if !name.is_empty()));
    if !well_formed {
        return None;
    }
    let pairs: Vec<(String, String)> = form_urlencoded::parse(text.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    (!pairs.is_empty()).then_some(pairs)
}

/// Whether a handshake request header becomes an insertion point.
fn header_is_point(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ALWAYS_POINT_HEADERS.contains(&lower.as_str()) || !SKIP_HEADERS.contains(&lower.as_str())
}

/// Whether a lowercase header name is one that carries session material.
fn is_session_header(lower: &str) -> bool {
    lower == "cookie" || lower == "authorization"
}

/// `ws` becomes `http` and `wss` becomes `https`; anything else is lowercased.
fn normalise_scheme(scheme: &str) -> String {
    let lower = scheme.to_ascii_lowercase();
    match lower.as_str() {
        "ws" => "http".to_string(),
        "wss" => "https".to_string(),
        _ => lower,
    }
}

/// `scheme://authority` with the scheme normalised, the default port filled in
/// and the authority lowercased: the one form two origins are compared in.
fn canonical_origin(scheme: &str, authority: &str) -> String {
    let scheme = normalise_scheme(scheme);
    let authority = authority_with_port(&scheme, authority).to_ascii_lowercase();
    format!("{scheme}://{authority}")
}

/// An operator-supplied origin string in [`canonical_origin`] form, or `None`
/// when it names no scheme or no authority.
fn parse_origin(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    Some(canonical_origin(scheme, authority))
}

/// Split an authority that already carries a port into `(host, port)`, looking
/// for the `:` after any closing bracket so an IPv6 literal survives.
fn split_authority(authority: &str, scheme: &str) -> (String, u16) {
    let after_brackets = authority.rfind(']').map_or(0, |at| at + 1);
    if let Some(colon) = authority
        .get(after_brackets..)
        .and_then(|rest| rest.rfind(':'))
    {
        let at = after_brackets + colon;
        if let (Some(host), Some(port)) = (authority.get(..at), authority.get(at + 1..)) {
            if let Ok(port) = port.parse::<u16>() {
                return (host.to_ascii_lowercase(), port);
            }
        }
    }
    (authority.to_ascii_lowercase(), default_port(scheme))
}

/// The low 32 bits of a [`DefaultHasher`] over `parts`, in order.
fn digest(parts: &[&str]) -> u32 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    // Truncation is the point: the id is 8 hex characters wide.
    #[allow(clippy::cast_possible_truncation)]
    {
        hasher.finish() as u32
    }
}

/// The stable token an insertion kind contributes to a point id.
fn kind_token(kind: InsertionKind) -> &'static str {
    match kind {
        InsertionKind::WsJsonValue => "ws_json_value",
        InsertionKind::WsText => "ws_text",
        InsertionKind::WsFormParam => "ws_form_param",
        InsertionKind::WsBinary => "ws_binary",
        InsertionKind::WsHandshakeHeader => "ws_handshake_header",
        _ => "other",
    }
}

/// The stable token a locator contributes to a point id.
fn locator_token(locator: &Locator) -> String {
    match locator {
        Locator::JsonPath(path) => format!("json:{path}"),
        Locator::FormParam(name) => format!("form:{name}"),
        Locator::WholeText => "text".to_string(),
        Locator::Binary => "binary".to_string(),
        Locator::HandshakeHeader(name) => format!("header:{}", name.to_ascii_lowercase()),
    }
}

/// A value that reads as a URL or an absolute path.
fn is_url(value: &str) -> bool {
    value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("ws://")
        || value.starts_with("wss://")
        || value.starts_with('/')
}

/// A value with an `@` and a `.` after it.
fn is_email(value: &str) -> bool {
    value
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

/// A value long enough, padded right and drawn only from the base64 alphabet.
fn is_base64(value: &str) -> bool {
    value.len() >= 16
        && value.len().is_multiple_of(4)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

/// A value that parses as a JSON object or array.
fn is_json_container(value: &str) -> bool {
    parse_json_container(value).is_some()
}

/// A name that ends in `id` (so `_id` too), or a value that is a UUID or is all
/// digits.
fn is_id(name: &str, value: &str) -> bool {
    name.to_ascii_lowercase().ends_with("id")
        || is_uuid(value)
        || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

/// A hyphenated 8-4-4-4-12 hexadecimal UUID.
fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, byte)| {
            if matches!(at, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::SystemTime;

    use aitm_core::{
        Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
        HttpVersion, InterceptState, WsDir, WsFlow, WsMessage, WsOpcode,
    };
    use aitm_scan_model::point::InsertionPoint;
    use aitm_scan_model::vocab::{InsertionKind, LaneKind, PointTrait};

    use crate::discover::{discover_flow, origin_matches, Discovered, IdGen};
    use crate::types::{Locator, PointSpec};

    fn peer() -> SocketAddr {
        "127.0.0.1:8080".parse().expect("fixture peer parses")
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: peer(),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::UNIX_EPOCH,
        }
    }

    /// The canonical captured handshake: `GET /ws` on `127.0.0.1:8080` carrying
    /// an `Origin`, a session `Cookie` and a subprotocol. Built here rather than
    /// taken from `testing.rs`, which task 2 owns.
    fn handshake_flow() -> HttpFlow {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("Host", "127.0.0.1:8080"),
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Version", "13"),
            ("Origin", "https://app.test"),
            ("Cookie", "sid=s3cr3t-cookie"),
            ("Sec-WebSocket-Protocol", "chat"),
            ("User-Agent", "fixture/1"),
        ] {
            headers.set(name, value);
        }

        let mut response_headers = HeaderMap::new();
        for (name, value) in [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("Sec-WebSocket-Protocol", "chat"),
        ] {
            response_headers.set(name, value);
        }

        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "127.0.0.1:8080".into(),
                path: "/ws".into(),
                version: HttpVersion::Http11,
                headers,
                body: Body::Empty,
                timestamp: SystemTime::UNIX_EPOCH,
            },
            response: Some(HttpResponse {
                status: 101,
                version: HttpVersion::Http11,
                headers: response_headers,
                trailers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::UNIX_EPOCH,
            }),
            client_conn: conn(),
            server_conn: Some(conn()),
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    fn message(dir: WsDir, opcode: WsOpcode, data: Vec<u8>) -> WsMessage {
        WsMessage {
            dir,
            opcode,
            data,
            timestamp: SystemTime::UNIX_EPOCH,
            injected: false,
        }
    }

    fn client_text(text: &str) -> WsMessage {
        message(
            WsDir::ClientToServer,
            WsOpcode::Text,
            text.as_bytes().into(),
        )
    }

    fn client_binary(bytes: Vec<u8>) -> WsMessage {
        message(WsDir::ClientToServer, WsOpcode::Binary, bytes)
    }

    fn server_text(text: &str) -> WsMessage {
        message(
            WsDir::ServerToClient,
            WsOpcode::Text,
            text.as_bytes().into(),
        )
    }

    fn ws_flow(handshake: &HttpFlow, messages: Vec<WsMessage>) -> WsFlow {
        WsFlow {
            id: FlowId::new(),
            handshake: handshake.id,
            messages,
            client_conn: conn(),
            server_conn: Some(conn()),
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// The canonical conversation: two client text frames and one server reply.
    fn fixture() -> (HttpFlow, WsFlow) {
        let handshake = handshake_flow();
        let ws = ws_flow(
            &handshake,
            vec![
                client_text(r#"{"type":"hello"}"#),
                client_text(r#"{"msg":"hi","user":"bob"}"#),
                server_text(r#"{"ok":true,"echo":"hi"}"#),
            ],
        );
        (handshake, ws)
    }

    /// `discover_flow` over one client text frame, for the single-frame cases.
    fn discover_one(frame: WsMessage) -> Discovered {
        let handshake = handshake_flow();
        let ws = ws_flow(&handshake, vec![frame]);
        discover_flow(&ws, &handshake, &mut IdGen::new("job-1"))
    }

    fn shapes(points: &[InsertionPoint]) -> Vec<(InsertionKind, &str, Option<&str>)> {
        points
            .iter()
            .map(|p| (p.kind, p.name.as_str(), p.path.as_deref()))
            .collect()
    }

    fn named<'a>(found: &'a Discovered, name: &str) -> &'a InsertionPoint {
        found
            .points
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("point {name} discovered"))
    }

    fn spec_of(found: &Discovered, point: &InsertionPoint) -> PointSpec {
        found
            .specs
            .iter()
            .find(|(id, _)| *id == point.id)
            .map(|(_, spec)| spec.clone())
            .expect("every point has a spec")
    }

    #[test]
    fn fixture_yields_expected_points() {
        let (handshake, ws) = fixture();
        let found = discover_flow(&ws, &handshake, &mut IdGen::new("job-1"));

        assert_eq!(
            shapes(&found.points),
            vec![
                (InsertionKind::WsHandshakeHeader, "origin", None),
                (InsertionKind::WsHandshakeHeader, "cookie", None),
                (
                    InsertionKind::WsHandshakeHeader,
                    "sec-websocket-protocol",
                    None
                ),
                (InsertionKind::WsJsonValue, "type", Some("type")),
                (InsertionKind::WsJsonValue, "msg", Some("msg")),
                (InsertionKind::WsJsonValue, "user", Some("user")),
            ]
        );
        assert_eq!(found.points.len(), 6);

        let cookie = named(&found, "cookie");
        assert_eq!(cookie.example.as_deref(), Some("<redacted>"));
        assert_eq!(cookie.traits, vec![PointTrait::Session]);
        assert_eq!(cookie.lane, LaneKind::Ws);
        assert_eq!(cookie.method.as_deref(), Some("GET"));
        assert_eq!(cookie.url.as_deref(), Some("http://127.0.0.1:8080/ws"));
        assert_eq!(cookie.site_node.as_deref(), Some(found.node.id.as_str()));
        assert_eq!(cookie.flow.map(|f| f.0), Some(ws.id));
        assert_eq!(
            spec_of(&found, cookie),
            PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(0),
                locator: Locator::HandshakeHeader("Cookie".into()),
            }
        );

        let origin = named(&found, "origin");
        assert_eq!(origin.example.as_deref(), Some("https://app.test"));
        assert_eq!(origin.traits, vec![PointTrait::Url]);

        let msg = named(&found, "msg");
        assert_eq!(msg.example.as_deref(), Some("hi"));
        assert_eq!(
            spec_of(&found, msg),
            PointSpec {
                ws_flow: ws.id,
                handshake: handshake.id,
                frame_index: Some(1),
                locator: Locator::JsonPath("msg".into()),
            }
        );

        assert_eq!(found.node.path_template, "/ws");
        assert_eq!(found.node.port, 8080);
        assert_eq!(found.node.host, "127.0.0.1");
        assert_eq!(found.node.scheme, "http");
        assert_eq!(found.node.method, "GET");
        assert!(found.node.auth);
        assert_eq!(found.node.points, 6);
        assert_eq!(found.node.params.len(), 6);
        assert!(!found.node.audited);
        assert_eq!(
            found.node.flows.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![handshake.id, ws.id]
        );
    }

    #[test]
    fn nested_json_paths_and_traits() {
        let found = discover_one(client_text(
            r#"{"user":{"id":42,"email":"a@b.c"},"tags":["x","y"],"token":"abc"}"#,
        ));

        let mut paths: Vec<&str> = found.points[found.points.len().saturating_sub(5)..]
            .iter()
            .map(|p| p.path.as_deref().expect("json points carry a path"))
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["tags[0]", "tags[1]", "token", "user.email", "user.id"]
        );

        let id = found
            .points
            .iter()
            .find(|p| p.path.as_deref() == Some("user.id"))
            .expect("user.id point");
        assert_eq!(id.name, "id");
        assert_eq!(id.traits, vec![PointTrait::Number, PointTrait::Id]);
        assert_eq!(id.example.as_deref(), Some("42"));

        let email = found
            .points
            .iter()
            .find(|p| p.path.as_deref() == Some("user.email"))
            .expect("user.email point");
        assert_eq!(email.traits, vec![PointTrait::Email]);

        let first_tag = found
            .points
            .iter()
            .find(|p| p.path.as_deref() == Some("tags[0]"))
            .expect("tags[0] point");
        assert_eq!(first_tag.name, "tags");

        let token = found
            .points
            .iter()
            .find(|p| p.path.as_deref() == Some("token"))
            .expect("token point");
        assert_eq!(token.example.as_deref(), Some("<redacted>"));
        assert!(token.traits.contains(&PointTrait::Session));
    }

    #[test]
    fn form_pairs_become_form_points() {
        let found = discover_one(client_text("a=1&b=hello"));
        let form: Vec<&InsertionPoint> = found
            .points
            .iter()
            .filter(|p| p.kind == InsertionKind::WsFormParam)
            .collect();

        assert_eq!(
            form.iter()
                .map(|p| (p.kind, p.name.as_str(), p.path.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (InsertionKind::WsFormParam, "a", None),
                (InsertionKind::WsFormParam, "b", None),
            ]
        );
        assert_eq!(form[0].traits, vec![PointTrait::Number, PointTrait::Id]);
        assert_eq!(form[1].traits, Vec::<PointTrait>::new());
        assert_eq!(
            spec_of(&found, form[1]).locator,
            Locator::FormParam("b".into())
        );
    }

    #[test]
    fn plain_text_is_one_point() {
        let found = discover_one(client_text("hello there"));
        let text: Vec<&InsertionPoint> = found
            .points
            .iter()
            .filter(|p| p.kind == InsertionKind::WsText)
            .collect();

        assert_eq!(text.len(), 1);
        assert_eq!(text[0].name, "text");
        assert_eq!(text[0].path, None);
        assert_eq!(text[0].example.as_deref(), Some("hello there"));
        assert_eq!(spec_of(&found, text[0]).locator, Locator::WholeText);
    }

    #[test]
    fn binary_frame_is_one_point() {
        let found = discover_one(client_binary(vec![0, 1, 2]));
        let binary: Vec<&InsertionPoint> = found
            .points
            .iter()
            .filter(|p| p.kind == InsertionKind::WsBinary)
            .collect();

        assert_eq!(binary.len(), 1);
        assert_eq!(binary[0].name, "binary");
        assert_eq!(binary[0].path, None);
        assert_eq!(binary[0].example, None);
        assert_eq!(spec_of(&found, binary[0]).locator, Locator::Binary);
    }

    #[test]
    fn repeats_count_frequency_and_keep_first_frame() {
        let handshake = handshake_flow();
        let ws = ws_flow(
            &handshake,
            vec![client_text(r#"{"msg":"a"}"#), client_text(r#"{"msg":"b"}"#)],
        );
        let found = discover_flow(&ws, &handshake, &mut IdGen::new("job-1"));

        let msg: Vec<&InsertionPoint> = found
            .points
            .iter()
            .filter(|p| p.kind == InsertionKind::WsJsonValue)
            .collect();
        assert_eq!(msg.len(), 1);
        assert_eq!(msg[0].name, "msg");
        assert_eq!(msg[0].frequency, 2);
        assert_eq!(msg[0].example.as_deref(), Some("a"));
        assert_eq!(spec_of(&found, msg[0]).frame_index, Some(0));
    }

    #[test]
    fn origin_matching_normalises_ports_and_schemes() {
        let handshake = handshake_flow();
        assert!(origin_matches(
            &handshake,
            &["http://127.0.0.1:8080".to_string()]
        ));
        assert!(!origin_matches(
            &handshake,
            &["http://127.0.0.1:8081".to_string()]
        ));

        let mut secure = handshake_flow();
        secure.request.scheme = "wss".into();
        secure.request.authority = "app.test".into();
        assert!(origin_matches(
            &secure,
            &["https://app.test:443".to_string()]
        ));
        assert!(origin_matches(&secure, &["https://APP.test".to_string()]));
        assert!(!origin_matches(&secure, &["http://app.test".to_string()]));
    }

    #[test]
    fn ids_are_stable_and_shaped() {
        let (handshake, ws) = fixture();
        let first = discover_flow(&ws, &handshake, &mut IdGen::new("job-1"));
        let second = discover_flow(&ws, &handshake, &mut IdGen::new("job-1"));

        let ids: Vec<&str> = first.points.iter().map(|p| p.id.as_str()).collect();
        let again: Vec<&str> = second.points.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, again);

        for id in &ids {
            let hex = id.strip_prefix("ws-").unwrap_or_else(|| panic!("{id}"));
            assert_eq!(hex.len(), 8, "{id}");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{id}"
            );
        }

        let mut distinct = ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), ids.len());
    }
}
