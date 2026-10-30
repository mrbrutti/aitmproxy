//! Sans-IO HTTP/1.1 state machine: a pure parser/encoder with no sockets.
//!
//! The driver (the HTTP module) feeds it bytes from either side with
//! [`HttpStateMachine::on_bytes`] and writes out whatever
//! [`HttpStateMachine::poll_outbound`] hands back. Bodies are never buffered
//! whole: each `Content-Length` slice or chunked-encoding chunk comes out as a
//! `*BodyChunk` event as soon as it is available. The machine handles one
//! exchange at a time; after `ResponseComplete` it is ready for the next request
//! on the same connection.

use std::fmt::Write as _;

use aitm_core::{Body, FlowId, HeaderMap, HttpRequest, HttpResponse, HttpVersion};
use anyhow::{anyhow, bail, Result};

/// Pure request/response parser+encoder. The core driver feeds it bytes and
/// pumps the bytes it wants to write; it never touches a socket itself.
pub trait HttpStateMachine: Send {
    /// Feed bytes read from one side; get back the protocol events they produced.
    fn on_bytes(&mut self, from: Side, buf: &[u8]) -> Result<Vec<HttpSansIoEvent>>;
    /// Bytes the machine wants written to a side (encoded request/response).
    fn poll_outbound(&mut self, to: Side) -> Option<Vec<u8>>;
}

/// Which peer bytes came from or go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// Fine-grained protocol events the module maps onto core `Event`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpSansIoEvent {
    RequestHeaders(FlowId),
    RequestBodyChunk {
        flow: FlowId,
        bytes: Vec<u8>,
    },
    RequestComplete(FlowId),
    ResponseHeaders(FlowId),
    ResponseBodyChunk {
        flow: FlowId,
        bytes: Vec<u8>,
    },
    ResponseComplete(FlowId),
    /// Hands off to `aitm-proto-ws`.
    Upgrade {
        flow: FlowId,
        protocol: String,
    },
}

/// Largest head (request/status line + headers) accepted before erroring.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest chunk-size line (hex size plus extensions) accepted.
const MAX_CHUNK_LINE_BYTES: usize = 1024;

/// How a message body is delimited on the wire.
#[derive(Debug, Clone, Copy)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// Where a chunked-encoding decoder is within the stream.
#[derive(Debug, Clone, Copy)]
enum ChunkPhase {
    /// Expecting `<hex-size>[;ext]\r\n`.
    Size,
    /// Inside chunk data with this many bytes still to come.
    Data(u64),
    /// Expecting the `\r\n` that closes a chunk's data.
    DataEnd,
    /// After the zero-size chunk: trailer lines until an empty one.
    Trailers,
}

/// What one side's reader is doing with incoming bytes.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Collecting a head.
    Head,
    /// In a `Content-Length` body with this many bytes left.
    Length(u64),
    /// In a chunked body.
    Chunked(ChunkPhase),
    /// Response body runs to connection close.
    UntilClose,
    /// Client only: request complete, response pending. The server reader
    /// parses a response head only while the client reader is here; server bytes
    /// that arrive in any other client phase are left unparsed in its buffer.
    Waiting,
    /// After a 101: bytes belong to the next protocol.
    Upgraded,
}

/// One side's receive buffer and parse phase.
struct Reader {
    buf: Vec<u8>,
    phase: Phase,
}

impl Reader {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            phase: Phase::Head,
        }
    }
}

/// What one decoding step produced.
enum Step {
    NeedMore,
    Data(Vec<u8>),
    Done,
}

/// How bytes queued for a side are framed on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutFraming {
    Raw,
    Chunked,
}

/// The HTTP/1.1 machine: one exchange at a time, keep-alive across exchanges.
pub struct Http1Machine {
    client: Reader,
    server: Reader,
    out_client: Vec<u8>,
    out_server: Vec<u8>,
    out_framing_client: OutFraming,
    out_framing_server: OutFraming,
    flow: Option<FlowId>,
    request: Option<HttpRequest>,
    response: Option<HttpResponse>,
    /// The `Upgrade:` protocol the current request asked for, if any.
    pending_upgrade: Option<String>,
    upgraded: bool,
}

impl Default for Http1Machine {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1Machine {
    /// A machine awaiting the first request.
    pub fn new() -> Self {
        Self {
            client: Reader::new(),
            server: Reader::new(),
            out_client: Vec::new(),
            out_server: Vec::new(),
            out_framing_client: OutFraming::Raw,
            out_framing_server: OutFraming::Raw,
            flow: None,
            request: None,
            response: None,
            pending_upgrade: None,
            upgraded: false,
        }
    }

    /// The flow id of the current (or most recent) exchange.
    pub fn flow(&self) -> Option<FlowId> {
        self.flow
    }

    /// The request head of the current exchange (body `Empty`; chunks come as
    /// events).
    pub fn request(&self) -> Option<&HttpRequest> {
        self.request.as_ref()
    }

    /// The response head of the current exchange, once parsed.
    pub fn response(&self) -> Option<&HttpResponse> {
        self.response.as_ref()
    }

    /// Whether a 101 completed and the connection now belongs to another protocol.
    pub fn is_upgraded(&self) -> bool {
        self.upgraded
    }

    /// Bytes received from `side` that this machine will not parse: anything
    /// after a 101 (the driver hands those to the next protocol), and server bytes
    /// that arrive while no request awaits a response, such as a second response
    /// in the same read as a completed one or the start of one nobody asked for
    /// (the driver decides what an unsolicited byte means).
    pub fn take_leftover(&mut self, side: Side) -> Vec<u8> {
        std::mem::take(&mut self.reader_mut(side).buf)
    }

    /// The peer on `from` closed its write side. Completes a close-delimited
    /// response body.
    pub fn on_eof(&mut self, from: Side) -> Vec<HttpSansIoEvent> {
        let mut events = Vec::new();
        if from == Side::Server {
            if let (Phase::UntilClose, Some(id)) = (self.server.phase, self.flow) {
                self.finish_response(id, &mut events);
            }
        }
        events
    }

    /// Queue an encoded request for the server. A buffered body is sent with a
    /// `Content-Length` matching its real length (replacing any stale framing
    /// headers a plugin left behind); a streamed body keeps the head's framing
    /// and is fed through [`Self::enqueue_body_chunk`].
    pub fn enqueue_request(&mut self, req: &HttpRequest) {
        let path = if req.path.is_empty() { "/" } else { &req.path };
        let first_line = format!("{} {} HTTP/1.1", req.method, path);
        let mut headers = req.headers.clone();
        headers.remove("proxy-connection");
        headers.remove("proxy-authorization");
        self.out_framing_server =
            encode_message(&first_line, &headers, &req.body, &mut self.out_server);
    }

    /// Queue an encoded response head (and buffered body, if any) for the client.
    pub fn enqueue_response(&mut self, resp: &HttpResponse) {
        let first_line = format!("HTTP/1.1 {} {}", resp.status, reason_phrase(resp.status));
        self.out_framing_client =
            encode_message(&first_line, &resp.headers, &resp.body, &mut self.out_client);
    }

    /// Queue a body slice for `to`, framed to match the head sent before it.
    pub fn enqueue_body_chunk(&mut self, to: Side, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let framing = self.out_framing(to);
        let out = self.out_mut(to);
        match framing {
            OutFraming::Chunked => {
                let mut size = String::new();
                // Writing to a String cannot fail.
                let _ = write!(size, "{:x}\r\n", bytes.len());
                out.extend_from_slice(size.as_bytes());
                out.extend_from_slice(bytes);
                out.extend_from_slice(b"\r\n");
            }
            OutFraming::Raw => out.extend_from_slice(bytes),
        }
    }

    /// Terminate a streamed body for `to` (the chunked terminator, if chunked).
    pub fn enqueue_body_end(&mut self, to: Side) {
        if self.out_framing(to) == OutFraming::Chunked {
            self.out_mut(to).extend_from_slice(b"0\r\n\r\n");
        }
        match to {
            Side::Client => self.out_framing_client = OutFraming::Raw,
            Side::Server => self.out_framing_server = OutFraming::Raw,
        }
    }

    fn reader_mut(&mut self, side: Side) -> &mut Reader {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    fn out_mut(&mut self, side: Side) -> &mut Vec<u8> {
        match side {
            Side::Client => &mut self.out_client,
            Side::Server => &mut self.out_server,
        }
    }

    fn out_framing(&self, side: Side) -> OutFraming {
        match side {
            Side::Client => self.out_framing_client,
            Side::Server => self.out_framing_server,
        }
    }

    fn on_client_bytes(&mut self, buf: &[u8]) -> Result<Vec<HttpSansIoEvent>> {
        self.client.buf.extend_from_slice(buf);
        let mut events = Vec::new();
        loop {
            match self.client.phase {
                Phase::Head => {
                    let Some(head) = take_head(&mut self.client.buf)? else {
                        break;
                    };
                    let req = parse_request(&head)?;
                    let id = FlowId::new();
                    self.flow = Some(id);
                    self.response = None;
                    self.upgraded = false;
                    self.pending_upgrade = upgrade_protocol(&req.headers);
                    let framing = request_framing(&req.headers)?;
                    self.request = Some(req);
                    events.push(HttpSansIoEvent::RequestHeaders(id));
                    match framing {
                        Framing::None | Framing::UntilClose => self.finish_request(id, &mut events),
                        Framing::Length(n) => self.client.phase = Phase::Length(n),
                        Framing::Chunked => self.client.phase = Phase::Chunked(ChunkPhase::Size),
                    }
                }
                Phase::Length(remaining) => {
                    let id = self.current_flow()?;
                    match step_length(&mut self.client.buf, remaining) {
                        Step::NeedMore => break,
                        Step::Data(bytes) => {
                            let left = remaining - bytes.len() as u64;
                            events.push(HttpSansIoEvent::RequestBodyChunk { flow: id, bytes });
                            if left == 0 {
                                self.finish_request(id, &mut events);
                            } else {
                                self.client.phase = Phase::Length(left);
                            }
                        }
                        Step::Done => self.finish_request(id, &mut events),
                    }
                }
                Phase::Chunked(phase) => {
                    let id = self.current_flow()?;
                    let mut phase = phase;
                    let step = step_chunked(&mut self.client.buf, &mut phase)?;
                    self.client.phase = Phase::Chunked(phase);
                    match step {
                        Step::NeedMore => break,
                        Step::Data(bytes) => {
                            events.push(HttpSansIoEvent::RequestBodyChunk { flow: id, bytes })
                        }
                        Step::Done => self.finish_request(id, &mut events),
                    }
                }
                // A request body never runs to close; anything else parks the
                // bytes until the exchange (or the connection) moves on.
                Phase::UntilClose | Phase::Waiting | Phase::Upgraded => break,
            }
        }
        Ok(events)
    }

    fn on_server_bytes(&mut self, buf: &[u8]) -> Result<Vec<HttpSansIoEvent>> {
        self.server.buf.extend_from_slice(buf);
        let mut events = Vec::new();
        loop {
            match self.server.phase {
                Phase::Head => {
                    let id = self.current_flow()?;
                    // A response head is parsed only while a request is complete
                    // and unanswered. Any other time the server has nothing
                    // legitimate to say, and parsing what it sent would attribute
                    // a stray response to an exchange that already finished
                    // (finish_response leaves the client reader in `Head`). Leave
                    // the bytes in the buffer for the driver to inspect through
                    // `take_leftover`, but never let them grow without bound.
                    if !matches!(self.client.phase, Phase::Waiting) {
                        if self.server.buf.len() > MAX_HEAD_BYTES {
                            bail!("unsolicited server bytes exceed {MAX_HEAD_BYTES} bytes");
                        }
                        break;
                    }
                    let Some(head) = take_head(&mut self.server.buf)? else {
                        break;
                    };
                    let resp = parse_response(&head)?;
                    let status = resp.status;
                    // Interim responses other than 101 carry nothing to capture.
                    if (100..200).contains(&status) && status != 101 {
                        continue;
                    }
                    let method = self
                        .request
                        .as_ref()
                        .map(|r| r.method.as_str())
                        .unwrap_or("");
                    let framing = response_framing(status, method, &resp.headers)?;
                    self.response = Some(resp);
                    events.push(HttpSansIoEvent::ResponseHeaders(id));
                    if status == 101 {
                        if self.pending_upgrade.is_none() {
                            bail!("101 Switching Protocols without an Upgrade request");
                        }
                        self.upgraded = true;
                        self.server.phase = Phase::Upgraded;
                        self.client.phase = Phase::Upgraded;
                        events.push(HttpSansIoEvent::ResponseComplete(id));
                        break;
                    }
                    match framing {
                        Framing::None => self.finish_response(id, &mut events),
                        Framing::Length(n) => self.server.phase = Phase::Length(n),
                        Framing::Chunked => self.server.phase = Phase::Chunked(ChunkPhase::Size),
                        Framing::UntilClose => self.server.phase = Phase::UntilClose,
                    }
                }
                Phase::Length(remaining) => {
                    let id = self.current_flow()?;
                    match step_length(&mut self.server.buf, remaining) {
                        Step::NeedMore => break,
                        Step::Data(bytes) => {
                            let left = remaining - bytes.len() as u64;
                            events.push(HttpSansIoEvent::ResponseBodyChunk { flow: id, bytes });
                            if left == 0 {
                                self.finish_response(id, &mut events);
                            } else {
                                self.server.phase = Phase::Length(left);
                            }
                        }
                        Step::Done => self.finish_response(id, &mut events),
                    }
                }
                Phase::Chunked(phase) => {
                    let id = self.current_flow()?;
                    let mut phase = phase;
                    let step = step_chunked(&mut self.server.buf, &mut phase)?;
                    self.server.phase = Phase::Chunked(phase);
                    match step {
                        Step::NeedMore => break,
                        Step::Data(bytes) => {
                            events.push(HttpSansIoEvent::ResponseBodyChunk { flow: id, bytes })
                        }
                        Step::Done => self.finish_response(id, &mut events),
                    }
                }
                Phase::UntilClose => {
                    let id = self.current_flow()?;
                    if !self.server.buf.is_empty() {
                        let bytes = std::mem::take(&mut self.server.buf);
                        events.push(HttpSansIoEvent::ResponseBodyChunk { flow: id, bytes });
                    }
                    break;
                }
                Phase::Waiting | Phase::Upgraded => break,
            }
        }
        Ok(events)
    }

    fn current_flow(&self) -> Result<FlowId> {
        self.flow
            .ok_or_else(|| anyhow!("message body or response bytes before any request"))
    }

    fn finish_request(&mut self, id: FlowId, events: &mut Vec<HttpSansIoEvent>) {
        self.client.phase = Phase::Waiting;
        events.push(HttpSansIoEvent::RequestComplete(id));
        if let Some(protocol) = self.pending_upgrade.clone() {
            events.push(HttpSansIoEvent::Upgrade { flow: id, protocol });
        }
    }

    fn finish_response(&mut self, id: FlowId, events: &mut Vec<HttpSansIoEvent>) {
        self.server.phase = Phase::Head;
        if matches!(self.client.phase, Phase::Waiting) {
            self.client.phase = Phase::Head;
        }
        self.pending_upgrade = None;
        events.push(HttpSansIoEvent::ResponseComplete(id));
    }

    /// Ready the machine for the next request after a plugin answered the
    /// current one without an upstream round-trip (a short circuit). There is
    /// no upstream response, so `finish_response` never runs; this performs the
    /// same client-side reset it would. Without it the client stays in
    /// `Phase::Waiting`, so a kept-alive connection never parses its next
    /// request and every further byte accumulates in the (then-uncapped)
    /// receive buffer — only `Phase::Head` enforces the head-size cap.
    pub fn short_circuit_done(&mut self) {
        if matches!(self.client.phase, Phase::Waiting) {
            self.client.phase = Phase::Head;
        }
        self.pending_upgrade = None;
    }
}

impl HttpStateMachine for Http1Machine {
    fn on_bytes(&mut self, from: Side, buf: &[u8]) -> Result<Vec<HttpSansIoEvent>> {
        match from {
            Side::Client => self.on_client_bytes(buf),
            Side::Server => self.on_server_bytes(buf),
        }
    }

    fn poll_outbound(&mut self, to: Side) -> Option<Vec<u8>> {
        let out = self.out_mut(to);
        if out.is_empty() {
            None
        } else {
            Some(std::mem::take(out))
        }
    }
}

/// Remove and return a complete head (without its blank-line terminator) from
/// the front of `buf`, or `None` if it is not all there yet.
fn take_head(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(end) => {
            let head: Vec<u8> = buf.drain(..end + 4).collect();
            Ok(Some(head[..end].to_vec()))
        }
        None if buf.len() > MAX_HEAD_BYTES => bail!("HTTP head exceeds {MAX_HEAD_BYTES} bytes"),
        None => Ok(None),
    }
}

/// Take up to `remaining` bytes of a `Content-Length` body from `buf`.
fn step_length(buf: &mut Vec<u8>, remaining: u64) -> Step {
    if remaining == 0 {
        return Step::Done;
    }
    if buf.is_empty() {
        return Step::NeedMore;
    }
    let take = usize::try_from(remaining)
        .map(|r| r.min(buf.len()))
        .unwrap_or(buf.len());
    Step::Data(buf.drain(..take).collect())
}

/// Advance a chunked-encoding decoder by one step over `buf`.
fn step_chunked(buf: &mut Vec<u8>, phase: &mut ChunkPhase) -> Result<Step> {
    match *phase {
        ChunkPhase::Size => {
            let Some(line) = take_line(buf, MAX_CHUNK_LINE_BYTES)? else {
                return Ok(Step::NeedMore);
            };
            let size = parse_chunk_size(&line)?;
            *phase = if size == 0 {
                ChunkPhase::Trailers
            } else {
                ChunkPhase::Data(size)
            };
            // Loop back to carry on with the data already buffered.
            step_chunked(buf, phase)
        }
        ChunkPhase::Data(remaining) => {
            if buf.is_empty() {
                return Ok(Step::NeedMore);
            }
            let take = usize::try_from(remaining)
                .map(|r| r.min(buf.len()))
                .unwrap_or(buf.len());
            let bytes: Vec<u8> = buf.drain(..take).collect();
            let left = remaining - take as u64;
            *phase = if left == 0 {
                ChunkPhase::DataEnd
            } else {
                ChunkPhase::Data(left)
            };
            Ok(Step::Data(bytes))
        }
        ChunkPhase::DataEnd => {
            if buf.len() < 2 {
                return Ok(Step::NeedMore);
            }
            if &buf[..2] != b"\r\n" {
                bail!("chunk data not followed by CRLF");
            }
            buf.drain(..2);
            *phase = ChunkPhase::Size;
            step_chunked(buf, phase)
        }
        ChunkPhase::Trailers => loop {
            let Some(line) = take_line(buf, MAX_HEAD_BYTES)? else {
                return Ok(Step::NeedMore);
            };
            if line.is_empty() {
                return Ok(Step::Done);
            }
            // Trailer fields are consumed and dropped.
        },
    }
}

/// Remove one CRLF-terminated line (without the CRLF) from the front of `buf`.
fn take_line(buf: &mut Vec<u8>, max: usize) -> Result<Option<Vec<u8>>> {
    match buf.windows(2).position(|w| w == b"\r\n") {
        Some(end) => {
            let line: Vec<u8> = buf.drain(..end + 2).collect();
            Ok(Some(line[..end].to_vec()))
        }
        None if buf.len() > max => bail!("line exceeds {max} bytes"),
        None => Ok(None),
    }
}

/// The hex size at the start of a chunk-size line; extensions after `;` ignored.
fn parse_chunk_size(line: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(line).map_err(|_| anyhow!("non-UTF-8 chunk size"))?;
    let size = text.split(';').next().unwrap_or("").trim();
    if size.is_empty() {
        bail!("empty chunk size");
    }
    if !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid chunk size {size:?}");
    }
    u64::from_str_radix(size, 16).map_err(|_| anyhow!("invalid chunk size {size:?}"))
}

/// Parse a request head: request line plus header fields.
fn parse_request(head: &[u8]) -> Result<HttpRequest> {
    let text = std::str::from_utf8(head).map_err(|_| anyhow!("non-UTF-8 request head"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("malformed request line {line:?}");
    };
    if method.is_empty() || target.is_empty() {
        bail!("malformed request line {line:?}");
    }
    if !version.starts_with("HTTP/1.") {
        bail!("unsupported HTTP version {version:?}");
    }
    let headers = parse_headers(lines)?;
    let (scheme, authority, path) = split_target(method, target, &headers);
    Ok(HttpRequest {
        method: method.to_string(),
        scheme,
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body: Body::Empty,
        timestamp: std::time::SystemTime::now(),
    })
}

/// Scheme, authority and path for a request target in origin, absolute or
/// authority form.
fn split_target(method: &str, target: &str, headers: &HeaderMap) -> (String, String, String) {
    let host = headers.get("host").unwrap_or("").to_string();
    if method.eq_ignore_ascii_case("CONNECT") {
        return ("https".to_string(), target.to_string(), String::new());
    }
    if target.starts_with('/') {
        return ("http".to_string(), host, target.to_string());
    }
    if let Some((scheme, rest)) = target.split_once("://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        return (scheme.to_string(), authority.to_string(), path.to_string());
    }
    ("http".to_string(), host, target.to_string())
}

/// Parse a response head: status line plus header fields.
fn parse_response(head: &[u8]) -> Result<HttpResponse> {
    let text = std::str::from_utf8(head).map_err(|_| anyhow!("non-UTF-8 response head"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or("");
    let Some((version, rest)) = line.split_once(' ') else {
        bail!("malformed status line {line:?}");
    };
    if !version.starts_with("HTTP/1.") {
        bail!("unsupported HTTP version {version:?}");
    }
    let code = rest.split(' ').next().unwrap_or("");
    let status: u16 = match code.parse() {
        Ok(s) if (100..600).contains(&s) && code.len() == 3 => s,
        _ => bail!("malformed status code {code:?}"),
    };
    let headers = parse_headers(lines)?;
    Ok(HttpResponse {
        status,
        version: HttpVersion::Http11,
        headers,
        body: Body::Empty,
        timestamp: std::time::SystemTime::now(),
    })
}

/// Parse `name: value` lines into a `HeaderMap`, keeping order and duplicates.
fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            bail!("malformed header line {line:?}");
        };
        let name = name.trim();
        if name.is_empty() || name.contains(' ') {
            bail!("malformed header name {name:?}");
        }
        // Fail closed on an invalid name/value (control byte, embedded CR/LF).
        // `set` would *drop* it silently; dropping a framing header such as
        // `Content-Length` desynchronises us from the peer (request smuggling).
        headers
            .try_set(name, value.trim())
            .map_err(|e| anyhow!("{e}"))?;
    }
    Ok(headers)
}

/// The protocol named by `Upgrade:` when `Connection:` lists `upgrade`.
fn upgrade_protocol(headers: &HeaderMap) -> Option<String> {
    let wants_upgrade = headers
        .get("connection")
        .map(|c| {
            c.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    if !wants_upgrade {
        return None;
    }
    headers
        .get("upgrade")
        .and_then(|u| u.split(',').next())
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
}

/// `Content-Length` as a number, if present and well-formed. More than one
/// header with *distinct* values is rejected: silently trusting the first is a
/// request/response-smuggling vector (RFC 7230 §3.3.3).
fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let parse = |v: &str| {
        let t = v.trim();
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
            bail!("invalid Content-Length {v:?}");
        }
        t.parse::<u64>()
            .map_err(|_| anyhow!("invalid Content-Length {v:?}"))
    };
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let n = parse(first)?;
    for v in values {
        if parse(v)? != n {
            bail!("conflicting Content-Length headers");
        }
    }
    Ok(Some(n))
}

/// Whether `Transfer-Encoding` ends in `chunked`. Any other coding is rejected.
fn is_chunked(headers: &HeaderMap) -> Result<bool> {
    match headers.get("transfer-encoding") {
        None => Ok(false),
        Some(te) => {
            let last = te.split(',').next_back().unwrap_or("").trim();
            if last.eq_ignore_ascii_case("chunked") {
                Ok(true)
            } else {
                bail!("unsupported Transfer-Encoding {te:?}")
            }
        }
    }
}

/// Body framing of a request: chunked, by length, or none. A message carrying
/// both `Transfer-Encoding` and `Content-Length` is rejected (RFC 7230 §3.3.3):
/// forwarding it lets the two ends disagree on the body boundary (smuggling).
fn request_framing(headers: &HeaderMap) -> Result<Framing> {
    let chunked = is_chunked(headers)?;
    let length = content_length(headers)?;
    if chunked && length.is_some() {
        bail!("both Transfer-Encoding and Content-Length present (RFC 7230 §3.3.3)");
    }
    if chunked {
        return Ok(Framing::Chunked);
    }
    Ok(match length {
        Some(0) | None => Framing::None,
        Some(n) => Framing::Length(n),
    })
}

/// Body framing of a response, given the request method and status.
fn response_framing(status: u16, method: &str, headers: &HeaderMap) -> Result<Framing> {
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || status == 101 {
        return Ok(Framing::None);
    }
    let chunked = is_chunked(headers)?;
    let length = content_length(headers)?;
    if chunked && length.is_some() {
        bail!("both Transfer-Encoding and Content-Length present (RFC 7230 §3.3.3)");
    }
    if chunked {
        return Ok(Framing::Chunked);
    }
    Ok(match length {
        Some(0) => Framing::None,
        Some(n) => Framing::Length(n),
        None => Framing::UntilClose,
    })
}

/// Encode a head (and a buffered body) onto `out`; returns how later chunks
/// for this message must be framed.
fn encode_message(
    first_line: &str,
    headers: &HeaderMap,
    body: &Body,
    out: &mut Vec<u8>,
) -> OutFraming {
    let mut headers = headers.clone();
    let had_transfer_encoding = headers.has("transfer-encoding");
    let (framing, buffered): (OutFraming, Option<&[u8]>) = match body {
        Body::Bytes(bytes) => {
            headers.remove("transfer-encoding");
            headers.remove("content-length");
            headers.set("Content-Length", &bytes.len().to_string());
            (OutFraming::Raw, Some(bytes))
        }
        Body::Empty => {
            headers.remove("transfer-encoding");
            if had_transfer_encoding {
                headers.remove("content-length");
                headers.set("Content-Length", "0");
            }
            (OutFraming::Raw, None)
        }
        Body::Streamed(_) => {
            // A streamed body keeps the head's own framing, but the header map
            // must still carry exactly one coding, or a downstream parser can be
            // desynchronised (response smuggling). When we frame chunked, drop any
            // `Content-Length` and collapse to a single `Transfer-Encoding: chunked`;
            // when we frame by length (or close), drop `Transfer-Encoding`.
            if is_chunked(&headers).unwrap_or(false) {
                headers.remove("content-length");
                // Preserve the full coding list (it already ends in `chunked`, per
                // `is_chunked`); only collapse duplicate `Transfer-Encoding` headers
                // to the single canonical value, so a transfer-coding such as
                // `gzip, chunked` is not silently dropped and left framed as plain
                // chunked over still-compressed bytes.
                let te = headers
                    .get("transfer-encoding")
                    .map(|v| v.trim().to_string())
                    .unwrap_or_else(|| "chunked".to_string());
                headers.remove("transfer-encoding");
                headers.set("Transfer-Encoding", &te);
                (OutFraming::Chunked, None)
            } else {
                headers.remove("transfer-encoding");
                (OutFraming::Raw, None)
            }
        }
    };
    out.extend_from_slice(first_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers.iter() {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if let Some(bytes) = buffered {
        out.extend_from_slice(bytes);
    }
    framing
}

/// Canonical reason phrase for a status (the model does not keep the wire one).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        // An unknown code still gets a non-empty, class-appropriate phrase rather
        // than a bare status line a strict client might reject.
        _ => match status {
            100..=199 => "Informational",
            200..=299 => "OK",
            300..=399 => "Redirection",
            400..=499 => "Client Error",
            500..=599 => "Server Error",
            _ => "Unknown Status",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::StreamBody;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.set(k, v);
        }
        h
    }

    fn header_lines(out: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(out)
            .split("\r\n")
            .take_while(|l| !l.is_empty())
            .skip(1) // the first line is the status/request line
            .map(|l| l.to_ascii_lowercase())
            .collect()
    }

    #[test]
    fn streamed_chunked_egress_drops_competing_content_length() {
        // A response head carrying BOTH Content-Length and Transfer-Encoding:
        // chunked, with a streamed body framed chunked, must go out with exactly
        // one framing header (I9: response smuggling otherwise).
        let h = headers(&[("Content-Length", "100"), ("Transfer-Encoding", "chunked")]);
        let mut out = Vec::new();
        let framing = encode_message("HTTP/1.1 200 OK", &h, &Body::Streamed(StreamBody), &mut out);
        assert_eq!(framing, OutFraming::Chunked);
        let lines = header_lines(&out);
        assert!(
            !lines.iter().any(|l| l.starts_with("content-length")),
            "Content-Length must be stripped when framing chunked, got {lines:?}"
        );
        let te: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("transfer-encoding"))
            .collect();
        assert_eq!(
            te,
            vec![&"transfer-encoding: chunked".to_string()],
            "exactly one Transfer-Encoding: chunked expected, got {lines:?}"
        );
    }

    #[test]
    fn streamed_chunked_egress_preserves_non_chunked_codings() {
        // `Transfer-Encoding: gzip, chunked` must survive intact when framing a
        // streamed chunked body: de-chunking does not un-gzip, so collapsing to
        // bare `chunked` would leave the client framed-plain over gzipped bytes.
        let h = headers(&[("Transfer-Encoding", "gzip, chunked")]);
        let mut out = Vec::new();
        let framing = encode_message("HTTP/1.1 200 OK", &h, &Body::Streamed(StreamBody), &mut out);
        assert_eq!(framing, OutFraming::Chunked);
        let te: Vec<_> = header_lines(&out)
            .into_iter()
            .filter(|l| l.starts_with("transfer-encoding"))
            .collect();
        assert_eq!(
            te,
            vec!["transfer-encoding: gzip, chunked".to_string()],
            "the gzip coding must be preserved, not collapsed to bare chunked"
        );
    }

    #[test]
    fn streamed_length_egress_drops_transfer_encoding() {
        // Framed by length: Transfer-Encoding must go, Content-Length stays.
        let h = headers(&[
            ("Content-Length", "100"),
            ("Transfer-Encoding", "gzip"), // not chunked -> length framing
        ]);
        let mut out = Vec::new();
        let framing = encode_message("HTTP/1.1 200 OK", &h, &Body::Streamed(StreamBody), &mut out);
        assert_eq!(framing, OutFraming::Raw);
        let lines = header_lines(&out);
        assert!(
            !lines.iter().any(|l| l.starts_with("transfer-encoding")),
            "Transfer-Encoding must be stripped when framing by length, got {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l == "content-length: 100"),
            "Content-Length must be kept, got {lines:?}"
        );
    }

    #[test]
    fn conflicting_content_length_is_rejected() {
        let h = headers(&[("Content-Length", "10"), ("Content-Length", "20")]);
        assert!(
            content_length(&h).is_err(),
            "distinct CL values must be rejected"
        );
        // Identical duplicates are not a conflict.
        let same = headers(&[("Content-Length", "10"), ("Content-Length", "10")]);
        assert_eq!(content_length(&same).unwrap(), Some(10));
    }

    #[test]
    fn content_length_with_transfer_encoding_is_rejected() {
        let h = headers(&[("Content-Length", "10"), ("Transfer-Encoding", "chunked")]);
        assert!(
            request_framing(&h).is_err(),
            "CL + TE on a request must be rejected (RFC 7230 §3.3.3)"
        );
        assert!(
            response_framing(200, "GET", &h).is_err(),
            "CL + TE on a response must be rejected (RFC 7230 §3.3.3)"
        );
    }

    #[test]
    fn short_circuit_resets_for_the_next_keep_alive_request() {
        // A plugin answers a request without an upstream round-trip (short
        // circuit): `finish_request` left the client in `Phase::Waiting`, and
        // only `finish_response` resets it to `Head`. Without a reset the next
        // request on a kept-alive connection is never parsed and every further
        // byte piles into `client.buf` unbounded (only `Phase::Head` is
        // head-size-capped). `short_circuit_done` must ready the machine so the
        // second request parses.
        let mut m = Http1Machine::new();
        let ev = m
            .on_bytes(Side::Client, b"GET /mock HTTP/1.1\r\nHost: t\r\n\r\n")
            .unwrap();
        assert!(
            ev.iter()
                .any(|e| matches!(e, HttpSansIoEvent::RequestComplete(_))),
            "first request should complete"
        );
        // The plugin's short-circuit response path in module.rs.
        m.enqueue_response(&HttpResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: Body::Empty,
            version: HttpVersion::Http11,
            timestamp: std::time::SystemTime::now(),
        });
        m.short_circuit_done();

        let ev2 = m
            .on_bytes(Side::Client, b"GET /next HTTP/1.1\r\nHost: t\r\n\r\n")
            .unwrap();
        assert!(
            ev2.iter()
                .any(|e| matches!(e, HttpSansIoEvent::RequestHeaders(_))),
            "a second keep-alive request after a short circuit must parse, got {ev2:?}"
        );
    }

    #[test]
    fn content_length_rejects_a_leading_plus() {
        // Rust's integer parse accepts a leading '+' (`"+5".parse::<u64>() == 5`),
        // which is not a valid RFC 7230 `1*DIGIT`. Reject it rather than diverge
        // from stricter peers.
        let h = headers(&[("Content-Length", "+5")]);
        assert!(
            content_length(&h).is_err(),
            "Content-Length with a leading '+' must be rejected"
        );
        let ok = headers(&[("Content-Length", "5")]);
        assert_eq!(content_length(&ok).unwrap(), Some(5));
    }

    #[test]
    fn chunk_size_rejects_a_leading_plus() {
        assert!(
            parse_chunk_size(b"+a").is_err(),
            "a chunk-size with a leading '+' must be rejected"
        );
        assert_eq!(parse_chunk_size(b"a").unwrap(), 10);
    }

    #[test]
    fn unknown_status_gets_a_class_phrase() {
        assert_eq!(reason_phrase(299), "OK");
        assert_eq!(reason_phrase(499), "Client Error");
        assert_eq!(reason_phrase(599), "Server Error");
        assert_eq!(reason_phrase(799), "Unknown Status");
        assert!(!reason_phrase(218).is_empty());
    }
}
