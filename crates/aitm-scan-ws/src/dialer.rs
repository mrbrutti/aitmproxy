//! The `WsDialer`: header replay rule, guard + semaphore, frame I/O, replay flows — written by task 6 of the T4 plan.
//!
//! One dialer is owned by the lane and one by the `ws.*` language (plan call
//! 23); each holds a [`MAX_CONNECTIONS`]-permit semaphore, so a lane's probe
//! hosts share four connections however many of them there are. Every dial is
//! gated by [`ScopeRateGuard::check_active`] on the handshake authority
//! *before* a socket is opened, and the resulting `ActionPermit` is held for
//! the connection's life (spec D8.3, plan call 2).
//!
//! Nothing here logs a header value or a frame payload: `tracing` lines carry
//! an authority, a frame kind and a byte length, and [`DialError`] carries the
//! transport's own text, never a header.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::guard::ActionPermit;
use aitm_core::{
    Body, ByteStream, ConnInfo, FlowId, FlowMeta, GuardError, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, ScopeRateGuard, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_scan_model::{Frame, FrameKind, WsOptions};
use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout_at;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::generate_request;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::transport::WsTransport;
use crate::types::{authority_with_port, default_port, HandshakeOverrides, MAX_CONNECTIONS};

/// Handshake request headers the dialer regenerates instead of replaying.
///
/// `Host`, `Connection`, `Upgrade` and `Sec-WebSocket-Version` are written by
/// tungstenite for the connection actually being made; `Sec-WebSocket-Key` is a
/// fresh nonce per dial (replaying the captured one would make the server's
/// `Sec-WebSocket-Accept` meaningless); `Sec-WebSocket-Accept` is a *response*
/// header and is never sent by a client (spec D8.3).
pub const REGENERATED_HEADERS: [&str; 6] = [
    "host",
    "connection",
    "upgrade",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-accept",
];

/// How long [`WsConn::close`] waits for the peer's Close before giving up.
const CLOSE_REPLY_WINDOW: Duration = Duration::from_millis(200);

/// How often [`WsConn::collect`] checks cancellation while waiting for frames.
const CANCEL_POLL: Duration = Duration::from_millis(50);

/// The largest upgrade-response head the dialer will read, in bytes.
///
/// A server that has not finished its head in 16 KiB is answering something
/// other than an upgrade; the read stops rather than buffering without bound.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// How many response headers the upgrade parser will accept (call 28).
const MAX_HEAD_HEADERS: usize = 64;

/// Whether `name` is a header the dialer writes itself.
fn is_regenerated(name: &str) -> bool {
    REGENERATED_HEADERS
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}

/// The WebSocket scheme a captured handshake's scheme implies.
fn ws_scheme(scheme: &str) -> &'static str {
    if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
        "wss"
    } else {
        "ws"
    }
}

/// `name` as an HTTP header name, or an error naming it.
fn header_name(name: &str) -> anyhow::Result<HeaderName> {
    HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("{name} is not a valid header name"))
}

/// `value` as an HTTP header value; the error names the header, never the value.
fn header_value(name: &str, value: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|_| anyhow!("the value of header {name} cannot be sent on the wire"))
}

/// The upgrade request that replays `handshake` with `overrides` applied.
///
/// Everything the capture sent is replayed — `Cookie`, `Origin`,
/// `Authorization`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions` and
/// any custom header — except [`REGENERATED_HEADERS`], which tungstenite writes
/// for this connection (including a fresh `Sec-WebSocket-Key`). `overrides` are
/// then applied: `strip` removes a header, `set` replaces or adds one. Naming a
/// regenerated header in either list is an error, so no check can make the
/// dialer re-send a stale key or lie about the host.
///
/// # Errors
///
/// When the captured authority and path do not form a URL, when a captured
/// header cannot be put on the wire, or when an override names a regenerated
/// header.
pub fn build_request(
    handshake: &HttpFlow,
    overrides: &HandshakeOverrides,
) -> anyhow::Result<Request<()>> {
    let captured = &handshake.request;
    let scheme = ws_scheme(&captured.scheme);
    let path = if captured.path.is_empty() {
        "/"
    } else {
        &captured.path
    };
    let url = format!("{scheme}://{}{path}", captured.authority);
    let mut request = url
        .as_str()
        .into_client_request()
        .with_context(|| format!("building an upgrade request for {url}"))?;

    let headers = request.headers_mut();
    for (name, value) in captured.headers.iter() {
        if is_regenerated(name) {
            continue;
        }
        // `append`, not `insert`: a capture may carry the same header twice
        // (two `Cookie` lines) and the replay must be what was captured.
        headers.append(header_name(name)?, header_value(name, value)?);
    }
    for name in &overrides.strip {
        if is_regenerated(name) {
            bail!("{name} is regenerated for every dial and cannot be overridden");
        }
        headers.remove(header_name(name)?);
    }
    for (name, value) in &overrides.set {
        if is_regenerated(name) {
            bail!("{name} is regenerated for every dial and cannot be overridden");
        }
        headers.insert(header_name(name)?, header_value(name, value)?);
    }
    Ok(request)
}

/// Per-dial protocol limits.
///
/// The frame/message cap is a property of the *job* profile
/// (`ScanProfile.ws.max_frame_bytes`) while a [`WsDialer`] is shared by every
/// probe host of a lane, so the cap travels with each dial rather than being
/// baked into the dialer (plan call 26).
#[derive(Debug, Clone, Copy)]
pub struct DialLimits {
    /// The largest frame and message this connection will read or write.
    pub max_frame_bytes: usize,
}

impl Default for DialLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: WsOptions::default().max_frame_bytes as usize,
        }
    }
}

/// What a dial got: an open connection, or a server that refused the upgrade.
///
/// A non-101 answer is **data, not an error** (plan call 18): the handshake
/// checks read a 401 or 403 straight off it.
// `Upgraded` is much larger than `Refused` because it owns the live stream and
// both permits. Boxing it would add an allocation to every successful dial (the
// common path) to shrink the rare refusal; the plan fixes this shape.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum DialOutcome {
    /// The upgrade completed; the conversation can start.
    Upgraded(WsConn),
    /// The server answered the upgrade with this status and these headers.
    Refused {
        /// The HTTP status the server answered with.
        status: u16,
        /// The response headers, lowercase names, in order.
        headers: Vec<(String, String)>,
    },
}

/// Why a dial could not be made at all.
///
/// A refused *upgrade* is not here — see [`DialOutcome::Refused`]. `Connect`
/// and `Handshake` carry the underlying error's text, which is a socket or
/// protocol message and never a header value.
#[derive(Debug)]
pub enum DialError {
    /// The scope/rate guard refused the authority.
    Guard(GuardError),
    /// The job deadline passed while waiting for a slot, a socket or the
    /// handshake.
    Timeout,
    /// The TCP or TLS connection could not be made.
    Connect(String),
    /// The WebSocket handshake itself failed.
    Handshake(String),
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::Guard(err) => write!(f, "guard refused the dial: {err}"),
            DialError::Timeout => write!(f, "the deadline passed before the dial completed"),
            DialError::Connect(text) => write!(f, "connect failed: {text}"),
            DialError::Handshake(text) => write!(f, "websocket handshake failed: {text}"),
        }
    }
}

impl std::error::Error for DialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DialError::Guard(err) => Some(err),
            _ => None,
        }
    }
}

/// The direct WebSocket client the lane and the `ws.*` language dial through.
///
/// It never goes through the proxy listener: the transport is a real TCP (and,
/// for `wss`, TLS) socket in production and a duplex pair under test. The
/// semaphore bounds *this dialer* at [`MAX_CONNECTIONS`] open connections; a
/// permit is held by the returned [`WsConn`] and released when it drops.
pub struct WsDialer {
    transport: Arc<dyn WsTransport>,
    slots: Arc<Semaphore>,
}

impl WsDialer {
    /// A dialer over `transport` with [`MAX_CONNECTIONS`] free slots.
    #[must_use]
    pub fn new(transport: Arc<dyn WsTransport>) -> Self {
        Self {
            transport,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    /// How many more connections this dialer will open before it makes a caller
    /// wait.
    #[must_use]
    pub fn slots_available(&self) -> usize {
        self.slots.available_permits()
    }

    /// Replay `handshake` (with `overrides`) and open the conversation.
    ///
    /// # Errors
    ///
    /// [`DialError::Guard`] when the authority is out of scope, rate limited
    /// past the deadline or otherwise refused; [`DialError::Timeout`],
    /// [`DialError::Connect`] or [`DialError::Handshake`] when the dial itself
    /// fails. A non-101 answer is `Ok(`[`DialOutcome::Refused`]`)`.
    pub async fn dial(
        &self,
        handshake: &HttpFlow,
        overrides: &HandshakeOverrides,
        guard: &dyn ScopeRateGuard,
        deadline: Instant,
        limits: DialLimits,
    ) -> Result<DialOutcome, DialError> {
        let request = build_request(handshake, overrides)
            .map_err(|err| DialError::Handshake(err.to_string()))?;
        self.dial_request(request, guard, deadline, limits).await
    }

    /// Dial a request built elsewhere (the `ws.*` language builds its own).
    ///
    /// The order is fixed and load-bearing: guard first (no socket is opened
    /// for an authority the operator did not put in scope), then a connection
    /// slot, then the socket, then the handshake — each bounded by `deadline`.
    ///
    /// # Errors
    ///
    /// As [`WsDialer::dial`].
    pub async fn dial_request(
        &self,
        request: Request<()>,
        guard: &dyn ScopeRateGuard,
        deadline: Instant,
        limits: DialLimits,
    ) -> Result<DialOutcome, DialError> {
        let uri = request.uri().clone();
        let scheme = uri.scheme_str().unwrap_or("ws").to_ascii_lowercase();
        let tls = scheme == "wss";
        let host = uri
            .host()
            .ok_or_else(|| DialError::Connect("the upgrade request has no host".to_string()))?;
        let port = uri.port_u16().unwrap_or_else(|| default_port(&scheme));
        let authority = match uri.port_u16() {
            Some(port) => format!("{host}:{port}"),
            None => authority_with_port(&scheme, host),
        };
        // `http` keeps an IPv6 literal in its brackets; a socket wants it bare.
        let dial_host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();

        let permit = check_authority(guard, &authority, deadline).await?;

        let until = tokio::time::Instant::from_std(deadline);
        let slot = match timeout_at(until, Arc::clone(&self.slots).acquire_owned()).await {
            Ok(Ok(slot)) => slot,
            Ok(Err(_closed)) => {
                return Err(DialError::Connect(
                    "the dialer's connection semaphore is closed".to_string(),
                ))
            }
            Err(_elapsed) => return Err(DialError::Timeout),
        };

        tracing::debug!(authority = %authority, tls, "ws dial");
        let stream = match timeout_at(
            until,
            self.transport.connect(&dial_host, port, tls, &dial_host),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(DialError::Connect(err.to_string())),
            Err(_elapsed) => return Err(DialError::Timeout),
        };

        let sent = RequestRecord::capture(&request, tls, &authority);
        let config = WebSocketConfig::default()
            .max_frame_size(Some(limits.max_frame_bytes))
            .max_message_size(Some(limits.max_frame_bytes));

        // The upgrade is driven here rather than by `client_async_with_config`
        // (plan call 28): tungstenite's client verification fails a handshake
        // whose 101 does not echo the requested subprotocol, echoes an
        // unrequested one, or echoes a different one — all three are server
        // behaviours this scanner has to *observe* (`ws-subprotocol-observe`),
        // and the replay keeps the captured `Sec-WebSocket-Protocol` (D8.3).
        let (head, key) =
            generate_request(request).map_err(|err| DialError::Handshake(err.to_string()))?;
        let (stream, buffered, head_end) =
            match timeout_at(until, exchange_head(stream, head)).await {
                Ok(Ok(exchanged)) => exchanged,
                Ok(Err(err)) => return Err(err),
                Err(_elapsed) => return Err(DialError::Timeout),
            };

        let mut parsed = [httparse::EMPTY_HEADER; MAX_HEAD_HEADERS];
        let mut response = httparse::Response::new(&mut parsed);
        match response.parse(&buffered[..head_end]) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => {
                return Err(DialError::Handshake(
                    "the upgrade response head is incomplete".to_string(),
                ))
            }
            Err(err) => {
                return Err(DialError::Handshake(format!(
                    "the upgrade response head is malformed: {err}"
                )))
            }
        }
        let status = response.code.ok_or_else(|| {
            DialError::Handshake("the upgrade response carries no status".to_string())
        })?;
        let response_headers: Vec<(String, String)> = response
            .headers
            .iter()
            .map(|header| {
                (
                    header.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(header.value).trim().to_string(),
                )
            })
            .collect();

        if status != 101 {
            tracing::debug!(authority = %authority, status, "ws upgrade refused");
            return Ok(DialOutcome::Refused {
                status,
                headers: response_headers,
            });
        }
        // `Sec-WebSocket-Accept` is the one thing the dialer does enforce: it
        // proves the peer answered *this* dial's fresh key. `Upgrade`,
        // `Connection` and the subprotocol are recorded, not enforced, so a
        // sloppy or hostile server stays observable instead of unreachable.
        let expected = derive_accept_key(key.as_bytes());
        let accepted = header_of(&response_headers, "sec-websocket-accept");
        if accepted != Some(expected.as_str()) {
            return Err(DialError::Handshake(
                "the 101 carries no matching Sec-WebSocket-Accept for this dial's key".to_string(),
            ));
        }

        let after_head = buffered[head_end..].to_vec();
        tracing::debug!(
            authority = %authority,
            status,
            buffered = after_head.len(),
            "ws upgrade"
        );
        // Bytes the server sent after the head are handed to the protocol state
        // machine, so a frame that arrived with the 101 is not lost.
        let stream =
            WebSocketStream::from_partially_read(stream, after_head, Role::Client, Some(config))
                .await;
        Ok(DialOutcome::Upgraded(WsConn {
            stream,
            request: sent,
            status,
            response_headers,
            peer: peer_of(&authority, port),
            tls,
            sni: tls.then(|| dial_host.clone()),
            opened: SystemTime::now(),
            started: Instant::now(),
            recorded: Vec::new(),
            _permit: permit,
            _slot: slot,
        }))
    }
}

/// Write the upgrade request and read the response head off `stream`.
///
/// Returns the stream, everything read so far (the head and whatever the server
/// sent after it) and the index one past the head's `\r\n\r\n`. The read is
/// bounded at [`MAX_HEAD_BYTES`] so a server that never ends its head cannot
/// make the dialer buffer without bound.
async fn exchange_head(
    mut stream: ByteStream,
    head: Vec<u8>,
) -> Result<(ByteStream, Vec<u8>, usize), DialError> {
    stream
        .write_all(&head)
        .await
        .map_err(|err| DialError::Connect(err.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|err| DialError::Connect(err.to_string()))?;

    let mut buffered: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    // Where the next scan starts: everything before it has been searched, less
    // the three bytes a `\r\n\r\n` straddling two reads could start in.
    let mut scanned = 0usize;
    loop {
        if let Some(end) = head_end(&buffered, scanned) {
            return Ok((stream, buffered, end));
        }
        scanned = buffered.len().saturating_sub(3);
        if buffered.len() >= MAX_HEAD_BYTES {
            return Err(DialError::Handshake(format!(
                "the upgrade response head exceeded {MAX_HEAD_BYTES} bytes"
            )));
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|err| DialError::Connect(err.to_string()))?;
        if read == 0 {
            return Err(DialError::Handshake(
                "the server closed before finishing the upgrade response head".to_string(),
            ));
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

/// One past the end of the `\r\n\r\n` that ends a head, searching from `from`.
fn head_end(buffered: &[u8], from: usize) -> Option<usize> {
    if buffered.len() < 4 {
        return None;
    }
    buffered
        .get(from..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| from + at + 4)
}

/// The value of the first header named `name` (names are already lowercase).
fn header_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// Pass `authority` through the guard, waiting out one rate limit if it fits.
///
/// A `RateLimited` longer than the time left is returned at once rather than
/// slept on (plan call 27); within the deadline it is slept once and retried
/// once, and a second refusal is final.
async fn check_authority(
    guard: &dyn ScopeRateGuard,
    authority: &str,
    deadline: Instant,
) -> Result<ActionPermit, DialError> {
    match guard.check_active(authority) {
        Ok(permit) => Ok(permit),
        Err(GuardError::RateLimited { retry_after }) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if retry_after > left {
                return Err(DialError::Guard(GuardError::RateLimited { retry_after }));
            }
            tracing::debug!(authority, "ws dial waiting out a rate limit");
            tokio::time::sleep(retry_after).await;
            guard.check_active(authority).map_err(DialError::Guard)
        }
        Err(err) => Err(DialError::Guard(err)),
    }
}

/// The peer address to record for `authority`.
///
/// A literal `host:port` is the real peer; a DNS name has no address here (the
/// transport owns resolution), so the port is recorded against the unspecified
/// address rather than inventing one.
fn peer_of(authority: &str, port: u16) -> SocketAddr {
    authority
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)))
}

/// The upgrade request as it went out, kept for the replay flow.
struct RequestRecord {
    scheme: &'static str,
    authority: String,
    path: String,
    headers: HeaderMap,
}

impl RequestRecord {
    /// Snapshot `request` before tungstenite consumes it.
    fn capture(request: &Request<()>, tls: bool, authority: &str) -> Self {
        let mut headers = HeaderMap::new();
        for (name, value) in request.headers() {
            headers.set(name.as_str(), &String::from_utf8_lossy(value.as_bytes()));
        }
        Self {
            // A WebSocket flow is recorded under the HTTP scheme of its
            // upgrade, the way a captured handshake is (`ws` -> `http`).
            scheme: if tls { "https" } else { "http" },
            authority: authority.to_string(),
            path: request
                .uri()
                .path_and_query()
                .map_or_else(|| "/".to_string(), |path| path.as_str().to_string()),
            headers,
        }
    }
}

/// One frame of the recorded conversation, with its direction and time.
struct Recorded {
    dir: WsDir,
    frame: Frame,
    at: SystemTime,
}

/// Why [`WsConn::collect`] stopped reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectEnd {
    /// The reply window elapsed.
    Window,
    /// The peer sent a Close frame.
    Close {
        /// The close code, when the frame carried one.
        code: Option<u16>,
    },
    /// The stream ended or errored. Not a failure: a server that drops the
    /// connection instead of closing it is itself an observation (plan call 18).
    Transport(String),
    /// The job deadline passed.
    Deadline,
    /// The job was cancelled.
    Cancelled,
}

/// The frames one [`WsConn::collect`] gathered, and why it stopped.
#[derive(Debug, Clone)]
pub struct CollectOutcome {
    /// Every frame seen in the window, in order, including the Pong the dialer
    /// answered a Ping with and the peer's Close.
    pub frames: Vec<Frame>,
    /// Why collection ended.
    pub ended: CollectEnd,
}

/// An open, scope-permitted WebSocket conversation.
///
/// Holds the guard's `ActionPermit` and the dialer's connection slot: dropping
/// the connection releases both. Every frame sent and received is recorded, so
/// [`WsConn::into_flows`] can hand the store a faithful replay conversation.
pub struct WsConn {
    stream: WebSocketStream<ByteStream>,
    request: RequestRecord,
    status: u16,
    response_headers: Vec<(String, String)>,
    peer: SocketAddr,
    tls: bool,
    sni: Option<String>,
    opened: SystemTime,
    started: Instant,
    recorded: Vec<Recorded>,
    _permit: ActionPermit,
    _slot: OwnedSemaphorePermit,
}

impl fmt::Debug for WsConn {
    /// Names the connection by authority and status only: no header value and
    /// no frame payload ever reaches a `Debug` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsConn")
            .field("authority", &self.request.authority)
            .field("status", &self.status)
            .field("frames", &self.recorded.len())
            .finish()
    }
}

impl WsConn {
    /// The status the server answered the upgrade with (101 for an open
    /// connection).
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The upgrade response headers, lowercase names, in order.
    #[must_use]
    pub fn response_headers(&self) -> Vec<(String, String)> {
        self.response_headers.clone()
    }

    /// The subprotocol the server echoed in its 101, if any.
    ///
    /// `None` means the upgrade completed without one — which is an
    /// observation, not a failure (plan call 28): `ws-subprotocol-observe`
    /// reads exactly this.
    #[must_use]
    pub fn subprotocol(&self) -> Option<String> {
        header_of(&self.response_headers, "sec-websocket-protocol").map(str::to_string)
    }

    /// Send one frame and record it.
    ///
    /// # Errors
    ///
    /// When a Text frame's payload is not UTF-8, or the stream refuses the
    /// write.
    pub async fn send(&mut self, frame: &Frame) -> anyhow::Result<()> {
        let message = match frame.kind {
            FrameKind::Text => Message::text(
                String::from_utf8(frame.payload.clone())
                    .context("a text frame payload must be valid UTF-8")?,
            ),
            FrameKind::Binary => Message::Binary(Bytes::from(frame.payload.clone())),
            FrameKind::Ping => Message::Ping(Bytes::from(frame.payload.clone())),
            FrameKind::Pong => Message::Pong(Bytes::from(frame.payload.clone())),
            FrameKind::Close => Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: String::from_utf8_lossy(&frame.payload).into_owned().into(),
            })),
        };
        tracing::debug!(kind = ?frame.kind, bytes = frame.payload.len(), "ws send");
        self.stream
            .send(message)
            .await
            .context("sending a websocket frame")?;
        self.record(WsDir::ClientToServer, frame.clone());
        Ok(())
    }

    /// Read frames for `window`, answering Ping and stopping on Close.
    ///
    /// `cancelled` is polled at least every 50 ms so a cancelled job stops
    /// waiting; `deadline` bounds the window the same way.
    ///
    /// The `Sync` bound on `cancelled` is load-bearing: it is held across this
    /// method's awaits, and a bare `&dyn Fn` is not `Sync`, so without it this
    /// future is not `Send` and no caller can return it as the `BoxFuture` the
    /// `ProbeHost` trait requires (task 7).
    pub async fn collect(
        &mut self,
        window: Duration,
        deadline: Instant,
        cancelled: &(dyn Fn() -> bool + Sync),
    ) -> CollectOutcome {
        let window_end = Instant::now() + window;
        let first = self.recorded.len();
        let ended = loop {
            if cancelled() {
                break CollectEnd::Cancelled;
            }
            let now = Instant::now();
            if now >= deadline {
                break CollectEnd::Deadline;
            }
            if now >= window_end {
                break CollectEnd::Window;
            }
            let step = (window_end - now).min(deadline - now).min(CANCEL_POLL);
            let message = match tokio::time::timeout(step, self.stream.next()).await {
                Err(_elapsed) => continue,
                Ok(None) => break CollectEnd::Transport("the stream ended".to_string()),
                Ok(Some(Err(err))) => break CollectEnd::Transport(err.to_string()),
                Ok(Some(Ok(message))) => message,
            };
            match message {
                Message::Text(text) => {
                    self.record(
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Text,
                            payload: text.as_bytes().to_vec(),
                        },
                    );
                }
                Message::Binary(bytes) => {
                    self.record(
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Binary,
                            payload: bytes.to_vec(),
                        },
                    );
                }
                Message::Ping(payload) => {
                    self.record(
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Ping,
                            payload: payload.to_vec(),
                        },
                    );
                    // Reading a Ping makes tungstenite queue the matching Pong;
                    // flushing puts it on the wire now instead of at the next
                    // write. Sending one as well would answer the Ping twice.
                    if let Err(err) = self.stream.flush().await {
                        break CollectEnd::Transport(err.to_string());
                    }
                    self.record(
                        WsDir::ClientToServer,
                        Frame {
                            kind: FrameKind::Pong,
                            payload: payload.to_vec(),
                        },
                    );
                }
                Message::Pong(payload) => {
                    self.record(
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Pong,
                            payload: payload.to_vec(),
                        },
                    );
                }
                Message::Close(frame) => {
                    let code = frame.as_ref().map(|frame| u16::from(frame.code));
                    self.record(
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Close,
                            payload: close_payload(frame.as_ref()),
                        },
                    );
                    break CollectEnd::Close { code };
                }
                Message::Frame(_) => {}
            }
        };
        CollectOutcome {
            frames: self.recorded[first..]
                .iter()
                .map(|recorded| recorded.frame.clone())
                .collect(),
            ended,
        }
    }

    /// Close the conversation and return whatever the peer answered with.
    ///
    /// Sends a normal Close, then waits up to 200 ms for the peer's Close,
    /// recording everything that arrives in the meantime.
    pub async fn close(&mut self) -> Vec<Frame> {
        let frame = Frame {
            kind: FrameKind::Close,
            payload: Vec::new(),
        };
        // An already-closed stream is the normal case when the peer closed
        // first; the conversation is recorded either way.
        if self.send(&frame).await.is_err() {
            return Vec::new();
        }
        let until = Instant::now() + CLOSE_REPLY_WINDOW;
        let outcome = self
            .collect(CLOSE_REPLY_WINDOW, until + CLOSE_REPLY_WINDOW, &|| false)
            .await;
        outcome.frames
    }

    /// The handshake and conversation of this dial, as replay flows.
    ///
    /// Both carry `metadata.is_replay = true` and `marks`; the `WsFlow` points
    /// at the `HttpFlow`'s id, and every frame the scanner sent is `injected`.
    /// Whether they reach the store is the record policy's call (spec D5), not
    /// the dialer's. Dropping the connection releases the guard permit and the
    /// dialer slot.
    #[must_use]
    pub fn into_flows(self, marks: Vec<String>) -> (HttpFlow, WsFlow) {
        let completed = SystemTime::now();
        let duration = Some(self.started.elapsed());
        let conn = ConnInfo {
            peer: self.peer,
            sni: self.sni.clone(),
            alpn: None,
            tls: self.tls,
            established: self.opened,
        };
        let mut response_headers = HeaderMap::new();
        for (name, value) in &self.response_headers {
            response_headers.set(name, value);
        }
        let meta = |duration| FlowMeta {
            marks: marks.clone(),
            is_replay: true,
            duration,
            ..FlowMeta::default()
        };

        let handshake = HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".to_string(),
                scheme: self.request.scheme.to_string(),
                authority: self.request.authority.clone(),
                path: self.request.path.clone(),
                version: HttpVersion::Http11,
                headers: self.request.headers,
                body: Body::Empty,
                timestamp: self.opened,
            },
            response: Some(HttpResponse {
                status: self.status,
                version: HttpVersion::Http11,
                headers: response_headers,
                trailers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: self.opened,
            }),
            client_conn: conn.clone(),
            server_conn: Some(conn.clone()),
            metadata: meta(duration),
            intercept: InterceptState::Observed,
        };
        let conversation = WsFlow {
            id: FlowId::new(),
            handshake: handshake.id,
            messages: self
                .recorded
                .into_iter()
                .map(|recorded| WsMessage {
                    dir: recorded.dir,
                    opcode: opcode_of(recorded.frame.kind),
                    data: recorded.frame.payload,
                    timestamp: recorded.at,
                    injected: recorded.dir == WsDir::ClientToServer,
                })
                .collect(),
            client_conn: conn.clone(),
            server_conn: Some(conn),
            metadata: FlowMeta {
                created: completed,
                ..meta(duration)
            },
            intercept: InterceptState::Observed,
        };
        (handshake, conversation)
    }

    /// Add one frame to the recorded conversation.
    fn record(&mut self, dir: WsDir, frame: Frame) {
        self.recorded.push(Recorded {
            dir,
            frame,
            at: SystemTime::now(),
        });
    }
}

/// The reason text of a Close frame, as bytes (empty when there is no frame).
fn close_payload(frame: Option<&CloseFrame>) -> Vec<u8> {
    frame.map_or_else(Vec::new, |frame| frame.reason.as_bytes().to_vec())
}

/// The core opcode a model frame kind records as.
fn opcode_of(kind: FrameKind) -> WsOpcode {
    match kind {
        FrameKind::Text => WsOpcode::Text,
        FrameKind::Binary => WsOpcode::Binary,
        FrameKind::Ping => WsOpcode::Ping,
        FrameKind::Pong => WsOpcode::Pong,
        FrameKind::Close => WsOpcode::Close,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        GuardError, HttpFlow, LimitConfig, ScopeEntry, ScopeRateGuard, StdGuard, WsDir, WsOpcode,
    };
    use aitm_scan_model::{Frame, FrameKind};
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tokio::sync::Notify;
    use tokio_tungstenite::tungstenite::handshake::server::{
        create_response, ErrorResponse, Request,
    };
    use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;

    use super::{build_request, CollectEnd, DialError, DialLimits, DialOutcome, WsConn, WsDialer};
    use crate::testing::{captured_conversation, echo_handler, ws_server, HandshakeDecision};
    use crate::types::HandshakeOverrides;

    /// A guard with the fixture authority in scope.
    fn guard_in_scope() -> Arc<StdGuard> {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        Arc::new(guard)
    }

    /// A guard with the fixture authority in scope and one request per second.
    fn throttled_guard() -> Arc<StdGuard> {
        let guard = StdGuard::new(LimitConfig {
            per_host_rps: 1,
            ..LimitConfig::default()
        });
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        Arc::new(guard)
    }

    /// Five seconds from now: every hermetic test finishes long before this.
    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// The value of one (lowercase) header of a logged handshake.
    fn hdr<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Dial the fixture handshake through `dialer`, expecting an upgrade.
    async fn upgrade(
        dialer: &WsDialer,
        handshake: &HttpFlow,
        overrides: &HandshakeOverrides,
        guard: &dyn ScopeRateGuard,
    ) -> WsConn {
        match dialer
            .dial(handshake, overrides, guard, soon(), DialLimits::default())
            .await
        {
            Ok(DialOutcome::Upgraded(conn)) => conn,
            Ok(DialOutcome::Refused { status, .. }) => {
                panic!("expected an upgrade, got {status}")
            }
            Err(err) => panic!("expected an upgrade, got {err}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_regenerates_key_and_keeps_the_rest() {
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let _conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let sent = &log.handshakes()[0];
        assert_ne!(
            hdr(sent, "sec-websocket-key"),
            Some("dGhlIHNhbXBsZSBub25jZQ=="),
            "the captured key must not be replayed"
        );
        assert!(
            hdr(sent, "sec-websocket-key").is_some(),
            "a fresh key must be sent"
        );
        assert_eq!(hdr(sent, "cookie"), Some("sid=s3cr3t-cookie"));
        assert_eq!(hdr(sent, "origin"), Some("https://app.test"));
        assert_eq!(hdr(sent, "sec-websocket-protocol"), Some("chat"));
        assert_eq!(hdr(sent, "user-agent"), Some("fixture/1"));
        assert_eq!(hdr(sent, "host"), Some("127.0.0.1:8080"));
        assert_eq!(hdr(sent, "sec-websocket-version"), Some("13"));
        assert_eq!(hdr(sent, "sec-websocket-accept"), None);
        assert_eq!(
            transport.connects(),
            vec![(
                "127.0.0.1".to_string(),
                8080u16,
                false,
                "127.0.0.1".to_string()
            )]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upgrade_without_subprotocol_echo_is_still_upgraded() {
        // The fixture asks for `Sec-WebSocket-Protocol: chat`; the default test
        // server completes the 101 without echoing one. tungstenite's own
        // client verification calls that a failed handshake, which would make
        // the scanner blind to a common server behaviour, so the dialer drives
        // the upgrade itself and records the subprotocol instead (call 28).
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        assert_eq!(conn.status(), 101);
        assert_eq!(conn.subprotocol(), None);
        assert_eq!(
            hdr(&log.handshakes()[0], "sec-websocket-protocol"),
            Some("chat"),
            "the replay still asks for the captured subprotocol"
        );
        assert_eq!(log.connections(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_accept_key_is_a_handshake_error() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|request: &Request| {
            let mut response = create_response(request).expect("a 101 base response");
            response.headers_mut().insert(
                "sec-websocket-accept",
                HeaderValue::from_static("bm90LXRoZS1yaWdodC1rZXk="),
            );
            Ok(response)
        });
        let (transport, _log) = ws_server(Some(decide), echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let err = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits::default(),
            )
            .await
            .expect_err("a 101 that does not answer this dial's key is not an upgrade");

        assert!(
            matches!(err, DialError::Handshake(ref text) if text.contains("Sec-WebSocket-Accept")),
            "expected an accept-key handshake error, got: {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn overrides_replace_and_strip() {
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let overrides =
            HandshakeOverrides::set("Origin", "https://attacker.invalid").and_strip("Cookie");

        let _conn = upgrade(&dialer, &handshake, &overrides, &*guard).await;

        let sent = &log.handshakes()[0];
        assert_eq!(hdr(sent, "origin"), Some("https://attacker.invalid"));
        assert_eq!(hdr(sent, "cookie"), None);
        assert_eq!(hdr(sent, "sec-websocket-protocol"), Some("chat"));
    }

    #[test]
    fn override_of_regenerated_header_is_err() {
        let (handshake, _) = captured_conversation();

        let err = build_request(
            &handshake,
            &HandshakeOverrides::set("Sec-WebSocket-Key", "x"),
        )
        .expect_err("a regenerated header may not be overridden");

        assert!(
            err.to_string().to_lowercase().contains("sec-websocket-key"),
            "the error must name the header, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_scope_authority_never_connects() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = StdGuard::default();

        let err = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &guard,
                soon(),
                DialLimits::default(),
            )
            .await
            .expect_err("an out-of-scope authority must refuse");

        assert!(
            matches!(err, DialError::Guard(GuardError::OutOfScope(ref host)) if host == "127.0.0.1:8080"),
            "expected an out-of-scope guard error, got: {err:?}"
        );
        assert!(
            transport.connects().is_empty(),
            "no socket may be opened for an out-of-scope authority"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_101_is_a_refused_outcome() {
        // The `Err` half is tungstenite's own `ErrorResponse`; the
        // `HandshakeDecision` contract fixes it, so it cannot be boxed away.
        #[allow(clippy::result_large_err)]
        let decide: HandshakeDecision = Arc::new(|_request| {
            let mut response = ErrorResponse::new(Some("forbidden".to_string()));
            *response.status_mut() = StatusCode::FORBIDDEN;
            Err(response)
        });
        let (transport, log) = ws_server(Some(decide), echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let outcome = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits::default(),
            )
            .await
            .expect("a rejected upgrade is data, not an error");

        match outcome {
            DialOutcome::Refused { status, headers } => {
                assert_eq!(status, 403);
                assert!(
                    headers
                        .iter()
                        .all(|(name, _)| name != "sec-websocket-accept"),
                    "a refusal carries no upgrade headers"
                );
            }
            DialOutcome::Upgraded(_) => panic!("a 403 must not upgrade"),
        }
        // The landed Task 2 harness counts completed upgrades in `connections()`
        // and every attempt in `handshakes()`; a rejected upgrade is an attempt.
        assert_eq!(log.handshakes().len(), 1);
        assert_eq!(log.connections(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn at_most_four_connections_at_once() {
        let hold = Arc::new(Notify::new());
        let hold_in_handler = Arc::clone(&hold);
        let (transport, _log) = ws_server(None, move |_conn| {
            let hold = Arc::clone(&hold_in_handler);
            async move {
                hold.notified().await;
            }
        });
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await);
        }
        assert_eq!(dialer.slots_available(), 0);

        let fifth = tokio::time::timeout(
            Duration::from_millis(200),
            dialer.dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits::default(),
            ),
        )
        .await;
        assert!(
            fifth.is_err(),
            "a fifth connection must wait while four are held"
        );

        drop(held.pop());
        let fifth = tokio::time::timeout(
            Duration::from_secs(5),
            dialer.dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits::default(),
            ),
        )
        .await
        .expect("the fifth dial must proceed once a slot frees")
        .expect("the fifth dial must succeed");
        assert!(matches!(fifth, DialOutcome::Upgraded(_)));
        hold.notify_waiters();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collect_answers_ping_and_stops_on_close() {
        let (transport, log) = ws_server(None, |conn| async move {
            let mut ws = conn.ws().await;
            ws.send(Message::Ping(Bytes::from_static(b"p")))
                .await
                .expect("server ping");
            ws.send(Message::text("a")).await.expect("server text");
            while let Some(Ok(message)) = ws.next().await {
                if let Message::Pong(payload) = message {
                    conn.record(payload.to_vec());
                    break;
                }
            }
            ws.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })))
            .await
            .expect("server close");
        });
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let collected = conn
            .collect(Duration::from_secs(1), soon(), &|| false)
            .await;

        assert_eq!(
            collected
                .frames
                .iter()
                .map(|frame| frame.kind)
                .collect::<Vec<_>>(),
            vec![
                FrameKind::Ping,
                FrameKind::Pong,
                FrameKind::Text,
                FrameKind::Close
            ]
        );
        assert_eq!(collected.ended, CollectEnd::Close { code: Some(1000) });
        assert_eq!(
            log.received(),
            vec![b"p".to_vec()],
            "the dialer answers a ping with exactly one pong"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn into_flows_records_a_replay_conversation() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        conn.send(&Frame {
            kind: FrameKind::Text,
            payload: b"hi".to_vec(),
        })
        .await
        .expect("send the probe frame");
        let collected = conn
            .collect(Duration::from_millis(300), soon(), &|| false)
            .await;
        assert_eq!(collected.ended, CollectEnd::Window);
        conn.close().await;

        let (http, ws) = conn.into_flows(vec!["scan:job-1".to_string()]);

        assert_eq!(http.response.as_ref().map(|r| r.status), Some(101));
        assert!(http.metadata.is_replay);
        assert_eq!(http.metadata.marks, vec!["scan:job-1".to_string()]);
        assert_eq!(
            http.request.headers.get("cookie"),
            Some("sid=s3cr3t-cookie")
        );
        assert_eq!(ws.handshake, http.id);
        assert!(ws.metadata.is_replay);
        assert_eq!(ws.metadata.marks, vec!["scan:job-1".to_string()]);
        assert_eq!(
            ws.messages
                .iter()
                .map(|m| (m.dir, m.opcode))
                .collect::<Vec<_>>(),
            vec![
                (WsDir::ClientToServer, WsOpcode::Text),
                (WsDir::ServerToClient, WsOpcode::Text),
                (WsDir::ClientToServer, WsOpcode::Close),
                (WsDir::ServerToClient, WsOpcode::Close),
            ]
        );
        assert_eq!(ws.messages[0].data, b"hi".to_vec());
        assert_eq!(ws.messages[1].data, b"echo:hi".to_vec());
        assert!(
            ws.messages
                .iter()
                .filter(|m| m.dir == WsDir::ClientToServer)
                .all(|m| m.injected),
            "every frame the scanner sent is injected"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rate_limited_waits_once_then_dials() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = throttled_guard();

        let _first = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;
        let started = Instant::now();
        let _second = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;
        let waited = started.elapsed();

        assert!(
            waited >= Duration::from_millis(500),
            "the second dial must wait out the rate limit, waited {waited:?}"
        );
        assert_eq!(transport.connects().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rate_limit_longer_than_deadline_is_a_guard_error() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = throttled_guard();

        let _first = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;
        let started = Instant::now();
        let err = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                Instant::now() + Duration::from_millis(50),
                DialLimits::default(),
            )
            .await
            .expect_err("a rate limit longer than the deadline must refuse");
        let waited = started.elapsed();

        assert!(
            matches!(err, DialError::Guard(GuardError::RateLimited { .. })),
            "expected a rate-limit guard error, got: {err:?}"
        );
        assert!(
            waited < Duration::from_millis(200),
            "the refusal must be immediate, took {waited:?}"
        );
        assert_eq!(transport.connects().len(), 1);
    }
}
