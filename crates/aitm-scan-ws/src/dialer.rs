//! The `WsDialer`: header replay rule, guard + semaphore, frame I/O, replay flows — written by task 6 of the T4 plan.
//!
//! One dialer is owned by the lane and one by the `ws.*` language (plan call
//! 23); each holds a [`MAX_CONNECTIONS`]-permit semaphore, so a lane's probe
//! hosts share four connections however many of them there are. Every dial is
//! gated by [`ScopeRateGuard::check_active`] on the handshake authority
//! *before* a socket is opened, and the resulting `ActionPermit` is held for
//! the connection's life (spec D8.3, plan call 2). The authority is then
//! resolved here and every candidate address passes [`aitm_core::ssrf_check`]
//! before the transport is handed the one it connects to (security finding
//! S3), so a scoped hostname that resolves to a private address is refused the
//! way every other upstream connect in the product refuses it.
//!
//! Nothing here logs a header value or a frame payload: `tracing` lines carry
//! an authority, a frame kind and a byte length, and [`DialError`] carries the
//! transport's own text, never a header value, a path or a query. A
//! third-party text is only ever passed through when it is known not to quote
//! what it was given: tungstenite's serialiser names the offending header
//! *and its value*, so that one is replaced here rather than forwarded
//! (security finding S9).

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::guard::ActionPermit;
use aitm_core::{
    ssrf_check, Body, ByteStream, ConnInfo, FlowId, FlowMeta, GuardError, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, ScopeRateGuard, SsrfPolicy, WsDir,
    WsFlow, WsMessage, WsOpcode,
};
use aitm_scan_model::{Frame, FrameKind, WsOptions};
use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout_at;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::handshake::client::generate_request;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as TungsteniteError, Message, Utf8Bytes};
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
pub(crate) const REGENERATED_HEADERS: [&str; 6] = [
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

/// `value` as an HTTP header value, or `None` when it cannot go on the wire.
///
/// Visible ASCII only. `HeaderValue::from_str` also accepts obs-text (bytes
/// 0x80-0xFF), which every serialiser downstream then refuses — tungstenite's
/// by quoting the whole value back in its error text (security finding S9). A
/// value this crate cannot put on the wire is refused here instead, by a
/// caller whose refusal names the header alone.
///
/// The one place the rule lives: the replay dialer ([`header_value`]) and the
/// `ws.*` language's `build_request` both go through it, each turning the
/// `None` into its own error type (quality round-2 Minor 1).
pub(crate) fn visible_ascii_header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value)
        .ok()
        .filter(|value| value.to_str().is_ok())
}

/// `value` as an HTTP header value; the error names the header, never the value.
///
/// The rule is [`visible_ascii_header_value`]'s.
fn header_value(name: &str, value: &str) -> anyhow::Result<HeaderValue> {
    visible_ascii_header_value(value)
        .ok_or_else(|| anyhow!("the value of header {name} cannot be sent on the wire"))
}

/// The `host:port` the scope guard is asked about for `request`.
///
/// The single place this derivation lives: [`WsDialer::dial_request`] uses it
/// for the dial it guards, and the `ws.*` language uses it for the refusal
/// reason, so a refusal names exactly the authority the guard saw. A request
/// with no host yields a bare `:port`, which the guard refuses like any other
/// out-of-scope authority; no path, query or header value ever reaches it.
#[must_use]
pub(crate) fn request_authority(request: &Request<()>) -> String {
    let uri = request.uri();
    let scheme = uri.scheme_str().unwrap_or("ws");
    let host = uri.host().unwrap_or_default();
    match uri.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => authority_with_port(scheme, host),
    }
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
/// header. The error names the scheme, the authority and a header *name*; it
/// never carries the path, the query or a header value (security finding S1).
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
    // The parser's own message is replaced: `http`'s and tungstenite's texts
    // are generic today, but the captured path and query must never be able to
    // reach an error through them.
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| anyhow!("the captured authority and path do not form a websocket url"))
        .with_context(|| {
            format!(
                "building an upgrade request for {scheme}://{}",
                captured.authority
            )
        })?;

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
/// baked into the dialer (plan call 26). The collection ceilings bound what one
/// [`WsConn::collect`] gathers and what a connection records over its life
/// (security finding S5): a server that floods replies ends the collection as
/// [`CollectEnd::Limit`] instead of growing it without bound.
#[derive(Debug, Clone, Copy)]
pub struct DialLimits {
    /// The largest frame and message this connection will read **or write**:
    /// tungstenite enforces it on incoming frames, [`WsConn::send`] on outgoing.
    pub max_frame_bytes: usize,
    /// Payload bytes one `collect` gathers before ending as `Limit`; also the
    /// most a connection records for its replay flow.
    pub max_collect_bytes: usize,
    /// Frames one `collect` gathers before ending as `Limit`; also the most a
    /// connection records for its replay flow.
    pub max_collect_frames: usize,
}

/// Default [`DialLimits::max_collect_bytes`]: 8 MiB.
pub const DEFAULT_MAX_COLLECT_BYTES: usize = 8 * 1024 * 1024;

/// Default [`DialLimits::max_collect_frames`].
pub const DEFAULT_MAX_COLLECT_FRAMES: usize = 256;

impl Default for DialLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: WsOptions::default().max_frame_bytes as usize,
            max_collect_bytes: DEFAULT_MAX_COLLECT_BYTES,
            max_collect_frames: DEFAULT_MAX_COLLECT_FRAMES,
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
/// A refused *upgrade* is not here — see [`DialOutcome::Refused`]. `Request`,
/// `Connect` and `Handshake` carry text that names a header, an authority or
/// a socket/protocol condition and never a header value, a path or a query.
#[derive(Debug)]
pub enum DialError {
    /// The scope/rate guard refused the authority, or the SSRF check refused
    /// every address it resolved to.
    Guard(GuardError),
    /// The upgrade request could not be built from the capture and overrides
    /// (a header that cannot go on the wire, an override of a regenerated
    /// header, an authority and path that form no URL).
    Request(String),
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
            DialError::Request(text) => {
                write!(f, "the upgrade request could not be built: {text}")
            }
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
    ssrf: SsrfPolicy,
}

impl WsDialer {
    /// A dialer over `transport` with [`MAX_CONNECTIONS`] free slots and the
    /// product's default SSRF posture ([`SsrfPolicy::default`]: private and
    /// loopback addresses are refused unless the literal address, or
    /// `localhost`, is itself in scope).
    #[must_use]
    pub fn new(transport: Arc<dyn WsTransport>) -> Self {
        Self {
            transport,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            ssrf: SsrfPolicy::default(),
        }
    }

    /// The same dialer with `policy` as its SSRF posture.
    #[must_use]
    pub fn with_ssrf(mut self, policy: SsrfPolicy) -> Self {
        self.ssrf = policy;
        self
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
    /// [`DialError::Request`] when the request cannot be built;
    /// [`DialError::Guard`] when the authority is out of scope, rate limited
    /// past the deadline, resolves only to refused addresses or is otherwise
    /// refused; [`DialError::Timeout`], [`DialError::Connect`] or
    /// [`DialError::Handshake`] when the dial itself fails. A non-101 answer is
    /// `Ok(`[`DialOutcome::Refused`]`)`.
    pub async fn dial(
        &self,
        handshake: &HttpFlow,
        overrides: &HandshakeOverrides,
        guard: &dyn ScopeRateGuard,
        deadline: Instant,
        limits: DialLimits,
    ) -> Result<DialOutcome, DialError> {
        let request = build_request(handshake, overrides)
            .map_err(|err| DialError::Request(format!("{err:#}")))?;
        self.dial_request(request, guard, deadline, limits).await
    }

    /// Dial a request built elsewhere (the `ws.*` language builds its own).
    ///
    /// The order is fixed and load-bearing: a connection slot first (so a
    /// dialer with all four slots busy does not pin a guard permit while it
    /// waits; security finding S8), then the guard (no socket is opened for an
    /// authority the operator did not put in scope), then resolution with the
    /// SSRF check on every candidate, then the socket, then the handshake —
    /// each bounded by `deadline`.
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
        // Checked up front: `timeout_at` polls its future before it looks at
        // the clock, so a dial whose every step is immediately ready (a free
        // slot, a literal address, a fast socket) would otherwise complete
        // after its deadline instead of refusing.
        if Instant::now() >= deadline {
            return Err(DialError::Timeout);
        }
        let uri = request.uri().clone();
        let scheme = uri.scheme_str().unwrap_or("ws").to_ascii_lowercase();
        let tls = scheme == "wss";
        let host = uri
            .host()
            .ok_or_else(|| DialError::Connect("the upgrade request has no host".to_string()))?;
        let port = uri.port_u16().unwrap_or_else(|| default_port(&scheme));
        let authority = request_authority(&request);
        // `http` keeps an IPv6 literal in its brackets; a socket wants it bare.
        let dial_host = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host)
            .to_string();

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

        let permit = check_authority(guard, &authority, deadline).await?;

        let addr = match timeout_at(until, self.resolve(guard, &authority, &dial_host, port)).await
        {
            Ok(resolved) => resolved?,
            Err(_elapsed) => return Err(DialError::Timeout),
        };

        tracing::debug!(authority = %authority, %addr, tls, "ws dial");
        let stream = match timeout_at(until, self.transport.connect(addr, tls, &dial_host)).await {
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
        let (head, key) = generate_request(request).map_err(unserialisable_request)?;
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
            peer: addr,
            tls,
            sni: tls.then(|| dial_host.clone()),
            opened: SystemTime::now(),
            started: Instant::now(),
            limits,
            recorded: Vec::new(),
            recorded_bytes: 0,
            unrecorded: 0,
            _permit: permit,
            _slot: slot,
        }))
    }

    /// Resolve `host:port` and return the first address the SSRF check admits.
    ///
    /// Every candidate is checked with `confine_to_scope = false`, exactly as
    /// `aitm-proto-http`'s sender does: scope confinement is the guard's job
    /// and has already run; this is the private/loopback/rebinding gate. When
    /// every candidate is refused the last refusal is returned as a guard
    /// error, and nothing has been connected.
    async fn resolve(
        &self,
        guard: &dyn ScopeRateGuard,
        authority: &str,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, DialError> {
        // `lookup_host` answers an IP literal without touching a resolver, so
        // the hermetic tests and a literal-scoped lab target never leave the
        // process here.
        let candidates = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| DialError::Connect(format!("{authority} could not be resolved")))?;
        let scope = guard.list_scope();
        // The last refusal, when every candidate was refused; `None` after the
        // loop means there was no candidate at all.
        let mut refused: Option<GuardError> = None;
        for candidate in candidates {
            match ssrf_check(&self.ssrf, &scope, false, authority, candidate.ip()) {
                Ok(()) => return Ok(SocketAddr::new(candidate.ip(), port)),
                Err(err) => {
                    tracing::debug!(
                        authority,
                        addr = %candidate,
                        "ws dial address refused by the SSRF check"
                    );
                    refused = Some(err);
                }
            }
        }
        match refused {
            Some(err) => Err(DialError::Guard(err)),
            None => Err(DialError::Connect(format!(
                "{authority} resolved to no address"
            ))),
        }
    }
}

/// The close frame an RFC 6455 close payload (code, then reason) describes.
///
/// The model payload is the same layout `close_payload` records; shorter than
/// a code is a plain normal close.
fn close_frame(payload: &[u8]) -> CloseFrame {
    match payload.get(..2) {
        Some(&[high, low]) => CloseFrame {
            code: CloseCode::from(u16::from_be_bytes([high, low])),
            reason: String::from_utf8_lossy(payload.get(2..).unwrap_or_default())
                .into_owned()
                .into(),
        },
        _ => CloseFrame {
            code: CloseCode::Normal,
            reason: String::new().into(),
        },
    }
}

/// `payload` as the message `build` makes of it, plus the one copy the record
/// keeps; the message and the copy share nothing but the original bytes.
fn shared_payload(payload: Vec<u8>, build: fn(Bytes) -> Message) -> (Message, Vec<u8>) {
    let bytes = Bytes::from(payload);
    let recorded = bytes.to_vec();
    (build(bytes), recorded)
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

/// The refusal for an upgrade request tungstenite would not serialise.
///
/// tungstenite's own text is **never** passed through (security finding S9):
/// its `Utf8` variant reads `… failed to convert header to a str for header
/// name 'cookie' with value: "sid=…"`, which would carry a captured cookie into
/// every check's `detail` and into a script's `BadArgs`. A
/// [`ProtocolError::InvalidHeader`] names a header and nothing else, so that
/// one name is repeated; everything else is reported without detail.
fn unserialisable_request(err: TungsteniteError) -> DialError {
    match err {
        TungsteniteError::Protocol(ProtocolError::InvalidHeader(name)) => DialError::Request(
            format!("the upgrade request could not be serialised for header {name}"),
        ),
        _ => DialError::Request("the upgrade request could not be serialised".to_string()),
    }
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
    /// The collection reached [`DialLimits::max_collect_frames`] or
    /// [`DialLimits::max_collect_bytes`]. Data, like `Transport`: the frames
    /// gathered so far are the observation (security finding S5).
    Limit,
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
    limits: DialLimits,
    recorded: Vec<Recorded>,
    recorded_bytes: usize,
    unrecorded: usize,
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
    pub fn response_headers(&self) -> &[(String, String)] {
        &self.response_headers
    }

    /// Frames this connection saw but did not record because the replay flow
    /// had reached the dial's collection ceilings (security finding S5).
    ///
    /// The count alone: a frame nobody recorded is never carried out of here.
    /// The probe host reads it after every probe and logs a truncated
    /// conversation at `debug`, so an operator reading an evidence flow that
    /// stops mid-exchange can tell a ceiling from a server that went quiet.
    #[must_use]
    pub(crate) fn unrecorded(&self) -> usize {
        self.unrecorded
    }

    /// Drain and return the frames recorded so far, clearing the record.
    ///
    /// The `ws.*` language calls this after every `ws.recv`: those frames were
    /// already returned to the script, so draining them keeps a long-lived
    /// handle's memory from growing with its conversation (security finding S5).
    /// The byte counter is reset with the record so recording continues from a
    /// clean budget. The replay-flow path ([`WsConn::into_flows`]) never calls
    /// this and so keeps the full conversation.
    pub(crate) fn take_recorded(&mut self) -> Vec<Frame> {
        self.recorded_bytes = 0;
        std::mem::take(&mut self.recorded)
            .into_iter()
            .map(|recorded| recorded.frame)
            .collect()
    }

    /// The subprotocol the server echoed in its 101, if any.
    ///
    /// `None` means the upgrade completed without one — which is an
    /// observation, not a failure (plan call 28): `ws-subprotocol-observe`
    /// reads exactly this.
    #[must_use]
    pub fn subprotocol(&self) -> Option<&str> {
        header_of(&self.response_headers, "sec-websocket-protocol")
    }

    /// Send one frame and record it.
    ///
    /// The payload is moved into the message and copied once for the record
    /// (quality finding Q6). A payload above the dial's `max_frame_bytes` is
    /// refused before anything reaches the wire (tester finding F2): the read
    /// cap and the write cap are the same number.
    ///
    /// # Errors
    ///
    /// When the payload exceeds the dial's frame limit, when a Text frame's
    /// payload is not UTF-8, or when the stream refuses the write. The text
    /// names lengths and kinds, never the payload.
    pub async fn send(&mut self, frame: Frame) -> anyhow::Result<()> {
        let len = frame.payload.len();
        let max = self.limits.max_frame_bytes;
        if len > max {
            bail!("a {len}-byte frame exceeds this dial's {max}-byte frame limit");
        }
        let kind = frame.kind;
        // One match and one tail (quality finding N9): every kind yields the
        // message that goes out *and* the bytes that are recorded, so no kind
        // can take a send path of its own and no arm exists for a message this
        // function never builds.
        let (message, payload) = match kind {
            FrameKind::Close => (
                Message::Close(Some(close_frame(&frame.payload))),
                frame.payload,
            ),
            FrameKind::Text => {
                let text = Utf8Bytes::try_from(Bytes::from(frame.payload))
                    .context("a text frame payload must be valid UTF-8")?;
                let payload = text.as_bytes().to_vec();
                (Message::Text(text), payload)
            }
            FrameKind::Binary => shared_payload(frame.payload, Message::Binary),
            FrameKind::Ping => shared_payload(frame.payload, Message::Ping),
            FrameKind::Pong => shared_payload(frame.payload, Message::Pong),
        };
        tracing::debug!(kind = ?kind, bytes = len, "ws send");
        self.stream
            .send(message)
            .await
            .context("sending a websocket frame")?;
        self.record(WsDir::ClientToServer, Frame { kind, payload });
        Ok(())
    }

    /// Read frames for `window`, answering Ping and stopping on Close.
    ///
    /// `cancelled` is polled at least every 50 ms so a cancelled job stops
    /// waiting; `deadline` bounds the window the same way. The dial's
    /// collection ceilings ([`DialLimits::max_collect_frames`],
    /// [`DialLimits::max_collect_bytes`]) end it as [`CollectEnd::Limit`] with
    /// what was gathered so far.
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
        let mut frames: Vec<Frame> = Vec::new();
        let mut bytes = 0usize;
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
                    self.collected(
                        &mut frames,
                        &mut bytes,
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Text,
                            payload: text.as_bytes().to_vec(),
                        },
                    );
                }
                Message::Binary(payload) => {
                    self.collected(
                        &mut frames,
                        &mut bytes,
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Binary,
                            payload: payload.to_vec(),
                        },
                    );
                }
                Message::Ping(payload) => {
                    self.collected(
                        &mut frames,
                        &mut bytes,
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
                    self.collected(
                        &mut frames,
                        &mut bytes,
                        WsDir::ClientToServer,
                        Frame {
                            kind: FrameKind::Pong,
                            payload: payload.to_vec(),
                        },
                    );
                }
                Message::Pong(payload) => {
                    self.collected(
                        &mut frames,
                        &mut bytes,
                        WsDir::ServerToClient,
                        Frame {
                            kind: FrameKind::Pong,
                            payload: payload.to_vec(),
                        },
                    );
                }
                Message::Close(frame) => {
                    let code = frame.as_ref().map(|frame| u16::from(frame.code));
                    self.collected(
                        &mut frames,
                        &mut bytes,
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
            if frames.len() >= self.limits.max_collect_frames
                || bytes >= self.limits.max_collect_bytes
            {
                tracing::debug!(
                    frames = frames.len(),
                    bytes,
                    "ws collect reached the dial's collection ceiling"
                );
                break CollectEnd::Limit;
            }
        };
        CollectOutcome { frames, ended }
    }

    /// Keep one collected frame: in this collection's list, and in the record.
    fn collected(&mut self, frames: &mut Vec<Frame>, bytes: &mut usize, dir: WsDir, frame: Frame) {
        *bytes = bytes.saturating_add(frame.payload.len());
        frames.push(frame.clone());
        self.record(dir, frame);
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
        if self.send(frame).await.is_err() {
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

    /// Add one frame to the recorded conversation, unless the replay flow has
    /// reached the dial's collection ceilings — then count it instead
    /// (security finding S5).
    fn record(&mut self, dir: WsDir, frame: Frame) {
        if self.recorded.len() >= self.limits.max_collect_frames
            || self.recorded_bytes >= self.limits.max_collect_bytes
        {
            self.unrecorded = self.unrecorded.saturating_add(1);
            return;
        }
        self.recorded_bytes = self.recorded_bytes.saturating_add(frame.payload.len());
        self.recorded.push(Recorded {
            dir,
            frame,
            at: SystemTime::now(),
        });
    }
}

/// A Close frame's payload in the RFC 6455 section 5.5.1 layout: the two-byte
/// big-endian code, then the reason (empty when there is no frame). The same
/// bytes `aitm-proto-ws` records for a captured Close, so a scan replay flow
/// matches a captured one and a check can read the code (plan call 34).
fn close_payload(frame: Option<&CloseFrame>) -> Vec<u8> {
    frame.map_or_else(Vec::new, |frame| {
        let mut payload = u16::from(frame.code).to_be_bytes().to_vec();
        payload.extend_from_slice(frame.reason.as_bytes());
        payload
    })
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
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        GuardError, HttpFlow, LimitConfig, ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard, WsDir,
        WsOpcode,
    };
    use aitm_scan_model::{Frame, FrameKind};
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::handshake::server::{
        create_response, ErrorResponse, Request,
    };
    use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;

    use super::{build_request, CollectEnd, DialError, DialLimits, DialOutcome, WsConn, WsDialer};
    use crate::testing::{
        captured_conversation, captured_conversation_with_cookie, echo_handler, ws_server,
        HandshakeDecision,
    };
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

    /// The job deadline handed to a dial that is expected to succeed: a safety
    /// net, never a measured bound. Every test here runs over the in-process
    /// duplex transport and finishes in milliseconds on an idle machine, but a
    /// loaded CI runner stretched the old five-second figure into a `Timeout`
    /// (2026-11-01, `upgrade_without_subprotocol_echo_is_still_upgraded`). A
    /// test that expects the deadline to win passes its own short one.
    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(60)
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
                SocketAddr::from(([127, 0, 0, 1], 8080)),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_non_ascii_header_value_is_refused_without_quoting_it() {
        // `HeaderValue::from_str` accepts obs-text, so a captured cookie with a
        // non-ASCII byte used to pass this layer and die in tungstenite's
        // serialiser, whose error quotes the whole value (security finding S9).
        // The refusal names the header and nothing of the value.
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation_with_cookie("sid=s3cr3t-caf\u{e9}");
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
            .expect_err("a header value that cannot go on the wire is not dialled");

        let text = err.to_string();
        assert!(
            matches!(err, DialError::Request(_)),
            "expected a request error, got: {err:?}"
        );
        assert!(
            text.to_lowercase()
                .contains("the value of header cookie cannot be sent on the wire"),
            "unexpected refusal: {text}"
        );
        assert!(
            !text.contains("s3cr3t") && !text.contains("caf"),
            "the refusal quoted the header value: {text}"
        );
        assert!(
            transport.connects().is_empty() && log.handshakes().is_empty(),
            "nothing may reach the wire for a request that cannot be built"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_tungstenite_will_not_serialise_is_refused_without_quoting_it() {
        // The second layer of finding S9: a request built elsewhere (the `ws.*`
        // language builds its own) can still carry an obs-text value, and
        // tungstenite's `generate_request` error is
        // `... for header name 'cookie' with value: "sid=s3cr3t-caf\xc3\xa9"`.
        // That text is never passed through.
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let guard = guard_in_scope();
        let mut request = "ws://127.0.0.1:8080/ws"
            .into_client_request()
            .expect("a client request for the fixture authority");
        request.headers_mut().insert(
            "cookie",
            HeaderValue::from_bytes("sid=s3cr3t-caf\u{e9}".as_bytes())
                .expect("obs-text is a valid header value"),
        );

        let err = dialer
            .dial_request(request, &*guard, soon(), DialLimits::default())
            .await
            .expect_err("a request that cannot be serialised is not dialled");

        let text = err.to_string();
        assert!(
            matches!(err, DialError::Request(_)),
            "expected a request error, got: {err:?}"
        );
        assert!(
            !text.contains("s3cr3t") && !text.contains("caf"),
            "the refusal quoted the header value: {text}"
        );
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
    async fn close_frame_payload_carries_code_and_reason() {
        // A collected Close frame's payload is the RFC 6455 section 5.5.1
        // layout — two big-endian code bytes then the reason — exactly what
        // `aitm-proto-ws` records for a captured Close, so a check can read the
        // code and a replay flow matches a captured one (plan call 34).
        let (transport, _log) = ws_server(None, |conn| async move {
            let mut ws = conn.ws().await;
            ws.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Size,
                reason: "too big".into(),
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

        assert_eq!(collected.ended, CollectEnd::Close { code: Some(1009) });
        let close = collected
            .frames
            .iter()
            .find(|frame| frame.kind == FrameKind::Close)
            .expect("the peer's Close is collected");
        assert_eq!(
            close.payload,
            vec![0x03, 0xF1, b't', b'o', b'o', b' ', b'b', b'i', b'g'],
            "code 1009 (0x03F1) big-endian, then the reason"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn into_flows_records_a_replay_conversation() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        conn.send(Frame {
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

    // --- Malformed upgrade responses (tester, stage 5) -------------------
    //
    // `dial_request` parses the 101 head by hand (plan call 28), so the parser
    // is this crate's own code and the server it has to survive is hostile, not
    // tungstenite. These drive raw bytes straight at the dialer through a bare
    // `DuplexTransport`: every one of them must come back as a `DialError`,
    // never a hang, a panic or an unbounded buffer.

    /// A transport whose server half writes `bytes` once and then holds the
    /// socket open, so the dialer's own bound is what ends the read.
    fn raw_server(bytes: Vec<u8>) -> Arc<crate::testing::DuplexTransport> {
        crate::testing::DuplexTransport::new(move |mut server| {
            let bytes = bytes.clone();
            tokio::spawn(async move {
                // The dialer writes its request first; read it so the duplex
                // buffer cannot fill and stall the write.
                let mut sink = [0u8; 4096];
                let _ = server.read(&mut sink).await;
                let _ = server.write_all(&bytes).await;
                let _ = server.flush().await;
                // Hold the half open: an EOF here would be a different error.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        })
    }

    /// A transport whose server half writes `bytes` and then drops the socket.
    fn raw_server_then_eof(bytes: Vec<u8>) -> Arc<crate::testing::DuplexTransport> {
        crate::testing::DuplexTransport::new(move |mut server| {
            let bytes = bytes.clone();
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                let _ = server.read(&mut sink).await;
                let _ = server.write_all(&bytes).await;
                let _ = server.shutdown().await;
            });
        })
    }

    /// Dial the fixture through `transport` and return the error it produced.
    async fn dial_error(transport: Arc<crate::testing::DuplexTransport>) -> DialError {
        let dialer = WsDialer::new(transport as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits::default(),
            )
            .await
            .expect_err("a malformed upgrade response is never an upgrade")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_head_that_never_ends_is_bounded_at_sixteen_kibibytes() {
        // 40 KiB of well-formed header lines and no `\r\n\r\n` anywhere: the
        // read has to stop at MAX_HEAD_BYTES instead of buffering the stream.
        let mut head = b"HTTP/1.1 101 Switching Protocols\r\n".to_vec();
        while head.len() < 40 * 1024 {
            head.extend_from_slice(b"x-filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }

        let err = dial_error(raw_server(head)).await;

        match err {
            DialError::Handshake(text) => assert_eq!(
                text, "the upgrade response head exceeded 16384 bytes",
                "the bound must be the dialer's, and it must say so"
            ),
            other => panic!("expected a bounded-head handshake error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_garbage_status_line_is_a_handshake_error() {
        let err = dial_error(raw_server(
            b"this is not an http response\r\nx: y\r\n\r\n".to_vec(),
        ))
        .await;

        match err {
            DialError::Handshake(text) => assert!(
                text.starts_with("the upgrade response head is malformed: "),
                "a parse failure must name itself, got: {text}"
            ),
            other => panic!("expected a malformed-head handshake error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn more_than_sixty_four_response_headers_is_a_handshake_error() {
        // 80 headers in a complete, otherwise valid 101 head: httparse is given
        // exactly MAX_HEAD_HEADERS slots, so this must be refused rather than
        // silently truncated into a head that looks like a clean upgrade.
        let mut head = b"HTTP/1.1 101 Switching Protocols\r\n".to_vec();
        for nth in 0..80 {
            head.extend_from_slice(format!("x-filler-{nth}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"\r\n");

        let err = dial_error(raw_server(head)).await;

        match err {
            DialError::Handshake(text) => assert!(
                text.starts_with("the upgrade response head is malformed: "),
                "too many headers is a parse failure, got: {text}"
            ),
            other => panic!("expected a malformed-head handshake error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_that_closes_mid_handshake_is_a_handshake_error() {
        let err = dial_error(raw_server_then_eof(
            b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n".to_vec(),
        ))
        .await;

        match err {
            DialError::Handshake(text) => assert_eq!(
                text, "the server closed before finishing the upgrade response head",
                "an EOF mid-head is a handshake failure, not a connect failure"
            ),
            other => panic!("expected a truncated-head handshake error, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_response_is_a_handshake_error() {
        let err = dial_error(raw_server_then_eof(Vec::new())).await;

        match err {
            DialError::Handshake(text) => assert_eq!(
                text,
                "the server closed before finishing the upgrade response head"
            ),
            other => panic!("expected a handshake error for an empty answer, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collect_stops_on_a_cancelled_job_inside_the_window() {
        // A five-second window against a server that never answers: the only
        // thing that can end this collection in time is the cancel poll.
        let (transport, _log) = ws_server(None, |conn: crate::testing::ServerConn| async move {
            let mut ws = conn.ws().await;
            while let Some(Ok(message)) = ws.next().await {
                if matches!(message, Message::Close(_)) {
                    break;
                }
            }
        });
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let cancel_at = Instant::now() + Duration::from_millis(150);
        let cancelled = move || Instant::now() >= cancel_at;
        let started = Instant::now();
        let outcome = conn
            .collect(
                Duration::from_secs(5),
                Instant::now() + Duration::from_secs(30),
                &cancelled,
            )
            .await;
        let waited = started.elapsed();

        assert_eq!(outcome.ended, CollectEnd::Cancelled);
        assert!(outcome.frames.is_empty(), "{:?}", outcome.frames);
        assert!(
            waited < Duration::from_secs(1),
            "the cancel must be seen within a poll interval, waited {waited:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_above_the_dial_limit_ends_the_collection_as_transport() {
        // Our own read limit must end the conversation as data (plan call 18),
        // never as an error and never as a silent empty window.
        let (transport, _log) = ws_server(None, |conn: crate::testing::ServerConn| async move {
            let mut ws = conn.ws().await;
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(_) => {
                        let _ = ws.send(Message::text("a".repeat(8192))).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = match dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits {
                    max_frame_bytes: 1024,
                    ..DialLimits::default()
                },
            )
            .await
            .expect("the upgrade completes")
        {
            DialOutcome::Upgraded(conn) => conn,
            DialOutcome::Refused { status, .. } => panic!("expected an upgrade, got {status}"),
        };

        conn.send(Frame {
            kind: FrameKind::Text,
            payload: b"hi".to_vec(),
        })
        .await
        .expect("a small frame is within the limit");
        let outcome = conn
            .collect(Duration::from_millis(500), soon(), &|| false)
            .await;

        assert!(
            matches!(outcome.ended, CollectEnd::Transport(_)),
            "an 8 KiB reply at a 1 KiB limit ends the stream: {:?}",
            outcome.ended
        );
        assert!(
            outcome.frames.is_empty(),
            "the oversized frame is not delivered: {:?}",
            outcome.frames
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn conn_debug_carries_no_header_value() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let shown = format!("{conn:?}");
        assert!(
            !shown.contains("s3cr3t-cookie"),
            "the replayed cookie must not reach a Debug output: {shown}"
        );
        assert!(
            shown.contains("127.0.0.1:8080") && shown.contains("101"),
            "Debug still has to identify the connection: {shown}"
        );
    }
    // --- Panel round 1a (security S1, S8; tester F2) ----------------------

    #[test]
    fn a_request_build_error_carries_no_url() {
        // Security finding S1: the captured path and query (a `?token=`) must
        // never reach an error text, and from there a check's `detail`.
        let (mut handshake, _) = captured_conversation();
        handshake.request.path = r#"/ws?token=eyJsecret&q="x""#.to_string();

        let err = build_request(&handshake, &HandshakeOverrides::default())
            .expect_err("a path with a raw quote does not form a url");

        let text = format!("{err:#}");
        assert!(
            !text.contains("eyJsecret") && !text.contains("\"x\""),
            "the error must not quote the path or query: {text}"
        );
        assert!(
            text.contains("ws://127.0.0.1:8080"),
            "the error still names the scheme and authority: {text}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_refuses_a_frame_above_the_dial_limit() {
        // Tester finding F2: `max_frame_bytes` must bound what the dialer
        // writes as well as what it reads. The refusal names the two lengths
        // and never the payload.
        let (transport, log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = match dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                DialLimits {
                    max_frame_bytes: 64,
                    ..DialLimits::default()
                },
            )
            .await
            .expect("the upgrade completes")
        {
            DialOutcome::Upgraded(conn) => conn,
            DialOutcome::Refused { status, .. } => panic!("expected an upgrade, got {status}"),
        };

        let err = conn
            .send(Frame {
                kind: FrameKind::Text,
                payload: b"B".repeat(4096),
            })
            .await
            .expect_err("a 4096-byte frame is above a 64-byte limit");

        assert_eq!(
            err.to_string(),
            "a 4096-byte frame exceeds this dial's 64-byte frame limit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            log.received().is_empty(),
            "nothing may reach the wire: {:?}",
            log.received().iter().map(Vec::len).collect::<Vec<_>>()
        );
        conn.send(Frame {
            kind: FrameKind::Text,
            payload: b"ok".to_vec(),
        })
        .await
        .expect("a frame within the limit still sends");
    }

    /// A guard that counts `check_active` calls and delegates the rest.
    struct CountingGuard {
        inner: Arc<StdGuard>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ScopeRateGuard for CountingGuard {
        fn check_active(&self, host: &str) -> Result<aitm_core::guard::ActionPermit, GuardError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.check_active(host)
        }
        fn add_scope(&self, entry: ScopeEntry) {
            self.inner.add_scope(entry);
        }
        fn remove_scope(&self, entry: &str) -> bool {
            self.inner.remove_scope(entry)
        }
        fn list_scope(&self) -> Vec<ScopeEntry> {
            self.inner.list_scope()
        }
        fn in_scope(&self, host: &str) -> bool {
            self.inner.in_scope(host)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_dialer_times_out_before_the_guard_is_asked() {
        // Security finding S8: the connection slot is taken before the guard's
        // concurrency permit, so a dialer with all four slots held does not
        // pin a guard permit while it waits.
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
        let counting = CountingGuard {
            inner: guard_in_scope(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let err = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &counting,
                Instant::now() + Duration::from_millis(100),
                DialLimits::default(),
            )
            .await
            .expect_err("no slot frees within the deadline");

        assert!(matches!(err, DialError::Timeout), "got {err:?}");
        assert_eq!(
            counting.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the guard must not be asked before a slot is held"
        );
        hold.notify_waiters();
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn dial_maps_a_request_build_error_to_request() {
        // Quality finding Q7: a request that cannot be built is its own
        // `DialError`, not a handshake failure; and (S1) the text carries no
        // path or query.
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (mut handshake, _) = captured_conversation();
        handshake.request.path = r#"/ws?token=eyJsecret&q="x""#.to_string();
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
            .expect_err("an unbuildable request never dials");

        match &err {
            DialError::Request(text) => {
                assert!(!text.contains("eyJsecret"), "{text}");
                assert!(!text.contains("\"x\""), "{text}");
            }
            other => panic!("expected DialError::Request, got {other:?}"),
        }
        assert!(
            err.to_string()
                .starts_with("the upgrade request could not be built: "),
            "{err}"
        );
        assert!(transport.connects().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_private_resolution_is_refused_before_connect() {
        // Security finding S3: the dialer resolves the authority and runs the
        // product's SSRF check on every candidate address before a socket is
        // opened. With the in-scope lift turned off, a loopback literal is
        // refused even though the guard admits the authority.
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>).with_ssrf(SsrfPolicy {
            allow_if_in_scope: false,
            ..SsrfPolicy::default()
        });
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
            .expect_err("a blocked private address must refuse");

        assert!(
            matches!(
                err,
                DialError::Guard(GuardError::PrivateAddressBlocked(ref host)) if host == "127.0.0.1"
            ),
            "expected a private-address guard error, got: {err:?}"
        );
        assert!(
            transport.connects().is_empty(),
            "no socket may be opened for a refused address"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_scoped_loopback_literal_is_admitted() {
        // The default policy lifts the private-address block for an IP literal
        // the operator put in scope, which is how every lab target is scoped.
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let _conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        assert_eq!(
            transport.connects(),
            vec![(
                SocketAddr::from(([127, 0, 0, 1], 8080)),
                false,
                "127.0.0.1".to_string()
            )]
        );
    }

    /// A server that answers the first Text frame with `count` frames of `each`
    /// bytes, then waits for the client's Close.
    fn flooding_server(count: usize, each: usize) -> Arc<crate::testing::DuplexTransport> {
        let (transport, _log) =
            ws_server(None, move |conn: crate::testing::ServerConn| async move {
                let mut ws = conn.ws().await;
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(_) => {
                            for _ in 0..count {
                                if ws.send(Message::text("r".repeat(each))).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        transport
    }

    async fn upgrade_with(
        transport: Arc<crate::testing::DuplexTransport>,
        limits: DialLimits,
    ) -> WsConn {
        let dialer = WsDialer::new(transport as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        match dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                soon(),
                limits,
            )
            .await
        {
            Ok(DialOutcome::Upgraded(conn)) => conn,
            Ok(DialOutcome::Refused { status, .. }) => panic!("expected an upgrade, got {status}"),
            Err(err) => panic!("expected an upgrade, got {err}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collect_ends_at_the_frame_ceiling() {
        // Security finding S5: a server that floods replies cannot make one
        // collection grow without bound; 256 frames end it as `Limit`.
        let mut conn = upgrade_with(flooding_server(300, 8), DialLimits::default()).await;
        conn.send(Frame {
            kind: FrameKind::Text,
            payload: b"go".to_vec(),
        })
        .await
        .expect("send");

        let outcome = conn
            .collect(Duration::from_secs(5), soon(), &|| false)
            .await;

        assert_eq!(outcome.ended, CollectEnd::Limit);
        assert_eq!(outcome.frames.len(), 256);
        assert!(outcome
            .frames
            .iter()
            .all(|frame| frame.kind == FrameKind::Text));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn collect_ends_at_the_byte_ceiling() {
        // Ten 1 MiB frames at the default 8 MiB ceiling: the eighth ends it.
        let mut conn = upgrade_with(
            flooding_server(10, 1 << 20),
            DialLimits {
                max_frame_bytes: 2 << 20,
                ..DialLimits::default()
            },
        )
        .await;
        conn.send(Frame {
            kind: FrameKind::Text,
            payload: b"go".to_vec(),
        })
        .await
        .expect("send");

        let outcome = conn
            .collect(Duration::from_secs(10), soon(), &|| false)
            .await;

        assert_eq!(outcome.ended, CollectEnd::Limit);
        assert_eq!(outcome.frames.len(), 8);
        assert_eq!(
            outcome
                .frames
                .iter()
                .map(|frame| frame.payload.len())
                .sum::<usize>(),
            8 << 20
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_recorded_conversation_is_capped_too() {
        // The replay flow a connection records is bounded by the same
        // ceilings; past them frames are counted, not kept.
        let mut conn = upgrade_with(flooding_server(300, 8), DialLimits::default()).await;
        conn.send(Frame {
            kind: FrameKind::Text,
            payload: b"go".to_vec(),
        })
        .await
        .expect("send");
        let outcome = conn
            .collect(Duration::from_secs(5), soon(), &|| false)
            .await;
        assert_eq!(outcome.ended, CollectEnd::Limit);
        assert_eq!(
            conn.unrecorded(),
            1,
            "the sent frame plus 256 replies is one over"
        );

        let (_http, ws) = conn.into_flows(Vec::new());

        assert_eq!(ws.messages.len(), 256);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dial_at_the_deadline_is_a_timeout_and_never_connects() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(Arc::clone(&transport) as Arc<_>);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();

        let err = dialer
            .dial(
                &handshake,
                &HandshakeOverrides::default(),
                &*guard,
                Instant::now(),
                DialLimits::default(),
            )
            .await
            .expect_err("a dial at its deadline cannot proceed");

        assert!(matches!(err, DialError::Timeout), "got {err:?}");
        assert!(transport.connects().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_collect_at_the_deadline_ends_as_deadline() {
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let mut conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let outcome = conn
            .collect(Duration::from_secs(5), Instant::now(), &|| false)
            .await;

        assert_eq!(outcome.ended, CollectEnd::Deadline);
        assert!(outcome.frames.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn response_headers_and_subprotocol_are_borrowed() {
        // Quality finding Q6: the accessors borrow instead of cloning.
        let (transport, _log) = ws_server(None, echo_handler);
        let dialer = WsDialer::new(transport);
        let (handshake, _) = captured_conversation();
        let guard = guard_in_scope();
        let conn = upgrade(&dialer, &handshake, &HandshakeOverrides::default(), &*guard).await;

        let headers: &[(String, String)] = conn.response_headers();
        let subprotocol: Option<&str> = conn.subprotocol();

        assert!(headers
            .iter()
            .any(|(name, _)| name == "sec-websocket-accept"));
        assert_eq!(subprotocol, None);
    }
}
