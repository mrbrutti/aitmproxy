//! The flow model: identity, HTTP/WebSocket flows, and interception lifecycle.
//!
//! Shapes (types, fields) are fixed by the platform spec; bodies and internal
//! representations are the builder's. Every flow is `Clone` so the store can hand
//! out owned snapshots and a plugin can `backup()` a flow before editing it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;

use crate::body::Body;
use crate::header::HeaderMap;

/// Opaque, globally unique flow identifier. UUID v4 backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(uuid::Uuid);

impl FlowId {
    /// Mint a fresh, random identifier.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// The underlying UUID.
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

impl Default for FlowId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for FlowId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}

/// Every captured interaction. An enum so new protocols slot in without core edits.
// The Http variant is the large one by design: it holds the whole decoded
// exchange. Boxing it would ripple through every `Flow::Http(` use in the
// workspace, so the size gap to `WebSocket` is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Flow {
    Http(HttpFlow),
    WebSocket(WsFlow),
}

impl Flow {
    /// This flow's identifier, regardless of protocol.
    pub fn id(&self) -> FlowId {
        match self {
            Flow::Http(f) => f.id,
            Flow::WebSocket(f) => f.id,
        }
    }

    /// This flow's metadata, regardless of protocol.
    pub fn metadata(&self) -> &FlowMeta {
        match self {
            Flow::Http(f) => &f.metadata,
            Flow::WebSocket(f) => &f.metadata,
        }
    }

    /// This flow's metadata for in-place edits, regardless of protocol.
    pub fn metadata_mut(&mut self) -> &mut FlowMeta {
        match self {
            Flow::Http(f) => &mut f.metadata,
            Flow::WebSocket(f) => &mut f.metadata,
        }
    }

    /// This flow's interception state, regardless of protocol.
    pub fn intercept(&self) -> &InterceptState {
        match self {
            Flow::Http(f) => &f.intercept,
            Flow::WebSocket(f) => &f.intercept,
        }
    }
}

/// A captured HTTP interaction.
#[derive(Debug, Clone)]
pub struct HttpFlow {
    pub id: FlowId,
    pub request: HttpRequest,
    /// `None` until the response arrives.
    pub response: Option<HttpResponse>,
    pub client_conn: ConnInfo,
    /// `None` if short-circuited before reaching upstream.
    pub server_conn: Option<ConnInfo>,
    pub metadata: FlowMeta,
    pub intercept: InterceptState,
}

impl HttpFlow {
    /// Finalise a response that ended before its body was complete.
    ///
    /// When the response head is stored and its body is still
    /// [`Body::Streamed`], the body becomes `Body::Bytes(captured)` (or
    /// `Body::Empty` when nothing was captured), `metadata.truncated` is set and
    /// `metadata.duration` is measured from `metadata.created`; returns `true`.
    /// In every other case (no response yet; a body already buffered, whether it
    /// completed or a plugin replaced it) nothing changes and it returns `false`.
    /// A second call therefore finds a buffered body and is a no-op: the method
    /// is idempotent by construction.
    ///
    /// This is the one rule for "a response that ended early is a truncated,
    /// finished response". The protocol modules apply it (through
    /// `FlowStore::abandon_response`) on every failure path once the head is
    /// stored, so the flow becomes terminal for `flow.clear` and eviction and
    /// `flow.get` reports a concrete `response_bytes`.
    pub fn abandon_response(&mut self, captured: Vec<u8>) -> bool {
        match self.response.as_mut() {
            Some(r) if matches!(r.body, Body::Streamed(_)) => {
                r.body = if captured.is_empty() {
                    Body::Empty
                } else {
                    Body::Bytes(captured)
                };
                self.metadata.truncated = true;
                self.metadata.duration = self.metadata.created.elapsed().ok();
                true
            }
            _ => false,
        }
    }
}

/// A captured WebSocket conversation (after the HTTP upgrade).
#[derive(Debug, Clone)]
pub struct WsFlow {
    pub id: FlowId,
    /// The originating `HttpFlow` (the 101 upgrade).
    pub handshake: FlowId,
    /// Newest message is `messages.last()`.
    pub messages: Vec<WsMessage>,
    pub client_conn: ConnInfo,
    pub server_conn: Option<ConnInfo>,
    pub metadata: FlowMeta,
    pub intercept: InterceptState,
}

/// An HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// `"https"` after TLS MITM.
    pub scheme: String,
    /// `host[:port]`.
    pub authority: String,
    /// Path plus query.
    pub path: String,
    pub version: HttpVersion,
    pub headers: HeaderMap,
    pub body: Body,
    pub timestamp: SystemTime,
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub version: HttpVersion,
    pub headers: HeaderMap,
    /// Trailer fields received after a chunked body (RFC 9110 6.5), in wire
    /// order with duplicates kept. Held apart from `headers` on purpose and
    /// never merged into them. This is a capture field: no code path writes it
    /// to a wire without the forbidden-name filter. Only HTTP/1.1 chunked
    /// responses populate it; h2 trailers are dropped.
    pub trailers: HeaderMap,
    pub body: Body,
    pub timestamp: SystemTime,
}

/// HTTP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
    H2,
}

/// A single WebSocket frame.
#[derive(Debug, Clone)]
pub struct WsMessage {
    pub dir: WsDir,
    pub opcode: WsOpcode,
    pub data: Vec<u8>,
    pub timestamp: SystemTime,
    /// `true` if a plugin or PoC authored this frame.
    pub injected: bool,
}

/// Direction of a WebSocket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDir {
    ClientToServer,
    ServerToClient,
}

/// WebSocket frame opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// Connection metadata for one side of a flow.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub peer: SocketAddr,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls: bool,
    pub established: SystemTime,
}

/// Per-flow bookkeeping: marks, comment, replay flag, timing, edit state.
#[derive(Debug, Clone)]
pub struct FlowMeta {
    pub marks: Vec<String>,
    pub comment: Option<String>,
    pub is_replay: bool,
    pub created: SystemTime,
    pub duration: Option<Duration>,
    /// The stored copy of a body is incomplete. Either the body exceeded the
    /// configured cap (the client still received the full stream), or the
    /// response ended early (the upstream closed, its read timed out, it sent
    /// malformed bytes, or the client went away) and the client received what
    /// the proxy had forwarded by then. The HTTP modules set it on the cap path;
    /// [`HttpFlow::abandon_response`] sets it on the early-end path.
    pub truncated: bool,
    /// The captured request was edited by `flow.mutate` since capture. Drives the
    /// inspector's "Edited" flag; the original is recoverable while the flow is
    /// still intercepted (`InterceptState::Intercepted { backup }`).
    pub edited: bool,
    /// Arrives as `NextLayerHint::peer_identity` from a capture ingress; `None` for a
    /// proxied, replayed or imported flow.
    /// The signing identifier of the process that opened the client connection, as a
    /// capture backend observed it (macOS NE: `com.apple.Safari`). `None` for a
    /// proxied flow. Backend-supplied text about a client: data to store and show,
    /// never a scope or guard input.
    pub source_app: Option<String>,
    /// The capture backend that delivered the client connection (`"macos-ne"`). `None`
    /// for a proxied flow.
    pub capture_interface: Option<String>,
}

impl Default for FlowMeta {
    fn default() -> Self {
        Self {
            marks: Vec::new(),
            comment: None,
            is_replay: false,
            created: SystemTime::now(),
            duration: None,
            truncated: false,
            edited: false,
            source_app: None,
            capture_interface: None,
        }
    }
}

impl FlowMeta {
    /// A fresh `FlowMeta` carrying only the client's attribution — the two fields a
    /// flow inherits from the connection (HTTP) or from its handshake flow (WebSocket).
    /// Everything else is the default, so a new attribution field is added in one place.
    #[must_use]
    pub fn with_attribution(source_app: Option<String>, capture_interface: Option<String>) -> Self {
        Self {
            source_app,
            capture_interface,
            ..Self::default()
        }
    }

    /// When the flow started: `created` as whole milliseconds since the Unix
    /// epoch, saturated at `i64::MAX`; `None` if the clock is before the epoch.
    /// The one `started_at` rule, so every command surface and push places a
    /// flow at the same time.
    pub fn started_at_ms(&self) -> Option<i64> {
        self.created.duration_since(UNIX_EPOCH).ok().map(whole_ms)
    }

    /// The flow's duration in whole milliseconds, saturated at `i64::MAX`;
    /// `None` while the flow is in flight or its end is unknown. The one
    /// `duration_ms` rule, so `flow.get`, `flow.table` and the pushes cannot
    /// drift.
    pub fn duration_ms(&self) -> Option<i64> {
        self.duration.map(whole_ms)
    }
}

/// A duration as whole milliseconds (the fraction dropped), saturated at
/// `i64::MAX` rather than wrapped or truncated.
fn whole_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// Lifecycle of interception for a single flow.
#[derive(Debug, Clone)]
pub enum InterceptState {
    /// Flowing normally.
    Observed,
    /// Parked as a pausable future; a backup was taken and a resume handle armed.
    Intercepted {
        backup: Box<Flow>,
        resume: ResumeHandle,
    },
    /// Resumed after interception (edits applied, forwarded).
    Resumed,
    /// Dropped; the client sees a reset/closed connection.
    Killed,
}

impl InterceptState {
    /// The lowercase label a command surface reports for this state.
    pub fn label(&self) -> &'static str {
        match self {
            InterceptState::Observed => "observed",
            InterceptState::Intercepted { .. } => "intercepted",
            InterceptState::Resumed => "resumed",
            InterceptState::Killed => "killed",
        }
    }
}

/// Wakes the parked pausable future when a command resumes the flow.
///
/// Oneshot-backed: [`ResumeHandle::new`] returns the handle plus the receiver the
/// parked future awaits; [`ResumeHandle::fire`] wakes it (idempotent).
#[derive(Debug, Clone)]
pub struct ResumeHandle {
    tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl ResumeHandle {
    /// A handle paired with the receiver the parked future should await.
    pub fn new() -> (Self, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        (
            Self {
                tx: Arc::new(Mutex::new(Some(tx))),
            },
            rx,
        )
    }

    /// Wake the parked future. A second call is a no-op.
    pub fn fire(&self) {
        if let Ok(mut guard) = self.tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }
    }
}
