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

/// How a `CONNECT` (or raw TLS) connection was handled: the outcome of one
/// tunnel row (spec D5). Stored in [`FlowMeta::tunnel`]; `None` there means the
/// flow is not a tunnel row at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    /// TLS terminated with the proxy's leaf; the inner requests are their own rows.
    Decrypted,
    /// Relayed byte for byte to the origin; the client saw the origin's own
    /// certificate. [`TunnelInfo::reason`] is `OutOfScope` or `Pinned`.
    Passthrough,
    /// The tunnel never became established. [`TunnelInfo::reason`] is one of the
    /// six failure codes.
    Failed,
}

impl TunnelMode {
    /// Every variant, in wire-code order: the one list a surface enumerates or
    /// reverses labels through ([`Self::from_label`]). `flow_model.rs` pins its
    /// length to the variant count, so it cannot silently fall behind the enum.
    pub const ALL: [TunnelMode; 3] = [
        TunnelMode::Decrypted,
        TunnelMode::Passthrough,
        TunnelMode::Failed,
    ];

    /// The wire code every surface emits as `tunnel` (spec D7).
    pub fn label(&self) -> &'static str {
        match self {
            TunnelMode::Decrypted => "decrypted",
            TunnelMode::Passthrough => "passthrough",
            TunnelMode::Failed => "failed",
        }
    }

    /// The inverse of [`Self::label`]: the mode whose wire code is exactly
    /// `label` (no case folding); `None` for a code this build does not know (a
    /// newer writer, a hand-edited file).
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.label() == label)
    }
}

/// Why a tunnel was passed through or failed (spec D5). `OutOfScope` and `Pinned`
/// accompany [`TunnelMode::Passthrough`]; the rest accompany [`TunnelMode::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelReason {
    /// The authority is not in Scope, so the proxy did not decrypt it.
    OutOfScope,
    /// The host is on the `tls.passthrough` list; pins win over Scope.
    Pinned,
    /// The client-facing handshake ended with a certificate-family TLS alert: the
    /// client refused the proxy's CA (Safari, `curl` without `--cacert`).
    ClientRejectedCertificate,
    /// EOF, reset or broken pipe from the client before the tunnel was established.
    ClientClosed,
    /// Any other client-side TLS alert or protocol error.
    ClientTlsError,
    /// DNS, refused, timed out or any I/O failure dialling the origin.
    UpstreamUnreachable,
    /// The origin's TLS handshake failed or timed out.
    UpstreamTlsFailed,
    /// Anything else: a malformed `CONNECT` head, an h2-to-h1 mirror refusal, TLS
    /// without an SNI the proxy could decrypt.
    ProtocolError,
}

impl TunnelReason {
    /// Every variant, in wire-code order (the two passthrough reasons, then the
    /// six failure codes of spec D5): the one list a surface enumerates or
    /// reverses labels through ([`Self::from_label`]). `flow_model.rs` pins its
    /// length to the variant count.
    pub const ALL: [TunnelReason; 8] = [
        TunnelReason::OutOfScope,
        TunnelReason::Pinned,
        TunnelReason::ClientRejectedCertificate,
        TunnelReason::ClientClosed,
        TunnelReason::ClientTlsError,
        TunnelReason::UpstreamUnreachable,
        TunnelReason::UpstreamTlsFailed,
        TunnelReason::ProtocolError,
    ];

    /// The wire code every surface emits as `tunnel_reason` (spec D7).
    pub fn label(&self) -> &'static str {
        match self {
            TunnelReason::OutOfScope => "out_of_scope",
            TunnelReason::Pinned => "pinned",
            TunnelReason::ClientRejectedCertificate => "client_rejected_certificate",
            TunnelReason::ClientClosed => "client_closed",
            TunnelReason::ClientTlsError => "client_tls_error",
            TunnelReason::UpstreamUnreachable => "upstream_unreachable",
            TunnelReason::UpstreamTlsFailed => "upstream_tls_failed",
            TunnelReason::ProtocolError => "protocol_error",
        }
    }

    /// The inverse of [`Self::label`]: the reason whose wire code is exactly
    /// `label` (no case folding); `None` for a code this build does not know.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.label() == label)
    }
}

/// The tunnel fields of a `CONNECT` row (spec D5): the outcome, the reason when
/// there is one, and the byte counts a passthrough tunnel reports when it closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInfo {
    pub mode: TunnelMode,
    /// `None` for a decrypted tunnel; set for passthrough and failed ones.
    pub reason: Option<TunnelReason>,
    /// Client-to-origin bytes relayed; set when a passthrough tunnel closes.
    pub bytes_up: Option<u64>,
    /// Origin-to-client bytes relayed; set when a passthrough tunnel closes.
    pub bytes_down: Option<u64>,
}

impl TunnelInfo {
    /// A tunnel relayed byte for byte, for `reason` (`OutOfScope` or `Pinned`).
    /// Byte counts are `None` until the relay closes.
    #[must_use]
    pub fn passthrough(reason: TunnelReason) -> Self {
        Self {
            mode: TunnelMode::Passthrough,
            reason: Some(reason),
            bytes_up: None,
            bytes_down: None,
        }
    }

    /// A tunnel the proxy terminated with its own leaf.
    #[must_use]
    pub fn decrypted() -> Self {
        Self {
            mode: TunnelMode::Decrypted,
            reason: None,
            bytes_up: None,
            bytes_down: None,
        }
    }

    /// A tunnel that never became established, for one of the failure reasons.
    #[must_use]
    pub fn failed(reason: TunnelReason) -> Self {
        Self {
            mode: TunnelMode::Failed,
            reason: Some(reason),
            bytes_up: None,
            bytes_down: None,
        }
    }
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
    /// Observed only, nothing acted on it (spec D4): plain HTTP to a host outside
    /// Scope is stored and shown, but no intercept rule parks it, no script sees it
    /// and no scanner touches it. A tunnel row is dispatched passively by virtue of
    /// `tunnel.is_some()`, so this stays `false` on it.
    pub passive: bool,
    /// The tunnel fields when this flow is a `CONNECT` row (spec D5); `None` for
    /// every other flow.
    pub tunnel: Option<TunnelInfo>,
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
            passive: false,
            tunnel: None,
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

    /// The terminal rule of spec D5 for a tunnel row: closed (or failed) iff this
    /// *is* a tunnel row (`tunnel.is_some()`) and its `duration` is set, which
    /// the producer does exactly once, when the tunnel closes or fails. The mode
    /// and the `200` acknowledgement an established tunnel carries play no part;
    /// the store consults this for `clear` and eviction. `false` for a flow that
    /// is not a tunnel row, however finished.
    pub fn tunnel_is_closed(&self) -> bool {
        self.tunnel.is_some() && self.duration.is_some()
    }
}

/// A duration as whole milliseconds (the fraction dropped), saturated at
/// `i64::MAX` rather than wrapped or truncated.
fn whole_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// A byte count as the bus integer: `n` itself when it fits, else `i64::MAX` —
/// saturated, never wrapped negative (the rule `duration_ms` follows). The one
/// place `flow.get`, `flow.table`, `flow.detail` and the push summary convert a
/// tunnel's `bytes_up` / `bytes_down`.
pub fn saturating_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
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
