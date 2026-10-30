//! The streamable-HTTP MCP transport (spec §F).
//!
//! A third [`McpTransport`](aitm_core::McpTransport) alongside stdio and
//! loopback-TCP: one HTTP endpoint at `path` that runs the same
//! [`McpServer::handle_on`] dispatch as the other transports, under a
//! [`Frontend::Mcp`] role. Because this exposes a MITM proxy *control plane*
//! over a network socket, every request passes four **fail-closed** guards,
//! checked in order before any dispatch:
//!
//! 1. **Auth** — `Authorization: Bearer <token>` must constant-time-equal the
//!    configured token, else `401` (the token is never echoed).
//! 2. **Origin** — a present `Origin` header must be in `allowed_origins`, else
//!    `403` (an empty allowlist rejects any present `Origin`; an absent one is
//!    allowed — same-origin / no-Origin tools still work).
//! 3. **Host** — the `Host` header must be a loopback literal or the authority
//!    of an allowlisted origin, else `403` (DNS-rebinding defence).
//! 4. **Method/path** — anything but `POST`/`GET` on `path` → `405`; a wrong
//!    path → `404`.
//!
//! The listener binds loopback by default; binding any other interface is an
//! explicit operator decision carried on the config's `bind`. The token and the
//! `Authorization` header are never logged; the single startup line goes to
//! stderr.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aitm_core::Frontend;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value as JsonValue;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::server::{ConnCtx, McpServer, NotificationSink};
use crate::transport::MAX_MESSAGE_BYTES;

/// The response body type the endpoint produces: a single boxed body so the
/// unary JSON answers and the streaming SSE lane share one `Response` type.
type SvcBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// Configuration for [`StreamableHttp::bind`] — the four fields of
/// [`McpTransport::StreamableHttp`](aitm_core::McpTransport::StreamableHttp).
#[derive(Debug, Clone)]
pub struct StreamableHttpCfg {
    /// The interface/port to bind (loopback by default).
    pub bind: SocketAddr,
    /// The required non-empty Bearer token.
    pub token: String,
    /// The exact `Origin` allowlist (empty = no cross-origin accepted).
    pub allowed_origins: Vec<String>,
    /// The request path the endpoint is served at (e.g. `/mcp`).
    pub path: String,
}

/// A bound streamable-HTTP MCP listener. Built by [`StreamableHttp::bind`],
/// driven by [`StreamableHttp::serve`].
pub struct StreamableHttp {
    listener: TcpListener,
    local_addr: SocketAddr,
    guard: Arc<Guard>,
}

/// The per-request guard state, shared (via `Arc`) across every connection.
struct Guard {
    token: String,
    allowed_origins: Vec<String>,
    path: String,
}

impl StreamableHttp {
    /// Bind `cfg.bind` (loopback by default) and return a ready listener. The
    /// token must be non-empty — a tokenless control plane is refused here, not
    /// at request time.
    pub async fn bind(cfg: StreamableHttpCfg) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.token.is_empty(),
            "the streamable-HTTP transport requires a non-empty token"
        );
        let listener = TcpListener::bind(cfg.bind).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            guard: Arc::new(Guard {
                token: cfg.token,
                allowed_origins: cfg.allowed_origins,
                path: cfg.path,
            }),
        })
    }

    /// The bound address (useful after binding port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept connections forever, serving each on its own task. Emits one
    /// startup line to stderr (never the token). Every request runs the four
    /// fail-closed guards before any dispatch.
    pub async fn serve(self, server: Arc<McpServer>) -> anyhow::Result<()> {
        // Operator-first-run hygiene: one quiet line, to stderr, never the token.
        eprintln!(
            "MCP streamable HTTP listening on {}{}",
            self.local_addr, self.guard.path
        );
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let io = TokioIo::new(stream);
            let guard = self.guard.clone();
            let server = server.clone();
            let service = service_fn(move |req| {
                let guard = guard.clone();
                let server = server.clone();
                async move { Ok::<_, Infallible>(handle(req, guard, server).await) }
            });
            tokio::spawn(async move {
                // A failed connection is that client's problem, not the server's.
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    }
}

/// Dispatch one request through the four fail-closed guards, then route it.
async fn handle(
    req: Request<Incoming>,
    guard: Arc<Guard>,
    server: Arc<McpServer>,
) -> Response<SvcBody> {
    // Guard 1: Bearer auth (constant-time). Never echo the token.
    let authorized = header(&req, AUTHORIZATION);
    if !check_bearer(authorized.as_deref(), &guard.token) {
        return status(StatusCode::UNAUTHORIZED);
    }
    // Guard 2: Origin allowlist.
    if !origin_allowed(header(&req, ORIGIN).as_deref(), &guard.allowed_origins) {
        return status(StatusCode::FORBIDDEN);
    }
    // Guard 3: Host / DNS-rebinding.
    if !host_allowed(header(&req, HOST).as_deref(), &guard.allowed_origins) {
        return status(StatusCode::FORBIDDEN);
    }
    // Guard 4: method/path.
    if req.uri().path() != guard.path {
        return status(StatusCode::NOT_FOUND);
    }
    match *req.method() {
        Method::POST => handle_post(req, server).await,
        Method::GET => handle_get(server),
        _ => status(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// POST: the body is one JSON-RPC message (or a batch array). Each message is
/// dispatched through [`McpServer::handle_on`] under a fresh [`Frontend::Mcp`]
/// connection; the reply (if any) is returned as `application/json`.
async fn handle_post(req: Request<Incoming>, server: Arc<McpServer>) -> Response<SvcBody> {
    // Bound the request body: an oversized body is refused, never buffered whole.
    let collected = match Limited::new(req.into_body(), MAX_MESSAGE_BYTES)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => return status(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let text = String::from_utf8_lossy(&collected).into_owned();

    // A batch (JSON array) is dispatched element by element; a single message is
    // passed through verbatim so `handle_on`'s own parse-error envelope stands.
    let reply = match serde_json::from_str::<JsonValue>(&text) {
        Ok(JsonValue::Array(items)) => dispatch_batch(server, items).await,
        _ => dispatch_one(server, text).await,
    };

    match reply {
        Some(body) => json_response(body),
        // Notifications (no reply) are acknowledged with `202 Accepted`.
        None => status(StatusCode::ACCEPTED),
    }
}

/// Dispatch a single message on the blocking pool (a slow tool must not stall
/// the runtime, mirroring `serve_lines`). Returns the reply line, if any.
async fn dispatch_one(server: Arc<McpServer>, message: String) -> Option<String> {
    tokio::task::spawn_blocking(move || server.handle_on(&ConnCtx::new(Frontend::Mcp), &message))
        .await
        .ok()
        .flatten()
}

/// Dispatch a batch, collecting the replies into a JSON array string. An
/// all-notification batch yields `None` (no reply), matching JSON-RPC batching.
async fn dispatch_batch(server: Arc<McpServer>, items: Vec<JsonValue>) -> Option<String> {
    let mut replies: Vec<JsonValue> = Vec::new();
    for item in items {
        if let Some(line) = dispatch_one(server.clone(), item.to_string()).await {
            if let Ok(v) = serde_json::from_str::<JsonValue>(&line) {
                replies.push(v);
            }
        }
    }
    (!replies.is_empty()).then(|| JsonValue::Array(replies).to_string())
}

/// GET: open a `text/event-stream` lane the server writes `notifications/aitm/*`
/// to (mirroring `serve_lines`' writer task). The lane exists so Streamable-HTTP
/// server→client notifications have a channel; it is drained to SSE `data:`
/// frames and torn down when the client disconnects.
fn handle_get(server: Arc<McpServer>) -> Response<SvcBody> {
    let sink = NotificationSink::new(server.push_capacity());
    let conn_id = server.next_conn_id();
    let (tx, rx) = mpsc::channel::<Bytes>(1);

    // A writer task drains the sink to the SSE channel; it ends when the client
    // drops the response body (the send fails) or the sink closes.
    tokio::spawn({
        let sink = sink.clone();
        async move {
            // An opening comment flushes response headers and keeps proxies warm.
            if tx
                .send(Bytes::from_static(b": connected\n\n"))
                .await
                .is_err()
            {
                return;
            }
            loop {
                for line in sink.drain() {
                    let frame = Bytes::from(format!("data: {line}\n\n"));
                    if tx.send(frame).await.is_err() {
                        server.drop_connection(conn_id);
                        return;
                    }
                }
                if sink.is_closed_and_drained() {
                    break;
                }
                sink.wait().await;
            }
            server.drop_connection(conn_id);
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream")
        .header("Cache-Control", "no-store")
        .body(SseBody { rx }.boxed_unsync())
        .expect("a well-formed SSE response")
}

/// A streaming body over the SSE notification channel.
struct SseBody {
    rx: mpsc::Receiver<Bytes>,
}

impl Body for SseBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ----------------------------------------------------------------- guards

/// The first value of `name`, as an owned `String`; `None` if absent or not
/// valid UTF-8 (a header we cannot read is treated as absent — fail closed).
fn header(req: &Request<Incoming>, name: hyper::header::HeaderName) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Guard 1: `Authorization: Bearer <token>` constant-time-equal to `token`.
/// A missing header, a non-`Bearer` scheme, or a mismatch all fail closed.
fn check_bearer(header: Option<&str>, token: &str) -> bool {
    let Some(h) = header else {
        return false;
    };
    let Some((scheme, value)) = h.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return false;
    }
    constant_time_eq(value.as_bytes(), token.as_bytes())
}

/// Guard 2: a present `Origin` must be in `allowed`; an absent one is allowed
/// (same-origin / no-Origin). An empty allowlist rejects any present `Origin`.
fn origin_allowed(origin: Option<&str>, allowed: &[String]) -> bool {
    match origin {
        None => true,
        Some(o) => allowed.iter().any(|a| a == o),
    }
}

/// Guard 3: the `Host` must be a loopback literal or the authority of an
/// allowlisted origin. A missing `Host` fails closed. Blocks a rebound DNS name
/// that resolves to loopback.
fn host_allowed(host: Option<&str>, allowed_origins: &[String]) -> bool {
    let Some(host) = host else {
        return false;
    };
    if is_loopback_host(host) {
        return true;
    }
    // An operator who allowlists a cross-origin host (via `allowed_origins`) may
    // also reach it by that authority; match the origin's `host[:port]`.
    allowed_origins
        .iter()
        .filter_map(|o| origin_authority(o))
        .any(|a| a == host)
}

/// Whether `host` (a `Host` header, optionally `:port`) names loopback:
/// `127.0.0.1`, `::1` (bracketed or not), or `localhost`.
fn is_loopback_host(host: &str) -> bool {
    matches!(host_name(host), "127.0.0.1" | "::1" | "localhost")
}

/// The hostname part of a `Host`/authority value, dropping any `:port` and the
/// brackets around an IPv6 literal (`[::1]:8084` → `::1`).
fn host_name(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // `[::1]` or `[::1]:port`.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match host.rsplit_once(':') {
        // `name:port` only when the suffix is all digits; a bare IPv6 has none.
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// The authority (`host[:port]`) of an origin like `https://evil.test:8443`.
fn origin_authority(origin: &str) -> Option<&str> {
    origin
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(rest))
}

/// Constant-time byte equality (length-safe): compares every byte of `expected`
/// so timing does not reveal a token prefix.
fn constant_time_eq(given: &[u8], expected: &[u8]) -> bool {
    let mut diff = given.len() ^ expected.len();
    for (i, &e) in expected.iter().enumerate() {
        diff |= usize::from(e ^ given.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

// ------------------------------------------------------------- responses

/// A `200 application/json` response carrying `body`.
fn json_response(body: String) -> Response<SvcBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(full(body))
        .expect("a well-formed JSON response")
}

/// A bodyless response with just `code`.
fn status(code: StatusCode) -> Response<SvcBody> {
    Response::builder()
        .status(code)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("a well-formed empty response")
}

/// Box a full buffered body into the endpoint's one body type.
fn full(body: impl Into<Bytes>) -> SvcBody {
    Full::new(body.into())
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_constant_time_compare() {
        assert!(check_bearer(Some("Bearer s3cret"), "s3cret"));
        // Scheme is case-insensitive; the token is not.
        assert!(check_bearer(Some("bearer s3cret"), "s3cret"));
        assert!(!check_bearer(Some("Bearer S3CRET"), "s3cret"));
        assert!(!check_bearer(Some("Bearer wrong"), "s3cret"));
        assert!(!check_bearer(Some("Bearer "), "s3cret"));
        assert!(!check_bearer(Some("s3cret"), "s3cret")); // no scheme
        assert!(!check_bearer(Some("Basic s3cret"), "s3cret")); // wrong scheme
        assert!(!check_bearer(None, "s3cret")); // missing header
    }

    #[test]
    fn origin_allowlist() {
        // Absent Origin is allowed (same-origin / no-Origin).
        assert!(origin_allowed(None, &[]));
        assert!(origin_allowed(None, &["https://ok.test".into()]));
        // Empty allowlist rejects any present Origin.
        assert!(!origin_allowed(Some("https://evil.test"), &[]));
        // Exact match only.
        assert!(origin_allowed(
            Some("https://ok.test"),
            &["https://ok.test".into()]
        ));
        assert!(!origin_allowed(
            Some("https://evil.test"),
            &["https://ok.test".into()]
        ));
    }

    #[test]
    fn host_loopback_and_allowlist() {
        // Loopback literals, with and without a port, v4 and v6.
        assert!(host_allowed(Some("127.0.0.1"), &[]));
        assert!(host_allowed(Some("127.0.0.1:8084"), &[]));
        assert!(host_allowed(Some("localhost"), &[]));
        assert!(host_allowed(Some("localhost:8084"), &[]));
        assert!(host_allowed(Some("[::1]"), &[]));
        assert!(host_allowed(Some("[::1]:8084"), &[]));
        // A rebound DNS name that is not loopback is refused.
        assert!(!host_allowed(Some("attacker.example"), &[]));
        assert!(!host_allowed(Some("attacker.example:8084"), &[]));
        // A missing Host fails closed.
        assert!(!host_allowed(None, &[]));
        // An operator-allowlisted origin's authority is accepted as a Host.
        assert!(host_allowed(
            Some("proxy.internal:8084"),
            &["https://proxy.internal:8084".into()]
        ));
    }

    #[test]
    fn origin_authority_strips_scheme_and_path() {
        assert_eq!(origin_authority("https://evil.test"), Some("evil.test"));
        assert_eq!(origin_authority("http://host:8443/mcp"), Some("host:8443"));
        assert_eq!(origin_authority("no-scheme"), None);
    }
}
