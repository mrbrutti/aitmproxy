//! The `/bus` WebSocket bridge (design §4.9): a relay of newline-delimited
//! JSON-RPC lines between a browser and the in-process `McpServer`, and of the
//! server's push notifications back to the browser. The first text frame must be
//! the token line `{"token":"…"}`, exactly as `LoopbackTcp` requires on its first
//! line; every later text frame holds one or more lines.
//!
//! An authenticated connection is one `ConnCtx`: its role, a unique `conn_id`,
//! and a bounded `NotificationSink`, shared by every frame it sends. That is what
//! lets `flow.subscribe` work here as it does over loopback TCP: a subscription is
//! tagged with the connection and dropped when the connection ends, on every exit
//! path. Frames are detached rather than cancelled, so one may still be running
//! at that point; the sink is closed before the subscriptions are dropped, and
//! the registry refuses a subscribe on a closed sink, so a late `flow.subscribe`
//! from such a frame registers nothing. The relay drains the sink onto the
//! socket, one text frame per notification line, interleaved with replies. The
//! notification lane is bounded by the server's `push_capacity` (drop-oldest,
//! then a `notifications/aitm/state {lagged:true}` marker on the next drain), so
//! a client that stops reading cannot grow server memory.
//!
//! Replies do not ride the sink: a finished frame's replies go straight to the
//! socket in line order, so a notification burst never delays them and a reply is
//! never queued twice or dropped. The two paths share one socket, so a
//! notification can arrive before the reply carrying its `sub_id`; clients
//! correlate replies by JSON-RPC `id`, as over TCP.
//!
//! A frame is the unit of work. The lines inside one frame run in order and are
//! answered in order, one text frame per reply, once the whole frame is done. A
//! frame may carry at most `MAX_LINES_PER_FRAME` lines; a client that sends more
//! is closed (`Size`) before any of its lines runs.
//!
//! Frames run concurrently (up to `MAX_IN_FLIGHT` per connection), so a
//! long-running command — `scan.discover` can run for minutes — never freezes the
//! other requests on the same socket; replies across frames arrive in completion
//! order and clients correlate them by JSON-RPC `id`. Clients that need one
//! request's effect before the next must wait for its reply; a Close or disconnect
//! discards replies still in flight. At the in-flight cap the loop stops reading,
//! so a client Close or disconnect is only noticed once a frame finishes — bounded
//! by those in-flight frames' own completion. All policy stays in the core: the
//! bridge authenticates, splits lines, and forwards.

use std::sync::Arc;
use std::time::Duration;

use aitm_core::Frontend;
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::{SinkExt as _, StreamExt as _};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value as JsonValue;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

use super::WebState;

/// Same bound as the MCP transports (`aitm-mcp` `MAX_MESSAGE_BYTES`).
pub const MAX_MESSAGE_BYTES: usize = 16 << 20;

/// A client must send its token within this budget after the upgrade. Without
/// it a peer that upgrades then stalls — or sends only pings / whitespace — pins
/// the connection and its task indefinitely, all *before* `classify_token`: an
/// unauthenticated connection-exhaustion DoS (remote under
/// `AITM_WEB_INSECURE_BIND`). The deadline is absolute, so pings cannot extend it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A peer being refused must finish the close handshake within this budget. `close`
/// sends our Close frame and then reads until the peer answers it; without a
/// deadline a peer that never answers — or keeps sending data — pins the
/// connection's task and socket indefinitely, including on the pre-auth refusals
/// that [`HANDSHAKE_TIMEOUT`] exists to bound. Past the deadline the connection is
/// dropped; that is not an error.
const CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The most frames one connection may have running at once. At the cap the relay
/// stops reading further frames (TCP backpressure) until one finishes, so neither
/// blocking tasks nor queued frames can grow without bound however fast a peer
/// sends. Each frame holds one blocking-pool thread while its commands run.
///
/// The cost of that backpressure: at the cap the loop is not reading at all, so a
/// client Close or disconnect is only noticed once a frame finishes — bounded by
/// the in-flight frames' own completion, however long their commands run.
pub const MAX_IN_FLIGHT: usize = 16;

// With a zero cap the relay's read branch would never be enabled, so an
// authenticated connection could never send a frame.
const _: () = assert!(MAX_IN_FLIGHT > 0);

/// The most request lines one text frame may carry. A frame is dispatched line by
/// line and its replies are held until the whole frame is done, so an unbounded
/// frame is a post-auth CPU/memory amplifier: one 16 MiB frame can hold hundreds
/// of thousands of tiny lines, and up to [`MAX_IN_FLIGHT`] such frames may be in
/// flight on one connection. A frame carrying more is refused — the connection is
/// closed with `Size` — before any of its lines is dispatched. The 16 MiB message
/// bound still applies independently. Same figure as `MAX_BATCH_LEN` in the MCP
/// HTTP transport. The token line is not a request and does not count.
const MAX_LINES_PER_FRAME: usize = 256;

/// The `Size` close reason for a frame over [`MAX_LINES_PER_FRAME`].
const TOO_MANY_LINES: &str = "too many lines in one frame";

/// JSON-RPC error code for a refused token (matches `LoopbackTcp`).
pub const UNAUTHORIZED: i64 = -32001;

/// The reply to a bad or missing token line.
pub const UNAUTHORIZED_REPLY: &str =
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"unauthorized"}}"#;

/// The outcome of validating an upgrade request.
pub enum Handshake {
    /// Send this `101 Switching Protocols` and take the connection over.
    Accept(Response<Full<Bytes>>),
    /// Send this refusal (400/403/426) as an ordinary response.
    Refuse(Response<Full<Bytes>>),
}

/// Validate the RFC 6455 upgrade request.
///
/// Origin policy: the UI is same-origin, so when a browser sends `Origin` its
/// authority must equal the request `Host`. Anything else is a cross-site
/// WebSocket hijack attempt and is refused before the upgrade.
pub fn handshake(req: &Request<Incoming>) -> Handshake {
    use Handshake::Refuse;
    let headers = req.headers();
    if !header_eq_ignore_case(headers, header::UPGRADE, "websocket") {
        return Refuse(plain(
            StatusCode::UPGRADE_REQUIRED,
            "websocket upgrade required",
        ));
    }
    if !connection_has_upgrade(headers) {
        return Refuse(plain(
            StatusCode::BAD_REQUEST,
            "Connection: Upgrade required",
        ));
    }
    if !header_eq_ignore_case(headers, header::SEC_WEBSOCKET_VERSION, "13") {
        return Refuse(plain(
            StatusCode::BAD_REQUEST,
            "unsupported Sec-WebSocket-Version",
        ));
    }
    let Some(key) = headers.get(header::SEC_WEBSOCKET_KEY) else {
        return Refuse(plain(StatusCode::BAD_REQUEST, "missing Sec-WebSocket-Key"));
    };
    if !origin_allowed(headers) {
        return Refuse(plain(StatusCode::FORBIDDEN, "origin not allowed"));
    }
    let accept = derive_accept_key(key.as_bytes());
    match Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(Full::new(Bytes::new()))
    {
        Ok(resp) => Handshake::Accept(resp),
        Err(_) => Refuse(plain(
            StatusCode::INTERNAL_SERVER_ERROR,
            "response build failed",
        )),
    }
}

/// Drive one upgraded connection until it closes. Spawned by the router after
/// the 101 is sent; `on_upgrade` resolves once hyper hands the socket over.
pub async fn run(on_upgrade: hyper::upgrade::OnUpgrade, state: Arc<WebState>) {
    let upgraded = match on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            debug!(error = %e, "websocket upgrade did not complete");
            return;
        }
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let ws =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(config)).await;
    if let Err(e) = relay(ws, &state).await {
        debug!(error = %e, "websocket bridge ended with an error");
    }
}

type Ws = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

async fn relay(mut ws: Ws, state: &WebState) -> anyhow::Result<()> {
    // Authentication: the first non-empty line of the first text frame. The
    // token's class picks the role every later line runs as.
    let pending: Vec<String>;
    let role;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let next = match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(next) => next,
            Err(_) => {
                debug!("web bus: authentication timed out before a token arrived");
                return close(ws, CloseCode::Policy, "authentication timeout").await;
            }
        };
        match next {
            Some(Ok(Message::Text(text))) => {
                let mut lines = lines_of(text.as_str());
                let Some(first) = lines.next() else {
                    continue; // whitespace only; wait for a real first line
                };
                let Some(resolved) = classify_token(first, state) else {
                    warn!("web bus: refused a connection with a bad token");
                    ws.send(Message::text(UNAUTHORIZED_REPLY)).await?;
                    return close(ws, CloseCode::Policy, "unauthorized").await;
                };
                // The lines that share the token's frame are ordinary requests and
                // answer to the same cap; only an authenticated peer gets here.
                let Some(rest) = bounded_lines(lines) else {
                    return close(ws, CloseCode::Size, TOO_MANY_LINES).await;
                };
                role = resolved;
                pending = rest;
                break;
            }
            Some(Ok(Message::Binary(_))) => {
                return close(ws, CloseCode::Unsupported, "text frames only").await;
            }
            Some(Ok(Message::Close(frame))) => {
                debug!(?frame, "websocket closed before authenticating");
                return Ok(());
            }
            Some(Ok(_)) => continue, // ping/pong: tungstenite answers them
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(()),
        }
    }
    debug!(?role, "web bus: connection authenticated");

    // The connection's one `ConnCtx`, minted only now that the peer has
    // authenticated: every frame runs under it, its sink is where the server
    // pushes this connection's notifications, and its id is what sweeps the
    // connection's subscriptions. The guard runs that teardown when this
    // function returns by any path, a panicked frame included.
    let sink = NotificationSink::new(state.mcp.push_capacity());
    let conn = Arc::new(ConnCtx {
        role,
        client_label: None,
        conn_id: state.mcp.next_conn_id(),
        out: Some(sink.clone()),
    });
    let guard = ConnGuard {
        mcp: Arc::clone(&state.mcp),
        conn_id: conn.conn_id,
        sink: sink.clone(),
    };

    // One task per frame, so a slow command (its blocking `invoke`) cannot stall
    // the reads and replies of the other frames on this socket. At most
    // `MAX_IN_FLIGHT` run at once; at the cap the loop stops reading (the read
    // branch below is disabled) until one finishes.
    //
    // When this function returns — client close, a transport error, a command that
    // panicked — the still-running frames are detached, not cancelled: a blocking
    // `Command::invoke` cannot be interrupted, so each runs to completion on its
    // blocking thread and its replies are dropped with the connection.
    let mut in_flight: FuturesUnordered<FrameTask> = FuturesUnordered::new();

    // Any lines that shared the token's frame are the first frame in flight.
    if !pending.is_empty() {
        in_flight.push(dispatch_frame(&state.mcp, &conn, pending));
    }

    loop {
        tokio::select! {
            // A frame finished: send its replies, in line order, one text frame
            // each. A panicked command surfaces as a `JoinError` and ends the
            // connection with an error.
            Some(done) = in_flight.next(), if !in_flight.is_empty() => {
                for reply in done? {
                    ws.send(Message::text(reply)).await?;
                }
            }
            // The server pushed to this connection: drain the sink and send each
            // line as one text frame. Not gated on the in-flight cap, so pushes
            // keep flowing while the read branch is paused. `Notify` stores a
            // permit, so a push that lands while another branch is mid-send is
            // taken on the next turn; a spurious wake drains nothing.
            _ = sink.wait() => {
                for line in sink.drain() {
                    ws.send(Message::text(line)).await?;
                }
            }
            next = ws.next(), if in_flight.len() < MAX_IN_FLIGHT => match next {
                Some(Ok(Message::Text(text))) => {
                    let Some(lines) = bounded_lines(lines_of(text.as_str())) else {
                        return refuse(ws, in_flight, guard, CloseCode::Size, TOO_MANY_LINES)
                            .await;
                    };
                    if !lines.is_empty() {
                        in_flight.push(dispatch_frame(&state.mcp, &conn, lines));
                    }
                }
                Some(Ok(Message::Binary(_))) => {
                    return refuse(
                        ws,
                        in_flight,
                        guard,
                        CloseCode::Unsupported,
                        "text frames only",
                    )
                    .await;
                }
                Some(Ok(Message::Close(frame))) => {
                    debug!(?frame, "websocket closed by the client");
                    return Ok(());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => debug!("websocket ping/pong"),
                Some(Ok(Message::Frame(_))) => {} // never surfaced on read
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            },
        }
    }
}

/// A frame's worth of work in flight: the replies its lines produced, in line
/// order (a notification yields none).
type FrameTask = tokio::task::JoinHandle<Vec<String>>;

/// Hand one frame's JSON-RPC lines to the core on a blocking thread (each
/// command's `invoke` runs synchronously there, as `transport::serve_lines` does)
/// under the connection's shared `ConnCtx`. The lines run **in order**, so the
/// returned replies are in the order the lines were sent; the caller sends them as
/// one text frame each once the whole frame is done. The context's role makes the
/// browser's own `initialize` reply carry the right `role` echo and gates commands
/// exactly as the other frontends do; its sink and id are what `flow.subscribe`
/// attaches to. Concurrency is across frames, never within one.
///
/// A line that panics discards the replies the frame's earlier lines produced
/// (they are held until the frame is done) and ends the connection.
fn dispatch_frame(mcp: &Arc<McpServer>, conn: &Arc<ConnCtx>, lines: Vec<String>) -> FrameTask {
    let mcp = Arc::clone(mcp);
    let conn = Arc::clone(conn);
    tokio::task::spawn_blocking(move || {
        lines
            .iter()
            .filter_map(|line| mcp.handle_on(&conn, line))
            .collect()
    })
}

/// Tears down a connection's server-side state when it ends. Held by `relay`
/// from authentication on, so it runs whichever way `relay` returns: client
/// Close, stream end, a transport error, a refusal, a panicked frame. It closes
/// the sink first and drops the connection's subscriptions second. The order
/// matters: a detached frame may run `flow.subscribe` after this; the registry
/// refuses a subscribe on a closed sink under its own lock, and one that slipped
/// in before the close is swept by the drop, so no subscription outlives its
/// connection (spec D4).
struct ConnGuard {
    mcp: Arc<McpServer>,
    conn_id: u64,
    sink: NotificationSink,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.sink.close();
        self.mcp.drop_connection(self.conn_id);
    }
}

/// Resolve the first-line token to a role, comparing in constant time against
/// each configured bridge token. The agent token is tried first; the operator
/// token only when `mcp.operator_token` was configured to a non-empty value (so
/// it is `Some` and not `""`). An empty operator token means "not configured",
/// mirroring `LoopbackTcp::with_operator_token`, so a `{"token":""}` line never
/// resolves to operator. `None` ⇒ the token matched neither and the connection
/// must be refused.
fn classify_token(first: &str, state: &WebState) -> Option<Frontend> {
    if token_line_matches(first, &state.agent_token) {
        return Some(Frontend::Mcp);
    }
    if let Some(op) = state.operator_token.as_deref().filter(|t| !t.is_empty()) {
        if token_line_matches(first, op) {
            return Some(Frontend::Operator);
        }
    }
    None
}

/// Refuse the peer after authentication: drop the frames in flight and the
/// connection's subscriptions, then close. Dropping the handles frees the replies
/// already produced rather than holding them (up to `MAX_IN_FLIGHT` ×
/// [`MAX_LINES_PER_FRAME`]) for the whole close handshake; the blocking tasks
/// still running are detached, as when the connection ends any other way.
/// Dropping the guard before the handshake means a peer that will not answer our
/// Close neither counts as a connected subscriber nor is pushed to for the whole
/// drain budget.
async fn refuse(
    ws: Ws,
    in_flight: FuturesUnordered<FrameTask>,
    guard: ConnGuard,
    code: CloseCode,
    reason: &'static str,
) -> anyhow::Result<()> {
    drop(in_flight);
    drop(guard);
    close(ws, code, reason).await
}

async fn close(ws: Ws, code: CloseCode, reason: &'static str) -> anyhow::Result<()> {
    close_within(ws, code, reason, CLOSE_DRAIN_TIMEOUT).await
}

/// Send a Close frame and wait for the peer to answer it, for at most `limit`
/// (covering our write as well as the drain, so a peer that stops reading cannot
/// stall it either). Running out of time is not an error: the connection is
/// dropped, which is all a peer that will not finish the handshake is owed.
async fn close_within<S>(
    mut ws: WebSocketStream<S>,
    code: CloseCode,
    reason: &'static str,
    limit: Duration,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    let handshake = async {
        if let Err(e) = ws.close(Some(frame)).await {
            debug!(error = %e, "websocket close failed");
            return;
        }
        // Drain so the close handshake completes and the client sees our frame.
        while let Some(Ok(_)) = ws.next().await {}
    };
    if tokio::time::timeout(limit, handshake).await.is_err() {
        debug!("websocket close handshake timed out; dropping the connection");
    }
    Ok(())
}

/// Non-empty, trimmed lines of a frame.
fn lines_of(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n').map(str::trim).filter(|l| !l.is_empty())
}

/// Own `lines` for dispatch, or `None` when there are more than
/// [`MAX_LINES_PER_FRAME`]. At most one line past the cap is read and copied, so
/// refusing an oversized frame costs a bounded amount however many lines it holds.
fn bounded_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Option<Vec<String>> {
    let owned: Vec<String> = lines
        .take(MAX_LINES_PER_FRAME + 1)
        .map(str::to_owned)
        .collect();
    (owned.len() <= MAX_LINES_PER_FRAME).then_some(owned)
}

/// `line` is exactly `{"token":"…"}` (one key, a string) and its value equals
/// `expected`, compared in constant time.
pub fn token_line_matches(line: &str, expected: &str) -> bool {
    let Ok(JsonValue::Object(obj)) = serde_json::from_str::<JsonValue>(line) else {
        return false;
    };
    if obj.len() != 1 {
        return false;
    }
    let Some(JsonValue::String(given)) = obj.get("token") else {
        return false;
    };
    constant_time_eq(given.as_bytes(), expected.as_bytes())
}

/// Length-leaking but content-constant-time comparison: every byte is folded
/// whichever position first differs. (Lengths of the two values are not secret;
/// the token is always 64 hex characters.)
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn header_eq_ignore_case(headers: &HeaderMap, name: header::HeaderName, want: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(want))
}

fn connection_has_upgrade(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONNECTION).iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
    })
}

/// No `Origin` (a non-browser client) passes; otherwise its authority must
/// equal `Host`.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin_matches_host(origin, host)
}

/// `Origin: http://127.0.0.1:8081` matches `Host: 127.0.0.1:8081`; the
/// scheme is dropped, the authority compared case-insensitively.
pub fn origin_matches_host(origin: &HeaderValue, host: &str) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let authority = match origin.trim().split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") =>
        {
            rest.split('/').next().unwrap_or_default()
        }
        _ => return false, // `null`, or something that is not a web origin
    };
    !authority.is_empty() && authority.eq_ignore_ascii_case(host.trim())
}

fn plain(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(text.as_bytes())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_line_must_be_exactly_the_token_object() {
        assert!(token_line_matches(r#"{"token":"abc"}"#, "abc"));
        assert!(token_line_matches(r#" {"token": "abc"} "#, "abc"));
        assert!(!token_line_matches(r#"{"token":"abd"}"#, "abc"));
        assert!(!token_line_matches(r#"{"token":"ab"}"#, "abc"));
        assert!(!token_line_matches(r#"{"token":"abc","x":1}"#, "abc"));
        assert!(!token_line_matches(r#"{"tok":"abc"}"#, "abc"));
        assert!(!token_line_matches(r#"{"token":1}"#, "abc"));
        assert!(!token_line_matches(r#""abc""#, "abc"));
        assert!(!token_line_matches("not json", "abc"));
        assert!(!token_line_matches(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            "abc"
        ));
    }

    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"sama"));
        assert!(!constant_time_eq(b"same", b"same1"));
    }

    #[test]
    fn origin_must_match_host() {
        let hv = |s: &str| HeaderValue::from_str(s).unwrap();
        assert!(origin_matches_host(
            &hv("http://127.0.0.1:8081"),
            "127.0.0.1:8081"
        ));
        assert!(origin_matches_host(
            &hv("HTTP://LocalHost:8081"),
            "localhost:8081"
        ));
        assert!(origin_matches_host(&hv("https://proxy.lan"), "proxy.lan"));
        assert!(!origin_matches_host(
            &hv("http://evil.example"),
            "127.0.0.1:8081"
        ));
        assert!(!origin_matches_host(
            &hv("http://127.0.0.1:8081"),
            "127.0.0.1:8082"
        ));
        assert!(!origin_matches_host(&hv("null"), "127.0.0.1:8081"));
        assert!(!origin_matches_host(&hv("file://"), ""));
        assert!(!origin_matches_host(
            &hv("ws://127.0.0.1:8081"),
            "127.0.0.1:8081"
        ));
    }

    #[test]
    fn a_frame_may_carry_at_most_the_line_cap() {
        assert_eq!(MAX_LINES_PER_FRAME, 256);
        // Exactly at the cap is accepted whole, in order.
        let at_cap: String = (0..MAX_LINES_PER_FRAME).map(|i| format!("{i}\n")).collect();
        let lines = bounded_lines(lines_of(&at_cap)).expect("a frame at the cap is accepted");
        assert_eq!(lines.len(), 256);
        assert_eq!(lines.first().map(String::as_str), Some("0"));
        assert_eq!(lines.last().map(String::as_str), Some("255"));
        // One line over is refused.
        let over: String = (0..=MAX_LINES_PER_FRAME)
            .map(|i| format!("{i}\n"))
            .collect();
        assert_eq!(bounded_lines(lines_of(&over)), None);
        // A flood is refused after reading only one line past the cap.
        let flood = "x\n".repeat(100_000);
        let mut seen = 0usize;
        let counted = lines_of(&flood).inspect(|_| seen += 1);
        assert_eq!(bounded_lines(counted), None);
        assert_eq!(seen, MAX_LINES_PER_FRAME + 1);
    }

    #[test]
    fn blank_lines_do_not_count_against_the_line_cap() {
        let padded = "\n  \r\n".repeat(MAX_LINES_PER_FRAME) + "{\"a\":1}\n\n";
        assert_eq!(
            bounded_lines(lines_of(&padded)),
            Some(vec!["{\"a\":1}".to_owned()])
        );
        assert_eq!(bounded_lines(lines_of("")), Some(Vec::new()));
    }

    /// Both ends of an in-memory WebSocket: (server end, client end).
    async fn socket_pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (server, client) = tokio::io::duplex(64 * 1024);
        (
            WebSocketStream::from_raw_socket(server, Role::Server, None).await,
            WebSocketStream::from_raw_socket(client, Role::Client, None).await,
        )
    }

    #[tokio::test]
    async fn close_gives_up_on_a_peer_that_never_answers() {
        // The client end is held open but never read from or written to, so it
        // never answers our Close frame. Without a deadline the drain waits forever.
        let (server, _stalled_client) = socket_pair().await;
        let closed = tokio::time::timeout(
            Duration::from_secs(5),
            close_within(
                server,
                CloseCode::Size,
                TOO_MANY_LINES,
                Duration::from_millis(50),
            ),
        )
        .await;
        assert!(
            matches!(closed, Ok(Ok(()))),
            "close must give up on a stalled peer and return Ok, got {closed:?}"
        );
    }

    #[tokio::test]
    async fn close_completes_the_handshake_with_a_peer_that_answers() {
        let (server, mut client) = socket_pair().await;
        // A drain limit far above the outer bound: finishing inside the outer bound
        // proves the handshake completed rather than the deadline firing.
        let server_side = close_within(
            server,
            CloseCode::Size,
            TOO_MANY_LINES,
            Duration::from_secs(30),
        );
        let client_side = async {
            // The client sees our Close frame, then answers it by polling on until
            // the server finishes and the stream ends.
            let frame = match client.next().await {
                Some(Ok(Message::Close(Some(frame)))) => frame,
                other => panic!("expected a Close frame, got {other:?}"),
            };
            assert_eq!(frame.code, CloseCode::Size);
            assert_eq!(frame.reason.as_str(), TOO_MANY_LINES);
            while let Some(Ok(_)) = client.next().await {}
        };
        let (closed, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server_side, client_side)
        })
        .await
        .expect("the close handshake completes without waiting for the drain deadline");
        closed.expect("a completed handshake is Ok");
    }

    #[test]
    fn unauthorized_reply_is_valid_json_rpc() {
        let v: JsonValue = serde_json::from_str(UNAUTHORIZED_REPLY).unwrap();
        assert_eq!(v["error"]["code"], UNAUTHORIZED);
        assert!(v["id"].is_null());
    }
}
