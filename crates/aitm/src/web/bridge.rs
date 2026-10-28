//! The `/bus` WebSocket bridge (design §4.9): a dumb relay of newline-delimited
//! JSON-RPC lines between a browser and the in-process `McpServer`. The first
//! text frame must be the token line `{"token":"…"}`, exactly as `LoopbackTcp`
//! requires on its first line; every later text frame holds one or more lines,
//! each answered (in order) with one text frame. All policy stays in the core:
//! the bridge authenticates, splits lines, and forwards.

use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt as _, StreamExt as _};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value as JsonValue;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, warn};

use super::WebState;

/// Same bound as the MCP transports (`aitm-mcp` `MAX_MESSAGE_BYTES`).
pub const MAX_MESSAGE_BYTES: usize = 16 << 20;

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
    // Authentication: the first non-empty line of the first text frame.
    let mut pending: Vec<String> = Vec::new();
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                let mut lines = lines_of(text.as_str());
                let Some(first) = lines.next() else {
                    continue; // whitespace only; wait for a real first line
                };
                if !token_line_matches(first, &state.token) {
                    warn!("web bus: refused a connection with a bad token");
                    ws.send(Message::text(UNAUTHORIZED_REPLY)).await?;
                    return close(ws, CloseCode::Policy, "unauthorized").await;
                }
                pending.extend(lines.map(str::to_owned));
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
    debug!("web bus: connection authenticated");

    // Any lines that shared the token's frame are ordinary messages.
    for line in pending {
        dispatch(&mut ws, state, line).await?;
    }

    while let Some(frame) = ws.next().await {
        match frame? {
            Message::Text(text) => {
                for line in lines_of(text.as_str()) {
                    dispatch(&mut ws, state, line.to_owned()).await?;
                }
            }
            Message::Binary(_) => {
                return close(ws, CloseCode::Unsupported, "text frames only").await;
            }
            Message::Close(frame) => {
                debug!(?frame, "websocket closed by the client");
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) => debug!("websocket ping/pong"),
            Message::Frame(_) => {} // never surfaced on read
        }
    }
    Ok(())
}

/// Hand one JSON-RPC line to the core on a blocking thread (the command's
/// `invoke` runs synchronously there, as `transport::serve_lines` does) and
/// send its reply, if any, as one text frame.
async fn dispatch(ws: &mut Ws, state: &WebState, line: String) -> anyhow::Result<()> {
    let srv = state.mcp.clone();
    let reply = tokio::task::spawn_blocking(move || srv.handle(&line)).await?;
    if let Some(reply) = reply {
        ws.send(Message::text(reply)).await?;
    }
    Ok(())
}

async fn close(mut ws: Ws, code: CloseCode, reason: &'static str) -> anyhow::Result<()> {
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    if let Err(e) = ws.close(Some(frame)).await {
        debug!(error = %e, "websocket close failed");
        return Ok(());
    }
    // Drain so the close handshake completes and the client sees our frame.
    while let Some(Ok(_)) = ws.next().await {}
    Ok(())
}

/// Non-empty, trimmed lines of a frame.
fn lines_of(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n').map(str::trim).filter(|l| !l.is_empty())
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
    fn unauthorized_reply_is_valid_json_rpc() {
        let v: JsonValue = serde_json::from_str(UNAUTHORIZED_REPLY).unwrap();
        assert_eq!(v["error"]["code"], UNAUTHORIZED);
        assert!(v["id"].is_null());
    }
}
