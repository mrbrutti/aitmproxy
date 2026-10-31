//! `aitm web` (F15): the static host and the `/bus` WebSocket bridge, driven
//! end to end against a real wired registry over a loopback listener.
//!
//! HTTP: `/` serves the UI (or the "not built" page) with the security
//! headers; unknown files are 404; `/healthz` is JSON; non-GET is 405.
//! Bridge: a bad token gets exactly one `-32001` reply and the stream ends; a
//! good token reaches `initialize`, the full `tools/list`, and `tools/call`;
//! lines batched in one frame answer in order; notifications answer nothing;
//! a cross-site `Origin` is refused at the handshake.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm::web::{self, WebState};
use aitm::wire::{assemble, Assembled};
use aitm_core::{Config, HttpFlow, HttpRequest, McpTransport, ProxyClient};
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value as JsonValue};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TIMEOUT: Duration = Duration::from_secs(10);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-{tag}-{nanos}-{n}"))
}

/// A `ProxyClient` nothing in these tests invokes.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

/// A served `aitm web` over a real registry; `addr` is the bound loopback port.
struct Server {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(tag: &str) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    let Assembled { proxy, .. } = assemble(&cfg).expect("assemble");
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let mcp = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        proxy.store(),
        client,
        proxy.guard(),
        None,
    );
    let state = Arc::new(WebState {
        mcp: Arc::new(mcp),
        agent_token: TOKEN.to_owned(),
        operator_token: None,
        bad_token_throttle: Default::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, state));
    Server { addr, task }
}

/// A parsed HTTP/1.1 response from the raw-socket client.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One request over a fresh connection with `Connection: close`.
async fn http(server: &Server, method: &str, path: &str) -> Reply {
    let mut stream = TcpStream::connect(server.addr).await.expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        server.addr
    );
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .expect("response within the timeout")
        .expect("read");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("ASCII head");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn assert_hardened(r: &Reply) {
    assert_eq!(
        r.header("content-security-policy"),
        Some(web::http::CONTENT_SECURITY_POLICY)
    );
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(r.header("cross-origin-opener-policy"), Some("same-origin"));
}

#[tokio::test]
async fn root_serves_the_ui_or_the_not_built_page_with_security_headers() {
    let server = start("root").await;
    let r = http(&server, "GET", "/").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_hardened(&r);
    let body = String::from_utf8_lossy(&r.body);
    match web::assets::lookup("index.html") {
        Some((index, _)) => assert_eq!(r.body, index, "the embedded index.html"),
        None => assert!(
            body.contains("aitmproxy web UI is not built"),
            "not-built page expected without a dist/: {body}"
        ),
    }
    // App routes fall back to the same document.
    let spa = http(&server, "GET", "/flows/abc").await;
    assert_eq!(spa.status, 200);
    assert_eq!(spa.body, r.body);
}

#[tokio::test]
async fn unknown_asset_is_404() {
    let server = start("404").await;
    let r = http(&server, "GET", "/assets/nope.js").await;
    assert_eq!(r.status, 404);
    assert_hardened(&r);
}

#[tokio::test]
async fn healthz_is_json() {
    let server = start("healthz").await;
    let r = http(&server, "GET", "/healthz").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    let v: JsonValue = serde_json::from_slice(&r.body).expect("JSON body");
    assert_eq!(v, json!({"ok": true}));
    assert_hardened(&r);
}

#[tokio::test]
async fn post_is_405() {
    let server = start("405").await;
    let r = http(&server, "POST", "/").await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET, HEAD"));
    assert_hardened(&r);
}

#[tokio::test]
async fn bus_without_upgrade_is_426() {
    let server = start("426").await;
    let r = http(&server, "GET", "/bus").await;
    assert_eq!(r.status, 426);
}

// ---- WebSocket bridge -----------------------------------------------------

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(server: &Server, origin: Option<&str>) -> Result<Ws, WsError> {
    let mut req = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    if let Some(o) = origin {
        req.headers_mut()
            .insert("Origin", o.parse().expect("origin header"));
    }
    let (ws, _) = tokio::time::timeout(TIMEOUT, connect_async(req))
        .await
        .expect("handshake within the timeout")?;
    Ok(ws)
}

async fn send_text(ws: &mut Ws, text: impl Into<String>) {
    ws.send(Message::text(text.into())).await.expect("send");
}

/// The next text frame, parsed.
async fn recv_json(ws: &mut Ws) -> JsonValue {
    let text = recv_text(ws).await.expect("a text frame");
    serde_json::from_str(&text).expect("reply is JSON")
}

/// The next text frame; `None` when the stream closed first.
async fn recv_text(ws: &mut Ws) -> Option<String> {
    loop {
        let next = tokio::time::timeout(TIMEOUT, ws.next())
            .await
            .expect("frame within the timeout");
        match next {
            Some(Ok(Message::Text(t))) => return Some(t.to_string()),
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(WsError::ConnectionClosed)) | Some(Err(WsError::AlreadyClosed)) => {
                return None
            }
            Some(Err(e)) => panic!("websocket error: {e}"),
        }
    }
}

async fn rpc(ws: &mut Ws, id: u64, method: &str, params: JsonValue) -> JsonValue {
    send_text(
        ws,
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
    )
    .await;
    let reply = recv_json(ws).await;
    assert_eq!(reply["id"], id, "reply matches the request: {reply}");
    reply
}

#[tokio::test]
async fn wrong_token_gets_one_unauthorized_reply_then_the_stream_ends() {
    let server = start("badtoken").await;
    let mut ws = ws_connect(&server, None).await.expect("handshake");
    send_text(&mut ws, r#"{"token":"wrong"}"#).await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    assert!(first.contains("-32001"), "{first}");
    let v: JsonValue = serde_json::from_str(&first).expect("JSON");
    assert_eq!(v["error"]["code"], -32001);
    assert_eq!(recv_text(&mut ws).await, None, "nothing after the refusal");
}

#[tokio::test]
async fn a_request_before_the_token_is_refused_too() {
    let server = start("notoken").await;
    let mut ws = ws_connect(&server, None).await.expect("handshake");
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).to_string(),
    )
    .await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    assert!(first.contains("-32001"), "{first}");
    assert_eq!(recv_text(&mut ws).await, None);
}

#[tokio::test]
async fn the_token_line_opens_the_bus() {
    let server = start("bus").await;
    let mut ws = ws_connect(&server, None).await.expect("handshake");
    // The web client appends a newline to every message (ws.ts).
    send_text(&mut ws, format!("{}\n", json!({"token": TOKEN}))).await;

    let init = rpc(
        &mut ws,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "aitm-web", "version": "0"}}),
    )
    .await;
    assert!(
        init["result"]["protocolVersion"].is_string(),
        "initialize result: {init}"
    );

    let tools = rpc(&mut ws, 2, "tools/list", json!({})).await;
    let n = tools["result"]["tools"].as_array().map_or(0, Vec::len);
    assert!(n >= 22, "expected the full command set, got {n}");

    let call = rpc(
        &mut ws,
        3,
        "tools/call",
        json!({"name": "flow.list", "arguments": {}}),
    )
    .await;
    let result = &call["result"];
    assert_eq!(result["isError"], false, "{call}");
    let structured = &result["structuredContent"];
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        structured == &json!([]) || text.trim() == "[]",
        "an empty flow list: {call}"
    );

    // Two lines in one frame answer in order, one frame per reply.
    let batch = format!(
        "{}\n{}\n",
        json!({"jsonrpc": "2.0", "id": 10, "method": "ping", "params": {}}),
        json!({"jsonrpc": "2.0", "id": 11, "method": "ping", "params": {}}),
    );
    send_text(&mut ws, batch).await;
    assert_eq!(recv_json(&mut ws).await["id"], 10);
    assert_eq!(recv_json(&mut ws).await["id"], 11);

    // A notification answers nothing: the next reply is the request after it.
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
    )
    .await;
    let after = rpc(&mut ws, 12, "ping", json!({})).await;
    assert!(after.get("result").is_some(), "{after}");

    ws.close(None).await.expect("close");
}

#[tokio::test]
async fn cross_site_origin_is_refused_at_the_handshake() {
    let server = start("origin").await;
    let err = match ws_connect(&server, Some("http://evil.example")).await {
        Err(e) => e,
        Ok(_) => panic!("the handshake must fail"),
    };
    match err {
        WsError::Http(resp) => assert_eq!(resp.status(), 403),
        other => panic!("expected an HTTP 403 refusal, got {other}"),
    }
    // The same-origin case still works.
    let same = format!("http://{}", server.addr);
    let mut ws = ws_connect(&server, Some(&same))
        .await
        .expect("same-origin handshake");
    send_text(&mut ws, json!({"token": TOKEN}).to_string()).await;
    let pong = rpc(&mut ws, 1, "ping", json!({})).await;
    assert!(pong.get("result").is_some(), "{pong}");
}

#[tokio::test]
async fn binary_frames_close_the_connection() {
    let server = start("binary").await;
    let mut ws = ws_connect(&server, None).await.expect("handshake");
    send_text(&mut ws, json!({"token": TOKEN}).to_string()).await;
    ws.send(Message::binary(vec![1, 2, 3])).await.expect("send");
    assert_eq!(
        recv_text(&mut ws).await,
        None,
        "closed without a text reply"
    );
}
