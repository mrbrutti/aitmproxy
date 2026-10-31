//! `aitm web` `/bus` role routing (Task 4, AC3/AC4/AC6/AC9/AC11/AC12): the
//! bridge classifies the first-line token against its two bridge tokens and
//! runs every later line under the resolved role, so the browser's own
//! `initialize` reply carries the right `role` echo (Decision C/D).
//!
//! The operator bridge token resolves to `Frontend::Operator` → `role:
//! "operator"`; the agent bridge token to `Frontend::Mcp` → `role: "agent"`;
//! any other token is refused `-32001` and the stream ends. When operator is
//! not configured (`operator_token: None`) the operator bridge token value
//! matches nothing and is refused too (operator-off-by-default).

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
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const AGENT_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OPERATOR_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TIMEOUT: Duration = Duration::from_secs(10);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-roles-{tag}-{nanos}-{n}"))
}

/// A `ProxyClient` nothing in these tests invokes.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

struct Server {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A served `aitm web` whose bridge holds the agent token and, when
/// `operator` is set, the operator bridge token too.
async fn start(tag: &str, operator: Option<&str>) -> Server {
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
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: operator.map(str::to_owned),
        bad_token_throttle: Default::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, state));
    Server { addr, task }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(server: &Server) -> Result<Ws, WsError> {
    let req = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    let (ws, _) = tokio::time::timeout(TIMEOUT, connect_async(req))
        .await
        .expect("handshake within the timeout")?;
    Ok(ws)
}

async fn send_text(ws: &mut Ws, text: impl Into<String>) {
    ws.send(Message::text(text.into())).await.expect("send");
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

/// Open the bus with `token`, run `initialize`, and return its result object.
async fn role_after_initialize(ws: &mut Ws, token: &str) -> JsonValue {
    send_text(ws, json!({ "token": token }).to_string()).await;
    send_text(
        ws,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "aitm-web", "version": "0"}}})
        .to_string(),
    )
    .await;
    let reply = recv_text(ws).await.expect("an initialize reply");
    let v: JsonValue = serde_json::from_str(&reply).expect("reply is JSON");
    assert_eq!(v["id"], 1, "reply matches the request: {v}");
    v["result"].clone()
}

#[tokio::test]
async fn operator_bridge_token_runs_as_operator() {
    let server = start("operator", Some(OPERATOR_TOKEN)).await;
    let mut ws = ws_connect(&server).await.expect("handshake");
    let result = role_after_initialize(&mut ws, OPERATOR_TOKEN).await;
    assert_eq!(result["role"], "operator", "initialize result: {result}");
}

#[tokio::test]
async fn agent_bridge_token_runs_as_agent() {
    let server = start("agent", Some(OPERATOR_TOKEN)).await;
    let mut ws = ws_connect(&server).await.expect("handshake");
    let result = role_after_initialize(&mut ws, AGENT_TOKEN).await;
    assert_eq!(result["role"], "agent", "initialize result: {result}");
}

#[tokio::test]
async fn unknown_token_is_refused_and_the_stream_ends() {
    let server = start("unknown", Some(OPERATOR_TOKEN)).await;
    let mut ws = ws_connect(&server).await.expect("handshake");
    send_text(&mut ws, json!({"token": "nope"}).to_string()).await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    let v: JsonValue = serde_json::from_str(&first).expect("JSON");
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(recv_text(&mut ws).await, None, "nothing after the refusal");
}

#[tokio::test]
async fn operator_token_unconfigured_refuses_the_operator_token() {
    // operator-off-by-default (AC11/AC12): with no operator bridge token, the
    // operator token value matches neither token and is refused -32001.
    let server = start("operator-off", None).await;
    let mut ws = ws_connect(&server).await.expect("handshake");
    send_text(&mut ws, json!({"token": OPERATOR_TOKEN}).to_string()).await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    let v: JsonValue = serde_json::from_str(&first).expect("JSON");
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(recv_text(&mut ws).await, None, "nothing after the refusal");

    // The agent token still works on the same agent-only server.
    let mut ws = ws_connect(&server).await.expect("handshake");
    let result = role_after_initialize(&mut ws, AGENT_TOKEN).await;
    assert_eq!(result["role"], "agent", "initialize result: {result}");
}

#[tokio::test]
async fn operator_token_empty_refuses_the_operator_path() {
    // AC12 empty-string sub-case: a hand-edited `operator_token: ""` deserializes
    // to `Some("")` but must behave exactly like "not configured" (it is filtered
    // as empty, mirroring the loopback transport). An empty `{"token":""}` line
    // therefore never resolves to operator, and the real operator token is
    // refused too — the operator path is not offered.
    let server = start("operator-empty", Some("")).await;

    // An empty bridge-token line is refused, not classified as operator.
    let mut ws = ws_connect(&server).await.expect("handshake");
    send_text(&mut ws, json!({"token": ""}).to_string()).await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    let v: JsonValue = serde_json::from_str(&first).expect("JSON");
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(recv_text(&mut ws).await, None, "nothing after the refusal");

    // The fixed OPERATOR_TOKEN is refused as well: empty means operator-off.
    let mut ws = ws_connect(&server).await.expect("handshake");
    send_text(&mut ws, json!({"token": OPERATOR_TOKEN}).to_string()).await;
    let first = recv_text(&mut ws).await.expect("an error reply");
    let v: JsonValue = serde_json::from_str(&first).expect("JSON");
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(recv_text(&mut ws).await, None, "nothing after the refusal");

    // The agent token still works on the same agent-only server.
    let mut ws = ws_connect(&server).await.expect("handshake");
    let result = role_after_initialize(&mut ws, AGENT_TOKEN).await;
    assert_eq!(result["role"], "agent", "initialize result: {result}");
}
