//! `aitm web` `/bus` audit attribution over a real loopback WebSocket (spec
//! `2026-10-30-audit-ring-integrity-design.md`, AC30).
//!
//! Every call a client makes over the web bridge is recorded in the one audit
//! ring that `agent.activity` reads. The bridge is a path, not a client: any
//! holder of a bridge token can open the socket and type whatever it likes into
//! `initialize.clientInfo.name`, so a declared name is forgeable and must never
//! reach the audit trail. The contract this test pins:
//!
//! - a call over the web bridge is attributed to the server-minted label
//!   `web-bridge`, for the agent token (origin `mcp`) and for the operator token
//!   (origin `operator`) alike;
//! - an agent connection that declares `clientInfo.name = "forged"` in
//!   `initialize` leaves no entry carrying `forged` as its `client_label`.
//!
//! The rig serves the real `web::serve` over `aitm::wire::assemble`'s registry and
//! `tui::server`, with the shared governance, the push wiring and the operator
//! bridge token `main.rs` gives the web run, exactly as `web_bus_governance.rs`
//! does. The commands used are the real ones: `agent.status` and `agent.activity`.
//!
//! These tests bind loopback sockets, so they run from the Terminal panel, not the
//! Bash sandbox.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm::tui::{self, TuiLog};
use aitm::web::{self, WebState};
use aitm::wire::assemble;
use aitm_core::{AgentPolicy, Config, Proxy};
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const AGENT_TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OPERATOR_TOKEN: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// Generous bound for anything that is expected to happen.
const TIMEOUT: Duration = Duration::from_secs(10);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-audit-label-{tag}-{nanos}-{n}"))
}

struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// The CA directory `assemble` wrote key material into; removed on drop.
    ca_dir: PathBuf,
    /// Kept alive for the test: the registry and store behind the served bridge.
    _proxy: Proxy,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.ca_dir);
    }
}

/// A served `aitm web` bridge under the default `auto` policy, with both bridge
/// tokens configured (the operator token always, so a test can open an operator
/// connection when it needs one).
async fn start(tag: &str) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.mcp.policy = AgentPolicy::Auto;
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(
        &assembled.proxy,
        &cfg,
        None,
        TuiLog::Off,
        Arc::clone(&assembled.job_bus),
    );
    let web_server = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let agent_state = &assembled.agent_state;
    let audit_ring = &assembled.audit_ring;
    let web_server = tui::with_shared_governance(web_server, agent_state, audit_ring);
    let web_server = web_server
        .with_push(assembled.push_tx.clone())
        .with_approval_timeout(TIMEOUT);
    let mcp = Arc::new(web_server);
    mcp.spawn_push_dispatcher();
    let web_state = Arc::new(WebState {
        mcp,
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: Some(OPERATOR_TOKEN.to_owned()),
        bad_token_throttle: Default::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, web_state));
    Server {
        addr,
        task,
        ca_dir: cfg.ca.dir.clone(),
        _proxy: assembled.proxy,
    }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(server: &Server) -> Ws {
    let req = format!("ws://{}/bus", server.addr)
        .into_client_request()
        .expect("client request");
    let (ws, _) = tokio::time::timeout(TIMEOUT, connect_async(req))
        .await
        .expect("handshake within the timeout")
        .expect("handshake");
    ws
}

async fn send_text(ws: &mut Ws, text: impl Into<String>) {
    ws.send(Message::text(text.into())).await.expect("send");
}

/// The next text frame, parsed; `None` when the stream ended first. Unbounded:
/// the caller puts a deadline on it.
async fn next_frame(ws: &mut Ws) -> Option<JsonValue> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                return Some(
                    serde_json::from_str(&t)
                        .unwrap_or_else(|e| panic!("a frame must be JSON ({e}): {t}")),
                )
            }
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Ok(_)) => continue,
            Some(Err(WsError::ConnectionClosed)) | Some(Err(WsError::AlreadyClosed)) => {
                return None
            }
            Some(Err(e)) => panic!("websocket error: {e}"),
        }
    }
}

/// Frames until one satisfies `pred`, within [`TIMEOUT`]. The frames skipped on
/// the way are in the failure message, so a wrong frame is diagnosable.
async fn recv_until(ws: &mut Ws, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
    let deadline = Instant::now() + TIMEOUT;
    let mut skipped: Vec<JsonValue> = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, next_frame(ws)).await {
            Err(_) => panic!("timed out waiting for {what}; frames seen meanwhile: {skipped:?}"),
            Ok(None) => {
                panic!(
                    "the stream ended while waiting for {what}; frames seen meanwhile: {skipped:?}"
                )
            }
            Ok(Some(frame)) if pred(&frame) => return frame,
            Ok(Some(frame)) => skipped.push(frame),
        }
    }
}

/// A `tools/call` request line for `name` with `arguments`.
fn call_line_with(id: u64, name: &str, arguments: JsonValue) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
    .to_string()
}

/// Open the bus as `token`: connect, authenticate, `initialize` declaring
/// `clientInfo.name = client_name`, and check the role echo is `role`.
async fn open_bus(server: &Server, token: &str, role: &str, client_name: &str) -> Ws {
    let mut ws = ws_connect(server).await;
    send_text(&mut ws, json!({ "token": token }).to_string()).await;
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": client_name, "version": "0"}}})
        .to_string(),
    )
    .await;
    let init = recv_until(&mut ws, "the initialize reply", |v| v["id"] == 0).await;
    assert_eq!(init["result"]["role"], role, "initialize reply: {init}");
    ws
}

/// One `tools/call` on `ws`, returning the whole reply whose `id` matches. Frames
/// that are not that reply (notifications) are skipped. Tests assert on
/// `reply["result"]` and print the whole reply in every message.
async fn call(ws: &mut Ws, id: u64, name: &str, arguments: JsonValue) -> JsonValue {
    send_text(ws, call_line_with(id, name, arguments)).await;
    recv_until(ws, &format!("the {name} reply"), |v| v["id"] == id).await
}

/// `reply` must be a successful tool result (`result.isError == false`); returns
/// the result's `structuredContent`.
fn ok_content<'a>(what: &str, reply: &'a JsonValue) -> &'a JsonValue {
    assert_eq!(
        reply["result"]["isError"], false,
        "{what} must be a successful tool result; the whole reply was: {reply}"
    );
    &reply["result"]["structuredContent"]
}

/// AC30: over a real `/bus`, a web agent that declares `clientInfo.name =
/// "forged"` and an operator bridge connection are both attributed to the
/// server-minted `web-bridge` label in `agent.activity`; the declared name never
/// appears as a `client_label`.
#[tokio::test]
async fn bridge_calls_are_attributed_to_web_bridge() {
    let server = start("attributed").await;

    // The agent declares a forged name in `initialize`, then makes one call.
    let mut agent = open_bus(&server, AGENT_TOKEN, "agent", "forged").await;
    let agent_status = call(&mut agent, 1, "agent.status", json!({})).await;
    ok_content("agent agent.status", &agent_status);

    // The operator makes its own `agent.status`, then lists the audit trail.
    let mut operator = open_bus(&server, OPERATOR_TOKEN, "operator", "aitm-web").await;
    let operator_status = call(&mut operator, 1, "agent.status", json!({})).await;
    ok_content("operator agent.status", &operator_status);
    let activity = call(&mut operator, 2, "agent.activity", json!({})).await;
    let entries = ok_content("operator agent.activity", &activity)
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {activity}"));

    assert!(
        entries.iter().any(|e| {
            e["command"] == "agent.status"
                && e["origin"] == "mcp"
                && e["client_label"] == "web-bridge"
        }),
        "the agent's agent.status must be listed with origin mcp and client_label web-bridge; \
         the whole reply was: {activity}"
    );
    assert!(
        entries.iter().any(|e| {
            e["command"] == "agent.status"
                && e["origin"] == "operator"
                && e["client_label"] == "web-bridge"
        }),
        "the operator's agent.status must be listed with origin operator and client_label \
         web-bridge; the whole reply was: {activity}"
    );
    assert!(
        entries.iter().all(|e| e["client_label"] != "forged"),
        "no entry may carry the forged declared name as its client_label; the whole reply was: \
         {activity}"
    );
}
