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

// The `/bus` harness shared with the other `web_bus_*` suites.
#[path = "support/web_bus.rs"]
#[allow(dead_code)] // this suite uses a subset of the shared harness
mod web_bus;

use serde_json::{json, Value as JsonValue};
use tokio_tungstenite::tungstenite::Error as WsError;
use web_bus::{
    recv_text, send_text, Server, ServerOptions, TestCommands, Ws, AGENT_TOKEN, OPERATOR_TOKEN,
};

/// A served `aitm web` whose bridge holds the agent token and, when `operator` is
/// set, the operator bridge token too. It uses the plain assembly with no test
/// commands and the `McpServer`'s own default gate, not the wired one the push
/// suite uses.
async fn start(tag: &str, operator: Option<&str>) -> Server {
    web_bus::start(
        tag,
        &TestCommands::new(),
        ServerOptions {
            operator_token: operator.map(str::to_owned),
            wired_gate: false,
            test_commands: false,
            ..ServerOptions::default()
        },
    )
    .await
}

/// Connect to the bus, handing back the handshake error instead of panicking on it.
async fn ws_connect(server: &Server) -> Result<Ws, WsError> {
    web_bus::try_ws_connect(server).await
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
