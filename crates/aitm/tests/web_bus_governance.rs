//! `aitm web` `/bus` agent governance over a real loopback WebSocket (spec
//! `2026-10-30-web-bus-agent-governance-design.md`, AC1-AC6 and AC16).
//!
//! The web bridge's `McpServer` is agent-facing: the agent bridge token resolves
//! to `Frontend::Mcp`, so it must be governed by the one agent policy every other
//! agent surface reads, follow every live `agent.set`, and record into the one
//! audit ring `agent.activity` and `agent.status` read. The contract these tests
//! pin:
//!
//! - a web agent under `readonly` reads but cannot write or widen, and
//!   `agent.status` reports the policy the gate enforces (AC1);
//! - under `paused` every tool call from the web agent is refused, while
//!   `initialize` and `tools/list` still answer (AC2);
//! - the same long-lived agent connection follows an operator's `agent.set`
//!   without reconnecting, in both directions (AC3);
//! - the operator bridge connection stays un-gated under `paused` (AC4, guard);
//! - a web agent's calls, allowed or refused, land in the shared audit trail and
//!   count in `agent.status.actions_last_minute` (AC5);
//! - under the default `auto` a sensitive web agent call is still refused (AC6,
//!   guard);
//! - under `ask` a sensitive web agent call parks for an operator subscribed on
//!   the same bridge, who is announced `approval_requested` and resolves it with
//!   `agent.approve` (AC16).
//!
//! The rig serves the real `web::serve` over `aitm::wire::assemble`'s registry and
//! `tui::server`, with the push wiring and the operator bridge token `main.rs`
//! gives the web run. The commands used are the real ones: `agent.status`,
//! `agent.activity`, `agent.set`, `agent.approve`, `flow.list`, `flow.kill`,
//! `flow.subscribe` and `scope.add`.
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
/// Bound for the one frame a parked call must produce: long enough for a loaded
/// machine, short enough that a refusal (which produces no such frame) fails fast.
const FAST: Duration = Duration::from_secs(5);
/// How long to listen for a frame that must not arrive.
const QUIET: Duration = Duration::from_millis(300);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-web-governance-{tag}-{nanos}-{n}"))
}

struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// Kept alive for the test: the registry and store behind the served bridge.
    _proxy: Proxy,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A served `aitm web` bridge seeded with `policy`, with both bridge tokens
/// configured (the operator token always, so a test can open an operator
/// connection when it needs one).
async fn start(tag: &str, policy: AgentPolicy) -> Server {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.mcp.policy = policy;
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let web_server = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let state = Arc::clone(&assembled.agent_state);
    let ring = Arc::clone(&assembled.audit_ring);
    let web_server = tui::with_shared_governance(web_server, &state, &ring); // MUTATION-POINT
    let web_server = web_server
        .with_push(assembled.push_tx.clone())
        .with_approval_timeout(TIMEOUT);
    let mcp = Arc::new(web_server);
    mcp.spawn_push_dispatcher();
    let state = Arc::new(WebState {
        mcp,
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: Some(OPERATOR_TOKEN.to_owned()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, state));
    Server {
        addr,
        task,
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

/// Frames until one satisfies `pred`, within `bound`. `Err` carries the frames
/// skipped on the way when the bound passes first; the stream ending panics.
async fn try_recv_until(
    ws: &mut Ws,
    bound: Duration,
    what: &str,
    pred: impl Fn(&JsonValue) -> bool,
) -> Result<JsonValue, Vec<JsonValue>> {
    let deadline = Instant::now() + bound;
    let mut skipped: Vec<JsonValue> = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, next_frame(ws)).await {
            Err(_) => return Err(skipped),
            Ok(None) => {
                panic!(
                    "the stream ended while waiting for {what}; frames seen meanwhile: {skipped:?}"
                )
            }
            Ok(Some(frame)) if pred(&frame) => return Ok(frame),
            Ok(Some(frame)) => skipped.push(frame),
        }
    }
}

/// Frames until one satisfies `pred`, within [`TIMEOUT`]. The frames skipped on
/// the way are in the failure message, so a wrong frame is diagnosable.
async fn recv_until(ws: &mut Ws, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
    match try_recv_until(ws, TIMEOUT, what, pred).await {
        Ok(frame) => frame,
        Err(skipped) => {
            panic!("timed out waiting for {what}; frames seen meanwhile: {skipped:?}")
        }
    }
}

/// Every frame that arrives within `bound`; the stream must stay open.
async fn drain_for(ws: &mut Ws, bound: Duration) -> Vec<JsonValue> {
    let deadline = Instant::now() + bound;
    let mut frames = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, next_frame(ws)).await {
            Err(_) => return frames,
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => panic!("the stream ended while listening; frames seen: {frames:?}"),
        }
    }
}

/// A `tools/call` request line for `name` with `arguments`.
fn call_line_with(id: u64, name: &str, arguments: JsonValue) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
    .to_string()
}

/// Open the bus as `token`: connect, authenticate, `initialize`, and check the
/// role echo is `role`.
async fn open_bus(server: &Server, token: &str, role: &str) -> Ws {
    let mut ws = ws_connect(server).await;
    send_text(&mut ws, json!({ "token": token }).to_string()).await;
    send_text(
        &mut ws,
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "aitm-web", "version": "0"}}})
        .to_string(),
    )
    .await;
    let init = recv_until(&mut ws, "the initialize reply", |v| v["id"] == 0).await;
    assert_eq!(init["result"]["role"], role, "initialize reply: {init}");
    ws
}

async fn open_agent(server: &Server) -> Ws {
    open_bus(server, AGENT_TOKEN, "agent").await
}

async fn open_operator(server: &Server) -> Ws {
    open_bus(server, OPERATOR_TOKEN, "operator").await
}

/// One `tools/call` on `ws`, returning the whole reply whose `id` matches. Frames
/// that are not that reply (notifications) are skipped. Tests assert on
/// `reply["result"]` and print the whole reply in every message.
async fn call(ws: &mut Ws, id: u64, name: &str, arguments: JsonValue) -> JsonValue {
    send_text(ws, call_line_with(id, name, arguments)).await;
    recv_until(ws, &format!("the {name} reply"), |v| v["id"] == id).await
}

/// `reply` must be a successful tool result (`result.isError == false`).
fn assert_ok(what: &str, reply: &JsonValue) {
    assert_eq!(
        reply["result"]["isError"], false,
        "{what} must be a successful tool result; the whole reply was: {reply}"
    );
}

/// [`assert_ok`], returning the result's `structuredContent`.
fn ok_content<'a>(what: &str, reply: &'a JsonValue) -> &'a JsonValue {
    assert_ok(what, reply);
    &reply["result"]["structuredContent"]
}

/// `reply` must be a refused tool result (`result.isError == true`) whose reason
/// text contains every fragment.
fn assert_refused(what: &str, reply: &JsonValue, fragments: &[&str]) {
    assert_eq!(
        reply["result"]["isError"], true,
        "{what} must be refused with a tool result (isError true); the whole reply was: {reply}"
    );
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: a refusal carries its reason as text: {reply}"));
    for fragment in fragments {
        assert!(
            text.contains(fragment),
            "{what}: the refusal must contain {fragment:?}; the whole reply was: {reply}"
        );
    }
}

/// AC1: under a seeded `readonly` policy the web agent reads, cannot write, and
/// cannot widen scope; `agent.status` reports the policy the gate enforces.
#[tokio::test]
async fn readonly_web_agent_reads_but_cannot_write_or_widen() {
    let server = start("readonly", AgentPolicy::ReadOnly).await;
    let mut agent = open_agent(&server).await;

    let status = call(&mut agent, 1, "agent.status", json!({})).await;
    assert_eq!(
        ok_content("agent.status under readonly", &status)["policy"],
        "readonly",
        "agent.status must report the policy the web gate enforces; the whole reply was: {status}"
    );

    let kill = call(&mut agent, 2, "flow.kill", json!({})).await;
    assert_refused(
        "flow.kill (Write) under readonly",
        &kill,
        &["`flow.kill` refused", "the agent policy is `readonly`"],
    );

    let widen = call(&mut agent, 3, "scope.add", json!({})).await;
    assert_refused(
        "scope.add (Sensitive) under readonly",
        &widen,
        &["`scope.add` refused", "the agent policy is `readonly`"],
    );
}

/// AC2: under a seeded `paused` policy every tool call from the web agent is
/// refused, including the Read ones and `flow.subscribe`; the handshake still
/// answers: `initialize` echoes the agent role and `tools/list` lists tools.
#[tokio::test]
async fn paused_web_agent_is_refused_everything_but_the_handshake() {
    let server = start("paused", AgentPolicy::Paused).await;
    // `open_bus` asserts the `initialize` reply's `role` echo is "agent".
    let mut agent = open_agent(&server).await;

    for (id, name) in (10u64..).zip([
        "agent.status",
        "flow.list",
        "flow.kill",
        "scope.add",
        "flow.subscribe",
    ]) {
        let reply = call(&mut agent, id, name, json!({})).await;
        assert_refused(
            &format!("{name} under paused"),
            &reply,
            &["the agent policy is `paused`"],
        );
    }

    send_text(
        &mut agent,
        json!({"jsonrpc": "2.0", "id": 20, "method": "tools/list"}).to_string(),
    )
    .await;
    let listed = recv_until(&mut agent, "the tools/list reply", |v| v["id"] == 20).await;
    let tools = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must still answer under paused: {listed}"));
    assert!(
        !tools.is_empty(),
        "tools/list must still list tools under paused: {listed}"
    );
    assert!(
        tools.iter().any(|t| t["name"] == "flow.list"),
        "tools/list must still list flow.list under paused: {listed}"
    );
}

/// AC3: one long-lived agent connection follows an operator's live `agent.set`
/// without reconnecting, down to `paused` and back up to `auto`, and the
/// operator's `agent.status` agrees with what the agent just experienced.
#[tokio::test]
async fn web_agent_follows_a_live_agent_set_without_reconnecting() {
    let server = start("live-follow", AgentPolicy::Auto).await;
    let mut agent = open_agent(&server).await;
    let mut operator = open_operator(&server).await;

    let before = call(&mut agent, 1, "flow.list", json!({})).await;
    assert_ok("agent flow.list under auto, before any agent.set", &before);

    let paused = call(&mut operator, 1, "agent.set", json!({"policy": "paused"})).await;
    assert_eq!(
        ok_content("operator agent.set paused", &paused)["policy"],
        "paused",
        "agent.set must report the policy now in effect; the whole reply was: {paused}"
    );
    let status = call(&mut operator, 2, "agent.status", json!({})).await;
    assert_eq!(
        ok_content("operator agent.status after paused", &status)["policy"],
        "paused",
        "the whole reply was: {status}"
    );
    let refused = call(&mut agent, 2, "flow.list", json!({})).await;
    assert_refused(
        "the same agent connection's flow.list after agent.set paused",
        &refused,
        &["the agent policy is `paused`"],
    );

    let auto = call(&mut operator, 3, "agent.set", json!({"policy": "auto"})).await;
    assert_eq!(
        ok_content("operator agent.set auto", &auto)["policy"],
        "auto",
        "the whole reply was: {auto}"
    );
    let status = call(&mut operator, 4, "agent.status", json!({})).await;
    assert_eq!(
        ok_content("operator agent.status after auto", &status)["policy"],
        "auto",
        "the whole reply was: {status}"
    );
    let again = call(&mut agent, 3, "flow.list", json!({})).await;
    assert_ok(
        "the same agent connection's flow.list after agent.set auto",
        &again,
    );
}

/// AC4 (guard): the operator bridge connection is un-gated by role, so under a
/// seeded `paused` policy it still reads and can change the policy. Passes with
/// or without the shared governance; it pins that the fix does not gate it.
#[tokio::test]
async fn operator_bridge_connection_stays_ungated_under_paused() {
    let server = start("operator-ungated", AgentPolicy::Paused).await;
    // `open_bus` asserts the `initialize` reply's `role` echo is "operator".
    let mut operator = open_operator(&server).await;

    let status = call(&mut operator, 1, "agent.status", json!({})).await;
    assert_ok("operator agent.status under paused", &status);
    let listed = call(&mut operator, 2, "flow.list", json!({})).await;
    assert_ok("operator flow.list under paused", &listed);
    let set = call(&mut operator, 3, "agent.set", json!({"policy": "auto"})).await;
    assert_eq!(
        ok_content("operator agent.set auto under paused", &set)["policy"],
        "auto",
        "the whole reply was: {set}"
    );
}

/// AC5: a web agent's calls, allowed and refused alike, land in the shared audit
/// trail: they count in `agent.status.actions_last_minute` and appear in
/// `agent.activity`, in call order, with origin `mcp`. The audit assertions run
/// before the agent-reply assertions so a missing audit trail is what fails first.
#[tokio::test]
async fn web_agent_calls_land_in_the_shared_audit_trail() {
    let server = start("audit", AgentPolicy::ReadOnly).await;
    let mut agent = open_agent(&server).await;
    let status = call(&mut agent, 1, "agent.status", json!({})).await;
    let kill = call(&mut agent, 2, "flow.kill", json!({})).await;

    // A new operator connection: its first tool call reads the count, so the
    // operator's own calls are not in it yet.
    let mut operator = open_operator(&server).await;
    let count = call(&mut operator, 1, "agent.status", json!({})).await;
    assert_eq!(
        ok_content("operator agent.status after two agent calls", &count)["actions_last_minute"],
        2,
        "the web agent's two calls (one allowed, one refused) must count; the whole reply was: \
         {count}"
    );

    let activity = call(&mut operator, 2, "agent.activity", json!({})).await;
    let entries = ok_content("operator agent.activity", &activity)
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {activity}"));
    assert!(
        entries.len() >= 2,
        "agent.activity must list the web agent's two calls first; the whole reply was: \
         {activity}"
    );
    assert_eq!(entries[0]["origin"], "mcp", "{activity}");
    assert_eq!(entries[0]["command"], "agent.status", "{activity}");
    assert_eq!(entries[0]["result"], "ok", "{activity}");
    assert_eq!(entries[1]["origin"], "mcp", "{activity}");
    assert_eq!(entries[1]["command"], "flow.kill", "{activity}");
    assert!(
        entries[1]["result"]["error"]
            .as_str()
            .is_some_and(|e| e.contains("readonly")),
        "the refused flow.kill is recorded with its readonly reason: {activity}"
    );
    assert!(
        entries.iter().skip(2).all(|e| e["origin"] == "operator"),
        "any entry after the web agent's two is the operator connection's own: {activity}"
    );

    // Last: the agent's own replies, an allowed read then a refused write.
    assert_ok("agent.status under readonly", &status);
    assert_refused(
        "flow.kill (Write) under readonly",
        &kill,
        &["the agent policy is `readonly`"],
    );
}

/// AC6 (guard): under the default `auto` a web agent's read runs and its
/// sensitive call is refused. Passes with or without the shared governance; it
/// pins that nothing changes in enforcement under the default.
#[tokio::test]
async fn default_auto_still_refuses_a_sensitive_web_agent_call() {
    let server = start("auto-default", AgentPolicy::Auto).await;
    let mut agent = open_agent(&server).await;

    let listed = call(&mut agent, 1, "flow.list", json!({})).await;
    assert_ok("agent flow.list under auto", &listed);

    let widen = call(&mut agent, 2, "scope.add", json!({})).await;
    assert_refused(
        "scope.add (Sensitive) under auto",
        &widen,
        &["the agent policy is `auto`"],
    );
}

/// The request id of the agent's parked `scope.add` in the `Ask` test.
const PARKED_CALL_ID: u64 = 7;

/// AC16: under `ask`, a web agent's `Sensitive` `scope.add` parks for an operator
/// bridge connection subscribed on the same bridge. That operator is announced
/// `approval_requested`, resolves the call with `agent.approve` over the same
/// connection, and the agent's call is refused as denied. Denial, not approval:
/// an approved agent `scope.add` still meets the command's own gate.
#[tokio::test]
async fn ask_parks_a_web_agent_call_for_an_operator_on_the_same_bridge() {
    let server = start("ask", AgentPolicy::Ask).await;
    let mut operator = open_operator(&server).await;
    let mut agent = open_agent(&server).await;

    // The operator subscribes; the reply carries a `sub_id`. A notification may
    // arrive first, so `call` finds the reply by id.
    let subscribed = call(&mut operator, 1, "flow.subscribe", json!({})).await;
    assert!(
        ok_content("operator flow.subscribe", &subscribed)["sub_id"].is_u64(),
        "flow.subscribe over /bus must succeed with a u64 sub_id; the whole reply was: \
         {subscribed}"
    );

    // The agent's call parks; the test does not wait for its reply.
    send_text(
        &mut agent,
        call_line_with(PARKED_CALL_ID, "scope.add", json!({"host": "example.com"})),
    )
    .await;

    let request = match try_recv_until(
        &mut operator,
        FAST,
        "the approval_requested notification",
        |v| {
            v["method"] == "notifications/aitm/agent"
                && v["params"]["event"] == "approval_requested"
        },
    )
    .await
    {
        Ok(frame) => frame,
        Err(operator_frames) => {
            let agent_frames = drain_for(&mut agent, QUIET).await;
            panic!(
                "no approval_requested reached the subscribed operator within {FAST:?}; \
                 operator frames seen: {operator_frames:?}; agent frames seen: {agent_frames:?}"
            );
        }
    };
    assert_eq!(request["params"]["command"], "scope.add", "{request}");
    let request_id = request["params"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the approval request carries a request_id: {request}"))
        .to_owned();
    assert!(
        request_id.starts_with("apr_"),
        "the request id starts apr_: {request}"
    );

    // Still parked: the agent socket has not been given a reply for its call.
    let agent_frames = drain_for(&mut agent, QUIET).await;
    assert!(
        agent_frames.iter().all(|f| f["id"] != PARKED_CALL_ID),
        "the parked scope.add must have no reply yet; agent frames seen: {agent_frames:?}"
    );

    // The operator denies it over the same bridge connection.
    let approved = call(
        &mut operator,
        2,
        "agent.approve",
        json!({ "request_id": request_id, "allow": false }),
    )
    .await;
    assert_ok("operator agent.approve allow=false", &approved);

    let done = recv_until(&mut agent, "the parked scope.add reply", |v| {
        v["id"] == PARKED_CALL_ID
    })
    .await;
    assert_refused(
        "the denied parked scope.add",
        &done,
        &["an operator denied the parked sensitive command"],
    );

    let status = call(&mut operator, 3, "agent.status", json!({})).await;
    assert_eq!(
        ok_content("operator agent.status under ask", &status)["policy"],
        "ask",
        "the whole reply was: {status}"
    );
}
