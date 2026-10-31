//! The connection id on audit lines, across the two governed agent servers
//! (spec `2026-10-30-bus-audit-connection-id-design.md`, D1, AC18).
//!
//! Since the web bus governance change, the primary agent server and the
//! `aitm web` bridge server share one `AuditRing` (`tui::with_shared_governance`),
//! but each counts its connections from 1. The raw counter therefore collides:
//! "agent, conn 1" exists on both servers, and a line from either would look the
//! same in the shared ring. `McpServer::connection_id` salts the counter with a
//! per-server random value so the two never render the same id.
//!
//! The first test here is in process: no sockets and no async runtime. The
//! servers are driven through `McpServer::handle_on` with hand-built `ConnCtx`
//! values, and both are built from one `Assembled`, the way `main.rs` builds them.
//!
//! The second test (AC19, at the bottom of the file) is the opposite: a real
//! loopback `/bus` WebSocket bridge, an agent-token and an operator-token
//! connection, and the audit lines each one is pushed. It binds sockets, so it
//! runs from the Terminal panel, not the Bash sandbox.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use aitm::tui::{self, TuiLog};
use aitm::web::{self, WebState};
use aitm::wire::assemble;
use aitm_core::{AgentPolicy, AuditRing, Config, Frontend, Proxy};
use aitm_mcp::{ConnCtx, McpServer};
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-audit-identity-{tag}-{nanos}-{n}"))
}

/// Two servers over one `Assembled`, policy `Auto`: `primary` (the agent server
/// the bare-`aitm` path serves) and `web` (the `aitm web` bridge's server), both
/// built through `tui::with_shared_governance`, so they share `ring`.
struct Rig {
    primary: McpServer,
    web: McpServer,
    ring: Arc<AuditRing>,
    ca_dir: PathBuf,
    _proxy: Proxy,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ca_dir);
    }
}

fn rig(tag: &str) -> Rig {
    let mut cfg = Config::default();
    cfg.mcp.policy = AgentPolicy::Auto;
    cfg.ca.dir = temp_ca_dir(tag);
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let state = &assembled.agent_state;
    let ring = &assembled.audit_ring;

    let primary = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let primary = tui::with_shared_governance(primary, state, ring);

    let web = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let web = tui::with_shared_governance(web, state, ring);

    Rig {
        primary,
        web,
        ring: Arc::clone(ring),
        ca_dir: cfg.ca.dir.clone(),
        _proxy: assembled.proxy,
    }
}

/// An agent connection as a transport builds the first one on a server: the
/// agent role, no label, `conn_id` 1 (every server's counter starts there), no
/// push sink.
fn first_agent_connection() -> ConnCtx {
    ConnCtx {
        role: Frontend::Mcp,
        client_label: None,
        conn_id: 1,
        out: None,
    }
}

/// One JSON-RPC request on `conn`; the whole parsed reply.
fn request_on(srv: &McpServer, conn: &ConnCtx, method: &str, params: JsonValue) -> JsonValue {
    let line = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let reply = srv
        .handle_on(conn, &line.to_string())
        .unwrap_or_else(|| panic!("a reply to {method}"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// One `tools/call` on `conn`; the whole parsed reply.
fn call(srv: &McpServer, conn: &ConnCtx, name: &str, arguments: JsonValue) -> JsonValue {
    request_on(
        srv,
        conn,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

/// The `connection_id` an `initialize` on `conn` echoes, as a string; panics when
/// the reply carries anything else.
fn initialize_id(srv: &McpServer, conn: &ConnCtx) -> String {
    let reply = request_on(srv, conn, "initialize", json!({}));
    reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize carries no string connection_id: {reply}"))
        .to_string()
}

/// AC18: the primary and the web server each hand their first agent connection
/// `conn_id` 1 and share one audit ring; the connection id on the two ring
/// entries, and in the two `initialize` replies, must still differ.
///
/// Both servers' connection is the same `ConnCtx` shape (agent, `conn_id` 1), so
/// the only thing that can tell the two apart is the per-server salt. With no
/// salt both would render `conn_..-1` and every `assert_ne!` below would fail.
#[test]
fn governed_servers_sharing_a_ring_never_share_an_id() {
    let rig = rig("shared-ring");
    let on_primary = first_agent_connection();
    let on_web = first_agent_connection();
    assert_eq!(
        (on_primary.conn_id, on_web.conn_id),
        (1, 1),
        "the setup: both servers' first connection carries the same conn_id"
    );

    // One audited call per server. `flow.list` is a `Read`, allowed under `Auto`.
    let primary_list = call(&rig.primary, &on_primary, "flow.list", json!({}));
    assert_eq!(
        primary_list["result"]["isError"],
        json!(false),
        "{primary_list}"
    );
    let web_list = call(&rig.web, &on_web, "flow.list", json!({}));
    assert_eq!(web_list["result"]["isError"], json!(false), "{web_list}");

    // The shared ring holds exactly the two lines (oldest first), so neither
    // server kept a ring of its own and `initialize` is not audited.
    let entries = rig.ring.recent(None, None);
    assert_eq!(entries.len(), 2, "one ring entry per server: {entries:?}");
    assert_eq!(
        entries
            .iter()
            .map(|e| e.command.as_str())
            .collect::<Vec<_>>(),
        ["flow.list", "flow.list"]
    );
    let (primary_entry, web_entry) = (&entries[0], &entries[1]);
    assert!(
        primary_entry.connection_id.is_some() && web_entry.connection_id.is_some(),
        "both lines come from a streaming connection, so both are attributed: {entries:?}"
    );
    assert_ne!(
        primary_entry.connection_id, web_entry.connection_id,
        "two servers, both conn_id 1, one ring: the lines must not share an id"
    );

    // The id each connection is told is the id its line carries, and the two
    // servers tell their connections different ids.
    let primary_id = initialize_id(&rig.primary, &on_primary);
    let web_id = initialize_id(&rig.web, &on_web);
    assert_ne!(
        primary_id, web_id,
        "the web server's initialize id must differ from the primary's"
    );
    assert_eq!(
        primary_entry.connection_id.as_deref(),
        Some(primary_id.as_str())
    );
    assert_eq!(web_entry.connection_id.as_deref(), Some(web_id.as_str()));
}

// ---------------------------------------------------------------------------
// AC19: the real `/bus` bridge. Everything below binds a loopback socket.
//
// The rig is copied from `web_bus_governance.rs`, not shared through
// `tests/support/`, because the existing `web_bus_*` test files must stay
// unmodified on this branch (spec AC24); moving the copies into `tests/support/`
// is a follow-up. It is the served `web::serve` over `assemble`'s registry and `tui::server`,
// with the shared governance, the push wiring and the two bridge tokens `main.rs`
// gives the web run. The one difference is the call helper: that file's `call`
// throws away every notification frame it skips on the way to a reply, and this
// test is about notification frames, so `Bus` keeps every frame it receives.
// ---------------------------------------------------------------------------

const AGENT_TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OPERATOR_TOKEN: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// Bound on every wait for something that must happen, so a hang fails in this
/// long rather than stalling the run.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A served `aitm web` bridge, policy `Auto`, both bridge tokens configured.
struct BusServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// The CA directory `assemble` wrote key material into; removed on drop.
    ca_dir: PathBuf,
    /// Kept alive for the test: the registry and store behind the served bridge.
    _proxy: Proxy,
}

impl Drop for BusServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.ca_dir);
    }
}

async fn start_bus(tag: &str) -> BusServer {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.mcp.policy = AgentPolicy::Auto;
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let web_server = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let web_server =
        tui::with_shared_governance(web_server, &assembled.agent_state, &assembled.audit_ring);
    let web_server = web_server
        .with_push(assembled.push_tx.clone())
        .with_approval_timeout(TIMEOUT);
    let mcp = Arc::new(web_server);
    mcp.spawn_push_dispatcher();
    let web_state = Arc::new(WebState {
        mcp,
        agent_token: AGENT_TOKEN.to_owned(),
        operator_token: Some(OPERATOR_TOKEN.to_owned()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(web::serve(listener, web_state));
    BusServer {
        addr,
        task,
        ca_dir: cfg.ca.dir.clone(),
        _proxy: assembled.proxy,
    }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(server: &BusServer) -> Ws {
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

/// One authenticated bus connection. Everything the server delivers on it, replies
/// and notification lines alike, is kept in `delivered` in arrival order, so a test
/// can ask afterwards what the stream did and did not carry.
struct Bus {
    ws: Ws,
    delivered: Vec<JsonValue>,
}

impl Bus {
    /// Read one more frame, keeping it; `None` when `deadline` passes first. The
    /// stream ending is a failure, not a quiet `None`.
    async fn pump(&mut self, deadline: Instant) -> Option<JsonValue> {
        match tokio::time::timeout_at(deadline, next_frame(&mut self.ws)).await {
            Err(_) => None,
            Ok(Some(frame)) => {
                self.delivered.push(frame.clone());
                Some(frame)
            }
            Ok(None) => panic!(
                "the stream ended; frames delivered so far: {:?}",
                self.delivered
            ),
        }
    }

    /// One JSON-RPC request, returning the whole reply whose `id` matches. Every
    /// other frame that arrives first stays in `delivered`.
    async fn request(&mut self, id: u64, method: &str, params: JsonValue) -> JsonValue {
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        send_text(&mut self.ws, line.to_string()).await;
        let deadline = Instant::now() + TIMEOUT;
        loop {
            match self.pump(deadline).await {
                Some(frame) if frame["id"] == id => return frame,
                Some(_) => {}
                None => panic!(
                    "timed out waiting for the reply to {method} (id {id}); frames delivered: {:?}",
                    self.delivered
                ),
            }
        }
    }

    /// One `tools/call`, returning the whole reply.
    async fn call(&mut self, id: u64, name: &str, arguments: JsonValue) -> JsonValue {
        self.request(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await
    }

    /// Wait until at least `count` delivered frames satisfy `pred`, counting the
    /// ones that already arrived, and return every such frame. Reading stops at
    /// [`TIMEOUT`], which fails with the frames seen.
    async fn wait_for(
        &mut self,
        what: &str,
        count: usize,
        pred: impl Fn(&JsonValue) -> bool,
    ) -> Vec<JsonValue> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let hits: Vec<JsonValue> = self.delivered.iter().filter(|f| pred(f)).cloned().collect();
            if hits.len() >= count {
                return hits;
            }
            if self.pump(deadline).await.is_none() {
                panic!(
                    "timed out waiting for {what} ({} of {count} seen); frames delivered: {:?}",
                    hits.len(),
                    self.delivered
                );
            }
        }
    }
}

/// Open the bus as `token`: connect, send the token line, `initialize`, and check
/// the role echo is `role`. Returns the connection and the whole `initialize` reply.
async fn open_bus(server: &BusServer, token: &str, role: &str) -> (Bus, JsonValue) {
    let mut ws = ws_connect(server).await;
    send_text(&mut ws, json!({ "token": token }).to_string()).await;
    let mut bus = Bus {
        ws,
        delivered: Vec::new(),
    };
    let init = bus
        .request(
            0,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "aitm-web", "version": "0"}}),
        )
        .await;
    assert_eq!(init["result"]["role"], role, "initialize reply: {init}");
    (bus, init)
}

/// The `connection_id` an `initialize` reply carries: a non-empty string of at most
/// 64 bytes, the only shape the contract pins.
fn connection_id_of(what: &str, reply: &JsonValue) -> String {
    let id = reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("{what} carries no string connection_id; the reply was: {reply}")
        });
    assert!(
        !id.is_empty() && id.len() <= 64,
        "{what}: connection_id must be non-empty and at most 64 bytes, got {id:?}"
    );
    id.to_owned()
}

/// `reply` must be a successful tool result (`result.isError == false`).
fn assert_ok(what: &str, reply: &JsonValue) {
    assert_eq!(
        reply["result"]["isError"], false,
        "{what} must be a successful tool result; the whole reply was: {reply}"
    );
}

/// Whether `frame` is the pushed audit line for `command`.
fn is_audit_line(frame: &JsonValue, command: &str) -> bool {
    frame["method"] == "notifications/aitm/agent" && frame["params"]["command"] == command
}

/// AC19: over a real `/bus` bridge the connection id is the server's, and the audit
/// stream is filtered by the viewer's role.
///
/// (1) An agent and an operator connection each learn a distinct, server-assigned
/// id from `initialize`. (3) A forged `clientInfo`, `_meta` and top-level claim in a
/// later `initialize` changes neither the id nor the label the lines carry. (4, 5)
/// Each connection's own call produces a line on its own stream stamped with its
/// own id and role. (6) The operator's `proxy.status` line never reaches the agent:
/// the proof is the agent's own later `flow.list` line, which the server fans out
/// after the operator's, so by the time it has arrived the operator's line would
/// have been in front of it on the same FIFO sink had it been pushed at all.
#[tokio::test]
async fn bridge_ids_are_server_assigned_and_the_stream_is_role_filtered() {
    let server = start_bus("bridge-ids").await;

    // (1) Each connection is told its own id; the two differ.
    let (mut agent, agent_init) = open_bus(&server, AGENT_TOKEN, "agent").await;
    let (mut operator, operator_init) = open_bus(&server, OPERATOR_TOKEN, "operator").await;
    let gid = connection_id_of("the agent's initialize", &agent_init);
    let oid = connection_id_of("the operator's initialize", &operator_init);
    assert_ne!(
        gid, oid,
        "two connections on one server must not share an id"
    );

    // (2) Both subscribe, so both streams receive pushed audit lines.
    for (who, bus) in [("agent", &mut agent), ("operator", &mut operator)] {
        let reply = bus.call(1, "flow.subscribe", json!({})).await;
        assert_ok(&format!("the {who}'s flow.subscribe"), &reply);
        assert!(
            reply["result"]["structuredContent"]["sub_id"].is_u64(),
            "the {who}'s flow.subscribe must return a u64 sub_id; the whole reply was: {reply}"
        );
    }

    // (3) A forged claim in a repeated `initialize` does not move the id.
    let forged = agent
        .request(
            2,
            "initialize",
            json!({
                "clientInfo": {"name": "conn_victim", "connection_id": "conn_victim"},
                "_meta": {"connection_id": "conn_victim"},
                "connection_id": "conn_victim",
            }),
        )
        .await;
    assert_eq!(
        connection_id_of("the agent's forged initialize", &forged),
        gid,
        "a repeated initialize must return the connection's own id, not a claimed one"
    );

    // (4) The agent's `flow.list` lands on the agent's stream under the agent's id,
    // and the bridge's own client label, `web-bridge` (the server mints it, since
    // PR 171: a path name, never `clientInfo.name`, forged or not).
    let listed = agent.call(3, "flow.list", json!({})).await;
    assert_ok("the agent's flow.list", &listed);
    let first = agent
        .wait_for("the agent's first flow.list audit line", 1, |v| {
            is_audit_line(v, "flow.list")
        })
        .await;
    let params = &first[0]["params"];
    assert_eq!(params["origin"], "mcp", "{}", first[0]);
    assert_eq!(
        params["connection_id"],
        gid.as_str(),
        "the line carries the server's id for this connection: {}",
        first[0]
    );
    assert_eq!(
        params.get("client_label"),
        Some(&json!("web-bridge")),
        "client_label is the server-minted web-bridge over /bus whatever clientInfo.name claimed: {}",
        first[0]
    );

    // (5) The operator's `proxy.status` lands on the operator's stream under the
    // operator's id.
    let status = operator.call(2, "proxy.status", json!({})).await;
    assert_ok("the operator's proxy.status", &status);
    let own = operator
        .wait_for("the operator's proxy.status audit line", 1, |v| {
            is_audit_line(v, "proxy.status")
        })
        .await;
    assert_eq!(own[0]["params"]["origin"], "operator", "{}", own[0]);
    assert_eq!(
        own[0]["params"]["connection_id"],
        oid.as_str(),
        "the operator's line carries the operator's id: {}",
        own[0]
    );

    // (6) Barrier, then the absence check. The operator's line was fanned out
    // inside the operator's call, which has returned. The agent's next audit line
    // is fanned out after it, so once that line is here the agent's stream has had
    // every chance to carry the operator's.
    let relisted = agent.call(4, "flow.list", json!({})).await;
    assert_ok("the agent's second flow.list", &relisted);
    let agent_lines = agent
        .wait_for("the agent's second flow.list audit line", 2, |v| {
            is_audit_line(v, "flow.list")
        })
        .await;
    assert!(
        agent
            .delivered
            .iter()
            .all(|v| v["params"]["origin"] != "operator"),
        "the agent's stream must carry no operator-origin line; frames delivered: {:?}",
        agent.delivered
    );
    assert!(
        agent
            .delivered
            .iter()
            .all(|v| v["params"]["command"] != "proxy.status"),
        "the agent's stream must not carry the operator's proxy.status line; frames delivered: {:?}",
        agent.delivered
    );
    // What the agent did see is exactly its own two calls, each under its own id.
    assert_eq!(
        agent
            .delivered
            .iter()
            .filter(|v| v["method"] == "notifications/aitm/agent")
            .filter_map(|v| v["params"]["command"].as_str())
            .collect::<Vec<_>>(),
        ["flow.list", "flow.list"],
        "the agent's audit lines are its own flow.list calls and nothing else: {:?}",
        agent.delivered
    );
    for line in &agent_lines {
        assert_eq!(line["params"]["origin"], "mcp", "{line}");
        assert_eq!(line["params"]["connection_id"], gid.as_str(), "{line}");
        assert_eq!(line["params"]["client_label"], "web-bridge", "{line}");
    }

    // The filter is by the viewer's role, not "own lines only": the operator's
    // stream carries both of the agent's calls, under the agent's id.
    let seen_by_operator = operator
        .wait_for(
            "both of the agent's flow.list lines on the operator's stream",
            2,
            |v| is_audit_line(v, "flow.list"),
        )
        .await;
    for line in &seen_by_operator {
        assert_eq!(line["params"]["origin"], "mcp", "{line}");
        assert_eq!(line["params"]["connection_id"], gid.as_str(), "{line}");
    }
}
