//! The `Ask` split between the primary agent server and the `aitm web` bridge
//! server, in process (spec `2026-10-30-web-bus-agent-governance-design.md`,
//! Design 4, AC9-AC11).
//!
//! `tui::with_shared_governance` shares the policy state and the audit ring
//! between the two servers; it does **not** share the approval hub
//! (`Subscriptions`, parked requests). So, under `ask`:
//!
//! - a web agent's `Sensitive` call is refused at once when no operator is
//!   subscribed on the web server, even if one is subscribed on the primary
//!   (AC9);
//! - an operator subscribed on the web server is announced the parked call and
//!   resolves it with `agent.approve` on the web server (AC10);
//! - an `agent.approve` sent to the primary for a call parked on the web server
//!   approves nothing, and the call stays parked (AC11).
//!
//! No sockets and no async runtime: the servers are driven through
//! `McpServer::handle_on`, a parked call blocks its own `std::thread`, and the
//! operator is a hand-built `ConnCtx` carrying a `NotificationSink`. Both
//! servers are built from one `Assembled`, the way `main.rs` builds them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use aitm::tui::{self, TuiLog};
use aitm::wire::assemble;
use aitm_core::{AgentPolicy, Config, Frontend, Proxy};
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use serde_json::{json, Value as JsonValue};

/// The approval timeout on both servers: far longer than any wait below, so a
/// call that parks is told apart from one that was refused at once.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
/// The most a call that must be refused at once, or announced, is given.
const FAST: Duration = Duration::from_secs(5);
/// How long to listen for a push that must not arrive.
const QUIET: Duration = Duration::from_millis(300);
/// How long a parked call is given to (wrongly) finish before it is asserted
/// still parked.
const SETTLE: Duration = Duration::from_millis(200);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-ask-split-{tag}-{nanos}-{n}"))
}

/// Two servers over one `Assembled`, policy `Ask`: `primary` (the agent server
/// the bare-`aitm` path serves) and `web` (the `aitm web` bridge's server).
struct Rig {
    primary: Arc<McpServer>,
    web: Arc<McpServer>,
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
    cfg.mcp.policy = AgentPolicy::Ask;
    cfg.ca.dir = temp_ca_dir(tag);
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let state = &assembled.agent_state;
    let ring = &assembled.audit_ring;

    let primary = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let primary = tui::with_shared_governance(primary, state, ring);
    let primary = primary.with_approval_timeout(APPROVAL_TIMEOUT);

    let web = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let web = tui::with_shared_governance(web, state, ring); // MUTATION-POINT
    let web = web.with_approval_timeout(APPROVAL_TIMEOUT);

    Rig {
        primary: Arc::new(primary),
        web: Arc::new(web),
        ca_dir: cfg.ca.dir.clone(),
        _proxy: assembled.proxy,
    }
}

/// One `tools/call` on `conn`; the whole JSON-RPC reply.
fn call(srv: &McpServer, conn: &ConnCtx, name: &str, arguments: JsonValue) -> JsonValue {
    let line = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    });
    let reply = srv
        .handle_on(conn, &line.to_string())
        .expect("a reply to a tools/call");
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// The text of a tool result's first content item, or "" when there is none.
fn text_of(reply: &JsonValue) -> &str {
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
}

/// An operator connection with a push sink, subscribed on `srv` (`flow.subscribe
/// {}`), as an operator bridge connection is. Returns the connection and its
/// sink, which `srv` pushes `notifications/aitm/*` lines into.
fn subscribe_operator(srv: &McpServer) -> (ConnCtx, NotificationSink) {
    let sink = NotificationSink::new(64);
    let conn = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: 1,
        out: Some(sink.clone()),
    };
    let reply = call(srv, &conn, "flow.subscribe", json!({}));
    assert!(
        reply["result"]["structuredContent"]["sub_id"].is_u64(),
        "the operator's flow.subscribe returns a sub_id: {reply}"
    );
    (conn, sink)
}

/// Poll `sink` every 10 ms for up to `timeout` for the first
/// `notifications/aitm/agent` line whose `params.event` is
/// `approval_requested`; other lines (audit lines, for one) are skipped.
fn wait_for_approval_request(sink: &NotificationSink, timeout: Duration) -> Option<JsonValue> {
    let deadline = Instant::now() + timeout;
    loop {
        for line in sink.drain() {
            let v: JsonValue = serde_json::from_str(&line).expect("a pushed line is JSON");
            if v["method"] == "notifications/aitm/agent"
                && v["params"]["event"] == "approval_requested"
            {
                return Some(v);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The web agent's sensitive call: `scope.add {host: "example.com"}` as an
/// agent connection. Valid arguments, because a parked call reads them for its
/// approval prompt.
fn agent_scope_add(srv: &McpServer) -> JsonValue {
    call(
        srv,
        &ConnCtx::new(Frontend::Mcp),
        "scope.add",
        json!({"host": "example.com"}),
    )
}

/// Run [`agent_scope_add`] on its own thread: a parked call blocks its thread.
fn spawn_agent_call(srv: &Arc<McpServer>) -> JoinHandle<JsonValue> {
    let srv = Arc::clone(srv);
    std::thread::spawn(move || agent_scope_add(&srv))
}

/// Wait up to [`FAST`] for `sink` to be announced a parked call. On a timeout,
/// panic naming the agent call's own reply when it has already returned, which
/// is what separates "it was refused" from "it is still running".
fn announced_request(
    sink: &NotificationSink,
    agent: JoinHandle<JsonValue>,
) -> (JsonValue, JoinHandle<JsonValue>) {
    match wait_for_approval_request(sink, FAST) {
        Some(request) => (request, agent),
        None if agent.is_finished() => {
            let reply = agent.join().expect("the agent thread");
            panic!("no approval_requested within 5s; the agent call already returned: {reply}")
        }
        None => panic!("no approval_requested within 5s; the agent call is still running"),
    }
}

/// The `request_id` of an `approval_requested` push, after checking the
/// command and the id's shape.
fn request_id_of(request: &JsonValue) -> String {
    assert_eq!(
        request["params"]["command"],
        json!("scope.add"),
        "{request}"
    );
    let id = request["params"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the push carries a string request_id: {request}"));
    assert!(id.starts_with("apr_"), "request_id `{id}` starts apr_");
    id.to_string()
}

/// AC9: an operator subscribed on the primary only does not make a web agent's
/// sensitive call park. The web server has no operator of its own, so the call
/// is refused at once (a 60 s approval timeout is not waited out), and nothing
/// is announced to the primary's operator.
#[test]
fn no_operator_on_the_web_server_refuses_a_web_call_at_once() {
    let rig = rig("no-web-operator");
    let (_p_operator, p_sink) = subscribe_operator(&rig.primary);

    let (tx, rx) = mpsc::channel();
    let web = Arc::clone(&rig.web);
    std::thread::spawn(move || {
        let _ = tx.send(agent_scope_add(&web));
    });
    let reply = rx.recv_timeout(FAST).unwrap_or_else(|_| {
        panic!("the web call did not return within 5s: it parked instead of refusing")
    });

    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert!(
        text_of(&reply).contains("no operator is connected to approve it"),
        "refused for want of a web operator: {reply}"
    );
    assert!(
        wait_for_approval_request(&p_sink, QUIET).is_none(),
        "nothing is announced to the primary's operator"
    );
}

/// AC10: an operator subscribed on the web server is announced the web agent's
/// parked call, and an `agent.approve` on the web server resolves it.
#[test]
fn an_operator_on_the_web_server_is_asked_and_resolves_on_the_web_server() {
    let rig = rig("web-operator");
    let (w_operator, w_sink) = subscribe_operator(&rig.web);

    let agent = spawn_agent_call(&rig.web);
    let (request, agent) = announced_request(&w_sink, agent);
    let request_id = request_id_of(&request);
    assert!(!agent.is_finished(), "the call is parked, not answered");

    let approve = call(
        &rig.web,
        &w_operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": false}),
    );
    assert_eq!(approve["result"]["isError"], json!(false), "{approve}");

    let reply = agent.join().expect("the agent thread");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert!(
        text_of(&reply).contains("an operator denied the parked sensitive command"),
        "{reply}"
    );
}

/// AC11: an `agent.approve` for a call parked on the web server, sent to the
/// primary, is the plain "no parked request" error and approves nothing; the
/// call stays parked until it is resolved on the web server. (Had the primary's
/// approve worked, the web server's would error and the call would have run.)
#[test]
fn an_approve_sent_to_the_primary_approves_nothing_parked_on_the_web_server() {
    let rig = rig("approve-on-primary");
    let (w_operator, w_sink) = subscribe_operator(&rig.web);

    let agent = spawn_agent_call(&rig.web);
    let (request, agent) = announced_request(&w_sink, agent);
    let request_id = request_id_of(&request);

    let misdirected = call(
        &rig.primary,
        &ConnCtx::new(Frontend::Operator),
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert_eq!(
        misdirected["result"]["isError"],
        json!(true),
        "{misdirected}"
    );
    assert!(
        text_of(&misdirected).contains("no parked request"),
        "{misdirected}"
    );
    std::thread::sleep(SETTLE);
    assert!(
        !agent.is_finished(),
        "the primary's approve resolved nothing: the web call is still parked"
    );

    let denied = call(
        &rig.web,
        &w_operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": false}),
    );
    assert_eq!(denied["result"]["isError"], json!(false), "{denied}");
    let reply = agent.join().expect("the agent thread");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert!(
        text_of(&reply).contains("an operator denied the parked sensitive command"),
        "{reply}"
    );
}
