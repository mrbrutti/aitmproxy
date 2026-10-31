//! `aitm tui` agent governance, in process (spec
//! `2026-10-30-tui-mode-governance-design.md`, AC1-AC6, plus the edge cases
//! around them).
//!
//! The loopback agent server that `tui::build_servers` builds must run on the
//! core's own `AgentState` and `AuditRing`, so that:
//!
//! - a live `agent.set` from the TUI governs the agent on its next call, in
//!   both directions (AC1, AC2);
//! - the seeded policy still carries over (AC3) and default `auto` is
//!   unchanged (AC4);
//! - every agent call, allowed or refused, lands in the one shared audit trail
//!   the TUI's `agent.status` and `agent.activity` read (AC5);
//! - the TUI's own in-process operator server stays ungated, unrecorded, and
//!   unable to approve (AC6).
//!
//! Around those, the edge cases a proxy must survive on the governed agent
//! server:
//!
//! - the agent cannot lift or widen the policy that governs it: its
//!   `agent.set` and `agent.approve` are refused under every posture;
//! - a paused agent still gets `initialize`, `tools/list` and `ping`;
//! - malformed and empty input is a protocol error that is never audited;
//! - an oversized, secret-bearing refused call reaches the TUI's trail as one
//!   row, and the secret is never shown;
//! - under `ask`, an operator-token client subscribed on the agent server
//!   resolves what the TUI cannot, and its connection drop ends the asking;
//! - the streamable-HTTP agent transport is governed by the same live state
//!   and ring;
//! - an operator-token client governs the agent as the TUI does and is
//!   recorded as `"operator"`;
//! - with `push_tx` unfed, a subscribed operator is still pushed one audit
//!   line per agent call.
//!
//! Each test's doc says whether it is a **red-set** test (it fails against the
//! pre-switch wiring, a private `AgentState` and a private ring in
//! `build_servers`' agent arm) or a **guard** (it passes against both wirings
//! and pins behaviour the switch must not disturb).
//!
//! No sockets and no async runtime. The rig builds through the production path
//! only (`assemble` → `governance()` → `services` → `build_servers`), never a
//! hand-built server: agent calls go through the agent server's `handle_on` as
//! `Frontend::Mcp`, TUI calls through the `InProcessHandler` the TUI itself
//! uses. A call that may park runs on its own thread under [`PARK_BOUND`].

mod support;

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aitm::tui::{self, TuiLog};
use aitm::wire::{assemble, Assembled};
use aitm_bus_client::InProcessHandler;
use aitm_core::{AgentPolicy, Config, Frontend, McpTransport, DEFAULT_ARGS_SUMMARY_CAP};
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use serde_json::{json, Value};

/// The loopback agent token the rig's transport is configured with.
const AGENT_TOKEN: &str = "tui-mode-governance-agent-token";
/// The operator token, so the agent arm carries both token classes as `aitm
/// tui` does. No test connects with it: the TUI is the in-process operator.
const OPERATOR_TOKEN: &str = "tui-mode-governance-operator-token";
/// The most a call that must be refused at once is given before it is judged
/// to have parked for operator approval instead; also the most a parked call
/// is given to return once an operator has resolved it.
const PARK_BOUND: Duration = Duration::from_secs(5);
/// The most an approval request is given to be announced to a subscribed
/// operator before the call is judged to have been refused instead.
const ANNOUNCE_BOUND: Duration = Duration::from_secs(5);
/// One argument far larger than any audit entry's argument summary.
const OVERSIZED: usize = 1 << 20;
/// A secret an agent might smuggle into a call's arguments.
const SECRET: &str = "hunter2-super-secret";

/// The two servers `aitm tui` builds over one `Assembled`, exactly as
/// `build_servers` builds them. `assembled` stays alive for the whole test so
/// its `audit_ring` can be read directly.
struct Rig {
    cfg: Config,
    assembled: Assembled,
    /// The agent-facing server (loopback TCP in `main`; never served here).
    agent: Arc<McpServer>,
    /// The TUI-facing server behind the TUI's real in-process handler.
    tui: InProcessHandler,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cfg.ca.dir);
    }
}

/// Build through the production path on loopback TCP. `None` keeps
/// `Config::default()`'s policy; `Some(p)` seeds `cfg.mcp.policy` before
/// `assemble`, as a test may.
fn rig(tag: &str, policy: Option<AgentPolicy>) -> Rig {
    rig_on(
        tag,
        policy,
        McpTransport::LoopbackTcp {
            port: 0,
            token: AGENT_TOKEN.into(),
            endpoint_file: None,
        },
    )
}

/// [`rig`] on an explicit agent transport. Nothing is served either way, so
/// no socket is bound whichever transport is named.
fn rig_on(tag: &str, policy: Option<AgentPolicy>, transport: McpTransport) -> Rig {
    let mut cfg = support::config(tag);
    cfg.mcp.transport = transport;
    cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into());
    if let Some(p) = policy {
        cfg.mcp.policy = p;
    }
    let assembled = assemble(&cfg).expect("assemble");
    let governance = assembled.governance();
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let (agent, tui) = tui::build_servers(&cfg, services, governance);
    Rig {
        cfg,
        assembled,
        agent: Arc::new(
            agent.expect("a loopback-TCP or streamable-HTTP transport gets an agent server"),
        ),
        tui,
    }
}

/// One JSON-RPC request line.
fn rpc_line(method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
}

/// One `tools/call` request line.
fn call_line(name: &str, arguments: Value) -> String {
    rpc_line("tools/call", json!({"name": name, "arguments": arguments}))
}

/// The whole JSON-RPC reply to `method` on the agent server, as `conn`.
fn agent_rpc(rig: &Rig, conn: &ConnCtx, method: &str, params: Value) -> Value {
    let reply = rig
        .agent
        .handle_on(conn, &rpc_line(method, params))
        .unwrap_or_else(|| panic!("the agent server replies to `{method}`"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// The whole JSON-RPC reply to a `tools/call` on the agent server, as `conn`.
fn agent_call(rig: &Rig, conn: &ConnCtx, name: &str, arguments: Value) -> Value {
    agent_rpc(
        rig,
        conn,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

/// The whole JSON-RPC reply to a `tools/call` through the TUI's in-process
/// handler, the TUI's real path.
fn tui_call(rig: &Rig, name: &str, arguments: Value) -> Value {
    let reply = (rig.tui)(&call_line(name, arguments))
        .unwrap_or_else(|| panic!("the TUI server replies to `{name}`"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// An agent `tools/call`, as a fresh `ConnCtx::new(Frontend::Mcp)`, on its
/// own thread; the thread's result is the whole JSON-RPC reply. A call that
/// parks for operator approval blocks its thread until an operator resolves
/// it, so the caller reads the reply through [`reply_within`].
fn spawn_agent_call(rig: &Rig, name: &str, arguments: Value) -> JoinHandle<Value> {
    let agent = Arc::clone(&rig.agent);
    let line = call_line(name, arguments);
    let what = name.to_string();
    std::thread::spawn(move || {
        let reply = agent
            .handle_on(&ConnCtx::new(Frontend::Mcp), &line)
            .unwrap_or_else(|| panic!("the agent server replies to `{what}`"));
        serde_json::from_str(&reply).expect("the reply is JSON")
    })
}

/// The reply of the agent call running on `handle`, which must arrive within
/// [`PARK_BOUND`]. `still_running` says what it means when it does not.
fn reply_within(handle: JoinHandle<Value>, name: &str, still_running: &str) -> Value {
    let deadline = Instant::now() + PARK_BOUND;
    while !handle.is_finished() {
        assert!(
            Instant::now() < deadline,
            "`{name}` did not return within {PARK_BOUND:?}: {still_running}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // A thread that ended without a reply panicked (no reply from the server,
    // or a reply that was not JSON). That is not a park.
    handle.join().unwrap_or_else(|_| {
        panic!("`{name}`: the agent thread ended without a reply (see its panic above)")
    })
}

/// An agent `tools/call` that must be refused at once. A call that parks for
/// operator approval never replies within [`PARK_BOUND`], so a timeout here is
/// that failure.
fn agent_call_within(rig: &Rig, name: &str, arguments: Value) -> Value {
    reply_within(
        spawn_agent_call(rig, name, arguments),
        name,
        "the agent call parked instead of refusing",
    )
}

/// The text of a tool result's first content item, or "" when there is none.
fn text_of(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
}

/// The tool ran: `result.isError` is `false`.
fn assert_ok(reply: &Value) {
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
}

/// The tool was refused: `result.isError` is `true` and the refusal text
/// contains every needle. `context` prefixes every message (empty for none);
/// a test that loops over postures passes the one it expected the refusal
/// under.
fn assert_refused_in(context: &str, reply: &Value, needles: &[&str]) {
    assert_eq!(reply["result"]["isError"], json!(true), "{context}{reply}");
    for needle in needles {
        assert!(
            text_of(reply).contains(needle),
            "{context}the refusal text lacks {needle:?}: {reply}"
        );
    }
}

/// [`assert_refused_in`] with no context.
fn assert_refused(reply: &Value, needles: &[&str]) {
    assert_refused_in("", reply, needles);
}

/// The TUI's `agent.set {policy}`; asserts the reply echoes `policy`.
fn tui_set_policy(rig: &Rig, policy: &str) {
    let reply = tui_call(rig, "agent.set", json!({"policy": policy}));
    assert_ok(&reply);
    assert_eq!(
        reply["result"]["structuredContent"]["policy"],
        json!(policy),
        "{reply}"
    );
}

/// The policy the TUI's `agent.status` reports.
fn tui_policy(rig: &Rig) -> Value {
    let reply = tui_call(rig, "agent.status", json!({}));
    assert_ok(&reply);
    reply["result"]["structuredContent"]["policy"].clone()
}

/// Red-set. AC1: a live `agent.set paused` from the TUI refuses the loopback
/// agent on its very next call, on the connection it already holds, and
/// `agent.set auto` lets it run again.
#[test]
fn a_tui_pause_refuses_the_loopback_agent_on_its_next_call() {
    let rig = rig("pause", None);
    let agent = ConnCtx::new(Frontend::Mcp);

    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));

    tui_set_policy(&rig, "paused");

    for name in ["flow.list", "agent.status", "flow.subscribe"] {
        let reply = agent_call(&rig, &agent, name, json!({}));
        assert_refused(&reply, &["the agent policy is `paused`"]);
    }
    assert_eq!(tui_policy(&rig), json!("paused"));

    tui_set_policy(&rig, "auto");
    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
}

/// Red-set. AC2: a live `agent.set readonly` allows the agent's reads and
/// refuses its writes; a live `agent.set ask` refuses a sensitive call at once
/// when no operator is connected to the agent server to approve it (the TUI
/// cannot).
#[test]
fn tui_readonly_and_ask_govern_the_loopback_agent_live() {
    let rig = rig("readonly-ask", None);
    let agent = ConnCtx::new(Frontend::Mcp);

    tui_set_policy(&rig, "readonly");
    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
    let kill = agent_call(&rig, &agent, "flow.kill", json!({}));
    assert_refused(
        &kill,
        &["`flow.kill` refused", "the agent policy is `readonly`"],
    );

    tui_set_policy(&rig, "ask");
    let add = agent_call_within(&rig, "scope.add", json!({"host": "example.com"}));
    assert_refused(&add, &["no operator is connected to approve it"]);
}

/// AC3 (guard): the policy seeded in `cfg.mcp.policy` governs the agent's
/// first call and is what the TUI's `agent.status` reports.
#[test]
fn the_seeded_policy_carries_over_to_the_loopback_agent() {
    let readonly = rig("seed-readonly", Some(AgentPolicy::ReadOnly));
    let kill = agent_call(
        &readonly,
        &ConnCtx::new(Frontend::Mcp),
        "flow.kill",
        json!({}),
    );
    assert_refused(&kill, &["the agent policy is `readonly`"]);
    assert_eq!(tui_policy(&readonly), json!("readonly"));

    let ask = rig("seed-ask", Some(AgentPolicy::Ask));
    let add = agent_call_within(&ask, "scope.add", json!({"host": "example.com"}));
    assert_refused(&add, &["no operator is connected to approve it"]);
    assert_eq!(tui_policy(&ask), json!("ask"));
}

/// AC4 (guard): under the default `auto`, the agent reads, and a sensitive
/// call is refused as before.
#[test]
fn default_auto_still_refuses_a_sensitive_loopback_agent_call() {
    let rig = rig("default-auto", None);
    let agent = ConnCtx::new(Frontend::Mcp);

    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
    let add = agent_call(&rig, &agent, "scope.add", json!({}));
    assert_refused(&add, &["the agent policy is `auto`"]);
    assert_eq!(tui_policy(&rig), json!("auto"));
}

/// Red-set. AC5: the loopback agent's calls, allowed and refused, are counted
/// and listed by the TUI's `agent.status` / `agent.activity`, and are in the
/// core's own `audit_ring`. The audit assertions run first so the red cause
/// is the count.
#[test]
fn loopback_agent_calls_land_in_the_shared_audit_trail() {
    let rig = rig("audit", Some(AgentPolicy::ReadOnly));
    let agent = ConnCtx::new(Frontend::Mcp);

    let status = agent_call(&rig, &agent, "agent.status", json!({}));
    let kill = agent_call(&rig, &agent, "flow.kill", json!({}));

    let tui_status = tui_call(&rig, "agent.status", json!({}));
    assert_ok(&tui_status);
    assert_eq!(
        tui_status["result"]["structuredContent"]["actions_last_minute"],
        json!(2),
        "the TUI's agent.status counts the agent's two calls: {tui_status}"
    );

    let activity = tui_call(&rig, "agent.activity", json!({}));
    assert_ok(&activity);
    let rows = activity["result"]["structuredContent"]
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {activity}"));
    assert_eq!(rows.len(), 2, "exactly the agent's two calls: {activity}");
    assert_eq!(rows[0]["origin"], json!("mcp"), "{activity}");
    assert_eq!(rows[0]["command"], json!("agent.status"), "{activity}");
    assert_eq!(rows[0]["result"], json!("ok"), "{activity}");
    assert_eq!(rows[1]["origin"], json!("mcp"), "{activity}");
    assert_eq!(rows[1]["command"], json!("flow.kill"), "{activity}");
    let error = rows[1]["result"]["error"]
        .as_str()
        .unwrap_or_else(|| panic!("the refused flow.kill has a string result.error: {activity}"));
    assert!(error.contains("readonly"), "{activity}");
    assert_eq!(rig.assembled.audit_ring.len(), 2);

    assert_ok(&status);
    assert_refused(&kill, &["readonly"]);
}

/// AC6 (guard): the TUI's own in-process operator server is ungated under
/// `paused`, cannot subscribe or approve (no push sink, no parked requests),
/// and writes nothing to the shared ring.
#[test]
fn the_tui_operator_surface_stays_ungated_unrecorded_and_cannot_approve() {
    let rig = rig("operator", Some(AgentPolicy::Paused));

    let list = tui_call(&rig, "flow.list", json!({}));
    assert_ok(&list);
    assert_eq!(list["result"]["structuredContent"], json!([]), "{list}");
    assert_eq!(tui_policy(&rig), json!("paused"));

    let intercept = tui_call(&rig, "flow.intercept", json!({"enabled": true}));
    assert_ok(&intercept);
    assert_eq!(
        intercept["result"]["structuredContent"]["enabled"],
        json!(true),
        "{intercept}"
    );

    let subscribe = tui_call(&rig, "flow.subscribe", json!({}));
    assert_refused(
        &subscribe,
        &["only meaningful over a streaming MCP connection"],
    );

    let approve = tui_call(
        &rig,
        "agent.approve",
        json!({"request_id": "apr_none", "allow": true}),
    );
    assert_refused(&approve, &["no parked request"]);

    assert_eq!(rig.assembled.audit_ring.len(), 0);
}

/// An operator-role connection with a push sink, subscribed on the agent
/// server (`flow.subscribe {}`), as an operator-token loopback client is.
fn subscribe_operator(rig: &Rig) -> (ConnCtx, NotificationSink) {
    let sink = NotificationSink::new(64);
    let conn = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: 1,
        out: Some(sink.clone()),
    };
    let reply = agent_call(rig, &conn, "flow.subscribe", json!({}));
    assert!(
        reply["result"]["structuredContent"]["sub_id"].is_u64(),
        "the operator's flow.subscribe returns a sub_id: {reply}"
    );
    (conn, sink)
}

/// Wait for the `approval_requested` push that announces `parked` to `sink`.
/// Returns as soon as the call has already returned (it was refused, not
/// parked), naming its reply, rather than waiting out [`ANNOUNCE_BOUND`].
fn announced_request(
    sink: &NotificationSink,
    parked: JoinHandle<Value>,
) -> (Value, JoinHandle<Value>) {
    let deadline = Instant::now() + ANNOUNCE_BOUND;
    loop {
        for line in sink.drain() {
            let push: Value = serde_json::from_str(&line).expect("a pushed line is JSON");
            if push["method"] == "notifications/aitm/agent"
                && push["params"]["event"] == "approval_requested"
            {
                return (push, parked);
            }
        }
        if parked.is_finished() {
            let reply = parked.join().expect("the agent thread");
            panic!("no approval_requested was pushed and the agent call already returned (it was refused, not parked): {reply}");
        }
        assert!(
            Instant::now() < deadline,
            "no approval_requested within {ANNOUNCE_BOUND:?}, and the agent call is still running"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Guard. The policy the agent is governed by is the operator's to write.
/// Under every posture the loopback agent's `agent.set` is refused (and never
/// parked, even under `ask`), and its `agent.approve` is the role refusal, so
/// a paused agent cannot lift the pause that governs it, and an agent cannot
/// widen itself. Both calls read the one shared `AgentState`, so this is the
/// property the shared state makes security-relevant.
#[test]
fn the_loopback_agent_cannot_rewrite_the_policy_that_governs_it() {
    let rig = rig("self-lift", None);
    for policy in ["paused", "readonly", "auto", "ask", "all"] {
        tui_set_policy(&rig, policy);
        let under = format!("under `{policy}`: ");
        // A target that differs from the current posture, so a change shows.
        let target = if policy == "all" { "readonly" } else { "all" };

        let set = agent_call_within(&rig, "agent.set", json!({"policy": target}));
        assert_refused_in(&under, &set, &["`agent.set` refused"]);

        let approve = agent_call_within(
            &rig,
            "agent.approve",
            json!({"request_id": "apr_never_parked", "allow": true}),
        );
        assert_refused_in(&under, &approve, &["cannot approve its own requests"]);

        // The role gate decides before the arguments are looked at, so a
        // malformed approve is the same refusal, not a schema error that
        // would tell the agent how to shape a valid one.
        let malformed = agent_call_within(&rig, "agent.approve", json!({"bogus": 1}));
        assert_refused_in(&under, &malformed, &["cannot approve its own requests"]);

        assert_eq!(
            tui_policy(&rig),
            json!(policy),
            "the agent changed the policy while it was `{policy}`"
        );
    }
}

/// Guard (spec Design 5, consequence 2). `paused` refuses every agent tool
/// call but `initialize`, `tools/list` and `ping` still answer, so a paused
/// agent connection stays up and can be resumed rather than being locked out
/// of the protocol. The first block is the control: the pause really is live.
#[test]
fn a_paused_loopback_agent_still_gets_initialize_tools_list_and_ping() {
    let rig = rig("paused-handshake", Some(AgentPolicy::Paused));
    let agent = ConnCtx::new(Frontend::Mcp);

    let refused = agent_call(&rig, &agent, "flow.list", json!({}));
    assert_refused(&refused, &["the agent policy is `paused`"]);

    let init = agent_rpc(&rig, &agent, "initialize", json!({}));
    assert_eq!(init["result"]["role"], json!("agent"), "{init}");
    assert!(init["result"]["protocolVersion"].is_string(), "{init}");

    let list = agent_rpc(&rig, &agent, "tools/list", json!({}));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list returns a tools array: {list}"))
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for expected in ["flow.list", "agent.set", "agent.status"] {
        assert!(
            names.contains(&expected),
            "tools/list names {expected}: {names:?}"
        );
    }

    let ping = agent_rpc(&rig, &agent, "ping", json!({}));
    assert_eq!(ping["result"], json!({}), "{ping}");
}

/// Red-set. Malformed and empty input on the agent server is a JSON-RPC
/// protocol error: it never runs a command and is never audited, it changes no
/// policy, and the server keeps serving afterwards. Two classes are covered:
/// lines that are not a request at all, and well-formed `tools/call` requests
/// whose tool or arguments are invalid (an unknown tool, `arguments` that are
/// not an object, an undeclared argument on an allowed read), which are the
/// protocol errors `call_tool` itself decides not to audit. (Which error code
/// each shape gets is `aitm-mcp`'s to pin.) The last two assertions are the
/// control that makes "never audited" mean something: one valid call lands in
/// the core's shared ring (red against the pre-switch wiring, whose ring is
/// private).
#[test]
fn malformed_and_empty_agent_input_is_a_protocol_error_that_is_never_audited() {
    let rig = rig("malformed", None);
    let agent = ConnCtx::new(Frontend::Mcp);

    for (what, line) in [
        ("an empty line", ""),
        ("truncated JSON", r#"{"jsonrpc":"2.0","id":1,"method":"#),
    ] {
        let reply = rig
            .agent
            .handle_on(&agent, line)
            .unwrap_or_else(|| panic!("{what}: a request gets a reply"));
        let reply: Value = serde_json::from_str(&reply).expect("the reply is JSON");
        assert!(
            reply["error"]["code"].is_i64(),
            "{what}: a JSON-RPC error with a code: {reply}"
        );
        assert!(
            reply.get("result").is_none(),
            "{what}: a malformed request ran something: {reply}"
        );
    }

    for (what, params) in [
        (
            "an unknown tool",
            json!({"name": "no.such.tool", "arguments": {}}),
        ),
        (
            "arguments that are not an object",
            json!({"name": "flow.list", "arguments": [1, 2]}),
        ),
        (
            "an undeclared argument on an allowed read",
            json!({"name": "flow.list", "arguments": {"bogus_arg": 1}}),
        ),
    ] {
        let reply = agent_rpc(&rig, &agent, "tools/call", params);
        assert!(
            reply.get("error").is_some(),
            "{what}: a JSON-RPC error: {reply}"
        );
        assert!(
            reply.get("result").is_none(),
            "{what}: an invalid tools/call ran something: {reply}"
        );
        assert_eq!(
            rig.assembled.audit_ring.len(),
            0,
            "{what}: a protocol error was audited"
        );
    }

    assert_eq!(
        rig.assembled.audit_ring.len(),
        0,
        "protocol failures are not command invocations and are not audited"
    );
    assert_eq!(tui_policy(&rig), json!("auto"));

    // Control: the server still serves, and the ring is live.
    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
    assert_eq!(
        rig.assembled.audit_ring.len(),
        1,
        "one valid agent call lands in the core's shared audit ring"
    );
}

/// Red-set. A refused call whose arguments are enormous and carry secrets
/// reaches the TUI's `agent.activity` as exactly one `"mcp"` row, and the
/// secret appears nowhere in that reply or in the refusal: the shared ring is
/// written by a loopback client the operator does not trust. (How the
/// argument summary is capped and redacted is `aitm-mcp`'s to pin.) Seeded
/// `Paused` so the call is refused and nothing runs.
#[test]
fn an_oversized_secret_bearing_agent_call_reaches_the_tui_trail_without_the_secret() {
    let rig = rig("oversized", Some(AgentPolicy::Paused));
    // Key order matters: the secret-bearing keys come first and the huge one
    // last, so the secrets fall inside the summary cap and the no-secret
    // assertion tests redaction, not truncation.
    let arguments = json!({
        "api_token": SECRET,
        "authorization": format!("Bearer {SECRET}"),
        "a_path": format!("/x?access_token={SECRET}&q=1"),
        "zz_big": "A".repeat(OVERSIZED),
    });

    let reply = agent_call(&rig, &ConnCtx::new(Frontend::Mcp), "flow.list", arguments);
    assert_refused(&reply, &["the agent policy is `paused`"]);
    assert!(
        !reply.to_string().contains(SECRET),
        "the refusal echoed a secret: {reply}"
    );

    let activity = tui_call(&rig, "agent.activity", json!({}));
    assert_ok(&activity);
    let rows = activity["result"]["structuredContent"]
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {}", short(&activity)));
    assert_eq!(
        rows.len(),
        1,
        "exactly the one oversized call: {}",
        short(&activity)
    );
    assert_eq!(rows[0]["origin"], json!("mcp"), "{}", short(&activity));
    assert_eq!(
        rows[0]["command"],
        json!("flow.list"),
        "{}",
        short(&activity)
    );
    // The row's `args` is the ring entry's argument summary. Its size bounds
    // what an untrusted loopback agent can store in the shared ring per call:
    // at most the cap plus the one ellipsis a truncation may append.
    let args = rows[0]["args"]
        .as_str()
        .unwrap_or_else(|| panic!("the row has a string args summary: {}", short(&activity)));
    assert!(
        args.len() <= DEFAULT_ARGS_SUMMARY_CAP + '…'.len_utf8(),
        "the args summary is {} bytes, over the {DEFAULT_ARGS_SUMMARY_CAP}-byte cap: an \
         untrusted loopback agent grew a shared ring entry past the bound",
        args.len()
    );
    assert!(
        !activity.to_string().contains(SECRET),
        "the TUI is shown a secret: {}",
        short(&activity)
    );
    assert_eq!(rig.assembled.audit_ring.len(), 1);
}

/// The first 600 bytes of a reply, so an assertion message cannot print a
/// megabyte.
fn short(reply: &Value) -> String {
    let text = reply.to_string();
    let mut cut = text.len().min(600);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

/// Red-set (spec Design 5, consequence 4; connection drop). Under `ask`, an
/// operator-token client subscribed on the agent server is announced the
/// agent's sensitive call and resolves it; the TUI's own server cannot resolve
/// it (a different `McpServer`, so "no parked request" even for a real id) and
/// the agent cannot approve its own call. The parked call ends in the
/// operator's denial, which also proves neither refused approve resolved it.
/// Then the operator's connection drops: the next sensitive agent call is
/// refused at once rather than parked behind a subscription that outlived its
/// connection.
#[test]
fn an_operator_on_the_agent_server_resolves_what_the_tui_cannot_and_a_drop_ends_asking() {
    let rig = rig("ask-approve", None);
    tui_set_policy(&rig, "ask");
    let (operator, sink) = subscribe_operator(&rig);

    let parked = spawn_agent_call(&rig, "scope.add", json!({"host": "example.com"}));
    let (request, parked) = announced_request(&sink, parked);
    assert_eq!(
        request["params"]["command"],
        json!("scope.add"),
        "{request}"
    );
    let request_id = request["params"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the push carries a string request_id: {request}"))
        .to_string();
    assert!(request_id.starts_with("apr_"), "{request_id}");
    assert!(!parked.is_finished(), "the call is parked, not answered");

    let from_tui = tui_call(
        &rig,
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert_refused(&from_tui, &["no parked request"]);
    let from_agent = agent_call(
        &rig,
        &ConnCtx::new(Frontend::Mcp),
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert_refused(&from_agent, &["cannot approve its own requests"]);

    let denied = agent_call(
        &rig,
        &operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": false}),
    );
    assert_ok(&denied);
    let outcome = reply_within(
        parked,
        "scope.add",
        "the operator's denial did not release the parked call",
    );
    assert_refused(
        &outcome,
        &["an operator denied the parked sensitive command"],
    );

    rig.agent.drop_connection(operator.conn_id);
    let after = agent_call_within(&rig, "scope.add", json!({"host": "example.com"}));
    assert_refused(&after, &["no operator is connected to approve it"]);
}

/// Red-set. The streamable-HTTP agent transport shares `build_servers`' agent
/// arm with loopback TCP, so it must be governed by the same live state and
/// ring: a live pause refuses its next call, and both calls are in the core's
/// shared ring. (AC1-AC7 drive loopback only.)
#[test]
fn the_streamable_http_agent_server_is_governed_by_the_same_live_state_and_ring() {
    let rig = rig_on(
        "http",
        None,
        McpTransport::streamable_http_default("tui-mode-governance-http-token".into()),
    );
    let agent = ConnCtx::new(Frontend::Mcp);

    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
    tui_set_policy(&rig, "paused");
    let refused = agent_call(&rig, &agent, "flow.list", json!({}));
    assert_refused(&refused, &["the agent policy is `paused`"]);

    assert_eq!(rig.assembled.audit_ring.len(), 2);
}

/// Red-set (spec Goal 1; Design 5, consequences 2, 3 and 5). An operator-token
/// client of the agent server governs the loopback agent exactly as the TUI
/// does: its `agent.set paused` refuses the agent's very next call, it is not
/// itself governed by the posture it set (its own `flow.list` still runs and it
/// can `agent.set` back), and every call on the agent server is in the core's
/// shared trail with the origin of the connection that made it, `"mcp"` for the
/// agent and `"operator"` for the operator-token client. The refusal is
/// asserted before the trail, so against the pre-switch wiring (a private
/// `AgentState`, which the operator's `agent.set` never reaches) the red cause
/// is the unrefused agent call.
#[test]
fn an_operator_token_client_governs_the_loopback_agent_and_is_recorded_as_operator() {
    let rig = rig("operator-client", None);
    let agent = ConnCtx::new(Frontend::Mcp);
    let operator = ConnCtx::new(Frontend::Operator);

    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));

    let pause = agent_call(&rig, &operator, "agent.set", json!({"policy": "paused"}));
    assert_ok(&pause);
    assert_eq!(
        pause["result"]["structuredContent"]["policy"],
        json!("paused"),
        "{pause}"
    );
    let refused = agent_call(&rig, &agent, "flow.list", json!({}));
    assert_refused(&refused, &["the agent policy is `paused`"]);
    assert_eq!(tui_policy(&rig), json!("paused"));

    // The operator keeps full control while the agent is paused.
    assert_ok(&agent_call(&rig, &operator, "flow.list", json!({})));
    let resume = agent_call(&rig, &operator, "agent.set", json!({"policy": "auto"}));
    assert_ok(&resume);
    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));

    let activity = tui_call(&rig, "agent.activity", json!({}));
    assert_ok(&activity);
    let rows = activity["result"]["structuredContent"]
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {activity}"));
    // (origin, command, whether the call ran) in call order.
    let expected = [
        ("mcp", "flow.list", true),
        ("operator", "agent.set", true),
        ("mcp", "flow.list", false),
        ("operator", "flow.list", true),
        ("operator", "agent.set", true),
        ("mcp", "flow.list", true),
    ];
    assert_eq!(
        rows.len(),
        expected.len(),
        "exactly the six calls on the agent server: {activity}"
    );
    for (i, (row, (origin, command, ran))) in rows.iter().zip(expected).enumerate() {
        assert_eq!(row["origin"], json!(origin), "row {i}: {activity}");
        assert_eq!(row["command"], json!(command), "row {i}: {activity}");
        if ran {
            assert_eq!(row["result"], json!("ok"), "row {i}: {activity}");
        } else {
            let error = row["result"]["error"]
                .as_str()
                .unwrap_or_else(|| panic!("row {i} is a refusal with a string error: {activity}"));
            assert!(error.contains("paused"), "row {i}: {activity}");
        }
    }
    assert_eq!(rig.assembled.audit_ring.len(), expected.len());
}

/// Guard (spec Design 4; the `main.rs` comment). With `push_tx` unfed, an
/// operator subscribed on the agent server is still pushed one
/// `notifications/aitm/agent` line per agent call, allowed or refused, and
/// nothing else: the audit stream does not depend on `push_tx`. The operator's
/// own successful `flow.subscribe` is connection management and is neither
/// audited nor pushed. Passes against both wirings: the subscription registry
/// and the push are the agent server's own either way.
#[test]
fn a_subscribed_operator_is_still_pushed_each_agent_call_with_push_unfed() {
    let rig = rig("audit-push", None);
    let (_operator, sink) = subscribe_operator(&rig);
    assert_eq!(
        sink.drain(),
        Vec::<String>::new(),
        "a successful flow.subscribe is not pushed back to its subscriber"
    );

    let agent = ConnCtx::new(Frontend::Mcp);
    assert_ok(&agent_call(&rig, &agent, "flow.list", json!({})));
    let add = agent_call(&rig, &agent, "scope.add", json!({}));
    assert_refused(&add, &["the agent policy is `auto`"]);

    let lines = sink.drain();
    assert_eq!(lines.len(), 2, "one push per agent call: {lines:?}");
    let pushes: Vec<Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("a pushed line is JSON"))
        .collect();
    for push in &pushes {
        assert_eq!(push["jsonrpc"], json!("2.0"), "{push}");
        assert_eq!(push["method"], json!("notifications/aitm/agent"), "{push}");
        assert_eq!(push["params"]["origin"], json!("mcp"), "{push}");
    }
    assert_eq!(pushes[0]["params"]["command"], json!("flow.list"));
    assert_eq!(pushes[0]["params"]["result"], json!("ok"));
    assert_eq!(pushes[1]["params"]["command"], json!("scope.add"));
    let error = pushes[1]["params"]["result"]["error"]
        .as_str()
        .unwrap_or_else(|| panic!("the refused scope.add has a string error: {}", pushes[1]));
    assert!(error.contains("auto"), "{}", pushes[1]);
}
