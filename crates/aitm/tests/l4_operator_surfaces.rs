//! Stage B end-to-end — the `l4.*` surface under M4 identity/policy, driven through
//! the real MCP server (`McpServer`), so the two-dimension agent gate, the operator
//! confirm-over-the-wire handshake, the F2 audit log, and the no-self-grant invariant
//! are exercised on the exact path a bus client takes (L4OPS-AC5/AC6; AC11 backing).
//!
//! The `aitm-proto-l4` crate tests cover the in-command half (sensitivity, the flag as
//! the command sees the caller, `confirm_prompt`, the toggle). These cover the halves
//! that live in the server: the `AgentPolicy` dimension, `defers_to_command_gate`, the
//! confirm-token lifecycle, and the audit ring.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::McpTransport;
use aitm_core::{
    AgentPolicy, AgentState, AuditResult, AuditRing, Frontend, HttpFlow, HttpRequest, MemFlowStore,
    ProxyClient, Registry, StdGuard,
};
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use aitm_plugins::AgentPlugin;
use aitm_proto_l4::config::{InterceptConfig, L4Config};
use aitm_proto_l4::types::{
    IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap,
};
use aitm_proto_l4::{L4Module, L4Privilege};
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// An enabled L4 config whose scope authorizes `l4.inject` to `127.0.0.1:9` on `lo0`.
/// `allow_agent_*` default false. Callers tweak the flags per test.
fn l4_cfg() -> L4Config {
    L4Config {
        enabled: true,
        intercept: Some(InterceptConfig::default()),
        scope: vec![L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "lo0".to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Inject,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        }],
        ..L4Config::default()
    }
}

/// A server over a registry holding the L4 module (`cfg`, full privilege so the real
/// verbs are present) and the M4 `AgentPlugin` (for `agent.set`), with the given
/// policy. The core services' guard is **empty**, so an in-scope-at-L4 inject that
/// gets past every gate is refused by the core `check_active` *before* any wire I/O —
/// keeping these tests hermetic. Returns the server and the shared audit ring.
fn server(cfg: &L4Config, policy: AgentPolicy) -> (McpServer, Arc<AuditRing>) {
    let agent_state = Arc::new(AgentState::new(policy));
    let ring = Arc::new(AuditRing::default());
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(L4Module::with_privilege(
        cfg,
        L4Privilege::available(),
    )));
    reg.add_plugin(Box::new(
        AgentPlugin::new(agent_state.clone()).with_audit_ring(ring.clone()),
    ));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(agent_state)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_audit_ring(ring.clone());
    (srv, ring)
}

/// Invoke `name` as `role` with `args`, returning the parsed `result` object.
fn call(srv: &McpServer, role: Frontend, name: &str, args: JsonValue) -> JsonValue {
    let req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    });
    let resp = srv
        .handle_on(&ConnCtx::new(role), &req.to_string())
        .expect("a request gets a response");
    let parsed: JsonValue = serde_json::from_str(&resp).expect("json");
    parsed["result"].clone()
}

/// Whether a `tools/call` result is a tool error (`isError: true`).
fn is_error(result: &JsonValue) -> bool {
    result["isError"].as_bool().unwrap_or(false)
}

/// The error/text of a tool result (for substring assertions).
fn text(result: &JsonValue) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn inject_args(dst: &str, port: i64) -> JsonValue {
    json!({
        "spec": {"layers": [
            {"ipv4": {"dst": dst}},
            {"udp": {"dst_port": port}},
            {"raw": [112, 114, 111, 98, 101]},
        ]},
        "dst": dst,
        "interface": "lo0",
        "port": port,
    })
}

const SENSITIVE_L4: &[&str] = &[
    "l4.scope.add",
    "l4.capture.start",
    "l4.inject",
    "l4.send_recv",
    "l4.intercept.start",
    "l4.intercept.mutate",
    "l4.intercept.forward",
    "l4.intercept.drop",
];

/// AC5 — under `AgentPolicy::Auto` (autonomous, zero-sensitive), every Sensitive
/// `l4.*` agent call is refused by the policy gate, flag on or not; a Read verb runs.
#[test]
fn auto_refuses_all_sensitive_l4() {
    // Even with every per-capability flag ON, Auto still refuses all Sensitive.
    let cfg = L4Config {
        allow_agent_inject: true,
        allow_agent_capture: true,
        allow_agent_intercept: true,
        allow_agent_widen: true,
        ..l4_cfg()
    };
    let (srv, _ring) = server(&cfg, AgentPolicy::Auto);

    for name in SENSITIVE_L4 {
        let res = call(&srv, Frontend::Mcp, name, json!({}));
        assert!(
            is_error(&res),
            "Auto must refuse the Sensitive agent call `{name}`"
        );
    }

    // A Read verb still runs under Auto.
    let res = call(&srv, Frontend::Mcp, "l4.interfaces", json!({}));
    assert!(!is_error(&res), "Auto must allow a Read l4 verb");
}

/// AC5 — under `All`, a Sensitive `l4.*` agent call is refused unless its
/// per-capability flag is on: flag off → the command's agent gate refuses; flag on →
/// the call passes both dimensions and reaches the guard (here the core guard, which
/// refuses the out-of-scope engagement host — proving it got past the flag).
#[test]
fn all_requires_the_per_capability_flag() {
    // Flag OFF: refused by the agent gate before the guard.
    let (srv_off, _r) = server(&l4_cfg(), AgentPolicy::All);
    let res = call(
        &srv_off,
        Frontend::Mcp,
        "l4.inject",
        inject_args("127.0.0.1", 9),
    );
    assert!(is_error(&res));
    assert!(
        text(&res).contains("capability is disabled"),
        "flag-off agent inject must be refused by the agent gate, got: {}",
        text(&res)
    );

    // Flag ON: past both dimensions; refused only by the core engagement guard.
    let cfg_on = L4Config {
        allow_agent_inject: true,
        ..l4_cfg()
    };
    let (srv_on, _r) = server(&cfg_on, AgentPolicy::All);
    let res = call(
        &srv_on,
        Frontend::Mcp,
        "l4.inject",
        inject_args("127.0.0.1", 9),
    );
    assert!(is_error(&res));
    let msg = text(&res);
    assert!(
        !msg.contains("capability is disabled"),
        "flag-on agent inject must pass the agent gate, got: {msg}"
    );
}

/// AC5 — the operator role is never flag-gated. With the inject flag off, an operator
/// out-of-scope inject is refused by the guard (not the agent gate), proving the flag
/// does not apply to the operator.
#[test]
fn operator_is_not_flag_gated() {
    let (srv, _r) = server(&l4_cfg(), AgentPolicy::Auto);
    // Out of L4 scope ⇒ `confirm_prompt` offers nothing (no token), and the guard
    // refuses in invoke — never the agent gate.
    let res = call(
        &srv,
        Frontend::Operator,
        "l4.inject",
        inject_args("8.8.8.8", 443),
    );
    assert!(is_error(&res));
    let msg = text(&res);
    assert!(
        msg.contains("out of L4 scope") && !msg.contains("capability is disabled"),
        "operator inject must bypass the flag and be refused by the guard, got: {msg}"
    );
}

/// AC5 — a gated agent request (refused) is recorded in the F2 audit ring, so a live
/// agent run over L4 is reviewable.
#[test]
fn gated_agent_refusal_is_logged() {
    let (srv, ring) = server(&l4_cfg(), AgentPolicy::All);
    let res = call(
        &srv,
        Frontend::Mcp,
        "l4.inject",
        inject_args("127.0.0.1", 9),
    );
    assert!(is_error(&res));

    let entry = ring
        .recent(None, None)
        .into_iter()
        .find(|e| e.command == "l4.inject")
        .expect("the gated l4.inject attempt must be audited");
    assert_eq!(entry.origin, Frontend::Mcp);
    assert!(
        matches!(entry.result, AuditResult::Error(_)),
        "the refusal must be recorded as an error outcome"
    );
}

/// AC6 — an operator `l4.inject` to an in-scope target returns `needs_confirmation`
/// with a token and a wire summary; re-issuing with `_confirm` consumes the token and
/// proceeds (here to the core guard's refusal — no wire I/O); a reused or bogus token
/// is refused.
#[test]
fn operator_confirm_handshake_and_token_lifecycle() {
    let (srv, _r) = server(&l4_cfg(), AgentPolicy::Auto);

    // First call → needs_confirmation + token + summary.
    let asked = call(
        &srv,
        Frontend::Operator,
        "l4.inject",
        inject_args("127.0.0.1", 9),
    );
    assert!(!is_error(&asked));
    assert_eq!(
        asked["structuredContent"]["status"],
        json!("needs_confirmation")
    );
    let summary = asked["structuredContent"]["prompt"].as_str().unwrap();
    assert!(
        summary.contains("127.0.0.1") && summary.contains("l4.inject"),
        "the summary must describe what hits the wire, got: {summary}"
    );
    let token = asked["structuredContent"]["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();

    // A bogus token is refused.
    let mut bad = inject_args("127.0.0.1", 9);
    bad["_confirm"] = json!("cfm_deadbeefdeadbeefdeadbeefdeadbeef");
    let refused = call(&srv, Frontend::Operator, "l4.inject", bad);
    assert!(is_error(&refused));
    assert!(text(&refused).contains("confirmation token is invalid"));

    // The real token proceeds past the handshake (consumed) to invoke — which the
    // empty core guard refuses, so no packet is sent. It is neither a fresh
    // needs_confirmation nor the invalid-token refusal.
    let mut ok = inject_args("127.0.0.1", 9);
    ok["_confirm"] = json!(token);
    let done = call(&srv, Frontend::Operator, "l4.inject", ok.clone());
    assert_ne!(
        done["structuredContent"]["status"],
        json!("needs_confirmation"),
        "a valid token must proceed, not re-ask"
    );
    assert!(
        !text(&done).contains("confirmation token is invalid"),
        "a valid token must not be rejected"
    );

    // Re-using the now-consumed token is refused (single-use).
    let reused = call(&srv, Frontend::Operator, "l4.inject", ok);
    assert!(is_error(&reused));
    assert!(text(&reused).contains("confirmation token is invalid"));
}

/// AC6 — an out-of-scope operator inject is refused by the guard **before** any
/// confirmation is offered: no `needs_confirmation`, no token minted.
#[test]
fn out_of_scope_refused_before_confirmation() {
    let (srv, _r) = server(&l4_cfg(), AgentPolicy::Auto);
    let res = call(
        &srv,
        Frontend::Operator,
        "l4.inject",
        inject_args("8.8.8.8", 443),
    );
    assert!(is_error(&res));
    assert_ne!(
        res["structuredContent"]["status"],
        json!("needs_confirmation"),
        "an out-of-scope target must not be offered confirmation"
    );
    assert!(
        res["structuredContent"]["confirm_token"].is_null(),
        "no token may be minted for an out-of-scope target"
    );
    assert!(text(&res).contains("out of L4 scope"));
}

/// AC11 backing / Review Focus #2 — an agent can never self-grant: under the most
/// permissive policy (`All`) and with every flag on, an agent `l4.agent.set`,
/// `agent.set`, and `l4.scope.add` are each refused.
#[test]
fn agent_cannot_self_grant() {
    // Even wide open: All policy, and (irrelevant to these three) every capability
    // flag on. Widen stays off so scope.add's own gate is exercised.
    let cfg = L4Config {
        allow_agent_inject: true,
        allow_agent_capture: true,
        allow_agent_intercept: true,
        allow_agent_widen: false,
        ..l4_cfg()
    };
    let (srv, _r) = server(&cfg, AgentPolicy::All);

    // The agent cannot flip its own L4 gates.
    let r = call(
        &srv,
        Frontend::Mcp,
        "l4.agent.set",
        json!({"capability": "inject", "allowed": true}),
    );
    assert!(is_error(&r), "agent l4.agent.set must be refused");

    // Nor the M4 policy.
    let r = call(&srv, Frontend::Mcp, "agent.set", json!({"policy": "all"}));
    assert!(is_error(&r), "agent agent.set must be refused");

    // Nor widen L4 scope (widen gate off).
    let r = call(
        &srv,
        Frontend::Mcp,
        "l4.scope.add",
        json!({
            "cidr": "10.0.0.0/8", "interface": "eth0",
            "direction": "outbound", "capability": "inject",
        }),
    );
    assert!(is_error(&r), "agent l4.scope.add must be refused");

    // The operator, by contrast, can read the gates.
    let status = call(&srv, Frontend::Operator, "l4.agent.status", json!({}));
    assert!(!is_error(&status));
    assert_eq!(status["structuredContent"]["inject"], json!(true));
}

// ---- L4PAR-AC5 / AC6: operator scope add through confirm-over-the-wire ---------

/// The AC5 entry (spec L4PAR-AC5).
fn scope_add_args() -> JsonValue {
    json!({
        "cidr": "127.0.0.1/32", "ports": "9100-9199", "interface": "lo0",
        "direction": "inbound", "capability": "capture",
    })
}

/// `tools/list` as `role`, the `tools` array.
fn list_tools(srv: &McpServer, role: Frontend) -> Vec<JsonValue> {
    let req = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}});
    let resp = srv
        .handle_on(&ConnCtx::new(role), &req.to_string())
        .expect("tools/list gets a response");
    let parsed: JsonValue = serde_json::from_str(&resp).expect("json");
    parsed["result"]["tools"]
        .as_array()
        .cloned()
        .expect("tools is an array")
}

/// The `l4.scope.list` entries as (id, source) pairs, read as the operator.
fn scope_sources(srv: &McpServer) -> Vec<(String, String)> {
    let listed = call(srv, Frontend::Operator, "l4.scope.list", json!({}));
    assert!(
        !is_error(&listed),
        "l4.scope.list failed: {}",
        text(&listed)
    );
    listed["structuredContent"]
        .as_array()
        .expect("scope list is an array")
        .iter()
        .map(|e| {
            (
                e["id"].as_str().expect("id").to_string(),
                e["source"].as_str().expect("source").to_string(),
            )
        })
        .collect()
}

fn widen(srv: &McpServer) -> JsonValue {
    let status = call(srv, Frontend::Operator, "l4.agent.status", json!({}));
    assert!(!is_error(&status), "{}", text(&status));
    status["structuredContent"]["widen"].clone()
}

/// L4PAR-AC5 (plan A6) — over the real MCP server with widen OFF, an operator
/// `l4.scope.add` returns `needs_confirmation` with a token and a prompt naming the
/// five entry fields; re-issuing with `_confirm` returns the new id; `l4.scope.list`
/// shows it `runtime` beside the config entry; `widen` reads false before and after;
/// `l4.scope.remove {id}` returns true and the list is back to the config entry.
#[test]
fn operator_scope_add_confirm_handshake() {
    let cfg = l4_cfg();
    assert!(!cfg.allow_agent_widen);
    let (srv, _r) = server(&cfg, AgentPolicy::Auto);
    assert_eq!(widen(&srv), json!(false), "widen off before");
    let before = scope_sources(&srv);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].1, "config");

    let asked = call(&srv, Frontend::Operator, "l4.scope.add", scope_add_args());
    assert!(!is_error(&asked), "{}", text(&asked));
    assert_eq!(
        asked["structuredContent"]["status"],
        json!("needs_confirmation")
    );
    let prompt = asked["structuredContent"]["prompt"]
        .as_str()
        .expect("prompt");
    for word in ["127.0.0.1/32", "9100-9199", "lo0", "inbound", "capture"] {
        assert!(prompt.contains(word), "prompt must name `{word}`: {prompt}");
    }
    let token = asked["structuredContent"]["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();
    assert_eq!(
        scope_sources(&srv),
        before,
        "the handshake step adds nothing"
    );

    let mut confirmed = scope_add_args();
    confirmed["_confirm"] = json!(token);
    let added = call(&srv, Frontend::Operator, "l4.scope.add", confirmed);
    assert!(!is_error(&added), "{}", text(&added));
    let id = added["structuredContent"]
        .as_str()
        .unwrap_or_else(|| panic!("the confirmed add returns the id string, got {added}"))
        .to_string();

    let after = scope_sources(&srv);
    assert_eq!(after.len(), 2);
    assert_eq!(after[0], before[0]);
    assert_eq!(after[1], (id.clone(), "runtime".to_string()));
    assert_eq!(widen(&srv), json!(false), "widen still off after");

    let removed = call(
        &srv,
        Frontend::Operator,
        "l4.scope.remove",
        json!({"id": id}),
    );
    assert!(!is_error(&removed), "{}", text(&removed));
    assert_eq!(removed["structuredContent"], json!(true));
    assert_eq!(scope_sources(&srv), before);
}

/// L4PAR-AC6 (plan A6) — an agent (`Frontend::Mcp`) under policy `All` with widen
/// OFF is refused with the widen text, is offered **no** handshake (no
/// `needs_confirmation`, `confirm_token` null) and the list is unchanged.
#[test]
fn agent_scope_add_not_offered_confirmation() {
    let (srv, _r) = server(&l4_cfg(), AgentPolicy::All);
    let before = scope_sources(&srv);

    let res = call(&srv, Frontend::Mcp, "l4.scope.add", scope_add_args());
    assert!(is_error(&res), "agent l4.scope.add must be refused");
    assert!(
        text(&res).contains("runtime L4 scope widening is disabled"),
        "the refusal is the widen text, got: {}",
        text(&res)
    );
    assert_ne!(
        res["structuredContent"]["status"],
        json!("needs_confirmation"),
        "an agent is never offered a handshake"
    );
    assert!(res["structuredContent"]["confirm_token"].is_null());
    assert_eq!(scope_sources(&srv), before);
}

/// Security panel (unit (a')) — an operator's **approval** of a parked agent call is
/// not an operator **confirmation**: under policy `ask` with widen OFF, the agent's
/// `l4.scope.add` parks, the operator `agent.approve`s it, the call then runs *as the
/// agent* and is still refused by the widen gate (the `OperatorConfirmed` proof is
/// minted only on a trusted-control dispatch, never for an approved agent). The
/// approval card's prompt carries no "re-issue with `_confirm`" instruction, and the
/// list is unchanged.
#[test]
fn agent_scope_add_ask_approved_still_widen_gated() {
    let cfg = l4_cfg();
    assert!(!cfg.allow_agent_widen, "widen stays off");
    let (srv, _r) = server(&cfg, AgentPolicy::Ask);
    let srv = Arc::new(srv.with_approval_timeout(Duration::from_secs(60)));
    let before = scope_sources(&srv);

    // An operator connection with a push sink, subscribed so the agent's call can
    // park (a Sensitive `ask` call with no operator connected is refused at once).
    let sink = NotificationSink::new(64);
    let operator = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(sink.clone()),
    };
    let sub = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "flow.subscribe", "arguments": {}}});
    let reply = srv
        .handle_on(&operator, &sub.to_string())
        .expect("flow.subscribe replies");
    let reply: JsonValue = serde_json::from_str(&reply).expect("json");
    assert!(
        reply["result"]["structuredContent"]["sub_id"].is_u64(),
        "the operator subscription registers: {reply}"
    );

    // The agent's call parks on its own thread.
    let agent_srv = Arc::clone(&srv);
    let agent = std::thread::spawn(move || {
        call(&agent_srv, Frontend::Mcp, "l4.scope.add", scope_add_args())
    });

    // The operator is announced the parked call.
    let deadline = Instant::now() + Duration::from_secs(5);
    let request = loop {
        let found = sink.drain().into_iter().find_map(|line| {
            let v: JsonValue = serde_json::from_str(&line).expect("a pushed line is JSON");
            (v["method"] == "notifications/aitm/agent"
                && v["params"]["event"] == "approval_requested")
                .then_some(v)
        });
        if let Some(v) = found {
            break v;
        }
        assert!(
            Instant::now() < deadline,
            "no approval_requested within 5 s (agent finished: {})",
            agent.is_finished()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(request["params"]["command"], json!("l4.scope.add"));
    let prompt = request["params"]["prompt"].as_str().expect("prompt");
    for word in ["127.0.0.1/32", "9100-9199", "lo0", "inbound", "capture"] {
        assert!(prompt.contains(word), "the card names `{word}`: {prompt}");
    }
    assert!(
        !prompt.contains("_confirm"),
        "the approval card must not tell the operator to re-issue with `_confirm`: {prompt}"
    );
    let request_id = request["params"]["request_id"]
        .as_str()
        .expect("request_id")
        .to_string();
    assert!(
        !agent.is_finished(),
        "the agent call is parked, not answered"
    );

    // The operator approves. The call now runs as the agent.
    let approved = call(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert!(
        !is_error(&approved),
        "approve succeeds: {}",
        text(&approved)
    );

    let res = agent.join().expect("the agent thread");
    assert!(is_error(&res), "the approved agent call is still refused");
    assert!(
        text(&res).contains("runtime L4 scope widening is disabled"),
        "the refusal is the widen text, not a policy or approval text, got: {}",
        text(&res)
    );
    assert_ne!(
        res["structuredContent"]["status"],
        json!("needs_confirmation"),
        "an approved agent is still never offered a handshake"
    );
    assert_eq!(scope_sources(&srv), before, "approval widened nothing");
    assert_eq!(widen(&srv), json!(false), "widen still off");
}

/// L4PAR-AC5 — `tools/list` reports `l4.scope.add` `confirmable: true` to the
/// operator and the agent alike (the UIs render their add control on it).
#[test]
fn scope_add_is_confirmable_in_tools_list() {
    let (srv, _r) = server(&l4_cfg(), AgentPolicy::Auto);
    for role in [Frontend::Operator, Frontend::Mcp] {
        let tools = list_tools(&srv, role);
        let add = tools
            .iter()
            .find(|t| t["name"] == json!("l4.scope.add"))
            .unwrap_or_else(|| panic!("{role:?}: tools/list has l4.scope.add"));
        assert_eq!(add["confirmable"], json!(true), "{role:?}: {add}");
    }
}

/// A real MCP server over an L4 module built from `cfg` (privilege present), whose
/// store holds one `capture` flow on `lo0` with a single inbound packet of
/// `bytes`. Returns the server and the flow's id string — the fixture the three
/// `l4.flow.get` bytes tests share.
fn server_with_flow(cfg: &L4Config, bytes: Vec<u8>) -> (McpServer, String) {
    use std::collections::VecDeque;
    use std::time::SystemTime;

    use aitm_proto_l4::craft::PacketSpec;
    use aitm_proto_l4::flow::{
        InMemoryL4FlowStore, L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet,
    };
    use aitm_proto_l4::guard::L4Guard;

    let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
    let module = L4Module::with_shared(
        Arc::new(L4Guard::new(cfg)),
        store.clone(),
        None,
        L4Privilege::available(),
    );
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(module));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio).with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    );
    let id = store.insert(L4Flow {
        id: L4FlowId::new(),
        kind: L4FlowKind::Capture,
        bind: L4Bind {
            interface: "lo0".into(),
            filter: None,
            queue: None,
        },
        packets: VecDeque::from(vec![L4Packet {
            dir: L4Direction::Inbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        }]),
        metadata: L4Meta::default(),
    });
    // The store's id is a uuid string on the wire.
    let id_str = serde_json::to_value(id)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .expect("L4FlowId serialises as a string");
    (srv, id_str)
}

/// L4PAR-AC1 — over the real MCP server, a packet's `bytes` (`Value::Bytes`) render
/// as standard padded base64 in `structuredContent`: `[0xde, 0xad]` is `"3q0="`.
/// The module is built over a store the test holds, so the flow is inserted directly.
#[test]
fn flow_get_bytes_are_base64_on_the_wire() {
    let (srv, id_str) = server_with_flow(&l4_cfg(), vec![0xde, 0xad]);

    // `l4.flow.list` confirms the flow is live.
    let ids = call(&srv, Frontend::Operator, "l4.flow.list", json!({}));
    assert!(!is_error(&ids), "flow.list failed: {}", text(&ids));
    assert_eq!(ids["structuredContent"], json!([id_str]));

    let flow = call(
        &srv,
        Frontend::Operator,
        "l4.flow.get",
        json!({"id": id_str}),
    );
    assert!(!is_error(&flow), "flow.get failed: {}", text(&flow));
    assert_eq!(
        flow["structuredContent"]["packets"][0]["bytes"],
        json!("3q0="),
        "bytes must be padded base64 on the wire, got {}",
        flow["structuredContent"]
    );
    for key in ["proto", "src", "dst", "src_port", "dst_port"] {
        assert!(
            flow["structuredContent"]["packets"][0][key].is_null(),
            "undecodable packet.{key} must be null, got {}",
            flow["structuredContent"]
        );
    }
}

/// L4PAR-AC35 — over the real MCP server, an agent (`Frontend::Mcp`) `l4.flow.get`
/// with the Capture gate closed (the default) returns the packet's headers, length
/// and time but **no `bytes`** key; the same flow read as the operator carries them.
/// An agent must not read the bus-token line off a loopback capture by default.
#[test]
fn agent_flow_get_has_no_bytes() {
    let cfg = l4_cfg();
    assert!(!cfg.allow_agent_capture, "the Capture gate starts closed");
    let (srv, id_str) = server_with_flow(&cfg, vec![0xde, 0xad]);

    let flow = call(&srv, Frontend::Mcp, "l4.flow.get", json!({"id": id_str}));
    assert!(!is_error(&flow), "agent flow.get failed: {}", text(&flow));
    let packet = flow["structuredContent"]["packets"][0]
        .as_object()
        .expect("packets[0] is an object");
    assert!(
        !packet.contains_key("bytes"),
        "an agent with the Capture gate closed must get no `bytes`, got {}",
        flow["structuredContent"]
    );
    assert_eq!(packet["length"], json!(2));
    assert_eq!(packet["dir"], json!("inbound"));
    assert!(packet["timestamp"].is_i64(), "timestamp present");
    assert!(packet.contains_key("proto"), "proto present (null here)");

    // The operator reading the same flow still gets the bytes.
    let flow = call(
        &srv,
        Frontend::Operator,
        "l4.flow.get",
        json!({"id": id_str}),
    );
    assert!(
        !is_error(&flow),
        "operator flow.get failed: {}",
        text(&flow)
    );
    assert_eq!(
        flow["structuredContent"]["packets"][0]["bytes"],
        json!("3q0=")
    );
}

// ---- Tester (stage 5): L4PAR-AC3 / AC4 / AC9 / AC35 over the real MCP server ----

/// A server like [`server`] but over an L4 module built with `privilege`.
fn server_with_privilege(cfg: &L4Config, privilege: L4Privilege, policy: AgentPolicy) -> McpServer {
    let agent_state = Arc::new(AgentState::new(policy));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(L4Module::with_privilege(cfg, privilege)));
    reg.add_plugin(Box::new(AgentPlugin::new(agent_state.clone())));
    McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(agent_state)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
}

/// L4PAR-AC3 / AC4 / AC9 — on an unprivileged core both status verbs answer the
/// operator **and** an agent (policy `auto`, gates closed) over the real MCP
/// server with no error and exactly the spec §1 object, while `l4.capture.start`
/// and `l4.intercept.start` still refuse with `L4 unavailable: ` + that reason.
#[test]
fn status_verbs_answer_operator_and_agent_over_mcp_when_unprivileged() {
    const CAP: &str = "no read+write access to any /dev/bpf* device (test)";
    const INT: &str = "in-path interception is unsupported here (test)";
    let srv = server_with_privilege(
        &l4_cfg(),
        L4Privilege {
            capture_inject: Some(CAP.into()),
            intercept: Some(INT.into()),
        },
        AgentPolicy::Auto,
    );
    let capture_code = if cfg!(any(target_os = "macos", target_os = "linux")) {
        "needs_privilege"
    } else {
        "unsupported_platform"
    };
    let intercept_code = if cfg!(target_os = "linux") {
        "needs_privilege"
    } else {
        "unsupported_platform"
    };
    for role in [Frontend::Operator, Frontend::Mcp] {
        let r = call(&srv, role, "l4.capture.status", json!({}));
        assert!(
            !is_error(&r),
            "{role:?} capture.status errored: {}",
            text(&r)
        );
        assert_eq!(
            r["structuredContent"],
            json!({"available": false, "code": capture_code, "reason": CAP, "captures": []}),
            "{role:?}"
        );
        let r = call(&srv, role, "l4.intercept.status", json!({}));
        assert!(
            !is_error(&r),
            "{role:?} intercept.status errored: {}",
            text(&r)
        );
        assert_eq!(
            r["structuredContent"],
            json!({"available": false, "code": intercept_code, "reason": INT, "sessions": []}),
            "{role:?}"
        );
    }
    let r = call(
        &srv,
        Frontend::Operator,
        "l4.capture.start",
        json!({"interface": "lo0"}),
    );
    assert!(is_error(&r), "capture.start must refuse while unavailable");
    assert!(
        text(&r).contains(&format!("L4 unavailable: {CAP}")),
        "got: {}",
        text(&r)
    );
    let r = call(
        &srv,
        Frontend::Operator,
        "l4.intercept.start",
        json!({"interface": "lo0"}),
    );
    assert!(
        is_error(&r),
        "intercept.start must refuse while unavailable"
    );
    assert!(
        text(&r).contains(&format!("L4 unavailable: {INT}")),
        "got: {}",
        text(&r)
    );
}

/// L4PAR-AC3 / AC4 — on a privileged core with in-path configured both status
/// verbs read `available: true, code: "available", reason: null` over the wire,
/// and `tools/list` describes both results as objects.
#[test]
fn status_verbs_available_over_mcp_when_privileged() {
    let srv = server_with_privilege(&l4_cfg(), L4Privilege::available(), AgentPolicy::Auto);
    for role in [Frontend::Operator, Frontend::Mcp] {
        let r = call(&srv, role, "l4.capture.status", json!({}));
        assert!(!is_error(&r), "{}", text(&r));
        assert_eq!(
            r["structuredContent"],
            json!({"available": true, "code": "available", "reason": null, "captures": []})
        );
        let r = call(&srv, role, "l4.intercept.status", json!({}));
        assert!(!is_error(&r), "{}", text(&r));
        assert_eq!(
            r["structuredContent"],
            json!({"available": true, "code": "available", "reason": null, "sessions": []})
        );
    }
}

/// L4PAR-AC35 — over the real MCP server, an agent whose Capture gate is open
/// (`l4.allow_agent_capture: true`) reads `bytes`, because it could capture them
/// itself; the agent lane with the gate closed is `agent_flow_get_has_no_bytes`.
#[test]
fn agent_flow_get_has_bytes_when_capture_gate_open() {
    let cfg = L4Config {
        allow_agent_capture: true,
        ..l4_cfg()
    };
    let (srv, id_str) = server_with_flow(&cfg, vec![0xde, 0xad]);

    let status = call(&srv, Frontend::Operator, "l4.agent.status", json!({}));
    assert_eq!(status["structuredContent"]["capture"], json!(true));
    let flow = call(&srv, Frontend::Mcp, "l4.flow.get", json!({"id": id_str}));
    assert!(!is_error(&flow), "agent flow.get failed: {}", text(&flow));
    assert_eq!(
        flow["structuredContent"]["packets"][0]["bytes"],
        json!("3q0="),
        "an agent with the Capture gate open reads the bytes, got {}",
        flow["structuredContent"]
    );
}
