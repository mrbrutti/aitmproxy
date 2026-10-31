//! Server-level checks that the F2 audit ring is a sound record: a real
//! `McpServer` over a real `AgentPlugin` and stub commands of each sensitivity,
//! one shared `Arc<AuditRing>`, driven in-process through `handle_on` (no
//! sockets). They prove `record_audit` files each invocation in the lane its
//! sensitivity and outcome call for (plan 2026-10-30-audit-ring-integrity,
//! Task 6), so a polling burst cannot evict a refused call and one source's
//! flood cannot evict another's entry.

use std::sync::Arc;

use aitm_core::{
    origin_label, AgentPolicy, AgentState, AuditResult, AuditRing, Command, CommandHost, Frontend,
    HttpFlow, HttpRequest, McpTransport, MemFlowStore, ParamDef, ParamSchema, Params, ProxyClient,
    Registry, Sensitivity, StdGuard, TypeDesc, Value, DEFAULT_AUDIT_CAPACITY,
    WEB_BRIDGE_CLIENT_LABEL,
};
use aitm_mcp::{ConnCtx, McpServer};
use aitm_plugins::AgentPlugin;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

// ---------------------------------------------------------------- fixtures

/// The host needs a `ProxyClient`; no stub command here calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A no-op command of a declared [`Sensitivity`]. Returns `"ran"` when the gate
/// lets it through.
struct TierCmd {
    name: &'static str,
    sens: Sensitivity,
}

impl Command for TierCmd {
    fn name(&self) -> &str {
        self.name
    }
    fn sensitivity(&self) -> Sensitivity {
        self.sens
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "stub".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ran".into()))
    }
}

/// A Read command whose `invoke` always fails, returning the caller-supplied
/// `reason` verbatim as the error, so a test can drive a failing `Read`.
struct ErrEchoCmd;

impl Command for ErrEchoCmd {
    fn name(&self) -> &str {
        "demo.errecho"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Fail with the given reason.".into(),
            params: vec![ParamDef {
                name: "reason".into(),
                ty: TypeDesc::Str,
                required: true,
                description: String::new(),
            }],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!(args.get_str("reason")?.to_string()))
    }
}

/// A server whose registry carries `demo.read` (Read), `demo.write` (Write),
/// `demo.sensitive` (Sensitive), the failing-Read `demo.errecho`, and the real
/// `AgentPlugin`, all sharing `ring`, so `agent.activity` and `agent.status` read
/// exactly what `record_audit` writes. The policy is `Auto`: Read and Write run,
/// Sensitive is refused (every one of them is audited).
fn audit_server(ring: Arc<AuditRing>) -> McpServer {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(TierCmd {
        name: "demo.read",
        sens: Sensitivity::Read,
    }));
    reg.add_command(Arc::new(TierCmd {
        name: "demo.write",
        sens: Sensitivity::Write,
    }));
    reg.add_command(Arc::new(TierCmd {
        name: "demo.sensitive",
        sens: Sensitivity::Sensitive,
    }));
    reg.add_command(Arc::new(ErrEchoCmd));
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    reg.add_plugin(Box::new(
        AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
    ));
    McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state)
        .with_audit_ring(ring)
}

/// An agent-role connection that declared `label` (the label is assigned after
/// construction, so this does not depend on `ConnCtx`'s full field list).
fn labelled(label: &str) -> ConnCtx {
    let mut conn = ConnCtx::new(Frontend::Mcp);
    conn.client_label = Some(label.to_string());
    conn
}

/// Call `name` with `args` on `conn`; parse the reply.
fn call(srv: &McpServer, conn: &ConnCtx, name: &str, args: JsonValue) -> JsonValue {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    });
    let resp = srv
        .handle_on(conn, &req.to_string())
        .expect("a request gets a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

/// Whether a `tools/call` reply is a tool error (a policy refusal, or any other
/// command error).
fn is_error(resp: &JsonValue) -> bool {
    resp["result"]["isError"] == json!(true)
}

// -------------------------------------------------------------------- tests

/// AC24: one connection (origin `mcp`, labelled `web-bridge`) makes a refused
/// `Sensitive` call, then a burst of more successful `Read` calls than the ring
/// has evidence slots. The same source on purpose: per-source fair share cannot
/// save the refusal, only the lanes can.
#[test]
fn a_read_burst_cannot_evict_a_refused_sensitive_call() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = labelled(WEB_BRIDGE_CLIENT_LABEL);

    assert!(
        is_error(&call(&srv, &conn, "demo.sensitive", json!({}))),
        "a Sensitive call under Auto is refused"
    );
    for _ in 0..DEFAULT_AUDIT_CAPACITY + 64 {
        let reply = call(&srv, &conn, "agent.status", json!({}));
        assert!(
            !is_error(&reply),
            "agent.status is a Read and runs: {reply}"
        );
    }

    let entries = ring.recent(None, None);
    let first = &entries[0];
    assert_eq!(first.command, "demo.sensitive");
    assert_eq!(origin_label(first.origin), "mcp");
    assert_eq!(first.client_label.as_deref(), Some(WEB_BRIDGE_CLIENT_LABEL));
    match &first.result {
        AuditResult::Error(reason) => {
            assert!(reason.contains("auto"), "refusal reason carried: {reason}");
        }
        other => panic!("expected the refusal to survive as an error, got {other:?}"),
    }
    assert_eq!(ring.evidence_len(), 1);
    assert_eq!(ring.routine_len(), 2048);
    assert_eq!(ring.len(), 2049);
}

/// AC25: source A (`agent-a`) makes one refused call; source B (`agent-b`)
/// makes twice the evidence capacity of refused calls. Fair share keeps A's
/// entry and gives B the rest of the lane. A guard once Task 5 is in.
#[test]
fn a_refused_flood_cannot_evict_another_sources_entry() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let source_a = labelled("agent-a");
    let source_b = labelled("agent-b");

    assert!(is_error(&call(
        &srv,
        &source_a,
        "demo.sensitive",
        json!({})
    )));
    for _ in 0..2 * DEFAULT_AUDIT_CAPACITY {
        assert!(is_error(&call(
            &srv,
            &source_b,
            "demo.sensitive",
            json!({})
        )));
    }

    let entries = ring.recent(None, None);
    let from_a: Vec<_> = entries
        .iter()
        .filter(|e| e.client_label.as_deref() == Some("agent-a"))
        .collect();
    assert_eq!(from_a.len(), 1, "A's one entry survives B's flood");
    assert_eq!(from_a[0].command, "demo.sensitive");
    assert_eq!(origin_label(from_a[0].origin), "mcp");
    assert_eq!(ring.evidence_len(), DEFAULT_AUDIT_CAPACITY);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.client_label.as_deref() == Some("agent-b"))
            .count(),
        4095
    );
    assert_eq!(ring.routine_len(), 0);
}

/// AC26: the lane follows the command's sensitivity and its outcome. After each
/// call on a fresh ring, `(evidence_len, routine_len)` is: a successful Read
/// `(0, 1)`; a failing Read `(1, 1)`; a successful Write `(2, 1)`; a refused
/// Sensitive `(3, 1)`.
#[test]
fn routing_follows_sensitivity_and_outcome() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx::new(Frontend::Mcp);

    let reply = call(&srv, &conn, "demo.read", json!({}));
    assert!(!is_error(&reply), "a Read runs under Auto: {reply}");
    assert_eq!(
        (ring.evidence_len(), ring.routine_len()),
        (0, 1),
        "a successful Read is routine"
    );

    let reply = call(&srv, &conn, "demo.errecho", json!({"reason": "x"}));
    assert!(is_error(&reply), "demo.errecho always fails: {reply}");
    assert_eq!(
        (ring.evidence_len(), ring.routine_len()),
        (1, 1),
        "a failing Read is evidence"
    );

    let reply = call(&srv, &conn, "demo.write", json!({}));
    assert!(!is_error(&reply), "a Write runs under Auto: {reply}");
    assert_eq!(
        (ring.evidence_len(), ring.routine_len()),
        (2, 1),
        "a successful Write is evidence"
    );

    let reply = call(&srv, &conn, "demo.sensitive", json!({}));
    assert!(is_error(&reply), "a Sensitive call under Auto is refused");
    assert_eq!(
        (ring.evidence_len(), ring.routine_len()),
        (3, 1),
        "a refused Sensitive is evidence"
    );
}

/// AC27: `agent.status.actions_last_minute` counts entries in both lanes. One
/// successful Read (routine) and one refused Sensitive (evidence), then the
/// status call itself (recorded only after it replies), reads 2. This is the
/// PR 145 AC5 value, unchanged by the lane split. A guard.
#[test]
fn actions_last_minute_counts_both_lanes() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx::new(Frontend::Mcp);

    assert!(!is_error(&call(&srv, &conn, "demo.read", json!({}))));
    assert!(is_error(&call(&srv, &conn, "demo.sensitive", json!({}))));

    let status = call(&srv, &conn, "agent.status", json!({}));
    assert_eq!(
        status["result"]["structuredContent"]["actions_last_minute"],
        json!(2),
        "both lanes are counted: {status}"
    );
}
