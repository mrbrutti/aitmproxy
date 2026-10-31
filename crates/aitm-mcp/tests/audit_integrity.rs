//! Server-level checks that the F2 audit ring is a sound record: a real
//! `McpServer` over a real `AgentPlugin` and stub commands of each sensitivity,
//! one shared `Arc<AuditRing>`, driven in-process through `handle_on` (no
//! sockets). They prove `record_audit` files each invocation in the lane its
//! sensitivity and outcome call for (plan 2026-10-30-audit-ring-integrity,
//! Task 6), so a polling burst cannot evict a refused call and one source's
//! flood cannot evict another's entry; and (Task 7) that a hostile client label
//! and an oversized error reason are bounded before the ring and the host see
//! them, and that unframed credentials in the arguments are masked.

use std::sync::Arc;

use aitm_core::{
    origin_label, AgentPolicy, AgentState, AuditResult, AuditRing, Command, CommandHost, Frontend,
    HttpFlow, HttpRequest, McpTransport, MemFlowStore, ParamDef, ParamSchema, Params, ProxyClient,
    Registry, Sensitivity, StdGuard, TypeDesc, Value, DEFAULT_AUDIT_CAPACITY,
    DEFAULT_RESULT_REASON_CAP, WEB_BRIDGE_CLIENT_LABEL,
};
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
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

/// A Read command that returns the client label its [`CommandHost`] carries
/// (`"<none>"` when there is none), so a test sees exactly what a command like
/// `findings.record` would stamp on a record.
struct ClientLabelCmd;

impl Command for ClientLabelCmd {
    fn name(&self) -> &str {
        "demo.client"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Return the host's client label.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str(host.client_label().unwrap_or("<none>").into()))
    }
}

/// A Read command that accepts a free-text `note` and a string-map `headers`
/// and returns its arguments, so the audit entry's `args_summary` has both an
/// unframed `key=value` run and a secret-named header to redact.
struct EchoCmd;

impl Command for EchoCmd {
    fn name(&self) -> &str {
        "demo.echo"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Echo a note and headers.".into(),
            params: vec![
                ParamDef {
                    name: "note".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "headers".into(),
                    ty: TypeDesc::Map(Box::new(TypeDesc::Str)),
                    required: false,
                    description: String::new(),
                },
            ],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Object(
            args.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        ))
    }
}

/// A server whose registry carries `demo.read` (Read), `demo.write` (Write),
/// `demo.sensitive` (Sensitive), the failing-Read `demo.errecho`, the
/// label-reporting `demo.client`, the argument-echoing `demo.echo`, and the real
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
    reg.add_command(Arc::new(ClientLabelCmd));
    reg.add_command(Arc::new(EchoCmd));
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

/// AC16: a connection whose `client_label` was assigned directly (the field is
/// `pub`, so capture-time sanitising alone can be bypassed) carries 10 MiB of
/// `B`. Both the host a command sees and the ring entry hold the 64-char
/// sanitised label, so across 20 calls the ring keeps `20 * 64` label bytes, not
/// 200 MiB. Twenty and not more: on unfixed code each call retains a 10 MiB
/// clone in the ring. Failure messages print lengths, never the label.
#[test]
fn a_hostile_label_is_bounded_in_the_ring_and_the_host() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = labelled(&"B".repeat(10 << 20));
    let bounded = "B".repeat(64);

    let reply = call(&srv, &conn, "demo.client", json!({}));
    let seen = reply["result"]["structuredContent"]
        .as_str()
        .expect("demo.client returns its label as a string");
    assert_eq!(seen.len(), 64, "the host's label length");
    assert_eq!(seen, bounded);

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].client_label.as_deref().map(str::len),
        Some(64),
        "the ring entry's label length"
    );
    assert_eq!(entries[0].client_label.as_deref(), Some(bounded.as_str()));
    assert_eq!(origin_label(entries[0].origin), "mcp");
    drop(entries);

    for _ in 1..20 {
        call(&srv, &conn, "demo.client", json!({}));
    }
    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 20);
    let stored: usize = entries
        .iter()
        .map(|e| e.client_label.as_deref().map_or(0, str::len))
        .sum();
    assert_eq!(stored, 20 * 64, "label bytes held by the ring");
}

/// AC28: a failing command whose error text is 1 MiB (an error can echo caller
/// input) is audited with a reason capped at `DEFAULT_RESULT_REASON_CAP` bytes
/// plus the three-byte `…`; the tool result still carries all of it. Failure
/// messages print lengths, never the reason.
#[test]
fn an_oversized_error_reason_is_capped_in_the_ring() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx::new(Frontend::Mcp);
    let reason = "x".repeat(1 << 20);

    let reply = call(&srv, &conn, "demo.errecho", json!({ "reason": reason }));
    assert!(is_error(&reply), "demo.errecho always fails");
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .expect("the error carries its text");
    assert!(
        text.contains(&reason),
        "the caller still receives the whole reason ({} bytes of text)",
        text.len()
    );

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, "demo.errecho");
    match &entries[0].result {
        AuditResult::Error(r) => {
            assert!(
                r.len() <= DEFAULT_RESULT_REASON_CAP + 3,
                "the audited reason is {} bytes",
                r.len()
            );
            assert!(r.starts_with("xxxx"), "the head of the reason is kept");
            assert!(r.ends_with('…'), "truncation is marked");
        }
        other => panic!("expected an error result, got {other:?}"),
    }
}

/// AC29: unframed credentials (`sid=`, `session=`, `auth=`, `jwt=` inside a
/// free-text value) and a secret-named header (`X-Session`) are masked in the
/// ring entry's `args_summary` and in the line pushed to a subscribed operator,
/// while a look-alike (`author=bob`) is left alone. Green once the shared
/// vocabulary covers the session and auth family (Tasks 1 and 2).
#[test]
fn args_summary_hides_unframed_credentials() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());

    let mut watcher = ConnCtx::new(Frontend::Operator);
    watcher.conn_id = srv.next_conn_id();
    watcher.out = Some(NotificationSink::new(64));
    let sub = call(&srv, &watcher, "flow.subscribe", json!({}));
    assert!(!is_error(&sub), "the operator subscribes: {sub}");

    let reply = call(
        &srv,
        &ConnCtx::new(Frontend::Mcp),
        "demo.echo",
        json!({
            "note": "go sid=SECRET1 session=SECRET2 auth=SECRET3 jwt=SECRET4 author=bob",
            "headers": {"X-Session": "SECRET5"},
        }),
    );
    assert!(!is_error(&reply), "demo.echo runs: {reply}");

    let entry = ring
        .recent(None, None)
        .into_iter()
        .find(|e| e.command == "demo.echo")
        .expect("the echo call was audited");
    let pushed = watcher
        .out
        .as_ref()
        .expect("the watcher has a sink")
        .drain()
        .join("\n");
    assert!(
        pushed.contains("notifications/aitm/agent"),
        "the agent line was pushed: {pushed}"
    );
    for secret in ["SECRET1", "SECRET2", "SECRET3", "SECRET4", "SECRET5"] {
        assert!(
            !entry.args_summary.contains(secret),
            "{secret} leaked into the audit entry: {}",
            entry.args_summary
        );
        assert!(
            !pushed.contains(secret),
            "{secret} leaked into the pushed line: {pushed}"
        );
    }
    assert!(
        entry.args_summary.contains("author=bob"),
        "a look-alike key survives: {}",
        entry.args_summary
    );
}

// ---------------------------------------------- stage 5 tester additions
//
// Each test below kills a mutant of the entry-size caps, the label helper, or the
// per-call bookkeeping that the tests above let survive.

/// The `AuditResult::Error` text the ring keeps for a `demo.errecho` call whose
/// reason is `reason`; it checks the call failed and was audited exactly once.
fn audited_reason(reason: &str) -> String {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx::new(Frontend::Mcp);
    let reply = call(&srv, &conn, "demo.errecho", json!({ "reason": reason }));
    assert!(is_error(&reply), "demo.errecho always fails");
    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1, "one call, one entry");
    match &entries[0].result {
        AuditResult::Error(r) => r.clone(),
        other => panic!("expected an error result, got {other:?}"),
    }
}

/// The error reason is recorded whole up to the cap and marked only past it. The
/// cap is the full 1024 bytes (not the 512 of `args_summary`).
#[test]
fn an_error_reason_is_kept_whole_up_to_the_cap_and_marked_beyond_it() {
    const CAP: usize = DEFAULT_RESULT_REASON_CAP;
    assert_eq!(CAP, 1024);
    assert_eq!(audited_reason("x"), "x", "a short reason is untouched");

    let at_cap = "y".repeat(CAP);
    let kept = audited_reason(&at_cap);
    assert_eq!(kept.len(), CAP, "a reason of exactly the cap is not cut");
    assert!(!kept.ends_with('…'), "and carries no truncation marker");
    assert_eq!(kept, at_cap);

    let one_over = "y".repeat(CAP + 1);
    assert_eq!(audited_reason(&one_over), format!("{}…", "y".repeat(CAP)));

    let huge = audited_reason(&"z".repeat(1 << 20));
    assert_eq!(
        huge.len(),
        CAP + '…'.len_utf8(),
        "cut at the cap, then marked"
    );
    assert!(huge.starts_with("zzzz") && huge.ends_with('…'));
}

/// The cut backs off to a char boundary, so a multi-byte character straddling the
/// cap is dropped whole rather than split (which would panic) or kept past the cap.
#[test]
fn a_multibyte_error_reason_is_cut_on_a_char_boundary() {
    // `x` then two-byte chars: the boundaries are odd, so byte 1024 is mid-char.
    let two_byte = format!("x{}", "é".repeat(2000));
    let kept = audited_reason(&two_byte);
    assert!(kept.starts_with("xéé") && kept.ends_with('…'));
    assert_eq!(kept.len(), 1023 + '…'.len_utf8());

    // `xx` then four-byte chars: the boundaries are 2 + 4k, so 1024 is mid-char.
    let four_byte = format!("xx{}", "😀".repeat(1000));
    let kept = audited_reason(&four_byte);
    assert!(kept.starts_with("xx😀") && kept.ends_with('…'));
    assert_eq!(kept.len(), 1022 + '…'.len_utf8());
}

/// `args_summary` has its own, smaller cap (512 bytes) and the same marker rule.
#[test]
fn an_oversized_argument_is_capped_in_args_summary() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx::new(Frontend::Mcp);
    let summaries = |note: &str| -> String {
        let reply = call(&srv, &conn, "demo.echo", json!({ "note": note }));
        assert!(!is_error(&reply), "demo.echo runs: {reply}");
        ring.recent(None, Some(1))
            .pop()
            .expect("the call was audited")
            .args_summary
    };

    assert_eq!(
        summaries("hi"),
        r#"{"note":"hi"}"#,
        "short args are untouched"
    );

    let long = summaries(&"n".repeat(100_000));
    assert_eq!(
        long.len(),
        aitm_core::DEFAULT_ARGS_SUMMARY_CAP + '…'.len_utf8()
    );
    assert!(long.starts_with(r#"{"note":"nnnn"#) && long.ends_with('…'));

    // `{"note":"` is 9 bytes, so the two-byte chars start at odd offsets and byte
    // 512 is mid-char: the cut backs off by one.
    let multibyte = summaries(&"é".repeat(5000));
    assert!(multibyte.ends_with('…'));
    assert_eq!(multibyte.len(), 511 + '…'.len_utf8());
}

/// The label is sanitised where the server consumes it, whatever set it: control
/// and bidi characters are dropped and a credential is masked, in the host a
/// command runs under and in the ring entry alike (not merely cut to 64 chars).
#[test]
fn a_directly_assigned_label_is_stripped_and_scrubbed_at_the_server() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = labelled("agent\u{202E}-x\n token=abc123zz");

    let reply = call(&srv, &conn, "demo.client", json!({}));
    let host_label = reply["result"]["structuredContent"]
        .as_str()
        .expect("demo.client returns its label as a string");
    assert_eq!(host_label, "agent-x token=[redacted]", "the host's label");

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].client_label.as_deref(),
        Some("agent-x token=[redacted]"),
        "the ring entry's label"
    );

    // A label with nothing visible left is no label: the host sees `<none>` and the
    // entry carries `None`.
    let blank = labelled("\u{200B}\u{0}  ");
    let reply = call(&srv, &blank, "demo.client", json!({}));
    assert_eq!(reply["result"]["structuredContent"], json!("<none>"));
    assert_eq!(ring.recent(None, Some(1))[0].client_label, None);
}

/// A padded lookalike of the reserved `web-bridge` keeps what marks it as a
/// client's own through the server's consumption pass. `declared_client_label` is
/// what a transport stores; the server sanitises it again to 64 characters where
/// it builds the host and the ring entry. A label of 62 to 64 characters that
/// read as `web-bridge` once lost its ` (declared)` suffix to that cut, so a
/// client's entry and finding showed the server's own name. Each row names the
/// raw label, and the exact label the ring entry and the host must both carry.
#[test]
fn a_padded_reserved_name_keeps_its_declared_suffix_through_the_server() {
    // U+17B4 (a Khmer vowel inherent, invisible) is kept by the sanitiser.
    let pad = |n: usize| "\u{17B4}".repeat(n);
    let rows: [(&str, String, String); 3] = [
        (
            "trailing pad, 64 chars",
            format!("web-bridge{}", pad(54)),
            // Cut to 53 chars, still reads as the name: marked, 64 chars in all.
            format!("web-bridge{} (declared)", pad(43)),
        ),
        (
            "inner pad, 64 chars",
            format!("web{}-bridge", pad(54)),
            // Cut to 53 chars, the head is `web` and no longer reads as the name.
            format!("web{}", pad(50)),
        ),
        (
            "inner pad, 50 chars",
            format!("web{}-bridge", pad(40)),
            // Short enough that nothing is cut: marked whole.
            format!("web{}-bridge (declared)", pad(40)),
        ),
    ];

    let mut bad: Vec<String> = Vec::new();
    for (row, raw, want) in rows {
        let stored = aitm_core::declared_client_label(&raw).expect("a label remains");
        if stored != want {
            bad.push(format!("{row}: transport stores {stored:?}, want {want:?}"));
        }

        let ring = Arc::new(AuditRing::default());
        let srv = audit_server(ring.clone());
        let conn = labelled(&stored);
        let reply = call(&srv, &conn, "demo.client", json!({}));
        let host_label = reply["result"]["structuredContent"]
            .as_str()
            .expect("demo.client returns its label as a string");
        if host_label != want {
            bad.push(format!("{row}: host sees {host_label:?}, want {want:?}"));
        }
        let entries = ring.recent(None, None);
        if entries.len() != 1 || entries[0].client_label.as_deref() != Some(want.as_str()) {
            bad.push(format!(
                "{row}: ring holds {:?}, want one entry labelled {want:?}",
                entries.iter().map(|e| &e.client_label).collect::<Vec<_>>()
            ));
        }
    }
    assert!(bad.is_empty(), "a label changed at the server: {bad:#?}");
}

/// Calls from several threads at once are each audited exactly once, in the lane
/// they belong in, and no source loses or gains an entry.
#[test]
fn concurrent_calls_are_each_audited_exactly_once() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 100;
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let srv = &srv;
            scope.spawn(move || {
                let conn = labelled(&format!("worker-{t}"));
                for _ in 0..PER_THREAD {
                    let reply = call(srv, &conn, "demo.read", json!({}));
                    assert!(!is_error(&reply), "a Read runs: {reply}");
                    let reply = call(srv, &conn, "demo.sensitive", json!({}));
                    assert!(is_error(&reply), "a Sensitive call is refused");
                }
            });
        }
    });
    // 800 of each: below both lane capacities, so nothing was evicted.
    assert_eq!(
        (ring.evidence_len(), ring.routine_len()),
        (THREADS * PER_THREAD, THREADS * PER_THREAD)
    );
    let entries = ring.recent(None, None);
    for t in 0..THREADS {
        let label = format!("worker-{t}");
        let reads = entries
            .iter()
            .filter(|e| {
                e.client_label.as_deref() == Some(label.as_str()) && e.command == "demo.read"
            })
            .count();
        let refusals = entries
            .iter()
            .filter(|e| {
                e.client_label.as_deref() == Some(label.as_str()) && e.command == "demo.sensitive"
            })
            .count();
        assert_eq!((reads, refusals), (PER_THREAD, PER_THREAD), "{label}");
    }
}
