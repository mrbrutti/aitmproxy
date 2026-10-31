//! Source-side strict redaction of the audit entry (plan 2026-10-31-durable-audit,
//! Task R3; spec Design 14.1, 14.2, AC45, AC47, AC60). A real `McpServer` over a
//! real `AgentPlugin` and two stub commands, one shared `Arc<AuditRing>`, driven
//! in-process through `handle_on` (no sockets). Each call is read back three
//! ways, which must carry the byte-identical text: the ring entry's
//! `args_summary`, the line pushed to a subscribed operator, and the entry
//! `agent.activity` returns.
//!
//! Every secret-looking value is a made-up canary (`CNRY` + row + `x` + eight hex
//! digits), never a real credential, and a failing table row is collected into one
//! assertion message so a single run names every wrong row.

use std::sync::Arc;

use aitm_core::{
    AgentPolicy, AgentState, AuditEntry, AuditResult, AuditRing, Command, CommandHost, Frontend,
    HttpFlow, HttpRequest, McpTransport, MemFlowStore, ParamDef, ParamSchema, Params, ProxyClient,
    Registry, Sensitivity, StdGuard, TypeDesc, Value,
};
use aitm_mcp::redact_args::redact_value;
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

/// Optional `Any`-typed parameters of `demo.accept`: one per argument shape the
/// tables below send (`a` carries the nested-collection row of AC45).
const ACCEPT_PARAMS: [&str; 12] = [
    "headers", "pairs", "entries", "request", "edits", "selector", "text", "vars", "note", "raw",
    "body", "a",
];

/// A `Write` command that accepts any of [`ACCEPT_PARAMS`] and succeeds, so the
/// audit entry carries exactly the arguments the call sent.
struct AcceptCmd;

impl Command for AcceptCmd {
    fn name(&self) -> &str {
        "demo.accept"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Accept anything.".into(),
            params: ACCEPT_PARAMS
                .iter()
                .map(|name| ParamDef {
                    name: (*name).into(),
                    ty: TypeDesc::Any,
                    required: false,
                    description: String::new(),
                })
                .collect(),
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ok".into()))
    }
}

/// A `Write` command whose `invoke` always fails, returning `note` verbatim as
/// the error, so the reason the audit entry keeps is exactly what the caller sent.
struct FailCmd;

impl Command for FailCmd {
    fn name(&self) -> &str {
        "demo.fail"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Fail quoting the note.".into(),
            params: vec![ParamDef {
                name: "note".into(),
                ty: TypeDesc::Str,
                required: true,
                description: String::new(),
            }],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!(args.get_str("note")?.to_string()))
    }
}

/// A server and its operator watcher, sharing one ring: the registry carries
/// `demo.accept`, `demo.fail` and the real `AgentPlugin` (so `agent.activity`
/// reads exactly what `record_audit` writes). The policy is `Auto`, so the
/// agent's `Write` calls run.
struct Rig {
    srv: McpServer,
    ring: Arc<AuditRing>,
    watcher: ConnCtx,
}

impl Rig {
    fn new() -> Rig {
        let ring = Arc::new(AuditRing::default());
        let mut reg = Registry::new();
        reg.add_command(Arc::new(AcceptCmd));
        reg.add_command(Arc::new(FailCmd));
        let state = Arc::new(AgentState::new(AgentPolicy::Auto));
        reg.add_plugin(Box::new(
            AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
        ));
        let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_agent_state(state)
            .with_audit_ring(ring.clone());

        let mut watcher = ConnCtx::new(Frontend::Operator);
        watcher.conn_id = srv.next_conn_id();
        watcher.out = Some(NotificationSink::new(64));
        let sub = call(&srv, &watcher, "flow.subscribe", json!({}));
        assert!(!is_error(&sub), "the operator subscribes: {sub}");
        Rig { srv, ring, watcher }
    }

    /// Call `name` as an agent (`Frontend::Mcp`) and return the reply.
    fn agent_call(&self, name: &str, args: JsonValue) -> JsonValue {
        call(&self.srv, &ConnCtx::new(Frontend::Mcp), name, args)
    }

    /// The one audit entry `command` produced, as the ring, the pushed line and
    /// `agent.activity` each carry it.
    fn views(&self, command: &str) -> Views {
        let ring = self
            .ring
            .recent(None, None)
            .into_iter()
            .find(|e| e.command == command)
            .unwrap_or_else(|| panic!("`{command}` was audited"));

        let pushed = self
            .watcher
            .out
            .as_ref()
            .expect("the watcher has a sink")
            .drain()
            .into_iter()
            .map(|line| serde_json::from_str::<JsonValue>(&line).expect("a pushed line is JSON"))
            .filter(|line| line["method"] == json!("notifications/aitm/agent"))
            .map(|line| line["params"].clone())
            .find(|params| params["command"] == json!(command))
            .unwrap_or_else(|| panic!("`{command}` was pushed to the operator"));

        let reply = call(
            &self.srv,
            &self.watcher,
            "agent.activity",
            json!({"limit": 50}),
        );
        assert!(!is_error(&reply), "agent.activity runs: {reply}");
        let activity = reply["result"]["structuredContent"]
            .as_array()
            .expect("activity is an array")
            .iter()
            .find(|e| e["command"] == json!(command))
            .unwrap_or_else(|| panic!("`{command}` is in agent.activity"))
            .clone();

        Views {
            ring,
            pushed,
            activity,
        }
    }
}

/// One audit entry read back through the three surfaces that show it.
struct Views {
    ring: AuditEntry,
    pushed: JsonValue,
    activity: JsonValue,
}

impl Views {
    /// The ring's `args_summary`, and whether the pushed line and the
    /// `agent.activity` entry carry the byte-identical string.
    fn args(&self) -> (&str, bool) {
        let ring = self.ring.args_summary.as_str();
        let same = self.pushed["args"] == json!(ring) && self.activity["args"] == json!(ring);
        (ring, same)
    }

    /// The reason of the ring's `Error` result (`None` for an `Ok` entry).
    fn ring_reason(&self) -> Option<&str> {
        match &self.ring.result {
            AuditResult::Error(reason) => Some(reason.as_str()),
            AuditResult::Ok => None,
        }
    }
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

/// Whether a `tools/call` reply is a tool error.
fn is_error(resp: &JsonValue) -> bool {
    resp["result"]["isError"] == json!(true)
}

/// A made-up secret for table row `row`: `CNRY` + row + `x` + eight hex digits.
fn canary(row: u32) -> String {
    format!("CNRY{row}x{:08x}", 0x5eed_0000 + row)
}

/// The literal a secret-named key or a rule S / D value is replaced by.
const R: &str = "<redacted>";

/// Every input of AC45 as `(arguments, expected audit args)`. The secret-bearing
/// values are canaries; `expected` never contains one.
fn ac45_rows() -> Vec<(JsonValue, JsonValue)> {
    let c = canary;
    vec![
        // 1. a header map: secret name and non-benign name redacted, benign kept.
        (
            json!({"headers": {
                "Accept": "text/html",
                "Authorization": format!("Bearer {}", c(1)),
                "Content-Type": "application/json",
                "X-Custom": c(1),
            }}),
            json!({"headers": {
                "Accept": "text/html",
                "Authorization": R,
                "Content-Type": "application/json",
                "X-Custom": R,
            }}),
        ),
        // 2. header pairs as arrays.
        (
            json!({"headers": [
                ["Cookie", format!("foo={}", c(2))],
                ["Accept", "text/html"],
                ["X-Zed", "z"],
            ]}),
            json!({"headers": [
                ["Cookie", R],
                ["Accept", "text/html"],
                ["X-Zed", R],
            ]}),
        ),
        // 3. header objects with name and value.
        (
            json!({"headers": [
                {"name": "Cookie", "value": c(3)},
                {"name": "Accept", "value": "text/html"},
            ]}),
            json!({"headers": [
                {"name": "Cookie", "value": R},
                {"name": "Accept", "value": "text/html"},
            ]}),
        ),
        // 4. rule S with no header key: a name/value object and a pair.
        (
            json!({
                "pairs": [{"name": "Authorization", "value": c(4)}],
                "entries": [["Set-Cookie", format!("{}=1", c(4))]],
            }),
            json!({
                "pairs": [{"name": "Authorization", "value": R}],
                "entries": [["Set-Cookie", R]],
            }),
        ),
        // 5. a header collection at any depth.
        (
            json!({"a": {"b": {"request_headers": {"X-Zed": c(5), "Host": "h.test"}}}}),
            json!({"a": {"b": {"request_headers": {"X-Zed": R, "Host": "h.test"}}}}),
        ),
        // 6. a routing header is the evidence and stays; a debug header does not.
        (
            json!({"edits": {"headers": {
                "X-Forwarded-Host": "evil.test",
                "X-Debug": c(6),
            }}}),
            json!({"edits": {"headers": {
                "X-Forwarded-Host": "evil.test",
                "X-Debug": R,
            }}}),
        ),
        // 7. a kept value still passes the strict text pass.
        (
            json!({"headers": {"Referer": format!("https://x.test/cb?token={}", c(7))}}),
            json!({"headers": {"Referer": "https://x.test/cb?token=[redacted]"}}),
        ),
        // 8. a non-string under a non-benign name is redacted whatever its type.
        (
            json!({"headers": {"X-N": 5}}),
            json!({"headers": {"X-N": R}}),
        ),
        // 9. rule S siblings: a secret selector names the text that follows.
        (
            json!({"selector": "#password", "text": c(9)}),
            json!({"selector": "#password", "text": R}),
        ),
        (
            json!({"selector": "input[name=api_token]", "text": c(10)}),
            json!({"selector": "input[name=api_token]", "text": R}),
        ),
        (
            json!({"selector": "#q", "text": "hello"}),
            json!({"selector": "#q", "text": "hello"}),
        ),
        // 10. secret-named keys, strict vocabulary: `pass` and `pw` segments.
        (
            json!({"vars": {
                "admin_pass": c(11),
                "pw": c(11),
                "target": "http://t.test",
                "user": "admin",
            }}),
            json!({"vars": {
                "admin_pass": R,
                "pw": R,
                "target": "http://t.test",
                "user": "admin",
            }}),
        ),
    ]
}

// -------------------------------------------------------------------- tests

/// AC45: rules S and D, through the real server. The ring entry's `args_summary`
/// parses to exactly the expected value, and the pushed line and `agent.activity`
/// carry the byte-identical string.
#[test]
fn rules_s_and_d_redact_header_collections_and_siblings() {
    let mut failures = Vec::new();
    for (input, expected) in ac45_rows() {
        let rig = Rig::new();
        let reply = rig.agent_call("demo.accept", input.clone());
        if is_error(&reply) {
            failures.push(format!("input {input}: demo.accept was refused: {reply}"));
            continue;
        }
        let views = rig.views("demo.accept");
        let (ring, same) = views.args();
        match serde_json::from_str::<JsonValue>(ring) {
            Ok(parsed) if parsed == expected => {}
            Ok(parsed) => {
                failures.push(format!("input {input}: expected {expected}, got {parsed}"))
            }
            Err(e) => failures.push(format!("input {input}: args is not JSON ({e}): {ring}")),
        }
        if !same {
            failures.push(format!(
                "input {input}: the three surfaces differ: ring {ring}, pushed {}, activity {}",
                views.pushed["args"], views.activity["args"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} row(s) wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// AC47, source half: `redact_value` is idempotent over every AC45 input and
/// the extra shapes, and the two honest entries that a writer must not disturb
/// come out of the source exactly (and as parseable JSON).
#[test]
fn redaction_is_idempotent_and_json_safe() {
    let mut inputs: Vec<JsonValue> = ac45_rows().into_iter().map(|(input, _)| input).collect();
    inputs.push(json!({"note": "Authorization: Bearer CNRY47x5eed0047"}));
    inputs.push(json!({"raw": "GET /\r\nCookie: a=b; z=CNRY47x5eed0048\r\nHost: x"}));
    inputs.push(json!({"u": "x?next=a%2Bb"}));
    let mut failures = Vec::new();
    for input in &inputs {
        let once = redact_value(input);
        let twice = redact_value(&once);
        if once != twice {
            failures.push(format!("input {input}: once {once}, twice {twice}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} value(s) not idempotent:\n{}",
        failures.len(),
        failures.join("\n")
    );

    // The note: the source masks the whole line after `Authorization:` and the
    // rendering still parses.
    let rig = Rig::new();
    let reply = rig.agent_call(
        "demo.accept",
        json!({"note": "Authorization: Bearer SECRET47"}),
    );
    assert!(!is_error(&reply), "demo.accept runs: {reply}");
    let views = rig.views("demo.accept");
    let (ring, same) = views.args();
    assert_eq!(ring, r#"{"note":"Authorization: [redacted]"}"#);
    assert!(same, "pushed and activity carry the ring's string");
    assert_eq!(
        serde_json::from_str::<JsonValue>(ring).expect("args parses as JSON"),
        json!({"note": "Authorization: [redacted]"})
    );

    // The raw request: a cookie line is masked to its end and the line breaks
    // stay the JSON escapes `\r\n` of the text.
    let rig = Rig::new();
    let reply = rig.agent_call(
        "demo.accept",
        json!({"raw": "GET /\r\nCookie: a=b; z=SECRET47\r\nHost: x"}),
    );
    assert!(!is_error(&reply), "demo.accept runs: {reply}");
    let views = rig.views("demo.accept");
    let (ring, same) = views.args();
    assert_eq!(ring, r#"{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x"}"#);
    assert!(same, "pushed and activity carry the ring's string");
    assert_eq!(
        serde_json::from_str::<JsonValue>(ring).expect("args parses as JSON"),
        json!({"raw": "GET /\r\nCookie: [redacted]\r\nHost: x"})
    );
}

/// AC60: the error reason of the audit entry is scrubbed with the strict pass at
/// the source (a cookie line is masked to its end, not to the first `;`), and the
/// ring, the pushed line and `agent.activity` carry the same reason.
#[test]
fn the_reason_is_scrubbed_strictly_at_the_source() {
    let rig = Rig::new();
    let reply = rig.agent_call(
        "demo.fail",
        json!({"note": "bad header Cookie: a=b; z=SECRET60 at line 3"}),
    );
    assert!(is_error(&reply), "demo.fail always fails: {reply}");
    let views = rig.views("demo.fail");

    assert_eq!(
        views.ring_reason(),
        Some("bad header Cookie: [redacted]"),
        "the ring's reason"
    );
    let expected = json!({"error": "bad header Cookie: [redacted]"});
    assert_eq!(views.pushed["result"], expected, "the pushed line's result");
    assert_eq!(
        views.activity["result"], expected,
        "agent.activity's result"
    );
    for (surface, text) in [
        ("ring", format!("{:?}", views.ring)),
        ("pushed", views.pushed.to_string()),
        ("activity", views.activity.to_string()),
    ] {
        assert!(
            !text.contains("SECRET60"),
            "the secret reached the {surface} entry: {text}"
        );
    }
}
