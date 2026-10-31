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
/// tables below send (`a` carries the nested-collection row of AC45, `list` the
/// 500000-leaf call of AC46).
const ACCEPT_PARAMS: [&str; 13] = [
    "headers", "pairs", "entries", "request", "edits", "selector", "text", "vars", "note", "raw",
    "body", "a", "list",
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

// ------------------------------------------- header shapes beyond AC45's rows

/// The text-mask literal a hidden raw header line carries (`Name: [redacted]`).
const T: &str = "[redacted]";

/// Header shapes the AC45 rows do not send, as `(arguments, expected audit
/// args)`: a pair whose second element is not a string, a pair that is the whole
/// value of the key, raw `Name: value` lines, and a header object that carries a
/// `values` list. Every secret-bearing value is a canary.
fn header_shape_rows() -> Vec<(JsonValue, JsonValue)> {
    let c = canary;
    vec![
        // a pair whose second element is any type: rule D decides by the name.
        (
            json!({"headers": [
                ["X-N", 5],
                ["X-Null", null],
                ["X-Obj", {"k": c(20)}],
                ["Content-Length", 7],
            ]}),
            json!({"headers": [
                ["X-N", R],
                ["X-Null", R],
                ["X-Obj", R],
                ["Content-Length", 7],
            ]}),
        ),
        // the pair is the value of the key itself.
        (
            json!({"headers": ["X-Debug", c(21)]}),
            json!({"headers": ["X-Debug", R]}),
        ),
        // raw header lines: benign survive, the rest are hidden.
        (
            json!({"headers": [
                "Host: example.com",
                "Accept: text/html",
                format!("X-Debug: {}", c(22)),
                format!("Cookie: a={}; c=d", c(22)),
                "Authorization: Basic Zm9v",
            ]}),
            json!({"headers": [
                "Host: example.com",
                "Accept: text/html",
                format!("X-Debug: {T}"),
                format!("Cookie: {T}"),
                format!("Authorization: {T}"),
            ]}),
        ),
        // raw lines in a response collection, deep in the arguments.
        (
            json!({"a": {"response_headers": [format!("Set-Cookie: sid={}", c(23))]}}),
            json!({"a": {"response_headers": [format!("Set-Cookie: {T}")]}}),
        ),
        // a header object with a `values` list beside its value.
        (
            json!({"headers": [{
                "name": "X-Debug", "value": c(24), "values": [c(24), "b"],
            }]}),
            json!({"headers": [{"name": "X-Debug", "value": R, "values": R}]}),
        ),
        // a header object with a `values` list and no `value`.
        (
            json!({"headers": [{"name": "Set-Cookie", "values": [c(25)]}]}),
            json!({"headers": [{"name": "Set-Cookie", "values": R}]}),
        ),
        // a benign name keeps its value and the other members take the general walk.
        (
            json!({"headers": [{"name": "Host", "value": "h.test", "values": ["a=b"]}]}),
            json!({"headers": [{"name": "Host", "value": "h.test", "values": ["a=b"]}]}),
        ),
    ]
}

/// Send each row to `demo.accept` as an agent and return one message per wrong
/// row: the parsed ring `args_summary` is not the expectation, the three surfaces
/// disagree, or a canary reached any of them.
fn row_failures(rows: Vec<(JsonValue, JsonValue)>) -> Vec<String> {
    let mut failures = Vec::new();
    for (input, expected) in rows {
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
        for (surface, text) in [
            ("ring", format!("{:?}", views.ring)),
            ("pushed", views.pushed.to_string()),
            ("activity", views.activity.to_string()),
        ] {
            if text.contains("CNRY") {
                failures.push(format!(
                    "input {input}: a canary reached the {surface}: {text}"
                ));
            }
        }
    }
    failures
}

/// Header pairs of any value type, raw header lines and header objects with a
/// `values` list are default-deny under a header-collection key, through the real
/// server, with the ring, the pushed line and `agent.activity` in agreement.
#[test]
fn header_pairs_lines_and_objects_are_default_deny() {
    let failures = row_failures(header_shape_rows());
    assert!(
        failures.is_empty(),
        "{} row(s) wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ------------------------------------------------------- bounded work (AC46)

/// `redact_value` returns at most 4097 characters for a 16 MiB string leaf, and a
/// wide value of 100 leaves of 100 KiB is shown as exactly 16 leaves cut at 4096
/// bytes plus an ellipsis and 84 ellipsis leaves: deterministic, not a clock.
#[test]
fn redaction_output_is_bounded_in_size() {
    let huge = redact_value(&JsonValue::String("a".repeat(16 * 1024 * 1024)));
    let text = huge.as_str().expect("a string leaf stays a string");
    assert!(
        text.chars().count() <= 4097,
        "the leaf kept {} characters",
        text.chars().count()
    );
    assert_eq!(text, format!("{}…", "a".repeat(4096)));

    let wide = redact_value(&JsonValue::Array(vec![
        JsonValue::String(
            "b".repeat(100 * 1024)
        );
        100
    ]));
    let leaves = wide.as_array().expect("an array stays an array");
    let total: usize = leaves.iter().map(|v| v.as_str().map_or(0, str::len)).sum();
    // 16 leaves of 4096 bytes + the three-byte `…`, then 84 leaves of `…` alone.
    assert_eq!(total, 16 * (4096 + 3) + 84 * 3, "the bytes the leaves kept");
    assert_eq!(leaves.len(), 100);
    assert_eq!(leaves[15].as_str().map(str::len), Some(4096 + 3));
    assert_eq!(leaves[16].as_str(), Some("…"));
}

/// One `demo.accept` call: the time it took, whether it was accepted, and the
/// ring entry's `args_summary` (the pushed line and `agent.activity` must carry
/// the same string).
fn timed_accept(args: JsonValue) -> (std::time::Duration, String) {
    let rig = Rig::new();
    let started = std::time::Instant::now();
    let reply = rig.agent_call("demo.accept", args);
    let took = started.elapsed();
    assert!(!is_error(&reply), "demo.accept was refused: {reply}");
    let views = rig.views("demo.accept");
    let (ring, same) = views.args();
    assert!(same, "the three surfaces carry the ring's string");
    (took, ring.to_string())
}

/// AC46: the work `redact_args` does is bounded whatever the arguments weigh. A
/// 16 MiB body and a 500000-leaf list each return within 5 seconds with an entry of
/// at most 515 bytes; a secret inside the examined 4 KiB of a leaf is masked and one
/// past it is absent. (The clock is the spec's check; the bytes of
/// `redaction_output_is_bounded_in_size` and the unit tests are the deterministic
/// ones.)
#[test]
fn redaction_work_is_bounded() {
    let five_seconds = std::time::Duration::from_secs(5);

    let (took, entry) = timed_accept(json!({"body": "a".repeat(16 * 1024 * 1024)}));
    assert!(took < five_seconds, "a 16 MiB body took {took:?}");
    assert!(entry.len() <= 515, "the entry is {} bytes", entry.len());
    assert!(entry.starts_with(r#"{"body":"aaaa"#), "entry: {entry}");

    let (took, entry) = timed_accept(json!({"list": vec!["x"; 500_000]}));
    assert!(took < five_seconds, "a 500000-leaf list took {took:?}");
    assert!(entry.len() <= 515, "the entry is {} bytes", entry.len());
    assert!(entry.starts_with(r#"{"list":["x","x""#), "entry: {entry}");

    // A 5000-character leaf with `password=<canary>` starting at character 4000
    // (inside the examined bound) and at character 4100 (beyond it).
    let secret = canary(46);
    let leaf_with_key_at = |start: usize| {
        let mut leaf = format!("{} password={secret} ", "a".repeat(start - 1));
        leaf.push_str(&"a".repeat(5000 - leaf.chars().count()));
        leaf
    };
    for start in [4000, 4100] {
        let leaf = leaf_with_key_at(start);
        assert_eq!(leaf.chars().count(), 5000);
        let (took, entry) = timed_accept(json!({"body": leaf.clone()}));
        assert!(took < five_seconds, "the 5000-character leaf took {took:?}");
        assert!(
            !entry.contains(&secret),
            "the secret at character {start} reached the entry: {entry}"
        );
        // The source value itself, which the 512-byte cap of the entry hides
        // behind: inside the bound the key is masked; past it the text is cut.
        let shown = redact_value(&json!({"body": leaf}));
        let shown = shown["body"].as_str().expect("a string").to_string();
        assert!(!shown.contains(&secret), "the secret survived: {shown}");
        if start == 4000 {
            assert!(shown.contains("password=[redacted]"), "masked: {shown}");
        } else {
            assert_eq!(shown, format!("{}…", "a".repeat(4096)));
        }
    }
}

// ------------------------------- line breaks and multi-value headers (R4 fix)

/// Header shapes that carry a line break or several values, as `(arguments,
/// expected audit args)`: a block of header lines in one string, a header array of
/// three or more items, and a kept header value whose later lines are headers. The
/// secret-bearing values are canaries.
fn multi_line_rows() -> Vec<(JsonValue, JsonValue)> {
    let c = canary;
    vec![
        // a string of header lines, CRLF and bare LF: judged line by line.
        (
            json!({"headers": format!("X-Debug: {}\r\nHost: x", c(30))}),
            json!({"headers": format!("X-Debug: {T}\r\nHost: x")}),
        ),
        (
            json!({"headers": format!("Cookie: a={}\nHost: x\nX-Zed: z", c(31))}),
            json!({"headers": format!("Cookie: {T}\nHost: x\nX-Zed: {T}")}),
        ),
        // a header array of three items: rule D by the first element over the rest.
        (
            json!({"headers": [["X-Zed", c(32), "b"], ["Accept", "t", "extra"]]}),
            json!({"headers": [["X-Zed", R, R], ["Accept", "t", "extra"]]}),
        ),
        (
            json!({"headers": ["X-Zed", c(33), "b"]}),
            json!({"headers": ["X-Zed", R, R]}),
        ),
        // a kept value with a header line after its first line break.
        (
            json!({"headers": [["Host", format!("x\r\nX-Debug: {}", c(34))]]}),
            json!({"headers": [["Host", format!("x\r\nX-Debug: {T}")]]}),
        ),
        (
            json!({"headers": {"Host": format!("x\r\nAccept: a\r\nX-Debug: {}", c(35))}}),
            json!({"headers": {"Host": format!("x\r\nAccept: a\r\nX-Debug: {T}")}}),
        ),
        (
            json!({"headers": [{
                "name": "Host", "value": "h", "values": [format!("a\r\nX-Debug: {}", c(36))],
            }]}),
            json!({"headers": [{
                "name": "Host", "value": "h", "values": [format!("a\r\nX-Debug: {T}")],
            }]}),
        ),
        // a header name that carries a header line.
        (
            json!({"headers": [[format!("X-A\r\nX-Debug: {}", c(37)), "v"]]}),
            json!({"headers": [[format!("X-A\r\nX-Debug: {T}"), R]]}),
        ),
    ]
}

/// A string of header lines, a header array of three or more items and a kept value
/// with header lines after a line break are default-deny, through the real server,
/// with the ring, the pushed line and `agent.activity` in agreement and no canary
/// on any of them.
#[test]
fn multi_line_and_multi_value_headers_are_default_deny() {
    let failures = row_failures(multi_line_rows());
    assert!(
        failures.is_empty(),
        "{} row(s) wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
