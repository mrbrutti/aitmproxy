//! Task 28 / AC7 / AC8, M2 Task 21 / M2-AC17: the real wired command set,
//! exercised through both frontends. Proves the exact `tools/list` (the M2 tools
//! plus the operator-command additions), that the six `browser.*` schemas match the
//! checked-in snapshot, that an open `headers` map (TypeDesc::Map) round-trips
//! through MCP and the CLI into a mutated flow, and that poc.run's `vars` map
//! is coerced rather than rejected.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::wire::build_proxy;
use aitm_core::{
    AgentPolicy, AgentState, Body, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, McpTransport, ProxyClient, ScopeEntry,
};
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

const EXPECTED_TOOLS: [&str; 38] = [
    "agent.status",
    "agent.set",
    "flow.subscribe",
    "flow.unsubscribe",
    "flow.list",
    "flow.get",
    "flow.detail",
    "flow.replay",
    "flow.intercept",
    "flow.resume",
    "flow.kill",
    "flow.mutate",
    "flow.mark",
    "flow.comment",
    "flow.clear",
    "proxy.status",
    "proxy.pause",
    "proxy.resume",
    "config.get",
    "request.send",
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.screenshot",
    "browser.eval",
    "browser.get_dom",
    "poc.build",
    "poc.run",
    "poc.list",
    "poc.get",
    "poc.artifact",
    "scope.add",
    "scope.remove",
    "scope.list",
    "ca.export",
    "ca.install",
    "ca.status",
    "ca.uninstall",
];

/// The six `browser.*` tool schemas as M1 shipped them, keyed by tool name.
/// M2 changes the engine behind them, never their surface (M2-AC17).
const BROWSER_SCHEMAS_SNAPSHOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/browser-tool-schemas.json"
);

/// The 12 operator-command tools (F5/F6/F7/F12/F13) whose input schemas the three
/// surfaces build their forms from; pinned so a shape change is a deliberate edit.
const OPERATOR_TOOLS: [&str; 12] = [
    "flow.detail",
    "flow.mark",
    "flow.comment",
    "flow.clear",
    "proxy.status",
    "proxy.pause",
    "proxy.resume",
    "config.get",
    "scope.remove",
    "poc.list",
    "poc.get",
    "poc.artifact",
];

const OPERATOR_SCHEMAS_SNAPSHOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/operator-tool-schemas.json"
);

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-fe-{tag}-{nanos}-{n}"))
}

fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.scope.entries = vec![ScopeEntry {
        host: "ex.test:80".into(),
    }];
    cfg
}

/// A `ProxyClient` that is never called by flow.mutate.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().unwrap(),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

fn insert_flow(store: &dyn FlowStore) -> FlowId {
    let flow = HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test:80".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    };
    store.insert(Flow::Http(flow))
}

fn rpc(server: &McpServer, id: u64, method: &str, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let resp = server.handle(&req.to_string()).expect("a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

#[test]
fn ac7_exact_tool_set() {
    let proxy = build_proxy(&config("ac7")).expect("build proxy");
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio);
    let resp = rpc(&server, 1, "tools/list", json!({}));
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let mut names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    let mut expected: Vec<String> = EXPECTED_TOOLS.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(
        names, expected,
        "tools/list must be exactly the M2 tools plus the operator-command additions"
    );

    // The browser.* schemas are byte-for-byte M1's: compare the six
    // inputSchemas, keyed by name, against the checked-in snapshot.
    let actual: serde_json::Map<String, JsonValue> = tools
        .iter()
        .filter(|t| {
            t["name"]
                .as_str()
                .unwrap_or_default()
                .starts_with("browser.")
        })
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["inputSchema"].clone(),
            )
        })
        .collect();
    assert_eq!(actual.len(), 6, "six browser.* tools: {:?}", actual.keys());
    let actual_text = serde_json::to_string_pretty(&actual).expect("serialize schemas");
    let snapshot_text = std::fs::read_to_string(BROWSER_SCHEMAS_SNAPSHOT).unwrap_or_else(|e| {
        panic!("read snapshot {BROWSER_SCHEMAS_SNAPSHOT}: {e}\nactual schemas:\n{actual_text}\n")
    });
    let snapshot: JsonValue = serde_json::from_str(&snapshot_text).expect("snapshot is JSON");
    assert_eq!(
        JsonValue::Object(actual),
        snapshot,
        "browser.* schemas drifted from the M1 snapshot; actual:\n{actual_text}\n"
    );

    // The 12 operator-command input schemas, keyed by name, against their snapshot.
    let operator: serde_json::Map<String, JsonValue> = tools
        .iter()
        .filter(|t| {
            t["name"]
                .as_str()
                .is_some_and(|n| OPERATOR_TOOLS.contains(&n))
        })
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["inputSchema"].clone(),
            )
        })
        .collect();
    assert_eq!(
        operator.len(),
        OPERATOR_TOOLS.len(),
        "all operator tools present: {:?}",
        operator.keys()
    );
    let operator_text = serde_json::to_string_pretty(&operator).expect("serialize schemas");
    let operator_snapshot = std::fs::read_to_string(OPERATOR_SCHEMAS_SNAPSHOT).unwrap_or_else(|e| {
        panic!("read snapshot {OPERATOR_SCHEMAS_SNAPSHOT}: {e}\nactual schemas:\n{operator_text}\n")
    });
    assert_eq!(
        JsonValue::Object(operator),
        serde_json::from_str::<JsonValue>(&operator_snapshot).expect("snapshot is JSON"),
        "operator-command schemas drifted; actual:\n{operator_text}\n"
    );

    // The headers map derives an open-object JSON Schema (TypeDesc::Map).
    let mutate = resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "flow.mutate")
        .expect("flow.mutate present");
    let headers_schema = &mutate["inputSchema"]["properties"]["edits"]["properties"]["headers"];
    assert_eq!(headers_schema["type"], "object");
    assert_eq!(headers_schema["additionalProperties"]["type"], "string");
}

#[test]
fn mutate_headers_roundtrip_over_mcp() {
    let proxy = build_proxy(&config("mcp")).expect("build proxy");
    let store = proxy.store();
    let id = insert_flow(store.as_ref());

    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        store.clone(),
        client,
        proxy.guard(),
        None,
    );

    let resp = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "flow.mutate", "arguments": {
            "id": id.to_string(),
            "edits": {"headers": {"X-Test": "mcp-value"}},
        }}),
    );
    assert_eq!(
        resp["result"]["isError"],
        json!(false),
        "mutate failed: {resp}"
    );

    let Some(Flow::Http(flow)) = store.get(id) else {
        panic!("flow missing");
    };
    assert_eq!(flow.request.headers.get("X-Test"), Some("mcp-value"));
}

#[test]
fn mutate_headers_roundtrip_over_cli() {
    let proxy = build_proxy(&config("cli")).expect("build proxy");
    let store = proxy.store();
    let id = insert_flow(store.as_ref());

    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let cli = aitm_cli::Cli::new(proxy.registry_arc()).with_services(
        store.clone(),
        client,
        proxy.guard(),
        None,
    );

    let argv = vec![
        "flow".to_string(),
        "mutate".to_string(),
        "--id".to_string(),
        id.to_string(),
        "--edits".to_string(),
        json!({"headers": {"X-Test": "cli-value"}}).to_string(),
    ];
    cli.dispatch(&argv).expect("cli mutate");

    let Some(Flow::Http(flow)) = store.get(id) else {
        panic!("flow missing");
    };
    assert_eq!(flow.request.headers.get("X-Test"), Some("cli-value"));
}

#[test]
fn mutate_rejects_crlf_in_header_value() {
    let proxy = build_proxy(&config("crlf")).expect("build proxy");
    let store = proxy.store();
    let id = insert_flow(store.as_ref());
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        store.clone(),
        client,
        proxy.guard(),
        None,
    );
    let resp = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "flow.mutate", "arguments": {
            "id": id.to_string(),
            "edits": {"headers": {"X-Evil": "a\r\nInjected: 1"}},
        }}),
    );
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "CRLF must be refused"
    );
    // The stored flow is unchanged.
    let Some(Flow::Http(flow)) = store.get(id) else {
        panic!("flow missing");
    };
    assert!(!flow.request.headers.has("X-Evil"));
}

#[test]
fn poc_run_vars_map_is_coerced_not_rejected() {
    let proxy = build_proxy(&config("vars")).expect("build proxy");
    let store = proxy.store();
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        store,
        client,
        proxy.guard(),
        None,
    );
    // A vars map of arbitrary values is accepted by the schema (Map(Any)); the
    // command then fails on the missing file, not on an argument shape error.
    let resp = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "poc.run", "arguments": {
            "poc_path": "/nonexistent/aitm-does-not-exist.yaml",
            "target": "http://ex.test",
            "vars": {"param": "q", "count": 3, "flag": true},
        }}),
    );
    assert_eq!(resp["result"]["isError"], json!(true));
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("nonexistent")
            || text.to_lowercase().contains("read")
            || text.contains("stat"),
        "vars must coerce and the command fail on the file, got: {text}"
    );
}

/// config.get reaches the control plugin over BOTH frontends only when the
/// frontend attached the config — the plumbing main.rs does for each.
#[test]
fn config_get_reaches_plugins_over_both_frontends() {
    let cfg = config("cfgget");
    let proxy = build_proxy(&cfg).expect("build proxy");
    let store = proxy.store();
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);

    // MCP: with_config set -> redacted config comes back; the token never does.
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio)
        .with_config(Arc::new(cfg.clone()))
        .with_services(store.clone(), client.clone(), proxy.guard(), None);
    let resp = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "config.get", "arguments": {}}),
    );
    assert_eq!(resp["result"]["isError"], json!(false), "{resp}");
    let got = &resp["result"]["structuredContent"];
    assert_eq!(got["listen"], json!(cfg.listen.to_string()));
    assert_eq!(got["scope"]["entries"][0], json!("ex.test:80"));
    assert!(
        !resp.to_string().contains("token"),
        "config.get must not leak any token field"
    );

    // MCP without config -> a clear tool error, not a panic or empty object.
    let server_no_cfg = McpServer::new(proxy.registry_arc(), McpTransport::Stdio).with_services(
        store.clone(),
        client.clone(),
        proxy.guard(),
        None,
    );
    let resp = rpc(
        &server_no_cfg,
        2,
        "tools/call",
        json!({"name": "config.get", "arguments": {}}),
    );
    assert_eq!(resp["result"]["isError"], json!(true), "{resp}");

    // CLI: with_config set -> the same redacted view.
    let cli = aitm_cli::Cli::new(proxy.registry_arc())
        .with_config(Arc::new(cfg.clone()))
        .with_services(store, client, proxy.guard(), None);
    let value = cli
        .dispatch(&["config".to_string(), "get".to_string()])
        .expect("cli config.get");
    let text = format!("{value:?}");
    assert!(
        text.contains(&cfg.listen.to_string()),
        "cli config.get: {text}"
    );
}

/// Wire-level proof of the default-off scope gate: an assembled proxy refuses an
/// MCP `scope.add` under `Config::default()`, and accepts it once the operator
/// sets `scope.allow_agent_widen` (covers the wire.rs plumbing of the flag).
#[test]
fn scope_add_gate_is_wired_default_off() {
    // Default config: the flag is off, so the agent (MCP) frontend is refused.
    // Run the agent under `All` so what decides is scope.add's own config gate, not
    // the policy: under the default `Auto` every Sensitive command is refused
    // outright (spec D2), which would mask the gate this test is proving.
    let mut cfg = config("gate-off");
    cfg.scope.allow_agent_widen = false;
    let proxy = build_proxy(&cfg).expect("build proxy");
    let store = proxy.store();
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let server = McpServer::new(proxy.registry_arc(), McpTransport::Stdio)
        .with_services(store, client, proxy.guard(), None)
        .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)));
    let resp = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "scope.add", "arguments": {"host": "new.test"}}),
    );
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "MCP scope.add must be refused when allow_agent_widen is off: {resp}"
    );

    // With the flag on, the same MCP call is accepted.
    let mut cfg2 = config("gate-on");
    cfg2.scope.allow_agent_widen = true;
    let proxy2 = build_proxy(&cfg2).expect("build proxy");
    let store2 = proxy2.store();
    let client2: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let server2 = McpServer::new(proxy2.registry_arc(), McpTransport::Stdio)
        .with_services(store2, client2, proxy2.guard(), None)
        .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)));
    let resp2 = rpc(
        &server2,
        1,
        "tools/call",
        json!({"name": "scope.add", "arguments": {"host": "new.test"}}),
    );
    assert_eq!(
        resp2["result"]["isError"],
        json!(false),
        "MCP scope.add must be accepted when allow_agent_widen is on: {resp2}"
    );
}

/// Startup guard: a PoC output dir that equals (or contains) the CA directory is
/// refused, so `poc.artifact` can never be pointed at the CA key.
#[test]
fn assemble_rejects_out_dir_containing_ca_dir() {
    let assemble_err = |cfg: &Config| match aitm::wire::assemble(cfg) {
        Ok(_) => panic!("assemble should have been refused"),
        Err(e) => e.to_string(),
    };

    // out_dir == ca.dir is the clearest footgun.
    let mut cfg = config("ca-guard");
    cfg.poc.out_dir = Some(cfg.ca.dir.clone());
    assert!(
        assemble_err(&cfg).contains("poc.out_dir"),
        "error should name poc.out_dir"
    );

    // A parent-of-ca.dir out_dir is refused too.
    let mut cfg2 = config("ca-guard2");
    cfg2.poc.out_dir = cfg2.ca.dir.parent().map(|p| p.to_path_buf());
    assert!(assemble_err(&cfg2).contains("poc.out_dir"));
}
