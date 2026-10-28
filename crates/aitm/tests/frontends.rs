//! Task 28 / AC7 / AC8, M2 Task 21 / M2-AC17: the real wired command set,
//! exercised through both frontends. Proves the exact 22-tool `tools/list`
//! (the 18 M1 tools plus `ca.*`), that the six `browser.*` schemas match the
//! checked-in snapshot, that an open `headers` map (TypeDesc::Map) round-trips
//! through MCP and the CLI into a mutated flow, and that poc.run's `vars` map
//! is coerced rather than rejected.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::wire::build_proxy;
use aitm_core::{
    Body, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, McpTransport, ProxyClient, ScopeEntry,
};
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

const EXPECTED_TOOLS: [&str; 31] = [
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
fn ac7_exact_twenty_two_tools() {
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
