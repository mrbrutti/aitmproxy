//! AC13 / AC15 (rule `url` clause matches the full request URL, plan Task 2): a
//! host-bearing `url` rule armed over the real MCP bus parks the matching flow,
//! `flow.get` reports it, and every rule schema that shares the matcher states
//! the full-URL-and-path subject.
//!
//! The bug this pins: `flow.intercept {rules:[{url:"*httpbin.org*"}]}` never
//! fired on a live core because the matcher ran the clause against the path
//! only. The matcher's own tests prove the subject; this drives the assembled
//! proxy's plugin chain the way `Chain::dispatch` does (mirroring
//! `aitm-plugins/tests/intercept_rules.rs`) and reads the outcome back through
//! `flow.get`, so the operator-visible contract is proved over the bus.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::wire::build_proxy;
use aitm_core::{
    Body, Config, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, McpTransport, ProxyClient, Registry,
    ScopeEntry, Verdict,
};
use aitm_mcp::{ConnCtx, McpServer};
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};
use tokio::sync::oneshot;

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-url-rules-{tag}-{nanos}-{n}"))
}

/// Both hosts are in scope, so the only thing deciding whether a flow parks is
/// the `url` rule.
fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg.scope.entries = vec![
        ScopeEntry {
            host: "ex.test".into(),
        },
        ScopeEntry {
            host: "other.test".into(),
        },
    ];
    cfg
}

/// Never called: nothing here replays or sends.
struct UnusedClient;
impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

/// A `GET http://{authority}{path}` flow in the store, as the HTTP module would
/// record it before dispatching `Event::Request`.
fn insert_flow(store: &dyn FlowStore, authority: &str, path: &str) -> FlowId {
    store.insert(Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: "127.0.0.1:0".parse().expect("loopback addr"),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }))
}

/// Run `Request(id)` through the assembled registry's whole plugin chain as
/// `Chain::dispatch` does, persist the flow, and return the parked receiver if
/// any plugin parked it.
fn dispatch_request(
    reg: &Registry,
    store: &dyn FlowStore,
    id: FlowId,
) -> Option<oneshot::Receiver<()>> {
    let mut flow = store.get(id).expect("flow stored");
    let parked = {
        let mut ctx = FlowCtx::new(&mut flow);
        for plugin in reg.plugins() {
            let verdict = plugin
                .lock()
                .expect("plugin lock")
                .on_event(&Event::Request(id), &mut ctx);
            assert_eq!(verdict, Verdict::Continue);
        }
        ctx.take_parked()
    };
    store.insert(flow);
    parked
}

/// One JSON-RPC request as `role`, returning the parsed `result`.
fn rpc(srv: &McpServer, role: Frontend, method: &str, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp = srv
        .handle_on(&ConnCtx::new(role), &req.to_string())
        .expect("a request gets a response");
    let parsed: JsonValue = serde_json::from_str(&resp).expect("response is JSON");
    parsed["result"].clone()
}

/// `tools/call name args` as `role`.
fn call(srv: &McpServer, role: Frontend, name: &str, args: JsonValue) -> JsonValue {
    rpc(
        srv,
        role,
        "tools/call",
        json!({"name": name, "arguments": args}),
    )
}

fn is_error(result: &JsonValue) -> bool {
    result["isError"].as_bool().unwrap_or(false)
}

fn text(result: &JsonValue) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn structured(result: &JsonValue) -> JsonValue {
    result["structuredContent"].clone()
}

/// AC13: arm a host-bearing rule as the operator (arming is Sensitive; the
/// operator role is the one that may do it), dispatch a matching and a
/// non-matching request through the chain, and read both states back through
/// `flow.get`.
#[test]
fn host_bearing_rule_parks_over_mcp() {
    let proxy = build_proxy(&config("park")).expect("build proxy");
    let store = proxy.store();
    let registry = proxy.registry_arc();
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let srv = McpServer::new(registry.clone(), McpTransport::Stdio).with_services(
        store.clone(),
        client,
        proxy.guard(),
        None,
    );

    let armed = call(
        &srv,
        Frontend::Operator,
        "flow.intercept",
        json!({"enabled": true, "rules": [{"url": "*ex.test*", "phase": "request"}]}),
    );
    assert!(!is_error(&armed), "flow.intercept failed: {}", text(&armed));
    let echoed = structured(&armed);
    assert_eq!(echoed["enabled"], json!(true), "armed: {echoed}");
    assert_eq!(
        echoed["rules"][0]["url"]["wildcard"],
        json!("*ex.test*"),
        "the rule is echoed back: {echoed}"
    );

    let matching = insert_flow(store.as_ref(), "ex.test", "/anything");
    let other = insert_flow(store.as_ref(), "other.test", "/anything");

    let parked = dispatch_request(registry.as_ref(), store.as_ref(), matching);
    assert!(
        parked.is_some(),
        "GET http://ex.test/anything parks under *ex.test*"
    );
    let not_parked = dispatch_request(registry.as_ref(), store.as_ref(), other);
    assert!(
        not_parked.is_none(),
        "GET http://other.test/anything does not park under *ex.test*"
    );

    let got = call(
        &srv,
        Frontend::Operator,
        "flow.get",
        json!({"id": matching.to_string()}),
    );
    assert!(!is_error(&got), "flow.get failed: {}", text(&got));
    assert_eq!(
        structured(&got)["intercept"],
        json!("intercepted"),
        "flow.get for the matching flow: {}",
        structured(&got)
    );

    let got_other = call(
        &srv,
        Frontend::Operator,
        "flow.get",
        json!({"id": other.to_string()}),
    );
    assert!(
        !is_error(&got_other),
        "flow.get failed: {}",
        text(&got_other)
    );
    assert_eq!(
        structured(&got_other)["intercept"],
        json!("observed"),
        "flow.get for the other host's flow: {}",
        structured(&got_other)
    );
}

/// The `inputSchema` of one listed tool.
fn input_schema(srv: &McpServer, tool: &str) -> JsonValue {
    let listed = rpc(srv, Frontend::Operator, "tools/list", json!({}));
    listed["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("`{tool}` is listed"))["inputSchema"]
        .clone()
}

/// A description must name both subjects, so an agent or operator reading the
/// schema learns a host-bearing pattern works and a path-only one still does.
fn assert_states_full_url_subject(what: &str, description: &JsonValue) {
    let description = description
        .as_str()
        .unwrap_or_else(|| panic!("{what} has a string description, got {description}"));
    for phrase in ["full request URL", "path"] {
        assert!(
            description.contains(phrase),
            "{what} description must mention `{phrase}`; got: {description}"
        );
    }
}

/// AC15 (schema descriptions): every rule schema that shares the matcher states
/// the full-URL-and-path subject. `flow.intercept` also spells out the wildcard
/// and regex rules (case, substring, `(?-i)`), since it is the schema agents
/// and surfaces read for a breakpoint rule.
#[test]
fn rule_schemas_state_the_full_url_subject() {
    let proxy = build_proxy(&config("schema")).expect("build proxy");
    let srv = McpServer::new(proxy.registry_arc(), McpTransport::Stdio);

    let intercept = input_schema(&srv, "flow.intercept");
    let url = &intercept["properties"]["rules"]["items"]["properties"]["url"]["description"];
    assert_states_full_url_subject("flow.intercept rules[].url", url);
    let url = url.as_str().unwrap_or_default();
    for phrase in ["case-insensitive", "substring", "(?-i)"] {
        assert!(
            url.contains(phrase),
            "flow.intercept rules[].url must state `{phrase}`; got: {url}"
        );
    }

    let ws = input_schema(&srv, "ws.intercept");
    assert_states_full_url_subject(
        "ws.intercept rules[].url",
        &ws["properties"]["rules"]["items"]["properties"]["url"]["description"],
    );

    let map = input_schema(&srv, "map.add");
    let condition = &map["properties"]["condition"]["description"];
    assert_states_full_url_subject("map.add condition", condition);
    assert!(
        !condition
            .as_str()
            .unwrap_or_default()
            .contains("request target path and authority"),
        "map.add condition must drop the path-only wording; got: {condition}"
    );
}
