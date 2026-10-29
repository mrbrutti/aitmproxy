//! TUI plan Task 4: `aitm tui` embeds the proxy in one process. `main` builds
//! the proxy exactly as the server path does and then `tui::build_servers`
//! constructs **two** `McpServer`s over the same `Arc<Registry>` and services:
//! one served on the configured agent transport (loopback TCP only — `None`
//! for stdio, which would share the terminal), one wrapped as
//! `Arc<McpServer>` whose `handle` becomes the TUI's in-process bus handler.
//! This test calls that same `build_servers` and drives the handler through
//! `aitm_bus_client::BusClient` over `InProcessTransport` — the literal
//! contract the TUI relies on (foundation §4.1–4.2, §4.10).

mod support;

use std::sync::Arc;
use std::time::SystemTime;

use aitm::tui::build_servers;
use aitm_bus_client::{BusClient, InProcessHandler, InProcessTransport};
use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, McpTransport,
};
use aitm_mcp::McpServer;
use serde_json::{json, Value};
use support::{assemble_services, config};

/// The two servers `aitm tui` builds, plus the shared store so a test can
/// observe that both see one proxy.
struct Embedded {
    /// The agent-facing server (loopback TCP in `main`; never served here
    /// because the sandbox cannot bind ports — its `handle` is the same code).
    agent: McpServer,
    /// The TUI-facing server behind the in-process handler.
    handler: InProcessHandler,
    store: Arc<dyn FlowStore>,
}

/// `main`'s `tui` wiring: `assemble`, the shared service handles, then
/// `build_servers` over a loopback-TCP agent transport.
fn embed(tag: &str) -> Embedded {
    let mut cfg = config(tag);
    cfg.mcp.transport = McpTransport::LoopbackTcp {
        port: 0,
        token: "test-token".into(),
        endpoint_file: None,
    };
    let (_proxy, services) = assemble_services(&cfg);
    let store = services.store.clone();
    let (agent, handler) = build_servers(&cfg, services);
    Embedded {
        agent: agent.expect("a loopback-TCP transport gets an agent server"),
        handler,
        store,
    }
}

fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("socket addr"),
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

/// `tools/call flow.list` straight through a server's `handle`, as the agent
/// transport would run it; returns the `structuredContent`.
fn flow_list_via_handle(server: &McpServer) -> Value {
    let req = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "flow.list", "arguments": {}},
    });
    let reply = server.handle(&req.to_string()).expect("a reply");
    let reply: Value = serde_json::from_str(&reply).expect("reply is JSON");
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
    reply["result"]["structuredContent"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_handler_serves_the_bus_contract_the_tui_relies_on() {
    let embedded = embed("contract");
    let bus = BusClient::new(Box::new(InProcessTransport::new(embedded.handler)));

    let info = bus
        .initialize("aitm-tui", "test")
        .await
        .expect("initialize");
    assert_eq!(info.name, "aitmproxy");

    let tools = bus.tools_list().await.expect("tools/list");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"flow.list"),
        "tools/list must contain flow.list, got {names:?}"
    );

    let flows = bus.call("flow.list", json!({})).await.expect("flow.list");
    assert_eq!(flows, json!([]), "a fresh proxy has no flows");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_servers_see_the_one_embedded_proxy() {
    let embedded = embed("shared");
    let bus = BusClient::new(Box::new(InProcessTransport::new(embedded.handler)));
    bus.initialize("aitm-tui", "test")
        .await
        .expect("initialize");

    let id = insert_flow(embedded.store.as_ref());

    let via_tui = bus.call("flow.list", json!({})).await.expect("flow.list");
    assert_eq!(via_tui, json!([id.to_string()]));

    let via_agent = flow_list_via_handle(&embedded.agent);
    assert_eq!(via_agent, via_tui, "agent and TUI servers share one store");
}

/// A stdio agent transport would share the terminal with the UI, so
/// `build_servers` serves no agent server for it; the TUI side still answers.
#[test]
fn a_stdio_agent_transport_gets_no_agent_server_beside_the_tui() {
    let mut cfg = config("stdio");
    cfg.mcp.transport = McpTransport::Stdio;
    let (_proxy, services) = assemble_services(&cfg);
    let (agent, handler) = build_servers(&cfg, services);
    assert!(agent.is_none(), "stdio is not served beside the TUI");
    let reply = handler(&json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{}}).to_string())
        .expect("the TUI-side server replies");
    let reply: Value = serde_json::from_str(&reply).expect("reply is JSON");
    assert_eq!(reply["id"], 1);
    assert!(reply["result"].is_object(), "{reply}");
}
