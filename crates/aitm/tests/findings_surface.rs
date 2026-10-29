//! M4 fix (quality panel, Important): the persistent `aitm-findings` store must
//! be reachable on the shipped `aitm` binary, not only in the test rigs.
//!
//! This exercises the binary's real command wiring — the same rhai tier
//! `main.rs` builds (via `LateHandles` + `ScriptServices`) PLUS the
//! `FindingsPlugin`, both placed in the one `ScriptWiring.commands` slot — and
//! then asks the MCP server's `tools/list` what the bus actually serves. It is
//! not a bespoke rig: it assembles the proxy the way `main.rs` does and reads
//! the live tool surface.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aitm::scripts::LateHandles;
use aitm::wire::{assemble_with_scripts, Features, Http1Sender, ScriptWiring};
use aitm_core::{AgentPolicy, AgentState, Config, McpTransport, PipelineClient, ProxyClient};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::{MemoryFindingSink, RhaiConfig, ScriptServices};

/// Assemble the proxy with the binary's command wiring and return the names the
/// MCP `tools/list` reports.
fn tool_names() -> Vec<String> {
    // The rhai tier, built as `main.rs` does: the engine's host verbs close over
    // these handles, left unbound here (we never dispatch a flow).
    let handles = LateHandles::new();
    let services = ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    let tier = aitm_plugin_rhai::wire::build(RhaiConfig::default(), services)
        .expect("the rhai tier builds with no scripts");

    // A process- and call-unique CA dir, so the three tests never race on one.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mut cfg = Config::default();
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-findings-surface-{unique}"));

    let assembled = assemble_with_scripts(
        &cfg,
        &Features::default(),
        ScriptWiring {
            plugins: Vec::new(),
            executor: Some(tier.executor.clone()),
            // The binary's wiring: BOTH the rhai tier's commands and the
            // persistent findings store, in one command-provider slot.
            commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
        },
    )
    .expect("assemble the proxy with the binary's command wiring");

    let registry = assembled.proxy.registry_arc();
    let store = assembled.proxy.store();
    let guard = assembled.proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new()),
    ));
    let server = aitm_mcp::McpServer::new(registry, McpTransport::Stdio)
        .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)))
        .with_services(store, client, guard, None);

    let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle(&req.to_string())
            .expect("a tools/list response"),
    )
    .expect("a JSON response");
    resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_string())
        .collect()
}

/// The persistent findings store's four commands all reach the bus on the
/// binary's wiring. This is the whole of the quality finding: without the fix
/// `findings.record`/`get`/`remove` are unknown tools on the shipped binary.
#[tokio::test]
async fn findings_store_commands_are_on_the_bus() {
    let names = tool_names();
    for tool in [
        "findings.record",
        "findings.get",
        "findings.remove",
        "findings.list",
    ] {
        assert!(
            names.contains(&tool.to_string()),
            "{tool} must be an MCP tool on the binary's wiring; got {names:?}"
        );
    }
}

/// The disk-backed `findings.list` is canonical and appears exactly once — the
/// rhai tier's in-memory listing no longer collides with it.
#[tokio::test]
async fn findings_list_is_unambiguous() {
    let names = tool_names();
    let count = names.iter().filter(|n| *n == "findings.list").count();
    assert_eq!(
        count, 1,
        "exactly one findings.list must be served (the persistent store); got {names:?}"
    );
}

/// The rhai tier's in-memory, script-emitted findings listing is preserved under
/// its new name, so scripts that record with `finding(...)` can still read back.
#[tokio::test]
async fn script_emitted_findings_listing_is_preserved() {
    let names = tool_names();
    assert!(
        names.contains(&"script.findings".to_string()),
        "the rhai tier's script-emitted findings listing must survive as script.findings; \
         got {names:?}"
    );
}
