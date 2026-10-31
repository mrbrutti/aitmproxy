//! `aitm tui` agent governance over a **real** loopback TCP connection (spec
//! `2026-10-30-tui-mode-governance-design.md`, AC7).
//!
//! The agent server `tui::build_servers` builds is run with `serve()` on
//! `127.0.0.1:0`, and one agent-token client, the same `aitm_bus_client`
//! `TcpTransport` the TUI itself uses, holds a single connection across a
//! live `agent.set paused` from the TUI's in-process handler. The connection's
//! next call must be refused with no reconnect, and both calls must show in
//! the TUI's `agent.activity`.
//!
//! The Claude sandbox cannot bind TCP ports. When `McpServer::serve` fails its
//! bind with `PermissionDenied`, the test prints a note and returns; it must
//! be run for real in the Terminal panel.

mod support;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aitm::tui::{self, TuiLog};
use aitm::wire::assemble;
use aitm_bus_client::{BusClient, BusError, TcpTransport};
use aitm_core::McpTransport;
use aitm_mcp::McpServer;
use anyhow::Context as _;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The loopback agent token both ends agree on.
const AGENT_TOKEN: &str = "tui-mode-governance-live-agent-token";
/// The operator token, so the agent arm carries both token classes as `aitm
/// tui` does. The TUI here is the in-process operator and never connects.
const OPERATOR_TOKEN: &str = "tui-mode-governance-live-operator-token";
/// Longest any single wait in this test is allowed to take.
const STEP: Duration = Duration::from_secs(5);

/// Removes the test's throwaway CA directory when dropped.
struct CaDirGuard(PathBuf);

impl Drop for CaDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Spawn `serve()` and wait for `on_bound` to report the address.
///
/// `Ok(None)` when the bind was refused with `PermissionDenied`: that is the
/// Claude sandbox, not a bug, and the caller skips with a note.
async fn start_server(server: McpServer) -> anyhow::Result<Option<(SocketAddr, JoinHandle<()>)>> {
    let (bound_tx, bound_rx) = oneshot::channel::<SocketAddr>();
    let server = server.on_bound(move |addr| {
        let _ = bound_tx.send(addr);
    });
    let (done_tx, done_rx) = oneshot::channel::<anyhow::Result<()>>();
    let task = tokio::spawn(async move {
        let _ = done_tx.send(server.serve().await);
    });
    match timeout(STEP, bound_rx)
        .await
        .context("waiting for on_bound")?
    {
        Ok(addr) => Ok(Some((addr, task))),
        Err(_closed) => {
            // `on_bound` was dropped unfired: `serve` ended before binding.
            let outcome = timeout(STEP, done_rx)
                .await
                .context("server task did not end after a failed bind")?
                .context("server task dropped its result")?;
            match outcome {
                Ok(()) => anyhow::bail!("serve returned Ok without ever binding"),
                Err(e) if is_permission_denied(&e) => Ok(None),
                Err(e) => Err(e.context("McpServer::serve failed to bind 127.0.0.1:0")),
            }
        }
    }
}

/// Whether an `io::Error` with `PermissionDenied` is anywhere in the chain
/// (`LoopbackTcp::bind` wraps `TcpListener::bind`'s error directly).
fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::PermissionDenied)
    })
}

/// One `tools/call` through the TUI's in-process handler; the whole JSON-RPC
/// reply.
fn tui_call(tui: &aitm_bus_client::InProcessHandler, name: &str, arguments: Value) -> Value {
    let line = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    });
    let reply =
        tui(&line.to_string()).unwrap_or_else(|| panic!("the TUI server replies to `{name}`"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_pause_reaches_an_open_loopback_connection_without_reconnecting() {
    // Build as the in-process rig does, with the config's default policy,
    // through the production path only.
    let mut cfg = support::config("live-pause");
    cfg.mcp.transport = McpTransport::LoopbackTcp {
        port: 0,
        token: AGENT_TOKEN.into(),
        endpoint_file: None,
    };
    cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into());
    let _ca_dir = CaDirGuard(cfg.ca.dir.clone());
    let assembled = assemble(&cfg).expect("assemble");
    let governance = assembled.governance();
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let (agent, tui) = tui::build_servers(&cfg, services, governance);
    let agent = agent.expect("a loopback-TCP transport gets an agent server");

    let Some((addr, server_task)) = start_server(agent)
        .await
        .expect("start the MCP server on loopback TCP")
    else {
        eprintln!(
            "tui_mode_governance_live: skipped — this sandbox refuses to bind 127.0.0.1:0 \
             (PermissionDenied); run cargo test -p aitm --test tui_mode_governance_live -- \
             --nocapture in the Terminal panel"
        );
        return;
    };

    // One agent connection, held open for the whole test.
    let transport = timeout(STEP, TcpTransport::connect(addr, AGENT_TOKEN))
        .await
        .unwrap_or_else(|_| panic!("connect within {STEP:?}"))
        .expect("connect to the loopback agent server");
    let client = BusClient::new(Box::new(transport));
    let info = timeout(STEP, client.initialize("tui-mode-governance-live", "test"))
        .await
        .unwrap_or_else(|_| panic!("initialize within {STEP:?}"))
        .expect("initialize");
    assert_eq!(
        info.role.as_deref(),
        Some("agent"),
        "the agent token is served as the agent role: {info:?}"
    );

    let first = timeout(STEP, client.call("flow.list", json!({})))
        .await
        .unwrap_or_else(|_| panic!("flow.list within {STEP:?}"));
    assert!(
        matches!(&first, Ok(v) if *v == json!([])),
        "the agent's first flow.list runs over an empty store: {first:?}"
    );

    let set = tui_call(&tui, "agent.set", json!({"policy": "paused"}));
    assert_eq!(set["result"]["isError"], json!(false), "{set}");
    assert_eq!(
        set["result"]["structuredContent"]["policy"],
        json!("paused"),
        "{set}"
    );

    // The same connection's next call: refused, no reconnect.
    let second = timeout(STEP, client.call("flow.list", json!({})))
        .await
        .unwrap_or_else(|_| panic!("flow.list after agent.set paused within {STEP:?}"));
    match second {
        Err(BusError::Tool(t)) if t.contains("the agent policy is `paused`") => {}
        other => panic!(
            "flow.list after agent.set paused on the same connection was not refused: {other:?}"
        ),
    }

    let activity = tui_call(&tui, "agent.activity", json!({}));
    assert_eq!(activity["result"]["isError"], json!(false), "{activity}");
    let rows = activity["result"]["structuredContent"]
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {activity}"));
    assert_eq!(rows.len(), 2, "exactly the agent's two calls: {activity}");
    assert_eq!(rows[0]["origin"], json!("mcp"), "{activity}");
    assert_eq!(rows[0]["command"], json!("flow.list"), "{activity}");
    assert_eq!(rows[0]["result"], json!("ok"), "{activity}");
    assert_eq!(rows[1]["origin"], json!("mcp"), "{activity}");
    assert_eq!(rows[1]["command"], json!("flow.list"), "{activity}");
    let error = rows[1]["result"]["error"]
        .as_str()
        .unwrap_or_else(|| panic!("the refused flow.list has a string result.error: {activity}"));
    assert!(error.contains("paused"), "{activity}");

    server_task.abort();
    drop(assembled);
}
