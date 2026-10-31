//! The connection id on audit lines, across the two governed agent servers
//! (spec `2026-10-30-bus-audit-connection-id-design.md`, D1, AC18).
//!
//! Since the web bus governance change, the primary agent server and the
//! `aitm web` bridge server share one `AuditRing` (`tui::with_shared_governance`),
//! but each counts its connections from 1. The raw counter therefore collides:
//! "agent, conn 1" exists on both servers, and a line from either would look the
//! same in the shared ring. `McpServer::connection_id` salts the counter with a
//! per-server random value so the two never render the same id.
//!
//! The test here is in process: no sockets and no async runtime. The servers are
//! driven through `McpServer::handle_on` with hand-built `ConnCtx` values, and
//! both are built from one `Assembled`, the way `main.rs` builds them.
//!
//! Layout: the rig and the call helpers come first, one `#[test]` per behaviour
//! after them, so a later test can add to the file without touching these.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::tui::{self, TuiLog};
use aitm::wire::assemble;
use aitm_core::{AgentPolicy, AuditRing, Config, Frontend, Proxy};
use aitm_mcp::{ConnCtx, McpServer};
use serde_json::{json, Value as JsonValue};

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-audit-identity-{tag}-{nanos}-{n}"))
}

/// Two servers over one `Assembled`, policy `Auto`: `primary` (the agent server
/// the bare-`aitm` path serves) and `web` (the `aitm web` bridge's server), both
/// built through `tui::with_shared_governance`, so they share `ring`.
struct Rig {
    primary: McpServer,
    web: McpServer,
    ring: Arc<AuditRing>,
    ca_dir: PathBuf,
    _proxy: Proxy,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ca_dir);
    }
}

fn rig(tag: &str) -> Rig {
    let mut cfg = Config::default();
    cfg.mcp.policy = AgentPolicy::Auto;
    cfg.ca.dir = temp_ca_dir(tag);
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(&assembled.proxy, &cfg, None, TuiLog::Off);
    let state = &assembled.agent_state;
    let ring = &assembled.audit_ring;

    let primary = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let primary = tui::with_shared_governance(primary, state, ring);

    let web = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let web = tui::with_shared_governance(web, state, ring);

    Rig {
        primary,
        web,
        ring: Arc::clone(ring),
        ca_dir: cfg.ca.dir.clone(),
        _proxy: assembled.proxy,
    }
}

/// An agent connection as a transport builds the first one on a server: the
/// agent role, no label, `conn_id` 1 (every server's counter starts there), no
/// push sink.
fn first_agent_connection() -> ConnCtx {
    ConnCtx {
        role: Frontend::Mcp,
        client_label: None,
        conn_id: 1,
        out: None,
    }
}

/// One JSON-RPC request on `conn`; the whole parsed reply.
fn request_on(srv: &McpServer, conn: &ConnCtx, method: &str, params: JsonValue) -> JsonValue {
    let line = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let reply = srv
        .handle_on(conn, &line.to_string())
        .unwrap_or_else(|| panic!("a reply to {method}"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// One `tools/call` on `conn`; the whole parsed reply.
fn call(srv: &McpServer, conn: &ConnCtx, name: &str, arguments: JsonValue) -> JsonValue {
    request_on(
        srv,
        conn,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

/// The `connection_id` an `initialize` on `conn` echoes, as a string; panics when
/// the reply carries anything else.
fn initialize_id(srv: &McpServer, conn: &ConnCtx) -> String {
    let reply = request_on(srv, conn, "initialize", json!({}));
    reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize carries no string connection_id: {reply}"))
        .to_string()
}

/// AC18: the primary and the web server each hand their first agent connection
/// `conn_id` 1 and share one audit ring; the connection id on the two ring
/// entries, and in the two `initialize` replies, must still differ.
///
/// Both servers' connection is the same `ConnCtx` shape (agent, `conn_id` 1), so
/// the only thing that can tell the two apart is the per-server salt. With no
/// salt both would render `conn_..-1` and every `assert_ne!` below would fail.
#[test]
fn governed_servers_sharing_a_ring_never_share_an_id() {
    let rig = rig("shared-ring");
    let on_primary = first_agent_connection();
    let on_web = first_agent_connection();
    assert_eq!(
        (on_primary.conn_id, on_web.conn_id),
        (1, 1),
        "the setup: both servers' first connection carries the same conn_id"
    );

    // One audited call per server. `flow.list` is a `Read`, allowed under `Auto`.
    let primary_list = call(&rig.primary, &on_primary, "flow.list", json!({}));
    assert_eq!(
        primary_list["result"]["isError"],
        json!(false),
        "{primary_list}"
    );
    let web_list = call(&rig.web, &on_web, "flow.list", json!({}));
    assert_eq!(web_list["result"]["isError"], json!(false), "{web_list}");

    // The shared ring holds exactly the two lines (oldest first), so neither
    // server kept a ring of its own and `initialize` is not audited.
    let entries = rig.ring.recent(None, None);
    assert_eq!(entries.len(), 2, "one ring entry per server: {entries:?}");
    assert_eq!(
        entries
            .iter()
            .map(|e| e.command.as_str())
            .collect::<Vec<_>>(),
        ["flow.list", "flow.list"]
    );
    let (primary_entry, web_entry) = (&entries[0], &entries[1]);
    assert!(
        primary_entry.connection_id.is_some() && web_entry.connection_id.is_some(),
        "both lines come from a streaming connection, so both are attributed: {entries:?}"
    );
    assert_ne!(
        primary_entry.connection_id, web_entry.connection_id,
        "two servers, both conn_id 1, one ring: the lines must not share an id"
    );

    // The id each connection is told is the id its line carries, and the two
    // servers tell their connections different ids.
    let primary_id = initialize_id(&rig.primary, &on_primary);
    let web_id = initialize_id(&rig.web, &on_web);
    assert_ne!(
        primary_id, web_id,
        "the web server's initialize id must differ from the primary's"
    );
    assert_eq!(
        primary_entry.connection_id.as_deref(),
        Some(primary_id.as_str())
    );
    assert_eq!(web_entry.connection_id.as_deref(), Some(web_id.as_str()));
}
