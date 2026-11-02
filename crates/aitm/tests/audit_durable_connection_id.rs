//! The durable JSONL carries the server-assigned `connection_id` for an entry that
//! the real `McpServer::record_audit` produced (spec D1 and AC17).
//!
//! `aitm-ca`'s `durable_line_has_the_same_keys_as_to_value` renders a hand-built
//! entry, and `aitm-mcp`'s durable-sink test records into a stand-in sink, so
//! neither proves that an entry built by `record_audit`, written by the real
//! `FileAuditLog` sink, reaches the file with the same id the connection was told
//! in `initialize`. This does, through the assembled server (the one `aitm web`
//! and bare `aitm` serve), over a real file. In process: no socket is bound.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::tui::{self, TuiLog};
use aitm::wire::assemble;
use aitm_ca::{AuditLog, FileAuditLog};
use aitm_core::{AgentPolicy, Config, Frontend};
use aitm_mcp::{ConnCtx, McpServer};
use serde_json::{json, Value as JsonValue};

/// A fresh scratch directory name, unique per call.
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-durable-identity-{tag}-{nanos}-{n}"))
}

/// One JSON-RPC request on `conn`; the whole parsed reply.
fn request_on(srv: &McpServer, conn: &ConnCtx, method: &str, params: JsonValue) -> JsonValue {
    let line = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let reply = srv
        .handle_on(conn, &line.to_string())
        .unwrap_or_else(|| panic!("a reply to {method}"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// A streaming connection as a transport builds it: a minted `conn_id`, no sink.
fn streaming(srv: &McpServer, role: Frontend, label: Option<&str>) -> ConnCtx {
    ConnCtx {
        role,
        client_label: label.map(str::to_string),
        conn_id: srv.next_conn_id(),
        out: None,
    }
}

/// The id `initialize` hands `conn`; panics when it is not a string.
fn initialize_id(srv: &McpServer, conn: &ConnCtx) -> String {
    let reply = request_on(srv, conn, "initialize", json!({}));
    reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize carries no string connection_id: {reply}"))
        .to_string()
}

/// A successful `flow.list` (a `Read`, allowed under `Auto`) on `conn`.
fn list(srv: &McpServer, conn: &ConnCtx) {
    let reply = request_on(
        srv,
        conn,
        "tools/call",
        json!({"name": "flow.list", "arguments": {}}),
    );
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
}

/// Every audited call writes one durable line whose `connection_id` is the id the
/// connection's own `initialize` returned (a string), `null` for a call that came
/// over no streaming connection, and the file keeps the operator's line although
/// an agent cannot read it from the ring.
#[test]
fn the_durable_line_of_a_real_audited_call_carries_the_servers_connection_id() {
    let dir = scratch("log");
    let log_path = dir.join("audit.jsonl");
    let log = Arc::new(FileAuditLog::new(log_path.clone()));
    AuditLog::open(&*log).expect("the durable log opens");

    let mut cfg = Config::default();
    cfg.mcp.policy = AgentPolicy::Auto;
    cfg.ca.dir = scratch("ca");
    let assembled = assemble(&cfg).expect("assemble");
    let services = tui::services(
        &assembled.proxy,
        &cfg,
        None,
        TuiLog::Off,
        Arc::clone(&assembled.job_bus),
    );
    let srv = tui::server(&cfg, cfg.mcp.transport.clone(), &services);
    let srv = tui::with_shared_governance(srv, &assembled.agent_state, &assembled.audit_ring)
        .with_durable_audit(log.clone());
    let ring = &assembled.audit_ring;

    let agent = streaming(&srv, Frontend::Mcp, Some("aitm-mac"));
    let operator = streaming(&srv, Frontend::Operator, None);
    let anonymous = ConnCtx::new(Frontend::Mcp);
    let agent_id = initialize_id(&srv, &agent);
    let operator_id = initialize_id(&srv, &operator);
    assert_ne!(agent_id, operator_id);

    list(&srv, &agent);
    list(&srv, &operator);
    list(&srv, &anonymous);

    let text = std::fs::read_to_string(&log_path).expect("the durable log was written");
    let lines: Vec<JsonValue> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("every durable line is JSON"))
        .collect();
    assert_eq!(
        lines.len(),
        3,
        "one line per audited call, initialize is not audited: {text}"
    );
    assert_eq!(
        lines
            .iter()
            .map(|l| l["connection_id"].clone())
            .collect::<Vec<_>>(),
        [json!(agent_id), json!(operator_id), JsonValue::Null],
        "each line names the connection that made the call, null for none"
    );
    assert_eq!(
        lines
            .iter()
            .map(|l| l["origin"].clone())
            .collect::<Vec<_>>(),
        [json!("mcp"), json!("operator"), json!("mcp")]
    );
    assert_eq!(
        lines[0]["client_label"],
        json!("aitm-mac"),
        "the label and the id travel together in one line"
    );

    // The durable log is the complete record (the three lines above, the operator's
    // included). The agent's view of the ring is not.
    assert_eq!(
        ring.recent_for(Frontend::Mcp, None, None).len(),
        2,
        "an agent cannot read the operator's entry from the ring"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cfg.ca.dir);
}
