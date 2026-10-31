//! The durable audit log is wired into every server this binary builds, in
//! process (spec Design 10; AC13, AC14 and AC15).
//!
//! The writer rides the shared `AuditRing`, so any server that shares the ring
//! is audited with no wiring of its own. These tests prove that for the servers
//! the binary builds, through the functions `main.rs` calls (`assemble`,
//! `tui::server`, `tui::with_shared_governance`, `tui::build_servers`), and that
//! the TUI's own in-process operator server, which keeps a private ring on
//! purpose, is not audited.
//!
//! No socket is bound: every call goes through `McpServer::handle_on` or the
//! `InProcessHandler`. The writer is attached with the production function
//! `aitm::audit_log::start_at(&assembled.audit_ring, &base, &ca_log, true)` on a
//! scratch directory (`start` needs a `Config` carrying an `mcp.audit_log` path
//! and is covered by `audit_log_config.rs`), never with
//! `McpServer::with_durable_audit`. `cfg.ca.dir` and `cfg.ca.audit_log` are
//! scratch paths too, so the operator's own directories are untouched, and the
//! handle's `shutdown` precedes every read of a file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use aitm::audit_log::{start_at, stream_path, AuditLogHandle, StreamKind};
use aitm::tui::{self, Services, TuiLog};
use aitm::wire::{assemble, Assembled};
use aitm_core::{AgentPolicy, Config, Frontend, McpTransport};
use aitm_mcp::{ConnCtx, McpServer};
use serde_json::{json, Value};

/// The most a shutdown is given to flush; every test asserts it finished.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);
/// The loopback transport's token. Made up; nothing is bound or served.
const LOOPBACK_TOKEN: &str = "audit-wiring-test-loopback-token";

/// A unique scratch directory that removes itself on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-audit-wiring-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One `assemble`, with the production writer attached to its audit ring.
struct Rig {
    cfg: Config,
    assembled: Assembled,
    handle: AuditLogHandle,
    /// The control stream's file; the other two sit beside it.
    base: PathBuf,
    /// Declared last so it is removed after everything above is dropped.
    _scratch: Scratch,
}

impl Rig {
    /// The agent transport is loopback TCP: `build_servers` serves an agent only
    /// on an addressable transport, and the other servers take it as a label.
    fn new(tag: &str) -> Rig {
        let scratch = Scratch::new(tag);
        let mut cfg = Config::default();
        cfg.mcp.policy = AgentPolicy::Auto;
        cfg.mcp.transport = McpTransport::LoopbackTcp {
            port: 0,
            token: LOOPBACK_TOKEN.into(),
            endpoint_file: None,
        };
        cfg.ca.dir = scratch.0.join("ca");
        cfg.ca.audit_log = scratch.0.join("ca-audit.jsonl");
        let assembled = assemble(&cfg).expect("assemble");
        let base = scratch.0.join("audit").join("audit.jsonl");
        let handle = start_at(&assembled.audit_ring, &base, &cfg.ca.audit_log, true)
            .expect("the writer starts on a scratch directory")
            .expect("an explicit start returns a handle");
        Rig {
            cfg,
            assembled,
            handle,
            base,
            _scratch: scratch,
        }
    }

    /// A fresh `Services` over the assembled proxy. `Services` is not `Clone`,
    /// so each consumer takes its own.
    fn services(&self) -> Services {
        tui::services(&self.assembled.proxy, &self.cfg, None, TuiLog::Off)
    }

    /// A server built the way `main.rs` builds its primary and its `aitm web`
    /// server: `tui::server` plus `tui::with_shared_governance`, nothing else.
    fn shared_server(&self) -> McpServer {
        tui::with_shared_governance(
            tui::server(&self.cfg, self.cfg.mcp.transport.clone(), &self.services()),
            &self.assembled.agent_state,
            &self.assembled.audit_ring,
        )
    }

    /// Flushes and stops the writer, then reads the three files back.
    fn finish(&self) -> Files {
        let report = self.handle.shutdown(SHUTDOWN_BUDGET);
        assert!(
            report.complete,
            "the writer did not flush in time: {report:?}"
        );
        Files::read(&self.base)
    }
}

/// Every parsed line of the three stream files.
struct Files {
    control: Vec<Value>,
    agent: Vec<Value>,
    reads: Vec<Value>,
}

impl Files {
    fn read(base: &Path) -> Files {
        let lines = |kind| read_lines(&stream_path(base, kind));
        Files {
            control: lines(StreamKind::Control),
            agent: lines(StreamKind::Agent),
            reads: lines(StreamKind::Reads),
        }
    }

    /// Each file opens with its own `start` marker (and so is never empty).
    fn assert_start_markers(&self) {
        for (kind, lines) in [
            (StreamKind::Control, &self.control),
            (StreamKind::Agent, &self.agent),
            (StreamKind::Reads, &self.reads),
        ] {
            let first = lines
                .first()
                .unwrap_or_else(|| panic!("the {} file is empty", kind.label()));
            assert_eq!(first["marker"], json!("start"), "{}: {first}", kind.label());
            assert_eq!(
                first["stream"],
                json!(kind.label()),
                "{}: {first}",
                kind.label()
            );
        }
    }
}

/// Each line of `path` parsed as JSON.
fn read_lines(path: &Path) -> Vec<Value> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    text.lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("a line of {} is not JSON ({error}): {line}", path.display())
            })
        })
        .collect()
}

/// The entry lines among `lines`: every line that is not a marker (a marker has
/// no `command`).
fn entries(lines: &[Value]) -> Vec<&Value> {
    lines
        .iter()
        .filter(|line| line.get("command").is_some())
        .collect()
}

/// One JSON-RPC request line.
fn rpc_line(method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
}

/// One `tools/call` request line.
fn call_line(name: &str, arguments: Value) -> String {
    rpc_line("tools/call", json!({"name": name, "arguments": arguments}))
}

/// The parsed reply to `line`.
fn parse_reply(reply: Option<String>, what: &str) -> Value {
    let reply = reply.unwrap_or_else(|| panic!("a reply to {what}"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// The whole parsed reply to one JSON-RPC request on `conn`.
fn request_on(srv: &McpServer, conn: &ConnCtx, method: &str, params: Value) -> Value {
    parse_reply(srv.handle_on(conn, &rpc_line(method, params)), method)
}

/// A streaming connection as a transport builds it: a minted `conn_id`, so the
/// server names it in `initialize` and in every audit line it makes.
fn streaming(srv: &McpServer, role: Frontend, label: Option<&str>) -> ConnCtx {
    let mut conn = ConnCtx::new(role);
    conn.conn_id = srv.next_conn_id();
    conn.client_label = label.map(str::to_string);
    conn
}

/// The id `initialize` hands `conn`; panics when it is not a string.
fn initialize_id(srv: &McpServer, conn: &ConnCtx) -> String {
    let reply = request_on(srv, conn, "initialize", json!({}));
    reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize carries no string connection_id: {reply}"))
        .to_string()
}

/// A tool call that must succeed (`result.isError` is `false`).
fn call_ok(srv: &McpServer, conn: &ConnCtx, name: &str, arguments: Value) {
    let reply = request_on(
        srv,
        conn,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    );
    assert_eq!(reply["result"]["isError"], json!(false), "{name}: {reply}");
}

/// AC13. A call made through a server `main.rs` builds reaches the file named
/// for its trust, carrying the id its own connection was told in `initialize`:
/// the operator's `agent.set` (Sensitive, evidence, trusted control) lands in
/// the control file, an agent's successful `flow.list` (a `Read`) in the reads
/// file, and nothing lands in the agent file. No `with_durable_audit` is used,
/// so the line can only have come through the ring.
#[test]
fn a_real_server_call_reaches_the_file_with_its_connection_id() {
    let rig = Rig::new("ac13");
    let srv = rig.shared_server();

    let operator = streaming(&srv, Frontend::Operator, None);
    let agent = streaming(&srv, Frontend::Mcp, Some("wiring-agent"));
    let operator_id = initialize_id(&srv, &operator);
    let agent_id = initialize_id(&srv, &agent);
    assert_ne!(operator_id, agent_id, "two connections, two ids");

    call_ok(&srv, &operator, "agent.set", json!({"policy": "auto"}));
    call_ok(&srv, &agent, "flow.list", json!({}));

    let files = rig.finish();
    files.assert_start_markers();

    let control = entries(&files.control);
    assert_eq!(control.len(), 1, "control file: {:?}", files.control);
    let set = control[0];
    assert_eq!(
        files.control.last(),
        Some(set),
        "the entry is the last line"
    );
    assert_eq!(set["command"], json!("agent.set"), "{set}");
    assert_eq!(set["origin"], json!("operator"), "{set}");
    assert_eq!(set["connection_id"], json!(operator_id), "{set}");
    assert_eq!(set["args"], json!(r#"{"policy":"auto"}"#), "{set}");
    assert_eq!(set["result"], json!("ok"), "{set}");

    let reads = entries(&files.reads);
    assert_eq!(reads.len(), 1, "reads file: {:?}", files.reads);
    let list = reads[0];
    assert_eq!(files.reads.last(), Some(list), "the entry is the last line");
    assert_eq!(list["command"], json!("flow.list"), "{list}");
    assert_eq!(list["origin"], json!("mcp"), "{list}");
    assert_eq!(list["connection_id"], json!(agent_id), "{list}");
    assert_eq!(list["client_label"], json!("wiring-agent"), "{list}");
    assert_eq!(list["args"], json!("{}"), "{list}");
    assert_eq!(list["result"], json!("ok"), "{list}");

    assert!(
        entries(&files.agent).is_empty(),
        "the agent made no evidence entry: {:?}",
        files.agent
    );
}

/// AC14. One writer on the ring audits every server that shares the ring: a
/// primary-shaped server, a web-shaped server, and the agent arm of
/// `tui::build_servers` over a loopback-TCP config (built over its own
/// `Services`, as `main.rs` does for each consumer). One `flow.list` on a
/// minted agent connection per server gives exactly three lines in the reads
/// file, each carrying the id its own connection was told, all distinct. A
/// design that attached the sink per server fails here as soon as one server is
/// skipped.
#[test]
fn every_server_this_binary_builds_is_audited() {
    let rig = Rig::new("ac14");
    let primary = rig.shared_server();
    let web = rig.shared_server();
    let (agent_arm, _tui_handler) =
        tui::build_servers(&rig.cfg, rig.services(), rig.assembled.governance());
    let agent_arm = agent_arm.expect("a loopback-TCP transport gets an agent server");

    let mut ids = Vec::new();
    for (name, srv) in [
        ("primary", &primary),
        ("web", &web),
        ("tui agent arm", &agent_arm),
    ] {
        let conn = streaming(srv, Frontend::Mcp, Some(name));
        ids.push(initialize_id(srv, &conn));
        call_ok(srv, &conn, "flow.list", json!({}));
    }
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        3,
        "three servers minted three distinct ids: {ids:?}"
    );

    let files = rig.finish();
    files.assert_start_markers();

    let reads = entries(&files.reads);
    assert_eq!(
        reads
            .iter()
            .map(|l| l["command"].clone())
            .collect::<Vec<_>>(),
        [json!("flow.list"), json!("flow.list"), json!("flow.list")],
        "reads file: {:?}",
        files.reads
    );
    assert_eq!(
        reads
            .iter()
            .map(|l| l["connection_id"].clone())
            .collect::<Vec<_>>(),
        ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
        "each line carries the id its own connection was told"
    );
    assert_eq!(
        reads
            .iter()
            .map(|l| l["client_label"].clone())
            .collect::<Vec<_>>(),
        [json!("primary"), json!("web"), json!("tui agent arm")],
        "and the label of the server that made it"
    );
    assert!(
        entries(&files.control).is_empty() && entries(&files.agent).is_empty(),
        "no other file holds an entry: control {:?}, agent {:?}",
        files.control,
        files.agent
    );
    assert_eq!(
        rig.assembled.audit_ring.len(),
        3,
        "the ring and the file agree"
    );
}

/// AC15 (guard). The TUI's in-process operator server is built by
/// `tui::server` alone and keeps a private ring on purpose, so the writer on
/// the shared ring never sees it: `tools/call` of `flow.list` and of
/// `agent.status` through the `InProcessHandler` leave all three files holding
/// only their `start` marker, and the shared ring empty. It is a guard: it
/// passes whether or not a writer is attached. That the writer is attached to
/// the shared ring is what AC13 and AC14, in this file, prove.
#[test]
fn the_tui_operator_server_stays_unaudited() {
    let rig = Rig::new("ac15");
    let ring = &rig.assembled.audit_ring;
    assert_eq!(ring.len(), 0, "nothing has been recorded yet");

    let (_agent_arm, handler) =
        tui::build_servers(&rig.cfg, rig.services(), rig.assembled.governance());
    for name in ["flow.list", "agent.status"] {
        let reply = parse_reply(handler(&call_line(name, json!({}))), name);
        assert_eq!(reply["result"]["isError"], json!(false), "{name}: {reply}");
    }

    let files = rig.finish();
    files.assert_start_markers();
    for (kind, lines) in [
        (StreamKind::Control, &files.control),
        (StreamKind::Agent, &files.agent),
        (StreamKind::Reads, &files.reads),
    ] {
        assert_eq!(
            lines.len(),
            1,
            "the {} file holds only its start marker: {lines:?}",
            kind.label()
        );
        assert!(entries(lines).is_empty(), "{}: {lines:?}", kind.label());
    }
    assert_eq!(ring.len(), 0, "the shared ring is unchanged");
}

/// Supplements AC35. No command the assembled registry offers is named
/// `audit.<something>`: the audit file has no reader over MCP (the spec's
/// non-goal), so there is nothing an agent could use to read it back. Every
/// name is read from the server's own `tools/list` reply, and the list is
/// shown to hold the commands the other tests call, so an empty or broken list
/// cannot pass.
#[test]
fn no_registered_command_name_starts_with_audit() {
    let rig = Rig::new("tools");
    let srv = rig.shared_server();
    let operator = ConnCtx::new(Frontend::Operator);

    let reply = request_on(&srv, &operator, "tools/list", json!({}));
    let tools = reply["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list carries a tools array: {reply}"));
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("every tool has a name"))
        .collect();

    for expected in ["agent.set", "agent.status", "flow.list"] {
        assert!(names.contains(&expected), "{expected} is listed: {names:?}");
    }
    let audit: Vec<&&str> = names
        .iter()
        .filter(|name| name.starts_with("audit."))
        .collect();
    assert!(audit.is_empty(), "no command is named audit.*: {audit:?}");
}
