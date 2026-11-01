//! The durable audit log, through the real `aitm` binary (spec
//! `docs/superpowers/specs/2026-10-31-durable-audit-design.md`, Design 3, 4, 10
//! and 14.4; AC31, AC36, AC37, AC58).
//!
//! Three of the four tests bind loopback sockets (the proxy, the browser's
//! proxy, the agent bus and, for `aitm web`, the UI) and so run from the
//! Terminal panel, not the Bash sandbox: `sigterm_flushes_a_real_boot`,
//! `a_healthy_boot_says_one_line_and_never_the_token` and
//! `the_generated_operator_bridge_token_never_reaches_disk`. The fourth,
//! `an_explicit_bad_path_fails_the_boot_loudly`, binds nothing: the binary fails
//! before any port is bound, and the test gives it addresses it never needs.
//!
//! Every spawn runs under a scratch directory: the environment is cleared, then
//! `PATH`, `RUST_LOG=info`, and `HOME` and `XDG_CONFIG_HOME` (the scratch
//! directory) are set, so no ambient `*_TOKEN` variable of the test host can add
//! a registration or a warning line, and the operator's real config directory is
//! never read or written. The config names a scratch `ca.dir` and `ca.audit_log`,
//! a browser engine that does not exist (the binary only warns), and a
//! loopback-TCP bus (never stdio: with stdin at EOF a stdio MCP arm ends the
//! `select!` and the process exits at once).
//!
//! No token is printed by a failure message: the child's output is shown with
//! every `#t=` link value masked, and a file that leaks is named, not quoted.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use futures::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// Spawn to a line the child must print, or to every listener accepting.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);

/// One reply on the bus, or one WebSocket handshake.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The spec's bound on `aitm` exiting after SIGTERM (AC31).
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the test waits for a boot that must fail. AC37 says it fails within 5
/// s, and it does so in milliseconds (before any port is bound); twice that keeps
/// a loaded machine from failing the test on the clock.
const FAILED_BOOT_TIMEOUT: Duration = Duration::from_secs(10);

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// `TOKEN-CANARY-8841` (AC36): the loopback bus token the healthy boot must
/// never say or write. Made up.
const CANARY_TOKEN: &str = "TOKEN-CANARY-8841";

/// The loopback bus token of the other tests. Made up.
const BUS_TOKEN: &str = "audit-binary-test-bus-token";

/// `mcp.operator_token` in the AC58 run (64 hex digits). Made up.
const MCP_OPERATOR_TOKEN: &str = "58a0c0ffee00112233445566778899aabbccddeeff00112233445566778899ab";

/// The web agent bridge token (`aitm web --token`) in the AC58 run (64 hex
/// digits). Made up.
const WEB_AGENT_TOKEN: &str = "58b1d1ffee11223344556677889900bbccddeeff11223344556677889900bbcd";

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// AC37 (no socket is bound): an explicit `mcp.audit_log` that cannot be used
/// fails the boot before any listener exists. The path sits under a regular
/// file, so no directory can be created for it.
#[test]
fn an_explicit_bad_path_fails_the_boot_loudly() {
    let dir = TempDir::new("badpath");
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"a regular file where a directory is needed").expect("write file");
    let bad = blocker.join("audit.jsonl");
    // Nothing is bound on the passing path, so no port is reserved.
    let config = write_config(dir.path(), &Ports::unbound(), &bad, BUS_TOKEN, None);

    let mut aitm = Aitm::spawn(dir.path(), &config, &[]);
    let Some(status) = aitm.wait_exit(FAILED_BOOT_TIMEOUT) else {
        let _ = aitm.child.kill();
        panic!(
            "the child did not exit within {FAILED_BOOT_TIMEOUT:?}:\n{}",
            aitm.output()
        );
    };
    aitm.settle();
    let output = aitm.output();
    assert!(
        !status.success(),
        "a bad explicit audit path must fail the boot, but the child exited {status}:\n{output}"
    );
    let path = bad.display().to_string();
    assert!(
        output.contains(&path),
        "output does not contain {path}:\n{output}"
    );
    assert!(
        !output.contains("proxy listening"),
        "the child said `proxy listening` although the boot had to fail first:\n{output}"
    );
}

/// AC31 `[socket]`: the real binary, an agent on the loopback bus, then SIGTERM.
/// The process exits within 10 s and the three files hold exactly what the
/// session did: the two reads, the refused `agent.set`, and a control file with
/// only its start marker.
#[test]
fn sigterm_flushes_a_real_boot() {
    let _serial = serial();
    let dir = TempDir::new("sigterm");
    let audit_dir = dir.path().join("audit");
    let ports = Ports::free();
    let config = write_config(
        dir.path(),
        &ports,
        &audit_dir.join("audit.jsonl"),
        BUS_TOKEN,
        None,
    );
    let mut aitm = Aitm::spawn(dir.path(), &config, &[]);
    wait_for_listeners(&mut aitm, &[ports.listen, ports.bus]);

    let mut bus = Bus::connect(ports.bus, BUS_TOKEN);
    let init = bus.request("initialize", initialize_params());
    assert_eq!(init["result"]["role"], "agent", "initialize reply: {init}");
    bus.call("flow.list", json!({}));
    bus.call("proxy.status", json!({}));
    let refused = bus.call("agent.set", json!({"policy": "auto"}));
    assert!(
        refused.get("error").is_some() || refused["result"]["isError"] == true,
        "an agent must be refused agent.set: {refused}"
    );

    aitm.signal("TERM");
    let status = aitm.exits_within(EXIT_TIMEOUT, "SIGTERM");
    assert!(
        status.success(),
        "aitm exited with {status} after SIGTERM; an orderly shutdown exits 0:\n{}",
        aitm.output()
    );

    let reads = read_stream(&audit_dir.join("audit.reads.jsonl"), "the reads file");
    assert_eq!(
        entry_commands(&reads),
        ["flow.list", "proxy.status"],
        "the reads file holds the two reads, in order"
    );
    for entry in entries(&reads) {
        assert_eq!(entry["origin"], "mcp", "a read over the agent bus: {entry}");
    }
    assert_start_marker_first(&reads, "reads");

    let agent = read_stream(&audit_dir.join("audit.agent.jsonl"), "the agent file");
    assert_eq!(
        entry_commands(&agent),
        ["agent.set"],
        "the agent file holds exactly the refused agent.set"
    );
    let refused_entry = entries(&agent)[0];
    assert_eq!(refused_entry["origin"], "mcp", "{refused_entry}");
    assert!(
        refused_entry["result"]["error"].is_string(),
        "the refused agent.set is recorded with an error result: {refused_entry}"
    );
    assert_start_marker_first(&agent, "agent");

    let control = read_stream(&audit_dir.join("audit.jsonl"), "the control file");
    assert_eq!(
        control.len(),
        1,
        "the control file holds only its start marker, got {} lines",
        control.len()
    );
    assert_start_marker_first(&control, "control");
}

/// AC36 `[socket]`: a healthy boot says one line about the audit log (its file),
/// and neither the output nor any of the three files ever holds the bus token.
#[test]
fn a_healthy_boot_says_one_line_and_never_the_token() {
    let _serial = serial();
    let dir = TempDir::new("oneline");
    let audit_dir = dir.path().join("audit");
    let control_path = audit_dir.join("audit.jsonl");
    let ports = Ports::free();
    let config = write_config(dir.path(), &ports, &control_path, CANARY_TOKEN, None);
    let mut aitm = Aitm::spawn(dir.path(), &config, &[]);
    wait_for_listeners(&mut aitm, &[ports.listen, ports.bus]);

    let mut bus = Bus::connect(ports.bus, CANARY_TOKEN);
    let init = bus.request("initialize", initialize_params());
    assert_eq!(init["result"]["role"], "agent", "initialize reply: {init}");
    for _ in 0..20 {
        bus.call("flow.list", json!({}));
    }

    aitm.signal("TERM");
    let status = aitm.exits_within(EXIT_TIMEOUT, "SIGTERM");
    assert!(
        status.success(),
        "aitm exited with {status} after SIGTERM:\n{}",
        aitm.output()
    );
    aitm.settle();

    let control = control_path.display().to_string();
    let lines = aitm.said();
    let about_the_audit: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains("aitm::audit") || line.contains(&control))
        .collect();
    assert_eq!(
        about_the_audit.len(),
        1,
        "a healthy boot says exactly one line about the audit log, got {}:\n{}",
        about_the_audit.len(),
        aitm.output()
    );
    assert!(
        lines.iter().any(|line| line.contains(&control)),
        "the line names the control file {control}:\n{}",
        aitm.output()
    );
    assert!(
        !lines.iter().any(|line| line.contains(CANARY_TOKEN)),
        "the child's output carries the bus token"
    );

    let leaking = files_containing(&audit_dir, &[("the bus token", CANARY_TOKEN)]);
    assert!(
        leaking.is_empty(),
        "the bus token reached the audit directory: {leaking:?}"
    );
    for name in ["audit.jsonl", "audit.agent.jsonl", "audit.reads.jsonl"] {
        assert!(
            audit_dir.join(name).is_file(),
            "{name} is one of the three files a boot creates"
        );
    }
}

/// AC58 `[socket]`: `aitm web` with an operator token configured. The per-run
/// operator bridge token is read from the operator link on stdout, used over the
/// real `/bus` as the operator, and, with the web agent token, in a host name.
/// After SIGTERM none of the operator bridge token, the web agent token or
/// `mcp.operator_token` is in any file of the audit directory, yet the control
/// file has the operator's entry, written and masked.
#[test]
fn the_generated_operator_bridge_token_never_reaches_disk() {
    let _serial = serial();
    let dir = TempDir::new("bridge");
    let audit_dir = dir.path().join("audit");
    let ports = Ports::free();
    let config = write_config(
        dir.path(),
        &ports,
        &audit_dir.join("audit.jsonl"),
        BUS_TOKEN,
        Some(MCP_OPERATOR_TOKEN),
    );
    let listen = ports.web.to_string();
    let mut aitm = Aitm::spawn(
        dir.path(),
        &config,
        &[
            "web",
            "--no-open",
            "--listen",
            &listen,
            "--token",
            WEB_AGENT_TOKEN,
        ],
    );
    // `web::startup_summary` prints the operator link on stdout:
    // `  Operator   http://<bound>/#t=<operator bridge token>&expect=operator`.
    let link = aitm.wait_for_line(STARTUP_TIMEOUT, |line| {
        line.trim_start().starts_with("Operator") && line.contains("#t=")
    });
    let bridge_token = fragment_token(&link);
    assert_eq!(
        bridge_token.len(),
        64,
        "the operator bridge token is 64 hex characters"
    );
    assert!(
        bridge_token != MCP_OPERATOR_TOKEN && bridge_token != WEB_AGENT_TOKEN,
        "the operator bridge token is a fresh per-run token, not one of the configured ones"
    );
    wait_for_listeners(&mut aitm, &[ports.web]);

    // The operator names the bridge token in a host; a refused or failed call is
    // still audited, so whether `scope.add` accepts the label does not matter.
    ws_call(
        ports.web,
        &bridge_token,
        "operator",
        "scope.add",
        json!({"host": format!("{bridge_token}.example.test")}),
    );
    ws_call(
        ports.web,
        WEB_AGENT_TOKEN,
        "agent",
        "scope.add",
        json!({"host": format!("{WEB_AGENT_TOKEN}.example.test")}),
    );

    aitm.signal("TERM");
    let status = aitm.exits_within(EXIT_TIMEOUT, "SIGTERM");
    assert!(
        status.success(),
        "aitm exited with {status} after SIGTERM:\n{}",
        aitm.output()
    );

    let leaking = files_containing(
        &audit_dir,
        &[
            ("the operator bridge token", bridge_token.as_str()),
            ("the web agent token", WEB_AGENT_TOKEN),
            ("mcp.operator_token", MCP_OPERATOR_TOKEN),
        ],
    );
    assert!(
        leaking.is_empty(),
        "a token reached the audit directory: {leaking:?}"
    );

    let control = read_stream(&audit_dir.join("audit.jsonl"), "the control file");
    let masked: Vec<&Value> = entries(&control)
        .into_iter()
        .filter(|entry| {
            entry["args"]
                .as_str()
                .is_some_and(|args| args.contains("[redacted].example.test"))
        })
        .collect();
    assert!(
        !masked.is_empty(),
        "the control file has no entry whose args contain `[redacted].example.test`; \
         its entries are {:?}",
        entry_commands(&control)
    );
    assert_eq!(masked[0]["command"], "scope.add", "{}", masked[0]);
    assert_eq!(masked[0]["origin"], "operator", "{}", masked[0]);
}

// ---------------------------------------------------------------------------
// The audit files
// ---------------------------------------------------------------------------

/// Every line of `path`, parsed. `what` names the file in the failure message
/// (a line is never quoted: it may carry what the test is looking for).
fn read_stream(path: &Path, what: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "{what} does not exist or is unreadable ({}): {e}",
            path.display()
        )
    });
    text.lines()
        .enumerate()
        .map(|(n, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{what}, line {}, is not JSON: {e}", n + 1))
        })
        .collect()
}

/// The lines that are entries (marker lines have no `command` key).
fn entries(lines: &[Value]) -> Vec<&Value> {
    lines
        .iter()
        .filter(|line| line.get("command").is_some())
        .collect()
}

/// The `command` of every entry line, in file order.
fn entry_commands(lines: &[Value]) -> Vec<String> {
    entries(lines)
        .iter()
        .map(|entry| entry["command"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The file's first line is the writer's `start` marker for `stream`.
fn assert_start_marker_first(lines: &[Value], stream: &str) {
    let first = lines.first().expect("a file with a start marker");
    assert_eq!(first["marker"], "start", "first line of the {stream} file");
    assert_eq!(first["stream"], stream, "first line of the {stream} file");
}

/// The names of the files directly under `dir` that contain any of `secrets`
/// (label, value), each as `<file>: <label>`. Never the value itself.
fn files_containing(dir: &Path, secrets: &[(&str, &str)]) -> Vec<String> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the audit directory {} is unreadable: {e}", dir.display()));
    for entry in entries.flatten() {
        let bytes = std::fs::read(entry.path()).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        for (label, secret) in secrets {
            if text.contains(secret) {
                found.push(format!("{}: {label}", entry.file_name().to_string_lossy()));
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------
// The agent bus (loopback TCP) and the web bus (WebSocket)
// ---------------------------------------------------------------------------

/// `initialize` parameters.
fn initialize_params() -> Value {
    json!({"protocolVersion": "2025-06-18", "capabilities": {},
           "clientInfo": {"name": "audit-binary-test", "version": "0"}})
}

/// A request line for `method`.
fn rpc_line(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// One loopback-TCP bus connection: the token line, then one request line and
/// one reply line at a time.
struct Bus {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
}

impl Bus {
    fn connect(addr: SocketAddr, token: &str) -> Self {
        let stream = TcpStream::connect_timeout(&addr, REPLY_TIMEOUT).expect("connect to the bus");
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .expect("read timeout");
        let writer = stream.try_clone().expect("clone the bus socket");
        let mut bus = Self {
            reader: BufReader::new(stream),
            writer,
            next_id: 1,
        };
        bus.send(&json!({ "token": token }).to_string());
        bus
    }

    fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .expect("write to the bus");
        self.writer.flush().expect("flush the bus");
    }

    /// Sends `method` and returns the reply that carries its id (a
    /// notification in between is skipped).
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&rpc_line(id, method, params));
        loop {
            let mut line = String::new();
            let read = self
                .reader
                .read_line(&mut line)
                .unwrap_or_else(|e| panic!("no reply to {method} within {REPLY_TIMEOUT:?}: {e}"));
            assert!(read > 0, "the bus closed before the reply to {method}");
            let reply: Value = serde_json::from_str(line.trim_end()).expect("a bus reply is JSON");
            if reply["id"] == id {
                return reply;
            }
        }
    }

    /// `tools/call name arguments`.
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name": name, "arguments": arguments}))
    }
}

/// One `tools/call` over the real `/bus` WebSocket of `aitm web` at `addr`,
/// authenticated with `token`, whose `initialize` reply must name `role`.
/// Returns the reply to the call.
fn ws_call(addr: SocketAddr, token: &str, role: &str, name: &str, arguments: Value) -> Value {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the WebSocket legs");
    runtime.block_on(async {
        tokio::time::timeout(REPLY_TIMEOUT, async {
            let (mut ws, _) = connect_async(format!("ws://{addr}/bus"))
                .await
                .expect("the /bus handshake");
            let first = json!({ "token": token }).to_string();
            ws.send(Message::text(first)).await.expect("send the token");
            let init = rpc_line(0, "initialize", initialize_params());
            ws.send(Message::text(init)).await.expect("send initialize");
            let init = ws_reply(&mut ws, 0).await;
            assert_eq!(init["result"]["role"], role, "initialize reply: {init}");
            let call = rpc_line(
                1,
                "tools/call",
                json!({"name": name, "arguments": arguments}),
            );
            ws.send(Message::text(call)).await.expect("send the call");
            let reply = ws_reply(&mut ws, 1).await;
            let _ = ws.close(None).await;
            reply
        })
        .await
        .unwrap_or_else(|_| panic!("no reply from /bus within {REPLY_TIMEOUT:?}"))
    })
}

/// The next text frame whose `id` is `id`.
async fn ws_reply<S>(ws: &mut S, id: u64) -> Value
where
    S: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                let frame: Value = serde_json::from_str(&text).expect("a bus frame is JSON");
                if frame["id"] == id {
                    return frame;
                }
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("websocket error while waiting for reply {id}: {e}"),
            None => panic!("the bus closed before reply {id}"),
        }
    }
}

/// The token of an operator link `http://<addr>/#t=<token>&expect=operator`.
fn fragment_token(link: &str) -> String {
    let after = link
        .split("#t=")
        .nth(1)
        .expect("the operator line has a `#t=` fragment");
    after
        .split(|c: char| c == '&' || c.is_whitespace())
        .next()
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// The child process
// ---------------------------------------------------------------------------

/// One `aitm` at a time across the socket tests: their free ports are chosen by
/// bind-and-release, so two at once could race for one.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A fresh, empty directory under the OS temp dir (no `tempfile` crate in this
/// workspace); removed when the guard drops.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aitm-audit-binary-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The addresses a config names.
struct Ports {
    /// `listen:`, the proxy.
    listen: SocketAddr,
    /// `browser.proxy_addr:`.
    browser: SocketAddr,
    /// The loopback-TCP agent bus.
    bus: SocketAddr,
    /// `aitm web --listen`.
    web: SocketAddr,
}

impl Ports {
    /// Four distinct loopback ports nothing listens on right now. All four are
    /// held until every one is chosen, so no two are the same. Binds sockets.
    fn free() -> Self {
        let held: Vec<TcpListener> = (0..4)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port"))
            .collect();
        let addrs: Vec<SocketAddr> = held
            .iter()
            .map(|listener| listener.local_addr().expect("local addr"))
            .collect();
        Self {
            listen: addrs[0],
            browser: addrs[1],
            bus: addrs[2],
            web: addrs[3],
        }
    }

    /// Addresses for a boot that must fail before it binds anything; this binds
    /// nothing. The proxy's `listen` is in TEST-NET-1, which no interface holds,
    /// so a binary that got as far as binding it would fail on that address
    /// instead of on the audit path: the test can tell the order apart on a host
    /// that allows binds. The rest are ephemeral and never used.
    fn unbound() -> Self {
        let any: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        Self {
            listen: SocketAddr::from(([203, 0, 113, 1], 9)),
            browser: any,
            bus: any,
            web: any,
        }
    }
}

/// Writes the config `aitm` runs under, in `dir`: the listeners and the agent
/// bus on `ports`, a scratch CA directory and CA audit log, a browser engine that
/// does not exist (a missing engine only warns), `mcp.audit_log: audit_log`, and
/// `mcp.operator_token` when given. Tokens are quoted so a hex run is never read
/// as a number.
fn write_config(
    dir: &Path,
    ports: &Ports,
    audit_log: &Path,
    bus_token: &str,
    operator_token: Option<&str>,
) -> PathBuf {
    let operator = operator_token
        .map(|token| format!("  operator_token: \"{token}\"\n"))
        .unwrap_or_default();
    let yaml = format!(
        "listen: {listen}\n\
         ca:\n  dir: \"{ca}\"\n  audit_log: \"{ca_audit}\"\n\
         mcp:\n  transport:\n    loopback_tcp:\n      port: {bus_port}\n      token: \"{bus_token}\"\n\
         {operator}  audit_log: \"{audit}\"\n\
         browser:\n  proxy_addr: {browser}\n  obscura:\n    binary: \"{engine}\"\n",
        listen = ports.listen,
        ca = dir.join("ca").display(),
        ca_audit = dir.join("ca-audit.jsonl").display(),
        bus_port = ports.bus.port(),
        audit = audit_log.display(),
        browser = ports.browser,
        engine = dir.join("no-such-obscura").display(),
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

/// The `aitm` binary under test, its stdout and stderr pumped into one line
/// channel (the tracing subscriber writes to stdout).
struct Aitm {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Aitm {
    /// `aitm --config <config> <args…>` with a cleared environment: `PATH`,
    /// `RUST_LOG=info`, and `HOME` and `XDG_CONFIG_HOME` in `home`.
    fn spawn(home: &Path, config: &Path, args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_aitm"))
            .arg("--config")
            .arg(config)
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("RUST_LOG", "info")
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn aitm");
        let (tx, lines) = mpsc::channel();
        pump(child.stdout.take().expect("piped stdout"), tx.clone());
        pump(child.stderr.take().expect("piped stderr"), tx);
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Reads lines until one satisfies `pred`, bounded by `timeout`; a child that
    /// exits or goes quiet first fails the test with everything it said.
    fn wait_for_line(&mut self, timeout: Duration, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(remaining) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if pred(&line) {
                        return line;
                    }
                }
                Err(_) => {
                    let exited = self.wait_exit(Duration::from_secs(1));
                    let _ = self.child.kill();
                    panic!(
                        "aitm produced no matching line within {timeout:?} (exited: {exited:?}):\n{}",
                        self.output()
                    );
                }
            }
        }
    }

    /// `kill -<signal> <aitm pid>`.
    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([&format!("-{signal}"), &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(
            status.success(),
            "kill -{signal} {} failed",
            self.child.id()
        );
    }

    /// Polls for the exit status up to `timeout`.
    fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    /// The exit status within `timeout`; a child still running is killed and the
    /// test fails with what it said.
    fn exits_within(&mut self, timeout: Duration, after: &str) -> ExitStatus {
        match self.wait_exit(timeout) {
            Some(status) => status,
            None => {
                let _ = self.child.kill();
                panic!(
                    "aitm did not exit within {timeout:?} of {after}:\n{}",
                    self.output()
                );
            }
        }
    }

    /// Takes in the lines still in flight once the child has exited (its pipes
    /// close with it, which ends both pump threads).
    fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(remaining) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Everything the child has said so far, raw, one entry per line.
    fn said(&mut self) -> Vec<String> {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.clone()
    }

    /// [`Aitm::said`] joined for a failure message, every `#t=` link value
    /// masked: a message never prints a token.
    fn output(&mut self) -> String {
        mask_link_tokens(&self.said().join("\n"))
    }
}

impl Drop for Aitm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `text` with the value of every `#t=<value>` fragment replaced.
fn mask_link_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("#t=") {
        out.push_str(&rest[..at + 3]);
        rest = &rest[at + 3..];
        let end = rest
            .find(|c: char| c == '&' || c.is_whitespace())
            .unwrap_or(rest.len());
        out.push_str("<token>");
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Forwards `reader`'s lines to `tx` on a thread until the pipe closes.
fn pump(reader: impl Read + Send + 'static, tx: Sender<String>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(strip_ansi(&line)).is_err() {
                break;
            }
        }
    });
}

/// Drops ANSI escape sequences (`ESC [ … <letter>`): the tracing subscriber
/// colours its output even into a pipe.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A TCP connect to `addr` succeeds (the connection is dropped at once).
fn accepting(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
}

/// Waits until every address in `addrs` accepts a connection; a child that never
/// gets there fails the test with what it said.
fn wait_for_listeners(aitm: &mut Aitm, addrs: &[SocketAddr]) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if addrs.iter().all(accepting) {
            return;
        }
        if let Ok(Some(status)) = aitm.child.try_wait() {
            panic!(
                "aitm exited ({status}) before {addrs:?} accepted:\n{}",
                aitm.output()
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
    let _ = aitm.child.kill();
    panic!(
        "aitm listeners {addrs:?} never came up within {STARTUP_TIMEOUT:?}:\n{}",
        aitm.output()
    );
}
