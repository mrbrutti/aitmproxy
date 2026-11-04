//! `aitm web` exits on SIGTERM from every launch shape (spec
//! `docs/superpowers/specs/2026-11-03-web-sigterm-stdio-tty-design.md`, AC1 and
//! AC2; plan `docs/superpowers/plans/2026-11-03-web-sigterm-stdio-tty-plan.md`,
//! Task 2).
//!
//! The 0.5.18 acceptance recorded "`aitm web` does not exit on SIGTERM". The
//! signal handling was fine: `aitm web` served the default stdio MCP transport
//! on a **terminal** stdin from a **background process group**, so its first
//! `read(0)` stopped the whole group with SIGTTIN and SIGTERM stayed pending
//! until SIGKILL. Two hermetic tests on the real binary pin the fix:
//!
//! - **pty regression** (AC1): `aitm web` launched through a pseudo-terminal
//!   into a background job is never stopped (`ps` state not `T`), serves the
//!   web port and the operator bus pointer, logs the one `info` line that says
//!   the agent transport is withheld, and exits 0 within 1 s of SIGTERM with
//!   the port refusing and the pointer gone.
//! - **pipe parity** (AC2): the same `aitm web` with a held pipe stdin still
//!   serves the stdio transport (an `initialize` is answered on stdout), takes
//!   a `scope.add` over the operator bus, exits 0 within 2 s of SIGTERM, and
//!   leaves the `scope.add` record in the durable audit log.
//!
//! The terminal comes from `python3 -c` and the standard library's
//! `pty.fork()` (openpty + fork + `setsid` + controlling tty on macOS and
//! Linux), because the workspace lint that forbids unchecked FFI code reaches
//! this test target and a `libc::openpty` + `TIOCSCTTY` spike would need it
//! (spec D4). A missing `python3` **fails** the pty test; it never skips.
//!
//! Both tests bind loopback sockets and spawn the binary, so they run from the
//! Terminal panel and in CI, never in the coder sandbox. Nothing here prints a
//! token: failure messages pass the child's output through
//! [`mask_link_tokens`], and the minted operator token is read from the `0600`
//! config and used only on the loopback bus.

#[path = "support/scripted_driver.rs"]
#[allow(dead_code)]
mod scripted_driver;

use std::io::{BufRead, BufReader, Read, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The one `info` line `aitm web` logs when it withholds the stdio agent
/// transport from a terminal stdin (spec D2). A literal copy: a test binary
/// cannot import from the `aitm` bin target; AC4 pins the production const to
/// the same bytes.
const WEB_STDIO_TTY_NOTE: &str = "mcp.transport is stdio and stdin is a terminal; aitm web does not serve the agent transport on it (an MCP client hands aitm a pipe)";

/// The reporter's stdin-EOF note (AC-W1-32); never produced when the transport
/// was withheld (spec D3).
const STDIN_EOF_NOTE: &str = "stdin closed · stdio MCP transport ended";

/// The signal arm's log line in `run()`.
const SHUTDOWN_LINE: &str = "shutdown signal received";

/// Spawn → the web port accepts, with slack for a cold binary.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);

/// SIGTERM → exit with a terminal stdin: no blocked stdin read exists, so the
/// `shutdown_timeout(1 s)` returns at once (spec D6; measured 0.13 s).
const TTY_EXIT_BOUND: Duration = Duration::from_secs(1);

/// SIGTERM → exit with a held pipe stdin: the R14 1 s grace for the blocked
/// read plus teardown (spec D6; measured 1.15 s).
const PIPE_EXIT_BOUND: Duration = Duration::from_secs(2);

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The relay that gives `aitm web` a controlling terminal as stdin (spec D4;
/// the plan carries this program verbatim). `pty.fork()` does openpty + fork +
/// `setsid` + controlling tty; the child execs `bash -c <argv[1]>`; the parent
/// sets a real window size (a 0×0 pty would change the reporter's layout),
/// relays the master to its own stdout until the slave side closes, then exits
/// with bash's status.
const PTY_RELAY: &str = r#"import errno, fcntl, os, pty, struct, sys, termios
script = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "-c", script])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
while True:
    try:
        data = os.read(fd, 65536)
    except OSError as e:
        if e.errno == errno.EIO:
            break
        raise
    if not data:
        break
    os.write(1, data)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
"#;

/// AC1: `aitm web` with its controlling terminal as stdin, in a background
/// process group, is not stopped by SIGTTIN; it serves, logs the withheld-
/// transport note once, and SIGTERM ends it with status 0 within 1 s, the web
/// port refusing and the pointer gone.
///
/// Before the fix this fails at step (b): the process is in state `T`, stopped
/// at its first read of the terminal (research §5).
#[test]
fn web_on_a_terminal_in_a_background_group_is_not_stopped_and_exits_on_sigterm() {
    let _serial = serial();
    let dir = TempDir::new("tty");
    let ports = Ports::free();
    let config = write_config(dir.path(), &ports);
    let run_dir = dir.path().join("run").join("cores");

    let mut run = PtyRun::spawn(dir.path(), &run_dir, &config, ports.web);
    let pid_line = run.wait_for_line(STARTUP_TIMEOUT, |l| l.starts_with("PID "));
    let pid = parse_pid(&pid_line);
    run.aitm_pid = Some(pid);

    assert!(
        wait_until(STARTUP_TIMEOUT, || accepting(&ports.web)),
        "the web port never accepted:\n{}",
        run.output()
    );

    // (b) Not stopped. Three checks 100 ms apart: a background group's tty
    // read raises SIGTTIN at once, so a stopped process shows `T` here.
    for _ in 0..3 {
        let stat = ps_stat(pid);
        assert!(
            !stat.is_empty(),
            "aitm web (pid {pid}) is gone before the signal:\n{}",
            run.output()
        );
        assert!(
            !stat.starts_with('T'),
            "aitm web (pid {pid}) is stopped (ps stat \"{stat}\"): its stdin read raised SIGTTIN from the background process group (spec AC1 b)\n{}",
            run.output()
        );
        thread::sleep(Duration::from_millis(100));
    }

    // (c) The pointer is written once the operator bus has bound.
    let pointer = pointer_path(&run_dir, pid);
    assert!(
        wait_until(Duration::from_secs(2), || pointer.exists()),
        "no pointer at {}:\n{}",
        pointer.display(),
        run.output()
    );

    // (d) SIGTERM ends it with status 0 within the bound.
    let sent = Instant::now();
    kill(pid, "TERM");
    let exit_line = run.wait_for_line(TTY_EXIT_BOUND, |l| l.starts_with("EXIT "));
    let elapsed = sent.elapsed();
    assert_eq!(
        exit_line,
        "EXIT 0",
        "aitm web did not exit 0 after SIGTERM:\n{}",
        run.output()
    );
    assert!(
        elapsed <= TTY_EXIT_BOUND,
        "aitm web took {elapsed:?} to exit after SIGTERM; the bound is 1 s:\n{}",
        run.output()
    );

    // (e) The web port refuses; (f) the pointer is gone.
    assert!(
        wait_until(Duration::from_millis(500), || !accepting(&ports.web)),
        "the web port {} still accepts after exit:\n{}",
        ports.web,
        run.output()
    );
    assert!(
        wait_until(Duration::from_secs(1), || !pointer.exists()),
        "the pointer {} survived the exit:\n{}",
        pointer.display(),
        run.output()
    );

    let status = run.wait_exit(Duration::from_secs(5));
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(0),
        "the pty relay did not exit 0 ({status:?}):\n{}",
        run.output()
    );
    run.settle();
    let joined = run.said().join("\n");

    // (a) The withheld-transport note; (g) the signal arm, and no EOF note.
    let notes = joined.matches(WEB_STDIO_TTY_NOTE).count();
    assert_eq!(
        notes,
        1,
        "the withheld-transport note {WEB_STDIO_TTY_NOTE:?} must appear exactly once (spec D2, G4); seen {notes} times:\n{}",
        mask_link_tokens(&joined)
    );
    assert!(
        joined.contains(SHUTDOWN_LINE),
        "the log lacks {SHUTDOWN_LINE:?}:\n{}",
        mask_link_tokens(&joined)
    );
    assert!(
        !joined.contains(STDIN_EOF_NOTE),
        "the stdin-EOF note appeared although no stdio transport was served:\n{}",
        mask_link_tokens(&joined)
    );
}

/// AC2: `aitm web` with a held pipe stdin keeps the stdio transport (an
/// `initialize` is answered on stdout), takes a `scope.add` over the operator
/// bus, exits 0 within 2 s of SIGTERM with the pipe still held, the web port
/// refusing and the pointer gone, and the `scope.add` record is in the durable
/// audit log. Green before and after the fix (spec D5).
#[test]
fn web_on_a_pipe_keeps_the_stdio_transport_and_exits_on_sigterm() {
    let _serial = serial();
    let dir = TempDir::new("pipe");
    let ports = Ports::free();
    let config = write_config(dir.path(), &ports);
    let run_dir = dir.path().join("run").join("cores");
    let audit_log = dir.path().join("audit").join("audit.jsonl");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aitm"));
    cmd.args(aitm_args(&config, ports.web));
    aitm_env(&mut cmd, dir.path(), &run_dir);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aitm");
    let pid = child.id();
    // Held until after the signal: the stdio transport's read stays blocked.
    let mut stdin = child.stdin.take().expect("piped stdin");
    let (rpc_tx, rpc_lines) = mpsc::channel();
    pump(child.stdout.take().expect("piped stdout"), rpc_tx);
    let (log_tx, log_lines) = mpsc::channel();
    pump(child.stderr.take().expect("piped stderr"), log_tx);
    let mut run = PipeRun {
        child,
        log_lines,
        seen: Vec::new(),
    };

    assert!(
        wait_until(STARTUP_TIMEOUT, || accepting(&ports.web)),
        "the web port never accepted:\n{}",
        run.output()
    );

    // (a) The stdio transport is served on the pipe.
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "web-sigterm-test", "version": "0"},
        },
    });
    stdin
        .write_all(format!("{initialize}\n").as_bytes())
        .expect("write initialize");
    stdin.flush().expect("flush initialize");
    let reply = rpc_reply(&rpc_lines, 1, Duration::from_secs(10)).unwrap_or_else(|| {
        panic!(
            "no stdout reply to initialize (id 1) within 10 s:\n{}",
            run.output()
        )
    });
    assert!(
        reply.get("result").is_some() && reply.get("error").is_none(),
        "initialize was not answered with a result: {reply}"
    );

    // (b) The operator bus takes a scope.add with the minted token.
    let pointer = pointer_path(&run_dir, pid);
    assert!(
        wait_until(Duration::from_secs(2), || pointer.exists()),
        "no pointer at {}:\n{}",
        pointer.display(),
        run.output()
    );
    let bus = bus_addr_from_pointer(&pointer);
    let token = token_in(&config).expect("the first run minted mcp.operator_token into the config");
    let added = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let mut c = scripted_driver::Client::connect(bus, &token).await?;
            c.initialize().await?;
            c.tool_call("scope.add", json!({"host": "example.test"}))
                .await
        });
    if let Err(e) = &added {
        panic!(
            "scope.add over the operator bus failed: {e:#}\n{}",
            run.output()
        );
    }

    // (c) SIGTERM with the pipe still held: status 0 within the bound.
    kill(pid, "TERM");
    let sent = Instant::now();
    let status = run.exits_within(PIPE_EXIT_BOUND);
    let elapsed = sent.elapsed();
    assert!(
        status.success(),
        "aitm web exited with {status} after SIGTERM; an orderly shutdown exits 0 (took {elapsed:?}):\n{}",
        run.output()
    );

    // (d) The web port refuses; (e) the pointer is gone.
    assert!(
        wait_until(Duration::from_millis(500), || !accepting(&ports.web)),
        "the web port {} still accepts after exit:\n{}",
        ports.web,
        run.output()
    );
    assert!(
        wait_until(Duration::from_secs(1), || !pointer.exists()),
        "the pointer {} survived the exit:\n{}",
        pointer.display(),
        run.output()
    );

    drop(stdin);
    run.settle();

    // (f) The control stream holds the scope.add; (g) no withheld note.
    assert!(
        audit_log.exists(),
        "the durable audit log {} does not exist after the exit:\n{}",
        audit_log.display(),
        run.output()
    );
    assert!(
        audit_lines_with(&audit_log, "\"command\":\"scope.add\"") >= 1,
        "no scope.add record in {}:\n{}",
        audit_log.display(),
        run.output()
    );
    let log = run.said().join("\n");
    assert!(
        !log.contains(WEB_STDIO_TTY_NOTE),
        "a pipe stdin must keep the stdio transport, yet the log says it was withheld:\n{}",
        mask_link_tokens(&log)
    );
}

// ---------------------------------------------------------------------------
// The pty harness (AC1).
// ---------------------------------------------------------------------------

/// `python3 -I -c PTY_RELAY <bash line>`: bash runs `aitm web` as a background
/// job (`set -m`, its own process group) with the pty as stdin, prints the pid,
/// waits, and prints the exit status. The relayed pty carries aitm's stderr
/// (the reporter, the ready card and the `info` tracing lines).
struct PtyRun {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
    /// The `aitm` pid once `PID <n>` was read; killed on drop so a failed run
    /// leaks nothing (a stopped process still dies to SIGKILL).
    aitm_pid: Option<u32>,
}

impl PtyRun {
    fn spawn(home: &Path, run_dir: &Path, config: &Path, web: SocketAddr) -> Self {
        let bash_line = format!(
            "set -m; {aitm} --config {config} web --no-open --listen {web} <&0 & echo PID $!; wait $!; echo EXIT $?",
            aitm = shell_quote(env!("CARGO_BIN_EXE_aitm")),
            config = shell_quote(&config.to_string_lossy()),
        );
        let mut cmd = Command::new("python3");
        cmd.args(["-I", "-c", PTY_RELAY, &bash_line]);
        aitm_env(&mut cmd, home, run_dir);
        let mut child = match cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => panic!(
                "python3 is required on PATH for the pty regression test (spec D4); it was not found"
            ),
            Err(e) => panic!("spawn python3: {e}"),
        };
        let (tx, lines) = mpsc::channel();
        pump(child.stdout.take().expect("piped stdout"), tx.clone());
        pump(child.stderr.take().expect("piped stderr"), tx);
        Self {
            child,
            lines,
            seen: Vec::new(),
            aitm_pid: None,
        }
    }

    /// Reads lines until one satisfies `pred`, bounded by `timeout`; a relay
    /// that exits or goes quiet first fails the test with everything it said.
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
                    panic!(
                        "the pty relay produced no matching line within {timeout:?} (exited: {exited:?}):\n{}",
                        self.output()
                    );
                }
            }
        }
    }

    /// Polls for the relay's exit status up to `timeout`.
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

    /// Takes in the lines still in flight once the relay has exited.
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

    /// Everything relayed so far, raw, one entry per line.
    fn said(&mut self) -> Vec<String> {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.clone()
    }

    /// [`PtyRun::said`] joined for a failure message, every `#t=` link value
    /// masked: a message never prints a token.
    fn output(&mut self) -> String {
        mask_link_tokens(&self.said().join("\n"))
    }
}

impl Drop for PtyRun {
    fn drop(&mut self) {
        if let Some(pid) = self.aitm_pid {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `s` in single quotes for bash. Temp paths contain no `'`; one that did
/// would be a test bug, not a shape to escape around.
fn shell_quote(s: &str) -> String {
    assert!(!s.contains('\''), "a path with a single quote: {s:?}");
    format!("'{s}'")
}

/// The digits after `PID `.
fn parse_pid(line: &str) -> u32 {
    line.strip_prefix("PID ")
        .map(str::trim)
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("not a PID line: {line:?}"))
}

/// `ps -o stat= -p <pid>`, trimmed; empty when the pid is gone. The first
/// character `T` means stopped, on macOS and Linux alike.
fn ps_stat(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `kill -<signal> <pid>`.
fn kill(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([&format!("-{signal}"), &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

// ---------------------------------------------------------------------------
// The pipe harness (AC2).
// ---------------------------------------------------------------------------

/// `aitm web` spawned directly with a piped stdin; stderr (the log) is pumped
/// here, stdout (JSON-RPC only in stdio mode) into its own channel.
struct PipeRun {
    child: Child,
    log_lines: Receiver<String>,
    seen: Vec<String>,
}

impl PipeRun {
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

    /// The exit status within `timeout`; a child still running is killed and
    /// the test fails with what it said.
    fn exits_within(&mut self, timeout: Duration) -> ExitStatus {
        match self.wait_exit(timeout) {
            Some(status) => status,
            None => {
                let _ = self.child.kill();
                panic!(
                    "aitm web did not exit within 2 s of SIGTERM with a held pipe stdin:\n{}",
                    self.output()
                );
            }
        }
    }

    fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.log_lines.recv_timeout(remaining) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn said(&mut self) -> Vec<String> {
        while let Ok(line) = self.log_lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.clone()
    }

    fn output(&mut self) -> String {
        mask_link_tokens(&self.said().join("\n"))
    }
}

impl Drop for PipeRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The first stdout line that parses as JSON with `id == want`, within
/// `timeout`; notifications and other lines are skipped.
fn rpc_reply(lines: &Receiver<String>, want: u64, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(remaining) {
            Ok(line) => {
                if let Ok(value) = serde_json::from_str::<Value>(line.trim()) {
                    if value.get("id").and_then(Value::as_u64) == Some(want) {
                        return Some(value);
                    }
                }
            }
            Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

/// One `aitm` at a time in this test binary: free ports are chosen by
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
            "aitm-web-sigterm-{tag}-{}-{nanos}",
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

/// The addresses a config names. No bus port: the agent transport is stdio
/// and the operator bus is ephemeral (its address comes from the pointer).
struct Ports {
    /// `listen:`, the proxy.
    listen: SocketAddr,
    /// `browser.proxy_addr:`.
    browser: SocketAddr,
    /// `aitm web --listen`.
    web: SocketAddr,
}

impl Ports {
    /// Three distinct loopback ports nothing listens on right now, held until
    /// every one is chosen so no two are the same. Binds sockets.
    fn free() -> Self {
        let held: Vec<TcpListener> = (0..3)
            .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port"))
            .collect();
        let addrs: Vec<SocketAddr> = held
            .iter()
            .map(|listener| listener.local_addr().expect("local addr"))
            .collect();
        Self {
            listen: addrs[0],
            browser: addrs[1],
            web: addrs[2],
        }
    }
}

/// Writes `<dir>/config.yaml`: the listeners on `ports`, a scratch CA dir and
/// CA audit log, the durable MCP audit log under `<dir>/audit`, and a browser
/// engine that does not exist (a missing engine only warns). No
/// `mcp.transport` (the default is stdio) and no `operator_token` (the first
/// run mints it).
fn write_config(dir: &Path, ports: &Ports) -> PathBuf {
    let yaml = format!(
        "listen: {listen}\n\
         ca:\n  dir: \"{ca}\"\n  audit_log: \"{ca_audit}\"\n\
         mcp:\n  audit_log: \"{audit}\"\n\
         browser:\n  proxy_addr: {browser}\n  obscura:\n    binary: \"{obscura}\"\n",
        listen = ports.listen,
        ca = dir.join("ca").display(),
        ca_audit = dir.join("ca-audit.jsonl").display(),
        audit = dir.join("audit").join("audit.jsonl").display(),
        browser = ports.browser,
        obscura = dir.join("no-such-obscura").display(),
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

/// The hermetic environment both tests share: cleared, then `PATH` (the
/// test's own, so `bash` and `python3` resolve), `RUST_LOG=info` (puts the
/// `info` lines on stderr), `HOME` and `XDG_CONFIG_HOME` in `home`,
/// `AITM_RUN_DIR` for the pointer, `AITM_LOG_FILE` inside the temp dir.
/// `AITM_AUDIT_LOG` and `AITM_OBSCURA*` stay unset.
fn aitm_env(cmd: &mut Command, home: &Path, run_dir: &Path) {
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("RUST_LOG", "info")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("AITM_RUN_DIR", run_dir)
        .env("AITM_LOG_FILE", home.join("aitm.log"));
}

/// `--config <config> web --no-open --listen <web>`.
fn aitm_args(config: &Path, web: SocketAddr) -> Vec<String> {
    vec![
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
        "web".to_string(),
        "--no-open".to_string(),
        "--listen".to_string(),
        web.to_string(),
    ]
}

/// `<run_dir>/<pid>.json`, the core pointer (R14 D4).
fn pointer_path(run_dir: &Path, pid: u32) -> PathBuf {
    run_dir.join(format!("{pid}.json"))
}

/// The `"bus"` field of the pointer file (keys
/// `v,pid,bus,operator,config,started_unix,version`).
fn bus_addr_from_pointer(path: &Path) -> SocketAddr {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read pointer {}: {e}", path.display()));
    let value: Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|e| panic!("pointer {} is not JSON: {e}", path.display()));
    value
        .get("bus")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("pointer {} has no bus address", path.display()))
}

/// The `operator_token:` value in `config`, as the first run minted it
/// (`  operator_token: <64 hex>`, unquoted).
fn token_in(config: &Path) -> Option<String> {
    let text = std::fs::read_to_string(config).expect("read config");
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("operator_token:"))
        .map(|v| v.trim().to_string())
}

/// Lines of `path` containing `needle`; 0 when the file is missing.
fn audit_lines_with(path: &Path, needle: &str) -> usize {
    std::fs::read_to_string(path)
        .map(|text| text.lines().filter(|l| l.contains(needle)).count())
        .unwrap_or(0)
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

/// Forwards `reader`'s lines to `tx` on a thread until the pipe closes. A pty
/// with ONLCR ends lines `\r\n`, so the `\r` is trimmed too.
fn pump(reader: impl Read + Send + 'static, tx: Sender<String>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let line = strip_ansi(line.trim_end_matches('\r'));
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

/// Drops ANSI escape sequences (`ESC [ … <letter>`): the tracing subscriber
/// colours its output into a pty.
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

/// Polls `check` every 50 ms until it holds or `timeout` passes.
fn wait_until(timeout: Duration, check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        thread::sleep(POLL_INTERVAL);
    }
    check()
}
