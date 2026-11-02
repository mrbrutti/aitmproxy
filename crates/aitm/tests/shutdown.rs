//! M2 Task 26 — M2-AC9, binary half: the `aitm` binary itself, sent SIGTERM
//! and (in a second run) SIGINT, exits in order and the obscura child it
//! spawned is gone within `stop_timeout`; no obscura process with this run's
//! ready-file remains. The driver half (`launch` / `close` / drop) is
//! `aitm-browser`'s `obscura_lifecycle.rs`.
//!
//! `[obscura]`: runs only with `AITM_OBSCURA=1` (the binary from
//! `AITM_OBSCURA_BIN`, else the discovery order); inert otherwise, so `cargo
//! test` stays hermetic:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura cargo test -p aitm --test shutdown
//! ```

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use aitm_core::ObscuraConfig;

/// Spawn → the `obscura started` line: the probe plus `start_timeout` (15 s),
/// with slack for a cold binary.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);

/// Spawn → every listener accepts, once the child is up.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The plan's bound on `aitm` exiting after the signal.
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// M2-AC9: SIGTERM ends `aitm` in order and reaps its obscura child.
#[test]
fn sigterm_reaps_obscura_child() {
    signal_reaps_child("TERM");
}

/// M2-AC9: the same for SIGINT, in a second `aitm` run.
#[test]
fn sigint_reaps_obscura_child() {
    signal_reaps_child("INT");
}

fn signal_reaps_child(signal: &str) {
    if !obscura_enabled() {
        return;
    }
    let _serial = serial();
    let dir = TempDir::new(signal);
    let (config, listeners) = write_config(dir.path());

    let mut aitm = Aitm::spawn(&config);
    let aitm_pid = aitm.child.id();

    let started = aitm.wait_for_line(STARTUP_TIMEOUT, |line| line.contains("obscura started"));
    let obscura_pid = parse_pid(&started);
    assert!(
        pid_alive(obscura_pid),
        "obscura {obscura_pid} is not alive after `obscura started`"
    );

    // `main` binds its listeners inside the same `select!` whose signal arm
    // installs the handlers, so once every listener accepts, a signal is
    // handled rather than left to its default action.
    assert!(
        wait_until(LISTEN_TIMEOUT, || listeners.iter().all(accepting)),
        "aitm listeners {listeners:?} never came up:\n{}",
        aitm.output()
    );

    aitm.signal(signal);
    let Some(status) = aitm.wait_exit(EXIT_TIMEOUT) else {
        let _ = aitm.child.kill();
        panic!(
            "aitm did not exit within {EXIT_TIMEOUT:?} of SIG{signal}:\n{}",
            aitm.output()
        );
    };
    assert!(
        status.success(),
        "aitm exited with {status} after SIG{signal}; an orderly shutdown exits 0:\n{}",
        aitm.output()
    );

    let budget = ObscuraConfig::default().stop_timeout + Duration::from_secs(1);
    assert!(
        wait_until(budget, || !pid_alive(obscura_pid)),
        "obscura {obscura_pid} still alive {budget:?} after aitm exited on SIG{signal}:\n{}",
        aitm.output()
    );

    let output = aitm.output();
    assert!(
        output.contains("shutdown signal received"),
        "aitm did not log the signal arm:\n{output}"
    );
    assert!(
        output.contains("obscura stopped"),
        "aitm did not log the graceful stop of its child:\n{output}"
    );

    // This run's ready-file is `aitm-obscura-<aitm pid>-<cdp port>.ready` under
    // the temp dir, and the child carries its path on `--ready-file`.
    let marker = format!("aitm-obscura-{aitm_pid}-");
    assert!(
        no_process_mentions(&marker),
        "an obscura child with ready-file {marker}* is still running"
    );
    assert!(
        !ready_file_exists(&marker),
        "ready-file {marker}* was left behind in {}",
        std::env::temp_dir().display()
    );
}

/// Run only when `AITM_OBSCURA=1` is set, so the default `cargo test` stays
/// hermetic.
fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (and AITM_OBSCURA_BIN) to run the obscura-backed test"
        );
        return false;
    }
    true
}

/// One `aitm` (and so one obscura) at a time across the two signal cases.
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
            "aitm-shutdown-{tag}-{}-{nanos}",
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

/// A loopback address nothing listens on right now (bind-and-release).
fn free_addr() -> SocketAddr {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .expect("free port")
}

/// Write the config `aitm` runs under: the main and browser listeners and the
/// MCP server on free loopback ports (loopback TCP so stdio is not consumed),
/// a temp CA dir and audit log, and the obscura binary from `AITM_OBSCURA_BIN`
/// when set. Returns the file and the three listener addresses.
fn write_config(dir: &Path) -> (PathBuf, [SocketAddr; 3]) {
    let listen = free_addr();
    let browser = free_addr();
    let mcp = free_addr();
    let mut yaml = format!(
        "listen: {listen}\n\
         ca:\n  dir: \"{ca}\"\n  audit_log: \"{audit}\"\n\
         mcp:\n  transport:\n    loopback_tcp:\n      port: {mcp_port}\n      token: shutdown-test\n\
         browser:\n  proxy_addr: {browser}\n",
        ca = dir.join("ca").display(),
        audit = dir.join("ca-audit.jsonl").display(),
        mcp_port = mcp.port(),
    );
    if let Some(binary) = std::env::var_os("AITM_OBSCURA_BIN") {
        yaml.push_str(&format!(
            "  obscura:\n    binary: \"{}\"\n",
            PathBuf::from(binary).display()
        ));
    }
    let path = dir.join("config.yaml");
    std::fs::write(&path, yaml).expect("write config");
    (path, [listen, browser, mcp])
}

/// The `aitm` binary under test, with its stdout and stderr pumped into one
/// line channel (the tracing subscriber writes to stdout).
struct Aitm {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Aitm {
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_aitm"))
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .env("AITM_AUDIT_LOG", "off")
            .env_remove("AITM_CONFIG")
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

    /// Read lines until one satisfies `pred`, bounded by `timeout`; a child
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
                    // The channel closes when the pipes do, a moment before
                    // the exit status is collectable; give it that moment.
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

    /// Poll for the exit status up to `timeout`.
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

    /// Everything the child has written so far, for assertions and diagnostics.
    fn output(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}

impl Drop for Aitm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Forward `reader`'s lines to `tx` on a thread until the pipe closes.
fn pump(reader: impl Read + Send + 'static, tx: Sender<String>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(strip_ansi(&line)).is_err() {
                break;
            }
        }
    });
}

/// Drop ANSI escape sequences (`ESC [ … <letter>`): the tracing subscriber
/// colours its output even into a pipe, which would split `pid=` in two.
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

/// The `pid=<n>` field of the `obscura started` line.
fn parse_pid(line: &str) -> u32 {
    let digits: String = line
        .split("pid=")
        .nth(1)
        .unwrap_or_else(|| panic!("no pid= field in {line:?}"))
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("pid= is not a number in {line:?}"))
}

/// `kill -0`: true while the pid exists (a reaped process no longer does).
fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A TCP connect to `addr` succeeds (the connection is dropped at once).
fn accepting(addr: &SocketAddr) -> bool {
    TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
}

/// Poll `check` every 50 ms until it holds or `timeout` passes.
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

/// No running process has `marker` in its command line (`pgrep` exits 1 when
/// nothing matches).
fn no_process_mentions(marker: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", marker])
        .output()
        .map(|o| !o.status.success() && o.stdout.is_empty())
        .unwrap_or(false)
}

/// A file whose name starts with `marker` exists in the OS temp dir.
fn ready_file_exists(marker: &str) -> bool {
    std::fs::read_dir(std::env::temp_dir())
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(marker))
        })
        .unwrap_or(false)
}
