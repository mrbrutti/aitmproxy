//! The real seeded target the live-proof tests run against, and the one HTTP
//! client they speak to it with.
//!
//! Both `tests/live_lane.rs` and `tests/live_language.rs` spawn T10's
//! `aitm-testtarget-serve` the same way and read the same control endpoints
//! back, so the process handling and the client live here once (quality
//! findings N2 and N3). Nothing here is a fixture: it starts a real binary and
//! speaks real HTTP/1.1 to it over loopback.

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// What a run without `$AITM_TESTTARGET_BIN` panics with (plan call 35).
///
/// A missing target must read as a failure to be fixed, never as a silent
/// green, so every path here panics rather than returning early.
pub const SKIP: &str = "SKIP: set AITM_TESTTARGET_BIN to the serve binary (cargo build -p \
                        aitm-testtarget -> target/debug/aitm-testtarget-serve; the in-tree target \
                        has /ws since main 395f9281)";

/// How long [`Target::start`] waits for the target's `ready` line.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// T10's `aitm-testtarget-serve`, running with its control origin.
pub struct Target {
    child: Child,
    /// Drains the child's stdout for the whole run, so a chatty target never
    /// blocks writing into a full pipe. Ends at EOF, which `Drop` causes by
    /// killing the child.
    _drain: JoinHandle<()>,
    /// `http://127.0.0.1:<port>` of the seeded origin.
    pub origin: String,
    /// `http://127.0.0.1:<port>` of the control origin.
    pub control: String,
}

impl Target {
    /// Spawn the binary in `mode` and read its listen lines up to `ready`.
    ///
    /// # Panics
    ///
    /// Without `$AITM_TESTTARGET_BIN`, when the binary will not spawn, when it
    /// exits before `ready`, when it has not printed `ready` within
    /// [`READY_TIMEOUT`], or when it names no origin.
    #[must_use]
    pub fn start(mode: &str) -> Self {
        let Ok(bin) = std::env::var("AITM_TESTTARGET_BIN") else {
            panic!("{SKIP}");
        };
        let mut child = Command::new(&bin)
            .args(["--mode", mode, "--port", "0", "--control-port", "0"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("{SKIP} (spawning {bin} failed: {err})"));
        let stdout = child.stdout.take().expect("the child's stdout is piped");
        let (lines, drain) = drain_lines(stdout);

        let mut origin = None;
        let mut control = None;
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = match lines.recv_timeout(left) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => panic!(
                    "{SKIP} (the target printed no `ready` line within {}s; it reported \
                     {origin:?} / {control:?})",
                    READY_TIMEOUT.as_secs()
                ),
                Err(RecvTimeoutError::Disconnected) => panic!(
                    "{SKIP} (the target exited before `ready`; it reported {origin:?} / \
                     {control:?})"
                ),
            };
            if let Some(rest) = line.strip_prefix("listening ") {
                origin = Some(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("control ") {
                control = Some(rest.to_string());
            } else if line == "ready" {
                break;
            }
        }

        let origin = origin.expect("the target printed a `listening` line");
        let control =
            control.expect("the target printed a `control` line (it needs --control-port)");
        println!("target[{mode}] origin={origin} control={control}");
        Self {
            child,
            _drain: drain,
            origin,
            control,
        }
    }

    /// `127.0.0.1:<port>` of the seeded origin.
    #[must_use]
    pub fn authority(&self) -> String {
        strip_scheme(&self.origin).to_string()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read `stdout` on a thread, forwarding trimmed lines until the receiver is
/// dropped and swallowing everything after that.
///
/// The swallowing half is the point: once the caller has its `ready` line it
/// stops reading, and a target that keeps logging would otherwise fill the
/// pipe buffer and block mid-request.
fn drain_lines(stdout: impl Read + Send + 'static) -> (Receiver<String>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if sender.send(line.trim().to_string()).is_err() {
                // Nobody is listening any more: keep the pipe empty.
                let mut rest = Vec::new();
                let _ = reader.read_to_end(&mut rest);
                return;
            }
        }
    });
    (receiver, handle)
}

/// `http://host:port` without its scheme.
#[must_use]
pub fn strip_scheme(origin: &str) -> &str {
    origin.split_once("://").map_or(origin, |(_, rest)| rest)
}

/// One request over a fresh connection, read to EOF; `(head, body)`.
///
/// The live tests' only HTTP client (quality finding N3). Deliberately
/// hand-written and `async`: the target and its control origin speak plain
/// HTTP/1.1 over loopback and the crate takes no HTTP client dependency for
/// its tests.
///
/// # Panics
///
/// When the origin will not accept a connection, or the exchange fails.
pub async fn http(
    origin: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, String) {
    let authority = strip_scheme(origin);
    let mut stream = TcpStream::connect(authority)
        .await
        .unwrap_or_else(|err| panic!("connect {authority}: {err}"));
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream
        .write_all(request.as_bytes())
        .await
        .unwrap_or_else(|err| panic!("send {method} {path}: {err}"));
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .unwrap_or_else(|err| panic!("read {method} {path}: {err}"));
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_once("\r\n\r\n").map_or_else(
        || (text.clone(), String::new()),
        |(head, body)| (head.to_string(), body.to_string()),
    )
}

/// `GET <path>` on the control origin, parsed as JSON.
///
/// # Panics
///
/// When the control origin will not answer, or answers something that is not
/// JSON.
pub async fn control_json(control: &str, path: &str) -> Value {
    let (head, body) = http(control, "GET", path, &[], "").await;
    serde_json::from_str(&body)
        .unwrap_or_else(|err| panic!("{path} is not JSON ({err}); head was {head:?}"))
}
