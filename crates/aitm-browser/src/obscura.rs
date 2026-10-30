//! The forked obscura engine as a managed child: finding the binary, probing
//! that it is the aitmproxy fork, building the exact `serve` command, running
//! the child from spawn to reap, and the `BrowserDriver` over it.
//!
//! Spec §D3 (discovery, probe), §D4 (argv, environment, lifecycle) and §D5
//! (`ObscuraDriver` over the shared CDP session).

use std::collections::VecDeque;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{BrowserConfig, BrowserDriver, ClickTarget, NavOutcome, ObscuraConfig, Value};
use anyhow::Context as _;
use chromiumoxide::browser::Browser;
use futures::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::driver::CdpSession;

/// Environment variables removed from the child so its trust and routing are
/// exactly what aitmproxy passes as flags, whatever the operator's shell carries.
pub const SCRUBBED_ENV: [&str; 11] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "OBSCURA_CA_CERT",
    "OBSCURA_PROXY",
    "OBSCURA_ALLOW_PRIVATE_NETWORK",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

/// Bound on each probe invocation (`--help`, `--version`): every subprocess is
/// bounded, and a binary that hangs on `--help` is not one we want to serve.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often `start` and `stop` re-check the child.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Stderr lines kept for error reports.
const STDERR_TAIL_LINES: usize = 50;

/// How long `start` lets the stderr pump drain after the child exited early.
const STDERR_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// The fork's CDP WebSocket path (`obscura serve` prints it when it listens).
const CDP_WS_PATH: &str = "/devtools/browser";

/// Prefix of the per-run directory (`<prefix><aitm pid>-<token>`) under the OS
/// temp dir that holds one child's ready-file. The directory is created `0700`
/// and the token is unpredictable, so no other local user can pre-create the
/// path the child treats as its readiness signal, nor read it.
const RUN_DIR_PREFIX: &str = "aitm-obscura-";
const READY_FILE_SUFFIX: &str = ".ready";

/// What the probe learned about the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeInfo {
    /// The `--version` output, trimmed; informational, never a pin.
    pub version: String,
}

/// Find the obscura binary: `browser.obscura.binary` → `AITM_OBSCURA_BIN`
/// (`env_bin`) → `<exe_dir>/obscura` → `<exe_dir>/../libexec/obscura` →
/// `path_lookup("obscura")`. The first candidate that exists is final; a
/// configured path that does not exist is an error, not a fall-through.
///
/// The `libexec` sibling is for package layouts that keep `aitm` on the PATH
/// (`<prefix>/bin/aitm`) but tuck the engine beside the other internals
/// (`<prefix>/libexec/obscura`) — e.g. a Homebrew install whose `bin/aitm` is a
/// symlink whose target `exe_dir` the platform did not resolve. `start` also
/// canonicalizes the exe first, so the common "all three in `libexec`" layout is
/// already found by the `<exe_dir>/obscura` candidate.
pub fn discover_binary(
    cfg: &ObscuraConfig,
    env_bin: Option<PathBuf>,
    exe_dir: Option<&Path>,
    path_lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(configured) = &cfg.binary {
        if configured.exists() {
            return Ok(configured.clone());
        }
        anyhow::bail!(
            "browser.obscura.binary {} does not exist",
            configured.display()
        );
    }

    let mut tried = Vec::new();
    let candidates = [
        env_bin,
        exe_dir.map(|dir| dir.join("obscura")),
        // `<exe_dir>/../libexec/obscura`: aitm in `bin/`, engine in a sibling
        // `libexec/` (Homebrew when the exe symlink was not resolved).
        exe_dir.map(|dir| dir.join("..").join("libexec").join("obscura")),
        path_lookup("obscura"),
    ];
    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    let tried = if tried.is_empty() {
        "nothing".to_string()
    } else {
        tried.join(", ")
    };
    anyhow::bail!(
        "obscura (the embedded browser engine) was not found.\n\
         Looked in: {tried}.\n\
         To get it:\n\
         \x20 - dev checkout: run `scripts/fetch-obscura-dev.sh` to drop obscura next to the aitm binary\n\
         \x20 - installed:    install an aitmproxy package (.deb/.rpm) or the release tarball, which bundle obscura beside aitm\n\
         \x20 - custom path:  set AITM_OBSCURA_BIN=/path/to/obscura, or browser.obscura.binary in your config"
    )
}

/// Check that `binary` is the aitmproxy fork — its `--help` must list
/// `--ca-cert` — then read its `--version`. No CDP connection is attempted.
pub async fn probe(binary: &Path) -> anyhow::Result<ProbeInfo> {
    let help = run_probe_flag(binary, "--help").await?;
    if !help.contains("--ca-cert") {
        anyhow::bail!(
            "{} is not the aitmproxy obscura fork: its --help does not list --ca-cert. \
             Get the fork with `scripts/fetch-obscura-dev.sh` (dev checkout) or install an \
             aitmproxy package; or point AITM_OBSCURA_BIN / browser.obscura.binary at the fork.",
            binary.display()
        );
    }
    let version = run_probe_flag(binary, "--version").await?;
    Ok(ProbeInfo {
        version: version.trim().to_string(),
    })
}

/// Run `<binary> <flag>` with the scrubbed environment and return its combined
/// stdout and stderr, bounded by [`PROBE_TIMEOUT`].
async fn run_probe_flag(binary: &Path, flag: &str) -> anyhow::Result<String> {
    let mut cmd = Command::new(binary);
    cmd.arg(flag)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    scrub_env(&mut cmd);

    let output = tokio::time::timeout(PROBE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{} {flag} did not finish within {PROBE_TIMEOUT:?}",
                binary.display()
            )
        })?
        .map_err(|err| spawn_error(err, binary))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn scrub_env(cmd: &mut Command) {
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
}

/// Turn a spawn failure into an operator-facing error. `EACCES` on a binary
/// we found is a missing exec bit or macOS Gatekeeper quarantine (Review
/// Focus #5), so the hint names both fixes.
fn spawn_error(err: io::Error, binary: &Path) -> anyhow::Error {
    if err.kind() == io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "{binary}: permission denied when running it ({err}); make it executable with \
             `chmod +x {binary}` and, if it was downloaded on macOS, clear the quarantine with \
             `xattr -d com.apple.quarantine {binary}`",
            binary = binary.display()
        )
    } else {
        anyhow::Error::new(err).context(format!("running {}", binary.display()))
    }
}

/// `PATH` lookup for discovery: the first `<dir>/<name>` that is a file.
fn lookup_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// A loopback port nothing listens on right now (bind-and-release).
///
/// Residual race (documented, accepted): the listener is dropped here and the
/// child binds the same port moments later, so a local process could grab it in
/// between. There is no inherited-FD path through `obscura serve --port`, and
/// `obscura` does not report a `--port 0` choice, so the window cannot be closed
/// from this side. It is mitigated: readiness is gated on the child's own
/// ready-file in a `0700` per-run directory (see [`wait_ready`]), never on a
/// bare TCP accept, so a stranger that stole the port is not mistaken for a
/// ready obscura, and the child that fails to bind exits with an error the
/// caller sees.
fn free_loopback_port() -> anyhow::Result<u16> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("picking a free loopback port")?;
    Ok(listener.local_addr()?.port())
}

/// An unpredictable 128-bit token as hex, seeded from the OS RNG (std's
/// `RandomState`), for the per-run directory and ready-file names. Not a secret;
/// just enough entropy that the path a local attacker would have to pre-create
/// is unguessable.
pub(crate) fn random_token() -> String {
    let a = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let b = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{a:016x}{b:016x}")
}

/// Create a `0700` per-run directory under the OS temp dir with an unpredictable
/// name and return it together with the ready-file path inside it. The child is
/// the only writer of the ready-file, and the private directory keeps any other
/// local user from reading it or pre-creating it.
fn make_run_dir() -> io::Result<(PathBuf, PathBuf)> {
    let token = random_token();
    let dir = std::env::temp_dir().join(format!("{RUN_DIR_PREFIX}{}-{token}", std::process::id()));
    create_private_dir(&dir)?;
    let ready_file = dir.join(format!("ready-{token}{READY_FILE_SUFFIX}"));
    Ok((dir, ready_file))
}

#[cfg(unix)]
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir(dir)
}

/// Log any per-run directory an earlier `aitm` left behind (it was killed, so no
/// destructor ran); the operator decides whether an obscura is still running.
fn warn_stale_run_dirs() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(RUN_DIR_PREFIX) && entry.path().is_dir() {
            warn!(
                path = %entry.path().display(),
                "stale obscura run directory from an earlier run; remove it if no obscura is running"
            );
        }
    }
}

/// Remove the per-run directory and its ready-file; a missing one is fine
/// (idempotent).
fn remove_run_dir(dir: &Path) {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            debug!(path = %dir.display(), %err, "could not remove the obscura run directory")
        }
    }
}

/// Forward the child's lines to `tracing` at debug, keeping the last
/// [`STDERR_TAIL_LINES`] in `tail` when given.
async fn pump_lines<R: AsyncRead + Unpin>(
    reader: R,
    stream: &'static str,
    tail: Option<Arc<Mutex<VecDeque<String>>>>,
) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        debug!(target: "obscura", stream, "{line}");
        if let Some(tail) = &tail {
            if let Ok(mut tail) = tail.lock() {
                if tail.len() == STDERR_TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        }
    }
}

/// A running `obscura serve` owned by one driver.
pub struct ObscuraProcess {
    child: Child,
    /// The pid at spawn; `Child::id` is `None` once the child is reaped.
    pid: u32,
    cdp_port: u16,
    /// The `0700` per-run directory that holds `ready_file`; removed on stop/drop.
    run_dir: PathBuf,
    ready_file: PathBuf,
    spawned_at: Instant,
    stop_timeout: Duration,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
}

impl ObscuraProcess {
    /// The exact command that would be spawned (argv + env), for tests, logging,
    /// and `start`: the spec's `serve …` line, with the CA passed as the
    /// certificate **file**, the scrubbed environment, and `kill_on_drop`.
    pub fn command(
        config: &BrowserConfig,
        binary: &Path,
        ca_cert: &Path,
        cdp_port: u16,
        ready_file: &Path,
    ) -> Command {
        if !config.headless {
            warn!("browser.headless = false is ignored: obscura has no head");
        }

        let mut cmd = Command::new(binary);
        cmd.arg("serve")
            .args(["--host", "127.0.0.1"])
            .args(["--port", &cdp_port.to_string()])
            .args([
                "--proxy",
                &format!("http://127.0.0.1:{}", config.proxy_addr.port()),
            ])
            .arg("--ca-cert")
            .arg(ca_cert);
        // Mirror the SSRF posture at the engine (audit I15, defence in depth): the
        // flag lets obscura's own navigations reach loopback/private ranges. It is
        // passed only when `config.obscura.allow_private` — a value the launch site
        // derived from the SSRF policy ∪ the seed scope via
        // `aitm_core::engine_may_reach_private`, so a scoped loopback target lifts
        // it even under the strict default (`block_private = true`), while a
        // pure-public scope under that policy keeps it off and obscura refuses
        // private targets on its own. The SSRF-filtering connector on the proxy
        // port remains the authoritative enforcement and re-checks every connection
        // (loopback included) after resolution; this flag never widens past it, it
        // only narrows the engine to match. It is frozen at launch: a host added
        // later (`scope.add`) is still gated by the connector, but the engine picks
        // up a newly private target only on relaunch.
        if config.obscura.allow_private {
            cmd.arg("--allow-private-network");
        }
        cmd.arg("--ready-file")
            .arg(ready_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        scrub_env(&mut cmd);
        // obscura takes its CDP bearer token from this variable, and
        // chromiumoxide 0.9's `Browser::connect` cannot send a header, so an
        // inherited token would only make every connect fail. The endpoint
        // stays loopback-only; `start` logs that it is unauthenticated.
        cmd.env_remove("OBSCURA_CDP_TOKEN");
        cmd
    }

    /// Discover and probe the binary, spawn `serve` on a free loopback port,
    /// and wait — bounded by `start_timeout` — until it listens. Returns the
    /// process and the CDP WebSocket URL to connect to.
    pub async fn start(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<(Self, String)> {
        // Resolve the exe path through any symlinks before taking its directory:
        // on macOS `current_exe()` returns the path as invoked, so a Homebrew
        // `bin/aitm` symlink leaves `exe_dir` as `bin/` and the engine beside the
        // real binary in `libexec/` is missed. Canonicalizing lands `exe_dir` on
        // the real directory; if it fails (e.g. the exe was removed) fall back to
        // the unresolved path, and `discover_binary` still probes the `libexec`
        // sibling.
        let exe_dir = std::env::current_exe()
            .ok()
            .map(|exe| std::fs::canonicalize(&exe).unwrap_or(exe))
            .and_then(|exe| exe.parent().map(Path::to_path_buf));
        let binary = discover_binary(
            &config.obscura,
            std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from),
            exe_dir.as_deref(),
            &lookup_on_path,
        )?;
        let probed = probe(&binary).await?;
        info!(binary = %binary.display(), version = %probed.version, "obscura probed");

        warn_stale_run_dirs();
        let cdp_port = free_loopback_port()?;
        // A fresh 0700 directory with an unpredictable name: the ready-file path
        // inside it cannot pre-exist (so a leftover cannot read as "ready" before
        // the child is) and no other local user can read or forge it.
        let (run_dir, ready_file) =
            make_run_dir().context("creating the obscura per-run directory")?;

        let mut child = Self::command(config, &binary, ca_cert, cdp_port, &ready_file)
            .spawn()
            .map_err(|err| spawn_error(err, &binary))?;
        let spawned_at = Instant::now();
        let Some(pid) = child.id() else {
            anyhow::bail!("obscura exited before its pid could be read");
        };
        info!(pid, port = cdp_port, "obscura started");
        info!("CDP endpoint is loopback-only and unauthenticated");

        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL_LINES)));
        let stderr_pump = child.stderr.take().map(|stderr| {
            tokio::spawn(pump_lines(stderr, "stderr", Some(Arc::clone(&stderr_tail))))
        });
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pump_lines(stdout, "stdout", None));
        }

        let mut process = Self {
            child,
            pid,
            cdp_port,
            run_dir,
            ready_file,
            spawned_at,
            stop_timeout: config.obscura.stop_timeout,
            stderr_tail,
        };
        process
            .wait_ready(config.obscura.start_timeout, stderr_pump)
            .await?;
        Ok((process, format!("ws://127.0.0.1:{cdp_port}{CDP_WS_PATH}")))
    }

    /// Poll until the child writes its ready-file; a child that exits first is
    /// an immediate error. Readiness is the child's own signal — written only
    /// once its CDP server listens — not a bare TCP accept (audit minor b): a
    /// stranger that grabbed the port after [`free_loopback_port`] released it
    /// can accept a connection, but it cannot write the ready-file in our `0700`
    /// directory. The authoritative CDP handshake is the `Browser::connect` in
    /// [`ObscuraDriver::launch`], which runs as soon as this returns and fails
    /// loudly if the listener is not in fact obscura.
    async fn wait_ready(
        &mut self,
        start_timeout: Duration,
        stderr_pump: Option<JoinHandle<()>>,
    ) -> anyhow::Result<()> {
        let deadline = self.spawned_at + start_timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                // Let the pump drain what the child wrote before it exited.
                if let Some(pump) = stderr_pump {
                    let _ = tokio::time::timeout(STDERR_DRAIN_TIMEOUT, pump).await;
                }
                anyhow::bail!(
                    "obscura exited during startup with {status}: {}",
                    self.stderr_tail_text()
                );
            }
            if self.ready_file.exists() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let _ = self.child.start_kill();
                anyhow::bail!(
                    "obscura (pid {}) did not listen on port {} within {start_timeout:?}: {}",
                    self.pid,
                    self.cdp_port,
                    self.stderr_tail_text()
                );
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn stderr_tail_text(&self) -> String {
        let tail = self
            .stderr_tail
            .lock()
            .map(|tail| tail.iter().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        if tail.is_empty() {
            "(no stderr)".to_string()
        } else {
            tail
        }
    }

    /// Time since the child was spawned, for callers that share `start_timeout`
    /// with their own attach step.
    pub(crate) fn since_spawn(&self) -> Duration {
        self.spawned_at.elapsed()
    }

    /// The child's pid while it runs; `None` once it has been reaped.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Reap the child if it has exited (sticky: keeps returning the status).
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Graceful stop: SIGTERM, poll up to `stop_timeout`, then SIGKILL; remove
    /// the ready-file. A child that already exited is just reaped.
    pub async fn stop(mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.send_term();
            let deadline = Instant::now() + self.stop_timeout;
            while self.child.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    warn!(
                        pid = self.pid,
                        "obscura did not exit within {:?} of SIGTERM; killing it",
                        self.stop_timeout
                    );
                    self.child.kill().await?;
                    break;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
        info!(pid = self.pid, "obscura stopped");
        remove_run_dir(&self.run_dir);
        Ok(())
    }

    /// Ask the child to exit. No `libc`/`nix` in the tree: on Unix this is
    /// `/bin/kill -TERM <pid>` (by absolute path, never a `PATH` lookup);
    /// elsewhere the only signal available is the kill.
    fn send_term(&mut self) {
        #[cfg(unix)]
        {
            match std::process::Command::new("/bin/kill")
                .args(["-TERM", &self.pid.to_string()])
                .status()
            {
                Ok(status) if status.success() => {}
                Ok(status) => debug!(pid = self.pid, %status, "kill -TERM did not succeed"),
                Err(err) => debug!(pid = self.pid, %err, "kill -TERM could not run"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.start_kill();
        }
    }
}

impl Drop for ObscuraProcess {
    /// `kill_on_drop` reaps the child; the per-run directory is ours to remove.
    fn drop(&mut self) {
        remove_run_dir(&self.run_dir);
    }
}

/// The forked obscura as the engine: a managed child and the CDP session over it.
pub struct ObscuraDriver {
    session: CdpSession,
    /// `None` once `close` has stopped the child.
    process: Mutex<Option<ObscuraProcess>>,
    /// `nav_timeout`: the bound on every primitive other than `navigate`,
    /// which `CdpSession` already bounds with the same value.
    op_timeout: Duration,
}

/// Run one primitive under `limit` (Global Constraint: every operation is
/// bounded). A CDP call on a live child can otherwise wait for as long as
/// the child keeps it waiting. `what` names the primitive in the error.
pub async fn bounded<T>(
    limit: Duration,
    what: &str,
    op: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    match tokio::time::timeout(limit, op).await {
        Ok(result) => result,
        Err(_) => {
            anyhow::bail!("embedded browser (obscura) {what} did not complete within {limit:?}")
        }
    }
}

impl ObscuraDriver {
    /// `ObscuraProcess::start`, then `Browser::connect` on its WebSocket URL,
    /// the handler task, and one `about:blank` page — all within
    /// `start_timeout` of the spawn. No `Security.setIgnoreCertificateErrors`:
    /// trust comes from `--ca-cert`, and obscura would accept the call as a
    /// no-op.
    pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Self> {
        let (process, ws_url) = ObscuraProcess::start(config, ca_cert).await?;
        let remaining = config
            .obscura
            .start_timeout
            .saturating_sub(process.since_spawn());
        let attached = tokio::time::timeout(remaining, async {
            let (browser, handler) = Browser::connect(&ws_url)
                .await
                .with_context(|| format!("connecting to obscura CDP at {ws_url}"))?;
            CdpSession::attach(browser, handler, config.nav_timeout).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "obscura CDP at {ws_url} was not attached within {:?} of spawn",
                config.obscura.start_timeout
            ))
        });
        let session = match attached {
            Ok(session) => session,
            Err(err) => {
                if let Err(stop_err) = process.stop().await {
                    debug!(%stop_err, "stopping obscura after a failed attach");
                }
                return Err(err);
            }
        };
        info!(pid = process.pid, %ws_url, "obscura CDP attached");
        Ok(Self {
            session,
            process: Mutex::new(Some(process)),
            op_timeout: config.nav_timeout,
        })
    }

    /// Graceful shutdown: CDP `Browser.close`, then SIGTERM, then SIGKILL after
    /// `stop_timeout`. What `main` calls on shutdown.
    pub async fn close(self) -> anyhow::Result<()> {
        self.shutdown().await
    }

    /// The close path through a shared handle (`LaunchedBrowser`); idempotent.
    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        if let Err(err) = self.session.close().await {
            debug!(%err, "CDP close failed; stopping the obscura child directly");
        }
        let process = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("obscura process lock poisoned"))?
            .take();
        match process {
            Some(process) => process.stop().await,
            None => Ok(()),
        }
    }

    /// The child's pid while it runs; `None` after `close` or once it is reaped.
    pub fn pid(&self) -> Option<u32> {
        self.process.lock().ok()?.as_ref()?.pid()
    }

    /// Dead-child detection (spec §D4): a child that exited is reported as
    /// such, not as a broken socket.
    fn ensure_alive(&self) -> anyhow::Result<()> {
        let mut guard = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("obscura process lock poisoned"))?;
        let Some(process) = guard.as_mut() else {
            anyhow::bail!("embedded browser (obscura) is closed");
        };
        match process.try_wait()? {
            Some(status) => anyhow::bail!("embedded browser (obscura) exited with {status}"),
            None => Ok(()),
        }
    }

    /// Run one primitive with the child checked before, and again after a
    /// failure (a timeout included): a child that died mid-call is the
    /// cause, not the socket.
    async fn guarded<T>(&self, op: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
        self.ensure_alive()?;
        match op.await {
            Ok(value) => Ok(value),
            Err(err) => {
                self.ensure_alive()?;
                Err(err)
            }
        }
    }

    /// [`Self::guarded`] under the per-operation bound, for the primitives
    /// `CdpSession` does not bound itself.
    async fn timed<T>(
        &self,
        what: &str,
        op: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.guarded(bounded(self.op_timeout, what, op)).await
    }
}

impl BrowserDriver for ObscuraDriver {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        let url = url.to_string();
        Box::pin(async move { self.guarded(self.session.navigate(&url)).await })
    }

    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(self.timed("click", self.session.click(target)))
    }

    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        let selector = selector.to_string();
        let text = text.to_string();
        Box::pin(async move {
            self.timed("type", self.session.type_text(&selector, &text))
                .await
        })
    }

    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(self.timed("screenshot", self.session.screenshot()))
    }

    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        let expr = expr.to_string();
        Box::pin(async move { self.timed("eval", self.session.eval(&expr)).await })
    }

    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        Box::pin(self.timed("get_dom", self.session.get_dom()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit minor b: the per-run directory is created private (`0700` on unix),
    /// the ready-file lives inside it, and its name is unpredictable — two runs
    /// never collide — so no other local user can read or forge the child's
    /// readiness signal.
    #[test]
    fn run_dir_is_private_and_unpredictable() {
        let (dir_a, ready_a) = make_run_dir().expect("create run dir a");
        let (dir_b, ready_b) = make_run_dir().expect("create run dir b");

        // Clean up whatever we created, whatever the assertions do.
        struct Cleanup<'a>(&'a Path, &'a Path);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                remove_run_dir(self.0);
                remove_run_dir(self.1);
            }
        }
        let _guard = Cleanup(&dir_a, &dir_b);

        assert!(
            dir_a.is_dir(),
            "run dir was not created: {}",
            dir_a.display()
        );
        assert!(
            ready_a.starts_with(&dir_a),
            "ready-file {} is not inside its run dir {}",
            ready_a.display(),
            dir_a.display()
        );
        assert!(
            ready_a.to_string_lossy().ends_with(READY_FILE_SUFFIX),
            "ready-file does not end in {READY_FILE_SUFFIX}: {}",
            ready_a.display()
        );
        assert!(
            !ready_a.exists(),
            "ready-file must not pre-exist: {}",
            ready_a.display()
        );
        assert_ne!(dir_a, dir_b, "two runs produced the same directory");
        assert_ne!(ready_a, ready_b, "two runs produced the same ready-file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir_a)
                .expect("stat run dir")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "run dir is not 0700: {:o}",
                mode & 0o777
            );
        }
    }

    /// The token has real entropy: a batch of them is all-distinct.
    #[test]
    fn random_token_does_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(random_token()), "random_token repeated");
        }
    }

    /// `discover_binary` candidate order and the package layouts it must cover.
    mod discovery {
        use super::*;
        use std::sync::atomic::{AtomicU32, Ordering};

        /// A unique temp directory for one test, removed on drop.
        struct TmpDir(PathBuf);

        impl TmpDir {
            fn new() -> Self {
                static N: AtomicU32 = AtomicU32::new(0);
                let dir = std::env::temp_dir().join(format!(
                    "aitm-disco-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&dir).unwrap();
                TmpDir(dir)
            }
            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TmpDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn touch(path: &Path) {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, b"#!/bin/sh\n").unwrap();
        }

        fn never_on_path(_: &str) -> Option<PathBuf> {
            None
        }

        /// `<exe_dir>/obscura` is found: the engine bundled beside the binary
        /// (dev checkout, and the canonicalized `libexec` install).
        #[test]
        fn finds_obscura_beside_the_exe() {
            let tmp = TmpDir::new();
            let bin = tmp.path().join("bin");
            touch(&bin.join("obscura"));
            let found =
                discover_binary(&ObscuraConfig::default(), None, Some(&bin), &never_on_path)
                    .unwrap();
            assert_eq!(found, bin.join("obscura"));
        }

        /// `<prefix>/bin/aitm` with the engine in `<prefix>/libexec/obscura`:
        /// the Homebrew layout when the exe symlink was not resolved. The
        /// sibling-`libexec` candidate must find it.
        #[test]
        fn finds_obscura_in_sibling_libexec() {
            let tmp = TmpDir::new();
            let bin = tmp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            touch(&tmp.path().join("libexec").join("obscura"));
            let found =
                discover_binary(&ObscuraConfig::default(), None, Some(&bin), &never_on_path)
                    .unwrap();
            assert_eq!(found, bin.join("..").join("libexec").join("obscura"));
        }

        /// `AITM_OBSCURA_BIN` (`env_bin`) wins over the bundled paths.
        #[test]
        fn env_bin_wins_over_exe_dir() {
            let tmp = TmpDir::new();
            let bin = tmp.path().join("bin");
            touch(&bin.join("obscura"));
            let env_bin = tmp.path().join("custom-obscura");
            touch(&env_bin);
            let found = discover_binary(
                &ObscuraConfig::default(),
                Some(env_bin.clone()),
                Some(&bin),
                &never_on_path,
            )
            .unwrap();
            assert_eq!(found, env_bin);
        }

        /// When nothing is found, the error names every candidate that was
        /// probed, including the `libexec` sibling, so the operator can see
        /// exactly where it looked.
        #[test]
        fn error_lists_every_candidate() {
            let tmp = TmpDir::new();
            let bin = tmp.path().join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            let err = discover_binary(&ObscuraConfig::default(), None, Some(&bin), &never_on_path)
                .unwrap_err()
                .to_string();
            assert!(err.contains("was not found"), "{err}");
            assert!(
                err.contains(&bin.join("obscura").display().to_string()),
                "{err}"
            );
            assert!(err.contains("libexec"), "{err}");
        }
    }
}
