//! A system Firefox as a managed child, driven over its remote-debugging (CDP)
//! endpoint, with a **throwaway profile** that carries both the proxy routing
//! and the MITM-CA trust — so the OS proxy and OS trust store are never touched
//! (M4 Task 13, Review Focus #5).
//!
//! The profile lives in a fresh temp directory for the run and is removed when
//! the driver drops. Its `user.js` points Firefox at aitmproxy's custom proxy
//! (`network.proxy.*`), and the CA is imported into the profile's own cert store
//! (`cert9.db`) with `certutil` — never into the OS store. `eval`/`get_dom` are
//! best-effort over Firefox's CDP subset; the gate requires only
//! navigate + screenshot + capture.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aitm_core::{BrowserConfig, BrowserDriver, ClickTarget, NavOutcome, Value};
use anyhow::Context as _;
use chromiumoxide::browser::Browser;
use futures::future::BoxFuture;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tracing::{debug, info};

use crate::driver::CdpSession;

/// How often `start` re-checks the child and the CDP port.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Bound on the `certutil` import of the CA into the profile.
const CERTUTIL_TIMEOUT: Duration = Duration::from_secs(10);

/// The nickname the CA is stored under in the profile cert store.
const CA_NICKNAME: &str = "aitmproxy-mitm-ca";

/// The throwaway-profile `user.js`: Firefox reads it on startup and copies each
/// `user_pref` into `prefs.js`, so the proxy routing and trust posture live in
/// this profile alone. The five proxy prefs the spec names
/// (`network.proxy.type=1`, http/ssl host + port, `allow_hijacking_localhost`)
/// route **all** traffic — loopback included — through aitmproxy's custom proxy;
/// the rest keep a headless automation profile from phoning home or prompting,
/// which would otherwise pollute the capture.
pub fn user_js(proxy_port: u16) -> String {
    let mut s = String::new();
    // Routing: a manual proxy at aitmproxy for http and https, loopback included.
    s.push_str("user_pref(\"network.proxy.type\", 1);\n");
    s.push_str("user_pref(\"network.proxy.http\", \"127.0.0.1\");\n");
    s.push_str(&format!(
        "user_pref(\"network.proxy.http_port\", {proxy_port});\n"
    ));
    s.push_str("user_pref(\"network.proxy.ssl\", \"127.0.0.1\");\n");
    s.push_str(&format!(
        "user_pref(\"network.proxy.ssl_port\", {proxy_port});\n"
    ));
    s.push_str("user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n");
    // Nothing bypasses the proxy; the default list exempts localhost otherwise.
    s.push_str("user_pref(\"network.proxy.no_proxies_on\", \"\");\n");
    // Keep the automated profile quiet: no first-run, update, telemetry or
    // safe-browsing traffic to muddy the captured flows.
    s.push_str("user_pref(\"browser.shell.checkDefaultBrowser\", false);\n");
    s.push_str("user_pref(\"app.update.enabled\", false);\n");
    s.push_str("user_pref(\"datareporting.policy.dataSubmissionEnabled\", false);\n");
    s.push_str("user_pref(\"toolkit.telemetry.enabled\", false);\n");
    s.push_str("user_pref(\"browser.safebrowsing.malware.enabled\", false);\n");
    s.push_str("user_pref(\"browser.safebrowsing.phishing.enabled\", false);\n");
    s
}

/// The exact Firefox launch command: a headless, isolated instance bound to the
/// throwaway `profile_dir` with its CDP endpoint on `remote_port`. The
/// `no-remote` + `new-instance` flags keep it off any already-running Firefox
/// (and its default profile); `headless = false` drops the headless flag for a
/// visible run.
pub fn command(binary: &Path, profile_dir: &Path, remote_port: u16, headless: bool) -> Command {
    let mut cmd = Command::new(binary);
    if headless {
        cmd.arg("-headless");
    }
    cmd.arg("--no-remote")
        .arg("--new-instance")
        .arg("--profile")
        .arg(profile_dir)
        .arg("--remote-debugging-port")
        .arg(remote_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// A loopback port nothing listens on right now (bind-and-release).
fn free_loopback_port() -> anyhow::Result<u16> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("picking a free loopback port")?;
    Ok(listener.local_addr()?.port())
}

/// A throwaway profile directory, removed on drop (RF#5: nothing outlives the
/// run). Created fresh under the OS temp dir.
struct ProfileDir(PathBuf);

impl ProfileDir {
    fn new() -> anyhow::Result<Self> {
        // Unique per call within this process, so concurrent launches never share
        // a profile dir.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aitm-firefox-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating the Firefox profile dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ProfileDir {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0) {
            if err.kind() != io::ErrorKind::NotFound {
                debug!(path = %self.0.display(), %err, "could not remove the Firefox profile dir");
            }
        }
    }
}

/// Import the MITM CA into the profile's own cert store (`cert9.db`) with
/// `certutil`, trusting it as a root for TLS (`C,,`). Profile-scoped: the OS
/// trust store is never touched (RF#5). A missing `certutil` is a clear,
/// actionable error — HTTPS interception silently fails without the trust, so
/// there is no fall-through.
async fn trust_ca_into_profile(profile_dir: &Path, ca_cert: &Path) -> anyhow::Result<()> {
    let mut cmd = Command::new("certutil");
    cmd.arg("-A")
        .args(["-n", CA_NICKNAME])
        .args(["-t", "C,,"])
        .arg("-i")
        .arg(ca_cert)
        .arg("-d")
        .arg(format!("sql:{}", profile_dir.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = tokio::time::timeout(CERTUTIL_TIMEOUT, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("certutil did not finish within {CERTUTIL_TIMEOUT:?}"))?
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "certutil not found: it is needed to trust the MITM CA into the Firefox \
                     profile (install the NSS tools, e.g. `brew install nss` or \
                     `apt-get install libnss3-tools`)"
                )
            } else {
                anyhow::Error::new(err).context("running certutil")
            }
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "certutil failed to import the MITM CA ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// A running Firefox owned by one driver, tied to its throwaway profile.
struct FirefoxProcess {
    child: Child,
    pid: u32,
    remote_port: u16,
    /// The throwaway profile; dropped (and so deleted) when this struct drops.
    profile: ProfileDir,
}

impl FirefoxProcess {
    /// Prepare the throwaway profile (proxy prefs + CA trust), spawn a headless
    /// Firefox on a free CDP port, and wait — bounded by `start_timeout` — until
    /// the endpoint accepts a connection. Returns the process and the HTTP CDP
    /// base URL (`chromiumoxide` reads the WebSocket URL from `/json/version`).
    async fn start(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<(Self, String)> {
        let fx = &config.firefox;
        let profile = ProfileDir::new()?;

        std::fs::write(
            profile.path().join("user.js"),
            user_js(config.proxy_addr.port()),
        )
        .with_context(|| format!("writing user.js into {}", profile.path().display()))?;
        trust_ca_into_profile(profile.path(), ca_cert).await?;

        let remote_port = free_loopback_port()?;
        let mut child = command(&fx.binary, profile.path(), remote_port, config.headless)
            .spawn()
            .map_err(|err| spawn_error(err, &fx.binary))?;
        let spawned_at = Instant::now();
        let Some(pid) = child.id() else {
            anyhow::bail!("firefox exited before its pid could be read");
        };
        info!(pid, port = remote_port, "firefox started");

        // Firefox's stdout/stderr at debug; nothing gates on it, but a crash is
        // then visible in the logs.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pump(stderr, "stderr"));
        }
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pump(stdout, "stdout"));
        }

        let mut process = Self {
            child,
            pid,
            remote_port,
            profile,
        };
        process.wait_ready(spawned_at, fx.start_timeout).await?;
        Ok((process, format!("http://127.0.0.1:{remote_port}")))
    }

    /// Poll until the CDP port accepts a connection; a child that exits first is
    /// an immediate error, and the deadline is `start_timeout` from the spawn.
    async fn wait_ready(
        &mut self,
        spawned_at: Instant,
        start_timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = spawned_at + start_timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                anyhow::bail!("firefox exited during startup with {status}");
            }
            if TcpStream::connect((Ipv4Addr::LOCALHOST, self.remote_port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let _ = self.child.start_kill();
                anyhow::bail!(
                    "firefox (pid {}) did not listen on CDP port {} within {start_timeout:?}",
                    self.pid,
                    self.remote_port
                );
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Kill Firefox and reap it; the profile dir is removed when the struct drops.
    async fn stop(mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        info!(pid = self.pid, "firefox stopped");
        Ok(())
    }
}

/// Forward the child's lines to `tracing` at debug.
async fn pump<R: tokio::io::AsyncRead + Unpin>(reader: R, stream: &'static str) {
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        debug!(target: "firefox", stream, "{line}");
    }
}

/// Turn a spawn failure into an operator-facing error, naming the fix for the
/// common cases (missing binary, non-executable).
fn spawn_error(err: io::Error, binary: &Path) -> anyhow::Error {
    match err.kind() {
        io::ErrorKind::NotFound => anyhow::anyhow!(
            "firefox binary {} not found; install Firefox or set browser.firefox.binary",
            binary.display()
        ),
        io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "{}: permission denied when running it ({err}); make it executable",
            binary.display()
        ),
        _ => anyhow::Error::new(err).context(format!("running {}", binary.display())),
    }
}

/// System Firefox as the engine: a managed child with a throwaway profile and
/// the CDP session over it.
pub struct FirefoxDriver {
    session: CdpSession,
    process: Mutex<Option<FirefoxProcess>>,
    op_timeout: Duration,
    profile_dir: PathBuf,
}

/// Run one primitive under `limit` (every operation is bounded).
async fn bounded<T>(
    limit: Duration,
    what: &str,
    op: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    match tokio::time::timeout(limit, op).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("firefox {what} did not complete within {limit:?}"),
    }
}

impl FirefoxDriver {
    /// `FirefoxProcess::start`, then `Browser::connect` on its CDP HTTP endpoint
    /// (`chromiumoxide` fetches the WebSocket URL from `/json/version`), the
    /// handler task, and one `about:blank` page — within `start_timeout` of the
    /// spawn.
    pub async fn launch(config: &BrowserConfig, ca_cert: &Path) -> anyhow::Result<Self> {
        let (process, cdp_url) = FirefoxProcess::start(config, ca_cert).await?;
        let profile_dir = process.profile.path().to_path_buf();
        let nav_timeout = config.firefox.nav_timeout;
        let attached = tokio::time::timeout(config.firefox.start_timeout, async {
            let (browser, handler) = Browser::connect(&cdp_url)
                .await
                .with_context(|| format!("connecting to firefox CDP at {cdp_url}"))?;
            CdpSession::attach(browser, handler, nav_timeout).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "firefox CDP at {cdp_url} was not attached within {:?} of spawn",
                config.firefox.start_timeout
            ))
        });
        let session = match attached {
            Ok(session) => session,
            Err(err) => {
                if let Err(stop_err) = process.stop().await {
                    debug!(%stop_err, "stopping firefox after a failed attach");
                }
                return Err(err);
            }
        };
        info!(pid = process.pid, %cdp_url, "firefox CDP attached");
        Ok(Self {
            session,
            process: Mutex::new(Some(process)),
            op_timeout: nav_timeout,
            profile_dir,
        })
    }

    /// Graceful shutdown: CDP `Browser.close`, then kill the child; the profile
    /// dir is removed with it. What `main` calls on shutdown.
    pub async fn close(self) -> anyhow::Result<()> {
        self.shutdown().await
    }

    /// The close path through a shared handle (`LaunchedBrowser`); idempotent.
    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        if let Err(err) = self.session.close().await {
            debug!(%err, "CDP close failed; killing the firefox child directly");
        }
        let process = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("firefox process lock poisoned"))?
            .take();
        match process {
            Some(process) => process.stop().await,
            None => Ok(()),
        }
    }

    /// The throwaway profile dir in use (RF#5 test: it is the temp one, and is
    /// removed once the driver drops).
    pub fn profile_dir(&self) -> &Path {
        &self.profile_dir
    }

    /// The child's pid while it runs; `None` after `close` or once reaped.
    pub fn pid(&self) -> Option<u32> {
        self.process.lock().ok()?.as_ref()?.pid()
    }

    /// A child that exited is reported as such, not as a broken socket.
    fn ensure_alive(&self) -> anyhow::Result<()> {
        let mut guard = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("firefox process lock poisoned"))?;
        let Some(process) = guard.as_mut() else {
            anyhow::bail!("firefox is closed");
        };
        match process.try_wait()? {
            Some(status) => anyhow::bail!("firefox exited with {status}"),
            None => Ok(()),
        }
    }

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

    async fn timed<T>(
        &self,
        what: &str,
        op: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        self.guarded(bounded(self.op_timeout, what, op)).await
    }
}

impl BrowserDriver for FirefoxDriver {
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
    use aitm_core::FirefoxConfig;
    use std::ffi::OsStr;

    /// RF#5 — `user.js` sets the five proxy prefs the spec names, pointed at the
    /// configured port, so the throwaway profile routes through aitmproxy's
    /// custom proxy and nothing else.
    #[test]
    fn user_js_sets_the_proxy_prefs() {
        let js = user_js(8081);
        assert!(js.contains("user_pref(\"network.proxy.type\", 1);"), "{js}");
        assert!(
            js.contains("user_pref(\"network.proxy.http\", \"127.0.0.1\");"),
            "{js}"
        );
        assert!(
            js.contains("user_pref(\"network.proxy.http_port\", 8081);"),
            "{js}"
        );
        assert!(
            js.contains("user_pref(\"network.proxy.ssl\", \"127.0.0.1\");"),
            "{js}"
        );
        assert!(
            js.contains("user_pref(\"network.proxy.ssl_port\", 8081);"),
            "{js}"
        );
        assert!(
            js.contains("user_pref(\"network.proxy.allow_hijacking_localhost\", true);"),
            "{js}"
        );
    }

    /// The port tracks the config: a different proxy port changes the pref.
    #[test]
    fn user_js_tracks_the_port() {
        let js = user_js(9999);
        assert!(js.contains("user_pref(\"network.proxy.http_port\", 9999);"));
        assert!(js.contains("user_pref(\"network.proxy.ssl_port\", 9999);"));
        assert!(!js.contains("8081"));
    }

    /// The launch argv binds Firefox to the throwaway profile with its CDP port,
    /// headless and isolated from any running instance.
    #[test]
    fn command_binds_profile_and_cdp_port() {
        let cmd = command(
            Path::new("/usr/bin/firefox"),
            Path::new("/tmp/aitm-firefox-prof"),
            19333,
            true,
        );
        let std_cmd = cmd.as_std();
        assert_eq!(std_cmd.get_program(), OsStr::new("/usr/bin/firefox"));
        let args: Vec<&OsStr> = std_cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "-headless",
                "--no-remote",
                "--new-instance",
                "--profile",
                "/tmp/aitm-firefox-prof",
                "--remote-debugging-port",
                "19333",
            ]
            .map(OsStr::new)
        );
    }

    /// `headless = false` drops `-headless` for a visible run; the profile and
    /// CDP flags stay.
    #[test]
    fn command_headful_drops_the_headless_flag() {
        let cmd = command(
            Path::new("/usr/bin/firefox"),
            Path::new("/tmp/prof"),
            1234,
            false,
        );
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "-headless"), "{args:?}");
        assert!(args.iter().any(|a| a == "--profile"), "{args:?}");
        assert!(
            args.iter().any(|a| a == "--remote-debugging-port"),
            "{args:?}"
        );
    }

    /// The default `FirefoxConfig` resolves `firefox` on `PATH` with sane bounds.
    #[test]
    fn default_config_is_sane() {
        let c = FirefoxConfig::default();
        assert_eq!(c.binary, PathBuf::from("firefox"));
        assert!(c.start_timeout >= Duration::from_secs(1));
        assert!(c.nav_timeout >= Duration::from_secs(1));
    }
}
