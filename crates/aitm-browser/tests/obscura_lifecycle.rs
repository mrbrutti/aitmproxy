//! Task 20: the obscura child's lifecycle and the driver over it.
//!
//! The hermetic tests run the shell-script fixtures in `tests/fixtures/` and
//! never need a real obscura. The `[obscura]` tests need the fork binary
//! (found by discovery, or `AITM_OBSCURA_BIN`) and run only when
//! `AITM_OBSCURA=1` is set; otherwise they skip inertly, like the Chrome tests
//! behind `AITM_CHROME`:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura cargo test -p aitm-browser --test obscura_lifecycle
//! ```

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_browser::{BrowserConfig, BrowserDriver, ObscuraDriver, ObscuraProcess};
use aitm_core::{BrowserEngine, ObscuraConfig};
use tracing::{field::Field, span, Event, Level, Metadata};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// The checked-in self-signed certificate `aitm-ca` tests use: a real PEM the
/// real obscura accepts on `--ca-cert` (it fails fast on anything else).
fn ca_cert_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../aitm-ca/tests/fixtures/ca.crt")
        .canonicalize()
        .expect("aitm-ca fixture ca.crt")
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
            "aitm-lifecycle-{tag}-{}-{nanos}",
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

/// The full error text of a result that must be `Err` (the `Ok` types here do
/// not implement `Debug`, so `expect_err` cannot be used).
fn err_text<T>(result: anyhow::Result<T>, must_fail_because: &str) -> String {
    match result {
        Ok(_) => panic!("expected an error: {must_fail_because}"),
        Err(err) => format!("{err:#}"),
    }
}

/// An obscura engine config pinned to one binary; everything else default.
fn config_with_binary(binary: PathBuf) -> BrowserConfig {
    BrowserConfig {
        obscura: ObscuraConfig {
            binary: Some(binary),
            ..ObscuraConfig::default()
        },
        ..BrowserConfig::default()
    }
}

// ---- hermetic ---------------------------------------------------------------

/// Review Focus #1 — a binary that passes the probe but exits during startup
/// surfaces its exit status and stderr tail at once, not after `start_timeout`.
#[tokio::test]
async fn start_reports_early_exit() {
    let config = config_with_binary(fixture("fake-obscura-exits.sh"));
    let started = Instant::now();

    let text = err_text(
        ObscuraProcess::start(&config, Path::new("/nonexistent/ca.crt")).await,
        "a child that exits during startup must be an error",
    );
    let elapsed = started.elapsed();

    assert!(
        text.contains("exited during startup"),
        "error does not say the child exited during startup: {text}"
    );
    assert!(
        text.contains('7'),
        "error does not carry exit status 7: {text}"
    );
    assert!(
        text.contains("boom"),
        "error does not carry the stderr tail: {text}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "start waited {elapsed:?} for a child that had already exited"
    );
}

/// Review Focus #5 — a discovered binary without the exec bit fails at spawn
/// with the quarantine hint, not a bare `EACCES`.
#[cfg(unix)]
#[tokio::test]
async fn spawn_permission_error_carries_hint() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("noexec");
    let binary = dir.path().join("obscura");
    std::fs::copy(fixture("fake-obscura-patched.sh"), &binary).expect("copy fixture");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o644))
        .expect("clear the exec bit");

    let text = err_text(
        ObscuraProcess::start(&config_with_binary(binary.clone()), Path::new("/ca/ca.crt")).await,
        "a non-executable binary must be an error",
    );
    assert!(
        text.contains("permission denied"),
        "error does not say permission denied: {text}"
    );
    assert!(
        text.contains("xattr -d com.apple.quarantine"),
        "error does not carry the quarantine hint: {text}"
    );
    assert!(
        text.contains(&binary.display().to_string()),
        "error does not name the binary: {text}"
    );
}

/// Spec §D4 — `headless` is meaningless for obscura: `headless = false` adds
/// no flag and is logged at WARN; `headless = true` is silent.
#[test]
fn headless_false_is_ignored_for_obscura() {
    let build = |headless: bool| {
        let config = BrowserConfig {
            headless,
            ..BrowserConfig::default()
        };
        let (subscriber, events) = Capture::new();
        let cmd = tracing::subscriber::with_default(subscriber, || {
            ObscuraProcess::command(
                &config,
                Path::new("/opt/aitm/obscura"),
                Path::new("/var/aitm/ca/ca.crt"),
                19222,
                Path::new("/tmp/aitm-ready-42"),
            )
        });
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let events = events.lock().expect("events").clone();
        (args, events)
    };

    let (args, events) = build(false);
    assert!(
        !args.iter().any(|a| a.contains("head")),
        "headless=false added a head flag: {args:?}"
    );
    assert!(
        events
            .iter()
            .any(|(level, text)| *level == Level::WARN && text.contains("headless")),
        "no WARN mentioning headless was logged: {events:?}"
    );

    let (_, events) = build(true);
    assert!(
        !events.iter().any(|(level, _)| *level == Level::WARN),
        "headless=true logged a warning: {events:?}"
    );
}

/// M2-AC8 (hermetic half) — `launch` dispatches on `config.engine`: with the
/// default engine it starts the configured obscura binary, and that binary's
/// startup failure is the error the caller sees.
#[tokio::test]
async fn launch_dispatches_on_engine() {
    let config = config_with_binary(fixture("fake-obscura-exits.sh"));
    assert_eq!(config.engine, BrowserEngine::Obscura);
    let text = err_text(
        aitm_browser::launch(&config, Path::new("/ca/ca.crt")).await,
        "the fixture exits during startup",
    );
    assert!(
        text.contains("exited during startup"),
        "launch did not start the obscura engine: {text}"
    );
}

/// A minimal `tracing` subscriber that records every event's level and fields
/// (no `tracing-subscriber` in this crate).
struct Capture(Events);

/// The `(level, fields)` of every event a [`Capture`] saw.
type Events = Arc<Mutex<Vec<(Level, String)>>>;

impl Capture {
    fn new() -> (Self, Events) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (Self(Arc::clone(&events)), events)
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0
            .lock()
            .expect("events")
            .push((*event.metadata().level(), fields.0));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

// ---- [obscura] --------------------------------------------------------------

/// Run the obscura-backed tests only when `AITM_OBSCURA=1` is set, so the
/// default `cargo test` stays hermetic.
fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (and AITM_OBSCURA_BIN) to run the obscura-backed test"
        );
        return false;
    }
    true
}

/// One real obscura at a time: the `pgrep` assertion below must not see another
/// test's child (mirrors `chrome_lock` in `tests/browser.rs`).
fn obscura_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// `kill -0`: true while the pid exists (a reaped process no longer does).
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        // Once the pid is gone, kill(1) reports "No such process"; that is the
        // answer we poll for, not noise for the test log.
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Poll `check` every 50 ms until it holds or `timeout` passes.
async fn wait_until(timeout: Duration, check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}

/// No `obscura serve … --ready-file` process is left on the machine.
fn no_obscura_child_remains() -> bool {
    // pgrep exits 1 when nothing matches.
    std::process::Command::new("pgrep")
        .args(["-f", "obscura.*--ready-file"])
        .output()
        .map(|o| !o.status.success() && o.stdout.is_empty())
        .unwrap_or(false)
}

/// M2-AC9 (driver half) — after `launch` the child is alive and CDP attached;
/// after `close()`, and separately after dropping the driver, the pid is gone
/// within `stop_timeout`, and no obscura child remains.
#[tokio::test]
async fn launch_close_reaps_child() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let config = BrowserConfig::default();
    let stop_timeout = config.obscura.stop_timeout;
    let ca_cert = ca_cert_fixture();

    let driver = ObscuraDriver::launch(&config, &ca_cert)
        .await
        .expect("launch obscura");
    let pid = driver.pid().expect("a launched driver has a pid");
    assert!(pid_alive(pid), "child {pid} is not alive after launch");
    // CDP is attached: a primitive answers. (A string, not arithmetic: obscura
    // reports JS numbers as floats, which is M2-AC13's concern, not this test's.)
    let joined = driver.eval("'a' + 'b'").await.expect("eval over CDP");
    assert_eq!(joined, aitm_core::Value::Str("ab".into()));

    driver.close().await.expect("close");
    assert!(
        wait_until(stop_timeout, || !pid_alive(pid)).await,
        "child {pid} still alive {stop_timeout:?} after close()"
    );

    let dropped = ObscuraDriver::launch(&config, &ca_cert)
        .await
        .expect("second launch");
    let pid2 = dropped.pid().expect("pid");
    assert!(pid_alive(pid2), "child {pid2} is not alive after launch");
    drop(dropped);
    assert!(
        wait_until(stop_timeout, || !pid_alive(pid2)).await,
        "child {pid2} still alive {stop_timeout:?} after drop"
    );

    assert!(
        wait_until(stop_timeout, no_obscura_child_remains).await,
        "an obscura child with --ready-file is still running"
    );
}

/// Spec §D4 — a child that dies while `aitm` runs is detected on the next
/// primitive, which fails naming the exit, not with a bare socket error.
#[tokio::test]
async fn dead_child_errors_clearly() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let config = BrowserConfig::default();
    let driver = ObscuraDriver::launch(&config, &ca_cert_fixture())
        .await
        .expect("launch obscura");
    let pid = driver.pid().expect("pid");

    let killed = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(killed.success(), "kill -9 {pid} failed");

    // SIGKILL is delivered asynchronously; the first primitive after it must
    // report the exit, and keep reporting it.
    let deadline = Instant::now() + Duration::from_secs(5);
    let text = loop {
        let result = tokio::time::timeout(Duration::from_secs(5), driver.eval("1"))
            .await
            .expect("eval on a dead child must not hang");
        match result {
            Err(err) if format!("{err:#}").contains("exited") => break format!("{err:#}"),
            other if Instant::now() >= deadline => {
                panic!("eval on a dead child did not report the exit: {other:?}")
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    assert!(
        text.contains("embedded browser (obscura) exited"),
        "unexpected error text: {text}"
    );
    assert!(text.contains('9'), "error does not name the signal: {text}");

    driver
        .close()
        .await
        .expect("close after a dead child is clean");
    assert!(
        wait_until(config.obscura.stop_timeout, no_obscura_child_remains).await,
        "an obscura child with --ready-file is still running"
    );
}
