//! The log file and the three-layer tracing composition (spec D7, D11; plan
//! Task 9; calls C12, C13, C14).
//!
//! Every `aitm` run writes an INFO log to `<aitm dir>/logs/aitm.log`
//! ([`default_log_dir`], amendment B: the `logs` sibling of the CA audit
//! log), overridable with `AITM_LOG_FILE` and, in tui mode for one more
//! release, `AITM_TUI_LOG`. The directory is created `0700`, the file is
//! opened append-only, `0600`, `O_NOFOLLOW|O_NONBLOCK`, must be a regular
//! file (a wider existing mode is tightened on the fd), and is rotated once
//! to `aitm.log.1` when it is over [`ROTATE_BYTES`] at open
//! ([`open_log_file`]).
//!
//! [`compose`] builds one `tracing_subscriber::registry()` with up to three
//! layers, each behind its own filter: the file layer (always, when the file
//! opened), the raw stderr stream (`-v`, `-vv` or a non-empty `RUST_LOG`;
//! never in tui mode) and, otherwise, the `UiLayer` that folds WARN+ into the
//! reporter's view. The stderr layer and the `UiLayer` are never both
//! installed (no double warnings), and tui mode installs the file layer only
//! (C14: after the handover ratatui owns the terminal). [`init_tracing`]
//! opens the file, composes, installs the global default once and remembers
//! the path for the error panel's `Log` footer ([`current_log_path`]). A log
//! file that cannot be opened never fails startup: one warning line, a
//! [`LogSink`] with `problem` set, and the run continues without a log.

use std::fs::{DirBuilder, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use aitm_term::caps::Verbosity;
use aitm_term::reporter::Reporter;
use aitm_term::tracing_layer::UiLayer;
use tracing::{Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::{fmt, EnvFilter};

use crate::startup::args::TermOpts;
use crate::startup::errors::StartupError;
use crate::tui::{TuiLog, LOG_PATH_ENV};

/// `<level>` followed by the curated noisy-crate caps, as one directive
/// string (quality Q10: the cap list is spelled once). The noisy transport
/// and browser dependencies are pinned to `warn` so a normal browsing session
/// does not bury the useful lines under per-connection dependency chatter.
macro_rules! with_noisy_caps {
    ($level:literal) => {
        concat!(
            $level,
            ",chromiumoxide=warn",
            ",tungstenite=warn",
            ",tokio_tungstenite=warn",
            ",hyper=warn",
            ",hyper_util=warn",
            ",rustls=warn",
            ",tower=warn",
            ",reqwest=warn",
        )
    };
}

/// The curated default tracing directive used when `RUST_LOG` is unset (AC3).
///
/// Operator-relevant lifecycle on the `aitm*` targets ("proxy listening", the
/// obscura start/stop/attach lines) stays at `info`, while the noisy
/// dependencies are capped at `warn` (`with_noisy_caps!`). Benign
/// per-connection disconnects are already emitted at `debug` (Task 1), so the
/// `info` baseline hides them without a per-target pin. `RUST_LOG`, when set,
/// overrides this wholesale (see [`build_env_filter`]).
pub const DEFAULT_LOG_DIRECTIVE: &str = with_noisy_caps!("info");

/// [`DEFAULT_LOG_DIRECTIVE`] with `debug` in front: the file (and `-vv`
/// stderr) filter when `RUST_LOG` is unset and the operator asked for debug
/// (plan C12). The noisy-crate caps stay, so `-vv` shows aitmproxy's own
/// DEBUG records, not hyper's.
pub const DEBUG_LOG_DIRECTIVE: &str = with_noisy_caps!("debug");

/// Environment variable naming an explicit log file, in every mode (spec D7).
/// In tui mode `AITM_TUI_LOG` ([`LOG_PATH_ENV`]) is still honoured after it,
/// for one release.
pub const LOG_FILE_ENV: &str = "AITM_LOG_FILE";

/// A log file larger than this at open is renamed to `<name>.1` before the
/// open (spec D7: 10 MiB; no mid-run rotation in wave 1).
pub const ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// The file name under [`default_log_dir`].
const LOG_FILE_NAME: &str = "aitm.log";

/// The path [`init_tracing`] opened, for the error panel's `Log` footer. Set
/// only when the file actually opened: a footer must never point the operator
/// at a log that does not exist.
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Build the server path's `EnvFilter`: `rust_log` (the `RUST_LOG` value) when it
/// is set and non-empty overrides the default wholesale; otherwise the curated
/// [`DEFAULT_LOG_DIRECTIVE`] is used. Both parse lossily, so a malformed
/// directive drops the bad part rather than failing startup.
pub fn build_env_filter(rust_log: Option<String>) -> EnvFilter {
    match rust_log_set(rust_log.as_deref()) {
        Some(directive) => EnvFilter::new(directive),
        None => EnvFilter::new(DEFAULT_LOG_DIRECTIVE),
    }
}

/// The one definition of "`RUST_LOG` is active" (quality Q2, tester F4):
/// the value is set and non-empty after trimming, the way
/// [`build_env_filter`] has always read it. Every consumer — the file
/// directive, the raw stderr stream ([`raw_stream`]) and the caps'
/// animation switch (`TermOpts::caps_from_parts`) — reads it through here,
/// so `RUST_LOG=" "` is inactive everywhere at once.
pub fn rust_log_active(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.trim().is_empty())
}

/// The `RUST_LOG` value when [`rust_log_active`], else `None`.
fn rust_log_set(rust_log: Option<&str>) -> Option<&str> {
    rust_log.filter(|v| rust_log_active(Some(v)))
}

/// The directive the file layer (and the raw stderr stream) filters with
/// (spec D7): a non-empty `RUST_LOG` wholesale; else `-vv` →
/// [`DEBUG_LOG_DIRECTIVE`]; else [`DEFAULT_LOG_DIRECTIVE`]. `-q` and `-v`
/// leave the file at the default (D7: `-q` affects only the reporter).
pub fn file_directive(rust_log: Option<&str>, verbosity: Verbosity) -> String {
    match rust_log_set(rust_log) {
        Some(directive) => directive.to_string(),
        None if verbosity >= Verbosity::Debug => DEBUG_LOG_DIRECTIVE.to_string(),
        None => DEFAULT_LOG_DIRECTIVE.to_string(),
    }
}

/// Whether the raw tracing stream goes to stderr (spec D7, AC-W1-20): a
/// non-empty `RUST_LOG`, or `-v`/`-vv`, and never in tui mode, where the
/// TUI owns the terminal (D11, plan C14).
pub fn raw_stream(opts: &TermOpts, rust_log: Option<&str>, tui: bool) -> bool {
    !tui && (rust_log_active(rust_log) || opts.verbosity >= Verbosity::Verbose)
}

/// The log directory: the `logs` sibling of the CA audit log, so it lands in
/// the per-user aitmproxy directory with the same platform fallbacks and no
/// `aitm-core` edit (spec amendment B; `~/Library/Application
/// Support/aitmproxy/logs` on macOS, `$XDG_CONFIG_HOME/aitmproxy/logs` on
/// Linux).
pub fn default_log_dir() -> PathBuf {
    aitm_core::CaConfig::default()
        .audit_log
        .with_file_name("logs")
}

/// Where the log goes: [`LOG_FILE_ENV`] when set and non-empty; else, in tui
/// mode, [`LOG_PATH_ENV`] when set and non-empty; else
/// `default_log_dir()/aitm.log`. `env` is the environment lookup, a closure
/// so tests need no process-global state.
pub fn log_file_path(tui: bool, env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let set = |key: &str| env(key).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(explicit) = set(LOG_FILE_ENV) {
        return explicit;
    }
    if tui {
        if let Some(explicit) = set(LOG_PATH_ENV) {
            return explicit;
        }
    }
    default_log_dir().join(LOG_FILE_NAME)
}

/// Open the log file for appending (spec D7): the parent directory is
/// created `0700`, a file over [`ROTATE_BYTES`] is first renamed to
/// `<name>.1` (replacing an older `.1`), and the file is opened
/// `O_CREAT|O_APPEND|O_WRONLY|O_NOFOLLOW|O_NONBLOCK`, mode `0600` when
/// created. The final component is never followed, so a symlink planted at
/// the log path fails the open instead of being written through (plan C13;
/// the pattern `aitm-proto-http` opens the CA key with). After the open
/// (security S2, spec amendment 2026-11-01) the fd must be a regular file —
/// a device, FIFO or socket is refused with `log path is not a regular
/// file`, and `O_NONBLOCK` makes a reader-less FIFO fail (`ENXIO`) instead
/// of blocking startup — and an existing file wider than `0600` is
/// tightened with `fchmod` on the open fd before anything is written.
pub fn open_log_file(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut dir = DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            dir.mode(0o700);
        }
        dir.create(parent)?;
    }
    rotate_if_large(path)?;

    let mut opts = OpenOptions::new();
    opts.append(true).create(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(std::io::Error::other(format!(
                "refusing to open symlinked log file {}",
                path.display()
            )));
        }
    }
    let file = opts.open(path)?;
    // Checked on the opened fd, not the path, so nothing can be swapped in
    // between the check and the first write.
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::other("log path is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

/// Rename `path` to `<name>.1` when it is a regular file larger than
/// [`ROTATE_BYTES`]; `rename` replaces an older `.1`. The size is read
/// without following a symlink, so a planted link is never rotated (and the
/// `O_NOFOLLOW` open refuses it next). A missing file is simply not rotated.
fn rotate_if_large(path: &Path) -> std::io::Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !meta.is_file() || meta.len() <= ROTATE_BYTES {
        return Ok(());
    }
    let Some(name) = path.file_name() else {
        return Ok(());
    };
    let mut rotated = name.to_os_string();
    rotated.push(".1");
    std::fs::rename(path, path.with_file_name(rotated))
}

/// Where this run's log went (spec D7): `path` when the file opened,
/// `problem` (the open error's text) when it did not. Startup continues
/// either way; the card's `Log` row and the TUI toast read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSink {
    pub path: Option<PathBuf>,
    pub problem: Option<String>,
}

/// The three-layer composition (spec D7), pure so tests drive it with an
/// in-memory writer under `tracing::subscriber::with_default`:
///
/// - the **file layer** when `file` is `Some`: `fmt`, never ANSI, filtered by
///   [`file_directive`];
/// - the **stderr layer** when [`raw_stream`]: `fmt` with the caps' colour,
///   same directive (the back-compat raw stream; AC-W1-20);
/// - otherwise, and only outside tui mode (plan C14), the **`UiLayer`** at
///   `WARN`, so WARN+ events fold into the reporter's view (AC-W1-19).
///
/// The stderr layer and the `UiLayer` are never both installed (no double
/// warnings); tui mode installs the file layer only.
pub fn compose<W>(
    opts: &TermOpts,
    reporter: &Reporter,
    file: Option<W>,
    tui: bool,
    rust_log: Option<&str>,
) -> Box<dyn Subscriber + Send + Sync>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let directive = file_directive(rust_log, opts.verbosity);
    let file_layer = file.map(|writer| {
        fmt::layer()
            .with_ansi(false)
            .with_writer(writer)
            .with_filter(EnvFilter::new(&directive))
    });
    let raw = raw_stream(opts, rust_log, tui);
    let stderr_layer = raw.then(|| {
        fmt::layer()
            .with_ansi(reporter.caps().color)
            .with_writer(std::io::stderr)
            .with_filter(EnvFilter::new(&directive))
    });
    let ui_layer = (!raw && !tui)
        .then(|| UiLayer::new(reporter.events(), Level::WARN).with_filter(LevelFilter::WARN));
    Box::new(
        tracing_subscriber::registry()
            .with(file_layer)
            .with(stderr_layer)
            .with(ui_layer),
    )
}

/// Open the log file for the composition. On failure the operator gets one
/// warning line through the reporter — the `Display` of
/// [`StartupError::LogFile`] (`log file unavailable: <path> (<why>)`), then
/// `· running without a log` (AC-W1-17; quality Q1: that variant is the one
/// place the wording lives) — and the sink records the open error's text as
/// the problem; nothing fails.
fn open_sink(reporter: &Reporter, path: &Path) -> (Option<Mutex<File>>, LogSink) {
    match open_log_file(path) {
        Ok(file) => (
            Some(Mutex::new(file)),
            LogSink {
                path: Some(path.to_path_buf()),
                problem: None,
            },
        ),
        Err(err) => {
            let problem = err.to_string();
            let unavailable = StartupError::LogFile {
                path: path.to_path_buf(),
                source: err,
            };
            reporter.warn(&format!(
                "{unavailable} {sep} running without a log",
                sep = reporter.glyphs().sep
            ));
            (
                None,
                LogSink {
                    path: None,
                    problem: Some(problem),
                },
            )
        }
    }
}

/// Install the process's tracing subscriber (spec D7, D11): open the log at
/// `path` ([`open_log_file`]; a failure warns and continues), [`compose`] the
/// layers with the process's `RUST_LOG`, set the global default once (a
/// second call keeps the first subscriber) and remember the path for
/// [`current_log_path`]. Returns where the log went.
pub fn init_tracing(opts: &TermOpts, reporter: &Reporter, path: &Path, tui: bool) -> LogSink {
    let (file, sink) = open_sink(reporter, path);
    let rust_log = std::env::var("RUST_LOG").ok();
    let subscriber = compose(opts, reporter, file, tui, rust_log.as_deref());
    // `main` calls this once; an embedding that installed its own subscriber
    // first keeps it, and this run's layers are simply not added.
    let _ = tracing::subscriber::set_global_default(subscriber);
    if let Some(opened) = &sink.path {
        let _ = LOG_PATH.set(opened.clone());
    }
    sink
}

/// The log file [`init_tracing`] opened in this process, for the error
/// panel's `Log` footer; `None` before `init_tracing` or when the file could
/// not be opened.
pub fn current_log_path() -> Option<PathBuf> {
    LOG_PATH.get().cloned()
}

/// The TUI's startup-toast value for this run's log (spec D11):
/// `TuiLog::File(path)` when the file opened, else `Unavailable` with the
/// sink's problem as `why`.
pub fn tui_log(sink: &LogSink, path: &Path) -> TuiLog {
    if sink.path.is_some() {
        TuiLog::File(path.to_path_buf())
    } else {
        TuiLog::Unavailable {
            path: path.to_path_buf(),
            why: sink.problem.clone().unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aitm_term::caps::{Caps, Verbosity};
    use aitm_term::reporter::Reporter;
    use aitm_term::testing::SharedSink;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::startup::args::TermOpts;
    use crate::tui::TuiLog;

    /// A hand-rolled temp dir under `std::env::temp_dir()`, removed on drop
    /// (plan C23; the `tempfile` crate is not in the lock).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("aitm-term-{tag}-{}-{seq}", std::process::id()));
            fs::create_dir_all(&dir).expect("create temp dir");
            TempDir(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A `MakeWriter` that appends every formatted log line to a shared buffer,
    /// so a test can read back exactly what the subscriber emitted.
    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl BufWriter {
        fn new() -> BufWriter {
            BufWriter(Arc::new(Mutex::new(Vec::new())))
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn opts(verbosity: Verbosity) -> TermOpts {
        TermOpts {
            verbosity,
            ..TermOpts::default()
        }
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    /// The first `n` bytes of a file (the rotated log is 10 MiB; never read
    /// it whole).
    fn head(path: &Path, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        File::open(path)
            .expect("open for head")
            .read_exact(&mut buf)
            .expect("read head");
        buf
    }

    /// The WARN the live proof uses (AC-W1-19), from a test target.
    fn warn_browser_unavailable() {
        tracing::warn!(
            engine = "obscura",
            "embedded browser unavailable; browser.* commands will error"
        );
    }

    #[test]
    fn default_log_dir_is_the_logs_sibling_of_the_ca_audit_log() {
        let expected = aitm_core::CaConfig::default()
            .audit_log
            .with_file_name("logs");
        assert_eq!(default_log_dir(), expected);
        assert!(
            default_log_dir().ends_with("aitmproxy/logs"),
            "{}",
            default_log_dir().display()
        );
    }

    #[test]
    fn log_file_path_precedence() {
        assert_eq!(LOG_FILE_ENV, "AITM_LOG_FILE");
        assert_eq!(crate::tui::LOG_PATH_ENV, "AITM_TUI_LOG");

        let both = |key: &str| match key {
            "AITM_LOG_FILE" => Some("/tmp/x.log".to_string()),
            "AITM_TUI_LOG" => Some("/tmp/t.log".to_string()),
            _ => None,
        };
        assert_eq!(log_file_path(false, &both), PathBuf::from("/tmp/x.log"));
        assert_eq!(log_file_path(true, &both), PathBuf::from("/tmp/x.log"));

        let tui_only = |key: &str| (key == "AITM_TUI_LOG").then(|| "/tmp/t.log".to_string());
        assert_eq!(log_file_path(true, &tui_only), PathBuf::from("/tmp/t.log"));
        assert_eq!(
            log_file_path(false, &tui_only),
            default_log_dir().join("aitm.log")
        );

        let empty = |_: &str| None;
        assert_eq!(
            log_file_path(false, &empty),
            default_log_dir().join("aitm.log")
        );
        assert_eq!(
            log_file_path(true, &empty),
            default_log_dir().join("aitm.log")
        );

        // An empty value is unset, as the tui path has always read it.
        let blank = |key: &str| (key == "AITM_LOG_FILE").then(String::new);
        assert_eq!(
            log_file_path(false, &blank),
            default_log_dir().join("aitm.log")
        );
    }

    #[test]
    fn open_log_file_creates_dir_0700_and_file_0600_and_appends() {
        let d = TempDir::new("open");
        let path = d.path().join("logs/aitm.log");

        let mut first = open_log_file(&path).expect("first open");
        assert_eq!(mode_of(&d.path().join("logs")), 0o700);
        assert_eq!(mode_of(&path), 0o600);
        first.write_all(b"a\n").expect("write a");
        drop(first);

        let mut second = open_log_file(&path).expect("second open");
        second.write_all(b"b\n").expect("write b");
        drop(second);

        assert_eq!(fs::read_to_string(&path).expect("read"), "a\nb\n");
        assert!(!d.path().join("logs/aitm.log.1").exists());
    }

    #[test]
    fn open_log_file_rotates_a_file_over_10_mib() {
        assert_eq!(ROTATE_BYTES, 10 * 1024 * 1024);
        let d = TempDir::new("rotate");
        let path = d.path().join("aitm.log");
        let rotated = d.path().join("aitm.log.1");

        let grow_to = |marker: &[u8], len: u64| {
            let mut f = open_log_file(&path).expect("open to grow");
            f.write_all(marker).expect("marker");
            f.set_len(len).expect("set_len");
        };

        // Exactly the limit does not rotate: the rule is "larger than".
        grow_to(b"edge\n", ROTATE_BYTES);
        drop(open_log_file(&path).expect("open at the limit"));
        assert!(!rotated.exists(), "a file of exactly ROTATE_BYTES stays");
        assert_eq!(fs::metadata(&path).expect("meta").len(), ROTATE_BYTES);

        grow_to(b"first\n", ROTATE_BYTES + 1);
        let f = open_log_file(&path).expect("open rotates");
        assert_eq!(
            f.metadata().expect("meta").len(),
            0,
            "the handle is on a fresh aitm.log"
        );
        assert_eq!(fs::metadata(&path).expect("meta").len(), 0);
        assert_eq!(
            fs::metadata(&rotated).expect("aitm.log.1 exists").len(),
            ROTATE_BYTES + 1
        );
        assert_eq!(head(&rotated, 5), b"edge\n");
        drop(f);

        grow_to(b"second\n", ROTATE_BYTES + 1);
        let f = open_log_file(&path).expect("second rotation");
        assert_eq!(fs::metadata(&path).expect("meta").len(), 0);
        assert_eq!(
            fs::metadata(&rotated).expect("meta").len(),
            ROTATE_BYTES + 1
        );
        assert_eq!(
            head(&rotated, 7),
            b"second\n",
            "the second rotation replaces aitm.log.1"
        );
        drop(f);
    }

    #[cfg(unix)]
    /// Security S2(a): `mode(0o600)` applies only at creation, so a log file
    /// that already exists wider (0644 here, say from an older build or a
    /// hand-made file) is tightened to 0600 on the open fd before it is
    /// written to; the contents are kept (append) and nothing is rotated.
    #[test]
    fn open_log_file_forces_0600_on_a_wider_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new("wide");
        let path = d.path().join("aitm.log");
        fs::write(&path, "old\n").expect("pre-create");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod 644");
        assert_eq!(mode_of(&path), 0o644, "precondition");

        let mut file = open_log_file(&path).expect("open the wide file");
        assert_eq!(mode_of(&path), 0o600, "the open tightens the mode");
        file.write_all(b"new\n").expect("append");
        drop(file);
        assert_eq!(fs::read_to_string(&path).expect("read"), "old\nnew\n");
        assert!(!d.path().join("aitm.log.1").exists());

        // A file that is already 0600 (or tighter) is left alone.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("chmod 400");
        drop(open_log_file(&path));
        assert_eq!(mode_of(&path), 0o400, "a tighter mode is not widened");
    }

    /// Security S2(b): a FIFO at the log path with no reader must fail the
    /// open promptly (`O_NONBLOCK` → `ENXIO`) instead of blocking startup
    /// forever on the write-open. The open runs on its own thread so a
    /// regression shows as a 1 s timeout, not a hung test binary. Skipped
    /// where `mkfifo` is not runnable.
    #[test]
    fn open_log_file_refuses_a_reader_less_fifo_within_a_second() {
        use std::os::unix::fs::FileTypeExt;
        use std::sync::mpsc;
        use std::time::Duration;
        let d = TempDir::new("fifo");
        let path = d.path().join("aitm.log");
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        let Ok(status) = made else {
            return; // no mkfifo on this host: nothing to prove
        };
        assert!(status.success(), "mkfifo {}: {status}", path.display());
        assert!(
            fs::symlink_metadata(&path)
                .expect("fifo metadata")
                .file_type()
                .is_fifo(),
            "precondition: a FIFO at the log path"
        );

        let (tx, rx) = mpsc::channel();
        let target = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(open_log_file(&target).map(drop));
        });
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(Err(err)) => {
                assert_eq!(err.raw_os_error(), Some(libc::ENXIO), "{err}");
            }
            Ok(Ok(())) => panic!("a reader-less FIFO was accepted as the log file"),
            Err(_) => panic!("open_log_file blocked on a reader-less FIFO for over 1 s"),
        }
    }

    /// Security S2(b): a device at the log path is refused after the open
    /// (`AITM_LOG_FILE=/dev/fd/1` would otherwise put INFO on stdout), and
    /// `open_sink` turns the refusal into the one `log file unavailable`
    /// warning; the device itself is untouched.
    #[test]
    fn open_log_file_refuses_a_device_at_the_log_path() {
        let path = Path::new("/dev/null");
        let err = open_log_file(path).expect_err("a device is not a log file");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "log path is not a regular file");

        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let (file, log_sink) = open_sink(&reporter, path);
        reporter.finish();
        assert!(file.is_none());
        assert_eq!(log_sink.path, None);
        assert_eq!(
            log_sink.problem.as_deref(),
            Some("log path is not a regular file")
        );
        assert_eq!(
            sink.text(),
            "warning: log file unavailable: /dev/null (log path is not a regular file) - running without a log\n"
        );
    }

    #[test]
    fn open_log_file_refuses_a_symlink() {
        let d = TempDir::new("symlink");
        let other = d.path().join("other.txt");
        fs::write(&other, "keep me\n").expect("write other");
        let link = d.path().join("aitm.log");
        std::os::unix::fs::symlink(&other, &link).expect("symlink");

        let err = open_log_file(&link).expect_err("a symlinked log file must be refused");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP), "{err}");
        assert_eq!(fs::read_to_string(&other).expect("read other"), "keep me\n");
        assert!(fs::symlink_metadata(&link)
            .expect("the link is still there")
            .file_type()
            .is_symlink());
        assert!(
            !d.path().join("aitm.log.1").exists(),
            "a symlink is never rotated"
        );
    }

    #[test]
    fn file_directive_and_raw_stream_tables() {
        assert_eq!(
            DEFAULT_LOG_DIRECTIVE,
            "info,chromiumoxide=warn,tungstenite=warn,tokio_tungstenite=warn,hyper=warn,\
             hyper_util=warn,rustls=warn,tower=warn,reqwest=warn"
        );
        assert_eq!(
            DEBUG_LOG_DIRECTIVE,
            "debug,chromiumoxide=warn,tungstenite=warn,tokio_tungstenite=warn,hyper=warn,\
             hyper_util=warn,rustls=warn,tower=warn,reqwest=warn"
        );

        assert_eq!(file_directive(Some("trace"), Verbosity::Normal), "trace");
        assert_eq!(file_directive(None, Verbosity::Debug), DEBUG_LOG_DIRECTIVE);
        assert_eq!(
            file_directive(None, Verbosity::Verbose),
            DEFAULT_LOG_DIRECTIVE
        );
        assert_eq!(
            file_directive(Some(""), Verbosity::Normal),
            DEFAULT_LOG_DIRECTIVE
        );
        assert_eq!(
            file_directive(Some("info"), Verbosity::Debug),
            "info",
            "RUST_LOG beats -vv for the file"
        );

        assert!(!raw_stream(&opts(Verbosity::Normal), None, false));
        assert!(raw_stream(&opts(Verbosity::Verbose), None, false));
        assert!(raw_stream(&opts(Verbosity::Normal), Some("info"), false));
        assert!(!raw_stream(&opts(Verbosity::Debug), Some("info"), true));
        assert!(!raw_stream(&opts(Verbosity::Normal), Some(""), false));
        assert!(!raw_stream(&opts(Verbosity::Quiet), None, false));
    }

    /// Quality Q2 / tester F4: the one predicate every consumer reads.
    /// Unset, empty and blank are inactive; anything with a non-space
    /// character is active, however it is padded; `raw_stream` and the file
    /// directive agree with it on the blank value.
    #[test]
    fn rust_log_active_is_trimmed_non_empty() {
        assert!(!rust_log_active(None));
        assert!(!rust_log_active(Some("")));
        assert!(!rust_log_active(Some(" ")));
        assert!(!rust_log_active(Some("\t\n")));
        assert!(rust_log_active(Some("info")));
        assert!(rust_log_active(Some(" warn ")));
        assert!(rust_log_active(Some("x")));

        assert!(!raw_stream(&opts(Verbosity::Normal), Some(" "), false));
        assert_eq!(
            file_directive(Some(" "), Verbosity::Normal),
            DEFAULT_LOG_DIRECTIVE
        );
        assert_eq!(
            file_directive(Some(" warn "), Verbosity::Normal),
            " warn ",
            "an active value is passed through untrimmed; EnvFilter trims"
        );
    }

    #[test]
    fn compose_sends_warn_to_the_reporter_and_info_to_the_file() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Normal),
            &reporter,
            Some(file.clone()),
            false,
            None,
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("proxy listening");
            warn_browser_unavailable();
        });
        reporter.finish();

        let logged = file.text();
        assert!(logged.contains("proxy listening"), "{logged:?}");
        assert!(
            logged.contains("embedded browser unavailable"),
            "{logged:?}"
        );
        assert!(logged.contains(" INFO "), "{logged:?}");
        assert!(logged.contains(" WARN "), "{logged:?}");
        assert!(
            !logged.as_bytes().contains(&0x1b),
            "the file layer is never ANSI: {logged:?}"
        );
        assert_eq!(
            sink.text(),
            "warning: embedded browser unavailable; browser.* commands will error engine=obscura\n"
        );
    }

    #[test]
    fn compose_without_a_file_still_folds_warn_into_the_view() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let subscriber = compose(
            &opts(Verbosity::Normal),
            &reporter,
            None::<BufWriter>,
            false,
            None,
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("proxy listening");
            warn_browser_unavailable();
        });
        reporter.finish();

        assert_eq!(
            sink.text(),
            "warning: embedded browser unavailable; browser.* commands will error engine=obscura\n"
        );
    }

    #[test]
    fn compose_with_a_raw_stream_installs_no_ui_layer() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Verbose);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Verbose),
            &reporter,
            Some(file.clone()),
            false,
            None,
        );

        tracing::subscriber::with_default(subscriber, warn_browser_unavailable);
        reporter.finish();

        assert_eq!(
            sink.text(),
            "",
            "the stderr layer took the WARN; no UiLayer under a raw stream"
        );
        let logged = file.text();
        assert!(
            logged.contains("embedded browser unavailable"),
            "{logged:?}"
        );
    }

    #[test]
    fn compose_in_tui_mode_installs_the_file_layer_only() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Normal),
            &reporter,
            Some(file.clone()),
            true,
            Some("info"),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("proxy listening");
            warn_browser_unavailable();
        });
        reporter.finish();

        assert_eq!(sink.text(), "", "tui mode: nothing reaches the view");
        let logged = file.text();
        assert!(logged.contains("proxy listening"), "{logged:?}");
        assert!(
            logged.contains("embedded browser unavailable"),
            "{logged:?}"
        );
    }

    #[test]
    fn open_sink_warns_and_records_the_problem_when_the_file_cannot_open() {
        let d = TempDir::new("unavailable");
        // A regular file where a log directory should be: creating the
        // directory below it fails (ENOTDIR), so the open fails.
        let blocker = d.path().join("logs");
        fs::write(&blocker, "not a directory\n").expect("write blocker");
        let path = blocker.join("sub").join("aitm.log");

        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let (file, log_sink) = open_sink(&reporter, &path);
        reporter.finish();

        assert!(file.is_none());
        assert_eq!(log_sink.path, None);
        let problem = log_sink.problem.clone().expect("problem recorded");
        assert!(problem.contains("Not a directory"), "{problem}");
        assert_eq!(
            sink.text(),
            format!(
                "warning: log file unavailable: {} ({problem}) - running without a log\n",
                path.display()
            )
        );
        assert_eq!(
            fs::read_to_string(&blocker).expect("blocker"),
            "not a directory\n"
        );
    }

    #[test]
    fn open_sink_returns_the_path_when_the_file_opens() {
        let d = TempDir::new("available");
        let path = d.path().join("logs/aitm.log");
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);

        let (file, log_sink) = open_sink(&reporter, &path);
        reporter.finish();

        assert!(file.is_some());
        assert_eq!(
            log_sink,
            LogSink {
                path: Some(path.clone()),
                problem: None
            }
        );
        assert_eq!(sink.text(), "", "no warning when the file opens");
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn tui_log_from_sink() {
        let p = PathBuf::from("/tmp/t.log");
        assert_eq!(
            tui_log(
                &LogSink {
                    path: Some(p.clone()),
                    problem: None
                },
                &p
            ),
            TuiLog::File(p.clone())
        );
        assert_eq!(
            tui_log(
                &LogSink {
                    path: None,
                    problem: Some("denied".to_string())
                },
                &p
            ),
            TuiLog::Unavailable {
                path: p.clone(),
                why: "denied".to_string()
            }
        );
    }

    /// Install a subscriber with `filter` over a buffer, run `f`, and return
    /// everything it emitted — so a test can assert which targets/levels survive.
    fn capture_with_filter(filter: tracing_subscriber::EnvFilter, f: impl FnOnce()) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(filter)
            .with_writer(BufWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn default_filter_quiets_connection_noise() {
        // AC3: the curated default (no RUST_LOG) keeps operator lifecycle while
        // silencing per-connection dependency chatter and benign disconnects.
        let out = capture_with_filter(build_env_filter(None), || {
            tracing::info!(target: "aitm_core::proxy", "proxy listening");
            tracing::info!(target: "chromiumoxide", "cdp event spam");
            tracing::debug!(target: "aitm_core::proxy", "connection closed before completion");
        });
        assert!(
            out.contains("proxy listening"),
            "operator lifecycle must survive the default filter: {out:?}"
        );
        assert!(
            !out.contains("cdp event spam"),
            "noisy dependency target must be pinned below info: {out:?}"
        );
        assert!(
            !out.contains("connection closed before completion"),
            "benign per-connection debug must stay hidden at the info baseline: {out:?}"
        );
    }

    #[test]
    fn rust_log_overrides_the_curated_default() {
        // AC3: RUST_LOG overrides the curated default wholesale — a directive that
        // raises a pinned dependency to trace makes its trace events appear.
        let out = capture_with_filter(build_env_filter(Some("chromiumoxide=trace".into())), || {
            tracing::trace!(target: "chromiumoxide", "cdp trace restored");
        });
        assert!(
            out.contains("cdp trace restored"),
            "RUST_LOG must override the curated default wholesale: {out:?}"
        );
    }

    #[test]
    fn empty_rust_log_falls_back_to_the_curated_default() {
        // An empty RUST_LOG is treated as unset, not as "disable everything".
        let out = capture_with_filter(build_env_filter(Some("   ".into())), || {
            tracing::info!(target: "aitm_core::proxy", "proxy listening");
        });
        assert!(
            out.contains("proxy listening"),
            "an empty RUST_LOG must fall back to the curated default: {out:?}"
        );
    }

    // ---- tester, whole-branch pass (spec D7, AC-W1-15/17/18/19/22) ----

    /// A parent that is a regular file: `mkdir` on it is `EEXIST`; a parent
    /// under a regular file is `ENOTDIR`. Either way the open fails, the file
    /// in the way is untouched and nothing is created beside it.
    #[cfg(unix)]
    #[test]
    fn open_log_file_fails_when_a_parent_is_a_file() {
        let d = TempDir::new("parent-file");
        let blocker = d.path().join("logs");
        fs::write(&blocker, "not a directory\n").expect("write blocker");

        let direct = open_log_file(&blocker.join("aitm.log")).expect_err("parent is a file");
        assert_eq!(direct.raw_os_error(), Some(libc::EEXIST), "{direct}");

        let nested = open_log_file(&blocker.join("sub").join("aitm.log"))
            .expect_err("grandparent is a file");
        assert_eq!(nested.raw_os_error(), Some(libc::ENOTDIR), "{nested}");

        assert_eq!(
            fs::read_to_string(&blocker).expect("blocker"),
            "not a directory\n"
        );
        assert_eq!(
            fs::read_dir(d.path()).expect("list").count(),
            1,
            "nothing was created beside the blocker"
        );
    }

    /// `AITM_LOG_FILE` naming a directory (AC-W1-18's failure twin): the
    /// open is `EISDIR`, the directory is neither rotated nor removed, and
    /// through `open_sink` the operator gets the one warning line while the
    /// run continues without a log.
    #[cfg(unix)]
    #[test]
    fn open_log_file_refuses_a_directory_at_the_log_path() {
        let d = TempDir::new("isdir");
        let path = d.path().join("aitm.log");
        fs::create_dir(&path).expect("make the directory");

        let err = open_log_file(&path).expect_err("a directory is not a log file");
        assert_eq!(err.raw_os_error(), Some(libc::EISDIR), "{err}");
        assert!(path.is_dir(), "still a directory");
        assert!(!d.path().join("aitm.log.1").exists(), "never rotated");

        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let (file, log_sink) = open_sink(&reporter, &path);
        reporter.finish();
        assert!(file.is_none());
        assert_eq!(log_sink.path, None);
        assert_eq!(
            log_sink.problem.as_deref(),
            Some("Is a directory (os error 21)")
        );
        assert_eq!(
            sink.text(),
            format!(
                "warning: log file unavailable: {} (Is a directory (os error 21)) - running without a log\n",
                path.display()
            )
        );
    }

    /// Blank overrides are unset in both modes; a relative override is taken
    /// as given (no resolution against any directory).
    #[test]
    fn log_file_path_blank_overrides_and_relative_values() {
        let blank_both =
            |key: &str| (key == "AITM_LOG_FILE" || key == "AITM_TUI_LOG").then(String::new);
        assert_eq!(
            log_file_path(true, &blank_both),
            default_log_dir().join("aitm.log")
        );
        assert_eq!(
            log_file_path(false, &blank_both),
            default_log_dir().join("aitm.log")
        );

        let blank_file_set_tui = |key: &str| match key {
            "AITM_LOG_FILE" => Some(String::new()),
            "AITM_TUI_LOG" => Some("/tmp/t.log".to_string()),
            _ => None,
        };
        assert_eq!(
            log_file_path(true, &blank_file_set_tui),
            PathBuf::from("/tmp/t.log"),
            "a blank AITM_LOG_FILE does not shadow AITM_TUI_LOG in tui mode"
        );
        assert_eq!(
            log_file_path(false, &blank_file_set_tui),
            default_log_dir().join("aitm.log"),
            "AITM_TUI_LOG is tui-only"
        );

        let relative = |key: &str| (key == "AITM_LOG_FILE").then(|| "x.log".to_string());
        assert_eq!(log_file_path(false, &relative), PathBuf::from("x.log"));
    }

    /// `-q` is the reporter's business (spec D7): WARN and ERROR events
    /// still fold into the view under `Quiet`, as `warning: …` / `error: …`
    /// lines with their fields, and the file keeps INFO.
    #[test]
    fn compose_under_quiet_still_folds_warn_and_error_into_the_view() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Quiet);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Quiet),
            &reporter,
            Some(file.clone()),
            false,
            None,
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("proxy listening");
            warn_browser_unavailable();
            tracing::error!(target: "aitm::wire", code = 7, "boom");
        });
        reporter.finish();

        assert_eq!(
            sink.text(),
            "warning: embedded browser unavailable; browser.* commands will error engine=obscura\n\
             error: boom code=7\n"
        );
        let logged = file.text();
        assert!(
            logged.contains(" INFO "),
            "-q never thins the file: {logged:?}"
        );
        assert!(logged.contains("proxy listening"), "{logged:?}");
        assert!(logged.contains("ERROR"), "{logged:?}");
    }

    /// AC-W1-22 through the whole composition: a WARN carrying `token`,
    /// `password` and `*secret` fields reaches the view with every one of
    /// them redacted and the other fields intact. The file layer is a plain
    /// `fmt` layer and does not redact (spec D7 puts redaction in the
    /// `UiLayer`); keeping tokens out of the file is the call-site pin
    /// `no_tracing_call_site_logs_a_tokened_url`'s job.
    #[test]
    fn compose_redacts_secret_fields_in_the_view() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Normal),
            &reporter,
            Some(file.clone()),
            false,
            None,
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                token = "not-a-real-token",
                password = "not-a-real-password",
                api_secret = "not-a-real-secret",
                url = "http://127.0.0.1:8082/",
                "bridge token minted"
            );
        });
        reporter.finish();

        assert_eq!(
            sink.text(),
            "warning: bridge token minted token=<redacted> password=<redacted> api_secret=<redacted> url=http://127.0.0.1:8082/\n"
        );
        let logged = file.text();
        assert!(
            logged.contains("token=\"not-a-real-token\"")
                || logged.contains("token=not-a-real-token"),
            "the file layer records the field as logged (no redaction there): {logged:?}"
        );
    }

    /// A non-empty `RUST_LOG` is the file's directive wholesale (spec D7): at
    /// `warn` the INFO record is dropped from the file, the WARN is kept, and
    /// the raw stderr stream replaces the `UiLayer` so the view gets nothing.
    #[test]
    fn compose_with_rust_log_warn_thins_the_file_and_installs_no_ui_layer() {
        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let file = BufWriter::new();
        let subscriber = compose(
            &opts(Verbosity::Normal),
            &reporter,
            Some(file.clone()),
            false,
            Some("warn"),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("proxy listening");
            warn_browser_unavailable();
        });
        reporter.finish();

        assert_eq!(sink.text(), "", "the raw stream took the WARN");
        let logged = file.text();
        assert!(
            !logged.contains("proxy listening"),
            "RUST_LOG=warn drops INFO from the file: {logged:?}"
        );
        assert!(
            logged.contains("embedded browser unavailable"),
            "{logged:?}"
        );
    }

    /// AC-W1-15's filter half: the per-script `loaded script` record is
    /// DEBUG, hidden by the default directive and shown by `-vv`'s, while
    /// the noisy-crate caps hold at both levels.
    #[test]
    fn file_directive_hides_loaded_script_by_default_and_shows_it_under_debug() {
        let emit = || {
            tracing::debug!(target: "aitm_plugin_rhai::loader", script = "x", "loaded script");
            tracing::debug!(target: "aitm::scripts", script = "x", "script loaded into the host");
            tracing::debug!(target: "hyper::proto::h1", "parsed headers");
            tracing::info!(target: "aitm_core::proxy", "proxy listening");
        };
        let default = capture_with_filter(
            tracing_subscriber::EnvFilter::new(file_directive(None, Verbosity::Normal)),
            emit,
        );
        assert!(default.contains("proxy listening"), "{default:?}");
        assert!(!default.contains("loaded script"), "{default:?}");
        assert!(
            !default.contains("script loaded into the host"),
            "{default:?}"
        );
        assert!(!default.contains("parsed headers"), "{default:?}");

        let debug = capture_with_filter(
            tracing_subscriber::EnvFilter::new(file_directive(None, Verbosity::Debug)),
            emit,
        );
        assert!(debug.contains("loaded script"), "{debug:?}");
        assert!(debug.contains("script loaded into the host"), "{debug:?}");
        assert!(debug.contains("proxy listening"), "{debug:?}");
        assert!(
            !debug.contains("parsed headers"),
            "hyper stays capped at warn under -vv: {debug:?}"
        );
        assert_eq!(debug.matches("loaded script").count(), 1, "{debug:?}");
        assert_eq!(
            debug.matches("script loaded into the host").count(),
            1,
            "{debug:?}"
        );
    }
}
