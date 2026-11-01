//! The log file and the three-layer tracing composition (spec D7, D11; plan
//! Task 9; calls C12, C13, C14).
//!
//! Every `aitm` run writes an INFO log to `<aitm dir>/logs/aitm.log`
//! ([`default_log_dir`], amendment B: the `logs` sibling of the CA audit
//! log), overridable with `AITM_LOG_FILE` and, in tui mode for one more
//! release, `AITM_TUI_LOG`. The directory is created `0700`, the file is
//! opened append-only, `0600`, `O_NOFOLLOW`, and rotated once to
//! `aitm.log.1` when it is over [`ROTATE_BYTES`] at open ([`open_log_file`]).
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
use crate::tui::{TuiLog, LOG_PATH_ENV};

/// The curated default tracing directive used when `RUST_LOG` is unset (AC3).
///
/// Operator-relevant lifecycle on the `aitm*` targets ("proxy listening", the
/// obscura start/stop/attach lines) stays at `info`, while the noisy transport
/// and browser dependencies are pinned to `warn` so a normal browsing session
/// does not bury the useful lines under per-connection dependency chatter.
/// Benign per-connection disconnects are already emitted at `debug` (Task 1),
/// so the `info` baseline hides them without a per-target pin. `RUST_LOG`, when
/// set, overrides this wholesale (see [`build_env_filter`]).
pub const DEFAULT_LOG_DIRECTIVE: &str = "info,\
    chromiumoxide=warn,\
    tungstenite=warn,\
    tokio_tungstenite=warn,\
    hyper=warn,\
    hyper_util=warn,\
    rustls=warn,\
    tower=warn,\
    reqwest=warn";

/// [`DEFAULT_LOG_DIRECTIVE`] with `debug` in front: the file (and `-vv`
/// stderr) filter when `RUST_LOG` is unset and the operator asked for debug
/// (plan C12). The noisy-crate caps stay, so `-vv` shows aitmproxy's own
/// DEBUG records, not hyper's.
pub const DEBUG_LOG_DIRECTIVE: &str = "debug,\
    chromiumoxide=warn,\
    tungstenite=warn,\
    tokio_tungstenite=warn,\
    hyper=warn,\
    hyper_util=warn,\
    rustls=warn,\
    tower=warn,\
    reqwest=warn";

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
    match rust_log.filter(|v| !v.trim().is_empty()) {
        Some(directive) => EnvFilter::new(directive),
        None => EnvFilter::new(DEFAULT_LOG_DIRECTIVE),
    }
}

/// A `RUST_LOG` value that counts as set: non-empty after trimming, the way
/// [`build_env_filter`] has always read it.
fn rust_log_set(rust_log: Option<&str>) -> Option<&str> {
    rust_log.filter(|v| !v.trim().is_empty())
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
    !tui && (rust_log_set(rust_log).is_some() || opts.verbosity >= Verbosity::Verbose)
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
/// `O_CREAT|O_APPEND|O_WRONLY|O_NOFOLLOW`, mode `0600` when created. The
/// final component is never followed, so a symlink planted at the log path
/// fails the open instead of being written through (plan C13; the pattern
/// `aitm-proto-http` opens the CA key with).
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
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
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
    opts.open(path)
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
/// warning line through the reporter (`log file unavailable: <path> (<why>)
/// · running without a log`; AC-W1-17) and the sink records the problem;
/// nothing fails.
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
            reporter.warn(&format!(
                "log file unavailable: {} ({err}) {sep} running without a log",
                path.display(),
                sep = reporter.glyphs().sep
            ));
            (
                None,
                LogSink {
                    path: None,
                    problem: Some(err.to_string()),
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
}
