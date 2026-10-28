//! Shell-outs behind a trait.
//!
//! Every effect on the OS, and every read of OS state, goes through
//! [`Executor`], so platform logic is pure with respect to the host it runs
//! on: a trust-store operation is a sequence of [`CmdLine`]s that tests can
//! assert on by their rendered form.

use std::io::{self, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};

/// One command to run. `program` and `args` reach the OS exactly as stored,
/// unquoted; quoting exists only in [`CmdLine::render`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdLine {
    pub program: String,
    pub args: Vec<String>,
    /// Piped to the child; `None` = /dev/null.
    pub stdin: Option<Vec<u8>>,
    /// `true` for anything that changes the store.
    pub mutating: bool,
}

impl CmdLine {
    /// `program` and `args` joined by single spaces; an arg containing
    /// whitespace is single-quoted. Stdin is never rendered. This string is
    /// what tests assert on and what results report.
    pub fn render(&self) -> String {
        std::iter::once(&self.program)
            .chain(&self.args)
            .map(String::as_str)
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Single-quote a word that would otherwise split (or vanish) on a shell
/// line; a word without whitespace is rendered as is.
fn quote(word: &str) -> String {
    if word.is_empty() || word.chars().any(char::is_whitespace) {
        format!("'{}'", word.replace('\'', r"'\''"))
    } else {
        word.to_string()
    }
}

/// What a finished child left behind. `code` is `None` when the child was
/// killed by a signal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    /// Exit status zero and nothing else.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// The host as the trust-store code sees it.
pub trait Executor: Send + Sync {
    /// `Err` only when the program could not be started or timed out; a
    /// non-zero exit is an `Ok` with its code.
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput>;
    /// `Ok(None)` when the file does not exist; `Err` on any other I/O
    /// failure (permission denied included).
    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>>;
    fn dir_exists(&self, path: &Path) -> bool;
    fn home_dir(&self) -> Option<PathBuf>;
    fn is_root(&self) -> bool;
}

/// Lock a mutex that only guards bookkeeping; a poisoned one still holds
/// usable data, so recover it rather than panic.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The absolute path a trust-store tool is spawned by. The stores name
/// tools by their short names, so rendered lines stay readable and the
/// spec's command tables hold; [`RealExecutor`] resolves them here rather
/// than on the caller's `PATH`, where a planted `security` or `sudo` would
/// win. Anything unlisted (the Linux refresh tools, which are reported as
/// missing packages when absent) and anything already absolute pass through.
pub fn absolute_program(program: &str) -> &str {
    if !cfg!(unix) {
        return program;
    }
    match program {
        "sudo" => "/usr/bin/sudo",
        "security" => "/usr/bin/security",
        "tee" => "/usr/bin/tee",
        "rm" => "/bin/rm",
        "id" => "/usr/bin/id",
        _ => program,
    }
}

/// The host itself: `std::process::Command` under a wall-clock timeout,
/// 15 s for queries and 180 s for mutations (long enough to type a password
/// or answer an OS dialog). On expiry the child is killed and `run` fails
/// with an error naming the command and `timed out`. Programs are spawned
/// by [`absolute_program`].
#[derive(Debug)]
pub struct RealExecutor {
    query_timeout: Duration,
    mutate_timeout: Duration,
    /// `id -u` is asked once per executor.
    root: OnceLock<bool>,
}

impl Default for RealExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RealExecutor {
    pub const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
    pub const MUTATE_TIMEOUT: Duration = Duration::from_secs(180);

    pub fn new() -> Self {
        Self::with_timeouts(Self::QUERY_TIMEOUT, Self::MUTATE_TIMEOUT)
    }

    pub fn with_timeouts(query: Duration, mutate: Duration) -> Self {
        Self {
            query_timeout: query,
            mutate_timeout: mutate,
            root: OnceLock::new(),
        }
    }

    #[cfg(unix)]
    fn probe_root(&self) -> bool {
        let id = CmdLine {
            program: "id".to_string(),
            args: vec!["-u".to_string()],
            stdin: None,
            mutating: false,
        };
        self.run(&id)
            .map(|out| out.success() && out.stdout.trim() == "0")
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    fn probe_root(&self) -> bool {
        false
    }
}

impl Executor for RealExecutor {
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        let timeout = if cmd.mutating {
            self.mutate_timeout
        } else {
            self.query_timeout
        };
        let rendered = cmd.render();

        let mut child = Command::new(absolute_program(&cmd.program))
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("could not start `{rendered}`"))?;

        // Feed stdin and drain both pipes on their own threads, so a child
        // that fills a pipe never deadlocks against the wait below.
        if let (Some(bytes), Some(mut stdin)) = (cmd.stdin.clone(), child.stdin.take()) {
            thread::spawn(move || {
                let _ = stdin.write_all(&bytes);
            });
        }
        let stdout = child.stdout.take().map(drain);
        let stderr = child.stderr.take().map(drain);

        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .with_context(|| format!("waiting for `{rendered}`"))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("`{rendered}` timed out after {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        };

        Ok(CmdOutput {
            code: status.code(),
            stdout: collect(stdout),
            stderr: collect(stderr),
        })
    }

    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn dir_exists(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        dirs::home_dir()
    }

    fn is_root(&self) -> bool {
        *self.root.get_or_init(|| self.probe_root())
    }
}

fn drain<R: Read + Send + 'static>(mut pipe: R) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

/// Lossily decoded output; empty when the pipe was never opened or its
/// reader panicked.
fn collect(reader: Option<JoinHandle<Vec<u8>>>) -> String {
    reader
        .and_then(|h| h.join().ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// `--dry-run`: queries and reads reach the wrapped executor; a mutating
/// command is recorded and answered with a synthetic success. The recorded
/// lines are what the command reports.
pub struct DryRunExecutor<'a> {
    inner: &'a dyn Executor,
    recorded: Mutex<Vec<String>>,
}

impl<'a> DryRunExecutor<'a> {
    pub fn new(inner: &'a dyn Executor) -> Self {
        Self {
            inner,
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Rendered lines of the mutating commands that would have run, in order.
    pub fn recorded(&self) -> Vec<String> {
        lock(&self.recorded).clone()
    }
}

impl Executor for DryRunExecutor<'_> {
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        if cmd.mutating {
            lock(&self.recorded).push(cmd.render());
            return Ok(CmdOutput {
                code: Some(0),
                ..CmdOutput::default()
            });
        }
        self.inner.run(cmd)
    }

    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner.read_file(path)
    }

    fn dir_exists(&self, path: &Path) -> bool {
        self.inner.dir_exists(path)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.inner.home_dir()
    }

    fn is_root(&self) -> bool {
        self.inner.is_root()
    }
}
