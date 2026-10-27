//! Shell-outs behind a trait.
//!
//! Every effect on the OS, and every read of OS state, goes through
//! [`Executor`], so platform logic is pure with respect to the host it runs
//! on: a trust-store operation is a sequence of [`CmdLine`]s that tests can
//! assert on by their rendered form.

use std::path::{Path, PathBuf};

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
