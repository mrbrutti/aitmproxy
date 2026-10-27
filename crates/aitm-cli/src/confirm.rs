//! Operator confirmation for commands that ask before they act.
//!
//! A command that must not run unseen (a `ca.*` trust-store change) returns a
//! question from `Command::confirm_prompt`; `Cli::dispatch` puts it to the
//! `Confirmer` unless the operator passed the reserved `--yes` flag. The CLI
//! never learns which commands ask: it only relays the question.

use std::io::{BufRead, IsTerminal, Write};

/// Puts a yes/no question to the operator.
pub trait Confirmer: Send + Sync {
    /// `Ok(true)` only when the operator answered yes; `Err` when the question
    /// could not be asked at all.
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool>;
}

/// Asks on the terminal: `<prompt> [y/N] ` on stderr, one line read from stdin.
/// Without a terminal it refuses and points at `--yes`, so a script never
/// hangs on a question nobody will see.
pub struct TtyConfirmer {
    interactive: bool,
}

impl TtyConfirmer {
    /// Interactive exactly when stdin is a terminal.
    pub fn from_stdin() -> Self {
        Self::new(std::io::stdin().is_terminal())
    }

    /// Force the interactive decision (tests, or a caller that already knows).
    pub fn new(interactive: bool) -> Self {
        Self { interactive }
    }
}

impl Confirmer for TtyConfirmer {
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        if !self.interactive {
            anyhow::bail!(
                "needs confirmation but stdin is not a terminal; \
                 pass --yes to confirm non-interactively"
            );
        }
        let mut err = std::io::stderr().lock();
        write!(err, "{prompt} [y/N] ")?;
        err.flush()?;
        let mut line = String::new();
        // EOF leaves the line empty, which is a "no".
        std::io::stdin().lock().read_line(&mut line)?;
        Ok(is_yes(&line))
    }
}

/// `y`/`yes`, trimmed and case-insensitive; anything else is no.
fn is_yes(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
