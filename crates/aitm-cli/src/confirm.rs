//! Operator confirmation for commands that ask before they act.
//!
//! A command that must not run unseen (a `ca.*` trust-store change) returns a
//! question from `Command::confirm_prompt`; `Cli::dispatch` puts it to the
//! `Confirmer` unless the operator passed the reserved `--yes` flag. The CLI
//! never learns which commands ask: it only relays the question.
//!
//! The question is structured text in the line protocol of
//! `aitm_term::prompt` (spec D16, AC-W2-8; plan C47): the first line says what
//! is about to happen, a line behind two spaces is a detail printed whole and
//! dim (a fingerprint, a location), a last line ending in `?` is the short
//! final ask, and every other line is a note wrapped to the terminal width.
//! [`TtyConfirmer`] renders it with [`render_confirm`] for the capabilities
//! it measured on stderr, or for the [`Caps`] a caller injected through
//! [`TtyConfirmer::with_caps`], and writes the rendered bytes itself; it
//! composes no human-facing text of its own.

use std::io::{BufRead, IsTerminal, Write};

use aitm_term::caps::{Caps, ColorChoice};
use aitm_term::prompt::{render_confirm, ConfirmPrompt};

/// Puts a yes/no question to the operator.
pub trait Confirmer: Send + Sync {
    /// `Ok(true)` only when the operator answered yes; `Err` when the question
    /// could not be asked at all.
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool>;
}

/// Asks on the terminal: the prompt rendered through the layer, ending in
/// `[y/N] `, on stderr; one line read from stdin. Without a terminal it
/// refuses and points at `--yes`, so a script never hangs on a question
/// nobody will see.
pub struct TtyConfirmer {
    interactive: bool,
    caps: Caps,
}

impl TtyConfirmer {
    /// Interactive exactly when stdin is a terminal.
    pub fn from_stdin() -> Self {
        Self::new(std::io::stdin().is_terminal())
    }

    /// Force the interactive decision (tests, or a caller that already knows).
    /// The prompt is rendered for stderr's measured capabilities until
    /// [`TtyConfirmer::with_caps`] says otherwise.
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            caps: Caps::detect_stderr(ColorChoice::Auto),
        }
    }

    /// Render the prompt for `caps` instead of stderr's measured
    /// capabilities (tests, or a caller that already honoured `--color`).
    pub fn with_caps(mut self, caps: Caps) -> Self {
        self.caps = caps;
        self
    }

    /// The prompt on `out`, the answer from `input`: the seam [`Confirmer::confirm`]
    /// drives with the locked stderr and stdin, and tests drive with buffers.
    /// Non-interactive refuses before writing a byte.
    pub(crate) fn confirm_with(
        &self,
        prompt: &str,
        out: &mut dyn Write,
        input: &mut dyn BufRead,
    ) -> anyhow::Result<bool> {
        if !self.interactive {
            anyhow::bail!(
                "needs confirmation but stdin is not a terminal; \
                 pass --yes to confirm non-interactively"
            );
        }
        let rendered = render_confirm(&self.caps, &ConfirmPrompt::parse(prompt));
        out.write_all(rendered.as_bytes())?;
        out.flush()?;
        let mut line = String::new();
        // EOF leaves the line empty, which is a "no".
        input.read_line(&mut line)?;
        Ok(is_yes(&line))
    }
}

impl Confirmer for TtyConfirmer {
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        self.confirm_with(
            prompt,
            &mut std::io::stderr().lock(),
            &mut std::io::stdin().lock(),
        )
    }
}

/// `y`/`yes`, trimmed and case-insensitive; anything else is no.
fn is_yes(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// What a UTF-8 pipe gets (plan rule 13).
    fn piped_utf8() -> Caps {
        Caps {
            tty: false,
            color: false,
            unicode: true,
            animate: false,
            width: 80,
            ci: false,
        }
    }

    const FINGERPRINT: &str = "5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE";

    const CA_NOTE: &str = "Every TLS client that uses that store will then trust certificates this proxy mints. The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.";

    /// The `aitm ca install` text exactly as `aitm-ca`'s `Op::prompt`
    /// composes it (plan task 7, mock-up M-W2-6).
    fn ca_install_text() -> String {
        format!(
            "Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 {FINGERPRINT}\n{CA_NOTE}\nInstall it?"
        )
    }

    /// Puts `prompt` to a confirmer with `input` on stdin and a `Vec<u8>` for
    /// stderr; returns the answer and what the operator saw.
    fn ask(confirmer: &TtyConfirmer, prompt: &str, input: &str) -> (anyhow::Result<bool>, String) {
        let mut out: Vec<u8> = Vec::new();
        let mut input = Cursor::new(input.as_bytes().to_vec());
        let answer = confirmer.confirm_with(prompt, &mut out, &mut input);
        (answer, String::from_utf8(out).expect("the prompt is UTF-8"))
    }

    #[test]
    fn interactive_prompt_renders_through_the_layer() {
        let confirmer = TtyConfirmer::new(true).with_caps(piped_utf8());
        let (answer, out) = ask(&confirmer, &ca_install_text(), "n\n");
        assert!(!answer.expect("an interactive prompt is answerable"));
        assert_eq!(
            out,
            "Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE\n  Every TLS client that uses that store will then trust certificates this proxy\n  mints. The embedded obscura browser is unaffected; it trusts the CA via\n  --ca-cert.\nInstall it? [y/N] "
        );
    }

    #[test]
    fn yes_and_eof() {
        let confirmer = TtyConfirmer::new(true).with_caps(piped_utf8());
        let prompt = "Inject 1 packet to 127.0.0.1:9 on lo0?";

        let (answer, out) = ask(&confirmer, prompt, "y\n");
        assert!(answer.expect("answerable"));
        // A single-line prompt is the wrapped question plus the tail (C47).
        assert_eq!(out, "Inject 1 packet to 127.0.0.1:9 on lo0? [y/N] ");

        let (answer, out) = ask(&confirmer, prompt, "YES\n");
        assert!(answer.expect("answerable"));
        assert_eq!(out, "Inject 1 packet to 127.0.0.1:9 on lo0? [y/N] ");

        // EOF leaves the line empty, which is a "no".
        let (answer, out) = ask(&confirmer, prompt, "");
        assert!(!answer.expect("answerable"));
        assert_eq!(out, "Inject 1 packet to 127.0.0.1:9 on lo0? [y/N] ");
    }

    #[test]
    fn non_interactive_refuses_and_points_at_yes() {
        let confirmer = TtyConfirmer::new(false);
        let (answer, out) = ask(&confirmer, &ca_install_text(), "y\n");
        let err = answer.expect_err("without a terminal the question cannot be asked");
        assert!(
            err.to_string()
                .contains("pass --yes to confirm non-interactively"),
            "{err}"
        );
        assert_eq!(out, "", "nothing is written when the question is refused");
    }
}
