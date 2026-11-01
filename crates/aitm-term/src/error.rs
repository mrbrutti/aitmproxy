//! The error panel: `ErrorReport`, `FixCommand` and the what/why/fix/log
//! renderers (spec D6, G4, T5/T6, mock-up M2; plan task 4, calls C5, C6, C27).
//!
//! Every error `aitm` shows is one [`ErrorReport`]: what happened, why, the
//! prose remedy, the one copy-safe fix command and where the log is. The rich
//! form (a TTY that may animate) paints the headline glyph, wraps the prose to
//! the two-space indent and shortens the log path to `~`; the plain form
//! (pipes, files, `-v`, CI) is `error: <what>` followed by unwrapped indented
//! lines and carries no escape byte. Nothing here touches a terminal or the
//! environment; the caller passes the [`Caps`] it measured.

use std::path::{Path, PathBuf};

use crate::caps::Caps;
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text;

/// Process exit status for an [`ErrorKind::Failure`] (spec D6).
pub const EXIT_FAILURE: i32 = 1;
/// Process exit status for an [`ErrorKind::Usage`] error (spec D6, AC-W1-13).
pub const EXIT_USAGE: i32 = 2;

/// The indent every body line of a panel carries (spec T3/T5).
const INDENT: &str = "  ";
/// The rich footer label, padded so the path starts in the card value column.
const LOG_LABEL: &str = "  Log           ";
/// What a usage error points at until wave 2 generates per-verb help (D6 rule 4).
const HELP_COMMAND: &str = "aitm --help";

/// Which family an error belongs to; it decides the exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// The operator asked for something the command line cannot mean; exit 2.
    Usage,
    /// The command was understood and failed; exit 1.
    Failure,
}

/// The one shell command that fixes or diagnoses the error. It is printed on
/// its own line, never wrapped, truncated or painted, so it stays copyable
/// (plan C5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixCommand(pub String);

/// An error as the operator should read it (spec D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReport {
    pub kind: ErrorKind,
    /// The headline: lowercase start and no trailing period when we compose
    /// it; verbatim when the core did (spec T6).
    pub what: String,
    /// Cause sentences, or the `anyhow` chain, one per entry.
    pub why: Vec<String>,
    /// The prose remedy.
    pub fix: Option<String>,
    /// The copy-safe command, if there is one.
    pub command: Option<FixCommand>,
    /// Where the log file is, if one was opened.
    pub log: Option<PathBuf>,
}

impl ErrorReport {
    /// A [`ErrorKind::Failure`] with only its headline set.
    pub fn failure(what: impl Into<String>) -> Self {
        ErrorReport {
            kind: ErrorKind::Failure,
            what: what.into(),
            why: Vec::new(),
            fix: None,
            command: None,
            log: None,
        }
    }

    /// A [`ErrorKind::Usage`] error whose fix command is `aitm --help`.
    pub fn usage(what: impl Into<String>) -> Self {
        ErrorReport {
            kind: ErrorKind::Usage,
            command: Some(FixCommand(HELP_COMMAND.to_string())),
            ..Self::failure(what)
        }
    }

    /// [`EXIT_USAGE`] for a usage error, [`EXIT_FAILURE`] otherwise.
    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Usage => EXIT_USAGE,
            ErrorKind::Failure => EXIT_FAILURE,
        }
    }

    /// Replaces the cause sentences.
    pub fn with_why(self, why: Vec<String>) -> Self {
        ErrorReport { why, ..self }
    }

    /// Sets the prose remedy.
    pub fn with_fix(self, fix: impl Into<String>) -> Self {
        ErrorReport {
            fix: Some(fix.into()),
            ..self
        }
    }

    /// Sets the copy-safe fix command.
    pub fn with_command(self, cmd: impl Into<String>) -> Self {
        ErrorReport {
            command: Some(FixCommand(cmd.into())),
            ..self
        }
    }

    /// Sets, or clears, the log path shown in the footer.
    pub fn with_log(self, log: Option<PathBuf>) -> Self {
        ErrorReport { log, ..self }
    }

    /// The TTY panel of mock-up M2.
    ///
    /// The headline is the danger-painted failed glyph, a space and `what`.
    /// Each `why` sentence and the `fix` prose are word-wrapped to
    /// `caps.width` behind the two-space indent (spec T5). When a command is
    /// set, a blank line and `  ▸ <command>` follow, printed whole whatever
    /// the width (plan C5). When a log path is set, a blank line and the
    /// `Log` footer follow, the path shortened with `~` for `home`. An absent
    /// block emits nothing, not even its blank line.
    pub fn render_rich(&self, caps: &Caps, glyphs: &Glyphs, home: Option<&Path>) -> String {
        let width = usize::from(caps.width);
        let mut out = String::new();

        out.push_str(&paint(caps, Role::Danger, glyphs.failed));
        out.push(' ');
        out.push_str(&self.what);
        out.push('\n');

        for sentence in self.why.iter().chain(self.fix.iter()) {
            for line in text::wrap(sentence, width, INDENT) {
                out.push_str(&line);
                out.push('\n');
            }
        }

        if let Some(FixCommand(command)) = &self.command {
            out.push('\n');
            out.push_str(INDENT);
            out.push_str(glyphs.fix);
            out.push(' ');
            out.push_str(command);
            out.push('\n');
        }

        if let Some(log) = &self.log {
            out.push('\n');
            out.push_str(LOG_LABEL);
            out.push_str(&text::tilde(log, home));
            out.push('\n');
        }

        out
    }

    /// The piped panel of mock-up M2: `error: <what>`, each `why` and `fix`
    /// sentence as one indented line (never wrapped), then `  fix: <command>`
    /// and `  log: <path>` when set. The log path is printed in full (plan
    /// C7). No glyph and no escape byte appear; the `Glyphs` parameter keeps
    /// the renderer pair symmetric for callers that hold one.
    pub fn render_plain(&self, _glyphs: &Glyphs) -> String {
        let mut out = format!("error: {}\n", self.what);
        for sentence in self.why.iter().chain(self.fix.iter()) {
            out.push_str(INDENT);
            out.push_str(sentence);
            out.push('\n');
        }
        if let Some(FixCommand(command)) = &self.command {
            out.push_str(INDENT);
            out.push_str("fix: ");
            out.push_str(command);
            out.push('\n');
        }
        if let Some(log) = &self.log {
            out.push_str(INDENT);
            out.push_str("log: ");
            out.push_str(&log.display().to_string());
            out.push('\n');
        }
        out
    }

    /// [`render_rich`](Self::render_rich) when the stream may animate, else
    /// [`render_plain`](Self::render_plain) (plan C6), with the glyph set the
    /// caps select.
    pub fn render(&self, caps: &Caps, home: Option<&Path>) -> String {
        let glyphs = Glyphs::for_caps(caps);
        if caps.animate {
            self.render_rich(caps, glyphs, home)
        } else {
            self.render_plain(glyphs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;
    use crate::glyphs::RICH;
    use std::path::{Path, PathBuf};

    /// A width-80 TTY that allows no colour: the M2 panel without SGR.
    fn tty_no_color() -> Caps {
        Caps {
            tty: true,
            color: false,
            unicode: true,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    /// The M2 report: port in use, one cause sentence, the remedy, the `lsof`
    /// command and the log path.
    fn m2_report() -> ErrorReport {
        ErrorReport::failure("cannot start: the proxy port 127.0.0.1:8080 is already in use")
            .with_why(vec![
                "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.".to_string(),
            ])
            .with_fix(
                "Free it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.",
            )
            .with_command("lsof -nP -iTCP:8080 -sTCP:LISTEN")
            .with_log(Some(PathBuf::from(
                "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log",
            )))
    }

    const USAGE_WHAT: &str = "usage: aitm [--config <path>] tui (takes no further arguments)";

    #[test]
    fn usage_report_exits_2_and_points_at_help() {
        let usage = ErrorReport::usage(USAGE_WHAT);
        assert_eq!(usage.exit_code(), 2);
        assert_eq!(usage.exit_code(), EXIT_USAGE);
        assert_eq!(usage.kind, ErrorKind::Usage);
        assert_eq!(usage.what, USAGE_WHAT);
        assert_eq!(usage.command, Some(FixCommand("aitm --help".into())));
        assert_eq!(usage.why, Vec::<String>::new());
        assert_eq!(usage.fix, None);
        assert_eq!(usage.log, None);

        let failure = ErrorReport::failure("x");
        assert_eq!(failure.exit_code(), 1);
        assert_eq!(failure.exit_code(), EXIT_FAILURE);
        assert_eq!(failure.kind, ErrorKind::Failure);
        assert_eq!(failure.command, None);
    }

    #[test]
    fn rich_panel_matches_m2_without_color() {
        let caps = tty_no_color();
        let home = Path::new("/Users/matt");
        let expected = "✕ cannot start: the proxy port 127.0.0.1:8080 is already in use\n  It is most likely held by another running `aitm`, the aitmproxy macOS app's\n  embedded core, or another program.\n  Free it, or set `listen:` to another address in\n  /Users/matt/Library/Application Support/aitmproxy/config.yaml.\n\n  ▸ lsof -nP -iTCP:8080 -sTCP:LISTEN\n\n  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log\n";
        assert_eq!(m2_report().render_rich(&caps, &RICH, Some(home)), expected);
        // `render` picks the rich form on an animating stream (plan C6).
        assert_eq!(m2_report().render(&caps, Some(home)), expected);
    }

    #[test]
    fn plain_panel_matches_m2() {
        let expected = "error: cannot start: the proxy port 127.0.0.1:8080 is already in use\n  It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.\n  Free it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.\n  fix: lsof -nP -iTCP:8080 -sTCP:LISTEN\n  log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log\n";
        let out = m2_report().render_plain(&RICH);
        assert_eq!(out, expected);
        assert!(
            !out.as_bytes().contains(&0x1b),
            "the plain panel must carry no escape byte"
        );
        // `render` picks the plain form on a non-animating stream, even one
        // whose locale would otherwise allow rich glyphs, and prints the full
        // log path (plan C6, C7; mock-up M2 piped).
        let piped = Caps {
            unicode: true,
            ..Caps::plain()
        };
        assert_eq!(
            m2_report().render(&piped, Some(Path::new("/Users/matt"))),
            expected
        );
    }

    #[test]
    fn rich_panel_paints_the_headline_glyph_only() {
        let caps = Caps {
            color: true,
            ..tty_no_color()
        };
        let out = m2_report().render_rich(&caps, &RICH, Some(Path::new("/Users/matt")));
        assert!(
            out.starts_with("\x1b[31m✕\x1b[0m cannot start"),
            "headline must open with the danger-painted glyph: {out:?}"
        );
        let lsof = out
            .lines()
            .find(|l| l.contains("lsof"))
            .unwrap_or_else(|| panic!("no lsof line in {out:?}"));
        assert_eq!(lsof, "  ▸ lsof -nP -iTCP:8080 -sTCP:LISTEN");
        assert!(
            !lsof.as_bytes().contains(&0x1b),
            "the fix command line must carry no escape byte: {lsof:?}"
        );
    }

    #[test]
    fn usage_panel_plain() {
        assert_eq!(
            ErrorReport::usage(USAGE_WHAT).render_plain(&RICH),
            "error: usage: aitm [--config <path>] tui (takes no further arguments)\n  fix: aitm --help\n"
        );
    }
}
