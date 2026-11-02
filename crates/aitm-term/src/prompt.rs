//! The `[y/N]` prompt through the layer (spec D14, D16, AC-W2-8; plan task 3,
//! call C47): [`ConfirmPrompt`], parsed from a command's newline-separated
//! prompt text, and [`render_confirm`], which prints the question, the dim
//! details, the wrapped notes and the final ask ending in `[y/N] `.
//!
//! A command composes its prompt as a small line protocol (`aitm-ca`'s
//! `Op::prompt` is the model): the first line is the question; a line that
//! begins with two spaces is a detail printed whole and dim, never wrapped
//! (the SHA-256 fingerprint, a location); the last line, when it ends with
//! `?`, is the short final ask; every other line is a note wrapped to the
//! terminal width behind a two-space indent. A single-line prompt is the
//! question alone and gets the tail on its own line. Nothing here touches a
//! terminal or the environment; the caller passes the [`Caps`] it measured
//! and writes the string itself.

use std::borrow::Cow;

use crate::caps::Caps;
use crate::card::INDENT;
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text;

/// The answer hint; the renderer appends it, with a trailing space, after
/// the final ask. No command's prompt text carries it.
pub const YES_NO: &str = "[y/N]";

/// A confirmation prompt as the operator should read it (plan C47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmPrompt {
    /// The first line: what is about to happen, wrapped to width.
    pub question: String,
    /// Lines that began with two spaces, trimmed: printed whole and dim, one
    /// per line, so a fingerprint is never broken across lines.
    pub details: Vec<String>,
    /// Every other line: wrapped to width behind a two-space indent.
    pub notes: Vec<String>,
    /// The short final ask (`Install it?`); empty for a single-line prompt,
    /// whose question then carries the `[y/N]` tail itself.
    pub ask: String,
}

impl ConfirmPrompt {
    /// Parses the line protocol: `text` is split on `\n` and blank lines are
    /// skipped; the first line is the `question`; a line starting with two
    /// spaces is a `detail` (trimmed); the last line, when there is more than
    /// one line, it ends with `?` and it is not a detail, is the `ask`;
    /// everything else is a `note`. A single-line text is the question alone
    /// with an empty `ask`; an empty text is an empty question.
    pub fn parse(text: &str) -> ConfirmPrompt {
        let lines: Vec<&str> = text
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .collect();
        let mut prompt = ConfirmPrompt {
            question: String::new(),
            details: Vec::new(),
            notes: Vec::new(),
            ask: String::new(),
        };
        let Some((&question, rest)) = lines.split_first() else {
            return prompt;
        };
        prompt.question = question.to_string();
        let last = rest.len().saturating_sub(1);
        for (i, &line) in rest.iter().enumerate() {
            if line.starts_with(INDENT) {
                prompt.details.push(line.trim().to_string());
            } else if i == last && line.ends_with('?') {
                prompt.ask = line.to_string();
            } else {
                prompt.notes.push(line.to_string());
            }
        }
        prompt
    }
}

/// Renders `prompt` for `caps` (mock-up M-W2-6): the question wrapped to
/// `caps.width`; each detail on its own line behind [`INDENT`], printed
/// whole; each note wrapped to the width behind [`INDENT`]; then the ask,
/// a space, [`YES_NO`] and a space. When the ask is empty the ` [y/N] ` tail
/// is appended to the question's last line instead. There is no trailing
/// newline: the cursor waits after the space for the answer.
///
/// Every string from the prompt passes through [`text::sanitize`] (a
/// location path or a fingerprint cannot smuggle an escape sequence) and,
/// when the caps select the ASCII glyph set, `·` and `…` become their ASCII
/// twins (spec T1). Only the details are painted ([`Role::Dim`]), and only
/// on a stream that animates and allows colour; everywhere else the output
/// carries no escape byte (plan C6).
pub fn render_confirm(caps: &Caps, prompt: &ConfirmPrompt) -> String {
    let width = usize::from(caps.width);
    let glyphs = Glyphs::for_caps(caps);
    let rich = caps.animate && caps.color;
    let clean = |s: &str| -> String { asciify(caps, glyphs, &text::sanitize(s)).into_owned() };

    let mut lines = text::wrap(&clean(&prompt.question), width, "");
    let tail = format!(" {YES_NO} ");
    // With no ask the tail joins the question's last line now; with one it
    // closes the prompt after the details and notes. Either way `tail` is
    // moved once (fix Q11).
    let ask = if prompt.ask.is_empty() {
        match lines.last_mut() {
            Some(last) => last.push_str(&tail),
            // An empty prompt is a caller bug; the operator still gets a
            // tail to answer, and nothing panics.
            None => lines.push(tail),
        }
        None
    } else {
        Some(format!("{}{tail}", clean(&prompt.ask)))
    };
    for detail in &prompt.details {
        let detail = clean(detail);
        let detail = if rich {
            paint(caps, Role::Dim, &detail)
        } else {
            detail
        };
        lines.push(format!("{INDENT}{detail}"));
    }
    for note in &prompt.notes {
        lines.extend(text::wrap(&clean(note), width, INDENT));
    }
    lines.extend(ask);
    lines.join("\n")
}

/// `s` with `·` and `…` replaced by the glyph set's `sep` and `ellipsis`
/// when the caps select the ASCII set (spec T1); borrowed and unchanged
/// otherwise. The same rule the reporter applies as bytes leave it; the
/// prompt is written by its caller, so it substitutes here.
fn asciify<'a>(caps: &Caps, glyphs: &Glyphs, s: &'a str) -> Cow<'a, str> {
    if caps.unicode || !s.contains(['·', '…']) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(s.replace('·', glyphs.sep).replace('…', glyphs.ellipsis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;

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

    /// A colour-capable 80-column terminal (plan rule 13).
    fn tty80() -> Caps {
        Caps {
            tty: true,
            color: true,
            unicode: true,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    const FINGERPRINT: &str = "5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE";

    const CA_NOTE: &str = "Every TLS client that uses that store will then trust certificates this proxy mints. The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.";

    /// The `aitm ca install` text exactly as `aitm-ca`'s `Op::prompt`
    /// composes it (plan task 7).
    fn ca_install_text(fingerprint: &str) -> String {
        format!(
            "Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 {fingerprint}\n{CA_NOTE}\nInstall it?"
        )
    }

    #[test]
    fn parse_splits_question_details_notes_and_ask() {
        assert_eq!(
            ConfirmPrompt::parse(&ca_install_text("AB:CD")),
            ConfirmPrompt {
                question: "Install the aitmproxy root CA into the login keychain (scope user)?"
                    .to_string(),
                details: vec!["SHA-256 AB:CD".to_string()],
                notes: vec![CA_NOTE.to_string()],
                ask: "Install it?".to_string(),
            }
        );
    }

    #[test]
    fn parse_single_line_is_a_bare_question() {
        let text = "Inject 1 packet to 127.0.0.1:9 on lo0?";
        assert_eq!(
            ConfirmPrompt::parse(text),
            ConfirmPrompt {
                question: text.to_string(),
                details: Vec::new(),
                notes: Vec::new(),
                ask: String::new(),
            }
        );
    }

    #[test]
    fn render_confirm_puts_the_fingerprint_on_its_own_line() {
        let prompt = ConfirmPrompt::parse(&ca_install_text(FINGERPRINT));
        assert_eq!(
            render_confirm(&piped_utf8(), &prompt),
            "Install the aitmproxy root CA into the login keychain (scope user)?\n  SHA-256 5B:A7:31:83:97:1A:96:38:4E:93:78:8D:54:AA:3E:EA:49:17:18:6E:50:A4:52:A7:66:E3:93:15:3E:8F:DB:AE\n  Every TLS client that uses that store will then trust certificates this proxy\n  mints. The embedded obscura browser is unaffected; it trusts the CA via\n  --ca-cert.\nInstall it? [y/N] "
        );
    }

    #[test]
    fn render_confirm_single_line_appends_the_tail() {
        let prompt = ConfirmPrompt::parse("Inject 1 packet to 127.0.0.1:9 on lo0?");
        assert_eq!(
            render_confirm(&piped_utf8(), &prompt),
            "Inject 1 packet to 127.0.0.1:9 on lo0? [y/N] "
        );
    }

    #[test]
    fn render_confirm_rich_dims_the_details_only() {
        let prompt = ConfirmPrompt::parse(&ca_install_text(FINGERPRINT));
        let out = render_confirm(&tty80(), &prompt);
        let lines: Vec<&str> = out.split('\n').collect();
        assert_eq!(lines.len(), 6, "{out:?}");
        assert_eq!(
            lines[0],
            "Install the aitmproxy root CA into the login keychain (scope user)?"
        );
        assert_eq!(
            format!("{}\n", lines[1]),
            format!("  \x1b[2mSHA-256 {FINGERPRINT}\x1b[0m\n")
        );
        assert_eq!(
            lines[2],
            "  Every TLS client that uses that store will then trust certificates this proxy"
        );
        assert_eq!(lines[5], "Install it? [y/N] ");
        for (i, line) in lines.iter().enumerate() {
            if i == 1 {
                continue;
            }
            assert!(
                !line.as_bytes().contains(&0x1b),
                "only the detail line is painted; line {i} is {line:?}"
            );
        }
        // Exactly one painted span: the dim introducer and its reset.
        assert_eq!(out.matches("\x1b[").count(), 2, "{out:?}");
        assert!(!out.ends_with('\n'), "the cursor waits after the space");
    }

    #[test]
    fn render_confirm_plain_has_no_escape_byte() {
        let prompt = ConfirmPrompt::parse(&ca_install_text(FINGERPRINT));
        // Colour forced on a stream that does not animate: still plain (C6).
        let forced_pipe = Caps {
            tty: false,
            color: true,
            unicode: true,
            animate: false,
            width: 80,
            ci: false,
        };
        let out = render_confirm(&forced_pipe, &prompt);
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
        assert_eq!(out, render_confirm(&piped_utf8(), &prompt));
        // An animating TTY without colour is plain too.
        let tty_no_color = Caps {
            color: false,
            ..tty80()
        };
        let out = render_confirm(&tty_no_color, &prompt);
        assert!(!out.as_bytes().contains(&0x1b), "{out:?}");
        assert_eq!(out, render_confirm(&piped_utf8(), &prompt));
    }

    // ---- the two rules the plan states without naming a test ----

    #[test]
    fn render_confirm_ascii_substitutes_the_separator_and_the_ellipsis() {
        let prompt = ConfirmPrompt::parse(
            "Trust 3 hosts · scope user?\n  SHA-256 AB…CD\nThe list is long …\nTrust them · now?",
        );
        assert_eq!(
            render_confirm(&Caps::plain(), &prompt),
            "Trust 3 hosts - scope user?\n  SHA-256 AB...CD\n  The list is long ...\nTrust them - now? [y/N] "
        );
        // A UTF-8 pipe keeps the rich characters.
        assert_eq!(
            render_confirm(&piped_utf8(), &prompt),
            "Trust 3 hosts · scope user?\n  SHA-256 AB…CD\n  The list is long …\nTrust them · now? [y/N] "
        );
    }

    #[test]
    fn render_confirm_sanitizes_every_string() {
        // A location path or fingerprint under an attacker's influence cannot
        // smuggle an escape sequence into the operator's terminal.
        let prompt = ConfirmPrompt::parse(
            "Install into /tmp/\x1b[31mred\x1b[0m (scope user)?\n  SHA-256 \x07AB\n  detail\u{202e}\nA note\u{200b}here.\nInstall\tit?",
        );
        let out = render_confirm(&tty80(), &prompt);
        assert_eq!(
            out,
            "Install into /tmp/\u{FFFD}[31mred\u{FFFD}[0m (scope user)?\n  \x1b[2mSHA-256 \u{FFFD}AB\x1b[0m\n  \x1b[2mdetail\u{FFFD}\x1b[0m\n  A note\u{FFFD}here.\nInstall it? [y/N] "
        );
        assert_eq!(out.matches("\x1b[").count(), 4, "{out:?}");
    }

    #[test]
    fn parse_skips_blank_lines_and_a_last_line_without_a_question_mark_is_a_note() {
        let prompt = ConfirmPrompt::parse("\nQ?\n\n  d\n\nnote one\nnote two\n");
        assert_eq!(
            prompt,
            ConfirmPrompt {
                question: "Q?".to_string(),
                details: vec!["d".to_string()],
                notes: vec!["note one".to_string(), "note two".to_string()],
                ask: String::new(),
            }
        );
        // Without an ask the tail sits on the question's last line.
        assert_eq!(
            render_confirm(&piped_utf8(), &prompt),
            "Q? [y/N] \n  d\n  note one\n  note two"
        );
        // A detail as the last line is a detail, not an ask, even with `?`.
        let prompt = ConfirmPrompt::parse("Q?\n  really?");
        assert_eq!(prompt.details, vec!["really?".to_string()]);
        assert_eq!(prompt.ask, "");
        // A two-line text whose last line ends in `?` is question and ask.
        let prompt = ConfirmPrompt::parse("Q?\nSure?");
        assert_eq!(prompt.notes, Vec::<String>::new());
        assert_eq!(prompt.ask, "Sure?");
        assert_eq!(render_confirm(&piped_utf8(), &prompt), "Q?\nSure? [y/N] ");
    }

    #[test]
    fn render_confirm_wraps_the_question_and_notes_to_width_but_never_a_detail() {
        let prompt = ConfirmPrompt::parse(
            "Remove the aitmproxy root CA from /very/long/location/path (scope user)?\n  SHA-256 AB:CD:EF:01:23:45:67:89\nRemove it?",
        );
        let narrow = Caps {
            width: 30,
            ..piped_utf8()
        };
        assert_eq!(
            render_confirm(&narrow, &prompt),
            "Remove the aitmproxy root CA\nfrom /very/long/location/path\n(scope user)?\n  SHA-256 AB:CD:EF:01:23:45:67:89\nRemove it? [y/N] "
        );
        // An empty text still ends with the tail and never panics.
        assert_eq!(
            render_confirm(&piped_utf8(), &ConfirmPrompt::parse("")),
            " [y/N] "
        );
    }

    // ---- tester, wave-2 pass 1 (AC-W2-8; plan C47) ----

    /// The protocol is `\n`-separated (plan C47); a `\r` is content. CRLF
    /// text therefore never panics and no control byte reaches the terminal
    /// (the sanitiser folds `\r` to a space), the fingerprint detail is still
    /// its own line and exactly one tail is printed — but a final ask that
    /// ends in `\r` rather than `?` is read as a note, so the tail lands on
    /// the question line. No in-tree command composes CRLF.
    #[test]
    fn parse_tolerates_crlf_without_a_control_byte_in_the_output() {
        let prompt = ConfirmPrompt::parse("Q?\r\n  SHA-256 AB:CD\r\nInstall it?\r\n");
        assert_eq!(prompt.question, "Q?\r");
        assert_eq!(prompt.details, vec!["SHA-256 AB:CD".to_string()]);
        assert_eq!(prompt.notes, vec!["Install it?\r".to_string()]);
        assert_eq!(prompt.ask, "");
        let out = render_confirm(&piped_utf8(), &prompt);
        assert!(!out.contains('\r'), "{out:?}");
        assert!(
            !out.bytes().any(|b| b < 0x20 && b != b'\n'),
            "a control byte reached the output: {out:?}"
        );
        assert_eq!(out.matches("[y/N] ").count(), 1, "{out:?}");
        assert!(out.contains("\n  SHA-256 AB:CD\n"), "{out:?}");
        assert_eq!(out, "Q? [y/N] \n  SHA-256 AB:CD\n  Install it?");
        // Only the last line can be the ask: an earlier line ending in `?` is
        // a note.
        let prompt = ConfirmPrompt::parse("Q?\nReally?\nSure?");
        assert_eq!(prompt.notes, vec!["Really?".to_string()]);
        assert_eq!(prompt.ask, "Sure?");
        assert_eq!(
            render_confirm(&piped_utf8(), &prompt),
            "Q?\n  Really?\nSure? [y/N] "
        );
    }

    /// Oversized input: a 10 000-character unbreakable question is printed
    /// whole with the tail; 400 words wrap so that every line but the one
    /// carrying the tail fits the width. The tail is the one constant.
    #[test]
    fn render_confirm_oversized_questions_never_panic() {
        assert_eq!(YES_NO, "[y/N]");
        let long = "x".repeat(10_000);
        let out = render_confirm(&piped_utf8(), &ConfirmPrompt::parse(&long));
        assert_eq!(out, format!("{long} [y/N] "));
        let words = "word ".repeat(400);
        let out = render_confirm(&piped_utf8(), &ConfirmPrompt::parse(words.trim()));
        let lines: Vec<&str> = out.split('\n').collect();
        assert_eq!(lines.len(), 25, "{}", lines.len());
        for line in &lines[..lines.len() - 1] {
            assert_eq!(text::width(line), 79, "{line:?}");
        }
        assert!(lines[lines.len() - 1].ends_with(" [y/N] "));
        assert_eq!(out.matches("word").count(), 400);
    }
}
