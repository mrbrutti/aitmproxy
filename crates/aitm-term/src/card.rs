//! The ready card: [`Card`]/[`Row`] and the rich and plain renderers (spec
//! D5, T3, M1, M1p, M6; plan task 3, calls C5, C6, C7, C27).
//!
//! A card is a headline (the pill line) and a list of labelled rows, each
//! with an optional next-step command. The rich renderer lays rows out in a
//! 14-column label field after a two-space indent so values start at column
//! 17; the plain renderer writes one `Label: value · command` line per row
//! and no headline (M1p). Neither truncates or wraps: URLs, paths and
//! commands stay copyable (C5). `~` shortening is the caller's job (C7), so
//! the card is mode-agnostic and the plain form prints whatever path it was
//! given.

use crate::caps::Caps;
use crate::glyphs::Glyphs;
use crate::style::{paint, Role};
use crate::text::width;

/// The two-space indent under the headline (spec T3).
pub const INDENT: &str = "  ";

/// The label column in the rich form (spec T3): `System proxy`, the longest
/// label at 12, plus 2.
pub const LABEL_WIDTH: usize = 14;

/// The ready card (spec D5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The pill line, written after the `ready` glyph in the rich form and
    /// omitted in the plain form.
    pub headline: String,
    /// The role the `ready` glyph is painted in (the headline text stays
    /// plain; spec T2 colours glyphs and state words only).
    pub headline_role: Role,
    pub rows: Vec<Row>,
}

/// One labelled row of a [`Card`] (spec D5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// One of spec T3's labels (`Bus`, `Scope`, `CA`, `System proxy`, …).
    pub label: &'static str,
    pub value: String,
    /// The role the value is painted in (`untrusted` and `off` are
    /// [`Role::Warning`], the `Log` path is [`Role::Dim`]).
    pub value_role: Role,
    /// A fix command printed under the row (rich) or after ` · ` (plain).
    pub next: Option<String>,
}

impl Card {
    /// The rich form (M1, M6): the painted `ready` glyph and the headline,
    /// then each row with its label padded to [`LABEL_WIDTH`] after
    /// [`INDENT`], then, when the row has a `next` command, the fix glyph and
    /// the command indented to the value column. Only the glyph and the
    /// value are painted; the fix line stays plain so it is copy-safe.
    pub fn render_rich(&self, caps: &Caps, glyphs: &Glyphs) -> String {
        let mut out = String::new();
        out.push_str(&paint(caps, self.headline_role, glyphs.ready));
        out.push(' ');
        out.push_str(&self.headline);
        out.push('\n');
        for row in &self.rows {
            out.push_str(INDENT);
            out.push_str(row.label);
            // A label wider than the column (a call-site bug; T3 caps them
            // at twelve) still gets one space so it is never glued to its value.
            let pad = LABEL_WIDTH.saturating_sub(width(row.label)).max(1);
            out.push_str(&" ".repeat(pad));
            out.push_str(&paint(caps, row.value_role, &row.value));
            out.push('\n');
            if let Some(next) = &row.next {
                out.push_str(INDENT);
                out.push_str(&" ".repeat(LABEL_WIDTH));
                out.push_str(glyphs.fix);
                out.push(' ');
                out.push_str(next);
                out.push('\n');
            }
        }
        out
    }

    /// The plain form (M1p): no headline; one `Label: value` line per row,
    /// followed by ` <sep> <command>` when the row has a `next` command.
    /// Zero escape bytes.
    pub fn render_plain(&self, glyphs: &Glyphs) -> String {
        let mut out = String::new();
        for row in &self.rows {
            out.push_str(row.label);
            out.push_str(": ");
            out.push_str(&row.value);
            if let Some(next) = &row.next {
                out.push(' ');
                out.push_str(glyphs.sep);
                out.push(' ');
                out.push_str(next);
            }
            out.push('\n');
        }
        out
    }

    /// [`Card::render_rich`] when `caps.animate`, else
    /// [`Card::render_plain`] (plan C6), with the glyph set
    /// [`Glyphs::for_caps`] picks.
    pub fn render(&self, caps: &Caps) -> String {
        let glyphs = Glyphs::for_caps(caps);
        if caps.animate {
            self.render_rich(caps, glyphs)
        } else {
            self.render_plain(glyphs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glyphs::{ASCII, RICH};

    /// The M1 card with the given `Log` value: M1 passes the `~`-shortened
    /// path, M1p the full one (C7).
    fn m1_card(log: &str) -> Card {
        Card {
            headline: "aitmproxy · listening 127.0.0.1:8080 · CA untrusted".to_string(),
            headline_role: Role::Success,
            rows: vec![
                Row {
                    label: "Bus",
                    value: "stdio (MCP)".to_string(),
                    value_role: Role::Plain,
                    next: None,
                },
                Row {
                    label: "Scope",
                    value: "Nothing is decrypted until a host is in Scope.".to_string(),
                    value_role: Role::Plain,
                    next: Some("aitm scope add --host <host>".to_string()),
                },
                Row {
                    label: "CA",
                    value: "untrusted".to_string(),
                    value_role: Role::Warning,
                    next: Some("aitm ca install".to_string()),
                },
                Row {
                    label: "System proxy",
                    value: "off".to_string(),
                    value_role: Role::Warning,
                    next: Some("aitm proxy system set".to_string()),
                },
                Row {
                    label: "Log",
                    value: log.to_string(),
                    value_role: Role::Dim,
                    next: None,
                },
            ],
        }
    }

    const FULL_LOG: &str = "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log";
    const TILDE_LOG: &str = "~/Library/Application Support/aitmproxy/logs/aitm.log";

    /// M1p, byte for byte.
    const M1P: &str = "Bus: stdio (MCP)\n\
        Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>\n\
        CA: untrusted · aitm ca install\n\
        System proxy: off · aitm proxy system set\n\
        Log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log\n";

    /// The nine M1 card lines, byte for byte, colour off.
    const M1: &str = "● aitmproxy · listening 127.0.0.1:8080 · CA untrusted\n\
        \x20 Bus           stdio (MCP)\n\
        \x20 Scope         Nothing is decrypted until a host is in Scope.\n\
        \x20               ▸ aitm scope add --host <host>\n\
        \x20 CA            untrusted\n\
        \x20               ▸ aitm ca install\n\
        \x20 System proxy  off\n\
        \x20               ▸ aitm proxy system set\n\
        \x20 Log           ~/Library/Application Support/aitmproxy/logs/aitm.log\n";

    /// A UTF-8 TTY with colour on or off.
    fn tty(color: bool) -> Caps {
        Caps {
            tty: true,
            color,
            unicode: true,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    #[test]
    fn plain_card_is_label_colon_value_lines() {
        assert_eq!(m1_card(FULL_LOG).render_plain(&RICH), M1P);
    }

    #[test]
    fn rich_card_matches_m1_without_color() {
        let out = m1_card(TILDE_LOG).render_rich(&tty(false), &RICH);
        assert_eq!(out, M1);
        assert_eq!(out.lines().count(), 9);
        assert!(
            !out.as_bytes().contains(&0x1b),
            "colour off must emit no escape byte"
        );
        // Values start at column 17: two of indent plus the 14-wide label.
        for line in out.lines().skip(1) {
            assert_eq!(&line[..INDENT.len()], INDENT, "{line:?}");
            assert_eq!(
                line.chars().nth(INDENT.len() + LABEL_WIDTH - 1),
                Some(' '),
                "{line:?}"
            );
            assert_ne!(
                line.chars().nth(INDENT.len() + LABEL_WIDTH),
                Some(' '),
                "{line:?}"
            );
        }
    }

    #[test]
    fn rich_card_paints_only_glyph_and_value() {
        let out = m1_card(TILDE_LOG).render_rich(&tty(true), &RICH);
        assert!(
            out.starts_with(
                "\x1b[32m●\x1b[0m aitmproxy · listening 127.0.0.1:8080 · CA untrusted\n"
            ),
            "{out:?}"
        );
        assert!(
            out.contains("  CA            \x1b[33muntrusted\x1b[0m\n"),
            "{out:?}"
        );
        // Plain-role values and the fix lines carry no escape at all.
        assert!(out.contains("\n  Bus           stdio (MCP)\n"), "{out:?}");
        assert!(
            out.contains("\n                ▸ aitm ca install\n"),
            "{out:?}"
        );
        assert!(out.contains("\n  Log           \x1b[2m~/Library/Application Support/aitmproxy/logs/aitm.log\x1b[0m\n"), "{out:?}");
    }

    #[test]
    fn ascii_plain_card_uses_the_ascii_separator() {
        let out = m1_card(FULL_LOG).render_plain(&ASCII);
        assert!(out.contains("CA: untrusted - aitm ca install\n"), "{out:?}");
        assert_eq!(
            out,
            "Bus: stdio (MCP)\n\
             Scope: Nothing is decrypted until a host is in Scope. - aitm scope add --host <host>\n\
             CA: untrusted - aitm ca install\n\
             System proxy: off - aitm proxy system set\n\
             Log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log\n"
        );
    }

    #[test]
    fn render_picks_plain_when_animation_is_off() {
        let card = m1_card(FULL_LOG);
        let still = tty(true).without_animation();
        let out = card.render(&still);
        assert_eq!(out, card.render_plain(&RICH));
        assert_eq!(out, M1P);
        assert!(
            !out.as_bytes().contains(&0x1b),
            "plain form must emit no escape byte even with colour on"
        );

        // And the rich form when animation is on, with the glyph set the
        // caps select.
        assert_eq!(
            m1_card(TILDE_LOG).render(&tty(false)),
            m1_card(TILDE_LOG).render_rich(&tty(false), &RICH)
        );
        let ascii_pipe = Caps::plain();
        assert_eq!(card.render(&ascii_pipe), card.render_plain(&ASCII));
    }

    // ---- tester additions ----

    #[test]
    fn empty_card_renders_its_headline_line_rich_and_nothing_plain() {
        let empty = Card {
            headline: String::new(),
            headline_role: Role::Success,
            rows: Vec::new(),
        };
        assert_eq!(empty.render_rich(&tty(false), &RICH), "● \n");
        assert_eq!(empty.render_rich(&tty(true), &RICH), "\x1b[32m●\x1b[0m \n");
        assert_eq!(empty.render_rich(&tty(false), &ASCII), "* \n");
        assert_eq!(empty.render_plain(&RICH), "");
        assert_eq!(empty.render(&Caps::plain()), "");
    }

    #[test]
    fn card_rows_are_never_truncated_however_narrow_the_terminal() {
        // Width is not consulted at all: ten columns, zero columns and
        // eighty give the same bytes (plan C5: URLs, paths and commands stay
        // copyable).
        let card = m1_card(TILDE_LOG);
        let narrow = Caps {
            width: 10,
            ..tty(false)
        };
        assert_eq!(card.render_rich(&narrow, &RICH), M1);
        let zero = Caps {
            width: 0,
            ..tty(false)
        };
        assert_eq!(card.render_rich(&zero, &RICH), M1);
        let narrow_pipe = Caps {
            width: 10,
            ..Caps::plain()
        };
        assert_eq!(
            m1_card(FULL_LOG).render(&narrow_pipe),
            m1_card(FULL_LOG).render_plain(&ASCII)
        );
    }

    #[test]
    fn a_label_wider_than_the_column_keeps_one_space_and_does_not_panic() {
        // T3 fixes the label set at twelve characters or fewer, so a wider
        // label is a call-site bug; the renderer only has to stay whole and
        // keep the label and value apart (fix task Q13).
        let card = Card {
            headline: "x".to_string(),
            headline_role: Role::Success,
            rows: vec![Row {
                label: "System proxy watchdog",
                value: "v".to_string(),
                value_role: Role::Plain,
                next: Some("aitm x".to_string()),
            }],
        };
        assert_eq!(
            card.render_rich(&tty(false), &RICH),
            "● x\n  System proxy watchdog v\n                ▸ aitm x\n"
        );
        assert_eq!(
            card.render_plain(&RICH),
            "System proxy watchdog: v · aitm x\n"
        );
    }

    #[test]
    fn rich_card_carries_no_bright_or_256_colour_sgr() {
        let out = m1_card(TILDE_LOG).render_rich(&tty(true), &RICH);
        assert!(!out.contains("\x1b[9"), "bright SGR forbidden: {out:?}");
        assert!(!out.contains("38;5"), "256-colour forbidden: {out:?}");
        assert!(!out.contains("38;2"), "truecolor forbidden: {out:?}");
        assert!(
            !out.contains("\x1b[4"),
            "background colour forbidden: {out:?}"
        );
        // Exactly the spans T2 allows: the glyph, two warning values and
        // the dim log path, each with its reset.
        assert_eq!(out.matches("\x1b[32m").count(), 1, "{out:?}");
        assert_eq!(out.matches("\x1b[33m").count(), 2, "{out:?}");
        assert_eq!(out.matches("\x1b[2m").count(), 1, "{out:?}");
        assert_eq!(out.matches("\x1b[0m").count(), 4, "{out:?}");
        assert_eq!(out.matches("\x1b[").count(), 8, "{out:?}");
    }
}
