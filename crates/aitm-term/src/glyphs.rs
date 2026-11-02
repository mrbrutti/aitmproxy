//! The brand glyph set and its ASCII twins (spec T1).
//!
//! Ambiguous-width glyphs (`●`, `○`, `·`, `─`, `…`) appear only at a line
//! start or between words, never inside an aligned column, so a
//! CJK-ambiguous-wide terminal cannot break alignment.

use crate::caps::Caps;

/// One glyph per role, plus the spinner frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Glyphs {
    /// The pill, a live listener row.
    pub ready: &'static str,
    /// A phase not yet started.
    pub pending: &'static str,
    /// A completed phase.
    pub done: &'static str,
    /// A failed phase, the error panel headline.
    pub failed: &'static str,
    /// A WARN event folded into the view.
    pub warn: &'static str,
    /// The one copy-safe fix command line.
    pub fix: &'static str,
    /// Between facts on one line.
    pub sep: &'static str,
    /// The card rule.
    pub rule: &'static str,
    /// Truncation.
    pub ellipsis: &'static str,
    /// The header line only; empty in ASCII.
    pub mark: &'static str,
    /// A running phase, TTY only.
    pub spinner: &'static [&'static str],
}

/// The rich (UTF-8) column of spec T1.
pub static RICH: Glyphs = Glyphs {
    ready: "●",
    pending: "○",
    done: "✓",
    failed: "✕",
    warn: "!",
    fix: "▸",
    sep: "·",
    rule: "─",
    ellipsis: "…",
    mark: "›•‹",
    spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
};

/// The ASCII column of spec T1.
pub static ASCII: Glyphs = Glyphs {
    ready: "*",
    pending: "o",
    done: "+",
    failed: "x",
    warn: "!",
    fix: ">",
    sep: "-",
    rule: "-",
    ellipsis: "...",
    mark: "",
    spinner: &["-", "\\", "|", "/"],
};

impl Glyphs {
    /// [`RICH`] when the caps allow Unicode glyphs, else [`ASCII`].
    pub fn for_caps(caps: &Caps) -> &'static Glyphs {
        if caps.unicode {
            &RICH
        } else {
            &ASCII
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;

    #[test]
    fn glyphs_follow_unicode() {
        let ascii = Glyphs::for_caps(&Caps::plain());
        assert!(
            std::ptr::eq(ascii, &ASCII),
            "plain caps select the ASCII set"
        );
        assert_eq!(ascii.done, "+");
        assert_eq!(ascii.mark, "");
        assert_eq!(ascii.spinner, ["-", "\\", "|", "/"]);

        let rich_caps = Caps {
            tty: true,
            color: true,
            unicode: true,
            animate: true,
            width: 120,
            ci: false,
        };
        let rich = Glyphs::for_caps(&rich_caps);
        assert!(
            std::ptr::eq(rich, &RICH),
            "unicode caps select the rich set"
        );
        assert_eq!(rich.done, "✓");
        assert_eq!(rich.spinner.len(), 10);
        assert_eq!(rich.spinner[0], "⠋");
        assert_eq!(rich.mark, "›•‹");
    }
}
