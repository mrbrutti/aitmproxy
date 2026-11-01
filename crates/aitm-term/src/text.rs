//! Text rules: display width, truncation, wrapping, `~` shortening and SGR
//! stripping (spec T5/T6; plan task 2).
//!
//! Width is measured with `unicode-width` on the text with its escape
//! sequences removed, so a painted glyph costs what the eye sees. East Asian
//! Ambiguous characters count as one column (the non-CJK reading); spec T1
//! keeps those glyphs out of aligned columns so that reading cannot break a
//! layout. Every function here is pure and allocation-only: no terminal, no
//! environment.

use std::path::Path;

use unicode_width::UnicodeWidthStr;

/// The Control Sequence Introducer every SGR (and cursor) sequence starts with.
const CSI: &str = "\x1b[";

/// SGR reset, appended when a truncation cuts inside a painted span.
const RESET: &str = "\x1b[0m";

/// Byte length of the control sequence at the start of `s`, which must begin
/// with [`CSI`]: the introducer, the parameter and intermediate bytes, and the
/// final byte (`0x40..=0x7e`). A sequence with no final byte runs to the end
/// of `s`. The final byte is ASCII, so the returned length is always a char
/// boundary.
fn csi_len(s: &str) -> usize {
    debug_assert!(s.starts_with(CSI));
    let body = &s[CSI.len()..];
    body.bytes()
        .position(|b| (0x40..=0x7e).contains(&b))
        .map_or(s.len(), |i| CSI.len() + i + 1)
}

/// Removes every `ESC [ … <final byte 0x40–0x7e>` control sequence from `s`:
/// SGR colour, cursor movement, clearing and the synchronized-update brackets
/// alike. An unterminated sequence hides everything after it (nothing of it
/// is visible); an `ESC` that is not followed by `[` is ordinary text and is
/// kept.
pub fn strip_sgr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(CSI) {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        rest = &rest[csi_len(rest)..];
    }
    out.push_str(rest);
    out
}

/// Display width of `s` in terminal columns, escape sequences excluded.
pub fn width(s: &str) -> usize {
    strip_sgr(s).width()
}

/// `s` unchanged when [`width`] fits in `max` columns; otherwise the longest
/// prefix whose width plus the ellipsis width is `<= max`, followed by
/// `ellipsis` (spec T5).
///
/// Escape sequences in the prefix are kept whole and cost no columns, so a
/// painted glyph at the start of a line survives. A sequence sitting exactly
/// at the cut is dropped with the text after it; if that leaves an SGR span
/// open, a reset follows the ellipsis so the attribute cannot bleed into the
/// next line. When `max` is smaller than the ellipsis itself only the
/// ellipsis is returned.
pub fn truncate(s: &str, max: usize, ellipsis: &str) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    let budget = max.saturating_sub(width(ellipsis));

    // `out` holds what we may keep (text and sequences); `visible` is the
    // same text without sequences, measured as a whole after every character
    // because `unicode-width` treats some sequences (ZWJ emoji, "\r\n") as a
    // unit rather than a sum of chars.
    let mut out = String::with_capacity(s.len());
    let mut visible = String::with_capacity(s.len());
    // Byte length of `out` at the last cut that fit, and whether an SGR span
    // was open there.
    let mut fit_len = 0;
    let mut open_at_fit = false;
    let mut open = false;

    let mut rest = s;
    while !rest.is_empty() {
        if rest.starts_with(CSI) {
            let seq = &rest[..csi_len(rest)];
            if seq.ends_with('m') {
                open = !matches!(seq, "\x1b[m" | "\x1b[0m");
            }
            out.push_str(seq);
            rest = &rest[seq.len()..];
            continue;
        }
        let Some(c) = rest.chars().next() else {
            break;
        };
        visible.push(c);
        if visible.width() > budget {
            break;
        }
        out.push(c);
        fit_len = out.len();
        open_at_fit = open;
        rest = &rest[c.len_utf8()..];
    }

    out.truncate(fit_len);
    out.push_str(ellipsis);
    if open_at_fit {
        out.push_str(RESET);
    }
    out
}

/// Greedy word wrap (spec T5): `s` is split on whitespace and the words are
/// packed, single-spaced, into lines of at most `width` columns, each line
/// prefixed with `indent`. A word wider than the room after the indent goes
/// on a line of its own, unbroken. Text with no words yields no lines.
pub fn wrap(s: &str, width: usize, indent: &str) -> Vec<String> {
    let room = width.saturating_sub(self::width(indent));
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0;
    for word in s.split_whitespace() {
        let word_width = self::width(word);
        if line.is_empty() {
            line.push_str(word);
            line_width = word_width;
        } else if line_width + 1 + word_width <= room {
            line.push(' ');
            line.push_str(word);
            line_width += 1 + word_width;
        } else {
            lines.push(format!("{indent}{line}"));
            line.clear();
            line.push_str(word);
            line_width = word_width;
        }
    }
    if !line.is_empty() {
        lines.push(format!("{indent}{line}"));
    }
    lines
}

/// `path` with a leading `home` replaced by `~` (spec T6); the full path
/// otherwise. The match is by whole components, so `/Users/matthew` is not
/// under `/Users/matt`; `home` itself becomes `~`; an empty `home` shortens
/// nothing.
pub fn tilde(path: &Path, home: Option<&Path>) -> String {
    let Some(home) = home.filter(|h| !h.as_os_str().is_empty()) else {
        return path.display().to_string();
    };
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn width_counts_columns_not_bytes() {
        assert_eq!(width("✓ 49 detections ready"), 21);
        assert_eq!(width("›•‹"), 3);
        assert_eq!(width("\x1b[32m✓\x1b[0m"), 1);
        assert_eq!(width("日本"), 4);
        assert_eq!(width(""), 0);
    }

    #[test]
    fn strip_sgr_removes_csi_sequences_only() {
        assert_eq!(strip_sgr("\x1b[?2026h\x1b[1A\x1b[2Kabc\x1b[0m"), "abc");
        assert_eq!(strip_sgr("plain"), "plain");
        assert_eq!(strip_sgr("✓ \x1b[2mdim\x1b[0m end"), "✓ dim end");
        // An unterminated sequence hides everything after it.
        assert_eq!(strip_sgr("a\x1b[3"), "a");
        // A lone ESC that starts no CSI is ordinary text.
        assert_eq!(strip_sgr("a\x1bb"), "a\x1bb");
    }

    #[test]
    fn truncate_keeps_short_text_and_ends_long_text_with_the_ellipsis() {
        assert_eq!(truncate("abcdef", 10, "…"), "abcdef");
        assert_eq!(truncate("abcdef", 4, "…"), "abc…");
        assert_eq!(truncate("abcdef", 5, "..."), "ab...");
        assert_eq!(truncate("abcdef", 6, "…"), "abcdef");
        assert_eq!(truncate("日本語です", 5, "…"), "日本…");
    }

    #[test]
    fn truncate_keeps_escape_sequences_whole_and_zero_width() {
        // A closed span before the cut survives untouched.
        assert_eq!(
            truncate("\x1b[33m!\x1b[0m abcdef", 6, "…"),
            "\x1b[33m!\x1b[0m abc…"
        );
        // A span still open at the cut is closed after the ellipsis.
        assert_eq!(
            truncate("\x1b[2mabcdef\x1b[0m", 4, "…"),
            "\x1b[2mabc…\x1b[0m"
        );
        // Painted text that fits is returned byte for byte.
        assert_eq!(
            truncate("\x1b[32m✓\x1b[0m done", 6, "…"),
            "\x1b[32m✓\x1b[0m done"
        );
        // No room for anything but the marker.
        assert_eq!(truncate("abcdef", 0, "…"), "…");
    }

    #[test]
    fn wrap_reproduces_the_m2_body() {
        assert_eq!(
            wrap(
                "It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.",
                80,
                "  "
            ),
            vec![
                "  It is most likely held by another running `aitm`, the aitmproxy macOS app's",
                "  embedded core, or another program.",
            ]
        );
        assert_eq!(
            wrap(
                "Free it, or set `listen:` to another address in /Users/matt/Library/Application Support/aitmproxy/config.yaml.",
                80,
                "  "
            ),
            vec![
                "  Free it, or set `listen:` to another address in",
                "  /Users/matt/Library/Application Support/aitmproxy/config.yaml.",
            ]
        );
    }

    #[test]
    fn wrap_never_breaks_a_word() {
        assert_eq!(wrap("abcdefghij", 5, ""), vec!["abcdefghij"]);
        assert_eq!(
            wrap("ab abcdefghij cd", 5, ""),
            vec!["ab", "abcdefghij", "cd"]
        );
    }

    #[test]
    fn wrap_of_nothing_is_no_lines_and_one_word_is_one_indented_line() {
        assert_eq!(wrap("", 80, "  "), Vec::<String>::new());
        assert_eq!(wrap("   \n\t ", 80, "  "), Vec::<String>::new());
        assert_eq!(wrap("x", 80, "  "), vec!["  x"]);
        // Runs of whitespace collapse to one space; a narrow width still
        // places the first word.
        assert_eq!(wrap("a   b", 3, ""), vec!["a b"]);
        assert_eq!(wrap("a b", 2, ""), vec!["a", "b"]);
    }

    #[test]
    fn tilde_shortens_only_under_home() {
        let home = Path::new("/Users/matt");
        assert_eq!(
            tilde(
                Path::new("/Users/matt/Library/Application Support/aitmproxy/config.yaml"),
                Some(home)
            ),
            "~/Library/Application Support/aitmproxy/config.yaml"
        );
        assert_eq!(tilde(Path::new("/tmp/x"), Some(home)), "/tmp/x");
        assert_eq!(
            tilde(
                Path::new("/Users/matt/Library/Application Support/aitmproxy/config.yaml"),
                None
            ),
            "/Users/matt/Library/Application Support/aitmproxy/config.yaml"
        );
    }

    #[test]
    fn tilde_matches_whole_components_and_ignores_an_empty_home() {
        let home = Path::new("/Users/matt");
        assert_eq!(tilde(Path::new("/Users/matt"), Some(home)), "~");
        assert_eq!(
            tilde(Path::new("/Users/matthew/x"), Some(home)),
            "/Users/matthew/x"
        );
        assert_eq!(tilde(Path::new("/tmp/x"), Some(Path::new(""))), "/tmp/x");
    }

    // ---- tester additions: edge cases a reporting layer must survive ----

    #[test]
    fn strip_sgr_survives_an_unterminated_introducer() {
        // A bare `ESC[` at the very end hides nothing but itself.
        assert_eq!(strip_sgr("a\x1b["), "a");
        assert_eq!(strip_sgr("\x1b["), "");
        // An unterminated sequence whose body is multibyte text ends at the
        // string's end without slicing inside a character.
        assert_eq!(strip_sgr("a\x1b[日本"), "a");
        assert_eq!(width("a\x1b["), 1);
        // Two sequences back to back, then text.
        assert_eq!(strip_sgr("\x1b[1A\x1b[2Kx"), "x");
    }

    #[test]
    fn truncate_with_room_smaller_than_the_ellipsis_returns_only_the_ellipsis() {
        assert_eq!(truncate("abcdef", 2, "..."), "...");
        assert_eq!(truncate("abcdef", 3, "..."), "...");
        assert_eq!(truncate("abcdef", 0, "..."), "...");
        assert_eq!(truncate("abcdef", 1, "…"), "…");
        // An empty text always fits, whatever the budget.
        assert_eq!(truncate("", 0, "…"), "");
    }

    #[test]
    fn truncate_a_ten_thousand_character_word_to_ten_columns() {
        let word = "x".repeat(10_000);
        let out = truncate(&word, 10, "…");
        assert_eq!(out, format!("{}…", "x".repeat(9)));
        assert_eq!(width(&out), 10);
        // Wide characters are never split: four columns hold one `日` and
        // the ellipsis, not one and a half.
        let wide = "日".repeat(10_000);
        assert_eq!(truncate(&wide, 4, "…"), "日…");
    }

    #[test]
    fn wrap_keeps_a_ten_thousand_character_word_whole_on_one_line() {
        let word = "y".repeat(10_000);
        let lines = wrap(&word, 80, "  ");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], format!("  {word}"));
        assert_eq!(lines[0].len(), 10_002);
        // Surrounded by short words it still stands alone, unbroken.
        let lines = wrap(&format!("a {word} b"), 80, "  ");
        assert_eq!(
            lines,
            vec!["  a".to_string(), format!("  {word}"), "  b".to_string()]
        );
    }

    #[test]
    fn wrap_at_zero_width_or_under_the_indent_puts_every_word_on_its_own_line() {
        assert_eq!(wrap("a b c", 0, ""), vec!["a", "b", "c"]);
        assert_eq!(wrap("a b c", 1, "  "), vec!["  a", "  b", "  c"]);
    }

    #[test]
    fn tilde_with_root_as_home() {
        let root = Path::new("/");
        assert_eq!(tilde(Path::new("/"), Some(root)), "~");
        assert_eq!(tilde(Path::new("/tmp/x"), Some(root)), "~/tmp/x");
        assert_eq!(tilde(Path::new("relative/x"), Some(root)), "relative/x");
        assert_eq!(tilde(Path::new(""), Some(Path::new("/Users/matt"))), "");
    }
}
