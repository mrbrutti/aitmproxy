//! The one gate every identity passes before it is cached or leaves the crate
//! (spec D5): strip control and invisible-format scalars, trim, and refuse
//! anything empty or implausibly long.

/// Maximum length, in bytes, of a sanitised identity. Longer names are dropped,
/// not truncated: a 257-byte "name" is not a name.
const MAX_LEN: usize = 256;

/// Remove every Unicode Cc scalar (`char::is_control`), every scalar in the
/// invisible-format (Cf) ranges U+00AD, U+061C, U+180E, U+200B–U+200F,
/// U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF, U+FFF9–U+FFFB, U+E0001,
/// U+E0020–U+E007F, and every non-ASCII whitespace scalar (`char::is_whitespace`
/// minus `is_ascii_whitespace`: NBSP, ideographic space, the Zs block, and the
/// line / paragraph separators U+2028 / U+2029, which render blank or break a
/// line; security finding S2, 2026-11-01); trim whitespace; `None` if nothing
/// is left or the result exceeds 256 bytes.
#[must_use]
pub fn sanitize(raw: &str) -> Option<String> {
    let kept: String = raw
        .chars()
        .filter(|&c| !c.is_control() && !is_invisible_format(c) && !is_non_ascii_whitespace(c))
        .collect();
    let trimmed = kept.trim_matches(char::is_whitespace);
    if trimmed.is_empty() || trimmed.len() > MAX_LEN {
        return None;
    }
    Some(trimmed.to_string())
}

/// The Unicode format (Cf) scalars that render as nothing: soft hyphen, bidi and
/// joiner controls, BOM, interlinear annotation, tag characters.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Whitespace that is not ASCII whitespace, plus the two separators the
/// `White_Space` property already covers but which are named here because they
/// are the line-injection cases: U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR.
fn is_non_ascii_whitespace(c: char) -> bool {
    matches!(c, '\u{2028}' | '\u{2029}') || (c.is_whitespace() && !c.is_ascii_whitespace())
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn strips_an_embedded_left_to_right_mark() {
        assert_eq!(sanitize("cu\u{200E}rl"), Some("curl".to_string()));
    }

    #[test]
    fn only_control_and_format_scalars_is_none() {
        assert_eq!(sanitize("\u{7}\u{200B}"), None);
    }

    #[test]
    fn trims_ascii_whitespace() {
        assert_eq!(sanitize("  node \n"), Some("node".to_string()));
    }

    #[test]
    fn exactly_256_bytes_is_kept() {
        assert_eq!(sanitize(&"a".repeat(256)), Some("a".repeat(256)));
    }

    #[test]
    fn over_256_bytes_is_dropped_not_truncated() {
        assert_eq!(sanitize(&"a".repeat(257)), None);
    }

    #[test]
    fn a_bundle_identifier_passes_unchanged() {
        assert_eq!(
            sanitize("com.apple.Safari"),
            Some("com.apple.Safari".to_string())
        );
    }

    #[test]
    fn every_listed_format_range_is_stripped() {
        let raw = "a\u{AD}\u{61C}\u{180E}\u{200B}\u{200F}\u{202A}\u{202E}\u{2060}\u{2064}\u{2066}\u{2069}\u{FEFF}\u{FFF9}\u{FFFB}\u{E0001}\u{E0020}\u{E007F}b";
        assert_eq!(sanitize(raw), Some("ab".to_string()));
    }

    #[test]
    fn whitespace_inside_is_kept_and_edges_trimmed() {
        assert_eq!(
            sanitize("\tGoogle Chrome Helper (Renderer)  "),
            Some("Google Chrome Helper (Renderer)".to_string())
        );
    }

    /// D5: the limit is 256 *bytes*, not scalars — 128 two-byte scalars pass,
    /// 129 do not.
    #[test]
    fn the_length_limit_is_bytes_not_chars() {
        assert_eq!(sanitize(&"é".repeat(128)), Some("é".repeat(128)));
        assert_eq!(sanitize(&"é".repeat(129)), None);
    }

    /// Stripping runs before the length check: 256 letters plus an invisible
    /// scalar is 259 bytes raw and exactly 256 after, so it is kept.
    #[test]
    fn stripping_happens_before_the_length_check() {
        let raw = format!("{}\u{200B}", "a".repeat(256));
        assert_eq!(sanitize(&raw), Some("a".repeat(256)));
    }

    /// Security finding S2 (2026-11-01): non-ASCII whitespace is dropped like
    /// a format scalar, so a no-break space at either edge is gone, not kept
    /// as content (it used to pass through and render as a blank).
    #[test]
    fn non_ascii_whitespace_is_dropped() {
        assert_eq!(sanitize("\u{A0}node\u{A0}"), Some("node".to_string()));
        assert_eq!(sanitize("py\u{A0}thon"), Some("python".to_string()));
    }

    /// S2: an ideographic space alone renders blank, so it is `None`, and the
    /// line / paragraph separators (U+2028 / U+2029) cannot inject a line.
    #[test]
    fn blank_rendering_whitespace_and_line_separators_are_none_or_stripped() {
        assert_eq!(sanitize("\u{3000}"), None);
        assert_eq!(sanitize("\u{2028}\u{2029}"), None);
        assert_eq!(sanitize("a\u{2028}b"), Some("ab".to_string()));
        assert_eq!(sanitize("a\u{2029}b"), Some("ab".to_string()));
    }

    #[test]
    fn empty_and_whitespace_only_are_none() {
        assert_eq!(sanitize(""), None);
        assert_eq!(sanitize(" \t\r\n"), None);
    }
}
