//! The one gate every identity passes before it is cached or leaves the crate
//! (spec D5): strip control and invisible-format scalars, trim, and refuse
//! anything empty or implausibly long.

/// Maximum length, in bytes, of a sanitised identity. Longer names are dropped,
/// not truncated: a 257-byte "name" is not a name.
const MAX_LEN: usize = 256;

/// Remove every Unicode Cc scalar (`char::is_control`) and every scalar in the
/// invisible-format (Cf) ranges U+00AD, U+061C, U+180E, U+200B–U+200F,
/// U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF, U+FFF9–U+FFFB, U+E0001,
/// U+E0020–U+E007F; trim ASCII whitespace; `None` if nothing is left or the result
/// exceeds 256 bytes.
#[must_use]
pub fn sanitize(raw: &str) -> Option<String> {
    let kept: String = raw
        .chars()
        .filter(|&c| !c.is_control() && !is_invisible_format(c))
        .collect();
    let trimmed = kept.trim_matches(|c: char| c.is_ascii_whitespace());
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
}
