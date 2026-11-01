//! Cell-width helpers shared by every screen: pad or truncate a string to a
//! column width (display width, not bytes), with an ellipsis when it is cut.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Display width in cells.
pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// A cell count as ratatui's `u16`, saturating instead of wrapping: the one
/// place the renderers convert a measured width or a row index.
pub fn cells(w: usize) -> u16 {
    u16::try_from(w).unwrap_or(u16::MAX)
}

/// Fit `s` into exactly `w` cells: pad with spaces or cut with `…`.
pub fn fit(s: &str, w: usize) -> String {
    let cur = width(s);
    if cur == w {
        return s.to_string();
    }
    if cur < w {
        let mut out = String::with_capacity(s.len() + (w - cur));
        out.push_str(s);
        out.extend(std::iter::repeat_n(' ', w - cur));
        return out;
    }
    truncate(s, w)
}

/// `s` without its control characters (`char::is_control`: C0, DEL, C1),
/// so a tab, an escape sequence or a newline from a core cannot move the
/// cursor or shift a column; the one place the Scan folds strip them (fix
/// round G, G10). A string without any is copied as it is.
pub fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Bound a core string in place for the screen (fix round H, H22; the one
/// fold-time cut the Scan tabs share): control characters stripped
/// ([`clean`]) when there are any, then cut to `max` cells ([`truncate`])
/// when it runs past `max` bytes (a char is never more cells than bytes,
/// so a string within the cap in bytes needs no walk and no allocation).
pub(crate) fn cut_to(s: &mut String, max: usize) {
    if s.chars().any(char::is_control) {
        *s = clean(s);
    }
    if s.len() > max {
        *s = truncate(s, max);
    }
}

/// Cut `s` to at most `w` cells, ending in `…` when anything was removed.
///
/// Bounded in work and in output (D6 hostile-core bounds; fix round E, E1):
/// the walk stops as soon as `s` is known not to fit, so a call is O(w)
/// whatever the input's length, and a string is also cut once it runs past
/// `4 * w` chars, so a run of width-0 characters (U+200B and kin) cannot
/// pass whole. The result is therefore at most `w` cells and `4 * w` chars.
/// A control character is charged one cell, as [`width`] charges it (fix
/// round G, G10), so the two never disagree on what fits.
pub fn truncate(s: &str, w: usize) -> String {
    if w == 0 {
        return String::new();
    }
    let max_chars = w.saturating_mul(4);
    let mut cells_used = 0;
    let mut chars_used = 0;
    // The byte length of the longest prefix that leaves room for the
    // ellipsis: at most `w - 1` cells and `4 * w - 1` chars.
    let mut keep = 0;
    for (i, c) in s.char_indices() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(1);
        if cells_used + cw > w || chars_used + 1 > max_chars {
            let mut out = String::with_capacity(keep + '…'.len_utf8());
            out.push_str(&s[..keep]);
            out.push('…');
            return out;
        }
        cells_used += cw;
        chars_used += 1;
        if cells_used < w && chars_used < max_chars {
            keep = i + c.len_utf8();
        }
    }
    s.to_string()
}

/// Right-align `s` in `w` cells.
pub fn right(s: &str, w: usize) -> String {
    let cur = width(s);
    if cur >= w {
        return truncate(s, w);
    }
    let mut out: String = std::iter::repeat_n(' ', w - cur).collect();
    out.push_str(s);
    out
}

/// Cut the middle of a URL-like string so host and tail survive: `https://a…/login`.
pub fn elide_middle(s: &str, w: usize) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    if w < 8 {
        return truncate(s, w);
    }
    let chars: Vec<char> = s.chars().collect();
    let keep_head = (w - 1) * 2 / 3;
    let keep_tail = w - 1 - keep_head;
    let head: String = chars.iter().take(keep_head).collect();
    let tail: String = chars[chars.len() - keep_tail..].iter().collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_pads_and_cuts() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abcd", 4), "abcd");
        assert_eq!(right("12", 5), "   12");
        assert_eq!(truncate("héllo wörld", 6), "héllo…");
        assert_eq!(width("✋ 2"), 4);
    }

    /// Q10: one saturating conversion for every cell count the renderers
    /// hand to ratatui, instead of `as u16` at each site.
    #[test]
    fn cells_saturates_instead_of_wrapping() {
        assert_eq!(cells(0), 0);
        assert_eq!(cells(5), 5);
        assert_eq!(cells(65_535), u16::MAX);
        assert_eq!(cells(70_000), u16::MAX);
        assert_eq!(cells(usize::MAX), u16::MAX);
    }

    /// Fix round E, E1: `truncate` is O(w) whatever the input. A string of a
    /// million width-0 characters (U+200B) is cut to at most `4 * w` chars,
    /// so the result is bounded in bytes as well as cells; a million `x`
    /// gives exactly `w` cells; a string that fits is returned whole.
    #[test]
    fn truncate_is_bounded_in_chars_and_cells() {
        let zero_width = "\u{200B}".repeat(1_000_000);
        let cut = truncate(&zero_width, 40);
        assert!(cut.chars().count() <= 160, "{} chars", cut.chars().count());
        assert!(cut.ends_with('…'));
        let wide = "x".repeat(1_000_000);
        let cut = truncate(&wide, 10);
        assert_eq!(width(&cut), 10);
        assert_eq!(cut, "xxxxxxxxx…");
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("", 5), "");
        assert_eq!(truncate("abc", 0), "");
        assert_eq!(truncate("ab", 1), "…");
    }

    /// Fix round G, G10: a control character is charged one cell, as
    /// `width()` charges it, so the "at most `w` cells" contract holds for a
    /// run of tabs too, and `clean` strips every control character.
    #[test]
    fn truncate_charges_a_control_char_one_cell_and_clean_strips_them() {
        let tabs = "\t".repeat(1000);
        let cut = truncate(&tabs, 8);
        assert!(width(&cut) <= 8, "{} cells", width(&cut));
        assert_eq!(cut.chars().count(), 8, "seven tabs and the ellipsis");
        assert_eq!(clean("a\tb\u{1b}[2Jc\nd"), "ab[2Jcd");
        assert_eq!(clean("plain"), "plain");
        assert_eq!(clean(""), "");
    }

    /// Fix round H, H22: `cut_to` strips control characters, cuts past
    /// `max` cells with an ellipsis, and leaves a short clean string as it
    /// is.
    #[test]
    fn cut_to_cleans_then_bounds() {
        let mut s = "a\tb\u{1b}c".to_string();
        cut_to(&mut s, 10);
        assert_eq!(s, "abc");
        let mut s = "x".repeat(50);
        cut_to(&mut s, 8);
        assert_eq!(s, "xxxxxxx…");
        let mut s = "\t".repeat(20) + "abcdefghij";
        cut_to(&mut s, 4);
        assert_eq!(s, "abc…");
        let mut s = "plain".to_string();
        cut_to(&mut s, 5);
        assert_eq!(s, "plain");
    }

    #[test]
    fn elide_keeps_both_ends() {
        let s = elide_middle("https://api.shop-staging.test/api/auth/login", 24);
        assert_eq!(width(&s), 24);
        assert!(s.starts_with("https://api.sho"));
        assert!(s.ends_with("/login"));
    }
}
