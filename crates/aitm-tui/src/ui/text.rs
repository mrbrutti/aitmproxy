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

/// Cut `s` to at most `w` cells, ending in `…` when anything was removed.
pub fn truncate(s: &str, w: usize) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    if w == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(0);
        if used + cw > w - 1 {
            break;
        }
        out.push(c);
        used += cw;
    }
    out.push('…');
    out
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

    #[test]
    fn elide_keeps_both_ends() {
        let s = elide_middle("https://api.shop-staging.test/api/auth/login", 24);
        assert_eq!(width(&s), 24);
        assert!(s.starts_with("https://api.sho"));
        assert!(s.ends_with("/login"));
    }
}
