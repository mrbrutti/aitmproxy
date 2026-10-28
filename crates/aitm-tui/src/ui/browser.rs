//! The browser view (§2.7 "Browser view", TUI column of §2.9): the URL, the
//! last screenshot as a placeholder, the page's DOM as an indented outline and
//! the last `eval` result. The terminal has no viewport (§2.10(c)), so the
//! panel says what it cannot show and `o` hands the screenshot to the desktop.
//! The outline comes from a tiny tag scanner, not an HTML parser: one line per
//! element, `tag#id.class`, `script`/`style` bodies skipped, capped at
//! [`OUTLINE_MAX`] lines. The DOM is page content, so every value it shows is
//! bounded and stripped of control characters.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::model::human_bytes;
use crate::theme::Theme;
use crate::tokens::color;
use crate::ui::overlays::{boxed, lines_into};
use crate::ui::text::truncate;

/// At most this many outline lines are kept (plan task 10: "first 200 lines").
pub const OUTLINE_MAX: usize = 200;

/// Deeper nesting than this is drawn at this indent; the path still walks it.
const INDENT_MAX: usize = 40;

/// An `id` or class name longer than this is cut (page content).
const NAME_MAX: usize = 40;

/// Classes shown per element.
const CLASSES_MAX: usize = 5;

/// Elements that never have a closing tag (HTML void elements).
const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// One indented `tag#id.class` line per element, document order, at most
/// [`OUTLINE_MAX`] lines. Comments, doctype and the bodies of `script` and
/// `style` are skipped; a closing tag ends its element's indent.
pub fn outline(html: &str) -> Vec<String> {
    let bytes = html.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < bytes.len() && out.len() < OUTLINE_MAX {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"<!--") {
            i = find(bytes, i + 4, b"-->").map_or(bytes.len(), |p| p + 3);
            continue;
        }
        match bytes.get(i + 1) {
            // Doctype, processing instruction: skip to `>`.
            Some(b'!' | b'?') => {
                i = find(bytes, i, b">").map_or(bytes.len(), |p| p + 1);
                continue;
            }
            // Closing tag: one level up.
            Some(b'/') => {
                depth = depth.saturating_sub(1);
                i = find(bytes, i, b">").map_or(bytes.len(), |p| p + 1);
                continue;
            }
            _ => {}
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'-' | b':'))
        {
            j += 1;
        }
        if j == start {
            // A stray `<` in text.
            i += 1;
            continue;
        }
        // Tag names are ASCII, so `start..j` is on char boundaries.
        let tag = html[start..j].to_ascii_lowercase();
        let (end, self_closing) = attrs_end(bytes, j);
        let (id, classes) = id_class(&html[j..end]);
        let mut label = format!("{}{tag}", "  ".repeat(depth.min(INDENT_MAX)));
        if let Some(id) = id {
            label.push('#');
            label.push_str(&id);
        }
        for c in classes {
            label.push('.');
            label.push_str(&c);
        }
        out.push(label);
        let after = (end + 1).min(bytes.len());
        if tag == "script" || tag == "style" {
            // The body is code, not markup: jump past `</script` / `</style`.
            let close = format!("</{tag}");
            i = find_ci(bytes, after, close.as_bytes())
                .and_then(|p| find(bytes, p, b">"))
                .map_or(bytes.len(), |p| p + 1);
            continue;
        }
        if !(self_closing || VOID.contains(&tag.as_str())) {
            depth += 1;
        }
        i = after;
    }
    out
}

/// The ancestor path of outline line `i`, `html › body › h1#title`; empty
/// when `i` is out of range.
pub fn path_of(outline: &[String], i: usize) -> String {
    let Some(line) = outline.get(i) else {
        return String::new();
    };
    let indent_of = |s: &str| s.len() - s.trim_start().len();
    let mut parts = vec![line.trim_start()];
    let mut need = indent_of(line);
    for l in outline[..i].iter().rev() {
        if need == 0 {
            break;
        }
        let ind = indent_of(l);
        if ind < need {
            parts.push(l.trim_start());
            need = ind;
        }
    }
    parts.reverse();
    parts.join(" › ")
}

/// Byte offset of `needle` in `hay[from..]`, as an offset into `hay`.
fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// [`find`], ASCII case-insensitive (`needle` is lowercase).
fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|p| p + from)
}

/// Offset of the `>` that ends the tag whose attributes start at `from`
/// (quotes honoured), or the input's length, and whether the tag closed
/// itself (`/>`).
fn attrs_end(bytes: &[u8], from: usize) -> (usize, bool) {
    let mut quote: Option<u8> = None;
    let mut k = from;
    while k < bytes.len() {
        let c = bytes[k];
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None if c == b'>' => return (k, k > from && bytes[k - 1] == b'/'),
            None => {}
        }
        k += 1;
    }
    (bytes.len(), false)
}

/// A page-supplied name made safe to draw: no control characters, bounded.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(NAME_MAX)
        .collect()
}

/// The `id` and `class` attribute values in an attribute string.
fn id_class(attrs: &str) -> (Option<String>, Vec<String>) {
    let mut id = None;
    let mut classes = Vec::new();
    let mut rest = attrs;
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        if rest.is_empty() {
            break;
        }
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '=' || c == '/')
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();
        let mut value = "";
        if let Some(r) = rest.strip_prefix('=') {
            let r = r.trim_start();
            match r.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let body = &r[1..];
                    let end = body.find(q).unwrap_or(body.len());
                    value = &body[..end];
                    // `q` is one byte, so `end + 1` is a char boundary.
                    rest = body.get(end + 1..).unwrap_or("");
                }
                Some(_) => {
                    let end = r.find(char::is_whitespace).unwrap_or(r.len());
                    value = &r[..end];
                    rest = &r[end..];
                }
                None => rest = r,
            }
        }
        match name.as_str() {
            "id" if !value.is_empty() => id = Some(clean(value)),
            "class" => classes.extend(
                value
                    .split_whitespace()
                    .take(CLASSES_MAX.saturating_sub(classes.len()))
                    .map(clean),
            ),
            _ => {}
        }
    }
    (id, classes)
}

/// Draw the view into `area`.
pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Browser — embedded obscura", area, buf);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let b = &app.browser;
    let w = usize::from(inner.width);
    let has_tools = app.tools.iter().any(|t| t.name.starts_with("browser."));
    let bold = |s: ratatui::style::Style| s.add_modifier(Modifier::BOLD);

    let mut top: Vec<Line<'_>> = Vec::with_capacity(4);
    let url = if b.url.is_empty() {
        "—"
    } else {
        b.url.as_str()
    };
    top.push(Line::from(vec![
        Span::styled(" URL ", bold(theme.text_tertiary())),
        Span::styled(
            truncate(url, w.saturating_sub(18)),
            bold(theme.text_primary()),
        ),
        Span::styled("  g navigate", theme.text_tertiary()),
    ]));
    let shot = match b.screenshot {
        Some((sw, sh, fmt, n)) if sw > 0 => format!(
            " [screenshot {sw}×{sh} {fmt} · {} · o to open]",
            human_bytes(n as u64)
        ),
        Some((_, _, fmt, n)) => {
            format!(
                " [screenshot {fmt} · {} · o to open]",
                human_bytes(n as u64)
            )
        }
        None => " [no screenshot yet · s]".to_string(),
    };
    top.push(Line::styled(shot, theme.text_secondary()));
    top.push(match (b.busy, &b.error) {
        (Some(busy), _) => Line::styled(format!(" ⟳ {busy}…"), theme.accent()),
        (None, Some(e)) => Line::styled(
            truncate(&format!(" error: {e}"), w),
            theme.fg(&color::status::SERVER_ERROR),
        ),
        (None, None) => Line::raw(""),
    });
    let n = b.dom_outline.len();
    let header = if n == 0 {
        " DOM outline".to_string()
    } else {
        format!(
            " DOM outline · {n} element{} · {}",
            if n == 1 { "" } else { "s" },
            path_of(&b.dom_outline, b.dom_cursor)
        )
    };
    top.push(Line::from(vec![
        Span::styled(
            truncate(&header, w.saturating_sub(12)),
            bold(theme.text_tertiary()),
        ),
        Span::styled("  d refresh", theme.text_tertiary()),
    ]));

    let eval = match &b.last_eval {
        Some(v) => {
            let mut lines = v.lines();
            let first = lines.next().unwrap_or("");
            let more = lines.count();
            let tail = if more > 0 {
                format!(" (+{more} lines)")
            } else {
                String::new()
            };
            Line::from(vec![
                Span::styled(" eval › ", bold(theme.text_tertiary())),
                Span::styled(
                    truncate(first, w.saturating_sub(10 + tail.len())),
                    theme.syntax_string(),
                ),
                Span::styled(tail, theme.text_tertiary()),
            ])
        }
        None => Line::from(vec![
            Span::styled(" eval › ", bold(theme.text_tertiary())),
            Span::styled(
                "—  e evaluates a JavaScript expression",
                theme.text_tertiary(),
            ),
        ]),
    };
    let bottom = [
        eval,
        Line::styled(
            " live viewport and tabs need core follow-up F14 (browser.tabs, browser.screencast)",
            theme.text_tertiary(),
        ),
        Line::styled(
            " g url · d dom · s screenshot · e eval · o open screenshot · ↑↓ outline · Esc back",
            theme.text_tertiary(),
        ),
    ];

    let [top_area, list, bottom_area] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(3),
    ])
    .areas(inner);
    lines_into(buf, top_area, &top, 0);
    lines_into(buf, bottom_area, &bottom, 0);

    if n == 0 {
        let empty = if !has_tools {
            "   this bus offers no browser.* tools — the proxy was built without the embedded browser"
        } else if b.busy.is_some() {
            ""
        } else {
            "   no DOM yet — d reads the page"
        };
        lines_into(buf, list, &[Line::styled(empty, theme.text_tertiary())], 0);
        return;
    }
    let height = usize::from(list.height);
    let scroll = if height == 0 {
        0
    } else {
        b.dom_cursor.saturating_sub(height - 1)
    };
    let lines: Vec<Line<'_>> = b
        .dom_outline
        .iter()
        .enumerate()
        .skip(scroll)
        .take(height)
        .map(|(i, label)| {
            let indent = label.len() - label.trim_start().len();
            let name = &label[indent..];
            let split = name.find(['#', '.']).unwrap_or(name.len());
            let (tag, rest) = name.split_at(split);
            if i == b.dom_cursor {
                Line::styled(format!(" {label}"), theme.selection())
            } else {
                Line::from(vec![
                    Span::raw(format!(" {}", &label[..indent])),
                    Span::styled(tag.to_string(), theme.syntax_key()),
                    Span::styled(rest.to_string(), theme.text_secondary()),
                ])
            }
        })
        .collect();
    lines_into(buf, list, &lines, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Shop &mdash; staging</title>
  <link rel="stylesheet" href="/app.css">
  <script src="/app.js"></script>
  <style>
    body > p { color: #000 }
  </style>
</head>
<body class="home dark">
  <!-- a comment with <b>tags</b> in it -->
  <h1 id="title">Shop</h1>
  <p class="lead">Welcome back. <a class="link" href="/account">Your account</a></p>
  <img id="hero" src="/hero.png" alt="a > b">
  <br/>
  <script>window.__state = {"cart": "<b>3</b>"}; if (a < b) {}</script>
</body>
</html>"#;

    #[test]
    fn outline_indents_tag_id_and_class_and_skips_script_and_style_bodies() {
        assert_eq!(
            outline(PAGE),
            vec![
                "html",
                "  head",
                "    meta",
                "    title",
                "    link",
                "    script",
                "    style",
                "  body.home.dark",
                "    h1#title",
                "    p.lead",
                "      a.link",
                "    img#hero",
                "    br",
                "    script",
            ]
        );
    }

    #[test]
    fn outline_survives_junk_and_stops_at_the_cap() {
        assert_eq!(outline(""), Vec::<String>::new());
        assert_eq!(outline("plain text, no tags"), Vec::<String>::new());
        assert_eq!(outline("<"), Vec::<String>::new());
        assert_eq!(outline("<div"), vec!["div"]);
        assert_eq!(outline("</div><p>"), vec!["p"]);
        assert_eq!(outline("<DIV ID=\"A\" Class=x>"), vec!["div#A.x"]);
        assert_eq!(outline("<script>never closed"), vec!["script"]);
        let many: String = "<li>x</li>".repeat(OUTLINE_MAX + 50);
        let lines = outline(&format!("<ul>{many}</ul>"));
        assert_eq!(lines.len(), OUTLINE_MAX);
        assert_eq!(lines[0], "ul");
        assert_eq!(lines[OUTLINE_MAX - 1], "  li");
        // Deep nesting does not overflow the indent.
        let deep = "<div>".repeat(600);
        let lines = outline(&deep);
        assert_eq!(lines.len(), OUTLINE_MAX);
        assert!(lines[OUTLINE_MAX - 1].ends_with("div"));
    }

    /// Page content is untrusted: ids and classes are bounded and stripped.
    #[test]
    fn outline_bounds_page_supplied_names() {
        let long = "x".repeat(300);
        let lines = outline(&format!(
            "<p id=\"a\u{7}b\u{1b}[31m\" class=\"{long} c1 c2 c3 c4 c5 c6 c7\">"
        ));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("p#ab[31m."), "{}", lines[0]);
        assert!(!lines[0].contains('\u{1b}'));
        let classes = lines[0].split('.').skip(1).collect::<Vec<_>>();
        assert_eq!(classes.len(), CLASSES_MAX);
        assert_eq!(classes[0].len(), NAME_MAX);
        // Non-ASCII attribute values do not break slicing.
        assert_eq!(outline("<p class='日本語 café'>"), vec!["p.日本語.café"]);
        assert_eq!(outline("<p title='x'>é</p><b>"), vec!["p", "b"]);
    }

    #[test]
    fn path_of_walks_the_ancestors() {
        let o = outline(PAGE);
        assert_eq!(path_of(&o, 0), "html");
        assert_eq!(path_of(&o, 8), "html › body.home.dark › h1#title");
        assert_eq!(path_of(&o, 10), "html › body.home.dark › p.lead › a.link");
        assert_eq!(path_of(&o, 99), "");
    }
}
