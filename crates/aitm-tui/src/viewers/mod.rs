//! Body viewers (foundation §2.7 "Inspector → Body viewers"), each a function
//! from bytes to styled lines so the inspector, quick-look and snapshots share
//! them: header tables, pretty JSON, a JSON tree with folds, hex, unified diff,
//! raw text, and the image placeholder the terminal degrades to.

pub mod diff;
pub mod hex;
pub mod image;
pub mod json;

use ratatui::text::{Line, Span};

use crate::model::{human_bytes, Message};
use crate::theme::Theme;

/// A body longer than this is "large" (§2.7 "Large bodies stream in pages"):
/// the inspector shows its first [`LARGE_BODY_PREVIEW_BYTES`] under a notice
/// and skips the JSON parse, the tree and the diff, so a frame stays cheap.
pub const LARGE_BODY_BYTES: usize = 1024 * 1024;
/// How much of a large body the preview shows.
pub const LARGE_BODY_PREVIEW_BYTES: usize = 64 * 1024;
/// The most lines any viewer hands the inspector per frame; the rest is
/// replaced by a trailing `… N more lines` notice (see [`page`]).
pub const MAX_VIEWER_LINES: usize = 4000;

/// Whether the inspector pages this message's body instead of viewing it whole.
pub fn is_large(msg: &Message) -> bool {
    msg.body.len() > LARGE_BODY_BYTES
}

/// Cut `lines` at [`MAX_VIEWER_LINES`], ending with how many were dropped.
pub fn page<'a>(theme: &Theme, mut lines: Vec<Line<'a>>) -> Vec<Line<'a>> {
    if lines.len() > MAX_VIEWER_LINES {
        let more = lines.len() - MAX_VIEWER_LINES;
        lines.truncate(MAX_VIEWER_LINES);
        lines.push(Line::styled(
            format!("… {more} more lines"),
            theme.text_tertiary(),
        ));
    }
    lines
}

/// The first [`LARGE_BODY_PREVIEW_BYTES`] of a large body under a notice line:
/// as text when `as_hex` is false and the prefix is UTF-8, as hex otherwise.
pub fn large_body_preview<'a>(
    theme: &Theme,
    msg: &Message,
    as_hex: bool,
    per_line: usize,
) -> Vec<Line<'a>> {
    let prefix = &msg.body[..LARGE_BODY_PREVIEW_BYTES.min(msg.body.len())];
    let mut lines = vec![Line::styled(
        format!(
            "large body · showing the first {} of {} · o to open externally",
            human_bytes(prefix.len() as u64),
            human_bytes(msg.body.len() as u64)
        ),
        theme.intercept_armed_quiet(),
    )];
    let text = if as_hex { None } else { text_prefix(prefix) };
    match text {
        Some(t) => lines.extend(
            t.lines()
                .map(|l| Line::styled(l.to_string(), theme.text_primary())),
        ),
        None => lines.extend(hex::dump(theme, prefix, per_line)),
    }
    lines
}

/// `bytes` as text when it is UTF-8, allowing one character cut off at the
/// end (the preview boundary is a byte count, not a character count).
fn text_prefix(bytes: &[u8]) -> Option<&str> {
    match std::str::from_utf8(bytes) {
        Ok(t) => Some(t),
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&bytes[..e.valid_up_to()]).ok(),
        Err(_) => None,
    }
}

/// [`body`] as the inspector shows it: the preview for a large body, else the
/// whole viewer cut at [`MAX_VIEWER_LINES`].
pub fn body_paged<'a>(theme: &Theme, msg: &Message) -> Vec<Line<'a>> {
    if is_large(msg) {
        large_body_preview(theme, msg, false, 16)
    } else {
        page(theme, body(theme, msg))
    }
}

/// [`raw`] as the inspector shows it: the envelope, then [`body_paged`].
pub fn raw_paged<'a>(theme: &Theme, msg: &Message, is_request: bool) -> Vec<Line<'a>> {
    let mut lines = envelope(theme, msg, is_request);
    lines.extend(body_paged(theme, msg));
    lines
}

/// `name: value` rows, names in the key colour, one header per line.
pub fn headers<'a>(theme: &Theme, headers: &'a [(String, String)]) -> Vec<Line<'a>> {
    if headers.is_empty() {
        return vec![Line::styled("(no headers)", theme.text_tertiary())];
    }
    let w = headers
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(0)
        .min(32);
    headers
        .iter()
        .map(|(n, v)| {
            Line::from(vec![
                Span::styled(
                    format!("{:<w$}", n.to_ascii_lowercase()),
                    theme.syntax_key(),
                ),
                Span::styled(" : ", theme.syntax_punct()),
                Span::styled(v.as_str(), theme.text_primary()),
            ])
        })
        .collect()
}

/// Two-column `key  value` facts (Summary / Connection tabs).
pub fn facts<'a>(theme: &Theme, rows: &[(&'a str, String)]) -> Vec<Line<'a>> {
    let w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:<w$}"), theme.text_secondary()),
                Span::raw("  "),
                Span::styled(v.clone(), theme.text_primary()),
            ])
        })
        .collect()
}

/// Query-string parameters as a table, percent-decoded for reading.
pub fn query<'a>(theme: &Theme, path: &str) -> Vec<Line<'a>> {
    let Some((_, q)) = path.split_once('?') else {
        return vec![Line::styled("(no query string)", theme.text_tertiary())];
    };
    let pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect();
    let w = pairs
        .iter()
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0)
        .min(32);
    pairs
        .into_iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{k:<w$}"), theme.syntax_key()),
                Span::styled(" = ", theme.syntax_punct()),
                Span::styled(v, theme.syntax_string()),
            ])
        })
        .collect()
}

/// Minimal percent-decoding (`+` → space) for display only. Works on bytes:
/// a `%` is an escape only when the two bytes after it are ASCII hex digits,
/// so a multibyte character there (client-controlled input) is left as is.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => match (bytes.get(i + 1), bytes.get(i + 2)) {
                (Some(&hi), Some(&lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    out.push((hex_value(hi) << 4) | hex_value(lo));
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of an ASCII hex digit (the caller has checked it is one).
fn hex_value(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

/// The message as it went over the wire: start line, headers, blank, body.
pub fn raw<'a>(theme: &Theme, msg: &Message, is_request: bool) -> Vec<Line<'a>> {
    let mut lines = envelope(theme, msg, is_request);
    lines.extend(body(theme, msg));
    lines
}

/// The start line, the headers and the blank line before the body.
fn envelope<'a>(theme: &Theme, msg: &Message, is_request: bool) -> Vec<Line<'a>> {
    let mut lines = Vec::new();
    let start = if is_request {
        format!(
            "{} {} {}",
            msg.method.as_deref().unwrap_or("GET"),
            msg.path.as_deref().unwrap_or("/"),
            msg.version.as_deref().unwrap_or("HTTP/1.1")
        )
    } else {
        format!(
            "{} {}",
            msg.version.as_deref().unwrap_or("HTTP/1.1"),
            msg.status.map_or("—".to_string(), |s| s.to_string())
        )
    };
    lines.push(Line::styled(
        start,
        theme
            .text_primary()
            .add_modifier(ratatui::style::Modifier::BOLD),
    ));
    for (n, v) in &msg.headers {
        lines.push(Line::from(vec![
            Span::styled(n.to_ascii_lowercase(), theme.syntax_key()),
            Span::styled(": ", theme.syntax_punct()),
            Span::styled(v.clone(), theme.text_primary()),
        ]));
    }
    lines.push(Line::raw(""));
    lines
}

/// The body with the viewer its content type calls for.
pub fn body<'a>(theme: &Theme, msg: &Message) -> Vec<Line<'a>> {
    if msg.body.is_empty() {
        return vec![Line::styled("0 B", theme.text_tertiary())];
    }
    let ct = msg.content_type().unwrap_or_default();
    if ct.starts_with("image/") {
        return image::placeholder(theme, &msg.body, &ct);
    }
    if let Some(text) = msg.body_text() {
        let looks_json = ct.contains("json")
            || text.trim_start().starts_with('{')
            || text.trim_start().starts_with('[');
        if looks_json {
            if let Some(lines) = json::pretty(theme, text) {
                return with_truncated(theme, lines, msg.body_truncated);
            }
        }
        if ct.contains("x-www-form-urlencoded") {
            return query(theme, &format!("?{text}"));
        }
        let lines = text
            .lines()
            .map(|l| Line::styled(l.to_string(), theme.text_primary()))
            .collect();
        return with_truncated(theme, lines, msg.body_truncated);
    }
    hex::dump(theme, &msg.body, 16)
}

fn with_truncated<'a>(theme: &Theme, mut lines: Vec<Line<'a>>, truncated: bool) -> Vec<Line<'a>> {
    if truncated {
        lines.insert(
            0,
            Line::styled(
                "⚠ body truncated by the proxy's capture cap — the client received the full stream",
                theme.intercept_armed_quiet(),
            ),
        );
    }
    lines
}
