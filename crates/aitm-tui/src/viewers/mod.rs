//! Body viewers (foundation §2.7 "Inspector → Body viewers"), each a function
//! from bytes to styled lines so the inspector, quick-look and snapshots share
//! them: header tables, pretty JSON, a JSON tree with folds, hex, unified diff,
//! raw text, and the image placeholder the terminal degrades to.

pub mod diff;
pub mod hex;
pub mod image;
pub mod json;

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::model::Message;
use crate::theme::Theme;

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

/// Minimal percent-decoding (`+` → space) for display only.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The message as it went over the wire: start line, headers, blank, body.
pub fn raw<'a>(theme: &Theme, msg: &Message, is_request: bool) -> Vec<Line<'a>> {
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
    lines.extend(body(theme, msg));
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

/// A plain styled line.
pub fn plain<'a>(text: impl Into<String>, style: Style) -> Line<'a> {
    Line::styled(text.into(), style)
}
