//! JSON viewers: a pretty, syntax-coloured print and a foldable tree with the
//! node path (JSONPath-ish) for the inspector's JSON tab.

use std::collections::HashSet;

use ratatui::text::{Line, Span};
use serde_json::Value;

use crate::theme::Theme;

/// Pretty-print with the syntax tokens. `None` when the text is not JSON.
pub fn pretty<'a>(theme: &Theme, text: &str) -> Option<Vec<Line<'a>>> {
    let v: Value = serde_json::from_str(text).ok()?;
    let mut out = Sink::default();
    render(theme, &v, 0, None, &mut out, &HashSet::new(), "$", true);
    Some(out.lines)
}

/// The tree view: like `pretty`, but a folded node collapses to one line
/// (`▸ "user": {…} 4 keys`) and every container line carries its fold marker.
pub fn tree<'a>(theme: &Theme, text: &str, folds: &HashSet<String>) -> Option<Vec<Line<'a>>> {
    tree_with_paths(theme, text, folds).map(|(lines, _)| lines)
}

/// The tree view plus, for each line, the node path it shows: `Some` for a
/// value line (a container's opening or folded line, or a leaf), `None` for
/// a closing bracket. Both vectors have the same length.
pub fn tree_with_paths<'a>(
    theme: &Theme,
    text: &str,
    folds: &HashSet<String>,
) -> Option<(Vec<Line<'a>>, Vec<Option<String>>)> {
    let v: Value = serde_json::from_str(text).ok()?;
    let mut out = Sink::default();
    render(theme, &v, 0, None, &mut out, folds, "$", false);
    Some((out.lines, out.paths))
}

/// The lines being built, each with the node path it belongs to.
#[derive(Default)]
struct Sink<'a> {
    lines: Vec<Line<'a>>,
    paths: Vec<Option<String>>,
}

impl<'a> Sink<'a> {
    fn push(&mut self, line: Line<'a>, path: Option<&str>) {
        self.lines.push(line);
        self.paths.push(path.map(str::to_string));
    }
}

/// Paths of every container node, in document order (for fold navigation).
pub fn container_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        walk(&v, "$", &mut out);
    }
    out
}

fn walk(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            out.push(path.to_string());
            for (k, c) in m {
                walk(c, &format!("{path}.{k}"), out);
            }
        }
        Value::Array(a) => {
            out.push(path.to_string());
            for (i, c) in a.iter().enumerate() {
                walk(c, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn render<'a>(
    theme: &Theme,
    v: &Value,
    depth: usize,
    key: Option<&str>,
    out: &mut Sink<'a>,
    folds: &HashSet<String>,
    path: &str,
    plain: bool,
) {
    let indent = "  ".repeat(depth);
    let mut spans: Vec<Span<'a>> = Vec::new();
    let is_container = matches!(v, Value::Object(_) | Value::Array(_));
    if !plain {
        let marker = if !is_container {
            "  "
        } else if folds.contains(path) {
            "▸ "
        } else {
            "▾ "
        };
        spans.push(Span::styled(marker, theme.text_tertiary()));
    }
    spans.push(Span::raw(indent.clone()));
    if let Some(k) = key {
        spans.push(Span::styled(format!("\"{k}\""), theme.syntax_key()));
        spans.push(Span::styled(": ", theme.syntax_punct()));
    }
    match v {
        Value::Object(m) if !plain && folds.contains(path) => {
            spans.push(Span::styled("{…}", theme.syntax_bracket()));
            spans.push(Span::styled(
                format!(" {} keys", m.len()),
                theme.text_tertiary(),
            ));
            out.push(Line::from(spans), Some(path));
        }
        Value::Array(a) if !plain && folds.contains(path) => {
            spans.push(Span::styled("[…]", theme.syntax_bracket()));
            spans.push(Span::styled(
                format!(" {} items", a.len()),
                theme.text_tertiary(),
            ));
            out.push(Line::from(spans), Some(path));
        }
        Value::Object(m) => {
            spans.push(Span::styled("{", theme.syntax_bracket()));
            out.push(Line::from(spans), Some(path));
            let n = m.len();
            for (i, (k, c)) in m.iter().enumerate() {
                let child = format!("{path}.{k}");
                render(theme, c, depth + 1, Some(k), out, folds, &child, plain);
                if i + 1 < n {
                    comma(out, theme);
                }
            }
            out.push(close(theme, &indent, "}", plain), None);
        }
        Value::Array(a) => {
            spans.push(Span::styled("[", theme.syntax_bracket()));
            out.push(Line::from(spans), Some(path));
            let n = a.len();
            for (i, c) in a.iter().enumerate() {
                let child = format!("{path}[{i}]");
                render(theme, c, depth + 1, None, out, folds, &child, plain);
                if i + 1 < n {
                    comma(out, theme);
                }
            }
            out.push(close(theme, &indent, "]", plain), None);
        }
        Value::String(s) => {
            spans.push(Span::styled(
                serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\"")),
                theme.syntax_string(),
            ));
            out.push(Line::from(spans), Some(path));
        }
        Value::Number(n) => {
            spans.push(Span::styled(n.to_string(), theme.syntax_number()));
            out.push(Line::from(spans), Some(path));
        }
        Value::Bool(b) => {
            spans.push(Span::styled(b.to_string(), theme.syntax_boolean()));
            out.push(Line::from(spans), Some(path));
        }
        Value::Null => {
            spans.push(Span::styled("null", theme.syntax_boolean()));
            out.push(Line::from(spans), Some(path));
        }
    }
}

fn comma(out: &mut Sink<'_>, theme: &Theme) {
    if let Some(last) = out.lines.last_mut() {
        last.spans.push(Span::styled(",", theme.syntax_punct()));
    }
}

fn close<'a>(theme: &Theme, indent: &str, bracket: &'static str, plain: bool) -> Line<'a> {
    let mut spans = Vec::new();
    if !plain {
        spans.push(Span::raw("  "));
    }
    spans.push(Span::raw(indent.to_string()));
    spans.push(Span::styled(bracket, theme.syntax_bracket()));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn pretty_prints_nested_json() {
        let t = Theme::new(true);
        let lines = pretty(
            &t,
            r#"{"token":"x","n":2,"user":{"id":1,"ok":true},"tags":["a",null]}"#,
        )
        .unwrap();
        assert_eq!(
            text(&lines),
            vec![
                "{",
                "  \"token\": \"x\",",
                "  \"n\": 2,",
                "  \"user\": {",
                "    \"id\": 1,",
                "    \"ok\": true",
                "  },",
                "  \"tags\": [",
                "    \"a\",",
                "    null",
                "  ]",
                "}",
            ]
        );
        assert!(pretty(&t, "not json").is_none());
    }

    #[test]
    fn tree_folds_a_node_to_one_line() {
        let t = Theme::new(true);
        let src = r#"{"user":{"id":1,"ok":true},"n":2}"#;
        let folds: HashSet<String> = ["$.user".to_string()].into_iter().collect();
        let lines = tree(&t, src, &folds).unwrap();
        assert_eq!(
            text(&lines),
            vec!["▾ {", "▸   \"user\": {…} 2 keys,", "    \"n\": 2", "  }"]
        );
        assert_eq!(container_paths(src), vec!["$", "$.user"]);
    }

    #[test]
    fn tree_with_paths_labels_every_node_line() {
        let t = Theme::new(true);
        let (lines, paths) = tree_with_paths(&t, r#"{"a":{"b":1}}"#, &HashSet::new()).unwrap();
        assert_eq!(
            text(&lines),
            vec!["▾ {", "▾   \"a\": {", "      \"b\": 1", "    }", "  }"]
        );
        assert_eq!(
            paths,
            vec![
                Some("$".to_string()),
                Some("$.a".to_string()),
                Some("$.a.b".to_string()),
                None,
                None,
            ]
        );
        // A folded container keeps its path on its one line.
        let folds: HashSet<String> = ["$.a".to_string()].into_iter().collect();
        let (lines, paths) = tree_with_paths(&t, r#"{"a":{"b":1},"c":[true]}"#, &folds).unwrap();
        assert_eq!(
            text(&lines),
            vec![
                "▾ {",
                "▸   \"a\": {…} 1 keys,",
                "▾   \"c\": [",
                "      true",
                "    ]",
                "  }"
            ]
        );
        assert_eq!(
            paths,
            vec![
                Some("$".to_string()),
                Some("$.a".to_string()),
                Some("$.c".to_string()),
                Some("$.c[0]".to_string()),
                None,
                None,
            ]
        );
        assert!(tree_with_paths(&t, "nope", &HashSet::new()).is_none());
        // `tree` stays the thin wrapper.
        assert_eq!(
            text(&tree(&t, r#"{"a":{"b":1}}"#, &HashSet::new()).unwrap()).len(),
            5
        );
    }
}
