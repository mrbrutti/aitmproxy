//! Diff viewer: unified under 120 columns, side-by-side at 120 or more
//! (§2.10(c) "diff is unified under 120 cols").

use ratatui::text::{Line, Span};
use similar::{ChangeTag, TextDiff};

use crate::theme::Theme;
use crate::ui::text::fit;

/// Unified diff of `old` → `new`, with `±` gutters and a 3-line context.
pub fn unified<'a>(theme: &Theme, old: &str, new: &str) -> Vec<Line<'a>> {
    let diff = TextDiff::from_lines(old, new);
    let mut out = Vec::new();
    for (i, group) in diff.grouped_ops(3).iter().enumerate() {
        if i > 0 {
            out.push(Line::styled("⋯", theme.text_tertiary()));
        }
        for op in group {
            for change in diff.iter_changes(op) {
                let text = change.value().trim_end_matches('\n').to_string();
                let line = match change.tag() {
                    ChangeTag::Delete => Line::styled(format!("- {text}"), theme.diff_remove()),
                    ChangeTag::Insert => Line::styled(format!("+ {text}"), theme.diff_add()),
                    ChangeTag::Equal => Line::styled(format!("  {text}"), theme.text_secondary()),
                };
                out.push(line);
            }
        }
    }
    if out.is_empty() {
        out.push(Line::styled("(identical)", theme.text_tertiary()));
    }
    out
}

/// Side-by-side diff: old on the left, new on the right, each `half` cells wide.
pub fn side_by_side<'a>(theme: &Theme, old: &str, new: &str, half: usize) -> Vec<Line<'a>> {
    let diff = TextDiff::from_lines(old, new);
    let mut out = Vec::new();
    for op in diff.ops() {
        let mut dels: Vec<String> = Vec::new();
        let mut ins: Vec<String> = Vec::new();
        for change in diff.iter_changes(op) {
            let text = change.value().trim_end_matches('\n').to_string();
            match change.tag() {
                ChangeTag::Delete => dels.push(text),
                ChangeTag::Insert => ins.push(text),
                ChangeTag::Equal => {
                    flush(theme, &mut out, &mut dels, &mut ins, half);
                    out.push(Line::from(vec![
                        Span::styled(fit(&text, half), theme.text_secondary()),
                        Span::styled(" │ ", theme.syntax_punct()),
                        Span::styled(fit(&text, half), theme.text_secondary()),
                    ]));
                }
            }
        }
        flush(theme, &mut out, &mut dels, &mut ins, half);
    }
    if out.is_empty() {
        out.push(Line::styled("(identical)", theme.text_tertiary()));
    }
    out
}

fn flush<'a>(
    theme: &Theme,
    out: &mut Vec<Line<'a>>,
    dels: &mut Vec<String>,
    ins: &mut Vec<String>,
    half: usize,
) {
    let n = dels.len().max(ins.len());
    for i in 0..n {
        let l = dels.get(i).map(|s| fit(s, half));
        let r = ins.get(i).map(|s| fit(s, half));
        out.push(Line::from(vec![
            match l {
                Some(s) => Span::styled(s, theme.diff_remove()),
                None => Span::raw(" ".repeat(half)),
            },
            Span::styled(" │ ", theme.syntax_punct()),
            match r {
                Some(s) => Span::styled(s, theme.diff_add()),
                None => Span::raw(" ".repeat(half)),
            },
        ]));
    }
    dels.clear();
    ins.clear();
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
    fn unified_marks_changes() {
        let t = Theme::new(true);
        let lines = unified(&t, "a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(text(&lines), vec!["  a", "- b", "+ B", "  c"]);
        assert_eq!(text(&unified(&t, "x", "x")), vec!["(identical)"]);
    }

    #[test]
    fn side_by_side_pairs_changes() {
        let t = Theme::new(true);
        let lines = side_by_side(&t, "a\nb\n", "a\nB\n", 3);
        assert_eq!(text(&lines), vec!["a   │ a  ", "b   │ B  "]);
    }
}
