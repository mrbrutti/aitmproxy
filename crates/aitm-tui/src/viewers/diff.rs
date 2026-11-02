//! Diff viewer: unified under 120 columns, side-by-side at 120 or more
//! (§2.10(c) "diff is unified under 120 cols").
//!
//! The diff runs once per frame on bodies a peer chose, so it is bounded
//! twice: each side is cut at [`MAX_DIFF_LINES`] lines / [`MAX_DIFF_BYTES`]
//! and Myers runs under a [`DIFF_BUDGET`] deadline (`similar` falls back to a
//! coarser alignment when it expires). Either cut ends the output with a note.

use std::time::{Duration, Instant};

use ratatui::text::{Line, Span};
use similar::{ChangeTag, TextDiff};

use crate::text::fit;
use crate::theme::Theme;

/// Lines per side the diff looks at (the viewers' page size).
pub const MAX_DIFF_LINES: usize = crate::viewers::MAX_VIEWER_LINES;
/// Bytes per side the diff looks at.
pub const MAX_DIFF_BYTES: usize = 256 * 1024;
/// How long Myers may run before `similar` degrades the alignment.
pub const DIFF_BUDGET: Duration = Duration::from_millis(50);

/// `s` cut to the caps, and whether anything was removed.
fn cap(s: &str) -> (&str, bool) {
    let mut end = s.len();
    if s.len() > MAX_DIFF_BYTES {
        end = MAX_DIFF_BYTES;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
    }
    let head = &s[..end];
    if let Some((i, _)) = head.match_indices('\n').nth(MAX_DIFF_LINES - 1) {
        end = end.min(i + 1);
    }
    (&s[..end], end < s.len())
}

/// Both sides capped, the deadlined diff, and the note lines to append.
fn prepare<'s>(old: &'s str, new: &'s str) -> (TextDiff<'s, 's, 's, str>, Instant, bool) {
    let (old, cut_old) = cap(old);
    let (new, cut_new) = cap(new);
    let start = Instant::now();
    let diff = TextDiff::configure()
        .deadline(start + DIFF_BUDGET)
        .diff_lines(old, new);
    (diff, start, cut_old || cut_new)
}

/// The trailing notes when the inputs were cut or the budget expired.
fn notes<'a>(theme: &Theme, out: &mut Vec<Line<'a>>, start: Instant, cut: bool) {
    if start.elapsed() >= DIFF_BUDGET {
        out.push(Line::styled(
            "diff cut at the 50 ms budget",
            theme.intercept_armed_quiet(),
        ));
    }
    if cut {
        out.push(Line::styled(
            format!(
                "diff input cut at {MAX_DIFF_LINES} lines / {} KiB per side",
                MAX_DIFF_BYTES / 1024
            ),
            theme.intercept_armed_quiet(),
        ));
    }
}

/// Unified diff of `old` → `new`, with `±` gutters and a 3-line context.
pub fn unified<'a>(theme: &Theme, old: &str, new: &str) -> Vec<Line<'a>> {
    let (diff, start, cut) = prepare(old, new);
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
    notes(theme, &mut out, start, cut);
    out
}

/// Side-by-side diff: old on the left, new on the right, each `half` cells wide.
pub fn side_by_side<'a>(theme: &Theme, old: &str, new: &str, half: usize) -> Vec<Line<'a>> {
    let (diff, start, cut) = prepare(old, new);
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
    notes(theme, &mut out, start, cut);
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

    /// S2: the diff is deadlined and its inputs capped, so two large
    /// unrelated bodies cannot stall a frame; the cut is announced.
    #[test]
    fn large_unrelated_inputs_diff_within_the_budget_and_say_they_were_cut() {
        let t = Theme::new(true);
        let old: String = (0..50_000).map(|i| format!("left line {i}\n")).collect();
        let new: String = (0..50_000)
            .map(|i| format!("right {} row\n", i * 7919 % 50_000))
            .collect();
        for (name, lines) in [
            ("unified", {
                let start = std::time::Instant::now();
                let l = unified(&t, &old, &new);
                assert!(
                    start.elapsed().as_millis() < 500,
                    "unified took {:?}",
                    start.elapsed()
                );
                l
            }),
            ("side_by_side", {
                let start = std::time::Instant::now();
                let l = side_by_side(&t, &old, &new, 40);
                assert!(
                    start.elapsed().as_millis() < 500,
                    "side_by_side took {:?}",
                    start.elapsed()
                );
                l
            }),
        ] {
            let last = text(&lines).last().cloned().unwrap_or_default();
            assert_eq!(
                last,
                format!(
                    "diff input cut at {MAX_DIFF_LINES} lines / {} KiB per side",
                    MAX_DIFF_BYTES / 1024
                ),
                "{name}"
            );
            assert!(
                lines.len() <= 2 * MAX_DIFF_LINES + 2,
                "{name}: {} lines",
                lines.len()
            );
        }
        // Small inputs carry no note.
        assert_eq!(text(&unified(&t, "a\n", "b\n")), vec!["- a", "+ b"]);
        // The byte cap applies even when there are few lines.
        let fat_old = format!("{}\n", "x".repeat(MAX_DIFF_BYTES + 10));
        let lines = text(&unified(&t, &fat_old, "y\n"));
        assert!(
            lines.last().unwrap().starts_with("diff input cut at"),
            "{lines:?}"
        );
    }
}
