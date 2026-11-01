//! The Issues tab (spec D2, D11, D13). The list half: the rows sit under
//! the five severity headers with their `by_severity` counts, a zero header
//! greyed rather than hidden (spec call 11); the filter banner tops the pane
//! and the filter keys foot it. The detail half: the read issue's lines
//! (`scan::issue_detail_lines`, bounded by the model) over the walkable
//! flow list (`scan::flow_refs`), scrolled by `detail_scroll` with the flow
//! under the cursor kept on screen, and the status-control footer. The
//! degraded states are the state banner's (D13: one state on screen).
//!
//! Row layout (builder's call, from the D11 mockup): `>` cursor mark, the
//! confidence glyph pair, the name, `METHOD path_template`, `kind:name` and
//! the status, in columns measured from the rows the model already bounded
//! (D6 hostile-core bounds); when the pane is narrow the name gives way
//! first, then the location, then the point column is dropped. Hue only on
//! data (D13): the headers in `Theme::severity`, everything else text
//! tokens.

use aitm_poc::Severity;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{
    count_of, flow_refs, grouped, issue_detail_lines, severity_header, IssuePane, IssueRow,
    ScanOffer, DETAIL_LABEL_W, LOCATION_MAX, NAME_MAX, POINT_MAX,
};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::scan::{hint, note, pane_rule, panes};
use crate::ui::selection_bg;
use crate::ui::text::{cells, fit, truncate, width};

/// Blank cells between columns.
const GAP: usize = 2;
/// The widest a status cell grows (`false_positive` is fourteen cells).
const STATUS_MAX: usize = 14;
/// The narrowest a cut column is allowed to get before the next one goes.
const COLUMN_MIN: usize = 8;
/// The list pane's footer (D11): the filter keys.
const FOOTER: &str = "S severity · C confidence · L lane · T status · J job · R reset";
/// The detail pane's footer (D11): the status controls, the flow open and
/// the PoC jump.
const DETAIL_FOOTER: &str = "c confirm · f false positive · u reopen · ⏎ open flow · P PoC";
/// The detail pane's one line while the cursor's row has no read yet (the
/// `scan.issue` is in flight, failed, or the verb is missing: the banner
/// says which).
const WAITING_FOR_ISSUE: &str = "waiting for scan.issue...";
/// The label of the flow list, padded like the model's labels.
const FLOWS_LABEL: &str = "flows";

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        // The banner carries the no-scanner, degraded and missing-verb
        // states; the body adds nothing to them.
        ScanOffer::None | ScanOffer::Legacy => {}
        ScanOffer::V2 if !app.has_tool("scan.issues") => {}
        ScanOffer::V2 if app.scan.issues.list.is_empty() => empty(app, theme, area, buf),
        ScanOffer::V2 => {
            let split = panes(area);
            pane_rule(theme, &split, buf);
            list(app, theme, split.list, buf);
            detail(app, theme, split.detail, buf);
        }
    }
}

/// The empty state (D13). With a filter set the line above it says which,
/// so the operator sees why an issue-bearing job shows nothing.
fn empty(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let filters = &app.scan.issues.filters;
    if filters.is_active() && area.height >= 2 {
        hint(theme, area, &filters.banner(), buf);
        let rest = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
        note(theme, rest, "no issues yet", buf);
    } else {
        note(theme, area, "no issues yet", buf);
    }
}

/// One line of the grouped list: a severity header or a row index.
enum Entry {
    Header(Severity),
    Row(usize),
}

/// The measured column widths of one list.
struct Columns {
    name: usize,
    location: usize,
    point: Option<usize>,
    status: usize,
}

impl Columns {
    /// Measure the rows, each column its widest content up to its cap (at
    /// least one cell); when the whole row does not fit `avail`, the name,
    /// then the location, give way down to [`COLUMN_MIN`], then the point
    /// column is dropped (the detail pane carries it).
    fn measure(rows: &[IssueRow], avail: usize) -> Self {
        let widest = |f: fn(&IssueRow) -> &str, cap: usize| -> usize {
            rows.iter()
                .map(|r| width(f(r)))
                .max()
                .unwrap_or(0)
                .clamp(1, cap)
        };
        let mut c = Columns {
            name: widest(|r| &r.name, NAME_MAX),
            location: widest(|r| &r.location, LOCATION_MAX),
            point: Some(widest(|r| &r.point, POINT_MAX)),
            status: widest(|r| r.status, STATUS_MAX),
        };
        if c.total() > avail {
            c.name = c.name.saturating_sub(c.total() - avail).max(COLUMN_MIN);
        }
        if c.total() > avail {
            c.location = c.location.saturating_sub(c.total() - avail).max(COLUMN_MIN);
        }
        if c.total() > avail {
            c.point = None;
        }
        c
    }

    /// The cells a row takes: the mark, the glyph pair, the columns and
    /// their gaps.
    fn total(&self) -> usize {
        1 + 2
            + 1
            + self.name
            + GAP
            + self.location
            + self.point.map_or(0, |p| GAP + p)
            + GAP
            + self.status
    }
}

/// The filter line, the grouped list scrolled so the cursor row is on
/// screen, and the footer.
fn list(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let issues = &app.scan.issues;
    hint(theme, area, &issues.filters.banner(), buf);
    let has_footer = area.height >= 3;
    let body_h = usize::from(area.height) - 1 - usize::from(has_footer);
    if body_h == 0 {
        return;
    }
    // The rows were bounded and built when the page was folded (D6).
    let rows = &issues.rows;
    let cols = Columns::measure(rows, usize::from(area.width));
    let mut entries: Vec<Entry> = Vec::with_capacity(rows.len() + 5);
    for (severity, members) in grouped(&issues.list) {
        entries.push(Entry::Header(severity));
        entries.extend(members.into_iter().map(Entry::Row));
    }
    let cursor = issues.cursor.min(rows.len().saturating_sub(1));
    let cursor_line = entries
        .iter()
        .position(|e| matches!(e, Entry::Row(k) if *k == cursor))
        .unwrap_or(0);
    let top = cursor_line.saturating_sub(body_h - 1);
    let focused = issues.pane == IssuePane::List;
    for (k, entry) in entries.iter().enumerate().skip(top).take(body_h) {
        let y = area.y + 1 + cells(k - top);
        let line_area = Rect::new(area.x, y, area.width, 1);
        match entry {
            Entry::Header(severity) => {
                let n = count_of(&issues.by_severity, *severity);
                let header = severity_header(*severity);
                // A zero header is greyed, not hidden (spec call 11); a
                // counted one wears its severity hue (D13: hue on data).
                let style = if n == 0 {
                    theme.text_tertiary()
                } else {
                    theme.severity(header)
                };
                put(
                    buf,
                    line_area,
                    Line::styled(format!(" {header} {n}"), style),
                );
            }
            Entry::Row(idx) => {
                if *idx == cursor && focused {
                    buf.set_style(line_area, selection_bg(theme));
                }
                if let Some(row) = rows.get(*idx) {
                    put(buf, line_area, row_line(theme, &cols, row, *idx == cursor));
                }
            }
        }
    }
    if has_footer {
        hint(
            theme,
            Rect::new(area.x, area.bottom() - 1, area.width, 1),
            FOOTER,
            buf,
        );
    }
}

/// The Detail pane (D11): the read issue's lines over its flow list, or the
/// waiting line while the row under the cursor has no read; the footer
/// takes the last row when there are two or more. The scroll is
/// `detail_scroll`, pulled so the flow under `flow_cursor` is on screen
/// while the Detail pane is focused (the flow keys would otherwise move a
/// cursor the operator cannot see).
fn detail(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let issues = &app.scan.issues;
    let has_footer = area.height >= 2;
    let body_h = usize::from(area.height) - usize::from(has_footer);
    let body = Rect::new(area.x, area.y, area.width, cells(body_h));
    match issues.detail() {
        None => note(theme, body, WAITING_FOR_ISSUE, buf),
        Some(issue) => {
            let focused = issues.pane == IssuePane::Detail;
            let w = usize::from(area.width) - 1;
            let mut lines: Vec<Line<'static>> = issue_detail_lines(issue)
                .iter()
                .enumerate()
                .map(|(k, text)| {
                    if k == 0 {
                        head_line(theme, text, w)
                    } else {
                        labelled_line(theme, text, w)
                    }
                })
                .collect();
            let flows = flow_refs(issue);
            let first_flow = lines.len() + 1;
            lines.push(Line::styled(
                format!(
                    " {FLOWS_LABEL:<DETAIL_LABEL_W$}{}",
                    if flows.is_empty() { " none" } else { "" }
                ),
                theme.text_secondary(),
            ));
            let flow_cursor = issues.flow_cursor.min(flows.len().saturating_sub(1));
            for (k, (id, tag)) in flows.iter().enumerate() {
                let under = k == flow_cursor;
                let mark = if under { ">" } else { " " };
                let id_w = w.saturating_sub(1 + 1 + 2 + width(tag));
                lines.push(Line::from(vec![
                    Span::styled(format!("{mark} "), theme.accent()),
                    Span::styled(truncate(id, id_w), theme.text_primary()),
                    Span::styled(format!("  {tag}"), theme.text_tertiary()),
                ]));
            }
            let mut top = usize::from(issues.detail_scroll).min(lines.len().saturating_sub(1));
            if focused && !flows.is_empty() {
                let flow_line = first_flow + flow_cursor;
                if flow_line < top {
                    top = flow_line;
                } else if flow_line >= top + body_h {
                    top = flow_line + 1 - body_h;
                }
            }
            for (k, line) in lines.into_iter().enumerate().skip(top).take(body_h) {
                let line_area = Rect::new(area.x, area.y + cells(k - top), area.width, 1);
                if focused && k == first_flow + flow_cursor && !flows.is_empty() {
                    buf.set_style(line_area, selection_bg(theme));
                }
                put(buf, line_area, line);
            }
        }
    }
    if has_footer {
        hint(
            theme,
            Rect::new(area.x, area.bottom() - 1, area.width, 1),
            DETAIL_FOOTER,
            buf,
        );
    }
}

/// The detail's first line: the name bold, then `severity · confidence ·
/// status` with the severity in its hue (D13: hue on data).
fn head_line(theme: &Theme, text: &str, w: usize) -> Line<'static> {
    let text = truncate(text, w);
    let Some((name, verdict)) = text.split_once("   ") else {
        return Line::styled(format!(" {text}"), theme.text_primary());
    };
    let mut spans = vec![Span::styled(
        format!(" {name}   "),
        theme.text_primary().add_modifier(Modifier::BOLD),
    )];
    match verdict.split_once(" · ") {
        Some((severity, rest)) => {
            spans.push(Span::styled(severity.to_string(), theme.severity(severity)));
            spans.push(Span::styled(format!(" · {rest}"), theme.text_secondary()));
        }
        None => spans.push(Span::styled(verdict.to_string(), theme.text_secondary())),
    }
    Line::from(spans)
}

/// A `label value` detail line: the label column (the model pads it to
/// `DETAIL_LABEL_W`) in secondary text, the value in primary, cut to `w`.
fn labelled_line(theme: &Theme, text: &str, w: usize) -> Line<'static> {
    let split = text
        .char_indices()
        .nth(DETAIL_LABEL_W)
        .map_or(text.len(), |(b, _)| b);
    let (label, value) = text.split_at(split);
    Line::from(vec![
        Span::styled(format!(" {label}"), theme.text_secondary()),
        Span::styled(
            truncate(value, w.saturating_sub(DETAIL_LABEL_W)),
            theme.text_primary(),
        ),
    ])
}

/// One row: the cursor mark, the glyph pair, then the measured cells.
fn row_line(theme: &Theme, cols: &Columns, row: &IssueRow, under_cursor: bool) -> Line<'static> {
    let gap = " ".repeat(GAP);
    let mark = if under_cursor { ">" } else { " " };
    let mut spans = vec![
        Span::styled(mark, theme.accent()),
        Span::styled(format!("{} ", row.glyphs), theme.text_secondary()),
        Span::styled(fit(&row.name, cols.name), theme.text_primary()),
        Span::styled(
            format!("{gap}{}", fit(&row.location, cols.location)),
            theme.text_secondary(),
        ),
    ];
    if let Some(w) = cols.point {
        spans.push(Span::styled(
            format!("{gap}{}", fit(&row.point, w)),
            theme.text_secondary(),
        ));
    }
    spans.push(Span::styled(
        format!("{gap}{}", fit(row.status, cols.status)),
        theme.text_tertiary(),
    ));
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str) -> IssueRow {
        IssueRow {
            glyphs: "●●",
            name: name.into(),
            location: "GET /search".into(),
            point: "query:q".into(),
            status: "open",
        }
    }

    /// Wide: every column at its content; narrow: the name gives way first,
    /// then the location, then the point column is dropped, and the row
    /// always fits.
    #[test]
    fn columns_shrink_from_the_name_then_drop_the_point() {
        let rows = vec![row("Reflected cross-site scripting")];
        let wide = Columns::measure(&rows, 89);
        assert_eq!(
            (wide.name, wide.location, wide.point, wide.status),
            (30, 11, Some(7), 4)
        );
        assert!(wide.total() <= 89);
        let narrow = Columns::measure(&rows, 40);
        assert!(narrow.total() <= 40, "{}", narrow.total());
        assert_eq!(narrow.point, Some(7));
        let tiny = Columns::measure(&rows, 30);
        assert_eq!(tiny.point, None, "the point column goes last");
        assert_eq!(tiny.name, COLUMN_MIN);
    }
}
