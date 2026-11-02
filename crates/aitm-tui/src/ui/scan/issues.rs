//! The Issues tab (spec D2, D11, D13). The list half: the rows sit under
//! the five severity headers with their `by_severity` counts, a zero header
//! greyed rather than hidden (spec call 11); the filter banner tops the pane
//! and the filter keys foot it. The detail half: the read issue's head and
//! `label value` pairs (`scan::issue_head`, `scan::issue_detail_lines`,
//! bounded by the model at fold time) around the walkable flow list
//! (`scan::flow_at`), scrolled by `detail_view.scroll`, pulled to the flow
//! under the flow cursor while `detail_view.follow_flow` is set (the last
//! key was a flow key), and the status-control footer. The degraded states are the state
//! banner's (D13: one state on screen).
//!
//! Row layout (builder's call, from the D11 mockup): `>` cursor mark, the
//! confidence glyph pair, the name, `METHOD path_template`, `kind:name` and
//! the status, in columns measured from the rows the model already bounded
//! (D6 hostile-core bounds); when the pane is narrow the name gives way
//! first, then the location, then the point column is dropped. Hue only on
//! data (D13): the headers in `Theme::severity`, everything else text
//! tokens.

use aitm_poc::Severity;
use aitm_scan_model::FlowRef;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{
    confidence_token, count_of, flow_at, grouped, issue_detail_lines, issue_head, severity_header,
    severity_token, status_token, DetailLayout, DetailRow, FlowTag, IssueHead, IssuePane, IssueRow,
    ScanOffer, LOCATION_MAX, NAME_MAX, POINT_MAX,
};
use crate::text::{cells, fit, truncate, width};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::scan::{
    hint, key_text, labelled, note, pane_rule, panes, rows, GAP, ISSUES_FILTER_KEYS, ISSUES_KEYS,
};
use crate::ui::selection_bg;

/// The widest a status cell grows: `false_positive`, the longest status
/// token, is fourteen cells (pinned by a unit test).
const STATUS_MAX: usize = 14;
/// The narrowest a cut column is allowed to get before the next one goes.
const COLUMN_MIN: usize = 8;
/// The detail pane's one line while the cursor's row has no read (the
/// `scan.issue` is in flight, failed, or the verb is missing: the banner
/// says which, so this stays neutral; fix round F, F2).
const NO_DETAIL: &str = "no detail read for this row";
/// The label of the flow list.
const FLOWS_LABEL: &str = "flows";
/// The `label` column every detail line after the head is written with
/// (`payload     <script>...`): the labels are padded to it so the values
/// line up, as in the D11 mockup.
const DETAIL_LABEL_W: usize = 11;

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
    let table = &issues.rows;
    let cols = Columns::measure(table, usize::from(area.width));
    let mut entries: Vec<Entry> = Vec::with_capacity(table.len() + 5);
    for (severity, members) in grouped(&issues.list) {
        entries.push(Entry::Header(severity));
        entries.extend(members.into_iter().map(Entry::Row));
    }
    let cursor = issues.cursor.min(table.len().saturating_sub(1));
    let cursor_line = entries
        .iter()
        .position(|e| matches!(e, Entry::Row(k) if *k == cursor))
        .unwrap_or(0);
    let focused = issues.pane == IssuePane::List;
    let body = Rect::new(area.x, area.y + 1, area.width, cells(body_h));
    rows(
        theme,
        body,
        entries.len(),
        cursor_line,
        focused,
        |k| match entries[k] {
            Entry::Header(severity) => {
                let n = count_of(&issues.by_severity, severity);
                let header = severity_header(severity);
                // A zero header is greyed, not hidden (spec call 11); a
                // counted one wears its severity hue (D13: hue on data).
                let style = if n == 0 {
                    theme.text_tertiary()
                } else {
                    theme.severity(header)
                };
                Line::styled(format!(" {header} {n}"), style)
            }
            Entry::Row(idx) => table.get(idx).map_or_else(Line::default, |row| {
                row_line(theme, &cols, row, idx == cursor)
            }),
        },
        buf,
    );
    if has_footer {
        hint(
            theme,
            Rect::new(area.x, area.bottom() - 1, area.width, 1),
            &key_text(&[ISSUES_FILTER_KEYS]),
            buf,
        );
    }
}

/// The Detail pane (D11): the read issue's head line, the lines before the
/// flows, the walkable flow list (its `flows` label, one line per flow, a
/// `... n more` line when the fold dropped any), then the lines after the
/// flows (fix round F, F1), or the placeholder while the row under the
/// cursor has no read; the footer takes the last row when there are two
/// or more. The scroll is `detail_view.scroll`, exactly as drawn, except
/// that while the Detail pane is focused and `follow_flow` is set (the
/// last key was a flow key; fix round F, F7) it is pulled so the flow under
/// the flow cursor is on screen. The row arithmetic is the model's
/// (`DetailLayout`, fix round G, G2); only the rows on screen are built
/// (fix round F, F4).
fn detail(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let issues = &app.scan.issues;
    let has_footer = area.height >= 2;
    let body_h = usize::from(area.height) - usize::from(has_footer);
    let body = Rect::new(area.x, area.y, area.width, cells(body_h));
    match issues.detail() {
        None => note(theme, body, NO_DETAIL, buf),
        Some(read) => {
            let focused = issues.pane == IssuePane::Detail;
            let w = usize::from(area.width);
            let lines = issue_detail_lines(read);
            let layout = DetailLayout::of(read);
            debug_assert_eq!(
                layout.total,
                1 + lines.before_flows.len()
                    + 1
                    + layout.flows
                    + usize::from(layout.more)
                    + lines.after_flows.len(),
                "the layout counts the lines built"
            );
            let flow_index = issues.flow_index();
            let view = &issues.detail_view;
            let mut top = usize::from(view.scroll).min(layout.total.saturating_sub(1));
            if focused && view.follow_flow {
                if let Some(f) = flow_index {
                    let flow_line = layout.first_flow + f;
                    if flow_line < top {
                        top = flow_line;
                    } else if flow_line >= top + body_h {
                        top = flow_line + 1 - body_h;
                    }
                }
            }
            for k in top..(top + body_h).min(layout.total) {
                let line_area = Rect::new(area.x, area.y + cells(k - top), area.width, 1);
                let row = layout.row(k);
                if focused && matches!(row, DetailRow::Flow(f) if Some(f) == flow_index) {
                    buf.set_style(line_area, selection_bg(theme));
                }
                let line = match row {
                    DetailRow::Head => head_line(theme, &issue_head(read), w),
                    DetailRow::Before(i) => {
                        let (label, value) = &lines.before_flows[i];
                        labelled(theme, label, value, w, DETAIL_LABEL_W)
                    }
                    DetailRow::FlowsLabel => labelled(
                        theme,
                        FLOWS_LABEL,
                        if layout.flows == 0 { "none" } else { "" },
                        w,
                        DETAIL_LABEL_W,
                    ),
                    DetailRow::Flow(f) => match flow_at(read, f) {
                        Some((id, tag)) => flow_line(theme, &id, tag, Some(f) == flow_index, w),
                        None => Line::default(),
                    },
                    DetailRow::More => labelled(
                        theme,
                        "",
                        &format!("... {} more", read.dropped.flows),
                        w,
                        DETAIL_LABEL_W,
                    ),
                    DetailRow::After(i) => {
                        let (label, value) = &lines.after_flows[i];
                        labelled(theme, label, value, w, DETAIL_LABEL_W)
                    }
                };
                put(buf, line_area, line);
            }
        }
    }
    if has_footer {
        hint(
            theme,
            Rect::new(area.x, area.bottom() - 1, area.width, 1),
            &key_text(&[ISSUES_KEYS]),
            buf,
        );
    }
}

/// The detail's first line: the name bold, then `severity · confidence ·
/// status` with the severity in its hue (D13: hue on data), each part
/// styled from the typed value, so a name that spells a verdict cannot
/// forge the hue (fix round F, F5); the name gives way when the pane is
/// narrow.
fn head_line(theme: &Theme, head: &IssueHead<'_>, w: usize) -> Line<'static> {
    let severity = severity_token(head.severity);
    let rest = format!(
        " · {} · {}",
        confidence_token(head.confidence),
        status_token(head.status)
    );
    let name_w = w.saturating_sub(1 + 3 + width(severity) + width(&rest));
    Line::from(vec![
        Span::styled(
            format!(" {}   ", truncate(head.name, name_w)),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ),
        Span::styled(severity.to_string(), theme.severity(severity)),
        Span::styled(rest, theme.text_secondary()),
    ])
}

/// One flow of the walkable list: the cursor mark, the id cut to the room
/// the tag leaves, then the tag.
fn flow_line(theme: &Theme, id: &FlowRef, tag: FlowTag, under: bool, w: usize) -> Line<'static> {
    let mark = if under { ">" } else { " " };
    let tag = tag.label();
    let id_w = w.saturating_sub(1 + 1 + 2 + width(tag));
    Line::from(vec![
        Span::styled(format!("{mark} "), theme.accent()),
        Span::styled(truncate(&id.to_string(), id_w), theme.text_primary()),
        Span::styled(format!("  {tag}"), theme.text_tertiary()),
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
    use crate::scan::status_token;
    use aitm_scan_model::IssueStatus;

    /// Fix round E, E16: the status column cap is the longest status token.
    #[test]
    fn status_max_is_the_longest_status_token() {
        assert_eq!(STATUS_MAX, status_token(IssueStatus::FalsePositive).len());
        for s in [IssueStatus::Open, IssueStatus::Confirmed] {
            assert!(status_token(s).len() <= STATUS_MAX);
        }
    }

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
