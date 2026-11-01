//! The Jobs tab (spec D2, D11, D13): the job table, newest first, over the
//! Detail pane of the cursor's job, with the legacy one-shot row on a legacy
//! bus (D12).
//!
//! Layout (builder's call, from the D11 wide mockup, which draws Jobs stacked
//! even at 120 columns because a full row needs the width): the table takes
//! the top of the body, sized to its rows up to two fifths of the height, a
//! rule, then the detail. Columns are measured from the rows; when the
//! `profile` and `targets` columns do not fit, the table drops them and the
//! detail's first line carries both (the narrow mockup). Hue only on data
//! (D13): the state cell by the status tokens, the severity cells by
//! `Theme::severity`; everything else is text and rule tokens.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use aitm_scan_model::JobState;

use crate::app::App;
use crate::scan::{
    detail_lines, probe_bar, severity_segments, JobPane, JobRow, LegacyRun, ScanOffer, BAR_NONE,
    SEVERITY_LEVELS,
};
use crate::theme::Theme;
use crate::tokens::color::status;
use crate::ui::bars::put;
use crate::ui::scan::{note, pane_rule, Panes};
use crate::ui::selection_bg;
use crate::ui::text::{cells, elide_middle, fit, right, truncate, width};

/// The probe bar's cells, the width of its `probes` header.
const PROBE_BAR_CELLS: usize = 6;
/// The severity bar's cells, the width of its `issues` header.
const SEVERITY_BAR_CELLS: usize = 6;
/// Blank cells between columns.
const GAP: usize = 2;
/// The widest a `profile` cell grows before it is cut.
const PROFILE_MAX: usize = 16;
/// The widest a `targets` cell grows before its middle is elided.
const TARGETS_MAX: usize = 48;
/// The share of the body the table may take when it has rows to fill it.
const LIST_PERCENT: u32 = 40;
/// The Detail pane's footer (D11).
const FOOTER: &str = "x cancel · ⏎ issues of this job · s start · m map";

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        ScanOffer::None => {}
        ScanOffer::Legacy => legacy(app, theme, area, buf),
        ScanOffer::V2 if app.scan.jobs.order.is_empty() => {
            note(theme, area, "no jobs yet: start one from Profiles (s)", buf)
        }
        ScanOffer::V2 => table(app, theme, area, buf),
    }
}

/// The job table over the Detail pane.
fn table(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let jobs = &app.scan.jobs;
    let rows: Vec<JobRow> = jobs.order.iter().map(|id| jobs.row_of(id)).collect();
    let split = split(area, rows.len());
    pane_rule(theme, &split, buf);
    list(app, theme, &rows, split.list, buf);
    detail(app, theme, &rows, split.detail, buf);
}

/// The table on top, sized to its header and rows up to [`LIST_PERCENT`] of
/// the body (at least the header and one row), a rule, the detail below.
/// A body too short for all three gives everything to the table.
fn split(area: Rect, rows: usize) -> Panes {
    let height = usize::from(area.height);
    if height < 3 {
        return Panes {
            list: area,
            detail: Rect::new(area.x, area.bottom(), area.width, 0),
            rule: None,
        };
    }
    let cap = usize::try_from(u32::from(area.height) * LIST_PERCENT / 100)
        .unwrap_or(height)
        .max(2);
    let list_h = (1 + rows).min(cap).min(height - 2);
    let list_h = cells(list_h);
    let list = Rect::new(area.x, area.y, area.width, list_h);
    let rule_y = area.y.saturating_add(list_h);
    let detail = Rect::new(
        area.x,
        rule_y.saturating_add(1),
        area.width,
        area.height.saturating_sub(list_h.saturating_add(1)),
    );
    Panes {
        list,
        detail,
        rule: Some(Rect::new(area.x, rule_y, area.width, 1)),
    }
}

/// The measured column widths of one table.
struct Columns {
    job: usize,
    profile: usize,
    targets: usize,
    state: usize,
    probes: usize,
    points: usize,
    elapsed: usize,
    /// Whether the `profile` and `targets` columns are drawn.
    full: bool,
}

impl Columns {
    /// Measure the rows: every column at least its header's width, `profile`
    /// and `targets` grown to their content up to a cap; those two are kept
    /// only when the whole row fits `avail` cells.
    fn measure(rows: &[JobRow], avail: usize) -> Self {
        let widest = |f: fn(&JobRow) -> &str, min: usize| -> usize {
            rows.iter().map(|r| width(f(r))).max().unwrap_or(0).max(min)
        };
        let mut c = Columns {
            job: widest(|r| &r.id, 3),
            profile: widest(|r| &r.profile, 7).min(PROFILE_MAX),
            targets: widest(|r| &r.targets, 7).min(TARGETS_MAX),
            state: widest(|r| &r.state_phase, 11),
            probes: widest(|r| &r.probes, 6),
            points: widest(|r| &r.points, 6),
            elapsed: widest(|r| &r.elapsed, 3),
            full: true,
        };
        c.full = c.total() <= avail;
        c
    }

    /// The cells a row takes: the cursor mark, the columns, the gaps, the
    /// probe bar beside its number and the severity bar.
    fn total(&self) -> usize {
        let mut n = 1 + self.job;
        if self.full {
            n += GAP + self.profile + GAP + self.targets;
        }
        n + GAP
            + self.state
            + GAP
            + self.probes
            + 1
            + PROBE_BAR_CELLS
            + GAP
            + self.points
            + GAP
            + SEVERITY_BAR_CELLS
            + GAP
            + self.elapsed
    }
}

/// The header and the rows, the cursor row highlighted while the List pane
/// is focused, scrolled so the cursor is always on screen.
fn list(app: &App, theme: &Theme, rows: &[JobRow], area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    let cols = Columns::measure(rows, usize::from(area.width));
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        header(theme, &cols),
    );
    let body_h = usize::from(area.height.saturating_sub(1));
    if body_h == 0 || rows.is_empty() {
        return;
    }
    let jobs = &app.scan.jobs;
    let cursor = jobs.cursor.min(rows.len() - 1);
    let top = cursor.saturating_sub(body_h - 1);
    let focused = jobs.pane == JobPane::List;
    for (k, row) in rows.iter().enumerate().skip(top).take(body_h) {
        let y = area.y + 1 + cells(k - top);
        let line_area = Rect::new(area.x, y, area.width, 1);
        if k == cursor && focused {
            buf.set_style(line_area, selection_bg(theme));
        }
        let state = jobs.state_of(&row.id);
        put(
            buf,
            line_area,
            row_line(theme, &cols, row, state, k == cursor),
        );
    }
}

/// `job  profile  targets  state/phase  probes  points  issues  el.`, the
/// middle two only in the full layout.
fn header(theme: &Theme, cols: &Columns) -> Line<'static> {
    let style = theme.text_secondary();
    let gap = " ".repeat(GAP);
    let mut spans = vec![Span::styled(format!(" {}", fit("job", cols.job)), style)];
    if cols.full {
        spans.push(Span::styled(
            format!(
                "{gap}{}{gap}{}",
                fit("profile", cols.profile),
                fit("targets", cols.targets)
            ),
            style,
        ));
    }
    spans.push(Span::styled(
        format!(
            "{gap}{}{gap}{}{gap}{}{gap}{}{gap}{}",
            fit("state/phase", cols.state),
            fit("probes", cols.probes + 1 + PROBE_BAR_CELLS),
            fit("points", cols.points),
            fit("issues", SEVERITY_BAR_CELLS),
            right("el.", cols.elapsed),
        ),
        style,
    ));
    Line::from(spans)
}

/// One row: the cursor mark, the text cells, the probe bar (filled cells in
/// primary text, the rest tertiary), the severity bar (one span per
/// non-zero severity in its `Theme::severity` hue) and the elapsed time.
fn row_line(
    theme: &Theme,
    cols: &Columns,
    row: &JobRow,
    state: Option<JobState>,
    under_cursor: bool,
) -> Line<'static> {
    let gap = " ".repeat(GAP);
    let mark = if under_cursor { ">" } else { " " };
    let mut spans = vec![
        Span::styled(mark.to_string(), theme.accent()),
        Span::styled(fit(&row.id, cols.job), theme.text_primary()),
    ];
    if cols.full {
        spans.push(Span::styled(
            format!(
                "{gap}{}{gap}{}",
                fit(&row.profile, cols.profile),
                fit(&elide_middle(&row.targets, cols.targets), cols.targets)
            ),
            theme.text_secondary(),
        ));
    }
    spans.push(Span::raw(gap.clone()));
    spans.push(Span::styled(
        fit(&row.state_phase, cols.state),
        state_style(theme, state),
    ));
    spans.push(Span::styled(
        format!("{gap}{} ", fit(&row.probes, cols.probes)),
        theme.text_primary(),
    ));
    spans.extend(probe_spans(theme, row));
    spans.push(Span::styled(
        format!("{gap}{}{gap}", fit(&row.points, cols.points)),
        theme.text_primary(),
    ));
    spans.extend(severity_spans(theme, row));
    spans.push(Span::styled(
        format!("{gap}{}", right(&row.elapsed, cols.elapsed)),
        theme.text_secondary(),
    ));
    Line::from(spans)
}

/// The probe bar split into its filled and empty runs. A row whose counters
/// are not known yet (`...`) draws the bar empty.
fn probe_spans(theme: &Theme, row: &JobRow) -> Vec<Span<'static>> {
    let (sent, budget) = row
        .probes
        .split_once('/')
        .and_then(|(s, b)| Some((s.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        .unwrap_or((0, 0));
    let bar = probe_bar(sent, budget, PROBE_BAR_CELLS);
    let filled: String = bar.chars().take_while(|c| *c == '━').collect();
    let empty: String = bar.chars().skip_while(|c| *c == '━').collect();
    vec![
        Span::styled(filled, theme.text_primary()),
        Span::styled(empty, theme.text_tertiary()),
    ]
}

/// The stacked severity bar: one span per non-zero severity in its hue,
/// `·` cells in tertiary when the tally is zero (D13: hue only on data).
fn severity_spans(theme: &Theme, row: &JobRow) -> Vec<Span<'static>> {
    let seg = severity_segments(&row.issues, SEVERITY_BAR_CELLS);
    if seg.iter().all(|n| *n == 0) {
        return vec![Span::styled(
            BAR_NONE.repeat(SEVERITY_BAR_CELLS),
            theme.text_tertiary(),
        )];
    }
    SEVERITY_LEVELS
        .iter()
        .zip(seg)
        .filter(|(_, n)| *n > 0)
        .map(|((label, glyph), n)| Span::styled(glyph.repeat(n), theme.severity(label)))
        .collect()
}

/// The state cell's hue (D13): `running` the accent, `done` success,
/// `failed` the server-error hue, `cancelled` tertiary. `cancelling` is
/// still live, so it keeps the accent; `queued` and an unknown state are
/// secondary text (builder's call).
fn state_style(theme: &Theme, state: Option<JobState>) -> Style {
    match state {
        Some(JobState::Running | JobState::Cancelling) => theme.accent(),
        Some(JobState::Done) => theme.fg(&status::SUCCESS),
        Some(JobState::Failed) => theme.fg(&status::SERVER_ERROR),
        Some(JobState::Cancelled) => theme.text_tertiary(),
        Some(JobState::Queued) | None => theme.text_secondary(),
    }
}

/// The Detail pane of the cursor's job: its id, profile and targets on the
/// first line, then the `label value` lines of [`detail_lines`] from the
/// full status, scrolled by `detail_scroll`; a job no `scan.status` has
/// answered for says so. The footer takes the last row when there are two
/// or more.
fn detail(app: &App, theme: &Theme, rows: &[JobRow], area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let jobs = &app.scan.jobs;
    let Some(row) = rows.get(jobs.cursor.min(rows.len().saturating_sub(1))) else {
        return;
    };
    let full = jobs.full.get(&row.id);
    let w = usize::from(area.width).saturating_sub(1);
    let mut lines: Vec<Line<'static>> = vec![Line::from(vec![
        Span::styled(
            format!(" {}", row.id),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}  {}", row.profile, row.targets),
            theme.text_secondary(),
        ),
    ])];
    match full {
        Some(status) => {
            // `label value`, one space between (the D11 mockup's shape):
            // no label column, so the line reads as the sentence it is.
            for (label, value) in detail_lines(status) {
                let value_w = w.saturating_sub(1 + width(&label) + 1);
                lines.push(Line::from(vec![
                    Span::styled(format!(" {label}"), theme.text_secondary()),
                    Span::styled(
                        format!(" {}", truncate(&value, value_w)),
                        theme.text_primary(),
                    ),
                ]));
            }
        }
        None => lines.push(Line::styled(
            " waiting for scan.status...",
            theme.text_tertiary(),
        )),
    }
    let has_footer = area.height >= 2;
    let body_h = usize::from(area.height) - usize::from(has_footer);
    let scroll = usize::from(jobs.detail_scroll).min(lines.len().saturating_sub(1));
    for (k, line) in lines.into_iter().skip(scroll).take(body_h).enumerate() {
        put(
            buf,
            Rect::new(area.x, area.y + cells(k), area.width, 1),
            line,
        );
    }
    if has_footer {
        put(
            buf,
            Rect::new(area.x, area.bottom() - 1, area.width, 1),
            Line::styled(format!(" {}", truncate(FOOTER, w)), theme.text_tertiary()),
        );
    }
}

/// The legacy one-shot as one row: its state, the target it crawled and the
/// key that launches it (D2's legacy launcher).
fn legacy(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    let run = LegacyRun::of(&app.scan.legacy);
    let (word, hue) = match run {
        LegacyRun::Idle => ("idle", theme.text_tertiary()),
        // D13: a running job is the accent, done is success, a failure is
        // the server-error hue.
        LegacyRun::Running => ("crawling...", theme.accent()),
        LegacyRun::Done => ("done", theme.fg(&status::SUCCESS)),
        LegacyRun::Error => ("error", theme.fg(&status::SERVER_ERROR)),
    };
    let target = app
        .scan
        .legacy
        .target
        .as_deref()
        .unwrap_or("no in-scope host: add one to scope (S)");
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        Line::from(vec![
            Span::styled(
                " one-shot ",
                theme.text_primary().add_modifier(Modifier::BOLD),
            ),
            Span::styled("· ", theme.text_tertiary()),
            Span::styled(word, hue),
            Span::raw("   "),
            Span::styled(
                truncate(target, usize::from(area.width).saturating_sub(28)),
                theme.text_secondary(),
            ),
        ]),
    );
    if area.height > 2 {
        put(
            buf,
            Rect::new(area.x, area.y + 2, area.width, 1),
            Line::styled(
                " r scan (scope-bound) · 3 Site map shows what it found · F findings",
                theme.text_tertiary(),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is sized to its rows up to two fifths of the body, with the
    /// rule right under it and the detail taking the rest.
    #[test]
    fn split_sizes_the_table_to_its_rows() {
        let p = split(Rect::new(0, 2, 120, 40), 2);
        assert_eq!(p.list, Rect::new(0, 2, 120, 3), "header plus two rows");
        assert_eq!(p.rule, Some(Rect::new(0, 5, 120, 1)));
        assert_eq!(p.detail, Rect::new(0, 6, 120, 36));

        let many = split(Rect::new(0, 0, 120, 40), 100);
        assert_eq!(many.list.height, 16, "two fifths of forty rows");

        let tiny = split(Rect::new(0, 0, 40, 2), 5);
        assert_eq!(tiny.list.height, 2);
        assert_eq!(tiny.rule, None);
        assert_eq!(tiny.detail.height, 0);
    }

    /// Below the full row's width the profile and targets columns are
    /// dropped; the rest of the columns keep their header widths.
    #[test]
    fn columns_drop_profile_and_targets_when_the_row_does_not_fit() {
        let row = JobRow {
            id: "scan-1a2b3c4d".into(),
            profile: "standard".into(),
            targets: "http://127.0.0.1:8080".into(),
            state_phase: "running/audit".into(),
            probes: "418/2000".into(),
            points: "80/120".into(),
            issues: Default::default(),
            elapsed: "42s".into(),
        };
        let wide = Columns::measure(std::slice::from_ref(&row), 198);
        assert!(wide.full);
        assert_eq!((wide.profile, wide.targets), (8, 21));
        let narrow = Columns::measure(std::slice::from_ref(&row), 88);
        assert!(!narrow.full);
        assert!(narrow.total() <= 88, "{}", narrow.total());
    }
}
