//! The Jobs tab (spec D2, D11, D13): the job table, newest first, over the
//! Detail pane of the cursor's job, with the legacy one-shot row on a legacy
//! bus (D12).
//!
//! Layout (builder's call, from the D11 wide mockup, which draws Jobs stacked
//! even at 120 columns because a full row needs the width): the table takes
//! the top of the body, sized to its rows up to two fifths of the height, a
//! rule, then the detail. Columns are measured from the rows, which the
//! model already bounded (D6 hostile-core bounds); when the `profile` and
//! `targets` columns do not fit, the table drops them and the detail's first
//! line carries both (the narrow mockup); in the full layout the detail's
//! first line is the id alone. Hue only on data (D13): the state cell by the
//! status tokens, the severity cells by `Theme::severity`; everything else
//! is text and rule tokens.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use aitm_scan_model::JobState;

use crate::app::App;
use crate::scan::{
    severity_runs, JobPane, JobRow, LegacyRun, ScanOffer, BAR_EMPTY, BAR_FILLED, PROBE_BAR_CELLS,
    PROFILE_MAX, SEVERITY_BAR_CELLS, TARGETS_MAX,
};
use crate::text::{cells, elide_middle, fit, right, truncate, width};
use crate::theme::Theme;
use crate::tokens::color::status;
use crate::ui::bars::put;
use crate::ui::scan::{
    blocked_footer, key_text, labelled, launch_reason, note, pane_rule, stacked, stacked_share,
    Panes, GAP, GAP_TEXT, JOBS_KEYS,
};

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
    let cols = Columns::measure(&rows, usize::from(split.list.width));
    // The clamped cursor, once: the list highlights it, the detail reads it.
    let cursor = jobs.cursor.min(rows.len().saturating_sub(1));
    pane_rule(theme, &split, buf);
    list(app, theme, &rows, &cols, cursor, split.list, buf);
    if let Some(row) = rows.get(cursor) {
        detail(app, theme, row, cols.full, split.detail, buf);
    }
}

/// The table on top, sized to its header and rows up to the shared
/// [`stacked_share`] of the body (at least the header and one row), a rule,
/// the detail below: [`stacked`] with content-sized rows. A body too short
/// for all three gives everything to the table.
fn split(area: Rect, rows: usize) -> Panes {
    let cap = usize::from(stacked_share(area.height)).max(2);
    stacked(area, cells((1 + rows).min(cap)))
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
            full: false,
        };
        c.full = c.total(true) <= avail;
        c
    }

    /// The cells a row takes with (`full`) or without the `profile` and
    /// `targets` columns: the cursor mark, the columns, the gaps, the probe
    /// bar beside its number and the severity bar.
    fn total(&self, full: bool) -> usize {
        let mut n = 1 + self.job;
        if full {
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

/// The header and the rows, the row at `cursor` (already clamped)
/// highlighted while the List pane is focused, scrolled so the cursor is
/// always on screen.
fn list(
    app: &App,
    theme: &Theme,
    rows: &[JobRow],
    cols: &Columns,
    cursor: usize,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height == 0 {
        return;
    }
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        header(theme, cols),
    );
    let body_h = usize::from(area.height.saturating_sub(1));
    if body_h == 0 || rows.is_empty() {
        return;
    }
    let jobs = &app.scan.jobs;
    let focused = jobs.pane == JobPane::List;
    let body = Rect::new(area.x, area.y + 1, area.width, cells(body_h));
    crate::ui::scan::rows(buf, theme, body, rows.len(), cursor, focused, |k| {
        let row = &rows[k];
        row_line(theme, cols, row, jobs.state_of(&row.id), k == cursor)
    });
}

/// `job  profile  targets  state/phase  probes  points  issues  el.`, the
/// middle two only in the full layout.
fn header(theme: &Theme, cols: &Columns) -> Line<'static> {
    let style = theme.text_secondary();
    let gap = GAP_TEXT;
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
    let gap = GAP_TEXT;
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
    spans.push(Span::raw(GAP_TEXT));
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

/// The probe bar: the row's typed `probe_fill` cells filled in primary
/// text, the rest empty in tertiary (an unknown row has a fill of 0).
fn probe_spans(theme: &Theme, row: &JobRow) -> Vec<Span<'static>> {
    let fill = row.probe_fill.min(PROBE_BAR_CELLS);
    vec![
        Span::styled(BAR_FILLED.repeat(fill), theme.text_primary()),
        Span::styled(
            BAR_EMPTY.repeat(PROBE_BAR_CELLS - fill),
            theme.text_tertiary(),
        ),
    ]
}

/// The stacked severity bar: one span per run of [`severity_runs`] in its
/// severity's hue; the zero tally's single unlabelled run in tertiary (D13:
/// hue only on data).
fn severity_spans(theme: &Theme, row: &JobRow) -> Vec<Span<'static>> {
    severity_runs(&row.issues, SEVERITY_BAR_CELLS)
        .into_iter()
        .map(|(label, run)| {
            let style = if label.is_empty() {
                theme.text_tertiary()
            } else {
                theme.severity(label)
            };
            Span::styled(run, style)
        })
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

/// The Detail pane of the cursor's job (`row`): its id on the first line,
/// with the profile and targets after it only when the table was too
/// narrow to draw them (`table_full` is false), then the `label value`
/// lines of `JobsState::detail_text` (the full status's lines, or the
/// waiting placeholder), scrolled by `detail_scroll`, over the shared
/// [`blocked_footer`]: the key footer, and above it the UI-3 or refused
/// launch reason ([`launch_reason`]) wrapped in the warning hue, since `s`
/// is live on this tab too (fix round G, G65).
fn detail(app: &App, theme: &Theme, row: &JobRow, table_full: bool, area: Rect, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    let jobs = &app.scan.jobs;
    let w = usize::from(area.width);
    let reason = launch_reason(app);
    let body = blocked_footer(theme, area, reason.as_deref(), &key_text(&[JOBS_KEYS]), buf);
    let mut first = vec![Span::styled(
        format!(" {}", row.id),
        theme.text_primary().add_modifier(Modifier::BOLD),
    )];
    if !table_full {
        // The two columns the narrow table dropped, cut to what the id
        // leaves of the row (the targets are the long part).
        let rest = w.saturating_sub(1 + width(&row.id) + 2);
        first.push(Span::styled(
            format!(
                "  {}",
                truncate(&format!("{}  {}", row.profile, row.targets), rest)
            ),
            theme.text_secondary(),
        ));
    }
    let mut lines: Vec<Line<'static>> = vec![Line::from(first)];
    for (label, value) in jobs.detail_text() {
        if label.is_empty() {
            lines.push(Line::styled(format!(" {value}"), theme.text_tertiary()));
            continue;
        }
        // `label value`, one space between (the D11 mockup's shape): no
        // label column, so the line reads as the sentence it is.
        lines.push(labelled(theme, label, &value, w, width(label)));
    }
    let body_h = usize::from(body.height);
    let scroll = usize::from(jobs.detail_scroll).min(lines.len().saturating_sub(1));
    for (k, line) in lines.into_iter().skip(scroll).take(body_h).enumerate() {
        put(
            buf,
            Rect::new(body.x, body.y + cells(k), body.width, 1),
            line,
        );
    }
}

/// The legacy one-shot as one row: its state and the target it crawled
/// (D2's legacy launcher); its keys are the status bar's hints, like every
/// other tab's (D11, D12).
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

    /// The fixture's row is 100 cells wide with its profile and targets
    /// columns (the two take 33 of them); below that width the two are
    /// dropped and the rest of the columns keep their header widths.
    #[test]
    fn columns_drop_profile_and_targets_when_the_row_does_not_fit() {
        let row = JobRow {
            id: "scan-1a2b3c4d".into(),
            profile: "standard".into(),
            targets: "http://127.0.0.1:8080".into(),
            state_phase: "running/audit".into(),
            probes: "418/2000".into(),
            probe_fill: 2,
            points: "80/120".into(),
            issues: Default::default(),
            elapsed: "42s".into(),
        };
        let cols = Columns::measure(std::slice::from_ref(&row), 100);
        assert_eq!(cols.total(true), 100, "the full row's width");
        assert_eq!(cols.total(false), 67, "without profile and targets");
        assert!(cols.full, "a 100-cell row fits 100 cells");
        assert_eq!((cols.profile, cols.targets), (8, 21));
        let narrow = Columns::measure(std::slice::from_ref(&row), 99);
        assert!(!narrow.full, "one cell short drops the two columns");
    }
}
