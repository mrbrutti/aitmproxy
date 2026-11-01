//! The Jobs tab's state (spec D3, D11) and the two text helpers its rows use.

use std::collections::{BTreeMap, BTreeSet};

use aitm_scan_model::{
    BySeverity, Canary, CanaryMethod, JobId, JobState, JobStatus, JobSummary, LaneKind, ListResult,
    Phase, StoppedReason,
};

use super::is_job_id;

/// Which pane of the Jobs tab holds the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JobPane {
    #[default]
    List,
    Detail,
}

/// The Jobs tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JobsState {
    /// The rows, newest first: `scan.list`'s order, with the `started_here`
    /// ids the list omits kept at the front (spec D3). A `scan.status` reply
    /// for a job not yet here puts it at the front until the next list, which
    /// drops it unless it is marked.
    pub order: Vec<JobId>,
    /// The summary of every listed job.
    pub summaries: BTreeMap<JobId, JobSummary>,
    /// Full status for the jobs `scan.status` has answered for.
    pub full: BTreeMap<JobId, JobStatus>,
    /// The list cursor.
    pub cursor: usize,
    pub pane: JobPane,
    /// Scroll offset of the Detail pane.
    pub detail_scroll: u16,
    /// The tick of the last `scan.list` request.
    pub listed_at_tick: u64,
    /// The jobs this TUI started (spec D3): a `StartResult` fold inserts the
    /// id (Task 12), a `scan.list` that carries it removes it, and
    /// [`JobsState::fold_list`] keeps at the front exactly the marked ids a
    /// list omits.
    pub started_here: BTreeSet<JobId>,
}

impl JobsState {
    /// Fold a `scan.status` / `scan.cancel` reply (spec D10): the full view
    /// replaces `full[job]`, its summary replaces `summaries[job]`, and a job
    /// not yet in `order` goes to the front (newest first).
    pub fn fold_status(&mut self, status: JobStatus) {
        let id = status.job.clone();
        if !self.order.contains(&id) {
            self.order.insert(0, id.clone());
        }
        self.summaries.insert(id.clone(), status.summary());
        self.full.insert(id, status);
    }

    /// Fold a `scan.list` reply (spec D3, D10). `order` becomes the list's
    /// order with, at the front, exactly the `started_here` ids the list
    /// omits; a list that carries a marked id unmarks it. The list's rows
    /// replace their `summaries`; `full` and `summaries` then keep only the
    /// jobs in `order`, so a job the core forgot, or one learned only from a
    /// reply or a push line, leaves with the list. A row whose id is not in
    /// the wire form is skipped (D6 hostile-core bounds). Returns the listed
    /// ids with no `full` entry yet, in list order, for one `scan.status`
    /// each (the caller caps them at [`super::MAX_STATUS_FOLLOWUPS`]).
    pub fn fold_list(&mut self, mut list: ListResult) -> Vec<JobId> {
        list.jobs.retain(|j| is_job_id(&j.job));
        let listed: BTreeSet<JobId> = list.jobs.iter().map(|j| j.job.clone()).collect();
        self.started_here.retain(|id| !listed.contains(id));
        let known: BTreeSet<&JobId> = self.order.iter().collect();
        let mut order: Vec<JobId> = self
            .order
            .iter()
            .filter(|id| self.started_here.contains(*id))
            .cloned()
            .collect();
        order.extend(
            self.started_here
                .iter()
                .filter(|id| !known.contains(id))
                .cloned(),
        );
        order.extend(list.jobs.iter().map(|j| j.job.clone()));
        for summary in list.jobs {
            self.summaries.insert(summary.job.clone(), summary);
        }
        let kept: BTreeSet<&JobId> = order.iter().collect();
        self.full.retain(|id, _| kept.contains(id));
        self.summaries.retain(|id, _| kept.contains(id));
        let followups = order
            .iter()
            .filter(|id| listed.contains(*id) && !self.full.contains_key(*id))
            .cloned()
            .collect();
        self.order = order;
        self.cursor = self.cursor.min(self.order.len().saturating_sub(1));
        followups
    }

    /// The newest job in `order` whose summary is not terminal (spec D2: the
    /// sidebar count is "the open issues total from the newest non-terminal
    /// job"). `None` when every listed job has finished.
    pub fn newest_active(&self) -> Option<&JobSummary> {
        self.order
            .iter()
            .filter_map(|id| self.summaries.get(id))
            .find(|s| !s.state.is_terminal())
    }

    /// The last state known for a job: the summary (refreshed by both
    /// `scan.list` and `scan.status`) first, the full view otherwise.
    pub fn state_of(&self, id: &str) -> Option<JobState> {
        self.summaries
            .get(id)
            .map(|s| s.state)
            .or_else(|| self.full.get(id).map(|s| s.state))
    }

    /// Every job in `summaries` or `full` whose state is not terminal: the
    /// cursor's job first, then `order`, then any known only to the maps
    /// (D6: the jobs the status timer polls, the first
    /// [`super::MAX_STATUS_FOLLOWUPS`] not already in flight per firing).
    pub fn live(&self) -> Vec<JobId> {
        let mut seen: BTreeSet<&JobId> = BTreeSet::new();
        let mut ids: Vec<JobId> = Vec::with_capacity(self.order.len());
        let under_cursor = self.order.get(self.cursor);
        for id in under_cursor
            .into_iter()
            .chain(self.order.iter())
            .chain(self.summaries.keys())
            .chain(self.full.keys())
        {
            if seen.insert(id) {
                ids.push(id.clone());
            }
        }
        ids.retain(|id| self.state_of(id).is_some_and(|s| !s.is_terminal()));
        ids
    }

    /// The job under the list cursor, if the list has one.
    pub fn cursor_job(&self) -> Option<&JobId> {
        self.order.get(self.cursor)
    }

    /// The row for a job in `order`, built through [`row`] from whatever is
    /// known: the summary (and the full view when `scan.status` answered), the
    /// full view alone when the list has not carried the job yet, or the bare
    /// id with every cell `...` when nothing has answered (a job started here
    /// before its first reply). `summaries` is never indexed: an `order` id
    /// may lack an entry (hand-off from the Task 5 panel).
    pub fn row_of(&self, id: &str) -> JobRow {
        let full = self.full.get(id);
        match (self.summaries.get(id), full) {
            (Some(summary), _) => row(summary, full),
            (None, Some(status)) => row(&status.summary(), Some(status)),
            (None, None) => JobRow::unknown(id),
        }
    }

    /// How many lines the Detail pane has for the cursor's job: the id line
    /// plus one per [`detail_lines`] entry; one line (the id alone) while no
    /// `scan.status` has answered. The reducer clamps `detail_scroll` to it.
    pub fn detail_len(&self) -> usize {
        1 + self
            .cursor_job()
            .and_then(|id| self.full.get(id))
            .map_or(0, |status| detail_lines(status).len())
    }
}

/// What a row cell reads until the value is known (spec D11: `profile` and
/// `targets` read `...` until the first `scan.status`).
pub const UNKNOWN: &str = "...";

/// One Jobs row, every cell already text except the severity tally, which
/// the view draws as a stacked bar coloured per severity (spec D11, D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub id: String,
    /// The profile name, `...` until a full status is known.
    pub profile: String,
    /// The targets joined by a space, `...` until a full status is known.
    pub targets: String,
    /// [`state_phase_text`].
    pub state_phase: String,
    /// `<sent>/<budget>`.
    pub probes: String,
    /// `<audited>/<found>`.
    pub points: String,
    pub issues: BySeverity,
    /// [`elapsed_text`].
    pub elapsed: String,
}

impl JobRow {
    /// A row for a job nothing has answered for yet: the id and `...`.
    pub fn unknown(id: &str) -> Self {
        Self {
            id: id.to_string(),
            profile: UNKNOWN.to_string(),
            targets: UNKNOWN.to_string(),
            state_phase: UNKNOWN.to_string(),
            probes: UNKNOWN.to_string(),
            points: UNKNOWN.to_string(),
            issues: BySeverity::default(),
            elapsed: UNKNOWN.to_string(),
        }
    }
}

/// The row for a job (spec D11): the counters from `summary`, which both
/// `scan.list` and `scan.status` refresh; the profile and targets from `full`,
/// which only `scan.status` carries, `...` until then.
pub fn row(summary: &JobSummary, full: Option<&JobStatus>) -> JobRow {
    JobRow {
        id: summary.job.clone(),
        profile: full.map_or_else(|| UNKNOWN.to_string(), |f| f.profile_name.clone()),
        targets: full.map_or_else(|| UNKNOWN.to_string(), |f| f.targets.join(" ")),
        state_phase: state_phase_text(summary.state, summary.phase),
        probes: format!("{}/{}", summary.probes.sent, summary.probes.budget),
        points: format!("{}/{}", summary.points.audited, summary.points.found),
        issues: summary.issues.by_severity,
        elapsed: elapsed_text(summary.elapsed_ms),
    }
}

/// The probe bar's filled cell: heavy box-drawing (spec D13: bars are
/// box-drawing cells; the mockup's geometric `▰▱` are not).
pub const BAR_FILLED: &str = "━";
/// The probe bar's empty cell: light box-drawing.
pub const BAR_EMPTY: &str = "─";
/// The severity bar's cell when the tally is zero.
pub const BAR_NONE: &str = "·";

/// `sent/budget` as `cells` box-drawing cells, filled from the left. The
/// filled count rounds up, so the first probe already shows and the bar
/// fills only at the budget; a zero budget (unlimited or unknown) draws
/// empty; more sent than budgeted fills the bar.
pub fn probe_bar(sent: u64, budget: u64, cells: usize) -> String {
    let filled = if budget == 0 || sent == 0 {
        0
    } else {
        let n = (u128::from(sent) * cells as u128).div_ceil(u128::from(budget));
        usize::try_from(n).unwrap_or(cells).min(cells)
    };
    let mut bar = BAR_FILLED.repeat(filled);
    bar.push_str(&BAR_EMPTY.repeat(cells - filled));
    bar
}

/// The severity bar's levels, gravest first: the `Theme::severity` label and
/// the cell glyph. Block heights encode the level so the stack reads on a
/// terminal without colour (builder's call; the spec leaves the glyphs open).
pub const SEVERITY_LEVELS: [(&str, &str); 5] = [
    ("critical", "█"),
    ("high", "▆"),
    ("medium", "▄"),
    ("low", "▂"),
    ("info", "▁"),
];

/// How many of `cells` each severity of `b` gets, gravest first (the order
/// of [`SEVERITY_LEVELS`]): every non-zero severity gets one cell, the rest
/// are shared in proportion by largest remainder (ties to the graver), so a
/// single critical among a hundred lows still shows. With fewer cells than
/// non-zero severities the gravest ones take them. All zero: all zero.
pub fn severity_segments(b: &BySeverity, cells: usize) -> [usize; 5] {
    let counts = [b.critical, b.high, b.medium, b.low, b.info];
    let total: u128 = counts.iter().map(|c| u128::from(*c)).sum();
    let mut seg = [0usize; 5];
    if total == 0 || cells == 0 {
        return seg;
    }
    let nonzero = counts.iter().filter(|c| **c > 0).count();
    if nonzero >= cells {
        let mut left = cells;
        for (s, c) in seg.iter_mut().zip(counts) {
            if c > 0 && left > 0 {
                *s = 1;
                left -= 1;
            }
        }
        return seg;
    }
    let spare = cells - nonzero;
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(5);
    let mut used = 0;
    for (i, c) in counts.iter().enumerate() {
        if *c == 0 {
            continue;
        }
        let exact = u128::from(*c) * spare as u128;
        let whole = usize::try_from(exact / total).unwrap_or(spare);
        seg[i] = 1 + whole;
        used += whole;
        remainders.push((exact % total, i));
    }
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, i) in remainders.into_iter().take(spare.saturating_sub(used)) {
        seg[i] += 1;
    }
    seg
}

/// The stacked severity bar as text: [`severity_segments`] drawn with the
/// [`SEVERITY_LEVELS`] glyphs, `·` per cell when the tally is zero. The view
/// colours each segment with `Theme::severity`; the glyph heights carry the
/// same reading without colour.
pub fn severity_bar(b: &BySeverity, cells: usize) -> String {
    let seg = severity_segments(b, cells);
    if seg.iter().all(|n| *n == 0) {
        return BAR_NONE.repeat(cells);
    }
    SEVERITY_LEVELS
        .iter()
        .zip(seg)
        .map(|((_, glyph), n)| glyph.repeat(n))
        .collect()
}

/// The Detail pane's `label value` lines for a job (spec D11): lanes
/// requested/run/skipped with reasons, who started it, the probe, crawl,
/// point and check counters, the session, then `clamped`, `stopped`,
/// `error` and `l4` only when present. Plain text; the view styles the label.
pub fn detail_lines(status: &JobStatus) -> Vec<(String, String)> {
    let mut lines = Vec::with_capacity(10);
    let lanes = &status.lanes;
    let mut lane_text = format!(
        "requested {} · run {}",
        lanes_text(&lanes.requested),
        lanes_text(&lanes.run)
    );
    if !lanes.skipped.is_empty() {
        let skipped: Vec<String> = lanes
            .skipped
            .iter()
            .map(|s| format!("{} ({})", lane_name(s.lane), s.reason))
            .collect();
        lane_text.push_str(" · skipped ");
        lane_text.push_str(&skipped.join(", "));
    }
    lines.push(("lanes".to_string(), lane_text));

    let by = &status.started_by;
    let who = match &by.client_label {
        Some(label) if !label.is_empty() => format!("{} ({label})", by.frontend),
        _ => by.frontend.clone(),
    };
    lines.push(("started by".to_string(), who));

    let p = &status.probes;
    let mut probes = format!(
        "sent {}/{} · errors {} · timeouts {} · rate waits {}",
        p.sent, p.budget, p.errors, p.timeouts, p.rate_waits
    );
    if !p.by_lane.is_empty() {
        let by_lane: Vec<String> = p
            .by_lane
            .iter()
            .map(|(lane, n)| format!("{} {n}", lane_name(*lane)))
            .collect();
        probes.push_str(" · by lane ");
        probes.push_str(&by_lane.join(", "));
    }
    lines.push(("probes".to_string(), probes));

    let c = &status.crawl;
    lines.push((
        "crawl".to_string(),
        format!(
            "pages {} · queued {} · depth {} · forms {}",
            c.pages, c.queued, c.depth, c.forms_submitted
        ),
    ));

    let pt = &status.points;
    lines.push((
        "points".to_string(),
        format!(
            "found {} · queued {} · audited {} · skipped ignored {}, frequent {}, limit {}",
            pt.found,
            pt.queued,
            pt.audited,
            pt.skipped.ignored,
            pt.skipped.frequent,
            pt.skipped.limit
        ),
    ));

    let ch = &status.checks;
    let mut checks = format!("{}/{} done", ch.done, ch.scheduled);
    if !ch.running.is_empty() {
        checks.push_str(" · running ");
        checks.push_str(&ch.running.join(", "));
    }
    lines.push(("checks".to_string(), checks));

    lines.push(("session".to_string(), session_text(status)));

    if !status.clamped.is_empty() {
        let clamped: Vec<String> = status
            .clamped
            .iter()
            .map(|c| format!("{} {} -> {}", c.field, c.requested, c.applied))
            .collect();
        lines.push(("clamped".to_string(), clamped.join(", ")));
    }
    if let Some(reason) = status.stopped_reason {
        lines.push(("stopped".to_string(), stopped_text(reason).to_string()));
    }
    if let Some(error) = &status.error {
        lines.push(("error".to_string(), error.clone()));
    }
    if let Some(l4) = &status.l4 {
        lines.push((
            "l4".to_string(),
            format!(
                "cases {} · crashes {} · liveness failures {} · retired {}",
                l4.cases, l4.crashes, l4.liveness_failures, l4.retired_elements
            ),
        ));
    }
    lines
}

/// The session line: `none` outside observed-session mode; else `reused` or
/// `new`, `lost` when lost, the canary, `browser partial` when the crawl was.
fn session_text(status: &JobStatus) -> String {
    let Some(s) = &status.session else {
        return "none".to_string();
    };
    let mut parts: Vec<String> = vec![if s.reused { "reused" } else { "new" }.to_string()];
    if s.lost {
        parts.push("lost".to_string());
    }
    parts.push(match &s.canary {
        Canary::None => "canary none".to_string(),
        Canary::Flow { method, path, .. } => {
            let m = match method {
                CanaryMethod::Get => "GET",
                CanaryMethod::Head => "HEAD",
            };
            format!("canary {m} {path}")
        }
    });
    if s.browser_partial {
        parts.push("browser partial".to_string());
    }
    parts.join(" · ")
}

/// A lane's wire name.
pub fn lane_name(lane: LaneKind) -> &'static str {
    match lane {
        LaneKind::Http => "http",
        LaneKind::Ws => "ws",
        LaneKind::L4Packet => "l4_packet",
        LaneKind::L4Stream => "l4_stream",
    }
}

/// Lanes joined by a space, `none` when empty.
fn lanes_text(lanes: &[LaneKind]) -> String {
    if lanes.is_empty() {
        return "none".to_string();
    }
    lanes
        .iter()
        .map(|l| lane_name(*l))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why a job stopped early, as the operator reads it.
fn stopped_text(reason: StoppedReason) -> &'static str {
    match reason {
        StoppedReason::Budget => "probe budget spent",
        StoppedReason::Time => "time budget spent",
        StoppedReason::Cancelled => "cancelled",
        StoppedReason::SessionLost => "session lost",
        StoppedReason::Errors => "per-host error ladder tripped",
        StoppedReason::Policy => "agent policy paused or read-only",
        StoppedReason::GuardRefused => "L4 guard refused a target",
        StoppedReason::Failed => "failed",
    }
}

/// A job's elapsed time for the row: `42s`, `2m05s`, `1h02m`.
pub fn elapsed_text(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// A job state's wire name, which is also what the operator reads.
pub fn state_text(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Cancelling => "cancelling",
        JobState::Done => "done",
        JobState::Cancelled => "cancelled",
        JobState::Failed => "failed",
    }
}

/// The row's `state/phase` cell: a non-terminal job reads
/// `<state>/<short phase>`, a terminal one its state alone.
pub fn state_phase_text(state: JobState, phase: Phase) -> String {
    let state_text = state_text(state);
    if state.is_terminal() {
        return state_text.to_string();
    }
    let short = match phase {
        Phase::Queued => "queued",
        Phase::Crawling => "crawl",
        Phase::Passive => "passive",
        Phase::Auditing => "audit",
        Phase::Reporting => "report",
        Phase::Done => "done",
    };
    format!("{state_text}/{short}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round A, A17: the newest job still running, in `order`, for the
    /// sidebar count; a list of finished jobs has none.
    #[test]
    fn newest_active_is_the_first_non_terminal_job_in_order() {
        let mut jobs = JobsState::default();
        for (id, state, total) in [
            ("scan-done", JobState::Done, 4),
            ("scan-live", JobState::Running, 2),
            ("scan-also-live", JobState::Queued, 0),
        ] {
            jobs.order.push(id.to_string());
            jobs.summaries.insert(
                id.to_string(),
                JobSummary {
                    job: id.to_string(),
                    state,
                    issues: aitm_scan_model::IssueCounters {
                        total,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }
        let active = jobs.newest_active().expect("a running job");
        assert_eq!(active.job, "scan-live");
        assert_eq!(active.issues.total, 2);

        jobs.order.retain(|j| j == "scan-done");
        assert!(jobs.newest_active().is_none(), "no live job, no count");
    }

    #[test]
    fn elapsed_rounds_down_to_whole_seconds() {
        assert_eq!(elapsed_text(0), "0s");
        assert_eq!(elapsed_text(999), "0s");
        assert_eq!(elapsed_text(60_000), "1m00s");
        assert_eq!(elapsed_text(3_600_000), "1h00m");
    }
}
