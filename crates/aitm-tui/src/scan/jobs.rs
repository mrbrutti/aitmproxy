//! The Jobs tab's state (spec D3, D11) and the text helpers its rows use.
//! A row is bounded when it is built (D6 hostile-core bounds): the view
//! measures and draws what [`row`] already cut, never the core's strings.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use aitm_scan_model::{
    BySeverity, Canary, CanaryMethod, CheckCounters, CheckErrorSample, CrawlCounters,
    CrawlErrorKind, JobId, JobState, JobStatus, JobSummary, LaneKind, ListResult, Phase,
    SkippedPoints, StoppedReason,
};

use super::{
    due, is_job_id, lane_token, more, severity_counts, severity_token, ScanError, DETAIL_VALUE_MAX,
    NOT_IN_TIME, SEVERITY_ORDER,
};
use crate::text::{clean, cut_to, truncate};

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
    /// The summary of every listed job. Every key is in `order`; an `order`
    /// id started here and not yet answered has none (`row_of` draws it as
    /// `...`). Invariant, kept by [`JobsState::fold_status`] and
    /// [`JobsState::fold_list`]: `full.keys() ⊆ summaries.keys() ⊆ order`
    /// (a status fold writes both maps and `order`; a list fold retains
    /// both maps to `order`), so the walks read `order` alone and a key of
    /// either map is always a row.
    pub summaries: BTreeMap<JobId, JobSummary>,
    /// Full status for the jobs `scan.status` has answered for, bounded at
    /// fold ([`ReadStatus`]); every key is in `summaries` and in `order`
    /// (see `summaries`).
    pub full: BTreeMap<JobId, ReadStatus>,
    /// The list cursor.
    pub cursor: usize,
    pub pane: JobPane,
    /// Where in `order` the next status firing's walk starts (spec D6, the
    /// [`super::MAX_STATUS_FOLLOWUPS`] cap): [`JobsState::live`] rotates
    /// `order` here and [`JobsState::advance_poll`] moves it past the jobs
    /// a firing attempted, so with `n` live jobs every one is reached within
    /// `ceil((n - 1) / 15)` firings while the cursor's job is live (it rides
    /// at the front out of turn, taking one of the 16 slots) and
    /// `ceil(n / 16)` otherwise, instead of the first 16 starving the rest.
    pub poll_offset: usize,
    /// Scroll offset of the Detail pane.
    pub detail_scroll: u16,
    /// The tick of the last `scan.list` request.
    pub listed_at_tick: u64,
    /// The tick of the last `scan.list` reply that folded (Jobs view D19;
    /// stamped by the reducer), so the Jobs banner can say how old the
    /// values on screen are while the bus stays silent; `None` until the
    /// first list lands.
    pub listed_ok_at_tick: Option<u64>,
    /// The tick the `scan.list` now in flight left (Jobs view D19
    /// amendment, the hung-core detector; stamped by the reducer): `None`
    /// when no list is in flight, when its reply settled (ok or error),
    /// when the bus dropped, or once the detector has fired for it, so it
    /// fires once per request and re-arms when the next list leaves.
    pub list_sent_at_tick: Option<u64>,
    /// The jobs this TUI started (spec D3): a `StartResult` fold inserts the
    /// id (Task 12), a `scan.list` that carries it removes it, and
    /// [`JobsState::fold_list`] keeps at the front exactly the marked ids a
    /// list omits.
    pub started_here: BTreeSet<JobId>,
    /// The jobs a `not_found` self-heal dropped since the last timer-driven
    /// `scan.list` (fix round G, G83): [`JobsState::fold_list`] asks no
    /// `scan.status` for them, so a core that lists a job and answers
    /// `not_found` for it is polled at most once per timer window instead
    /// of driving a reply-paced list/status ping-pong. The forty-tick timer
    /// clears it when its list leaves.
    pub healed: BTreeSet<JobId>,
    /// The tab's own error (spec D13 as ruled 2026-11-01, fix round H, H56):
    /// the last `scan.list`, `scan.status` or `scan.cancel` failure, shown
    /// on the Jobs banner alone until the next success under its tag
    /// ([`super::ScanState::clear_error`]) or, for a keyed
    /// `scan.status:<job>` / `scan.cancel:<job>` error, until its job turns
    /// terminal or leaves the list ([`super::ScanState::fold_job_status`],
    /// [`super::ScanState::fold_job_list`]; fix round H, H66). Its third
    /// source is the hung-core detector (Jobs view D19 amendment): the
    /// uncoded `scan.list` error [`NOT_IN_TIME`], set by the reducer when
    /// the list in flight is [`super::LIST_OVERDUE_TICKS`] overdue and
    /// cleared by that list's late fold like any other `scan.list` error.
    pub error: Option<ScanError>,
}

/// Whether the `scan.list` that left on `sent_at` is `limit_ticks` or more
/// ticks overdue on `now_tick` (Jobs view D19 amendment, the hung-core
/// detector): [`due`]'s comparison, so no list in flight (`None`) is never
/// overdue and a tick behind the stamp never underflows.
pub fn list_overdue(now_tick: u64, sent_at: Option<u64>, limit_ticks: u64) -> bool {
    due(sent_at, now_tick, limit_ticks)
}

impl JobsState {
    /// Whether the Jobs error is the hung-core detector's sentence (Jobs
    /// view D19 amendment): an uncoded `scan.list` error whose detail is
    /// [`NOT_IN_TIME`]. While it stands, `x` is refused: a cancel would
    /// queue behind the hung call and fire unseen when the core wakes. Any
    /// other `scan.list` error, the same words under a keyed tag, or no
    /// error at all reads false.
    pub fn unanswered(&self) -> bool {
        self.error
            .as_ref()
            .is_some_and(|e| e.tag == "scan.list" && e.code.is_none() && e.detail == NOT_IN_TIME)
    }

    /// Fold a `scan.status` / `scan.cancel` reply (spec D10): the full view
    /// replaces `full[job]`, its summary replaces `summaries[job]`, and a job
    /// not yet in `order` goes to the front (newest first). The core's
    /// strings are bounded here, once ([`bound_status`]; D6: "row strings
    /// are bounded once at fold time"), so [`row`] and the Detail pane only
    /// copy bounded text.
    pub fn fold_status(&mut self, status: JobStatus) {
        let read = ReadStatus::new(status);
        let id = read.job.clone();
        if !self.order.contains(&id) {
            self.order.insert(0, id.clone());
        }
        self.summaries.insert(id.clone(), read.summary());
        self.full.insert(id, read);
    }

    /// A job this TUI started answered with its first status (spec D7;
    /// fix round G, G64): the id is marked `started_here` (the next list
    /// that omits it keeps it at the front, fix round B, B3), the status
    /// folded, the id moved to the front of `order`, and the List pane
    /// focused on it from the top. The reducer keeps the D6 bounds and the
    /// toasts.
    pub fn land_started(&mut self, status: JobStatus) {
        let id = status.job.clone();
        self.started_here.insert(id.clone());
        self.fold_status(status);
        if let Some(pos) = self.order.iter().position(|j| *j == id) {
            if pos != 0 {
                let moved = self.order.remove(pos);
                self.order.insert(0, moved);
            }
        }
        self.cursor = 0;
        self.pane = JobPane::List;
        self.detail_scroll = 0;
    }

    /// Forget a job the core no longer knows (D9 `not_found`; fix round G,
    /// G77): out of `order`, `summaries`, `full` and `started_here` (else
    /// the next list would put it back at the front), the cursor clamped
    /// to what is left.
    pub fn forget(&mut self, id: &str) {
        self.order.retain(|j| j != id);
        self.summaries.remove(id);
        self.full.remove(id);
        self.started_here.remove(id);
        self.cursor = self.cursor.min(self.order.len().saturating_sub(1));
    }

    /// Fold a `scan.list` reply (spec D3, D10). `order` becomes the list's
    /// order with, at the front, exactly the `started_here` ids the list
    /// omits; a list that carries a marked id unmarks it. The list's rows
    /// replace their `summaries`; `full` and `summaries` then keep only the
    /// jobs in `order`, so a job the core forgot, or one learned only from a
    /// reply or a push line, leaves with the list. A row whose id is not in
    /// the wire form is skipped and the list is cut to [`JOBS_MAX`] rows
    /// (D6 hostile-core bounds; fix round H, H36). Returns, in list order,
    /// the listed ids not in `healed` (G83) that need one `scan.status`
    /// each (the caller caps them at [`super::MAX_STATUS_FOLLOWUPS`]): the
    /// ids with no `full` entry yet, and the ids the list calls terminal
    /// while `full[id].state` is still live (Jobs view D19, T1: `live()`
    /// stops polling a job the moment the list calls it terminal, so
    /// without this the stored status, and the Detail pane's checks line,
    /// would stay at the last running read).
    pub fn fold_list(&mut self, mut list: ListResult) -> Vec<JobId> {
        list.jobs.retain(|j| is_job_id(&j.job));
        list.jobs.truncate(JOBS_MAX);
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
            .filter(|id| listed.contains(*id) && !self.healed.contains(*id))
            .filter(|id| match self.full.get(*id) {
                None => true,
                Some(full) => {
                    !full.state.is_terminal()
                        && self
                            .summaries
                            .get(*id)
                            .is_some_and(|s| s.state.is_terminal())
                }
            })
            .cloned()
            .collect();
        debug_assert!(
            self.summaries.keys().all(|id| kept.contains(id))
                && self.full.keys().all(|id| self.summaries.contains_key(id)),
            "full.keys() ⊆ summaries.keys() ⊆ order"
        );
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

    /// Every job in `order` whose state is not terminal, in the order the
    /// status timer polls them (D6): the cursor's job first, then `order`
    /// read from `poll_offset` round to it. The maps are retained to
    /// `order` (see `summaries`), so nothing else can be live.
    pub fn live(&self) -> Vec<JobId> {
        let n = self.order.len();
        let start = if n == 0 { 0 } else { self.poll_offset % n };
        let under_cursor = self.order.get(self.cursor);
        let mut ids: Vec<JobId> = Vec::with_capacity(n);
        ids.extend(under_cursor.cloned());
        ids.extend(
            self.order[start..]
                .iter()
                .chain(&self.order[..start])
                .filter(|id| Some(*id) != under_cursor)
                .cloned(),
        );
        ids.retain(|id| self.state_of(id).is_some_and(|s| !s.is_terminal()));
        ids
    }

    /// Move the status walk past the jobs one firing attempted (`polled`,
    /// the prefix of [`JobsState::live`] the cap let through, in flight or
    /// sent): the next firing starts at the `order` entry after the last one
    /// walked. The cursor's job rides at the front out of turn, so it is
    /// skipped unless it is all the firing reached; with it live each
    /// firing advances the walk by 15, so `n` live jobs are all reached
    /// within `ceil((n - 1) / 15)` firings, `ceil(n / 16)` without it. A
    /// job no longer in `order` leaves the offset where it was.
    pub fn advance_poll(&mut self, polled: &[JobId]) {
        let cursor = self.cursor_job();
        let last = polled
            .iter()
            .rev()
            .find(|id| Some(*id) != cursor)
            .or(polled.last());
        if let Some(i) = last.and_then(|id| self.order.iter().position(|o| o == id)) {
            self.poll_offset = (i + 1) % self.order.len();
        }
    }

    /// The job under the list cursor, if the list has one.
    pub fn cursor_job(&self) -> Option<&JobId> {
        self.order.get(self.cursor)
    }

    /// The row for a job in `order`, built through [`row`] from whatever is
    /// known: the summary (and the full view when `scan.status` answered),
    /// or the bare id with every cell `...` when nothing has answered (a job
    /// started here before its first reply). `summaries` is never indexed:
    /// an `order` id may lack an entry; a `full` entry without a summary
    /// cannot happen (`full.keys() ⊆ summaries.keys()`, see `summaries`).
    pub fn row_of(&self, id: &str) -> JobRow {
        match self.summaries.get(id) {
            Some(summary) => row(summary, self.full.get(id)),
            None => JobRow::unknown(id),
        }
    }

    /// The Detail pane's `label value` lines for the cursor's job: the
    /// lines of its full status (lanes, started by, probes, crawl, points,
    /// checks, session, then `clamped`, `stopped`, `error` and `l4` when
    /// present), or the one placeholder line (an empty label) while no
    /// `scan.status` has answered. The view draws exactly these under the
    /// id line; [`JobsState::detail_len`] counts them without building them.
    pub fn detail_text(&self) -> Vec<(&'static str, String)> {
        match self.cursor_job().and_then(|id| self.full.get(id)) {
            Some(read) => detail_lines(read),
            None => vec![("", WAITING_FOR_STATUS.to_string())],
        }
    }

    /// How many lines the Detail pane has for the cursor's job: the id line
    /// plus [`JobsState::detail_text`]'s count, counted without building the
    /// lines. The reducer clamps `detail_scroll` to it on every key.
    pub fn detail_len(&self) -> usize {
        1 + self
            .cursor_job()
            .and_then(|id| self.full.get(id))
            .map_or(1, |r| detail_line_count(r))
    }
}

/// The Detail pane's one line while no `scan.status` has answered.
const WAITING_FOR_STATUS: &str = "waiting for scan.status...";

/// The most entries the Detail pane lists of `checks.running`, `clamped`
/// and `lanes.skipped` (fix round G, G11; the builder's number): the fold
/// keeps this many and counts the rest into [`StatusDropped`], which the
/// lines print as `+n`.
pub const DETAIL_LIST_MAX: usize = 8;

/// How many entries [`bound_status`] cut off each of the Detail lists
/// (fix round G, G11), so their lines can end in `+n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusDropped {
    pub running: usize,
    pub clamped: usize,
    pub skipped: usize,
    /// Targets past [`DETAIL_LIST_MAX`] (fix round G, G102).
    pub targets: usize,
    /// `checks.error_samples` past [`DETAIL_LIST_MAX`] (Jobs view D19, T1).
    pub error_samples: usize,
    /// `checks.skipped_samples` past [`DETAIL_LIST_MAX`] (Jobs view D19, T1).
    pub skipped_samples: usize,
}

/// A full status as `JobsState::full` holds it (fix round G, G11,
/// mirroring the Issues tab's `ReadIssue`): the `JobStatus` with its
/// strings and lists bounded by [`bound_status`], and what that cut off.
/// Derefs to the `JobStatus`, so a reader writes `read.probes` as before.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadStatus {
    pub status: JobStatus,
    pub dropped: StatusDropped,
}

impl ReadStatus {
    /// Bound `status` once ([`bound_status`]) and keep what was cut.
    pub fn new(mut status: JobStatus) -> Self {
        let dropped = bound_status(&mut status);
        Self { status, dropped }
    }
}

impl Deref for ReadStatus {
    type Target = JobStatus;

    fn deref(&self) -> &JobStatus {
        &self.status
    }
}

/// Bound a `scan.status` reply once, at fold (D6 hostile-core bounds; fix
/// round G, G10, G11): control characters stripped from every string the
/// screen reads; `profile_name` cut to [`PROFILE_MAX`], every target to
/// four times [`TARGETS_MAX`], and `error`, `started_by.frontend`,
/// `client_label`, each `clamped[].field`, each `lanes.skipped[].reason`,
/// each `checks.running[]`, each `check`, `point` and `detail` of
/// `checks.error_samples[]` and `checks.skipped_samples[]` (Jobs view D19,
/// T1) and the canary path to [`DETAIL_VALUE_MAX`] cells; the three lists,
/// `targets` and both sample lists cut to [`DETAIL_LIST_MAX`] with the rest
/// counted in the returned [`StatusDropped`] (G102); `lanes.requested` and
/// `lanes.run` sorted and deduped (fix round H, H33: four kinds at most, so
/// the Detail pane joins a bounded list).
fn bound_status(status: &mut JobStatus) -> StatusDropped {
    dedup_lanes(&mut status.lanes.requested);
    dedup_lanes(&mut status.lanes.run);
    let cut = |s: &mut String| cut_to(s, DETAIL_VALUE_MAX);
    status.profile_name = truncate(&clean(&status.profile_name), PROFILE_MAX);
    let dropped = StatusDropped {
        running: cap(&mut status.checks.running),
        clamped: cap(&mut status.clamped),
        skipped: cap(&mut status.lanes.skipped),
        targets: cap(&mut status.targets),
        error_samples: cap(&mut status.checks.error_samples),
        skipped_samples: cap(&mut status.checks.skipped_samples),
    };
    for target in &mut status.targets {
        *target = truncate(&clean(target), 4 * TARGETS_MAX);
    }
    cut(&mut status.started_by.frontend);
    let mut fields: Vec<&mut String> = Vec::new();
    fields.extend(status.error.as_mut());
    fields.extend(status.started_by.client_label.as_mut());
    fields.extend(status.clamped.iter_mut().map(|c| &mut c.field));
    fields.extend(status.lanes.skipped.iter_mut().map(|s| &mut s.reason));
    fields.extend(status.checks.running.iter_mut());
    let samples = status
        .checks
        .error_samples
        .iter_mut()
        .chain(status.checks.skipped_samples.iter_mut());
    for sample in samples {
        fields.push(&mut sample.check);
        fields.push(&mut sample.point);
        fields.push(&mut sample.detail);
    }
    if let Some(session) = &mut status.session {
        if let Canary::Flow { path, .. } = &mut session.canary {
            fields.push(path);
        }
    }
    for field in fields {
        cut(field);
    }
    dropped
}

/// Sort and dedup a lane list and give its capacity back (fix round H,
/// H33): at most one entry per [`LaneKind`], in declaration order.
fn dedup_lanes(lanes: &mut Vec<LaneKind>) {
    lanes.sort_unstable();
    lanes.dedup();
    lanes.shrink_to_fit();
}

/// Cut `v` to [`DETAIL_LIST_MAX`], give the capacity back and return how
/// many entries left.
fn cap<T>(v: &mut Vec<T>) -> usize {
    let dropped = v.len().saturating_sub(DETAIL_LIST_MAX);
    v.truncate(DETAIL_LIST_MAX);
    v.shrink_to_fit();
    dropped
}

/// The most rows a `scan.list` reply folds to (fix round H, H36; D6
/// hostile-core bounds): the list is cut to this many before the
/// started-here ids are put in front, so `order` is bounded in count.
pub const JOBS_MAX: usize = 256;
/// The widest a `profile` cell grows before it is cut (the column cap, and
/// the bound [`JobsState::fold_status`] applies to the core's string).
pub const PROFILE_MAX: usize = 16;
/// The widest a `targets` column grows before its middle is elided;
/// [`JobsState::fold_status`] cuts every target to four times this and
/// [`row`] keeps at most four times this of the joined targets.
pub const TARGETS_MAX: usize = 48;
/// How many targets [`row`] joins; the rest are counted (`+n`).
const TARGETS_JOINED: usize = 4;
/// The progress bar's cells, drawn beside the row's `progress` number.
pub const PROGRESS_BAR_CELLS: usize = 6;
/// The severity bar's cells, the width of its `issues` header.
pub const SEVERITY_BAR_CELLS: usize = 6;

/// What a row cell reads until the value is known (spec D11: `profile` and
/// `targets` read `...` until the first `scan.status`).
pub const UNKNOWN: &str = "...";

/// One Jobs row, every cell already text and bounded except the severity
/// tally, which the view draws as a stacked bar coloured per severity (spec
/// D11, D13), and the progress bar's fill, typed so the view never parses
/// the row's text back (Jobs view D19, T2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub id: String,
    /// The profile name, cut to [`PROFILE_MAX`] by the fold; `...` until a
    /// full status is known.
    pub profile: String,
    /// The first [`TARGETS_JOINED`] targets (each cut by the fold) joined
    /// by a space (`+n` for the rest), the whole cut to four times
    /// [`TARGETS_MAX`]; `...` until a full status is known.
    pub targets: String,
    /// [`state_phase_text`].
    pub state_phase: String,
    /// [`progress_text`]: `<done>/<scheduled>` checks while auditing,
    /// `<pages>/<known>` while crawling, `...` while indeterminate or until
    /// a full status is known.
    pub progress: String,
    /// [`progress_fill`] of the derived ring over [`PROGRESS_BAR_CELLS`];
    /// 0 while indeterminate or unknown.
    pub progress_fill: usize,
    /// `<sent>/<budget>` probes, a number without a bar.
    pub budget: String,
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
            progress: UNKNOWN.to_string(),
            progress_fill: 0,
            budget: UNKNOWN.to_string(),
            points: UNKNOWN.to_string(),
            issues: BySeverity::default(),
            elapsed: UNKNOWN.to_string(),
        }
    }
}

/// The row for a job (spec D11): the counters from `summary`, which both
/// `scan.list` and `scan.status` refresh; the profile and targets from `full`,
/// which only `scan.status` carries, `...` until then. The core's strings
/// were bounded when the status was folded ([`JobsState::fold_status`], D6
/// hostile-core bounds), so this only copies bounded text and a frame's
/// measuring and eliding runs over at most a few hundred cells per row.
pub fn row(summary: &JobSummary, full: Option<&ReadStatus>) -> JobRow {
    let status = full.map(|f| &f.status);
    let (ring, source) = progress_ring(summary, status);
    JobRow {
        id: summary.job.clone(),
        profile: full.map_or_else(|| UNKNOWN.to_string(), |f| f.profile_name.clone()),
        targets: full.map_or_else(
            || UNKNOWN.to_string(),
            |f| targets_text(&f.targets, f.dropped.targets),
        ),
        state_phase: state_phase_text(summary.state, summary.phase),
        progress: progress_text(source),
        progress_fill: progress_fill(ring.bar_fraction(), PROGRESS_BAR_CELLS),
        budget: format!("{}/{}", summary.probes.sent, summary.probes.budget),
        points: format!("{}/{}", summary.points.audited, summary.points.found),
        issues: summary.issues.by_severity,
        elapsed: elapsed_text(summary.elapsed_ms),
    }
}

/// The row's `targets` cell: the first [`TARGETS_JOINED`] targets (each
/// already cut by the fold) joined by a space, `+n` for any more (the
/// `dropped` the fold cut past [`DETAIL_LIST_MAX`] counted in; G102), the
/// whole cut to four times [`TARGETS_MAX`].
fn targets_text(targets: &[String], dropped: usize) -> String {
    let mut text = targets
        .iter()
        .take(TARGETS_JOINED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let beyond = targets.len().saturating_sub(TARGETS_JOINED) + dropped;
    text.push_str(&more(beyond));
    truncate(&text, 4 * TARGETS_MAX)
}

/// The progress bar's filled cell: heavy box-drawing (spec D13: bars are
/// box-drawing cells; the mockup's geometric `▰▱` are not).
pub const BAR_FILLED: &str = "━";
/// The progress bar's empty cell: light box-drawing.
pub const BAR_EMPTY: &str = "─";
/// The severity bar's cell when the tally is zero.
pub const BAR_NONE: &str = "·";

/// The kind of ring the derived progress draws (Jobs view D8): the TUI's
/// bar is the ring. `Finished` keeps the final fraction when the counters
/// give one, so a finished bar keeps its fill.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ring {
    None,
    Indeterminate,
    Determinate(f64),
    Finished(Option<f64>),
}

impl Ring {
    /// The fraction the bar draws: the determinate value while live, the
    /// final one for a finished job (D8: a finished bar keeps its fill),
    /// `None` for an indeterminate ring.
    pub(crate) fn bar_fraction(self) -> Option<f64> {
        match self {
            Ring::Determinate(f) | Ring::Finished(Some(f)) => Some(f),
            Ring::None | Ring::Indeterminate | Ring::Finished(None) => None,
        }
    }
}

/// Where the row's `progress` numbers come from (Jobs view D19): the
/// counters the ring was derived from, carried as numbers so [`row`]
/// formats only the cell it draws ([`progress_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// `<done>/<scheduled>` checks: auditing, reporting once any were
    /// scheduled, and a finished job that scheduled any.
    Checks { done: u64, scheduled: u64 },
    /// `<pages>/<pages + queued>`: crawling once any are known, and a
    /// finished job that scheduled no checks but knew pages.
    Crawl { pages: u64, known: u64 },
    /// Nothing to show: indeterminate, queued, or no status yet.
    None,
}

/// The derived progress of a job (Jobs view D8; the parity pin P15–P22):
/// computed from the summary's state and phase and, once `scan.status`
/// has answered, the full counters; never from a text cell.
#[derive(Debug, Clone, PartialEq)]
pub struct JobProgress {
    pub ring: Ring,
    /// The determinate value, 0 to 1; `None` otherwise (a finished job
    /// included: its card is the end sentence).
    pub fraction: Option<f64>,
    /// The card's progress line: `3,236 of 6,468 checks`, `46 pages, 12
    /// queued`, …; empty for a finished job.
    pub phase_line: String,
    /// `Now: xss-reflected` / `Now: xss-reflected and 3 more`; `None` when
    /// no check is running.
    pub now_line: Option<String>,
}

/// The numeric half of [`progress`], D8's table made total: `queued`
/// waits; `running` and `cancelling` take the running rule for the phase
/// (crawling over `pages + queued`, auditing over `scheduled`, passive
/// indeterminate, reporting 1); a terminal state is finished over the
/// final counters (the auditing rule, else the crawling rule, else none);
/// running without a status yet is indeterminate. With the ring, the
/// [`Source`] of its numbers, so [`row`] formats no words it does not draw
/// (Task 4.5c). The fraction is clamped at 1, so a core reporting more
/// done than scheduled reads `100 %`, never more.
pub(crate) fn progress_ring(summary: &JobSummary, full: Option<&JobStatus>) -> (Ring, Source) {
    let Some(full) = full else {
        return if summary.state.is_terminal() {
            (Ring::Finished(None), Source::None)
        } else {
            (Ring::Indeterminate, Source::None)
        };
    };
    let checks = checks_fraction(&full.checks).map(|f| {
        (
            f,
            Source::Checks {
                done: full.checks.done,
                scheduled: full.checks.scheduled,
            },
        )
    });
    let crawl = crawl_fraction(&full.crawl).map(|f| {
        (
            f,
            Source::Crawl {
                pages: full.crawl.pages,
                known: full.crawl.pages.saturating_add(full.crawl.queued),
            },
        )
    });
    let determinate = |numbers: Option<(f64, Source)>| match numbers {
        Some((f, source)) => (Ring::Determinate(f), source),
        None => (Ring::Indeterminate, Source::None),
    };
    match summary.state {
        JobState::Queued => (Ring::Indeterminate, Source::None),
        state if state.is_terminal() => match checks.or(crawl) {
            Some((f, source)) => (Ring::Finished(Some(f)), source),
            None => (Ring::Finished(None), Source::None),
        },
        _ => match summary.phase {
            Phase::Crawling => determinate(crawl),
            Phase::Auditing => determinate(checks),
            Phase::Reporting => (
                Ring::Determinate(1.0),
                checks.map_or(Source::None, |(_, source)| source),
            ),
            Phase::Passive | Phase::Queued | Phase::Done => (Ring::Indeterminate, Source::None),
        },
    }
}

/// The derived progress of a job: the ring and its fraction from
/// [`progress_ring`], the card's words on top ([`phase_line`] and the
/// `Now:` line). The Detail pane reads this; the row reads
/// [`progress_ring`] alone.
pub fn progress(summary: &JobSummary, full: Option<&JobStatus>) -> JobProgress {
    let (ring, source) = progress_ring(summary, full);
    let fraction = match ring {
        Ring::Determinate(f) => Some(f),
        Ring::None | Ring::Indeterminate | Ring::Finished(_) => None,
    };
    JobProgress {
        ring,
        fraction,
        phase_line: phase_line(summary, full, source),
        now_line: full.and_then(|f| now_line(&f.checks.running)),
    }
}

/// The card's progress line (D8): `queued` waits for the engine; a
/// terminal state has none (its card is the end sentence); running without
/// a status yet is the phase word; crawling counts pages and queued,
/// passive and reporting have fixed words, auditing counts the checks once
/// the ring's [`Source`] is the checks (`Scheduling checks` before), the
/// other phases their word.
fn phase_line(summary: &JobSummary, full: Option<&JobStatus>, source: Source) -> String {
    match (summary.state, full) {
        (JobState::Queued, _) => "Waiting for the engine to start this job.".to_string(),
        (state, _) if state.is_terminal() => String::new(),
        (_, None) => phase_word(summary.phase).to_string(),
        (_, Some(full)) => match summary.phase {
            Phase::Crawling => format!(
                "{}, {} queued",
                plural(full.crawl.pages, "page"),
                grouped(full.crawl.queued)
            ),
            Phase::Passive => "Passive checks over captured traffic".to_string(),
            Phase::Auditing => match source {
                Source::Checks { done, scheduled } => {
                    format!("{} of {}", grouped(done), plural(scheduled, "check"))
                }
                Source::Crawl { .. } | Source::None => "Scheduling checks".to_string(),
            },
            Phase::Reporting => "Writing results".to_string(),
            Phase::Queued | Phase::Done => phase_word(summary.phase).to_string(),
        },
    }
}

/// The auditing rule: `done / scheduled`, clamped at 1; `None` while
/// nothing is scheduled.
fn checks_fraction(checks: &CheckCounters) -> Option<f64> {
    (checks.scheduled > 0).then(|| (checks.done as f64 / checks.scheduled as f64).min(1.0))
}

/// The crawling rule: `pages / (pages + queued)`; `None` while nothing was
/// fetched or queued.
fn crawl_fraction(crawl: &CrawlCounters) -> Option<f64> {
    let known = crawl.pages.saturating_add(crawl.queued);
    (known > 0).then(|| crawl.pages as f64 / known as f64)
}

/// `Now: <first id>`, `Now: <first id> and <n> more`; `None` for none.
fn now_line(running: &[String]) -> Option<String> {
    let first = running.first()?;
    Some(match running.len() - 1 {
        0 => format!("Now: {first}"),
        n => format!("Now: {first} and {n} more"),
    })
}

/// The percent of a determinate fraction, floored (D8: it never reads
/// `100 %` before the fraction is 1), with a U+00A0 before the `%` so the
/// string is the mac's and the web's byte for byte (the parity pin P15);
/// ratatui draws the no-break space as one blank cell. `None` for none.
pub(crate) fn percent_text(fraction: Option<f64>) -> Option<String> {
    fraction.map(|f| format!("{}\u{a0}%", (f.clamp(0.0, 1.0) * 100.0).floor() as u64))
}

/// How many of `cells` the progress bar fills for `fraction`: the floor of
/// the fraction over the cells, like the percent, so the bar reads full
/// only at 1; nothing for an indeterminate (`None`) or non-finite value.
pub fn progress_fill(fraction: Option<f64>, cells: usize) -> usize {
    let Some(f) = fraction else {
        return 0;
    };
    if !f.is_finite() {
        return 0;
    }
    let n = (f.clamp(0.0, 1.0) * cells as f64).floor();
    usize::try_from(n as u64).unwrap_or(cells).min(cells)
}

/// The progress bar as `cells` box-drawing cells, [`progress_fill`] of
/// them [`BAR_FILLED`] from the left, the rest [`BAR_EMPTY`] (Jobs view
/// D8: an indeterminate bar is all empty; a finished bar keeps its fill).
pub fn progress_bar(fraction: Option<f64>, cells: usize) -> String {
    let filled = progress_fill(fraction, cells);
    let mut bar = BAR_FILLED.repeat(filled);
    bar.push_str(&BAR_EMPTY.repeat(cells - filled));
    bar
}

/// The row's `progress` cell (Jobs view D19): the numbers of the ring's
/// [`Source`], `<done>/<scheduled>` checks or `<pages>/<pages + queued>`,
/// `...` while indeterminate or until a full status is known.
pub(crate) fn progress_text(source: Source) -> String {
    match source {
        Source::Checks { done, scheduled } => format!("{done}/{scheduled}"),
        Source::Crawl { pages, known } => format!("{pages}/{known}"),
        Source::None => UNKNOWN.to_string(),
    }
}

/// The severity bar's cell glyph per level, indexed like
/// [`SEVERITY_ORDER`] (gravest first). Block heights encode the level so
/// the stack reads on a terminal without colour (builder's call; the spec
/// leaves the glyphs open); the `Theme::severity` label of a run is its
/// severity's [`severity_token`].
pub const SEVERITY_LEVELS: [&str; 5] = ["█", "▆", "▄", "▂", "▁"];

/// How many of `cells` each severity of `b` gets, gravest first (the order
/// of [`SEVERITY_ORDER`]): every non-zero severity gets one cell, the rest
/// are shared in proportion by largest remainder (ties to the graver), so a
/// single critical among a hundred lows still shows. With fewer cells than
/// non-zero severities the gravest ones take them. All zero: all zero.
pub fn severity_segments(b: &BySeverity, cells: usize) -> [usize; 5] {
    let counts = severity_counts(b);
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

/// The stacked severity bar as runs: one `(severity label, glyph run)` per
/// non-zero severity, gravest first ([`severity_segments`] drawn with the
/// [`SEVERITY_LEVELS`] glyphs); a zero tally is one run with an empty label
/// and `·` per cell. The view colours each run with `Theme::severity`; the
/// glyph heights carry the same reading without colour.
pub fn severity_runs(b: &BySeverity, cells: usize) -> Vec<(&'static str, String)> {
    let seg = severity_segments(b, cells);
    if seg.iter().all(|n| *n == 0) {
        return vec![("", BAR_NONE.repeat(cells))];
    }
    SEVERITY_ORDER
        .iter()
        .zip(SEVERITY_LEVELS)
        .zip(seg)
        .filter(|(_, n)| *n > 0)
        .map(|((severity, glyph), n)| (severity_token(*severity), glyph.repeat(n)))
        .collect()
}

/// The stacked severity bar as text: [`severity_runs`] concatenated.
pub fn severity_bar(b: &BySeverity, cells: usize) -> String {
    severity_runs(b, cells)
        .into_iter()
        .map(|(_, run)| run)
        .collect()
}

/// How many lines [`detail_lines`] gives `status`, without building them:
/// the first line, for a stopped reason the `wire` line plus the `stopped`
/// line when D4 gives it a sentence ([`stopped_sentence`]), the `now` line
/// when a check is running, the attention lines
/// ([`attention_line_count`]), the seven fixed lines, then one each for
/// `clamped`, `error` and `l4` when present. Kept in step with
/// `detail_lines` by its unit tests.
fn detail_line_count(status: &JobStatus) -> usize {
    let stopped = match status.stopped_reason {
        None => 0,
        Some(reason) => {
            1 + usize::from(stopped_sentence_applies(
                reason,
                status.state,
                status.error.as_deref(),
            ))
        }
    };
    1 + stopped
        + usize::from(!status.checks.running.is_empty())
        + attention_line_count(status)
        + DETAIL_FIXED_LINES
        + usize::from(!status.clamped.is_empty())
        + usize::from(status.error.is_some())
        + usize::from(status.l4.is_some())
}

/// The Detail pane's first line (Jobs view D19, T2): the end sentence for
/// a terminal job ([`end_sentence`], the parity pin P1–P3), else the
/// percent and the phase line of the derived progress (`50 % · 3,236 of
/// 6,468 checks`), the phase line alone while indeterminate.
fn first_line(status: &JobStatus) -> String {
    if let Some(sentence) = end_sentence(
        status.state,
        status.elapsed_ms,
        status.points.found,
        status.checks.done,
        status.checks.scheduled,
    ) {
        return sentence;
    }
    let p = progress(&status.summary(), Some(status));
    match percent_text(p.fraction) {
        Some(percent) => format!("{percent} · {}", p.phase_line),
        None => p.phase_line,
    }
}

/// The attention lines (Jobs view D9), in this order and only when
/// non-zero: `7 checks could not run` with its samples as `<check>:
/// <detail>` rows, `3 checks were skipped` (`1 check was skipped`, plan gap
/// 26) with its samples, and the crawl trouble ([`crawl_trouble`]) with
/// the last error's words after a dash when the core named one. The
/// samples were cut at fold ([`bound_status`]): [`DETAIL_LIST_MAX`] rows
/// per list, each field at most [`DETAIL_VALUE_MAX`] cells, so a sample
/// row is at most `2 × DETAIL_VALUE_MAX + 2` cells; the renderer cuts it
/// to the pane with a trailing `…`.
fn attention_lines(status: &JobStatus) -> Vec<String> {
    let ch = &status.checks;
    let mut lines = Vec::with_capacity(attention_line_count(status));
    if ch.errors > 0 {
        lines.push(format!("{} could not run", plural(ch.errors, "check")));
        lines.extend(ch.error_samples.iter().map(sample_line));
    }
    if ch.skipped > 0 {
        let verb = if ch.skipped == 1 { "was" } else { "were" };
        lines.push(format!("{} {verb} skipped", plural(ch.skipped, "check")));
        lines.extend(ch.skipped_samples.iter().map(sample_line));
    }
    if let Some(trouble) = crawl_trouble(&status.crawl) {
        lines.push(match status.crawl.last_error {
            Some(kind) => format!("{trouble} — {}", crawl_error_words(kind)),
            None => trouble,
        });
    }
    lines
}

/// How many lines [`attention_lines`] gives, without building them.
fn attention_line_count(status: &JobStatus) -> usize {
    let ch = &status.checks;
    let errors = if ch.errors > 0 {
        1 + ch.error_samples.len()
    } else {
        0
    };
    let skipped = if ch.skipped > 0 {
        1 + ch.skipped_samples.len()
    } else {
        0
    };
    errors + skipped + usize::from(status.crawl.errors > 0)
}

/// `<check>: <detail>`; the check alone when the core gave no detail.
fn sample_line(sample: &CheckErrorSample) -> String {
    if sample.detail.is_empty() {
        sample.check.clone()
    } else {
        format!("{}: {}", sample.check, sample.detail)
    }
}

/// [`stopped_sentence`] for a status's own state, budget and error.
fn status_stopped_sentence(status: &JobStatus, reason: StoppedReason) -> Option<String> {
    stopped_sentence(
        reason,
        status.state,
        status.probes.budget,
        status.error.as_deref(),
    )
}

/// The lines every [`detail_lines`] has: lanes, started by, probes, crawl,
/// points, checks, session.
const DETAIL_FIXED_LINES: usize = 7;

/// The Detail pane's lines for a job (spec D11; Jobs view D19, T2). First
/// the [`first_line`] with an empty label (the end sentence, or the
/// percent and phase line), then `stopped` (D4's sentence, omitted when D4
/// says none) with the raw token under it on a `wire` line, `now` with the
/// running check ids, the [`attention_lines`] (empty labels), and the
/// `label value` lines: lanes requested/run/skipped with reasons, who
/// started it, the probe, crawl (with `· errors n (<last error words>)`
/// when the crawl hit any; Jobs view D4), point counters (the skip clause
/// is the Kit's three skip words; Jobs view D21, plan gap 62), check
/// counters (with `· errors n · skipped n` when non-zero), the session,
/// then `clamped`, `error` and `l4` only when present; a list the fold cut
/// ends in `+n` (fix round G, G11). Plain text; the view styles the label.
/// Read through [`JobsState::detail_text`], the one public reading of the
/// pane (fix round E, E5).
fn detail_lines(read: &ReadStatus) -> Vec<(&'static str, String)> {
    let status = &read.status;
    let mut lines = Vec::with_capacity(detail_line_count(status));
    lines.push(("", first_line(status)));
    if let Some(reason) = status.stopped_reason {
        if let Some(sentence) = status_stopped_sentence(status, reason) {
            lines.push(("stopped", sentence));
        }
        lines.push(("wire", format!("stopped_reason: {}", stopped_token(reason))));
    }
    if !status.checks.running.is_empty() {
        lines.push((
            "now",
            format!(
                "{}{}",
                status.checks.running.join(", "),
                more(read.dropped.running)
            ),
        ));
    }
    lines.extend(attention_lines(status).into_iter().map(|l| ("", l)));
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
            .map(|s| format!("{} ({})", lane_token(s.lane), s.reason))
            .collect();
        lane_text.push_str(" · skipped ");
        lane_text.push_str(&skipped.join(", "));
        lane_text.push_str(&more(read.dropped.skipped));
    }
    lines.push(("lanes", lane_text));

    let by = &status.started_by;
    let who = match &by.client_label {
        Some(label) if !label.is_empty() => format!("{} ({label})", by.frontend),
        _ => by.frontend.clone(),
    };
    lines.push(("started by", who));

    let p = &status.probes;
    let mut probes = format!(
        "sent {}/{} · errors {} · timeouts {} · rate waits {}",
        p.sent, p.budget, p.errors, p.timeouts, p.rate_waits
    );
    if !p.by_lane.is_empty() {
        let by_lane: Vec<String> = p
            .by_lane
            .iter()
            .map(|(lane, n)| format!("{} {n}", lane_token(*lane)))
            .collect();
        probes.push_str(" · by lane ");
        probes.push_str(&by_lane.join(", "));
    }
    lines.push(("probes", probes));

    let c = &status.crawl;
    let mut crawl = format!(
        "pages {} · queued {} · depth {} · forms {}",
        c.pages, c.queued, c.depth, c.forms_submitted
    );
    if c.errors > 0 {
        crawl.push_str(&format!(" · errors {}", c.errors));
        if let Some(kind) = c.last_error {
            crawl.push_str(&format!(" ({})", crawl_error_words(kind)));
        }
    }
    lines.push(("crawl", crawl));

    let pt = &status.points;
    lines.push((
        "points",
        format!(
            "found {} · queued {} · audited {} · {}",
            grouped(pt.found),
            grouped(pt.queued),
            grouped(pt.audited),
            point_skip_words(&pt.skipped).join(" · ")
        ),
    ));

    let ch = &status.checks;
    let mut checks = format!("{}/{} done", ch.done, ch.scheduled);
    if ch.errors > 0 {
        checks.push_str(&format!(" · errors {}", ch.errors));
    }
    if ch.skipped > 0 {
        checks.push_str(&format!(" · skipped {}", ch.skipped));
    }
    if !ch.running.is_empty() {
        checks.push_str(" · running ");
        checks.push_str(&ch.running.join(", "));
        checks.push_str(&more(read.dropped.running));
    }
    lines.push(("checks", checks));

    lines.push(("session", session_text(status)));

    if !status.clamped.is_empty() {
        let clamped: Vec<String> = status
            .clamped
            .iter()
            .map(|c| format!("{} {} -> {}", c.field, c.requested, c.applied))
            .collect();
        lines.push((
            "clamped",
            format!("{}{}", clamped.join(", "), more(read.dropped.clamped)),
        ));
    }
    if let Some(error) = &status.error {
        lines.push(("error", error.clone()));
    }
    if let Some(l4) = &status.l4 {
        lines.push((
            "l4",
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

/// Lanes joined by a space, `none` when empty.
fn lanes_text(lanes: &[LaneKind]) -> String {
    if lanes.is_empty() {
        return "none".to_string();
    }
    lanes
        .iter()
        .map(|l| lane_token(*l))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why a job stopped early, as the operator reads it: D4's sentence for
/// the reason, identical on the mac, web and TUI surfaces (Jobs view D4,
/// the parity pin). The budget sentence carries a literal `{budget}`
/// placeholder that [`stopped_sentence`] fills with the grouped number.
pub fn stopped_text(reason: StoppedReason) -> &'static str {
    match reason {
        StoppedReason::Budget => {
            "Stopped early: the probe budget of {budget} was spent. Raise it in the profile to go further."
        }
        StoppedReason::Time => "Stopped early: the time budget ran out.",
        StoppedReason::Cancelled => "Stopped early: the job was cancelled.",
        StoppedReason::SessionLost => {
            "Stopped early: the session was lost and the profile says stop when that happens."
        }
        StoppedReason::Errors => "Stopped early: too many errors from the target.",
        StoppedReason::Policy => "Stopped early: the agent policy changed to paused or read-only.",
        StoppedReason::GuardRefused => "Stopped early: the L4 guard refused a target mid-run.",
        StoppedReason::Failed => "Stopped early: an error ended the job.",
    }
}

/// The stopped-reason sentence for the Detail pane (Jobs view D4): the
/// `{budget}` of [`stopped_text`] filled with `probes_budget` grouped;
/// `None` for a reason the state already says (`cancelled` on a cancelled
/// job) or the error text already shows (`failed` with a non-empty
/// `error`; an empty error counts as none, plan gap 8).
pub fn stopped_sentence(
    reason: StoppedReason,
    state: JobState,
    probes_budget: u64,
    error: Option<&str>,
) -> Option<String> {
    if !stopped_sentence_applies(reason, state, error) {
        return None;
    }
    Some(match reason {
        StoppedReason::Budget => stopped_text(reason).replace("{budget}", &grouped(probes_budget)),
        _ => stopped_text(reason).to_string(),
    })
}

/// D4's nil rules alone (Task 4.5c): whether [`stopped_sentence`] has a
/// sentence for `reason`, so the line count can know without building it.
/// `cancelled` on a cancelled job is said by the state; `failed` with a
/// non-empty error is said by the error line (an empty error counts as
/// none, plan gap 8); every other reason has its sentence.
fn stopped_sentence_applies(reason: StoppedReason, state: JobState, error: Option<&str>) -> bool {
    match reason {
        StoppedReason::Cancelled => state != JobState::Cancelled,
        StoppedReason::Failed => !error.is_some_and(|e| !e.is_empty()),
        _ => true,
    }
}

/// The wire token of a stopped reason, as `scan.status` carries it
/// (`session_lost`, `guard_refused`, …): the Detail pane's `wire` line,
/// `stopped_reason: <token>`, the one place the raw token is shown (Jobs
/// view D4). Pinned against serde's spelling by the unit test.
pub(crate) fn stopped_token(reason: StoppedReason) -> &'static str {
    match reason {
        StoppedReason::Budget => "budget",
        StoppedReason::Time => "time",
        StoppedReason::Cancelled => "cancelled",
        StoppedReason::SessionLost => "session_lost",
        StoppedReason::Errors => "errors",
        StoppedReason::Policy => "policy",
        StoppedReason::GuardRefused => "guard_refused",
        StoppedReason::Failed => "failed",
    }
}

/// The words for a `crawl.last_error` token (Jobs view D4): `transport`
/// and `other` both read as a failed connection.
pub fn crawl_error_words(kind: CrawlErrorKind) -> &'static str {
    match kind {
        CrawlErrorKind::ConnectRefused => "the target refused the connection",
        CrawlErrorKind::Tls => "TLS handshake failed",
        CrawlErrorKind::Timeout => "the target did not answer in time",
        CrawlErrorKind::H2NotNegotiated => "the target does not speak HTTP/2",
        CrawlErrorKind::Transport | CrawlErrorKind::Other => "the connection failed",
    }
}

/// `The crawl fetched 1 page and hit 1 error` (Jobs view D4); `None` when
/// the crawl hit none.
pub fn crawl_trouble(crawl: &CrawlCounters) -> Option<String> {
    if crawl.errors == 0 {
        return None;
    }
    Some(format!(
        "The crawl fetched {} and hit {}",
        plural(crawl.pages, "page"),
        plural(crawl.errors, "error")
    ))
}

/// The one sentence for a terminal job (Jobs view D4, the parity pin P1 to
/// P3): `Done in 1:09 · 1,020 points · 6,468 checks.`, `Cancelled after
/// 1:55; 3,236 of 6,468 checks had run. What it found stays.`, `Failed
/// after 0:12.` (the error text follows on its own line); `None` while
/// the job is live.
pub fn end_sentence(
    state: JobState,
    elapsed_ms: u64,
    points_found: u64,
    checks_done: u64,
    checks_scheduled: u64,
) -> Option<String> {
    let elapsed = elapsed_clock(elapsed_ms);
    match state {
        JobState::Done => Some(format!(
            "Done in {elapsed} · {} · {}.",
            plural(points_found, "point"),
            plural(checks_scheduled, "check")
        )),
        JobState::Cancelled => Some(format!(
            "Cancelled after {elapsed}; {} of {} had run. What it found stays.",
            grouped(checks_done),
            plural(checks_scheduled, "check")
        )),
        JobState::Failed => Some(format!("Failed after {elapsed}.")),
        JobState::Queued | JobState::Running | JobState::Cancelling => None,
    }
}

/// The end sentences' elapsed time: `m:ss`, or `h:mm:ss` from an hour on
/// (the mac Kit's `ScanFormat.elapsed`; the row keeps [`elapsed_text`]).
fn elapsed_clock(ms: u64) -> String {
    let total = ms / 1000;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// `1 point` / `1,020 points`: the one singular rule of the sentences, the
/// count grouped ([`grouped`]).
fn plural(n: u64, noun: &str) -> String {
    let s = if n == 1 { "" } else { "s" };
    format!("{} {noun}{s}", grouped(n))
}

/// The Kit's `ScanFormat.pointSkipWords` (Jobs view D21, plan gap 62): one
/// `<grouped count> <words>` text per skip counter in the Kit's order
/// (frequent, ignored, limit), zeros included: `722 skipped as repetitive`,
/// `6 skipped by rule`, `0 skipped at the per-request cap`.
fn point_skip_words(skipped: &SkippedPoints) -> [String; 3] {
    [
        format!("{} skipped as repetitive", grouped(skipped.frequent)),
        format!("{} skipped by rule", grouped(skipped.ignored)),
        format!("{} skipped at the per-request cap", grouped(skipped.limit)),
    ]
}

/// A count with a `,` every three digits (`6,468`, `1,234,567`) whatever
/// the locale (Jobs view D4, D11).
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
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

/// The row's `state` cell (Jobs view D19, T2; the parity pin P23 in the
/// TUI's lowercase): the phase word alone while `running` (`auditing`),
/// the state word alone otherwise (`queued`, `cancelling`, `done`,
/// `cancelled`, `failed`), as the other surfaces read it.
pub fn state_phase_text(state: JobState, phase: Phase) -> String {
    match state {
        JobState::Running => phase_word(phase),
        JobState::Queued
        | JobState::Cancelling
        | JobState::Done
        | JobState::Cancelled
        | JobState::Failed => state_text(state),
    }
    .to_string()
}

/// A phase's word, as the operator reads it in the row and on the card.
fn phase_word(phase: Phase) -> &'static str {
    match phase {
        Phase::Queued => "queued",
        Phase::Crawling => "crawling",
        Phase::Passive => "passive",
        Phase::Auditing => "auditing",
        Phase::Reporting => "reporting",
        Phase::Done => "done",
    }
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

    /// Fix round C, C20/C24: the count the reducer clamps the scroll to
    /// mirrors the lines the view draws, with and without every optional
    /// line.
    #[test]
    fn detail_line_count_mirrors_detail_lines() {
        let read_of = |status: &JobStatus| ReadStatus {
            status: status.clone(),
            dropped: StatusDropped::default(),
        };
        let bare = JobStatus::default();
        assert_eq!(
            detail_line_count(&bare),
            detail_lines(&read_of(&bare)).len()
        );
        // Jobs view D19, T2: the first line (the queued default's waiting
        // line) sits over the seven fixed lines.
        assert_eq!(detail_line_count(&bare), 8);
        let full = JobStatus {
            clamped: vec![aitm_scan_model::Clamped {
                field: "budget.probes".into(),
                requested: 9000,
                applied: 2000,
            }],
            stopped_reason: Some(StoppedReason::Budget),
            error: Some("boom".into()),
            l4: Some(Default::default()),
            ..Default::default()
        };
        assert_eq!(
            detail_line_count(&full),
            detail_lines(&read_of(&full)).len()
        );
        assert_eq!(
            detail_line_count(&full),
            13,
            "first line + stopped + wire + seven fixed + clamped + error + l4"
        );
    }

    /// Fix round G, G64, G77: a started job lands at the front with the
    /// List pane on it, even when the list already carried it further
    /// down; forgetting the cursor's job clamps the cursor.
    #[test]
    fn land_started_fronts_the_job_and_forget_clamps_the_cursor() {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/scan.status.json"
        );
        let text = std::fs::read_to_string(fixture).expect("the status fixture");
        let status: JobStatus = serde_json::from_str(&text).expect("the fixture parses");
        let mut jobs = JobsState::default();
        let other = JobStatus {
            job: "scan-0b0b0b0b".into(),
            ..status.clone()
        };
        jobs.fold_status(other);
        jobs.fold_status(status.clone());
        jobs.fold_status(JobStatus {
            job: "scan-0c0c0c0c".into(),
            ..status.clone()
        });
        assert_eq!(
            jobs.order,
            vec!["scan-0c0c0c0c", "scan-1a2b3c4d", "scan-0b0b0b0b"],
            "newest first"
        );
        jobs.cursor = 2;
        jobs.pane = JobPane::Detail;
        jobs.detail_scroll = 5;
        jobs.land_started(status);
        assert_eq!(
            jobs.order,
            vec!["scan-1a2b3c4d", "scan-0c0c0c0c", "scan-0b0b0b0b"],
            "the already-listed job moves to the front"
        );
        assert!(jobs.started_here.contains("scan-1a2b3c4d"));
        assert_eq!(
            (jobs.cursor, jobs.pane, jobs.detail_scroll),
            (0, JobPane::List, 0)
        );
        assert_eq!(jobs.full.len(), 3);

        jobs.cursor = 2;
        jobs.forget("scan-0b0b0b0b");
        assert_eq!(jobs.order, vec!["scan-1a2b3c4d", "scan-0c0c0c0c"]);
        assert_eq!(jobs.cursor, 1, "the cursor clamps to the last row");
        assert!(!jobs.summaries.contains_key("scan-0b0b0b0b"));
        assert!(!jobs.full.contains_key("scan-0b0b0b0b"));
        jobs.forget("scan-1a2b3c4d");
        assert!(!jobs.started_here.contains("scan-1a2b3c4d"));
        assert_eq!(jobs.cursor, 0);
    }

    #[test]
    fn elapsed_rounds_down_to_whole_seconds() {
        assert_eq!(elapsed_text(0), "0s");
        assert_eq!(elapsed_text(999), "0s");
        assert_eq!(elapsed_text(60_000), "1m00s");
        assert_eq!(elapsed_text(3_600_000), "1h00m");
    }

    /// The status fixture as a `ReadStatus`, with `state` replaced.
    fn fixture_status(state: JobState) -> JobStatus {
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/scan.status.json"
        );
        let text = std::fs::read_to_string(fixture).expect("the status fixture");
        let mut status: JobStatus = serde_json::from_str(&text).expect("the fixture parses");
        status.state = state;
        status
    }

    /// A `scan.list` row for `id` in `state`.
    fn listed(id: &str, state: JobState) -> JobSummary {
        JobSummary {
            job: id.to_string(),
            state,
            ..Default::default()
        }
    }

    /// Jobs view AC39 (D19, T1): a list that turns a job terminal while its
    /// stored status is still live asks for one more `scan.status` for it,
    /// so the Detail pane's checks line is not left at the last running read
    /// (the TUI's C1/C2 shape: `live()` stops polling it at once); a job
    /// whose stored status is already terminal is not asked again; a job
    /// with no stored status is still asked, as before.
    #[test]
    fn fold_list_rereads_a_job_the_list_turned_terminal() {
        let mut jobs = JobsState::default();
        assert_eq!(jobs.listed_ok_at_tick, None);
        jobs.fold_status(fixture_status(JobState::Running));
        assert_eq!(jobs.full["scan-1a2b3c4d"].state, JobState::Running);

        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed("scan-1a2b3c4d", JobState::Done)],
        });
        assert_eq!(
            followups,
            vec!["scan-1a2b3c4d".to_string()],
            "the list says done, the stored status still says running"
        );
        assert_eq!(jobs.summaries["scan-1a2b3c4d"].state, JobState::Done);
        assert_eq!(
            jobs.full["scan-1a2b3c4d"].state,
            JobState::Running,
            "the stale read stays until the follow-up lands"
        );

        jobs.fold_status(fixture_status(JobState::Done));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed("scan-1a2b3c4d", JobState::Done)],
        });
        assert_eq!(
            followups,
            Vec::<JobId>::new(),
            "both terminal: nothing to re-read"
        );

        let followups = jobs.fold_list(ListResult {
            jobs: vec![
                listed("scan-1a2b3c4d", JobState::Done),
                listed("scan-55667788", JobState::Running),
            ],
        });
        assert_eq!(
            followups,
            vec!["scan-55667788".to_string()],
            "a job with no stored status is still asked"
        );

        jobs.healed.insert("scan-1a2b3c4d".to_string());
        jobs.fold_status(fixture_status(JobState::Running));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed("scan-1a2b3c4d", JobState::Done)],
        });
        assert_eq!(
            followups,
            Vec::<JobId>::new(),
            "a healed job is not re-read even when the list turned it terminal"
        );
    }

    /// Jobs view AC40 and the parity pin P1–P7, P9–P14 (plan Overview;
    /// spec D4), byte for byte. P8 (an unknown reason token) has no Rust
    /// form: `aitm_scan_model::StoppedReason` is a closed enum, so an
    /// unknown token fails the status parse before any sentence is built.
    /// P14's unknown crawl token likewise: `CrawlErrorKind` is closed; its
    /// `Transport` and `Other` read the same words.
    #[test]
    fn stopped_and_crawl_words_are_the_parity_sentences() {
        use aitm_scan_model::{CrawlCounters, CrawlErrorKind};

        // P5, and the AC40 literal.
        assert_eq!(
            stopped_text(StoppedReason::Errors),
            "Stopped early: too many errors from the target."
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Errors, JobState::Done, 2000, None).as_deref(),
            Some("Stopped early: too many errors from the target.")
        );
        // The template carries a literal placeholder; the caller formats the number.
        assert!(stopped_text(StoppedReason::Budget).contains("the probe budget of"));
        assert!(stopped_text(StoppedReason::Budget).contains("{budget}"));
        // Tester, Task 4.4: the whole template, so a re-wording cannot slip
        // past the two `contains` above.
        assert_eq!(
            stopped_text(StoppedReason::Budget),
            "Stopped early: the probe budget of {budget} was spent. Raise it in the profile to go further."
        );
        // P4.
        assert_eq!(
            stopped_sentence(StoppedReason::Budget, JobState::Done, 2000, None).as_deref(),
            Some(
                "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further."
            )
        );
        // P6: the state sentence already says it.
        assert_eq!(
            stopped_sentence(StoppedReason::Cancelled, JobState::Cancelled, 2000, None),
            None
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Cancelled, JobState::Done, 2000, None).as_deref(),
            Some("Stopped early: the job was cancelled.")
        );
        // P7: the error text is shown instead; an empty error counts as none.
        assert_eq!(
            stopped_sentence(StoppedReason::Failed, JobState::Failed, 2000, Some("boom")),
            None
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Failed, JobState::Failed, 2000, None).as_deref(),
            Some("Stopped early: an error ended the job.")
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Failed, JobState::Failed, 2000, Some("")).as_deref(),
            Some("Stopped early: an error ended the job.")
        );
        // The rest of D4's table.
        assert_eq!(
            stopped_text(StoppedReason::Time),
            "Stopped early: the time budget ran out."
        );
        assert_eq!(
            stopped_text(StoppedReason::SessionLost),
            "Stopped early: the session was lost and the profile says stop when that happens."
        );
        assert_eq!(
            stopped_text(StoppedReason::Policy),
            "Stopped early: the agent policy changed to paused or read-only."
        );
        assert_eq!(
            stopped_text(StoppedReason::GuardRefused),
            "Stopped early: the L4 guard refused a target mid-run."
        );
        // P9: the raw token, as serde writes it on the wire.
        for reason in [
            StoppedReason::Budget,
            StoppedReason::Time,
            StoppedReason::Cancelled,
            StoppedReason::SessionLost,
            StoppedReason::Errors,
            StoppedReason::Policy,
            StoppedReason::GuardRefused,
            StoppedReason::Failed,
        ] {
            let wire = serde_json::to_value(reason).expect("a token");
            assert_eq!(Some(stopped_token(reason)), wire.as_str(), "{reason:?}");
        }
        assert_eq!(stopped_token(StoppedReason::Errors), "errors");
        assert_eq!(stopped_token(StoppedReason::SessionLost), "session_lost");

        // P13, P14 and the rest of the `last_error` words.
        assert_eq!(
            crawl_error_words(CrawlErrorKind::ConnectRefused),
            "the target refused the connection"
        );
        assert_eq!(
            crawl_error_words(CrawlErrorKind::Tls),
            "TLS handshake failed"
        );
        assert_eq!(
            crawl_error_words(CrawlErrorKind::Timeout),
            "the target did not answer in time"
        );
        assert_eq!(
            crawl_error_words(CrawlErrorKind::H2NotNegotiated),
            "the target does not speak HTTP/2"
        );
        assert_eq!(
            crawl_error_words(CrawlErrorKind::Transport),
            "the connection failed"
        );
        assert_eq!(
            crawl_error_words(CrawlErrorKind::Other),
            "the connection failed"
        );

        // P10–P12.
        let crawl = |pages: u64, errors: u64| CrawlCounters {
            pages,
            errors,
            ..Default::default()
        };
        assert_eq!(
            crawl_trouble(&crawl(1, 1)).as_deref(),
            Some("The crawl fetched 1 page and hit 1 error")
        );
        assert_eq!(
            crawl_trouble(&crawl(46, 2)).as_deref(),
            Some("The crawl fetched 46 pages and hit 2 errors")
        );
        assert_eq!(crawl_trouble(&crawl(46, 0)), None);
        assert_eq!(
            crawl_trouble(&crawl(0, 1)).as_deref(),
            Some("The crawl fetched 0 pages and hit 1 error")
        );
        assert_eq!(
            crawl_trouble(&crawl(1200, 1000)).as_deref(),
            Some("The crawl fetched 1,200 pages and hit 1,000 errors"),
            "grouped"
        );

        // P1–P3, and nothing for a live job.
        assert_eq!(
            end_sentence(JobState::Done, 69_000, 1020, 0, 6468).as_deref(),
            Some("Done in 1:09 · 1,020 points · 6,468 checks.")
        );
        assert_eq!(
            end_sentence(JobState::Cancelled, 115_000, 0, 3236, 6468).as_deref(),
            Some("Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.")
        );
        assert_eq!(
            end_sentence(JobState::Failed, 12_000, 0, 0, 0).as_deref(),
            Some("Failed after 0:12.")
        );
        assert_eq!(
            end_sentence(JobState::Done, 3_723_000, 1, 0, 1).as_deref(),
            Some("Done in 1:02:03 · 1 point · 1 check."),
            "h:mm:ss from an hour on; the one singular rule"
        );
        assert_eq!(
            end_sentence(JobState::Running, 69_000, 1020, 3236, 6468),
            None
        );
        assert_eq!(
            end_sentence(JobState::Cancelling, 69_000, 1020, 3236, 6468),
            None
        );
        assert_eq!(end_sentence(JobState::Queued, 0, 0, 0, 0), None);

        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(6468), "6,468");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    /// Jobs view AC40 (D19, T1): the Detail pane's `stopped` line is D4's
    /// sentence (omitted when D4 says nil), the raw token follows on a
    /// `wire` line, the `crawl` line names its errors and the last error's
    /// words, the `checks` line its errors and skips; the count the scroll
    /// clamps to mirrors every shape.
    #[test]
    fn detail_lines_carry_the_wire_and_error_clauses() {
        use aitm_scan_model::CrawlErrorKind;

        let mut status = fixture_status(JobState::Done);
        status.stopped_reason = Some(StoppedReason::Errors);
        status.crawl.errors = 1;
        status.crawl.last_error = Some(CrawlErrorKind::ConnectRefused);
        status.checks.errors = 7;
        status.checks.skipped = 3;
        let read = ReadStatus::new(status.clone());
        let lines = detail_lines(&read);
        assert_eq!(detail_line_count(&read.status), lines.len());
        let value = |label: &str| {
            lines
                .iter()
                .find(|(l, _)| *l == label)
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("no {label} line: {lines:?}"))
        };
        assert_eq!(
            value("stopped"),
            "Stopped early: too many errors from the target."
        );
        assert_eq!(value("wire"), "stopped_reason: errors");
        let stopped_at = lines.iter().position(|(l, _)| *l == "stopped");
        let wire_at = lines.iter().position(|(l, _)| *l == "wire");
        assert_eq!(
            wire_at,
            stopped_at.map(|i| i + 1),
            "the raw token sits under the sentence"
        );
        assert_eq!(
            value("crawl"),
            "pages 37 · queued 0 · depth 3 · forms 4 · errors 1 (the target refused the connection)"
        );
        assert!(
            value("crawl").ends_with("· errors 1 (the target refused the connection)"),
            "{:?}",
            value("crawl")
        );
        assert!(
            value("checks").contains("· errors 7"),
            "{:?}",
            value("checks")
        );
        assert!(
            value("checks").contains("· skipped 3"),
            "{:?}",
            value("checks")
        );
        assert_eq!(
            value("checks"),
            "180/240 done · errors 7 · skipped 3 · running http.reflected-xss, http.sqli-error"
        );

        // No last error: the count alone. No errors or skips: the old line.
        status.crawl.last_error = None;
        status.checks.errors = 0;
        status.checks.skipped = 0;
        let read = ReadStatus::new(status.clone());
        let lines = detail_lines(&read);
        assert_eq!(detail_line_count(&read.status), lines.len());
        let crawl = &lines.iter().find(|(l, _)| *l == "crawl").expect("crawl").1;
        assert_eq!(crawl, "pages 37 · queued 0 · depth 3 · forms 4 · errors 1");
        let checks = &lines
            .iter()
            .find(|(l, _)| *l == "checks")
            .expect("checks")
            .1;
        assert_eq!(
            checks,
            "180/240 done · running http.reflected-xss, http.sqli-error"
        );
        status.crawl.errors = 0;
        let lines = detail_lines(&ReadStatus::new(status.clone()));
        let crawl = &lines.iter().find(|(l, _)| *l == "crawl").expect("crawl").1;
        assert_eq!(crawl, "pages 37 · queued 0 · depth 3 · forms 4");

        // P6 in the pane: no `stopped` line, the `wire` line still.
        status.state = JobState::Cancelled;
        status.stopped_reason = Some(StoppedReason::Cancelled);
        let read = ReadStatus::new(status.clone());
        let lines = detail_lines(&read);
        assert_eq!(detail_line_count(&read.status), lines.len());
        assert!(
            !lines.iter().any(|(l, _)| *l == "stopped"),
            "cancelled on a cancelled job has no sentence: {lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .find(|(l, _)| *l == "wire")
                .map(|(_, v)| v.as_str()),
            Some("stopped_reason: cancelled")
        );
        // Jobs view D19, T2: the end sentence first, the `now` line for the
        // fixture's two running checks.
        assert_eq!(
            detail_line_count(&read.status),
            DETAIL_FIXED_LINES + 3,
            "the sentence, the wire line, the now line and the seven fixed"
        );

        // P4 in the pane: the budget comes from the status's probes.
        status.state = JobState::Done;
        status.stopped_reason = Some(StoppedReason::Budget);
        let lines = detail_lines(&ReadStatus::new(status));
        assert_eq!(
            lines.iter().find(|(l, _)| *l == "stopped").map(|(_, v)| v.as_str()),
            Some(
                "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further."
            )
        );
    }

    /// Jobs view AC40 (D19, T1; D6 hostile-core bounds): every sample
    /// string is cut to `DETAIL_VALUE_MAX` cells at fold and both sample
    /// lists to `DETAIL_LIST_MAX`, the rest counted.
    #[test]
    fn bound_status_cuts_the_samples() {
        use crate::text::width;
        use aitm_scan_model::CheckErrorSample;

        let sample = |k: usize| CheckErrorSample {
            check: format!("http.c{k}"),
            point: format!("p{k}"),
            detail: format!("d{k}"),
        };
        let mut status = fixture_status(JobState::Done);
        status.checks.error_samples = (0..9).map(sample).collect();
        status.checks.error_samples[0].detail = "x".repeat(1000);
        status.checks.error_samples[1].check = "\t".repeat(10) + &"c".repeat(1000);
        status.checks.error_samples[2].point = "y".repeat(1000);
        status.checks.skipped_samples = (0..9).map(sample).collect();
        status.checks.skipped_samples[0].detail = "z".repeat(1000);
        let read = ReadStatus::new(status);

        assert_eq!(read.checks.error_samples.len(), DETAIL_LIST_MAX);
        assert_eq!(read.dropped.error_samples, 1);
        assert_eq!(read.checks.skipped_samples.len(), DETAIL_LIST_MAX);
        assert_eq!(read.dropped.skipped_samples, 1);
        assert_eq!(
            width(&read.checks.error_samples[0].detail),
            DETAIL_VALUE_MAX
        );
        assert_eq!(width(&read.checks.error_samples[1].check), DETAIL_VALUE_MAX);
        assert!(
            !read.checks.error_samples[1].check.contains('\t'),
            "control characters stripped"
        );
        assert_eq!(width(&read.checks.error_samples[2].point), DETAIL_VALUE_MAX);
        assert_eq!(
            width(&read.checks.skipped_samples[0].detail),
            DETAIL_VALUE_MAX
        );
        assert_eq!(
            read.checks.error_samples[3].detail, "d3",
            "short ones untouched"
        );

        let bare = ReadStatus::new(fixture_status(JobState::Running));
        assert_eq!(bare.dropped, StatusDropped::default());
    }

    /// Jobs view AC41 and the parity pin P15–P23 (plan Overview; spec D8,
    /// D19): the derived progress, the bar and the state words. The percent
    /// carries a U+00A0 before the `%`, so the string is byte-identical to
    /// the mac and web pins; ratatui draws the no-break space as one blank
    /// cell. P8 and P14's unknown tokens are closed enums here (see
    /// `stopped_and_crawl_words_are_the_parity_sentences`).
    #[test]
    fn progress_and_bar_follow_the_parity_table() {
        let near = |a: f64, b: f64| (a - b).abs() < 0.0001;
        let status = |state: JobState, phase: Phase| JobStatus {
            state,
            phase,
            ..Default::default()
        };
        let of = |s: &JobStatus| progress(&s.summary(), Some(s));

        // P15.
        let mut auditing = status(JobState::Running, Phase::Auditing);
        auditing.checks.done = 3236;
        auditing.checks.scheduled = 6468;
        let p = of(&auditing);
        assert!(p.fraction.is_some_and(|f| near(f, 0.5003)), "{p:?}");
        assert!(
            matches!(p.ring, Ring::Determinate(f) if near(f, 0.5003)),
            "{p:?}"
        );
        assert_eq!(percent_text(p.fraction).as_deref(), Some("50\u{a0}%"));
        assert_eq!(p.phase_line, "3,236 of 6,468 checks");
        assert_eq!(p.now_line, None);

        // P16, and the singular.
        let mut crawling = status(JobState::Running, Phase::Crawling);
        crawling.crawl.pages = 46;
        crawling.crawl.queued = 12;
        let p = of(&crawling);
        assert!(p.fraction.is_some_and(|f| near(f, 0.7931)), "{p:?}");
        assert_eq!(p.phase_line, "46 pages, 12 queued");
        crawling.crawl.pages = 1;
        crawling.crawl.queued = 0;
        let p = of(&crawling);
        assert_eq!(p.fraction, Some(1.0));
        assert_eq!(p.phase_line, "1 page, 0 queued");
        crawling.crawl.pages = 0;
        let p = of(&crawling);
        assert_eq!(p.ring, Ring::Indeterminate, "nothing fetched or queued yet");
        assert_eq!(p.phase_line, "0 pages, 0 queued");

        // P17.
        let p = of(&status(JobState::Running, Phase::Passive));
        assert_eq!(p.ring, Ring::Indeterminate);
        assert_eq!(p.fraction, None);
        assert_eq!(percent_text(p.fraction), None);
        assert_eq!(p.phase_line, "Passive checks over captured traffic");

        // P18.
        let p = of(&status(JobState::Running, Phase::Reporting));
        assert_eq!(p.ring, Ring::Determinate(1.0));
        assert_eq!(p.fraction, Some(1.0));
        assert_eq!(percent_text(p.fraction).as_deref(), Some("100\u{a0}%"));
        assert_eq!(p.phase_line, "Writing results");

        // P19.
        let p = of(&status(JobState::Queued, Phase::Queued));
        assert_eq!(p.ring, Ring::Indeterminate);
        assert_eq!(p.fraction, None);
        assert_eq!(p.phase_line, "Waiting for the engine to start this job.");

        // P20.
        let p = of(&status(JobState::Running, Phase::Auditing));
        assert_eq!(p.ring, Ring::Indeterminate);
        assert_eq!(p.fraction, None);
        assert_eq!(p.phase_line, "Scheduling checks");

        // P21.
        let mut cancelled = status(JobState::Cancelled, Phase::Done);
        cancelled.checks.done = 3236;
        cancelled.checks.scheduled = 6468;
        let p = of(&cancelled);
        assert!(
            matches!(p.ring, Ring::Finished(Some(f)) if near(f, 0.5003)),
            "{p:?}"
        );
        assert_eq!(p.fraction, None);
        assert_eq!(percent_text(p.fraction), None);
        assert_eq!(p.phase_line, "");
        assert_eq!(
            p.ring.bar_fraction().map(|f| near(f, 0.5003)),
            Some(true),
            "a finished bar keeps its fill"
        );
        let mut done = status(JobState::Done, Phase::Done);
        done.crawl.pages = 46;
        done.crawl.queued = 12;
        assert!(
            matches!(of(&done).ring, Ring::Finished(Some(f)) if near(f, 0.7931)),
            "no checks scheduled: the crawling rule"
        );
        assert_eq!(
            of(&status(JobState::Failed, Phase::Crawling)).ring,
            Ring::Finished(None),
            "no counters at all"
        );

        // P22.
        let mut running = auditing.clone();
        assert_eq!(of(&running).now_line, None);
        running.checks.running = vec!["xss-reflected".into()];
        assert_eq!(of(&running).now_line.as_deref(), Some("Now: xss-reflected"));
        running.checks.running = vec![
            "xss-reflected".into(),
            "sqli-error".into(),
            "ssrf".into(),
            "open-redirect".into(),
        ];
        assert_eq!(
            of(&running).now_line.as_deref(),
            Some("Now: xss-reflected and 3 more")
        );

        // Cancelling keeps the running rule for its phase.
        auditing.state = JobState::Cancelling;
        let p = of(&auditing);
        assert!(p.fraction.is_some_and(|f| near(f, 0.5003)), "{p:?}");
        assert_eq!(p.phase_line, "3,236 of 6,468 checks");

        // Running without a status yet: indeterminate, the phase word.
        auditing.state = JobState::Running;
        let p = progress(&auditing.summary(), None);
        assert_eq!(p.ring, Ring::Indeterminate);
        assert_eq!(p.fraction, None);
        assert_eq!(p.phase_line, "auditing");
        assert_eq!(p.now_line, None);

        // A core reporting more done than scheduled clamps at 1.
        auditing.checks.done = 7000;
        let p = of(&auditing);
        assert_eq!(p.fraction, Some(1.0));
        assert_eq!(percent_text(p.fraction).as_deref(), Some("100\u{a0}%"));

        // The row's progress text: checks while auditing, pages while
        // crawling, `...` when indeterminate.
        auditing.checks.done = 3236;
        assert_eq!(
            progress_text(progress_ring(&auditing.summary(), Some(&auditing)).1),
            "3236/6468"
        );
        crawling.crawl.pages = 46;
        crawling.crawl.queued = 12;
        assert_eq!(
            progress_text(progress_ring(&crawling.summary(), Some(&crawling)).1),
            "46/58"
        );
        let passive = status(JobState::Running, Phase::Passive);
        assert_eq!(
            progress_text(progress_ring(&passive.summary(), Some(&passive)).1),
            "..."
        );
        assert_eq!(
            progress_text(progress_ring(&auditing.summary(), None).1),
            "..."
        );
        assert_eq!(
            progress_text(progress_ring(&cancelled.summary(), Some(&cancelled)).1),
            "3236/6468",
            "a finished row keeps its counters"
        );

        // The bar (AC41): floor of the fraction over the cells, like the
        // percent's floor (D8), so it reads full only at 1.
        assert_eq!(progress_bar(Some(0.5), 6), "━━━───");
        assert_eq!(progress_bar(None, 6), "──────");
        assert_eq!(progress_bar(Some(1.0), 6), "━━━━━━");
        assert_eq!(progress_bar(Some(0.5003), 6), "━━━───");
        assert_eq!(progress_bar(Some(0.99), 6), "━━━━━─");
        assert_eq!(progress_bar(Some(2.0), 6), "━━━━━━", "capped");
        assert_eq!(progress_fill(Some(0.5003), 6), 3);
        assert_eq!(progress_fill(Some(f64::NAN), 6), 0);
        assert_eq!(progress_fill(None, 6), 0);

        // P1 again beside the words (AC41).
        assert_eq!(
            end_sentence(JobState::Done, 69_000, 1020, 0, 6468).as_deref(),
            Some("Done in 1:09 · 1,020 points · 6,468 checks.")
        );

        // P23 (TUI spelling): the phase word while running, the state word
        // otherwise.
        assert_eq!(
            state_phase_text(JobState::Running, Phase::Auditing),
            "auditing"
        );
        assert_eq!(
            state_phase_text(JobState::Running, Phase::Crawling),
            "crawling"
        );
        assert_eq!(
            state_phase_text(JobState::Running, Phase::Passive),
            "passive"
        );
        assert_eq!(
            state_phase_text(JobState::Running, Phase::Reporting),
            "reporting"
        );
        assert_eq!(state_phase_text(JobState::Running, Phase::Queued), "queued");
        assert_eq!(
            state_phase_text(JobState::Cancelling, Phase::Auditing),
            "cancelling"
        );
        assert_eq!(state_phase_text(JobState::Queued, Phase::Queued), "queued");
        assert_eq!(state_phase_text(JobState::Done, Phase::Done), "done");
        assert_eq!(
            state_phase_text(JobState::Cancelled, Phase::Auditing),
            "cancelled"
        );
        assert_eq!(
            state_phase_text(JobState::Failed, Phase::Crawling),
            "failed"
        );

        // The row carries the progress, its fill and the budget as a number.
        let built = row(
            &auditing.summary(),
            Some(&ReadStatus::new(auditing.clone())),
        );
        assert_eq!(built.progress, "3236/6468");
        assert_eq!(built.progress_fill, 3);
        assert_eq!(built.budget, "0/0");
        assert_eq!(built.state_phase, "auditing");
        let bare = JobRow::unknown("scan-1a2b3c4d");
        assert_eq!(
            (
                bare.progress.as_str(),
                bare.progress_fill,
                bare.budget.as_str()
            ),
            ("...", 0, "...")
        );
    }

    /// Jobs view AC42 (D19, T2): the Detail pane opens with the end
    /// sentence (terminal) or the percent and phase line (live), the
    /// stopped lines right under a sentence, then `now`, the attention
    /// lines, and only then the label-value lines; the count the scroll
    /// clamps to mirrors every shape.
    #[test]
    fn detail_first_lines_are_the_sentence_or_the_progress() {
        use aitm_scan_model::{CheckErrorSample, CrawlErrorKind};

        let lines_of = |status: &JobStatus| {
            let read = ReadStatus::new(status.clone());
            let lines = detail_lines(&read);
            assert_eq!(detail_line_count(&read.status), lines.len(), "{lines:?}");
            lines
        };
        // A cancelled job: P2, the wire line (P6: no sentence), the labels.
        let mut status = fixture_status(JobState::Cancelled);
        status.elapsed_ms = 115_000;
        status.checks.done = 3236;
        status.checks.scheduled = 6468;
        status.checks.running.clear();
        status.stopped_reason = Some(StoppedReason::Cancelled);
        let lines = lines_of(&status);
        assert_eq!(
            lines[..2],
            [
                (
                    "",
                    "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays."
                        .to_string()
                ),
                ("wire", "stopped_reason: cancelled".to_string()),
            ]
        );
        assert_eq!(lines[2].0, "lanes");

        // Done on the budget: P1's shape, then P4 and its wire line.
        status.state = JobState::Done;
        status.stopped_reason = Some(StoppedReason::Budget);
        let lines = lines_of(&status);
        assert_eq!(lines[0].1, "Done in 1:55 · 120 points · 6,468 checks.");
        assert_eq!(
            lines[1],
            (
                "stopped",
                "Stopped early: the probe budget of 2,000 was spent. Raise it in the profile to go further."
                    .to_string()
            )
        );
        assert_eq!(lines[2], ("wire", "stopped_reason: budget".to_string()));
        assert_eq!(lines[3].0, "lanes");

        // Failed: the sentence, the error line stays where it was.
        status.state = JobState::Failed;
        status.stopped_reason = Some(StoppedReason::Failed);
        status.error = Some("boom".into());
        status.elapsed_ms = 12_000;
        let lines = lines_of(&status);
        assert_eq!(lines[0].1, "Failed after 0:12.");
        assert_eq!(lines[1], ("wire", "stopped_reason: failed".to_string()));
        assert!(lines.iter().any(|(l, v)| *l == "error" && v == "boom"));

        // A running job: the percent and the phase line, then `now`.
        let mut status = fixture_status(JobState::Running);
        status.checks.done = 3236;
        status.checks.scheduled = 6468;
        status.checks.running = vec!["xss-reflected".into()];
        let lines = lines_of(&status);
        assert_eq!(
            lines[0],
            ("", "50\u{a0}% · 3,236 of 6,468 checks".to_string())
        );
        assert_eq!(lines[1], ("now", "xss-reflected".to_string()));
        assert_eq!(lines[2].0, "lanes");
        status.checks.running.clear();
        let lines = lines_of(&status);
        assert_eq!(lines[1].0, "lanes", "no running check, no `now` line");

        // The attention lines (D9): errors with their samples, skips with
        // theirs (the singular, plan gap 26), the crawl trouble.
        let sample = |check: &str, detail: &str| CheckErrorSample {
            check: check.into(),
            point: "p".into(),
            detail: detail.into(),
        };
        status.checks.errors = 7;
        status.checks.error_samples = vec![
            sample("http.sqli-error", "timed out"),
            sample("http.ssrf", ""),
        ];
        status.checks.skipped = 1;
        status.checks.skipped_samples = vec![sample("http.xxe", "no XML body")];
        status.crawl.errors = 1;
        status.crawl.last_error = Some(CrawlErrorKind::ConnectRefused);
        let lines = lines_of(&status);
        assert_eq!(
            lines[1..7],
            [
                ("", "7 checks could not run".to_string()),
                ("", "http.sqli-error: timed out".to_string()),
                ("", "http.ssrf".to_string()),
                ("", "1 check was skipped".to_string()),
                ("", "http.xxe: no XML body".to_string()),
                (
                    "",
                    "The crawl fetched 37 pages and hit 1 error — the target refused the connection"
                        .to_string()
                ),
            ]
        );
        assert_eq!(lines[7].0, "lanes");
        status.crawl.last_error = None;
        let lines = lines_of(&status);
        assert_eq!(lines[6].1, "The crawl fetched 37 pages and hit 1 error");

        // The samples are bounded by the fold: nine → DETAIL_LIST_MAX rows.
        status.checks.error_samples = (0..9).map(|k| sample(&format!("c{k}"), "d")).collect();
        let lines = lines_of(&status);
        assert_eq!(lines[1].1, "7 checks could not run");
        assert_eq!(
            lines[1 + DETAIL_LIST_MAX].1,
            format!("c{}: d", DETAIL_LIST_MAX - 1)
        );
        assert_eq!(lines[2 + DETAIL_LIST_MAX].1, "1 check was skipped");

        // Indeterminate live states: the phase line alone.
        let passive = fixture_status(JobState::Running);
        let mut passive = JobStatus {
            phase: Phase::Passive,
            ..passive
        };
        passive.checks.running.clear();
        assert_eq!(
            lines_of(&passive)[0],
            ("", "Passive checks over captured traffic".to_string())
        );
        let queued = JobStatus {
            state: JobState::Queued,
            ..passive
        };
        assert_eq!(
            lines_of(&queued)[0],
            ("", "Waiting for the engine to start this job.".to_string())
        );
    }

    /// Jobs view D21, plan gap 62 (Task 4.4a): the `points` line's skip
    /// clause is the Kit's three `ScanPointSkipWords.text` in the Kit's
    /// order (frequent, ignored, limit), each count grouped, zeros kept, so
    /// the skip rows read the same on the three surfaces; the line count
    /// does not move.
    #[test]
    fn points_line_reads_the_kit_skip_words() {
        let points_line = |status: &JobStatus| -> String {
            let read = ReadStatus::new(status.clone());
            let lines = detail_lines(&read);
            assert_eq!(detail_line_count(&read.status), lines.len(), "{lines:?}");
            let (_, value) = lines
                .iter()
                .find(|(label, _)| *label == "points")
                .expect("a points line");
            value.clone()
        };

        let mut status = fixture_status(JobState::Running);
        status.points.found = 1020;
        status.points.queued = 923;
        status.points.audited = 97;
        status.points.skipped.frequent = 722;
        status.points.skipped.ignored = 6;
        status.points.skipped.limit = 0;
        assert_eq!(
            points_line(&status),
            "found 1,020 · queued 923 · audited 97 · 722 skipped as repetitive · 6 skipped by rule · 0 skipped at the per-request cap"
        );

        status.points.skipped.frequent = 0;
        status.points.skipped.ignored = 1200;
        status.points.skipped.limit = 3;
        assert_eq!(
            points_line(&status),
            "found 1,020 · queued 923 · audited 97 · 0 skipped as repetitive · 1,200 skipped by rule · 3 skipped at the per-request cap"
        );
    }

    /// Tester, Task 4.4 (AC39's edges; D19 T1, D4 amendment): the re-read
    /// rule is `is_terminal` on both sides, not a `Done` comparison. A
    /// `cancelling` read the list turns `cancelled`, and a `running` read
    /// the list turns `failed`, are re-read; a `done` read the list calls
    /// `failed` is not (both terminal); a list that keeps the job live asks
    /// nothing; an empty list asks nothing and lets the stale read go.
    /// Until the re-read lands the row follows the list (the finished bar
    /// keeps the stored counters' fill) while the Detail pane keeps the
    /// live first line: a sentence is never built from a live status.
    #[test]
    fn fold_list_followups_follow_is_terminal_across_states() {
        let id = "scan-1a2b3c4d".to_string();
        let mut jobs = JobsState::default();

        jobs.fold_status(fixture_status(JobState::Cancelling));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed(&id, JobState::Cancelled)],
        });
        assert_eq!(followups, vec![id.clone()], "cancelling -> cancelled");

        jobs.fold_status(fixture_status(JobState::Running));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed(&id, JobState::Failed)],
        });
        assert_eq!(followups, vec![id.clone()], "running -> failed");
        let row = jobs.row_of(&id);
        assert_eq!(row.state_phase, "failed");
        assert_eq!(
            (row.progress.as_str(), row.progress_fill),
            ("180/240", 4),
            "the finished bar keeps the stored counters' fill"
        );
        assert_eq!(
            jobs.detail_text()[0],
            ("", "75\u{a0}% · 180 of 240 checks".to_string()),
            "a live stored status never yields a sentence"
        );

        jobs.fold_status(fixture_status(JobState::Done));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed(&id, JobState::Failed)],
        });
        assert_eq!(
            followups,
            Vec::<JobId>::new(),
            "done vs failed: both terminal, nothing to re-read"
        );
        assert_eq!(
            jobs.detail_text()[0],
            ("", "Done in 0:42 · 120 points · 240 checks.".to_string())
        );

        jobs.fold_status(fixture_status(JobState::Running));
        let followups = jobs.fold_list(ListResult {
            jobs: vec![listed(&id, JobState::Running)],
        });
        assert_eq!(
            followups,
            Vec::<JobId>::new(),
            "the list keeps it live: the timer polls it"
        );

        let followups = jobs.fold_list(ListResult { jobs: vec![] });
        assert_eq!(followups, Vec::<JobId>::new());
        assert!(jobs.full.is_empty() && jobs.order.is_empty());
        assert_eq!(
            jobs.detail_text(),
            vec![("", WAITING_FOR_STATUS.to_string())]
        );
    }

    /// Tester, Task 4.4 (D6 hostile-core bounds on the T2 model): the
    /// derived progress, the percent, the bar and the sentences take any
    /// `u64` the core sends without a panic, clamp where D8 says so, and
    /// read the bounded lists, never the core's.
    #[test]
    fn progress_and_sentences_survive_hostile_counters() {
        let status = |state: JobState, phase: Phase| JobStatus {
            state,
            phase,
            ..Default::default()
        };
        let of = |s: &JobStatus| progress(&s.summary(), Some(s));

        // More done than scheduled, at the top of the range: clamped at 1.
        let mut auditing = status(JobState::Running, Phase::Auditing);
        auditing.checks.done = u64::MAX;
        auditing.checks.scheduled = 1;
        let p = of(&auditing);
        assert_eq!(p.ring, Ring::Determinate(1.0));
        assert_eq!(p.fraction, Some(1.0));
        assert_eq!(percent_text(p.fraction).as_deref(), Some("100\u{a0}%"));
        assert_eq!(p.phase_line, "18,446,744,073,709,551,615 of 1 check");
        assert_eq!(progress_bar(p.ring.bar_fraction(), 6), "━━━━━━");
        assert_eq!(
            progress_text(progress_ring(&auditing.summary(), Some(&auditing)).1),
            "18446744073709551615/1"
        );

        // Crawl counters whose sum would overflow saturate.
        let mut crawling = status(JobState::Running, Phase::Crawling);
        crawling.crawl.pages = u64::MAX;
        crawling.crawl.queued = u64::MAX;
        let p = of(&crawling);
        assert_eq!(p.fraction, Some(1.0));
        assert_eq!(
            p.phase_line,
            "18,446,744,073,709,551,615 pages, 18,446,744,073,709,551,615 queued"
        );
        assert_eq!(
            progress_text(progress_ring(&crawling.summary(), Some(&crawling)).1),
            "18446744073709551615/18446744073709551615"
        );
        let mut done = status(JobState::Done, Phase::Done);
        done.crawl.queued = u64::MAX;
        assert_eq!(
            of(&done).ring,
            Ring::Finished(Some(0.0)),
            "nothing fetched, everything queued: a finished bar with no fill"
        );
        assert_eq!(progress_bar(of(&done).ring.bar_fraction(), 6), "──────");

        // The bar and the percent on values the model never produces.
        assert_eq!(progress_bar(Some(-1.0), 6), "──────");
        assert_eq!(progress_bar(Some(f64::INFINITY), 6), "──────");
        assert_eq!(progress_bar(Some(f64::NEG_INFINITY), 6), "──────");
        assert_eq!(progress_bar(Some(f64::NAN), 6), "──────");
        assert_eq!(progress_bar(Some(0.5), 0), "");
        assert_eq!(progress_bar(None, 0), "");
        assert_eq!(progress_bar(Some(1.0), 1), "━");
        assert_eq!(progress_bar(Some(0.999), 1), "─");
        assert_eq!(percent_text(Some(-0.5)).as_deref(), Some("0\u{a0}%"));
        assert_eq!(percent_text(Some(0.0)).as_deref(), Some("0\u{a0}%"));
        assert_eq!(percent_text(Some(0.999)).as_deref(), Some("99\u{a0}%"));
        assert_eq!(percent_text(Some(7.0)).as_deref(), Some("100\u{a0}%"));
        assert_eq!(percent_text(None), None);

        // Empty and oversized inputs to the sentences.
        assert_eq!(
            end_sentence(JobState::Done, 0, 0, 0, 0).as_deref(),
            Some("Done in 0:00 · 0 points · 0 checks.")
        );
        assert_eq!(
            end_sentence(JobState::Cancelled, 0, 0, 0, 0).as_deref(),
            Some("Cancelled after 0:00; 0 of 0 checks had run. What it found stays.")
        );
        assert_eq!(
            end_sentence(JobState::Failed, u64::MAX, u64::MAX, u64::MAX, u64::MAX).as_deref(),
            Some("Failed after 5124095576030:25:51.")
        );
        assert_eq!(
            end_sentence(JobState::Done, 59_999, u64::MAX, 0, u64::MAX).as_deref(),
            Some(
                "Done in 0:59 · 18,446,744,073,709,551,615 points · 18,446,744,073,709,551,615 checks."
            )
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Budget, JobState::Done, u64::MAX, None).as_deref(),
            Some(
                "Stopped early: the probe budget of 18,446,744,073,709,551,615 was spent. Raise it in the profile to go further."
            )
        );
        assert_eq!(
            stopped_sentence(StoppedReason::Budget, JobState::Done, 0, None).as_deref(),
            Some(
                "Stopped early: the probe budget of 0 was spent. Raise it in the profile to go further."
            )
        );
        let crawl = CrawlCounters {
            pages: 0,
            errors: u64::MAX,
            ..Default::default()
        };
        assert_eq!(
            crawl_trouble(&crawl).as_deref(),
            Some("The crawl fetched 0 pages and hit 18,446,744,073,709,551,615 errors")
        );
        assert_eq!(elapsed_text(u64::MAX), "5124095576030h25m");
        assert_eq!(grouped(u64::MAX), "18,446,744,073,709,551,615");

        // `now_line` reads the bounded list: a thousand running ids are
        // cut to DETAIL_LIST_MAX at fold, and the line counts what was
        // kept, never the core's thousand; an empty list gives none.
        let mut running = fixture_status(JobState::Running);
        running.checks.running = (0..1000).map(|k| format!("c{k}")).collect();
        let read = ReadStatus::new(running);
        assert_eq!(read.dropped.running, 1000 - DETAIL_LIST_MAX);
        let p = progress(&read.summary(), Some(&read.status));
        assert_eq!(p.now_line.as_deref(), Some("Now: c0 and 7 more"));
        let lines = detail_lines(&read);
        assert_eq!(
            lines[1],
            ("now", "c0, c1, c2, c3, c4, c5, c6, c7 +992".to_string())
        );
        let mut none = fixture_status(JobState::Running);
        none.checks.running.clear();
        assert_eq!(of(&none).now_line, None);
    }

    /// Jobs view AC60 (D19 amendment, the hung-core detector): the
    /// overdue test counts from the tick the list left with `due`'s
    /// comparison; no list in flight is never overdue, and a tick behind
    /// the stamp never underflows.
    #[test]
    fn list_overdue_counts_from_the_send() {
        assert!(!list_overdue(119, Some(40), 80));
        assert!(list_overdue(120, Some(40), 80));
        assert!(!list_overdue(500, None, 80));
        assert!(
            !list_overdue(10, Some(40), 80),
            "a tick behind never underflows"
        );
    }

    /// Jobs view AC60 (D19 amendment): `unanswered` is true for exactly the
    /// detector's sentence under `scan.list`, not for another `scan.list`
    /// error, not for the same words under a keyed tag, not for no error.
    #[test]
    fn unanswered_reads_only_the_list_sentence() {
        let mut jobs = JobsState::default();
        assert!(!jobs.unanswered());
        jobs.error = Some(ScanError::uncoded("scan.list", NOT_IN_TIME));
        assert!(jobs.unanswered());
        jobs.error = Some(ScanError::uncoded("scan.list", "boom"));
        assert!(!jobs.unanswered());
        jobs.error = Some(ScanError::uncoded("scan.status:scan-1a2b3c4d", NOT_IN_TIME));
        assert!(!jobs.unanswered());
    }

    /// Jobs view Task 4.5c (3): `stopped_sentence_applies` holds D4's nil
    /// rules alone, so the scroll count need not build the sentence; it
    /// agrees with `stopped_sentence` on the parity inputs P4–P7 and the
    /// rest of the table, each answer named.
    #[test]
    fn stopped_sentence_applies_mirrors_the_sentence() {
        let cases: [(StoppedReason, JobState, Option<&str>, bool); 9] = [
            // P4: the budget sentence.
            (StoppedReason::Budget, JobState::Done, None, true),
            // P5: too many errors.
            (StoppedReason::Errors, JobState::Done, None, true),
            // P6: the state already says it; on another state it is said.
            (StoppedReason::Cancelled, JobState::Cancelled, None, false),
            (StoppedReason::Cancelled, JobState::Done, None, true),
            // P7: the error text is shown instead; an empty error is none.
            (StoppedReason::Failed, JobState::Failed, Some("boom"), false),
            (StoppedReason::Failed, JobState::Failed, Some(""), true),
            (StoppedReason::Failed, JobState::Failed, None, true),
            (StoppedReason::Time, JobState::Done, None, true),
            (StoppedReason::GuardRefused, JobState::Cancelled, None, true),
        ];
        for (reason, state, error, applies) in cases {
            assert_eq!(
                stopped_sentence_applies(reason, state, error),
                applies,
                "{reason:?} {state:?} {error:?}"
            );
            assert_eq!(
                stopped_sentence(reason, state, 2000, error).is_some(),
                applies,
                "{reason:?} {state:?} {error:?}"
            );
        }
    }

    /// Jobs view Task 4.5c (2): `progress_ring` names the counters its
    /// numbers come from, so `row` formats only the cell it draws: the
    /// checks while auditing (and reporting, once any were scheduled) and
    /// for a finished job that scheduled any; the crawl while crawling and
    /// for a finished job that scheduled none; none while indeterminate,
    /// queued, or before a status. `progress_text` is the cell per source.
    #[test]
    fn progress_ring_names_the_source_of_its_numbers() {
        let status = |state: JobState, phase: Phase| JobStatus {
            state,
            phase,
            ..Default::default()
        };
        let of = |s: &JobStatus| progress_ring(&s.summary(), Some(s));

        let mut auditing = status(JobState::Running, Phase::Auditing);
        auditing.checks.done = 3236;
        auditing.checks.scheduled = 6468;
        let (ring, source) = of(&auditing);
        assert!(matches!(ring, Ring::Determinate(_)), "{ring:?}");
        assert_eq!(
            source,
            Source::Checks {
                done: 3236,
                scheduled: 6468
            }
        );
        assert_eq!(progress_text(source), "3236/6468");

        let mut crawling = status(JobState::Running, Phase::Crawling);
        crawling.crawl.pages = 46;
        crawling.crawl.queued = 12;
        assert_eq!(
            of(&crawling).1,
            Source::Crawl {
                pages: 46,
                known: 58
            }
        );
        assert_eq!(
            progress_text(Source::Crawl {
                pages: 46,
                known: 58
            }),
            "46/58"
        );

        // Reporting is determinate at 1; its cell is the checks once any
        // were scheduled, else dots.
        let mut reporting = status(JobState::Running, Phase::Reporting);
        assert_eq!(of(&reporting), (Ring::Determinate(1.0), Source::None));
        reporting.checks.done = 240;
        reporting.checks.scheduled = 240;
        assert_eq!(
            of(&reporting),
            (
                Ring::Determinate(1.0),
                Source::Checks {
                    done: 240,
                    scheduled: 240
                }
            )
        );

        // Indeterminate: scheduling, passive, no status yet, queued.
        let scheduling = status(JobState::Running, Phase::Auditing);
        assert_eq!(of(&scheduling), (Ring::Indeterminate, Source::None));
        assert_eq!(progress_text(Source::None), "...");
        let passive = status(JobState::Running, Phase::Passive);
        assert_eq!(of(&passive), (Ring::Indeterminate, Source::None));
        assert_eq!(
            progress_ring(&auditing.summary(), None),
            (Ring::Indeterminate, Source::None)
        );
        auditing.state = JobState::Queued;
        assert_eq!(
            of(&auditing),
            (Ring::Indeterminate, Source::None),
            "queued ignores the counters"
        );

        // Finished: the checks when any were scheduled, else the crawl,
        // else nothing; no status gives nothing.
        let mut done = status(JobState::Done, Phase::Done);
        done.checks.done = 240;
        done.checks.scheduled = 240;
        done.crawl.pages = 5;
        assert_eq!(
            of(&done),
            (
                Ring::Finished(Some(1.0)),
                Source::Checks {
                    done: 240,
                    scheduled: 240
                }
            )
        );
        done.checks.scheduled = 0;
        assert_eq!(
            of(&done),
            (
                Ring::Finished(Some(1.0)),
                Source::Crawl { pages: 5, known: 5 }
            )
        );
        done.crawl.pages = 0;
        assert_eq!(of(&done), (Ring::Finished(None), Source::None));
        assert_eq!(
            progress_ring(&done.summary(), None),
            (Ring::Finished(None), Source::None)
        );
    }
}
