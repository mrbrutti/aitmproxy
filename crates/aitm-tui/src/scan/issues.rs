//! The Issues tab's state (spec D3, D11): the grouped list, its filters and
//! the issues read so far, plus the pure helpers the reducer and the view
//! share. A row is bounded when it is built (D6 hostile-core bounds): the
//! view measures and draws what [`issue_row`] already cut, never the core's
//! strings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use aitm_poc::Severity;
use aitm_scan_model::{
    BySeverity, Confidence, FlowRef, Issue, IssueId, IssueLocation, IssueStatus, IssueSummary,
    IssueTarget, IssuesResult, JobId, L4Evidence, L4Location, L4Oracle, L4Transport, LaneKind,
    Timing,
};
use serde_json::{json, Map, Value};

use super::{
    confidence_token, is_issue_id, lane_token, more, scroll, severity_token, status_token, step,
    walk, wire_token, Dir, ScanError, CURSOR_MAX, DETAIL_LIST_MAX, DETAIL_VALUE_MAX,
    ISSUES_PAGE_LIMIT, SEVERITY_ORDER,
};
use crate::action::Action;
use crate::text::{clean, cut_to, truncate};

/// How many `Tick`s between two `scan.issues` refreshes while the Issues tab
/// is shown and a job is live (spec D6: five seconds).
pub const ISSUES_POLL_TICKS: u64 = 20;

/// The detail of the uncoded error a `scan.issue` reply gets when its `id` is
/// not the key of the tag it answers (the D6 hostile-core bound applied to
/// the keyed issue read): nothing is folded from such a reply.
pub const OTHER_ISSUE: &str = "reply named a different issue";

/// The widest a row's `name` cell grows before it is cut (the column cap,
/// and the bound [`issue_row`] applies when it is built).
pub const NAME_MAX: usize = 40;
/// The widest a row's location cell grows before it is cut.
pub const LOCATION_MAX: usize = 32;
/// The widest a row's `kind:name` cell grows before it is cut.
pub const POINT_MAX: usize = 24;
/// The most full issues `IssuesState::read` holds between folds (D6
/// hostile-core bounds; fix round E, E1): a cheap memory bound beside the
/// per-fold prune, the oldest inserted leaving first.
pub const READ_MAX: usize = 64;
/// The most rows of the timing table [`issue_detail_lines`] prints; a longer
/// series ends in a `... n more` line.
const TIMING_ROWS_MAX: usize = 12;
/// The most mutators of an L4 mutation chain [`issue_detail_lines`] prints;
/// [`bound_issue`] keeps one more than that, so the line can end in `...`
/// without holding the whole chain.
const MUTATIONS_MAX: usize = 16;
/// The most probe flows a read issue keeps (D6 hostile-core bounds; fix
/// round F, F4): [`bound_issue`] cuts `evidence.probe_flows` to this many
/// and counts the rest into [`ReadIssue::dropped_flows`], which the view
/// renders once as `... n more` under the flow list.
const FLOWS_MAX: usize = 64;

/// The confidence glyph pair, indexed tentative, firm, certain (spec D11,
/// "Left to the builder"): two flat monochrome dots, filled as the verdict
/// firms up, so the reading survives without colour. Read through
/// [`confidence_glyphs`].
const CONFIDENCE_GLYPHS: [&str; 3] = ["○○", "●○", "●●"];

/// Which pane of the Issues tab holds the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IssuePane {
    #[default]
    List,
    Detail,
}

/// The filter a key cycles (`S`, `C`, `L`, `T`, `J`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueFilterKey {
    Severity,
    Confidence,
    Lane,
    Status,
    Job,
}

/// The `scan.issues` filters (spec D3). Each `None` means "no filter".
///
/// `severity_min` is the wire type the issue rows carry,
/// [`aitm_poc::Severity`], so the filter serialises through serde like every
/// other field and never passes through a string mapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssueFilters {
    pub severity_min: Option<Severity>,
    pub confidence_min: Option<Confidence>,
    pub lane: Option<LaneKind>,
    pub status: Option<IssueStatus>,
    pub job: Option<JobId>,
}

/// The ring `S` walks (spec D11): none, low, medium, high, critical.
const SEVERITY_RING: [Option<Severity>; 5] = [
    None,
    Some(Severity::Low),
    Some(Severity::Medium),
    Some(Severity::High),
    Some(Severity::Critical),
];
/// The ring `C` walks: none, firm, certain.
const CONFIDENCE_RING: [Option<Confidence>; 3] =
    [None, Some(Confidence::Firm), Some(Confidence::Certain)];
/// The ring `L` walks: none, http, ws, l4_packet, l4_stream.
const LANE_RING: [Option<LaneKind>; 5] = [
    None,
    Some(LaneKind::Http),
    Some(LaneKind::Ws),
    Some(LaneKind::L4Packet),
    Some(LaneKind::L4Stream),
];
/// The ring `T` walks: none, open, confirmed, false_positive.
const STATUS_RING: [Option<IssueStatus>; 4] = [
    None,
    Some(IssueStatus::Open),
    Some(IssueStatus::Confirmed),
    Some(IssueStatus::FalsePositive),
];

/// One step forward round `ring` from `cur`; a value outside the ring (a
/// minimum no key reaches, `info` or `tentative`) goes back to none.
fn ring_next<T: PartialEq + Copy>(ring: &[Option<T>], cur: Option<T>) -> Option<T> {
    if ring.contains(&cur) {
        step(ring, cur, Dir::Next)
    } else {
        None
    }
}

impl IssueFilters {
    /// Cycle the filter `key` names one step (spec D11) round its ring
    /// ([`SEVERITY_RING`], [`CONFIDENCE_RING`], [`LANE_RING`],
    /// [`STATUS_RING`]); job toggles between the Jobs cursor's job
    /// (`jobs_cursor_job`) and none. Every cycle wraps back to none.
    pub fn cycle(&mut self, key: IssueFilterKey, jobs_cursor_job: Option<&str>) {
        match key {
            IssueFilterKey::Severity => {
                self.severity_min = ring_next(&SEVERITY_RING, self.severity_min)
            }
            IssueFilterKey::Confidence => {
                self.confidence_min = ring_next(&CONFIDENCE_RING, self.confidence_min)
            }
            IssueFilterKey::Lane => self.lane = ring_next(&LANE_RING, self.lane),
            IssueFilterKey::Status => self.status = ring_next(&STATUS_RING, self.status),
            IssueFilterKey::Job => {
                self.job = match self.job {
                    Some(_) => None,
                    None => jobs_cursor_job.map(str::to_string),
                }
            }
        }
    }

    /// The `scan.issues` arguments (spec D6): every `Some` filter under its
    /// umbrella-contract name and serde token, `None` omitted, and the page
    /// size [`ISSUES_PAGE_LIMIT`].
    pub fn args(&self) -> Value {
        let mut args = Map::new();
        if let Some(s) = self.severity_min {
            args.insert("severity_min".into(), json!(severity_token(s)));
        }
        if let Some(c) = self.confidence_min {
            args.insert("confidence_min".into(), json!(confidence_token(c)));
        }
        if let Some(l) = self.lane {
            args.insert("lane".into(), json!(lane_token(l)));
        }
        if let Some(st) = self.status {
            args.insert("status".into(), json!(status_token(st)));
        }
        if let Some(j) = &self.job {
            args.insert("job".into(), json!(j));
        }
        args.insert("limit".into(), json!(ISSUES_PAGE_LIMIT));
        Value::Object(args)
    }

    /// The filter line (spec D11, the mockup's `filters: job scan-1a2b3c4d ·
    /// S none · C none`): the job first when one is set, then every lettered
    /// filter with its value or `none`, so the line also reads as the key
    /// legend (builder's call).
    pub fn banner(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(5);
        if let Some(job) = &self.job {
            parts.push(format!("job {job}"));
        }
        parts.push(format!(
            "S {}",
            self.severity_min.map_or(NONE, severity_token)
        ));
        parts.push(format!(
            "C {}",
            self.confidence_min.map_or(NONE, confidence_token)
        ));
        parts.push(format!("L {}", self.lane.map_or(NONE, lane_token)));
        parts.push(format!("T {}", self.status.map_or(NONE, status_token)));
        format!("filters: {}", parts.join(" · "))
    }

    /// Whether any filter is set.
    pub fn is_active(&self) -> bool {
        *self != Self::default()
    }
}

/// What the filter line reads for an unset filter.
const NONE: &str = "none";

/// The row indices of `list` grouped under the five severities in
/// [`SEVERITY_ORDER`] (critical, high, medium, low, info), every group
/// present even when empty so the view draws its zero header; within a group
/// the wire order is kept.
pub fn grouped(list: &[IssueSummary]) -> Vec<(Severity, Vec<usize>)> {
    SEVERITY_ORDER
        .iter()
        .map(|s| {
            let rows = list
                .iter()
                .enumerate()
                .filter(|(_, i)| i.severity == *s)
                .map(|(k, _)| k)
                .collect();
            (*s, rows)
        })
        .collect()
}

/// The confidence glyph pair of a row ([`CONFIDENCE_GLYPHS`]).
pub fn confidence_glyphs(c: Confidence) -> &'static str {
    match c {
        Confidence::Tentative => CONFIDENCE_GLYPHS[0],
        Confidence::Firm => CONFIDENCE_GLYPHS[1],
        Confidence::Certain => CONFIDENCE_GLYPHS[2],
    }
}

/// The text cells of one Issues row (spec D11: `confidence glyph · name ·
/// METHOD path_template · kind:name · status`), every string already cut to
/// its cap by [`issue_row`] (D6 hostile-core bounds), measured by the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRow {
    pub glyphs: &'static str,
    /// The name, cut to [`NAME_MAX`].
    pub name: String,
    /// `METHOD path_template`, or the template alone without a method, cut
    /// to [`LOCATION_MAX`].
    pub location: String,
    /// `kind:name`, the insertion kind's wire token and the point's name,
    /// cut to [`POINT_MAX`].
    pub point: String,
    /// The status token (`open`, `confirmed`, `false_positive`).
    pub status: &'static str,
}

/// Build the row cells for a summary, each cut to its cap here, once, so a
/// frame measures and elides at most a few hundred cells per row.
pub fn issue_row(i: &IssueSummary) -> IssueRow {
    let location = match &i.location.method {
        Some(m) => format!("{m} {}", i.location.path_template),
        None => i.location.path_template.clone(),
    };
    // Control characters are stripped before the cut (fix round G, G10),
    // so a tab-only name cannot shift the row's other columns.
    IssueRow {
        glyphs: confidence_glyphs(i.confidence),
        name: truncate(&clean(&i.name), NAME_MAX),
        location: truncate(&clean(&location), LOCATION_MAX),
        point: truncate(
            &clean(&format!(
                "{}:{}",
                wire_token(&i.location.kind),
                i.location.name
            )),
            POINT_MAX,
        ),
        status: status_token(i.status),
    }
}

/// A full issue as `IssuesState::read` holds it (fix round F, F4): the
/// `Issue` with its strings bounded by [`bound_issue`], and what that bound
/// dropped ([`Dropped`]), so the detail pane can say `... n more` under the
/// lists it kept. Derefs to the `Issue`, so a reader that wants a field
/// writes `read.name` as before.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadIssue {
    pub issue: Issue,
    pub dropped: Dropped,
}

/// What [`bound_issue`] cut off a read issue's lists (fix round G, G6,
/// G12), so the Detail pane's `... n more` lines name the real counts; all
/// zero when nothing was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    /// Probe flows past [`FLOWS_MAX`].
    pub flows: usize,
    /// Finders (`Issue.jobs`) past [`DETAIL_LIST_MAX`] (fix round H, H84).
    pub jobs: usize,
    /// Mutators of the L4 mutation chain past `MUTATIONS_MAX + 1`.
    pub mutations: usize,
    /// Timing rows past `TIMING_ROWS_MAX + 1`.
    pub timing: usize,
}

/// The full issues read so far (fix round G, G3): by id, with the
/// insertion order the cap evicts in, kept in step by every operation.
/// At most [`READ_MAX`] entries, the oldest leaving first; a landing on
/// an already-read row moves it to the back ([`ReadCache::touch`]), so
/// eviction never drops the row under the cursor (G4).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReadCache {
    by_id: BTreeMap<IssueId, ReadIssue>,
    order: VecDeque<IssueId>,
}

impl ReadCache {
    pub fn get(&self, id: &str) -> Option<&ReadIssue> {
        self.by_id.get(id)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// The ids held, in id order.
    pub fn keys(&self) -> impl Iterator<Item = &IssueId> {
        self.by_id.keys()
    }

    /// Insert or replace `id`'s issue; a new id joins the back of the
    /// order and, past [`READ_MAX`], the oldest leaves.
    pub fn insert(&mut self, id: IssueId, read: ReadIssue) {
        if self.by_id.insert(id.clone(), read).is_none() {
            self.order.push_back(id);
            while self.by_id.len() > READ_MAX {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.by_id.remove(&oldest);
            }
        }
        debug_assert_eq!(self.order.len(), self.by_id.len(), "order is by_id's twin");
    }

    /// Move `id` to the back of the eviction order (the cursor landed on
    /// it); nothing for an id not held.
    pub fn touch(&mut self, id: &str) {
        if let Some(k) = self.order.iter().position(|held| held == id) {
            if let Some(held) = self.order.remove(k) {
                self.order.push_back(held);
            }
        }
    }

    /// Keep the entries `keep` says yes to, dropping the rest from the
    /// order as well.
    pub fn retain(&mut self, mut keep: impl FnMut(&IssueId, &ReadIssue) -> bool) {
        self.by_id.retain(|id, read| keep(id, read));
        self.order.retain(|id| self.by_id.contains_key(id));
    }
}

/// The Detail pane's view state (fix round G, G7): what is scrolled, which
/// flow the cursor is on and whether the view follows it. One struct, so
/// the three reset together when the list cursor lands on a new row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetailView {
    /// The first detail line on screen, exactly what the view draws; the
    /// paging keys move it while the Detail pane is focused (plan task 8).
    pub scroll: u16,
    /// Cursor over the detail's flow list ([`flow_at`]), walked by
    /// `Up`/`Down` while the Detail pane is focused (spec D11); read
    /// clamped through [`IssuesState::flow_index`].
    pub flow_cursor: usize,
    /// Whether the view pulls the scroll so the flow under `flow_cursor`
    /// is on screen (fix round F, F7): set by `Up`/`Down` with the Detail
    /// pane focused (a flow key moves a cursor the operator must see),
    /// cleared by the paging keys and by a new row, so `scroll` alone
    /// decides what is drawn after `PageUp`/`PageDown`/`Home`/`End`.
    pub follow_flow: bool,
}

impl DetailView {
    /// A new row under the list cursor: the detail from the top, the
    /// first flow, nothing followed.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// A paging key over `len` lines: the scroll moves, the flow no longer
    /// leads.
    pub fn scroll(&mut self, action: &Action, len: usize, page: usize) {
        scroll(&mut self.scroll, action, len, page);
        self.follow_flow = false;
    }

    /// A flow key over `flows` flows: the cursor moves and the view
    /// follows it.
    pub fn walk_flow(&mut self, action: &Action, flows: usize, page: usize) {
        self.flow_cursor = walk(action, self.flow_cursor, flows, page);
        self.follow_flow = true;
    }

    /// Keep the flow cursor on the list of `flows` flows (fix round F, F6).
    pub fn clamp_flow(&mut self, flows: usize) {
        self.flow_cursor = self.flow_cursor.min(flows.saturating_sub(1));
    }
}

impl std::ops::Deref for ReadIssue {
    type Target = Issue;

    fn deref(&self) -> &Issue {
        &self.issue
    }
}

/// Which flow of the detail's walkable list an entry is (spec D11): a probe
/// flow, or the baseline the probes were compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTag {
    Probe,
    Baseline,
}

impl FlowTag {
    /// The word the flow list prints beside the id.
    pub fn label(self) -> &'static str {
        match self {
            FlowTag::Probe => "probe",
            FlowTag::Baseline => "baseline",
        }
    }
}

/// The Issues tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IssuesState {
    /// `scan.issues`' rows, in wire order, at most [`ISSUES_PAGE_LIMIT`] of
    /// them, every id in the wire form and every other string and the
    /// `jobs` list bounded once at fold ([`bound_summary`]; fix round H,
    /// H86); the view groups them by severity ([`grouped`] reads the
    /// severities off it). `rows` is its display
    /// twin, index for index (`fold_result` asserts the lengths); `list`
    /// stays because the reducer reads summary fields the display row does
    /// not carry for a row whose full issue is not yet read: the id for the
    /// cursor landing and the keyed calls, `poc_ref` and `name` for `P`,
    /// `status` for the round trip.
    pub list: Vec<IssueSummary>,
    /// The display row of every `list` entry, index for index, built once
    /// per fold with its strings bounded (D6 hostile-core bounds): what the
    /// view measures and draws.
    pub rows: Vec<IssueRow>,
    /// The severity tally the headers show.
    pub by_severity: BySeverity,
    /// `Some` while another page can be fetched; dropped to `None` at fold
    /// when the core's cursor is over [`CURSOR_MAX`] bytes (fix round I,
    /// I3; D6 hostile-core bounds). Unlike the Site map's G16 path this
    /// raises no error: the Issues tab never echoes the cursor back yet
    /// (the filters re-read the first page), so there is nothing to refuse,
    /// only an unbounded string not to hold.
    pub next_cursor: Option<String>,
    pub filters: IssueFilters,
    /// The list cursor.
    pub cursor: usize,
    pub pane: IssuePane,
    /// The full issues received from `scan.issue` and `scan.issue.update`,
    /// by id, each bounded as a [`ReadIssue`]: inserted on a reply only,
    /// never on send, only while the page lists the id, and pruned by
    /// every fold to the page's ids, so `read.len() <= list.len()` (spec
    /// D3, D6; fix round D, D1; fix round E, E11). An entry also leaves on
    /// a terminal line for its job ([`IssuesState::forget_job`]) or as the
    /// oldest once [`READ_MAX`] are held ([`ReadCache`]).
    pub read: ReadCache,
    /// The Detail pane's scroll, flow cursor and follow flag
    /// ([`DetailView`]), reset together when the list cursor lands on a
    /// new row.
    pub detail_view: DetailView,
    /// The tick of the last `scan.issues` request this tab sent; `None`
    /// until the tab was first opened (spec D6: "when the Issues tab was
    /// ever opened" reads `is_some()`, and the 20-tick timer counts from
    /// it).
    pub fetched_at_tick: Option<u64>,
    /// The one `scan.issue` read in flight, by id (spec D6: at most one at a
    /// time); the reply, ok or failed, clears it, as does a disconnect.
    pub pending_read: Option<IssueId>,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

impl IssuesState {
    /// Fold a `scan.issues` reply (spec D10): the page replaces `list` and
    /// `rows`, the tally and `next_cursor`; the list cursor follows the
    /// issue id it was on, re-found in the new page like the Jobs and Site
    /// map cursors (spec D11; fix round H, H75: a refetch after a status
    /// change moved the rows under a fixed index), and is clamped to the
    /// page only when that id is gone. Hostile-core bounds (D6): a row
    /// whose id is not in the wire form is dropped, the page is cut to
    /// [`ISSUES_PAGE_LIMIT`], every summary the page keeps is bounded
    /// ([`bound_summary`]: its free strings and its `jobs`; fix round H,
    /// H86) before its display row is built from it, a `next_cursor` over
    /// [`CURSOR_MAX`] bytes is dropped (fix round I, I3), and `read` keeps
    /// only the ids the page lists.
    pub fn fold_result(&mut self, mut result: IssuesResult) {
        result.issues.retain(|i| is_issue_id(&i.id));
        result.issues.truncate(ISSUES_PAGE_LIMIT);
        result.issues.iter_mut().for_each(bound_summary);
        let selected = self.cursor_issue().map(|i| i.id.clone());
        self.rows = result.issues.iter().map(issue_row).collect();
        self.list = result.issues;
        self.by_severity = result.by_severity;
        self.next_cursor = result.next_cursor.filter(|c| c.len() <= CURSOR_MAX);
        let found = selected.and_then(|id| self.list.iter().position(|i| i.id == id));
        self.cursor = found.unwrap_or(self.cursor.min(self.list.len().saturating_sub(1)));
        let listed: BTreeSet<&str> = self.list.iter().map(|i| i.id.as_str()).collect();
        self.read.retain(|id, _| listed.contains(id.as_str()));
        debug_assert_eq!(
            self.list.len(),
            self.rows.len(),
            "rows is list's display twin, index for index"
        );
    }

    /// The row under the list cursor, if the list has one.
    pub fn cursor_issue(&self) -> Option<&IssueSummary> {
        self.list.get(self.cursor)
    }

    /// The full issue of the row under the cursor, when `scan.issue` has
    /// answered for it: what the detail pane shows, so it is always the row
    /// under the cursor and never the issue read last (fix round D, D1).
    pub fn detail(&self) -> Option<&ReadIssue> {
        self.read.get(&self.cursor_issue()?.id)
    }

    /// Fold a full `Issue` from `scan.issue` or `scan.issue.update` (spec
    /// D10): it replaces `read[id]`, and the matching `list` row and its
    /// display row are rebuilt from `issue.summary()`, so the list shows
    /// the status the reply carries. An issue the page does not list is
    /// dropped, not read (fix round E, E11): the D1 invariant
    /// `read.len() <= list.len()` then holds between folds as well.
    /// Hostile-core bounds (D6; fix round E, E1, E19; fix round F, F4):
    /// every string the detail lines read and the probe flow list are cut
    /// here, once ([`bound_issue`]), and `read` keeps at most [`READ_MAX`]
    /// entries, the oldest inserted leaving first. When the folded issue
    /// is the cursor's, the flow cursor is clamped to the flow list it now
    /// has (fix round F, F6).
    pub fn fold_issue(&mut self, mut issue: Issue) {
        let Some(k) = self.list.iter().position(|row| row.id == issue.id) else {
            return;
        };
        let dropped = bound_issue(&mut issue);
        let summary = issue.summary();
        self.rows[k] = issue_row(&summary);
        self.list[k] = summary;
        let id = issue.id.clone();
        self.read.insert(id, ReadIssue { issue, dropped });
        if k == self.cursor {
            let flows = self.flow_count();
            self.detail_view.clamp_flow(flows);
        }
    }

    /// How many flows the detail's walkable list has: the kept probe flows
    /// and the baseline; 0 while the row under the cursor is unread.
    pub fn flow_count(&self) -> usize {
        self.detail().map_or(0, |i| flow_count_of(i))
    }

    /// `flow_cursor` clamped to the flow list: the index of the flow the
    /// Detail pane highlights, `None` when the list is empty.
    pub fn flow_index(&self) -> Option<usize> {
        let n = self.flow_count();
        (n > 0).then(|| self.detail_view.flow_cursor.min(n - 1))
    }

    /// The flow under the (clamped) flow cursor and its tag: what `Enter`
    /// opens with the Detail pane focused (spec D11; fix round F, F9).
    /// Indexes the list directly, never builds it.
    pub fn flow_under_cursor(&self) -> Option<(FlowRef, FlowTag)> {
        flow_at(self.detail()?, self.flow_index()?)
    }

    /// How many lines the Detail pane has for the row under the cursor
    /// ([`DetailLayout::total`]), counted without building them; 0 while
    /// the row is unread. The reducer clamps the scroll to it.
    pub fn detail_len(&self) -> usize {
        self.detail().map_or(0, |read| DetailLayout::of(read).total)
    }

    /// Drop every read issue whose every finder is `job` (spec D6: a
    /// terminal line for the job lets the next landing read the issue
    /// again), by the jobs the issue itself names (fix round H, H84; fix
    /// round I, I2): `jobs` when it lists any, else `job`, read in place
    /// without a clone. A filtered-out job's issues leave too, an issue
    /// another listed job still owns stays read, and a `jobs` that repeats
    /// the one finder (collapsed at fold anyway, I1) or disagrees with
    /// `job` is read by what it lists.
    pub fn forget_job(&mut self, job: &str) {
        self.read.retain(|_, i| {
            let only_this_job = if i.jobs.is_empty() {
                i.job == job
            } else {
                i.jobs.iter().all(|j| j == job)
            };
            !only_this_job
        });
    }
}

/// What one row of the Detail pane is ([`DetailLayout::row`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailRow {
    Head,
    /// `before_flows[i]` of [`issue_detail_lines`].
    Before(usize),
    FlowsLabel,
    /// The `f`th flow of [`flow_at`].
    Flow(usize),
    /// The `... n more` line under the flows.
    More,
    /// `after_flows[i]`.
    After(usize),
}

/// The row arithmetic of the Detail pane (fix round G, G2): where each run
/// starts, over the read issue alone, so the reducer counts the rows and
/// the view maps a row index to what it draws without building the rows
/// before it. The head line, the lines before the flows, the `flows`
/// label, one line per flow, the `... n more` line when the fold dropped
/// any, then the lines after the flows ([`issue_detail_lines`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetailLayout {
    /// The row of the `flows` label.
    pub flows_label: usize,
    /// The row of the first flow.
    pub first_flow: usize,
    /// How many flows are listed.
    pub flows: usize,
    /// Whether a `... n more` row follows the flows.
    pub more: bool,
    /// The row of the first line after the flows.
    pub first_after: usize,
    /// The rows in all; `IssuesState::detail_len` reads it.
    pub total: usize,
}

impl DetailLayout {
    pub fn of(read: &ReadIssue) -> Self {
        let (before, after) = detail_line_counts(read);
        let flows_label = 1 + before;
        let first_flow = flows_label + 1;
        let flows = flow_count_of(read);
        let more = read.dropped.flows > 0;
        let first_after = first_flow + flows + usize::from(more);
        Self {
            flows_label,
            first_flow,
            flows,
            more,
            first_after,
            total: first_after + after,
        }
    }

    /// What row `k` draws.
    pub fn row(&self, k: usize) -> DetailRow {
        if k == 0 {
            DetailRow::Head
        } else if k < self.flows_label {
            DetailRow::Before(k - 1)
        } else if k == self.flows_label {
            DetailRow::FlowsLabel
        } else if k < self.first_flow + self.flows {
            DetailRow::Flow(k - self.first_flow)
        } else if self.more && k == self.first_flow + self.flows {
            DetailRow::More
        } else {
            DetailRow::After(k - self.first_after)
        }
    }
}

/// Cut every free string a `scan.issues` row carries to [`DETAIL_VALUE_MAX`]
/// cells and its `jobs` to [`DETAIL_LIST_MAX`] ids, once, when the page
/// enters `list` (D6 hostile-core bounds; fix round H, H86): the display
/// twin [`issue_row`] builds is bounded by its own caps, but `list` kept
/// the summary as received, so a page of [`ISSUES_PAGE_LIMIT`] rows each
/// carrying an unbounded `jobs` array of unbounded ids, or a megabyte
/// `name`, sat in memory whole, and `P` read the raw `poc_ref` and `name`
/// off it. The same fields [`bound_issue`] cuts on the full issue are cut
/// here on the summary shape (`job`, `jobs`, `check_id`, `class`, `name`,
/// the target, the location and its L4 point, `poc_ref`, `finding_id`);
/// `id` was matched by the fold and is left alone, as are the enums and
/// numbers the contract bounds. The truncated `jobs` gives its capacity
/// back. The fields both shapes carry are listed once, in the helpers
/// [`location_strings`], [`target_strings`] and [`bound_jobs`] this and
/// [`bound_issue`] share (fix round I, I1).
fn bound_summary(summary: &mut IssueSummary) {
    bound_jobs(&mut summary.jobs);
    let mut fields: Vec<&mut String> = vec![
        &mut summary.job,
        &mut summary.name,
        &mut summary.class,
        &mut summary.check_id,
    ];
    fields.extend(target_strings(&mut summary.target));
    fields.extend(location_strings(&mut summary.location));
    fields.extend(summary.jobs.iter_mut());
    fields.extend(
        [summary.poc_ref.as_mut(), summary.finding_id.as_mut()]
            .into_iter()
            .flatten(),
    );
    for field in fields {
        cut_to(field, DETAIL_VALUE_MAX);
    }
}

/// Every string an [`IssueLocation`] carries (the path, its template, the
/// point's name, then the method, field path and WS path when present, and
/// the L4 point's ip, grammar, field path and mutation when it has one), as
/// the mutable borrows the fold cuts (fix round I, I1: listed once for
/// [`bound_summary`] and [`bound_issue`]).
fn location_strings(loc: &mut IssueLocation) -> Vec<&mut String> {
    let mut fields: Vec<&mut String> = vec![&mut loc.path, &mut loc.path_template, &mut loc.name];
    fields.extend(
        [
            loc.method.as_mut(),
            loc.field_path.as_mut(),
            loc.ws_path.as_mut(),
        ]
        .into_iter()
        .flatten(),
    );
    if let Some(l4) = &mut loc.l4 {
        fields.push(&mut l4.ip);
        fields.extend(
            [
                l4.grammar.as_mut(),
                l4.field_path.as_mut(),
                l4.mutation.as_mut(),
            ]
            .into_iter()
            .flatten(),
        );
    }
    fields
}

/// The two strings an [`IssueTarget`] carries, the scheme and the host (the
/// port is a number the contract bounds).
fn target_strings(target: &mut IssueTarget) -> [&mut String; 2] {
    [&mut target.scheme, &mut target.host]
}

/// Bound a `jobs` list at fold (fix round H, H84, H86; fix round I, I1):
/// a finder listed twice is kept once, at its first place, then the list
/// is cut to [`DETAIL_LIST_MAX`] and gives its capacity back. Returns how
/// many distinct finders the cut dropped (the `+n` of the `job` line); a
/// collapsed duplicate is the same finder, not a dropped one.
fn bound_jobs(jobs: &mut Vec<JobId>) -> usize {
    let mut seen: BTreeSet<JobId> = BTreeSet::new();
    jobs.retain(|j| seen.insert(j.clone()));
    let dropped = jobs.len().saturating_sub(DETAIL_LIST_MAX);
    jobs.truncate(DETAIL_LIST_MAX);
    jobs.shrink_to_fit();
    dropped
}

/// Cut every string [`issue_detail_lines`], [`issue_head`] and [`flow_at`]
/// read off an `Issue` to [`DETAIL_VALUE_MAX`] cells (and so at most four
/// times that in chars), once, when the issue enters `read` (D6
/// hostile-core bounds; fix round E, E19; fix round F, F4): the free-text
/// fields a core fills (`description`, `evidence.payload`,
/// `evidence.matched`, `remediation`, `note`) and every other string that
/// reaches the screen (`name`, `class`, `check_id`, the target, the
/// location and its L4 point, `poc_ref`, `finding_id`, the L4 evidence's
/// seed, scope and hex, each mutator). The mutation chain keeps
/// [`MUTATIONS_MAX`] plus one, the probe flow list [`FLOWS_MAX`], each
/// timing series [`TIMING_ROWS_MAX`] plus one (fix round G, G12); the
/// probe flows and timing rows dropped are returned, so the pane can count
/// them, and every truncated vector gives its capacity back. Ids the fold
/// matched (`id`), enums and numbers the contract already bounds are left
/// alone; `job`, a free string on the wire, is cut like the rest (G1), and
/// so is every id of `jobs`, kept to [`DETAIL_LIST_MAX`] with the rest
/// counted (H84). The per-frame line building then runs over bounded text
/// only.
fn bound_issue(issue: &mut Issue) -> Dropped {
    let cut = |s: &mut String| cut_to(s, DETAIL_VALUE_MAX);
    let dropped_jobs = bound_jobs(&mut issue.jobs);
    let mut fields: Vec<&mut String> = vec![
        &mut issue.description,
        &mut issue.job,
        &mut issue.name,
        &mut issue.class,
        &mut issue.check_id,
    ];
    fields.extend(target_strings(&mut issue.target));
    fields.extend(location_strings(&mut issue.location));
    fields.extend(issue.jobs.iter_mut());
    fields.extend(
        [
            issue.evidence.payload.as_mut(),
            issue.evidence.matched.as_mut(),
            issue.remediation.as_mut(),
            issue.note.as_mut(),
            issue.poc_ref.as_mut(),
            issue.finding_id.as_mut(),
        ]
        .into_iter()
        .flatten(),
    );
    let mut dropped_mutations = 0;
    if let Some(l4) = &mut issue.evidence.l4 {
        dropped_mutations = l4.mutation_chain.len().saturating_sub(MUTATIONS_MAX + 1);
        l4.mutation_chain.truncate(MUTATIONS_MAX + 1);
        l4.mutation_chain.shrink_to_fit();
        fields.push(&mut l4.seed_id);
        fields.push(&mut l4.scope_entry);
        fields.push(&mut l4.sent_hex);
        fields.extend(l4.mutation_chain.iter_mut());
    }
    for field in fields {
        cut(field);
    }
    let flows = &mut issue.evidence.probe_flows;
    let dropped_flows = flows.len().saturating_sub(FLOWS_MAX);
    flows.truncate(FLOWS_MAX);
    flows.shrink_to_fit();
    let mut dropped_timing = 0;
    if let Some(t) = &mut issue.evidence.timing {
        let keep = TIMING_ROWS_MAX + 1;
        dropped_timing = timing_rows(t).saturating_sub(keep);
        if dropped_timing > 0 {
            t.requested_s.truncate(keep);
            t.requested_s.shrink_to_fit();
            t.observed_ms.truncate(keep);
            t.observed_ms.shrink_to_fit();
            t.baseline_ms.truncate(keep);
            t.baseline_ms.shrink_to_fit();
        }
    }
    Dropped {
        flows: dropped_flows,
        jobs: dropped_jobs,
        mutations: dropped_mutations,
        timing: dropped_timing,
    }
}

/// The detail's first line as parts (spec D11; fix round F, F5, F8): the
/// name, then the severity, confidence and status the view styles from the
/// typed values, so a name that spells a verdict cannot forge the hue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueHead<'a> {
    pub name: &'a str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: IssueStatus,
}

/// The head line of `issue` ([`IssueHead`]).
pub fn issue_head(issue: &Issue) -> IssueHead<'_> {
    IssueHead {
        name: &issue.name,
        severity: issue.severity,
        confidence: issue.confidence,
        status: issue.status,
    }
}

/// One `label value` pair of the Detail pane; the view lays the two out
/// (fix round F, F8: the model bakes no layout into strings). An empty
/// label is a continuation line (a timing row).
pub type DetailLine = (&'static str, String);

/// The Detail pane's lines for a read issue (spec D11, plan task 8), split
/// where the walkable flow list sits (fix round F, F1): `before_flows` is
/// class, check id and lane; the target; the location (and the `l4` point
/// under it when the issue has one, H60); the description;
/// the evidence (`payload`, `matched`, the timing table, the diff lengths,
/// the L4 fields) when present; `after_flows` is the PoC and finding refs,
/// remediation and note when present, the jobs that found the issue
/// (H84), then occurrences with first and last seen. The head is [`issue_head`]; the flows are [`flow_at`]. Built from
/// the strings [`bound_issue`] cut once at fold time; the view cuts each
/// line to the pane. Nothing but the named fields of the `Issue` is ever
/// rendered, so no cookie or header value can reach the screen from here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetailLines {
    pub before_flows: Vec<DetailLine>,
    pub after_flows: Vec<DetailLine>,
}

/// The lines of the Issues Detail pane for the read issue ([`DetailLines`]).
pub fn issue_detail_lines(read: &ReadIssue) -> DetailLines {
    let issue = &read.issue;
    let mut before: Vec<DetailLine> = Vec::with_capacity(BEFORE_FIXED_LINES + 8);
    before.push((
        "class",
        format!(
            "{} · check {} · lane {}",
            issue.class,
            issue.check_id,
            lane_token(issue.lane)
        ),
    ));
    before.push((
        "target",
        format!(
            "{}://{}:{}",
            issue.target.scheme, issue.target.host, issue.target.port
        ),
    ));
    before.push(("location", location_text(issue)));
    if let Some(l4) = &issue.location.l4 {
        before.push(("l4", l4_location_text(l4)));
    }
    before.push(("description", issue.description.clone()));
    let ev = &issue.evidence;
    if let Some(p) = &ev.payload {
        before.push(("payload", p.clone()));
    }
    if let Some(m) = &ev.matched {
        before.push(("matched", m.clone()));
    }
    if let Some(t) = &ev.timing {
        timing_lines(t, read.dropped.timing, &mut before);
    }
    if let Some(d) = &ev.diff {
        before.push((
            "diff",
            format!(
                "baseline {} · true {} · false {} (response lengths)",
                d.baseline_len, d.true_len, d.false_len
            ),
        ));
    }
    if let Some(l4) = &ev.l4 {
        l4_lines(l4, read.dropped.mutations, &mut before);
    }
    let mut after: Vec<DetailLine> = Vec::with_capacity(AFTER_FIXED_LINES + 2);
    after.push((
        "poc",
        issue
            .poc_ref
            .as_deref()
            .map_or_else(|| "none".to_string(), |r| format!("{r} (P)")),
    ));
    after.push((
        "finding",
        issue.finding_id.as_deref().unwrap_or("none").to_string(),
    ));
    if let Some(r) = &issue.remediation {
        after.push(("remediation", r.clone()));
    }
    if let Some(n) = &issue.note {
        after.push(("note", n.clone()));
    }
    after.push(("job", jobs_text(issue, read.dropped.jobs)));
    after.push((
        "seen",
        format!(
            "{} occurrence{} · first {} · last {}",
            issue.occurrences,
            if issue.occurrences == 1 { "" } else { "s" },
            seen_text(issue.first_seen),
            seen_text(issue.last_seen)
        ),
    ));
    DetailLines {
        before_flows: before,
        after_flows: after,
    }
}

/// The lines every `before_flows` has: class, target, location,
/// description.
const BEFORE_FIXED_LINES: usize = 4;
/// The lines every `after_flows` has: poc, finding, job, seen.
const AFTER_FIXED_LINES: usize = 4;

/// How many lines [`issue_detail_lines`] builds for the read issue, as
/// `(before_flows, after_flows)`, counted without building them (the
/// reducer clamps the scroll on every key). Pinned to the built lines by a
/// unit test.
fn detail_line_counts(read: &ReadIssue) -> (usize, usize) {
    let issue = &read.issue;
    let ev = &issue.evidence;
    let before = BEFORE_FIXED_LINES
        + usize::from(issue.location.l4.is_some())
        + usize::from(ev.payload.is_some())
        + usize::from(ev.matched.is_some())
        + ev.timing.as_ref().map_or(0, timing_line_count)
        + usize::from(ev.diff.is_some())
        + ev.l4.as_ref().map_or(0, |_| L4_LINES);
    let after = AFTER_FIXED_LINES
        + usize::from(issue.remediation.is_some())
        + usize::from(issue.note.is_some());
    (before, after)
}

/// Both runs of [`detail_line_counts`] together (the unit tests' pin).
#[cfg(test)]
fn detail_line_count(read: &ReadIssue) -> usize {
    let (before, after) = detail_line_counts(read);
    before + after
}

/// `METHOD path_template · kind name`, then the request path when it is
/// not the template, the JSON field path and the WebSocket path when
/// present. The L4 point is its own `l4` line ([`l4_location_text`]; fix
/// round H, H60).
fn location_text(issue: &Issue) -> String {
    let loc = &issue.location;
    let mut text = match &loc.method {
        Some(m) => format!("{m} {}", loc.path_template),
        None => loc.path_template.clone(),
    };
    text.push_str(&format!(" · {} {}", wire_token(&loc.kind), loc.name));
    if loc.path != loc.path_template {
        text.push_str(&format!(" · path {}", loc.path));
    }
    if let Some(f) = &loc.field_path {
        text.push_str(&format!(" · field {f}"));
    }
    if let Some(w) = &loc.ws_path {
        text.push_str(&format!(" · ws {w}"));
    }
    text
}

/// The `job` detail line (fix round H, H84): every job that found or
/// re-found the issue (`jobs_or_job()`, the first finder first, each id cut
/// by [`bound_issue`]) joined by `, `, then ` +n` for the finders the fold
/// cut past [`DETAIL_LIST_MAX`].
fn jobs_text(issue: &Issue, dropped: usize) -> String {
    format!("{}{}", issue.jobs_or_job().join(", "), more(dropped))
}

/// The `l4` detail line (fix round H, H60): `ip:port/proto`, then the
/// grammar, field path and mutation, each only when present, joined by
/// ` · `. Every part was cut by [`bound_issue`].
fn l4_location_text(l4: &L4Location) -> String {
    let proto = match l4.proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    };
    let mut text = format!("{}:{}/{proto}", l4.ip, l4.port);
    for part in [&l4.grammar, &l4.field_path, &l4.mutation]
        .into_iter()
        .flatten()
    {
        text.push_str(" · ");
        text.push_str(part);
    }
    text
}

/// The timing table (spec D11): a header line, one row per sample
/// (`requested_s | observed_ms | baseline_ms`, a series shorter than the
/// longest reads `-`), at most [`TIMING_ROWS_MAX`] of them with a
/// `... n more` line past that (`n` counting the `dropped` rows the fold
/// cut as well, fix round G, G12), then `slope`/`r`.
fn timing_lines(t: &Timing, dropped: usize, out: &mut Vec<DetailLine>) {
    out.push((
        "timing",
        "requested_s | observed_ms | baseline_ms".to_string(),
    ));
    let rows = timing_rows(t);
    let shown = rows.min(TIMING_ROWS_MAX);
    for k in 0..shown {
        let cell = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
        out.push((
            "",
            format!(
                "{:>11} | {:>11} | {:>11}",
                cell(t.requested_s.get(k).map(|v| format!("{v:.1}"))),
                cell(t.observed_ms.get(k).map(ToString::to_string)),
                cell(t.baseline_ms.get(k).map(ToString::to_string)),
            ),
        ));
    }
    if rows > shown {
        out.push(("", format!("... {} more", rows - shown + dropped)));
    }
    out.push(("", format!("slope {:.1} ms/s · r {:.2}", t.slope, t.r)));
}

/// The sample count of a timing table: its longest series.
fn timing_rows(t: &Timing) -> usize {
    t.requested_s
        .len()
        .max(t.observed_ms.len())
        .max(t.baseline_ms.len())
}

/// The lines [`timing_lines`] writes: header, the shown rows, the overflow
/// line when there is one, the fit line.
fn timing_line_count(t: &Timing) -> usize {
    let rows = timing_rows(t);
    let shown = rows.min(TIMING_ROWS_MAX);
    2 + shown + usize::from(rows > shown)
}

/// The lines [`l4_lines`] writes: case, oracle, liveness, mutations, sent.
const L4_LINES: usize = 5;

/// The L4 evidence (spec D11, "L4 evidence fields when present"): the seed
/// and reproduction counts, the oracle's reading, the liveness probes, the
/// mutation chain (the first [`MUTATIONS_MAX`], then `... n more` counting
/// the one [`bound_issue`] kept past them and the `dropped` it cut; fix
/// round G, G6) and the bytes sent (hex).
fn l4_lines(l4: &L4Evidence, dropped: usize, out: &mut Vec<DetailLine>) {
    out.push((
        "l4 case",
        format!(
            "seed {} · rng {} · prior messages {} · reproduced {}/{} · scope {}",
            l4.seed_id,
            l4.rng_seed,
            l4.prior_messages,
            l4.reproduced.0,
            l4.reproduced.1,
            l4.scope_entry
        ),
    ));
    out.push(("oracle", oracle_text(l4.oracle)));
    let yes_no = |b: bool| if b { "passed" } else { "failed" };
    out.push((
        "liveness",
        format!(
            "before {} · after {}",
            yes_no(l4.liveness_before),
            yes_no(l4.liveness_after)
        ),
    ));
    let mut chain = l4
        .mutation_chain
        .iter()
        .take(MUTATIONS_MAX)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" > ");
    if l4.mutation_chain.len() > MUTATIONS_MAX {
        let more = l4.mutation_chain.len() - MUTATIONS_MAX + dropped;
        chain.push_str(&format!(" ... {more} more"));
    }
    if chain.is_empty() {
        chain.push_str("none");
    }
    out.push(("mutations", chain));
    out.push(("sent hex", l4.sent_hex.clone()));
}

/// How an L4 oracle read the reaction, in words.
fn oracle_text(o: L4Oracle) -> String {
    match o {
        L4Oracle::ProtocolError => "protocol error".to_string(),
        L4Oracle::Reset => "connection reset".to_string(),
        L4Oracle::Icmp { icmp_type, code } => format!("icmp type {icmp_type} code {code}"),
        L4Oracle::Silence => "silence".to_string(),
        L4Oracle::LivenessFailed => "liveness failed".to_string(),
        L4Oracle::LatencyOutlier => "latency outlier".to_string(),
    }
}

/// The `k`th flow of the detail's walkable list (spec D11): the kept probe
/// flows in wire order, then the baseline flow; `None` past the end. The
/// refs are UUIDs the parse already validated, so a frame indexes the two
/// fields directly and never builds the list (fix round F, F4, F9).
pub fn flow_at(issue: &Issue, k: usize) -> Option<(FlowRef, FlowTag)> {
    let ev = &issue.evidence;
    match ev.probe_flows.get(k) {
        Some(probe) => Some((*probe, FlowTag::Probe)),
        None if k == ev.probe_flows.len() => ev.baseline_flow.map(|b| (b, FlowTag::Baseline)),
        None => None,
    }
}

/// How many flows [`flow_at`] indexes for `issue`.
fn flow_count_of(issue: &Issue) -> usize {
    issue.evidence.probe_flows.len() + usize::from(issue.evidence.baseline_flow.is_some())
}

/// A wire timestamp (Unix milliseconds) as `YYYY-MM-DD HH:MM:SS` UTC: the
/// civil-date arithmetic written out, so the crate needs no time
/// dependency for one read-only line.
fn seen_text(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_glyphs_fill_as_the_verdict_firms() {
        assert_eq!(confidence_glyphs(Confidence::Certain), "●●");
        assert_eq!(confidence_glyphs(Confidence::Tentative), "○○");
    }

    #[test]
    fn severity_cycles_from_none_through_critical_and_back() {
        let mut f = IssueFilters::default();
        let mut seen = Vec::new();
        for _ in 0..5 {
            f.cycle(IssueFilterKey::Severity, None);
            seen.push(f.severity_min);
        }
        assert_eq!(
            seen,
            vec![
                Some(Severity::Low),
                Some(Severity::Medium),
                Some(Severity::High),
                Some(Severity::Critical),
                None
            ]
        );
        // A minimum no key reaches goes back to none rather than sticking.
        f.severity_min = Some(Severity::Info);
        f.cycle(IssueFilterKey::Severity, None);
        assert_eq!(f.severity_min, None);
        f.confidence_min = Some(Confidence::Tentative);
        f.cycle(IssueFilterKey::Confidence, None);
        assert_eq!(f.confidence_min, None);
    }

    #[test]
    fn args_carry_only_the_set_filters_under_their_wire_tokens() {
        let mut f = IssueFilters::default();
        assert_eq!(f.args(), json!({ "limit": 512 }));
        f.lane = Some(LaneKind::L4Packet);
        f.status = Some(IssueStatus::FalsePositive);
        f.job = Some("scan-1a2b3c4d".into());
        assert_eq!(
            f.args(),
            json!({
                "lane": "l4_packet",
                "status": "false_positive",
                "job": "scan-1a2b3c4d",
                "limit": 512,
            })
        );
        assert_eq!(
            f.banner(),
            "filters: job scan-1a2b3c4d · S none · C none · L l4_packet · T false_positive"
        );
    }

    #[test]
    fn job_toggles_against_the_cursor() {
        let mut f = IssueFilters::default();
        f.cycle(IssueFilterKey::Job, None);
        assert_eq!(f.job, None, "no cursor job, nothing to filter on");
        f.cycle(IssueFilterKey::Job, Some("scan-1a2b3c4d"));
        assert_eq!(f.job.as_deref(), Some("scan-1a2b3c4d"));
        f.cycle(IssueFilterKey::Job, Some("scan-55667788"));
        assert_eq!(f.job, None, "a second press clears, whatever the cursor");
    }

    /// The contract pack's issue, parsed; a missing or malformed file is a
    /// test bug and panics with its path (fix round F, F13).
    fn fixture_issue() -> Issue {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/scan.issue.json"
        );
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("scan.issue.json: cannot read {path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("scan.issue.json: {e}"))
    }

    /// An `Issue` as `read` would hold it, nothing dropped.
    fn read_of(issue: &Issue) -> ReadIssue {
        ReadIssue {
            issue: issue.clone(),
            dropped: Dropped::default(),
        }
    }

    /// `(label, value)` pairs from literals, for the pins below.
    fn pairs(lines: &[(&'static str, &str)]) -> Vec<DetailLine> {
        lines.iter().map(|(l, v)| (*l, (*v).to_string())).collect()
    }

    /// Task 8 (fix round F, F1, F8): the detail pairs in their D11 order
    /// around the flow list, the head as typed parts, the flows indexed
    /// probes first then the baseline, and the counts equal to what is
    /// built.
    #[test]
    fn detail_lines_read_the_fixture_issue() {
        let issue = fixture_issue();
        assert_eq!(
            issue_head(&issue),
            IssueHead {
                name: "Reflected cross-site scripting",
                severity: Severity::High,
                confidence: Confidence::Certain,
                status: IssueStatus::Open,
            }
        );
        let lines = issue_detail_lines(&read_of(&issue));
        assert_eq!(
            lines.before_flows,
            pairs(&[
                (
                    "class",
                    "reflected-xss · check http.reflected-xss · lane http"
                ),
                ("target", "http://127.0.0.1:8080"),
                ("location", "GET /search · query q"),
                (
                    "description",
                    "A request parameter is reflected into the response unescaped."
                ),
                ("payload", "<script>aitm-canary()</script>"),
                (
                    "matched",
                    "reflected marker aitm-canary in an HTML text node"
                ),
            ])
        );
        assert_eq!(
            lines.after_flows,
            pairs(&[
                ("poc", "poc-3b1c (P)"),
                ("finding", "finding-7a21"),
                (
                    "remediation",
                    "Contextually encode output and set a strict CSP."
                ),
                ("job", "scan-1a2b3c4d"),
                (
                    "seen",
                    "1 occurrence · first 2025-10-31 08:40:00 · last 2025-10-31 08:40:00"
                ),
            ])
        );
        assert_eq!(
            detail_line_count(&read_of(&issue)),
            lines.before_flows.len() + lines.after_flows.len()
        );
        let flows: Vec<(String, &str)> = (0..4)
            .filter_map(|k| flow_at(&issue, k))
            .map(|(id, tag)| (id.to_string(), tag.label()))
            .collect();
        assert_eq!(
            flows,
            vec![
                ("550e8400-e29b-41d4-a716-446655440000".to_string(), "probe"),
                ("7c9e6679-7425-40de-944b-e07fc1f90ae7".to_string(), "probe"),
                (
                    "16fd2706-8baf-433b-82eb-8c7fada847da".to_string(),
                    "baseline"
                ),
            ]
        );
        assert_eq!(flow_count_of(&issue), 3);
        let mut state = IssuesState::default();
        assert_eq!(state.detail_len(), 0, "an unread row has no detail");
        assert_eq!(state.flow_count(), 0);
        assert_eq!(state.flow_index(), None);
        assert_eq!(state.flow_under_cursor(), None);
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        state.fold_issue(issue);
        // The head, eleven pairs (the `job` line among them, H84), the
        // flows label and three flows.
        assert_eq!(
            state.detail_len(),
            1 + 11 + 1 + 3,
            "head, pairs, label, flows"
        );
        assert_eq!(state.flow_count(), 3);
        state.detail_view.flow_cursor = 9;
        assert_eq!(state.flow_index(), Some(2), "clamped to the baseline");
        assert_eq!(
            state
                .flow_under_cursor()
                .map(|(id, tag)| (id.to_string(), tag)),
            Some((
                "16fd2706-8baf-433b-82eb-8c7fada847da".to_string(),
                FlowTag::Baseline
            ))
        );
    }

    /// Task 8: timing, diff and L4 evidence render as their table and
    /// fields; a long series is cut to `TIMING_ROWS_MAX` with an overflow
    /// line; the count still equals the lines built; a 1 MiB description is
    /// cut to 400 cells at fold time (fix round F, F4), and so is every
    /// other string the pane reads; the mutation chain keeps one past
    /// `MUTATIONS_MAX` and the line ends in `...`.
    #[test]
    fn detail_lines_render_timing_diff_and_l4_evidence() {
        use aitm_scan_model::{Diff, Evidence};
        let mut issue = fixture_issue();
        issue.evidence = Evidence {
            payload: None,
            matched: None,
            probe_flows: Vec::new(),
            baseline_flow: None,
            timing: Some(Timing {
                requested_s: vec![1.0, 2.0, 3.0],
                observed_ms: vec![1010, 2020],
                baseline_ms: vec![12, 11, 13],
                slope: 1004.5,
                r: 0.998,
                correlated: true,
            }),
            diff: Some(Diff {
                baseline_len: 1200,
                true_len: 1200,
                false_len: 980,
            }),
            l4: Some(L4Evidence {
                sent_hex: "deadbeef".into(),
                seed_id: "hello".into(),
                rng_seed: 42,
                mutation_chain: vec!["flip".into(), "truncate".into()],
                prior_messages: 3,
                oracle: L4Oracle::Icmp {
                    icmp_type: 3,
                    code: 3,
                },
                liveness_before: true,
                liveness_after: false,
                reproduced: (2, 3),
                scope_entry: "l4-1".into(),
            }),
        };
        issue.remediation = None;
        issue.description = "D".repeat(1 << 20);
        issue.check_id = "C".repeat(1 << 20);
        assert_eq!(bound_issue(&mut issue).flows, 0, "no probe flows to drop");
        let lines = issue_detail_lines(&read_of(&issue));
        assert_eq!(
            detail_line_count(&read_of(&issue)),
            lines.before_flows.len() + lines.after_flows.len()
        );
        assert_eq!(
            &lines.before_flows[4..9],
            &pairs(&[
                ("timing", "requested_s | observed_ms | baseline_ms"),
                ("", "        1.0 |        1010 |          12"),
                ("", "        2.0 |        2020 |          11"),
                ("", "        3.0 |           - |          13"),
                ("", "slope 1004.5 ms/s · r 1.00"),
            ])[..]
        );
        assert_eq!(
            lines.before_flows[9],
            (
                "diff",
                "baseline 1200 · true 1200 · false 980 (response lengths)".to_string()
            )
        );
        assert_eq!(
            &lines.before_flows[10..15],
            &pairs(&[
                (
                    "l4 case",
                    "seed hello · rng 42 · prior messages 3 · reproduced 2/3 · scope l4-1"
                ),
                ("oracle", "icmp type 3 code 3"),
                ("liveness", "before passed · after failed"),
                ("mutations", "flip > truncate"),
                ("sent hex", "deadbeef"),
            ])[..]
        );
        assert_eq!(lines.before_flows.len(), 15);
        let (label, description) = &lines.before_flows[3];
        assert_eq!(*label, "description");
        assert_eq!(description.chars().count(), 400, "{description:?}");
        assert!(description.ends_with('…'));
        let (_, class) = &lines.before_flows[0];
        assert_eq!(
            class.chars().count(),
            "reflected-xss · check ".chars().count() + 400 + " · lane http".chars().count()
        );
        assert!(class.contains("CCCC… · lane http"), "{class:?}");
        assert_eq!(flow_at(&issue, 0), None);
        assert_eq!(flow_count_of(&issue), 0);

        let l4 = issue.evidence.l4.as_mut().unwrap_or_else(|| panic!("l4"));
        l4.mutation_chain = (0..1000).map(|k| format!("m{k}")).collect();
        let timing = issue
            .evidence
            .timing
            .as_mut()
            .unwrap_or_else(|| panic!("timing"));
        timing.observed_ms = vec![0; 40];
        let bounded = bound_issue(&mut issue);
        assert_eq!(bounded.timing, 40 - (TIMING_ROWS_MAX + 1), "G12");
        let l4 = issue.evidence.l4.as_ref().unwrap_or_else(|| panic!("l4"));
        assert_eq!(l4.mutation_chain.len(), MUTATIONS_MAX + 1);
        let read = ReadIssue {
            dropped: bounded,
            ..read_of(&issue)
        };
        let lines = issue_detail_lines(&read);
        assert_eq!(
            detail_line_count(&read),
            lines.before_flows.len() + lines.after_flows.len()
        );
        assert_eq!(
            lines.before_flows[4 + 1 + TIMING_ROWS_MAX],
            ("", "... 28 more".to_string())
        );
        let mutations = lines
            .before_flows
            .iter()
            .find(|(l, _)| *l == "mutations")
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            mutations,
            "m0 > m1 > m2 > m3 > m4 > m5 > m6 > m7 > m8 > m9 > m10 > m11 > m12 > m13 > m14 > m15 ... 984 more"
        );

        // Fix round H, H21 (G2): the same issue with 100 probe flows folded
        // through the state pins the one layout arithmetic with both the L4
        // lines above the flows and the `... n more` row below them: the
        // total is `detail_len`, 64 flows are kept and 36 counted, and the
        // first row past the flows and the overflow row is `After(0)`.
        let probe = fixture_issue().evidence.probe_flows[0];
        issue.evidence.probe_flows = vec![probe; 100];
        let mut state = IssuesState::default();
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        state.fold_issue(issue);
        let read = state.detail().unwrap_or_else(|| panic!("read"));
        assert_eq!(read.evidence.probe_flows.len(), FLOWS_MAX);
        assert_eq!(read.dropped.flows, 36);
        let lines = issue_detail_lines(read);
        assert!(
            lines.before_flows.iter().any(|(l, _)| *l == "l4 case"),
            "the L4 lines sit above the flows: {:?}",
            lines.before_flows
        );
        let layout = DetailLayout::of(read);
        assert_eq!(layout.total, state.detail_len());
        assert_eq!(layout.flows_label, 1 + lines.before_flows.len());
        assert_eq!(layout.flows, FLOWS_MAX);
        assert!(layout.more);
        assert_eq!(layout.first_after, layout.first_flow + FLOWS_MAX + 1);
        assert_eq!(
            layout.row(layout.first_flow + FLOWS_MAX - 1),
            DetailRow::Flow(FLOWS_MAX - 1)
        );
        assert_eq!(layout.row(layout.first_after - 1), DetailRow::More);
        assert_eq!(layout.row(layout.first_after), DetailRow::After(0));
        assert_eq!(layout.total, layout.first_after + lines.after_flows.len());
    }

    /// Fix round G, G12: the timing series are cut to `TIMING_ROWS_MAX + 1`
    /// at fold and the rows dropped are counted beside the issue, so the
    /// `... n more` line still names the real count; the truncated vectors
    /// give their capacity back.
    #[test]
    fn fold_issue_cuts_the_timing_series_and_keeps_the_count() {
        let mut issue = fixture_issue();
        issue.evidence.timing = Some(Timing {
            requested_s: vec![1.0; 1_000_000],
            observed_ms: vec![7; 1_000_000],
            baseline_ms: vec![3; 10],
            slope: 1.0,
            r: 0.5,
            correlated: false,
        });
        issue.evidence.probe_flows = vec![issue.evidence.probe_flows[0]; 1000];
        let mut state = IssuesState::default();
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        state.fold_issue(issue);
        let read = state.detail().unwrap_or_else(|| panic!("read"));
        let t = read
            .evidence
            .timing
            .as_ref()
            .unwrap_or_else(|| panic!("timing"));
        assert_eq!(t.requested_s.len(), TIMING_ROWS_MAX + 1);
        assert_eq!(t.observed_ms.len(), TIMING_ROWS_MAX + 1);
        assert_eq!(t.baseline_ms.len(), 10, "a short series is left alone");
        assert_eq!(read.dropped.timing, 1_000_000 - (TIMING_ROWS_MAX + 1));
        assert_eq!(read.dropped.timing, 999_987);
        assert!(t.observed_ms.capacity() < 1000, "capacity given back");
        assert!(read.evidence.probe_flows.capacity() < 1000);
        let lines = issue_detail_lines(read);
        let more = lines
            .before_flows
            .iter()
            .find(|(_, v)| v.starts_with("... "))
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert_eq!(more, "... 999988 more");
        assert_eq!(
            detail_line_count(read),
            lines.before_flows.len() + lines.after_flows.len()
        );
    }

    /// Fix round F, F4: the probe flow list is cut to `FLOWS_MAX` at fold
    /// time and the dropped count kept beside the issue; the baseline
    /// survives as the last flow and the detail counts the `... n more`
    /// line.
    #[test]
    fn fold_issue_keeps_flows_max_probe_flows_and_counts_the_rest() {
        let mut issue = fixture_issue();
        let probe = issue.evidence.probe_flows[0];
        issue.evidence.probe_flows = vec![probe; 1000];
        assert!(issue.evidence.baseline_flow.is_some());
        let mut state = IssuesState::default();
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        state.detail_view.flow_cursor = 999;
        state.fold_issue(issue);
        let read = state.detail().unwrap_or_else(|| panic!("read"));
        assert_eq!(read.evidence.probe_flows.len(), 64);
        assert_eq!(read.dropped.flows, 936);
        assert_eq!(state.flow_count(), 65);
        assert_eq!(
            state.detail_view.flow_cursor, 64,
            "clamped to the baseline (F6)"
        );
        assert_eq!(
            state.flow_under_cursor().map(|(_, tag)| tag),
            Some(FlowTag::Baseline)
        );
        assert_eq!(state.detail_len(), 1 + 11 + 1 + 65 + 1);
        // Fix round G, G2: the layout is the one arithmetic; its total is
        // `detail_len`, its runs are the lines built, and `first_after`
        // sits past the flows and the `... n more` row.
        let read = state.detail().expect("read");
        let layout = DetailLayout::of(read);
        assert_eq!(layout.total, state.detail_len());
        let lines = issue_detail_lines(read);
        assert_eq!(layout.flows_label, 1 + lines.before_flows.len());
        assert_eq!(layout.first_flow, layout.flows_label + 1);
        assert_eq!(layout.flows, 65);
        assert!(layout.more);
        assert_eq!(layout.first_after, layout.first_flow + 65 + 1);
        assert_eq!(layout.total, layout.first_after + lines.after_flows.len());
        assert_eq!(layout.row(0), DetailRow::Head);
        assert_eq!(layout.row(layout.flows_label), DetailRow::FlowsLabel);
        assert_eq!(layout.row(layout.first_flow + 64), DetailRow::Flow(64));
        assert_eq!(layout.row(layout.first_after - 1), DetailRow::More);
        assert_eq!(layout.row(layout.first_after), DetailRow::After(0));
        assert_eq!(
            layout.row(layout.total - 1),
            DetailRow::After(lines.after_flows.len() - 1)
        );
    }

    #[test]
    fn seen_text_is_utc_civil_time() {
        assert_eq!(seen_text(0), "1970-01-01 00:00:00");
        assert_eq!(seen_text(1_761_900_000_000), "2025-10-31 08:40:00");
        assert_eq!(seen_text(951_782_400_000), "2000-02-29 00:00:00");
        assert_eq!(seen_text(946_684_799_000), "1999-12-31 23:59:59");
        assert_eq!(seen_text(4_107_542_400_000), "2100-03-01 00:00:00");
    }

    /// Task 8: a folded issue replaces its list row and display row.
    #[test]
    fn fold_issue_replaces_the_row() {
        let mut issue = fixture_issue();
        let mut state = IssuesState::default();
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        issue.status = IssueStatus::Confirmed;
        state.fold_issue(issue);
        assert_eq!(state.list[0].status, IssueStatus::Confirmed);
        assert_eq!(state.rows[0].status, "confirmed");
        assert_eq!(
            state.detail().map(|i| i.status),
            Some(IssueStatus::Confirmed)
        );
    }
}
