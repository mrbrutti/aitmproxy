//! The Issues tab's state (spec D3, D11): the grouped list, its filters and
//! the issues read so far, plus the pure helpers the reducer and the view
//! share. A row is bounded when it is built (D6 hostile-core bounds): the
//! view measures and draws what [`issue_row`] already cut, never the core's
//! strings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use aitm_poc::Severity;
use aitm_scan_model::{
    BySeverity, Confidence, InsertionKind, Issue, IssueId, IssueStatus, IssueSummary, IssuesResult,
    JobId, L4Evidence, L4Location, L4Oracle, L4Transport, LaneKind, Timing,
};
use serde_json::{json, Map, Value};

use super::{is_issue_id, step, Dir, ScanError, ISSUES_PAGE_LIMIT};
use crate::text::truncate;

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
/// The widest any one detail value grows before it is cut (D6 hostile-core
/// bounds: a detail line is built from the core's strings when the pane is
/// drawn, so every value is cut here before the view measures it).
pub const DETAIL_VALUE_MAX: usize = 400;
/// The most full issues `IssuesState::read` holds between folds (D6
/// hostile-core bounds; fix round E, E1): a cheap memory bound beside the
/// per-fold prune, the oldest inserted leaving first.
pub const READ_MAX: usize = 64;
/// The most rows of the timing table [`issue_detail_lines`] prints; a longer
/// series ends in a `... n more` line.
pub const TIMING_ROWS_MAX: usize = 12;
/// The most mutators of an L4 mutation chain [`issue_detail_lines`] prints.
const MUTATIONS_MAX: usize = 16;
/// The tag of a probe flow in [`flow_refs`].
pub const PROBE: &str = "probe";
/// The tag of the baseline flow in [`flow_refs`].
pub const BASELINE: &str = "baseline";

/// The confidence glyph pair, indexed tentative, firm, certain (spec D11,
/// "Left to the builder"): two flat monochrome dots, filled as the verdict
/// firms up, so the reading survives without colour. Read through
/// [`confidence_glyphs`].
const CONFIDENCE_GLYPHS: [&str; 3] = ["○○", "●○", "●●"];

/// The five severities in header order, gravest first (spec D11). Every
/// per-severity table of the crate ([`severity_counts`], the Jobs tab's bar
/// glyphs) is indexed like this.
pub const SEVERITY_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

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

/// A severity's wire token (`"high"`): the wire spelling is the operator
/// spelling throughout the tab. Pinned to the serde names by a unit test.
pub fn severity_token(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// A confidence's wire token (`"firm"`).
pub fn confidence_token(c: Confidence) -> &'static str {
    match c {
        Confidence::Tentative => "tentative",
        Confidence::Firm => "firm",
        Confidence::Certain => "certain",
    }
}

/// A lane's wire token (`"l4_packet"`).
pub fn lane_token(l: LaneKind) -> &'static str {
    match l {
        LaneKind::Http => "http",
        LaneKind::Ws => "ws",
        LaneKind::L4Packet => "l4_packet",
        LaneKind::L4Stream => "l4_stream",
    }
}

/// An issue status's wire token (`"false_positive"`).
pub fn status_token(s: IssueStatus) -> &'static str {
    match s {
        IssueStatus::Open => "open",
        IssueStatus::Confirmed => "confirmed",
        IssueStatus::FalsePositive => "false_positive",
    }
}

/// An insertion kind's wire token (`"query"`, `"ws_json_value"`), read off
/// serde: twenty kinds, built once per fold by [`issue_row`], never per
/// frame. A kind that does not serialise to a string (none) reads `?`.
fn kind_token(kind: InsertionKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// The header label of a severity (`CRITICAL`, `HIGH`, ...).
pub fn severity_header(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// The tally's five counts in [`SEVERITY_ORDER`] order: the one walk of a
/// `BySeverity` the headers and the Jobs tab's severity bar share.
pub fn severity_counts(b: &BySeverity) -> [u64; 5] {
    [b.critical, b.high, b.medium, b.low, b.info]
}

/// The `by_severity` count for `s`.
pub fn count_of(b: &BySeverity, s: Severity) -> u64 {
    SEVERITY_ORDER
        .iter()
        .position(|x| *x == s)
        .map_or(0, |i| severity_counts(b)[i])
}

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
    IssueRow {
        glyphs: confidence_glyphs(i.confidence),
        name: truncate(&i.name, NAME_MAX),
        location: truncate(&location, LOCATION_MAX),
        point: truncate(
            &format!("{}:{}", kind_token(i.location.kind), i.location.name),
            POINT_MAX,
        ),
        status: status_token(i.status),
    }
}

/// The Issues tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IssuesState {
    /// `scan.issues`' rows, in wire order, at most [`ISSUES_PAGE_LIMIT`] of
    /// them and every id in the wire form; the view groups them by severity.
    pub list: Vec<IssueSummary>,
    /// The display row of every `list` entry, index for index, built once
    /// per fold with its strings bounded (D6 hostile-core bounds): what the
    /// view measures and draws.
    pub rows: Vec<IssueRow>,
    /// The severity tally the headers show.
    pub by_severity: BySeverity,
    /// `Some` while another page can be fetched.
    pub next_cursor: Option<String>,
    pub filters: IssueFilters,
    /// The list cursor.
    pub cursor: usize,
    pub pane: IssuePane,
    /// The full issues received from `scan.issue` (and, from the Issues
    /// detail task on, `scan.issue.update`), by id: inserted on a reply
    /// only, never on send, and pruned by every fold to the page's ids, so
    /// `read.len() <= list.len()` (spec D3, D6; fix round D, D1). An entry
    /// also leaves on a terminal line for its job ([`IssuesState::forget_job`]).
    pub read: BTreeMap<IssueId, Issue>,
    /// The keys of `read` in insertion order, oldest first: the eviction
    /// order once `read` holds [`READ_MAX`] entries (fix round E, E1). Kept
    /// in step with `read` by every insert and prune.
    pub read_order: VecDeque<IssueId>,
    /// Cursor over the detail's probe flows ([`flow_refs`]), walked by
    /// `Up`/`Down` while the Detail pane is focused (spec D11).
    pub flow_cursor: usize,
    /// The first detail line on screen; the paging keys scroll it while
    /// the Detail pane is focused (plan task 8), a new row resets it.
    pub detail_scroll: u16,
    /// The tick of the last `scan.issues` request this tab sent; `None`
    /// until the tab was first opened (spec D6: "when the Issues tab was
    /// ever opened" reads `is_some()`, and the 20-tick timer counts from
    /// it).
    pub fetched_at_tick: Option<u64>,
    /// The one `scan.issue` read in flight, by id (spec D6: at most one at a
    /// time); the reply, ok or failed, clears it, as does a disconnect.
    pub pending_read: Option<String>,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

impl IssuesState {
    /// Fold a `scan.issues` reply (spec D10): the page replaces `list` and
    /// `rows`, the tally and `next_cursor`; the list cursor is clamped to
    /// the new page. Hostile-core bounds (D6): a row whose id is not in the
    /// wire form is dropped, the page is cut to [`ISSUES_PAGE_LIMIT`], the
    /// row strings are bounded here, and `read` keeps only the ids the page
    /// lists.
    pub fn fold_result(&mut self, mut result: IssuesResult) {
        result.issues.retain(|i| is_issue_id(&i.id));
        result.issues.truncate(ISSUES_PAGE_LIMIT);
        self.rows = result.issues.iter().map(issue_row).collect();
        self.list = result.issues;
        self.by_severity = result.by_severity;
        self.next_cursor = result.next_cursor;
        self.cursor = self.cursor.min(self.list.len().saturating_sub(1));
        let listed: BTreeSet<&str> = self.list.iter().map(|i| i.id.as_str()).collect();
        self.read.retain(|id, _| listed.contains(id.as_str()));
        self.prune_read_order();
    }

    /// Drop from `read_order` every id no longer in `read`, after a prune
    /// of `read`.
    fn prune_read_order(&mut self) {
        self.read_order.retain(|id| self.read.contains_key(id));
    }

    /// The row under the list cursor, if the list has one.
    pub fn cursor_issue(&self) -> Option<&IssueSummary> {
        self.list.get(self.cursor)
    }

    /// The full issue of the row under the cursor, when `scan.issue` has
    /// answered for it: what the detail pane shows, so it is always the row
    /// under the cursor and never the issue read last (fix round D, D1).
    pub fn detail(&self) -> Option<&Issue> {
        self.read.get(&self.cursor_issue()?.id)
    }

    /// Fold a full `Issue` from `scan.issue` or `scan.issue.update` (spec
    /// D10): it replaces `read[id]`, and the matching `list` row and its
    /// display row are rebuilt from `issue.summary()`, so the list shows
    /// the status the reply carries. An issue the page does not list is
    /// dropped, not read (fix round E, E11): the D1 invariant
    /// `read.len() <= list.len()` then holds between folds as well.
    /// Hostile-core bounds (D6; fix round E, E1, E19): the strings the
    /// detail lines are built from are cut here, once ([`bound_issue`]),
    /// and `read` keeps at most [`READ_MAX`] entries, the oldest inserted
    /// leaving first.
    pub fn fold_issue(&mut self, mut issue: Issue) {
        let Some(k) = self.list.iter().position(|row| row.id == issue.id) else {
            return;
        };
        bound_issue(&mut issue);
        let summary = issue.summary();
        self.rows[k] = issue_row(&summary);
        self.list[k] = summary;
        let id = issue.id.clone();
        if self.read.insert(id.clone(), issue).is_none() {
            self.read_order.push_back(id);
            while self.read.len() > READ_MAX {
                match self.read_order.pop_front() {
                    Some(oldest) => {
                        self.read.remove(&oldest);
                    }
                    // Nothing tracked (entries written past this fold): drop
                    // the first key, so the bound holds whatever happened.
                    None => {
                        if let Some(first) = self.read.keys().next().cloned() {
                            self.read.remove(&first);
                        }
                    }
                }
            }
        }
    }

    /// How many lines the Detail pane has for the row under the cursor:
    /// [`issue_detail_lines`]' count plus the flow list ([`flow_refs`] under its
    /// label), counted without building them; 0 while the row is unread.
    /// The reducer clamps `detail_scroll` to it.
    pub fn detail_len(&self) -> usize {
        self.detail()
            .map_or(0, |i| issue_detail_line_count(i) + flow_list_len(i))
    }

    /// Drop every read issue that belongs to `job` (spec D6: a terminal
    /// line for the job lets the next landing read the issue again), by the
    /// job the issue itself names, so a filtered-out job's issues leave too.
    pub fn forget_job(&mut self, job: &str) {
        self.read.retain(|_, i| i.job != job);
        self.prune_read_order();
    }
}

/// Cut the strings [`issue_detail_lines`] reads off an `Issue` to
/// [`DETAIL_VALUE_MAX`] cells (and so at most four times that in chars),
/// once, when the issue enters `read` (D6 hostile-core bounds; fix round E,
/// E19): `description`, `evidence.payload`, `evidence.matched`,
/// `remediation` and `note`, the free-text fields a core fills; the rest
/// are ids, enums and numbers the contract already bounds. The per-frame
/// line building then runs over bounded text only.
fn bound_issue(issue: &mut Issue) {
    let cut = |s: &mut String| {
        // A char is never more cells than bytes, so a string within the cap
        // in bytes needs no walk and no new allocation.
        if s.len() > DETAIL_VALUE_MAX {
            *s = truncate(s, DETAIL_VALUE_MAX);
        }
    };
    cut(&mut issue.description);
    for field in [
        issue.evidence.payload.as_mut(),
        issue.evidence.matched.as_mut(),
        issue.remediation.as_mut(),
        issue.note.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        cut(field);
    }
}

/// The `label` column every detail line after the first is written with
/// (`payload  <script>...`): the labels are padded to it so the values line
/// up, as in the D11 mockup.
pub const DETAIL_LABEL_W: usize = 11;

/// One `label value` detail line, the label padded to [`DETAIL_LABEL_W`] and the
/// value cut to [`DETAIL_VALUE_MAX`].
fn line(label: &str, value: &str) -> String {
    format!(
        "{label:<DETAIL_LABEL_W$} {}",
        truncate(value, DETAIL_VALUE_MAX)
    )
}

/// The lines of the Issues Detail pane for `issue` (spec D11, plan task 8),
/// in this order: the name with `severity · confidence · status`; class,
/// check id and lane; the target; the location; the description; the
/// evidence (`payload`, `matched`, the timing table, the diff lengths, the
/// L4 fields) when present; the PoC and finding refs; remediation and note
/// when present; occurrences with first and last seen. The flows are not
/// here: [`flow_refs`] lists them, and the view draws them as the walkable
/// list under these lines. Every value is cut to [`DETAIL_VALUE_MAX`]
/// (D6 hostile-core bounds); the view cuts each line to the pane. Nothing
/// but the named fields of the `Issue` is ever rendered, so no cookie or
/// header value can reach the screen from here.
pub fn issue_detail_lines(issue: &Issue) -> Vec<String> {
    let mut out = Vec::with_capacity(issue_detail_line_count(issue));
    out.push(format!(
        "{}   {} · {} · {}",
        truncate(&issue.name, DETAIL_VALUE_MAX),
        severity_token(issue.severity),
        confidence_token(issue.confidence),
        status_token(issue.status)
    ));
    out.push(line(
        "class",
        &format!(
            "{} · check {} · lane {}",
            issue.class,
            issue.check_id,
            lane_token(issue.lane)
        ),
    ));
    out.push(line(
        "target",
        &format!(
            "{}://{}:{}",
            issue.target.scheme, issue.target.host, issue.target.port
        ),
    ));
    out.push(line("location", &location_text(issue)));
    out.push(line("description", &issue.description));
    let ev = &issue.evidence;
    if let Some(p) = &ev.payload {
        out.push(line("payload", p));
    }
    if let Some(m) = &ev.matched {
        out.push(line("matched", m));
    }
    if let Some(t) = &ev.timing {
        timing_lines(t, &mut out);
    }
    if let Some(d) = &ev.diff {
        out.push(line(
            "diff",
            &format!(
                "baseline {} · true {} · false {} (response lengths)",
                d.baseline_len, d.true_len, d.false_len
            ),
        ));
    }
    if let Some(l4) = &ev.l4 {
        l4_lines(l4, &mut out);
    }
    out.push(line(
        "poc",
        &issue
            .poc_ref
            .as_deref()
            .map_or_else(|| "none".to_string(), |r| format!("{r} (P)")),
    ));
    out.push(line(
        "finding",
        issue.finding_id.as_deref().unwrap_or("none"),
    ));
    if let Some(r) = &issue.remediation {
        out.push(line("remediation", r));
    }
    if let Some(n) = &issue.note {
        out.push(line("note", n));
    }
    out.push(line(
        "seen",
        &format!(
            "{} occurrence{} · first {} · last {}",
            issue.occurrences,
            if issue.occurrences == 1 { "" } else { "s" },
            seen_text(issue.first_seen),
            seen_text(issue.last_seen)
        ),
    ));
    out
}

/// The lines every [`issue_detail_lines`] has: the name line, class, target,
/// location, description, poc, finding, seen.
const DETAIL_FIXED_LINES: usize = 8;

/// How many lines [`issue_detail_lines`] builds for `issue`, counted without
/// building them (the reducer clamps the scroll on every key). Pinned to
/// `issue_detail_lines(issue).len()` by a unit test.
pub fn issue_detail_line_count(issue: &Issue) -> usize {
    let ev = &issue.evidence;
    DETAIL_FIXED_LINES
        + usize::from(ev.payload.is_some())
        + usize::from(ev.matched.is_some())
        + ev.timing.as_ref().map_or(0, timing_line_count)
        + usize::from(ev.diff.is_some())
        + ev.l4.as_ref().map_or(0, |_| L4_LINES)
        + usize::from(issue.remediation.is_some())
        + usize::from(issue.note.is_some())
}

/// `METHOD path_template · kind name`, then the request path when it is
/// not the template, the JSON field path, the WebSocket path and the L4
/// point (`ip:port/proto`, grammar, field, mutation) when present.
fn location_text(issue: &Issue) -> String {
    let loc = &issue.location;
    let mut text = match &loc.method {
        Some(m) => format!("{m} {}", loc.path_template),
        None => loc.path_template.clone(),
    };
    text.push_str(&format!(" · {} {}", kind_token(loc.kind), loc.name));
    if loc.path != loc.path_template {
        text.push_str(&format!(" · path {}", loc.path));
    }
    if let Some(f) = &loc.field_path {
        text.push_str(&format!(" · field {f}"));
    }
    if let Some(w) = &loc.ws_path {
        text.push_str(&format!(" · ws {w}"));
    }
    if let Some(l4) = &loc.l4 {
        text.push_str(&format!(" · l4 {}", l4_location_text(l4)));
    }
    text
}

/// `ip:port/proto`, then the grammar, field path and mutation when set.
fn l4_location_text(l4: &L4Location) -> String {
    let proto = match l4.proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    };
    let mut text = format!("{}:{}/{proto}", l4.ip, l4.port);
    if let Some(g) = &l4.grammar {
        text.push_str(&format!(" grammar {g}"));
    }
    if let Some(f) = &l4.field_path {
        text.push_str(&format!(" field {f}"));
    }
    if let Some(m) = &l4.mutation {
        text.push_str(&format!(" mutation {m}"));
    }
    text
}

/// The timing table (spec D11): a header line, one row per sample
/// (`requested_s | observed_ms | baseline_ms`, a series shorter than the
/// longest reads `-`), at most [`TIMING_ROWS_MAX`] of them with a
/// `... n more` line past that, then `slope`/`r`.
fn timing_lines(t: &Timing, out: &mut Vec<String>) {
    out.push(line("timing", "requested_s | observed_ms | baseline_ms"));
    let rows = timing_rows(t);
    let shown = rows.min(TIMING_ROWS_MAX);
    for k in 0..shown {
        let cell = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
        out.push(line(
            "",
            &format!(
                "{:>11} | {:>11} | {:>11}",
                cell(t.requested_s.get(k).map(|v| format!("{v:.1}"))),
                cell(t.observed_ms.get(k).map(ToString::to_string)),
                cell(t.baseline_ms.get(k).map(ToString::to_string)),
            ),
        ));
    }
    if rows > shown {
        out.push(line("", &format!("... {} more", rows - shown)));
    }
    out.push(line(
        "",
        &format!("slope {:.1} ms/s · r {:.2}", t.slope, t.r),
    ));
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
/// mutation chain and the bytes sent (hex, cut like every value).
fn l4_lines(l4: &L4Evidence, out: &mut Vec<String>) {
    out.push(line(
        "l4 case",
        &format!(
            "seed {} · rng {} · prior messages {} · reproduced {}/{} · scope {}",
            l4.seed_id,
            l4.rng_seed,
            l4.prior_messages,
            l4.reproduced.0,
            l4.reproduced.1,
            l4.scope_entry
        ),
    ));
    out.push(line("oracle", &oracle_text(l4.oracle)));
    let yes_no = |b: bool| if b { "passed" } else { "failed" };
    out.push(line(
        "liveness",
        &format!(
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
        chain.push_str(&format!(
            " > ... {} more",
            l4.mutation_chain.len() - MUTATIONS_MAX
        ));
    }
    if chain.is_empty() {
        chain.push_str("none");
    }
    out.push(line("mutations", &chain));
    out.push(line("sent hex", &l4.sent_hex));
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

/// The flows the Detail pane lists (spec D11): every probe flow tagged
/// [`PROBE`] in wire order, then the baseline flow tagged [`BASELINE`]. The
/// ids are the `FlowRef` UUIDs, already validated by the parse.
pub fn flow_refs(issue: &Issue) -> Vec<(String, &'static str)> {
    let ev = &issue.evidence;
    let mut out = Vec::with_capacity(ev.probe_flows.len() + 1);
    out.extend(ev.probe_flows.iter().map(|f| (f.to_string(), PROBE)));
    if let Some(b) = &ev.baseline_flow {
        out.push((b.to_string(), BASELINE));
    }
    out
}

/// How many flows [`flow_refs`] lists, counted without building them.
pub fn flow_refs_len(issue: &Issue) -> usize {
    issue.evidence.probe_flows.len() + usize::from(issue.evidence.baseline_flow.is_some())
}

/// The lines the view's flow list takes: its `flows` label line and one
/// line per flow ([`flow_refs_len`]), or the label alone reading none.
pub fn flow_list_len(issue: &Issue) -> usize {
    1 + flow_refs_len(issue)
}

/// A wire timestamp (Unix milliseconds) as `YYYY-MM-DD HH:MM:SS` UTC: the
/// civil-date arithmetic written out, so the crate needs no time
/// dependency for one read-only line.
pub fn seen_text(ms: u64) -> String {
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

    #[test]
    fn headers_and_counts_follow_the_tally() {
        let b = BySeverity {
            high: 1,
            medium: 1,
            ..Default::default()
        };
        let labels: Vec<String> = SEVERITY_ORDER
            .iter()
            .map(|s| format!("{} {}", severity_header(*s), count_of(&b, *s)))
            .collect();
        assert_eq!(
            labels,
            vec!["CRITICAL 0", "HIGH 1", "MEDIUM 1", "LOW 0", "INFO 0"]
        );
        assert_eq!(severity_counts(&b), [0, 1, 1, 0, 0]);
        assert_eq!(confidence_glyphs(Confidence::Certain), "●●");
        assert_eq!(confidence_glyphs(Confidence::Tentative), "○○");
    }

    /// Fix round D, D11: the static tokens are the serde names, variant for
    /// variant, so the filter arguments and the row cells never drift from
    /// the contract.
    #[test]
    fn static_tokens_match_the_serde_names() {
        fn serde_name<T: serde::Serialize>(v: T) -> String {
            serde_json::to_value(v)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        }
        for s in SEVERITY_ORDER {
            assert_eq!(severity_token(s), serde_name(s));
            assert_eq!(severity_header(s), severity_token(s).to_ascii_uppercase());
        }
        for c in [Confidence::Tentative, Confidence::Firm, Confidence::Certain] {
            assert_eq!(confidence_token(c), serde_name(c));
        }
        for l in [
            LaneKind::Http,
            LaneKind::Ws,
            LaneKind::L4Packet,
            LaneKind::L4Stream,
        ] {
            assert_eq!(lane_token(l), serde_name(l));
        }
        for st in [
            IssueStatus::Open,
            IssueStatus::Confirmed,
            IssueStatus::FalsePositive,
        ] {
            assert_eq!(status_token(st), serde_name(st));
        }
        assert_eq!(kind_token(InsertionKind::WsJsonValue), "ws_json_value");
    }

    /// The contract pack's issue, parsed.
    fn fixture_issue() -> Issue {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/scan.issue.json"
        ))
        .unwrap_or_default();
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("scan.issue.json: {e}"))
    }

    /// Task 8: the detail lines in their order, the labels padded, the
    /// flows listed probes first then the baseline, and the counts equal
    /// to what is built.
    #[test]
    fn detail_lines_read_the_fixture_issue() {
        let issue = fixture_issue();
        let lines = issue_detail_lines(&issue);
        assert_eq!(
            lines,
            vec![
                "Reflected cross-site scripting   high · certain · open".to_string(),
                "class       reflected-xss · check http.reflected-xss · lane http".into(),
                "target      http://127.0.0.1:8080".into(),
                "location    GET /search · query q".into(),
                "description A request parameter is reflected into the response unescaped.".into(),
                "payload     <script>aitm-canary()</script>".into(),
                "matched     reflected marker aitm-canary in an HTML text node".into(),
                "poc         poc-3b1c (P)".into(),
                "finding     finding-7a21".into(),
                "remediation Contextually encode output and set a strict CSP.".into(),
                "seen        1 occurrence · first 2025-10-31 08:40:00 · last 2025-10-31 08:40:00"
                    .into(),
            ]
        );
        assert_eq!(issue_detail_line_count(&issue), lines.len());
        assert_eq!(
            flow_refs(&issue),
            vec![
                ("550e8400-e29b-41d4-a716-446655440000".to_string(), "probe"),
                ("7c9e6679-7425-40de-944b-e07fc1f90ae7".to_string(), "probe"),
                (
                    "16fd2706-8baf-433b-82eb-8c7fada847da".to_string(),
                    "baseline"
                ),
            ]
        );
        assert_eq!(flow_refs_len(&issue), 3);
        assert_eq!(flow_list_len(&issue), 4);
        let mut state = IssuesState::default();
        assert_eq!(state.detail_len(), 0, "an unread row has no detail");
        state.list = vec![issue.summary()];
        state.rows = vec![issue_row(&state.list[0])];
        state.read.insert(issue.id.clone(), issue);
        assert_eq!(state.detail_len(), 11 + 4);
    }

    /// Task 8: timing, diff and L4 evidence render as their table and
    /// fields; a long series is cut to `TIMING_ROWS_MAX` with an overflow
    /// line; the count still equals the lines built; a 1 MiB value is cut
    /// to `DETAIL_VALUE_MAX` cells.
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
        let lines = issue_detail_lines(&issue);
        assert_eq!(issue_detail_line_count(&issue), lines.len());
        assert_eq!(
            &lines[5..10],
            &[
                "timing      requested_s | observed_ms | baseline_ms".to_string(),
                "                    1.0 |        1010 |          12".into(),
                "                    2.0 |        2020 |          11".into(),
                "                    3.0 |           - |          13".into(),
                "            slope 1004.5 ms/s · r 1.00".into(),
            ]
        );
        assert_eq!(
            lines[10],
            "diff        baseline 1200 · true 1200 · false 980 (response lengths)"
        );
        assert_eq!(
            &lines[11..16],
            &[
                "l4 case     seed hello · rng 42 · prior messages 3 · reproduced 2/3 · scope l4-1"
                    .to_string(),
                "oracle      icmp type 3 code 3".into(),
                "liveness    before passed · after failed".into(),
                "mutations   flip > truncate".into(),
                "sent hex    deadbeef".into(),
            ]
        );
        let description = &lines[4];
        assert_eq!(
            description.chars().count(),
            DETAIL_LABEL_W + 1 + DETAIL_VALUE_MAX,
            "{description:?}"
        );
        assert!(description.ends_with('…'));
        assert!(flow_refs(&issue).is_empty());
        assert_eq!(flow_list_len(&issue), 1);

        let timing = issue
            .evidence
            .timing
            .as_mut()
            .unwrap_or_else(|| panic!("timing"));
        timing.observed_ms = vec![0; 40];
        let lines = issue_detail_lines(&issue);
        assert_eq!(issue_detail_line_count(&issue), lines.len());
        assert_eq!(lines[5 + 1 + TIMING_ROWS_MAX], "            ... 28 more");
    }

    #[test]
    fn seen_text_is_utc_civil_time() {
        assert_eq!(seen_text(0), "1970-01-01 00:00:00");
        assert_eq!(seen_text(1_761_900_000_000), "2025-10-31 08:40:00");
        assert_eq!(seen_text(951_782_400_000), "2000-02-29 00:00:00");
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
