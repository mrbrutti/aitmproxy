//! The Issues tab's state (spec D3, D11): the grouped list, its filters and
//! the issues read so far, plus the pure helpers the reducer and the view
//! share. A row is bounded when it is built (D6 hostile-core bounds): the
//! view measures and draws what [`issue_row`] already cut, never the core's
//! strings.

use std::collections::{BTreeMap, BTreeSet};

use aitm_poc::Severity;
use aitm_scan_model::{
    BySeverity, Confidence, InsertionKind, Issue, IssueId, IssueStatus, IssueSummary, IssuesResult,
    JobId, LaneKind,
};
use serde_json::{json, Map, Value};

use super::{is_issue_id, step, Dir, ScanError, ISSUES_PAGE_LIMIT};
use crate::ui::text::truncate;

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
    /// Cursor over the detail's probe flows.
    pub flow_cursor: usize,
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

    /// Drop every read issue that belongs to `job` (spec D6: a terminal
    /// line for the job lets the next landing read the issue again), by the
    /// job the issue itself names, so a filtered-out job's issues leave too.
    pub fn forget_job(&mut self, job: &str) {
        self.read.retain(|_, i| i.job != job);
    }
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
}
