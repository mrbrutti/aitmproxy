//! The Issues tab's state (spec D3, D11): the grouped list, its filters and
//! the open issue, plus the pure helpers the reducer and the view share.

use std::collections::BTreeSet;

use aitm_poc::Severity;
use aitm_scan_model::{
    BySeverity, Confidence, Issue, IssueStatus, IssueSummary, IssuesResult, JobId, LaneKind,
};
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::{ScanError, ISSUES_PAGE_LIMIT};

/// How many `Tick`s between two `scan.issues` refreshes while the Issues tab
/// is shown and a job is live (spec D6: five seconds).
pub const ISSUES_POLL_TICKS: u64 = 20;

/// The detail of the uncoded error a `scan.issue` reply gets when its `id` is
/// not the key of the tag it answers (the D6 hostile-core bound applied to
/// the keyed issue read, builder's call): nothing is folded from such a reply.
pub const OTHER_ISSUE: &str = "reply named a different issue";

/// The confidence glyph pair, indexed tentative, firm, certain (spec D11,
/// "Left to the builder"): two flat monochrome dots, filled as the verdict
/// firms up, so the reading survives without colour.
pub const CONFIDENCE_GLYPHS: [&str; 3] = ["○○", "●○", "●●"];

/// The five severities in header order, gravest first (spec D11).
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

impl IssueFilters {
    /// Cycle the filter `key` names one step (spec D11): severity `none, low,
    /// medium, high, critical`; confidence `none, firm, certain`; lane `none,
    /// http, ws, l4_packet, l4_stream`; status `none, open, confirmed,
    /// false_positive`; job toggles between the Jobs cursor's job
    /// (`jobs_cursor_job`) and none. Every cycle wraps back to none.
    pub fn cycle(&mut self, key: IssueFilterKey, jobs_cursor_job: Option<&str>) {
        match key {
            IssueFilterKey::Severity => {
                self.severity_min = match self.severity_min {
                    None => Some(Severity::Low),
                    Some(Severity::Low) => Some(Severity::Medium),
                    Some(Severity::Medium) => Some(Severity::High),
                    Some(Severity::High) => Some(Severity::Critical),
                    Some(Severity::Critical | Severity::Info) => None,
                }
            }
            IssueFilterKey::Confidence => {
                self.confidence_min = match self.confidence_min {
                    None => Some(Confidence::Firm),
                    Some(Confidence::Firm) => Some(Confidence::Certain),
                    Some(Confidence::Certain | Confidence::Tentative) => None,
                }
            }
            IssueFilterKey::Lane => {
                self.lane = match self.lane {
                    None => Some(LaneKind::Http),
                    Some(LaneKind::Http) => Some(LaneKind::Ws),
                    Some(LaneKind::Ws) => Some(LaneKind::L4Packet),
                    Some(LaneKind::L4Packet) => Some(LaneKind::L4Stream),
                    Some(LaneKind::L4Stream) => None,
                }
            }
            IssueFilterKey::Status => {
                self.status = match self.status {
                    None => Some(IssueStatus::Open),
                    Some(IssueStatus::Open) => Some(IssueStatus::Confirmed),
                    Some(IssueStatus::Confirmed) => Some(IssueStatus::FalsePositive),
                    Some(IssueStatus::FalsePositive) => None,
                }
            }
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
            args.insert("severity_min".into(), json!(token(&s)));
        }
        if let Some(c) = self.confidence_min {
            args.insert("confidence_min".into(), json!(token(&c)));
        }
        if let Some(l) = self.lane {
            args.insert("lane".into(), json!(token(&l)));
        }
        if let Some(st) = self.status {
            args.insert("status".into(), json!(token(&st)));
        }
        if let Some(j) = &self.job {
            args.insert("job".into(), json!(j));
        }
        args.insert("limit".into(), json!(ISSUES_PAGE_LIMIT));
        Value::Object(args)
    }

    /// The filter banner (spec D11, the mockup's `filters: job scan-1a2b3c4d
    /// · S none · C none`): the job first when one is set, then every lettered
    /// filter with its value or `none`, so the line also reads as the key
    /// legend (builder's call).
    pub fn banner(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(5);
        if let Some(job) = &self.job {
            parts.push(format!("job {job}"));
        }
        parts.push(format!(
            "S {}",
            self.severity_min.map_or_else(none, |s| token(&s))
        ));
        parts.push(format!(
            "C {}",
            self.confidence_min.map_or_else(none, |c| token(&c))
        ));
        parts.push(format!("L {}", self.lane.map_or_else(none, |l| token(&l))));
        parts.push(format!(
            "T {}",
            self.status.map_or_else(none, |s| token(&s))
        ));
        format!("filters: {}", parts.join(" · "))
    }

    /// Whether any filter is set.
    pub fn is_active(&self) -> bool {
        *self != Self::default()
    }
}

fn none() -> String {
    "none".to_string()
}

/// The serde token of a contract enum (`"l4_packet"`, `"false_positive"`,
/// `"high"`): the wire spelling is the operator spelling throughout the tab.
/// A value that does not serialise to a string (none of ours) reads `?`.
pub fn token<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// The header label of a severity (`CRITICAL`, `HIGH`, ...).
pub fn severity_header(s: Severity) -> String {
    token(&s).to_ascii_uppercase()
}

/// The `by_severity` count for `s`.
pub fn count_of(b: &BySeverity, s: Severity) -> u64 {
    match s {
        Severity::Critical => b.critical,
        Severity::High => b.high,
        Severity::Medium => b.medium,
        Severity::Low => b.low,
        Severity::Info => b.info,
    }
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
/// METHOD path_template · kind:name · status`), measured by the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRow {
    pub glyphs: &'static str,
    pub name: String,
    /// `METHOD path_template`, or the template alone without a method.
    pub location: String,
    /// `kind:name`, the insertion kind's wire token and the point's name.
    pub point: String,
    /// The status token (`open`, `confirmed`, `false_positive`).
    pub status: String,
}

/// Build the row cells for a summary.
pub fn issue_row(i: &IssueSummary) -> IssueRow {
    let location = match &i.location.method {
        Some(m) => format!("{m} {}", i.location.path_template),
        None => i.location.path_template.clone(),
    };
    IssueRow {
        glyphs: confidence_glyphs(i.confidence),
        name: i.name.clone(),
        location,
        point: format!("{}:{}", token(&i.location.kind), i.location.name),
        status: token(&i.status),
    }
}

/// The Issues tab.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IssuesState {
    /// `scan.issues`' rows, in wire order; the view groups them by severity.
    pub list: Vec<IssueSummary>,
    /// The severity tally the headers show.
    pub by_severity: BySeverity,
    /// `Some` while another page can be fetched.
    pub next_cursor: Option<String>,
    pub filters: IssueFilters,
    /// The list cursor.
    pub cursor: usize,
    pub pane: IssuePane,
    /// The open issue (`scan.issue` / `scan.issue.update` reply).
    pub detail: Option<Issue>,
    /// Cursor over the detail's probe flows.
    pub flow_cursor: usize,
    /// The tick of the last `scan.issues` request this tab sent; `None`
    /// until the tab was first opened (spec D6: "when the Issues tab was
    /// ever opened" reads `is_some()`).
    pub fetched_at_tick: Option<u64>,
    /// The issue ids `scan.issue` was asked for (spec D6: once per id); an id
    /// leaves on a status update or on a terminal line for its job.
    pub fetched: BTreeSet<String>,
    /// This tab's last error.
    pub error: Option<ScanError>,
}

impl IssuesState {
    /// Fold a `scan.issues` reply (spec D10): the page replaces `list`, the
    /// tally and the cursor; the list cursor is clamped to the new page.
    pub fn fold_result(&mut self, result: IssuesResult) {
        self.list = result.issues;
        self.by_severity = result.by_severity;
        self.next_cursor = result.next_cursor;
        self.cursor = self.cursor.min(self.list.len().saturating_sub(1));
    }

    /// The row under the list cursor, if the list has one.
    pub fn cursor_issue(&self) -> Option<&IssueSummary> {
        self.list.get(self.cursor)
    }

    /// Forget every fetched id that belongs to `job` (spec D6: a terminal
    /// line for the job lets the next landing read the issue again), read
    /// from the list rows and the open detail.
    pub fn forget_job(&mut self, job: &str) {
        let of_job: BTreeSet<&str> = self
            .list
            .iter()
            .filter(|i| i.job == job)
            .map(|i| i.id.as_str())
            .chain(
                self.detail
                    .iter()
                    .filter(|i| i.job == job)
                    .map(|i| i.id.as_str()),
            )
            .collect();
        self.fetched.retain(|id| !of_job.contains(id.as_str()));
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
        assert_eq!(confidence_glyphs(Confidence::Certain), "●●");
        assert_eq!(confidence_glyphs(Confidence::Tentative), "○○");
    }
}
