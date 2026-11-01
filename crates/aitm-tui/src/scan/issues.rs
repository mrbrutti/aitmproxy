//! The Issues tab's state (spec D3, D11): the grouped list, its filters and
//! the open issue.

use aitm_scan_model::{BySeverity, Confidence, Issue, IssueStatus, IssueSummary, JobId, LaneKind};

use super::ScanError;
use crate::model::Severity;

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
/// `severity_min` is the TUI's own [`crate::model::Severity`] (the same five
/// levels, in `aitm-poc`'s order and names): the wire type is
/// `aitm_poc::Severity`, which `aitm-scan-model` does not re-export, and the
/// plan admits no dependency beyond `aitm-scan-model`; the filter is serialised
/// through `Severity::label` (builder's decision).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssueFilters {
    pub severity_min: Option<Severity>,
    pub confidence_min: Option<Confidence>,
    pub lane: Option<LaneKind>,
    pub status: Option<IssueStatus>,
    pub job: Option<JobId>,
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
    /// The tick of the last `scan.issues` request.
    pub fetched_at_tick: u64,
    /// This tab's last error.
    pub error: Option<ScanError>,
}
