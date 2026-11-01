//! The Jobs tab's state (spec D3, D11) and the two text helpers its rows use.

use std::collections::BTreeMap;

use aitm_scan_model::{JobId, JobState, JobStatus, JobSummary, Phase};

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
    /// `scan.list`'s order (newest first); jobs this TUI started are inserted
    /// at the front until the next list.
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

/// The row's `state/phase` cell: a non-terminal job reads
/// `<state>/<short phase>`, a terminal one its state alone.
pub fn state_phase_text(state: JobState, phase: Phase) -> String {
    let state_text = match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Cancelling => "cancelling",
        JobState::Done => "done",
        JobState::Cancelled => "cancelled",
        JobState::Failed => "failed",
    };
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

    #[test]
    fn elapsed_rounds_down_to_whole_seconds() {
        assert_eq!(elapsed_text(0), "0s");
        assert_eq!(elapsed_text(999), "0s");
        assert_eq!(elapsed_text(60_000), "1m00s");
        assert_eq!(elapsed_text(3_600_000), "1h00m");
    }
}
