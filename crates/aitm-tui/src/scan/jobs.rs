//! The Jobs tab's state (spec D3, D11) and the two text helpers its rows use.

use std::collections::{BTreeMap, BTreeSet};

use aitm_scan_model::{JobId, JobState, JobStatus, JobSummary, ListResult, Phase};

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
