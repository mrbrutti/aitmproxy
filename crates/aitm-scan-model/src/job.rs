//! Job state, phases and counters (spec D5). Task 6 of the T1a plan owns this file.
//!
//! [`JobStatus`] is the whole live view of a scan: its state and phase, every
//! monotonic counter, the lane report and the clamp log. [`JobSummary`] is the
//! trimmed view the push line and `scan.list` carry (call A11): the same counter
//! structs, dropping the heavy per-phase detail.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::issue::{ByConfidence, BySeverity};
use crate::session::Canary;
use crate::vocab::LaneKind;

/// A job's coarse lifecycle state (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Accepted, not yet running.
    #[default]
    Queued,
    /// Running.
    Running,
    /// A cancel was requested; the worker is winding down.
    Cancelling,
    /// Finished normally.
    Done,
    /// Stopped by a cancel.
    Cancelled,
    /// Stopped by an error.
    Failed,
}

impl JobState {
    /// Whether the job has reached a terminal state (no further transition).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobState::Done | JobState::Cancelled | JobState::Failed
        )
    }
}

/// The worker phase a running job is in (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Before the worker starts.
    #[default]
    Queued,
    /// Crawling the target.
    Crawling,
    /// Running passive checks over captured flows.
    Passive,
    /// Auditing insertion points with active checks.
    Auditing,
    /// Writing results.
    Reporting,
    /// Finished.
    Done,
}

/// Why a job stopped before completing every planned probe (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoppedReason {
    /// The probe budget was spent.
    Budget,
    /// The time budget was spent.
    Time,
    /// The job was cancelled.
    Cancelled,
    /// The session stopped working and `on_lost` is `stop`.
    SessionLost,
    /// The per-host error ladder tripped.
    Errors,
    /// Agent policy turned `paused`/`read_only`.
    Policy,
    /// The L4 guard refused a target mid-run.
    GuardRefused,
    /// An unexpected error ended the job.
    Failed,
}

/// Who started the job (spec D5): the frontend name and an optional client label.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct StartedBy {
    /// The lowercase `aitm_core::Frontend` name (`cli`/`mcp`/`operator`).
    pub frontend: String,
    /// The bus client label, when one was given.
    pub client_label: Option<String>,
}

/// Probe-budget and per-lane probe counters (spec D5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ProbeCounters {
    /// Probes sent so far.
    pub sent: u64,
    /// The probe budget for the whole job.
    pub budget: u64,
    /// Probes that errored.
    pub errors: u64,
    /// Probes that timed out.
    pub timeouts: u64,
    /// Times the job waited on a rate limit instead of aborting.
    pub rate_waits: u64,
    /// Probes sent per lane.
    pub by_lane: BTreeMap<LaneKind, u64>,
}

/// Crawler counters (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct CrawlCounters {
    /// Pages fetched.
    pub pages: u64,
    /// Pages still queued.
    pub queued: u64,
    /// The deepest level reached.
    pub depth: u32,
    /// Forms submitted.
    pub forms_submitted: u64,
}

/// Insertion-point counters (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct PointCounters {
    /// Points found.
    pub found: u64,
    /// Points queued for audit.
    pub queued: u64,
    /// Points audited.
    pub audited: u64,
    /// Points skipped, by reason.
    pub skipped: SkippedPoints,
}

/// Why insertion points were skipped (spec D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct SkippedPoints {
    /// Ignored by an `audit.ignore` rule (e.g. the `session` trait).
    pub ignored: u64,
    /// Dropped because the value recurs too often to be interesting.
    pub frequent: u64,
    /// Dropped by the per-request cap.
    pub limit: u64,
}

/// Check-scheduling counters (spec D5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct CheckCounters {
    /// Checks scheduled.
    pub scheduled: u64,
    /// Checks finished.
    pub done: u64,
    /// The ids of the checks running right now (bounded to 8 by the engine).
    pub running: Vec<String>,
}

/// Issue counters (spec D5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct IssueCounters {
    /// Total issues found.
    pub total: u64,
    /// Issues by severity.
    pub by_severity: BySeverity,
    /// Issues by confidence.
    pub by_confidence: ByConfidence,
}

/// L4 fuzzing counters (spec D5), present only when an L4 lane ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct L4Counters {
    /// Cases sent.
    pub cases: u64,
    /// Crashes observed.
    pub crashes: u64,
    /// Liveness probes that failed.
    pub liveness_failures: u64,
    /// Elements retired after repeated crashes.
    pub retired_elements: u64,
}

/// The session's live status (spec D5), present only in observed-session mode.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct SessionStatus {
    /// Whether an observed session was reused.
    pub reused: bool,
    /// Whether the session was lost mid-run.
    pub lost: bool,
    /// The auth-lost canary in force.
    pub canary: Canary,
    /// Whether an HttpOnly session cookie kept the browser crawl partial.
    pub browser_partial: bool,
}

/// Which lanes were requested, which ran, and which were skipped (spec D1/D3/D5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct LaneReport {
    /// The lanes the profile asked for.
    pub requested: Vec<LaneKind>,
    /// The lanes that actually ran.
    pub run: Vec<LaneKind>,
    /// The lanes that were skipped, with a reason.
    pub skipped: Vec<SkippedLane>,
}

/// A skipped lane and why (spec D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SkippedLane {
    /// The lane that was skipped.
    pub lane: LaneKind,
    /// Why it was skipped (e.g. `lane not built`).
    pub reason: String,
}

/// A value the engine clamped to a configured ceiling (spec D1/D3/D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Clamped {
    /// The field that was clamped (e.g. `probes`).
    pub field: String,
    /// The value that was asked for.
    pub requested: u64,
    /// The value that was applied.
    pub applied: u64,
}

/// The whole live view of a scan job (spec D5).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct JobStatus {
    /// `scan-<8 hex>`.
    pub job: crate::ids::JobId,
    /// The coarse lifecycle state.
    pub state: JobState,
    /// The worker phase.
    pub phase: Phase,
    /// The resolved profile's name.
    pub profile_name: String,
    /// The targets the job runs against.
    pub targets: Vec<String>,
    /// Who started the job.
    pub started_by: StartedBy,
    /// When the job started (epoch milliseconds).
    pub started_at: u64,
    /// When the job finished (epoch milliseconds), when terminal.
    pub finished_at: Option<u64>,
    /// Elapsed wall time in milliseconds.
    pub elapsed_ms: u64,
    /// Why the job stopped, when it stopped early.
    pub stopped_reason: Option<StoppedReason>,
    /// Probe counters.
    pub probes: ProbeCounters,
    /// Crawler counters.
    pub crawl: CrawlCounters,
    /// Insertion-point counters.
    pub points: PointCounters,
    /// Check counters.
    pub checks: CheckCounters,
    /// Issue counters.
    pub issues: IssueCounters,
    /// L4 counters, when an L4 lane ran.
    pub l4: Option<L4Counters>,
    /// Session status, in observed-session mode.
    pub session: Option<SessionStatus>,
    /// The lane report.
    pub lanes: LaneReport,
    /// Values clamped to a ceiling.
    pub clamped: Vec<Clamped>,
    /// A terminal error message, when the job failed.
    pub error: Option<String>,
}

impl JobStatus {
    /// The summary view for the push line and `scan.list` (call A11): the whole
    /// `probes`/`points`/`issues` counter structs, dropping the per-phase detail.
    pub fn summary(&self) -> JobSummary {
        JobSummary {
            job: self.job.clone(),
            state: self.state,
            phase: self.phase,
            elapsed_ms: self.elapsed_ms,
            probes: self.probes.clone(),
            points: self.points,
            issues: self.issues.clone(),
        }
    }
}

/// The trimmed job view the push line and `scan.list` carry (call A11).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct JobSummary {
    /// `scan-<8 hex>`.
    pub job: crate::ids::JobId,
    /// The coarse lifecycle state.
    pub state: JobState,
    /// The worker phase.
    pub phase: Phase,
    /// Elapsed wall time in milliseconds.
    pub elapsed_ms: u64,
    /// Probe counters.
    pub probes: ProbeCounters,
    /// Insertion-point counters.
    pub points: PointCounters,
    /// Issue counters.
    pub issues: IssueCounters,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_status_default_round_trips() {
        let status = JobStatus::default();
        let json = serde_json::to_string(&status).expect("serializes");
        let back: JobStatus = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, status);
    }

    #[test]
    fn by_lane_keys_are_lane_tokens() {
        let mut status = JobStatus::default();
        status.probes.by_lane.insert(LaneKind::Http, 400);
        status.probes.by_lane.insert(LaneKind::Ws, 18);

        let json = serde_json::to_string(&status).expect("serializes");
        assert!(
            json.contains(r#""by_lane":{"http":400,"ws":18}"#),
            "by_lane tokens: {json}"
        );

        let back: JobStatus = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, status);
    }

    #[test]
    fn summary_drops_crawl_and_keeps_counters() {
        let mut status = JobStatus::default();
        status.probes.sent = 42;
        let summary = status.summary();
        assert_eq!(summary.probes.sent, 42);

        let json = serde_json::to_string(&summary).expect("serializes");
        assert!(!json.contains("crawl"), "summary dropped crawl: {json}");
        assert!(
            !json.contains("started_by"),
            "summary dropped started_by: {json}"
        );
    }

    #[test]
    fn terminal_states() {
        assert!(JobState::Done.is_terminal());
        assert!(JobState::Cancelled.is_terminal());
        assert!(JobState::Failed.is_terminal());
        assert!(!JobState::Queued.is_terminal());
        assert!(!JobState::Running.is_terminal());
        assert!(!JobState::Cancelling.is_terminal());
    }
}
