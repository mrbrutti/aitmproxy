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

/// Why every request of an all-failing client crawl failed (spec D5,
/// amendment 39). A closed token on [`CrawlCounters::last_error`]: a crawl that
/// made at least one request and had every one fail (no page fetched) says why,
/// so the job can run its passive checks over what it still has ("degrade, do
/// not fail") and a frontend can still name the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlErrorKind {
    /// A forced `h2` against an h1-only listener (amendment 21's counted probe
    /// error `h2_not_negotiated`).
    H2NotNegotiated,
    /// The connection was refused.
    ConnectRefused,
    /// A TLS handshake or certificate failure.
    Tls,
    /// The probe timed out.
    Timeout,
    /// Any other connect or transport failure.
    Transport,
    /// A free-text browser-crawl failure that is not one of the tokens above.
    Other,
}

impl CrawlErrorKind {
    /// The wire token for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H2NotNegotiated => "h2_not_negotiated",
            Self::ConnectRefused => "connect_refused",
            Self::Tls => "tls",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Other => "other",
        }
    }

    /// The kind for an exact token, or `None` for free text (no heuristics).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "h2_not_negotiated" => Some(Self::H2NotNegotiated),
            "connect_refused" => Some(Self::ConnectRefused),
            "tls" => Some(Self::Tls),
            "timeout" => Some(Self::Timeout),
            "transport" => Some(Self::Transport),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
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
    /// Crawls that failed outright (a browser crawl that timed out or was
    /// refused), counted so a job that fell back to captured flows or the client
    /// crawl says so instead of silently running on fewer points (additive,
    /// 2026-11-01; absent on the wire means 0).
    pub errors: u64,
    /// Forms the crawl deliberately did not submit: logout-looking and
    /// destructive-looking (action path or field name containing `delete`,
    /// `remove`, `destroy`, `password`, `transfer`, `pay`, `purchase`,
    /// `unsubscribe`, `confirm`). Additive, 2026-11-01; absent on the wire
    /// means 0.
    pub forms_skipped: u64,
    /// Why an all-failing client crawl failed: set only when the crawl made at
    /// least one request and every one failed (`errors > 0 && pages == 0`), so
    /// a frontend can name the cause (amendment 39). Additive, 2026-11-01;
    /// absent on the wire means none.
    pub last_error: Option<CrawlErrorKind>,
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
    /// Check runs that ended in an `error` verdict — the check could not say
    /// whether the point is vulnerable (a missing runner, a refused budget, a
    /// panic). Additive (amendment 58): absent on an older record, read as 0.
    pub errors: u64,
    /// The first [`MAX_CHECK_ERROR_SAMPLES`] distinct `(check, detail)` error
    /// pairs of the job, so an operator sees *why* a lane was inert instead
    /// of a bare counter. Additive (amendment 58): absent, read as empty.
    pub error_samples: Vec<CheckErrorSample>,
}

/// The most entries `CheckCounters.error_samples` keeps per job (amendment
/// 58). Distinct `(check, detail)` pairs past the cap are counted in
/// `checks.errors` but not sampled.
pub const MAX_CHECK_ERROR_SAMPLES: usize = 8;

/// One sampled `error` verdict (amendment 58): which check, the first point it
/// failed on, and its detail — scrubbed and bounded like an evidence excerpt
/// by the engine before it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct CheckErrorSample {
    /// The check's id (`CheckMeta.id`).
    pub check: String,
    /// The id of the first insertion point the pair was seen on.
    pub point: String,
    /// The verdict's detail, scrubbed and cut to an excerpt.
    pub detail: String,
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
    /// The field that was clamped, as the dotted profile path, e.g. `budget.probes`.
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

    /// Panel Q4 — the summary is structurally the status minus exactly the
    /// per-phase detail: every surviving key carries the same value, and no
    /// key is added.
    /// Additive crawl counters (2026-11-01): `errors` and `forms_skipped`
    /// default to 0 when absent on the wire, so an older frontend's record or
    /// a lane that never reports them still parses; both serialize by name.
    #[test]
    fn crawl_counters_additive_fields_default_to_zero() {
        let old: CrawlCounters =
            serde_json::from_str(r#"{"pages":3,"queued":0,"depth":1,"forms_submitted":2}"#)
                .expect("a record without the additive fields parses");
        assert_eq!(
            old,
            CrawlCounters {
                pages: 3,
                depth: 1,
                forms_submitted: 2,
                ..CrawlCounters::default()
            }
        );
        assert_eq!(old.errors, 0);
        assert_eq!(old.forms_skipped, 0);

        let json = serde_json::to_value(CrawlCounters {
            forms_skipped: 4,
            errors: 1,
            ..CrawlCounters::default()
        })
        .expect("serializes");
        assert_eq!(json["forms_skipped"], 4);
        assert_eq!(json["errors"], 1);
    }

    /// Amendment 58: `checks.errors` and `checks.error_samples` are additive
    /// — a record written before them parses to 0 / empty — and a sample
    /// round-trips by name with its three fields.
    #[test]
    fn check_counters_additive_fields_default_to_zero() {
        let old: CheckCounters = serde_json::from_str(r#"{"scheduled":4,"done":4,"running":[]}"#)
            .expect("a record without the additive fields parses");
        assert_eq!(
            old,
            CheckCounters {
                scheduled: 4,
                done: 4,
                ..CheckCounters::default()
            }
        );
        assert_eq!(old.errors, 0);
        assert!(old.error_samples.is_empty());

        let json = serde_json::to_value(CheckCounters {
            errors: 2,
            error_samples: vec![CheckErrorSample {
                check: "http.xss".into(),
                point: "p1".into(),
                detail: "runner missing".into(),
            }],
            ..CheckCounters::default()
        })
        .expect("serializes");
        assert_eq!(json["errors"], 2);
        assert_eq!(json["error_samples"][0]["check"], "http.xss");
        assert_eq!(json["error_samples"][0]["point"], "p1");
        assert_eq!(json["error_samples"][0]["detail"], "runner missing");
        assert_eq!(MAX_CHECK_ERROR_SAMPLES, 8);
    }

    #[test]
    fn summary_is_the_status_minus_the_detail_fields() {
        let status = JobStatus {
            job: "scan-1a2b3c4d".into(),
            state: JobState::Running,
            phase: Phase::Auditing,
            elapsed_ms: 4321,
            profile_name: "standard".into(),
            probes: ProbeCounters {
                sent: 42,
                by_lane: BTreeMap::from([(LaneKind::Http, 42)]),
                ..ProbeCounters::default()
            },
            points: PointCounters {
                found: 7,
                ..PointCounters::default()
            },
            issues: IssueCounters {
                total: 2,
                ..IssueCounters::default()
            },
            crawl: CrawlCounters {
                pages: 9,
                ..CrawlCounters::default()
            },
            ..JobStatus::default()
        };

        let mut full = serde_json::to_value(&status).expect("status serializes");
        let object = full.as_object_mut().expect("status is a JSON object");
        for dropped in [
            "profile_name",
            "targets",
            "started_by",
            "started_at",
            "finished_at",
            "stopped_reason",
            "crawl",
            "checks",
            "l4",
            "session",
            "lanes",
            "clamped",
            "error",
        ] {
            assert!(
                object.remove(dropped).is_some(),
                "the status carries `{dropped}`"
            );
        }
        let summary = serde_json::to_value(status.summary()).expect("summary serializes");
        assert_eq!(full, summary);
    }

    /// Amendment 39: the crawl's all-failed reason is a closed token on
    /// `crawl.last_error`. `parse` is an exact token match (no heuristics), its
    /// inverse `as_str` is the wire token, a free-text browser reason parses to
    /// `None`, and the field round-trips as that token while an old record
    /// without it loads as `None`.
    #[test]
    fn crawl_error_kind_parses_exact_tokens_and_round_trips() {
        assert_eq!(
            CrawlErrorKind::parse("h2_not_negotiated"),
            Some(CrawlErrorKind::H2NotNegotiated)
        );
        assert_eq!(
            CrawlErrorKind::parse("connect_refused"),
            Some(CrawlErrorKind::ConnectRefused)
        );
        assert_eq!(
            CrawlErrorKind::parse("timeout"),
            Some(CrawlErrorKind::Timeout)
        );
        assert_eq!(CrawlErrorKind::parse("tls"), Some(CrawlErrorKind::Tls));
        assert_eq!(
            CrawlErrorKind::parse("transport"),
            Some(CrawlErrorKind::Transport)
        );
        assert_eq!(CrawlErrorKind::parse("other"), Some(CrawlErrorKind::Other));
        assert_eq!(CrawlErrorKind::parse("the browser refused the seed"), None);
        assert_eq!(
            CrawlErrorKind::H2NotNegotiated.as_str(),
            "h2_not_negotiated"
        );
        assert_eq!(CrawlErrorKind::ConnectRefused.as_str(), "connect_refused");

        let json = serde_json::to_value(CrawlCounters {
            last_error: Some(CrawlErrorKind::Timeout),
            ..CrawlCounters::default()
        })
        .expect("serializes");
        assert_eq!(json["last_error"], "timeout");

        let old: CrawlCounters =
            serde_json::from_str(r#"{"pages":1}"#).expect("a record without last_error parses");
        assert_eq!(old.last_error, None);
        assert_eq!(old.pages, 1);
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
