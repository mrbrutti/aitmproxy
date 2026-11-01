//! Verb result types and the job notification line (spec D3). Task 8 of the T1a plan owns this file.
//!
//! One type per scanner verb result, plus [`JobNotification`], the params of the
//! `notifications/aitm/job` push line. Several verbs return a type that already
//! lives in another module and so have no result type here:
//!
//! | Verb | Result |
//! |---|---|
//! | `scan.start`, `scan.map` | [`StartResult`] |
//! | `scan.status`, `scan.cancel` | [`crate::job::JobStatus`] |
//! | `scan.list` | [`ListResult`] |
//! | `scan.issues` | [`IssuesResult`] |
//! | `scan.issue`, `scan.issue.update` | [`crate::issue::Issue`] |
//! | `scan.sitemap` | [`SitemapResult`] |
//! | `scan.checks` | [`ChecksResult`] |
//! | `scan.profile.list` | [`ProfileListResult`] |
//! | `scan.profile.get` | [`crate::profile::ScanProfile`] |
//! | `scan.profile.save` | [`ProfileSaveResult`] |
//! | `scan.profile.delete` | [`ProfileDeleteResult`] |
//! | `scan.session.preview` | [`crate::session::SessionProfile`] |
//!
//! These are the UI-consumed end of the wire (spec D2), so every type here
//! tolerates unknown keys and treats an absent optional key as `None` or empty:
//! a newer core may add a key without breaking an older UI. Timestamps are epoch
//! milliseconds.

use serde::{Deserialize, Serialize};

use crate::check::CheckMeta;
use crate::ids::JobId;
use crate::issue::{BySeverity, IssueSummary};
use crate::job::{Clamped, JobStatus, JobSummary, LaneReport};
use crate::point::{InsertionPoint, SiteNode};
use crate::profile::ScanProfile;
use crate::vocab::{Intensity, LaneKind, Speed};

/// The result of `scan.start` and `scan.map`, returned immediately: the job was
/// accepted, not finished (spec D3).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct StartResult {
    /// The new job's id (`scan-<8 hex>`).
    pub job: JobId,
    /// The job's status at acceptance, normally `state: queued`.
    pub status: JobStatus,
    /// Every profile field the engine clamped to a configured ceiling. Clamping
    /// is not an error (spec D3), so a caller learns about it only from here.
    pub clamped: Vec<Clamped>,
    /// Which lanes were asked for, which run, and why any was skipped. A profile
    /// with one available lane is not refused; the rest are reported here (D1, D5).
    pub lanes: LaneReport,
    /// Present when the profile has an L4 lane: whether the L4 lane only plans
    /// its cases instead of sending them (spec D3, D8.4). `None` means the
    /// profile has no L4 lane, and the key is absent from the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// The result of `scan.list`: the known jobs, newest first.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ListResult {
    /// One summary per retained job (live jobs plus the retained history).
    pub jobs: Vec<JobSummary>,
}

/// The result of `scan.issues`: one page of issues and the tally behind them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct IssuesResult {
    /// The page of issues, in the order the store returned them.
    pub issues: Vec<IssueSummary>,
    /// The cursor to pass back for the next page, or `None` on the last page.
    pub next_cursor: Option<String>,
    /// The severity tally over the whole filtered set, not just this page.
    pub by_severity: BySeverity,
}

/// The result of `scan.sitemap`: the site tree and the insertion points on it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct SitemapResult {
    /// The site nodes in this page.
    pub nodes: Vec<SiteNode>,
    /// The insertion points in this page, at most the requested `limit`.
    pub points: Vec<InsertionPoint>,
    /// The cursor to pass back for the next page, or `None` on the last page.
    pub next_cursor: Option<String>,
}

/// The result of `scan.checks`: the unified catalogue as loaded (spec D4).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ChecksResult {
    /// The checks matching the filter, native and script alike.
    pub checks: Vec<CheckMeta>,
}

/// The result of `scan.profile.list`: every built-in and saved profile.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ProfileListResult {
    /// One entry per profile, built-ins first.
    pub profiles: Vec<ProfileListEntry>,
}

/// One line of `scan.profile.list`: enough to populate a picker without
/// fetching the whole profile tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileListEntry {
    /// The profile's name, the key `scan.profile.get` takes.
    pub name: String,
    /// Whether the profile ships with aitmproxy. A built-in cannot be saved
    /// over or deleted.
    pub builtin: bool,
    /// The three dials a picker shows.
    pub summary: ProfileSummary,
}

/// The three dials that describe a profile at a glance (spec D3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileSummary {
    /// The lanes the profile runs.
    #[serde(default)]
    pub lanes: Vec<LaneKind>,
    /// How invasive the profile is.
    pub intensity: Intensity,
    /// The profile's time-versus-coverage dial.
    pub speed: Speed,
}

impl From<&ScanProfile> for ProfileSummary {
    fn from(profile: &ScanProfile) -> Self {
        Self {
            lanes: profile.lanes.clone(),
            intensity: profile.intensity,
            speed: profile.speed,
        }
    }
}

/// The result of `scan.profile.save`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ProfileSaveResult {
    /// The name the profile was saved under.
    pub saved: String,
    /// Where it was written: `<findings.dir>/scan/profiles/<name>.yaml`.
    pub path: String,
}

/// The result of `scan.profile.delete`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ProfileDeleteResult {
    /// Whether a profile was removed. `false` means there was nothing to delete.
    pub deleted: bool,
}

/// What a [`JobNotification`] reports (spec D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEvent {
    /// The job began running. Never coalesced.
    #[default]
    Started,
    /// The job moved to a new phase. Never coalesced.
    Phase,
    /// Counters advanced. Coalesced to [`MAX_PROGRESS_LINES_PER_SECOND`] per job.
    Progress,
    /// An issue was raised; `issue` carries it. Never coalesced.
    Issue,
    /// The job finished on its own. Terminal, never coalesced.
    Finished,
    /// The job was cancelled. Terminal, never coalesced.
    Cancelled,
    /// The job stopped on an error; `status.state` is `failed`. Terminal.
    Failed,
}

/// The params of a `notifications/aitm/job` push line (spec D3).
///
/// Push is a trigger, not the truth: a UI refreshes from `scan.status` and
/// `scan.issues` when a line arrives and never reconstructs job state from the
/// lines alone, because `progress` lines are coalesced and a late subscriber
/// misses the earlier ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct JobNotification {
    /// The job the line belongs to.
    pub job: JobId,
    /// The job kind, [`JOB_KIND_SCAN`] for a scan. The notification is generic
    /// over job kinds (spec D9), so a client filters on this.
    pub kind: String,
    /// What happened.
    pub event: JobEvent,
    /// The line's sequence number inside the job, starting at 1 and strictly
    /// increasing. A gap means a coalesced or missed line.
    pub seq: u64,
    /// When the line was emitted (epoch milliseconds).
    pub ts_ms: u64,
    /// The job's summary counters at that moment.
    pub status: JobSummary,
    /// The issue, on an [`JobEvent::Issue`] line only. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue: Option<IssueSummary>,
}

/// The method of the job progress push line (spec D3).
pub const JOB_NOTIFICATION_METHOD: &str = "notifications/aitm/job";

/// The [`JobNotification::kind`] a scanner job uses.
pub const JOB_KIND_SCAN: &str = "scan";

/// How many [`JobEvent::Progress`] lines a job may emit per second. The engine
/// coalesces the rest; `started`, `phase`, `issue` and the terminal events are
/// never coalesced (spec D3).
pub const MAX_PROGRESS_LINES_PER_SECOND: u32 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::issue::{IssueLocation, IssueSummary, IssueTarget};
    use crate::job::{JobState, JobStatus, Phase, SkippedLane};
    use crate::profile::builtin;
    use crate::vocab::{Confidence, InsertionKind, Intensity, IssueStatus, LaneKind, Speed};

    fn issue_summary() -> IssueSummary {
        IssueSummary {
            id: "issue-9f8e7d6c".to_string(),
            job: "scan-1a2b3c4d".to_string(),
            check_id: "http.reflected-xss".to_string(),
            class: "reflected-xss".to_string(),
            name: "Reflected cross-site scripting".to_string(),
            severity: aitm_poc::Severity::High,
            confidence: Confidence::Certain,
            status: IssueStatus::Open,
            lane: LaneKind::Http,
            target: IssueTarget {
                scheme: "http".to_string(),
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            location: IssueLocation {
                method: Some("GET".to_string()),
                path: "/search".to_string(),
                path_template: "/search".to_string(),
                kind: InsertionKind::Query,
                name: "q".to_string(),
                field_path: None,
                ws_path: None,
                l4: None,
            },
            first_seen: 1_761_900_000_000,
            last_seen: 1_761_900_000_000,
            occurrences: 1,
            poc_ref: None,
            finding_id: None,
        }
    }

    #[test]
    fn start_result_round_trips_with_skipped_lane() {
        let result = StartResult {
            job: "scan-1a2b3c4d".to_string(),
            status: JobStatus {
                state: JobState::Queued,
                ..JobStatus::default()
            },
            clamped: vec![Clamped {
                field: "budget.probes".to_string(),
                requested: 50_000,
                applied: 20_000,
            }],
            lanes: LaneReport {
                requested: vec![LaneKind::Http, LaneKind::Ws],
                run: vec![LaneKind::Http],
                skipped: vec![SkippedLane {
                    lane: LaneKind::Ws,
                    reason: "lane not available on this build".to_string(),
                }],
            },
            dry_run: None,
        };

        let json = serde_json::to_string(&result).expect("serializes");
        assert!(
            json.contains(
                r#""skipped":[{"lane":"ws","reason":"lane not available on this build"}]"#
            ),
            "skipped lane on the wire: {json}"
        );

        let back: StartResult = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, result);
    }

    #[test]
    fn dry_run_is_absent_unless_set() {
        let plain = StartResult::default();
        let json = serde_json::to_string(&plain).expect("serializes");
        assert!(!json.contains("dry_run"), "no dry_run key: {json}");

        let l4 = StartResult {
            dry_run: Some(false),
            ..StartResult::default()
        };
        let json = serde_json::to_string(&l4).expect("serializes");
        assert!(json.contains(r#""dry_run":false"#), "dry_run key: {json}");
        let back: StartResult = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.dry_run, Some(false));
    }

    #[test]
    fn job_event_tokens() {
        assert_eq!(
            serde_json::to_string(&JobEvent::Progress).expect("serializes"),
            "\"progress\""
        );
        assert_eq!(
            serde_json::to_string(&JobEvent::Finished).expect("serializes"),
            "\"finished\""
        );
        assert_eq!(
            serde_json::from_str::<JobEvent>("\"cancelled\"").expect("deserializes"),
            JobEvent::Cancelled
        );
    }

    #[test]
    fn notification_round_trips() {
        assert_eq!(JOB_NOTIFICATION_METHOD, "notifications/aitm/job");
        assert_eq!(JOB_KIND_SCAN, "scan");
        assert_eq!(MAX_PROGRESS_LINES_PER_SECOND, 4);

        let mut status = JobStatus {
            state: JobState::Running,
            phase: Phase::Auditing,
            ..JobStatus::default()
        };
        status.issues.total = 1;

        let line = JobNotification {
            job: "scan-1a2b3c4d".to_string(),
            kind: JOB_KIND_SCAN.to_string(),
            event: JobEvent::Issue,
            seq: 7,
            ts_ms: 1_761_900_000_000,
            status: status.summary(),
            issue: Some(issue_summary()),
        };

        let json = serde_json::to_string(&line).expect("serializes");
        assert!(json.contains(r#""event":"issue""#), "event token: {json}");
        assert!(json.contains(r#""seq":7"#), "seq: {json}");

        let back: JobNotification = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, line);
        assert_eq!(back.issue.expect("issue carried").id, "issue-9f8e7d6c");
    }

    #[test]
    fn notification_without_issue_omits_the_key() {
        let line = JobNotification {
            job: "scan-1a2b3c4d".to_string(),
            kind: JOB_KIND_SCAN.to_string(),
            event: JobEvent::Started,
            seq: 1,
            ts_ms: 1_761_900_000_000,
            status: JobStatus::default().summary(),
            issue: None,
        };

        let json = serde_json::to_string(&line).expect("serializes");
        assert!(!json.contains("\"issue\""), "no issue key: {json}");
        let back: JobNotification = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.issue, None);
    }

    #[test]
    fn profile_summary_from_standard() {
        let standard = builtin("standard").expect("standard is built in");
        assert_eq!(
            ProfileSummary::from(&standard),
            ProfileSummary {
                lanes: vec![LaneKind::Http, LaneKind::Ws],
                intensity: Intensity::Medium,
                speed: Speed::Normal,
            }
        );
    }

    #[test]
    fn issues_result_tolerates_missing_cursor() {
        let parsed: IssuesResult =
            serde_json::from_str(r#"{"issues":[],"by_severity":{}}"#).expect("deserializes");
        assert_eq!(parsed.next_cursor, None);
        assert_eq!(parsed.by_severity, BySeverity::default());
        assert!(parsed.issues.is_empty());
    }

    #[test]
    fn results_tolerate_unknown_keys() {
        let checks: ChecksResult =
            serde_json::from_str(r#"{"checks":[],"total":0}"#).expect("unknown keys ignored");
        assert!(checks.checks.is_empty());

        let deleted: ProfileDeleteResult =
            serde_json::from_str(r#"{"deleted":true,"path":"x"}"#).expect("unknown keys ignored");
        assert!(deleted.deleted);
    }

    #[test]
    fn list_sitemap_and_profile_results_round_trip() {
        let list = ListResult {
            jobs: vec![JobStatus::default().summary()],
        };
        let json = serde_json::to_string(&list).expect("serializes");
        assert_eq!(
            serde_json::from_str::<ListResult>(&json).expect("deserializes"),
            list
        );

        let sitemap = SitemapResult {
            nodes: Vec::new(),
            points: Vec::new(),
            next_cursor: Some("node-42".to_string()),
        };
        let json = serde_json::to_string(&sitemap).expect("serializes");
        assert!(
            json.contains(r#""next_cursor":"node-42""#),
            "cursor: {json}"
        );
        assert_eq!(
            serde_json::from_str::<SitemapResult>(&json).expect("deserializes"),
            sitemap
        );

        let listing = ProfileListResult {
            profiles: vec![ProfileListEntry {
                name: "standard".to_string(),
                builtin: true,
                summary: ProfileSummary::from(&builtin("standard").expect("built in")),
            }],
        };
        let json = serde_json::to_string(&listing).expect("serializes");
        assert!(json.contains(r#""builtin":true"#), "builtin flag: {json}");
        assert_eq!(
            serde_json::from_str::<ProfileListResult>(&json).expect("deserializes"),
            listing
        );

        let saved = ProfileSaveResult {
            saved: "my-api".to_string(),
            path: "/tmp/findings/scan/profiles/my-api.yaml".to_string(),
        };
        let json = serde_json::to_string(&saved).expect("serializes");
        assert_eq!(
            serde_json::from_str::<ProfileSaveResult>(&json).expect("deserializes"),
            saved
        );
    }

    #[test]
    fn issues_result_carries_severity_tally() {
        let mut by_severity = BySeverity::default();
        by_severity.bump(aitm_poc::Severity::High);
        let result = IssuesResult {
            issues: vec![issue_summary()],
            next_cursor: Some("issue-9f8e7d6c".to_string()),
            by_severity,
        };

        let json = serde_json::to_string(&result).expect("serializes");
        assert!(json.contains(r#""high":1"#), "tally on the wire: {json}");
        assert_eq!(
            serde_json::from_str::<IssuesResult>(&json).expect("deserializes"),
            result
        );
    }
}
