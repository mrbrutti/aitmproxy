//! Issues and their summaries (spec D6). Task 6 of the T1a plan owns this file.
//!
//! An [`Issue`] is the scanner's finding record: a dedupe-stable report of one
//! weakness at one location, carrying its evidence. An [`IssueSummary`] is the
//! same thing with the heavy fields dropped, for the push line and `scan.list`
//! (spec D6, call A12). The severity tally [`BySeverity`] and confidence tally
//! [`ByConfidence`] live here because the issue vocabulary owns them; the job's
//! `IssueCounters` (see [`crate::job`]) reuses them.

use serde::{Deserialize, Serialize};

use aitm_poc::Severity;

use crate::check::Evidence;
use crate::ids::{IssueId, JobId};
use crate::vocab::{Confidence, InsertionKind, IssueStatus, L4Transport, LaneKind};

/// A count of issues by severity (spec D5 `issues.by_severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct BySeverity {
    /// `critical` issues.
    pub critical: u64,
    /// `high` issues.
    pub high: u64,
    /// `medium` issues.
    pub medium: u64,
    /// `low` issues.
    pub low: u64,
    /// `info` issues.
    pub info: u64,
}

impl BySeverity {
    /// Add one issue of severity `s` to the tally.
    pub fn bump(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// A count of issues by confidence (spec D5 `issues.by_confidence`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct ByConfidence {
    /// `certain` issues.
    pub certain: u64,
    /// `firm` issues.
    pub firm: u64,
    /// `tentative` issues.
    pub tentative: u64,
}

impl ByConfidence {
    /// Add one issue of confidence `c` to the tally.
    pub fn bump(&mut self, c: Confidence) {
        match c {
            Confidence::Certain => self.certain += 1,
            Confidence::Firm => self.firm += 1,
            Confidence::Tentative => self.tentative += 1,
        }
    }
}

/// The origin an issue was found on (spec D6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IssueTarget {
    /// The URL scheme (`http`/`https`/`ws`/`wss`).
    pub scheme: String,
    /// The host.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// Where an L4 issue sits, when the issue's lane is `l4_packet`/`l4_stream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L4Location {
    /// The target IP.
    pub ip: String,
    /// The target port.
    pub port: u16,
    /// The transport.
    pub proto: L4Transport,
    /// The grammar the message was built from, when known.
    #[serde(default)]
    pub grammar: Option<String>,
    /// The field path inside the message, when known.
    #[serde(default)]
    pub field_path: Option<String>,
    /// The mutation that provoked the issue, when known.
    #[serde(default)]
    pub mutation: Option<String>,
}

/// The precise location of an issue inside a request (spec D6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IssueLocation {
    /// The request method, when the issue is HTTP/WS.
    #[serde(default)]
    pub method: Option<String>,
    /// The concrete request path.
    pub path: String,
    /// The path with volatile segments templated (`/{id}`, `/{uuid}`, `/{oid}`).
    pub path_template: String,
    /// The insertion kind the issue was found at.
    pub kind: InsertionKind,
    /// The name of the parameter, header, cookie or field.
    pub name: String,
    /// The field path inside a structured body, when applicable.
    #[serde(default)]
    pub field_path: Option<String>,
    /// The WebSocket path, when the issue is on a WS frame.
    #[serde(default)]
    pub ws_path: Option<String>,
    /// The L4 location, when the issue's lane is L4.
    #[serde(default)]
    pub l4: Option<L4Location>,
}

/// A scanner finding: one weakness at one location (spec D6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Issue {
    /// `issue-<8 hex>`, stable for the life of the job.
    pub id: IssueId,
    /// The job that found it.
    pub job: JobId,
    /// The check that reported it.
    pub check_id: String,
    /// The weakness class (`reflected-xss`, `sqli-error`, ...).
    pub class: String,
    /// The human-readable name.
    pub name: String,
    /// The severity (`aitm_poc::Severity`, five levels).
    pub severity: Severity,
    /// How sure the verdict is.
    pub confidence: Confidence,
    /// The triage state.
    pub status: IssueStatus,
    /// The lane the issue belongs to.
    pub lane: LaneKind,
    /// The origin the issue was found on.
    pub target: IssueTarget,
    /// Where the issue sits inside the request.
    pub location: IssueLocation,
    /// The evidence that supports it.
    pub evidence: Evidence,
    /// When the issue was first seen (epoch milliseconds).
    pub first_seen: u64,
    /// When the issue was last seen (epoch milliseconds).
    pub last_seen: u64,
    /// How many times the issue was observed (dedupe raises this).
    pub occurrences: u32,
    /// A reference into the PoC store, when a PoC was built.
    #[serde(default)]
    pub poc_ref: Option<String>,
    /// The linked `FindingRecord` id, when a reproduction passed.
    #[serde(default)]
    pub finding_id: Option<String>,
    /// A description of the weakness.
    pub description: String,
    /// Remediation guidance, when available.
    #[serde(default)]
    pub remediation: Option<String>,
    /// An operator's triage note, when set.
    #[serde(default)]
    pub note: Option<String>,
}

impl Issue {
    /// The summary form for the push line and `scan.list` (call A12): the same
    /// issue minus `evidence`, `description`, `remediation` and `note`.
    pub fn summary(&self) -> IssueSummary {
        IssueSummary {
            id: self.id.clone(),
            job: self.job.clone(),
            check_id: self.check_id.clone(),
            class: self.class.clone(),
            name: self.name.clone(),
            severity: self.severity,
            confidence: self.confidence,
            status: self.status,
            lane: self.lane,
            target: self.target.clone(),
            location: self.location.clone(),
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            occurrences: self.occurrences,
            poc_ref: self.poc_ref.clone(),
            finding_id: self.finding_id.clone(),
        }
    }
}

/// An [`Issue`] minus `evidence`, `description`, `remediation` and `note` (call
/// A12): the shape the push line and `scan.list` carry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IssueSummary {
    /// `issue-<8 hex>`.
    pub id: IssueId,
    /// The job that found it.
    pub job: JobId,
    /// The check that reported it.
    pub check_id: String,
    /// The weakness class.
    pub class: String,
    /// The human-readable name.
    pub name: String,
    /// The severity.
    pub severity: Severity,
    /// How sure the verdict is.
    pub confidence: Confidence,
    /// The triage state.
    pub status: IssueStatus,
    /// The lane the issue belongs to.
    pub lane: LaneKind,
    /// The origin the issue was found on.
    pub target: IssueTarget,
    /// Where the issue sits inside the request.
    pub location: IssueLocation,
    /// When the issue was first seen (epoch milliseconds).
    pub first_seen: u64,
    /// When the issue was last seen (epoch milliseconds).
    pub last_seen: u64,
    /// How many times the issue was observed.
    pub occurrences: u32,
    /// A reference into the PoC store, when a PoC was built.
    #[serde(default)]
    pub poc_ref: Option<String>,
    /// The linked `FindingRecord` id, when a reproduction passed.
    #[serde(default)]
    pub finding_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_issue() -> Issue {
        Issue {
            id: "issue-9f8e7d6c".into(),
            job: "scan-01020304".into(),
            check_id: "reflected-xss".into(),
            class: "reflected-xss".into(),
            name: "Reflected XSS".into(),
            severity: Severity::High,
            confidence: Confidence::Firm,
            status: IssueStatus::Open,
            lane: LaneKind::Http,
            target: IssueTarget {
                scheme: "https".into(),
                host: "t.example".into(),
                port: 443,
            },
            location: IssueLocation {
                method: Some("GET".into()),
                path: "/search".into(),
                path_template: "/search".into(),
                kind: InsertionKind::Query,
                name: "q".into(),
                field_path: None,
                ws_path: None,
                l4: None,
            },
            evidence: Evidence::default(),
            first_seen: 1,
            last_seen: 2,
            occurrences: 1,
            poc_ref: None,
            finding_id: None,
            description: "A payload reflected unescaped.".into(),
            remediation: Some("Encode output.".into()),
            note: None,
        }
    }

    #[test]
    fn issue_summary_has_no_evidence() {
        let issue = sample_issue();
        let summary = issue.summary();
        assert_eq!(summary.id, "issue-9f8e7d6c");

        let json = serde_json::to_string(&summary).expect("serializes");
        assert!(
            !json.contains("evidence"),
            "summary dropped evidence: {json}"
        );
        assert!(
            !json.contains("description"),
            "summary dropped description: {json}"
        );
    }

    #[test]
    fn by_severity_bump() {
        let mut tally = BySeverity::default();
        tally.bump(Severity::High);
        tally.bump(Severity::High);
        tally.bump(Severity::Info);
        assert_eq!(tally.high, 2);
        assert_eq!(tally.info, 1);
        assert_eq!(tally.critical, 0);
    }

    #[test]
    fn by_confidence_bump() {
        let mut tally = ByConfidence::default();
        tally.bump(Confidence::Certain);
        tally.bump(Confidence::Certain);
        tally.bump(Confidence::Tentative);
        assert_eq!(tally.certain, 2);
        assert_eq!(tally.tentative, 1);
        assert_eq!(tally.firm, 0);
    }
}
