//! The finding record, its query filter/summary, and the on-disk serde mirror.
//!
//! [`FindingRecord`] and its two helper structs copy the spec/plan field list
//! exactly. They are not `serde`-derived directly: `FlowId`, `Frontend` and
//! `SystemTime` have no (or no human-friendly) serde form, so a private
//! [`StoredRecord`] mirror carries the on-disk shape — `origin` as `cli|mcp|operator`,
//! timestamps as RFC 3339, flow ids and the capture as their string form — and the
//! two `From`/`TryFrom` conversions bridge it. Keeping the mirror private means the
//! public record stays the declared shape while the YAML on disk stays readable.

use std::time::SystemTime;

use aitm_core::{FlowId, Frontend};
use aitm_poc::Severity;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A persisted finding: what was found, where, how it reproduces, and the
/// artifacts that back it. Fields are the spec/plan list, copied exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingRecord {
    pub id: String,
    pub title: String,
    pub class: String,
    pub severity: Severity,
    pub target: String,
    pub discovered_at: SystemTime,
    pub origin: Frontend,
    pub client_label: Option<String>,
    pub poc_ref: String,
    pub reproduction: Reproduction,
    pub artifacts: FindingArtifacts,
    pub flows: Vec<FlowId>,
    pub notes: Option<String>,
}

/// The reproduction outcome the grader scores: a finding is found-and-reproduced
/// iff `passed && control_passed == Some(false)` (passes on the vulnerable path,
/// fails on the patched control).
#[derive(Debug, Clone, PartialEq)]
pub struct Reproduction {
    pub passed: bool,
    pub control_passed: Option<bool>,
    pub run_at: SystemTime,
}

/// The three artifacts a recorded finding references.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingArtifacts {
    pub finding_capture: FlowId,
    pub poc_path: String,
    pub screenshot_path: String,
}

/// A list-view projection of a [`FindingRecord`] — the fields a "Findings" page or
/// the agent needs to triage without reading the whole record.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub class: String,
    pub severity: Severity,
    pub target: String,
    pub discovered_at: SystemTime,
    pub origin: Frontend,
    pub poc_ref: String,
    pub passed: bool,
    pub control_passed: Option<bool>,
}

impl FindingSummary {
    /// Project a record into its list-view summary.
    pub fn of(r: &FindingRecord) -> Self {
        Self {
            id: r.id.clone(),
            title: r.title.clone(),
            class: r.class.clone(),
            severity: r.severity,
            target: r.target.clone(),
            discovered_at: r.discovered_at,
            origin: r.origin,
            poc_ref: r.poc_ref.clone(),
            passed: r.reproduction.passed,
            control_passed: r.reproduction.control_passed,
        }
    }
}

/// A `findings.list` filter. An unset field matches everything; set fields are
/// ANDed. `since` keeps findings discovered at or after the instant.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FindingFilter {
    pub target: Option<String>,
    pub class: Option<String>,
    pub severity: Option<Severity>,
    pub since: Option<SystemTime>,
}

impl FindingFilter {
    /// Whether `r` passes every set field of the filter.
    pub fn matches(&self, r: &FindingRecord) -> bool {
        if let Some(t) = &self.target {
            if &r.target != t {
                return false;
            }
        }
        if let Some(c) = &self.class {
            if &r.class != c {
                return false;
            }
        }
        if let Some(s) = self.severity {
            if r.severity != s {
                return false;
            }
        }
        if let Some(since) = self.since {
            if r.discovered_at < since {
                return false;
            }
        }
        true
    }
}

/// `Frontend` → the stable on-disk string. Fail-closed to the agent role for any
/// future variant (`Frontend` is `#[non_exhaustive]`).
pub(crate) fn origin_str(f: Frontend) -> &'static str {
    match f {
        Frontend::Cli => "cli",
        Frontend::Operator => "operator",
        Frontend::Mcp => "mcp",
        _ => "mcp",
    }
}

/// The on-disk string → `Frontend`; anything unrecognised is the agent role.
fn origin_from(s: &str) -> Frontend {
    match s {
        "cli" => Frontend::Cli,
        "operator" => Frontend::Operator,
        _ => Frontend::Mcp,
    }
}

pub(crate) fn fmt_time(t: SystemTime) -> String {
    OffsetDateTime::from(t)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub(crate) fn parse_time(s: &str) -> anyhow::Result<SystemTime> {
    Ok(SystemTime::from(OffsetDateTime::parse(s, &Rfc3339)?))
}

/// The human-readable on-disk mirror of one finding. Private: the public API is
/// [`FindingRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredRecord {
    pub id: String,
    pub title: String,
    pub class: String,
    pub severity: Severity,
    pub target: String,
    pub discovered_at: String,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_label: Option<String>,
    pub poc_ref: String,
    pub reproduction: StoredReproduction,
    pub artifacts: StoredArtifacts,
    #[serde(default)]
    pub flows: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredReproduction {
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_passed: Option<bool>,
    pub run_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredArtifacts {
    pub finding_capture: String,
    pub poc_path: String,
    pub screenshot_path: String,
}

impl From<&FindingRecord> for StoredRecord {
    fn from(r: &FindingRecord) -> Self {
        Self {
            id: r.id.clone(),
            title: r.title.clone(),
            class: r.class.clone(),
            severity: r.severity,
            target: r.target.clone(),
            discovered_at: fmt_time(r.discovered_at),
            origin: origin_str(r.origin).to_string(),
            client_label: r.client_label.clone(),
            poc_ref: r.poc_ref.clone(),
            reproduction: StoredReproduction {
                passed: r.reproduction.passed,
                control_passed: r.reproduction.control_passed,
                run_at: fmt_time(r.reproduction.run_at),
            },
            artifacts: StoredArtifacts {
                finding_capture: r.artifacts.finding_capture.to_string(),
                poc_path: r.artifacts.poc_path.clone(),
                screenshot_path: r.artifacts.screenshot_path.clone(),
            },
            flows: r.flows.iter().map(|f| f.to_string()).collect(),
            notes: r.notes.clone(),
        }
    }
}

impl TryFrom<StoredRecord> for FindingRecord {
    type Error = anyhow::Error;

    fn try_from(s: StoredRecord) -> Result<Self, Self::Error> {
        let flows = s
            .flows
            .iter()
            .map(|f| f.parse::<FlowId>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid flow id in record: {e}"))?;
        let finding_capture = s
            .artifacts
            .finding_capture
            .parse::<FlowId>()
            .map_err(|e| anyhow::anyhow!("invalid finding_capture id: {e}"))?;
        Ok(FindingRecord {
            id: s.id,
            title: s.title,
            class: s.class,
            severity: s.severity,
            target: s.target,
            discovered_at: parse_time(&s.discovered_at)?,
            origin: origin_from(&s.origin),
            client_label: s.client_label,
            poc_ref: s.poc_ref,
            reproduction: Reproduction {
                passed: s.reproduction.passed,
                control_passed: s.reproduction.control_passed,
                run_at: parse_time(&s.reproduction.run_at)?,
            },
            artifacts: FindingArtifacts {
                finding_capture,
                poc_path: s.artifacts.poc_path,
                screenshot_path: s.artifacts.screenshot_path,
            },
            flows,
            notes: s.notes,
        })
    }
}
