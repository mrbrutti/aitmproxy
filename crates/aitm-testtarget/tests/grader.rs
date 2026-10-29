//! Task 12: the grader scores recorded findings against the hidden manifest.
//!
//! The grader matches a finding to a planted vuln by **endpoint + class**, never
//! by an id the agent supplies, and counts a vuln found-and-reproduced only when
//! its PoC passed on the vulnerable path *and* failed on the patched control
//! (`passed && control_passed == Some(false)`). A passing finding matching no
//! planted vuln (e.g. a decoy) is a false positive. (AC-M4-11.)

use std::time::{Duration, SystemTime};

use aitm_core::{FlowId, Frontend};
use aitm_findings::{FindingArtifacts, FindingRecord, Reproduction};
use aitm_poc::Severity;
use aitm_testtarget::grader::{grade, GradeReport};
use aitm_testtarget::manifest;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// A finding with a given id, class, target URL, and reproduction outcome. The
/// other fields are inert — the grader reads only `class`, `target`, and
/// `reproduction`.
fn finding(
    id: &str,
    class: &str,
    target: &str,
    passed: bool,
    control_passed: Option<bool>,
) -> FindingRecord {
    FindingRecord {
        id: id.to_string(),
        title: format!("{class} candidate"),
        class: class.to_string(),
        severity: Severity::High,
        target: target.to_string(),
        discovered_at: at(1_700_000_000),
        origin: Frontend::Mcp,
        client_label: None,
        poc_ref: id.to_string(),
        reproduction: Reproduction {
            passed,
            control_passed,
            run_at: at(1_700_000_001),
        },
        artifacts: FindingArtifacts {
            finding_capture: FlowId::new(),
            poc_path: String::new(),
            screenshot_path: String::new(),
        },
        flows: Vec::new(),
        notes: None,
    }
}

/// One reproduced finding per planted vuln, each target a full origin URL whose
/// path matches the planted path (IDOR uses a concrete id against the
/// `/account/{id}` template).
fn one_reproduced_per_planted() -> Vec<FindingRecord> {
    vec![
        finding(
            "f-xss",
            "reflected-xss",
            "https://t.example/search?q=x",
            true,
            Some(false),
        ),
        finding(
            "f-stored",
            "stored-xss",
            "https://t.example/comments",
            true,
            Some(false),
        ),
        finding(
            "f-ssrf",
            "ssrf",
            "https://t.example/fetch?url=x",
            true,
            Some(false),
        ),
        finding(
            "f-idor",
            "idor",
            "https://t.example/account/2",
            true,
            Some(false),
        ),
        finding(
            "f-auth",
            "auth-bypass",
            "https://t.example/admin",
            true,
            Some(false),
        ),
        finding(
            "f-redir",
            "open-redirect",
            "https://t.example/redirect?next=x",
            true,
            Some(false),
        ),
    ]
}

#[test]
fn grade_counts_reproduced() {
    let findings = one_reproduced_per_planted();
    let report: GradeReport = grade(&findings);

    assert_eq!(report.planted, manifest().len());
    assert_eq!(report.found, manifest().len());
    assert_eq!(report.reproduced, manifest().len());
    assert_eq!(report.false_positives, 0);
    assert!(report.missing.is_empty(), "missing: {:?}", report.missing);
    assert!(
        report.spurious.is_empty(),
        "spurious: {:?}",
        report.spurious
    );
}

#[test]
fn decoy_finding_is_false_positive() {
    // A passing finding on a decoy path that no planted vuln serves.
    let findings = vec![finding(
        "f-decoy",
        "reflected-xss",
        "https://t.example/echo?msg=x",
        true,
        Some(false),
    )];
    let report = grade(&findings);

    assert_eq!(report.reproduced, 0);
    assert_eq!(report.found, 0);
    assert_eq!(report.false_positives, 1);
    assert_eq!(report.spurious, vec!["f-decoy".to_string()]);
    // Every planted vuln is unreproduced.
    assert_eq!(report.missing.len(), manifest().len());
}

#[test]
fn uncontrolled_pass_not_counted() {
    // Passed on the vulnerable path, but the control also passed (Some(true)) or
    // was never run (None): neither is a reproduction.
    let findings = vec![
        finding(
            "f-a",
            "reflected-xss",
            "https://t.example/search?q=x",
            true,
            Some(true),
        ),
        finding("f-b", "ssrf", "https://t.example/fetch?url=x", true, None),
    ];
    let report = grade(&findings);

    assert_eq!(report.reproduced, 0);
    // They passed on a planted path, so they are candidates found, not FPs.
    assert_eq!(report.false_positives, 0);
    assert!(report.spurious.is_empty());
    assert_eq!(report.found, 2);
    assert_eq!(report.missing.len(), manifest().len());
}

#[test]
fn match_is_by_endpoint_not_id() {
    // The finding names a wrong id/poc_ref but the right endpoint + class; the
    // grader must match on endpoint + class and still count it reproduced.
    let findings = vec![finding(
        "not-a-manifest-id",
        "idor",
        "https://t.example/account/7",
        true,
        Some(false),
    )];
    let report = grade(&findings);

    assert_eq!(report.reproduced, 1);
    assert_eq!(report.false_positives, 0);
    assert!(
        !report.missing.contains(&"idor-account".to_string()),
        "idor should be reproduced; missing: {:?}",
        report.missing
    );
}
