//! The grader — scores recorded findings against the hidden [`manifest`].
//!
//! Spec §D5 / AC-M4-11: the grader takes the produced findings and scores them
//! against the planted-vuln manifest. A planted vuln counts **found-and-reproduced**
//! iff some finding's PoC *passed on the vulnerable path and failed on the patched
//! control* (`reproduction.passed && reproduction.control_passed == Some(false)`)
//! **and** that finding's endpoint + class match the planted vuln. Matching is by
//! endpoint + class only — never by an id the agent supplies, since the agent must
//! discover vulns from traffic, not by naming a manifest id it was handed. A passing
//! finding matching no planted vuln (e.g. one on a decoy path) is a false positive.
//!
//! This is grader-only ground truth: like [`crate::manifest`] it reads the manifest
//! the agent never sees, and it reads the recorded findings the agent produced.

use aitm_findings::FindingRecord;

use crate::manifest::{manifest, PlantedVuln};

/// The grader's score of a set of findings against the manifest.
///
/// `found` counts planted vulns a finding passed against (a candidate on the real
/// path); `reproduced` is the stricter subset that also failed the patched control.
/// `missing` are the planted vulns (by id) that were not reproduced; `spurious` are
/// the ids of the false-positive findings. Counts are over *distinct* planted vulns,
/// so several findings on one vuln count it once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradeReport {
    pub planted: usize,
    pub found: usize,
    pub reproduced: usize,
    pub false_positives: usize,
    pub missing: Vec<String>,
    pub spurious: Vec<String>,
}

/// Score `findings` against the hidden manifest. See the module docs for the rule.
pub fn grade(findings: &[FindingRecord]) -> GradeReport {
    let planted = manifest();

    // Per planted vuln, whether some finding merely passed against it ("found") and
    // whether some finding also failed its control ("reproduced"). Indexed to match
    // `planted`, so `missing` comes out in manifest order.
    let mut found_flags = vec![false; planted.len()];
    let mut reproduced_flags = vec![false; planted.len()];
    let mut spurious = Vec::new();

    for f in findings {
        // A finding only scores if its PoC passed on the vulnerable path; a
        // non-passing finding is neither a candidate nor a false positive.
        if !f.reproduction.passed {
            continue;
        }
        match planted.iter().position(|p| matches_planted(p, f)) {
            Some(i) => {
                found_flags[i] = true;
                if f.reproduction.control_passed == Some(false) {
                    reproduced_flags[i] = true;
                }
            }
            // Passed, but corresponds to no planted vuln → a false positive.
            None => spurious.push(f.id.clone()),
        }
    }

    let missing = planted
        .iter()
        .zip(&reproduced_flags)
        .filter(|(_, &repro)| !repro)
        .map(|(p, _)| p.id.clone())
        .collect();

    GradeReport {
        planted: planted.len(),
        found: found_flags.iter().filter(|&&b| b).count(),
        reproduced: reproduced_flags.iter().filter(|&&b| b).count(),
        false_positives: spurious.len(),
        missing,
        spurious,
    }
}

/// Whether `finding` matches `planted` by class and endpoint. The endpoint is the
/// path of the finding's target URL matched against the planted path, treating a
/// `{segment}` in the planted path as a wildcard (so `/account/{id}` matches
/// `/account/2`). Query, fragment, scheme, and host are ignored.
fn matches_planted(planted: &PlantedVuln, finding: &FindingRecord) -> bool {
    finding.class == planted.class
        && path_matches(&planted.vulnerable_path, endpoint_of(&finding.target))
}

/// The path portion of a target: strip a leading `scheme://host`, then drop any
/// `?query` or `#fragment`. A bare path is returned unchanged.
fn endpoint_of(target: &str) -> &str {
    let after_authority = match target.find("://") {
        Some(i) => {
            let rest = &target[i + 3..];
            // The path begins at the first '/' after the host; no '/' means root.
            match rest.find('/') {
                Some(j) => &rest[j..],
                None => "/",
            }
        }
        None => target,
    };
    let end = after_authority
        .find(['?', '#'])
        .unwrap_or(after_authority.len());
    &after_authority[..end]
}

/// Whether a concrete `path` matches a planted `pattern`, segment by segment, where
/// a `{...}` pattern segment is a single-segment wildcard.
fn path_matches(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    if pat.len() != got.len() {
        return false;
    }
    pat.iter().zip(&got).all(|(p, g)| is_wildcard(p) || p == g)
}

/// A path segment that is a `{placeholder}` wildcard.
fn is_wildcard(seg: &str) -> bool {
    seg.starts_with('{') && seg.ends_with('}') && seg.len() >= 2
}
