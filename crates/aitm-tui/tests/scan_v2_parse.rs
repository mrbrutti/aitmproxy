//! Scanner v2 TUI, plan task 1: the `crate::scan` module parses every fixture of
//! the contract pack into its D10 type, tolerates unknown keys, turns a
//! malformed reply into a `ScanError` with `code: None`, words every D9 code,
//! and pins the tag / elapsed / state-phase helpers.
//!
//! Fixture-driven: this proves parsing only. Acceptance is the pty cell against
//! a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_scan_model::{
    ChecksResult, Issue, IssuesResult, JobEvent, JobNotification, JobState, ListResult, Phase,
    ProfileDeleteResult, ProfileListResult, ProfileSaveResult, ScanErrorCode, ScanProfile,
    SessionProfile, SitemapResult, StartResult,
};
use aitm_tui::scan::{
    elapsed_text, parse_result, state_phase_text, tag_keyed, tag_parts, ScanError,
};
use common::fixture;
use serde_json::{json, Value};

fn parse<T: serde::de::DeserializeOwned>(verb: &str, value: &Value) -> T {
    match parse_result::<T>(verb, value) {
        Ok(v) => v,
        Err(e) => panic!("{verb}: {}", e.detail),
    }
}

#[test]
fn every_fixture_parses_into_its_contract_type() {
    let start: StartResult = parse("scan.start", &fixture("scan.start.json"));
    assert_eq!(start.clamped[0].field, "budget.probes");
    let map: StartResult = parse("scan.map", &fixture("scan.map.json"));
    assert_eq!(map.job, "scan-1a2b3c4d");

    let status: aitm_scan_model::JobStatus = parse("scan.status", &fixture("scan.status.json"));
    assert_eq!(status.probes.sent, 418);
    assert_eq!(status.probes.budget, 2000);
    assert_eq!(status.points.audited, 80);
    assert_eq!(status.points.found, 120);
    assert_eq!(status.state, JobState::Running);
    assert_eq!(status.phase, Phase::Auditing);
    let cancel: aitm_scan_model::JobStatus = parse("scan.cancel", &fixture("scan.cancel.json"));
    assert_eq!(cancel.state, JobState::Cancelling);

    let list: ListResult = parse("scan.list", &fixture("scan.list.json"));
    assert_eq!(list.jobs.len(), 2);

    let issues: IssuesResult = parse("scan.issues", &fixture("scan.issues.json"));
    assert_eq!(issues.by_severity.high, 1);
    let issue: Issue = parse("scan.issue", &fixture("scan.issue.json"));
    assert_eq!(issue.id, "issue-9f8e7d6c");
    let updated: Issue = parse("scan.issue.update", &fixture("scan.issue.update.json"));
    assert_eq!(updated.status, aitm_scan_model::IssueStatus::FalsePositive);

    let sitemap: SitemapResult = parse("scan.sitemap", &fixture("scan.sitemap.json"));
    assert_eq!(sitemap.next_cursor, Some("node-2".into()));

    let checks: ChecksResult = parse("scan.checks", &fixture("scan.checks.json"));
    assert_eq!(checks.checks.len(), 3);

    let profiles: ProfileListResult =
        parse("scan.profile.list", &fixture("scan.profile.list.json"));
    assert_eq!(profiles.profiles.len(), 7);
    let profile: ScanProfile = parse("scan.profile.get", &fixture("scan.profile.get.json"));
    assert_eq!(profile.name, "standard");
    let saved: ProfileSaveResult = parse("scan.profile.save", &fixture("scan.profile.save.json"));
    assert_eq!(saved.saved, "my-api");
    let deleted: ProfileDeleteResult =
        parse("scan.profile.delete", &fixture("scan.profile.delete.json"));
    assert!(deleted.deleted);

    let session: SessionProfile = parse(
        "scan.session.preview",
        &fixture("scan.session.preview.json"),
    );
    assert_eq!(session.cookies, vec!["sid".to_string()]);

    let pushes: [(Value, JobEvent); 7] = [
        (fixture("job.started.json"), JobEvent::Started),
        (fixture("job.phase.json"), JobEvent::Phase),
        (fixture("job.progress.json"), JobEvent::Progress),
        (fixture("job.issue.json"), JobEvent::Issue),
        (fixture("job.finished.json"), JobEvent::Finished),
        (fixture("job.cancelled.json"), JobEvent::Cancelled),
        (fixture("job.failed.json"), JobEvent::Failed),
    ];
    for (params, event) in pushes {
        let line: JobNotification = parse("notifications/aitm/job", &params);
        assert_eq!(line.kind, "scan");
        assert_eq!(line.event, event);
    }
}

#[test]
fn unknown_keys_are_tolerated() {
    let mut v = fixture("scan.status.json");
    v["future"] = json!(1);
    let status = parse_result::<aitm_scan_model::JobStatus>("scan.status", &v)
        .expect("a reply with an extra key still parses");
    assert_eq!(status.job, "scan-1a2b3c4d");
    assert_eq!(status.probes.sent, 418);
}

#[test]
fn a_malformed_reply_is_a_contract_error() {
    let err = parse_result::<aitm_scan_model::JobStatus>("scan.status", &json!({"job": 5}))
        .expect_err("a non-string job id is not a JobStatus");
    assert_eq!(err.verb, "scan.status");
    assert_eq!(err.code, None);
    assert!(
        err.detail.starts_with("reply did not match the contract ("),
        "the detail carries no verb (D10): {:?}",
        err.detail
    );
    assert!(
        err.wording()
            .starts_with("scan.status: reply did not match the contract ("),
        "wording was {:?}",
        err.wording()
    );
    assert!(
        !err.wording().contains("scan.status: scan.status"),
        "the verb is prefixed once, not twice: {:?}",
        err.wording()
    );
}

/// A verb the bus lacks (fix round A, A21): the constructor is uncoded with
/// the detail `is not on this bus`, and its wording reads `<verb> is not on
/// this bus` with no colon and the verb named once.
#[test]
fn a_missing_verb_is_worded_without_repeating_the_verb() {
    let err = ScanError::missing_verb("scan.cancel");
    assert_eq!(err.verb, "scan.cancel");
    assert_eq!(err.code, None);
    assert_eq!(err.detail, "is not on this bus");
    assert_eq!(err.wording(), "scan.cancel is not on this bus");
}

#[test]
fn error_codes_get_fixed_wording() {
    let busy = ScanError::from_message("scan.start", "scan: busy: d");
    assert_eq!(busy.code, Some(ScanErrorCode::Busy));
    assert_eq!(busy.detail, "d");
    assert_eq!(
        busy.wording(),
        "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x): d"
    );

    let table: [(&str, ScanErrorCode, &str); 9] = [
        // On a launch tag no list is refreshed, so the clause is omitted
        // (D9 as amended; fix round G, G75): the keyed form is pinned below.
        (
            "not_found",
            ScanErrorCode::NotFound,
            "No longer known to the core (it may have restarted)",
        ),
        (
            "busy",
            ScanErrorCode::Busy,
            "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x)",
        ),
        (
            "out_of_scope",
            ScanErrorCode::OutOfScope,
            "Out of scope: add the HTTP host to Scope (S) or an L4 scope entry with the inject capability covering the target",
        ),
        (
            "refused_agent",
            ScanErrorCode::RefusedAgent,
            "Refused for the agent role: this client is not the operator; check the token the TUI was started with",
        ),
        (
            "refused_l4",
            ScanErrorCode::RefusedL4,
            "L4 refused: enable `l4.enabled` in config (and the agent L4 gates for an agent-started job)",
        ),
        (
            "lane_unavailable",
            ScanErrorCode::LaneUnavailable,
            "No requested lane can run on this core; pick other lanes or a build that has them",
        ),
        (
            "invalid_profile",
            ScanErrorCode::InvalidProfile,
            "Profile rejected; fix the named field and launch or save again",
        ),
        (
            "unknown_check",
            ScanErrorCode::UnknownCheck,
            "Unknown check selector; remove it from include/exclude (the tree lists only loaded checks)",
        ),
        (
            "confirm_required",
            ScanErrorCode::ConfirmRequired,
            "The core wanted a confirmation this client did not send (the token may have expired); launch again to get a fresh prompt",
        ),
    ];
    for (token, code, text) in table {
        let e = ScanError::from_message("scan.start", &format!("scan: {token}: why"));
        assert_eq!(e.code, Some(code), "{token}");
        assert_eq!(e.detail, "why", "{token}");
        assert_eq!(e.wording(), format!("{text}: why"), "{token}");
    }

    let healed = ScanError::from_message("scan.status:scan-1a2b3c4d", "scan: not_found: why");
    assert_eq!(
        healed.wording(),
        "No longer known to the core (it may have restarted); the list is being refreshed: why",
        "a keyed status tag ran the self-heal"
    );

    let plain = ScanError::from_message("scan.start", "boom");
    assert_eq!(plain.code, None);
    assert_eq!(plain.detail, "boom");
    assert_eq!(plain.wording(), "scan.start: boom");
}

#[test]
fn helpers_pin_their_literals() {
    assert_eq!(
        tag_keyed("scan.status", "scan-1a2b3c4d"),
        "scan.status:scan-1a2b3c4d"
    );
    assert_eq!(
        tag_parts("scan.status:scan-1a2b3c4d"),
        ("scan.status", Some("scan-1a2b3c4d"))
    );
    assert_eq!(tag_parts("scan.list"), ("scan.list", None));

    assert_eq!(elapsed_text(42_000), "42s");
    assert_eq!(elapsed_text(125_000), "2m05s");
    assert_eq!(elapsed_text(3_725_000), "1h02m");

    assert_eq!(
        state_phase_text(JobState::Running, Phase::Auditing),
        "running/audit"
    );
    assert_eq!(
        state_phase_text(JobState::Queued, Phase::Queued),
        "queued/queued"
    );
    assert_eq!(
        state_phase_text(JobState::Running, Phase::Crawling),
        "running/crawl"
    );
    assert_eq!(
        state_phase_text(JobState::Running, Phase::Passive),
        "running/passive"
    );
    assert_eq!(
        state_phase_text(JobState::Cancelling, Phase::Reporting),
        "cancelling/report"
    );
    assert_eq!(state_phase_text(JobState::Done, Phase::Done), "done");
    assert_eq!(
        state_phase_text(JobState::Cancelled, Phase::Auditing),
        "cancelled"
    );
    assert_eq!(
        state_phase_text(JobState::Failed, Phase::Crawling),
        "failed"
    );
}
