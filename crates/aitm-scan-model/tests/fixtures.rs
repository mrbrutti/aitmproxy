//! The fixture pack: one example of every scanner verb result and every push
//! line, parsed back into its model type (plan task 9, spec D3 and D12).
//!
//! The pack under `crates/aitm-scan-model/fixtures/` is a development aid for the
//! UI tracks (T7/T8/T9), which build against the wire shapes before the engine
//! lands. These tests keep the pack honest: every file parses into the type the
//! D3 contract says it carries, the pinned literals hold, the set of files is
//! exactly the contract's surface, the push lines carry a monotonic sequence, and
//! no file carries a secret-looking value. A fixture run is never acceptance
//! evidence (spec Verification); only a run against a real target is.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use aitm_scan_model::{
    builtin, Canary, CanaryMethod, CheckOrigin, CheckScope, ChecksResult, InsertionKind, Issue,
    IssueStatus, JobEvent, JobNotification, JobState, ListResult, ProfileDeleteResult,
    ProfileListResult, ProfileSaveResult, ScanProfile, SessionProfile, SitemapResult, StartResult,
    BUILTIN_PROFILE_NAMES, JOB_KIND_SCAN,
};

/// Every fixture file the pack must carry (spec D3's verb results and push lines).
const ALL_FIXTURES: [&str; 22] = [
    "scan.start.json",
    "scan.map.json",
    "scan.status.json",
    "scan.list.json",
    "scan.cancel.json",
    "scan.issues.json",
    "scan.issue.json",
    "scan.issue.update.json",
    "scan.sitemap.json",
    "scan.checks.json",
    "scan.profile.list.json",
    "scan.profile.get.json",
    "scan.profile.save.json",
    "scan.profile.delete.json",
    "scan.session.preview.json",
    "job.started.json",
    "job.phase.json",
    "job.progress.json",
    "job.issue.json",
    "job.finished.json",
    "job.cancelled.json",
    "job.failed.json",
];

/// The seven push-line fixtures, in the order their `seq` runs 1..=7.
const PUSH_FIXTURES: [&str; 7] = [
    "job.started.json",
    "job.phase.json",
    "job.progress.json",
    "job.issue.json",
    "job.finished.json",
    "job.cancelled.json",
    "job.failed.json",
];

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Read a fixture by name, failing the test by name if it is missing.
fn read(name: &str) -> String {
    let path = fixtures_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "fixture {name} missing or unreadable at {}: {e}",
            path.display()
        )
    })
}

#[test]
fn every_fixture_parses_into_its_model_type() {
    // A table of (file, parse-and-assert closure): each closure parses the file's
    // text into the D3 type it carries and asserts the pinned literals. A missing
    // file fails in `read` by name; a wrong shape fails in the closure, and the
    // loop names the offending file.
    type FixtureCheck = (&'static str, fn(&str));
    let checks: Vec<FixtureCheck> = vec![
        ("scan.start.json", |s| {
            let r: StartResult = serde_json::from_str(s).expect("StartResult");
            assert_eq!(r.job, "scan-1a2b3c4d");
            assert_eq!(r.status.state, JobState::Queued);
            assert_eq!(r.lanes.skipped.len(), 1);
            assert_eq!(r.lanes.skipped[0].lane, aitm_scan_model::LaneKind::Ws);
            assert_eq!(
                r.lanes.skipped[0].reason,
                "lane not available on this build"
            );
            assert_eq!(r.clamped.len(), 1);
            assert_eq!(r.clamped[0].field, "budget.probes");
            assert_eq!(r.clamped[0].requested, 50_000);
            assert_eq!(r.clamped[0].applied, 20_000);
        }),
        ("scan.map.json", |s| {
            let r: StartResult = serde_json::from_str(s).expect("StartResult");
            assert_eq!(r.lanes.run, vec![aitm_scan_model::LaneKind::Http]);
            assert_eq!(r.status.phase, aitm_scan_model::Phase::Crawling);
        }),
        ("scan.status.json", |s| {
            let r: aitm_scan_model::JobStatus = serde_json::from_str(s).expect("JobStatus");
            assert_eq!(r.state, JobState::Running);
            assert_eq!(r.phase, aitm_scan_model::Phase::Auditing);
            assert_eq!(r.probes.sent, 418);
            assert_eq!(r.probes.budget, 2000);
            assert_eq!(r.issues.total, 3);
            assert!(r.session.is_some(), "status carries a session");
        }),
        ("scan.list.json", |s| {
            let r: ListResult = serde_json::from_str(s).expect("ListResult");
            assert_eq!(r.jobs.len(), 2);
            assert_eq!(r.jobs[0].job, "scan-1a2b3c4d");
        }),
        ("scan.cancel.json", |s| {
            let r: aitm_scan_model::JobStatus = serde_json::from_str(s).expect("JobStatus");
            assert_eq!(r.state, JobState::Cancelling);
        }),
        ("scan.issues.json", |s| {
            let r: aitm_scan_model::IssuesResult = serde_json::from_str(s).expect("IssuesResult");
            assert_eq!(r.issues.len(), 2);
            assert_eq!(r.by_severity.high, 1);
            assert_eq!(r.next_cursor, None);
        }),
        ("scan.issue.json", |s| {
            let r: Issue = serde_json::from_str(s).expect("Issue");
            assert_eq!(r.id, "issue-9f8e7d6c");
            assert_eq!(r.class, "reflected-xss");
            assert_eq!(r.severity, aitm_poc::Severity::High);
            assert_eq!(r.confidence, aitm_scan_model::Confidence::Certain);
            assert!(r.evidence.matched.is_some(), "evidence has a match");
            assert!(r.poc_ref.is_some(), "issue links a PoC");
            assert!(r.finding_id.is_some(), "issue links a finding");
        }),
        ("scan.issue.update.json", |s| {
            let r: Issue = serde_json::from_str(s).expect("Issue");
            assert_eq!(r.status, IssueStatus::FalsePositive);
            assert_eq!(r.note.as_deref(), Some("intended behaviour"));
        }),
        ("scan.sitemap.json", |s| {
            let r: SitemapResult = serde_json::from_str(s).expect("SitemapResult");
            assert!(
                r.nodes.iter().any(|n| n.path_template == "/account/{id}"),
                "a node templates the id segment"
            );
            assert!(
                r.points.iter().any(|p| p.kind == InsertionKind::JsonValue
                    && p.path.as_deref() == Some("profile.address.city")),
                "a json_value point addresses a nested field"
            );
            assert!(
                r.points.iter().any(|p| p.kind == InsertionKind::Cookie
                    && p.example.as_deref() == Some("<redacted>")),
                "a cookie point's example is redacted"
            );
        }),
        ("scan.checks.json", |s| {
            let r: ChecksResult = serde_json::from_str(s).expect("ChecksResult");
            assert_eq!(r.checks.len(), 3);
            assert!(
                r.checks
                    .iter()
                    .any(|c| matches!(c.origin, CheckOrigin::Native)),
                "a native check is present"
            );
            assert!(
                r.checks
                    .iter()
                    .any(|c| matches!(c.origin, CheckOrigin::Bundled { .. })),
                "a bundled check is present"
            );
            assert!(
                r.checks
                    .iter()
                    .any(|c| matches!(c.origin, CheckOrigin::Custom { .. })),
                "a custom check is present"
            );
            // Tester (T1b Task 1): the one entry carrying `"scope": "origin"`
            // reads as `Origin`; the two without the key read as the `Point`
            // default, so a pre-T1b catalogue entry schedules as it always did.
            let scopes: Vec<CheckScope> = r.checks.iter().map(|c| c.scope).collect();
            assert_eq!(
                scopes,
                vec![CheckScope::Point, CheckScope::Point, CheckScope::Origin]
            );
        }),
        ("scan.profile.list.json", |s| {
            let r: ProfileListResult = serde_json::from_str(s).expect("ProfileListResult");
            assert_eq!(r.profiles.len(), 7);
            assert!(
                r.profiles.iter().all(|p| p.builtin),
                "every entry is a builtin"
            );
            let names: Vec<&str> = r.profiles.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, BUILTIN_PROFILE_NAMES.to_vec());
        }),
        ("scan.profile.get.json", |s| {
            let r: ScanProfile = serde_json::from_str(s).expect("ScanProfile");
            assert_eq!(r, builtin("standard").expect("standard is a builtin"));
        }),
        ("scan.profile.save.json", |s| {
            let r: ProfileSaveResult = serde_json::from_str(s).expect("ProfileSaveResult");
            assert_eq!(r.saved, "my-api");
            assert!(
                r.path.ends_with("scan/profiles/my-api.yaml"),
                "path is the yaml under scan/profiles: {}",
                r.path
            );
        }),
        ("scan.profile.delete.json", |s| {
            let r: ProfileDeleteResult = serde_json::from_str(s).expect("ProfileDeleteResult");
            assert!(r.deleted);
        }),
        ("scan.session.preview.json", |s| {
            let r: SessionProfile = serde_json::from_str(s).expect("SessionProfile");
            assert_eq!(r.cookies, vec!["sid".to_string()]);
            assert_eq!(r.headers, vec!["authorization".to_string()]);
            assert_eq!(
                r.canary,
                Canary::Flow {
                    method: CanaryMethod::Get,
                    path: "/account".to_string(),
                    expected_status: Some(200),
                }
            );
        }),
        ("job.started.json", |s| {
            assert_push(s, JobEvent::Started, None)
        }),
        ("job.phase.json", |s| assert_push(s, JobEvent::Phase, None)),
        ("job.progress.json", |s| {
            assert_push(s, JobEvent::Progress, None)
        }),
        ("job.issue.json", |s| assert_push(s, JobEvent::Issue, None)),
        ("job.finished.json", |s| {
            assert_push(s, JobEvent::Finished, Some(JobState::Done))
        }),
        ("job.cancelled.json", |s| {
            assert_push(s, JobEvent::Cancelled, Some(JobState::Cancelled))
        }),
        ("job.failed.json", |s| {
            assert_push(s, JobEvent::Failed, Some(JobState::Failed))
        }),
    ];

    assert_eq!(
        checks.len(),
        ALL_FIXTURES.len(),
        "the table covers every fixture"
    );

    for (name, check) in checks {
        let text = read(name);
        let outcome = std::panic::catch_unwind(|| check(&text));
        if let Err(cause) = outcome {
            let detail = cause
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| cause.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic>");
            panic!("fixture {name} failed its contract check: {detail}");
        }
    }
}

/// Assert a push line's invariants: it is a scan job line, carries the named
/// event, carries an `issue` only on the `Issue` event, and carries the expected
/// terminal state when one is given.
fn assert_push(text: &str, event: JobEvent, state: Option<JobState>) {
    let line: JobNotification = serde_json::from_str(text).expect("JobNotification");
    assert_eq!(line.kind, JOB_KIND_SCAN, "push line is a scan job line");
    assert_eq!(line.event, event, "push line carries its event");
    if event == JobEvent::Issue {
        assert!(line.issue.is_some(), "the issue event carries an issue");
    } else {
        assert!(
            line.issue.is_none(),
            "only the issue event carries an issue"
        );
    }
    if let Some(state) = state {
        assert_eq!(line.status.state, state, "terminal push line state");
    }
}

#[test]
fn fixture_pack_is_complete() {
    let present: BTreeSet<String> = fs::read_dir(fixtures_dir())
        .expect("fixtures directory exists")
        .filter_map(|entry| {
            let name = entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            name.ends_with(".json").then_some(name)
        })
        .collect();
    let expected: BTreeSet<String> = ALL_FIXTURES.iter().map(|s| s.to_string()).collect();

    let missing: Vec<&String> = expected.difference(&present).collect();
    let stray: Vec<&String> = present.difference(&expected).collect();
    assert!(missing.is_empty(), "fixtures missing: {missing:?}");
    assert!(stray.is_empty(), "stray fixtures: {stray:?}");
}

#[test]
fn no_fixture_carries_a_secret_value() {
    // The session preview carries cookie and header *names* only; the sitemap's
    // cookie example is `<redacted>`. These tokens would mean a real value leaked
    // into a fixture (spec D7's anti-goal "no result carries session material").
    const FORBIDDEN: [&str; 5] = [
        "Bearer ",
        "sid=",
        "Set-Cookie",
        "\"Cookie\":",
        "\"Authorization\":",
    ];

    for name in ALL_FIXTURES {
        let text = read(name);
        for needle in FORBIDDEN {
            assert!(
                !text.contains(needle),
                "fixture {name} carries a secret-looking value: {needle:?}"
            );
        }
    }
}

/// Tester: the result types are deliberately tolerant (`#[serde(default)]`, no
/// `deny_unknown_fields`), which means a fixture key the model does **not** have
/// — a typo, a renamed field, a key left over from an older draft — parses
/// silently and the UI tracks build against a shape the engine will never send.
/// This closes that hole: every key in every fixture must survive a parse and a
/// re-serialize of the model type that carries it.
#[test]
fn no_fixture_key_is_silently_dropped() {
    /// Parse a fixture into its model type and serialize the model back.
    type Reparse = fn(&str) -> serde_json::Value;

    macro_rules! reparse {
        ($t:ty) => {
            (|s: &str| -> serde_json::Value {
                let v: $t = serde_json::from_str(s).expect("fixture parses");
                serde_json::to_value(&v).expect("model re-serializes")
            }) as Reparse
        };
    }

    let table: Vec<(&str, Reparse)> = vec![
        ("scan.start.json", reparse!(StartResult)),
        ("scan.map.json", reparse!(StartResult)),
        ("scan.status.json", reparse!(aitm_scan_model::JobStatus)),
        ("scan.list.json", reparse!(ListResult)),
        ("scan.cancel.json", reparse!(aitm_scan_model::JobStatus)),
        ("scan.issues.json", reparse!(aitm_scan_model::IssuesResult)),
        ("scan.issue.json", reparse!(Issue)),
        ("scan.issue.update.json", reparse!(Issue)),
        ("scan.sitemap.json", reparse!(SitemapResult)),
        ("scan.checks.json", reparse!(ChecksResult)),
        ("scan.profile.list.json", reparse!(ProfileListResult)),
        ("scan.profile.get.json", reparse!(ScanProfile)),
        ("scan.profile.save.json", reparse!(ProfileSaveResult)),
        ("scan.profile.delete.json", reparse!(ProfileDeleteResult)),
        ("scan.session.preview.json", reparse!(SessionProfile)),
        ("job.started.json", reparse!(JobNotification)),
        ("job.phase.json", reparse!(JobNotification)),
        ("job.progress.json", reparse!(JobNotification)),
        ("job.issue.json", reparse!(JobNotification)),
        ("job.finished.json", reparse!(JobNotification)),
        ("job.cancelled.json", reparse!(JobNotification)),
        ("job.failed.json", reparse!(JobNotification)),
    ];
    assert_eq!(
        table.len(),
        ALL_FIXTURES.len(),
        "the table covers every fixture"
    );

    for (name, reparse) in table {
        let text = read(name);
        let original: serde_json::Value = serde_json::from_str(&text).expect("fixture is JSON");
        let emitted = reparse(&text);
        let mut lost = Vec::new();
        collect_lost_keys(&original, &emitted, String::new(), &mut lost);
        assert!(
            lost.is_empty(),
            "fixture {name} carries keys the model does not: {lost:?}"
        );
    }
}

/// Walk `original` against `emitted` and record every object key the model did
/// not emit back. A `null` in the fixture whose key is absent from the output is
/// allowed: that is a `skip_serializing_if` optional, not a lost key.
fn collect_lost_keys(
    original: &serde_json::Value,
    emitted: &serde_json::Value,
    path: String,
    lost: &mut Vec<String>,
) {
    match (original, emitted) {
        (serde_json::Value::Object(o), serde_json::Value::Object(e)) => {
            for (key, value) in o {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match e.get(key) {
                    Some(got) => collect_lost_keys(value, got, child, lost),
                    None if value.is_null() => {}
                    None => lost.push(child),
                }
            }
        }
        (serde_json::Value::Array(o), serde_json::Value::Array(e)) => {
            for (i, value) in o.iter().enumerate() {
                if let Some(got) = e.get(i) {
                    collect_lost_keys(value, got, format!("{path}[{i}]"), lost);
                } else {
                    lost.push(format!("{path}[{i}]"));
                }
            }
        }
        _ => {}
    }
}

#[test]
fn push_sequence_is_monotonic() {
    let seqs: Vec<u64> = PUSH_FIXTURES
        .iter()
        .map(|name| {
            let line: JobNotification = serde_json::from_str(&read(name)).expect("JobNotification");
            line.seq
        })
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6, 7]);
}
