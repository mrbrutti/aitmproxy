//! Scanner v2 TUI, plan task 6: the Jobs tab (spec D6, D10, D11, D13).
//!
//! `scan.list` then `scan.status` render rows newest first with the profile
//! and targets filled only for the job a status answered for; `x` cancels the
//! cursor's job once until the reply and is inert (with a banner) on a
//! terminal job or without the verb; `Enter` opens Issues filtered to the job
//! with one `scan.issues`; the detail pane lists lanes, session and checks.
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_scan_model::{BySeverity, JobStatus, JobSummary, LaneKind};
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::App;
use aitm_tui::scan::{
    progress_bar, progress_fill, row, severity_bar, severity_runs, JobsState, ReadStatus,
    ScanError, ScanTab, DETAIL_LIST_MAX, DETAIL_VALUE_MAX, JOBS_MAX, PROFILE_MAX, TARGETS_MAX,
};
use aitm_tui::text::width;
use common::*;
use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.issues",
    "scan.cancel",
];

const JOB: &str = "scan-1a2b3c4d";
const OTHER: &str = "scan-55667788";

/// A connected v2 app at 200x50 on the Jobs tab, the `scan.list` its open
/// issued already settled empty, so nothing is in flight.
fn app_with(tools: &[&str]) -> App {
    let mut app = opened_minimal(tools);
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    app
}

fn app() -> App {
    app_with(TOOLS)
}

/// A `scan.status` reply for `JOB` under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    reply(&format!("scan.status:{JOB}"), "scan.status", body)
}

/// The `scan.list.json` reply under its single-slot tag.
fn list_reply() -> BusEvent {
    reply("scan.list", "scan.list", fixture("scan.list.json"))
}

/// The `scan.status.json` fixture with its state and phase replaced.
fn status_in(state: &str, phase: &str) -> Value {
    let mut body = fixture("scan.status.json");
    body["state"] = json!(state);
    body["phase"] = json!(phase);
    body
}

/// The strip-and-banner row of the Scan view.
fn banner_row(text: &str) -> &str {
    line_with(text, "1 Profiles").unwrap_or_default()
}

fn cancel_request() -> BusRequest {
    tagged(
        &format!("scan.cancel:{JOB}"),
        "scan.cancel",
        json!({ "job": JOB }),
    )
}

/// T7-1, T7-8: one `scan.status` renders the row with every literal the
/// plan names, profile and targets included. Jobs view D19, T2 re-pinned
/// the literals: the progress column reads the checks (180 of 240, a bar
/// four cells of six), the budget column the probes as a number, the state
/// cell the phase word.
#[test]
fn status_renders_the_row_literals() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let text = screen(&app);
    let line = line_with(&text, JOB).unwrap_or_else(|| panic!("no row for {JOB}: {text}"));
    for literal in [
        "180/240 ━━━━──",
        "418/2000  80/120",
        "auditing",
        "standard",
        "http://127.0.0.1:8080",
        "▆▆▄▄▂▂",
        "42s",
    ] {
        assert!(
            line.contains(literal),
            "the {JOB} row lacks {literal:?}: {line:?}"
        );
    }
    assert!(!line.contains("running/audit"), "{line:?}");
    let header = line_with(&text, "progress").unwrap_or_default();
    for col in [
        "job", "profile", "targets", "state", "progress", "budget", "points", "issues", "el.",
    ] {
        assert!(header.contains(col), "the header lacks {col:?}: {header:?}");
    }
    assert!(
        line_index(&text, "progress") < line_index(&text, JOB),
        "the header sits above the first row"
    );
}

/// T7-8: `scan.list` then `scan.status` fills profile and targets only for
/// the job the status answered for; the other reads `...`; rows are newest
/// first, the list's order.
#[test]
fn list_then_status_fills_only_the_statusd_job() {
    let mut app = app();
    let reqs = app.on_bus(list_reply());
    assert_eq!(
        reqs.len(),
        2,
        "one status follow-up per listed job: {reqs:?}"
    );
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));

    let text = screen(&app);
    let first = line_with(&text, JOB).unwrap_or_default();
    let second = line_with(&text, OTHER).unwrap_or_default();
    assert!(first.contains("standard"), "{first:?}");
    assert!(first.contains("http://127.0.0.1:8080"), "{first:?}");
    assert!(
        second.contains("..."),
        "unknown profile reads ...: {second:?}"
    );
    assert!(
        !second.contains("standard"),
        "the other job's profile is not known yet: {second:?}"
    );
    assert!(
        second.contains("done"),
        "the listed state shows: {second:?}"
    );
    assert_eq!(app.scan.jobs.order[0], JOB);
    assert!(
        line_index(&text, JOB) < line_index(&text, OTHER),
        "the first row is {JOB}"
    );
}

/// T7-8, D4: `x` sends `scan.cancel {job}` once; a second `x` before the
/// reply sends nothing; the reply's state shows in the row and settles the tag.
#[test]
fn cancel_is_sent_once_until_the_reply() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));

    let first = app.update(Action::ScanCancel);
    assert_eq!(first, vec![cancel_request()]);
    let second = app.update(Action::ScanCancel);
    assert!(second.is_empty(), "the tag dedupe holds it: {second:?}");
    assert!(app.scan.inflight.contains(&format!("scan.cancel:{JOB}")));

    let reqs = app.on_bus(reply(
        &format!("scan.cancel:{JOB}"),
        "scan.cancel",
        fixture("scan.cancel.json"),
    ));
    assert!(reqs.is_empty(), "a cancel reply pushes nothing: {reqs:?}");
    assert!(
        !app.scan.inflight.contains(&format!("scan.cancel:{JOB}")),
        "the reply settles the tag"
    );
    let text = screen(&app);
    let line = line_with(&text, JOB).unwrap_or_default();
    assert!(
        line.contains("cancelling"),
        "the row shows the reply's state: {line:?}"
    );
    // The third `x` goes out again: the job is still not terminal.
    let third = app.update(Action::ScanCancel);
    assert_eq!(third, vec![cancel_request()]);
}

/// D11: on a terminal job `x` is inert and the banner reads `already <state>`
/// as a notice, not through the error channel (fix round C, C19): no
/// `scan.cancel:` prefix, no `ScanError` recorded, and the next key clears
/// it.
#[test]
fn cancel_on_a_terminal_job_is_inert() {
    let mut app = app();
    let _ = app.on_bus(status_reply(status_in("done", "done")));
    let reqs = app.update(Action::ScanCancel);
    assert!(reqs.is_empty(), "a done job is not cancelled: {reqs:?}");
    assert!(app.scan.inflight.is_empty());
    let text = screen(&app);
    let strip = banner_row(&text);
    assert!(
        strip.contains("already done"),
        "the banner says why the key did nothing: {strip:?}"
    );
    assert!(
        !strip.contains("scan.cancel:"),
        "a notice is not an error: {strip:?}"
    );
    assert_eq!(app.scan.last_error, None, "no error is recorded");
    assert_eq!(app.scan.notice.as_deref(), Some("already done"));

    let _ = app.update(Action::Down);
    assert_eq!(app.scan.notice, None, "the next key clears the notice");
    let strip = banner_row(&screen(&app)).to_string();
    assert!(!strip.contains("already done"), "{strip:?}");
}

/// T7-13: without `scan.cancel` on the bus `x` sends nothing and the screen
/// says `scan.cancel is not on this bus`.
#[test]
fn cancel_without_the_verb_is_inert_and_says_so() {
    let mut app = app_with(&["scan.start", "scan.list", "scan.status", "scan.issues"]);
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reqs = app.update(Action::ScanCancel);
    assert!(reqs.is_empty(), "no verb, no call: {reqs:?}");
    let text = screen(&app);
    assert!(
        text.contains("scan.cancel is not on this bus"),
        "the missing verb is named: {text}"
    );
}

/// T7-8, D6: `Enter` on a row opens Issues with `filters.job` set and sends
/// exactly one `scan.issues {job, limit: 512}`.
#[test]
fn enter_opens_issues_filtered_to_the_job() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reqs = app.update(Action::Enter);
    assert_eq!(app.scan.tab, ScanTab::Issues);
    assert_eq!(app.scan.issues.filters.job.as_deref(), Some(JOB));
    assert_eq!(reqs.len(), 1, "exactly one request: {reqs:?}");
    match &reqs[0] {
        BusRequest::CallTagged { tag, name, args } => {
            assert_eq!(tag, "scan.issues");
            assert_eq!(name, "scan.issues");
            assert_eq!(args["job"], JOB);
            assert_eq!(args["limit"], 512);
        }
        other => panic!("not a tagged scan.issues: {other:?}"),
    }
}

/// D11: the detail pane lists the lanes requested, run and skipped with the
/// reason, the session and the checks running.
#[test]
fn detail_lists_lanes_and_session() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let text = screen(&app);
    for literal in [
        "lanes requested http ws",
        "run http",
        "skipped ws (lane not available on this build)",
        "reused",
        "GET /account",
        "http.reflected-xss",
    ] {
        assert!(
            text.contains(literal),
            "the detail lacks {literal:?}: {text}"
        );
    }
    // The lanes line whole, as `detail_text` builds it (plan Task 16).
    let lines = app.scan.jobs.detail_text();
    assert_eq!(
        lines
            .iter()
            .find(|(l, _)| *l == "lanes")
            .map(|(_, v)| v.as_str()),
        Some("requested http ws · run http · skipped ws (lane not available on this build)")
    );
}

/// Fix round C, C20 and fix round E, E1 (D6 hostile-core bounds): the
/// core's strings are bounded once, when the status is folded, so the row
/// only copies bounded text. A 1 MiB `targets[0]` and a 300-char profile
/// name leave `full[job]` holding at most `4 * TARGETS_MAX` cells (and one
/// more char than four times that) and a `PROFILE_MAX`-cell profile; the
/// row reads the same; more than four targets are counted rather than
/// joined; the table still draws the targets cell at most `TARGETS_MAX`
/// wide with an ellipsis.
#[test]
fn rows_are_bounded_at_construction() {
    let mut app = app();
    let mut body = fixture("scan.status.json");
    body["targets"] = json!(["h".repeat(1 << 20)]);
    body["profile_name"] = json!("p".repeat(300));
    let _ = app.on_bus(status_reply(body));

    let full = app
        .scan
        .jobs
        .full
        .get(JOB)
        .unwrap_or_else(|| panic!("the status was folded"));
    assert!(
        full.targets[0].chars().count() <= 4 * TARGETS_MAX + 1,
        "targets[0] is {} chars after the fold",
        full.targets[0].chars().count()
    );
    assert!(width(&full.targets[0]) <= 4 * TARGETS_MAX);
    assert_eq!(width(&full.profile_name), PROFILE_MAX);

    let built = app.scan.jobs.row_of(JOB);
    assert!(
        width(&built.targets) <= 4 * TARGETS_MAX,
        "targets text is {} cells",
        width(&built.targets)
    );
    assert_eq!(width(&built.profile), PROFILE_MAX);
    assert!(built.profile.ends_with('…'));

    let text = screen(&app);
    let header = line_with(&text, "progress").unwrap_or_default();
    let from = col_of(header, "targets").expect("a targets column");
    let to = col_of(header, "state").expect("a state column");
    assert!(
        to - from <= TARGETS_MAX + 2,
        "the targets column spans {} cells",
        to - from
    );
    let line = line_with(&text, JOB).unwrap_or_default();
    assert!(line.contains('…'), "the cut is shown: {line:?}");

    let status: JobStatus =
        serde_json::from_value(fixture("scan.status.json")).expect("the fixture parses");
    let many = JobStatus {
        targets: (1..=6).map(|n| format!("http://h{n}.test")).collect(),
        ..status
    };
    let crowded = row(&many.summary(), Some(&ReadStatus::new(many)));
    assert_eq!(
        crowded.targets,
        "http://h1.test http://h2.test http://h3.test http://h4.test +2"
    );
}

/// Fix round G, G11 (D6 hostile-core bounds): the Detail pane's free-text
/// fields are cut at fold to `DETAIL_VALUE_MAX` cells (`error`, the
/// frontend and client label, each clamped field, skipped reason and
/// running check id, the canary path) and the three lists are capped at
/// `DETAIL_LIST_MAX` with the rest counted as `+n`; a 1 MiB `error` and a
/// thousand running checks still render.
#[test]
fn detail_fields_and_lists_are_bounded_at_fold() {
    let mut app = app();
    let mut body = fixture("scan.status.json");
    body["error"] = json!("e".repeat(1 << 20));
    body["started_by"]["client_label"] = json!("\t".repeat(1 << 20));
    body["checks"]["running"] = json!((0..1000).map(|k| format!("http.c{k}")).collect::<Vec<_>>());
    body["lanes"]["skipped"] = json!((0..20)
        .map(|k| json!({ "lane": "ws", "reason": format!("r{k}") }))
        .collect::<Vec<_>>());
    body["clamped"] = json!((0..20)
        .map(|k| json!({ "field": format!("f{k}"), "requested": 9, "applied": 1 }))
        .collect::<Vec<_>>());
    body["session"]["canary"]["path"] = json!("/p".repeat(1 << 16));
    let samples: Vec<Value> = (0..9)
        .map(|k| json!({ "check": format!("http.c{k}"), "point": format!("p{k}"), "detail": "d".repeat(1000) }))
        .collect();
    body["checks"]["error_samples"] = json!(samples);
    body["checks"]["skipped_samples"] = json!(samples);
    let _ = app.on_bus(status_reply(body));
    let full = app.scan.jobs.full.get(JOB).expect("folded");
    let error = full.error.as_deref().unwrap_or_default();
    assert!(
        error.chars().count() <= 4 * DETAIL_VALUE_MAX,
        "{} chars",
        error.chars().count()
    );
    assert!(width(error) <= DETAIL_VALUE_MAX);
    assert_eq!(
        full.started_by.client_label.as_deref(),
        Some(""),
        "tabs stripped"
    );
    assert_eq!(full.checks.running.len(), DETAIL_LIST_MAX);
    assert_eq!(full.lanes.skipped.len(), DETAIL_LIST_MAX);
    assert_eq!(full.clamped.len(), DETAIL_LIST_MAX);
    assert_eq!(full.dropped.running, 1000 - DETAIL_LIST_MAX);
    assert_eq!(full.dropped.skipped, 20 - DETAIL_LIST_MAX);
    assert_eq!(full.dropped.clamped, 20 - DETAIL_LIST_MAX);
    // Jobs view D19, T1: the check samples are bounded at the same fold.
    assert_eq!(full.checks.error_samples.len(), DETAIL_LIST_MAX);
    assert_eq!(full.checks.skipped_samples.len(), DETAIL_LIST_MAX);
    assert_eq!(full.dropped.error_samples, 9 - DETAIL_LIST_MAX);
    assert_eq!(full.dropped.skipped_samples, 9 - DETAIL_LIST_MAX);
    assert_eq!(
        width(&full.checks.error_samples[0].detail),
        DETAIL_VALUE_MAX
    );
    assert_eq!(
        width(&full.checks.skipped_samples[0].detail),
        DETAIL_VALUE_MAX
    );
    let lines = app.scan.jobs.detail_text();
    let value = |label: &str| {
        lines
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no {label} line: {lines:?}"))
    };
    assert!(
        value("checks").ends_with("http.c7 +992"),
        "{:?}",
        value("checks")
    );
    assert!(
        value("lanes").ends_with("ws (r7) +12"),
        "{:?}",
        value("lanes")
    );
    assert!(
        value("clamped").ends_with("f7 9 -> 1 +12"),
        "{:?}",
        value("clamped")
    );
    let session = value("session");
    assert!(
        width(&session) <= DETAIL_VALUE_MAX + 40,
        "{} cells",
        width(&session)
    );
    let text = screen(&app);
    assert!(text.lines().all(|l| l.chars().count() <= 200));
    assert_eq!(app.scan.jobs.detail_len(), 1 + lines.len());
}

/// Fix round C, C20 and fix round E, E5: the Detail pane's length is
/// counted without building its lines, and it counts exactly the id line
/// plus what `detail_text` draws, for a job with a full status and for one
/// nothing has answered for (the placeholder line).
#[test]
fn detail_len_counts_what_detail_text_draws() {
    let status: JobStatus =
        serde_json::from_value(fixture("scan.status.json")).expect("the fixture parses");
    let mut jobs = JobsState::default();
    jobs.fold_status(status);
    assert_eq!(jobs.detail_len(), 1 + jobs.detail_text().len());
    // Jobs view D19, T2: the progress line and the `now` line (the
    // fixture's two running checks) open the pane.
    assert_eq!(
        jobs.detail_len(),
        10,
        "the id line, the progress line, the now line and the seven fixed lines"
    );
    assert_eq!(
        jobs.detail_text()[0],
        ("", "75\u{a0}% · 180 of 240 checks".to_string())
    );
    assert_eq!(
        jobs.detail_text()[1],
        ("now", "http.reflected-xss, http.sqli-error".to_string())
    );
    assert_eq!(jobs.detail_text()[2].0, "lanes");
    // Jobs view D19, T1 and T2: a stopped job opens with the end sentence,
    // then the stopped sentence and the wire line.
    let mut stopped = fixture("scan.status.json");
    stopped["state"] = json!("done");
    stopped["stopped_reason"] = json!("errors");
    stopped["checks"]["running"] = json!([]);
    let stopped: JobStatus = serde_json::from_value(stopped).expect("the fixture parses");
    jobs.fold_status(stopped);
    assert_eq!(jobs.detail_len(), 1 + jobs.detail_text().len());
    assert_eq!(
        jobs.detail_len(),
        11,
        "the id line, the sentence, `stopped`, `wire` and the seven fixed lines"
    );
    let lines = jobs.detail_text();
    let head: Vec<(&str, &str)> = lines[..3].iter().map(|(l, v)| (*l, v.as_str())).collect();
    assert_eq!(
        head,
        vec![
            ("", "Done in 0:42 · 120 points · 240 checks."),
            ("stopped", "Stopped early: too many errors from the target."),
            ("wire", "stopped_reason: errors"),
        ]
    );
    assert_eq!(lines[3].0, "lanes");
    let mut bare = JobsState::default();
    bare.order.push(JOB.to_string());
    assert_eq!(
        bare.detail_text(),
        vec![("", "waiting for scan.status...".to_string())],
        "no status: the placeholder line"
    );
    assert_eq!(bare.detail_len(), 1 + bare.detail_text().len());
    assert_eq!(bare.detail_len(), 2, "the id line and the placeholder");
}

/// Fix round C, C28: the detail's first line repeats the profile and the
/// targets only when the table was too narrow to draw them (the narrow
/// mockup); in the wide layout the row already shows them.
#[test]
fn detail_first_line_carries_profile_and_targets_only_when_the_table_dropped_them() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));

    let wide = text_of(&app, 200, 50);
    let lines: Vec<&str> = wide.lines().filter(|l| l.contains(JOB)).collect();
    assert_eq!(lines.len(), 2, "the row and the detail id line: {wide}");
    assert!(
        lines[0].contains("standard"),
        "the wide row: {:?}",
        lines[0]
    );
    assert!(
        !lines[1].contains("standard"),
        "the wide detail does not repeat it: {:?}",
        lines[1]
    );

    let narrow = text_of(&app, 90, 40);
    let lines: Vec<&str> = narrow.lines().filter(|l| l.contains(JOB)).collect();
    assert_eq!(lines.len(), 2, "the row and the detail id line: {narrow}");
    assert!(
        !lines[0].contains("standard"),
        "the narrow row drops it: {:?}",
        lines[0]
    );
    assert!(
        lines[1].contains("standard") && lines[1].contains("http://127.0.0.1:8080"),
        "the narrow detail carries both: {:?}",
        lines[1]
    );
}

/// The row builder: `...` until a full status is known (the progress too,
/// which needs the status's check counters; Jobs view D19, T2); the
/// counters in the `<sent>/<budget>` and `<audited>/<found>` shapes.
#[test]
fn row_reads_dots_until_the_status_is_known() {
    let status: JobStatus =
        serde_json::from_value(fixture("scan.status.json")).expect("the fixture parses");
    let summary: JobSummary = status.summary();
    let bare = row(&summary, None);
    assert_eq!(bare.id, JOB);
    assert_eq!(bare.profile, "...");
    assert_eq!(bare.targets, "...");
    assert_eq!(bare.progress, "...");
    assert_eq!(bare.progress_fill, 0);
    assert_eq!(bare.budget, "418/2000");
    assert_eq!(bare.points, "80/120");
    assert_eq!(bare.state_phase, "auditing");
    assert_eq!(bare.elapsed, "42s");
    assert_eq!(bare.issues.high, 1);
    let full = row(&summary, Some(&ReadStatus::new(status)));
    assert_eq!(full.profile, "standard");
    assert_eq!(full.targets, "http://127.0.0.1:8080");
    assert_eq!(full.progress, "180/240");
    assert_eq!(full.progress_fill, 4, "floor of 0.75 over six cells");
    assert_eq!(full.budget, "418/2000");
}

/// The bars: the progress bar (Jobs view D8, D19 T2) floors like its
/// percent, so it reads full only at 1 and empty while indeterminate; the
/// severity stack gives every non-zero severity a cell, graver first. The
/// text bars are composed from the typed fills and `severity_runs` the
/// view styles (fix round C, C21, C23). The probe bar is gone (Task 4.5c):
/// the budget is a number without a bar.
#[test]
fn bars_are_box_drawing_cells() {
    assert_eq!(progress_fill(Some(0.5), 6), 3);
    assert_eq!(progress_fill(None, 6), 0);
    assert_eq!(progress_fill(Some(0.75), 6), 4);
    assert_eq!(progress_bar(Some(0.5), 6), "━━━───");
    assert_eq!(progress_bar(None, 6), "──────");
    assert_eq!(progress_bar(Some(1.0), 6), "━━━━━━");

    let three = BySeverity {
        high: 1,
        medium: 1,
        low: 1,
        ..Default::default()
    };
    assert_eq!(severity_bar(&three, 6), "▆▆▄▄▂▂");
    assert_eq!(
        severity_runs(&three, 6),
        vec![
            ("high", "▆▆".to_string()),
            ("medium", "▄▄".to_string()),
            ("low", "▂▂".to_string()),
        ]
    );
    assert_eq!(severity_bar(&BySeverity::default(), 6), "······");
    assert_eq!(
        severity_runs(&BySeverity::default(), 6),
        vec![("", "······".to_string())]
    );
    let lopsided = BySeverity {
        critical: 1,
        low: 99,
        ..Default::default()
    };
    assert_eq!(severity_bar(&lopsided, 4), "█▂▂▂");
}

/// Fix round F, F15 (spec D3: the notice is "cleared by the next key only,
/// never by a reply"): job A done and job B running, `x` on A leaves
/// `already done` in the banner; a `scan.status` reply for B, the kind of
/// background poll that lands within a second, leaves it there; the next
/// key clears it.
#[test]
fn a_status_reply_does_not_clear_the_notice() {
    let mut app = app();
    let _ = app.on_bus(list_reply());
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.jobs.cursor_job().map(String::as_str), Some(OTHER));
    let reqs = app.update(Action::ScanCancel);
    assert!(reqs.is_empty(), "a done job is not cancelled: {reqs:?}");
    assert_eq!(app.scan.notice.as_deref(), Some("already done"));

    let reqs = app.on_bus(status_reply(fixture("scan.status.json")));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(
        app.scan.notice.as_deref(),
        Some("already done"),
        "a reply for another job erased the notice"
    );
    let strip = banner_row(&screen(&app)).to_string();
    assert!(strip.contains("already done"), "{strip:?}");

    let _ = app.update(Action::Down);
    assert_eq!(app.scan.notice, None, "the next key clears the notice");
}

/// Fix round G, G65: the Jobs Detail pane draws the UI-3 reason wrapped over
/// its footer the way Profiles does, whole at 90x40 (no cut at 90 columns),
/// and a refused launch (D13's refused state) the same way, since `s` is
/// live on this tab too.
#[test]
fn jobs_detail_wraps_the_blocked_reason_and_the_refused_launch_over_its_footer() {
    const FOOTER: &str = "x cancel · ⏎ issues of this job";
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reason = "L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, 127.0.0.1/32 ports 7000, capability inject (l4.scope.add).";
    app.scan.launch.blocked = Some(reason.to_string());
    for (cols, rows) in [(200u16, 50u16), (90, 40)] {
        let text = text_of(&app, cols, rows);
        for want in [
            "L4 launch disabled",
            "interface \"*\"",
            "direction outbound",
            "127.0.0.1/32",
            "7000",
            "capability inject",
            "(l4.scope.add)",
        ] {
            assert!(
                text.contains(want),
                "{cols}x{rows}: {want:?} missing from the Jobs tab:\n{text}"
            );
        }
        let y = line_index(&text, "L4 launch disabled").expect("the reason row");
        let footer = line_index(&text, FOOTER).expect("the Jobs footer");
        assert!(
            y < footer,
            "{cols}x{rows}: the reason sits above the footer"
        );
        let x = col_of(text.lines().nth(y).expect("row"), "L4 launch").expect("column");
        let buf = draw(&app, cols, rows);
        assert_eq!(
            cell(&buf, x, y).fg,
            theme()
                .fg(&aitm_tui::tokens::color::status::CLIENT_ERROR)
                .fg
                .expect("the theme sets a foreground"),
            "{cols}x{rows}: the warning hue"
        );
    }

    // A refused launch with no gate holding: the D9 wording takes the same
    // rows (Task 13 ruling: both tabs draw it).
    app.scan.launch.blocked = None;
    let _ = app.on_bus(failed(
        "scan.start",
        "scan.start",
        "scan: out_of_scope: evil.test is not in scope",
    ));
    let text = screen(&app);
    // The banner and the toast carry the wording too (D13); the footer
    // copy is the row within the four above the footer.
    let footer = line_index(&text, FOOTER).expect("the Jobs footer");
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        (footer.saturating_sub(4)..footer)
            .any(|y| lines[y].contains("Out of scope: add the HTTP host to Scope (S)")),
        "the refused wording sits in the footer rows:\n{text}"
    );
}

/// Fix round G, G102 (D6 hostile-core bounds): `targets` is bounded in
/// count as well as per string: a status with 100 000 targets keeps
/// `DETAIL_LIST_MAX` of them, counts the rest into `dropped.targets`, and
/// the row's `+n` names every target the row does not show.
#[test]
fn targets_are_capped_in_count_at_fold_with_the_rest_counted() {
    let mut app = app();
    let mut status = fixture("scan.status.json");
    status["targets"] = json!((0..100_000)
        .map(|k| format!("http://h{k}.test"))
        .collect::<Vec<_>>());
    let _ = app.on_bus(status_reply(status));
    let read = app.scan.jobs.full.get(JOB).expect("the status is folded");
    assert_eq!(read.targets.len(), DETAIL_LIST_MAX);
    assert_eq!(read.dropped.targets, 100_000 - DETAIL_LIST_MAX);
    let row = app.scan.jobs.row_of(JOB);
    assert!(
        row.targets.ends_with(" +99996"),
        "the row counts every target it does not show: {:?}",
        row.targets
    );
    assert!(row.targets.starts_with("http://h0.test http://h1.test"));
    let _ = text_of(&app, 200, 50);
}

/// Fix round H, H33 (D6 hostile-core bounds): `lanes.requested` and
/// `lanes.run` are bounded in count at fold, not joined per frame. A status
/// with 100_000 `http` run lanes (and the requested list in reverse with
/// duplicates) folds to `run == [Http]` and `requested == [Http, Ws]`, and
/// the Detail pane's lanes line reads `run http` at 200x50 with no second
/// `http` token.
#[test]
fn lanes_are_deduped_and_sorted_at_fold() {
    let mut app = app();
    let mut body = fixture("scan.status.json");
    body["lanes"]["run"] = json!(vec!["http"; 100_000]);
    body["lanes"]["requested"] = json!(["ws", "http", "ws", "http"]);
    let _ = app.on_bus(status_reply(body));
    let full = app.scan.jobs.full.get(JOB).expect("folded");
    assert_eq!(full.lanes.run, vec![LaneKind::Http]);
    assert_eq!(full.lanes.requested, vec![LaneKind::Http, LaneKind::Ws]);
    assert!(
        full.lanes.run.capacity() <= 4,
        "capacity {} not given back",
        full.lanes.run.capacity()
    );
    let text = screen(&app);
    let line =
        line_with(&text, "lanes requested").unwrap_or_else(|| panic!("no lanes line: {text}"));
    assert!(
        line.contains("requested http ws · run http · skipped"),
        "{line:?}"
    );
    assert_eq!(
        line.matches("http").count(),
        2,
        "one requested http, one run http: {line:?}"
    );
}

/// Fix round H, H36 (D6 hostile-core bounds): `scan.list` has a row-count
/// cap. A list of 100_000 ids folds to `JOBS_MAX` (256) rows, the first
/// listed ids kept in list order, a `started_here` id the list omits still
/// in front, and the screen still draws.
#[test]
fn a_huge_list_folds_to_jobs_max_rows() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    app.scan.jobs.started_here.insert(JOB.to_string());
    let template = fixture("scan.list.json")["jobs"][0].clone();
    let jobs: Vec<Value> = (0..100_000)
        .map(|k| {
            let mut s = template.clone();
            s["job"] = json!(format!("scan-{k:08x}"));
            s
        })
        .collect();
    let _ = app.on_bus(reply("scan.list", "scan.list", json!({ "jobs": jobs })));
    assert_eq!(
        app.scan.jobs.order.len(),
        JOBS_MAX + 1,
        "256 listed + 1 started here"
    );
    assert_eq!(app.scan.jobs.order[0], JOB);
    assert_eq!(app.scan.jobs.order[1], "scan-00000000");
    assert_eq!(app.scan.jobs.order[JOBS_MAX], "scan-000000ff");
    assert_eq!(app.scan.jobs.summaries.len(), JOBS_MAX + 1);
    let _ = screen(&app);
}

/// D13 hue on data (plan Task 16): the Jobs row's state cell takes the
/// status token of its state (`running` the accent, `done` success,
/// `failed` server-error, `cancelled` tertiary) and the id cell beside it
/// stays primary text, whether or not the row is under the cursor.
#[test]
fn the_state_cell_wears_its_states_hue() {
    use aitm_tui::tokens::color::status;

    let theme = theme();
    let fg = |style: ratatui::style::Style| style.fg.expect("the theme sets a foreground");
    let table = [
        ("running", "auditing", "auditing", fg(theme.accent())),
        ("done", "done", "done", fg(theme.fg(&status::SUCCESS))),
        (
            "failed",
            "done",
            "failed",
            fg(theme.fg(&status::SERVER_ERROR)),
        ),
        ("cancelled", "done", "cancelled", fg(theme.text_tertiary())),
    ];
    for (state, phase, text, want) in table {
        for under_cursor in [true, false] {
            let mut app = app();
            let _ = app.on_bus(list_reply());
            let _ = app.on_bus(status_reply(status_in(state, phase)));
            if !under_cursor {
                let _ = app.update(Action::Down);
                assert_eq!(app.scan.jobs.cursor, 1);
            }
            let buf = draw(&app, 200, 50);
            let shown = to_text(&buf);
            let y = line_index(&shown, JOB).unwrap_or_else(|| panic!("no row: {shown}"));
            let line = shown.lines().nth(y).expect("the row");
            let x = col_of(line, text).unwrap_or_else(|| panic!("{text:?} in {line:?}"));
            assert_eq!(
                cell(&buf, x, y).fg,
                want,
                "{state} under_cursor={under_cursor}: the state cell's hue"
            );
            let id_x = col_of(line, JOB).expect("the id");
            assert_eq!(
                cell(&buf, id_x, y).fg,
                fg(theme.text_primary()),
                "{state}: the id is primary text"
            );
        }
    }
}

/// Jobs view AC42 (D19, T2): the Detail pane of a cancelled job opens with
/// the end sentence, right under the id line, and the label-value lines
/// follow it; a running job's opens with the percent and the phase line,
/// then the `now` line.
#[test]
fn detail_of_a_cancelled_job_opens_with_the_end_sentence() {
    let mut app = app();
    let mut body = status_in("cancelled", "done");
    body["elapsed_ms"] = json!(115_000);
    body["checks"]["done"] = json!(3236);
    body["checks"]["scheduled"] = json!(6468);
    body["checks"]["running"] = json!([]);
    body["stopped_reason"] = json!("cancelled");
    let _ = app.on_bus(status_reply(body));
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let rule = lines
        .iter()
        .position(|l| l.starts_with("│─"))
        .unwrap_or_else(|| panic!("no rule row under the table:\n{text}"));
    assert!(
        lines[rule + 1].contains(JOB),
        "the id line under the rule: {:?}",
        lines[rule + 1]
    );
    assert!(
        lines[rule + 2]
            .contains("Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays."),
        "the end sentence is the detail's first line: {:?}",
        lines[rule + 2]
    );
    assert!(
        lines[rule + 3].contains("wire stopped_reason: cancelled"),
        "{:?}",
        lines[rule + 3]
    );
    assert!(
        lines[rule + 4].contains("lanes requested"),
        "{:?}",
        lines[rule + 4]
    );
    let row = line_with(&text, "cancelled").expect("the row");
    assert!(
        row.contains("3236/6468 ━━━───"),
        "a finished bar keeps its fill: {row:?}"
    );

    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let rule = lines
        .iter()
        .position(|l| l.starts_with("│─"))
        .expect("the rule row");
    // The percent keeps its U+00A0 in the cell (the parity string, byte
    // for byte); a terminal draws it as a blank.
    assert!(
        lines[rule + 2].contains("75\u{a0}% · 180 of 240 checks"),
        "the live first line: {:?}",
        lines[rule + 2]
    );
    assert!(
        lines[rule + 3].contains("now http.reflected-xss, http.sqli-error"),
        "{:?}",
        lines[rule + 3]
    );
}

/// Jobs view AC43's unit half (D19, T2): the Jobs banner's error carries
/// how old the values on screen are, from the tick of the last `scan.list`
/// that folded (250 ms a tick), so a stopped core reads as stale values
/// rather than a frozen screen; without a folded list there is no clause.
#[test]
fn banner_carries_the_values_age() {
    use aitm_tui::ui::scan::values_age_text;

    assert_eq!(
        values_age_text(168, Some(0)).as_deref(),
        Some("showing values from 42s ago")
    );
    assert_eq!(
        values_age_text(168, Some(160)).as_deref(),
        Some("showing values from 2s ago")
    );
    assert_eq!(
        values_age_text(1000, Some(0)).as_deref(),
        Some("showing values from 4m10s ago")
    );
    assert_eq!(values_age_text(168, None), None);
    assert_eq!(
        values_age_text(5, Some(9)).as_deref(),
        Some("showing values from 0s ago"),
        "a tick behind never underflows"
    );

    let mut app = app();
    assert_eq!(
        app.scan.jobs.listed_ok_at_tick,
        Some(app.ticks),
        "the open's settled scan.list stamped the tick"
    );
    let _ = app.on_bus(list_reply());
    app.ticks = 168;
    let _ = app.on_bus(failed("scan.list", "scan.list", "scan: busy: full"));
    let strip = banner_row(&screen(&app)).to_string();
    assert!(
        strip.trim_end_matches(['│', ' ']).ends_with("Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x): full · showing values from 42s ago"),
        "{strip:?}"
    );
    let _ = app.on_bus(list_reply());
    assert_eq!(
        app.scan.jobs.listed_ok_at_tick,
        Some(168),
        "the fold stamps the tick"
    );
    let strip = banner_row(&screen(&app)).to_string();
    assert!(
        !strip.contains("showing values"),
        "no error, no age clause: {strip:?}"
    );
}

/// Tester, Task 4.4 (AC39 through the app; D19 T1): a `scan.list` that
/// turns the job terminal while its stored status is still live issues one
/// `scan.status` follow-up for it and stamps the fold's tick; the row reads
/// the list's state at once with the finished bar keeping its fill, while
/// the Detail pane keeps the live first line until the re-read lands; the
/// next list, both sides terminal, asks nothing.
#[test]
fn a_list_that_turns_the_job_terminal_rereads_it() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let mut list = fixture("scan.list.json");
    list["jobs"].as_array_mut().expect("rows").truncate(1);
    list["jobs"][0]["state"] = json!("cancelled");
    list["jobs"][0]["phase"] = json!("done");
    app.ticks = 40;
    let reqs = app.on_bus(reply("scan.list", "scan.list", list.clone()));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.status:{JOB}"),
            "scan.status",
            json!({ "job": JOB })
        )],
        "one re-read for the job the list turned terminal"
    );
    assert_eq!(app.scan.jobs.listed_ok_at_tick, Some(40));
    let text = screen(&app);
    let row = line_with(&text, JOB).expect("the row");
    assert!(
        row.contains("cancelled   180/240 ━━━━──  418/2000"),
        "the row follows the list, the finished bar keeps its fill (the progress column is right-aligned to its 8-cell minimum): {row:?}"
    );
    assert_eq!(
        app.scan.jobs.detail_text()[0],
        ("", "75\u{a0}% · 180 of 240 checks".to_string()),
        "the stale live read never yields a sentence"
    );

    let mut done = status_in("cancelled", "done");
    done["elapsed_ms"] = json!(115_000);
    done["checks"]["done"] = json!(3236);
    done["checks"]["scheduled"] = json!(6468);
    done["checks"]["running"] = json!([]);
    let _ = app.on_bus(status_reply(done));
    assert_eq!(
        app.scan.jobs.detail_text()[0],
        (
            "",
            "Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.".to_string()
        )
    );
    let reqs = app.on_bus(reply("scan.list", "scan.list", list));
    assert_eq!(reqs, Vec::new(), "both terminal: nothing to re-read");
}

/// Tester, Task 4.4 (D6 hostile-core bounds through the screen; D8): a
/// core reporting more checks done than scheduled renders a full bar and
/// `100 %`, never more; an auditing job with nothing scheduled renders `...`
/// with an empty bar and `Scheduling checks`; a crawling job's progress
/// reads pages over known with its percent floored; and an unknown
/// `stopped_reason` token (the parity table's P8, unrepresentable in the
/// model's closed enum) fails the status parse, so nothing of that reply
/// folds and the Jobs banner names the contract mismatch.
#[test]
fn hostile_counters_render_a_clamped_progress() {
    let mut app = app();
    let mut body = status_in("running", "auditing");
    body["checks"]["done"] = json!(u64::MAX);
    body["checks"]["scheduled"] = json!(240);
    body["checks"]["running"] = json!([]);
    let _ = app.on_bus(status_reply(body));
    let text = screen(&app);
    let row = line_with(&text, JOB).expect("the row");
    assert!(
        row.contains("auditing  18446744073709551615/240 ━━━━━━  418/2000"),
        "{row:?}"
    );
    assert_eq!(
        app.scan.jobs.detail_text()[0],
        (
            "",
            "100\u{a0}% · 18,446,744,073,709,551,615 of 240 checks".to_string()
        )
    );

    let mut body = status_in("running", "auditing");
    body["checks"]["done"] = json!(0);
    body["checks"]["scheduled"] = json!(0);
    body["checks"]["running"] = json!([]);
    let _ = app.on_bus(status_reply(body));
    let text = screen(&app);
    let row = line_with(&text, JOB).expect("the row");
    assert!(
        row.contains("... ──────  418/2000") && !row.contains('━'),
        "indeterminate: dots and an empty bar: {row:?}"
    );
    assert_eq!(
        app.scan.jobs.detail_text()[0],
        ("", "Scheduling checks".to_string())
    );

    let mut body = status_in("running", "crawling");
    body["crawl"]["pages"] = json!(46);
    body["crawl"]["queued"] = json!(12);
    body["checks"]["running"] = json!([]);
    let _ = app.on_bus(status_reply(body));
    let text = screen(&app);
    let row = line_with(&text, JOB).expect("the row");
    assert!(
        row.contains("crawling     46/58 ━━━━──  418/2000"),
        "{row:?}"
    );
    assert_eq!(
        app.scan.jobs.detail_text()[0],
        ("", "79\u{a0}% · 46 pages, 12 queued".to_string())
    );

    // P8 has no TUI form: the parse refuses the token and folds nothing.
    let before = app.scan.jobs.full.get(JOB).cloned();
    let mut body = status_in("done", "done");
    body["stopped_reason"] = json!("paused");
    let _ = app.on_bus(status_reply(body));
    assert_eq!(
        app.scan.jobs.full.get(JOB).cloned(),
        before,
        "a reply outside the contract folds nothing"
    );
    let shown = screen(&app);
    let strip = banner_row(&shown);
    assert!(
        strip.contains("scan.status: reply did not match the contract (unknown variant `paused`"),
        "{strip:?}"
    );
    assert!(!shown.contains("Stopped early"), "{shown}");
}

/// Jobs view AC60 (D19 amendment, gap 66): a `scan.list` that leaves on the
/// tick-40 timer and gets no reply sets nothing by tick 119; on tick 120
/// (`LIST_OVERDUE_TICKS` after the send) the Jobs error reads the
/// not-answering sentence and the banner carries it with the age clause
/// counted from the last fold (tick 0); the request is not cancelled (still
/// in flight, so the tick-120 timer sends no second list); `x` while the
/// sentence stands sends nothing and toasts the refusal; the late list reply
/// at tick 121 clears the banner, stamps the fold and `x` is live again.
#[test]
fn a_held_list_turns_into_the_not_answering_banner() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    app.ticks = 0;
    app.scan.jobs.listed_ok_at_tick = Some(0);

    let mut reqs = Vec::new();
    for _ in 0..40 {
        reqs = app.update(Action::Tick);
    }
    assert!(
        reqs.contains(&tagged("scan.list", "scan.list", json!({}))),
        "the fortieth tick's list: {reqs:?}"
    );
    assert_eq!(app.scan.jobs.list_sent_at_tick, Some(40));

    let mut later = Vec::new();
    for _ in 0..79 {
        later.extend(app.update(Action::Tick));
    }
    assert_eq!(app.ticks, 119);
    assert_eq!(app.scan.jobs.error, None, "tick 119: not yet overdue");

    later.extend(app.update(Action::Tick));
    assert_eq!(app.ticks, 120);
    assert_eq!(
        app.scan
            .jobs
            .error
            .as_ref()
            .map(ScanError::wording)
            .as_deref(),
        Some("scan.list: the bus did not reply in time")
    );
    let strip = banner_row(&screen(&app)).to_string();
    assert!(
        strip
            .trim_end_matches(['│', ' '])
            .ends_with("scan.list: the bus did not reply in time · showing values from 30s ago"),
        "{strip:?}"
    );
    assert_eq!(
        app.scan.jobs.list_sent_at_tick, None,
        "the detector fired once"
    );
    assert!(
        app.scan.inflight.contains("scan.list"),
        "the request is not cancelled"
    );
    assert!(
        !later.contains(&tagged("scan.list", "scan.list", json!({}))),
        "no second scan.list left between ticks 41 and 120: {later:?}"
    );
    assert!(app.scan.jobs.unanswered());

    let reqs = app.update(Action::ScanCancel);
    assert_eq!(
        reqs,
        Vec::new(),
        "x sends nothing while the core is not answering"
    );
    assert_eq!(
        toast(&app),
        "scan.cancel not sent: the bus did not reply in time"
    );

    let _ = app.update(Action::Tick);
    assert_eq!(app.ticks, 121);
    let _ = app.on_bus(list_reply());
    assert_eq!(
        app.scan.jobs.error, None,
        "the late fold clears the sentence"
    );
    let strip = banner_row(&screen(&app)).to_string();
    assert!(!strip.contains("showing values"), "{strip:?}");
    assert_eq!(app.scan.jobs.listed_ok_at_tick, Some(121));
    assert!(!app.scan.jobs.unanswered());
}

/// Jobs view Task 4.5c (1), the Part 4 security minor: the Detail pane's
/// empty-label rows (the first line, the attention rows) are cut to the
/// pane with the same trailing `…` the labelled lines get, so a long
/// `<check>: <detail>` sample ends in `…` in the pane's last cell instead
/// of clipping without a mark; at a width that fits, no mark.
#[test]
fn detail_empty_label_rows_are_cut_to_the_pane_with_an_ellipsis() {
    let mut app = app();
    let mut body = status_in("cancelled", "done");
    body["elapsed_ms"] = json!(115_000);
    body["checks"]["done"] = json!(3236);
    body["checks"]["scheduled"] = json!(6468);
    body["checks"]["running"] = json!([]);
    body["checks"]["errors"] = json!(1);
    body["checks"]["error_samples"] = json!([
        { "check": "http.sqli-error", "point": "p", "detail": "d".repeat(120) }
    ]);
    body["stopped_reason"] = json!("cancelled");
    let _ = app.on_bus(status_reply(body));

    // 200 columns: the sample row fits whole, no mark.
    let wide = screen(&app);
    let sample = line_with(&wide, "http.sqli-error: ").expect("the sample row");
    assert_eq!(
        sample,
        format!(
            "│ http.sqli-error: {}{}│",
            "d".repeat(120),
            " ".repeat(198 - 18 - 120)
        )
    );

    // 80 columns (an inner width of 78): the row is cut to 77 cells after
    // the leading space, the `…` in the pane's last cell.
    let _ = app.update(Action::Resize(80, 50));
    let narrow = text_of(&app, 80, 50);
    let sample = line_with(&narrow, "http.sqli-error: ").expect("the sample row");
    assert_eq!(sample, format!("│ http.sqli-error: {}…│", "d".repeat(59)));

    // 40 columns: the first line (the end sentence) is cut the same way.
    let _ = app.update(Action::Resize(40, 50));
    let tiny = text_of(&app, 40, 50);
    let first = line_with(&tiny, "Cancelled after").expect("the first line");
    assert_eq!(first, "│ Cancelled after 1:55; 3,236 of 6,468…│");
}
