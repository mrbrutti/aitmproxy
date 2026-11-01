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

use aitm_scan_model::{BySeverity, JobStatus, JobSummary};
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::{
    detail_lines, probe_bar, probe_fill, row, severity_bar, severity_runs, JobsState, ScanTab,
    PROFILE_MAX, TARGETS_MAX,
};
use aitm_tui::ui::text::width;
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
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, tools, None);
    let _ = app.update(Action::OpenScan);
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: json!({ "jobs": [] }),
    });
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    assert_eq!(app.mode, Mode::Scan);
    assert!(
        app.scan.inflight.is_empty(),
        "nothing in flight at the start"
    );
    app
}

fn app() -> App {
    app_with(TOOLS)
}

/// A `scan.status` reply for `JOB` under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: format!("scan.status:{JOB}"),
        name: "scan.status".into(),
        value: body,
    }
}

/// The `scan.list.json` reply under its single-slot tag.
fn list_reply() -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: fixture("scan.list.json"),
    }
}

/// The `scan.status.json` fixture with its state and phase replaced.
fn status_in(state: &str, phase: &str) -> Value {
    let mut body = fixture("scan.status.json");
    body["state"] = json!(state);
    body["phase"] = json!(phase);
    body
}

fn screen(app: &App) -> String {
    text_of(app, 200, 50)
}

/// The strip-and-banner row of the Scan view.
fn banner_row(text: &str) -> &str {
    line_with(text, "1 Profiles").unwrap_or_default()
}

fn cancel_request() -> BusRequest {
    BusRequest::CallTagged {
        tag: format!("scan.cancel:{JOB}"),
        name: "scan.cancel".into(),
        args: json!({ "job": JOB }),
    }
}

/// T7-1, T7-8: one `scan.status` renders the row with every literal the
/// plan names, profile and targets included.
#[test]
fn status_renders_the_row_literals() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let text = screen(&app);
    let line = line_with(&text, JOB).unwrap_or_else(|| panic!("no row for {JOB}: {text}"));
    for literal in [
        "418/2000 ━━────",
        "80/120",
        "running/audit",
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
    let header = line_with(&text, "state/phase").unwrap_or_default();
    for col in [
        "job", "profile", "targets", "probes", "points", "issues", "el.",
    ] {
        assert!(header.contains(col), "the header lacks {col:?}: {header:?}");
    }
    assert!(
        line_index(&text, "state/phase") < line_index(&text, JOB),
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

    let reqs = app.on_bus(BusEvent::CallTaggedOk {
        tag: format!("scan.cancel:{JOB}"),
        name: "scan.cancel".into(),
        value: fixture("scan.cancel.json"),
    });
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
}

/// Fix round C, C20 (D6 hostile-core bounds): the row is bounded when it is
/// built, not per frame. A 1 MiB `targets[0]` and a long profile name give
/// a row whose text is at most four target cells wide and whose profile is
/// cut to the column cap, more than four targets are counted rather than
/// joined, the table still draws the targets cell at most `TARGETS_MAX`
/// wide with an ellipsis, and the Detail pane's length is counted without
/// building its lines.
#[test]
fn rows_are_bounded_at_construction_not_at_render() {
    let mut app = app();
    let mut body = fixture("scan.status.json");
    body["targets"] = json!(["h".repeat(1 << 20)]);
    body["profile_name"] = json!("p".repeat(300));
    let _ = app.on_bus(status_reply(body));

    let built = app.scan.jobs.row_of(JOB);
    assert!(
        width(&built.targets) <= 4 * TARGETS_MAX,
        "targets text is {} cells",
        width(&built.targets)
    );
    assert_eq!(width(&built.profile), PROFILE_MAX);
    assert!(built.profile.ends_with('…'));

    let text = screen(&app);
    let header = line_with(&text, "state/phase").unwrap_or_default();
    let from = col_of(header, "targets").expect("a targets column");
    let to = col_of(header, "state/phase").expect("a state column");
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
        ..status.clone()
    };
    let crowded = row(&many.summary(), Some(&many));
    assert_eq!(
        crowded.targets,
        "http://h1.test http://h2.test http://h3.test http://h4.test +2"
    );

    let mut jobs = JobsState::default();
    jobs.fold_status(status.clone());
    assert_eq!(jobs.detail_len(), 1 + detail_lines(&status).len());
    assert_eq!(
        jobs.detail_text(),
        detail_lines(&status),
        "the view and the count read the same lines"
    );
    let mut bare = JobsState::default();
    bare.order.push(JOB.to_string());
    assert_eq!(
        bare.detail_text(),
        vec![("", "waiting for scan.status...".to_string())],
        "no status: the placeholder line"
    );
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

/// The row builder: `...` until a full status is known; the counters in the
/// plan's `<sent>/<budget>` and `<audited>/<found>` shapes.
#[test]
fn row_reads_dots_until_the_status_is_known() {
    let status: JobStatus =
        serde_json::from_value(fixture("scan.status.json")).expect("the fixture parses");
    let summary: JobSummary = status.summary();
    let bare = row(&summary, None);
    assert_eq!(bare.id, JOB);
    assert_eq!(bare.profile, "...");
    assert_eq!(bare.targets, "...");
    assert_eq!(bare.probes, "418/2000");
    assert_eq!(bare.points, "80/120");
    assert_eq!(bare.state_phase, "running/audit");
    assert_eq!(bare.elapsed, "42s");
    assert_eq!(bare.issues.high, 1);
    let full = row(&summary, Some(&status));
    assert_eq!(full.profile, "standard");
    assert_eq!(full.targets, "http://127.0.0.1:8080");
}

/// The bars: progress rounds up so any probe shows, a zero budget is empty;
/// the severity stack gives every non-zero severity a cell, graver first.
/// The text bars are composed from the typed `probe_fill` and
/// `severity_runs` the view styles (fix round C, C21, C23).
#[test]
fn bars_are_box_drawing_cells() {
    assert_eq!(probe_fill(418, 2000, 6), 2);
    assert_eq!(probe_fill(0, 2000, 6), 0);
    assert_eq!(probe_fill(5, 0, 4), 0);
    assert_eq!(probe_fill(3000, 2000, 4), 4);
    assert_eq!(probe_bar(418, 2000, 6), "━━────");
    assert_eq!(probe_bar(0, 2000, 6), "──────");
    assert_eq!(probe_bar(2000, 2000, 6), "━━━━━━");
    assert_eq!(probe_bar(5, 0, 4), "────");
    assert_eq!(probe_bar(3000, 2000, 4), "━━━━");

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
