//! Scanner v2 TUI, plan task 7: the Issues tab's list half (spec D6, D10,
//! D11, D13).
//!
//! Entering Issues, any filter change and every twentieth tick while a job is
//! live fetch `scan.issues {filters, limit: 512}`; the reply renders grouped
//! under the five severity headers with their `by_severity` counts; the
//! cursor landing on a row fetches `scan.issue {id}` once per id until a
//! terminal line for its job forgets it.
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_poc::Severity;
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::{IssueFilterKey, IssueFilters, ScanTab};
use common::*;
use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.issues",
    "scan.issue",
    "scan.cancel",
];

const JOB: &str = "scan-1a2b3c4d";
const XSS: &str = "issue-9f8e7d6c";
const REDIRECT: &str = "issue-4c3b2a19";

/// A connected v2 app at 200x50 on the Profiles tab, the `scan.list` its
/// open issued already settled empty, so nothing is in flight.
fn app() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    let _ = app.update(Action::OpenScan);
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: json!({ "jobs": [] }),
    });
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.tab, ScanTab::Profiles);
    assert!(
        app.scan.inflight.is_empty(),
        "nothing in flight at the start"
    );
    app
}

/// The `scan.issues` request the Issues tab sends under its single-slot tag.
fn issues_request(args: Value) -> BusRequest {
    BusRequest::CallTagged {
        tag: "scan.issues".into(),
        name: "scan.issues".into(),
        args,
    }
}

/// The `scan.issue {id}` request under its keyed tag.
fn issue_request(id: &str) -> BusRequest {
    BusRequest::CallTagged {
        tag: format!("scan.issue:{id}"),
        name: "scan.issue".into(),
        args: json!({ "id": id }),
    }
}

/// A `scan.issues` reply under its tag.
fn issues_reply(body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: "scan.issues".into(),
        name: "scan.issues".into(),
        value: body,
    }
}

/// The `scan.status.json` reply for `JOB` under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: format!("scan.status:{JOB}"),
        name: "scan.status".into(),
        value: body,
    }
}

fn issues_requests(reqs: &[BusRequest]) -> Vec<&Value> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { name, args, .. } if name == "scan.issues" => Some(args),
            _ => None,
        })
        .collect()
}

fn screen(app: &App) -> String {
    text_of(app, 200, 50)
}

/// T7-9, D6: `ScanTab(Issues)` sends exactly one `scan.issues {limit: 512}`
/// (no filter is set, so only the page size travels).
#[test]
fn entering_issues_fetches_with_the_filters() {
    let mut app = app();
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(reqs, vec![issues_request(json!({ "limit": 512 }))]);
    assert_eq!(app.scan.tab, ScanTab::Issues);
    assert_eq!(
        app.scan.issues.fetched_at_tick,
        Some(0),
        "the fetch stamps the tab as opened"
    );
    assert!(app.scan.inflight.contains("scan.issues"));
}

/// T7-9, D11: `scan.issues.json` renders the five headers with their
/// `by_severity` counts in severity order, and each row under its header
/// with its location, point and status.
#[test]
fn issues_render_grouped_under_severity_headers_with_counts() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(app.scan.issues.list.len(), 2);
    assert_eq!(app.scan.issues.by_severity.high, 1);
    assert_eq!(app.scan.issues.next_cursor, None);

    let text = screen(&app);
    let headers = ["CRITICAL 0", "HIGH 1", "MEDIUM 1", "LOW 0", "INFO 0"];
    let rows: Vec<usize> = headers
        .iter()
        .map(|h| line_index(&text, h).unwrap_or_else(|| panic!("no header {h:?}: {text}")))
        .collect();
    assert!(
        rows.windows(2).all(|w| w[0] < w[1]),
        "the headers read critical, high, medium, low, info: {rows:?}"
    );

    let xss = line_index(&text, "Reflected cross-site scripting")
        .unwrap_or_else(|| panic!("no XSS row: {text}"));
    assert!(
        rows[1] < xss && xss < rows[2],
        "the high issue sits between HIGH and MEDIUM: {xss} in {rows:?}"
    );
    let xss_line = text.lines().nth(xss).unwrap_or_default();
    for literal in ["GET /search", "query:q", "open"] {
        assert!(
            xss_line.contains(literal),
            "the XSS row lacks {literal:?}: {xss_line:?}"
        );
    }
    let redirect = line_index(&text, "Open redirect").unwrap_or_else(|| panic!("no row: {text}"));
    assert!(
        rows[2] < redirect && redirect < rows[3],
        "the medium issue sits between MEDIUM and LOW: {redirect} in {rows:?}"
    );
    assert!(
        !text.contains("no issues yet"),
        "a populated list is not the empty state"
    );
}

/// T7-9, D11: `S` cycles the severity minimum to `low`, refetches with
/// `severity_min: "low"` and prints it in the filter banner; `R` clears
/// every filter and refetches with the page size alone.
#[test]
fn filters_cycle_and_refetch() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Severity));
    assert_eq!(app.scan.issues.filters.severity_min, Some(Severity::Low));
    assert_eq!(
        reqs,
        vec![issues_request(
            json!({ "severity_min": "low", "limit": 512 })
        )]
    );
    let text = screen(&app);
    assert!(
        text.contains("S low"),
        "the banner prints the active severity filter: {text}"
    );
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    // The other keys cycle their own filter and travel under the serde name.
    let _ = app.update(Action::ScanFilter(IssueFilterKey::Confidence));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.update(Action::ScanFilter(IssueFilterKey::Lane));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Status));
    let args = issues_requests(&reqs);
    assert_eq!(args.len(), 1, "{reqs:?}");
    assert_eq!(
        args[0],
        &json!({
            "severity_min": "low",
            "confidence_min": "firm",
            "lane": "http",
            "status": "open",
            "limit": 512,
        })
    );
    let text = screen(&app);
    for literal in ["S low", "C firm", "L http", "T open"] {
        assert!(
            text.contains(literal),
            "the banner lacks {literal:?}: {text}"
        );
    }
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let reqs = app.update(Action::ScanFilterReset);
    assert_eq!(app.scan.issues.filters, IssueFilters::default());
    assert_eq!(reqs, vec![issues_request(json!({ "limit": 512 }))]);
}

/// D11: `J` toggles the job filter between the Jobs cursor's job and none.
#[test]
fn j_toggles_the_job_filter_to_the_jobs_cursor() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert_eq!(app.scan.issues.filters.job.as_deref(), Some(JOB));
    assert_eq!(
        reqs,
        vec![issues_request(json!({ "job": JOB, "limit": 512 }))]
    );
    assert!(screen(&app).contains(&format!("job {JOB}")));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert_eq!(app.scan.issues.filters.job, None);
    assert_eq!(reqs, vec![issues_request(json!({ "limit": 512 }))]);
}

/// T7-9, D6: the cursor landing on a row sends `scan.issue {id}` once; a
/// later landing on the same id sends nothing.
#[test]
fn cursor_on_a_row_fetches_the_issue_once() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    // The list arriving puts the cursor on its first row: the first landing.
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    assert_eq!(app.scan.issues.cursor, 0);

    let down = app.update(Action::Down);
    assert_eq!(app.scan.issues.cursor, 1);
    assert_eq!(down, vec![issue_request(REDIRECT)]);

    let up = app.update(Action::Up);
    assert_eq!(app.scan.issues.cursor, 0);
    assert!(up.is_empty(), "the first row was asked for already: {up:?}");
    assert!(app.scan.issues.fetched.contains(XSS));
    assert!(app.scan.issues.fetched.contains(REDIRECT));

    // The detail reply under its keyed tag fills `detail`.
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: format!("scan.issue:{XSS}"),
        name: "scan.issue".into(),
        value: fixture("scan.issue.json"),
    });
    assert_eq!(
        app.scan.issues.detail.as_ref().map(|i| i.id.as_str()),
        Some(XSS)
    );
    assert!(!app.scan.inflight.contains(&format!("scan.issue:{XSS}")));
}

/// D6: a terminal line for a job forgets the ids it fetched, so the next
/// landing asks again; the other job's ids stay.
#[test]
fn a_terminal_line_forgets_the_jobs_fetched_issues() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.fetched.len(), 2);
    // Settle both detail reads, so the tag dedupe is not what holds a
    // re-read back below.
    for id in [XSS, REDIRECT] {
        let mut issue = fixture("scan.issue.json");
        issue["id"] = json!(id);
        let _ = app.on_bus(BusEvent::CallTaggedOk {
            tag: format!("scan.issue:{id}"),
            name: "scan.issue".into(),
            value: issue,
        });
    }
    assert!(app.scan.inflight.is_empty());
    assert_eq!(app.scan.issues.fetched.len(), 2, "a reply keeps the id");

    let reqs = app.on_bus(BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
        "params": fixture("job.finished.json"),
    })));
    assert!(
        app.scan.issues.fetched.is_empty(),
        "both issues belong to {JOB}: {:?}",
        app.scan.issues.fetched
    );
    // The line also refreshes the list (D6 third row); its reply lands the
    // cursor again and asks for the row once more.
    assert!(issues_requests(&reqs).len() == 1, "{reqs:?}");
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(REDIRECT)]);
}

/// T7-9, D6: with a running job, the Issues tab refetches every 20 ticks;
/// once the job is terminal the timer is quiet.
#[test]
fn issues_refresh_every_twenty_ticks_while_a_job_is_live() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(issues_requests(&reqs).len(), 1);
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let mut total = 0;
    for _ in 0..20 {
        let reqs = app.update(Action::Tick);
        total += issues_requests(&reqs).len();
        // Keep the status poll settled so it never blocks the count.
        let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    }
    assert_eq!(total, 1, "one scan.issues per 20 ticks while a job is live");
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let mut done = fixture("scan.status.json");
    done["state"] = json!("done");
    done["phase"] = json!("done");
    let _ = app.on_bus(status_reply(done));
    let mut after = 0;
    for _ in 0..40 {
        after += issues_requests(&app.update(Action::Tick)).len();
    }
    assert_eq!(after, 0, "a terminal job does not drive the issues timer");
}
