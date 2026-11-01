//! Scanner v2 TUI, plan task 7: the Issues tab's list half (spec D6, D10,
//! D11, D13).
//!
//! Entering Issues, any filter change and every twentieth tick while a job is
//! live fetch `scan.issues {filters, limit: 512}`; the reply renders grouped
//! under the five severity headers with their `by_severity` counts; the
//! cursor landing on a row reads `scan.issue {id}` when `read` lacks the id
//! and no read is pending; a reply fills `read`, a fold prunes it to the
//! page, a terminal line for its job drops its entries (fix round D, D1).
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_poc::Severity;
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::{is_issue_id, IssueFilterKey, IssueFilters, IssuePane, ScanTab};
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
const JOB_B: &str = "scan-0b0b0b0b";
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

/// The `scan.issue.json` reply under its keyed tag, its `id` rewritten to
/// `id` so the fold-under-key check passes for any row.
fn issue_reply(id: &str) -> BusEvent {
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(id);
    BusEvent::CallTaggedOk {
        tag: format!("scan.issue:{id}"),
        name: "scan.issue".into(),
        value: issue,
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

/// T7-9, D6 (fix round D, D1): the cursor landing on a row reads it once,
/// a reply fills `read`, and `detail()` is the lookup for the row under the
/// cursor: after Down (second row read) then Up, the detail is the first
/// row's issue, never the one read last.
#[test]
fn cursor_on_a_row_reads_it_once_and_detail_follows_the_cursor() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    // The list arriving puts the cursor on its first row: the first landing.
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    assert_eq!(app.scan.issues.cursor, 0);
    assert_eq!(app.scan.issues.pending_read.as_deref(), Some(XSS));
    assert!(app.scan.issues.read.is_empty(), "a send is not a read");
    let _ = app.on_bus(issue_reply(XSS));
    assert_eq!(app.scan.issues.pending_read, None);
    assert_eq!(app.scan.issues.read.len(), 1);
    assert!(!app.scan.inflight.contains(&format!("scan.issue:{XSS}")));

    let down = app.update(Action::Down);
    assert_eq!(app.scan.issues.cursor, 1);
    assert_eq!(down, vec![issue_request(REDIRECT)]);
    let _ = app.on_bus(issue_reply(REDIRECT));
    assert_eq!(app.scan.issues.read.len(), 2);
    assert_eq!(
        app.scan.issues.detail().map(|i| i.id.as_str()),
        Some(REDIRECT)
    );

    let up = app.update(Action::Up);
    assert_eq!(app.scan.issues.cursor, 0);
    assert!(up.is_empty(), "the first row was read already: {up:?}");
    assert_eq!(
        app.scan.issues.detail().map(|i| i.id.as_str()),
        Some(XSS),
        "the detail is the row under the cursor"
    );
}

/// D1 (3): at most one `scan.issue` is in flight. Two landings before any
/// reply send one request; the reply clears `pending_read`.
#[test]
fn two_landings_before_any_reply_send_one_read() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    let down = app.update(Action::Down);
    assert_eq!(app.scan.issues.cursor, 1);
    assert!(down.is_empty(), "a read is pending: {down:?}");
    assert_eq!(app.scan.issues.pending_read.as_deref(), Some(XSS));
    let _ = app.on_bus(issue_reply(XSS));
    assert_eq!(app.scan.issues.pending_read, None);
    assert!(app.scan.inflight.is_empty());
}

/// D3: a failed `scan.issue` clears the pending read and inserts nothing,
/// so a later landing on the same row reads it again.
#[test]
fn a_failed_read_leaves_the_issue_readable() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.on_bus(BusEvent::CallTaggedFailed {
        tag: format!("scan.issue:{XSS}"),
        name: "scan.issue".into(),
        message: "scan: not_found: issue-9f8e7d6c".into(),
    });
    assert_eq!(app.scan.issues.pending_read, None);
    assert!(app.scan.issues.read.is_empty(), "a failure reads nothing");
    assert!(app.scan.inflight.is_empty());

    let down = app.update(Action::Down);
    assert_eq!(down, vec![issue_request(REDIRECT)]);
    let _ = app.on_bus(issue_reply(REDIRECT));
    let up = app.update(Action::Up);
    assert_eq!(
        up,
        vec![issue_request(XSS)],
        "the failed row is asked for again"
    );
}

/// D5: a `scan.issue` reply naming another issue than the tag's key is not
/// folded: `detail()` stays `None` and the tab's error names the mismatch.
#[test]
fn a_read_naming_another_issue_is_not_folded() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut other = fixture("scan.issue.json");
    other["id"] = json!(REDIRECT);
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: format!("scan.issue:{XSS}"),
        name: "scan.issue".into(),
        value: other,
    });
    assert_eq!(app.scan.issues.detail(), None);
    assert!(app.scan.issues.read.is_empty());
    assert_eq!(app.scan.issues.pending_read, None);
    assert_eq!(
        app.scan.issues.error.as_ref().map(|e| e.detail.as_str()),
        Some("reply named a different issue")
    );
}

/// D1 (2): a terminal line for a job drops its `read` entries, even while
/// the `J` filter points at another job, so the next landing reads afresh.
#[test]
fn a_terminal_line_drops_the_jobs_read_issues_even_when_filtered_out() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let mut other = fixture("scan.status.json");
    other["job"] = json!(JOB_B);
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: format!("scan.status:{JOB_B}"),
        name: "scan.status".into(),
        value: other,
    });
    assert_eq!(app.scan.jobs.cursor_job().map(String::as_str), Some(JOB_B));
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.on_bus(issue_reply(XSS));
    assert_eq!(app.scan.issues.read.len(), 1);

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert_eq!(app.scan.issues.filters.job.as_deref(), Some(JOB_B));
    assert_eq!(issues_requests(&reqs).len(), 1);

    let reqs = app.on_bus(BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
        "params": fixture("job.finished.json"),
    })));
    assert!(
        app.scan.issues.read.is_empty(),
        "the read issue belongs to {JOB}: {:?}",
        app.scan.issues.read.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        issues_requests(&reqs).len(),
        0,
        "the filtered refetch is already in flight: {reqs:?}"
    );
}

/// D1 (1): a page whose rows carry a 1 MiB id is dropped row by row: no
/// `scan.issue` leaves, nothing is read or in flight.
#[test]
fn a_page_of_oversized_ids_is_dropped_without_a_read() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.on_bus(issue_reply(XSS));
    let huge = format!("issue-{}", "a".repeat(1 << 20));
    let mut page = fixture("scan.issues.json");
    for row in page["issues"].as_array_mut().unwrap_or(&mut Vec::new()) {
        row["id"] = json!(huge);
    }
    let reqs = app.on_bus(issues_reply(page));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert!(app.scan.issues.list.is_empty());
    assert!(
        app.scan.issues.read.is_empty(),
        "the fold pruned the old read"
    );
    assert!(app.scan.inflight.is_empty());
    assert_eq!(app.scan.issues.pending_read, None);
}

/// D1 (2): `read` is pruned to the page on every fold, so a hundred pages
/// of a hundred distinct ids leave `read.len() <= list.len()`.
#[test]
fn read_never_outgrows_the_page() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let template = fixture("scan.issues.json")["issues"][0].clone();
    for page_no in 0..100u32 {
        let rows: Vec<Value> = (0..100u32)
            .map(|k| {
                let mut row = template.clone();
                row["id"] = json!(format!("issue-{:08x}", page_no * 100 + k));
                row
            })
            .collect();
        let first = rows[0]["id"].as_str().unwrap_or_default().to_string();
        let reqs = app.on_bus(issues_reply(json!({
            "issues": rows,
            "next_cursor": null,
            "by_severity": { "critical": 0, "high": 100, "medium": 0, "low": 0, "info": 0 },
        })));
        assert_eq!(reqs, vec![issue_request(&first)]);
        let _ = app.on_bus(issue_reply(&first));
    }
    assert_eq!(app.scan.issues.list.len(), 100);
    assert!(
        app.scan.issues.read.len() <= app.scan.issues.list.len(),
        "{} read over {} rows",
        app.scan.issues.read.len(),
        app.scan.issues.list.len()
    );
    assert!(app.scan.inflight.is_empty());
}

/// D1 (1): the issue-id wire form, `issue-` and exactly eight lowercase hex
/// digits.
#[test]
fn is_issue_id_accepts_only_eight_lowercase_hex() {
    assert!(is_issue_id("issue-9f8e7d6c"));
    assert!(!is_issue_id("issue-9F8E7D6C"));
    assert!(!is_issue_id("issue-9f8e7d6"));
    assert!(!is_issue_id(""));
}

/// D6 pin: `S` on the Jobs tab sends nothing and moves no filter.
#[test]
fn s_on_the_jobs_tab_sends_nothing() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Severity));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.issues.filters, IssueFilters::default());
}

/// D6 pin: coming back to the view on the Issues tab is entering it, so
/// `OpenScan` after `Back` sends `scan.issues` again.
#[test]
fn open_scan_after_back_from_issues_refetches() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.update(Action::Back);
    assert_ne!(app.mode, Mode::Scan);
    let reqs = app.update(Action::OpenScan);
    assert_eq!(app.scan.tab, ScanTab::Issues);
    assert_eq!(issues_requests(&reqs), vec![&json!({ "limit": 512 })]);
}

/// D6 pin: with the Detail pane focused, `Down` moves no list cursor and
/// sends no `scan.issue`.
#[test]
fn detail_focused_down_sends_no_read() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.on_bus(issue_reply(XSS));
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(app.scan.issues.pane, IssuePane::Detail);
    let reqs = app.update(Action::Down);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.issues.cursor, 0);
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

/// D2: row strings are bounded once at fold time. A 1 MiB `name` becomes a
/// row name of at most 40 cells ending in an ellipsis, drawn as 39 `N`s and
/// `…` at 200x50; a 600-row page is cut to `ISSUES_PAGE_LIMIT`.
#[test]
fn rows_are_bounded_at_fold_time() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let mut page = fixture("scan.issues.json");
    page["issues"][0]["name"] = json!("N".repeat(1 << 20));
    let _ = app.on_bus(issues_reply(page));
    assert_eq!(app.scan.issues.rows.len(), 2);
    let name = app.scan.issues.rows[0].name.as_str();
    assert_eq!(name.chars().count(), 40, "{name:?}");
    assert!(name.ends_with('…'), "{name:?}");
    let text = screen(&app);
    let line = line_with(&text, "NNNN").unwrap_or_else(|| panic!("no row: {text}"));
    assert_eq!(line.matches('N').count(), 39, "{line:?}");
    assert!(line.contains("N…"), "{line:?}");

    let template = fixture("scan.issues.json")["issues"][0].clone();
    let rows: Vec<Value> = (0..600u32)
        .map(|k| {
            let mut row = template.clone();
            row["id"] = json!(format!("issue-{k:08x}"));
            row
        })
        .collect();
    let _ = app.on_bus(issues_reply(json!({
        "issues": rows,
        "next_cursor": null,
        "by_severity": { "critical": 0, "high": 600, "medium": 0, "low": 0, "info": 0 },
    })));
    assert_eq!(app.scan.issues.list.len(), 512);
    assert_eq!(app.scan.issues.rows.len(), 512);
}
