//! Scanner v2 TUI, plan task 7: the Issues tab's list half (spec D6, D10,
//! D11, D13). The Detail pane's tests are `scan_v2_issue_detail.rs` (fix
//! round G, G8).
//!
//! Entering Issues, any filter change and, while a job is live, twenty
//! ticks after the last fetch read `scan.issues {filters, limit: 512}`;
//! the reply renders grouped under the five severity headers with their
//! `by_severity` counts; the cursor landing on a row reads `scan.issue
//! {id}` when `read` lacks the id and no read is pending; a reply fills
//! `read`, a fold prunes it to the page and caps it at `READ_MAX`, a
//! terminal line for its job drops its entries (fix round D, D1); a
//! degraded bus is named in the banner.
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_poc::Severity;
use aitm_scan_model::IssueStatus;
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::scan::{is_issue_id, IssueFilterKey, IssueFilters, ScanTab, READ_MAX};
use common::*;
use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.issues",
    "scan.issue",
    "scan.issue.update",
    "scan.cancel",
];

const JOB: &str = "scan-1a2b3c4d";
const JOB_B: &str = "scan-0b0b0b0b";
const XSS: &str = "issue-9f8e7d6c";
const REDIRECT: &str = "issue-4c3b2a19";
/// A connected v2 app at 200x50 on the Profiles tab offering `tools`, the
/// `scan.list` its open issued already settled empty, so nothing is in
/// flight.
fn app_with(tools: &[&str]) -> App {
    opened_minimal(tools)
}

/// [`app_with`] offering every verb the Issues tab uses.
fn app() -> App {
    app_with(TOOLS)
}

/// `TOOLS` without `verb`.
fn tools_without(verb: &str) -> Vec<&'static str> {
    TOOLS.iter().copied().filter(|t| *t != verb).collect()
}

/// The strip row's banner: the text after the tab strip, trimmed of the
/// box edge and padding.
fn strip_banner(text: &str) -> &str {
    line_with(text, "1 Profiles")
        .unwrap_or_default()
        .trim_end_matches(['│', ' '])
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
    tagged(
        &format!("scan.issue:{id}"),
        "scan.issue",
        json!({ "id": id }),
    )
}

/// A `scan.issues` reply under its tag.
fn issues_reply(body: Value) -> BusEvent {
    reply("scan.issues", "scan.issues", body)
}

/// The `scan.issue.json` reply under its keyed tag, its `id` rewritten to
/// `id` so the fold-under-key check passes for any row.
fn issue_reply(id: &str) -> BusEvent {
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(id);
    reply(&format!("scan.issue:{id}"), "scan.issue", issue)
}

/// The `scan.status.json` reply for `JOB` under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    reply(&format!("scan.status:{JOB}"), "scan.status", body)
}

fn issues_requests(reqs: &[BusRequest]) -> Vec<&Value> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { name, args, .. } if name == "scan.issues" => Some(args),
            _ => None,
        })
        .collect()
}

/// A `scan.issues` page of `n` rows cut from the fixture's first row, the
/// `k`th row's id being `id_of(k)`, every row high so the tally reads it.
fn page_of(n: usize, id_of: impl Fn(usize) -> String) -> Value {
    let template = fixture("scan.issues.json")["issues"][0].clone();
    let rows: Vec<Value> = (0..n)
        .map(|k| {
            let mut row = template.clone();
            row["id"] = json!(id_of(k));
            row
        })
        .collect();
    json!({
        "issues": rows,
        "next_cursor": null,
        "by_severity": { "critical": 0, "high": n, "medium": 0, "low": 0, "info": 0 },
    })
}

/// The Issues filter line as drawn in the list pane: the row cut at the
/// pane rule (the detail pane shares the row), without the trailing pane
/// padding, so a test pins the whole literal.
fn filter_line(text: &str) -> &str {
    let line = line_with(text, "filters:").unwrap_or_default();
    // The first `│` is the box edge, the second the pane rule.
    let after_edge = line.char_indices().nth(1).map_or(0, |(b, _)| b);
    let end = line[after_edge..]
        .find('│')
        .map_or(line.len(), |b| after_edge + b);
    line[..end].trim_end_matches(' ')
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
    // The row under the cursor, with the measured spacing (fix round D,
    // D13): mark, glyph pair, name, location, point, status.
    let xss_line = text.lines().nth(xss).unwrap_or_default();
    assert!(
        xss_line.starts_with("│>●● Reflected cross-site scripting  GET /search  query:q     open"),
        "the XSS row: {xss_line:?}"
    );
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
    assert_eq!(
        filter_line(&screen(&app)),
        "│ filters: S low · C none · L none · T none",
        "the filter line prints the active severity filter"
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
    assert_eq!(
        filter_line(&screen(&app)),
        "│ filters: S low · C firm · L http · T open"
    );
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
    assert_eq!(
        filter_line(&screen(&app)),
        format!("│ filters: job {JOB} · S none · C none · L none · T none")
    );
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
/// reply send one request; the reply settles it and (fix round E, E10)
/// retries the held landing, so the one read in flight is now the row
/// under the cursor's.
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
    let reqs = app.on_bus(issue_reply(XSS));
    assert_eq!(reqs, vec![issue_request(REDIRECT)]);
    assert_eq!(app.scan.issues.pending_read.as_deref(), Some(REDIRECT));
    assert_eq!(app.scan.inflight.len(), 1, "still one read in flight");
    assert!(!app.scan.inflight.contains(&format!("scan.issue:{XSS}")));
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

/// Fix round E, E10: a landing suppressed while a read was pending is
/// retried once when that read lands. The list arriving reads row 0; `Down`
/// to row 1 sends nothing (a read is pending); row 0's reply then leaves
/// exactly one `scan.issue` for row 1, the row under the cursor; that
/// row's reply retries nothing further.
#[test]
fn a_landing_suppressed_by_a_pending_read_is_retried_when_the_read_lands() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    let down = app.update(Action::Down);
    assert!(down.is_empty(), "a read is pending: {down:?}");
    assert_eq!(app.scan.issues.cursor, 1);

    let reqs = app.on_bus(issue_reply(XSS));
    assert_eq!(
        reqs,
        vec![issue_request(REDIRECT)],
        "the row under the cursor is read once the pending read lands"
    );
    assert_eq!(app.scan.issues.pending_read.as_deref(), Some(REDIRECT));
    // The reply for the row under the cursor retries nothing further.
    let reqs = app.on_bus(issue_reply(REDIRECT));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.issues.read.len(), 2);
}

/// Fix round E, E10, the failure half: a failed reply never retries the
/// held landing (no retry loop). A fresh list lands on row 0, `Down` is
/// held by the pending read, and the failure of row 0's read leaves
/// nothing; the next landing asks again.
#[test]
fn a_failed_pending_read_does_not_retry_the_held_landing() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let _ = app.update(Action::Down);
    let reqs = app.on_bus(BusEvent::CallTaggedFailed {
        tag: format!("scan.issue:{XSS}"),
        name: "scan.issue".into(),
        message: "scan: not_found: gone".into(),
    });
    assert!(reqs.is_empty(), "a failed read retries nothing: {reqs:?}");
    assert_eq!(app.scan.issues.pending_read, None);
    let reqs = app.update(Action::Up);
    assert_eq!(reqs, vec![issue_request(XSS)]);
}

/// Fix round E, E11: a `scan.issue` reply for an id the page no longer
/// lists is not inserted, so `read.len() <= list.len()` holds between
/// folds too. Land on X, refetch to a page without X, fold X's reply:
/// `read` stays empty.
#[test]
fn a_read_for_an_unlisted_id_is_not_inserted() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    let other = page_of(2, |k| format!("issue-0000000{k}"));
    let reqs = app.on_bus(issues_reply(other));
    assert!(
        reqs.is_empty(),
        "the pending read blocks a new one: {reqs:?}"
    );
    let _ = app.on_bus(issue_reply(XSS));
    assert!(
        app.scan.issues.read.is_empty(),
        "an unlisted id is not read: {:?}",
        app.scan.issues.read.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        app.scan.issues.pending_read.as_deref(),
        Some("issue-00000000")
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
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", other));
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
    let _ = app.on_bus(reply(&format!("scan.status:{JOB_B}"), "scan.status", other));
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
    for page_no in 0..100usize {
        let id_of = |k: usize| format!("issue-{:08x}", page_no * 100 + k);
        let first = id_of(0);
        let reqs = app.on_bus(issues_reply(page_of(100, id_of)));
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

/// Fix round E, E1 (D6 hostile-core bounds): `read` keeps at most `READ_MAX`
/// entries between folds, the oldest inserted leaving first, so a page of
/// a hundred rows walked and read one by one never holds more than 64 full
/// issues; the row under the cursor is always among them.
#[test]
fn read_keeps_at_most_read_max_entries_dropping_the_oldest() {
    assert_eq!(READ_MAX, 64);
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let ids: Vec<String> = (0..100u32).map(|k| format!("issue-{k:08x}")).collect();
    let reqs = app.on_bus(issues_reply(page_of(100, |k| ids[k].clone())));
    assert_eq!(reqs, vec![issue_request(&ids[0])]);
    let _ = app.on_bus(issue_reply(&ids[0]));
    for (k, id) in ids.iter().enumerate().take(71).skip(1) {
        let reqs = app.update(Action::Down);
        assert_eq!(reqs, vec![issue_request(id)], "row {k}");
        let _ = app.on_bus(issue_reply(id));
    }
    assert_eq!(app.scan.issues.read.len(), READ_MAX);
    assert!(
        !app.scan.issues.read.contains(&ids[0]),
        "the oldest read left first"
    );
    assert!(
        !app.scan.issues.read.contains(&ids[6]),
        "the seven oldest are gone"
    );
    assert!(app.scan.issues.read.contains(&ids[7]));
    assert!(app.scan.issues.read.contains(&ids[70]));
    assert_eq!(
        app.scan.issues.detail().map(|i| i.id.as_str()),
        Some(ids[70].as_str())
    );
    // The evicted row is unread again: landing on it reads it once more;
    // a landing on a row still read sends nothing, so nothing is answered.
    for _ in 0..70 {
        let reqs = app.update(Action::Up);
        let id = &ids[app.scan.issues.cursor];
        if !reqs.is_empty() {
            assert_eq!(reqs, vec![issue_request(id)]);
            let _ = app.on_bus(issue_reply(id));
        }
    }
    assert_eq!(app.scan.issues.cursor, 0);
    assert!(app.scan.issues.read.contains(&ids[0]));
    assert_eq!(app.scan.issues.read.len(), READ_MAX);
}

/// Fix round G, G3 (G4's edge): eviction never drops the row under the
/// cursor. With `READ_MAX` rows read, a landing on the oldest read row
/// moves it to the back of the order, so the next insert evicts the row
/// after it; coming back to the oldest row finds it still read.
#[test]
fn a_landing_on_a_read_row_keeps_it_from_the_next_eviction() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let ids: Vec<String> = (0..100u32).map(|k| format!("issue-{k:08x}")).collect();
    let _ = app.on_bus(issues_reply(page_of(100, |k| ids[k].clone())));
    let _ = app.on_bus(issue_reply(&ids[0]));
    for id in ids.iter().take(READ_MAX).skip(1) {
        let _ = app.update(Action::Down);
        let _ = app.on_bus(issue_reply(id));
    }
    assert_eq!(app.scan.issues.read.len(), READ_MAX);
    assert_eq!(app.scan.issues.cursor, READ_MAX - 1);
    // Back to the oldest read row: nothing is sent (it is read), and the
    // landing moves it to the back of the eviction order.
    let reqs = app.update(Action::Home);
    assert!(reqs.is_empty(), "row 0 is still read: {reqs:?}");
    assert_eq!(app.scan.issues.cursor, 0);
    // A fresh read lands: the row after it is the oldest now.
    let _ = app.update(Action::End);
    assert_eq!(app.scan.issues.cursor, 99);
    let _ = app.on_bus(issue_reply(&ids[99]));
    assert_eq!(app.scan.issues.read.len(), READ_MAX);
    assert!(
        app.scan.issues.read.contains(&ids[0]),
        "the row the cursor landed on last survives the eviction"
    );
    assert!(
        !app.scan.issues.read.contains(&ids[1]),
        "the row after it was the oldest"
    );
    let reqs = app.update(Action::Home);
    assert!(reqs.is_empty(), "row 0 needs no second read: {reqs:?}");
    assert_eq!(
        app.scan.issues.detail().map(|i| i.id.as_str()),
        Some(ids[0].as_str())
    );
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

/// T7-9, D6: with a running job, the Issues tab refetches twenty ticks
/// after its last `scan.issues` left (entered at tick 0, so at tick 20 and
/// not before; fix round D, D7); once the job is terminal the timer is
/// quiet.
#[test]
fn issues_refresh_every_twenty_ticks_while_a_job_is_live() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(issues_requests(&reqs).len(), 1);
    assert_eq!(app.scan.issues.fetched_at_tick, Some(0));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let mut fired_at = Vec::new();
    for tick in 1..=20u64 {
        let reqs = app.update(Action::Tick);
        if !issues_requests(&reqs).is_empty() {
            fired_at.push(tick);
        }
        // Keep the status poll settled so it never blocks the count.
        let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    }
    assert_eq!(
        fired_at,
        vec![20],
        "one scan.issues, twenty ticks after the stamp"
    );
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

    let _ = app.on_bus(issues_reply(page_of(600, |k| format!("issue-{k:08x}"))));
    assert_eq!(app.scan.issues.list.len(), 512);
    assert_eq!(app.scan.issues.rows.len(), 512);
}

/// Fix round G, G10: a name made of a million tabs is stripped at fold, so
/// the row's other columns sit where the neighbouring row's do (a control
/// character is charged one cell by `truncate` and `width` alike, and the
/// fold strips them before the row is built).
#[test]
fn a_tab_only_name_does_not_shift_the_other_columns() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let mut page = fixture("scan.issues.json");
    page["issues"][0]["name"] = json!("\t".repeat(1 << 20));
    let _ = app.on_bus(issues_reply(page));
    assert_eq!(app.scan.issues.rows.len(), 2);
    assert_eq!(app.scan.issues.rows[0].name, "", "the tabs are stripped");
    let text = screen(&app);
    let tabbed = line_with(&text, "GET /search").unwrap_or_else(|| panic!("no row: {text}"));
    let other = line_with(&text, "GET /go").unwrap_or_else(|| panic!("no row: {text}"));
    assert!(!tabbed.contains('\t'), "{tabbed:?}");
    assert_eq!(
        col_of(tabbed, "open"),
        col_of(other, "open"),
        "the status column lines up:\n{tabbed}\n{other}"
    );
}

/// D4 (spec D11, amended): on a v2 bus with `scan.issues` but no
/// `scan.issue`, the Issues strip row names the missing verb, and a cursor
/// landing sends nothing (the quiet `scan_poll` path, ruling b).
#[test]
fn a_bus_without_scan_issue_is_named_in_the_issues_banner() {
    let mut app = app_with(&tools_without("scan.issue"));
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(
        issues_requests(&reqs).len(),
        1,
        "scan.issues is still served"
    );
    let text = screen(&app);
    let strip = strip_banner(&text);
    assert!(
        strip.ends_with("scan.issue is not on this bus"),
        "the strip row names the missing read verb: {strip:?}"
    );
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert!(
        reqs.is_empty(),
        "a landing without scan.issue sends nothing: {reqs:?}"
    );
    assert_eq!(app.scan.issues.pending_read, None);
    assert_eq!(app.scan.issues.list.len(), 2, "the list is still shown");
}

/// Fix round E, E17 (D11): the Issues tab's degraded text names every verb
/// the tab uses, so a v2 bus without `scan.issue.update` says so in the
/// strip row while the list and the read are still served; `c` then sends
/// nothing and the banner already explains why.
#[test]
fn a_bus_without_scan_issue_update_is_named_in_the_issues_banner() {
    let mut app = app_with(&tools_without("scan.issue.update"));
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(issues_requests(&reqs).len(), 1);
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)], "the read is still served");
    let text = screen(&app);
    let strip = strip_banner(&text);
    assert!(
        strip.ends_with("scan.issue.update is not on this bus"),
        "the strip row names the missing update verb: {strip:?}"
    );
    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::Confirmed));
    assert!(reqs.is_empty(), "no verb, no call: {reqs:?}");
}

/// D7 (spec D6): the Issues timer counts from `fetched_at_tick`, so a tab
/// entered at tick 19 is not fetched again at tick 20; the next fetch is at
/// tick 39, twenty ticks after the stamp.
#[test]
fn issues_timer_counts_from_the_last_fetch_not_the_tick_modulo() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    for _ in 0..19 {
        let reqs = app.update(Action::Tick);
        assert_eq!(issues_requests(&reqs).len(), 0, "{reqs:?}");
        let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    }
    let reqs = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(issues_requests(&reqs).len(), 1);
    assert_eq!(app.scan.issues.fetched_at_tick, Some(19));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));

    let mut fired_at = Vec::new();
    for tick in 20..=40u64 {
        let reqs = app.update(Action::Tick);
        if !issues_requests(&reqs).is_empty() {
            fired_at.push(tick);
            let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
        }
        let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    }
    assert_eq!(fired_at, vec![39], "twenty ticks after the stamp, once");
    assert_eq!(app.scan.issues.fetched_at_tick, Some(39));
}

/// A `scan.issues` page whose `k`th row is the fixture's first row with
/// the id and name of `rows[k]`, every row high so the tally reads it.
fn named_page(rows: &[(&str, &str)]) -> Value {
    let template = fixture("scan.issues.json")["issues"][0].clone();
    let issues: Vec<Value> = rows
        .iter()
        .map(|(id, name)| {
            let mut row = template.clone();
            row["id"] = json!(id);
            row["name"] = json!(name);
            row
        })
        .collect();
    json!({
        "issues": issues,
        "next_cursor": null,
        "by_severity": { "critical": 0, "high": rows.len(), "medium": 0, "low": 0, "info": 0 },
    })
}

/// [`issue_reply`] with the issue's `name` rewritten too, so the row the
/// fold rebuilds from the reply keeps the name the page gave it.
fn named_issue_reply(id: &str, name: &str) -> BusEvent {
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(id);
    issue["name"] = json!(name);
    reply(&format!("scan.issue:{id}"), "scan.issue", issue)
}

/// The Scan box's rows split at the pane rule: `(list, detail)` text per
/// screen line, each trimmed, for the lines that have both panes.
fn panes(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('│');
            let _edge = parts.next()?;
            let list = parts.next()?;
            let detail = parts.next()?;
            Some((list.trim(), detail.trim()))
        })
        .collect()
}

/// The list row the `>` cursor mark is drawn on.
fn marked_row(text: &str) -> String {
    let marked: Vec<&str> = panes(text)
        .into_iter()
        .filter_map(|(list, _)| list.strip_prefix('>'))
        .collect();
    assert_eq!(marked.len(), 1, "one cursor row: {marked:?}\n{text}");
    marked[0].to_string()
}

const ID_A: &str = "issue-000000aa";
const ID_B: &str = "issue-000000bb";
const ID_C: &str = "issue-000000cc";
const ID_D: &str = "issue-000000dd";
const PAGE_ABCD: &[(&str, &str)] = &[
    (ID_A, "Issue A"),
    (ID_B, "Issue B"),
    (ID_C, "Issue C"),
    (ID_D, "Issue D"),
];

/// An Issues tab on `PAGE_ABCD` with the cursor on row 3 (`ID_D`), rows
/// 0 and 3 read and nothing in flight.
fn app_on_row_three() -> App {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let reqs = app.on_bus(issues_reply(named_page(PAGE_ABCD)));
    assert_eq!(reqs, vec![issue_request(ID_A)]);
    for _ in 0..3 {
        let reqs = app.update(Action::Down);
        assert!(reqs.is_empty(), "a read is pending: {reqs:?}");
    }
    assert_eq!(app.scan.issues.cursor, 3);
    // The pending read settles and the held landing on row 3 is retried.
    let reqs = app.on_bus(named_issue_reply(ID_A, "Issue A"));
    assert_eq!(reqs, vec![issue_request(ID_D)]);
    let reqs = app.on_bus(named_issue_reply(ID_D, "Issue D"));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.issues.pending_read, None);
    assert_eq!(app.scan.issues.detail().map(|i| i.id.as_str()), Some(ID_D));
    app
}

/// Spec D11 (ruling 2026-11-01, H75): the Issues list cursor follows the
/// issue id across folds. On row 3 (`Issue D`), a refetched page that
/// lists that issue at row 1 leaves the cursor on it: `cursor_issue()` is
/// the same id, the `>` row drawn is `Issue D`, the detail is still its,
/// and the fold sends no second `scan.issue` for an id already read.
#[test]
fn the_issues_cursor_follows_the_issue_id_across_a_fold() {
    let mut app = app_on_row_three();
    let refetched = named_page(&[
        (ID_B, "Issue B"),
        (ID_D, "Issue D"),
        (ID_A, "Issue A"),
        (ID_C, "Issue C"),
    ]);
    let reqs = app.on_bus(issues_reply(refetched));
    assert!(
        reqs.is_empty(),
        "the cursor's issue is read already: {reqs:?}"
    );
    assert_eq!(app.scan.issues.cursor, 1, "re-found at its new row");
    assert_eq!(
        app.scan.issues.cursor_issue().map(|i| i.id.as_str()),
        Some(ID_D),
        "the cursor stays on the issue, not the index"
    );
    let detail = app.scan.issues.detail().expect("the detail is still read");
    assert_eq!(detail.id.as_str(), ID_D);
    assert_eq!(detail.name, "Issue D");

    let text = screen(&app);
    let row = marked_row(&text);
    assert!(
        row.contains("Issue D"),
        "the > row is the issue the operator was on: {row:?}"
    );
    assert!(
        !row.contains("Issue B"),
        "row 1's old occupant is not marked: {row:?}"
    );
    let head = panes(&text)
        .into_iter()
        .map(|(_, detail)| detail)
        .find(|d| d.starts_with("Issue "))
        .unwrap_or_default();
    assert_eq!(head, "Issue D   high · certain · open");
}

/// H75's other half: when the refetched page no longer lists the cursor's
/// id, the index clamps as before (row 3 of four becomes row 1 of two), the
/// row now under the cursor is unread, so one `scan.issue` goes out for it,
/// and the dropped issue leaves `read`.
#[test]
fn a_fold_that_drops_the_cursor_id_clamps_the_index() {
    let mut app = app_on_row_three();
    let refetched = named_page(&[(ID_B, "Issue B"), (ID_C, "Issue C")]);
    let reqs = app.on_bus(issues_reply(refetched));
    assert_eq!(app.scan.issues.cursor, 1, "clamped to the last row");
    assert_eq!(
        app.scan.issues.cursor_issue().map(|i| i.id.as_str()),
        Some(ID_C)
    );
    assert_eq!(reqs, vec![issue_request(ID_C)], "the new row is unread");
    assert!(
        !app.scan.issues.read.contains(ID_D),
        "the dropped id left read"
    );
    assert!(
        app.scan.issues.detail().is_none(),
        "nothing read for row 1 yet"
    );
    let row = marked_row(&screen(&app));
    assert!(row.contains("Issue C"), "{row:?}");
}
