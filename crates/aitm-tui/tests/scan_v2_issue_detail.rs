//! Scanner v2 TUI, plan task 8: the Issues tab's Detail pane (spec D3, D6,
//! D11, D13; fix round G, G8: split from `scan_v2_issues.rs`, the list
//! half).
//!
//! The read issue's head and `label value` lines, bounded once at fold
//! time; the walkable flow list between the evidence and the PoC ref, its
//! cursor and the `Enter` that opens a flow through the store; the paging
//! keys and the follow-the-flow scroll; the status round trips (`c` `f`
//! `u`) and the `P` jump to the Findings panel; the neutral placeholder
//! before a read.
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_scan_model::IssueStatus;
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::model::Finding;
use aitm_tui::scan::{IssuePane, ScanTab, DETAIL_VALUE_MAX};
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

const XSS: &str = "issue-9f8e7d6c";
const REDIRECT: &str = "issue-4c3b2a19";
/// The first probe flow of `scan.issue.json`.
const PROBE_1: &str = "550e8400-e29b-41d4-a716-446655440000";

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

/// A line of the 200x50 detail pane (the text right of the pane rule),
/// found by `needle` and trimmed of the pane padding and the box edge, so
/// a test pins the whole literal (fix round F, F13).
fn detail_line<'a>(text: &'a str, needle: &str) -> &'a str {
    let line = line_with(text, needle).unwrap_or_else(|| panic!("no line with {needle:?}: {text}"));
    let rule = line.rfind('│').unwrap_or_default();
    line[..rule].rsplit('│').next().unwrap_or_default().trim()
}

/// Fix round E, E12: the flow cursor is reset when the list cursor moves,
/// not by whichever read answers. With the Detail pane focused and the
/// flow cursor on the second flow, a `scan.issue` reply for another row
/// leaves it there.
#[test]
fn a_read_answering_for_another_row_does_not_reset_the_flow_cursor() {
    let mut app = app_with_xss_read();
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 1);
    let reqs = app.on_bus(issue_reply(REDIRECT));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(
        app.scan.issues.detail_view.flow_cursor, 1,
        "the reply moved the flow cursor"
    );
    assert_eq!(app.scan.issues.detail().map(|i| i.id.as_str()), Some(XSS));
    // Moving the list cursor resets it.
    let _ = app.update(Action::ScanPanePrev);
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 0);
}

/// Fix round E, E18 (D11 "⏎ open or act"): `Enter` with the List pane
/// focused focuses the Detail pane and sends nothing; the row stays.
#[test]
fn enter_on_the_list_focuses_the_detail_pane() {
    let mut app = app_with_xss_read();
    assert_eq!(app.scan.issues.pane, IssuePane::List);
    let reqs = app.update(Action::Enter);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.issues.pane, IssuePane::Detail);
    assert_eq!(app.scan.issues.cursor, 0);
    assert_eq!(app.mode, Mode::Scan);
    let _ = app.update(Action::Back);
    assert_eq!(app.scan.issues.pane, IssuePane::List, "Esc closes the pane");
    assert_eq!(app.mode, Mode::Scan);
}

/// Fix round E, E19 (D6 hostile-core bounds): the `Issue` strings the
/// detail lines are built from are bounded once when the reply is folded
/// into `read`, so a 1 MiB `description`, `payload`, `matched`,
/// `remediation` and `note` leave an entry of at most 400 cells (the
/// model's `DETAIL_VALUE_MAX`, and four times that in chars) each, and the
/// pane still draws the description cut with an ellipsis.
#[test]
fn read_issue_strings_are_bounded_at_fold_time() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["description"] = json!("D".repeat(1 << 20));
    issue["evidence"]["payload"] = json!("P".repeat(1 << 20));
    issue["evidence"]["matched"] = json!("M".repeat(1 << 20));
    issue["remediation"] = json!("R".repeat(1 << 20));
    issue["note"] = json!("N".repeat(1 << 20));
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let read = app
        .scan
        .issues
        .read
        .get(XSS)
        .unwrap_or_else(|| panic!("the reply was folded"));
    let bounded = |s: &str| s.chars().count() <= 4 * 400 && s.ends_with('…');
    assert!(
        bounded(&read.description),
        "description: {} chars",
        read.description.chars().count()
    );
    assert!(bounded(
        read.evidence.payload.as_deref().unwrap_or_default()
    ));
    assert!(bounded(
        read.evidence.matched.as_deref().unwrap_or_default()
    ));
    assert!(bounded(read.remediation.as_deref().unwrap_or_default()));
    assert!(bounded(read.note.as_deref().unwrap_or_default()));
    let text = screen(&app);
    let line = line_with(&text, "description DDDD").unwrap_or_else(|| panic!("no line: {text}"));
    assert!(line.contains("D…"), "{line:?}");
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

/// A connected app on the Issues tab with the page folded and the XSS row
/// read (`scan.issue.json` under its keyed tag), so the detail pane shows
/// the issue under the cursor.
fn app_with_xss_read() -> App {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let reqs = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(reqs, vec![issue_request(XSS)]);
    let _ = app.on_bus(reply(
        &format!("scan.issue:{XSS}"),
        "scan.issue",
        fixture("scan.issue.json"),
    ));
    assert_eq!(app.scan.issues.detail().map(|i| i.id.as_str()), Some(XSS));
    app
}

/// T7-9, D11: the detail pane shows the evidence of the read issue
/// (`payload`, the payload, the matched text); `f` sends exactly
/// `scan.issue.update {id, status: "false_positive"}` under its keyed tag,
/// and the `scan.issue.update.json` reply replaces both the row and the
/// read issue.
#[test]
fn detail_shows_evidence_and_status_round_trips() {
    let mut app = app_with_xss_read();
    let text = screen(&app);
    // The detail pane's lines, trimmed of the pane padding, pinned
    // literally (fix round F, F13).
    assert_eq!(
        detail_line(&text, "payload"),
        "payload     <script>aitm-canary()</script>"
    );
    assert_eq!(
        detail_line(&text, "matched"),
        "matched     reflected marker aitm-canary in an HTML text node"
    );
    assert_eq!(
        detail_line(&text, "Reflected cross-site scripting   "),
        "Reflected cross-site scripting   high · certain · open",
        "the detail's first line names the issue and its verdict"
    );
    assert_eq!(
        detail_line(&text, "c confirm"),
        "c confirm · f false positive · u reopen · ⏎ open flow · P PoC",
        "the detail footer"
    );

    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::FalsePositive));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.issue.update:{XSS}"),
            "scan.issue.update",
            json!({ "id": XSS, "status": "false_positive" })
        )]
    );
    assert!(app
        .scan
        .inflight
        .contains(&format!("scan.issue.update:{XSS}")));
    // The same key again is not re-issued while the update is in flight.
    assert!(app
        .update(Action::ScanIssueStatus(IssueStatus::FalsePositive))
        .is_empty());

    let reqs = app.on_bus(reply(
        &format!("scan.issue.update:{XSS}"),
        "scan.issue.update",
        fixture("scan.issue.update.json"),
    ));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert!(app.scan.inflight.is_empty());
    assert_eq!(
        app.scan.issues.detail().map(|i| i.status),
        Some(IssueStatus::FalsePositive)
    );
    assert_eq!(app.scan.issues.list[0].status, IssueStatus::FalsePositive);
    assert_eq!(app.scan.issues.rows[0].status, "false_positive");
    let text = screen(&app);
    let row = line_with(&text, "Reflected cross-site scripting  GET /search")
        .unwrap_or_else(|| panic!("no XSS row: {text}"));
    assert!(
        row.contains("false_positive"),
        "the row shows the new status: {row:?}"
    );
    assert_eq!(
        detail_line(&text, "Reflected cross-site scripting   "),
        "Reflected cross-site scripting   high · certain · false_positive",
        "the detail shows the new status"
    );
    assert_eq!(
        detail_line(&text, "note "),
        "note        intended behaviour",
        "the update's note is shown"
    );

    // `c` and `u` travel under their own tokens.
    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::Confirmed));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.issue.update:{XSS}"),
            "scan.issue.update",
            json!({ "id": XSS, "status": "confirmed" })
        )]
    );
    let _ = app.on_bus(BusEvent::CallTaggedFailed {
        tag: format!("scan.issue.update:{XSS}"),
        name: "scan.issue.update".into(),
        message: "scan: not_found: issue-9f8e7d6c".into(),
    });
    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::Open));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.issue.update:{XSS}"),
            "scan.issue.update",
            json!({ "id": XSS, "status": "open" })
        )]
    );
}

/// T7-9, D11: with the Detail pane focused, the flow cursor starts on the
/// first probe flow; `⏎` on a flow the store does not hold toasts the
/// existing "not in the flow list" text and stays in the Scan view.
#[test]
fn enter_on_a_probe_flow_not_in_the_store_toasts() {
    let mut app = app_with_xss_read();
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(app.scan.issues.pane, IssuePane::Detail);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 0);
    let reqs = app.update(Action::Enter);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.mode, Mode::Scan);
    let toast = toast(&app);
    assert!(toast.contains(PROBE_1), "{toast:?}");
    assert!(toast.contains("not in the flow list"), "{toast:?}");
}

/// T7-9, D11: `↑↓` with Detail focused walk the probe flows then the
/// baseline; `⏎` on a flow the store holds opens it in the inspector.
#[test]
fn enter_on_a_known_probe_flow_opens_the_inspector() {
    let mut app = app_with_xss_read();
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        PROBE_1,
        "GET",
        "127.0.0.1:8080",
        "/search?q=x",
        Some(200),
        "none",
    )]));
    let _ = app.update(Action::ScanPaneNext);
    // The three flows are walkable and the cursor is clamped to them.
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 1);
    let _ = app.update(Action::Down);
    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.issues.detail_view.flow_cursor, 2,
        "two probes and the baseline"
    );
    let _ = app.update(Action::Up);
    let _ = app.update(Action::Up);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 0);
    let text = screen(&app);
    assert!(
        line_with(&text, PROBE_1).is_some_and(|l| l.contains("probe")),
        "the probe flow is listed with its tag: {text}"
    );
    assert!(
        line_with(&text, "16fd2706-8baf-433b-82eb-8c7fada847da")
            .is_some_and(|l| l.contains("baseline")),
        "the baseline flow is listed with its tag: {text}"
    );
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Inspector);
    assert_eq!(app.selected.as_deref(), Some(PROBE_1));
}

/// T7-9, D11: `P` opens Findings with the cursor on the first finding whose
/// `poc_path` names the issue's `poc_ref` (file stem or file name, fix
/// round F, F3); without such a finding it toasts the ref; an issue
/// without a `poc_ref` toasts that.
#[test]
fn open_poc_switches_to_findings_or_toasts() {
    let mut app = app_with_xss_read();
    let other = Finding::from_json(&json!({ "poc_path": "/pocs/open-redirect.yaml" }))
        .unwrap_or_else(|| panic!("a finding"));
    let matching = Finding::from_json(&json!({ "poc_path": "/pocs/poc-3b1c.yaml" }))
        .unwrap_or_else(|| panic!("a finding"));
    app.findings = vec![other, matching];
    let reqs = app.update(Action::ScanOpenPoc);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.mode, Mode::Findings);
    assert_eq!(app.finding_cursor, 1);

    let mut app = app_with_xss_read();
    app.findings.clear();
    let _ = app.update(Action::ScanOpenPoc);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(toast(&app), "PoC poc-3b1c is not in the Findings list");

    // A finding whose title equals the issue name matches too.
    let mut app = app_with_xss_read();
    app.findings = vec![Finding::from_json(&json!({
        "poc_path": "/pocs/other.yaml",
        "title": "Reflected cross-site scripting",
    }))
    .unwrap_or_else(|| panic!("a finding"))];
    let _ = app.update(Action::ScanOpenPoc);
    assert_eq!(app.mode, Mode::Findings);
    assert_eq!(app.finding_cursor, 0);

    // The second row has no `poc_ref`.
    let mut app = app_with_xss_read();
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.cursor, 1);
    let _ = app.update(Action::ScanOpenPoc);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(toast(&app), "this issue has no PoC");
}

/// Fix round F, F1 (D11 order): the walkable flow list sits between the
/// evidence and the refs, so on the 200x50 detail the `flows` label's row
/// lies after the `matched` row and before the `poc` row.
#[test]
fn flow_list_is_drawn_between_the_evidence_and_the_poc_ref() {
    let app = app_with_xss_read();
    let text = screen(&app);
    let matched = line_index(&text, "matched     reflected marker")
        .unwrap_or_else(|| panic!("no matched line: {text}"));
    let flows =
        line_index(&text, "flows       ").unwrap_or_else(|| panic!("no flows label: {text}"));
    let poc = line_index(&text, "poc         poc-3b1c (P)")
        .unwrap_or_else(|| panic!("no poc line: {text}"));
    assert!(
        matched < flows && flows < poc,
        "matched {matched}, flows {flows}, poc {poc}: {text}"
    );
    // The three flows follow the label, probes first then the baseline.
    assert_eq!(line_index(&text, PROBE_1), Some(flows + 1));
    assert_eq!(
        line_index(&text, "16fd2706-8baf-433b-82eb-8c7fada847da"),
        Some(flows + 3)
    );
}

/// Fix round F, F2: before any `scan.issue` reply the detail pane reads the
/// neutral `no detail read for this row` (true while a read is in flight,
/// after a failed one and when the verb is missing; the banner says which).
#[test]
fn detail_placeholder_is_neutral_before_a_read() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    assert_eq!(app.scan.issues.detail(), None);
    let text = screen(&app);
    assert!(
        line_with(&text, "no detail read for this row").is_some(),
        "{text}"
    );
    assert!(
        line_with(&text, "waiting for scan.issue").is_none(),
        "the old wording is gone: {text}"
    );
}

/// Fix round F, F4 (D6 hostile-core bounds): an issue with 100 000 probe
/// flows folds to `FLOWS_MAX` (64) kept, the rest counted once as a
/// `... 99936 more` line under the list, and the pane renders at 200x50.
#[test]
fn probe_flows_are_bounded_at_fold_time_with_a_more_line() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    let flows: Vec<String> = (0..100_000u32)
        .map(|k| format!("550e8400-e29b-41d4-a716-4466{k:08x}"))
        .collect();
    issue["evidence"]["probe_flows"] = json!(flows);
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let read = app
        .scan
        .issues
        .read
        .get(XSS)
        .unwrap_or_else(|| panic!("the reply was folded"));
    assert_eq!(read.evidence.probe_flows.len(), 64);
    assert_eq!(read.dropped.flows, 99_936);
    // `End` lands on the last line; one page up shows the end of the flow
    // list with its count.
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::End);
    let _ = app.update(Action::PageUp);
    let text = screen(&app);
    assert_eq!(detail_line(&text, "... 99936 more"), "... 99936 more");
    assert!(
        line_with(&text, "550e8400-e29b-41d4-a716-44660000003f").is_some(),
        "the 64th kept flow: {text}"
    );
    assert!(
        line_with(&text, "550e8400-e29b-41d4-a716-446600000040").is_none(),
        "the 65th was dropped: {text}"
    );
}

/// Fix round F, F5 (D13: hue on data): a name that spells a verdict
/// (`Debug marker   critical · certain · confirmed`) cannot forge the head
/// line's hue; the verdict cell takes the issue's real severity hue
/// (`info`) and the name stays primary text.
#[test]
fn head_line_verdict_hue_comes_from_the_typed_severity_not_the_name() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["name"] = json!("Debug marker   critical · certain · confirmed");
    issue["severity"] = json!("info");
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let buf = draw(&app, 200, 50);
    let text = to_text(&buf);
    let head =
        line_with(&text, "Debug marker   critical").unwrap_or_else(|| panic!("no head: {text}"));
    let y = line_index(&text, "Debug marker   critical").unwrap_or_default();
    assert!(
        head.contains("Debug marker   critical · certain · confirmed   info · certain · open"),
        "{head:?}"
    );
    let forged = col_of(head, "critical").unwrap_or_default();
    let real = col_of(head, "   info").unwrap_or_default() + 3;
    let theme = theme();
    assert_eq!(
        Some(cell(&buf, real, y).fg),
        theme.severity("info").fg,
        "the verdict cell wears the real severity"
    );
    assert_eq!(
        Some(cell(&buf, forged, y).fg),
        theme.text_primary().fg,
        "the forged word in the name is plain primary text"
    );
    assert_ne!(
        Some(cell(&buf, forged, y).fg),
        theme.severity("critical").fg
    );
}

/// Fix round F, F6 and F9: the flow cursor is clamped when an update shrinks
/// the flow list. Cursor on flow 3 of 3, a `scan.issue.update` reply with a
/// single probe flow and no baseline: `Enter` opens that one flow.
#[test]
fn an_update_that_shrinks_the_flow_list_clamps_the_flow_cursor() {
    const ONLY: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    let mut app = app_with_xss_read();
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        ONLY,
        "GET",
        "127.0.0.1:8080",
        "/search?q=x",
        Some(200),
        "none",
    )]));
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::Down);
    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.issues.detail_view.flow_cursor, 2,
        "the baseline, flow 3 of 3"
    );
    let mut update = fixture("scan.issue.update.json");
    update["evidence"]["probe_flows"] = json!([ONLY]);
    update["evidence"]["baseline_flow"] = Value::Null;
    let _ = app.on_bus(reply(
        &format!("scan.issue.update:{XSS}"),
        "scan.issue.update",
        update,
    ));
    assert_eq!(
        app.scan.issues.detail_view.flow_cursor, 0,
        "clamped to the one flow"
    );
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Inspector);
    assert_eq!(app.selected.as_deref(), Some(ONLY));
}

/// The fixture issue made tall: twelve timing rows, L4 evidence and its
/// three flows, read under the XSS row.
fn app_with_tall_xss_read() -> App {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["evidence"]["timing"] = json!({
        "requested_s": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0],
        "observed_ms": [1010, 2020, 3030, 4040, 5050, 6060, 7070, 8080, 9090, 10100, 11110, 12120],
        "baseline_ms": [12, 11, 13, 12, 11, 13, 12, 11, 13, 12, 11, 13],
        "slope": 1004.5,
        "r": 0.998
    });
    issue["evidence"]["l4"] = json!({
        "sent_hex": "deadbeef",
        "seed_id": "hello",
        "rng_seed": 42,
        "mutation_chain": ["flip", "truncate"],
        "prior_messages": 3,
        "oracle": { "kind": "reset" },
        "liveness_before": true,
        "liveness_after": false,
        "reproduced": [2, 3],
        "scope_entry": "l4-1"
    });
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    assert!(
        app.scan
            .issues
            .detail()
            .is_some_and(|i| i.evidence.l4.is_some()),
        "the tall issue was read"
    );
    app
}

/// Fix round F, F7: `detail_scroll` is what is drawn; the view follows the
/// flow cursor only after a flow key. On the tall detail at 90x40 with
/// Detail focused: `End` leaves the name line, `Home` shows it again with
/// the flows off screen, `Down` brings the flow row back on screen, and
/// `PageUp` scrolls away from it again.
#[test]
fn paging_keys_reach_the_top_of_a_tall_detail_and_down_follows_the_flow() {
    let mut app = app_with_tall_xss_read();
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(app.scan.issues.pane, IssuePane::Detail);
    const NAME: &str = "Reflected cross-site scripting   high";
    const FLOW_2: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    let _ = app.update(Action::End);
    let text = text_of(&app, 90, 40);
    assert!(line_with(&text, NAME).is_none(), "End left the top: {text}");
    assert!(
        line_with(&text, "seen        1 occurrence").is_some(),
        "{text}"
    );

    let _ = app.update(Action::Home);
    assert_eq!(app.scan.issues.detail_view.scroll, 0);
    let text = text_of(&app, 90, 40);
    assert!(
        line_with(&text, NAME).is_some(),
        "Home shows the name: {text}"
    );
    assert!(
        line_with(&text, FLOW_2).is_none(),
        "the flows are below the fold: {text}"
    );

    let _ = app.update(Action::Down);
    assert_eq!(app.scan.issues.detail_view.flow_cursor, 1);
    let text = text_of(&app, 90, 40);
    assert!(
        line_with(&text, FLOW_2).is_some_and(|l| l.contains("> ")),
        "Down brings the flow under the cursor on screen: {text}"
    );

    let _ = app.update(Action::PageUp);
    let text = text_of(&app, 90, 40);
    assert!(
        line_with(&text, FLOW_2).is_none(),
        "PageUp scrolls away from the flow again: {text}"
    );
}

/// [`app_with_xss_read`] with the XSS row's `poc_ref` replaced on the page
/// and in the read issue, and two findings in the list: an unrelated one
/// and `/pocs/poc-3b1c.yaml`.
fn app_with_poc_ref(poc_ref: Value) -> App {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let mut page = fixture("scan.issues.json");
    page["issues"][0]["poc_ref"] = poc_ref.clone();
    let _ = app.on_bus(issues_reply(page));
    let mut issue = fixture("scan.issue.json");
    issue["poc_ref"] = poc_ref;
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let other = Finding::from_json(&json!({ "poc_path": "/pocs/open-redirect.yaml" }))
        .unwrap_or_else(|| panic!("a finding"));
    let matching = Finding::from_json(&json!({ "poc_path": "/pocs/poc-3b1c.yaml" }))
        .unwrap_or_else(|| panic!("a finding"));
    app.findings = vec![other, matching];
    app
}

/// Fix round F, F3: a degenerate `poc_ref` never jumps to an unrelated
/// finding. An empty (or blank) ref is "no PoC"; `/`, `.yaml` and `poc`
/// (a substring of every PoC path) toast and stay in Scan; the ref is
/// matched on the file stem or the file name, so `poc-3b1c` and
/// `poc-3b1c.yaml` both find `/pocs/poc-3b1c.yaml`; a 1000-char ref is cut
/// to 80 cells in the toast (F4).
#[test]
fn degenerate_poc_refs_toast_and_never_switch_to_findings() {
    for blank in ["", "   "] {
        let mut app = app_with_poc_ref(json!(blank));
        let _ = app.update(Action::ScanOpenPoc);
        assert_eq!(app.mode, Mode::Scan, "{blank:?}");
        assert_eq!(toast(&app), "this issue has no PoC", "{blank:?}");
    }
    for degenerate in ["/", ".yaml", "poc", "pocs", "3b1c"] {
        let mut app = app_with_poc_ref(json!(degenerate));
        let _ = app.update(Action::ScanOpenPoc);
        assert_eq!(app.mode, Mode::Scan, "{degenerate:?}");
        assert_eq!(
            toast(&app),
            format!("PoC {degenerate} is not in the Findings list")
        );
    }
    for real in ["poc-3b1c", "poc-3b1c.yaml", " poc-3b1c "] {
        let mut app = app_with_poc_ref(json!(real));
        let _ = app.update(Action::ScanOpenPoc);
        assert_eq!(app.mode, Mode::Findings, "{real:?}");
        assert_eq!(app.finding_cursor, 1, "{real:?}");
    }
    let long = "x".repeat(1000);
    let mut app = app_with_poc_ref(json!(long));
    let _ = app.update(Action::ScanOpenPoc);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(
        toast(&app),
        format!("PoC {}… is not in the Findings list", "x".repeat(79))
    );
}

/// Fix round G, G6: the mutation chain shows its first sixteen mutators
/// and then how many more the issue carried, counting the ones the fold
/// cut as well (G12's shape), never a bare `...`.
#[test]
fn the_mutation_chain_overflow_names_its_count() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(XSS);
    let chain: Vec<String> = (0..100).map(|k| format!("m{k}")).collect();
    issue["evidence"]["l4"] = json!({
        "seed_id": "seed-1",
        "rng_seed": 7,
        "prior_messages": 0,
        "reproduced": [3, 3],
        "scope_entry": "entry-1",
        "oracle": { "kind": "reset" },
        "liveness_before": true,
        "liveness_after": false,
        "mutation_chain": chain,
        "sent_hex": "00ff",
    });
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let read = app.scan.issues.detail().expect("the issue is read");
    let l4 = read.evidence.l4.as_ref().expect("l4 evidence");
    assert_eq!(
        l4.mutation_chain.len(),
        17,
        "sixteen plus the one past them"
    );
    assert_eq!(read.dropped.mutations, 83);
    let text = screen(&app);
    let line = detail_line(&text, "mutations");
    assert!(line.starts_with("mutations   m0 > m1 > "), "{line:?}");
    assert!(line.ends_with("> m15 ... 84 more"), "{line:?}");
    assert!(!line.contains("m16"), "{line:?}");
}

/// Every string leaf of `value`, depth first.
fn string_leaves(value: &Value, path: String, out: &mut Vec<(String, usize)>) {
    match value {
        Value::String(s) => out.push((path, s.chars().count())),
        Value::Array(items) => {
            for (k, item) in items.iter().enumerate() {
                string_leaves(item, format!("{path}[{k}]"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                string_leaves(item, format!("{path}.{key}"), out);
            }
        }
        _ => {}
    }
}

/// Set every string leaf of `value` but the root `id` to `text` where the
/// whole document still parses as the contract's `Issue` (an enum token or
/// a UUID cannot change), one leaf at a time, keeping the ones that parse.
/// Returns how many leaves were set.
fn inflate_free_text(value: &mut Value, text: &str) -> usize {
    let mut leaves = Vec::new();
    string_leaves(value, String::new(), &mut leaves);
    let mut set = 0;
    for (path, _) in leaves {
        if path == ".id" {
            // The listed id: the keyed fold matches it, so it stays.
            continue;
        }
        let before = value.clone();
        let mut node = &mut *value;
        for part in path.split('.').skip(1) {
            let (key, index) = match part.split_once('[') {
                Some((k, rest)) => (k, rest.trim_end_matches(']').parse::<usize>().ok()),
                None => (part, None),
            };
            node = &mut node[key];
            if let Some(i) = index {
                node = &mut node[i];
            }
        }
        *node = json!(text);
        if serde_json::from_value::<aitm_scan_model::Issue>(value.clone()).is_err() {
            *value = before;
        } else {
            set += 1;
        }
    }
    set
}

/// Fix round G, G1: `bound_issue` names its fields by hand, so this walks
/// the issue generically: every free-text string leaf of the fixture set
/// to 1 MiB folds to at most `4 * DETAIL_VALUE_MAX` chars once read
/// (`truncate`'s contract: at most `w` cells and `4 * w` chars, the
/// ellipsis included), whatever the field.
#[test]
fn every_free_text_leaf_of_a_read_issue_is_bounded() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(XSS);
    // Fill the optional runs too, so their leaves are walked.
    issue["evidence"]["l4"] = json!({
        "seed_id": "seed-1",
        "rng_seed": 7,
        "prior_messages": 0,
        "reproduced": [3, 3],
        "scope_entry": "entry-1",
        "oracle": { "kind": "reset" },
        "liveness_before": true,
        "liveness_after": false,
        "mutation_chain": ["m0", "m1"],
        "sent_hex": "00ff",
    });
    issue["location"]["l4"] = json!({
        "ip": "127.0.0.1",
        "port": 7000,
        "proto": "tcp",
        "grammar": "dns",
        "field_path": "q.name",
        "mutation": "flip",
    });
    issue["remediation"] = json!("fix it");
    issue["note"] = json!("a note");
    let huge = "x".repeat(1 << 20);
    let set = inflate_free_text(&mut issue, &huge);
    assert!(set >= 20, "the free-text leaves were inflated: {set}");
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let read = app.scan.issues.detail().expect("the issue is read");
    let folded = serde_json::to_value(&read.issue).expect("an issue serialises");
    let mut leaves = Vec::new();
    string_leaves(&folded, String::new(), &mut leaves);
    for (path, chars) in leaves {
        assert!(
            chars <= 4 * DETAIL_VALUE_MAX,
            "{path} holds {chars} chars after the fold"
        );
    }
    let _ = screen(&app);
}

/// D6 keyed-reply discipline, the `scan.issue.update` half (plan Task 16):
/// an update reply whose `id` is another issue's folds nothing: the read
/// issue under the cursor keeps its status, the list row and its display
/// row are unchanged, nothing is read for the other id, the Issues error
/// reads `reply named a different issue` under the update tag, and the
/// tag is settled so `f` is live again; the genuine reply then folds and
/// clears the error.
#[test]
fn an_update_naming_another_issue_is_not_folded() {
    let mut app = app_with_xss_read();
    let tag = format!("scan.issue.update:{XSS}");
    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::FalsePositive));
    assert_eq!(reqs.len(), 1, "{reqs:?}");

    let mut other = fixture("scan.issue.update.json");
    other["id"] = json!(REDIRECT);
    let reqs = app.on_bus(reply(&tag, "scan.issue.update", other));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(
        app.scan.issues.detail().map(|i| i.status),
        Some(IssueStatus::Open),
        "the read issue keeps its status"
    );
    assert_eq!(app.scan.issues.list[0].status, IssueStatus::Open);
    assert_eq!(
        app.scan.issues.list[1].status,
        IssueStatus::Open,
        "the other row is not touched either"
    );
    assert_eq!(app.scan.issues.rows[0].status, "open");
    assert!(
        !app.scan.issues.read.contains(REDIRECT),
        "nothing is read for the other id"
    );
    let err = app
        .scan
        .issues
        .error
        .as_ref()
        .expect("the mismatch is the Issues tab's error");
    assert_eq!(err.tag, tag);
    assert_eq!(err.code, None);
    assert_eq!(err.detail, "reply named a different issue");
    assert!(app.scan.inflight.is_empty(), "the tag is settled");
    let text = screen(&app);
    let row = line_with(&text, "Reflected cross-site scripting  GET /search")
        .unwrap_or_else(|| panic!("no XSS row: {text}"));
    assert!(
        row.contains("  open") && !row.contains("false_positive"),
        "the row still reads open: {row:?}"
    );

    let reqs = app.update(Action::ScanIssueStatus(IssueStatus::FalsePositive));
    assert_eq!(reqs.len(), 1, "f is live again: {reqs:?}");
    let _ = app.on_bus(reply(
        &tag,
        "scan.issue.update",
        fixture("scan.issue.update.json"),
    ));
    assert_eq!(
        app.scan.issues.detail().map(|i| i.status),
        Some(IssueStatus::FalsePositive),
        "the genuine reply folds"
    );
    assert_eq!(app.scan.issues.error, None, "and clears the error");
}

/// Fix round H, H60 (`Issue.location.l4`, T1b's final head): an issue
/// found on the L4 lane renders its L4 point as its own `l4` detail line,
/// `ip:port/proto · grammar · field_path · mutation`, each optional part
/// only when present, right under `location`, which keeps the HTTP form
/// alone. The fixture issue with the full L4 location reads every part;
/// with only the target it reads `ip:port/proto`.
#[test]
fn an_l4_location_renders_its_own_detail_line() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(issues_reply(fixture("scan.issues.json")));
    let mut issue = fixture("scan.issue.json");
    issue["location"]["l4"] = json!({
        "ip": "127.0.0.1",
        "port": 7000,
        "proto": "tcp",
        "grammar": "dns",
        "field_path": "q.name",
        "mutation": "flip",
    });
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let text = screen(&app);
    assert_eq!(
        detail_line(&text, "127.0.0.1:7000/tcp"),
        "l4          127.0.0.1:7000/tcp · dns · q.name · flip",
        "the l4 line: {text}"
    );
    assert_eq!(
        detail_line(&text, "location"),
        "location    GET /search · query q",
        "the location line keeps the HTTP form alone"
    );
    let lines: Vec<&str> = text.lines().collect();
    let location = lines
        .iter()
        .position(|l| l.contains("location    GET /search"))
        .expect("the location row");
    assert!(
        lines[location + 1].contains("l4          127.0.0.1:7000/tcp"),
        "l4 sits right under location:\n{text}"
    );

    let mut issue = fixture("scan.issue.json");
    issue["location"]["l4"] = json!({ "ip": "10.0.0.7", "port": 5353, "proto": "udp" });
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let text = screen(&app);
    assert_eq!(
        detail_line(&text, "10.0.0.7:5353/udp"),
        "l4          10.0.0.7:5353/udp",
        "only the target when the optional parts are absent: {text}"
    );
    assert!(
        !text.contains("· l4 "),
        "the inline form on the location line is gone: {text}"
    );
}

/// Fix round H, H84 (`Issue.jobs`, #232 `7252d0df`): an issue belongs to
/// every job that found or re-found it. The detail's `job` line lists
/// `jobs_or_job()` joined by `, `: both ids of a two-job issue, the one
/// `job` of a record written before the field existed.
#[test]
fn the_job_line_names_every_job_that_found_the_issue() {
    let mut app = app_with_xss_read();
    let text = screen(&app);
    assert_eq!(
        detail_line(&text, "job         scan-"),
        "job         scan-1a2b3c4d",
        "an older record reads its one job: {text}"
    );

    let mut issue = fixture("scan.issue.json");
    issue["jobs"] = json!(["scan-1a2b3c4d", "scan-2b3c4d5e"]);
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let text = screen(&app);
    assert_eq!(
        detail_line(&text, "job         scan-"),
        "job         scan-1a2b3c4d, scan-2b3c4d5e",
        "both finders, first finder first: {text}"
    );
}

/// Fix round H, H84: `forget_job` drops a read issue only when the job is
/// its sole finder, so an issue another listed job still owns stays read
/// (its detail is not re-fetched for a job that did not stop owning it).
#[test]
fn forget_job_keeps_an_issue_another_job_still_owns() {
    let mut app = app_with_xss_read();
    let mut issue = fixture("scan.issue.json");
    issue["jobs"] = json!(["scan-1a2b3c4d", "scan-2b3c4d5e"]);
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    assert!(app.scan.issues.detail().is_some());
    app.scan.issues.forget_job("scan-1a2b3c4d");
    assert!(
        app.scan.issues.detail().is_some(),
        "the first finder's terminal line keeps a two-job issue read"
    );
    app.scan.issues.forget_job("scan-2b3c4d5e");
    assert!(
        app.scan.issues.detail().is_some(),
        "neither listed job is the sole finder"
    );

    let mut app = app_with_xss_read();
    assert!(app.scan.issues.detail().is_some());
    app.scan.issues.forget_job("scan-1a2b3c4d");
    assert!(
        app.scan.issues.detail().is_none(),
        "a one-job issue is dropped by its only finder"
    );
    assert!(app.scan.issues.read.is_empty());
}

/// Fix round H, H84 (D6 hostile-core bounds): the `jobs` list is cut at
/// fold to `DETAIL_LIST_MAX` ids, each cut like `job`, and the line says
/// `+n` for the rest; twenty finders read as the first eight and `+12`.
#[test]
fn the_job_line_is_bounded_at_fold_with_a_plus_n() {
    use aitm_tui::scan::DETAIL_LIST_MAX;

    let mut app = app_with_xss_read();
    let mut issue = fixture("scan.issue.json");
    let jobs: Vec<String> = (0..20).map(|k| format!("scan-{k:08x}")).collect();
    issue["jobs"] = json!(jobs);
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    let read = app.scan.issues.detail().expect("read");
    assert_eq!(read.jobs.len(), DETAIL_LIST_MAX);
    assert!(read.jobs.capacity() < 20, "capacity given back");
    let want = format!(
        "{} +{}",
        jobs[..DETAIL_LIST_MAX].join(", "),
        20 - DETAIL_LIST_MAX
    );
    let lines = aitm_tui::scan::issue_detail_lines(read);
    assert!(
        lines.after_flows.contains(&("job", want.clone())),
        "the job line: {:?}",
        lines.after_flows
    );
    // The pane cuts the long line once to its width, ellipsis on the cut.
    let text = screen(&app);
    let row = detail_line(&text, "job         scan-");
    assert!(
        row.starts_with("job         scan-00000000, scan-00000001, scan-00000002"),
        "{row}"
    );
    assert!(row.ends_with('…'), "cut by the pane: {row}");
}
