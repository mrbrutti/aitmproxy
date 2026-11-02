//! Scanner v2 TUI, plan task 5: routing and cadence (spec D5, D6, D10).
//!
//! A `notifications/aitm/job` push line is a trigger for one tagged
//! `scan.status`, never a flow `Refresh`; every other notification is coalesced
//! into at most one `Refresh` on the next `Tick`; live jobs are polled every
//! fourth tick behind the tag dedupe; `scan.status` / `scan.list` replies fold
//! into `App.scan.jobs`, and a malformed reply leaves the prior row.
//!
//! Fixture-driven: this proves the reducer only. Acceptance is the pty cell
//! against a real core (spec Acceptance criteria, "Live").

mod common;

use std::collections::BTreeSet;

use aitm_scan_model::{JobStatus, ListResult};
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::{
    is_job_id, parse_result, JobsState, Launch, LaunchVerb, PendingLaunch, ScanTab,
    MAX_STATUS_FOLLOWUPS,
};
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

/// A connected v2 app at 200x50 with the five verbs this file needs.
fn app() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    app
}

/// A connected v2 app in the Scan view with its opening `scan.list` settled
/// empty, so nothing is in flight.
fn scan_app() -> App {
    let mut app = app();
    let _ = app.update(Action::OpenScan);
    let _ = app.on_bus(empty_list_reply());
    assert_eq!(app.mode, Mode::Scan);
    assert!(
        app.scan.inflight.is_empty(),
        "nothing in flight at the start"
    );
    app
}

/// A `notifications/aitm/job` push line carrying `params`, as the bus task
/// hands it over.
fn job_line(params: Value) -> BusEvent {
    BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
        "params": params,
    }))
}

/// A `scan.list` reply under its single-slot tag.
fn list_reply(value: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value,
    }
}

/// A `scan.status` reply for `job` under its keyed tag.
fn status_reply_for(job: &str, body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: format!("scan.status:{job}"),
        name: "scan.status".into(),
        value: body,
    }
}

/// The `job.progress.json` push line.
fn progress_line() -> BusEvent {
    job_line(fixture("job.progress.json"))
}

/// The `scan.status.json` reply for `JOB` under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    status_reply_for(JOB, body)
}

/// `scan.status.json` with its job replaced by `id`, unparsed.
fn running_body(id: &str) -> Value {
    let mut body = fixture("scan.status.json");
    body["job"] = json!(id);
    body
}

/// Forty running jobs as a `scan.list` body: their ids, in list order, and
/// the reply value.
fn forty_running_jobs() -> (Vec<String>, Value) {
    let template = fixture("scan.list.json")["jobs"][0].clone();
    let ids: Vec<String> = (0..40).map(|n| format!("scan-000000{n:02}")).collect();
    let jobs: Vec<Value> = ids
        .iter()
        .map(|id| {
            let mut row = template.clone();
            row["job"] = json!(id);
            row
        })
        .collect();
    (ids, json!({ "jobs": jobs }))
}

/// The `scan.status {job}` request under its keyed tag.
fn status_request(job: &str) -> BusRequest {
    BusRequest::CallTagged {
        tag: format!("scan.status:{job}"),
        name: "scan.status".into(),
        args: json!({ "job": job }),
    }
}

fn status_requests(reqs: &[BusRequest]) -> usize {
    reqs.iter()
        .filter(|r| matches!(r, BusRequest::CallTagged { name, .. } if name == "scan.status"))
        .count()
}

/// Every tagged call in `reqs`, whatever its verb (fix round B, B9: the
/// dedupe pin counts them all, not only `scan.status`).
fn tagged_requests(reqs: &[BusRequest]) -> usize {
    reqs.iter()
        .filter(|r| matches!(r, BusRequest::CallTagged { .. }))
        .count()
}

/// The tags of every `scan.status` request in `reqs`, in order.
fn status_tags(reqs: &[BusRequest]) -> Vec<String> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { tag, name, .. } if name == "scan.status" => Some(tag.clone()),
            _ => None,
        })
        .collect()
}

/// The job ids every `scan.status` request in `reqs` asks about, in order.
fn status_jobs(reqs: &[BusRequest]) -> Vec<String> {
    status_tags(reqs)
        .iter()
        .map(|tag| tag.trim_start_matches("scan.status:").to_string())
        .collect()
}

/// The `scan.list {}` request under its single-slot tag.
fn list_request() -> BusRequest {
    BusRequest::CallTagged {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        args: json!({}),
    }
}

/// An empty `scan.list` reply, settling the tag without adding a job.
fn empty_list_reply() -> BusEvent {
    list_reply(json!({ "jobs": [] }))
}

fn tick(app: &mut App) -> Vec<BusRequest> {
    app.update(Action::Tick)
}

/// T7-2: a job line yields exactly one tagged `scan.status {job}` and no
/// `Refresh` (push is a trigger, poll is truth). The view is open: outside
/// it an unknown job's line is left to the next `scan.list` (fix round C,
/// C1).
#[test]
fn a_job_line_triggers_one_tagged_status_and_no_refresh() {
    let mut app = scan_app();
    let reqs = app.on_bus(progress_line());
    assert_eq!(reqs, vec![status_request(JOB)]);
}

/// Fix round C, C1: outside the Scan view a push line for a job the TUI
/// does not know (not in `order`, not started here) yields nothing, so a
/// core cannot grow the state one entry per pushed id where no `scan.list`
/// ever prunes it; the next list on opening the view brings the job. Once
/// the job is known, or marked as started here, the same line polls it
/// from any mode.
#[test]
fn an_unknown_job_line_outside_the_scan_view_requests_nothing() {
    let mut app = app();
    assert_eq!(app.mode, Mode::Flows);
    let reqs = app.on_bus(progress_line());
    assert!(
        reqs.is_empty(),
        "an unknown job is not polled here: {reqs:?}"
    );
    assert!(app.scan.inflight.is_empty());
    assert!(
        app.scan.jobs.order.is_empty(),
        "nothing is folded from a line"
    );

    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);
    let reqs = app.on_bus(progress_line());
    assert_eq!(reqs, vec![status_request(JOB)], "a known job is polled");

    let mut started = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = connect(&mut started, TOOLS, None);
    started.scan.jobs.started_here.insert(JOB.to_string());
    let reqs = started.on_bus(progress_line());
    assert_eq!(
        reqs,
        vec![status_request(JOB)],
        "a job started here is polled before its first list"
    );
}

/// T7-2: a flow line yields nothing itself; the next `Tick` yields exactly one
/// `Refresh`; the tick after it yields none.
#[test]
fn a_flow_line_is_coalesced_to_one_refresh_on_the_next_tick() {
    let mut app = app();
    let reqs = app.on_bus(BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/flow",
        "params": { "id": "f1", "event": "request" },
    })));
    assert!(
        reqs.is_empty(),
        "a flow line pushes nothing itself: {reqs:?}"
    );
    assert!(app.flows_dirty, "the line marks the flow list dirty");
    let first = tick(&mut app);
    assert_eq!(first, vec![BusRequest::Refresh]);
    let second = tick(&mut app);
    assert!(second.is_empty(), "the dirty flag is consumed: {second:?}");
}

/// T7-2: four coalesced `progress` lines in a row yield one in-flight
/// `scan.status` (tag dedupe).
#[test]
fn four_progress_lines_yield_one_inflight_status() {
    let mut app = scan_app();
    let mut total = 0;
    for _ in 0..4 {
        total += tagged_requests(&app.on_bus(progress_line()));
    }
    assert_eq!(total, 1, "one tagged call in total, the status");
    assert_eq!(
        app.scan.inflight,
        BTreeSet::from([format!("scan.status:{JOB}")])
    );
}

/// T7-3: with one non-terminal job, 8 ticks each answered in between yield 2
/// `scan.status`; 8 unanswered yield 1; after a `done` reply 40 ticks yield 0.
#[test]
fn status_polls_every_four_ticks_only_while_live() {
    let mut app = app();
    let status = fixture("scan.status.json");
    let reqs = app.on_bus(status_reply(status.clone()));
    assert!(reqs.is_empty(), "a status reply pushes nothing: {reqs:?}");
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);

    let mut answered = 0;
    for _ in 0..8 {
        answered += status_requests(&tick(&mut app));
        let _ = app.on_bus(status_reply(status.clone()));
    }
    assert_eq!(answered, 2, "one poll per 4 ticks when each is answered");

    let mut unanswered = 0;
    for _ in 0..8 {
        unanswered += status_requests(&tick(&mut app));
    }
    assert_eq!(unanswered, 1, "the tag dedupe holds the second poll back");

    let mut done = status;
    done["state"] = json!("done");
    done["phase"] = json!("done");
    let _ = app.on_bus(status_reply(done));
    assert!(app.scan.inflight.is_empty(), "the reply settles the tag");
    let mut after = 0;
    for _ in 0..40 {
        after += status_requests(&tick(&mut app));
    }
    assert_eq!(after, 0, "a terminal job is not polled");
}

/// D10: `scan.list` sets the order and asks `scan.status` once for every
/// listed job without a full entry.
#[test]
fn scan_list_folds_order_and_asks_status_for_unknown_jobs() {
    let mut app = app();
    let reqs = app.on_bus(list_reply(fixture("scan.list.json")));
    assert_eq!(
        app.scan.jobs.order,
        vec![JOB.to_string(), "scan-55667788".to_string()]
    );
    assert_eq!(app.scan.jobs.summaries.len(), 2);
    assert!(
        app.scan.jobs.full.is_empty(),
        "a list carries no full status"
    );
    let tags: Vec<String> = reqs
        .iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { tag, name, args } if name == "scan.status" => {
                assert_eq!(args["job"], tag.trim_start_matches("scan.status:"));
                Some(tag.clone())
            }
            BusRequest::Refresh => panic!("a scan.* reply never pushes Refresh"),
            _ => None,
        })
        .collect();
    assert_eq!(
        tags,
        vec![
            format!("scan.status:{JOB}"),
            "scan.status:scan-55667788".to_string()
        ]
    );
    assert_eq!(reqs.len(), 2, "exactly the two status calls: {reqs:?}");
}

/// D4: `Disconnected` clears the in-flight set (nothing sent before it will
/// be answered).
#[test]
fn disconnect_clears_inflight() {
    let mut app = scan_app();
    let _ = app.on_bus(progress_line());
    assert!(!app.scan.inflight.is_empty());
    let _ = app.on_bus(BusEvent::Disconnected("x".into()));
    assert!(app.scan.inflight.is_empty());
}

/// T7-1, D10: a malformed `scan.status` leaves the prior row and sets an
/// uncoded `ScanError`.
#[test]
fn a_malformed_status_keeps_the_row() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let reqs = app.on_bus(status_reply(json!({ "job": 5 })));
    assert!(reqs.is_empty(), "a bad reply pushes nothing: {reqs:?}");
    assert_eq!(app.scan.jobs.full[JOB].probes.sent, 418);
    let err = app
        .scan
        .last_error
        .as_ref()
        .expect("the mismatch is recorded");
    assert_eq!(err.code, None);
    assert_eq!(err.verb, "scan.status");
}

/// D6 hostile-core bounds (fix round B, B1): a `scan.status` reply whose
/// `job` is not the tag's key folds nothing (no new row, no `full` entry) and
/// records an uncoded error; the polled row stays as it was.
#[test]
fn a_status_reply_naming_another_job_is_not_folded() {
    let mut app = app();
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let mut forged = fixture("scan.status.json");
    forged["job"] = json!("scan-ffff0001");
    let reqs = app.on_bus(status_reply(forged));
    assert!(reqs.is_empty(), "a refused reply pushes nothing: {reqs:?}");
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);
    assert!(!app.scan.jobs.full.contains_key("scan-ffff0001"));
    assert!(!app.scan.jobs.summaries.contains_key("scan-ffff0001"));
    assert_eq!(app.scan.jobs.full[JOB].probes.sent, 418);
    let err = app
        .scan
        .last_error
        .as_ref()
        .expect("the mismatch is recorded");
    assert_eq!(err.code, None);
    assert_eq!(err.verb, "scan.status");
    assert_eq!(err.detail, "reply named a different job");
    assert!(
        app.scan.inflight.is_empty(),
        "the tag is settled even when the reply is refused"
    );
}

/// D6 hostile-core bounds (fix round B, B4): a push line whose job id is not
/// `scan-` + eight lowercase hex digits is dropped, so a forged id never
/// becomes a tag key, an argument or an `inflight` entry.
#[test]
fn a_push_line_with_a_forged_job_id_is_dropped() {
    let mut app = app();
    let mut params = fixture("job.progress.json");
    params["job"] = json!("scan-../../x");
    let reqs = app.on_bus(job_line(params));
    assert!(reqs.is_empty(), "a forged id yields no request: {reqs:?}");
    assert!(app.scan.inflight.is_empty());
    assert!(
        !app.flows_dirty,
        "a job line never marks the flow list dirty"
    );

    assert!(is_job_id("scan-1a2b3c4d"));
    assert!(
        !is_job_id("scan-1A2B3C4D"),
        "upper case is not the wire form"
    );
    assert!(!is_job_id("scan-1a2b3c4"), "seven digits");
    assert!(!is_job_id("scan-1a2b3c4d5"), "nine digits");
    assert!(!is_job_id("scan-../../x"));
    assert!(!is_job_id(""));
}

/// D6 hostile-core bounds (fix round B, B4): a `scan.list` row with a forged
/// id is skipped; the well-formed rows are folded and polled as before.
#[test]
fn a_list_row_with_a_forged_job_id_is_skipped() {
    let mut app = app();
    let mut list = fixture("scan.list.json");
    list["jobs"][1]["job"] = json!("scan-ZZZZZZZZ");
    let reqs = app.on_bus(list_reply(list));
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);
    assert_eq!(app.scan.jobs.summaries.len(), 1);
    assert_eq!(reqs, vec![status_request(JOB)]);
}

/// A running `scan.status.json` body under `id`, parsed.
fn running_status(id: &str) -> JobStatus {
    parse_result::<JobStatus>("scan.status", &running_body(id))
        .expect("scan.status.json with its job replaced parses as a JobStatus")
}

/// `scan.list.json`, parsed.
fn list_fixture() -> ListResult {
    parse_result::<ListResult>("scan.list", &fixture("scan.list.json")).expect("the list")
}

/// D3 `started_here` rule (fix round B, B3, a): a job this TUI started that
/// the list omits stays at the front of `order`, with its `full` entry.
#[test]
fn fold_list_keeps_a_started_here_job_the_list_omits_at_the_front() {
    let mut jobs = JobsState::default();
    jobs.fold_status(running_status("scan-aaaaaaaa"));
    jobs.started_here.insert("scan-aaaaaaaa".to_string());
    let followups = jobs.fold_list(list_fixture());
    assert_eq!(
        jobs.order,
        vec![
            "scan-aaaaaaaa".to_string(),
            JOB.to_string(),
            "scan-55667788".to_string()
        ]
    );
    assert!(jobs.full.contains_key("scan-aaaaaaaa"));
    assert!(jobs.summaries.contains_key("scan-aaaaaaaa"));
    assert_eq!(
        jobs.started_here,
        BTreeSet::from(["scan-aaaaaaaa".to_string()]),
        "a job the list still omits stays marked"
    );
    assert_eq!(
        followups,
        vec![JOB.to_string(), "scan-55667788".to_string()],
        "the listed jobs without a full entry are polled once"
    );
}

/// D3 `started_here` rule (fix round B, B3, b): a running job learned only
/// from a reply (not started here) is dropped from `order`, `full` and
/// `summaries` when a list omits it.
#[test]
fn fold_list_drops_a_running_job_the_list_omits_unless_started_here() {
    let mut jobs = JobsState::default();
    jobs.fold_status(running_status("scan-bbbbbbbb"));
    assert_eq!(jobs.order, vec!["scan-bbbbbbbb".to_string()]);
    let _ = jobs.fold_list(list_fixture());
    assert_eq!(
        jobs.order,
        vec![JOB.to_string(), "scan-55667788".to_string()]
    );
    assert!(!jobs.full.contains_key("scan-bbbbbbbb"));
    assert!(!jobs.summaries.contains_key("scan-bbbbbbbb"));
    assert!(jobs.live().iter().all(|id| id != "scan-bbbbbbbb"));
}

/// D3 `started_here` rule (fix round B, B3, c): a list that carries the id
/// removes it from `started_here`; `order` is the list's order.
#[test]
fn fold_list_unmarks_a_started_here_job_the_list_carries() {
    let mut jobs = JobsState::default();
    jobs.fold_status(running_status(JOB));
    jobs.started_here.insert(JOB.to_string());
    let _ = jobs.fold_list(list_fixture());
    assert!(jobs.started_here.is_empty());
    assert_eq!(
        jobs.order,
        vec![JOB.to_string(), "scan-55667788".to_string()]
    );
}

/// D6 hostile-core bounds (fix round B, B2): a `scan.list` of 40 running
/// jobs yields exactly `MAX_STATUS_FOLLOWUPS` (16) `scan.status` requests on
/// the fold and exactly 16 more, none repeated, on the next status firing,
/// the cursor's job first; the rest wait for the firing after that.
#[test]
fn status_followups_are_capped_per_fold_and_per_firing() {
    assert_eq!(MAX_STATUS_FOLLOWUPS, 16);
    let mut app = app();
    let (ids, list) = forty_running_jobs();
    let reqs = app.on_bus(list_reply(list));
    assert_eq!(app.scan.jobs.order, ids);
    let first = status_tags(&reqs);
    assert_eq!(
        first.len(),
        reqs.len(),
        "only scan.status requests leave the fold"
    );
    let expected: Vec<String> = ids[..16]
        .iter()
        .map(|id| format!("scan.status:{id}"))
        .collect();
    assert_eq!(first, expected, "the first 16 listed jobs, in list order");

    for _ in 0..3 {
        let quiet = tick(&mut app);
        assert!(
            quiet.is_empty(),
            "no status timer before the 4th tick: {quiet:?}"
        );
    }
    app.scan.jobs.cursor = 39;
    let second = status_tags(&tick(&mut app));
    let mut expected: Vec<String> = vec![format!("scan.status:{}", ids[39])];
    expected.extend(ids[16..31].iter().map(|id| format!("scan.status:{id}")));
    assert_eq!(
        second, expected,
        "the cursor's job first, then order, 16 in all"
    );
    let distinct: BTreeSet<&String> = first.iter().chain(second.iter()).collect();
    assert_eq!(distinct.len(), 32, "none duplicated");
    assert_eq!(app.scan.inflight.len(), 32);
}

/// Fix round C, C2: under the 16-cap the status walk starts at a rotating
/// offset, so with 40 running jobs three firings (every reply answered in
/// between) reach every job at least once; the cursor's job still goes
/// first each time. Without the rotation the same 16 would be polled every
/// firing and the rest starved.
#[test]
fn status_polls_rotate_so_every_live_job_is_reached_within_three_firings() {
    let mut app = app();
    let (ids, list) = forty_running_jobs();
    let reqs = app.on_bus(list_reply(list));
    for id in status_jobs(&reqs) {
        let _ = app.on_bus(status_reply_for(&id, running_body(&id)));
    }
    assert!(
        app.scan.inflight.is_empty(),
        "the fold's follow-ups are answered"
    );
    app.scan.jobs.cursor = 39;

    let mut reached: BTreeSet<String> = BTreeSet::new();
    for firing in 1..=3 {
        for _ in 0..3 {
            let quiet = tick(&mut app);
            assert!(
                quiet.is_empty(),
                "firing {firing}: quiet tick sent {quiet:?}"
            );
        }
        let polled = status_jobs(&tick(&mut app));
        assert_eq!(
            polled.len(),
            16,
            "firing {firing} sends the cap: {polled:?}"
        );
        assert_eq!(
            polled[0], ids[39],
            "firing {firing}: the cursor's job first"
        );
        for id in polled {
            reached.insert(id.clone());
            let _ = app.on_bus(status_reply_for(&id, running_body(&id)));
        }
    }
    let all: BTreeSet<String> = ids.iter().cloned().collect();
    let missed: Vec<&String> = all.difference(&reached).collect();
    assert!(
        missed.is_empty(),
        "never polled in three firings: {missed:?}"
    );
}

/// Fix round C, C6: `live()` reads the cursor's job then `order` alone;
/// `summaries` and `full` are retained to `order` by every list fold, so a
/// job a list dropped is in neither, and an entry smuggled into the maps
/// outside `order` is never polled.
#[test]
fn live_reads_order_alone() {
    let mut jobs = JobsState::default();
    jobs.fold_status(running_status("scan-bbbbbbbb"));
    let _ = jobs.fold_list(list_fixture());
    assert_eq!(
        jobs.order,
        vec![JOB.to_string(), "scan-55667788".to_string()]
    );
    assert_eq!(jobs.live(), vec![JOB.to_string()], "the listed running job");
    jobs.summaries.insert(
        "scan-cccccccc".to_string(),
        running_status("scan-cccccccc").summary(),
    );
    assert_eq!(
        jobs.live(),
        vec![JOB.to_string()],
        "a summary outside order is not polled"
    );
}

/// D13 error granularity (fix round B, B7): a keyed verb's error is cleared
/// only by a success under the same tag, so job B's success never clears job
/// A's error; a single-slot verb keeps clearing on its own next success.
#[test]
fn a_keyed_error_is_cleared_only_by_the_same_key() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::CallTaggedFailed {
        tag: "scan.status:scan-aaaaaaaa".into(),
        name: "scan.status".into(),
        message: "boom".into(),
    });
    let err = app
        .scan
        .last_error
        .clone()
        .expect("the failure is recorded");
    assert_eq!(err.tag, "scan.status:scan-aaaaaaaa");
    assert_eq!(err.verb, "scan.status");
    assert_eq!(err.wording(), "scan.status: boom");

    let mut sibling = fixture("scan.status.json");
    sibling["job"] = json!("scan-bbbbbbbb");
    let _ = app.on_bus(status_reply_for("scan-bbbbbbbb", sibling));
    assert_eq!(
        app.scan.last_error.as_ref().map(|e| e.tag.as_str()),
        Some("scan.status:scan-aaaaaaaa"),
        "job B's success leaves job A's error"
    );

    let mut same = fixture("scan.status.json");
    same["job"] = json!("scan-aaaaaaaa");
    let _ = app.on_bus(status_reply_for("scan-aaaaaaaa", same));
    assert_eq!(app.scan.last_error, None, "job A's own success clears it");

    let _ = app.on_bus(BusEvent::CallTaggedFailed {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        message: "boom".into(),
    });
    assert_eq!(
        app.scan.last_error.as_ref().map(|e| e.tag.as_str()),
        Some("scan.list")
    );
    let _ = app.on_bus(empty_list_reply());
    assert_eq!(
        app.scan.last_error, None,
        "a single-slot verb clears as before"
    );
}

/// D6, first row (fix round B, B9): `OpenScan` on a v2 bus requests the
/// list exactly once; a second open while it is in flight requests nothing.
#[test]
fn open_scan_requests_the_list_once() {
    let mut app = app();
    assert_eq!(app.update(Action::OpenScan), vec![list_request()]);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.jobs.listed_at_tick, 0);
    let again = app.update(Action::OpenScan);
    assert!(again.is_empty(), "the tag is still in flight: {again:?}");
}

/// D6, first row (fix round B, B9): 40 `Tick`s in `Mode::Scan` give exactly
/// one `scan.list`; 40 in `Mode::Flows` give none.
#[test]
fn forty_ticks_in_scan_mode_list_once() {
    let mut scan = app();
    let _ = scan.update(Action::OpenScan);
    let _ = scan.on_bus(empty_list_reply());
    let mut all = Vec::new();
    for _ in 0..40 {
        all.extend(tick(&mut scan));
    }
    assert_eq!(all, vec![list_request()]);
    assert_eq!(scan.scan.jobs.listed_at_tick, 40);

    let mut flows = app();
    assert_eq!(flows.mode, Mode::Flows);
    let mut none = Vec::new();
    for _ in 0..40 {
        none.extend(tick(&mut flows));
    }
    assert!(none.is_empty(), "no list outside the Scan view: {none:?}");
}

/// D6, third row (fix round B, B9): in `Mode::Scan` on the Issues tab, a
/// `finished` line yields `scan.status {job}` and `scan.issues {limit: 512}`.
/// Entering Issues fetches the list itself (Task 7), so that fetch is settled
/// with an empty page first; otherwise the tag dedupe would hold the line's
/// `scan.issues` back.
#[test]
fn a_terminal_line_on_the_issues_tab_requests_issues() {
    let mut app = app();
    let _ = app.update(Action::OpenScan);
    let _ = app.on_bus(empty_list_reply());
    let entering = app.update(Action::ScanTab(ScanTab::Issues));
    assert_eq!(
        entering,
        vec![BusRequest::CallTagged {
            tag: "scan.issues".into(),
            name: "scan.issues".into(),
            args: json!({ "limit": 512 }),
        }],
        "entering Issues fetches once"
    );
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.issues".into(),
        name: "scan.issues".into(),
        value: json!({ "issues": [] }),
    });
    assert!(app.scan.inflight.is_empty(), "the entry fetch is settled");
    let reqs = app.on_bus(job_line(fixture("job.finished.json")));
    assert_eq!(
        reqs,
        vec![
            status_request(JOB),
            BusRequest::CallTagged {
                tag: "scan.issues".into(),
                name: "scan.issues".into(),
                args: json!({ "limit": 512 }),
            },
        ]
    );
}

/// D4 (fix round B, B9): `Disconnected` drops a launch in flight.
#[test]
fn disconnect_clears_pending_launch() {
    let mut app = app();
    app.scan.launch.pending = Some(PendingLaunch {
        call: LaunchVerb::Start,
        launch: Launch {
            args: json!({ "profile_name": "standard" }),
            profile_name: Some("standard".into()),
        },
    });
    let _ = app.on_bus(BusEvent::Disconnected("x".into()));
    assert_eq!(app.scan.launch.pending, None);
}

/// D6 hostile-core bounds, the `scan.cancel` half of the keyed-reply rule
/// (plan Task 16): a `scan.cancel:<job>` reply whose `job` is another id
/// folds nothing (the polled row keeps its running state and no row
/// appears for the other id), records the uncoded `reply named a
/// different job` under the cancel tag in the Jobs slot, and settles the
/// tag so `x` is live again; the genuine reply then folds and clears it.
#[test]
fn a_cancel_reply_naming_another_job_is_not_folded() {
    let mut app = scan_app();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.on_bus(status_reply(fixture("scan.status.json")));
    let cancel_tag = format!("scan.cancel:{JOB}");
    let reqs = app.update(Action::ScanCancel);
    assert_eq!(reqs.len(), 1, "x sends the cancel: {reqs:?}");
    assert!(app.scan.inflight.contains(&cancel_tag));

    let mut forged = fixture("scan.cancel.json");
    forged["job"] = json!("scan-ffff0001");
    let reqs = app.on_bus(BusEvent::CallTaggedOk {
        tag: cancel_tag.clone(),
        name: "scan.cancel".into(),
        value: forged,
    });
    assert!(reqs.is_empty(), "a refused reply pushes nothing: {reqs:?}");
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);
    assert!(!app.scan.jobs.full.contains_key("scan-ffff0001"));
    assert!(!app.scan.jobs.summaries.contains_key("scan-ffff0001"));
    assert_eq!(
        app.scan.jobs.full[JOB].state,
        aitm_scan_model::JobState::Running,
        "the polled row keeps the state its own reply gave it"
    );
    let err = app
        .scan
        .jobs
        .error
        .as_ref()
        .expect("the mismatch is the Jobs tab's error");
    assert_eq!(err.tag, cancel_tag);
    assert_eq!(err.verb, "scan.cancel");
    assert_eq!(err.code, None);
    assert_eq!(err.detail, "reply named a different job");
    assert!(
        !app.scan.inflight.contains(&cancel_tag),
        "the tag is settled even when the reply is refused"
    );

    let reqs = app.update(Action::ScanCancel);
    assert_eq!(reqs.len(), 1, "x is live again: {reqs:?}");
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: cancel_tag,
        name: "scan.cancel".into(),
        value: fixture("scan.cancel.json"),
    });
    assert_eq!(
        app.scan.jobs.full[JOB].state,
        aitm_scan_model::JobState::Cancelling,
        "the genuine reply folds"
    );
    assert_eq!(
        app.scan.jobs.error, None,
        "and its success clears the error"
    );
}

/// D5 (plan Task 16): a `notifications/aitm/job` line is acted on only
/// when it is a scan job line that parses. A line of another kind, one
/// without an `event`, one whose `status` is not a summary, params that
/// are not an object and a line with no params at all request nothing,
/// fold nothing, record no error and never mark the flow list dirty (a
/// job line is not a flow line, whatever its shape); the well-formed line
/// still polls.
#[test]
fn a_job_line_of_another_kind_or_malformed_is_ignored() {
    let mut app = scan_app();
    let mut other_kind = fixture("job.progress.json");
    other_kind["kind"] = json!("replay");
    let mut no_event = fixture("job.progress.json");
    no_event.as_object_mut().expect("an object").remove("event");
    let mut bad_status = fixture("job.progress.json");
    bad_status["status"] = json!("not a summary");
    for (what, params) in [
        ("another kind", other_kind),
        ("no event", no_event),
        ("a status that is not a summary", bad_status),
        ("params that are a string", json!("garbage")),
        ("params that are an array", json!([1, 2, 3])),
        ("null params", Value::Null),
    ] {
        let reqs = app.on_bus(job_line(params));
        assert!(reqs.is_empty(), "{what}: requested {reqs:?}");
        assert!(app.scan.inflight.is_empty(), "{what}: nothing in flight");
        assert!(
            !app.flows_dirty,
            "{what}: a job line never marks the flow list dirty"
        );
        assert!(app.scan.jobs.order.is_empty(), "{what}: nothing folded");
        assert_eq!(
            app.scan.last_error, None,
            "{what}: an ignored line is not an error"
        );
    }
    let reqs = app.on_bus(BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
    })));
    assert!(reqs.is_empty(), "no params: {reqs:?}");
    assert!(!app.flows_dirty, "no params: not a flow line either");
    assert!(tick(&mut app).is_empty(), "nothing was left for the tick");

    assert_eq!(
        app.on_bus(progress_line()),
        vec![status_request(JOB)],
        "the well-formed line still polls"
    );
}
