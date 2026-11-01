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

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::App;
use aitm_tui::caps::TermCaps;
use common::*;
use serde_json::{json, Value};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/",
            $name
        ))
    };
}

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.issues",
    "scan.cancel",
];

const JOB: &str = "scan-1a2b3c4d";

fn value(text: &str) -> Value {
    serde_json::from_str(text).expect("fixture is JSON")
}

/// A connected v2 app at 200x50 with the five verbs this file needs.
fn app() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    app
}

/// The `job.progress.json` push line, as the bus task hands it over.
fn progress_line() -> BusEvent {
    BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
        "params": value(fixture!("job.progress.json")),
    }))
}

/// The `scan.status.json` reply under its keyed tag.
fn status_reply(body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: format!("scan.status:{JOB}"),
        name: "scan.status".into(),
        value: body,
    }
}

fn status_requests(reqs: &[BusRequest]) -> usize {
    reqs.iter()
        .filter(|r| matches!(r, BusRequest::CallTagged { name, .. } if name == "scan.status"))
        .count()
}

fn tick(app: &mut App) -> Vec<BusRequest> {
    app.update(Action::Tick)
}

/// T7-2: a job line yields exactly one tagged `scan.status {job}` and no
/// `Refresh` (push is a trigger, poll is truth).
#[test]
fn a_job_line_triggers_one_tagged_status_and_no_refresh() {
    let mut app = app();
    let reqs = app.on_bus(progress_line());
    assert_eq!(
        reqs,
        vec![BusRequest::CallTagged {
            tag: format!("scan.status:{JOB}"),
            name: "scan.status".into(),
            args: json!({ "job": JOB }),
        }]
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
    let mut app = app();
    let mut total = 0;
    for _ in 0..4 {
        total += status_requests(&app.on_bus(progress_line()));
    }
    assert_eq!(total, 1, "one tagged status in total");
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
    let status = value(fixture!("scan.status.json"));
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
    let reqs = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: value(fixture!("scan.list.json")),
    });
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
    let mut app = app();
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
    let _ = app.on_bus(status_reply(value(fixture!("scan.status.json"))));
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
