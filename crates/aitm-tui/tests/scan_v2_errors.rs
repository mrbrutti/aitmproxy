//! Scanner v2 TUI, plan task 13: errors by code (spec D9, D13; T7-7).
//!
//! Every `CallTaggedFailed` for a `scan.*` verb becomes a `ScanError`: its
//! D9 wording is the owning tab's banner and an Error toast, an unparseable
//! message is shown verbatim as `<verb>: <message>`, `not_found` on a keyed
//! status drops the job and refreshes the list, a refused launch shows its
//! wording in the launch footer in the warning hue and leaves `s` live, and
//! the next success under the same tag clears the error.
//!
//! Fixture-driven: this proves the reducer and the drawing only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest, Level};
use aitm_tui::app::App;
use aitm_tui::scan::{ScanError, ScanTab, ERROR_DETAIL_MAX};
use common::*;
use serde_json::json;

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.map",
    "scan.list",
    "scan.status",
    "scan.cancel",
    "scan.profile.list",
    "scan.profile.get",
    "scan.checks",
    "l4.scope.list",
];

const SCOPE_HOST: &str = "auth.shop-staging.test";
const JOB: &str = "scan-1a2b3c4d";

/// The Profiles detail side's key footer (D11): the refused wording sits on
/// the row above it.
const PROFILES_FOOTER: &str = "s start · m map · w save as · e edit · Space toggle";

/// The D9 table, pinned literally: wire code, operator wording.
const D9: [(&str, &str); 9] = [
    // On a launch tag nothing is refreshed, so the clause is omitted (D9
    // as amended; fix round G, G75).
    ("not_found", "No longer known to the core (it may have restarted)"),
    (
        "busy",
        "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x)",
    ),
    (
        "out_of_scope",
        "Out of scope: add the HTTP host to Scope (S) or an L4 scope entry with the inject capability covering the target",
    ),
    (
        "refused_agent",
        "Refused for the agent role: this client is not the operator; check the token the TUI was started with",
    ),
    (
        "refused_l4",
        "L4 refused: enable `l4.enabled` in config (and the agent L4 gates for an agent-started job)",
    ),
    (
        "lane_unavailable",
        "No requested lane can run on this core; pick other lanes or a build that has them",
    ),
    (
        "invalid_profile",
        "Profile rejected; fix the named field and launch or save again",
    ),
    (
        "unknown_check",
        "Unknown check selector; remove it from include/exclude (the tree lists only loaded checks)",
    ),
    (
        "confirm_required",
        "The core wanted a confirmation this client did not send (the token may have expired); launch again to get a fresh prompt",
    ),
];

/// [`opened_v2`] at 240x50 with one host in scope: 240 columns so the
/// longest D9 wording fits the banner and one footer row.
fn opened() -> App {
    let mut app = opened_v2(TOOLS);
    let _ = app.update(Action::Resize(240, 50));
    app.scope = vec![SCOPE_HOST.to_string()];
    app
}

fn screen(app: &App) -> String {
    text_of(app, 240, 50)
}

/// The tab strip row, which carries the state banner (D11).
fn banner_line(text: &str) -> &str {
    line_with(text, "1 Profiles").expect("the tab strip is drawn")
}

/// The rows the Profiles footer reason may wrap onto (at most four, D11),
/// the detail side only, joined with one space, and the row index the
/// first of them (the one carrying `needle`) sits on. The wrap cuts after
/// a clause-ending `:`, so the wording and its detail can sit on two rows.
fn footer_reason(text: &str, needle: &str) -> (String, usize) {
    let footer =
        line_index(text, PROFILES_FOOTER).unwrap_or_else(|| panic!("the footer is drawn:\n{text}"));
    let lines: Vec<&str> = text.lines().collect();
    let first = (footer.saturating_sub(4)..footer)
        .find(|y| lines[*y].contains(needle))
        .unwrap_or_else(|| panic!("{needle:?} sits above the footer:\n{text}"));
    let joined = (first..footer)
        .map(|y| {
            // The detail side: between the pane rule and the box's right
            // border.
            lines[y].rsplit('│').nth(1).unwrap_or(lines[y]).trim()
        })
        .collect::<Vec<_>>()
        .join(" ");
    (joined, first)
}

/// The launch requests among `reqs`.
fn launch_requests(reqs: &[BusRequest]) -> Vec<&BusRequest> {
    reqs.iter()
        .filter(|r| match r {
            BusRequest::CallTagged { name, .. } | BusRequest::Call { name, .. } => {
                matches!(name.as_str(), "scan.start" | "scan.map")
            }
            _ => false,
        })
        .collect()
}

/// D9, T7-7: each of the nine codes on a failed `scan.start` reads as its
/// D9 wording then `: <detail>` on the Profiles tab and as an Error toast;
/// the toast is the same text `ScanError::wording` gives.
#[test]
fn each_code_renders_its_wording_in_the_tab_and_the_toast() {
    for (code, text) in D9 {
        let mut app = opened();
        let message = format!("scan: {code}: d");
        let out = app.on_bus(failed("scan.start", "scan.start", &message));
        assert!(
            out.is_empty(),
            "{code}: a failed launch requests nothing: {out:?}"
        );
        let expected = format!("{text}: d");
        let shown = screen(&app);
        assert!(
            shown.contains(text),
            "{code}: the D9 text is on screen:\n{shown}"
        );
        assert!(
            shown.contains(": d"),
            "{code}: the detail follows the wording:\n{shown}"
        );
        assert_eq!(toast(&app), expected, "{code}: the toast is the wording");
        assert_eq!(
            toast(&app),
            ScanError::from_message("scan.start", &message).wording(),
            "{code}: the toast is ScanError::wording"
        );
        let last = app.toasts.back().expect("a toast");
        assert_eq!(last.level, Level::Error, "{code}: an Error toast");
        let err = app
            .scan
            .profiles
            .error
            .as_ref()
            .unwrap_or_else(|| panic!("{code}: scan.start is the Profiles tab's error"));
        assert_eq!(err.wording(), expected);
    }
}

/// Fix round G, G82: the core's `detail` is bounded once, where the error
/// is made, so the banner, the footer wrap and the toast all read at most
/// `ERROR_DETAIL_MAX` cells (four times that in chars) of it, control
/// characters stripped; a 1 MiB detail still renders.
#[test]
fn a_huge_error_detail_is_bounded_at_the_error() {
    let mut app = opened();
    let detail = format!("\x1b[2J{}", "d".repeat(1 << 20));
    let _ = app.on_bus(failed(
        "scan.start",
        "scan.start",
        &format!("scan: out_of_scope: {detail}"),
    ));
    let err = app
        .scan
        .profiles
        .error
        .clone()
        .expect("the Profiles tab's error");
    assert!(
        err.detail.chars().count() <= 4 * ERROR_DETAIL_MAX,
        "{} chars",
        err.detail.chars().count()
    );
    assert!(!err.detail.contains('\x1b'), "control characters stripped");
    assert!(err.detail.ends_with('…'), "{:?}", &err.detail[..40]);
    let shown = toast(&app);
    assert!(
        shown.chars().count() <= 4 * ERROR_DETAIL_MAX + 160,
        "the toast is the bounded wording: {} chars",
        shown.chars().count()
    );
    let text = screen(&app);
    assert!(text.contains("Out of scope"), "{text}");
}

/// D9: a message outside the `scan: <code>: <detail>` shape is shown
/// verbatim as `<verb>: <message>`, on screen and in the toast.
#[test]
fn an_unparseable_message_is_shown_verbatim() {
    let mut app = opened();
    let _ = app.on_bus(failed("scan.start", "scan.start", "boom"));
    let shown = screen(&app);
    assert!(
        shown.contains("scan.start: boom"),
        "the verbatim message is on screen:\n{shown}"
    );
    assert_eq!(toast(&app), "scan.start: boom");
}

/// D9 `not_found` (spec call 8): a keyed `scan.status` that the core no
/// longer knows drops the job from `order`, `summaries`, `full` and
/// `started_here`, and the reducer asks for the list once, nothing else.
#[test]
fn not_found_on_status_drops_the_job_and_refreshes_the_list() {
    let mut app = opened();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.on_bus(reply(
        &format!("scan.status:{JOB}"),
        "scan.status",
        fixture("scan.status.json"),
    ));
    app.scan.jobs.started_here.insert(JOB.to_string());
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);
    assert!(app.scan.jobs.full.contains_key(JOB));
    assert!(app.scan.jobs.summaries.contains_key(JOB));

    let out = app.on_bus(failed(
        &format!("scan.status:{JOB}"),
        "scan.status",
        "scan: not_found: gone",
    ));
    assert!(app.scan.jobs.order.is_empty(), "{:?}", app.scan.jobs.order);
    assert!(!app.scan.jobs.full.contains_key(JOB));
    assert!(!app.scan.jobs.summaries.contains_key(JOB));
    assert!(
        !app.scan.jobs.started_here.contains(JOB),
        "a dropped job is not re-inserted at the front by the next list"
    );
    assert_eq!(
        out,
        vec![tagged("scan.list", "scan.list", json!({}))],
        "exactly one scan.list"
    );
    assert_eq!(
        toast(&app),
        "No longer known to the core (it may have restarted); the list is being refreshed: gone"
    );
    // The refreshed list without the job keeps it out (the started_here
    // mark went with it).
    let _ = app.on_bus(reply("scan.list", "scan.list", json!({ "jobs": [] })));
    assert!(app.scan.jobs.order.is_empty(), "{:?}", app.scan.jobs.order);
}

/// Fix round G, G75: `not_found` on a keyed `scan.cancel` is the same
/// self-heal as on `scan.status`: the job leaves `order`, `summaries`,
/// `full` and `started_here`, exactly one `scan.list {}` leaves, and the
/// wording keeps the refresh clause.
#[test]
fn not_found_on_cancel_drops_the_job_and_refreshes_the_list() {
    let mut app = opened();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.on_bus(reply(
        &format!("scan.status:{JOB}"),
        "scan.status",
        fixture("scan.status.json"),
    ));
    app.scan.jobs.started_here.insert(JOB.to_string());
    let out = app.on_bus(BusEvent::CallTaggedFailed {
        tag: format!("scan.cancel:{JOB}"),
        name: "scan.cancel".into(),
        message: "scan: not_found: gone".into(),
    });
    assert!(app.scan.jobs.order.is_empty());
    assert!(!app.scan.jobs.summaries.contains_key(JOB));
    assert!(!app.scan.jobs.full.contains_key(JOB));
    assert!(!app.scan.jobs.started_here.contains(JOB));
    assert_eq!(out, vec![tagged("scan.list", "scan.list", json!({}))]);
    assert_eq!(
        toast(&app),
        "No longer known to the core (it may have restarted); the list is being refreshed: gone"
    );
}

/// Fix round G, G74 (D13 as amended) and G83: the `scan.list` the
/// self-heal requested clears the `not_found` error when it lands (no
/// same-tag success can ever come); a list that still carries the healed
/// job asks no `scan.status` for it until the timer's list, so a core
/// that lists a job and answers `not_found` cannot drive a ping-pong.
#[test]
fn the_heal_list_clears_the_error_and_does_not_repoll_the_job() {
    let mut app = opened();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.on_bus(reply(
        &format!("scan.status:{JOB}"),
        "scan.status",
        fixture("scan.status.json"),
    ));
    let out = app.on_bus(failed(
        &format!("scan.status:{JOB}"),
        "scan.status",
        "scan: not_found: gone",
    ));
    assert_eq!(out, vec![tagged("scan.list", "scan.list", json!({}))]);
    assert!(app.scan.last_error.is_some());
    assert!(banner_line(&screen(&app)).contains("No longer known to the core"));

    // The requested list lands, still carrying the job (a hostile core),
    // listed as done so the four-tick status timer leaves it alone and
    // only the list path is observed.
    let mut list = fixture("scan.list.json");
    list["jobs"][0]["state"] = json!("done");
    let out = app.on_bus(reply("scan.list", "scan.list", list.clone()));
    assert_eq!(
        app.scan.last_error, None,
        "the heal's list clears the error"
    );
    assert!(
        !banner_line(&screen(&app)).contains("No longer known to the core"),
        "{}",
        screen(&app)
    );
    let status_jobs: Vec<&str> = out
        .iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { name, args, .. } if name == "scan.status" => {
                args["job"].as_str()
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        status_jobs,
        vec!["scan-55667788"],
        "no scan.status for the healed job: {out:?}"
    );

    // The timer's list polls it again.
    let mut list_sent = false;
    let mut out = Vec::new();
    for _ in 0..40 {
        let reqs = app.update(Action::Tick);
        if reqs.contains(&tagged("scan.list", "scan.list", json!({}))) {
            list_sent = true;
        }
        out.extend(reqs);
    }
    assert!(list_sent, "the forty-tick list left: {out:?}");
    assert!(
        !out.iter().any(|r| matches!(
            r,
            BusRequest::CallTagged { name, args, .. } if name == "scan.status" && args["job"] == JOB
        )),
        "nothing polled the healed job inside the window: {out:?}"
    );
    let out = app.on_bus(reply("scan.list", "scan.list", list));
    assert!(
        out.iter().any(|r| matches!(
            r,
            BusRequest::CallTagged { name, args, .. } if name == "scan.status" && args["job"] == JOB
        )),
        "the timer window re-polls the job: {out:?}"
    );
}

/// D13 refused state, D7: `out_of_scope` on a launch clears `pending`,
/// shows its wording in the launch footer in the warning hue, and leaves
/// `s` live so the operator can launch again after fixing scope.
#[test]
fn a_refused_launch_keeps_the_key_live() {
    let mut app = opened();
    app.scan.profiles.cursor = 3;
    let reqs = app.update(Action::ScanStart);
    assert_eq!(launch_requests(&reqs).len(), 1, "{reqs:?}");
    assert!(app.scan.launch.pending.is_some());

    let out = app.on_bus(failed(
        "scan.start",
        "scan.start",
        "scan: out_of_scope: evil.test is not in scope",
    ));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(app.scan.launch.pending, None);
    assert_eq!(
        app.scan.launch.blocked, None,
        "a refusal is not the UI-3 gate"
    );

    let text = screen(&app);
    let (reason, y) = footer_reason(&text, "Out of scope");
    assert!(
        reason.contains("Out of scope: add the HTTP host to Scope (S)"),
        "the refused wording sits in the footer rows:\n{text}"
    );
    assert!(
        reason.ends_with("evil.test is not in scope"),
        "with its detail: {reason}"
    );
    assert!(
        banner_line(&text).contains("Out of scope: add the HTTP host to Scope (S)"),
        "and the banner shows the tab's error:\n{text}"
    );
    let row = text.lines().nth(y).expect("the wording row");
    let x = col_of(row, "Out of scope").expect("the wording column");
    let buf = draw(&app, 240, 50);
    assert_eq!(
        cell(&buf, x, y).fg,
        theme()
            .fg(&aitm_tui::tokens::color::status::CLIENT_ERROR)
            .fg
            .expect("the theme sets a foreground"),
        "the warning hue"
    );

    let reqs = app.update(Action::ScanStart);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.start",
            "scan.start",
            json!({ "profile_name": "standard" })
        )],
        "the launch key is live again"
    );
}

/// D13: the error of a verb is shown until the next successful reply under
/// the same tag; a failed `scan.list` reads as its wording on Jobs (and as
/// the toast) and a good `scan.list` clears the banner.
#[test]
fn a_success_clears_the_error() {
    let mut app = opened();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let wording = "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x): full";
    let _ = app.on_bus(failed("scan.list", "scan.list", "scan: busy: full"));
    let shown = screen(&app);
    assert!(
        banner_line(&shown).contains(wording),
        "the wording is the banner:\n{shown}"
    );
    assert_eq!(toast(&app), wording);

    let _ = app.on_bus(reply("scan.list", "scan.list", fixture("scan.list.json")));
    let shown = screen(&app);
    assert!(
        !banner_line(&shown).contains("Scanner busy"),
        "the success cleared the banner:\n{shown}"
    );
    assert_eq!(app.scan.last_error, None);
    assert_eq!(app.scan.jobs.order.len(), 2, "the list folded");
}
