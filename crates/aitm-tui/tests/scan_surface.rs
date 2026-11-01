//! Component tests for the TUI Scan operator surface (scanner-integration
//! Stage 1, AC4). They drive the reducer and render against the core fixture
//! (`scan.discover` is in `CORE_TOOLS`), the way the other `aitm-tui` component
//! tests run. The scanner engine is `aitm-plugin-scanner`; these only exercise
//! the UI that surfaces its `scan.discover` result.

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode, SidebarItem};
use aitm_tui::keys;
use aitm_tui::scan::legacy::InjectionPointRow;
use aitm_tui::scan::ScanTab;
use aitm_tui::snapshot::{render, to_text};
use aitm_tui::theme::Theme;
use common::{legacy_app, press};
use crossterm::event::KeyCode;
use serde_json::{json, Value};

fn screen(app: &App) -> String {
    to_text(&render(app, &Theme::new(true), app.width, app.height))
}

/// Open the view and show the Site map tab, where the legacy
/// `scan.discover` result lives on a v2-shaped surface (spec D12).
fn open_site_map(app: &mut App) {
    let _ = app.update(Action::OpenScan);
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
}

/// The `scan.discover` requests among `reqs`, as their `target` arguments.
fn discover_targets(reqs: &[BusRequest]) -> Vec<String> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::Call { name, args } if name == "scan.discover" => Some(
                args.get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            _ => None,
        })
        .collect()
}

/// A `scan.discover` result: two endpoints, two injection points (one redacted
/// cookie), mirroring the scanner's `endpoints` + `injection_points` JSON. The
/// `endpoint_flows` map (AC3) links one endpoint URL to its flow id, keyed by
/// the same scrubbed URL that appears in `endpoints`; the root URL is
/// deliberately absent, to exercise the "no linked flow" path.
fn discover_result() -> Value {
    json!({
        "endpoints": [
            "http://auth.shop-staging.test/",
            "http://auth.shop-staging.test/login"
        ],
        "endpoint_flows": {
            "http://auth.shop-staging.test/login": "f50"
        },
        "injection_points": [
            { "flow": "f50", "location": "query", "name": "next", "example": "/dashboard" },
            { "flow": "f50", "location": "cookie", "name": "session", "example": "<redacted>" }
        ],
        "pages_crawled": 2,
        "stopped_reason": Value::Null
    })
}

/// Viewing the Scan panel never crawls: a `scan.discover` is up to hundreds of
/// real browser navigations against the target. `OpenScan` (the sidebar item,
/// bare `:scan`) opens the view and shows the scope-bound target `r` would
/// crawl, and sends nothing.
#[test]
fn open_scan_opens_without_launching() {
    let mut app = legacy_app(200, 50);
    assert!(
        app.has_tool("scan.discover"),
        "fixture offers scan.discover"
    );

    let reqs = app.update(Action::OpenScan);
    assert_eq!(app.mode, Mode::Scan, "OpenScan enters the Scan view");
    assert_eq!(app.sidebar, SidebarItem::Scan);
    assert!(
        !app.scan.legacy.running,
        "viewing the panel starts no crawl"
    );
    assert!(
        discover_targets(&reqs).is_empty(),
        "no scan.discover request on open: {reqs:?}"
    );
    // The header shows the scope-bound target an explicit launch would crawl:
    // the selected flow's host (f50, in scope).
    // D8 (D12 ruling): the seed is the origin rule's answer, not a
    // hard-coded `http://`; the fixture host has only https flows.
    assert_eq!(
        app.scan.legacy.target.as_deref(),
        Some("https://auth.shop-staging.test"),
        "the target is seeded for display, not launched"
    );
    let text = screen(&app);
    assert!(text.contains("idle"), "the open state reads idle: {text}");

    // Bare `:scan` is the same open-only path.
    let mut app = legacy_app(200, 50);
    let reqs = app.run_command("scan");
    assert_eq!(app.mode, Mode::Scan);
    assert!(!app.scan.legacy.running, "`:scan` alone starts no crawl");
    assert!(
        discover_targets(&reqs).is_empty(),
        "no scan.discover request from bare `:scan`: {reqs:?}"
    );
}

/// AC4 (reducer): the explicit `r` launch sends one scope-bound
/// `scan.discover` (running); a second launch while running sends nothing; the
/// matching `CallOk` populates `endpoints`/`points` and clears running.
#[test]
fn explicit_launch_emits_discover_and_result_populates_state() {
    let mut app = legacy_app(200, 50);
    let _ = app.update(Action::OpenScan);
    // `r` is the launch key the header hint names.
    assert_eq!(
        keys::map(press(KeyCode::Char('r')), Mode::Scan),
        Some(Action::ScanLaunch)
    );

    let reqs = app.update(Action::ScanLaunch);
    assert!(app.scan.legacy.running, "the launch sets the running flag");
    // D8 (D12 ruling): the launch sends the origin rule's answer for the
    // selected flow's host, which the fixture captured over https.
    assert_eq!(
        discover_targets(&reqs),
        vec!["https://auth.shop-staging.test".to_string()],
        "one scope-bound scan.discover was launched: {reqs:?}"
    );

    // The running flag disables re-launch while the crawl is in flight.
    let again = app.update(Action::ScanLaunch);
    assert!(
        discover_targets(&again).is_empty(),
        "no second crawl while one is running: {again:?}"
    );

    let _ = app.on_bus(BusEvent::CallOk {
        name: "scan.discover".into(),
        value: discover_result(),
    });
    assert!(
        !app.scan.legacy.running,
        "the CallOk clears the running flag"
    );
    assert_eq!(
        app.scan.legacy.endpoints,
        vec![
            "http://auth.shop-staging.test/".to_string(),
            "http://auth.shop-staging.test/login".to_string(),
        ],
        "endpoints populate from the result"
    );
    assert_eq!(
        app.scan.legacy.points.len(),
        2,
        "both injection points populate"
    );
    assert_eq!(app.scan.legacy.points[0].location, "query");
    assert_eq!(app.scan.legacy.points[0].name, "next");
    assert_eq!(app.scan.legacy.points[0].example, "/dashboard");
    assert_eq!(app.scan.legacy.points[1].location, "cookie");
    assert_eq!(app.scan.legacy.points[1].name, "session");
    assert_eq!(
        app.scan.legacy.points[1].example, "<redacted>",
        "the redacted cookie example is carried through verbatim, not re-derived"
    );

    // A failed/refused crawl settles the flag and keeps the reason.
    let _ = app.update(Action::ScanLaunch);
    assert!(app.scan.legacy.running);
    let _ = app.on_bus(BusEvent::CallFailed {
        name: "scan.discover".into(),
        message: "out of scope".into(),
    });
    assert!(
        !app.scan.legacy.running,
        "a CallFailed clears the running flag"
    );
    assert_eq!(app.scan.legacy.error.as_deref(), Some("out of scope"));
}

/// `:scan <target>` launches against that target, scope-gated: an in-scope
/// host (in any spelling) is crawled, an out-of-scope host is refused with a
/// toast and nothing reaches the wire (deny-by-default).
#[test]
fn scan_command_with_target_is_scope_gated() {
    let mut app = legacy_app(200, 50);
    let reqs = app.run_command("scan https://api.shop-staging.test:8443/admin?x=1");
    assert_eq!(app.mode, Mode::Scan);
    assert!(app.scan.legacy.running);
    // D8: the typed scheme and port are kept, the path dropped.
    assert_eq!(
        discover_targets(&reqs),
        vec!["https://api.shop-staging.test:8443".to_string()],
        "the typed target keeps its scheme and port, authority only: {reqs:?}"
    );

    let mut app = legacy_app(200, 50);
    let reqs = app.run_command("scan evil.example");
    assert_eq!(app.mode, Mode::Scan, "the view still opens");
    assert!(
        !app.scan.legacy.running,
        "an out-of-scope target is not launched"
    );
    assert!(
        discover_targets(&reqs).is_empty(),
        "nothing reaches the wire for an out-of-scope host: {reqs:?}"
    );
    let toast = app
        .toasts
        .back()
        .map(|t| t.text.clone())
        .unwrap_or_default();
    assert!(
        toast.contains("Out of scope") && toast.contains("evil.example"),
        "the refusal names the host: {toast:?}"
    );
}

/// AC4 (snapshot): the sidebar `Scan` row renders when `scan.discover` is
/// offered, and after an explicit launch lands its result the Scan view
/// renders its launch header, the discovered endpoints and the discovered
/// injection points.
#[test]
fn scan_sidebar_row_and_view_regions_render() {
    let mut app = legacy_app(200, 50);

    // The sidebar (drawn with the flow list) shows a Scan row when the tool is
    // offered.
    let sidebar = screen(&app);
    assert!(
        sidebar.lines().any(|l| l.contains("Scan")),
        "the sidebar lists a Scan row: {sidebar}"
    );

    // Open, launch explicitly, land a result, then render the Scan view.
    open_site_map(&mut app);
    let _ = app.update(Action::ScanLaunch);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "scan.discover".into(),
        value: discover_result(),
    });
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.sidebar, SidebarItem::Scan);

    let text = screen(&app);
    assert!(text.contains("Endpoints"), "endpoints region: {text}");
    assert!(
        text.contains("Injection points"),
        "injection-points region: {text}"
    );
    assert!(
        text.contains("login"),
        "a discovered endpoint renders: {text}"
    );
    assert!(
        text.contains("query") && text.contains("next"),
        "a discovered injection point renders its location + name: {text}"
    );
}

/// Parity with the web view's endpoint→flow links: the selected injection
/// point's `flow` (from the scanner's result) opens in the existing inspector
/// on ⏎ / →; an id no longer in the list is refused with a toast, not a crash.
#[test]
fn enter_opens_the_selected_injection_points_flow() {
    for code in [KeyCode::Enter, KeyCode::Right] {
        assert_eq!(
            keys::map(press(code), Mode::Scan),
            Some(Action::Enter),
            "{code:?} opens the point's flow"
        );
    }
    let mut app = legacy_app(200, 50);
    open_site_map(&mut app);
    let _ = app.update(Action::ScanLaunch);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "scan.discover".into(),
        value: discover_result(),
    });
    app.scan.legacy.points[1].flow = "f-missing".into();
    app.selected = None;

    assert_eq!(app.scan.legacy.cursor, 0);
    let _ = app.update(Action::Enter);
    assert_eq!(
        app.selected.as_deref(),
        Some("f50"),
        "the point's flow becomes the selection"
    );
    assert_eq!(app.mode, Mode::Inspector, "and opens in the inspector");

    // A point whose flow is gone from the list: stay put, say why.
    app.mode = Mode::Scan;
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.legacy.cursor, 1);
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Scan, "no inspector for a missing flow");
    assert_eq!(app.selected.as_deref(), Some("f50"), "selection unchanged");
    let toast = app
        .toasts
        .back()
        .map(|t| t.text.clone())
        .unwrap_or_default();
    assert!(
        toast.contains("f-missing") && toast.contains("not in the flow list"),
        "the refusal names the flow: {toast:?}"
    );
}

/// AC3 endpoint→flow link: the result's `endpoint_flows` map (endpoint URL →
/// flow id, keyed by the same scrubbed URL as `endpoints`) populates the state;
/// Tab focuses the endpoints list and ⏎ opens the selected endpoint's flow in
/// the existing inspector — parity with the injection-point path. An endpoint
/// with no entry in the map opens nothing (and does not crash).
#[test]
fn enter_opens_the_selected_endpoints_flow() {
    // Tab toggles which of the two Scan lists has the cursor.
    assert_eq!(
        keys::map(press(KeyCode::Tab), Mode::Scan),
        Some(Action::ScanPaneNext),
        "Tab switches focus between endpoints and injection points"
    );

    let mut app = legacy_app(200, 50);
    open_site_map(&mut app);
    let _ = app.update(Action::ScanLaunch);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "scan.discover".into(),
        value: discover_result(),
    });

    // `endpoint_flows` parsed into state, keyed by the scrubbed endpoint URL.
    assert_eq!(
        app.scan
            .legacy
            .endpoint_flows
            .get("http://auth.shop-staging.test/login")
            .map(String::as_str),
        Some("f50"),
        "endpoint_flows links the /login endpoint to its flow id"
    );
    assert!(
        !app.scan
            .legacy
            .endpoint_flows
            .contains_key("http://auth.shop-staging.test/"),
        "the root endpoint has no linked flow"
    );

    // Focus the endpoints list, move to /login (the second endpoint, the one
    // with a flow) and open it: parity with the injection-point ⏎ path.
    app.selected = None;
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.legacy.endpoint_cursor, 1,
        "Down moves the endpoint cursor"
    );
    let _ = app.update(Action::Enter);
    assert_eq!(
        app.selected.as_deref(),
        Some("f50"),
        "the endpoint's linked flow becomes the selection"
    );
    assert_eq!(
        app.mode,
        Mode::Inspector,
        "and opens in the existing inspector"
    );

    // An endpoint with no linked flow: stay put, select nothing.
    app.mode = Mode::Scan;
    let _ = app.update(Action::Up);
    assert_eq!(
        app.scan.legacy.endpoint_cursor, 0,
        "back on the root endpoint"
    );
    app.selected = None;
    let _ = app.update(Action::Enter);
    assert_eq!(
        app.mode,
        Mode::Scan,
        "no inspector for an endpoint with no linked flow"
    );
    assert_eq!(app.selected, None, "nothing is selected");
}

/// PgUp/PgDn page the injection-point cursor like the flow and findings lists
/// (a page is the list body: the terminal height minus the panel chrome).
#[test]
fn page_keys_move_the_injection_point_cursor() {
    let mut app = legacy_app(200, 50);
    open_site_map(&mut app);
    app.scan.legacy.points = (0..60)
        .map(|i| InjectionPointRow {
            flow: "f50".into(),
            location: "query".into(),
            name: format!("p{i}"),
            example: String::new(),
        })
        .collect();
    assert_eq!(
        keys::map(press(KeyCode::PageDown), Mode::Scan),
        Some(Action::PageDown)
    );
    // 50 rows - 10 chrome rows (three bars, two box edges, the tab strip,
    // the banner, the column header, the pane rule and a detail line)
    // = a 40-row page.
    let _ = app.update(Action::PageDown);
    assert_eq!(app.scan.legacy.cursor, 40, "one page down");
    let _ = app.update(Action::PageDown);
    assert_eq!(app.scan.legacy.cursor, 59, "clamped at the last point");
    let _ = app.update(Action::PageUp);
    assert_eq!(app.scan.legacy.cursor, 19, "one page up");
    let _ = app.update(Action::Home);
    assert_eq!(app.scan.legacy.cursor, 0);
    let _ = app.update(Action::End);
    assert_eq!(app.scan.legacy.cursor, 59);
}

/// `]`/`[` never land on the Scan row when the bus does not offer
/// `scan.discover` (the row is not drawn then); with the tool they do.
#[test]
fn sidebar_step_skips_scan_when_the_tool_is_absent() {
    let mut app = legacy_app(200, 50);
    app.tools.retain(|t| t.name != "scan.discover");
    assert!(!app.has_tool("scan.discover"));
    app.sidebar = SidebarItem::Agent;
    let _ = app.update(Action::SidebarNext);
    assert_eq!(
        app.sidebar,
        SidebarItem::Pinned,
        "] skips the invisible Scan row and wraps"
    );
    let _ = app.update(Action::SidebarPrev);
    assert_eq!(
        app.sidebar,
        SidebarItem::Agent,
        "[ skips it on the way back"
    );

    let mut app = legacy_app(200, 50);
    app.sidebar = SidebarItem::Agent;
    let _ = app.update(Action::SidebarNext);
    assert_eq!(
        app.sidebar,
        SidebarItem::Scan,
        "with scan.discover offered, ] lands on Scan"
    );
    assert_eq!(app.mode, Mode::Scan);
}

/// Fix round A, A20 (spec D12 "nothing changes in behaviour"): on a legacy bus
/// the first `Esc` on the Site map leaves the view at once, even though the
/// first open focuses the Points pane; it never spends the key flipping panes.
#[test]
fn first_esc_on_the_legacy_site_map_leaves_the_view() {
    let mut app = legacy_app(200, 50);
    open_site_map(&mut app);
    assert_eq!(app.mode, Mode::Scan);
    let _ = app.update(Action::Back);
    assert_eq!(
        app.mode,
        Mode::Flows,
        "one Esc leaves the legacy Site map (D12)"
    );
}

/// Fix round A, A13: a refused or failed legacy crawl is drawn, not only
/// stored. The Jobs tab's banner reads the reason as `scan.discover: <msg>`.
#[test]
fn a_failed_legacy_crawl_is_drawn_on_the_jobs_tab() {
    let mut app = legacy_app(200, 50);
    let _ = app.update(Action::OpenScan);
    assert_eq!(app.scan.tab, ScanTab::Jobs);
    let _ = app.update(Action::ScanLaunch);
    let _ = app.on_bus(BusEvent::CallFailed {
        name: "scan.discover".into(),
        message: "out of scope".into(),
    });
    assert_eq!(app.scan.legacy.error.as_deref(), Some("out of scope"));
    let text = screen(&app);
    assert!(
        text.contains("scan.discover: out of scope"),
        "the Jobs tab draws the failure reason: {text}"
    );
}
