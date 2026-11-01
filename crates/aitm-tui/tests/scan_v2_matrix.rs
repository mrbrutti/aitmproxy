//! Scanner v2 TUI, plan task 4: the feature-detection matrix (spec D2) and the
//! common tab chrome (D11). Three buses, three surfaces: a legacy bus (only
//! `scan.discover`) keeps today's one-shot behaviour and reaches the wire only
//! on an explicit launch; a bus with neither scanner verb hides the sidebar row
//! and says so in every tab; a v2 bus lands on Profiles and remembers the tab.
//!
//! Fixture-driven: this proves the reducer and the rendering only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode, SidebarItem};
use aitm_tui::caps::TermCaps;
use aitm_tui::fixture_app_core;
use aitm_tui::scan::{MapPane, ScanTab};
use common::*;
use serde_json::Value;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../aitm-scan-model/fixtures/",
            $name
        ))
    };
}

/// Every `scan.*` verb of the v2 contract: a test that means "a legacy bus"
/// must keep meaning that after T1b re-pins `CORE_TOOLS`.
const V2_TOOLS: &[&str] = &[
    "scan.start",
    "scan.map",
    "scan.status",
    "scan.list",
    "scan.cancel",
    "scan.issues",
    "scan.issue",
    "scan.issue.update",
    "scan.sitemap",
    "scan.checks",
    "scan.profile.list",
    "scan.profile.get",
    "scan.profile.save",
    "scan.profile.delete",
    "scan.session.preview",
];

/// The core fixture with every v2 scanner verb removed: `scan.discover` only.
fn legacy_app(cols: u16, rows: u16) -> App {
    let mut app = fixture_app_core(cols, rows);
    app.tools.retain(|t| !V2_TOOLS.contains(&t.name.as_str()));
    app
}

/// The text of every tab of the Scan view, in strip order.
fn tab_texts(app: &mut App) -> Vec<(ScanTab, String)> {
    ScanTab::ALL
        .iter()
        .map(|tab| {
            let _ = app.update(Action::ScanTab(*tab));
            (*tab, text_of(app, app.width, app.height))
        })
        .collect()
}

/// The tool names of every call (tagged or not) in `reqs`.
fn called(reqs: &[BusRequest]) -> Vec<String> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::Call { name, .. } | BusRequest::CallTagged { name, .. } => {
                Some(name.clone())
            }
            _ => None,
        })
        .collect()
}

/// D2, legacy row: with only `scan.discover` the first open lands on Jobs, the
/// one synthetic one-shot row is the Jobs tab, Profiles says what it would
/// need, and opening the view reaches the wire with nothing at all (a crawl is
/// hundreds of real navigations: only `r` / `:scan <host>` launch one).
#[test]
fn legacy_bus_opens_on_jobs_with_the_one_shot_row_and_no_scan_calls() {
    let mut app = legacy_app(200, 50);
    assert!(app.has_tool("scan.discover"));
    assert!(
        !app.has_tool("scan.start"),
        "a legacy bus has no scan.start"
    );

    let reqs = app.update(Action::OpenScan);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(
        app.scan.tab,
        ScanTab::Jobs,
        "a legacy bus has no profiles, so the first open lands on Jobs"
    );
    let scan_calls: Vec<String> = called(&reqs)
        .into_iter()
        .filter(|n| n.starts_with("scan."))
        .collect();
    assert!(
        scan_calls.is_empty(),
        "opening the view calls no scanner verb: {scan_calls:?}"
    );

    let jobs = text_of(&app, 200, 50);
    assert!(
        jobs.contains("one-shot"),
        "the Jobs tab is the legacy one-shot row: {jobs}"
    );
    // D11's common chrome: the four-tab strip, in strip order, with the
    // state banner beside it.
    let strip = line_with(&jobs, "1 Profiles").unwrap_or_default();
    assert!(
        col_of(strip, "1 Profiles") < col_of(strip, "2 Jobs")
            && col_of(strip, "2 Jobs") < col_of(strip, "3 Site map")
            && col_of(strip, "3 Site map") < col_of(strip, "4 Issues")
            && col_of(strip, "4 Issues") < col_of(strip, "idle"),
        "the tab strip reads 1 Profiles 2 Jobs 3 Site map 4 Issues, then the banner: {strip:?}"
    );

    let _ = app.update(Action::ScanTab(ScanTab::Profiles));
    let profiles = text_of(&app, 200, 50);
    assert!(
        profiles.contains("profiles need scan.profile.list (scanner v2)"),
        "Profiles is degraded on a legacy bus: {profiles}"
    );
}

/// D2, bottom row: no scanner at all. The sidebar has no Scan row (never land
/// on a row that is not drawn) and `:scan` still opens the view, which names
/// both verbs it could have been served by, in every tab.
#[test]
fn no_scanner_hides_the_row_and_scan_names_both_verbs() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &["flow.list", "flow.get"], None);
    assert!(!app.has_tool("scan.discover"));

    let flows = text_of(&app, 200, 50);
    assert!(
        !flows.lines().any(|l| l.contains(" Scan ")),
        "no Scan row without a scanner: {flows}"
    );

    let reqs = app.run_command("scan");
    assert_eq!(app.mode, Mode::Scan, "the view still opens");
    assert!(called(&reqs).is_empty(), "and calls nothing: {reqs:?}");
    for (tab, text) in tab_texts(&mut app) {
        assert!(
            text.contains("the scanner is not on this bus (scan.start / scan.discover)"),
            "{tab:?} names both verbs: {text}"
        );
    }
}

/// D2, v2 row and Architect's call 1: `scan.start` means profiles, so the
/// first open lands on Profiles; a later open restores the tab the operator
/// left on.
#[test]
fn v2_first_open_lands_on_profiles_and_remembers_the_tab() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &["scan.start", "scan.list", "scan.status"], None);

    let _ = app.update(Action::OpenScan);
    assert_eq!(
        app.scan.tab,
        ScanTab::Profiles,
        "a v2 bus opens on Profiles"
    );
    assert_eq!(app.sidebar, SidebarItem::Scan);

    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows, "Esc leaves the view");

    let _ = app.update(Action::OpenScan);
    assert_eq!(
        app.scan.tab,
        ScanTab::Jobs,
        "the second open restores the tab the operator left on"
    );
}

/// Fix round A, A2: the Site map's pane-to-list choice is made once, keyed on
/// the bus. On a v2 bus with `scan.sitemap` nodes on screen and the legacy
/// lists empty, `Down` walks the v2 nodes and `Enter` opens the selected
/// node's first flow; no legacy row is ever read.
#[test]
fn v2_site_map_enter_opens_the_v2_nodes_first_flow() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &["scan.start", "scan.sitemap", "flow.list"], None);
    let sitemap: Value = serde_json::from_str(fixture!("scan.sitemap.json")).expect("fixture");
    let result: aitm_scan_model::SitemapResult =
        serde_json::from_value(sitemap).expect("fixture parses");
    let flow_id = result.nodes[0].flows[0].to_string();
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        &flow_id,
        "GET",
        "127.0.0.1:8080",
        "/account/1",
        Some(200),
        "none",
    )]));
    app.selected = None;

    let _ = app.update(Action::OpenScan);
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    app.scan.sitemap.nodes = result.nodes;
    app.scan.sitemap.points = result.points;
    app.scan.sitemap.pane = MapPane::Nodes;
    assert!(app.scan.legacy.endpoints.is_empty() && app.scan.legacy.points.is_empty());

    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.sitemap.node_cursor, 0,
        "one node: Down stays on it"
    );
    assert_eq!(
        app.scan.legacy.endpoint_cursor, 0,
        "the legacy cursor is not touched"
    );
    let _ = app.update(Action::Enter);
    assert_eq!(
        app.selected.as_deref(),
        Some(flow_id.as_str()),
        "Enter selects the v2 node's first flow"
    );
    assert_eq!(app.mode, Mode::Inspector, "and opens it in the inspector");
}
