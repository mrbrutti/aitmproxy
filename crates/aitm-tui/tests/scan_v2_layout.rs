//! Scanner v2 TUI, plan task 14: layout at every size, narrow stacking, the
//! status-bar hints, the palette entry and the help overlay (spec D11, D13;
//! T7-14).
//!
//! Every tab renders without a panic at 200x50, 90x40, 100x30 and 40x4; below
//! 100 columns the detail pane stacks under the list; the Jobs table drops
//! its `profile` and `targets` columns when the row does not fit and the
//! detail's first line carries both (the Task 6 panel hand-off); the bottom
//! line's hints follow the tab; `:scan` still opens the view and the palette
//! and help name the surface.
//!
//! Fixture-driven: this proves the rendering only. Acceptance is the pty cell
//! against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode, BUILTIN_COMMANDS};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::ScanTab;
use aitm_tui::ui::scan::HELP;
use common::*;
use serde_json::{json, Value};

/// Every verb of the v2 surface (spec D2, D3).
const TOOLS: &[&str] = &[
    "scan.start",
    "scan.map",
    "scan.list",
    "scan.status",
    "scan.cancel",
    "scan.issues",
    "scan.issue",
    "scan.issue.update",
    "scan.sitemap",
    "scan.profile.list",
    "scan.profile.get",
    "scan.profile.save",
    "scan.profile.delete",
    "scan.checks",
    "scan.session.preview",
];

const JOB: &str = "scan-1a2b3c4d";
/// The high issue of `scan.issues.json`.
const XSS: &str = "issue-9f8e7d6c";

/// The sizes T7-14 names.
const SIZES: [(u16, u16); 4] = [(200, 50), (90, 40), (100, 30), (40, 4)];

fn reply(tag: &str, name: &str, value: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: tag.into(),
        name: name.into(),
        value,
    }
}

/// A connected v2 app at 200x50 with every tab populated from the fixture
/// pack: the `standard` editor open on Profiles, one status'd job on Jobs,
/// the site map page, and the issues page with the high issue read.
fn populated() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    let _ = app.update(Action::OpenScan);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.tab, ScanTab::Profiles);
    let _ = app.on_bus(reply("scan.list", "scan.list", json!({ "jobs": [] })));
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        fixture("scan.profile.list.json"),
    ));
    let _ = app.on_bus(reply(
        "scan.checks",
        "scan.checks",
        fixture("scan.checks.json"),
    ));
    assert_eq!(app.scan.profiles.list.len(), 7);
    // The `standard` editor, the way the operator opens it.
    app.scan.profiles.cursor = 3;
    assert_eq!(app.scan.profiles.list[3].name, "standard");
    let _ = app.update(Action::Enter);
    let _ = app.on_bus(reply(
        "scan.profile.get:standard",
        "scan.profile.get",
        fixture("scan.profile.get.json"),
    ));
    assert!(app.scan.profiles.editor.is_some(), "the editor is open");

    // One job, status'd, so its row carries profile and targets.
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let _ = app.on_bus(reply(
        &format!("scan.status:{JOB}"),
        "scan.status",
        fixture("scan.status.json"),
    ));
    assert_eq!(app.scan.jobs.order, vec![JOB.to_string()]);

    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let _ = app.on_bus(reply(
        "scan.sitemap",
        "scan.sitemap",
        fixture("scan.sitemap.json"),
    ));
    assert!(!app.scan.sitemap.nodes.is_empty(), "the map has nodes");

    let _ = app.update(Action::ScanTab(ScanTab::Issues));
    let _ = app.on_bus(reply(
        "scan.issues",
        "scan.issues",
        fixture("scan.issues.json"),
    ));
    assert_eq!(app.scan.issues.list.len(), 2);
    let mut issue = fixture("scan.issue.json");
    issue["id"] = json!(XSS);
    let _ = app.on_bus(reply(&format!("scan.issue:{XSS}"), "scan.issue", issue));
    assert_eq!(
        app.scan.issues.detail().map(|i| i.id.as_str()),
        Some(XSS),
        "the high issue is read"
    );
    let _ = app.update(Action::ScanTab(ScanTab::Profiles));
    app
}

/// `text_of` at `cols`x`rows`, the app resized to match first.
fn screen_at(app: &mut App, cols: u16, rows: u16) -> String {
    let _ = app.update(Action::Resize(cols, rows));
    text_of(app, cols, rows)
}

fn row_of(text: &str, needle: &str) -> usize {
    line_index(text, needle).unwrap_or_else(|| panic!("no line with {needle:?}:\n{text}"))
}

/// The bottom line of the screen: the status bar.
fn bottom_line(text: &str) -> &str {
    text.lines().last().unwrap_or_default()
}

/// T7-14: every tab renders at every size the criterion names without a
/// panic, with the tab strip on screen wherever there is a row for it.
#[test]
fn every_tab_renders_at_every_size() {
    let mut app = populated();
    for tab in ScanTab::ALL {
        let _ = app.update(Action::ScanTab(tab));
        for (cols, rows) in SIZES {
            let text = screen_at(&mut app, cols, rows);
            assert_eq!(
                text.lines().count(),
                usize::from(rows),
                "{tab:?} at {cols}x{rows} renders every row"
            );
            for line in text.lines() {
                assert!(
                    line.chars().count() <= usize::from(cols),
                    "{tab:?} at {cols}x{rows}: a line overran the width: {line:?}"
                );
            }
            if rows >= 8 {
                assert!(
                    text.contains("1 Profiles"),
                    "{tab:?} at {cols}x{rows} shows the tab strip:\n{text}"
                );
            }
        }
    }
}

/// T7-14, D11: at 90 columns the detail pane stacks under the list (its
/// lines sit below the last list row); at 200 the two sit side by side, so
/// the detail's head shares the list's first row and the evidence lines
/// sit within the first rows of the list.
#[test]
fn narrow_frames_stack_the_detail_below_the_list() {
    let mut app = populated();
    let _ = app.update(Action::ScanTab(ScanTab::Issues));

    let narrow = screen_at(&mut app, 90, 40);
    assert!(
        row_of(&narrow, "payload") > row_of(&narrow, "Open redirect"),
        "at 90 columns the evidence sits under the last issue row:\n{narrow}"
    );

    let wide = screen_at(&mut app, 200, 50);
    assert_eq!(
        row_of(&wide, "Reflected cross-site scripting   high"),
        row_of(&wide, "filters:"),
        "at 200 columns the detail's head shares the list's first row:\n{wide}"
    );
    // The head, class, target, location and description lines come before
    // the evidence (Task 8), so `payload` is the detail's sixth row while
    // `HIGH 1` is the list's third.
    assert!(
        row_of(&wide, "payload") <= row_of(&wide, "HIGH 1") + 3,
        "at 200 columns the evidence sits beside the list:\n{wide}"
    );

    let _ = app.update(Action::ScanTab(ScanTab::Profiles));
    let narrow = screen_at(&mut app, 90, 40);
    assert!(
        row_of(&narrow, "profile standard") > row_of(&narrow, "thorough"),
        "at 90 columns the editor sits under the profile list:\n{narrow}"
    );
}

/// T7-14 and the Task 6 panel hand-off: at 90x40 the Jobs row has no room
/// for `profile` and `targets`, so the header drops them and the detail's
/// first line carries both after the id.
#[test]
fn jobs_narrow_row_drops_profile_and_targets_into_the_detail() {
    let mut app = populated();
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let text = screen_at(&mut app, 90, 40);
    let header = text
        .lines()
        .find(|l| l.contains("state/phase"))
        .unwrap_or_else(|| panic!("no Jobs header:\n{text}"));
    let words: Vec<&str> = header.trim_matches('│').split_whitespace().collect();
    assert_eq!(
        words,
        ["job", "state/phase", "probes", "points", "issues", "el."],
        "the narrow header: {header:?}"
    );
    assert!(!header.contains("profile") && !header.contains("targets"));

    // The rule between the table and the detail: the one body row that is
    // all rule glyphs between the box's sides.
    let rule = text
        .lines()
        .position(|l| l.starts_with("│─"))
        .unwrap_or_else(|| panic!("no rule row under the table:\n{text}"));
    let first_detail = text
        .lines()
        .nth(rule + 1)
        .unwrap_or_else(|| panic!("no detail line under the rule:\n{text}"));
    assert!(
        first_detail.contains(JOB)
            && first_detail.contains("standard")
            && first_detail.contains("http://127.0.0.1:8080"),
        "the detail's first line carries id, profile and targets: {first_detail:?}"
    );
    let row = text
        .lines()
        .find(|l| l.contains("running/audit"))
        .unwrap_or_default();
    assert!(
        !row.contains("standard"),
        "the narrow row does not carry the profile: {row:?}"
    );

    let wide = screen_at(&mut app, 200, 50);
    let header = wide
        .lines()
        .find(|l| l.contains("state/phase"))
        .unwrap_or_default();
    let words: Vec<&str> = header.trim_matches('│').split_whitespace().collect();
    assert_eq!(
        words,
        [
            "job",
            "profile",
            "targets",
            "state/phase",
            "probes",
            "points",
            "issues",
            "el."
        ],
        "the full header: {header:?}"
    );
}

/// D11: the status bar's hints list the active tab's keys.
#[test]
fn hints_follow_the_tab() {
    let mut app = populated();
    for (tab, key) in [
        (ScanTab::Profiles, "s start"),
        (ScanTab::Jobs, "x cancel"),
        (ScanTab::SiteMap, "n next page"),
        (ScanTab::Issues, "f false positive"),
    ] {
        let _ = app.update(Action::ScanTab(tab));
        let text = screen_at(&mut app, 200, 50);
        let bottom = bottom_line(&text);
        assert!(
            bottom.contains(key),
            "{tab:?}: the bottom line names {key:?}: {bottom:?}"
        );
        assert!(
            bottom.contains("Esc back"),
            "{tab:?}: the bottom line names Esc back: {bottom:?}"
        );
    }
    // The legacy launch keys are not the v2 Jobs hints.
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let text = screen_at(&mut app, 200, 50);
    assert!(
        !bottom_line(&text).contains("r scan"),
        "a v2 bus has no one-shot key: {:?}",
        bottom_line(&text)
    );

    // On a legacy bus the Jobs tab's hints are the one-shot's keys (D12),
    // in the bar now rather than in the pane (Task 4 panel).
    let mut legacy = legacy_app(200, 50);
    let _ = legacy.update(Action::OpenScan);
    let _ = legacy.update(Action::ScanTab(ScanTab::Jobs));
    let text = text_of(&legacy, 200, 50);
    let bottom = bottom_line(&text);
    assert!(
        bottom.contains("r scan") && bottom.contains("F findings") && bottom.contains("Esc back"),
        "the legacy Jobs hints: {bottom:?}"
    );
    assert!(
        !text.contains("r scan (scope-bound)"),
        "the in-pane key line is gone:\n{text}"
    );
}

/// D11: `:scan` still opens the view with the open's reads; the palette
/// entry names `scan.start`; the help overlay has a Scan section with the
/// tab keys.
#[test]
fn palette_and_help_name_the_surface() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    let reqs = app.run_command("scan");
    assert_eq!(app.mode, Mode::Scan, "`:scan` opens the view");
    let names: Vec<&str> = reqs
        .iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        ["scan.list", "scan.profile.list", "scan.checks"],
        "the open's reads, nothing launched: {reqs:?}"
    );

    let (_, detail) = BUILTIN_COMMANDS
        .iter()
        .find(|(cmd, _)| *cmd == "scan")
        .unwrap_or_else(|| panic!("no `scan` palette entry: {BUILTIN_COMMANDS:?}"));
    assert_eq!(
        *detail,
        "Scan view: profiles, jobs, site map, issues (s starts scan.start; :scan <origin> starts against an origin)"
    );

    let _ = app.update(Action::Help);
    assert_eq!(app.mode, Mode::Help);
    let text = text_of(&app, 200, 50);
    // The heading is found by its own text at the box's left edge, not by a
    // ` Scan` that the `F / S / @` line also carries (fix round G, G88).
    let scan_heading = row_of(&text, "│ Scan");
    assert_eq!(
        row_of(&text, "1 2 3 4"),
        scan_heading + 1,
        "the tab keys sit right under the Scan heading:\n{text}"
    );
    assert!(!HELP.is_empty(), "the Scan help section has entries");
    for (key, what) in HELP {
        // The overlay's key column: `│ <key padded to 10>` inside the box.
        let column = format!("│ {key:<10}");
        let line = text
            .lines()
            .skip(scan_heading + 1)
            .find(|l| l.contains(&column))
            .unwrap_or_else(|| panic!("no help line for {key}:\n{text}"));
        // The entry's whole text is on the line: a clipped line fails.
        assert!(
            line.contains(what),
            "{key} help carries its whole text {what:?}: {line:?}"
        );
    }
    for (key, word) in [
        ("Profiles", "s start"),
        ("Jobs", "x cancel"),
        ("Site map", "n next page"),
        ("Issues", "f false positive"),
    ] {
        let entry = HELP
            .iter()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("no {key} entry in HELP: {HELP:?}"));
        assert!(
            entry.1.contains(word),
            "{key} help names {word:?}: {entry:?}"
        );
    }
}
