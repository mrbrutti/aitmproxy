//! Scanner v2 TUI, plan task 12: launch, `StartResult`, the UI-3 gate and
//! the `scan.*` confirm wiring (spec D2, D7, D8, D10, D11, D13).
//!
//! `s` sends `scan.start` with the editor's typed draft, else the list
//! cursor's name; `:scan <origin>` sends `{target}` after the D8 rule and the
//! scope check; a `needs_confirmation` reply opens the shared overlay and
//! `y` re-issues the identical args plus `_confirm` under the same tag; a
//! `StartResult` lands in Jobs with its toasts; the UI-3 gate blocks an L4
//! launch with the D7 reason until an inject-capable L4 scope entry arrives;
//! `m` falls back to the legacy `scan.discover` when `scan.map` is absent.
//!
//! Fixture-driven: this proves the reducer and the overlay only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_scan_model::{L4TargetSpec, L4Transport, LaneKind, ScanProfile};
use aitm_tui::action::{Action, BusEvent, BusRequest, Level};
use aitm_tui::app::{App, Mode, CONFIRM_TOOLS};
use aitm_tui::caps::TermCaps;
use aitm_tui::keys;
use aitm_tui::scan::{EditorField, LaunchVerb, ProfilePane, ScanTab, EDITOR_FIELDS};
use common::*;
use crossterm::event::KeyCode;
use serde_json::json;

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.map",
    "scan.list",
    "scan.status",
    "scan.profile.list",
    "scan.profile.get",
    "scan.checks",
    "l4.scope.list",
];

const SCOPE_HOST: &str = "auth.shop-staging.test";
const ORIGIN: &str = "https://auth.shop-staging.test";

const GATE_NO_LAYER: &str = "L4 launch disabled: the L4 layer is not on this bus (l4.scope.list)";
const GATE_NO_TARGET: &str = "L4 launch disabled: add an L4 target (ip, port, proto) first";
const GATE_NO_INJECT: &str = "L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, 127.0.0.1/32 ports 7000, capability inject (l4.scope.add).";

/// The launch requests among `reqs`: `scan.start`, `scan.map` or the
/// legacy `scan.discover`, tagged or not (an open also lists jobs and
/// reads the profile list and the catalogue, which are not launches).
fn launch_requests(reqs: &[BusRequest]) -> Vec<&BusRequest> {
    reqs.iter()
        .filter(|r| match r {
            BusRequest::CallTagged { name, .. } | BusRequest::Call { name, .. } => {
                matches!(name.as_str(), "scan.start" | "scan.map" | "scan.discover")
            }
            _ => false,
        })
        .collect()
}

/// A connected v2 app at 200x50 on Flows, with one host in scope and no
/// captured flows, so a typed `https://` origin keeps its scheme (D8).
fn connected_with(tool_names: &[&str]) -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, tool_names, None);
    app.scope = vec![SCOPE_HOST.to_string()];
    app
}

/// [`opened_v2`] with one host in scope.
fn opened_with(tool_names: &[&str]) -> App {
    let mut app = opened_v2(tool_names);
    app.scope = vec![SCOPE_HOST.to_string()];
    app
}

fn opened() -> App {
    opened_with(TOOLS)
}

/// Open the `standard` editor the way the operator does (plan task 10):
/// cursor on row 3, `Enter`, the `scan.profile.get.json` reply.
fn open_standard(app: &mut App) {
    app.scan.profiles.cursor = 3;
    let reqs = app.update(Action::Enter);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.profile.get:standard",
            "scan.profile.get",
            json!({ "name": "standard" })
        )]
    );
    let _ = app.on_bus(reply(
        "scan.profile.get:standard",
        "scan.profile.get",
        fixture("scan.profile.get.json"),
    ));
    let editor = app
        .scan
        .profiles
        .editor
        .as_ref()
        .expect("the editor opened");
    assert_eq!(editor.draft.name, "standard");
    assert_eq!(editor.draft.lanes, vec![LaneKind::Http, LaneKind::Ws]);
}

/// Put the Fields cursor on `field`.
fn focus_field(app: &mut App, field: EditorField) {
    app.scan.profiles.pane = ProfilePane::Fields;
    let idx = EDITOR_FIELDS
        .iter()
        .position(|f| *f == field)
        .expect("a D3 field");
    app.scan.profiles.editor.as_mut().expect("an editor").field = idx;
}

/// Space on a lane field, the operator's way of flipping a lane.
fn toggle_lane(app: &mut App, field: EditorField) {
    focus_field(app, field);
    let reqs = app.update(Action::ScanToggle);
    assert!(reqs.is_empty(), "a lane toggle sends nothing: {reqs:?}");
}

/// Turn the `standard` draft into an L4-stream-only one through the Fields
/// pane: http off, ws off, l4_stream on.
fn make_l4_stream_only(app: &mut App) {
    toggle_lane(app, EditorField::LaneHttp);
    toggle_lane(app, EditorField::LaneWs);
    toggle_lane(app, EditorField::LaneL4Stream);
    let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
    assert_eq!(draft.lanes, vec![LaneKind::L4Stream]);
}

/// The `t` prompt with `127.0.0.1:7000/tcp`.
fn add_l4_target(app: &mut App) {
    let _ = app.update(Action::ScanL4TargetPrompt);
    for c in "127.0.0.1:7000/tcp".chars() {
        let _ = app.update(Action::Input(c));
    }
    let reqs = app.update(Action::Submit);
    assert!(reqs.is_empty(), "an L4 target sends nothing: {reqs:?}");
    assert_eq!(app.mode, Mode::Scan);
    let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
    assert_eq!(
        draft.target.l4,
        vec![L4TargetSpec {
            ip: "127.0.0.1".into(),
            port: 7000,
            proto: L4Transport::Tcp,
            grammar: None,
        }]
    );
}

fn toast_texts(app: &App) -> Vec<(Level, String)> {
    app.toasts
        .iter()
        .map(|t| (t.level, t.text.clone()))
        .collect()
}

/// D11: `s` and `m` are the launch keys in `Mode::Scan`.
#[test]
fn launch_keys_map_to_their_actions() {
    assert_eq!(
        keys::map(press(KeyCode::Char('s')), Mode::Scan),
        Some(Action::ScanStart)
    );
    assert_eq!(
        keys::map(press(KeyCode::Char('m')), Mode::Scan),
        Some(Action::ScanMap)
    );
}

/// D7, T7-4: from the editor `s` sends `scan.start { profile }` with the
/// whole typed draft, records the pending launch, and a second `s` is
/// refused locally while the first is in flight.
#[test]
fn start_from_the_editor_sends_the_typed_profile() {
    let mut app = opened();
    open_standard(&mut app);
    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "exactly one request: {reqs:?}");
    let BusRequest::CallTagged { tag, name, args } = &reqs[0] else {
        panic!("a tagged call: {reqs:?}");
    };
    assert_eq!(tag, "scan.start");
    assert_eq!(name, "scan.start");
    assert_eq!(
        args.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec!["profile".to_string()]),
        "the editor launch carries the profile and nothing else: {args}"
    );
    let sent: ScanProfile = serde_json::from_value(args["profile"].clone()).unwrap();
    let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
    assert_eq!(&sent, draft, "the wire profile is the draft, round-tripped");
    assert_eq!(sent.name, "standard");
    let pending = app.scan.launch.pending.as_ref().expect("a pending launch");
    assert_eq!(pending.call, LaunchVerb::Start);
    assert_eq!(pending.launch.profile_name.as_deref(), Some("standard"));
    assert!(app.scan.inflight.contains("scan.start"));

    let reqs = app.update(Action::ScanStart);
    assert!(reqs.is_empty(), "a second launch is refused: {reqs:?}");
    assert_eq!(toast(&app), "a launch is already in flight");
}

/// D7, T7-4: without an editor, `s` on a list row sends the row's name.
#[test]
fn start_from_the_list_sends_the_name() {
    let mut app = opened();
    assert!(app.scan.profiles.editor.is_none());
    app.scan.profiles.cursor = 3;
    let reqs = app.update(Action::ScanStart);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.start",
            "scan.start",
            json!({ "profile_name": "standard" })
        )]
    );
    let pending = app.scan.launch.pending.as_ref().expect("a pending launch");
    assert_eq!(pending.launch.args, json!({ "profile_name": "standard" }));
    assert_eq!(pending.launch.profile_name.as_deref(), Some("standard"));
}

/// D8, T7-4: `:scan <origin>` under v2 sends `scan.start { target }` with the
/// typed origin's scheme kept; a host the scope does not cover sends no
/// `scan.*` call and toasts the D8 text naming the host.
#[test]
fn scan_command_with_an_origin_sends_target_or_refuses() {
    let mut app = connected_with(TOOLS);
    let reqs = app.run_command(&format!("scan {ORIGIN}"));
    // The one launch among the open's reads: a tagged `scan.start`, never
    // the legacy `scan.discover` (which `launch_requests` would list).
    assert_eq!(
        launch_requests(&reqs),
        vec![&tagged(
            "scan.start",
            "scan.start",
            json!({ "target": ORIGIN })
        )],
        "all requests: {reqs:?}"
    );
    assert_eq!(
        app.scan.launch.pending.as_ref().map(|p| p.call.as_str()),
        Some("scan.start")
    );
    assert_eq!(app.mode, Mode::Scan);

    let mut app = connected_with(TOOLS);
    let reqs = app.run_command("scan evil.test");
    assert!(
        launch_requests(&reqs).is_empty(),
        "an out-of-scope host launches nothing: {reqs:?}"
    );
    assert_eq!(
        toast(&app),
        "Out of scope: add `evil.test` to scope to scan it",
        ":scan evil.test toasts the D8 text naming the host"
    );
    assert_eq!(app.scan.launch.pending, None);
}

/// Fix round G, G61 and G14: the D8 scope refusal is one rule with one
/// literal on every path: `:scan <origin>` under v2, `s` from an editor
/// whose draft holds an uncovered origin, the `o` prompt, and the legacy
/// `:scan <host>`; none of them reaches the wire.
#[test]
fn every_scope_refusal_path_toasts_the_one_literal() {
    const LITERAL: &str = "Out of scope: add `evil.test` to scope to scan it";

    let mut app = connected_with(TOOLS);
    let reqs = app.run_command("scan https://evil.test");
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(toast(&app), LITERAL, ":scan under v2");

    let mut app = opened();
    open_standard(&mut app);
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push("https://evil.test".to_string());
    let reqs = app.update(Action::ScanStart);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(toast(&app), LITERAL, "s from the editor");

    let mut app = opened();
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    for c in "https://evil.test".chars() {
        let _ = app.update(Action::Input(c));
    }
    let reqs = app.update(Action::Submit);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(toast(&app), LITERAL, "the o prompt");

    let mut app = legacy_app(200, 50);
    app.scope = vec![SCOPE_HOST.to_string()];
    let reqs = app.run_command("scan evil.test");
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(toast(&app), LITERAL, "the legacy :scan");

    // The legacy launch with nothing in scope names what to do, without
    // an em dash (G14).
    let mut app = legacy_app(200, 50);
    app.scope.clear();
    app.selected = None;
    let _ = app.update(Action::OpenScan);
    let reqs = app.update(Action::ScanLaunch);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(
        toast(&app),
        "Scan needs an in-scope host: add one to scope (S) first"
    );
}

/// D7: `scan.start` is not a local `y/N` tool; the server decides whether a
/// launch needs a confirmation over the wire.
#[test]
fn scan_start_is_not_a_local_confirm_tool() {
    assert!(!CONFIRM_TOOLS.contains(&"scan.start"));
    assert!(!CONFIRM_TOOLS.contains(&"scan.map"));
}

/// D7, T7-5: a `needs_confirmation` reply opens the overlay with the
/// server's prompt and the scan-launch title; `y` re-issues the identical
/// args plus `_confirm` under the same tag; `n` on a fresh prompt sends
/// nothing, toasts `scan.start cancelled` and clears the pending launch.
#[test]
fn needs_confirmation_opens_the_overlay_y_reissues_n_cancels() {
    let mut app = opened();
    app.scan.profiles.cursor = 3;
    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "{reqs:?}");

    let reqs = app.on_bus(reply(
        "scan.start",
        "scan.start",
        json!({ "status": "needs_confirmation", "prompt": "Prompt-7Q verbatim", "confirm_token": "tok-1" }),
    ));
    assert!(
        reqs.is_empty(),
        "a prompt sends nothing by itself: {reqs:?}"
    );
    assert_eq!(app.mode, Mode::WireConfirm);
    assert!(
        app.scan.launch.pending.is_some(),
        "the launch stays pending through the prompt"
    );
    assert!(
        !app.scan.inflight.contains("scan.start"),
        "the first call is answered"
    );
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Prompt-7Q verbatim"), "{text}");
    assert!(text.contains("scan launch"), "{text}");

    let reqs = app.update(Action::WireConfirm(true));
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.start",
            "scan.start",
            json!({ "profile_name": "standard", "_confirm": "tok-1" })
        )]
    );
    assert_eq!(app.mode, Mode::Scan, "the overlay closes to the Scan view");
    assert!(
        app.scan.inflight.contains("scan.start"),
        "re-issued under its tag"
    );
    assert!(
        app.scan.launch.pending.is_some(),
        "still pending until the result"
    );

    let _ = app.on_bus(reply(
        "scan.start",
        "scan.start",
        json!({ "status": "needs_confirmation", "prompt": "Prompt-8R", "confirm_token": "tok-2" }),
    ));
    assert_eq!(app.mode, Mode::WireConfirm);
    let reqs = app.update(Action::WireConfirm(false));
    assert!(reqs.is_empty(), "cancel sends nothing: {reqs:?}");
    assert_eq!(toast(&app), "scan.start cancelled");
    assert_eq!(app.scan.launch.pending, None);
    assert_eq!(app.mode, Mode::Scan);
    assert!(app.wire_confirm.is_none());

    // The key is live again after a cancel.
    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "a fresh launch leaves: {reqs:?}");
}

/// D7, D10, T7-4: a `StartResult` folds its status into Jobs, puts the new
/// job first with the cursor on it, clears the pending launch, toasts the
/// start line and a second Warn toast for the clamped fields.
#[test]
fn a_start_result_lands_in_jobs_with_its_toasts() {
    let mut app = opened();
    app.scan.profiles.cursor = 3;
    let _ = app.update(Action::ScanStart);
    app.toasts.clear();

    let reqs = app.on_bus(reply(
        "scan.start",
        "scan.start",
        fixture("scan.start.json"),
    ));
    assert!(
        !reqs.iter().any(|r| matches!(r, BusRequest::Refresh)),
        "no flow refresh from a scan reply (D4): {reqs:?}"
    );
    assert_eq!(app.scan.tab, ScanTab::Jobs);
    assert_eq!(app.scan.jobs.order, vec!["scan-1a2b3c4d".to_string()]);
    assert_eq!(app.scan.jobs.cursor, 0);
    assert!(
        app.scan.jobs.started_here.contains("scan-1a2b3c4d"),
        "B3: marked started here"
    );
    let full = app
        .scan
        .jobs
        .full
        .get("scan-1a2b3c4d")
        .expect("the status is folded");
    assert_eq!(full.profile_name, "standard");
    assert_eq!(full.targets, vec!["http://127.0.0.1:8080".to_string()]);
    assert!(app.scan.jobs.summaries.contains_key("scan-1a2b3c4d"));
    assert_eq!(app.scan.launch.pending, None);
    assert!(!app.scan.inflight.contains("scan.start"));

    let toasts = toast_texts(&app);
    assert!(
        toasts.contains(&(
            Level::Info,
            "scan-1a2b3c4d started: standard (http)".to_string()
        )),
        "{toasts:?}"
    );
    assert!(
        toasts.contains(&(
            Level::Warn,
            "clamped: budget.probes 50000 -> 20000".to_string()
        )),
        "{toasts:?}"
    );
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("scan-1a2b3c4d"),
        "the Jobs row is on screen: {text}"
    );
}

/// D7, T7-6: an L4-stream draft with a target but no inject-capable L4
/// scope entry shows the D7 reason naming the entry to add and `s` sends
/// nothing; an `L4Scope` event carrying such an entry clears the reason
/// and the same `s` sends one `scan.start`.
#[test]
fn the_l4_gate_blocks_without_an_inject_entry() {
    let mut app = opened();
    open_standard(&mut app);
    assert_eq!(app.scan.launch.blocked, None, "an HTTP draft is not gated");
    make_l4_stream_only(&mut app);
    add_l4_target(&mut app);
    assert!(app.l4.scope.is_empty());
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_INJECT));

    let text = text_of(&app, 200, 50);
    for want in [
        "interface \"*\"",
        "direction outbound",
        "127.0.0.1/32",
        "7000",
        "capability inject",
    ] {
        assert!(text.contains(want), "{want:?} missing from:\n{text}");
    }
    let reqs = app.update(Action::ScanStart);
    assert!(reqs.is_empty(), "a blocked launch sends nothing: {reqs:?}");
    assert_eq!(app.scan.launch.pending, None);

    let reqs = app.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "*", "capability": "inject", "cidr": "127.0.0.1/32",
        "ports": "7000", "direction": "outbound"
    })]));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.launch.blocked, None);
    assert!(!text_of(&app, 200, 50).contains("L4 launch disabled"));

    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let BusRequest::CallTagged { tag, name, args } = &reqs[0] else {
        panic!("a tagged call: {reqs:?}");
    };
    assert_eq!((tag.as_str(), name.as_str()), ("scan.start", "scan.start"));
    let sent: ScanProfile = serde_json::from_value(args["profile"].clone()).unwrap();
    assert_eq!(sent.lanes, vec![LaneKind::L4Stream]);
    assert_eq!(sent.target.l4[0].port, 7000);

    // A capture-only entry does not open the gate.
    let mut app = opened();
    open_standard(&mut app);
    make_l4_stream_only(&mut app);
    add_l4_target(&mut app);
    let _ = app.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "*", "capability": "capture", "cidr": "127.0.0.1/32",
        "ports": "7000", "direction": "outbound"
    })]));
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_INJECT));
}

/// D7: the gate's three reasons in D7 order: the L4 layer missing from the
/// bus comes first, an empty `draft.target.l4` second.
#[test]
fn the_gate_names_the_missing_layer_and_target() {
    let without_l4: Vec<&str> = TOOLS
        .iter()
        .copied()
        .filter(|t| *t != "l4.scope.list")
        .collect();
    let mut app = opened_with(&without_l4);
    open_standard(&mut app);
    make_l4_stream_only(&mut app);
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_LAYER));
    add_l4_target(&mut app);
    assert_eq!(
        app.scan.launch.blocked.as_deref(),
        Some(GATE_NO_LAYER),
        "the layer comes before the target"
    );
    assert!(app.update(Action::ScanStart).is_empty());
    assert!(text_of(&app, 200, 50).contains("(l4.scope.list)"));

    let mut app = opened();
    open_standard(&mut app);
    make_l4_stream_only(&mut app);
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_TARGET));
    assert!(app.update(Action::ScanStart).is_empty());
    assert!(text_of(&app, 200, 50).contains("add an L4 target"));

    // Dropping the L4 lane again opens the gate.
    toggle_lane(&mut app, EditorField::LaneL4Stream);
    assert_eq!(app.scan.launch.blocked, None);
}

/// Task 10 security ruling (D11): an origin that reached the draft from
/// `scan.profile.get`, or outlived a scope shrink, is re-checked on `s`;
/// a host the scope does not cover refuses the launch with the D8 toast.
#[test]
fn start_refuses_a_draft_origin_outside_scope() {
    let mut app = opened();
    open_standard(&mut app);
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push("https://evil.test".to_string());
    let reqs = app.update(Action::ScanStart);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(app.scan.launch.pending, None);
    assert_eq!(
        toast(&app),
        "Out of scope: add `evil.test` to scope to scan it",
        "s from the editor toasts the D8 text naming the host"
    );

    // `m` applies the same rule.
    let reqs = app.update(Action::ScanMap);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(app.scan.launch.pending, None);

    // An in-scope origin passes.
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .retain(|o| o != "https://evil.test");
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push(ORIGIN.to_string());
    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
}

/// D2, D7: `m` sends `scan.map` when the bus has it; without it, with
/// `scan.discover` present, the map falls back to the legacy one-shot on the
/// draft's first origin through the legacy path.
#[test]
fn map_falls_back_to_discover() {
    let mut app = opened();
    open_standard(&mut app);
    let reqs = app.update(Action::ScanMap);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let BusRequest::CallTagged { tag, name, args } = &reqs[0] else {
        panic!("a tagged call: {reqs:?}");
    };
    assert_eq!((tag.as_str(), name.as_str()), ("scan.map", "scan.map"));
    let sent: ScanProfile = serde_json::from_value(args["profile"].clone()).unwrap();
    assert_eq!(sent.name, "standard");
    assert_eq!(
        app.scan.launch.pending.as_ref().map(|p| p.call.as_str()),
        Some("scan.map")
    );

    let with_discover: Vec<&str> = TOOLS
        .iter()
        .copied()
        .filter(|t| *t != "scan.map")
        .chain(["scan.discover"])
        .collect();
    let mut app = opened_with(&with_discover);
    open_standard(&mut app);
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push(ORIGIN.to_string());
    let reqs = app.update(Action::ScanMap);
    assert_eq!(
        reqs,
        vec![BusRequest::Call {
            name: "scan.discover".into(),
            args: json!({ "target": ORIGIN }),
        }]
    );
    assert_eq!(
        app.scan.launch.pending, None,
        "the legacy one-shot is not a v2 launch"
    );
    assert!(
        app.scan.legacy.running,
        "the legacy path tracks the one-shot"
    );

    // Neither verb: inert with the reason.
    let without_both: Vec<&str> = TOOLS.iter().copied().filter(|t| *t != "scan.map").collect();
    let mut app = opened_with(&without_both);
    open_standard(&mut app);
    let reqs = app.update(Action::ScanMap);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(toast(&app), "scan.map is not on this bus");
}

/// Fix round G, G71 (D7 as amended): the UI-3 L4 gate holds `s` only; a
/// map runs no L4 lane, so `m` on an L4-blocked draft with an in-scope
/// origin sends one `scan.map`.
#[test]
fn the_l4_gate_holds_start_but_not_map() {
    let mut app = opened();
    open_standard(&mut app);
    make_l4_stream_only(&mut app);
    add_l4_target(&mut app);
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push(ORIGIN.to_string());
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_INJECT));
    let reqs = app.update(Action::ScanStart);
    assert!(reqs.is_empty(), "s is held: {reqs:?}");
    let reqs = app.update(Action::ScanMap);
    assert_eq!(reqs.len(), 1, "m is not: {reqs:?}");
    let BusRequest::CallTagged { tag, name, .. } = &reqs[0] else {
        panic!("a tagged call: {reqs:?}");
    };
    assert_eq!((tag.as_str(), name.as_str()), ("scan.map", "scan.map"));
}

/// Fix round G, G72: the start toast joins the distinct run lanes (four at
/// most, declaration order) and is cut to the save toast's width, so a
/// reply with a hundred thousand `http` lanes toasts one `http`.
#[test]
fn the_start_toast_dedupes_the_run_lanes() {
    let mut app = opened();
    app.scan.profiles.cursor = 3;
    let _ = app.update(Action::ScanStart);
    app.toasts.clear();
    let mut start = fixture("scan.start.json");
    start["lanes"]["run"] = json!(vec!["http"; 100_000]);
    let _ = app.on_bus(reply("scan.start", "scan.start", start));
    let toasts = toast_texts(&app);
    assert!(
        toasts.contains(&(
            Level::Info,
            "scan-1a2b3c4d started: standard (http)".to_string()
        )),
        "{toasts:?}"
    );
    assert!(toasts.iter().all(|(_, t)| t.chars().count() <= 4 * 200));
}

/// Fix round G, G73 (D7 as amended): with no editor the UI-3 gate reads
/// the Profiles cursor row's lanes: the layer text when `l4.scope.list` is
/// absent, else the text naming the editor; `s` stays inert while it
/// holds and the Profiles footer shows it; an HTTP row is not gated.
#[test]
fn a_list_row_with_an_l4_lane_is_gated_without_an_editor() {
    const GATE_OPEN_PROFILE: &str =
        "L4 launch disabled: open the profile (⏎) to check its L4 target and scope";
    let without_layer: Vec<&str> = TOOLS
        .iter()
        .copied()
        .filter(|t| *t != "l4.scope.list")
        .collect();
    let mut app = opened_with(&without_layer);
    assert!(app.scan.profiles.editor.is_none());
    let _ = app.update(Action::End);
    let _ = app.update(Action::Up);
    assert_eq!(
        app.scan.profiles.list[app.scan.profiles.cursor].name,
        "l4-stream-safe"
    );
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_NO_LAYER));
    let text = text_of(&app, 200, 50);
    assert!(text.contains(GATE_NO_LAYER), "{text}");
    let reqs = app.update(Action::ScanStart);
    assert!(launch_requests(&reqs).is_empty(), "{reqs:?}");

    let mut app = opened();
    let _ = app.update(Action::End);
    assert_eq!(
        app.scan.profiles.list[app.scan.profiles.cursor].name,
        "l4-full"
    );
    assert_eq!(app.scan.launch.blocked.as_deref(), Some(GATE_OPEN_PROFILE));
    let text = text_of(&app, 200, 50);
    assert!(text.contains(GATE_OPEN_PROFILE), "{text}");
    assert!(launch_requests(&app.update(Action::ScanStart)).is_empty());

    for _ in 0..3 {
        let _ = app.update(Action::Up);
    }
    assert_eq!(
        app.scan.profiles.list[app.scan.profiles.cursor].name,
        "standard"
    );
    assert_eq!(app.scan.launch.blocked, None);
    let reqs = app.update(Action::ScanStart);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.start",
            "scan.start",
            json!({ "profile_name": "standard" })
        )]
    );
}

/// Fix round G, G67: a second wire confirm replacing a `scan.*` one on
/// screen toasts `<call> confirmation dropped` and clears the pending
/// launch; `y` on a confirm whose re-issue the reducer refuses clears it
/// too; a launch reply with no pending launch is recorded, not folded.
#[test]
fn a_replaced_scan_confirm_drops_its_pending_launch() {
    let mut app = opened();
    app.scan.profiles.cursor = 3;
    let _ = app.update(Action::ScanStart);
    let _ = app.on_bus(reply(
        "scan.start",
        "scan.start",
        json!({ "status": "needs_confirmation", "prompt": "P1", "confirm_token": "tok-1" }),
    ));
    assert_eq!(app.mode, Mode::WireConfirm);
    assert!(app.scan.launch.pending.is_some());

    // An L4 inject in flight (the handshake opens the overlay only for the
    // pending call of its name, L4 parity spec §3).
    app.l4.pending = Some(("l4.inject".to_string(), json!({ "flow": "l4-1" })));
    let _ = app.on_bus(BusEvent::CallOk {
        name: "l4.inject".into(),
        value: json!({ "status": "needs_confirmation", "prompt": "P2", "confirm_token": "tok-2" }),
    });
    assert_eq!(app.mode, Mode::WireConfirm);
    assert_eq!(
        app.wire_confirm.as_ref().map(|c| c.call.as_str()),
        Some("l4.inject")
    );
    assert_eq!(
        app.scan.launch.pending, None,
        "the stranded launch is cleared"
    );
    let toasts = toast_texts(&app);
    assert!(
        toasts.contains(&(Level::Warn, "scan.start confirmation dropped".to_string())),
        "{toasts:?}"
    );
    let _ = app.update(Action::WireConfirm(false));

    // `y` whose re-issue is refused (the verb left the bus) clears pending.
    let _ = app.update(Action::ScanStart);
    let _ = app.on_bus(reply(
        "scan.start",
        "scan.start",
        json!({ "status": "needs_confirmation", "prompt": "P3", "confirm_token": "tok-3" }),
    ));
    assert!(app.scan.launch.pending.is_some());
    app.tools.retain(|t| t.name != "scan.start");
    let reqs = app.update(Action::WireConfirm(true));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.scan.launch.pending, None);

    // A launch reply with nothing pending is an uncoded error, not a fold.
    let mut app = opened();
    assert_eq!(app.scan.launch.pending, None);
    let reqs = app.on_bus(reply(
        "scan.start",
        "scan.start",
        fixture("scan.start.json"),
    ));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert!(app.scan.jobs.order.is_empty(), "nothing folded");
    assert_eq!(
        app.scan.last_error.as_ref().map(|e| e.detail.as_str()),
        Some("reply with no pending launch")
    );
}

/// D7, D13: while the gate holds a reason, the Jobs tab's footer shows it
/// too (`s` is live there), in the warning hue, above the key footer.
#[test]
fn the_jobs_footer_shows_the_blocked_reason() {
    let mut app = opened();
    open_standard(&mut app);
    app.scan.profiles.cursor = 3;
    let _ = app.update(Action::ScanStart);
    let _ = app.on_bus(reply(
        "scan.start",
        "scan.start",
        fixture("scan.start.json"),
    ));
    assert_eq!(app.scan.tab, ScanTab::Jobs);
    assert!(!text_of(&app, 200, 50).contains("L4 launch disabled"));

    app.scan.launch.blocked = Some(GATE_NO_INJECT.to_string());
    for (cols, rows) in [(200u16, 50u16), (90, 40)] {
        let text = text_of(&app, cols, rows);
        let y = line_index(&text, "L4 launch disabled")
            .unwrap_or_else(|| panic!("{cols}x{rows}: the reason is drawn:\n{text}"));
        let footer = line_index(&text, "x cancel")
            .unwrap_or_else(|| panic!("{cols}x{rows}: the footer is drawn:\n{text}"));
        assert!(
            y < footer,
            "{cols}x{rows}: the reason sits above the footer"
        );
        let x = col_of(text.lines().nth(y).unwrap_or_default(), "L4 launch").unwrap_or_default();
        let buf = draw(&app, cols, rows);
        assert_eq!(
            cell(&buf, x, y).fg,
            theme()
                .fg(&aitm_tui::tokens::color::status::CLIENT_ERROR)
                .fg
                .unwrap_or_default(),
            "{cols}x{rows}: the warning hue"
        );
    }
    assert!(
        app.update(Action::ScanStart).is_empty(),
        "blocked in Jobs too"
    );
}

/// Fix round G, G62: the one "already running" guard sits in
/// `scan_launch`, so every legacy launch path (`r`, `:scan <host>`, `s`
/// on a legacy bus, and the `m` fallback to `scan.discover` on a v2 bus
/// without `scan.map`) answers a running crawl with the one toast and
/// sends nothing.
#[test]
fn every_legacy_launch_path_shares_the_running_guard() {
    const RUNNING: &str = "a scan is already running";
    let mut legacy = legacy_app(200, 50);
    let _ = legacy.update(Action::OpenScan);
    legacy.scan.legacy.running = true;
    for (what, action) in [("r", Action::ScanLaunch), ("s", Action::ScanStart)] {
        let reqs = legacy.update(action);
        assert!(launch_requests(&reqs).is_empty(), "{what}: {reqs:?}");
        assert_eq!(toast(&legacy), RUNNING, "{what}");
        legacy.toasts.clear();
    }
    let reqs = legacy.run_command("scan auth.shop-staging.test");
    assert!(launch_requests(&reqs).is_empty(), ":scan: {reqs:?}");
    assert_eq!(toast(&legacy), RUNNING, ":scan <host>");

    // A v2 bus without `scan.map` but with `scan.discover`: `m` falls to
    // the legacy crawl, through the same guard.
    let tools: Vec<&str> = TOOLS
        .iter()
        .copied()
        .filter(|t| *t != "scan.map")
        .chain(["scan.discover"])
        .collect();
    let mut app = opened_with(&tools);
    open_standard(&mut app);
    // The fallback needs an origin to crawl before it reaches the guard
    // (with none, `map needs an origin` is the refusal).
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("editor")
        .draft
        .target
        .origins
        .push(format!("https://{SCOPE_HOST}"));
    app.scan.legacy.running = true;
    let reqs = app.update(Action::ScanMap);
    assert!(launch_requests(&reqs).is_empty(), "m fallback: {reqs:?}");
    assert_eq!(toast(&app), RUNNING, "m fallback");
}

/// D6 and the Task 12 ruling in D11 (pinned in plan Task 16): a
/// `StartResult` is folded only when its `job` is in the wire form and
/// `status.job` names the same job. A reply whose status names another
/// job, and one whose id is forged, leave Jobs empty and the tab on
/// Profiles, toast no start line, clear the pending launch (the reply
/// answered it) and record an uncoded error under `scan.start`; a
/// `needs_confirmation` reply without a `confirm_token` opens no overlay
/// and is a contract error that frees the key the same way.
#[test]
fn a_start_result_is_folded_only_under_its_own_job() {
    let mut mismatch = fixture("scan.start.json");
    mismatch["status"]["job"] = json!("scan-ffff0001");
    let mut forged = fixture("scan.start.json");
    forged["job"] = json!("scan-../../x");
    forged["status"]["job"] = json!("scan-../../x");
    let no_token = json!({ "status": "needs_confirmation", "prompt": "Prompt-7Q verbatim" });
    for (what, value, detail) in [
        (
            "status names another job",
            mismatch,
            "reply named a different job",
        ),
        (
            "a forged id",
            forged,
            "reply named a job id outside the wire form",
        ),
        (
            "a confirm without a token",
            no_token,
            "reply did not match the contract (",
        ),
    ] {
        let mut app = opened();
        app.scan.profiles.cursor = 3;
        let reqs = app.update(Action::ScanStart);
        assert_eq!(reqs.len(), 1, "{what}: {reqs:?}");
        app.toasts.clear();

        let reqs = app.on_bus(reply("scan.start", "scan.start", value));
        assert!(reqs.is_empty(), "{what}: {reqs:?}");
        assert_eq!(app.mode, Mode::Scan, "{what}: no overlay");
        assert!(app.wire_confirm.is_none(), "{what}");
        assert_eq!(app.scan.tab, ScanTab::Profiles, "{what}: not switched");
        assert!(app.scan.jobs.order.is_empty(), "{what}: nothing folded");
        assert!(app.scan.jobs.full.is_empty(), "{what}");
        assert!(app.scan.jobs.started_here.is_empty(), "{what}");
        assert_eq!(app.scan.launch.pending, None, "{what}: answered");
        assert!(!app.scan.inflight.contains("scan.start"), "{what}");
        let err = app
            .scan
            .profiles
            .error
            .as_ref()
            .unwrap_or_else(|| panic!("{what}: scan.start is the Profiles tab's error"));
        assert_eq!(err.tag, "scan.start", "{what}");
        assert_eq!(err.code, None, "{what}");
        assert!(
            err.detail.starts_with(detail),
            "{what}: {:?} starts with {detail:?}",
            err.detail
        );
        assert!(
            toast_texts(&app)
                .iter()
                .all(|(_, t)| !t.contains("started")),
            "{what}: no start toast: {:?}",
            toast_texts(&app)
        );
        let reqs = app.update(Action::ScanStart);
        assert_eq!(reqs.len(), 1, "{what}: the key is live again: {reqs:?}");
    }
}
