//! Component tests for the TUI L4 operator surface (ui-ext Part 3,
//! L4OPS-AC7–AC13). They drive the reducer and render against an L4-enabled
//! fixture, the way the other `aitm-tui` component tests run. The default
//! builtin fixture has no L4 surface; these build one so the HTTP-count tests
//! stay stable.

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::fixture::Fixture;
use aitm_tui::fixture_app_from;
use aitm_tui::l4::L4Gate;
use aitm_tui::model::FlowKind;
use aitm_tui::snapshot::{render, to_text};
use aitm_tui::theme::Theme;
use serde_json::{json, Value};

/// The `l4.*` tools the surface feature-detects, as `tools/list` entries.
fn l4_tool_names(with_agent_set: bool) -> Vec<&'static str> {
    let mut names = vec![
        "l4.interfaces",
        "l4.scope.list",
        "l4.scope.add",
        "l4.scope.remove",
        "l4.flow.list",
        "l4.flow.get",
        "l4.craft",
        "l4.capture.start",
        "l4.capture.stop",
        "l4.capture.status",
        "l4.inject",
        "l4.send_recv",
        "l4.intercept.start",
        "l4.intercept.stop",
        "l4.intercept.status",
        "l4.intercept.list",
        "l4.intercept.mutate",
        "l4.intercept.forward",
        "l4.intercept.drop",
        "l4.agent.status",
    ];
    if with_agent_set {
        names.push("l4.agent.set");
    }
    names
}

fn scope_entry(cap: &str) -> Value {
    json!({
        "interface": "lo0", "capability": cap,
        "cidr": {"addr": "127.0.0.0", "prefix": 8},
        "ports": {"lo": 0, "hi": 65535}, "direction": "outbound"
    })
}

fn pkt(dir: &str, len: u64, injected: bool, layers: &[&str]) -> Value {
    json!({"dir": dir, "length": len, "injected": injected, "layers": layers})
}

/// A fixture with the L4 surface: lo0 is in scope (capture + inject), eth0 is
/// not; four L4 flows (capture / craft / out-of-scope capture / intercept).
fn l4_fixture(with_agent_set: bool) -> Fixture {
    let mut fx = Fixture::builtin();
    for name in l4_tool_names(with_agent_set) {
        fx.tools.push(json!({
            "name": name, "description": "l4 test tool",
            "inputSchema": {"type": "object", "properties": {}}
        }));
    }
    fx.l4_scope = vec![scope_entry("capture"), scope_entry("inject")];
    fx.l4_flows = vec![
        json!({
            "id": "l4-1", "kind": "capture", "interface": "lo0", "filter": "udp port 7",
            "queue": null, "packet_count": 2, "injected_count": 1,
            "packets": [pkt("outbound", 33, true, &["IPv4", "UDP", "Raw"]),
                        pkt("inbound", 33, false, &["IPv4", "UDP", "Raw"])]
        }),
        json!({
            "id": "l4-2", "kind": "craft", "interface": "lo0", "filter": null,
            "queue": null, "packet_count": 0, "injected_count": 0, "packets": []
        }),
        json!({
            "id": "l4-3", "kind": "capture", "interface": "eth0", "filter": "tcp port 443",
            "queue": null, "packet_count": 1, "injected_count": 0,
            "packets": [pkt("inbound", 54, false, &["Ether", "IPv4", "TCP"])]
        }),
        json!({
            "id": "l4-4", "kind": "intercept", "interface": "lo0", "filter": null,
            "queue": 100, "packet_count": 1, "injected_count": 0,
            "packets": [pkt("inbound", 60, false, &["IPv4", "TCP", "Raw"])]
        }),
    ];
    fx.l4_agent = json!({"capture": true, "inject": false, "intercept": false, "widen": false});
    fx.l4_interfaces = vec![json!("lo0"), json!("eth0")];
    fx
}

fn l4_app(cols: u16, rows: u16) -> App {
    fixture_app_from(l4_fixture(true), cols, rows)
}

fn screen(app: &App) -> String {
    to_text(&render(app, &Theme::new(true), app.width, app.height))
}

/// L4OPS-AC7 / AC12: the union flow list renders every kind — HTTP method
/// badges, the `WS` badge, and the L4 badge + TCP/UDP/ICMP sub-label — and an
/// L4 row with no cells renders a labelled placeholder, never an empty line.
#[test]
fn every_kind_renders() {
    let app = l4_app(200, 50);
    let text = screen(&app);
    // HTTP (a method badge) and WebSocket (the WS badge) are present.
    assert!(
        text.contains("POST") || text.contains("GET"),
        "http row: {text}"
    );
    assert!(text.contains("WS"), "websocket row: {text}");
    // The L4 rows render the L4 badge + the decoded transport sub-label.
    assert!(text.contains("L4 UDP"), "l4 UDP row: {text}");
    assert!(text.contains("L4 TCP"), "l4 TCP row: {text}");
    // The craft flow has no packets yet: its sub-label is a labelled `?`
    // placeholder, not blank (AC7 "never nothing").
    assert!(
        text.contains("L4 ?"),
        "undecoded L4 sub-label placeholder: {text}"
    );

    // A defensive placeholder renders for an L4 row whose cells are missing.
    let mut app = app;
    if let Some(row) = app.flows.iter_mut().find(|r| r.id == "l4-2") {
        row.l4 = None;
    }
    let text = screen(&app);
    assert!(
        text.contains("L4 flow l4-2 — details pending"),
        "labelled placeholder for a cell-less L4 row: {text}"
    );
}

/// L4OPS-AC9: an out-of-L4-scope flow's inject is disabled with the scope
/// reason, and it reaches no `l4.inject` on the wire.
#[test]
fn out_of_scope_inject_disabled() {
    let mut app = l4_app(200, 50);
    app.selected = Some("l4-3".into()); // eth0 — not in L4 scope
    app.mode = Mode::Inspector;
    assert!(
        !app.in_scope(app.selected_row().unwrap()),
        "l4-3 is out of scope"
    );

    let reqs = app.update(Action::L4Inject);
    assert!(
        reqs.is_empty(),
        "an out-of-scope inject sends nothing to the wire: {reqs:?}"
    );
    // The disabled reason is surfaced, naming scope.
    let text = screen(&app);
    assert!(
        text.to_lowercase().contains("out of l4 scope"),
        "scope reason surfaced: {text}"
    );
    // The craft pane shows the inject-disabled note for the out-of-scope flow.
    app.update(Action::InspectorPaneToggle); // → Craft pane
    let text = screen(&app);
    assert!(
        text.contains("inject disabled") && text.to_lowercase().contains("scope"),
        "craft pane shows inject disabled with the scope reason: {text}"
    );
}

/// L4OPS-AC10: an in-scope inject goes only through `l4.inject`, shows the
/// confirm overlay with the wire summary (destination + scope + count), and the
/// confirm re-issues the identical call with the reserved `_confirm` token.
#[test]
fn inject_shows_confirm() {
    let mut app = l4_app(200, 50);
    app.selected = Some("l4-2".into()); // craft flow on lo0 — in scope
    app.mode = Mode::Inspector;
    app.l4.pane = aitm_tui::l4::L4Pane::Craft;

    let reqs = app.update(Action::L4Inject);
    assert_eq!(reqs.len(), 1, "one call: {reqs:?}");
    let BusRequest::Call { name, .. } = &reqs[0] else {
        panic!("expected a Call, got {reqs:?}");
    };
    assert_eq!(
        name, "l4.inject",
        "inject reaches the wire only via l4.inject"
    );

    // The server answers the first call with `needs_confirmation` + the wire
    // summary (what M4 + the fixture produce).
    let reply = json!({
        "status": "needs_confirmation",
        "prompt": "l4.inject: 1 packet(s) to destination 127.0.0.1 on lo0 — matched scope entry \
                   lo0 127.0.0.0/8 (inject), minted permit budget 10 pps. Confirm?",
        "confirm_token": "tok-1"
    });
    let _ = app.on_bus(BusEvent::CallOk {
        name: "l4.inject".into(),
        value: reply,
    });
    assert_eq!(app.mode, Mode::WireConfirm, "the confirm overlay opens");
    let text = screen(&app);
    assert!(text.contains("127.0.0.1"), "destination shown: {text}");
    assert!(
        text.to_lowercase().contains("scope"),
        "scope entry shown: {text}"
    );
    assert!(text.contains("budget"), "permit budget shown: {text}");

    // Confirming re-issues the identical call plus the `_confirm` token.
    let reqs = app.update(Action::WireConfirm(true));
    assert_eq!(reqs.len(), 1);
    let BusRequest::Call { name, args } = &reqs[0] else {
        panic!("expected a Call, got {reqs:?}");
    };
    assert_eq!(name, "l4.inject");
    assert_eq!(
        args["_confirm"], "tok-1",
        "re-issued with the confirm token"
    );
}

/// L4OPS-AC8: a packet's layer tree renders as a labelled, indented **text**
/// tree (a terminal cannot draw a graphical tree — it is rendered, not dropped).
#[test]
fn layer_tree_degrades_labelled() {
    let mut app = l4_app(200, 60);
    app.selected = Some("l4-1".into()); // UDP capture with IPv4/UDP/Raw layers
    app.mode = Mode::Inspector;
    app.l4.pane = aitm_tui::l4::L4Pane::Packets;
    let text = screen(&app);
    assert!(
        text.contains("layer tree (text)"),
        "the tree is labelled as a text tree: {text}"
    );
    for layer in ["IPv4", "UDP", "Raw"] {
        assert!(text.contains(layer), "layer {layer} rendered: {text}");
    }
    // The captured-packet hex degrades honestly (l4.flow.get carries no bytes).
    assert!(
        text.to_lowercase().contains("not carried by l4.flow.get"),
        "honest hex degradation note: {text}"
    );
}

/// L4OPS-AC11: the Agent view's L4 toggles reflect the gate that governs the
/// agent path; toggling sets it via `l4.agent.set` where present, and is
/// read-only with an honest note where absent.
#[test]
fn toggle_reflects_gate() {
    // Settable: l4.agent.set is on the bus; inject gate is off.
    let mut app = l4_app(200, 50);
    app.mode = Mode::Agent;
    assert!(!app.l4.gates.inject, "inject gate starts off");
    let text = screen(&app);
    assert!(
        text.contains("L4 agent capabilities"),
        "the L4 capability section renders: {text}"
    );
    // The Inject toggle shows its gate state (off) distinct from Capture (on).
    let inject_line = text
        .lines()
        .find(|l| l.contains("Inject"))
        .unwrap_or_else(|| panic!("no Inject line: {text}"));
    assert!(
        inject_line.contains("off"),
        "inject reads off: {inject_line:?}"
    );
    let capture_line = text.lines().find(|l| l.contains("Capture")).unwrap();
    assert!(
        capture_line.contains("on"),
        "capture reads on: {capture_line:?}"
    );

    // Toggling the inject gate sets it over the wire.
    let reqs = app.update(Action::L4ToggleGate(L4Gate::Inject));
    assert_eq!(reqs.len(), 1, "one call: {reqs:?}");
    let BusRequest::Call { name, args } = &reqs[0] else {
        panic!("expected a Call, got {reqs:?}");
    };
    assert_eq!(name, "l4.agent.set");
    assert_eq!(args["capability"], "inject");
    assert_eq!(args["allowed"], true, "off → on");

    // Read-only: without l4.agent.set the toggle sends nothing and says why.
    let mut app = fixture_app_from(l4_fixture(false), 200, 50);
    app.mode = Mode::Agent;
    assert!(!app.has_tool("l4.agent.set"));
    let reqs = app.update(Action::L4ToggleGate(L4Gate::Inject));
    assert!(reqs.is_empty(), "read-only toggle sends nothing: {reqs:?}");
    let text = screen(&app);
    assert!(
        text.contains("Read-only here") && text.contains("l4.allow_agent_"),
        "honest read-only note: {text}"
    );
}

/// Sanity: the L4 flows join the union list and selecting one opens the L4
/// inspector (not the HTTP inspector).
#[test]
fn l4_flow_opens_its_own_inspector() {
    let mut app = l4_app(200, 50);
    assert!(
        app.flows.iter().any(|r| r.kind == FlowKind::L4),
        "L4 rows are in the union list"
    );
    app.selected = Some("l4-1".into());
    app.mode = Mode::Inspector;
    let text = screen(&app);
    assert!(
        text.contains("Packets") && text.contains("Craft"),
        "L4 inspector panes: {text}"
    );
}
