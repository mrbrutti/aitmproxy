//! Shared helpers for the tester's integration tests. Everything here goes
//! through `aitm-tui`'s public surface: `App::update` / `App::on_bus` for
//! state, `snapshot::render` + `snapshot::to_text` for what the operator sees.

#![allow(dead_code)]

use aitm_tui::action::{Action, BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::fixture_app_core;
use aitm_tui::model::ProxyStatus;
use aitm_tui::scan::{ScanOffer, ScanTab};
use aitm_tui::snapshot::{render, to_text};
use aitm_tui::theme::Theme;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::{Buffer, Cell};
use serde_json::{json, Value};

/// The design palette: what every snapshot renders with.
pub fn theme() -> Theme {
    Theme::new(true)
}

/// Draw `app` off-screen at `cols`×`rows`.
pub fn draw(app: &App, cols: u16, rows: u16) -> Buffer {
    render(app, &theme(), cols, rows)
}

/// The screen as text, styles dropped, one line per row.
pub fn text_of(app: &App, cols: u16, rows: u16) -> String {
    to_text(&draw(app, cols, rows))
}

/// The first line containing `needle`.
pub fn line_with<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    text.lines().find(|l| l.contains(needle))
}

/// The row index of the first line containing `needle`.
pub fn line_index(text: &str, needle: &str) -> Option<usize> {
    text.lines().position(|l| l.contains(needle))
}

/// The cell column where `needle` starts in `line`. `to_text` emits exactly
/// one symbol per cell (a wide glyph's second cell is a space), so the char
/// index is the column.
pub fn col_of(line: &str, needle: &str) -> Option<usize> {
    line.find(needle).map(|b| line[..b].chars().count())
}

/// A cell, panicking with the coordinates when it is outside the buffer.
pub fn cell(buf: &Buffer, x: usize, y: usize) -> &Cell {
    buf.cell((x as u16, y as u16)).unwrap_or_else(|| {
        panic!(
            "no cell at ({x}, {y}) in a {}×{} buffer",
            buf.area.width, buf.area.height
        )
    })
}

pub fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

pub fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

/// Tool entries with an empty schema, enough for `App::has_tool`.
pub fn tools(names: &[&str]) -> Vec<ToolInfo> {
    names
        .iter()
        .map(|n| ToolInfo {
            name: (*n).to_string(),
            description: format!("{n} (test)"),
            input_schema: json!({"type":"object","properties":{}}),
        })
        .collect()
}

/// The commands the bus serves today (50 since the core merge of
/// 2026-10-28). Every test binary compiles this module; not all use the list.
#[allow(unused_imports)]
pub use aitm_tui::CORE_TOOLS;

/// The 22 commands the bus served before that merge: a bus with none of
/// the F5/F6/F7/F12/F13/M3 tools. Tests that prove a *missing* tool degrades
/// honestly connect to this list; `CORE_TOOLS` is for "today's core".
pub const PRE_MERGE_TOOLS: &[&str] = &[
    "flow.list",
    "flow.get",
    "flow.intercept",
    "flow.resume",
    "flow.kill",
    "flow.mutate",
    "flow.replay",
    "request.send",
    "scope.add",
    "scope.list",
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.screenshot",
    "browser.eval",
    "browser.get_dom",
    "poc.build",
    "poc.run",
    "ca.export",
    "ca.status",
    "ca.install",
    "ca.uninstall",
];

/// The core fixture as a legacy scanner bus (spec D2, D12): `scan.discover`
/// and every non-`scan.` tool are kept, every other `scan.*` verb is dropped,
/// so a file that means "the legacy path" keeps meaning it however
/// `CORE_TOOLS` is re-pinned. Asserts the offer it built.
pub fn legacy_app(cols: u16, rows: u16) -> App {
    let mut app = fixture_app_core(cols, rows);
    app.tools
        .retain(|t| t.name == "scan.discover" || !t.name.starts_with("scan."));
    assert_eq!(
        app.scan_offer(),
        ScanOffer::Legacy,
        "the fixture is a legacy scanner bus"
    );
    app
}

/// A `flow.get` summary as the core shapes it (§4.3).
pub fn summary(
    id: &str,
    method: &str,
    authority: &str,
    path: &str,
    status: Option<u16>,
    intercept: &str,
) -> Value {
    json!({
        "id": id, "kind": "http", "method": method, "scheme": "https",
        "authority": authority, "path": path, "status": status,
        "is_replay": false, "intercept": intercept,
    })
}

/// Connect `app` to a bus offering `tool_names`, as the bus task would:
/// `Connected`, then, when the caller names a listen address, the
/// `proxy.status` the handshake reads (listening, armed off, capturing).
pub fn connect(app: &mut App, tool_names: &[&str], listening: Option<&str>) -> Vec<BusRequest> {
    let mut out = app.on_bus(BusEvent::Connected {
        server: "aitmproxy test".into(),
        tools: tools(tool_names),
        role: None,
    });
    if let Some(addr) = listening {
        out.extend(app.on_bus(BusEvent::ProxyStatus(ProxyStatus {
            listening: true,
            address: Some(addr.to_string()),
            intercept_armed: false,
            capturing: true,
            paused: 0,
            flows: 0,
        })));
    }
    out
}

/// Visible flow ids in display order.
pub fn visible_ids(app: &App) -> Vec<String> {
    app.visible()
        .into_iter()
        .map(|i| app.flows[i].id.clone())
        .collect()
}

/// The current toast's text, or a marker when there is none.
pub fn toast(app: &App) -> &str {
    app.current_toast()
        .map_or("<no toast>", |t| t.text.as_str())
}

/// One file of the scanner contract pack (`crates/aitm-scan-model/fixtures/`),
/// parsed, so a test writes `fixture("scan.status.json")` (fix round B,
/// B10). Read at run time, so a test binary does not embed every fixture it
/// names; a missing or malformed file is a test bug and panics with its name.
pub fn fixture(name: &str) -> Value {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../aitm-scan-model/fixtures/").to_string() + name;
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {name}: cannot read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("fixture {name} is not JSON: {e}"))
}

/// A tagged call request, as the reducer issues one (fix round G, G80: the
/// one scaffolding the scanner v2 suites share).
pub fn tagged(tag: &str, name: &str, args: Value) -> BusRequest {
    BusRequest::CallTagged {
        tag: tag.into(),
        name: name.into(),
        args,
    }
}

/// A tagged success reply.
pub fn reply(tag: &str, name: &str, value: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: tag.into(),
        name: name.into(),
        value,
    }
}

/// A tagged failure reply.
pub fn failed(tag: &str, name: &str, message: &str) -> BusEvent {
    BusEvent::CallTaggedFailed {
        tag: tag.into(),
        name: name.into(),
        message: message.into(),
    }
}

/// A connected v2 app at 200x50 opened on the Scan view (landing on
/// Profiles, D2) with the open's three reads (`scan.list`,
/// `scan.profile.list`, `scan.checks`; D6) asserted to leave and settled
/// from the fixtures: an empty job list, the seven profiles and the check
/// catalogue. Nothing is in flight afterwards.
pub fn opened_v2(tool_names: &[&str]) -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, tool_names, None);
    let reqs = app.update(Action::OpenScan);
    assert_eq!(
        reqs,
        vec![
            tagged("scan.list", "scan.list", json!({})),
            tagged("scan.profile.list", "scan.profile.list", json!({})),
            tagged("scan.checks", "scan.checks", json!({})),
        ],
        "the first open lands on Profiles and reads its list and checks (D6)"
    );
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
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.tab, ScanTab::Profiles);
    assert_eq!(app.scan.profiles.list[3].name, "standard");
    assert!(app.scan.inflight.is_empty(), "{:?}", app.scan.inflight);
    app
}
