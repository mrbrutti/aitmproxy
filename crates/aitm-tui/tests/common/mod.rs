//! Shared helpers for the tester's integration tests. Everything here goes
//! through `aitm-tui`'s public surface: `App::update` / `App::on_bus` for
//! state, `ui::render` into an off-screen `Buffer` for what the operator
//! sees. There is no recorded data: every test writes the `BusEvent`s it
//! needs as inline literals in the core's wire shapes.

#![allow(dead_code)]

use aitm_tui::action::{Action, BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::App;
use aitm_tui::caps::TermCaps;
use aitm_tui::model::ProxyStatus;
use aitm_tui::theme::Theme;
use aitm_tui::ui::render;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::{Buffer, Cell};
use ratatui::layout::Rect;
use serde_json::{json, Value};

/// The design palette: what every off-screen draw renders with.
pub fn theme() -> Theme {
    Theme::new(true)
}

/// Draw `app` off-screen at `cols`×`rows`, exactly as `ui::view` would draw
/// a terminal of that size.
pub fn draw(app: &App, cols: u16, rows: u16) -> Buffer {
    let area = Rect::new(0, 0, cols, rows);
    let mut buf = Buffer::empty(area);
    render(app, &theme(), area, &mut buf);
    buf
}

/// A drawn buffer as text, styles dropped: one symbol per cell, each line
/// trimmed of trailing spaces, `\n`-joined and ending in `\n`.
pub fn to_text(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.y..area.bottom() {
        let mut line = String::new();
        for x in area.x..area.right() {
            if let Some(c) = buf.cell((x, y)) {
                line.push_str(c.symbol());
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The screen as text, styles dropped, one line per row.
pub fn text_of(app: &App, cols: u16, rows: u16) -> String {
    to_text(&draw(app, cols, rows))
}

/// An [`App`] at `cols`×`rows`, connected to a bus that offers every
/// [`CORE_TOOLS`] name (bus address `test`, so it is not a loopback bus).
/// Flows, details, scope and findings are not part of it; each test feeds
/// the `BusEvent`s it needs as inline literals.
pub fn connected_app(cols: u16, rows: u16) -> App {
    let mut app = App::new(TermCaps::full(), "test");
    let _ = app.update(Action::Resize(cols, rows));
    let _ = connect(&mut app, CORE_TOOLS, None);
    app
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

/// The commands the bus serves today: every name in `aitm_tui::CORE_TOOLS`,
/// pinned against the real server by `crates/aitm/tests/tui_live_bus.rs`.
/// Every test binary compiles this module; not all use the list.
#[allow(unused_imports)]
pub use aitm_tui::CORE_TOOLS;

/// The 22 commands the bus served before that merge — a bus with none of
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
/// `Connected`, then — when the caller names a listen address — the
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
