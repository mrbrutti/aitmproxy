//! Shared helpers for the tester's integration tests. Everything here goes
//! through `aitm-tui`'s public surface: `App::update` / `App::on_bus` for
//! state, `snapshot::render` + `snapshot::to_text` for what the operator sees.

#![allow(dead_code)]

use aitm_tui::action::{BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::App;
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

/// The 22 commands the bus serves today (foundation §4.1) — no F* tools.
pub const CORE_TOOLS: &[&str] = &[
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

/// Connect `app` to a bus offering `tool_names`, as the bus task would.
pub fn connect(app: &mut App, tool_names: &[&str], listening: Option<&str>) -> Vec<BusRequest> {
    app.on_bus(BusEvent::Connected {
        server: "aitmproxy test".into(),
        tools: tools(tool_names),
        listening: listening.map(str::to_string),
    })
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
