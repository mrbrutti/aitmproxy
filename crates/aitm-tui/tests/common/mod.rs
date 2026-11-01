//! Shared helpers for the tester's integration tests. Everything here goes
//! through `aitm-tui`'s public surface: `App::update` / `App::on_bus` for
//! state, `ui::render` into an off-screen `Buffer` for what the operator
//! sees. There is no recorded data: every test writes the `BusEvent`s it
//! needs as inline literals in the core's wire shapes.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::sync::Once;
use std::time::Instant;

use aitm_tui::action::{Action, BusEvent, BusRequest, ToolInfo};
use aitm_tui::app::{App, Mode, Pane, RESPONSE_TABS};
use aitm_tui::caps::TermCaps;
use aitm_tui::model::{Finding, FlowDetail, ProxyStatus};
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
/// trimmed of trailing spaces, `\n`-joined and ending in `\n` — one line
/// per row, even for a zero-width buffer (no cells, so every line is
/// empty). The cells are row-major: each `width`-long chunk of `content()`
/// is one row.
pub fn to_text(buf: &Buffer) -> String {
    let (width, height) = (usize::from(buf.area.width), usize::from(buf.area.height));
    if width == 0 {
        return "\n".repeat(height);
    }
    let mut out = String::new();
    for row in buf.content().chunks(width) {
        let line: String = row.iter().map(Cell::symbol).collect();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The screen as text, styles dropped, one line per row.
pub fn text_of(app: &App, cols: u16, rows: u16) -> String {
    to_text(&draw(app, cols, rows))
}

/// The toolbar row at `cols` columns, styles dropped, trailing spaces trimmed.
pub fn toolbar_at(app: &App, cols: u16) -> String {
    let area = Rect::new(0, 0, cols, 1);
    let mut buf = Buffer::empty(area);
    aitm_tui::ui::bars::toolbar(app, &theme(), area, &mut buf);
    to_text(&buf).trim_end().to_string()
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

/// A `cols`×`rows` app on today's bus with two flows and their details, both
/// in scope — `f41`, a completed GET with a JSON response, and `f50`, a POST
/// paused at intercept (selected) — plus one library PoC, so every mode and
/// prompt is reachable the way the operator reaches it.
pub fn sample_app(cols: u16, rows: u16) -> App {
    let mut app = connected_app(cols, rows);
    let _ = app.on_bus(BusEvent::Scope(vec![
        "api.shop-staging.test".into(),
        "auth.shop-staging.test".into(),
    ]));
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary(
            "f41",
            "GET",
            "api.shop-staging.test",
            "/api/products?category=electronics&limit=20",
            Some(200),
            "observed",
        ),
        summary(
            "f50",
            "POST",
            "auth.shop-staging.test",
            "/api/auth/login",
            None,
            "intercepted",
        ),
    ]));
    let products = br#"{"items":[{"id":101,"name":"USB-C dock","price":89.5}],"page":1,"total":1}"#;
    let f41 = FlowDetail::from_json(&json!({
        "id": "f41", "kind": "http", "intercept": "observed", "edited": false,
        "request": {
            "method": "GET", "scheme": "https", "authority": "api.shop-staging.test",
            "path": "/api/products?category=electronics&limit=20", "version": "HTTP/2",
            "headers": [["host", "api.shop-staging.test"], ["accept", "application/json"]],
            "body": null, "body_size": 0, "body_truncated": false
        },
        "response": {
            "status": 200, "version": "HTTP/2",
            "headers": [["content-type", "application/json; charset=utf-8"]],
            "body": aitm_tui::base64::encode(products), "body_size": products.len(),
            "body_truncated": false
        },
        "client_conn": {"peer": "127.0.0.1:52101", "sni": "api.shop-staging.test",
                        "alpn": "h2", "tls": true, "process": "curl"},
        "server_conn": {"peer": "203.0.113.10:443", "sni": "api.shop-staging.test",
                        "alpn": "h2", "tls": true},
        "meta": {"marks": [], "comment": null, "is_replay": false,
                 "created": "2026-10-27T11:04:58.120Z", "duration_ms": 89,
                 "truncated": false, "origin": "human"}
    }))
    .unwrap();
    let login = br#"{"email":"ops@shop-staging.test","password":"correct-horse-battery"}"#;
    let f50 = FlowDetail::from_json(&json!({
        "id": "f50", "kind": "http", "intercept": "intercepted", "edited": false,
        "request": {
            "method": "POST", "scheme": "https", "authority": "auth.shop-staging.test",
            "path": "/api/auth/login", "version": "HTTP/2",
            "headers": [["host", "auth.shop-staging.test"],
                        ["content-type", "application/json"], ["accept", "*/*"]],
            "body": aitm_tui::base64::encode(login), "body_size": login.len(),
            "body_truncated": false
        },
        "response": null,
        "client_conn": {"peer": "127.0.0.1:52114", "sni": "auth.shop-staging.test",
                        "alpn": "h2", "tls": true, "process": "curl"},
        "server_conn": null,
        "meta": {"marks": [], "comment": null, "is_replay": false,
                 "created": "2026-10-27T11:05:22.994Z", "duration_ms": null,
                 "truncated": false, "origin": "human"}
    }))
    .unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(f41)));
    let _ = app.on_bus(BusEvent::Detail(Box::new(f50)));
    // One library PoC (`poc.list`), never run, so `r` in Findings has a
    // file to offer; the `poc.get` it asks for is left unanswered.
    let _ = app.on_bus(BusEvent::Findings(vec![Finding::from_json(&json!({
        "poc_path": "pocs/open-redirect-next.yaml", "id": "open-redirect-next",
        "title": "Open redirect via next=", "severity": "low"
    }))
    .unwrap()]));
    app.selected = Some("f50".into());
    app
}

/// Five megabytes of JSON — an array of small objects — for the body-viewer
/// volume tests.
pub fn five_mb_json() -> String {
    let mut body = String::with_capacity(5 * 1024 * 1024 + 128);
    body.push('[');
    let mut i = 0usize;
    while body.len() < 5 * 1024 * 1024 {
        let _ = write!(
            body,
            "{{\"id\":{i},\"name\":\"item-{i}\",\"price\":{}.5,\"tags\":[\"a\",\"b\"],\"in_stock\":{}}},",
            i % 1000,
            i.is_multiple_of(2)
        );
        i += 1;
    }
    body.pop();
    body.push(']');
    body
}

/// An app on the Response pane of a flow whose response body is 5 MB of
/// JSON, and that body's text.
pub fn big_body_app() -> (App, String) {
    let text = five_mb_json();
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &["flow.list", "flow.get", "flow.detail"], None);
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "big",
        "GET",
        "api.test",
        "/big",
        Some(200),
        "observed",
    )]));
    let detail = FlowDetail::from_json(&json!({
        "id": "big", "kind": "http",
        "request": {"method":"GET","path":"/big","headers":[]},
        "response": {"status":200,"headers":[["content-type","application/json"]],
                     "body": aitm_tui::base64::encode(text.as_bytes())},
    }))
    .unwrap();
    let t = Instant::now();
    let _ = app.on_bus(BusEvent::Detail(Box::new(detail)));
    eprintln!(
        "tester: 5 MB body base64-decoded through on_bus in {:?}",
        t.elapsed()
    );
    app.mode = Mode::Inspector;
    app.inspector.pane = Pane::Response;
    (app, text)
}

/// Select the inspector's response tab `name` (`Body`, `Raw`, `JSON`, `Hex`).
pub fn response_tab(app: &mut App, name: &str) {
    app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == name).unwrap();
}

thread_local! {
    /// Set while this thread is inside [`quietly`].
    static SUPPRESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
static QUIET_HOOK: Once = Once::new();

/// Run `f` with panic messages from *this thread* suppressed, so a sweep
/// that `catch_unwind`s hundreds of renders does not spray the log. The
/// panic hook is one process-global slot: the old per-test `take_hook` /
/// `set_hook(|_| {})` / `set_hook(previous)` dance raced the other test
/// threads and could eat a real failure's message. This installs ONE hook,
/// once, that forwards to the default hook unless the panicking thread is
/// inside `quietly`; every other thread's panic prints as usual.
pub fn quietly<T>(f: impl FnOnce() -> T) -> T {
    QUIET_HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !SUPPRESS.with(std::cell::Cell::get) {
                default(info);
            }
        }));
    });
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SUPPRESS.with(|s| s.set(false));
        }
    }
    let _reset = Reset;
    SUPPRESS.with(|s| s.set(true));
    f()
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
            system_proxy: None,
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
