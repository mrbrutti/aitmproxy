//! Robustness and regression pins for the TUI, salvaged from the tester's
//! shell, pass-2, fix-pass-2 and component suites (spec
//! 2026-10-31-remove-fake-data-ui-modes, D7). Every app here is built from
//! inline literals in the core's wire shapes: `connected_app` gives a bus
//! that offers every `CORE_TOOLS` name, `PRE_MERGE_TOOLS` one that proves
//! degradation, and each test writes the `BusEvent`s it needs. Nothing a
//! proxy peer, the keyboard or a terminal resize can send may panic the UI.

mod common;

use std::collections::HashSet;
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{Duration, Instant};

use aitm_tui::action::ToolSchema as _;
use aitm_tui::action::{Action, BusEvent, BusRequest, Level, Param, ToolInfo};
use aitm_tui::app::{
    App, Mode, PaletteKind, Pane, PromptKind, SidebarItem, MAX_DETAILS, RESPONSE_TABS,
};
use aitm_tui::caps::TermCaps;
use aitm_tui::filter;
use aitm_tui::keys;
use aitm_tui::model::{AgentPolicy, Finding, FlowDetail, Message};
use aitm_tui::viewers;
use common::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

/// Bound for the interactive paths over 5 000 flows (render, filter, palette).
/// The plan's target is "a flow list of 5 000 rows rendering under 50 ms";
/// these tests run unoptimised (debug), so the bound is 5× that. A
/// regression that makes a frame cost the 250 ms tick still fails.
const INTERACTIVE: Duration = Duration::from_millis(250);
/// Generous, CI-tolerant ceiling for the 5 MB body paths (a frame render).
/// These tests run unoptimised (debug): locally one frame is ~0.75 s, but a
/// loaded or parallel GitHub runner reaches ~2.7 s, so a tight 2 s bound
/// false-fails intermittently. 10 s still catches a pathological regression
/// (an O(n²) parse, or the per-frame full-rebuild freeze the FINDING on
/// `inspector_frames_with_a_five_megabyte_body_do_not_freeze` documents)
/// without flaking under CI load.
const BULK: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ helpers

fn call(name: &str, args: serde_json::Value) -> BusRequest {
    BusRequest::Call {
        name: name.into(),
        args,
    }
}

fn ok(name: &str, value: serde_json::Value) -> BusEvent {
    BusEvent::CallOk {
        name: name.into(),
        value,
    }
}

fn failed(name: &str, message: &str) -> BusEvent {
    BusEvent::CallFailed {
        name: name.into(),
        message: message.into(),
    }
}

/// A real 1×1 PNG — the smallest well-formed image file — for the tests that
/// need a genuine image on disk.
fn test_png() -> Vec<u8> {
    let png = aitm_tui::base64::decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
    )
    .expect("a base64 PNG");
    assert_eq!(
        aitm_tui::viewers::image::dimensions(&png),
        Some((1, 1, "PNG"))
    );
    png
}

/// A `cols`×`rows` app on today's bus with two flows and their details, both
/// in scope — `f41`, a completed GET with a JSON response, and `f50`, a POST
/// paused at intercept (selected) — plus one library PoC, so every mode and
/// prompt is reachable the way the operator reaches it.
fn sample_app_at(cols: u16, rows: u16) -> App {
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

/// [`sample_app_at`] at the design size, 200×50.
fn sample_app() -> App {
    sample_app_at(200, 50)
}

// ------------------------------------------------------- shell: sizes

#[test]
fn terminals_below_40x4_show_the_minimum_size_line() {
    let app = connected_app(200, 50);
    for (c, r) in [(39u16, 3u16), (39, 4), (40, 3), (10, 10), (100, 2)] {
        let text = text_of(&app, c, r);
        assert!(
            text.lines().next().unwrap_or("").starts_with(
                &"aitm-tui needs at least 40×4"
                    .chars()
                    .take(usize::from(c))
                    .collect::<String>()
            ),
            "{c}×{r}: {text:?}"
        );
    }
    assert_eq!(text_of(&app, 1, 1), "a\n");
    assert_eq!(text_of(&app, 0, 0), "");
    // 40×4 is the minimum the message names, so the shell must draw there.
    let text = text_of(&app, 40, 4);
    assert!(!text.contains("needs at least"), "40×4 is enough: {text:?}");
    assert!(text.contains("aitmproxy"), "{text:?}");
}

/// Every mode at every awkward size: a resize mid-session must never panic.
#[test]
fn no_mode_panics_at_any_terminal_size() {
    let cols = [
        1u16, 2, 3, 10, 20, 39, 40, 41, 50, 60, 79, 80, 99, 100, 101, 119, 120, 121, 127, 128, 140,
        159, 160, 161, 200, 300,
    ];
    let rows = [1u16, 2, 3, 4, 5, 6, 7, 8, 10, 12, 20, 50, 100];

    let base = sample_app();
    let mut states: Vec<(&str, App)> = Vec::new();
    states.push(("flows", base.clone()));
    let mut a = base.clone();
    a.mode = Mode::Inspector;
    states.push(("inspector", a));
    let mut a = base.clone();
    a.selected = Some("f41".into());
    a.mode = Mode::Inspector;
    a.inspector.pane = Pane::Response;
    a.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == "JSON").unwrap();
    a.inspector.cursor_line = 4;
    states.push(("inspector-json", a));
    let mut a = base.clone();
    let _ = a.update(Action::Edit);
    assert_eq!(
        a.mode,
        Mode::Edit,
        "f50 is paused with a detail: Edit opens"
    );
    states.push(("edit", a));
    // The palette overlay has its own test below: it is the one state that
    // panics on short terminals, and it must not mask the rest of this sweep.
    let mut a = base.clone();
    let _ = a.update(Action::FilterOpen);
    states.push(("filter-prompt", a));
    for (name, action) in [
        ("compose", Action::Compose),
        ("scope", Action::OpenScope),
        ("findings", Action::OpenFindings),
        ("agent", Action::OpenAgent),
        ("help", Action::Help),
        ("quick-look", Action::QuickLook),
    ] {
        let mut a = base.clone();
        let _ = a.update(action);
        states.push((name, a));
    }
    let mut a = base.clone();
    a.mode = Mode::Prompt(PromptKind::ScopeAdd);
    states.push(("scope-prompt", a));
    let mut a = base.clone();
    a.selected = None;
    states.push(("no-selection", a));
    let mut empty = App::new(TermCaps::full(), "x");
    let _ = connect(&mut empty, CORE_TOOLS, None);
    states.push(("empty", empty));

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    let mut renders = 0usize;
    for (name, state) in &states {
        for &c in &cols {
            for &r in &rows {
                let mut app = state.clone();
                let _ = app.update(Action::Resize(c, r));
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    let buf = draw(&app, c, r);
                    let _ = to_text(&buf);
                }));
                renders += 1;
                if let Err(e) = outcome {
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                        .unwrap_or_else(|| "non-string panic".into());
                    failures.push(format!("{name} at {c}×{r}: {msg}"));
                }
            }
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(
        failures.is_empty(),
        "{} of {renders} renders panicked:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// FINDING (fixed): `ui/overlays.rs::palette` sized its box as
/// `items.min(10) + 2` rows and only clamped `y` with `saturating_sub`, so on
/// a terminal shorter than ~12 rows the box ran past the bottom of the screen
/// and ratatui's `Buffer` indexing panicked. Pressing `:` in an 80×10
/// terminal crashed the TUI.
#[test]
fn palette_overlay_survives_short_terminals() {
    let mut app = sample_app();
    let _ = app.update(Action::PaletteOpen);
    for c in "fl".chars() {
        let _ = app.update(Action::Input(c));
    }
    // Tall enough: the overlay draws above the prompt line.
    let _ = app.update(Action::Resize(80, 20));
    let text = text_of(&app, 80, 20);
    assert!(text.contains(" palette "), "{text}");
    assert!(text.contains("flow.list"), "{text}");

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (c, r) in [
        (80u16, 4u16),
        (80, 6),
        (80, 8),
        (80, 10),
        (120, 11),
        (200, 5),
    ] {
        let _ = app.update(Action::Resize(c, r));
        if catch_unwind(AssertUnwindSafe(|| draw(&app, c, r))).is_err() {
            failures.push(format!("{c}×{r}"));
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(
        failures.is_empty(),
        "the palette overlay panics at: {}",
        failures.join(", ")
    );
}

// ------------------------------------------------------- volume edge cases

#[test]
fn five_thousand_flows_ingest_and_render_within_bounds() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    // A bus without `flow.detail`, so ingest is measured without the 5000
    // detail fetches the lit core would ask for.
    let _ = connect(&mut app, PRE_MERGE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::Scope(vec!["*.shop-staging.test".into()]));
    let methods = ["GET", "POST", "PUT", "DELETE"];
    let summaries: Vec<_> = (0..5000usize)
        .map(|i| {
            summary(
                &format!("f{i}"),
                methods[i % 4],
                &format!("h{}.shop-staging.test", i % 37),
                &format!("/api/items/{i}?page={}", i % 9),
                if i % 5 == 0 {
                    None
                } else {
                    Some(200 + (i % 3) as u16 * 100)
                },
                if i % 97 == 0 {
                    "intercepted"
                } else {
                    "observed"
                },
            )
        })
        .collect();

    let t = Instant::now();
    let reqs = app.on_bus(BusEvent::Flows(summaries.clone()));
    let ingest = t.elapsed();
    assert!(
        reqs.is_empty(),
        "no flow.detail on this bus, so no detail fetches"
    );
    assert_eq!(app.flows.len(), 5000);
    assert_eq!(app.next_seq, 5001);

    let t = Instant::now();
    let _ = app.on_bus(BusEvent::Flows(summaries.clone()));
    let refresh = t.elapsed();
    assert_eq!(
        app.flows.len(),
        5000,
        "a refresh with the same ids keeps every row"
    );

    let t = Instant::now();
    let buf = draw(&app, 200, 50);
    let render_time = t.elapsed();
    let text = to_text(&buf);
    assert!(
        text.contains("5000 / 5000 rows"),
        "auto-selected the newest: {text}"
    );
    assert!(
        text.contains("/api/items/4999"),
        "the list scrolled to the selection: {text}"
    );
    assert!(
        text.contains(&format!("· {} paused", 5000 / 97 + 1)),
        "{text}"
    );

    let t = Instant::now();
    let _ = app.run_command("filter ~m POST & ~s 2xx");
    let n = app.visible().len();
    let filter_time = t.elapsed();
    assert!(n > 0 && n < 5000, "{n}");

    let t = Instant::now();
    let _ = app.update(Action::PaletteOpen);
    for c in "items/49".chars() {
        let _ = app.update(Action::Input(c));
    }
    let items = app.palette_items().len();
    let palette_time = t.elapsed();
    assert!(items > 0);

    eprintln!(
        "tester: 5000 flows — ingest {ingest:?}, refresh {refresh:?}, render 200×50 {render_time:?}, filter {filter_time:?} ({n} rows), palette {palette_time:?} ({items} items)"
    );
    for (what, d) in [
        ("ingest", ingest),
        ("refresh", refresh),
        ("render", render_time),
        ("filter", filter_time),
        ("palette", palette_time),
    ] {
        assert!(d < INTERACTIVE, "{what} took {d:?} (bound {INTERACTIVE:?})");
    }
}

fn five_mb_json() -> String {
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

/// An app on the Response pane of a flow whose response body is 5 MB of JSON.
fn big_body_app() -> (App, String) {
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

fn response_tab(app: &mut App, name: &str) {
    app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == name).unwrap();
}

#[test]
fn a_five_megabyte_json_body_renders_without_panicking() {
    let (mut app, text) = big_body_app();
    let msg = Message {
        headers: vec![("content-type".into(), "application/json".into())],
        body: text.clone().into_bytes(),
        ..Message::default()
    };
    let theme = theme();

    let t = Instant::now();
    let lines = viewers::body(&theme, &msg);
    let pretty = t.elapsed();
    assert!(lines.len() > 100_000, "{}", lines.len());

    let t = Instant::now();
    let (tree, paths) = viewers::json::tree_with_paths(&theme, &text, &HashSet::new())
        .expect("5 MB of JSON parses");
    let tree_time = t.elapsed();
    assert_eq!(tree.len(), paths.len());

    let t = Instant::now();
    let hex = viewers::hex::dump(&theme, msg.body.as_slice(), 16);
    let hex_time = t.elapsed();
    assert_eq!(hex.len(), msg.body.len().div_ceil(16));

    // Every tab draws the body without panicking.
    for tab in ["Body", "Raw", "JSON", "Hex"] {
        response_tab(&mut app, tab);
        let frame = text_of(&app, 200, 50);
        assert!(frame.contains("Response  Headers"), "{tab}: {frame}");
    }
    response_tab(&mut app, "Hex");
    assert!(text_of(&app, 200, 50).contains("00000000  5b 7b 22 69"));

    eprintln!(
        "tester: 5 MB JSON ({} bytes) — viewers::body {pretty:?} ({} lines), tree_with_paths {tree_time:?} ({} lines), hex::dump {hex_time:?} ({} rows)",
        msg.body.len(),
        lines.len(),
        tree.len(),
        hex.len()
    );
    // This test's contract is "renders without panicking" plus the output-shape
    // asserts above; the per-stage wall-clock is logged for diagnostics only, not
    // gated here. A strict bound in a debug build false-fails under loaded/parallel
    // CI runners (local ~0.75 s, CI ~2.7 s); frame timing is gated by the dedicated
    // `inspector_frames_with_a_five_megabyte_body_do_not_freeze` test instead.
}

/// FINDING (fixed): the inspector rebuilt the whole viewer on every frame
/// (and the JSON tab rebuilt the tree three times: `json_cursor_path` for the
/// tab row, `content`, and again for the cursor). With a 5 MB body selected a
/// single frame cost more than the 250 ms tick, so the UI froze while that
/// flow was selected. §2.7: "Large bodies stream in pages". The bound is the
/// generous CI-tolerant `BULK` ceiling (see its doc), not a tight 2 s, so the
/// regression guard survives loaded CI runners.
#[test]
fn inspector_frames_with_a_five_megabyte_body_do_not_freeze() {
    let (mut app, _) = big_body_app();
    let mut report = String::new();
    let mut slow = Vec::new();
    for tab in ["Body", "Raw", "JSON", "Hex"] {
        response_tab(&mut app, tab);
        let t = Instant::now();
        let frame = text_of(&app, 200, 50);
        let d = t.elapsed();
        assert!(frame.contains("Response  Headers"), "{tab}: {frame}");
        let _ = write!(report, "{tab} {d:?}  ");
        if d >= BULK {
            slow.push(format!("{tab} tab frame {d:?}"));
        }
    }
    eprintln!("tester: one inspector frame at 200×50 with a 5 MB body — {report}");
    assert!(slow.is_empty(), "{}", slow.join(", "));
}

// ------------------------------------------------------- the random walk

/// A seeded random walk through every mode — Browser, Ca and Confirm
/// included — with bus events, resizes and every key the key map knows,
/// never panics.
#[test]
fn a_random_walk_through_every_mode_including_browser_ca_and_confirm_never_panics() {
    for (seed0, cols, rows) in [
        (0x9e37_79b9_7f4a_7c15u64, 100u16, 30u16),
        (0x2545_f491_4f6c_dd1du64, 200, 50),
    ] {
        walk(seed0, cols, rows);
    }
}

fn walk(seed0: u64, cols: u16, rows: u16) {
    let codes = key_codes();
    let mut app = sample_app_at(cols, rows);
    let mut seed = seed0;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failure = None;
    let mut visited: HashSet<String> = HashSet::new();
    let (mut c, mut r) = (cols, rows);
    for step in 0..3000usize {
        visited.insert(format!("{:?}", app.mode));
        let roll = next() % 20;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            match roll {
                // Steer into the new modes and feed the bus events their
                // calls would produce.
                0 => {
                    let _ = app.run_command("ca");
                }
                1 => {
                    let _ = app.run_command("ca.install");
                }
                2 => {
                    let _ = app.update(Action::OpenBrowser);
                }
                3 => {
                    let _ = app.on_bus(ok(
                        "browser.get_dom",
                        json!("<div><p id=x>a < b<span class='y'>"
                            .repeat(usize::try_from(next() % 300).unwrap_or(1))),
                    ));
                }
                4 => {
                    let _ = app.on_bus(ok(
                        "browser.screenshot",
                        json!(aitm_tui::base64::encode(
                            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x02\0\0\0\x03"
                        )),
                    ));
                }
                5 => {
                    let _ = app.on_bus(BusEvent::Toast(Level::Error, "engine gone".into()));
                }
                6 => {
                    let _ = app.on_bus(ok("ca.status", json!({"installed": true, "path": "/x"})));
                }
                7 => {
                    let _ = app.on_bus(BusEvent::DetailFailed("f41".into()));
                }
                8 => {
                    let _ = app.on_bus(BusEvent::Flows(vec![
                        summary(
                            "f41",
                            "GET",
                            "api.shop-staging.test",
                            "/api/products",
                            Some(200),
                            "observed",
                        ),
                        summary("z1", "POST", "new.test", "/n", None, "intercepted"),
                    ]));
                }
                9 => {
                    let _ = app.on_bus(BusEvent::Disconnected("reset".into()));
                    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
                }
                _ => {
                    let code = codes[(next() as usize) % codes.len()];
                    let m = if next() % 7 == 0 {
                        KeyModifiers::CONTROL
                    } else {
                        KeyModifiers::NONE
                    };
                    if let Some(action) = keys::map(KeyEvent::new(code, m), app.mode) {
                        if action != Action::Quit {
                            let _ = app.update(action);
                        }
                    }
                }
            }
            if step % 25 == 0 {
                (c, r) = match next() % 5 {
                    0 => (80, 24),
                    1 => (120, 11),
                    2 => (cols, rows),
                    3 => (41, 5),
                    _ => (200, 50),
                };
                let _ = app.update(Action::Resize(c, r));
            }
            let _ = text_of(&app, c, r);
        }));
        if let Err(e) = outcome {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            failure = Some(format!(
                "seed {seed0:#x} step {step} roll {roll} in {:?} at {c}×{r}: {msg}",
                app.mode
            ));
            break;
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(failure.is_none(), "{}", failure.unwrap());
    for mode in [
        "Browser",
        "Ca",
        "Prompt(Confirm)",
        "Prompt(Palette)",
        "Flows",
    ] {
        assert!(
            visited.contains(mode),
            "the walk never reached {mode}; visited {visited:?}"
        );
    }
    eprintln!(
        "tester pass 2: walk {seed0:#x} at {cols}×{rows} visited {} modes: {visited:?}",
        visited.len()
    );
}

fn key_codes() -> Vec<KeyCode> {
    let mut v = vec![
        KeyCode::Backspace,
        KeyCode::Enter,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Delete,
        KeyCode::Esc,
        KeyCode::F(5),
    ];
    v.extend((0x20u8..0x7f).map(|b| KeyCode::Char(char::from(b))));
    v.extend(['é', '日', '\u{200b}', '\u{1F512}'].map(KeyCode::Char));
    v
}

// ----------------------------------------------------- filters at the edge

/// I3 / S9: a `/re/` argument that would compile past the 1 MiB program
/// limit is refused with the limit named, one under it compiles, an invalid
/// one names the syntax error — at the parser and through `:filter`.
#[test]
fn regex_filters_name_the_size_limit_and_syntax_errors() {
    let err = filter::parse("~u /x{99999}/").unwrap_err();
    assert!(err.starts_with("bad regex /x{99999}/: "), "{err}");
    assert!(
        err.to_lowercase().contains("size limit"),
        "the 1 MiB program cap is what refuses it: {err}"
    );
    // Nested counted repetition grows the program multiplicatively.
    let err = filter::parse("~b /(a{1000}){1000}/").unwrap_err();
    assert!(
        err.to_lowercase().contains("size limit") || err.contains("too"),
        "{err}"
    );
    // Under the cap: compiles and matches case-insensitively.
    let expr = filter::parse("~u /^HTTPS:\\/\\/api\\.[a-z-]+\\.test\\/api\\/x{3}$/")
        .unwrap()
        .expect("an expression");
    let row = aitm_tui::model::FlowRow::from_summary(
        &json!({"id":"r","method":"GET","scheme":"https","authority":"api.shop-staging.test","path":"/api/xxx","status":200}),
        1,
    )
    .unwrap();
    let ctx = filter::Ctx {
        detail: None,
        in_scope: true,
    };
    assert!(expr.matches(&row, &ctx));
    assert!(
        filter::parse("~u /a{500}/").is_ok(),
        "a 500-wide literal fits"
    );
    // Through the app: the toast names the problem and the list is unchanged.
    // Three rows: a products GET, the login POST and a `/api/me` GET, so the
    // valid regex at the end selects exactly the two `/api/(auth|me)` URLs.
    let mut app = connected_app(200, 50);
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary(
            "f41",
            "GET",
            "api.shop-staging.test",
            "/api/products?category=electronics",
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
        summary(
            "f51",
            "GET",
            "api.shop-staging.test",
            "/api/me",
            Some(200),
            "observed",
        ),
    ]));
    let before = visible_ids(&app);
    assert_eq!(before, ["f41", "f50", "f51"]);
    let _ = app.run_command("filter ~u /x{99999}/");
    assert!(
        toast(&app).starts_with("filter: bad regex /x{99999}/: "),
        "{}",
        toast(&app)
    );
    assert!(app.filter.is_none());
    assert_eq!(visible_ids(&app), before);
    let _ = app.run_command("filter ~u /(/");
    assert!(
        toast(&app).starts_with("filter: bad regex /(/: "),
        "{}",
        toast(&app)
    );
    // The live prompt swallows the error until Enter: the last valid prefix
    // (`~d /[`, a literal) stays applied while the regex is unfinished, and
    // Enter on the broken one keeps the prompt open.
    let _ = app.update(Action::FilterOpen);
    for c in "~d /[/".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert!(
        app.filter.is_some(),
        "the `~d /[` literal is the last good prefix"
    );
    assert!(visible_ids(&app).is_empty(), "no host contains `/[`");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Filter));
    assert!(
        toast(&app).starts_with("filter: bad regex"),
        "{}",
        toast(&app)
    );
    // A valid one from the prompt applies live.
    let _ = app.update(Action::Back);
    let _ = app.update(Action::FilterOpen);
    for c in "~u /\\/api\\/(auth|me)/".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(visible_ids(&app), ["f50", "f51"]);
}

/// Every documented filter atom and operator selects exactly the rows its
/// table states, against thirteen inline rows: the atoms that read a
/// detail (`~t`, `~client`, `~comment`, `~mark`, `~a`, `~e`, `~b`, `~h`)
/// get one; the WebSocket row takes its host from its listed 101 handshake.
#[test]
fn filter_expressions_select_the_documented_rows() {
    let mut app = connected_app(200, 50);
    let _ = app.on_bus(BusEvent::Scope(vec!["*.shop-staging.test".into()]));
    let api = "api.shop-staging.test";
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary(
            "f1",
            "GET",
            api,
            "/api/products?category=electronics",
            Some(200),
            "observed",
        ),
        summary(
            "f2",
            "POST",
            "auth.shop-staging.test",
            "/api/auth/login",
            None,
            "intercepted",
        ),
        summary(
            "f3",
            "GET",
            "cdn.shop-staging.test",
            "/static/app.js",
            Some(304),
            "observed",
        ),
        summary(
            "f4",
            "GET",
            "tracker.example.com",
            "/pixel.gif",
            Some(200),
            "observed",
        ),
        json!({
            "id": "f5", "kind": "http", "method": "GET", "scheme": "https",
            "authority": api, "path": "/api/orders", "status": 500,
            "is_replay": true, "intercept": "observed"
        }),
        summary("f6", "GET", api, "/api/orders/42", Some(200), "observed"),
        summary(
            "f7",
            "PUT",
            api,
            "/api/cart/items/42",
            Some(200),
            "observed",
        ),
        summary(
            "f8",
            "GET",
            "cdn.shop-staging.test",
            "/live",
            Some(101),
            "observed",
        ),
        json!({
            "id": "f9", "kind": "websocket", "handshake": "f8", "messages": 2,
            "is_replay": false, "intercept": "observed"
        }),
        summary("f10", "PATCH", api, "/api/profile", Some(401), "observed"),
        summary("f11", "DELETE", api, "/api/cart/items/7", None, "killed"),
        summary("f12", "GET", api, "/api/me", None, "observed"),
        summary("f13", "HEAD", api, "/health", Some(200), "observed"),
    ]));
    // The details the detail-reading atoms need, in the core's shape.
    let detail = |id: &str,
                  req_headers: serde_json::Value,
                  req_body: Option<&[u8]>,
                  response: serde_json::Value,
                  process: &str,
                  meta: serde_json::Value| {
        FlowDetail::from_json(&json!({
            "id": id, "kind": "http", "intercept": "observed", "edited": id == "f2",
            "request": {"method": null, "headers": req_headers,
                        "body": req_body.map(aitm_tui::base64::encode),
                        "body_size": req_body.map_or(0, <[u8]>::len)},
            "response": response,
            "client_conn": {"peer": "127.0.0.1:52101", "sni": null, "alpn": "h2",
                            "tls": true, "process": process},
            "server_conn": null,
            "meta": meta
        }))
        .unwrap()
    };
    let meta = |marks: &[&str], comment: Option<&str>, origin: &str| {
        json!({"marks": marks, "comment": comment, "is_replay": false,
               "created": "2026-10-27T11:04:58.120Z", "duration_ms": 12,
               "truncated": false, "origin": origin})
    };
    let json_200 = json!({"status": 200, "headers": [["content-type", "application/json"]]});
    let html_200 =
        json!({"status": 200, "headers": [["content-type", "text/html; charset=utf-8"]]});
    let html_500 = json!({"status": 500, "headers": [["content-type", "text/html"]]});
    let login = br#"{"email":"ops@shop-staging.test","password":"correct-horse-battery"}"#;
    for d in [
        detail(
            "f1",
            json!([["host", api], ["x-request-id", "req-7f3a"]]),
            None,
            json_200,
            "curl",
            meta(&[], None, "human"),
        ),
        detail(
            "f2",
            json!([
                ["host", "auth.shop-staging.test"],
                ["content-type", "application/json"]
            ]),
            Some(login),
            json!(null),
            "curl",
            meta(&[], None, "human"),
        ),
        detail(
            "f5",
            json!([["host", api]]),
            None,
            html_500,
            "curl",
            meta(&[], Some("retried after a timeout"), "agent"),
        ),
        detail(
            "f6",
            json!([["host", api]]),
            None,
            html_200.clone(),
            "Safari",
            meta(&["red"], None, "human"),
        ),
        detail(
            "f7",
            json!([["host", api]]),
            None,
            json!({"status": 200, "headers": []}),
            "aitm",
            meta(&["sky"], None, "agent"),
        ),
    ] {
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    }
    assert_eq!(
        app.row("f9").unwrap().authority,
        "cdn.shop-staging.test",
        "the WebSocket row took its host from the listed handshake f8"
    );

    let cases: &[(&str, &[&str])] = &[
        ("~paused", &["f2"]),
        ("~killed", &["f11"]),
        ("~ws", &["f9"]),
        ("~replay", &["f5"]),
        ("~a", &["f5", "f7"]),
        ("~e", &["f2"]),
        ("~oos", &["f4"]),
        ("~q", &["f12"]),
        ("~d cdn", &["f3", "f8", "f9"]),
        ("~t html", &["f5", "f6"]),
        ("~client curl", &["f1", "f2", "f5"]),
        ("~comment retried", &["f5"]),
        ("~mark red", &["f6"]),
        ("~mark sky", &["f7"]),
        ("~s 4xx", &["f10"]),
        ("~s 304", &["f3"]),
        ("~s 5xx", &["f5"]),
        ("~b correct-horse", &["f2"]),
        ("~h x-request-id", &["f1"]),
        ("~m HEAD | login", &["f2", "f13"]),
        // f8 is the 101 upgrade; f9 (the WebSocket row) has no detail, so
        // its method is the `WS` placeholder and `~m GET` leaves it out.
        ("!~s 2xx ~m GET", &["f3", "f5", "f8", "f12"]),
        ("products & ~s 200", &["f1"]),
        ("(~m PUT | ~m PATCH) & ~d api", &["f7", "f10"]),
        ("~u \"cart/items/42\"", &["f7"]),
        ("~u api/*/login", &["f2"]),
        ("~url orders ~method GET !~replay", &["f6"]),
    ];
    for (expr, want) in cases {
        let _ = app.run_command(&format!("filter {expr}"));
        assert!(app.filter.is_some(), "{expr} parses");
        assert_eq!(visible_ids(&app), *want, "{expr}");
    }
    let _ = app.run_command("filter ~scope");
    assert_eq!(
        visible_ids(&app).len(),
        12,
        "every row but the tracker is under *.shop-staging.test"
    );
    let _ = app.run_command("filter ~zz");
    assert_eq!(toast(&app), "filter: unknown filter `~zz`");
    // `/` opens the prompt prefilled with the current expression.
    let _ = app.run_command("filter ~m GET");
    assert_eq!(
        keys::map(press(KeyCode::Char('/')), Mode::Flows),
        Some(Action::FilterOpen)
    );
    let _ = app.update(Action::FilterOpen);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Filter));
    assert_eq!(app.prompt, "~m GET");
    let text = text_of(&app, 200, 50);
    assert!(text.contains(" / ~m GET"), "{text}");
    assert!(text.contains("filter: editing…"), "{text}");
}

// ------------------------------------------------------ status bar totals

/// The status bar's byte total is a dash until a size is known: a bus
/// without `flow.detail` never knows one, a loaded detail makes the sum
/// real, and a detail whose bodies are empty honestly says `0 B`.
#[test]
fn status_bar_total_is_a_dash_until_a_size_is_known() {
    // A bus without `flow.detail` (the pre-merge core) knows no sizes.
    let mut old = App::new(TermCaps::full(), "x");
    let _ = old.update(Action::Resize(200, 50));
    let _ = connect(&mut old, PRE_MERGE_TOOLS, None);
    let _ = old.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/",
        Some(200),
        "observed",
    )]));
    assert!(old
        .flows
        .iter()
        .all(|r| r.req_size.is_none() && r.resp_size.is_none()));
    let status = text_of(&old, 200, 50).lines().last().unwrap().to_string();
    assert!(
        status.contains("— ↑ — ↓ — (F4)"),
        "no size is known without flow.detail: {status}"
    );
    assert!(!status.contains("0 B ↑"), "{status}");
    // With details, the sum is real: `f50`'s request body and `f41`'s
    // response body are both non-empty.
    let full = sample_app();
    let status = text_of(&full, 200, 50).lines().last().unwrap().to_string();
    assert!(!status.contains("— ↑ — ↓ —"), "{status}");
    assert!(!status.contains("0 B ↑"), "{status}");
    // With details whose bodies are all empty, `0 B` is the honest number.
    let mut empty = App::new(TermCaps::full(), "x");
    let _ = empty.update(Action::Resize(200, 50));
    let _ = connect(&mut empty, &["flow.list", "flow.get", "flow.detail"], None);
    let _ = empty.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/",
        Some(204),
        "observed",
    )]));
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http",
        "request":{"method":"GET","path":"/","headers":[]},"response":{"status":204,"headers":[]}}))
    .unwrap();
    let _ = empty.on_bus(BusEvent::Detail(Box::new(d)));
    let status = text_of(&empty, 200, 50).lines().last().unwrap().to_string();
    assert!(status.contains("0 B ↑ — ↓ — (F4)"), "{status}");
}

// ------------------------------------------------------- the detail cache

/// S3 (public surface): the detail cap is `MAX_DETAILS` through `on_bus`,
/// and Q1's `DetailFailed` mark survives the prune while the flow is listed
/// and is dropped with the flow.
#[test]
fn detail_cap_and_detail_failed_marks_follow_the_flow_list() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = connect(&mut app, &["flow.list", "flow.get", "flow.detail"], None);
    let n = MAX_DETAILS + 10;
    let summaries: Vec<_> = (0..n)
        .map(|i| {
            summary(
                &format!("f{i}"),
                "GET",
                "h.test",
                "/p",
                Some(200),
                "observed",
            )
        })
        .collect();
    let reqs = app.on_bus(BusEvent::Flows(summaries.clone()));
    assert_eq!(reqs.len(), n, "one detail per new row");
    let _ = app.on_bus(BusEvent::DetailFailed("f5".into()));
    for i in 0..n {
        if i == 5 {
            continue;
        }
        let d = FlowDetail::from_json(&json!({"id": format!("f{i}"), "kind": "http"})).unwrap();
        let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    }
    // The next poll: nothing re-requested (f5 is marked, the rest are loaded)
    // and the map is capped.
    let reqs = app.on_bus(BusEvent::Flows(summaries.clone()));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.details.len(), MAX_DETAILS);
    assert!(app.detail_failed.contains("f5"));
    // An evicted detail is not re-fetched by a poll, even when the row's
    // state changes (the row keeps its summary columns); selecting the row
    // fetches it again.
    assert!(!app.details.contains_key("f0"), "oldest evicted");
    let mut changed = summaries.clone();
    changed[0] = summary("f0", "GET", "h.test", "/p", Some(500), "observed");
    let reqs = app.on_bus(BusEvent::Flows(changed));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.row("f0").and_then(|r| r.status), Some(500));
    app.selected = Some("f0".into());
    assert_eq!(
        app.update(Action::Enter),
        vec![BusRequest::Detail("f0".into())]
    );
    let _ = app.update(Action::Back);
    // f5 vanishes: its mark goes with it; back again, it is asked for anew.
    let _ = app.on_bus(BusEvent::Flows(summaries[6..].to_vec()));
    assert!(!app.detail_failed.contains("f5"));
    let reqs = app.on_bus(BusEvent::Flows(summaries[5..].to_vec()));
    assert_eq!(reqs, vec![BusRequest::Detail("f5".into())]);
}

/// §4.2 step 3: `tools/list` drives features — `flow.detail` fetches happen
/// only when the bus offers the tool, for new rows, on Enter, and when a
/// row's state changes after its detail was loaded.
#[test]
fn tools_list_drives_detail_fetching() {
    // "A bus without flow.detail" is the pre-merge core now.
    let core_only = |app: &mut App| connect(app, PRE_MERGE_TOOLS, None);
    let mut app = App::new(TermCaps::full(), "x");
    let _ = core_only(&mut app);
    let a = summary("a", "GET", "h.test", "/a", None, "observed");
    assert!(
        app.on_bus(BusEvent::Flows(vec![a.clone()])).is_empty(),
        "no flow.detail: no fetch"
    );
    assert!(app.update(Action::Enter).is_empty());
    assert_eq!(app.mode, Mode::Inspector);
    assert!(text_of(&app, 200, 50).contains("need core follow-up F5"));

    let mut app = App::new(TermCaps::full(), "x");
    let mut with_detail: Vec<&str> = PRE_MERGE_TOOLS.to_vec();
    with_detail.push("flow.detail");
    let _ = connect(&mut app, &with_detail, None);
    assert_eq!(
        app.on_bus(BusEvent::Flows(vec![a.clone()])),
        vec![BusRequest::Detail("a".into())]
    );
    assert!(text_of(&app, 200, 50).contains("loading detail…"));
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http","request":{"method":"GET","path":"/a","headers":[["host","h.test"]]}})).unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    assert!(app.details.contains_key("a"));
    // Same state again: no refetch.
    assert!(app.on_bus(BusEvent::Flows(vec![a.clone()])).is_empty());
    // The response landed: the stale detail is dropped and fetched again.
    let done = summary("a", "GET", "h.test", "/a", Some(200), "observed");
    assert_eq!(
        app.on_bus(BusEvent::Flows(vec![done.clone()])),
        vec![BusRequest::Detail("a".into())]
    );
    assert!(!app.details.contains_key("a"));
    // Enter on a row without a detail asks for it; with one, it does not.
    assert_eq!(
        app.update(Action::Enter),
        vec![BusRequest::Detail("a".into())]
    );
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http"})).unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    let _ = app.update(Action::Back);
    assert!(app.update(Action::Enter).is_empty());
    // A bus notification (F4) triggers a refresh; CallOk too.
    assert_eq!(
        app.on_bus(BusEvent::Notification(
            json!({"method":"notifications/aitm/state","params":{"paused":1}})
        )),
        vec![BusRequest::Refresh]
    );
    assert_eq!(
        app.on_bus(BusEvent::CallOk {
            name: "flow.kill".into(),
            value: json!("ok")
        }),
        vec![BusRequest::Refresh]
    );
    assert_eq!(toast(&app), "Killed");
    // `ToolInfo::params` reads the schema a form is built from (§4.2 step 3).
    let t = ToolInfo {
        name: "x".into(),
        description: String::new(),
        input_schema: json!({"type":"object","properties":{"id":{"type":"string","description":"The flow."},"n":{"type":"integer"}},"required":["id"]}),
    };
    assert_eq!(
        t.params(),
        vec![
            Param {
                name: "id".to_string(),
                ty: "string".to_string(),
                required: true,
                description: "The flow.".to_string(),
            },
            Param {
                name: "n".to_string(),
                ty: "integer".to_string(),
                required: false,
                description: String::new(),
            },
        ]
    );
}

// --------------------------------------------------------- selection

#[test]
fn auto_select_and_selection_stability() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = connect(&mut app, CORE_TOOLS, None);
    let a = summary("a", "GET", "h.test", "/a", Some(200), "observed");
    let b = summary("b", "GET", "h.test", "/b", Some(200), "observed");
    let c = summary("c", "GET", "h.test", "/c", None, "observed");
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone()]));
    assert_eq!(app.selected.as_deref(), Some("a"), "first flow is selected");
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone(), b.clone()]));
    assert_eq!(
        app.selected.as_deref(),
        Some("a"),
        "a new flow does not steal selection"
    );

    assert_eq!(
        keys::map(press(KeyCode::Char('t')), Mode::Flows),
        Some(Action::ToggleAutoSelect)
    );
    let _ = app.update(Action::ToggleAutoSelect);
    assert_eq!(toast(&app), "Auto-select on");
    assert!(text_of(&app, 160, 30).contains("Auto-select ●"));
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone(), b.clone(), c.clone()]));
    assert_eq!(
        app.selected.as_deref(),
        Some("c"),
        "auto-select follows the newest"
    );
    // Moving by hand turns auto-select off again.
    let _ = app.update(Action::Up);
    assert!(!app.auto_select);
    assert_eq!(app.selected.as_deref(), Some("b"));

    // b vanishes: selection cleared, a and c keep their numbers.
    let _ = app.on_bus(BusEvent::Flows(vec![a, c]));
    assert_eq!(app.selected, None);
    assert_eq!(
        app.flows
            .iter()
            .map(|r| (r.id.as_str(), r.seq))
            .collect::<Vec<_>>(),
        vec![("a", 1), ("c", 3)]
    );
    // Navigation with no selection lands on the newest.
    let _ = app.update(Action::Down);
    assert_eq!(app.selected.as_deref(), Some("c"));
    let _ = app.update(Action::Home);
    assert_eq!(app.selected.as_deref(), Some("a"));
    let _ = app.update(Action::End);
    assert_eq!(app.selected.as_deref(), Some("c"));
}

// --------------------------------------------------- honest degradation

/// Every control whose tool the bus does not offer degrades to a labelled
/// follow-up instead of an empty pane or a silent no-op, and reaches the
/// bus once the tool is there.
#[test]
fn every_absent_tool_degrades_to_a_labelled_follow_up() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(200, 50));
    // The pre-merge bus: none of the F5/F6/F7/F12/F13 tools, so each
    // control's label is exercised (today's core has them all).
    let _ = connect(&mut app, PRE_MERGE_TOOLS, None);
    app.scope = vec!["h.test".into()];
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ]));
    app.selected = Some("a".into());

    let expect_toast = |app: &mut App, action: Action, f: &str| {
        assert!(
            app.update(action.clone()).is_empty(),
            "{action:?} must not reach the bus"
        );
        assert!(toast(app).contains(f), "{action:?}: {}", toast(app));
    };
    expect_toast(&mut app, Action::Mark, "F6");
    expect_toast(&mut app, Action::Comment, "F6");
    expect_toast(&mut app, Action::AgentSet(AgentPolicy::Paused), "F1");
    for (cmd, f) in [
        ("clear", "F7"),
        ("pause", "F7"),
        ("record", "F7"),
        ("import /x.har", "F10"),
        ("scope rm h.test", "F12"),
    ] {
        assert!(app.run_command(cmd).is_empty(), "{cmd}");
        assert!(toast(&app).contains(f), "{cmd}: {}", toast(&app));
    }
    // Edit on a paused flow without flow.detail: F5, and nothing is asked
    // of a bus that cannot answer (Q-6: one `request_detail` gate).
    app.selected = Some("b".into());
    assert!(
        app.update(Action::Edit).is_empty(),
        "no flow.detail on this bus: nothing to fetch"
    );
    assert!(toast(&app).contains("F5"), "{}", toast(&app));
    assert_eq!(app.mode, Mode::Flows);
    // The inspector and quick-look say F5 instead of showing an empty pane.
    app.mode = Mode::Inspector;
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("Headers and bodies need core follow-up F5 (flow.detail)"),
        "{text}"
    );
    app.mode = Mode::QuickLook;
    assert!(text_of(&app, 200, 50).contains("Bodies need core follow-up F5 (flow.detail)"));
    app.mode = Mode::Flows;
    // The toolbar pill, the sidebar and the panels carry their labels.
    let text = text_of(&app, 200, 50);
    for label in [
        "(core follow-up F7)",
        "F10│",
        "M3│",
        "F1│",
        "n/a (F1)",
        "↑ — ↓ — (F4)",
    ] {
        assert!(text.contains(label), "{label}: {text}");
    }
    // The Browser item's count is the tab count, which needs F14: a dash
    // for "missing" (§2.8), not a "not built" label — the view is built.
    assert!(
        line_with(&text, "  Browser").is_some_and(|l| l.ends_with("—│")),
        "{:?}",
        line_with(&text, "  Browser")
    );
    let _ = app.update(Action::OpenScope);
    assert!(text_of(&app, 200, 50).contains("(needs core follow-up F12)"));
    assert!(text_of(&app, 200, 50).contains("readout needs F7, config.get"));
    let _ = app.update(Action::ToggleIntercept);
    app.mode = Mode::Flows;
    app.selected = Some("a".into());
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/a",
        Some(200),
        "observed",
    )]));
    assert!(text_of(&app, 200, 50).contains("Rules… needs core follow-up F3"));
    // The paused bar's Kill hint names the abort modes F3 adds; `:export`
    // names F10 (fix pass 1, I1).
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ]));
    assert!(
        text_of(&app, 200, 50).contains("[d Kill · abort mode: reset (429/503 need F3)]"),
        "{}",
        text_of(&app, 200, 50)
    );
    assert!(app.run_command("export").is_empty());
    assert!(toast(&app).contains("F10"), "{}", toast(&app));

    // With the tools present, the same controls reach the bus.
    app.tools.extend(tools(&[
        "flow.mark",
        "flow.comment",
        "agent.set",
        "flow.clear",
        "proxy.pause",
        "proxy.resume",
        "flow.import",
        "scope.remove",
    ]));
    let _ = app.update(Action::Mark);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Mark));
    for c in "red sky".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::Mark {
            id: "a".into(),
            marks: vec!["red".into(), "sky".into()]
        }]
    );
    let _ = app.update(Action::Comment);
    for c in "looks odd".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::Comment {
            id: "a".into(),
            text: "looks odd".into()
        }]
    );
    assert_eq!(app.run_command("clear"), vec![BusRequest::ClearFlows]);
    assert_eq!(app.run_command("pause"), vec![BusRequest::ProxyPause(true)]);
    assert_eq!(
        app.run_command("record"),
        vec![BusRequest::ProxyPause(false)]
    );
    assert_eq!(
        app.run_command("scope rm h.test"),
        vec![BusRequest::ScopeRemove("h.test".into())]
    );
    assert_eq!(
        app.run_command("import /x.har"),
        vec![BusRequest::Import("/x.har".into())]
    );
}

// ------------------------------------------------------------ prompts

/// M1: a prompt returns to the mode it was opened from, not to a mode fixed
/// by its kind — `:` from the Scope panel lands back in Scope, `/` from the
/// inspector back in the inspector.
#[test]
fn a_prompt_returns_to_the_mode_it_was_opened_from() {
    let mut app = sample_app();
    let _ = app.update(Action::OpenScope);
    assert_eq!(app.mode, Mode::Scope);
    let _ = app.update(Action::PaletteOpen);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Palette));
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Scope, "Esc from `:` opened in Scope");

    app.mode = Mode::Inspector;
    let _ = app.update(Action::FilterOpen);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Filter));
    for c in "login".chars() {
        let _ = app.update(Action::Input(c));
    }
    let _ = app.update(Action::Submit);
    assert_eq!(
        app.mode,
        Mode::Inspector,
        "Enter from `/` opened in Inspector"
    );
    assert_eq!(app.filter_text, "login");

    // The palette's Enter on a blank line goes back where it came from too.
    let _ = app.run_command("ca");
    assert_eq!(app.mode, Mode::Ca);
    let _ = app.update(Action::PaletteOpen);
    let _ = app.update(Action::Submit);
    assert_eq!(app.mode, Mode::Ca, "Enter (blank) from `:` opened in Ca");

    // A chained prompt keeps the origin of the first one.
    let _ = app.update(Action::OpenFindings);
    let _ = app.update(Action::PocRerun);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocTarget));
    let _ = app.update(Action::Submit);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocVars));
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Findings);
}

/// Every prompt kind: Esc and a blank Enter both land in the mode the
/// prompt was opened from and clear the line; the chained first prompts
/// go home on Esc and to their second prompt on Enter; a blank Enter on
/// Confirm is a "no".
#[test]
fn esc_and_enter_from_every_prompt_land_in_the_same_mode() {
    let open = |app: &mut App, kind: PromptKind| {
        app.mode = Mode::Flows;
        app.selected = Some("f50".into());
        match kind {
            PromptKind::Palette => {
                let _ = app.update(Action::PaletteOpen);
            }
            PromptKind::Filter => {
                let _ = app.update(Action::FilterOpen);
            }
            PromptKind::Comment => {
                let _ = app.update(Action::Comment);
            }
            PromptKind::Mark => {
                let _ = app.update(Action::Mark);
            }
            PromptKind::Pin => app.mode = Mode::Prompt(PromptKind::Pin),
            PromptKind::ScopeAdd => {
                let _ = app.update(Action::OpenScope);
                let _ = app.update(Action::ScopeAddPrompt);
            }
            PromptKind::PocName => {
                let _ = app.update(Action::BuildPoc);
            }
            PromptKind::PocParam => {
                let _ = app.update(Action::BuildPoc);
                let _ = app.update(Action::Submit);
            }
            PromptKind::PocTarget => {
                let _ = app.update(Action::OpenFindings);
                let _ = app.update(Action::PocRerun);
            }
            PromptKind::PocVars => {
                let _ = app.update(Action::OpenFindings);
                let _ = app.update(Action::PocRerun);
                let _ = app.update(Action::Submit);
            }
            PromptKind::CaExport => {
                let _ = app.run_command("ca");
                let _ = app.update(Action::CaExportPrompt);
            }
            PromptKind::Confirm => {
                let _ = app.run_command("ca");
                let _ = app.update(Action::Command("ca.install".into()));
            }
            PromptKind::BrowserUrl => {
                let _ = app.update(Action::OpenBrowser);
                let _ = app.update(Action::BrowserNavigatePrompt);
            }
            PromptKind::BrowserEval => {
                let _ = app.update(Action::OpenBrowser);
                let _ = app.update(Action::BrowserEvalPrompt);
            }
        }
        assert_eq!(app.mode, Mode::Prompt(kind), "{kind:?} opens");
    };
    let cases = [
        (PromptKind::Palette, Mode::Flows),
        (PromptKind::Filter, Mode::Flows),
        (PromptKind::Comment, Mode::Flows),
        (PromptKind::Mark, Mode::Flows),
        (PromptKind::Pin, Mode::Flows),
        (PromptKind::ScopeAdd, Mode::Scope),
        (PromptKind::PocParam, Mode::Flows),
        (PromptKind::PocVars, Mode::Findings),
        (PromptKind::CaExport, Mode::Ca),
        (PromptKind::Confirm, Mode::Ca),
        (PromptKind::BrowserUrl, Mode::Browser),
        (PromptKind::BrowserEval, Mode::Browser),
    ];
    for (kind, home) in cases {
        let mut app = sample_app();
        open(&mut app, kind);
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, home, "Esc from {kind:?}");
        assert_eq!(app.prompt, "", "Esc clears the line ({kind:?})");
        open(&mut app, kind);
        let _ = app.update(Action::Submit);
        assert_eq!(app.mode, home, "Enter (blank) from {kind:?}");
        assert_eq!(app.prompt, "", "Enter clears the line ({kind:?})");
    }
    // The chained first prompts: Esc goes home, Enter goes to the second prompt.
    for (kind, home, next) in [
        (PromptKind::PocName, Mode::Flows, PromptKind::PocParam),
        (PromptKind::PocTarget, Mode::Findings, PromptKind::PocVars),
    ] {
        let mut app = sample_app();
        open(&mut app, kind);
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, home, "Esc from {kind:?}");
        open(&mut app, kind);
        let _ = app.update(Action::Submit);
        assert_eq!(app.mode, Mode::Prompt(next), "Enter from {kind:?}");
    }
    // Confirm: Enter on the blank line is a "no", like Esc — nothing is sent.
    let mut app = sample_app();
    open(&mut app, PromptKind::Confirm);
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(toast(&app), "ca.install cancelled");
}

/// SEC-4: `dry_run` skips the local confirm only when the tool's schema
/// declares it and the value is the JSON boolean `true`; a tool without
/// the parameter always asks.
#[test]
fn dry_run_bypasses_the_confirm_only_as_a_declared_boolean_true() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = connect(&mut app, CORE_TOOLS, None);
    // The test bus's empty schema declares no `dry_run`: the prompt opens anyway.
    assert!(app.run_command("ca.install dry_run=true").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let _ = app.update(Action::Back);
    assert!(app.run_command("ca.install dry_run=TRUE").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let _ = app.update(Action::Back);

    // A schema that declares it as a boolean: `true` bypasses, `false` asks.
    app.tools.retain(|t| t.name != "ca.uninstall");
    app.tools.push(ToolInfo {
        name: "ca.uninstall".into(),
        description: "Remove the CA (confirmed).".into(),
        input_schema: json!({"type":"object","properties":{"dry_run":{"type":"boolean","description":"Only report."}}}),
    });
    assert_eq!(
        app.run_command("ca.uninstall dry_run=true"),
        vec![call("ca.uninstall", json!({"dry_run": true}))]
    );
    assert_eq!(app.mode, Mode::Flows);
    assert!(app.run_command("ca.uninstall dry_run=false").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let _ = app.update(Action::Back);
    // Against the declared boolean, `TRUE` is not JSON: refused before anything is sent.
    assert!(app.run_command("ca.uninstall dry_run=TRUE").is_empty());
    assert_eq!(app.mode, Mode::Flows);
    assert!(
        toast(&app).starts_with("ca.uninstall: dry_run:"),
        "{}",
        toast(&app)
    );
}

// ------------------------------------------------------- findings on disk

/// M3: a PoC path that names a directory with a `.yaml` name is not read —
/// the entry's YAML stays empty and the error says it wants a regular file.
#[test]
fn finding_yaml_refuses_a_directory_handle_with_a_yaml_name() {
    let dir =
        std::env::temp_dir().join(format!("aitm-tui-robustness-fstat-{}", std::process::id()));
    let as_dir = dir.join("poc.yaml");
    std::fs::create_dir_all(&as_dir).unwrap();
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.on_bus(BusEvent::Findings(vec![Finding::from_json(
        &json!({"poc_path": as_dir.to_string_lossy(), "passed": true}),
    )
    .unwrap()]));
    assert_eq!(app.findings[0].yaml, None);
    let err = app.findings[0].yaml_error.as_deref().unwrap_or("");
    assert!(err.contains("regular file"), "{err:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// M5: Findings `o` hands the desktop a regular file whose first bytes are
/// an image; a `.png`-named text file or directory opens nothing and the
/// toast says so with the resolved path.
#[test]
fn findings_o_opens_only_a_regular_file_that_is_an_image() {
    let dir =
        std::env::temp_dir().join(format!("aitm-tui-robustness-image-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("dir.png")).unwrap();
    let fake = dir.join("fake.png");
    std::fs::write(&fake, "hello, not an image\n").unwrap();
    let real = dir.join("real.png");
    std::fs::write(&real, test_png()).unwrap();

    let mut app = sample_app();
    // A local path is only opened from a loopback bus (C10): elsewhere the
    // bytes come through `poc.artifact`.
    app.bus_address = "127.0.0.1:9090".into();
    let _ = app.update(Action::OpenFindings);
    app.finding_cursor = 0;

    app.findings[0].screenshot_path = Some(fake.to_string_lossy().into_owned());
    let _ = app.update(Action::OpenExternally);
    assert!(
        app.take_open_target().is_none(),
        "a text file is not opened"
    );
    assert_eq!(
        toast(&app),
        format!(
            "not an image: {}",
            std::fs::canonicalize(&fake).unwrap().display()
        )
    );

    app.findings[0].screenshot_path = Some(dir.join("dir.png").to_string_lossy().into_owned());
    let _ = app.update(Action::OpenExternally);
    assert!(
        app.take_open_target().is_none(),
        "a directory is not opened"
    );
    assert!(toast(&app).starts_with("not an image: "), "{}", toast(&app));

    app.findings[0].screenshot_path = Some(real.to_string_lossy().into_owned());
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("a real PNG opens");
    assert_eq!(target.path, std::fs::canonicalize(&real).unwrap());
    assert_eq!(target.label, "screenshot");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The PoC YAML is read from disk only for small, regular `.yaml`/`.yml`
/// files (the loopback bus without `poc.get`), the read copy is carried
/// forward across `poc.list` passes, and a result that brings its own YAML
/// wins over the carried copy.
#[test]
fn finding_yaml_is_read_only_from_small_regular_yaml_files_and_is_carried_forward() {
    let dir = std::env::temp_dir().join(format!("aitm-tui-robustness-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.yaml");
    std::fs::write(&good, "name: ok\n").unwrap();
    let not_yaml = dir.join("notes.txt");
    std::fs::write(&not_yaml, "name: txt\n").unwrap();
    let big = dir.join("big.yml");
    std::fs::write(&big, "x".repeat(256 * 1024 + 1)).unwrap();
    let subdir = dir.join("dir.yaml");
    std::fs::create_dir_all(&subdir).unwrap();
    // `poc.list` entries are files, not runs (C8): no `passed` here, so a
    // later pass replaces them rather than keeping them as run results.
    let finding = |p: &Path| {
        Finding::from_json(&json!({"poc_path": p.to_string_lossy(), "title": "t"})).unwrap()
    };

    // A loopback bus without `poc.get`: the YAML is read from disk.
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.on_bus(BusEvent::Findings(vec![
        finding(&good),
        finding(&not_yaml),
        finding(&big),
        finding(&subdir),
    ]));
    assert_eq!(app.findings[0].yaml.as_deref(), Some("name: ok\n"));
    assert_eq!(app.findings[0].yaml_error, None);
    for (i, want) in [(1, ".yaml"), (2, "256 KiB"), (3, "regular file")] {
        assert_eq!(app.findings[i].yaml, None, "finding {i}");
        let err = app.findings[i].yaml_error.as_deref().unwrap_or("");
        assert!(
            err.contains(want),
            "finding {i}: {err:?} should mention {want:?}"
        );
    }

    // The file is gone, but a new `poc.list` pass keeps what was read.
    std::fs::remove_file(&good).unwrap();
    let _ = app.on_bus(BusEvent::Findings(vec![finding(&good), finding(&big)]));
    assert_eq!(app.findings[0].yaml.as_deref(), Some("name: ok\n"));
    assert!(app.findings[1]
        .yaml_error
        .as_deref()
        .unwrap_or("")
        .contains("256 KiB"));
    // A result that brings its own YAML wins over the carried copy.
    let inline =
        Finding::from_json(&json!({"poc_path": good.to_string_lossy(), "yaml": "name: inline\n"}))
            .unwrap();
    let _ = app.on_bus(BusEvent::Findings(vec![inline]));
    assert_eq!(app.findings[0].yaml.as_deref(), Some("name: inline\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// SEC-2: Findings `o` opens the screenshot by its canonical path; a path
/// that does not resolve here opens nothing locally — on a bus with
/// `poc.artifact` (C10) it is fetched, on one without it the toast says why.
#[test]
fn findings_o_canonicalizes_the_screenshot_path_and_refuses_one_that_does_not_resolve() {
    let mut app = connected_app(200, 50);
    // One `poc.run` result whose screenshot is a relative path that does
    // not exist in this process's working directory.
    let _ = app.on_bus(BusEvent::Findings(vec![Finding::from_json(&json!({
        "poc_path": "pocs/reflected-xss-search.yaml", "title": "Reflected XSS in search",
        "severity": "high", "target": "https://www.shop-staging.test", "passed": true,
        "screenshot_path": "pocs/reflected-xss-search.png"
    }))
    .unwrap()]));
    app.bus_address = "127.0.0.1:9090".into();
    let _ = app.update(Action::OpenFindings);
    app.finding_cursor = 0;
    assert_eq!(
        app.findings[0].screenshot_path.as_deref(),
        Some("pocs/reflected-xss-search.png"),
        "a relative path that does not exist here"
    );
    assert_eq!(
        app.update(Action::OpenExternally),
        vec![call(
            "poc.artifact",
            json!({"path": "pocs/reflected-xss-search.png"})
        )],
        "unresolved here, so fetched through the bus"
    );
    assert!(app.take_open_target().is_none(), "nothing to open yet");
    app.pending_artifact = None;
    app.tools.retain(|t| t.name != "poc.artifact");
    assert!(app.update(Action::OpenExternally).is_empty());
    assert!(app.take_open_target().is_none(), "nothing to open");
    assert!(toast(&app).starts_with("open: "), "{}", toast(&app));

    let dir = std::env::temp_dir().join(format!("aitm-tui-robustness-shot-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    let shot = dir.join("shot.png");
    std::fs::write(&shot, test_png()).unwrap();
    let dotted = dir.join("sub").join("..").join("shot.png");
    app.findings[0].screenshot_path = Some(dotted.to_string_lossy().into_owned());
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("an existing file opens");
    assert_eq!(target.path, std::fs::canonicalize(&shot).unwrap());
    assert!(!target.path.components().any(|c| c.as_os_str() == ".."));
    assert_eq!(target.label, "screenshot");
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------- browser calls in flight

/// M2: only the `browser.*` calls the view tracks (those with a busy label)
/// count as in flight — an answer for an untracked `browser.*` tool does
/// not settle a tracked call that is still waiting.
#[test]
fn an_untracked_browser_tool_answer_does_not_settle_a_tracked_call_in_flight() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let mut with_tabs: Vec<&str> = CORE_TOOLS.to_vec();
    with_tabs.push("browser.tabs");
    let _ = connect(&mut app, &with_tabs, None);
    let _ = app.update(Action::BrowserRefreshDom);
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(app.browser.busy, Some("reading the DOM"));

    // An untracked call is not counted when sent …
    assert_eq!(
        app.run_command("browser.tabs"),
        vec![call("browser.tabs", json!({}))]
    );
    assert_eq!(app.browser.inflight, 1, "browser.tabs is not tracked");
    assert_eq!(app.browser.busy, Some("reading the DOM"));
    // … nor when it answers or fails.
    let _ = app.on_bus(BusEvent::CallOk {
        name: "browser.tabs".into(),
        value: json!([]),
    });
    assert_eq!(app.browser.inflight, 1, "get_dom is still in flight");
    assert_eq!(app.browser.busy, Some("reading the DOM"));
    let _ = app.on_bus(failed("browser.tabs", "no tabs"));
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(app.browser.busy, Some("reading the DOM"));
    assert_eq!(app.browser.error, None, "not the view's answer");
    assert_eq!(toast(&app), "no tabs");

    let _ = app.on_bus(BusEvent::CallOk {
        name: "browser.get_dom".into(),
        value: json!("<html></html>"),
    });
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
}

/// QI-1: an error toast about something else while a `browser.*` call is in
/// flight is not that call's answer — the view stays busy and shows no
/// error; only a `CallFailed` naming a `browser.*` tool settles it.
#[test]
fn an_unrelated_error_toast_does_not_settle_an_in_flight_browser_call() {
    let mut app = connected_app(200, 50);
    let reqs = app.update(Action::OpenBrowser);
    assert_eq!(
        reqs,
        vec![
            call("browser.get_dom", json!({})),
            call("browser.screenshot", json!({})),
        ]
    );
    // The screenshot answers; the DOM read is the one call left in flight.
    let _ = app.on_bus(BusEvent::CallOk {
        name: "browser.screenshot".into(),
        value: json!(aitm_tui::base64::encode(b"\x89PNG\r\n\x1a\n")),
    });
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(app.browser.busy, Some("loading the page"));

    let _ = app.on_bus(BusEvent::Toast(
        Level::Error,
        "flow is not intercepted".into(),
    ));
    assert_eq!(app.browser.inflight, 1, "still waiting for browser.get_dom");
    assert_eq!(app.browser.busy, Some("loading the page"));
    assert_eq!(app.browser.error, None);
    assert_eq!(toast(&app), "flow is not intercepted");

    // A failed call for another tool is a toast only.
    let _ = app.on_bus(failed("flow.resume", "flow is not intercepted"));
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(app.browser.error, None);

    // The browser call's own failure settles it and lands in the panel.
    let _ = app.on_bus(failed("browser.get_dom", "browser engine is not running"));
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser engine is not running")
    );
    assert_eq!(toast(&app), "browser engine is not running");
    assert!(
        text_of(&app, 200, 50).contains("error: browser engine is not running"),
        "{}",
        text_of(&app, 200, 50)
    );
    // Extra failures never underflow the counter.
    let _ = app.on_bus(failed("browser.screenshot", "late"));
    assert_eq!(app.browser.inflight, 0);
}

/// QI-1: a disconnect (and the reconnect that follows) forgets every
/// `browser.*` call in flight — the bus will never answer them.
#[test]
fn a_disconnect_during_a_navigate_clears_the_browser_busy_state() {
    let mut app = connected_app(200, 50);
    let reqs = app.run_command("browser.navigate url=https://asked.test/");
    assert_eq!(reqs.len(), 1);
    assert_eq!(app.browser.busy, Some("navigating"));
    assert_eq!(app.browser.inflight, 1);

    let _ = app.on_bus(BusEvent::Disconnected("reset".into()));
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
    assert!(
        !text_of(&app, 200, 50).contains("⟳ navigating"),
        "{}",
        text_of(&app, 200, 50)
    );

    // In flight again, then the reconnect lands: forgotten too.
    let _ = app.update(Action::BrowserScreenshot);
    assert_eq!(app.browser.inflight, 1);
    let _ = connect(&mut app, CORE_TOOLS, None);
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
}

/// QI-1: the bus task's "not on this bus" branch is a `CallFailed` too, so
/// the browser view shows it the same way; `Toast` is left for notices with
/// no tool behind them.
#[test]
fn a_not_on_this_bus_call_failed_lands_in_the_browser_panel() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, None);
    let _ = app.update(Action::OpenBrowser);
    assert_eq!(app.browser.inflight, 2);
    let _ = app.on_bus(failed(
        "browser.screenshot",
        "browser.screenshot is not on this bus",
    ));
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser.screenshot is not on this bus")
    );
    assert_eq!(toast(&app), "browser.screenshot is not on this bus");
    assert_eq!(app.current_toast().map(|t| t.level), Some(Level::Error));
    let _ = app.on_bus(BusEvent::Toast(
        Level::Warn,
        "browser.get_dom is not on this bus".into(),
    ));
    assert_eq!(
        app.browser.inflight, 1,
        "a Toast is a notice, never a call's answer"
    );
}

// ------------------------------------------------------ websocket rows

/// P2-F1: a WebSocket row whose handshake is not listed has no host; the
/// Domains grouping leaves it out instead of drawing an empty group, and
/// the sidebar's domain count does not count it.
#[test]
fn a_websocket_row_without_a_listed_handshake_makes_no_empty_domains_group() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, None);
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("h1", "GET", "api.test", "/a", Some(200), "observed"),
        json!({"id":"w1","kind":"websocket","handshake":"gone","messages":1,"intercept":"observed"}),
    ]));
    assert_eq!(app.row("w1").unwrap().authority, "");
    assert_eq!(app.domains(), vec![("api.test".to_string(), 1)]);
    app.sidebar = SidebarItem::Domains;
    let vis = app.visible();
    assert_eq!(vis.len(), 2, "the row is still listed");
    let headers: Vec<String> = (0..vis.len())
        .filter_map(|pos| app.group_header(&vis, pos))
        .map(|(k, _)| k)
        .collect();
    assert_eq!(headers, vec!["api.test".to_string()]);
    let text = text_of(&app, 200, 50);
    assert!(
        line_with(&text, "  Domains").is_some_and(|l| l.contains("1")),
        "{text}"
    );
    // A scope-gated verb on it is refused without naming an empty host.
    app.selected = Some("w1".into());
    assert!(app.update(Action::BuildPoc).is_empty());
    assert_eq!(
        toast(&app),
        "Out of scope — unknown host (the WebSocket handshake is not listed)"
    );
}

// ------------------------------------------- tester: hostile tools/list

/// Tester: a bus whose `tools/list` is empty — every plugin off, or a list
/// that failed to parse — leaves every mode drawable at the design size and
/// in a small terminal, degrades each control to its follow-up label, sends
/// nothing for a tool that is not there, and lists no tool in the palette.
#[test]
fn a_bus_that_offers_no_tools_renders_every_mode_and_sends_nothing() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let reqs = connect(&mut app, &[], None);
    assert_eq!(
        reqs,
        vec![BusRequest::Refresh],
        "the handshake still asks for the first list"
    );
    assert!(app.tools.is_empty());
    app.scope = vec!["h.test".into()];
    let reqs = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ]));
    assert!(reqs.is_empty(), "no flow.detail: nothing fetched: {reqs:?}");
    assert_eq!(app.flows.len(), 2, "rows land without any tool listed");
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("listen address unknown (core follow-up F7)"),
        "{text}"
    );
    assert!(text.contains("https://h.test/a"), "{text}");
    // Controls stay local and say which follow-up they need.
    app.selected = Some("a".into());
    for (action, label) in [
        (Action::Mark, "F6"),
        (Action::Comment, "F6"),
        (Action::AgentSet(AgentPolicy::Paused), "F1"),
    ] {
        assert!(
            app.update(action.clone()).is_empty(),
            "{action:?} must not reach the bus"
        );
        assert!(toast(&app).contains(label), "{action:?}: {}", toast(&app));
    }
    // Edit on the paused row: refused at the edit verb itself, by name,
    // before the F5 detail check is even reached.
    app.selected = Some("b".into());
    assert!(app.update(Action::Edit).is_empty());
    assert_eq!(toast(&app), "flow.mutate is not on this bus");
    assert_eq!(app.mode, Mode::Flows);
    // A tool name typed as a command is refused, not sent.
    assert!(app.run_command("flow.list").is_empty());
    assert_eq!(toast(&app), "unknown command `flow.list` (try :help)");
    // The palette holds the built-in commands and the rows, never a tool.
    let _ = app.update(Action::PaletteOpen);
    for c in "fl".chars() {
        let _ = app.update(Action::Input(c));
    }
    let items = app.palette_items();
    assert!(!items.is_empty(), "the built-in commands are still offered");
    assert!(
        items
            .iter()
            .all(|i| !matches!(i.kind, PaletteKind::Tool(_))),
        "no tool on the bus, no tool in the palette: {:?}",
        items.iter().map(|i| &i.label).collect::<Vec<_>>()
    );
    let _ = app.update(Action::Back);
    // Every mode draws, at the design size and in an 80×24 terminal.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for mode in [
        Mode::Flows,
        Mode::Inspector,
        Mode::QuickLook,
        Mode::Scope,
        Mode::Findings,
        Mode::Agent,
        Mode::Ca,
        Mode::Browser,
        Mode::Help,
        Mode::Config,
        Mode::Compose,
        Mode::Prompt(PromptKind::Palette),
        Mode::Prompt(PromptKind::Filter),
        Mode::Prompt(PromptKind::Confirm),
    ] {
        for (c, r) in [(200u16, 50u16), (80, 24)] {
            let mut a = app.clone();
            a.mode = mode;
            let _ = a.update(Action::Resize(c, r));
            match catch_unwind(AssertUnwindSafe(|| text_of(&a, c, r))) {
                Ok(text) if text.lines().count() == usize::from(r) => {}
                Ok(text) => failures.push(format!(
                    "{mode:?} at {c}×{r}: {} lines",
                    text.lines().count()
                )),
                Err(_) => failures.push(format!("{mode:?} at {c}×{r}: panicked")),
            }
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // The inspector on a row without a detail says why, instead of an empty pane.
    app.mode = Mode::Inspector;
    assert!(
        text_of(&app, 200, 50).contains("Headers and bodies need core follow-up F5 (flow.detail)"),
        "{}",
        text_of(&app, 200, 50)
    );
}

/// Tester: a `tools/list` of ten thousand entries — long names, one empty
/// name, one duplicate — is held whole, found by exact name only, drawn in
/// the palette at every size without panicking, and the odd entries neither
/// hide the real tools nor become something that is sent.
#[test]
fn a_ten_thousand_entry_tools_list_with_an_empty_and_a_duplicate_name_still_renders() {
    let mut names: Vec<String> = (0..10_000)
        .map(|i| format!("plugin{:04}.verb-with-a-rather-long-name-{i}", i % 97))
        .collect();
    names.push(String::new());
    names.push("flow.list".into());
    names.push("flow.list".into());
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &refs, Some("127.0.0.1:8080"));
    assert_eq!(app.tools.len(), 10_003, "the list is held whole");
    assert!(app.has_tool("flow.list"));
    assert!(app.has_tool("plugin0000.verb-with-a-rather-long-name-0"));
    assert!(app.has_tool("plugin0008.verb-with-a-rather-long-name-9999"));
    assert!(!app.has_tool("plugin0008"), "a prefix is not a tool");
    assert!(!app.has_tool("flow.lis"), "a prefix is not a tool");
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/a",
        Some(200),
        "observed",
    )]));
    // The palette finds the last entry by a fragment of its name.
    let _ = app.update(Action::PaletteOpen);
    for c in "name-9999".chars() {
        let _ = app.update(Action::Input(c));
    }
    let items = app.palette_items();
    assert!(
        items.iter().any(|i| matches!(
            &i.kind,
            PaletteKind::Tool(t) if t == "plugin0008.verb-with-a-rather-long-name-9999"
        )),
        "{:?}",
        items.iter().map(|i| &i.label).collect::<Vec<_>>()
    );
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (c, r) in [(200u16, 50u16), (80, 24), (80, 6), (41, 5)] {
        let _ = app.update(Action::Resize(c, r));
        match catch_unwind(AssertUnwindSafe(|| text_of(&app, c, r))) {
            Ok(text) => assert_eq!(text.lines().count(), usize::from(r), "{c}×{r}"),
            Err(_) => failures.push(format!("{c}×{r}")),
        }
    }
    std::panic::set_hook(previous_hook);
    assert!(
        failures.is_empty(),
        "the palette over 10 003 tools panics at: {}",
        failures.join(", ")
    );
    let _ = app.update(Action::Resize(200, 50));
    assert!(
        text_of(&app, 200, 50).contains("name-9999"),
        "the match is drawn"
    );
    // An empty prompt line runs nothing; the empty-named entry is not a command.
    let _ = app.update(Action::Back);
    assert!(app.run_command("").is_empty());
    assert_eq!(app.mode, Mode::Flows);
    // The real tool still reaches the bus by name, once.
    assert_eq!(
        app.run_command("flow.list"),
        vec![call("flow.list", json!({}))]
    );
}

// ----------------------------------------------- tester: a bus that drops

/// Tester: the bus drops after the list landed and while two details and
/// two browser calls are outstanding. The rows the operator already has
/// stay listed and selected, the toolbar and status bar say so, the drop
/// itself sends nothing, the browser calls are forgotten, a late answer
/// from the old connection is still folded in, and the reconnect is a new
/// session: a fresh list, and the lost detail is asked for on `Enter`
/// (a poll never re-asks for an existing row — the contract
/// `tools_list_drives_detail_fetching` pins).
#[test]
fn a_bus_drop_after_the_list_landed_keeps_the_rows_and_recovers_on_reconnect() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, None);
    let rows = vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ];
    let reqs = app.on_bus(BusEvent::Flows(rows.clone()));
    assert_eq!(
        reqs,
        vec![
            BusRequest::Detail("a".into()),
            BusRequest::Detail("b".into())
        ]
    );
    app.selected = Some("a".into());
    let _ = app.update(Action::OpenBrowser);
    assert_eq!(app.browser.inflight, 2);
    let _ = app.update(Action::Back);

    let reqs = app.on_bus(BusEvent::Disconnected("connection reset by peer".into()));
    assert!(reqs.is_empty(), "nothing is sent on a dead bus: {reqs:?}");
    assert_eq!(app.flows.len(), 2, "the rows the operator had stay listed");
    assert_eq!(app.selected.as_deref(), Some("a"));
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
    assert_eq!(toast(&app), "bus: connection reset by peer");
    let text = text_of(&app, 200, 50);
    assert!(
        text.lines().next().unwrap().contains("bus disconnected"),
        "{text}"
    );
    assert!(
        text.lines().last().unwrap().contains("bus down · retrying"),
        "{text}"
    );
    assert!(text.contains("https://h.test/a"), "{text}");
    // Keys still work on what is there: moving onto `b`, which has no
    // detail, asks for one as always — the reducer is plain data and the
    // bus task owns delivery; this request dies with the dead connection.
    assert_eq!(
        app.update(Action::Down),
        vec![BusRequest::Detail("b".into())]
    );
    assert_eq!(app.selected.as_deref(), Some("b"));
    // A late detail delivered by the old connection is folded in, not refused.
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http"})).unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    assert!(app.details.contains_key("a"));

    // Reconnect: a new session asks for a fresh list; the toolbar follows
    // the proxy.status the handshake reads.
    let reqs = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    assert_eq!(reqs, vec![BusRequest::Refresh]);
    let text = text_of(&app, 200, 50);
    assert!(
        text.lines()
            .next()
            .unwrap()
            .contains("listening 127.0.0.1:8080"),
        "{text}"
    );
    assert!(!text.contains("bus down"), "{text}");
    // The poll after it: both rows known, `a` loaded; nothing re-asked.
    let reqs = app.on_bus(BusEvent::Flows(rows));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.flows.len(), 2);
    // `b`'s detail was lost to the drop: Enter asks for it.
    assert_eq!(app.selected.as_deref(), Some("b"));
    assert_eq!(
        app.update(Action::Enter),
        vec![BusRequest::Detail("b".into())]
    );
    assert!(text_of(&app, 200, 50).contains("loading detail…"));
}
