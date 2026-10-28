//! Core sync (2026-10-28): the F-gated rows lit up against the real core's
//! shapes — what the operator sees (render) for C1–C12. The model and
//! reducer halves are unit tests in `model.rs` / `app.rs`; the bus halves in
//! `tester_bus_task.rs`.

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode, Pane, REQUEST_TABS, RESPONSE_TABS};
use aitm_tui::caps::TermCaps;
use aitm_tui::fixture_app;
use aitm_tui::model::{Finding, FlowDetail, ProxyStatus};
use common::*;
use serde_json::json;

fn status(listening: bool, capturing: bool) -> ProxyStatus {
    ProxyStatus {
        listening,
        address: Some("127.0.0.1:8080".into()),
        intercept_armed: false,
        capturing,
        paused: 5,
        flows: 3,
    }
}

fn toolbar(app: &App) -> String {
    text_of(app, 200, 50).lines().next().unwrap().to_string()
}

/// C3: the listening pill follows `proxy.status`: the address while serving,
/// `not serving` when the proxy never bound, `capture paused` and the
/// toolbar's `‖ paused` while capture is off; the F7 label only when the
/// bus has no `proxy.status` at all.
#[test]
fn pill_follows_proxy_status() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, PRE_MERGE_TOOLS, None);
    assert!(
        toolbar(&app).contains("listen address unknown (core follow-up F7)"),
        "{}",
        toolbar(&app)
    );
    let _ = connect(&mut app, CORE_TOOLS, None);
    let t = toolbar(&app);
    assert!(t.contains("listen address unknown"), "{t}");
    assert!(
        !t.contains("F7"),
        "the tool exists; nothing to follow up: {t}"
    );
    let _ = app.on_bus(BusEvent::ProxyStatus(status(true, true)));
    let t = toolbar(&app);
    assert!(t.contains("listening 127.0.0.1:8080"), "{t}");
    assert!(t.contains("● rec"), "{t}");
    let _ = app.on_bus(BusEvent::ProxyStatus(status(true, false)));
    let t = toolbar(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · capture paused"),
        "{t}"
    );
    assert!(t.contains("‖ paused"), "{t}");
    let _ = app.on_bus(BusEvent::ProxyStatus(status(false, true)));
    let t = toolbar(&app);
    assert!(t.contains("not serving"), "{t}");
    assert!(!t.contains("listening 127.0.0.1"), "{t}");
}

/// C3: the status bar's paused count is the store's while the list is
/// filtered (the view's count only covers what the filter lets through).
#[test]
fn status_bar_paused_count_prefers_the_store_while_filtered() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", None, "intercepted"),
        summary("b", "POST", "h.test", "/b", Some(200), "observed"),
    ]));
    let status_line = |app: &App| text_of(app, 200, 50).lines().last().unwrap().to_string();
    assert!(
        status_line(&app).contains("· 1 paused"),
        "{}",
        status_line(&app)
    );
    let _ = app.on_bus(BusEvent::ProxyStatus(status(true, true)));
    assert!(
        status_line(&app).contains("· 1 paused"),
        "unfiltered: the view's own count: {}",
        status_line(&app)
    );
    let _ = app.run_command("filter ~m POST");
    assert!(
        status_line(&app).contains("· 5 paused"),
        "filtered: the store's count: {}",
        status_line(&app)
    );
}

/// C8 / C9: the Findings panel lists library entries as not run (no ✓/✗,
/// `r to run`), shows the description under the title and no assertions
/// section for them; run results keep their verdict; the sidebar counts all.
#[test]
fn findings_panel_renders_library_entries_as_not_run_with_their_description() {
    let mut app = fixture_app(200, 50);
    // The sidebar (drawn with the flow list) counts every entry: two runs
    // and the library-only third PoC.
    let shell = text_of(&app, 200, 50);
    let sidebar: String = line_with(&shell, "  Findings")
        .unwrap()
        .chars()
        .take(28)
        .collect();
    assert!(sidebar.ends_with("3│"), "{sidebar:?}");
    let _ = app.update(Action::OpenFindings);
    let text = text_of(&app, 200, 50);
    let xss = line_with(&text, "Reflected XSS in /api/search q").unwrap();
    assert!(xss.contains("✓"), "{xss}");
    let idor = line_with(&text, "IDOR on /api/cart/items/{id}").unwrap();
    assert!(idor.contains("✗"), "{idor}");
    let lib = line_with(&text, "Open redirect via next=").unwrap();
    assert!(!lib.contains('✓') && !lib.contains('✗'), "{lib}");
    assert!(lib.contains("low"), "{lib}");
    assert!(text.contains("· not run · r to run"), "{text}");
    assert!(text.contains("3 findings"), "status bar counts all: {text}");
    // The selected run result shows its assertions and its description.
    assert!(text.contains(" Assertions"), "{text}");
    assert!(
        text.contains("reflected into the results heading without encoding"),
        "description from poc.get: {text}"
    );
    // The library-only entry: description and YAML, no assertions.
    app.finding_cursor = app
        .findings
        .iter()
        .position(|f| f.poc_path == "pocs/open-redirect-next.yaml")
        .expect("the library entry is listed");
    let text = text_of(&app, 200, 50);
    assert!(!text.contains(" Assertions"), "{text}");
    assert!(
        text.contains("next= parameter is followed verbatim"),
        "{text}"
    );
    assert!(
        text.contains(" name: Open redirect via next="),
        "YAML: {text}"
    );
    assert!(text.contains("not run yet"), "{text}");
    // A script finding names its script instead of a PoC file.
    let _ = app.on_bus(BusEvent::ScriptFindings(vec![Finding::from_script_json(
        &json!({"name": "admin write", "severity": "high", "source": "observer",
                "detail": "unauthenticated", "flow_id": "f42", "at": 39904067}),
    )
    .unwrap()]));
    app.finding_cursor = app.findings.len() - 1;
    let text = text_of(&app, 200, 50);
    assert!(text.contains(" script  observer"), "{text}");
    assert!(text.contains("11:05:04.067"), "{text}");
    assert!(text.contains("unauthenticated"), "{text}");
    assert!(!text.contains(" poc     "), "{text}");
}

/// C11: `:config` draws the redacted object, one line per leaf with nested
/// keys joined by `.` and arrays by `, `; without `config.get` it is
/// labelled; Esc leaves.
#[test]
fn config_panel_flattens_the_redacted_object() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, PRE_MERGE_TOOLS, None);
    let _ = app.run_command("config");
    assert_eq!(app.mode, Mode::Config);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("Config — the redacted config.get view"),
        "{text}"
    );
    assert!(
        text.contains("config.get is not on this bus (needs core follow-up F7)"),
        "{text}"
    );
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);

    let _ = connect(&mut app, CORE_TOOLS, None);
    let _ = app.run_command("config");
    assert!(text_of(&app, 200, 50).contains("loading config.get…"));
    let _ = app.on_bus(BusEvent::CallOk {
        name: "config.get".into(),
        value: json!({
            "listen": "127.0.0.1:8080", "ssl_insecure": false, "max_flows": 10000,
            "scope": {"entries": ["a.test", "*.b.test"], "allow_agent_widen": false},
            "mcp": {"transport": "loopback_tcp", "port": 9090},
            "poc_dir": null
        }),
    });
    let text = text_of(&app, 200, 50);
    let line = |key: &str| -> String {
        text.lines()
            .find(|l| l.contains(&format!("│ {key} ")))
            .unwrap_or_else(|| panic!("no line for {key}:\n{text}"))
            .trim_end_matches(['│', ' '])
            .to_string()
    };
    assert!(
        line("listen").ends_with("127.0.0.1:8080"),
        "{}",
        line("listen")
    );
    assert!(line("ssl_insecure").ends_with("false"));
    assert!(line("max_flows").ends_with("10000"));
    assert!(
        line("scope.entries").ends_with("a.test, *.b.test"),
        "{}",
        line("scope.entries")
    );
    assert!(line("scope.allow_agent_widen").ends_with("false"));
    assert!(line("mcp.transport").ends_with("loopback_tcp"));
    assert!(line("mcp.port").ends_with("9090"));
    assert!(line("poc_dir").ends_with("—"), "{}", line("poc_dir"));
    // One value column: every value starts where `listen`'s does.
    let col = col_of(&line("listen"), "127.0.0.1:8080").unwrap();
    assert_eq!(col_of(&line("mcp.port"), "9090"), Some(col));
    assert!(text.contains("read-only · Esc back"), "{text}");
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);
}

/// C11: the scope panel's rate-limit readout comes from `config.get`'s
/// `limits` once fetched; the F7 note stays only for a bus without the tool.
#[test]
fn scope_panel_rate_limits_come_from_config_get() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, PRE_MERGE_TOOLS, None);
    let _ = app.on_bus(BusEvent::Scope(vec!["a.test".into()]));
    let _ = app.update(Action::OpenScope);
    assert!(text_of(&app, 200, 50).contains("readout needs F7, config.get"));
    let _ = app.update(Action::Back);
    let _ = connect(&mut app, CORE_TOOLS, None);
    assert_eq!(
        app.update(Action::OpenScope),
        vec![BusRequest::Call {
            name: "config.get".into(),
            args: json!({})
        }]
    );
    let text = text_of(&app, 200, 50);
    assert!(text.contains("rate limit: loading config.get…"), "{text}");
    let _ = app.on_bus(BusEvent::CallOk {
        name: "config.get".into(),
        value: json!({"limits": {"global_rps": 50, "per_host_rps": 10, "max_concurrency": 8}}),
    });
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("rate limit: 10 rps per host · 50 global · 8 concurrent"),
        "{text}"
    );
    assert!(!text.contains("F7"), "{text}");
}

/// C1: a WebSocket flow's messages draw with the direction arrow from the
/// core's `dir`, the `timestamp` clock and the text; in the inspector's
/// Response Body tab and quick-look.
#[test]
fn websocket_messages_draw_with_arrows_from_the_core_direction() {
    let mut app = fixture_app(200, 50);
    app.selected = Some("f47".into());
    app.mode = Mode::Inspector;
    app.inspector.pane = Pane::Response;
    app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == "Body").unwrap();
    let text = text_of(&app, 200, 50);
    let sub = line_with(&text, "{\"type\":\"subscribe\"").expect("the first message");
    assert!(sub.contains("11:05:05.001 → text"), "{sub}");
    let ack = line_with(&text, "{\"type\":\"ack\"").expect("the reply");
    assert!(ack.contains("11:05:05.040 ← text"), "{ack}");
    assert_eq!(app.row("f47").unwrap().ws_messages, Some(3));
    // An unknown direction is drawn as `?`, never guessed.
    let d = FlowDetail::from_json(&json!({"id":"f47","kind":"websocket","handshake":"f40",
        "messages":[{"dir":"sideways","opcode":"text","data":"aGk=","timestamp":"2026-10-27T11:05:05.001Z"}]}))
    .unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    let text = text_of(&app, 200, 50);
    assert!(line_with(&text, " ? text hi").is_some(), "{text}");
}

/// C2: the Connection tab shows when each side was established; a client
/// connection whose process is null leaves the Client column a dash while
/// the peer stays on the tab.
#[test]
fn connection_tab_shows_established_and_a_null_process_is_a_dash() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    app.scope = vec!["h.test".into()];
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/a",
        Some(200),
        "observed",
    )]));
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http",
        "request":{"method":"GET","scheme":"https","authority":"h.test","path":"/a","version":"HTTP/1.1","headers":[],"body":null,"body_size":7,"body_truncated":false},
        "response":{"status":200,"version":"HTTP/1.1","headers":[],"body":null,"body_size":2048,"body_truncated":false},
        "client_conn":{"peer":"127.0.0.1:51000","sni":"h.test","alpn":"http/1.1","tls":true,"established":"2026-10-27T11:05:04.900Z","process":null},
        "server_conn":{"peer":"203.0.113.9:443","sni":"h.test","alpn":"http/1.1","tls":true,"established":"2026-10-27T11:05:04.950Z"},
        "meta":{"marks":[],"comment":null,"is_replay":false,"created":"2026-10-27T11:05:04.966Z","duration_ms":12,"truncated":false,"edited":false,"origin":null},
        "intercept":"observed","edited":false}))
    .unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    app.selected = Some("a".into());
    let text = text_of(&app, 200, 50);
    let row = line_with(&text, "https://h.test/a").expect("the row");
    assert!(
        row.contains("2.0 KB"),
        "response size from body_size: {row}"
    );
    assert!(row.contains("7 B"), "request size from body_size: {row}");
    assert!(
        !row.contains("127.0.0.1:51000"),
        "the peer is not the client: {row}"
    );
    app.mode = Mode::Inspector;
    app.inspector.pane = Pane::Request;
    app.inspector.request_tab = REQUEST_TABS
        .iter()
        .position(|t| *t == "Connection")
        .unwrap();
    let text = text_of(&app, 200, 50);
    assert!(text.contains("127.0.0.1:51000"), "{text}");
    assert!(
        line_with(&text, "established").is_some_and(|l| l.contains("11:05:04.900")),
        "{text}"
    );
    assert!(text.contains("203.0.113.9:443"), "{text}");
    assert!(
        text.contains("process") && text.contains("— (not resolved by the core yet)"),
        "{text}"
    );
}
