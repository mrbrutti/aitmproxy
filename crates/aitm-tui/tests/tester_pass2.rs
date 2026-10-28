//! Tester (stage 5), pass 2 — regression pins for the pass-1 and panel-1
//! fixes that had state-level tests but no render-level or edge-case test,
//! plus the interaction between the modes added since pass 1 (Browser, Ca,
//! Confirm). Each test names the finding it pins.

mod common;

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use aitm_tui::action::{Action, BusEvent, BusRequest, Level};
use aitm_tui::app::{App, Mode, PromptKind, MAX_DETAILS};
use aitm_tui::caps::TermCaps;
use aitm_tui::filter;
use aitm_tui::keys;
use aitm_tui::model::{Finding, FlowDetail};
use aitm_tui::ui::browser::OUTLINE_MAX;
use aitm_tui::{fixture_app, fixture_app_core};
use common::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

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

/// `(width, height, format, byte count)` of the last screenshot.
fn shot_facts(app: &App) -> Option<(u32, u32, &'static str, usize)> {
    app.browser
        .screenshot
        .as_ref()
        .map(|s| (s.width, s.height, s.format, s.bytes.len()))
}

// ------------------------------------------------------------- S1 / I2

/// S1 / I2 (render): the confirm prompt names the tool, its description and
/// `y/N` on the prompt line, so the operator knows what `y` will do; the
/// answers behave the same whichever way the call was reached.
#[test]
fn confirm_prompt_renders_the_tool_description_and_y_n() {
    let mut app = fixture_app(200, 50);
    assert!(app.run_command("ca.install").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let text = text_of(&app, 200, 50);
    let line = line_with(&text, "confirm: ca.install").expect("prompt line");
    assert!(line.contains("[y/N]"), "{line}");
    assert!(line.contains("y runs it · n / Esc cancels"), "{line}");
    let desc = app.confirm.as_ref().unwrap().description.clone();
    assert!(!desc.is_empty(), "the fixture describes ca.install");
    assert!(
        line.contains(&desc.chars().take(30).collect::<String>()),
        "the description is on the line: {line}"
    );
    // The prompt is also readable on a narrow terminal (hint dropped, prompt kept).
    let _ = app.update(Action::Resize(80, 24));
    let narrow = text_of(&app, 80, 24);
    assert!(
        line_with(&narrow, "confirm: ca.install").is_some(),
        "{narrow}"
    );
    // `Y` (upper case) is a yes too.
    assert_eq!(
        app.update(Action::Input('Y')),
        vec![call("ca.install", json!({}))]
    );
    // Any other character is a no.
    let _ = app.run_command("ca.uninstall");
    assert!(app.update(Action::Input('x')).is_empty());
    assert_eq!(toast(&app), "ca.uninstall cancelled");
    assert!(text_of(&app, 80, 24).contains("ca.uninstall cancelled"));
    // Typed `yes` + Enter runs; typed `no` + Enter cancels. `dry_run` does
    // not skip the prompt while the fixture's `ca.install` schema declares
    // no such parameter (SEC-4): the bus task would prune it and the real
    // call would run.
    let _ = app.run_command("ca.install");
    for c in "yes".chars() {
        let _ = app.update(Action::Input(c));
        if app.mode != Mode::Prompt(PromptKind::Confirm) {
            break;
        }
    }
    // The first typed character already answered (`y`): the call went out.
    assert_eq!(app.mode, Mode::Flows);
    let _ = app.run_command("ca.install");
    assert!(app.update(Action::Input('n')).is_empty());
    assert_eq!(app.mode, Mode::Flows);
    assert!(app.run_command("ca.install dry_run=TRUE").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let _ = app.update(Action::Back);
    assert!(app.run_command("ca.install dry_run=false").is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let _ = app.update(Action::Back);
    // Through the key map: `i` in the CA panel → confirm → `y` → back on the panel.
    let _ = app.run_command("ca");
    assert_eq!(app.mode, Mode::Ca);
    let action = keys::map(press(KeyCode::Char('i')), Mode::Ca).unwrap();
    assert!(app.update(action).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let action = keys::map(press(KeyCode::Char('y')), app.mode).unwrap();
    assert_eq!(app.update(action), vec![call("ca.install", json!({}))]);
    assert_eq!(app.mode, Mode::Ca);
    // A stale confirm with no held call cannot send anything.
    app.mode = Mode::Prompt(PromptKind::Confirm);
    app.confirm = None;
    assert!(app.update(Action::Input('y')).is_empty());
    assert_eq!(app.mode, Mode::Flows);
}

/// I2 (render): the `:ca` panel in each of its states — no `ca.status` on
/// the bus, loading, facts, a non-object reply — and the action hints that
/// name what the bus lacks.
#[test]
fn ca_panel_renders_status_facts_and_its_degraded_states() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(120, 30));
    let no_ca: Vec<&str> = CORE_TOOLS
        .iter()
        .copied()
        .filter(|t| !t.starts_with("ca."))
        .collect();
    let _ = connect(&mut app, &no_ca, None);
    assert!(app.run_command("ca").is_empty());
    assert_eq!(app.mode, Mode::Ca);
    let text = text_of(&app, 120, 30);
    assert!(text.contains("CA — the MITM certificate"), "{text}");
    assert!(text.contains("ca.status is not on this bus."), "{text}");
    assert!(
        text.contains(
            "e export (not on this bus) · i install (not on this bus) · u uninstall (not on this bus) · Esc back"
        ),
        "{text}"
    );
    assert!(
        text.contains("local y/N first: the bus has no confirm step until core follow-up F1"),
        "{text}"
    );
    // `e` with no ca.export says so and stays on the panel.
    assert!(app.update(Action::CaExportPrompt).is_empty());
    assert_eq!(app.mode, Mode::Ca);
    assert_eq!(toast(&app), "ca.export is not on this bus");

    // The core bus: the panel asks and says it is loading.
    let _ = connect(&mut app, CORE_TOOLS, None);
    assert_eq!(app.run_command("ca"), vec![call("ca.status", json!({}))]);
    let text = text_of(&app, 120, 30);
    assert!(text.contains("loading ca.status…"), "{text}");
    assert!(
        text.contains("e export · i install · u uninstall · Esc back"),
        "{text}"
    );
    // Facts, in the reply's order, aligned.
    let reqs = app.on_bus(ok(
        "ca.status",
        json!({"path": "/tmp/ca.pem", "fingerprint": "AB:CD:EF", "installed": false, "expires": null}),
    ));
    assert!(reqs.is_empty());
    let text = text_of(&app, 120, 30);
    for want in [
        "path         /tmp/ca.pem",
        "fingerprint  AB:CD:EF",
        "installed    false",
        "expires      —",
    ] {
        assert!(text.contains(want), "{want:?} missing:\n{text}");
    }
    // A non-object reply is shown verbatim, never silently dropped.
    let _ = app.on_bus(ok("ca.status", json!("installed")));
    assert!(
        text_of(&app, 120, 30).contains("ca.status: \"installed\""),
        "{}",
        text_of(&app, 120, 30)
    );
    let _ = app.on_bus(ok("ca.status", json!({})));
    assert!(text_of(&app, 120, 30).contains("ca.status: {}"));
    // Keys from the panel: `e` opens the export prompt, Esc returns to the panel.
    let _ = app.update(keys::map(press(KeyCode::Char('e')), Mode::Ca).unwrap());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::CaExport));
    assert!(text_of(&app, 120, 30).contains("ca export:"));
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Ca);
    // An install result re-reads the status.
    assert_eq!(
        app.on_bus(ok("ca.install", json!("installed into the login keychain"))),
        vec![call("ca.status", json!({})), BusRequest::Refresh]
    );
    assert_eq!(toast(&app), "ca.install: installed into the login keychain");
    // The panel survives the smallest shell size.
    let _ = app.update(Action::Resize(40, 4));
    let _ = text_of(&app, 40, 4);
    let _ = app.update(Action::Resize(1, 1));
    let _ = text_of(&app, 1, 1);
}

// ---------------------------------------------------------------- C4

/// C4 (render): a finding whose YAML could not be read from `poc_path` says
/// so in the panel; a remote bus explains why it did not try; YAML read from
/// disk is drawn under the `YAML` heading.
#[test]
fn finding_yaml_read_failure_is_shown_in_the_panel() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("aitm-tui-pass2-{}.yaml", std::process::id()));
    std::fs::write(&path, "name: read from disk\nsteps:\n  - get /\n").unwrap();
    let findings = || {
        vec![
            Finding::from_json(
                &json!({"poc_path": "/nonexistent/aitm-tui/pass2.yaml", "passed": false}),
            )
            .unwrap(),
            Finding::from_json(&json!({"poc_path": path.to_string_lossy(), "passed": true}))
                .unwrap(),
        ]
    };
    let mut local = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = local.update(Action::Resize(160, 40));
    let _ = connect(&mut local, CORE_TOOLS, None);
    let _ = local.on_bus(BusEvent::Findings(findings()));
    let _ = local.update(Action::OpenFindings);
    let text = text_of(&local, 160, 40);
    let line = line_with(&text, "yaml not readable:").expect("the failure is on screen");
    assert!(
        line.contains("No such file") || line.contains("os error"),
        "the OS reason is quoted: {line}"
    );
    assert!(
        !text.contains(" YAML"),
        "no YAML heading without YAML: {text}"
    );
    let _ = local.update(Action::Down);
    let text = text_of(&local, 160, 40);
    assert!(text.contains(" YAML"), "{text}");
    assert!(text.contains(" name: read from disk"), "{text}");
    assert!(text.contains("   - get /"), "{text}");

    let mut remote = App::new(TermCaps::full(), "10.0.0.5:9090");
    let _ = remote.update(Action::Resize(160, 40));
    let _ = connect(&mut remote, CORE_TOOLS, None);
    let _ = remote.on_bus(BusEvent::Findings(findings()));
    let _ = remote.update(Action::OpenFindings);
    let text = text_of(&remote, 160, 40);
    assert!(
        text.contains("yaml: not in the result; read from poc_path only on a loopback bus"),
        "{text}"
    );
    assert!(!text.contains("yaml not readable"), "{text}");
    let _ = std::fs::remove_file(&path);
}

// --------------------------------------------- the honest core snapshot

/// `--snapshot-core` (M-misc): against the 22 core tools the screen carries
/// no data that only an F-gated tool could have produced, and every F-gated
/// surface is labelled where the plan says (I1, Q11).
#[test]
fn core_fixture_render_has_no_f_gated_data_and_every_f_label() {
    let mut app = fixture_app_core(200, 50);
    let text = text_of(&app, 200, 50);
    // Labels on the shell.
    for label in [
        "Cookies (F5)",
        "Timing (F5)",
        "Set-Cookie (F5)",
        "Agent · n/a (F1)",
        "↑ — ↓ — (F4)",
        // Two recorded flows are paused, so the bar is the saturated one.
        "[d Kill · abort mode: reset (429/503 need F3)]",
    ] {
        assert!(text.contains(label), "{label:?} missing:\n{text}");
    }
    let sidebar = |needle: &str| -> String {
        line_with(&text, needle)
            .unwrap_or_else(|| panic!("sidebar item {needle:?}"))
            .chars()
            .take(28)
            .collect()
    };
    assert!(
        sidebar("  Agent").ends_with("F1│"),
        "{:?}",
        sidebar("  Agent")
    );
    assert!(
        sidebar("  Saved").ends_with("F10│"),
        "{:?}",
        sidebar("  Saved")
    );
    assert!(
        sidebar("  Scripts").ends_with("M3│"),
        "{:?}",
        sidebar("  Scripts")
    );
    assert!(
        sidebar("  Browser").ends_with("—│"),
        "{:?}",
        sidebar("  Browser")
    );
    assert!(
        sidebar("  Findings").ends_with("F13│"),
        "no poc.list: {:?}",
        sidebar("  Findings")
    );
    // No F5 data in the list: every Duration / Request / Response cell is a
    // dash — no `ms`, no byte counts, no edited pencil, no TLS padlock state.
    let header_y = line_index(&text, "URL").expect("list header");
    let rows: Vec<&str> = text
        .lines()
        .skip(header_y + 1)
        .take_while(|l| l.contains("https://") || l.contains("wss://"))
        .collect();
    assert_eq!(rows.len(), 15, "all 15 recorded flows are listed:\n{text}");
    for row in &rows {
        assert!(!row.contains(" ms"), "duration without flow.detail: {row}");
        for unit in [" B ", " kB", " KB", " MB"] {
            assert!(!row.contains(unit), "size without flow.detail: {row}");
        }
        assert!(
            !row.contains(aitm_tui::tokens::glyph::COMPOSE),
            "edited mark without flow.detail: {row}"
        );
    }
    // The inspector says F5 instead of inventing headers.
    assert!(
        text.contains("Headers and bodies need core follow-up F5 (flow.detail)"),
        "{text}"
    );
    assert!(!text.contains("x-forwarded-for"), "{text}");
    // The status bar's counts are the real ones: no findings, no agent rate.
    // (The in-scope count is pinned by `websocket_rows_on_the_core_bus_…`:
    // today it reads 12 because the WebSocket row has no authority.)
    let status = text.lines().last().unwrap();
    assert!(status.contains("11 / 15 rows · 2 paused · "), "{status}");
    assert!(!status.contains("findings"), "{status}");
    assert!(
        !text.contains("/min"),
        "no agent rate without agent.status: {text}"
    );
    // The same screen in the inspector and the panels.
    let _ = app.update(Action::OpenAgent);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("agent.status is not on this bus (core follow-up F1)"),
        "{text}"
    );
    let _ = app.update(Action::Back);
    let _ = app.update(Action::OpenFindings);
    assert!(text_of(&app, 200, 50).contains("No findings — build a PoC from any flow with P."));
    let _ = app.update(Action::Back);
    let _ = app.update(Action::OpenScope);
    assert!(text_of(&app, 200, 50).contains("readout needs F7, config.get"));
    // And the 100×30 shell the second SVG was taken at.
    let _ = app.update(Action::Back);
    let _ = app.update(Action::Resize(100, 30));
    let text = text_of(&app, 100, 30);
    assert!(
        text.contains("↑ — ↓ — (F4)") || text.contains("11 / 15"),
        "{text}"
    );
}

// ------------------------------------------- findings pinned this pass

/// FINDING P2-F1 (Important, §2.10(c) "never silently", §3.7 tui ✓): the
/// core's `flow.get` summary for a WebSocket flow carries no `authority`,
/// `scheme` or `path` — only `handshake` (the id of the 101 HTTP flow, which
/// is in the same list) and `messages` (`crates/aitm-plugins/src/capture.rs`
/// `summarize`, `Flow::WebSocket` arm). `FlowRow::from_summary` keeps the
/// `handshake` id but nothing resolves it, so on the real bus every
/// WebSocket row reads `wss://`, is counted out of scope (empty authority),
/// and every verb on it is refused with "add `` to scope". The row must take
/// its URL from the handshake row when that row is listed, and a refusal
/// must never name an empty host.
#[test]
fn websocket_rows_on_the_core_bus_take_their_url_from_the_handshake_row() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::Scope(vec!["api.test".into()]));
    let handshake = summary(
        "h1",
        "GET",
        "api.test",
        "/ws/notify?v=2",
        Some(101),
        "observed",
    );
    let ws = json!({"id": "w1", "kind": "websocket", "handshake": "h1", "messages": 3,
                    "is_replay": false, "intercept": "observed"});
    let _ = app.on_bus(BusEvent::Flows(vec![handshake, ws]));
    let row = app.row("w1").expect("the WebSocket row");
    assert_eq!(
        row.authority, "api.test",
        "authority from the handshake row"
    );
    assert_eq!(row.url(), "wss://api.test/ws/notify?v=2");
    assert_eq!(row.ws_messages, Some(3));
    assert!(app.in_scope(row), "the handshake's host is in scope");
    assert_eq!(app.in_scope_count(), 2);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("wss://api.test/ws/notify?v=2"), "{text}");
    assert!(!text.contains("wss:// "), "no bare scheme: {text}");
    // The verbs see an in-scope WebSocket flow: replay is refused for being
    // a WebSocket (F9), not for being out of scope.
    app.selected = Some("w1".into());
    assert!(app.update(Action::Replay).is_empty());
    assert!(toast(&app).contains("F9"), "{}", toast(&app));
    // An `http` handshake gives `ws`.
    let _ = app.on_bus(BusEvent::Flows(vec![
        json!({"id":"h2","kind":"http","method":"GET","scheme":"http","authority":"plain.test:8080","path":"/s","status":101,"intercept":"observed"}),
        json!({"id":"w2","kind":"websocket","handshake":"h2","messages":0,"intercept":"observed"}),
    ]));
    assert_eq!(app.row("w2").unwrap().url(), "ws://plain.test:8080/s");
    // Handshake not listed (evicted or cleared): whatever the row shows, the
    // refusal must not print an empty host.
    let _ = app.on_bus(BusEvent::Flows(vec![
        json!({"id":"w3","kind":"websocket","handshake":"gone","messages":1,"intercept":"observed"}),
    ]));
    app.selected = Some("w3".into());
    let _ = app.update(Action::Replay);
    assert!(
        !toast(&app).contains("``"),
        "empty host named: {}",
        toast(&app)
    );
}

/// FINDING P2-F2 (Minor, §2.8 "missing is —, a real 0 B is 0 B"): the status
/// bar's byte total is `human_bytes(sum of unwrap_or(0))`
/// (`crates/aitm-tui/src/app.rs` `total_bytes`, `ui/bars.rs` status right
/// cluster), so against the core bus — where no size is known without F5 —
/// it reads `0 B`. It must be a dash until at least one size is known.
#[test]
fn status_bar_total_is_a_dash_until_a_size_is_known() {
    let core = fixture_app_core(200, 50);
    assert!(core
        .flows
        .iter()
        .all(|r| r.req_size.is_none() && r.resp_size.is_none()));
    let status = text_of(&core, 200, 50).lines().last().unwrap().to_string();
    assert!(
        status.contains("— ↑ — ↓ — (F4)"),
        "no size is known on the core bus: {status}"
    );
    assert!(!status.contains("0 B ↑"), "{status}");
    // With details, the sum is real; with details whose bodies are all empty,
    // `0 B` is the honest number.
    let full = fixture_app(200, 50);
    let status = text_of(&full, 200, 50).lines().last().unwrap().to_string();
    assert!(!status.contains("— ↑ — ↓ —"), "{status}");
    assert!(!status.contains("0 B ↑"), "{status}");
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

// ------------------------------------------------- browser view edges

/// Task 10 edges: malformed HTML through the bus — unclosed tags, `<` in
/// text, unterminated comments/quotes, 10 000 nested divs — yields a bounded
/// outline that renders and navigates at both plan sizes.
#[test]
fn browser_outline_survives_malformed_html_through_the_app() {
    let mut app = fixture_app(200, 50);
    let reqs = app.update(Action::OpenBrowser);
    assert_eq!(reqs.len(), 2);
    // Unclosed tags, `<` in text, 10 000 nested divs, an unterminated
    // comment, an unterminated script, then an unterminated attribute quote
    // (which, as in a browser, swallows the rest of the document).
    let junk = format!(
        "<html><body>if a < b and c<d then <<<<{}<!-- unterminated comment <div> \
         <script>var s = '<div>';{}</script><p id=\"never closed>text<span class='x",
        "<div>".repeat(10_000),
        "<b>".repeat(50)
    );
    let _ = app.on_bus(ok("browser.get_dom", json!(junk)));
    assert_eq!(app.browser.dom_outline.len(), OUTLINE_MAX);
    assert_eq!(app.browser.dom_outline[0], "html");
    assert_eq!(app.browser.dom_outline[1], "  body");
    assert!(
        app.browser.dom_outline[OUTLINE_MAX - 1].trim_start() == "div",
        "{:?}",
        &app.browser.dom_outline[OUTLINE_MAX - 3..]
    );
    for (c, r) in [(100u16, 30u16), (200, 50), (41, 5), (80, 10)] {
        let _ = app.update(Action::Resize(c, r));
        let text = text_of(&app, c, r);
        if r >= 20 {
            assert!(text.contains("200 elements"), "{c}×{r}: {text}");
        }
        let _ = app.update(Action::End);
        assert_eq!(app.browser.dom_cursor, OUTLINE_MAX - 1);
        let text = text_of(&app, c, r);
        // `c<d then <<<<<div>` scans as an element `d` with junk attributes
        // (a browser does the same), so the path starts `html › body › d`.
        if c >= 100 && r >= 20 {
            assert!(text.contains("html › body › d › div"), "{c}×{r}: {text}");
        }
        let _ = app.update(Action::PageUp);
        let _ = app.update(Action::Home);
        assert_eq!(app.browser.dom_cursor, 0);
        let _ = app.update(Action::PageDown);
        let _ = text_of(&app, c, r);
    }
    // The same document, short enough to reach the tail: the comment, the
    // script body and the unterminated quote are all skipped, nothing after
    // the quote is an element.
    let tail = "<html><body>x<<<<<div><!-- open <div> <script>'<div>'</script><p id=\"never closed>text<span class='x";
    let _ = app.on_bus(ok("browser.get_dom", json!(tail)));
    assert_eq!(app.browser.dom_outline, vec!["html", "  body", "    div"]);
    // Text with `<` but no element; a non-string reply: an empty outline and
    // the panel's empty state, cursor reset.
    let _ = app.on_bus(ok(
        "browser.get_dom",
        json!("a < b && c < d <<<< <!doctype> <?xml?> </p>"),
    ));
    assert!(app.browser.dom_outline.is_empty());
    assert_eq!(app.browser.dom_cursor, 0);
    let _ = app.update(Action::Resize(200, 50));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("no DOM yet — d reads the page"), "{text}");
    let _ = app.update(Action::Down);
    let _ = app.update(Action::End);
    assert_eq!(app.browser.dom_cursor, 0);
    // A non-string reply is stringified and scanned as text: the one tag in
    // the JSON is found, nothing panics.
    let _ = app.on_bus(ok("browser.get_dom", json!({"html": "<p>"})));
    assert_eq!(app.browser.dom_outline, vec!["p"]);
    let _ = app.on_bus(ok("browser.get_dom", json!(null)));
    assert!(app.browser.dom_outline.is_empty());
    // A page of 1 MiB of text with no tags costs well under a frame budget.
    let flat = "x".repeat(1 << 20);
    let t = Instant::now();
    let _ = app.on_bus(ok("browser.get_dom", json!(flat)));
    let d = t.elapsed();
    assert!(d.as_millis() < 250, "1 MiB of text took {d:?}");
    assert!(app.browser.dom_outline.is_empty());
    // Attributes with control characters stay out of the screen.
    let _ = app.on_bus(ok(
        "browser.get_dom",
        json!("<p id=\"a\u{1b}[31mb\" class=\"\u{7}c\">"),
    ));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("p#a[31mb.c"), "{text}");
    assert!(!text.contains('\u{1b}'));
}

/// Task 10 edges: a `browser.screenshot` reply that is not a PNG — other
/// image magic, bytes that are no image, bad base64, a non-string — is
/// labelled honestly and never panics; `o` still hands real bytes over.
#[test]
fn browser_screenshot_of_non_png_bytes_is_labelled_not_trusted() {
    let mut app = fixture_app(200, 50);
    let _ = app.update(Action::OpenBrowser);
    // JPEG magic: format from the bytes, dimensions unknown → no `W×H`.
    let _ = app.on_bus(ok(
        "browser.screenshot",
        json!(aitm_tui::base64::encode(
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
        )),
    ));
    assert_eq!(shot_facts(&app), Some((0, 0, "JPEG", 11)));
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("[screenshot JPEG · 11 B · o to open]"),
        "{text}"
    );
    assert!(!text.contains("0×0"), "{text}");
    // Bytes that are no image at all.
    let _ = app.on_bus(ok(
        "browser.screenshot",
        json!(aitm_tui::base64::encode(b"hello")),
    ));
    assert_eq!(shot_facts(&app), Some((0, 0, "image", 5)));
    assert_eq!(app.browser.error, None);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("[screenshot image · 5 B · o to open]"),
        "{text}"
    );
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("bytes are bytes");
    assert_eq!(std::fs::read(&target.path).unwrap(), b"hello");
    let _ = std::fs::remove_file(&target.path);
    // Bad base64, an empty string, a number, an object: an error in the
    // panel, the previous screenshot kept (no layout shift).
    for bad in [
        json!("!!!not base64!!!"),
        json!(""),
        json!(42),
        json!({"png": "x"}),
    ] {
        let _ = app.update(Action::BrowserScreenshot);
        assert_eq!(app.browser.error, None, "a new call clears the error");
        let _ = app.on_bus(ok("browser.screenshot", bad.clone()));
        assert_eq!(
            app.browser.error.as_deref(),
            Some("browser.screenshot: the result is not image bytes"),
            "{bad}"
        );
        assert_eq!(app.browser.busy, None);
        assert_eq!(shot_facts(&app), Some((0, 0, "image", 5)));
        let text = text_of(&app, 200, 50);
        assert!(
            text.contains("error: browser.screenshot: the result is not image bytes"),
            "{bad}: {text}"
        );
    }
    // A 1×1 PNG with a 4 MiB tail: dimensions read from the header, no copy
    // of the bytes into the screen.
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&1u32.to_be_bytes());
    png.extend_from_slice(&1u32.to_be_bytes());
    png.extend(std::iter::repeat_n(0xAAu8, 4 << 20));
    let t = Instant::now();
    let _ = app.on_bus(ok(
        "browser.screenshot",
        json!(aitm_tui::base64::encode(&png)),
    ));
    let text = text_of(&app, 200, 50);
    let d = t.elapsed();
    // `human_bytes` is decimal: 4 194 328 B → 4.2 MB.
    assert!(
        text.contains("[screenshot 1×1 PNG · 4.2 MB · o to open]"),
        "{text}"
    );
    assert!(!text.contains("\u{aa}"), "no bytes on screen");
    assert!(d.as_secs() < 2, "4 MiB screenshot took {d:?}");
}

/// Task 10 edges: errors while calls are in flight. Two calls out, one
/// fails: the view stays busy for the other and shows the error; a notice
/// that is not a `browser.*` call's failure is not mistaken for the answer;
/// a failed call with nothing in flight is only a toast. (QI-1: a failed
/// call is `CallFailed` naming its tool, so no level/prefix guessing.)
#[test]
fn browser_errors_while_calls_are_in_flight_settle_one_at_a_time() {
    let mut app = fixture_app(200, 50);
    let reqs = app.update(Action::OpenBrowser);
    assert_eq!(reqs.len(), 2);
    assert_eq!(app.browser.inflight, 2);
    // A warning about something else while in flight: not the answer.
    let _ = app.on_bus(BusEvent::Toast(
        Level::Warn,
        "flow.get f50: store hiccup".into(),
    ));
    assert_eq!(app.browser.inflight, 2);
    assert_eq!(app.browser.error, None);
    // Nor is another tool's failure.
    let _ = app.on_bus(failed("flow.resume", "flow is not intercepted"));
    assert_eq!(app.browser.inflight, 2);
    assert_eq!(app.browser.error, None);
    // The first call fails: one left, still busy, error shown.
    let _ = app.on_bus(failed("browser.screenshot", "page crashed"));
    assert_eq!(app.browser.inflight, 1);
    assert_eq!(app.browser.busy, Some("loading the page"));
    assert_eq!(app.browser.error.as_deref(), Some("page crashed"));
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("⟳ loading the page…"),
        "busy wins the line: {text}"
    );
    // The second is answered: idle; the error stays until the next call.
    let _ = app.on_bus(ok("browser.get_dom", json!("<p>")));
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(app.browser.busy, None);
    assert_eq!(app.browser.error.as_deref(), Some("page crashed"));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("error: page crashed"), "{text}");
    assert_eq!(app.browser.dom_outline, vec!["p"]);
    // Nothing in flight: an error toast is not a browser error.
    let _ = app.on_bus(BusEvent::Toast(
        Level::Error,
        "flow is not intercepted".into(),
    ));
    assert_eq!(app.browser.error.as_deref(), Some("page crashed"));
    assert_eq!(app.browser.inflight, 0);
    // The bus task's "not on this bus" for a `browser.*` call while in flight
    // is the answer; `inflight` never underflows past zero on extra failures.
    let _ = app.update(Action::BrowserScreenshot);
    let _ = app.on_bus(failed(
        "browser.screenshot",
        "browser.screenshot is not on this bus",
    ));
    assert_eq!(app.browser.inflight, 0);
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser.screenshot is not on this bus")
    );
    for _ in 0..3 {
        let _ = app.on_bus(failed("browser.get_dom", "late"));
    }
    assert_eq!(app.browser.inflight, 0);
    // A navigate reply with no `final_url` keeps the URL that was asked for;
    // with one, the bus wins; a non-object reply does not lose the URL.
    let reqs = app.run_command("browser.navigate url=https://asked.test/");
    assert_eq!(reqs.len(), 1);
    let reqs = app.on_bus(ok("browser.navigate", json!({})));
    assert_eq!(app.browser.url, "https://asked.test/");
    assert!(
        reqs.iter()
            .any(|r| matches!(r, BusRequest::Call { name, .. } if name == "browser.get_dom")),
        "a navigate re-reads the page: {reqs:?}"
    );
    assert_eq!(app.browser.busy, Some("loading the page"));
    assert_eq!(app.browser.inflight, 2);
    let _ = app.on_bus(ok("browser.get_dom", json!("<html>")));
    let _ = app.on_bus(ok(
        "browser.screenshot",
        json!(aitm_tui::base64::encode(b"x")),
    ));
    assert_eq!(app.browser.inflight, 0);
    let _ = app.run_command("browser.navigate url=https://asked.test/2");
    let _ = app.on_bus(ok(
        "browser.navigate",
        json!({"final_url": "https://landed.test/", "status": 302}),
    ));
    assert_eq!(app.browser.url, "https://landed.test/");
    assert_eq!(toast(&app), "navigated: https://landed.test/ (302)");
    let _ = app.run_command("browser.navigate url=https://asked.test/3");
    let _ = app.on_bus(ok("browser.navigate", json!("weird")));
    assert_eq!(app.browser.url, "https://asked.test/3");
    // An eval reply of any JSON shape is text in the panel; a multi-line one
    // shows its first line and the count.
    for (value, want) in [
        (json!(null), "eval › null"),
        (json!(3.5), "eval › 3.5"),
        (json!([1, 2]), "eval › [1,2]"),
        (json!("l1\nl2\nl3"), "eval › l1 (+2 lines)"),
    ] {
        let _ = app.run_command("browser.eval expr=x");
        let _ = app.on_bus(ok("browser.eval", value));
        let text = text_of(&app, 200, 50);
        assert!(text.contains(want), "{want:?}:\n{text}");
    }
}

// --------------------------------------------------- random interaction

/// Every key in every mode, including the modes added since pass 1
/// (Browser, Ca, Confirm and the new prompts), driven by a 3 000-step
/// deterministic walk at 100×30 and at 200×50 with resizes, bus events and
/// panel entries injected along the way. No step may panic, and the walk
/// must actually have visited the new modes.
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
    let mut app = fixture_app(cols, rows);
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

// ----------------------------------------------------- I3 regex limits

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
    let mut app = fixture_app(200, 50);
    let before = visible_ids(&app);
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

// ------------------------------------------------- S3 / Q1 at the edge

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

/// M-misc (render): `A` with an out-of-scope paused flow puts the skip count
/// in the status bar, and the bar's verbs still target the in-scope one.
#[test]
fn resume_all_skip_toast_is_on_screen_and_the_bar_still_targets_in_scope() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(160, 40));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    let _ = app.on_bus(BusEvent::Scope(vec!["in.test".into()]));
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("o1", "GET", "out.test", "/o", None, "intercepted"),
        summary("i1", "POST", "in.test", "/i", None, "intercepted"),
        summary("o2", "GET", "out.test", "/o2", None, "intercepted"),
    ]));
    let action = keys::map(press(KeyCode::Char('A')), Mode::Flows).unwrap();
    assert_eq!(action, Action::ResumeAll);
    assert_eq!(app.update(action), vec![BusRequest::Resume("i1".into())]);
    let text = text_of(&app, 160, 40);
    assert!(
        text.contains("Resume all: 1 resumed, 2 skipped — out of scope"),
        "{text}"
    );
    // `a` on the oldest (out of scope) is refused with the host; the bar
    // still shows 3 paused.
    app.selected = Some("o1".into());
    assert!(app.update(Action::Resume).is_empty());
    assert_eq!(toast(&app), "Out of scope — add `out.test` to scope to act");
    assert!(text_of(&app, 160, 40).contains("3 paused"));
    // All out of scope: nothing sent, 0 resumed.
    let _ = app.on_bus(BusEvent::Scope(vec![]));
    assert!(app.update(Action::ResumeAll).is_empty());
    assert_eq!(
        toast(&app),
        "Resume all: 0 resumed, 3 skipped — out of scope (add their hosts to scope to act)"
    );
}
