//! Coder (stage 4), panel pass 2 fix task — one test per finding, written
//! red before the fix. Each test names the finding it covers.

mod common;

use std::path::Path;

use aitm_tui::action::{Action, BusEvent, BusRequest, Level, ToolInfo};
use aitm_tui::app::{App, Mode, PromptKind, SidebarItem};
use aitm_tui::caps::TermCaps;
use aitm_tui::model::Finding;
use aitm_tui::{fixture_app, fixture_app_core, CORE_TOOLS};
use common::*;
use serde_json::json;

fn call(name: &str, args: serde_json::Value) -> BusRequest {
    BusRequest::Call {
        name: name.into(),
        args,
    }
}

fn failed(name: &str, message: &str) -> BusEvent {
    BusEvent::CallFailed {
        name: name.into(),
        message: message.into(),
    }
}

// ------------------------------------------------------------------ QI-1

/// QI-1: an error toast about something else while a `browser.*` call is in
/// flight is not that call's answer — the view stays busy and shows no
/// error; only a `CallFailed` naming a `browser.*` tool settles it.
#[test]
fn an_unrelated_error_toast_does_not_settle_an_in_flight_browser_call() {
    let mut app = fixture_app(200, 50);
    let _ = connect(&mut app, CORE_TOOLS, None);
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
    let mut app = fixture_app(200, 50);
    let _ = connect(&mut app, CORE_TOOLS, None);
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

// ----------------------------------------------------------------- P2-F1

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

/// P2-F1 (fixture): the recorded bus lists f47's handshake `f40`, so the
/// honest core snapshot shows the WebSocket row with its URL and in scope.
#[test]
fn the_core_fixture_lists_the_websocket_handshake_so_the_ws_row_has_a_url() {
    let app = fixture_app_core(200, 50);
    let f40 = app.row("f40").expect("the handshake flow is listed");
    assert_eq!(f40.method, "GET");
    assert_eq!(f40.status, Some(101));
    assert_eq!(f40.url(), "https://api.shop-staging.test/ws/notifications");
    let f47 = app.row("f47").expect("the WebSocket flow");
    assert_eq!(f47.handshake.as_deref(), Some("f40"));
    assert_eq!(f47.url(), "wss://api.shop-staging.test/ws/notifications");
    assert!(app.in_scope(f47));
    assert_eq!(app.in_scope_count(), 14, "15 flows, f44 out of scope");
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("wss://api.shop-staging.test/ws/notifications"),
        "{text}"
    );
    assert!(!text.contains("wss:// "), "{text}");
}

// ----------------------------------------------------------------- SEC-1

/// SEC-1: `poc_path` is read only when it names a regular `.yaml`/`.yml`
/// file of at most 256 KiB; anything else is a `yaml_error`. YAML already
/// read (or already failed) is carried forward by `poc_path` on the next
/// `poc.list` pass, so the panel does not re-read every file every 18 s.
#[test]
fn finding_yaml_is_read_only_from_small_regular_yaml_files_and_is_carried_forward() {
    let dir = std::env::temp_dir().join(format!("aitm-tui-fix-pass2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.yaml");
    std::fs::write(&good, "name: ok\n").unwrap();
    let not_yaml = dir.join("notes.txt");
    std::fs::write(&not_yaml, "name: txt\n").unwrap();
    let big = dir.join("big.yml");
    std::fs::write(&big, "x".repeat(256 * 1024 + 1)).unwrap();
    let subdir = dir.join("dir.yaml");
    std::fs::create_dir_all(&subdir).unwrap();
    let finding = |p: &Path| {
        Finding::from_json(&json!({"poc_path": p.to_string_lossy(), "passed": true})).unwrap()
    };

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

// ----------------------------------------------------------------- SEC-2

/// SEC-2: Findings `o` opens the screenshot by its canonical path; a path
/// that does not resolve opens nothing and says why.
#[test]
fn findings_o_canonicalizes_the_screenshot_path_and_refuses_one_that_does_not_resolve() {
    let mut app = fixture_app(200, 50);
    let _ = app.update(Action::OpenFindings);
    app.finding_cursor = 0;
    assert_eq!(
        app.findings[0].screenshot_path.as_deref(),
        Some("pocs/reflected-xss-search.png"),
        "the fixture's relative path does not exist here"
    );
    let _ = app.update(Action::OpenExternally);
    assert!(app.take_open_target().is_none(), "nothing to open");
    assert!(toast(&app).starts_with("open: "), "{}", toast(&app));

    let dir = std::env::temp_dir().join(format!("aitm-tui-fix-pass2-shot-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    let shot = dir.join("shot.png");
    std::fs::write(&shot, b"\x89PNG\r\n\x1a\n").unwrap();
    let dotted = dir.join("sub").join("..").join("shot.png");
    app.findings[0].screenshot_path = Some(dotted.to_string_lossy().into_owned());
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("an existing file opens");
    assert_eq!(target.path, std::fs::canonicalize(&shot).unwrap());
    assert!(!target.path.components().any(|c| c.as_os_str() == ".."));
    assert_eq!(target.label, "screenshot");
    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------- SEC-4

/// SEC-4: `dry_run` skips the local confirm only when the tool's schema
/// declares it and the value is the JSON boolean `true`; a tool without
/// the parameter (today's `ca.install`) always asks.
#[test]
fn dry_run_bypasses_the_confirm_only_as_a_declared_boolean_true() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = connect(&mut app, CORE_TOOLS, None);
    // The fixture-shaped schema has no `dry_run`: the prompt opens anyway.
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

// ------------------------------------------------------------------ SP-1

/// SP-1: today's TCP bus has no `proxy.status`, so the core-only fixture app
/// has no listening address and the pill says F7; the full fixture keeps it.
#[test]
fn the_core_only_fixture_app_has_no_listening_address_and_the_pill_says_f7() {
    let core = fixture_app_core(200, 50);
    assert_eq!(core.listening, None);
    let toolbar = text_of(&core, 200, 50).lines().next().unwrap().to_string();
    assert!(
        toolbar.contains("listen address unknown (core follow-up F7)"),
        "{toolbar}"
    );
    assert!(!toolbar.contains("listening 127.0.0.1:8080"), "{toolbar}");
    assert_eq!(
        fixture_app(200, 50).listening.as_deref(),
        Some("127.0.0.1:8080")
    );
}

// ------------------------------------------------------------------ SP-2

/// SP-2: the Findings sidebar item reads `F13` while the bus has no
/// `poc.list` and nothing ran this session; `0` only when the list exists
/// and is empty; the count once there is anything to count.
#[test]
fn the_findings_sidebar_item_says_f13_without_poc_list_and_0_only_with_an_empty_list() {
    let item = |app: &App| -> String {
        line_with(&text_of(app, 200, 50), "  Findings")
            .expect("the sidebar item")
            .chars()
            .take(28)
            .collect()
    };
    let mut core = fixture_app_core(200, 50);
    assert!(item(&core).ends_with("F13│"), "{:?}", item(&core));
    // A run this session is counted even without poc.list.
    let _ = core.on_bus(BusEvent::CallOk {
        name: "poc.run".into(),
        value: json!({"poc_path": "pocs/x.yaml", "passed": true}),
    });
    assert!(item(&core).ends_with("1│"), "{:?}", item(&core));

    let mut with_list: Vec<&str> = CORE_TOOLS.to_vec();
    with_list.push("poc.list");
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &with_list, None);
    assert!(item(&app).ends_with("0│"), "{:?}", item(&app));
    let _ = app.on_bus(BusEvent::Findings(vec![]));
    assert!(item(&app).ends_with("0│"), "{:?}", item(&app));
    let full = fixture_app(200, 50);
    assert!(item(&full).ends_with("2│"), "{:?}", item(&full));
}

// ------------------------------------------------------------------- Q-1

/// Q-1: the CA panel's `i`/`u` on a bus without the CA plugin name the
/// missing tool, not "unknown command".
#[test]
fn ca_panel_install_without_the_ca_plugin_names_the_missing_tool() {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let no_ca: Vec<&str> = CORE_TOOLS
        .iter()
        .copied()
        .filter(|t| !t.starts_with("ca."))
        .collect();
    let _ = connect(&mut app, &no_ca, None);
    let _ = app.run_command("ca");
    assert_eq!(app.mode, Mode::Ca);
    let i = aitm_tui::keys::map(press(crossterm::event::KeyCode::Char('i')), Mode::Ca).unwrap();
    assert!(app.update(i).is_empty());
    assert_eq!(app.mode, Mode::Ca);
    assert_eq!(
        toast(&app),
        "ca.install is not on this bus (needs the CA plugin)"
    );
    let u = aitm_tui::keys::map(press(crossterm::event::KeyCode::Char('u')), Mode::Ca).unwrap();
    assert!(app.update(u).is_empty());
    assert_eq!(
        toast(&app),
        "ca.uninstall is not on this bus (needs the CA plugin)"
    );
    // Not a typed command: the string pseudo-commands are gone.
    assert!(app.run_command("browser-dom").is_empty());
    assert_eq!(toast(&app), "unknown command `browser-dom` (try :help)");
}

// ------------------------------------------------------------------- Q-2

/// Q-2: Esc and Enter from every prompt land in the same mode — the one the
/// prompt was opened from (ScopeAdd → Scope, CaExport → Ca, the browser
/// prompts → Browser, the PoC run prompts → Findings, Confirm → where the
/// call was made, everything else → Flows).
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
        let mut app = fixture_app(200, 50);
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
        let mut app = fixture_app(200, 50);
        open(&mut app, kind);
        let _ = app.update(Action::Back);
        assert_eq!(app.mode, home, "Esc from {kind:?}");
        open(&mut app, kind);
        let _ = app.update(Action::Submit);
        assert_eq!(app.mode, Mode::Prompt(next), "Enter from {kind:?}");
    }
    // Confirm: Enter on the blank line is a "no", like Esc — nothing is sent.
    let mut app = fixture_app(200, 50);
    open(&mut app, PromptKind::Confirm);
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(toast(&app), "ca.install cancelled");
}
