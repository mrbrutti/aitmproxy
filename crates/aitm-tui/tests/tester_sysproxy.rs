//! Tester additions (stage 5, plan 2026-10-31-system-proxy-automation, PR 2,
//! Tasks 16–18; spec §D12 / §D14, SP-AC26). The coder's `sysproxy_pill.rs`
//! and the `app.rs` / `model.rs` unit tests pin the happy path; this file
//! pins the edges a bus client must survive: the core's own `setting` flag,
//! a poll landing while our call is in flight, degenerate and malformed
//! `system_proxy` objects and replies, cross-verb errors, command-line
//! spelling, the key table's neighbours, the palette as the operator reaches
//! it, and the toolbar at every width. Every app is `App::new` populated by
//! hand: there is no fixture.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use aitm_tui::action::{Action, BusEvent, BusRequest, Level};
use aitm_tui::app::{App, BusStatus, Mode, PaletteKind, PromptKind};
use aitm_tui::caps::TermCaps;
use aitm_tui::keys;
use aitm_tui::model::{ProxyStatus, SystemProxyWord};
use common::*;
use crossterm::event::KeyCode;
use serde_json::{json, Value};

const VERBS: &[&str] = &[
    "proxy.system.set",
    "proxy.system.unset",
    "proxy.system.status",
];
const GATE_TOAST: &str = "System proxy needs the core's proxy.system.* verbs";
const USAGE_TOAST: &str = "usage: :sysproxy on|off|status";

// ------------------------------------------------------------------ helpers

/// A connected operator bus that is listening on `127.0.0.1:8080`, with the
/// three `proxy.system.*` verbs offered; no system-proxy word yet.
fn listening_app() -> App {
    let mut app = App::new(TermCaps::full(), "test");
    app.bus = BusStatus::Connected {
        server: "aitmproxy test".into(),
        address: "test".into(),
        role: Some("operator".into()),
    };
    app.listening = Some("127.0.0.1:8080".into());
    app.serving = Some(true);
    app.tools.extend(tools(VERBS));
    app
}

fn word(state: &str) -> SystemProxyWord {
    SystemProxyWord {
        state: state.into(),
        supported: true,
        ..SystemProxyWord::default()
    }
}

fn other(host: &str, port: u16) -> SystemProxyWord {
    SystemProxyWord {
        host: Some(host.into()),
        port: Some(port),
        ..word("other")
    }
}

fn call(name: &str) -> BusRequest {
    BusRequest::Call {
        name: name.into(),
        args: json!({}),
    }
}

fn ok(name: &str, value: Value) -> BusEvent {
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

/// A `proxy.status` poll carrying `system_proxy`.
fn poll(system_proxy: Value) -> BusEvent {
    BusEvent::ProxyStatus(ProxyStatus::from_json(&json!({
        "listening": true, "address": "127.0.0.1:8080", "capturing": true,
        "system_proxy": system_proxy
    })))
}

fn toolbar_text(app: &App) -> String {
    toolbar_at(app, 160)
}

fn last_toast(app: &App) -> (Level, &str) {
    let t = app.current_toast().expect("a toast");
    (t.level, t.text.as_str())
}

// --------------------------------------------------- §D12 words, placement

/// §D12/§D14: the word sits between the address and `· capture paused` too
/// (the coder pinned only `· intercept armed`); `off` and `needs_privilege`
/// reach the toolbar; and the full frame (not just the bare `toolbar`
/// call) shows the word.
#[test]
fn pill_word_sits_before_capture_paused_and_reaches_the_full_frame() {
    let mut app = listening_app();
    app.capture_paused = true;
    app.system_proxy = Some(word("points_at_us"));
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → us · capture paused"),
        "paused: {t:?}"
    );
    let frame = text_of(&app, 160, 40);
    assert!(
        frame.contains("· sys-proxy → us · capture paused"),
        "full frame lacks the word:\n{frame}"
    );

    app.capture_paused = false;
    app.system_proxy = Some(word("off"));
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy off"),
        "off: {t:?}"
    );
    assert!(!t.contains("· intercept armed") && !t.contains("· capture paused"));

    app.system_proxy = Some(word("needs_privilege"));
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy needs admin"),
        "needs_privilege: {t:?}"
    );

    // `unsupported` and `unknown` render nothing, with or without a state.
    for state in ["unsupported", "unknown"] {
        app.system_proxy = Some(word(state));
        app.intercept_armed = true;
        let t = toolbar_text(&app);
        assert!(
            t.contains("listening 127.0.0.1:8080 · intercept armed"),
            "{state}: {t:?}"
        );
        assert!(!t.contains("sys-proxy"), "{state} shows a word: {t:?}");
    }
}

/// §D6/§D12: the core's own `setting: true` (another client's call) reads
/// `setting…` with no in-flight flag of ours; and a poll that lands while
/// our call is in flight keeps `setting…` until our reply settles it.
#[test]
fn core_setting_flag_and_a_poll_during_our_flight_both_read_setting() {
    let mut app = listening_app();
    let _ = app.on_bus(poll(json!({
        "state": "points_at_us", "host": null, "port": null,
        "managed_by_us": true, "setting": true, "supported": true, "detail": "d"
    })));
    assert!(!app.sysproxy_setting, "the core's flag is not ours");
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy setting…"),
        "core setting: {t:?}"
    );
    assert!(!t.contains("→ us"), "{t:?}");

    // The core's flag drops; the state word returns on the next poll.
    let _ = app.on_bus(poll(
        json!({"state": "off", "setting": false, "supported": true}),
    ));
    assert!(toolbar_text(&app).contains("· sys-proxy off"));

    // Our own `on`; a poll with the still-old state arrives before the reply.
    assert_eq!(
        app.run_command(":sysproxy on"),
        vec![call("proxy.system.set")]
    );
    let _ = app.on_bus(poll(
        json!({"state": "off", "setting": false, "supported": true}),
    ));
    assert!(app.sysproxy_setting, "a poll does not settle our flight");
    let t = toolbar_text(&app);
    assert!(t.contains("· sys-proxy setting…"), "poll mid-flight: {t:?}");
    assert!(!t.contains("· sys-proxy off"), "{t:?}");

    // The reply settles it and the word follows the reply.
    let _ = app.on_bus(ok(
        "proxy.system.set",
        json!({"state": "points_at_us", "managed_by_us": true, "supported": true,
               "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)"}),
    ));
    assert!(!app.sysproxy_setting);
    assert!(toolbar_text(&app).contains("· sys-proxy → us"));
}

/// Degenerate `other` objects (no host, no port, a port outside u16, a
/// non-string state, an empty object, a wrongly-cased state) render nothing
/// rather than a half word; non-object `system_proxy` values parse to `None`.
#[test]
fn degenerate_words_render_nothing() {
    let mut app = listening_app();
    let cases: Vec<(&str, Value)> = vec![
        (
            "other without host",
            json!({"state":"other","port":9090,"supported":true}),
        ),
        (
            "other without port",
            json!({"state":"other","host":"127.0.0.1","supported":true}),
        ),
        (
            "port > u16",
            json!({"state":"other","host":"127.0.0.1","port":70000,"supported":true}),
        ),
        (
            "negative port",
            json!({"state":"other","host":"127.0.0.1","port":-1,"supported":true}),
        ),
        (
            "string port",
            json!({"state":"other","host":"127.0.0.1","port":"9090","supported":true}),
        ),
        ("numeric state", json!({"state":42,"supported":true})),
        ("empty object", json!({})),
        (
            "wrong case",
            json!({"state":"OTHER","host":"127.0.0.1","port":9090}),
        ),
        (
            "points_at_us spelled with a space",
            json!({"state":"points at us"}),
        ),
    ];
    for (name, v) in cases {
        let _ = app.on_bus(poll(v.clone()));
        assert!(
            app.system_proxy.is_some(),
            "{name}: an object always parses (it is the pill that declines)"
        );
        let t = toolbar_text(&app);
        assert!(t.contains("listening 127.0.0.1:8080"), "{name}: {t:?}");
        assert!(!t.contains("sys-proxy"), "{name} renders a word: {t:?}");
    }
    for (name, v) in [
        ("null", json!(null)),
        ("array", json!([])),
        ("string", json!("off")),
        ("bool", json!(true)),
        ("number", json!(1)),
    ] {
        let _ = app.on_bus(poll(v));
        assert_eq!(app.system_proxy, None, "{name}");
        assert!(!toolbar_text(&app).contains("sys-proxy"), "{name}");
    }
}

/// Nothing a core (or the OS proxy setting another process wrote) can put
/// in `host` may panic the toolbar, at any width; and from the hints
/// threshold up, the `other` word is whole beside `· intercept armed`.
#[test]
fn toolbar_with_the_word_never_panics_and_is_whole_from_150_cols() {
    let hosts = [
        "127.0.0.1",
        "fe80::1234:5678:9abc:def0%en0",
        "proxy.corp.example.internal.very.long.name.that.keeps.going.example",
        "",
        "a\tb",
        "a\nb",
        "☃☃☃☃☃☃☃☃",
        "\u{200b}\u{feff}zero-width",
        "\u{7f}\u{1b}[31mred",
    ];
    let mut words: Vec<SystemProxyWord> = hosts.iter().map(|h| other(h, 65535)).collect();
    words.extend(["points_at_us", "off", "needs_privilege", "unknown"].map(word));
    let mut failures = Vec::new();
    for w in &words {
        for setting in [false, true] {
            for armed in [false, true] {
                let mut app = listening_app();
                app.system_proxy = Some(w.clone());
                app.sysproxy_setting = setting;
                app.intercept_armed = armed;
                for cols in 1..=240u16 {
                    if catch_unwind(AssertUnwindSafe(|| toolbar_at(&app, cols))).is_err() {
                        failures.push(format!(
                            "{:?} setting={setting} armed={armed} at {cols}",
                            w.host
                        ));
                    }
                }
                for (c, r) in [(40u16, 4u16), (80, 24), (120, 30), (150, 40), (200, 50)] {
                    let _ = app.update(Action::Resize(c, r));
                    if catch_unwind(AssertUnwindSafe(|| text_of(&app, c, r))).is_err() {
                        failures.push(format!("{:?} frame at {c}×{r}", w.host));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "toolbar panics: {}",
        failures.join("; ")
    );

    let mut app = listening_app();
    app.system_proxy = Some(other("127.0.0.1", 9090));
    app.intercept_armed = true;
    for cols in 150..=240u16 {
        let t = toolbar_at(&app, cols);
        assert!(
            t.contains("listening 127.0.0.1:8080 · sys-proxy → 127.0.0.1:9090 · intercept armed"),
            "clipped at {cols}: {t:?}"
        );
        assert!(t.contains("[⚙ Agent"), "agent toggle lost at {cols}: {t:?}");
    }
}

// ------------------------------------------------------ replies and errors

/// A malformed `proxy.system.set`/`unset` reply (null, array, string, no
/// `detail`, non-string or empty `detail`) still settles the in-flight flag,
/// never panics, keeps the last good word when the reply is not an object,
/// and toasts the `<verb>: ok` fallback.
#[test]
fn malformed_set_replies_settle_the_flag_and_fall_back_to_verb_ok() {
    let mut app = listening_app();
    app.system_proxy = Some(word("off"));
    for (name, v) in [
        ("null", json!(null)),
        ("array", json!([1, 2])),
        ("string", json!("done")),
        ("number", json!(0)),
    ] {
        assert_eq!(
            app.run_command(":sysproxy on"),
            vec![call("proxy.system.set")]
        );
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(ok("proxy.system.set", v));
        assert!(!app.sysproxy_setting, "{name}: flag stuck");
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("off"),
            "{name}: a non-object reply must not clobber the word"
        );
        assert_eq!(
            last_toast(&app),
            (Level::Info, "proxy.system.set: ok"),
            "{name}"
        );
        assert!(!toolbar_text(&app).contains("setting…"), "{name}");
    }

    // An object without a usable `detail`: flag settles, fallback toast.
    for (name, v) in [
        (
            "no detail",
            json!({"state": "points_at_us", "supported": true}),
        ),
        (
            "empty detail",
            json!({"state": "points_at_us", "detail": ""}),
        ),
        (
            "numeric detail",
            json!({"state": "points_at_us", "detail": 7}),
        ),
        (
            "null detail",
            json!({"state": "points_at_us", "detail": null}),
        ),
    ] {
        let _ = app.run_command(":sysproxy off");
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(ok("proxy.system.unset", v));
        assert!(!app.sysproxy_setting, "{name}: flag stuck");
        assert_eq!(
            last_toast(&app),
            (Level::Info, "proxy.system.unset: ok"),
            "{name}"
        );
        assert_eq!(
            app.system_proxy.as_ref().map(|w| w.state.as_str()),
            Some("points_at_us"),
            "{name}: the object's state is taken"
        );
    }

    // An empty object settles the flag and shows no half word.
    let _ = app.run_command(":sysproxy on");
    let _ = app.on_bus(ok("proxy.system.set", json!({})));
    assert!(!app.sysproxy_setting);
    let t = toolbar_text(&app);
    assert!(
        !t.contains("setting…") && !t.contains("sys-proxy → :"),
        "{t:?}"
    );

    // `status` with a malformed reply never touches the flag.
    let _ = app.run_command(":sysproxy on");
    assert!(app.sysproxy_setting);
    let _ = app.on_bus(ok("proxy.system.status", json!(null)));
    assert!(
        app.sysproxy_setting,
        "a status reply is not our set's reply"
    );
    assert_eq!(last_toast(&app), (Level::Info, "proxy.system.status: ok"));
}

/// §D14: a bus error for `set`/`unset` settles the flag and is verbatim:
/// but an error for `proxy.system.status` or for an unrelated verb that
/// lands mid-flight must not fake-settle the pill.
#[test]
fn only_set_and_unset_errors_settle_the_flight() {
    let mut app = listening_app();
    app.system_proxy = Some(word("off"));
    let _ = app.run_command(":sysproxy on");
    assert!(app.sysproxy_setting);

    let _ = app.on_bus(failed("proxy.system.status", "status: executor timed out"));
    assert!(
        app.sysproxy_setting,
        "a status failure is not our set's reply"
    );
    assert_eq!(
        last_toast(&app),
        (Level::Error, "status: executor timed out")
    );

    let _ = app.on_bus(failed("flow.clear", "nope"));
    assert!(
        app.sysproxy_setting,
        "an unrelated error must not settle it"
    );

    let _ = app.on_bus(failed(
        "proxy.system.set",
        "a system-proxy change is already in flight",
    ));
    assert!(!app.sysproxy_setting);
    assert_eq!(
        last_toast(&app),
        (Level::Error, "a system-proxy change is already in flight")
    );
    assert_eq!(
        app.system_proxy.as_ref().map(|w| w.state.as_str()),
        Some("off"),
        "an error keeps the last polled word"
    );
    assert!(toolbar_text(&app).contains("· sys-proxy off"));

    // The refusal wording of an agent-token bus (§D14 "shown verbatim"),
    // including odd whitespace and an empty message. A toast is stored
    // with its control characters stripped (scanner v2 fix round H, H47:
    // `App::toast` bounds every toast once with `text::cut_to`), so the
    // newline of the last message is gone and nothing else changes.
    for msg in [
        "proxy.system.unset is operator-only",
        "  leading and trailing  ",
        "",
        "multi\nline",
    ] {
        let _ = app.run_command(":sysproxy off");
        assert!(app.sysproxy_setting);
        let _ = app.on_bus(failed("proxy.system.unset", msg));
        assert!(!app.sysproxy_setting, "{msg:?}");
        let shown = aitm_tui::text::clean(msg);
        assert_eq!(last_toast(&app), (Level::Error, shown.as_str()), "{msg:?}");
    }
}

// ----------------------------------------------------------- command line

/// `:sysproxy` spelling: surrounding and inner whitespace is forgiven, the
/// colon is optional (the palette runs the bare line), a trailing word or a
/// different case is a usage error with no call and no flag, and the gate
/// hangs on `proxy.system.set` alone (§D14).
#[test]
fn sysproxy_command_line_edges() {
    let mut app = listening_app();
    assert_eq!(
        app.run_command("  :sysproxy   on  "),
        vec![call("proxy.system.set")]
    );
    app.sysproxy_setting = false;
    assert_eq!(
        app.run_command("sysproxy off"),
        vec![call("proxy.system.unset")]
    );
    app.sysproxy_setting = false;

    for bad in [
        ":sysproxy on now",
        ":sysproxy ON",
        ":sysproxy Off",
        ":sysproxy toggle",
        ":sysproxy on|off|status",
        ":sysproxy :on",
    ] {
        app.toasts.clear();
        assert!(app.run_command(bad).is_empty(), "{bad}");
        assert!(!app.sysproxy_setting, "{bad} raised the flag");
        assert_eq!(last_toast(&app), (Level::Error, USAGE_TOAST), "{bad}");
    }

    // The gate is `proxy.system.set` alone: a core that offers only `set`
    // still gets `status` and `off`; one that offers only `status` gets
    // the warning for all three.
    let mut set_only = App::new(TermCaps::full(), "test");
    set_only.tools.extend(tools(&["proxy.system.set"]));
    assert_eq!(
        set_only.run_command(":sysproxy status"),
        vec![call("proxy.system.status")]
    );
    assert_eq!(
        set_only.run_command(":sysproxy off"),
        vec![call("proxy.system.unset")]
    );
    let mut status_only = App::new(TermCaps::full(), "test");
    status_only.tools.extend(tools(&["proxy.system.status"]));
    for line in [":sysproxy on", ":sysproxy off", ":sysproxy status"] {
        assert!(status_only.run_command(line).is_empty(), "{line}");
        assert_eq!(
            last_toast(&status_only),
            (Level::Warn, GATE_TOAST),
            "{line}"
        );
    }
    // The usage error wins over the gate: a bad form on a bare bus is a
    // usage toast, not the verbs warning.
    let mut bare = App::new(TermCaps::full(), "test");
    assert!(bare.run_command(":sysproxy sideways").is_empty());
    assert_eq!(last_toast(&bare), (Level::Error, USAGE_TOAST));
}

// ------------------------------------------------------------------- keys

/// `s` is `ToggleSysProxy` in the flow list only; `S` is still the scope
/// panel, and `s` in the inspector, the help
/// overlay and the prompts is something else (text, close, …).
#[test]
fn key_s_is_flows_only_and_its_neighbours_are_untouched() {
    let s = press(KeyCode::Char('s'));
    assert_eq!(keys::map(s, Mode::Flows), Some(Action::ToggleSysProxy));
    assert_eq!(
        keys::map(press(KeyCode::Char('S')), Mode::Flows),
        Some(Action::OpenScope),
        "capital S must stay the scope panel"
    );
    // Ctrl-S is not asserted: `flows()` ignores `ctrl` for every plain
    // letter (`l`, `t` alike), so Ctrl-S toggles too: the table's existing
    // convention, recorded in the tester report, not this task's defect.
    for mode in [
        Mode::Inspector,
        Mode::QuickLook,
        Mode::Edit,
        Mode::Compose,
        Mode::Scope,
        Mode::Findings,
        Mode::Agent,
        Mode::Ca,
        Mode::Browser,
        Mode::Scan,
        Mode::Config,
        Mode::Help,
        Mode::Prompt(PromptKind::Palette),
        Mode::Prompt(PromptKind::Filter),
    ] {
        assert_ne!(
            keys::map(s, mode),
            Some(Action::ToggleSysProxy),
            "s toggles the system proxy in {mode:?}"
        );
    }
    assert_eq!(
        keys::map(press(KeyCode::Char('s')), Mode::Prompt(PromptKind::Palette)),
        Some(Action::Input('s')),
        "typing `s` in the palette is text"
    );

    // Key → reducer → bus, end to end, on a connected operator bus.
    let mut app = listening_app();
    app.system_proxy = Some(other("127.0.0.1", 9090));
    let action = keys::map(s, app.mode).expect("mapped");
    assert_eq!(app.update(action), vec![call("proxy.system.set")]);
    assert!(toolbar_text(&app).contains("· sys-proxy setting…"));
}

// ---------------------------------------------------------------- palette

/// The palette as the operator reaches it: `:` then typing finds the entry
/// by name and by its description, the overlay draws it, and Enter on the
/// bare word shows the usage line rather than firing a call.
#[test]
fn palette_finds_sysproxy_by_name_and_description_and_enter_shows_usage() {
    let mut app = listening_app();
    let _ = app.update(Action::Resize(160, 40));
    let _ = app.update(Action::PaletteOpen);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Palette));
    for c in "sysproxy".chars() {
        let _ = app.update(Action::Input(c));
    }
    let items = app.palette_items();
    let first = items.first().expect("a match");
    assert_eq!(first.label, ":sysproxy on|off|status");
    assert_eq!(first.detail, "Set / restore the OS system proxy (s)");
    assert_eq!(
        first.kind,
        PaletteKind::Command("sysproxy on|off|status".into())
    );
    let text = text_of(&app, 160, 40);
    let line = line_with(&text, ":sysproxy on|off|status")
        .unwrap_or_else(|| panic!("palette overlay lacks the entry:\n{text}"));
    assert!(
        line.contains("Set / restore the OS system proxy (s)"),
        "{line:?}"
    );

    // Enter on the bare word runs `sysproxy` → the usage toast, no call.
    let reqs = app.update(Action::Submit);
    assert!(reqs.is_empty(), "{reqs:?}");
    assert!(!app.sysproxy_setting);
    assert_eq!(last_toast(&app), (Level::Error, USAGE_TOAST));
    assert_eq!(app.mode, Mode::Flows);

    // By description, and by the key hint.
    for q in ["system proxy", "(s)", "restore"] {
        app.prompt = q.into();
        assert!(
            app.palette_items()
                .iter()
                .any(|i| i.label == ":sysproxy on|off|status"),
            "query {q:?} misses the entry"
        );
    }
    // A full form typed in the palette fires the call.
    app.prompt.clear();
    let _ = app.update(Action::PaletteOpen);
    for c in "sysproxy on".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(app.update(Action::Submit), vec![call("proxy.system.set")]);
    assert!(app.sysproxy_setting);
}

// ------------------------------------------------------------------- help

/// The help overlay keeps the `s` line in key order (after `b / l / t`,
/// before `y / o`) at every size, and its footer: drawn at once where the
/// box fits (160x50), reached with `End` on a terminal too short for the
/// whole overlay (the help scrolls since fix round G, G85).
#[test]
fn help_overlay_orders_the_s_line_and_keeps_its_footer() {
    let mut app = listening_app();
    for (c, r) in [(100u16, 37u16), (120, 40), (160, 50)] {
        app.mode = Mode::Help;
        app.help_scroll = 0;
        let text = text_of(&app, c, r);
        let blt = line_index(&text, "toggle sidebar · layout below/right · auto-select")
            .unwrap_or_else(|| panic!("no b/l/t line at {c}×{r}:\n{text}"));
        let s = line_index(
            &text,
            "set / restore the system proxy (:sysproxy on|off|status)",
        )
        .unwrap_or_else(|| panic!("no s line at {c}×{r}:\n{text}"));
        let yo = line_index(&text, "copy URL (OSC 52)")
            .unwrap_or_else(|| panic!("no y/o line at {c}×{r}:\n{text}"));
        assert!(
            blt < s && s < yo,
            "order at {c}×{r}: b/l/t={blt} s={s} y/o={yo}"
        );
        let _ = app.update(Action::Resize(c, r));
        let _ = app.update(Action::End);
        let end = text_of(&app, c, r);
        assert!(
            end.contains("any other key closes this help."),
            "footer unreachable at {c}×{r}:\n{end}"
        );
        if r >= 50 {
            assert!(
                text.contains("any other key closes this help."),
                "footer clipped at {c}×{r}:\n{text}"
            );
        }
    }
}
