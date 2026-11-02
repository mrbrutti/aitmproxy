//! Task 18 (plan 2026-10-31-system-proxy-automation, §D12 / §D14): the
//! listening pill carries the system-proxy word after the address and before
//! the intercept/capture state; the help overlay and the palette name key `s`
//! and `:sysproxy`. Every app here is `App::new` populated by hand — there is
//! no fixture.

mod common;

use aitm_tui::app::{App, BusStatus, Mode, BUILTIN_COMMANDS};
use aitm_tui::caps::TermCaps;
use aitm_tui::model::SystemProxyWord;
use aitm_tui::ui::bars::toolbar;
use common::*;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

/// A connected app that is listening on `127.0.0.1:8080`, system-proxy word
/// unknown yet.
fn listening_app() -> App {
    let mut app = App::new(TermCaps::full(), "test");
    app.bus = BusStatus::Connected {
        server: "aitmproxy test".into(),
        address: "test".into(),
        role: Some("operator".into()),
    };
    app.listening = Some("127.0.0.1:8080".into());
    app.serving = Some(true);
    app
}

fn word(state: &str) -> SystemProxyWord {
    SystemProxyWord {
        state: state.into(),
        supported: true,
        ..SystemProxyWord::default()
    }
}

/// The toolbar row at 160 columns, styles dropped, trailing spaces trimmed.
fn toolbar_text(app: &App) -> String {
    toolbar_at(app, 160)
}

#[test]
fn pill_shows_the_word_table() {
    let mut app = listening_app();

    // `other(h,p)` → the address, then the word.
    app.system_proxy = Some(SystemProxyWord {
        host: Some("127.0.0.1".into()),
        port: Some(9090),
        ..word("other")
    });
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → 127.0.0.1:9090"),
        "other: {t:?}"
    );

    // `points_at_us` → "us".
    app.system_proxy = Some(word("points_at_us"));
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → us"),
        "points_at_us: {t:?}"
    );

    // Our own in-flight set/unset wins over the state.
    app.sysproxy_setting = true;
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy setting…"),
        "setting: {t:?}"
    );
    assert!(!t.contains("→ us"), "setting hides the state word: {t:?}");
    app.sysproxy_setting = false;

    // No verb on this bus → nothing after the address.
    app.system_proxy = None;
    let t = toolbar_text(&app);
    assert!(t.contains("listening 127.0.0.1:8080"), "none: {t:?}");
    assert!(!t.contains("sys-proxy"), "none shows no word: {t:?}");

    // The word sits before the state (`· intercept armed`), not after.
    app.system_proxy = Some(word("points_at_us"));
    app.intercept_armed = true;
    let t = toolbar_text(&app);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → us · intercept armed"),
        "armed: {t:?}"
    );
}

/// The `: palette · layout · b sidebar` hints are a courtesy: at 160 columns
/// they show beside a bare listening pill and yield when a long `other`
/// word would otherwise be clipped against the agent toggle; at 220 columns
/// the same word and the hints both fit, so both render.
#[test]
fn toolbar_hints_yield_to_the_pill_word() {
    let mut app = listening_app();
    let t = toolbar_at(&app, 160);
    assert!(t.contains("listening 127.0.0.1:8080"), "{t:?}");
    assert!(t.contains("b sidebar"), "hints shown without a word: {t:?}");

    // A corporate proxy host drives the yield, not ambient text widths.
    app.system_proxy = Some(SystemProxyWord {
        host: Some("proxy.corp.example.internal".into()),
        port: Some(3128),
        ..word("other")
    });
    let t = toolbar_at(&app, 160);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → proxy.corp.example.internal:3128"),
        "the word is whole: {t:?}"
    );
    assert!(!t.contains("b sidebar"), "hints yielded: {t:?}");
    assert!(t.contains("[⚙ Agent"), "the agent toggle stays: {t:?}");

    // The other direction: wide enough for both, both are present.
    let t = toolbar_at(&app, 220);
    assert!(
        t.contains("listening 127.0.0.1:8080 · sys-proxy → proxy.corp.example.internal:3128"),
        "the word is whole at 220: {t:?}"
    );
    assert!(t.contains("b sidebar"), "hints return at 220: {t:?}");
    assert!(t.contains("[⚙ Agent"), "the agent toggle at 220: {t:?}");
}

#[test]
fn help_overlay_names_key_s_and_keeps_its_footer() {
    let mut app = listening_app();
    app.mode = Mode::Help;
    let text = text_of(&app, 160, 50);
    let line = line_with(
        &text,
        "set / restore the system proxy (:sysproxy on|off|status)",
    )
    .unwrap_or_else(|| panic!("no key s line in:\n{text}"));
    // `key_line` pads the key to ten cells inside the box's left border.
    assert!(
        line.contains("│ s         set / restore the system proxy"),
        "key column: {line:?}"
    );
    // The new line must not push the closing hint off the box.
    assert!(
        text.contains("Any key closes this help."),
        "footer clipped:\n{text}"
    );
}

/// The palette entry's exact tuple; the neighbours' casing ("Set the agent
/// policy", "Open the scope panel") and the bare key in parentheses. The
/// tester's `palette_finds_sysproxy_by_name_and_description_and_enter_shows_usage`
/// drives the same text through the overlay.
#[test]
fn palette_lists_the_sysproxy_command() {
    assert!(
        BUILTIN_COMMANDS.contains(&(
            "sysproxy on|off|status",
            "Set / restore the OS system proxy (s)"
        )),
        "BUILTIN_COMMANDS: {BUILTIN_COMMANDS:?}"
    );
}

/// F-tui 2: `toolbar` adds four widths; a host wide enough to saturate
/// `cells()` must not overflow the sum (a debug-build panic before the fix).
/// The agent toggle and the left cluster still render; the word is clipped.
#[test]
fn toolbar_survives_a_host_that_saturates_the_cell_width() {
    let mut app = listening_app();
    app.system_proxy = Some(SystemProxyWord {
        host: Some("h".repeat(70_000)),
        port: Some(3128),
        ..word("other")
    });
    for cols in [1u16, 80, 150, 160, 240, u16::MAX] {
        let area = Rect::new(0, 0, cols, 1);
        let mut buf = Buffer::empty(area);
        toolbar(&app, &theme(), area, &mut buf);
        let t = to_text(&buf);
        if cols >= 160 {
            assert!(t.contains("aitmproxy"), "left cluster at {cols}: {t:?}");
            assert!(t.contains("[⚙ Agent"), "agent toggle at {cols}: {t:?}");
            assert!(!t.contains("b sidebar"), "hints must yield at {cols}");
        }
    }
}
