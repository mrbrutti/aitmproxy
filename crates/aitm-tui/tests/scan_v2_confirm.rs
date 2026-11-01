//! Scanner v2 TUI, plan task 3: the wire-confirm overlay generalised from the
//! L4 confirm. One `WireConfirm` type and one `Mode::WireConfirm` overlay serve
//! both the `l4.*` guarded verbs and the `scan.*` launches (spec D3, D7). The
//! title and footnote are chosen by the call name; `n`/`Esc` cancels with the
//! `<call> cancelled` toast and returns to the mode the launch came from.
//!
//! Fixture-driven: this proves the overlay and the cancel path only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

use aitm_tui::action::{Action, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::fixture_app_core;
use aitm_tui::scan::launch::WireConfirm;
use aitm_tui::snapshot::{render, to_text};
use aitm_tui::theme::Theme;
use serde_json::json;

fn screen(app: &App, cols: u16, rows: u16) -> String {
    to_text(&render(app, &Theme::new(true), cols, rows))
}

fn toast(app: &App) -> &str {
    app.current_toast()
        .map_or("<no toast>", |t| t.text.as_str())
}

/// D7: the title and footnote are picked by the call name — `scan.*` reads the
/// scan-launch wording, `l4.*` the guarded-L4 wording — and the server's prompt
/// is shown verbatim between them.
#[test]
fn the_overlay_titles_and_footnotes_by_call_name() {
    let mut app = fixture_app_core(200, 50);
    app.wire_confirm = Some(WireConfirm {
        call: "scan.start".into(),
        args: json!({ "profile_name": "l4-stream-safe" }),
        prompt: "P".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;

    let text = screen(&app, 200, 50);
    assert!(
        text.contains("Confirm over the wire: scan launch"),
        "scan launch title: {text}"
    );
    assert!(
        text.lines().any(|l| l.contains(" P")),
        "the prompt is shown verbatim: {text}"
    );
    assert!(
        text.contains("Confirming starts the job now; x in Jobs cancels it at any time."),
        "scan footnote: {text}"
    );

    app.wire_confirm = Some(WireConfirm {
        call: "l4.inject".into(),
        args: json!({ "spec": { "layers": [] } }),
        prompt: "P".into(),
        token: "tok-1".into(),
    });
    let text = screen(&app, 200, 50);
    assert!(
        text.contains("Confirm over the wire: guarded L4 action"),
        "guarded L4 title: {text}"
    );
    assert!(
        text.contains("This reaches the wire only through l4.inject"),
        "L4 footnote: {text}"
    );
}

/// D7: `n` cancels, toasting `<call> cancelled`, clearing the pending confirm
/// and returning to the mode the launch came from, and sends nothing.
#[test]
fn n_cancels_with_the_call_name() {
    let mut app = fixture_app_core(200, 50);
    app.wire_confirm = Some(WireConfirm {
        call: "scan.start".into(),
        args: json!({ "profile_name": "l4-stream-safe" }),
        prompt: "P".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;

    let reqs: Vec<BusRequest> = app.update(Action::WireConfirm(false));
    assert!(reqs.is_empty(), "cancel sends nothing: {reqs:?}");
    assert!(app.wire_confirm.is_none(), "the pending confirm is cleared");
    assert_eq!(
        app.mode, app.wire_confirm_from,
        "cancel returns to the launch mode"
    );
    assert_eq!(toast(&app), "scan.start cancelled");
}

/// The box is centred and fits both the narrow and the wide layout without
/// panicking, and the title is drawn exactly once at each width.
#[test]
fn the_box_fits_both_widths() {
    let mut app = fixture_app_core(200, 50);
    app.wire_confirm = Some(WireConfirm {
        call: "scan.start".into(),
        args: json!({ "profile_name": "l4-stream-safe" }),
        prompt: "This scan sends malformed traffic and may disrupt the target. Continue?".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;

    for (cols, rows) in [(90u16, 40u16), (200, 50)] {
        let text = screen(&app, cols, rows);
        let count = text.matches("Confirm over the wire: scan launch").count();
        assert_eq!(count, 1, "the title appears once at {cols}x{rows}: {text}");
    }
}
