//! Scanner v2 TUI, plan task 3: the wire-confirm overlay generalised from the
//! L4 confirm. One `WireConfirm` type and one `Mode::WireConfirm` overlay serve
//! both the `l4.*` guarded verbs and the `scan.*` launches (spec D3, D7). The
//! title and footnote are chosen by the call name; `n`/`Esc` cancels with the
//! `<call> cancelled` toast and returns to the mode the launch came from.
//!
//! Fixture-driven: this proves the overlay and the cancel path only. Acceptance
//! is the pty cell against a real core (spec Acceptance criteria, "Live").

use aitm_tui::action::{Action, BusEvent, BusRequest};
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
        prompt: "Prompt-7Q verbatim".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;

    let text = screen(&app, 200, 50);
    assert!(
        text.contains("Confirm over the wire: scan launch"),
        "scan launch title: {text}"
    );
    assert!(
        text.contains("Prompt-7Q verbatim"),
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
    app.wire_confirm_from = Mode::Scan;

    let reqs: Vec<BusRequest> = app.update(Action::WireConfirm(false));
    assert!(reqs.is_empty(), "cancel sends nothing: {reqs:?}");
    assert!(app.wire_confirm.is_none(), "the pending confirm is cleared");
    assert_eq!(
        app.mode,
        Mode::Scan,
        "cancel returns to the mode the launch came from"
    );
    assert_eq!(toast(&app), "scan.start cancelled");
}

/// Fix round A, A5: a confirm token is bound to the connection that issued
/// it, so a `Disconnected` while the overlay is up drops the pending confirm,
/// returns to the mode the launch came from and says why; nothing is sent.
#[test]
fn a_disconnect_drops_the_pending_confirm() {
    let mut app = fixture_app_core(200, 50);
    app.wire_confirm = Some(WireConfirm {
        call: "scan.start".into(),
        args: json!({ "profile_name": "l4-stream-safe" }),
        prompt: "Prompt-7Q verbatim".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;
    app.wire_confirm_from = Mode::Scan;

    let reqs = app.on_bus(BusEvent::Disconnected("connection reset".into()));
    assert!(reqs.is_empty(), "a disconnect sends nothing: {reqs:?}");
    assert!(app.wire_confirm.is_none(), "the pending confirm is dropped");
    assert_eq!(
        app.mode,
        Mode::Scan,
        "the overlay closes to the launch mode"
    );
    assert!(
        app.toasts
            .iter()
            .any(|t| t.text == "scan.start confirmation dropped: bus disconnected"),
        "the operator is told why: {:?}",
        app.toasts
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
    );
    let text = screen(&app, 200, 50);
    assert!(
        !text.contains("Confirm over the wire"),
        "the overlay is gone: {text}"
    );
}

/// Fix round C, C3: the token is dropped whatever mode is on screen (an L4
/// confirm pending while the operator looked at the flow list is just as
/// dead after a disconnect); the mode is restored only when the overlay
/// itself was up, so a view the operator is in stays where it is.
#[test]
fn a_disconnect_drops_a_pending_confirm_outside_the_overlay() {
    let mut app = fixture_app_core(200, 50);
    app.wire_confirm = Some(WireConfirm {
        call: "l4.inject".into(),
        args: json!({ "spec": { "layers": [] } }),
        prompt: "P".into(),
        token: "tok-1".into(),
    });
    app.mode = Mode::Flows;
    app.wire_confirm_from = Mode::Inspector;

    let reqs = app.on_bus(BusEvent::Disconnected("connection reset".into()));
    assert!(reqs.is_empty(), "a disconnect sends nothing: {reqs:?}");
    assert_eq!(app.wire_confirm, None, "the pending confirm is dropped");
    assert_eq!(app.mode, Mode::Flows, "the mode the operator is in stays");
    assert_eq!(
        app.toasts
            .iter()
            .filter(|t| t.text == "l4.inject confirmation dropped: bus disconnected")
            .count(),
        1,
        "the operator is told once: {:?}",
        app.toasts
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
    );
}

/// Fix round A, A11 (D13: hue only on data): the overlay's call-name line
/// reads in the accent for a `scan.*` call and in the L4 hue for an `l4.*`
/// call; the two hues differ.
#[test]
fn the_call_name_line_takes_the_hue_of_its_family() {
    let theme = Theme::new(true);
    let accent = theme.accent().fg.expect("accent has a colour");
    let l4 = theme.l4().fg.expect("l4 has a colour");
    assert_ne!(accent, l4, "the two hues are distinct");

    for (call, want) in [("scan.start", accent), ("l4.inject", l4)] {
        let mut app = fixture_app_core(200, 50);
        app.wire_confirm = Some(WireConfirm {
            call: call.into(),
            args: json!({}),
            prompt: "Prompt-7Q verbatim".into(),
            token: "tok-1".into(),
        });
        app.mode = Mode::WireConfirm;
        let buf = render(&app, &theme, 200, 50);
        let text = to_text(&buf);
        let needle = format!(" {call}");
        let (y, line) = text
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(&needle))
            .unwrap_or_else(|| panic!("the call-name line is drawn: {text}"));
        let x = line
            .find(call)
            .map(|b| line[..b].chars().count())
            .expect("column");
        let cell = buf.cell((x as u16, y as u16)).expect("cell");
        assert_eq!(cell.fg, want, "{call}: the call-name hue");
    }
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

/// Fix round G, G55: the prompt is wrapped by cell width, not by character
/// count, so a prompt of wide glyphs never overruns the box.
#[test]
fn the_prompt_wraps_by_cell_width_not_chars() {
    let mut app = fixture_app_core(60, 20);
    // Twelve words of two wide glyphs: 35 chars, which a char count would
    // put on one 48-cell row and clip, but 95 cells, which wrap onto two.
    let prompt = ["日本"; 12].join(" ");
    app.wire_confirm = Some(WireConfirm {
        call: "scan.start".into(),
        args: json!({}),
        prompt,
        token: "tok-1".into(),
    });
    app.mode = Mode::WireConfirm;
    let text = screen(&app, 60, 20);
    // `to_text` writes a wide glyph as the glyph and one pad cell.
    let rows: Vec<&str> = text.lines().filter(|l| l.contains('日')).collect();
    assert_eq!(
        rows.len(),
        2,
        "a prompt wider than the box takes two rows:\n{text}"
    );
    let shown: usize = rows.iter().map(|r| r.matches('日').count()).sum();
    assert_eq!(
        shown, 12,
        "every word is on screen, none clipped away:\n{text}"
    );
    assert_eq!(
        rows[0].matches('日').count(),
        9,
        "nine words fill 44 of 48 cells"
    );
}
