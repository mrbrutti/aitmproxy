//! Scanner v2 TUI, plan task 3: the wire-confirm overlay generalised from the
//! L4 confirm. One `WireConfirm` type and one `Mode::WireConfirm` overlay serve
//! both the `l4.*` guarded verbs and the `scan.*` launches (spec D3, D7). The
//! title and footnote are chosen by the call name; `n`/`Esc` cancels with the
//! `<call> cancelled` toast and returns to the mode the launch came from.
//!
//! Inline-literal driven (the sample app of `common`): this proves the
//! overlay and the cancel path only. Acceptance is the pty cell against a
//! real core (spec Acceptance criteria, "Live").

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::scan::launch::WireConfirm;
use aitm_tui::theme::Theme;
use common::{connect, draw, sample_app, text_of, to_text, toast, CORE_TOOLS};
use serde_json::json;

fn screen(app: &App, cols: u16, rows: u16) -> String {
    text_of(app, cols, rows)
}

/// D7: the title and footnote are picked by the call name (`scan.*` reads the
/// scan-launch wording, `l4.*` the guarded-L4 wording) and the server's prompt
/// is shown verbatim between them.
#[test]
fn the_overlay_titles_and_footnotes_by_call_name() {
    let mut app = sample_app(200, 50);
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
    let mut app = sample_app(200, 50);
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
    let mut app = sample_app(200, 50);
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
    let mut app = sample_app(200, 50);
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
        let mut app = sample_app(200, 50);
        app.wire_confirm = Some(WireConfirm {
            call: call.into(),
            args: json!({}),
            prompt: "Prompt-7Q verbatim".into(),
            token: "tok-1".into(),
        });
        app.mode = Mode::WireConfirm;
        let buf = draw(&app, 200, 50);
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
    let mut app = sample_app(200, 50);
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
    let mut app = sample_app(60, 20);
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

/// The v2 bus the launch cell connects to (fix round H, H18).
const SCAN_TOOLS: &[&str] = &[
    "scan.start",
    "scan.map",
    "scan.list",
    "scan.status",
    "scan.profile.list",
    "scan.profile.get",
    "scan.checks",
    "l4.scope.list",
];

/// Fix round H, H18: the overlay sits over the view the launch came from.
/// A `needs_confirmation` on `scan.start` from Profiles keeps the Scan view
/// (its box title and the tab strip) under the box; the Flows view, which
/// `main_region` would draw, is not on screen.
#[test]
fn a_scan_confirm_draws_over_the_scan_view() {
    let mut app = common::opened_v2(SCAN_TOOLS);
    app.scope = vec!["auth.shop-staging.test".to_string()];
    app.scan.profiles.cursor = 3; // `standard`
    let reqs = app.update(Action::ScanStart);
    assert_eq!(reqs.len(), 1, "one launch leaves: {reqs:?}");
    let reqs = app.on_bus(common::reply(
        "scan.start",
        "scan.start",
        json!({ "status": "needs_confirmation", "prompt": "Prompt-7Q verbatim", "confirm_token": "tok-1" }),
    ));
    assert!(reqs.is_empty(), "{reqs:?}");
    assert_eq!(app.mode, Mode::WireConfirm);
    assert_eq!(app.wire_confirm_from, Mode::Scan);

    let text = screen(&app, 200, 50);
    assert!(
        text.contains("Confirm over the wire: scan launch"),
        "the overlay is up: {text}"
    );
    assert!(
        text.contains(" 1 Profiles "),
        "the Scan tab strip stays under the overlay: {text}"
    );
    assert!(
        text.contains(" Scan "),
        "the Scan box title stays under the overlay: {text}"
    );
    assert!(
        !text.contains("No flows yet"),
        "the Flows view is not drawn under a Scan launch: {text}"
    );
}

/// Fix round H, H18: an L4 confirm raised from the flow list or its
/// inspector still draws the flow list under the box; the Scan view is not
/// pulled in.
#[test]
fn an_l4_confirm_from_flows_still_shows_the_flow_list() {
    for from in [Mode::Flows, Mode::Inspector] {
        let mut app = sample_app(200, 50);
        app.wire_confirm = Some(WireConfirm {
            call: "l4.inject".into(),
            args: json!({ "spec": { "layers": [] } }),
            prompt: "P".into(),
            token: "tok-1".into(),
        });
        app.mode = Mode::WireConfirm;
        app.wire_confirm_from = from;

        let text = screen(&app, 200, 50);
        assert!(
            text.contains("Confirm over the wire: guarded L4 action"),
            "{from:?}: the overlay is up: {text}"
        );
        assert!(
            text.contains("shop-staging.test"),
            "{from:?}: the flow list stays under the overlay: {text}"
        );
        assert!(
            !text.contains(" 1 Profiles "),
            "{from:?}: the Scan view is not drawn under an L4 confirm: {text}"
        );
    }
}

/// A `needs_confirmation` handshake for `scan.start` carrying `prompt`,
/// folded through `WireConfirm::from_reply` (the fold the H34 bound lives
/// in).
fn confirm_for(prompt: String) -> WireConfirm {
    let reply = json!({
        "status": "needs_confirmation",
        "prompt": prompt,
        "confirm_token": "tok-9",
    });
    WireConfirm::from_reply("scan.start", &json!({ "profile_name": "standard" }), &reply)
        .expect("a confirmation handshake")
}

/// Fix round H, H34 (D6 hostile-core bounds): the server's prompt is
/// bounded once, in `WireConfirm::from_reply`, to `PROMPT_MAX` cells with
/// control characters stripped. A 1 MiB prompt of tab-joined words folds
/// to one unit, cut once with an ellipsis and no tab left; nothing is
/// rendered here (fix round H, H69: the fold bound and the box wrap are
/// two tests).
#[test]
fn a_huge_prompt_is_bounded_once_at_fold() {
    use aitm_tui::scan::launch::PROMPT_MAX;
    use aitm_tui::text::width;

    let words = "word\t".repeat(1 << 18);
    assert!(words.len() >= 1 << 20);
    let confirm = confirm_for(words);
    assert!(
        width(&confirm.prompt) <= PROMPT_MAX,
        "{} cells",
        width(&confirm.prompt)
    );
    assert!(confirm.prompt.ends_with('…'), "cut once at fold");
    assert!(!confirm.prompt.contains('\t'), "tabs stripped");
}

/// Fix round H, H34 and H50: a bounded prompt of `PROMPT_MAX` cells of
/// space-separated words needs more rows than the 16-row box holds, so
/// the overlay wraps it to the box's rows only: at 200x50 the cleaned
/// prompt is drawn, the row the box cannot finish ends in an ellipsis,
/// and the `y confirm` key line is the last row drawn inside the box
/// (H50).
#[test]
fn a_prompt_wider_than_the_box_wraps_and_keeps_the_key_line_last() {
    use aitm_tui::scan::launch::PROMPT_MAX;
    use aitm_tui::text::width;

    let spaced = "word ".repeat(1 << 18);
    let confirm = confirm_for(spaced);
    assert!(width(&confirm.prompt) <= PROMPT_MAX);
    let mut app = sample_app(200, 50);
    app.wire_confirm = Some(confirm);
    app.mode = Mode::WireConfirm;
    let text = screen(&app, 200, 50);
    let title = text
        .lines()
        .position(|l| l.contains("Confirm over the wire: scan launch"))
        .expect("the box title");
    let rows: Vec<&str> = text
        .lines()
        .skip(title + 1)
        .take_while(|l| !l.contains('└'))
        .collect();
    assert!(
        rows.iter().any(|l| l.contains("word word word")),
        "the cleaned prompt is drawn: {text}"
    );
    assert!(
        rows.iter()
            .filter(|l| l.contains("word word"))
            .any(|l| l.contains('…')),
        "a prompt the box cannot hold ends in an ellipsis: {text}"
    );
    let key = rows
        .iter()
        .position(|l| l.contains("y confirm (re-issues with _confirm) · n / Esc cancel"))
        .unwrap_or_else(|| panic!("the key line is drawn inside the box: {text}"));
    assert!(
        rows[key + 1..].iter().all(|l| l
            .trim_matches(|c: char| c == '│' || c.is_whitespace())
            .is_empty()),
        "the key line is the last row drawn in the box: {text}"
    );
}

/// L4OPS-AC10, re-homed from the fixture-driven L4 surface suite (T7-5
/// identifiers: `Mode::WireConfirm`, `Action::WireConfirm`): an in-scope
/// inject of a craft flow goes only through `l4.inject`; the server's
/// `needs_confirmation` opens the wire-confirm overlay with the prompt's
/// wire summary (destination, scope entry, permit budget); `y` re-issues
/// the identical call with the reserved `_confirm` token.
#[test]
fn an_l4_inject_shows_the_wire_confirm_and_reissues_with_the_token() {
    let mut tools: Vec<&str> = CORE_TOOLS.to_vec();
    tools.extend(["l4.flow.list", "l4.flow.get", "l4.scope.list", "l4.inject"]);
    let mut app = App::new(TermCaps::full(), "test");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, &tools, None);
    let _ = app.on_bus(BusEvent::L4Scope(vec![json!({
        "interface": "lo0", "capability": "inject",
        "cidr": {"addr": "127.0.0.0", "prefix": 8},
        "ports": {"lo": 0, "hi": 65535}, "direction": "outbound"
    })]));
    let _ = app.on_bus(BusEvent::L4Flows(vec![json!({
        "id": "l4-2", "kind": "craft", "interface": "lo0", "filter": null,
        "queue": null, "packet_count": 0, "injected_count": 0, "packets": []
    })]));
    app.selected = Some("l4-2".into());
    app.mode = Mode::Inspector;
    app.l4.pane = aitm_tui::l4::L4Pane::Craft;

    let reqs = app.update(Action::L4Inject);
    let [BusRequest::Call { name, args }] = reqs.as_slice() else {
        panic!("exactly one call: {reqs:?}");
    };
    assert_eq!(
        name, "l4.inject",
        "inject reaches the wire only via l4.inject"
    );
    assert!(
        args.get("_confirm").is_none(),
        "the probe carries no token: {args}"
    );
    let probe = args.clone();

    let reply = json!({
        "status": "needs_confirmation",
        "prompt": "l4.inject: 1 packet(s) to destination 127.0.0.1 on lo0. Matched scope entry \
                   lo0 127.0.0.0/8 (inject), minted permit budget 10 pps. Confirm?",
        "confirm_token": "tok-1"
    });
    let reqs = app.on_bus(BusEvent::CallOk {
        name: "l4.inject".into(),
        value: reply,
    });
    assert!(
        reqs.is_empty(),
        "the overlay waits for the operator: {reqs:?}"
    );
    assert_eq!(app.mode, Mode::WireConfirm, "the confirm overlay opens");
    assert_eq!(app.wire_confirm_from, Mode::Inspector);
    let text = screen(&app, 200, 50);
    assert!(
        text.contains("Confirm over the wire: guarded L4 action"),
        "guarded L4 title: {text}"
    );
    assert!(text.contains("127.0.0.1"), "destination shown: {text}");
    assert!(
        text.contains("Matched scope entry"),
        "scope entry shown: {text}"
    );
    assert!(
        text.contains("budget 10 pps"),
        "permit budget shown: {text}"
    );

    let reqs = app.update(Action::WireConfirm(true));
    let mut confirmed = probe;
    confirmed["_confirm"] = json!("tok-1");
    assert_eq!(
        reqs,
        vec![BusRequest::Call {
            name: "l4.inject".into(),
            args: confirmed,
        }],
        "re-issued once, identical arguments plus the confirm token"
    );
    assert_eq!(
        app.mode,
        Mode::Inspector,
        "back to the mode the launch came from"
    );
    assert!(
        app.wire_confirm.is_none(),
        "the pending confirm is consumed"
    );
}
