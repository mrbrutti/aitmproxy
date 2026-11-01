//! Scanner v2 TUI, plan task 10: the Profiles tab's model and reducer (spec
//! D3, D6, D8, D10, D11, D13).
//!
//! Entering Profiles the first time reads `scan.profile.list {}` and
//! `scan.checks {}`; `Enter` on a row reads `scan.profile.get {name}` and the
//! reply opens the editor over the typed `ScanProfile`; an observed session
//! with an origin reads `scan.session.preview {target}` and the session line
//! shows names only; the check tree writes exactly one selector per toggle;
//! `e` cycles, toggles or prompts by field kind; `w` on a builtin asks for a
//! name and sends the serialised draft; `D` goes through the confirm prompt;
//! hostile replies are bounded at fold.
//!
//! Fixture-driven: this proves the reducer and the model only. Acceptance is
//! the pty cell against a real core (spec Acceptance criteria, "Live").

mod common;

use aitm_scan_model::{
    Intensity, L4TargetSpec, L4Transport, LaneKind, ScanProfile, SessionMode, UseBrowser,
};
use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode, PromptKind};
use aitm_tui::caps::TermCaps;
use aitm_tui::keys;
use aitm_tui::scan::{
    parse_l4_target, session_line, tree_nodes, tri_state, EditorField, L4TargetError, OriginSource,
    ProfilePane, ScanTab, TriState, BUILTIN_MARK, CHECKS_MAX, COLLAPSED_MARK, EDITING_MARK,
    EDITOR_FIELDS, L4_TARGET_ERROR, OPEN_MARK, ORIGIN_HOST_ERROR, ORIGIN_SCHEME_ERROR,
    PROFILES_MAX, SELECTOR_MAX, VALUE_MAX,
};
use aitm_tui::ui::selection_bg;
use common::*;
use crossterm::event::KeyCode;
use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.profile.list",
    "scan.profile.get",
    "scan.profile.save",
    "scan.profile.delete",
    "scan.checks",
    "scan.session.preview",
];

const ORIGIN: &str = "http://127.0.0.1:8080";
const SESSION_LINE: &str = "session: observed · sid, authorization (names) · canary GET /account";

/// A connected v2 app at 200x50, still on Flows: nothing scan-related has
/// been asked yet.
fn connected() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    app
}

/// [`opened_v2`] on this suite's tools, with the fixture counts asserted.
fn app() -> App {
    let app = opened_v2(TOOLS);
    assert_eq!(
        app.scan.profiles.list.len(),
        7,
        "the seven fixture profiles"
    );
    assert_eq!(
        app.scan.profiles.checks.len(),
        3,
        "the three fixture checks"
    );
    assert!(
        app.scan.inflight.is_empty(),
        "nothing in flight at the start: {:?}",
        app.scan.inflight
    );
    app
}

/// Open the `standard` editor the way the operator does: cursor on row 3,
/// `Enter`, the `scan.profile.get.json` reply.
fn open_standard(app: &mut App) {
    app.scan.profiles.cursor = 3;
    assert_eq!(app.scan.profiles.list[3].name, "standard");
    let reqs = app.update(Action::Enter);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.profile.get:standard",
            "scan.profile.get",
            json!({ "name": "standard" })
        )],
        "Enter on a row reads the profile under its keyed tag"
    );
    let reqs = app.on_bus(reply(
        "scan.profile.get:standard",
        "scan.profile.get",
        fixture("scan.profile.get.json"),
    ));
    assert!(
        reqs.is_empty(),
        "no origin yet, so no session preview is read: {reqs:?}"
    );
    let editor = app
        .scan
        .profiles
        .editor
        .as_ref()
        .expect("the editor opened");
    assert_eq!(editor.draft.name, "standard");
    assert!(editor.builtin, "standard is a builtin");
    assert!(!editor.dirty, "freshly loaded");
    assert_eq!(editor.loaded_from.as_deref(), Some("standard"));
    assert_eq!(
        app.scan.profiles.pane,
        ProfilePane::Fields,
        "the editor opens with the Fields pane focused"
    );
}

/// Put the Fields cursor on `field`.
fn focus_field(app: &mut App, field: EditorField) {
    app.scan.profiles.pane = ProfilePane::Fields;
    let idx = EDITOR_FIELDS
        .iter()
        .position(|f| *f == field)
        .expect("a D3 field");
    app.scan.profiles.editor.as_mut().expect("an editor").field = idx;
}

/// Put the Checks cursor on the tree node whose selector is `selector`.
fn focus_node(app: &mut App, selector: &str) {
    app.scan.profiles.pane = ProfilePane::Checks;
    let idx = app
        .scan
        .profiles
        .rows()
        .position(|n| n.selector == selector)
        .unwrap_or_else(|| {
            let tree: Vec<_> = app.scan.profiles.rows().collect();
            panic!("no node {selector:?} in {tree:?}")
        });
    app.scan
        .profiles
        .editor
        .as_mut()
        .expect("an editor")
        .tree_cursor = idx;
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        let _ = app.update(Action::Input(c));
    }
}

/// The pane segment (between box or pane rules) of the first row carrying
/// `needle`, trimmed, so a test pins the row as drawn (fix round G, G60).
fn row_text(text: &str, needle: &str) -> String {
    let line = line_with(text, needle).unwrap_or_else(|| panic!("no row with {needle:?}:\n{text}"));
    line.split('│')
        .find(|seg| seg.contains(needle))
        .expect("the needle's pane")
        .trim()
        .to_string()
}

/// The Profiles keys of spec D11 and plan task 10, in `Mode::Scan`. `Right`
/// stays `Enter` (`tests/scan_surface.rs` pins it for the legacy point
/// list); `l` is the expand key the tree gets instead.
#[test]
fn profiles_keys_map_to_their_actions() {
    for (code, want) in [
        (KeyCode::Char('e'), Action::ScanEdit),
        (KeyCode::Char(' '), Action::ScanToggle),
        (KeyCode::Char('w'), Action::ScanSave),
        (KeyCode::Char('D'), Action::ScanDelete),
        (KeyCode::Char('N'), Action::ScanNewProfile),
        (KeyCode::Char('o'), Action::ScanOriginPrompt),
        (KeyCode::Char('a'), Action::ScanOriginAdd),
        (KeyCode::Char('d'), Action::ScanOriginRemove),
        (KeyCode::Char('t'), Action::ScanL4TargetPrompt),
        (KeyCode::Char('h'), Action::Left),
        (KeyCode::Left, Action::Left),
        (KeyCode::Char('l'), Action::Right),
        (KeyCode::Right, Action::Enter),
    ] {
        assert_eq!(keys::map(press(code), Mode::Scan), Some(want), "{code:?}");
    }
    for kind in [
        PromptKind::ScanOrigin,
        PromptKind::ScanField,
        PromptKind::ScanProfileName,
        PromptKind::ScanL4Target,
    ] {
        assert_eq!(
            keys::map(press(KeyCode::Char('x')), Mode::Prompt(kind)),
            Some(Action::Input('x')),
            "{kind:?} takes text"
        );
        assert_eq!(
            keys::map(press(KeyCode::Enter), Mode::Prompt(kind)),
            Some(Action::Submit)
        );
    }
}

/// D6: entering Profiles the first time reads the list and the check
/// catalogue; a second entry reads nothing (the tags are in flight, then
/// the panes are filled).
#[test]
fn entering_profiles_fetches_list_and_checks_once() {
    let mut app = connected();
    assert_eq!(
        app.update(Action::ScanTab(ScanTab::Profiles)),
        vec![
            tagged("scan.profile.list", "scan.profile.list", json!({})),
            tagged("scan.checks", "scan.checks", json!({})),
        ]
    );
    assert!(
        app.update(Action::ScanTab(ScanTab::Profiles)).is_empty(),
        "both tags are in flight"
    );
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        fixture("scan.profile.list.json"),
    ));
    let _ = app.on_bus(reply(
        "scan.checks",
        "scan.checks",
        fixture("scan.checks.json"),
    ));
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    assert!(
        app.update(Action::ScanTab(ScanTab::Profiles)).is_empty(),
        "a populated tab is not re-read on entry"
    );
    let open = app.update(Action::OpenScan);
    assert_eq!(
        open,
        vec![tagged("scan.list", "scan.list", json!({}))],
        "opening the view later lists the jobs only"
    );
    assert_eq!(
        app.scan.profiles.list[3].name, "standard",
        "the fixture folded in order"
    );
    assert!(app.scan.profiles.list[3].builtin);
}

/// D6, D10, D11: `Enter` on a row reads the profile; the reply opens the
/// editor; a typed origin (`o`) joins the draft and, the session being
/// observed, reads `scan.session.preview {target}`; the session line is
/// built from names only (never a value, D7).
#[test]
fn enter_on_a_row_opens_the_editor_and_previews_the_session() {
    let mut app = app();
    open_standard(&mut app);
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));

    let _ = app.update(Action::ScanOriginPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanOrigin));
    type_text(&mut app, ORIGIN);
    let reqs = app.update(Action::Submit);
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.session.preview:{ORIGIN}"),
            "scan.session.preview",
            json!({ "target": ORIGIN })
        )],
        "an observed session with its first origin reads the preview"
    );
    assert_eq!(app.mode, Mode::Scan, "the prompt closed");
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(editor.draft.target.origins, vec![ORIGIN.to_string()]);
    assert!(editor.dirty, "adding an origin dirties the draft");
    assert!(
        editor
            .origin_choices
            .iter()
            .any(|c| c.origin == ORIGIN && c.source == OriginSource::Typed),
        "the typed origin is a picker row: {:?}",
        editor.origin_choices
    );
    let before = session_line(editor, &app.scan.profiles.previews);
    assert!(
        before.starts_with("session: observed"),
        "no preview yet: {before:?}"
    );
    assert_ne!(before, SESSION_LINE);

    let _ = app.on_bus(reply(
        &format!("scan.session.preview:{ORIGIN}"),
        "scan.session.preview",
        fixture("scan.session.preview.json"),
    ));
    assert!(app.scan.inflight.is_empty());
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    let line = session_line(editor, &app.scan.profiles.previews);
    assert_eq!(line, SESSION_LINE);
    assert!(!line.contains('='), "names only, never a value: {line:?}");

    // A second typed origin is not the first, so no second preview; the
    // same origin twice is not added twice.
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, ORIGIN);
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .target
            .origins,
        vec![ORIGIN.to_string()]
    );

    // An origin outside the scope is refused with the D8 toast and nothing
    // reaches the wire or the draft.
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, "https://evil.test");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(
        toast(&app),
        "Out of scope: add `evil.test` to scope to scan it"
    );
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .target
            .origins,
        vec![ORIGIN.to_string()]
    );

    // A session set to none reads no preview and says so.
    let _ = app.update(Action::Back);
    focus_field(&mut app, EditorField::SessionMode);
    let _ = app.update(Action::ScanEdit);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(editor.draft.session.mode, SessionMode::None);
    assert_eq!(
        session_line(editor, &app.scan.profiles.previews),
        "session: none"
    );
}

/// D3, T7-11: a toggle writes exactly the node's own selector. Two toggles
/// on `http.sqli-error` land on Exclude with nothing in `include`; one on
/// the `sqli-error` class writes the bare class; one on the `http` lane
/// writes `lane:http`. `tri_state` reads each back.
#[test]
fn check_tree_toggles_write_exactly_the_selectors() {
    let mut app = app();
    open_standard(&mut app);
    let tree: Vec<_> = app.scan.profiles.rows().collect();
    let selectors: Vec<&str> = tree.iter().map(|n| n.selector.as_str()).collect();
    assert_eq!(
        selectors,
        vec![
            "lane:http",
            "information-disclosure",
            "http.custom-marker",
            "reflected-xss",
            "http.reflected-xss",
            "sqli-error",
            "http.sqli-error",
        ],
        "lane, then classes in name order, then their checks: {tree:?}"
    );
    assert_eq!(tree[0].depth, 0);
    assert_eq!(tree[1].depth, 1);
    assert_eq!(tree[2].depth, 2);
    assert_eq!(tree[2].id(), Some("http.custom-marker"));
    assert_eq!(tree[1].id(), None);
    assert_eq!(tree[0].label(), "http");
    assert_eq!(tree[6].label(), "http.sqli-error");

    focus_node(&mut app, "http.sqli-error");
    let _ = app.update(Action::ScanToggle);
    {
        let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
        assert_eq!(draft.checks.include, vec!["http.sqli-error".to_string()]);
        assert_eq!(
            tri_state(&draft.checks, "http.sqli-error"),
            TriState::Include
        );
    }
    let _ = app.update(Action::ScanToggle);
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        assert!(editor.draft.checks.include.is_empty());
        assert_eq!(
            editor.draft.checks.exclude,
            vec!["http.sqli-error".to_string()]
        );
        assert_eq!(
            tri_state(&editor.draft.checks, "http.sqli-error"),
            TriState::Exclude
        );
        assert!(editor.dirty);
    }

    focus_node(&mut app, "sqli-error");
    let _ = app.update(Action::ScanToggle);
    {
        let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
        assert_eq!(draft.checks.include, vec!["sqli-error".to_string()]);
        assert_eq!(
            draft.checks.exclude,
            vec!["http.sqli-error".to_string()],
            "the class toggle touches no other entry"
        );
        assert_eq!(tri_state(&draft.checks, "sqli-error"), TriState::Include);
        assert_eq!(
            tri_state(&draft.checks, "http.reflected-xss"),
            TriState::Default
        );
    }

    focus_node(&mut app, "lane:http");
    let _ = app.update(Action::ScanToggle);
    {
        let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
        assert_eq!(
            draft.checks.include,
            vec!["sqli-error".to_string(), "lane:http".to_string()]
        );
    }

    // A third toggle on the leaf returns it to Default, removing the one
    // selector it wrote.
    focus_node(&mut app, "http.sqli-error");
    let _ = app.update(Action::ScanToggle);
    {
        let draft = &app.scan.profiles.editor.as_ref().expect("editor").draft;
        assert!(draft.checks.exclude.is_empty());
        assert_eq!(
            draft.checks.include,
            vec!["sqli-error".to_string(), "lane:http".to_string()]
        );
    }

    // Left collapses the lane node; the tree shrinks to the lane alone and
    // Right (Enter) expands it again.
    focus_node(&mut app, "lane:http");
    let _ = app.update(Action::Left);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert!(editor.collapsed.contains("lane:http"));
    assert_eq!(app.scan.profiles.visible_len(), 1);
    let _ = app.update(Action::Right);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert!(editor.collapsed.is_empty());
    // The cursor walks the tree's rows, not the catalogue's three entries.
    let _ = app.update(Action::End);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .tree_cursor,
        6
    );
}

/// D11: `e` on an enum field moves it to the next variant in declaration
/// order; Space on a lane field removes the lane; `e` on a number field
/// opens `ScanField` prefilled with the current value and `Submit` writes
/// the parsed number; a non-number is refused with `<label> must be a
/// number`.
#[test]
fn editing_cycles_enums_toggles_bools_and_prompts_numbers() {
    let mut app = app();
    open_standard(&mut app);

    focus_field(&mut app, EditorField::Intensity);
    assert!(app.update(Action::ScanEdit).is_empty());
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        assert_eq!(editor.draft.intensity, Intensity::Intrusive);
        assert!(editor.dirty);
    }
    let _ = app.update(Action::ScanEdit);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .intensity,
        Intensity::Passive,
        "the cycle wraps"
    );

    focus_field(&mut app, EditorField::UseBrowser);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .crawl
            .use_browser,
        UseBrowser::Always
    );

    focus_field(&mut app, EditorField::LaneWs);
    let _ = app.update(Action::ScanToggle);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .lanes,
        vec![LaneKind::Http]
    );
    let _ = app.update(Action::ScanToggle);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .lanes,
        vec![LaneKind::Http, LaneKind::Ws],
        "a lane comes back in declaration order"
    );

    focus_field(&mut app, EditorField::SubmitForms);
    let _ = app.update(Action::ScanToggle);
    assert!(
        !app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .crawl
            .submit_forms
    );

    focus_field(&mut app, EditorField::BudgetProbes);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanField));
    assert_eq!(app.prompt, "2000", "prefilled with the current value");
    for _ in 0..4 {
        let _ = app.update(Action::Backspace);
    }
    type_text(&mut app, "3000");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Scan);
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        assert_eq!(editor.draft.budget.probes, 3000);
        assert!(editor.dirty);
    }

    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.prompt, "3000");
    type_text(&mut app, "x");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(toast(&app), "budget_probes must be a number");
    assert_eq!(
        app.mode,
        Mode::Prompt(PromptKind::ScanField),
        "the prompt stays open for another try"
    );
    assert!(app.prompt.is_empty(), "the line is cleared");
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .budget
            .probes,
        3000,
        "a refused value changes nothing"
    );

    focus_field(&mut app, EditorField::Name);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.prompt, "standard");
    type_text(&mut app, "-2");
    let _ = app.update(Action::Submit);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .name,
        "standard-2"
    );

    // `e` on Origins and Checks focuses the pane instead of editing.
    focus_field(&mut app, EditorField::Origins);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.scan.profiles.pane, ProfilePane::Origins);
    focus_field(&mut app, EditorField::Checks);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.scan.profiles.pane, ProfilePane::Checks);

    // `N` opens a fresh editor over the defaults.
    let _ = app.update(Action::ScanNewProfile);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(editor.draft, ScanProfile::default());
    assert_eq!(editor.loaded_from, None);
    assert!(!editor.builtin);
    assert!(!editor.dirty);
    assert_eq!(app.scan.profiles.pane, ProfilePane::Fields);
}

/// `parse_l4_target` reads `ip:port[/tcp|udp][ grammar]`; `t` opens the
/// prompt and a bad line is refused with the one error text.
#[test]
fn l4_target_prompt_parses() {
    assert_eq!(
        parse_l4_target("127.0.0.1:7000/tcp"),
        Ok(L4TargetSpec {
            ip: "127.0.0.1".into(),
            port: 7000,
            proto: L4Transport::Tcp,
            grammar: None,
        })
    );
    let udp = parse_l4_target("10.0.0.1:53/udp dns").expect("a udp target with a grammar");
    assert_eq!(udp.proto, L4Transport::Udp);
    assert_eq!(udp.port, 53);
    assert_eq!(udp.grammar, Some("dns".into()));
    assert_eq!(
        parse_l4_target("[::1]:9000").map(|t| (t.ip, t.proto)),
        Ok(("::1".to_string(), L4Transport::Tcp)),
        "a bracketed IPv6 address, tcp by default"
    );
    for bad in [
        "garbage",
        "127.0.0.1",
        "host.test:80",
        "127.0.0.1:0",
        "127.0.0.1:70000",
        "127.0.0.1:80/icmp",
        "127.0.0.1:80/tcp a b",
        "",
    ] {
        assert_eq!(parse_l4_target(bad), Err(L4TargetError), "{bad:?}");
    }
    assert_eq!(
        L4_TARGET_ERROR,
        "L4 target must be ip:port[/tcp|udp][ grammar]"
    );

    let mut app = app();
    open_standard(&mut app);
    let _ = app.update(Action::ScanL4TargetPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanL4Target));
    type_text(&mut app, "garbage");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(toast(&app), L4_TARGET_ERROR);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanL4Target));
    type_text(&mut app, "127.0.0.1:7000/tcp");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Scan);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(
        editor.draft.target.l4,
        vec![L4TargetSpec {
            ip: "127.0.0.1".into(),
            port: 7000,
            proto: L4Transport::Tcp,
            grammar: None,
        }]
    );
    assert!(editor.dirty);
}

/// D11, T7-11: `w` on a builtin asks for a name; the typed name replaces
/// `draft.name` and the whole typed profile goes out serialised; the reply
/// toasts `saved <name> at <path>`, clears `dirty` and refreshes the list.
#[test]
fn save_on_a_builtin_asks_for_a_name_then_saves() {
    let mut app = app();
    open_standard(&mut app);
    assert!(app.update(Action::ScanSave).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanProfileName));
    assert!(
        app.prompt.is_empty(),
        "no prefill: the builtin's name is taken"
    );

    // A builtin name is refused and the prompt stays.
    type_text(&mut app, "thorough");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanProfileName));
    assert!(toast(&app).contains("thorough"), "{}", toast(&app));

    type_text(&mut app, "team-x");
    let reqs = app.update(Action::Submit);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let BusRequest::CallTagged { tag, name, args } = &reqs[0] else {
        panic!("not a tagged call: {reqs:?}");
    };
    assert_eq!(tag, "scan.profile.save");
    assert_eq!(name, "scan.profile.save");
    assert_eq!(args["profile"]["name"], json!("team-x"));
    let sent: ScanProfile =
        serde_json::from_value(args["profile"].clone()).expect("the typed profile round-trips");
    assert_eq!(sent.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    assert_eq!(
        sent,
        app.scan.profiles.editor.as_ref().expect("editor").draft,
        "exactly the draft, serialised with serde"
    );
    assert_eq!(app.mode, Mode::Scan);

    // The reply names the draft (fix round G, G46: one naming another
    // profile is not adopted), at the fixture's path shape.
    let mut save = fixture("scan.profile.save.json");
    save["saved"] = json!("team-x");
    save["path"] = json!("/Users/operator/.aitmproxy/findings/scan/profiles/team-x.yaml");
    let (saved, path) = (
        save["saved"].as_str().expect("saved"),
        save["path"].as_str().expect("path"),
    );
    let reqs = app.on_bus(reply(
        "scan.profile.save",
        "scan.profile.save",
        save.clone(),
    ));
    assert_eq!(toast(&app), format!("saved {saved} at {path}"));
    assert_eq!(
        reqs,
        vec![tagged("scan.profile.list", "scan.profile.list", json!({}))],
        "a save refreshes the list (D6)"
    );
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert!(!editor.dirty);
    assert!(!editor.builtin, "the saved copy is the operator's");
    assert_eq!(editor.loaded_from.as_deref(), Some(saved));

    // A non-builtin saves straight away, under the same tag.
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        fixture("scan.profile.list.json"),
    ));
    focus_field(&mut app, EditorField::MaxDepth);
    let _ = app.update(Action::ScanEdit);
    type_text(&mut app, "1");
    let _ = app.update(Action::Submit);
    let reqs = app.update(Action::ScanSave);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let BusRequest::CallTagged { tag, args, .. } = &reqs[0] else {
        panic!("not a tagged call: {reqs:?}");
    };
    assert_eq!(tag, "scan.profile.save");
    assert_eq!(args["profile"]["name"], json!("team-x"));
    assert_eq!(args["profile"]["crawl"]["max_depth"], json!(31));
    assert_eq!(app.mode, Mode::Scan, "no name prompt for a saved profile");
}

/// Fix round G, G49 and G42: a typed profile name must match the engine's
/// rule `^[a-z0-9][a-z0-9._-]{0,63}$` (lowercase only, builtins refused,
/// never lowercased on the operator's behalf); a refusal keeps the prompt
/// open with the one toast, and the accepted name is trimmed like any
/// field text.
#[test]
fn a_typed_profile_name_follows_the_engine_rule() {
    const RULE: &str = "profile name: a-z 0-9 . _ - only, lowercase, up to 64";
    let mut app = app();
    open_standard(&mut app);
    assert!(app.update(Action::ScanSave).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanProfileName));
    let too_long = "n".repeat(65);
    for bad in [
        "../../x",
        "/abs",
        ".hidden",
        "Standard",
        too_long.as_str(),
        "a b",
    ] {
        type_text(&mut app, bad);
        assert!(app.update(Action::Submit).is_empty(), "{bad:?}");
        assert_eq!(
            app.mode,
            Mode::Prompt(PromptKind::ScanProfileName),
            "{bad:?} keeps the prompt open"
        );
        assert_eq!(toast(&app), RULE, "{bad:?}");
        assert!(app.prompt.is_empty(), "{bad:?}: the line is cleared");
    }
    // A padded builtin name is still the builtin's (G42: trimmed first).
    type_text(&mut app, "  thorough  ");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanProfileName));
    assert_eq!(
        toast(&app),
        "thorough is a builtin profile; pick another name"
    );

    type_text(&mut app, "  team-x.v2  ");
    let reqs = app.update(Action::Submit);
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    let BusRequest::CallTagged { args, .. } = &reqs[0] else {
        panic!("not a tagged call: {reqs:?}");
    };
    assert_eq!(args["profile"]["name"], json!("team-x.v2"), "trimmed");
    assert_eq!(app.mode, Mode::Scan);
    let text = text_of(&app, 200, 50);
    assert!(!text.contains(RULE), "{text}");

    // The same rule on the `e` prompt of the name field.
    focus_field(&mut app, EditorField::Name);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanField));
    assert_eq!(app.prompt, "team-x.v2", "prefilled");
    app.prompt.clear();
    type_text(&mut app, "Bad Name");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanField));
    assert_eq!(toast(&app), RULE);
}

/// Fix round G, G49: the `profile name:` prompt label spells the rule.
#[test]
fn the_profile_name_prompt_label_spells_the_rule() {
    let mut app = app();
    open_standard(&mut app);
    let _ = app.update(Action::ScanSave);
    let text = text_of(&app, 200, 50);
    let line = line_with(&text, "profile name:").unwrap_or_else(|| panic!("{text}"));
    assert!(
        line.contains("a-z 0-9 . _ - lowercase · ⏎ save as"),
        "{line:?}"
    );
}

/// Fix round G, G46: a `scan.profile.save` reply naming another profile
/// is not adopted as `loaded_from`; the uncoded error is recorded.
#[test]
fn a_save_reply_naming_another_profile_is_not_adopted() {
    let mut app = app();
    open_standard(&mut app);
    let _ = app.update(Action::ScanSave);
    type_text(&mut app, "team-x");
    let _ = app.update(Action::Submit);
    let _ = app.on_bus(reply(
        "scan.profile.save",
        "scan.profile.save",
        json!({ "saved": "other", "path": "/p/other.yaml" }),
    ));
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(editor.loaded_from.as_deref(), Some("standard"), "unchanged");
    assert!(editor.dirty, "not marked saved");
    let err = app.scan.profiles.error.as_ref().expect("recorded");
    assert_eq!(err.tag, "scan.profile.save");
    assert_eq!(err.detail, "save reply named a different profile");
    assert_ne!(toast(&app), "saved other at /p/other.yaml");

    let _ = app.on_bus(reply(
        "scan.profile.save",
        "scan.profile.save",
        json!({ "saved": "team-x", "path": "/p/team-x.yaml" }),
    ));
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(editor.loaded_from.as_deref(), Some("team-x"));
    assert!(!editor.dirty);
    assert_eq!(
        app.scan.profiles.error, None,
        "the same-tag success clears it"
    );
}

/// Fix round G, G47: a control character makes a name or a check selector
/// unusable; the row or check is dropped at fold.
#[test]
fn control_characters_make_a_selector_unusable() {
    let mut app = app();
    let mut list = fixture("scan.profile.list.json");
    list["profiles"][0]["name"] = json!("a\x1b[2Jb");
    list["profiles"][1]["name"] = json!("tab\tbed");
    let _ = app.on_bus(reply("scan.profile.list", "scan.profile.list", list));
    let names: Vec<&str> = app
        .scan
        .profiles
        .list
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names.len(), 5, "{names:?}");
    assert!(names.iter().all(|n| !n.chars().any(char::is_control)));
    let mut checks = fixture("scan.checks.json");
    checks["checks"][0]["id"] = json!("http.x\u{7}");
    let _ = app.on_bus(reply("scan.checks", "scan.checks", checks));
    assert_eq!(app.scan.profiles.checks.len(), 2);
}

/// Fix round G, G48: a canary path is cut at the first `?` or `#` at fold,
/// so a query string from a hostile core never reaches the session line.
#[test]
fn the_canary_path_is_cut_at_the_query() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, ORIGIN);
    let _ = app.update(Action::Submit);
    let mut preview = fixture("scan.session.preview.json");
    preview["canary"]["path"] = json!("/account?token=abc#frag");
    let _ = app.on_bus(reply(
        &format!("scan.session.preview:{ORIGIN}"),
        "scan.session.preview",
        preview,
    ));
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    let line = session_line(editor, &app.scan.profiles.previews);
    assert_eq!(line, SESSION_LINE);
    assert!(!line.contains("token"), "{line:?}");
}

/// Fix round G, G50 (D11 as amended): re-opening a profile re-reads its
/// session preview; the cache never suppresses the read, only the
/// in-flight dedupe does.
#[test]
fn reopening_a_profile_rereads_the_session_preview() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, ORIGIN);
    let reqs = app.update(Action::Submit);
    assert_eq!(reqs.len(), 1, "the first preview read: {reqs:?}");
    let _ = app.on_bus(reply(
        &format!("scan.session.preview:{ORIGIN}"),
        "scan.session.preview",
        fixture("scan.session.preview.json"),
    ));
    assert!(app.scan.profiles.previews.contains_key(ORIGIN));

    let _ = app.update(Action::Back);
    assert_eq!(app.scan.profiles.pane, ProfilePane::List);
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["target"]["origins"] = json!([ORIGIN]);
    let reqs = app.on_bus(reply("scan.profile.get:standard", "scan.profile.get", get));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.session.preview:{ORIGIN}"),
            "scan.session.preview",
            json!({ "target": ORIGIN })
        )],
        "a second preview read leaves despite the cached one"
    );
    // While it is in flight the dedupe holds a third.
    let _ = app.update(Action::Back);
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["target"]["origins"] = json!([ORIGIN]);
    let reqs = app.on_bus(reply("scan.profile.get:standard", "scan.profile.get", get));
    assert!(reqs.is_empty(), "deduped while in flight: {reqs:?}");
}

/// D11: `D` on a non-builtin row asks `delete profile <name>? y/N` through
/// the existing confirm prompt; `y` sends `scan.profile.delete {name}`
/// under its keyed tag; the reply toasts and refreshes the list. A builtin
/// row is refused without a prompt.
#[test]
fn delete_goes_through_the_confirm_prompt() {
    let mut app = app();
    let mut list = fixture("scan.profile.list.json");
    list["profiles"]
        .as_array_mut()
        .expect("profiles")
        .push(json!({
            "name": "team-x",
            "builtin": false,
            "summary": { "lanes": ["http"], "intensity": "light", "speed": "fast" }
        }));
    let _ = app.on_bus(reply("scan.profile.list", "scan.profile.list", list));
    assert_eq!(app.scan.profiles.list.len(), 8);

    app.scan.profiles.cursor = 3;
    assert!(app.update(Action::ScanDelete).is_empty());
    assert_eq!(app.mode, Mode::Scan, "a builtin opens no prompt");
    assert!(toast(&app).contains("builtin"), "{}", toast(&app));

    app.scan.profiles.cursor = 7;
    assert!(app.update(Action::ScanDelete).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    let confirm = app.confirm.as_ref().expect("a confirm call waits");
    assert_eq!(confirm.description, "delete profile team-x? y/N");
    assert_eq!(confirm.name, "scan.profile.delete");
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("delete profile team-x? y/N"),
        "the prompt shows the question: {text}"
    );

    let reqs = app.update(Action::Input('y'));
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.profile.delete:team-x",
            "scan.profile.delete",
            json!({ "name": "team-x" })
        )]
    );
    assert_eq!(app.mode, Mode::Scan, "back to the view");
    assert!(app.scan.inflight.contains("scan.profile.delete:team-x"));

    let reqs = app.on_bus(reply(
        "scan.profile.delete:team-x",
        "scan.profile.delete",
        fixture("scan.profile.delete.json"),
    ));
    assert_eq!(toast(&app), "deleted team-x");
    assert_eq!(
        reqs,
        vec![tagged("scan.profile.list", "scan.profile.list", json!({}))],
        "a delete refreshes the list (D6)"
    );

    // `n` sends nothing.
    let _ = app.update(Action::ScanDelete);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Confirm));
    assert!(app.update(Action::Input('n')).is_empty());
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(toast(&app), "scan.profile.delete cancelled");
}

/// D6 hostile-core bounds: an oversized catalogue and list are cut at fold,
/// an over-long or empty id or name is dropped, a session name carrying a
/// `=` is cut before it, a reply naming another profile or origin is not
/// folded, and empty replies and keys on empty panes never panic.
#[test]
fn hostile_profile_replies_are_bounded() {
    let mut app = app();

    let one = fixture("scan.checks.json")["checks"][0].clone();
    let mut checks: Vec<Value> = (0..CHECKS_MAX + 50)
        .map(|k| {
            let mut c = one.clone();
            c["id"] = json!(format!("http.check-{k}"));
            c
        })
        .collect();
    checks[0]["id"] = json!("x".repeat(10_000));
    checks[1]["id"] = json!("");
    checks[2]["class"] = json!("");
    checks[3]["description"] = json!("d".repeat(100_000));
    let _ = app.on_bus(reply(
        "scan.checks",
        "scan.checks",
        json!({ "checks": checks }),
    ));
    let folded = &app.scan.profiles.checks;
    assert_eq!(
        folded.len(),
        CHECKS_MAX,
        "the three bad rows go, the rest is cut"
    );
    assert!(
        folded
            .iter()
            .all(|c| !c.id.is_empty() && c.id.len() <= SELECTOR_MAX && !c.class.is_empty()),
        "ids and classes are selectors: bounded or dropped"
    );
    assert!(folded
        .iter()
        .all(|c| c.description.chars().count() <= 4 * VALUE_MAX));
    let tree: Vec<_> = tree_nodes(folded, &Default::default(), &Default::default())
        .into_iter()
        .filter(|n| !n.hidden)
        .collect();
    assert_eq!(
        tree.len(),
        CHECKS_MAX + 2,
        "one lane, one class, every check"
    );

    let entry = fixture("scan.profile.list.json")["profiles"][0].clone();
    let mut profiles: Vec<Value> = (0..PROFILES_MAX + 50)
        .map(|k| {
            let mut p = entry.clone();
            p["name"] = json!(format!("p-{k}"));
            p
        })
        .collect();
    profiles[0]["name"] = json!("n".repeat(10_000));
    profiles[1]["name"] = json!("");
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        json!({ "profiles": profiles }),
    ));
    let list = &app.scan.profiles.list;
    assert_eq!(
        list.len(),
        PROFILES_MAX,
        "the two bad rows go, the rest is cut"
    );
    assert!(list
        .iter()
        .all(|p| !p.name.is_empty() && p.name.len() <= SELECTOR_MAX));

    // A `scan.profile.get` reply naming another profile is not folded.
    app.scan.profiles.cursor = 2;
    let name = app.scan.profiles.list[2].name.clone();
    let _ = app.update(Action::Enter);
    let mut other = fixture("scan.profile.get.json");
    other["name"] = json!("someone-else");
    let _ = app.on_bus(reply(
        &format!("scan.profile.get:{name}"),
        "scan.profile.get",
        other,
    ));
    assert!(app.scan.profiles.editor.is_none(), "nothing folded");
    let err = app
        .scan
        .profiles
        .error
        .as_ref()
        .expect("the mismatch is recorded");
    assert_eq!(err.tag, format!("scan.profile.get:{name}"));
    assert!(err.code.is_none());

    // The real reply folds; a session preview with a `name=value` cookie
    // name shows the name only.
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["name"] = json!(name);
    get["target"]["origins"] = json!([ORIGIN]);
    let reqs = app.on_bus(reply(
        &format!("scan.profile.get:{name}"),
        "scan.profile.get",
        get,
    ));
    assert_eq!(
        reqs,
        vec![tagged(
            &format!("scan.session.preview:{ORIGIN}"),
            "scan.session.preview",
            json!({ "target": ORIGIN })
        )],
        "an observed profile with an origin reads its preview on open"
    );
    let mut preview = fixture("scan.session.preview.json");
    preview["cookies"] = json!(["sid=s3cr3t", "x".repeat(5000)]);
    preview["headers"] = json!((0..500).map(|k| format!("h{k}")).collect::<Vec<_>>());
    let _ = app.on_bus(reply(
        &format!("scan.session.preview:{ORIGIN}"),
        "scan.session.preview",
        preview,
    ));
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    let line = session_line(editor, &app.scan.profiles.previews);
    assert!(!line.contains('='), "{line}");
    assert!(!line.contains("s3cr3t"), "{line}");
    assert!(line.contains("sid"), "{line}");
    assert!(line.len() < 4000, "bounded: {}", line.len());

    // A preview naming another origin is not folded.
    let _ = app.update(Action::ScanNewProfile);
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, "https://127.0.0.1");
    let _ = app.update(Action::Submit);
    let mut preview = fixture("scan.session.preview.json");
    preview["origin"] = json!("https://elsewhere.test");
    let _ = app.on_bus(reply(
        "scan.session.preview:https://127.0.0.1",
        "scan.session.preview",
        preview,
    ));
    assert!(!app.scan.profiles.previews.contains_key("https://127.0.0.1"));
    assert!(!app
        .scan
        .profiles
        .previews
        .contains_key("https://elsewhere.test"));

    // Empty replies and keys on empty panes.
    let _ = app.on_bus(reply("scan.checks", "scan.checks", json!({ "checks": [] })));
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        json!({ "profiles": [] }),
    ));
    assert!(app.scan.profiles.checks.is_empty());
    assert!(app.scan.profiles.list.is_empty());
    app.scan.profiles.pane = ProfilePane::Checks;
    let _ = app.update(Action::ScanToggle);
    let _ = app.update(Action::Left);
    let _ = app.update(Action::Enter);
    let _ = app.update(Action::Down);
    app.scan.profiles.pane = ProfilePane::Origins;
    let editor = app.scan.profiles.editor.as_mut().expect("editor");
    editor.origin_choices.clear();
    let _ = app.update(Action::ScanOriginAdd);
    let _ = app.update(Action::ScanOriginRemove);
    let _ = app.update(Action::Enter);
    app.scan.profiles.pane = ProfilePane::List;
    assert!(app.update(Action::Enter).is_empty(), "no row, no read");
    assert!(app.update(Action::ScanDelete).is_empty());
    let _ = text_of(&app, 200, 50);
    let _ = text_of(&app, 40, 4);
}

/// Fix round G, G51: a `scan.profile.list` row's lanes are sorted and
/// deduped at fold (the four kinds at most) and the row's lanes text is
/// built there, so a row with a hundred thousand `http` lanes renders
/// `http` once and a row with `[ws, http, http]` renders `http ws`.
#[test]
fn list_lanes_are_deduped_at_fold_and_rendered_once() {
    let mut app = app();
    let entry = fixture("scan.profile.list.json")["profiles"][0].clone();
    let mut flood = entry.clone();
    flood["name"] = json!("flood");
    flood["summary"]["lanes"] = json!(vec!["http"; 100_000]);
    let mut mixed = entry;
    mixed["name"] = json!("mixed");
    mixed["summary"]["lanes"] = json!(["ws", "http", "http"]);
    let _ = app.on_bus(reply(
        "scan.profile.list",
        "scan.profile.list",
        json!({ "profiles": [flood, mixed] }),
    ));
    let list = &app.scan.profiles.list;
    assert_eq!(list[0].summary.lanes, vec![LaneKind::Http]);
    assert_eq!(list[1].summary.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    assert_eq!(app.scan.profiles.lanes_text, vec!["http", "http ws"]);
    let (left, _) = halves(&app, 200, 50);
    let flood_row = line_with(&left, "flood").unwrap_or_else(|| panic!("no row:\n{left}"));
    assert_eq!(flood_row.matches("http").count(), 1, "{flood_row:?}");
    let mixed_row = line_with(&left, "mixed").unwrap_or_else(|| panic!("no row:\n{left}"));
    assert!(mixed_row.contains("http ws"), "{mixed_row:?}");
    assert!(!mixed_row.contains("ws http"), "{mixed_row:?}");
}

/// Fix round G, G52: `text_of(field)` is the one text rule; it reads any
/// field without moving the cursor, and equals what `field_text()` prints
/// with the cursor on that field.
#[test]
fn text_of_reads_every_field_without_moving_the_cursor() {
    let mut app = app();
    open_standard(&mut app);
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    for (i, f) in EDITOR_FIELDS.iter().enumerate() {
        let mut probe = editor.clone();
        probe.field = i;
        assert_eq!(editor.text_of(*f), probe.field_text(), "{f:?}");
    }
    assert_eq!(editor.field, 0, "the cursor did not move");
    assert_eq!(editor.text_of(EditorField::Name), "standard");
    assert_eq!(editor.text_of(EditorField::Intensity), "medium");
}

/// Fix round G, G45 and G53: a `scan.profile.get` reply over the draft
/// bounds is refused, not cut (the draft is echoed back on `w` and `s`):
/// the editor stays closed, the uncoded error `profile exceeds bounds` is
/// recorded under the tag and no `scan.session.preview` leaves. An
/// unparseable L4 target ip is over bounds too. A reply within bounds
/// folds with its lanes sorted and deduped.
#[test]
fn an_oversized_profile_reply_is_refused_not_adopted() {
    let mut app = app();
    app.scan.profiles.cursor = 3;
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["target"]["origins"] = json!((0..100_000)
        .map(|k| format!("https://h{k}.test"))
        .collect::<Vec<_>>());
    let reqs = app.on_bus(reply("scan.profile.get:standard", "scan.profile.get", get));
    assert!(app.scan.profiles.editor.is_none(), "nothing adopted");
    let err = app
        .scan
        .last_error
        .as_ref()
        .expect("the refusal is recorded");
    assert_eq!(err.detail, "profile exceeds bounds");
    assert_eq!(err.tag, "scan.profile.get:standard");
    assert!(err.code.is_none());
    assert!(
        !reqs.iter().any(|r| matches!(
            r,
            BusRequest::CallTagged { name, .. } if name == "scan.session.preview"
        )),
        "no preview leaves for a refused profile: {reqs:?}"
    );

    // G53: an L4 target whose ip is not an address is over bounds.
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["target"]["l4"] = json!([{ "ip": "x".repeat(1 << 20), "port": 7000 }]);
    let _ = app.on_bus(reply("scan.profile.get:standard", "scan.profile.get", get));
    assert!(app.scan.profiles.editor.is_none(), "nothing adopted");
    assert_eq!(
        app.scan.last_error.as_ref().map(|e| e.detail.as_str()),
        Some("profile exceeds bounds")
    );

    // Within bounds: the reply folds, the lanes sorted and deduped, and
    // the refusal is cleared by the same-tag success (D13).
    let _ = app.update(Action::Enter);
    let mut get = fixture("scan.profile.get.json");
    get["lanes"] = json!(["ws", "http", "http"]);
    let _ = app.on_bus(reply("scan.profile.get:standard", "scan.profile.get", get));
    let editor = app
        .scan
        .profiles
        .editor
        .as_ref()
        .expect("the editor opened");
    assert_eq!(editor.draft.lanes, vec![LaneKind::Http, LaneKind::Ws]);
    assert_eq!(app.scan.last_error, None);
}

/// D11: `a` in the Origins pane adds the highlighted choice to the draft,
/// `d` removes it; the picker rows follow the scope and the captured flows
/// (D8) and keep what the operator typed.
#[test]
fn origins_pane_adds_and_removes_choices() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["auth.shop-staging.test".into()]));
    let _ = app.update(Action::ScanNewProfile);
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        let origins: Vec<&str> = editor
            .origin_choices
            .iter()
            .map(|c| c.origin.as_str())
            .collect();
        assert_eq!(origins, vec!["https://auth.shop-staging.test"]);
    }
    let mut http = summary(
        "f1",
        "GET",
        "auth.shop-staging.test:8080",
        "/",
        Some(200),
        "none",
    );
    http["scheme"] = json!("http");
    let _ = app.on_bus(BusEvent::Flows(vec![http]));
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        let origins: Vec<&str> = editor
            .origin_choices
            .iter()
            .map(|c| c.origin.as_str())
            .collect();
        assert_eq!(
            origins,
            vec![
                "https://auth.shop-staging.test",
                "http://auth.shop-staging.test:8080"
            ],
            "a captured http flow adds its origin (D8)"
        );
    }

    // `a` outside the Origins pane is inert.
    assert_eq!(app.scan.profiles.pane, ProfilePane::Fields);
    let _ = app.update(Action::ScanOriginAdd);
    assert!(app
        .scan
        .profiles
        .editor
        .as_ref()
        .expect("editor")
        .draft
        .target
        .origins
        .is_empty());

    app.scan.profiles.pane = ProfilePane::Origins;
    let _ = app.update(Action::Down);
    let reqs = app.update(Action::ScanOriginAdd);
    assert_eq!(
        reqs,
        vec![tagged(
            "scan.session.preview:http://auth.shop-staging.test:8080",
            "scan.session.preview",
            json!({ "target": "http://auth.shop-staging.test:8080" })
        )]
    );
    {
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        assert_eq!(
            editor.draft.target.origins,
            vec!["http://auth.shop-staging.test:8080".to_string()]
        );
        assert!(editor.dirty);
    }
    let _ = app.update(Action::Up);
    let _ = app.update(Action::ScanOriginAdd);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .target
            .origins,
        vec![
            "http://auth.shop-staging.test:8080".to_string(),
            "https://auth.shop-staging.test".to_string()
        ]
    );
    let _ = app.update(Action::ScanOriginRemove);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .target
            .origins,
        vec!["http://auth.shop-staging.test:8080".to_string()]
    );
    let _ = app.update(Action::ScanOriginRemove);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .target
            .origins,
        vec!["http://auth.shop-staging.test:8080".to_string()],
        "removing a choice the draft lacks changes nothing"
    );
}

// ---------------------------------------------------------------------------
// Plan task 11: the Profiles view (spec D11 mockup, D8 picker, D13 states).
// ---------------------------------------------------------------------------

/// The screen split at the pane rule: `(list, detail)` texts, one line per
/// row. The rule column is read from the footer line (`s start`), which the
/// detail pane always carries; the box borders are outside both halves.
fn halves(app: &App, cols: u16, rows: u16) -> (String, String) {
    let text = text_of(app, cols, rows);
    let footer =
        line_with(&text, "s start · m map").unwrap_or_else(|| panic!("no footer:\n{text}"));
    let rule = col_of(footer, " s start").unwrap_or_else(|| panic!("no footer col: {footer:?}"));
    let mut list = String::new();
    let mut detail = String::new();
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        let (l, d) = chars.split_at(rule.min(chars.len()));
        list.push_str(&l.iter().collect::<String>());
        list.push('\n');
        detail.push_str(&d.iter().collect::<String>());
        detail.push('\n');
    }
    (list, detail)
}

/// Focus a secondary pane the operator's way: the Fields cursor on the
/// `origins` or `checks` field, then `e`.
fn focus_pane(app: &mut App, field: EditorField, pane: ProfilePane) {
    focus_field(app, field);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.scan.profiles.pane, pane);
}

/// Plan task 11: every fixture row prints `name · lanes · intensity ·
/// speed` with the builtin mark, the cursor row carries the `>` mark and
/// the selection style while the List pane is focused.
#[test]
fn profile_list_renders_seven_rows_with_the_builtin_mark() {
    let app = app();
    let (list, _) = halves(&app, 200, 50);
    for name in [
        "passive-only",
        "map-only",
        "light-http",
        "standard",
        "thorough",
        "l4-stream-safe",
        "l4-full",
    ] {
        let line = line_with(&list, name).unwrap_or_else(|| panic!("no row {name}:\n{list}"));
        assert!(
            line.contains(BUILTIN_MARK),
            "{name} is a builtin: {line:?} lacks {BUILTIN_MARK:?}"
        );
    }
    let standard = row_text(&list, "standard");
    for want in ["http ws", "medium", "normal"] {
        assert!(standard.contains(want), "{standard:?} lacks {want:?}");
    }
    // The row as drawn (fix round G, G60): the name column is the widest
    // name (`l4-stream-safe`, 14 cells), then the pad, the blank held-mark
    // cell and the builtin mark, then lanes, intensity and speed.
    assert_eq!(
        standard,
        "standard        ·  http ws              medium     normal"
    );
    let header = line_with(&list, "name").unwrap_or_else(|| panic!("no row with {:?}", "name"));
    assert!(
        header.contains("lanes") && header.contains("intensity") && header.contains("speed"),
        "column header: {header:?}"
    );
    // The cursor row (index 0) is marked and highlighted; no other row is.
    let first = line_with(&list, "passive-only")
        .unwrap_or_else(|| panic!("no row with {:?}", "passive-only"));
    assert!(first.trim_start_matches('│').starts_with('>'), "{first:?}");
    assert!(
        !standard.trim_start_matches('│').starts_with('>'),
        "{standard:?}"
    );
    let buf = draw(&app, 200, 50);
    let y = line_index(&text_of(&app, 200, 50), "passive-only").unwrap_or_default();
    let x = col_of(first, "passive-only").unwrap_or_default();
    assert_eq!(
        cell(&buf, x, y).bg,
        selection_bg(&theme()).bg.unwrap_or_default()
    );
    let y3 = line_index(&text_of(&app, 200, 50), "standard").unwrap_or_default();
    assert_ne!(
        cell(&buf, x, y3).bg,
        selection_bg(&theme()).bg.unwrap_or_default()
    );
}

/// Plan task 11 (T7-11, render half): the Fields pane in `EDITOR_FIELDS`
/// order as the D11 mockup, the lanes as `[x]`/`[ ]`, the budget line, the
/// Task 10 session line verbatim; the Checks pane as the lane to class to
/// check tree with the tri-state glyphs and the collapse markers.
#[test]
fn the_editor_renders_fields_tree_and_session() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, ORIGIN);
    let _ = app.update(Action::Submit);
    let _ = app.on_bus(reply(
        &format!("scan.session.preview:{ORIGIN}"),
        "scan.session.preview",
        fixture("scan.session.preview.json"),
    ));
    let (_, detail) = halves(&app, 200, 50);
    // One row per line as drawn (fix round G, G60).
    assert_eq!(
        row_text(&detail, "[x] http"),
        "lanes     [x] http  [x] ws  [ ] l4_packet  [ ] l4_stream"
    );
    assert_eq!(
        row_text(&detail, "probes 2000"),
        "budget    probes 2000 · time 600 s · issues 1024"
    );
    for want in [
        "profile standard (builtin)",
        "dirty",
        ORIGIN,
        "[x] http",
        "[x] ws",
        "[ ] l4_packet",
        "[ ] l4_stream",
        "intensity medium",
        "speed normal",
        "accuracy normal",
        "crawl",
        "depth 3",
        "pages 200",
        SESSION_LINE,
        "on_lost stop",
        "probes 2000 · time 600 s · issues 1024",
        "version auto",
        "record issues_only",
        "s start · m map · w save as · e edit · Space toggle",
    ] {
        assert!(detail.contains(want), "{want:?} missing from:\n{detail}");
    }
    // The fields come in EDITOR_FIELDS order: the header first, budget
    // before http, the footer last.
    let at = |needle: &str| line_index(&detail, needle).unwrap_or_else(|| panic!("{needle}"));
    assert!(at("profile standard") < at("origins"));
    assert!(at("origins") < at("[x] http"));
    assert!(at("[x] http") < at("intensity medium"));
    assert!(at("intensity medium") < at("checks"));
    assert!(at("checks") < at("crawl"));
    assert!(at("crawl") < at(SESSION_LINE));
    assert!(at(SESSION_LINE) < at("probes 2000"));
    assert!(at("probes 2000") < at("version auto"));
    assert!(at("version auto") < at("s start"));
    // The check summary line carries the lane and class glyphs.
    let checks =
        line_with(&detail, "checks").unwrap_or_else(|| panic!("no row with {:?}", "checks"));
    assert!(
        checks.contains(&format!("{} http", TriState::Default.glyph())),
        "{checks:?}"
    );
    assert!(
        checks.contains("reflected-xss") && checks.contains("sqli-error"),
        "{checks:?}"
    );

    // The Checks pane: the tree under the fields while it is focused.
    focus_pane(&mut app, EditorField::Checks, ProfilePane::Checks);
    focus_node(&mut app, "http.sqli-error");
    let _ = app.update(Action::ScanToggle);
    let _ = app.update(Action::ScanToggle);
    focus_node(&mut app, "sqli-error");
    let _ = app.update(Action::ScanToggle);
    let (_, detail) = halves(&app, 200, 50);
    for want in [
        "http",
        "reflected-xss",
        "sqli-error",
        "information-disclosure",
        "http.sqli-error",
        "http.reflected-xss",
        "http.custom-marker",
    ] {
        assert!(detail.contains(want), "{want:?} missing from:\n{detail}");
    }
    let tree_at = |needle: &str| {
        detail
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(k, _)| k)
            .last()
            .unwrap_or_else(|| panic!("{needle}"))
    };
    let lane = tree_at(&format!("{OPEN_MARK} {} http ", TriState::Default.glyph()));
    let class = tree_at(&format!("{} sqli-error", TriState::Include.glyph()));
    let leaf = tree_at(&format!("{} http.sqli-error", TriState::Exclude.glyph()));
    assert!(
        lane < class && class < leaf,
        "lane {lane} class {class} leaf {leaf}"
    );
    let lane_line = detail.lines().nth(lane).unwrap_or_default();
    assert!(lane_line.contains(OPEN_MARK), "{lane_line:?}");
    assert!(
        detail
            .lines()
            .nth(class)
            .unwrap_or_default()
            .contains(&format!(
                "{OPEN_MARK} {} sqli-error",
                TriState::Include.glyph()
            )),
        "a class node carries the open mark"
    );
    // Collapse the lane: the classes and checks vanish, the mark flips.
    focus_node(&mut app, "lane:http");
    let _ = app.update(Action::Left);
    let (_, collapsed) = halves(&app, 200, 50);
    let lane_line = line_with(
        &collapsed,
        &format!("{COLLAPSED_MARK} {} http", TriState::Default.glyph()),
    );
    assert!(lane_line.is_some(), "collapsed lane row:\n{collapsed}");
    // The row as drawn (G60): the cursor mark, the collapse marker, the
    // tri-state glyph and the label.
    assert_eq!(
        row_text(
            &collapsed,
            &format!("{COLLAPSED_MARK} {} http", TriState::Default.glyph())
        ),
        format!(">{COLLAPSED_MARK} {} http", TriState::Default.glyph())
    );
    assert!(
        !collapsed.contains("http.custom-marker"),
        "the checks under a collapsed lane are hidden:\n{collapsed}"
    );
}

/// Review log, Task 10: `Esc` returns the pane to the List but keeps the
/// editor held; the held editor's row carries [`EDITING_MARK`] so the
/// operator sees which profile `Tab` returns to, and a dirty draft adds
/// `dirty` to the editor header.
#[test]
fn a_held_editor_is_marked_on_its_list_row() {
    let mut app = app();
    open_standard(&mut app);
    let _ = app.update(Action::Back);
    assert_eq!(app.scan.profiles.pane, ProfilePane::List);
    assert!(app.scan.profiles.editor.is_some(), "Esc keeps the editor");
    let (list, detail) = halves(&app, 200, 50);
    let standard =
        line_with(&list, "standard").unwrap_or_else(|| panic!("no row with {:?}", "standard"));
    assert!(standard.contains(EDITING_MARK), "{standard:?}");
    for other in ["passive-only", "map-only", "thorough"] {
        let line = line_with(&list, other).unwrap_or_else(|| panic!("no row with {:?}", other));
        assert!(!line.contains(EDITING_MARK), "{line:?}");
    }
    assert!(
        !detail.contains("dirty"),
        "a fresh editor is clean:\n{detail}"
    );
    // Dirty it: the header says so.
    focus_field(&mut app, EditorField::Intensity);
    let _ = app.update(Action::ScanEdit);
    let (_, detail) = halves(&app, 200, 50);
    let header = line_with(&detail, "profile standard")
        .unwrap_or_else(|| panic!("no row with {:?}", "profile standard"));
    assert!(header.contains("dirty"), "{header:?}");
    // Without an editor the detail says how to open one and no row is marked.
    app.scan.profiles.editor = None;
    let (list, detail) = halves(&app, 200, 50);
    assert!(!list.contains(EDITING_MARK));
    assert!(
        detail.contains("⏎ opens the profile under the cursor"),
        "{detail}"
    );
}

/// Plan task 11 (T7-12, picker render): the Origins pane lists the D8
/// choices with their source; a host with only https flows yields the
/// https origin alone, a captured http flow adds its origin; the rows in
/// the draft are ticked.
#[test]
fn the_origin_picker_offers_scheme_correct_origins() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["auth.shop-staging.test".into()]));
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "f0",
        "GET",
        "auth.shop-staging.test",
        "/login",
        Some(200),
        "none",
    )]));
    let _ = app.update(Action::ScanNewProfile);
    focus_pane(&mut app, EditorField::Origins, ProfilePane::Origins);
    let (_, detail) = halves(&app, 200, 50);
    assert!(
        detail.contains("https://auth.shop-staging.test"),
        "{detail}"
    );
    assert!(
        !detail.contains("http://auth.shop-staging.test"),
        "{detail}"
    );
    let row = row_text(&detail, "] https://auth.shop-staging.test");
    assert!(row.contains("scope"), "the source is named: {row:?}");
    assert!(
        row.contains("[ ] https://"),
        "not in the draft yet: {row:?}"
    );
    // The picker row as drawn (G60): the cursor mark, the tick, the origin
    // and its source.
    assert_eq!(row, ">[ ] https://auth.shop-staging.test  scope");

    let mut http = summary(
        "f1",
        "GET",
        "auth.shop-staging.test:8080",
        "/",
        Some(200),
        "none",
    );
    http["scheme"] = json!("http");
    let _ = app.on_bus(BusEvent::Flows(vec![http]));
    let (_, detail) = halves(&app, 200, 50);
    assert!(
        detail.contains("https://auth.shop-staging.test"),
        "{detail}"
    );
    let row = line_with(&detail, "http://auth.shop-staging.test:8080")
        .unwrap_or_else(|| panic!("{detail}"));
    assert!(row.contains("flows"), "{row:?}");
    let _ = app.update(Action::ScanOriginAdd);
    let (_, detail) = halves(&app, 200, 50);
    let row = line_with(&detail, "] https://auth.shop-staging.test")
        .unwrap_or_else(|| panic!("no row with {:?}", "] https://auth.shop-staging.test"));
    assert!(row.contains("[x] https://"), "added to the draft: {row:?}");
}

/// Plan task 11: wildcard scope entries cannot be origins (D8); they are
/// listed greyed (tertiary text) with the hint to type one.
#[test]
fn wildcards_are_greyed_with_the_hint() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["*.shop-staging.test".into()]));
    let _ = app.update(Action::ScanNewProfile);
    focus_pane(&mut app, EditorField::Origins, ProfilePane::Origins);
    let text = text_of(&app, 200, 50);
    let line = line_with(&text, "*.shop-staging.test").unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains("type an origin (o)"), "{line:?}");
    let y = line_index(&text, "*.shop-staging.test").unwrap_or_default();
    let x = col_of(line, "*.shop-staging.test").unwrap_or_default();
    let buf = draw(&app, 200, 50);
    assert_eq!(
        cell(&buf, x, y).fg,
        theme().text_tertiary().fg.unwrap_or_default()
    );
}

/// Plan task 11: while `launch.blocked` is `Some` (Task 12 computes it) the
/// text sits over the footer in the warning hue, wrapped so the whole
/// reason is readable at 200 and at 90 columns.
#[test]
fn a_blocked_launch_prints_its_reason_in_the_warning_hue() {
    let mut app = app();
    open_standard(&mut app);
    let reason = "L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, 127.0.0.1/32 ports 7000, capability inject (l4.scope.add).";
    app.scan.launch.blocked = Some(reason.to_string());
    for (cols, rows) in [(200u16, 50u16), (90, 40)] {
        let text = text_of(&app, cols, rows);
        for want in [
            "L4 launch disabled",
            "interface \"*\"",
            "direction outbound",
            "127.0.0.1/32",
            "7000",
            "capability inject",
            "(l4.scope.add)",
        ] {
            assert!(
                text.contains(want),
                "{cols}x{rows}: {want:?} missing from:\n{text}"
            );
        }
        let y = line_index(&text, "L4 launch disabled").unwrap_or_default();
        let x = col_of(text.lines().nth(y).unwrap_or_default(), "L4 launch").unwrap_or_default();
        let buf = draw(&app, cols, rows);
        assert_eq!(
            cell(&buf, x, y).fg,
            theme()
                .fg(&aitm_tui::tokens::color::status::CLIENT_ERROR)
                .fg
                .unwrap_or_default(),
            "{cols}x{rows}: the warning hue"
        );
        let footer = line_index(&text, "s start · m map").unwrap_or_default();
        assert!(
            y < footer,
            "{cols}x{rows}: the reason sits above the footer"
        );
    }
    app.scan.launch.blocked = None;
    assert!(!text_of(&app, 200, 50).contains("L4 launch disabled"));
}

/// Plan task 11: nothing panics at 200x50, 90x40 or 40x4, whichever pane is
/// focused, with and without an editor, with and without a blocked reason.
#[test]
fn profiles_view_draws_at_every_size() {
    let mut app = app();
    for (cols, rows) in [(200u16, 50u16), (90, 40), (40, 4), (12, 3)] {
        let _ = text_of(&app, cols, rows);
    }
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into(), "*.x".into()]));
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    type_text(&mut app, ORIGIN);
    let _ = app.update(Action::Submit);
    app.scan.launch.blocked = Some("blocked ".repeat(40));
    for pane in [
        ProfilePane::List,
        ProfilePane::Fields,
        ProfilePane::Origins,
        ProfilePane::Checks,
    ] {
        app.scan.profiles.pane = pane;
        for (cols, rows) in [(200u16, 50u16), (90, 40)] {
            let text = text_of(&app, cols, rows);
            assert!(
                text.contains("s start · m map") && text.contains("blocked blocked"),
                "{pane:?} {cols}x{rows}: footer and reason stay on screen:\n{text}"
            );
            assert!(
                text.contains("profile standard (builtin)"),
                "{pane:?} {cols}x{rows}: the header stays on screen"
            );
        }
        for (cols, rows) in [(40u16, 4u16), (12, 3), (1, 1)] {
            let _ = text_of(&app, cols, rows);
        }
    }
}

/// Fix round G, G58: the wildcard rule is one function, so the Origins
/// pane greys exactly what the picker skipped: a bare `*` entry is offered
/// to nobody and listed greyed with the hint, like `*.host`.
#[test]
fn a_bare_star_scope_entry_is_greyed_not_offered() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["*".into()]));
    let _ = app.update(Action::ScanNewProfile);
    focus_pane(&mut app, EditorField::Origins, ProfilePane::Origins);
    let editor = app.scan.profiles.editor.as_ref().expect("an editor");
    assert!(
        editor.origin_choices.is_empty(),
        "`*` is not an origin choice: {:?}",
        editor.origin_choices
    );
    let text = text_of(&app, 200, 50);
    let line = line_with(&text, "type an origin (o)")
        .unwrap_or_else(|| panic!("the wildcard row is drawn:\n{text}"));
    assert!(line.contains("*  type an origin (o)"), "{line:?}");
}

/// Fix round G, G34: the four prompt submits share one retry rule. A host
/// or scheme refusal in the `o` prompt keeps the prompt open with the line
/// cleared (the operator tries again or leaves with Esc), like the field,
/// L4-target and profile-name prompts; the out-of-scope refusal closes it
/// (the D8 toast answers the operator, scope is fixed elsewhere).
#[test]
fn an_origin_refused_by_the_rule_keeps_the_prompt_open_but_out_of_scope_closes_it() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::Scope(vec!["127.0.0.1".into()]));
    let _ = app.update(Action::ScanNewProfile);
    let _ = app.update(Action::ScanOriginPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanOrigin));
    type_text(&mut app, "http://a b");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(
        app.mode,
        Mode::Prompt(PromptKind::ScanOrigin),
        "a host refusal keeps the prompt open"
    );
    assert!(
        app.prompt.is_empty(),
        "with the line cleared: {:?}",
        app.prompt
    );
    assert_eq!(toast(&app), ORIGIN_HOST_ERROR);
    type_text(&mut app, "ftp://127.0.0.1");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanOrigin));
    assert_eq!(toast(&app), ORIGIN_SCHEME_ERROR);
    type_text(&mut app, "https://evil.test");
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Scan, "out of scope closes the prompt");
    assert_eq!(
        toast(&app),
        "Out of scope: add `evil.test` to scope to scan it"
    );
    assert!(app
        .scan
        .profiles
        .editor
        .as_ref()
        .expect("editor")
        .draft
        .target
        .origins
        .is_empty());
}

/// Fix round H, H45: the Fields pane walks by key, the way the live
/// operator drives it: the key map pins each key to its action, then the
/// walk of [`walk_to_use_browser_and_set_never`] from the open `standard`
/// editor.
#[test]
fn the_fields_pane_walks_by_key() {
    let mut app = app();
    open_standard(&mut app);
    for (key, action) in [
        (KeyCode::Esc, Action::Back),
        (KeyCode::Tab, Action::ScanPaneNext),
        (KeyCode::Home, Action::Home),
        (KeyCode::Char('g'), Action::Home),
        (KeyCode::Down, Action::Down),
        (KeyCode::Char('j'), Action::Down),
        (KeyCode::Char('e'), Action::ScanEdit),
    ] {
        assert_eq!(keys::map(press(key), Mode::Scan), Some(action), "{key:?}");
    }
    walk_to_use_browser_and_set_never(&mut app);
}

/// The live cell's walk (fix round H, H45): `Esc` drops to the List pane
/// with the draft kept, `Tab` returns to Fields, `Home` then `Down` twelve
/// times (the `EDITOR_FIELDS` index of `use_browser`) puts the field cursor
/// on it, and `e` twice cycles it `auto` -> `always` -> `never`, read off
/// the crawl Fields line at 200x50; no prompt opens.
fn walk_to_use_browser_and_set_never(app: &mut App) {
    let pane_before = app.scan.profiles.pane;
    let _ = app.update(Action::Back);
    assert_eq!(
        app.scan.profiles.pane,
        ProfilePane::List,
        "Esc drops to the list from {pane_before:?}"
    );
    assert!(app.scan.profiles.editor.is_some(), "the draft is kept");
    assert_eq!(app.mode, Mode::Scan);
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(
        app.scan.profiles.pane,
        ProfilePane::Fields,
        "Tab returns to Fields"
    );
    let _ = app.update(Action::Home);
    let idx = EDITOR_FIELDS
        .iter()
        .position(|f| *f == EditorField::UseBrowser)
        .expect("a D3 field");
    assert_eq!(idx, 12);
    for _ in 0..idx {
        let _ = app.update(Action::Down);
    }
    let editor = app.scan.profiles.editor.as_ref().expect("an editor");
    assert_eq!(
        editor.field(),
        EditorField::UseBrowser,
        "field {} after pane {pane_before:?}",
        editor.field
    );
    let _ = app.update(Action::ScanEdit);
    let _ = app.update(Action::ScanEdit);
    assert_eq!(app.mode, Mode::Scan, "e on a cycle field opens no prompt");
    let text = text_of(app, 200, 50);
    let line = line_with(&text, "browser ").unwrap_or_else(|| panic!("no crawl line: {text}"));
    assert!(line.contains("browser never"), "{line:?}");
}

/// Fix round H, H45, the live walk in full: the `o` origin prompt answered
/// first (the live cell adds the target origin before it walks the
/// fields), then `Esc`, `Tab`, `Home`, `Down` x12, `e` x2.
#[test]
fn the_fields_pane_walks_by_key_after_an_origin_prompt() {
    let mut app = app();
    app.scope = vec!["127.0.0.1".to_string()];
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanOrigin));
    for c in "http://127.0.0.1:8080".chars() {
        let _ = app.update(Action::Input(c));
    }
    let _ = app.update(Action::Submit);
    assert_eq!(app.mode, Mode::Scan, "the prompt closed: {:?}", toast(&app));
    walk_to_use_browser_and_set_never(&mut app);
}

/// Fix round H, H43 (same class as H18): a prompt draws over the view it
/// was opened from. `o` on the `standard` editor keeps the Scan view (the
/// tab strip and the editor head) under the `origin:` prompt bar at
/// 200x50 instead of the Flows view; a `/` filter prompt from the flow
/// list still keeps the flow list.
#[test]
fn a_prompt_draws_over_the_view_it_was_opened_from() {
    let mut app = app();
    open_standard(&mut app);
    let _ = app.update(Action::ScanOriginPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScanOrigin));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("origin:"), "the prompt bar is up: {text}");
    assert!(
        text.contains(" 1 Profiles"),
        "the Scan tab strip stays under the prompt: {text}"
    );
    assert!(
        text.contains("profile standard"),
        "the editor head stays under the prompt: {text}"
    );
    assert!(
        !text.contains("No flows yet"),
        "the Flows view is not drawn under a Scan prompt: {text}"
    );

    let mut flows = aitm_tui::fixture_app_core(200, 50);
    let _ = flows.update(Action::FilterOpen);
    assert_eq!(flows.mode, Mode::Prompt(PromptKind::Filter));
    let text = text_of(&flows, 200, 50);
    assert!(
        text.contains("shop-staging.test"),
        "the flow list stays under a Flows prompt: {text}"
    );
    assert!(
        !text.contains(" 1 Profiles"),
        "the Scan view is not drawn under a Flows prompt: {text}"
    );
}

/// Fix round H, H48 (D11 as amended): with an editor held, `e` edits the
/// field under the Fields cursor only while the Fields pane is focused.
/// From the List, Origins or Checks pane it changes no field, sends
/// nothing and toasts `e edits a field: Tab to the Fields pane`; from
/// Fields it cycles as before.
#[test]
fn e_edits_a_field_only_from_the_fields_pane() {
    const TOAST: &str = "e edits a field: Tab to the Fields pane";
    let mut app = app();
    open_standard(&mut app);
    focus_field(&mut app, EditorField::Intensity);
    assert_eq!(
        app.scan
            .profiles
            .editor
            .as_ref()
            .expect("editor")
            .draft
            .intensity,
        Intensity::Medium,
        "the fixture's starting intensity"
    );

    for pane in [ProfilePane::List, ProfilePane::Origins, ProfilePane::Checks] {
        app.toasts.clear();
        app.scan.profiles.pane = pane;
        let reqs = app.update(Action::ScanEdit);
        assert!(reqs.is_empty(), "{pane:?}: nothing sent: {reqs:?}");
        let editor = app.scan.profiles.editor.as_ref().expect("editor");
        assert_eq!(
            editor.draft.intensity,
            Intensity::Medium,
            "{pane:?}: e off the Fields pane changes no field"
        );
        assert!(!editor.dirty, "{pane:?}: the draft stays clean");
        assert_eq!(toast(&app), TOAST, "{pane:?}: the toast names the pane");
        assert_eq!(
            app.scan.profiles.pane, pane,
            "{pane:?}: the focused pane is kept"
        );
        assert_eq!(app.mode, Mode::Scan, "{pane:?}: no prompt opened");
    }

    app.toasts.clear();
    app.scan.profiles.pane = ProfilePane::Fields;
    assert!(app.update(Action::ScanEdit).is_empty());
    let editor = app.scan.profiles.editor.as_ref().expect("editor");
    assert_eq!(
        editor.draft.intensity,
        Intensity::Intrusive,
        "from Fields, e cycles as before"
    );
    assert!(editor.dirty);
    assert_ne!(toast(&app), TOAST, "no pane toast from Fields");
}
