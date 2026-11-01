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
    check_tree, parse_l4_target, session_line, tri_state, EditorField, OriginSource, ProfilePane,
    ScanTab, TriState, CHECKS_MAX, EDITOR_FIELDS, L4_TARGET_ERROR, PROFILES_MAX,
};
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

fn tagged(tag: &str, name: &str, args: Value) -> BusRequest {
    BusRequest::CallTagged {
        tag: tag.into(),
        name: name.into(),
        args,
    }
}

fn reply(tag: &str, name: &str, value: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: tag.into(),
        name: name.into(),
        value,
    }
}

/// A connected v2 app at 200x50, still on Flows: nothing scan-related has
/// been asked yet.
fn connected() -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, TOOLS, None);
    app
}

/// [`connected`], opened on the Scan view (landing on Profiles, D2) with the
/// open's three reads settled: an empty `scan.list`, the profile list and
/// the check catalogue fixtures. Nothing is in flight afterwards.
fn app() -> App {
    let mut app = connected();
    let reqs = app.update(Action::OpenScan);
    assert_eq!(
        reqs,
        vec![
            tagged("scan.list", "scan.list", json!({})),
            tagged("scan.profile.list", "scan.profile.list", json!({})),
            tagged("scan.checks", "scan.checks", json!({})),
        ],
        "the first open lands on Profiles and reads its list and checks (D6)"
    );
    let _ = app.on_bus(reply("scan.list", "scan.list", json!({ "jobs": [] })));
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
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.tab, ScanTab::Profiles);
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
    let editor = app.scan.profiles.editor.as_mut().expect("an editor");
    let tree = check_tree(&app.scan.profiles.checks, &editor.collapsed);
    let idx = tree
        .iter()
        .position(|n| n.selector == selector)
        .unwrap_or_else(|| panic!("no node {selector:?} in {tree:?}"));
    editor.tree_cursor = idx;
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        let _ = app.update(Action::Input(c));
    }
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
    let tree = check_tree(&app.scan.profiles.checks, &Default::default());
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
    assert_eq!(tree[2].id.as_deref(), Some("http.custom-marker"));
    assert_eq!(tree[1].id, None);
    assert_eq!(tree[0].label, "http");
    assert_eq!(tree[6].label, "http.sqli-error");

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
    assert_eq!(
        check_tree(&app.scan.profiles.checks, &editor.collapsed).len(),
        1
    );
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
        assert_eq!(
            parse_l4_target(bad),
            Err(L4_TARGET_ERROR.to_string()),
            "{bad:?}"
        );
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

    let save = fixture("scan.profile.save.json");
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
    assert!(folded.len() <= CHECKS_MAX, "{}", folded.len());
    assert!(
        folded
            .iter()
            .all(|c| !c.id.is_empty() && c.id.len() <= 128 && !c.class.is_empty()),
        "ids and classes are selectors: bounded or dropped"
    );
    assert!(folded.iter().all(|c| c.description.len() <= 1000));
    let tree = check_tree(folded, &Default::default());
    assert!(tree.len() <= 2 * CHECKS_MAX + 4);

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
    assert!(list.len() <= PROFILES_MAX, "{}", list.len());
    assert!(list
        .iter()
        .all(|p| !p.name.is_empty() && p.name.len() <= 128));

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
