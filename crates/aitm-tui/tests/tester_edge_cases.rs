//! Tester (stage 5) — malformed, empty and oversized input, and a key/reducer
//! sweep. Nothing a proxy peer or the keyboard can send may panic the UI: a
//! crash here is a crash of the operator's console mid-test. Every app here
//! is built from inline literals in the core's wire shapes.

mod common;

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use aitm_tui::action::{Action, BusEvent};
use aitm_tui::app::{parse_kv_args, App, ComposeForm, EditBuffer, Mode, PromptKind};
use aitm_tui::base64;
use aitm_tui::filter;
use aitm_tui::keys;
use aitm_tui::model::{
    scope_covers, AgentPolicy, AgentState, Finding, FlowDetail, FlowKind, FlowRow, Intercept,
    Message, Meta, Origin, Severity, WsDir,
};
use aitm_tui::ui::text::{elide_middle, fit, right, truncate, width};
use aitm_tui::viewers;
use common::*;
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MediaKeyCode, ModifierKeyCode,
};
use serde_json::{json, Value};

fn lines_text(lines: &[ratatui::text::Line<'_>]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
        .collect()
}

// ------------------------------------------------------------ model parsers

#[test]
fn flow_detail_from_json_tolerates_empty_and_wrongly_typed_input() {
    assert!(FlowDetail::from_json(&json!({})).is_none());
    assert!(FlowDetail::from_json(&json!({"id": 5})).is_none());
    assert!(FlowDetail::from_json(&json!([])).is_none());
    assert!(FlowDetail::from_json(&Value::Null).is_none());
    assert!(FlowDetail::from_json(&json!("f1")).is_none());

    let d = FlowDetail::from_json(&json!({
        "id":"x","kind":7,"request":"nope","response":[1],"client_conn":true,"server_conn":null,
        "meta":"m","messages":"f","intercept":42,"edited":"yes"
    }))
    .unwrap();
    assert_eq!(d.kind, FlowKind::Http);
    assert!(d.request.is_none());
    assert!(d.response.is_none());
    assert!(d.client_conn.is_none());
    assert!(d.server_conn.is_none());
    assert_eq!(d.meta, Meta::default());
    assert!(d.messages.is_empty());
    assert_eq!(d.intercept, Intercept::Observed);
    assert!(!d.edited);

    // Wrong types inside the messages: each bad field is dropped, not fatal.
    let d = FlowDetail::from_json(&json!({
        "id":"x",
        "request":{"method":1,"headers":[["only-one"],["a","b","c"],[1,2],"str",{"name":"n","value":"v"},{"name":"n"}],
                   "body":"***not base64***","status":"200","body_truncated":"true"},
        "response":{"status":70000,"headers":{"k":"v","n":1},"body":12}
    }))
    .unwrap();
    let req = d.request.unwrap();
    assert_eq!(req.method, None);
    assert_eq!(req.headers, vec![("n".to_string(), "v".to_string())]);
    assert!(req.body.is_empty(), "undecodable base64 is an empty body");
    assert!(!req.body_truncated);
    assert_eq!(req.status, None);
    let resp = d.response.unwrap();
    assert_eq!(resp.status, None, "70000 does not fit a status code");
    assert_eq!(resp.headers, vec![("k".to_string(), "v".to_string())]);
    assert!(resp.body.is_empty());
    assert_eq!(resp.content_type(), None);
    assert_eq!(resp.body_text(), Some(""));

    // Messages with missing fields (the core's `messages`, C1): an absent or
    // unknown direction is `None`, never guessed.
    let d = FlowDetail::from_json(
        &json!({"id":"w","kind":"websocket","messages":[{}, {"dir":"client_to_server","data":"aGk="}, 7]}),
    )
    .unwrap();
    assert_eq!(d.kind, FlowKind::WebSocket);
    assert_eq!(d.messages.len(), 3);
    assert_eq!(d.messages[0].dir, None);
    assert_eq!(d.messages[0].opcode, "text");
    assert_eq!(d.messages[0].timestamp, None);
    assert_eq!(d.messages[1].dir, Some(WsDir::ClientToServer));
    assert_eq!(d.messages[1].data, b"hi");
    assert_eq!(d.messages[2].dir, None);

    // Through the app: a malformed detail for a known flow leaves the row as it was.
    let mut app = sample_app(200, 50);
    let before = app.row("f41").unwrap().clone();
    assert!(
        before.time.is_some() && before.req_size.is_some(),
        "{before:?}"
    );
    let d = FlowDetail::from_json(&json!({"id":"f41","request":"nope","response":"nope"})).unwrap();
    let _ = app.on_bus(aitm_tui::action::BusEvent::Detail(Box::new(d)));
    let after = app.row("f41").unwrap();
    assert_eq!(after.method, before.method);
    assert_eq!(after.authority, before.authority);
    assert_eq!(after.status, before.status);
    assert_eq!(
        after.req_size, before.req_size,
        "absent messages leave the columns alone"
    );
    assert_eq!(after.time, None, "meta columns follow the latest detail");
    assert!(text_of(&app, 200, 50).contains("/api/products"));
}

#[test]
fn flow_summary_and_finding_parsers_tolerate_garbage() {
    assert!(FlowRow::from_summary(&json!({}), 1).is_none());
    assert!(FlowRow::from_summary(&json!({"id": null}), 1).is_none());
    assert!(FlowRow::from_summary(&json!("f1"), 1).is_none());
    let r = FlowRow::from_summary(
        &json!({"id":"x","status":"200","method":5,"kind":"websocket","messages":"many"}),
        9,
    )
    .unwrap();
    assert_eq!(r.status, None);
    assert_eq!(r.method, "WS");
    assert_eq!(r.scheme, "wss");
    assert_eq!(r.ws_messages, None);
    assert_eq!(r.url(), "wss://");
    assert_eq!(r.host(), "");
    assert_eq!(r.path_only(), "");
    assert_eq!(r.query(), None);
    assert!(!r.pending(), "a WebSocket flow is never 'pending'");
    assert_eq!(
        FlowRow::from_summary(&json!({"id":"y","status":70000}), 1)
            .unwrap()
            .status,
        None
    );
    assert_eq!(
        FlowRow::from_summary(&json!({"id":"z","status":-1}), 1)
            .unwrap()
            .status,
        None
    );
    let r = FlowRow::from_summary(&json!({"id":"q","intercept":"weird"}), 1).unwrap();
    assert_eq!(r.intercept, Intercept::Observed);
    assert!(r.pending());
    assert_eq!(r.method, "—");
    assert_eq!(
        FlowRow::from_summary(&json!({"id":"v","authority":"[::1]:8080"}), 1)
            .unwrap()
            .host(),
        "[::1]"
    );

    assert!(Finding::from_json(&json!({})).is_none());
    assert!(Finding::from_json(&json!({"poc_path": 1})).is_none());
    let f = Finding::from_json(
        &json!({"poc_path":"/p/x.yaml","severity":"BOGUS","evaluated":"nope","passed":"yes"}),
    )
    .unwrap();
    assert_eq!(f.title, "x");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.assertions.is_empty());
    assert!(!f.passed);
    assert_eq!(f.origin, Origin::Unknown);

    let mut a = AgentState::default();
    a.apply_status(&json!({}));
    assert_eq!(a.policy, None);
    a.apply_status(&json!({"policy":"all","log":[{"command":"x"},{"nope":1},"str"]}));
    assert_eq!(a.policy, Some(AgentPolicy::All));
    assert_eq!(a.log.len(), 1);
    assert_eq!(a.log[0].origin_name, "?");
    a.apply_status(&json!({"policy":"sideways"}));
    assert_eq!(a.policy, None);
    assert_eq!(AgentPolicy::parse("read-only"), Some(AgentPolicy::ReadOnly));
}

// ---------------------------------------------------------- byte decoding

#[test]
fn base64_and_percent_decoding_survive_odd_input() {
    assert_eq!(base64::decode(""), Some(vec![]));
    assert_eq!(base64::decode("===="), Some(vec![]));
    assert_eq!(base64::decode("A"), Some(vec![]), "six bits make no byte");
    assert_eq!(base64::decode("QQ"), Some(b"A".to_vec()));
    assert_eq!(base64::decode("Zm9v\r\n YmFy\t"), Some(b"foobar".to_vec()));
    assert_eq!(base64::decode("Zm9v!"), None);
    assert_eq!(base64::decode("Zm9vé"), None);
    let big = vec![0xabu8; 3 * 1024 * 1024];
    assert_eq!(base64::decode(&base64::encode(&big)).unwrap(), big);

    assert_eq!(viewers::percent_decode("a%20b+c"), "a b c");
    assert_eq!(viewers::percent_decode("%zz%4"), "%zz%4");
    assert_eq!(viewers::percent_decode("%"), "%");
    assert_eq!(viewers::percent_decode("%%"), "%%");
    assert_eq!(viewers::percent_decode("%C3%A9"), "é");
    assert_eq!(
        viewers::percent_decode("%E2%82"),
        "\u{fffd}",
        "an incomplete sequence is replaced"
    );
    assert_eq!(viewers::percent_decode("日本%20語"), "日本 語");
}

/// FINDING: `viewers::percent_decode` slices `&s[i + 1..i + 3]` by byte
/// offsets after a `%`; when a multi-byte character follows within those two
/// bytes the slice lands inside the character and `str` indexing panics.
/// The query string of any captured request reaches this through the Request
/// pane's Query tab (and a form body through the Body tab), so a client that
/// sends `GET /x?%aé=1` through the proxy crashes the operator's TUI.
#[test]
fn percent_decoding_survives_a_multibyte_character_after_the_percent_sign() {
    let (direct, via_query_tab) = quietly(|| {
        let direct = catch_unwind(|| viewers::percent_decode("%aé=1"));
        let mut app = connected_app(200, 50);
        let _ = app.on_bus(BusEvent::Flows(vec![summary(
            "evil",
            "GET",
            "api.shop-staging.test",
            "/search?q=%aé&x=1",
            Some(200),
            "observed",
        )]));
        app.selected = Some("evil".into());
        app.mode = Mode::Inspector;
        app.inspector.request_tab = aitm_tui::app::REQUEST_TABS
            .iter()
            .position(|t| *t == "Query")
            .unwrap();
        let via_query_tab = catch_unwind(AssertUnwindSafe(|| text_of(&app, 200, 50)));
        (direct, via_query_tab)
    });
    assert!(direct.is_ok(), "percent_decode(\"%aé=1\") panicked");
    assert!(
        via_query_tab.is_ok(),
        "rendering the Query tab of `/search?q=%aé&x=1` panicked"
    );
    assert!(via_query_tab.unwrap().contains("x = 1"));
}

// ------------------------------------------------------------- filter fuzz

#[test]
fn filter_parser_never_panics_and_names_each_error() {
    let inputs = [
        "~",
        "((",
        "~s xx",
        "\"",
        "'",
        ")",
        "&",
        "|",
        "!",
        "~u",
        "~m GET extra",
        "a b c",
        "((a))",
        "!(~m GET | ~s 2xx) & !~ws",
        "~ ~ ~",
        "~u \"\"",
        "\"\"",
        "~s 2xx",
        "~s x",
        "~s",
        "~h",
        "~b ",
        "~~",
        "~1",
        "~_x",
        "~u (a)",
        "~scope foo",
        "!!",
        "!!!~a",
        "~d *.",
        "~u ?",
        "~u *",
        "~u ***",
        "~u \"a | b\"",
        "a|",
        "|a",
        "a&",
        "&a",
        "()",
        "( )",
        "~c 2xx",
        "~code 200",
        "~client",
        "~mark",
        "~comment x y",
        "\t\t",
        "\n",
        "login\n",
        "~u über",
        "~u 日本",
        "~m gEt",
        "~s 99999999999999999999",
        "~s -1",
        "~s 2xxxx",
        "~u \\",
        "~u %",
        // Regex arguments (fix pass 1, I3) and their edges.
        "/",
        "//",
        "/(/",
        "~u //",
        "~u /(/",
        "~u /\\/",
        "~b /a/ /b/",
        "~m /GET/",
        "~d /(?i)x/",
        "~u /x{99999}/",
        "~u \"/x/\"",
        "/日本/",
    ];
    for s in inputs {
        let _ = filter::parse(s);
    }
    assert!(filter::parse("~u /(/")
        .unwrap_err()
        .starts_with("bad regex /(/: "));
    assert_eq!(
        filter::parse("~m /GET/").unwrap_err(),
        "`~m` takes a literal, not a regex"
    );
    assert_eq!(
        filter::parse(&format!("{}~a", "!".repeat(10_000))).unwrap_err(),
        "expression too deep"
    );
    assert!(
        filter::parse("~u /x{99999}/").is_err(),
        "a regex past the size limit is refused, not compiled"
    );
    assert_eq!(filter::parse("~").unwrap_err(), "`~` needs a name");
    assert_eq!(filter::parse("((").unwrap_err(), "expression ends early");
    assert_eq!(filter::parse("\"").unwrap_err(), "unterminated quote");
    assert_eq!(filter::parse(")").unwrap_err(), "unexpected `)`");
    assert_eq!(filter::parse("()").unwrap_err(), "unexpected `)`");
    assert_eq!(filter::parse("~u").unwrap_err(), "`~u` needs an argument");
    assert_eq!(filter::parse("~zz x").unwrap_err(), "unknown filter `~zz`");
    assert_eq!(filter::parse("&a").unwrap_err(), "unexpected `&`");
    assert_eq!(filter::parse("a|").unwrap_err(), "expression ends early");
    assert_eq!(filter::parse("(~m GET").unwrap_err(), "missing `)`");
    assert_eq!(filter::parse("").unwrap(), None);
    assert_eq!(filter::parse("\t \t").unwrap(), None);

    // `~s xx` is a status pattern that matches nothing; `~s 99999…` the same.
    let row = FlowRow::from_summary(
        &json!({"id":"x","method":"GET","scheme":"https","authority":"a.test","path":"/p","status":200}),
        1,
    )
    .unwrap();
    let ctx = filter::Ctx {
        detail: None,
        in_scope: true,
    };
    for e in [
        "~s xx",
        "~s 99999999999999999999",
        "~s -1",
        "~s 2xxxx",
        "~s x",
    ] {
        assert!(
            !filter::parse(e).unwrap().unwrap().matches(&row, &ctx),
            "{e}"
        );
    }
    assert!(filter::parse("~s 2xx")
        .unwrap()
        .unwrap()
        .matches(&row, &ctx));
    assert!(filter::parse("~s 200")
        .unwrap()
        .unwrap()
        .matches(&row, &ctx));
    // Wildcards on anything.
    for p in [
        "*", "***", "?", "a*b*c", "*.test", "**?**", "", "%", "\\", "日本",
    ] {
        let _ = filter::wild(p, &row.url());
        let _ = filter::wild(p, "");
    }
    assert!(filter::wild("", "anything"));
    assert!(filter::wild("*", ""));
    assert!(!filter::wild("?", ""));
    assert!(filter::wild("A.TEST", "https://a.test/p"));
    // The prompt applies live and swallows parse errors until Enter.
    let mut app = connected_app(200, 50);
    let _ = app.update(Action::FilterOpen);
    for c in "~m (".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert!(app.filter.is_none());
    let _ = app.update(Action::Submit);
    assert_eq!(
        app.mode,
        Mode::Prompt(PromptKind::Filter),
        "stays open on an error"
    );
    assert!(toast(&app).starts_with("filter: "), "{}", toast(&app));
}

// ------------------------------------------------------------ key sweep

fn every_key_code() -> Vec<KeyCode> {
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
        KeyCode::Insert,
        KeyCode::Null,
        KeyCode::Esc,
        KeyCode::CapsLock,
        KeyCode::ScrollLock,
        KeyCode::NumLock,
        KeyCode::PrintScreen,
        KeyCode::Pause,
        KeyCode::Menu,
        KeyCode::KeypadBegin,
        KeyCode::Media(MediaKeyCode::Play),
        KeyCode::Media(MediaKeyCode::MuteVolume),
        KeyCode::Modifier(ModifierKeyCode::LeftShift),
        KeyCode::Modifier(ModifierKeyCode::IsoLevel3Shift),
    ];
    v.extend((1..=24).map(KeyCode::F));
    v.extend((0x20u8..0x7f).map(|b| KeyCode::Char(char::from(b))));
    v.extend(
        [
            '\t',
            '\n',
            '\r',
            '\u{7f}',
            'é',
            '✋',
            '日',
            '\u{200b}',
            '\u{1F512}',
        ]
        .map(KeyCode::Char),
    );
    v
}

fn every_mode() -> Vec<Mode> {
    let mut v = vec![
        Mode::Flows,
        Mode::Inspector,
        Mode::Edit,
        Mode::Compose,
        Mode::Scope,
        Mode::Findings,
        Mode::Agent,
        Mode::Ca,
        Mode::Browser,
        Mode::Help,
        Mode::QuickLook,
    ];
    for k in [
        PromptKind::Palette,
        PromptKind::Filter,
        PromptKind::Comment,
        PromptKind::Mark,
        PromptKind::Pin,
        PromptKind::ScopeAdd,
        PromptKind::PocName,
        PromptKind::PocParam,
        PromptKind::PocTarget,
        PromptKind::PocVars,
        PromptKind::CaExport,
        PromptKind::Confirm,
    ] {
        v.push(Mode::Prompt(k));
    }
    v
}

/// The sample app put into `mode` the way the operator would get there.
fn app_in(mode: Mode) -> App {
    let mut app = sample_app(200, 50);
    match mode {
        Mode::Edit => {
            let _ = app.update(Action::Edit);
            assert_eq!(app.mode, Mode::Edit);
        }
        Mode::Compose => {
            let _ = app.update(Action::Compose);
        }
        Mode::Prompt(PromptKind::Palette) => {
            let _ = app.update(Action::PaletteOpen);
            for c in "fl".chars() {
                let _ = app.update(Action::Input(c));
            }
        }
        Mode::Prompt(PromptKind::Filter) => {
            let _ = app.update(Action::FilterOpen);
        }
        Mode::Prompt(PromptKind::PocName) => {
            let _ = app.update(Action::BuildPoc);
        }
        Mode::Prompt(PromptKind::PocParam) => {
            let _ = app.update(Action::BuildPoc);
            let _ = app.update(Action::Submit);
        }
        Mode::Prompt(PromptKind::PocTarget) => {
            app.mode = Mode::Findings;
            let _ = app.update(Action::PocRerun);
        }
        Mode::Prompt(PromptKind::PocVars) => {
            app.mode = Mode::Findings;
            let _ = app.update(Action::PocRerun);
            let _ = app.update(Action::Submit);
        }
        Mode::Prompt(PromptKind::CaExport) => {
            let _ = app.run_command("ca");
            let _ = app.update(Action::CaExportPrompt);
        }
        Mode::Prompt(PromptKind::Confirm) => {
            let _ = app.run_command("ca.install");
        }
        Mode::Ca => {
            let _ = app.run_command("ca");
        }
        other => app.mode = other,
    }
    assert_eq!(app.mode, mode);
    app
}

#[test]
fn key_map_returns_an_option_for_every_key_in_every_mode() {
    let codes = every_key_code();
    let mods = [
        KeyModifiers::NONE,
        KeyModifiers::SHIFT,
        KeyModifiers::CONTROL,
        KeyModifiers::ALT,
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        KeyModifiers::SUPER,
    ];
    let kinds = [
        KeyEventKind::Press,
        KeyEventKind::Repeat,
        KeyEventKind::Release,
    ];
    let mut mapped = 0usize;
    let mut total = 0usize;
    for mode in every_mode() {
        for code in &codes {
            for m in mods {
                for kind in kinds {
                    let mut key = KeyEvent::new(*code, m);
                    key.kind = kind;
                    let action = keys::map(key, mode);
                    total += 1;
                    if kind == KeyEventKind::Release {
                        assert_eq!(
                            action, None,
                            "{mode:?} {code:?} {m:?}: releases are ignored"
                        );
                    } else if action.is_some() {
                        mapped += 1;
                    }
                }
            }
        }
    }
    assert!(mapped > 0 && mapped < total);
    // Ctrl-C leaves from everywhere; Esc leaves every overlay.
    for mode in every_mode() {
        assert_eq!(keys::map(ctrl('c'), mode), Some(Action::Quit), "{mode:?}");
        if mode != Mode::Flows {
            assert_eq!(
                keys::map(press(KeyCode::Esc), mode),
                Some(Action::Back),
                "{mode:?}"
            );
        }
    }
}

/// Every mapped key, applied to the app in every mode, then drawn: no panic.
#[test]
fn reducer_and_renderer_survive_every_key_in_every_mode() {
    let codes = every_key_code();
    let mut failures = Vec::new();
    let mut applied = 0usize;
    quietly(|| {
        for mode in every_mode() {
            let base = app_in(mode);
            assert_eq!(
                text_of(&base, 200, 50).lines().count(),
                50,
                "{mode:?} draws the whole 200×50 screen"
            );
            for code in &codes {
                for m in [KeyModifiers::NONE, KeyModifiers::CONTROL] {
                    let Some(action) = keys::map(KeyEvent::new(*code, m), mode) else {
                        continue;
                    };
                    let mut app = base.clone();
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        let _ = app.update(action.clone());
                        let _ = app.update(Action::Resize(100, 30));
                        let _ = text_of(&app, 100, 30);
                    }));
                    applied += 1;
                    if let Err(e) = outcome {
                        let msg = e
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                            .unwrap_or_default();
                        failures.push(format!("{mode:?} + {code:?} {m:?} → {action:?}: {msg}"));
                    }
                }
            }
        }
    });
    assert!(applied > 500, "{applied}");
    assert!(
        failures.is_empty(),
        "{} of {applied} key applications panicked:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A deterministic random walk of 3 000 keys through the whole UI.
#[test]
fn a_random_key_walk_never_panics() {
    let codes = every_key_code();
    let mut app = sample_app(200, 50);
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut failure = None;
    quietly(|| {
        for step in 0..3000usize {
            let code = codes[(next() as usize) % codes.len()];
            let m = if next() % 7 == 0 {
                KeyModifiers::CONTROL
            } else {
                KeyModifiers::NONE
            };
            let key = KeyEvent::new(code, m);
            // Ctrl-C would only set should_quit; keep walking.
            let Some(action) = keys::map(key, app.mode) else {
                continue;
            };
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = app.update(action.clone());
                if step % 25 == 0 {
                    let (c, r) = match next() % 4 {
                        0 => (80, 24),
                        1 => (120, 30),
                        2 => (200, 50),
                        _ => (41, 5),
                    };
                    let _ = app.update(Action::Resize(c, r));
                    let _ = text_of(&app, c, r);
                }
            }));
            if let Err(e) = outcome {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_default();
                failure = Some(format!(
                    "step {step}: {key:?} in {:?} → {action:?}: {msg}",
                    app.mode
                ));
                break;
            }
        }
    });
    assert!(failure.is_none(), "{}", failure.unwrap());
    let _ = app.update(Action::Resize(200, 50));
    assert_eq!(
        text_of(&app, 200, 50).lines().count(),
        50,
        "the whole 200×50 screen still draws after the walk"
    );
}

#[test]
fn run_command_survives_odd_lines_and_reports_each_problem() {
    let mut app = sample_app(200, 50);
    // Two verbs carry their `tools/list` input schema, because the asserts
    // below ride on it: `flow.get` requires `id`; `flow.intercept` takes a
    // boolean `enabled`. Every other tool keeps the empty schema.
    for t in &mut app.tools {
        match t.name.as_str() {
            "flow.get" => {
                t.input_schema = json!({
                    "type": "object",
                    "properties": {"id": {"type": "string", "description": "The flow to summarize."}},
                    "required": ["id"]
                });
            }
            "flow.intercept" => {
                t.input_schema = json!({
                    "type": "object",
                    "properties": {"enabled": {"type": "boolean",
                                               "description": "true to arm (default), false to disarm."}}
                });
            }
            _ => {}
        }
    }
    let odd = [
        "",
        ":",
        "::",
        " : ",
        "scope",
        "scope add",
        "scope add ",
        "scope rm",
        "scope xyz",
        "poc",
        "poc run",
        "poc run ",
        "poc run x y z",
        "poc build",
        "layout",
        "layout sideways",
        "curl",
        "curl -X",
        "curl -H",
        "pin",
        "pin ",
        "intercept",
        "intercept off",
        "intercept maybe",
        "agent",
        "agent xyz",
        "findings run  x",
        "resume",
        "resume all",
        "kill",
        "replay",
        "compose",
        "copy",
        "auto",
        "refresh",
        "help",
        "flow.get",
        "flow.get id=f41",
        "flow.get id",
        "flow.get =",
        "flow.get id=f41 extra=1",
        "flow.intercept enabled=notabool",
        "flow.mark id=f41 marks=[1,2",
        "request.send authority=api.shop-staging.test body='a b'",
        "browser.navigate url=https://x",
        "nonsense",
        "\u{0}",
        "filter",
        "filter ~",
        "import",
        "import x",
        "日本語",
        "~m GET",
        // Fix pass 1 commands.
        "split",
        "export",
        "ca",
        "ca.install",
        "ca.install dry_run=true",
        "browser",
        "compose post-json",
        "compose ws",
        "compose nope",
        "compose ",
        "filter ~u /(/",
        "filter ~u /^https/",
    ];
    for cmd in odd {
        let _ = app.run_command(cmd);
        app.mode = Mode::Flows;
        app.confirm = None;
    }
    assert!(app.run_command("flow.get").is_empty());
    assert_eq!(toast(&app), "flow.get: missing required `id`");
    assert!(app.run_command("flow.get id").is_empty());
    assert_eq!(toast(&app), "flow.get: `id` is not key=value");
    assert!(app
        .run_command("flow.intercept enabled=notabool")
        .is_empty());
    assert!(
        toast(&app).starts_with("flow.intercept: enabled:"),
        "{}",
        toast(&app)
    );
    assert_eq!(
        app.run_command("flow.intercept enabled=true"),
        vec![aitm_tui::action::BusRequest::Call {
            name: "flow.intercept".into(),
            args: json!({"enabled": true})
        }]
    );
    assert!(app.run_command("nonsense").is_empty());
    assert_eq!(toast(&app), "unknown command `nonsense` (try :help)");
    assert_eq!(
        app.run_command("poc run x y z"),
        vec![aitm_tui::action::BusRequest::PocRun {
            poc_path: "x".into(),
            target: Some("y z".into()),
            vars: None
        }]
    );
    let _ = app.run_command("layout sideways");
    assert_eq!(app.layout, aitm_tui::app::Layout::Horizontal);
    assert_eq!(
        app.run_command("intercept maybe"),
        vec![aitm_tui::action::BusRequest::Intercept(true)]
    );
    assert!(!app.should_quit);
    let _ = app.run_command("quit");
    assert!(app.should_quit);
}

// ------------------------------------------------- compose / kv / edit

#[test]
fn compose_kv_and_edit_buffer_edge_cases() {
    let form = |url: &str, headers: &str| ComposeForm {
        method: "GET".into(),
        url: url.into(),
        headers: headers.into(),
        ..ComposeForm::default()
    };
    assert_eq!(
        form("nohost", "").to_send_args().unwrap_err(),
        "URL needs a scheme (http:// or https://)"
    );
    assert_eq!(
        form("https://", "").to_send_args().unwrap_err(),
        "URL needs a host"
    );
    assert_eq!(
        form("https://h.test", "bad header")
            .to_send_args()
            .unwrap_err(),
        "header `bad header` needs `name: value`"
    );
    assert_eq!(
        form("https://h.test", "").to_send_args().unwrap()["path"],
        "/"
    );
    assert_eq!(
        form("https://h.test", "").authority().as_deref(),
        Some("h.test")
    );
    assert_eq!(form("https://", "").authority(), None);
    assert_eq!(form("garbage", "").authority(), None);

    assert!(ComposeForm::from_curl("curl").is_none());
    assert!(ComposeForm::from_curl("curl -X").is_none());
    assert!(ComposeForm::from_curl("curl -H").is_none());
    assert!(ComposeForm::from_curl("curl -d").is_none());
    assert!(ComposeForm::from_curl("").is_none());
    let f = ComposeForm::from_curl("curl --data-raw '{\"a\":1}' https://h/").unwrap();
    assert_eq!(
        (f.method.as_str(), f.url.as_str(), f.body.as_str()),
        ("POST", "https://h/", "{\"a\":1}")
    );
    let f = ComposeForm::from_curl("curl -u user:pw -o out.bin -A ua https://h/x").unwrap();
    assert_eq!((f.method.as_str(), f.url.as_str()), ("GET", "https://h/x"));
    let f = ComposeForm::from_curl("curl --header 'A: 1' --request delete https://h/").unwrap();
    assert_eq!((f.method.as_str(), f.headers.as_str()), ("DELETE", "A: 1"));
    let f = ComposeForm::from_curl("curl \"https://h/a b\" --compressed -sS").unwrap();
    assert_eq!(f.url, "https://h/a b");

    assert_eq!(parse_kv_args("", None).unwrap(), json!({}));
    assert_eq!(
        parse_kv_args("a", None).unwrap_err(),
        "`a` is not key=value"
    );
    assert_eq!(
        parse_kv_args("k='a b' n=1 e= q==v", None).unwrap(),
        json!({"k":"a b","n":"1","e":"","q":"=v"})
    );
    let t = aitm_tui::action::ToolInfo {
        name: "t".into(),
        description: String::new(),
        input_schema: json!({"properties":{"id":{"type":"string"},"n":{"type":"integer"},"on":{"type":"boolean"},"o":{"type":"object"}},"required":["id"]}),
    };
    // Object arguments are quoted shell-style; bare braces lose their quotes.
    assert_eq!(
        parse_kv_args("id=x n=2 on=true o='{\"a\":1}'", Some(&t)).unwrap(),
        json!({"id":"x","n":2,"on":true,"o":{"a":1}})
    );
    assert!(parse_kv_args("id=x o={\"a\":1}", Some(&t))
        .unwrap_err()
        .starts_with("o: "));
    assert!(parse_kv_args("id=x n=two", Some(&t))
        .unwrap_err()
        .starts_with("n: "));
    assert_eq!(
        parse_kv_args("n=2", Some(&t)).unwrap_err(),
        "missing required `id`"
    );

    let e = EditBuffer::from_request("x", &Message::default());
    assert_eq!(e.lines, vec!["GET / HTTP/1.1", ""]);
    // An untouched body is never sent (byte-exact round trip), so there is
    // no `body` key for an empty body either; clearing every line changes
    // nothing about the (empty) body.
    assert_eq!(
        e.to_edits(),
        json!({"method":"GET","path":"/","headers":{}})
    );
    let mut empty = e.clone();
    empty.lines.clear();
    assert_eq!(empty.to_edits(), json!({"headers":{}}));
    assert!(empty.dirty());
    let bin = EditBuffer::from_request(
        "x",
        &Message {
            body: vec![0xff, 0xfe, 0x00],
            ..Message::default()
        },
    );
    assert_eq!(
        bin.lines[2],
        "<3 binary bytes — edit in hex is a follow-up>"
    );
    // A binary body is described, never sent back — even if the placeholder is edited.
    let mut bin_edited = bin.clone();
    bin_edited.lines[2] = "typed over".into();
    assert!(bin_edited.to_edits().get("body").is_none());
    // Editing at the ends of lines and across lines.
    let mut app = sample_app(200, 50);
    let _ = app.update(Action::Edit);
    for _ in 0..40 {
        let _ = app.update(Action::Right);
    }
    let _ = app.update(Action::Input('!'));
    assert!(app.edit.as_ref().unwrap().lines[0].ends_with("HTTP/2!"));
    let _ = app.update(Action::Home);
    let _ = app.update(Action::Backspace);
    let _ = app.update(Action::Up);
    let _ = app.update(Action::Up);
    for _ in 0..200 {
        let _ = app.update(Action::Down);
    }
    let _ = app.update(Action::End);
    let _ = app.update(Action::Enter);
    let _ = app.update(Action::Backspace);
    let _ = app.update(Action::Input('é'));
    let _ = app.update(Action::Left);
    let _ = app.update(Action::Input('✋'));
    let e = app.edit.as_ref().unwrap();
    assert!(
        e.lines.last().unwrap().ends_with("✋é"),
        "{:?}",
        e.lines.last()
    );
    assert!(e.dirty());
    assert!(scope_covers(&["".to_string()], "") && !scope_covers(&["".to_string()], "h"));
}

// ----------------------------------------------------- text and viewers

#[test]
fn text_helpers_and_viewers_survive_empty_and_wide_input() {
    assert_eq!(fit("", 0), "");
    assert_eq!(fit("abc", 0), "");
    assert_eq!(truncate("abc", 0), "");
    assert_eq!(truncate("abc", 1), "…");
    assert_eq!(right("abc", 0), "");
    assert_eq!(right("abc", 2), "a…");
    assert_eq!(fit("🔓🔓", 3), "🔓…");
    assert_eq!(width(&fit("🔓", 4)), 4);
    assert_eq!(elide_middle("abcdefghijklmnop", 8), "abcd…nop");
    let _ = elide_middle("🔓🔓🔓🔓🔓🔓", 8);
    assert_eq!(elide_middle("ab", 0), "");
    assert_eq!(elide_middle("abcdefghij", 7), "abcdef…");

    let t = theme();
    assert_eq!(lines_text(&viewers::headers(&t, &[])), ["(no headers)"]);
    assert_eq!(lines_text(&viewers::query(&t, "/x")), ["(no query string)"]);
    assert!(viewers::query(&t, "/x?").is_empty());
    assert_eq!(lines_text(&viewers::query(&t, "/x?&&a")), ["a = "]);
    let long_key = format!("/x?{}=1", "k".repeat(80));
    assert!(lines_text(&viewers::query(&t, &long_key))[0].ends_with(" = 1"));
    assert!(viewers::hex::dump(&t, &[], 16).is_empty());
    assert_eq!(
        viewers::hex::dump(&t, b"abc", 0).len(),
        3,
        "per_line 0 is treated as 1"
    );
    assert_eq!(
        lines_text(&viewers::diff::unified(&t, "", "")),
        ["(identical)"]
    );
    let _ = viewers::diff::side_by_side(&t, "a\n", "b\n", 0);
    assert_eq!(
        lines_text(&viewers::raw(&t, &Message::default(), true)),
        ["GET / HTTP/1.1", "", "0 B"]
    );
    assert_eq!(
        lines_text(&viewers::raw(&t, &Message::default(), false)),
        ["HTTP/1.1 —", "", "0 B"]
    );
    assert!(viewers::facts(&t, &[]).is_empty());

    // Deep nesting stays within serde_json's recursion limit: not JSON, so
    // the body falls back to plain text instead of overflowing the stack.
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    assert!(viewers::json::pretty(&t, &deep).is_none());
    assert!(viewers::json::tree(&t, &deep, &HashSet::new()).is_none());
    assert!(viewers::json::container_paths(&deep).is_empty());
    let msg = Message {
        headers: vec![("content-type".into(), "application/json".into())],
        body: deep.clone().into_bytes(),
        ..Message::default()
    };
    assert_eq!(lines_text(&viewers::body(&t, &msg)), [deep.as_str()]);
    let shallow = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert_eq!(viewers::json::pretty(&t, &shallow).unwrap().len(), 200);
    assert_eq!(
        lines_text(&viewers::json::tree(&t, "null", &HashSet::new()).unwrap()),
        ["  null"]
    );
    assert!(viewers::json::pretty(&t, "").is_none());
    assert_eq!(
        lines_text(&viewers::json::pretty(&t, "\"\\u0000\\n\"").unwrap()),
        ["\"\\u0000\\n\""]
    );

    assert_eq!(viewers::image::dimensions(b"\x89PNG\r\n\x1a\n\0\0"), None);
    assert_eq!(viewers::image::dimensions(b"\xff\xd8\xff"), None);
    assert_eq!(
        viewers::image::dimensions(b"\xff\xd8\xff\xe0\x00\x10JFIF"),
        Some((0, 0, "JPEG"))
    );
    assert_eq!(
        viewers::image::dimensions(b"\xff\xd8\x00garbage-after-soi"),
        Some((0, 0, "JPEG"))
    );
    assert_eq!(viewers::image::dimensions(b"GIF89a"), None);
    assert_eq!(
        viewers::image::dimensions(b"RIFF\0\0\0\0WEBPVP8 "),
        Some((0, 0, "WebP"))
    );
    assert_eq!(
        lines_text(&viewers::image::placeholder(&t, &[], "image/png"))[0],
        "[image image/png · 0 B · o to open]"
    );
}
