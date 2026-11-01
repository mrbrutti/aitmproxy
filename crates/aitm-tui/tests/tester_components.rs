//! Tester (stage 5) — the §2.7 component vocabulary as the TUI draws it, the
//! "needs core follow-up F*n*" rule (§2.10(c): never silent), and §4.2's
//! "`tools/list` drives features". Each test states which commitment it proves.

mod common;

use aitm_tui::action::ToolSchema as _;
use aitm_tui::action::{Action, BusEvent, BusRequest, Level, Param, ToolInfo};
use aitm_tui::app::{App, Chip, Mode, Pane, PromptKind, SidebarItem, REQUEST_TABS, RESPONSE_TABS};
use aitm_tui::caps::TermCaps;
use aitm_tui::fixture::Fixture;
use aitm_tui::fixture_app;
use aitm_tui::keys;
use aitm_tui::model::{AgentPolicy, AgentState, FlowDetail, Message};
use aitm_tui::tokens::{color, glyph};
use aitm_tui::viewers;
use common::*;
use crossterm::event::KeyCode;
use ratatui::style::Modifier;
use serde_json::json;

fn span_text(line: &ratatui::text::Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

fn lines_text(lines: &[ratatui::text::Line<'_>]) -> Vec<String> {
    lines.iter().map(span_text).collect()
}

/// The fixture app at 200×50 with `id` selected and the inspector on `pane`/`tab`.
fn inspector_on(id: &str, pane: Pane, tab: &str) -> App {
    let mut app = fixture_app(200, 50);
    app.selected = Some(id.into());
    app.mode = Mode::Inspector;
    app.inspector.pane = pane;
    let tabs = match pane {
        Pane::Request => &REQUEST_TABS[..],
        Pane::Response => &RESPONSE_TABS[..],
    };
    let i = tabs
        .iter()
        .position(|t| *t == tab)
        .unwrap_or_else(|| panic!("tab {tab}"));
    match pane {
        Pane::Request => app.inspector.request_tab = i,
        Pane::Response => app.inspector.response_tab = i,
    }
    app
}

// ------------------------------------------------------ §2.7 flow list

/// §2.7 "Flow list → States": selected, pending, paused, killed, replay,
/// out of scope, agent tick; plus the method and status badges in the list.
#[test]
fn flow_list_rows_show_every_state_from_the_foundation() {
    let app = fixture_app(200, 50);
    let theme = theme();
    let buf = draw(&app, 200, 50);
    let text = to_text_lines(&buf);
    let row = |needle: &str| -> (usize, &str) {
        text.iter()
            .enumerate()
            .find(|(_, l)| l.contains(needle))
            .map(|(y, l)| (y, l.as_str()))
            .unwrap_or_else(|| panic!("no row containing {needle:?}"))
    };
    let amber = theme.fg(&color::intercept::BASE).fg.unwrap();
    let teal = theme.agent().fg.unwrap();
    let dim = theme.text_tertiary().fg.unwrap();
    let ink = theme.text_primary().fg.unwrap();

    // Selected (f50): the `active` fill across the row, never the accent.
    let (y, line) = row("/api/auth/login");
    let url_x = col_of(line, "https://").unwrap();
    let sel_bg = theme.selection().bg.unwrap();
    assert_eq!(cell(&buf, url_x, y).bg, sel_bg);
    assert_eq!(cell(&buf, url_x + 60, y).bg, sel_bg);
    assert_ne!(sel_bg, theme.accent().fg.unwrap());
    // Paused: amber dot, amber left tick, `Paused` badge in the Status column.
    assert!(line.contains("Paused"), "{line}");
    assert_eq!(cell(&buf, url_x - 10, y).symbol(), "▎", "left edge tick");
    assert_eq!(cell(&buf, url_x - 10, y).fg, amber);
    assert_eq!(cell(&buf, url_x - 8, y).symbol(), glyph::RECORD);
    assert_eq!(cell(&buf, url_x - 8, y).fg, amber);
    assert!(line.contains(glyph::COMPOSE), "edited pencil: {line}");

    // Pending (f52): amber dot, grey dash status, `…` duration.
    let (y, line) = row("/assets/hero.webp");
    let url_x = col_of(line, "https://").unwrap();
    assert_eq!(cell(&buf, url_x - 8, y).fg, amber);
    let after_url = &line[line.find("hero.webp").unwrap()..];
    assert!(after_url.contains(" — "), "dash status: {line}");
    assert!(after_url.contains("…"), "pending duration: {line}");
    assert_eq!(
        cell(&buf, url_x - 10, y).symbol(),
        " ",
        "no tick on a human pending flow"
    );

    // Killed (f49): grey, URL struck through, `killed` status.
    let (y, line) = row("/api/account/delete");
    let url_x = col_of(line, "https://").unwrap();
    assert!(line.contains("killed"), "{line}");
    assert!(cell(&buf, url_x, y)
        .modifier
        .contains(Modifier::CROSSED_OUT));
    assert_eq!(
        cell(&buf, url_x, y).fg,
        theme.fg(&color::status::KILLED).fg.unwrap()
    );
    assert_eq!(
        cell(&buf, url_x - 8, y).fg,
        theme.fg(&color::status::KILLED).fg.unwrap()
    );

    // Replay (f46): `↻` after `#`, agent tick, `agent` in the Origin column.
    let (y, line) = row(&format!("7{}", glyph::REPLAY));
    assert!(line.contains("/api/orders?page=3"), "{line}");
    let url_x = col_of(line, "https://").unwrap();
    assert_eq!(cell(&buf, url_x - 10, y).symbol(), "▎");
    assert_eq!(cell(&buf, url_x - 10, y).fg, teal);
    assert!(line.trim_end().ends_with("agent"), "origin column: {line}");
    // The other agent-originated flow (f48) also carries the tick; f41 does not.
    let (y, line) = row("/api/search?q=");
    assert_eq!(
        cell(&buf, col_of(line, "https://").unwrap() - 10, y).fg,
        teal
    );
    let (_, line) = row("/api/products?category");
    assert!(!line.contains("agent"), "{line}");

    // Out of scope (f44): the whole row at text.tertiary.
    let (y, line) = row("telemetry.vendor-analytics.example");
    for needle in [
        "https://",
        "/v2/batch",
        "Safari",
        "POST",
        "204",
        "11:05:01.772",
        "143 ms",
        "37 B",
    ] {
        let x = col_of(line, needle).unwrap();
        assert_eq!(cell(&buf, x, y).fg, dim, "dim {needle:?}: {line}");
    }
    // In scope (f41): host in ink.
    let (y, line) = row("/api/products?category");
    assert_eq!(cell(&buf, col_of(line, "https://").unwrap(), y).fg, ink);

    // Method badge colours come from the method pairs; status text from its class.
    let (y, line) = row("/api/account/delete");
    let m_x = col_of(line, "DELETE").unwrap();
    assert_eq!(cell(&buf, m_x, y).fg, theme.method("DELETE").fg.unwrap());
    let (y, line) = row("    6 https");
    assert!(line.contains("502"), "f45: {line}");
    let s_x = col_of(line, "502").unwrap();
    assert_eq!(
        cell(&buf, s_x, y).fg,
        theme.status(Some(502), false).fg.unwrap()
    );
    let (y, line) = row("/api/products?category");
    let s_x = col_of(line, " 200 ").unwrap() + 1;
    assert_eq!(
        cell(&buf, s_x, y).fg,
        theme.status(Some(200), false).fg.unwrap()
    );

    // WebSocket (f47): `WS` badge and the frame count in the Response column
    // (f40, its handshake, shares the path; the scheme tells them apart).
    let (_, line) = row("wss://api.shop-staging.test/ws/notifications");
    assert!(line.contains(" WS "), "{line}");
    assert!(line.contains(&format!("3 {}", glyph::WEBSOCKET)), "{line}");

    // SSL column: open padlock when decrypted, warning when not.
    let (_, line) = row("/api/products?category");
    assert!(line.contains(glyph::LOCK_OPEN), "{line}");
    let (_, line) = row("/api/health");
    assert!(line.contains("⚠"), "pinned upstream, not decrypted: {line}");
}

fn to_text_lines(buf: &ratatui::buffer::Buffer) -> Vec<String> {
    aitm_tui::snapshot::to_text(buf)
        .lines()
        .map(str::to_string)
        .collect()
}

/// §2.7 "Method & status badges" in the summary strip: `200 OK` pill,
/// `Paused`, `killed`, `pending`, `WS`.
#[test]
fn summary_strip_badges_follow_the_flow_state() {
    for (id, badge) in [
        ("f41", " 200 OK "),
        ("f45", " 502 Bad Gateway "),
        ("f53", " 422 Unprocessable Content "),
        ("f50", " Paused · request "),
        ("f49", " killed "),
        ("f52", " pending "),
        ("f47", " WS "),
    ] {
        let app = inspector_on(id, Pane::Request, "Headers");
        let text = text_of(&app, 200, 50);
        assert!(text.contains(badge), "{id} should show {badge:?}:\n{text}");
    }
    let app = inspector_on("f44", Pane::Request, "Headers");
    assert!(text_of(&app, 200, 50).contains("OUT OF SCOPE"));
}

/// §2.8: new flows do not steal the selection unless Auto-select is on; a
/// vanished flow drops its selection; `#` numbers are stable for the session.
#[test]
fn auto_select_and_selection_stability() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = connect(&mut app, CORE_TOOLS, None);
    let a = summary("a", "GET", "h.test", "/a", Some(200), "observed");
    let b = summary("b", "GET", "h.test", "/b", Some(200), "observed");
    let c = summary("c", "GET", "h.test", "/c", None, "observed");
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone()]));
    assert_eq!(app.selected.as_deref(), Some("a"), "first flow is selected");
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone(), b.clone()]));
    assert_eq!(
        app.selected.as_deref(),
        Some("a"),
        "a new flow does not steal selection"
    );

    assert_eq!(
        keys::map(press(KeyCode::Char('t')), Mode::Flows),
        Some(Action::ToggleAutoSelect)
    );
    let _ = app.update(Action::ToggleAutoSelect);
    assert_eq!(toast(&app), "Auto-select on");
    assert!(text_of(&app, 160, 30).contains("Auto-select ●"));
    let _ = app.on_bus(BusEvent::Flows(vec![a.clone(), b.clone(), c.clone()]));
    assert_eq!(
        app.selected.as_deref(),
        Some("c"),
        "auto-select follows the newest"
    );
    // Moving by hand turns auto-select off again.
    let _ = app.update(Action::Up);
    assert!(!app.auto_select);
    assert_eq!(app.selected.as_deref(), Some("b"));

    // b vanishes: selection cleared, a and c keep their numbers.
    let _ = app.on_bus(BusEvent::Flows(vec![a, c]));
    assert_eq!(app.selected, None);
    assert_eq!(
        app.flows
            .iter()
            .map(|r| (r.id.as_str(), r.seq))
            .collect::<Vec<_>>(),
        vec![("a", 1), ("c", 3)]
    );
    // Navigation with no selection lands on the newest.
    let _ = app.update(Action::Down);
    assert_eq!(app.selected.as_deref(), Some("c"));
    let _ = app.update(Action::Home);
    assert_eq!(app.selected.as_deref(), Some("a"));
    let _ = app.update(Action::End);
    assert_eq!(app.selected.as_deref(), Some("c"));
}

/// §2.6 sidebar groups: Apps/Domains group the list with headers; `]`/`[` step.
#[test]
fn sidebar_items_group_the_list_and_open_the_panels() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char(']')), Mode::Flows),
        Some(Action::SidebarNext)
    );
    assert_eq!(app.sidebar, SidebarItem::All);
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Apps);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("▾ obscura  7"), "{text}");
    assert!(text.contains("▾ curl  3"), "{text}");
    assert!(text.contains("▾ python3  2"), "{text}");
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Domains);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("▾ api.shop-staging.test  11"), "{text}");
    assert!(text.contains("▾ cdn.shop-staging.test  2"), "{text}");
    // Domains lists the hosts under the item in the sidebar.
    assert!(
        line_with(&text, "◦ api.shop-staging.t…").is_some(),
        "{text}"
    );

    // Scope filters the list (§2.7 "The flow list's Scope sidebar item filters
    // to in-scope"); the panel is `S` / `:scope`.
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Scope);
    assert_eq!(app.mode, Mode::Flows);
    assert_eq!(visible_ids(&app).len(), 14, "f44 is out of scope");
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Findings);
    assert_eq!(app.mode, Mode::Findings);
    // Browser: the view opens and asks the bus for the page (task 10); the
    // only F-number on it is the live viewport/tabs line.
    let reqs = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Browser);
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Browser — embedded obscura"), "{text}");
    assert!(!text.contains("not built"), "{text}");
    assert!(
        text.contains("live viewport and tabs need core follow-up F14"),
        "{text}"
    );
    assert_eq!(
        keys::map(press(KeyCode::Esc), Mode::Browser),
        Some(Action::Back)
    );
    let _ = app.update(Action::SidebarNext);
    assert!(toast(&app).contains("F8"), "{}", toast(&app));
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.mode, Mode::Agent);
    // Scan (scanner-integration Stage 1): the Scan view opens when the bus
    // offers `scan.discover`.
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Scan, "the Scan surface");
    assert_eq!(app.mode, Mode::Scan);
    let _ = app.update(Action::SidebarNext);
    assert_eq!(app.sidebar, SidebarItem::Pinned, "wraps around");
    let _ = app.update(Action::SidebarNext);
    assert!(toast(&app).contains("F10"), "Saved: {}", toast(&app));
    let _ = app.update(Action::SidebarPrev);
    let _ = app.update(Action::SidebarPrev);
    assert_eq!(app.sidebar, SidebarItem::Scan);
}

/// §2.7 "working-session pinning": `p` pins the selected host to the top.
#[test]
fn pinning_a_host_sorts_it_first_and_shows_in_the_sidebar() {
    let mut app = fixture_app(200, 50);
    app.selected = Some("f44".into());
    assert_eq!(
        keys::map(press(KeyCode::Char('p')), Mode::Flows),
        Some(Action::Pin)
    );
    let _ = app.update(Action::Pin);
    assert_eq!(toast(&app), "Pinned telemetry.vendor-analytics.example");
    assert_eq!(visible_ids(&app)[0], "f44");
    let text = text_of(&app, 200, 50);
    let pinned: String = line_with(&text, "  Pinned")
        .unwrap()
        .chars()
        .take(28)
        .collect();
    assert!(pinned.ends_with("1│"), "{pinned:?}");
    assert!(text.contains("◎ telemetry.vendor-an…"), "{text}");
    let _ = app.update(Action::Pin);
    assert_eq!(toast(&app), "Unpinned telemetry.vendor-analytics.example");
    assert_eq!(visible_ids(&app)[0], "f40", "arrival order again");
    let _ = app.run_command("pin cdn.shop-staging.test");
    assert_eq!(&visible_ids(&app)[..2], ["f43", "f52"]);
}

// --------------------------------------------------- §2.7 chips and filter

/// §2.7 "Content-type chip bar": one active chip, `1…9 0` select, layered
/// under the filter; Esc clears the filter first, then the chip.
#[test]
fn chips_quick_filter_the_list_and_render_as_active() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char('7')), Mode::Flows),
        Some(Action::ChipIndex(6))
    );
    let _ = app.update(Action::ChipIndex(6));
    assert_eq!(app.chip, Chip::Json);
    assert_eq!(visible_ids(&app), ["f41", "f42", "f46", "f53"]);
    assert!(text_of(&app, 200, 50)
        .lines()
        .nth(1)
        .unwrap()
        .contains(" JSON "));
    let _ = app.update(Action::ChipIndex(3));
    assert_eq!(visible_ids(&app), ["f47"]);
    let _ = app.update(Action::ChipIndex(5));
    assert_eq!(app.chip, Chip::H2);
    assert_eq!(
        visible_ids(&app),
        ["f41", "f42", "f43", "f50", "f51", "f52"]
    );
    let _ = app.update(Action::ChipIndex(12));
    assert_eq!(app.chip, Chip::Document);
    assert_eq!(visible_ids(&app), ["f45", "f48"]);
    let _ = app.update(Action::ChipNext);
    assert_eq!(app.chip, Chip::Media);
    assert!(
        visible_ids(&app).is_empty(),
        "no media response was captured"
    );
    let _ = app.update(Action::ChipPrev);
    let _ = app.update(Action::ChipPrev);
    assert_eq!(app.chip, Chip::GraphQl);

    // Layered: chip Json + filter ~m PUT → f42 only; Esc clears filter, then chip.
    let _ = app.update(Action::ChipIndex(6));
    let _ = app.run_command("filter ~m PUT");
    assert_eq!(visible_ids(&app), ["f42"]);
    let chips = text_of(&app, 200, 50).lines().nth(1).unwrap().to_string();
    assert!(
        chips.contains("~m PUT") && chips.contains("Esc clears"),
        "{chips}"
    );
    let _ = app.update(Action::Back);
    assert!(app.filter.is_none());
    assert_eq!(app.chip, Chip::Json);
    let _ = app.update(Action::Back);
    assert_eq!(app.chip, Chip::All);
    assert_eq!(visible_ids(&app).len(), 15);
}

/// §2.7 "Filter bar": the mitmproxy-style grammar is the portable text form;
/// every atom the module documents, evaluated over the fixture.
#[test]
fn filter_expressions_select_the_documented_rows() {
    let mut app = fixture_app(200, 50);
    let cases: &[(&str, &[&str])] = &[
        ("~paused", &["f50", "f51"]),
        ("~killed", &["f49"]),
        ("~ws", &["f47"]),
        ("~replay", &["f46"]),
        ("~a", &["f46", "f48"]),
        ("~e", &["f50"]),
        ("~oos", &["f44"]),
        ("~q", &["f52"]),
        ("~d cdn", &["f43", "f52"]),
        ("~t html", &["f45", "f48"]),
        ("~client curl", &["f45", "f49", "f50"]),
        ("~comment retried", &["f46"]),
        ("~mark red", &["f48"]),
        ("~mark sky", &["f42"]),
        ("~s 4xx", &["f53"]),
        ("~s 304", &["f43"]),
        ("~s 5xx", &["f45"]),
        ("~b correct-horse", &["f50"]),
        ("~h x-request-id", &["f41"]),
        ("~m HEAD | login", &["f50", "f54"]),
        // f40 is the 101 upgrade; f47's detail names the handshake method,
        // so the WebSocket flow is a GET too.
        (
            "!~s 2xx ~m GET",
            &["f40", "f43", "f45", "f47", "f51", "f52"],
        ),
        ("products & ~s 200", &["f41"]),
        ("(~m PUT | ~m PATCH) & ~d api", &["f42", "f53"]),
        ("~u \"cart/items/42\"", &["f42"]),
        ("~u api/*/login", &["f50"]),
        ("~url orders ~method GET !~replay", &["f45"]),
    ];
    for (expr, want) in cases {
        let _ = app.run_command(&format!("filter {expr}"));
        assert!(app.filter.is_some(), "{expr} parses");
        assert_eq!(visible_ids(&app), *want, "{expr}");
    }
    let _ = app.run_command("filter ~scope");
    assert_eq!(visible_ids(&app).len(), 14);
    let _ = app.run_command("filter ~zz");
    assert_eq!(toast(&app), "filter: unknown filter `~zz`");
    // `/` opens the prompt prefilled with the current expression.
    let _ = app.run_command("filter ~m GET");
    assert_eq!(
        keys::map(press(KeyCode::Char('/')), Mode::Flows),
        Some(Action::FilterOpen)
    );
    let _ = app.update(Action::FilterOpen);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Filter));
    assert_eq!(app.prompt, "~m GET");
    let text = text_of(&app, 200, 50);
    assert!(text.contains(" / ~m GET"), "{text}");
    assert!(text.contains("filter: editing…"), "{text}");
}

// ------------------------------------------------------------ §2.7 palette

/// §2.7 / §4.2: the palette is built from `tools/list` (name + description),
/// the built-in `:` commands and flows by URL; a tool with required
/// parameters asks for `key=value` arguments.
#[test]
fn palette_offers_tools_commands_and_flows() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char(':')), Mode::Flows),
        Some(Action::PaletteOpen)
    );
    let _ = app.update(Action::PaletteOpen);
    let items = app.palette_items();
    let detail = items
        .iter()
        .find(|i| i.label == "flow.detail")
        .expect("every tool is a palette item");
    assert!(
        detail.detail.starts_with("(F5) Headers, bodies"),
        "{}",
        detail.detail
    );
    assert!(items.iter().any(|i| i.label == ":scope add <host>"));
    assert!(
        !items.iter().any(|i| i.detail == "flow"),
        "flows need two typed chars"
    );

    for c in "orders".chars() {
        let _ = app.update(Action::Input(c));
    }
    let items = app.palette_items();
    let flow = items
        .iter()
        .find(|i| i.detail == "flow")
        .expect("flows match by URL");
    assert!(
        flow.label
            .starts_with("#6 GET https://api.shop-staging.test/api/orders"),
        "{}",
        flow.label
    );
    let text = text_of(&app, 200, 50);
    assert!(text.contains(" palette "), "{text}");
    assert!(text.contains(" : orders"), "{text}");
    assert!(
        text.contains("#6 GET https://api.shop-stagi… flow"),
        "{text}"
    );
    // Pick the flow: it becomes the selection.
    app.palette_cursor = items.iter().position(|i| i.detail == "flow").unwrap();
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.selected.as_deref(), Some("f45"));
    assert_eq!(app.mode, Mode::Flows);

    // Fuzzy over tool names and descriptions.
    let _ = app.update(Action::PaletteOpen);
    for c in "fdet".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert!(app.palette_items().iter().any(|i| i.label == "flow.detail"));
    let _ = app.update(Action::Back);

    // A tool with required params: the first Enter asks for arguments.
    let _ = app.update(Action::PaletteOpen);
    for c in "flow.get".chars() {
        let _ = app.update(Action::Input(c));
    }
    app.palette_cursor = app
        .palette_items()
        .iter()
        .position(|i| i.label == "flow.get")
        .unwrap();
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.prompt, "flow.get ");
    assert_eq!(
        toast(&app),
        "flow.get: type key=value arguments, then Enter"
    );
    for c in "id=f41".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::Call {
            name: "flow.get".into(),
            args: json!({"id": "f41"})
        }]
    );
    // A missing required argument is refused before it reaches the bus.
    let _ = app.update(Action::PaletteOpen);
    for c in "flow.get body=inline".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(toast(&app), "flow.get: missing required `id`");
    // Ctrl-F is the other spelling of the filter prompt.
    assert_eq!(keys::map(ctrl('f'), Mode::Flows), Some(Action::FilterOpen));
}

/// FINDING (minor): `keys.rs::flows` runs `nav(key.code)` before the
/// modifier-guarded arms, and `nav` maps `Char('k')` to `Up` regardless of
/// modifiers, so the `KeyCode::Char('k') if ctrl => PaletteOpen` arm is
/// unreachable. The README and the help overlay promise `Ctrl-K` (§2.7 ⌘K).
#[test]
fn ctrl_k_opens_the_palette_as_the_readme_promises() {
    assert_eq!(keys::map(ctrl('k'), Mode::Flows), Some(Action::PaletteOpen));
}

// ----------------------------------------------------- §2.7 inspector

/// §2.7 "Inspector": request tabs Headers · Cookies · Query · Body · Raw ·
/// Summary · Timing · Connection and response tabs Headers · Set-Cookie ·
/// Body · Raw · JSON · Hex · Diff, each drawing its viewer. Cookies and
/// Set-Cookie parse the served headers live (I17a); only Timing draws its F5
/// follow-up sentence.
#[test]
fn inspector_tabs_draw_their_viewers() {
    assert_eq!(REQUEST_TABS.len(), 8);
    assert_eq!(RESPONSE_TABS.len(), 7);
    let cases: &[(Pane, &str, &str, &[&str])] = &[
        (
            // f41 sends `cookie: session=9f1c…`: parsed live onto its row.
            Pane::Request,
            "Cookies",
            "f41",
            &["session = 9f1c…"],
        ),
        (
            Pane::Request,
            "Timing",
            "f41",
            &["Timing need core follow-up F5"],
        ),
        (
            // f41's response sets no cookie: the live empty state, not F5.
            Pane::Response,
            "Set-Cookie",
            "f41",
            &["(no cookies set)"],
        ),
        (
            Pane::Request,
            "Headers",
            "f41",
            &[
                "user-agent : Mozilla/5.0 (obscura)",
                "cookie     : session=9f1c…",
            ],
        ),
        (
            Pane::Request,
            "Query",
            "f41",
            &["category = electronics", "limit    = 20"],
        ),
        (Pane::Request, "Body", "f41", &["0 B"]),
        (
            Pane::Request,
            "Body",
            "f42",
            &["\"qty\": 2,", "\"gift_wrap\": false"],
        ),
        (
            Pane::Request,
            "Raw",
            "f41",
            &[
                "GET /api/products?category=electronics&limit=20 HTTP/2",
                "accept: application/json",
            ],
        ),
        (
            Pane::Request,
            "Summary",
            "f41",
            &["f41", "in scope", "89 ms", "created"],
        ),
        (
            Pane::Request,
            "Connection",
            "f41",
            &[
                "127.0.0.1:52101",
                "yes (decrypted)",
                "203.0.113.10:443",
                "obscura",
                "h2",
            ],
        ),
        (Pane::Request, "Connection", "f44", &["— (not reached)"]),
        (
            Pane::Response,
            "Headers",
            "f41",
            &[
                "content-type  : application/json; charset=utf-8",
                "x-request-id  : c1a4f0",
            ],
        ),
        (
            Pane::Response,
            "Body",
            "f41",
            &["\"items\": [", "\"Noise-cancelling headphones\""],
        ),
        (
            Pane::Response,
            "Body",
            "f45",
            &["<html><head><title>502 Bad Gateway"],
        ),
        (
            Pane::Response,
            "Raw",
            "f41",
            &["HTTP/2 200", "cache-control: no-store"],
        ),
        (
            Pane::Response,
            "JSON",
            "f41",
            &["▾ {", "▾   \"items\": [", "$"],
        ),
        (Pane::Response, "JSON", "f45", &["body is not JSON"]),
        // The response pane is 86 cells wide here: 8 bytes per row (16 from 100 cells).
        (
            Pane::Response,
            "Hex",
            "f41",
            &[
                "00000000  7b 0a 20 20  22 69 74 65  │ {·  \"ite",
                "00000008  6d 73 22 3a  20 5b 0a 20  │ ms\": [·",
            ],
        ),
        (
            Pane::Response,
            "Diff",
            "f41",
            &["Diff needs a response and an earlier flow to the same endpoint"],
        ),
        (
            Pane::Response,
            "Headers",
            "f50",
            &["No response yet — the request is paused."],
        ),
        (
            Pane::Response,
            "Body",
            "f49",
            &["No response — the request was killed."],
        ),
        (
            Pane::Response,
            "Body",
            "f52",
            &["No response yet — the request is in flight."],
        ),
    ];
    for (pane, tab, id, wants) in cases {
        let app = inspector_on(id, *pane, tab);
        let text = text_of(&app, 200, 50);
        for want in *wants {
            assert!(
                text.contains(want),
                "{id} {pane:?}/{tab}: missing {want:?}\n{text}"
            );
        }
    }
    // Keyboard: Tab toggles the pane, ←/→ step tabs and wrap.
    let mut app = inspector_on("f41", Pane::Request, "Headers");
    assert_eq!(
        keys::map(press(KeyCode::Tab), Mode::Inspector),
        Some(Action::InspectorPaneToggle)
    );
    let _ = app.update(Action::InspectorPaneToggle);
    assert_eq!(app.inspector.pane, Pane::Response);
    assert_eq!(
        keys::map(press(KeyCode::Right), Mode::Inspector),
        Some(Action::InspectorTabNext)
    );
    // The response pane opens on Body (index 2 since Set-Cookie was added):
    // three steps back wrap to Diff.
    assert_eq!(RESPONSE_TABS[app.inspector.response_tab], "Body");
    let _ = app.update(Action::InspectorTabPrev);
    let _ = app.update(Action::InspectorTabPrev);
    assert_eq!(RESPONSE_TABS[app.inspector.response_tab], "Headers");
    let _ = app.update(Action::InspectorTabPrev);
    assert_eq!(RESPONSE_TABS[app.inspector.response_tab], "Diff");
    // The focused pane's title takes the accent.
    let buf = draw(&app, 200, 50);
    let text = aitm_tui::snapshot::to_text(&buf);
    let y = line_index(&text, "Response  Headers").unwrap();
    let x = col_of(text.lines().nth(y).unwrap(), "Response").unwrap();
    assert_eq!(cell(&buf, x, y).fg, theme().accent().fg.unwrap());
}

/// §2.7 "WebSocket" / §3.7 "WS flow with frame list": the frames of a
/// WebSocket flow are reachable in the inspector.
///
/// FINDING: `ui/inspector.rs` only lists frames inside `pending_response`,
/// which runs when the response message is absent. A recorded WebSocket flow
/// carries its `101` handshake as the response, so every Response tab shows
/// the handshake (Headers) or `0 B` (Body) and the frames are never drawn.
#[test]
fn websocket_frames_are_listed_in_the_inspector() {
    let mut found = false;
    for tab in RESPONSE_TABS {
        let app = inspector_on("f47", Pane::Response, tab);
        let text = text_of(&app, 200, 50);
        if text.contains("\"type\":\"subscribe\"") {
            found = true;
        }
    }
    for tab in REQUEST_TABS {
        let app = inspector_on("f47", Pane::Request, tab);
        if text_of(&app, 200, 50).contains("\"type\":\"subscribe\"") {
            found = true;
        }
    }
    let mut app = inspector_on("f47", Pane::Response, "Body");
    app.mode = Mode::QuickLook;
    if text_of(&app, 200, 50).contains("\"type\":\"subscribe\"") {
        found = true;
    }
    assert!(
        found,
        "no inspector tab or quick-look shows f47's three frames"
    );
}

/// §2.9/§2.10(c): "diff is unified under 120 cols", side by side at 120+.
/// The implementation keys on the response pane's width: unified when the
/// pane is narrower than 120 cells, side by side when it is at least 120.
#[test]
fn diff_is_unified_in_narrow_panes_and_side_by_side_in_wide_ones() {
    // f46 repeats f45 (same method, host, path): the Diff tab compares them.
    let mut app = inspector_on("f46", Pane::Response, "Diff");
    let text = text_of(&app, 200, 50);
    assert!(text.contains("vs flow #6 (11:05:03.890)"), "{text}");
    // 200 columns with the sidebar: the response pane is 86 cells → unified.
    assert!(
        text.contains("- <html><head><title>502 Bad Gateway"),
        "{text}"
    );
    assert!(text.contains("+ {"), "{text}");
    assert!(!text.contains(" │ {"), "{text}");

    // Full-screen below 120 columns: unified too.
    let _ = app.update(Action::Resize(100, 40));
    let text = text_of(&app, 100, 40);
    assert!(text.contains("- <html>"), "{text}");
    assert!(text.contains("+ {"), "{text}");

    // 300 columns, sidebar hidden: the pane is 150 cells → side by side.
    let _ = app.update(Action::Resize(300, 60));
    let _ = app.update(Action::ToggleSidebar);
    let text = text_of(&app, 300, 60);
    let paired = line_with(&text, "502 Bad Gateway").expect("old body on the left");
    assert!(paired.contains(" │ "), "{paired}");
    assert!(
        paired.trim_end().ends_with('{'),
        "new body on the right: {paired}"
    );
    assert!(!text.contains("- <html>"), "{text}");

    // The viewer functions themselves.
    let t = theme();
    assert_eq!(
        lines_text(&viewers::diff::unified(&t, "a\nb\n", "a\nc\n")),
        vec!["  a", "- b", "+ c"]
    );
    assert_eq!(
        lines_text(&viewers::diff::side_by_side(&t, "a\nb\n", "a\nc\n", 4)),
        vec!["a    │ a   ", "b    │ c   "]
    );
}

/// §2.7 body viewers by content: pretty JSON, form table, image placeholder
/// (§2.10(c) "no inline images"), hex for bytes that are not UTF-8, the
/// `truncated` notice, `0 B` for an empty body.
#[test]
fn body_viewer_dispatches_on_content_type_and_bytes() {
    let t = theme();
    let msg = |ct: &str, body: &[u8]| Message {
        headers: vec![("Content-Type".into(), ct.into())],
        body: body.to_vec(),
        ..Message::default()
    };

    // JSON by content type, and by shape when the type lies.
    assert_eq!(
        lines_text(&viewers::body(&t, &msg("application/json", br#"{"a":1}"#)))[0],
        "{"
    );
    assert_eq!(
        lines_text(&viewers::body(&t, &msg("text/plain", br#"[1,2]"#))),
        vec!["[", "  1,", "  2", "]"]
    );
    // Form bodies become the query table.
    assert_eq!(
        lines_text(&viewers::body(
            &t,
            &msg(
                "application/x-www-form-urlencoded",
                b"a=1&b=hello+world&c=%2Fx"
            )
        )),
        vec!["a = 1", "b = hello world", "c = /x"]
    );
    // Images: the placeholder with dimensions, never the bytes.
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&1200u32.to_be_bytes());
    png.extend_from_slice(&800u32.to_be_bytes());
    png.extend_from_slice(&[0u8; 500]);
    let lines = lines_text(&viewers::body(&t, &msg("image/png", &png)));
    assert_eq!(lines[0], "[image 1200×800 PNG · 524 B · o to open]");
    assert!(lines[1].contains("kitty or sixel"));
    let lines = lines_text(&viewers::body(&t, &msg("image/svg+xml", b"<svg/>")));
    assert_eq!(lines[0], "[image image/svg+xml · 6 B · o to open]");
    // Not UTF-8 → hex: offset · bytes · ASCII.
    let lines = lines_text(&viewers::body(
        &t,
        &msg("application/octet-stream", &[0xff, 0xfe, 0x00, 0x41, 0x42]),
    ));
    assert_eq!(
        lines,
        vec!["00000000  ff fe 00 41 42                                    │ ···AB"]
    );
    // Invalid UTF-8 even with a text content type still goes to hex.
    let lines = lines_text(&viewers::body(
        &t,
        &msg("application/json", &[0x7b, 0xff, 0x7d]),
    ));
    assert!(lines[0].starts_with("00000000  7b ff 7d"), "{lines:?}");
    // Empty body prints a real zero (§2.8 "a real 0 B body is 0 B").
    assert_eq!(
        lines_text(&viewers::body(&t, &msg("application/json", b""))),
        vec!["0 B"]
    );
    // Truncated bodies carry the notice first.
    let mut cut = msg("text/plain", b"hello\nworld");
    cut.body_truncated = true;
    let lines = lines_text(&viewers::body(&t, &cut));
    assert!(
        lines[0].starts_with("⚠ body truncated by the proxy's capture cap"),
        "{lines:?}"
    );
    assert_eq!(&lines[1..], ["hello", "world"]);

    // Through the app: an image response shows the placeholder on the Body tab
    // and the Hex tab still shows the bytes.
    let mut app = fixture_app(200, 50);
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "img",
        "GET",
        "cdn.shop-staging.test",
        "/hero.png",
        Some(200),
        "observed",
    )]));
    let d = FlowDetail::from_json(&json!({
        "id":"img","kind":"http",
        "request":{"method":"GET","path":"/hero.png","headers":[]},
        "response":{"status":200,"headers":[["content-type","image/png"]],"body": aitm_tui::base64::encode(&png)},
    }))
    .unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    app.selected = Some("img".into());
    app.mode = Mode::Inspector;
    app.inspector.pane = Pane::Response;
    app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == "Body").unwrap();
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("[image 1200×800 PNG · 524 B · o to open]"),
        "{text}"
    );
    assert!(
        !text.contains("IHDR"),
        "no raw bytes on the Body tab: {text}"
    );
    app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == "Hex").unwrap();
    assert!(text_of(&app, 200, 50).contains("00000000  89 50 4e 47"));
    // `o` is the documented way out (§2.9): the bytes go to a private temp
    // file and the run loop hands it to the desktop.
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("an image body is openable");
    assert!(
        target.path.ends_with("aitm-tui-img.png"),
        "{}",
        target.path.display()
    );
    assert_eq!(std::fs::read(&target.path).unwrap(), png);
    assert!(
        toast(&app).ends_with("aitm-tui-img.png — opening"),
        "{}",
        toast(&app)
    );
    let _ = std::fs::remove_file(&target.path);
    // The list's chip bar classifies it as Media.
    app.mode = Mode::Flows;
    let _ = app.update(Action::ChipIndex(13));
    assert_eq!(visible_ids(&app), ["img"]);
}

/// §2.7 "Space quick-look body": the body of the selection in a floating box.
#[test]
fn quick_look_shows_the_body_and_help_lists_the_keys() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char(' ')), Mode::Flows),
        Some(Action::QuickLook)
    );
    let _ = app.update(Action::QuickLook);
    assert_eq!(app.mode, Mode::QuickLook);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("#11 POST https://auth.shop-staging.test/api/auth/login"),
        "{text}"
    );
    assert!(
        text.contains("\"password\": \"correct-horse-battery\""),
        "paused: the request body: {text}"
    );
    assert_eq!(
        keys::map(press(KeyCode::Esc), Mode::QuickLook),
        Some(Action::Back)
    );
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);

    assert_eq!(
        keys::map(press(KeyCode::Char('?')), Mode::Flows),
        Some(Action::Help)
    );
    let _ = app.update(Action::Help);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("aitm-tui · keys and commands"), "{text}");
    assert!(text.contains("arm / disarm intercept"), "{text}");
    assert!(text.contains(":scope add <host>"), "{text}");
    assert!(text.contains("Any key closes this help."), "{text}");
    assert_eq!(
        keys::map(press(KeyCode::Char('x')), Mode::Help),
        Some(Action::Back)
    );
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);
}

// ------------------------------------------------- §2.7 intercept bar

/// §2.7 "Intercept / breakpoint bar": hidden when disarmed, the quiet
/// armed-but-empty line, the saturated bar with the oldest paused flow and
/// its verbs, the selected paused row retargeting the verbs, Edit's verbs.
#[test]
fn intercept_bar_has_three_states_and_targets_the_selection() {
    // Disarmed, nothing paused: no bar at all.
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(160, 40));
    let _ = connect(&mut app, CORE_TOOLS, Some("127.0.0.1:8080"));
    app.scope = vec!["h.test".into()];
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/a",
        Some(200),
        "observed",
    )]));
    let text = text_of(&app, 160, 40);
    assert!(!text.contains("Intercept armed"), "{text}");
    assert!(!text.contains("Resume all"), "{text}");
    assert!(!text.contains("intercept armed"), "pill: {text}");

    // Armed, nothing paused: the quiet tint line and the F3 note for rules.
    assert_eq!(
        keys::map(press(KeyCode::Char('i')), Mode::Flows),
        Some(Action::ToggleIntercept)
    );
    assert_eq!(
        app.update(Action::ToggleIntercept),
        vec![BusRequest::Intercept(true)]
    );
    let _ = app.on_bus(BusEvent::CallOk {
        name: "flow.intercept".into(),
        value: json!(true),
    });
    assert_eq!(toast(&app), "Intercept armed — every request pauses");
    let buf = draw(&app, 160, 40);
    let text = aitm_tui::snapshot::to_text(&buf);
    let y = line_index(&text, "Intercept armed — every request pauses here").expect("quiet bar");
    let line = text.lines().nth(y).unwrap();
    assert!(line.contains("[i] Disarm"), "{line}");
    assert!(line.contains("Rules… needs core follow-up F3"), "{line}");
    let x = col_of(line, "Intercept").unwrap();
    assert_eq!(
        cell(&buf, x, y).bg,
        theme().intercept_armed_quiet().bg.unwrap()
    );
    assert!(
        text.lines().next().unwrap().contains("intercept armed"),
        "pill turns amber"
    );
    // The bar sits directly above the status bar when there is no inspector.
    let _ = app.update(Action::Resize(100, 30));
    let text = text_of(&app, 100, 30);
    assert_eq!(line_index(&text, "Intercept armed"), Some(28), "{text}");

    // Paused flows: the saturated bar, the oldest first, the verbs.
    let mut app = fixture_app(200, 50);
    app.selected = Some("f41".into());
    let text = text_of(&app, 200, 50);
    let bar = line_with(&text, "2 paused  ").unwrap();
    assert!(
        bar.contains("POST https://auth.shop-staging.test/api/auth/login"),
        "oldest: {bar}"
    );
    assert_eq!(app.intercept_target().map(|r| r.id.as_str()), Some("f50"));
    assert_eq!(
        app.update(Action::Resume),
        vec![BusRequest::Resume("f50".into())]
    );
    // Selecting the other paused row retargets the bar.
    app.selected = Some("f51".into());
    let text = text_of(&app, 200, 50);
    assert!(line_with(&text, "2 paused  ")
        .unwrap()
        .contains("GET https://api.shop-staging.test/api/me"));
    assert_eq!(
        app.update(Action::Kill),
        vec![BusRequest::Kill("f51".into())]
    );
    assert_eq!(
        app.update(Action::ResumeAll),
        vec![
            BusRequest::Resume("f50".into()),
            BusRequest::Resume("f51".into())
        ]
    );
    // `:intercept off` disarms through the bus.
    assert_eq!(
        app.run_command("intercept off"),
        vec![BusRequest::Intercept(false)]
    );
    let _ = app.on_bus(BusEvent::Intercept(false));
    assert!(!app.intercept_armed);
    // Paused rows keep the bar even when disarmed.
    assert!(text_of(&app, 200, 50).contains("2 paused  "));

    // Edit: the bar shows Apply & Resume, the editor marks changed lines.
    app.selected = Some("f50".into());
    assert_eq!(
        keys::map(press(KeyCode::Char('e')), Mode::Flows),
        Some(Action::Edit)
    );
    let _ = app.update(Action::Edit);
    assert_eq!(app.mode, Mode::Edit);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("[^S Apply & Resume] [^R Revert] [Esc Cancel]"),
        "{text}"
    );
    assert!(text.contains("editing"), "{text}");
    assert!(text.contains("POST /api/auth/login HTTP/2"), "{text}");
    assert!(text.contains("no edits yet"), "{text}");
    assert_eq!(
        keys::map(press(KeyCode::Char('X')), Mode::Edit),
        Some(Action::Input('X'))
    );
    let _ = app.update(Action::Input('X'));
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("~ XPOST /api/auth/login HTTP/2"),
        "changed gutter: {text}"
    );
    assert!(text.contains("edits pending"), "{text}");
    assert!(text.contains("^S Apply & Resume"), "status bar: {text}");
    assert_eq!(keys::map(ctrl('r'), Mode::Edit), Some(Action::RevertEdit));
    let _ = app.update(Action::RevertEdit);
    assert!(!app.edit.as_ref().unwrap().dirty());
    assert_eq!(
        keys::map(ctrl('s'), Mode::Edit),
        Some(Action::ApplyAndResume)
    );
    assert_eq!(
        app.update(Action::ApplyAndResume),
        vec![BusRequest::Resume("f50".into())],
        "clean buffer: resume only"
    );
    assert_eq!(app.mode, Mode::Flows);
    // Esc cancels back to the inspector and drops the buffer.
    let _ = app.update(Action::Edit);
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Inspector);
    assert!(app.edit.is_none());
}

// ------------------------------------------------------- §2.7 compose

/// §2.7 "Compose / repeat": full-screen form, cURL import, Edit & repeat
/// prefill, the scope pre-check (§4.6) before `request.send`.
#[test]
fn compose_form_imports_curl_prefills_from_flows_and_prechecks_scope() {
    let mut app = fixture_app(200, 50);
    let reqs = app.run_command(
        r#"curl -X PUT 'https://api.shop-staging.test/api/cart/items/42' -H "Content-Type: application/json" -d '{"qty":2}'"#,
    );
    assert!(reqs.is_empty());
    assert_eq!(app.mode, Mode::Compose);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Compose request"), "{text}");
    assert!(text.contains("PUT"), "{text}");
    assert!(
        text.contains("https://api.shop-staging.test/api/cart/items/42"),
        "{text}"
    );
    assert!(text.contains("Content-Type: application/json"), "{text}");
    assert!(text.contains("{\"qty\":2}"), "{text}");
    assert!(text.contains("api.shop-staging.test is in scope"), "{text}");
    assert!(text.contains("^S Send (request.send)"), "{text}");

    // Send: Ctrl-S or Ctrl-Enter from any field.
    assert_eq!(
        keys::map(ctrl('s'), Mode::Compose),
        Some(Action::ComposeSend)
    );
    assert_eq!(
        keys::map(
            crossterm::event::KeyEvent::new(
                KeyCode::Enter,
                crossterm::event::KeyModifiers::CONTROL
            ),
            Mode::Compose
        ),
        Some(Action::ComposeSend)
    );
    let reqs = app.update(Action::ComposeSend);
    assert_eq!(
        reqs,
        vec![BusRequest::Send(json!({
            "method":"PUT","scheme":"https","authority":"api.shop-staging.test","path":"/api/cart/items/42",
            "headers":{"Content-Type":"application/json"},"body":"{\"qty\":2}"
        }))]
    );
    assert_eq!(app.mode, Mode::Flows);
    assert_eq!(app.compose_history.len(), 1);
    // The result arrives as a new flow and is selected.
    let _ = app.on_bus(BusEvent::CallOk {
        name: "request.send".into(),
        value: json!("f55"),
    });
    assert_eq!(app.selected.as_deref(), Some("f55"));
    assert_eq!(toast(&app), "request.send → new flow f55");

    // Out of scope: the form says so and Send is refused with the reason.
    let _ = app.run_command("curl https://evil.example/x -d a=1");
    assert_eq!(app.mode, Mode::Compose);
    assert_eq!(app.compose.method, "POST");
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("evil.example is out of scope — add it with :scope add"),
        "{text}"
    );
    assert!(text.contains("1 sent this session"), "{text}");
    assert!(app.update(Action::ComposeSend).is_empty());
    assert_eq!(
        toast(&app),
        "Out of scope — add `evil.example` to scope to send"
    );
    assert_eq!(app.mode, Mode::Compose, "stays on the form");
    let _ = app.update(Action::Back);

    // Edit & repeat: `n` prefills from the selection.
    app.selected = Some("f42".into());
    assert_eq!(
        keys::map(press(KeyCode::Char('n')), Mode::Flows),
        Some(Action::Compose)
    );
    let _ = app.update(Action::Compose);
    assert_eq!(app.compose.method, "PUT");
    assert_eq!(
        app.compose.url,
        "https://api.shop-staging.test/api/cart/items/42"
    );
    assert!(
        app.compose
            .headers
            .contains("content-type: application/json"),
        "{}",
        app.compose.headers
    );
    assert_eq!(app.compose.body, r#"{"qty": 2, "gift_wrap": false}"#);
    // Tab/Enter step through the fields; typing edits the active one.
    assert_eq!(app.compose.field, 1);
    let _ = app.update(Action::Submit);
    assert_eq!(app.compose.field, 2);
    let _ = app.update(Action::Up);
    let _ = app.update(Action::Up);
    assert_eq!(app.compose.field, 0);
    let _ = app.update(Action::Backspace);
    let _ = app.update(Action::Backspace);
    let _ = app.update(Action::Backspace);
    for c in "patch".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(app.compose.method, "patch");
    assert_eq!(app.compose.to_send_args().unwrap()["method"], "PATCH");
    // Repeat (`r`) replays unchanged; a WebSocket flow cannot.
    app.mode = Mode::Flows;
    assert_eq!(
        keys::map(press(KeyCode::Char('r')), Mode::Flows),
        Some(Action::Replay)
    );
    assert_eq!(
        app.update(Action::Replay),
        vec![BusRequest::Replay("f42".into())]
    );
    app.selected = Some("f47".into());
    assert!(app.update(Action::Replay).is_empty());
    assert!(toast(&app).contains("F9"), "{}", toast(&app));
    // A bad curl line is reported.
    let _ = app.run_command("curl");
    assert_eq!(toast(&app), "could not parse that curl command line");
}

// ------------------------------------------------------- §2.7 scope panel

/// §2.7 "Scope panel (scope-as-authorisation)": entries with counts, hosts
/// seen but out of scope, `a` adds (a human action), `d` removes via F12.
#[test]
fn scope_panel_lists_entries_counts_and_out_of_scope_hosts() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char('S')), Mode::Flows),
        Some(Action::OpenScope)
    );
    let _ = app.update(Action::OpenScope);
    assert_eq!(app.mode, Mode::Scope);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Scope — the authorised hosts"), "{text}");
    assert!(
        line_with(&text, "api.shop-staging.test")
            .unwrap()
            .contains("11 flows"),
        "{text}"
    );
    assert!(
        line_with(&text, "auth.shop-staging.test")
            .unwrap()
            .contains("1 flows"),
        "{text}"
    );
    assert!(
        line_with(&text, "cdn.shop-staging.test")
            .unwrap()
            .contains("2 flows"),
        "{text}"
    );
    assert!(text.contains("Seen but out of scope:"), "{text}");
    assert!(
        text.contains("telemetry.vendor-analytics.example (1)"),
        "{text}"
    );
    assert!(
        text.contains(" a add · d remove · Esc back"),
        "fixture has scope.remove: {text}"
    );

    // `a` → the add prompt → scope.add; back on the panel afterwards.
    assert_eq!(
        keys::map(press(KeyCode::Char('a')), Mode::Scope),
        Some(Action::ScopeAddPrompt)
    );
    let _ = app.update(Action::ScopeAddPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::ScopeAdd));
    assert!(text_of(&app, 200, 50).contains("a human action"));
    for c in "*.other.test".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::ScopeAdd("*.other.test".into())]
    );
    assert_eq!(app.mode, Mode::Scope);
    let _ = app.on_bus(BusEvent::CallOk {
        name: "scope.add".into(),
        value: json!("*.other.test"),
    });
    assert_eq!(toast(&app), "Scope + *.other.test");
    let _ = app.on_bus(BusEvent::Scope(vec![
        "api.shop-staging.test".into(),
        "*.other.test".into(),
    ]));
    assert_eq!(app.in_scope_count(), 11);

    // `d` removes the entry under the cursor (scope.remove is on this bus).
    let _ = app.update(Action::Down);
    assert_eq!(app.scope_cursor, 1);
    assert_eq!(
        keys::map(press(KeyCode::Char('d')), Mode::Scope),
        Some(Action::ScopeRemoveSelected)
    );
    assert_eq!(
        app.update(Action::ScopeRemoveSelected),
        vec![BusRequest::ScopeRemove("*.other.test".into())]
    );
    // Without scope.remove the control is labelled F12.
    app.tools.retain(|t| t.name != "scope.remove");
    assert!(app.update(Action::ScopeRemoveSelected).is_empty());
    assert_eq!(toast(&app), "scope.remove needs core follow-up F12");
    assert!(text_of(&app, 200, 50).contains("d remove (needs core follow-up F12)"));
    // Every mutating verb on an out-of-scope flow is refused with the host.
    app.mode = Mode::Flows;
    app.selected = Some("f44".into());
    for action in [Action::Replay, Action::BuildPoc] {
        assert!(app.update(action).is_empty());
        assert_eq!(
            toast(&app),
            "Out of scope — add `telemetry.vendor-analytics.example` to scope to act"
        );
    }
}

// ---------------------------------------------------- §2.7 findings panel

/// §2.7 "PoC panel (Findings)": list with severity and verdict, detail with
/// capture, screenshot placeholder, assertions, YAML; Enter opens the capture;
/// `r` runs again; a `poc.run` result lands at the top.
#[test]
fn findings_panel_lists_runs_and_opens_the_capture() {
    let mut app = fixture_app(200, 50);
    assert_eq!(
        keys::map(press(KeyCode::Char('F')), Mode::Flows),
        Some(Action::OpenFindings)
    );
    let _ = app.update(Action::OpenFindings);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Findings — PoCs and runs"), "{text}");
    let first = line_with(&text, "Reflected XSS in /api/search q").unwrap();
    assert!(first.contains("✓") && first.contains("high"), "{first}");
    let second = line_with(&text, "IDOR on /api/cart/items/{id}").unwrap();
    assert!(
        second.contains("✗") && second.contains("medium"),
        "{second}"
    );
    assert!(
        text.contains("capture f48  (⏎ opens it in the inspector)"),
        "{text}"
    );
    assert!(
        text.contains("[screenshot · pocs/reflected-xss-search.png · o to open]"),
        "{text}"
    );
    assert!(text.contains(" Assertions"), "{text}");
    assert!(text.contains("✓ status == 200"), "{text}");
    assert!(
        text.contains("name: Reflected XSS in /api/search q"),
        "YAML: {text}"
    );
    assert!(text.contains("export needs core follow-up F13"), "{text}");
    // Two runs plus the library-only third PoC (C8: `poc.list` is files).
    assert!(text.contains("3 findings"), "status bar: {text}");

    // Enter opens the finding capture in the inspector.
    assert_eq!(
        keys::map(press(KeyCode::Enter), Mode::Findings),
        Some(Action::Enter)
    );
    let _ = app.update(Action::Enter);
    assert_eq!(app.selected.as_deref(), Some("f48"));
    assert_eq!(app.mode, Mode::Inspector);
    assert!(text_of(&app, 200, 50).contains("onerror=alert(1)"));

    // `r` on the second finding asks for a target and runs poc.run.
    let _ = app.update(Action::OpenFindings);
    let _ = app.update(Action::Down);
    assert_eq!(app.finding_cursor, 1);
    let text = text_of(&app, 200, 50);
    assert!(text.contains(" no screenshot"), "{text}");
    assert!(text.contains("✗ dsl: body.item_id != 42"), "{text}");
    assert_eq!(
        keys::map(press(KeyCode::Char('r')), Mode::Findings),
        Some(Action::PocRerun)
    );
    let _ = app.update(Action::PocRerun);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocTarget));
    for c in "https://staging2.test".chars() {
        let _ = app.update(Action::Input(c));
    }
    // Target, then vars (§2.7 "Run again … editable target/vars"); blank = none.
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocVars));
    assert!(text_of(&app, 200, 50).contains(" vars: "));
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::PocRun {
            poc_path: "pocs/idor-cart-items.yaml".into(),
            target: Some("https://staging2.test".into()),
            vars: None
        }]
    );
    assert_eq!(app.mode, Mode::Findings);
    let result = json!({"passed": false, "finding_capture": "f42", "poc_path": "pocs/idor-cart-items.yaml",
        "evaluated": [{"assertion": "status == 200", "matched": true}], "severity": "medium",
        "target": "https://staging2.test", "at": "2026-10-27T12:00:00.000Z", "origin": "human"});
    let _ = app.on_bus(BusEvent::CallOk {
        name: "poc.run".into(),
        value: result,
    });
    assert_eq!(app.findings.len(), 3);
    assert_eq!(app.findings[0].target, "https://staging2.test");
    assert_eq!(app.finding_cursor, 0);
    assert_eq!(toast(&app), "PoC failed: idor-cart-items");

    // `P` builds a PoC from the selected flow via the name prompt.
    app.mode = Mode::Flows;
    app.selected = Some("f48".into());
    assert_eq!(
        keys::map(press(KeyCode::Char('P')), Mode::Flows),
        Some(Action::BuildPoc)
    );
    let _ = app.update(Action::BuildPoc);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocName));
    for c in "Reflected XSS".chars() {
        let _ = app.update(Action::Input(c));
    }
    // Name, then param (`poc.build {flow_id, name, param}`, §4.3).
    assert!(app.update(Action::Submit).is_empty());
    assert_eq!(app.mode, Mode::Prompt(PromptKind::PocParam));
    assert!(text_of(&app, 200, 50).contains(" poc param: "));
    for c in "q".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::PocBuild {
            flow_id: "f48".into(),
            name: Some("Reflected XSS".into()),
            param: Some("q".into())
        }]
    );
    let _ = app.on_bus(BusEvent::CallOk {
        name: "poc.build".into(),
        value: json!("pocs/reflected-xss.yaml"),
    });
    assert_eq!(toast(&app), "PoC written: pocs/reflected-xss.yaml");
    // A capture that is no longer in the store is reported, not opened.
    app.findings[0].finding_capture = Some("gone".into());
    let _ = app.update(Action::OpenFindings);
    let _ = app.update(Action::Home);
    app.finding_cursor = 0;
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Findings);
    assert_eq!(toast(&app), "finding capture is not in the flow store");
}

// ------------------------------------------------------- §2.7 agent toggle

/// §2.7 "Agent toggle" (F1/F2): teal when the agent may act, grey when
/// paused; the panel sets the policy and lists the activity log with agent
/// rows in teal; without `agent.status` the control is labelled F1.
#[test]
fn agent_toggle_and_panel_follow_the_policy() {
    let mut app = fixture_app(200, 50);
    let theme = theme();
    let buf = draw(&app, 200, 50);
    let toolbar = aitm_tui::snapshot::to_text(&buf)
        .lines()
        .next()
        .unwrap()
        .to_string();
    let x = col_of(&toolbar, "Agent ●").unwrap();
    assert_eq!(
        cell(&buf, x, 0).fg,
        theme.agent().fg.unwrap(),
        "teal while the agent may act"
    );

    assert_eq!(
        keys::map(press(KeyCode::Char('@')), Mode::Flows),
        Some(Action::OpenAgent)
    );
    let _ = app.update(Action::OpenAgent);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Agent (MCP) — policy and activity"), "{text}");
    assert!(
        text.contains("policy: all tools · 14 actions in the last minute · 1 client(s)"),
        "{text}"
    );
    assert!(text.contains("● 1 all tools"), "{text}");
    assert!(text.contains("○ 3 paused"), "{text}");
    let log = line_with(&text, "flow.replay").expect("activity log row");
    assert!(
        log.contains("mcp") && log.contains("id=f45") && log.contains("ok → f46"),
        "{log}"
    );
    assert!(text.contains("refused: agent cannot widen scope"), "{text}");
    assert!(
        text.contains("flow.intercept")
            && line_with(&text, "enabled=true").unwrap().contains("tui"),
        "{text}"
    );
    // Agent rows in teal, the TUI's own row not.
    let buf = draw(&app, 200, 50);
    let text = aitm_tui::snapshot::to_text(&buf);
    let y = line_index(&text, "flow.replay").unwrap();
    let x = col_of(text.lines().nth(y).unwrap(), "mcp").unwrap();
    assert_eq!(cell(&buf, x, y).fg, theme.agent().fg.unwrap());
    let y = line_index(&text, "enabled=true").unwrap();
    let x = col_of(text.lines().nth(y).unwrap(), "tui").unwrap();
    assert_ne!(cell(&buf, x, y).fg, theme.agent().fg.unwrap());

    // `3` pauses the agent through the bus; the toolbar and sidebar follow.
    assert_eq!(
        keys::map(press(KeyCode::Char('3')), Mode::Agent),
        Some(Action::AgentSet(AgentPolicy::Paused))
    );
    assert_eq!(
        app.update(Action::AgentSet(AgentPolicy::Paused)),
        vec![BusRequest::AgentSet(AgentPolicy::Paused)]
    );
    let mut paused = AgentState::default();
    paused.apply_status(&json!({"policy":"paused","actions_last_minute":0,"connected_clients":1}));
    let _ = app.on_bus(BusEvent::Agent(paused));
    assert!(text_of(&app, 200, 50).contains("● 3 paused"));
    // Back on the flow list: toolbar and sidebar reflect the pause.
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Flows);
    let buf = draw(&app, 200, 50);
    let text = aitm_tui::snapshot::to_text(&buf);
    let toolbar = text.lines().next().unwrap();
    assert!(toolbar.contains("Agent ● paused · 0/min"), "{toolbar}");
    let x = col_of(toolbar, "Agent ●").unwrap();
    assert_eq!(
        cell(&buf, x, 0).fg,
        theme.text_tertiary().fg.unwrap(),
        "grey when paused"
    );
    let sidebar: String = line_with(&text, "  Agent")
        .unwrap()
        .chars()
        .take(28)
        .collect();
    assert!(sidebar.ends_with("paused│"), "{sidebar:?}");
    assert_eq!(
        app.run_command("agent readonly"),
        vec![BusRequest::AgentSet(AgentPolicy::ReadOnly)]
    );
    let _ = app.run_command("agent");
    assert_eq!(app.mode, Mode::Agent);

    // No agent.status/set on the bus: the control is read-only and says F1.
    // Since M4 `CORE_TOOLS` carries the agent tools, so the degraded case uses a
    // pre-F1 bus (`PRE_MERGE_TOOLS`), the standard "a missing tool degrades" list.
    let mut bare = App::new(TermCaps::full(), "x");
    let _ = bare.update(Action::Resize(200, 50));
    let _ = connect(&mut bare, PRE_MERGE_TOOLS, None);
    let text = text_of(&bare, 200, 50);
    assert!(text.contains("Agent · n/a (F1)"), "{text}");
    let sidebar: String = line_with(&text, "  Agent")
        .unwrap()
        .chars()
        .take(28)
        .collect();
    assert!(sidebar.ends_with("F1│"), "{sidebar:?}");
    let _ = bare.update(Action::OpenAgent);
    let text = text_of(&bare, 200, 50);
    assert!(
        text.contains("agent.status is not on this bus (core follow-up F1)"),
        "{text}"
    );
    assert!(
        text.contains("needs core follow-up F2 for the audit ring"),
        "{text}"
    );
    assert!(bare.update(Action::AgentSet(AgentPolicy::All)).is_empty());
    assert_eq!(
        toast(&bare),
        "Agent policy needs core follow-up F1 (agent.set)"
    );
}

// -------------------------------------------- the "needs core F*n*" rule

/// §2.10(c) "where a translation cannot be faithful, the surface degrades …
/// never silently": every control whose tool is absent from `tools/list`
/// renders a labelled "needs core follow-up F*n*" instead of doing nothing.
#[test]
fn every_absent_tool_degrades_to_a_labelled_follow_up() {
    let mut app = App::new(TermCaps::full(), "x");
    let _ = app.update(Action::Resize(200, 50));
    // The pre-merge bus: none of the F5/F6/F7/F12/F13 tools, so each
    // control's label is exercised (today's core has them all).
    let _ = connect(&mut app, PRE_MERGE_TOOLS, None);
    app.scope = vec!["h.test".into()];
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ]));
    app.selected = Some("a".into());

    let expect_toast = |app: &mut App, action: Action, f: &str| {
        assert!(
            app.update(action.clone()).is_empty(),
            "{action:?} must not reach the bus"
        );
        assert!(toast(app).contains(f), "{action:?}: {}", toast(app));
    };
    expect_toast(&mut app, Action::Mark, "F6");
    expect_toast(&mut app, Action::Comment, "F6");
    expect_toast(&mut app, Action::AgentSet(AgentPolicy::Paused), "F1");
    for (cmd, f) in [
        ("clear", "F7"),
        ("pause", "F7"),
        ("record", "F7"),
        ("import /x.har", "F10"),
        ("scope rm h.test", "F12"),
    ] {
        assert!(app.run_command(cmd).is_empty(), "{cmd}");
        assert!(toast(&app).contains(f), "{cmd}: {}", toast(&app));
    }
    // Edit on a paused flow without flow.detail: F5, and nothing is asked
    // of a bus that cannot answer (Q-6: one `request_detail` gate).
    app.selected = Some("b".into());
    assert!(
        app.update(Action::Edit).is_empty(),
        "no flow.detail on this bus: nothing to fetch"
    );
    assert!(toast(&app).contains("F5"), "{}", toast(&app));
    assert_eq!(app.mode, Mode::Flows);
    // The inspector and quick-look say F5 instead of showing an empty pane.
    app.mode = Mode::Inspector;
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("Headers and bodies need core follow-up F5 (flow.detail)"),
        "{text}"
    );
    app.mode = Mode::QuickLook;
    assert!(text_of(&app, 200, 50).contains("Bodies need core follow-up F5 (flow.detail)"));
    app.mode = Mode::Flows;
    // The toolbar pill, the sidebar and the panels carry their labels.
    let text = text_of(&app, 200, 50);
    for label in [
        "(core follow-up F7)",
        "F10│",
        "M3│",
        "F1│",
        "n/a (F1)",
        "↑ — ↓ — (F4)",
    ] {
        assert!(text.contains(label), "{label}: {text}");
    }
    // The Browser item's count is the tab count, which needs F14: a dash
    // for "missing" (§2.8), not a "not built" label — the view is built.
    assert!(
        line_with(&text, "  Browser").is_some_and(|l| l.ends_with("—│")),
        "{:?}",
        line_with(&text, "  Browser")
    );
    let _ = app.update(Action::OpenScope);
    assert!(text_of(&app, 200, 50).contains("(needs core follow-up F12)"));
    assert!(text_of(&app, 200, 50).contains("readout needs F7, config.get"));
    let _ = app.update(Action::ToggleIntercept);
    app.mode = Mode::Flows;
    app.selected = Some("a".into());
    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        "a",
        "GET",
        "h.test",
        "/a",
        Some(200),
        "observed",
    )]));
    assert!(text_of(&app, 200, 50).contains("Rules… needs core follow-up F3"));
    // The paused bar's Kill hint names the abort modes F3 adds; `:export`
    // names F10 (fix pass 1, I1).
    let _ = app.on_bus(BusEvent::Flows(vec![
        summary("a", "GET", "h.test", "/a", Some(200), "observed"),
        summary("b", "POST", "h.test", "/b", None, "intercepted"),
    ]));
    assert!(
        text_of(&app, 200, 50).contains("[d Kill · abort mode: reset (429/503 need F3)]"),
        "{}",
        text_of(&app, 200, 50)
    );
    assert!(app.run_command("export").is_empty());
    assert!(toast(&app).contains("F10"), "{}", toast(&app));

    // With the tools present, the same controls reach the bus.
    app.tools.extend(tools(&[
        "flow.mark",
        "flow.comment",
        "agent.set",
        "flow.clear",
        "proxy.pause",
        "proxy.resume",
        "flow.import",
        "scope.remove",
    ]));
    let _ = app.update(Action::Mark);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::Mark));
    for c in "red sky".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::Mark {
            id: "a".into(),
            marks: vec!["red".into(), "sky".into()]
        }]
    );
    let _ = app.update(Action::Comment);
    for c in "looks odd".chars() {
        let _ = app.update(Action::Input(c));
    }
    assert_eq!(
        app.update(Action::Submit),
        vec![BusRequest::Comment {
            id: "a".into(),
            text: "looks odd".into()
        }]
    );
    assert_eq!(app.run_command("clear"), vec![BusRequest::ClearFlows]);
    assert_eq!(app.run_command("pause"), vec![BusRequest::ProxyPause(true)]);
    assert_eq!(
        app.run_command("record"),
        vec![BusRequest::ProxyPause(false)]
    );
    assert_eq!(
        app.run_command("scope rm h.test"),
        vec![BusRequest::ScopeRemove("h.test".into())]
    );
    assert_eq!(
        app.run_command("import /x.har"),
        vec![BusRequest::Import("/x.har".into())]
    );
}

/// §4.2 step 3: `tools/list` drives features — `flow.detail` fetches happen
/// only when the bus offers the tool, for new rows, on Enter, and when a
/// row's state changes after its detail was loaded.
#[test]
fn tools_list_drives_detail_fetching() {
    // "A bus without flow.detail" is the pre-merge core now.
    let core_only = |app: &mut App| connect(app, PRE_MERGE_TOOLS, None);
    let mut app = App::new(TermCaps::full(), "x");
    let _ = core_only(&mut app);
    let a = summary("a", "GET", "h.test", "/a", None, "observed");
    assert!(
        app.on_bus(BusEvent::Flows(vec![a.clone()])).is_empty(),
        "no flow.detail: no fetch"
    );
    assert!(app.update(Action::Enter).is_empty());
    assert_eq!(app.mode, Mode::Inspector);
    assert!(text_of(&app, 200, 50).contains("need core follow-up F5"));

    let mut app = App::new(TermCaps::full(), "x");
    let mut with_detail: Vec<&str> = PRE_MERGE_TOOLS.to_vec();
    with_detail.push("flow.detail");
    let _ = connect(&mut app, &with_detail, None);
    assert_eq!(
        app.on_bus(BusEvent::Flows(vec![a.clone()])),
        vec![BusRequest::Detail("a".into())]
    );
    assert!(text_of(&app, 200, 50).contains("loading detail…"));
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http","request":{"method":"GET","path":"/a","headers":[["host","h.test"]]}})).unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    assert!(app.details.contains_key("a"));
    // Same state again: no refetch.
    assert!(app.on_bus(BusEvent::Flows(vec![a.clone()])).is_empty());
    // The response landed: the stale detail is dropped and fetched again.
    let done = summary("a", "GET", "h.test", "/a", Some(200), "observed");
    assert_eq!(
        app.on_bus(BusEvent::Flows(vec![done.clone()])),
        vec![BusRequest::Detail("a".into())]
    );
    assert!(!app.details.contains_key("a"));
    // Enter on a row without a detail asks for it; with one, it does not.
    assert_eq!(
        app.update(Action::Enter),
        vec![BusRequest::Detail("a".into())]
    );
    let d = FlowDetail::from_json(&json!({"id":"a","kind":"http"})).unwrap();
    let _ = app.on_bus(BusEvent::Detail(Box::new(d)));
    let _ = app.update(Action::Back);
    assert!(app.update(Action::Enter).is_empty());
    // A bus notification (F4) marks the list stale and the next tick
    // refreshes it once (scanner v2 D5 coalescing); CallOk refreshes at once.
    assert!(app
        .on_bus(BusEvent::Notification(
            json!({"method":"notifications/aitm/state","params":{"paused":1}})
        ))
        .is_empty());
    assert_eq!(app.update(Action::Tick), vec![BusRequest::Refresh]);
    assert_eq!(
        app.on_bus(BusEvent::CallOk {
            name: "flow.kill".into(),
            value: json!("ok")
        }),
        vec![BusRequest::Refresh]
    );
    assert_eq!(toast(&app), "Killed");
    // `ToolInfo::params` reads the schema a form is built from (§4.2 step 3).
    let t = ToolInfo {
        name: "x".into(),
        description: String::new(),
        input_schema: json!({"type":"object","properties":{"id":{"type":"string","description":"The flow."},"n":{"type":"integer"}},"required":["id"]}),
    };
    assert_eq!(
        t.params(),
        vec![
            Param {
                name: "id".to_string(),
                ty: "string".to_string(),
                required: true,
                description: "The flow.".to_string(),
            },
            Param {
                name: "n".to_string(),
                ty: "integer".to_string(),
                required: false,
                description: String::new(),
            },
        ]
    );
    let _ = Level::Info;
}

// ------------------------------------------------------ §2.7 browser view

/// Run `reqs` against the fixture as the bus task would and feed the answers
/// back: `CallOk` for a result, `CallFailed` for a tool error (QI-1).
fn answer(app: &mut App, fx: &mut Fixture, reqs: Vec<BusRequest>) {
    for r in reqs {
        if let BusRequest::Call { name, args } = r {
            let obj = args.as_object().cloned().unwrap_or_default();
            match fx.call(&name, &obj) {
                Ok(value) => {
                    let _ = app.on_bus(BusEvent::CallOk { name, value });
                }
                Err(message) => {
                    let _ = app.on_bus(BusEvent::CallFailed { name, message });
                }
            }
        }
    }
}

fn call(name: &str, args: serde_json::Value) -> BusRequest {
    BusRequest::Call {
        name: name.into(),
        args,
    }
}

/// `(width, height, format, byte count)` of the last screenshot.
fn shot_facts(app: &App) -> Option<(u32, u32, &'static str, usize)> {
    app.browser
        .screenshot
        .as_ref()
        .map(|s| (s.width, s.height, s.format, s.bytes.len()))
}

/// The browser view opened on the fixture, its first DOM and screenshot
/// answered — where every browser test below starts.
fn browser_open() -> (App, Fixture) {
    let mut app = fixture_app(200, 50);
    let mut fx = Fixture::builtin();
    let reqs = app.update(Action::OpenBrowser);
    answer(&mut app, &mut fx, reqs);
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(app.browser.busy, None);
    (app, fx)
}

/// §2.7 "Browser view … TUI: URL + last screenshot as placeholder + `get_dom`
/// text outline"; §2.9 "URL, DOM outline, last screenshot placeholder".
/// Plan task 10: opening the view asks the bus for the page once and draws
/// the URL (a dash until a navigate), the screenshot line and the outline.
#[test]
fn browser_view_opens_asking_for_the_page_and_shows_url_screenshot_and_outline() {
    let mut app = fixture_app(200, 50);
    let mut fx = Fixture::builtin();
    let reqs = app.update(Action::OpenBrowser);
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(app.sidebar, SidebarItem::Browser);
    assert_eq!(
        reqs,
        vec![
            call("browser.get_dom", json!({})),
            call("browser.screenshot", json!({})),
        ]
    );
    assert_eq!(app.browser.busy, Some("loading the page"));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("[no screenshot yet · s]"), "{text}");
    assert!(text.contains("loading the page"), "{text}");
    // The URL is unknown until the operator navigates: a dash (§2.8).
    assert!(
        line_with(&text, " URL ").is_some_and(|l| l.contains("—")),
        "{text}"
    );

    answer(&mut app, &mut fx, reqs);
    assert_eq!(app.browser.busy, None);
    assert_eq!(app.browser.error, None);
    assert_eq!(
        app.browser.dom_outline,
        vec![
            "html",
            "  head",
            "    meta",
            "    title",
            "    script",
            "  body",
            "    h1#title",
            "    p.lead",
            "      a.link",
            "    img#hero",
            "    script",
        ]
    );
    assert_eq!(shot_facts(&app), Some((1, 1, "PNG", 70)));
    let text = text_of(&app, 200, 50);
    assert!(text.contains("Browser — embedded obscura"), "{text}");
    assert!(
        text.contains("[screenshot 1×1 PNG · 70 B · o to open]"),
        "{text}"
    );
    assert!(line_with(&text, "      a.link").is_some(), "{text}");
    assert!(text.contains("11 elements"), "{text}");
    assert!(
        text.contains("live viewport and tabs need core follow-up F14"),
        "{text}"
    );
}

/// Task 10: ↓ walks the outline and the header names the cursor's path;
/// Home and End jump to its ends.
#[test]
fn browser_outline_navigation_names_the_cursor_path() {
    let (mut app, _) = browser_open();
    for _ in 0..6 {
        let _ = app.update(Action::Down);
    }
    assert_eq!(app.browser.dom_cursor, 6);
    let text = text_of(&app, 200, 50);
    assert!(text.contains("html › body › h1#title"), "{text}");
    let _ = app.update(Action::Home);
    assert_eq!(app.browser.dom_cursor, 0);
    let _ = app.update(Action::End);
    assert_eq!(app.browser.dom_cursor, 10);
}

/// §2.10(c) "navigate … still work": `g` opens the URL prompt prefilled
/// with the current URL; ⏎ sends `browser.navigate`; Esc returns to the view.
#[test]
fn browser_url_prompt_prefills_the_current_url_and_navigates() {
    let (mut app, mut fx) = browser_open();
    assert_eq!(
        keys::map(press(KeyCode::Char('g')), Mode::Browser),
        Some(Action::BrowserNavigatePrompt)
    );
    let _ = app.update(Action::BrowserNavigatePrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::BrowserUrl));
    assert_eq!(app.prompt, "");
    for c in "https://shop-staging.test/".chars() {
        let _ = app.update(Action::Input(c));
    }
    let reqs = app.update(Action::Submit);
    assert_eq!(
        reqs,
        vec![call(
            "browser.navigate",
            json!({"url": "https://shop-staging.test/"})
        )]
    );
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(app.browser.busy, Some("navigating"));
    answer(&mut app, &mut fx, reqs);
    assert_eq!(app.browser.url, "https://shop-staging.test/");
    assert!(
        text_of(&app, 200, 50).contains("https://shop-staging.test/"),
        "{}",
        text_of(&app, 200, 50)
    );
    let _ = app.update(Action::BrowserNavigatePrompt);
    assert_eq!(app.prompt, "https://shop-staging.test/");
    let _ = app.update(Action::Back);
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(app.prompt, "");
}

/// §2.10(c) "eval … still work": `e` prompts for an expression; the
/// argument is named by the tool's schema (`expr` on today's bus), not
/// hard-coded; the result is drawn on the `eval ›` line.
#[test]
fn browser_eval_prompt_sends_the_schema_named_argument_and_shows_the_result() {
    let (mut app, mut fx) = browser_open();
    assert_eq!(
        keys::map(press(KeyCode::Char('e')), Mode::Browser),
        Some(Action::BrowserEvalPrompt)
    );
    let _ = app.update(Action::BrowserEvalPrompt);
    assert_eq!(app.mode, Mode::Prompt(PromptKind::BrowserEval));
    for c in "document.title".chars() {
        let _ = app.update(Action::Input(c));
    }
    let reqs = app.update(Action::Submit);
    assert_eq!(
        reqs,
        vec![call("browser.eval", json!({"expr": "document.title"}))]
    );
    assert_eq!(app.browser.busy, Some("evaluating"));
    answer(&mut app, &mut fx, reqs);
    assert_eq!(app.browser.last_eval.as_deref(), Some("Shop — staging"));
    assert!(
        text_of(&app, 200, 50).contains("eval › Shop — staging"),
        "{}",
        text_of(&app, 200, 50)
    );
}

/// Task 10: `d` re-reads the DOM and `s` captures a screenshot, each naming
/// what is in flight.
#[test]
fn browser_d_and_s_refresh_the_dom_and_the_screenshot() {
    let (mut app, _) = browser_open();
    assert_eq!(
        keys::map(press(KeyCode::Char('d')), Mode::Browser),
        Some(Action::BrowserRefreshDom)
    );
    assert_eq!(
        keys::map(press(KeyCode::Char('s')), Mode::Browser),
        Some(Action::BrowserScreenshot)
    );
    assert_eq!(
        app.update(Action::BrowserRefreshDom),
        vec![call("browser.get_dom", json!({}))]
    );
    assert_eq!(app.browser.busy, Some("reading the DOM"));
    assert_eq!(
        app.update(Action::BrowserScreenshot),
        vec![call("browser.screenshot", json!({}))]
    );
    assert_eq!(app.browser.busy, Some("capturing a screenshot"));
    assert_eq!(app.browser.inflight, 2);
}

/// `:browser.navigate url=…` typed anywhere is the same call the prompt
/// makes and feeds the same view.
#[test]
fn browser_navigate_command_feeds_the_same_view() {
    let (mut app, mut fx) = browser_open();
    let reqs = app.run_command("browser.navigate url=https://x");
    assert_eq!(
        reqs,
        vec![call("browser.navigate", json!({"url": "https://x"}))]
    );
    assert_eq!(app.browser.busy, Some("navigating"));
    answer(&mut app, &mut fx, reqs);
    assert_eq!(app.browser.url, "https://x");
    assert!(
        text_of(&app, 200, 50).contains("https://x"),
        "{}",
        text_of(&app, 200, 50)
    );
}

/// §2.9 "o opens it": `o` writes the screenshot to a private temp file and
/// hands it to the desktop.
#[test]
fn browser_o_writes_the_screenshot_to_a_temp_file_and_opens_it() {
    let (mut app, _) = browser_open();
    assert_eq!(
        keys::map(press(KeyCode::Char('o')), Mode::Browser),
        Some(Action::OpenExternally)
    );
    let _ = app.update(Action::OpenExternally);
    let target = app.take_open_target().expect("an open target");
    assert!(
        target.path.to_string_lossy().ends_with(".png"),
        "{:?}",
        target.path
    );
    assert_eq!(std::fs::read(&target.path).unwrap().len(), 70);
    assert_eq!(target.label, "screenshot");
    let _ = std::fs::remove_file(&target.path);
}

/// `:browser` opens the view too and does not re-fetch what it already has.
#[test]
fn browser_command_opens_the_view_without_refetching() {
    let (mut app, _) = browser_open();
    app.mode = Mode::Flows;
    assert!(app.run_command("browser").is_empty());
    assert_eq!(app.mode, Mode::Browser);
    assert_eq!(app.browser.inflight, 0);
}

/// §2.10(c) "where a translation cannot be faithful, the surface degrades …
/// never silently": a bus without `browser.*`, and a tool error from a bus
/// that has them but no engine, both show in the panel itself.
#[test]
fn browser_view_says_when_the_bus_has_no_browser_and_shows_tool_errors() {
    let mut app = fixture_app(200, 50);
    let no_browser: Vec<&str> = CORE_TOOLS
        .iter()
        .copied()
        .filter(|t| !t.starts_with("browser."))
        .collect();
    let _ = connect(&mut app, &no_browser, None);
    assert!(app.update(Action::OpenBrowser).is_empty());
    assert_eq!(app.mode, Mode::Browser);
    let text = text_of(&app, 200, 50);
    assert!(
        text.contains("this bus offers no browser.* tools"),
        "{text}"
    );
    assert!(app.update(Action::BrowserRefreshDom).is_empty());
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser.get_dom is not on this bus")
    );
    assert!(
        text_of(&app, 200, 50).contains("browser.get_dom is not on this bus"),
        "{}",
        text_of(&app, 200, 50)
    );
    assert!(app.update(Action::BrowserNavigatePrompt).is_empty());
    assert_eq!(
        app.mode,
        Mode::Browser,
        "no prompt for a tool that is absent"
    );

    // The tools are there but nothing answers behind them (a live proxy with
    // no obscura): the error lands in the panel, not only in a toast.
    let _ = connect(&mut app, CORE_TOOLS, None);
    let reqs = app.update(Action::BrowserRefreshDom);
    assert_eq!(reqs.len(), 1);
    assert_eq!(app.browser.busy, Some("reading the DOM"));
    assert_eq!(app.browser.error, None, "a new call clears the old error");
    let _ = app.on_bus(BusEvent::CallFailed {
        name: "browser.get_dom".into(),
        message: "browser engine is not running".into(),
    });
    assert_eq!(app.browser.busy, None);
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser engine is not running")
    );
    let text = text_of(&app, 200, 50);
    assert!(text.contains("browser engine is not running"), "{text}");
    assert_eq!(toast(&app), "browser engine is not running");
    // An info toast while idle is not a browser error.
    let _ = app.on_bus(BusEvent::Toast(Level::Info, "Resumed".into()));
    assert_eq!(
        app.browser.error.as_deref(),
        Some("browser engine is not running")
    );

    // `o` with no screenshot says so instead of opening nothing.
    let _ = app.update(Action::OpenExternally);
    assert!(app.take_open_target().is_none());
    assert_eq!(toast(&app), "no screenshot yet — s captures one");

    // A fixture document without a `browser` section still answers like the
    // bus did before task 10, so that error path stays reachable in tests.
    let mut fx = Fixture::parse(r#"{"tools":[{"name":"browser.get_dom"}]}"#).unwrap();
    assert_eq!(
        fx.call("browser.get_dom", &serde_json::Map::new()),
        Err("fixture has no browser engine; run against a live proxy".into())
    );
}
