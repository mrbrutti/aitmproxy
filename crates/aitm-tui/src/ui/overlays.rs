//! Full-screen forms and floating panels (§2.7 "Dialogs: full-screen forms in
//! the TUI"): the command palette, compose, the scope panel, the PoC findings
//! panel, the agent panel with its activity log, quick-look and help.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Widget};

use crate::app::{App, PaletteKind, BUILTIN_COMMANDS};
use crate::model::{clock_of, scope_covers, value_text, AgentPolicy, FlowKind, Origin};
use crate::theme::Theme;
use crate::tokens::{color, glyph};
use crate::ui::centered;
use crate::ui::text::{cells, fit, truncate};
use crate::viewers;

/// A bordered, titled panel filling `area`; returns the drawable inside.
pub(crate) fn boxed(theme: &Theme, title: &str, area: Rect, buf: &mut Buffer) -> Rect {
    Clear.render(area, buf);
    buf.set_style(area, theme.surface());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.rule())
        .title(Span::styled(
            format!(" {title} "),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    block.render(area, buf);
    inner
}

/// Draw `lines[scroll..]` top-down into `area`, as many as fit.
pub(crate) fn lines_into(buf: &mut Buffer, area: Rect, lines: &[Line<'_>], scroll: usize) {
    for (k, line) in lines
        .iter()
        .skip(scroll)
        .take(usize::from(area.height))
        .enumerate()
    {
        buf.set_line(area.x, area.y + cells(k), line, area.width);
    }
}

fn key_line(theme: &Theme, key: &str, what: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {key:<10}"),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ),
        Span::styled(what.to_string(), theme.text_secondary()),
    ])
}

fn heading(theme: &Theme, t: &str) -> Line<'static> {
    Line::styled(format!(" {t}"), theme.accent().add_modifier(Modifier::BOLD))
}

pub fn palette(app: &App, theme: &Theme, screen: Rect, prompt_line: Rect, buf: &mut Buffer) {
    let items = app.palette_items();
    if items.is_empty() {
        return;
    }
    // The box sits above the prompt line and never leaves the screen: shrink
    // it to the rows available there, and draw nothing when fewer than three
    // fit (border, one item, border) — a short terminal keeps the prompt.
    let above = prompt_line.y.saturating_sub(screen.y);
    let h = cells(items.len().min(10) + 2).min(above);
    let w = screen.width.min(100);
    if h < 3 || w < 4 {
        return;
    }
    let y = prompt_line.y - h;
    let area = Rect::new(screen.x + (screen.width - w) / 2, y, w, h).intersection(screen);
    let inner = boxed(theme, "palette", area, buf);
    let top = app
        .palette_cursor
        .saturating_sub(usize::from(inner.height).saturating_sub(1));
    for (k, it) in items
        .iter()
        .skip(top)
        .take(usize::from(inner.height))
        .enumerate()
    {
        let selected = top + k == app.palette_cursor;
        let row = Rect::new(inner.x, inner.y + cells(k), inner.width, 1);
        if selected {
            buf.set_style(row, theme.selection());
        }
        let label_style = match &it.kind {
            PaletteKind::Command(_) => theme.text_primary().add_modifier(Modifier::BOLD),
            PaletteKind::Tool(_) => theme.accent().add_modifier(Modifier::BOLD),
            PaletteKind::Flow(_) => theme.text_secondary(),
        };
        let line = Line::from(vec![
            Span::styled(format!(" {} ", fit(&it.label, 30)), label_style),
            Span::styled(
                truncate(&it.detail, usize::from(inner.width).saturating_sub(34)),
                theme.text_secondary(),
            ),
        ]);
        buf.set_line(row.x, row.y, &line, row.width);
    }
}

/// The flow list's help lines, as `(key, what)` pairs: the table the overlay
/// draws under its `Flow list` heading, so [`help_line_count`] can count
/// them without a theme.
const FLOW_KEYS: &[(&str, &str)] = &[
    ("↑↓ j k", "move · PgUp/PgDn · g/G first/last"),
    (
        "⏎ / Esc",
        "inspect the selection · back (full screen below 120 columns)",
    ),
    ("Space", "quick-look the body"),
    ("i", "arm / disarm intercept"),
    ("a / A", "resume the targeted paused flow / resume all"),
    ("d", "kill the targeted paused flow"),
    ("e", "edit the paused request (raw), then ^S Apply & Resume"),
    (
        "r / n",
        "replay unchanged / compose (prefilled from the selection)",
    ),
    ("p / m / c", "pin host / mark / comment"),
    ("P", "build a PoC from the selected flow"),
    (
        "F / S / @",
        "findings · scope · agent panels · :scan the Scan view (keys below)",
    ),
    ("1-9 0 Tab", "content-type chips"),
    ("[ ]", "sidebar items (Apps, Domains, Scope, …)"),
    (
        "b / l / t",
        "toggle sidebar · layout below/right · auto-select",
    ),
    ("y / o", "copy URL (OSC 52) · open externally"),
    (
        "/",
        "filter expression: ~u ~d ~m ~s ~h ~b ~t ~a ~paused ~killed · & | ! ( )",
    ),
    (":", "command palette, every bus tool plus:"),
];

/// How many palette commands the help lists.
const HELP_COMMANDS: usize = 14;

/// The help overlay's closing line.
const HELP_CLOSE: &str = " ↑↓ PgUp PgDn Home End scroll · any other key closes this help.";

/// The help overlay's box width.
const HELP_WIDTH: u16 = 110;

/// Every line of the help overlay, in order: the flow list's keys and
/// palette commands, the Scan section, a blank and the closing line.
fn help_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![heading(theme, "Flow list")];
    for (key, what) in FLOW_KEYS {
        lines.push(key_line(theme, key, what));
    }
    for (cmd, detail) in BUILTIN_COMMANDS.iter().take(HELP_COMMANDS) {
        lines.push(Line::from(vec![
            Span::styled(format!("   :{cmd:<26}"), theme.accent()),
            Span::styled((*detail).to_string(), theme.text_tertiary()),
        ]));
    }
    lines.push(heading(theme, "Scan"));
    for (key, groups) in crate::ui::scan::HELP {
        lines.push(key_line(theme, key, &crate::ui::scan::key_text(groups)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(HELP_CLOSE, theme.text_tertiary()));
    lines
}

/// The number of lines [`help_lines`] builds, from the same tables, so the
/// reducer can clamp the scroll without a theme.
fn help_line_count() -> usize {
    1 + FLOW_KEYS.len()
        + BUILTIN_COMMANDS.len().min(HELP_COMMANDS)
        + 1
        + crate::ui::scan::HELP.len()
        + 2
}

/// The help box on a `cols`x`rows` screen: wide enough for its lines, as
/// tall as they need up to the screen (fix round G, G89).
fn help_box(screen: Rect, lines: usize) -> Rect {
    centered(
        screen,
        HELP_WIDTH,
        u16::try_from(lines + 2).unwrap_or(u16::MAX),
    )
}

/// The furthest the help overlay scrolls on a `cols`x`rows` screen: the
/// lines that do not fit inside its box (fix round G, G85). Zero when the
/// screen is tall enough for all of them.
pub fn help_scroll_max(cols: u16, rows: u16) -> usize {
    let lines = help_line_count();
    let inner = help_box(Rect::new(0, 0, cols, rows), lines)
        .height
        .saturating_sub(2);
    lines.saturating_sub(usize::from(inner))
}

/// The rows the help overlay shows at once on a `cols`x`rows` screen: its
/// page for PgUp/PgDn.
pub fn help_page(cols: u16, rows: u16) -> usize {
    usize::from(
        help_box(Rect::new(0, 0, cols, rows), help_line_count())
            .height
            .saturating_sub(2),
    )
    .max(1)
}

/// The help overlay: every key and palette command, scrolled by
/// `app.help_scroll` when the screen is too short for all of its lines,
/// with a `more` marker on the cut edge (fix round G, G85).
pub fn help(app: &App, theme: &Theme, screen: Rect, buf: &mut Buffer) {
    let lines = help_lines(theme);
    let area = help_box(screen, lines.len());
    let inner = boxed(theme, "aitm-tui · keys and commands", area, buf);
    if inner.height == 0 {
        return;
    }
    let max = lines.len().saturating_sub(usize::from(inner.height));
    let scroll = usize::from(app.help_scroll).min(max);
    lines_into(buf, inner, &lines, scroll);
    let mut marker = |text: &str, y: u16| {
        let row = fit(&format!(" {text}"), usize::from(inner.width));
        buf.set_line(
            inner.x,
            y,
            &Line::styled(row, theme.text_tertiary()),
            inner.width,
        );
    };
    if scroll < max {
        marker("more ↓", inner.bottom() - 1);
    }
    if scroll > 0 {
        marker("↑ more", inner.y);
    }
}

pub fn quick_look(app: &App, theme: &Theme, screen: Rect, buf: &mut Buffer) {
    let Some(row) = app.selected_row() else {
        return;
    };
    let area = centered(
        screen,
        screen.width.saturating_sub(10).max(40),
        screen.height.saturating_sub(6).max(6),
    );
    let title = format!("#{} {} {}", row.seq, row.method, truncate(&row.url(), 60));
    let inner = boxed(theme, &title, area, buf);
    let lines: Vec<Line<'_>> = match app.selected_detail() {
        Some(d) if row.kind == FlowKind::WebSocket => crate::ui::inspector::ws_frames(theme, d),
        Some(d) => match d.response.as_ref().or(d.request.as_ref()) {
            Some(m) => viewers::body_paged(theme, m),
            None => vec![Line::styled("no body yet", theme.text_tertiary())],
        },
        None => vec![Line::styled(
            "Bodies need core follow-up F5 (flow.detail).",
            theme.intercept_armed_quiet(),
        )],
    };
    lines_into(buf, inner, &lines, usize::from(app.inspector.scroll));
}

pub fn compose(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Compose request", area, buf);
    let f = &app.compose;
    let [method, url, headers, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Min(4),
        Constraint::Length(2),
    ])
    .areas(inner);
    let field = |buf: &mut Buffer, r: Rect, idx: usize, label: &str, text: &str, multi: bool| {
        let active = f.field == idx;
        let label_style = if active {
            theme.accent().add_modifier(Modifier::BOLD)
        } else {
            theme.text_secondary()
        };
        buf.set_string(r.x + 1, r.y, label, label_style);
        let body_area = Rect::new(
            r.x + 1,
            r.y + 1,
            r.width.saturating_sub(2),
            r.height.saturating_sub(1),
        );
        if body_area.height == 0 {
            return;
        }
        buf.set_style(body_area, theme.raised());
        if multi {
            for (k, l) in text.lines().take(usize::from(body_area.height)).enumerate() {
                buf.set_string(
                    body_area.x,
                    body_area.y + cells(k),
                    fit(l, usize::from(body_area.width)),
                    theme.text_primary(),
                );
            }
            if active {
                let last = text
                    .lines()
                    .count()
                    .saturating_sub(usize::from(!text.is_empty() && !text.ends_with('\n')));
                let col = text.rsplit('\n').next().map_or(0, |l| l.chars().count());
                let cy = body_area.y + cells(last.min(usize::from(body_area.height) - 1));
                let cx =
                    body_area.x + cells(col.min(usize::from(body_area.width).saturating_sub(1)));
                buf.set_style(
                    Rect::new(cx, cy, 1, 1),
                    ratatui::style::Style::default().add_modifier(Modifier::REVERSED),
                );
            }
        } else {
            buf.set_string(
                body_area.x,
                body_area.y,
                fit(text, usize::from(body_area.width)),
                theme.text_primary(),
            );
            if active {
                let cx = body_area.x
                    + cells(
                        text.chars()
                            .count()
                            .min(usize::from(body_area.width).saturating_sub(1)),
                    );
                buf.set_style(
                    Rect::new(cx, body_area.y, 1, 1),
                    ratatui::style::Style::default().add_modifier(Modifier::REVERSED),
                );
            }
        }
    };
    field(buf, method, 0, "Method", &f.method, false);
    field(buf, url, 1, "URL", &f.url, false);
    field(
        buf,
        headers,
        2,
        "Headers (name: value, one per line)",
        &f.headers,
        true,
    );
    field(buf, body, 3, "Body", &f.body, true);
    let scope_note = match f.authority() {
        Some(a) if scope_covers(&app.scope, &a) => Span::styled(
            format!("{a} is in scope"),
            theme.fg(&color::status::SUCCESS),
        ),
        Some(a) => Span::styled(
            format!("{a} is out of scope — add it with :scope add"),
            theme.fg(&color::intercept::BASE),
        ),
        None => Span::styled("enter a URL", theme.text_tertiary()),
    };
    buf.set_line(
        foot.x + 1,
        foot.y,
        &Line::from(vec![
            Span::styled(
                "Tab/↑↓ fields · ^S Send (request.send) · :curl <cmd> imports · Esc cancel   ",
                theme.text_tertiary(),
            ),
            scope_note,
        ]),
        foot.width.saturating_sub(1),
    );
    if !app.compose_history.is_empty() {
        buf.set_string(
            foot.x + 1,
            foot.y + 1,
            format!("{} sent this session", app.compose_history.len()),
            theme.text_tertiary(),
        );
    }
}

pub fn scope(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Scope — the authorised hosts", area, buf);
    let mut lines = vec![
        Line::styled(
            " Only in-scope hosts can be acted on (replay, edit, compose, PoC). Adding is a human action.",
            theme.text_secondary(),
        ),
        Line::raw(""),
    ];
    if app.scope.is_empty() {
        lines.push(Line::styled(
            " Scope is empty — every flow is dimmed and read-only. Press a to add a host.",
            theme.intercept_armed_quiet(),
        ));
    }
    for (i, h) in app.scope.iter().enumerate() {
        let n = app
            .flows
            .iter()
            .filter(|r| scope_covers(std::slice::from_ref(h), &r.authority))
            .count();
        let style = if i == app.scope_cursor {
            theme.selection().add_modifier(Modifier::BOLD)
        } else {
            theme.text_primary()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} {}", glyph::SCOPE, fit(h, 44)), style),
            Span::styled(
                format!("{n} flows   rate limit: {}", rate_limit_readout(app)),
                theme.text_tertiary(),
            ),
        ]));
    }
    lines.push(Line::raw(""));
    let oos: Vec<String> = app
        .domains()
        .into_iter()
        .filter(|(h, _)| !scope_covers(&app.scope, h))
        .map(|(h, n)| format!("{h} ({n})"))
        .collect();
    if !oos.is_empty() {
        lines.push(Line::styled(
            " Seen but out of scope:",
            theme.text_secondary(),
        ));
        for h in oos {
            lines.push(Line::styled(format!("   {h}"), theme.text_tertiary()));
        }
    }
    lines.push(Line::raw(""));
    let remove_note = if app.has_tool("scope.remove") {
        "d remove"
    } else {
        "d remove (needs core follow-up F12)"
    };
    lines.push(Line::styled(
        format!(" a add · {remove_note} · Esc back"),
        theme.text_tertiary(),
    ));
    lines_into(buf, inner, &lines, 0);
}

/// The scope panel's rate-limit words: the `limits` of `config.get` (F7)
/// once fetched; what is missing otherwise.
fn rate_limit_readout(app: &App) -> String {
    let limits = app.config.as_ref().and_then(|c| c.get("limits"));
    match limits {
        Some(l) => {
            let n = |k: &str| {
                l.get(k)
                    .and_then(serde_json::Value::as_u64)
                    .map_or("—".to_string(), |v| v.to_string())
            };
            format!(
                "{} rps per host · {} global · {} concurrent",
                n("per_host_rps"),
                n("global_rps"),
                n("max_concurrency")
            )
        }
        None if app.has_tool("config.get") => "loading config.get…".to_string(),
        None => "core default (readout needs F7, config.get)".to_string(),
    }
}

pub fn findings(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Findings — PoCs and runs", area, buf);
    if app.findings.is_empty() {
        buf.set_string(
            inner.x + 1,
            inner.y + 1,
            "No findings — build a PoC from any flow with P.",
            theme.text_tertiary(),
        );
        return;
    }
    let [list, detail] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(inner);
    for y in list.y..list.bottom() {
        buf.set_string(list.right().saturating_sub(1), y, "│", theme.rule());
    }
    let mut lines = Vec::new();
    for (i, f) in app.findings.iter().enumerate() {
        let selected = i == app.finding_cursor;
        // A library entry (C8) has no verdict: it is a PoC file nobody ran.
        let verdict = match (f.ran, f.passed) {
            (false, _) => ("·", theme.text_tertiary()),
            (true, true) => ("✓", theme.fg(&color::status::SUCCESS)),
            (true, false) => ("✗", theme.fg(&color::status::SERVER_ERROR)),
        };
        let base = if selected {
            theme.selection()
        } else {
            theme.text_primary()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {} ", verdict.0), verdict.1),
            Span::styled(
                format!(" {} ", f.severity.label()),
                theme.severity(f.severity.label()),
            ),
            Span::styled(
                format!(
                    " {}",
                    truncate(&f.title, usize::from(list.width).saturating_sub(22))
                ),
                base.add_modifier(Modifier::BOLD),
            ),
        ]));
        let origin = if f.origin == Origin::Agent {
            Span::styled(" agent", theme.agent())
        } else {
            Span::raw("")
        };
        let second = match (&f.script, f.ran) {
            (Some(s), _) => format!("       script {s} · {}", clock_of(&f.when)),
            (None, false) => "       · not run · r to run".to_string(),
            (None, true) => format!("       {} · {}", truncate(&f.target, 30), clock_of(&f.when)),
        };
        lines.push(Line::from(vec![
            Span::styled(second, theme.text_tertiary()),
            origin,
        ]));
    }
    lines_into(
        buf,
        Rect::new(list.x, list.y, list.width.saturating_sub(1), list.height),
        &lines,
        0,
    );

    let Some(f) = app.findings.get(app.finding_cursor) else {
        return;
    };
    let mut d = vec![Line::from(vec![
        Span::styled(
            format!(" {}", f.title),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}", f.severity.label()),
            theme.severity(f.severity.label()),
        ),
    ])];
    // C9: the PoC's description (from `poc.get`, or a script's `detail`).
    if let Some(desc) = &f.description {
        for l in desc.lines() {
            d.push(Line::styled(format!(" {l}"), theme.text_secondary()));
        }
    }
    match &f.script {
        Some(s) => d.push(Line::styled(
            format!(" script  {s}"),
            theme.text_secondary(),
        )),
        None => {
            if f.ran {
                d.push(Line::styled(
                    format!(" target  {}", f.target),
                    theme.text_secondary(),
                ));
            }
            d.push(Line::styled(
                format!(" poc     {}", f.poc_path),
                theme.text_secondary(),
            ));
        }
    }
    if f.ran {
        d.push(Line::styled(
            format!(
                " capture {}  (⏎ opens it in the inspector)",
                f.finding_capture.as_deref().unwrap_or("—")
            ),
            theme.text_secondary(),
        ));
        match &f.screenshot_path {
            Some(p) => d.push(Line::styled(
                format!(" [screenshot · {p} · o to open]"),
                theme.text_secondary(),
            )),
            None if f.script.is_none() => {
                d.push(Line::styled(" no screenshot", theme.text_tertiary()))
            }
            None => {}
        }
    } else {
        d.push(Line::styled(
            " not run yet — r runs it (poc.run: target, then vars)",
            theme.text_tertiary(),
        ));
    }
    d.push(Line::raw(""));
    if f.ran && f.script.is_none() {
        d.push(Line::styled(
            " Assertions",
            theme.accent().add_modifier(Modifier::BOLD),
        ));
        for (a, ok) in &f.assertions {
            let mark = if *ok {
                Span::styled(" ✓ ", theme.fg(&color::status::SUCCESS))
            } else {
                Span::styled(" ✗ ", theme.fg(&color::status::SERVER_ERROR))
            };
            d.push(Line::from(vec![
                mark,
                Span::styled(a.clone(), theme.text_primary()),
            ]));
        }
        d.push(Line::raw(""));
    }
    if f.script.is_some() {
        // A script finding has no PoC file behind it.
    } else if let Some(y) = &f.yaml {
        d.push(Line::styled(
            " YAML",
            theme.accent().add_modifier(Modifier::BOLD),
        ));
        // The shared PoC-YAML colouriser (UI-ext plan Task 7), the same token
        // set the edit path uses; a leading space keeps the panel's indent.
        for mut line in crate::syntax::highlight_yaml(theme, y) {
            line.spans.insert(0, Span::raw(" "));
            d.push(line);
        }
    } else if let Some(e) = &f.yaml_error {
        d.push(Line::styled(
            format!(" yaml not readable: {e}"),
            theme.intercept_armed_quiet(),
        ));
    } else if app.has_tool("poc.get") {
        d.push(Line::styled(
            " yaml: loading (poc.get)…",
            theme.text_tertiary(),
        ));
    } else {
        d.push(Line::styled(
            " yaml: not in the result; read from poc_path only on a loopback bus (poc.get is not on this bus)",
            theme.text_tertiary(),
        ));
    }
    d.push(Line::raw(""));
    d.push(Line::styled(
        " r run (poc.run: target, then vars) · o open screenshot · export needs core follow-up F13",
        theme.text_tertiary(),
    ));
    lines_into(buf, detail, &d, 0);
}

/// The config panel (`:config`, F7): the redacted `config.get` object, one
/// line per leaf. Nested keys join with `.`, arrays with `, `; `null` is a
/// dash. Read-only.
pub fn config(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Config — the redacted config.get view", area, buf);
    let mut lines = Vec::new();
    match &app.config {
        Some(v) => {
            let mut rows: Vec<(String, String)> = Vec::new();
            flatten_config("", v, &mut rows);
            let w = rows
                .iter()
                .map(|(k, _)| k.chars().count())
                .max()
                .unwrap_or(0);
            for (k, text) in rows {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {k:<w$}"), theme.text_secondary()),
                    Span::raw("  "),
                    Span::styled(text, theme.text_primary()),
                ]));
            }
        }
        None if app.has_tool("config.get") => {
            lines.push(Line::styled(" loading config.get…", theme.text_tertiary()))
        }
        None => lines.push(Line::styled(
            " config.get is not on this bus (needs core follow-up F7).",
            theme.intercept_armed_quiet(),
        )),
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " The MCP token and key material are never sent; this view is read-only · Esc back",
        theme.text_tertiary(),
    ));
    lines_into(buf, inner, &lines, 0);
}

/// `{"a":{"b":1},"c":[1,2]}` → `[("a.b","1"),("c","1, 2")]`, in key order.
fn flatten_config(prefix: &str, v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_config(&key, child, out);
            }
        }
        serde_json::Value::Array(items) => out.push((
            prefix.to_string(),
            items.iter().map(value_text).collect::<Vec<_>>().join(", "),
        )),
        serde_json::Value::Null => out.push((prefix.to_string(), "—".to_string())),
        other => out.push((prefix.to_string(), value_text(other))),
    }
}

/// The CA panel (§3.6): the facts `ca.status` reports, and the three
/// actions — `e` export, `i` install, `u` uninstall (the last two confirmed
/// locally, see `CONFIRM_TOOLS`).
pub fn ca(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "CA — the MITM certificate", area, buf);
    let mut lines = Vec::new();
    match &app.ca_status {
        Some(serde_json::Value::Object(map)) if !map.is_empty() => {
            let w = map.keys().map(String::len).max().unwrap_or(0).min(24);
            for (k, v) in map {
                let text = match v {
                    serde_json::Value::Null => "—".to_string(),
                    other => value_text(other),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!(" {k:<w$}"), theme.text_secondary()),
                    Span::raw("  "),
                    Span::styled(text, theme.text_primary()),
                ]));
            }
        }
        Some(other) => lines.push(Line::styled(
            format!(" ca.status: {other}"),
            theme.text_primary(),
        )),
        None if app.has_tool("ca.status") => {
            lines.push(Line::styled(" loading ca.status…", theme.text_tertiary()))
        }
        None => lines.push(Line::styled(
            " ca.status is not on this bus.",
            theme.intercept_armed_quiet(),
        )),
    }
    lines.push(Line::raw(""));
    let avail = |name: &str| {
        if app.has_tool(name) {
            String::new()
        } else {
            " (not on this bus)".to_string()
        }
    };
    lines.push(Line::styled(
        format!(
            " e export{} · i install{} · u uninstall{} · Esc back",
            avail("ca.export"),
            avail("ca.install"),
            avail("ca.uninstall")
        ),
        theme.text_tertiary(),
    ));
    lines.push(Line::styled(
        " install/uninstall ask for a local y/N first: the bus has no confirm step until core follow-up F1.",
        theme.text_tertiary(),
    ));
    lines_into(buf, inner, &lines, 0);
}

/// The per-feature L4 agent capability toggles (L4OPS-AC11). Each reflects the
/// gate that governs the agent L4 path: settable where `l4.agent.set` is on the
/// bus, read-only with an honest note where it is not. The L4 section is drawn
/// only when the bus has the L4 surface; it stays silent on a plain HTTP bus.
fn l4_capabilities(app: &App, theme: &Theme, lines: &mut Vec<Line<'static>>) {
    if !app.has_tool("l4.agent.status") && !app.has_tool("l4.flow.list") {
        return;
    }
    let settable = app.has_tool("l4.agent.set");
    let keys = ["c", "i", "n", "w"];
    lines.push(Line::styled(
        " L4 agent capabilities — each toggle is the gate that governs the agent L4 path",
        theme.accent().add_modifier(Modifier::BOLD),
    ));
    for (gate, key) in crate::l4::L4Gate::ALL.into_iter().zip(keys) {
        let on = app.l4.gates.get(gate);
        let dot = if on { "●" } else { "○" };
        let state = if on { "on " } else { "off" };
        let style = if on {
            theme.l4().add_modifier(Modifier::BOLD)
        } else {
            theme.text_primary()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {dot} {key} {:<10} {state} ", gate.label()), style),
            Span::styled(gate.describe().to_string(), theme.text_secondary()),
        ]));
    }
    let note = if !app.l4.gates.present {
        " (l4.agent.status is not on this bus — gate states unknown)"
    } else if settable {
        " Toggle with the key; the agent can never flip its own gates."
    } else {
        " Read-only here — set l4.allow_agent_* in config and restart (l4.agent.set is not on this bus)."
    };
    lines.push(Line::styled(note, theme.text_tertiary()));
    lines.push(Line::raw(""));
}

pub fn agent(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Agent (MCP) — policy and activity", area, buf);
    let policy_line = |p: AgentPolicy, key: &str, what: &str| -> Line<'static> {
        let on = app.agent.policy == Some(p);
        let dot = if on { "●" } else { "○" };
        let style = if on {
            theme.agent().add_modifier(Modifier::BOLD)
        } else {
            theme.text_primary()
        };
        Line::from(vec![
            Span::styled(format!(" {dot} {key} {:<10}", p.label()), style),
            Span::styled(what.to_string(), theme.text_secondary()),
        ])
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", glyph::AGENT), theme.agent()),
            Span::styled(
                match app.agent.policy {
                    Some(p) => format!("policy: {} · {} actions in the last minute · {} client(s)", p.label(), app.agent.actions_last_minute, app.agent.connected_clients),
                    None => "agent.status is not on this bus (core follow-up F1) — the toggle is read-only here".to_string(),
                },
                theme.text_primary(),
            ),
        ]),
        Line::raw(""),
        policy_line(AgentPolicy::All, "1", "the agent may call every tool"),
        policy_line(AgentPolicy::ReadOnly, "2", "list/get/status only; mutations are refused"),
        policy_line(AgentPolicy::Paused, "3", "every tools/call from MCP returns \"paused by operator\""),
        Line::raw(""),
    ];
    l4_capabilities(app, theme, &mut lines);
    lines.push(Line::styled(
        " Activity log — every command from every frontend (agent rows in teal)",
        theme.accent().add_modifier(Modifier::BOLD),
    ));
    if app.agent.log.is_empty() {
        lines.push(Line::styled(
            "   (empty — needs core follow-up F2 for the audit ring)",
            theme.text_tertiary(),
        ));
    }
    for e in app.agent.log.iter().rev() {
        let origin_style = if e.origin == Origin::Agent {
            theme.agent()
        } else {
            theme.text_secondary()
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", clock_of(&e.at)), theme.text_tertiary()),
            Span::styled(format!("{:<6}", e.origin_name), origin_style),
            Span::styled(
                format!("{:<16}", e.command),
                theme.text_primary().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{}  ", truncate(&e.args, 50)),
                theme.text_secondary(),
            ),
            Span::styled(e.result.clone(), theme.text_tertiary()),
        ]));
    }
    lines_into(buf, inner, &lines, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round G, G85/G89: the line count the reducer clamps with is the
    /// count the overlay draws, and the box is as tall as the lines need.
    #[test]
    fn help_line_count_matches_the_lines_drawn() {
        let theme = Theme::new(true);
        let lines = help_lines(&theme);
        assert_eq!(help_line_count(), lines.len());
        let tall = help_box(Rect::new(0, 0, 200, 50), lines.len());
        assert_eq!(usize::from(tall.height), lines.len() + 2);
        assert_eq!(help_scroll_max(200, 50), 0);
        assert_eq!(help_scroll_max(100, 30), lines.len() - 28);
        assert_eq!(help_page(100, 30), 28);
    }
}
