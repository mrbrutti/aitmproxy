//! The one-line bars: toolbar (listening pill, agent toggle), content-type
//! chips, the intercept bar ("one line above the status bar in yellow reverse
//! video", §2.7), the status bar and the `:`/`/` prompt that replaces it.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::action::Level;
use crate::app::{App, BusStatus, Chip, Mode, PromptKind};
use crate::model::{human_bytes, AgentPolicy};
use crate::text::{cells, truncate, width};
use crate::theme::Theme;
use crate::tokens::glyph;
use crate::ui::FrameView;

/// The toolbar shows its `: palette · layout · b sidebar` hints from this
/// width up; narrower, the agent toggle alone is the right cluster.
pub const TOOLBAR_HINTS_COLS: u16 = 150;

/// Blank cells the centred listening pill needs free around it so it never
/// abuts the left cluster or the agent toggle: the hints decision reserves
/// one gutter per side (`2 * PILL_GUTTER`); the placement branch takes a
/// single gutter as the minimum total gap, which is what the 160/220-column
/// tests pin.
const PILL_GUTTER: usize = 2;

/// The intercept bar's Kill hint: the abort mode is fixed at connection
/// reset until core follow-up F3 adds 429/503.
pub const KILL_HINT: &str = "[d Kill · abort mode: reset (429/503 need F3)]";

/// The status bar's throughput cluster: live rates need the F4 push stream.
pub const THROUGHPUT_PLACEHOLDER: &str = "↑ — ↓ — (F4)";

/// Write a line, clipped to the area.
pub fn put(buf: &mut Buffer, area: Rect, line: Line<'_>) {
    if area.height == 0 {
        return;
    }
    buf.set_line(area.x, area.y, &line, area.width);
}

/// Write `left` and `right` on one line, the right part right-aligned.
pub fn put_sides(buf: &mut Buffer, area: Rect, left: Line<'_>, right: Line<'_>) {
    if area.height == 0 {
        return;
    }
    let rw = cells(right.width());
    buf.set_line(area.x, area.y, &left, area.width.saturating_sub(rw + 1));
    if rw < area.width {
        buf.set_line(area.x + area.width - rw, area.y, &right, rw);
    }
}

pub fn toolbar(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.raised());
    let bold = theme.text_primary().add_modifier(Modifier::BOLD);
    let mut left = vec![
        Span::styled(" ›•‹ ", theme.accent().add_modifier(Modifier::BOLD)),
        Span::styled("aitmproxy", bold),
        Span::styled("  ", theme.text_secondary()),
    ];
    let rec = if app.capture_paused {
        Span::styled(format!("{} paused ", glyph::PAUSE), theme.text_secondary())
    } else {
        Span::styled(
            format!("{} rec ", glyph::RECORD),
            theme.fg(&crate::tokens::color::status::SUCCESS),
        )
    };
    left.push(rec);
    left.push(Span::styled(
        format!(" {} compose  {} clear", glyph::COMPOSE, glyph::CLEAR),
        theme.text_tertiary(),
    ));

    // The listening pill, centred.
    let (dot_style, state) = if app.intercept_armed {
        (
            theme.fg(&crate::tokens::color::intercept::BASE),
            " · intercept armed",
        )
    } else if app.capture_paused {
        (theme.text_tertiary(), " · capture paused")
    } else {
        (theme.fg(&crate::tokens::color::status::SUCCESS), "")
    };
    // The address comes from `proxy.status` (F7) or the embed; `listening:
    // false` there means the proxy never bound (a one-shot command).
    let listen = match (&app.bus, app.serving, &app.listening) {
        (BusStatus::Connecting, _, None) => "connecting to the bus…".to_string(),
        (BusStatus::Disconnected(_), _, None) => "bus disconnected".to_string(),
        (_, Some(false), _) => "not serving".to_string(),
        (_, _, Some(l)) => format!("listening {l}"),
        (_, _, None) if app.has_tool("proxy.status") => "listen address unknown".to_string(),
        (_, _, None) => "listen address unknown (core follow-up F7)".to_string(),
    };
    // The §D12 system-proxy word sits after the address; this TUI's own
    // in-flight set/unset reads `setting…` (D14). The CA-trust word
    // (§D17.6) follows it; the state closes the pill.
    let sysproxy = app
        .system_proxy
        .as_ref()
        .and_then(|w| w.pill(app.sysproxy_setting))
        .map(|p| format!(" {p}"))
        .unwrap_or_default();
    let ca = app
        .ca_trust_word()
        .map(|w| format!(" {w}"))
        .unwrap_or_default();
    let pill = Line::from(vec![
        Span::styled("● ", dot_style),
        Span::styled("aitmproxy", bold),
        Span::styled(
            format!(" · {listen}{sysproxy}{ca}{state}"),
            theme.text_secondary(),
        ),
    ]);

    let agent_style = match app.agent.policy {
        Some(AgentPolicy::All) | Some(AgentPolicy::ReadOnly) => {
            theme.agent().add_modifier(Modifier::BOLD)
        }
        Some(AgentPolicy::Paused) | None => theme.text_tertiary().add_modifier(Modifier::BOLD),
    };
    let agent_label = match app.agent.policy {
        Some(p) => format!(
            "{} Agent ● {} · {}/min",
            glyph::AGENT,
            p.label(),
            app.agent.actions_last_minute
        ),
        None => format!("{} Agent · n/a (F1)", glyph::AGENT),
    };
    let layout = match app.layout {
        crate::app::Layout::Horizontal => "▄▄ below",
        crate::app::Layout::Vertical => "▌▐ right",
    };
    // Widths are summed in `usize`: `cells()` saturates at `u16::MAX`, and an
    // unbounded `other` host could otherwise overflow a `u16` sum.
    let lw = Line::from(left.clone()).width();
    let pw = pill.width();
    let cols = usize::from(area.width);
    let mut right = vec![Span::styled(format!("[{agent_label}]"), agent_style)];
    // The key hints are a courtesy; below this width (or when the pill,
    // which now carries the system-proxy word, would otherwise be clipped
    // against the agent toggle) they are dropped.
    let hints = Span::styled(
        format!("  {} palette  {}  b sidebar", glyph::PALETTE, layout),
        theme.text_tertiary(),
    );
    let with_hints = lw + pw + Line::from(right.clone()).width() + hints.width() + 2 * PILL_GUTTER;
    if area.width >= TOOLBAR_HINTS_COLS && with_hints <= cols {
        right.push(hints);
    }
    right.push(Span::raw(" "));
    let right = Line::from(right);
    let rw = right.width();
    buf.set_line(area.x, area.y, &Line::from(left), area.width);
    if lw + rw + PILL_GUTTER < cols {
        // Inside this branch `lw`, `rw` and the free span all fit in `u16`.
        let free_start = cells(lw);
        let free_end = area.width.saturating_sub(cells(rw));
        let free = free_end.saturating_sub(free_start);
        let x = if pw + PILL_GUTTER <= usize::from(free) {
            area.x + free_start + (free - cells(pw)) / 2
        } else {
            area.x + free_start + 1
        };
        buf.set_line(x, area.y, &pill, free_end.saturating_sub(x - area.x));
        buf.set_line(area.x + area.width - cells(rw), area.y, &right, cells(rw));
    }
}

pub fn chips(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    let mut spans = vec![Span::raw(" ")];
    for (i, c) in Chip::ALL.iter().enumerate() {
        if matches!(c, Chip::Http | Chip::H1 | Chip::Json) {
            spans.push(Span::styled("│ ", theme.rule()));
        }
        let label = c.label();
        let style = if *c == app.chip {
            theme
                .raised()
                .add_modifier(Modifier::BOLD)
                .patch(theme.text_primary())
        } else {
            theme.text_secondary()
        };
        let key = if i < 9 {
            format!("{}", i + 1)
        } else if i == 9 {
            "0".into()
        } else {
            String::new()
        };
        if *c == app.chip {
            spans.push(Span::styled(format!(" {label} "), style));
        } else {
            spans.push(Span::styled(label, style));
        }
        if !key.is_empty() {
            spans.push(Span::styled(
                key,
                theme.text_tertiary().add_modifier(Modifier::DIM),
            ));
        }
        spans.push(Span::raw(" "));
    }
    let left = Line::from(spans);
    let right = match (&app.filter, app.mode) {
        (_, Mode::Prompt(PromptKind::Filter)) => Line::styled("filter: editing… ", theme.accent()),
        (Some(_), _) => Line::from(vec![
            Span::styled(format!("{} ", glyph::FILTER), theme.accent()),
            Span::styled(
                truncate(&app.filter_text, 40),
                theme.accent().add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Esc clears ", theme.text_tertiary()),
        ]),
        (None, _) => Line::styled(
            format!("{} / filter ", glyph::FILTER),
            theme.text_tertiary(),
        ),
    };
    put_sides(buf, area, left, right);
}

pub fn intercept(app: &App, theme: &Theme, view: &FrameView, area: Rect, buf: &mut Buffer) {
    let paused = &view.paused;
    if paused.is_empty() {
        if !app.intercept_armed {
            return;
        }
        buf.set_style(area, theme.intercept_armed_quiet());
        put(
            buf,
            area,
            Line::from(vec![
                Span::styled(
                    format!(
                        " {} Intercept armed: every request pauses here",
                        glyph::INTERCEPT
                    ),
                    theme.intercept_armed_quiet().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "   [i] Disarm   Rules… needs core follow-up F3",
                    theme.intercept_armed_quiet(),
                ),
            ]),
        );
        return;
    }
    buf.set_style(area, theme.intercept_bar());
    let target = view.intercept_target(app);
    let (desc, edited) = match target {
        Some(r) => {
            let d = format!("{} {}", r.method, r.url());
            (
                d,
                r.edited || app.edit.as_ref().is_some_and(|e| e.id == r.id && e.dirty()),
            )
        }
        None => (String::new(), false),
    };
    let edited_note = if edited { " · edited" } else { "" };
    let actions = if app.mode == Mode::Edit {
        "[^S Apply & Resume] [^R Revert] [Esc Cancel]".to_string()
    } else {
        format!("[a Resume] [A Resume all] {KILL_HINT} [e Edit] [i Disarm]")
    };
    let count = format!(" {} {} paused", glyph::INTERCEPT, paused.len());
    let left = Line::from(vec![
        Span::styled(count, theme.intercept_bar()),
        Span::styled(
            format!("  {desc}{edited_note}"),
            theme.intercept_bar().remove_modifier(Modifier::BOLD),
        ),
    ]);
    let right = Line::styled(format!("{actions} "), theme.intercept_bar());
    let total = left.width() + right.width() + 1;
    if total > usize::from(area.width) {
        let avail = usize::from(area.width).saturating_sub(right.width() + 2);
        let left = Line::styled(
            truncate(
                &format!(" {} {} paused  {desc}", glyph::INTERCEPT, paused.len()),
                avail,
            ),
            theme.intercept_bar(),
        );
        put_sides(buf, area, left, right);
    } else {
        put_sides(buf, area, left, right);
    }
}

pub fn status(app: &App, theme: &Theme, view: &FrameView, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.raised());
    // The key hints for this mode, most important first; the right-most are
    // dropped when the centre counts would not fit otherwise.
    let mut hints: Vec<(&str, &str)> = match app.mode {
        Mode::Flows => vec![
            ("?", "help"),
            ("i", "intercept"),
            ("e", "edit"),
            ("r", "replay"),
            ("n", "compose"),
            ("P", "poc"),
            (":", "palette"),
            (
                "t",
                if app.auto_select {
                    "Auto-select ●"
                } else {
                    "Auto-select ○"
                },
            ),
        ],
        Mode::Inspector => vec![
            ("Esc", "back"),
            ("Tab", "pane"),
            ("←→", "tabs"),
            ("↑↓", "scroll"),
            ("e", "edit"),
            ("y", "copy url"),
        ],
        Mode::Edit => vec![
            ("^S", "Apply & Resume"),
            ("^R", "revert"),
            ("Esc", "cancel"),
        ],
        Mode::Findings => vec![
            ("↑↓", "select"),
            ("⏎", "open capture"),
            ("r", "run again"),
            ("o", "open screenshot"),
            ("Esc", "back"),
        ],
        Mode::Scope => vec![("a", "add"), ("d", "remove"), ("Esc", "back")],
        Mode::Agent => vec![
            ("1", "all"),
            ("2", "read-only"),
            ("3", "paused"),
            ("Esc", "back"),
        ],
        Mode::Compose => vec![("Tab", "next field"), ("^S", "send"), ("Esc", "cancel")],
        Mode::Ca => vec![
            ("e", "export"),
            ("i", "install"),
            ("u", "uninstall"),
            ("Esc", "back"),
        ],
        Mode::Browser => vec![
            ("g", "url"),
            ("d", "dom"),
            ("s", "shot"),
            ("e", "eval"),
            ("o", "open"),
            ("Esc", "back"),
        ],
        // The active tab's keys (D11), kept with the view that owns them.
        Mode::Scan => crate::ui::scan::hints(app).to_vec(),
        _ => vec![("Esc", "back")],
    };
    let hint_line = |hints: &[(&str, &str)]| -> Line<'static> {
        let mut spans: Vec<Span<'static>> = Vec::with_capacity(hints.len() * 2);
        for (k, label) in hints {
            spans.push(Span::styled(
                format!(" {k}"),
                theme.text_primary().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!(" {label} "), theme.text_secondary()));
        }
        Line::from(spans)
    };

    let center: Line<'static> = if let Some(t) = app.current_toast() {
        let style = match t.level {
            Level::Info => theme.text_primary(),
            Level::Warn => theme.intercept_armed_quiet(),
            Level::Error => theme.fg(&crate::tokens::color::status::SERVER_ERROR),
        };
        Line::styled(t.text.clone(), style.add_modifier(Modifier::BOLD))
    } else {
        let vis = view.visible.len();
        let pos = view
            .selected_pos(app)
            .map_or("–".to_string(), |p| (p + 1).to_string());
        let mut spans = vec![Span::styled(
            format!("{pos} / {vis} rows"),
            theme.text_secondary(),
        )];
        // The view only knows the rows it holds; while the list is filtered
        // the store's own count (`proxy.status.paused`, F7) is the truth.
        let paused = match (app.filter.is_some(), app.store_paused) {
            (true, Some(n)) => usize::try_from(n).unwrap_or(usize::MAX),
            _ => view.paused.len(),
        };
        if paused > 0 {
            spans.push(Span::styled(
                format!(" · {paused} paused"),
                theme
                    .fg(&crate::tokens::color::intercept::BASE)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        spans.push(Span::styled(
            format!(" · {} in scope", app.in_scope_count()),
            theme.text_secondary(),
        ));
        if !app.findings.is_empty() {
            spans.push(Span::styled(
                format!(" · {} findings", app.findings.len()),
                theme.text_secondary(),
            ));
        }
        Line::from(spans)
    };

    let (bus_dot, bus_text) = match &app.bus {
        BusStatus::Connected { address, role, .. } => {
            if app.role_mismatch() {
                // AC8: the token did not resolve to the expected role (or no
                // role was echoed): warn rather than proceed silently.
                let resolved = role.as_deref().unwrap_or("role unknown");
                let expected = app.expect_role.as_deref().unwrap_or("");
                (
                    theme.fg(&crate::tokens::color::status::SERVER_ERROR),
                    format!("bus {address} · {resolved} ⚠ expected {expected}"),
                )
            } else {
                // AC7: surface the resolved role when the server echoed one;
                // older cores echo none, so the line stays as it was.
                let suffix = role
                    .as_deref()
                    .map(|r| format!(" · {r}"))
                    .unwrap_or_default();
                (
                    theme.fg(&crate::tokens::color::status::SUCCESS),
                    format!("bus {address}{suffix}"),
                )
            }
        }
        BusStatus::Connecting => (theme.text_tertiary(), "bus connecting…".to_string()),
        BusStatus::Disconnected(_) => (
            theme.fg(&crate::tokens::color::status::SERVER_ERROR),
            "bus down · retrying".to_string(),
        ),
    };
    // Throughput needs the F4 push stream; until then the cluster says so
    // (§2.7 "Status bar": `196 MB ↑ 6 KB/s ↓ 3 KB/s`). The total is a dash
    // until a size is known (F5), a real `0 B` once one is (§2.8).
    let total = app
        .total_bytes()
        .map_or_else(|| "—".to_string(), human_bytes);
    let right = Line::from(vec![
        Span::styled(total, theme.text_secondary()),
        Span::styled(format!(" {THROUGHPUT_PLACEHOLDER}"), theme.text_tertiary()),
        Span::styled("  ● ", bus_dot),
        Span::styled(format!("{bus_text} "), theme.text_secondary()),
    ]);

    let rw = cells(right.width());
    let cw = cells(center.width());
    // Drop hints from the right before touching the centre counts. Every
    // sum saturates (fix round H, H47): the three widths are each clamped
    // to `u16::MAX` by `cells`, so a plain add could still wrap.
    let needed = cw.saturating_add(2).saturating_add(rw);
    let mut left_line = hint_line(&hints);
    while !hints.is_empty() && cells(left_line.width()).saturating_add(needed) > area.width {
        hints.pop();
        left_line = hint_line(&hints);
    }
    let lw = cells(left_line.width());
    buf.set_line(area.x, area.y, &left_line, area.width.saturating_sub(rw));
    if lw.saturating_add(rw) < area.width {
        buf.set_line(area.x + area.width - rw, area.y, &right, rw);
        let free = area.width - lw - rw;
        if cw.saturating_add(2) <= free {
            let x = area.x + lw + (free - cw) / 2;
            buf.set_line(x, area.y, &center, cw);
        } else if free > 4 {
            let x = area.x + lw + 1;
            buf.set_line(x, area.y, &center, free - 2);
        }
    }
}

pub fn prompt(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.raised());
    let Mode::Prompt(kind) = app.mode else {
        return;
    };
    let (sigil, hint) = match kind {
        PromptKind::Palette => (":", "command or tool · ↑↓ choose · ⏎ run · Esc"),
        PromptKind::Filter => (
            "/",
            "~u url ~d host ~m method ~s status ~a agent ~paused · & | ! ( )",
        ),
        PromptKind::Comment => ("comment:", "⏎ save · Esc"),
        PromptKind::Mark => ("mark:", "colours separated by spaces · ⏎ save"),
        PromptKind::Pin => ("pin host:", "⏎ pin"),
        PromptKind::ScopeAdd => (
            "scope add:",
            "host · host:port · *.wildcard (a human action)",
        ),
        PromptKind::PocName => (
            "poc name:",
            "human title for the finding · blank = none · ⏎ next (param)",
        ),
        PromptKind::PocParam => (
            "poc param:",
            "query parameter to parameterize · blank = none · ⏎ build (poc.build)",
        ),
        PromptKind::PocTarget => (
            "target:",
            "base URL for `target` · blank = the PoC's own · ⏎ next (vars)",
        ),
        PromptKind::PocVars => ("vars:", "k=v k2=v2 … · blank = none · ⏎ run (poc.run)"),
        PromptKind::CaExport => (
            "ca export:",
            "[pem|der] [path] · blank = defaults · ⏎ export (ca.export)",
        ),
        PromptKind::Confirm => ("confirm:", "y runs it · n / Esc cancels"),
        PromptKind::BrowserUrl => (
            "url:",
            "http(s) URL for the embedded browser · ⏎ go (browser.navigate) · Esc",
        ),
        PromptKind::BrowserEval => (
            "eval:",
            "JavaScript expression · ⏎ run (browser.eval) · Esc",
        ),
        // The Profiles editor's prompts (scanner v2 spec D4, D11).
        PromptKind::ScanOrigin => ("origin:", "scheme://host[:port] · ⏎ add"),
        PromptKind::ScanField => ("value:", "⏎ set · Esc"),
        PromptKind::ScanProfileName => ("profile name:", "a-z 0-9 . _ - lowercase · ⏎ save as"),
        PromptKind::ScanL4Target => ("l4 target:", "ip:port[/tcp|udp][ grammar] · ⏎ add"),
    };
    let text = match (kind, &app.confirm) {
        (PromptKind::Confirm, Some(c)) => {
            format!(
                " {sigil} {}: {} [y/N] {}",
                c.name, c.description, app.prompt
            )
        }
        _ => format!(" {sigil} {}", app.prompt),
    };
    let cursor = Span::styled(" ", Style::default().add_modifier(Modifier::REVERSED));
    let left = Line::from(vec![
        Span::styled(text, theme.text_primary().add_modifier(Modifier::BOLD)),
        cursor,
    ]);
    let right = Line::styled(format!("{hint} "), theme.text_tertiary());
    if width(hint) + left.width() + 2 > usize::from(area.width) {
        put(buf, area, left);
    } else {
        put_sides(buf, area, left, right);
    }
}
