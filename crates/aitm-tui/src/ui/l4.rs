//! The L4 operator surface's inspector and the inject confirm overlay
//! (ui-ext §3.2–§3.4, L4OPS-AC8/AC10/AC12). The flow list renders L4 rows in
//! `ui::flows`; this draws the selected L4 flow: a packet list, a packet's
//! layer tree (honest indented **text** tree) + hex, the YAML craft editor with
//! its `build()` hex preview, and the in-path intercept bar.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::l4::{L4Flow, L4Pane};
use crate::theme::Theme;
use crate::tokens::glyph;
use crate::ui::bars::{put, put_sides};
use crate::ui::overlays::lines_into;
use crate::ui::selection_bg;
use crate::ui::text::{cells, truncate};
use crate::viewers;

/// Draw the L4 inspector for the selected flow into `area`.
pub fn inspector(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    for x in area.x..area.right() {
        buf.set_string(x, area.y, "─", theme.rule());
    }
    let Some(flow) = app.selected_l4() else {
        buf.set_string(
            area.x + 2,
            area.y + 1,
            "Select an L4 flow to inspect it.",
            theme.text_tertiary(),
        );
        return;
    };
    let [_, summary_area, tabs_area, body] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
    ])
    .areas(area);
    summary(app, theme, flow, summary_area, buf);
    pane_tabs(app, theme, tabs_area, buf);
    match app.l4.pane {
        L4Pane::Packets => packets_pane(app, theme, flow, body, buf),
        L4Pane::Craft => craft_pane(app, theme, flow, body, buf),
        L4Pane::Intercept => intercept_pane(app, theme, flow, body, buf),
    }
}

/// The summary strip: the L4 badge + sub-label, target, state, counts, scope.
fn summary(app: &App, theme: &Theme, flow: &L4Flow, area: Rect, buf: &mut Buffer) {
    let proto = flow.proto().unwrap_or("?");
    let mut left = vec![
        Span::raw(" "),
        Span::styled(format!(" L4 {proto} "), theme.l4_badge()),
        Span::raw("  "),
        Span::styled(
            flow.target(),
            theme.text_primary().add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  {}", flow.kind), theme.l4()),
    ];
    if let Some(q) = flow.queue {
        left.push(Span::styled(format!("  queue {q}"), theme.text_secondary()));
    }
    let meta = format!(
        "{} packets · {} injected · {} ",
        flow.packet_count,
        flow.injected_count,
        if app.l4.in_scope(flow) {
            "in scope"
        } else {
            "OUT OF SCOPE"
        }
    );
    put_sides(
        buf,
        area,
        Line::from(left),
        Line::styled(meta, theme.text_secondary()),
    );
}

/// The pane tab row: Packets | Craft | Intercept.
fn pane_tabs(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.raised());
    let mut spans = vec![Span::styled(
        " L4  ",
        theme.l4().add_modifier(Modifier::BOLD),
    )];
    for p in L4Pane::ALL {
        let style = if p == app.l4.pane {
            theme
                .accent()
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            theme.text_secondary()
        };
        spans.push(Span::styled(p.label(), style));
        spans.push(Span::raw("  "));
    }
    put(buf, area, Line::from(spans));
}

/// The Packets pane: the packet list on top, the selected packet's layer tree
/// (text) + hex below (L4OPS-AC8).
fn packets_pane(app: &App, theme: &Theme, flow: &L4Flow, area: Rect, buf: &mut Buffer) {
    if area.height < 2 {
        return;
    }
    let [list_area, detail_area] =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    // The packet list: dir arrow, length, decoded summary, injected tick.
    if flow.packets.is_empty() {
        buf.set_string(
            list_area.x + 1,
            list_area.y,
            "no packets yet — craft and inject one, or start capture",
            theme.text_tertiary(),
        );
    } else {
        let cursor = app.l4.packet_cursor.min(flow.packets.len() - 1);
        let h = usize::from(list_area.height);
        let top = cursor.saturating_sub(h.saturating_sub(1));
        for (k, p) in flow.packets.iter().enumerate().skip(top).take(h) {
            let y = list_area.y + cells(k - top);
            if k == cursor {
                buf.set_style(
                    Rect::new(list_area.x, y, list_area.width, 1),
                    selection_bg(theme),
                );
            }
            let injected = if p.injected {
                Span::styled("  injected", theme.agent())
            } else {
                Span::raw("")
            };
            let line = Line::from(vec![
                Span::styled(format!(" {} ", p.arrow()), theme.l4()),
                Span::styled(format!("{:>5}B  ", p.length), theme.text_secondary()),
                Span::styled(
                    truncate(
                        &p.summary(),
                        usize::from(list_area.width).saturating_sub(24),
                    ),
                    theme.text_primary(),
                ),
                injected,
            ]);
            buf.set_line(list_area.x, y, &line, list_area.width);
        }
    }
    // The selected packet's detail: layer tree (text) + hex.
    for x in detail_area.x..detail_area.right() {
        buf.set_string(x, detail_area.y, "─", theme.rule());
    }
    let detail = Rect::new(
        detail_area.x,
        detail_area.y + 1,
        detail_area.width,
        detail_area.height.saturating_sub(1),
    );
    let mut lines: Vec<Line> = Vec::new();
    match flow.packets.get(
        app.l4
            .packet_cursor
            .min(flow.packets.len().saturating_sub(1)),
    ) {
        Some(p) => {
            for l in crate::l4::layer_tree_lines(&p.layers) {
                let style = if l.ends_with(':') {
                    theme.accent().add_modifier(Modifier::BOLD)
                } else {
                    theme.text_primary()
                };
                lines.push(Line::styled(l, style));
            }
            lines.push(Line::raw(""));
            // `l4.flow.get` carries no raw bytes, so a captured packet has none;
            // the hex view is honest about it (the craft pane shows crafted hex).
            lines.push(Line::styled(
                format!("hex: {} bytes", p.length),
                theme.accent().add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::styled(
                "raw bytes are not carried by l4.flow.get — craft a packet (Craft pane) to preview its hex",
                theme.text_tertiary(),
            ));
        }
        None => lines.push(Line::styled("no packet selected", theme.text_tertiary())),
    }
    lines_into(buf, detail, &lines, 0);
}

/// The Craft pane: the YAML `PacketSpec` editor + its `build()` hex preview.
fn craft_pane(app: &App, theme: &Theme, flow: &L4Flow, area: Rect, buf: &mut Buffer) {
    if area.height < 2 {
        return;
    }
    let [editor, preview] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
    // The YAML editor (read + highlighted; editing lands via the command bus
    // and the palette today — the hook for in-pane Rhai craft is the
    // protocol-extensible seam, ui-ext §3.2).
    buf.set_string(
        editor.x + 1,
        editor.y,
        "PacketSpec (YAML) — b build · s inject (guarded)",
        theme.accent().add_modifier(Modifier::BOLD),
    );
    let body = Rect::new(
        editor.x,
        editor.y + 1,
        editor.width,
        editor.height.saturating_sub(1),
    );
    let craft = &app.l4.craft;
    for (k, raw) in craft
        .lines
        .iter()
        .enumerate()
        .take(usize::from(body.height))
    {
        let y = body.y + cells(k);
        let mut line = crate::syntax::highlight_yaml(theme, raw)
            .into_iter()
            .next()
            .unwrap_or_else(|| Line::raw(raw.clone()));
        line.spans.insert(0, Span::raw(" "));
        buf.set_line(body.x, y, &line, body.width);
        if k == craft.cursor_line {
            buf.set_style(Rect::new(body.x, y, body.width, 1), selection_bg(theme));
        }
    }
    // The build() hex preview / error.
    for x in preview.x..preview.right() {
        buf.set_string(x, preview.y, "─", theme.rule());
    }
    let pv = Rect::new(
        preview.x,
        preview.y + 1,
        preview.width,
        preview.height.saturating_sub(1),
    );
    let mut lines: Vec<Line> = Vec::new();
    if let Some(e) = &craft.error {
        lines.push(Line::styled(
            format!("craft error: {e}"),
            theme.fg(&crate::tokens::color::status::SERVER_ERROR),
        ));
    }
    match &craft.preview {
        Some(bytes) => {
            lines.push(Line::styled(
                format!(
                    "build() → {} bytes · {}",
                    bytes.len(),
                    if craft.preview_layers.is_empty() {
                        "raw".to_string()
                    } else {
                        craft.preview_layers.join(" / ")
                    }
                ),
                theme.l4().add_modifier(Modifier::BOLD),
            ));
            let per_line = if pv.width >= 100 { 16 } else { 8 };
            lines.extend(viewers::hex::dump(theme, bytes, per_line));
        }
        None if craft.error.is_none() => lines.push(Line::styled(
            "press b to build this spec into a hex preview (l4.craft)",
            theme.text_tertiary(),
        )),
        None => {}
    }
    if !app.l4.inject_in_scope(flow) {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "inject disabled — out of L4 scope (add an inject entry for this interface)",
            theme.text_tertiary(),
        ));
    }
    lines_into(buf, pv, &lines, 0);
}

/// The Intercept pane: the in-path Forward/Mutate/Drop bar, feature-detected
/// from `l4.intercept.*` (L4OPS-AC12); documented-limited when absent.
fn intercept_pane(app: &App, theme: &Theme, flow: &L4Flow, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    let present = app.has_tool("l4.intercept.forward");
    let mut lines: Vec<Line> = Vec::new();
    if !present {
        lines.push(Line::styled(
            "In-path intercept is documented-limited here: this bus offers no l4.intercept.*",
            theme.intercept_armed_quiet(),
        ));
        lines.push(Line::styled(
            "(Linux NFQUEUE + CAP_NET_ADMIN; macOS is Phase 2 via the Network Extension.)",
            theme.text_tertiary(),
        ));
        lines_into(buf, area, &lines, 0);
        return;
    }
    match flow.parked() {
        Some(p) => {
            // The amber intercept bar, mirroring the HTTP one, labelled a packet.
            let bar = Rect::new(area.x, area.y, area.width, 1);
            buf.set_style(bar, theme.intercept_bar());
            let left = Line::styled(
                format!(
                    " {} packet parked · {} {}B",
                    glyph::INTERCEPT,
                    p.summary(),
                    p.length
                ),
                theme.intercept_bar(),
            );
            let right = Line::styled(
                "[a Forward] [e Mutate] [d Drop] (confirm) ".to_string(),
                theme.intercept_bar(),
            );
            put_sides(buf, bar, left, right);
            let rest = Rect::new(
                area.x,
                area.y + 1,
                area.width,
                area.height.saturating_sub(1),
            );
            for l in crate::l4::layer_tree_lines(&p.layers) {
                lines.push(Line::styled(l, theme.text_primary()));
            }
            if !app.l4.in_scope(flow) {
                lines.push(Line::styled(
                    "out of L4 scope — Forward/Drop disabled",
                    theme.text_tertiary(),
                ));
            }
            lines_into(buf, rest, &lines, 0);
        }
        None => {
            lines.push(Line::styled(
                "No parked packet. Start an in-path session (l4.intercept.start) to park one.",
                theme.text_tertiary(),
            ));
            lines_into(buf, area, &lines, 0);
        }
    }
}
