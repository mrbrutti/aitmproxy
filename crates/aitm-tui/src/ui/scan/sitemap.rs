//! The Site map tab (spec D2, D11, D12, D13). Plan task 4 draws the legacy
//! `scan.discover` result in the two panes it moved into: the reached
//! endpoints as nodes, the discovered injection points as points, with the
//! text today's view drew. The v2 `scan.sitemap` nodes arrive with the Site
//! map task.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{MapPane, ScanOffer};
use crate::theme::Theme;
use crate::ui::scan::{note, pane_rule, panes};
use crate::ui::selection_bg;
use crate::ui::text::{cells, truncate};

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        // The banner carries the no-scanner and missing-verb states; the
        // body adds nothing to them.
        ScanOffer::None => {}
        ScanOffer::V2 if !app.has_tool("scan.sitemap") => {}
        ScanOffer::V2 if app.scan.sitemap.nodes.is_empty() => {
            note(theme, area, "no site map yet", buf)
        }
        // The legacy result is the map on a legacy bus (D12); the v2 nodes
        // render with the Site map task.
        _ => {
            let (left, right) = panes(area);
            pane_rule(theme, area, buf);
            endpoints(app, theme, left, buf);
            points(app, theme, right, buf);
        }
    }
}

/// The reached endpoints: a cursor list of URLs rendered verbatim. The cursor
/// row is highlighted only while the Nodes pane is focused; Enter opens the
/// selected endpoint's linked flow in the inspector (AC3).
fn endpoints(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    buf.set_string(
        area.x + 1,
        area.y,
        "Endpoints",
        theme.accent().add_modifier(Modifier::BOLD),
    );
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    if app.scan.legacy.endpoints.is_empty() {
        buf.set_string(
            body.x + 1,
            body.y,
            "none yet: r scans an in-scope target",
            theme.text_tertiary(),
        );
        return;
    }
    let focused = app.scan.sitemap.pane == MapPane::Nodes;
    let h = usize::from(body.height);
    let cursor = app
        .scan
        .legacy
        .endpoint_cursor
        .min(app.scan.legacy.endpoints.len() - 1);
    let top = cursor.saturating_sub(h.saturating_sub(1));
    for (k, e) in app
        .scan
        .legacy
        .endpoints
        .iter()
        .enumerate()
        .skip(top)
        .take(h)
    {
        let y = body.y + cells(k - top);
        if focused && k == cursor {
            buf.set_style(Rect::new(body.x, y, body.width, 1), selection_bg(theme));
        }
        let line = Line::from(vec![
            Span::styled(" • ", theme.text_tertiary()),
            Span::styled(
                truncate(e, usize::from(body.width).saturating_sub(4)),
                theme.text_primary(),
            ),
        ]);
        buf.set_line(body.x, y, &line, body.width);
    }
}

/// The discovered injection points: a cursor list of location + name + a
/// redacted example (the scanner redacts at the source; the UI never
/// re-derives a raw value).
fn points(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    buf.set_string(
        area.x + 1,
        area.y,
        "Injection points",
        theme.accent().add_modifier(Modifier::BOLD),
    );
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    if body.height == 0 {
        return;
    }
    if app.scan.legacy.points.is_empty() {
        buf.set_string(body.x + 1, body.y, "none yet", theme.text_tertiary());
        return;
    }
    let focused = app.scan.sitemap.pane == MapPane::Points;
    let h = usize::from(body.height);
    let cursor = app.scan.legacy.cursor.min(app.scan.legacy.points.len() - 1);
    let top = cursor.saturating_sub(h.saturating_sub(1));
    for (k, p) in app.scan.legacy.points.iter().enumerate().skip(top).take(h) {
        let y = body.y + cells(k - top);
        if focused && k == cursor {
            buf.set_style(Rect::new(body.x, y, body.width, 1), selection_bg(theme));
        }
        let line = Line::from(vec![
            Span::styled(
                format!(" {:<12} ", truncate(&p.location, 12)),
                theme.accent(),
            ),
            Span::styled(
                format!("{} ", truncate(&p.name, 24)),
                theme.text_primary().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                truncate(&p.example, usize::from(body.width).saturating_sub(40)),
                theme.text_secondary(),
            ),
        ]);
        buf.set_line(body.x, y, &line, body.width);
    }
}
