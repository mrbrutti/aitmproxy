//! The Scan operator surface (scanner-integration Stage 1, AC4): a scope-bound
//! `scan.discover` launch header, the discovered endpoints (each openable to its
//! linked flow, AC3) and the discovered injection points. It mirrors the
//! Findings/Browser panels' shape and reuses the shared list rendering; the
//! scanner engine is `aitm-plugin-scanner` and this only surfaces its result.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::{App, ScanFocus};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::overlays::boxed;
use crate::ui::selection_bg;
use crate::ui::text::{cells, truncate};

/// Draw the Scan view into `area`.
pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Scan — crawl & injection-point discovery", area, buf);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    // Degraded when the bus does not offer the scanner (never broken, §2.8).
    if !app.has_tool("scan.discover") {
        buf.set_string(
            inner.x + 1,
            inner.y + 1,
            "scan.discover is not on this bus (needs the scanner plugin).",
            theme.text_tertiary(),
        );
        return;
    }
    let [target_line, hint_line, lists] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
    ])
    .areas(inner);

    header(app, theme, target_line, hint_line, buf);

    let [ep, ip] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(lists);
    for y in ep.y..ep.bottom() {
        buf.set_string(ep.right().saturating_sub(1), y, "│", theme.rule());
    }
    endpoints(
        app,
        theme,
        Rect::new(ep.x, ep.y, ep.width.saturating_sub(1), ep.height),
        buf,
    );
    points(app, theme, ip, buf);
}

/// The launch header: the scope-bound target and the crawl state, then a hint
/// (or the last error).
fn header(app: &App, theme: &Theme, target_area: Rect, hint_area: Rect, buf: &mut Buffer) {
    let state = if app.scan.running {
        Span::styled(
            "crawling…",
            theme.text_secondary().add_modifier(Modifier::BOLD),
        )
    } else if app.scan.endpoints.is_empty() && app.scan.points.is_empty() {
        Span::styled("idle", theme.text_tertiary())
    } else {
        Span::styled(
            format!(
                "{} endpoints · {} injection points",
                app.scan.endpoints.len(),
                app.scan.points.len()
            ),
            theme.text_secondary(),
        )
    };
    let target = app
        .scan
        .target
        .as_deref()
        .unwrap_or("no in-scope host — add one to scope (S)");
    put(
        buf,
        target_area,
        Line::from(vec![
            Span::styled(" target ", theme.accent().add_modifier(Modifier::BOLD)),
            Span::styled(
                truncate(target, usize::from(target_area.width).saturating_sub(24)),
                theme.text_primary(),
            ),
            Span::raw("   "),
            state,
        ]),
    );
    let hint = match &app.scan.error {
        Some(e) => Line::styled(
            format!(" error: {e}"),
            theme.fg(&crate::tokens::color::status::SERVER_ERROR),
        ),
        None => Line::styled(
            " r scan (scope-bound) · Tab switch list · ↑↓ move · ⏎ open flow · F findings",
            theme.text_tertiary(),
        ),
    };
    put(buf, hint_area, hint);
}

/// The reached endpoints: a cursor list of URLs rendered verbatim. When the
/// endpoints list is focused (Tab), ⏎ opens the selected endpoint's linked flow
/// in the inspector (AC3) — the cursor row is highlighted only while focused.
fn endpoints(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
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
    if app.scan.endpoints.is_empty() {
        buf.set_string(
            body.x + 1,
            body.y,
            "none yet — r scans an in-scope target",
            theme.text_tertiary(),
        );
        return;
    }
    let focused = app.scan.focus == ScanFocus::Endpoints;
    let h = usize::from(body.height);
    let cursor = app.scan.endpoint_cursor.min(app.scan.endpoints.len() - 1);
    let top = cursor.saturating_sub(h.saturating_sub(1));
    for (k, e) in app.scan.endpoints.iter().enumerate().skip(top).take(h) {
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
/// redacted example (the scanner redacts at the source; the UI never re-derives
/// a raw value).
fn points(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
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
    if app.scan.points.is_empty() {
        buf.set_string(body.x + 1, body.y, "none yet", theme.text_tertiary());
        return;
    }
    let focused = app.scan.focus == ScanFocus::Points;
    let h = usize::from(body.height);
    let cursor = app.scan.cursor.min(app.scan.points.len() - 1);
    let top = cursor.saturating_sub(h.saturating_sub(1));
    for (k, p) in app.scan.points.iter().enumerate().skip(top).take(h) {
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
