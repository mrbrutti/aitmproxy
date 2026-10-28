//! The inspector (§2.7): a summary strip (`POST · 200 OK · URL · meta`), then
//! Request | Response panes — side by side at 120 columns or more, stacked
//! below that — each with its tab row and a body viewer. In Edit mode the
//! request pane is the raw editor for the paused request.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::{App, Mode, Pane, REQUEST_TABS, RESPONSE_TABS};
use crate::model::{
    clock_of, human_bytes, human_ms, FlowDetail, FlowKind, FlowRow, Intercept, Message,
};
use crate::theme::Theme;
use crate::tokens::color;
use crate::ui::bars::put;
use crate::ui::text::{fit, truncate};
use crate::viewers;

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    for x in area.x..area.right() {
        buf.set_string(x, area.y, "─", theme.rule());
    }
    let Some(row) = app.selected_row() else {
        buf.set_string(
            area.x + 2,
            area.y + 1,
            "Select a flow to inspect it.",
            theme.text_tertiary(),
        );
        return;
    };
    let detail = app.selected_detail();
    let [_, summary_area, panes] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
    ])
    .areas(area);
    summary(app, theme, row, detail, summary_area, buf);

    let side_by_side = panes.width >= 120;
    let (req_area, resp_area) = if side_by_side {
        let [l, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .areas(panes);
        for y in l.y..l.bottom() {
            buf.set_string(l.right().saturating_sub(1), y, "│", theme.rule());
        }
        (Rect::new(l.x, l.y, l.width.saturating_sub(1), l.height), r)
    } else {
        let [t, b] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(panes);
        (t, b)
    };
    pane(app, theme, row, detail, Pane::Request, req_area, buf);
    pane(app, theme, row, detail, Pane::Response, resp_area, buf);
}

fn summary(
    app: &App,
    theme: &Theme,
    row: &FlowRow,
    detail: Option<&FlowDetail>,
    area: Rect,
    buf: &mut Buffer,
) {
    let method = if row.kind == FlowKind::WebSocket {
        "WS"
    } else {
        row.method.as_str()
    };
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(format!(" {method} "), theme.method(method)),
        Span::raw(" "),
    ];
    let status = match (row.intercept, row.status) {
        (Intercept::Intercepted, _) => {
            Span::styled(" Paused · request ", theme.badge(&color::method::PUT))
        }
        (Intercept::Killed, _) => Span::styled(
            " killed ",
            theme
                .fg(&color::status::KILLED)
                .add_modifier(Modifier::BOLD),
        ),
        (_, Some(code)) => Span::styled(
            format!(" {code} {} ", reason(code)),
            theme.status(Some(code), false),
        ),
        (_, None) => Span::styled(" pending ", theme.fg(&color::status::PENDING)),
    };
    spans.push(status);
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("{}://{}", row.scheme, row.authority),
        theme.text_primary().add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(row.path.clone(), theme.fg(&color::text::LINK)));
    let left = Line::from(spans);

    let mut meta: Vec<String> = Vec::new();
    if let Some(v) = &row.version {
        meta.push(v.clone());
    }
    if let Some(c) = detail.and_then(|d| d.client_conn.as_ref()) {
        if c.tls {
            meta.push(format!(
                "TLS{}",
                c.alpn
                    .as_deref()
                    .map_or(String::new(), |a| format!(" · {a}"))
            ));
        } else {
            meta.push("plain".into());
        }
    }
    if let Some(n) = row.req_size {
        meta.push(format!("req {}", human_bytes(n)));
    }
    if let Some(n) = row.resp_size {
        meta.push(format!("resp {}", human_bytes(n)));
    }
    if let Some(ms) = row.duration_ms {
        meta.push(human_ms(ms));
    }
    if let Some(c) = &row.client {
        meta.push(format!("client {c}"));
    }
    meta.push(if app.in_scope(row) {
        "in scope".into()
    } else {
        "OUT OF SCOPE".into()
    });
    let right = Line::styled(format!("{} ", meta.join(" · ")), theme.text_secondary());
    crate::ui::bars::put_sides(buf, area, left, right);
}

fn reason(code: u16) -> &'static str {
    match code {
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn pane(
    app: &App,
    theme: &Theme,
    row: &FlowRow,
    detail: Option<&FlowDetail>,
    which: Pane,
    area: Rect,
    buf: &mut Buffer,
) {
    if area.height < 2 {
        return;
    }
    let focused = app.inspector.pane == which
        && matches!(app.mode, Mode::Inspector | Mode::Edit | Mode::QuickLook);
    let (title, tabs, active) = match which {
        Pane::Request => ("Request", &REQUEST_TABS[..], app.inspector.request_tab),
        Pane::Response => ("Response", &RESPONSE_TABS[..], app.inspector.response_tab),
    };
    let title_style = if focused {
        theme.accent().add_modifier(Modifier::BOLD)
    } else {
        theme.text_primary().add_modifier(Modifier::BOLD)
    };
    let mut spans = vec![Span::styled(format!(" {title}  "), title_style)];
    for (i, t) in tabs.iter().enumerate() {
        if i == active {
            spans.push(Span::styled(
                *t,
                theme
                    .accent()
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ));
        } else {
            spans.push(Span::styled(*t, theme.text_secondary()));
        }
        spans.push(Span::raw("  "));
    }
    if which == Pane::Request && app.mode == Mode::Edit {
        spans.push(Span::styled(
            "editing",
            theme
                .fg(&color::intercept::BASE)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let tab_rect = Rect::new(area.x, area.y, area.width, 1);
    buf.set_style(tab_rect, theme.raised());
    put(buf, tab_rect, Line::from(spans));

    let body = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    let lines: Vec<Line<'_>> = if which == Pane::Request && app.mode == Mode::Edit {
        return editor(app, theme, body, buf);
    } else {
        content(app, theme, row, detail, which, tabs[active], body.width)
    };
    let scroll = if focused {
        usize::from(app.inspector.scroll)
    } else {
        0
    };
    let scroll = scroll.min(lines.len().saturating_sub(1));
    let gutter = lines.len() > 1
        && tabs[active] != "Headers"
        && tabs[active] != "Summary"
        && tabs[active] != "Connection";
    for (k, line) in lines
        .iter()
        .skip(scroll)
        .take(usize::from(body.height))
        .enumerate()
    {
        let y = body.y + k as u16;
        let mut x = body.x;
        if gutter {
            let n = format!("{:>4} ", scroll + k + 1);
            buf.set_string(x, y, &n, theme.line_number());
            x += 5;
        }
        buf.set_line(x, y, line, body.right().saturating_sub(x));
    }
    if lines.len() > usize::from(body.height) {
        let more = format!(
            " ↓ {} more ",
            lines.len() - scroll - usize::from(body.height).min(lines.len() - scroll)
        );
        let x = body.right().saturating_sub(more.len() as u16 + 1);
        buf.set_string(x, body.bottom() - 1, more, theme.text_tertiary());
    }
}

fn content<'a>(
    app: &'a App,
    theme: &Theme,
    row: &'a FlowRow,
    detail: Option<&'a FlowDetail>,
    which: Pane,
    tab: &str,
    width: u16,
) -> Vec<Line<'a>> {
    let Some(d) = detail else {
        let mut lines = viewers::facts(theme, &summary_facts(app, row, None));
        if app.has_tool("flow.detail") {
            lines.push(Line::styled("loading detail…", theme.text_tertiary()));
        } else {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "Headers and bodies need core follow-up F5 (flow.detail); the bus serves summaries only today.",
                theme.intercept_armed_quiet(),
            ));
        }
        return lines;
    };
    let msg: Option<&Message> = match which {
        Pane::Request => d.request.as_ref(),
        Pane::Response => d.response.as_ref(),
    };
    match (which, tab) {
        (_, "Headers") => match msg {
            Some(m) => viewers::headers(theme, &m.headers),
            None => pending_response(app, theme, row, d, width),
        },
        (Pane::Request, "Query") => viewers::query(theme, &row.path),
        (_, "Body") => match msg {
            Some(m) => viewers::body(theme, m),
            None => pending_response(app, theme, row, d, width),
        },
        (_, "Raw") => match msg {
            Some(m) => viewers::raw(theme, m, which == Pane::Request),
            None => pending_response(app, theme, row, d, width),
        },
        (Pane::Request, "Summary") => viewers::facts(theme, &summary_facts(app, row, Some(d))),
        (Pane::Request, "Connection") => {
            let mut rows: Vec<(&str, String)> = Vec::new();
            for (label, c) in [
                ("client", d.client_conn.as_ref()),
                ("server", d.server_conn.as_ref()),
            ] {
                match c {
                    Some(c) => {
                        rows.push((label, c.peer.clone().unwrap_or_else(|| "—".into())));
                        rows.push((
                            "  tls",
                            if c.tls {
                                "yes (decrypted)".into()
                            } else {
                                "no".into()
                            },
                        ));
                        rows.push(("  sni", c.sni.clone().unwrap_or_else(|| "—".into())));
                        rows.push(("  alpn", c.alpn.clone().unwrap_or_else(|| "—".into())));
                        if let Some(p) = &c.process {
                            rows.push(("  process", p.clone()));
                        }
                    }
                    None => rows.push((label, "— (not reached)".into())),
                }
            }
            viewers::facts(theme, &rows)
        }
        (Pane::Response, "JSON") => match msg.and_then(Message::body_text) {
            Some(t) => viewers::json::tree(theme, t, &app.inspector.folds)
                .unwrap_or_else(|| vec![Line::styled("body is not JSON", theme.text_tertiary())]),
            None => pending_response(app, theme, row, d, width),
        },
        (Pane::Response, "Hex") => match msg {
            Some(m) if !m.body.is_empty() => {
                viewers::hex::dump(theme, &m.body, if width >= 100 { 16 } else { 8 })
            }
            Some(_) => vec![Line::styled("0 B", theme.text_tertiary())],
            None => pending_response(app, theme, row, d, width),
        },
        (Pane::Response, "Diff") => {
            let other = reference_flow(app, row);
            let (Some(cur), Some((other_row, other_d))) = (msg, other) else {
                return vec![Line::styled(
                    "Diff needs a response and an earlier flow to the same endpoint (or :diff <id>).",
                    theme.text_tertiary(),
                )];
            };
            let old = other_d
                .response
                .as_ref()
                .and_then(Message::body_text)
                .unwrap_or("");
            let new = cur.body_text().unwrap_or("");
            let mut lines = vec![Line::styled(
                format!(
                    "vs flow #{} ({})",
                    other_row.seq,
                    other_row.time.as_deref().map_or("—".to_string(), clock_of)
                ),
                theme.text_tertiary(),
            )];
            if width >= 120 {
                lines.extend(viewers::diff::side_by_side(
                    theme,
                    old,
                    new,
                    usize::from(width / 2).saturating_sub(4),
                ));
            } else {
                lines.extend(viewers::diff::unified(theme, old, new));
            }
            lines
        }
        _ => vec![Line::styled("—", theme.text_tertiary())],
    }
}

/// While a request is paused there is no response: say so, and show the last
/// response to this endpoint for reference (as the mockup does).
fn pending_response<'a>(
    app: &'a App,
    theme: &Theme,
    row: &FlowRow,
    d: &FlowDetail,
    _width: u16,
) -> Vec<Line<'a>> {
    let why = match d.intercept {
        Intercept::Intercepted => "No response yet — the request is paused.",
        Intercept::Killed => "No response — the request was killed.",
        _ if row.kind == FlowKind::WebSocket => "WebSocket: see the frames below.",
        _ => "No response yet — the request is in flight.",
    };
    let mut lines = vec![Line::styled(why, theme.text_tertiary())];
    if row.kind == FlowKind::WebSocket {
        for f in &d.frames {
            let arrow = if f.dir == "c2s" { "→" } else { "←" };
            let style = if f.dir == "c2s" {
                theme.fg(&color::status::INFORMATIONAL)
            } else {
                theme.text_primary()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{} ", f.time.as_deref().map_or("—".to_string(), clock_of)),
                    theme.text_tertiary(),
                ),
                Span::styled(format!("{arrow} {} ", f.opcode), style),
                Span::styled(
                    String::from_utf8_lossy(&f.data).into_owned(),
                    theme.text_primary(),
                ),
                Span::styled(if f.injected { "  injected" } else { "" }, theme.agent()),
            ]));
        }
        return lines;
    }
    if let Some((other, od)) = reference_flow(app, row) {
        if let Some(resp) = &od.response {
            lines.push(Line::styled(
                format!(
                    "Showing the last response to this endpoint (flow #{}, {}) for reference.",
                    other.seq,
                    other.time.as_deref().map_or("—".to_string(), clock_of)
                ),
                theme.text_tertiary(),
            ));
            lines.push(Line::raw(""));
            lines.extend(viewers::body(theme, resp));
        }
    }
    lines
}

/// The most recent earlier flow to the same method + host + path that has a response.
fn reference_flow<'a>(app: &'a App, row: &FlowRow) -> Option<(&'a FlowRow, &'a FlowDetail)> {
    if let Some(id) = &app.inspector.diff_with {
        if let (Some(r), Some(d)) = (app.row(id), app.details.get(id)) {
            return Some((r, d));
        }
    }
    app.flows
        .iter()
        .filter(|r| {
            r.id != row.id
                && r.seq < row.seq
                && r.authority == row.authority
                && r.path_only() == row.path_only()
                && r.method == row.method
        })
        .filter_map(|r| {
            app.details
                .get(&r.id)
                .filter(|d| d.response.is_some())
                .map(|d| (r, d))
        })
        .max_by_key(|(r, _)| r.seq)
}

fn summary_facts<'a>(app: &App, row: &FlowRow, d: Option<&FlowDetail>) -> Vec<(&'a str, String)> {
    let mut rows: Vec<(&str, String)> = vec![
        ("id", row.id.clone()),
        (
            "kind",
            if row.kind == FlowKind::WebSocket {
                "websocket".into()
            } else {
                "http".into()
            },
        ),
        ("method", row.method.clone()),
        ("url", row.url()),
        (
            "status",
            match row.intercept {
                Intercept::Intercepted => "paused (intercepted)".into(),
                Intercept::Killed => "killed".into(),
                _ => row
                    .status
                    .map_or("pending".into(), |s| format!("{s} {}", reason(s))),
            },
        ),
        ("state", format!("{:?}", row.intercept).to_lowercase()),
        (
            "replay",
            if row.is_replay {
                "yes".into()
            } else {
                "no".into()
            },
        ),
        ("origin", format!("{:?}", row.origin).to_lowercase()),
        (
            "scope",
            if app.in_scope(row) {
                "in scope".into()
            } else {
                "out of scope — mutating actions disabled".into()
            },
        ),
    ];
    if let Some(d) = d {
        rows.push((
            "created",
            d.meta.created.clone().unwrap_or_else(|| "—".into()),
        ));
        rows.push(("duration", d.meta.duration_ms.map_or("—".into(), human_ms)));
        rows.push((
            "request",
            d.request
                .as_ref()
                .map_or("—".into(), |m| human_bytes(m.body.len() as u64)),
        ));
        rows.push((
            "response",
            d.response
                .as_ref()
                .map_or("—".into(), |m| human_bytes(m.body.len() as u64)),
        ));
        rows.push(("edited", if d.edited { "yes".into() } else { "no".into() }));
        rows.push((
            "marks",
            if d.meta.marks.is_empty() {
                "—".into()
            } else {
                d.meta.marks.join(", ")
            },
        ));
        rows.push((
            "comment",
            d.meta.comment.clone().unwrap_or_else(|| "—".into()),
        ));
        if d.meta.truncated {
            rows.push(("truncated", "yes — body capture cap hit".into()));
        }
    }
    rows
}

fn editor(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let Some(e) = &app.edit else {
        return;
    };
    let h = usize::from(area.height.saturating_sub(1));
    let top = e.cursor_line.saturating_sub(h.saturating_sub(1));
    for (k, line) in e.lines.iter().skip(top).take(h).enumerate() {
        let y = area.y + k as u16;
        let idx = top + k;
        let style = if line.is_empty() && idx > 0 {
            theme.text_tertiary()
        } else if idx == 0 {
            theme.text_primary().add_modifier(Modifier::BOLD)
        } else if line.contains(':') && !e.lines[..idx].iter().any(String::is_empty) {
            theme.text_primary()
        } else {
            theme.syntax_string()
        };
        let changed = e.original.get(idx) != Some(line);
        let gutter = if changed { "~ " } else { "  " };
        buf.set_string(area.x, y, gutter, theme.fg(&color::intercept::BASE));
        buf.set_string(
            area.x + 2,
            y,
            fit(line, usize::from(area.width.saturating_sub(2))),
            style,
        );
        if idx == e.cursor_line {
            let cx =
                area.x + 2 + e.cursor_col.min(usize::from(area.width.saturating_sub(3))) as u16;
            buf.set_style(
                Rect::new(cx, y, 1, 1),
                Style::default().add_modifier(Modifier::REVERSED),
            );
        }
    }
    let hint = if e.dirty() {
        "edits pending · ^S Apply & Resume sends flow.mutate then flow.resume · ^R revert · Esc cancel"
    } else {
        "no edits yet · type to change the request line, headers or body · ^S resumes unchanged"
    };
    buf.set_string(
        area.x + 2,
        area.bottom() - 1,
        truncate(hint, usize::from(area.width.saturating_sub(2))),
        theme.text_tertiary(),
    );
}
