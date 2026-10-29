//! The inspector (§2.7): a summary strip (`POST · 200 OK · URL · meta`), then
//! Request | Response panes — side by side at 120 columns or more, stacked
//! below that — each with its tab row and a body viewer. In Edit mode the
//! request pane is the raw editor for the paused request.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::{tab_follow_up, App, Mode, Pane, REQUEST_TABS, RESPONSE_TABS};
use crate::model::{
    clock_of, human_bytes, human_ms, FlowDetail, FlowKind, FlowRow, Intercept, Message, WsDir,
};
use crate::theme::Theme;
use crate::tokens::color;
use crate::ui::bars::{put, put_sides};
use crate::ui::selection_bg;
use crate::ui::text::{cells, fit, truncate};
use crate::viewers;

/// What a tab that waits on a core follow-up says instead of a viewer.
pub fn follow_up_sentence(tab: &str, f: &str) -> String {
    format!("{tab} need core follow-up {f} (flow.detail does not carry phase timings yet).")
}

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
        // A tab waiting on a core follow-up is drawn dim with its F-number
        // (§2.10(c): never silent), and still selectable so it can say why.
        let label = match tab_follow_up(t) {
            Some(f) => format!("{t} ({f})"),
            None => (*t).to_string(),
        };
        let disabled = tab_follow_up(t).is_some();
        if i == active {
            spans.push(Span::styled(
                label,
                theme
                    .accent()
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ));
        } else if disabled {
            spans.push(Span::styled(label, theme.text_tertiary()));
        } else {
            spans.push(Span::styled(label, theme.text_secondary()));
        }
        spans.push(Span::raw("  "));
    }
    // The `editing` badge is right-aligned so it survives a pane too narrow
    // for the whole tab row.
    let editing = (which == Pane::Request && app.mode == Mode::Edit).then(|| {
        Line::styled(
            "editing ",
            theme
                .fg(&color::intercept::BASE)
                .add_modifier(Modifier::BOLD),
        )
    });
    let tab_rect = Rect::new(area.x, area.y, area.width, 1);
    buf.set_style(tab_rect, theme.raised());
    // The JSON tab builds its tree once per frame: the node path on the tab
    // row (§2.7 "JSONPath of node") and the pane's lines come from the same
    // build. A large body (viewers::LARGE_BODY_BYTES) is not parsed at all.
    let json_tab = which == Pane::Response && tabs[active] == "JSON";
    let json = if json_tab {
        detail
            .and_then(|d| d.response.as_ref())
            .filter(|m| !viewers::is_large(m))
            .and_then(Message::body_text)
            .and_then(|t| viewers::json::tree_with_paths(theme, t, &app.inspector.folds))
    } else {
        None
    };
    let (json_lines, json_paths) = match json {
        Some((lines, paths)) => (Some(lines), Some(paths)),
        None => (None, None),
    };
    let path = json_paths.as_ref().and_then(|paths| {
        let last = paths.len().min(viewers::MAX_VIEWER_LINES).checked_sub(1)?;
        paths
            .get(app.inspector.cursor_line.min(last))
            .cloned()
            .flatten()
    });
    let right = match (editing, path) {
        (Some(badge), _) => Some(badge),
        (None, Some(path)) => Some(Line::styled(format!("{path} "), theme.text_secondary())),
        (None, None) => None,
    };
    match right {
        Some(right) => put_sides(buf, tab_rect, Line::from(spans), right),
        None => put(buf, tab_rect, Line::from(spans)),
    }

    let body = Rect::new(area.x, area.y + 1, area.width, area.height - 1);
    if which == Pane::Request && app.mode == Mode::Edit {
        return editor(app, theme, body, buf);
    }
    let has_tree = json_paths.is_some();
    let lines = viewers::page(
        theme,
        content(
            app,
            theme,
            row,
            detail,
            which,
            tabs[active],
            body.width,
            json_lines,
        ),
    );
    let last = lines.len().saturating_sub(1);
    let height = usize::from(body.height);
    // The focused pane scrolls to its offset, then far enough that the cursor
    // line is inside the window.
    let cursor = focused.then(|| app.inspector.cursor_line.min(last));
    let scroll = match cursor {
        Some(c) => {
            let s = usize::from(app.inspector.scroll).min(last);
            if c < s {
                c
            } else if c >= s + height {
                c + 1 - height
            } else {
                s
            }
        }
        None => 0,
    };
    // Line numbers only in front of a real viewer: not the key/value tabs,
    // and not the summary-facts fallback a tab shows before detail arrives
    // (the Query table comes from the row, so it counts either way).
    let viewer_tab = matches!(
        tabs[active],
        "Query" | "Body" | "Raw" | "JSON" | "Hex" | "Diff"
    );
    let gutter = lines.len() > 1 && viewer_tab && (detail.is_some() || tabs[active] == "Query");
    let highlight = cursor.filter(|_| has_tree);
    for (k, line) in lines.iter().skip(scroll).take(height).enumerate() {
        let y = body.y + cells(k);
        let mut x = body.x;
        if gutter {
            let n = format!("{:>4} ", scroll + k + 1);
            buf.set_string(x, y, &n, theme.line_number());
            x += 5;
        }
        buf.set_line(x, y, line, body.right().saturating_sub(x));
        if highlight == Some(scroll + k) {
            // Background and modifier only, so the syntax colours survive.
            buf.set_style(Rect::new(body.x, y, body.width, 1), selection_bg(theme));
        }
    }
    if lines.len() > usize::from(body.height) {
        let more = format!(
            " ↓ {} more ",
            lines.len() - scroll - usize::from(body.height).min(lines.len() - scroll)
        );
        let x = body.right().saturating_sub(cells(more.len()) + 1);
        buf.set_string(x, body.bottom() - 1, more, theme.text_tertiary());
    }
}

/// The lines of one tab. `json_lines` is the JSON tree `pane` already built
/// for the Response JSON tab (`None` on every other tab, or when the body is
/// large or not JSON).
#[allow(clippy::too_many_arguments)]
fn content<'a>(
    app: &'a App,
    theme: &Theme,
    row: &'a FlowRow,
    detail: Option<&'a FlowDetail>,
    which: Pane,
    tab: &str,
    width: u16,
    json_lines: Option<Vec<Line<'a>>>,
) -> Vec<Line<'a>> {
    // The query string is in the summary row; it needs no detail.
    if (which, tab) == (Pane::Request, "Query") {
        return viewers::query(theme, &row.path);
    }
    // Timing waits on core follow-up F5; Cookies and Set-Cookie render live
    // from the served headers below.
    if let Some(f) = tab_follow_up(tab) {
        return vec![Line::styled(
            follow_up_sentence(tab, f),
            theme.intercept_armed_quiet(),
        )];
    }
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
            None => pending_response(app, theme, row, d),
        },
        // Cookies / Set-Cookie parsed live from the served headers (I17a).
        (Pane::Request, "Cookies") => match msg {
            Some(m) => viewers::cookies(theme, &m.headers, false),
            None => pending_response(app, theme, row, d),
        },
        (Pane::Response, "Set-Cookie") => match msg {
            Some(m) => viewers::cookies(theme, &m.headers, true),
            None => pending_response(app, theme, row, d),
        },
        // A WebSocket flow's response is its `101` handshake (Headers tab); its
        // frames are the body worth reading.
        (Pane::Response, "Body") if row.kind == FlowKind::WebSocket => ws_frames(theme, d),
        (_, "Body") => match msg {
            Some(m) => viewers::body_paged(theme, m),
            None => pending_response(app, theme, row, d),
        },
        (_, "Raw") => match msg {
            Some(m) => viewers::raw_paged(theme, m, which == Pane::Request),
            None => pending_response(app, theme, row, d),
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
                        rows.push((
                            "  established",
                            c.established.as_deref().map_or("—".to_string(), clock_of),
                        ));
                        if label == "client" {
                            // Peer→process resolution is deferred by the core
                            // (foundation Q6): it reports null until then.
                            rows.push((
                                "  process",
                                c.process
                                    .clone()
                                    .unwrap_or_else(|| "— (not resolved by the core yet)".into()),
                            ));
                        }
                    }
                    None => rows.push((label, "— (not reached)".into())),
                }
            }
            viewers::facts(theme, &rows)
        }
        (Pane::Response, "JSON") => match (msg, json_lines) {
            (Some(m), _) if viewers::is_large(m) => {
                viewers::large_body_preview(theme, m, false, 16)
            }
            (Some(_), Some(lines)) => lines,
            (Some(_), None) => vec![Line::styled("body is not JSON", theme.text_tertiary())],
            (None, _) => pending_response(app, theme, row, d),
        },
        (Pane::Response, "Hex") => {
            let per_line = if width >= 100 { 16 } else { 8 };
            match msg {
                Some(m) if viewers::is_large(m) => {
                    viewers::large_body_preview(theme, m, true, per_line)
                }
                Some(m) if !m.body.is_empty() => viewers::hex::dump(theme, &m.body, per_line),
                Some(_) => vec![Line::styled("0 B", theme.text_tertiary())],
                None => pending_response(app, theme, row, d),
            }
        }
        (Pane::Response, "Diff") => {
            let other = reference_flow(app, row);
            let (Some(cur), Some((other_row, other_d))) = (msg, other) else {
                return vec![Line::styled(
                    "Diff needs a response and an earlier flow to the same endpoint (or :diff <id>).",
                    theme.text_tertiary(),
                )];
            };
            let other_resp = other_d.response.as_ref();
            if viewers::is_large(cur) || other_resp.is_some_and(viewers::is_large) {
                return vec![Line::styled(
                    format!(
                        "large body · diff skipped over {} · o to open externally",
                        human_bytes(viewers::LARGE_BODY_BYTES as u64)
                    ),
                    theme.intercept_armed_quiet(),
                )];
            }
            let old = other_resp.and_then(Message::body_text).unwrap_or("");
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
) -> Vec<Line<'a>> {
    let why = match d.intercept {
        Intercept::Intercepted => "No response yet — the request is paused.",
        Intercept::Killed => "No response — the request was killed.",
        _ if row.kind == FlowKind::WebSocket => "WebSocket: see the frames below.",
        _ => "No response yet — the request is in flight.",
    };
    let mut lines = vec![Line::styled(why, theme.text_tertiary())];
    if row.kind == FlowKind::WebSocket {
        lines.extend(ws_frames(theme, d));
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
            lines.extend(viewers::body_paged(theme, resp));
        }
    }
    lines
}

/// A WebSocket flow's frames (§3.7 "WS flow with frame list"), one per line:
/// `time · → / ← · opcode · text · injected`. The Response pane's Body tab
/// and quick-look show these; the `101` handshake stays on the Headers tab.
pub fn ws_frames<'a>(theme: &Theme, d: &FlowDetail) -> Vec<Line<'a>> {
    if d.messages.is_empty() {
        return vec![Line::styled("no frames yet", theme.text_tertiary())];
    }
    d.messages
        .iter()
        .map(|f| {
            let arrow = f.dir.map_or("?", WsDir::arrow);
            let style = match f.dir {
                Some(WsDir::ClientToServer) => theme.fg(&color::status::INFORMATIONAL),
                _ => theme.text_primary(),
            };
            Line::from(vec![
                Span::styled(
                    format!(
                        "{} ",
                        f.timestamp.as_deref().map_or("—".to_string(), clock_of)
                    ),
                    theme.text_tertiary(),
                ),
                Span::styled(format!("{arrow} {} ", f.opcode), style),
                Span::styled(
                    String::from_utf8_lossy(&f.data).into_owned(),
                    theme.text_primary(),
                ),
                Span::styled(if f.injected { "  injected" } else { "" }, theme.agent()),
            ])
        })
        .collect()
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
        let y = area.y + cells(k);
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
                area.x + 2 + cells(e.cursor_col.min(usize::from(area.width.saturating_sub(3))));
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

#[cfg(test)]
mod tests {
    use crate::action::Action;
    use crate::app::{Mode, Pane, RESPONSE_TABS};
    use crate::snapshot::{render as snap, to_text};
    use crate::theme::Theme;

    fn json_tab_app(cols: u16, rows: u16) -> crate::app::App {
        let mut app = crate::fixture_app(cols, rows);
        app.selected = Some("f41".into());
        app.mode = Mode::Inspector;
        app.inspector.pane = Pane::Response;
        app.inspector.response_tab = RESPONSE_TABS.iter().position(|t| *t == "JSON").unwrap();
        app
    }

    /// The buffer row (as text) that contains `needle`, with its y.
    fn row_with(buf: &ratatui::buffer::Buffer, needle: &str) -> Option<(u16, String)> {
        to_text(buf)
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(needle))
            .map(|(y, l)| (y as u16, l.to_string()))
    }

    #[test]
    fn json_tab_highlights_the_cursor_line_and_shows_its_path() {
        let theme = Theme::new(true);
        let mut app = json_tab_app(200, 50);
        app.inspector.cursor_line = 4;
        let buf = snap(&app, &theme, 200, 50);
        let (_, tabs) = row_with(&buf, "Response  Headers").expect("response tab row");
        assert!(
            tabs.trim_end().ends_with("$.items[0].name"),
            "node path right-aligned on the tab row: {tabs:?}"
        );
        let (y, _) = row_with(&buf, "Noise-cancelling headphones").expect("cursor line drawn");
        let sel = theme.selection().bg;
        let x = to_text(&buf)
            .lines()
            .nth(usize::from(y))
            .and_then(|l| l.find("Noise"))
            .unwrap() as u16;
        assert_eq!(buf.cell((x, y)).map(|c| c.bg), Some(sel.unwrap()));
        // The line above is not highlighted.
        assert_ne!(buf.cell((x, y - 1)).map(|c| c.bg), Some(sel.unwrap()));

        // Off the JSON tab there is no path and no highlight.
        app.inspector.response_tab = 1;
        let buf = snap(&app, &theme, 200, 50);
        let (_, tabs) = row_with(&buf, "Response  Headers").unwrap();
        assert!(!tabs.contains("$."), "{tabs:?}");

        // Without detail both Body tabs fall back to the summary facts, which
        // are not a body viewer: no line-number gutter in front of them.
        app.inspector.request_tab = crate::app::REQUEST_TABS
            .iter()
            .position(|t| *t == "Body")
            .unwrap();
        app.details.remove("f41");
        let text = to_text(&snap(&app, &theme, 200, 50));
        // The `id … f41` fact row: whatever sits before it on the line (the
        // sidebar), the label is `id`, not a line number followed by `id`.
        let fact_prefixes: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once("f41").map(|(before, _)| before.trim_end()))
            .filter(|before| before.ends_with("id"))
            .collect();
        assert!(!fact_prefixes.is_empty(), "{text}");
        for before in fact_prefixes {
            let before_id = before.strip_suffix("id").unwrap_or("").trim_end();
            assert!(
                !before_id.ends_with(|c: char| c.is_ascii_digit()),
                "gutter on facts: {before:?}"
            );
        }
    }

    /// I1/I17a: only Timing waits on F5 — it is labelled, dim, and says why.
    #[test]
    fn timing_tab_is_labelled_and_explains_itself() {
        let theme = Theme::new(true);
        let mut app = crate::fixture_app(200, 50);
        app.selected = Some("f41".into());
        app.mode = Mode::Inspector;
        let buf = snap(&app, &theme, 200, 50);
        let (y, req_tabs) = row_with(&buf, "Request  Headers").expect("request tab row");
        assert!(req_tabs.contains("Timing (F5)"), "{req_tabs}");
        // Cookies and Set-Cookie are live now: no F5 label on them.
        assert!(
            req_tabs.contains("Cookies  "),
            "cookies is live: {req_tabs}"
        );
        assert!(!req_tabs.contains("Cookies (F5)"), "{req_tabs}");
        let x = req_tabs
            .find("Timing")
            .map(|b| req_tabs[..b].chars().count())
            .unwrap();
        assert_eq!(
            buf.cell((x as u16, y)).map(|c| c.fg),
            theme.text_tertiary().fg,
            "disabled tab is dim"
        );
        let (_, resp_tabs) = row_with(&buf, "Response  Headers").expect("response tab row");
        assert!(!resp_tabs.contains("Set-Cookie (F5)"), "{resp_tabs}");

        app.inspector.pane = Pane::Request;
        app.inspector.request_tab = crate::app::REQUEST_TABS
            .iter()
            .position(|t| *t == "Timing")
            .unwrap();
        let text = to_text(&snap(&app, &theme, 200, 50));
        assert!(
            text.contains("Timing need core follow-up F5"),
            "Timing sentence: {text}"
        );
        // The reworded sentence no longer claims headers/bodies only.
        assert!(!text.contains("headers and bodies only"), "{text}");
    }

    /// I17a / minor (d): the Cookies tab parses the served `Cookie:` header
    /// live, binding each value to its own name on the same row.
    #[test]
    fn cookies_tab_renders_served_cookies_bound_to_their_names() {
        let theme = Theme::new(true);
        let mut app = crate::fixture_app(200, 50);
        app.selected = Some("f41".into());
        app.mode = Mode::Inspector;
        app.inspector.pane = Pane::Request;
        app.inspector.request_tab = crate::app::REQUEST_TABS
            .iter()
            .position(|t| *t == "Cookies")
            .unwrap();
        let buf = snap(&app, &theme, 200, 50);
        // f41 sends `cookie: session=9f1c…`: the value sits on the `session`
        // row, not merely somewhere on the screen.
        let (_, row) = row_with(&buf, "session").expect("cookie name row");
        assert!(
            row.contains("session") && row.contains("= 9f1c…"),
            "value bound to its name: {row:?}"
        );
        // No follow-up placeholder on a live tab.
        assert!(
            !to_text(&buf).contains("need core follow-up F5"),
            "cookies is live"
        );
    }

    #[test]
    fn json_tab_scrolls_to_keep_the_cursor_visible() {
        let theme = Theme::new(true);
        // A short terminal: the response pane shows fewer than 18 lines.
        let mut app = json_tab_app(200, 20);
        let text = to_text(&snap(&app, &theme, 200, 20));
        assert!(text.contains("\"items\": ["), "{text}");
        assert!(
            !text.contains("\"total\": 2"),
            "pane must be shorter than the tree: {text}"
        );
        // Cursor on the last line: the window follows it down.
        let _ = app.update(Action::End);
        assert_eq!(app.inspector.cursor_line, 17);
        let text = to_text(&snap(&app, &theme, 200, 20));
        assert!(text.contains("\"total\": 2"), "{text}");
        // And back up: Home shows the top again.
        let _ = app.update(Action::Home);
        let text = to_text(&snap(&app, &theme, 200, 20));
        assert!(text.contains("\"items\": ["), "{text}");
    }
}
