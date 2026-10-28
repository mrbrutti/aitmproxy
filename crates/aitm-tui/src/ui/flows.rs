//! The flow list (§2.7 "Flow list"): one line per row, Proxyman's column set,
//! colour on data not chrome. Columns drop from the right as the terminal
//! narrows; the status dot, `#`, URL, method, status and time always stay.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::model::{clock_of, human_bytes, human_ms, FlowKind, FlowRow, Origin};
use crate::theme::Theme;
use crate::tokens::{color, glyph};
use crate::ui::text::{elide_middle, fit, right, width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColKey {
    Tick,
    Dot,
    Seq,
    Url,
    Client,
    Method,
    Status,
    Time,
    Dur,
    Req,
    Resp,
    Ssl,
    Edited,
    Origin,
}

#[derive(Debug, Clone, Copy)]
pub struct Col {
    pub key: ColKey,
    pub title: &'static str,
    pub w: usize,
    pub right: bool,
}

/// The columns that fit in `width` cells, URL taking what is left.
pub fn columns(width: usize) -> Vec<Col> {
    let mut cols = vec![
        Col {
            key: ColKey::Tick,
            title: "",
            w: 1,
            right: false,
        },
        Col {
            key: ColKey::Dot,
            title: "",
            w: 1,
            right: false,
        },
        Col {
            key: ColKey::Seq,
            title: "#",
            w: 5,
            right: true,
        },
        Col {
            key: ColKey::Url,
            title: "URL",
            w: 20,
            right: false,
        },
        Col {
            key: ColKey::Method,
            title: "Method",
            w: 7,
            right: false,
        },
        Col {
            key: ColKey::Status,
            title: "Status",
            w: 6,
            right: false,
        },
        Col {
            key: ColKey::Time,
            title: "Time",
            w: 12,
            right: false,
        },
    ];
    let optional = [
        (
            80,
            Col {
                key: ColKey::Client,
                title: "Client",
                w: 8,
                right: false,
            },
        ),
        (
            95,
            Col {
                key: ColKey::Dur,
                title: "Duration",
                w: 8,
                right: true,
            },
        ),
        (
            110,
            Col {
                key: ColKey::Req,
                title: "Request",
                w: 8,
                right: true,
            },
        ),
        (
            120,
            Col {
                key: ColKey::Resp,
                title: "Response",
                w: 8,
                right: true,
            },
        ),
        (
            128,
            Col {
                key: ColKey::Ssl,
                title: "SSL",
                w: 3,
                right: false,
            },
        ),
        (
            134,
            Col {
                key: ColKey::Edited,
                title: "Ed",
                w: 2,
                right: false,
            },
        ),
        (
            142,
            Col {
                key: ColKey::Origin,
                title: "Origin",
                w: 6,
                right: false,
            },
        ),
    ];
    for (min, c) in optional {
        if width >= min {
            // Client sits right after URL, as Proxyman orders it.
            if c.key == ColKey::Client {
                cols.insert(4, c);
            } else {
                cols.push(c);
            }
        }
    }
    let fixed: usize = cols
        .iter()
        .filter(|c| c.key != ColKey::Url)
        .map(|c| c.w + 1)
        .sum();
    if let Some(url) = cols.iter_mut().find(|c| c.key == ColKey::Url) {
        url.w = width.saturating_sub(fixed + 1).max(12);
    }
    cols
}

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    if area.height == 0 {
        return;
    }
    let cols = columns(usize::from(area.width));

    // Header row.
    let mut hdr: Vec<Span<'_>> = Vec::new();
    for c in &cols {
        let t = if c.right {
            right(c.title, c.w)
        } else {
            fit(c.title, c.w)
        };
        hdr.push(Span::styled(t, theme.text_secondary()));
        hdr.push(Span::raw(" "));
    }
    buf.set_style(Rect::new(area.x, area.y, area.width, 1), theme.raised());
    buf.set_line(area.x, area.y, &Line::from(hdr), area.width);

    let rows_area = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    let visible = app.visible();
    if visible.is_empty() {
        let msg = if app.flows.is_empty() {
            match &app.listening {
                Some(l) => format!("No flows yet — point a client at {l} or open the browser."),
                None => {
                    "No flows yet — point a client at the proxy or open the browser.".to_string()
                }
            }
        } else {
            "No flows match this filter — Esc clears it.".to_string()
        };
        if rows_area.height > 0 {
            buf.set_string(
                rows_area.x + 2,
                rows_area.y + rows_area.height / 3,
                msg,
                theme.text_tertiary(),
            );
        }
        return;
    }

    // Entries: group headers interleaved with rows.
    enum Entry {
        Header(String, usize),
        Row(usize),
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(visible.len() + 8);
    for (pos, &i) in visible.iter().enumerate() {
        if let Some((title, n)) = app.group_header(&visible, pos) {
            entries.push(Entry::Header(title, n));
        }
        entries.push(Entry::Row(i));
    }
    let sel_pos = app.selected.as_deref().and_then(|id| {
        entries
            .iter()
            .position(|e| matches!(e, Entry::Row(i) if app.flows[*i].id == id))
    });
    let h = usize::from(rows_area.height);
    let offset = match sel_pos {
        Some(p) if p >= h => p + 1 - h,
        Some(_) => 0,
        None => entries.len().saturating_sub(h),
    };

    for (k, entry) in entries.iter().skip(offset).take(h).enumerate() {
        let y = rows_area.y + k as u16;
        let row_rect = Rect::new(rows_area.x, y, rows_area.width, 1);
        match entry {
            Entry::Header(title, n) => {
                buf.set_style(row_rect, theme.raised());
                let line = Line::from(vec![
                    Span::styled(
                        format!("  ▾ {title}"),
                        theme.text_primary().add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("  {n}"), theme.text_tertiary()),
                ]);
                buf.set_line(row_rect.x, y, &line, row_rect.width);
            }
            Entry::Row(i) => {
                let r = &app.flows[*i];
                let selected = app.selected.as_deref() == Some(r.id.as_str());
                if selected {
                    let sel = theme.selection();
                    let mut bg_only = Style::default().add_modifier(sel.add_modifier);
                    if let Some(bg) = sel.bg {
                        bg_only = bg_only.bg(bg);
                    }
                    buf.set_style(row_rect, bg_only);
                }
                let line = row_line(app, theme, r, &cols);
                buf.set_line(row_rect.x, y, &line, row_rect.width);
            }
        }
    }
}

fn row_line<'a>(app: &App, theme: &Theme, r: &'a FlowRow, cols: &[Col]) -> Line<'a> {
    let in_scope = app.in_scope(r);
    let dim = theme.text_tertiary();
    // Out-of-scope rows are entirely tertiary (§2.7 "scope-as-authorisation").
    let s = |style: Style| if in_scope { style } else { dim };
    let mut spans: Vec<Span<'a>> = Vec::with_capacity(cols.len() * 2);
    for c in cols {
        let span = match c.key {
            ColKey::Tick => match (r.origin, r.paused()) {
                (_, true) => Span::styled("▎", s(theme.fg(&color::intercept::BASE))),
                (Origin::Agent, _) => Span::styled("▎", s(theme.agent())),
                _ => Span::raw(" "),
            },
            ColKey::Dot => {
                let style = if r.paused() || r.pending() {
                    theme.fg(&color::intercept::BASE)
                } else if r.killed() {
                    theme.fg(&color::status::KILLED)
                } else if r.kind == FlowKind::WebSocket {
                    theme.fg(&color::status::INFORMATIONAL)
                } else {
                    theme
                        .status(r.status, false)
                        .remove_modifier(Modifier::BOLD)
                };
                Span::styled(glyph::RECORD, s(style))
            }
            ColKey::Seq => {
                let t = if r.is_replay {
                    format!("{}{}", r.seq, glyph::REPLAY)
                } else {
                    r.seq.to_string()
                };
                Span::styled(right(&t, c.w), s(theme.text_secondary()))
            }
            ColKey::Url => {
                // host in ink, path in the accent/link colour, query dimmed.
                let scheme_host = format!("{}://{}", r.scheme, r.authority);
                let path = r.path_only().to_string();
                let query = r.query().unwrap_or("").to_string();
                let total = width(&scheme_host) + width(&path) + width(&query);
                let host_style = if r.killed() {
                    theme
                        .fg(&color::status::KILLED)
                        .add_modifier(Modifier::CROSSED_OUT)
                } else {
                    theme.text_primary()
                };
                if total <= c.w {
                    let pad = c.w - total;
                    spans.push(Span::styled(scheme_host, s(host_style)));
                    spans.push(Span::styled(path, s(theme.fg(&color::text::LINK))));
                    spans.push(Span::styled(query, s(dim)));
                    spans.push(Span::raw(" ".repeat(pad + 1)));
                    continue;
                }
                let host_w = width(&scheme_host);
                if host_w + 6 <= c.w {
                    let rest_w = c.w - host_w;
                    let tail = elide_middle(&format!("{path}{query}"), rest_w);
                    spans.push(Span::styled(scheme_host, s(host_style)));
                    spans.push(Span::styled(
                        fit(&tail, rest_w),
                        s(theme.fg(&color::text::LINK)),
                    ));
                    spans.push(Span::raw(" "));
                    continue;
                }
                Span::styled(fit(&elide_middle(&r.url(), c.w), c.w), s(host_style))
            }
            ColKey::Client => match &r.client {
                Some(cl) => Span::styled(fit(cl, c.w), s(theme.text_secondary())),
                None => Span::styled(fit("—", c.w), dim),
            },
            ColKey::Method => {
                let m = if r.kind == FlowKind::WebSocket {
                    "WS"
                } else {
                    r.method.as_str()
                };
                let label = fit(&format!(" {m}"), c.w);
                Span::styled(label, s(theme.method(m)))
            }
            ColKey::Status => {
                if r.paused() {
                    Span::styled(
                        fit("Paused", c.w),
                        s(theme
                            .fg(&color::intercept::BASE)
                            .add_modifier(Modifier::BOLD)),
                    )
                } else if r.killed() {
                    Span::styled(fit("killed", c.w), s(theme.fg(&color::status::KILLED)))
                } else {
                    match r.status {
                        Some(code) => Span::styled(
                            fit(&code.to_string(), c.w),
                            s(theme.status(Some(code), false)),
                        ),
                        None => Span::styled(fit("—", c.w), dim),
                    }
                }
            }
            ColKey::Time => Span::styled(
                fit(&r.time.as_deref().map_or("—".to_string(), clock_of), c.w),
                s(theme.text_secondary()),
            ),
            ColKey::Dur => {
                let t = match (r.duration_ms, r.pending() || r.paused()) {
                    (Some(ms), _) => human_ms(ms),
                    (None, true) => "…".to_string(),
                    (None, false) => "—".to_string(),
                };
                Span::styled(right(&t, c.w), s(theme.text_secondary()))
            }
            ColKey::Req => Span::styled(
                right(&r.req_size.map_or("—".into(), human_bytes), c.w),
                s(theme.text_secondary()),
            ),
            ColKey::Resp => {
                let t = if r.kind == FlowKind::WebSocket {
                    r.ws_messages.map_or("—".to_string(), |n| format!("{n} ⇄"))
                } else {
                    r.resp_size.map_or("—".into(), human_bytes)
                };
                Span::styled(right(&t, c.w), s(theme.text_secondary()))
            }
            ColKey::Ssl => {
                let (g, st) = match (r.scheme.as_str(), r.tls) {
                    ("https" | "wss", Some(true)) | ("https" | "wss", None) => {
                        ("🔓", theme.text_secondary())
                    }
                    ("https" | "wss", Some(false)) => ("⚠", theme.fg(&color::intercept::BASE)),
                    _ => ("  ", dim),
                };
                Span::styled(fit(g, c.w), s(st))
            }
            ColKey::Edited => Span::styled(
                fit(if r.edited { glyph::COMPOSE } else { " " }, c.w),
                s(theme.text_secondary()),
            ),
            ColKey::Origin => match r.origin {
                Origin::Agent => Span::styled(
                    fit("agent", c.w),
                    s(theme.agent().add_modifier(Modifier::BOLD)),
                ),
                _ => Span::raw(" ".repeat(c.w)),
            },
        };
        spans.push(span);
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_drop_from_the_right_as_the_terminal_narrows() {
        let wide = columns(200);
        assert!(wide.iter().any(|c| c.key == ColKey::Origin));
        assert_eq!(wide[4].key, ColKey::Client);
        let url = wide.iter().find(|c| c.key == ColKey::Url).unwrap();
        let used: usize = wide.iter().map(|c| c.w + 1).sum();
        assert!((190..=200).contains(&used));
        assert!(url.w > 60);
        let narrow = columns(90);
        assert!(!narrow.iter().any(|c| c.key == ColKey::Resp));
        assert!(narrow.iter().any(|c| c.key == ColKey::Client));
        let tiny = columns(60);
        assert_eq!(
            tiny.iter().map(|c| c.key).collect::<Vec<_>>(),
            vec![
                ColKey::Tick,
                ColKey::Dot,
                ColKey::Seq,
                ColKey::Url,
                ColKey::Method,
                ColKey::Status,
                ColKey::Time
            ]
        );
    }
}
