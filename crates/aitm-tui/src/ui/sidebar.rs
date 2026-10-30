//! The 28-column sidebar (§2.6 "Sidebar groups"): Working (Pinned, Saved),
//! All (Apps, Domains), aitmproxy (Scope, Findings, Browser, Scripts, Agent).
//! Counts sit only on queues; the selected item carries the `active` tint.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::{App, SidebarItem};
use crate::model::AgentPolicy;
use crate::theme::Theme;
use crate::tokens::glyph;
use crate::ui::text::{fit, truncate};

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    let w = usize::from(area.width);
    let mut y = area.y;
    let bottom = area.bottom();
    let mut line = |buf: &mut Buffer, l: Line<'_>| {
        if y < bottom {
            buf.set_line(area.x, y, &l, area.width);
            y += 1;
        }
    };

    line(
        buf,
        Line::from(vec![
            Span::styled(" ›•‹ ", theme.accent().add_modifier(Modifier::BOLD)),
            Span::styled(
                "aitmproxy",
                theme.text_primary().add_modifier(Modifier::BOLD),
            ),
        ]),
    );
    line(buf, Line::raw(""));

    let group = |title: &str| {
        Line::styled(
            format!(" {title}"),
            theme.text_tertiary().add_modifier(Modifier::BOLD),
        )
    };
    let item = |app: &App, it: SidebarItem, count: Option<String>, queue: bool| -> Line<'static> {
        let selected = app.sidebar == it;
        let base = if selected {
            theme.selection().add_modifier(Modifier::BOLD)
        } else {
            theme.text_primary()
        };
        let label = format!("  {}", it.label());
        let count_s = count.unwrap_or_default();
        let count_style = if selected {
            theme.selection()
        } else if queue {
            theme.text_secondary().add_modifier(Modifier::BOLD)
        } else {
            theme.text_tertiary()
        };
        let pad = w.saturating_sub(label.chars().count() + count_s.chars().count() + 1);
        Line::from(vec![
            Span::styled(label, base),
            Span::styled(
                " ".repeat(pad),
                if selected {
                    theme.selection()
                } else {
                    theme.surface()
                },
            ),
            Span::styled(format!("{count_s} "), count_style),
        ])
    };
    let child = |icon: &str, name: &str, count: Option<usize>| -> Line<'static> {
        let c = count.map_or(String::new(), |n| n.to_string());
        let avail = w.saturating_sub(6 + c.chars().count() + 1);
        Line::from(vec![
            Span::styled(format!("    {icon} "), theme.text_tertiary()),
            Span::styled(fit(&truncate(name, avail), avail), theme.text_secondary()),
            Span::styled(format!("{c} "), theme.text_tertiary()),
        ])
    };

    line(buf, group("Working"));
    let pinned_n = app.pinned_hosts.len();
    line(
        buf,
        item(
            app,
            SidebarItem::Pinned,
            (pinned_n > 0).then(|| pinned_n.to_string()),
            false,
        ),
    );
    for h in app.pinned_hosts.iter().take(3) {
        let n = app.flows.iter().filter(|r| r.host() == h).count();
        line(buf, child(glyph::SCOPE, h, Some(n)));
    }
    line(
        buf,
        item(app, SidebarItem::Saved, Some("F10".into()), false),
    );
    line(buf, Line::raw(""));

    line(buf, group("All"));
    line(
        buf,
        item(
            app,
            SidebarItem::All,
            Some(app.flows.len().to_string()),
            false,
        ),
    );
    let apps = app.apps();
    line(
        buf,
        item(app, SidebarItem::Apps, Some(apps.len().to_string()), false),
    );
    if app.sidebar == SidebarItem::Apps {
        for (name, n) in apps.iter().take(6) {
            let icon = name
                .chars()
                .next()
                .map_or("·".to_string(), |c| c.to_string());
            line(buf, child(&icon, name, Some(*n)));
        }
    }
    let domains = app.domains();
    line(
        buf,
        item(
            app,
            SidebarItem::Domains,
            Some(domains.len().to_string()),
            false,
        ),
    );
    if app.sidebar == SidebarItem::Domains {
        for (name, n) in domains.iter().take(6) {
            line(buf, child("◦", name, Some(*n)));
        }
    }
    line(buf, Line::raw(""));

    line(buf, group("aitmproxy"));
    line(
        buf,
        item(
            app,
            SidebarItem::Scope,
            Some(app.scope.len().to_string()),
            true,
        ),
    );
    // The findings list across sessions is `poc.list` (F13): without it the
    // item carries that label until a run this session gives it a count;
    // `0` only when the list exists and is empty.
    let findings_count = if !app.findings.is_empty() {
        app.findings.len().to_string()
    } else if app.has_tool("poc.list") {
        "0".to_string()
    } else {
        "F13".to_string()
    };
    line(
        buf,
        item(app, SidebarItem::Findings, Some(findings_count), true),
    );
    // The count here is the open tab count, which needs `browser.tabs` (F14):
    // missing is a dash (§2.8), the view itself is built (task 10).
    line(
        buf,
        item(app, SidebarItem::Browser, Some("—".into()), false),
    );
    line(
        buf,
        item(app, SidebarItem::Scripts, Some("M3".into()), false),
    );
    let agent_count = match app.agent.policy {
        Some(AgentPolicy::Paused) => "paused".to_string(),
        Some(_) => format!("{}/min", app.agent.actions_last_minute),
        None => "F1".to_string(),
    };
    line(buf, item(app, SidebarItem::Agent, Some(agent_count), true));
    // The Scan surface appears only when the bus offers the scanner plugin
    // (`scan.discover`); its count is the injection points found this session.
    if app.has_tool("scan.discover") {
        let scan_count = if !app.scan.points.is_empty() {
            app.scan.points.len().to_string()
        } else {
            "—".to_string()
        };
        line(buf, item(app, SidebarItem::Scan, Some(scan_count), false));
    }

    // Footer: the sidebar filter hint, pinned to the bottom.
    if area.height > 2 {
        let foot = Line::from(vec![
            Span::styled(" [ ] ", theme.text_primary().add_modifier(Modifier::BOLD)),
            Span::styled("move  ", theme.text_tertiary()),
            Span::styled("b ", theme.text_primary().add_modifier(Modifier::BOLD)),
            Span::styled("hide", theme.text_tertiary()),
        ]);
        buf.set_line(area.x, bottom - 1, &foot, area.width);
    }
    // Right edge rule.
    for yy in area.y..bottom {
        buf.set_string(area.right().saturating_sub(1), yy, "│", theme.rule());
    }
}
