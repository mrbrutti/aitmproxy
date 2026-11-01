//! The Scan operator surface (scanner v2 spec D2, D11, D13): one box with the
//! four-tab strip, a one-line state banner and the active tab's view.
//!
//! This module owns only the chrome every tab shares; `profiles`, `jobs`,
//! `sitemap` and `issues` draw one tab each, and `confirm` is the wire-confirm
//! overlay. What the view can show at all is the feature matrix of D2: a bus
//! with `scan.start` gets the v2 surface, a bus with only `scan.discover` the
//! legacy one-shot (D12), a bus with neither is told so in the banner.

pub mod confirm;
pub mod issues;
pub mod jobs;
pub mod profiles;
pub mod sitemap;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{ScanOffer, ScanTab};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::overlays::boxed;
use crate::ui::text::truncate;

/// What a bus without any scanner is told, in the banner of every tab (D2).
pub const NO_SCANNER: &str = "the scanner is not on this bus (scan.start / scan.discover)";

/// Draw the Scan view into `area`.
pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let inner = boxed(theme, "Scan", area, buf);
    if inner.height == 0 || inner.width == 0 {
        return;
    }
    let strip = Rect::new(inner.x, inner.y, inner.width, 1);
    tab_strip(app, theme, strip, buf);
    if inner.height < 2 {
        return;
    }
    let body = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);
    match app.scan.tab {
        ScanTab::Profiles => profiles::render(app, theme, body, buf),
        ScanTab::Jobs => jobs::render(app, theme, body, buf),
        ScanTab::SiteMap => sitemap::render(app, theme, body, buf),
        ScanTab::Issues => issues::render(app, theme, body, buf),
    }
}

/// `1 Profiles  2 Jobs  3 Site map  4 Issues`, the active tab bold, with the
/// state banner to its right (D11). A banner too long for what the strip
/// leaves is cut rather than wrapped; the detail it names is always on the
/// tab itself.
fn tab_strip(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let mut spans = Vec::new();
    for tab in ScanTab::ALL {
        let active = app.scan.tab == tab;
        let style = if active {
            theme.text_primary().add_modifier(Modifier::BOLD)
        } else {
            theme.text_tertiary()
        };
        spans.push(Span::styled(
            format!(" {} {} ", tab.index() + 1, tab.label()),
            style,
        ));
    }
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let room = usize::from(area.width).saturating_sub(used + 4);
    let text = banner(app);
    if room > 0 {
        spans.push(Span::raw("    "));
        spans.push(Span::styled(
            truncate(&text, room),
            banner_style(app, theme),
        ));
    }
    put(buf, area, Line::from(spans));
}

/// The banner's hue: an error reads in the server-error colour, everything
/// else is secondary text (D13: hue only on data).
fn banner_style(app: &App, theme: &Theme) -> ratatui::style::Style {
    if tab_error(app).is_some() {
        theme.fg(&crate::tokens::color::status::SERVER_ERROR)
    } else {
        theme.text_secondary()
    }
}

/// What a legacy bus can say about profiles (D2).
const PROFILES_DEGRADED: &str = "profiles need scan.profile.list (scanner v2)";

/// What a legacy bus can say about issues (D2, literal fixed on panel review
/// 2026-11-01).
const ISSUES_DEGRADED: &str = "issues need scan.issues (scanner v2)";

/// The one-line state of the active tab (D11, D13), in this order: no
/// scanner at all, the last error of this tab, the tab's degraded text (a
/// legacy bus, or a v2 bus missing the tab's verb), a refresh in flight over
/// an empty pane, or `idle`. The banner is the one place a degraded state is
/// written (D13: exactly one state on screen); the pane bodies never repeat
/// it.
fn banner(app: &App) -> String {
    if app.scan_offer() == ScanOffer::None {
        return NO_SCANNER.to_string();
    }
    if let Some(e) = tab_error(app) {
        return e.wording();
    }
    if let Some(text) = degraded(app) {
        return text;
    }
    if let Some(verb) = refreshing(app) {
        return format!("refreshing {verb}...");
    }
    "idle".to_string()
}

/// The active tab's degraded text, when the bus cannot serve it (D2): on a
/// legacy bus Profiles and Issues name what they need; on a v2 bus a tab
/// whose own verb is missing names it. Jobs is not gated by a verb in D2 (a
/// v2 bus has `scan.start` by definition), and the Site map on a legacy bus
/// is the legacy result (D12), not degraded.
fn degraded(app: &App) -> Option<String> {
    let verb = match (app.scan_offer(), app.scan.tab) {
        (ScanOffer::Legacy, ScanTab::Profiles) => return Some(PROFILES_DEGRADED.to_string()),
        (ScanOffer::Legacy, ScanTab::Issues) => return Some(ISSUES_DEGRADED.to_string()),
        (ScanOffer::V2, ScanTab::Profiles) => "scan.profile.list",
        (ScanOffer::V2, ScanTab::SiteMap) => "scan.sitemap",
        (ScanOffer::V2, ScanTab::Issues) => "scan.issues",
        _ => return None,
    };
    (!app.has_tool(verb)).then(|| missing_verb(verb))
}

/// The active tab's last error, falling back to the view's for a tab that
/// keeps none of its own. On a legacy bus the Jobs tab's error is the
/// `scan.discover` failure the legacy state kept (fix round A, A13).
fn tab_error(app: &App) -> Option<crate::scan::ScanError> {
    let own = match app.scan.tab {
        ScanTab::Profiles => app.scan.profiles.error.clone(),
        ScanTab::Jobs if app.scan_offer() == ScanOffer::Legacy => app
            .scan
            .legacy
            .error
            .as_deref()
            .map(|e| crate::scan::ScanError::from_message("scan.discover", e)),
        ScanTab::Jobs => None,
        ScanTab::SiteMap => app.scan.sitemap.error.clone(),
        ScanTab::Issues => app.scan.issues.error.clone(),
    };
    own.or_else(|| app.scan.last_error.clone())
}

/// The verb the active tab is waiting on while its pane is still empty.
fn refreshing(app: &App) -> Option<&'static str> {
    let (verb, empty) = match app.scan.tab {
        ScanTab::Profiles => ("scan.profile.list", app.scan.profiles.list.is_empty()),
        ScanTab::Jobs => ("scan.list", app.scan.jobs.order.is_empty()),
        ScanTab::SiteMap => ("scan.sitemap", app.scan.sitemap.nodes.is_empty()),
        ScanTab::Issues => ("scan.issues", app.scan.issues.list.is_empty()),
    };
    let waiting = app
        .scan
        .inflight
        .iter()
        .any(|tag| crate::scan::tag_parts(tag).0 == verb);
    (empty && waiting).then_some(verb)
}

/// Split a tab's body into its list and detail panes: side by side (45/55)
/// from 100 columns, stacked (40/60) below that, with one rule between them
/// (D11). Both rects exclude the rule.
pub fn panes(area: Rect) -> (Rect, Rect) {
    if area.width >= 100 {
        let left = area.width * 45 / 100;
        let list = Rect::new(area.x, area.y, left, area.height);
        let detail = Rect::new(
            area.x + left + 1,
            area.y,
            area.width.saturating_sub(left + 1),
            area.height,
        );
        (list, detail)
    } else {
        let top = (area.height * 40 / 100).max(1);
        let list = Rect::new(area.x, area.y, area.width, top);
        let rest = area.height.saturating_sub(top + 1);
        let detail = Rect::new(area.x, area.y + top + 1, area.width, rest);
        (list, detail)
    }
}

/// Draw the rule [`panes`] leaves between the two panes.
pub fn pane_rule(theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.width >= 100 {
        let x = area.x + area.width * 45 / 100;
        for y in area.y..area.bottom() {
            buf.set_string(x, y, "│", theme.rule());
        }
    } else {
        let y = area.y + (area.height * 40 / 100).max(1);
        if y < area.bottom() {
            buf.set_string(area.x, y, "─".repeat(usize::from(area.width)), theme.rule());
        }
    }
}

/// One line of secondary text at the top of `area`: what a tab draws when it
/// is empty, degraded or not served by this bus (D13).
pub fn note(theme: &Theme, area: Rect, text: &str, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    buf.set_string(
        area.x + 1,
        area.y,
        truncate(text, usize::from(area.width).saturating_sub(2)),
        theme.text_tertiary(),
    );
}

/// The inline wording of a control whose verb this bus does not offer (D2).
pub fn missing_verb(verb: &str) -> String {
    format!("{verb} is not on this bus")
}
