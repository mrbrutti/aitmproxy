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

/// A tab body split into its list and detail panes, with the rule between
/// them (D11). Both panes exclude the rule; `rule` is `None` when the body is
/// too small to leave a cell for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Panes {
    pub list: Rect,
    pub detail: Rect,
    pub rule: Option<Rect>,
}

/// Split a tab's body into its list and detail panes: side by side (45/55)
/// from 100 columns, stacked (40/60) below that, with one rule between them
/// (D11). The split is decided once, here, and the arithmetic runs in `u32`
/// so a very wide terminal cannot overflow `u16` (fix round A, A12).
pub fn panes(area: Rect) -> Panes {
    let percent = |whole: u16, pct: u32| -> u16 {
        // `whole * pct / 100 <= whole`, so the narrowing cannot lose bits.
        u16::try_from(u32::from(whole) * pct / 100).unwrap_or(whole)
    };
    if area.width >= 100 {
        let left = percent(area.width, 45);
        let list = Rect::new(area.x, area.y, left, area.height);
        let rule_x = area.x.saturating_add(left);
        let detail = Rect::new(
            rule_x.saturating_add(1),
            area.y,
            area.width.saturating_sub(left.saturating_add(1)),
            area.height,
        );
        let rule = (left < area.width).then(|| Rect::new(rule_x, area.y, 1, area.height));
        Panes { list, detail, rule }
    } else {
        let top = percent(area.height, 40).max(1);
        let list = Rect::new(area.x, area.y, area.width, top);
        let rule_y = area.y.saturating_add(top);
        let detail = Rect::new(
            area.x,
            rule_y.saturating_add(1),
            area.width,
            area.height.saturating_sub(top.saturating_add(1)),
        );
        let rule = (top < area.height).then(|| Rect::new(area.x, rule_y, area.width, 1));
        Panes { list, detail, rule }
    }
}

/// Draw the rule [`panes`] left between the two panes, if it left one.
pub fn pane_rule(theme: &Theme, panes: &Panes, buf: &mut Buffer) {
    let Some(rule) = panes.rule else {
        return;
    };
    if rule.width == 1 {
        for y in rule.y..rule.bottom() {
            buf.set_string(rule.x, y, "│", theme.rule());
        }
    } else {
        buf.set_string(
            rule.x,
            rule.y,
            "─".repeat(usize::from(rule.width)),
            theme.rule(),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round A, A12: the split is computed in `u32`, so a very wide
    /// terminal (1500 columns overflows `u16` at `width * 45`) neither
    /// panics nor loses the rule; the list is 45 percent of the width.
    #[test]
    fn panes_split_a_1500_column_rect_without_overflow() {
        let area = Rect::new(0, 0, 1500, 60);
        let p = panes(area);
        assert_eq!(u32::from(p.list.width), 1500 * 45 / 100);
        assert_eq!(p.list, Rect::new(0, 0, 675, 60));
        assert_eq!(p.rule, Some(Rect::new(675, 0, 1, 60)));
        assert_eq!(p.detail, Rect::new(676, 0, 824, 60));
        let mut buf = Buffer::empty(area);
        pane_rule(&Theme::new(true), &p, &mut buf);
        assert_eq!(buf.cell((675, 59)).map(|c| c.symbol()), Some("│"));
    }

    /// Below 100 columns the panes stack 40/60 with one rule row between.
    #[test]
    fn panes_stack_below_100_columns() {
        let p = panes(Rect::new(0, 3, 80, 20));
        assert_eq!(p.list, Rect::new(0, 3, 80, 8));
        assert_eq!(p.rule, Some(Rect::new(0, 11, 80, 1)));
        assert_eq!(p.detail, Rect::new(0, 12, 80, 11));
    }
}
