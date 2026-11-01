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
use crate::scan::{ScanError, ScanOffer, ScanTab, NO_SCANNER};
use crate::theme::Theme;
use crate::ui::bars::put;
use crate::ui::overlays::boxed;
use crate::ui::text::truncate;

/// The blank cells between the tab strip and the state banner (D11).
const GAP: usize = 4;

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
    for (k, tab) in ScanTab::ALL.into_iter().enumerate() {
        let active = app.scan.tab == tab;
        let style = if active {
            theme.text_primary().add_modifier(Modifier::BOLD)
        } else {
            theme.text_tertiary()
        };
        spans.push(Span::styled(format!(" {} {} ", k + 1, tab.label()), style));
    }
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let room = usize::from(area.width).saturating_sub(used + GAP);
    // The active tab's error is found once per frame; the legacy Jobs tab's
    // is built here from the text the legacy state kept, so the banner and
    // its hue borrow the same value.
    let legacy_error = legacy_jobs_error(app);
    let error = tab_error(app, legacy_error.as_ref());
    let text = banner(app, error);
    if room > 0 {
        spans.push(Span::raw(" ".repeat(GAP)));
        spans.push(Span::styled(
            truncate(&text, room),
            banner_style(theme, error),
        ));
    }
    put(buf, area, Line::from(spans));
}

/// The banner's hue: an error reads in the server-error colour, everything
/// else (a notice included) is secondary text (D13: hue only on data).
fn banner_style(theme: &Theme, error: Option<&ScanError>) -> ratatui::style::Style {
    if error.is_some() {
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
/// scanner at all, the last error of this tab (`error`, found once per
/// frame by [`tab_error`]), the notice a key left (`already <state>`, which
/// answers the operator's last key and so outranks a standing degraded
/// text), the tab's degraded text (a legacy bus, or a v2 bus missing the
/// tab's verb), a refresh in flight over an empty pane, or `idle`. The
/// banner is the one place a degraded state is written (D13: exactly one
/// state on screen); the pane bodies never repeat it.
fn banner(app: &App, error: Option<&ScanError>) -> String {
    if app.scan_offer() == ScanOffer::None {
        return NO_SCANNER.to_string();
    }
    if let Some(e) = error {
        return e.wording();
    }
    if let Some(notice) = &app.scan.notice {
        return notice.clone();
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
    (!app.has_tool(verb)).then(|| ScanError::missing_verb(verb).wording())
}

/// On a legacy bus the Jobs tab's error is the `scan.discover` failure the
/// legacy state kept as text; the one `ScanError` built per frame, so the
/// Jobs tab's row never has to keep an error of its own. `None` on a v2
/// bus, where the Jobs tab reads `last_error` alone.
fn legacy_jobs_error(app: &App) -> Option<ScanError> {
    if app.scan.tab != ScanTab::Jobs || app.scan_offer() != ScanOffer::Legacy {
        return None;
    }
    app.scan
        .legacy
        .error
        .as_deref()
        .map(|e| ScanError::from_message("scan.discover", e))
}

/// The active tab's last error, falling back to the view's for a tab that
/// keeps none of its own; `legacy` is [`legacy_jobs_error`], the Jobs
/// tab's on a legacy bus.
fn tab_error<'a>(app: &'a App, legacy: Option<&'a ScanError>) -> Option<&'a ScanError> {
    let own = match app.scan.tab {
        ScanTab::Profiles => app.scan.profiles.error.as_ref(),
        ScanTab::Jobs => legacy,
        ScanTab::SiteMap => app.scan.sitemap.error.as_ref(),
        ScanTab::Issues => app.scan.issues.error.as_ref(),
    };
    own.or(app.scan.last_error.as_ref())
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
/// too small to leave a cell for it. Built only by [`panes`] and
/// [`stacked`], so every tab shares one arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Panes {
    pub list: Rect,
    pub detail: Rect,
    pub rule: Option<Rect>,
    /// Whether the panes sit left and right (a vertical rule) rather than
    /// top and bottom (a horizontal one).
    pub side_by_side: bool,
}

/// The share of a stacked body the list takes when it has rows to fill it
/// (D11: 40/60); the Jobs tab sizes its table to its rows up to this.
pub const STACKED_LIST_PERCENT: u32 = 40;

/// `whole * pct / 100` in `u32`, so a very wide terminal cannot overflow
/// `u16`. `whole * pct / 100 <= whole`, so the narrowing cannot lose bits.
fn percent(whole: u16, pct: u32) -> u16 {
    u16::try_from(u32::from(whole) * pct / 100).unwrap_or(whole)
}

/// The rows a stacked body's list takes at [`STACKED_LIST_PERCENT`].
pub fn stacked_share(height: u16) -> u16 {
    percent(height, STACKED_LIST_PERCENT)
}

/// Split a tab's body into its list and detail panes: side by side (45/55)
/// from 100 columns, stacked ([`STACKED_LIST_PERCENT`] over the rest) below
/// that, with one rule between them (D11). The split is decided once, here.
pub fn panes(area: Rect) -> Panes {
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
        Panes {
            list,
            detail,
            rule,
            side_by_side: true,
        }
    } else {
        stacked(area, stacked_share(area.height))
    }
}

/// Stack a tab's body: `list_rows` rows of list on top (at least one, and
/// at least one row left for the detail), one rule row, the detail below.
/// A body too short for all three (under three rows) gives everything to
/// the list and leaves no rule and an empty detail.
pub fn stacked(area: Rect, list_rows: u16) -> Panes {
    if area.height < 3 {
        return Panes {
            list: area,
            detail: Rect::new(area.x, area.bottom(), area.width, 0),
            rule: None,
            side_by_side: false,
        };
    }
    let top = list_rows.clamp(1, area.height - 2);
    let list = Rect::new(area.x, area.y, area.width, top);
    let rule_y = area.y.saturating_add(top);
    let detail = Rect::new(
        area.x,
        rule_y.saturating_add(1),
        area.width,
        area.height - top - 1,
    );
    Panes {
        list,
        detail,
        rule: Some(Rect::new(area.x, rule_y, area.width, 1)),
        side_by_side: false,
    }
}

/// Draw the rule [`panes`] left between the two panes, if it left one: a
/// vertical line beside the list when the panes sit side by side, a
/// horizontal one under it when they are stacked.
pub fn pane_rule(theme: &Theme, panes: &Panes, buf: &mut Buffer) {
    let Some(rule) = panes.rule else {
        return;
    };
    if panes.side_by_side {
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
        assert!(p.side_by_side);
        assert_eq!(u32::from(p.list.width), 1500 * 45 / 100);
        assert_eq!(p.list, Rect::new(0, 0, 675, 60));
        assert_eq!(p.rule, Some(Rect::new(675, 0, 1, 60)));
        assert_eq!(p.detail, Rect::new(676, 0, 824, 60));
        let mut buf = Buffer::empty(area);
        pane_rule(&Theme::new(true), &p, &mut buf);
        assert_eq!(buf.cell((675, 59)).map(|c| c.symbol()), Some("│"));
    }

    /// Below 100 columns the panes stack 40/60 with one rule row between,
    /// drawn as a horizontal line.
    #[test]
    fn panes_stack_below_100_columns() {
        let p = panes(Rect::new(0, 3, 80, 20));
        assert!(!p.side_by_side);
        assert_eq!(p.list, Rect::new(0, 3, 80, 8));
        assert_eq!(p.rule, Some(Rect::new(0, 11, 80, 1)));
        assert_eq!(p.detail, Rect::new(0, 12, 80, 11));
        let mut buf = Buffer::empty(Rect::new(0, 0, 80, 23));
        pane_rule(&Theme::new(true), &p, &mut buf);
        assert_eq!(buf.cell((79, 11)).map(|c| c.symbol()), Some("─"));
        assert_eq!(buf.cell((0, 12)).map(|c| c.symbol()), Some(" "));
    }

    /// Fix round C, C22: the one stacked arithmetic. The list keeps at
    /// least one row and leaves at least one for the detail; a body under
    /// three rows is all list, with no rule.
    #[test]
    fn stacked_clamps_the_list_and_handles_a_short_body() {
        let p = stacked(Rect::new(0, 0, 50, 10), 3);
        assert_eq!(p.list, Rect::new(0, 0, 50, 3));
        assert_eq!(p.rule, Some(Rect::new(0, 3, 50, 1)));
        assert_eq!(p.detail, Rect::new(0, 4, 50, 6));
        assert_eq!(stacked(Rect::new(0, 0, 50, 10), 0).list.height, 1);
        assert_eq!(stacked(Rect::new(0, 0, 50, 10), 40).list.height, 8);
        let short = stacked(Rect::new(0, 0, 50, 2), 5);
        assert_eq!(short.list, Rect::new(0, 0, 50, 2));
        assert_eq!(short.rule, None);
        assert_eq!(short.detail, Rect::new(0, 2, 50, 0));
    }
}
