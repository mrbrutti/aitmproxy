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

use std::borrow::Cow;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{elapsed_text, ScanError, ScanOffer, ScanTab, NO_SCANNER};
use crate::text::{cells, fit, truncate, width};
use crate::theme::Theme;
use crate::tokens::color::status;
use crate::ui::bars::put;
use crate::ui::overlays::boxed;
use crate::ui::selection_bg;

/// The blank cells between the tab strip and the state banner (D11).
const STRIP_GAP: usize = 4;

/// Blank cells between the columns of a tab's list (fix round G, G59: the
/// one pair the Profiles, Jobs and Issues tables share).
pub const GAP: usize = 2;
/// [`GAP`] as the text a header or a row writes between columns.
pub const GAP_TEXT: &str = "  ";
const _: () = assert!(GAP_TEXT.len() == GAP, "GAP_TEXT spells GAP cells");

/// The most rows a blocked or refused reason wraps onto over a footer; the
/// rest is cut ([`blocked_footer`]).
pub const BLOCKED_ROWS_MAX: usize = 4;

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
    let room = usize::from(area.width).saturating_sub(used + STRIP_GAP);
    // The active tab's error is found once per frame; the legacy Jobs tab's
    // is built here from the text the legacy state kept, so the banner and
    // its hue borrow the same value.
    let legacy_error = legacy_jobs_error(app);
    let error = tab_error(app, legacy_error.as_ref());
    let text = banner(app, error);
    if room > 0 {
        spans.push(Span::raw(" ".repeat(STRIP_GAP)));
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
        theme.fg(&status::SERVER_ERROR)
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
/// frame by [`tab_error`]; on Jobs with the age of the values on screen
/// after it, ` · showing values from 42s ago`, Jobs view D19 T2 and
/// [`values_age_text`]), the notice a key left (`already <state>`, which
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
        let mut text = e.wording();
        if app.scan.tab == ScanTab::Jobs {
            if let Some(age) = values_age_text(app.ticks, app.scan.jobs.listed_ok_at_tick) {
                text.push_str(" · ");
                text.push_str(&age);
            }
        }
        return text;
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

/// How old the Jobs values on screen are (Jobs view D15, D19 T2): the
/// ticks since the last `scan.list` that folded (`listed_ok_at_tick`,
/// stamped by the reducer), 250 ms each, as `showing values from 42s ago`
/// in the row's elapsed shape ([`elapsed_text`]); `None` before the first
/// list lands. A core that stops answering leaves the banner's error on
/// screen, and this says the numbers under it are from before it.
pub fn values_age_text(now_tick: u64, listed_ok_at_tick: Option<u64>) -> Option<String> {
    let since = now_tick.saturating_sub(listed_ok_at_tick?);
    Some(format!(
        "showing values from {} ago",
        elapsed_text(since.saturating_mul(TICK_MS))
    ))
}

/// The period of one `Tick`, in milliseconds (the runtime's interval).
const TICK_MS: u64 = 250;

/// The active tab's degraded text, when the bus cannot serve it (D2): on a
/// legacy bus Profiles and Issues name what they need; on a v2 bus a tab
/// names the first of its verbs the bus lacks (D11: Issues needs
/// `scan.issues` for the list, `scan.issue` for the read and
/// `scan.issue.update` for the status keys; fix round D, D4, and fix round
/// E, E17). Jobs is not gated by a verb in D2 (a v2 bus has `scan.start`
/// by definition), and the Site map on a legacy bus is the legacy result
/// (D12), not degraded.
fn degraded(app: &App) -> Option<String> {
    let verbs: &[&str] = match (app.scan_offer(), app.scan.tab) {
        (ScanOffer::Legacy, ScanTab::Profiles) => return Some(PROFILES_DEGRADED.to_string()),
        (ScanOffer::Legacy, ScanTab::Issues) => return Some(ISSUES_DEGRADED.to_string()),
        (ScanOffer::V2, ScanTab::Profiles) => &["scan.profile.list"],
        (ScanOffer::V2, ScanTab::SiteMap) => &["scan.sitemap"],
        (ScanOffer::V2, ScanTab::Issues) => &["scan.issues", "scan.issue", "scan.issue.update"],
        _ => return None,
    };
    verbs
        .iter()
        .find(|verb| !app.has_tool(verb))
        .map(|verb| ScanError::missing_verb(verb).wording())
}

/// On a legacy bus the Jobs tab's error is the `scan.discover` failure the
/// legacy state kept as text; the one `ScanError` built per frame. `None`
/// on a v2 bus, where the Jobs tab reads its own `JobsState::error` (fix
/// round H, H56).
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

/// The active tab's own error and nothing else (spec D13 as ruled
/// 2026-11-01, fix round H, H56: another tab's error never sits on this
/// banner; `ScanState::last_error` is the view-wide record the tests
/// read, never drawn here; the toast is built from the `ScanError` in
/// `App::on_scan_failed`). `legacy` is [`legacy_jobs_error`], the Jobs
/// tab's on a legacy bus.
fn tab_error<'a>(app: &'a App, legacy: Option<&'a ScanError>) -> Option<&'a ScanError> {
    let own = app.scan.error_slot(app.scan.tab).as_ref();
    if app.scan.tab == ScanTab::Jobs {
        legacy.or(own)
    } else {
        own
    }
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

/// A status-bar hint: a key and what it does, in the shape `bars::status`
/// draws for every mode.
pub type Hint = (&'static str, &'static str);

/// `Esc back`, the last hint of every Scan bar (D11): last so it is the
/// first to go when the bar is narrow.
const ESC_BACK: Hint = ("Esc", "back");

/// `⏎ open flow`, the Site map's and the Issues tab's flow open (fix round
/// H, H28: one hint, named where the tables and the legacy bar read it).
const OPEN_FLOW: Hint = ("⏎", "open flow");

/// `parts` joined into one `N`-long array, `N` being their total length:
/// how a bar is built from its tab's key table, its extra hints and
/// [`ESC_BACK`] at compile time ([`key_table`]).
const fn join<const N: usize>(parts: &[&[Hint]]) -> [Hint; N] {
    let mut out = [("", ""); N];
    let mut k = 0;
    let mut i = 0;
    while i < parts.len() {
        let mut j = 0;
        while j < parts[i].len() {
            out[k] = parts[i][j];
            k += 1;
            j += 1;
        }
        i += 1;
    }
    assert!(k == N, "N is the parts' total length");
    out
}

/// One key table per tab (fix round G, G84, G90): `$keys` is what the
/// tab's in-pane footer spells and `$bar` the same hints, then the `$more`
/// table when the tab has one, then [`ESC_BACK`], the status bar's list.
/// The help overlay joins the same tables ([`HELP`]), so a key is named
/// once.
macro_rules! key_table {
    ($keys:ident, $bar:ident $(, $more:ident)?: $($hint:expr),+ $(,)?) => {
        pub(crate) const $keys: &[Hint] = &[$($hint),+];
        pub(crate) const $bar: &[Hint] =
            &join::<{ $keys.len() $(+ $more.len())? + 1 }>(&[$keys, $($more,)? &[ESC_BACK]]);
    };
}

key_table!(PROFILES_KEYS, PROFILES_BAR:
    ("s", "start"), ("m", "map"), ("w", "save as"), ("e", "edit"), ("Space", "toggle"));
/// The Profiles keys the help lists beyond the footer's.
pub(crate) const PROFILES_MORE: &[Hint] = &[
    ("N", "new"),
    ("D", "delete"),
    ("o", "origin"),
    ("t", "L4 target"),
];
key_table!(JOBS_KEYS, JOBS_BAR:
    ("x", "cancel"), ("⏎", "issues of this job"), ("s", "start"), ("m", "map"));
key_table!(SITEMAP_KEYS, SITEMAP_BAR:
    OPEN_FLOW, ("n", "next page"), ("J", "job filter"));
/// `R reset`, in the Issues list footer and in the bar.
const RESET: Hint = ("R", "reset");
/// The five filter keys as the bar and the help spell them, compactly.
const FILTERS: Hint = ("S C L T J", "filters");
/// The Issues hints the bar and the help list beyond the list footer's
/// (fix round H, H28).
const ISSUES_MORE: &[Hint] = &[FILTERS, RESET];
key_table!(ISSUES_KEYS, ISSUES_BAR, ISSUES_MORE:
    ("c", "confirm"), ("f", "false positive"), ("u", "reopen"), OPEN_FLOW, ("P", "PoC"));
/// The Issues list footer: the filter keys (D11).
pub(crate) const ISSUES_FILTER_KEYS: &[Hint] = &[
    ("S", "severity"),
    ("C", "confidence"),
    ("L", "lane"),
    ("T", "status"),
    ("J", "job"),
    RESET,
];
/// The keys every tab shares, the help's first Scan line.
const SHARED_KEYS: &[Hint] = &[
    ("Profiles · Jobs · Site map · Issues", "tabs"),
    ("Tab/BackTab", "pane"),
    ESC_BACK,
];

/// The Jobs bar on a legacy bus: the one-shot's keys (D12).
const LEGACY_JOBS_BAR: &[Hint] = &[
    ("r", "scan"),
    ("3", "site map"),
    ("F", "findings"),
    ESC_BACK,
];
/// The degraded Profiles tab on a legacy bus (fix round G, G86): `s`/`m`
/// run the one-shot like `r` (Task 12 ruling), the rest of its keys have
/// nothing to act on.
const LEGACY_PROFILES_BAR: &[Hint] = &[("s", "scan"), ("m", "map"), ("3", "site map"), ESC_BACK];
/// The degraded Issues tab on a legacy bus (G86).
const LEGACY_ISSUES_BAR: &[Hint] = &[("3", "site map"), ESC_BACK];
/// The Site map on a legacy bus (G86): the flow open without the v2
/// paging and job filter.
const LEGACY_SITEMAP_BAR: &[Hint] = &[OPEN_FLOW, ESC_BACK];

/// The status-bar hints of the Scan view (D11: the hints list the active
/// tab's keys): the tab's keys most important first, `Esc back` last so it
/// is the first to go when the bar is narrow. On a legacy bus the Jobs tab
/// carries the one-shot's keys instead (D12) and the degraded tabs only
/// the keys they serve (G86).
pub fn hints(app: &App) -> &'static [Hint] {
    let legacy = app.scan_offer() == ScanOffer::Legacy;
    match (legacy, app.scan.tab) {
        (true, ScanTab::Profiles) => LEGACY_PROFILES_BAR,
        (true, ScanTab::Jobs) => LEGACY_JOBS_BAR,
        (true, ScanTab::SiteMap) => LEGACY_SITEMAP_BAR,
        (true, ScanTab::Issues) => LEGACY_ISSUES_BAR,
        (false, ScanTab::Profiles) => PROFILES_BAR,
        (false, ScanTab::Jobs) => JOBS_BAR,
        (false, ScanTab::SiteMap) => SITEMAP_BAR,
        (false, ScanTab::Issues) => ISSUES_BAR,
    }
}

/// `key what · key what ...`: the key groups joined the way a footer and a
/// help line spell them.
pub fn key_text(groups: &[&[Hint]]) -> String {
    groups
        .iter()
        .flat_map(|g| g.iter())
        .map(|(k, w)| format!("{k} {w}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The help overlay's Scan section (D11): the keys every tab shares, then
/// one line per tab, each a heading and the key groups [`key_text`] joins
/// under the overlay's `Scan` heading. The groups are the tabs' own tables
/// (G90), so the help never drifts from the bar or the footers.
pub const HELP: &[(&str, &[&[Hint]])] = &[
    ("1 2 3 4", &[SHARED_KEYS]),
    ("Profiles", &[PROFILES_KEYS, PROFILES_MORE]),
    ("Jobs", &[JOBS_KEYS]),
    ("Site map", &[SITEMAP_KEYS]),
    ("Issues", &[ISSUES_KEYS, ISSUES_MORE]),
];

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

/// One line of tertiary text on the first row of `area`, one cell in and
/// cut to the width: the one way a tab draws its filter line, its footers
/// and its empty-state note (fix round D, D10). Nothing is drawn into an
/// area under two cells wide or without a row.
pub fn hint(theme: &Theme, area: Rect, text: &str, buf: &mut Buffer) {
    if area.height == 0 || area.width < 2 {
        return;
    }
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        Line::styled(
            format!(" {}", truncate(text, usize::from(area.width) - 1)),
            theme.text_tertiary(),
        ),
    );
}

/// What a tab draws when it is empty (D13): a [`hint`] at the top of `area`.
pub fn note(theme: &Theme, area: Rect, text: &str, buf: &mut Buffer) {
    hint(theme, area, text, buf);
}

/// One `label value` line of a Detail pane (fix round F, F8), the one
/// layout the Jobs and Issues panes share: a pad cell, the label fitted to
/// `label_w` cells in secondary text, one space, the value in primary text
/// cut so the whole line fits `w` cells. A fixed `label_w` lines the
/// values up (the Issues pane, as in the D11 mockup; an empty label then
/// indents a continuation line); `width(label)` lets the line read as the
/// sentence it is (the Jobs pane).
pub fn labelled(
    theme: &Theme,
    label: &str,
    value: &str,
    w: usize,
    label_w: usize,
) -> Line<'static> {
    let value_w = w.saturating_sub(1 + label_w + 1);
    Line::from(vec![
        Span::styled(format!(" {}", fit(label, label_w)), theme.text_secondary()),
        Span::styled(
            format!(" {}", truncate(value, value_w)),
            theme.text_primary(),
        ),
    ])
}

/// The rows of a list pane (fix round G, G56): `total` rows scrolled so
/// `cursor` is on screen (the rows above it give way first), the cursor
/// row highlighted while `focused`, each row built by `line(k)` only when
/// it is drawn. The one scroll-and-highlight loop every tab's list shares;
/// `buf` last like [`hint`] and [`blocked_footer`].
pub fn rows(
    theme: &Theme,
    area: Rect,
    total: usize,
    cursor: usize,
    focused: bool,
    mut line: impl FnMut(usize) -> Line<'static>,
    buf: &mut Buffer,
) {
    if area.height == 0 || area.width == 0 || total == 0 {
        return;
    }
    let h = usize::from(area.height);
    let cursor = cursor.min(total - 1);
    let top = cursor.saturating_sub(h - 1);
    for k in top..total.min(top + h) {
        let row = Rect::new(area.x, area.y + cells(k - top), area.width, 1);
        if k == cursor && focused {
            buf.set_style(row, selection_bg(theme));
        }
        put(buf, row, line(k));
    }
}

/// The reason a launch key cannot or did not go through, for a tab's
/// footer (Task 13 ruling: Jobs and Profiles both draw it): the UI-3 text
/// while the gate holds (`launch.blocked`, D7; the key is inert), else the
/// refused launch's D9 wording (D13's refused state: the key stays live
/// and the operator reads why the core said no). The wording is built
/// only when no gate text stands (G81).
pub fn launch_reason(app: &App) -> Option<Cow<'_, str>> {
    app.scan
        .launch
        .blocked
        .as_deref()
        .map(Cow::Borrowed)
        .or_else(|| app.scan.refused_launch().map(|e| Cow::Owned(e.wording())))
}

/// A Detail pane's bottom (fix round G, G65): the `footer` [`hint`] on the
/// last row when there are two or more, and above it the `blocked` reason
/// wrapped clause by clause ([`wrap`]) onto at most [`BLOCKED_ROWS_MAX`]
/// rows in the warning hue (D13's refused state; `status.clientError` is
/// the `state.warning` foreground on both schemes), always leaving at
/// least one row to the body. Returns the body rect left above them.
pub fn blocked_footer(
    theme: &Theme,
    area: Rect,
    blocked: Option<&str>,
    footer: &str,
    buf: &mut Buffer,
) -> Rect {
    let h = usize::from(area.height);
    if h < 2 || area.width < 2 {
        return area;
    }
    let w = usize::from(area.width) - 1;
    let reason = blocked.map_or_else(Vec::new, |text| wrap(text, w, BLOCKED_ROWS_MAX));
    let foot_rows = (1 + reason.len()).min(h - 1);
    let body = Rect::new(area.x, area.y, area.width, cells(h - foot_rows));
    let foot_y = area.y + cells(h - foot_rows);
    let warn = theme.fg(&status::CLIENT_ERROR);
    for (k, row) in reason.iter().take(foot_rows - 1).enumerate() {
        put(
            buf,
            Rect::new(area.x, foot_y + cells(k), area.width, 1),
            Line::styled(format!(" {row}"), warn),
        );
    }
    hint(
        theme,
        Rect::new(area.x, area.bottom() - 1, area.width, 1),
        footer,
        buf,
    );
    body
}

/// Wrap `text` into rows of at most `w` cells, at most `max_rows` of them.
/// The units are the text's clauses (cut after a `,` `.` `:` or `;` that a
/// space follows, so a dotted address stays whole), and the words of a
/// clause wider than a row: the D7 reasons name the missing scope entry
/// clause by clause (`direction outbound,`), and a clause kept on one row
/// keeps each `field value` pair readable. A word wider than a row is cut,
/// and when the units do not all fit the rows the last row ends in an
/// ellipsis. Empty for an empty text, a zero width or no rows.
pub fn wrap(text: &str, w: usize, max_rows: usize) -> Vec<String> {
    if w == 0 || max_rows == 0 {
        return Vec::new();
    }
    let mut units: Vec<&str> = Vec::new();
    for clause in clauses(text) {
        if width(clause) <= w {
            units.push(clause);
        } else {
            units.extend(clause.split_whitespace());
        }
    }
    let mut rows: Vec<String> = Vec::new();
    let mut i = 0;
    while i < units.len() && rows.len() < max_rows {
        let mut row = String::new();
        while i < units.len() {
            let unit = units[i];
            if row.is_empty() {
                row = truncate(unit, w);
            } else if width(&row) + 1 + width(unit) <= w {
                row.push(' ');
                row.push_str(unit);
            } else {
                break;
            }
            i += 1;
        }
        rows.push(row);
    }
    if i < units.len() {
        if let Some(last) = rows.last_mut() {
            *last = truncate(&format!("{last} …"), w);
        }
    }
    rows
}

/// `text` cut after every `,` `.` `:` or `;` that whitespace or the end
/// follows, each piece trimmed, empty pieces dropped.
fn clauses(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        let ends_clause = matches!(b, b',' | b'.' | b':' | b';')
            && bytes.get(i + 1).is_none_or(u8::is_ascii_whitespace);
        if ends_clause {
            // `b` is ASCII, so `i + 1` is a char boundary.
            let clause = text[start..=i].trim();
            if !clause.is_empty() {
                out.push(clause);
            }
            start = i + 1;
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round F, F8: the one `label value` layout. Without a column the
    /// label takes its width; with one it is padded (an empty label indents
    /// a continuation line); the value is cut so the line fits `w`.
    #[test]
    fn labelled_lays_out_the_label_column_and_cuts_the_value() {
        let theme = Theme::new(true);
        let text = |line: Line<'static>| -> String {
            line.spans.iter().map(|s| s.content.as_ref()).collect()
        };
        assert_eq!(
            text(labelled(&theme, "lanes", "requested http", 40, 5)),
            " lanes requested http"
        );
        assert_eq!(
            text(labelled(&theme, "payload", "<x>", 40, 11)),
            " payload     <x>"
        );
        assert_eq!(
            text(labelled(&theme, "", "1.0 | 2", 40, 11)),
            "             1.0 | 2"
        );
        let cut = text(labelled(&theme, "note", &"n".repeat(50), 20, 11));
        assert_eq!(cut.chars().count(), 20, "{cut:?}");
        assert_eq!(cut, " note        nnnnnn…");
        assert_eq!(
            text(labelled(&theme, "a", "bcd", 3, 1)),
            " a ",
            "no room: the value is empty"
        );
    }

    /// Fix round G, G56: the one scroll arithmetic. The cursor row is the
    /// last on screen once it is past the pane (`top = cursor - (h - 1)`),
    /// only the rows on screen are built, and the cursor row is highlighted
    /// only while focused.
    #[test]
    fn rows_scroll_to_the_cursor_and_highlight_it_while_focused() {
        let theme = Theme::new(true);
        let area = Rect::new(0, 0, 10, 3);
        let mut buf = Buffer::empty(area);
        let mut built = Vec::new();
        rows(
            &theme,
            area,
            10,
            7,
            true,
            |k| {
                built.push(k);
                Line::raw(format!("row {k}"))
            },
            &mut buf,
        );
        assert_eq!(built, vec![5, 6, 7], "top = 7 - (3 - 1)");
        assert_eq!(buf.cell((0, 2)).map(|c| c.symbol()), Some("r"));
        assert_eq!(
            buf.cell((0, 2)).map(|c| c.bg),
            Some(selection_bg(&theme).bg.unwrap_or_default()),
            "the cursor row carries the selection"
        );
        assert_ne!(
            buf.cell((0, 1)).map(|c| c.bg),
            Some(selection_bg(&theme).bg.unwrap_or_default())
        );

        let mut buf = Buffer::empty(area);
        let mut built = Vec::new();
        rows(
            &theme,
            area,
            10,
            1,
            false,
            |k| {
                built.push(k);
                Line::raw("x")
            },
            &mut buf,
        );
        assert_eq!(
            built,
            vec![0, 1, 2],
            "a cursor inside the pane keeps top at 0"
        );
        assert_ne!(
            buf.cell((0, 1)).map(|c| c.bg),
            Some(selection_bg(&theme).bg.unwrap_or_default()),
            "unfocused: no highlight"
        );

        let mut buf = Buffer::empty(area);
        let mut built = Vec::new();
        rows(
            &theme,
            area,
            2,
            99,
            true,
            |k| {
                built.push(k);
                Line::raw("x")
            },
            &mut buf,
        );
        assert_eq!(built, vec![0, 1], "the cursor is clamped to the last row");
        rows(
            &theme,
            area,
            0,
            0,
            true,
            |_| unreachable!("no rows"),
            &mut buf,
        );
    }

    /// The wrap keeps words whole, cuts a word wider than a row, stops at
    /// the row cap and marks what it dropped; a wide glyph counts its cells.
    #[test]
    fn wrap_breaks_at_clauses_then_spaces_and_caps_the_rows() {
        assert_eq!(wrap("a bb ccc", 5, 4), vec!["a bb", "ccc"]);
        assert_eq!(wrap("abcdefgh ij", 5, 4), vec!["abcd…", "ij"]);
        assert_eq!(wrap("one two three four", 9, 1), vec!["one two …"]);
        assert_eq!(wrap("one two", 9, 1), vec!["one two"]);
        assert!(wrap("x", 0, 4).is_empty());
        assert!(wrap("", 9, 4).is_empty());
        assert_eq!(
            wrap("日本 日本", 5, 4),
            vec!["日本", "日本"],
            "two wide glyphs are four cells, two of them do not fit five"
        );
        // A clause that fits moves whole to the next row; a dotted address
        // is not a clause end.
        assert_eq!(
            wrap("Add one with x, direction outbound, 10.0.0.1/32 y.", 22, 4),
            vec!["Add one with x,", "direction outbound,", "10.0.0.1/32 y."]
        );
        assert_eq!(clauses("a: b, c.d; e"), vec!["a:", "b,", "c.d;", "e"]);
    }

    /// Fix round G, G65: the footer takes the last row, the reason the
    /// rows above it up to the cap, and the body keeps at least one row.
    #[test]
    fn blocked_footer_leaves_the_body_above_the_reason_and_the_footer() {
        let theme = Theme::new(true);
        let area = Rect::new(0, 0, 8, 6);
        let mut buf = Buffer::empty(area);
        let body = blocked_footer(&theme, area, Some("one, two, three"), "k key", &mut buf);
        assert_eq!(
            body,
            Rect::new(0, 0, 8, 2),
            "three reason rows and the footer"
        );
        let row = |y: u16| -> String {
            (0..8)
                .filter_map(|x| buf.cell((x, y)).map(|c| c.symbol().to_string()))
                .collect::<String>()
                .trim_end()
                .to_string()
        };
        assert_eq!(row(2), " one,");
        assert_eq!(row(4), " three");
        assert_eq!(row(5), " k key");
        let mut buf = Buffer::empty(area);
        let body = blocked_footer(&theme, area, None, "k key", &mut buf);
        assert_eq!(body.height, 5, "no reason: the footer alone");
        let short = Rect::new(0, 0, 8, 2);
        let mut buf = Buffer::empty(short);
        let body = blocked_footer(&theme, short, Some("one, two"), "k key", &mut buf);
        assert_eq!(body.height, 1, "the body keeps a row");
        let one = Rect::new(0, 0, 8, 1);
        assert_eq!(blocked_footer(&theme, one, Some("x"), "k", &mut buf), one);
    }

    /// Fix round G, G84: every key a footer spells is in its tab's bar,
    /// and the help lines are joined from the same tables.
    #[test]
    fn footer_keys_are_a_subset_of_the_bar_keys() {
        let keys = |t: &[Hint]| -> Vec<&str> {
            t.iter().flat_map(|(k, _)| k.split_whitespace()).collect()
        };
        for (footer, bar) in [
            (PROFILES_KEYS, PROFILES_BAR),
            (JOBS_KEYS, JOBS_BAR),
            (ISSUES_KEYS, ISSUES_BAR),
            (ISSUES_FILTER_KEYS, ISSUES_BAR),
            (SITEMAP_KEYS, SITEMAP_BAR),
        ] {
            let bar_keys = keys(bar);
            for key in keys(footer) {
                assert!(bar_keys.contains(&key), "{key} is in the bar {bar:?}");
            }
            assert_eq!(bar.last(), Some(&ESC_BACK));
        }
        assert_eq!(
            key_text(&[JOBS_KEYS]),
            "x cancel · ⏎ issues of this job · s start · m map"
        );
        assert_eq!(
            key_text(&[ISSUES_KEYS, ISSUES_MORE]),
            "c confirm · f false positive · u reopen · ⏎ open flow · P PoC · S C L T J filters · R reset"
        );
        assert_eq!(
            key_text(&[SHARED_KEYS]),
            "Profiles · Jobs · Site map · Issues tabs · Tab/BackTab pane · Esc back"
        );
    }

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
