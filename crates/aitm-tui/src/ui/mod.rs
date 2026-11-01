//! The screen: foundation §2.6's regions as ratatui layouts. One line each for
//! the toolbar, chip bar and status bar; a 28-column sidebar (`b` toggles);
//! the flow list; the intercept bar when armed; the inspector below (or right)
//! of the list on wide terminals and full-screen on narrow ones (§2.10(c)).
//! Everything draws into a `Buffer`, so a snapshot renders the same way the
//! live terminal does.

pub mod bars;
pub mod browser;
pub mod complete;
pub mod flows;
pub mod inspector;
pub mod l4;
pub mod overlays;
pub mod scan;
pub mod sidebar;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::Frame;

use crate::app::{App, Layout as Placement, Mode, PromptKind};
use crate::model::FlowRow;
use crate::theme::Theme;
use crate::tokens::size::SIDEBAR_COLS;

/// What one frame needs from the flow list, computed once in [`render`] and
/// handed to every region: the visible rows in display order and the paused
/// rows. Each is an index into `app.flows`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameView {
    pub visible: Vec<usize>,
    pub paused: Vec<usize>,
}

impl FrameView {
    pub fn of(app: &App) -> Self {
        Self {
            visible: app.visible(),
            paused: (0..app.flows.len())
                .filter(|&i| app.flows[i].paused())
                .collect(),
        }
    }

    /// The flow the intercept bar acts on: the selected row if it is paused,
    /// else the oldest paused one (§2.7).
    pub fn intercept_target<'a>(&self, app: &'a App) -> Option<&'a FlowRow> {
        match app.selected_row() {
            Some(r) if r.paused() => Some(r),
            _ => self
                .paused
                .iter()
                .map(|&i| &app.flows[i])
                .min_by_key(|r| r.seq),
        }
    }

    /// The selected row's position among the visible rows.
    pub fn selected_pos(&self, app: &App) -> Option<usize> {
        let id = app.selected.as_deref()?;
        self.visible.iter().position(|&i| app.flows[i].id == id)
    }
}

/// The selected row's background and modifier only (no foreground), so the
/// syntax and state colours of the cells underneath survive the highlight.
pub fn selection_bg(theme: &Theme) -> Style {
    let sel = theme.selection();
    let mut s = Style::default().add_modifier(sel.add_modifier);
    if let Some(bg) = sel.bg {
        s = s.bg(bg);
    }
    s
}

/// Draw a frame.
pub fn view(app: &App, theme: &Theme, frame: &mut Frame) {
    let area = frame.area();
    render(app, theme, area, frame.buffer_mut());
}

/// Draw the whole UI into `buf`.
pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    buf.set_style(area, theme.surface());
    if area.height < 4 || area.width < 40 {
        buf.set_string(
            area.x,
            area.y,
            "aitm-tui needs at least 40×4",
            theme.text_secondary(),
        );
        return;
    }
    let view = FrameView::of(app);
    let [toolbar, chips, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
        Constraint::Length(1),
    ])
    .areas(area);

    bars::toolbar(app, theme, toolbar, buf);
    bars::chips(app, theme, chips, buf);

    // The wire-confirm overlay sits over the view the launch came from (fix
    // round H, H18): its body is `wire_confirm_from`'s, the Scan view for a
    // `scan.*` launch, the flow list and inspector for a guarded L4 verb.
    let body_mode = match app.mode {
        Mode::WireConfirm => app.wire_confirm_from,
        mode => mode,
    };
    match body_mode {
        Mode::Compose => overlays::compose(app, theme, body, buf),
        Mode::Scope => overlays::scope(app, theme, body, buf),
        Mode::Findings => overlays::findings(app, theme, body, buf),
        Mode::Agent => overlays::agent(app, theme, body, buf),
        Mode::Browser => browser::render(app, theme, body, buf),
        Mode::Ca => overlays::ca(app, theme, body, buf),
        Mode::Config => overlays::config(app, theme, body, buf),
        Mode::Scan => scan::render(app, theme, body, buf),
        Mode::Inspector | Mode::Edit if app.narrow() => inspector::render(app, theme, body, buf),
        _ => main_region(app, theme, &view, body, buf),
    }

    if let Mode::Prompt(kind) = app.mode {
        bars::prompt(app, theme, status, buf);
        if kind == PromptKind::Palette {
            overlays::palette(app, theme, area, status, buf);
        }
    } else {
        bars::status(app, theme, &view, status, buf);
    }

    match app.mode {
        Mode::Help => overlays::help(app, theme, area, buf),
        Mode::QuickLook => overlays::quick_look(app, theme, area, buf),
        Mode::WireConfirm => scan::confirm::render(app, theme, area, buf),
        _ => {}
    }
}

fn main_region(app: &App, theme: &Theme, view: &FrameView, area: Rect, buf: &mut Buffer) {
    let show_sidebar = app.sidebar_open && area.width >= 100;
    let (side, main) = if show_sidebar {
        let [s, m] =
            Layout::horizontal([Constraint::Length(SIDEBAR_COLS), Constraint::Min(20)]).areas(area);
        (Some(s), m)
    } else {
        (None, area)
    };
    if let Some(s) = side {
        sidebar::render(app, theme, s, buf);
    }

    let bar_lines = u16::from(app.intercept_armed || !view.paused.is_empty());
    let show_inspector = !app.narrow() && app.selected.is_some();
    match (show_inspector, app.layout) {
        (false, _) => {
            let [list, bar] =
                Layout::vertical([Constraint::Min(2), Constraint::Length(bar_lines)]).areas(main);
            flows::render(app, theme, view, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, view, bar, buf);
            }
        }
        (true, Placement::Horizontal) => {
            let [list, bar, insp] = Layout::vertical([
                Constraint::Percentage(50),
                Constraint::Length(bar_lines),
                Constraint::Min(6),
            ])
            .areas(main);
            flows::render(app, theme, view, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, view, bar, buf);
            }
            inspector::render(app, theme, insp, buf);
        }
        (true, Placement::Vertical) => {
            let [left, insp] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Min(40)]).areas(main);
            let [list, bar] =
                Layout::vertical([Constraint::Min(2), Constraint::Length(bar_lines)]).areas(left);
            flows::render(app, theme, view, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, view, bar, buf);
            }
            inspector::render(app, theme, insp, buf);
        }
    }
}

/// A centred box of at most `w`×`h` inside `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Mode;
    use ratatui::style::Modifier;

    /// S8: a compose field whose body area is zero cells wide must not
    /// underflow; `overlays::compose` is reachable with any `Rect`.
    #[test]
    fn compose_survives_a_zero_width_field_area() {
        let mut app = crate::fixture_app(200, 50);
        app.mode = Mode::Compose;
        let theme = Theme::new(true);
        for w in [0u16, 1, 2, 3, 4] {
            let area = Rect::new(0, 0, w, 12);
            let mut buf = Buffer::empty(area);
            overlays::compose(&app, &theme, area, &mut buf);
        }
    }

    /// Q7: the two row-highlight sites share one helper that keeps only the
    /// selection's background and modifier so syntax colours survive.
    #[test]
    fn selection_bg_keeps_background_and_modifier_only() {
        let tc = Theme::new(true);
        let s = selection_bg(&tc);
        assert_eq!(s.bg, tc.selection().bg);
        assert_eq!(s.fg, None);
        assert_eq!(s.add_modifier, tc.selection().add_modifier);
        let ansi = Theme::new(false);
        let s = selection_bg(&ansi);
        assert_eq!(s.bg, None);
        assert_eq!(s.fg, None);
        assert!(s.add_modifier.contains(Modifier::REVERSED));
    }

    /// Q6: the per-frame view is computed once and agrees with the queries.
    #[test]
    fn frame_view_is_the_visible_and_paused_sets() {
        let app = crate::fixture_app(200, 50);
        let view = FrameView::of(&app);
        assert_eq!(view.visible, app.visible());
        assert_eq!(
            view.paused
                .iter()
                .map(|&i| app.flows[i].id.as_str())
                .collect::<Vec<_>>(),
            vec!["f50", "f51"]
        );
        assert_eq!(
            view.intercept_target(&app).map(|r| r.id.as_str()),
            Some("f50")
        );
        let mut app = app;
        app.selected = Some("f51".into());
        assert_eq!(
            FrameView::of(&app)
                .intercept_target(&app)
                .map(|r| r.id.as_str()),
            Some("f51")
        );
    }
}
