//! The screen: foundation §2.6's regions as ratatui layouts. One line each for
//! the toolbar, chip bar and status bar; a 28-column sidebar (`b` toggles);
//! the flow list; the intercept bar when armed; the inspector below (or right)
//! of the list on wide terminals and full-screen on narrow ones (§2.10(c)).
//! Everything draws into a `Buffer`, so a snapshot renders the same way the
//! live terminal does.

pub mod bars;
pub mod flows;
pub mod inspector;
pub mod overlays;
pub mod sidebar;
pub mod text;

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::Frame;

use crate::app::{App, Layout as Placement, Mode, PromptKind, SPLIT_COLS};
use crate::theme::Theme;
use crate::tokens::size::SIDEBAR_COLS;

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
    let [toolbar, chips, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(2),
        Constraint::Length(1),
    ])
    .areas(area);

    bars::toolbar(app, theme, toolbar, buf);
    bars::chips(app, theme, chips, buf);

    match app.mode {
        Mode::Compose => overlays::compose(app, theme, body, buf),
        Mode::Scope => overlays::scope(app, theme, body, buf),
        Mode::Findings => overlays::findings(app, theme, body, buf),
        Mode::Agent => overlays::agent(app, theme, body, buf),
        Mode::Inspector | Mode::Edit if app.narrow() => inspector::render(app, theme, body, buf),
        _ => main_region(app, theme, body, buf),
    }

    if let Mode::Prompt(kind) = app.mode {
        bars::prompt(app, theme, status, buf);
        if kind == PromptKind::Palette {
            overlays::palette(app, theme, area, status, buf);
        }
    } else {
        bars::status(app, theme, status, buf);
    }

    match app.mode {
        Mode::Help => overlays::help(app, theme, area, buf),
        Mode::QuickLook => overlays::quick_look(app, theme, area, buf),
        _ => {}
    }
}

fn main_region(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
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

    let bar_lines = u16::from(app.intercept_armed || !app.paused().is_empty());
    let show_inspector = !app.narrow() && app.selected.is_some();
    match (show_inspector, app.layout) {
        (false, _) => {
            let [list, bar] =
                Layout::vertical([Constraint::Min(2), Constraint::Length(bar_lines)]).areas(main);
            flows::render(app, theme, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, bar, buf);
            }
        }
        (true, Placement::Horizontal) => {
            let [list, bar, insp] = Layout::vertical([
                Constraint::Percentage(50),
                Constraint::Length(bar_lines),
                Constraint::Min(6),
            ])
            .areas(main);
            flows::render(app, theme, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, bar, buf);
            }
            inspector::render(app, theme, insp, buf);
        }
        (true, Placement::Vertical) => {
            let [left, insp] =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Min(40)]).areas(main);
            let [list, bar] =
                Layout::vertical([Constraint::Min(2), Constraint::Length(bar_lines)]).areas(left);
            flows::render(app, theme, list, buf);
            if bar_lines > 0 {
                bars::intercept(app, theme, bar, buf);
            }
            inspector::render(app, theme, insp, buf);
        }
    }
    let _ = SPLIT_COLS;
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
