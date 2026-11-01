//! The Profiles tab (spec D2, D11, D13). Plan task 4 draws its empty state
//! and a plain list only; the degraded states (a legacy bus, a v2 bus without
//! `scan.profile.list`) are the banner's (D13: one state on screen), so the
//! body draws nothing then. The editor, the origin picker and the check tree
//! arrive with the Profiles tasks.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::ScanOffer;
use crate::theme::Theme;
use crate::ui::scan::note;
use crate::ui::text::{cells, truncate};

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        // The banner carries the no-scanner, degraded and missing-verb
        // states; the body adds nothing to them.
        ScanOffer::None | ScanOffer::Legacy => {}
        ScanOffer::V2 if !app.has_tool("scan.profile.list") => {}
        ScanOffer::V2 if app.scan.profiles.list.is_empty() => {
            note(theme, area, "no profiles yet", buf)
        }
        ScanOffer::V2 => list(app, theme, area, buf),
    }
}

/// The profile names, built-ins marked. The editor pane is the Profiles
/// tasks'; this keeps a filled list honest until then.
fn list(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    let h = usize::from(area.height);
    let cursor = app.scan.profiles.cursor;
    for (k, p) in app.scan.profiles.list.iter().enumerate().take(h) {
        let style = if k == cursor {
            theme.text_primary().add_modifier(Modifier::BOLD)
        } else {
            theme.text_primary()
        };
        let line = Line::from(vec![
            Span::styled(if p.builtin { " · " } else { "   " }, theme.text_tertiary()),
            Span::styled(
                truncate(&p.name, usize::from(area.width).saturating_sub(4)),
                style,
            ),
        ]);
        buf.set_line(area.x, area.y + cells(k), &line, area.width);
    }
}
