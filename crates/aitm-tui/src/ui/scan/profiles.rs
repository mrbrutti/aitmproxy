//! The Profiles tab (spec D2, D11, D13). Plan task 4 draws its three states
//! only: degraded on a legacy bus, degraded on a v2 bus without
//! `scan.profile.list`, and empty. The list, the editor, the origin picker and
//! the check tree arrive with the Profiles tasks.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::ScanOffer;
use crate::theme::Theme;
use crate::ui::scan::{missing_verb, note};
use crate::ui::text::{cells, truncate};

/// What a bus without the v2 scanner can say about profiles (D2).
pub const DEGRADED: &str = "profiles need scan.profile.list (scanner v2)";

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        // The banner already names both verbs; one line is enough.
        ScanOffer::None => {}
        ScanOffer::Legacy => note(theme, area, DEGRADED, buf),
        ScanOffer::V2 if !app.has_tool("scan.profile.list") => {
            note(theme, area, &missing_verb("scan.profile.list"), buf)
        }
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
