//! The Issues tab (spec D2, D11, D13). Plan task 4 draws its empty state
//! only; the degraded states are the banner's (D13: one state on screen), and
//! the severity headers, the rows, the filters and the detail pane arrive
//! with the Issues tasks.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::app::App;
use crate::scan::ScanOffer;
use crate::theme::Theme;
use crate::ui::scan::note;

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        // The banner carries the no-scanner, degraded and missing-verb
        // states; the body adds nothing to them.
        ScanOffer::None | ScanOffer::Legacy => {}
        ScanOffer::V2 if !app.has_tool("scan.issues") => {}
        ScanOffer::V2 if app.scan.issues.list.is_empty() => note(theme, area, "no issues yet", buf),
        ScanOffer::V2 => {}
    }
}
