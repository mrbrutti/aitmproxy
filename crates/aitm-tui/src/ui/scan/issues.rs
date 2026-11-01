//! The Issues tab (spec D2, D11, D13). Plan task 4 draws its degraded and
//! empty states only; the severity headers, the rows, the filters and the
//! detail pane arrive with the Issues tasks.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::app::App;
use crate::scan::ScanOffer;
use crate::theme::Theme;
use crate::ui::scan::{missing_verb, note};

/// What a legacy bus can say about issues. D2 calls for a degraded banner
/// here but fixes no words for it; this mirrors the Profiles wording, which
/// the spec does fix (builder's decision, plan task 4).
pub const DEGRADED: &str = "issues need scan.issues (scanner v2)";

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        ScanOffer::None => {}
        ScanOffer::Legacy => note(theme, area, DEGRADED, buf),
        ScanOffer::V2 if !app.has_tool("scan.issues") => {
            note(theme, area, &missing_verb("scan.issues"), buf)
        }
        ScanOffer::V2 if app.scan.issues.list.is_empty() => note(theme, area, "no issues yet", buf),
        ScanOffer::V2 => {}
    }
}
