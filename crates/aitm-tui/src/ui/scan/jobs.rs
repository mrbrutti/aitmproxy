//! The Jobs tab (spec D2, D11, D13). Plan task 4 draws the legacy launcher
//! (one synthetic row for the `scan.discover` one-shot, D12) and the empty
//! state; the real job rows, bars and detail pane arrive with the Jobs task.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};

use crate::app::App;
use crate::scan::{LegacyRun, ScanOffer};
use crate::theme::Theme;
use crate::tokens::color::status;
use crate::ui::bars::put;
use crate::ui::scan::note;
use crate::ui::text::truncate;

pub fn render(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    match app.scan_offer() {
        ScanOffer::None => {}
        ScanOffer::Legacy => legacy(app, theme, area, buf),
        ScanOffer::V2 if app.scan.jobs.order.is_empty() => {
            note(theme, area, "no jobs yet: start one from Profiles (s)", buf)
        }
        ScanOffer::V2 => {}
    }
}

/// The legacy one-shot as one row: its state, the target it crawled and the
/// key that launches it (D2's legacy launcher).
fn legacy(app: &App, theme: &Theme, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }
    let run = LegacyRun::of(&app.scan.legacy);
    let (word, hue) = match run {
        LegacyRun::Idle => ("idle", theme.text_tertiary()),
        // D13: a running job is the accent, done is success, a failure is
        // the server-error hue.
        LegacyRun::Running => ("crawling...", theme.accent()),
        LegacyRun::Done => ("done", theme.fg(&status::SUCCESS)),
        LegacyRun::Error => ("error", theme.fg(&status::SERVER_ERROR)),
    };
    let target = app
        .scan
        .legacy
        .target
        .as_deref()
        .unwrap_or("no in-scope host: add one to scope (S)");
    put(
        buf,
        Rect::new(area.x, area.y, area.width, 1),
        Line::from(vec![
            Span::styled(
                " one-shot ",
                theme.text_primary().add_modifier(Modifier::BOLD),
            ),
            Span::styled("· ", theme.text_tertiary()),
            Span::styled(word, hue),
            Span::raw("   "),
            Span::styled(
                truncate(target, usize::from(area.width).saturating_sub(28)),
                theme.text_secondary(),
            ),
        ]),
    );
    if area.height > 2 {
        put(
            buf,
            Rect::new(area.x, area.y + 2, area.width, 1),
            Line::styled(
                " r scan (scope-bound) · 3 Site map shows what it found · F findings",
                theme.text_tertiary(),
            ),
        );
    }
}
