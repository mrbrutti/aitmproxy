//! The wire-confirm overlay (spec D3, D7), generalised from the L4 inject
//! confirm. One overlay serves both the `l4.*` guarded verbs and the `scan.*`
//! launches: the server's `prompt` is shown verbatim, the title and footnote are
//! chosen by the call name, and `y` re-issues the identical args plus `_confirm`
//! while `n` / Esc cancels. It reads `App::wire_confirm`.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;

use crate::app::App;
use crate::scan::launch::WireConfirm;
use crate::theme::Theme;
use crate::ui::centered;
use crate::ui::overlays::{boxed, lines_into};
use crate::ui::scan::wrap;

/// The family of the call under confirmation, classified once from its
/// name: it picks the title, the footnote and the hue of the call-name line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// A `scan.*` launch.
    Scan,
    /// Any other call: the guarded `l4.*` verbs.
    L4,
}

impl Family {
    fn of(confirm: &WireConfirm) -> Family {
        if confirm.is_scan() {
            Family::Scan
        } else {
            Family::L4
        }
    }

    /// The box title; the separator is a colon (spec D7).
    fn title(self) -> &'static str {
        match self {
            Family::Scan => "Confirm over the wire: scan launch",
            Family::L4 => "Confirm over the wire: guarded L4 action",
        }
    }

    /// The tertiary line under the prompt. The L4 line is a fact about
    /// `l4.inject` (L4OPS-AC10); the same overlay also confirms an operator
    /// `l4.scope.add` and the intercept verdicts (L4 parity spec §3, §4),
    /// where that sentence would be false, so it is shown for the inject only.
    fn footnote(self, call: &str) -> Option<&'static str> {
        match self {
            Family::Scan => {
                Some("Confirming starts the job now; x in Jobs cancels it at any time.")
            }
            Family::L4 if call == "l4.inject" => {
                Some("This reaches the wire only through l4.inject; the guard enforces scope.")
            }
            Family::L4 => None,
        }
    }

    /// D13, hue only on data: the call-name line reads in the hue of its
    /// family, the accent for a scan launch and the L4 hue for an L4 verb.
    fn hue(self, theme: &Theme) -> Style {
        match self {
            Family::Scan => theme.accent(),
            Family::L4 => theme.l4(),
        }
    }
}

/// Draw the wire-confirm overlay for the pending `App::wire_confirm`: a
/// `scan.*` call reads the scan-launch wording, any other call (the `l4.*`
/// verbs) the guarded-L4 wording ([`Family`]).
pub fn render(app: &App, theme: &Theme, screen: Rect, buf: &mut Buffer) {
    let Some(c) = &app.wire_confirm else {
        return;
    };
    let family = Family::of(c);
    let footnote = family.footnote(&c.call);
    // The rows around the prompt: the call-name line and the blank below it
    // above, the blank and the key line below, plus the footnote row when the
    // call has one (fix round J, J2).
    let frame = 4 + usize::from(footnote.is_some());
    let area = centered(
        screen,
        screen.width.saturating_sub(10).clamp(40, 90),
        screen.height.saturating_sub(8).clamp(7, 16),
    );
    let inner = boxed(theme, family.title(), area, buf);
    let mut lines = vec![
        Line::styled(
            format!(" {}", c.call),
            family.hue(theme).add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
    ];
    // Wrap the server's prompt (bounded at fold, fix round H, H34) to the
    // panel width by cell width (fix round G, G55) and to the rows the box
    // has left after the frame rows above and below it (fix round H, H50),
    // so the key line is always the last row drawn; an empty prompt keeps
    // its one blank row.
    let mut chunks = wrap(
        &c.prompt,
        usize::from(inner.width).saturating_sub(2),
        usize::from(inner.height).saturating_sub(frame),
    );
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    for chunk in chunks {
        lines.push(Line::styled(format!(" {chunk}"), theme.text_primary()));
    }
    lines.push(Line::raw(""));
    if let Some(footnote) = footnote {
        lines.push(Line::styled(format!(" {footnote}"), theme.text_tertiary()));
    }
    lines.push(Line::styled(
        " y confirm (re-issues with _confirm) · n / Esc cancel",
        theme.accent().add_modifier(Modifier::BOLD),
    ));
    lines_into(buf, inner, &lines, 0);
}
