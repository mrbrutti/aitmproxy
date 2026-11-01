//! The wire-confirm overlay (spec D3, D7), generalised from the L4 inject
//! confirm. One overlay serves both the `l4.*` guarded verbs and the `scan.*`
//! launches: the server's `prompt` is shown verbatim, the title and footnote are
//! chosen by the call name, and `y` re-issues the identical args plus `_confirm`
//! while `n` / Esc cancels. It reads `App::wire_confirm`.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::Line;

use crate::app::App;
use crate::theme::Theme;
use crate::ui::centered;
use crate::ui::overlays::{boxed, lines_into};

/// Draw the wire-confirm overlay for the pending `App::wire_confirm`. The title
/// separator is a colon (spec D7); a `scan.*` call reads the scan-launch
/// wording, any other call (the `l4.*` verbs) the guarded-L4 wording.
pub fn render(app: &App, theme: &Theme, screen: Rect, buf: &mut Buffer) {
    let Some(c) = &app.wire_confirm else {
        return;
    };
    let (title, footnote) = if c.call.starts_with("scan.") {
        (
            "Confirm over the wire: scan launch",
            "Confirming starts the job now; x in Jobs cancels it at any time.",
        )
    } else {
        (
            "Confirm over the wire: guarded L4 action",
            "This reaches the wire only through l4.inject; the guard enforces scope.",
        )
    };
    let area = centered(
        screen,
        screen.width.saturating_sub(10).clamp(40, 90),
        screen.height.saturating_sub(8).clamp(7, 16),
    );
    let inner = boxed(theme, title, area, buf);
    // D13, hue only on data: the call-name line reads in the hue of its
    // family, the accent for a scan launch and the L4 hue for an L4 verb.
    let call_hue = if c.call.starts_with("scan.") {
        theme.accent()
    } else {
        theme.l4()
    };
    let mut lines = vec![
        Line::styled(
            format!(" {}", c.call),
            call_hue.add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
    ];
    // Wrap the server's prompt to the panel width, shown verbatim.
    for chunk in wrap(&c.prompt, usize::from(inner.width).saturating_sub(2)) {
        lines.push(Line::styled(format!(" {chunk}"), theme.text_primary()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(format!(" {footnote}"), theme.text_tertiary()));
    lines.push(Line::styled(
        " y confirm (re-issues with _confirm) · n / Esc cancel",
        theme.accent().add_modifier(Modifier::BOLD),
    ));
    lines_into(buf, inner, &lines, 0);
}

/// Greedy word-wrap to `width` columns.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}
