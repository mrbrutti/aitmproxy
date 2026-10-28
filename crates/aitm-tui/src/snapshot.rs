//! Render the UI off-screen: a `Buffer` of any size, exported as plain text,
//! ANSI, or an SVG that draws every cell with the truecolor palette. Used by
//! tests and by `aitm-tui --snapshot out.svg` to show a screen without a
//! terminal.

use std::fmt::Write as _;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};

use crate::app::App;
use crate::theme::Theme;
use crate::tokens::color;
use crate::ui;

/// Draw `app` into a fresh buffer of `cols`×`rows`.
pub fn render(app: &App, theme: &Theme, cols: u16, rows: u16) -> Buffer {
    let area = Rect::new(0, 0, cols, rows);
    let mut buf = Buffer::empty(area);
    ui::render(app, theme, area, &mut buf);
    buf
}

/// The buffer as lines of text, styles dropped.
pub fn to_text(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.y..area.bottom() {
        let mut line = String::new();
        for x in area.x..area.right() {
            if let Some(c) = buf.cell((x, y)) {
                line.push_str(c.symbol());
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn rgb(c: Color, fallback: (u8, u8, u8)) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Black => (0x16, 0x16, 0x18),
        Color::Red => (0xf8, 0x71, 0x71),
        Color::Green => (0x4a, 0xde, 0x80),
        Color::Yellow => (0xf5, 0xa5, 0x24),
        Color::Blue => (0x60, 0xa5, 0xfa),
        Color::Magenta => (0xc4, 0xb5, 0xfd),
        Color::Cyan => (0x2d, 0xd4, 0xbf),
        Color::Gray | Color::White => (0xe6, 0xe6, 0xe8),
        Color::DarkGray => (0x8e, 0x8e, 0x93),
        _ => fallback,
    }
}

fn hex((r, g, b): (u8, u8, u8)) -> String {
    format!("#{r:02X}{g:02X}{b:02X}")
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// An SVG of the buffer: one `rect` per background run, one `text` per style run.
pub fn to_svg(buf: &Buffer) -> String {
    const CW: f32 = 8.4;
    const CH: f32 = 18.0;
    let area = buf.area;
    let page = color::ground::PAGE.dark;
    let def_fg = color::text::PRIMARY.dark;
    let def_bg = color::ground::SURFACE.dark;
    let w = area.width as f32 * CW + 16.0;
    let h = area.height as f32 * CH + 16.0;
    let mut svg = String::new();
    let _ = writeln!(
        svg,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0}" height="{h:.0}" viewBox="0 0 {w:.0} {h:.0}" font-family="SF Mono, JetBrains Mono, Menlo, monospace" font-size="14">"#
    );
    let _ = writeln!(
        svg,
        r#"<rect width="100%" height="100%" fill="{}"/>"#,
        hex((page.0, page.1, page.2))
    );
    for y in area.y..area.bottom() {
        let py = 8.0 + (y - area.y) as f32 * CH;
        let mut x = area.x;
        while x < area.right() {
            let Some(cell) = buf.cell((x, y)) else {
                x += 1;
                continue;
            };
            let key = (cell.fg, cell.bg, cell.modifier);
            let mut run = String::new();
            let start = x;
            while x < area.right() {
                let Some(c) = buf.cell((x, y)) else { break };
                if (c.fg, c.bg, c.modifier) != key {
                    break;
                }
                run.push_str(c.symbol());
                x += 1;
            }
            let (mut fg, mut bg) = (
                rgb(key.0, (def_fg.0, def_fg.1, def_fg.2)),
                rgb(key.1, (def_bg.0, def_bg.1, def_bg.2)),
            );
            if key.2.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let px = 8.0 + (start - area.x) as f32 * CW;
            let width = (x - start) as f32 * CW;
            let _ = writeln!(
                svg,
                r#"<rect x="{px:.1}" y="{py:.1}" width="{width:.1}" height="{CH}" fill="{}"/>"#,
                hex(bg)
            );
            if run.trim().is_empty() {
                continue;
            }
            let weight = if key.2.contains(Modifier::BOLD) {
                r#" font-weight="bold""#
            } else {
                ""
            };
            let opacity = if key.2.contains(Modifier::DIM) {
                r#" opacity="0.7""#
            } else {
                ""
            };
            let deco = if key.2.contains(Modifier::CROSSED_OUT) {
                r#" text-decoration="line-through""#
            } else if key.2.contains(Modifier::UNDERLINED) {
                r#" text-decoration="underline""#
            } else {
                ""
            };
            let _ = writeln!(
                svg,
                r#"<text x="{px:.1}" y="{:.1}" fill="{}" xml:space="preserve"{weight}{opacity}{deco}>{}</text>"#,
                py + 13.5,
                hex(fg),
                xml(&run)
            );
        }
    }
    svg.push_str("</svg>\n");
    svg
}

/// The buffer with 24-bit SGR colour, for pasting into a terminal or a file.
pub fn to_ansi(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            let Some(c) = buf.cell((x, y)) else { continue };
            let fg = rgb(c.fg, (0xe6, 0xe6, 0xe8));
            let bg = rgb(c.bg, (0x1e, 0x1e, 0x20));
            let bold = if c.modifier.contains(Modifier::BOLD) {
                "1;"
            } else {
                ""
            };
            let _ = write!(
                out,
                "\x1b[{bold}38;2;{};{};{};48;2;{};{};{}m{}",
                fg.0,
                fg.1,
                fg.2,
                bg.0,
                bg.1,
                bg.2,
                c.symbol()
            );
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_app;

    #[test]
    fn fixture_main_screen_renders_the_shell() {
        let app = fixture_app(200, 50);
        let theme = Theme::new(true);
        let text = to_text(&render(&app, &theme, 200, 50));
        assert!(text.contains("aitmproxy"), "{text}");
        assert!(text.contains("listening 127.0.0.1:8080"), "{text}");
        assert!(text.contains("2 paused"), "{text}");
        assert!(text.contains("auth.shop-staging.test"), "{text}");
        assert!(text.contains("Paused"), "{text}");
        assert!(text.contains("Request"), "{text}");
        assert!(text.contains("Response"), "{text}");
        assert!(text.contains("bus fixture"), "{text}");
        assert!(text.contains("Findings"), "{text}");
        let svg = to_svg(&render(&app, &theme, 200, 50));
        assert!(svg.starts_with("<svg"));
        assert!(
            svg.contains("#F5A524"),
            "the intercept amber must appear in the SVG"
        );
        assert!(
            svg.contains("#2DD4BF"),
            "the agent teal must appear in the SVG"
        );
    }

    #[test]
    fn narrow_terminal_hides_the_inline_inspector_and_full_screens_it() {
        let mut app = fixture_app(100, 30);
        let theme = Theme::new(true);
        let text = to_text(&render(&app, &theme, 100, 30));
        assert!(!text.contains("Response  Headers"), "{text}");
        let _ = app.update(crate::action::Action::Enter);
        assert_eq!(app.mode, crate::app::Mode::Inspector);
        let text = to_text(&render(&app, &theme, 100, 30));
        assert!(text.contains("Request"), "{text}");
        assert!(text.contains("Response"), "{text}");
    }
}
