//! Maps design tokens onto ratatui [`Style`]s.
//!
//! The rules come from `docs/design/operator-ui-foundation.md` §2.10(c):
//! truecolor terminals use the token's **dark** hex; 256/16-colour terminals
//! use the token's `tui` ANSI name; weight → bold, tertiary → dim, selection →
//! reverse video in the accent. Tokens with no ANSI name fall back to
//! [`Color::Reset`] (the terminal's own foreground/background), except
//! `text.tertiary`, which becomes `DarkGray` so the "dim" tier survives.

use ratatui::style::{Color, Modifier, Style};

use crate::tokens::{color, ColorToken, PairToken};

/// Resolves tokens to styles for one terminal capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// `true` when the terminal renders 24-bit colour; `false` for the
    /// ANSI-16/256 fallback.
    pub truecolor: bool,
}

impl Theme {
    /// Builds a theme for a truecolor (`true`) or ANSI (`false`) terminal.
    pub fn new(truecolor: bool) -> Self {
        Self { truecolor }
    }

    /// The colour a single-value token resolves to on this terminal.
    ///
    /// Truecolor → the dark hex. Otherwise the `tui` ANSI name, or
    /// [`Color::Reset`] when the token has none.
    pub fn color(&self, t: &ColorToken) -> Color {
        if self.truecolor {
            rgb(t.dark)
        } else {
            ansi(t.ansi)
        }
    }

    /// A foreground-only style in the token's colour.
    pub fn fg(&self, t: &ColorToken) -> Style {
        Style::default().fg(self.color(t))
    }

    /// A badge: tint background + deep text (§2.2), always bold.
    ///
    /// On ANSI terminals the pair collapses to its ANSI name as the
    /// foreground, with no background.
    pub fn badge(&self, p: &PairToken) -> Style {
        let style = if self.truecolor {
            Style::default().fg(rgb(p.dark_fg)).bg(rgb(p.dark_bg))
        } else {
            Style::default().fg(ansi(p.ansi))
        };
        style.add_modifier(Modifier::BOLD)
    }

    /// `text.primary`: hosts, header names, values, titles.
    pub fn text_primary(&self) -> Style {
        self.fg(&color::text::PRIMARY)
    }

    /// `text.secondary`: column headers, labels, timestamps.
    pub fn text_secondary(&self) -> Style {
        self.fg(&color::text::SECONDARY)
    }

    /// `text.tertiary`: placeholders and meta. Dim on every terminal;
    /// `DarkGray` where truecolor is unavailable.
    pub fn text_tertiary(&self) -> Style {
        let fg = if self.truecolor {
            rgb(color::text::TERTIARY.dark)
        } else {
            Color::DarkGray
        };
        Style::default().fg(fg).add_modifier(Modifier::DIM)
    }

    /// `ground.surface`: panels, the flow table, inspector panes.
    pub fn surface(&self) -> Style {
        if self.truecolor {
            Style::default()
                .bg(rgb(color::ground::SURFACE.dark))
                .fg(rgb(color::text::PRIMARY.dark))
        } else {
            Style::default()
        }
    }

    /// `ground.raised`: chips, wells, the status bar, group headers.
    pub fn raised(&self) -> Style {
        if self.truecolor {
            Style::default().bg(rgb(color::ground::RAISED.dark))
        } else {
            Style::default()
        }
    }

    /// The selected row or sidebar item: `ground.active` tint on truecolor,
    /// reverse video in the accent otherwise.
    pub fn selection(&self) -> Style {
        if self.truecolor {
            Style::default()
                .bg(rgb(color::ground::ACTIVE.dark))
                .fg(rgb(color::text::PRIMARY.dark))
        } else {
            Style::default()
                .fg(ansi(color::accent::BASE.ansi))
                .add_modifier(Modifier::REVERSED)
        }
    }

    /// `accent.base` as a foreground.
    pub fn accent(&self) -> Style {
        self.fg(&color::accent::BASE)
    }

    /// The armed-intercept bar with something paused: the one saturated
    /// fill with on-colour text (§2.2); yellow reverse video on ANSI (§2.7).
    pub fn intercept_bar(&self) -> Style {
        if self.truecolor {
            Style::default()
                .bg(rgb(color::intercept::BASE.dark))
                .fg(rgb(color::intercept::ON_BASE.dark))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(ansi(color::intercept::BASE.ansi))
                .add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    /// The intercept bar when armed but nothing is paused: a quiet tint.
    pub fn intercept_armed_quiet(&self) -> Style {
        if self.truecolor {
            Style::default()
                .bg(rgb(color::intercept::TINT.dark))
                .fg(rgb(color::intercept::DEEP.dark))
        } else {
            Style::default().fg(ansi(color::intercept::BASE.ansi))
        }
    }

    /// `agent.base` as a foreground: the agent's presence over MCP.
    pub fn agent(&self) -> Style {
        self.fg(&color::agent::BASE)
    }

    /// The L4 hue (ui-ext §3.2, OQ1 → slate/indigo): a foreground distinct from
    /// accent-blue, intercept-amber, agent-teal and WS-violet. TUI-local until
    /// the foundation adds `color.l4.*` to `tokens.json` (OQ1 is Matt's); on
    /// ANSI it degrades to blue, the `L4` badge text disambiguating it.
    pub fn l4(&self) -> Style {
        if self.truecolor {
            Style::default().fg(Color::Rgb(0x81, 0x8C, 0xF8))
        } else {
            Style::default().fg(Color::Blue)
        }
    }

    /// The L4 kind badge: a slate/indigo tint + on-colour text (§2.2), bold;
    /// blue on ANSI.
    pub fn l4_badge(&self) -> Style {
        if self.truecolor {
            Style::default()
                .fg(Color::Rgb(0xC7, 0xCD, 0xFF))
                .bg(Color::Rgb(0x31, 0x33, 0x52))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        }
    }

    /// The badge for an HTTP method (case-insensitive). Unknown methods use
    /// the grey `method.head` pair.
    pub fn method(&self, method: &str) -> Style {
        let pair = match method.to_ascii_uppercase().as_str() {
            "GET" => &color::method::GET,
            "POST" => &color::method::POST,
            "PUT" => &color::method::PUT,
            "PATCH" => &color::method::PATCH,
            "DELETE" => &color::method::DELETE,
            "HEAD" => &color::method::HEAD,
            "OPTIONS" => &color::method::OPTIONS,
            "CONNECT" => &color::method::CONNECT,
            "WS" => &color::method::WS,
            _ => &color::method::HEAD,
        };
        self.badge(pair)
    }

    /// The style for a status code, bold (§2.3: 600 on the status code).
    ///
    /// `None` is a flow still in flight (`status.pending`); `killed` adds
    /// strikethrough over `status.killed`; otherwise the 1xx–5xx class.
    /// Codes outside 100–599 are treated as transport errors (`serverError`).
    pub fn status(&self, code: Option<u16>, killed: bool) -> Style {
        if killed {
            return self
                .fg(&color::status::KILLED)
                .add_modifier(Modifier::BOLD | Modifier::CROSSED_OUT);
        }
        let token = match code {
            None => &color::status::PENDING,
            Some(100..=199) => &color::status::INFORMATIONAL,
            Some(200..=299) => &color::status::SUCCESS,
            Some(300..=399) => &color::status::REDIRECT,
            Some(400..=499) => &color::status::CLIENT_ERROR,
            Some(_) => &color::status::SERVER_ERROR,
        };
        self.fg(token).add_modifier(Modifier::BOLD)
    }

    /// The pill for a PoC finding severity (`critical`/`high`/`medium`/
    /// `low`/`info`, case-insensitive). Unknown values use `info`.
    pub fn severity(&self, s: &str) -> Style {
        let pair = match s.to_ascii_lowercase().as_str() {
            "critical" => &color::severity::CRITICAL,
            "high" => &color::severity::HIGH,
            "medium" => &color::severity::MEDIUM,
            "low" => &color::severity::LOW,
            _ => &color::severity::INFO,
        };
        self.badge(pair)
    }

    /// `syntax.key`: JSON keys, header names, XML attribute names.
    pub fn syntax_key(&self) -> Style {
        self.fg(&color::syntax::KEY)
    }

    /// `syntax.string`: string values.
    pub fn syntax_string(&self) -> Style {
        self.fg(&color::syntax::STRING)
    }

    /// `syntax.number`: numeric values.
    pub fn syntax_number(&self) -> Style {
        self.fg(&color::syntax::NUMBER)
    }

    /// `syntax.boolean`: `true`/`false`/`null` and keywords.
    pub fn syntax_boolean(&self) -> Style {
        self.fg(&color::syntax::BOOLEAN)
    }

    /// `syntax.punct`: braces, colons, commas.
    pub fn syntax_punct(&self) -> Style {
        self.fg(&color::syntax::PUNCT)
    }

    /// `syntax.keyword` (Rhai control words). The spec adds `syntax.keyword` to
    /// `tokens.json` as an additive token (UI-ext spec §1.1); until it lands,
    /// the TUI resolves it to `syntax.boolean`, whose own token description
    /// reads "true/false/null, keywords". Point this at `color::syntax::KEYWORD`
    /// when that token is added.
    pub fn syntax_keyword(&self) -> Style {
        self.fg(&color::syntax::BOOLEAN)
    }

    /// `syntax.comment` (source comments). The spec adds `syntax.comment` to
    /// `tokens.json` as an additive token (UI-ext spec §1.1); until it lands,
    /// the TUI resolves it to the dim `text.tertiary` meta tier. Point this at
    /// `color::syntax::COMMENT` when that token is added.
    pub fn syntax_comment(&self) -> Style {
        self.text_tertiary()
    }

    /// `syntax.bracket`: outer object/array brackets.
    pub fn syntax_bracket(&self) -> Style {
        self.fg(&color::syntax::BRACKET)
    }

    /// `syntax.lineNumber`: the gutter; dim on every terminal.
    pub fn line_number(&self) -> Style {
        let fg = if self.truecolor {
            rgb(color::syntax::LINE_NUMBER.dark)
        } else {
            Color::DarkGray
        };
        Style::default().fg(fg).add_modifier(Modifier::DIM)
    }

    /// `syntax.diffAdd`: an added line in a diff.
    pub fn diff_add(&self) -> Style {
        self.diff(&color::syntax::DIFF_ADD, Color::Green)
    }

    /// `syntax.diffRemove`: a removed line in a diff.
    pub fn diff_remove(&self) -> Style {
        self.diff(&color::syntax::DIFF_REMOVE, Color::Red)
    }

    /// `line.border`: panel edges, splitters, the rule under tab bars.
    pub fn rule(&self) -> Style {
        if self.truecolor {
            self.fg(&color::line::BORDER)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    }

    /// Badge-like pair style for diff lines. The diff pairs carry no `tui`
    /// name, so the ANSI fallback is supplied by the caller.
    fn diff(&self, p: &PairToken, ansi_fallback: Color) -> Style {
        if self.truecolor {
            Style::default().fg(rgb(p.dark_fg)).bg(rgb(p.dark_bg))
        } else {
            Style::default().fg(p.ansi.and_then(ansi_name).unwrap_or(ansi_fallback))
        }
    }
}

/// A truecolor [`Color`] from a token's RGB triple.
fn rgb(c: crate::tokens::Rgb) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}

/// An ANSI-16 [`Color`] from a token's `tui` name; [`Color::Reset`] when the
/// token has none or the name is unknown.
fn ansi(name: Option<&str>) -> Color {
    name.and_then(ansi_name).unwrap_or(Color::Reset)
}

/// Parses an ANSI colour name (case-insensitive).
fn ansi_name(name: &str) -> Option<Color> {
    match name.to_ascii_lowercase().as_str() {
        "black" => Some(Color::Black),
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "yellow" => Some(Color::Yellow),
        "blue" => Some(Color::Blue),
        "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "white" => Some(Color::White),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolor_uses_dark_hex() {
        let t = Theme::new(true);
        assert_eq!(t.color(&color::accent::BASE), Color::Rgb(0x60, 0xA5, 0xFA));
        assert_eq!(t.accent().fg, Some(Color::Rgb(0x60, 0xA5, 0xFA)));
    }

    #[test]
    fn ansi_uses_tui_name() {
        let t = Theme::new(false);
        assert_eq!(t.color(&color::accent::BASE), Color::Blue);
        assert_eq!(t.color(&color::agent::BASE), Color::Cyan);
        assert_eq!(t.color(&color::intercept::BASE), Color::Yellow);
        assert_eq!(t.color(&color::status::KILLED), Color::White);
    }

    #[test]
    fn ansi_without_name_resets_then_tertiary_dims() {
        let t = Theme::new(false);
        assert_eq!(t.color(&color::text::TERTIARY), Color::Reset);
        assert_eq!(t.text_primary().fg, Some(Color::Reset));

        let tertiary = t.text_tertiary();
        assert_eq!(tertiary.fg, Some(Color::DarkGray));
        assert!(tertiary.add_modifier.contains(Modifier::DIM));

        let tertiary_tc = Theme::new(true).text_tertiary();
        assert_eq!(tertiary_tc.fg, Some(Color::Rgb(0x8E, 0x8E, 0x93)));
        assert!(tertiary_tc.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn method_badge_is_case_insensitive_and_bold() {
        let post = Theme::new(true).method("post");
        assert_eq!(post.bg, Some(Color::Rgb(0x14, 0x32, 0x2A)));
        assert_eq!(post.fg, Some(Color::Rgb(0x86, 0xEF, 0xAC)));
        assert!(post.add_modifier.contains(Modifier::BOLD));

        let post_ansi = Theme::new(false).method("POST");
        assert_eq!(post_ansi.fg, Some(Color::Green));
        assert_eq!(post_ansi.bg, None);
        assert!(post_ansi.add_modifier.contains(Modifier::BOLD));

        assert_eq!(
            Theme::new(true).method("BREW"),
            Theme::new(true).method("head")
        );
    }

    #[test]
    fn status_by_class() {
        let t = Theme::new(true);
        assert_eq!(
            t.status(Some(404), false).fg,
            Some(Color::Rgb(0xFC, 0xD3, 0x4D))
        );
        assert_eq!(
            t.status(Some(200), false).fg,
            Some(Color::Rgb(0x4A, 0xDE, 0x80))
        );
        assert_eq!(
            t.status(Some(101), false).fg,
            Some(Color::Rgb(0xC4, 0xB5, 0xFD))
        );
        assert_eq!(
            t.status(Some(302), false).fg,
            Some(Color::Rgb(0x7D, 0xD3, 0xFC))
        );
        assert_eq!(
            t.status(Some(502), false).fg,
            Some(Color::Rgb(0xF8, 0x71, 0x71))
        );
        assert_eq!(t.status(None, false).fg, Some(Color::Rgb(0xF5, 0xA5, 0x24)));
        assert!(t
            .status(Some(404), false)
            .add_modifier
            .contains(Modifier::BOLD));

        let killed = t.status(None, true);
        assert!(killed.add_modifier.contains(Modifier::CROSSED_OUT));
        assert_eq!(killed.fg, Some(Color::Rgb(0x8E, 0x8E, 0x93)));

        assert_eq!(
            Theme::new(false).status(Some(500), false).fg,
            Some(Color::Red)
        );
    }

    #[test]
    fn ansi_selection_is_reverse_video_in_the_accent() {
        let sel = Theme::new(false).selection();
        assert!(sel.add_modifier.contains(Modifier::REVERSED));
        assert_eq!(sel.fg, Some(Color::Blue));

        let sel_tc = Theme::new(true).selection();
        assert_eq!(sel_tc.bg, Some(Color::Rgb(0x2B, 0x33, 0x44)));
        assert!(!sel_tc.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn intercept_bar_styles() {
        let bar = Theme::new(true).intercept_bar();
        assert_eq!(bar.bg, Some(Color::Rgb(0xF5, 0xA5, 0x24)));
        assert_eq!(bar.fg, Some(Color::Rgb(0x1F, 0x13, 0x00)));
        assert!(bar.add_modifier.contains(Modifier::BOLD));

        let bar_ansi = Theme::new(false).intercept_bar();
        assert_eq!(bar_ansi.fg, Some(Color::Yellow));
        assert!(bar_ansi
            .add_modifier
            .contains(Modifier::REVERSED | Modifier::BOLD));

        let quiet = Theme::new(true).intercept_armed_quiet();
        assert_eq!(quiet.bg, Some(Color::Rgb(0x3A, 0x2E, 0x12)));
        assert_eq!(quiet.fg, Some(Color::Rgb(0xFB, 0xBF, 0x24)));
        assert_eq!(
            Theme::new(false).intercept_armed_quiet().fg,
            Some(Color::Yellow)
        );
    }

    #[test]
    fn severity_and_diff_and_rule() {
        assert_eq!(
            Theme::new(true).severity("Critical").fg,
            Some(Color::Rgb(0xFC, 0xA5, 0xA5))
        );
        assert_eq!(Theme::new(false).severity("medium").fg, Some(Color::Yellow));
        assert_eq!(Theme::new(false).severity("unknown").fg, Some(Color::White));

        let add = Theme::new(true).diff_add();
        assert_eq!(add.fg, Some(Color::Rgb(0x86, 0xEF, 0xAC)));
        assert_eq!(add.bg, Some(Color::Rgb(0x14, 0x32, 0x2A)));
        assert_eq!(Theme::new(false).diff_add().fg, Some(Color::Green));
        assert_eq!(Theme::new(false).diff_remove().fg, Some(Color::Red));

        assert_eq!(
            Theme::new(true).rule().fg,
            Some(Color::Rgb(0x2E, 0x2E, 0x31))
        );
        assert_eq!(Theme::new(false).rule().fg, Some(Color::DarkGray));
        assert_eq!(Theme::new(false).surface(), Style::default());
        assert_eq!(
            Theme::new(true).raised().bg,
            Some(Color::Rgb(0x26, 0x26, 0x28))
        );
    }
}
