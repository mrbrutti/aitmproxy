//! What the terminal can do, read from the environment once at start-up. The
//! foundation (§2.9, §2.10(c)) degrades by capability, never silently: colours
//! fall back to ANSI-16 without truecolor, images stay placeholders unless a
//! graphics protocol is advertised, and the clipboard uses OSC 52 only where the
//! terminal is known to accept it.

/// Terminal capabilities that change what the TUI draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermCaps {
    /// 24-bit colour: use the dark hex palette; otherwise the ANSI names.
    pub truecolor: bool,
    /// Kitty graphics protocol advertised (inline images possible).
    pub kitty: bool,
    /// Sixel graphics likely supported.
    pub sixel: bool,
    /// OSC 52 clipboard writes are worth attempting.
    pub osc52: bool,
}

impl TermCaps {
    /// Detect from the process environment.
    pub fn detect() -> Self {
        Self::from_env(|k| std::env::var(k).ok())
    }

    /// Detect from an environment lookup (testable).
    pub fn from_env(env: impl Fn(&str) -> Option<String>) -> Self {
        let colorterm = env("COLORTERM").unwrap_or_default().to_ascii_lowercase();
        let term = env("TERM").unwrap_or_default().to_ascii_lowercase();
        let program = env("TERM_PROGRAM").unwrap_or_default().to_ascii_lowercase();
        let truecolor = colorterm == "truecolor"
            || colorterm == "24bit"
            || term.contains("direct")
            || matches!(
                program.as_str(),
                "iterm.app" | "wezterm" | "ghostty" | "kitty" | "alacritty" | "vscode"
            )
            || env("KITTY_WINDOW_ID").is_some()
            || env("WEZTERM_PANE").is_some();
        let kitty = term.contains("kitty")
            || env("KITTY_WINDOW_ID").is_some()
            || program == "ghostty"
            || program == "wezterm";
        let sixel = matches!(program.as_str(), "wezterm" | "mlterm" | "foot")
            || term.contains("sixel")
            || term.starts_with("foot");
        // Terminals known to implement OSC 52 writes; tmux relays it when
        // `set-clipboard` is on, which is its default.
        let osc52 = kitty
            || matches!(
                program.as_str(),
                "iterm.app" | "wezterm" | "ghostty" | "alacritty" | "kitty" | "vscode"
            )
            || env("TMUX").is_some()
            || term.starts_with("xterm")
            || term.starts_with("foot");
        Self {
            truecolor,
            kitty,
            sixel,
            osc52,
        }
    }

    /// Every capability on: what the off-screen test renders use, so they
    /// draw the design palette.
    pub const fn full() -> Self {
        Self {
            truecolor: true,
            kitty: false,
            sixel: false,
            osc52: true,
        }
    }

    /// A plain 16-colour terminal.
    pub const fn ansi16() -> Self {
        Self {
            truecolor: false,
            kitty: false,
            sixel: false,
            osc52: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn colorterm_truecolor_enables_the_hex_palette() {
        let caps = TermCaps::from_env(env_of(&[
            ("COLORTERM", "truecolor"),
            ("TERM", "xterm-256color"),
        ]));
        assert!(caps.truecolor);
        assert!(!caps.kitty);
        assert!(caps.osc52);
    }

    #[test]
    fn bare_xterm_is_ansi_only() {
        let caps = TermCaps::from_env(env_of(&[("TERM", "xterm")]));
        assert!(!caps.truecolor);
        assert!(!caps.kitty);
        assert!(!caps.sixel);
    }

    #[test]
    fn kitty_advertises_graphics_and_truecolor() {
        let caps = TermCaps::from_env(env_of(&[("TERM", "xterm-kitty"), ("KITTY_WINDOW_ID", "1")]));
        assert!(caps.truecolor);
        assert!(caps.kitty);
        assert!(caps.osc52);
    }

    #[test]
    fn wezterm_advertises_sixel() {
        let caps = TermCaps::from_env(env_of(&[("TERM_PROGRAM", "WezTerm")]));
        assert!(caps.sixel);
        assert!(caps.truecolor);
    }
}
