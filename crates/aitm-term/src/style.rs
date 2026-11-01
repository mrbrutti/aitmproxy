//! Colour roles (spec T2, D3; plan C2).
//!
//! [`paint`] wraps a string in the classic 16-colour SGR code for its
//! [`Role`] and always resets. The codes are written by hand: crossterm 0.29
//! encodes every named colour in the 256-colour form (`38;5;n`), which T2
//! forbids. Colour goes on glyphs and state words, never on whole lines.

use crate::caps::Caps;

/// What a piece of text means, mapped to `tokens.json`'s `tui` names (spec T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The mark and the header wordmark (`accent.base.tui`, blue).
    Accent,
    /// `●` listening, `✓` done (`state.success.tui`, green).
    Success,
    /// `!` warnings, `untrusted`, `○` (`state.warning.tui`, yellow).
    Warning,
    /// `✕`, the error headline glyph (`state.danger.tui`, red).
    Danger,
    /// Descriptions, the `Log` row, paths (`text.tertiary`, the dim attribute).
    Dim,
    /// The wordmark, a label the eye should land on.
    Bold,
    /// Everything else (`text.primary`).
    Plain,
}

impl Role {
    /// Every role, for tests and tables that iterate them.
    pub const ALL: [Role; 7] = [
        Role::Accent,
        Role::Success,
        Role::Warning,
        Role::Danger,
        Role::Dim,
        Role::Bold,
        Role::Plain,
    ];

    /// The SGR introducer for this role; `None` for [`Role::Plain`].
    fn sgr(self) -> Option<&'static str> {
        match self {
            Role::Accent => Some("\x1b[34m"),
            Role::Success => Some("\x1b[32m"),
            Role::Warning => Some("\x1b[33m"),
            Role::Danger => Some("\x1b[31m"),
            Role::Dim => Some("\x1b[2m"),
            Role::Bold => Some("\x1b[1m"),
            Role::Plain => None,
        }
    }
}

/// SGR reset: every painted span ends with it.
const RESET: &str = "\x1b[0m";

/// `text` wrapped in `role`'s SGR code and a reset; `text` unchanged when the
/// caps allow no colour or the role is [`Role::Plain`].
pub fn paint(caps: &Caps, role: Role, text: &str) -> String {
    match role.sgr() {
        Some(code) if caps.color => format!("{code}{text}{RESET}"),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;

    fn rich() -> Caps {
        Caps {
            tty: true,
            color: true,
            unicode: true,
            animate: true,
            width: 120,
            ci: false,
        }
    }

    #[test]
    fn paint_emits_classic_sgr_and_resets() {
        let caps = rich();
        assert_eq!(
            paint(&caps, Role::Accent, "aitmproxy"),
            "\x1b[34maitmproxy\x1b[0m"
        );
        assert_eq!(
            paint(&caps, Role::Success, "aitmproxy"),
            "\x1b[32maitmproxy\x1b[0m"
        );
        assert_eq!(
            paint(&caps, Role::Warning, "aitmproxy"),
            "\x1b[33maitmproxy\x1b[0m"
        );
        assert_eq!(
            paint(&caps, Role::Danger, "aitmproxy"),
            "\x1b[31maitmproxy\x1b[0m"
        );
        assert_eq!(
            paint(&caps, Role::Dim, "aitmproxy"),
            "\x1b[2maitmproxy\x1b[0m"
        );
        assert_eq!(
            paint(&caps, Role::Bold, "aitmproxy"),
            "\x1b[1maitmproxy\x1b[0m"
        );
        assert_eq!(paint(&caps, Role::Plain, "aitmproxy"), "aitmproxy");
    }

    #[test]
    fn paint_emits_no_escape_when_color_is_off() {
        let caps = Caps::plain();
        for role in Role::ALL {
            let out = paint(&caps, role, "x");
            assert_eq!(out, "x", "{role:?} must leave the text alone");
            assert!(
                !out.as_bytes().contains(&0x1b),
                "{role:?} must emit no escape byte"
            );
        }
    }
}
