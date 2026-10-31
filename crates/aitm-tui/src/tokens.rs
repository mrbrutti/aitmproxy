//! Design tokens, generated at build time from `docs/design/tokens.json`.
//!
//! Nothing in this module is hand-written: `build.rs` parses the W3C-style
//! tokens file (the single source of truth shared with the macOS app and the
//! web UI, see `docs/design/operator-ui-foundation.md` §2.2–§2.5 and §2.10(c))
//! and writes `$OUT_DIR/tokens.rs`, which is pulled in below with `include!`.
//!
//! What the generated file contains:
//!
//! - [`Rgb`], [`ColorToken`] (a single light/dark colour) and [`PairToken`]
//!   (a `{fg, bg}` badge pair), each carrying the optional `tui` ANSI-16 name
//!   used by terminals that cannot show truecolor.
//! - `color::<group>::<NAME>` constants, one per `color.*` token, with
//!   camelCase names turned into `SCREAMING_SNAKE` (`onAccent` → `ON_ACCENT`).
//! - `glyph::<NAME>` string constants, one per `icon.glyph.*`, holding the
//!   `tui` Unicode glyph (an empty string stays empty).
//! - `size::SIDEBAR_COLS`: the one size token the TUI keeps (every other size
//!   collapses to one terminal line).
//! - `ALL_COLORS` / `ALL_PAIRS`: `(dotted.name, &token)` tables for
//!   diagnostics and tests.
//! - `TOKENS_VERSION`: the file's `$version`.
//!
//! **Adding a token.** Edit `docs/design/tokens.json` first (§2.5: a new icon
//! or colour is added there before any surface uses it), then rebuild; the
//! build script re-runs whenever the JSON changes. A token whose `$value` has
//! `light`/`dark` hex strings becomes a `ColorToken`; one whose values are
//! `{fg, bg}` objects becomes a `PairToken`. Give it a `tui` sibling key when
//! it needs an ANSI fallback. Malformed input fails the build on purpose.
//!
//! Mapping tokens onto ratatui `Style`s (truecolor vs ANSI, bold/dim/reverse)
//! is the job of [`crate::theme`], not this module.

include!(concat!(env!("OUT_DIR"), "/tokens.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_tokens_json() {
        assert_eq!(TOKENS_VERSION, "0.1.0");
    }

    #[test]
    fn accent_base_has_dark_hex_and_ansi_name() {
        assert_eq!(color::accent::BASE.dark, Rgb(0x60, 0xA5, 0xFA));
        assert_eq!(color::accent::BASE.light, Rgb(0x25, 0x63, 0xEB));
        assert_eq!(color::accent::BASE.ansi, Some("blue"));
    }

    #[test]
    fn intercept_base_light_hex() {
        assert_eq!(color::intercept::BASE.light, Rgb(0xD9, 0x77, 0x06));
        assert_eq!(color::intercept::BASE.ansi, Some("yellow"));
    }

    #[test]
    fn method_post_is_a_pair_with_ansi() {
        assert_eq!(color::method::POST.dark_fg, Rgb(0x86, 0xEF, 0xAC));
        assert_eq!(color::method::POST.dark_bg, Rgb(0x14, 0x32, 0x2A));
        assert_eq!(color::method::POST.light_fg, Rgb(0x15, 0x80, 0x3D));
        assert_eq!(color::method::POST.light_bg, Rgb(0xDC, 0xFC, 0xE7));
        assert_eq!(color::method::POST.ansi, Some("green"));
    }

    #[test]
    fn tokens_without_tui_key_have_no_ansi() {
        assert_eq!(color::text::TERTIARY.ansi, None);
        assert_eq!(color::ground::PAGE.ansi, None);
        assert_eq!(color::syntax::DIFF_ADD.ansi, None);
    }

    #[test]
    fn camel_case_names_become_screaming_snake() {
        assert_eq!(color::syntax::DIFF_ADD.light_fg, Rgb(0x15, 0x80, 0x3D));
        assert_eq!(color::text::ON_ACCENT.dark, Rgb(0x0B, 0x12, 0x20));
        assert_eq!(color::syntax::LINE_NUMBER.dark, Rgb(0x5C, 0x5C, 0x62));
        assert_eq!(color::status::CLIENT_ERROR.dark, Rgb(0xFC, 0xD3, 0x4D));
        assert_eq!(color::intercept::ON_BASE.light, Rgb(0x1F, 0x13, 0x00));
    }

    #[test]
    fn glyphs_carry_the_tui_string() {
        assert_eq!(glyph::RECORD, "●");
        assert_eq!(glyph::INTERCEPT, "✋");
        assert_eq!(glyph::REPLAY, "↻");
        assert_eq!(glyph::LOCK_OPEN, "🔓");
        assert_eq!(glyph::SIDEBAR, "");
        assert_eq!(glyph::COPY, "");
    }

    #[test]
    fn sidebar_width_is_28_columns() {
        assert_eq!(size::SIDEBAR_COLS, 28);
    }

    #[test]
    fn tables_cover_every_token() {
        // Counted by hand from tokens.json (0.1.0, with the `mark` group the
        // GUI surfaces added on 2026-10-28 and the `syntax.currentLine` +
        // `syntax.match` JSON-viewer tokens):
        //   single colours: ground 6 + line 4 + text 6 + accent 3 + intercept 4
        //                 + agent 3 + status 7 + syntax 11 + mark 11
        //                 + l4 3 (base/deep/tint, added 2026-10-29 for the L4 badge) = 58
        //   pairs:          method 9 + severity 5 + syntax 2 (diffAdd/diffRemove)
        //                 + l4.badge 1 + state 4 (success/warning/danger/neutral,
        //                   added 2026-10-30 for the semantic CA/script badges) = 21
        assert_eq!(ALL_COLORS.len(), 58);
        assert_eq!(ALL_PAIRS.len(), 21);
        assert_eq!(
            color::mark::TEAL.ansi,
            color::mark::TEAL.ansi,
            "mark tokens are generated"
        );

        let page = ALL_COLORS
            .iter()
            .find(|(name, _)| *name == "ground.page")
            .map(|(_, t)| **t);
        assert_eq!(page, Some(color::ground::PAGE));

        let get = ALL_PAIRS
            .iter()
            .find(|(name, _)| *name == "method.get")
            .map(|(_, t)| **t);
        assert_eq!(get, Some(color::method::GET));
    }
}
