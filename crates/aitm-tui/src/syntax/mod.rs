//! Tolerant colourisers for the two languages an operator edits — Rhai
//! (plugins and PoC `script` steps) and PoC YAML — driven by the shared
//! grammar under `docs/design/languages/` (UI-ext spec §1, plan Task 7). Each
//! tokenizer turns source into `(SyntaxToken, text)` runs that [`style_for`]
//! maps to the foundation `syntax.*` styles, so the Scripts editor and the
//! Findings PoC viewer colour the same way the web and macOS surfaces do.
//!
//! The colourisers never throw on partial input (an unterminated string, a
//! half-written line, an odd YAML row): a bad line still renders, and later
//! lines keep their colour (spec Review Focus: "malformed / partial source
//! while typing").

pub mod rhai;
pub mod yaml;

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::theme::Theme;

/// A coloured run's semantic class — the shared grammar's `map_token` targets
/// (`docs/design/languages/rhai.grammar.json`). `Keyword` and `Comment` are
/// the spec's additive tokens; until `tokens.json` grows `syntax.keyword` /
/// `syntax.comment`, the TUI resolves `Keyword` to the foundation's
/// `syntax.boolean` (whose own token description reads "true/false/null,
/// keywords") and `Comment` to the dim `text.tertiary` tier — a seam that
/// [`style_for`] changes in one place when those tokens land (spec §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxToken {
    /// Rhai control words (`fn`, `let`, `if` …).
    Keyword,
    /// `true` / `false` and other literals.
    Boolean,
    /// String literals in any form.
    Str,
    /// Numeric literals.
    Number,
    /// Line and block comments.
    Comment,
    /// A mapping key (YAML/JSON key position).
    Key,
    /// Operators and punctuation.
    Punct,
    /// Identifiers and uncoloured text.
    Text,
}

/// The ratatui style the foundation gives a token class.
pub fn style_for(theme: &Theme, tok: SyntaxToken) -> Style {
    match tok {
        SyntaxToken::Keyword => theme.syntax_keyword(),
        SyntaxToken::Boolean => theme.syntax_boolean(),
        SyntaxToken::Str => theme.syntax_string(),
        SyntaxToken::Number => theme.syntax_number(),
        SyntaxToken::Comment => theme.syntax_comment(),
        SyntaxToken::Key => theme.syntax_key(),
        SyntaxToken::Punct => theme.syntax_punct(),
        SyntaxToken::Text => theme.text_primary(),
    }
}

/// Turns per-line `(token, text)` runs into styled [`Line`]s whose spans own
/// their text (so they outlive the source).
fn to_lines(theme: &Theme, rows: Vec<Vec<(SyntaxToken, String)>>) -> Vec<Line<'static>> {
    rows.into_iter()
        .map(|row| {
            Line::from(
                row.into_iter()
                    .map(|(tok, text)| Span::styled(text, style_for(theme, tok)))
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

/// Rhai source as coloured [`Line`]s for the inspector/editor. The
/// concatenation of every line's spans is exactly `src`, line by line.
pub fn highlight_rhai(theme: &Theme, src: &str) -> Vec<Line<'static>> {
    to_lines(theme, rhai::tokenize(src))
}

/// PoC YAML source as coloured [`Line`]s, in view and edit alike.
pub fn highlight_yaml(theme: &Theme, src: &str) -> Vec<Line<'static>> {
    to_lines(theme, yaml::tokenize(src))
}
