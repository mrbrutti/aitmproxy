//! Terminal reporting layer for the `aitm` CLI (spec
//! `docs/superpowers/specs/2026-11-01-cli-terminal-reporting-design.md`).
//!
//! Every human-facing line `aitm` writes goes through this crate: capability
//! detection with a plain fallback (`caps`), colour roles painted as classic
//! 16-colour SGR (`style`), the brand glyph set with its ASCII twins
//! (`glyphs`), text rules (`text`), the ready card (`card`), the error panel
//! (`error`), the `tracing` layer that folds WARN+ into the view
//! (`tracing_layer`) and the in-place `Reporter` (`reporter`). `event` and
//! `clock` are the seams between them; `testing` holds the sink and clock
//! doubles other crates' tests reuse.
//!
//! Consumers use module paths (`aitm_term::reporter::Reporter`,
//! `aitm_term::caps::Caps`); this root declares modules and nothing else
//! (plan call C1).

pub mod caps;
pub mod card;
pub mod clock;
pub mod error;
pub mod event;
pub mod glyphs;
pub mod help;
pub mod prompt;
pub mod reporter;
pub mod style;
pub mod testing;
pub mod text;
pub mod tracing_layer;
