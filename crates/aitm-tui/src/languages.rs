//! Language tables generated from `docs/design/languages/*.json` by `build.rs`
//! — the same single-source-of-truth pattern as [`crate::tokens`]. The Rhai
//! keyword/literal sets drive the [`crate::syntax`] tokenizer; the embedded
//! `rhai.api.json` and `poc-yaml.schema.json` drive [`crate::ui::complete`].
//! A surface never hard-codes a keyword, host-function name or PoC key: all of
//! them come from these shared files (UI-ext spec §1.1).

include!(concat!(env!("OUT_DIR"), "/languages.rs"));
