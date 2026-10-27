//! Browser configuration.
//!
//! `BrowserConfig` and `SsrfPolicy` are declared in `aitm-core` (the core
//! `Config` references them, and core cannot depend on this crate). They are
//! re-exported here so a caller can write `aitm_browser::BrowserConfig`.

pub use aitm_core::{BrowserConfig, SsrfPolicy};
