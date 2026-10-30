//! `aitm-plugin-scanner` — the deterministic scanner plugin (Stage 1 skeleton).

pub mod config;
pub mod crawl;
pub mod discover;
pub mod plugin;

pub use config::ScannerConfig;
pub use crawl::{crawl, CrawlOutcome};
pub use discover::{enumerate, InjectionPoint, Location};
pub use plugin::ScannerPlugin;
