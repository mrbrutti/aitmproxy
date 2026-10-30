//! `aitm-plugin-scanner` — the deterministic scanner plugin (Stage 1 skeleton).

pub mod checks;
pub mod commands;
pub mod config;
pub mod crawl;
pub mod discover;
pub mod passive;
pub mod plugin;
pub mod report;

pub use checks::{AttackMode, CheckDefinition, Evidence, Payload};
pub use config::ScannerConfig;
pub use crawl::{crawl, CrawlOutcome};
pub use discover::{enumerate, InjectionPoint, Location};
pub use passive::{passive_checks, PassiveFinding};
pub use plugin::ScannerPlugin;
pub use report::{index_to_value, load_records};
