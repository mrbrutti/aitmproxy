//! `aitm-plugin-scanner` — the deterministic scanner plugin (Stage 1 skeleton).

pub mod checks;
pub mod commands;
pub mod config;
pub mod crawl;
pub mod discover;
pub mod inject;
pub mod passive;
pub mod plugin;
pub mod report;
pub mod reproduce;

pub use checks::{severity_for, AttackMode, CheckDefinition, Evidence, Payload};
pub use config::ScannerConfig;
pub use crawl::{crawl, CrawlOutcome};
pub use discover::{enumerate, InjectionPoint, Location};
pub use inject::{bounded, class_points, inject, target_flows, Confirmed, InjectOutcome, TimedOut};
pub use passive::{passive_checks, PassiveFinding};
pub use plugin::ScannerPlugin;
pub use report::{index_to_value, load_records};
pub use reproduce::{build_poc, record_finding};
