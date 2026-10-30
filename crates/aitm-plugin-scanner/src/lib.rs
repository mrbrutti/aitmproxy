//! `aitm-plugin-scanner` — the deterministic scanner plugin (Stage 1 skeleton).

pub mod config;
pub mod discover;
pub mod plugin;

pub use config::ScannerConfig;
pub use discover::{enumerate, InjectionPoint, Location};
pub use plugin::ScannerPlugin;
