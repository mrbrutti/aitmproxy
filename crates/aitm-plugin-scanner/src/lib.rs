//! `aitm-plugin-scanner` — the deterministic scanner plugin (Stage 1 skeleton).

pub mod config;
pub mod plugin;

pub use config::ScannerConfig;
pub use plugin::ScannerPlugin;
