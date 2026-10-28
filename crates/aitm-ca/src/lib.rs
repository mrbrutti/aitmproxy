//! `aitm-ca`: manages the OS trust store for aitmproxy's MITM root CA.
//!
//! The `ca.*` command family (`export`, `status`, `install`, `uninstall`)
//! drives the platform trust-store tools through the [`exec::Executor`]
//! trait, so every effect on the host is a rendered command line that tests
//! can assert on, and records each change in a fail-closed JSONL audit log
//! ([`audit::AuditLog`]). [`CaPlugin`] registers the four commands.

pub mod audit;
pub mod cert;
pub mod commands;
pub mod exec;
pub mod platform;
pub mod store;
pub mod testing;

pub use audit::{AuditLog, AuditRecord, FileAuditLog};
pub use cert::CaCert;
pub use commands::CaPlugin;
pub use exec::{CmdLine, CmdOutput, DryRunExecutor, Executor, RealExecutor};
pub use store::{
    store_for, LinuxFamily, Platform, Presence, Scope, Trust, TrustError, TrustErrorKind,
    TrustStore,
};
