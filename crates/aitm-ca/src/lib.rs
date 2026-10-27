//! `aitm-ca`: manages the OS trust store for aitmproxy's MITM root CA.
//!
//! The `ca.*` command family (`export`, `status`, `install`, `uninstall`)
//! drives the platform trust-store tools through the [`exec::Executor`]
//! trait, so every effect on the host is a rendered command line that tests
//! can assert on, and records each change in a fail-closed JSONL audit log
//! ([`audit::AuditLog`]).

pub mod audit;
pub mod cert;
pub mod commands;
pub mod exec;
pub mod platform;
pub mod store;
pub mod testing;
