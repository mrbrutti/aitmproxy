//! `aitm-core` — the protocol-agnostic core of aitmproxy.
//!
//! Hosts the flow model, the typed event bus + ordered plugin chain, the command
//! registry, the flow store, the scope/rate guard, and the proxy acceptor. Every
//! other crate in the workspace depends on this one.

/// The crate version, wired to the Cargo package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
