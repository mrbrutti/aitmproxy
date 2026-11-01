//! macOS Network/System Extension capture backend (L4 Phase 2), core side.
//!
//! The extension's root `NETransparentProxyProvider` captures flows and hands them
//! to the embedded core over Unix domain sockets. This module holds the core
//! (Rust) half of that path — the parts provable in the sandbox against synthesized
//! flows and loopback sockets, with no Mac, no signing, and no Apple portal. The
//! Swift provider and the signing/packaging live in Band C.
//!
//! Captured flows feed the protocol-general capture ingress in [`crate::ingress`]
//! (`CoreIngress` / `CapturedTcpFlow` / `CapturedUdpFlow`); this backend adapts the
//! handoff onto those types rather than redeclaring them.

pub mod activation_gate;
pub mod adapter;
pub mod availability;
pub mod capability;
pub mod config;
pub mod feeder;
pub mod listener;
pub mod peer_auth;
pub mod rendezvous;
pub mod scope_spec;
pub mod status;
#[cfg(test)]
pub(crate) mod test_support;
