//! macOS Network/System Extension capture backend (L4 Phase 2), core side.
//!
//! These modules live in `crates/aitm` rather than `aitm-core` because they feed
//! the Phase-1 `CaptureIngress` (`crate::ingress`), which depends on
//! `aitm-proto-l4` and so cannot move into `aitm-core` without a dependency cycle.
//! They are provable by Rust tests against synthesized flows and need no Mac.

pub mod capability;
