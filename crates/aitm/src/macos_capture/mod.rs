//! macOS live-capture backend (L4 Phase 2): the Rust side of the
//! `NETransparentProxyProvider` system extension — the activation gate, the
//! core-listener handoff, and the no-CA-key invariant. Each concern is a
//! submodule so the sysex pieces land independently of the cross-platform core.

pub mod activation_gate;
