//! macOS capture backend (L4 Phase 2). The sandbox-provable Rust seam that feeds
//! the protocol-general `CaptureIngress` from a `NETransparentProxyProvider`
//! system extension. Each submodule is one Band-B unit; the Swift sysex and its
//! signing/activation live under `apps/mac/` (Band C).

pub mod availability;
