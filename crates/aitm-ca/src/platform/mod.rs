//! Per-platform `TrustStore` implementations. All three compile on every
//! host so each platform's command lines are unit-tested against canned
//! output wherever the suite runs; only `Platform::detect` consults the
//! target OS.

pub mod linux;
pub mod macos;
pub mod windows;
