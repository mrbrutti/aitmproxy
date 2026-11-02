//! macOS lane: libproc socket scan + `CFBundle` identity.
//!
//! The bundle-path rule is a plain string function and is not cfg-gated, so it
//! builds and tests on every host; the libproc FFI (plan Task 3) and the scanner
//! (Task 5) are macOS-only.

pub(crate) mod bundle_path;
