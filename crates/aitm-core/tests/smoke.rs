//! Task 1: workspace builds and `aitm-core` exposes its version.

#[test]
fn workspace_builds() {
    // `VERSION` is wired to the crate's own Cargo package version.
    assert!(!aitm_core::VERSION.is_empty());
    assert_eq!(aitm_core::VERSION, env!("CARGO_PKG_VERSION"));
}
