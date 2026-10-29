//! M5 exit gate — the hard structural checks (M5 plan Task 15).
//!
//! These are **source-structural** invariants, verified by reading the crate's own
//! production source (never a test module), so they hold regardless of privilege,
//! platform, or whether the privileged suites ran. They are the milestone's hard
//! gates:
//!
//! - **AC20 — no `unsafe`:** `#![forbid(unsafe_code)]` is present at the crate root.
//!   (The crate also *compiles* under that attribute, which is the enforcement; this
//!   test guards against someone silently deleting the attribute.)
//! - **AC21 — one choke point:** exactly one production call site puts bytes on the
//!   wire (`backend.inject(..)` in `wire.rs::send_on_wire`), and that function cannot
//!   be reached without an `L4Permit` (by type); the mangling-verdict path likewise
//!   holds an `L4Permit` minted only by `L4Guard::check`.
//!
//! AC19 ("core untouched") is a hard gate too, but it needs the repo's `aitm-core`
//! tree and the merge-base with `main`, so it lives where the whole workspace is in
//! scope: `crates/aitm/tests/l4_wiring.rs::aitm_core_untouched`. It is not duplicated
//! here.

use std::path::{Path, PathBuf};

/// The crate's `src/` directory (resolved from this test crate's manifest dir).
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The production (non-test) prefix of a source file: everything before the trailing
/// `#[cfg(test)] mod tests` block. Every module in this crate keeps its unit tests in
/// one such trailing block, so this cleanly excludes test-only code (e.g. mock
/// backends that legitimately call `.inject(..)`) from the structural scan.
fn production_prefix(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => source,
    }
}

/// Every `*.rs` file under `src/`, recursively.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// AC20 — the crate root forbids `unsafe`. The dependency crates' own `unsafe`
/// (pcap / nfq) stays internal to them; `aitm-proto-l4` itself has none.
#[test]
fn crate_root_forbids_unsafe() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("read lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "the crate root must keep `#![forbid(unsafe_code)]` (AC20)"
    );
}

/// AC21 — there is exactly **one** production wire-write call site in the whole
/// crate, and it is in `wire.rs` (the `send_on_wire` choke point). A new `.inject(..)`
/// call anywhere else in production code fails this test.
#[test]
fn exactly_one_production_wire_write() {
    let mut sites: Vec<(String, usize)> = Vec::new();
    for file in rust_sources(&src_dir()) {
        let source = std::fs::read_to_string(&file).expect("read source");
        let count = production_prefix(&source).matches(".inject(").count();
        if count > 0 {
            let name = file
                .strip_prefix(src_dir())
                .unwrap_or(&file)
                .to_string_lossy()
                .into_owned();
            sites.push((name, count));
        }
    }

    assert_eq!(
        sites,
        vec![("wire.rs".to_string(), 1)],
        "the only production wire write must be the single `send_on_wire` choke point; found: {sites:?}"
    );
}

/// AC21 — the single wire write is gated by an `L4Permit` **by type**: `send_on_wire`
/// takes `permit: &mut L4Permit`, so it cannot be called without a permit, and the
/// permit's fields are private to the guard module (a `compile_fail` doctest in
/// `wire.rs` proves it cannot be forged). This test pins the signature contract.
#[test]
fn wire_write_requires_permit_by_type() {
    let wire = std::fs::read_to_string(src_dir().join("wire.rs")).expect("read wire.rs");
    let prod = production_prefix(&wire);
    assert!(
        prod.contains("pub fn send_on_wire("),
        "send_on_wire must be the public wire-write entry point"
    );
    assert!(
        prod.contains("permit: &mut L4Permit"),
        "send_on_wire must require an L4Permit by type (the unforgeable token) (AC21)"
    );
}

/// AC21 — the mangling-verdict path is gated the same way. A mutated packet is only
/// ever reinjected through an [`InterceptHandle`], which holds an `L4Permit` for the
/// session's lifetime; that handle is constructed **only** inside `start_intercept`,
/// which mints the permit via `L4Guard::check(L4Action::Intercept, ..)`. So there is
/// no way to submit a mangling verdict without having passed the guard.
#[test]
fn mangling_verdict_requires_permit_by_type() {
    let intercept =
        std::fs::read_to_string(src_dir().join("intercept").join("mod.rs")).expect("read mod.rs");
    let prod = production_prefix(&intercept);

    // The live session holds a permit, by type, for its whole lifetime.
    assert!(
        prod.contains("_permit: L4Permit"),
        "InterceptHandle must hold an L4Permit for the session lifetime (AC21)"
    );
    // The permit is minted only by the guard, as an Intercept permit.
    assert!(
        prod.contains("guard.check(L4Action::Intercept"),
        "start_intercept must mint the Intercept permit via L4Guard::check (AC21)"
    );
    // The permit field is private, so a caller outside this module cannot forge an
    // InterceptHandle (and thus cannot reach `submit_verdict`) without going through
    // `start_intercept` — the only minting path. A `pub _permit` would break that.
    assert!(
        !prod.contains("pub _permit"),
        "the held L4Permit must stay a private field so InterceptHandle is unforgeable (AC21)"
    );
}
