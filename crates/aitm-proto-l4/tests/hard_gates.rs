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
//!   holds an `L4Permit` minted only by `L4Guard::check`. The one other production
//!   `.inject(..)` site, in `backend/routed.rs`, is `RoutedBackend::inject`'s
//!   backend-layer delegation to the in-process or helper backend (privilege plan
//!   P1b.8); it has no caller other than `send_on_wire` and is pinned to exactly one.
//!   The third, in `backend/helper.rs`, is `HelperBackend::inject`'s one delegation
//!   to `HelperSession::inject` (privilege plan P1b.13), reached only through
//!   `RoutedBackend`; it too is pinned to exactly one.
//!
//! AC19 ("core untouched") is a hard gate too, but it needs the repo's `aitm-core`
//! tree and the merge-base with `main`, so it lives where the whole workspace is in
//! scope: `crates/aitm/tests/l4_wiring.rs::aitm_core_untouched`. It is not duplicated
//! here.
//!
//! **These text scans are supplementary, not the guarantee.** They grep the
//! production source and would miss, for example, a wire write spelled differently
//! or a verdict path refactored around the string they match. The *actual*
//! one-choke-point and one-mangling-path guarantees are enforced by the **type
//! system**, which no test can bypass: `L4Permit` has private fields minted only by
//! `L4Guard::check`, `send_on_wire` takes one by
//! type, `InterceptHandle` holds one for the session's life, and the `compile_fail`
//! doctest in `wire.rs` proves the permit cannot be forged. These tests only guard
//! against someone silently editing those structural properties away; read them as a
//! tripwire over the type-level proof, not as the proof itself.

use std::path::{Path, PathBuf};

/// The crate's `src/` directory (resolved from this test crate's manifest dir).
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The production (non-test) prefix of a source file: everything before the first
/// `#[cfg(test)]` that introduces a **module** (`mod tests`, `pub(crate) mod fakes`).
/// Every module in this crate keeps its unit tests in such a trailing block, so this
/// cleanly excludes test-only code (e.g. mock backends that legitimately call
/// `.inject(..)`) from the structural scan.
///
/// A `#[cfg(test)]` on a single test-only *method* earlier in the file does not end
/// the prefix (tester, privilege unit p1b): `privilege/state.rs` carries two such
/// seams hundreds of lines before its `mod tests`, and cutting there would hide the
/// watcher thread, the session attach and the direct helper start from the scan.
/// Including a test-only method in the scan is the conservative direction: a wire
/// write inside one would still trip the gate.
fn production_prefix(source: &str) -> &str {
    const ATTR: &str = "#[cfg(test)]";
    let mut from = 0;
    while let Some(rel) = source[from..].find(ATTR) {
        let idx = from + rel;
        let after = source[idx + ATTR.len()..].trim_start();
        if after.starts_with("mod ")
            || after.starts_with("pub mod ")
            || after.starts_with("pub(crate) mod ")
        {
            return &source[..idx];
        }
        from = idx + ATTR.len();
    }
    source
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
/// crate, and it is in `wire.rs` (the `send_on_wire` choke point). The only other
/// production `.inject(..)` site is `RoutedBackend::inject`'s backend-layer
/// delegation in `backend/routed.rs` (privilege plan P1b.8): it routes the call the
/// choke point already authorized to the in-process or helper backend and has no
/// caller other than `send_on_wire`. The third is `HelperBackend::inject`'s one
/// delegation to `HelperSession::inject` in `backend/helper.rs` (privilege plan
/// P1b.13), reached only through `RoutedBackend`. All three are pinned to exactly
/// one; a new `.inject(..)` call anywhere else in production code, or a second one
/// in any of these files, fails this test.
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

    sites.sort();
    assert_eq!(
        sites,
        vec![
            ("backend/helper.rs".to_string(), 1),
            ("backend/routed.rs".to_string(), 1),
            ("wire.rs".to_string(), 1)
        ],
        "the only production wire write must be the single `send_on_wire` choke point, plus \
         `RoutedBackend::inject`'s one delegation in backend/routed.rs and \
         `HelperBackend::inject`'s one delegation in backend/helper.rs; found: {sites:?}"
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

/// Tester (privilege unit p1b): the tripwire's notion of "production code" must
/// reach the end of every production item. `privilege/state.rs` puts
/// `#[cfg(test)]` on two test-only methods (`with_requester`, `changes`) long
/// before its `mod tests`; cutting the scan at the first attribute would leave the
/// watcher thread, the session attach and the direct helper start (plan P1b.14)
/// outside `exactly_one_production_wire_write`. This pins that the scan reaches
/// them, still stops at the test module, and that the one choke point is in view.
#[test]
fn production_prefix_reaches_the_trailing_test_module() {
    let state = std::fs::read_to_string(src_dir().join("privilege").join("state.rs"))
        .expect("read privilege/state.rs");
    let prod = production_prefix(&state);
    for item in [
        "fn run_watcher(",
        "fn attach_session(",
        "fn spawn_direct(",
        "impl Acceptor for HelperListener",
        "pub fn current_platform()",
    ] {
        assert!(
            prod.contains(item),
            "the production scan of privilege/state.rs must reach `{item}`"
        );
    }
    assert!(
        !prod.contains("\nmod tests {"),
        "the scan stops at the trailing test module"
    );
    assert!(
        !prod.contains("#[test]"),
        "no test function is inside the production prefix"
    );

    let wire = std::fs::read_to_string(src_dir().join("wire.rs")).expect("read wire.rs");
    let prod = production_prefix(&wire);
    assert!(prod.contains("pub fn send_on_wire("));
    assert!(!prod.contains("#[test]"));

    // The rule on synthetic sources: an early test-only method does not end the
    // prefix; the first test-only module does; a file without one is whole.
    let synthetic = "fn a() {}\n    #[cfg(test)]\n    fn seam() {}\nfn b() {}\n\
                     #[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
    let prefix = production_prefix(synthetic);
    assert!(prefix.contains("fn b()"), "{prefix:?}");
    assert!(!prefix.contains("fn t()"), "{prefix:?}");
    assert_eq!(production_prefix("fn a() {}\n"), "fn a() {}\n");
    assert_eq!(
        production_prefix("fn a() {}\n#[cfg(test)]\npub(crate) mod fakes {}\n"),
        "fn a() {}\n"
    );
}
