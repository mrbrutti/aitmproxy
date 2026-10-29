//! Task 20 / AC-M4-19: the core-untouched milestone-exit check.
//!
//! The M4 anti-goal is explicit: "If supporting the agent required editing
//! `aitm-core`'s flow/event model or protocol seams (beyond the additive
//! command/registry/transport changes F1/F4 are), the architecture has failed.
//! F1/F4 are additive to the command/transport layer; they do not touch the
//! protocol modules or the `Flow`/`Event` enums." AC-M4-19 asks a diff check to
//! confirm the `Flow`/`Event` enums and the `ProtocolModule`/protocol crates are
//! unchanged by the branch.
//!
//! This is inherently a git-diff check, so — exactly like the browser e2e gates
//! behind `AITM_OBSCURA` — it skips gracefully (printing why, passing) when git
//! or the `main` ref is unavailable (a sandbox, a shallow CI checkout, a source
//! tarball), so it never breaks the hermetic `cargo test`. Where git and `main`
//! are present it is authoritative: it diffs the whole branch against its
//! merge-base with `main` and fails if any protected path changed.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The workspace root: `CARGO_MANIFEST_DIR` is `<root>/crates/aitm`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root is two levels above crates/aitm")
        .to_path_buf()
}

/// Run `git` in the repo root, returning trimmed stdout on a zero exit, else
/// `None` (git missing, not a repo, ref absent — any reason to skip).
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Protected paths M4 must not touch: the `Event` and `Flow` enum modules and the
/// protocol crates (the `ProtocolModule` seam). A changed path is a violation iff
/// it is one of these exact enum files or lives under a protocol crate's `src/`.
fn is_protected(path: &str) -> bool {
    path == "crates/aitm-core/src/event.rs"
        || path == "crates/aitm-core/src/flow.rs"
        || path.starts_with("crates/aitm-proto-http/src/")
        || path.starts_with("crates/aitm-proto-ws/src/")
}

#[test]
fn core_and_protocols_untouched() {
    let root = repo_root();

    // Resolve the branch's base. `main` must exist and share history with HEAD;
    // if not (no git, detached source tree, shallow clone), skip — the check is a
    // milestone-exit gate, not a hermetic unit of behaviour.
    let Some(base) = git(&root, &["merge-base", "main", "HEAD"]) else {
        eprintln!(
            "m4_core_untouched: skipped; `git merge-base main HEAD` unavailable \
             (no git, no `main` ref, or not a repo). Run in a full checkout to enforce AC-M4-19."
        );
        return;
    };
    assert!(!base.is_empty(), "merge-base returned empty output");

    let Some(changed) = git(&root, &["diff", "--name-only", &format!("{base}...HEAD")]) else {
        eprintln!("m4_core_untouched: skipped; `git diff` against the base failed.");
        return;
    };

    // An empty diff (the branch is the base) trivially satisfies the invariant.
    let violations: Vec<&str> = changed
        .lines()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter(|p| is_protected(p))
        .collect();

    assert!(
        violations.is_empty(),
        "AC-M4-19 violated: M4 changed the Flow/Event enums or a protocol crate \
         (the branch must stay additive to the command/registry/transport layer). \
         Protected paths changed vs {base}:\n  {}",
        violations.join("\n  ")
    );
}
