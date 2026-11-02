//! Scaffolding shared by the source-scan pins (`no_bypass.rs`,
//! `no_stdout_tracing.rs`; quality Q5): the workspace walk, the
//! production-line rule and the `Hit` they report. Cargo's shared test-helper
//! convention: each pin declares `mod common;`, and because every binary uses
//! a different subset, `dead_code` is allowed here.
//!
//! Boundary (quality Q19): `common` is textual source scans of the tree only;
//! proxy assembly, CA directories and service helpers live in `support/mod.rs`.
//!
//! The scan is deliberately textual — `std::fs::read_dir` and `str::lines`,
//! no `syn`, no `walkdir` — so the pins stay dependency-free and a reader can
//! predict exactly what they catch.

#![allow(dead_code)]

use std::fmt;
use std::path::{Path, PathBuf};

/// One offending line, displayed as `path:line: text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub path: PathBuf,
    pub line: usize,
    pub needle: &'static str,
    pub text: String,
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.path.display(), self.line, self.text)
    }
}

/// True for a line that opens an inline module — `mod x {`, `pub mod x {`,
/// `pub(crate) mod x {`, or a one-line `mod x { … }` — at any indentation.
/// A declaration (`mod x;`, any visibility) is not one: that is the line a
/// `#[cfg(test)]` may gate without hiding the code after it (tester F1).
pub fn opens_inline_module(line: &str) -> bool {
    let t = line.trim();
    (t.starts_with("mod ") || t.starts_with("pub mod ") || t.starts_with("pub(crate) mod "))
        && !t.ends_with(';')
}

/// True when the first significant line of `rest` — not blank, not a `//`
/// comment, not another attribute — opens an inline module.
fn opens_test_module_after(rest: &[&str]) -> bool {
    rest.iter()
        .map(|line| line.trim())
        .find(|t| !t.is_empty() && !t.starts_with("//") && !t.starts_with("#["))
        .is_some_and(opens_inline_module)
}

/// The production lines of a source file, numbered from 1: everything before
/// the column-0 `#[cfg(test)]` that opens the trailing test module — the
/// first one whose next significant line is an inline `mod … {`
/// ([`opens_inline_module`]) — minus every line whose trimmed text starts
/// with `//`. A column-0 `#[cfg(test)]` on anything else does not end the
/// scan (tester F1): a `pub(crate) mod test_support;` declaration, as in
/// `crates/aitm/src/macos_capture/mod.rs`, a `use`, a single `fn`. An
/// indented `#[cfg(test)]` on one item never does. A file with no trailing
/// test module is scanned to its end.
pub fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let cut = (0..lines.len())
        .find(|&at| lines[at] == "#[cfg(test)]" && opens_test_module_after(&lines[at + 1..]))
        .unwrap_or(lines.len());
    lines
        .into_iter()
        .take(cut)
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// The workspace root, two levels above this crate's manifest.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, recursively, in sorted order.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
    let mut out = Vec::new();
    for entry in entries {
        let path = entry
            .unwrap_or_else(|err| panic!("read_dir entry under {}: {err}", dir.display()))
            .path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The hits, one per line, indented for an assertion message.
pub fn list(hits: &[Hit]) -> String {
    hits.iter()
        .map(|hit| format!("  {hit}"))
        .collect::<Vec<_>>()
        .join("\n")
}
