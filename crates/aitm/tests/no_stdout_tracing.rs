//! The no-stdout-tracing pin (spec D7, D14, AC-W1-29; plan Task 13).
//!
//! `tracing` never writes to stdout. The only `fmt` layers are the file layer
//! and the raw stderr layer that `crates/aitm/src/startup/log.rs` composes,
//! each with an explicit `.with_writer(..)`, and that file is the only place a
//! subscriber is built or installed. This test scans `crates/aitm/src` and
//! `crates/aitm-term/src` for every construction or installation site
//! (`tracing_subscriber::fmt()`, a bare `fmt()` where `tracing_subscriber`'s
//! `fmt` is in reach, `fmt::layer()`, `.try_init()`, `.init()` on a
//! subscriber/layer/registry line, `set_global_default(`) outside each
//! file's `#[cfg(test)]` tail and asserts every hit lives in [`HOME`], whose
//! `fmt::layer()` count equals its `.with_writer(` count. The scanner is a
//! pure function over `(path, text)` so the self-check proves it bites.

use std::fmt;
use std::path::{Path, PathBuf};

/// The one file allowed to build and install the tracing subscriber.
const HOME: &str = "crates/aitm/src/startup/log.rs";

/// The roots the scan walks, relative to the workspace root.
const ROOTS: [&str; 2] = ["crates/aitm/src", "crates/aitm-term/src"];

/// A `tracing_subscriber::fmt()` subscriber builder (reported for the bare
/// `fmt()` spelling too when the file imports `tracing_subscriber::fmt` or
/// the line names `tracing_subscriber`).
const FMT: &str = "fmt()";
/// A `fmt::layer()` builder; each needs its own `.with_writer(`.
const LAYER: &str = "fmt::layer()";
/// Installing a builder as the global default.
const TRY_INIT: &str = ".try_init()";
/// Same, on a line that names a subscriber, layer or registry.
const INIT: &str = ".init()";
/// The explicit install.
const SET_GLOBAL: &str = "set_global_default(";
/// The writer every `fmt` layer must name (never the stdout default).
const WITH_WRITER: &str = ".with_writer(";

/// One offending line, displayed as `path:line: text`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    path: PathBuf,
    line: usize,
    needle: &'static str,
    text: String,
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.path.display(), self.line, self.text)
    }
}

/// The production lines of a source file, numbered from 1: everything before
/// the first line that is exactly `#[cfg(test)]` at column 0 (the trailing
/// `mod tests` convention; an indented `#[cfg(test)]` on a single item does
/// not end the scan), minus every line whose trimmed text starts with `//`.
fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .take_while(|(_, line)| *line != "#[cfg(test)]")
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// True for a `use` line that brings `tracing_subscriber`'s `fmt` into reach
/// (`use tracing_subscriber::fmt;`, `use tracing_subscriber::fmt::…`,
/// `use tracing_subscriber::{fmt, …}`), after which a bare `fmt()` in the
/// file is a subscriber construction.
fn imports_tracing_fmt(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("use ") || trimmed.contains(" use "))
        && trimmed.contains("tracing_subscriber")
        && trimmed.contains("fmt")
}

/// Every column at which `needle` occurs in `line`, paired with the needle.
fn positions<'a>(
    line: &'a str,
    needle: &'static str,
) -> impl Iterator<Item = (usize, &'static str)> + 'a {
    line.match_indices(needle).map(move |(at, _)| (at, needle))
}

/// The scanner: every subscriber construction or installation on a
/// production line of `text`, in line then column order.
fn scan_tracing(path: &Path, text: &str) -> Vec<Hit> {
    let lines: Vec<(usize, &str)> = production_lines(text).collect();
    let imports_fmt = lines.iter().any(|(_, line)| imports_tracing_fmt(line));
    let mut hits = Vec::new();
    for (line_no, line) in lines {
        let lower = line.to_ascii_lowercase();
        let names_a_subscriber = ["subscriber", "layer", "registry"]
            .iter()
            .any(|word| lower.contains(word));
        let mut found: Vec<(usize, &'static str)> = Vec::new();
        if imports_fmt || line.contains("tracing_subscriber") {
            found.extend(positions(line, FMT));
        }
        found.extend(positions(line, LAYER));
        found.extend(positions(line, TRY_INIT));
        if names_a_subscriber {
            found.extend(positions(line, INIT));
        }
        found.extend(positions(line, SET_GLOBAL));
        found.sort_unstable();
        hits.extend(found.into_iter().map(|(_, needle)| Hit {
            path: path.to_path_buf(),
            line: line_no,
            needle,
            text: line.trim().to_string(),
        }));
    }
    hits
}

/// How many times `needle` occurs on the production lines of `text`.
fn count(text: &str, needle: &str) -> usize {
    production_lines(text)
        .map(|(_, line)| line.matches(needle).count())
        .sum()
}

/// The workspace root, two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, recursively, in sorted order.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
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

fn list(hits: &[Hit]) -> String {
    hits.iter()
        .map(|hit| format!("  {hit}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn tracing_scanner_catches_a_bare_fmt_init() {
    let text = "use tracing_subscriber::fmt;\nfn i() { let _ = fmt().try_init(); }\n";
    let hits = scan_tracing(Path::new("inline.rs"), text);
    let line = "fn i() { let _ = fmt().try_init(); }".to_string();
    assert_eq!(
        hits,
        vec![
            Hit {
                path: PathBuf::from("inline.rs"),
                line: 2,
                needle: "fmt()",
                text: line.clone(),
            },
            Hit {
                path: PathBuf::from("inline.rs"),
                line: 2,
                needle: ".try_init()",
                text: line,
            },
        ]
    );
    assert_eq!(
        hits[0].to_string(),
        "inline.rs:2: fn i() { let _ = fmt().try_init(); }"
    );
}

#[test]
fn every_subscriber_construction_lives_in_startup_log_and_has_a_writer() {
    let root = workspace_root();
    let home = Path::new(HOME);
    let mut outside = Vec::new();
    let mut inside = Vec::new();
    let mut layers = 0usize;
    let mut writers = 0usize;
    let mut saw_home = false;
    for sub in ROOTS {
        for path in rust_files(&root.join(sub)) {
            let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            let hits = scan_tracing(&rel, &text);
            if rel == home {
                saw_home = true;
                inside = hits;
                layers = count(&text, LAYER);
                writers = count(&text, WITH_WRITER);
            } else {
                outside.extend(hits);
            }
        }
    }
    assert!(saw_home, "{HOME} was not scanned");
    assert!(
        outside.is_empty(),
        "{} tracing subscriber construction/installation site(s) outside {HOME} (spec D7: \
         the composition lives in startup/log.rs and never writes to stdout):\n{}",
        outside.len(),
        list(&outside)
    );
    assert!(
        !inside.is_empty(),
        "{HOME} builds and installs no subscriber at all; the scanner would not be proving anything"
    );
    assert!(
        layers >= 1,
        "{HOME} builds no fmt::layer(); the file layer and the stderr layer should be there"
    );
    assert_eq!(
        layers, writers,
        "{HOME}: {layers} fmt::layer() but {writers} .with_writer( — every fmt layer must name \
         its writer (the default is stdout)"
    );
}
