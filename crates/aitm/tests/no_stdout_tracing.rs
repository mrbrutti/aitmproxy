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
//!
//! The walk, the production-line rule and `Hit` are shared with the other
//! pins through `tests/common/mod.rs` (quality Q5).

use std::path::{Path, PathBuf};

mod common;
use common::{list, production_lines, rust_files, workspace_root, Hit};

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

/// Tester F1 / quality Q5: the same tail rule as `no_bypass.rs` — a column-0
/// `#[cfg(test)]` on a `pub(crate) mod x;` declaration does not end the
/// scan, so a layer built after it is caught; `count` reads the same lines.
#[test]
fn tracing_scanner_keeps_reading_past_a_cfg_test_declaration() {
    let text = "#[cfg(test)]\npub(crate) mod test_support;\nfn i() { let _ = fmt::layer(); }\n#[cfg(test)]\nmod tests { fn t() { let _ = fmt::layer().with_writer(std::io::stdout); } }\n";
    let hits = scan_tracing(Path::new("inline.rs"), text);
    assert_eq!(
        hits,
        vec![Hit {
            path: PathBuf::from("inline.rs"),
            line: 3,
            needle: "fmt::layer()",
            text: "fn i() { let _ = fmt::layer(); }".to_string(),
        }]
    );
    assert_eq!(count(text, LAYER), 1);
    assert_eq!(count(text, WITH_WRITER), 0);
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
