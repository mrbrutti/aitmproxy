//! The no-bypass pin (spec D14, AC-W1-28; plan Task 13).
//!
//! No human-facing text bypasses the `aitm-term` layer: every `println!`,
//! `print!`, `eprintln!` and `eprint!` under `crates/aitm/src` and
//! `crates/aitm-cli/src` must sit in a file on the [`ALLOWED`] list (each
//! entry carries the reason spec D14 gives) or in the file's `#[cfg(test)]`
//! tail. The scanner is a pure function over `(path, text)` so the
//! self-checks below prove it bites; the tree-wide test walks the committed
//! sources with `std::fs::read_dir` (no `walkdir`).
//!
//! `crates/aitm-tui/src` joins the scan in a later wave (amendment D).

use std::fmt;
use std::path::{Path, PathBuf};

/// The files allowed to write to stdout/stderr directly, with the reason spec
/// D14 gives for each. W2 removes `confirm.rs` when the prompt goes through
/// the layer.
const ALLOWED: [(&str, &str); 3] = [
    (
        "crates/aitm/src/render.rs",
        "`render_cli_value` builds the stdout bytes a one-shot result is written with",
    ),
    (
        "crates/aitm/src/startup/mod.rs",
        "`write_stdout`: the pre-boot version/help text, `aitm web --help` and the operator-token confirmation",
    ),
    (
        "crates/aitm-cli/src/confirm.rs",
        "the `[y/N]` prompt, until W3 routes it through the layer",
    ),
];

/// The roots the scan walks, relative to the workspace root.
const ROOTS: [&str; 2] = ["crates/aitm/src", "crates/aitm-cli/src"];

/// The print macros no production line may call.
const NEEDLES: [&str; 4] = ["println!(", "print!(", "eprintln!(", "eprint!("];

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
/// `mod tests` convention; an indented `#[cfg(test)]` on a single item, as in
/// `macos_capture/feeder.rs`, does not end the scan), minus every line whose
/// trimmed text starts with `//`.
fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .take_while(|(_, line)| *line != "#[cfg(test)]")
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// True when the byte before `at` continues an identifier, so a needle found
/// at `at` is the tail of a longer name (`println!(` inside `eprintln!(`).
fn glued_to_identifier(line: &str, at: usize) -> bool {
    at.checked_sub(1)
        .and_then(|before| line.as_bytes().get(before))
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

/// The scanner: every print macro call on a production line of `text`, in
/// line then column order.
fn scan_prints(path: &Path, text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line_no, line) in production_lines(text) {
        let mut found: Vec<(usize, &'static str)> = NEEDLES
            .iter()
            .flat_map(|needle| {
                line.match_indices(needle)
                    .filter(|(at, _)| !glued_to_identifier(line, *at))
                    .map(move |(at, _)| (at, *needle))
            })
            .collect();
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
fn scanner_catches_a_print_outside_a_test_module() {
    let text =
        "fn f() { println!(\"x\"); }\n#[cfg(test)]\nmod tests { fn g() { println!(\"y\"); } }\n";
    let hits = scan_prints(Path::new("inline.rs"), text);
    assert_eq!(
        hits,
        vec![Hit {
            path: PathBuf::from("inline.rs"),
            line: 1,
            needle: "println!(",
            text: "fn f() { println!(\"x\"); }".to_string(),
        }]
    );
    assert_eq!(
        hits[0].to_string(),
        "inline.rs:1: fn f() { println!(\"x\"); }"
    );
}

#[test]
fn scanner_ignores_indented_cfg_test_attributes_and_comments() {
    let text =
        "    #[cfg(test)]\n    fn only_in_tests() {}\n// println!(\"c\")\nfn h() { eprintln!(\"z\"); }\n";
    let hits = scan_prints(Path::new("inline.rs"), text);
    assert_eq!(
        hits,
        vec![Hit {
            path: PathBuf::from("inline.rs"),
            line: 4,
            needle: "eprintln!(",
            text: "fn h() { eprintln!(\"z\"); }".to_string(),
        }]
    );
}

#[test]
fn no_print_macro_outside_the_allow_list() {
    let root = workspace_root();
    for (allowed, reason) in ALLOWED {
        assert!(
            root.join(allowed).is_file(),
            "allow-list entry {allowed} ({reason}) names a file that no longer exists; drop it"
        );
    }

    let mut walked = Vec::new();
    let mut hits = Vec::new();
    for sub in ROOTS {
        for path in rust_files(&root.join(sub)) {
            let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
            walked.push(rel.clone());
            if ALLOWED.iter().any(|(allowed, _)| Path::new(allowed) == rel) {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            hits.extend(scan_prints(&rel, &text));
        }
    }
    // The allow-listed files sit one directory below each root, so reaching
    // them proves the walk covers both roots and recurses.
    for (allowed, _) in ALLOWED {
        assert!(
            walked.iter().any(|rel| rel == Path::new(allowed)),
            "the walk over {ROOTS:?} never reached {allowed}; rust_files is not recursing"
        );
    }

    let allowed = ALLOWED
        .iter()
        .map(|(path, reason)| format!("  {path} — {reason}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        hits.is_empty(),
        "{} print macro call(s) outside the allow-list and outside #[cfg(test)] (spec D14: \
         human-facing text goes through the aitm-term layer):\n{}\nallowed direct writers:\n{allowed}",
        hits.len(),
        list(&hits)
    );
}
