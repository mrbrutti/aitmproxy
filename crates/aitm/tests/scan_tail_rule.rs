//! Tester (whole-branch pass): the guard behind the two source-scan pins.
//!
//! `tests/no_bypass.rs` (AC-W1-28) and `tests/no_stdout_tracing.rs`
//! (AC-W1-29) stop reading a file at its first column-0 `#[cfg(test)]`,
//! assuming it opens the trailing `mod tests { … }`. A column-0
//! `#[cfg(test)]` on anything else — a `mod x;` declaration, a `use`, a
//! single `fn` — would end their scan early and hide every print macro or
//! subscriber built after it. This test makes that assumption explicit over
//! the same roots: the first column-0 `#[cfg(test)]` of every file must be
//! followed by an inline `mod … {`, or, when it gates a declaration, nothing
//! but blank lines, comments, attributes and further `mod …;` declarations
//! may follow (so the hidden tail holds no code). Today the one declaration
//! case is `crates/aitm/src/macos_capture/mod.rs`, whose tail is the
//! `test_support` declaration alone.

use std::path::{Path, PathBuf};

/// The roots the two pins walk, plus the one the tracing pin adds.
const ROOTS: [&str; 3] = [
    "crates/aitm/src",
    "crates/aitm-cli/src",
    "crates/aitm-term/src",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

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

/// A line the pins' blind tail may hold without hiding anything: blank, a
/// comment, an attribute, or a `mod …;` declaration.
fn harmless_tail_line(line: &str) -> bool {
    let t = line.trim();
    t.is_empty()
        || t.starts_with("//")
        || t.starts_with("#[")
        || t.starts_with("#![")
        || (t.ends_with(';')
            && (t.starts_with("mod ")
                || t.starts_with("pub mod ")
                || t.starts_with("pub(crate) mod ")))
}

fn opens_inline_module(line: &str) -> bool {
    let t = line.trim_end();
    (t.starts_with("mod ") || t.starts_with("pub mod ") || t.starts_with("pub(crate) mod "))
        && t.ends_with('{')
}

/// The pure check over `(path, text)`: `None` when the file is fine, else
/// the `path:line: why` of the violation.
fn check_tail_rule(path: &Path, text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let first = lines.iter().position(|line| *line == "#[cfg(test)]")?;
    let Some(next) = lines.get(first + 1) else {
        return Some(format!(
            "{}:{}: #[cfg(test)] is the last line",
            path.display(),
            first + 1
        ));
    };
    if opens_inline_module(next) {
        return None;
    }
    for (offset, line) in lines[first + 1..].iter().enumerate() {
        if !harmless_tail_line(line) {
            return Some(format!(
                "{}:{}: code after a column-0 #[cfg(test)] that is not a trailing `mod tests {{`: {}",
                path.display(),
                first + 2 + offset,
                line.trim()
            ));
        }
    }
    None
}

#[test]
fn check_bites_on_a_cfg_test_declaration_above_code() {
    let text = "#[cfg(test)]\nmod helpers;\nfn prod() { println!(\"hidden\"); }\n";
    assert_eq!(
        check_tail_rule(Path::new("inline.rs"), text).as_deref(),
        Some(
            "inline.rs:3: code after a column-0 #[cfg(test)] that is not a trailing `mod tests {`: fn prod() { println!(\"hidden\"); }"
        )
    );
    let text = "#[cfg(test)]\nuse std::fmt;\n";
    assert_eq!(
        check_tail_rule(Path::new("inline.rs"), text).as_deref(),
        Some(
            "inline.rs:2: code after a column-0 #[cfg(test)] that is not a trailing `mod tests {`: use std::fmt;"
        )
    );
}

#[test]
fn check_accepts_a_trailing_module_and_a_declaration_only_tail() {
    assert_eq!(
        check_tail_rule(
            Path::new("ok.rs"),
            "fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn t() { println!(\"x\"); }\n}\n"
        ),
        None
    );
    assert_eq!(
        check_tail_rule(
            Path::new("ok.rs"),
            "pub mod a;\n#[cfg(test)]\npub(crate) mod test_support;\n"
        ),
        None
    );
    assert_eq!(
        check_tail_rule(
            Path::new("ok.rs"),
            "fn prod() {}\n    #[cfg(test)]\n    fn t() {}\n"
        ),
        None,
        "an indented attribute is not a column-0 one"
    );
    assert_eq!(check_tail_rule(Path::new("ok.rs"), ""), None);
}

#[test]
fn every_scanned_file_hides_no_code_behind_its_first_cfg_test() {
    let root = workspace_root();
    let mut violations = Vec::new();
    let mut files = 0usize;
    for sub in ROOTS {
        for path in rust_files(&root.join(sub)) {
            files += 1;
            let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            if let Some(why) = check_tail_rule(&rel, &text) {
                violations.push(why);
            }
        }
    }
    assert!(
        files >= 30,
        "the walk saw only {files} files; is the workspace root right?"
    );
    assert!(
        violations.is_empty(),
        "{} file(s) hide code behind a column-0 #[cfg(test)] that is not a trailing test module; \
         tests/no_bypass.rs and tests/no_stdout_tracing.rs stop scanning there and would miss it:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}
