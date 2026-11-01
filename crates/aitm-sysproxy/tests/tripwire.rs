//! SP-AC28 tripwire: the system-proxy code never escalates privileges.
//!
//! Walks `crates/aitm-sysproxy/src` plus the fixed list of workspace files
//! the system-proxy PRs touch and fails on any non-comment line containing
//! `sudo `, `osascript` or `with administrator privileges`. A second test
//! fails on any line under `crates/aitm-sysproxy/src` containing `unsafe`
//! (comments included: `grep -rn unsafe` must be empty).
//!
//! Plan: docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md, Task 12.

use std::fs;
use std::path::{Path, PathBuf};

/// The strings SP-AC28 forbids outside comments.
const FORBIDDEN: [&str; 3] = ["sudo ", "osascript", "with administrator privileges"];

/// Workspace files outside `crates/aitm-sysproxy/src` that the system-proxy
/// PRs touch, relative to the workspace root. A file that does not exist yet
/// is skipped with a printed `NOTE`.
const WORKSPACE_FILES: [&str; 15] = [
    "crates/aitm/src/main.rs",
    "crates/aitm/src/wire.rs",
    "crates/aitm/src/config_file.rs",
    "crates/aitm-plugins/src/control.rs",
    "crates/aitm-tui/src/model.rs",
    "crates/aitm-tui/src/app.rs",
    "crates/aitm-tui/src/keys.rs",
    "crates/aitm-tui/src/ui/bars.rs",
    "apps/web/src/state/app.ts",
    "apps/web/src/state/systemProxy.ts",
    "apps/web/src/shell/Toolbar.tsx",
    "apps/mac/Sources/AitmproxyKit/SystemProxyFacts.swift",
    "apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift",
    "apps/mac/Sources/Aitmproxy/Session+SystemProxy.swift",
    "apps/mac/Sources/Aitmproxy/Shell/SystemProxySheet.swift",
];

/// One offending line.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    path: PathBuf,
    line: usize,
    needle: &'static str,
    text: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: contains {:?}: {}",
            self.path.display(),
            self.line,
            self.needle,
            self.text.trim()
        )
    }
}

/// `CARGO_MANIFEST_DIR` is `<workspace>/crates/aitm-sysproxy`.
fn manifest_dir() -> PathBuf {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("cargo sets CARGO_MANIFEST_DIR for integration tests");
    PathBuf::from(dir)
}

fn workspace_root() -> PathBuf {
    let root = manifest_dir().join("..").join("..");
    root.canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize workspace root {}: {e}", root.display()))
}

/// This test's own source, which legitimately spells the forbidden strings.
fn own_source() -> PathBuf {
    let own = manifest_dir().join("tests").join("tripwire.rs");
    own.canonicalize().unwrap_or(own)
}

/// A line whose trimmed text starts with one of these is a comment.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    ["//", "///", "//!", "#", "*", "/*"]
        .iter()
        .any(|p| t.starts_with(p))
}

/// Non-comment lines of `text` that contain a forbidden string.
fn scan_text(path: &Path, text: &str) -> Vec<Violation> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !is_comment(line))
        .flat_map(|(i, line)| {
            FORBIDDEN
                .iter()
                .filter(move |needle| line.contains(*needle))
                .map(move |needle| Violation {
                    path: path.to_path_buf(),
                    line: i + 1,
                    needle,
                    text: line.to_string(),
                })
        })
        .collect()
}

/// Every line of `text` containing `unsafe`, comments included.
fn scan_unsafe(path: &Path, text: &str) -> Vec<Violation> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.contains("unsafe"))
        .map(|(i, line)| Violation {
            path: path.to_path_buf(),
            line: i + 1,
            needle: "unsafe",
            text: line.to_string(),
        })
        .collect()
}

/// Every regular file under `dir`, recursively, sorted for stable output.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("read_dir entry under {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
    out.sort();
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The crate's own sources plus the fixed workspace list, minus this file.
fn scanned_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let own = own_source();
    let mut files = Vec::new();
    walk(&root.join("crates/aitm-sysproxy/src"), &mut files);
    for rel in WORKSPACE_FILES {
        let path = root.join(rel);
        if path.is_file() {
            files.push(path);
        } else {
            println!("NOTE: {rel} does not exist yet; skipped");
        }
    }
    files.retain(|p| p.canonicalize().map(|c| c != own).unwrap_or(true));
    assert!(
        !files.is_empty(),
        "tripwire scanned nothing under {}",
        root.display()
    );
    files
}

#[test]
fn no_privilege_escalation_strings_in_the_system_proxy_code() {
    let files = scanned_files();
    let mut violations = Vec::new();
    for path in &files {
        violations.extend(scan_text(path, &read(path)));
    }
    assert!(
        violations.is_empty(),
        "SP-AC28: {} forbidden privilege-escalation string(s) in {} scanned file(s):\n{}",
        violations.len(),
        files.len(),
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    println!("SP-AC28: {} files clean", files.len());
}

#[test]
fn no_unsafe_in_the_crate() {
    let src = workspace_root().join("crates/aitm-sysproxy/src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    assert!(!files.is_empty(), "nothing under {}", src.display());
    let mut violations = Vec::new();
    for path in &files {
        violations.extend(scan_unsafe(path, &read(path)));
    }
    assert!(
        violations.is_empty(),
        "SP-AC28: `unsafe` under crates/aitm-sysproxy/src:\n{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The scanner itself must catch what the plan says it catches, so that
/// an empty tree or a broken walker cannot pass by accident.
#[test]
fn scanner_catches_planted_strings_and_ignores_comments() {
    let p = Path::new("scratch.rs");
    let planted = concat!(
        "fn main() {\n",
        "    let x = \"su",
        "do \";\n",
        "    // su",
        "do in a comment is fine\n",
        "    # osa",
        "script in a hash comment is fine\n",
        "    /* with administrator ",
        "privileges in a block comment is fine */\n",
        "    * with administrator ",
        "privileges on a star line is fine\n",
        "    run(\"osa",
        "script\");\n",
        "    say(\"with administrator ",
        "privileges\");\n",
        "}\n",
    );
    let found = scan_text(p, planted);
    let got: Vec<(usize, &str)> = found.iter().map(|v| (v.line, v.needle)).collect();
    assert_eq!(
        got,
        vec![
            (2, "sudo "),
            (7, "osascript"),
            (8, "with administrator privileges")
        ]
    );

    let clean = "fn main() {\n    let sudoku = 1; // no trailing space after sudo\n}\n";
    assert_eq!(scan_text(p, clean), Vec::new());

    let unsafe_text = "// SAFETY: none\nlet y = unsafe { 1 };\n";
    let u = scan_unsafe(p, unsafe_text);
    assert_eq!(u.len(), 1);
    assert_eq!(u[0].line, 2);
    assert_eq!(u[0].needle, "unsafe");
}
