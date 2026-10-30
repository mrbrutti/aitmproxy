//! Task 10: drift guard for the trust-gate shape.
//!
//! Every agent/operator gate in the workspace must ask the one predicate
//! (`CallerTrust::is_trusted_control`, reached through
//! `Frontend::is_trusted_control` or `CommandHost::caller_is_trusted_control`).
//! A gate written as a comparison against the agent role
//! (`host.frontend() == Frontend::Mcp`) is a deny-list: it fails open when a new
//! `Frontend` variant is added, and the compiler cannot exhaustiveness-check a
//! comparison. This test scans every `crates/*/src/**/*.rs` for that shape.
//!
//! It is a tripwire for the shape that shipped, not a proof. Aliasing
//! (`let agent = Frontend::Mcp; x == agent`), comparing a role string, or a cast
//! all evade it. The scanner is a pure function with its own self-tests, so a
//! regex edit cannot silently weaken it, and a non-vacuity test proves it reads
//! the files it claims to.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

/// Reviewed exceptions: `(path suffix, reason)`. A file whose path ends with the
/// suffix is skipped. Empty on purpose: every deny-list gate was migrated, and
/// an entry here is a decision a reviewer must sign off.
const ALLOWED: &[(&str, &str)] = &[];

/// The longest snippet a hit reports, so a huge `matches!` stays readable.
const MAX_SNIPPET: usize = 160;

/// The compiled matchers, built once.
struct Patterns {
    /// `==`/`!=` then an untrusted role: `x == Frontend::Mcp`.
    op_then_role: Regex,
    /// An untrusted role then `==`/`!=`: `Frontend::Mcp != x`.
    role_then_op: Regex,
    /// An untrusted role anywhere (used inside `matches!` bodies).
    role: Regex,
    /// The opening of a `matches!` call; the last char is the opening bracket.
    matches_open: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // An untrusted role with any path prefix (`aitm_core::Frontend::Mcp`).
        // `\s*` around `::` tolerates rustfmt line-breaking.
        let role = r"\b(?:\w+\s*::\s*)*(?:Frontend\s*::\s*Mcp|CallerTrust\s*::\s*Agent)\b";
        let compile = |pattern: &str| Regex::new(pattern).expect("static regex compiles");
        Patterns {
            op_then_role: compile(&format!(r"(?:==|!=)\s*&?\s*{role}")),
            role_then_op: compile(&format!(r"{role}\s*(?:==|!=)")),
            role: compile(role),
            matches_open: compile(r"\bmatches\s*!\s*[(\[{]"),
        }
    })
}

/// `src` with every comment (`//`, `///`, `//!`, nested `/* */`) and every string,
/// raw-string and char literal replaced by spaces. Newlines are kept, so line
/// numbers hold. Prose that merely mentions a gate shape, and a `//` inside a
/// string, can then neither trip the scan nor hide a real hit after it.
fn blank_comments_and_literals(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let end = match (chars[i], chars.get(i + 1).copied()) {
            ('/', Some('/')) => Some(line_comment_end(&chars, i)),
            ('/', Some('*')) => Some(block_comment_end(&chars, i)),
            ('"', _) => Some(string_end(&chars, i + 1)),
            ('r', _) => raw_string_end(&chars, i),
            ('\'', _) => char_literal_end(&chars, i),
            _ => None,
        };
        match end {
            Some(end) => {
                out.extend(
                    chars[i..end]
                        .iter()
                        .map(|&c| if c == '\n' { '\n' } else { ' ' }),
                );
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// Index of the newline ending the `//` comment at `i` (not consumed), or the end.
fn line_comment_end(chars: &[char], i: usize) -> usize {
    chars[i..]
        .iter()
        .position(|&c| c == '\n')
        .map_or(chars.len(), |n| i + n)
}

/// Index just past the (possibly nested) `/* */` comment at `i`, or the end if
/// it is unterminated.
fn block_comment_end(chars: &[char], i: usize) -> usize {
    let mut depth = 0usize;
    let mut j = i;
    while j < chars.len() {
        match (chars[j], chars.get(j + 1).copied()) {
            ('/', Some('*')) => {
                depth += 1;
                j += 2;
            }
            ('*', Some('/')) => {
                depth = depth.saturating_sub(1);
                j += 2;
                if depth == 0 {
                    return j;
                }
            }
            _ => j += 1,
        }
    }
    chars.len()
}

/// Index just past the string literal whose body starts at `start`.
fn string_end(chars: &[char], start: usize) -> usize {
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '\\' => j += 2,
            '"' => return j + 1,
            _ => j += 1,
        }
    }
    chars.len()
}

/// Index just past the raw string (`r"..."`, `r#"..."#`, also `br`) whose `r`
/// is at `i`; `None` if this `r` does not start one (an identifier, `r#type`).
fn raw_string_end(chars: &[char], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0usize;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    if chars.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < chars.len() {
        if chars[j] == '"' && (0..hashes).all(|k| chars.get(j + 1 + k) == Some(&'#')) {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(chars.len())
}

/// Index just past the char literal whose `'` is at `i`; `None` for a lifetime
/// or a loop label (`'a`, `'outer:`).
fn char_literal_end(chars: &[char], i: usize) -> Option<usize> {
    match chars.get(i + 1) {
        // An escape (`'\n'`, `'\''`, `'\\'`, `'\u{41}'`): skip the escaped char,
        // then run to the closing quote.
        Some('\\') => {
            let mut j = i + 3;
            while let Some(&c) = chars.get(j) {
                match c {
                    '\'' => return Some(j + 1),
                    '\n' => return None,
                    _ => j += 1,
                }
            }
            None
        }
        // One char then a closing quote (`'x'`, `'"'`).
        Some(_) if chars.get(i + 2) == Some(&'\'') => Some(i + 3),
        _ => None,
    }
}

/// Byte offset just past the bracket closing the one opened just before `from`,
/// or the end of `code` if it never closes. Only ASCII brackets are compared, so
/// scanning bytes is safe on UTF-8.
fn closing_bracket_end(code: &str, from: usize, open: u8) -> usize {
    let close = match open {
        b'(' => b')',
        b'[' => b']',
        _ => b'}',
    };
    let mut depth = 1usize;
    for (offset, &b) in code.as_bytes()[from..].iter().enumerate() {
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return from + offset + 1;
            }
        }
    }
    code.len()
}

/// Every deny-list comparison of the untrusted role in `src`, as
/// `(1-based line, snippet)`, in source order. The line is where the hit starts.
///
/// A hit is `==`/`!=` next to `Frontend::Mcp` or `CallerTrust::Agent` (either
/// order, any path prefix, whitespace and newlines tolerated), or either name
/// anywhere inside a `matches!(...)`. Overlapping matches merge into one hit.
fn deny_list_hits(src: &str) -> Vec<(usize, String)> {
    let code = blank_comments_and_literals(src);
    let pats = patterns();

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for re in [&pats.op_then_role, &pats.role_then_op] {
        ranges.extend(re.find_iter(&code).map(|m| (m.start(), m.end())));
    }
    for open in pats.matches_open.find_iter(&code) {
        let bracket = code.as_bytes()[open.end() - 1];
        let end = closing_bracket_end(&code, open.end(), bracket);
        if pats.role.is_match(&code[open.end()..end]) {
            ranges.push((open.start(), end));
        }
    }

    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }

    merged
        .into_iter()
        .map(|(start, end)| {
            let line = 1 + code[..start].bytes().filter(|&b| b == b'\n').count();
            let snippet = code[start..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            (line, snippet.chars().take(MAX_SNIPPET).collect())
        })
        .collect()
}

/// Every `*.rs` under `<crates_dir>/*/src/`, recursively, sorted. `tests/`
/// directories and `apps/` are not under that glob and are not scanned.
fn rust_sources(crates_dir: &Path) -> Vec<PathBuf> {
    let mut crate_dirs: Vec<PathBuf> = fs::read_dir(crates_dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", crates_dir.display()))
        .map(|entry| entry.expect("crates dir entry").path())
        .filter(|path| path.is_dir())
        .collect();
    crate_dirs.sort();

    let mut out = Vec::new();
    for krate in crate_dirs {
        let src = krate.join("src");
        if src.is_dir() {
            collect_rs(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let entry = entry.expect("source dir entry");
        let path = entry.path();
        // `file_type` does not follow symlinks, so a directory loop cannot recurse forever.
        let is_dir = entry.file_type().expect("source entry type").is_dir();
        if is_dir {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The workspace `crates/` directory: the parent of `aitm-core`'s manifest dir.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aitm-core's manifest dir has a parent: the crates dir")
        .to_path_buf()
}

fn hit(line: usize, snippet: &str) -> (usize, String) {
    (line, snippet.to_string())
}

#[test]
fn scanner_flags_every_deny_list_shape() {
    let cases: &[(&str, (usize, &str))] = &[
        (
            "if host.frontend() == Frontend::Mcp && !flag {",
            (1, "== Frontend::Mcp"),
        ),
        (
            "if aitm_core::Frontend::Mcp != role {",
            (1, "aitm_core::Frontend::Mcp !="),
        ),
        (
            "if inputs.caller == CallerTrust::Agent {",
            (1, "== CallerTrust::Agent"),
        ),
        (
            // Multi-line: rustfmt put the operator on its own line.
            "if ctx.caller()\n    == CallerTrust::Agent\n{",
            (2, "== CallerTrust::Agent"),
        ),
        (
            "let gated = matches!(host.frontend(), Frontend::Mcp);",
            (1, "matches!(host.frontend(), Frontend::Mcp)"),
        ),
        (
            // Multi-line `matches!` with the role in an or-pattern.
            "matches!(\n    host.frontend(),\n    Frontend::Mcp | Frontend::Cli\n)",
            (
                1,
                "matches!( host.frontend(), Frontend::Mcp | Frontend::Cli )",
            ),
        ),
        (
            "let is_agent = frontend == Frontend::Mcp;",
            (1, "== Frontend::Mcp"),
        ),
    ];
    for (input, (line, snippet)) in cases {
        assert_eq!(
            deny_list_hits(input),
            vec![hit(*line, snippet)],
            "expected exactly one hit for {input:?}"
        );
    }
}

#[test]
fn scanner_ignores_legitimate_shapes() {
    let inputs: &[&str] = &[
        // A match arm classifies; it is not a comparison.
        "Frontend::Mcp => CallerTrust::Agent,",
        // Comments, plain and doc.
        "// if host.frontend() == Frontend::Mcp {",
        "/// the old shape was `host.frontend() == Frontend::Mcp`",
        // The migrated shape.
        "assert!(!host.caller_is_trusted_control());",
        // Cli-only gates fail closed and name no untrusted role.
        "if host.frontend() != Frontend::Cli && !flag {",
        "if conn.role == Frontend::Operator {",
        // A label site's fallback arm.
        "_ => CallerTrust::Agent,",
        // Constructing a host for a role.
        "CommandHost::new(&s, &c, &g, None).with_frontend(Frontend::Mcp)",
    ];
    for input in inputs {
        assert_eq!(
            deny_list_hits(input),
            Vec::<(usize, String)>::new(),
            "expected no hit for {input:?}"
        );
    }
}

/// Prose that merely mentions the shape (comments, string literals) is blanked
/// before matching, and blanking never hides or shifts a real hit after it.
#[test]
fn scanner_blanks_comments_and_literals_before_matching() {
    // Prose: zero hits.
    let prose: &[&str] = &[
        r#"let msg = "never write host.frontend() == Frontend::Mcp";"#,
        r##"let msg = r#"x == "quoted" == Frontend::Mcp"#;"##,
        "let msg = \"escaped \\\" quote then == Frontend::Mcp\";",
        "/* host.frontend() == Frontend::Mcp */",
        "/* outer /* nested == CallerTrust::Agent */ still a comment == Frontend::Mcp */",
        "//! matches!(role, Frontend::Mcp)",
        "let multi = \"line one\n== Frontend::Mcp\nline three\";",
    ];
    for input in prose {
        assert_eq!(
            deny_list_hits(input),
            Vec::<(usize, String)>::new(),
            "expected no hit for {input:?}"
        );
    }

    // Real code after blanked prose is still found, on the right line.
    let after: &[(&str, (usize, &str))] = &[
        // A block comment spanning lines keeps the line numbers intact.
        (
            "/* a\n == Frontend::Mcp\n*/\nlet x = f == Frontend::Mcp;",
            (4, "== Frontend::Mcp"),
        ),
        // `//` inside a string literal is not a comment.
        (
            r#"let u = "http://x"; if f == Frontend::Mcp {"#,
            (1, "== Frontend::Mcp"),
        ),
        // A `"` char literal does not open a string.
        (
            r#"let q = '"'; if f == Frontend::Mcp {"#,
            (1, "== Frontend::Mcp"),
        ),
        // An escaped quote char literal does not open a string.
        (
            r#"let q = '\''; if f == Frontend::Mcp {"#,
            (1, "== Frontend::Mcp"),
        ),
        // A lifetime is not a char literal.
        (
            "fn f<'a>(x: &'a Frontend) -> bool { x == &Frontend::Mcp }",
            (1, "== &Frontend::Mcp"),
        ),
    ];
    for (input, (line, snippet)) in after {
        assert_eq!(
            deny_list_hits(input),
            vec![hit(*line, snippet)],
            "expected exactly one hit for {input:?}"
        );
    }

    // Two comparisons are two hits, in source order, each on its own line.
    assert_eq!(
        deny_list_hits("a == Frontend::Mcp\nb != CallerTrust::Agent"),
        vec![hit(1, "== Frontend::Mcp"), hit(2, "!= CallerTrust::Agent")]
    );
}

#[test]
fn no_deny_list_gate_in_any_crate_src() {
    let crates_dir = crates_dir();
    let mut offenders: Vec<String> = Vec::new();
    for path in rust_sources(&crates_dir) {
        if ALLOWED
            .iter()
            .any(|(suffix, _reason)| path.ends_with(suffix))
        {
            continue;
        }
        let src =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let shown = path.strip_prefix(&crates_dir).unwrap_or(&path);
        for (line, snippet) in deny_list_hits(&src) {
            offenders.push(format!("crates/{}:{line}: {snippet}", shown.display()));
        }
    }
    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "deny-list trust gate(s) found. A comparison against the agent role fails \
         open when a `Frontend` or `CallerTrust` variant is added, and the compiler \
         cannot catch it. Ask the one predicate instead: \
         `host.caller_is_trusted_control()` or `Frontend::is_trusted_control()`. \
         Offending sites:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn scan_is_not_vacuous() {
    let files = rust_sources(&crates_dir());
    assert!(
        files.len() >= 100,
        "the scan read only {} files; the crates path is wrong",
        files.len()
    );
    assert!(
        files.iter().any(|p| p.ends_with("aitm-mcp/src/server.rs")),
        "aitm-mcp/src/server.rs is not among the scanned files"
    );
    assert!(
        files.iter().any(|p| p.ends_with("aitm-core/src/ctx.rs")),
        "aitm-core/src/ctx.rs is not among the scanned files"
    );
}

/// `scan_is_not_vacuous` proves the walk reads top-level `src/*.rs`; this proves it
/// also reaches gate files that live in nested directories, so a walker that
/// stopped recursing could not shrink the scan to the top level and still pass.
#[test]
fn scan_reaches_nested_gate_files() {
    let files = rust_sources(&crates_dir());
    for nested in [
        "aitm-proto-l4/src/commands/agent.rs",
        "aitm/src/macos_capture/activation_gate.rs",
    ] {
        assert!(
            files.iter().any(|p| p.ends_with(nested)),
            "{nested} (a nested gate file) is not among the scanned files"
        );
    }
}

/// A throwaway `crates/` tree under the system temp dir, removed on drop.
struct FixtureTree(PathBuf);

impl FixtureTree {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aitm-trust-scan-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(&root).expect("create fixture root");
        Self(root)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().expect("fixture file has a parent"))
            .expect("create fixture dir");
        fs::write(&path, body).expect("write fixture file");
    }
}

impl Drop for FixtureTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The walker, over a fixture `crates/` tree: it descends into nested `src/`
/// directories, picks up only `*.rs`, and ignores `tests/`, `benches/`, a
/// Cargo.toml, a stray file directly under `crates/`, and a crate with no `src/`.
#[test]
fn rust_sources_walks_nested_src_only() {
    let tree = FixtureTree::new("walk");
    tree.write("a/src/lib.rs", "");
    tree.write("a/src/deep/er/x.rs", "");
    tree.write("a/src/notes.txt", "");
    tree.write("a/tests/t.rs", "");
    tree.write("a/benches/b.rs", "");
    tree.write("a/Cargo.toml", "");
    tree.write("b/src/y.rs", "");
    tree.write("c/README.md", "");
    tree.write("stray.rs", "");

    let rel: Vec<String> = rust_sources(&tree.0)
        .iter()
        .map(|p| {
            p.strip_prefix(&tree.0)
                .expect("under the fixture root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert_eq!(
        rel,
        vec![
            "a/src/deep/er/x.rs".to_string(),
            "a/src/lib.rs".to_string(),
            "b/src/y.rs".to_string()
        ]
    );
}

/// End to end on a fixture tree: a deny-list gate re-introduced in a nested `src/`
/// file is reported with its file and line, a migrated gate next to it is not, and
/// a deny-list shape that appears only under `tests/` is out of scope.
#[test]
fn a_reintroduced_deny_list_gate_is_found_with_file_and_line() {
    let tree = FixtureTree::new("probe");
    tree.write(
        "probe/src/deep/gate.rs",
        "fn migrated(h: &CommandHost) -> bool { !h.caller_is_trusted_control() }\n\
         \n\
         fn probe(h: &CommandHost) -> bool {\n    h.frontend() == Frontend::Mcp\n}\n",
    );
    tree.write(
        "probe/tests/not_scanned.rs",
        "fn t(h: &CommandHost) -> bool { h.frontend() == Frontend::Mcp }\n",
    );

    let mut found: Vec<(String, usize, String)> = Vec::new();
    for path in rust_sources(&tree.0) {
        let src = fs::read_to_string(&path).expect("read fixture source");
        let rel = path
            .strip_prefix(&tree.0)
            .expect("under the fixture root")
            .to_string_lossy()
            .replace('\\', "/");
        for (line, snippet) in deny_list_hits(&src) {
            found.push((rel.clone(), line, snippet));
        }
    }
    assert_eq!(
        found,
        vec![(
            "probe/src/deep/gate.rs".to_string(),
            4,
            "== Frontend::Mcp".to_string()
        )]
    );
}
