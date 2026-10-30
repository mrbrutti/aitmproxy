//! Comprehensive widget-lint (plan Task 20 / W11, acceptance AC14).
//!
//! Walks EVERY committed `crates/aitm-mcp/widgets/*.html` and enforces the
//! shared house style documented in `docs/superpowers/widget-convention.md`:
//! self-contained document, no unsafe DOM sinks, no inline event handlers, and
//! no literal hex colours outside the one generated token block. The files are
//! discovered at test time by reading the directory, so adding or removing a
//! widget keeps this gate honest without editing the test.

use std::fs;
use std::path::{Path, PathBuf};

/// Start marker of the generated token block (hex colours live only here).
const TOKEN_START: &str = "/* tokens (generated";
/// End marker of the generated token block.
const TOKEN_END: &str = "/* /tokens */";

/// Discover every `*.html` file under this crate's `widgets/` directory,
/// returned sorted by file name for deterministic failure messages.
fn widget_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("widgets");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read widgets dir {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("html"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no widget *.html files discovered under {}",
        dir.display()
    );
    files
}

/// Short display name (file name only) for failure messages.
fn name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Count non-overlapping occurrences of `needle` in `hay`.
fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

/// Find the first literal 6-digit hex colour (`#RRGGBB`) and its byte offset.
/// Equivalent to the regex `#[0-9a-fA-F]{6}`.
fn find_hex(s: &str) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    let is_hex = |b: u8| b.is_ascii_hexdigit();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && i + 7 <= bytes.len() {
            let hex = &bytes[i + 1..i + 7];
            if hex.iter().all(|&b| is_hex(b)) {
                return Some((i, format!("#{}", std::str::from_utf8(hex).unwrap())));
            }
        }
        i += 1;
    }
    None
}

/// Collect every literal 6-digit hex colour as `(byte_offset, text)`.
fn all_hex(s: &str) -> Vec<(usize, String)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && i + 7 <= bytes.len() {
            let hex = &bytes[i + 1..i + 7];
            if hex.iter().all(|&b| b.is_ascii_hexdigit()) {
                out.push((i, format!("#{}", std::str::from_utf8(hex).unwrap())));
                i += 7;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Find the first inline event-handler attribute (` on<name>=`, e.g.
/// ` onclick=`). Equivalent to the regex ` on[a-z]+=` (a leading space, the
/// literal `on`, one or more ASCII lowercase letters, then `=`).
fn find_inline_handler(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i + 3 < n {
        if bytes[i] == b' ' && bytes[i + 1] == b'o' && bytes[i + 2] == b'n' {
            let mut j = i + 3;
            while j < n && bytes[j].is_ascii_lowercase() {
                j += 1;
            }
            // require at least one letter after `on`, then `=`
            if j > i + 3 && j < n && bytes[j] == b'=' {
                return Some(std::str::from_utf8(&bytes[i + 1..j]).unwrap().to_string());
            }
        }
        i += 1;
    }
    None
}

/// AC14 #1: every widget starts with `<!DOCTYPE html>` and is non-empty.
#[test]
fn widgets_start_with_doctype_and_nonempty() {
    for path in widget_files() {
        let src = read(&path);
        assert!(!src.trim().is_empty(), "{} is empty", name(&path));
        assert!(
            src.starts_with("<!DOCTYPE html>"),
            "{} must start with `<!DOCTYPE html>` (found: {:?})",
            name(&path),
            &src[..src.len().min(20)]
        );
    }
}

/// AC14 #2: no unsafe DOM sinks, no `javascript:` URLs, no inline `on*=`
/// handler attributes. (Named in the plan: `no_unsafe_dom_in_widgets`.)
#[test]
fn no_unsafe_dom_in_widgets() {
    const BANNED: &[&str] = &[
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "javascript:",
    ];
    for path in widget_files() {
        let src = read(&path);
        for pat in BANNED {
            assert!(
                !src.contains(pat),
                "{} contains banned pattern `{}`",
                name(&path),
                pat
            );
        }
        if let Some(handler) = find_inline_handler(&src) {
            panic!(
                "{} contains an inline event-handler attribute `{}=` (use addEventListener)",
                name(&path),
                handler
            );
        }
    }
}

/// AC14 #3: no literal 6-digit hex colour appears OUTSIDE the generated token
/// block. (Named in the plan: `no_literal_hex_in_widgets`.)
#[test]
fn no_literal_hex_in_widgets() {
    for path in widget_files() {
        let src = read(&path);
        let start = src.find(TOKEN_START).unwrap_or_else(|| {
            panic!(
                "{} has no token-block start marker `{}`",
                name(&path),
                TOKEN_START
            )
        });
        let end = src.find(TOKEN_END).unwrap_or_else(|| {
            panic!(
                "{} has no token-block end marker `{}`",
                name(&path),
                TOKEN_END
            )
        });
        assert!(
            start < end,
            "{} token-block markers are out of order (start {start} >= end {end})",
            name(&path)
        );
        for (offset, hex) in all_hex(&src) {
            let inside = start <= offset && offset < end;
            assert!(
                inside,
                "{} contains literal hex colour `{}` at byte {} OUTSIDE the generated token block \
                 (use var(--color-…))",
                name(&path),
                hex,
                offset
            );
        }
    }
}

/// AC14 #4: exactly one `<style>` and exactly one classic `<script>` element.
/// The house style uses a classic `<script>` (no `type="module"`).
#[test]
fn exactly_one_style_and_one_script() {
    for path in widget_files() {
        let src = read(&path);
        let styles = count(&src, "<style");
        let scripts = count(&src, "<script");
        assert_eq!(
            styles,
            1,
            "{} must have exactly one <style> element, found {}",
            name(&path),
            styles
        );
        assert_eq!(
            scripts,
            1,
            "{} must have exactly one <script> element, found {}",
            name(&path),
            scripts
        );
    }
}

/// AC14 #5: every widget inlines the tokens — it contains both the token-block
/// start and end markers.
#[test]
fn widgets_inline_token_block() {
    for path in widget_files() {
        let src = read(&path);
        assert!(
            src.contains(TOKEN_START),
            "{} is missing the token-block start marker `{}`",
            name(&path),
            TOKEN_START
        );
        assert!(
            src.contains(TOKEN_END),
            "{} is missing the token-block end marker `{}`",
            name(&path),
            TOKEN_END
        );
    }
}

/// Guard: `find_hex` is self-consistent (a minimal smoke so a deleted body is a
/// failing test, not a silent pass).
#[test]
fn hex_scanner_detects_a_colour() {
    assert_eq!(find_hex("x: #Ab12Cd;"), Some((3, "#Ab12Cd".to_string())));
    assert_eq!(find_hex("no colour here #zzz"), None);
}
