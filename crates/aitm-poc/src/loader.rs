//! Shared, hardened filesystem loading for PoCs and their artifacts.
//!
//! `poc.run`, `poc.get`, `poc.list` and `poc.artifact` all read files that a
//! remote caller names, so the read must resist symlink and traversal tricks and
//! must not become a file-existence oracle. One implementation lives here and both
//! the runner and the library commands call it — the security-sensitive path is
//! written once.

use std::path::Path;

use crate::model::Poc;

/// Max bytes for a PoC document (a billion-laughs / huge-document guard).
pub const MAX_POC_BYTES: u64 = 1024 * 1024;

/// A confinement failure. Deliberately one message for every cause (missing,
/// outside the root, not a regular file, too large) so the command cannot be used
/// to probe for files outside the permitted directory.
#[derive(Debug)]
pub struct ConfinedError;

impl std::fmt::Display for ConfinedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not found or outside the configured PoC directory")
    }
}

impl std::error::Error for ConfinedError {}

/// Open read-only, not following a symlink at the final component (`O_NOFOLLOW`)
/// and non-blocking (`O_NONBLOCK`, so opening a FIFO cannot hang the reader).
#[cfg(unix)]
fn open_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to open a symlink",
        ));
    }
    std::fs::File::open(path)
}

/// Read a regular file capped at `max` bytes: open hardened, require a regular
/// file, and read via `take(max + 1)` so an oversize file is rejected without
/// buffering the whole thing.
pub fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = open_hardened(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut buf = Vec::new();
    file.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds the size cap",
        ));
    }
    Ok(buf)
}

/// Read `path`, requiring it to resolve (canonicalized, so `..` and symlinks are
/// followed) under `root`. When `allowed_exts` is non-empty, the **canonical**
/// path's extension must be one of them — so a `foo.png` symlink pointing at a
/// `bar.pem` is rejected, not just one named `.pem`. Every failure collapses to
/// one [`ConfinedError`] (no file-existence oracle).
pub fn read_confined(
    path: &Path,
    root: &Path,
    max: u64,
    allowed_exts: &[&str],
) -> Result<Vec<u8>, ConfinedError> {
    let within = || -> Option<Vec<u8>> {
        let canon_root = root.canonicalize().ok()?;
        let canon_path = path.canonicalize().ok()?;
        if !canon_path.starts_with(&canon_root) {
            return None;
        }
        if !allowed_exts.is_empty() {
            let ext = canon_path.extension().and_then(|e| e.to_str());
            if !ext.is_some_and(|e| allowed_exts.contains(&e)) {
                return None;
            }
        }
        // The canonical path has no symlink final component, so the hardened read
        // is a pure confinement + size check.
        read_capped(&canon_path, max).ok()
    };
    within().ok_or(ConfinedError)
}

/// Parse and validate a PoC document, without echoing the offending content.
pub fn parse_poc(text: &str) -> anyhow::Result<Poc> {
    // The byte cap bounds the *source*, but `serde_yaml` expands aliases while
    // parsing, so a kilobyte of `&a`/`*a` references can materialize gigabytes
    // (a "billion laughs" bomb) before any size check downstream could help.
    // Reject anchors/aliases up front, before `from_str` ever expands them.
    if contains_anchor_or_alias(text) {
        anyhow::bail!("PoC uses YAML anchors/aliases, which are not allowed");
    }
    let raw: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|_| anyhow::anyhow!("not valid YAML"))?;
    crate::schema::validate(&raw).map_err(|e| anyhow::anyhow!("failed validation: {e}"))?;
    serde_yaml::from_value(raw).map_err(|_| anyhow::anyhow!("not a valid PoC document"))
}

/// Whether `text` contains a YAML anchor (`&name`) or alias (`*name`) indicator.
///
/// It scans outside of quoted scalars and comments, and only treats `&`/`*` as an
/// indicator when it opens a token (start of line, or after whitespace or a flow
/// indicator) and is followed by a name character. That keeps a legitimate `&` in
/// an unquoted URL (`?a=1&b=2`) or a `*` in a regex from being misread as YAML.
fn contains_anchor_or_alias(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    // `prev` is the last meaningful byte; start-of-input counts as a line start.
    let mut prev = b'\n';
    let mut in_squote = false;
    let mut in_dquote = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let c = bytes[i];
        if in_comment {
            if c == b'\n' {
                in_comment = false;
                prev = b'\n';
            }
            i += 1;
            continue;
        }
        if in_squote {
            if c == b'\'' {
                in_squote = false;
            }
            i += 1;
            continue;
        }
        if in_dquote {
            if c == b'\\' {
                i += 2; // skip an escaped character (e.g. `\"`)
                continue;
            }
            if c == b'"' {
                in_dquote = false;
            }
            i += 1;
            continue;
        }

        let at_token_start = matches!(
            prev,
            b'\n' | b' ' | b'\t' | b':' | b',' | b'-' | b'[' | b'{'
        );
        match c {
            b'\'' => in_squote = true,
            b'"' => in_dquote = true,
            b'#' if matches!(prev, b'\n' | b' ' | b'\t') => in_comment = true,
            b'&' | b'*' if at_token_start => {
                let name = bytes
                    .get(i + 1)
                    .is_some_and(|&n| n.is_ascii_alphanumeric() || n == b'_' || n == b'-');
                if name {
                    return true;
                }
            }
            _ => {}
        }
        prev = match c {
            b'\t' | b'\r' => b' ',
            other => other,
        };
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "id: demo\ninfo:\n  name: n\n  severity: low\n";

    /// I5: a small alias bomb is rejected before `serde_yaml` can expand it.
    #[test]
    fn alias_bomb_rejected() {
        let bomb = format!(
            "{HEADER}steps: []\nsuccess:\n  type: status\n  status: 200\n\
             a: &a [\"x\",\"x\",\"x\",\"x\"]\nb: &b [*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n"
        );
        let err = parse_poc(&bomb).expect_err("an alias bomb must be rejected");
        assert!(
            err.to_string().contains("anchors/aliases"),
            "want an anchor/alias refusal, got: {err}"
        );
    }

    /// A normal PoC — whose values legitimately contain `&` (a URL query) and `*`
    /// (a regex) — is not misread as using anchors/aliases, and parses.
    #[test]
    fn ampersand_and_star_in_values_parse() {
        let yaml = format!(
            "{HEADER}steps:\n  - http:\n      method: GET\n      url: \"http://x.test/?a=1&b=2\"\n\
             success:\n  - type: regex\n    regex: \"a*b\"\n"
        );
        assert!(
            !contains_anchor_or_alias(&yaml),
            "`&`/`*` inside quoted scalars must not be read as YAML indicators"
        );
        parse_poc(&yaml).expect("a plain PoC with `&`/`*` in values must parse");
    }
}
