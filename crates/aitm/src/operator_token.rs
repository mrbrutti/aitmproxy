//! `aitm operator-token generate [--force]` (spec Decision F / F2): turn on
//! operator access by writing a CSPRNG `mcp.operator_token` into the config file
//! without the secret ever reaching the terminal or a log.
//!
//! The edit is **surgical**: [`insert_operator_token`] is a pure text transform
//! that inserts or replaces only the `operator_token` value, creating the `mcp:`
//! block if absent and leaving every other key, comment and line ending intact.
//! It is deliberately *not* a serde round-trip, which would drop comments and
//! reflow the document. A config whose `mcp:` section is written as an inline
//! flow mapping (`mcp: {…}`) is refused rather than corrupted. The command is
//! CLI-only and never registered as an MCP/registry tool, so no agent can write
//! the operator secret (the no-self-promotion anti-goal).

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Why writing `mcp.operator_token` could not proceed.
#[derive(Debug)]
pub enum OperatorTokenError {
    /// A non-empty `operator_token` already exists and `--force` was not given;
    /// the file is left unchanged so an existing operator is never locked out.
    AlreadySet,
    /// The resolved config file does not exist. The operator must create a
    /// config before operator access can be enabled.
    NoConfigFile(PathBuf),
    /// The `mcp:` section is an inline flow mapping (`mcp: {…}`) or a scalar; the
    /// surgical editor will not rewrite it. Rewrite it as a block mapping first.
    InlineMcpSection,
}

impl fmt::Display for OperatorTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperatorTokenError::AlreadySet => write!(
                f,
                "operator_token is already set; refusing to overwrite it. Re-run with \
                 `--force` to rotate it (this invalidates the current operator token)."
            ),
            OperatorTokenError::NoConfigFile(path) => write!(
                f,
                "config file {} does not exist; create a config before enabling operator access",
                path.display()
            ),
            OperatorTokenError::InlineMcpSection => write!(
                f,
                "the `mcp:` section is written inline (`mcp: {{…}}`); rewrite it as a block \
                 mapping before running `operator-token generate`"
            ),
        }
    }
}

impl std::error::Error for OperatorTokenError {}

/// Return the config text with `mcp.operator_token` set to `token`, preserving
/// every other byte, comment and line ending. Creates an `mcp:` block when the
/// file has none. Returns [`OperatorTokenError::AlreadySet`] when a non-empty
/// `operator_token` already exists and `!force`, and
/// [`OperatorTokenError::InlineMcpSection`] when `mcp:` is an inline mapping.
///
/// Pure: no I/O, no randomness. `token` is written verbatim and unquoted, so the
/// caller is responsible for supplying a value with no YAML-special characters
/// (the generated CSPRNG token is hex).
pub fn insert_operator_token(
    yaml: &str,
    token: &str,
    force: bool,
) -> Result<String, OperatorTokenError> {
    let crlf = yaml.contains("\r\n");
    let mut lines: Vec<String> = yaml.split('\n').map(str::to_string).collect();

    // Locate the top-level `mcp:` key, refusing an inline mapping/scalar.
    let mut mcp_idx = None;
    for (idx, line) in lines.iter().enumerate() {
        let lg = logical(line);
        if !indent_of(lg).is_empty() {
            continue; // not a top-level key
        }
        if let Some(rest) = lg.trim_start().strip_prefix("mcp:") {
            let rest = rest.trim_start();
            if !rest.is_empty() && !rest.starts_with('#') {
                return Err(OperatorTokenError::InlineMcpSection);
            }
            mcp_idx = Some(idx);
            break;
        }
    }

    let Some(mcp_idx) = mcp_idx else {
        // No `mcp:` block: append one with the token as its only child.
        append_mcp_block(&mut lines, token, crlf);
        return Ok(lines.join("\n"));
    };

    // Scan the block's direct children for an existing `operator_token` and for
    // the indentation its children use. Comments never end the block.
    let mcp_indent_len = indent_of(logical(&lines[mcp_idx])).len();
    let mut child_indent: Option<String> = None;
    let mut existing_ot: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate().skip(mcp_idx + 1) {
        let lg = logical(line);
        let trimmed = lg.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent_of(lg).len() <= mcp_indent_len {
            break; // dedent to the mcp level or beyond: block ended
        }
        if child_indent.is_none() {
            child_indent = Some(indent_of(lg).to_string());
        }
        if trimmed.starts_with("operator_token:") {
            existing_ot = Some(idx);
            break;
        }
    }

    if let Some(idx) = existing_ot {
        let lg = logical(&lines[idx]);
        let indent = indent_of(lg).to_string();
        let after = lg[indent.len()..]
            .strip_prefix("operator_token:")
            .unwrap_or("");
        if !force && !value_is_empty(after) {
            return Err(OperatorTokenError::AlreadySet);
        }
        // Preserve any inline comment on the value line.
        let comment = after.find(" #").map(|p| &after[p..]).unwrap_or("");
        let content = format!("{indent}operator_token: {token}{comment}");
        lines[idx] = raw(content, crlf);
    } else {
        let indent =
            child_indent.unwrap_or_else(|| format!("{:width$}", "", width = mcp_indent_len + 2));
        let content = format!("{indent}operator_token: {token}");
        lines.insert(mcp_idx + 1, raw(content, crlf));
    }

    Ok(lines.join("\n"))
}

/// Read `config_path`, write a freshly generated CSPRNG `mcp.operator_token`
/// into it via [`insert_operator_token`], and return the path written. Errors if
/// the file is absent ([`OperatorTokenError::NoConfigFile`]) or already carries a
/// token without `force`.
pub fn generate_and_store(config_path: &Path, force: bool) -> anyhow::Result<PathBuf> {
    let yaml = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OperatorTokenError::NoConfigFile(config_path.to_path_buf()).into());
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading config file {}", config_path.display()));
        }
    };
    let token = generate_operator_token();
    let updated = insert_operator_token(&yaml, &token, force)?;
    std::fs::write(config_path, updated)
        .with_context(|| format!("writing config file {}", config_path.display()))?;
    Ok(config_path.to_path_buf())
}

/// The non-sensitive confirmation printed after a successful write. It names the
/// config path and that operator access is enabled, and reminds the operator to
/// restart; it never contains the token (it is not even given one).
pub fn confirmation_message(path: &Path) -> String {
    format!(
        "operator access enabled: wrote mcp.operator_token to {}\n\
         restart the proxy (and any `aitm web`/`aitm-tui --bus`/mac session) for it to take effect.",
        path.display()
    )
}

/// A fresh operator token from the platform CSPRNG. `uuid::Uuid::new_v4` draws
/// from the OS CSPRNG (the same source `aitm_mcp` uses for confirm tokens); two
/// concatenated give a 256-bit, 64-hex-character secret with no YAML-special
/// characters, so it is safe to write unquoted.
fn generate_operator_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Append a fresh `mcp:` block carrying only `operator_token` to `lines`,
/// ensuring the file ends with a newline.
fn append_mcp_block(lines: &mut Vec<String>, token: &str, crlf: bool) {
    let block = [
        raw("mcp:".to_string(), crlf),
        raw(format!("  operator_token: {token}"), crlf),
    ];
    if lines.last().is_some_and(String::is_empty) {
        // The file ends with a newline (trailing empty split element); insert the
        // block before it so the final newline is preserved.
        let at = lines.len() - 1;
        for (i, line) in block.into_iter().enumerate() {
            lines.insert(at + i, line);
        }
    } else {
        lines.extend(block);
        lines.push(String::new()); // final newline
    }
}

/// The line without its trailing `\r`, so CRLF and LF files inspect the same.
fn logical(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// The leading-whitespace string of a (logical) line; reused verbatim so tabs
/// and space widths survive.
fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// Re-attach the line ending style: new lines in a CRLF file carry a `\r` so the
/// `"\n"` join reproduces `\r\n`.
fn raw(content: String, crlf: bool) -> String {
    if crlf {
        let mut c = content;
        c.push('\r');
        c
    } else {
        content
    }
}

/// Whether the text following `operator_token:` is an empty value (absent, `""`,
/// or `''`), which the role model treats as "not configured".
fn value_is_empty(after: &str) -> bool {
    let v = match after.find(" #") {
        Some(p) => &after[..p],
        None => after,
    };
    let v = v.trim();
    v.is_empty() || v == "\"\"" || v == "''"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_file;

    #[test]
    fn inserts_into_existing_mcp_block() {
        let input = "listen: 127.0.0.1:8080\n\
                     mcp:\n  \
                     transport:\n    \
                     loopback_tcp:\n      \
                     port: 9090\n      \
                     token: abc\n";
        let out = insert_operator_token(input, "abc123", false).unwrap();
        let cfg = config_file::parse(&out).unwrap();
        assert_eq!(cfg.mcp.operator_token.as_deref(), Some("abc123"));
        assert!(
            out.contains("listen: 127.0.0.1:8080"),
            "unrelated top-level key dropped:\n{out}"
        );
        assert!(
            out.contains("port: 9090"),
            "transport block dropped:\n{out}"
        );
    }

    #[test]
    fn creates_mcp_block_when_absent() {
        let input = "listen: 127.0.0.1:8080\n";
        let out = insert_operator_token(input, "abc123", false).unwrap();
        let cfg = config_file::parse(&out).unwrap();
        assert_eq!(cfg.mcp.operator_token.as_deref(), Some("abc123"));
        assert!(out.contains("listen: 127.0.0.1:8080"));
    }

    #[test]
    fn refuses_existing_without_force() {
        let input = "mcp:\n  operator_token: oldsecret\n";
        let err = insert_operator_token(input, "new999", false).unwrap_err();
        assert!(matches!(err, OperatorTokenError::AlreadySet));
    }

    #[test]
    fn force_replaces_existing() {
        let input = "mcp:\n  operator_token: oldsecret\n";
        let out = insert_operator_token(input, "new999", true).unwrap();
        let cfg = config_file::parse(&out).unwrap();
        assert_eq!(cfg.mcp.operator_token.as_deref(), Some("new999"));
        assert!(!out.contains("oldsecret"), "old token not replaced:\n{out}");
    }

    #[test]
    fn empty_existing_token_is_replaced_without_force() {
        // An empty `operator_token` means "not configured", so writing over it
        // needs no --force (Review Focus: hand-edited empty value).
        let input = "mcp:\n  operator_token: \"\"\n";
        let out = insert_operator_token(input, "abc123", false).unwrap();
        let cfg = config_file::parse(&out).unwrap();
        assert_eq!(cfg.mcp.operator_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn preserves_crlf_and_comments() {
        let input = "# top comment\r\n\
                     mcp:\r\n  \
                     transport:\r\n    \
                     loopback_tcp:\r\n      \
                     port: 9090\r\n      \
                     token: abc\r\n\
                     # trailing comment\r\n";
        let out = insert_operator_token(input, "abc123", false).unwrap();
        assert!(
            out.contains("# trailing comment"),
            "comment dropped:\n{out:?}"
        );
        assert!(out.contains("\r\n"), "CRLF endings lost:\n{out:?}");
        assert!(
            out.contains("  operator_token: abc123\r\n"),
            "inserted line is not CRLF:\n{out:?}"
        );
        let cfg = config_file::parse(&out).unwrap();
        assert_eq!(cfg.mcp.operator_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn refuses_inline_mcp_mapping() {
        // Review Focus: an inline `mcp: {…}` must refuse, not corrupt the file.
        let input = "mcp: {operator_token: x}\n";
        let err = insert_operator_token(input, "abc123", true).unwrap_err();
        assert!(matches!(err, OperatorTokenError::InlineMcpSection));
    }

    #[test]
    fn confirmation_names_the_path_and_never_the_token() {
        let path = Path::new("/etc/aitmproxy/config.yaml");
        let msg = confirmation_message(path);
        assert!(msg.contains("/etc/aitmproxy/config.yaml"));
        assert!(
            !msg.contains("deadbeefdeadbeef"),
            "confirmation must not echo a token"
        );
        assert!(msg.to_lowercase().contains("restart"));
    }

    #[test]
    fn generated_token_is_nonempty_and_hex() {
        let token = generate_operator_token();
        assert!(!token.is_empty());
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
