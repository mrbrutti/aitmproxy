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
//!
//! Since the one-shot spec (§D3) a serving first run also mints the token
//! automatically through [`mint_if_absent`]: the same surgical editor, the same
//! atomic write, the result always `0600`, and never fatal (a failure is a
//! [`Minted::Skipped`] that turns the operator bus off for the run). The minted
//! value travels as an [`OperatorToken`], whose `Debug` redacts and which has no
//! `Display`, so it cannot reach a log, phase line or error string by accident.

use std::fmt;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
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
        // Only a DIRECT child of `mcp:` is the mcp-level `operator_token`: its
        // indent must equal the block's child indent. A deeper `operator_token:`
        // (e.g. under `mcp.transport`) is a different key and is left untouched.
        let is_direct_child = child_indent.as_deref().map(str::len) == Some(indent_of(lg).len());
        if is_direct_child && trimmed.starts_with("operator_token:") {
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
    write_atomically(config_path, &updated)
        .with_context(|| format!("writing config file {}", config_path.display()))?;
    Ok(config_path.to_path_buf())
}

/// The operator token a serving first run minted (spec §D3). `Debug` prints
/// `OperatorToken(<redacted>)` and there is deliberately no `Display`, so the
/// value cannot reach a log record, a phase line or an error string by accident
/// (AC-R14-28/29); the one way to read it is [`OperatorToken::expose`].
pub struct OperatorToken(String);

impl OperatorToken {
    /// The token value, for the single consumer that stores it in
    /// `cfg.mcp.operator_token`. Never format, log or print the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperatorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorToken(<redacted>)")
    }
}

/// What [`mint_if_absent`] did. Never an error: minting is best-effort and a
/// failure only turns the operator bus off for this run (plan C4).
#[derive(Debug)]
pub enum Minted {
    /// The file already carries a non-empty `mcp.operator_token`; nothing was
    /// written.
    Present,
    /// A fresh token was inserted and the file written `0600`.
    Written {
        /// The config file that now holds the token.
        path: PathBuf,
        /// The minted token, for `cfg.mcp.operator_token`.
        token: OperatorToken,
    },
    /// The token could not be minted. `reason` is the operator-facing tail of
    /// the warning (`… could not write mcp.operator_token to <path> · <reason>`)
    /// and never contains a token.
    Skipped {
        /// Why, in the spec's words (e.g. `<path> does not exist`,
        /// `<path> is not a regular file`, `the mcp: section is written inline`,
        /// `cannot write <path>: <io error>`).
        reason: String,
    },
}

/// Mint `mcp.operator_token` into the config at `path` when it has none.
///
/// Returns [`Minted::Present`] when the file already has a non-empty token,
/// [`Minted::Written`] after inserting a fresh CSPRNG token with
/// [`insert_operator_token`] (every other byte kept) and writing the file
/// through [`write_atomically`] (so it is `0600` afterwards whatever it was
/// before), and [`Minted::Skipped`] otherwise: a missing file when
/// `create_if_missing` is false (an explicit `--config` is never created), a
/// symlink at the path (a dotfile-managed config is never written through or
/// replaced by an automatic first-run write; reading a token elsewhere still
/// follows symlinks), a non-regular file at the path, an inline `mcp: {…}`
/// section, or an unreadable/unwritable file or directory. With
/// `create_if_missing` an absent file starts from empty text and its parent
/// directory is created `0700` if absent. Never fatal; never returns the token
/// in a `reason`.
pub fn mint_if_absent(path: &Path, create_if_missing: bool) -> Minted {
    let skipped = |reason: String| Minted::Skipped { reason };
    if std::fs::symlink_metadata(path).is_ok_and(|md| md.file_type().is_symlink()) {
        return skipped(format!(
            "{} is a symlink: aitm does not write a token through it; add \
             mcp.operator_token yourself or set mcp.operator_bus.enabled: false",
            path.display()
        ));
    }
    let yaml = match std::fs::metadata(path) {
        Ok(md) if !md.is_file() => {
            return skipped(format!("{} is not a regular file", path.display()));
        }
        Ok(_) => match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => return skipped(format!("cannot read {}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create_if_missing {
                return skipped(format!("{} does not exist", path.display()));
            }
            if let Err(e) = create_private_parent(path) {
                return skipped(format!("cannot write {}: {e}", path.display()));
            }
            String::new()
        }
        Err(e) => return skipped(format!("cannot read {}: {e}", path.display())),
    };

    let token = generate_operator_token();
    let updated = match insert_operator_token(&yaml, &token, false) {
        Ok(text) => text,
        Err(OperatorTokenError::AlreadySet) => return Minted::Present,
        Err(OperatorTokenError::InlineMcpSection) => {
            return skipped("the mcp: section is written inline".to_string());
        }
        Err(e @ OperatorTokenError::NoConfigFile(_)) => return skipped(e.to_string()),
    };

    match write_atomically(path, &updated) {
        Ok(()) => Minted::Written {
            path: path.to_path_buf(),
            token: OperatorToken(token),
        },
        Err(e) => skipped(format!("cannot write {}: {e}", path.display())),
    }
}

/// Create `path`'s parent directory with mode `0700` when it does not exist
/// yet. An existing parent is left exactly as the operator has it.
fn create_private_parent(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    if parent.symlink_metadata().is_ok() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
}

/// Replace `path`'s contents with `data` via a sibling temp file and an atomic
/// `rename`, so a crash or full disk can never truncate the operator's config to
/// an empty or half-written file. The rename also replaces the target in place
/// without following a symlink into another inode. Both files share `path`'s
/// parent directory, so the rename stays within one filesystem (where it is
/// atomic). The temp file is removed if the write or the rename fails.
///
/// The temp file is created `0600` (`create_new` so no existing inode is
/// reused, then an explicit `set_permissions` so the umask cannot widen or
/// narrow it), so the renamed result is `0600` whatever the umask and whatever
/// mode the old file had (spec §D3, research F7).
///
/// Durability (security S4; §D3 runs this on every first start): the temp
/// file is `sync_all`ed before the rename, so its bytes are on disk before
/// the name points at them and a crash right after the rename cannot leave
/// a complete-looking empty config (the rename-after-write hazard of
/// delayed-allocation filesystems); an fsync failure there is an error and
/// the temp file is removed. After the rename the parent directory is
/// `sync_all`ed so the new name itself is durable; a filesystem that refuses
/// a directory fsync costs one `debug!`, not the write. So what holds when
/// this returns `Ok`: the file is either the old config or the complete new
/// one, never a torn one; that it is the new one after a crash is guaranteed
/// only when the directory fsync succeeded, otherwise from the filesystem's
/// next journal flush.
fn write_atomically(path: &Path, data: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{stem}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = file
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(data.as_bytes()))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        tracing::debug!(
            path = %dir.display(),
            error = %e,
            "could not fsync the config's directory after the rename; the new name is durable at the next journal flush"
        );
    }
    Ok(())
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
/// concatenated give a 64-hex-character secret carrying ~244 bits of entropy
/// (each v4 UUID fixes 6 of its 128 bits as version/variant, so ~122 bits
/// each). It has no YAML-special characters, so it is safe to write unquoted.
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
    use std::os::unix::fs::PermissionsExt;

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
    fn nested_operator_token_is_not_treated_as_the_mcp_key() {
        // A deeper `operator_token:` (here indented under `mcp.transport`) is NOT
        // a direct child of `mcp:`, so it must be left intact and a fresh
        // mcp-level `operator_token` inserted directly under `mcp:`.
        let input = "mcp:\n  transport:\n    operator_token: nested\n";
        let out = insert_operator_token(input, "abc123", false).unwrap();
        assert!(
            out.contains("    operator_token: nested"),
            "nested key was rewritten:\n{out}"
        );
        assert!(
            out.contains("\n  operator_token: abc123"),
            "mcp-level token not inserted as a direct child:\n{out}"
        );
    }

    #[test]
    fn generate_and_store_writes_the_token_and_keeps_other_keys() {
        let dir =
            std::env::temp_dir().join(format!("aitm-optok-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "listen: 127.0.0.1:8080\nmcp:\n  transport:\n    loopback_tcp:\n      port: 9090\n      token: abc\n",
        )
        .unwrap();
        // The file starts world-readable so the assertion below proves the atomic
        // write tightens it to 0600 rather than inheriting the old mode or the
        // umask (spec D3, research F7).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        generate_and_store(&path, false).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config must be 0600 after the write, got {mode:o}"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        let cfg = config_file::parse(&text).unwrap();
        let tok = cfg
            .mcp
            .operator_token
            .as_deref()
            .expect("operator token written");
        assert_eq!(tok.len(), 64, "token is 64 hex chars: {tok}");
        assert!(
            tok.chars().all(|c| c.is_ascii_hexdigit()),
            "token is hex: {tok}"
        );
        assert!(
            text.contains("listen: 127.0.0.1:8080") && text.contains("port: 9090"),
            "unrelated keys dropped:\n{text}"
        );
        // The atomic rename leaves no temp sibling behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name() != "config.yaml")
            .map(|e| e.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp sibling left behind: {leftovers:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generated_token_is_nonempty_and_hex() {
        let token = generate_operator_token();
        assert!(!token.is_empty());
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// A fresh, unique temp directory for one minting test.
    fn mint_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aitm-mint-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Assert `text` is exactly `prefix` + 64 hex chars + `"\n"` and return the
    /// 64-char token it carries.
    fn token_line_after(text: &str, prefix: &str) -> String {
        let rest = text
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("text does not start with {prefix:?}:\n{text}"));
        let tok = rest
            .strip_suffix('\n')
            .unwrap_or_else(|| panic!("text does not end with a newline:\n{text}"));
        assert_eq!(
            tok.len(),
            64,
            "token is 64 hex chars, got {}:\n{text}",
            tok.len()
        );
        assert!(
            tok.chars().all(|c| c.is_ascii_hexdigit()),
            "token is not hex:\n{text}"
        );
        tok.to_string()
    }

    /// S4 (security pass 1): `write_atomically` fsyncs the temp file before
    /// the rename and the parent directory after it. A directory the process
    /// cannot open for that fsync (`0300`: it may create and rename inside it
    /// but not read it) costs one `debug!`, never the write: the file lands
    /// `0600` with the exact bytes and no temp sibling remains.
    #[test]
    fn write_atomically_tolerates_a_directory_it_cannot_fsync() {
        let dir = mint_dir();
        let path = dir.join("config.yaml");
        let data = "mcp:\n  operator_token: not-a-real-token\n";
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
        let dir_opens = std::fs::File::open(&dir).is_ok();
        let result = write_atomically(&path, data);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !dir_opens,
            "premise: a 0300 directory cannot be opened for fsync (not running as root)"
        );
        result.expect("a directory fsync failure is tolerated");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), data);
        assert_eq!(mode_of(&path), 0o600);
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["config.yaml".to_string()],
            "no temp sibling remains"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mint_creates_the_default_file_0600_with_one_token_line() {
        // AC-R14-3: the default config does not exist (nor its parent); the
        // first serving run creates both, the file 0600 and the parent 0700,
        // with exactly one token line; a second run changes nothing.
        let dir = mint_dir();
        let parent = dir.join("aitmproxy");
        let p = parent.join("config.yaml");
        assert!(!parent.exists());

        let first = mint_if_absent(&p, true);
        let token = match first {
            Minted::Written { path, token } => {
                assert_eq!(path, p);
                token
            }
            other => panic!("expected Written, got {other:?}"),
        };
        assert_eq!(mode_of(&p), 0o600, "file mode {:o}", mode_of(&p));
        assert_eq!(
            mode_of(&parent),
            0o700,
            "parent mode {:o}",
            mode_of(&parent)
        );
        let text = std::fs::read_to_string(&p).unwrap();
        let in_file = token_line_after(&text, "mcp:\n  operator_token: ");
        assert_eq!(
            token.expose(),
            in_file,
            "returned token differs from the file's"
        );
        // Exactly one operator_token line.
        assert_eq!(text.matches("operator_token:").count(), 1);

        let second = mint_if_absent(&p, true);
        assert!(matches!(second, Minted::Present), "second call: {second:?}");
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            text,
            "bytes changed on a Present run"
        );
        assert_eq!(mode_of(&p), 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_inserts_into_an_existing_0644_file_and_tightens_it() {
        // AC-R14-4: a pre-existing config gains exactly the one line, every
        // other byte unchanged, and ends up 0600 even though it was 0644.
        let dir = mint_dir();
        let p = dir.join("config.yaml");
        let before = "# c\nlisten: 127.0.0.1:8080\n";
        std::fs::write(&p, before).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&p), 0o644);

        let minted = mint_if_absent(&p, false);
        let token = match minted {
            Minted::Written { path, token } => {
                assert_eq!(path, p);
                token
            }
            other => panic!("expected Written, got {other:?}"),
        };
        assert_eq!(mode_of(&p), 0o600, "file mode {:o}", mode_of(&p));
        let text = std::fs::read_to_string(&p).unwrap();
        let in_file = token_line_after(
            &text,
            "# c\nlisten: 127.0.0.1:8080\nmcp:\n  operator_token: ",
        );
        assert_eq!(token.expose(), in_file);
        assert_eq!(
            text,
            format!("# c\nlisten: 127.0.0.1:8080\nmcp:\n  operator_token: {in_file}\n")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_skips_without_creating_when_told_not_to() {
        // An explicit --config that names a missing file is never created by
        // minting (spec D3: a mistyped path stays the config error).
        let dir = mint_dir();
        let p = dir.join("missing.yaml");

        let minted = mint_if_absent(&p, false);
        match minted {
            Minted::Skipped { reason } => {
                assert_eq!(reason, format!("{} does not exist", p.display()));
                assert!(reason.ends_with("does not exist"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(
            !p.exists(),
            "file was created despite create_if_missing = false"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_skips_an_inline_mcp_section() {
        // Plan C4: the surgical editor's InlineMcpSection becomes a Skipped
        // with the spec's words; the file is left byte-for-byte alone.
        let dir = mint_dir();
        let p = dir.join("config.yaml");
        let before = "mcp: {operator_token: \"\"}\n";
        std::fs::write(&p, before).unwrap();

        let minted = mint_if_absent(&p, false);
        match minted {
            Minted::Skipped { reason } => {
                assert_eq!(reason, "the mcp: section is written inline");
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&p).unwrap(), before);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_skips_a_directory_at_the_path() {
        // A non-regular file at the config path is refused with the spec's
        // words and nothing is written into or over it.
        let dir = mint_dir();
        let p = dir.join("config.yaml");
        std::fs::create_dir(&p).unwrap();

        let minted = mint_if_absent(&p, true);
        match minted {
            Minted::Skipped { reason } => {
                assert_eq!(reason, format!("{} is not a regular file", p.display()));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(p.is_dir(), "the directory was replaced");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_skips_a_symlinked_config() {
        // A dotfile-managed config (a symlink) is never minted into: replacing
        // the link would break it and writing through it could put a secret
        // into a git-tracked repo. The link and its target are left untouched.
        let dir = mint_dir();
        let target = dir.join("target.yaml");
        let before = "listen: 127.0.0.1:8080\n";
        std::fs::write(&target, before).unwrap();
        let link = dir.join("config.yaml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let minted = mint_if_absent(&link, true);
        match minted {
            Minted::Skipped { reason } => {
                assert_eq!(
                    reason,
                    format!(
                        "{} is a symlink: aitm does not write a token through it; add \
                         mcp.operator_token yourself or set mcp.operator_bus.enabled: false",
                        link.display()
                    )
                );
                assert!(reason.contains("is a symlink"), "{reason}");
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink was replaced"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), before);
        assert_eq!(std::fs::read_to_string(&link).unwrap(), before);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn minted_debug_never_prints_the_token() {
        // AC-R14-29: the token wrapper redacts in Debug; the enum inherits it.
        let token = OperatorToken("optoken-test-abc".into());
        assert_eq!(format!("{token:?}"), "OperatorToken(<redacted>)");
        assert_eq!(token.expose(), "optoken-test-abc");

        let minted = Minted::Written {
            path: PathBuf::from("/tmp/x/config.yaml"),
            token,
        };
        let dbg = format!("{minted:?}");
        assert!(dbg.contains("<redacted>"), "no redaction marker: {dbg}");
        assert!(!dbg.contains("optoken-test-abc"), "token leaked: {dbg}");
        assert!(dbg.contains("/tmp/x/config.yaml"), "path missing: {dbg}");
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// The env var the umask re-exec child reads: the directory to mint into.
    const UMASK_CHILD_ENV: &str = "AITM_TESTER_UMASK_CHILD_DIR";

    /// Tester — AC-R14-3/4, research F7: `write_atomically` creates `0600`
    /// whatever the umask. The umask is process-global and `libc::umask`
    /// needs `unsafe` (forbidden), so this test re-executes the test binary
    /// under `sh -c 'umask <m>; exec …'` for a permissive (`000`), a
    /// restrictive (`077`) and a middling (`027`) mask. The child mints into a
    /// fresh dir, rotates with `generate_and_store(.., true)`, writes a plain
    /// control file (whose mode proves the mask was in force) and asserts the
    /// modes; the parent asserts the child passed and re-reads every mode.
    #[test]
    fn tester_mint_and_generate_are_0600_under_any_umask() {
        if let Ok(dir) = std::env::var(UMASK_CHILD_ENV) {
            let dir = PathBuf::from(dir);
            let parent = dir.join("aitmproxy");
            let p = parent.join("config.yaml");
            std::fs::File::create(dir.join("control")).expect("control file");
            assert!(
                matches!(mint_if_absent(&p, true), Minted::Written { .. }),
                "child: first run writes"
            );
            assert_eq!(mode_of(&p), 0o600, "child: minted mode {:o}", mode_of(&p));
            assert_eq!(
                mode_of(&parent),
                0o700,
                "child: parent mode {:o}",
                mode_of(&parent)
            );
            generate_and_store(&p, true).expect("child: rotate");
            assert_eq!(mode_of(&p), 0o600, "child: rotated mode {:o}", mode_of(&p));
            return;
        }

        let exe = std::env::current_exe().expect("the test binary path");
        for (mask, control_mode) in [("000", 0o666), ("077", 0o600), ("027", 0o640)] {
            let dir = mint_dir();
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!(
                    "umask {mask} && exec \"$0\" --exact \
                     operator_token::tests::tester_mint_and_generate_are_0600_under_any_umask \
                     --test-threads=1 --nocapture"
                ))
                .arg(&exe)
                .env(UMASK_CHILD_ENV, &dir)
                .output()
                .expect("re-exec the test binary under a umask");
            assert!(
                out.status.success(),
                "umask {mask}: the child failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                mode_of(&dir.join("control")),
                control_mode,
                "umask {mask} was not in force in the child"
            );
            let p = dir.join("aitmproxy").join("config.yaml");
            assert_eq!(
                mode_of(&p),
                0o600,
                "umask {mask}: config mode {:o}",
                mode_of(&p)
            );
            assert_eq!(
                mode_of(&dir.join("aitmproxy")),
                0o700,
                "umask {mask}: parent mode"
            );
            let text = std::fs::read_to_string(&p).unwrap();
            token_line_after(&text, "mcp:\n  operator_token: ");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Tester — spec D3 "never fatal": in a read-only directory the first run
    /// skips with `cannot write <path>: …`, creates nothing; an existing
    /// token-less config there is left byte-identical, its `0644` mode kept,
    /// no temp sibling behind; a parent that cannot be created skips too.
    #[test]
    fn tester_mint_skips_in_a_read_only_directory_and_changes_nothing() {
        let dir = mint_dir();
        let ro = dir.join("ro");
        std::fs::create_dir(&ro).unwrap();
        let missing = ro.join("config.yaml");
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::File::create(ro.join("probe")).is_ok() {
            eprintln!("skipping: this user can write a 0500 directory (root)");
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }

        match mint_if_absent(&missing, true) {
            Minted::Skipped { reason } => assert!(
                reason.starts_with(&format!("cannot write {}: ", missing.display())),
                "{reason}"
            ),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(
            std::fs::read_dir(&ro).unwrap().next().is_none(),
            "nothing was created in the read-only dir"
        );

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        let existing = ro.join("existing.yaml");
        let before = "# keep me\nlisten: 127.0.0.1:8080\n";
        std::fs::write(&existing, before).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();

        match mint_if_absent(&existing, false) {
            Minted::Skipped { reason } => assert!(
                reason.starts_with(&format!("cannot write {}: ", existing.display())),
                "{reason}"
            ),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&existing).unwrap(), before);
        assert_eq!(mode_of(&existing), 0o644, "the mode is not touched either");
        let names: Vec<String> = std::fs::read_dir(&ro)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["existing.yaml".to_string()], "no temp sibling");

        let deep = ro.join("sub").join("config.yaml");
        match mint_if_absent(&deep, true) {
            Minted::Skipped { reason } => assert!(
                reason.starts_with(&format!("cannot write {}: ", deep.display())),
                "{reason}"
            ),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(!ro.join("sub").exists());

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tester — AC-R14-3: a `Present` run only reads the file, so its bytes
    /// and its mtime are unchanged; a single-quoted empty value (`''`) is as
    /// absent as `""` and is replaced, an inline comment on that line kept.
    #[test]
    fn tester_present_keeps_the_mtime_and_quoted_empty_values_are_absent() {
        let dir = mint_dir();
        let p = dir.join("config.yaml");
        let text = "mcp:\n  operator_token: optoken-test-present\n";
        std::fs::write(&p, text).unwrap();
        let before = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(matches!(mint_if_absent(&p, true), Minted::Present));
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), before);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), text);

        let single = dir.join("single.yaml");
        std::fs::write(&single, "mcp:\n  operator_token: ''\n").unwrap();
        match mint_if_absent(&single, false) {
            Minted::Written { token, .. } => assert_eq!(
                std::fs::read_to_string(&single).unwrap(),
                format!("mcp:\n  operator_token: {}\n", token.expose())
            ),
            other => panic!("expected Written over '', got {other:?}"),
        }
        assert_eq!(mode_of(&single), 0o600);

        let commented = dir.join("commented.yaml");
        std::fs::write(&commented, "mcp:\n  operator_token: \"\" # none yet\n").unwrap();
        match mint_if_absent(&commented, false) {
            Minted::Written { token, .. } => {
                let out = std::fs::read_to_string(&commented).unwrap();
                assert_eq!(
                    out,
                    format!("mcp:\n  operator_token: {} # none yet\n", token.expose())
                );
                let cfg = config_file::parse(&out).unwrap();
                assert_eq!(cfg.mcp.operator_token.as_deref(), Some(token.expose()));
            }
            other => panic!("expected Written over \"\", got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Tester — spec D3 "a non-regular file at the path": a FIFO is
    /// `Skipped(<path> is not a regular file)` from its metadata alone and
    /// is never opened (nobody writes the pipe, so a read would block
    /// forever). Run on a helper thread with a deadline so a regression
    /// hangs the probe, not the suite.
    #[test]
    fn tester_mint_skips_a_fifo_without_opening_it() {
        let dir = mint_dir();
        let fifo = dir.join("config.yaml");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo {}", fifo.display());

        let (tx, rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let reason = match mint_if_absent(&probe, true) {
                Minted::Skipped { reason } => Some(reason),
                _ => None,
            };
            let _ = tx.send(reason);
        });
        let reason = rx
            .recv_timeout(std::time::Duration::from_millis(5_000))
            .expect("mint_if_absent must not block on a FIFO")
            .expect("a FIFO is Skipped");
        assert_eq!(reason, format!("{} is not a regular file", fifo.display()));
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(
                &std::fs::symlink_metadata(&fifo).unwrap().file_type()
            ),
            "the FIFO was replaced"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
