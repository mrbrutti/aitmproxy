//! `o` — open externally (§2.9 "placeholder + `o` opens externally"). The
//! terminal cannot show an image or page a 5 MB body, so the TUI hands the
//! file to the desktop: `open` on macOS, `xdg-open` elsewhere, spawned and
//! not waited for. A body that only exists in memory is first written to a
//! private temp file. The app stays pure: `App::take_open_target` yields the
//! [`OpenTarget`] and the `run` loop in `lib.rs` performs it.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What `o` opens: a path on this machine and a short label for the toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTarget {
    pub path: PathBuf,
    pub label: String,
}

/// The desktop opener for this platform.
fn opener() -> &'static str {
    if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    }
}

/// Hand `t.path` to the desktop opener without waiting for it. `Ok` means
/// the opener was spawned; what it does with the file is its business.
pub fn open_externally(t: &OpenTarget) -> std::io::Result<()> {
    Command::new(opener())
        .arg(&t.path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(drop)
}

/// A flow id (or a typed PoC name) reduced to filename-safe characters:
/// ASCII alphanumerics, `-` and `_`, at most 64 of them; `flow` when nothing
/// survives.
pub fn safe_name(id: &str) -> String {
    let s: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect();
    if s.is_empty() {
        "flow".into()
    } else {
        s
    }
}

/// Write `bytes` to `temp_dir()/aitm-tui-<id>.<ext>`, readable by this user
/// only (0600 on unix), replacing any earlier file of that name.
pub fn body_to_temp_file(id: &str, ext: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let ext: String = ext
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    let ext = if ext.is_empty() {
        "bin".to_string()
    } else {
        ext
    };
    let path = std::env::temp_dir().join(format!("aitm-tui-{}.{ext}", safe_name(id)));
    write_private(&path, bytes)?;
    Ok(path)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // Remove first so an existing file's mode cannot survive the rewrite.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_goes_to_a_private_temp_file_named_after_the_flow() {
        let path = body_to_temp_file("f41", "png", b"\x89PNG-bytes").unwrap();
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("aitm-tui-f41.png")
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"\x89PNG-bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }
        // Rewriting the same id replaces the content and keeps the mode.
        let again = body_to_temp_file("f41", "png", b"second").unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ids_and_extensions_from_the_bus_are_sanitised() {
        assert_eq!(safe_name("../../etc/passwd"), "etcpasswd");
        assert_eq!(safe_name(""), "flow");
        assert_eq!(safe_name("f-1_2"), "f-1_2");
        let path = body_to_temp_file("a/b", "../sh", b"x").unwrap();
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("aitm-tui-ab.sh")
        );
        let _ = std::fs::remove_file(&path);
        let path = body_to_temp_file("z", "", b"x").unwrap();
        assert!(path.to_string_lossy().ends_with("aitm-tui-z.bin"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opener_matches_the_platform() {
        if cfg!(target_os = "macos") {
            assert_eq!(opener(), "open");
        } else {
            assert_eq!(opener(), "xdg-open");
        }
    }
}
