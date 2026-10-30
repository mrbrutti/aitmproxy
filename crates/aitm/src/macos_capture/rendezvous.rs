//! Rendezvous-file writer for the macOS Network/System Extension capture
//! handoff (core side).
//!
//! The sysex provider runs as **root** and the core (`aitm`) as the **user**, so
//! they share no home directory. The provider discovers the core's 0700 socket
//! directory through a single well-known file whose one line is the absolute
//! path of that directory. This module publishes that file to the byte-exact
//! path, shape, and mode the provider's `Rendezvous` reader requires
//! (`apps/mac/Extension/Sources/FlowHandoff.swift`, `HandoffConfig` lines 36-74
//! and `Rendezvous` lines 586-640).
//!
//! The write is hardened against a squatter: it unlinks any pre-existing entry
//! first and then creates the file with `O_CREAT | O_EXCL` (`create_new`), so it
//! never follows a planted symlink to clobber its target and never leaves
//! another process's stale content in place. The returned [`RendezvousFile`] is
//! an RAII guard that removes the file on drop.

use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// Byte-exact with `FlowHandoff.swift` `HandoffConfig.rendezvousPath` (line 54).
pub const RENDEZVOUS_PATH: &str = "/private/tmp/aitmproxy-capture.rendezvous";

/// macOS `sockaddr_un.sun_path` is 104 bytes. The socket-dir path plus `/` plus
/// the longest socket filename (`control.sock`) must fit, mirroring
/// `FlowHandoff.swift` lines 611-614 (`dir.utf8.count + 1 + longestSocket <
/// sun_path`).
const SUN_PATH_MAX: usize = 104;

/// RAII guard over a published rendezvous file: its [`Drop`] best-effort removes
/// the file so a core shutdown does not leave a stale path for the provider.
#[derive(Debug)]
pub struct RendezvousFile {
    path: PathBuf,
}

impl RendezvousFile {
    /// Publish `socket_dir` to `rendezvous_path` and return the removal guard.
    ///
    /// Writes a single line — the canonical absolute path of `socket_dir` plus a
    /// trailing newline — to a freshly created mode-0600 regular file, replacing
    /// any pre-existing entry without following a symlink.
    ///
    /// # Errors
    /// Propagates the canonicalize error if `socket_dir` does not exist; returns
    /// [`io::ErrorKind::InvalidInput`] if the canonical path is too long to fit a
    /// socket name within `sun_path`; propagates any error opening or writing the
    /// rendezvous file (including [`io::ErrorKind::AlreadyExists`] if an entry
    /// reappears at the path between the unlink and the create).
    pub fn publish(
        socket_dir: &Path,
        rendezvous_path: impl Into<PathBuf>,
    ) -> io::Result<RendezvousFile> {
        // The provider dials `<dir>/control.sock`; publish the realpath so a
        // relative or symlinked dir cannot smuggle a different target.
        let abs = fs::canonicalize(socket_dir)?;
        // Reject a dir whose path cannot hold a socket name within `sun_path`,
        // mirroring the provider's own check (FlowHandoff.swift:611-614).
        if abs.as_os_str().len() + 1 + super::listener::CONTROL_SOCK.len() >= SUN_PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket dir path too long to fit a socket name within sun_path",
            ));
        }
        let rendezvous_path = rendezvous_path.into();
        let body = format!("{}\n", abs.display());

        // Unlink-first then create-new: `create_new` (O_CREAT|O_EXCL) fails
        // `AlreadyExists` on any entry — regular file OR symlink — that reappears
        // between the unlink and the create, so publishing never follows a planted
        // symlink nor writes through another process's stale file.
        let _ = fs::remove_file(&rendezvous_path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&rendezvous_path)?;
        file.write_all(body.as_bytes())?;

        Ok(RendezvousFile {
            path: rendezvous_path,
        })
    }

    /// The rendezvous file path this guard will remove.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RendezvousFile {
    fn drop(&mut self) {
        // Best-effort: a double-remove or an already-gone file is ignored.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

    // AC7 note: `CaptureListener::publish_rendezvous` is intentionally NOT
    // unit-tested here. It writes the real `/private/tmp` constant and
    // presupposes a bound `CaptureListener` (a UDS bind — EPERM in the sandbox).
    // Its correctness rests on these `publish` tests plus the compiler; its live
    // exercise is NE plan Task 18.

    /// A scratch directory under `std::env::temp_dir()` with a unique suffix (the
    /// crate convention — see `operator_token.rs`), removed on drop.
    ///
    /// The name is kept SHORT on purpose: the real socket dir (`sockdir` below)
    /// must fit `sun_path` (the very budget `publish` enforces). On the host,
    /// `std::env::temp_dir()` is the long `/private/var/folders/.../T` path, so a
    /// long prefix + a full 32-char UUID + a long subdir would push the socket dir
    /// past the budget and make `publish` (correctly) reject it. A short prefix and
    /// an 8-hex-char suffix leave ample headroom under the budget.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Scratch {
            let uniq = uuid::Uuid::new_v4().simple().to_string();
            let p = std::env::temp_dir().join(format!("art{label}{}", &uniq[..8]));
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Create a mode-0700 socket directory inside `scratch`. Named `d` (one char)
    /// so the canonical socket-dir path stays well within the `sun_path` budget
    /// `publish` enforces, even under the host's long `std::env::temp_dir()`.
    fn make_socket_dir(scratch: &Scratch) -> PathBuf {
        let dir = scratch.path().join("d");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    // --- Rust mirrors of the Swift provider's `Rendezvous` acceptance checks ---

    /// Mirror of `Rendezvous.isAcceptableFile` (FlowHandoff.swift:627-631): a
    /// regular file (`S_IFREG`), no group/other WRITE bit, size in `1..=1024`.
    fn is_acceptable_file(md: &fs::Metadata) -> bool {
        (md.mode() & 0o170000) == 0o100000
            && (md.mode() & 0o022) == 0
            && md.size() >= 1
            && md.size() <= 1024
    }

    /// Mirror of `Rendezvous.isAcceptableDirectory` (FlowHandoff.swift:635-639):
    /// a real directory (`S_IFDIR`, `lstat`ed so not a symlink), no group/other
    /// access, owned by the same uid as the rendezvous file.
    fn is_acceptable_directory(md: &fs::Metadata, file_uid: u32) -> bool {
        (md.mode() & 0o170000) == 0o040000 && (md.mode() & 0o077) == 0 && md.uid() == file_uid
    }

    /// Mirror of the path checks (FlowHandoff.swift:610-614): absolute, no NUL
    /// byte, and `dir + '/' + "control.sock"` fits `sun_path` (104).
    fn path_fits(dir: &str) -> bool {
        dir.starts_with('/') && !dir.as_bytes().contains(&0) && dir.len() + 1 + 12 < 104
    }

    #[test]
    fn rendezvous_path_matches_swift_constant() {
        // AC1
        assert_eq!(RENDEZVOUS_PATH, "/private/tmp/aitmproxy-capture.rendezvous");
    }

    #[test]
    fn publish_writes_absolute_mode_0600_file() {
        // AC2
        let scratch = Scratch::new("ac2");
        let dir = make_socket_dir(&scratch);
        let rv = scratch.path().join("rv");

        let _guard = RendezvousFile::publish(&dir, &rv).unwrap();

        let raw = fs::read_to_string(&rv).unwrap();
        let canonical = fs::canonicalize(&dir).unwrap();
        assert_eq!(raw.trim(), canonical.to_string_lossy());
        assert!(raw.ends_with('\n'));

        let md = fs::metadata(&rv).unwrap();
        assert!((1..=1024).contains(&md.len()));
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn published_file_passes_swift_acceptance_mirror() {
        // AC3
        let scratch = Scratch::new("ac3");
        let dir = make_socket_dir(&scratch);
        let rv = scratch.path().join("rv");

        let _guard = RendezvousFile::publish(&dir, &rv).unwrap();

        let file_md = fs::metadata(&rv).unwrap();
        assert!(is_acceptable_file(&file_md), "file must be acceptable");

        let canonical = fs::canonicalize(&dir).unwrap();
        let dir_md = fs::symlink_metadata(&canonical).unwrap();
        assert!(
            is_acceptable_directory(&dir_md, file_md.uid()),
            "0700 same-owner dir must be acceptable"
        );

        assert!(
            path_fits(&canonical.to_string_lossy()),
            "canonical dir path must fit sun_path"
        );
    }

    #[test]
    fn too_long_dir_path_is_rejected() {
        // AC4
        let scratch = Scratch::new("ac4");
        // Build a nested dir whose canonical path makes abs.len() + 1 + 12 >= 104.
        let mut dir = scratch.path().to_path_buf();
        while fs::canonicalize(&dir).unwrap().as_os_str().len() + 1 + 12 < 104 {
            dir.push("components-padding-segment");
            fs::create_dir(&dir).unwrap();
        }

        let rv = scratch.path().join("rv");
        let err = RendezvousFile::publish(&dir, &rv).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn publish_replaces_stale_file() {
        // AC5 (stale regular file)
        let scratch = Scratch::new("ac5stale");
        let dir = make_socket_dir(&scratch);
        let rv = scratch.path().join("rv");
        fs::write(&rv, b"/private/tmp/some-old-dir\n").unwrap();

        let _guard = RendezvousFile::publish(&dir, &rv).unwrap();

        let raw = fs::read_to_string(&rv).unwrap();
        let canonical = fs::canonicalize(&dir).unwrap();
        assert_eq!(raw.trim(), canonical.to_string_lossy());
        assert_ne!(raw.trim(), "/private/tmp/some-old-dir");
    }

    #[test]
    fn publish_does_not_write_through_a_symlink() {
        // AC5 (planted symlink)
        let scratch = Scratch::new("ac5link");
        let dir = make_socket_dir(&scratch);
        let victim = scratch.path().join("victim");
        fs::write(&victim, b"VICTIM").unwrap();
        let rv = scratch.path().join("rv");
        symlink(&victim, &rv).unwrap();

        let _guard = RendezvousFile::publish(&dir, &rv).unwrap();

        // The victim's content is untouched: publish unlinked the link, not it.
        assert_eq!(fs::read(&victim).unwrap(), b"VICTIM");

        // The rendezvous path is now a fresh regular file, not a symlink.
        let lmd = fs::symlink_metadata(&rv).unwrap();
        assert!(!lmd.file_type().is_symlink());
        assert!(lmd.file_type().is_file());

        let raw = fs::read_to_string(&rv).unwrap();
        let canonical = fs::canonicalize(&dir).unwrap();
        assert_eq!(raw.trim(), canonical.to_string_lossy());
    }

    #[test]
    fn drop_removes_the_file() {
        // AC6
        let scratch = Scratch::new("ac6");
        let dir = make_socket_dir(&scratch);
        let rv = scratch.path().join("rv");

        {
            let guard = RendezvousFile::publish(&dir, &rv).unwrap();
            assert_eq!(guard.path(), rv.as_path());
            assert!(rv.exists());
        }
        assert!(!rv.exists());
    }
}
