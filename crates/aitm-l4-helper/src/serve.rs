//! `serve` start-up (spec §5.1 steps 1–6, §7 T3; plan P2.6; spike S7).
//!
//! The privilege-reducing half of the Linux helper. After pkexec starts it as
//! root, it records its parent, works out the invoking user, drops to that user
//! keeping only `CAP_NET_RAW`, checks the socket path as that user, connects,
//! authenticates the peer, and arms the parent-death signal last. A failed step
//! returns `Err` and `main` exits before any other I/O.
//!
//! The pure parts (`invoking_user`, `check_socket_path`, `PathMeta`) are
//! platform-neutral and unit-tested everywhere. The syscalls (`drop_to`,
//! `startup`) are `cfg(target_os = "linux")` and first compile on the Linux rig
//! (plan amendment A5). Every message here may reach a terminal: it names the
//! failing property and never a command for the operator to type (plan Rule 2).

use std::ffi::OsStr;

/// Work out the user the helper serves (spec §5.1 step 2).
///
/// `PKEXEC_UID` is trusted only when the real uid is 0 (started by pkexec); it
/// must then be a plain decimal `u32` other than 0. A caller that is not root
/// is always its own `real_uid`, whatever `PKEXEC_UID` says (AC18).
pub fn invoking_user(real_uid: u32, pkexec_uid: Option<&OsStr>) -> Result<u32, String> {
    if real_uid != 0 {
        return Ok(real_uid);
    }
    let raw = pkexec_uid.ok_or_else(|| {
        "started as root without PKEXEC_UID: the helper never serves as root".to_string()
    })?;
    let uid =
        parse_decimal_uid(raw).ok_or_else(|| "PKEXEC_UID is not a decimal uid".to_string())?;
    if uid == 0 {
        return Err("PKEXEC_UID is 0: the helper never serves as root".to_string());
    }
    Ok(uid)
}

/// Exactly the ASCII digits of a `u32`: no sign, no whitespace, no prefix,
/// nothing that is not UTF-8. pkexec writes `%d`, so this is what arrives.
fn parse_decimal_uid(raw: &OsStr) -> Option<u32> {
    let text = raw.to_str()?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok()
}

/// What `lstat` says about one path, reduced to the fields spec §5.1 step 4
/// checks. Built from `std::fs::Metadata` on Unix, or by hand in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMeta {
    pub is_socket: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub uid: u32,
    /// The full `st_mode`; only the low nine permission bits are compared.
    pub mode: u32,
}

#[cfg(unix)]
impl PathMeta {
    /// Reduce a `symlink_metadata` result. On a symlink `is_dir` and
    /// `is_socket` are false, so a link to a socket is refused as a symlink.
    pub fn from_metadata(meta: &std::fs::Metadata) -> PathMeta {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let kind = meta.file_type();
        PathMeta {
            is_socket: kind.is_socket(),
            is_dir: kind.is_dir(),
            is_symlink: kind.is_symlink(),
            uid: meta.uid(),
            mode: meta.mode(),
        }
    }
}

/// Spec §5.1 step 4: the socket is a Unix socket and not a symlink; its
/// directory is a directory, not a symlink, owned by the invoking user, mode
/// exactly 0700. Checked only after the drop, as the invoking user.
pub fn check_socket_path(sock: &PathMeta, dir: &PathMeta, invoking: u32) -> Result<(), String> {
    if sock.is_symlink {
        return Err("socket path is a symlink".to_string());
    }
    if !sock.is_socket {
        return Err("socket path is not a Unix socket".to_string());
    }
    if dir.is_symlink {
        return Err("socket directory is a symlink".to_string());
    }
    if !dir.is_dir {
        return Err("socket directory is not a directory".to_string());
    }
    if dir.uid != invoking {
        return Err(format!(
            "socket directory is owned by uid {}, not the invoking user {invoking}",
            dir.uid
        ));
    }
    let perm = dir.mode & 0o777;
    if perm != 0o700 {
        return Err(format!("socket directory mode is {perm:04o}, not 0700"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub use linux::startup;

/// The syscalls: Linux only (plan A5: first compiled on the Linux rig).
#[cfg(target_os = "linux")]
mod linux {
    use super::{check_socket_path, invoking_user, PathMeta};
    use caps::{CapSet, Capability, CapsHashSet};
    use nix::sys::prctl;
    use nix::sys::signal::Signal;
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use nix::unistd::{geteuid, getppid, getuid, setgroups, setresgid, setresuid, Uid, User};
    use std::ffi::OsStr;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    /// Spec §5.1 steps 1–6, in that order. `Err` means `main` must exit
    /// before any other I/O.
    pub fn startup(connect: &Path, pkexec_uid: Option<&OsStr>) -> Result<UnixStream, String> {
        // 1. Record the parent (argv was validated by `cli::parse` already).
        let parent = getppid();

        // 2. The invoking user.
        let user = invoking_user(getuid().as_raw(), pkexec_uid)?;

        // 3. Drop to that user with CAP_NET_RAW only, then no_new_privs.
        drop_to(user)?;

        // 4. Only now, as the invoking user, look at the path.
        let sock_meta = std::fs::symlink_metadata(connect)
            .map_err(|err| format!("socket path cannot be inspected: {err}"))?;
        let dir_path = connect
            .parent()
            .ok_or_else(|| "socket path has no parent directory".to_string())?;
        let dir_meta = std::fs::symlink_metadata(dir_path)
            .map_err(|err| format!("socket directory cannot be inspected: {err}"))?;
        check_socket_path(
            &PathMeta::from_metadata(&sock_meta),
            &PathMeta::from_metadata(&dir_meta),
            user,
        )?;

        // 5. Connect and authenticate the peer: our invoking user, and the
        //    process that spawned us (pkexec execs in place, spike S7).
        let stream = UnixStream::connect(connect)
            .map_err(|err| format!("connect to the core's socket failed: {err}"))?;
        let peer = getsockopt(&stream, PeerCredentials)
            .map_err(|err| format!("peer credentials unavailable: {err}"))?;
        if peer.uid() != user {
            return Err(format!(
                "peer uid {} is not the invoking user {user}",
                peer.uid()
            ));
        }
        if peer.pid() != parent.as_raw() {
            return Err(format!(
                "peer pid {} is not the parent process {}",
                peer.pid(),
                parent.as_raw()
            ));
        }

        // 6. Last: the parent-death signal (the kernel clears it at the
        //    credential change, so it must follow step 3), then confirm the
        //    parent did not die before it was armed.
        prctl::set_pdeathsig(Signal::SIGKILL)
            .map_err(|err| format!("parent-death signal not set: {err}"))?;
        if getppid() != parent {
            return Err("the core exited before the parent-death signal was armed".to_string());
        }
        Ok(stream)
    }

    /// Spec §5.1 step 3 in spike S7's proven order (plan A1, spec S1).
    ///
    /// Root: (a) drop every capability but `CAP_NET_RAW` from the bounding
    /// set while `CAP_SETPCAP` is still held; (b) clear the ambient set;
    /// (c) `PR_SET_KEEPCAPS`, without which the uid change empties the
    /// permitted set; (d) `setgroups([primary gid])` (never `initgroups`,
    /// which keeps the admin group), `setresgid`, `setresuid`; (e) permitted
    /// and effective to `{CAP_NET_RAW}`, inheritable cleared; (f) keepcaps
    /// off. Root or not: (g) `no_new_privs`.
    fn drop_to(user: u32) -> Result<(), String> {
        let is_root = getuid().is_root() || geteuid().is_root();
        if is_root {
            // (a) Bounding set. A capability this kernel does not know makes
            // PR_CAPBSET_READ fail (EINVAL); that one is skipped. Every other
            // failure is fatal.
            for cap in caps::all() {
                if cap == Capability::CAP_NET_RAW {
                    continue;
                }
                // `Ok(false)` is already gone; `Err` is a capability this
                // kernel does not know (PR_CAPBSET_READ gives EINVAL).
                if let Ok(true) = caps::has_cap(None, CapSet::Bounding, cap) {
                    caps::drop(None, CapSet::Bounding, cap)
                        .map_err(|err| format!("bounding set still holds {cap}: {err}"))?;
                }
            }
            // (b) Ambient set.
            caps::clear(None, CapSet::Ambient)
                .map_err(|err| format!("ambient set not cleared: {err}"))?;
            // (c) Keep the permitted set across the uid change.
            prctl::set_keepcaps(true).map_err(|err| format!("keepcaps not set: {err}"))?;
            // (d) Groups, gid, uid: the invoking user's primary group only.
            let uid = Uid::from_raw(user);
            let gid = User::from_uid(uid)
                .map_err(|err| format!("invoking user {user} cannot be looked up: {err}"))?
                .map(|entry| entry.gid)
                .ok_or_else(|| format!("invoking user {user} has no passwd entry"))?;
            setgroups(&[gid]).map_err(|err| format!("supplementary groups not set: {err}"))?;
            setresgid(gid, gid, gid).map_err(|err| format!("gid not changed: {err}"))?;
            setresuid(uid, uid, uid).map_err(|err| format!("uid not changed: {err}"))?;
            // (e) Permitted and effective to CAP_NET_RAW only, inheritable
            // empty. Permitted first: the effective set is empty after the
            // uid change, so it is a subset either way.
            let net_raw: CapsHashSet = [Capability::CAP_NET_RAW].into_iter().collect();
            caps::set(None, CapSet::Permitted, &net_raw)
                .map_err(|err| format!("permitted set not reduced: {err}"))?;
            caps::set(None, CapSet::Effective, &net_raw)
                .map_err(|err| format!("effective set not reduced: {err}"))?;
            caps::clear(None, CapSet::Inheritable)
                .map_err(|err| format!("inheritable set not cleared: {err}"))?;
            // (f) Keepcaps off again.
            prctl::set_keepcaps(false).map_err(|err| format!("keepcaps not cleared: {err}"))?;
            // Never continue as root, whatever the calls above reported.
            if getuid().is_root() || geteuid().is_root() {
                return Err("still root after the privilege drop".to_string());
            }
        }
        // (g) Root or not: no new privileges from here on.
        prctl::set_no_new_privs().map_err(|err| format!("no_new_privs not set: {err}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn env(value: &str) -> Option<&OsStr> {
        Some(OsStr::new(value))
    }

    #[test]
    fn a_non_root_caller_is_the_invoking_user_whatever_pkexec_uid_says() {
        // AC18: run directly (not root) with PKEXEC_UID=0, the helper takes getuid().
        assert_eq!(invoking_user(1000, env("0")), Ok(1000));
        assert_eq!(invoking_user(1000, None), Ok(1000));
        assert_eq!(invoking_user(1000, env("garbage")), Ok(1000));
    }

    #[test]
    fn root_trusts_a_decimal_pkexec_uid() {
        assert_eq!(invoking_user(0, env("1000")), Ok(1000));
        assert_eq!(invoking_user(0, env("4294967295")), Ok(4_294_967_295));
    }

    #[test]
    fn root_without_pkexec_uid_is_an_error() {
        let err = invoking_user(0, None).expect_err("root without PKEXEC_UID is refused");
        assert_eq!(
            err,
            "started as root without PKEXEC_UID: the helper never serves as root"
        );
    }

    #[test]
    fn root_with_pkexec_uid_zero_is_an_error_that_says_so() {
        let err = invoking_user(0, env("0")).expect_err("PKEXEC_UID=0 is refused");
        assert_eq!(err, "PKEXEC_UID is 0: the helper never serves as root");
    }

    #[test]
    fn root_with_a_malformed_pkexec_uid_is_an_error() {
        for bad in [
            "",
            "-1",
            " 1000",
            "1000x",
            "4294967296",
            "+1000",
            "1000 ",
            "0x3e8",
        ] {
            assert_eq!(
                invoking_user(0, env(bad)),
                Err("PKEXEC_UID is not a decimal uid".to_string()),
                "PKEXEC_UID={bad:?} must be refused"
            );
        }
    }

    #[test]
    fn root_with_a_non_utf8_pkexec_uid_is_an_error() {
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(&[b'1', 0xff, b'0']);
        let err = invoking_user(0, Some(bad)).expect_err("non-UTF-8 PKEXEC_UID is refused");
        assert_eq!(err, "PKEXEC_UID is not a decimal uid");
    }

    fn good_socket() -> PathMeta {
        PathMeta {
            is_socket: true,
            is_dir: false,
            is_symlink: false,
            uid: 1000,
            mode: 0o140_755,
        }
    }

    fn good_dir() -> PathMeta {
        PathMeta {
            is_socket: false,
            is_dir: true,
            is_symlink: false,
            uid: 1000,
            mode: 0o040_700,
        }
    }

    #[test]
    fn an_owned_0700_directory_holding_a_real_socket_is_accepted() {
        assert_eq!(check_socket_path(&good_socket(), &good_dir(), 1000), Ok(()));
    }

    #[test]
    fn a_directory_owned_by_another_uid_is_refused_naming_ownership() {
        let dir = PathMeta {
            uid: 1001,
            ..good_dir()
        };
        let err = check_socket_path(&good_socket(), &dir, 1000).expect_err("foreign owner refused");
        assert_eq!(
            err,
            "socket directory is owned by uid 1001, not the invoking user 1000"
        );
    }

    #[test]
    fn a_directory_with_mode_0755_is_refused_naming_the_mode() {
        let dir = PathMeta {
            mode: 0o040_755,
            ..good_dir()
        };
        let err = check_socket_path(&good_socket(), &dir, 1000).expect_err("0755 refused");
        assert_eq!(err, "socket directory mode is 0755, not 0700");
    }

    #[test]
    fn a_symlinked_socket_is_refused() {
        let sock = PathMeta {
            is_symlink: true,
            ..good_socket()
        };
        let err = check_socket_path(&sock, &good_dir(), 1000).expect_err("symlink refused");
        assert_eq!(err, "socket path is a symlink");
    }

    #[test]
    fn a_non_socket_at_the_path_is_refused() {
        let sock = PathMeta {
            is_socket: false,
            ..good_socket()
        };
        let err = check_socket_path(&sock, &good_dir(), 1000).expect_err("regular file refused");
        assert_eq!(err, "socket path is not a Unix socket");
    }

    #[test]
    fn a_symlinked_directory_is_refused() {
        let dir = PathMeta {
            is_symlink: true,
            ..good_dir()
        };
        let err = check_socket_path(&good_socket(), &dir, 1000).expect_err("symlinked dir refused");
        assert_eq!(err, "socket directory is a symlink");
    }

    #[test]
    fn a_non_directory_parent_is_refused() {
        let dir = PathMeta {
            is_dir: false,
            ..good_dir()
        };
        let err = check_socket_path(&good_socket(), &dir, 1000).expect_err("non-dir refused");
        assert_eq!(err, "socket directory is not a directory");
    }

    #[test]
    fn mode_check_compares_only_the_permission_bits() {
        // Only the permission bits are compared: 0o040_700 (a directory) passes.
        let dir = PathMeta {
            mode: 0o040_700,
            ..good_dir()
        };
        assert_eq!(check_socket_path(&good_socket(), &dir, 1000), Ok(()));
        // 0710 (group execute) is not 0700.
        let dir = PathMeta {
            mode: 0o040_710,
            ..good_dir()
        };
        assert_eq!(
            check_socket_path(&good_socket(), &dir, 1000),
            Err("socket directory mode is 0710, not 0700".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_meta_from_metadata_reads_type_owner_and_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base =
            std::env::temp_dir().join(format!("aitm-l4-helper-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir(&base).expect("tempdir");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700");
        let link = base.with_extension("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&base, &link).expect("symlink");

        let dir_meta = std::fs::symlink_metadata(&base).expect("lstat dir");
        let dir = PathMeta::from_metadata(&dir_meta);
        assert!(dir.is_dir);
        assert!(!dir.is_symlink);
        assert!(!dir.is_socket);
        assert_eq!(dir.mode & 0o777, 0o700);
        assert_eq!(dir.uid, dir_meta.uid());

        let link_meta = std::fs::symlink_metadata(&link).expect("lstat link");
        let linked = PathMeta::from_metadata(&link_meta);
        assert!(linked.is_symlink);
        assert!(!linked.is_dir);
        assert!(!linked.is_socket);

        let file = base.join("not-a-socket");
        std::fs::write(&file, b"x").expect("write");
        let file_meta = std::fs::symlink_metadata(&file).expect("lstat file");
        let file = PathMeta::from_metadata(&file_meta);
        assert!(!file.is_socket);
        assert!(!file.is_dir);
        assert!(!file.is_symlink);

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The words plan Rule 2 forbids, matched as whole words (the regex
    /// `\b(sudo|setcap|chmod|chgrp|chown|dseditgroup|launchctl|pkexec)\b`).
    fn names_a_command(msg: &str) -> Option<&'static str> {
        const FORBIDDEN: [&str; 8] = [
            "sudo",
            "setcap",
            "chmod",
            "chgrp",
            "chown",
            "dseditgroup",
            "launchctl",
            "pkexec",
        ];
        msg.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .find_map(|word| FORBIDDEN.iter().copied().find(|f| *f == word))
    }

    #[test]
    fn no_start_up_error_names_a_command() {
        let mut messages = vec![
            invoking_user(0, None).expect_err("err"),
            invoking_user(0, env("0")).expect_err("err"),
            invoking_user(0, env("")).expect_err("err"),
            invoking_user(0, env("-1")).expect_err("err"),
            invoking_user(0, env("1000x")).expect_err("err"),
        ];
        let sock = good_socket();
        let dir = good_dir();
        let cases: [(PathMeta, PathMeta, u32); 6] = [
            (
                PathMeta {
                    is_symlink: true,
                    ..sock
                },
                dir,
                1000,
            ),
            (
                PathMeta {
                    is_socket: false,
                    ..sock
                },
                dir,
                1000,
            ),
            (
                sock,
                PathMeta {
                    is_symlink: true,
                    ..dir
                },
                1000,
            ),
            (
                sock,
                PathMeta {
                    is_dir: false,
                    ..dir
                },
                1000,
            ),
            (sock, dir, 1001),
            (
                sock,
                PathMeta {
                    mode: 0o040_755,
                    ..dir
                },
                1000,
            ),
        ];
        for (sock, dir, invoking) in &cases {
            messages.push(check_socket_path(sock, dir, *invoking).expect_err("err"));
        }
        assert_eq!(messages.len(), 11);
        for msg in &messages {
            assert_eq!(
                names_a_command(msg),
                None,
                "message {msg:?} names a command"
            );
        }
        // The matcher itself works as whole words.
        assert_eq!(names_a_command("run sudo now"), Some("sudo"));
        assert_eq!(names_a_command("PKEXEC_UID is 0"), None);
    }

    // ---- Tester edge cases (stage 5, unit p2) ------------------------------

    #[test]
    fn tester_uid_max_is_an_ordinary_uid_for_both_checks() {
        assert_eq!(invoking_user(u32::MAX, env("0")), Ok(u32::MAX));
        assert_eq!(invoking_user(u32::MAX, None), Ok(u32::MAX));
        let dir = PathMeta {
            uid: u32::MAX,
            ..good_dir()
        };
        assert_eq!(check_socket_path(&good_socket(), &dir, u32::MAX), Ok(()));
        assert_eq!(
            check_socket_path(&good_socket(), &dir, 1000),
            Err(
                "socket directory is owned by uid 4294967295, not the invoking user 1000"
                    .to_string()
            )
        );
        assert_eq!(
            check_socket_path(&good_socket(), &good_dir(), u32::MAX),
            Err(
                "socket directory is owned by uid 1000, not the invoking user 4294967295"
                    .to_string()
            )
        );
        // uid 0 is refused upstream by invoking_user; the path check itself
        // treats it as any other owner.
        let root_dir = PathMeta {
            uid: 0,
            ..good_dir()
        };
        assert_eq!(check_socket_path(&good_socket(), &root_dir, 0), Ok(()));
        assert_eq!(
            check_socket_path(&good_socket(), &root_dir, 1000),
            Err("socket directory is owned by uid 0, not the invoking user 1000".to_string())
        );
    }

    #[test]
    fn tester_special_mode_bits_on_the_directory_are_ignored_by_design() {
        // Only the low nine bits are compared (the existing design, see
        // `mode_check_compares_only_the_permission_bits`): a setuid, setgid
        // or sticky bit on an otherwise 0700 directory passes. Tester finding
        // for the panel: spec §5.1 says "mode 0700"; decide whether the
        // special bits should refuse too.
        for mode in [0o044_700_u32, 0o042_700, 0o041_700, 0o047_700] {
            assert_eq!(
                check_socket_path(&good_socket(), &PathMeta { mode, ..good_dir() }, 1000),
                Ok(()),
                "{mode:o}"
            );
        }
        // Any difference in the nine bits is refused, naming those bits only.
        for (mode, text) in [
            (0o044_000_u32, "socket directory mode is 0000, not 0700"),
            (0o040_777, "socket directory mode is 0777, not 0700"),
            (0o040_600, "socket directory mode is 0600, not 0700"),
            (0o040_701, "socket directory mode is 0701, not 0700"),
            (0o040_070, "socket directory mode is 0070, not 0700"),
        ] {
            assert_eq!(
                check_socket_path(&good_socket(), &PathMeta { mode, ..good_dir() }, 1000),
                Err(text.to_string()),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn tester_check_order_is_socket_first_then_directory() {
        // Every property wrong at once: the socket's symlink check speaks
        // first, then its type, then the directory's symlink, type, owner
        // and mode, each named alone.
        let bad = PathMeta {
            is_socket: false,
            is_dir: false,
            is_symlink: true,
            uid: 7,
            mode: 0o120_777,
        };
        assert_eq!(
            check_socket_path(&bad, &bad, 1000),
            Err("socket path is a symlink".to_string())
        );
        let not_sock = PathMeta {
            is_symlink: false,
            ..bad
        };
        assert_eq!(
            check_socket_path(&not_sock, &bad, 1000),
            Err("socket path is not a Unix socket".to_string())
        );
        assert_eq!(
            check_socket_path(&good_socket(), &bad, 1000),
            Err("socket directory is a symlink".to_string())
        );
        let not_dir = PathMeta {
            is_symlink: false,
            ..bad
        };
        assert_eq!(
            check_socket_path(&good_socket(), &not_dir, 1000),
            Err("socket directory is not a directory".to_string())
        );
        let foreign = PathMeta {
            is_dir: true,
            ..not_dir
        };
        assert_eq!(
            check_socket_path(&good_socket(), &foreign, 1000),
            Err("socket directory is owned by uid 7, not the invoking user 1000".to_string())
        );
        let wide = PathMeta {
            uid: 1000,
            ..foreign
        };
        assert_eq!(
            check_socket_path(&good_socket(), &wide, 1000),
            Err("socket directory mode is 0777, not 0700".to_string())
        );
        // The socket's own owner and mode are not part of the check.
        let odd_socket = PathMeta {
            uid: 7,
            mode: 0o140_000,
            ..good_socket()
        };
        assert_eq!(check_socket_path(&odd_socket, &good_dir(), 1000), Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn tester_pkexec_uid_odd_encodings() {
        use std::os::unix::ffi::OsStrExt;
        // Leading zeros are still a decimal u32 (pkexec writes %d, so this
        // never arrives; harmless either way).
        assert_eq!(invoking_user(0, env("0001000")), Ok(1000));
        // Non-ASCII digits, valid UTF-8, are not a decimal uid.
        assert_eq!(
            invoking_user(0, env("١٠٠٠")),
            Err("PKEXEC_UID is not a decimal uid".to_string())
        );
        assert_eq!(
            invoking_user(0, env("１０００")),
            Err("PKEXEC_UID is not a decimal uid".to_string())
        );
        // Non-UTF-8 of every shape: a lone continuation byte, an overlong
        // encoding, a truncated sequence, a digit after a bad byte.
        for bad in [
            &[0xff][..],
            &[0xc0, 0x80],
            &[b'1', 0xe2, 0x82],
            &[0x80, b'1'],
            &[b'1', b'0', b'0', b'0', 0xff],
        ] {
            assert_eq!(
                invoking_user(0, Some(OsStr::from_bytes(bad))),
                Err("PKEXEC_UID is not a decimal uid".to_string()),
                "{bad:?}"
            );
            // A caller that is not root ignores it entirely.
            assert_eq!(
                invoking_user(1000, Some(OsStr::from_bytes(bad))),
                Ok(1000),
                "{bad:?}"
            );
        }
        // An embedded NUL cannot come from the environment; the parser does
        // not care either way.
        assert_eq!(
            invoking_user(0, env("10\u{0}00")),
            Err("PKEXEC_UID is not a decimal uid".to_string())
        );
        // All zeros is still zero.
        assert_eq!(
            invoking_user(0, env("0000")),
            Err("PKEXEC_UID is 0: the helper never serves as root".to_string())
        );
        // u32::MAX + 1 and a 40-digit value are refused as not a uid.
        assert_eq!(
            invoking_user(0, env("4294967296")),
            Err("PKEXEC_UID is not a decimal uid".to_string())
        );
        assert_eq!(
            invoking_user(0, env(&"9".repeat(40))),
            Err("PKEXEC_UID is not a decimal uid".to_string())
        );
    }
}
