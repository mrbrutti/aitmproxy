//! Linux gatherer: the inputs of the spec §2.2 Linux table and the §5.5
//! "a prompt is possible" test.
//!
//! The decisions live in pure functions ([`parse_cap_eff`], [`candidates`],
//! [`root_owned_chain`], [`prompt_possible`]) that compile and are tested on
//! every OS. The I/O ([`gather_linux`]) only reads: `/proc/self/status`, file
//! metadata along the helper's path, the policy file, `pkexec`'s presence, the
//! environment, and `/dev/tty`. The one thing it runs is the helper's own
//! `probe`, as this user, with a bounded wait. Discovery finds a helper to
//! probe; only the policy's exec path is ever run through polkit, and that is
//! P1b.14's job, not this file's.

use std::path::{Path, PathBuf};

use crate::privilege::contract::LINUX_HELPER_PATH;
use crate::privilege::derive::LinuxInputs;

/// File name of the helper binary wherever it is installed.
pub const HELPER_FILE_NAME: &str = "aitm-l4-helper";

/// NixOS's `security.wrappers` output directory.
pub const NIX_WRAPPERS_HELPER_PATH: &str = "/run/wrappers/bin/aitm-l4-helper";

/// The polkit policy the Linux packages install (spec §5.4).
pub const POLKIT_POLICY_PATH: &str =
    "/usr/share/polkit-1/actions/com.mrbrutti.aitmproxy.l4-helper.policy";

/// Where the polkit launcher lives on every distribution the packages target.
pub const PKEXEC_PATH: &str = "/usr/bin/pkexec";

/// Capability bit numbers from `linux/capability.h`.
pub const CAP_NET_ADMIN: u32 = 12;
/// See [`CAP_NET_ADMIN`].
pub const CAP_NET_RAW: u32 = 13;

/// The `CapEff` mask from a `/proc/<pid>/status` document, when it has one.
#[must_use]
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Whether capability bit `cap` is set in an effective-capabilities mask.
#[must_use]
pub fn has_cap(cap_eff: u64, cap: u32) -> bool {
    cap < 64 && cap_eff & (1u64 << cap) != 0
}

/// Helper discovery order (spec §2.2): the configured `l4.privilege.helper_path`,
/// `<exe dir>/aitm-l4-helper`, the package path, then NixOS's wrappers directory.
/// A place named twice is listed once, so it is probed once.
#[must_use]
pub fn candidates(helper_path: Option<&Path>, exe_dir: &Path) -> Vec<PathBuf> {
    let mut order: Vec<PathBuf> = Vec::with_capacity(4);
    let mut push = |path: PathBuf| {
        if !order.contains(&path) {
            order.push(path);
        }
    };
    if let Some(configured) = helper_path {
        push(configured.to_path_buf());
    }
    push(exe_dir.join(HELPER_FILE_NAME));
    push(PathBuf::from(LINUX_HELPER_PATH));
    push(PathBuf::from(NIX_WRAPPERS_HELPER_PATH));
    order
}

/// What matters about one path component for [`root_owned_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMeta {
    /// Owner uid.
    pub uid: u32,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// The component itself is a symlink (not followed).
    pub is_symlink: bool,
}

/// Group- or other-write bits: anyone but the owner could replace the file.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// A helper path only root could have placed: every component from the root
/// directory to the binary is root-owned, neither group- nor world-writable,
/// and not a symlink. An empty chain was never inspected and is `false`.
#[must_use]
pub fn root_owned_chain(chain: &[PathMeta]) -> bool {
    !chain.is_empty()
        && chain
            .iter()
            .all(|meta| meta.uid == 0 && meta.mode & GROUP_OR_OTHER_WRITE == 0 && !meta.is_symlink)
}

/// Spec §5.5 as corrected by spike S7: a polkit prompt can reach the operator
/// when `DISPLAY` or `WAYLAND_DISPLAY` is set (a graphical agent is likely), or
/// when the process has a controlling terminal (`open("/dev/tty")` succeeds;
/// pkexec's textual agent uses that, not stdin). An empty `DISPLAY` or
/// `WAYLAND_DISPLAY` counts as unset.
#[must_use]
pub fn prompt_possible(display: Option<&str>, wayland: Option<&str>, tty_opens: bool) -> bool {
    let set = |var: Option<&str>| var.is_some_and(|value| !value.is_empty());
    set(display) || set(wayland) || tty_opens
}

/// Everything `derive` needs from this Linux host (spec §2.2 Linux table).
/// `helper_path` is the configured `l4.privilege.helper_path`;
/// `session_connected` is what the helper-session owner knows (P1b.13).
///
/// `pub(crate)`: P1b.6's `PrivilegeState` wires it behind the `Prober` seam.
#[cfg(target_os = "linux")]
pub(crate) fn gather_linux(helper_path: Option<&Path>, session_connected: bool) -> LinuxInputs {
    use crate::privilege::derive::HelperCandidate;

    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_cap_eff(&status))
        .unwrap_or(0);

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let helper = candidates(helper_path, &exe_dir)
        .into_iter()
        .find(|path| path.is_file())
        .map(|path| HelperCandidate {
            at_policy_path: path == Path::new(LINUX_HELPER_PATH),
            root_owned_chain: path_chain(&path).is_some_and(|chain| root_owned_chain(&chain)),
            file_caps_net_raw: probe_reports_net_raw(&path),
            path,
        });

    LinuxInputs {
        cap_net_raw: has_cap(cap_eff, CAP_NET_RAW),
        cap_net_admin: has_cap(cap_eff, CAP_NET_ADMIN),
        session_connected,
        helper,
        policy_file_present: Path::new(POLKIT_POLICY_PATH).is_file(),
        pkexec_present: Path::new(PKEXEC_PATH).is_file(),
        prompt_possible: prompt_possible(
            std::env::var("DISPLAY").ok().as_deref(),
            std::env::var("WAYLAND_DISPLAY").ok().as_deref(),
            std::fs::File::open("/dev/tty").is_ok(),
        ),
    }
}

/// Portable stand-in: nothing here is a Linux host, so no capability, helper,
/// policy, launcher or prompt is claimed.
#[cfg(not(target_os = "linux"))]
pub(crate) fn gather_linux(_helper_path: Option<&Path>, session_connected: bool) -> LinuxInputs {
    LinuxInputs {
        cap_net_raw: false,
        cap_net_admin: false,
        session_connected,
        helper: None,
        policy_file_present: false,
        pkexec_present: false,
        prompt_possible: false,
    }
}

/// Metadata of every component from `/` down to `path`, symlinks not followed.
/// `None` when any component cannot be read: an unreadable chain is not a
/// root-owned one.
#[cfg(target_os = "linux")]
fn path_chain(path: &Path) -> Option<Vec<PathMeta>> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return None;
    }
    let mut chain = Vec::new();
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component);
        let meta = std::fs::symlink_metadata(&cursor).ok()?;
        chain.push(PathMeta {
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
            is_symlink: meta.file_type().is_symlink(),
        });
    }
    Some(chain)
}

/// Run `<helper> probe` as this user with a bounded wait and read the
/// `cap_net_raw` field of its one JSON line (plan P2.5). Anything short of
/// `true` is `false`: a helper that cannot run or answer has no file caps we
/// can rely on.
#[cfg(target_os = "linux")]
fn probe_reports_net_raw(helper: &Path) -> bool {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const PROBE_WAIT: Duration = Duration::from_secs(2);

    let Ok(mut child) = Command::new(helper)
        .arg("probe")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
    else {
        return false;
    };
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PROBE_WAIT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Err(_) => return false,
        }
    };
    if !status.success() {
        return false;
    }
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.take(4096).read_to_end(&mut stdout);
    }
    serde_json::from_slice::<serde_json::Value>(&stdout)
        .ok()
        .and_then(|value| {
            value
                .get("cap_net_raw")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    #[test]
    fn parse_cap_eff_reads_the_hex_line() {
        assert_eq!(parse_cap_eff("CapEff:\t0000000000002000\n"), Some(0x2000));
        let status = "Name:\taitm\nCapInh:\t0000000000000000\nCapPrm:\t0000000000003000\nCapEff:\t0000000000003000\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x3000));
        assert_eq!(parse_cap_eff("Name:\taitm\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);

        // The two bits derive cares about (P2.5 reads the same ones).
        assert!(has_cap(0x2000, CAP_NET_RAW));
        assert!(!has_cap(0x2000, CAP_NET_ADMIN));
        assert!(has_cap(0x1000, CAP_NET_ADMIN));
        assert!(!has_cap(0x1000, CAP_NET_RAW));
    }

    #[test]
    fn candidate_order_is_configured_exe_package_wrappers() {
        let order = candidates(Some(Path::new("/opt/x")), Path::new("/home/u/bin"));
        assert_eq!(
            order,
            vec![
                PathBuf::from("/opt/x"),
                PathBuf::from("/home/u/bin/aitm-l4-helper"),
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
        // Without a configured path the list is the three fixed places.
        let order = candidates(None, Path::new("/usr/bin"));
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/bin/aitm-l4-helper"),
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
        // A configured path equal to a fixed place is probed once.
        let order = candidates(
            Some(Path::new("/usr/lib/aitmproxy/aitm-l4-helper")),
            Path::new("/usr/lib/aitmproxy"),
        );
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/lib/aitmproxy/aitm-l4-helper"),
                PathBuf::from("/run/wrappers/bin/aitm-l4-helper"),
            ]
        );
    }

    fn root(mode: u32) -> PathMeta {
        PathMeta {
            uid: 0,
            mode,
            is_symlink: false,
        }
    }

    #[test]
    fn root_owned_chain_rejects_user_dirs_writable_bits_and_symlinks() {
        // The packaged path: / , /usr, /usr/lib, /usr/lib/aitmproxy, the helper.
        let packaged = [
            root(0o755),
            root(0o755),
            root(0o755),
            root(0o755),
            root(0o755),
        ];
        assert!(root_owned_chain(&packaged));
        // A 0750 root-owned helper (the headless layout) is still root-owned.
        assert!(root_owned_chain(&[root(0o755), root(0o755), root(0o750)]));

        // /home/u (uid 1000) in the chain.
        let home = [
            root(0o755),
            root(0o755),
            PathMeta {
                uid: 1000,
                mode: 0o755,
                is_symlink: false,
            },
            PathMeta {
                uid: 1000,
                mode: 0o755,
                is_symlink: false,
            },
        ];
        assert!(!root_owned_chain(&home));

        // Group-writable anywhere.
        assert!(!root_owned_chain(&[root(0o755), root(0o775), root(0o755)]));
        // World-writable anywhere (even sticky /tmp).
        assert!(!root_owned_chain(&[root(0o755), root(0o1777), root(0o755)]));
        // A symlink anywhere.
        assert!(!root_owned_chain(&[
            root(0o755),
            PathMeta {
                uid: 0,
                mode: 0o777,
                is_symlink: true,
            },
            root(0o755),
        ]));
        // Nothing inspected is not a root-owned chain.
        assert!(!root_owned_chain(&[]));
    }

    #[test]
    fn prompt_possible_three_rows() {
        assert!(!prompt_possible(None, None, false));
        assert!(prompt_possible(Some(":0"), None, false));
        assert!(prompt_possible(None, None, true));
        // Wayland alone is enough; an empty DISPLAY is unset.
        assert!(prompt_possible(None, Some("wayland-0"), false));
        assert!(!prompt_possible(Some(""), Some(""), false));
    }
}
