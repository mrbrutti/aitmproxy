//! The Linux `/proc` walk (spec D4, Linux bullet; D5, Linux paragraph).
//!
//! `find_owners`: `/proc/net/tcp{,6}` rows whose `uid` is ours and whose
//! `(local, remote)` is a wanted `(client, proxy)` give socket inodes; then every
//! `/proc/<pid>/fd/*` link is read, ascending pid, until each inode has an owner
//! or the deadline passes. `identity`: `readlink /proc/<pid>/exe` basename, else
//! `/proc/<pid>/comm`.
//!
//! The scanner takes its `/proc` root as a path so the walk is tested on any host
//! against a fixture tree; only [`LinuxScanner::new`] (which reads the real
//! `/proc`) is Linux-only.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use crate::linux::parse::{exe_basename, fd_socket_inode, parse_stat_starttime, parse_tcp_row};
use crate::matching::tuple_matches;
use crate::types::{ProcessKey, SocketScanner, Tuple};

/// The uid stored when `/proc/self` could not be read: no `/proc/net/tcp` row can
/// carry it, so the scanner matches nothing rather than guessing.
#[cfg(target_os = "linux")]
const NO_UID: u32 = u32::MAX;

/// The Linux [`SocketScanner`]: same-user `/proc/net/tcp{,6}` rows → inode →
/// `/proc/<pid>/fd` walk.
pub(crate) struct LinuxScanner {
    /// A pid never reported as an owner (production: our own).
    pub(crate) skip_pid: Option<u32>,
    /// Our effective uid; rows of other users are skipped before any fd walk.
    uid: u32,
    /// The procfs mount, `/proc` in production, a fixture tree in tests.
    root: PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxScanner {
    /// The production scanner: the real `/proc`, our uid (from the owner of
    /// `/proc/self`, no libc), our own pid skipped.
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::MetadataExt;
        let uid = fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(NO_UID);
        Self::with_root(PathBuf::from("/proc"), uid, Some(std::process::id()))
    }
}

impl LinuxScanner {
    /// A scanner over an arbitrary procfs root. `uid` is the only uid whose
    /// rows are considered; `skip_pid` is never reported.
    pub(crate) fn with_root(root: PathBuf, uid: u32, skip_pid: Option<u32>) -> Self {
        Self {
            skip_pid,
            uid,
            root,
        }
    }

    fn pid_dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    /// Socket inode → wanted tuple, from the rows of `<root>/net/<table>` that are
    /// ours and whose local end is the client and remote end the proxy. The
    /// first row per tuple wins.
    fn collect_inodes(
        &self,
        table: &str,
        v6: bool,
        wanted: &[Tuple],
        out: &mut HashMap<u64, Tuple>,
    ) {
        let Ok(text) = fs::read_to_string(self.root.join("net").join(table)) else {
            return;
        };
        for line in text.lines() {
            if out.len() == wanted.len() {
                return;
            }
            let Some(row) = parse_tcp_row(line, v6) else {
                continue;
            };
            if row.uid != self.uid {
                continue;
            }
            let hit = wanted.iter().find(|t| {
                !out.values().any(|claimed| claimed == *t)
                    && tuple_matches(
                        row.local.ip(),
                        row.local.port(),
                        row.remote.ip(),
                        row.remote.port(),
                        t,
                    )
            });
            if let Some(t) = hit {
                out.entry(row.inode).or_insert(*t);
            }
        }
    }

    /// Every numeric directory name under the root, ascending.
    fn pids(&self) -> Vec<u32> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut pids: Vec<u32> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect();
        pids.sort_unstable();
        pids
    }

    /// The socket inodes held open by `pid`; empty when its fd table cannot be read.
    fn socket_inodes(&self, pid: u32) -> Vec<u64> {
        let Ok(entries) = fs::read_dir(self.pid_dir(pid).join("fd")) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let target = fs::read_link(e.path()).ok()?;
                fd_socket_inode(target.to_str()?)
            })
            .collect()
    }

    /// Field 22 of `<root>/<pid>/stat`, or 0 when it cannot be read.
    fn start_time(&self, pid: u32) -> u64 {
        fs::read_to_string(self.pid_dir(pid).join("stat"))
            .ok()
            .and_then(|s| parse_stat_starttime(&s))
            .unwrap_or(0)
    }
}

impl SocketScanner for LinuxScanner {
    fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey> {
        let mut owners = HashMap::new();
        if wanted.is_empty() {
            return owners;
        }

        let mut inodes: HashMap<u64, Tuple> = HashMap::new();
        self.collect_inodes("tcp", false, wanted, &mut inodes);
        if inodes.len() < wanted.len() {
            self.collect_inodes("tcp6", true, wanted, &mut inodes);
        }
        if inodes.is_empty() {
            return owners;
        }

        for pid in self.pids() {
            if Instant::now() >= deadline || inodes.is_empty() {
                break;
            }
            if Some(pid) == self.skip_pid {
                continue;
            }
            let held = self.socket_inodes(pid);
            if held.is_empty() {
                continue;
            }
            let mut key: Option<ProcessKey> = None;
            for inode in held {
                let Some(tuple) = inodes.remove(&inode) else {
                    continue;
                };
                let key = *key.get_or_insert_with(|| ProcessKey {
                    pid,
                    start: self.start_time(pid),
                });
                owners.insert(tuple, key);
            }
        }
        owners
    }

    fn identity(&self, key: ProcessKey) -> Option<String> {
        let dir = self.pid_dir(key.pid);
        fs::read_link(dir.join("exe"))
            .ok()
            .and_then(|p| exe_basename(p.to_str()?))
            .or_else(|| {
                let comm = fs::read_to_string(dir.join("comm")).ok()?;
                let comm = comm.trim();
                (!comm.is_empty()).then(|| comm.to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::SocketAddr;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::LinuxScanner;
    use crate::types::{ProcessKey, SocketScanner, Tuple};

    const UID: u32 = 1000;
    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    // Little-endian hex words, as the kernel prints them on x86-64 / aarch64.
    const LOOPBACK4: &str = "0100007F";
    const LOOPBACK6: &str = "00000000000000000000000001000000";
    const MAPPED4: &str = "0000000000000000FFFF00000100007F";

    /// A fake `/proc` under `$TMPDIR`, removed on drop.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "aitm-peer-process-scan-{tag}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("net")).unwrap();
            // The entries a real /proc has that are not pids.
            fs::create_dir_all(root.join("sys")).unwrap();
            symlink("1", root.join("self")).unwrap();
            Self { root }
        }

        fn root(&self) -> &Path {
            &self.root
        }

        fn table(&self, name: &str, rows: &[String]) {
            let mut text = String::from(TCP_HEADER);
            text.push('\n');
            for row in rows {
                text.push_str(row);
                text.push('\n');
            }
            fs::write(self.root.join("net").join(name), text).unwrap();
        }

        fn pid(&self, pid: u32) -> &Self {
            fs::create_dir_all(self.root.join(pid.to_string()).join("fd")).unwrap();
            self
        }

        fn fd(&self, pid: u32, n: u32, target: &str) -> &Self {
            symlink(
                target,
                self.root
                    .join(pid.to_string())
                    .join("fd")
                    .join(n.to_string()),
            )
            .unwrap();
            self
        }

        fn stat(&self, pid: u32, comm: &str, starttime: u64) -> &Self {
            let text = format!(
                "{pid} ({comm}) S 1 {pid} {pid} 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 {starttime} 1000 2 3 4\n"
            );
            fs::write(self.root.join(pid.to_string()).join("stat"), text).unwrap();
            self
        }

        fn exe(&self, pid: u32, target: &str) -> &Self {
            symlink(target, self.root.join(pid.to_string()).join("exe")).unwrap();
            self
        }

        fn comm(&self, pid: u32, text: &str) -> &Self {
            fs::write(self.root.join(pid.to_string()).join("comm"), text).unwrap();
            self
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn row(local: &str, lport: u16, remote: &str, rport: u16, uid: u32, inode: u64) -> String {
        format!(
            "   0: {local}:{lport:04X} {remote}:{rport:04X} 01 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 1 0000000000000000 20 4 30 10 -1"
        )
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn tuple(client: &str, proxy: &str) -> Tuple {
        Tuple {
            client: sa(client),
            proxy: sa(proxy),
        }
    }

    fn scanner(fx: &Fixture, skip_pid: Option<u32>) -> LinuxScanner {
        LinuxScanner::with_root(fx.root().to_path_buf(), UID, skip_pid)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn finds_the_owner_of_a_v4_loopback_tuple() {
        let fx = Fixture::new("v4");
        fx.table(
            "tcp",
            &[
                row(LOOPBACK4, 49864, LOOPBACK4, 8080, UID, 12345),
                // The proxy's own accepted socket: reversed direction, must not match.
                row(LOOPBACK4, 8080, LOOPBACK4, 49864, UID, 12346),
            ],
        );
        fx.table("tcp6", &[]);
        fx.pid(100)
            .fd(100, 0, "/dev/null")
            .fd(100, 5, "socket:[999]")
            .stat(100, "other", 1);
        fx.pid(4242)
            .fd(4242, 0, "/dev/null")
            .fd(4242, 3, "socket:[12345]")
            .fd(4242, 7, "pipe:[42]")
            .stat(4242, "curl", 98765);

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[wanted], soon());

        assert_eq!(owners.len(), 1);
        assert_eq!(
            owners[&wanted],
            ProcessKey {
                pid: 4242,
                start: 98765
            }
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn a_row_owned_by_another_uid_is_never_matched() {
        let fx = Fixture::new("uid");
        fx.table("tcp", &[row(LOOPBACK4, 49864, LOOPBACK4, 8080, 0, 12345)]);
        fx.table("tcp6", &[]);
        fx.pid(4242)
            .fd(4242, 3, "socket:[12345]")
            .stat(4242, "curl", 1);

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[wanted], soon());

        assert!(owners.is_empty(), "{owners:?}");
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn the_lowest_pid_wins_and_skip_pid_is_honoured() {
        // A forked child inherits the socket: two pids hold the same inode.
        let fx = Fixture::new("lowest");
        fx.table("tcp", &[row(LOOPBACK4, 49864, LOOPBACK4, 8080, UID, 12345)]);
        fx.table("tcp6", &[]);
        fx.pid(20)
            .fd(20, 3, "socket:[12345]")
            .stat(20, "child", 200);
        fx.pid(10)
            .fd(10, 3, "socket:[12345]")
            .stat(10, "parent", 100);
        fx.pid(9).fd(9, 3, "socket:[777]").stat(9, "bystander", 9);

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");

        let owners = scanner(&fx, None).find_owners(&[wanted], soon());
        assert_eq!(
            owners[&wanted],
            ProcessKey {
                pid: 10,
                start: 100
            }
        );

        let owners = scanner(&fx, Some(10)).find_owners(&[wanted], soon());
        assert_eq!(
            owners[&wanted],
            ProcessKey {
                pid: 20,
                start: 200
            }
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn tcp6_rows_match_native_v6_and_mapped_v4_tuples() {
        let fx = Fixture::new("v6");
        fx.table("tcp", &[]);
        fx.table(
            "tcp6",
            &[
                row(LOOPBACK6, 49864, LOOPBACK6, 8080, UID, 501),
                row(MAPPED4, 49865, MAPPED4, 8080, UID, 502),
            ],
        );
        fx.pid(31).fd(31, 4, "socket:[501]").stat(31, "six", 31);
        fx.pid(32).fd(32, 4, "socket:[502]").stat(32, "mapped", 32);

        let native = tuple("[::1]:49864", "[::1]:8080");
        // The core sees a v4 peer even when the client used a mapped v6 socket.
        let mapped = tuple("127.0.0.1:49865", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[native, mapped], soon());

        assert_eq!(owners.len(), 2);
        assert_eq!(owners[&native], ProcessKey { pid: 31, start: 31 });
        assert_eq!(owners[&mapped], ProcessKey { pid: 32, start: 32 });
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn a_missing_stat_still_matches_with_start_zero() {
        let fx = Fixture::new("nostat");
        fx.table("tcp", &[row(LOOPBACK4, 49864, LOOPBACK4, 8080, UID, 12345)]);
        fx.table("tcp6", &[]);
        fx.pid(4242).fd(4242, 3, "socket:[12345]");

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[wanted], soon());

        assert_eq!(
            owners[&wanted],
            ProcessKey {
                pid: 4242,
                start: 0
            }
        );
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn an_expired_deadline_finds_nothing() {
        let fx = Fixture::new("deadline");
        fx.table("tcp", &[row(LOOPBACK4, 49864, LOOPBACK4, 8080, UID, 12345)]);
        fx.table("tcp6", &[]);
        fx.pid(4242)
            .fd(4242, 3, "socket:[12345]")
            .stat(4242, "curl", 1);

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let owners = scanner(&fx, None).find_owners(&[wanted], past);

        assert!(owners.is_empty(), "{owners:?}");
    }

    #[test]
    fn an_empty_proc_yields_nothing_and_does_not_panic() {
        let fx = Fixture::new("empty");
        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[wanted], soon());
        assert!(owners.is_empty());

        let missing = fx.root().join("does-not-exist");
        let owners = LinuxScanner::with_root(missing, UID, None).find_owners(&[wanted], soon());
        assert!(owners.is_empty());
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn a_pid_without_a_readable_fd_dir_is_skipped() {
        let fx = Fixture::new("nofd");
        fx.table("tcp", &[row(LOOPBACK4, 49864, LOOPBACK4, 8080, UID, 12345)]);
        fx.table("tcp6", &[]);
        // Another user's process: /proc/<pid>/fd exists but is unreadable; here
        // simply absent, which read_dir reports the same way (an Err).
        fs::create_dir_all(fx.root().join("7")).unwrap();
        fx.pid(4242)
            .fd(4242, 3, "socket:[12345]")
            .stat(4242, "curl", 5);

        let wanted = tuple("127.0.0.1:49864", "127.0.0.1:8080");
        let owners = scanner(&fx, None).find_owners(&[wanted], soon());

        assert_eq!(
            owners[&wanted],
            ProcessKey {
                pid: 4242,
                start: 5
            }
        );
    }

    #[test]
    fn identity_is_the_exe_basename_with_the_deleted_marker_stripped() {
        let fx = Fixture::new("exe");
        fx.pid(4242)
            .exe(4242, "/usr/bin/curl (deleted)")
            .comm(4242, "not-this\n");

        let identity = scanner(&fx, None).identity(ProcessKey {
            pid: 4242,
            start: 1,
        });

        assert_eq!(identity, Some("curl".to_string()));
    }

    #[test]
    fn identity_falls_back_to_comm_when_exe_is_unreadable() {
        let fx = Fixture::new("comm");
        fx.pid(4242).comm(4242, "python3\n");

        let identity = scanner(&fx, None).identity(ProcessKey {
            pid: 4242,
            start: 1,
        });

        assert_eq!(identity, Some("python3".to_string()));
    }

    #[test]
    fn identity_of_a_vanished_pid_is_none() {
        let fx = Fixture::new("gone");
        fx.pid(4242).comm(4242, "   \n");

        let scanner = scanner(&fx, None);
        assert_eq!(
            scanner.identity(ProcessKey {
                pid: 4242,
                start: 1
            }),
            None
        );
        assert_eq!(
            scanner.identity(ProcessKey {
                pid: 99999,
                start: 1
            }),
            None
        );
    }
}
