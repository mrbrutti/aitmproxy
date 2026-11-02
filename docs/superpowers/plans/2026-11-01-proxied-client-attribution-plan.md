# Proxied client attribution — implementation plan

**Status:** approved (2026-11-01, autonomous mode)
**Spec:** `docs/superpowers/specs/2026-11-01-proxied-client-attribution-design.md`
**Branch / worktree:** `claude/friendly-tu-2d144a` (this worktree, off main `f6fe1a14`)

## Overview

Eight tasks in two crates plus wiring and tests. A new unsafe-isolated leaf crate
`crates/aitm-peer-process` does the scanning (macOS libproc, Linux `/proc`), the matching, the
identity, the sanitising, the coalescing and the caching; `aitm-core` gains a `PeerResolver`
trait, a builder step and the start-at-accept / 25 ms-after-the-peek step in `handle_conn`;
`aitm` wires the real resolver and the docs change wording; an e2e cell proves `curl -x` → Client
`curl` on a real core.

Dependency graph and fan-out (tasks on one line touch disjoint files and may run in parallel):

```
wave 1:  T1 (leaf skeleton + portable parsers)   ||   T6 (aitm-core trait + acceptor)
wave 2:  T2 (coalescer/cache)  ||  T3 (macOS ffi + pins + raw self-test)  ||  T4 (Linux glue)
wave 3:  T5 (macOS scanner + identity + ProcessResolver assembly; needs T2, T3, T4, T6)
wave 4:  T7 (wire.rs + Cargo + wording)          [T8 authoring may start here]
wave 5:  T8 (e2e cell + rewrite of the old null cell; proof needs T7's binary)
```

Terminal-only tests (they bind loopback sockets; the sandbox refuses `bind`/`connect`): T3's and
T5's self-resolution tests, T6's acceptor tests (`cargo test -p aitm-core proxy::`), T8. The Coder
runs them via the Terminal panel and quotes the output; everything else runs in the sandbox with
`cargo test --offline`.

Parallel-coder rules apply (memory `aitmproxy-parallel-coders-shared-worktree`): commit by
pathspec, never `cargo fmt` on a crate root (format the leaf files you touched), per-package
gates while a wave is in flight, full gate before the panel.

## Tasks

### Task 1: leaf crate skeleton + portable rules and parsers

- **Satisfies:** AC6, AC7 (and the crate half of the Constraints: deny-unsafe leaf, no new deps)
- **Depends on:** none
- **Files:** `Cargo.toml` (modify: add member `"crates/aitm-peer-process"` next to
  `"crates/aitm-peer-token"` and alias `aitm-peer-process = { path = "crates/aitm-peer-process" }`
  next to the `aitm-peer-token` alias), `crates/aitm-peer-process/Cargo.toml` (create),
  `crates/aitm-peer-process/src/lib.rs` (create), `src/types.rs` (create), `src/sanitize.rs`
  (create), `src/matching.rs` (create), `src/linux/mod.rs` + `src/linux/parse.rs` (create; the
  parsers are **not** cfg-gated so they are tested on the Mac — `#[cfg(target_os = "linux")]` goes
  on the glue in Task 4 only), `src/macos/mod.rs` + `src/macos/bundle_path.rs` (create; the path
  rule is not cfg-gated either).
- **Change:**
  - `Cargo.toml` of the crate copies `aitm-peer-token`'s header comment and
    `[lints.rust] unsafe_code = "deny"`; `[dependencies] aitm-core.workspace = true`;
    `[target.'cfg(target_os = "macos")'.dependencies] libc = "0.2"` and `core-foundation = "0.10"`.
    `description = "Leaf crate holding the audited unsafe libproc calls: name the process behind an accepted loopback TCP connection."`
  - `src/types.rs`:
    ```rust
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct Tuple { pub client: SocketAddr, pub proxy: SocketAddr }
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub struct ProcessKey { pub pid: u32, pub start: u64 }
    #[derive(Clone, Debug)]
    pub struct Limits { pub scan_deadline: Duration, pub scan_tokens: u32, pub scan_refill_per_s: u32, pub cache_entries: usize }
    impl Default for Limits  // 250 ms, 20, 20, 256 (amended 2026-11-01, F2; was 10, 10)
    pub(crate) trait SocketScanner: Send + Sync {
        fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey>;
        fn identity(&self, key: ProcessKey) -> Option<String>;   // raw, unsanitised
    }
    ```
  - `src/sanitize.rs`: `pub fn sanitize(raw: &str) -> Option<String>` exactly as spec D5
    (Cc via `char::is_control`, the listed Cf ranges, trim, empty → `None`, > 256 bytes → `None`).
  - `src/matching.rs`: `pub(crate) fn canonical(ip: IpAddr) -> IpAddr` (mapped v4 → v4),
    `pub(crate) fn tuple_matches(laddr: IpAddr, lport: u16, faddr: IpAddr, fport: u16, wanted: &Tuple) -> bool`,
    `pub(crate) fn port_from_libproc(raw: i32) -> u16` (`u16::from_be((raw as u32 & 0xFFFF) as u16)`).
  - `src/linux/parse.rs`:
    ```rust
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct TcpRow { pub local: SocketAddr, pub remote: SocketAddr, pub state: u8, pub uid: u32, pub inode: u64 }
    pub(crate) fn parse_tcp_row(line: &str, v6: bool) -> Option<TcpRow>;   // hex words native-endian, ports host-order
    pub(crate) fn parse_stat_starttime(stat: &str) -> Option<u64>;         // field 22 after the last ')'
    pub(crate) fn exe_basename(link: &str) -> Option<String>;              // strips " (deleted)"
    pub(crate) fn fd_socket_inode(link: &str) -> Option<u64>;              // "socket:[N]"
    ```
  - `src/macos/bundle_path.rs`: `pub(crate) fn innermost_bundle(path: &str) -> Option<&str>`
    (last non-final component ending in `.app`/`.xpc`/`.appex`; returns the prefix through it).
  - `src/lib.rs`: crate doc (why the crate exists, fail-closed), `pub mod` lines, `pub use
    types::{Limits, ProcessKey, Tuple}; pub use sanitize::sanitize;`. A placeholder
    `pub struct ProcessResolver;` is **not** added here (Task 5 owns it) so the crate compiles
    as a library of pure functions in this task.
- **Test:** in each module's `mod tests`, the literal cases of AC6 and AC7:
  `parse_tcp_row("   0: 0100007F:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1", false)`
  `== Some(TcpRow { local: "127.0.0.1:49864", remote: "127.0.0.1:8080", state: 1, uid: 1000, inode: 12345 })`;
  the `::1` and `::ffff:127.0.0.1` tcp6 rows (`#[cfg(target_endian = "little")]`);
  `parse_stat_starttime("1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 98765 1000 2") == Some(98765)`;
  `exe_basename("/usr/bin/curl (deleted)") == Some("curl")`; `fd_socket_inode("socket:[12345]") == Some(12345)`;
  the five `innermost_bundle` cases; `tuple_matches` true/false cases; `port_from_libproc(0x406f) == 28480`;
  the six `sanitize` cases (`"cu\u{200E}rl"` → `Some("curl")`, 257 × `a` → `None`, …).
- **Done when:** `cargo test --offline -p aitm-peer-process` passes in the sandbox,
  `cargo clippy --offline -p aitm-peer-process --all-targets -- -D warnings` and `cargo fmt --check`
  on the new files pass, and the workspace still builds (`cargo check --offline --workspace`).

### Task 2: coalescer, rate limit, identity cache

- **Satisfies:** AC14, AC15 (D3)
- **Depends on:** Task 1
- **Files:** `crates/aitm-peer-process/src/coalesce.rs` (create), `src/cache.rs` (create),
  `src/lib.rs` (modify: `mod coalesce; mod cache;`)
- **Change:**
  ```rust
  // cache.rs
  pub(crate) struct IdentityCache { map: HashMap<ProcessKey, Option<String>>, order: VecDeque<ProcessKey>, cap: usize }
  impl IdentityCache {
      pub(crate) fn new(cap: usize) -> Self;
      pub(crate) fn get(&self, key: &ProcessKey) -> Option<Option<String>>;   // outer None = miss
      pub(crate) fn insert(&mut self, key: ProcessKey, identity: Option<String>);  // FIFO evict at cap
      #[cfg(test)] pub(crate) fn len(&self) -> usize;  // Q4
  }
  // coalesce.rs
  pub(crate) struct Coalescer<S: SocketScanner> { scanner: S, limits: Limits, state: Mutex<State>, wake: Condvar }
  struct State { scanning: bool, pending: HashSet<Tuple>, results: HashMap<Tuple, Option<ProcessKey>>, tokens: f64, last_refill: Instant, cache: IdentityCache }
  impl<S: SocketScanner> Coalescer<S> {
      pub(crate) fn new(scanner: S, limits: Limits) -> Self;
      /// The spec D3 algorithm: register, lead or wait, then identity via the cache; sanitised.
      pub(crate) fn resolve(&self, tuple: Tuple) -> Option<String>;
  }
  ```
  Leader loop, token bucket (`capacity = scan_tokens`, refill `scan_refill_per_s` per second,
  fractional accumulation), deadline `Instant::now() + limits.scan_deadline` passed to
  `find_owners`; a waiter gives up at the same deadline. `identity()` is called only on a cache
  miss, result (even `None`) inserted. `sanitize` applied to the raw identity before caching.
- **Test:** `mod tests` with `FakeScanner { calls: Mutex<Vec<Vec<Tuple>>>, delay: Duration, owners: HashMap<Tuple, ProcessKey>, identities: Mutex<Vec<ProcessKey>> }`:
  - `eight_concurrent_resolutions_share_at_most_two_scans`: 8 threads, 8 tuples, delay 20 ms →
    `calls.len() <= 2`, every thread gets `Some(<its name>)`.
  - `drained_bucket_returns_none_without_a_scan`: `Limits { scan_tokens: 0, .. }` → `None`,
    `calls.is_empty()`.
  - `deadline_bounds_a_slow_scan`: `scan_deadline = 1 ms`, delay 50 ms → `None` returned within
    40 ms of the call.
  - `identity_is_cached_per_pid_and_start`: two tuples → same `ProcessKey` → `identities.len() == 1`;
    a third tuple → same pid, `start + 1` → `identities.len() == 2`.
  - `cache_evicts_fifo_at_capacity`: `IdentityCache::new(256)`, insert keys 0..=256 → `len() == 256`,
    `get(&key0) == None`, `get(&key1).is_some()`.
  - `sanitised_identity_leaves_the_coalescer`: raw `"cu\u{200E}rl"` → `Some("curl")`.
- **Done when:** the six tests pass in the sandbox; per-package clippy/fmt clean.
- **Amendment 2026-11-01 (F2, spec D3 amendment):** `State` gains `warm: VecDeque<u32>` (MRU,
  `WARM_CAPACITY = 16`); `lead_scan` probes the warm pids via
  `SocketScanner::find_owners_among(wanted, deadline, pids) -> Probe { owners, gone }` without a
  token, drops `gone` pids, then takes one token for one `find_owners` over the missed tuples
  only; matched pids move to the front. `Limits::default()` bucket is 20/20. Tests (fake scanner
  records full vs targeted calls): `warm_hits_skip_the_full_scan_and_the_bucket` (1 token, no
  refill: one full scan then 50 warm hits, 50 targeted probes of `[4242]`),
  `a_targeted_miss_falls_through_to_one_full_scan`,
  `warm_set_keeps_the_sixteen_most_recently_matched_pids`,
  `a_pid_whose_probe_finds_no_sockets_leaves_the_warm_set`; the bucket tests use two pids so the
  second lookup is a warm miss. `lead_scan` holds a `ScanGuard` whose `Drop` writes `None` for the
  batch, clears `scanning` and notifies on unwind (T-F1); tests
  `a_scanner_panic_does_not_wedge_later_callers`, `a_waiter_is_released_when_the_leader_panics`.

### Task 3: macOS libproc FFI wrappers, layout pins, raw self-resolution

- **Satisfies:** AC8, AC9 (the `find_owners` half), the unsafe-isolation constraint
- **Depends on:** Task 1
- **Files:** `crates/aitm-peer-process/src/macos/ffi.rs` (create), `src/macos/mod.rs` (modify:
  `#[cfg(target_os = "macos")] pub(crate) mod ffi;`)
- **Change:** all `unsafe` in this one file, module-level `#![allow(unsafe_code)]`, every block
  with a `// SAFETY:` comment. `#[repr(C)]` mirrors (names as in `sys/proc_info.h`):
  `proc_fdinfo { proc_fd: i32, proc_fdtype: u32 }`, `in_sockinfo` (80 bytes: `insi_fport: i32`,
  `insi_lport: i32`, `insi_gencnt: u64`, `insi_flags: u32`, `insi_flow: u32`, `insi_vflag: u8`,
  `insi_ip_ttl: u8`, `_pad: [u8; 6]`, `insi_faddr: [u8; 16]`, `insi_laddr: [u8; 16]`, `_tail: [u8; 16]`),
  `tcp_sockinfo` (120 bytes: `tcpsi_ini: in_sockinfo`, `tcpsi_state: i32`, rest as blob),
  `socket_fdinfo` (792 bytes: `_pfi: [u8; 24]`, `_psi_head: [u8; 208]`, `soi_kind: i32`,
  `_pad: i32`, `soi_proto: [u8; 552]`). Constants `PROC_ALL_PIDS: u32 = 1`,
  `PROC_PIDFDSOCKETINFO: i32 = 3`, `SOCKINFO_TCP: i32 = 2`, `INI_IPV4: u8 = 1`, `INI_IPV6: u8 = 2`.
  Safe wrappers (each `Option`/`Vec`, fail-closed). Only `find_owners_raw`, `find_owners_among_raw`,
  `pid_path`, `pid_name` are `pub(crate)`; every other wrapper, mirror and constant below is private
  to `ffi.rs` (Q3, 2026-11-01):
  ```rust
  fn list_pids() -> Vec<u32>;                                          // proc_listpids(PROC_ALL_PIDS), two-call sizing
  fn socket_fds(pid: u32) -> Option<Vec<i32>>;                         // PROC_PIDLISTFDS, filtered to PROX_FDTYPE_SOCKET; None on EPERM/ESRCH
  struct TcpSocket { laddr: IpAddr, lport: u16, faddr: IpAddr, fport: u16 }
  fn tcp_socket(pid: u32, fd: i32) -> Option<TcpSocket>;               // PROC_PIDFDSOCKETINFO; None unless soi_kind == SOCKINFO_TCP and the full 792 bytes were written; ports via port_from_libproc; addresses per insi_vflag
  pub(crate) fn pid_path(pid: u32) -> Option<String>;                  // proc_pidpath into a 4096-byte buffer
  pub(crate) fn pid_name(pid: u32) -> Option<String>;                  // proc_name into a 256-byte buffer
  fn pid_start_micros(pid: u32) -> Option<u64>;                        // PROC_PIDTBSDINFO → pbi_start_tvsec*1_000_000 + pbi_start_tvusec
  pub(crate) fn find_owners_raw(wanted: &[Tuple], deadline: Instant, skip_pid: Option<u32>) -> HashMap<Tuple, ProcessKey>;
  ```
  `find_owners_raw`: pids ascending, skip `skip_pid`, deadline checked per pid and every 64 fds within a pid (`FD_DEADLINE_STRIDE` in `types.rs`, S3), `socket_fds` →
  `tcp_socket` → `tuple_matches`; first match per tuple wins; `pid_start_micros` only for matched
  pids (`start` = 0 if it fails, still a match).
- **Test:** `#[cfg(target_os = "macos")] mod tests`:
  - `socket_fdinfo_layout_matches_the_sdk`: the ten AC8 pins via `size_of` / `offset_of!`.
  - `self_resolution_v4` (Terminal): listener `127.0.0.1:0`, connect, accept →
    `find_owners_raw(&[tuple], now + 1 s, None)[&tuple].pid == std::process::id()`.
  - `self_resolution_v6` (Terminal): the same on `[::1]:0`.
  - `closed_port_resolves_nothing` (Terminal): a tuple whose client port came from a socket that
    was dropped → map is empty.
  - `other_users_pids_are_skipped_not_errors`: `socket_fds(1) == None` (launchd, EPERM) and
    `list_pids().len() > 1`.
- **Done when:** the layout test passes in the sandbox; the Terminal run of
  `cargo test -p aitm-peer-process macos::ffi` is quoted green; clippy/fmt clean.

### Task 4: Linux scanner glue (cfg-gated, fixture-tested on the Mac)

- **Satisfies:** the Linux half of D2/D4/D5 (live proof is the follow-up named in the spec)
- **Depends on:** Task 1
- **Files:** `crates/aitm-peer-process/src/linux/scan.rs` (create), `src/linux/mod.rs` (modify:
  `#[cfg(any(target_os = "linux", test))] pub(crate) mod scan;` — amended 2026-11-01 in the
  whole-branch panel (P3, accepted (a)): the walk builds under `cfg(test)` on every host so it is
  fixture-tested here, matching spec Summary item 8; only `LinuxScanner::new` stays
  `cfg(target_os = "linux")`)
- **Change:**
  ```rust
  pub(crate) struct LinuxScanner { pub(crate) skip_pid: Option<u32>, uid: u32, root: PathBuf }
  #[cfg(target_os = "linux")]
  impl LinuxScanner { pub(crate) fn new() -> Self; }  // root = /proc; uid via std::os::unix::fs::MetadataExt on /proc/self (no libc dep); own pid skipped
  impl LinuxScanner { pub(crate) fn with_root(root: PathBuf, uid: u32, skip_pid: Option<u32>) -> Self; }  // any procfs root: a fixture tree in tests
  impl SocketScanner for LinuxScanner {
      fn find_owners(..)  // read <root>/net/tcp and tcp6, parse_tcp_row, match wanted by (local==client, remote==proxy) after canonical(); row.uid must equal self.uid; inode → walk <root>/[0-9]+/fd ascending, readlink, fd_socket_inode == inode; skip skip_pid; deadline per pid and every 64 fds within a pid (`FD_DEADLINE_STRIDE` in `types.rs`, S3); ProcessKey.start from parse_stat_starttime(<root>/<pid>/stat)
      fn identity(..)     // exe_basename(readlink <root>/<pid>/exe) else <root>/<pid>/comm trimmed
  }
  ```
- **Test:** the parsers are Task 1's. Here: fixture tests over a fake `/proc` under `$TMPDIR`
  (`linux::scan::tests`, 16 after the fix range; the four added: a probe with no matching row
  walks nothing (Q6), a malformed row does not abort the table, two tuples of one process share one
  key, the fd walk of one pid stops at an expired deadline (S5). At the panel: a same-uid row is matched, another uid's row is never
  matched, the lowest pid wins and `skip_pid` is honoured, a missing `stat` still matches with
  `start == 0`, an expired deadline finds nothing, an empty `/proc` does not panic, an unreadable
  fd dir is skipped, identity via `exe` then `comm`, a vanished pid is `None`, a malformed row does
  not abort the table, a targeted probe walks only the given pids). Plus the cross-check
  `cargo check --offline -p aitm-peer-process --target x86_64-unknown-linux-gnu` if that target's
  std is installed; otherwise the Coder reports "Linux glue unverified on this Mac" and the Tester
  notes it.
- **Done when:** the Mac build is unaffected (`cargo test --offline -p aitm-peer-process` still
  green), the fixture tests are green, and the cross-check result is quoted either way. Result at
  the panel: Homebrew rustc 1.97.1, no rustup, only aarch64-apple-darwin std;
  `cargo check --offline -p aitm-peer-process --target x86_64-unknown-linux-gnu` →
  error[E0463]: can't find crate for `core` — unverified on this Mac; live Linux proof is the
  spec's named follow-up.

### Task 5: macOS scanner + identity, `ProcessResolver`, trait impl, full self-resolution

- **Satisfies:** AC9 (the `resolve` half), D5
- **Depends on:** Tasks 2, 3, 4, 6
- **Files:** `crates/aitm-peer-process/src/macos/scan.rs` (create), `src/macos/identity.rs`
  (create), `src/macos/mod.rs` (modify), `src/resolver.rs` (create), `src/lib.rs` (modify:
  `mod resolver; pub use resolver::ProcessResolver;`)
- **Change:**
  ```rust
  // macos/identity.rs
  pub(crate) fn bundle_identifier(bundle_path: &str) -> Option<String>;  // CFURL::from_path(p, true) → CFBundle::new → info_dictionary()["CFBundleIdentifier"] downcast CFString
  pub(crate) fn identity_for_path(path: &str) -> Option<String>;        // innermost_bundle → bundle_identifier, else basename
  // macos/scan.rs
  pub(crate) struct MacScanner { pub(crate) skip_pid: Option<u32> }
  impl SocketScanner for MacScanner {
      fn find_owners(..) { ffi::find_owners_raw(wanted, deadline, self.skip_pid) }
      fn identity(&self, key) { ffi::pid_path(key.pid).and_then(|p| identity_for_path(&p)).or_else(|| ffi::pid_name(key.pid)) }
  }
  // resolver.rs
  pub struct ProcessResolver { inner: Coalescer<PlatformScanner> }  // PlatformScanner = MacScanner | LinuxScanner | NoScanner by cfg
  impl ProcessResolver {
      pub fn new() -> Self;                                   // Limits::default(), skip own pid
      pub fn with_limits(limits: Limits) -> Self;
      #[doc(hidden)] pub fn for_tests(limits: Limits, skip_pid: Option<u32>) -> Self;   // tests only; with_limits(l) = build(l, Some(own pid)) (Q5/Q10, 2026-11-01)
  }
  impl Default for ProcessResolver
  impl aitm_core::peer::PeerResolver for ProcessResolver {
      fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String> { self.inner.resolve(Tuple { client: peer, proxy: local }) }
  }
  ```
  `NoScanner` (other OS): `find_owners` → empty, `identity` → `None`.
- **Test:**
  - `identity_for_path_fixtures` (sandbox, macOS): `identity_for_path("/usr/bin/curl") == Some("curl")`;
    `identity_for_path("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking") == Some("com.apple.WebKit.Networking")`
    (reads the real system bundle; `#[ignore]`-free because the path exists on every macOS 26+);
    `identity_for_path("/nonexistent/Foo.app/Contents/MacOS/Foo") == Some("Foo")` (bundle read
    fails → basename).
  - `resolve_names_this_process` (Terminal): listener `127.0.0.1:0`, connect, accept;
    `ProcessResolver::for_tests(Limits::default(), None).resolve(accepted.peer_addr()?, accepted.local_addr()?)`
    `== Some(s)` with `s.starts_with("aitm_peer_process")`.
  - `resolve_skips_own_pid_in_production_shape` (Terminal): the same pair with
    `ProcessResolver::new()` → `None` (our own socket is the only owner and it is skipped).
  - `non_macos_resolver_is_none` (`cfg(not(any(macos, linux)))`).
- **Done when:** sandbox tests green; Terminal run quoted; `cargo test --offline -p aitm-peer-process`
  and clippy/fmt clean for the package.
- **Amendment 2026-11-01 (F2):** `MacScanner::find_owners_among` delegates to
  `ffi::find_owners_among_raw(wanted, deadline, skip_pid, pids)`, the per-pid body of
  `find_owners_raw` factored into `walk_pids`; a pid whose `socket_fds` is `None` **or empty** is
  `gone` (`Probe::gone` contract: fd table unreadable or no socket fd at all, same on both
  platforms; Q2, 2026-11-01). `LinuxScanner::find_owners_among` reads the tables as before and
  walks only the given `/proc/<pid>` dirs through the shared per-pid body
  `owners_of_pid(pid, &mut inodes, deadline, &mut owners) -> PidWalk { Socketless, Walked, Expired }`;
  only the probe pushes `Socketless` to `gone`, and a probe whose tuples have no table row walks no
  pid (Q6, Q7, 2026-11-01). Tests: `ffi::tests::
  a_targeted_probe_reports_unreadable_pids_gone` (sandbox: pid 1 EPERM and `i32::MAX` ESRCH are
  `gone`), `ffi::tests::warm_probe_names_this_process_without_a_full_scan` (Terminal),
  `linux::scan::tests::a_targeted_probe_walks_only_the_given_pids_and_reports_the_idle_ones`
  (fixture). `NoScanner::find_owners_among` → `Probe::default()`. The e2e cell's step 4 becomes a
  hard check that all 20 latency rows carry a python `source_app`.

### Task 6: `aitm-core` — `PeerResolver`, builder step, `handle_conn` concurrency and budget

- **Satisfies:** AC1, AC2, AC3, AC4, AC5
- **Depends on:** none (parallel with Task 1)
- **Files:** `crates/aitm-core/src/peer.rs` (create), `crates/aitm-core/src/lib.rs` (modify:
  `pub mod peer; pub use peer::PeerResolver;`), `crates/aitm-core/src/proxy.rs` (modify),
  `crates/aitm-core/src/protocol.rs` (modify: doc comments of `peer_identity`/`capture_interface`
  per spec D7 + one test), `crates/aitm-core/src/flow.rs` (modify: doc comment of `source_app`
  / `capture_interface` lines 407-416, wording only)
- **Change:**
  ```rust
  // peer.rs
  pub trait PeerResolver: Send + Sync + 'static { fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String>; }
  pub const ATTRIBUTION_BUDGET: Duration = Duration::from_millis(25);
  pub fn is_loopback_peer(ip: IpAddr) -> bool;
  pub(crate) fn start_attribution(resolver: Option<&Arc<dyn PeerResolver>>, peer: SocketAddr, local: Option<SocketAddr>) -> Option<JoinHandle<Option<String>>>;
  pub(crate) const MAX_IN_FLIGHT: usize = 64;  // S1 (2026-11-01): process-wide in-flight cap; start_attribution → None when no permit
  fn start_attribution_with(slots: &Arc<tokio::sync::Semaphore>, ..)  // the form tests drive with their own pool; resolve runs under catch_unwind (Q1)
  pub(crate) async fn finish_attribution(task: Option<JoinHandle<Option<String>>>, budget: Duration) -> Option<String>;
  // proxy.rs
  struct ProxyInner { .., peer_resolver: Option<Arc<dyn PeerResolver>> }
  pub struct ProxyBuilder { .., peer_resolver: Option<Arc<dyn PeerResolver>> }
  impl ProxyBuilder { pub fn with_peer_resolver(mut self, resolver: Arc<dyn PeerResolver>) -> Self; }
  // handle_conn: before the peek
  let local = stream.local_addr().ok();
  let attribution = peer::start_attribution(inner.peer_resolver.as_ref(), peer, local);
  // after the peek
  let peer_identity = peer::finish_attribution(attribution, peer::ATTRIBUTION_BUDGET).await;
  // hint: peer_identity, capture_interface: None  (comment rewritten per D7 and the tunnel_authority invariant)
  ```
  `tracing::debug!` on a resolved identity's presence (`resolved = identity.is_some()`),
  `tracing::warn!(%peer, ..)` once per process when the resolver panics (then `debug!`),
  `tracing::debug!` on a join error; never the string, never a pid or path.
- **Test:**
  - `peer::tests::loopback_classification`: the eight `is_loopback_peer` literals of AC1.
  - `peer::tests::non_loopback_peer_spawns_no_task` (sandbox, `#[tokio::test]`): `CountingResolver`
    (`AtomicUsize`) with `10.0.0.1:5000` and `[2001:db8::1]:5000` → `None`, count `0`;
    `127.0.0.1:5000`, `[::1]:5000`, `[::ffff:127.0.0.1]:5000` → `Some`, awaited count `3`.
  - `peer::tests::finish_within_budget_flattens`: task returning `Some("x")` → `Some("x")`; task
    sleeping 200 ms with budget 10 ms → `None` in under 100 ms.
  - `peer::tests::the_sixty_fifth_concurrent_attribution_is_refused_without_a_spawn`,
    `peer::tests::in_flight_cap_is_sixty_four`,
    `peer::tests::a_panicking_resolver_yields_none_not_an_error` (S1, Q1, 2026-11-01).
  - `proxy::tests::resolver_result_reaches_the_hint` (Terminal): `RecordingModule` (claims all,
    stores `hint.clone()` in a `Mutex<Option<NextLayerHint>>`), resolver returning
    `Some("curl-test")`, `Proxy::run_on(TcpListener::bind("127.0.0.1:0"))` in a task, connect, write
    `b"GET / HTTP/1.1\r\n\r\n"`, wait → `hint.peer_identity == Some("curl-test")`,
    `hint.capture_interface == None`.
  - `proxy::tests::slow_resolver_yields_none_within_budget` (Terminal): resolver sleeps 500 ms →
    `peer_identity == None`, elapsed from connect to module spawn `< 400 ms`.
  - `proxy::tests::no_resolver_means_no_identity` (Terminal): default builder → `None`.
  - `protocol::tests::tunnel_authority_ignores_peer_identity_on_the_proxied_path`: AC5 literal →
    `Some(Authority::new("example.com", 443))`.
- **Done when:** sandbox tests green; the Terminal run of `cargo test -p aitm-core` quoted green
  (all pre-existing tests unchanged); clippy/fmt clean for the package.

### Task 7: wire the real resolver; wording in plugins and docs

- **Satisfies:** AC16, D2 (wiring), D7
- **Depends on:** Tasks 5, 6
- **Files:** `crates/aitm/Cargo.toml` (modify: `aitm-peer-process.workspace = true` under
  `[dependencies]` with a comment mirroring the `aitm-peer-token` one), `crates/aitm/src/wire.rs`
  (modify: line 406), `crates/aitm-plugins/src/capture.rs` (modify: wording at 74, 191, 198, 303,
  309, 451, 458, 467), `crates/aitm-plugins/src/detail.rs` (modify: 316-320),
  `docs/design/operator-ui-foundation.md` (modify: line 395 + one sentence after the table)
- **Change:** `Proxy::builder().with_config(cfg.clone()).with_peer_resolver(Arc::new(aitm_peer_process::ProcessResolver::new()))`
  with a comment: "names the loopback client of every proxied connection (spec
  2026-11-01-proxied-client-attribution); `capture_interface` stays null on this path". Wording:
  "null unless the core could name the client" everywhere, keeping the word "proxied" in the two
  `ParamDef` descriptions, e.g. "Identifier of the app that opened the connection: a capture
  backend's observation, or the core's own resolution of a proxied loopback client; null when
  neither could name it." and "Capture backend that delivered the connection (`macos-ne`); null
  for a proxied flow." (the second sentence is still exactly true).
- **Test:** `cargo test --offline -p aitm-plugins` (the two pins
  `schemas_declare_source_app_and_capture_interface`, `flow_get_and_table_report_source_app` stay
  green); `grep -rn "null for a proxied" crates docs/design` lists only the `capture_interface`
  descriptions; `cargo build --offline -p aitm` succeeds; a manual Terminal smoke:
  `target/debug/aitm --config <tmp> &` then `curl -sS -x http://127.0.0.1:<port> http://127.0.0.1:<upstream>/x`
  and `flow.table` over the bus shows `"source_app": "curl"` (quoted in the Coder's report; this
  is the first live proof and goes into the PR body).
- **Done when:** full Rust gate green from the Terminal; the smoke quoted.

### Task 8: e2e — the positive cell and the rewrite of the proxied-null cell

- **Satisfies:** AC10, AC11, AC12, AC13, AC16 (the e2e half)
- **Depends on:** Task 7 (for the proof; authoring may begin after Task 6)
- **Files:** `tests/e2e/proxy/test_client_attribution.py` (create),
  `tests/e2e/flow/test_source_app_null_on_proxied.py` (modify), `tests/e2e/proxy/README.md`
  (modify: one bullet)
- **Change:** new cell header `# e2e: tier=T1 surface=proxy needs=openssl`, docstring stating
  the four proofs, reusing `aitm_e2e` (`Aitm.server`, `BusClient.operator`, `Upstream`,
  `proxyutil.via_proxy`, `tls.{have, curl, curl_code, ca_cert, start_https_echo, upstream_cert}`)
  and `_clients.ProxyConfig`. Steps:
  1. boot a core (`scope_entries=[]`), `Upstream().start()`; `curl -sS -m 15 -x http://127.0.0.1:<proxy> <up>/attr-<uuid>`;
     poll `flow.table` for the row; check `isinstance(source_app, str) and "curl" in source_app.lower()`,
     `capture_interface is None`; `flow.detail {"id": id}` → `client_conn.process == source_app`.
  2. `via_proxy(proxy_port, "GET", f"{up.base}/py-<uuid>")` → row `source_app.lower()` contains
     `"python"`, `capture_interface is None`.
  3. `scope.add 127.0.0.1`; `start_https_echo(*upstream_cert(work))`;
     `curl --cacert <ca> -m 15 -x … https://127.0.0.1:<tls>/attr-<uuid>` → the `CONNECT` row for
     `127.0.0.1:<tls>` and the `GET` row both carry `"curl"` in `source_app`, `capture_interface` null.
  4. 20 sequential `via_proxy` GETs timed with `time.perf_counter`; print
     `median_ms=<value>`; check `median < 100`.
  Skip (77) when `curl` or `openssl` is missing or on an OS where the resolver is `None` by
  design (`sys.platform not in ("darwin", "linux")`). Exit 0 on pass, non-zero on fail.
  Rewrite of the flow cell per spec D8: `both_null` becomes `capture_null_and_source_consistent`:
  `capture_interface` key present and `None`; `source_app` key present and (`None` or a `str` not
  in `PLACEHOLDERS`); the three surfaces agree; docstring and title updated; the schema
  "proxied" check kept.
- **Test:** from the Terminal: `python3 tests/e2e/proxy/test_client_attribution.py` → exit 0 with
  `[ok]` lines for each AC and the printed median; `python3 tests/e2e/flow/test_source_app_null_on_proxied.py`
  → exit 0; `python3 tests/e2e/run.py proxy flow` green.
- **Done when:** both cells quoted green from the Terminal; the full Rust gate green; the PR body
  carries the macOS live proof (AC17) and names the Linux live proof as a follow-up.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 3 | orchestrator (Terminal live run) | Critical | F1 `socket_fdinfo` mirror used `soi_kind`/`soi_proto` at 232/240 (offsets inside `socket_info`); every socket read `soi_kind == 0`, nothing matched | fixed in 5b7971d0 (absolute 256/264, C `offsetof` probe; spec AC8 + research 24 corrected) |
| 2, 5 | orchestrator (Terminal live run) | Important | F2 20 rapid sequential GETs named only 14 rows: every connection paid a full, token-limited scan | fixed in 28ff96f4 (warm-pid MRU probe first, full scan only on miss, bucket 20/20; e2e asserts all 20 rows named) |
| 2 | quality, tester | Important | Q1 / T-F1 a panicking scanner leaves `scanning = true` forever; JoinError swallowed silently | fixed in d3e949fc (`ScanGuard` drop guard, `catch_unwind` + `warn!` in the blocking task; two tests) |
| 6 | security | Minor | S1 one `spawn_blocking` per loopback connection, no in-flight cap; non-leader waits the 250 ms deadline | fixed in d3e949fc (`MAX_IN_FLIGHT = 64` semaphore, `try_acquire_owned` → `None`) |
| 1 | security | Minor | S2 sanitiser passed whitespace-only / Zl / Zp / non-ASCII Zs identities | fixed in 8a6e3960 |
| 3, 4 | security | Minor | S3 scan deadline checked between pids only | fixed in 8a6e3960 (`FD_DEADLINE_STRIDE = 64`) |
| 3 | security | Minor | S4 ffi module doc overstated the pin test; unsafe count is 10 (coder said 8) | fixed in 8a6e3960; 10 blocks signed off in the security report |
| 2, 3, 4, 5, 8 | quality | Minor | Q2 `Probe::gone` platform mismatch; Q3 ffi over-visibility; Q4 `len` allow; Q5 duplicated `Limits`; Q6 `walk_pids(report_gone)`; Q7 warm-order comment; Q8 test hygiene; Q9 e2e scratch dir | fixed in 7aab1f88 + e28dcb4d |
| 7 | spec | Important | P1 AC16 grep hit in `crates/aitm-plugins/tests/capture.rs:843` | fixed in faad7ee9 (tester) |
| plan | spec | Important | P2 F2 amendment swallowed the `### Task 6` heading | fixed in 8015c9e2 |
| 4 | spec | Important | P3 Linux glue is `cfg(any(linux, test))` + root-path fixture tests, plan said `cfg(linux)` and no fixture test | accepted by the orchestrator 2026-11-01 (autonomous mode): fixture tests are real coverage of the walk and the test-only build does not ship; plan Task 4 + spec Constraints amended in 8015c9e2; Linux cross-check "unverified on this Mac" quoted there |
| spec | spec | Minor | P4 stale 10/10 bucket sentences; P7 D9 five-signal telemetry never emitted | fixed in 8015c9e2 (20/20; D9 presence-only) |
| 2, 5 | spec | Minor | P5 attribute-only edits outside declared files; P6 fix 5b7971d0 edited spec AC8 + research 24; P8 Task 8 passes `"body": "none"` | accepted by the orchestrator 2026-11-01 (expected consequence of staged scaffolding allows; orchestrator-directed AC correction; documented parameter) |
| whole | tester | Minor | T-F2 AC16 literal grep hits archival 2026-10-31 spec/plan and this spec quoting the phrase | accepted by the orchestrator 2026-11-01; AC16 scope set to `crates docs/design` in 11c1b107 |
| 2, 3, 4, 5 | quality (re-check) | Minor | Q10 `with_limits` routed through `for_tests`; Q11 `ScanGuard::drop` duplicated the scan tail; Q12 guard safety rests on declaration order; Q13 two `Arc` scanner impls; Q14 `PanickingScanner::panics` one-valued; Q15 `FD_DEADLINE_STRIDE` twice | fixed in 4e158b1a (Q12: the proposed `try_lock` variant was shown unsound by a contention test; blocking `lock()` kept, invariant documented and pinned) |
| 4, 6 | security (re-check) | Minor | S5 Linux `socket_inodes` readlink walk had no deadline stride; S6 panic `warn!` unbounded per connection | fixed in 4e158b1a |
| spec, plan | spec (re-check) | Important | P9 spec D3/D5/D9/AC9 described pre-fix behaviour (S1 cap, ScanGuard, stride, S2 whitespace, panic logging, `for_tests`) | fixed in 11c1b107 |
| plan | spec (re-check) | Minor | P10-P12 plan Tasks 2-6 stale signatures; P13 AC16 self-contradictory | fixed in 11c1b107 |
| integration | orchestrator | Minor | Second main merge for the orchestrator's gate: origin/main 2044ac52 (#282, aitm-mcp verbs/pins) merged as 3aa78d87 with no conflicts (first merge 446bca30 of c99ea718 resolved two additive conflicts: `aitm-core/src/lib.rs` mod/use lines kept both sides, `aitm/src/wire.rs` builder line keeps main's scanner block plus `.with_peer_resolver`). Targeted gate on 3aa78d87 (fmt, clippy -D warnings, `cargo test --no-fail-fast -p aitm-core -p aitm-mcp -p aitm`): 87 suites green, 1 red = `aitm audit_log::tests::a_wedged_rotation_holds_the_file_to_twice_its_cap` under load avg 95-200, 3/3 green alone right after; both e2e cells exit 0 (all 20 rows named) | diff vs main unchanged by the merges, panel coverage stands; flake accepted as load noise by the orchestrator 2026-11-01 |
| gate | orchestrator | Minor | Full-gate noise under load avg 150-250 (sibling worktrees building): `aitm audit_log::tests::a_wedged_rotation_holds_the_file_to_twice_its_cap` red once (3/3 green alone, file untouched); `aitm tests/web_bus_write_deadline` pair and `aitm-plugin-rhai engine::each_run_gets_a_fresh_budget_and_exposes_its_deadline` (known flakes, memory `aitmproxy-load-flaky-tests`); `aitm-core tests/redact_strict` rows "no result within 60 s" (HOSTILE_SECS budget at load ~200; redaction untouched) | accepted as load noise by the orchestrator 2026-11-01; gate 1 (28ff96f4) exit 0 clean; final gate quoted in the PR |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
