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
    impl Default for Limits  // 250 ms, 10, 10, 256
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
      pub(crate) fn len(&self) -> usize;
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
  Safe wrappers (each `Option`/`Vec`, fail-closed):
  ```rust
  pub(crate) fn list_pids() -> Vec<u32>;                               // proc_listpids(PROC_ALL_PIDS), two-call sizing
  pub(crate) fn socket_fds(pid: u32) -> Option<Vec<i32>>;              // PROC_PIDLISTFDS, filtered to PROX_FDTYPE_SOCKET; None on EPERM/ESRCH
  pub(crate) struct TcpSocket { pub laddr: IpAddr, pub lport: u16, pub faddr: IpAddr, pub fport: u16 }
  pub(crate) fn tcp_socket(pid: u32, fd: i32) -> Option<TcpSocket>;    // PROC_PIDFDSOCKETINFO; None unless soi_kind == SOCKINFO_TCP and the full 792 bytes were written; ports via port_from_libproc; addresses per insi_vflag
  pub(crate) fn pid_path(pid: u32) -> Option<String>;                  // proc_pidpath into a 4096-byte buffer
  pub(crate) fn pid_name(pid: u32) -> Option<String>;                  // proc_name into a 256-byte buffer
  pub(crate) fn pid_start_micros(pid: u32) -> Option<u64>;             // PROC_PIDTBSDINFO → pbi_start_tvsec*1_000_000 + pbi_start_tvusec
  pub(crate) fn find_owners_raw(wanted: &[Tuple], deadline: Instant, skip_pid: Option<u32>) -> HashMap<Tuple, ProcessKey>;
  ```
  `find_owners_raw`: pids ascending, skip `skip_pid`, deadline checked per pid, `socket_fds` →
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

### Task 4: Linux scanner glue (cfg-gated)

- **Satisfies:** the Linux half of D2/D4/D5 (live proof is the follow-up named in the spec)
- **Depends on:** Task 1
- **Files:** `crates/aitm-peer-process/src/linux/scan.rs` (create), `src/linux/mod.rs` (modify:
  `#[cfg(target_os = "linux")] pub(crate) mod scan;`)
- **Change:**
  ```rust
  pub(crate) struct LinuxScanner { pub(crate) skip_pid: Option<u32>, uid: u32 }
  impl LinuxScanner { pub(crate) fn new() -> Self; }  // uid via std::os::unix::fs::MetadataExt on /proc/self (no libc dep)
  impl SocketScanner for LinuxScanner {
      fn find_owners(..)  // read /proc/net/tcp and tcp6, parse_tcp_row, match wanted by (local==client, remote==proxy) after canonical(); row.uid must equal self.uid; inode → walk /proc/[0-9]+/fd ascending, readlink, fd_socket_inode == inode; skip skip_pid; deadline per pid; ProcessKey.start from parse_stat_starttime(/proc/<pid>/stat)
      fn identity(..)     // exe_basename(readlink /proc/<pid>/exe) else /proc/<pid>/comm trimmed
  }
  ```
- **Test:** the parsers are Task 1's. Here: `cargo check --offline -p aitm-peer-process --target x86_64-unknown-linux-gnu`
  if that target's std is installed (`rustup target list --installed`); otherwise the Coder
  reports "Linux glue unverified on this Mac" and the Tester notes it. No fixture-only test for the
  glue (memory `aitmproxy-no-fixture-ui-evidence` spirit: the proof is the follow-up on a Linux host).
- **Done when:** the Mac build is unaffected (`cargo test --offline -p aitm-peer-process` still
  green) and the cross-check result is quoted either way.

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
      #[doc(hidden)] pub fn with_skip_pid(self, skip: Option<u32>) -> Self;   // tests only
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
    `ProcessResolver::new().with_skip_pid(None).resolve(accepted.peer_addr()?, accepted.local_addr()?)`
    `== Some(s)` with `s.starts_with("aitm_peer_process")`.
  - `resolve_skips_own_pid_in_production_shape` (Terminal): the same pair with
    `ProcessResolver::new()` → `None` (our own socket is the only owner and it is skipped).
  - `non_macos_resolver_is_none` (`cfg(not(any(macos, linux)))`).
- **Done when:** sandbox tests green; Terminal run quoted; `cargo test --offline -p aitm-peer-process`
  and clippy/fmt clean for the package.

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
  `tracing::debug!` on a resolved identity's presence (`resolved = identity.is_some()`), never the
  string.
- **Test:**
  - `peer::tests::loopback_classification`: the eight `is_loopback_peer` literals of AC1.
  - `peer::tests::non_loopback_peer_spawns_no_task` (sandbox, `#[tokio::test]`): `CountingResolver`
    (`AtomicUsize`) with `10.0.0.1:5000` and `[2001:db8::1]:5000` → `None`, count `0`;
    `127.0.0.1:5000`, `[::1]:5000`, `[::ffff:127.0.0.1]:5000` → `Some`, awaited count `3`.
  - `peer::tests::finish_within_budget_flattens`: task returning `Some("x")` → `Some("x")`; task
    sleeping 200 ms with budget 10 ms → `None` in under 100 ms.
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

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
