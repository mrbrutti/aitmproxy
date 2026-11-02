# Proxied client attribution — design

**Status:** approved — self-approved 2026-11-01 by the orchestrator session (autonomous mode)
**Research inputs:** `docs/research/24-loopback-peer-process-resolution.md` (primary),
`docs/research/23-macos-observe-only-lane.md` §3.5 (F5), `docs/research/21-macos-app-icon-resolution.md`
(Q1, Q2, Q5: what the Kit does with an identifier), prior spec
`docs/superpowers/specs/2026-10-31-ne-source-app-on-the-wire-design.md` (the plumbing this reuses).
Two measurements taken while writing this spec (2026-11-01, macOS 27.0, this Mac, C probes in
`$TMPDIR`) are quoted in the evidence table and in D5.
**Branch / worktree:** `claude/friendly-tu-2d144a` (this worktree, at main `f6fe1a14`).

## Intent

Today only the macOS Network Extension fills `FlowMeta.source_app`, so every proxied row —
`curl -x 127.0.0.1:8080`, a browser pointed at the proxy, the embedded obscura browser — shows
Client "—" in every UI. The core accepted that connection and knows the client's loopback
`ip:port`; the process that owns the other end can be found without privileges and without an
extension (the way Proxyman does it with the NE off): on macOS a libproc socket scan of same-user
processes, on Linux `/proc/net/tcp{,6}` → inode → `/proc/*/fd`. This change makes the core name the
client process of every proxied connection whose peer is loopback and put that name in the slot
PR #195 already plumbed end to end (`NextLayerHint::peer_identity` → `FlowMeta::source_app` →
`flow.get`/`flow.table`/`flow.detail.client_conn.process`/push summary/session files/mac Kit). Done
when a real `curl -x` through a real core shows Client `curl` in `flow.table`.

## Goals

- A plain or CONNECT request from a loopback client through either listener (client-facing or
  browser-facing) stores `FlowMeta::source_app = Some(<identity>)` when the core could name the
  client within the budget; `capture_interface` stays `None` on every proxied flow.
- The identity vocabulary is one the mac Kit already renders (`AppIdentifier`, `ClientInfo.displayName(forSourceApp:)`):
  a bundle identifier when the client runs from a bundle (`com.apple.Safari`,
  `com.apple.WebKit.Networking`, `com.google.Chrome.helper.renderer`, `com.apple.python3`), else the
  executable's basename (`curl`, `python3.14`, `node-5555…` which the Kit trims). The TUI and web
  Client columns show the same string via `client_conn.process`.
- No measurable latency: resolution starts at accept, runs on a blocking thread concurrently with
  the peek, and the connection waits for it at most 25 ms after the peek; on timeout the flow
  proceeds with `None`.
- Zero configuration, zero privileges, zero new wire fields, zero new bus verbs.
- Default-off in `aitm-core`: a `Proxy` built without a resolver behaves exactly as today, so every
  existing test is untouched.

## Non-goals

- UDP / L4 flows (`L4Meta`, `L4FlowStore`); they are a different record.
- Resolving non-loopback peers (a LAN client using the Mac as its proxy). Never attempted (D1).
- Naming root or other-user clients (`trustd`, `mDNSResponder`). The kernel refuses the fd read
  (`EPERM` on 361 of 1 583 pids in research 24 §3.1); they stay `None`, never a guess.
- The "responsible process" walk (`WebKit.Networking` → Safari). `responsibility_*` is private
  SPI (research 24 §3.3); the Kit already labels the shared WebKit services honestly.
- Any change under `apps/mac/**`. The Kit already turns every string this spec emits into an icon
  and a name (research 21; `AppIdentifier.trimmedAdHoc`, `knownUnbundled`, `fallbackName`). The
  three stale "Nil for a proxied flow" comments in `FlowSummary.swift` are a follow-up for the mac
  queue, not this change (a Swift edit would pull the Swift gate into a core PR).
- Icons, display names, localisation: the UIs' job, from the string.
- A `.desktop` lookup on Linux; Linux identity is the executable basename.
- Late delivery of a slow answer (a `ClientResolved`-style event): a connection that misses the
  budget stays `None` forever (D3). The per-process cache makes the next connection hit.
- Emitting more than one string (`pid`, `path`, `owner_pid`): research 24 §4 floats it; the wire
  stays as PR #195 left it (brief: no new fields unless a real need appears; none did).

## Anti-goals

- A placeholder where the core has no identity: never `"unknown"`, `""`, `"proxy"`, a pid, or a
  path. Unknown is `None`.
- Leaking anything but the identity: never the executable path (`/Users/matt/…` names the user and
  the project), never argv/`cmdline`/`environ`/`KERN_PROCARGS2`, never a log line at `info` carrying
  the string. The identity is data about a client: stored and shown, never a scope, guard or
  routing input.
- Touching vnode fds (`PROC_PIDFDVNODEPATHINFO`): a process stuck on an SMB share hangs the caller
  indefinitely (research 24 §3.1). Socket fds only.
- A scan per accept under a connection flood (a scan is ~7 ms of CPU on 1.5k pids): the rate limit
  (D3) bounds scans per second; attribution degrades to `None`, the proxy does not slow down.
- Filling `capture_interface` on the proxied path. `NextLayerHint::tunnel_authority`
  (`crates/aitm-core/src/protocol.rs:80-105`) reads `capture_interface.is_some()` as "came from a
  capture ingress, so `dst` is the real destination"; a proxied hint with it set would pick the
  wrong port for an SNI-only tunnel. `source_app` non-null with `capture_interface` null is the
  defined shape for "explicit proxy, client named by the core".
- Pulling bindgen, `libproc`, `plist`, `procfs` or any new third-party crate. The sandbox cannot
  fetch; the lock gains no new crate.

## Constraints

- Rust gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- Workspace `[workspace.lints.rust] unsafe_code = "forbid"` (`Cargo.toml:46-49`). The one
  precedent for isolated unsafe is `crates/aitm-peer-token`: its `Cargo.toml` restates
  `[lints.rust] unsafe_code = "deny"`, one `#[allow(unsafe_code)]` site, macOS-only `libc` dep,
  fail-closed `Option`. The new leaf crate copies that pattern; every `unsafe` block carries a
  `// SAFETY:` comment and is signed off in the Security reviewer's report (WORKFLOW rule).
- `libc` 0.2.191 (cached) has `proc_listpids`, `proc_pidinfo`, `proc_pidfdinfo`, `proc_pidpath`,
  `proc_name`, `proc_fdinfo`, `proc_bsdinfo`, `PROC_PIDLISTFDS`, `PROX_FDTYPE_SOCKET`,
  `PROC_PIDTBSDINFO`, but **not** `socket_fdinfo`, `in_sockinfo`, `SOCKINFO_TCP`,
  `PROC_PIDFDSOCKETINFO`, `PROC_ALL_PIDS`. The crate owns a minimal `#[repr(C)]` mirror of
  `struct socket_fdinfo` (792 bytes; offsets in research 24 §3.1, header
  `$(xcrun --show-sdk-path)/usr/include/sys/proc_info.h`) pinned by size/offset tests.
- Dependencies allowed in the leaf crate: `libc` 0.2 and `core-foundation` 0.10 (both macOS-only,
  both already in `Cargo.lock` — `core-foundation 0.10.1` is a direct macOS dependency of `aitm`),
  `aitm-core` (for the trait). Nothing else.
- Tests that bind a loopback socket (the self-resolution tests, the `aitm-core` acceptor tests, the
  e2e cell) run from the Terminal panel, not the Claude sandbox (memory
  `aitmproxy-sandbox-no-socket-binds`). Parsers, the match rule, the sanitiser, the coalescer and
  the layout pins run anywhere.
- Linux is implemented but live-proven on a Linux host as a follow-up (D-h). The Linux glue is
  `cfg(target_os = "linux")`; its parsers are portable and fixture-tested on the Mac.
- `rust-version = "1.97"`: `std::mem::offset_of!` is available for the layout pins.
- Load: the e2e timing bound must survive a loaded Mac (memory `aitmproxy-load-flaky-tests`); it is
  a generous absolute bound, printed, not a differential measurement.

## Design

### Evidence (verified 2026-11-01 in this worktree at `f6fe1a14`)

| Fact | Where | Consequence |
|---|---|---|
| Acceptor: `accept_loop` → `tokio::spawn(handle_conn(inner, stream, peer, ssrf))`; `handle_conn` peeks 2048 bytes, then builds `NextLayerHint { .., peer_identity: None, capture_interface: None }` | `crates/aitm-core/src/proxy.rs:150-160` (spawn), `:218-250` (peek + hint) | Both listeners (`run_on` client-facing, `run_browser_on` obscura) go through it: one change point |
| `ProxyBuilder { config, modules, plugins }` with `with_config / register_module / register_plugin / build`; `ProxyInner { registry, store, guard, chain, modules, browser_ssrf, egress }` | `proxy.rs:409-490`, `:27-38` | Add one builder step and one `ProxyInner` field |
| `crates/aitm/src/wire.rs:406` `let mut builder = Proxy::builder().with_config(cfg.clone());` | wire.rs | The one production call site to wire the real resolver |
| Downstream of the hint everything exists (PR #195): `Conn::with_attribution(ctx.hint())` at `module.rs:283, 414, 560`; `Conn::flow_meta()` `:1046`; `tunnel_request()` copies both onto CONNECT rows `:779`; upgrade hint re-carries `:1624`; WS inherits; passthrough copies `hint.peer_identity`; `capture.rs:321-324` emits `source_app`/`capture_interface`; `detail.rs:183,199,321-330` emits `client_conn.process` from `source_app`; `aitm-mcp flow_summary` pushes them; sessionio round-trips | cited files | The change is exactly: fill `peer_identity` on the proxied path |
| `tunnel_authority` keys on `capture_interface.is_some()` | `protocol.rs:80-105` | `capture_interface` MUST stay `None` on the proxied path |
| TUI Client column reads `client_conn.process` (`model.rs:226-230, 388-401`); web `apps/web/src/bus/normalize.ts:117,197` reads `client_conn` | cited files | TUI and web light up with no change |
| Mac Kit: `AppIdentifier.candidates/trimmedAdHoc/fallbackName/knownUnbundled`, `ClientInfo.displayName(forSourceApp:)` turn a bundle id or a bare name into icon + name; `node-<hex>` tails stripped; WebKit services labelled honestly | `apps/mac/Sources/AitmproxyKit/AppIdentifier.swift` | No mac change needed |
| Workspace forbids unsafe; `aitm-peer-token` is the precedent (deny + one allow, macOS-only libc) | `Cargo.toml:46-49`, `crates/aitm-peer-token/{Cargo.toml,src/lib.rs:47}` | New leaf crate copies the pattern |
| Full libproc scan of 1 583 pids: 6.8-7.05 ms; `proc_listpids` 0.12-0.22 ms; `proc_pidpath` ~8 µs each; `PIDLISTFDS` ok for 1 222 pids, `EPERM` for 361 (all other-user) | research 24 §3.1-3.2 (V) | Budget and rate limit are sized on this |
| `insi_lport`/`insi_fport`: network order in the low 16 bits of a 4-byte int (sequential listeners read 0x406f, 0x416f, 0x426f → `ntohs` gives 28480, 28481, 28482) | research 24 §3.1 (V) | Match rule: `u16::from_be(raw as u16)` |
| `socket_fdinfo` layout: size 792; `psi` at 24; `soi_kind` at 256; `soi_proto` at 264 (232/240 inside `socket_info`, which starts at 24; `soi_proto` union is 528 bytes; corrected 2026-11-01 by a C `offsetof` probe); in `in_sockinfo` (80 bytes): `insi_fport` 0, `insi_lport` 4, `insi_vflag` 24, `insi_faddr` 32, `insi_laddr` 48; `tcpsi_state` at 80 of the 120-byte `tcp_sockinfo`; `SOCKINFO_TCP` = 2; `PROC_PIDFDSOCKETINFO` = 3; `PROC_ALL_PIDS` = 1; `PROX_FDTYPE_SOCKET` = 2; `INI_IPV4` = 1, `INI_IPV6` = 2; address unions are `in4in6_addr` (`i46a_pad32[3]`, then `i46a_addr4`) or `in6_addr` | research 24 §3.1 (V, C `offsetof` probe) | The mirror and its pin test |
| **Measured here:** `SecCodeCopyGuestWithAttributes(kSecGuestAttributePid)` + `SecCodeCopySigningInformation`: first lookup in a fresh process 51-82 ms (pid 1, `/bin/sleep`), warm Apple-signed pids 0.4-0.7 ms, an **ad-hoc-signed** binary 45-53 ms on **every** call | C probe, 2026-11-01 | Option A of D-e rejected (D5) |
| **Measured here:** `CFBundleCreate` + `CFBundleGetIdentifier`: Safari.app (cryptex path, cold) 113 ms once, then 0.01 ms; Python.app 1.57 ms, WebKit.Networking.xpc 0.89 ms, Google Chrome.app 1.07 ms, Xcode.app 1.93 ms cold, all 0.01 ms warm. `core-foundation 0.10.1` exposes `CFBundle::new(CFURL) -> Option<CFBundle>`, `info_dictionary()`, `CFURL::from_path` safely | C probe + `~/.cargo/registry/src/*/core-foundation-0.10.1/src/{bundle,url}.rs` | Option B is cheap and unsafe-free |
| `/usr/bin/python3` is the xcode-select shim (signing id `com.apple.dt.xcode_select.tool-shim-public`) that execs `…/Python3.framework/…/Python.app/Contents/MacOS/Python` whose bundle id is `com.apple.python3`; `/usr/bin/curl` → `com.apple.curl`, no bundle | research 24 §3.3, §3.6; `codesign -dv` here | Innermost-bundle rule; `curl` is a bare basename |
| Existing pins of today's null: `tests/e2e/flow/test_source_app_null_on_proxied.py` asserts BOTH keys null on a proxied flow; `crates/aitm-plugins/tests/capture.rs:790-850` asserts each description contains the word "proxied" and the store-level null | cited files | The e2e cell is rewritten (D8); the Rust test keeps passing if the new descriptions keep the word "proxied" |

### D1. Loopback peers only; never fail the flow (decided by the orchestrator, D-a)

Resolution is attempted iff `is_loopback_peer(peer.ip())`: `127.0.0.0/8`, `::1`, or an IPv4-mapped
`::ffff:127.0.0.0/8`. Any other peer never calls the resolver (no task is spawned). Any error,
timeout, unreadable process, ambiguous or missing match gives `peer_identity: None`. Nothing on
this path can return an error to `handle_conn`; the connection is served exactly as today.

### D2. Where it lives: a leaf crate plus a small trait in `aitm-core` (decided, D-b)

- New leaf crate `crates/aitm-peer-process` (workspace member, alias
  `aitm-peer-process = { path = … }`), modelled on `aitm-peer-token`: `[lints.rust] unsafe_code = "deny"`,
  unsafe confined to `src/macos/ffi.rs` behind safe wrappers, each `unsafe` block with a `// SAFETY:`
  comment. Dependencies: `aitm-core` (the trait); `[target.'cfg(target_os = "macos")'.dependencies]`
  `libc = "0.2"`, `core-foundation = "0.10"`. No tokio: the resolver is synchronous.
- `aitm-core` gains `crates/aitm-core/src/peer.rs` (`pub mod peer;` in `lib.rs`, `pub use peer::PeerResolver;`):

  ```rust
  pub trait PeerResolver: Send + Sync + 'static {
      /// Name the process owning the client end of an accepted connection. `peer` is the
      /// client's address, `local` the accepted socket's own address. Blocking: called on a
      /// blocking thread. `None` means unknown, never a placeholder.
      fn resolve(&self, peer: SocketAddr, local: SocketAddr) -> Option<String>;
  }
  pub const ATTRIBUTION_BUDGET: Duration = Duration::from_millis(25);
  pub fn is_loopback_peer(ip: IpAddr) -> bool;
  ```

  `ProxyBuilder::with_peer_resolver(self, r: Arc<dyn PeerResolver>) -> Self`; `ProxyInner` gains
  `peer_resolver: Option<Arc<dyn PeerResolver>>`. Default `None` = today's behaviour.
- `crates/aitm/src/wire.rs:406` becomes
  `Proxy::builder().with_config(cfg.clone()).with_peer_resolver(Arc::new(aitm_peer_process::ProcessResolver::new()))`.
  `ProcessResolver` implements `aitm_core::peer::PeerResolver` inside the leaf crate
  **(Architect's call: the leaf crate depends on `aitm-core` so `aitm` needs no adapter type; it
  stays a leaf in the unsafe sense, and `aitm-core`'s own tests use fakes)**.
- Other OS (`not(any(macos, linux))`): `ProcessResolver::resolve` always returns `None`.

### D3. Off the hot path: start at accept, budget after the peek, coalesce, rate-limit, cache (decided shape, D-c; numbers are the Architect's)

In `handle_conn`, **before** the peek:

```rust
let local = stream.local_addr().ok();
let attribution = peer::start_attribution(inner.peer_resolver.as_ref(), peer, local);
```

`start_attribution` returns `Some(tokio::task::spawn_blocking(move || r.resolve(peer, local)))`
only when a resolver is set, `local` is known and `is_loopback_peer(peer.ip())`; else `None`
(no task). After the peek:

```rust
let peer_identity = peer::finish_attribution(attribution, peer::ATTRIBUTION_BUDGET).await;
```

`finish_attribution` is `tokio::time::timeout(budget, handle)` flattened: `Ok(Ok(Some(s)))` → `Some(s)`,
anything else (timeout, join error, `None`) → `None`. On timeout the blocking task is dropped but
keeps running to completion in the pool (its result still warms the identity cache; it is bounded
by the scan deadline below). The hint is built with `peer_identity`, `capture_interface: None`.

**Budget: 25 ms after the peek completes (Architect's call).** Sizing: the measured full scan is
7 ms on 1.5k pids; a connection that arrives mid-scan joins the next one (≤ 14 ms); identity for a
new process costs `proc_pidpath` (8 µs) plus one cold `CFBundle` read (1-2 ms; one outlier of
113 ms on a cold cryptex path, paid once per boot); 25 ms is ~3.5× a scan, below human perception,
and an order of magnitude under a TLS handshake. Because the task started at accept and the peek
itself waits for the client's first bytes, most answers are already in when the wait begins.

**Coalescing (in the leaf crate, `src/coalesce.rs`, platform-independent, tested with a fake
scanner).** One scan runs at a time. `resolve` registers its `Tuple { client: peer, proxy: local }`
in a pending set under a `Mutex`; if no scan is running the caller becomes the **leader**: it
snapshots every pending tuple, runs one scan that matches all of them, writes each result, notifies
a `Condvar`, and if new tuples arrived meanwhile loops as leader again (subject to the rate limit).
A non-leader waits on the `Condvar` until its tuple has a result or `scan_deadline` passes.

**Rate limit (Architect's call): a token bucket of capacity 10, refilled at 10 tokens/s.** A scan
consumes a token. A caller that finds no scan running and no token returns `None` at once. Worst
case under a flood: 10 scans/s × 7 ms = 7 % of one core; idle cost zero. A browser page load
(bursts of a few connections within milliseconds) is one or two scans.

> **Amendment 2026-11-01 (live-proof finding F2, decided by the orchestrator).** The paragraph
> above under-counted: sequential connections do not coalesce, so every connection paid a full
> scan and a token, and a 20-request burst from one python process named 14 rows. Two changes:
>
> 1. **Warm set first.** The coalescer keeps the most recently matched pids (MRU, capacity 16;
>    a pid that matches moves to the front; a pid whose probe finds no socket fds is dropped).
>    The leader first probes **only** the warm pids (`SocketScanner::find_owners_among(wanted,
>    deadline, pids) -> Probe { owners, gone }`, pids passed ascending so the lowest matching pid
>    still wins per D4). A warm probe is **not** rate-limited: it costs one
>    `proc_pidinfo(PROC_PIDLISTFDS)` plus one `proc_pidfdinfo` per socket fd for ≤ 16 processes
>    (sub-millisecond); on Linux the `/proc/net/tcp{,6}` read plus ≤ 16 `/proc/<pid>/fd` walks.
> 2. **Full scan only on a miss**, and only then is a token taken; the bucket semantics stay
>    (dry bucket → `None` at once for the missed tuples) but it is **capacity 20, refill 20/s**.
>    Worst case under a flood of *new* processes: 20 scans/s × 7 ms = 140 ms/s ≈ 14 % of one
>    core; zero when idle; a client seen once costs no token on any later connection.
>
> `Limits::default()` is therefore (250 ms, 20, 20, 256); the warm capacity is a crate constant,
> not a knob (D6).

**Scan deadline (Architect's call): 250 ms wall clock**, checked between pids; on expiry the scan
ends and every tuple it did not match resolves `None`. This bounds a pathological host (tens of
thousands of fds) and the blocking-pool occupancy.

**Identity cache (Architect's call on shape).** `IdentityCache`: `HashMap<ProcessKey, Option<String>>`
+ insertion-order `VecDeque<ProcessKey>`, capacity 256, FIFO eviction; `ProcessKey { pid: u32, start: u64 }`
where `start` is the process start time (macOS: `pbi_start_tvsec * 1_000_000 + pbi_start_tvusec`
from `PROC_PIDTBSDINFO`; Linux: field 22 `starttime` of `/proc/<pid>/stat`), so a recycled pid never
serves a stale name. Both `Some` and `None` identities are cached. The result for a **connection**
is computed once at accept and never re-resolved (it lives on the flow).

Tunables live in `pub struct Limits { scan_deadline: Duration, scan_tokens: u32, scan_refill_per_s: u32, cache_entries: usize }`
with `Default` = (250 ms, 10, 10, 256), reachable through `ProcessResolver::with_limits` for tests
only; nothing reads them from config (D6).

### D4. Match rule (decided, D-d)

For a wanted `Tuple { client, proxy }` and a scanned TCP socket with
`(laddr, lport, faddr, fport)`:

- ports: macOS `lport = u16::from_be((raw_insi_lport as u32 & 0xFFFF) as u16)` (same for `fport`);
  Linux ports are already host-order hex in `/proc/net/tcp`.
- addresses: `canonical(ip)` maps an IPv4-mapped IPv6 address to its IPv4; the match is
  `lport == client.port() && fport == proxy.port() && canonical(laddr) == canonical(client.ip()) && canonical(faddr) == canonical(proxy.ip())`.
  macOS decodes `insi_laddr`/`insi_faddr` by `insi_vflag`: `INI_IPV4` → the 4 bytes at offset 12
  of the 16-byte union; `INI_IPV6` → the 16 bytes as `in6_addr`.
- only `soi_kind == SOCKINFO_TCP`; only fds with `proc_fdtype == PROX_FDTYPE_SOCKET` are ever
  passed to `proc_pidfdinfo` (never vnodes); `tcpsi_state` is not filtered on.
- skip our own pid (`std::process::id()`), except where a test asks the scanner not to
  (`skip_pid: Option<u32>`, production `Some(own pid)`).
- pids ascending; the lowest matching pid wins; a second match for the same tuple is ignored.
- any per-pid or per-fd error (`EPERM`, `ESRCH`, `ENOTSOCK`, `EBADF`, short read) is a skip, never
  a result.
- Linux: the `/proc/net/tcp{,6}` row's `uid` must equal our effective uid, else `None` without a
  fd walk (a free privilege test); the fd walk reads `/proc/<pid>/fd/*` symlinks for
  `socket:[<inode>]`, ascending pid, skipping own pid and any directory it cannot read.

### D5. Identity vocabulary: bundle identifier when bundled, else executable basename (D-e: option B, Architect's choice with reasons)

**Rejected: A (code-signing identifier via Security.framework).** Measured here: the signing-info
lookup costs 51-82 ms on first use in a process and **45-53 ms on every call for an ad-hoc-signed
binary** — which is every cargo-built tool, every Homebrew bottle, every nix binary, i.e. the
developer's own clients. The first connection of each such process would miss any ~25 ms budget,
and falling back to a basename for it while later rows carry `com.apple.curl` would split one
process over two Apps groups. It would also add Security/CoreFoundation FFI to the unsafe surface.

**Chosen: B.** On macOS the identity of a matched pid is:

1. `proc_pidpath(pid)` → the executable path (never stored, never logged).
2. `innermost_bundle(path)`: the **last** path component (excluding the final executable
   component) whose name ends in `.app`, `.xpc` or `.appex`; the bundle path is the prefix through
   that component. If found, `CFBundle::new(CFURL::from_path(bundle, true))` →
   `info_dictionary()["CFBundleIdentifier"]` as a string. (Innermost, not outermost: research 24 §3.3
   shows `/usr/bin/python3` runs `Python.app` inside `Xcode.app`, where outermost gives
   `com.apple.dt.Xcode` and innermost the correct `com.apple.python3`; for Chrome the innermost
   helper id `com.google.Chrome.helper.renderer` is what the NE emits and the Kit walks it to Chrome.)
3. Else the path's final component (basename). If `proc_pidpath` fails, `proc_name(pid)`.
4. `sanitize` (below); `None` if nothing printable remains.

On Linux: `readlink /proc/<pid>/exe` basename with a trailing `" (deleted)"` removed; else
`/proc/<pid>/comm` trimmed; then `sanitize`.

Why this is one vocabulary with the NE lane: Apple documents the signing identifier as equal to the
bundle identifier for every app signed the standard way (research 21 Q2), so bundled clients
(`com.apple.Safari`, `com.apple.WebKit.Networking`, `com.google.Chrome.helper.renderer`,
`com.apple.python3`, `com.anthropic.claudefordesktop.helper`) produce the same string on both
lanes. Bare executables differ (`curl` here vs `com.apple.curl` from the NE); the Kit renders both
as `curl` with the process glyph, and the bare form is what Linux produces, so a proxied CLI tool
looks the same on every platform. This divergence is accepted and recorded here.

**`sanitize(raw: &str) -> Option<String>`:** remove every scalar for which `char::is_control()` is
true (Unicode Cc) and every scalar in these format (Cf) ranges: U+00AD, U+061C, U+180E,
U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF, U+FFF9–U+FFFB, U+E0001,
U+E0020–U+E007F; trim ASCII whitespace; `None` if empty or if the result exceeds 256 bytes
(dropped, not truncated — a 257-byte "name" is not a name). Applied before caching and before the
string leaves the crate.

Never: a path, argv, `cmdline`, `environ`, `KERN_PROCARGS2`, the private `responsibility_*` SPI.

### D6. No knob (decided, D-f)

No config key, flag or env var. Resolution is on whenever the binary runs on macOS or Linux. Tests
that need it off build a `Proxy` without `with_peer_resolver`.

### D7. Wording: what `source_app` + `capture_interface` mean now

- `source_app` non-null, `capture_interface` non-null (`"macos-ne"`): captured by a backend, which
  observed the signing identifier.
- `source_app` non-null, `capture_interface` null: explicit proxy; the core named the loopback
  client (this spec).
- both null: the core could not name the client (non-loopback peer, other user, exited before the
  scan, budget missed, rate-limited, unsupported OS), or a replayed/imported flow.

Doc comments and prose that say "null for a proxied flow" change to "null unless the core could
name the client" (keeping the word "proxied" in the two `ParamDef` descriptions, which
`schemas_declare_source_app_and_capture_interface` asserts): `crates/aitm-core/src/protocol.rs`
(`peer_identity`, `capture_interface` docs), `crates/aitm-core/src/flow.rs:407-416`,
`crates/aitm-plugins/src/capture.rs:74, 191, 198, 303, 309, 451, 458, 467`,
`crates/aitm-plugins/src/detail.rs:316-320`, `docs/design/operator-ui-foundation.md:395` (the
`flow.get` row) plus one sentence after the table stating the three-way meaning above.

### D8. The existing proxied-null e2e cell changes meaning

`tests/e2e/flow/test_source_app_null_on_proxied.py` today asserts both keys null on a proxied
flow. After this change its honest statement is: `capture_interface` is present and null on a
proxied flow; `source_app` is present and is either null or a non-placeholder string; the three read
surfaces (`flow.get`, `flow.table`, push summary) agree on both values; the schemas still say
"proxied". It is edited in place (file name kept so the runner's history stays continuous), its
docstring rewritten to say what it now proves. The new positive proof lives in
`tests/e2e/proxy/test_client_attribution.py` (AC10-AC13).

### D9. Logging and privacy posture

- The resolver logs at `debug` only: scan count, duration, matched/unmatched, rate-limited, deadline
  hit. Never the identity string above `debug`, never a path or pid at any level in `aitm-core`
  (the leaf crate has no tracing dependency; it returns values).
- Same-user only by construction: the kernel refuses other users' fd tables; we never escalate,
  never ask for a helper, never read `/proc/<pid>/cmdline`.
- The identity is text chosen by whoever built the client binary: bounded (≤ 256 bytes), scrubbed
  of control/format scalars, stored as data, shown by UIs that already treat `source_app` as
  untrusted text (Kit: `tooltipText`, `sanitized`; prior spec anti-goals). It never reaches a
  scope, guard, passthrough or routing decision.
- The audit ring and session files already carry `source_app`; nothing new is persisted.

### Ripple (measured)

| Type / site | Change |
|---|---|
| `ProxyBuilder` (proxy.rs:409) | `+ peer_resolver: Option<Arc<dyn PeerResolver>>`, `+ with_peer_resolver` |
| `ProxyInner` (proxy.rs:27) | `+ peer_resolver` |
| `handle_conn` (proxy.rs:218) | start task before the peek; `peer_identity` from `finish_attribution` |
| `NextLayerHint {` literals | unchanged (fields exist) |
| `wire.rs:406` | one chained call |
| `crates/aitm/Cargo.toml` | `aitm-peer-process.workspace = true` (all targets) |
| root `Cargo.toml` | member + alias |
| capture.rs / detail.rs / flow.rs / protocol.rs / operator-ui-foundation.md | wording only |

## Acceptance criteria

1. **AC1 (gate).** A hint built by the acceptor for a peer that is not loopback (`10.0.0.1:5000`,
   `[2001:db8::1]:5000`) spawns no resolver task: with a counting fake resolver,
   `start_attribution(Some(&r), peer, Some(local))` returns `None` and the counter stays `0`; for
   `127.0.0.1:5000`, `[::1]:5000` and `[::ffff:127.0.0.1]:5000` it returns `Some(task)`.
   `is_loopback_peer` is `true` for `127.0.0.1`, `127.5.5.5`, `::1`, `::ffff:127.0.0.1`; `false`
   for `10.0.0.1`, `::ffff:10.0.0.1`, `2001:db8::1`, `0.0.0.0`.
2. **AC2 (result reaches the hint).** A `Proxy` built with a fake resolver returning
   `Some("curl-test".into())` and a recording module, driven by one loopback connection that sends
   `b"GET / HTTP/1.1\r\n\r\n"`, hands the module a hint with
   `peer_identity == Some("curl-test")` and `capture_interface == None`.
3. **AC3 (budget).** With a fake resolver that sleeps 500 ms, the module receives
   `peer_identity == None` and is spawned less than 400 ms after the client connected.
4. **AC4 (default).** A `Proxy` built without `with_peer_resolver` yields `peer_identity == None`
   (one explicit test; every pre-existing `aitm-core` test passes unchanged).
5. **AC5 (tunnel authority unchanged).** A hint with `client_hello_sni = Some("example.com")`,
   `dst = 127.0.0.1:50000`, `peer_identity = Some("curl")`, `capture_interface = None`,
   `from_upgrade = false`, empty `first_bytes` has `tunnel_authority() == Some(Authority::new("example.com", 443))`.
6. **AC6 (leaf parsers, literal fixtures, sandbox-runnable).**
   - Linux row `"   0: 0100007F:C2C8 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1"`
     parses to local `127.0.0.1:49864`, remote `127.0.0.1:8080`, state `0x01`, uid `1000`,
     inode `12345`; the tcp6 row with local `00000000000000000000000001000000:C2C8` parses to
     `[::1]:49864`; `0000000000000000FFFF00000100007F:C2C8` parses to `[::ffff:127.0.0.1]:49864`
     (little-endian hosts; the tests are `cfg(target_endian = "little")`); a short or non-hex row
     is `None`.
   - `/proc/<pid>/stat` text `"1234 (my proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 98765 1000 2 ..."`
     gives start time `98765` (the comm contains a space and is skipped by the last `)`).
   - `exe_basename("/usr/bin/curl") == Some("curl")`, `exe_basename("/usr/bin/curl (deleted)") == Some("curl")`,
     `fd_socket_inode("socket:[12345]") == Some(12345)`, `fd_socket_inode("/dev/null") == None`.
   - `innermost_bundle("/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python") == Some(".../Resources/Python.app")`;
     `innermost_bundle("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)")`
     ends in `Google Chrome Helper (Renderer).app`;
     `innermost_bundle("/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking")`
     ends in `com.apple.WebKit.Networking.xpc`; `innermost_bundle("/usr/bin/curl") == None`;
     `innermost_bundle("/tmp/x.app") == None` (the executable itself is not a bundle).
   - match rule: `tuple_matches` is `true` for `(laddr ::ffff:127.0.0.1, lport 49864, faddr 127.0.0.1, fport 8080)`
     against `Tuple { client 127.0.0.1:49864, proxy 127.0.0.1:8080 }`, `false` when either port
     differs or `laddr` is `10.0.0.1`; macOS port decoding: raw `0x406f` → `28480`.
7. **AC7 (sanitiser).** `sanitize("cu\u{200E}rl") == Some("curl")`, `sanitize("\u{7}\u{200B}") == None`,
   `sanitize("  node \n") == Some("node")`, `sanitize(&"a".repeat(256)).is_some()`,
   `sanitize(&"a".repeat(257)) == None`, `sanitize("com.apple.Safari") == Some("com.apple.Safari")`.
8. **AC8 (layout pins, macOS).** `size_of::<socket_fdinfo>() == 792`, `offset_of!(socket_fdinfo, psi.soi_kind) == 256`,
   `offset_of!(socket_fdinfo, psi.soi_proto) == 264` (232/240 inside `socket_info`, which starts at 24;
   corrected 2026-11-01 by a C `offsetof` probe), `size_of::<in_sockinfo>() == 80`,
   `offset_of!(in_sockinfo, insi_lport) == 4`, `offset_of!(in_sockinfo, insi_vflag) == 24`,
   `offset_of!(in_sockinfo, insi_faddr) == 32`, `offset_of!(in_sockinfo, insi_laddr) == 48`,
   `offset_of!(tcp_sockinfo, tcpsi_state) == 80`, `size_of::<proc_fdinfo>() == 8`.
9. **AC9 (self-resolution, macOS, Terminal).** A `std::net::TcpListener` on `127.0.0.1:0`, a
   client `TcpStream::connect`, `accept()`; `MacScanner { skip_pid: None }.find_owners(&[Tuple { client: accepted.peer_addr(), proxy: accepted.local_addr() }], deadline)`
   returns that tuple mapped to `ProcessKey { pid: std::process::id(), .. }`; the same on
   `[::1]:0`; and through the public `ProcessResolver::resolve(peer, local)` (own pid not skipped
   via `with_skip_pid(None)` test hook) the identity is `Some(s)` with
   `s.starts_with("aitm_peer_process")` (the test binary's basename). A tuple whose client port is
   a closed socket resolves `None`.
10. **AC10 (e2e, curl).** `tests/e2e/proxy/test_client_attribution.py` (`# e2e: tier=T1 surface=proxy`,
    real core via `Aitm.server`, real `Upstream`): after `curl -sS -x http://127.0.0.1:<port> <upstream>/attr-<uuid>`,
    the `flow.table` row for that path has `source_app` a string whose lower-case contains `"curl"`,
    `capture_interface is None`, and `flow.detail {id}` has `client_conn.process == source_app`.
11. **AC11 (e2e, python).** A `via_proxy` request from the test process itself yields a row whose
    `source_app` lower-case contains `"python"` (`com.apple.python3`, `org.python.python`,
    `python3.14`, `Python` all qualify) with `capture_interface` null.
12. **AC12 (e2e, CONNECT).** With `scope.add 127.0.0.1` and the `start_https_echo` origin,
    `curl --cacert <aitm ca> -x … https://127.0.0.1:<tls>/attr-<uuid>` produces a `CONNECT` row and a
    `GET` row for that authority; both have `source_app` containing `"curl"` and
    `capture_interface` null.
13. **AC13 (e2e, latency).** 20 sequential plain `via_proxy` GETs through the same core: the median
    wall time, printed in the output, is under 100 ms. (An absolute bound: the 25 ms budget is the
    most attribution can add per connection, so this is honest about what it bounds and cheap to
    run; it is not a differential measurement.)
14. **AC14 (coalescing, fake scanner, sandbox-runnable).** With a fake `SocketScanner` that
    records each `find_owners` call's wanted set and sleeps 20 ms, 8 threads resolving 8 distinct
    tuples concurrently cause at most 2 scans and every thread gets its own result; with the bucket
    drained (`Limits { scan_tokens: 0, .. }`) `resolve` returns `None` without calling the scanner;
    with `scan_deadline = 1 ms` and a scanner that sleeps 50 ms, `resolve` returns `None`.
15. **AC15 (cache).** Two resolutions mapping to the same `ProcessKey` call `identity` once; a key
    with the same pid and a different `start` calls it again; inserting 257 keys evicts the first.
16. **AC16 (wording).** `grep -rn "null for a proxied" crates docs` finds nothing outside
    `apps/mac/**` and `docs/research/**`; `schemas_declare_source_app_and_capture_interface` and
    `flow_get_and_table_report_source_app` pass unchanged; the e2e flow cell (D8) passes against
    the new core.
17. **AC17 (gates and proof).** Rust gate green; `cargo test -p aitm-peer-process` and the
    `aitm-core` acceptor tests run from the Terminal with output quoted; the PR body carries the
    macOS live proof: `curl -x` through a real core and the `flow.table` row showing `"source_app": "curl"`
    (or the Homebrew form), and the Linux live proof is named as a follow-up.

## Left to the builder

- Internal module layout of the leaf crate beyond the named files; names of private helpers.
- Whether the `#[repr(C)]` mirror models `soi_proto` as a typed union or a `[u8; 552]` blob read at
  fixed offsets — as long as AC8 pins hold and the reads are bounds-checked.
- The `Condvar` vs. `std::sync::mpsc` mechanics of the coalescer, as long as AC14 holds and a
  non-leader never spins.
- How `skip_pid` is threaded for the self-resolution tests (a `#[cfg(test)]`-only constructor or a
  `pub fn with_skip_pid(Option<u32>)`), as long as production always skips its own pid.
- Which errno values are logged at `debug`; none are returned.
- Whether `finish_attribution` lives in `peer.rs` or `proxy.rs`.
- The exact doc-comment sentences under D7, keeping "proxied" in the two `ParamDef` descriptions.
- Whether to add an IPv4-mapped self-resolution test (dual-stack listener on `[::]:0`) on top of
  the two required ones.

## Open questions

None. The orchestrator's decisions D-a to D-h are written in as D1-D9; the remaining choices
are the Architect's calls listed below.

## Summary

Make the core name the client of every loopback proxied connection: a new unsafe-isolated leaf
crate `aitm-peer-process` scans same-user sockets (libproc on macOS, `/proc` on Linux), matches
the accepted socket's 4-tuple after `ntohs`, maps the pid to a bundle identifier (innermost
`.app`/`.xpc`/`.appex` via `CFBundle`) or an executable basename, sanitises it, and caches per
`(pid, start_time)`; `aitm-core` gains a `PeerResolver` trait, a builder step, and a
start-at-accept / wait-25-ms-after-the-peek step in `handle_conn` that fills
`NextLayerHint::peer_identity` while leaving `capture_interface` null, so PR #195's plumbing carries
the name to every UI with no new wire field, verb, or mac change.

**Architect's calls** (correct any in the plan's Review log):
1. Identity vocabulary option B (bundle identifier if bundled, innermost bundle, else basename),
   because the signing-identifier lookup measured 45-82 ms (every call for ad-hoc binaries) against
   a 25 ms budget, and B is unsafe-free with the locked `core-foundation` crate.
2. Budget 25 ms after the peek; scan deadline 250 ms; token bucket 10 / 10 per s; cache 256 FIFO
   keyed `(pid, start_time)`; both `Some` and `None` identities cached.
3. The leaf crate depends on `aitm-core` and implements the trait itself (no adapter in `aitm`).
4. `.app`, `.xpc`, `.appex` are the bundle suffixes recognised; `.framework` is not.
5. The existing proxied-null e2e cell is rewritten in place to the new meaning (D8) rather than
   deleted; the positive proof is a new proxy-surface cell.
6. No Swift edits; the stale `FlowSummary.swift` comments are a mac-queue follow-up.
7. The sanitiser drops (rather than truncates) names over 256 bytes.
8. Linux glue is cfg-gated and fixture-tested on macOS; its live proof is the follow-up the brief
   names.
