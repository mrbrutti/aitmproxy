# macOS NE live-capture feeder implementation plan

**Status:** approved — self-approved 2026-10-30 (autonomous mode); implementing Stage 4 coder-by-coder on `claude/ne-live-feeder`.
**Spec:** `docs/superpowers/specs/2026-10-30-aitmproxy-macos-ne-live-feeder-design.md`
**Branch / worktree:** `claude/ne-live-feeder`

## Overview

Five tasks build the core-side live capture feeder on top of PR #122's building
blocks. **Task 1 (config)** and **Task 2 (peer-auth seam)** are logically
independent and may fan out — their only shared file is the one-line `macos_capture/mod.rs`
module declaration (add both `pub mod` lines up front, or let the second rebase the
single-line add). **Task 3 (the feeder)** depends on Task 2. **Task 4 (the loopback
fake-provider integration test)** depends on Task 3. **Task 5 (runtime wiring)**
depends on Tasks 1, 2, and 3. Tasks 2 and 4 bind real UDS and so run their
UDS-binding tests via the **Terminal panel** (the Bash sandbox refuses UDS bind with
EPERM); every other test is sandbox-safe via `UnixStream::pair()` or in-memory types.

The full gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
is run via the Terminal panel after each task.

## Tasks

### Task 1: `macos_capture` enable config

- **Satisfies:** LF-AC1, LF-AC12 (config-only on-switch).
- **Depends on:** none.
- **Files:**
  - `crates/aitm/src/macos_capture/config.rs` (create)
  - `crates/aitm/src/macos_capture/mod.rs` (modify: add `pub mod config;`)
  - `crates/aitm/src/macos_capture/activation_gate.rs` (modify: add `serde::Deserialize` derive to `SysexActivationConfig`)
  - `crates/aitm/src/config_file.rs` (modify)
  - `crates/aitm/src/wire.rs` (modify: `Features` field + its `Default`)
  - `crates/aitm/src/main.rs` (modify: **plan-gap fix, added by the build owner 2026-10-30**) — adding `macos_capture` to `Settings` breaks its exhaustive destructure at `main.rs:153` (no `..`). Add `..` so the binary compiles and the full gate stays green; Task 5 replaces it with the real `macos_capture` wiring. One token, zero Task-5 behaviour.
- **Change:**
  - In `config.rs`: `pub struct MacosCaptureConfig { pub enabled: bool, pub activation: SysexActivationConfig }`
    with `#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]` and
    `#[serde(default, deny_unknown_fields)]`; `Default` yields `enabled: false`.
  - In `activation_gate.rs`: add `serde::Deserialize` (with `#[serde(default, deny_unknown_fields)]`)
    to `SysexActivationConfig` so it nests under `macos_capture.activation`.
  - In `config_file.rs`: add `macos_capture: Option<MacosCaptureConfig>` to the
    `ConfigFile` serde mirror and `pub macos_capture: MacosCaptureConfig` to
    `Settings`; in `parse_settings` map `file.macos_capture.unwrap_or_default()` into
    `Settings` (absent section ⇒ default, disabled).
  - In `wire.rs`: add `pub macos_capture: MacosCaptureConfig` to `Features` and
    `macos_capture: MacosCaptureConfig::default()` to its `Default` impl.
- **Test:** `config_file.rs` unit tests.
  `macos_capture_defaults_disabled`: `parse_settings("listen: 127.0.0.1:8080\n").unwrap().macos_capture.enabled`
  equals `false`.
  `macos_capture_enable_round_trips`: `parse_settings("macos_capture:\n  enabled: true\n").unwrap().macos_capture.enabled`
  equals `true`.
  `macos_capture_unknown_key_errors`: `parse_settings("macos_capture:\n  nope: true\n").is_err()`
  equals `true`.
- **Done when:** the three tests pass and the full gate passes.

### Task 2: peer-auth seam + listener fd accessors

- **Satisfies:** LF-AC3 / LF-AC7 (the verification mechanism), spec §Peer-auth seam.
- **Depends on:** none (shares only `mod.rs` with Task 1).
- **Files:**
  - `crates/aitm/src/macos_capture/peer_auth.rs` (create)
  - `crates/aitm/src/macos_capture/mod.rs` (modify: add `pub mod peer_auth;`)
  - `crates/aitm/src/macos_capture/listener.rs` (modify: fd accessors)
  - `crates/aitm/Cargo.toml` (modify: add macOS-target deps) + `Cargo.lock`
  - **Plan gaps the coder surfaced (build-owner disposition 2026-10-30):** (1) the workspace
    lint `unsafe_code = "forbid"` cannot be lifted by `#[allow]`, so `crates/aitm/Cargo.toml`
    changes `[lints] workspace = true` → `[lints.rust] unsafe_code = "deny"`; unsafe stays a
    hard error everywhere except the one audited `#[allow(unsafe_code)]` on `peer_audit_token`
    (with a `// SAFETY:` comment). **FLAGGED FOR THE SECURITY PANEL:** accept this localized
    `forbid`→`deny` relaxation for `crates/aitm`, or isolate the single `getsockopt` into a
    minimal helper crate to keep the workspace-wide `forbid`. (2) `core-foundation = "0.10"`
    added as a macOS dep (needed for `CFData` to carry the audit token; no new crate —
    `security-framework` already pulls it at 0.10.1). (3) `security-framework = "3.7"` (locked
    3.7.0) via `os::macos::code_signing`.
- **Change:**
  - `pub trait PeerVerifier: Send + Sync { fn verify(&self, fd: std::os::fd::RawFd) -> bool; }`.
  - `pub const PROVIDER_REQUIREMENT: &str = "anchor apple generic and certificate leaf[subject.OU] = \"995PCLM9KH\"";`
  - `pub struct CodeSignatureVerifier { requirement: String }` + `impl Default`
    (uses `PROVIDER_REQUIREMENT`) + `pub fn with_requirement(req: impl Into<String>) -> Self`;
    `impl PeerVerifier for CodeSignatureVerifier`. On `target_os = "macos"`: read the
    peer audit token with `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, ...)` (an
    `unsafe` libc call with a `// SAFETY:` comment) and check it against a
    `SecRequirement` built from `requirement` via the `security-framework`
    `os::macos::code_signing` API; **any** error or a non-success check returns
    `false`. On non-macOS: `verify` returns `false`.
  - In `listener.rs`: `impl std::os::fd::AsRawFd for ControlChannel` (returns the
    control stream's fd) and `pub fn peer_fd(&self) -> std::os::fd::RawFd` on
    `DataConnection` (or `impl AsRawFd for DataConnection`).
  - In `Cargo.toml`: `[target.'cfg(target_os = "macos")'.dependencies]` add
    `security-framework = "<current>"` and `libc = "0.2"`.
- **Test:** `peer_auth.rs` unit tests, sandbox-safe (`UnixStream::pair()` — connected
  fds, no path bind).
  `unsigned_peer_is_rejected`: with `let (a, _b) = UnixStream::pair().unwrap();`,
  `CodeSignatureVerifier::default().verify(a.as_raw_fd())` equals `false` (the
  `cargo test` binary is not Developer-ID-team-signed — mirrors the Swift self-test
  "production requirement rejects unsigned peer").
  `malformed_requirement_is_rejected`:
  `CodeSignatureVerifier::with_requirement("this is not a requirement").verify(a.as_raw_fd())`
  equals `false`.
  `control_channel_exposes_a_valid_fd`: a `ControlChannel::from_stream` over one end
  of a pair has `as_raw_fd() >= 0` equal to `true`.
  (If the Terminal-panel run environment ever reports a self-signed `cargo test`
  binary that *passes* the team requirement, the first two assertions degrade to
  "verify is callable and deterministic"; the builder notes this, but on this host
  the ad-hoc test binary is expected to be rejected.)
- **Done when:** the tests pass (Terminal-panel gate, as the crate now links
  Security.framework) and the full gate passes.

### Task 3: the capture-session feeder

- **Satisfies:** LF-AC3, LF-AC4, LF-AC5, LF-AC9 (feeder logic), LF-AC11 (pairing
  bound), LF-AC13.
- **Depends on:** Task 2 (`PeerVerifier`, listener fd accessors).
- **Files:**
  - `crates/aitm/src/macos_capture/feeder.rs` (create)
  - `crates/aitm/src/macos_capture/mod.rs` (modify: add `pub mod feeder;`)
  - `crates/aitm/src/ingress.rs` (modify: extend `one_choke_point_survives_ingress`'s
    scanned set to include `macos_capture/feeder.rs`)
  - `crates/aitm/src/macos_capture/listener.rs` (modify — **added by the build owner
    2026-10-30**, see refinement #1): a `ControlChannel::into_halves` split.

- **Build-owner refinements (2026-10-30, from the Task-3 coder's pre-implementation design review; all approved):**
  1. **`ControlChannel` must split** so the feeder can read `FlowOpen`s and re-send `Scope`
     on a 1 s timer concurrently. `recv`'s `read_exact` is NOT cancel-safe in `select!`, and
     the type has no split. Add `pub fn into_halves(self) -> (ControlReader, ControlWriter)`
     to `listener.rs` via tokio `UnixStream::into_split`; `ControlReader::recv` keeps the
     codec + `bytes_read`, `ControlWriter::send` keeps the write path. Run peer-verify +
     `recv_hello` on the UNSPLIT channel first, THEN split; the reader task is only ever
     cancelled as a whole (never mid-frame), the writer is driven by the poll tick. (~30 lines
     + a `UnixStream::pair()` test.)
  2. **`FlowPairing<D = DataConnection>`** generic over the data half, so `pairing_map_is_bounded`
     and an either-order pairing test run in the sandbox (a real `DataConnection` needs a bind).
  3. **`spawn_pump` takes a `tokio::sync::watch::Receiver` stop signal** so pumps abort at
     shutdown (spec LF-AC10); don't rely on a `JoinSet` reap.
  4. **Shed at the concurrency cap** with `Semaphore::try_acquire_owned` + a log line — never
     queue (queuing holds sockets open and defeats the fd bound).
  5. **Run `verifier.verify(...)` under `tokio::task::spawn_blocking`** — it makes
     Security.framework calls once per data socket; inline would stall a runtime worker.
  6. **Pairing state is per-attachment, not per-session**, so a reconnecting provider's
     `flow_id`s can't collide with stale pending entries.
  7. **Data-accept-stall (follow-up, note in the Review log, NOT a blocker):** `accept_data`
     reads the handshake before the data peer is verified, so a silent same-uid peer can stall
     the data-accept path. Mitigate now with a bounded timeout around the handshake read and by
     structuring the data path so one slow/silent peer cannot stall other flows; a full fix
     (split accept from handshake in `listener.rs`, verify the fd before reading) is a
     follow-up. Record the residual in the Review log for the security panel.
- **Change:**
  - `pub struct CaptureSession` with fields per the spec; `pub fn new(ingress: Arc<CoreIngress>,
    l7_guard: Arc<dyn aitm_core::ScopeRateGuard>, l4_guard: Option<Arc<aitm_proto_l4::guard::L4Guard>>,
    verifier: Arc<dyn PeerVerifier>, socket_dir: PathBuf) -> Self` (builder setters for
    the tuning defaults: scope poll interval 1 s, pending caps 1024, concurrency cap
    4096).
  - `pub async fn run(self, shutdown: impl std::future::Future<Output = ()> + Send)` —
    the lifecycle in the spec: bind → `publish_rendezvous` (hold the guard) → accept
    loop (verify control peer → `recv_hello` → serve). Fail-open at each step
    (log + return/continue; never panic/abort).
  - Internal, unit-testable helpers:
    - `fn current_scope_spec(&self) -> ScopeSpec` = `provider_scope_spec(&self.l7_guard.list_scope(), &l4_scope)`.
    - `async fn serve_control(&self, control: ControlChannel, shutdown)` driving the
      Hello gate, the initial `Scope` send, scope-poll re-emission (re-send only when
      the `spec` string changed), and the `FlowOpen`/data pairing loop.
    - A `FlowPairing` map type with `pending_opens`/`pending_data` keyed by `flow_id`,
      bounded with oldest-eviction, returning a ready `(FlowOpen, DataConnection)` when
      both halves are present.
    - `fn spawn_pump(ingress, open, data, permit)` calling
      `adapter::dispatch_captured_flow` and logging+isolating any `Err`.
  - Default production socket dir const, e.g. `pub const DEFAULT_SOCKET_DIR: &str = "/private/tmp/aitmproxy-capture.d";`
- **Test:** `feeder.rs` unit tests, sandbox-safe (`UnixStream::pair()` for the control
  channel via `ControlChannel::from_stream`; stub `PeerVerifier`s; an in-memory
  `CoreIngress`).
  `rejected_control_peer_gets_no_scope`: with a rejecting verifier, after a provider
  pair sends `Hello`, the core side writes **zero** bytes back — the provider's
  `ControlChannel::recv()` returns a clean EOF (no `Scope`). Assert the provider
  received no `ControlMessage`.
  `verified_peer_gets_scope_matching_emitter`: with an accepting verifier and a guard
  whose `list_scope()` is `[ScopeEntry{host:"example.com"}]`, the provider receives
  `ControlMessage::Scope(s)` with `s.spec == "example.com"` (the emitter's output).
  `scope_change_triggers_resend`: after the first `Scope`, adding
  `ScopeEntry{host:"api.test"}` to the guard causes a second `Scope` whose `spec` ==
  `"example.com api.test"`; with no change, no second frame arrives within two poll
  intervals.
  `hello_mismatch_tears_down`: a provider sending `Hello{protocol_version: 2}` gets no
  `Scope` and the channel is closed (provider `recv` sees EOF).
  `pairing_map_is_bounded`: inserting cap+1 unpaired `FlowOpen`s leaves the map at the
  cap (oldest evicted) — assert `len() == cap`.
- **Done when:** the tests pass, `one_choke_point_survives_ingress` still passes
  (feeder has no `.inject(`/`send_on_wire(`), and the full gate passes.

### Task 4: loopback fake-provider integration test

- **Satisfies:** LF-AC2, LF-AC6, LF-AC7, LF-AC8, LF-AC10, LF-AC11 (end to end).
- **Depends on:** Task 3.
- **Files:**
  - `crates/aitm/tests/macos_ne_feeder_loopback.rs` (create)
- **Change:** an integration test that **acts as the Swift provider** over the real
  sockets, modelled on the Task-11 DEBUG self-check and the `ingress.rs` stub-wired
  `CoreIngress` tests. It:
  1. builds a recording `CoreIngress` — a real `CoreIngress::empty().with_stream(...)`
     wired to a `StubModule` (claims, records its `NextLayerHint`), a `MockGuard`
     (in-scope toggle), `MockSink`, `MockConnector`, plus `with_l4(L4Guard, InMemoryL4FlowStore)`
     for UDP (the same stubs `ingress.rs` tests already define, lifted into the test);
  2. starts a `CaptureSession` on a short scratch socket dir with an **accepting**
     stub `PeerVerifier`, on a tokio task with a cancellation `shutdown`;
  3. reads the rendezvous file (asserts it names the 0700 dir, mode 0600) — **LF-AC2**;
  4. connects a `ControlChannel` to `control.sock`, sends `ControlMessage::Hello`,
     and reads a `ControlMessage::Scope` whose `spec` matches the emitter — **LF-AC6**
     setup;
  5. sends a TCP `FlowOpen{flow_id, kind:Tcp, remote, remote_hostname, source_app}`,
     dials `data.sock`, writes `write_data_handshake{flow_id}` then bytes
     (`b"GET / HTTP/1.1\r\nhi"`), and asserts the `StubModule` was spawned with
     `hint.dst == remote` (in scope) — **LF-AC6**; repeats out-of-scope and asserts
     **no** spawn (refused);
  6. sends a UDP `FlowOpen` + a datagram and asserts it lands in the L4
     `InMemoryL4FlowStore` in scope and is refused out of scope — **LF-AC6**;
  7. asserts `ControlChannel::bytes_read()` on the core side equals only the metadata
     size (no bulk bytes on control) — **LF-AC8**;
  8. connects a data socket with a **rejecting** verifier variant (second session) and
     asserts no bytes are fed — **LF-AC7**;
  9. fires `shutdown` and asserts the rendezvous file and both socket files are gone —
     **LF-AC10**.
  The test **binds UDS**, so it runs via the **Terminal panel**. Guard the bind: if
  `CaptureListener::bind`/`publish_rendezvous` returns `PermissionDenied`, `eprintln!`
  a clear "skipped: UDS bind unavailable (run via Terminal panel)" and return, so a
  stray Bash-sandbox `cargo test` stays green while the Terminal-panel gate exercises
  the real path.
- **Test:** the integration test itself. Key literal expectations:
  - the received `Scope.spec` equals the emitter output for the seeded scope (e.g.
    `"example.com"`);
  - the recorded `hint.dst.to_string()` equals the `FlowOpen.remote` (e.g.
    `"93.184.216.34:443"`);
  - the in-scope TCP flow spawns the stub exactly once; the out-of-scope one spawns
    it zero times;
  - the in-scope UDP store `list().len()` is `1`; the out-of-scope one adds none;
  - after `shutdown`, `Path::new(RENDEZVOUS_PATH).exists()` is `false` and
    `control.sock`/`data.sock` do not exist.
- **Done when:** the integration test passes in the Terminal panel and the full gate
  passes.

### Task 5: runtime wiring (assemble + main, macOS-gated)

- **Satisfies:** LF-AC1 (`None` when disabled), LF-AC9 (proxy unaffected), LF-AC12
  (no agent path).
- **Depends on:** Task 1, Task 2, Task 3.
- **Files:**
  - `crates/aitm/src/wire.rs` (modify: `Assembled.l4_guard` + `build_capture_session`)
  - `crates/aitm/src/main.rs` (modify: thread config, spawn the session)
- **Change:**
  - In `wire.rs`: add `pub l4_guard: Option<Arc<aitm_proto_l4::guard::L4Guard>>` to
    `Assembled`, set from the `l4_half` guard clone (`Some` iff `features.l4.enabled`,
    else `None`). Add
    `pub fn build_capture_session(features: &Features, ingress: CoreIngress,
    l7_guard: Arc<dyn ScopeRateGuard>, l4_guard: Option<Arc<L4Guard>>,
    verifier: Arc<dyn PeerVerifier>, socket_dir: PathBuf) -> Option<CaptureSession>`
    returning `Some` only when `features.macos_capture.enabled`.
  - In `main.rs`: destructure `l4_ingress` and the new `l4_guard`; thread
    `macos_capture` from `Settings` into `Features`; when
    `cfg!(target_os = "macos")` **and** `features.macos_capture.enabled`, build the
    session (`CodeSignatureVerifier::default()`, `feeder::DEFAULT_SOCKET_DIR`,
    `proxy.guard()`) and add `result = session.run(aitm::shutdown_signal())` as a
    `tokio::select!` arm beside the proxy accept loops (so the existing shutdown
    stops it cleanly). When disabled or off-macOS, the ingress is dropped as today.
- **Test:** `wire.rs` unit tests (sandbox-safe — no bind, `build_capture_session`
  short-circuits before `run`).
  `capture_session_absent_when_disabled`: `build_capture_session` with
  `Features { macos_capture: MacosCaptureConfig { enabled: false, .. }, .. }` returns
  `None` (`is_none()` equals `true`).
  `capture_session_present_when_enabled`: the same with `enabled: true` returns
  `Some` (`is_some()` equals `true`).
  `l4_guard_tracks_l4_enabled`: `assemble_with` with `Features { l4: L4Config { enabled: true, .. }, .. }`
  yields `Assembled.l4_guard.is_some() == true`, and with L4 disabled
  `l4_guard.is_none() == true`.
  `no_agent_path_to_capture_session` (structural, mirrors `one_choke_point_survives_ingress`):
  scan the bus/MCP/session command sources and assert zero matches of
  `build_capture_session(` / `CaptureSession::` outside `main.rs`, `wire.rs`, and
  `macos_capture/` — the on-switch is reachable only from the config-driven startup
  path.
- **Done when:** the four tests pass and the full gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 2 | build-owner (pre-seed) | — | Workspace `unsafe_code = "forbid"` relaxed to `deny` for `crates/aitm` (one audited `#[allow(unsafe_code)]` getsockopt with `// SAFETY:`) because `forbid` cannot be lifted by `#[allow]` | **FOR THE SECURITY PANEL:** accept this localized relaxation, or isolate the single `getsockopt` into a minimal helper crate to keep the workspace-wide `forbid`. |
| 3 | build-owner (pre-seed) | Minor | No `recv_hello` timeout: a verified-but-hung provider holds the single control slot until it disconnects, blocking reattachment | **For the panel** — low (the control peer is team-verified first). ~10-line fix (timeout around `recv_hello`) if wanted. |
| 3 | build-owner (pre-seed) | Minor | Data handshake is read before the data peer is verified; a silent same-uid peer holds an accept slot for the 5 s timeout; ~16 within 5 s could stall the data path (refinement #7 residual) | **For the panel** — low (0700 dir + team-verified control peer). Mitigated now by the 5 s handshake timeout + 16 concurrent accept pipelines; full fix = split accept from handshake and verify the fd before reading. |
| 3 | build-owner (pre-seed) | info | `rejected_control_peer_gets_no_scope` accepts EOF or `ConnectionReset`; the reset arm (Linux) is unverified on this macOS host (EOF observed 5/5) | accepted — defensive cross-platform arm. |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
