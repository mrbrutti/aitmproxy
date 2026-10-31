# macOS NE live-capture feeder design

**Status:** approved — self-approved 2026-10-30 (autonomous mode, memory `aitmproxy-autonomous-approve-merge-mode`). Open questions resolved by the build owner: (1) mutual peer auth — **YES** (core-verifies-provider; same-uid squatter defence, within NE-AC6); (2) live `CaptureCapability` surfacing — **follow-up** (captured flows still reach all three UIs via `CoreIngress`→flow list, which is Task 18's cross-UI assertion; only the "Capturing" indicator state is deferred); (3) scope re-emission — **1 s polling now, `watch` deferred**.
**Research inputs:** `docs/research/05-synthesis.md`;
`docs/superpowers/specs/2026-10-29-aitmproxy-macos-network-extension-design.md`
(D2, D3, D4, D9, NE-AC5/6/7/17); `docs/superpowers/specs/2026-10-30-macos-ne-core-prereqs-*`
(PR #122, the rendezvous writer + scope-spec emitter);
side-session notes `core-ne-rendezvous-scope-STATUS.md` and `task11-handoff-contract.md`;
the provider half `apps/mac/Extension/Sources/FlowHandoff.swift` (PR #95/#100, peer
auth + `CoreLink` + `ScopeMatcher` + `Rendezvous`).

## Intent

PR #122 landed every core-side **building block** for macOS NE capture — the
`CaptureListener` (0700 socket dir, control + per-flow data sockets), the
`RendezvousFile` writer, the `provider_scope_spec` emitter, the `dispatch_captured_flow`
adapter, the `CaptureIngress`/`CoreIngress` sink, the `activation_gate`, the
`capability` state, and the `availability` map — but nothing **runs** them. The
macOS-NE milestone plan's Task 18 ("Change: none — exercises the built system") is
wrong: there is no core-side runtime that binds the listener, publishes the
rendezvous file, authenticates the Swift provider, pushes scope, and pumps each
captured flow into `CoreIngress`. This spec defines that runtime — the **live
capture feeder** — so a flow the signed system extension hands off actually reaches
`CoreIngress` and appears in the flow list. It is the last core-side piece before
NE-AC17's real-Mac acceptance run can happen.

## Goals

- A core-side async **capture session** that, when NE capture is enabled, binds the
  `CaptureListener`, publishes the rendezvous file (holding the guard for the
  session), accepts the provider's control channel, **verifies the provider's code
  signature** (fail-closed), validates the `Hello`, pushes the provider scope (and
  re-pushes on scope change), and pumps each `FlowOpen`'s data socket into
  `CoreIngress` via the existing `dispatch_captured_flow` adapter.
- Enabling the feeder is a **deny-by-default, operator-only** config action; an
  agent cannot turn it on, and the default build does not run it.
- **Fail-open everywhere.** No bind/accept/auth/scope/pump error, and no provider
  misbehaviour, may panic or abort the core or the user's network. A feeder that
  never starts or that stops leaves the provider with no attached core, which (by
  the provider's own contract) sends every flow direct.
- The feeder is **protocol-general**: it reuses the one `dispatch_captured_flow`
  seam (TCP → `ProtocolModule`, UDP → `L4Guard`) and adds no protocol-specific
  branch of its own, so a future captured protocol is a seam change, not a feeder
  change.
- A **loopback fake-provider integration test** stands in for the Swift provider
  over the real sockets (connect, `Hello`, receive `Scope`, open a flow, send
  bytes) and proves the bytes reach a recording `CoreIngress`.

## Non-goals

- The Swift provider, its `handleNewFlow`, self-exclusion, the rendezvous reader,
  peer auth of the core, or the `ScopeMatcher` (all shipped in `FlowHandoff.swift`).
- Sysex install/activation and the two System Settings prompts (the app's job;
  `activation_gate` already gates *who* may trigger it).
- Updating the live `CaptureCapability` surface the app shows (`capability.rs`
  already maps states; wiring the feeder's attach/detach into a live capability
  handle read over the bus is a separate follow-up — see Open questions).
- Any new wire-write path. The feeder reads the guard and feeds the ingress; it
  never injects. `one_choke_point_survives_ingress` must keep passing.
- Raw packet-level L4 on macOS (honestly `L4Unavailable`, per `availability.rs`).
- The `tests/e2e/ne/` repeatable-script harness and the real-Mac run (NE-AC17,
  Task 18 of the milestone); this spec unblocks them.

## Anti-goals

- **Breaking the user's network.** The macOS NE captures system-wide. A feeder bug
  that crashes the core, stalls a flow forever, or makes the provider claim a flow
  the core then refuses would break ordinary browsing. The feeder must fail open at
  every step and never widen scope.
- **Shipping plaintext to a squatter.** A 0700 dir keeps other uids out, but a
  same-uid process can still connect to `control.sock`/`data.sock`. The feeder must
  verify the peer's code signature before sending scope or feeding bytes, exactly
  as the Swift side verifies the core. A peer failing the requirement gets nothing.
- **An agent-reachable on-switch.** Enabling capture must stay with the operator.
- **Unbounded resource growth** from a hostile or buggy provider (flood of
  `FlowOpen`s with no data socket, data sockets with no `FlowOpen`, giant frames).
- **Redeclaring** `CoreIngress`, the listener types, or the adapter. Reuse them.

## Constraints

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- **Deny-by-default + operator gating.** Reuse `activation_gate::SysexActivationConfig`
  / `check_activation_caller`; the enable flag defaults off and is config-authored
  (operator authority).
- **Peer auth fail-closed**, mirroring `FlowHandoff.swift`'s `PeerAuth`: team OU
  `995PCLM9KH`, requirement `anchor apple generic and certificate leaf[subject.OU] = "995PCLM9KH"`.
- **No CA key ever reaches the extension** (D10): the feeder moves bytes only; TLS
  stays in the core. Unchanged here, but the feeder must not introduce a key path.
- **`sun_path` budget** (104): the socket dir path + `/control.sock` must fit, as
  `rendezvous::publish` already enforces.
- **UDS bind is not available in the Bash sandbox** (EPERM, per `rendezvous.rs`'s
  AC7 note). Tests that bind a real `CaptureListener` run via the **Terminal
  panel**; tests using `UnixStream::pair()` (connected, no path bind) are
  sandbox-safe.
- **Platform.** The real peer-auth check is macOS-only (Security.framework). The
  feeder module compiles on any Unix (so the loopback test runs on this macOS host
  through a `PeerVerifier` seam); the production wiring in `main.rs` is spawned only
  under `cfg!(target_os = "macos")`.
- **Reuse the PR #122 seam APIs verbatim:** `CaptureListener::bind` /
  `publish_rendezvous` / `accept_control` / `accept_data`, `ControlChannel::send`/`recv`,
  `adapter::recv_hello`, `adapter::dispatch_captured_flow`, `scope_spec::provider_scope_spec`.

## Design

### Enable-config decision (Architect's call)

There is **no** existing NE/capture enable flag. `l4.enabled` constructs the
Linux-only raw-packet L4 module (unavailable on macOS) and is the wrong switch; the
NE feeder captures **both** TCP (L7) and UDP (L4), and the ingress stream half is
wired for every build regardless of `l4.enabled`. So a **new** config section is
needed.

**Decision:** a new config section `macos_capture`, deserialized into a new
`MacosCaptureConfig`, riding alongside `l4` in the config-file `Settings`/`Features`
exactly as `l4` does (it lives in the `aitm` crate, not `aitm-core`, because it
reuses `SysexActivationConfig`):

```
macos_capture:
  enabled: false            # the exact enable flag; default off
  activation:
    allow_agent_sysex_install: false   # existing activation_gate knob, reused
```

- `MacosCaptureConfig { pub enabled: bool, pub activation: SysexActivationConfig }`,
  `#[serde(default, deny_unknown_fields)]`, `Default { enabled: false, .. }`.
- The feeder runs **iff** `macos_capture.enabled` is true **and**
  `cfg!(target_os = "macos")`.
- `enabled` is authored only in the config file, i.e. operator authority — the
  deny-by-default gate. **No bus/MCP/agent command flips it.** If a runtime enable
  trigger is ever added, it must pass `activation_gate::check_activation_caller`
  (the same gate that governs the install), which is why `SysexActivationConfig` is
  nested here rather than left standalone.
- The enable flag's **exact name is `macos_capture.enabled`**.

### Module placement

A new file `crates/aitm/src/macos_capture/feeder.rs` holds the session runtime; a
new `crates/aitm/src/macos_capture/peer_auth.rs` holds the peer-verification seam; a
new `crates/aitm/src/macos_capture/config.rs` holds `MacosCaptureConfig`. All are
declared in `macos_capture/mod.rs`. No existing seam type is redeclared.

### Peer-auth seam (`peer_auth.rs`)

The Swift provider verifies the **core** before sending a flow; the feeder adds the
symmetric check — the **core verifies the provider** before sending scope or feeding
bytes. This is an addition beyond D3's literal one-directional text, within NE-AC6's
"authenticated handoff" intent (**Architect's call**, see §Reconciliation).

- `pub trait PeerVerifier: Send + Sync { fn verify(&self, fd: RawFd) -> bool; }` —
  fail-closed by contract (any doubt ⇒ `false`).
- `pub const PROVIDER_REQUIREMENT: &str = "anchor apple generic and certificate leaf[subject.OU] = \"995PCLM9KH\"";`
  (byte-identical to `PeerAuth.coreRequirement`), with a `TODO` to narrow to the
  sysex's designated requirement at GA, mirroring the Swift `TODO`.
- `pub struct CodeSignatureVerifier { requirement: String }` with `Default` using
  `PROVIDER_REQUIREMENT`; its `verify` (macOS):
  1. `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &audit_token, &len)` (libc FFI,
     `unsafe` with a `// SAFETY:` comment) — on any error ⇒ `false`;
  2. resolve the audit token to a `SecCode` and check it against a `SecRequirement`
     built from `requirement` (via the `security-framework` crate's
     `os::macos::code_signing`) — any Security.framework error or a non-success
     validity check ⇒ `false`.
  On a non-macOS target `verify` returns `false` (fail-closed); the real path is
  never compiled off-macOS.
- The feeder holds `Arc<dyn PeerVerifier>`, so the loopback test injects a stub
  (accept/reject) and the production path injects `CodeSignatureVerifier::default()`.
- Minimal seam additions in `listener.rs` so the feeder can hand the verifier a
  `RawFd`: `impl AsRawFd for ControlChannel` and a `DataConnection::peer_fd(&self) -> RawFd`
  (or `impl AsRawFd for DataConnection`). These expose an fd; they do not redeclare
  the types.

Known, accepted caveat (mirrors the milestone Review log, Task 11): `LOCAL_PEERTOKEN`
has an inherent TOCTOU; it is outside the threat model (a verified root provider is
trusted not to pass its fd on).

### The capture session (`feeder.rs`)

A struct the runtime builds once and `.run(shutdown)`s:

- `pub struct CaptureSession` holding: `ingress: Arc<CoreIngress>`,
  `l7_guard: Arc<dyn ScopeRateGuard>`, `l4_guard: Option<Arc<L4Guard>>`,
  `verifier: Arc<dyn PeerVerifier>`, `socket_dir: PathBuf`, and tuning (scope poll
  interval, pending/concurrency bounds).
- `pub fn new(...)` with the fields above (signatures named in the plan).
- `pub async fn run(self, shutdown: impl Future<Output = ()> + Send)` — the session
  lifetime. Everything it does is fail-open.

**Lifecycle / loop:**

1. `CaptureListener::bind(self.socket_dir)` → on `Err`, log and **return** (the
   core keeps serving; the provider finds no rendezvous and fails open). The default
   `socket_dir` is a short fixed path within the `sun_path` budget (**Architect's
   call:** `/private/tmp/aitmproxy-capture.d`, created+locked 0700 by `bind`).
2. `listener.publish_rendezvous()` → **hold the `RendezvousFile` guard** for the
   whole session; on `Err`, drop the listener, log, return.
3. **Accept loop** (until `shutdown`): `listener.accept_control()`; then
   - verify the control peer: `verifier.verify(control.as_raw_fd())` → on `false`,
     close the channel (drop) and continue the accept loop (no scope sent);
   - `adapter::recv_hello(&mut control)` → on `Err` (version mismatch / non-`Hello`
     / EOF), drop and continue;
   - send the initial scope (below); then serve the attached provider until the
     control channel ends, then loop back to accept the next (the provider
     reconnects every ~2 s — `attachRetrySeconds`).
4. **Serving an attached provider** runs concurrently, all under the session:
   - **Scope push + re-emission.** Compute `provider_scope_spec(&l7_guard.list_scope(),
     &l4_scope())` where `l4_scope()` is `l4_guard.map(|g| g.list_scope()).unwrap_or_default()`;
     `control.send(ControlMessage::Scope(spec))`. A **scope-change hook** re-sends
     when the spec changes. There is no scope-change notification in the core today;
     the **minimal hook is polling** (**Architect's call**): on a fixed interval
     (default 1 s) recompute the spec and re-send only if its `spec` string differs
     from the last sent. Rationale: the provider is a coarse pre-filter under the
     authoritative core guard, so a ≤1 s stale spec is safe — a stale-narrower spec
     sends a flow direct (under-inclusive, safe); a stale-wider spec is caught by
     the core guard (the flow is refused, a ≤1 s transient). Polling is
     self-contained (no mutation-site plumbing) and fail-open. A `tokio::sync::watch`
     signalled from `scope.add`/`l4.scope.add` is the event-driven alternative, left
     as a follow-up.
   - **Control read loop.** `control.recv()` yields `ControlMessage`s; the feeder
     acts only on `FlowOpen` (other variants ignored, forward-compatible). On a
     `None`/`Err`, the provider detached → tear down this attachment and return to
     the accept loop.
   - **Data accept loop.** `listener.accept_data()` yields a `DataConnection`
     (its `flow_id` from the handshake). Verify the data peer
     (`verifier.verify(data.peer_fd())`) → on `false`, drop (no bytes fed).
   - **Flow pairing.** `FlowOpen` (control) and `DataConnection` (data) arrive on
     two sockets; the provider dials the data socket, sends `FlowOpen`, then the
     handshake — so order is not guaranteed. The feeder keeps two small maps keyed
     by `flow_id` (`pending_opens`, `pending_data`); when both halves are present it
     removes them and **spawns a pump**. Both maps are **bounded** (**Architect's
     call:** cap 1024 each) with oldest-eviction and a stale-half timeout, so a
     provider that opens without dialling (or dials without opening) cannot grow
     memory.
   - **Per-flow pump.** For a paired `(FlowOpen, DataConnection)`, spawn a task:
     `adapter::dispatch_captured_flow(&ingress, &open, data).await`. That reuses the
     existing guarded path: TCP → sniff + `dispatch_tcp` (module spawn or verbatim
     passthrough of the authoritative dst); UDP → `udp_admits` then one-datagram-at-
     a-time `dispatch_udp`. Backpressure is per-flow (its own socket + kernel
     buffers; UDP memory is one 64 KiB datagram at a time — the adapter already
     bounds this). A pump task's `Err` or panic is logged and isolated: it ends that
     one flow (its sockets close; the provider's pump ends and closes the NE flow)
     and never touches another flow or the core. Concurrent pumps are bounded
     (**Architect's call:** a semaphore, default 4096, released on completion) to
     avoid fd exhaustion.
5. **Shutdown.** When `shutdown` fires: stop accepting, drop the `RendezvousFile`
   guard (removes the file), drop the `CaptureListener` (removes the sockets),
   signal pump tasks to abort. The provider then detaches and fails open.

### Fail-open summary (per step)

| Step | Failure | Behaviour |
|---|---|---|
| bind | dir cannot be created/locked, socket cannot bind | log; return; core serves; provider fails open |
| publish_rendezvous | canonicalize / `sun_path` / create error | drop listener; log; return |
| accept_control | accept error | log; back off; retry the accept loop |
| peer verify (control) | `false` | close channel; no scope; accept next |
| recv_hello | version mismatch / non-Hello / EOF | close channel; accept next |
| scope send | write error | tear down attachment; accept next |
| accept_data | accept error | log; continue serving other flows |
| peer verify (data) | `false` | close that data socket; no bytes fed |
| pairing | unmatched half overflows the cap / times out | evict the oldest; log once |
| pump | I/O error / panic | isolate to that flow; close its sockets |
| shutdown | — | drop rendezvous + listener; abort pumps |

The invariant: **nothing the feeder does can panic or abort the core process or
stall the user's network.** The feeder runs as its own task; a top-level catch
logs and returns, leaving the proxy accept loops running.

### Runtime wiring

- `wire.rs`: add `pub l4_guard: Option<Arc<L4Guard>>` to `Assembled` (a clone of the
  L4 module's guard, `Some` iff `l4.enabled`), and `pub macos_capture: MacosCaptureConfig`
  to `Features` (Default: disabled). A small pure helper
  `build_capture_session(features, assembled, verifier, socket_dir) -> Option<CaptureSession>`
  returns `Some` only when `features.macos_capture.enabled` — testable without
  binding.
- `config_file.rs`: add `macos_capture: Option<MacosCaptureConfig>` to the file
  mirror and `macos_capture: MacosCaptureConfig` to `Settings`, mapped in
  `parse_settings` (absent section ⇒ default, disabled).
- `main.rs`: thread `macos_capture` into `Features`; when enabled and
  `cfg!(target_os = "macos")`, build the session (`CodeSignatureVerifier::default()`,
  the default socket dir) and run it as a `tokio::select!` arm alongside the proxy
  accept loops, driven to a clean stop by the existing `shutdown_signal()`.

## Acceptance criteria

Tags: **[Rust-sandbox]** provable by `UnixStream::pair()`/in-memory tests in the
Bash sandbox; **[Rust-terminal]** needs a real UDS bind, run via the Terminal
panel; **[structural]** a source-level tripwire.

1. **LF-AC1 — Disabled by default.** `MacosCaptureConfig::default().enabled` is
   `false`; a config file with no `macos_capture` section parses to a disabled
   config; `build_capture_session` returns `None`. No listener binds, no rendezvous
   file is written. **[Rust-sandbox]**
2. **LF-AC2 — Enable starts the session.** With `macos_capture.enabled: true` on
   macOS, `run` binds a 0700 socket dir and publishes the rendezvous file at
   `RENDEZVOUS_PATH` naming that dir (mode 0600, single line + `\n`), holding the
   guard; the Swift `Rendezvous` acceptance mirror accepts it. **[Rust-terminal]**
3. **LF-AC3 — Control peer-auth fail-closed.** With a `PeerVerifier` that rejects,
   the feeder sends **no** `Scope` frame and closes the control channel; with one
   that accepts, it proceeds. **[Rust-sandbox]**
4. **LF-AC4 — Hello gate.** The feeder validates the `Hello` via `recv_hello`; a
   version mismatch or a non-`Hello` first frame tears the control channel down and
   no `Scope`/flow is served. **[Rust-sandbox]**
5. **LF-AC5 — Scope emission + re-emission.** After a verified `Hello`, the feeder
   sends `ControlMessage::Scope(provider_scope_spec(l7, l4))` whose `spec` equals the
   emitter's output for the live scope; after the scope changes it sends a second
   `Scope` with the new spec; an unchanged scope is **not** re-sent. **[Rust-sandbox]**
6. **LF-AC6 — Flow reaches CoreIngress (the loopback fake-provider test).** A test
   acting as the Swift provider over the real sockets — connect, send `Hello`,
   receive `Scope`, send a TCP `FlowOpen`, dial the data socket, send the handshake
   and bytes — causes `dispatch_captured_flow` to feed a recording `CoreIngress`:
   an **in-scope** flow is dispatched (the recording module sees `hint.dst` = the
   authoritative remote) and an **out-of-scope** flow is refused; a UDP flow's
   datagram lands in the L4 store in scope and is refused out of scope.
   **[Rust-terminal]**
7. **LF-AC7 — Data peer-auth fail-closed.** A data socket whose peer the verifier
   rejects is dropped and **no** bytes are fed for that flow; the control channel and
   other flows are unaffected. **[Rust-terminal]** (bind) / **[Rust-sandbox]** (logic
   over a pair where feasible)
8. **LF-AC8 — Control/data separation preserved.** Across a served session only
   metadata crosses the control channel: `ControlChannel::bytes_read()` stays at the
   `Hello` + `FlowOpen` metadata size; bulk bytes cross only the data sockets.
   **[Rust-terminal]**
9. **LF-AC9 — Fail-open on feeder error.** `run` with an unbindable socket dir, or a
   pump that errors, logs and returns/continues without panicking; a wiring test
   proves the proxy accept loops are unaffected. **[Rust-sandbox]**
10. **LF-AC10 — Clean shutdown.** When `shutdown` fires, the rendezvous file and the
    control/data socket files are removed (guard + listener drop) and pump tasks
    stop. **[Rust-terminal]**
11. **LF-AC11 — Bounded pending/concurrency.** `pending_opens`/`pending_data` do not
    grow past their cap (oldest evicted); a flood of unpaired `FlowOpen`s or data
    sockets cannot exhaust memory. **[Rust-sandbox]** (the pairing map unit) /
    **[Rust-terminal]** (end to end)
12. **LF-AC12 — Operator-only, no agent on-switch.** Enabling is config-only; a
    structural test proves no bus/MCP/`Session`/palette path reaches
    `CaptureSession::run`/`build_capture_session`, and the `activation_gate` test for
    `check_activation_caller` still holds. **[structural]** / **[Rust-sandbox]**
13. **LF-AC13 — No new wire-write path.** `one_choke_point_survives_ingress` extends
    to `macos_capture/feeder.rs`: it contains no `.inject(` and no `send_on_wire(`.
    **[structural]**

## Reconciliation with the macOS-NE milestone spec/plan

- **Task 18 is NOT "Change: none."** This feeder is the core runtime Task 18
  assumed existed. NE-AC17's real-Mac run depends on it; the milestone plan's Task 18
  entry should be corrected to depend on this feeder landing.
- **D2** — honoured verbatim: the feeder adds no dispatch; it calls
  `dispatch_captured_flow`, which routes TCP → `ProtocolModule` and UDP → `L4Guard`.
- **D3** — honoured: per-flow UDS + a metadata-only control channel, 0700 dir,
  fail-open when no core/peer. **Deviation (Architect's call):** D3's text specifies
  peer auth in one direction (provider verifies core). The feeder **adds** the
  symmetric core-verifies-provider check, because a same-uid non-provider can
  otherwise connect to the listener and read scope or inject fake flows. This is
  within NE-AC6's "authenticated handoff" intent and matches the Swift side's own
  per-socket verification discipline. Flagged for Matt to confirm (Open questions).
- **D4** — self-exclusion and loop avoidance stay provider-side; not the feeder's
  job. Version-bump/uninstall are the app's. No change.
- **D9** — the feeder's attach/detach naturally map to `CaptureCapability`
  `ApprovedAttached`/`Capturing` ⇄ not-attached, but wiring a live capability handle
  the app reads over the bus is **out of scope** here (Open questions).
- **NE-AC5/6/7** — the feeder is the core half: fail-open (AC5), authenticated
  handoff (AC6), control/data separation + per-flow backpressure (AC7). NE-AC3's
  deny-by-default is inherited unchanged from the adapter/ingress (the feeder adds
  no guard and no bypass).
- **PR #122 contract** — the feeder is exactly the "Task-9/18 feeder" the #122
  STATUS note said it did **not** build; it calls the documented call sites verbatim.

## Left to the builder

- The exact tuning constants within the stated defaults (scope poll interval 1 s,
  pending caps 1024, concurrency cap 4096) and the stale-half timeout.
- Whether `DataConnection` exposes its fd via `AsRawFd` or a `peer_fd()` method, and
  whether `ControlChannel` does the same — either is fine.
- The internal task structure (one `select!` task vs. a small set of spawned tasks
  sharing the pairing maps behind a mutex), provided the fail-open and bounds hold.
- Whether the socket dir default is a bare const or derived (e.g. uid-suffixed),
  within the `sun_path` budget and the single-rendezvous-path reality.
- The `security-framework` API surface used (its `os::macos::code_signing` module),
  provided `verify` fails closed on every error.

## Open questions

1. **Mutual peer auth.** Confirm the feeder should verify the **provider's** code
   signature (core-verifies-provider), not only rely on the provider verifying the
   core. (Architect's call: yes — same-uid squatter defence; within NE-AC6.) If no,
   the feeder trusts any same-uid connector in the 0700 dir.
2. **Live capability surfacing.** Should the feeder drive a live `CaptureCapability`
   handle (attach → `Capturing`, detach → not-attached) that the macOS app reads over
   the bus, or is that a separate follow-up? (Architect's call: follow-up — out of
   scope here.)
3. **Scope re-emission mechanism.** Polling (1 s) is the default minimal hook. Is an
   event-driven `watch` from the scope-mutation sites wanted now, or deferred?
   (Architect's call: polling now, `watch` deferred.)
