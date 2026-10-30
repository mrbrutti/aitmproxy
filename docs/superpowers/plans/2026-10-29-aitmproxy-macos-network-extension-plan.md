# macOS Network/System Extension capture path (L4 Phase 2) implementation plan

**Status:** approved (2026-10-29, by the orchestrator on Matt's behalf, autonomous
mode). **Implementation is HELD** until Matt answers the spec's three (a) items
(A1 Apple-portal setup, A2 flow-level-L4 ceiling, A3 packaging C1-vs-C2). Task 1
(the signing spike) runs first, on Matt's Mac via the Terminal panel, and is
blocked on A1 (it needs his Developer ID). All seven (b) defaults are locked per
the spec's Resolved decisions.
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-macos-network-extension-design.md`
**Branch / worktree:** `feat/macos-network-extension`

## Overview

This plan builds the macOS capture path in three bands, in strict risk order.

- **Band A — Stage-0 spike (Task 1), GATING.** Before any signed or packaged
  work, a throwaway experiment proves the risky part: sign and activate a
  do-nothing `NETransparentProxyProvider` system extension with Matt's Developer
  ID team, pass the two System Settings prompts, and push one flow across an
  authenticated Unix socket. Per WORKFLOW.md's Experiments track it runs in a
  **separate session and worktree on `experiment/macos-ne-spike`**, is **never
  merged**, and is written up with the experiment template. **No `[Mac]` or
  `[Build]` task (Tasks 10–18) starts until this spike proves the signing +
  activation path.**
- **Band B — `[Rust]` sandbox-TDD seam (Tasks 2–9).** These are provable by
  Rust tests against synthesized flows and need no Mac. They build the macOS
  capture *backend* in the `aitm` wiring layer that feeds the Phase-1
  protocol-general `CaptureIngress`. **Hard prerequisite:** that ingress
  (parent spec L4OPS-AC17).
  **Updated 2026-10-29:** L4 operator surfaces Phase 1 **landed on `main` (PR #45,
  `d8837ed`)**, bringing an **L4-only** `CaptureIngress`/`CoreIngress` in
  `crates/aitm/src/ingress.rs` (guarded by the real `L4Guard`). It **cannot** move
  into `aitm-core` (that would cycle with `aitm-proto-l4`), so the seam stays in
  `crates/aitm`. The missing **TCP/stream dispatch half** is delivered by a
  standalone prerequisite plan,
  `docs/superpowers/plans/2026-10-29-aitmproxy-capture-ingress-prereq-plan.md`,
  which extends that ingress with `CapturedTcpFlow` (carrying `peer_identity:
  Option<String>`), `dispatch_captured_tcp(ingress: &CoreIngress, …)` (authoritative
  dst → `ProtocolModule`, out-of-scope refusal, in-scope-unclaimed verbatim
  passthrough) and a `CapturedUdpFlow` adapter over the L4 path.
  **Reconciliation (supersedes Tasks 2–4 below):** Band B **consumes** that API and
  does **not** redeclare these types — the ingress is `CoreIngress` (not
  `CaptureIngress`), and the macOS `source_app: SourceAppId` maps onto the ingress's
  `peer_identity`. Because the prerequisite already realizes the seam-level dispatch,
  deny-by-default, and passthrough (the substance of NE-AC1/AC2/AC3), Band B's
  Tasks 2–4 **narrow to the macOS capture-backend adapter** (construct the
  `Captured*Flow` from the NE handoff and call the ingress) plus verifying the macOS
  path — to be re-scoped when Band B is dispatched.
  **UNBLOCKED 2026-10-29:** the prerequisite merged (PR #47, all-PASS panel). Band B
  may proceed; it is independent of the signing spike (which gates only Band C). Launch
  order: the independent Rust pieces first — **Task 8** (core-listener handoff topology;
  peer-auth defaulted to `LOCAL_PEERTOKEN` pending the spike), **Task 5**
  (L4Unavailable mapping), **Task 6** (capability-state), **Task 7** (operator-gate) —
  in parallel (disjoint files); **Task 9** after Task 8; the **macOS flow adapter**
  (narrowed ex-Tasks 2–4: map the handoff flow representation → `CapturedTcpFlow`/
  `CapturedUdpFlow`, `source_app`→`peer_identity`, call `dispatch_captured_tcp(&CoreIngress,…)`/
  `dispatch_udp`) **after Task 8 pins the flow representation** — no spike dependency.
  **Carry-over Minors from the PR #47 panel, to address in the Band B task that touches
  the code:** forward `in_scope` on `LateGuard`/`LateHandles` before any live capture
  routes through them (wiring task); match `handle_conn`'s logged path for the
  module-spawn error and dedup the hint/ctx block (adapter); add the passthrough
  dial-failure test and drop the needless `first_bytes` clone (adapter).
- **Band C — `[Mac]` / `[Build]` Terminal-panel build (Tasks 10–18).** The
  Swift sysex, the host-app activation/approval UX, nested signing and
  notarization, version-bump reconcile, capture indicator/uninstall, and the
  real-flow acceptance run. **The Claude Bash sandbox cannot sign, build
  Swift/Xcode, reach Apple, or run the extension**, so every Band-C task's test
  is a Terminal-panel command with an observable pass condition. Every Band-C
  task **depends on Task 1 (the spike)**.
  **Readiness (2026-10-29):** Band C's briefs (Tasks 10–18) are prepped and
  dispatch-ready; they are gated on **Task 1 (the signing spike)** which is gated on
  **Matt's Apple-portal setup (A1, confirmed he will do it)** — the two App IDs + two
  Developer ID profiles with the NE entitlement. Decisions are locked: **C1** (A3,
  embedded sysex), **operator-only** approval, **`/Applications`**, **Developer ID
  direct**. Fire these coders on a user turn once the portal + spike are done; each is
  `[Mac]`/`[Build]`, runs ONLY in the Terminal panel on a real Mac.
- **Final gate — Task 19**, the mandatory Stage-6 security review (NE-AC18).

**Parallelism.** Band-B tasks 2–9 are largely independent: each owns its own
file under `crates/aitm/src/macos_capture/` and its own test file. Task 2
creates `mod.rs`; tasks 3, 5, 6, 7, 8, 9 each only *append one `mod …;` line*
to it and otherwise touch disjoint files, so they can fan out to parallel Coder
child sessions with a trivial merge of that one line. Task 4 depends on Tasks 2
and 3. In Band C, Tasks 10 and 14 can start together once the spike passes;
Task 11 depends on 10; Tasks 12, 13, 16, 17 depend on 11; Task 15 depends on 14;
Task 18 depends on 11, 13, 15; Task 19 depends on everything.

**Open-question couplings (not resolved here — Matt's to answer; the plan takes
the spec's recommended default and flags it).**

- **OQ3 packaging C1 vs C2.** Band C assumes **C1** (sysex embedded in
  `Aitmproxy.app`); Tasks 10, 14, 15, 16 are written for one bundle. If Matt
  picks C2 (separate capture-host app), Tasks 10/14/15/16 re-target a second
  bundle and a second approval — a structural change, flagged per task.
- **OQ4 operator-only approval.** Tasks 7 and 13 assume activation is
  operator-only, gated like `ca.allow_agent_install`. If Matt wants an
  agent-drivable path, Task 7's default flips.
- **OQ1 parent-bundle location.** Tasks 14/18 assume `/Applications`; the spike
  (Task 1) settles whether `~/Applications` works.
- **OQ1 AC19 wording / OQ2 raw-packet ceiling.** Tasks 2–5 implement the **G1**
  reading (TCP → `ProtocolModule`, UDP → flow-level L4, raw-packet =
  `L4Unavailable`). A G2 rewording would change test *names/strings*, not the
  seam.
- **OQ9 QUIC.** No task forces QUIC→TCP fallback; UDP flows pass through as
  direct/guarded L4 per the default.

## Tasks

### Task 1: Stage-0 signing + activation spike (GATING, experiment track)

- **Satisfies:** none directly — **de-risks and unblocks** all `[Mac]`/`[Build]`
  tasks (10–18); settles spec Open-questions 5 & 6 and research OQ3/6/7.
- **Depends on:** none. **Gates Tasks 10–18.**
- **Track:** Experiment, not a Coder task. **Separate session + worktree on
  `experiment/macos-ne-spike`; never merged** (WORKFLOW.md §Experiments). Runs
  entirely in the Terminal panel on Matt's Mac.
- **Files:** a throwaway Xcode project under the experiment worktree (not this
  branch); write-up at `docs/research/experiments/2026-10-29-macos-ne-spike.md`
  (the only artifact that lands, via the experiment write-up, not as code).
- **Change:** a minimal host app + a do-nothing `NETransparentProxyProvider`
  sysex signed with Matt's Developer ID team (two App IDs, two profiles);
  `OSSystemExtensionRequest.activationRequest`; a catch-all included rule; a
  provider that connects one Unix socket back to a tiny listener and echoes one
  flow; manual `codesign` with the full entitlement set incl.
  `com.apple.application-identifier` + `com.apple.developer.team-identifier`.
- **Test / pass condition (Terminal panel):**
  1. `systemextensionsctl list` shows the extension **`[activated enabled]`**
     after the two System Settings prompts are approved.
  2. `codesign -d --entitlements :- <sysex>` shows the NE array value
     **`app-proxy-provider-systemextension`**.
  3. The listener logs **one** flow's bytes crossing the socket, and the socket
     directory is mode **`0700`**.
  4. Record which parent-bundle location worked (`/Applications` vs
     `~/Applications`) and whether `LOCAL_PEERTOKEN` peer-signature validation
     was feasible or XPC `setCodeSigningRequirement` was needed.
- **Done when:** the write-up states Proven/Disproven for each of OQ5/6 and
  research OQ3/6/7, and names the peer-auth mechanism and parent-bundle location
  the real build (Tasks 11, 14) must adopt. **Nothing from the branch is reused
  as code.**

### Task 2: macOS capture-backend adapter → `CaptureIngress` (folds old Tasks 2–4)

- **Satisfies:** NE-AC1, NE-AC2, NE-AC3.
- **Depends on:** `CaptureIngress` **and Task 8 — both now on `main`** (PR #47 and
  PR #60). **Launchable now;** cut the worktree from current `main`.
- **Scope note (why this folds old Tasks 2–4):** the ingress TCP/UDP dispatch,
  deny-by-default, authoritative-dst `NextLayerHint`, and in-scope-unclaimed passthrough
  **already exist on `main`** (prereq plan, PR #47). This task is the **thin macOS
  adapter** that converts a handoff flow into the ingress's own types and calls it — it
  does **not** re-implement dispatch and does **not** redeclare the flow types. NE-AC3
  (deny-by-default) is satisfied by the ingress itself; this task asserts the macOS path
  routes through it.
- **Files:** `crates/aitm/src/macos_capture/adapter.rs` (create),
  `crates/aitm/tests/macos_capture_adapter.rs` (create),
  `crates/aitm/src/macos_capture/mod.rs` (create-or-extend — `mod adapter;`; trivial
  parallel-merge with the other Band-B tasks' one-line appends),
  `crates/aitm/src/ingress.rs` (modify — carry-over Minor fixes only, below).
- **Change:** consume Task 8's landed handoff in `crate::macos_capture::listener`:
  accept the provider's control channel (`CaptureListener::accept_control` →
  `ControlChannel`), read each `ControlMessage::FlowOpen { flow_id, kind, remote,
  remote_hostname, source_app, local }`, and take its per-flow data socket
  (`accept_data` → `DataConnection`, correlated by `flow_id`). Map onto the ingress
  types **defined in `crates/aitm/src/ingress.rs`** (do not redeclare): for `FlowKind::Tcp`,
  build `CapturedTcpFlow { stream, dst, sni, first_bytes, peer_identity }` from
  `remote → dst`, `remote_hostname → sni`, `source_app → peer_identity`,
  `DataConnection::into_stream() → stream` (peeking its leading bytes for `first_bytes`);
  for `FlowKind::Udp`, build `CapturedUdpFlow { target, datagrams, peer_identity }` from
  `remote → target` and `DataConnection::recv_datagram` → `datagrams`. Then call
  `dispatch_captured_tcp(&CoreIngress, flow)` (TCP) and `CoreIngress::dispatch_udp(&flow)`
  (UDP). **No new guard** — deny-by-default is enforced inside the ingress (`dispatch_tcp`
  refuses out-of-scope before any dispatch; `dispatch_udp` via `L4Guard`). Validate
  `Hello.protocol_version` here (the version check the listener deferred to the adapter)
  and refuse a mismatch.
  **Carry-over Minors from the PR #47 panel, fix here in `ingress.rs`:** (b) log the
  module-spawn error the way `handle_conn` does, and dedup the duplicated hint/ctx block;
  (c) add the passthrough dial-failure test; (d) drop the needless `first_bytes` clone.
- **Test:** `macos_tcp_flow_adapts_and_dispatches` — a synthesized handoff TCP flow to
  `dst = 93.184.216.34:443`, `sni = Some("example.com")`, a set `source_app` becomes a
  `CapturedTcpFlow` whose `peer_identity` is the mapped source-app id, and
  `dispatch_captured_tcp` returns `StreamOutcome::Dispatched` with the HTTP module's
  `NextLayerHint.dst.to_string() == "93.184.216.34:443"`; an **out-of-scope** flow
  returns `StreamOutcome::Refused` with zero dispatch. `macos_udp_flow_adapts_and_dispatches`
  — in-scope UDP admitted, out-of-scope refused via `L4Guard`. Plus the (c) passthrough
  dial-failure test.
- **Done when:** the tests pass and the full gate passes.

### Task 3: ~~UDP flow → flow-level L4 unit behind L4Guard~~ — FOLDED into Task 2

The ingress already dispatches UDP via `L4Guard` (prereq PR #47). The macOS UDP
adaptation is the `CapturedUdpFlow` half of the Task 2 adapter; there is no separate
UDP dispatch function to build. Superseded.

### Task 4: ~~Deny-by-default below the ingress (both protocols)~~ — FOLDED into Task 2

Deny-by-default below the ingress is enforced **inside** the ingress on `main` (prereq
PR #47: `dispatch_tcp` refuses out-of-scope before any dispatch; `dispatch_udp` via
`L4Guard`), and was verified by that PR's Stage-6 security panel. Task 2's adapter tests
assert the macOS path routes through it (NE-AC3); no separate choke is added. Superseded.

### Task 5: Raw packet-level L4 honestly unavailable on the macOS embedded core

- **Satisfies:** NE-AC4.
- **Depends on:** `CaptureIngress` (on `main`). Independently launchable now — creates-or-extends `crates/aitm/src/macos_capture/mod.rs` + the `lib.rs` export (trivial parallel-merge with the other Band-B tasks).
- **Files:** `crates/aitm/src/macos_capture/availability.rs` (create),
  `crates/aitm/tests/macos_capture_availability.rs` (create),
  `crates/aitm/src/macos_capture/mod.rs` (modify — append `mod availability;`).
- **Change:** a mapping that, on the macOS embedded core, makes `l4.inject`,
  `l4.send_recv`, and the `l4.intercept.*` verbs return
  `L4GuardError::L4Unavailable(reason)` (never a panic, never silence) whose
  `reason` names macOS as flow-level and raw-packet L4 as Linux-only. Exact
  wording is the builder's within that.
- **Test:** `raw_packet_verbs_unavailable_on_macos` — for each of the three
  verbs the result is `L4GuardError::L4Unavailable(_)` and the reason string
  **contains** the literal substrings **`"flow-level"`** and **`"Linux-only"`**.
- **Done when:** the test passes and the full gate passes.

### Task 6: Capture-capability state + honest degradation reason (core side)

- **Satisfies:** NE-AC10 (Rust / capability-state-mapping side).
- **Depends on:** `CaptureIngress` (on `main`). Independently launchable now — creates-or-extends `macos_capture/mod.rs` + `lib.rs` export (trivial parallel-merge).
- **Files:** `crates/aitm/src/macos_capture/capability.rs` (create),
  `crates/aitm/tests/macos_capture_capability.rs` (create),
  `crates/aitm/src/macos_capture/mod.rs` (modify — append `mod capability;`).
- **Change:** `pub enum CaptureCapability { ExtensionNotInstalled, PendingApproval,
  ApprovedAttached, Capturing, Degraded(String) }` and a mapping such that when
  the state is not `ApprovedAttached`/`Capturing`, every macOS wire verb returns
  `L4Unavailable { reason }` whose reason **names the extension as the path**
  (extends L4OPS-AC18); when `ApprovedAttached`, the verb proceeds.
- **Test:** `degraded_until_attached_names_extension` — in
  `ExtensionNotInstalled`, a wire verb returns `L4Unavailable` whose reason
  **contains** the literal substring **`"approve the extension"`**; in
  `ApprovedAttached`, the same verb does **not** return `L4Unavailable`.
- **Done when:** the test passes and the full gate passes.

### Task 7: Operator-only approval gate (agent cannot install/approve the sysex)

- **Satisfies:** NE-AC11 (gate).
- **Depends on:** `CaptureIngress` (on `main`). Independently launchable now — creates-or-extends `macos_capture/mod.rs` + `lib.rs` export (trivial parallel-merge).
- **Files:** `crates/aitm/src/macos_capture/activation_gate.rs` (create),
  `crates/aitm/tests/macos_capture_gate.rs` (create),
  `crates/aitm/src/macos_capture/mod.rs` (modify — append `mod activation_gate;`).
- **Change:** a config flag `allow_agent_sysex_install: bool` (**default false**,
  mirroring `ca.allow_agent_install` / `l4.allow_agent_widen` in
  `crates/aitm-proto-l4/src/config.rs`) and a guard
  `fn check_activation_caller(origin, cfg) -> Result<(), ActivationRefused>` that
  refuses the sysex install/activation command when the caller is the **agent
  frontend** (the same caller-origin discriminator the bus already carries for
  `ca.allow_agent_install`) and the flag is false. **Operator-only confirmed
  (Matt's A-answers). SHIPPED on `main` via PR #60.**
- **Test:** `agent_cannot_trigger_sysex_install` — with default config, an
  agent-origin call returns `Err(ActivationRefused)`; an operator-origin call
  returns `Ok(())`; with `allow_agent_sysex_install = true`, the agent-origin
  call returns `Ok(())`.
- **Done when:** the test passes and the full gate passes.

### Task 8: Core-listener handoff — control/data separation, 0700 dir, per-flow backpressure

- **Satisfies:** NE-AC7 (Rust loopback round-trip), NE-AC6 (core-listener side). Also folds carry-over Minor (a): forward `in_scope` on the delegating `LateGuard` (`crates/aitm/src/wire.rs`) and `LateHandles` (`crates/aitm/src/scripts.rs`) so the capture path's guard delegation is complete before a live feeder routes through it.
- **Depends on:** `CaptureIngress` (on `main`). Independently launchable now — creates-or-extends `macos_capture/mod.rs` + `lib.rs` export (trivial parallel-merge). Pins the handoff flow representation that Task 2 (adapter) maps from. The shared `CapturedTcpFlow`/`CapturedUdpFlow` types come from `crates/aitm/src/ingress.rs` — do not redeclare them.
- **Files:** `crates/aitm/src/macos_capture/listener.rs` (create),
  `crates/aitm/tests/macos_capture_listener.rs` (create),
  `crates/aitm/src/macos_capture/mod.rs` (modify — append `mod listener;`).
- **Change:** `pub struct CaptureListener` that creates its control-socket
  directory **mode 0700**, binds a control UDS, and accepts **one data socket per
  flow**; a control codec carrying only {hello, scope/intercept spec, per-flow
  open metadata (flow id, TCP|UDP, original remote endpoint, `remoteHostname`,
  source-app id, local endpoint for UDP)} and a per-flow data path carrying raw
  bytes (TCP) / length-delimited datagrams (UDP). Wire format is the builder's,
  within control/data separation. (Peer **code-signature** validation is the
  provider's job — Task 11 / `[Mac]`; this task proves the socket topology and
  the private directory.)
- **Test:** `control_and_data_separation_roundtrip` — over a loopback UDS pair,
  send a hello + one flow-open metadata on the control channel and a **65536**-byte
  payload on that flow's data socket; assert `data_received.len() == 65536`, the
  control channel carried **0** bulk payload bytes, and
  `fs::metadata(dir).permissions().mode() & 0o777 == 0o700`.
- **Done when:** the test passes and the full gate passes.

### Task 9: No CA key reaches the capture backend

- **Satisfies:** NE-AC16 (Rust / no-key side).
- **Depends on:** Task 8 — **on `main`** (PR #60). **Launchable now;** cut from current `main`.
- **Files:** `crates/aitm/tests/macos_capture_no_key.rs` (create). (Behavioural
  assertion only; no production change expected if Tasks 2 & 8 already exclude
  the key.)
- **Change:** none, unless the test shows the handoff types expose a key — then a
  minimal removal. The capture backend and its control/data messages must carry
  no CA private-key material.
- **Test:** `control_hello_carries_no_ca_key` — wire a backend whose core holds a
  CA with a known private-key DER byte sequence `KEY_DER`; drive one flow through
  the listener (Task 8); assert the concatenated control + data bytes sent to the
  provider **do not contain** `KEY_DER` (`bytes.windows(KEY_DER.len()).any(…) ==
  false`).
- **Done when:** the test passes and the full gate passes.

### Task 10: Xcode sysex target — `NETransparentProxyProvider` skeleton + fail-open

- **Satisfies:** NE-AC5 (fail-open behaviour implemented; end-to-end verified in
  Task 18). **[Mac]/[Build].**
- **Depends on:** Task 1 (spike).
- **Files (C1 — confirmed, Matt's A3: sysex embedded in `Aitmproxy.app`):** `apps/mac/Extension/Aitmproxy.xcodeproj` (create),
  `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (create),
  `apps/mac/Extension/Sources/main.swift` (create),
  `apps/mac/Extension/Info.plist` (create).
- **Change:** `class TransparentProxyProvider: NETransparentProxyProvider` with
  `startProxy`, one **catch-all** included rule (any remote, prefix 0, protocol
  any, outbound), and `handleNewFlow` that returns `false` (flow goes direct)
  whenever there is **no attached control channel / no spec / no matching scope**
  — the fail-open contract. `main.swift` calls
  `NEProvider.startSystemExtensionMode()` early then `dispatchMain()`. `Info.plist`
  carries `CFBundlePackageType = SYSX`, `NSSystemExtensionUsageDescription`, and
  a `NetworkExtension` dict mapping `NEProviderClasses` → the provider class.
  Uses current macOS 26+ APIs (`remoteFlowEndpoint`, `localFlowEndpoint`,
  audit-token identity), not deprecated `NWHostEndpoint`.
- **Test / pass condition (Terminal panel):**
  `xcodebuild -project apps/mac/Extension/Aitmproxy.xcodeproj -scheme Extension build`
  **exits 0**, and `plutil -p apps/mac/Extension/Info.plist` shows
  `"CFBundlePackageType" => "SYSX"` and the `NEProviderClasses` mapping. Fail-open
  is asserted end-to-end in Task 18 (no-core-attached → browsing unaffected).
- **Done when:** the build exits 0 and the plist keys are present (Terminal panel).

### Task 11: Provider ↔ core handoff + peer code-signature validation

- **Satisfies:** NE-AC6 (end-to-end), NE-AC7 (end-to-end).
- **Depends on:** Task 1, Task 8 (the Rust listener it connects to), Task 10.
- **Files:** `apps/mac/Extension/Sources/FlowHandoff.swift` (create),
  `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify).
- **Change:** on each handled flow, connect the per-flow data socket, send the
  handshake + metadata on the control channel, and run the two copiers
  (write-all-before-read, inbound reads capped) for TCP / length-delimited
  datagrams for UDP. **Before sending any flow**, validate the core's code
  signature via the peer audit token (`LOCAL_PEERTOKEN`) resolved to a code
  requirement, or XPC `setCodeSigningRequirement` — **whichever the spike (Task
  1) proved**; a peer failing the requirement receives **no** flow data.
- **Test / pass condition (Terminal panel, real Mac):** with the real core
  listening, capture one in-scope flow and confirm its bytes cross the per-flow
  socket while the control channel carries only metadata (log inspection /
  `fs_usage`); then start a **decoy** listener on the control dir that fails the
  code requirement and confirm it receives **zero** flow bytes. Pass: real core
  gets the flow, decoy gets nothing.
- **Done when:** both conditions hold (Terminal panel).

### Task 12: Loop avoidance — self-exclusion by source-app identity

- **Satisfies:** NE-AC8.
- **Depends on:** Task 1, Task 11.
- **Files:** `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify — the
  two entry-point call sites) and `apps/mac/Extension/Sources/FlowHandoff.swift` (modify —
  the `SelfExclusion` predicate, placed beside the sibling identity/auth helpers in the
  same Extension target and testable from the DEBUG self-check; Files line expanded
  2026-10-30 per the Task-12 spec-panel finding).
- **Change:** in `handleNewFlow` **and** `handleNewUDPFlow`, exclude flows whose
  **source app is signed by our Developer ID team** — the source-app **audit token**
  resolved to a `SecCode` and checked against the team requirement (OU `995PCLM9KH`),
  reusing Task 11's `PeerAuth.verifyPeer`. Keyed on the code signature, not pid and not a
  guessed identifier string; rely on wildcard rules already excluding loopback (the bus,
  obscura↔core on 127.0.0.1).
- **Why by team code signature (security panel, 2026-10-30):** aitm and obscura are both
  team-signed, so both are excluded regardless of their specific signing identifier — this
  **eliminates** the self-DoS a guessed "aitm"/"obscura" string risked (a wrong guess would
  silently self-capture and loop). It over-excludes any other `995PCLM9KH`-signed binary,
  which in practice is only aitmproxy's own — acceptable; narrowing to aitm's full
  designated requirement (spec D4 "aitm and obscura specifically") is a tracked GA-hardening
  item. NE-AC8's live confirmation (zero self-/loopback flows) still happens at Task 18.
- **Test / pass condition (Terminal panel, real Mac):** run a capture session with
  the core dialing upstream and obscura browsing; inspect the flow list and
  confirm **no** flow is attributed to `aitm` or `obscura` and no loopback flow
  appears. Pass: zero self-originated flows captured.
- **Done when:** the condition holds (Terminal panel).

### Task 13: Host-app activation, two-prompt approval, capability transition (+ operator gate e2e)

- **Satisfies:** NE-AC9; NE-AC10 (end-to-end); NE-AC11 (end-to-end).
- **Depends on:** Task 1, Task 7 (the Rust gate), Task 11.
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (create),
  `apps/mac/Sources/Aitmproxy/Bus/CoreHealthState.swift` (modify — the
  capture-capability property beside core health). **Files-line expanded 2026-10-30 per
  the Task-13 panel:** `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift` (create — the
  pure `CaptureCapability` state machine + `CaptureExtension` bundle gate, in AitmproxyKit
  so it is unit-testable; the `Aitmproxy` executable has no test target),
  `apps/mac/Tests/AitmproxyKitTests/CaptureCapabilityTests.swift` (create — 14 tests), and
  `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify — the single operator
  activation call site in the launch `.task`). **`App.swift` is deliberately UNTOUCHED**
  (the orchestrator required minimal App.swift because another session was rewriting it;
  `ShellView`'s `.task` is the real launch surface and there is exactly one `Window`, so
  one controller).
- **Change:** submit `OSSystemExtensionRequest.activationRequest` to
  `OSSystemExtensionManager.shared` early; keep the app alive while pending;
  surface `CaptureCapability` transitions `extension-not-installed → pending-approval
  → approved-attached → capturing`; wire the trigger to the **operator** path only
  (agent/`Frontend::Mcp` cannot invoke it — Task 7 gate). **Operator-only is
  confirmed (Matt's A-answers); the gate is Task 7's `allow_agent_sysex_install`
  (default off), now on `main`.**
- **Test / pass condition (Terminal panel, real Mac):** launch the app; complete
  the two System Settings prompts (Network Extensions approve + Add Proxy
  Configurations Allow); confirm the UI capability reaches **`approved-attached`**
  and, before approval, every wire verb returned `L4Unavailable` naming the
  extension. Separately confirm an MCP-driven trigger is **refused** (no prompt
  appears). Pass: capability transitions as listed; agent trigger refused.
- **Done when:** the conditions hold (Terminal panel).

### Task 14: Entitlement plists + inside-out signing in `build.sh` (regression fix)

- **Satisfies:** NE-AC12 (development build carries entitlements).
- **Depends on:** Task 1, Task 10.
- **Files:** `apps/mac/Aitmproxy.entitlements` (create — app),
  `apps/mac/Extension/Aitmproxy-Extension.entitlements` (create — sysex),
  `apps/mac/build.sh` (modify). **Do not** reuse `EmbeddedObscura.entitlements`.
- **Change:** app entitlements carry `com.apple.developer.networking.networkextension`
  (array), `com.apple.developer.system-extension.install = true`,
  `com.apple.application-identifier`, `com.apple.developer.team-identifier`; sysex
  entitlements carry the NE array + the App-ID/team claims. `build.sh`: assemble
  the sysex at `Contents/Library/SystemExtensions/<sysex-id>.systemextension`,
  copy each `embedded.provisionprofile`, **sign the sysex first (inside-out) then
  the app**, each with an explicit `--entitlements`. Install to **`/Applications`**
  (B3 default; the Task-1 spike confirms whether `~/Applications` also satisfies the
  parent-bundle check). Fixes today's `--force` /
  no-`--entitlements` re-sign (the app currently ships with no entitlements).
- **Test / pass condition (Terminal panel):** after `apps/mac/build.sh`,
  `codesign -d --entitlements :- <app>` and `… <sysex>` each show the NE array
  value **`app-proxy-provider-systemextension`** (or the dev-identity
  **`app-proxy-provider`** value), and the app shows
  `com.apple.developer.system-extension.install`. Pass: both entitlement sets
  present; neither empty.
- **Done when:** the condition holds (Terminal panel).

### Task 15: Nested Developer ID signing, verify-or-fail, and notarization in `notarize-dmg.sh`

- **Satisfies:** NE-AC13; NE-AC12 (release verify step).
- **Depends on:** Task 14.
- **Files:** `scripts/notarize-dmg.sh` (modify). (`scripts/make-dmg.sh` unchanged
  — `ditto` preserves signatures.)
- **Change:** re-sign **inside-out with Developer ID** (`--options runtime
  --timestamp`): the **sysex first** (its `-systemextension` entitlements +
  embedded Developer ID profile), then `obscura`, `aitm`, then the **app with
  `--entitlements`** + its embedded profile. Extend the verify step to dump
  entitlements from both (`codesign -d --entitlements :-`) and **fail the build**
  if the NE array lacks the `-systemextension` suffix or the app lacks
  `system-extension.install`. `notarytool submit --wait` + `stapler` on the DMG
  unchanged.
- **Test / pass condition (Terminal panel):** run the signed path; the verify step
  **exits non-zero** on a deliberately stripped entitlement and **exits 0** when
  correct; `stapler validate <dmg>` and `spctl --assess` **pass**. Pass: verify
  gate fails-closed on missing entitlements; staple/spctl pass on the good build.
- **Done when:** the conditions hold (Terminal panel).

### Task 16: Version-bump discipline + proxy-configuration reconcile

- **Satisfies:** NE-AC14.
- **Depends on:** Task 1, Task 11.
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (modify),
  `apps/mac/Extension/Info.plist` (modify — `CFBundleVersion` comment; `build.sh`
  already stamps `__BUILD__` with a timestamp, so no literal bump is needed).
  Beyond the declared list (recorded here per workflow): the settle/backoff/
  connected-check schedule is extracted as the pure, unit-tested
  `TunnelReconcilePolicy` in `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift`
  (modify), with coverage in
  `apps/mac/Tests/AitmproxyKitTests/CaptureCapabilityTests.swift` (modify) — keeping
  the framework-facing controller thin, matching the Task-13 split.
- **Change:** `actionForReplacingExtension` returns `.replace`; after a
  replacement, reconcile the saved `NETransparentProxyManager` configuration
  (settle delay + connected-check) so a version bump does not leave it disabled
  (leash #58). Settle/backoff constants are the builder's.
- **Test / pass condition (Terminal panel, real Mac):** bump the sysex
  `CFBundleVersion`, rebuild, reactivate; confirm `systemextensionsctl list`
  shows the **new** version `[activated enabled]` and the proxy configuration is
  **re-enabled** (capture resumes) without a manual re-approval. Pass: new version
  active and configuration enabled.
- **Done when:** the condition holds (Terminal panel).

### Task 17: Capture indicator + uninstall

- **Satisfies:** NE-AC15.
- **Depends on:** Task 1, Task 11.
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (modify),
  `apps/mac/Sources/Aitmproxy/SettingsView.swift` (modify — indicator + uninstall
  control). Beyond the declared list (recorded here per workflow):
  `apps/mac/Sources/AitmproxyKit/CaptureCapability.swift` (modify — the `.uninstalled`
  event and the `isCaptureOn` / `isInstalledOrInstalling` / `canUninstall` predicates
  the indicator and button read) + its tests in
  `apps/mac/Tests/AitmproxyKitTests/CaptureCapabilityTests.swift` (modify); and
  `apps/mac/Sources/Aitmproxy/Bus/CoreHealthState.swift` (modify — a weak
  `extensionController` handle, published by `start()`, so the Settings window, a
  separate scene, can reach the controller to uninstall without a global singleton
  and without touching `ShellView`). The build owner replaced the coder's first cut
  (a `static weak var current` on the controller) with this handle: same operator-only
  reachability, no global mutable state.
- **Change:** show a visible "capture is on" indicator while the extension is
  active and attached; an uninstall path that submits `deactivationRequest` and
  removes the `NETransparentProxyManager` configuration. Indicator obeys the
  monochrome/editorial UI rule.
- **Test / pass condition (Terminal panel, real Mac):** with capture attached the
  indicator reads **on**; invoke uninstall and confirm `systemextensionsctl list`
  no longer shows the extension as enabled and the saved proxy configuration is
  gone. Pass: indicator reflects state; uninstall deactivates + removes config.
- **Done when:** the condition holds (Terminal panel).

### Task 18: Real in-scope flow captured end to end (milestone acceptance)

- **Satisfies:** NE-AC17; NE-AC16 (Mac / real HTTPS MITM, no key in extension);
  NE-AC5 (fail-open end-to-end).
- **Depends on:** Task 11, Task 13, Task 15.
- **Files:** none (acceptance run); results recorded in the plan's Shipped section
  at Stage 7.
- **Change:** none — exercises the built system. The in-scope target is the
  builder's choice (loopback may not be capturable — spec "Left to the builder";
  a non-loopback in-scope target may be required).
- **Test / pass condition (Terminal panel, real Mac, extension approved):**
  1. A real **in-scope HTTPS** flow is captured, **MITM'd** (decrypted via the
     core's CA), and appears in the flow list; the extension process holds **no
     CA key** (`codesign`/memory inspection shows none handed over).
  2. A real **in-scope UDP** flow appears as an **L4 flow**.
  3. **Out-of-scope** traffic is **not** captured.
  4. With the core stopped, ordinary browsing is **unaffected** (fail-open,
     NE-AC5).
  5. **CROSS-UI (Matt's explicit mandate, 2026-10-30):** the captured in-scope flow
     (HTTPS + the L4/UDP flow) must appear in **all three UIs reading the same core**:
     (a) the **macOS app**, (b) **`aitm web`**, (c) **`aitm tui`** — not just at the
     provider. Capture proof + a shot/assertion from each UI.
  Pass: all five observed on a real Mac — the milestone's "real packets, not
  screenshots" bar.
- **REPEATABLE E2E SCRIPT (Matt's mandate, 2026-10-30):** everything about the NE that
  CAN be automated is scripted + asserted on ground truth under **`tests/e2e/ne/`**
  (aligning with the `e2e-test-arch` `tests/e2e/` runner once it lands): build/sign/
  notarize/install checks (codesign -d entitlements, stapler/spctl, systemextensionsctl
  parse), the provider↔core handoff (the Rust `CaptureListener` round-trip, already in
  `macos_capture_*` tests), loop-avoidance self-exclusion, and the capability state
  machine (the `CaptureCapabilityTests`). The **ONLY** manual step allowed is the **two
  System Settings approval clicks** (Apple requires a human); the script pauses for them
  and resumes, asserting `[activated enabled]` + the cross-UI appearance afterward.
  **Depends on:** the `e2e-test-arch` runner + the orchestrator's core-side rendezvous
  writer + Task-2 scope-spec emitter landing first.
- **LIVE-VERIFICATION CARRY-FORWARDS (from the 16/17 panel, 2026-10-30):**
  - Confirm whether a real Mac emits a transient `NEVPNStatus.invalid` during a version-bump
    replacement. If it does NOT, map `.invalid` to a degrade in
    `ExtensionController.applyTunnelStatus` so an externally-removed proxy configuration stops
    reading "Capture is on" (today `.invalid` is advisory to avoid a sticky degrade on a
    replacement blip).
  - Confirm whether `OSSystemExtensionRequest` deactivation is ever human-gated (a System
    Settings prompt). If NEVER, harden `deactivate()` with a bounded timeout guarded by
    `deactivation != nil` (so a late real callback cannot double-resume) against a dropped
    terminal callback; if it IS human-gated, surface a "needs approval" state during uninstall
    instead of a silent "Removing…".
  - Confirm the `NEVPNError.code → TunnelFailure` classification against real reconcile
    failures — especially that refusing "Add Proxy Configurations" is permanent (not retried).
- **Done when:** all five conditions hold on a real Mac AND the repeatable `tests/e2e/ne/`
  script passes every automatable assertion (Terminal panel).

### Task 19: Mandatory Stage-6 security review

- **Satisfies:** NE-AC18.
- **Depends on:** Tasks 2–18.
- **Files:** a findings report (reviewer output), recorded in the Review log.
- **Change:** none — a `security-reviewer` pass (plus the parallel quality/spec
  reviewers) over the whole branch, confirming: deny-by-default survives the
  extension layer (no un-guarded flow), the handoff is peer-authenticated and
  fails open, no CA key reaches the extension, and no agent can install/approve
  it.
- **Test / pass condition:** the security review returns **no open Critical/
  Important findings**; any Minor is fixed or accepted by Matt in the Review log.
- **Done when:** the panel has no open findings and the Review log is complete.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 14 | spec | Important | NE build installed to `~/Applications`, where the sysex cannot activate (spike: Code=3); must be `/Applications` | fixed — build.sh now selects `/Applications` for an NE build, keeps `~/Applications` for the dev loop |
| 10 | spec | Important | Catch-all rule was `.TCP`, foreclosing UDP capture (NE-AC2/AC17); plan says "protocol any" | fixed — rule now `protocol: .any` (TCP+UDP) |
| 14 | security, quality | Minor | `codesign … \| grep -v … \|\| true` swallows codesign's exit status; a failed restricted-entitlement sign still prints "installed (signed)" | fixed — new `cs()` wrapper aborts the build on codesign failure |
| 14 | quality | Minor | "no sysex embedded" hint named `SIGN_IDENTITY`, but the code reads `NE_SIGN_IDENTITY` | fixed — hint corrected to `NE_SIGN_IDENTITY` |
| 10 | quality | Minor | Deprecated `NENetworkRule(remoteNetwork:…)` init (macOS 15) emits a build warning; Task 10 says "not deprecated NWHostEndpoint" | fixed — switched to the non-deprecated `remoteNetworkEndpoint:` init; `swiftc` compiles clean (no warning) |
| 10 | spec | Minor | `swiftc` build replaces the plan's `apps/mac/Extension/Aitmproxy.xcodeproj` (spec D6) | **accepted by Matt 2026-10-30** (via orchestrator) — repo is SwiftPM-only ("no Xcode project", apps/mac/CLAUDE.md) and the Task-1 spike proved swiftc + manual codesign handles the `-systemextension` entitlement on Xcode 27.1; spec D6 to be amended to swiftc |
| 11 | spec, security, quality | n/a | **PASS panel 2026-10-30** — no Critical/Important; security signed off the code + model (NE-AC6/AC7). | — |
| 11 | quality | Minor | `decodeCore` was stricter than its forward-compat doc (non-object payload tore the channel down) | fixed — accepts any single-key object as ignored |
| 11 | quality | Minor | Unowned `TODO(tighten)` on the team-wide requirement | fixed — TODO now references the plan Review log / Task 11 hardening |
| 11 | quality | Minor | ~680-line DEBUG self-check co-located in `FlowHandoff.swift` | noted in-code as deliberate (no separate test target; `#if DEBUG` excludes it from release); splitting tracked as cleanup |
| 11 | security | Minor | Code requirement is team-wide (`OU=995PCLM9KH`), not aitm's full designated requirement | **accepted (hardening TODO)** — plan Task 11 specifies the team requirement; narrow to aitm's identifier before GA (TODO in code) |
| 11 | security | Minor | Inherent `LOCAL_PEERTOKEN` TOCTOU (verified core passing its fd on) — outside threat model; pidversion defeats pid-reuse | **accepted** — confirm at Task 18 the real core passes no accepted fds to unverified children |
| 11 | security | Minor | `claim()` can block the NE queue up to ~4s under a wedged (verified) core before fail-open | **accepted (low priority)** — bounded + self-gated; optional move off-queue / lower timeout as hardening |
| 11 | security | Minor | No cap on concurrent claimed flows (threads/memory per flow in the root sysex) | **accepted (hardening TODO)** — add a soft cap (fail open past it) as a follow-up |
| 11 | security | Minor (info) | `FD_CLOEXEC` set result ignored (no exec in the sysex today) | accepted — informational |
| 11 | spec, security, quality | Minor | Live decoy/real-core round-trip + core-side rendezvous writer + scope-spec emitter not exercised here | **deferred by design** — live decoy run → Task 18; rendezvous writer + scope emitter are core-side follow-ups (flagged in code + PR #100) |
| 12 | spec | Important | `SelfExclusion` added to `FlowHandoff.swift`, not named in Task 12's Files list (undeclared file) | fixed — Task 12 Files line expanded to declare `FlowHandoff.swift` (placement beside the sibling identity helpers, testable from the DEBUG self-check); no cross-task leak |
| 12 | security | Important | Self-exclusion rested on *guessed* signing identifiers; a wrong/under-match silently self-captures → loop (self-DoS) | **FIXED (orchestrator override of the tracked-acceptance)** — re-hardened to check the source-app **audit token** against the team requirement (OU `995PCLM9KH`) via Task 11's `PeerAuth.verifyPeer`; aitm/obscura are both team-signed so the guess is eliminated. Security panel re-run for a clean sign-off |
| 12 | security | Minor | Over-match: now excludes ANY `995PCLM9KH`-signed binary, broader than spec D4 "aitm/obscura specifically" | **accepted** — in practice the only team-signed binaries a user runs are aitmproxy's own; GA-narrowing uses the decoupled `SelfExclusion.selfRequirement` and MUST cover both aitm AND obscura designated requirements (next row) |
| 12 | security (re-review) | Minor | Self-exclusion reused `PeerAuth.coreRequirement`; narrowing that to aitm-only at GA would silently stop excluding obscura → loop | **FIXED (pre-merge)** — gave self-exclusion its own `SelfExclusion.selfRequirement` constant, decoupled from the core-peer requirement, so the two GA-narrowings cannot entangle; obscura stays excluded. Security re-review verdict: **PASS / clean sign-off** |
| 12 | security | Minor | No automated unit test for `isSelf` | **accepted** — it is now a `SecCode` call (needs a real process), not a pure predicate; live confirmation of zero self/loopback flows at Task 18 |
| 13 | spec, security, quality | n/a | **PASS panel 2026-10-30** — all three PASS, no Critical/Important. NE-AC9/10/11 met at the code level; live `[Mac]` checks HELD to Task 18. | — |
| 13 | spec, quality, security | Minor | Declared `App.swift` left untouched; activation wiring in `ShellView.swift`; pure state machine + test in `AitmproxyKit`, not the declared files | **accepted** — Files line expanded above; App.swift untouched by the orchestrator's instruction (another session rewrites it); `Aitmproxy` executable has no test target so pure logic went to AitmproxyKit (mirrors `CoreHealth`). Not a cross-task leak |
| 13 | quality | Minor | `applyTunnelStatus` called synchronously after `startVPNTunnel` is a no-op in the common path | **FIXED** — comment added noting it only catches a reused already-connected manager |
| 13 | quality | Minor | `applying(.activated)`/`.needsUserApproval` reset away from `.capturing` unguarded (asymmetric with tunnel events) | **FIXED (doc)** — `applying(_:)` doc now states activation events are authoritative and intentionally override `.capturing` (a real re-approval), while tunnel events are advisory |
| 13 | security | Minor | "single call site" of `ExtensionController.start()` is convention, not compiler-enforced; a future second caller could reach activation | **accepted (non-exploitable)** — the reviewer confirmed FOUR independent layers protect NE-AC11 (one call site; agents can't drive GUI lifecycle; any future bus path still hits the Rust `allow_agent_sysex_install` gate; macOS requires interactive approval). Strong in-code comment present; a CI/test grep guard is an optional future hardening |
| 16, 17 | spec, security, quality | n/a | **PASS panel 2026-10-30** — all three PASS, no Critical/Important. NE-AC14/AC15 met at the code level; live `[Mac]` checks HELD to Task 18. The build-owner's singleton→`CoreHealthState.extensionController` weak handle was reviewed clean ("the right idiom… no cleaner approach worth the churn"); operator-only invariant confirmed (grep: no bus/MCP/Session/palette path to `start()`/`uninstall()`/the handle). | — |
| 16, 17 | quality | Minor | `waitUntilConnected` duplicated its connected-check inside and after the loop | **FIXED (verified swift test green)** — single sample site (`for sample in 0...pollCount`, sleep only when `sample < pollCount`); same sample/sleep counts, no behaviour change |
| 16, 17 | quality | Minor | `NEVPNStatus.invalid` folds into `.tunnelDisconnected`, so an externally-removed config can still read "Capture is on" | **documented + Task-18 carry-forward** — kept advisory to avoid a *sticky* degrade on a transient mid-replacement `.invalid`; code comment + a Task 18 live item to map `.invalid`→degrade if a real Mac never emits it transiently |
| 16, 17 | quality | Minor | Two test gaps: `.capturing.applying(.tunnelConnected)` idempotency; `TunnelReconcilePolicy.pollCount` `max(1,…)` floor | **FIXED (verified)** — added `anAlreadyCapturingStateIsUnchangedByAnotherTunnelConnectedEvent` + `theConnectedCheckAlwaysSamplesAtLeastOnce` (318 tests green) |
| 16, 17 | security | Minor | Deactivation continuation has no timeout; a dropped terminal callback would hang `uninstall()` with the activity assertion held | **accepted + Task-18 carry-forward** — `OSSystemExtensionRequest` delivers exactly one terminal callback and deactivation may itself wait on a human prompt (a blind timeout could fail a legitimate wait); code comment records the decision; revisit with a guarded timeout at Task 18 if deactivation proves never human-gated |
| 16, 17 | security | Minor (info) | `removeSavedConfiguration` left `tunnelManager` non-nil on a mid-loop throw | **FIXED** — `tunnelManager = nil` up front (torn down regardless) |
| 16, 17 | spec | Minor | `isTransient` leash-#58 classifier was pure logic but untested in app-target code | **FIXED (verified)** — hoisted the retry policy to `TunnelFailure` in AitmproxyKit with a table test; `ExtensionController` maps `NEVPNError.code`→`TunnelFailure` via a compiler-checked exhaustive switch |
| 16, 17 | spec | Minor (info) | `build.sh` stamps `CFBundleVersion` at minute resolution; two builds in one minute would not trigger a replace | **accepted (out of range)** — `build.sh` is not a Task 16/17 file; a rebuild+reactivate cycle exceeds a minute. Note for the orchestrator: switch to `%Y%m%d%H%M%S` |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
