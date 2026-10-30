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
- **Files:** `apps/mac/Extension/Sources/TransparentProxyProvider.swift` (modify).
- **Change:** in `handleNewFlow`, exclude flows whose **source-app identity**
  (audit-token signing identifier) is `aitm` or the embedded `obscura` (predicate
  left to the builder within "not pid-based"); rely on wildcard rules already
  excluding loopback (the bus, obscura↔core on 127.0.0.1).
- **Test / pass condition (Terminal panel, real Mac):** run a capture session with
  the core dialing upstream and obscura browsing; inspect the flow list and
  confirm **no** flow is attributed to `aitm` or `obscura` and no loopback flow
  appears. Pass: zero self-originated flows captured.
- **Done when:** the condition holds (Terminal panel).

### Task 13: Host-app activation, two-prompt approval, capability transition (+ operator gate e2e)

- **Satisfies:** NE-AC9; NE-AC10 (end-to-end); NE-AC11 (end-to-end).
- **Depends on:** Task 1, Task 7 (the Rust gate), Task 11.
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift` (create),
  `apps/mac/Sources/Aitmproxy/Bus/CoreHealthState.swift` (modify — add the
  capture-capability state beside core health), `apps/mac/Sources/Aitmproxy/App.swift`
  (modify — submit the activation request on launch, operator-triggered only).
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
  `apps/mac/Extension/Info.plist` (modify — bump `CFBundleVersion`).
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
  control).
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
  Pass: all four observed on a real Mac — the milestone's "real packets, not
  screenshots" bar.
- **Done when:** all four conditions hold (Terminal panel).

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

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
