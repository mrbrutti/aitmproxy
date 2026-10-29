# L4 operator surfaces implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement this plan task-by-task.
> One fresh Coder per task in the plan's worktree; panel review per task and once on the
> whole branch. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md` (approved 2026-10-28; L4OPS-AC1–AC19)
**Branch / worktree:** Stage A completes and merges `feat/aitmproxy-m5`. Stages B–G run on a fresh
`feat/aitmproxy-l4-operator-surfaces` worktree **cut from `main` after M5 lands** (so the new
seams build on a tree that already has L4 + M4). Independent tasks fan out to child branches cut
from the plan branch, merged back on panel-pass; two writers never share a file.

**Goal:** Make L4 operator-drivable and provable end to end — land M5 on `main`, register `l4.*`
on the live loopback-TCP bus under the M4 identity/policy model, build the L4 surfaces in all
three UIs, and prove the whole stack against a real in-scope L4 target two ways (MCP + CUA) —
**Phase 1** only; the macOS Network/System Extension is **Phase 2** and gets its own research note,
spec and plan.

**Architecture:** An integration milestone. The L4 engine (M5 `aitm-proto-l4`), the L4 UI look
(ui-scripting-highlight-l4 Part 3, absorbed here), and the `l4.*` scripting vocabulary
(protocol-extensible seam, coordinated-not-duplicated) are each already designed; this plan builds
the four seams between them. L4 registers as a `Plugin` into `aitm/src/wire.rs`, so its `l4.*`
commands reach the loopback-TCP `McpServer` registry. Every `l4.*` command gains an M4
`sensitivity()`; the agent path is gated by `AgentPolicy` **and** per-capability `l4.allow_agent_*`
flags; operator `Sensitive` verbs use confirm-over-the-wire. The UIs reach the wire only through the
guard-gated `l4.*` commands. The capture/ingress boundary is shaped **protocol-general** so Phase 2's
macOS extension drops in without a rewrite.

**Tech stack:** Rust (`aitm-proto-l4`, `aitm`, `aitm-mcp`, `aitm-testtarget`); the three UIs — web
(SolidJS + CodeMirror 6, `apps/web`), TUI (ratatui, `crates/aitm-tui` + `aitm-bus-client`), macOS
(SwiftUI/AppKit, `apps/mac`). `aitm-core` consumed, never edited.

## Global constraints

Every task implicitly includes these (from the spec):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (Rust)
  plus each UI's own build/test, green before any review. Privilege-/OS-gated L4 tests are
  `#[ignore]`d and gated by `AITM_L4_TESTS` / `AITM_L4_INPATH`; absent privilege they assert
  `L4Unavailable`, never fail.
- **No `aitm-core` edits (M5-AC19).** L4 flows stay in the l4-owned `L4FlowStore`; the UI reads L4
  detail via the `FlowKind` `list_cmd`/`detail_cmd` indirection (`l4.flow.list`/`l4.flow.get`),
  never `flow.detail`. The flow list is a union of `flow.list` + `l4.flow.list`.
- **`forbid(unsafe_code)`** in `aitm-proto-l4`; `unsafe` stays inside `pcap`/`nfq`.
- **Deny-by-default + one choke point.** `send_on_wire` and the mangling-verdict path require an
  `L4Permit` by type (M5-AC21). The bus and UI add layers *above* the guard, never a path around it.
- **Fail-closed privilege.** `l4.enabled` defaults false; missing privilege/libpcap/NFQUEUE/
  unsupported OS → typed `L4Unavailable`, never a panic.
- **M4 identity/policy (hard prerequisite on `main`).** `Frontend::Operator` vs `Mcp`;
  `AgentPolicy{All,Auto,Ask,ReadOnly,Paused}` × `Command::sensitivity(){Read,Write,Sensitive}`;
  two gate dimensions (policy AND per-capability flag). Confirm-over-the-wire two-phase for operator
  `Sensitive` verbs. Gated agent requests/refusals land in the F2 activity log.
- **UI foundation.** Palette/type/components/motion binding; L4 badge hue slate/indigo
  (`color.l4.*`); feature-detect from `tools/list`; honest degradation; colour on data not chrome;
  a shared conformance fixture proves the three surfaces identical.
- **Protocol-general capture seam.** The capture/ingress boundary does not assume a single protocol
  or backend (Phase-2 obligation, exercised in Phase 1 by the Linux/CLI L4 backend).
- **git/gh and the macOS build run through the Terminal panel only.**

## Review focus

Input classes the spec implies but a happy path won't exercise; each pinned to a task:

1. **Unprivileged core, enabled L4.** `l4.enabled=true` with no `CAP_NET_RAW` must advertise `l4.*`
   yet fail each wire verb with a typed `L4Unavailable{reason}` naming the missing capability — not
   a panic, not silent absence. Pinned in Task 3 (`enabled_no_priv_wire_unavailable`).
2. **Agent self-grant.** An agent (`Frontend::Mcp`) call to `l4.agent.set`, to change `AgentPolicy`,
   or to `l4.scope.add` must be refused regardless of flags. Pinned in Task 9 (`agent_cannot_self_grant`).
3. **UI reaches the wire only via the guard.** No surface and no bus adapter may reach `send_on_wire`
   without an `L4Permit`; an out-of-scope UI inject is refused by the guard before any confirm dialog.
   Pinned in Task 10 (`one_choke_point_survives_bus`) and each surface task (`out_of_scope_inject_disabled`).
4. **Forged / stale confirm token.** A `_confirm` token that is reused, belongs to another pending
   call, or is absent must be refused. Pinned in Task 8 (`confirm_token_single_use_bound`).
5. **macOS embedded-core degradation.** The macOS app's embedded user-level core must render the L4
   surface and return `L4Unavailable` (naming the Phase-2 extension) for wire verbs, while the same
   UI pointed at a privileged core drives L4 fully. Pinned in Task 14 (`macos_embedded_core_degrades`).

## Overview

**Phase 1** (this plan's build): Stage **A** lands M5; Stage **B** adds the bus identity/policy seam;
Stage **C** the protocol-general capture boundary; Stage **D** the live L4 target; Stage **E** the
three UI surfaces (ui-ext Part 3, absorbed); Stage **F** the two-way acceptance; Stage **G** the
security gate and Phase-1 exit. **Phase 2** (macOS Network/System Extension) is a handoff section —
no tasks here; it is preceded by research note 10 and its own spec + plan.

**Parallel groups (disjoint files, after dependencies land):**

| Group | Tasks | Why disjoint |
|---|---|---|
| **P1** | 1 ∥ 2 | M5 `commands/{capture,inject,sendrecv}` vs `commands/intercept` (per M5 plan) |
| **P2** | 11 ∥ (6→7) ∥ 10 | `aitm-testtarget` vs policy wiring vs the ingress boundary |
| **P3** | 12 ∥ 13 ∥ 14 | `apps/web` vs `crates/aitm-tui` vs `apps/mac` (three disjoint surfaces) |

Longest sequential chain: 1/2 → 3 → 4 → 5(land) → 6 → 7 → 8 → 12/13/14 → 15 → 17 → 18.

---

## Phase 1

### Stage A — Land M5 on `main`

### Task 1: M5 active wire commands (`l4.capture.*`, `l4.inject`, `l4.send_recv`)
- **Satisfies:** L4OPS-AC1 (via M5-AC1/2/9/10/11).
- **Depends on:** none (M5 Tasks 6/7/8/9 already green on `feat/aitmproxy-m5`). **∥ Task 2.**
- **Files:** per **M5 plan Task 10** — `aitm-proto-l4/src/commands/{capture,inject,sendrecv}.rs`
  (create), `module.rs` (modify: register). This plan does not restate M5 Task 10; execute it as
  written, composing `L4Guard::check` with `ScopeRateGuard::check_active`.
- **Test:** M5 Task 10's tests (`inject_out_of_scope_refused`; `loopback_roundtrip`,
  `send_recv_cmd` under `AITM_L4_TESTS`).
- **Done when:** M5 Task 10 is complete and its gate passes.

### Task 2: M5 in-path commands (`l4.intercept.*`)
- **Satisfies:** L4OPS-AC1 (via M5-AC12/13, AC3-Intercept).
- **Depends on:** none (M5 Task 11 green). **∥ Task 1.**
- **Files:** per **M5 plan Task 12** — `aitm-proto-l4/src/commands/intercept.rs` (create),
  `module.rs` (modify). Execute as written.
- **Test:** M5 Task 12's tests (`mutate_forward_delivers_mangled`, `drop_not_delivered`,
  `intercept_requires_capability` under `AITM_L4_INPATH`).
- **Done when:** M5 Task 12 is complete and its gate passes.

### Task 3: Bus-registration refinement (register-when-enabled, fail-closed wire) — **replaces M5 Task 13**
- **Satisfies:** L4OPS-AC2, AC3; M5-AC17/AC19.
- **Depends on:** Task 1, Task 2.
- **Files:** `aitm/src/wire.rs` (modify: register `L4Module`), `aitm/src/config*.rs` (modify: add the
  `l4:` section with `deny_unknown_fields`), `aitm-proto-l4/src/module.rs` /
  `aitm-proto-l4/src/lib.rs` (modify: a startup privilege probe + per-command `L4Unavailable`).
- **Change (this is the amended Task-13 behaviour):** a cheap startup capability **probe** (not an
  actual raw-socket open against a target) cached into the module. In `wire.rs`: when
  `cfg.l4.enabled`, `register_plugin(Box::new(L4Module::new(&cfg.l4)))` **regardless of privilege**;
  when `!enabled`, register nothing. When enabled but the probe reports no privilege, the wire verbs
  (`l4.capture.*`, `l4.inject`, `l4.send_recv`, `l4.intercept.*`) return
  `L4Unavailable { reason }` naming the missing capability (`CAP_NET_RAW` / `CAP_NET_ADMIN` /
  `/dev/bpf`); the pure/read verbs (`l4.interfaces`, `l4.scope.*`, `l4.flow.*`, `l4.craft`) work.
- **Test:** `enabled_registers_commands` — `enabled=true` → `l4.craft` + `l4.inject` present in the
  registry. `disabled_not_registered` — `enabled=false` → no `l4.*`. `enabled_no_priv_wire_unavailable`
  — `enabled=true` + mocked no-privilege → `l4.interfaces` Ok, `l4.inject` → `L4Unavailable` with the
  capability reason, proxy still builds, no panic. `core_untouched` — `git diff` under `aitm-core/`
  empty.
- **Done when:** tests pass + gate. (M5 Task 14 Rhai is **not** done here — deferred to the
  protocol-extensible seam.)

### Task 4: M5 exit gate + hard-gate checks
- **Satisfies:** L4OPS-AC1 (via M5-AC9/10/11/12/13/19/20/21 end-to-end).
- **Depends on:** Task 3.
- **Files:** per **M5 plan Task 15** — `aitm-proto-l4/tests/*.rs`, a gate/CI check. Execute as
  written, plus assert the registration refinement from Task 3 end-to-end.
- **Test:** M5 Task 15's suite (scoped-loopback round-trip + `send_recv`; Linux-gated in-path
  mutate-forward + drop; `core_untouched`; `no_unsafe`; `one_choke_point`), each quoting real output.
- **Done when:** all M5-AC1–AC21 green through the gate; ready for the M5 panel.

### Task 5: Land M5 on `main`
- **Satisfies:** L4OPS-AC1 (merge).
- **Depends on:** Task 4.
- **Files:** none (integration).
- **Change:** run the Stage-6 panel (security/quality/spec) on `feat/aitmproxy-m5`; fix findings via
  fresh Coder fix-tasks; when no open findings remain, merge via
  `superpowers:finishing-a-development-branch`. Fill the M5 plan's **Shipped** section.
- **Test:** the panel reports no open findings; `main` builds green with the gate; `git diff` under
  `aitm-core/` empty on the merge commit.
- **Done when:** M5 is on `main`. **Gate for Stages B–G.** Cut the
  `feat/aitmproxy-l4-operator-surfaces` worktree from `main` here (M4 must also be on `main`).

### Stage B — Bus registration, identity, policy

### Task 6: Sensitivity classification for `l4.*`
- **Satisfies:** L4OPS-AC4.
- **Depends on:** Task 5; **M4 on `main`** (`Command::sensitivity()`).
- **Files:** `aitm-proto-l4/src/commands/*.rs` (modify: implement `sensitivity()` per command).
- **Change:** each `l4.*` command returns its `sensitivity()` per the spec §2.2 table — `Read`:
  `l4.interfaces`, `l4.scope.list`, `l4.flow.list/get`, `l4.capture.status`, `l4.intercept.status/list`,
  `l4.craft`; `Write`: `l4.scope.remove`, `l4.capture.stop`, `l4.intercept.stop/revert`; `Sensitive`:
  `l4.scope.add`, `l4.capture.start`, `l4.inject`, `l4.send_recv`, `l4.intercept.start/mutate/forward/drop`.
- **Test:** `sensitivity_classified` — iterate the registered `l4.*` set; assert each matches the
  table and no command falls through to a non-explicit default; a command with no explicit impl
  would default `Sensitive` (asserted for a probe command).
- **Done when:** test passes + gate.

### Task 7: Per-capability agent gates (`l4.allow_agent_*`, two-dimension enforcement)
- **Satisfies:** L4OPS-AC5.
- **Depends on:** Task 6.
- **Files:** `aitm/src/config*.rs` (modify: add `l4.allow_agent_{inject,capture,intercept,widen}`,
  default false), the agent-path gate where `call_tool` enforces `AgentPolicy` (modify: compose the
  per-capability flag with the policy for `Sensitive` `l4.*`).
- **Change:** for a `Frontend::Mcp` call to a `Sensitive` `l4.*` command, require **both** the policy
  (Auto refuses all Sensitive; All allows iff the flag is on; Ask parks; ReadOnly/Paused refuse) and
  the matching `l4.allow_agent_*` flag. Operator role bypasses the flags (confirm handles it, Task 8).
  Gated requests/refusals append to the F2 activity log.
- **Test:** `auto_refuses_all_sensitive_l4`; `all_requires_flag` — `All` + `inject` flag off →
  refused, flag on → reaches the guard; `operator_not_flag_gated`; `gated_request_logged`.
- **Done when:** tests pass + gate.

### Task 8: Operator confirm-over-the-wire for the hard L4 verbs
- **Satisfies:** L4OPS-AC6.
- **Depends on:** Task 6; M4 confirm handshake on `main`.
- **Files:** the M4 confirm plumbing call-site (modify) + `aitm-proto-l4` command handlers for
  `l4.inject`, `l4.send_recv`, `l4.intercept.forward`, `l4.intercept.drop` (modify: declare they
  require operator confirmation and build the wire summary).
- **Change:** first operator call to these verbs returns `needs_confirmation` + a single-use
  `confirm_token` bound to the pending call + a summary (destination addr/port/iface/direction,
  `PacketSummary`, count, matched scope entry, minted permit budget); re-issue with the reserved
  `_confirm` proceeds. An out-of-scope target is refused by `L4Guard` **before** a token is minted.
- **Test:** `inject_needs_confirmation` — first call → `needs_confirmation` + token + summary; with
  `_confirm` → proceeds. `confirm_token_single_use_bound` — a reused token, another call's token, or
  an absent token → refused. `out_of_scope_refused_before_confirm` — out-of-scope → `OutOfL4Scope`,
  no token minted.
- **Done when:** tests pass + gate.

### Task 9: `l4.agent.set` / `l4.agent.status` (operator-only live toggle)
- **Satisfies:** L4OPS-AC5, AC11 (backing command).
- **Depends on:** Task 7.
- **Files:** `aitm-proto-l4/src/commands/agent.rs` (create), `module.rs` (modify: register).
- **Change:** `l4.agent.status` (`Read`) returns the four gate states; `l4.agent.set {capability,
  allowed}` (operator-only — `Frontend::Mcp` is refused outright, so an agent can neither call nor
  read-then-flip it) mutates the runtime flag, parallel to `agent.set` for policy.
- **Test:** `operator_sets_gate` — operator `l4.agent.set{inject,true}` → `l4.agent.status` shows it
  on, an agent `l4.inject` under `All` now reaches the guard. `agent_cannot_self_grant` — a
  `Frontend::Mcp` `l4.agent.set` (and `agent.set`, and `l4.scope.add`) → refused regardless of flags.
- **Done when:** tests pass + gate.

### Stage C — Protocol-general capture seam

### Task 10: Protocol-general capture/ingress boundary (Phase-2-ready)
- **Satisfies:** L4OPS-AC17; guards L4OPS-AC19 (P2).
- **Depends on:** Task 5.
- **Files:** `aitm/src/wire.rs` or a small `aitm/src/ingress.rs` (create/modify) — a wiring-layer
  boundary; **no `aitm-core` edit.**
- **Change:** define a `CaptureIngress`-style trait/boundary that accepts captured traffic with
  protocol-dispatch context and routes each protocol behind its own guard (HTTP/WS via the existing
  acceptor seam; L4 via `aitm-proto-l4`'s capture path behind `L4Guard`). Phase 1 wires only the
  Linux/CLI L4 backend into it; the boundary must not name a single protocol or backend (so Phase 2's
  macOS extension implements the same trait).
- **Test:** `ingress_dispatches_by_protocol` — feed the boundary an L4 capture → it routes through
  `L4Guard` and lands in the `L4FlowStore`; feed an out-of-scope L4 packet → guard refuses, nothing
  stored. `one_choke_point_survives_bus` — the only wire-write remains `send_on_wire` (permit by type).
- **Done when:** tests pass + gate.

### Stage D — Live L4 target

### Task 11: Extend `aitm-testtarget` with an opt-in loopback L4 service
- **Satisfies:** L4OPS-AC13/AC14 (the real in-scope asset).
- **Depends on:** Task 5. **∥ Stage B/C.**
- **Files:** `aitm-testtarget/src/l4.rs` (create), `aitm-testtarget/src/lib.rs` or `main.rs`
  (modify: opt-in flag), the grader-only manifest (modify: declare the L4 service in-scope).
- **Change:** a bounded, opt-in loopback L4 service — a UDP echo/responder and a minimal TCP service
  — exhibiting L4-observable behaviour for capture/craft/inject/send_recv/in-path, hermetic and
  in-scope by construction. Reuses the M4 target's opt-in + manifest pattern.
- **Test:** `l4_service_echoes` — a loopback UDP datagram to the service → the echoed payload back
  (bounded). `l4_service_opt_in` — off by default; manifest marks it in-scope.
- **Done when:** tests pass + gate.

### Stage E — L4 UI surfaces (ui-ext Part 3, absorbed)

> Each surface builds the **designed** ui-scripting-highlight-l4 Part 3 surface against the now-live
> bus: the union flow list, the L4 inspector (packet list + layer tree + hex + craft editor), capture
> controls with scope-dimming, guarded inject via the confirm dialog, the Linux-gated intercept bar,
> and the per-feature MCP toggle. Each consumes the shared `flow-kinds.json` (ui-ext PR #8). The
> design is not re-decided here; each task realizes it with the surface's native machinery. Depends on
> Stage B + ui-ext PR #8 + the UI foundation PRs on `main`.

### Task 12: web L4 surface (`apps/web`)
- **Satisfies:** L4OPS-AC7/AC8/AC9/AC10/AC11/AC12.
- **Depends on:** Tasks 7, 8, 9; ui-ext PR #8. **∥ Tasks 13, 14.**
- **Files:** `apps/web/src/panels/flows/*`, `apps/web/src/panels/l4/*` (create),
  `apps/web/src/panels/agent/*` (modify: L4 toggles) — per ui-ext Part 3 §3.2.
- **Change:** union list (`flow.list` + `l4.flow.list` via `flow-kinds.json`), L4 badge/sub-label,
  packet list + layer tree + hex + CodeMirror craft editor (YAML now; Rhai when the seam lands),
  capture controls + scope-dimming, inject → confirm dialog (target + `PacketSummary` + scope +
  permit budget) → `l4.inject`, intercept bar (feature-detected), L4 capability toggles in the Agent
  panel reading/setting `l4.agent.*`.
- **Test:** web harness — `every_kind_renders` (http/ws/l4 rows + placeholder); `out_of_scope_inject_disabled`;
  `inject_shows_confirm`; `toggle_reflects_gate`. (CUA in Task 17.)
- **Done when:** tests pass + the web build/test gate.

### Task 13: TUI L4 surface (`crates/aitm-tui`)
- **Satisfies:** L4OPS-AC7/AC8/AC9/AC10/AC11/AC12.
- **Depends on:** Tasks 7, 8, 9; ui-ext PR #8. **∥ Tasks 12, 14.**
- **Files:** `crates/aitm-tui/src/ui/*`, `crates/aitm-tui/src/model.rs`, `.../action.rs` (modify/create)
  — per ui-ext Part 3 §3.2, with the layer tree as an honest indented text tree.
- **Change:** as Task 12 in ratatui idiom; the confirm dialog as a modal overlay; the intercept bar
  feature-detected; honest degradation for the layer tree labelled as such.
- **Test:** TUI component tests — `every_kind_renders`; `out_of_scope_inject_disabled`;
  `inject_shows_confirm`; `layer_tree_degrades_labelled`.
- **Done when:** tests pass + gate.

### Task 14: macOS L4 surface (`apps/mac`)
- **Satisfies:** L4OPS-AC7/AC8/AC9/AC10/AC11/AC12/AC18.
- **Depends on:** Tasks 7, 8, 9; ui-ext PR #8. **∥ Tasks 12, 13.**
- **Files:** `apps/mac/.../L4*.swift` (create), `apps/mac/.../Agent*.swift`,
  `apps/mac/.../Flow*.swift` (modify) — per ui-ext Part 3 §3.2.
- **Change:** as Task 12 in SwiftUI; **plus AC18**: against the app's embedded user-level core the L4
  surface renders and wire verbs surface `L4Unavailable` (naming the Phase-2 extension as the path);
  pointed at a privileged core over the bus it drives L4 fully.
- **Test:** macOS tests — `every_kind_renders`; `out_of_scope_inject_disabled`; `inject_shows_confirm`;
  `macos_embedded_core_degrades` (embedded core → `L4Unavailable` with the extension reason; privileged
  core → full drive). Build via the bama pipeline in the Terminal panel.
- **Done when:** tests pass + the macOS build/test gate.

### Task 15: Cross-surface conformance fixture (parity)
- **Satisfies:** L4OPS-AC16.
- **Depends on:** Tasks 12, 13, 14.
- **Files:** `docs/design/languages/` or the shared fixtures dir (modify/create: an L4 flow-kind +
  confirm-dialog conformance fixture), per-surface fixture consumers (modify).
- **Change:** a shared fixture asserting the L4 badge, packet/craft viewers, confirm dialog and
  toggles render identically (tokens/type/motion) across the three surfaces; keyboard-triggered
  actions do not animate.
- **Test:** `l4_surface_parity` on each surface against the shared fixture.
- **Done when:** passes on all three + gates.

### Stage F — Two-way acceptance (real packets)

### Task 16: Agent-driven (MCP) acceptance against the target
- **Satisfies:** L4OPS-AC13.
- **Depends on:** Stage B, Task 11.
- **Files:** `aitm-proto-l4/tests/acceptance_mcp.rs` or `aitm/tests/*` (create).
- **Change:** a harness-neutral script over the loopback bus runs `l4.scope.add` → `l4.capture.start`
  → `l4.craft` → `l4.inject` → `l4.flow.get` (captured) → `l4.send_recv` (echo) → (Linux)
  `l4.intercept.start`/mutate/forward/drop against the Task-11 target with **real packets**;
  deterministic in CI where privilege exists, asserting `L4Unavailable` cleanly where not. Asserts
  the guard-airtightness refusals (out-of-scope inject; missing-flag agent call; rate-cap trip).
- **Test:** `mcp_acceptance_roundtrip` (`AITM_L4_TESTS`); `mcp_inpath_mutate_forward_drop`
  (`AITM_L4_INPATH`); `mcp_out_of_scope_and_missing_flag_refused` (hermetic).
- **Done when:** passes/skips cleanly + gate.

### Task 17: CUA (human-driven) acceptance per surface
- **Satisfies:** L4OPS-AC14.
- **Depends on:** Stage E, Task 11.
- **Files:** each surface's CUA harness (reuse the M4 / UI-PR harnesses) + a short written run record
  per surface (the real-clicks evidence, in the side-session notes or `docs/`).
- **Change:** a real operator drives, in each of macOS/web/TUI: open L4 view → `l4.scope.add`
  (confirm) → capture → author a `PacketSpec` → **Inject** (confirm dialog) → packet appears in list
  + layer tree + hex → `send_recv` → (Linux) intercept Forward/Mutate/Drop; plus the out-of-scope
  dimmed/disabled case. Against the Task-11 target with real packets.
- **Test:** the CUA run passes on each surface with captured evidence (not a screenshot alone —
  real clicks against a live core + real packets), quoted in the run record.
- **Done when:** all three surfaces pass; records committed.

### Stage G — Security gate + Phase-1 exit

### Task 18: Mandatory Stage-6 security review + Phase-1 exit gate
- **Satisfies:** L4OPS-AC15, AC16, AC17, AC18 end-to-end; the Phase-1 exit.
- **Depends on:** all Phase-1 tasks.
- **Files:** none new (integration + any fix-tasks the panel dispatches).
- **Change:** run the Stage-6 panel on the whole branch with the spec Part-5 charter —
  **mandatory security review with extra scrutiny on inject/craft/send/intercept**: the guard survives
  the bus + three UIs (no path to `send_on_wire`/verdict without an `L4Permit`); scope cannot be
  bypassed from any surface; every `l4.*` has a `sensitivity()` (default `Sensitive`); no agent
  self-grant; confirm tokens unforgeable; fail-closed privilege + no token leak; no new `unsafe`.
  Then merge via `superpowers:finishing-a-development-branch`.
- **Test:** the panel reports no open findings on the inject/craft/send/intercept paths; the full
  Rust gate + the three UI gates green; AC17 (`ingress_dispatches_by_protocol`), AC18
  (`macos_embedded_core_degrades`) and AC16 (`l4_surface_parity`) all green on the integrated branch.
- **Done when:** no open findings; Phase 1 on `main`.

---

## Phase 2 — macOS Network/System Extension (handoff; no tasks here)

**Not built by this plan.** Phase 2 gives the self-contained macOS app a live L4 capture path via an
`NETransparentProxyProvider`-class Network/System Extension (the Proxyman way) — not a privileged
helper, not manual proxy config — feeding the **same protocol-general capture seam** (Task 10) behind
the same guards, so it serves HTTP/WS/L4 alike.

**Before Phase 2 begins:**
1. **Research note `docs/research/10-macos-network-extension.md`** — which provider class supports
   raw-L4 capture/inject + in-path mutate on current macOS; whether mangle (not just allow/deny) is
   reachable; the provider ↔ core transport; activation/approval UX; entitlements, nested signing,
   notarization in the existing packaging pipeline.
2. Its own **Stage-2 spec** and **Stage-3 plan** (`…-l4-macos-extension-*`), through all seven stages.

**Phase-1 obligations that must hold for Phase 2 to drop in** (verified by AC17/AC18): the capture
boundary is protocol-general and backend-agnostic; `L4Guard`/scope/`L4Permit` sit in the core below
the ingress so an extension-fed packet is guarded identically to a `pcap`-fed one; the macOS
connection abstraction surfaces "embedded core has an approved extension" as a feature-detected,
honestly-degraded capability.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
