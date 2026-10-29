# aitmproxy Milestone 5 — raw L4 / packet MITM implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** shipped (2026-10-28) — whole-branch Stage-6 panel passed with all findings
resolved; branch synced to current `main` (M4 + M6) with a green gate; landing on `main`
as Stage A of the L4 operator-surfaces milestone.
**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md`
(approved 2026-10-28; M5-AC1–AC21)
**Branch / worktree:** `feat/aitmproxy-m5` in a fresh worktree cut from `main`.
**Note (M5 Task 14 deferred):** the Rhai `l4.*` host functions are **not** built here;
they are owned by the protocol-extensibility seam (approved spec
`docs/superpowers/specs/2026-10-28-aitmproxy-protocol-extensible-languages-design.md`).
M5 lands the `l4.*` **command** surface only.

**Goal:** Ship `aitm-proto-l4` — raw-packet **capture**, scapy-style **craft +
guarded inject**, **send-and-receive** (`sr`/`sr1`), and Linux **in-path packet
interception** (the `flow.intercept`/`mutate` analog) — for **authorized** L4
fuzzing / memory-safety testing, reachable over the command bus, MCP, and the M3
Rhai tier, behind a deny-by-default `L4Guard`, with **no `aitm-core` edits** and
every M5 acceptance criterion green.

**Architecture:** One new crate, `aitm-proto-l4`, on the existing `Plugin` +
`Command` seams (L4 is command-driven, not acceptor-driven). An in-crate
deny-by-default `L4Guard` extends scope to CIDR + port + interface + direction +
capability (`Capture`/`Inject`/`Intercept`) + rate, composed with the core
`ScopeRateGuard`. Every wire write and every mangling verdict passes **one guarded
choke point** (`send_on_wire` / the verdict path) that requires an `L4Permit` only
`L4Guard::check` mints. Crafting is pure/sans-IO (`etherparse` + `pnet_packet`);
capture/inject use `pcap`; in-path uses `nfq` (Linux NFQUEUE) on a **dedicated
owning thread**, macOS returns `L4Unavailable`. Flows live in an l4-owned
`L4FlowStore` (no core edit). The binary wires the module opt-in and fail-closed;
`aitm-plugin-rhai` gains guard-routed `l4.*` host functions.

**Tech stack:** Rust; `pcap`, `pnet_packet`, `etherparse`, `nfq` (Linux, `cfg`),
`uuid`, `thiserror`, `serde`/`serde_yaml`, `tokio`; `aitm-core` + `aitm-plugin`
(consumed, never edited). Versions/MSRV re-checked with `cargo info` at build time
(research-note provenance). `rustables` is **excluded** (GPL-3.0).

## Global constraints

Every task implicitly includes these (from the spec):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  before any review. Default `cargo test` is hermetic: no raw sockets, no NFQUEUE,
  no privilege, no network. Privilege-/OS-gated tests are `#[ignore]`d **and** need
  `AITM_L4_TESTS=1` (capture/inject/send-recv) / `AITM_L4_INPATH=1` (Linux NFQUEUE);
  absent privilege, they assert `L4Unavailable` rather than failing.
- **`forbid(unsafe_code)`** at the crate root; no `unsafe` block (AC20). `nfq`/`pcap`
  `unsafe` stays internal to those deps.
- **No `aitm-core` edits (AC19).** New crate + binary wiring + config only. L4 flows
  live in the l4-owned `L4FlowStore`.
- **TDD:** no production code without a failing test first; the Coder's report quotes
  both runs.
- **Declared signatures are authoritative.** Types/fields/method signatures in the
  spec are copied exactly; bodies and file layout inside a module are the builder's.
- **Deny-by-default + one choke point.** Nothing captures/injects/intercepts without
  a matching scope entry; the single wire-write function and the mangling-verdict
  path both require an `L4Permit`.
- **Fail-closed.** Missing privilege / libpcap / NFQUEUE / an unsupported OS ⇒ a
  typed `L4Unavailable`, never a panic. `enabled` defaults false.
- **In-path fails open** (verdict timeout / overflow default `Forward`) so the
  target's unrelated traffic is never stalled.
- **Git/gh via the Terminal panel** (`run_in_terminal`), never the sandboxed shell.

## Review focus

Input classes the spec implies but a happy path won't exercise; each pinned to a test:

1. **Malformed field survives the builder.** `ipv4.checksum = Some(0x0000)` must
   reach the wire as `0x0000`, not be "fixed". Pinned in Task 2 (`build_preserves_malformed_checksum`).
2. **Out-of-scope auto-forward in-path.** A queued packet outside scope must be
   forwarded untouched and never parked. Pinned in Task 11 (`out_of_scope_auto_forward`).
3. **No verdict in time.** A parked packet past its deadline must get `on_timeout`
   (Forward) and the reader must not hang. Pinned in Task 11 (`verdict_timeout_forwards`).
4. **Script cannot bypass the guard.** A Rhai `l4.inject` to an out-of-scope dst must
   be refused by the same guard. Pinned in Task 14 (`rhai_out_of_scope_refused`).
5. **Core untouched.** `git diff` under `aitm-core/` must be empty. Pinned in Task 13
   (`core_untouched`).

## Overview

One stream, one crate. Phases: **foundation** (1) → **pure + guard + store**
(2, 3, 4, 5) → **wire + active** (6, 7, 8) → **commands** (9, 10) → **in-path**
(11, 12) → **wiring + rhai** (13, 14) → **exit** (15).

**Parallel groups (disjoint files, after dependencies land):**

| Group | Tasks | Why disjoint |
|---|---|---|
| **P1** | 2 ∥ 4 (after 1) | `craft.rs` vs `guard.rs` |
| **P2** | 9 ∥ 5→6 chain (after 2,3,4) | `commands/*` vs `guard.rs`/`wire.rs` |
| **P3** | 11 ∥ 7→8 (after 4,6,3) | `intercept/*` vs `capture.rs`/`sendrecv.rs` |

Longest sequential chain: 1 → 4 → 5 → 6 → 7 → 8 → 10 → 13 → 15 (9 tasks).

## Tasks

### Task 1: Crate scaffold + config + scope/guard value types

- **Satisfies:** foundation; part of AC1, AC17.
- **Depends on:** none. **Independent:** starts the stream.
- **Files:** `aitm-proto-l4/Cargo.toml` (create), `aitm-proto-l4/src/lib.rs`,
  `src/config.rs`, `src/types.rs` (create); workspace `Cargo.toml` (modify: add member).
- **Change:** `#![forbid(unsafe_code)]`. Types from the spec: `L4Config`, `L4Backend`,
  `InterceptConfig`, `Verdict`; `L4ScopeEntry`, `L4ScopeId`, `L4Capability`,
  `L4Action`, `L4Direction`, `L4Proto`, `L4Target`, `IpCidr`, `PortRange`, `RateCap`.
  serde derives; `Default for L4Config` with `enabled=false`. Deps: `serde`,
  `uuid`, `thiserror`; `aitm-core`, `aitm-plugin`.
- **Test:** `config_deserializes_yaml` — parse a YAML `L4Config` with one scope entry
  + an `intercept` block; assert `enabled == false` by default (omitted key),
  `scope[0].capability == Inject`, `scope[0].inject_rate.pps == 5`,
  `intercept.on_timeout == Verdict::Forward`.
- **Done when:** test passes and the full gate passes.

### Task 2: Pure craft model

- **Satisfies:** AC7.
- **Depends on:** Task 1. **Independent of** Task 4 (P1).
- **Files:** `aitm-proto-l4/src/craft.rs` (create).
- **Change:** `PacketSpec`, `Layer`, `Ipv4Spec`/`Ipv6Spec`/`TcpSpec`/`UdpSpec`/
  `IcmpSpec`/`EtherSpec` (Option-per-field), `PacketSummary`, `CraftError`;
  `PacketSpec::build`, `PacketSpec::summarize`. Deps: `etherparse`, `pnet_packet`.
- **Test:** `build_preserves_malformed_checksum` — build
  `[Ipv4{dst:127.0.0.1, checksum:Some(0x0000)}, Udp{dst_port:9}, Raw(b"probe")]`;
  assert the IPv4 checksum field in the output bytes == `0x0000`. Then the same with
  `checksum:None` → assert the field == the correctly computed checksum (literal for
  this fixed input). Proves verbatim override **and** auto-complete, no privilege.
- **Done when:** passes + gate.

### Task 3: L4 flow store + packet model

- **Satisfies:** foundation for AC8, AC9, AC10, AC12.
- **Depends on:** Task 1, Task 2 (`PacketSummary`).
- **Files:** `aitm-proto-l4/src/flow.rs` (create).
- **Change:** `L4Flow`, `L4FlowKind`, `L4FlowId`, `L4Packet`, `L4Bind`, `L4Meta`,
  `L4FlowStore` trait + an in-memory impl.
- **Test:** `store_insert_append_get` — insert a `Craft` flow, `append_packet` an
  `L4Packet{injected:true}`, `get` → `packets.len() == 1`, `packets.last().injected
  == true`, `kind == L4FlowKind::Craft`.
- **Done when:** passes + gate.

### Task 4: `L4Guard` — scope match + capability + denylist

- **Satisfies:** AC1, AC2, AC3, AC4.
- **Depends on:** Task 1. **Independent of** Task 2 (P1).
- **Files:** `aitm-proto-l4/src/guard.rs` (create).
- **Change:** `L4Guard` (scope list), `L4GuardError` (`OutOfL4Scope`,
  `CapabilityNotGranted`, `DangerousDestinationBlocked`, `L4Unavailable` for now);
  `add_scope`/`remove_scope`/`list_scope`; `check` doing scope + capability + the
  dangerous-destination denylist only (rate/caps in Task 5). CIDR + port matching.
- **Test:** `empty_scope_refuses` — `check(Inject, loopback)` == `Err(OutOfL4Scope)`.
  `in_scope_ok` — add a loopback `Inject` entry → `check(Inject, loopback)` is `Ok`.
  `capability_split` — with a `Capture`-only entry: `check(Inject,..)` ==
  `CapabilityNotGranted(Inject)` and `check(Intercept,..)` ==
  `CapabilityNotGranted(Intercept)`. `denylist` — `check(Inject, 169.254.169.254)`
  with no matching entry == `DangerousDestinationBlocked`.
- **Done when:** passes + gate.

### Task 5: `L4Guard` — rate/size/count caps + `L4Permit`

- **Satisfies:** AC5, AC6; part of AC21.
- **Depends on:** Task 4.
- **Files:** `aitm-proto-l4/src/guard.rs` (modify).
- **Change:** per-entry `inject_rate` + `global_inject_pps` token buckets;
  `L4Permit` (RAII); errors `InjectionRateExceeded`/`PacketTooLarge`/`CountExceeded`;
  `check` returns a permit carrying the bounded budget.
- **Test:** `rate_cap_trips` — `inject_rate.pps = 2`; the 3rd `check` within the
  window == `InjectionRateExceeded { .. }`. `oversize` — a packet over
  `max_packet_bytes` == `PacketTooLarge { max }`. `count` — a batch over
  `max_packets_per_call` == `CountExceeded { max }`.
- **Done when:** passes + gate.

### Task 6: Wire choke point + pcap backend + fail-closed

- **Satisfies:** AC17, AC20, part of AC21.
- **Depends on:** Task 5.
- **Files:** `aitm-proto-l4/src/wire.rs`, `src/backend/mod.rs`, `src/backend/pcap.rs`
  (create).
- **Change:** `trait CaptureInjectBackend` (open-capture, inject); `PcapBackend`;
  `fn send_on_wire(permit: L4Permit, iface: &str, bytes: &[u8]) -> Result<(), L4Error>`
  — the **only** wire-write, requiring an `L4Permit` by type. `L4Unavailable` when
  libpcap/privilege is absent. Dep: `pcap`.
- **Test:** `send_on_wire_requires_permit` — a structural/doc test asserting the
  signature consumes an `L4Permit` (no permit ⇒ won't compile; captured as a
  compile-fail doc or a trait-level note). `backend_unavailable_without_privilege`
  — a `MockBackend` simulating no privilege → inject returns `L4Unavailable`, no
  panic. (AC20 is enforced by `#![forbid(unsafe_code)]` compiling.)
- **Done when:** passes + gate.

### Task 7: Capture task (scoped BPF filter, background)

- **Satisfies:** AC8.
- **Depends on:** Task 4, Task 6, Task 3. **Independent of** Task 11 (P3).
- **Files:** `aitm-proto-l4/src/capture.rs` (create).
- **Change:** a scope-derived BPF-filter builder; a background capture task that
  appends in-scope `L4Packet`s to an `L4Flow`; a capture-task registry.
- **Test (`AITM_L4_TESTS`, loopback):** `capture_excludes_out_of_scope` — scope CIDR
  *A*; generate one in-scope and one out-of-scope packet on loopback; the flow holds
  only the in-scope one. Skips asserting `L4Unavailable` without privilege.
- **Done when:** passes (or skips cleanly) + gate.

### Task 8: `send_recv` (sr/sr1)

- **Satisfies:** AC10, AC11.
- **Depends on:** Task 6, Task 7, Task 3.
- **Files:** `aitm-proto-l4/src/sendrecv.rs` (create).
- **Change:** `SendRecvSpec`, `ReplyMatch`, `SendRecvOutcome`; `send_recv(..)` —
  `guard.check(Inject)` + `(Capture)`, send via `send_on_wire`, await the correlated
  reply within `timeout` (default `ReplyMatch::FiveTuple` reversed), record stimulus
  + reply linked in an `L4Flow{kind:SendRecv}`.
- **Test (`AITM_L4_TESTS`, loopback):** `send_recv_response` — a local UDP echo on
  loopback → `SendRecvOutcome::Response` carrying the echoed payload.
  `send_recv_no_response` — no responder → `NoResponse { waited }` with
  `waited >= timeout`, returns (does not hang).
- **Done when:** passes/skips + gate.

### Task 9: Active commands (no wire): `l4.interfaces`, `l4.scope.*`, `l4.flow.*`, `l4.craft`

- **Satisfies:** part of AC18.
- **Depends on:** Task 2, Task 3, Task 4. **Independent of** the 5→6 chain (P2).
- **Files:** `aitm-proto-l4/src/module.rs`, `src/commands/{mod,scope,flow,craft}.rs`
  (create).
- **Change:** `L4Module` (`Plugin`); `load` registers `Command` impls with
  `ParamSchema` for `l4.interfaces`, `l4.scope.add/remove/list`, `l4.flow.list/get`,
  `l4.craft`.
- **Test:** `commands_registered` — `load` into a `Registry`; assert `l4.craft` and
  `l4.scope.add` are present; invoke `l4.craft` with a spec → result carries the
  built byte length (literal) + a summary. `scope_add_then_list` roundtrips an entry.
- **Done when:** passes + gate.

### Task 10: Active wire commands: `l4.capture.*`, `l4.inject`, `l4.send_recv`

- **Satisfies:** AC1, AC2, AC9, AC10, AC11 (via commands).
- **Depends on:** Task 6, Task 7, Task 8, Task 9.
- **Files:** `aitm-proto-l4/src/commands/{capture,inject,sendrecv}.rs` (create);
  `module.rs` (modify: register).
- **Change:** `Command` impls routing to the capture task / `send_on_wire` /
  `send_recv`; each calls `L4Guard::check` and, for defense in depth,
  `CommandHost::guard().check_active(..)`.
- **Test:** `inject_out_of_scope_refused` — command-level `l4.inject` to an
  out-of-scope dst → `OutOfL4Scope`. `loopback_roundtrip` (`AITM_L4_TESTS`) — AC9 via
  commands. `send_recv_cmd` (`AITM_L4_TESTS`) — AC10/AC11 via commands.
- **Done when:** passes/skips + gate.

### Task 11: In-path NFQUEUE backend (Linux; dedicated thread) + lifecycle

- **Satisfies:** AC14, AC15, part of AC16.
- **Depends on:** Task 4, Task 3, Task 6 (the `L4Unavailable` pattern).
- **Files:** `aitm-proto-l4/src/intercept/{mod,nfqueue_linux,unsupported}.rs` (create).
- **Change:** `trait InterceptBackend`; a Linux `nfq` reader on a **dedicated
  `std::thread`** owning the queue, surfacing parked packets via a channel and taking
  verdicts back; parks only in-scope packets (`ParkedPacket`, `L4InterceptState`),
  **auto-forwards out-of-scope untouched**; enforces `verdict_timeout`, `max_parked`,
  and fail-open `on_timeout`/`on_overflow`. A macOS/unsupported impl returns
  `L4Unavailable`. Dep: `nfq` behind `cfg(target_os = "linux")`.
- **Test (`AITM_L4_INPATH`, Linux):** `out_of_scope_auto_forward` (AC14) — an
  out-of-scope queued packet is forwarded, never parked. `verdict_timeout_forwards`
  (AC15) — a parked packet past its deadline gets `on_timeout` (Forward); the reader
  does not hang. `unsupported_or_no_cap` (AC16) — on non-Linux, or Linux without
  `CAP_NET_ADMIN`, start → `L4Unavailable`, no panic.
- **Done when:** passes/skips + gate.

### Task 12: In-path commands: `l4.intercept.*`

- **Satisfies:** AC12, AC13, AC3 (Intercept), part of AC16, part of AC21.
- **Depends on:** Task 11, Task 2, Task 9.
- **Files:** `aitm-proto-l4/src/commands/intercept.rs` (create); `module.rs` (modify).
- **Change:** `Command` impls mirroring `flow.*`: `l4.intercept.start/stop/status`
  (`guard.check(Intercept)`; bind the queue), `l4.intercept.list`,
  `l4.intercept.mutate`/`revert` (edit via `PacketSpec`/bytes, record a backup),
  `l4.intercept.forward` (Forward verdict, mangled if mutated — through the guarded
  path), `l4.intercept.drop` (Drop).
- **Test (`AITM_L4_INPATH`, Linux):** `mutate_forward_delivers_mangled` (AC12) —
  against a loopback `nft` queue, a parked packet mutated + forwarded is delivered
  mangled. `drop_not_delivered` (AC13). `intercept_requires_capability` (AC3) — a
  `Capture`-only scope → `l4.intercept.start` == `CapabilityNotGranted(Intercept)`.
- **Done when:** passes/skips + gate.

### Task 13: Binary wiring + config plumbing + fail-closed

- **Satisfies:** AC17, AC19.
- **Depends on:** Task 10, Task 12.
- **Files:** `aitm/src/*` (wiring, modify), `aitm/src/config*.rs` (modify: add the
  `l4` section with `deny_unknown_fields`).
- **Change:** construct `L4Module` only when `enabled` and privilege is present;
  `register_plugin`; on missing privilege log "L4 unavailable" and start normally;
  in-path needs `intercept: Some(..)` + `CAP_NET_ADMIN` or it reports `L4Unavailable`.
- **Test:** `disabled_not_registered` (AC17) — `enabled=false` → no `l4.*` in the
  registry. `enabled_no_priv_starts` (AC17) — `enabled=true` + mocked no-privilege →
  `L4Unavailable`, the proxy still builds. `core_untouched` (AC19) —
  `git diff --name-only <base> -- aitm-core` is empty (asserted in a test/CI check).
- **Done when:** passes + gate.

### Task 14: Rhai `l4.*` host functions

- **Satisfies:** AC18.
- **Depends on:** Task 5, Task 6, Task 10, Task 12.
- **Files:** `aitm-plugin-rhai/src/l4.rs` (create); the Rhai host setup (modify).
- **Change:** register `l4.craft`/`inject`/`send_recv`/`capture_start`/`flow_get`/
  `intercept_*` host functions, each routed through the same `L4Guard`; present only
  when the module is enabled; versioned surface.
- **Test:** `rhai_out_of_scope_refused` (AC18) — a script calling `l4.inject` to an
  out-of-scope dst is refused by the guard (error surfaced to the script);
  `l4.*` absent when the module is disabled.
- **Done when:** passes + gate.

### Task 15: Exit / integration tests + hard-gate checks

- **Satisfies:** AC9, AC10, AC11, AC12, AC13, AC18, AC19, AC20, AC21 end-to-end; the
  M5 exit gate.
- **Depends on:** all.
- **Files:** `aitm-proto-l4/tests/*.rs` (create); a gate/CI check.
- **Change:** integration tests for the scoped-loopback active round-trip +
  `send_recv`; Linux-gated in-path mutate-forward + drop; the `core_untouched` git
  check (AC19); a `no_unsafe` presence check for `#![forbid(unsafe_code)]` (AC20);
  a `one_choke_point` structural check (AC21) — `send_on_wire` and the mangling
  verdict both require an `L4Permit`.
- **Test:** the above, each quoting real command output; the full gate green with
  the gated suites run where privilege exists.
- **Done when:** all M5-AC1–AC21 green through the gate; ready for stage-6 panel.

## Review log

Whole-branch Stage-6 panel (security, quality, spec) run 2026-10-28 on the assembled
branch; findings and dispositions below. All fixes verified by a focused security
re-review before landing.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| whole-branch | security | Important | In-path `mutate`→`forward` reinjected mutated bytes without re-checking scope/denylist/size | Fixed in `97912a1` — `forward` now re-runs `L4Guard::check(Intercept)` + size on the mutated bytes; re-review CONFIRMED CLOSED |
| whole-branch | security/quality | Important | Injection rate cap counted `check` calls, not packets (`pps × max_packets_per_call`) | Fixed in `97912a1` — one rate token spent per packet in `authorize_packet`; re-review CONFIRMED CLOSED |
| whole-branch | security | Important | `l4.scope.add` had no agent gate (bus caller could self-authorize any dst) | Fixed in `0e14521` — gated by new `l4.allow_agent_widen` (default false); runtime entries can't lift the denylist. Approved by Matt 2026-10-28; forward-compatible with Stage B. Re-review CONFIRMED CLOSED |
| whole-branch | security | Minor | `send_recv` reply capture skipped the per-packet capture-scope check | Fixed in `97912a1` (`guard.check(Capture, reply_target)` before recording) |
| whole-branch | security/quality | Minor | `flow.rs` panicked on lock poison while the rest of the crate recovers | Fixed in `97912a1` (`PoisonError::into_inner`) |
| whole-branch | quality | Minor | `proto_of`/`spec_proto` duplicated verbatim | Fixed in `97912a1` (hoisted to `PacketSpec::transport_proto`) |
| whole-branch | quality | Minor | AC21 hard-gate tests are source-text greps, weaker than they read | Fixed in `97912a1` (doc note: supplementary to the type-level guarantee) |
| whole-branch | quality/spec/security | Important | Branch cut from a stale `main`; `wire.rs`/`config_file.rs`/`main.rs`/`Cargo.toml` conflict with M4+M6 | Resolved by the orchestrator: merged current `main` (`b64c488`) into the branch (`7d5b65b`), conflicts resolved keeping both sides' features, gate green |
| whole-branch | spec | Minor | plan `Status` draft; `platform-design.md` roadmap edit undeclared; `serde_json` not in tech-stack line | Accepted (doc bookkeeping): Status flipped; roadmap edit accepted; `serde_json` already in the lockfile |

Task 14 (Rhai `l4.*`) absence is **not** a finding — deferred by approved decision to the
protocol-extensibility seam.

## Shipped

- **Merged to `main`:** `aitm-proto-l4` (scoped capture, scapy-style craft, guard-gated
  inject, send-and-receive, Linux NFQUEUE in-path interception) behind a deny-by-default
  `L4Guard`/`L4Permit` with one `send_on_wire` choke point and an l4-owned `L4FlowStore`;
  the `l4.*` command surface registered on the live loopback-TCP bus (opt-in via
  `l4.enabled`, fail-closed `L4Unavailable` when unprivileged); `l4.scope.add` gated by
  `l4.allow_agent_widen` (deny-by-default). All M5-AC1–AC21 green; no `aitm-core` edits
  (AC19); `#![forbid(unsafe_code)]` (AC20).
- **Cut / deferred:** Rhai `l4.*` host functions and the native `l4:` PoC step → the
  protocol-extensibility seam. The `l4.scope.add` operator/agent split (operator path +
  confirm) → L4 operator-surfaces Stage B (needs M4's `Frontend::Operator`).
- **Follow-ups:** L4 operator-surfaces Stages B–G (bus policy classification, the three
  UI surfaces, live two-way testing) are now unblocked (M4 + M6 + M5 on main).
