# L4 parity fixes design

**Status:** Approved for the pre-approved small fixes (Matt, 2026-10-31, via the orchestrator); design questions i–iii proceed on their recommended defaults pending Matt's word, unit (a)'s operator scope-add (question ii) merges last
**Research inputs:** `docs/research/12-l4-parity-audit.md` (defects D0-D15), `docs/research/05-synthesis.md`.
**Stays consistent with:** `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md` (Part 2 policy, §3 UI contract, L4OPS-AC*), `docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md` (L4Guard / L4Permit authorisation model), `docs/design/languages/flow-kinds.json` (`l4` descriptor), `docs/design/languages/filter.grammar.json` (`~l4 ~tcp ~udp ~icmp`).
**Sibling spec (not designed here):** D0, the product obtaining capture privilege itself, from `docs/research/13-l4-capture-privilege-without-cli.md`.

## Intent

The L4 audit drove every frontend against a real `l4.enabled` core and found the L4 surface broken or absent in ways that have nothing to do with privilege: two UIs send the wrong id to Forward/Drop, the web sends a param the core rejects, the macOS app never reads a live L4 flow, the macOS craft sample is rejected, the operator cannot add L4 scope without opening the agent's Widen gate, a read verb errors instead of answering, `l4.flow.get` carries no bytes, times or addresses, and the chips, help and docs omit L4. This spec fixes D1-D15 as five independent PRs, so that the day D0 lands, every frontend already lights up correctly from one honest availability state the core reports. Until then each surface says plainly why capture is off, and nothing on screen can only fail.

## Goals

- Every frontend reads capture and intercept availability from the core (`l4.capture.status`, `l4.intercept.status`) and renders capture- and intercept-dependent controls disabled with the core's `reason`.
- Forward / Drop / Mutate / Revert send the parked-packet id from `l4.intercept.list` in every UI; where `l4.intercept.*` is unavailable (always on macOS) the bar is documented-limited.
- `l4.flow.get` packets carry `bytes`, `timestamp`, `proto`, `src`, `dst`, `src_port`, `dst_port`, in a bounded window.
- An operator adds L4 scope through operator confirm-over-the-wire, in TUI, web and macOS; the agent Widen gate governs agents only, unchanged.
- The macOS app shows live L4 rows from the bus, with no dependence on sample data.
- L4 / TCP / UDP chips and the `~l4 ~tcp ~udp ~icmp` atoms are visible in every UI; the agent-facing docs list `l4.*`.

## Non-goals

- D0: obtaining capture privilege (NE, SMAppService, ChmodBPF, setcap, polkit). This spec only leaves the seam (Design §1).
- D8: folding L4 flows into the core `FlowStore` / `flow.subscribe` (open question i). No new `l4.flow.table` verb.
- D9: a real L4 path to findings and PoC (`poc.build` / `findings.record` resolving an L4 id). Here the UIs simply stop sending HTTP verbs with L4 ids. **(Architect's call)**: a real L4 PoC needs its own design, and it follows from question i.
- macOS capture start/stop controls. Capture on a Mac only exists after D0, so the D0 spec designs that affordance. **(Architect's call)**
- macOS Mutate. On macOS intercept is always documented-limited; a Mac pointed at a Linux core gets Forward/Drop only in this spec. **(Architect's call)**
- New bus verbs. Every change is to an existing verb's arguments or reply, so the three new-verb contracts (EXPECTED_TOOLS, CORE_TOOLS, bus-fixture) are not touched.
- Anything under `apps/mac/Extension` (owned by the NE session).

## Anti-goals

- A fix that widens what an agent can do. Agent policy, the per-capability gates, the Widen gate and the scope guard stay exactly as they are for `Frontend::Mcp`.
- A control that can only fail: an intercept bar on macOS with clickable Forward/Drop, a Start capture button that can only return `L4 unavailable`.
- Evidence from sample data. A green fixture scene, mock-bus run, snapshot or seeded store proves nothing here (Constraints, "Evidence rule").
- Unbounded replies: `l4.flow.get` with bytes for 65,536 packets in a single reply.

## Constraints

- **Evidence rule (Matt, 2026-10-31).** No fixture, snapshot, self-test or seeded-store run counts as evidence or as a regression gate for any frontend. This covers macOS `Fixtures+L4.swift` rows, the snapshot and fixture self-test harness (`tools/snap.sh`, `selftest.sh` with `APP_FIXTURES`), the web mock bus (`?bus=mock`, `bus/mock.ts`), and TUI `--fixture` / `fixture.rs`. Proof is one of: the real frontend against a real core with real traffic; the honest **blocked** verdict when the product cannot capture yet; unit tests of pure logic (Rust / Swift Kit / TS functions whose input is built in the test); or source tripwires (grep or structural checks that stop a wrong argument shape or a fixture-only path from coming back). Where the audit matrix says "fixture-only", read it as **missing live**.
- **Fixture removal lands first.** Another session is deleting the fixture and sample-data modes from all three frontends. Every unit here rebases on that PR's merge SHA (call it `R`; `R` is on top of 5eac2a5) and lists none of the files it removes.
- **`l4.intercept.*` stays Linux NFQUEUE only.** On a macOS core every UI renders the intercept bar documented-limited.
- **Zero `aitm-core` edits.** Every core change lives in `aitm-proto-l4` (plus its tests and `crates/aitm/tests`). `CommandHost::caller_is_trusted_control()` and `Command::confirm_prompt` already exist, so nothing in the design needs a core edit.
- **Deny-by-default and agent gating untouched** (L4OPS-AC5 tests stay green, unmodified in their agent assertions).
- **One writer per file.** The five units have disjoint file lists (Design §7).
- **Operator hygiene.** No token is printed or logged by any new code.

## Design

### 1. The availability seam (for D0)

`l4.capture.status` and `l4.intercept.status` stop being privilege-gated and always answer:

| Field | Type | Meaning |
|---|---|---|
| `available` | bool | the capability class works on this core now |
| `code` | string | `available`, `needs_privilege` (the platform supports it, the process lacks it), `unsupported_platform`, `not_configured` (intercept with no `l4.intercept` config) |
| `reason` | string or null | the exact text the gated verbs return in `L4 unavailable: <reason>`; null when available |
| `captures` / `sessions` | array | the existing payload (capture flow ids / intercept session objects); `[]` when unavailable |

The status verbs are registered outside the `L4Gated` wrapper and read the same cached `L4Privilege` the wrapper uses, so their `reason` and the start/stop error can never disagree. `l4.capture.start/stop` and the other `l4.intercept.*` verbs keep their typed `L4Unavailable` error. **(Architect's call)**: `l4.intercept.status` gets the same shape as `capture.status`, because the UIs need intercept availability too, and one shape means one parser. `code` is added so the D0 spec can attach "Allow packet capture" to `needs_privilege` without matching on strings.

Frontend rule: every UI re-reads both status verbs on its slow poll and never caches availability for the session. When D0 makes availability change at runtime, the controls light up without a restart. The D0 spec owns making `L4Privilege` refreshable.

Compatibility: a UI must accept the old shapes too (a bare array means `available: true`; an error whose text contains `L4 unavailable` means `available: false` with that text as the reason), because the macOS app can be pointed at an older external core.

### 2. `l4.flow.get` content (D7)

Every packet object keeps `dir`, `length`, `injected`, `layers` and gains:

- `bytes`: the on-wire bytes as standard padded base64. This is `Value::Bytes`, the encoding `l4.craft` already uses.
- `timestamp`: integer milliseconds since the Unix epoch, UTC. This matches HTTP `flow.get`'s `started_at`. **(Architect's call)**: ms rather than RFC 3339.
- `proto`: `TCP`, `UDP`, `ICMP`, `ICMPv6`, or null.
- `src`, `dst`: IP address strings, or null.
- `src_port`, `dst_port`: integers for TCP/UDP, otherwise null.

These come from one new pure function in `craft.rs` next to `PacketSpec::summarize`, over the existing `parse_frame`. Field names match `PacketSpec` (`src_port` / `dst_port`), so a packet read back can seed the craft editor.

The flow object gains `started_at` (flow creation, ms), plus flow-level `proto`, `src`, `dst`, `src_port`, `dst_port` taken from the first decodable packet, so a list row can show its target without reading packets.

Bounded window **(Architect's call)**: there are new optional params `offset` (default 0) and `limit` (default 256, clamped to 4096). The reply gains `offset`; `packet_count` stays the total. `limit: 0` returns the flow fields with `packets: []`. List polling uses `limit: 0` and only the inspector fetches a window. A UI detects `limit` from the `l4.flow.get` inputSchema in `tools/list`, and omits the param against an older core.

### 3. Operator L4 scope add (D5, D11)

- `ScopeAdd` gains a `confirm_prompt` that summarises the entry (cidr, ports, interface, direction, capability, inject rate). It is `Some` even with empty args, so `tools/list` reports `confirmable: true`.
- `ScopeAdd::invoke` branches on `host.caller_is_trusted_control()`. A trusted caller (operator, CLI) goes to a new `pub(crate)` guard method that skips the Widen gate. Anyone else goes to the unchanged `add_runtime_scope`, which stays Widen-gated. Both paths force `source = Runtime`, so an operator runtime add never lifts the dangerous-destination denylist; only config scope does.
- The MCP server already offers confirm-over-the-wire only to `Frontend::Operator`, and the CLI asks its `Confirmer` unless `--yes`. So an operator add is always confirmed, and an agent is never offered a handshake.
- Rhai and the PoC `l4:` step keep calling `add_runtime_scope` directly and stay Widen-gated for every caller: scripts cannot be confirmed. An agent call parked under `Ask` and then approved still runs as `Frontend::Mcp`, so it is still Widen-gated.
- `l4.scope.list` entries gain `source: "config" | "runtime"` so UIs can label them. **(Architect's call)**

### 4. Parked-packet verbs and the intercept bar (D2, D6)

- The intercept bar works on the selected intercept flow's parked packets, taken from `l4.intercept.list` filtered by `flow == <flow id>`. It defaults to the oldest one. Forward / Drop / Mutate / Revert send `{id: <parked id>}`, and Mutate also sends `spec` (the craft editor's current spec).
- Forward / Drop keep the existing operator confirm dialog.
- When `l4.intercept.status` says `available: false` the bar is a single documented-limited line showing the core's `reason`, with no live buttons. The UI then does not poll `l4.intercept.list`.

### 5. PoC `l4:` default interface (D14)

`DEFAULT_INTERFACE` becomes per-OS: `lo0` on macOS and the other BSDs, `lo` on Linux, chosen at compile time.

### 6. Rig (for every live check)

`aitm web` built from the unit's branch, rebased on `R` (UI units also include unit (a); see §8). It runs with:

- `l4.enabled: true`;
- config `l4.scope`: lo0 `127.0.0.1/32` ports `9000-9999`, one entry each for capture, inject and intercept;
- an operator token read from the 0600 config;
- an agent token;
- `python3 -m http.server 9099` as the real HTTP/TCP target, proxied so real HTTP rows exist;
- a UDP echo on 9053.

On this Mac `/dev/bpf*` is root-only, so this is the **unprivileged rig**. Each AC below is tagged:

- **[now]**: provable on the unprivileged rig.
- **[D0]**: needs the privilege spec first. Until then the verdict is "blocked: needs D0", never a fixture.
- **[Linux]**: needs a privileged Linux NFQUEUE core. The verdict is "blocked: no Linux rig" when there is none.

The prepared privileged walk (capture lo0, real HTTP/TCP/UDP traffic, `l4.flow.get`, craft + inject to the echo, `send_recv`, out-of-scope inject refused) becomes `tests/e2e/l4/test_l4_parity_priv.py`. It runs fully where `l4.capture.status.available` is true and otherwise reports blocked with the core's reason.

### 7. Fix units (one PR each against `main` at or after `R`)

**(a) core**, branch `fix/l4-parity-core`. Covers D7, D11, D5 core, D14, the D13 e2e docstrings, and the §1 seam.
- `crates/aitm-proto-l4/src/commands/flow.rs`, `src/craft.rs`, `src/commands/capture.rs`, `src/commands/intercept.rs`, `src/commands/mod.rs`, `src/commands/scope.rs`, `src/guard.rs`, `src/module.rs`, `src/language.rs`
- `crates/aitm-proto-l4/tests/surface.rs`, `tests/operator_surfaces.rs`, `tests/inpath.rs`, `tests/active_roundtrip.rs`, `tests/language.rs` (shape updates only)
- `crates/aitm/tests/l4_operator_surfaces.rs`, `crates/aitm/tests/l4_acceptance_mcp.rs`
- `tests/e2e/l4/test_l4_capture_flow.py`, `tests/e2e/l4/test_l4_scope_self_exclusion.py`: the `capture.status` shape changes, and the docstrings stop naming the Network Extension for pcap privilege (`l4.capture.start` is pcap/BPF only)
- new `tests/e2e/l4/test_l4_parity_core.py` (unprivileged live checks), new `tests/e2e/l4/test_l4_parity_priv.py` (privileged walk, blocked-aware)

**(b) TUI**, branch `fix/l4-parity-tui`. Covers D2, D5 UI, D6, D9 UI, D10, D10c, and capture controls.
- `crates/aitm-tui/src/app.rs`, `src/bus.rs`, `src/l4.rs`, `src/model.rs`, `src/filter.rs`, `src/keys.rs`, `src/action.rs`, `src/ui/l4.rs`, `src/ui/overlays.rs`, `src/ui/flows.rs`, `src/ui/sidebar.rs`, `src/ui/bars.rs`, `src/ui/complete.rs`
- new `crates/aitm-tui/tests/l4_parity.rs` (pure-logic App tests: input built in the test, output is the emitted `BusRequest`s)
- `crates/aitm/tests/l4_cua_tui.rs`
- new `tests/e2e/l4/test_l4_tui_live.py` (real `aitm-tui` in a pty against the rig bus, the audit's method)
- Capture commands: `:l4 capture <iface> [inbound|outbound]`, `:l4 stop [<id>]`, with completion. Key letters are the builder's choice, as long as help lists them.
- Mutate in the craft pane ("apply to parked packet" plus revert). **(Architect's call)**: the TUI is the Linux operator's main surface.

**(c) web**, branch `fix/l4-parity-web`. Covers D3, D5 UI, D6, D9 UI, D10, D10b, D12.
- `apps/web/src/panels/l4/store.ts`, `model.ts`, `CaptureControls.tsx`, `L4CaptureBar.tsx`, `L4InterceptBar.tsx`, `L4InspectorPanel.tsx`, `L4Inspector.tsx`, `PacketList.tsx`, `LayerTree.tsx`, `model.test.ts`, new `args.test.ts`
- `apps/web/src/panels/agent/L4Toggles.tsx`
- `apps/web/src/shell/chips.ts`, `shell/shortcuts.ts`, `shell/RoleBanner.tsx`
- `apps/web/src/state/app.ts` (Chip type, `matchesChip`)
- `apps/web/src/flows/FlowList.tsx`, `flows/ContextMenu.tsx`
- `apps/web/src/bus/noise.ts`
- `apps/web/scripts/cua-l4.mjs`, `scripts/CUA-L4-RUN-RECORD.md` (the live browser run, already real-core)
- `filter`: the web stops sending it, and the filter input becomes a direction select (`inbound` / `outbound`). **(Architect's call)**: the core derives the BPF filter from L4 scope by design, so a free-form operator BPF string is a second, unguarded definition of what gets captured.
- Chips: `TCP UDP L4` as their own group after `WebSocket`, the order macOS shipped in #196. ⌘1-⌘9 follow bar order.
- Polling **(Architect's call)**:
  - while `capture.status` says unavailable and `l4.flow.list` is empty, the L4 lane polls every 10 s, not 1.5 s;
  - `l4.intercept.status/list` are read only when intercept is available;
  - list rows use `limit: 0`;
  - one failed read is logged once per distinct message, not once per tick.
- D12: on an agent-role connection, every Sensitive L4 control renders disabled with an "operator only" reason and sends nothing.

**(d) macOS**, branch `fix/l4-parity-mac`. Covers D1, D2, D4, D5 UI, D6, D9 UI, D15. It does not touch `apps/mac/Extension`, any fixture, snapshot or fixture self-test file being removed in `R`, or `ContentCategory.swift`: the L4/TCP/UDP chips already shipped in #196 and only need a live check.
- `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`: poll `l4.flow.list` and `l4.flow.get` (with `limit: 0`) when `tools/list` offers them, and emit them into the flow list.
- `apps/mac/Sources/Aitmproxy/Session.swift`: union the live L4 rows; `l4Availability` comes from the live status replies; `APP_L4_EMBEDDED` is gone from any live path.
- `apps/mac/Sources/Aitmproxy/Session+Verbs.swift`: L4 rows offer no HTTP verbs.
- `apps/mac/Sources/Aitmproxy/Inspector/L4Inspector.swift`:
  - `sampleSpec` uses `src_port` / `dst_port` and a `raw` byte list. This is the live craft editor's starting text, not fixture data, which is why the fix stays;
  - Forward/Drop send the parked id;
  - the intercept bar is documented-limited when unavailable;
  - the packet time, src/dst and hex come from §2.
- `apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift`, `Panels/ScopeSheet.swift`: an L4 scope section with list and add (operator confirm). **(Architect's call)**: parity with §3.3 of the operator-surfaces spec.
- `apps/mac/Sources/AitmproxyKit/L4.swift`: parse the §2 fields; `L4Availability.resolve` reads the status replies, old shapes included.
- `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- new `apps/mac/tools/check-l4-live.sh` (tripwire), new `apps/mac/tools/cua-l4-live.sh` (CUA against a `snap-dev` dev bundle with `APP_LIVE=1` and the isolated defaults suite, connected to the rig as its external core)
- `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`, only if it survives `R`; it is a real-bus check.
- D15: reproduce the pinned hosts first on a fresh isolated suite and an empty `APP_STORE`. If the cause is in a file not listed here, the Coder stops and reports.

**(e) docs**, branch `docs/l4-parity`. Covers D13.
- `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md` (regenerate from an `l4.enabled` core, or add the `l4.*` family by hand)
- `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md` (an L4 section: availability object, operator-confirmed scope add, the Linux-only intercept, parked ids), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` (one paragraph separating HTTP `flow.intercept` from `l4.intercept.*`)

### 8. Order

(b), (d) and (e) are independent of each other. (c) reads `capture.status` today and would break on the new shape, so (c) merges **before** (a), or on the same day. (c) tolerates both shapes. Every UI unit's live checks that depend on (a) (scope-add confirm, status objects, flow.get fields) run on a local integration of that unit with (a). (e) documents (a)'s behaviour and merges after (a).

## Acceptance criteria

Done for every unit means three things:
- the Rust gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes;
- the web gate `npm run typecheck && npm test && npm run build` (apps/web) and the mac gate (`swift build` via `tools/snap-dev.sh`, `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, `tools/grid-lint.sh`) pass where touched;
- every AC's named check has been run, with output quoted.

Snapshot, fixture self-test and mock-bus steps are **not** accepted as proof for this work. For visuals, the evidence is light and dark screenshots of the live dev bundle against the rig, which the Coder has looked at. A suite CI runs must not be left red, but a green suite there is never cited.

**Core (a)**
1. **L4PAR-AC1 flow.get packet fields.** A Rust unit test calls `FlowGet::invoke` over a store holding an IPv4/UDP packet crafted as 127.0.0.1:40000 to 127.0.0.1:9053 with payload `hello-l4` at a fixed `SystemTime`. The packet reads `proto "UDP"`, `src "127.0.0.1"`, `dst "127.0.0.1"`, `src_port 40000`, `dst_port 9053`, `bytes` equal to the base64 of the crafted bytes, and `timestamp` equal to the fixed ms. An undecodable packet `[0xde, 0xad]` reads `proto/src/dst/src_port/dst_port null`, `bytes "3q0="`. [now: unit]. Real captured packets show the same fields via `test_l4_parity_priv.py` [D0].
2. **L4PAR-AC2 bounded window.** Unit: a 300-packet flow returns 256 packets by default with `packet_count 300`. `offset 290, limit 50` returns 10 packets with `offset 290`. `limit 0` returns `packets []`. `limit 100000` returns at most 4096. Live: the rig's `tools/list` inputSchema for `l4.flow.get` lists optional `offset` and `limit` [now].
3. **L4PAR-AC3 honest capture.status.** On the rig, `l4.capture.status` as operator and as agent returns, with no error, `{available: false, code: "needs_privilege", reason: "no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)", captures: []}`. `l4.capture.start {interface: "lo0"}` still errors `L4 unavailable: ` followed by that same reason (`test_l4_parity_core.py`) [now]. Unit: a module built with `L4Privilege::available()` returns `available: true, code: "available", reason: null` [now: unit].
4. **L4PAR-AC4 honest intercept.status.** On the rig, `l4.intercept.status` returns `{available: false, code: "unsupported_platform", reason: "in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)", sessions: []}`, and `l4.intercept.start` still errors [now]. Unit: no intercept config on an otherwise privileged module gives `code: "not_configured"`.
5. **L4PAR-AC5 operator scope add, confirmed.** On the rig with `widen: false`, operator `l4.scope.add {cidr: "127.0.0.1/32", ports: "9100-9199", interface: "lo0", direction: "inbound", capability: "capture"}` returns `needs_confirmation` with a `confirm_token` and a prompt containing `127.0.0.1/32`, `9100-9199`, `lo0`, `inbound`, `capture`. Re-issuing with `_confirm` returns an id. `l4.scope.list` then shows it with `source: "runtime"` and the three config entries with `source: "config"`. `l4.agent.status` reads `widen: false` before and after. `l4.scope.remove` removes the entry. `tools/list` shows `l4.scope.add` `confirmable: true` [now].
6. **L4PAR-AC6 agents unchanged.** On the rig, agent token, policy `all`, widen off: `l4.scope.add` is refused with the existing "runtime L4 scope widening is disabled" text, no confirmation is offered, and the list is unchanged. Policy `auto` is refused by policy [now]. Unit: a Rhai `l4.scope.add` with a trusted-control caller is still refused while widen is off. The L4OPS-AC5 tests in `crates/aitm/tests/l4_operator_surfaces.rs` pass with their agent assertions unmodified.
7. **L4PAR-AC7 runtime provenance.** Unit: an operator-path add of `169.254.169.254/32` with `dangerous_dst_override: true` stores `Runtime`, and `check(Inject)` to that address still returns `DangerousDestinationBlocked` [now: unit].
8. **L4PAR-AC8 PoC default interface.** Unit: an `l4:` step with no `interface` resolves to `lo0` under `cfg(target_os = "macos")` and to `lo` under Linux [now: unit]. Live send on lo0 [D0].
9. **L4PAR-AC9 no core edits.** `git diff --stat <base>...HEAD -- crates/aitm-core` is empty. A unit test asserts the two status verbs are not `L4Gated`: they return `Ok` on a module whose privilege is unavailable [now].

**TUI (b)**
10. **L4PAR-AC10 parked id.** Unit (`l4_parity.rs`): with intercept flow `F` and an `l4.intercept.list` reply `[{id: "P1", flow: "F", ...}]`, Forward emits exactly `Call {name: "l4.intercept.forward", args: {"id": "P1"}}`, Drop the same with `l4.intercept.drop`, and neither ever sends `"F"`. Live forward on a parked packet [Linux].
11. **L4PAR-AC11 documented-limited bar.** Live TUI on the rig: the L4 intercept bar shows the core's `reason` text, and the Forward/Drop/Mutate keys put no `l4.intercept.*` call on the bus (checked in the rig core's debug log or audit ring for the TUI connection) [now].
12. **L4PAR-AC12 Mutate/Revert.** Unit: "apply to parked packet" emits `l4.intercept.mutate {id: "P1", spec: <editor spec>}`, and revert emits `l4.intercept.revert {id: "P1"}`. Live [Linux].
13. **L4PAR-AC13 L4 scope view and add.** Live TUI on the rig: the scope panel shows an "L4 scope" section with the three config entries (lo0, 127.0.0.1/32, 9000-9999, capture/inject/intercept). `:scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture` opens a confirm with the core's prompt, `y` adds it, and it appears in the section within one slow poll. HTTP `:scope add <host>` is unchanged [now, with (a)].
14. **L4PAR-AC14 chips and help.** Live TUI on the rig with real HTTP rows: an `L4` quick filter is visible; help and the filter hint list `~l4 ~tcp ~udp ~icmp`; `~l4` hides every HTTP row [now]. L4 rows shown under it [D0].
15. **L4PAR-AC15 capture controls.** Live TUI on the rig: the L4 view shows "capture unavailable" plus the AC3 reason; `:l4 capture lo0` refuses locally with that reason and puts no `l4.capture.start` on the bus [now]. Start, list, stop [D0].
16. **L4PAR-AC16 no HTTP verbs on L4 rows.** Unit: on an L4 row the mark, comment, replay and PoC actions emit zero `BusRequest`s and toast that they are not available for L4 flows [now: unit]. With a real L4 row [D0].
17. **L4PAR-AC17 stale banner gone.** Live TUI as operator on the rig: the Agent overlay's first line is `policy: <policy> · ...`. Tripwire: the string `core follow-up F1` does not appear in `crates/aitm-tui/src` [now].

**Web (c)**
18. **L4PAR-AC18 capture args.** Unit (`args.test.ts`): the capture-start builder returns exactly the keys `interface` and `direction`. Live: a check fetches the rig's `tools/list` and asserts every key every L4 arg builder emits (capture start/stop, intercept verbs, scope add) is in that verb's inputSchema. Tripwire: no `filter` key in any `l4.capture.start` call in `apps/web/src` [now].
19. **L4PAR-AC19 Start/Stop capture.** Live browser (`cua-l4.mjs`) as operator on the rig: Start capture is disabled with the AC3 reason as its visible text or tooltip [now]. Unit: Stop emits `l4.capture.stop {id}` for each running id. Live start and stop [D0].
20. **L4PAR-AC20 intercept bar.** Live browser on the rig: the bar is one documented-limited line with the AC4 reason and no enabled Forward/Mutate/Drop [now]. Unit: Mutate emits `l4.intercept.mutate {id: <parked id>, spec}`, Revert emits `l4.intercept.revert {id}`, Forward/Drop send the parked id. Live [Linux].
21. **L4PAR-AC21 chips.** Live browser on the rig with real proxied HTTP rows: the chip bar reads `All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2 | ...`, selecting `L4` leaves zero HTTP rows, and ⌘5 selects `TCP` [now]. L4 rows under it [D0].
22. **L4PAR-AC22 L4 scope add.** Live browser on the rig: the AC5 entry is added through the L4 page's add form, with the confirm dialog showing the core's prompt, and it appears in the scope list with `runtime` provenance [now, with (a)].
23. **L4PAR-AC23 poll less.** Live browser as operator, 60 s idle on the rig: the activity log gains no L4 polling error entries, and the rig core's debug log shows at most 12 `l4.*` calls per minute from that connection [now].
24. **L4PAR-AC24 agent role.** Live browser on the agent URL: Start capture, Inject, scope add, Forward/Drop/Mutate and the gate toggles are disabled with an "operator only" reason, and none of them reaches the bus [now].

**macOS (d)**
25. **L4PAR-AC25 live L4 polling.** A live dev bundle (`APP_LIVE=1`, isolated suite, rig as external core): the rig core's debug log shows `l4.flow.list` from the mac connection on every poll. Tripwire `check-l4-live.sh`: it fails if `BusService.swift` lacks `l4.flow.list` and `l4.flow.get`, or if `APP_L4_EMBEDDED` appears in a live path [now]. Live L4 rows [D0].
26. **L4PAR-AC26 availability from the core.** The dev bundle against the rig shows the AC3 reason in the L4 surface, and Inject is disabled with it [now]. Kit unit: `resolve` maps the AC3 object to `.degraded(reason)`, `{available: true}` and a bare array to `.available`, and an error containing `L4 unavailable` to `.degraded`.
27. **L4PAR-AC27 sampleSpec accepted.** The dev bundle's Craft tab, Build on the untouched starting text: `l4.craft` on the rig returns `length 36` and the preview shows 36 bytes of hex [now]. Kit unit: the sample's JSON has `udp.src_port 40000`, `udp.dst_port 9`, and `raw` as a 8-element byte array.
28. **L4PAR-AC28 intercept on macOS.** The dev bundle against the rig: the bar is documented-limited with the AC4 reason, with no clickable Forward/Drop [now]. Kit unit: the verdict args builder returns `{id: <parked id>}`. Live [Linux].
29. **L4PAR-AC29 chips live, no HTTP verbs.** The dev bundle against the rig with real HTTP rows: `TCP UDP L4` chips are present and `L4` leaves zero HTTP rows [now]. Kit unit: the context-action model for an L4 row has no mark, comment, replay or PoC [now: unit].
30. **L4PAR-AC30 L4 scope on the Scope page.** The dev bundle against the rig: the Scope page lists the three config L4 entries and adds the AC5 entry through the operator confirm [now, with (a)].
31. **L4PAR-AC31 no phantom pins.** The dev bundle with a fresh isolated suite and an empty `APP_STORE` against the rig shows no pinned hosts the operator did not pin [now].

**Docs (e)**
32. **L4PAR-AC32 docs list l4.\*.** `mcp-tool-catalog.txt` and `tool-reference.md` each contain all 25 `l4.*` names from the rig's `tools/list`, checked by a script diffing the two. The overview skill names `l4.capture.status`'s `available/code/reason`, the operator-confirmed `l4.scope.add`, and the Linux-only `l4.intercept.*`. `tests/e2e/l4/` no longer attributes pcap privilege to the Network Extension (done in (a)) [now].

**Cross-cutting**
33. **L4PAR-AC33 nothing that can only fail.** On the rig, in each of TUI, web and macOS, no enabled control's action returns `L4 unavailable` (ACs 11, 15, 19, 20, 26 and 28 together) [now]. Panel security review confirms no diff widens an agent path.

## Left to the builder

- Key letters, layout and wording of documented-limited lines and disabled-reason tooltips, within the foundation tokens and the icon/editorial rules.
- How the TUI/web/mac pick the "selected parked packet" beyond the oldest-first default.
- The tripwire mechanism per surface (crate test reading source, shell grep, vitest over source), as long as it fails on the named regression.
- Whether the docs are regenerated or hand-edited.
- The mac L4 poll interval (no faster than the HTTP poll), and how the web's back-off resets when a capture starts.

## Open questions

1. **(i) Store.** Keep `InMemoryL4FlowStore` with UI polling, or fold L4 flows into the core `FlowStore` so `flow.list`/`flow.subscribe` carry them? **Recommended: keep it for this spec.** With `limit: 0` polling and the web back-off the cost is bounded. Folding in is an `aitm-core` change (D8) and is the natural home for D9 (L4 PoC/findings), so it belongs in its own spec after D0.
2. **(ii) Operator scope add.** Operator confirm-over-the-wire (§3), or reuse the agent Widen gate? **Recommended: operator confirm.** It matches §2.3/§3.3 of the operator-surfaces spec and leaves the Widen gate meaning exactly "may the agent widen". Reusing the gate forces the operator to open the agent's door in order to add scope themselves.
3. **(iii) macOS intercept bar.** Hide it, or show it disabled? **Recommended: show one documented-limited line with the core's reason and no buttons** (L4OPS-AC12 "renders documented-limited"). Hiding it makes a Mac look like intercept was never built, and the line tells the operator that a Linux core lights it up.

## Summary

Five disjoint PRs fix D1-D15 on top of the fixture-removal PR. The core adds bytes, time and addresses to a bounded `l4.flow.get`, makes both status verbs answer honestly with `available/code/reason` (the D0 seam), and lets the operator add L4 scope through confirm-over-the-wire without touching agent gates. The TUI, web and macOS units then send parked ids, render intercept documented-limited on macOS, add L4 scope views and chips, stop sending HTTP verbs with L4 ids, and read availability live. Docs list `l4.*`. Every AC is a live check on the unprivileged rig, a pure-logic unit test, or a tripwire, or it is marked blocked on D0 or a Linux rig. No fixture counts.

**Architect's calls:** `code` field and `intercept.status` getting the same honest shape; ms `timestamp`; `offset`/`limit` window (256 default, 4096 cap); `source` on `l4.scope.list`; the web drops `filter` for a direction select; web chip order matches macOS; web back-off (10 s while unavailable and empty, ≤12 `l4.*` calls/min idle); TUI gets Mutate; macOS gets an L4 scope section but no capture controls (deferred to D0) and no Mutate; D9 handled only as "no HTTP verbs on L4 rows"; merge order (c) before (a).
