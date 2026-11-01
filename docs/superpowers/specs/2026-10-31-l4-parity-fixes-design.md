# L4 parity fixes design

**Status:** Approved for the pre-approved small fixes (Matt, 2026-10-31, via the orchestrator); forks (i) and (iii) decided on their defaults; fork (ii), the operator scope add, is with Matt and ships as its own PR (`fix/l4-parity-core-scope`, §7(a')); panel fixes of 2026-10-31 folded in.
**Research inputs:** `docs/research/12-l4-parity-audit.md` (defects D0–D15, D11 split into D11a/D11b), `docs/research/05-synthesis.md`.
**Stays consistent with:** `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md` (Part 2 policy, §3 UI contract, L4OPS-AC*), `docs/superpowers/specs/2026-10-27-aitmproxy-m5-l4-packet-mitm-design.md` (L4Guard / L4Permit authorisation model), `docs/design/languages/flow-kinds.json` (`l4` descriptor), `docs/design/languages/filter.grammar.json` (`~l4 ~tcp ~udp ~icmp`).
**Related:** `docs/superpowers/specs/2026-10-31-l4-capture-privilege-design.md` (D0, the product obtaining capture privilege; it layers an optional `privilege` object on this spec's status shape, §1). `docs/superpowers/specs/2026-10-31-capture-status-verb-design.md` is unrelated: its `capture.status` reports NE flows, while `l4.capture.status` here reports raw frames.
**Supersedes:** the M5 spec's command-table rows that put `l4.capture.status` and `l4.intercept.status` behind the capture/intercept privilege gate (they always answer now, §1); L4OPS-AC18's macOS reason naming the Phase-2 extension (the Kit `embeddedReason`; the mac app reads the core's `reason` instead).

## Intent

The L4 audit drove every frontend against a real `l4.enabled` core and found the L4 surface broken or absent in ways that have nothing to do with privilege: two UIs send the wrong id to Forward/Drop, the web sends a param the core rejects, the macOS app never reads a live L4 flow, the macOS craft sample is rejected, the operator cannot add L4 scope without opening the agent's Widen gate (D5, D11b), the status verbs error instead of answering (D11a), `l4.flow.get` carries no bytes, times or addresses, and the chips, help and docs omit L4. This spec fixes D1–D15 as independent PRs, so that the day D0 lands, every frontend already lights up correctly from one honest availability state the core reports. Until then each surface says plainly why capture is off, and nothing on screen can only fail. Adding packet bytes to the bus must not give an agent a way to read the core's own traffic.

## Goals

- Every frontend reads capture and intercept availability from the core (`l4.capture.status`, `l4.intercept.status`) and renders capture- and intercept-dependent controls disabled with the core's `reason`.
- Forward / Drop / Mutate / Revert send the parked-packet id from `l4.intercept.list`, oldest parked packet first, in every UI; where `l4.intercept.*` is unavailable (always on macOS) the bar is documented-limited.
- `l4.flow.get` packets carry `bytes`, `timestamp`, `proto`, `src`, `dst`, `src_port`, `dst_port`, in a window bounded by count and by bytes. Bytes reach trusted callers always, and an agent only per packet: captured packets need its Capture gate, injected packets its Inject gate (§2.2).
- No capture ever records the core's own listeners (proxy, browser, bus, web, MCP HTTP).
- An operator adds L4 scope through operator confirm-over-the-wire, in TUI, web and macOS; the agent Widen gate governs agents only, unchanged.
- The macOS app shows live L4 rows from the bus, with no dependence on sample data.
- L4 / TCP / UDP chips and the `~l4 ~tcp ~udp ~icmp` atoms are visible in every UI; the agent-facing docs list `l4.*`.

## Non-goals

- D0: obtaining capture privilege (NE, SMAppService, ChmodBPF, setcap, polkit). This spec only leaves the seam (Design §1).
- macOS capture start/stop controls, and `EmbeddedCoreLaunch.swift` writing `l4.enabled: true` into the embedded core's config. Both are owned by the privilege spec (its §3.2 and L4PRIV-AC26): capture on a Mac only exists after D0.
- D8: folding L4 flows into the core `FlowStore` / `flow.subscribe` (fork (i), decided). No new `l4.flow.table` verb.
- D9: a real L4 path to findings and PoC (`poc.build` / `findings.record` resolving an L4 id). Here the UIs simply stop sending HTTP verbs with L4 ids. **(Architect's call)**: a real L4 PoC needs its own design, and it follows from fork (i).
- macOS Mutate. On macOS intercept is always documented-limited; a Mac pointed at a Linux core gets Forward/Drop only. **(Architect's call)**
- Follow-ups, not built here: `l4.intercept.start` from any UI; `l4.send_recv` from any UI; the macOS Inject's hard-coded destination (127.0.0.1 port 9).
- New bus verbs. Every change is to an existing verb's arguments or reply, so the three new-verb contracts (EXPECTED_TOOLS, CORE_TOOLS, bus-fixture) are not touched.
- Anything under `apps/mac/Extension` (owned by the NE session).

## Anti-goals

- A fix that widens what an agent can do. Agent policy, the per-capability gates, the Widen gate and the scope guard stay exactly as they are for `Frontend::Mcp`.
- An agent reading bytes it could not capture itself, or the operator token off a loopback capture of the bus.
- A control that can only fail: an intercept bar on macOS with clickable Forward/Drop, a Start capture button that can only return `L4 unavailable`, a scope-add form against a core that cannot confirm it.
- Evidence from sample data. A green fixture scene, mock-bus run, snapshot or seeded store proves nothing here (Constraints, "Evidence rule").
- Unbounded replies: `l4.flow.get` with bytes for 65,536 packets, or 4096 jumbo frames, in a single reply.
- Raw control bytes from a packet reaching a terminal or the DOM.

## Constraints

- **Evidence rule (Matt, 2026-10-31).** No fixture, snapshot, self-test or seeded-store run counts as evidence or as a regression gate for any frontend. This covers macOS `Fixtures+L4.swift` rows, the snapshot and fixture self-test harness (`tools/snap.sh`, `selftest.sh` with `APP_FIXTURES`), the web mock bus (`?bus=mock`, `bus/mock.ts`), and TUI `--fixture` / `fixture.rs`. Proof is one of: the real frontend against a real core with real traffic; the honest **blocked** verdict when the product cannot capture yet; unit tests of pure logic (Rust / Swift Kit / TS functions whose input is built in the test); or source tripwires (grep or structural checks that stop a wrong argument shape or a fixture-only path from coming back). Audit cells marked "missing live (fixture-only at 1854fae)" are missing.
- **Fixture removal lands first.** Another session is deleting the fixture and sample-data modes from all three frontends. Every unit here rebases on that PR's merge SHA (`R`, on top of 5eac2a5) and lists none of the files it removes.
- **`l4.intercept.*` stays Linux NFQUEUE only.** On a macOS core every UI renders the intercept bar documented-limited.
- **Zero `aitm-core` edits.** Core changes live in `aitm-proto-l4`, plus the L4 wiring in `crates/aitm/src/{wire,main,tui}.rs` that hands the module the core's own listener ports (§2.1) and `crates/aitm/src/ingress.rs` (the NE ingress passes the §2.1 choke point), plus their tests. `CommandHost::caller_is_trusted_control()` and `Command::confirm_prompt` already exist.
- **Deny-by-default and agent gating untouched** (L4OPS-AC5 tests stay green, unmodified in their agent assertions).
- **One writer per file.** The units have disjoint file lists (Design §7); a unit that follows another on the same file is cut after the first merges.
- **Operator hygiene.** No token is printed or logged by any new code.

## Design

### 1. The availability seam (D11a, for D0)

Unit (a) owns un-gating `l4.capture.status` and `l4.intercept.status`. They always answer, for operator and agent alike, with this stable contract:

| Field | Type | Meaning |
|---|---|---|
| `available` | bool | the capability class works on this core now |
| `code` | string | one value from the vocabulary table below |
| `reason` | string or null | the exact text the gated verbs return after `L4 unavailable: `; null when available |
| `captures` / `sessions` | array | the existing payload (capture flow ids / intercept session objects); `[]` when unavailable |

**Availability vocabulary** (the same table appears in the privilege spec §2.4):

| `code` | `available` | When |
|---|---|---|
| `available` | true | the class works on this core now |
| `needs_privilege` | false | the platform supports the class and this process lacks the privilege: capture/inject without read+write `/dev/bpf*` (macOS) or `CAP_NET_RAW` (Linux); intercept on Linux without `CAP_NET_ADMIN` |
| `unsupported_platform` | false | no backend for the class on this OS: intercept on macOS and every non-Linux OS; capture/inject outside macOS and Linux |
| `not_configured` | false | supported and privileged, but intercept has no `l4.intercept` config block |

Privilege outranks configuration. Tests assert `code` and `available`; the literal `reason` text is asserted only by the live check of task A9, because the privilege spec rewrites the probe strings when D0 lands. The privilege spec only **adds** an optional `privilege` object beside these keys and maps its `needs_approval` to `code: "needs_privilege"`; it changes no key defined here.

The status verbs are registered outside the `L4Gated` wrapper. They read availability through an `AvailabilitySource` queried at invoke time, never a value captured at build time. Today the source closes over the cached `L4Privilege`, the same one the wrapper uses, so the status `reason` and the start/stop error cannot disagree; D0 swaps in `PrivilegeState` without touching the commands. `l4.capture.start/stop` and the other `l4.intercept.*` verbs keep their typed `L4Unavailable` error. **(Architect's call)**: `l4.intercept.status` gets the same shape as `l4.capture.status`, because the UIs need intercept availability too, and one shape means one parser.

Frontend rules:
- Every UI re-reads both status verbs on its slow poll and never caches availability for the session, so when D0 changes availability at runtime the controls light up without a restart.
- Until the first reply, availability is pending and the UI shows exactly `Reading L4 availability…` (TUI, web and macOS share this literal).
- Compatibility with an older core (the macOS app can be pointed at one): a bare array means `available: true`; a tool error whose text contains `L4 unavailable: ` means `available: false` with `reason` = the text after that marker.

### 2. `l4.flow.get` content (D7)

Every packet object keeps `dir`, `length`, `injected`, `layers` and gains:

- `bytes`: the on-wire bytes as standard padded base64 (`Value::Bytes`, as `l4.craft` already uses). Present only under §2.2.
- `timestamp`: integer milliseconds since the Unix epoch, UTC, matching HTTP `flow.get`'s `started_at`. **(Architect's call)**: ms rather than RFC 3339.
- `proto`: `TCP`, `UDP`, `ICMP`, `ICMPv6`, or null.
- `src`, `dst`: IP address strings, or null.
- `src_port`, `dst_port`: integers for TCP/UDP, otherwise null.

These come from one pure function in `craft.rs` next to `PacketSpec::summarize`, over the existing `parse_frame`. Field names match `PacketSpec` (`src_port` / `dst_port`), so a packet read back can seed the craft editor. The flow object gains `started_at` (flow creation, ms) and flow-level `proto`, `src`, `dst`, `src_port`, `dst_port` from the first decodable packet, so a list row can show its target without reading packets.

**Bounded window (Architect's call):** optional params `offset` (default 0) and `limit` (default 256, clamped to 4096). The reply gains `offset`; `packet_count` stays the total. `limit: 0` returns the flow fields with `packets: []`. List polling uses `limit: 0`; only the inspector fetches a window. A UI detects `limit` from the `l4.flow.get` inputSchema in `tools/list` and omits it against an older core.

**Byte budget.** One reply carries at most 4 MiB (4,194,304 bytes) of raw packet bytes. Packets are added in order while the running total stays within the budget, and at least one packet is returned when any remain in the window. When the budget stops the window early the reply carries `truncated: true` and `next_offset` (the index of the first packet not returned); otherwise `truncated: false` and `next_offset: null`. Sizing: 4 MiB raw is about 5.6 MiB of base64, and the MCP server sends the value twice (`structuredContent` plus the pretty-printed `content` text), so a full reply stays under the bus's 16 MiB message cap. A reply without `bytes` (§2.2) still honours the window.

#### 2.1 Self-exclusion of the core's own listeners

At construction the L4 module is given the core's own listener ports: proxy, embedded-browser proxy, bus loopback TCP, web UI, and MCP streamable HTTP, each when bound (`set_self_ports` at assembly, `add_self_ports` from every bind hook, including the `aitm tui` agent server). One guard choke point, `L4Guard::admit_frame` / `admit_endpoints`, refuses a frame when a self port is its source **or** destination and either the interface is a loopback interface by name (`lo`, `lo<n>`) or an address is loopback (IPv4, IPv6, IPv4-mapped). **Every recorder** passes it before `append_packet`: the capture loop, the `l4.send_recv` reply listener (which also ANDs `self_exclusion_bpf(interface)` into its BPF), the Linux intercept queue (a self frame is forwarded untouched, never parked or listed) and the macOS Network Extension ingress. `scope_filter` ANDs the same `not port …` clause onto the BPF filter for a loopback interface. This holds whatever the scope says, including config scope. Reason: without it, an agent could read the operator token from an operator client's `initialize` frame through any of those paths (panel on the first cut found the capture-only guard insufficient: send_recv replies, parks and NE units reach the same store). Known limit, accepted: only this core's ports are excluded; another core on the same host (for example the mac app's embedded core beside an `aitm web`) and the embedded browser's CDP port are not.

#### 2.2 Bytes only to trusted callers

`bytes` is present for `host.caller_is_trusted_control()` (operator, CLI) always. For an agent the decision is **per packet**, whatever the flow kind: a captured packet (`injected: false`, whether it came from a capture, a `send_recv` reply listener or an intercept park) carries `bytes` only when the agent's Capture gate is open; an authored packet (`injected: true`) only when its Inject gate is open. Amended twice after the panel: a single Capture-gate switch exposed intercept bytes of traffic the agent could not capture, and a per-flow-kind rule let an Inject-only agent read captured send_recv replies (`l4.send_recv` itself returns no payload). Any packet the caller may not see keeps every other field (headers, addresses, ports, timestamps, layers) and has no `bytes` key; the byte budget counts only emitted bytes. The Rhai `l4.flow.get` applies the same predicate from its invocation context, and accepts optional `offset`/`limit` like the bus verb so scripts can page.

#### 2.3 Rendering packet bytes (every UI)

A hex/ASCII view renders bytes outside 0x20–0x7e as `.`. The web never inserts packet-derived text with `innerHTML`; the TUI never writes a raw control byte to the terminal; the macOS app renders through `Text` only.

### 3. Operator L4 scope add (D5, D11b; fork (ii), own PR)

- `ScopeAdd` gains a `confirm_prompt` that summarises the entry: cidr, ports, interface, direction, capability, inject rate. It is `Some` even with empty args, so `tools/list` reports `confirmable: true`. When ports are omitted it says `all ports`; when the inject rate is 0 it says `inject refused (rate 0)`; for a prefix shorter than /16 (IPv4) or /48 (IPv6) it adds `WARNING: /<n> is a wide range`.
- `ScopeAdd::invoke` branches on `host.caller_is_trusted_control()`. A trusted caller (operator, CLI) goes to a new guard method `add_operator_scope(entry, proof: OperatorConfirmed)`, which skips the Widen gate. `OperatorConfirmed` is a zero-sized proof type whose only constructor is `pub(in crate::commands::scope)`, so the compiler, not a source grep, guarantees that nothing outside the scope command can reach the ungated path. Anyone else goes to the unchanged, Widen-gated `add_runtime_scope`. Both paths end in one private `push_runtime(entry)` that forces `source = Runtime`, so an operator runtime add never lifts the dangerous-destination denylist; only config scope does.
- The MCP server offers confirm-over-the-wire only to `Frontend::Operator`, and the CLI asks its `Confirmer` unless `--yes`. So an operator add is always confirmed, and an agent is never offered a handshake.
- Rhai and the PoC `l4:` step keep calling `add_runtime_scope` and stay Widen-gated for every caller: scripts cannot be confirmed. An agent call parked under `Ask` and then approved still runs as `Frontend::Mcp`, so it is still Widen-gated.
- `l4.scope.list` entries gain `source: "config" | "runtime"`. **(Architect's call)**
- Every UI renders its scope-add control only when `tools/list` shows `l4.scope.add` with `confirmable: true`. Against a core without (a') there is no form, not a form that can only fail.

### 4. Parked-packet verbs and the intercept bar (D2, D6)

- `l4.intercept.list` returns parked packets in arrival order, oldest first, each carrying `parked_at` (epoch ms). Arrival is a monotonic sequence assigned when the packet is parked, not the packet id, which is a random uuid.
- The intercept bar works on the selected intercept flow's parked packets from `l4.intercept.list` filtered by `flow == <flow id>`, defaulting to the first listed (the oldest). Forward / Drop / Mutate / Revert send `{id: <parked id>}`; Mutate also sends `spec` (the craft editor's current spec).
- Forward / Drop keep the existing operator confirm dialog.
- When `l4.intercept.status` says `available: false` the bar is one documented-limited line with the core's `reason` and no live buttons, and the UI does not poll `l4.intercept.list`.

### 5. PoC `l4:` default interface (D14)

`DEFAULT_INTERFACE` becomes per-OS: `lo0` on macOS and the other BSDs, `lo` on Linux, chosen at compile time.

### 6. Rig (for every live check)

`aitm web` built from the unit's branch, rebased on `R` (UI units also include unit (a); see §8), with:

- `l4.enabled: true`;
- config `l4.scope`: lo0 `127.0.0.1/32` ports `9000-9999`, one entry each for capture, inject and intercept;
- an operator token read from the 0600 config, and an agent token;
- `python3 -m http.server 9099` as the real HTTP/TCP target, proxied so real HTTP rows exist;
- a UDP echo on 9053.

On this Mac `/dev/bpf*` is root-only, so this is the **unprivileged rig**. Each AC is tagged:

- **[now]**: provable on the unprivileged rig.
- **[D0]**: needs the privilege spec first. Until then the verdict is "blocked: needs D0", never a fixture.
- **[Linux]**: needs a privileged Linux NFQUEUE core. The verdict is "blocked: no Linux rig" when there is none.

The prepared privileged walk (capture lo0, real HTTP/TCP/UDP traffic, `l4.flow.get`, craft + inject to the echo, `send_recv`, out-of-scope inject refused) becomes `tests/e2e/l4/test_l4_parity_priv.py`. It runs fully where `l4.capture.status.available` is true and otherwise reports blocked with the core's reason.

### 7. Fix units (one PR each against `main` at or after `R`)

**(a) core**, branch `fix/l4-parity-core`. Covers D7, D11a, D14, the D13 e2e docstrings, the §1 seam, §2.1–§2.2, the byte budget and §4's arrival order.
- `crates/aitm-proto-l4/src/commands/{flow,capture,intercept,mod,scope,sendrecv}.rs`, `src/{craft,types,capture,guard,module,language,sendrecv}.rs`, `src/intercept/mod.rs`
- `crates/aitm/src/wire.rs`, `crates/aitm/src/main.rs`, `crates/aitm/src/tui.rs` (the self-exclusion ports and bind hooks, §2.1), `crates/aitm/src/ingress.rs` (NE ingress passes the §2.1 choke point)
- `crates/aitm-proto-l4/tests/{surface,inpath,active_roundtrip,language}.rs`, `crates/aitm/tests/{l4_operator_surfaces,l4_acceptance_mcp,l4_pocstep_wiring}.rs`: shape updates and the new AC tests named in the plan. `l4_pocstep_wiring.rs` and `tests/language.rs` make their `IFACE` per-OS for §5, building their Rhai scripts with `format!` so the normative no-`interface` step bodies stay as written.
- `tests/e2e/l4/test_l4_capture_flow.py`, `tests/e2e/l4/test_l4_scope_self_exclusion.py`: the status shape, and docstrings that stop naming the Network Extension for pcap privilege (`l4.capture.start` is pcap/BPF only)
- new `tests/e2e/l4/test_l4_parity_core.py` (unprivileged live checks), new `tests/e2e/l4/test_l4_parity_priv.py` (privileged walk, blocked-aware)

**(a') core scope**, branch `fix/l4-parity-core-scope`, cut from `main` after (a) merges. Covers D5 core and D11b (§3); the `source` field on `l4.scope.list` ships in (a).
- `crates/aitm-proto-l4/src/commands/{scope,mod}.rs`, `src/guard.rs`
- `crates/aitm-proto-l4/tests/{operator_surfaces,language}.rs`, `crates/aitm/tests/l4_operator_surfaces.rs`
- `tests/e2e/l4/test_l4_parity_core.py` (adds the scope-add live checks)

**(b) TUI**, branch `fix/l4-parity-tui`. Covers D2, D5 UI, D6, D9 UI, D10, D10c, and capture controls.
- `crates/aitm-tui/src/{app,bus,l4,model,filter,keys,action}.rs`, `src/ui/{l4,overlays,flows,sidebar,bars,complete}.rs`
- `crates/aitm-bus-client/src/lib.rs` (`ToolDef` gains `confirmable`), and the `ToolDef` / `ToolInfo` struct literals it breaks in `crates/aitm-tui/tests/{common/mod,fix_pass2,tester_components,tester_edge_cases}.rs`
- new `crates/aitm-tui/tests/l4_parity.rs` (pure-logic App tests: input built in the test, output is the emitted `BusRequest`s)
- `crates/aitm/tests/l4_cua_tui.rs`; new `tests/e2e/l4/test_l4_tui_live.py` (real `aitm-tui` in a pty against the rig bus)
- Capture commands: `:l4 capture <iface> [inbound|outbound]`, `:l4 stop [<id>]`, with completion. Key letters are the builder's, as long as help lists them.
- Mutate in the craft pane ("apply to parked packet" plus revert). **(Architect's call)**: the TUI is the Linux operator's main surface.
- The agent overlay parses and labels the core's `auto` and `ask` policies for display only; setting them from the TUI is a separate change.

**(c) web**, branch `fix/l4-parity-web`. Covers D3, D5 UI, D6, D9 UI, D10, D10b, D12.
- `apps/web/src/panels/l4/{store.ts, model.ts, CaptureControls.tsx, L4CaptureBar.tsx, L4InterceptBar.tsx, L4InspectorPanel.tsx, L4Inspector.tsx, PacketList.tsx, LayerTree.tsx, model.test.ts}`, new `args.test.ts`
- `apps/web/src/panels/agent/L4Toggles.tsx`, `apps/web/src/shell/{chips.ts, shortcuts.ts, RoleBanner.tsx}`, `apps/web/src/state/app.ts` (Chip type, `matchesChip`), `apps/web/src/flows/{FlowList.tsx, ContextMenu.tsx}`
- `apps/web/scripts/cua-l4.mjs`, `scripts/CUA-L4-RUN-RECORD.md` (the live browser run, already real-core)
- `filter`: the web stops sending it, and the filter input becomes a direction select (`inbound` / `outbound`). **(Architect's call)**: the core derives the BPF filter from L4 scope by design, so a free-form operator BPF string is a second, unguarded definition of what gets captured.
- Chips: `TCP UDP L4` as their own group after `WebSocket`, the order macOS shipped in #196. ⌘1–⌘9 follow bar order.
- Polling **(Architect's call)**: while `l4.capture.status` says unavailable and `l4.flow.list` is empty, the L4 lane is idle and reads `l4.flow.list`, `l4.capture.status` and `l4.intercept.status` on a 10 s tick, `l4.scope.list` and `l4.agent.status` every 60 s (at most 30 `l4.*` calls per minute); `l4.intercept.list` is read only when intercept is available; list rows use `limit: 0`; `store.ts` logs each distinct read-failure message once, not once per tick.
- D12: on an agent-role connection, every Sensitive L4 control renders disabled with an "operator only" reason and sends nothing.

**(d) macOS**, branch `fix/l4-parity-mac`. Covers D1, D2, D4, D5 UI, D6, D9 UI, D15. It does not touch `apps/mac/Extension`, any file `R` removes, `ContentCategory.swift` (the chips shipped in #196 and only need a live check), the capture controls or `EmbeddedCoreLaunch.swift` (privilege spec).
- `apps/mac/Sources/Aitmproxy/Bus/BusService.swift`: poll `l4.flow.list` and `l4.flow.get` (with `limit: 0`) when `tools/list` offers them, and emit them into the flow list; read the status verbs, `l4.scope.list`, and `l4.intercept.list` when intercept is available.
- `apps/mac/Sources/Aitmproxy/Session.swift`: union the live L4 rows; availability comes from the live status replies; `APP_L4_EMBEDDED` is gone from any live path.
- `apps/mac/Sources/Aitmproxy/Session+Verbs.swift`: L4 rows offer no HTTP verbs.
- `apps/mac/Sources/Aitmproxy/Inspector/L4Inspector.swift`: the craft editor starts from the accepted sample (`src_port` / `dst_port`, a `raw` byte list; the live editor's starting text, not fixture data); Forward/Drop send the parked id; the intercept bar is documented-limited when unavailable; packet time, src/dst and hex come from §2.
- `apps/mac/Sources/Aitmproxy/Panels/ScopePanel.swift`, `Panels/ScopeSheet.swift`: an L4 section with the availability lines, the L4 scope list, and add (operator confirm, shown only per §3's last rule). **(Architect's call)**: parity with §3.3 of the operator-surfaces spec. There is no row-less craft sheet.
- `apps/mac/Sources/AitmproxyKit/L4.swift`, `apps/mac/Sources/AitmBusClient/ToolDescriptor.swift` (`confirmable`), `apps/mac/Tests/AitmproxyKitTests/L4Tests.swift`
- new `apps/mac/tools/check-l4-live.sh` (tripwires), new `apps/mac/tools/cua-l4-live.sh` (CUA against a `snap-dev` dev bundle with `APP_LIVE=1` and an isolated defaults suite, connected to the rig as its external core)
- `apps/mac/Sources/Aitmproxy/SelfTest+Live.swift`, only if it survives `R`; it is a real-bus check.
- D15: reproduce the pinned hosts first on a fresh isolated suite and an empty `APP_STORE`. If the cause is in a file not listed here, the Coder stops and reports.

**(e) docs**, branch `docs/l4-parity`. Covers D13.
- `docs/research/mcp-tool-catalog.txt`, `aitmproxy-plugin/docs/tool-reference.md` (regenerate from an `l4.enabled` core, or add the `l4.*` family by hand)
- `aitmproxy-plugin/skills/aitmproxy-overview/SKILL.md` (an L4 section: availability object, operator-confirmed scope add, the Linux-only intercept, parked ids), `aitmproxy-plugin/skills/aitmproxy-intercept-mutate/SKILL.md` (one paragraph separating HTTP `flow.intercept` from `l4.intercept.*`)

### 8. Order

- (b), (d) and (e) are independent of each other. (c) reads `l4.capture.status` today and would break on the new shape, so (c) merges **before** (a), or on the same day; (c) tolerates both shapes.
- (a') is cut from `main` after (a) merges and merges after Matt answers fork (ii). Because every UI shows its scope-add control only when `tools/list` reports `l4.scope.add` `confirmable: true`, the UI units may merge before (a').
- Every UI unit's live checks that depend on (a) or (a') run on a local integration of that unit with them. (e) documents (a)/(a') behaviour and merges after them.
- The privilege spec's core branch is cut after (a) merges; its TUI, web and mac branches after (b), (c) and (d) merge.

## Acceptance criteria

Done for every unit means three things:
- the Rust gate `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes;
- the web gate `npm run typecheck && npm test && npm run build` (apps/web) and the mac gate (`swift build` via `tools/snap-dev.sh`, `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`, `tools/grid-lint.sh`) pass where touched;
- every AC's named check has been run, with output quoted.

Snapshot, fixture self-test and mock-bus steps are **not** accepted as proof for this work. For visuals, the evidence is light and dark screenshots of the live dev bundle against the rig, which the Coder has looked at. A suite CI runs must not be left red, but a green suite there is never cited.

**Core (a)**
1. **L4PAR-AC1 flow.get packet fields.** A Rust unit test calls `FlowGet::invoke` as the operator over a store holding an IPv4/UDP packet crafted as 127.0.0.1:40000 to 127.0.0.1:9053 with payload `hello-l4` at a fixed `SystemTime`. The packet reads `proto "UDP"`, `src "127.0.0.1"`, `dst "127.0.0.1"`, `src_port 40000`, `dst_port 9053`, `bytes` equal to the base64 of the crafted bytes, and `timestamp` equal to the fixed ms. An undecodable packet `[0xde, 0xad]` reads `proto/src/dst/src_port/dst_port null`, `bytes "3q0="`. [now: unit]. Real captured packets show the same fields via `test_l4_parity_priv.py` [D0].
2. **L4PAR-AC2 bounded window.** Unit: a 300-packet flow returns 256 packets by default with `packet_count 300`. `offset 290, limit 50` returns 10 packets with `offset 290`. `limit 0` returns `packets []`. `limit 100000` returns at most 4096. Live: the rig's `tools/list` inputSchema for `l4.flow.get` lists optional `offset` and `limit` [now].
3. **L4PAR-AC3 honest capture.status.** On the rig, `l4.capture.status` as operator and as agent returns, with no error, `available: false`, `code: "needs_privilege"`, a non-null `reason`, and `captures: []`; `l4.capture.start {interface: "lo0"}` still errors with `L4 unavailable: ` followed by exactly that `reason` (`test_l4_parity_core.py`, which also quotes the literal) [now]. Unit: a module whose availability source reports available returns `available: true, code: "available", reason: null` [now: unit].
4. **L4PAR-AC4 honest intercept.status.** On the rig, `l4.intercept.status` returns `available: false`, `code: "unsupported_platform"`, a non-null `reason`, `sessions: []`, and `l4.intercept.start` still errors with that reason [now]. Unit: no intercept config on an otherwise privileged module gives `code: "not_configured"`; on Linux, a probe without `CAP_NET_ADMIN` gives `code: "needs_privilege"`.
8. **L4PAR-AC8 PoC default interface.** Unit: an `l4:` step with no `interface` resolves to `lo0` under `cfg(target_os = "macos")` and to `lo` under Linux [now: unit]. Live send on lo0 [D0].
9. **L4PAR-AC9 no core edits.** `git diff --stat <base>...HEAD -- crates/aitm-core` is empty. A unit test asserts the two status verbs are not `L4Gated`: they return `Ok` on a module whose privilege is unavailable [now].
34. **L4PAR-AC34 self-exclusion.** Unit: with self ports `{27431}`, a loopback frame 127.0.0.1:51000 → 127.0.0.1:27431, and its reply 27431 → 51000, are not recorded even under a capture scope covering `127.0.0.1/32` all ports, while 51000 → 9099 is; `scope_filter` for `lo0` ends with `and not port 27431`. Live: on a privileged rig a capture of lo0 never records the bus connection the check itself makes [D0]. Every recorder passes the choke point: `send_recv_reply_capture_ignores_self_traffic`, `self_port_packet_is_forwarded_never_parked` (intercept), `ingress_refuses_the_cores_own_loopback_traffic` (NE), `the_bound_port_hook_adds_the_agent_port_to_the_l4_guard` (the shared hook) and `attach_bound_hook_feeds_the_bound_port_to_the_l4_guard` (`aitm tui`, binds a loopback port, Terminal gate) are the unit halves.
35. **L4PAR-AC35 bytes per packet.** Unit (`flow_get_bytes_gate_is_per_packet`, `rhai_flow_get_bytes_gate_is_per_packet`, over MCP `agent_flow_get_has_no_bytes` / `agent_flow_get_has_bytes_when_capture_gate_open`): a SendRecv flow with one injected and one captured packet read by an agent with only the Inject gate open carries `bytes` on the injected packet only; with only the Capture gate open, on the captured packet only; an Intercept flow read with only the Intercept gate open carries no `bytes`; the operator and the CLI get both. Live: an agent `l4.flow.get` on a capture flow carrying the bus port returns no `bytes` [D0].
36. **L4PAR-AC36 byte budget.** Unit: 300 packets of 60,000 bytes with the default window return 69 packets, `truncated: true`, `next_offset: 69`; a 3-packet flow returns `truncated: false`, `next_offset: null` [now: unit].
37. **L4PAR-AC37 arrival order.** Unit: parking `P2` and then `P1`, where `P1`'s uuid sorts lower, makes `l4.intercept.list` return ids in the order `[P2, P1]`, each with an integer `parked_at`, and the `P2` entry's `parked_at` ≤ the `P1` entry's [now: unit]. Live [Linux].
38. **L4PAR-AC38 availability read at invoke time.** Unit: one registered module whose availability source is flipped from unavailable to available between two `l4.capture.status` calls answers `available: false` and then `available: true`, with no rebuild [now: unit].

**Core scope (a')**
5. **L4PAR-AC5 operator scope add, confirmed.** On the rig with `widen: false`, operator `l4.scope.add {cidr: "127.0.0.1/32", ports: "9100-9199", interface: "lo0", direction: "inbound", capability: "capture"}` returns `needs_confirmation` with a `confirm_token` and a prompt containing `127.0.0.1/32`, `9100-9199`, `lo0`, `inbound`, `capture`. Re-issuing with `_confirm` returns an id. `l4.scope.list` then shows it with `source: "runtime"` and the three config entries with `source: "config"`. `l4.agent.status` reads `widen: false` before and after. `l4.scope.remove` removes the entry. `tools/list` shows `l4.scope.add` `confirmable: true` [now]. Unit: the prompt with ports omitted contains `all ports`; with `inject_rate` 0 it contains `inject refused (rate 0)`; for `10.0.0.0/8` it contains `WARNING: /8 is a wide range`.
6. **L4PAR-AC6 agents unchanged.** On the rig, agent token, policy `all`, widen off: `l4.scope.add` is refused with the existing "runtime L4 scope widening is disabled" text, no confirmation is offered, and the list is unchanged. Policy `auto` is refused by policy [now]. Unit: a Rhai `l4.scope.add` with a trusted-control caller is still refused while widen is off. The L4OPS-AC5 tests in `crates/aitm/tests/l4_operator_surfaces.rs` pass with their agent assertions unmodified.
7. **L4PAR-AC7 runtime provenance.** Unit: an operator-path add of `169.254.169.254/32` with `dangerous_dst_override: true` stores `Runtime`, and `check(Inject)` to that address still returns `DangerousDestinationBlocked` [now: unit].

**TUI (b)**
10. **L4PAR-AC10 parked id.** Unit (`l4_parity.rs`): with intercept flow `F` and an `l4.intercept.list` reply `[{id: "P1", flow: "F", ...}]`, Forward emits exactly `Call {name: "l4.intercept.forward", args: {"id": "P1"}}`, Drop the same with `l4.intercept.drop`, and neither ever sends `"F"`. Live forward on a parked packet [Linux].
11. **L4PAR-AC11 documented-limited bar.** Live TUI on the rig: the L4 intercept bar shows the core's `reason` text, and the Forward/Drop/Mutate keys put no `l4.intercept.*` call on the bus (checked in the rig core's audit ring for the TUI connection) [now].
12. **L4PAR-AC12 Mutate/Revert.** Unit: "apply to parked packet" emits `l4.intercept.mutate {id: "P1", spec: <editor spec>}`, and revert emits `l4.intercept.revert {id: "P1"}`. Live [Linux].
13. **L4PAR-AC13 L4 scope view and add.** Live TUI on the rig: the scope panel shows an "L4 scope" section with the three config entries (lo0, 127.0.0.1/32, 9000-9999, capture/inject/intercept). Against a core with (a'), `:scope add l4 127.0.0.1/32 9100-9199 lo0 inbound capture` opens a confirm with the core's prompt, `y` adds it, and it appears in the section within one slow poll; against a core without it, `:scope add l4` is refused locally and sends nothing. HTTP `:scope add <host>` is unchanged [now, with (a')].
14. **L4PAR-AC14 chips and help.** Live TUI on the rig with real HTTP rows: an `L4` quick filter is visible; help and the filter hint list `~l4 ~tcp ~udp ~icmp`; `~l4` hides every HTTP row [now]. L4 rows shown under it [D0].
15. **L4PAR-AC15 capture controls.** Live TUI on the rig: the L4 view shows "capture unavailable" plus the AC3 reason; `:l4 capture lo0` refuses locally with that reason and puts no `l4.capture.start` on the bus [now]. Start, list, stop [D0].
16. **L4PAR-AC16 no HTTP verbs on L4 rows.** Unit: on an L4 row the mark, comment, replay and PoC actions emit zero `BusRequest`s and toast that they are not available for L4 flows [now: unit]. With a real L4 row [D0].
17. **L4PAR-AC17 stale banner gone.** Live TUI as operator on the rig: the Agent overlay's first line is `policy: <policy> · ...`. Tripwire: the string `core follow-up F1` (not followed by a digit) does not appear in `crates/aitm-tui/src` [now].

**Web (c)**
18. **L4PAR-AC18 capture args.** Unit (`args.test.ts`): the capture-start builder returns exactly the keys `interface` and `direction`. Live: a check fetches the rig's `tools/list` and asserts every key every L4 arg builder emits (capture start/stop, intercept verbs, scope add) is in that verb's inputSchema. Tripwire: no `filter` key in any `l4.capture.start` call in `apps/web/src` [now].
19. **L4PAR-AC19 Start/Stop capture.** Live browser (`cua-l4.mjs`) as operator on the rig: Start capture is disabled with the AC3 reason as its visible text or tooltip [now]. Unit: Stop emits `l4.capture.stop {id}` for each running id. Live start and stop [D0].
20. **L4PAR-AC20 intercept bar.** Live browser on the rig: the bar is one documented-limited line with the AC4 reason and no enabled Forward/Mutate/Drop [now]. Unit: Mutate emits `l4.intercept.mutate {id: <parked id>, spec}`, Revert emits `l4.intercept.revert {id}`, Forward/Drop send the parked id. Live [Linux].
21. **L4PAR-AC21 chips.** Live browser on the rig with real proxied HTTP rows: the chip bar reads `All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2 | ...`, selecting `L4` leaves zero HTTP rows, and ⌘5 selects `TCP` [now]. L4 rows under it [D0].
22. **L4PAR-AC22 L4 scope add.** Live browser on the rig with (a'): the AC5 entry is added through the L4 page's add form, the confirm dialog showing the core's prompt, and it appears in the scope list with `runtime` provenance. Against a core without (a') the form is absent [now, with (a')].
23. **L4PAR-AC23 poll less.** Live browser as operator, 60 s idle on the rig: the activity log gains no L4 polling error entries, and the rig core's audit ring shows at most 30 `l4.*` calls per minute from that connection [now].
24. **L4PAR-AC24 agent role.** Live browser on the agent URL: Start capture, Inject, scope add, Forward/Drop/Mutate and the gate toggles are disabled with an "operator only" reason, and none of them reaches the bus [now].

**macOS (d)**
25. **L4PAR-AC25 live L4 polling.** A live dev bundle (`APP_LIVE=1`, isolated suite, rig as external core): the rig core's audit ring shows `l4.flow.list` from the mac connection on every poll. Tripwire `check-l4-live.sh`: it fails if `BusService.swift` lacks `l4.flow.list` and `l4.flow.get`, or if `APP_L4_EMBEDDED` appears under `apps/mac/Sources` or `apps/mac/tools` [now]. Live L4 rows [D0].
26. **L4PAR-AC26 availability from the core.** The dev bundle against the rig shows, on the Scope page's L4 section, a capture line stating that capture and inject are unavailable with the AC3 reason, and the intercept line with the AC4 reason [now]. The Inject button itself needs an L4 row [D0]. Kit unit: `resolve` maps the AC3 object to `.degraded(reason)`, `{available: true}` and a bare array to `.available`, an error containing `L4 unavailable: X` to `.degraded(reason: "X")`, and no reply to `.pending`.
27. **L4PAR-AC27 sample accepted.** `l4.craft` on the rig, called over the bus with the parsed starting text, returns `length 36` [now]. Kit unit: the sample's JSON has `udp.src_port 40000`, `udp.dst_port 9`, and `raw` as an 8-element byte array. Build in the app's Craft tab needs an L4 row: blocked: needs D0.
28. **L4PAR-AC28 intercept on macOS.** The dev bundle against the rig: the intercept line is documented-limited with the AC4 reason, with no clickable Forward/Drop [now]. Kit unit: the verdict args builder returns `{id: <parked id>}`. Live [Linux].
29. **L4PAR-AC29 chips live, no HTTP verbs.** The dev bundle against the rig with real HTTP rows: `TCP UDP L4` chips are present and `L4` leaves zero HTTP rows [now]. Kit unit: the context-action model for an L4 row has no enabled mark, comment, replay or PoC [now: unit].
30. **L4PAR-AC30 L4 scope on the Scope page.** The dev bundle against the rig lists the three config L4 entries; with (a') it adds the AC5 entry through the operator confirm, and without (a') it shows no add form [now, with (a')].
31. **L4PAR-AC31 no phantom pins.** The dev bundle with a fresh isolated suite and an empty `APP_STORE` against the rig shows no pinned hosts the operator did not pin [now].

**Docs (e)**
32. **L4PAR-AC32 docs list l4.\*.** `mcp-tool-catalog.txt` and `tool-reference.md` each contain all 25 `l4.*` names from the rig's `tools/list`, checked by a script diffing the two. The overview skill names `l4.capture.status`'s `available/code/reason`, the operator-confirmed `l4.scope.add`, and the Linux-only `l4.intercept.*`. `tests/e2e/l4/` no longer attributes pcap privilege to the Network Extension (done in (a)) [now].

**Cross-cutting**
33. **L4PAR-AC33 nothing that can only fail.** On the rig, in each of TUI, web and macOS, no enabled control's action returns `L4 unavailable` (ACs 11, 15, 19, 20, 26 and 28 together) [now]. Panel security review confirms no diff widens an agent path.
39. **L4PAR-AC39 scope-add control only where confirmable.** Unit, one per UI: the TUI's `supports_operator_scope_add`, the web's `supportsOperatorScopeAdd` and the Kit's `L4Wire.supportsOperatorScopeAdd` each return true for a `tools/list` holding `l4.scope.add` with `confirmable: true`, and false when `confirmable` is false or absent or the tool is missing [now: unit].
40. **L4PAR-AC40 packet text is inert.** Unit, one per UI: the hex/ASCII renderer maps bytes `[0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41]` to the ASCII column `.[A..~A`, and its output contains no character below 0x20 other than the line breaks it adds itself [now: unit].

## Left to the builder

- Key letters, layout and wording of documented-limited lines and disabled-reason tooltips, within the foundation tokens and the icon/editorial rules.
- How the TUI/web/mac pick the "selected parked packet" beyond the oldest-first default.
- The tripwire mechanism per surface (crate test reading source, shell grep, vitest over source), as long as it fails on the named regression.
- Whether the docs are regenerated or hand-edited.
- The mac L4 poll interval (no faster than the HTTP poll), and how the web's back-off resets when a capture starts.

## Open questions

Decided on 2026-10-31 (routine calls; Matt may override): **(i)** keep `InMemoryL4FlowStore` with UI polling; folding L4 into the core `FlowStore` (D8, an `aitm-core` change and the natural home for D9) is its own spec after D0. **(iii)** the macOS intercept bar is one documented-limited line with the core's reason and no buttons (L4OPS-AC12).

Still with Matt:

1. **(ii) Operator scope add.** Operator confirm-over-the-wire (§3), or reuse the agent Widen gate? **Recommended: operator confirm.** It matches §2.3/§3.3 of the operator-surfaces spec and leaves the Widen gate meaning exactly "may the agent widen"; reusing the gate forces the operator to open the agent's door to add scope themselves. It ships as (a'), so (a) does not wait on this answer.
2. **`content` text without base64.** The orchestrator asked that `l4.flow.get`'s MCP `content` text omit the base64 `bytes`. The `content` text is rendered generically by `aitm-mcp` (`render::render_content`, summary plus the whole value); a per-verb omission needs either a new `Command` hook (an `aitm-core` edit, which this spec forbids) or a generic `aitm-mcp` render rule (for example: a string under a key named `bytes` longer than 64 characters renders as `<N bytes, base64, in structuredContent>`, which would also shorten `l4.craft`). **Recommended: the generic `aitm-mcp` rule, in its own small change after (a).** The 4 MiB budget already keeps the duplicated reply under the cap without it.
