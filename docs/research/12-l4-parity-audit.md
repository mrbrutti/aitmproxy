# L4 parity audit: raw TCP/UDP flows in every frontend, proven on real traffic

**Date:** 2026-10-31. **Method:** a live `aitm web` core from `main` (1854fae, v0.5.4)
with `l4.enabled: true` and a config-declared loopback scope, driven over the real bus
as operator and as agent (python `aitm_e2e.bus`), with the real TUI in a pty, the real
web UI in a browser, and a dev bundle of the macOS app connected to that core as its
external core. Every "proven" cell below names the command that was run and what was
seen. A cell is **fixture-only** when the surface shows the capability only from
`Fixtures+L4.swift` / `fixture.rs` / `mock.ts` data, and **missing** when nothing in the
surface reaches the verb. Matt's rule for this audit: sample data is not proof.

Rig: `/tmp/claude/l4-rig/config.yaml` (proxy 28180, browser 28181, bus 27431, web 28182;
`l4.scope` = lo0 `127.0.0.1/32` ports 9000-9999, one entry each for capture, inject,
intercept), `python3 -m http.server 9099` as the TCP target, a UDP echo on 9053.

## Headline

1. **On macOS there is no L4 tamper path at all, by design.** `l4.intercept.*` (park,
   mutate, forward, drop) is Linux NFQUEUE only; every call on this Mac returns
   `L4 unavailable: in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN /
   NFQUEUE only)`. What a Mac can do once `/dev/bpf*` is readable is capture, craft,
   inject and send_recv. The three UIs nevertheless draw a Forward / Drop bar.
2. **The macOS app never shows a live L4 flow.** `BusService` polls only `flow.list` and
   `flow.get`; the only callers of `l4.flow.list` / `l4.flow.get` are the fixture
   command runner in `Session.swift`. Against a privileged external core the L4 rows,
   badges and inspector stay empty. Everything L4 the app has shipped is fixture-only.
3. **Two of the three UIs send the wrong id to Forward / Drop.** The TUI
   (`app.rs` `l4_intercept_verb`) and the mac `L4Inspector.interceptVerb` send the L4
   *flow* id; the core's `l4.intercept.forward/drop/mutate/revert` take the *parked
   packet* id from `l4.intercept.list`. Only the web UI sends the parked id.
4. **Scope-as-authorisation is config-only in practice.** Operator `l4.scope.add` is
   refused (`runtime L4 scope widening is disabled; declare scope in the l4.scope config
   block or set l4.allow_agent_widen`) unless the operator first flips the *agent*
   Widen gate with `l4.agent.set`. No UI offers an L4 scope add, and the TUI scope panel
   shows HTTP scope only.
5. **L4 flows are invisible to the generic flow surface.** They live in
   `InMemoryL4FlowStore`, never in `flow.list`, `flow.get`, `flow.detail` or the
   `flow.subscribe` push, so every UI polls `l4.flow.list` + N × `l4.flow.get`;
   `l4.flow.get` carries no bytes, timestamps, addresses or ports, so no UI can show
   src/dst, a hex dump, or a timeline. `poc.build`, `flow.mark`, `flow.comment`,
   `flow.replay` on an L4 id fail with `no flow with id`.

## Bus verbs, as seen live (operator token unless noted)

| Verb | Unprivileged core (this Mac, `/dev/bpf*` root-only) | Notes |
|---|---|---|
| `tools/list` | 109 tools, 25 `l4.*` (`agent.set/status`, `capture.start/stop/status`, `craft`, `flow.get/list`, `inject`, `intercept.drop/forward/list/mutate/revert/start/status/stop`, `interfaces`, `recon`, `scope.add/list/remove`, `send_recv`, `tcp_probe`, `udp_probe`) | L4OPS-AC2 holds |
| `l4.interfaces` | OK, lists `lo0`, `en0`, utun*, … | |
| `l4.scope.list` | OK, the three config entries with ids, `ports: "9000-9999"`, `inject_rate` | |
| `l4.agent.status` | `{"capture": false, "inject": false, "intercept": false, "widen": false}` | |
| `l4.flow.list` | `[]` | |
| `l4.craft {spec}` | OK: `{"bytes": base64, "length": 30, "summary": {"layers": ["IPv4","UDP"], "length": 30}}` | pure, no privilege, agent too |
| `l4.capture.start {interface: lo0, direction: inbound}` | `L4 unavailable: no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)` | L4OPS-AC3 holds |
| `l4.capture.status` | same `L4 unavailable` error | a read verb that errors instead of answering "none, unavailable because …" |
| `l4.capture.stop {id}` | same | |
| `l4.capture.start {interface, filter}` (what the web UI sends) | `-32602 unknown param filter for l4.capture.start` | **web bug**, fails before privilege |
| `l4.inject` / `l4.send_recv` | schema `spec*, dst*, interface*, port, count` / `… timeout_ms, expect`; without `dst`: `missing required param dst` | |
| `l4.intercept.start/status/list` | `L4 unavailable: in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)` | by design |
| `l4.scope.add {cidr, ports, interface, direction, capability}` | **refused** for the operator: `runtime L4 scope widening is disabled; … set l4.allow_agent_widen` | spec §3.3 says operator-confirmed add |
| `l4.agent.set {capability: widen, allowed: true}` then `l4.scope.add` | OK: gate flips, add returns an id, `l4.scope.list` shows it; `l4.scope.remove` works; gate flipped back | the only runtime path to add scope |
| agent token, policy `auto` | `l4.flow.list`, `l4.scope.list`, `l4.agent.status`, `l4.craft` OK; `l4.agent.set` and `l4.capture.start` refused: `the agent policy is auto … permits no sensitive actions` | L4OPS-AC5 holds |
| `poc.build {flow_id: <l4 uuid>}` | `poc.build: no flow with id …` | HTTP store only |
| `flow.mark` / `flow.comment` / `flow.replay` on an L4 id | `no flow with id …` | the TUI sends these on an L4 row |
| `findings.record {…, flows: [<l4 uuid>]}` | needs `target`, `class`; stores any uuid without resolving it (code: `aitm-findings/src/commands.rs`) | not a real link |
| Mac `L4Inspector.sampleSpec` sent to `l4.craft` | `invalid PacketSpec: invalid type: map, expected a sequence` (keys `sport/dport`, `raw: {data}`; the core wants `src_port/dst_port`, `raw: [bytes]`) | **mac bug**, hidden by the fixture |

Privileged results: **blocked, needs privileged capture the product does not yet obtain itself.**
See "Live capture" below.

## Frontend × capability matrix

Legend: **live** = proven with real captured packets on this rig (none in this audit);
**blocked** = needs privileged capture the product does not yet obtain itself; **live-unpriv** =
proven on the real bus but only the honest `L4Unavailable` path could be exercised;
**fixture-only** = exists only on sample data; **missing** = no path to the verb;
**n/a (platform)** = Linux-only verb, cannot be exercised on macOS; **wrong** = reaches
the verb with arguments the core rejects.

| Capability | MCP tools (agent) | CLI | TUI | Web UI | macOS app |
|---|---|---|---|---|---|
| List L4 flows | live-unpriv (`l4.flow.list` → `[]`); **blocked** (no privileged capture) | one-shot `aitm l4.flow.list` runs its own in-process core, never the running one: **missing** against a live core | polls `l4.flow.list`+`get` (`bus.rs`); **blocked** | polls every 1.5 s (`store.ts`); **blocked** | **fixture-only**: no live caller of `l4.flow.*` |
| Kind badge / TCP-UDP sub-label / chips | n/a | n/a | L4 badge + sub-label in `ui/flows.rs`; **no L4 chip**, help lists no L4 keys, filter hint omits `~l4 ~tcp ~udp` (filter accepts `~tcp`, seen) | L4 row component; **no L4/TCP/UDP quick-filter chip** (seen: All HTTP HTTPS WebSocket h1 h2 JSON …) | badge/sub-label in `FlowCellView`; **no L4/TCP/UDP chips** on main (seen) |
| Inspect packets (layers, hex, timeline) | `l4.flow.get` returns `layers`, `length`, `dir`, `injected` only: no bytes, time, addresses | missing | text layer tree; no hex (bus has no bytes) | LayerTree, no hex | fixture-only |
| L4 scope view | `l4.scope.list` live | `aitm l4.scope.list` in-process only | **missing** (scope panel is HTTP only, seen) | read-only list on the L4 page (seen) | fixture-only |
| L4 scope add (confirm) | operator refused unless Widen gate on (seen) | n/a | missing (`:scope add` → HTTP `scope.add`) | missing (run record admits it) | missing |
| Capture start / stop / status | start/stop/status gated; **blocked** | n/a | **missing** (no key, no palette shortcut beyond raw tool) | start only, **no stop**; filter param **wrong** (`unknown param filter`); unprivileged notice seen: `l4.capture.start: L4 unavailable: no read+write access to any /dev/bpf* device …` | missing |
| Intercept / pause (park) | n/a (platform) | n/a | missing (`intercept.start` never called) | missing | missing |
| Resume (forward) | n/a (platform) | n/a | **wrong id** (flow id) | parked id (code) | **wrong id** (flow id), fixture rows |
| Kill (drop) | n/a (platform) | n/a | **wrong id** | parked id (code) | **wrong id**, fixture rows |
| Mutate parked packet | n/a (platform) | n/a | missing (Edit opens craft pane) | **stub notice** | missing |
| Craft (build preview) | `l4.craft` live (seen) | n/a | `l4.craft` wired | `l4.craft` wired | wired but **sample spec rejected** (seen) |
| Inject (confirm) | gated; **blocked** | n/a | `s` → `l4.inject`; **blocked** | ConfirmInject → `l4.inject`; **blocked** | hard-coded dst 127.0.0.1 port 9, fixture rows only |
| Replay / send_recv | `l4.send_recv` gated; **blocked** | n/a | missing (`r` blocked for non-HTTP) | missing | missing |
| Findings / PoC from an L4 flow | `poc.build` → `no flow with id`; `findings.record` stores an unresolved uuid | n/a | `P` sends HTTP `poc.build` with the L4 id → `no flow` | missing | missing |
| Agent gate toggles | `l4.agent.status/set` live (seen) | `aitm l4.agent.status` in-process | **live**: `@` then `c` flipped Capture on, bus `l4.agent.status` → `capture: true`, `c` again → false (seen); banner still says "agent.status is not on this bus (core follow-up F1) — read-only", which is stale | **live**: Agent panel switch `Agent Capture` aria-checked false→true, bus → `capture: true`, click again → false (seen) | `AgentPanel` reads/sets live behind `l4Enabled` (code only: no CUA click in this audit) |
| Honest degradation (`L4Unavailable`) | typed error (seen) | n/a | toast (per `l4-cua-tui-acceptance.md`) | transient notice (seen) | `L4Availability` set only by `APP_L4_EMBEDDED=1` in fixture mode |

## Live capture (privileged half): blocked

**Blocked: needs privileged capture the product does not yet obtain itself.** On this Mac
`/dev/bpf0-3` are mode 0600 root (measured from the login shell at 16:25 PDT on
2026-10-31: `os.stat` 0o20600 gid 0, `open("/dev/bpf0","r+b")` → Permission denied), and
the only way the current product can capture is for the operator to run `sudo chgrp` /
`sudo chmod` on the device nodes or run the core as root. Matt's rule (2026-10-31): the
operator must never have to type a command line for a privilege the product should
obtain itself through the OS's own prompt, the way Proxyman does. So the sudo rig was
withdrawn, no capture, inject or send_recv was observed with real packets in this audit,
and every capture-dependent cell below is marked **blocked**, not proven. The prepared
walk (`/tmp/claude/l4-rig/walk4.py`: capture lo0 → real HTTP, TCP and UDP traffic →
`l4.flow.get` → craft + inject to the UDP echo → `send_recv` → out-of-scope inject
refused) is the acceptance script for the privilege design in
`docs/research/13-l4-capture-privilege-without-cli.md` and its spec.

This is the root defect, **D0** below: the product has no self-obtained privilege path on
any OS, so L4 capture is unreachable for every frontend as shipped.

## What the design promised that is not there

From `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md`:

- §3.1 / L4OPS-AC7 "union flow list, every kind renders": true in TUI and web (code),
  false in macOS (fixture-only). Filter atoms `~l4 ~tcp ~udp ~icmp` are not surfaced.
- §3.3 / L4OPS-AC9 "scope panel gains an L4 scope view; adding an L4 scope entry is
  Sensitive (operator confirm)": no UI adds L4 scope; the core refuses the operator.
- §3.4 / L4OPS-AC12 "intercept bar … where absent (macOS/unprivileged) renders
  documented-limited": TUI and mac render Forward / Drop with a wrong id; nobody can
  reach `l4.intercept.mutate` from a UI.
- L4OPS-AC14 "real-packet CUA acceptance ×3": the plan's review log already records no
  real-packet run on macOS. The macOS run cannot have happened: the app has no live L4
  list.
- L4OPS-AC18 "macOS honest degradation … pointing the macOS UI at a privileged core
  drives L4 fully": false, the app never reads L4 flows from any core.
- `docs/research/mcp-tool-catalog.txt` has no `l4.*` entry; `aitmproxy-plugin/docs/
  tool-reference.md` says the family "is not listed here"; the agent skills never
  mention L4. The agent learns L4 only from live `tools/list` descriptions.
- The Rhai / PoC `l4:` step default interface is `lo` (`language.rs`), wrong on macOS.
- `tests/e2e/l4/*` docstrings say macOS needs the Network Extension; `l4.capture.start`
  is pcap/BPF only, and NE-captured TCP lands in the HTTP store (`ingress.rs`); NE UDP
  reaches the L4 store only when `l4.enabled`, which the embedded core's config never
  sets (`EmbeddedCoreLaunch.swift`).

## Defects, ranked

| # | Severity | Surface | Defect | Evidence |
|---|---|---|---|---|
| D0 | Critical | product | No self-obtained capture privilege on any OS: the core only probes `/dev/bpf*` / `CAP_NET_RAW` and tells the operator to "install ChmodBPF or run with privilege"; no frontend offers an "Allow packet capture" action, so L4 is unreachable without a command line | `module.rs` `probe()`; live `L4 unavailable: no read+write access to any /dev/bpf* device`; `/dev/bpf*` 0600 root measured 16:25 PDT |
| D1 | Critical | macOS | No live L4 rows: `l4.flow.list/get` never called outside fixtures; the whole L4 surface is sample data | `Session.swift:350-390` (fixture runner), `BusService.swift:144-148`; live dev bundle shows 0 rows against an `l4.enabled` core |
| D2 | Critical | TUI, macOS | Forward / Drop send the flow id; core wants the parked-packet id → every verdict fails against a real intercept | `app.rs` `l4_intercept_verb` `json!({"id": flow.id})`; `L4Inspector.swift` `interceptVerb`; `intercept.rs` `ParamDef id: "The parked packet id (from l4.intercept.list)"` |
| D3 | Important | web | Filtered capture sends `filter`, rejected `unknown param`; no Stop capture control | live `-32602`; `CaptureControls.tsx` |
| D4 | Important | macOS | Craft sample spec uses `sport/dport` and `raw: {data}`; the core rejects it | live `invalid PacketSpec: invalid type: map, expected a sequence` |
| D5 | Important | core + all UIs | Operator cannot add L4 scope without flipping the agent Widen gate; no UI has L4 scope add; TUI scope panel has no L4 view | live refusal; `guard.rs add_runtime_scope`; TUI screen |
| D6 | Important | all UIs | Intercept bar drawn where the verb is unavailable and Mutate is unreachable (web stub, TUI/mac none) | `L4InspectorPanel.tsx:92`; `app.rs:1598` |
| D7 | Important | core | `l4.flow.get` lacks bytes, timestamps, src/dst: no hex, no timeline, no target column from data | `commands/flow.rs:170-229` |
| D8 | Important | core | L4 flows absent from `flow.list/get/detail/subscribe`: every UI polls N+1 calls; no push | `module.rs:9-12` (zero core edits by design) |
| D9 | Important | core + UIs | No L4 path to findings / PoC: `poc.build` is HTTP-only, `findings.record` stores an unresolved id, TUI `P` sends HTTP `poc.build` | live `no flow with id` |
| D10 | Minor | TUI, web, macOS | No `L4` / `TCP` / `UDP` chips; TUI help and filter hint omit the L4 atoms | screens |
| D10b | Minor | web | Polling churn: every 1.5 s the web calls `l4.flow.list`, `l4.scope.list`, `l4.capture.status`, `l4.agent.status`, `l4.intercept.status`, `l4.intercept.list`; on an unprivileged core four of those error each tick and fill the activity log (238 entries within 20 s of opening the page) | web Agent panel activity log, seen |
| D10c | Minor | TUI | Agent panel banner "agent.status is not on this bus (core follow-up F1) — the toggle is read-only here" while the toggles work live | screen |
| D11 | Minor | core | `l4.capture.status` errors `L4Unavailable` instead of answering; `l4.scope.add` is not confirm-gated though the spec calls it Sensitive | live |
| D12 | Minor | web | The first printed URL connects as an agent, so L4 actions are refused with a policy message until the operator URL is used | live |
| D13 | Minor | docs | MCP catalogue, plugin tool reference and agent skills omit `l4.*`; e2e docstrings blame the NE for pcap privilege | files |
| D14 | Minor | scripting | PoC `l4:` default interface `lo` is wrong on macOS | `language.rs:104` |
| D15 | Minor | macOS | Live session (`APP_LIVE=1`) shows fixture pinned hosts `api.shop-staging.test`, `auth.shop-staging.test` | screenshot |

## Verified by hand

- `tools/list` over loopback TCP as operator: 109 tools, the 25 `l4.*` above.
- Every error string in this note is the verbatim bus reply, truncated only in length.
- TUI screens are the real `aitm-tui` 0.5.4 in a 160×44 pty against the rig bus.
- Web screens are the real embedded `aitm web` UI (v0.5.4) as operator.
- The mac dev bundle (`DEV_TAG=l4audit tools/snap-dev.sh`, APP_LIVE=1, isolated defaults suite)
  shows `core external`, Scope 1, 0 flows, no L4 chips.
