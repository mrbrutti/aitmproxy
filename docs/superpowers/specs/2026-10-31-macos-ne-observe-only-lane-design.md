# macOS NE observe-only lane design

**Status:** draft
**Research inputs:** `docs/research/12-macos-observe-only-lane.md` (primary; "research
12" below), `docs/research/10-macos-network-extension.md` (§3.1, §3.5, §3.7, §3.9),
`docs/research/experiments/2026-10-29-macos-ne-spike.md`.
**Extends / reconciles with:** `2026-10-29-aitmproxy-macos-network-extension-design.md`
(D1–D4, D8, D9, NE-AC3/5/6/8/11, resolved OQ10);
`2026-10-30-aitmproxy-macos-ne-live-feeder-design.md` (LF-AC1/4/8/12, the
`macos_capture` section, the fail-open table); `2026-10-30-macos-ne-ship-and-toggle-design.md`
(Capture Settings tab, `capture.enabled`, `CaptureCapability.inactive`, TG-AC9);
`2026-10-30-macos-ne-core-prereqs-design.md` (under-inclusive, never over-inclusive).
**Code read (2026-10-31, `a248897`):** `apps/mac/Extension/Sources/*.swift`, the two
entitlement plists and `Extension/Info.plist`; `crates/aitm/src/macos_capture/*.rs`,
`crates/aitm/src/{ingress,wire}.rs`; `crates/aitm-core/src/{command,ctx,flow,store,protocol}.rs`;
`crates/aitm-plugins/src/{capture,detail}.rs`; `crates/aitm-mcp/src/server.rs`
(`policy_decision`, `defers_to_command_gate`); `crates/aitm-proto-l4/src/commands/agent.rs`
(`L4AgentGate`); `apps/mac/Sources/Aitmproxy/{Shell/ShellView,Session}.swift`,
`apps/mac/Sources/AitmproxyKit/{Flow,FlowSummary,CaptureCapability,L4}.swift`;
`apps/web/src/{state/app.ts,bus/normalize.ts,model/flow.ts}`; `crates/aitm-tui/src/model.rs`.

## Intent

On 2026-10-31 (v0.5.3) the whole NE chain worked on Matt's Mac: extension approved,
provider attached, and every flow declined because the scope was empty
(deny-by-default). Matt expected Proxyman / Little Snitch style visibility: the Apps
page listing every app's connections (app, destination, protocol, counts) even with no
scope. Today there is no way to see all apps' traffic without MITM-ing it, and the Apps
page is empty live even for in-scope captures because the core drops the source-app
identity at the ingress (research 12 §3.0 fact 1, §3.1). This spec designs the
**observe-only lane**: connection *metadata* for flows the provider does not claim, plus
the identity plumbing for flows it does, so the Apps page becomes a real network monitor
while MITM stays deny-by-default and the provider stays fail-open. Design only.

## Goals

- **Part 1 — identity on claimed flows.** A captured in-scope flow reaches `flow.get` /
  `flow.table` / `flow.detail` with its source app, so the three UIs' existing per-app
  slots (`ClientInfo`, web `clientOf`, TUI `process`) fill live.
- **Part 2 — observed rows for declined flows.** With the operator's explicit opt-in the
  provider reports *app, remote IP:port, hostname when connect-by-name, TCP|UDP, time*
  for each flow it declines, over the existing authenticated control channel, without
  claiming it. The Apps page lists every app's connections with counts.
- **Fail-open unchanged.** An observe emit never blocks or slows `handleNewFlow`; a wedged
  or absent core leaves the network untouched; events are lossy and bounded by construction.
- **Metadata, never bytes.** No payload, DNS answer, or body of an out-of-scope flow ever
  crosses the control channel or lands in the core.
- **Operator-only, default off, agent-gated; a wire that can grow into option (b)**
  without UI or store rework (research 12 Candidate 2).

## Non-goals

- No `NEFilterDataProvider` in v1 (bytes, duration, close, ICMP, inbound, loopback). Its
  impact is assessed so Matt can choose it; it is not built here.
- No claim-and-relay of out-of-scope flows (option (c)); rejected in §Recommendation.
- No reverse DNS, SNI peeking, or DNS proxying; a flow without `remoteHostname` shows as
  IP:port (Little Snitch's own fallback).
- No proxy-only (loopback `127.0.0.1:<port>`) client attribution: those flows never reach
  the extension (research 12 §3.5); F5's libproc lookup is a separate item.
- No disk persistence, export, or history across core restarts; no `flow.subscribe` push
  of observed rows (UIs poll); no TUI observe view (TUI gets Part 1 only).
- No change to scope semantics, `ScopeMatcher`, the scope-spec emitter, the data socket,
  or the per-flow pairing path.

## Anti-goals

- **Observation that slows or blocks the Mac's connections.** If `handleNewFlow` can wait
  on the core, a socket, or JSON encoding because of an emit, NE-AC5 is broken even if
  every row renders.
- **Bytes on the control channel for a declined flow**, however few.
- **A quiet widening.** Enabling observation must not make the provider claim one more
  flow or the scope-spec emitter emit a wider token.
- **An agent-reachable on-switch, or agent-readable rows by default.**
- **Observed rows that look like captured flows** (a body, an inspector, intercept
  actions, or a seat in the flow list).
- **Other users' apps on the operator's screen** (the sysex is root and global; parent OQ10).

## Constraints

- **Fail-open stays.** The provider never claims a flow the core may refuse; an observe
  emit must never block or slow `handleNewFlow`; a wedged (alive, not reading) or absent
  core leaves the network untouched (research 12 §3.2.4; the tree's 2 s
  `handshakeSendTimeoutSeconds` comment).
- **Code-signature peer auth on the UDS stays in both directions** (NE-AC6, LF-AC3/7). No
  new socket, no new unauthenticated path; `FlowSeen` rides the verified control channel.
- **No agent/MCP path widens capture or turns observation on.** Operator opt-in only, by
  config file and the Capture Settings tab (LF-AC12 / TG-AC9 precedent).
- **Deny-by-default MITM scope is untouched**; `claim()` runs first and is unchanged.
- **Apple approval is assessed, not performed.** Verified 2026-10-31 (Terminal panel,
  research 12 §3.3.5): both A1 Developer ID profiles already allow
  `content-filter-provider-systemextension`, `dns-proxy-systemextension`,
  `packet-tunnel-provider-systemextension` and the rest, so even (b) needs no portal
  change or new profile. Every signing is Matt's identity in the Terminal panel; no coder
  or agent touches the portal, profiles, or approval prompts.
- **Protocol-version discipline.** A new `ControlMessage` variant is a decode error on
  today's core and detaches the provider (research 12 §3.1, §3.2.6); the version must bump
  so skew fails loudly at `Hello`, never mid-stream.
- **Bounds everywhere.** `MAX_FRAME_LEN` (1 MiB) stays; new queues and stores have fixed
  caps with oldest-eviction; `MemFlowStore` (50 000 flows) is not shared.
- **Gates.** Rust gate green before review; `forbid(unsafe_code)` holds; the Swift side
  passes `./build.sh`, `swift test`, snapshots and grid checks. UDS bind, Swift builds,
  and real-Mac checks run in the Terminal panel. Seven stages; a Stage-6 **security
  review is mandatory** (provider and handoff are touched).

## Design

Defaults the Architect chose are marked **(Architect's call)**.

### Recommendation: option (a) now, wire shaped for (b) — research 12 Candidate 2

**Decision (Architect's call).** Build (a): a metadata-only `FlowSeen` from the existing
`NETransparentProxyProvider` for flows it declines, on the existing control channel.
Shape the message family and the core store so a later `NEFilterDataProvider` (b) can
feed byte counts and close events into the same rows. Do not build (b) or (c) now.

**v1 gives:** per app (signing identifier; executable path as the fallback for system
processes), remote IP:port, hostname when the app used a connect-by-name API, TCP or UDP,
connection counts, first/last seen. **Not in v1:** bytes, duration, close/success, ICMP,
inbound, loopback (research 12 §3.2.2: the transparent-proxy headers expose none of these
for a declined flow).

**Only (b) adds:** per-flow byte totals and periodic statistics (header-documented on
`NEFilterReport`, but population for an allow-without-filtering verdict is **unverified**),
a close event, ICMP, the app-versus-creating-process split, inbound flows, opt-in loopback
(research 12 §3.3.1–3.3.2, §4.2). **Its costs:** a third consent prompt, a second
synchronous verdict in every app's connection path, an **unknown** fail-open posture on
provider death, field-reported regressions when a filter and a transparent proxy coexist,
and de-duplication (a filter reports every flow, including the ones the proxy claims;
§3.3.4, §3.3.7). The parent D1 already records `NEFilterDataProvider` as "a possible
future observe-only complement, not v1"; this spec keeps that.

**Why (a) for v1:** no new provider class, entitlement, plist entry, profile, prompt, or
consent; its one new risk, the emit's backpressure, is removed by construction (Part 3);
and the Apps-page deliverable does not need bytes. (b) returns only if Matt answers Open
question 2 "bytes are required".

**Why (c) is rejected** (research 12 §3.4): the core becomes every app's egress, so a
core stall or refusal breaks every app (the parent anti-goal "breaks the user's network
when the core is gone"); `dispatch_tcp` refuses out-of-scope flows and its SSRF connector
blocks LAN targets, so claiming all needs a new unguarded passthrough disposition (a
deny-by-default design change); the upstream leg loses the source app (appears as
`aitm`); all apps' bytes transit the core's memory, inverting D2's privacy win; every
claimed-flow quirk (Chromium UDP, mbuf leaks) becomes the product's bug.

### Part 1 — identity on claimed flows (in scope: the F5 core half)

**Decision (Architect's call): this spec plumbs identity onto claimed flows.** Without it
the Apps page stays empty for in-scope captures whatever the extension reports (research
12 §4.0). This is F5's core half and may edit `aitm-core`: the `"process": null` slot in
`detail.rs` was reserved as a core concern (foundation Q6), not an NE accommodation.

- `aitm-core/src/flow.rs`: `ConnInfo` gains `pub process: Option<String>` (the source-app
  signing identifier). Every `ConnInfo {` literal (production: `aitm-proto-http/src/{module,h2}.rs`;
  ~12 test files under `aitm-plugins/tests`) gains `process: None`.
- `aitm-core/src/protocol.rs`: `ModuleCtx` gains `peer_identity: Option<String>`, builder
  `pub fn with_peer_identity(mut self, id: Option<String>) -> Self`, accessor
  `pub fn peer_identity(&self) -> Option<&str>`; `for_upgrade` copies it.
- `aitm/src/ingress.rs` `dispatch_tcp`: `.with_peer_identity(flow.peer_identity.clone())`
  (the field is filled by `adapter.rs` and read nowhere today). UDP identity rides Part 2 only.
- HTTP and WS modules: copy `ctx.peer_identity()` into `client_conn.process`;
  `server_conn.process` stays `None`.
- `aitm-plugins`: `detail.rs` `conn(c, with_process)` emits `c.process` instead of the
  constant `null`; `capture.rs` `summarize` (`flow.get`) and `flow_row`/`row_fields`
  (`flow.table`) gain `"process": string|null`.
- UIs: mac `FlowSummary(json:)` reads `process`; `row()` sets
  `client: ClientInfo(name: process, bundleID: process)` (display-name lookup left to the
  builder). Web `clientOf` and TUI `Conn::parse` already read `client_conn.process`.

Part 1 carries only the signing-identifier string `FlowOpen.source_app` already holds; a
richer claimed-flow identity (pid, path) is a `FlowOpen` wire change and is **not** made.

### Part 2 — the wire: two new control messages, protocol version 2

Both halves of `ControlMessage` (`listener.rs:125-132`; Swift `HandoffMessages`) gain
`FlowSeen(FlowSeen)` (provider → core, one per declined flow) and `Observe(ObserveSpec)`
(core → provider, after `Scope` and on change).

`FlowSeen` **(Architect's call)**, metadata-only by construction — no byte-, payload-, or
body-typed field exists on the struct:

| Field | Type | Source (research 12 §3.2.1, §3.2.3) |
|---|---|---|
| `kind` | `FlowKind` (`Tcp`\|`Udp`) | which delegate fired |
| `remote` | `SocketAddr` | `remoteFlowEndpoint` / `initialRemoteFlowEndpoint` |
| `remote_hostname` | `Option<String>` | `remoteHostname` (connect-by-name only; ≤ 253 bytes) |
| `source_app` | `Option<String>` | `metaData.sourceAppSigningIdentifier`; `None` when empty |
| `source_path` | `Option<String>` | `proc_pidpath_audittoken`, resolved **only when `source_app` is `None`**; the provider truncates to 1 024 bytes |
| `source_pid` | `Option<u32>` | `audit_token_to_pid`; display-only, never a grouping key (pid reuse) |
| `source_uid` | `Option<u32>` | `audit_token_to_euid`; already filtered provider-side (Part 3) |
| `seen_at_ms` | `u64` | provider wall clock, ms since the Unix epoch |
| `dropped` | `u64` | the provider's cumulative count of queue drops |

Reserved for (b), absent from the struct until (b) lands: `bytes_in`, `bytes_out`,
`closed_at_ms`. The store row (Part 4) already has optional slots for them, so (b) is a
field addition, not a reshape.

`ObserveSpec { enabled: bool }`: the feeder sends it right after `Scope` on attach and
again on change; a provider that has not received `Observe(true)` emits nothing. The
provider's `decodeCore` ignores unknown single-key messages, so an old provider under a
new core stays silent.

**Version.** `HANDOFF_PROTOCOL_VERSION` (`adapter.rs:42`) and `HandoffConfig.protocolVersion`
(`FlowHandoff.swift:60`) both become **2**. `check_hello` keeps **exact** matching
**(Architect's call)**: a v1 provider against a v2 core, or the reverse, is refused at
`Hello` with a log line naming both versions; the provider fails open and retries every
2 s; the next `enable()` replaces the sysex (both halves ship in one DMG, `CFBundleVersion`
bumps per build). Rejected: accepting `{1, 2}`, which hides skew.

### Part 3 — the provider: enqueue-only emit, dedicated writer, uid filter

In `handleNewFlow` / `handleNewUDPFlow` the existing order holds and one step is appended
for the declined case: (1) `SelfExclusion.isSelf` (self flows are neither claimed nor
observed); (2) `claim()` unchanged — a claimed flow returns `true` and is **not** observed
(it appears as a captured flow via Part 1); (3) **new, on decline only:** if the
attachment has `observe == true` and the flow's audit-token euid equals the attached
core's uid, build a `FlowSeenDescriptor` from fields already read for the claim decision
plus three integer extractions from the audit token, `ObserveQueue.tryPush(descriptor)`,
then return `false` as today.

- **`tryPush` is the only work on the NE thread.** O(1), a short mutex with no I/O under
  it, no JSON encoding, no syscalls beyond the audit-token extraction and (only when the
  signing id is empty) one `proc_pidpath_audittoken`. Never `CoreLink.send` (it takes
  `writeLock` and blocks up to 2 s; research 12 §3.2.4).
- **Bounded, drop-oldest.** `ObserveQueue` capacity **2 048** **(Architect's call**, a
  multi-second browser burst at the §3.2.5 estimate; the §5 item 7 experiment can retune).
  On overflow the oldest entry is dropped and a counter increments; it rides the next
  `FlowSeen.dropped`.
- **One writer thread** (`ObserveWriter`) drains the queue, encodes one frame per event,
  and writes through `CoreLink.send` under the existing 2 s `SO_SNDTIMEO`. A failed send
  tears the channel down exactly as a failed `FlowOpen` does (detach → every flow direct).
  Per-event frames **(Architect's call)**; provider-side aggregation is rejected for v1
  (loses per-flow timestamps; the core aggregates on read).
- **The writer shares `CoreLink.send`'s `writeLock` with the claim path.** `claim()` runs
  on the NE thread for **claimed** flows and already sends `FlowOpen` through
  `CoreLink.send` (`FlowHandoff.swift:720-731`: `writeLock` plus the 2 s `SO_SNDTIMEO`
  write). A claimed flow's `FlowOpen` may therefore wait behind at most **one** in-flight
  observe write, bounded by that 2 s timeout on a wedged core, after which the observe
  send fails, `send` tears the channel down (`shutdownBoth`), the queued `claim()` send
  fails at once, and every flow fails open — the same 2 s bound the claim path has today.
  **Declined** flows are never affected (`tryPush` only).
- **Nothing produced or kept while detached.** `Observe` state and the queue are cleared
  in `CoreLink.detach`; the provider holds no history for an absent core (a root process
  holding all apps' history is a privacy exposure, research 12 §3.2.4).
- **uid filter (resolves OQ10 for observed rows).** At attach the provider already reads
  the core's peer audit token (`PeerAuth.peerAuditToken(of:)`); it keeps its
  `audit_token_to_euid` as `coreUID`. A flow whose euid differs, or whose token is
  missing, is not observed. So root daemons (`mDNSResponder`) and other users' apps never
  appear **(Architect's call**, Open question 4). The claim path's OQ10 is not retro-fitted here.
- A flow that matched scope but failed `claim()` (data-socket dial or peer check failed)
  went direct and is observed like any declined flow.

### Part 4 — the core: a separate bounded store and two gated commands

New module `crates/aitm/src/macos_capture/observe.rs` **(Architect's call**: the `aitm`
wiring layer beside the feeder; not `aitm-core`, not a new crate; not the closed `Flow`
enum, not `L4Flow`, not `MemFlowStore` — research 12 §3.1, §4.3).

- `pub struct ObservedFlow { kind, remote, remote_hostname, app: AppKey, source_pid,
  source_uid, seen_at_ms, bytes_in: Option<u64>, bytes_out: Option<u64>,
  closed_at_ms: Option<u64> }`; `AppKey` is `source_app` if present else `source_path`,
  with `is_path: bool`.
- `pub struct ObserveStore`: a `VecDeque<ObservedFlow>` capped at **20 000** events and an
  aggregate `HashMap<(AppKey, SocketAddr, FlowKind), Agg { count, first_seen_ms,
  last_seen_ms, hostname }>` capped at **10 000** keys, both drop-oldest (by `last_seen_ms`
  for the aggregate) **(Architect's call)**. Counters: `received`; `dropped_core` (ring
  evictions plus rate-cap drops); `aggregate_evicted`; `dropped_provider` (the max
  `FlowSeen.dropped` seen). No `std::fs`/`tokio::fs`; empty on every core restart.
- **Soft rate cap (Architect's call):** above **5 000** `FlowSeen`/s the feeder counts
  the excess as `dropped_core` and skips the insert (memory is already bounded; this caps CPU).
- Feeder (`feeder.rs` control loop): act on `FlowSeen` (insert) beside `FlowOpen`; never
  touch the pairing map for a `FlowSeen`; send `Observe` after the initial `Scope` and
  whenever `observe.enabled` changes. The "detach on decode error" branch stays.
- **Commands**, registered in `wire.rs` **iff** `macos_capture.enabled &&
  macos_capture.observe.enabled` on macOS (UIs feature-detect by presence):
  - `observe.apps` → `{ enabled, received, dropped_provider, dropped_core,
    aggregate_evicted, apps: [{ app, is_path, count, first_seen_ms, last_seen_ms,
    destinations: [{ remote, hostname, kind, count, first_seen_ms, last_seen_ms,
    bytes_in, bytes_out }] }] }`, apps by `count` descending.
  - `observe.events { limit?: int }` → the newest `limit` (default 200, max 1 000)
    `ObservedFlow`s, newest first, as flat objects.
  - Both are `Sensitivity::Read` and wrapped in `ObserveAgentGate`, a copy of
    `L4AgentGate`'s shape: `invoke` refuses when `!host.caller_is_trusted_control() &&
    !cfg.observe.agent_readable`, naming the knob **(Architect's call**: Read plus an
    Mcp-only config gate, not `Sensitive`, which would make `Ask` park a read and `All`
    refuse unless listed in `defers_to_command_gate`). `AgentPolicy::Paused` is refused by
    `policy_decision` anyway. There is no per-row gating (research 12 §3.1), so the gate
    is per command and observed rows live only behind these two commands — never in
    `flow.list`/`flow.table`/`flow.subscribe`.
  - `docs/research/mcp-tool-catalog.txt` and the agent-surface tests gain both names.

### Part 5 — the operator switch

```yaml
macos_capture:
  enabled: false
  observe:
    enabled: false          # observe-only lane; default off
    agent_readable: false   # may Frontend::Mcp call observe.*; default off
```

`ObserveConfig { enabled: bool, agent_readable: bool }`, `Default` all false,
`deny_unknown_fields`. Both knobs are **config-file-only**; no bus/MCP/`Session`/palette
path flips them (LF-AC12 extended). The app writes `observe.enabled` the way
ship-and-toggle writes `macos_capture.enabled`: `EmbeddedCoreLaunch.Config` gains
`observeEnabled: Bool = false`; `yaml()` appends the `observe:` block **only** when
`captureEnabled && observeEnabled`; `EmbeddedCore.spawn()` reads `UserDefaults` key
`observe.enabled` fresh each spawn; applied via `restartCoreTick`. `agent_readable` has
**no** app control in v1 **(Architect's call)**: a hand-edited config knob like
`ca.allow_agent_install`.

The Capture Settings tab (ship-and-toggle 2d) gains a second `Toggle` "Show every app's
connections (observe-only)" bound to `observe.enabled`, **disabled** while
`capture.enabled` is off, with one line: "Lists each app's destinations without
intercepting them. Nothing is decrypted or stored on disk." Menu item + shortcut per the
mac design rule; snapshots cover on/off.

### Part 6 — how the three UIs consume it

- **macOS Apps page.** `Session` polls `observe.apps` on its flow-table cadence when the
  command is present, into `ObservedApps` (Kit). The page merges two sources by app key:
  captured flows' `client` (Part 1) and observed apps. A destination is tagged
  **captured** (links to the flow list filtered by app; normal inspector) or **observed**
  (muted badge, no inspector, no intercept/replay/body actions, a small popover with app,
  pid, destinations). Observed rows never enter `Session.rows`. With the command absent
  the page shows the PR #181 explanatory state pointing at Capture Settings. Drops show
  as one line: "N connections not recorded".
- **Web.** A sidebar "All apps" panel fed by `observe.apps` beside the existing
  `groups().apps`; observed entries carry `observed: true`, render muted, never enter
  `entries`. `clientOf` is unchanged; Part 1 makes `client_conn.process` non-null.
- **TUI.** Part 1 only: the `process` column fills.

Observed rows are distinguished by shape, not styling alone: no flow id, no body sizes,
no status, no intercept state.

### Security analysis

**Data flow.** Root sysex → (self-exclusion, uid filter, bounded queue) → one JSON frame
per event on the **peer-verified** control UDS in a 0700 dir → the feeder, which has
**verified the provider** before reading → `ObserveStore` (in-memory, bounded) →
`observe.*` over the bus to operator-token clients, and to agents only if
`agent_readable`. **Never collected:** payload bytes, first bytes, DNS answers, URLs, SNI
from bytes, close/success, byte counts (v1). **Collected:** app signing id or executable
path, pid, uid, remote IP:port, hostname when connect-by-name, kind, provider timestamp.

**Who can read.** Trusted control (`Frontend::Operator`/`Cli`, any bus-token holder: the
same trust as the flow list). `Frontend::Mcp`: refused by `ObserveAgentGate` unless
`agent_readable`; under `Paused` refused by `policy_decision` regardless. `observe.events`
is the sensitive one: a timeline of the user's apps' destinations. Both knobs default off.

**Opt-in.** Config file plus the Capture Settings toggle; no bus/MCP verb; OL-AC14 proves it.

**Retention.** Ring 20 000 events / 10 000 keys, drop-oldest; provider queue 2 048,
cleared on detach; no disk; cleared on core restart (toggling observe off restarts the core).

**Privacy posture versus the parent spec.** D2's "we never even receive out-of-scope
bytes" stays literally true. The anti-goal "captures out-of-scope or non-consented
traffic into the core" is read as *flow bytes*. Proposed amendment to the parent spec
(Matt's to approve; this spec does not edit it): "*Traffic* means flow bytes. Connection
metadata about out-of-scope flows may enter the core only through the observe-only lane
(`2026-10-31-macos-ne-observe-only-lane-design.md`), which the operator enables
explicitly, carries no bytes, and is filtered to the operator's own uid." NE-AC3 is
untouched: observed rows reach no module, plugin, guard, or capture-path store.

| Threat | Exposure | Mitigation |
|---|---|---|
| Hostile or buggy provider floods `FlowSeen` | core CPU/memory | mutual peer auth (only our signed sysex can speak); `MAX_FRAME_LEN`; ring/aggregate caps; 5 000/s cap; decode error → detach |
| Same-uid squatter in the 0700 dir | fake rows, scope read | LF's core-verifies-provider check: an unverified peer gets no `Scope`/`Observe` and is not read (LF-AC3); the bus token guards reads |
| Another transparent proxy on the Mac | attribution shows that proxy as source; coverage gaps | documented degradation (research 12 §3.2.7); rows are "as seen"; no NE mitigation |
| pid reuse | wrong process in a popover | pid is display-only; the grouping key is signing id/path; `(pid, pidversion)` left to (b) |
| Stale sysex after upgrade | silent observe-less run | exact version match at `Hello`; capability degraded until `enable()` replaces it |
| Agent exfiltrates the app/destination timeline | privacy | `agent_readable` default off; `Paused` refuses; every `observe.*` call is audited like any command |
| Operator leaves observe on | same-uid app metadata in a user-level process's memory | bounded, in-memory only; state visible in the Capture tab; off clears |

**Fail-open proof obligations** (each has an AC): (1) for a declined flow the NE thread
does no I/O and takes no lock held during I/O; for a claimed flow the pre-existing ≤ 2 s
bound holds, and observation adds at most one in-flight write to it; (2) the writer is the
only sender of `FlowSeen`, under the 2 s timeout; a failure detaches; (3) a never-reading
core stalls at most one in-flight write, then detaches; `handleNewFlow` keeps returning
within its normal bound; (4) nothing is produced or buffered while detached; (5) version
skew is refused at `Hello` and fails open; (6) a `FlowSeen` decode error takes the
existing detach branch; (7) enabling observe changes no `claim()` input and no scope-spec
token.

**Trade-off, stated plainly.** A slow-but-alive core is more likely to hit the 2 s send
timeout under observe load than before (more frames on the same channel); that detaches
the provider and pauses in-scope capture until the ~2 s re-attach. The bounded queue,
per-event frames under 2 KiB, and the kernel socket buffer are the mitigations, and the
research §5 item 7 rate experiment sizes them.

### Apple-approval impact assessment

**Option (a), recommended:** no entitlement value, no `Info.plist`/`NEProviderClasses`
change, no new provider class, no new consent, no portal or profile change. The sysex
`CFBundleVersion` bumps as on every build and is replaced through the normal `enable()`
activation (NE-AC14 reconcile). Signing/notarization are the usual Developer ID release
steps Matt performs in the Terminal panel.

**Option (b), if ever chosen** (research 12 §3.3.5–3.3.6): add
`content-filter-provider-systemextension` to the `networkextension` array in **both**
`apps/mac/Aitmproxy.entitlements` and `apps/mac/Extension/Aitmproxy-Extension.entitlements`;
add `com.apple.networkextension.filter-data` → `FilterDataProvider` to `NEProviderClasses`
(one sysex, one process); the host drives `NEFilterManager` (`filterSockets = true`,
Inspector grade, no `disableEncryptedDNSSettings`); a **third** consent ("filter network
content") fires; whether adding the class re-triggers the sysex approval is **unknown**
(§5 item 16); `notarize-dmg.sh`'s verify step should assert the new value. **Verified: no
portal change and no new profile** (both profiles already allow the value). Still Matt's
identity for every sign.

**Never done by a coder or agent, under either option:** portal edits, profile minting or
regeneration, `codesign`/`notarytool` with Matt's identity, System Settings approval
clicks, `systemextensionsctl`. A plan task needing one is a `[Mac]` task with Matt as actor.

## Acceptance criteria

Tags: **[Rust-sandbox]** `UnixStream::pair()`/in-memory tests; **[Rust-terminal]** real
UDS bind; **[Swift-unit]** `swift test` on the Kit or the extension's pure types;
**[web-unit]** the web app's unit tests (**Architect's call**: an added tag);
**[Mac]** real Mac, Terminal panel, signed and approved extension; **[structural]** a
source tripwire; **[review]** a Stage-6 finding.

1. **OL-AC1 — identity reaches the wire.** `dispatch_captured_flow` of a TCP `FlowOpen
   { source_app: Some("com.example.browser"), .. }` through `CoreIngress` to a recording
   HTTP module stores an `HttpFlow` with `client_conn.process == Some("com.example.browser")`;
   `flow.detail` emits `"process":"com.example.browser"` under `client_conn`; `flow.get`
   and `flow.table` rows carry `"process":"com.example.browser"`; `source_app: None`
   emits `"process":null` in all three. **[Rust-sandbox]**
2. **OL-AC2 — the UIs fill their slot.** `FlowSummary(json:)` with `"process":
   "com.apple.Safari"` gives `row().client?.bundleID == "com.apple.Safari"`, and
   `Session.clients` over two such rows yields one entry with count 2 **[Swift-unit]**;
   web `normalize` of a detail with `client_conn.process == "com.apple.Safari"` gives
   `client.id == "com.apple.Safari"` **[web-unit]**; TUI `Conn::parse` gives
   `process == Some("com.apple.Safari")` **[Rust-sandbox]**.
3. **OL-AC3 — `FlowSeen` round-trips and is metadata-only.** A maximal `FlowSeen`
   (every `Option` populated, 253-byte hostname, 1 024-byte path) sent through
   `ControlChannel::send`/`recv` over a pair decodes equal and `bytes_read` after it is
   **< 2 048**; after 100 such frames `bytes_read < 204 800`. An exhaustive destructure in
   the test proves the struct has no `Vec<u8>`/body field. **[Rust-sandbox]**
4. **OL-AC4 — version skew fails loudly.** `HANDOFF_PROTOCOL_VERSION == 2`;
   `check_hello(Hello { protocol_version: 1 })` is `Err` whose message contains `"1"` and
   `"2"`; the feeder closes that channel and sends no `Scope` and no `Observe` (extends
   LF-AC4) **[Rust-sandbox]**. `HandoffConfig.protocolVersion == 2` and
   `HandoffMessages.hello()` is exactly `{"Hello":{"protocol_version":2}}` **[Swift-unit]**.
5. **OL-AC5 — `Observe` is sent iff enabled.** After a verified `Hello`, with
   `observe.enabled = true` the feeder sends `Scope` then `Observe(ObserveSpec { enabled:
   true })`; with it `false` (default) no `Observe` frame is sent over the whole session.
   **[Rust-sandbox]**
6. **OL-AC6 — the provider emits only what it should.** `decodeCore` of
   `{"Observe":{"enabled":true}}` yields `.observe(true)`. With observe off (default) a
   declined flow enqueues nothing; with observe on a declined same-uid flow enqueues
   exactly one descriptor equal to the flow's fields; a claimed flow, an `isSelf` flow, a
   flow with euid ≠ `coreUID`, and a flow with no audit token each enqueue nothing.
   **[Swift-unit]**
7. **OL-AC7 — non-blocking under a wedged core.** With an `ObserveWriter` whose sink
   never drains, after 10 000 `tryPush` calls the queue holds exactly **2 048** entries,
   `dropped == 7 952`, and the sink recorded zero writes from the pushing thread (these
   three are the pass condition); the total wall-clock time of the 10 000 pushes is
   logged as a measurement and must stay under a generous **1 s** bound. **[Swift-unit]**
8. **OL-AC8 — writer failure detaches; detach clears; a claim never waits unbounded.**
   A failed writer send shuts the control channel (the existing `CoreLink.send` path);
   `detach` empties the queue and resets `observe` to off; no descriptor survives a
   detach. With the writer's in-flight send blocked on a never-draining socket pair, a
   concurrent `claim()` `FlowOpen` send returns within the 2 s `SO_SNDTIMEO` bound
   (failing) and the channel is detached — no unbounded wait on `writeLock`. **[Swift-unit]**
9. **OL-AC9 — `FlowSeen` never touches pairing.** The feeder's control loop, fed one
   `FlowOpen` and ten `FlowSeen`, has `pairing_len == 1` and ten `ObservedFlow`s; other
   variants are still ignored without detaching. **[Rust-sandbox]**
10. **OL-AC10 — the store is bounded.** 100 000 `FlowSeen` with distinct remotes leave
    `events.len() == 20_000`, `aggregate.len() == 10_000`, `dropped_core == 80_000`,
    `aggregate_evicted == 90_000`; the oldest `seen_at_ms` present is the 80 001st's.
    **[Rust-sandbox]**
11. **OL-AC11 — the commands' literal output.** For three events — two `com.apple.Safari`
    → `1.1.1.1:443` Tcp (hostname `example.com`), one `com.apple.curl` →
    `93.184.216.34:80` Tcp (no hostname) — `observe.apps` returns `enabled == true`,
    `apps[0].app == "com.apple.Safari"`, `apps[0].count == 2`,
    `apps[0].destinations[0].remote == "1.1.1.1:443"`,
    `apps[0].destinations[0].hostname == "example.com"`, `apps[1].app == "com.apple.curl"`,
    `apps[1].count == 1`; `observe.events { limit: 2 }` returns two rows, newest first.
    **[Rust-sandbox]**
12. **OL-AC12 — registered iff enabled.** With the default config the registry has no
    `observe.apps`/`observe.events`; with `macos_capture.enabled && observe.enabled` on
    macOS both are present. **[Rust-sandbox]**
13. **OL-AC13 — agent gating.** With `agent_readable = false`, `invoke` from a
    `Frontend::Mcp` host is `Err` containing `"agent_readable"`; from `Operator` and
    `Cli` it is `Ok`; with `agent_readable = true` Mcp is `Ok`;
    `sensitivity() == Sensitivity::Read` for both commands. **[Rust-sandbox]**
14. **OL-AC14 — operator-only on-switch.** `no_agent_path_to_capture_session` extends
    its symbol list with `ObserveStore::` and `build_observe` under the same allow-list
    (`main.rs`, `wire.rs`, `macos_capture/`); a Swift tripwire proves `observe.enabled`
    and the toggle glue have exactly their operator call sites (Capture Settings control
    + menu command), mirroring TG-AC9. **[structural]**
15. **OL-AC15 — config defaults and parse.** `MacosCaptureConfig::default().observe ==
    ObserveConfig { enabled: false, agent_readable: false }`;
    `"macos_capture:\n  enabled: true\n  observe:\n    enabled: true\n"` parses with
    `observe.enabled == true`, `agent_readable == false`; a misspelled key under
    `observe:` is an error. **[Rust-sandbox]**
16. **OL-AC16 — the app emits the gate only when on.** `EmbeddedCoreLaunch.Config(
    captureEnabled: true, observeEnabled: true).yaml()` contains the exact substring
    `"macos_capture:\n  enabled: true\n  observe:\n    enabled: true"`; with
    `observeEnabled: false` no `"observe"`; with `captureEnabled: false` no
    `"macos_capture"` even if `observeEnabled` is true; `observeEnabled` defaults to
    `false`. **[Swift-unit]**
17. **OL-AC17 — Apps page model and look.** `ObservedApps.merge(captured:observed:)`
    groups by app key; an observed destination has `source == .observed`, no flow ids,
    `isInteractive == false`; a captured one lists its flow ids **[Swift-unit]**. The Apps
    page snapshot (light and dark) shows observed rows with the "observed" badge and no
    inspector actions; `tools/grid-lint.sh` and `check-layout.swift` print PASS **[Mac]**.
18. **OL-AC18 — web panel.** Normalizing an `observe.apps` result yields "All apps"
    entries with `observed: true`; the flow list `entries` length is unchanged. **[web-unit]**
19. **OL-AC19 — fail-open end to end with an empty scope.** Real Mac, extension approved,
    scope empty, capture ON, observe ON: within 10 s of `curl https://example.com`
    (HTTP 200) the Apps page lists `com.apple.curl` → `example.com` (or its IP:port)
    count 1 and every other active app with counts; `flow.list` stays empty (no flow
    claimed); Safari browsing is unaffected; with N observed events the feeder's logged
    control `bytes_read` ≤ (`Hello`+`Scope`+`Observe` sizes) + N × 2 048. With observe
    OFF the page shows the explanatory state and `bytes_read` stays at the
    `Hello`+`Scope` size. **[Mac]**
20. **OL-AC20 — wedged core, live.** With observe ON and traffic flowing, `kill -STOP`
    the embedded core: new Safari and `curl` connections keep succeeding with no visible
    delay; the provider logs a detach within ~2 s of its next write; after `kill -CONT` it
    reattaches within ~4 s and observed rows resume. **[Mac]**
21. **OL-AC21 — no persistence, no wire write.** `observe.rs` contains no `std::fs`,
    `tokio::fs`, `.inject(`, or `send_on_wire(` (extends LF-AC13); a fresh
    `ObserveStore` is empty. **[structural]** / **[Rust-sandbox]**
22. **OL-AC22 — gates green.** `cargo fmt --check && cargo clippy --all-targets -- -D
    warnings && cargo test`; `./build.sh`, `swift test`, snapshots and grid checks.
    **[Rust-sandbox]** / **[Mac]**
23. **OL-AC23 — mandatory security review.** A Stage-6 security review confirms
    metadata-only by construction (OL-AC3), operator-only on-switch (OL-AC14), uid filter
    and self-exclusion (OL-AC6), agent gating (OL-AC13), non-blocking emit and
    detach-on-failure (OL-AC7/8/20), exact version match (OL-AC4), no new unauthenticated
    path, and no change to `claim()` inputs or the scope-spec emitter. Findings block the
    merge. **[review]**

## Left to the builder

- `ObserveQueue`/`ObserveWriter` shapes (a `Thread` vs a serial `DispatchQueue`; ring vs
  deque), within "O(1) `tryPush`, no I/O on the NE thread for a declined flow, one
  `FlowSeen` sender, 2 s send timeout, clear on detach".
- The writer **may** take `writeLock` with a `try`/re-queue, or yield to a pending
  `claim()` send, if that keeps the ≤ 2 s claim-path bound (Part 3); builder's choice.
- Whether `coreUID` comes from the control peer's audit token at `serve` or one
  `LOCAL_PEERCRED` read; a missing value disables observation either way.
- Aggregate eviction and rate-cap window details; exact error strings and log lines (the
  `check_hello` message must contain both version numbers).
- Display-name resolution in the mac app (`NSWorkspace` by bundle id; last path component
  for `is_path` rows), SF Symbols, badge styling, popover layout, menu placement and
  shortcut; the web panel layout and polling hook.
- Test plumbing for `Frontend::Mcp` vs `Operator` hosts (reuse the `L4AgentGate` tests);
  whether `FlowSummary` stores `process` or only threads it through `row()`.

## Open questions

Only Matt can answer these; each carries the Architect's recommendation.

1. **(a) now, wire shaped for (b) — confirm the fork.** Recommend Candidate 2 as designed.
   (b) in v1 means a third consent, an unknown fail-open posture on provider death,
   filter-plus-proxy field regressions, and a de-duplication design (research 12 §3.3.4,
   §3.3.7, §4.2).
2. **Are bytes and duration required in v1?** Recommend **no**. If yes, (b) is the only
   route; (a) cannot provide them (research 12 §3.2.2).
3. **May agents read observed rows?** Recommend **not by default**: `observe.*` is `Read`
   but refused for `Frontend::Mcp` unless `macos_capture.observe.agent_readable` is set in
   the config file (no app control in v1).
4. **Whose flows appear?** Recommend **same-uid only, self excluded**: other users' apps
   and root daemons are not observed; `aitm`/obscura never are. To list root daemons the
   rule becomes `euid ∈ {coreUID, 0}`, a one-line change with a privacy note.
5. **Is a third consent prompt acceptable?** Only relevant to (b); recommend deferring
   until bytes are required.
6. **Run the research §5 experiments before the plan?** Recommend **items 6 and 8** (a
   one-day field survey of the §3.2.1 fields; UDP `return false` on macOS 27 with
   DNS/QUIC/Chromium) as one throwaway `experiment/macos-ne-observe-survey` session before
   Stage 3: they size the queue and settle the UDP unknown the shipped provider already
   carries. Defer 7 and 9; defer the (b) items 10–17 entirely.
7. **Approve the parent-spec wording amendment** (§Security analysis) so the anti-goal
   reads as flow bytes and names this lane as the sanctioned metadata path.
8. **Hostnames: connect-by-name only, else IP:port, no reverse DNS?** Recommend yes
   (Little Snitch calls reverse DNS "of little use"; it would also originate DNS traffic
   from the core).

---

**Summary.** Build the observe-only lane as option (a): the existing transparent-proxy
provider emits a metadata-only `FlowSeen` (app, remote, hostname when connect-by-name,
TCP|UDP, pid/uid, time) for each flow it declines, from a bounded drop-oldest queue
drained by one writer thread so `handleNewFlow` never blocks and a wedged core detaches
and fails open; the core answers with an `Observe` switch, bumps the handoff protocol to
version 2 with exact matching, keeps rows in a separate bounded `ObserveStore` in the
`aitm` wiring layer behind two `Read` commands (`observe.apps`, `observe.events`) an
agent cannot call unless `agent_readable` is set, and ships the F5 core half so claimed
flows carry their source app too. The switch is config-file-only plus a second toggle on
the Capture Settings tab, default off, same-uid only, self excluded, nothing on disk. The
Apps page, web sidebar, and TUI `process` column fill; observed rows never look like
captured flows. No entitlement, plist, profile, or prompt changes; option (b) is assessed
and left for when bytes are required.

**Architect's calls (approve or correct):**

- **C1:** Option (a) first, wire and store shaped for (b) (Candidate 2); (c) rejected.
- **C2:** Part 1 (identity on claimed flows, the F5 core half) is in scope and may edit
  `aitm-core` (`ConnInfo.process`, `ModuleCtx.peer_identity`).
- **C3:** `FlowSeen` fields as tabled; `source_path` only when the signing id is empty,
  capped at 1 024 bytes; pid display-only; cumulative `dropped`; `bytes_*`/`closed_at_ms`
  reserved, not present, until (b).
- **C4:** Protocol version 2 with **exact** `Hello` matching, not `{1, 2}`.
- **C5:** Provider: enqueue-only `tryPush`, capacity 2 048, drop-oldest, one writer thread
  over `CoreLink.send`, per-event frames, nothing kept while detached.
- **C6:** Same-uid filter via the core peer's euid; root daemons, other users, and self
  excluded; the claim path's OQ10 not retro-fitted here.
- **C7:** `ObserveStore` in `crates/aitm/src/macos_capture/observe.rs`: 20 000 events,
  10 000 aggregate keys, 5 000/s soft cap, no disk.
- **C8:** `observe.apps` and `observe.events`, `Sensitivity::Read`, wrapped in an
  `L4AgentGate`-style `ObserveAgentGate` on `macos_capture.observe.agent_readable`
  (default false); registered iff capture and observe are enabled.
- **C9:** `agent_readable` has no app control in v1 (config file only).
- **C10:** UIs poll; no `flow.subscribe` push; no TUI observe view; a `[web-unit]` tag.
- **C11:** The parent-spec reconciling wording proposed in §Security analysis.
