# macOS observe-only lane: every app's connections in the Apps page without claiming out-of-scope flows (NE capture input)

> **Provenance:** AI-generated research summary produced by the Researcher
> engine on **2026-10-31**. Sources: the Xcode 27.1 MacOSX SDK headers on the
> author's Mac (macOS 27.0, build 26A428), Apple developer documentation and
> DevForums threads, Little Snitch / LuLu / Proxyman / mitmproxy public docs and
> source, the two A1 Developer ID provisioning profiles on this Mac, and the
> aitmproxy tree at `a248897` (this worktree).
> **Method caveat:** every web page below was read through the WebFetch or
> WebSearch tools, which summarise the page with a small model; quotes are as the
> summariser returned them. Apple's `developer.apple.com/documentation` pages are
> JavaScript-rendered, so they were read through the site's
> `tutorials/data/...json` endpoint. Markers: **(header)** first-hand in the SDK
> on this Mac; **(tree)** first-hand in this repo; **(local)** a read-only check
> on this Mac; **(W)** a web page read through WebFetch (summariser quote);
> **(S)** a search-result summary only; **(3P)** a third-party report (GitHub
> issue, forum poster, vendor docs), not an Apple statement. Anything marked
> **unverified** was not seen in a source. No fetched page carried instructions
> aimed at this task.
> **Sandbox limits on this run:** `log show`, `netstat -s`, `systemextensionsctl
> list` and `curl` to `raw.githubusercontent.com` were refused, so **no live
> new-flow rate was measured** (3.2.5 is an estimate) and LuLu's source was read
> through WebFetch, not cloned.
> **Tree caveat:** this worktree is at `a248897`. `origin/main` has since gained
> #180, and PR #181 (`fix/ne-no-scope-hint`, not an ancestor of `origin/main` in
> the local refs) rewrites the Apps-page placeholder in `ShellView.swift`; the
> `ShellView` cites below are to `a248897`.
> **Scope:** tooling-architecture research for an operator with written
> authorization to test in-scope targets. Nothing here is a design decision.

## 1. Question

How can the macOS capture extension show every app's connections (app,
destination host or IP:port, protocol, connection counts, ideally bytes) in the
Apps page, Proxyman or Little Snitch "Network Monitor" style, without claiming or
MITM-ing out-of-scope flows, and what does each of three options (metadata-only
`FlowSeen` from the transparent proxy, an `NEFilterDataProvider`, claim-and-relay
everything) cost?

## 2. Short answer

Yes, without claiming flows. (a) A metadata-only `FlowSeen` from the existing
transparent proxy gives app (signing id plus audit token), remote IP:port,
hostname only for connect-by-name flows, TCP or UDP, and counts; never bytes,
duration or close. It needs no new prompt, entitlement or profile, but must be
queued off `handleNewFlow`. (b) An `NEFilterDataProvider` in the same sysex adds
bytes, duration and ICMP; the existing profiles already allow it; cost is one
more prompt and a verdict in every app's connection path. (c) breaks fail-open
and today's ingress. Today no source app reaches any UI.

## 3. Findings

All sources read 2026-10-31 unless dated otherwise. "Inference" marks my reading,
not a source claim.

### 3.0 Facts the Architect should not trip over

| # | Fact | Source |
|---|---|---|
| 1 | The Apps page is empty live for a reason that no extension option fixes: the source-app identity is **dropped inside the core**, the wire emits `"process": null`, and the macOS UI has nowhere to decode one (3.1). | tree |
| 2 | On macOS, `NEFilterFlow.sourceAppIdentifier`, `sourceAppUniqueIdentifier` and `sourceAppVersion` are **`API_UNAVAILABLE(macos)`**. The filter's macOS identity fields are `sourceAppAuditToken` (10.15), `sourceProcessAuditToken` (13.0) and `identifier` (10.15). | header |
| 3 | mitmproxy's local mode with **no argument captures everything** on the machine; the narrowing (`local:curl`) is optional. So "mitmproxy claims only matched flows" is true only when the user narrows it. What they share is that capture is **operator-started**, not that they claim a subset: mitmproxy's extension returns `false` when it has no spec (note 10, 3.3); Proxyman's is an off-by-default Settings toggle (note 10, 3.1). | W: docs.mitmproxy.org/stable/concepts/modes/, mitmproxy.org/posts/local-capture/macos/ |
| 4 | Proxyman's Network Extension docs describe **HTTP and HTTPS from every app** only ("Capturing HTTP and HTTPS from local applications"); they say nothing about non-HTTP TCP/UDP, a network-monitor view, or bytes. Its app grouping is a display filter over captured HTTP flows. | W: proxyman.com/docs/advanced-features/network-extension, proxyman.com/posts/2026-10-06-introducing-network-extension |
| 5 | Both A1 Developer ID profiles **already allow `content-filter-provider-systemextension`** (and `dns-proxy-systemextension`, `packet-tunnel-provider-systemextension`, `relay`, `url-filter-provider`, `hotspot-provider`, `dns-settings`). No portal work or profile regeneration is needed for option (b). | local (3.3.5) |
| 6 | The two macOS-15 flow methods the shipped provider uses have **inconsistent header text about `return false`** (3.2.2): the macOS-15 UDP delegate says "the flow is terminated" with no transparent-proxy caveat. | header |
| 7 | One sysex can host both providers in **one process**; Apple's own header example shows both classes in one `NEProviderClasses`. | header; W: DTS thread 800887 |

### 3.1 What the tree does today (tree, read 2026-10-31 at `a248897`)

**Provider (Swift, in the root sysex).**

- One catch-all outbound rule, protocol `.any` (TCP and UDP), remote and local
  `nil`, prefix 0 (`apps/mac/Extension/Sources/TransparentProxyProvider.swift`
  lines 40-55). `Info.plist` `NEProviderClasses` has only
  `com.apple.networkextension.app-proxy` (`apps/mac/Extension/Info.plist`).
- `handleNewFlow` (line 74) and `handleNewUDPFlow(_:initialRemoteFlowEndpoint:)`
  (lines 81-85) first run `SelfExclusion.isSelf(sourceAppAuditToken:)`, then hand
  the flow to `FlowHandoff.handleTCP/handleUDP`. **`isSelf` is a Security.framework
  check, `SecCodeCopyGuestWithAttributes` plus `SecCodeCheckValidity`
  (`FlowHandoff.swift` 120-137, 181-186), and it runs for every new flow,
  claimed or not.** Its cost is not measured here (3.2.4).
- `FlowHandoff.claim` (1259-1295): reads `link.current()` (nil when detached,
  then `false`), applies `ScopeMatcher.matches(hostname:ip:port:)` (500-585; an
  empty spec matches nothing), and only then dials the per-flow data socket,
  verifies its peer, sends `FlowOpen` and the handshake. Fields read:
  `flow.remoteFlowEndpoint` (TCP, line 1301), the `initialRemote` endpoint and
  `flow.localFlowEndpoint` (UDP, 1320-1324), `flow.remoteHostname`,
  `flow.metaData.sourceAppSigningIdentifier` (1304, 1323), and
  `sourceAppAuditToken` (only inside `isSelf`). **Not read anywhere:**
  `networkInterface`, `isBound`, `sourceAppUniqueIdentifier`,
  `filterFlowIdentifier`, and the audit token's pid, uid or path (`grep` for
  `euid|ruid|audit_token_to` in `apps/mac/Extension/Sources` returns nothing, so
  spec decision OQ10 "filter by audit-token UID" is not implemented in the
  provider).
- `FlowOpenMessage` (210-218) carries `flow_id, kind, remote, remote_hostname,
  source_app, local`; `source_app` is the **signing identifier string only**.
- `CoreLink.send` (720-731) takes `writeLock` and does a **blocking** `write` on
  the control fd; `serve` sets `SO_SNDTIMEO` to
  `handshakeSendTimeoutSeconds = 2` on that fd (743; constant at line 73, whose
  comment reads "A wedged (alive but not reading) core must not stall
  `handleNewFlow`"). `claim` calls it, so a claimed flow can block
  `handleNewFlow` up to 2 s per blocking call, serialised on `writeLock`.
  Declined flows never reach it today.

**Core (Rust).**

- `ControlMessage = Hello | Scope | FlowOpen`
  (`crates/aitm/src/macos_capture/listener.rs:125-132`); `FlowOpen` fields at
  listener.rs 103-121. Decoding is `serde_json::from_slice` into that enum
  (listener.rs 386-392), so an **unknown variant is a decode error**
  (`InvalidData`). In `feeder.rs` the control read loop (lines 463-476) acts only
  on `FlowOpen`, ignores the other two known variants (`debug!`), and on any
  `Err` logs "capture control read failed; detaching the provider" and ends the
  attachment. Consequence: a provider that sends a new variant to a core that
  lacks it detaches itself on its first send (version-skew fact for any new
  message).
- **The source-app identity is dropped at the ingress. Verified.**
  `CapturedTcpFlow.peer_identity` and `CapturedUdpFlow.peer_identity` exist
  (`crates/aitm/src/ingress.rs:67,96`) and the adapter fills them from
  `open.source_app` (`adapter.rs:182,201`). `dispatch_tcp` (ingress.rs ~176-230)
  reads `flow.sni`, `flow.dst` and `flow.first_bytes`, builds a `NextLayerHint`
  and a `ModuleCtx` from `store`, `sink`, `connector`, `modules` and the hint,
  and **never reads `peer_identity`**. Across `crates/`, the only read of
  `.peer_identity` is a unit-test assertion at `adapter.rs:392`, inside
  `#[cfg(test)]` (begins `adapter.rs:289`). `ModuleCtx`
  (`aitm-core/src/protocol.rs:74-86`) has no identity field; `ConnInfo`
  (`aitm-core/src/flow.rs:194-200`: `peer, sni, alpn, tls, established`) and
  `FlowMeta` (204-217) have no app or process field.
- The wire already advertises the gap: `flow.get`'s connection object emits
  `"process": null`, with a comment "Peer->process (the Client column) is
  deferred (foundation Q6): a stable null until core resolves the owning
  process" (`crates/aitm-plugins/src/detail.rs:307-318`).
- Today's stores: `Flow` is a **closed enum** `Http | WebSocket`
  (`aitm-core/src/flow.rs:58-61`); `flow.get`'s `summarize` matches only those
  (`aitm-plugins/src/capture.rs:180-215`). `L4Flow` is the only non-HTTP store
  and is packet-shaped: `kind: Capture | Craft | SendRecv | Intercept`,
  `packets: VecDeque<L4Packet>` with raw on-wire bytes, `bind: L4Bind {interface,
  filter, queue}` (`aitm-proto-l4/src/flow.rs:34-111`). Neither fits "an app
  connected to host:port, N times".
- `MemFlowStore` holds `DEFAULT_MAX_FLOWS = 50_000` and 512 MiB, FIFO eviction
  (`aitm-core/src/store.rs:86-95`), so observe-only rows sharing it would evict
  real captured flows.

**What an agent (`Frontend::Mcp`) can read today.** `flow.list`
(`aitm-plugins/src/capture.rs:42-66`), `flow.get`, `flow.table` (capture.rs
223-255), `flow.subscribe` (`aitm-plugins/src/subscription.rs:65-76`) and
`l4.flow.list/get` (`aitm-proto-l4/src/commands/flow.rs:17-80`) are all
`Sensitivity::Read`. `policy_decision` (`aitm-mcp/src/server.rs:2010-2050`)
gates **per command, not per row**: `Read` is allowed under `All`, `Auto`, `Ask`
and `ReadOnly`; only `Paused` refuses (also `agent_reads_allowed`, 2525-2530, for
subscriptions). `FlowList::invoke` returns `host.store().list()` with no filter;
the only hidden rows are those captured while the store's record toggle is
paused (`store.rs:104-108`). **There is no per-row visibility gating**, so any
row put in a store behind a `Read` command is readable by an agent in every
non-Paused posture. A new command defaults to `Sensitivity::Sensitive`
(`command.rs:44-77`), which `Auto` refuses, `Ask` parks, and `All` allows only if
it is listed in `defers_to_command_gate` (server.rs:2484-2500).

**UIs.**

- macOS: `Session.clients` is derived from `row.client` (`Session.swift:429`);
  `ClientInfo` is constructed only in `Fixtures.swift:7-11` (grep of
  `AitmproxyKit` and `Aitmproxy` finds no live construction); `FlowSummary`
  has no client field and its header says "no ... client. Everything else on a
  row waits for F5" (`FlowSummary.swift:4-5`); `Flow.swift:106` says "F5 resolves
  peer -> process in the core". At `a248897`, `ShellView.swift:201-204` swaps the
  **whole table** for `AppsNeedsExtension` when `session.clients.isEmpty`
  (struct at 332-345), which is always, live (PR #181's branch changes this to a
  banner over the table; the underlying emptiness is unchanged).
- Web: a sidebar "apps" grouping exists (`apps/web/src/state/app.ts:1077-1092`,
  keyed on `f.client.id`), fed by `clientOf` in `apps/web/src/bus/normalize.ts:
  108-120`, which reads `client_conn.process` (the `null` above) and falls back to
  `id: 'unknown'`.
- TUI: `crates/aitm-tui/src/model.rs:395-405` reads `process` into its
  connection model; there is no per-app grouping.

Net: three UIs have a per-app slot and the core feeds them `null`. Any option
below still needs the core to carry identity onto rows for **claimed** flows
(F5). The observe lane only adds rows for flows nobody claimed.

### 3.2 Option (a): metadata-only `FlowSeen` for flows the provider does not claim

#### 3.2.1 What NE exposes at `handleNewFlow` / `handleNewUDPFlow`, before `open()` (header)

Read first-hand from the Xcode 27.1 MacOSX SDK, `NetworkExtension.framework/Headers`.
No `open()` is needed to read any of these; the shipped provider already reads
them on declined flows.

| Property | Declared on | Availability macro (verbatim) | Notes (quoted or paraphrased from the header) |
|---|---|---|---|
| `remoteFlowEndpoint` | `NEAppProxyTCPFlow` | `API_AVAILABLE(macos(15.0), ios(18.0), visionos(2.0))` | "the intended remote endpoint of the flow"; old `remoteEndpoint` is `API_DEPRECATED_WITH_REPLACEMENT(..., macos(10.11, 15.0))` |
| `initialRemoteFlowEndpoint` (method parameter) | `handleNewUDPFlow:initialRemoteFlowEndpoint:` | `API_AVAILABLE(macos(15.0), ...)` | "The initial remote endpoint provided by the proxied app when the flow was opened". One endpoint: later datagrams to other destinations on the same UDP flow are not visible to a declined flow (inference from the API shape) |
| `localFlowEndpoint` | `NEAppProxyUDPFlow` **only** | `API_AVAILABLE(macos(15.0), ...)`, `nullable` | "the local endpoint of the flow's corresponding socket". **No TCP equivalent** exists on `NEAppProxyTCPFlow` |
| `remoteHostname` | `NEAppProxyFlow` | `API_AVAILABLE(macos(11.0), ios(14.2))`, `nullable` | "If the flow was created by passing a hostname to a 'connect by name' API such as NSURLSession or Network.framework, this property is set". A self-resolving client (Chromium-style) yields IP only |
| `networkInterface` | `NEAppProxyFlow` | `API_AVAILABLE(macos(10.15.4), ios(13.4))`, read-write `nullable nw_interface_t` | "information about the network interface used by the flow" |
| `isBound` | `NEAppProxyFlow` | `API_AVAILABLE(macos(11.1), ios(14.3))` | "YES if the flow was bound by the application to a specific interface" |
| `metaData.sourceAppSigningIdentifier` | `NEFlowMetaData` | `API_AVAILABLE(macos(10.11), ...)`, non-null `NSString` | "(almost always equivalent to the bundle identifier) ... may be empty in cases where the flow originates from a system process" |
| `metaData.sourceAppUniqueIdentifier` | `NEFlowMetaData` | `API_AVAILABLE(macos(10.11), ...)` | "uniquely identifies the binary for each build ... may be empty ... system process" |
| `metaData.sourceAppAuditToken` | `NEFlowMetaData` | `API_AVAILABLE(macos(10.15))`, `nullable NSData` | "Audit token of the source application of the flow." |
| `metaData.filterFlowIdentifier` | `NEFlowMetaData` | `API_AVAILABLE(macos(10.15.4))`, `nullable NSUUID` | "The identifier of the content filter flow corresponding to this flow." |

Protocol is the delegate that fired (`handleNewFlow` with an `NEAppProxyTCPFlow`
vs `handleNewUDPFlow`), and the rule's protocol is TCP, UDP or any only (note
10, 3.2). `NEFlowMetaData` has **no** `sourceProcessAuditToken`; only the filter
side has that (3.3.1). Whether `sourceAppAuditToken` is non-nil for every flow,
including system-process flows, is **unverified**; the spike (below) and the
shipped provider rely on it being present for user apps.

Existing first-hand evidence that this metadata is readable on declined flows:
the Task-1 spike's provider returned `false` for every flow and still reported
`FLOW remote=example.com sourceApp=com.apple.curl`, `alive.github.com ...
com.apple.Safari`, `github.com ... com.apple.git-remote-http`, and
`sourceAppSigningIdentifier` populated for `aitm-7728c895773169c7` and
`com.openai.codex.helper` (`docs/research/experiments/2026-10-29-macos-ne-spike.md`,
tree).

#### 3.2.2 What is not available (header, read in full)

- `NEAppProxyFlow.h`, `NEAppProxyTCPFlow.h`, `NEAppProxyUDPFlow.h` expose **no
  byte count, no duration, no state, no close or error callback**. The only
  members are `open...`, `closeRead/WriteWithError`, `setMetadata:`, `metaData`,
  `networkInterface`, `remoteHostname`, `isBound` (base), the read/write calls and
  the endpoint properties above.
- `handleNewFlow:` returns `BOOL`; `NEAppProxyProvider.h:60`: "NO if the proxy
  implementation has not retained the flow and will not handle the flow data. In
  NETransparentProxyProvider sub-classes returning NO causes the flow to be
  handled by the networking stack without any proxy." After `false`, no API in
  `NEAppProxyProvider.h` or `NETransparentProxyProvider.h` delivers a later
  callback for that flow. So a declined flow gives **no success or failure signal,
  no bytes, no close** (absence in the two provider headers, which I read in full).
  A `FlowSeen` row can therefore only say "this app tried to reach this endpoint
  at this time", never "and it connected / and it moved N bytes".
- **Header inconsistency on `false` for UDP.** `NETransparentProxyProvider.h:23`
  and the deprecated `handleNewUDPFlow:initialRemoteEndpoint:`
  (`NEAppProxyProvider.h:87`) say returning NO sends the flow direct. The
  macOS-15 method the shipped provider overrides,
  `handleNewUDPFlow:initialRemoteFlowEndpoint:` (`NEAppProxyProvider.h:74`), says
  only "NO if the proxy implementation has not retained the flow and will not
  handle the flow data. In this case the flow is terminated" with no transparent
  proxy caveat. Probably a doc omission (the class doc covers it), but UDP
  `false` on macOS 27 was not exercised by the TCP-only spike and is
  **unverified**. It is the same exposure the shipped provider already has, not
  one (a) adds.
- Apple's "Handling Flow Copying" article (W) says "To let the operating system
  handle the flow, return false for NETransparentProxyProvider" and gives
  flow-control guidance only (write before the next read; bound buffers to avoid
  a jetsam event). It has **no guidance on `handleNewFlow` latency or blocking**.
  Across DevForums threads 700065, 716594, 761134, 770707, 667962 and 677357
  (all (W)) I found **no Apple statement** on how long `handleNewFlow` may take or
  on which queue it runs. The tree's own precedent is the "wedged core must not
  stall `handleNewFlow`" comment (3.1).

#### 3.2.3 Resolving the audit token (header)

| Need | API | Header evidence |
|---|---|---|
| pid, euid, ruid, process-id version | `audit_token_to_pid`, `audit_token_to_euid`, `audit_token_to_ruid`, `audit_token_to_pidversion` | `usr/include/bsm/libbsm.h:1423-1425, 1492, 1520, 1548, 1566`, `API_AVAILABLE(macos(10.8))` for the last. The header says `audit_token_to_au32` is deprecated and these calls "should be used instead" |
| executable path | `proc_pidpath_audittoken(audit_token_t*, buf, size)` | `usr/include/libproc.h:103`, `API_AVAILABLE(macos(11.0))`; `proc_pidpath(pid, ...)` at :102 |
| bundle or code path, signing info | `SecCodeCopyGuestWithAttributes(... kSecGuestAttributeAudit ...)` then `SecCodeCopyPath` | `Security.framework/Headers/SecCode.h:127,189,289-303`. Already used in the tree for `PeerAuth.verifyPeer(auditToken:)` (`FlowHandoff.swift:120-137`) |

- **pid reuse:** the audit token carries the process-id version, so
  `(pid, pidversion)` is a stable process key (inference from the header's
  description of `audit_token_to_pidversion`: "identify Mach tasks and senders of
  Mach messages").
- **Multi-user:** the sysex is root and global; `audit_token_to_euid/ruid` give the
  flow's user. Spec decision OQ10 (`2026-10-29-...-design.md:538, 597`) says "filter
  by audit-token UID to the approving user"; the provider reads no UID today
  (3.1). Observe-only rows from other users' apps are a **privacy** matter beyond
  bytes (the same applies to option (b)).
- **Display name** (not an NE field): the path from `proc_pidpath_audittoken`, or
  the bundle from `SecCodeCopyPath`, then `Bundle`-style lookup, is the usual
  route; helper processes (a Safari WebKit network process) report their own
  signing id. Little Snitch 6.2.1 attributes helper processes in an app bundle to
  the parent app (**(S)**, search summary of its release notes). The audit-token
  resolution cost of each API is **unmeasured** here.

#### 3.2.4 Per-flow cost and the backpressure problem

- Today every new flow already pays one `SecCodeCopyGuestWithAttributes` +
  `SecCodeCheckValidity` in `isSelf` (3.1). Little Snitch's docs warn the
  code-signature check "may take a while for large bundles such as Xcode" (W:
  help.obdev.at/littlesnitch6/lsm-inspector). Whether Security.framework caches
  per process is **unverified**. `proc_pidpath_audittoken` and the
  `audit_token_to_*` calls are plain syscalls or integer extraction (inference:
  no IPC is documented in the headers); they would add little next to `isSelf`.
- `handleNewFlow` must return `Bool`; there is no async completion form
  (`NEAppProxyProvider.h:62`). A `FlowSeen` emitted from inside it must therefore
  be **enqueue-only**: a bounded in-memory queue drained by a dedicated writer
  thread, dropping the oldest on overflow. Calling `CoreLink.send` directly would
  put the 2 s blocking write and the `writeLock` in every flow's path (3.1); with
  a wedged core the whole Mac's new connections would queue behind the lock. That
  is the same failure class as the spec anti-goal "A provider that breaks the user's
  network when the core is gone" (spec line 99; a wedged core is the alive-but-not-
  reading case the tree's own 2 s comment names). Reader-side precedent in the tree:
  bounded pairing maps (`feeder.rs:65` `DEFAULT_PENDING_CAP = 1024`, TTL 30 s at
  :71) and `MAX_FRAME_LEN = 1 MiB` (`listener.rs:58`).
- Detached core: `link.current()` is nil, so the provider has nowhere to send;
  whether to buffer a short history in a root process is a privacy call (a root
  sysex holding all apps' connection history), not a mechanical one.
- Wire size: a JSON `FlowSeen` is on the order of 150-250 bytes (estimate from
  `FlowOpen`'s fields); at a few hundred events per second that is well under 1
  MiB/s on a Unix socket. The load that matters is **per-event Swift allocation
  and one JSON encode per flow**, and the core's per-frame `serde_json` decode.
  Provider-side aggregation (per app + remote + protocol, flushed on a timer) is a
  way to cut both; it loses per-flow timestamps (a design trade-off, 4.1).

#### 3.2.5 New-flow rates (estimate, no source)

I found **no published figure** for new connections per second on a desktop Mac,
and the sandbox refused the local counters (`netstat -s -p tcp`, `log show`).
Order-of-magnitude estimate, clearly labelled as such: sustained single digits to
low tens per second on an idle-to-busy desktop, with bursts of tens to a few
hundred per second when a browser loads a page (many connections plus QUIC UDP
flows plus DNS UDP flows from `mDNSResponder`) or a sync client starts. Measurement
suggestions are in section 5, item 7. The 2026-10-31 diagnosis (auto-memory entry
`aitmproxy-ne-live-capture-diagnosis`, not re-observed here) reports per-flow
"provider rejected new flow" log lines under process `AitmproxyNE`; `grep` finds no
such string in the tree's Swift sources, so they are presumably the NE framework's
own. Counting them per hour is a cheap rate source.

#### 3.2.6 Wire compatibility and where rows land

- A new `ControlMessage` variant is a **protocol-version fact**: the shipped
  core detaches the provider on an unknown variant (3.1). `Hello.protocol_version`
  is checked by `recv_hello` and refused on mismatch (`adapter.rs`), so a bump
  makes skew fail loudly; the sysex is replaced only on a higher version (note 10,
  3.5). Both halves ship in one DMG, so skew is limited to a stale activated
  sysex against a newer core, or the reverse.
- `FlowSeen` has **no data socket and no pairing**: it does not use the
  1024-entry pairing maps and is not a `FlowOpen`. It is a one-way event.
- No existing store fits (3.1). Candidates for the Architect: a new bounded ring
  in the `aitm` wiring layer behind its own command(s), versus synthesising an
  `L4Flow` (wrong shape, carries packets) or an HTTP `Flow` (wrong). Whichever,
  the **agent-visibility gate is new work** (3.1, no per-row gating exists).
- The spec text to reconcile: D2 says "Out-of-scope flows are not captured at all
  ... we never even receive out-of-scope bytes (a privacy win)" (spec line
  229-231) and the anti-goal reads "A provider that captures out-of-scope or
  non-consented traffic into the core" (line 93). `FlowSeen` sends out-of-scope
  **metadata** and no bytes; the literal D2 wording is about bytes, the anti-goal
  wording is about "traffic". Reading is for the Architect and Matt.

#### 3.2.7 Field risks specific to (a)

- Another transparent proxy on the Mac changes what aitm sees (thread 677357, (W)).
  A poster reports that with several transparent proxies enabled only one handles a
  given flow, in an order that depends on install order; DTS (Matt Eaton): control
  over the order, "No, not that I am aware of", and in his test one proxy claimed a
  Safari flow while the second saw it, did not claim it, and the OS handled it. The
  poster found that as the **second** proxy `flow.metadata` reflected the first
  proxy's process, not the browser, and DTS said "You may be running into a
  limitation here or a bug". So (a)'s app attribution and coverage
  are degraded on a Mac that also runs Proxyman's extension or mitmproxy local
  capture (inference for aitm; (3P)/DTS for the behaviour).
- `return false` is not always clean (thread 716594, DTS Quinn Oct 2022, (W)): a
  VPN client's TCP flow failed after `false`; DTS: "if you do the second and that
  causes the flow's originating process to fail, there's not much you can do".
  Same exposure the shipped provider already has; (a) adds none.
- Chromium UDP under a rule: thread 770707 (W), still open: a poster reports
  `setsockopt(IP_DONTFRAG)` returns `ECONNRESET` on a UDP socket connected to a
  destination covered by the proxy's rules "whenever the transparent proxy is
  active", reproducible on macOS 26 and 27, Chromium QUIC fails with
  `NEAppProxyFlowErrorDomain` code 2. Whether this also applies when the
  provider returns `false` is not stated. The shipped provider's catch-all rule
  already covers UDP, so this is an existing, unmeasured exposure (section 5, item 8).

### 3.3 Option (b): an `NEFilterDataProvider` alongside the transparent proxy (Little Snitch / LuLu model)

#### 3.3.1 What the filter sees (header)

`NEFilterDataProvider.handleNewFlow:` returns an `NEFilterNewFlowVerdict`
(`NEFilterDataProvider.h:53`); there is no async completion form other than
`pauseVerdict` plus `resumeFlow:withVerdict:` (lines 115-123, 198; "UDP flows will
be dropped if not resumed within 10 seconds"). The flow object is an
`NEFilterSocketFlow` (`NEFilterFlow.h`):

| Property | Availability macro (verbatim) | Notes |
|---|---|---|
| `NEFilterFlow.sourceAppAuditToken` | `API_AVAILABLE(macos(10.15))`, `nullable NSData` | "Audit token of the source application of the flow." |
| `NEFilterFlow.sourceProcessAuditToken` | `API_AVAILABLE(macos(13.0))`, `nullable` | "the process that created the flow. In cases where the connection was created by a system process on behalf of the source application, sourceProcessAuditToken will be different from sourceAppAuditToken". **The transparent proxy's `NEFlowMetaData` has no equivalent** |
| `NEFilterFlow.identifier` | `API_AVAILABLE(macos(10.15), ios(13.1))` | "The unique identifier of the flow." (`NSUUID`) |
| `NEFilterFlow.direction` | `API_AVAILABLE(macos(10.15), ios(13.0))` | "Initial direction of the flow (outgoing or incoming flow)": the filter also sees **inbound** flows |
| `NEFilterFlow.URL` | `API_AVAILABLE(macos(10.15), ios(9.0))` | nil unless the flow came from WebKit |
| `NEFilterFlow.sourceAppUniqueIdentifier / sourceAppIdentifier / sourceAppVersion` | `API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, ...)` | **unavailable on macOS** |
| `NEFilterSocketFlow.remoteFlowEndpoint` | `API_AVAILABLE(macos(15.0), ...)`, `nullable nw_endpoint_t` | "may be nil when [NEFilterDataProvider handleNewFlow:] is invoked and if so will be populated upon receiving network data" |
| `NEFilterSocketFlow.localFlowEndpoint` | `API_AVAILABLE(macos(15.0), ...)`, `nullable` | same caveat |
| `NEFilterSocketFlow.remoteHostname` | `API_AVAILABLE(macos(11.0), ios(14.0))` | "only non-nil if the flow was created using Network.framework or NSURLSession" |
| `NEFilterSocketFlow.socketFamily / socketType / socketProtocol` | `API_AVAILABLE(macos(10.15), ...)` | e.g. `PF_INET`, `SOCK_STREAM`, `IPPROTO_TCP` |

Two differences from the transparent proxy: (i) the **remote endpoint may be
absent at `handleNewFlow`** (notably unconnected UDP) and only fills in later, so
a row built at new-flow time can lack the IP:port the proxy's
`initialRemoteFlowEndpoint` gives immediately; the `NEFilterReport.flow` at close
carries the populated flow; (ii) the filter distinguishes the **app** from the
**creating system process** (`sourceProcessAuditToken`).

**ICMP and other IP protocols.** WWDC25 session 234 (W, transcript as returned):
"NEFilterDataProvider provides you with TCP and UDP flows, as well as other IP
protocol traffic, such as ICMP." The header corroborates non-TCP/UDP flows
exist: for them "readBytes includes a 4-bytes NEFilterDataAttribute field"
(`NEFilterDataProvider.h:60,70`; `NEFilterDataAttributeHasIPHeader`,
`API_AVAILABLE(macos(10.15.5))`, line 37). What an ICMP flow looks like in
`NEFilterSocketFlow` (endpoint, app, whether `ping` appears at all) is
**unverified**. WWDC19 session 714 (W) described coverage in TCP and UDP terms
only, so the ICMP claim rests on the 2025 session.

#### 3.3.2 Verdicts, reports, bytes and duration (header, Apple forums)

- `NEFilterDataVerdict.allowVerdict` and `NEFilterNewFlowVerdict.allowVerdict`
  exist on macOS (`API_AVAILABLE(macos(10.15))`; `NEFilterProvider.h:165`,
  `NEFilterDataProvider.h:157`). `needRulesVerdict` is `API_UNAVAILABLE(macos)`.
- **Reports are requested on the verdict but delivered separately.** `NEFilterVerdict.shouldReport`
  (`API_AVAILABLE(... macos(10.15))`, `NEFilterProvider.h:119-130`): "Whether or
  not to send a report to the control provider's -[NEFilterProvider handleReport:]
  method when processing this verdict and when the flow is closed ... applies when
  the action taken upon a flow is allow, deny, remediate, or filterData ...
  Setting this flag on a verdict for a socket flow will also cause the data
  provider's -[NEFilterProvider handleReport:] method to be called when the flow
  is closed." The header sentence that the data provider "does not need to wait for a
  response ... before continuing to process the flow" is written for the iOS control-
  provider split; that `handleReport:` delivery does not hold up the flow is an
  inference, to be measured (section 5, items 10 and 17).
- `NEFilterReport` (`NEFilterProvider.h:298-329`): `flow`, `action`, `event`
  (`NewFlow` 1, `DataDecision` 2, `FlowClosed` 3, `Statistics` 4 on macOS
  10.15.4+), and `bytesInboundCount` / `bytesOutboundCount`: "This property is only
  non-zero when the report event is NEFilterReportEventFlowClosed or
  NEFilterReportEventFlowStatistics."
- **Periodic statistics:** `statisticsReportFrequency` is a property of
  `NEFilterNewFlowVerdict` (`NEFilterProvider.h:149`) and `NEFilterDataVerdict`
  (`NEFilterDataProvider.h:150`), `API_AVAILABLE(macos(10.15.4))`; default
  `NEFilterReportFrequencyNone`; Low "approximately 5 seconds", Medium
  "approximately 1 second", High "approximately half a second"
  (`NEFilterProvider.h:98-107`).
- So, by the header, a filter can return `allow` for every new flow **and** ask
  for `shouldReport` plus a statistics frequency, receiving `handleReport:` at new
  flow, periodically, and at close. **Not stated anywhere I read:** whether the
  byte counts are non-zero for a flow allowed at new-flow time **without** data
  filtering (`filterDataVerdict`/pass-peek). A forum poster (thread 669751, (W))
  saw counts only after the allow/drop decision and wanted them before; a DTS
  reply (Matt Eaton, thread 665784, (W)) says to set `shouldReport` on the
  `NEFilterNewFlowVerdict` allow and read `report.flow` in `handle(_ report:)`,
  and that poster found `sourceAppAuditToken` **nil on the report's flow** but
  populated in `handleNewFlow` (inference: cache identity at new-flow time keyed
  by `flow.identifier`). Little Snitch's Network Monitor shows "total amount of
  data sent and received" and rates (W: help.obdev.at/littlesnitch6/lsm-inspector),
  an existence proof that a content filter can feed byte totals; which API it uses
  is **unverified**.
- **Pass-through semantics.** `allowVerdict` at new-flow ends the provider's
  involvement for that flow (no data callbacks), which is the cheap observe-only
  path. The data-filtering alternative is `filterDataVerdictWithFilterInbound:...`
  then `dataVerdictWithPassBytes:peekBytes:` per chunk; `NEFilterFlowBytesMax` used
  "as a pass value" means "all upcoming bytes should be passed"
  (`NEFilterFlow.h:16-20`, `NEFilterDataProvider.h:176-182`). That route sends the
  flow's bytes through the sysex's callbacks and is not needed for observation.
- **Duration:** no field. A report carries no timestamp; duration would be
  new-flow arrival to `FlowClosed` arrival measured by our own clock (inference),
  so it includes report-delivery latency.
- **Peeking bytes is optional and is a privacy choice.** `filterDataVerdict...peek`
  would hand the sysex every app's first bytes (Little Snitch does this for SNI,
  W: help.obdev.at/littlesnitch6/adv-server-names). Not needed for app, endpoint,
  counts, bytes or duration.

#### 3.3.3 Pre-filtering, grade, loopback, coexistence (header)

- `NEFilterSettings` (`NEFilterSettings.h:25-52`): up to **1000** ordered
  `NEFilterRule`s; per flow "the NEFilterAction of the first rule that matches is
  taken": `Allow` ("without consulting this provider"), `Drop`, or `FilterData`
  ("Call this provider's handleNewFlow: method"). The default action is
  `FilterData`, i.e. "the system will pass every single flow of TCP and UDP data"
  (WWDC19 714, (W)). `defaultAction` of `Allow` needs at least one rule. Rules are
  `NENetworkRule`-based (remote endpoint, prefix, protocol, direction;
  `NEFilterRule.h`), **not app-based**, so excluding `aitm` or obscura from the
  filter is a per-flow check inside the provider, as for the proxy.
- **Loopback:** "The default action for loopback traffic is NEFilterActionAllow
  and cannot be changed. To filter loopback traffic you must include rules ...
  that specifically match loopback traffic and have an action of
  NEFilterActionFilterData" (`NEFilterSettings.h:30-33`). LuLu does this (W:
  127.0.0.0/8 and ::1/128 rules, all `FilterData`, default `Allow`).
- **Grade and coexistence:** `NEFilterManagerGrade` has `Firewall` ("see network
  traffic before other filter grades") and `Inspector` ("after firewall grade
  filters"); `enabled`: "On macOS, up to 4 filter configurations of the same grade
  can be enabled simultaneously" (`NEFilterManager.h:54-63, 115-120`). An
  observe-only filter is the Inspector use case (inference from the header's
  wording). Field reports of LuLu alongside Microsoft Defender for Endpoint
  coexisting, and of a hypothesis that two filters change ordering (3P, LuLu
  issue 836, (W)).
- `NEFilterProviderConfiguration` (`NEFilterProviderConfiguration.h`):
  `filterSockets` must be YES ("If NO, the filter plugin will not see any socket
  flows"), `filterPackets` instantiates a packet provider (not needed),
  `filterDataProviderBundleIdentifier` names the sysex (if nil and the app bundle
  holds more than one, "which one will be used is undefined"); `filterBrowsers` is
  deprecated on macOS. `NEFilterManager.disableEncryptedDNSSettings`
  (`API_AVAILABLE(macos(15.0))`) "Causes the content filter to disable any other
  installed encrypted DNS settings, including iCloud Private Relay"; it should not
  be set for an observe-only filter (inference; the header says use it only to
  intercept cleartext UDP DNS).

#### 3.3.4 Order versus the proxy, correlation, double counting

- DTS (Matt Eaton, thread 667962, (W)): with a data filter returning `allow` for
  every flow plus a transparent proxy matching every flow, on Big Sur 11.1 "HTTP
  flows hit both NEFilterDataProvider and NEProxyTransparentManager", and "the
  websocket flow would not hit the content filter first and be caught by the
  transparent proxy". So both providers see a flow, and (implied by that second
  sentence) the filter normally sees it first. No Apple page I read states the ordering (WWDC19 714 and WWDC25 234
  describe each provider's trigger separately).
- **Correlation key.** `NEFlowMetaData.filterFlowIdentifier` is documented as "The
  identifier of the content filter flow corresponding to this flow" (header,
  `API_AVAILABLE(macos(10.15.4))`, `nullable`). Whether it equals
  `NEFilterFlow.identifier` for a transparent-proxy flow is **unverified**: DTS
  Quinn (thread 132688, (W)) answered "I don't know )-:" to exactly that question,
  and the asker had found `filterFlowIdentifier` nil in an `NEPacket`'s metadata (a
  packet-tunnel flow, a different class). DTS on synchronising two providers: "Not
  within the NetworkExtension framework". If both providers run in one sysex
  process they can share a lock-protected dictionary (DTS Quinn, thread 800887,
  (W)), but that only helps if a shared key exists. Fallback keys, all inference:
  `(pid, pidversion)` from the audit token plus remote endpoint plus a time window.
- **Why correlation matters.** A filter reports **every** flow, including those the
  proxy then claims; the core also receives a `FlowOpen` for each claimed flow, so
  the Apps page would show the same connection twice unless the two are joined.
  (a) has no such duplicate: `FlowSeen` is emitted only for declined flows.
- **The re-originated dial.** For an in-scope MITM'd flow the core dials upstream
  from the user-level `aitm` process (`ingress.rs` `PassedThrough` and the module
  connectors). The filter sees that dial as a separate flow whose source is `aitm`;
  the spike log already shows `aitm-<hash>` as a `sourceAppSigningIdentifier`
  (experiments/2026-10-29-macos-ne-spike.md, tree). Unless the filter applies the
  same self-exclusion as the proxy (`SelfExclusion.isSelf`, team-OU requirement,
  FlowHandoff.swift:158-187), the Apps page lists an `aitm` row per MITM'd flow
  (inference). The embedded obscura's loopback traffic to the proxy is not seen
  (loopback default `Allow`); its upstream dials are `aitm`'s.

#### 3.3.5 Packaging, entitlement, profiles (header, local, W)

- **One sysex, two providers.** Apple's header is explicit: `NEProvider.h:124-147`,
  `+startSystemExtensionMode`: "The system extension must declare a mapping of
  Network Extension extension points to NEProvider sub-class instances in its
  Info.plist", with the example `NEProviderClasses` holding **both**
  `com.apple.networkextension.app-proxy` and
  `com.apple.networkextension.filter-data` (header). DTS Quinn (thread 800887,
  (W)): "A sysex can include multiple types of NE providers. For example, a single
  sysex might include a content filter and a DNS proxy provider. In that case the
  system instantiates all of the NE providers in the same sysex process." The
  alternative, "a single container app can contain multiple sysexen, each
  including a single NE provider", gives separate processes. LuLu's sysex declares
  only `com.apple.networkextension.filter-data` plus an `NEMachServiceName` (W:
  raw `LuLu/Extension/Info.plist`). The shipped `Info.plist` and `main.swift`
  (one `startSystemExtensionMode()`) need one added plist entry and one new
  `NEFilterDataProvider` subclass; `apps/mac/Extension/Sources/main.swift` is 11
  lines.
- **Entitlement value.** `content-filter-provider-systemextension`: "The filter
  APIs you use to allow or deny network connections created by other apps on the
  system, when signed with a Developer ID profile." (W: Apple entitlement page; it
  contains no request or approval language.) LuLu's extension entitlement file carries this value under
  `com.apple.developer.networking.networkextension` (W). Both shipped entitlement
  files list only
  `app-proxy-provider-systemextension` today
  (`apps/mac/Extension/Aitmproxy-Extension.entitlements`,
  `apps/mac/Aitmproxy.entitlements`, tree); (b) would add the new value to **both**
  (the host calls `NEFilterManager`; DTS thread 800887, in note 10, says app and
  extension both carry the NE entitlement; a per-value rule for the app was not
  re-read). `scripts/notarize-dmg.sh:195-197` asserts the presence of
  `app-proxy-provider-systemextension` only (tree), so adding a value does not
  break it and a missing filter value would not be caught by it.
- **Profiles already allow it. Verified (local, 2026-10-31).** `security cms -D`
  was refused in the sandbox (`cert import failed: UNIX[Operation not permitted]`),
  so I decoded the two profiles with `openssl smime -inform der -verify -noverify`
  and extracted **only** the `Entitlements` dictionary (no certificate blob read) from
  `~/Library/MobileDevice/Provisioning Profiles/`:

  | Profile (`Name`, both expire 2044-10-25) | App ID | `networkextension` allowlist |
  |---|---|---|
  | `Aitmproxy NE DeveloperID` | `995PCLM9KH.com.mrbrutti.aitmproxy.ne` | `packet-tunnel-provider-systemextension`, `app-proxy-provider-systemextension`, **`content-filter-provider-systemextension`**, `dns-proxy-systemextension`, `dns-settings`, `relay`, `url-filter-provider`, `hotspot-provider` |
  | `Aitmproxy Host DeveloperID` | `995PCLM9KH.com.mrbrutti.aitmproxy` | the same eight values, plus `com.apple.developer.system-extension.install = true` |

  This confirms the A1 note's claim ("enabling it grants ALL provider entitlement
  values", `A1-DONE-record.md`, side-session folder) for both profiles. A profile's
  allowlist is fixed at mint time, and these were minted with the capability on, so
  **no regeneration and no portal step is needed** to add a content filter or a DNS
  proxy to the existing sysex and host. A signed entitlement must be a subset of the
  profile allowlist (note 10, 3.4); adding `content-filter-provider-systemextension`
  is a subset.
- **Apple approval.** Network Extension providers are self-service (DTS thread
  67613, (W): exceptions only "app push providers" and "Hotspot Helper"); the
  iOS-style restriction "a content filter can only be used on a supervised device"
  is iOS, and TN3134's macOS content-filter row lists "system extension, minimum
  10.15" with no restriction (W). The existence of the minted profile is first-hand
  evidence that Matt's team needed no special grant.
- **Sandbox of a macOS filter data provider.** Apple's `NEFilterDataProvider` page
  (W) still says the extension "runs in a very restrictive sandbox" that blocks
  "network access, IPC, and disk write operations". DTS Quinn (thread 133761, June
  2020, (W)): that text "is accurate for iOS ... but that separation doesn't exist
  on macOS", "written prior to the introduction of filter providers on the Mac";
  the poster connected to a UNIX socket from a sysex content filter. DTS (thread
  127981, Jan 2020, (W)): macOS sandbox "very liberal ... I must admit that I've not
  actually tried it". These are macOS 10.15-era statements. Whether the **filter's
  callbacks in a sysex that also hosts the proxy** can connect to
  `/private/tmp/aitmproxy-capture.d/control.sock` on macOS 27 is **unverified**
  (the proxy half is proven by the spike).

#### 3.3.6 Approval UX

- Today's UX: two System Settings prompts (extension approval; "Add Proxy
  Configurations"; spec D8, note 10 3.5).
- A content filter adds its own consent. ESET's KB for **macOS 26 and 27** (W:
  support.eset.com/en/kb7636): the sysex toggles live in System Settings, General,
  Login Items & Extensions, Extensions, By App; then "When an alert asks to 'Add
  proxy configuration,' click Allow"; then "When the notification asks to let ESET
  filter network content, click Allow ... Otherwise, the firewall will not work";
  both are "a prompt, not in a settings pane". WWDC19 714 (W): "prompts the user to
  confirm that they want to allow the system extension to filter network traffic".
  Little Snitch 6 (W: help.obdev.at/littlesnitch6/intro-install): "macOS asks
  whether Little Snitch should be allowed to filter network content", plus a
  sysex approval at Privacy & Security > Security. So (b) is a **third** consent on
  top of the two the proxy needs. A filter is also togglable under System Settings
  > Network > VPN & Filters ((S), from a LuLu issue summary).
- Not found: whether replacing the already-approved sysex with a build that adds the
  `filter-data` class re-triggers the extension approval, and the exact wording and
  location on macOS 27 (the ESET and Little Snitch pages are vendor documents, (3P)).
- No headless path: the same pending-until-human fact as the proxy (D8), so the
  operator-only gate in NE-AC11 extends unchanged (the app drives `NEFilterManager`;
  no bus verb).

#### 3.3.7 Field risks

All **(3P)** or DTS-in-forum unless stated; none verified on macOS 27.

- **Filter plus transparent proxy together (Big Sur 11.1).** With a data filter that
  returned `allowVerdict` for every flow and a proxy matching every flow, Safari
  WebSockets failed (`OSStatus -9810`), SSH by hostname hit broken pipe, and
  Outlook Exchange sync failed (thread 667962, (W)). DTS Matt Eaton: excluding the
  port from the filter worked around it; on 11.2 beta 2 "I was able to run a TCP
  filter with NEFilterDataProvider and a TCP NENetworkRule with
  NETransparentProxyProvider and make a wss:// connection successfully"; the thread
  does not confirm a final-release fix. Directly relevant because (b) is exactly
  "allow everything" plus a proxy.
- **macOS 26.4 beta 2 content-filter regression (LuLu issue 836, (W)).** With iCloud
  Private Relay on, activating a content filter stopped browser traffic; the
  reporter tested "both LuLu and Little Snitch (same behavior)"; reported resolved
  in beta 3, with later intermittent reports on beta 3 and 26.3.1; closed 2026-04-06
  with no Apple statement quoted. An unconfirmed comment in the thread attributes
  Chrome connection resets to a synchronous `allowVerdict` in a `FilterData` filter
  that "a small delay avoided".
- **Fail-open or fail-closed on provider death: no authoritative answer.** A
  DevForums question (S, NetworkExtension tag page) asks exactly what a data
  provider crash, suspend or hang does to allowed, paused and partly-released
  flows, and shows no reply. A poster (thread 742974, (W)) says "Apple is following
  a 'fail secure' approach when a network system extension fails ... no networking
  is allowed" after a code-signature or profile rejection on macOS 14.2, with no
  DTS comment on that point (the DTS reply there is about TestFlight and signing).
  That is a failed **load**, not a runtime crash, and a poster's reading. A filter
  developer's own repo says it designs to fail open (3P, GitHub
  kevinabouhanna/NetworkMonitor issue 128, (S)). **This is the decisive unknown for
  the fail-open posture of (b)**, and it needs an experiment (section 5, item 14).
- **Verdict latency.** Both providers' `handleNewFlow` gate the flow, so enabling
  (b) means two synchronous per-flow callbacks in one process for every flow, one
  gating the other's. CPU and latency cost are **unmeasured**; Microsoft Defender's
  content filter appears in a macOS 26.5 kernel-panic report on Mac17 hardware
  (S, forum tag page), not attributable to the API.

#### 3.3.8 Prior art: what each tool actually shows

| Tool | Mechanism | Per-process connections and bytes |
|---|---|---|
| Little Snitch 6 | NE content filter ((W) install page) | Network Monitor: process path, code ID, owner; hostname and the IPs resolved for it; TCP/UDP ports and protocol; "how often a connection was established and how many attempts were denied"; total data sent and received with rates; summary counts of processes and domains; helper processes attributed to the parent app since 6.2.1 ((S)). Hostnames from **DNS sniffing** (watches every process's resolutions), **deep packet inspection** (lets the process connect, captures the first request, reads SNI), else the **IP address** ("presents this address ... in Network Monitor") (W: adv-server-names). Reverse DNS is "of little use" |
| LuLu (Objective-See) | Sysex with only `filter-data`; XPC to the app (W: Info.plist, `NEMachServiceName`) | Per-flow alerts and rules, not a traffic monitor. `FilterDataProvider.m` (W summary, 53 KB): three outbound rules (127.0.0.0/8, ::1/128, any) all `FilterData`, default `Allow`; returns allow, drop or pause; reads `sourceAppAuditToken`, `sourceProcessAuditToken`, `remoteEndpoint`, `remoteHostname`, `flow.URL`; **never sets `shouldReport` or `statisticsReportFrequency` and has no `handleReport:`**, so it counts no bytes; no DNS or reverse lookup, only framework-provided names |
| Proxyman Network Extension | `NETransparentProxyProvider` (W) | HTTP and HTTPS only, "from every app"; app and domain grouping is a display filter over captured flows; no non-HTTP view or bytes documented |
| mitmproxy local capture | `NETransparentProxyProvider` (note 10, 3.3; W: docs) | `--mode local` captures everything by default, narrowed by `local:curl`, `local:!curl`, `local:<pid>`; flow-view process display not stated on the pages read |

### 3.4 Option (c): claim and relay all flows as TCP/UDP passthrough with byte counting in the core

Why this conflicts with the shipped design and with the fail-open principle.
Evidence is tree or DTS/3P; where only inference, it is said.

1. **The core becomes the egress for every app.** A claimed flow's bytes go
   NE flow to sysex to Unix socket to core to upstream socket
   (`FlowHandoff.swift` pumps; `maxInboundRead = 16 KiB`, line 67). A core
   stall, crash or `Refused` is then a per-app connection failure for **every**
   app, not "flows go direct". The spec's anti-goal reads "A provider that breaks
   the user's network when the core is gone" (spec line 99) and NE-AC5 requires
   that an absent core means every flow goes direct. Field precedent for a stalled
   claimed flow taking the whole machine's networking: thread 700065 (W): after a
   claimed flow's write failed (`NEAppProxyFlowErrorDomain` code 1) "the whole
   machine then lost Internet access, and `handleNewFlow` and `handleNewUDPFlow`
   stopped being called until the VPN was turned off"; no Apple cause or fix.
2. **Today's ingress cannot do it.** `CoreIngress::dispatch_tcp` scope-gates first:
   `if !sd.guard.in_scope(&authority) { return StreamOutcome::Refused; }`
   (`ingress.rs:176-194`; `ScopeRateGuard::in_scope` defaults to `false`,
   `aitm-core/src/guard.rs:35-37`). **A refused flow is closed, which breaks the
   app's connection.** The `PassedThrough` branch only runs for in-scope flows no
   module claims, and dials through `proxy.upstream_connector(true)`, the
   `SsrfConnector`, whose default policy blocks private and loopback targets
   (`SsrfPolicy::default()`, `aitm-core/src/config.rs:482-489`; `proxy.rs:90-104`).
   So with every flow claimed, out-of-scope traffic would be refused and LAN
   targets (printers, NAS, AirPlay, local dev servers) would fail the SSRF check
   unless explicitly in scope. (c) needs a new, unguarded "observe-passthrough"
   disposition. That is a deny-by-default design change, not a wiring one, and it
   adds a new dial path: the comment on `upstream_connector` (`proxy.rs:90-94`)
   says its construction "adds no new, unguarded dial path".
3. **Source-app identity is lost to the OS for the upstream leg.** The core dials
   from the user-level `aitm` process, which the OS and other firewalls see as
   `aitm` (the spike log shows `sourceApp=aitm-<hash>` for its dials, tree).
   `NEAppProxyFlow.setMetadata:` (header, `NEAppProxyFlow.h:99-105`, macOS
   10.15.4) exists to "provide accurate source app information" to a connection the
   *provider* opens with Network.framework; it does not help a separate process.
   The header exposes `isBound` and `networkInterface` (3.2.1) because a relay is
   expected to honour an app's interface binding; whether the core's connector
   does is **not examined** here. Happy-eyeballs racing, IPv6 scope ids (the tree
   already special-cases link-local `%idx`, `FlowHandoff.swift:462`) and
   per-address source selection become the relay's job (inference).
4. **Bytes are copied through user space on both sides.** Sysex read then socket
   write, then core socket read then upstream write: two extra user-space copies
   per byte versus direct. A forum report of a 10x send-speed drop with a
   passthrough `NETransparentProxyProvider` exists (thread 691957, (S), summary
   only). Inference: bulk transfers bear this most.
5. **All apps' plaintext transits the core's memory** even if never stored: HTTP,
   cleartext protocols, DNS-over-UDP, and TLS ciphertext of every app, in a process
   that also holds the CA key and serves an agent bus. That inverts D2's "we never
   even receive out-of-scope bytes (a privacy win)" (spec line 229-231) and the
   anti-goal at line 93.
6. **Claimed-flow quirks multiply.** Note 10 3.9 (read 2026-10-29, (3P)): Chromium
   UDP flows fail when claimed (thread 770707, re-read today, (W): code 2 "The peer
   closed the flow"; Safari and Firefox work); a UDP rule leaked mbufs and panicked
   a machine before 15.1 (thread 762804, (3P) in note 10); Claiming
   everything adds these claimed-flow quirks to every app. The `false` quirks (VPN
   clients, AirDrop; threads 716594, 710762) already apply to the declined path.
7. **Prior art does not claim everything silently.** Apple's own DTS guidance is to
   claim as little as possible: "Set up the rules so that you're not passed the flow.
   Or return false" (thread 716594, (W)). mitmproxy's `--mode local` and Proxyman's
   HTTP(S)-from-every-app **do** claim broadly, but only after the user starts the
   tool (mitmproxy's extension returns `false` with no spec, note 10 3.3; Proxyman's
   is an off-by-default toggle), and both are man-in-the-middle tools by purpose. aitmproxy's deny-by-default scope is the
   stricter posture, and the live 2026-10-31 run (provider attached, empty scope,
   every flow declined, Matt's Mac unaffected) shows the declined path is the
   exercised one.

### 3.5 Adjacent facts (d), briefly

**`NEDNSProxyProvider` as hostname attribution.** It would see every app's DNS
queries with `NEAppProxyFlow.metaData` (same base class, so the same audit token),
the same information Little Snitch recovers by DNS sniffing through its content filter. But it is not an observe-only
complement: `NEDNSProxyProvider.h:59,73`: "NO if the proxy implementation has not
retained the flow and will not handle the flow data. In this case the flow is
terminated", and DTS Quinn (thread 126994, (W)): "Realistically, you will need to
handle all requests. If your infrastructure isn't up for that, you'll need to
resolve the requests it can't handle internally." So a DNS proxy puts the extension
**in the resolution path of every app** (a resolver outage is a whole-Mac DNS
outage), the (c) failure mode scoped to DNS. Encrypted DNS and iCloud Private
Relay hide queries from any DNS observer (inference). `dns-proxy-systemextension`
is already in both profiles (3.3.5). A content filter can also see UDP/53 flows if
it peeks bytes; `NEFilterManager.disableEncryptedDNSSettings` exists for that
(3.3.3). Hostnames are not needed for the Apps page (IP is acceptable, as Little
Snitch's fallback).

**F5, peer to process for proxy-only (loopback) flows.** A browser configured to
use `127.0.0.1:<port>` never reaches the NE: loopback is excluded by the wildcard
rule (note 10, 3.2; live diagnosis: "proxied flows are loopback and never reach the
NE"). The core's accepted socket knows the client's `ip:ephemeral_port`; the
process owning that socket must be found. The usual technique (3P, a GitHub PR for
an open-source "proxymate" tool, (S) search summary; Proxyman's method is
**undocumented** in what I read): scan processes' file descriptors with libproc
(`proc_listpids`, `proc_pidinfo(PROC_PIDLISTFDS)`, `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`),
match the loopback peer's `(local port, foreign port)` pair, coalesce scans so one
runs at a time off the forwarding path (reported ~3 ms), then map the pid to the
outermost `.app` using the responsible pid so WebKit helpers show as Safari. This
needs no extension and no entitlement (inference: libproc FD enumeration of other
users' processes needs privilege; same-user processes do not). A second route
exists only with option (b): a filter that opts into loopback with `FilterData`
rules sees the app-to-proxy flow with `sourceAppAuditToken`, and its
`localFlowEndpoint` (nullable at new-flow, "populated upon receiving network data",
3.3.1) could be joined to the core's accepted peer address (inference, unverified).

## 4. Candidate directions (for the Architect, not decisions)

### 4.0 A prerequisite common to every option

Whatever the extension reports, the Apps page stays empty live until the core
carries identity onto rows (3.1, fact 1): `FlowOpen.source_app` to
`CapturedTcpFlow/CapturedUdpFlow.peer_identity` (already filled by `adapter.rs`)
to something `flow.get` / `flow.table` emit (the `"process": null` slot in
`detail.rs:307-318`) to the three UIs' existing slots (macOS `ClientInfo` /
`FlowSummary`, web `clientOf`, TUI `process`). That is F5's core half and is needed
for **claimed** flows even if no observe lane is built. Today `source_app` is a
signing-identifier string only; a richer identity (name, path, pid, uid) would be a
wire change.

### 4.1 The options

**Candidate 1: (a) only, `FlowSeen` from the existing transparent proxy.**
Evidence points here if the Apps page needs "who talks to what, and how often".

- Gives: app, remote IP:port, hostname when connect-by-name, TCP or UDP, counts.
  Never bytes, duration, close, success or ICMP (3.2.2).
- Costs: no new prompt, entitlement, profile, Info.plist entry or provider class.
  Swift: an enqueue-only emit in the two `handle*` methods, a bounded drop-oldest
  queue and a writer thread (never `CoreLink.send` from `handleNewFlow`, 3.2.4), an
  audit-token resolver. Rust: one `ControlMessage` variant plus a
  `protocol_version` bump (3.2.6), a new bounded store and command(s) with their own
  agent gate (3.1), UI mapping.
- Risks: per-flow attribution cost unmeasured (the SecCode check is already paid per
  flow); UDP `false` unverified on macOS 27; degraded when another transparent proxy
  claims first (3.2.7); out-of-scope metadata enters the core (spec wording, 3.2.6).
- Fail-open: preserved if and only if the emit cannot block and loses events under
  pressure.

**Candidate 2: (a) first, wire designed to grow into (b).** Same as Candidate 1,
with the message family and the store shaped so that a later filter could feed bytes
and close events into the same rows (for example an event with optional byte fields,
or a second message type). Cost: some design effort now; benefit: no UI or store
rework if bytes are wanted later. Open point for the Architect: whether (b) ever
reports claimed flows too (duplicates, 3.3.4) and so needs correlation.

**Candidate 3: (b) only, an observe-only `NEFilterDataProvider` in the same sysex.**
Evidence points here only if bytes, duration or ICMP are required in v1.

- Gives: everything in Candidate 1 plus per-flow byte totals and statistics (header;
  population for allow-without-data-filtering unverified), a close event, other IP
  protocols (WWDC25, semantics unverified), the app-versus-creating-process split,
  inbound flows, and opt-in loopback.
- Costs: Info.plist `filter-data` entry; a new `NEFilterDataProvider` subclass;
  `NEFilterManager` configuration in the host app; `content-filter-provider-
  systemextension` added to both entitlement files (profiles already allow it:
  verified, so no portal work); a third consent prompt; per-flow self-exclusion in
  the filter; a join or de-duplication against claimed flows (the
  `filterFlowIdentifier` key is unverified); extending the notarize verify step.
- Risks: fail-open posture on provider death is **unknown** (3.3.7); two synchronous
  per-flow callbacks gate every connection in one process; field reports of
  filter-plus-proxy and Private Relay regressions on macOS 11 and 26; a sandbox
  question for the UDS (10.15-era DTS only).
- Prior position: NE spec D1 notes `NEFilterDataProvider` "only as a possible future
  observe-only complement for ICMP, not v1", and note 10's Candidate A3 is "complement,
  not v1"; choosing it here would revise that.

**Candidate 4: (c) claim and relay every flow.** Evidence points against (3.4):
the core would be every app's egress (fail-open lost), today's ingress refuses
out-of-scope flows and SSRF-blocks LAN targets, the upstream leg loses source-app
identity, all apps' bytes transit the core, and every claimed-flow quirk becomes the
product's bug. What would have to be true to reconsider it: a per-app operator
opt-in (which is the scope mechanism again), a new unguarded "observe-passthrough"
disposition added to the ingress under a spec change, and a measured relay that
cannot stall the Mac.

**Not candidates here:** `NEDNSProxyProvider` for attribution (it must answer every
query, 3.5); a packet tunnel (note 10, 3.1).

### 4.2 Comparison

| What it yields / costs | (a) `FlowSeen` from the proxy | (b) `NEFilterDataProvider` (allow-all + reports) | (c) claim and relay all |
|---|---|---|---|
| App identity | signing id string, audit token (nullable) to pid, uid, path (we resolve) | audit token, plus `sourceProcessAuditToken` (system process acting for the app) | same as (a) on the client leg; upstream leg appears as `aitm` |
| Destination IP:port | TCP yes (`remoteFlowEndpoint`, macOS 15+); UDP only the initial remote | usually at new flow; **may be nil until data** (UDP); populated in the report | yes |
| Hostname | only connect-by-name (`remoteHostname`); Chromium-style gives IP only | same | same, plus SNI from the bytes the core sees |
| Protocol | TCP, UDP | TCP, UDP, other IP protocols (ICMP per WWDC25), inbound flows | TCP, UDP |
| Connection count | yes (UDP: per socket flow) | yes | yes |
| Bytes | **no** | yes by header at `FlowClosed` / `Statistics`; populated-for-allow unverified | yes (core counts) |
| Duration | **no** | derived from event arrival times | yes |
| Close, success, failure | **none** | `FlowClosed` event, no error detail | yes |
| ICMP | no | yes per WWDC25 (semantics unverified) | no |
| Loopback | not seen | opt-in via loopback `FilterData` rules | not seen |
| New approval prompts | none | one more ("filter network content"); sysex re-approval on adding the class unknown | none |
| Extension, entitlement, profile changes | none | Info.plist +1 entry, new provider class, entitlements +1 value in both files; **profiles already allow it (verified)**; host `NEFilterManager` | none to NE; large core changes |
| Fail-open posture | preserved if emit is non-blocking and lossy | **unknown** on provider death; verdict gates every flow; 3P regressions | **violated**: core on every app's data path |
| Privacy surface | all apps' connection metadata (incl. other users unless UID-filtered) reaches the core; agent-readable unless a new gate exists; no bytes | same metadata plus byte counts; peeking bytes is optional and not needed | all apps' bytes transit the core |
| Dedup with claimed flows | none (only declined flows are reported) | **needed** (filter reports every flow, claimed or not) | none |
| Build cost | small | medium to large | largest, needs a spec change |
| Largest unknown | per-flow attribution cost, flow rate, UDP `false` on macOS 27 | fail on death, bytes for allow, key equality, sandbox, prompt on upgrade | n/a |

### 4.3 Design questions that are the Architect's and Matt's (not answered here)

1. **Policy:** may out-of-scope connection **metadata** enter the core at all (NE spec
   D2 lines 229-231, anti-goal line 93, NE-AC3), and who switches observe mode on?
   Precedent: `macos_capture.enabled` is config-file only, with a structural test
   (LF-AC12).
2. **Where rows live:** not the closed `Flow` enum, not `L4Flow`, not the 50,000-flow
   FIFO `MemFlowStore` (it would evict real captures). A separate bounded ring with
   its own command(s) is the shape the evidence allows; the agent gate is new work
   because per-row gating does not exist (3.1).
3. **Granularity:** a row per flow, or provider-side aggregation per app and
   destination (cuts events, loses per-flow timestamps).
4. **Whose flows:** other users' (OQ10 unimplemented), `aitm`'s and obscura's own
   (self flows are excluded today, `TransparentProxyProvider.swift:74,83`).
5. **Version skew:** bump `Hello.protocol_version` or add a capability, because an
   unknown variant makes the shipped core detach the provider (3.1).

## 5. Open questions

Only Matt, his Mac, or an experiment can settle these. Commands are suggestions;
none was run here (the sandbox refused the system tools) and none is verified to
print the expected labels.

**For Matt (policy):**

1. Are bytes and duration needed for the Apps page in v1? This is the (a) versus (b)
   fork; (a) cannot provide them.
2. Is every app's connection metadata sitting in the core's memory acceptable, and
   may an agent (`Frontend::Mcp`) read it? If yes, under which `AgentPolicy`
   postures and behind which operator gate?
3. Should `aitm`'s and obscura's own flows, and other logged-in users' flows,
   appear?
4. Is a third consent prompt acceptable if (b) is chosen?
5. Should the Apps page also list proxy-only clients (a browser pointed at
   `127.0.0.1:<port>`)? Those never reach the extension; they need F5's libproc
   lookup (3.5) or an opt-in filter loopback rule.

**Experiments for option (a):**

6. *Field survey.* A throwaway build logs, for a working day, every field in 3.2.1 at
   `handleNewFlow` and `handleNewUDPFlow`: how often `sourceAppAuditToken` is nil,
   `remoteFlowEndpoint` is nil, `remoteHostname` is set, and `sourceAppSigningIdentifier`
   is empty (system processes), with the audit token's uid.
7. *Cost and rate.* Time `isSelf`, `proc_pidpath_audittoken` and
   `SecCodeCopyPath` per flow, and measure new flows per second (the provider's
   framework log lines "provider rejected new flow" counted per hour, as in the
   2026-10-31 diagnosis; or `netstat -s -p tcp` deltas, which the sandbox refused).
   This sizes the queue (3.2.4).
8. *UDP `false` on macOS 27.* Exercise the macOS-15 `handleNewUDPFlow` fail-open
   path (3.2.2 header inconsistency) with DNS, QUIC and Chromium under the shipped
   catch-all `.any` rule while returning `false` (thread 770707, 3.2.7).
9. *Another transparent proxy.* With Proxyman's extension enabled first or second,
   does aitm's provider still see flows, and whose identity does `metaData` carry
   (thread 677357)?

**Experiments for option (b)** (a do-nothing `NEFilterDataProvider` added to the
spike sysex):

10. Return `allow` with `shouldReport = true` and `statisticsReportFrequency = Low`:
    are `bytesInboundCount` / `bytesOutboundCount` non-zero at `FlowClosed` and
    `Statistics` for a flow allowed **without** data filtering?
11. Is `NEFlowMetaData.filterFlowIdentifier` (proxy side) equal to
    `NEFilterFlow.identifier` (filter side) for a proxied flow, and is it ever nil
    (DTS Quinn: "I don't know")?
12. What does `ping` (ICMP) look like to the filter: does it appear, with which
    endpoint and app?
13. Is `sourceAppAuditToken` on `report.flow` nil (thread 665784), and is
    `remoteFlowEndpoint` populated by close for unconnected UDP?
14. **Fail behaviour:** with the filter enabled and flows live, make the sysex die or
    hang (and, separately, disable the filter in System Settings): does traffic
    continue, stall or fail? This decides whether (b) can be fail-open.
15. Can the filter's callbacks, inside the sysex that also hosts the proxy, connect to
    the 0700 Unix socket on macOS 27 (DTS statements are 10.15-era)?
16. Prompt behaviour on macOS 27: does adding the `filter-data` class to the approved
    sysex re-trigger the extension approval, and where do the "filter network
    content" prompt and the filter toggle live?
17. Regression checks on macOS 26/27: an allow-all filter plus the proxy with
    WebSockets and SSH (thread 667962), with iCloud Private Relay on and off (LuLu
    issue 836), and alongside Little Snitch or LuLu if installed. Measured
    per-connection latency with and without the filter.

**Unresolved from earlier notes:** note 10's open question 14 (multi-user) and spec
OQ10 remain decisions without code in the provider.

## 6. Sources

All read 2026-10-31. "(header)" = first-hand in the Xcode 27.1 MacOSX SDK on this Mac
(macOS 27.0, 26A428). "(local)" = read-only check on this Mac. "(tree)" = this
repo at `a248897` unless noted. "(W)" = web page via WebFetch summariser. "(S)" =
search-result summary only. "(3P)" = third-party.

**SDK headers (header)**, under
`/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/`:

- `System/Library/Frameworks/NetworkExtension.framework/Headers/`:
  `NEAppProxyFlow.h`, `NEAppProxyTCPFlow.h`, `NEAppProxyUDPFlow.h`,
  `NEFlowMetaData.h`, `NEAppProxyProvider.h`, `NETransparentProxyProvider.h`,
  `NEProvider.h` (lines 123-149), `NEFilterDataProvider.h`, `NEFilterProvider.h`,
  `NEFilterFlow.h`, `NEFilterManager.h`, `NEFilterProviderConfiguration.h`,
  `NEFilterSettings.h`, `NEFilterRule.h`, `NEDNSProxyProvider.h`
- `usr/include/bsm/libbsm.h` (audit-token accessors), `usr/include/libproc.h`
  (`proc_pidpath`, `proc_pidpath_audittoken`),
  `System/Library/Frameworks/Security.framework/Headers/SecCode.h`

**Local (local)**

- `~/Library/MobileDevice/Provisioning Profiles/Aitmproxy NE DeveloperID.provisionprofile`
  and `Aitmproxy Host DeveloperID.provisionprofile`: only the `Entitlements`, `Name`
  and `ExpirationDate` keys were extracted, via `openssl smime -inform der -verify
  -noverify` piped to `plutil -extract` (`security cms -D` was refused by the sandbox)
- Refused by the sandbox, so not used: `log show`, `netstat -s -p tcp`,
  `sysctl kern.boottime`, `systemextensionsctl list`, `curl` to
  `raw.githubusercontent.com`

**Apple documentation (W, JSON endpoints under `developer.apple.com/tutorials/data/documentation/`)**

- `networkextension/handling-flow-copying.json`,
  `technotes/tn3134-network-extension-provider-deployment.json`,
  `networkextension/content-filter-providers.json`,
  `networkextension/nefilterdataprovider.json`,
  `bundleresources/entitlements/com.apple.developer.networking.networkextension.json`
- WWDC25 session 234: https://developer.apple.com/videos/play/wwdc2025/234/ ;
  WWDC19 session 714 (transcript via https://asciiwwdc.com/2019/sessions/714)

**Apple DevForums (W unless noted)**

- 800887 Network Extension Provider Packaging (multi-provider sysex, one process, one
  XPC endpoint): https://developer.apple.com/forums/thread/800887
- 67613 Network Extension Framework Entitlements (self-service):
  https://developer.apple.com/forums/thread/67613
- 133761 and 127981 (filter sandbox on macOS):
  https://developer.apple.com/forums/thread/133761 ,
  https://developer.apple.com/forums/thread/127981
- 667962 NEFilterDataProvider and NETransparentProxyProvider together:
  https://developer.apple.com/forums/thread/667962
- 132688 filterFlowIdentifier versus identifier:
  https://developer.apple.com/forums/thread/132688
- 665784 and 669751 (`shouldReport`, byte counts):
  https://developer.apple.com/forums/thread/665784 ,
  https://developer.apple.com/forums/thread/669751
- 677357 ordering of transparent proxies:
  https://developer.apple.com/forums/thread/677357
- 126994 DNS proxy must handle all requests:
  https://developer.apple.com/forums/thread/126994
- 716594 `false` for a VPN client; 770707 Chromium UDP under a rule; 700065 whole
  machine lost Internet after a claimed flow stalled; 761134 "if you just wanted to
  look at traffic, a content filter would work":
  https://developer.apple.com/forums/thread/716594 ,
  https://developer.apple.com/forums/thread/770707 ,
  https://developer.apple.com/forums/thread/700065 ,
  https://developer.apple.com/forums/thread/761134
- 742974 "fail secure" poster remark: https://developer.apple.com/forums/thread/742974
- (S, search summary only) 691957 passthrough slowdown, 133543 and 756756 UDS in a
  sandbox, NetworkExtension tag page (provider-crash question, Defender panic)

**Vendor and project sources**

- Little Snitch 6: https://help.obdev.at/littlesnitch6/adv-server-names ,
  https://help.obdev.at/littlesnitch6/lsm-inspector ,
  https://help.obdev.at/littlesnitch6/intro-install (W)
- LuLu: https://github.com/objective-see/LuLu ; `LuLu/Extension/{Info.plist,
  Extension.entitlements,FilterDataProvider.m}` read via WebFetch of
  `raw.githubusercontent.com`; issue 836: https://github.com/objective-see/LuLu/issues/836 (W)
- Proxyman: https://proxyman.com/docs/advanced-features/network-extension ,
  https://proxyman.com/posts/2026-10-06-introducing-network-extension (W)
- mitmproxy: https://docs.mitmproxy.org/stable/concepts/modes/ ,
  https://mitmproxy.org/posts/local-capture/macos/ (W)
- ESET KB7636 (macOS 26 and 27 prompts):
  https://support.eset.com/en/kb7636-allow-system-extensions-for-your-eset-product-for-macos (W)
- (S) charlie-niekirk/proxymate PR 5 (libproc peer-pid lookup),
  kevinabouhanna/NetworkMonitor issue 128, Little Snitch release notes

**aitmproxy tree (tree)**

- Provider: `apps/mac/Extension/Sources/{TransparentProxyProvider,FlowHandoff,main}.swift`,
  `apps/mac/Extension/Info.plist`, `apps/mac/Extension/Aitmproxy-Extension.entitlements`,
  `apps/mac/Aitmproxy.entitlements`
- Core: `crates/aitm/src/macos_capture/{listener,adapter,feeder}.rs`,
  `crates/aitm/src/ingress.rs`, `crates/aitm/src/wire.rs`,
  `crates/aitm-core/src/{flow,store,command,guard,protocol,proxy,config}.rs`,
  `crates/aitm-proto-l4/src/{flow.rs,commands/flow.rs}`,
  `crates/aitm-plugins/src/{capture,detail,subscription}.rs`,
  `crates/aitm-mcp/src/server.rs`
- UIs: `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`,
  `apps/mac/Sources/Aitmproxy/Session.swift`,
  `apps/mac/Sources/AitmproxyKit/{Flow,FlowSummary,Fixtures}.swift`,
  `apps/web/src/{state/app.ts,bus/normalize.ts}`, `crates/aitm-tui/src/model.rs`
- Scripts: `scripts/notarize-dmg.sh` (lines 195-197), `apps/mac/build.sh`
- Docs: `docs/research/10-macos-network-extension.md`,
  `docs/research/experiments/2026-10-29-macos-ne-spike.md`,
  `docs/superpowers/specs/2026-10-29-aitmproxy-macos-network-extension-design.md`,
  `.../2026-10-30-aitmproxy-macos-ne-live-feeder-design.md`,
  `.../2026-10-30-macos-ne-ship-and-toggle-design.md`
- Outside the repo: the A1 record
  `.../side-session-notes/local_75059306-.../A1-DONE-record.md` (the capability note
  verified in 3.3.5) and the auto-memory entry `aitmproxy-ne-live-capture-diagnosis`
  (live 2026-10-31 diagnosis)
- `origin/fix/ne-no-scope-hint` (PR #181) read for the `ShellView` banner only
