# macOS Network/System Extension capture path (L4 Phase 2) — design

**Status:** approved (2026-10-29). **All decisions locked** — the seven (b)
defaults plus Matt's three (a) answers: **A1** Matt sets up the Apple portal (two
App IDs, Network Extension + System Extension capabilities, two Developer ID
profiles carrying the NE entitlement); **A2** accept the flow-level macOS L4
ceiling (raw-packet L4 stays Linux/CLI-only); **A3** C1 — embed the sysex in
`Aitmproxy.app`. Build proceeds per the plan: the Band-B `[Rust]` seam tasks start
once the Phase-1 `CaptureIngress` prerequisite is met; the `[Mac]`/`[Build]` tasks
are gated on Task 1 (the signing spike), which itself waits on Matt completing the
portal setup (it needs his Developer ID + the two profiles).
**Research inputs:** `docs/research/10-macos-network-extension.md` (primary),
`docs/research/09-l4-inpath-interception.md`, `docs/research/08-l4-packet-rust.md`,
`docs/research/07-ca-install.md`.
**Realizes:** `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md`
**L4OPS-AC19** (macOS extension capture path, P2, gated) and the Phase-1 seam it
reserves, **L4OPS-AC17** (protocol-general capture seam). Binding principle from
that spec: **one capture path, all protocols** (its §"Design principle").
**Extends:** `docs/superpowers/specs/2026-10-28-aitmproxy-core-connection-model-design.md`
(the capability a UI feature-detects on the core it drives) with "this embedded
core has an approved extension providing capture."
**Phase:** this is **Phase 2** of the L4 milestone. Phase 1 (CLI/Linux-first
live-wire L4) is a separate, approved milestone and is a **prerequisite seam**,
not re-specified here. **Design only; nothing here is built.**

## Intent

Give the self-contained macOS app a **live capture path the Proxyman way**: a
macOS Network/System Extension that hooks every app's outbound traffic at the OS
level, with the user's explicit approval, and feeds it into aitmproxy's core —
**not** a bare privileged helper and **not** manual system-proxy configuration.
Today the macOS app's embedded, user-level core returns `L4Unavailable` for every
wire verb (L4OPS-AC18): it can render the surfaces but cannot capture. A
`NETransparentProxyProvider`-class system extension, as mitmproxy and Proxyman
ship, is the sanctioned way to capture on macOS without disabling SIP, without a
root helper, and without the user having to point their system proxy at us. Per
Matt's hard requirement (2026-10-28), the extension is **protocol-general**: it
is the single macOS ingress for HTTP/WS/L4 and future protocols, handing captured
traffic to the core, which dispatches by protocol behind each protocol's
deny-by-default guard. It is not an L4-only shim.

## Goals

- **One capture path, all protocols.** Captured TCP flows reach the core's
  existing `ProtocolModule` acceptor seam (HTTP/WS/future) and captured UDP flows
  reach a flow-level L4 kind, both through the **same** protocol-general capture
  ingress the Linux/CLI L4 backend uses (L4OPS-AC17) — no macOS-only protocol
  path, no second seam.
- **Deny-by-default at every new layer.** No captured flow reaches a protocol
  module or an L4 plugin without passing the core's guard (`ScopeRateGuard` for
  L7, `L4Guard` for L4) below the ingress. The extension is a transport, never an
  authority; there is no path around the guard.
- **Honest, feature-detected capability.** The macOS app surfaces "extension
  approved and attached" as a capability beside the existing core-health state;
  until the extension is approved and connected, the wire verbs degrade honestly
  with a reason naming the extension as the path (L4OPS-AC18 extended to Phase 2).
- **Authenticated, fail-open handoff.** The extension and the core exchange flows
  over an authenticated transport with control/data separation; a root provider
  never ships plaintext flows to an unverified peer, and when the core is absent
  the provider **fails open** (flows go direct, nothing breaks).
- **A buildable, signable, notarizable package.** The sysex is nested-signed and
  notarized inside the existing Developer ID pipeline with the correct entitlements
  and embedded provisioning profiles; the current scripts' "no entitlements"
  regression is fixed.
- **Operator-controlled approval and a visible capture indicator.** Activation
  and OS approval are an operator action (07 precedent); the app shows when
  capture is on and offers a clean uninstall.

## Non-goals

- **No raw packet-level L4 on macOS.** The extension is flow-level (TCP byte
  streams, UDP datagrams). Packet craft/inject/mutate and in-path NFQUEUE-style
  interception stay Linux-only; on macOS they remain `L4Unavailable`. BPF
  capture-only (research 08) is the packet ceiling and is not built here.
- **No Phase-1 rebuild.** The protocol-general `CaptureIngress`, `L4Guard`,
  `L4Permit`, scope model, `L4FlowStore`, and the `l4.*` command/bus/UI surface
  are Phase 1's and are consumed as-is. A gap found in them is reported to the
  Phase-1 owners, not patched here.
- **No change to the core's TLS/CA model.** The core terminates TLS and owns the
  CA exactly as for an explicit proxy (07). The extension adds no trust step and
  never touches the CA key.
- **No Mac App Store build.** Direct Developer ID distribution only; the App Store
  requires an appex plus a sandboxed core, which this product cannot meet.
- **No MDM / managed-deployment flow, no headless activation.** Activation stays
  pending until a human approves in System Settings; we do not build an
  MDM-preapproval path.
- **No new L4 protocol semantics, DoS primitive, or pinning/QUIC-decrypt bypass.**
  Native QUIC is not decrypted (Proxyman's own limit); forcing QUIC to TCP
  fallback, if wanted, is an open question, not a built default.

## Anti-goals

- **A provider that captures out-of-scope or non-consented traffic into the
  core.** If any flow reaches a protocol module or L4 plugin without the core's
  guard passing it, deny-by-default is broken. *Amendment (2026-11-01, approved by
  Matt via the observe-only-lane spec, its OQ7):* "traffic" means flow **bytes**.
  Connection **metadata** about out-of-scope flows may enter the core only through the
  observe-only lane (`2026-10-31-macos-ne-observe-only-lane-design.md`), which the
  operator enables explicitly, carries no bytes, and is filtered to the operator's own uid.
- **A root sysex that hands plaintext flows to a squatting local process.** If the
  data path can be hijacked by an unauthenticated peer on a user-writable socket,
  the design has failed.
- **A provider that breaks the user's network when the core is gone.** If an
  approved-but-core-absent extension drops or stalls flows instead of letting them
  go direct, it is a failure even if capture works when the core is up.
- **An agent that can install or approve the system extension.** If an agent
  (`Frontend::Mcp`) can trigger the sysex install or OS approval, the operator
  gate is theatre.
- **The app shipping with no entitlements** (today's `--force` / no
  `--entitlements` re-sign) carried into an NE build, where it silently prevents
  activation.
- **"It compiles" acceptance.** Synthetic buffers alone are not the bar for the
  capture path; the final bar is a real in-scope flow captured and MITM'd on a
  real Mac through an approved extension.

## Constraints

- **One capture path, all protocols; deny-by-default; one choke point.** Mirrors
  the parent spec's Constraints. The extension feeds the core's protocol-general
  ingress; the guard sits in the core below the ingress; `send_on_wire` and the
  verdict path still require an `L4Permit` where L4 writes happen (Linux only).
- **Phase-1 seam is a hard prerequisite.** Research §3.7 records that the
  protocol-general `CaptureIngress` (L4OPS Phase-1, its Task 10) is **not in this
  worktree** (no `ingress` module under `crates/aitm/src`, HEAD `44f02be`), that
  `aitm-core`'s `handle_conn` fills `NextLayerHint.dst` with the *accepted peer*
  (client) address (`crates/aitm-core/src/proxy.rs`), that unclaimed connections
  are dropped, and that `aitm-proto-l4`'s `L4Module` is command-driven, not an
  acceptor. **This spec builds the macOS backend that feeds that ingress; the
  ingress itself must exist first.** If its shape differs from what §3.7 assumed,
  that is a Phase-1 gap to report, not to patch here.
- **No `aitm-core` edits to accommodate the extension.** The macOS ingress sits in
  the `aitm` wiring layer and the new Swift targets, consistent with L4OPS-AC19's
  "guarded identically to the `pcap` path." Carrying the captured flow's
  authoritative destination and source-app identity into dispatch is done through
  the ingress/`ModuleCtx`, not by reshaping `aitm-core`'s acceptor — flagged to
  Phase-1 if the hint needs a destination-authoritative field.
- **`forbid(unsafe_code)`** holds in the Rust crates; the sysex provider is
  **Swift** (Apple's NetworkExtension API is Swift/Obj-C; a Rust sysex via
  `objc2-network-extension` would need `unsafe` and is rejected). `aitm`/the core
  stay Rust and unprivileged.
- **Build/verify outside the sandbox only.** The Claude Bash sandbox cannot sign,
  build Swift/Xcode, reach Apple, or run `git`/`gh`. Every Xcode/bama build,
  `codesign`, `notarytool`, `OSSystemExtensionRequest` activation, and the
  real-Mac acceptance run go through the Terminal panel on Matt's machine. The
  spec is design; the plan's build/verify tasks are Terminal-panel tasks.
- **macOS 26+ target.** `Info.plist.in` sets `LSMinimumSystemVersion 26.0`; the
  sysex targets macOS 26/27 and must use the current APIs (`remoteFlowEndpoint`,
  `localFlowEndpoint`, audit-token identity), not mitmproxy's deprecated
  `NWHostEndpoint` calls (research §3.1).
- **Developer ID only; self-service entitlement.** The NE entitlement needs **no
  Apple approval** (self-service since Nov 2016, research §3.4). Two App IDs, two
  Developer ID profiles carrying `app-proxy-provider-systemextension`, and the
  System Extension + Network Extensions capabilities are required on Matt's team.
- **Workflow.** Seven stages; the Rust gate green before any review; the Swift/app
  build verified in the Terminal panel; a Stage-6 **security** review is mandatory
  (same posture the parent spec held for the L4 wire paths).

## Design

The macOS capture path has three pieces: a **Swift system extension** (the
`NETransparentProxyProvider`), a **host that activates it and brokers the
handoff** (the existing `apps/mac` app, extended), and a **Rust capture backend**
in `aitm` that turns handed-over flows into the core's protocol-general ingress
units. Each decision below states its reason; defaults the Architect chose are
marked **(Architect's call)**.

### D1 — Provider: `NETransparentProxyProvider` as a Developer ID system extension

**Decision (adopt research Candidate A1).** Use a single
`NETransparentProxyProvider` packaged as a Developer ID **system extension**
(`.systemextension`). It is the only system-wide provider that returns the full
bidirectional bytes of each flow *and* lets the owner edit or park them, and the
only one that chooses per-flow whether to handle a flow or let it go direct. It is
Developer ID-supported as a sysex (appex is Mac App Store only). It is exactly
what mitmproxy and Proxyman (macOS 26+) ship.

**Flow-level consequence, stated plainly.** The provider sees **TCP byte streams
and UDP datagram flows with endpoints and process identity — not IP packets.**
There are no IP headers, TCP flags, retransmissions, fragments, ICMP, or raw IP.
Loopback is excluded by wildcard rules; traffic is outbound only. Therefore:

- The macOS capture path is a **flow** ingress, matching the `ByteStream`/flow
  shape the core already consumes — a natural fit for the ONE seam.
- **Raw packet-level L4 (craft/inject/mutate, in-path NFQUEUE-style) is
  impossible through this provider** and stays `L4Unavailable` on macOS. The
  providers that see packets (`NEPacketTunnelProvider`, `NEFilterPacketProvider`)
  either cannot edit or need a full user-space TCP/IP stack (a *second* ingress
  shape) — rejected (research §3.1–3.2).

Rejected alternatives: `NEAppProxyProvider` (per-app only on macOS);
`NEPacketTunnelProvider` (packets only, no app metadata, needs a user-space
stack); `NEFilterDataProvider` (observe-only, cannot mutate) — the last is noted
only as a possible future observe-only complement for ICMP, not v1.

### D2 — The protocol-general seam mapping (the central AC19 question)

**Decision (adopt research Candidate G1): keep L4OPS-AC19 as written and read it
this way.** A captured flow enters the core's **one protocol-general capture
ingress** (the Phase-1 `CaptureIngress`) and is dispatched by protocol:

- **TCP flow → the existing `ProtocolModule` acceptor seam.** The flow is a
  `ByteStream` plus a `NextLayerHint`; the acceptor sniffs it (ClientHello/SNI,
  first bytes, ALPN) and the HTTP/WS/future module claims it, exactly as for an
  explicit-proxy connection. **The one difference from the explicit-proxy path:
  the extension gives us the authoritative original destination up front**, so
  `hint.dst` must carry the flow's *remote* endpoint (and `remoteHostname`/SNI
  when present), not the client peer address. Carrying the destination (and the
  source-app identity) into dispatch is an ingress/`ModuleCtx` concern, flagged to
  Phase 1 if `NextLayerHint` needs a destination-authoritative field or a
  source-identity field (§3.7).
- **UDP flow → a flow-level L4 kind behind `L4Guard`.** A UDP flow is datagrams
  plus per-datagram remote endpoints and process identity — **not** the IP-packet
  `L4Packet` model (`crates/aitm-proto-l4/src/flow.rs` assumes on-wire IP bytes).
  It enters as a **flow-level L4 unit** guarded by `L4Guard`. Whether this is a
  new `FlowKind`/flow variant or synthesized UDP frames is an implementation
  choice for the plan **(left to the builder, within "guarded identically")**,
  but it must not require raw-packet machinery.
- **Raw packet-level L4 craft/inject/mutate → `L4Unavailable` on macOS.** As D1.

**Deny-by-default placement.** Every captured flow — TCP or UDP — passes the
core's guard **below** the ingress before any protocol module or L4 plugin sees
it. The extension's provider rules and per-flow `handleNewFlow` decision are a
coarse pre-filter (they decide what even enters the provider), but the
**authoritative** scope check is the core's guard, identical to the `pcap`-fed
path. An out-of-scope flow is never dispatched.

**The unclaimed-flow problem (new, macOS-specific).** `handleNewFlow` must answer
`true` (handle) or `false` (go direct) immediately, before the core can sniff
bytes, and the core's `handle_conn` today **drops** an unclaimed connection
(§3.7) — harmless for an explicit proxy, but for a system-wide extension a
dropped flow **breaks the user's app**. Resolution:

- **Out-of-scope flows are not captured at all:** the provider returns `false`
  (flow goes direct) for any flow the core's pushed scope-set does not cover.
  Deny-by-default thus also means we never even receive out-of-scope bytes (a
  privacy win). **(Architect's call)** the provider learns the active scope-set
  over the control channel and matches it in `handleNewFlow`; because provider
  *rules* cannot be hot-edited without a restart (§3.5), the catch-all rule stays
  broad and the per-flow decision does the scoping.
- **In-scope captured flows are always forwarded or MITM'd, never silently
  dropped.** A captured TCP flow that no L7 module claims must be **tunnelled
  verbatim to its original destination** (a universal passthrough), because
  dropping it breaks the user. This passthrough-on-unclaimed behaviour is a seam
  obligation on the capture ingress (the existing SNI-pinned
  `aitm-plugin-passthrough` is not general enough). **Flagged to Phase 1** as a
  requirement the ingress must satisfy; the macOS backend depends on it.

**Final AC19 wording is Matt's to confirm** — adopt G1 (keep the text, read it as
above) or reword to a G2 phrasing that spells out "flows, not packets." Carried to
Open questions.

### D3 — Handoff transport: per-flow Unix sockets + an authenticated control channel

**Decision (adopt research Candidate B1, hardened).** The provider and the core
exchange flows over **Unix domain sockets**: one **control channel** plus **one
data socket per flow**, mitmproxy's proven shape. Rationale: the core stays a
plain tokio listener; a TCP flow maps directly to a `ByteStream`; per-flow sockets
give each flow its own buffers and backpressure; UDP framing is ours
(length-delimited datagrams with endpoints). XPC (B2) is Apple's recommended
*control* plane but is not a byte-stream API (bulk flow data over XPC has no
stream backpressure; fd-passing is unverified), and loopback-TCP+token (B3) is a
second listener with weaker peer auth. **(Architect's call)** B1 for both planes;
revisit XPC for the control plane only if peer authentication over UDS proves
unreliable (Open question).

**Required properties:**

- **Control/data separation.** The control channel carries: a capability hello,
  the active intercept/scope-set spec, and per-flow open notifications with
  metadata (flow id, TCP|UDP, original remote endpoint, `remoteHostname` when
  present, source-app identity, local endpoint for UDP). The per-flow data socket
  carries raw bytes (TCP) or length-delimited datagrams (UDP) after a small
  handshake. No bulk bytes on the control channel.
- **Peer authentication — a root sysex must not ship plaintext to a squatter.**
  The control socket lives in a **0700** directory the host creates; the provider
  **validates the core's code signature** before sending any flow, via the peer's
  audit token (`LOCAL_PEERTOKEN`, `sys/un.h`) resolved to a code requirement, or —
  if that proves unreliable — an XPC control channel with
  `setCodeSigningRequirement`. mitmproxy's `/tmp/mitmproxy-<pid>` with no
  permissions is explicitly **not** adopted (research §3.7). The exact
  peer-auth mechanism's feasibility on macOS 27 is an Open question / spike.
- **Fail-open when the core is absent.** With no control channel attached (core
  not running, crashed, or not yet connected), the provider returns `false` for
  every new flow so all traffic goes direct and the user's network is unaffected.
  Nothing in NetworkExtension does this automatically; the provider implements it
  (mitmproxy does the same by returning `false` when it has no spec).

### D4 — Loop avoidance and lifecycle safety

- **Self-exclusion.** The core's own upstream dials and the embedded `obscura`
  browser's flows are ordinary flows to the provider and must be excluded, or the
  tool captures itself. **(Architect's call)** exclude by **source-app identity**
  (audit token / signing identifier of `aitm` and `obscura`), which the provider
  reads per flow, rather than by pid (pid reuse/ordering hazards). Loopback (the
  bus; obscura↔core on 127.0.0.1) is already not captured by wildcard rules, which
  removes the proxy port from the loop. Whether the embedded obscura carries a
  usable `sourceAppSigningIdentifier` is an Open question / spike.
- **Version-bump discipline.** Every change to the sysex **must** bump its bundle
  version or existing installs are not replaced; the host returns `.replace` from
  `actionForReplacingExtension`; after a replacement the saved proxy configuration
  is reconciled (settle delay + connected-check) because a version bump can leave
  the NE configuration disabled (leash #58).
- **Capture indicator + uninstall.** The app shows a visible "capture is on"
  indicator while the extension is active and attached, and offers an uninstall
  path (`deactivationRequest` + remove the `NETransparentProxyManager`
  configuration).

### D5 — Packaging

**Decision (Architect's call, open to Matt): C1 — the sysex is embedded inside
`Aitmproxy.app`.** One bundle, one cask, one version, one notarization. The sysex
lives at `Contents/Library/SystemExtensions/<sysex-id>.systemextension` (Apple's
required location); its frameworks live inside the sysex, not the app.

Reason: the macOS story this milestone serves is the **self-contained app**
(core-connection spec). A single bundle keeps activation, signing, and
version-bump coupling in one place and matches the embedded-core model already
shipped. The alternative — C2, a separate "capture-host" app (mitmproxy's
Redirector.app) installed to `/Applications` — better fits a CLI-first story and
decouples the signing surface, at the cost of a second bundle, a second approval,
and more release engineering.

**CLI-first implication (must be surfaced to Matt).** A system extension can only
be activated by a bundled host app that carries the entitlements; **a CLI-only
macOS user (`aitm` with no app installed) cannot activate the extension.** Under
C1 the CLI user gets capture only by also installing the app; the CLI could at
most attach to an already-approved extension or drive the app (Proxyman's CLI
pattern). This is the core trade-off of C1 vs C2 and is an Open question for Matt.

### D6 — Build system

**Decision (Architect's call): D1 — a small Xcode project builds the sysex (and
its activation glue), while SwiftPM `build.sh`/bama keep building the main app.**
Reason: the sysex needs nested, inside-out signing with **two** provisioning
profiles (app + sysex) and the `-systemextension` entitlement handling that Xcode
26-and-earlier mis-signed on export and Xcode 27 claims to fix; Apple's own
guidance and mitmproxy both use Xcode for the extension. Pure-script assembly (D2)
keeps one toolchain but makes the builder hand-manage profiles, `Info.plist`
keys, and the `application-identifier`/`team-identifier` claims — exactly the
failure modes research §3.4 catalogued. The cost of D1 is a second build system
beside bama; it is contained to the sysex.

The sysex `Info.plist` carries `CFBundlePackageType SYSX`,
`NSSystemExtensionUsageDescription`, and a `NetworkExtension` dictionary mapping
`NEProviderClasses` → the provider class; its `main` calls
`NEProvider.startSystemExtensionMode()` early.

### D7 — Entitlements, signing, notarization

**Entitlements (research §3.4).** Apple approval is **not** required. Exact keys:

| Target | Key | Developer ID value |
|---|---|---|
| Sysex **and** host app | `com.apple.developer.networking.networkextension` (array) | `app-proxy-provider-systemextension` |
| Host app | `com.apple.developer.system-extension.install` (bool) | `true` |
| Both (manual signing) | `com.apple.application-identifier` (`TEAMID.bundle-id`), `com.apple.developer.team-identifier` | required claims |

Two new entitlement plists (`apps/mac/Aitmproxy.entitlements` for the app, a sysex
one); **do not** reuse `EmbeddedObscura.entitlements` (obscura-only). Development
day-to-day uses an Apple Development identity with the unsuffixed
`app-proxy-provider` value; ad-hoc (`-`) signing **cannot** carry restricted
entitlements.

**Account prerequisites (checklist for Matt; none verified against his account).**
A Developer ID Application cert (already required by `notarize-dmg.sh`); **two App
IDs** (the app `com.mrbrutti.aitmproxy` + a new sysex bundle id); the *Network
Extensions* capability on both and *System Extension* on the app; **two Developer
ID provisioning profiles**, one per App ID, whose allowlist carries
`app-proxy-provider-systemextension` (and `system-extension.install` on the app),
each embedded as `embedded.provisionprofile` in its bundle. Whether these exist on
Matt's team is an Open question.

**Script changes (research §3.6).** The current scripts re-sign the outer app with
`codesign --force` and **no `--entitlements`**, so the app ships today with **no
entitlements at all** — a regression that would silently block activation. The
plan must:

- `apps/mac/build.sh` / the new Xcode build: assemble and **sign the sysex first**
  (inside-out), then the app, each with an explicit `--entitlements` and its
  embedded profile; install to `/Applications` (or prove `~/Applications` works —
  Open question / spike).
- `scripts/notarize-dmg.sh`: re-sign the **sysex first** with Developer ID
  (`--options runtime --timestamp`, the `-systemextension` entitlements, embedded
  Developer ID profile), then `obscura`, `aitm`, then the **app with
  `--entitlements`** and its embedded profile; extend the verify step to dump
  entitlements (`codesign -d --entitlements :-`) from both and **fail** if the NE
  array lacks the `-systemextension` suffix or the app lacks
  `system-extension.install`. `notarytool`/`stapler` on the DMG are otherwise
  unchanged (nested code is covered by notarizing the outer container).
- `scripts/make-dmg.sh`: no change expected (`ditto` preserves signatures).

### D8 — User approval UX and activation

- **Activation.** The app (not the CLI) submits
  `OSSystemExtensionRequest.activationRequest` to `OSSystemExtensionManager.shared`
  early in launch; it stays alive while the request is pending.
- **Two System Settings prompts.** (1) *Login Items & Extensions → Extensions →
  Network Extensions*: approve the extension, authenticate. (2) *Add Proxy
  Configurations*: Allow. Both are required and cannot be suppressed without MDM.
- **No headless path.** Activation stays pending until a human approves and the app
  stays open; an agent driving the app cannot finish activation.
- **Operator-only approval (Architect's call, 07 precedent).** Triggering the
  sysex install/activation is an **operator** action, gated like
  `ca.allow_agent_install`: an agent (`Frontend::Mcp`) can neither install nor
  approve the extension. Matt to confirm.

### D9 — Capability surfacing and honest degradation (core-connection tie)

The macOS app already feature-detects the core it drives (core-connection spec)
and shows a health state. Phase 2 adds a **capture capability** beside it:

- **States:** `extension-not-installed` → `pending-approval` → `approved-attached`
  (control channel up) → `capturing`; plus `degraded(reason)`.
- Until `approved-attached`, every macOS wire verb returns
  `L4Unavailable { reason }` whose reason **names the extension as the path**
  (extending L4OPS-AC18 from "use a privileged remote core" to "approve the
  extension"). After attach, the embedded core captures live and the L4/HTTP
  surfaces drive fully.
- Pointing the macOS UI at a privileged Linux/remote core over the bus still
  drives L4 fully, as in Phase 1 — the extension is the macOS-*local* path, not the
  only one.

### D10 — CA / TLS

The **core terminates TLS** exactly as for an explicit proxy; the extension only
moves bytes, so it needs **neither the CA nor the key** and adds no new trust
step. The CA trust-store install and its prompts remain 07's. SNI comes from the
ClientHello (`parse_client_hello_sni` already exists in `proxy.rs`), supplemented
by `remoteHostname` for connect-by-name flows. The root sysex **must not** receive
or store the CA key; the key stays in the core only (DTS: a sysex uses the
file-based System keychain and should not share secrets with the container app).

## Acceptance criteria

Each is observable and testable. Criteria marked **[Rust]** are provable by
Rust unit/integration tests in the sandbox against synthesized flows; **[Mac]**
require a real Mac in the Terminal panel with a signed, approved extension;
**[Build]** are provable by inspecting signed artifacts in the Terminal panel.

1. **NE-AC1 — One seam, TCP → ProtocolModule.** A synthesized captured TCP flow
   (bytes + authoritative original destination + SNI) fed through the macOS
   capture backend reaches the core's protocol-general `CaptureIngress` and is
   dispatched to the HTTP module with `hint.dst` = the **original destination**
   (not the client peer); the same path the Linux/CLI L4 backend uses. **[Rust]**
2. **NE-AC2 — One seam, UDP → guarded L4 flow.** A synthesized captured UDP flow
   enters as a flow-level L4 unit behind `L4Guard`; an **out-of-scope** UDP flow
   is refused by `L4Guard` before any datagram reaches a plugin. **[Rust]**
3. **NE-AC3 — Deny-by-default below the ingress.** No captured flow (TCP or UDP)
   reaches a protocol module or L4 plugin without the core's guard passing it; a
   test proves an out-of-scope captured flow is never dispatched and an in-scope
   one is. **[Rust]**
4. **NE-AC4 — Raw packet-level L4 is honestly unavailable.** On the macOS embedded
   core, `l4.inject` / `l4.send_recv` / `l4.intercept.*` return
   `L4Unavailable { reason }` whose reason names macOS as flow-level and raw-packet
   L4 as Linux-only — never a panic, never silence. **[Rust]**
5. **NE-AC5 — Fail-open when the core is absent.** With the extension loaded but no
   control channel attached, every new flow goes direct (provider returns `false`)
   and ordinary browsing works unaffected. **[Mac]**
6. **NE-AC6 — Authenticated handoff; no plaintext to a squatter.** The control
   socket lives in a 0700 directory; the provider validates the core's code
   signature before sending any flow, and a peer failing the code requirement
   receives no flow data. **[Mac]** (transport shape also **[Rust]** at the
   core-listener side).
7. **NE-AC7 — Control/data separation & per-flow backpressure.** Control messages
   (hello, scope/intercept spec, per-flow open metadata) travel the control
   channel; each captured flow uses its own data socket; no bulk bytes cross the
   control channel. **[Rust]** (loopback round-trip) / **[Mac]** (end to end).
8. **NE-AC8 — Loop avoidance.** A capture session shows no flow originated by the
   core's own upstream dials or by the embedded `obscura` (excluded by source-app
   identity; loopback not captured). **[Mac]**
9. **NE-AC9 — Activation & two-prompt approval.** The app activates the sysex via
   `OSSystemExtensionRequest`; the user completes the two System Settings prompts;
   the capability transitions to `approved-attached`. **[Mac]**
10. **NE-AC10 — Honest degradation until approved.** Before approval the macOS
    capture-capability surface reports a not-approved state and every wire verb
    returns `L4Unavailable` naming the extension as the path; after approval the
    embedded core captures live. **[Rust]** (capability-state mapping) / **[Mac]**
    (end to end).
11. **NE-AC11 — Operator-only approval.** An agent (`Frontend::Mcp`) cannot trigger
    the sysex install or OS approval; the action is operator-gated like
    `ca.allow_agent_install`. **[Rust]** (gate) / **[Mac]** (end to end).
12. **NE-AC12 — Entitlements present (regression fixed).** The signed app and sysex
    each carry their entitlements: `codesign -d --entitlements :-` shows the NE
    array with the `-systemextension` suffix on both and `system-extension.install`
    on the app; the verify step fails the build if they are absent. **[Build]**
13. **NE-AC13 — Nested signing & notarization.** The DMG notarizes and staples with
    the sysex nested inside the app, signed inside-out with embedded Developer ID
    profiles; `spctl`/`stapler validate` pass. **[Build]**
14. **NE-AC14 — Version-bump & configuration reconcile.** A sysex change bumps the
    sysex bundle version, the host returns `.replace`, and the saved proxy
    configuration is re-enabled after the replacement (no silent disable). **[Mac]**
15. **NE-AC15 — Capture indicator & uninstall.** The app shows a visible "capture
    is on" indicator while attached, and an uninstall deactivates the sysex and
    removes the proxy configuration. **[Mac]**
16. **NE-AC16 — CA/TLS unchanged; extension holds no key.** The sysex neither
    receives nor stores the CA key; MITM TLS termination stays in the core; SNI is
    taken from the ClientHello (plus `remoteHostname` when present). **[Rust]** (no
    key reaches the backend) / **[Mac]** (real HTTPS MITM).
17. **NE-AC17 — Real in-scope flow captured end to end.** On a real Mac with the
    extension approved, a real **in-scope** HTTPS flow is captured, MITM'd, and
    appears in the flow list; a real in-scope UDP flow appears as an L4 flow;
    out-of-scope traffic is not captured. This is the milestone's acceptance bar
    (parent spec's "real packets, not screenshots"). **[Mac]**
18. **NE-AC18 — Mandatory security review.** A Stage-6 security review confirms
    deny-by-default survives the extension layer (no un-guarded flow), the handoff
    is peer-authenticated and fails open, no CA key reaches the extension, and no
    agent can install/approve it; findings block the merge. **[review]**

## Left to the builder

- Whether the captured UDP flow is a new `FlowKind`/flow variant or synthesized
  UDP frames, within "guarded identically by `L4Guard`, no raw-packet machinery."
- The control-channel wire format (framing, protobuf vs a small Rust-native
  encoding) and the per-flow data-socket handshake, within control/data separation
  and peer authentication.
- The sysex bundle id, the 0700 socket directory location, and the rendezvous
  mechanism the host uses to publish the control-socket path to the core (reuse
  the core-connection rendezvous-file precedent).
- Backoff/settle-delay constants for the version-bump configuration reconcile.
- The exact entitlement plist contents beyond the keys named in D7, and the Xcode
  project layout for the sysex target, within the signing rules.
- The source-app-identity predicate used for self-exclusion (signing identifier
  vs audit-token requirement), within "not pid-based."
- Which real in-scope target the NE-AC17 acceptance run uses (the Phase-1
  `aitm-testtarget` L4 service is loopback; loopback may not be capturable — see
  Open question — so a non-loopback in-scope target may be required).

## Resolved decisions (locked 2026-10-29, orchestrator on Matt's behalf)

The seven **(b)** open questions were ruled as recommended and are now binding on
the plan:

- **G1 (OQ1):** keep L4OPS-AC19's approved text; read it per §D2 (TCP → `ProtocolModule`
  seam, UDP → flow-level L4 behind `L4Guard`, raw-packet L4 = `L4Unavailable`).
- **Operator-only approval (OQ4):** sysex install/approval is operator-gated like
  `ca.allow_agent_install`; no agent path.
- **Parent bundle = `/Applications` (OQ6);** the Task-1 spike confirms `~/Applications`.
- **Run the Task-1 signing spike (OQ7)** — but it stays blocked until A1 (needs Matt's
  Developer ID), on his Mac via the Terminal panel.
- **Developer ID direct only; App Store out of scope (OQ8).**
- **QUIC left as direct UDP (OQ9)** — no forced QUIC→TCP fallback.
- **Multi-user: filter by audit-token UID to the approving user (OQ10).**

Matt's three **(a)** answers (2026-10-29), now also binding:

- **A1 (OQ5) — Developer account:** Matt will set up the Apple portal — two App IDs,
  Network Extension + System Extension capabilities, two Developer ID provisioning
  profiles carrying `app-proxy-provider-systemextension` (+ `system-extension.install`
  on the app). Task 1 (the signing spike) and all `[Mac]`/`[Build]` tasks wait on this.
- **A2 (OQ2) — macOS L4 ceiling:** ACCEPTED. macOS is flow-level only; raw-packet L4
  craft/inject/mutate/in-path stays Linux/CLI-only and is `L4Unavailable` on the macOS
  embedded core. No packet-tunnel second ingress.
- **A3 (OQ3) — Packaging:** **C1** — embed the sysex in `Aitmproxy.app` (one bundle).
  A CLI-only macOS user cannot activate capture without the app; accepted.

## Open questions

**None remain — all resolved (2026-10-29).** The ten items below are kept for
provenance, each tagged **[RESOLVED]**. Ordered most important first.

1. **[RESOLVED → G1]** **AC19 final wording.** Adopt **G1** (keep L4OPS-AC19's text, read it as D2:
   TCP → `ProtocolModule` seam, UDP → flow-level L4 behind `L4Guard`, raw-packet
   L4 = `L4Unavailable`), or reword to a **G2** phrasing that spells out "flows,
   not packets"? This is the central design question and may edit an
   already-approved spec's text.
2. **[RESOLVED → A2 accepted]** **Raw-packet-L4 ceiling acceptance.** Is flow-level-only on macOS (no raw
   packet craft/inject/mutate, no in-path interception; BPF capture-only is the
   theoretical ceiling and is not built) **acceptable** for AC19, or does Matt want
   a different bar (e.g. the packet-tunnel second-ingress route)? (research OQ15)
3. **[RESOLVED → A3 = C1]** **Packaging C1 vs C2.** Embed the sysex in `Aitmproxy.app` (C1, recommended —
   one bundle, serves the self-contained app) and accept that a **CLI-only macOS
   user cannot activate the extension**, or ship a separate capture-host app (C2)
   for the CLI-first story at the cost of a second bundle and a second approval?
   (research OQ12)
4. **[RESOLVED → operator-only]** **Operator-only approval.** Confirm that activating/approving the system
   extension is an **operator-only** action (no agent-driven install), gated like
   `ca.allow_agent_install`. (research OQ5)
5. **[RESOLVED → A1 Matt sets up portal]** **Developer-account state.** Does Matt's team have (or can mint) **two App IDs**
   with *Network Extensions* on both and *System Extension* on the app, and **two
   Developer ID provisioning profiles** carrying
   `app-proxy-provider-systemextension` (+ `system-extension.install` on the app)?
   Nothing here was verified against the account. (research OQ2)
6. **[RESOLVED → /Applications]** **Parent-bundle location.** Is installing to **`/Applications`** (the cask
   default) acceptable, or must `~/Applications` (where `build.sh` installs today)
   work? `OSSystemExtensionErrorUnsupportedParentBundleLocation` exists; sources
   only say "appropriate Applications directory." Cheap to settle with a spike.
   (research OQ1)
7. **[RESOLVED → yes, blocked on A1]** **Run the activation/handoff spike before the plan?** Research Candidate H
   proposes a throwaway `experiment/macos-ne-spike` that signs and activates a
   do-nothing `NETransparentProxyProvider` with Matt's team and proves one flow
   across an authenticated Unix socket. It would settle OQ4–6 above and research
   OQ3/6/7 (manual-`codesign` entitlement acceptance on macOS 27, peer-auth
   feasibility, self-exclusion identity) **before** any plan work. Recommend
   running it. Do you want it?
8. **[RESOLVED → Developer ID only]** **App Store out of scope — confirm.** Direct Developer ID only (appex is App
   Store only and needs a sandboxed core). (research OQ13)
9. **[RESOLVED → direct UDP]** **QUIC handling.** Native QUIC is not decrypted. Do you want QUIC forced to TCP
   fallback (needs the `return true` + immediate close-write workaround, with the
   UDP/Chromium flow quirks research §3.9 flags), or left as direct UDP?
   (research OQ9)
10. **[RESOLVED → filter by audit-token UID]** **Multi-user filtering.** The sysex is global and root; flows from other
    logged-in users reach the provider. Filter by audit-token UID, or capture all?
    (research OQ14)
