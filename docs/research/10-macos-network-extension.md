# macOS Network/System Extension capture path, "the Proxyman way" (L4 Phase 2 input)

> **Provenance:** AI-generated research summary produced by the Researcher
> engine on **2026-10-29**. Sources: Apple developer documentation and DevForums
> threads, the mitmproxy and mitmproxy_rs source trees, Proxyman's published docs
> and launch post, a handful of third-party GitHub issues, the aitmproxy tree, and
> a few read-only local checks on the author's Mac (macOS 27.0, build 26A428,
> Xcode 27.1, build 27A9269).
> **Method caveat:** every Apple documentation page, forum thread, GitHub file
> and web page below was read through the WebFetch or WebSearch tools, which
> summarise the page with a small model. Quotes are as the summariser returned
> them (it truncates long quotes). Apple's `developer.apple.com/documentation`
> pages are JavaScript-rendered, so they were read through the site's
> `tutorials/data/...json` endpoint. Items marked **(header)**, **(man)** or
> **(tree)** were read first-hand on this Mac or in this repo. Items marked
> **(S)** are search-result summaries only. Items marked **(3P)** are
> third-party reports (GitHub issues, forum posters), not Apple statements.
> Anything marked **unverified** was not seen in a source. No fetched page
> carried instructions aimed at this task. **Scope:** tooling-architecture
> research for an operator with written authorization to test in-scope
> targets. Nothing here is a design decision.

## 1. Question

How should aitmproxy capture traffic on macOS through a Network/System
Extension "the Proxyman way": which NetworkExtension provider feeds the core's
one protocol-general capture path, and what is the full productionization
surface (entitlement and provisioning, sysext packaging and activation, user
approval, nested signing, notarization, and the extension-to-core handoff)?

## 2. Short answer

Candidate: an `NETransparentProxyProvider` shipped as a Developer ID system
extension, as mitmproxy and Proxyman (macOS 26+) do. It sees every app's
outbound TCP/UDP flows and exchanges full bytes, so the core can MITM and
mutate. It is flow-level only: no raw packets, ICMP, or loopback by default, so
packet-level L4 craft/inject/mutate stays unavailable on macOS. The Network
Extension entitlement is self-service (no Apple approval); you need two App IDs,
two Developer ID profiles with `-systemextension` values, and
`system-extension.install`. Today's scripts give the app no entitlements.
Handoff candidate: per-flow Unix sockets plus an authenticated control channel.

## 3. Findings

All sources read 2026-10-29. "Inference" marks my reading, not a source claim.

### 3.0 What this note resolves from earlier notes and the spec

| Earlier open item | Answer here |
|---|---|
| 09 OQ5: must Apple grant the Network Extension entitlement for Developer ID? | **No.** Self-service since Nov 2016 (3.4). Apple-managed exceptions are app push providers and Hotspot Helper only. |
| 09 OQ5: `system-extension.install` entitlement and the approval flow | Restricted entitlement, authorised by an embedded profile; approval is two user prompts (3.4, 3.5). |
| 09 OQ4 / spec Part 7: which provider supports raw-L4 capture/inject and in-path mutate? | **None.** The mutating, system-wide provider is flow-level (TCP/UDP). Packet providers cannot edit; packet tunnel needs its own TCP/IP stack (3.1, 3.2). |
| Spec Part 7 groups "transparent-proxy / packet-tunnel / content-filter" as `NETransparentProxyProvider`-class | They are different class trees **(header)**: `NETransparentProxyProvider : NEAppProxyProvider : NETunnelProvider : NEProvider`; `NEPacketTunnelProvider : NETunnelProvider`; `NEFilterDataProvider` and `NEFilterPacketProvider : NEFilterProvider : NEProvider`. Only the first fits a mutating capture path. |
| L4OPS-AC19 wording: "captures live traffic through the extension into the same protocol-general seam" | True for **flows**, not **packets**. See 3.2 and Candidate G: the AC19 text needs an Architect decision. |

### 3.1 Provider choice

**What Apple and the reference tools use.**

- DTS (Quinn, Apr 2020, thread 131815): "Most folks use a content filter
  provider or a transparent proxy provider." A transparent proxy "sees traffic
  from all apps, regardless of whether they were installed via MDM or not",
  whereas an app proxy provider "is a form of per-app VPN, and thus it only sees
  traffic from specific apps" (Mar 2022 reply, same thread).
- mitmproxy's macOS local capture "first used Apple's Packet Tunnel Provider but
  found it hard to process traffic from specific apps", then "switched to the App
  Proxy Provider API", which "handles only TCP and UDP and lets the OS handle
  other flows" (mitmproxy.org post "Intercepting macOS Applications"). Its source
  confirms the class: `TransparentProxyProvider` subclasses
  `NETransparentProxyProvider`, entitlement value
  `app-proxy-provider-systemextension` (mitmproxy_rs
  `mitmproxy-macos/redirector/network-extension/`, files read through WebFetch).
- Proxyman's Network Extension (launched 2026-10-06, BETA, off by default):
  "Built on Apple's transparent proxy Network Extension API" (`NETransparentProxyProvider`
  named in its docs), a "native macOS system extension" signed with a Developer
  ID certificate and notarized, **Proxyman PRO direct edition only, macOS 26 or
  later, not in Setapp** (proxyman.com post and docs). It captures **HTTP and
  HTTPS** only as marketed; "does not bypass certificate pinning or decrypt
  native QUIC" (proxyman.com/network-extension).

**Comparison for the three required properties.**

| Provider (macOS packaging) | (a) System-wide, all apps | (b) Full bidirectional bytes, can mutate | (c) Fits one protocol-general ingress | Evidence |
|---|---|---|---|---|
| **`NETransparentProxyProvider`** (sysext; appex is App Store only) | **Yes**, per `includedNetworkRules`; per-flow keep or let-pass (`return false` goes direct) | **Yes**: provider reads and writes each flow's bytes (`readData`/`write`, `readDatagrams`/`writeDatagrams`) and so can edit or park | **Yes for flows**: TCP stream maps to `ByteStream`; UDP is datagram-shaped | TN3134 table; header; DTS 131815; mitmproxy |
| `NEAppProxyProvider` (sysex) | **No on macOS**: per-app VPN, only apps opted in (MDM app mapping) | Yes (same flow API) | Same flow shape | DTS 131815 |
| `NEPacketTunnelProvider` (sysex; appex App Store only) | Yes, if a default route goes into the tunnel | **Packets only**: raw IP in/out; you must terminate and re-originate TCP/UDP yourself | Packet-shaped; no flow or app metadata | WWDC25 234; 09 3.4; mitmproxy post |
| `NEFilterDataProvider` (sysex only) | Yes; sees TCP/UDP flows and "other IP protocol traffic, such as ICMP" | **No**: verdicts are allow/drop/pass-and-peek **(header)**: `allowVerdict`, `dropVerdict`, `dataVerdictWithPassBytes:peekBytes:` | Observe-only | WWDC25 234; header |
| `NEFilterPacketProvider` (sysex only) | Yes, L2 packets | **No** edit; allow/drop/delay (09 3.4) | Packet-shaped, observe/park only | 09; header |

Notes behind the table:

- **Class check (header):** `NETransparentProxyProvider : NEAppProxyProvider`;
  available macOS 11.0+. Documented differences from its parent: returning `NO`
  from `handleNewFlow:` "causes the flow to proceed to communicate directly with
  the flow's ultimate destination, instead of closing the flow with a 'Connection
  Refused' error"; it ignores DNS and proxy settings; "connect by name" flows
  "will not bypass DNS resolution". The Handling Flow Copying article calls it
  "the only provider that lets you choose per flow whether to handle it or let
  the system do it".
- **Packet tunnel for anything else is discouraged:** WWDC25 session 234: "Use
  NEPacketTunnelProvider only to tunnel IP traffic... will not receive flow or
  application level metadata needed to do other things, like proxying DNS
  requests or content filtering." A packet tunnel capture would need a user-space
  TCP/IP stack in the core (09 3.3 records that `mitmproxy_rs` does exactly that
  with a tun device on Linux). Inference: that is a second ingress shape
  (packets), not the one seam.
- **Packaging:** TN3134 (JSON, read 2026-10-29): transparent proxy and app proxy
  and packet tunnel are "system extension, 10.15, no restriction" on macOS and
  "app extension ... App Store only"; content filter, DNS proxy and packet
  filter are sysex-only. "If a macOS row doesn't mention the 'App Store only'
  restriction, the provider supports both App Store distribution and direct
  distribution using Developer ID signing."
- **Per-flow identity:** `NEFlowMetaData` **(header)** gives
  `sourceAppSigningIdentifier` (may be empty for system processes),
  `sourceAppUniqueIdentifier`, `sourceAppAuditToken` (macOS 10.15+), and
  `filterFlowIdentifier`. `NEAppProxyFlow.remoteHostname` is set only "if the
  flow was created by passing a hostname to a 'connect by name' API" (macOS
  11.0+). TCP: `remoteFlowEndpoint` (`nw_endpoint_t`, macOS 15+; the older
  `remoteEndpoint` is deprecated). UDP: `readDatagramsAndFlowEndpoints...` and
  `localFlowEndpoint` (macOS 15+). **mitmproxy's source still calls the deprecated
  `NWHostEndpoint` APIs** (WebFetch of `FlowExtensions.swift` and the provider);
  a new provider targeting macOS 26+ should not copy them.

### 3.2 What a flow-level capture means for "all protocols incl. future L4"

- **TCP and UDP only (header).** `NENetworkRuleProtocol` has exactly three
  values: `Any` ("Matches TCP and UDP traffic"), `TCP`, `UDP`. mitmproxy says the
  same ("handles only TCP and UDP", Proxyman: HTTP/HTTPS). No ICMP, no raw IP,
  no other IP protocols. Only `NEFilterDataProvider` sees ICMP, and it cannot edit.
- **Outbound only (header):** the included-rules doc says "The matchDirection
  property must be NETrafficDirectionOutbound" (`NETransparentProxyNetworkSettings.h`).
- **Loopback is excluded by wildcard rules (header):** "If the address is a
  wildcard address (0.0.0.0 or ::) then the rule will match all destinations
  except for loopback... To match loopback traffic set the address to the
  loopback address." DevForums **(3P posters, DTS surprised)**: explicit
  `127.0.0.1/32` rules did not deliver loopback flows (threads 794776, Jul 2025;
  680190, after macOS 11.3, reporter saw `appliesToLoopback = NO` in logs;
  666130). Consequence for us: the app's bus (loopback TCP) cannot be captured
  by mistake, which also removes a loop; but **`aitm-testtarget`'s loopback L4
  service cannot be a Phase-2 capture target** unless explicit loopback rules are
  proven to work on macOS 27 (open question 4).
- **DNS (header):** "A port string of '53' is not allowed. Destination
  Domain-based rules must be used to match DNS traffic."
- **What the unit is:** a TCP stream (bidirectional bytes, no segment
  boundaries) or a UDP flow (datagrams plus per-datagram remote endpoints).
  There are no IP headers, TCP flags, retransmissions, or fragments. Inference:
  "L4" via the extension means **flow-level L4**: opaque TCP bytes and UDP
  datagrams with endpoints and process identity. The packet model in the tree
  (`L4Packet { bytes: raw on-wire bytes, decoded: PacketSummary, .. }`,
  `crates/aitm-proto-l4/src/flow.rs`, tree) assumes IP packets, so extension-fed
  flows would need either a new flow kind or synthesized frames. Not decided here.
- **Packet-level mutate on macOS is closed again:** 09 3.4 already found no
  supported packet-mangle path; this note's provider survey agrees (the only
  providers that see packets cannot edit; the tunnel needs a full stack).
  Phase-1's macOS answer for raw capture stays BPF capture-only (08).

### 3.3 How the reference implementations are built (mitmproxy_rs)

Read through WebFetch of `github.com/mitmproxy/mitmproxy_rs` `main`, 2026-10-29.

- **Components:** `mitmproxy-macos/redirector/` holds `macos-redirector` (the host
  app that "sets up and hosts the network extension"), `network-extension/` (the
  sysex), and `ipc/` (protobuf). Xcode project, not SwiftPM.
- **Start sequence (redirector README):** (1) `start_local_redirector` copies the
  redirector app into `/Applications`, "which system extension installation
  requires"; (2) the Rust side opens a Unix socket listener and launches the app,
  passing the socket path; (3) the app installs the sysex and configures the
  transparent proxy; (4) the OS starts the sysex, which connects back over the
  socket as a **control channel**; (5) Rust sends the intercept spec; (6) for each
  matching flow the sysex opens a **separate Unix socket per flow** "to give each
  connection its own buffers and backpressure".
- **Rust side (`src/packet_sources/macos.rs`):** binds
  `/tmp/mitmproxy-<pid>`, sets no permissions on it; launches the redirector with
  `Command::new` and the socket path as the sole argument; waits up to 5 s for the
  control connection; length-delimited protobuf `InterceptConf` out; per-flow
  handshake is a big-endian `u32` length plus a protobuf `NewFlow` (TCP or UDP);
  **TCP payload after the handshake is raw bytes, UDP is length-delimited
  protobuf `UdpPacket` per datagram**.
- **Sysex (`TransparentProxyProvider.swift`):** reads the socket path from
  `protocolConfiguration.serverAddress`; one catch-all included rule (any remote,
  any local, prefix 0, protocol any, outbound); `handleNewFlow` resolves the source
  process from `sourceAppAuditToken`, returns `false` (flow goes direct) if there
  is no spec, no process info, or the spec does not match; otherwise `flow.open`,
  connects the per-flow socket, sends the handshake, and runs two copiers.
  Backpressure is read-one-then-write-one (inbound reads capped at 8 KB).
- **Selection and loop avoidance:** the spec is a list of patterns, each a PID or a
  substring of the process **path**; a leading `!` excludes. The Python side
  always sends `!<own pid>` (`mitmproxy/proxy/mode_servers.py`,
  `spec = f"{self.mode.data},!{os.getpid()}"`). The sysex itself has no
  self-exclusion code. DTS (Matt Eaton, 2020, thread 658631) recommends the audit
  token path for ignoring flows and says `excludedNetworkRules` cannot express
  "not my process".
- **Host app (`app.swift`):** `OSSystemExtensionRequest.activationRequest`, then
  loads `NETransparentProxyManager`s, creates or reuses one with
  `providerBundleIdentifier` and `serverAddress` = socket path, saves, reloads,
  `startVPNTunnel()`. `requestNeedsUserApproval` only logs. `actionForReplacingExtension`
  always returns `.replace`. The README says to **bump the extension version on
  every change, or existing installs are not replaced**.
- **Entitlements (read):** extension: `com.apple.developer.networking.networkextension`
  = `["app-proxy-provider-systemextension"]` only; app: the same array plus
  `com.apple.developer.system-extension.install` = true. The extension entitlement
  file shows **no App Sandbox key**, which is consistent with it opening
  `/tmp` sockets.
- **Build and notarize (`.github/scripts/build-macos-redirector.sh`):** two
  Developer ID provisioning profiles written from secrets (app and extension); a
  temporary keychain; `xcodebuild archive`; `xcodebuild -exportArchive` with an
  `ExportOptions.plist` (`method developer-id`, `signingStyle manual`, a profile
  name per bundle id, `teamID`); `ditto -c -k --keepParent`; `xcrun notarytool
  submit --wait`; `xcrun stapler staple` on the `.app`; tarball. The script never
  calls `codesign` directly. (Whether the export step hit the `-systemextension`
  Xcode bug in 3.4 is not stated; they use manual signing.)
- **Proxyman's CLI** (`proxyman-cli network-extension` status, install, uninstall,
  enable, disable, retry; "Proxyman must be open") is the same shape: the CLI
  drives the GUI app, which owns the entitlement. Inference for CLI-first: any
  CLI path on macOS needs a host app on disk.

### 3.4 Entitlement and provisioning reality

**Is Apple approval needed?** For Network Extension providers, **no**. Sources:

- DTS "Network Extension Framework Entitlements" (thread 67613, first posted
  2016-11-11): "Originally, using any of these facilities required authorisation
  from Apple... In Nov 2016 this policy changed for Network Extension providers.
  Any developer can now use the Network Extension provider capability like they
  would any other capability." Exceptions: **app push providers** and **Hotspot
  Helper** still need an Apple-managed capability.
- Apple's entitlement page (`com.apple.developer.networking.networkextension`):
  no request language; Developer ID steps are "enable the Network Extension
  capability for your Developer ID-signed app. Generate a new provisioning
  profile and download it."
- developer.apple.com/system-extensions: you "need to request an entitlement from
  Apple" for DriverKit, for letting "other developers use your system
  extensions" (the redistributable entitlement), or for EndpointSecurity. Network
  extensions are not in that list.
- Managed-capability help page: "Managed capabilities are app services that need
  an entitlement assigned to your account by Apple... Required role: Account
  Holder." Network Extension is not named there.

**Exact entitlements.**

| Target | Key | Value for **development** (Apple Development identity) | Value for **Developer ID** distribution |
|---|---|---|---|
| Sysex **and** host app | `com.apple.developer.networking.networkextension` (array) | `app-proxy-provider` | `app-proxy-provider-systemextension` |
| Host app | `com.apple.developer.system-extension.install` (bool) | `true` | `true` |
| Both (manual signing) | `com.apple.application-identifier` = `TEAMID.bundle-id`; `com.apple.developer.team-identifier` | required claims | required claims |

- Value list and meaning: `app-proxy-provider` "The APIs you use to proxy TCP and
  UDP connections"; `app-proxy-provider-systemextension` "...when signed with a
  Developer ID profile" (Apple entitlement page). A transparent proxy uses the
  app-proxy value (mitmproxy's files; Apple's page has no separate
  "transparent-proxy" value).
- DTS (Quinn, thread 800887 rev. 2025-11-06): "both the app and the extension
  must be signed with the `com.apple.developer.networking.networkextension`
  entitlement. This is a restricted entitlement, that is, it must be authorised
  by a provisioning profile." Developer ID: "use the values with the
  `-systemextension` suffix". The suffix exists so "Developer ID signed" sysexes
  are identifiable; DTS (Quinn, Jun 2021, thread 664126): "Apple made a specific
  policy decision to support NE sysex (but not appex) providers in Developer ID
  apps."
- `system-extension.install` page: "Add this entitlement for all system
  extension types." Quinn (Jun 2025, thread 790296; the log there lists it among
  "Unsatisfied entitlements") treats it as covered by the same rule: restricted
  entitlements "aren't authorised by a provisioning profile" fail. The "System
  Extension" capability on the App ID provides it (**(S)**, third-party GitHub
  issue mirage #3 describes `xcodebuild -allowProvisioningUpdates` adding it; the
  portal flow for macOS App IDs is otherwise **unverified**).
- **Manual signing needs the App ID claim:** Quinn (Jun 2025, thread 790296):
  "Your app is missing the App ID entitlement (`com.apple.application-identifier`)...
  that entitlement is used to tie your app to its profile." Xcode adds it
  automatically; a script that calls `codesign --entitlements` must include it
  (inference from the quote).
- **Launch failures if wrong:** Quinn (Aug 2025, thread 795579) checklist: the
  app "has an embedded profile; that profile is a Developer ID profile; includes
  the certificate you used to sign the app; its entitlement allowlist includes
  all of the restricted entitlements the app claims". "The number one cause of the
  problem is forgetting to embed a Developer ID profile." The log symptom is
  "Unsatisfied entitlements: com.apple.developer.system-extension.install,
  com.apple.developer.networking.networkextension, com.apple.developer.team-identifier".

**What the developer account must have (checklist for Matt; none of it was
verified against his account).**

1. A **Developer ID Application** certificate (the existing `notarize-dmg.sh`
   already depends on one).
2. **Two explicit App IDs**, for example the app (`com.mrbrutti.aitmproxy`, from
   `Info.plist.in`) and a new sysex bundle id (naming is a design call). Mitmproxy
   uses exactly two, with two profiles. DTS says the sysex needs its own profile
   and the app needs one too (Quinn, thread 737894).
3. **App ID capabilities:** *Network Extensions* on both (with the app-proxy
   provider box); *System Extension* on the app.
4. **Two Developer ID provisioning profiles**, one per App ID, whose allowlist
   carries `app-proxy-provider-systemextension` (the portal adds the suffix itself
   for Developer ID, DTS Quinn in thread 786886) and, for the app,
   `system-extension.install`. Each is embedded as `Contents/embedded.provisionprofile`
   in its own bundle (Quinn's recipe in thread 737894, 3.6).
5. **For day-to-day development, Apple Development identity plus development
   profiles** with the unsuffixed value. Quinn (thread 737894 and 795579): "Don't
   use Developer ID for day-to-day development." Quinn (thread 805996): SIP does
   not have to be disabled to test a **NE** sysex with an Apple Development cert.
6. Xcode: Quinn's post says Xcode 26 and earlier do not know the `-systemextension`
   requirement and mis-sign on export; "Xcode 27.0b1... it should now be possible
   to export a Developer ID signed app with an Network Extension system extension
   from the Xcode organiser" (thread 737894). This Mac has Xcode 27.1 (local
   `xcodebuild -version`). Not tested.
- **What I could and could not see locally:** `security find-identity -v -p
  codesigning` returned zero identities inside this sandbox (probably keychain
  access; not a statement about Matt's keychain), and four `.mobileprovision`
  files exist under `~/Library/MobileDevice/Provisioning Profiles`. I did **not**
  open them. A one-line check Matt can run:
  `security cms -D -i <profile> | plutil -p - | grep -A6 networkextension`.

### 3.5 Packaging, activation, and user approval

**sysex vs appex.** Developer ID distribution requires a **sysex**; appex is
Mac App Store only for transparent proxy, app proxy and packet tunnel (TN3134;
Quinn thread 805996: "we only support appex packaging in Mac App Store apps...
converting an appex to a sysex is not a trivial task"). App Store distribution
is out of reach for this product in practice (embedded core spawning, obscura JIT
entitlements; inference). Proxyman ships the direct edition only.

**Bundle layout and keys.**

- Location: "System extensions reside inside your app's
  `Contents/Library/SystemExtensions` folder" (Apple, Installing System Extensions
  and Drivers). Sysex is "effectively a launchd daemon", runs **as root**,
  "global to the system"; the container app runs as the user; activation "copies
  it to a protected location", so **frameworks must live inside the sysex**
  (`Contents/Frameworks`, rpath `@executable_path/../Frameworks`), not the app's
  (Quinn, thread 800887).
- Sysex `Info.plist` (**(S)** for `SYSX` and the usage string, forum search
  summaries and WWDC19 702 transcript; `NetworkExtension`/`NEProviderClasses` from
  the SDK **(header)**): `CFBundlePackageType` = `SYSX`;
  `NSSystemExtensionUsageDescription` (user-visible reason); a `NetworkExtension`
  dictionary with `NEProviderClasses` mapping `com.apple.networkextension.app-proxy`
  to the provider class, and optional `NEMachServiceName` (3.7). `main.swift`
  calls `NEProvider.startSystemExtensionMode()` "as early as possible"
  (**(header)** and Quinn thread 725805) then `dispatchMain()`.
- **Language:** the provider is Swift or Objective-C. A Rust sysex would be via
  `objc2-network-extension` (crates.io, 0.3.2, 2025-10-04, "Bindings to the
  NetworkExtension framework"; **unverified** beyond the registry entry), which
  would very likely need `unsafe` calls (inference) against the workspace's
  `unsafe_code = "forbid"` (07 3.4). The
  existing `apps/mac` is Swift, so the sysex is naturally Swift; `aitm` stays
  Rust and unprivileged.

**Activation.** Container app submits
`OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:queue:)`
to `OSSystemExtensionManager.shared` "as early as possible in your app's launch".
Per the SDK header **(header, SystemExtensions.h)**: `requestNeedsUserApproval:`
fires when approval is needed, "the activation request will remain pending until
user approves, or until the application exits" (so the app must stay alive);
`request:actionForReplacingExtension:withExtension:` decides replace vs abort and
"if the local system has System Extension developer mode enabled, this callback
will always fire"; a result of `...WillCompleteAfterReboot` means inactive until
reboot. Error codes in the header include `MissingEntitlement` (2),
`UnsupportedParentBundleLocation` (3), `CodeSignatureInvalid` (8),
`ForbiddenBySystemPolicy` (10), `AuthorizationRequired` (13). The system verifies
the location, signature, that the entitlements match those "granted to your
development team", and the identifier (Apple article).

**Must the app be in `/Applications`?** Apple: "Your app is installed in an
appropriate `Applications` directory of the system." Quinn (thread 725805):
"the container app must be in the Applications directory", with footnote "Unless
you disable SIP". mitmproxy copies its host app into `/Applications`. **Whether
`~/Applications` (where `apps/mac/build.sh` installs today) counts is not stated
in any source read** (open question 1). The Homebrew cask target is `/Applications`
by default (**inference**; the cask file is in the separate tap, not read).

**User approval (two prompts), macOS 26 and 27.**

1. **Extension approval:** System Settings, General, Login Items & Extensions,
   Extensions, "By App" or "By Category", Network Extensions, toggle the extension
   on, authenticate (ESET KB7636, heading "macOS Tahoe (26) and Golden Gate (27)":
   same steps for both; Proxyman docs: "By Category -> Network Extensions, then
   enable Proxyman"). Quinn's debugging post (thread 725805) still says "Each
   activation must be approved in System Settings > Privacy & Security"; the two
   wordings differ and I did not reconcile them on a macOS 27 machine.
2. **Network configuration:** "Add Proxy Configurations" alert, choose Allow
   (Proxyman, ESET). DTS (Matt Eaton, thread 658961, Sep 2020): "For general use
   cases the user will always need to allow the installation of the Network System
   Extension and allow the Network Configuration to be saved on the machine... you
   should want to keep this prompt available." MDM can pre-approve the extension;
   the proxy-configuration prompt cannot be suppressed for a transparent proxy
   without MDM (same thread).
3. No headless path. The pending-until-approved behavior above means an agent
   driving the app cannot finish activation; this is the same fact 07 recorded for
   trust-store prompts. The existing `ca.allow_agent_install` / `scope.allow_agent_widen`
   style of gate is the precedent (spec Part 2.3).
4. **macOS 27 specifics:** I found **no Apple release note** changing system
   extension or transparent-proxy behaviour in macOS 27. A third-party API diff
   (miniswift.run, **(S)**) lists 19 added NetworkExtension APIs, none
   transparent-proxy specific; Apple's WWDC26 deployment page adds a declarative
   `dns-proxy` configuration and stricter TLS checks for some system processes
   (**(S)**). Proxyman and ESET document macOS 27 as supported.

**Lifecycle after approval.**

- The sysex stays active across reboot (**(3P)** pia-foss/desktop #94);
  activation is replace-on-higher-version;
  deleting the app deactivates its extensions (WWDC19 702); a `deactivationRequest`
  also exists. In development "each activation must be approved"; rebuilding a
  sysex needs deactivate then reactivate; leftover deactivated sysexes clear on
  restart (Quinn thread 725805).
- **Persistence of the proxy configuration is fragile (3P):** (a) leash #58
  (closed 2026-10-17): after a sysex **version bump** "the NE configuration ends
  up disabled"; their fix needed a settle delay, a replaced-extension flag, and a
  connected-check; (b) pia-foss/desktop #94 (macOS 26.3, open): macOS
  "intermittently forgets" the user's proxy-configuration approval across reboots
  so the prompt reappears; headless machines stay broken. Both are reports, not
  Apple statements.
- **Always-on side effect:** once saved and enabled, the configuration outlives
  the host app and core. A provider that is loaded while the core is gone must
  **fail open** (return `false` so flows go direct); nothing in NE does that for
  you (search found no source; Inference). mitmproxy does it by returning `false`
  when it has no spec.

### 3.6 Signing and notarization mapped onto the existing scripts

**What the scripts do today (tree, read 2026-10-29).**

| File | Behaviour that matters here |
|---|---|
| `apps/mac/build.sh` | SwiftPM build, then **hand-assembles** `~/Applications/Aitmproxy.app`: copies the binary into `Contents/MacOS`, writes `Info.plist` from `Info.plist.in` with `sed`, bundles the core under `Contents/Resources/core/{aitm,obscura}`. Signs obscura (with `EmbeddedObscura.entitlements`) and `aitm`, then `codesign --force --sign "$identity" "$app"` for the outer app with **no `--entitlements`**. Identity: first "Apple Development" or ad hoc (`-`). |
| `scripts/notarize-dmg.sh` | Re-signs inside-out with Developer ID + `--options runtime --timestamp`: obscura (entitlements), `aitm`, then `codesign --force ... --sign "$dev_id" "$app"` (again **no `--entitlements`**), `codesign --verify --deep --strict`, builds the DMG via `make-dmg.sh`, signs the DMG, `notarytool submit --wait` with an ASC API key, `stapler staple` the **DMG**, `stapler validate`, `spctl`. |
| `scripts/make-dmg.sh` | `ditto` the app into a staging folder with an `/Applications` symlink, `hdiutil create ... UDZO`. Reads name and version from the app's `Info.plist`. |
| `scripts/package.sh` | Builds web UI and `cargo build --release -p aitm`, downloads `obscura`, writes a CLI tarball. Does not touch the app or a sysex. |
| `Info.plist.in` | `LSMinimumSystemVersion 26.0`, bundle id `com.mrbrutti.aitmproxy`. |

**Why this matters.** The `codesign` man page **(man)**: re-signing with
`--force` and no `--preserve-metadata`: "If this option is absent, any old
signature has no effect on the signing process." So with no `--entitlements`
flag the outer app is signed with **no entitlements at all**, today and after
any re-sign. For an NE host the entitlements must be given explicitly (and the
sysex must be signed first). `--deep` for signing is "(DEPRECATED for signing as
of macOS 13.0)" and "almost never what you want" (man); the scripts already
sign by hand, which is correct.

**Sign order and recipe (Quinn, thread 737894, quoted shape).** For Developer
ID, sign inside-out: the sysex first, then the app; both with `--timestamp -o
runtime` and an explicit `--entitlements`; each bundle carries its own
`embedded.provisionprofile`: app at `Contents/embedded.provisionprofile`, sysex at
`Contents/Library/SystemExtensions/<id>.systemextension/Contents/embedded.provisionprofile`;
"Re-sign any other code (frameworks, app extensions) as well"; "Notarisation is
manual, since you're bypassing the Xcode Direct Distribution workflow." Quinn's
other posts: notarize "only the outermost container" (here the DMG, which the
script already does) and staple that container (thread 701581); a stapled DMG
does not by itself say anything about the app after it is dragged out (not
stated in the source), so stapling the `.app` before the DMG is built is a
candidate, **unverified**.

**What each script would need (candidate edits, not decisions).**

| File | Addition |
|---|---|
| `apps/mac/build.sh` | (1) Build the sysex target (SwiftPM `executableTarget`, or a small Xcode project) and **assemble** `Contents/Library/SystemExtensions/<id>.systemextension/Contents/{MacOS,Info.plist}` with `CFBundlePackageType SYSX`, `NSSystemExtensionUsageDescription`, `NetworkExtension.NEProviderClasses`. (2) Copy each provisioning profile to its `embedded.provisionprofile` (development profiles in dev). (3) Sign the sysex with its entitlements file **before** the app; sign the app with an entitlements file (`application-identifier`, `team-identifier`, NE array, `system-extension.install`). (4) Install to `/Applications` (or prove `~/Applications` works). Dev identity must be a real Apple Development cert: ad hoc (`-`) cannot carry restricted entitlements (Quinn: they "must be authorised by a provisioning profile"). |
| `scripts/notarize-dmg.sh` | (1) Re-sign the **sysex** first with Developer ID, `--options runtime --timestamp`, entitlements (the `-systemextension` values), and Developer ID profile embedded. (2) Re-sign `obscura`, `aitm`, then the **app with `--entitlements`** and the Developer ID app profile embedded. (3) Extend the verify step to dump entitlements from both (`codesign -d --entitlements :-`) and fail if the NE array lacks the suffix. (4) `notarytool` and `stapler` unchanged (nested code is covered by notarizing the DMG). |
| `scripts/make-dmg.sh` | No change expected (uses `ditto`, which preserves signatures per its own comment). |
| `scripts/package.sh` | No sysex; only if the CLI gains an "install host app" step (3.7 candidate C). |
| New: entitlement plists | Two files: `apps/mac/Aitmproxy.entitlements` (app) and a sysex one. Do **not** reuse `EmbeddedObscura.entitlements` (it is for obscura only, per its own comment). |
| Credentials | Two Developer ID profiles stored outside the repo, next to the existing `~/.appstoreconnect/` pattern (the script header already keeps credentials out of the repo). |

**Distribution consequence.** Developer ID direct distribution only (App Store
needs appex plus a sandboxed core, 3.5). The cask puts the app in `/Applications`,
which satisfies the location rule; mitmproxy also ships its sysex through
Homebrew (mitmproxy.org post, "signed and notarized system extension").

### 3.7 The extension-to-core handoff

**What must cross the boundary, per flow** (derived from 3.1 and the tree): a
flow id; protocol (TCP or UDP); the **original remote endpoint** (IP:port) and
`remoteHostname` when present; source app identity (signing identifier, audit
token or pid); local endpoint for UDP; then the byte stream (TCP) or datagrams
(UDP). The core then does what it already does for an accepted connection.

**How it lands on today's seam (tree, read 2026-10-29).**

- `ProtocolModule::spawn(io: ByteStream, ctx: ModuleCtx)` plus
  `NextLayerHint { dst, is_tls, client_hello_sni, alpn, first_bytes, from_upgrade }`
  (`crates/aitm-core/src/protocol.rs`). A flow from the extension is a
  `ByteStream` plus a hint, so L7 protocol modules need no change in shape.
- **But `handle_conn` fills `hint.dst` with the accepted peer address**
  (`crates/aitm-core/src/proxy.rs`, `dst: peer`), i.e. the client, not the
  destination, because an explicit proxy learns the target from CONNECT or the
  request. A capture ingress knows the destination up front, and the hint has no
  field for "this destination is authoritative" or for source-app identity.
  Whether to add fields to the hint, carry them in `ModuleCtx`, or wrap them in
  the ingress is an Architect call; the spec's "no `aitm-core` edits" constraint
  was M5's (L4OPS Constraints) and the ingress is meant to sit in the `aitm`
  wiring layer.
- **Unclaimed flows are dropped today:** `handle_conn` logs "no protocol module
  claimed the connection" and returns, closing the stream. For explicit proxying
  that is harmless; for a system-wide extension a dropped flow **breaks the app's
  connection**. Since `handleNewFlow` must answer `true` or `false` immediately,
  before the core can sniff the first bytes, either (a) the provider only takes
  flows the core wants (scope or app rules), or (b) the core needs a universal
  passthrough that dials the original destination and tunnels bytes verbatim.
  `aitm-plugin-passthrough` exists (tree) but is host-pinned by SNI. Not decided.
- **The L4 module is not an acceptor today:** `aitm-proto-l4`'s `L4Module` is a
  `Plugin` plus `Command` registrar ("command-driven, not acceptor-driven: it
  has no listening socket to take over", `module.rs`). Its guard is `L4Guard`.
  The Phase-1 `CaptureIngress` of the operator-surfaces plan (Task 10, "a
  wiring-layer boundary") **is not in this worktree** (no `ingress` under
  `crates/aitm/src`, HEAD `44f02be`), so what the extension plugs into is still
  unbuilt. The research input to that task: the extension's native unit is a
  flow, so the boundary must accept "stream" and "datagram" units, not only
  packets.

**Transport options, with evidence.**

| Option | Evidence | Fits | Costs and risks |
|---|---|---|---|
| **Unix domain sockets: control socket plus a socket per flow** (mitmproxy) | 3.3. Sysex has no sandbox key in mitmproxy's entitlements; raw bytes per flow give independent backpressure | Core stays a plain tokio listener; maps to `ByteStream`; UDP framing is ours | Socket path is user-writable: mitmproxy uses `/tmp/mitmproxy-<pid>` and sets **no permissions** (3.3), so a local process can squat the path; a **root** sysex then hands plaintext flows to it. Needs a 0700 directory and **peer authentication in the sysex**: `LOCAL_PEERCRED` **(man, unix(4))** and `LOCAL_PEERTOKEN` **(header, `sys/un.h`: "retrieve peer audit token")** exist, so the sysex can check the listener's code signature. |
| **Loopback TCP with token** (today's bus pattern) | The app's bus is loopback TCP with a per-launch token and a 0600 rendezvous file (core-connection spec, tree) | Reuses the rendezvous idea; loopback is not captured by wildcard rules (3.2) | Any local process can connect (token only); extra port; bulk bytes over a JSON-RPC bus is wrong, so this would be a **second** listener anyway |
| **XPC (Mach service, `NEMachServiceName`)** | DTS (Quinn, thread 800887): in a sysex, app-provider messages are "supported, but they are rarely used. Rather, most products use XPC"; sysex publishes `NEMachServiceName`, app uses `NSXPCConnection(machServiceName:options:.privileged)`; the endpoint is in the global namespace so "Any process on the system can open a connection to it"; **one named endpoint, one listener per sysex**; multiple GUI users may each connect. `NSXPCConnection.setCodeSigningRequirement(_:)` (macOS 13.0+) enforces a peer requirement and "invalidates" the connection on mismatch | Best-documented control plane with built-in peer requirement | Not a byte-stream API: bulk flow data over XPC messages has no stream backpressure. File descriptors can be passed (`NSFileHandle` over `NSXPCConnection`, `xpc_fd_create`; **(S)**, with a 2024 forum report of a decode failure and an ownership caveat), so XPC could carry a control channel and hand over one socketpair per flow (**unverified**) |
| **`sendProviderMessage` / `handleAppMessage`** | **(header)** on `NETunnelProviderSession` and `NETunnelProvider`; DTS: "rarely used" for sysex | Small control messages | Not a data plane |
| **Hybrid: XPC (or authenticated UDS) control, per-flow UDS data** | Combination of the above | Apple-recommended control plus mitmproxy-proven data | Two mechanisms to build and test |

**How `apps/mac` fits (tree).** The app already supervises the embedded core:
fresh CSPRNG token, 0600 per-launch config, a rendezvous file the core writes
after bind, restart with backoff (`Bus/EmbeddedCore.swift`,
`EmbeddedCoreController.swift`; core-connection spec). The app is **unsandboxed**
(no app entitlements today). The same actor could (1) activate the sysex and
save the `NETransparentProxyManager` (these calls require the entitlements, so
only a bundled host can do them), (2) publish the capture-ingress endpoint
through the existing rendezvous, (3) surface "extension approved and attached"
as a capability beside the existing `CoreHealthState`, honest-degraded until
approved (spec Part 7 obligation 3). A CLI-only `aitm` on macOS cannot activate
the sysex by itself; it could only attach to an already-approved extension, or
drive the app (Proxyman's CLI pattern).

**Loop avoidance (the core's own traffic).** The core's upstream dials and the
embedded obscura browser's traffic are ordinary flows to the provider. Options
seen: exclude by pid from the control channel (mitmproxy; pid reuse and ordering
are the caveats, Inference), or by `sourceAppSigningIdentifier` / audit-token
requirement (DTS in thread 658631; Quinn's `SecCodeCopyGuestWithAttributes`
example, thread 128423, not read). Loopback traffic (the bus, obscura to
core on 127.0.0.1) is not captured by wildcard rules, which removes the proxy
port from the loop (3.2). `NEAppProxyFlow.setMetadata(_ parameters:)` **(header,
macOS 10.15.4)** exists to give "accurate source app information" to a
connection the provider opens itself; relevant only if the *provider* dials
upstream.

**Guards and scope (deny-by-default).** Three places can enforce scope, and
none is chosen here:

1. **Provider rules.** `includedNetworkRules` / `excludedNetworkRules`
   (exclusion wins, **(header, docs)**). DTS (Matt Eaton, Feb 2022, thread 699972):
   "The provider needs to be restarted for any rules you add/remove to take
   affect... hot-restarting the provider over and over on the fly is not a
   recommended path." So scope **changes** cannot cheaply rewrite the rules.
2. **Per-flow decision in `handleNewFlow`.** DTS's workflow (thread 664120):
   "filter on all traffic, decide if the application is coming from an app you
   want to filter and return true... Return false to let the flow traverse the
   system as normal." Cost: every flow enters the provider process.
3. **The core's guard below the ingress** (`ScopeRateGuard`, `L4Guard`), which the
   spec already requires (Part 7 obligation 2) so an extension-fed flow is
   guarded identically.

Discarding rather than passing a flow is awkward: DTS (Matt Eaton, thread
664120): "For NETransparentProxyProvider discarding the flow would be an
enhancement request"; workarounds "Return YES from handleNewFlow: and then
immediately call closeReadWithError: and closeWriteWithError:" (May 2021; one
reporter confirmed it on 10.15.7, not on 11). Relevant to forcing HTTP/3 to
fall back to TCP, since Proxyman states native QUIC is not decrypted.

### 3.8 TLS and the CA

- The **core terminates TLS** exactly as with an explicit proxy; the extension
  only moves bytes, so the extension needs neither the CA nor the key. The CA
  trust-store install, its Touch ID/admin prompt, and the "never hand the key to
  anything else" rule are 07's (3.1, 3.7). The extension adds no new trust step.
- Proxyman documents the same split: "Capturing traffic and decrypting HTTPS are
  separate steps"; Node, Ruby and Python "may need" their own trust setup; no
  pinning bypass.
- SNI extraction on a raw ClientHello already exists in the acceptor
  (`parse_client_hello_sni`, `proxy.rs`). `remoteHostname` can supplement it for
  connect-by-name flows (header). Whether ECH or SNI-less clients matter here is
  **unverified**.
- A root sysex must not receive or store the CA key. DTS (Quinn, thread 800887):
  the sysex "doesn't have access to the data protection keychain. It must use the
  file-based keychain, and specifically the System keychain", and secrets should
  not be shared with the container app; consistent with keeping the key in the
  core only.

### 3.9 Operational risks reported in the field

All **(3P)** forum posters or GitHub reporters unless marked DTS. None is
verified on macOS 27.

- **Returning `false` is not always clean.** AirDrop breaks with a provider that
  returns `false` for everything; mDNSResponder flows were terminated instead of
  bypassed; a VPN client's traffic failed after `false` (threads 710762, 716594;
  DTS Quinn, Oct 2022: "your only option is... return false... if... that causes
  the flow's originating process to fail, there's not much you can do").
  One poster set port 3483 in `excludedNetworkRules` and still received flows to
  that port (search summary **(S)** of the forum thread listing).
- **UDP rule leak:** with a UDP rule in `includedNetworkRules`, kernel mbufs
  leaked about four per second and a machine panicked; reporter says "resolved
  as of 15.1 or later" (thread 762804).
- **Chromium UDP/QUIC flows:** opening Chrome/Brave/Opera UDP flows fails with
  `NEAppProxyFlowErrorDomain` code 2 "peer closed the flow" while Safari and
  Firefox work; no fix in the thread (770707).
- **`remotePrefix 0` rule oddity:** a Chrome UDP rule worked at prefix 16, not 0
  (thread 698626).
- **`startProxy` may be called more than once on macOS Tahoe** (forum tag-page
  summary **(S)**); `startProxy` must call its completion handler or the
  provider sits in "connecting" (Quinn, via search summary).
- **Respawn:** a transparent proxy killed while not connected is not expected to
  respawn without On Demand rules (DTS, search summary **(S)**).
- **Flow-control rule:** "Write all data before reading more, so the provider
  doesn't buffer unbounded data. Unbounded buffering can cause a jetsam event"
  (Handling Flow Copying, Apple).
- **Beta status in the market:** the only shipping "Proxyman way" product labels
  its extension BETA and off by default, macOS 26+ only.

## 4. Candidate directions (for the Architect, not decisions)

**A. Provider.**

- **A1 (evidence points here): `NETransparentProxyProvider` as the single
  mutating capture provider.** Only system-wide provider that returns bytes you
  can edit; used by mitmproxy and Proxyman; Developer ID supported as a sysex;
  per-flow pass-through. Cost: TCP/UDP flows only; loopback not captured; UDP and
  Chromium flow quirks (3.9); scope changes need a provider restart.
- **A2 fallback: `NEPacketTunnelProvider`.** Gets raw IP (including ICMP) for a
  routed range; no app metadata; needs a user-space TCP/IP stack in the core and
  re-origination of every flow, so it is a *second* ingress shape and the VPN
  surface in System Settings. mitmproxy tried it first and left it. Worth
  keeping only if a requirement for packet-shaped capture on macOS appears.
- **A3 complement, not v1: `NEFilterDataProvider`** in the same sysex for
  observe-only coverage of ICMP and other IP protocols. No mutation; one more
  approval prompt ("Filter Network Content", ESET); one named XPC endpoint per
  sysex (Quinn). Only if "future L4 observe" on macOS is wanted.
- **Not candidates:** `NEAppProxyProvider` (per-app only on macOS);
  `NEFilterPacketProvider` (no edit; 09).

**B. Handoff transport.**

- **B1 per-flow Unix sockets plus a control socket** (mitmproxy). Proven, plain
  Rust listener. Needs a private directory and peer-signature check in the sysex
  (3.7) so a root provider never ships plaintext flows to a squatter.
- **B2 XPC control plus per-flow sockets/fds.** Apple's recommended control plane
  and a built-in code-signing requirement; fd-passing for the data plane is
  unverified. Rust side must speak XPC or a small Swift shim in the app must
  broker it (the app is Swift, the core is Rust): extra moving part.
- **B3 loopback TCP + token**. Reuses the bus idea; weakest peer authentication;
  a second listener regardless.
- A requirement either way: **control and data are separate**, and the extension
  **fails open** when the control channel is gone.

**C. Packaging.**

- **C1 sysex embedded in `Aitmproxy.app`.** One bundle, one cask, one version.
  CLI-only users on macOS get no capture unless they also install the app.
- **C2 separate small capture host app (mitmproxy's "Redirector.app")**
  installed to `/Applications` by the CLI or cask, carrying the sysex; the main
  app and `aitm` both talk to it. Fits the CLI/Linux-first phasing and keeps the
  signing surface and version-bump coupling off the main app. Cost: a second
  app bundle, two things to approve, more release engineering.

**D. Build system.**

- **D1 small Xcode project (or generated) for the sysex and host only**, with
  `xcodebuild archive/export` or Quinn's re-sign recipe; SwiftPM and `build.sh`
  keep building the main app. Matches mitmproxy and Apple's "automatic code
  signing is easiest" advice; adds a second build system next to the bama
  SwiftPM pipeline.
- **D2 pure script assembly** (extend `build.sh`/`notarize-dmg.sh` as in 3.6).
  Keeps one toolchain; you hand-manage profiles, `Info.plist`, and the
  application-identifier claims, which are exactly the failure modes in 3.4.

**E. Scope and safety placement.** Narrow static rules (for example TCP only,
operator-chosen ports) plus per-flow filtering by scope and by user ID, plus the
core's guard; versus broad rule plus per-flow filtering. Evidence: broad rules
route every flow through the provider and expose the `false`-return quirks;
rules cannot be edited without a provider restart.

**F. Lifecycle.** Fail-open when no core is attached; version-bump discipline
(always raise the sysex version, return `.replace`, reconcile the proxy
configuration after replacement, per leash #58); a visible "capture is on"
indicator; uninstall path (`deactivationRequest`, remove the proxy configuration).

**G. AC19 reconciliation (design question, flagged).** The extension feeds
**flows**. Either (G1) AC19 is read as "TCP streams go to the existing
`ProtocolModule` seam and UDP datagram flows become a flow-level L4 kind behind
`L4Guard`", with raw packet craft/inject/mutate explicitly `L4Unavailable` on
macOS, or (G2) AC19 is reworded. This is for the Architect and Matt, not the
researcher.

**H. Gate ordering.** Everything in 3.4 can be front-loaded: a throwaway
`experiment/macos-ne-spike` that signs and activates a do-nothing
`NETransparentProxyProvider` sysex with Matt's team, then proves one flow across
a Unix socket, would settle open questions 1 to 5 before any spec work.

## 5. Open questions

Only Matt, his developer account, or a real signing experiment can settle these.

1. **Does `~/Applications` satisfy the parent-bundle-location check?**
   (`OSSystemExtensionErrorUnsupportedParentBundleLocation` exists; sources only
   say "appropriate Applications directory".) Cheap experiment.
2. **State of Matt's team:** which App IDs exist, whether *Network Extensions*
   and *System Extension* capabilities are enabled on macOS App IDs, whether the
   portal will mint a Developer ID profile carrying
   `app-proxy-provider-systemextension` for each. (`security cms -D` on the four
   local profiles, or the portal.)
3. **Manual `codesign` with the full entitlement set**, including
   `com.apple.application-identifier` and `team-identifier`, accepted on macOS 27
   with Xcode 27.1 outside Xcode's export. Quinn's recipe is for Xcode 26 and
   earlier; the Xcode 27 note is a beta remark.
4. **Loopback capture with explicit `127.0.0.1/32` and `::1/128` rules on macOS
   27** (the `nc -l` / `nc 127.0.0.1` test Quinn suggests). Decides whether
   `aitm-testtarget` loopback can be the Phase-2 target, or a non-loopback
   in-scope target is required. Also: is traffic to the Mac's own LAN address
   treated as loopback?
5. **Does an agent-driven or CLI-only flow need the app open?** Activation stays
   pending until approved and the app exits; confirm the prompts' exact behaviour
   on macOS 27, whether `requestNeedsUserApproval` fires, and whether Matt wants
   approval to be an operator-only action (07 precedent).
6. **Peer authentication feasibility:** can a root sysex reliably validate the
   listener's code signature from `LOCAL_PEERTOKEN`, or must it use XPC's
   `setCodeSigningRequirement`? And fd passing over XPC: works or not?
7. **Self-exclusion method:** signing identifier vs audit token vs pid for
   `aitm` and obscura on macOS 27; do the embedded obscura browser's flows carry a
   useful `sourceAppSigningIdentifier`?
8. **`return false` safety on macOS 27** with a catch-all rule (AirDrop,
   mDNSResponder, VPN clients). Determines whether a broad rule is acceptable.
9. **UDP and QUIC:** is the Chromium UDP flow failure and the UDP mbuf leak
   present on macOS 27? Does Matt want QUIC forced to TCP fallback (needs the
   close-after-true workaround)?
10. **Proxy-configuration persistence on macOS 26 and 27:** are the reboot and
    version-bump losses (3P reports) reproducible? Needs a soak on a real Mac.
11. **macOS 27 (Golden Gate) release notes:** no Apple page found; re-check the
    NetworkExtension and SystemExtensions release notes in the installed SDK/docs.
12. **Host-app question for Matt:** is a separate or embedded app bundle (C1 or
    C2) acceptable for the "CLI-first" story, given a CLI-only macOS user cannot
    activate the extension?
13. **App Store:** confirmed out of scope? (Direct Developer ID only; appex is
    App Store only.)
14. **Multi-user:** the sysex is global and root; flows from other logged-in users
    reach the provider. Whether to filter by audit-token UID is a policy call
    (the UID field of the audit token is **unverified** here).
15. **Raw-packet L4 on macOS** after this note: BPF capture-only (08) is the
    ceiling. Is that acceptable for AC19, or does Matt want a different bar?
16. **Re-verify all registry and doc facts** by reading the installed SDK
    headers beyond the ones quoted and by a test run (see provenance).

## 6. Sources

All read 2026-10-29. "(header)" = first-hand in the Xcode 27.1 MacOSX SDK on
this Mac. "(man)" = local man page. "(tree)" = this repo. "(S)" = search-result
summary only.

**Apple documentation (JSON endpoints under `developer.apple.com/tutorials/data/documentation/`)**

- TN3134 Network Extension provider deployment: `technotes/tn3134-network-extension-provider-deployment.json`
- `networkextension/netransparentproxyprovider`, `.../netransparentproxynetworksettings`,
  `.../nenetworkrule`, `.../neappproxyflow`, `.../neappproxytcpflow`,
  `.../neappproxyudpflow`, `.../neflowmetadata`, `.../handling-flow-copying`
- `bundleresources/entitlements/com.apple.developer.networking.networkextension`,
  `.../com.apple.developer.system-extension.install`
- `systemextensions/installing-system-extensions-and-drivers`,
  `systemextensions/ossystemextensionrequest`;
  `foundation/nsxpcconnection/setcodesigningrequirement(_:)`
- https://developer.apple.com/system-extensions/ ,
  https://developer.apple.com/help/account/capabilities/capability-requests ,
  https://developer.apple.com/help/account/reference/supported-capabilities-macos
  (table check marks lost in extraction)
- WWDC25 session 234 transcript: https://developer.apple.com/videos/play/wwdc2025/234/ ;
  WWDC19 session 702: https://developer.apple.com/videos/play/wwdc2019/702/
- SDK headers (header), under
  `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/`:
  `NetworkExtension.framework/Headers/{NETransparentProxyProvider,NEAppProxyProvider,NEAppProxyFlow,NEAppProxyTCPFlow,NEAppProxyUDPFlow,NEFlowMetaData,NENetworkRule,NETransparentProxyNetworkSettings,NETransparentProxyManager,NEProvider,NETunnelProviderSession,NETunnelProvider,NEFilterDataProvider,NEFilterProvider,NEFilterPacketProvider,NEPacketTunnelProvider}.h`;
  `SystemExtensions.framework/Headers/SystemExtensions.h`; `usr/include/sys/un.h`
  (`LOCAL_PEERPID`, `LOCAL_PEERTOKEN`)
- Local man pages (man): `codesign(1)`, `unix(4)`

**Apple DevForums (DTS posts)**

- 800887 Network Extension Provider Packaging (Quinn, 2025-09-17, rev. 2025-11-06): https://developer.apple.com/forums/thread/800887
- 737894 Exporting a Developer ID Network Extension: https://developer.apple.com/forums/thread/737894
- 725805 Debugging a Network Extension Provider: https://developer.apple.com/forums/thread/725805
- 67613 Network Extension Framework Entitlements: https://developer.apple.com/forums/thread/67613
- 664126 Developer ID PP for app with Network Extension: https://developer.apple.com/forums/thread/664126
- 786886 Entitlement Request Support: https://developer.apple.com/forums/thread/786886
- 795579 Content Filter entitlement mismatch: https://developer.apple.com/forums/thread/795579
- 790296 Gatekeeper disallowing directly distributed app: https://developer.apple.com/forums/thread/790296
- 805996 App Extension Network Extension: https://developer.apple.com/forums/thread/805996
- 131815 App Proxy Provider and Mac App Store: https://developer.apple.com/forums/thread/131815
- 658961 Avoid showing VPN pop up (transparent proxy): https://developer.apple.com/forums/thread/658961
- 658631 Avoiding my own flows: https://developer.apple.com/forums/thread/658631
- 664120 NEAppProxyProvider with dynamic rules: https://developer.apple.com/forums/thread/664120
- 699972 Update filter rule on the run: https://developer.apple.com/forums/thread/699972
- 716594 Flow dropped after returning false: https://developer.apple.com/forums/thread/716594
- 794776 Intercept local connections: https://developer.apple.com/forums/thread/794776
- 762804 UDP mbufs and panics: https://developer.apple.com/forums/thread/762804
- 708877 XPC Resources (index page only; no content on peer validation read)
- 701581 Packaging Mac Software for Distribution: https://developer.apple.com/forums/thread/701581
- (S) 770707 Chrome UDP flows, 698626 IPv6/UDP rule, 680190 and 666130 loopback,
  710762 AirDrop, 760232 excludedRules, 51592 / 126716 / 756360 XPC file handles,
  703140 and 133687 restart behaviour, 121823 rule setup, 795579 related

**Reference implementations**

- mitmproxy_rs (read via WebFetch of `raw.githubusercontent.com/mitmproxy/mitmproxy_rs/main/`):
  `mitmproxy-macos/redirector/{README.md,ExportOptions.plist,app.swift (macos-redirector/),
  network-extension/{TransparentProxyProvider,FlowExtensions,InterceptConf,main}.swift,
  network-extension/{Info.plist,network_extension.entitlements},
  macos-redirector/macos_redirector.entitlements}`, `src/packet_sources/macos.rs`,
  `.github/scripts/build-macos-redirector.sh`
- mitmproxy: `mitmproxy/proxy/mode_servers.py` (raw, main);
  https://mitmproxy.org/posts/local-capture/macos/
- Proxyman: https://proxyman.com/posts/2026-10-06-introducing-network-extension ,
  https://proxyman.com/docs/advanced-features/network-extension ,
  https://proxyman.com/network-extension
- ESET KB7636 (approval steps, macOS 26 and 27): https://support.eset.com/en/kb7636-allow-system-extensions-for-your-eset-product-for-macos
- Third-party reports (3P): https://github.com/sixtoad/leash/issues/58 ,
  https://github.com/pia-foss/desktop/issues/94 ; (S) miniswift.run "What's new in
  NetworkExtension, iOS & macOS 27 SDK"; (S) Apple "WWDC26 device management updates"
- crates.io API: `objc2-network-extension` (0.3.2, 2025-10-04)

**aitmproxy tree (tree)**

- `docs/superpowers/WORKFLOW.md`, `.claude/agents/researcher.md`
- `docs/research/09-l4-inpath-interception.md`, `08-l4-packet-rust.md`, `07-ca-install.md`
- `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md`
  (Part 7, AC17, AC19), `.../plans/2026-10-28-aitmproxy-l4-operator-surfaces.md`
  (Task 10), `.../specs/2026-10-28-aitmproxy-core-connection-model-design.md`
- `crates/aitm-core/src/{protocol.rs,proxy.rs,stream.rs}`,
  `crates/aitm-proto-l4/src/{module.rs,flow.rs}`, `crates/aitm-proto-http/src/module.rs`
- `apps/mac/{Package.swift,Info.plist.in,EmbeddedObscura.entitlements,build.sh,CLAUDE.md}`,
  `apps/mac/Sources/Aitmproxy/Bus/{EmbeddedCore,EmbeddedCoreController,BusService,CoreHealthState}.swift`
- `scripts/{package.sh,make-dmg.sh,notarize-dmg.sh}`, `INSTALL.md`

**Local observations (read-only, this Mac)**: `sw_vers` (27.0, 26A428),
`xcodebuild -version` (Xcode 27.1, 27A9269), `security find-identity -v -p
codesigning` (0 identities inside the sandbox), directory listing of
`~/Library/MobileDevice/Provisioning Profiles` (four files; not opened).
