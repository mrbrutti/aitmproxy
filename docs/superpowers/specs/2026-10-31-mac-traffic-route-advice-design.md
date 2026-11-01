# macOS traffic-route advice design

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode); amended 2026-11-01 (self-approved, autonomous mode): stage-6 fix pass on docs PR #242 plus the orchestrator's gate-2/gate-5 rulings of 2026-11-01 (see Amendments)
**Research inputs:**
- Live diagnosis, 2026-10-31, installed 0.5.4 app (observation only): `/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_9f6f2891-d1f9-458f-a0c7-0c5668557fb3/live-sidebar-not-loading-diagnosis.md`
- `docs/research/22-macos-system-proxy-toggle.md` — read-back via `CFNetworkCopySystemProxySettings()`, the sibling "Set as system proxy" work and its candidate words; §5a's live observation (Proxyman's `127.0.0.1:9090` set for HTTP+HTTPS on both enabled services)
- `docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md` (PR #196, on `main` as `5eac2a50`; the working tree holds the shipping `ConnectionSummary.swift`, `StatusPanel.swift`, `ShellView.swift`) — the Getting-started list, the one-home rule, `check-connection-words.sh`
- `docs/superpowers/specs/2026-10-31-ne-no-scope-honest-state-design.md` — `CaptureAdvice`, deny-by-default on an empty scope, the Apps banners
- `apps/mac/docs/GLOSSARY.md` — "All Apps" vocabulary
- NE session, v0.5.5 live run (2026-10-31): Matt's Mac does not trust the aitm CA, so every HTTPS
  capture fails and Safari falls back to QUIC; plain HTTP through the extension works, with
  `source_app`. `ca.status` (`crates/aitm-ca/src/commands.rs` ~550–670) reports
  `stores: {user|system: {installed, trusted: "yes"|"no"|"unknown", location}}`; the Kit
  already decodes it (`AitmproxyKit/Panels/CAStatus.swift`, consumed by `Panels/CAPanel.swift`).
  The core's default install scope on macOS is User — the login keychain, macOS's own auth dialog
  (`crates/aitm-ca/src/store.rs` `Platform::default_scope`, `platform/macos.rs` `LOGIN_KEYCHAIN`).
- Matt's decision, 2026-10-31: **per-host decryption like Proxyman** — the core decrypts only hosts
  in Scope and passes every other HTTPS connection through as a TLS tunnel, shown as a row (a core
  story the orchestrator owns; not this spec's code). `AitmproxyKit/Flow.swift` already has
  `TLSState.tunnelled` ("CONNECT tunnel passed through; not decrypted"); `FlowSummary` (line ~156)
  does not yet produce it from the wire. Shared strings confirmed by the improve-loop session for
  stories S-073/S-074/S-080 (notes `proxyman-capture-flow-gaps.md` §3).
- Per-host decryption merged as PR #228 (`448e75e0`, released as v0.5.9 = `8175eea3`): `proxy.status` now carries
  `decrypt = {scope_hosts: Int, decrypting: Bool, advice: String?}` (`crates/aitm-plugins/src/control.rs`
  ~140–155) where `advice` is the core constant `NOTHING_DECRYPTED_ADVICE` =
  `"Nothing is decrypted until a host is in Scope."` (`crates/aitm-core/src/config.rs:176`) while
  `scope_hosts == 0` and `null` once a host is in Scope — "the one constant every surface prints
  verbatim". Rows carry `tunnel` (`decrypted` | `passthrough` | `failed`), `tunnel_reason`
  (`out_of_scope`, `pinned`, `client_rejected_certificate`, `client_closed`, `client_tls_error`,
  `upstream_unreachable`, `upstream_tls_failed`, `protocol_error`), `bytes_up`, `bytes_down`
  (`crates/aitm-plugins/src/capture.rs` `tunnel_fields` ~265–283; labels in
  `crates/aitm-core/src/flow.rs` `TunnelMode`/`TunnelReason`).
- Orchestrator rulings, 2026-11-01 (recorded as the plan's gate-2 answers and gate 5): the app has **no
  reader of its own** for the system proxy — the fact arrives from the system-proxy session: PR 4a ships
  `AitmproxyKit/SystemProxyState.swift` (the type this spec defines, plus its Kit tests) ahead of this
  spec's PR; PR4 (after us) decodes `proxy.status.system_proxy` and the `proxy.system.set`/`unset`
  replies into it and writes `Session.systemProxy`. `ConnectionAction.openNetworkSettings` is **denied**
  (Matt: system-proxy setup happens automatically in the app with the OS's own prompt, never by sending
  him to System Settings). The CA fact is the CA-trust session's published `Session.caTrust`
  (mac PR D, branch `claude/ca-trust-mac`, `apps/mac/Sources/Aitmproxy/Session+CATrust.swift`); CA
  polling is PR D's. `BusService.swift` is granted for exactly one line (the `proxy.status.decrypt`
  decode). The base of this design is `main 8e19c2e3`.

## Intent

On the installed 0.5.4 app Matt saw Flows 0 / Apps 0 / Domains 0 while "traffic flows". The
sidebar, the poll and the bus were fine (`curl -x 127.0.0.1:8080` moved the counts within one
poll). Nothing from ordinary apps reached the core because both automatic routes into the
proxy were closed: the macOS system proxy did not point at the core (at diagnosis time it was
off — `HTTPEnable 0, HTTPSEnable 0`; right now it points at Proxyman's `127.0.0.1:9090` — either
way Safari bypasses 8080) and `scope.list` was `[]` (All Apps is on, and the extension rejects
every flow on an empty scope: `provider rejected new flow TCP com.apple.Safari …`). The app said
none of this; the Flows empty state read only "No flows yet — Point a client at 127.0.0.1:8080
or open the browser." This spec gives the app one Kit model of the two routes (system proxy;
All Apps + scope) and makes the Status page's Getting-started list and the Flows page's empty
state / one-line banner say, in the same words, which route is closed and the one action that
opens it.

The two routes differ in what they carry, and the words say so: the **system proxy** delivers
every proxy-aware app, regardless of Scope (the passive proxy is not scope-gated); **All Apps**
delivers the in-scope hosts of every app (the extension is).

Two more facts sit beside the two routes and gate what either can carry. **Scope**: under per-host
decryption nothing is decrypted until a host is in Scope — on either route; the rest passes through
as tunnel rows. **CA trust**: whether the **aitm CA is trusted** in the keychain. Untrusted, HTTPS on both routes fails (browsers using QUIC load directly)
while plain HTTP flows; the app must say so from the keychain read-back (`ca.status`), never from a
client-side flag.

## Goals

- With the scope empty on a build with All Apps on, the Flows page's empty state shows the core's
  own sentence `Nothing is decrypted until a host is in Scope.` with its buttons (Add Host…, Open
  Scope…). Once PR4 feeds the system-proxy slot, a system proxy that is off adds the line, verbatim,
  `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`, and one
  pointing elsewhere the same line naming what it found (`system proxy on · 127.0.0.1:9090, not
  this core — …`), each with PR4's Set as System Proxy action. Until PR4 lands the system proxy is
  unknown and neither page says anything about it — never "off".
- With the CA not trusted (Matt's Mac today), both pages carry one more line, verbatim: `HTTPS is
  not captured until the CA is trusted` — the Flows empty state as a row, the Status checklist as
  the undone step "Trust the aitmproxy CA"; when `ca.status` has not been read, nothing is said
  about the CA, and nothing ever reads "trusted" unless a store reports `trusted: "yes"`.
- The Status page's Getting-started list shows the same lines as undone steps (each step keeps its
  existing action: the All Apps step `.turnCaptureOn`, the Scope step `.openScope`); after `scope.add` over the bus the scope line disappears from both pages within one
  poll; after the system proxy is set to the core's address (PR4's toggle or `networksetup`) the
  system-proxy line disappears the same way — without any view being told.
- When flows exist and neither route is open, one line above the Flows table says so; when
  flows exist and at least one route is open, nothing is shown.
- Every word comes from `AitmproxyKit.ConnectionSummary`; `check-connection-words.sh` fails if
  a view spells `system proxy off` or `Nothing is decrypted until a host is in Scope` itself.
- The system-proxy fact is a public, stable Kit value (`SystemProxyState`, defined here as the
  shared contract and shipped by the system-proxy session's PR 4a) that PR4 fills from
  `proxy.status.system_proxy` (PR #246's `init?(compact:listenAddress:)`) and extends (`SystemProxyFacts`,
  `.setSystemProxy`/`.unsetSystemProxy`, the Proxy ▸ toggle), so the app has one read-back type and
  one set of words for the system proxy.

## Non-goals

- A "Set as system proxy" / "Restore system proxy" action, its helper, its snapshot-and-restore
  file, its Proxy ▸ toggle (⌥⌘P) and its `ConnectionAction`s (`.setSystemProxy`, `.unsetSystemProxy`
  are **reserved** for the system-proxy session's PR4, §D2a; its bus verbs are already on `main`,
  PR #214). This spec adds the read-only route fact only; the system-proxy line carries **no
  action** until PR4 fills it. Never an "Open Network Settings…" action: the orchestrator denied
  `.openNetworkSettings` 2026-11-01 (Matt: system-proxy setup happens in the app with the OS's own
  prompt, never by sending him to System Settings).
- Installing, trusting or polling the CA from code in this spec: `ConnectionAction.trustCA` (title
  "Trust the aitmproxy CA"), `.openCAPanel`, `CATrustFacts`, `Session.caTrust`/`caStatus`,
  `refreshCAStatus()` and `Session+CATrust.swift` are the CA-trust session's mac PR D, which lands
  before this spec's PR and owns the install side (confirm prompt, admin prompt). This spec
  **consumes** PR D's `Session.caTrust` and its `CATrustFacts` helpers as the CA entry's line,
  actions and step; it declares none of them, never calls `ca.status` or `ca.install`, and does not
  change `Panels/CAPanel.swift`. Never `.installCA`.
- Any copy change outside the two surfaces (Flows empty state + Flows banner; Getting-started
  steps). The toolbar pill, the lane cards, Settings, the Apps page's `AppsAttributionBanner` /
  `AppsEmptyState` and `ScopeBanner`'s text are unchanged (one exception: `ScopeBanner`'s call
  site in `MainView.flows` is removed, §D8; the struct and its text stay).
- Anything under `apps/mac/Extension/`, any core (Rust) change, any new bus verb, any in-app read
  of the macOS proxy settings (`CFNetworkCopySystemProxySettings()`, `SCDynamicStore`): the
  core's `proxy.system.status` is the one reader, and PR4 is the one poller.
- PAC/WPAD, SOCKS, per-service or per-app proxy settings, a browser's own manual proxy
  (Firefox), the bypass list. The system-proxy model answers one question: do the effective
  global HTTP/HTTPS system-proxy settings point at this core's listen address.
- The `firstFlow` step's words and action (unchanged).

## Anti-goals

- A second vocabulary: a `TrafficRouteAdvice` that views build from `scopeHosts` / `coreHealth`
  themselves, parallel to `ConnectionSummary`; or a second system-proxy type in the sibling
  work. Two derivations is how two pages end up disagreeing.
- A view computing the predicate ("system proxy closed and scope empty and flows exist")
  itself, even once. Views read `routes` and render.
- Nagging: a banner while a route is open, two stacked banners saying the same thing, a step
  that reads done when the fact is not.
- Lying: saying "off" when the system proxy is on and pointing at another port; saying anything
  about the system proxy before it has been read or with the bus down.
- A view reaching the capture switch or the `ExtensionController` (the capture tripwires).
- A second reader of the system proxy (an in-app CFNetwork or SCDynamicStore copy beside the
  core's `proxy.system.status`): two readers is two derivations.
- Proving this with fixture or sample data.
- Saying the CA is trusted on an unread or `unknown` status, or deriving trust from anything but
  the keychain read-back `ca.status` returns.
- Running `ca.install` on Matt's Mac as part of any proof (hard gate, Constraints).

## Constraints

- **Proof is real, not fixtures (Matt, binding: "STOP USING THE FAKE DATA UI TESTS").** The
  app's fixture and sample-data modes are being deleted by a dedicated session; that removal PR
  lands first and this branch rebases once onto its merge SHA. This spec references none of that
  machinery, and no acceptance criterion relies on any seeded store, sample rows, snapshot or
  in-app self-check, as evidence or as a regression gate. Proof is (1) Kit unit tests of the
  pure model that construct their own literal values — one `ConnectionSummary.make` call per
  row of the predicate table (§D10) with the expected strings; (2) the three source tripwires
  `tools/check-capture-operator-only.sh`, `tools/check-capture-toggle.sh`,
  `tools/check-connection-words.sh`; (3) the real installed app with the extension on and real
  requests — and, on the first build that also contains PR4, the real system-proxy state flipped
  (PR4's toggle, or `networksetup`/`scutil` in the Terminal) — screenshots of the Flows and Status
  pages showing the same words, and bus reads (`scope.list`, `scope.add`, operator token never
  printed).
- **Hard gate — no `ca.install` on Matt's Mac.** Trusting the aitm CA on his machine is Matt's
  decision and he has not given it. No proof, script, Coder, Tester or orchestrating session calls
  `ca.install` (or clicks Install… on the CA page) on his Mac. The live proof proves only the
  NOT-trusted state and its line as his Mac is today, plus `ca.status` over the bus showing
  `trusted: "no"`. The install → line-disappears path is proved only after Matt says in his own
  words that the CA may be trusted, and then only through the app's own step (the Status checklist's
  Trust the aitmproxy CA action — PR D's `.trustCA` — with its admin prompt), never a direct verb call.
- **CA parts land after PR D, and consume what PR D publishes.** The CA-trust session's mac PR D
  (branch `claude/ca-trust-mac`) lands before this spec's PR and publishes the CA fact this spec
  reads — `Session.caTrust: CATrustFacts?` and nothing else: computed by PR D via
  `CATrustFacts(status:)` from the raw `Session.caStatus: CAStatus?` (nil until the first answer,
  reset by `Session.forgetCATrust()` when the bus disconnects); nil when every store is unknown or
  the certificate does not exist; `installing` and `needsAdmin` already applied from
  `Session.caTrustInstalling` / `Session.caTrustNeedsAdmin`. Cadence is PR D's:
  `BusService.pollLoop` calls `session.refreshCAStatus()` on the first tick and every 10th 500 ms
  tick (`BusService.caStatusEveryTicks = 10`), forced after `trustCA()`/`untrustCA()`. PR D's Kit
  `CATrustFacts` has fields `{trusted, scope, fingerprint, platform, installing, needsAdmin}` and
  helpers `{text, state, remedy, actions, step, quicCaveat, notTrustedLine, laneTitle, …}` (read from
  `claude/ca-trust-mac` `4ae616d3`); this spec consumes **`text`** (the one-line fact string),
  `actions` and `step` instead of recomputing the CA words — PR D's `state` is a `LaneState`
  (`ok`/`working`/`warning`), not a string, and its `remedy` is a longer sentence (`notTrustedLine`,
  `needsAdminMacLine`), neither of which is a line here (one vocabulary — the strings in §D2a are PR D's). This spec's own CA work (the `make(caTrust:)`
  slot, the `.caTrust` entry, the `.caTrusted` step, the Flows/Status rendering, and the hand-over
  that replaces PR D's interim `StatusPanel` insertion — `stepsWithCATrust` and `CATrustRow` — with
  this spec's step and row, keeping the words) starts only once PR D is on `main`. The system-proxy,
  All Apps and Scope parts are not gated on it and land first (plan Tasks 1/2 vs 1b/2b).
- **`SystemProxyState` is PR #246's file.** The type is defined here (§D2) as the shared contract and
  shipped — type plus 31 Kit tests and `init?(compact:listenAddress:)`, no polling, no other file —
  by the system-proxy session as PR #246 (branch `claude/system-proxy-kit-type`) ahead of this
  spec's PR (plan gate 5). This spec declares nothing of it and compiles against it; PR4 proper
  keeps ownership and adds `SystemProxyFacts` and the `proxy.status.system_proxy` polling that
  writes `Session.systemProxy`. TR-AC1/2 are the contract PR #246's tests pin.
- **`FlowSummary` decoder is a separate claim.** Mapping the wire's `tunnel` field onto
  `FlowRow.tls` edits `AitmproxyKit/FlowSummary.swift` and adds its Kit tests; the orchestrator
  granted that claim 2026-11-01 (plan gate 4 and "Coordinator contract for Task 1c"). It is plan
  Task 1c; everything else here is independent of it, and TR-AC20 becomes unconditional once Task
  1c is in.
- **Start SHA and claims.** This design is against `main 8e19c2e3` (this worktree's base; v0.5.9 /
  PR #228 and the system-proxy verbs PR #214 are in; it supersedes the `5eac2a50` and `8175eea3`
  references of earlier revisions). Code starts after the fixture-removal mac PR (gate 1), PR 4a
  (gate 5) and, for the CA parts, PR D (gate 3). The orchestrator's file claims are the plan's
  gate 2, answered 2026-11-01. In `Shell/ShellView.swift` only `EmptyFlows` (the struct at ~316–336)
  and the insertion of the one new banner in `MainView.flows` (~171–200) may change; lines 49–62
  (the palette overlay) and the palette transition belong to another session and are not touched.
- **One model.** `ConnectionSummary` is extended; no parallel type. The route words live in
  `AitmproxyKit/ConnectionSummary.swift`; the system-proxy value in PR 4a's
  `AitmproxyKit/SystemProxyState.swift`. Both surfaces read `Session.trafficRoutes`, a one-line
  accessor of `connectionSummary.routes` (§D7).
- **Words, exactly** (§D2a, §D4). "All Apps" is the feature's name in every user-facing string
  (`ConnectionLane.Kind.capture.title == "All Apps"`; verbs "Capture All Apps", "All Apps
  Settings…"); "Capture"/"Extension" appear only where macOS does (approval, uninstall). The
  lane principle "system proxy → every proxy-aware app, regardless of Scope; All Apps → in-scope
  hosts of every app" is carried by the model (`TrafficRoute.detail`) and shown on both surfaces.
- **Shared vocabulary** (§D2a): `SystemProxyState`, `SystemProxyState.Endpoint`,
  `SystemProxyRoute` and the system-proxy words are public, stable and additive-only from the
  moment they land (PR #246 ships them with `init?(compact:listenAddress:)`); PR4 adds `SystemProxyFacts`
  and the reserved actions beside them. `CATrustFacts`, `TrafficRoute.Kind.caTrust` and the CA words are
  shared the same way with the CA-trust session (PR D writes the install side and the facts; this
  `ConnectionSummary` model consumes them). This spec may use `addScopeHost` (new),
  `copyListenAddress`, `openScope`, `turnCaptureOn`, the existing `openCaptureSettings` /
  `approveInSystemSettings`, and PR D's `.trustCA` / `.openCAPanel` (consumed, never declared). It
  adds no `openNetworkSettings` (denied) and leaves the system-proxy entry's `actions` empty for
  PR4's `.setSystemProxy`.
- **The read is the core's, and it is the effective global setting.** `proxy.status.system_proxy`
  (PR4; the core refreshes it ≤ 5 s and immediately after `proxy.system.set`/`unset`) classifies
  the system-wide effective proxies, which follow the PRIMARY network service (per-service values
  can disagree, e.g. under a VPN — research 22 §2.4, an inference from issue reports and the
  SystemConfiguration headers, not from configd source). The app reads nothing per-service and
  nothing from CFNetwork; the words say "system proxy", never a service name.
- **Tripwires.** `tools/check-connection-words.sh` must keep failing on a view that spells a
  connection word, including the new route words (its word list gains them, §D9).
  `tools/check-capture-operator-only.sh` rule 5 parses `Shell/ShellView.swift` for exactly one
  `ExtensionController(` construction and one `.start()` on it: that block is not touched.
  `tools/check-capture-toggle.sh` NS-AC4 (ShellView reads no `capture.enabled`, calls no
  `CaptureSwitch`, touches no `extensionController`) must hold for the new banner file too.
- **The system-proxy fact is a value.** `ConnectionSummary.make` takes `SystemProxyState?`; no
  file under `apps/mac/Sources` calls `CFNetworkCopySystemProxySettings()` (TR-AC8).
  `Session.systemProxy` is nil until PR4's first answer and is written by PR4 only (§D6).
- **Cadence.** Nothing new is polled. The system-proxy fact rides PR4's decode of the existing
  `proxy.status` poll (`BusService.pollInterval`, 500 ms); the CA fact rides PR D's
  `refreshCAStatus()` (first tick, then every 10th tick — on macOS `ca.status` spawns
  `/usr/bin/security` per store, `crates/aitm-ca/src/exec.rs`; two stores at 2 ticks/s would be
  ~4 spawns a second — inference, unmeasured); `proxy.status.decrypt` is decoded from the same
  `proxy.status` reply the app already polls (§D6). Never a new verb, never a new read.
- **No new dependencies.** The Kit stays free of SwiftUI, AppKit, CFNetwork and
  SystemConfiguration (it parses a plain dictionary and `JSONValue`); the app target imports
  nothing new.
- **Design rules.** Tokens from `Tok`/`Space`; `SmallButton`/`FlatButton`; hairline rules; no
  hard-coded colours; layout judged on the real-app screenshots.
- **Honest, not nagging** (§D5): banner only while BOTH routes are closed and flows exist.

## Design

### D1. Extend `ConnectionSummary.make`; add a `routes` field (Architect's call, confirmed by the coordinators)

`make` gains one input, `systemProxy: SystemProxyState?`, and `ConnectionSummary` gains one
stored field, `routes: TrafficRoutes`, computed inside `make` from the facts the lanes and steps
already use (`CaptureAdvice`, `scopeHostCount`, `flowCount`, the bus lane, `listenAddress`). The
Getting-started steps are built *from* `routes` (§D4), so Status and Flows read one derivation.

Why not a parallel `make`: the Status page needs the route words inside its steps anyway, and a
second function over the same inputs is the two-derivations trap. Why not steps alone: the
Flows empty state needs 0–2 lines with actions and the banner needs a predicate over
`flowCount`; neither fits `GettingStartedStep`.

### D2. Types (Kit, pure)

`AitmproxyKit/SystemProxyState.swift` — **defined here as the shared contract, implemented by the
system-proxy session (file owned by PR4; shipped as the tiny PR 4a = PR #246, branch
`claude/system-proxy-kit-type`, with 31 Kit tests, ahead of this spec's PR — plan gate 5)**. PR #246
also carries `init?(compact:listenAddress:)`, PR4's decoder of `proxy.status.system_proxy`
(`points_at_us` → both endpoints at the listen address, `other` → both at `host:port`, `off` → `.off`,
`unsupported` / `needs_privilege` / `unknown` / malformed → nil). This spec declares nothing of it; its
`make(systemProxy:)` calls `state.route(to: listenAddress)` for the word, so `points_at_us` reads
`system proxy on · L`:

```swift
/// The effective global macOS HTTP/HTTPS system proxy (follows the primary network service) — the
/// one read-back every system-proxy surface in the app uses: this spec's route advice and PR4's
/// toggle. Filled by PR4 from `proxy.status.system_proxy` via `init?(compact:listenAddress:)` (PR #246:
/// points_at_us → both endpoints at the listen address, other → both at host:port, off → .off,
/// unsupported / needs_privilege / unknown / malformed → nil) and from the `proxy.system.set`/`unset`
/// replies. `nil` endpoint = that protocol's *Enable key is 0 or absent. `init(settings:)` is the pure
/// dictionary form (number or numeric-string ports).
public struct SystemProxyState: Hashable, Sendable {
    public struct Endpoint: Hashable, Sendable {
        public let host: String                      // PR #246: `let`, not `var`
        public let port: Int
        /// "host:port" (computed, plan call 3)
        public var address: String { "\(host):\(port)" }
        public init(host: String, port: Int)
    }
    public let http: Endpoint?
    public let https: Endpoint?
    public init(http: Endpoint?, https: Endpoint?)
    /// Keys "HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"
    /// (the values of the kCFNetworkProxies* constants). Enable is any non-zero number; a Port is
    /// accepted as a number or a numeric string (research 22 §2.2 documents only the dictionary's
    /// shape — that CFNetwork hands back NSNumber is unverified; the string form costs nothing and
    /// was asked for by the system-proxy session, which owns this type).
    public init(settings: [String: Any])
    /// PR #246 / PR4: the bus object `proxy.status.system_proxy` (a `JSONValue`, the Kit's bus-object
    /// convention). points_at_us → both endpoints at `listenAddress`; other → both at host:port;
    /// off → .off; unsupported / needs_privilege / unknown / malformed → nil. An `other` whose endpoint
    /// equals `listenAddress` → nil (unknown): the core reports its partial case "HTTP → us, HTTPS off"
    /// as `other` at our own host:port, and two endpoints cannot express "partly at us".
    public init?(compact: JSONValue, listenAddress: String)
    public static let off = SystemProxyState(http: nil, https: nil)
    /// Does the system proxy deliver traffic to a core listening at `listenAddress` ("host:port")?
    public func route(to listenAddress: String) -> SystemProxyRoute
}

public enum SystemProxyRoute: Hashable, Sendable {
    /// Neither protocol enabled.
    case off
    /// At least one protocol points at the core.
    case thisCore(http: Bool, https: Bool)
    /// Enabled, and no protocol points at the core: another proxy (Proxyman, Charles, a corporate
    /// proxy) is the system proxy. Carries the first enabled endpoint (HTTP, then HTTPS).
    case other(host: String, port: Int)
}
```

Matching rule for `route(to:)`: ports equal, and hosts equal after lower-casing and stripping IPv6
brackets (`[::1]` ≡ `::1`), or both loopback (`127.0.0.1`, `localhost`, `::1`), or the listen host is
a wildcard (`0.0.0.0`, `::`) and the proxy host is loopback. `thisCore` is reported when at least one protocol matches (an
HTTP-only system proxy does deliver `http://` traffic; the words say "HTTP only"). `.other` is a
real, current case: Matt's Mac carries Proxyman's `127.0.0.1:9090` for HTTP and HTTPS. PR #246's
`init?(compact:listenAddress:)` maps the core's one verdict `points_at_us` to both endpoints at the
listen address, so `route(to:)` yields `.thisCore(true, true)` and the word is `system proxy on · L`;
the `HTTP only` / `HTTPS only` lines remain for the dictionary form.

`AitmproxyKit/ConnectionSummary.swift` additions:

```swift
public enum ConnectionAction {
    …, case addScopeHost                  // NEW here: title "Add Host…" — the Scope entry's remedy button (opens Scope with its add sheet)
    // PR4 (system-proxy session), not added by this spec — fills the system-proxy entry's actions:
    //   case setSystemProxy, unsetSystemProxy
    // PR D (CA-trust session), consumed by this spec, never declared here:
    //   case trustCA /* title "Trust the aitmproxy CA" */, openCAPanel
    // Denied 2026-11-01 (orchestrator): openNetworkSettings — nothing sends the operator to System Settings ▸ Network
}

// AitmproxyKit — PR D's `CATrustFacts` (CA-trust session, branch `claude/ca-trust-mac`); this spec declares
// nothing of it and consumes it through `Session.caTrust` (§D6)
public struct CATrustFacts: Hashable, Sendable {
    public var trusted: Bool
    /// The store that reports trusted == "yes": "user" | "system"; nil when not trusted.
    public var scope: String?
    public var fingerprint: String?
    public var platform: String            // `ca.status.platform`; no default — tests pass "macos"
    public var installing = false          // applied by PR D from Session.caTrustInstalling
    public var needsAdmin = false          // applied by PR D from Session.caTrustNeedsAdmin
    /// PR D: nil unless some store answered yes or no (`CAStatus.trustReported`); `Session.caTrust`
    /// adds `caStatus.exists` — renders as unknown, never as trusted, never as not trusted.
    public init?(status: CAStatus)
    // PR D's helpers (4ae616d3), consumed here:
    //   text: String        — the one-line fact: "trusting CA…" | "CA trusted (System keychain)" | "CA trusted (user keychain)"
    //                         | "CA trust needs an administrator" | "HTTPS is not captured until the CA is trusted"   → our `line`
    //   actions             — [] installing; [.openCAPanel] trusted or needsAdmin; [.trustCA, .openCAPanel] otherwise → our `actions`
    //   step                — GettingStartedStep(.caTrusted, title: trustCA.title when plain not-trusted else text,
    //                         done: state == .ok, action: done ? nil : actions.first)                               → our step's title/action
    // not used here: state (a LaneState ok/working/warning), remedy (notTrustedLine / needsAdminMacLine), quicCaveat, laneTitle, …
}

// AitmproxyKit/DecryptStatus.swift (new)
/// `proxy.status.decrypt` as the core reports it (v0.5.9+): how many hosts the decryption list
/// (Scope) holds, whether anything is decrypted, and the one sentence the core asks every surface
/// to print verbatim while nothing is. nil from an older core (no `decrypt` key).
public struct DecryptStatus: Hashable, Sendable {
    public var scopeHosts: Int
    public var decrypting: Bool
    /// `NOTHING_DECRYPTED_ADVICE` while `scopeHosts == 0`; nil once a host is in Scope.
    public var advice: String?
    public init(scopeHosts: Int, decrypting: Bool, advice: String?)
    /// nil unless `json` is the `decrypt` object (it always carries `scope_hosts`).
    public init?(json: JSONValue)
}

public struct TrafficRoute: Hashable, Sendable {
    public enum Kind: String, Hashable, Sendable, CaseIterable { case systemProxy, allApps, scope, caTrust }
    public let kind: Kind
    public let open: Bool
    /// The one line, verbatim on both pages (§D4).
    public let line: String
    /// What this route carries (the lane principle), the same on every state of the route:
    /// systemProxy → "every proxy-aware app, regardless of Scope"; allApps → "in-scope hosts of every app".
    public let detail: String
    /// What opens the route, primary first; empty when open — and empty for the system-proxy entry
    /// until PR4 fills `.setSystemProxy`.
    public let actions: [ConnectionAction]
    /// The state words: `line` up to its first " — " ("system proxy off", "All Apps off"), or the whole
    /// line when it has none (the quoted Scope sentence, verbatim with its period; the CA line). The
    /// one-line banner is the shown entries' states joined with " · " (§D5); remedies are never text
    /// there — they are the entry's `actions.first`, shown as the banner's one button.
    public var state: String
}

public struct TrafficRoutes: Hashable, Sendable {
    /// nil while the system proxy is unknown: before PR4 lands, before PR4's first `proxy.status`
    /// answer, a session with no live bus, or a state the core cannot classify.
    public let systemProxy: TrafficRoute?
    /// nil when this build has no extension (`CaptureAdvice.unsupported`) or an external core is active.
    public let allApps: TrafficRoute?
    /// The Scope fact (not a route; under per-host decryption it gates decryption on both). Always
    /// present: closed iff `!open` per §D3 (`!decrypt.decrypting` when `decrypt` is present and the
    /// bus lane is `.ok`, else `scopeHostCount == 0`).
    public let scope: TrafficRoute
    /// The CA fact (not a route; it gates HTTPS on both). nil while `ca.status` is unread or unknown.
    public let caTrust: TrafficRoute?
    /// The closed entries we know about — system proxy, All Apps, Scope, CA, in that order: the Flows
    /// empty-state lines. Empty unless the bus lane is `.ok`.
    public let advice: [TrafficRoute]
    /// The one-line banner text above the Flows table, or nil (§D5): the shown entries' `state`s joined " · ".
    public let banner: String?
    /// The banner's one button: the first shown entry that has an action, its `actions.first` (nil when
    /// none has one). Priority: system proxy (PR4's Set as System Proxy, once filled), All Apps, Scope, CA.
    public let bannerAction: ConnectionAction?
    public var anyOpen: Bool
}

public struct GettingStartedStep {
    public enum Kind { case coreRunning, busConnected, caTrusted /* PR D's source order */, systemProxy /* NEW */, extensionOn, scopeSet, firstFlow } // source order is PR D's; the Getting-started STEPS order is make's (systemProxy, extensionOn, scopeSet, caTrusted)
    …
    /// The route's `detail` for the route/CA steps (shown as the row's help); nil for the others.
    public let detail: String?   // NEW, defaulted nil
}

public struct ConnectionSummary {
    …
    public let routes: TrafficRoutes
    public static func make(
        core connection: CoreConnection?, activeKind: ActiveCoreKind, bus: BusState, role: String?,
        roleWarning: Bool, capability: CaptureCapability, captureSupported: Bool, scopeHostCount: Int,
        flowCount: Int, listenAddress: String, coreCapture: CoreCaptureStatus? = nil,
        systemProxy: SystemProxyState? = nil,         // NEW, defaulted so existing call sites compile; `Session.systemProxy`, written by PR4
        caTrust: CATrustFacts? = nil,                 // NEW; PR D's `Session.caTrust`; nil = unread/unknown
        tunnelledFlowCount: Int = 0,                  // NEW; rows whose `tls == .tunnelled` (§D5)
        decrypt: DecryptStatus? = nil                 // NEW; `proxy.status.decrypt`, nil from an older core
    ) -> ConnectionSummary
}
```

**Why a `DecryptStatus` value and not a `decryptAdvice: String?` beside `scopeHostCount` (Architect's
call).** The core's object carries the count, the flag and the sentence together; decoding it once
means the step's N, the entry's open/closed state and the quoted sentence can never come from two
reads (`scope.list` is no longer needed for N — `Session.scopeHosts` stays for the Scope page and
the capture lane). An older core simply yields nil and the fallback strings. The parser is a pure
Kit test.

**Kit row/detail decoder (plan Task 1c, own claim) — the #228 wire contract, names agreed with the
improve-loop session (they match the core's types):**

```swift
public enum TunnelMode: String, Hashable, Sendable { case decrypted, passthrough, failed }
public enum TunnelReason: String, Hashable, Sendable {
    case outOfScope = "out_of_scope", pinned, clientRejectedCertificate = "client_rejected_certificate",
         clientClosed = "client_closed", clientTLSError = "client_tls_error",
         upstreamUnreachable = "upstream_unreachable", upstreamTLSFailed = "upstream_tls_failed",
         protocolError = "protocol_error"                                   // unknown label → nil, never a crash
}
// on BOTH FlowSummary and FlowRow:
public var tunnel: TunnelMode?          // wire `tunnel`; nil when not a CONNECT row or an older core
public var tunnelReason: TunnelReason?  // wire `tunnel_reason`
public var tunnelBytesUp: Int64?        // wire `bytes_up`  (same guards as request/response bytes)
public var tunnelBytesDown: Int64?      // wire `bytes_down`
public var passive: Bool                // wire `passive`; absent → false
// FlowRow only:
public var isTunnel: Bool { tunnel != nil }
// FlowDetail (AitmproxyKit/FlowDetail.swift, decoded in FlowDetail+Wire.swift from meta.tunnel / meta.passive):
public struct TunnelInfo: Hashable, Sendable { public var mode: TunnelMode; public var reason: TunnelReason?; public var bytesUp: Int64?; public var bytesDown: Int64? }
public var tunnel: TunnelInfo?
public var passive: Bool
```

`FlowRow.tls` from `tunnel`: `.decrypted` → `.decrypted`, `.passthrough` → `.tunnelled`, `.failed` →
`.pinnedOrFailed`, nil → today's scheme rule (`https`/`wss` → `.decrypted`, else `.none`). `inScope`
keeps the scope-list rule unchanged. All five row fields join `FlowRow ==` (every mutable field must,
memory: a missing one made the Apps banner not redraw). The byte counts ride on the row because the
improve-loop session's tunnel-row inspector and a possible column consume our Kit names; nothing in
this spec renders them. Wire source: `crates/aitm-plugins/src/capture.rs` `tunnel_fields` (row),
`crates/aitm-plugins/src/detail.rs` ~355–380 (`meta.passive`, `meta.tunnel {mode, reason, bytes_up,
bytes_down}`), labels in `crates/aitm-core/src/flow.rs`.

`CATrustFacts(status:)`, anything on `CAStatus`, and the CA read are PR D's; nothing in this spec reads
`CAStatus`. The CA entry's `line` and `actions` and the `caTrusted` step come from PR D's `text`,
`actions` and `step` helpers (§D3/§D4); the strings in §D2a are PR D's and are the test oracle
(TR-AC16). The field-by-field mapping is confirmed against PR D's file when plan gate 3 is recorded;
if a helper returns a different string, §D2a is amended first and the literal follows PR D.

### D2a. Shared vocabulary (stable; consumed by the sibling set-system-proxy work)

The system-proxy session's operator-only `proxy.system.status/set/unset` verbs are on `main`
(PR #214, `3d710ab7`). Its PR 4a ships `SystemProxyState.swift` (the type below, with its Kit
tests, PR #246) ahead of this spec's PR, including `init?(compact:listenAddress:)` over
`proxy.status.system_proxy = { state: off|points_at_us|other|unsupported|needs_privilege|unknown,
host, port, managed_by_us, setting, supported, detail }`; its PR4 (after us) adds `SystemProxyFacts`,
the `proxy.status` polling that writes `Session.systemProxy`, the Proxy ▸ toggle (⌥⌘P) and the
actions `.setSystemProxy`/`.unsetSystemProxy`. It
uses exactly these names and words and does not redefine any of the following.

| Name | Meaning |
|---|---|
| `SystemProxyState` | effective global read-back of the macOS HTTP/HTTPS proxy; `http`/`https: Endpoint?`; `init(settings:)` (Port as number or numeric string); `init?(compact:listenAddress:)` (the bus object; PR #246); `.off`; PR #246's file |
| `SystemProxyState.Endpoint` | `host`, `port`, `address` ("host:port", computed), `init(host:port:)` |
| `SystemProxyRoute` | `.off`, `.thisCore(http:https:)`, `.other(host:port:)` — `state.route(to: listenAddress)` |
| `Session.systemProxy: SystemProxyState?` | declared by this spec's Task 2 (nil, never written by this spec's code — plan call 4); **written by PR4 only**, from the `system_proxy` sub-object of every `proxy.status` poll and from the direct replies of `proxy.system.set`/`unset`; nil = unknown, never rendered as "off" |
| `ConnectionAction.addScopeHost` | title "Add Host…"; opens the Scope page with its add sheet — the Scope entry's remedy button (shared with S-073/S-074/S-080) |
| `ConnectionAction.setSystemProxy`, `.unsetSystemProxy` | **reserved names** for PR4's actions (candidate titles "Set as System Proxy" / "Restore System Proxy", research 22 §4); PR4 fills the system-proxy entry's `actions` and the `systemProxy` step's action with `.setSystemProxy`; empty here |
| `SystemProxyFacts` | PR4's richer value (`managed_by_us`, `setting`, `supported`, `detail`) beside `SystemProxyState`; not read here |
| `TrafficRoute.Kind.systemProxy` / `.allApps` / `.scope` / `.caTrust` | the two routes, and the two facts that gate what they carry (Scope → decryption, CA → HTTPS) |
| `CATrustFacts` | PR D's: fields `{trusted, scope ("user" \| "system"), fingerprint, platform, installing, needsAdmin}`, `init?(status: CAStatus)`, helpers `{text, state, remedy, actions, step, quicCaveat, notTrustedLine, laneTitle, …}`; nil slot = unknown |
| `Session.caTrust: CATrustFacts?` | PR D's published CA state (`Session+CATrust.swift`); the only CA value this spec reads |
| `ConnectionAction.trustCA`, `.openCAPanel` | PR D's (title "Trust the aitmproxy CA"); consumed here as the CA entry's actions (PR D's `actions`) and the `caTrusted` step's action |

**Lane principle** (in `TrafficRoute.detail`, the GLOSSARY, and both surfaces):
*system proxy → every proxy-aware app, regardless of Scope; All Apps → in-scope hosts of every app.*

Words (L = the core's listen address, H:P = a foreign endpoint; lower-case initial, the lane-word
convention, so they can follow a dot, a "·" or a glyph):

| Fact | Line |
|---|---|
| off | `system proxy off — set L as the system proxy, or point a client at it` |
| points at the core, both protocols | `system proxy on · L` |
| points at the core, HTTP only / HTTPS only | `system proxy on · L · HTTP only` / `system proxy on · L · HTTPS only` |
| points at another proxy | `system proxy on · H:P, not this core — set L as the system proxy, or point a client at it` |

The `.other` line must name the endpoint it found and say the core is not the system proxy; it
never reads "off". The sibling's "changed by another app" (research 22 §4) is *its* derived state
— its own snapshot says it set L, the read-back says `.other` — not a `SystemProxyRoute` case and
not defined here. The bare state words a toggle or status row needs are the prefixes above:
`system proxy off`, `system proxy on · L`, `system proxy on · H:P, not this core`.

CA words (one string per fact, both surfaces, all PR D's `text`; S = `scope` rendered "user keychain" / "System keychain" — capital S, PR D verbatim):

| Fact | Line | Detail |
|---|---|---|
| trusted | `CA trusted (S)` — e.g. `CA trusted (user keychain)`, accurate because the core's macOS default install scope is User, the login keychain | `HTTPS on both routes` |
| not trusted | `HTTPS is not captured until the CA is trusted` (the Status step's title is `Trust the aitmproxy CA`; the Flows row and the banner use the line) | `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then` |
| installing (PR D sets `installing`) | `trusting CA…` | as not trusted |
| needs admin (PR D sets `needsAdmin`) | `CA trust needs an administrator` (PR D's `text`; its `remedy` is the longer `needsAdminMacLine`, shown on the CA page, not here) | as not trusted |
| unread / unknown (nil slot) | nothing — no step, no row, no banner clause | — |

Every row is PR D's string (its `text`/`step` helpers), listed here so there is one table;
this spec never sets `installing` or `needsAdmin`.

**Scope words — shared with the improve-loop session's stories S-073/S-074/S-080** (confirmed verbatim):

| Fact | String | Where |
|---|---|---|
| scope empty (closed), core v0.5.9+ | **quoted verbatim, and nothing appended**: `proxy.status.decrypt.advice` = `Nothing is decrypted until a host is in Scope.` (core spec D9: every frontend prints it verbatim and never composes its own sentence; `state` = the same string, period included) | Flows empty-state row, the banner (also when every flow is a tunnel), the `scopeSet` step's detail; identical to the TUI's and web's text and survives a core wording change |
| scope empty (closed), older core (no `decrypt`) | fallback: our own copy of the same words, `Nothing is decrypted until a host is in Scope.` (no remedy suffix) | same |
| the remedy | the **button**, never text: `Add Host…` (`ConnectionAction.addScopeHost`, new here: `show(.scope)` + the Scope page's add sheet). The Status step keeps `Open Scope…` (`.openScope`) because its title already names the task | Flows row, banner button |
| scope empty, Status step | `Add a host to Scope` (today with the DNS hint: `Add a host to Scope (for now as example.com:443)`) → **Open Scope…** | `scopeSet` step title / action |
| scope set (open) | ours: `Scope: N hosts decrypted` via `Format.count` — `Scope: 1 host decrypted`, `Scope: 3 hosts decrypted`; N = `decrypt.scope_hosts` when present, else `scopeHostCount` (the core's `advice` is null in this state) | `scopeSet` done title, the Scope entry's line |
| detail | `Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel` | `TrafficRoute.detail` for `.scope` |
| system proxy / CA lines | as in the tables above | S-073/S-074 reuse them unchanged |

Adjacent vocabulary **owned by that session** (its tunnel-row inspector; not implemented here, listed
so no one re-words it): `HTTPS is not decrypted — add <host> to Scope to see the content`; buttons
`Add <host> to Scope (⌥⏎)` / `Add every host <client> talks to`; after adding `Added — the next
connection to <host> is decrypted`; S-074's failed-handshake line `TLS handshake failed — the client
did not accept the aitmproxy CA.` followed by our CA sentence. `every host is read-only` is retired
everywhere.

### D3. Route derivation (inside `make`)

Let `L` = `listenAddress`, `a` = `CaptureAdvice.make(capability:supported:scopeHostCount:)`
(already computed for the capture lane), `n` = `scopeHostCount`.

System proxy route (`nil` when `systemProxy == nil` — unknown: before PR4, before its first answer,
or a state the core cannot classify); `detail` = `every proxy-aware app, regardless of Scope`.
**Orchestrator ruling 2026-11-01:** the closed entries carry **no action in this PR**; PR4 fills
`[.setSystemProxy]` (its Set as System Proxy, the OS's own prompt). `.openNetworkSettings` is denied.

| `systemProxy.route(to: L)` | open | `line` | `actions` |
|---|---|---|---|
| `.off` | no | `system proxy off — set L as the system proxy, or point a client at it` | `[]` (PR4: `[.setSystemProxy]`) |
| `.other(H, P)` | no | `system proxy on · H:P, not this core — set L as the system proxy, or point a client at it` | `[]` (PR4: `[.setSystemProxy]`) |
| `.thisCore(true, true)` | yes | `system proxy on · L` | `[]` |
| `.thisCore(true, false)` | yes | `system proxy on · L · HTTP only` | `[]` |
| `.thisCore(false, true)` | yes | `system proxy on · L · HTTPS only` | `[]` |

All Apps route (`nil` when `a == .unsupported` or `activeKind == .external`); `detail` = `in-scope hosts of every app`.
**Architect's call:** the All Apps fact is closed only when the extension is NOT on; with it on, the
route is open whatever the scope — the Scope fact below owns the empty-scope clause, so the composed
banner never says it twice. (`CaptureAdvice.onEmptyScope` still drives the capture *lane*, untouched.)

| `a` | open | `line` | `actions` |
|---|---|---|---|
| `.off` | no | `All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)` | `[.openCaptureSettings]` |
| `.awaitingApproval` | no | `All Apps waiting for approval — approve the extension in System Settings` | `[.approveInSystemSettings]` |
| `.degraded(r)` | no | `All Apps degraded — r` | `[.openCaptureSettings]` |
| `.onEmptyScope`, `.on(hosts: n)` | yes | `All Apps on` | `[]` |

Scope fact (always present; `kind = .scope`; `detail` = `Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel`):

Let `d` = `decrypt` when the bus lane's state is `.ok`, else nil (nil also from an older core; the
one-line `BusService` grant has no disconnect reset, so a stale `decrypt` is ignored by rule, not by a
reset); closed ⇔ `d != nil ? !d.decrypting : scopeHostCount == 0`; `N` = `d?.scopeHosts ?? scopeHostCount`.

| state | open | `line` (= `state`: no " — " clause) | `actions` |
|---|---|---|---|
| closed, `d?.advice` present | no | `d.advice` **verbatim** — today `Nothing is decrypted until a host is in Scope.` | `[.addScopeHost, .openScope]` |
| closed, `d == nil` or `d.advice == nil` | no | our fallback, the same words: `Nothing is decrypted until a host is in Scope.` | `[.addScopeHost, .openScope]` |
| open | yes | `Scope: ` + `Format.count(N, "host")` + ` decrypted` (`Scope: 1 host decrypted`) | `[]` |

The text is the core's own sentence so every surface in the product (TUI, web, this app) prints one
string (core spec D9) and a core wording change reaches this app without an edit; the remedy is the
**button** `Add Host…`, never appended text. The open form stays ours: the core's `advice` is null then.

CA fact (`nil` when `caTrust == nil`, i.e. PR D's `Session.caTrust` is nil); `kind = .caTrust`,
`open = trusted`; `line` = PR D's `text`, `actions` = PR D's `actions`, `detail` = `HTTPS on both
routes` when trusted, else `HTTPS is not captured until the CA is trusted — browsers using QUIC load
directly until then`. What those helpers yield (PR D's own code, `CATrustFacts.swift` on
`claude/ca-trust-mac` `4ae616d3`; `installing` wins over `trusted`, which wins over `needsAdmin`):

| `caTrust` | open | `line` (= `text`) | `actions` |
|---|---|---|---|
| `installing == true` | no | `trusting CA…` | `[]` |
| `trusted == true` | yes | `CA trusted (System keychain)` when `scope == "system"`, else `CA trusted (user keychain)` (PR D has no scope-nil form: trusted ⇔ a store said yes) | `[.openCAPanel]` — an open entry's actions are not offered (§D2: empty when open) |
| `needsAdmin == true` | no | `CA trust needs an administrator` | `[.openCAPanel]` (PR D offers the panel only; the step's action is `.openCAPanel`) |
| otherwise | no | `HTTPS is not captured until the CA is trusted` | `[.trustCA, .openCAPanel]` (title "Trust the aitmproxy CA" — the banner's button when the CA is the first shown fact with an action) |

The open entry stores `actions = []` like every other open entry (PR D's `[.openCAPanel]` for a trusted
fact is the CA page's affordance, not a route remedy); the closed entries store PR D's `actions` as is.

`advice` = `[systemProxy, allApps, scope, caTrust].compactMap { $0 }.filter { !$0.open }`, in that
order, when the bus lane's state is `.ok`, else `[]` (the scope is known only through the bus).
`anyOpen` counts the two routes only.

### D4. Words and where they appear

**Getting-started steps**, in order: `coreRunning`, `busConnected`, `systemProxy`,
`extensionOn`, `scopeSet`, `caTrusted`, `firstFlow`.

- `systemProxy` (new): **omitted from `steps` while `routes.systemProxy == nil`** (the fact is
  unknown — before PR4, before its first answer: anti-goal "lying"). `title` =
  `routes.systemProxy.line` verbatim; `detail` = the route's `detail`; `done` = `open`; `action` =
  nil in this PR (PR4 sets `.setSystemProxy` when closed).
- `extensionOn`: `unsupported` → "All Apps capture is not in this build" (unchanged, action nil);
  `.off` / `.awaitingApproval` / `.degraded` → `title` = the All Apps route `line`, `detail` = the
  route's `detail`, `done` false, action `.turnCaptureOn` / `.approveInSystemSettings` /
  `.openCaptureSettings` (unchanged actions); `.onEmptyScope` / `.on` → "All Apps is on", done,
  `detail` = the route's `detail` (**Architect's call**: was "Capture extension is on", pre-rev-3
  vocabulary; one string, test-pinned).
- `scopeSet`: keeps its title and action. Undone (the Scope entry closed, §D3): `title` = "Add a host to
  Scope (for now as example.com:443)" (unchanged; the DNS hint goes with the provider fix), action
  `.openScope`, `detail` = the Scope entry's `line` (the quoted core sentence; our same-words fallback
  on an older core). Done: `title` = `Scope: N hosts
  decrypted` with N = `decrypt.scopeHosts` when present (`Format.count`; was "Scope has n hosts"),
  action nil, `detail` = the Scope entry's `detail`.
- `coreRunning`, `busConnected`, `firstFlow`: unchanged, `detail` nil.
- `caTrusted` (PR D's `GettingStartedStep.Kind`): **omitted while `routes.caTrust == nil`** (unread
  or unknown: we can neither say it is trusted nor that it is not, and a step that cannot name its
  fix is noise — the CA page shows the raw detail). `done` = `open`; `title` and `action` are PR D's
  `step` (`CATrustFacts.step`, 4ae616d3): `title` = `Trust the aitmproxy CA` for the plain not-trusted
  fact, else `text` (`CA trust needs an administrator` when `needsAdmin`, `trusting CA…` while
  `installing`, `CA trusted (user keychain)` / `(System keychain)` when done); `action` =
  `actions.first` when not done — `.trustCA` for the plain not-trusted fact (PR D's confirm and admin
  prompts), **`.openCAPanel` when `needsAdmin`**, nil while `installing` — and nil when done.
  `.openCAPanel` stays the Flows row's second button, and the CA page is reachable from the sidebar
  and Proxy ▸ Certificate Authority…; `detail` = the route's `detail`. **Hand-over from PR D:** PR D
  ships an interim `StatusPanel` insertion (`stepsWithCATrust`, `CATrustRow`) so its step is visible
  before this spec lands — it inserts `session.caTrustStep` **after `busConnected`**; this spec's step
  replaces it — the insertion and the row call are removed, the words stay, and the step **moves to
  after `scopeSet`** (§D7, plan Task 2b). **PR D's two nil-facts rows are dropped here (Architect's
  call, open question 21):** `CATrustFacts.unknownStep()` ("CA trust unknown — open the Certificate
  Authority panel") and `notGeneratedStep()` ("CA not generated yet — the core creates it on first
  start"), which PR D shows when `ca.status` was read but `caTrust` is nil, do not enter this list,
  because `make` reads `Session.caTrust` and nothing else (the orchestrator's ruling) and this spec
  omits the step whenever `routes.caTrust == nil`; the first-run sheet (`Shell/SetupSheet.swift`,
  PR D's) keeps `session.caTrustStep` with both rows, and the CA page shows the raw status.
  The Status step title and the Flows line differ on purpose for this one fact (a checklist names
  the task, a flow list names the consequence); both strings come from the model.

Route lines start lower-case (except the proper name "All Apps") and the Status rows show them
verbatim, done or not (**Architect's call**: one string per fact beats a sentence-cased twin; the
sibling toggle reuses the same strings). `StepRow` gains `.help(step.detail ?? step.title)` —
one line in `StatusPanel.swift`.

**Flows empty state** (`EmptyFlows`, unfiltered): the "No flows yet" headline stays. Under it,
when `routes.advice` is non-empty, one row per entry — the `line` with every action in the entry's
`actions` as `SmallButton`s (Add Host… and Open Scope… for the Scope row; Trust the aitmproxy CA and
the CA page for the CA row; All Apps Settings… for the All Apps row; none for the system-proxy row
until PR4 fills `.setSystemProxy`), and the entry's `detail` as a smaller tertiary line beneath —
*instead of* the generic "Point a client at L or open the browser." line; when `advice` is empty the
generic line stays as today. The filtered state ("No flows match") is unchanged.

**Flows banner**: §D5.

### D5. The banner predicate (exact) and the one-line rule

```
knownOpenRoute ⇔  (routes.systemProxy?.open ?? false)  ∨  (routes.allApps?.open ?? false)
closedRoutes   =  knownOpenRoute ? [] : [systemProxy, allApps].compactMap{$0}.filter{!$0.open}   // an unknown system proxy (nil) is never named
scopeClosed    ⇔  !routes.scope.open
allTunnels     ⇔  flowCount > 0  ∧  tunnelledFlowCount == flowCount
caClosed       ⇔  routes.caTrust != nil  ∧  !routes.caTrust.open
shown          =  closedRoutes
               +  (scopeClosed ∧ (!closedRoutes.isEmpty ∨ allTunnels) ? [scope] : [])
               +  (caClosed ? [caTrust] : [])                       // priority order
banner != nil  ⇔  flowCount > 0  ∧  bus.state == .ok  ∧  !shown.isEmpty
banner         =  shown.map(\.state).joined(" · ")            // text: states only, no remedy clause
bannerAction   =  shown.first { !$0.actions.isEmpty }?.actions.first   // the one button: the first shown fact that has a remedy
```

**Why `knownOpenRoute`, not a "both routes read and closed" rule (Architect's call, 2026-11-01).** With no
reader of our own the system proxy is unknown on every build until PR4 lands, and unknown again until
PR4's first answer; a banner that waited for a *known-closed* system proxy would never name a closed All
Apps. The rule names only what is known closed and says nothing about the unknown (anti-goal "lying"):
an unknown system proxy beside an open All Apps is a known open route — no banner; beside a closed All
Apps the banner reads `All Apps off …` and never mentions the system proxy. **`bannerAction` skips an
entry with no action (Architect's call):** a closed system-proxy fact carries none until PR4, and must
not swallow the button.

`tunnelledFlowCount` = the rows whose `FlowRow.tls == .tunnelled` (`AitmproxyKit/Flow.swift`:
"CONNECT tunnel passed through; not decrypted"), counted by `Session+Connection` and passed into
`make`. The core (v0.5.9, PR #228) surfaces every CONNECT as a row with `tunnel` =
`passthrough` | `decrypted` | `failed`; the Kit decoder maps `passthrough` → `.tunnelled` (plan Task
1c, its own claim, §D2). Until Task 1c is in, `FlowSummary` still maps every `https`/`wss` row to
`.decrypted`, `tunnelledFlowCount` is 0, `allTunnels` is false and TR-AC20 is deferred; with Task
1c in, TR-AC20 is unconditional.

**Quoted sentence in the composed line.** The Scope `state` is the core's sentence verbatim,
period included, so a composed line reads `… · Nothing is decrypted until a host is in Scope. · …`
(verbatim beats typography — the text must equal the TUI's and web's); its remedy is the button
`Add Host…`. A single shown Scope fact yields exactly the core's sentence.

**Why "all tunnels", not "any tunnel" (Architect's call).** A tunnel row carries its own remedy
in the inspector (the improve-loop session's `Add <host> to Scope (⌥⏎)`), so one unreadable row
among readable ones needs no banner. When every row is a tunnel the operator can read nothing and
the one line says why; with a route open and some rows readable, the Scope fact is not banner
material (anti-goal: nagging). It always appears in the empty state when closed.

**Composed form (Architect's call, after the improve-loop observation; shape aligned with core
spec D9).** Up to four facts compete for one `Tok.Size.Row.dense` (28 pt) line, and full lines with
remedies would be ~260 characters. The banner names every shown fact by its *state words* joined
with ` · ` and carries **no remedy text at all**; the remedy is the banner's one **button**, the
first shown fact's primary action: system proxy → PR4's `Set as System Proxy` (none in this PR),
All Apps off → `All Apps Settings…`, Scope → `Add Host…`, CA → `Trust the aitmproxy CA`. So the
CA remedy becomes a button too, and the Scope text is the core's sentence untouched. Literals
(button in the last column; "system proxy unknown" is every build until PR4 lands):

| Shown facts | `banner` | `bannerAction` |
|---|---|---|
| fresh install until PR4: system proxy unknown + All Apps off + scope empty + CA not trusted | `All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` | `.openCaptureSettings` |
| fresh install with PR4: system proxy off + All Apps off + scope empty + CA not trusted | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` | `.openCaptureSettings` in this PR (PR4: `.setSystemProxy`) |
| system proxy off + All Apps off + scope empty | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.` | `.openCaptureSettings` (PR4: `.setSystemProxy`) |
| system proxy off + All Apps off + scope set | `system proxy off · All Apps off` | `.openCaptureSettings` (PR4: `.setSystemProxy`) |
| system proxy unknown + All Apps off + scope set | `All Apps off` | `.openCaptureSettings` |
| a route open + scope empty + every row a tunnel | `Nothing is decrypted until a host is in Scope.` | `.addScopeHost` |
| a route open + scope empty + every row a tunnel + CA not trusted | `Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` | `.addScopeHost` |
| a route open + scope empty + some rows readable (plain HTTP) | nil, or `HTTPS is not captured until the CA is trusted` when the CA is not trusted | — / `.trustCA` |
| a route open + CA not trusted | `HTTPS is not captured until the CA is trusted` | `.trustCA` |
| no extension in the build + system proxy off + scope empty | `system proxy off · Nothing is decrypted until a host is in Scope.` | `.addScopeHost` (PR4: `.setSystemProxy`) |
| no extension in the build + system proxy off + scope set | `system proxy off` | nil in this PR (PR4: `.setSystemProxy`) |
| no extension in the build + system proxy unknown + scope empty + every row a tunnel | `Nothing is decrypted until a host is in Scope.` | `.addScopeHost` |

A closed CA fact alone does not close the routes, but it adds its state whenever flows exist and
HTTPS is not trusted: the flows the operator sees are the plain-HTTP ones and every HTTPS attempt
is failing right now.

The view (`RouteBanner`) shows `banner` in one line — `lineLimit(1)`, `truncationMode(.tail)`,
`Tok.Size.Row.dense` (28 pt; `Tokens.swift:296`), tertiary ink, the former `ScopeBanner` shape — with
the full `banner` and the shown entries' `detail`s joined with ` · ` as its `.help`, and **one**
`SmallButton` for `bannerAction` (`All Apps Settings…` / `Add Host…` / `Trust the aitmproxy CA`;
PR4 adds `Set as System Proxy`); nothing when `bannerAction` is nil; nothing else sits on the line.

**One banner line, everywhere flows are listed (§D8).** On every page that renders the flow
table — Flows, Pinned, Domains, Apps — the route banner is the only banner: shown iff
`routes.banner != nil`, above the table; when nothing is shown, no banner at all. `ScopeBanner`
and `AppsAttributionBanner` are no longer rendered on any page (§D8). The column header therefore
sits at most one 28 pt line (`Tok.Size.Row.dense`) below the chip bar, never two (56 pt).

### D6. Where the live facts come from (no reader of our own — orchestrator rulings 2026-11-01)

Three `Session` facts feed `make`; this spec writes exactly one of them.

- **`Session.systemProxy: SystemProxyState?`** — declared by this spec's Task 2 as a plain observed
  property on `Session.swift`, nil at init and **never written by this spec's code** (plan call 4).
  PR4 (system-proxy session, after this PR) writes it from the `system_proxy` sub-object of every
  `proxy.status` poll (existing cadence — `refreshProxyStatus()` every 500 ms tick; the core refreshes it ≤ 5 s and immediately
  after set/unset) and from the direct replies of `proxy.system.set`/`unset`, via PR #246's
  `SystemProxyState.init?(compact:listenAddress:)` (points_at_us → both endpoints at the listen
  address, other → both at host:port, off → `.off`, unsupported / needs_privilege / unknown /
  malformed → nil). Until PR4 lands the value is nil on
  every build: the `systemProxy` step is omitted, no system-proxy words appear anywhere, and nothing
  reads "off". There is no `Bus/SystemProxyReader.swift`, no `CFNetworkCopySystemProxySettings()`
  call and no `refreshSystemProxy()` in this PR — the earlier in-app reader was withdrawn by the
  orchestrator (two readers is two derivations; the core's `proxy.system.status` is the one reader).
- **`Session.decrypt: DecryptStatus?`** — the one `BusService.swift` line this PR is granted, inside
  the existing `refreshProxyStatus()`: `session.decrypt = status["decrypt"].flatMap(DecryptStatus.init)`
  (no new verb, no new read: `proxy.status` is already polled every tick; no `defer` reset — §D3
  ignores `decrypt` whenever the bus lane is not `.ok`, so a stale value after a disconnect changes
  nothing). An older core without `decrypt` leaves it nil and the Kit falls back to `scopeHostCount`.
- **`Session.caTrust: CATrustFacts?`** — PR D's published CA state (`Session+CATrust.swift`, branch
  `claude/ca-trust-mac`), read as is: computed by PR D from the raw `Session.caStatus` via
  `CATrustFacts(status:)` (nil = unknown or no certificate; `installing`/`needsAdmin` applied by PR D;
  reset by `Session.forgetCATrust()` on disconnect) on PR D's cadence (`BusService.pollLoop` →
  `session.refreshCAStatus()` on the first tick and every 10th 500 ms tick,
  `BusService.caStatusEveryTicks = 10`, forced after `trustCA()`/`untrustCA()`). A trust change made
  in Keychain Access or by `aitm ca install` from a terminal reaches both pages within ~5 s without a
  visit to the CA page. This spec adds no CA read and no `Session.caStatus`.

`Session+Connection.connectionSummary` passes `systemProxy: systemProxy`, `decrypt: decrypt`,
`tunnelledFlowCount: rows.count { $0.tls == .tunnelled }` and `caTrust: caTrust` to `make`. The CA
page keeps its own read (untouched); the two agree within one CA tick.

### D7. Views and files (the claim list — the plan's gate 2 records the orchestrator's answers of 2026-11-01)

- `AitmproxyKit/ConnectionSummary.swift`, `Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (the
  predicate-table test). **PR 4a's, read-only here:** `AitmproxyKit/SystemProxyState.swift` and
  `Tests/AitmproxyKitTests/SystemProxyStateTests.swift` (TR-AC1/2). **PR D's, read-only here:**
  `AitmproxyKit/CATrustFacts.swift` (or wherever PR D puts the type), `AitmproxyKit/Panels/CAStatus.swift`,
  `Session+CATrust.swift`, `Panels/CAPanel.swift` — not changed by anyone here.
- `Session.swift`: `var systemProxy: SystemProxyState?` (nil; written by PR4 only, §D6) and
  `var decrypt: DecryptStatus?` (from `proxy.status.decrypt`, nil until read / on an older core).
  `Session.caTrust`/`caStatus` are PR D's.
- `Session+Connection.swift` (on PR D's merged SHA — PR D edits the same `perform` switch; sequential,
  never simultaneous): `connectionSummary` passes `systemProxy:`, `decrypt:`, `tunnelledFlowCount:`
  and `caTrust: caTrust`; new one-line accessor `var trafficRoutes: TrafficRoutes { connectionSummary.routes }`
  — the only thing the Flows surfaces read, so `connectionSummary`'s reader allow-list does not grow
  and no lane word can leak into `ShellView.swift`; `perform(connection: .addScopeHost)` does
  `show(.scope)` then `scopeSheetVisible = true` (the Proxy ▸ Scope… menu's add-sheet path) and
  returns `true`. No `.openNetworkSettings` case (denied).
- `Bus/BusService.swift`: **exactly one added line**, in the existing `refreshProxyStatus()`:
  `session.decrypt = status["decrypt"].flatMap(DecryptStatus.init)` (§D6). No `refreshSystemProxy()`,
  no `refreshCAStatus()`, no reader file, no reset line, no new verb.
- `AitmproxyKit/DecryptStatus.swift` (new) + `Tests/AitmproxyKitTests/DecryptStatusTests.swift` (new).
- `AitmproxyKit/FlowSummary.swift`, `AitmproxyKit/Flow.swift` (`TunnelMode`, `TunnelReason`, the five
  `FlowRow` fields, `isTunnel`, `==`), `AitmproxyKit/FlowDetail.swift` (`TunnelInfo`, `tunnel`,
  `passive`), `AitmproxyKit/FlowDetail+Wire.swift` + `Tests/AitmproxyKitTests/FlowSummaryTests.swift`
  (new), `FlowRowEqualityTests.swift`, `FlowDetailWireTests.swift` — **plan Task 1c, claim granted
  2026-11-01**; file-disjoint from Task 1; nothing else in this spec touches them.
- `Shell/RouteBanner.swift` (new): renders `session.trafficRoutes.banner` and its one `bannerAction`
  button through `session.perform(connection:)`; `.openCaptureSettings`, which `perform` leaves to
  the view, sets `settingsTab = .capture` and calls `openSettings()` exactly as `AppsAttributionBanner`
  does. Mentions no `connectionSummary`, `ConnectionSummary`, `LaneDot`, `LaneState`, `CaptureSwitch`,
  `capture.enabled`, `extensionController`.
- `Shell/ShellView.swift`, two hunks only: (1) `EmptyFlows` (struct ~316–336) reads
  `session.trafficRoutes.advice` (via `@Environment(Session.self)`, or a `routes:` parameter
  passed from the existing `flowTable` overlay call, `ShellView.swift:258` — builder's choice) and gains the
  route rows; `allowsHitTesting` stays off except for its buttons. (2) In `MainView.flows`
  (~171–200) the `ScopeBanner()` branch and the `AppsAttributionBanner()` block are removed and one
  insertion takes their place: `if session.trafficRoutes.banner != nil { RouteBanner(); Rule() }`
  on every list page (§D8 lists the two removed call sites verbatim). The `AppsAttributionBanner`
  struct stays. Nothing else in the file changes; the `ExtensionController` block (rule 5) and
  lines 49–62 are untouched.
- `Panels/StatusPanel.swift` — **stated once, here; TR-AC8 and the plan refer to it:** (a) the one
  `.help(step.detail ?? step.title)` line on `StepRow` (§D4); (b) `.addScopeHost` joins the
  handled-by-`perform` case list in `run(_:)` (its switch over `ConnectionAction` is exhaustive; PR D
  adds its own `.trustCA`/`.openCAPanel` cases); (c) the PR D hand-over: the interim
  `stepsWithCATrust` insertion and the `CATrustRow` call are removed — this spec's `caTrusted` step
  and the Flows CA row carry the same words (§D4).
- `tools/check-connection-words.sh`: §D9. `tools/check-capture-toggle.sh` (granted on the
  fixture-removal mac SHA; that PR modifies the script): the NS-AC8 banner pins move to
  `RouteBanner()` (§D8).
- **Not touched** (withdrawn with `.openNetworkSettings`, 2026-11-01): `App.swift`,
  `AitmproxyKit/CommandMap.swift`, `apps/mac/docs/BRIEF.md`, `apps/mac/docs/GLOSSARY.md` — the Proxy
  menu gets only PR4's toggle (⌥⌘P), nothing of ours. **Not touched** either: `apps/mac/docs/STORIES.md`
  (the improve-loop session owns S-073/S-074/S-080 and writes them with §D2a's strings),
  `Bus/SystemProxyReader.swift` (never created), `Panels/CAPanel.swift`, `Session+CATrust.swift`.

### D8. One banner line: `ScopeBanner` and `AppsAttributionBanner` retire from the list pages

Observed by the improve-loop session on `main 9dba3d9f` (fresh install, empty scope, no source
app): `ScopeBanner` ("No scope set — every host is read-only until you add one") and
`AppsAttributionBanner` ("Flows carry no source app yet, so this page cannot group them.") stacked
above the Apps list — each a `Tok.Size.Row.dense` row (28 pt: `Tokens.swift:296`; `ScopePanel.swift:268`,
`ShellView.swift:368`), so two rows push the column header 56 pt down — and a click aimed at row 1
hit the header and sorted by URL. (The session's note did not record a pixel measurement; the
live step, TR-AC19, measures the header offset against that token.)

Rule: on every page that lists flows, at most ONE `Tok.Size.Row.dense` (28 pt) banner line is ever
shown, and it is the route banner of this spec. It absorbs the scope line (the Scope fact: `Nothing is decrypted until a
host is in Scope.`; "every host is read-only" is retired) and replaces `AppsAttributionBanner` (its "no source app" case is the
All Apps / scope / CA state in the shared vocabulary, with the one remedy button). Neither old banner is
rendered when the route banner is, and when nothing is closed no banner is shown at all.

**Apps-page predicate.** Rows exist and `clients` is empty → the route banner iff
`routes.banner != nil` (the same rule as every other list page: both routes closed, every row a
tunnel with an empty scope, or the CA not trusted), else no banner — the Client column reads "—" and nothing claims a reason, because with
every fact open the only remaining reason is that proxied flows carry no source app, which is
the icons-and-names work, not an operator remedy. Rows empty → `AppsEmptyState` as today
(unchanged; it is an empty state, not a banner).

What stays: the `ScopeBanner` struct in `Panels/ScopePanel.swift` (untouched, now unreferenced;
delete with a later cleanup) and the `AppsAttributionBanner` struct in `ShellView.swift` (kept so
`check-capture-toggle.sh`'s NS-AC3 body pins hold; its call site goes). The read-only-scope fact
stays visible in the status bar's scope item and on the Scope page.

Call sites removed in `Shell/ShellView.swift`, both inside `MainView.flows` (~185–193 on `main
8e19c2e3`): (1) `} else if !Store.usesFixtures, session.scopeHosts.isEmpty, case .connected =
session.bus { ScopeBanner(); Rule() }` (as the fixture-removal PR leaves it), (2)
`if session.page == .apps, session.clients.isEmpty, !session.rows.isEmpty { AppsAttributionBanner();
Rule() }`. In their place, one insertion: `if session.trafficRoutes.banner != nil { RouteBanner();
Rule() }`, on every list page.

**Tripwire follow-through.** `tools/check-capture-toggle.sh` NS-AC8 pins `AppsAttributionBanner()`
rendered exactly once in `MainView` and ordered above `if session.splitView {`. Those pins move
to the route banner: `RouteBanner()` exactly once in `MainView`, guarded by
`session.trafficRoutes.banner != nil {`, ordered above `if session.splitView {`;
`AppsAttributionBanner()` count in `MainView` = 0. The NS-AC3 struct/body pins and the
`AppsEmptyState` pins are unchanged.

### D9. Tripwire changes (`tools/check-connection-words.sh`)

- Rule 1 word list: add an opening-quote prefix pattern so a view that spells
  `"system proxy off`, `"system proxy on`, `"All Apps on`, `"All Apps off`, `"All Apps waiting`,
  `"All Apps degraded`, `"Nothing is decrypted`, `"Scope:`, `"HTTPS is not captured`,
  `"Trust the aitmproxy CA`, `"CA trusted`, `"trusting CA` or `"CA trust needs` fails (the existing list matches whole literals only, and the route
  lines interpolate the address, so a prefix pattern is required).
- Rule 2 reader allow-list: **unchanged**. `Shell/ShellView.swift` and `Shell/RouteBanner.swift`
  read `trafficRoutes`, never `connectionSummary`.
- New rule 3: `trafficRoutes` is defined exactly once, in `Session+Connection.swift`, as
  `connectionSummary.routes`; `Shell/RouteBanner.swift` mentions none of `connectionSummary`,
  `ConnectionSummary`, `LaneDot`, `LaneState`.

### D10. Predicate table

SP = system proxy route; AA = `CaptureAdvice` (on = `.on`/`.onEmptyScope`); SC = `decrypt.scopeHosts`
when `decrypt` is present, else `scopeHostCount` (the scope line is the quoted core sentence when
`decrypt.advice` is present, the fallback otherwise — same `state`, so every banner literal below holds
for both);
T = every row a tunnel; bus `.ok` throughout (with the bus not `.ok`: no advice, no banner, steps
as today). SP "unknown (nil)" is every build until PR4 lands. L = listen address; H:P = a foreign endpoint. The Kit test makes one
`ConnectionSummary.make` call per row with literal inputs and pins the literal lines. "E" = the
Flows empty-state entries (0 flows), "B" = the banner (flows > 0).

| SP | AA | SC | Status `systemProxy` / `extensionOn` / `scopeSet` | E | B (T false) | B (T true) |
|---|---|---|---|---|---|---|
| unknown (nil) | on | 0 | absent / ✓ All Apps is on / ○ Add a host to Scope … | scope line | no | scope line |
| unknown — the core's partial case (`other` at our own address: HTTP → us, HTTPS off; PR #246 maps it to nil) | any | any | absent / per AA / per SC | per AA / SC | no system-proxy contribution (step omitted, banner as if unknown) | same |
| off | on | n | ○ system proxy off — … / ✓ / ✓ Scope: n hosts decrypted | system proxy line | no | no (T impossible with a host decrypting — if seen, no) |
| off | on | 0 | ○ system proxy off — … / ✓ All Apps is on / ○ Add a host to Scope … | system proxy line, scope line | no | `Nothing is decrypted until a host is in Scope.` |
| unknown (nil) | off / awaiting / degraded | 0 | absent / ○ All Apps off — … (or waiting / degraded) / ○ Add a host … | All Apps, scope lines | `All Apps off · Nothing is decrypted until a host is in Scope.` (waiting/degraded state words likewise), button All Apps Settings… | same |
| unknown (nil) | off | n | absent / ○ / ✓ | All Apps line | `All Apps off` | same |
| off | off / awaiting / degraded | 0 | ○ … / ○ All Apps off — … (or waiting / degraded) / ○ Add a host … | system proxy, All Apps, scope lines | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.` (waiting/degraded state words likewise) | same |
| off | off | n | ○ / ○ / ✓ | system proxy, All Apps lines | `system proxy off · All Apps off` | same |
| off | unsupported or external core | 0 | ○ / "not in this build" or lane / ○ | system proxy, scope lines | `system proxy off · Nothing is decrypted until a host is in Scope.` | same |
| off | unsupported or external core | n | ○ / … / ✓ | system proxy line | `system proxy off` | same |
| other(H,P) | any | any | ○ system proxy on · H:P, not this core — … / per AA / per SC | as the "off" rows with the other line | as the "off" rows with the other state | same |
| thisCore(·,·) | on | 0 | ✓ system proxy on · L [· HTTP(S) only] / ✓ / ○ Add a host … | scope line | no | scope line |
| thisCore(·,·) | on | n | ✓ / ✓ / ✓ | generic line | no | no |
| thisCore(·,·) | off / awaiting / degraded | 0 | ✓ / ○ / ○ | All Apps line, scope line | no (a route is open) | scope line |
| thisCore(·,·) | unsupported | any | ✓ / … / per SC | scope line when SC = 0 | no | scope line when SC = 0 |

The CA fact is orthogonal to every row above and adds one column each:

| CA | Status `caTrusted` step | E (appended last) | B |
|---|---|---|---|
| nil (unread / unknown) | absent | nothing | the row's value |
| trusted (scope user) | ✓ CA trusted (user keychain) | nothing | the row's value |
| not trusted | ○ Trust the aitmproxy CA (button Trust the aitmproxy CA) | `HTTPS is not captured until the CA is trusted` (buttons Trust the aitmproxy CA, the CA page) | the row's states + ` · HTTPS is not captured until the CA is trusted`; where the row says **no** and flows > 0, the CA line alone with the button Trust the aitmproxy CA |
| installing (PR D) | ○ trusting CA… | `trusting CA…` | as not trusted |

## Acceptance criteria

Ordinals are the ids. Kit tests (literal strings), `L = "127.0.0.1:8080"`; TR-AC1/2 are the
`SystemProxyState` contract PR 4a proves, TR-AC15 the `CATrustFacts` contract PR D proves.

1. **TR-AC1 [kit-unit — contract; implemented and proved by PR #246's `SystemProxyStateTests`]**
   `SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 9090, "HTTPSEnable": 1,
   "HTTPSProxy": "127.0.0.1", "HTTPSPort": 9090])` → `http == Endpoint(host: "127.0.0.1", port: 9090)`, `https`
   the same, `http?.address == "127.0.0.1:9090"`; `["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080,
   "HTTPSEnable": 0]` → `https == nil`; **a numeric-string port** `["HTTPEnable": 1, "HTTPProxy": "127.0.0.1",
   "HTTPPort": "9090"]` → `http?.port == 9090`, and `"HTTPPort": "abc"` → `http == nil`; an absent or `0` Enable
   yields nil; `SystemProxyState(settings: [:]) == .off`.
2. **TR-AC2 [kit-unit — contract; PR #246]** `route(to: L)`: off → `.off`; both at `127.0.0.1:8080` →
   `.thisCore(http: true, https: true)`; both at `localhost:8080` → the same; HTTP at
   `127.0.0.1:8080`, HTTPS nil → `.thisCore(http: true, https: false)`; both at `127.0.0.1:9090`
   → `.other(host: "127.0.0.1", port: 9090)`; HTTP at `10.0.0.1:3128`, HTTPS at `127.0.0.1:8080`
   → `.thisCore(http: false, https: true)`; HTTP nil, HTTPS at `10.0.0.1:3128` →
   `.other(host: "10.0.0.1", port: 3128)`; listen `0.0.0.0:8080` with proxy `127.0.0.1:8080` →
   `.thisCore(true, true)`. `init?(compact:listenAddress:)` (PR #246): `{state: "points_at_us", host: "127.0.0.1", port: 8080}` →
   `route(to: L) == .thisCore(http: true, https: true)`; `{state: "other", host: "127.0.0.1", port: 9090}` → `.other(host: "127.0.0.1", port: 9090)`;
   `{state: "off"}` → `.off`; `{state: "unknown"}`, `{state: "unsupported"}`, `{state: "needs_privilege"}`, `{}` → nil;
   **PR #246's listen-address vectors:** `listenAddress: "::1:8080"` (a bare IPv6 literal, no brackets) → nil;
   `listenAddress: ":::8080"` → nil (the core prints `[::]:8080`, which parses; a malformed listen address is
   unknown, never a match).
   **the partial case:** `{state: "other", host: "127.0.0.1", port: 8080}` with `listenAddress: L` → nil (unknown — the
   core reports "HTTP → us, HTTPS off" as `other` at our own address; the route step is omitted and the banner
   gains nothing until PR4's facts carry the verb's `state`/`detail`).
3. **TR-AC3 [kit-unit]** `make(core: nil, activeKind: .embedded, bus: .connected("127.0.0.1:60745"),
   role: "operator", roleWarning: false, capability: .capturing, captureSupported: true,
   scopeHostCount: 0, flowCount: 0, listenAddress: L, systemProxy: .off).routes.advice.map(\.line) ==
   ["system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it",
   "Nothing is decrypted until a host is in Scope."]`; `advice.map(\.kind) == [.systemProxy, .scope]`
   (All Apps is on, so open: `routes.allApps?.line == "All Apps on"`); `advice.map(\.detail) ==
   ["every proxy-aware app, regardless of Scope", "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"]`;
   `advice[0].actions == []` (PR4 fills `.setSystemProxy`); `advice[1].actions == [.addScopeHost, .openScope]`;
   `routes.scope.state == "Nothing is decrypted until a host is in Scope."` (= its line);
   `banner == nil`, `bannerAction == nil`; `anyOpen == true` (All Apps). The same with `flowCount: 6` → `advice.map(\.kind) == [.systemProxy, .scope]` (advice lists closed facts regardless of rows; the empty-state view alone decides when to show it) and
   `banner == nil` (a route is open and the rows are readable); with `flowCount: 6, tunnelledFlowCount: 6`
   → `banner == "Nothing is decrypted until a host is in Scope."`; with `capability: .inactive, flowCount: 6` →
   `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`
   (the system-proxy entry has no action in this PR). The same with `systemProxy` both at `127.0.0.1:9090` and `flowCount: 0` →
   `advice[0].line == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`
   and no advice line contains `"off"`. **Quoted core sentence:** the same inputs plus
   `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Nothing is decrypted until a host is in Scope.")` →
   `routes.scope.line == "Nothing is decrypted until a host is in Scope."` (verbatim, period included),
   `routes.scope.state == "Nothing is decrypted until a host is in Scope."` (period kept), `routes.scope.open == false`, `actions == [.addScopeHost, .openScope]`; with `flowCount: 6, tunnelledFlowCount: 6`
   → `banner == "Nothing is decrypted until a host is in Scope."`, `bannerAction == .addScopeHost`; with `capability: .inactive, flowCount: 6` →
   `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`
   (identical to the fallback composition). **Stale list:** `decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil)` with
   `scopeHostCount: 0` → `routes.scope.open == true`, `line == "Scope: 2 hosts decrypted"`
   (N comes from `decrypt`), no `.scope` entry in `advice`, and with `flowCount: 6, tunnelledFlowCount: 6` →
   `banner == nil` (the Scope fact follows `decrypt`, not the stale list). `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil)` →
   the fallback `line == "Nothing is decrypted until a host is in Scope."`. **Bus not `.ok`:** the quoted inputs with
   `bus: .disconnected` → `routes.scope.line == "Nothing is decrypted until a host is in Scope."` from `scopeHostCount`
   (a `decrypt` value is ignored while the bus lane is not `.ok`), `advice == []`.
4. **TR-AC4 [kit-unit, predicate table]** One `make` call per row of §D10 pinning `routes` and
   the steps, including: `.inactive` → All Apps line `"All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`
   with `[.openCaptureSettings]`; `.pendingApproval` → `"All Apps waiting for approval — approve the extension in System Settings"`,
   `[.approveInSystemSettings]`; `.degraded("x")` → `"All Apps degraded — x"`; `.capturing` with
   `scopeHostCount: 1` → `routes.allApps?.line == "All Apps on"`, open, `[]`, and
   `routes.scope.line == "Scope: 1 host decrypted"`, open; `scopeHostCount: 3` → `"Scope: 3 hosts decrypted"`;
   HTTP-only at the core →
   `"system proxy on · 127.0.0.1:8080 · HTTP only"`, open; both at the core → `"system proxy on · 127.0.0.1:8080"`;
   `systemProxy: nil, .capturing, scopeHostCount: 0` → `routes.systemProxy == nil` and `advice` holds
   the scope line only; **system proxy unknown, All Apps off:** `systemProxy: nil, .inactive, scopeHostCount: 0, flowCount: 3`
   → `banner == "All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`,
   no `"system proxy"` anywhere in `banner` or `advice`; `systemProxy: nil, .inactive, scopeHostCount: 2, flowCount: 3`
   → `banner == "All Apps off"`; `captureSupported: false` → `routes.allApps == nil`, and with `systemProxy: .off,
   scopeHostCount: 2, flowCount: 3` the banner is the system-proxy state alone (`"system proxy off"`, `bannerAction == nil`
   in this PR), with `scopeHostCount: 0`
   it is `"system proxy off · Nothing is decrypted until a host is in Scope."` with `bannerAction == .addScopeHost`;
   `captureSupported: false, systemProxy: nil, scopeHostCount: 0, flowCount: 3` → `banner == nil`, and with
   `tunnelledFlowCount: 3` → `banner == "Nothing is decrypted until a host is in Scope."`; `systemProxy: .off, capability: .capturing,
   scopeHostCount: 2, flowCount: 3` → `banner == nil` (one route open) and `anyOpen == true`;
   `systemProxy` at `127.0.0.1:9090`, `.capturing`, `scopeHostCount: 2`, `flowCount: 3` →
   `banner == nil`; bus `.disconnected` → `advice == []`, `banner == nil`; `activeKind: .external`
   → `routes.allApps == nil`.
5. **TR-AC5 [kit-unit]** Steps: with `systemProxy: nil`, `steps.map(\.kind)` contains no
   `.systemProxy`; with `systemProxy: .off` it is `[.coreRunning, .busConnected, .systemProxy,
   .extensionOn, .scopeSet, .firstFlow]` and the `.systemProxy` step has `done == false`,
   `title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`,
   `detail == "every proxy-aware app, regardless of Scope"`, `action == nil` (PR4: `.setSystemProxy`);
   with both protocols at `127.0.0.1:9090` the title is the `not this core` line, undone; with
   both at the core it is done with `title == "system proxy on · 127.0.0.1:8080"`, action nil,
   and `allStepsDone` is then true when the other steps are. `.capturing, scopeHostCount: 0` →
   `extensionOn.title == "All Apps is on"` (done, `detail == "in-scope hosts of every app"`) and
   `scopeSet.title == "Add a host to Scope (for now as example.com:443)"`, `done == false`, action
   `.openScope`, `detail == "Nothing is decrypted until a host is in Scope."`; `.inactive` →
   `extensionOn.title` is the All Apps off line with action `.turnCaptureOn`; `.pendingApproval` →
   the waiting line with `.approveInSystemSettings`; `.capturing, scopeHostCount: 2` →
   `scopeSet.title == "Scope: 2 hosts decrypted"`, `done == true`, `action == nil`,
   `detail == "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"`;
   `scopeHostCount: 1` → `"Scope: 1 host decrypted"`; `coreRunning`/`busConnected`/`firstFlow` have `detail == nil`.
6. **TR-AC6 [kit-unit]** `ConnectionAction.addScopeHost.title == "Add Host…"`, `isDestructive == false`;
   `ConnectionAction.trustCA.title == "Trust the aitmproxy CA"` (PR D's). `ConnectionAction.allCases`
   equals the 14 pre-existing cases (`startCore` … `copyListenAddress`, in source order) plus
   `addScopeHost` and PR D's `trustCA`, `openCAPanel` in the merged order — the Coder pins the literal
   list; it contains no `openNetworkSettings` (denied), no `setSystemProxy` and no `unsetSystemProxy`
   (PR4's).

Source tripwires:

7. **TR-AC7 [structural]** `tools/check-connection-words.sh` PASS on the branch, and FAIL
   (tester mutation, reverted) when `Text("system proxy off — x")`, `Text("system proxy on · x")`,
   `Text("HTTPS is not captured until the CA is trusted")`, `Text("Trust the aitmproxy CA")`
   or `Text("Nothing is decrypted until a host is in Scope.")` is added to any view in
   `Sources/Aitmproxy`, when `Shell/ShellView.swift` or `Shell/RouteBanner.swift` mentions
   `connectionSummary`, or when a second `trafficRoutes` definition appears.
   `tools/check-capture-operator-only.sh` PASS unchanged and `tools/check-capture-toggle.sh` PASS
   with its NS-AC8 banner pins moved to `RouteBanner()` (and FAIL, mutation, when a second
   `RouteBanner()` or an `AppsAttributionBanner()` call returns to `MainView`):
   rule 5 still finds exactly one `ExtensionController(` and one `.start()` in `ShellView.swift`;
   `RouteBanner.swift` and `ShellView.swift` contain no `CaptureSwitch`, `capture.enabled`,
   `extensionController`.
8. **TR-AC8 [structural]** `grep -rln CFNetworkCopySystemProxySettings apps/mac/Sources` is **empty**
   (no reader of our own); no file under `Sources/AitmproxyKit` imports CFNetwork, SystemConfiguration,
   SwiftUI or AppKit; `Package.swift` is unchanged; the set of files naming `"ca.status"` under
   `apps/mac/Sources` is identical to PR D's merged SHA (this spec adds no caller and no verb);
   `grep -rn 'ca.install' apps/mac/Sources/Aitmproxy/Shell apps/mac/Sources/Aitmproxy/Session+Connection.swift apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` is empty;
   `git diff <base> -- apps/mac/Sources/Aitmproxy/Bus/BusService.swift` is exactly one added line
   (the `decrypt` decode in `refreshProxyStatus()`, plus at most a comment) and contains no `await`;
   `git diff <base> -- apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`
   shows hunks only inside `MainView.flows` and the `EmptyFlows` struct (lines 49–62 and the
   `ExtensionController` block identical); `git diff <base> -- apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift`
   is the §D7 footprint: the `.help` line, `.addScopeHost` in `run(_:)`'s handled list, and the removal
   of PR D's interim `stepsWithCATrust`/`CATrustRow` insertion — nothing else.
9. **TR-AC9 [gates]** `swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build-routes`
   green including the new tests; the release build (`./build.sh --ne --allow-unnotarized` as the input
   to `scripts/notarize-dmg.sh`, `docs/RELEASE.md` step 3) has no warnings; the Rust gate is
   unaffected (no Rust change).

Real installed app (the notarized build containing this change, installed in `/Applications`,
embedded core running, All Apps on with the extension attached — a `./build.sh --debug` dev build
may be used for an early pass, but it cannot activate the extension and does not count).
**System-proxy clauses run only on the first build that also contains PR4**; on a build without
PR4 the system proxy is unknown, the `systemProxy` step is absent, no system-proxy words appear,
and those clauses are recorded as "deferred to PR4", not failed. Every `networksetup` write runs
in the Terminal panel (any admin prompt is Matt's; research 22 §5b saw none in its one run),
records the original values of every enabled service first (`networksetup -listallnetworkservices`,
`-getwebproxy`, `-getsecurewebproxy`) and restores them at the end; the primary service is the
one `route -n get default` names. The operator token is read from the 0600 per-launch config into
a shell variable and never printed. Evidence = `screencapture` PNGs under
`/tmp/claude/route-advice/`, the `scutil --proxy` output before each step, and the bus replies.

10. **TR-AC10 [live, as found]** With `scope.list` over the operator bus `[]`: **(a) this PR's build
    (system proxy unknown):** the Flows page shows "No flows yet" with
    `Nothing is decrypted until a host is in Scope.`, its detail line and its buttons (Add Host…,
    Open Scope…); the Status page's Getting-started list has **no** system-proxy step, shows
    `✓ All Apps is on` and `○ Add a host to Scope (for now as example.com:443)` (Open Scope…) whose
    help is the scope line; nowhere does either page mention the system proxy. Clicking Add Host…
    opens the Scope page with its add sheet; Open Scope… shows the Scope page; hovering the All Apps
    step shows `in-scope hosts of every app` as its help. **(b) the first build with PR4,** with the
    system proxy as Matt has it today (`scutil --proxy`: `HTTPEnable : 1`, `HTTPProxy : 127.0.0.1`,
    `HTTPPort : 9090`, HTTPS the same): the Flows empty state gains, above the scope row,
    `system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    with its detail line and PR4's Set as System Proxy button; Status shows `○` the system-proxy line
    with that button and its help `every proxy-aware app, regardless of Scope`. Nowhere does either
    page say the system proxy is off. One screenshot of each page per build.
11. **TR-AC11 [live]** `scope.add example.com:443` over the operator bus, no app interaction:
    within one second both pages drop the scope line; the system-proxy line (if any) stays; the
    `scopeSet` step reads `✓ Scope: 1 host decrypted`. `scope.remove` brings the line back on both
    pages. Screenshots before/after.
12. **TR-AC12 [live, flipped — PR4 build only]** On every enabled service, `networksetup -setwebproxystate <svc> off`
    and `-setsecurewebproxystate <svc> off`: within one poll of the core's refresh both pages read
    `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (`scutil --proxy` confirms `HTTPEnable : 0`). Then `-setwebproxy <svc> 127.0.0.1 8080` and
    `-setsecurewebproxy <svc> 127.0.0.1 8080` on the primary service (or PR4's toggle): the
    system-proxy line disappears from the Flows empty state and the Status step reads
    `✓ system proxy on · 127.0.0.1:8080`; a real `http://example.com/` in Safari then produces a
    flow with no `-x`. Then `-setwebproxy <svc> 127.0.0.1 8081` on the primary service: both
    pages read `system proxy on · 127.0.0.1:8081, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (HTTP) — or `· HTTPS only` if HTTPS still points at 8080, per §D3. Finally the recorded
    Proxyman values are restored and re-read with `-getwebproxy`/`-getsecurewebproxy`; both pages
    show the TR-AC10(b) line again. On this PR's build: recorded as deferred to PR4.
13. **TR-AC13 [live, banner]** With `scope.list` `[]`, `curl -x 127.0.0.1:8080 http://example.com/` ×2
    (plain-HTTP rows, readable): **(a) this PR's build:** with All Apps on the Flows page shows the
    table and no banner (a route is open and the rows are readable) — or, with the CA untrusted, the
    CA-only line of TR-AC17; the operator then switches All Apps OFF in the toolbar (real click; the
    one known route closed): ONE banner line composed per §D5 — `All Apps off · Nothing is decrypted
    until a host is in Scope.` (plus ` · HTTPS is not captured until the CA is trusted` while the CA is
    untrusted) — with one button, All Apps Settings…, no system-proxy words, and no "No scope set"
    `ScopeBanner` anywhere; Pinned, Domains and Apps show the same single line and no other banner.
    After `scope.add example.com:443` the Scope state leaves the line; after switching All Apps back
    ON the banner is gone (or the CA-only line remains) and nothing replaces it. **(b) the PR4 build,**
    system proxy as found (`.other`) and All Apps off: the line starts `system proxy on · 127.0.0.1:9090, not this core · All Apps off · …`
    with PR4's Set as System Proxy as the button; after the system proxy is set to 127.0.0.1:8080
    the system-proxy state leaves it; with every fact open the banner is gone. Restored afterwards.
14. **TR-AC14 — deleted 2026-11-01** (orchestrator: `.openNetworkSettings` denied; no menu item, no
    Network Settings… action). Its surviving clauses — Add Host…, Open Scope… and the step help — are
    in TR-AC10(a).
15. **TR-AC15 [kit-unit, CA facts — contract; implemented and proved by PR D]** `CATrustFacts(status:)`
    over literal `CAStatus(json:)` inputs: `stores.user.trusted == "yes"` → `trusted == true`,
    `scope == "user"`, `fingerprint == <the sha256>`; `user "no"`, `system "no"` → `trusted == false`,
    `scope == nil`; `user "unknown"` only → `nil`; no `stores` with `exists == true` → `nil`;
    `system "yes"`, `user "no"` → `trusted == true`, `scope == "system"`; `installing == false` and
    `needsAdmin == false` on every result.
16. **TR-AC16 [kit-unit, CA in routes and steps]** With the TR-AC3 inputs plus
    `caTrust: <PR D's CATrustFacts: trusted false, scope nil, fingerprint "AB:CD", platform "macos", installing false, needsAdmin false>`
    (`notTrusted`): `routes.caTrust?.line == "HTTPS is not captured until the CA is trusted"` (= PR D's `text`),
    `routes.caTrust?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`,
    `routes.caTrust?.actions == [.trustCA, .openCAPanel]` (PR D's `actions`, 4ae616d3),
    `advice.map(\.kind) == [.systemProxy, .scope, .caTrust]` (All Apps on → open),
    `anyOpen == true`; `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrusted, .firstFlow]`,
    the `.caTrusted` step `title == "Trust the aitmproxy CA"`, `done == false`, `action == .trustCA`,
    `detail` = the detail string above. With `flowCount: 6` → `banner == "HTTPS is not captured until the CA is trusted"`,
    `bannerAction == .trustCA` (All Apps open, rows readable); with `flowCount: 6, tunnelledFlowCount: 6` →
    `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .addScopeHost`;
    with `capability: .inactive, flowCount: 6` →
    `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .openCaptureSettings`;
    with `systemProxy: nil, capability: .inactive, flowCount: 6` →
    `banner == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"` (the fresh install until PR4).
    With `systemProxy` both at the core, `.capturing`, `scopeHostCount: 2`, `flowCount: 3`, same
    `caTrust` → `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`, `anyOpen == true`.
    With `trusted: true, scope: "user"` →
    `routes.caTrust?.line == "CA trusted (user keychain)"`, `open == true`, `detail == "HTTPS on both routes"`,
    `actions == []`, the step `title == "CA trusted (user keychain)"`, `done == true`, `action == nil`, and with the two routes open
    `banner == nil`; `scope: "system"` → `"CA trusted (System keychain)"` (capital S, PR D verbatim).
    `caTrust: nil` → `routes.caTrust == nil`, no `.caTrusted` step, no CA text in `advice` or `banner`.
    `installing: true` → `line == "trusting CA…"`, `open == false`, `actions == []`, the step `title == "trusting CA…"`,
    `action == nil`; `needsAdmin: true` → `line == "CA trust needs an administrator"`, `open == false`,
    `actions == [.openCAPanel]`, the step `title == "CA trust needs an administrator"`, `action == .openCAPanel`;
    with `flowCount: 3`, both routes open and `needsAdmin: true` → `banner == "CA trust needs an administrator"`,
    `bannerAction == .openCAPanel`.
17. **TR-AC17 [live, CA not trusted — HARD GATE: no `ca.install`]** On Matt's Mac as it is today:
    `ca.status` over the operator bus (`…/bus-ca-status.json`) shows every store with
    `trusted: "no"` (or `installed: "absent"`). Within one CA tick of connecting, the Flows empty
    state shows, after the route rows, the row `HTTPS is not captured until the CA is trusted`
    with its detail `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then`
    and its buttons Trust the aitmproxy CA and the CA page — **present, not clicked**; the Status
    checklist shows `○ Trust the aitmproxy CA` with the same help and its Trust the aitmproxy CA
    button — present, not clicked; PR D's interim `CATrustRow` is gone and the words are unchanged;
    with the TR-AC13 curl rows present and All Apps on the banner is exactly
    `HTTPS is not captured until the CA is trusted` with the button Trust the aitmproxy CA; with All
    Apps off it ends in ` · HTTPS is not captured until the CA is trusted`. Nothing on either page
    reads "trusted". **No one runs `ca.install`, clicks Install… on the CA page, or clicks Trust the
    aitmproxy CA on his Mac for this proof.** The trusted state (`CA trusted (user keychain)`, the
    line gone) is proved only after Matt says in his own words that the CA may be trusted, through
    the app's own step (that button, PR D's `.trustCA`, with its prompts) — recorded then in the
    plan's Shipped section, not here.
18. **TR-AC18 [kit-unit, composed banner]** `TrafficRoute.state`: the system-proxy off route has
    `state == "system proxy off"` (its `line` keeps the ` — set …` clause for the row and the step);
    the CA line has `state` == its line; All Apps `.on(hosts: 2)` has `line == "All Apps on"`;
    `routes.scope` with `scopeHostCount: 0` has `state == line == "Nothing is decrypted until a host is in Scope."`.
    `bannerAction` is the first shown entry that has an action: `.openCaptureSettings` whenever All Apps
    off is shown (the system-proxy entry has no action in this PR; PR4's `.setSystemProxy` then takes
    precedence), `.addScopeHost` for the Scope fact when nothing before it has an action, `.trustCA`
    for the CA-only case, nil when `banner == nil` or no shown entry has an action.
    `make(… bus ok, capability: .inactive, captureSupported: true, scopeHostCount: 0, flowCount: 3,
    listenAddress: L, systemProxy: .off, caTrust: notTrusted)`
    → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`,
    `bannerAction == .openCaptureSettings` (the fresh-install case with PR4); the same with `systemProxy: nil` →
    `banner == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`,
    `bannerAction == .openCaptureSettings` (the fresh-install case until PR4); the same with `.capturing` →
    `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`
    (All Apps open, rows readable), and with `tunnelledFlowCount: 3` → `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`,
    `bannerAction == .addScopeHost`;
    `.capturing`, `caTrust: nil`, `tunnelledFlowCount: 3` → `banner == "Nothing is decrypted until a host is in Scope."`;
    `.inactive`, `caTrust: nil` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`;
    `.inactive`, `scopeHostCount: 2`, `caTrust: nil` → `banner == "system proxy off · All Apps off"`;
    `captureSupported: false, systemProxy: .off, scopeHostCount: 2, flowCount: 3` → `banner == "system proxy off"`, `bannerAction == nil`;
    every single-fact banner equals that fact's `state` (`"system proxy off"` for the no-extension,
    scope-set case — never the line with its remedy clause).
19. **TR-AC19 [live, one banner line]** On the installed app with rows present (TR-AC13 state), on
    each of Flows, Pinned, Domains and Apps: exactly one banner line above the table, none of
    the old texts "No scope set" / "Flows carry no source app" anywhere; the column header's top
    edge (from the window screenshot, or the table header's AX frame) sits exactly one
    `Tok.Size.Row.dense` = **28 pt** below its position after Edit ▸ Clear empties the list (no rows →
    `banner == nil` → no banner), never 56 (two stacked rows); Undo Clear restores rows and the
    single banner. A click on the first row's y selects row 1 and does not sort.
20. **TR-AC20 [live, per-host decryption, v0.5.9+]** Unconditional once plan Task 1c (the `tunnel`
    decoder) is in; until then recorded as deferred, not failed. With the installed app on the
    v0.5.9+ core, `scope.list` `[]`, and curl pointed at the proxy:
    `curl -x 127.0.0.1:8080 https://example.com/` → one row whose SSL column shows the tunnel state
    (`flow.get` carries `tunnel: "passthrough"`, `tunnel_reason: "out_of_scope"`; no body); with every
    row a tunnel (Edit ▸ Clear first) the banner reads exactly the core's sentence
    `Nothing is decrypted until a host is in Scope.` (with the CA untrusted on that Mac:
    `Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted`, button `Add Host…`),
    and the Flows empty state (after another Clear) shows the same quoted sentence as its row with
    `Add Host…` (and `Open Scope…`). `proxy.status.decrypt` over the bus reads `{scope_hosts: 0, decrypting: false,
    advice: "Nothing is decrypted until a host is in Scope."}`. `scope.add example.com:443` → the
    line leaves both pages within one poll, the `scopeSet` step reads `✓ Scope: 1 host decrypted`,
    `proxy.status.decrypt.advice` is null; `curl -x 127.0.0.1:8080 --cacert <exported PEM>
    https://example.com/` (PEM from `aitm ca export` / the CA page's Export PEM — a file, no keychain
    change, so the hard gate holds) → a row with `tunnel: "decrypted"`, SSL column decrypted, body
    present. `scope.remove` → the next `curl https://` row is a passthrough tunnel again and the
    line is back. Safari's HTTPS still needs the keychain to trust the CA and stays under the hard
    gate; curl with `--cacert` is the decrypted-row proof.
21. **TR-AC21 [kit-unit, `DecryptStatus`]** `DecryptStatus(json:)` over literal `JSONValue` objects:
    `{"scope_hosts": 0, "decrypting": false, "advice": "Nothing is decrypted until a host is in Scope."}`
    → `scopeHosts == 0`, `decrypting == false`, `advice == "Nothing is decrypted until a host is in Scope."`;
    `{"scope_hosts": 2, "decrypting": true, "advice": null}` → `scopeHosts == 2`, `decrypting == true`,
    `advice == nil`; `{}` → nil; a `proxy.status` object without `decrypt` → `status["decrypt"].flatMap(DecryptStatus.init) == nil`.
22. **TR-AC22 [kit-unit, the #228 row/detail decoder — plan Task 1c]** With literal `flow.get`
    objects (`scheme: "https"`): `tunnel: "passthrough"` → `FlowSummary.tunnel == .passthrough`,
    `row.tls == .tunnelled`, `row.isTunnel == true`; `"failed"` → `.failed` / `.pinnedOrFailed`;
    `"decrypted"` → `.decrypted` / `.decrypted`; `tunnel: null` or absent → `tunnel == nil`,
    `isTunnel == false`, `tls == .decrypted` (scheme rule); `scheme: "http"`, no `tunnel` → `.none`.
    `tunnel_reason`: each of the eight labels decodes to its `TunnelReason` case
    (`"out_of_scope"` → `.outOfScope`, …, `"protocol_error"` → `.protocolError`); `"something_new"`
    → `tunnelReason == nil` (never a crash); absent → nil. `bytes_up: 1234`, `bytes_down: 56` →
    `tunnelBytesUp == 1234`, `tunnelBytesDown == 56` on summary and row; null/absent → nil;
    `passive: true` → `passive == true`; absent → `false`. `FlowDetail(json:)` over a literal detail
    object with `meta.tunnel: {mode: "passthrough", reason: "out_of_scope", bytes_up: 1, bytes_down: 2}`
    and `meta.passive: false` → `detail.tunnel == TunnelInfo(mode: .passthrough, reason: .outOfScope,
    bytesUp: 1, bytesDown: 2)`, `detail.passive == false`; `meta.tunnel: null` → `detail.tunnel == nil`;
    `meta.passive` absent → `false`. `FlowRow ==` notices a change in each of `tunnel`,
    `tunnelReason`, `tunnelBytesUp`, `tunnelBytesDown`, `passive` (one `FlowRowEqualityTests` row per
    field); `inScope` is unchanged by any of them.

## Left to the builder

- `EmptyFlows` reading `session.trafficRoutes` via the environment or taking a `routes:`
  parameter; the glyphs for the lines (`network` and `app.badge` suggested); the detail
  line's size (`Tok.Typography.Size.sm`, tertiary ink suggested).
- `Hashable`/`Sendable` conformances and the `TrafficRoutes` memberwise init shape, provided the
  public fields above exist with these names.
- Deleting the now-unreferenced `ScopeBanner` struct, `AppsAttributionBanner` struct and
  `CaptureAdvice.banner` is a later cleanup with its own tripwire edits; not here.
- How `tunnelledFlowCount` is counted in `Session+Connection` (a filter over `rows` is fine at
  today's sizes; cache it beside `rowsVersion` if it shows in a profile).
- Whether `FlowSummary.tunnel` is stored as `String?` or a small enum; only the `tls` mapping is pinned.
- Which of PR D's helpers (`state`, `text`, `notTrustedLine`, …) is the CA entry's `line` in code,
  provided the §D2a strings come out (gate 3 confirms the mapping).

## Open questions

None block. Calls Matt may want to flip (each a one-line change):

1. Route lines start lower-case on the Status rows too (§D4). Alternative: a sentence-cased
   `title` twin for Status.
2. The `systemProxy` step stays undone while the system proxy is off or elsewhere even when All
   Apps carries traffic, so "Everything is connected" needs the system proxy to point here.
   Alternative: mark it done when any route is open.
3. `ScopeBanner` and `AppsAttributionBanner` are no longer rendered on any list page; the route
   banner is the one 28 pt line (`Tok.Size.Row.dense`, §D8). Alternative: keep `ScopeBanner` where the route banner is absent (see 12).
4. A build with no extension shows the system-proxy banner (once PR4 feeds the slot) whenever rows
   come only from a hand-pointed client (§D5). Alternative: suppress when `allApps == nil`.
5. (Superseded 2026-11-01 by the orchestrator's ruling: no in-app reader; PR4 polls
   `proxy.status.system_proxy`. The earlier poll-tick-vs-`SCDynamicStore` choice no longer exists.)
6. "Capture extension is on" → "All Apps is on" (§D4).
7. Open-state words `system proxy on · L` (research 22's candidate, lane-word style) rather than
   `system proxy is L`; `.other` words `system proxy on · H:P, not this core — …`.
8. The not-trusted `detail` repeats the line's first clause (both are the coordinators' binding
   strings); trimming the detail to `browsers using QUIC load directly until then` is one string.
9. (Resolved by PR D: `CATrustFacts(status:)` is failable — nil when every store is unknown or
   the certificate does not exist — so unknown never renders as trusted or not trusted.)
10. The `caTrusted` step's action is PR D's `.trustCA` (its confirm and admin prompts) and the Flows
    CA row carries `.trustCA` + `.openCAPanel`, both from PR D's `actions`; this spec replaces PR D's
    interim `StatusPanel` insertion with its own step. Alternative: the row navigates to the CA page only.
11. Composed banner (§D5): state words of every shown fact as text, the highest-priority fact's
    remedy as the one button (system proxy > All Apps > Scope > CA). Alternative: show only the
    highest-priority fact's state and a count ("· 2 more").
12. The read-only-scope banner retires from the list pages (its fact lives in the route banner, the
    status bar and the Scope page). Alternative: keep it on pages where the route banner is absent.
13. The Scope fact enters the banner only when both routes are closed or EVERY row is a tunnel
    (§D5); a mixed list relies on the tunnel row's own inline remedy. Alternative: any tunnel row.
14. All Apps is reported open whenever the extension is on, even with an empty scope — true under
    per-host decryption (PR #228, on `main`: connections arrive as tunnel rows), and the empty state's
    scope line is what tells the operator. Alternative: report All Apps closed on an empty scope.
15. Done form `Scope: N hosts decrypted` (coordinators' proposal, accepted) rather than "Scope has n
    hosts"; `Format.count` gives `1 host` / `n hosts`.
16. `DecryptStatus` value over a bare `decryptAdvice: String?` (§D2). The banner carries no remedy
    text for any fact — states joined, one remedy button (core spec D9 alignment); the quoted
    Scope sentence keeps its period inside a composed line (verbatim beats typography).
    Alternative: strip the period in the composed form only.
17. The five #228 row fields ride on `FlowRow` (agreed Kit names; the improve-loop inspector and a
    possible column consume them) even though this spec renders none of them. Alternative: summary-only.
18. (2026-11-01) The banner predicate names only *known-closed* routes (`knownOpenRoute`, §D5): with
    the system proxy unknown (every build until PR4) a closed All Apps is still named and the
    system proxy is not mentioned. Alternative: no banner until both routes are read.
19. (2026-11-01) `bannerAction` is the first shown fact that has an action, so a closed system-proxy
    fact with no action yet (until PR4's `.setSystemProxy`) does not swallow the button. Alternative:
    strictly the first shown fact's action, nil if it has none.
20. (2026-11-01) `Session.systemProxy` is declared by this spec's Task 2 (nil, never written here) so
    `connectionSummary` compiles before PR4 lands; PR4 writes it. Alternative: PR4 declares it and
    this spec's `make` call gains the argument on PR4's rebase.
21. (2026-11-01) PR D's two nil-facts Status rows (`unknownStep()`, `notGeneratedStep()`) are dropped
    from the Getting-started list when this spec's step replaces PR D's interim insertion: `make`
    reads `Session.caTrust` alone and omits the step while it is nil; the first-run sheet and the CA
    page keep them. Alternative: pass PR D's `Session.caTrustStep` into `make` and keep both rows.

## Summary

One Kit value, `ConnectionSummary.routes`, derived inside `make` from a `SystemProxyState?` input
(the type defined here as the shared contract and shipped by the system-proxy session's PR 4a; the
value written by its PR4 from `proxy.status.system_proxy`, nil = unknown until then) plus the facts
the lanes already use, names the two automatic routes into the proxy — the macOS system proxy
(every proxy-aware app, regardless of Scope) and All Apps (in-scope hosts of every app) — as open
or closed with one line, one detail and one action each, plus two facts that gate what the routes
carry: Scope (per-host decryption, Matt's 2026-10-31 decision: `Nothing is decrypted until a host is
in Scope.`, shown in the banner when a known route is closed or every row is a tunnel) and CA trust
(PR D's published `Session.caTrust`, consumed through its `CATrustFacts` helpers). The Status page's
Getting-started list (a `systemProxy` step once PR4 feeds the slot; the `extensionOn`/`scopeSet`
steps' words; the `caTrusted` step with PR D's `.trustCA`) and the Flows page's empty state and
one-line banner read `Session.trafficRoutes` and nothing else, so they cannot disagree; the banner
shows only while a known route is closed (or every row is a tunnel, or HTTPS is untrusted) and flows
exist, as one composed `Tok.Size.Row.dense` (28 pt) line that is the only banner on every list page
(`ScopeBanner` and `AppsAttributionBanner` retire from them), with one button — the first shown
fact's remedy (`All Apps Settings…` / `Add Host…` / `Trust the aitmproxy CA`; PR4 adds `Set as
System Proxy`). The app has no reader of its own: no CFNetwork call, no `ca.status` call, one
`BusService` line (`proxy.status.decrypt`), no menu item (`.openNetworkSettings` was denied — setup
happens in the app with the OS prompt). No proof ever runs `ca.install` on Matt's Mac. Proof is Kit
unit tests (one `make` per predicate-table row), the three source tripwires and the real installed
app — the system-proxy clauses on the first build that also contains PR4 — never fixture or
sample-data UI tests.

## Amendments after approval

Entries are a dated log. Where an earlier entry conflicts with a later one, the later entry and the
body text above govern. Superseded by the 2026-11-01 entries, wherever an earlier entry says them:
the CA "reserved / no button" wording and `.trustCA`/`.openCAPanel` as reserved names; the in-app
system-proxy reader (`SystemProxyReader`, the poll-tick CFNetwork read); the Proxy ▸ Network
Settings… item and `Open Network Settings…` as a button or `bannerAction`; the 40 pt banner figure
(it is `Tok.Size.Row.dense` = 28 pt); the predicate names `bothClosed ∨ caClosed` and `routesClosed`
(now `knownOpenRoute` / `closedRoutes`, §D5); the `— set …` remedy suffix and the fresh-install
literals that carry it; the composed `state` stripping a trailing period (the period is kept) and the
`… — add one` fallback (the fallback is the core's sentence verbatim); the start SHA `8175eea3` (base
`main 8e19c2e3`); `CATrustFacts.remedy: String?` and a `trustedScope`/`trustReported` contract of our
own (PR D's `needsAdmin`, `text`, `actions`, `step` are consumed instead).

- 2026-10-31 (coordinating session, agreed with the system-proxy session): `SystemProxyState(settings:)` accepts a Port given as a number or a numeric string. (The "Network Settings…" menu item agreed in the same exchange was withdrawn 2026-11-01 when the orchestrator denied `.openNetworkSettings`; the Proxy menu gets only PR4's toggle, ⌥⌘P — unused by the app today, `grep keyboardShortcut("p"` finds nothing.)
- 2026-10-31 (coordinating session, agreed with the NE and system-proxy-automation sessions): third fact **CA trust** added — `CATrustFacts` (`trusted`, `scope`, `fingerprint`, sibling-owned `installing`/`remedy`), `make(caTrust:)`, `TrafficRoute.Kind.caTrust`, step `caTrust` "Trust the aitmproxy CA" / `CA trusted (user keychain)`, line `HTTPS is not captured until the CA is trusted`, detail `… — browsers using QUIC load directly until then`, banner rule `bothClosed ∨ caClosed`, `ca.status` read every 10th tick; `.trustCA`/`.openCAPanel` reserved; **hard gate: no `ca.install` on Matt's Mac in any proof** (TR-AC15–17).
- 2026-10-31 (coordinating session, after the improve-loop measurement on `main 9dba3d9f`): D8 widened — one 40 pt banner line on every list page (Flows, Pinned, Domains, Apps), the route banner only; `ScopeBanner()` and `AppsAttributionBanner()` call sites removed from `MainView.flows` (structs kept), `check-capture-toggle.sh` NS-AC8 pins move to `RouteBanner()`; composed banner form (`TrafficRoute.state`/`remedy`; states joined ` · ` + the one remedy, priority system proxy > All Apps > CA) with the fresh-install literal `system proxy off · All Apps off · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`; Apps-page predicate stated; TR-AC18 (kit) and TR-AC19 (live header position) added; TR-AC3/13/16 literals updated.
- 2026-10-31 (coordinating session, Matt's per-host-decryption decision; strings confirmed by the improve-loop session for S-073/S-074/S-080): the Scope fact becomes its own `TrafficRoute` (`Kind.scope`, always present) with line `Nothing is decrypted until a host is in Scope.` / `Scope: N hosts decrypted` and detail `Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel`; All Apps is closed only when off/awaiting/degraded (open line `All Apps on`), so no clause repeats; `make(tunnelledFlowCount:)` from `FlowRow.tls == .tunnelled`; banner rule `routesClosed ∨ (scopeClosed ∧ (routesClosed ∨ allTunnels)) ∨ caClosed` with the fresh-install literal `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`; `scopeSet` keeps title/action, done form `Scope: N hosts decrypted`, detail = the scope line; "every host is read-only" retired; D2a lists the improve-loop session's adjacent tunnel-row strings; TR-AC3/4/5/16/18 literals updated, TR-AC20 (conditional on the core story) added; `check-connection-words.sh` prefixes gain `"Nothing is decrypted` and `"Scope:`.
- 2026-10-31 (coordinating session, agreed with the CA-trust session): `CATrustFacts.swift`, `CATrustFactsTests.swift` and the two additive `CAStatus` fields are implemented in the CA-trust session's PR (number TBD) to this spec's definitions; this spec remains the contract (TR-AC15 proved there). Our CA work (`make(caTrust:)`, `.caTrust` entry/step, `ca.status` read, rendering) is gated on that PR; system-proxy/All Apps/Scope parts are not (plan Tasks 1/2 split into 1/1b and 2/2b).

- 2026-10-31 (coordinating session, orchestrator registry update): the CA-trust session's mac PR D lands BEFORE this spec's PR and carries, as a narrow additive exception on `ConnectionSummary.swift`, `ConnectionAction.trustCA` and `.openCAPanel` with their titles and `GettingStartedStep.Kind.caTrusted` with its title — nothing else; `CATrustFacts` and the two `CAStatus` fields live in that PR too. This spec's step kind is therefore `.caTrusted` (not `.caTrust`; the route kind `TrafficRoute.Kind.caTrust` is unchanged), Task 1 must not redeclare those cases, and this branch rebases onto PR D's merged SHA before Task 1b/2b. Coding still starts on the fixture-removal SHA.
- 2026-11-01 (coordinating session, after PR #228 / v0.5.9): the Scope entry quotes `proxy.status.decrypt.advice` verbatim (`Nothing is decrypted until a host is in Scope.`) when present and falls back to our `… — add one` on an older core; `make(decrypt: DecryptStatus?)` (new Kit value decoded from `proxy.status`, which `BusService` already polls — no new read); N for `Scope: N hosts decrypted` = `decrypt.scope_hosts`; composed `state` strips one trailing `.`, remedy `add one`; Kit row decoder maps `tunnel` `passthrough`→`.tunnelled`, `failed`→`.pinnedOrFailed`, `decrypted`→`.decrypted` (plan Task 1c, own claim pending; `tunnel_reason`/bytes stay on the wire); TR-AC20 rewritten around curl passthrough/`--cacert` decrypted rows and unconditional once Task 1c is in; TR-AC21/22 added; start SHA `8175eea3`.
- 2026-11-01 (coordinating session, aligned with core spec D9 and the improve-loop session): banner text = shown states joined ` · ` with **no remedy text**; the remedy is one button `bannerAction` (`Open Network Settings…` / `All Apps Settings…` / `Add Host…` / `Trust the aitmproxy CA`); the Scope line is `proxy.status.decrypt.advice` verbatim (`Nothing is decrypted until a host is in Scope.`), fallback the same words, `— add one` retired; new `ConnectionAction.addScopeHost` ("Add Host…"); the Status step keeps `Open Scope…`. Task 1c widened to the full #228 contract: `TunnelMode`, `TunnelReason` (8), `tunnel`/`tunnelReason`/`tunnelBytesUp`/`tunnelBytesDown`/`passive` on `FlowSummary` and `FlowRow` (+ `isTunnel`, `==`), `FlowDetail.tunnel: TunnelInfo?` + `passive` from `meta`; TR-AC3/6/16/18/22 and D5/D10 literals updated.
- 2026-11-01 (stage-6 fix pass on docs PR #242, spec + quality panel; self-approved, autonomous mode): post-PR-D CA state everywhere (the CA entry carries PR D's `[.trustCA, .openCAPanel]`, the `caTrusted` step's action is `.trustCA`, the CA-only banner button is `.trustCA`; every "reserved / no button" sentence removed; step kind `.caTrusted`, route kind `.caTrust`); TR-AC3 has one Scope action list and the stale-list banner case; D10 banner cells carry no remedy text; `scopeClosed ⇔ !routes.scope.open`; the numeric-string Port vector is in TR-AC1; `Tok.Size.Row.dense` is 28 pt (not 40) — D5/D8/TR-AC19 say 28 / 56 and D8 no longer claims a pixel measurement; AC ordinals = ids; `Endpoint.address` computed; STORIES.md not touched; the StatusPanel footprint stated once (D7); labels on the inferences (primary-service rule, NSNumber, spawn rate); base `main 8e19c2e3`.
- 2026-11-01 (orchestrator rulings, recorded as the plan's gate 2 and gate 5): **no in-app system-proxy reader** — `Bus/SystemProxyReader.swift`, `refreshSystemProxy()` and the `CFNetworkCopySystemProxySettings()` call are dropped; `SystemProxyState.swift` (the type as defined here, with its Kit tests) ships as the system-proxy session's PR 4a = PR #246 ahead of this PR (gate 5), with `init?(compact:listenAddress:)` over `proxy.status.system_proxy`; PR4 (after us) adds `SystemProxyFacts`, the polling, the toggle and `.setSystemProxy`/`.unsetSystemProxy`, writing `Session.systemProxy`; until PR4 the system proxy is unknown (step omitted, no words, never "off"). **`.openNetworkSettings` denied** (Matt: setup happens in the app with the OS prompt): no action, no `settingsURL`, no menu item, no CommandMap/BRIEF/GLOSSARY rows, plan Task 4 removed, TR-AC14 deleted; the system-proxy entry's `actions` are empty until PR4. **CA fact = PR D's published `Session.caTrust`** (`Session+CATrust.swift`; `CATrustFacts` fields `{trusted, scope, fingerprint, platform, installing, needsAdmin}`, helpers `{text, actions, step, …}` consumed (`text` is the line; `state` is a `LaneState`); PR D's cadence `caStatusEveryTicks = 10`); no `refreshCAStatus()`, no `Session.caStatus` here; plan Task 2b removes PR D's interim `stepsWithCATrust`/`CATrustRow` once the CA step exists. **`BusService.swift` = one line** (`proxy.status.decrypt`); `check-capture-toggle.sh` GO on the fixture-removal mac SHA; `Session+Connection.swift` GO on PR D's SHA for `.addScopeHost` and `tunnelledFlowCount`. D5 predicate restated as `knownOpenRoute` with `bannerAction` = the first shown fact that has an action (Architect's calls 18/19); D6/D7 rewritten; the live proof's system-proxy clauses run on the first build that also contains PR4.
