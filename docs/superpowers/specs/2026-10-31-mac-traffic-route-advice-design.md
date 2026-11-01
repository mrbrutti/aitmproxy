# macOS traffic-route advice design

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode)
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
- Per-host decryption merged as PR #228 (`main 8175eea3` = v0.5.9): `proxy.status` now carries
  `decrypt = {scope_hosts: Int, decrypting: Bool, advice: String?}` (`crates/aitm-plugins/src/control.rs`
  ~140–155) where `advice` is the core constant `NOTHING_DECRYPTED_ADVICE` =
  `"Nothing is decrypted until a host is in Scope."` (`crates/aitm-core/src/config.rs:176`) while
  `scope_hosts == 0` and `null` once a host is in Scope — "the one constant every surface prints
  verbatim". Rows carry `tunnel` (`decrypted` | `passthrough` | `failed`), `tunnel_reason`
  (`out_of_scope`, `pinned`, `client_rejected_certificate`, `client_closed`, `client_tls_error`,
  `upstream_unreachable`, `upstream_tls_failed`, `protocol_error`), `bytes_up`, `bytes_down`
  (`crates/aitm-plugins/src/capture.rs` `tunnel_fields` ~265–283; labels in
  `crates/aitm-core/src/flow.rs` `TunnelMode`/`TunnelReason`).

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

- With the system proxy not pointing at the core and the scope empty on a build with All Apps
  on, the Flows page's empty state shows two lines — for a system proxy that is off, verbatim
  `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`; for one
  pointing elsewhere, the same line naming what it found (`system proxy on · 127.0.0.1:9090, not
  this core — …`) — and the core's own sentence `Nothing is decrypted until a host is in Scope.`,
  each with its action (Open Network Settings… / Copy Address; Add Host…).
- With the CA not trusted (Matt's Mac today), both pages carry one more line, verbatim: `HTTPS is
  not captured until the CA is trusted` — the Flows empty state as a row, the Status checklist as
  the undone step "Trust the aitmproxy CA"; when `ca.status` has not been read, nothing is said
  about the CA, and nothing ever reads "trusted" unless a store reports `trusted: "yes"`.
- The Status page's Getting-started list shows the same lines as undone steps with the same
  actions; after `scope.add` over the bus the scope line disappears from both pages within one
  poll; after the system proxy is set to the core's address the system-proxy line disappears
  the same way — without any view being told.
- When flows exist and neither route is open, one line above the Flows table says so; when
  flows exist and at least one route is open, nothing is shown.
- Every word comes from `AitmproxyKit.ConnectionSummary`; `check-connection-words.sh` fails if
  a view spells `system proxy off` or `Nothing is decrypted until a host is in Scope` itself.
- The system-proxy fact is a public, stable Kit value (`SystemProxyState`) that the sibling
  set-system-proxy work (`proxy.system.status/set/unset`, Settings ▸ Proxy toggle) consumes
  unchanged, so the app has one read-back type and one set of words for the system proxy.

## Non-goals

- A "Set as system proxy" / "Restore system proxy" action, its helper, its snapshot-and-restore
  file, its bus verbs and its `ConnectionAction`s (`.setSystemProxy`, `.unsetSystemProxy` are
  **reserved** for that session, §D2a). Here the system-proxy line only *opens* System Settings
  ▸ Network; this spec adds read-only facts.
- Installing or trusting the CA from this app's surfaces: `ConnectionAction.trustCA` (title "Trust
  the aitmproxy CA") and `.openCAPanel` are **reserved** for the system-proxy-automation session,
  which owns the install-action side (confirm prompt, admin prompt). The CA page
  (`Panels/CAPanel.swift`) is not changed here. Never `.installCA`.
- Any copy change outside the two surfaces (Flows empty state + Flows banner; Getting-started
  steps). The toolbar pill, the lane cards, Settings, the Apps page's `AppsAttributionBanner` /
  `AppsEmptyState` and `ScopeBanner`'s text are unchanged (one exception: `ScopeBanner` *yields*
  to the route banner on the Flows page, §D8).
- Anything under `apps/mac/Extension/`, any core (Rust) change, any new bus verb.
- PAC/WPAD, SOCKS, per-service or per-app proxy settings, a browser's own manual proxy
  (Firefox), the bypass list, CA trust. The model answers one question: do the effective global
  HTTP/HTTPS system-proxy settings point at this core's listen address.
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
  `tools/check-connection-words.sh`; (3) the real installed app with the extension on and the
  real system-proxy state flipped via `networksetup`/`scutil` in the Terminal plus a real
  request — screenshots of the Flows and Status pages showing the same words, and bus reads
  (`scope.list`, `scope.add`, operator token never printed).
- **Hard gate — no `ca.install` on Matt's Mac.** Trusting the aitm CA on his machine is Matt's
  decision and he has not given it. No proof, script, Coder, Tester or orchestrating session calls
  `ca.install` (or clicks Install… on the CA page) on his Mac. The live proof proves only the
  NOT-trusted state and its line as his Mac is today, plus `ca.status` over the bus showing
  `trusted: "no"`. The install → line-disappears path is proved only after Matt says in his own
  words that the CA may be trusted, and then only through the app's own step (the Status checklist
  action with its admin prompt, once the sibling's `.trustCA` lands), never a direct verb call.
- **CA parts land after the CA-trust session's PR.** `AitmproxyKit/CATrustFacts.swift`, its tests
  and the two additive `CAStatus` fields (`trustedScope`, `trustReported`) are implemented by the
  CA-trust session in its PR, to this spec's definitions. This spec stays the contract; its own
  CA work (the `make(caTrust:)` slot, the `.caTrust` entry and step, the `ca.status` read, the
  Flows/Status rendering of the CA line) starts only once that PR is on `main`. The system-proxy,
  All Apps and Scope parts are not gated on it and land first (plan Tasks 1/2 vs 1b/2b).
- **`FlowSummary` decoder is a separate claim.** Mapping the wire's `tunnel` field onto
  `FlowRow.tls` edits `AitmproxyKit/FlowSummary.swift` and adds its Kit tests; the coordinator has
  asked the orchestrator for that claim. It is plan Task 1c, gated on the answer; everything else
  here is independent of it, and TR-AC20 becomes unconditional once Task 1c is in.
- **Start SHA and claims.** Code starts from `main` at or after `8175eea3` (v0.5.9, PR #228 merged; supersedes `5eac2a50`) and
  after the fixture-removal PR; this worktree is rebased onto `5eac2a50` and the design is
  against the working tree. The orchestrator's claim approval is granted for the files in §D7.
  In `Shell/ShellView.swift` only `EmptyFlows` (the struct at ~319–336) and the insertion of the
  one new banner in `MainView.flows` (~174–200) may change; lines 49–62 (the palette overlay) and
  the palette transition belong to another session and are not touched.
- **One model.** `ConnectionSummary` is extended; no parallel type. The route words live in
  `AitmproxyKit/ConnectionSummary.swift`; the system-proxy value in the new
  `AitmproxyKit/SystemProxyState.swift`. Both surfaces read `Session.trafficRoutes`, a one-line
  accessor of `connectionSummary.routes` (§D7).
- **Words, exactly** (§D2a, §D4). "All Apps" is the feature's name in every user-facing string
  (`ConnectionLane.Kind.capture.title == "All Apps"`; verbs "Capture All Apps", "All Apps
  Settings…"); "Capture"/"Extension" appear only where macOS does (approval, uninstall). The
  lane principle "system proxy → every proxy-aware app, regardless of Scope; All Apps → in-scope
  hosts of every app" is carried by the model (`TrafficRoute.detail`) and shown on both surfaces.
- **Shared vocabulary** (§D2a): `SystemProxyState`, `SystemProxyState.Endpoint`,
  `SystemProxyRoute` and the system-proxy words are public, stable and additive-only from the
  moment they land; the sibling set-system-proxy spec consumes them and adds the reserved
  actions beside them. `CATrustFacts`, `TrafficRoute.Kind.caTrust` and the CA words are shared the
  same way with the system-proxy-automation session (it writes the install side and consumes this
  `ConnectionSummary` model). This spec may use only `openNetworkSettings` (new),
  `copyListenAddress`, `openScope`, `turnCaptureOn` and the existing `openCaptureSettings` /
  `approveInSystemSettings`; `.trustCA` and `.openCAPanel` are reserved, so the CA step and row
  ship with no action until they land.
- **The read is the effective global setting.** `CFNetworkCopySystemProxySettings()` returns
  the system-wide effective proxies, which follow the PRIMARY network service (per-service values
  can disagree, e.g. under a VPN). The model reads that and nothing per-service; the words say
  "system proxy", never a service name.
- **Tripwires.** `tools/check-connection-words.sh` must keep failing on a view that spells a
  connection word, including the new route words (its word list gains them, §D9).
  `tools/check-capture-operator-only.sh` rule 5 parses `Shell/ShellView.swift` for exactly one
  `ExtensionController(` construction and one `.start()` on it: that block is not touched.
  `tools/check-capture-toggle.sh` NS-AC4 (ShellView reads no `capture.enabled`, calls no
  `CaptureSwitch`, touches no `extensionController`) must hold for the new banner file too.
- **The system-proxy fact is a value.** `ConnectionSummary.make` takes `SystemProxyState?`;
  the only code that calls `CFNetworkCopySystemProxySettings()` is `Bus/SystemProxyReader.swift`
  in the app target, called only from `BusService`'s live connection (§D6).
- **Cadence.** No read faster than `BusService.pollInterval` (500 ms); the system-proxy read rides
  the existing poll tick. `ca.status` is read on the same loop but every 10th tick (§D6): on macOS
  it spawns `/usr/bin/security` per store (`crates/aitm-ca/src/exec.rs`), so a 500 ms cadence would
  mean ~8 subprocesses a second. Never a new verb.
- **No new dependencies.** CFNetwork is a system framework; the Kit stays free of SwiftUI,
  AppKit and CFNetwork (it parses a plain dictionary).
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

`AitmproxyKit/SystemProxyState.swift` (new):

```swift
/// The effective global macOS HTTP/HTTPS system proxy as `CFNetworkCopySystemProxySettings()`
/// reports it (follows the primary network service) — the one read-back every system-proxy
/// surface in the app uses: this spec's route advice, the set-system-proxy toggle and
/// `proxy.system.status`. `nil` endpoint = that protocol's *Enable key is 0 or absent. Built from
/// the raw dictionary so the parser is testable without CFNetwork.
public struct SystemProxyState: Hashable, Sendable {
    public struct Endpoint: Hashable, Sendable {
        public var host: String
        public var port: Int
        /// "host:port"
        public var address: String
    }
    public var http: Endpoint?
    public var https: Endpoint?
    public init(http: Endpoint?, https: Endpoint?)
    /// Keys "HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"
    /// (the values of the kCFNetworkProxies* constants). Enable is any non-zero number; a Port is
    /// accepted as a number or a numeric string (CFNetwork hands back NSNumber; the string form
    /// costs nothing and was asked for by the system-proxy session, which shares this type).
    public init(settings: [String: Any])
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

Matching rule for `route(to:)`: ports equal, and hosts equal after lower-casing, or both
loopback (`127.0.0.1`, `localhost`, `::1`), or the listen host is a wildcard (`0.0.0.0`, `::`)
and the proxy host is loopback. `thisCore` is reported when at least one protocol matches (an
HTTP-only system proxy does deliver `http://` traffic; the words say "HTTP only"). `.other` is a
real, current case: Matt's Mac carries Proxyman's `127.0.0.1:9090` for HTTP and HTTPS.

`AitmproxyKit/ConnectionSummary.swift` additions:

```swift
public enum ConnectionAction {
    …, case openNetworkSettings           // NEW here: title "Open Network Settings…"
    …, case addScopeHost                  // NEW here: title "Add Host…" — the Scope entry's remedy button (opens Scope with its add sheet)
    // RESERVED for the set-system-proxy session, not added by this spec:
    //   case setSystemProxy, unsetSystemProxy
    // RESERVED for the system-proxy-automation session (CA install side), not added by this spec:
    //   case trustCA /* title "Trust the aitmproxy CA" */, openCAPanel
}
extension ConnectionAction {
    /// The System Settings pane the action opens; nil for every other action.
    public var settingsURL: URL?   // openNetworkSettings → "x-apple.systempreferences:com.apple.Network-Settings.extension"
                                   // approveInSystemSettings → the existing LoginItems URL (moved here: one table)
}

// AitmproxyKit/CATrustFacts.swift (new) — shared contract; IMPLEMENTED by the CA-trust session's PR (number TBD),
// with exactly these names and strings, together with the two additive CAStatus fields (§D7)
/// What the keychain says about the aitm CA, as `ca.status` reports it. `installing` and `remedy` are
/// the sibling's verb-sourced fields (in-flight install, needs-admin); this spec passes the defaults.
public struct CATrustFacts: Hashable, Sendable {
    public var trusted: Bool
    /// The store that reports trusted == "yes": "user" | "system"; nil when not trusted.
    public var scope: String?
    public var fingerprint: String?
    public var installing: Bool = false
    public var remedy: String? = nil
    public init(trusted: Bool, scope: String?, fingerprint: String?, installing: Bool = false, remedy: String? = nil)
    /// Pure, from the Kit's `CAStatus`. Failable: nil when no store reports "yes" or "no" (the core's
    /// "unknown", or no stores), which renders as unknown — never as trusted, never as not trusted.
    public init?(status: CAStatus)
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
    /// What opens the route, primary first; empty when open.
    public let actions: [ConnectionAction]
    /// The state words: `line` up to its first " — " ("system proxy off", "All Apps off"), or the whole
    /// line when it has none (the quoted Scope sentence, verbatim with its period; the CA line). The
    /// one-line banner is the shown entries' states joined with " · " (§D5); remedies are never text
    /// there — they are the entry's `actions.first`, shown as the banner's one button.
    public var state: String
}

public struct TrafficRoutes: Hashable, Sendable {
    /// nil until the system proxy has been read (first poll; a session with no live bus).
    public let systemProxy: TrafficRoute?
    /// nil when this build has no extension (`CaptureAdvice.unsupported`) or an external core is active.
    public let allApps: TrafficRoute?
    /// The Scope fact (not a route; under per-host decryption it gates decryption on both). Always
    /// present: closed iff `scopeHostCount == 0`.
    public let scope: TrafficRoute
    /// The CA fact (not a route; it gates HTTPS on both). nil while `ca.status` is unread or unknown.
    public let caTrust: TrafficRoute?
    /// The closed entries we know about — system proxy, All Apps, Scope, CA, in that order: the Flows
    /// empty-state lines. Empty unless the bus lane is `.ok`.
    public let advice: [TrafficRoute]
    /// The one-line banner text above the Flows table, or nil (§D5): the shown entries' `state`s joined " · ".
    public let banner: String?
    /// The banner's one button: the highest-priority shown entry's `actions.first` (nil when that entry
    /// has none). Priority: system proxy, All Apps, Scope, CA.
    public let bannerAction: ConnectionAction?
    public var anyOpen: Bool
}

public struct GettingStartedStep {
    public enum Kind { case coreRunning, busConnected, systemProxy /* NEW */, extensionOn, scopeSet, caTrusted /* from the CA-trust PR D */, firstFlow }
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
        systemProxy: SystemProxyState? = nil,         // NEW, defaulted so existing call sites compile
        caTrust: CATrustFacts? = nil,                 // NEW; nil = `ca.status` unread/unknown
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

The Kit `CAStatus` decoder gains nothing the sibling does not also need: `CATrustFacts(status:)`
reads `stores.*.trusted` labels ("yes" → trusted with that store's scope; any "no" and no "yes" →
not trusted; only "unknown"/none → nil) and `fingerprint_sha256`. `CAStatus.trusted: Bool` stays.

### D2a. Shared vocabulary (stable; consumed by the sibling set-system-proxy work)

The sibling session adds operator-only `proxy.system.status/set/unset` verbs and a Settings ▸
Proxy toggle. It consumes exactly these names and words and adds its own actions beside them; it
does not redefine any of the following.

| Name | Meaning |
|---|---|
| `SystemProxyState` | effective global read-back of the macOS HTTP/HTTPS proxy; `http`/`https: Endpoint?`; `init(settings:)`; `.off` |
| `SystemProxyState.Endpoint` | `host`, `port`, `address` ("host:port") |
| `SystemProxyRoute` | `.off`, `.thisCore(http:https:)`, `.other(host:port:)` — `state.route(to: listenAddress)` |
| `ConnectionAction.openNetworkSettings` | title "Open Network Settings…"; `settingsURL` = `x-apple.systempreferences:com.apple.Network-Settings.extension` |
| `ConnectionAction.addScopeHost` | title "Add Host…"; opens the Scope page with its add sheet — the Scope entry's remedy button (shared with S-073/S-074/S-080) |
| `ConnectionAction.setSystemProxy`, `.unsetSystemProxy` | **reserved names** for the sibling's actions (candidate titles "Set as System Proxy" / "Restore System Proxy", research 22 §4); not implemented here |
| `TrafficRoute.Kind.systemProxy` / `.allApps` / `.scope` / `.caTrust` | the two routes, and the two facts that gate what they carry (Scope → decryption, CA → HTTPS) |
| `CATrustFacts` | `trusted`, `scope` ("user" \| "system"), `fingerprint`, `installing` (sibling), `remedy` (sibling); `init?(status: CAStatus)`; nil slot = unknown |
| `ConnectionAction.trustCA`, `.openCAPanel` | **reserved names** for the system-proxy-automation session (title "Trust the aitmproxy CA"); not implemented here |

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

CA words (one string per fact, both surfaces; S = `scope` rendered "user keychain" / "system keychain"):

| Fact | Line | Detail |
|---|---|---|
| trusted | `CA trusted (S)` — e.g. `CA trusted (user keychain)`, accurate because the core's macOS default install scope is User, the login keychain | `HTTPS on both routes` |
| not trusted | `HTTPS is not captured until the CA is trusted` (the Status step's title is `Trust the aitmproxy CA`; the Flows row and the banner use the line) | `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then` |
| installing (sibling sets `installing`) | `trusting CA…` | as not trusted |
| needs admin (sibling sets `remedy`) | `CA trust needs an administrator` (= `remedy`) | as not trusted |
| unread / unknown (nil slot) | nothing — no step, no row, no banner clause | — |

The last two rows are the sibling's strings, listed here so there is one table; this spec never sets
`installing` or `remedy`.

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

System proxy route (`nil` when `systemProxy == nil`); `detail` = `every proxy-aware app, regardless of Scope`:

| `systemProxy.route(to: L)` | open | `line` | `actions` |
|---|---|---|---|
| `.off` | no | `system proxy off — set L as the system proxy, or point a client at it` | `[.openNetworkSettings, .copyListenAddress]` |
| `.other(H, P)` | no | `system proxy on · H:P, not this core — set L as the system proxy, or point a client at it` | `[.openNetworkSettings, .copyListenAddress]` |
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

Let `d` = `decrypt` (nil from an older core); closed ⇔ `d != nil ? !d.decrypting : scopeHostCount == 0`;
`N` = `d?.scopeHosts ?? scopeHostCount`.

| state | open | `line` (= `state`: no " — " clause) | `actions` |
|---|---|---|---|
| closed, `d?.advice` present | no | `d.advice` **verbatim** — today `Nothing is decrypted until a host is in Scope.` | `[.addScopeHost, .openScope]` |
| closed, `d == nil` or `d.advice == nil` | no | our fallback, the same words: `Nothing is decrypted until a host is in Scope.` | `[.addScopeHost, .openScope]` |
| open | yes | `Scope: ` + `Format.count(N, "host")` + ` decrypted` (`Scope: 1 host decrypted`) | `[]` |

The text is the core's own sentence so every surface in the product (TUI, web, this app) prints one
string (core spec D9) and a core wording change reaches this app without an edit; the remedy is the
**button** `Add Host…`, never appended text. The open form stays ours: the core's `advice` is null then.

CA fact (`nil` when `caTrust == nil`); `kind = .caTrust`, `detail` = `HTTPS on both routes` when
trusted, else `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then`:

| `caTrust` | open | `line` | `actions` |
|---|---|---|---|
| `trusted == true` | yes | `CA trusted (user keychain)` / `(system keychain)` per `scope`; `CA trusted` when `scope` is nil | `[]` |
| `installing == true` | no | `trusting CA…` | `[]` |
| `remedy != nil` | no | the `remedy` text (sibling's `CA trust needs an administrator`) | `[.trustCA, .openCAPanel]` |
| otherwise | no | `HTTPS is not captured until the CA is trusted` | `[.trustCA, .openCAPanel]` (PR D's cases; title "Trust the aitmproxy CA" — the banner's button when the CA is the highest-priority shown fact) |

`advice` = `[systemProxy, allApps, scope, caTrust].compactMap { $0 }.filter { !$0.open }`, in that
order, when the bus lane's state is `.ok`, else `[]` (the scope is known only through the bus).
`anyOpen` counts the two routes only.

### D4. Words and where they appear

**Getting-started steps**, in order: `coreRunning`, `busConnected`, `systemProxy`,
`extensionOn`, `scopeSet`, `caTrust`, `firstFlow`.

- `systemProxy` (new): **omitted from `steps` while `routes.systemProxy == nil`** (the fact has
  not been read: anti-goal "lying"). `title` = `routes.systemProxy.line` verbatim; `detail` =
  the route's `detail`; `done` = `open`; `action` = `.openNetworkSettings` when closed, nil when
  open.
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
- `caTrust` (new): **omitted while `routes.caTrust == nil`** (unread or unknown: we can neither say
  it is trusted nor that it is not, and a step that cannot name its fix is noise — the CA page shows
  the raw detail). `done` = `open`; `title` = `Trust the aitmproxy CA` when not done, `CA trusted
  (user keychain)` (the route line) when done; `detail` = the route's `detail`; `action` = nil in
  this spec (no `ConnectionAction` reaches the CA page today; the sibling's `.trustCA` becomes the
  primary action and `.openCAPanel` the secondary when they land — the step is listed without a
  button until then, and the CA page stays reachable from the sidebar and Proxy ▸ Certificate
  Authority…). The Status step title and the Flows line differ on purpose for this one fact (a
  checklist names the task, a flow list names the consequence); both strings come from the model.

Route lines start lower-case (except the proper name "All Apps") and the Status rows show them
verbatim, done or not (**Architect's call**: one string per fact beats a sentence-cased twin; the
sibling toggle reuses the same strings). `StepRow` gains `.help(step.detail ?? step.title)` —
one line in `StatusPanel.swift`.

**Flows empty state** (`EmptyFlows`, unfiltered): the "No flows yet" headline stays. Under it,
when `routes.advice` is non-empty, one row per entry — the `line` with its primary action as a
`SmallButton` (plus Copy Address for the system-proxy line; the CA row has no button until the
reserved actions land), and the entry's `detail` as a smaller tertiary line beneath — *instead of* the generic "Point a client at L or open the
browser." line; when `advice` is empty the generic line stays as today. The filtered state ("No
flows match") is unchanged.

**Flows banner**: §D5.

### D5. The banner predicate (exact) and the one-line rule

```
routesClosed   ⇔  routes.systemProxy != nil  ∧  !routes.systemProxy.open
               ∧  (routes.allApps == nil  ∨  !routes.allApps.open)
scopeClosed    ⇔  scopeHostCount == 0
allTunnels     ⇔  flowCount > 0  ∧  tunnelledFlowCount == flowCount
caClosed       ⇔  routes.caTrust != nil  ∧  !routes.caTrust.open
shown          =  (routesClosed ? [systemProxy, allApps].compactMap{$0}.filter{!$0.open} : [])
               +  (scopeClosed ∧ (routesClosed ∨ allTunnels) ? [scope] : [])
               +  (caClosed ? [caTrust] : [])                       // priority order
banner != nil  ⇔  flowCount > 0  ∧  bus.state == .ok  ∧  !shown.isEmpty
banner         =  shown.map(\.state).joined(" · ")            // text: states only, no remedy clause
bannerAction   =  shown.first?.actions.first                     // the one button: the highest-priority remedy
```

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

**Composed form (Architect's call, after the improve-loop measurement; shape aligned with core
spec D9).** Up to four facts compete for one 40 pt line, and full lines with remedies would be
~260 characters. The banner names every shown fact by its *state words* joined with ` · ` and
carries **no remedy text at all**; the remedy is the banner's one **button**, the highest-priority
shown fact's primary action: system proxy → `Open Network Settings…`, All Apps off → `All Apps
Settings…`, Scope → `Add Host…`, CA → `Trust the aitmproxy CA`. So the system-proxy and CA
remedies become buttons too, and the Scope text is the core's sentence untouched. Literals
(button in the last column):

| Shown facts | `banner` | `bannerAction` |
|---|---|---|
| fresh install: system proxy off + All Apps off + scope empty + CA not trusted | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` | `.openNetworkSettings` |
| system proxy off + All Apps off + scope empty | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope.` | `.openNetworkSettings` |
| system proxy off + All Apps off + scope set | `system proxy off · All Apps off` | `.openNetworkSettings` |
| a route open + scope empty + every row a tunnel | `Nothing is decrypted until a host is in Scope.` | `.addScopeHost` |
| a route open + scope empty + every row a tunnel + CA not trusted | `Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` | `.addScopeHost` |
| a route open + scope empty + some rows readable (plain HTTP) | nil, or `HTTPS is not captured until the CA is trusted` when the CA is not trusted | — / `.trustCA` |
| a route open + CA not trusted | `HTTPS is not captured until the CA is trusted` | `.trustCA` |
| no extension in the build + system proxy off + scope empty | `system proxy off · Nothing is decrypted until a host is in Scope.` | `.openNetworkSettings` |
| no extension in the build + system proxy off + scope set | `system proxy off` | `.openNetworkSettings` |

A closed CA fact alone does not close the routes, but it adds its state whenever flows exist and
HTTPS is not trusted: the flows the operator sees are the plain-HTTP ones and every HTTPS attempt
is failing right now.

The view (`RouteBanner`) shows `banner` in one line — `lineLimit(1)`, `truncationMode(.tail)`,
`Tok.Size.Row.dense` (40 pt), tertiary ink, the former `ScopeBanner` shape — with the full
`banner` and the shown entries' `detail`s joined with ` · ` as its `.help`, and **one** `SmallButton`
for `bannerAction` (`Open Network Settings…` / `All Apps Settings…` / `Add Host…` / `Trust the
aitmproxy CA`); nothing else sits on the line.

**One banner line, everywhere flows are listed (§D8).** On every page that renders the flow
table — Flows, Pinned, Domains, Apps — the route banner is the only banner: shown iff
`routes.banner != nil`, above the table; when nothing is shown, no banner at all. `ScopeBanner`
and `AppsAttributionBanner` are no longer rendered on any page (§D8). The column header therefore
sits at most one 40 pt line below the chip bar, never two.

### D6. The live reader and its cadence (Architect's call: poll tick)

`Bus/SystemProxyReader.swift` (app target, new): one static function that bridges
`CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]` — the effective
global settings — into `SystemProxyState(settings:)`, `nil` when the call returns nothing.
`BusService` calls it right after `refreshProxyStatus()` in `pollLoop` and once after `connect()`
succeeds, writing `session.systemProxy` only when the value changed (no re-render churn).
`Session.systemProxy: SystemProxyState?` is a plain observed property, `nil` until the first live
read; `Session+Connection.connectionSummary` passes it to `make`.

Why the poll tick and not `SCDynamicStore` notifications: (1) the read is a sub-millisecond
dynamic-store dictionary copy, so twice a second costs nothing measurable; (2) it lands with the
same ≤500 ms latency as `scope.list` and `proxy.status`, so the two route facts never disagree
in age; (3) a notification source needs a run-loop/dispatch hookup, a second framework import
and its own teardown — a moving part with no pure test; (4) it honours "no polling faster than
the existing poll loop" by construction. If the read ever shows in a profile,
`SCDynamicStoreSetNotificationKeys` on `State:/Network/Global/Proxies` is the drop-in; nothing in
the model changes. The sibling's `proxy.system.status` verb, when it lands, can replace the
in-app read with the core's — same type, same words.

**`ca.status` read.** `BusService` already owns the poll; it gains `refreshCAStatus()`: once after
`connect()` succeeds and then every 10th `pollLoop` tick (~5 s), calling the existing read-only,
unaudited `ca.status` verb and writing `session.caStatus: CAStatus?` only when changed (reset to nil
in the `pollLoop` `defer`). Why not every tick: on macOS the verb spawns `/usr/bin/security` per
store. Why not only the CA page's `onAppear` read: the Status and Flows surfaces must follow a trust
change made in Keychain Access or by `aitm ca install` from a terminal without a visit to the CA
page. `Session+Connection.connectionSummary` passes `caTrust: caStatus.flatMap(CATrustFacts.init)`.
The CA page keeps its own read (untouched); the two agree within one CA tick.

### D7. Views and files (the claim list)

- `AitmproxyKit/SystemProxyState.swift` (new), `AitmproxyKit/ConnectionSummary.swift`,
  `Tests/AitmproxyKitTests/SystemProxyStateTests.swift` (new),
  `Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (the predicate-table test).
  **Implemented by the CA-trust session's PR (number TBD), to this spec's definitions, not here:**
  `AitmproxyKit/CATrustFacts.swift` (new), `Tests/AitmproxyKitTests/CATrustFactsTests.swift` (new)
  and the two additive fields `trustedScope` / `trustReported` in `AitmproxyKit/Panels/CAStatus.swift`.
  `Panels/CAPanel.swift` is **not** changed by anyone here.
- `Session.swift`: `var systemProxy: SystemProxyState?`, `var caStatus: CAStatus?`,
  `var decrypt: DecryptStatus?` (from `proxy.status.decrypt`, nil until read / on an older core).
- `Session+Connection.swift`: `connectionSummary` passes `systemProxy:`, `decrypt:`,
  `tunnelledFlowCount:` and `caTrust: caStatus.flatMap(CATrustFacts.init)`; new one-line accessor
  `var trafficRoutes: TrafficRoutes { connectionSummary.routes }` — the only thing the Flows
  surfaces read, so `connectionSummary`'s reader allow-list does not grow and no lane word can
  leak into `ShellView.swift`; `perform(connection: .addScopeHost)` does `show(.scope)` then
  `scopeSheetVisible = true` (the Proxy ▸ Scope… menu's add-sheet path); `perform(connection:
  .openNetworkSettings)` opens `action.settingsURL` with `NSWorkspace` (and `.approveInSystemSettings` switches to the same
  `settingsURL` table).
- `Bus/SystemProxyReader.swift` (new), `Bus/BusService.swift` (the two system-proxy call sites,
  `refreshCAStatus()` with its tick counter, §D6, and — in the existing `refreshProxyStatus()` —
  `session.decrypt = status["decrypt"].flatMap(DecryptStatus.init)`, reset to nil in the `pollLoop`
  `defer`; no new verb, no new read: `proxy.status` is already polled every tick).
- `AitmproxyKit/DecryptStatus.swift` (new) + `Tests/AitmproxyKitTests/DecryptStatusTests.swift` (new).
- `AitmproxyKit/FlowSummary.swift`, `AitmproxyKit/Flow.swift` (`TunnelMode`, `TunnelReason`, the five
  `FlowRow` fields, `isTunnel`, `==`), `AitmproxyKit/FlowDetail.swift` (`TunnelInfo`, `tunnel`,
  `passive`), `AitmproxyKit/FlowDetail+Wire.swift` + `Tests/AitmproxyKitTests/FlowSummaryTests.swift`
  (new), `FlowRowEqualityTests.swift`, `FlowDetailWireTests.swift` — **plan Task 1c, pending the
  orchestrator's claim answer**; file-disjoint from Task 1; nothing else in this spec touches them.
- `Shell/RouteBanner.swift` (new): renders `session.trafficRoutes.banner` with the closed
  routes' primary actions through `session.perform(connection:)`; `.openCaptureSettings`, which
  `perform` leaves to the view, sets `settingsTab = .capture` and calls `openSettings()` exactly as
  `AppsAttributionBanner` does. Mentions no `connectionSummary`, `ConnectionSummary`, `LaneDot`,
  `LaneState`, `CaptureSwitch`, `capture.enabled`, `extensionController`.
- `Shell/ShellView.swift`, two hunks only: (1) `EmptyFlows` (struct ~319–336) reads
  `session.trafficRoutes.advice` (via `@Environment(Session.self)`, or a `routes:` parameter
  passed from the existing `flowTable` overlay call at ~261 — builder's choice) and gains the
  route rows; `allowsHitTesting` stays off except for its buttons. (2) In `MainView.flows`
  (~174–200) the `ScopeBanner()` branch and the `AppsAttributionBanner()` block are removed and one
  insertion takes their place: `if session.trafficRoutes.banner != nil { RouteBanner(); Rule() }`
  on every list page (§D8 lists the two removed call sites verbatim). The `AppsAttributionBanner`
  struct stays. Nothing else in the file changes; the `ExtensionController` block (rule 5) and
  lines 49–62 are untouched.
- `Panels/StatusPanel.swift`: the one `.help` line on `StepRow` (§D4).
- `App.swift` + `AitmproxyKit/CommandMap.swift`: Proxy ▸ "Network Settings…" menu item (every
  action has a menu item; shortcut left to the builder, must not clash) and its command-map
  entry (the map is the menu's table of record).
- `tools/check-connection-words.sh`: §D9. `tools/check-capture-toggle.sh`: the NS-AC8 banner pins
  move to `RouteBanner()` (§D8).
- `apps/mac/docs/GLOSSARY.md`: "System proxy" and "Route" rows carrying the lane principle;
  `docs/STORIES.md`: S-073 "See why nothing is flowing" (depends S-072).

### D8. One banner line: `ScopeBanner` and `AppsAttributionBanner` retire from the list pages

Measured by the improve-loop session on `main 9dba3d9f` (fresh install, empty scope, no source
app): `ScopeBanner` ("No scope set — every host is read-only until you add one") and
`AppsAttributionBanner` ("Flows carry no source app yet, so this page cannot group them.") stacked
above the Apps list, 40 pt each, pushing the column header 80 pt down so a click aimed at row 1
hit the header and sorted by URL.

Rule: on every page that lists flows, at most ONE 40 pt banner line is ever shown, and it is the
route banner of this spec. It absorbs the scope line (the Scope fact: `Nothing is decrypted until a
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

Call sites removed in `Shell/ShellView.swift`, both inside `MainView.flows` (~187–197 on `main
5eac2a50`): (1) `} else if !Store.usesFixtures, session.scopeHosts.isEmpty, case .connected =
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
as today). L = listen address; H:P = a foreign endpoint. The Kit test makes one
`ConnectionSummary.make` call per row with literal inputs and pins the literal lines. "E" = the
Flows empty-state entries (0 flows), "B" = the banner (flows > 0).

| SP | AA | SC | Status `systemProxy` / `extensionOn` / `scopeSet` | E | B (T false) | B (T true) |
|---|---|---|---|---|---|---|
| unknown (nil) | on | 0 | absent / ✓ All Apps is on / ○ Add a host to Scope … | scope line | no | scope line |
| off | on | n | ○ system proxy off — … / ✓ / ✓ Scope: n hosts decrypted | system proxy line | no | no (T impossible with a host decrypting — if seen, no) |
| off | on | 0 | ○ system proxy off — … / ✓ All Apps is on / ○ Add a host to Scope … | system proxy line, scope line | no | `Nothing is decrypted until a host is in Scope.` |
| off | off / awaiting / degraded | 0 | ○ … / ○ All Apps off — … (or waiting / degraded) / ○ Add a host … | system proxy, All Apps, scope lines | `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. — set …` (waiting/degraded state words likewise) | same |
| off | off | n | ○ / ○ / ✓ | system proxy, All Apps lines | `system proxy off · All Apps off — set …` | same |
| off | unsupported or external core | 0 | ○ / "not in this build" or lane / ○ | system proxy, scope lines | `system proxy off · Nothing is decrypted until a host is in Scope. — set …` | same |
| off | unsupported or external core | n | ○ / … / ✓ | system proxy line | `system proxy off — set …` | same |
| other(H,P) | any | any | ○ system proxy on · H:P, not this core — … / per AA / per SC | as the "off" rows with the other line | as the "off" rows with the other state | same |
| thisCore(·,·) | on | 0 | ✓ system proxy on · L [· HTTP(S) only] / ✓ / ○ Add a host … | scope line | no | scope line |
| thisCore(·,·) | on | n | ✓ / ✓ / ✓ | generic line | no | no |
| thisCore(·,·) | off / awaiting / degraded | 0 | ✓ / ○ / ○ | All Apps line, scope line | no (a route is open) | scope line |
| thisCore(·,·) | unsupported | any | ✓ / … / per SC | scope line when SC = 0 | no | scope line when SC = 0 |

The CA fact is orthogonal to every row above and adds one column each:

| CA | Status `caTrust` step | E (appended last) | B |
|---|---|---|---|
| nil (unread / unknown) | absent | nothing | the row's value |
| trusted (scope user) | ✓ CA trusted (user keychain) | nothing | the row's value |
| not trusted | ○ Trust the aitmproxy CA (no button yet) | `HTTPS is not captured until the CA is trusted` | the row's states + ` · HTTPS is not captured until the CA is trusted` (before the remedy); where the row says **no** and flows > 0, the CA line alone |
| installing (sibling) | ○ trusting CA… | `trusting CA…` | as not trusted |

## Acceptance criteria

Kit unit tests (literal strings), `L = "127.0.0.1:8080"`:

1. **TR-AC1 [kit-unit]** `SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1",
   "HTTPPort": 9090, "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": 9090])` →
   `http == Endpoint(host: "127.0.0.1", port: 9090)`, `https` the same, `http?.address == "127.0.0.1:9090"`;
   `["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080, "HTTPSEnable": 0]` → `https == nil`;
   an absent or `0` Enable yields nil; `SystemProxyState(settings: [:]) == .off`.
2. **TR-AC2 [kit-unit]** `route(to: L)`: off → `.off`; both at `127.0.0.1:8080` →
   `.thisCore(http: true, https: true)`; both at `localhost:8080` → the same; HTTP at
   `127.0.0.1:8080`, HTTPS nil → `.thisCore(http: true, https: false)`; both at `127.0.0.1:9090`
   → `.other(host: "127.0.0.1", port: 9090)`; HTTP at `10.0.0.1:3128`, HTTPS at `127.0.0.1:8080`
   → `.thisCore(http: false, https: true)`; HTTP nil, HTTPS at `10.0.0.1:3128` →
   `.other(host: "10.0.0.1", port: 3128)`; listen `0.0.0.0:8080` with proxy `127.0.0.1:8080` →
   `.thisCore(true, true)`.
3. **TR-AC3 [kit-unit]** `make(core: nil, activeKind: .embedded, bus: .connected("127.0.0.1:60745"),
   role: "operator", roleWarning: false, capability: .capturing, captureSupported: true,
   scopeHostCount: 0, flowCount: 0, listenAddress: L, systemProxy: .off).routes.advice.map(\.line) ==
   ["system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it",
   "Nothing is decrypted until a host is in Scope."]`; `advice.map(\.kind) == [.systemProxy, .scope]`
   (All Apps is on, so open: `routes.allApps?.line == "All Apps on"`); `advice.map(\.detail) ==
   ["every proxy-aware app, regardless of Scope", "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"]`;
   `advice[0].actions == [.openNetworkSettings, .copyListenAddress]`; `advice[1].actions == [.openScope]`;
   `routes.scope.state == "Nothing is decrypted until a host is in Scope."` (= its line), `advice[1].actions == [.addScopeHost, .openScope]`;
   `banner == nil`, `bannerAction == nil`; `anyOpen == true` (All Apps). The same with `flowCount: 6` → `advice == []` and
   `banner == nil` (a route is open and the rows are readable); with `flowCount: 6, tunnelledFlowCount: 6`
   → `banner == "Nothing is decrypted until a host is in Scope."`; with `capability: .inactive, flowCount: 6` →
   `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`.
   The same with `systemProxy` both at `127.0.0.1:9090` and `flowCount: 0` →
   `advice[0].line == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`
   and no advice line contains `"off"`. **Quoted core sentence:** the same inputs plus
   `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Nothing is decrypted until a host is in Scope.")` →
   `routes.scope.line == "Nothing is decrypted until a host is in Scope."` (verbatim, period included),
   `routes.scope.state == "Nothing is decrypted until a host is in Scope."` (period kept), `routes.scope.open == false`, `actions == [.addScopeHost, .openScope]`; with `flowCount: 6, tunnelledFlowCount: 6`
   → `banner == "Nothing is decrypted until a host is in Scope."`; with `capability: .inactive, flowCount: 6` →
   `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openNetworkSettings`
   (identical to the fallback composition); the all-tunnels case above has `bannerAction == .addScopeHost`. `decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil)` with
   `scopeHostCount: 0` (stale list) → `routes.scope.open == true`, `line == "Scope: 2 hosts decrypted"`
   (N comes from `decrypt`). `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil)` →
   the fallback `line == "Nothing is decrypted until a host is in Scope."`.
4. **TR-AC4 [kit-unit, predicate table]** One `make` call per row of §D10 pinning `routes` and
   the steps, including: `.inactive` → All Apps line `"All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`
   with `[.openCaptureSettings]`; `.pendingApproval` → `"All Apps waiting for approval — approve the extension in System Settings"`,
   `[.approveInSystemSettings]`; `.degraded("x")` → `"All Apps degraded — x"`; `.capturing` with
   `scopeHostCount: 1` → `routes.allApps?.line == "All Apps on"`, open, `[]`, and
   `routes.scope.line == "Scope: 1 host decrypted"`, open; `scopeHostCount: 3` → `"Scope: 3 hosts decrypted"`;
   HTTP-only at the core →
   `"system proxy on · 127.0.0.1:8080 · HTTP only"`, open; both at the core → `"system proxy on · 127.0.0.1:8080"`;
   `systemProxy: nil, .capturing, scopeHostCount: 0` → `routes.systemProxy == nil` and `advice` holds
   the scope line only; `captureSupported: false` → `routes.allApps == nil`, and with `systemProxy: .off,
   scopeHostCount: 2, flowCount: 3` the banner is the system-proxy line alone, with `scopeHostCount: 0`
   it is `"system proxy off · Nothing is decrypted until a host is in Scope."` with `bannerAction == .openNetworkSettings`; `systemProxy: .off, capability: .capturing,
   scopeHostCount: 2, flowCount: 3` → `banner == nil` (one route open) and `anyOpen == true`;
   `systemProxy` at `127.0.0.1:9090`, `.capturing`, `scopeHostCount: 2`, `flowCount: 3` →
   `banner == nil`; bus `.disconnected` → `advice == []`, `banner == nil`; `activeKind: .external`
   → `routes.allApps == nil`.
5. **TR-AC5 [kit-unit]** Steps: with `systemProxy: nil`, `steps.map(\.kind)` contains no
   `.systemProxy`; with `systemProxy: .off` it is `[.coreRunning, .busConnected, .systemProxy,
   .extensionOn, .scopeSet, .firstFlow]` and the `.systemProxy` step has `done == false`,
   `title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`,
   `detail == "every proxy-aware app, regardless of Scope"`, `action == .openNetworkSettings`;
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
6a. **TR-AC15 [kit-unit, CA facts — contract; implemented and proved by the CA-trust session's PR]** `CATrustFacts(status:)` over literal `CAStatus(json:)` inputs:
   `stores.user.trusted == "yes"` → `trusted == true`, `scope == "user"`, `fingerprint == <the sha256>`;
   `user "no"`, `system "no"` → `trusted == false`, `scope == nil`; `user "unknown"` only → `nil`;
   no `stores` with `exists == true` → `nil`; `system "yes"`, `user "no"` → `trusted == true`,
   `scope == "system"`; `installing == false` and `remedy == nil` on every result.
6b. **TR-AC16 [kit-unit, CA in routes and steps]** With the TR-AC3 inputs plus
   `caTrust: CATrustFacts(trusted: false, scope: nil, fingerprint: "AB:CD")`:
   `routes.caTrust?.line == "HTTPS is not captured until the CA is trusted"`,
   `routes.caTrust?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`,
   `routes.caTrust?.actions == [.trustCA, .openCAPanel]`, `advice.map(\.kind) == [.systemProxy, .scope, .caTrust]`
   (All Apps on → open), `anyOpen == true`; `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrusted, .firstFlow]`,
   the `.caTrust` step `title == "Trust the aitmproxy CA"`, `done == false`, `action == nil`,
   `detail` = the detail string above. With `flowCount: 6` → `banner == "HTTPS is not captured until the CA is trusted"`
   (All Apps open, rows readable); with `flowCount: 6, tunnelledFlowCount: 6` →
   `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`; with `capability: .inactive, flowCount: 6` →
   `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`.
   With `systemProxy` both at the core, `.capturing`, `scopeHostCount: 2`, `flowCount: 3`, same
   `caTrust` → `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`, `anyOpen == true`.
   With `caTrust: CATrustFacts(trusted: true, scope: "user", fingerprint: "AB:CD")` →
   `routes.caTrust?.line == "CA trusted (user keychain)"`, `open == true`, `detail == "HTTPS on both routes"`,
   the step `title == "CA trusted (user keychain)"`, `done == true`, and with the two routes open
   `banner == nil`; `scope: "system"` → `"CA trusted (system keychain)"`; `scope: nil` → `"CA trusted"`.
   `caTrust: nil` → `routes.caTrust == nil`, no `.caTrust` step, no CA text in `advice` or `banner`.
   `installing: true` → `line == "trusting CA…"`, `open == false`; `remedy: "CA trust needs an administrator"`
   → `line == "CA trust needs an administrator"`.
6. **TR-AC6 [kit-unit]** `ConnectionAction.addScopeHost.title == "Add Host…"`, `isDestructive == false`, `settingsURL == nil`;
   `ConnectionAction.openNetworkSettings.title == "Open Network Settings…"`,
   `.isDestructive == false`, `settingsURL?.absoluteString == "x-apple.systempreferences:com.apple.Network-Settings.extension"`;
   `approveInSystemSettings.settingsURL?.absoluteString == "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"`;
   every other action's `settingsURL` is nil; `ConnectionAction` has no case named
   `setSystemProxy`, `unsetSystemProxy`, `trustCA` or `openCAPanel` (reserved; a test that the enum's `allCases`-style
   witness list has exactly the pre-existing cases plus `openNetworkSettings`). `CommandMap` lists
   "Network Settings…" under Proxy.

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
8. **TR-AC8 [structural]** `grep -rln CFNetworkCopySystemProxySettings apps/mac/Sources` prints
   exactly `apps/mac/Sources/Aitmproxy/Bus/SystemProxyReader.swift`; no file under
   `Sources/AitmproxyKit` imports CFNetwork, SystemConfiguration, SwiftUI or AppKit;
   `Package.swift` is unchanged; `grep -rln '"ca.status"' apps/mac/Sources` prints exactly
   `Bus/BusService.swift` and `Panels/CAPanel.swift` (no new caller, no new verb);
   `grep -rn 'ca.install' apps/mac/Sources/Aitmproxy/Bus apps/mac/Sources/Aitmproxy/Shell apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` is empty;
   `git diff <base> -- apps/mac/Sources/Aitmproxy/Shell/ShellView.swift`
   shows hunks only inside `MainView.flows` and the `EmptyFlows` struct (lines 49–62 and the
   `ExtensionController` block identical); `git diff <base> -- apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift`
   is the one `.help` line.
9. **TR-AC9 [gates]** `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build` green
   including the new tests; the release build (`./build.sh --ne --allow-unnotarized` as the input
   to `scripts/notarize-dmg.sh`, `docs/RELEASE.md` step 3) has no warnings; the Rust gate is
   unaffected (no Rust change).

Real installed app (the notarized build containing this change, installed in `/Applications`,
embedded core running, All Apps on with the extension attached — a `./build.sh --debug` dev build
may be used for an early pass of the system-proxy lines, but it cannot activate the extension and
does not count). Every `networksetup` write runs in the Terminal panel (admin prompt is Matt's),
records the original values of every enabled service first (`networksetup -listallnetworkservices`,
`-getwebproxy`, `-getsecurewebproxy`) and restores them at the end; the primary service is the
one `route -n get default` names. The operator token is read from the 0600 per-launch config into
a shell variable and never printed. Evidence = `screencapture` PNGs under
`/tmp/claude/route-advice/`, the `scutil --proxy` output before each step, and the bus replies.

10. **TR-AC10 [live, as found]** With the system proxy as Matt has it today (`scutil --proxy`:
    `HTTPEnable : 1`, `HTTPProxy : 127.0.0.1`, `HTTPPort : 9090`, HTTPS the same) and
    `scope.list` over the operator bus `[]`: the Flows page shows "No flows yet" with
    `system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    and `Nothing is decrypted until a host is in Scope.`, each with its detail line and its
    buttons (Open Network Settings…, Copy Address; Open Scope…); the Status page's Getting-started
    list shows `○` the system-proxy line (Open Network Settings…), `✓ All Apps is on`, and
    `○ Add a host to Scope (for now as example.com:443)` (Open Scope…) whose help is the scope line. Nowhere does either
    page say the system proxy is off. One screenshot of each page.
11. **TR-AC11 [live]** `scope.add example.com:443` over the operator bus, no app interaction:
    within one second both pages drop the scope line; the system-proxy line stays; the
    `scopeSet` step reads `✓ Scope: 1 host decrypted`. `scope.remove` brings the line back on both
    pages. Screenshots before/after.
12. **TR-AC12 [live, flipped]** On every enabled service, `networksetup -setwebproxystate <svc> off`
    and `-setsecurewebproxystate <svc> off`: within one second both pages read
    `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (`scutil --proxy` confirms `HTTPEnable : 0`). Then `-setwebproxy <svc> 127.0.0.1 8080` and
    `-setsecurewebproxy <svc> 127.0.0.1 8080` on the primary service: within one second the
    system-proxy line disappears from the Flows empty state and the Status step reads
    `✓ system proxy on · 127.0.0.1:8080`; a real `http://example.com/` in Safari then produces a
    flow with no `-x`. Then `-setwebproxy <svc> 127.0.0.1 8081` on the primary service: both
    pages read `system proxy on · 127.0.0.1:8081, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (HTTP) — or `· HTTPS only` if HTTPS still points at 8080, per §D3. Finally the recorded
    Proxyman values are restored and re-read with `-getwebproxy`/`-getsecurewebproxy`; both pages
    show the TR-AC10 line again.
13. **TR-AC13 [live, banner]** With the system proxy not pointing at the core (as found) and
    `scope.list` `[]`, `curl -x 127.0.0.1:8080 http://example.com/` ×2: the Flows page shows the
    table with the rows and ONE banner line composed per §D5 (the state words of every closed
    fact, no remedy text) with one button, Open Network Settings…, and no "No
    scope set" `ScopeBanner` anywhere; Pinned, Domains and Apps show the same single line and no
    other banner. After `scope.add example.com:443` the All Apps state leaves the line; after
    `scope.remove` and the system proxy set to 127.0.0.1:8080 the system-proxy state leaves it;
    with every fact open the banner is gone and nothing replaces it; restored afterwards.
14. **TR-AC14 [live, actions]** Clicking Open Network Settings… on either page opens System
    Settings ▸ Network; Proxy ▸ Network Settings… in the menu bar does the same; Copy Address
    puts `127.0.0.1:8080` on the pasteboard (`pbpaste`); Open Scope… shows the Scope page.
    Hovering a route step on Status shows its detail (`every proxy-aware app, regardless of Scope`
    / `in-scope hosts of every app`) as the help.
15. **TR-AC17 [live, CA not trusted — HARD GATE: no `ca.install`]** On Matt's Mac as it is today:
    `ca.status` over the operator bus (`…/bus-ca-status.json`) shows every store with
    `trusted: "no"` (or `installed: "absent"`). Within one CA tick of connecting, the Flows empty
    state shows, after the two route rows, the row `HTTPS is not captured until the CA is trusted`
    with its detail `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then`
    and no button; the Status checklist shows `○ Trust the aitmproxy CA` with the same help and no
    button; with the TR-AC13 curl rows present the banner ends in ` · HTTPS is not captured until the CA is trusted`;
    with a route open (TR-AC12's 8080 step) and the curl rows present the banner is exactly
    `HTTPS is not captured until the CA is trusted`. Nothing on either page reads "trusted".
    **No one runs `ca.install` or clicks Install… on his Mac for this proof.** The trusted state
    (`CA trusted (user keychain)`, the line gone) is proved only after Matt says in his own words
    that the CA may be trusted, through the app's own step once `.trustCA` exists — recorded then
    in the plan's Shipped section, not here.
16. **TR-AC18 [kit-unit, composed banner]** `TrafficRoute.state`: the system-proxy off route has
    `state == "system proxy off"` (its `line` keeps the ` — set …` clause for the row and the step);
    the CA line has `state` == its line; All Apps `.on(hosts: 2)` has `line == "All Apps on"`;
    `routes.scope` with `scopeHostCount: 0` has `state == line == "Nothing is decrypted until a host is in Scope."`. `bannerAction` is
    the highest-priority shown entry's first action: `.openNetworkSettings` whenever the system-proxy
    fact is shown, `.openCaptureSettings` when only All Apps + Scope are shown, `.addScopeHost` for
    the all-tunnels Scope-only case, `.trustCA` for the CA-only case, nil when `banner == nil`.
    `make(… bus ok, capability: .inactive, captureSupported: true, scopeHostCount: 0, flowCount: 3,
    listenAddress: L, systemProxy: .off, caTrust: CATrustFacts(trusted: false, scope: nil, fingerprint: nil))`
    → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`
    (the fresh-install case); the same with `.capturing` → `banner == "HTTPS is not captured until the CA is trusted"`
    (All Apps open, rows readable), and with `tunnelledFlowCount: 3` → `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`;
    `.capturing`, `caTrust: nil`, `tunnelledFlowCount: 3` → `banner == "Nothing is decrypted until a host is in Scope."`;
    `.inactive`, `caTrust: nil` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`;
    `.inactive`, `scopeHostCount: 2`, `caTrust: nil` → `banner == "system proxy off · All Apps off"`;
    every single-fact banner equals that fact's `state` (`"system proxy off"` for the no-extension,
    scope-set case — never the line with its remedy clause).
17. **TR-AC19 [live, one banner line]** On the installed app with rows present (TR-AC13 state), on
    each of Flows, Pinned, Domains and Apps: exactly one banner line above the table, none of
    the old texts "No scope set" / "Flows carry no source app" anywhere; the column header's top
    edge (from the window screenshot, or the table header's AX frame) sits exactly 40 pt below
    its position after Edit ▸ Clear empties the list (no rows → `banner == nil` → no banner),
    never 80; Undo Clear restores rows and the single banner. A click on the first row's y
    selects row 1 and does not sort.
18. **TR-AC20 [live, per-host decryption, v0.5.9+]** Unconditional once plan Task 1c (the `tunnel`
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
19. **TR-AC21 [kit-unit, `DecryptStatus`]** `DecryptStatus(json:)` over literal `JSONValue` objects:
    `{"scope_hosts": 0, "decrypting": false, "advice": "Nothing is decrypted until a host is in Scope."}`
    → `scopeHosts == 0`, `decrypting == false`, `advice == "Nothing is decrypted until a host is in Scope."`;
    `{"scope_hosts": 2, "decrypting": true, "advice": null}` → `scopeHosts == 2`, `decrypting == true`,
    `advice == nil`; `{}` → nil; a `proxy.status` object without `decrypt` → `status["decrypt"].flatMap(DecryptStatus.init) == nil`.
20. **TR-AC22 [kit-unit, the #228 row/detail decoder — plan Task 1c]** With literal `flow.get`
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
  parameter; the glyphs for the two lines (`network` and `app.badge` suggested); the detail
  line's size (`Tok.Typography.Size.sm`, tertiary ink suggested).
- The menu shortcut for Proxy ▸ Network Settings… (must not clash; `CommandMap` lists it).
- Widening the loopback set beyond `127.0.0.1`, `localhost`, `::1` (for example `127.0.0.0/8`),
  as long as TR-AC2 holds.
- Whether `SystemProxyReader` returns `nil` or `.off` when `CFNetworkCopySystemProxySettings()`
  itself returns nil (either is honest; nil keeps the step hidden).
- `Hashable`/`Sendable` conformances and the `TrafficRoutes` memberwise init shape, provided the
  public fields above exist with these names.
- The `ca.status` tick divisor (10 = ~5 s) may be lowered to 4 if the `security` cost measures
  negligible; never 1.
- Where `CATrustFacts.swift` sits in the Kit (top level suggested; `Panels/` holds `CAStatus`).
- Deleting the now-unreferenced `ScopeBanner` struct, `AppsAttributionBanner` struct and
  `CaptureAdvice.banner` is a later cleanup with its own tripwire edits; not here.
- How `tunnelledFlowCount` is counted in `Session+Connection` (a filter over `rows` is fine at
  today's sizes; cache it beside `rowsVersion` if it shows in a profile).
- Whether `FlowSummary.tunnel` is stored as `String?` or a small enum; only the `tls` mapping is pinned.

## Open questions

None block. Calls Matt may want to flip (each a one-line change):

1. Route lines start lower-case on the Status rows too (§D4). Alternative: a sentence-cased
   `title` twin for Status.
2. The `systemProxy` step stays undone while the system proxy is off or elsewhere even when All
   Apps carries traffic, so "Everything is connected" needs the system proxy to point here.
   Alternative: mark it done when any route is open.
3. `ScopeBanner` and `AppsAttributionBanner` are no longer rendered on any list page; the route
   banner is the one 40 pt line (§D8). Alternative: keep `ScopeBanner` where the route banner is absent (see 12).
4. A build with no extension shows the system-proxy banner whenever rows come only from a
   hand-pointed client (§D5). Alternative: suppress when `allApps == nil`.
5. Poll-tick reading over `SCDynamicStore` notifications (§D6).
6. "Capture extension is on" → "All Apps is on" (§D4).
7. Open-state words `system proxy on · L` (research 22's candidate, lane-word style) rather than
   `system proxy is L`; `.other` words `system proxy on · H:P, not this core — …`.
8. The not-trusted `detail` repeats the line's first clause (both are the coordinators' binding
   strings); trimming the detail to `browsers using QUIC load directly until then` is one string.
9. `CATrustFacts(status:)` is failable (nil on the core's `unknown`) so unknown never renders as
   not trusted; the sibling may prefer a non-failable init plus a `known` flag.
10. The CA step and row ship without a button until `.trustCA`/`.openCAPanel` land; an interim
    navigation action to the CA page would be one more case.
11. Composed banner (§D5): state words of every shown fact as text, the highest-priority fact's
    remedy as the one button (system proxy > All Apps > Scope > CA). Alternative: show only the
    highest-priority fact's state and a count ("· 2 more").
12. The read-only-scope banner retires from the list pages (its fact lives in the route banner, the
    status bar and the Scope page). Alternative: keep it on pages where the route banner is absent.
13. The Scope fact enters the banner only when both routes are closed or EVERY row is a tunnel
    (§D5); a mixed list relies on the tunnel row's own inline remedy. Alternative: any tunnel row.
14. All Apps is reported open whenever the extension is on, even with an empty scope — true under
    per-host decryption (connections arrive as tunnel rows); until the core story lands the
    extension still rejects everything on an empty scope, and the empty state's scope line is what
    tells the operator. Alternative: keep All Apps closed on an empty scope until the story ships.
15. Done form `Scope: N hosts decrypted` (coordinators' proposal, accepted) rather than "Scope has n
    hosts"; `Format.count` gives `1 host` / `n hosts`.
16. `DecryptStatus` value over a bare `decryptAdvice: String?` (§D2). The banner carries no remedy
    text for any fact — states joined, one remedy button (core spec D9 alignment); the quoted
    Scope sentence keeps its period inside a composed line (verbatim beats typography).
    Alternative: strip the period in the composed form only.
17. The five #228 row fields ride on `FlowRow` (agreed Kit names; the improve-loop inspector and a
    possible column consume them) even though this spec renders none of them. Alternative: summary-only.

## Summary

One Kit value, `ConnectionSummary.routes`, derived inside `make` from a new public
`SystemProxyState?` input plus the facts the lanes already use, names the two automatic routes
into the proxy — the macOS system proxy (every proxy-aware app, regardless of Scope) and All
Apps (in-scope hosts of every app) — as open or closed with one line, one detail and one action
each, plus two facts that gate what the routes carry: Scope (per-host decryption, Matt's
2026-10-31 decision: `Nothing is decrypted until a host is in Scope.`, shown in the banner
when both routes are closed or every row is a tunnel) and CA trust. The Status page's Getting-started list (a new `systemProxy` step; the
`extensionOn`/`scopeSet` steps' words) and the Flows page's empty state and one-line banner read
`Session.trafficRoutes` and nothing else, so they cannot disagree; the banner shows only while
both routes are closed and flows exist, as one composed 40 pt line that is the only banner on
every list page (`ScopeBanner` and `AppsAttributionBanner` retire from them). `SystemProxyState`, `SystemProxyRoute` (`.off`,
`.thisCore`, `.other` — Proxyman's `127.0.0.1:9090` is the live `.other` case today) and the
system-proxy words are shared vocabulary for the sibling set-system-proxy work, which owns the
reserved `.setSystemProxy`/`.unsetSystemProxy`. The effective global proxy is read with
`CFNetworkCopySystemProxySettings()` once per existing poll tick in the app target. A third fact, `CATrustFacts` from the
keychain read-back `ca.status` (read every 10th poll tick), adds the step "Trust the aitmproxy CA"
and the line `HTTPS is not captured until the CA is trusted` to both surfaces and to the banner
whenever flows exist and HTTPS is untrusted — Matt's Mac today; its install side is the sibling's
(`.trustCA`, `.openCAPanel` reserved) and no proof ever runs `ca.install` on his Mac. Proof is Kit
unit tests (one `make` per predicate-table row), the three source tripwires and the real installed
app with the real system proxy flipped — no fixture or sample-data UI tests.

## Amendments after approval

- 2026-10-31 (coordinating session, agreed with the system-proxy session): `SystemProxyState(settings:)` accepts a Port given as a number or a numeric string; the "Network Settings…" menu item sits in a new Proxy-menu group right after the first divider (before Browser), with that session's "Set as System Proxy" toggle (⌥⌘P) to be added on the line above it. ⌥⌘P is unused by the app today (`grep keyboardShortcut("p"` finds nothing).
- 2026-10-31 (coordinating session, agreed with the NE and system-proxy-automation sessions): third fact **CA trust** added — `CATrustFacts` (`trusted`, `scope`, `fingerprint`, sibling-owned `installing`/`remedy`), `make(caTrust:)`, `TrafficRoute.Kind.caTrust`, step `caTrust` "Trust the aitmproxy CA" / `CA trusted (user keychain)`, line `HTTPS is not captured until the CA is trusted`, detail `… — browsers using QUIC load directly until then`, banner rule `bothClosed ∨ caClosed`, `ca.status` read every 10th tick; `.trustCA`/`.openCAPanel` reserved; **hard gate: no `ca.install` on Matt's Mac in any proof** (TR-AC15–17).
- 2026-10-31 (coordinating session, after the improve-loop measurement on `main 9dba3d9f`): D8 widened — one 40 pt banner line on every list page (Flows, Pinned, Domains, Apps), the route banner only; `ScopeBanner()` and `AppsAttributionBanner()` call sites removed from `MainView.flows` (structs kept), `check-capture-toggle.sh` NS-AC8 pins move to `RouteBanner()`; composed banner form (`TrafficRoute.state`/`remedy`; states joined ` · ` + the one remedy, priority system proxy > All Apps > CA) with the fresh-install literal `system proxy off · All Apps off · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`; Apps-page predicate stated; TR-AC18 (kit) and TR-AC19 (live header position) added; TR-AC3/13/16 literals updated.
- 2026-10-31 (coordinating session, Matt's per-host-decryption decision; strings confirmed by the improve-loop session for S-073/S-074/S-080): the Scope fact becomes its own `TrafficRoute` (`Kind.scope`, always present) with line `Nothing is decrypted until a host is in Scope.` / `Scope: N hosts decrypted` and detail `Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel`; All Apps is closed only when off/awaiting/degraded (open line `All Apps on`), so no clause repeats; `make(tunnelledFlowCount:)` from `FlowRow.tls == .tunnelled`; banner rule `routesClosed ∨ (scopeClosed ∧ (routesClosed ∨ allTunnels)) ∨ caClosed` with the fresh-install literal `system proxy off · All Apps off · Nothing is decrypted until a host is in Scope · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`; `scopeSet` keeps title/action, done form `Scope: N hosts decrypted`, detail = the scope line; "every host is read-only" retired; D2a lists the improve-loop session's adjacent tunnel-row strings; TR-AC3/4/5/16/18 literals updated, TR-AC20 (conditional on the core story) added; `check-connection-words.sh` prefixes gain `"Nothing is decrypted` and `"Scope:`.
- 2026-10-31 (coordinating session, agreed with the CA-trust session): `CATrustFacts.swift`, `CATrustFactsTests.swift` and the two additive `CAStatus` fields are implemented in the CA-trust session's PR (number TBD) to this spec's definitions; this spec remains the contract (TR-AC15 proved there). Our CA work (`make(caTrust:)`, `.caTrust` entry/step, `ca.status` read, rendering) is gated on that PR; system-proxy/All Apps/Scope parts are not (plan Tasks 1/2 split into 1/1b and 2/2b).

- 2026-10-31 (coordinating session, orchestrator registry update): the CA-trust session's mac PR D lands BEFORE this spec's PR and carries, as a narrow additive exception on `ConnectionSummary.swift`, `ConnectionAction.trustCA` and `.openCAPanel` with their titles and `GettingStartedStep.Kind.caTrusted` with its title — nothing else; `CATrustFacts` and the two `CAStatus` fields live in that PR too. This spec's step kind is therefore `.caTrusted` (not `.caTrust`; the route kind `TrafficRoute.Kind.caTrust` is unchanged), Task 1 must not redeclare those cases, and this branch rebases onto PR D's merged SHA before Task 1b/2b. Coding still starts on the fixture-removal SHA.
- 2026-11-01 (coordinating session, after PR #228 / v0.5.9): the Scope entry quotes `proxy.status.decrypt.advice` verbatim (`Nothing is decrypted until a host is in Scope.`) when present and falls back to our `… — add one` on an older core; `make(decrypt: DecryptStatus?)` (new Kit value decoded from `proxy.status`, which `BusService` already polls — no new read); N for `Scope: N hosts decrypted` = `decrypt.scope_hosts`; composed `state` strips one trailing `.`, remedy `add one`; Kit row decoder maps `tunnel` `passthrough`→`.tunnelled`, `failed`→`.pinnedOrFailed`, `decrypted`→`.decrypted` (plan Task 1c, own claim pending; `tunnel_reason`/bytes stay on the wire); TR-AC20 rewritten around curl passthrough/`--cacert` decrypted rows and unconditional once Task 1c is in; TR-AC21/22 added; start SHA `8175eea3`.
- 2026-11-01 (coordinating session, aligned with core spec D9 and the improve-loop session): banner text = shown states joined ` · ` with **no remedy text**; the remedy is one button `bannerAction` (`Open Network Settings…` / `All Apps Settings…` / `Add Host…` / `Trust the aitmproxy CA`); the Scope line is `proxy.status.decrypt.advice` verbatim (`Nothing is decrypted until a host is in Scope.`), fallback the same words, `— add one` retired; new `ConnectionAction.addScopeHost` ("Add Host…"); the Status step keeps `Open Scope…`. Task 1c widened to the full #228 contract: `TunnelMode`, `TunnelReason` (8), `tunnel`/`tunnelReason`/`tunnelBytesUp`/`tunnelBytesDown`/`passive` on `FlowSummary` and `FlowRow` (+ `isTunnel`, `==`), `FlowDetail.tunnel: TunnelInfo?` + `passive` from `meta`; TR-AC3/6/16/18/22 and D5/D10 literals updated.
