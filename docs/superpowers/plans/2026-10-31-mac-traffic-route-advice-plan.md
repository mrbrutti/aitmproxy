# macOS traffic-route advice — implementation plan

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode)
**Spec:** `docs/superpowers/specs/2026-10-31-mac-traffic-route-advice-design.md`
(approved 2026-10-31; acceptance criteria TR-AC1 … TR-AC19; TR-AC15–17 are the CA-trust fact, TR-AC18–19 the one-banner-line rule, both 2026-10-31 amendments)
**Branch / worktree:** this worktree, `claude/apps-attribution-8ab619`
(`/Users/matt/Security/aitmproxy/.claude/worktrees/apps-attribution-8ab619`), rebased on
`main 3fe92f6`. It ships as one PR to `main`.

## Gate: nothing below starts until both hold

1. **The fixture-removal mac PR is on `main` and this branch has rebased once onto its merge
   SHA** (the orchestrator sends it; record here: `__________`). That PR deletes the mac app's
   fixture, sample-data, snapshot, self-test and gallery modes. **This plan references none of
   them.** A Coder who meets `Store.usesFixtures`, `Fixtures.`, `SelfTest`, `SnapshotScenes` or
   `APP_FIXTURES` in a file it edits leaves it alone and reports it; it never adds one. After the
   rebase, the `ScopeBanner` condition in `MainView.flows` is whatever that PR left (today it reads
   `!Store.usesFixtures, session.scopeHosts.isEmpty, case .connected = session.bus`; Task 3 removes
   that branch whatever its post-removal form, spec D8).
2. **The orchestrator's file claim is granted** for: `AitmproxyKit/ConnectionSummary.swift`;
   `Shell/ShellView.swift` — `EmptyFlows`, the one banner insertion in `MainView.flows` and the removal
   of the `ScopeBanner()` / `AppsAttributionBanner()` call sites there (spec D8) only,
   lines 49–62 (palette overlay) and the palette transition untouched; `Tests/AitmproxyKitTests/**`;
   `tools/check-connection-words.sh`; the Status page's Getting-started steps (`Panels/StatusPanel.swift`)
   where wording moves; the new `Bus/SystemProxyReader.swift`; the `Session.trafficRoutes` accessor
   (`Session+Connection.swift`). Spec §D7 additionally names `Session.swift` (two stored properties: `systemProxy`, `caStatus`),
   `Bus/BusService.swift` (two system-proxy call sites + `refreshCAStatus()` + one reset),
   `AitmproxyKit/CATrustFacts.swift` (new) and `Tests/AitmproxyKitTests/CATrustFactsTests.swift` (new), `Shell/RouteBanner.swift` (new), `App.swift`
   (one menu item), `AitmproxyKit/CommandMap.swift` (one entry), `apps/mac/docs/BRIEF.md` (one
   token — `CommandMapTests.mapMatchesTheBrief` compares the map against the brief, so the entry
   cannot land without it), `apps/mac/docs/GLOSSARY.md` and `apps/mac/docs/STORIES.md`. **The
   orchestrator confirms these before Wave B** (question Q1 below). `Bus/BusService.swift` and
   `Session.swift` are also modified by the sibling icons plan on this same branch
   (`2026-10-31-mac-app-icons-and-names-plan.md` Tasks 5/6): Task 2 here and those tasks are
   **never run concurrently**; whichever lands second rebases onto the first.

Before Wave A the orchestrator runs the baseline gate once on the rebased tree (Swift gate below
plus the three tripwires) so every later failure is attributable to this plan.

## Environment adaptation (every Coder reads this)

- **The Claude Bash sandbox cannot run SwiftPM** (EPERM on the module cache and `/var/folders`;
  memory `sandbox-swift-and-git-switch-quirks`). A Coder writes the test first, then the code, and
  runs only sandbox-safe checks (`swiftc -parse -module-cache-path "$TMPDIR/mc" <files>` for syntax;
  a sandbox-caused failure is not a code failure and is reported as such). The Coder's report says,
  in these words, **"sandbox: cannot run swift test — handing the gate to the orchestrating
  session"**, and lists the exact tests it expects to go red-then-green and the literal values
  they pin.
- **The Swift gate** is run by the orchestrating session in the Terminal panel:

  ```
  swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build-routes
  ```

  redirected to a log under `/tmp/claude/` and judged by its exit code, never a grep pipeline
  (memory `gate-exit-status-not-grep`). The orchestrator runs it after each wave, commits the
  wave's tasks once green, and quotes the output in the Tester hand-off.
- **Tripwires** (TR-AC7), Terminal: `apps/mac/tools/check-capture-operator-only.sh`,
  `apps/mac/tools/check-capture-toggle.sh`, `apps/mac/tools/check-connection-words.sh` — each
  prints PASS. The structural greps of TR-AC8 run in the sandbox.
- **Rust gate** (TR-AC9): no Rust file changes; `cargo fmt --check && cargo clippy --all-targets
  -- -D warnings && cargo test` runs once on the whole branch to prove it.
- **Building the real app** (Task 6 only): Terminal only. The dev bundle is `apps/mac/build.sh
  --debug` into `~/Applications` (CLAUDE.md); the installed build is the notarized DMG
  (`apps/mac/build.sh --ne --allow-unnotarized --replace` → `scripts/notarize-dmg.sh`,
  `docs/RELEASE.md` step 3; memory `aitmproxy-release-pipeline`). Never `pkill -f obscura` or
  `pkill -f aitm` globally (memory `aitmproxy-obscura-multisession-hazards`).
- **Evidence rule.** Proof is (K) Kit unit tests that build their own literal values, (T) the three
  tripwires, (L) the real app with the real system proxy flipped and real requests. No seeded
  store, sample rows, snapshot, gallery or in-app self-check is evidence for anything here.
- **Hard gate — no `ca.install` on Matt's Mac.** Trusting the aitm CA on his machine is Matt's
  decision and he has not given it. No Coder, Tester, script or orchestrating session calls
  `ca.install` (or clicks Install… on the CA page) on his Mac. Task 6 proves only the NOT-trusted
  state and its line, plus `ca.status` over the bus showing `trusted: "no"`. The install →
  line-disappears path is proved only after Matt says in his own words that the CA may be
  trusted, and then only through the app's own Status step (the sibling's `.trustCA` with its
  admin prompt), never a direct verb call from a script. `Panels/CAPanel.swift` and
  `AitmproxyKit/Panels/CAStatus.swift` join the do-not-touch list.
- **Do-not-touch:** `apps/mac/Sources/AitmproxyKit/CaptureAdvice.swift`, `CaptureCapability.swift`,
  `apps/mac/Package.swift`, `apps/mac/Sources/Aitmproxy/UI/Tokens.swift` (generated),
  `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`, `Panels/ScopePanel.swift`
  (`ScopeBanner`'s text), anything under `apps/mac/Extension/` or `crates/`. In
  `Shell/ShellView.swift`: lines 49–62, the `ExtensionController(` block (~102–103) and everything
  outside the two named hunks. A Coder whose task seems to need one of these **stops and reports**.
- **Stop-and-report rule.** A Coder that finds the spec wrong (a D-section that cannot be built as
  written, a signature that will not typecheck under strict concurrency) stops and reports; it does
  not redesign. One known seam is pre-decided in the plan calls (StatusPanel's exhaustive switch,
  call 1).

## Overview

Six tasks in five waves. Wave A is pure Kit (one task: the value types, the `make` extension and
the whole predicate table as tests, the CA-trust fact included). Wave B wires the app target to the Kit value (reader, poll
tick, `Session.systemProxy`, `Session.trafficRoutes`, `perform(.openNetworkSettings)`). Wave C has
two file-disjoint UI tasks: the two surfaces (Status steps' help + Flows empty state + the route
banner) and the menu/command-map/docs. Wave D updates the words tripwire, which can only pass once
`trafficRoutes` and `RouteBanner.swift` exist. Wave E is the real-app proof plus the whole-branch
Tester and panel.

| Wave | Tasks | Parallel? |
|---|---|---|
| A | Task 1 | — |
| B | Task 2 (after 1) | — ; not concurrent with the icons plan's Tasks 5/6 (shared `BusService.swift`, `Session.swift`) |
| C | Task 3 ∥ Task 4 (both after 2) | yes, file-disjoint |
| D | Task 5 (after 3) | — (may run beside Task 4 if Task 3 landed first) |
| E | Task 6, then whole-branch Tester and the three reviewers | sequential |

Evidence classes: **K** Tasks 1, 4 (CommandMap); **T** Task 5 (run), Task 6 (whole branch);
**L** Task 6. Tasks 2 and 3 have no Kit test by construction (CFNetwork, SwiftUI); their proof is
the TR-AC8 structural greps, Task 6, and the diff review.

---

## Tasks

### Task 1: Kit model — `SystemProxyState`, `TrafficRoutes`, `make(systemProxy:)`, the predicate table

- **Satisfies:** TR-AC1, TR-AC2, TR-AC3, TR-AC4, TR-AC5, TR-AC6 (all but the `CommandMap` clause), TR-AC15, TR-AC16, TR-AC18
- **Depends on:** none
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/SystemProxyState.swift` (create)
  - `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify)
  - `apps/mac/Tests/AitmproxyKitTests/SystemProxyStateTests.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (modify)
  - `apps/mac/Sources/AitmproxyKit/CATrustFacts.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/CATrustFactsTests.swift` (create)
- **Change:** exactly spec D2/D2a/D3/D4/D5 (CA amendment included), Foundation only (no CFNetwork, SystemConfiguration,
  SwiftUI, AppKit import anywhere in the Kit).

  `SystemProxyState.swift`:

  ```swift
  public struct SystemProxyState: Hashable, Sendable {
      public struct Endpoint: Hashable, Sendable {
          public var host: String
          public var port: Int
          public var address: String { "\(host):\(port)" }      // computed (plan call 3)
          public init(host: String, port: Int)
      }
      public var http: Endpoint?
      public var https: Endpoint?
      public init(http: Endpoint?, https: Endpoint?)
      public init(settings: [String: Any])
      public static let off = SystemProxyState(http: nil, https: nil)
      public func route(to listenAddress: String) -> SystemProxyRoute
  }

  public enum SystemProxyRoute: Hashable, Sendable {
      case off
      case thisCore(http: Bool, https: Bool)
      case other(host: String, port: Int)
  }
  ```

  `init(settings:)` rules: a protocol's endpoint is non-nil iff its `*Enable` value is a number
  (`NSNumber`/`Bool`) that is non-zero **and** `*Proxy` is a non-empty `String` **and** `*Port`
  is a number; otherwise nil (absent Enable, `0`, or an enabled flag with no host/port all read as
  nil — honest, never invented). Keys are the literal strings `"HTTPEnable"`, `"HTTPProxy"`,
  `"HTTPPort"`, `"HTTPSEnable"`, `"HTTPSProxy"`, `"HTTPSPort"`.

  `route(to:)` rules: split `listenAddress` at its last `:` into host and port (strip `[`/`]`
  around an IPv6 host; an unparseable address compares as no match). Two hosts match when equal
  after lower-casing, or both are loopback (`127.0.0.1`, `localhost`, `::1`; the builder may widen
  to `127.0.0.0/8`), or the listen host is a wildcard (`0.0.0.0`, `::`) and the proxy host is
  loopback. Ports must be equal. Result: no endpoint enabled → `.off`; at least one endpoint
  matches → `.thisCore(http: <http matches>, https: <https matches>)`; else `.other(host:port:)`
  from the first enabled endpoint, HTTP then HTTPS.

  `ConnectionSummary.swift`:

  ```swift
  public enum ConnectionAction: Hashable, Sendable, CaseIterable {   // CaseIterable added (plan call 2)
      …existing 16 cases…, case openNetworkSettings                 // title "Open Network Settings…"
      // RESERVED for the set-system-proxy session, not added here: setSystemProxy, unsetSystemProxy
      public var settingsURL: URL?   // openNetworkSettings → x-apple.systempreferences:com.apple.Network-Settings.extension
                                     // approveInSystemSettings → x-apple.systempreferences:com.apple.LoginItems-Settings.extension
                                     // every other case → nil
  }

  public struct TrafficRoute: Hashable, Sendable {
      public enum Kind: String, Hashable, Sendable, CaseIterable { case systemProxy, allApps, caTrust }
      public let kind: Kind
      public let open: Bool
      public let line: String
      public let detail: String
      public let actions: [ConnectionAction]
      public var state: String      // line before its first " — " (whole line when none)
      public var remedy: String?    // line after its first " — ", nil when none
      public init(kind: Kind, open: Bool, line: String, detail: String, actions: [ConnectionAction])
  }

  public struct TrafficRoutes: Hashable, Sendable {
      public let systemProxy: TrafficRoute?
      public let allApps: TrafficRoute?
      public let caTrust: TrafficRoute?                                // nil = ca.status unread/unknown
      public let advice: [TrafficRoute]
      public let banner: String?
      public var anyOpen: Bool { [systemProxy, allApps].compactMap { $0 }.contains(where: \.open) }   // routes only
      public init(systemProxy: TrafficRoute?, allApps: TrafficRoute?, caTrust: TrafficRoute?, advice: [TrafficRoute], banner: String?)
  }

  public struct GettingStartedStep {
      public enum Kind: String, …, CaseIterable { case coreRunning, busConnected, systemProxy, extensionOn, scopeSet, caTrust, firstFlow }
      public let detail: String?                                      // NEW
      public init(kind: Kind, title: String, done: Bool, action: ConnectionAction? = nil, detail: String? = nil)
  }

  public struct ConnectionSummary {
      public let routes: TrafficRoutes                                // NEW stored field
      public static func make(core:activeKind:bus:role:roleWarning:capability:captureSupported:
                              scopeHostCount:flowCount:listenAddress:coreCapture: = nil,
                              systemProxy: SystemProxyState? = nil,
                              caTrust: CATrustFacts? = nil) -> ConnectionSummary
  }
  ```

  `CATrustFacts.swift` (spec D2, shared with the system-proxy-automation session; Foundation only):

  ```swift
  public struct CATrustFacts: Hashable, Sendable {
      public var trusted: Bool
      public var scope: String?        // "user" | "system" store that reports trusted == "yes"
      public var fingerprint: String?
      public var installing: Bool = false   // sibling-sourced; this spec passes false
      public var remedy: String? = nil      // sibling-sourced; this spec passes nil
      public init(trusted: Bool, scope: String?, fingerprint: String?, installing: Bool = false, remedy: String? = nil)
      public init?(status: CAStatus)   // plan call 10: failable — nil when no store reports "yes" or "no"
  }
  ```

  `init?(status:)` cannot read store labels from today's `CAStatus` (it keeps only `trusted: Bool`),
  so `CAStatus` gains two **additive** stored fields in the same commit, decoded in `init?(json:)` and
  defaulted in the memberwise init: `trustedScope: String?` (the first store key whose `trusted` is
  `"yes"`, `"user"` before `"system"`) and `trustReported: Bool` (any store's `trusted` is `"yes"` or
  `"no"`). `CATrustFacts(status:)` = nil when `!trustReported`; else `trusted = status.trusted`,
  `scope = status.trustedScope`, `fingerprint = status.fingerprint.isEmpty ? nil : status.fingerprint`.
  Nothing else in `CAStatus.swift` changes (`statusText`, `confirmPrompt`, `guides` untouched) and
  `CAPanel.swift` is not touched. **Claim:** `AitmproxyKit/Panels/CAStatus.swift` for these two
  fields only (orchestrator, Q1).

  CA fact in `make` (spec D3/D4/D5): `routes.caTrust` nil when `caTrust == nil`; else `kind: .caTrust`,
  `open = trusted`, `line` = `"CA trusted (user keychain)"` / `"CA trusted (system keychain)"` /
  `"CA trusted"` (scope nil) when trusted, `"trusting CA…"` when `installing`, the `remedy` text when
  set, else `"HTTPS is not captured until the CA is trusted"`; `detail` = `"HTTPS on both routes"`
  when trusted, else `"HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`;
  `actions = []` always (`.trustCA`/`.openCAPanel` are reserved). `advice` = `[systemProxy, allApps, caTrust]`
  closed entries in that order (bus `.ok`). Banner: `bothClosed ∨ caClosed` per spec D5; `shown` =
  the closed routes (when `bothClosed`) then the CA entry (when `caClosed`); text =
  `shown.map(\.state).joined(" · ")` + `" — " + <first non-nil remedy in shown>` (none for CA) —
  the composed form; a single shown entry yields exactly its `line`. Step `caTrust`
  after `scopeSet`, omitted when `routes.caTrust == nil`; `title` = `"Trust the aitmproxy CA"` when
  not done, the route line when done; `detail` = the route detail; `action = nil`.

  Inside `make`: compute `routes` (private `routes(systemProxy:advice:activeKind:bus:scopeHostCount:flowCount:listenAddress:)`)
  **before** `steps`, and pass `routes` into `steps`. Route derivation and words are spec D3,
  verbatim — the system-proxy lines use `L` = `listenAddress` and `H:P` = the `.other` endpoint;
  the All Apps `.on` line is `"All Apps on · " + Format.count(n, "host") + " in scope"`;
  `advice` = the closed non-nil routes, system proxy first, **only when the bus lane's `state == .ok`**,
  else `[]`; `banner` = spec D5's predicate, the closed routes' lines joined with `" · "`.
  Steps are spec D4: `systemProxy` step omitted while `routes.systemProxy == nil`, otherwise
  `title = line`, `detail = detail`, `done = open`, `action = .openNetworkSettings` when closed;
  `extensionOn` titles become the All Apps route line for `.off`/`.awaitingApproval`/`.degraded`
  (actions unchanged: `.turnCaptureOn`/`.approveInSystemSettings`/`.openCaptureSettings`) and
  `"All Apps is on"` for `.onEmptyScope`/`.on` (detail `"in-scope hosts of every app"`);
  `scopeSet` for `.onEmptyScope` is `"All Apps on, nothing in scope — add a host"` with detail
  `"in-scope hosts of every app"`, otherwise unchanged with `detail nil`.

  **Existing tests this changes** (update them in the same commit; they are the spec's new words):
  in `gettingStartedStepsFollowTheFacts`, `fresh.steps[2].title` becomes
  `"All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`
  and `waiting.steps[2].title` becomes
  `"All Apps waiting for approval — approve the extension in System Settings"`. The five-element
  `done` arrays stay (no `systemProxy:` → five steps).

- **Test:** the private `make(...)` helper in `ConnectionSummaryTests` gains `systemProxy: SystemProxyState? = nil`;
  add a helper `both(_ host: String, _ port: Int) -> SystemProxyState` (HTTP and HTTPS at that
  endpoint). `L = "127.0.0.1:8080"`.

  `SystemProxyStateTests.swift`:
  - `parsesTheProxiesDictionary` (TR-AC1): `SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 9090, "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": 9090])`
    → `http == Endpoint(host: "127.0.0.1", port: 9090)`, `https == http`, `http?.address == "127.0.0.1:9090"`;
    `["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080, "HTTPSEnable": 0]` → `https == nil`, `http?.port == 8080`;
    `["HTTPEnable": 0, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080]` → `http == nil`;
    `["HTTPProxy": "127.0.0.1", "HTTPPort": 8080]` (Enable absent) → `http == nil`;
    `SystemProxyState(settings: [:]) == .off`.
  - `routeToTheCore` (TR-AC2), every literal: `.off.route(to: L) == .off`;
    `both("127.0.0.1", 8080)` → `.thisCore(http: true, https: true)`; `both("localhost", 8080)` → the same;
    `SystemProxyState(http: Endpoint(host: "127.0.0.1", port: 8080), https: nil)` → `.thisCore(http: true, https: false)`;
    `both("127.0.0.1", 9090)` → `.other(host: "127.0.0.1", port: 9090)`;
    `http 10.0.0.1:3128, https 127.0.0.1:8080` → `.thisCore(http: false, https: true)`;
    `http nil, https 10.0.0.1:3128` → `.other(host: "10.0.0.1", port: 3128)`;
    `both("127.0.0.1", 8080).route(to: "0.0.0.0:8080") == .thisCore(http: true, https: true)`;
    `both("127.0.0.1", 8081).route(to: L) == .other(host: "127.0.0.1", port: 8081)`.

  `ConnectionSummaryTests.swift` additions:
  - `routesAdviceAndBanner` (TR-AC3): `make(bus: .connected("127.0.0.1:60745"), role: "operator", capability: .capturing, hosts: 0, flows: 0, systemProxy: .off).routes`:
    `advice.map(\.line) == ["system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it", "All Apps on, nothing in scope — add a host"]`,
    `advice.map(\.detail) == ["every proxy-aware app, regardless of Scope", "in-scope hosts of every app"]`,
    `advice[0].actions == [.openNetworkSettings, .copyListenAddress]`, `advice[1].actions == [.openScope]`,
    `banner == nil`, `anyOpen == false`. Same with `flows: 6` → `advice == []`,
    `banner == "system proxy off · All Apps on, nothing in scope — set 127.0.0.1:8080 as the system proxy, or point a client at it"`.
    Same with `systemProxy: both("127.0.0.1", 9090), flows: 0` →
    `advice[0].line == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`
    and `advice.allSatisfy { !$0.line.contains("off") }`.
  - `predicateTable` (TR-AC4), one `make` per row, bus `.connected("x")`/`role: "operator"` unless stated:
    `.inactive, systemProxy: .off` → `routes.allApps?.line == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`, `actions == [.openCaptureSettings]`, `open == false`;
    `.pendingApproval` → `"All Apps waiting for approval — approve the extension in System Settings"`, `[.approveInSystemSettings]`;
    `.degraded("x")` → `"All Apps degraded — x"`, `[.openCaptureSettings]`;
    `.capturing, hosts: 1` → `"All Apps on · 1 host in scope"`, `open == true`, `actions == []`;
    `systemProxy: SystemProxyState(http: Endpoint(host: "127.0.0.1", port: 8080), https: nil)` → `routes.systemProxy?.line == "system proxy on · 127.0.0.1:8080 · HTTP only"`, `open == true`, `actions == []`;
    `https`-only at the core → `"system proxy on · 127.0.0.1:8080 · HTTPS only"`;
    `both("127.0.0.1", 8080)` → `"system proxy on · 127.0.0.1:8080"`;
    `systemProxy: nil, .capturing, hosts: 0` → `routes.systemProxy == nil`, `advice.map(\.line) == ["All Apps on, nothing in scope — add a host"]`;
    `supported: false, systemProxy: .off, flows: 3` → `routes.allApps == nil`, `banner == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    `supported: false, systemProxy: .off, flows: 0` → `advice.map(\.kind) == [.systemProxy]`;
    `systemProxy: .off, .capturing, hosts: 2, flows: 3` → `banner == nil`, `anyOpen == true`;
    `both("127.0.0.1", 9090), .capturing, hosts: 2, flows: 3` → `banner == nil`;
    `both("127.0.0.1", 8080), .capturing, hosts: 0, flows: 3` → `banner == nil`, `advice.map(\.kind) == [.allApps]`;
    `bus: .disconnected, systemProxy: .off, .capturing, hosts: 0` → `advice == []`, `banner == nil`;
    `bus: .connected("x"), role: "agent", roleWarning: true, systemProxy: .off` → `advice == []` (lane not `.ok`);
    `kind: .external, bus: .connected("x"), role: "operator", .capturing, hosts: 2, systemProxy: .off` → `routes.allApps == nil`, `advice.map(\.kind) == [.systemProxy]`;
    `systemProxy: .off, .inactive, flows: 3` → `banner == "system proxy off · All Apps off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`.
  - `stepsCarryTheRouteWords` (TR-AC5): `systemProxy: nil` → `steps.map(\.kind)` contains no `.systemProxy`;
    `systemProxy: .off` → `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow]`,
    `steps[2].done == false`, `steps[2].title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`,
    `steps[2].detail == "every proxy-aware app, regardless of Scope"`, `steps[2].action == .openNetworkSettings`;
    `both("127.0.0.1", 9090)` → `steps[2].title == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`, `done == false`;
    `both("127.0.0.1", 8080)` with `core(.ready), .capturing, hosts: 2, flows: 1` → `steps[2].title == "system proxy on · 127.0.0.1:8080"`, `done == true`, `action == nil`, `allStepsDone == true`;
    `.capturing, hosts: 0` → `extensionOn.title == "All Apps is on"`, `done == true`, `detail == "in-scope hosts of every app"`, `scopeSet.title == "All Apps on, nothing in scope — add a host"`, `scopeSet.action == .openScope`, `scopeSet.detail == "in-scope hosts of every app"`;
    `.inactive` → `extensionOn.title == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`, `action == .turnCaptureOn`;
    `.pendingApproval` → the waiting line, `action == .approveInSystemSettings`;
    `.degraded("x")` → `extensionOn.title == "All Apps degraded — x"`, `action == .openCaptureSettings`;
    `.capturing, hosts: 2` → `scopeSet.title == "Scope has 2 hosts"`, `scopeSet.detail == nil`;
    `coreRunning`, `busConnected`, `firstFlow` → `detail == nil`.
  - `openNetworkSettingsAction` (TR-AC6 Kit part): `ConnectionAction.openNetworkSettings.title == "Open Network Settings…"`,
    `isDestructive == false`, `settingsURL?.absoluteString == "x-apple.systempreferences:com.apple.Network-Settings.extension"`,
    `ConnectionAction.approveInSystemSettings.settingsURL?.absoluteString == "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"`,
    `ConnectionAction.allCases.filter { $0.settingsURL != nil } == [.approveInSystemSettings, .openNetworkSettings]`,
    `ConnectionAction.allCases == [.startCore, .restartCore, .showCoreLog, .switchToEmbedded, .reconnectBus, .openBusSettings, .turnCaptureOn, .turnCaptureOff, .openScope, .approveInSystemSettings, .uninstallExtension, .openCaptureSettings, .openBrowser, .copyListenAddress, .openNetworkSettings]`
    (the reserved `setSystemProxy`/`unsetSystemProxy` are absent by construction of this literal list).

  `CATrustFactsTests.swift` (TR-AC15), inputs built with `CAStatus(json:)` over literal `JSONValue`
  objects (`"exists": true`, `"fingerprint_sha256": "AB:CD"`, `"stores": {...}`):
  - user `"yes"` → `CATrustFacts(status:)?.trusted == true`, `scope == "user"`, `fingerprint == "AB:CD"`, `installing == false`, `remedy == nil`;
  - user `"no"`, system `"no"` → `trusted == false`, `scope == nil`;
  - user `"unknown"` only → `nil`; `"exists": true` with no `stores` → `nil`;
  - system `"yes"`, user `"no"` → `trusted == true`, `scope == "system"`;
  - `CAStatus.trusted` unchanged in meaning: `trusted == (CATrustFacts(status:)?.trusted ?? false)` on every input above.

  `ConnectionSummaryTests` additions for the CA fact (TR-AC16), `notTrusted = CATrustFacts(trusted: false, scope: nil, fingerprint: "AB:CD")`,
  `trustedUser = CATrustFacts(trusted: true, scope: "user", fingerprint: "AB:CD")`:
  - `caTrustJoinsAdviceAndSteps`: TR-AC3 inputs + `caTrust: notTrusted` → `routes.caTrust?.line == "HTTPS is not captured until the CA is trusted"`,
    `routes.caTrust?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`,
    `routes.caTrust?.actions == []`, `advice.map(\.kind) == [.systemProxy, .allApps, .caTrust]`, `anyOpen == false`,
    `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrust, .firstFlow]`,
    `steps[5].title == "Trust the aitmproxy CA"`, `steps[5].done == false`, `steps[5].action == nil`, `steps[5].detail == <the detail string>`;
  - `caTrustBanner`: same + `flows: 6` → `banner == "system proxy off · All Apps on, nothing in scope · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: notTrusted` → `banner == "HTTPS is not captured until the CA is trusted"`, `anyOpen == true`;
    `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: trustedUser` → `banner == nil`;
    `systemProxy: .off, .capturing, hosts: 0, flows: 3, caTrust: trustedUser` → the TR-AC3 two-line banner with no CA clause;
  - `caTrusted`: `caTrust: trustedUser` → `routes.caTrust?.line == "CA trusted (user keychain)"`, `open == true`, `detail == "HTTPS on both routes"`, `steps` contain `.caTrust` with `title == "CA trusted (user keychain)"`, `done == true`;
    `scope: "system"` → `"CA trusted (system keychain)"`; `scope: nil, trusted: true` → `"CA trusted"`;
    `allStepsDone == true` with `core(.ready)`, `both("127.0.0.1", 8080)`, `.capturing, hosts: 2, flows: 1, caTrust: trustedUser`;
  - `caUnknownSaysNothing`: `caTrust: nil` → `routes.caTrust == nil`, no `.caTrust` step, `advice`/`banner` carry no `"CA"` and no `"HTTPS"`;
  - `caSiblingStates`: `CATrustFacts(trusted: false, scope: nil, fingerprint: nil, installing: true)` → `line == "trusting CA…"`, `open == false`;
    `remedy: "CA trust needs an administrator"` → `line == "CA trust needs an administrator"`, `open == false`.
  - `composedBanner` (TR-AC18): `routes.systemProxy?.state == "system proxy off"`, `routes.systemProxy?.remedy == "set 127.0.0.1:8080 as the system proxy, or point a client at it"` (`.off` input);
    `routes.caTrust?.remedy == nil` and `state == line` (`notTrusted`); `.capturing, hosts: 2` → `routes.allApps?.remedy == nil`;
    `.inactive, hosts: 0, flows: 3, systemProxy: .off, caTrust: notTrusted` → `banner == "system proxy off · All Apps off · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    `.capturing, hosts: 0, flows: 3, systemProxy: .off, caTrust: notTrusted` → `banner == "system proxy off · All Apps on, nothing in scope · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    `.capturing, hosts: 0, flows: 3, systemProxy: .off` → `banner == "system proxy off · All Apps on, nothing in scope — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    `.inactive, flows: 3, systemProxy: .off` → `banner == "system proxy off · All Apps off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`;
    single-fact cases: `banner == routes.<fact>?.line` for `supported: false, .off, flows: 3` and for `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: notTrusted`.
- **Done when:** the new tests and the two updated expectations pass, every other existing
  `AitmproxyKitTests` suite still passes, and the Swift gate is green (Terminal, orchestrator).
  Sandbox evidence: `swiftc -parse` clean on the four files; the report lists the literal values above.

### Task 2: App reader, poll-tick wiring, `Session.systemProxy`, `Session.trafficRoutes`, `perform(.openNetworkSettings)`

- **Satisfies:** TR-AC8 (CFNetwork single file; Kit import rule), the model half of TR-AC10–13
  (the fact reaches the views within one poll)
- **Depends on:** Task 1
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Bus/SystemProxyReader.swift` (create)
  - `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify: two call sites + one reset)
  - `apps/mac/Sources/Aitmproxy/Session.swift` (modify: two stored properties)
  - `apps/mac/Sources/Aitmproxy/Session+Connection.swift` (modify)
- **Change:**

  ```swift
  // Bus/SystemProxyReader.swift — the ONLY file in Sources that names CFNetworkCopySystemProxySettings
  import CFNetwork
  import AitmproxyKit
  enum SystemProxyReader {
      /// The effective global HTTP/HTTPS proxy settings, bridged into the Kit value; nil when
      /// CFNetwork returns nothing (plan call 4: nil, not .off — keeps the step hidden).
      static func read() -> SystemProxyState?
  }
  ```

  `Session.swift`: `var systemProxy: SystemProxyState?` and `var caStatus: CAStatus?` (both observed,
  nil at init; doc comment "nil until the first live read; reset to nil when the live connection ends").

  `BusService.swift`: `private func refreshSystemProxy()` — `let state = SystemProxyReader.read();
  if state != session.systemProxy { session.systemProxy = state }`. Called (1) once right after
  `await refreshScope()` in the connect path (before `pollLoop`), (2) in `pollLoop` right after
  `await refreshProxyStatus()`. The `pollLoop` `defer` additionally sets `session.systemProxy = nil`
  beside the throughput reset (plan call 5: a session with no live bus says nothing about the
  system proxy). No new timer; no read outside these three lines.

  `BusService.swift`, CA: `private func refreshCAStatus()` — `guard let client, let json = try? await client.call("ca.status"),
  let parsed = CAStatus(json: json) else { return }; if parsed != session.caStatus { session.caStatus = parsed }`.
  Called (1) once after the connect-path `refreshSystemProxy()`, (2) in `pollLoop` every 10th
  iteration (a `tick` counter local to `pollLoop`, `tick % 10 == 0`, reset per connection; plan
  call 9 — `ca.status` spawns `/usr/bin/security` per store on macOS). The `pollLoop` `defer` also
  sets `session.caStatus = nil`. The same existing verb the CA page calls; no new verb, no change to
  `CAPanel.swift`.

  `Session+Connection.swift`: `connectionSummary` passes `systemProxy: systemProxy` and
  `caTrust: caStatus.flatMap(CATrustFacts.init)`;
  new accessor, the only one of its name in the app target:

  ```swift
  /// The two automatic routes into the proxy (spec D7): what the Flows surfaces read, so no lane
  /// word reaches ShellView and the connectionSummary reader allow-list does not grow.
  var trafficRoutes: TrafficRoutes { connectionSummary.routes }
  ```

  `perform(connection:)`: `case .approveInSystemSettings, .openNetworkSettings:` opens
  `action.settingsURL` with `NSWorkspace.shared.open` (the literal LoginItems URL string moves out
  of this file into the Kit table) and returns `true`.

- **Test:** none in Kit by construction. Sandbox structural checks the Coder runs and quotes:
  `grep -rln CFNetworkCopySystemProxySettings apps/mac/Sources` → exactly
  `apps/mac/Sources/Aitmproxy/Bus/SystemProxyReader.swift`;
  `grep -rlE '^import (CFNetwork|SystemConfiguration|SwiftUI|AppKit)' apps/mac/Sources/AitmproxyKit` → empty;
  `grep -rn 'var trafficRoutes' apps/mac/Sources/Aitmproxy` → one line, in `Session+Connection.swift`,
  containing `connectionSummary.routes`; `grep -c 'refreshSystemProxy()' apps/mac/Sources/Aitmproxy/Bus/BusService.swift`
  → `3` (definition + two calls); `grep -c 'refreshCAStatus()' apps/mac/Sources/Aitmproxy/Bus/BusService.swift`
  → `3`; `grep -rln '"ca.status"' apps/mac/Sources` → exactly `Bus/BusService.swift` and
  `Panels/CAPanel.swift`; `grep -rn 'ca.install' apps/mac/Sources/Aitmproxy/Bus apps/mac/Sources/Aitmproxy/Session*.swift`
  → empty; `git diff -- apps/mac/Package.swift` → empty. Live proof is Task 6.
- **Done when:** the greps print the values above, the app target compiles (`swift build` in the
  Swift gate run), and the Swift gate is green.

### Task 3: The two surfaces — Status step help, Flows empty-state route rows, `RouteBanner`

- **Satisfies:** the view half of TR-AC10, TR-AC11, TR-AC12, TR-AC13, TR-AC14, TR-AC17, TR-AC19 (Flows/Status
  buttons, help, the CA row without a button, the one-banner-line rule), TR-AC8 (ShellView/StatusPanel diff footprint)
- **Depends on:** Task 2
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Shell/RouteBanner.swift` (create)
  - `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify — two hunks only)
  - `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (modify — two lines)
- **Change:**

  `StatusPanel.swift`: in `StepRow.body`, add `.help(step.detail ?? step.title)` to the row
  (one line). In `run(_:)`, add `.openNetworkSettings` to the already-handled case list at
  `case .showCoreLog, .reconnectBus, .openScope, .openBrowser, .copyListenAddress, .approveInSystemSettings:`
  (exhaustive switch over the enum; plan call 1). Nothing else in the file.

  `Shell/RouteBanner.swift`:

  ```swift
  /// One line above the Flows table while BOTH routes are closed and flows exist (spec D5).
  struct RouteBanner: View {
      @Environment(Session.self) private var session
      @Environment(\.openSettings) private var openSettings
      var body: some View   // reads session.trafficRoutes only
  }
  ```

  Renders `session.trafficRoutes.banner` (`lineLimit(1)`, `truncationMode(.tail)`,
  `Tok.Size.Row.dense` height, `Tok.Ink.tertiary` ink, `Space.md` horizontal padding, a `Rule`
  under it from the caller — the `ScopeBanner`/`AppsAttributionBanner` shape), `.help` = the closed
  routes' `detail`s joined with `" · "`, and one `SmallButton(action.title)` per closed route's
  **first** action (at most two): `session.perform(connection: action)`; when it returns `false`
  and the action is `.openCaptureSettings`, set `session.settingsTab = .capture` and call
  `openSettings()` exactly as `AppsAttributionBanner` does. Glyph `"network"`. The file mentions
  none of `connectionSummary`, `ConnectionSummary`, `LaneDot`, `LaneState`, `CaptureSwitch`,
  `capture.enabled`, `extensionController`, `CaptureAdvice`.

  `ShellView.swift` hunk 1 — `MainView.flows` (spec D8): remove two call sites — the
  `ScopeBanner()` branch (`} else if <scope-empty ∧ bus connected, as the rebased tree has it> {
  ScopeBanner(); Rule() }`) and the Apps block (`if session.page == .apps, session.clients.isEmpty,
  !session.rows.isEmpty { AppsAttributionBanner(); Rule() }`) — and insert, where the Apps block
  was (above `if session.splitView {`):

  ```
  if session.trafficRoutes.banner != nil {
      RouteBanner()
      Rule()
  }
  ```

  No page condition: the route banner is the only banner on Flows, Pinned, Domains and Apps, and
  with nothing closed no banner renders. The `ScopeBanner` struct (`Panels/ScopePanel.swift`) and
  the `AppsAttributionBanner` struct (this file) stay, unreferenced from `MainView`; `AppsEmptyState()`
  and its condition are untouched.

  `ShellView.swift` hunk 2 — `EmptyFlows`: gains `var routes: [TrafficRoute]` (passed from the
  `flowTable` overlay call as `routes: session.trafficRoutes.advice`; plan call 6 — a parameter,
  not the environment, so the struct stays a pure function of its inputs). Unfiltered and
  `routes` non-empty: under "No flows yet", one row per route — glyph (`"network"` for
  `.systemProxy`, `"app.badge"` for `.allApps`, `Tok.Glyph.lock` for `.caTrust`), `Text(route.line)`,
  its actions as `SmallButton`s (every action in `route.actions`, so the system-proxy row offers
  Open Network Settings… and Copy Address, the All Apps row its one, the CA row none — `.trustCA`
  is reserved for the sibling; the row is informational until it lands), and `Text(route.detail)` beneath at
  `Tok.Typography.Size.sm`, tertiary ink — **instead of** the generic "Point a client at … or open
  the browser." line. `routes` empty: today's generic line. Filtered: unchanged. Buttons call
  `session.perform(connection:)` with the same `.openCaptureSettings` fallback as the banner, so
  `EmptyFlows` gains `@Environment(Session.self)` and `@Environment(\.openSettings)` for the
  actions only. `allowsHitTesting(false)` moves from the whole VStack to the text elements so the
  buttons stay clickable. Nothing else in the file; lines 49–62 and the `ExtensionController(` block
  byte-identical.

- **Test:** none in Kit by construction. Sandbox structural checks the Coder quotes:
  `git diff <wave-C-base> -- apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` shows hunks only
  inside `MainView.flows` and `EmptyFlows` (+ the one-argument change at the `flowTable` overlay
  call, which sits inside `flowTable`, ~261 — report it as the third hunk, it is the `EmptyFlows`
  call site named in D7); `sed -n 49,62p` before and after identical;
  `grep -cE 'ExtensionController[[:space:]]*\(' …/ShellView.swift` → `1`;
  `grep -c 'ScopeBanner()' …/ShellView.swift` → `0`; `grep -c 'AppsAttributionBanner()' …/ShellView.swift` → `0`;
  `grep -c 'RouteBanner()' …/ShellView.swift` → `1`; `grep -c 'struct AppsAttributionBanner: View' …/ShellView.swift` → `1`;
  `grep -nE 'connectionSummary|ConnectionSummary|LaneDot|LaneState|CaptureSwitch|capture\.enabled|extensionController|CaptureAdvice' …/Shell/RouteBanner.swift` → empty;
  `git diff <wave-C-base> -- apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` is two added
  tokens (the `.help` line, the `.openNetworkSettings` case). `apps/mac/tools/grid-lint.sh` PASS
  (source check). Visual proof is Task 6's screenshots.
- **Done when:** the checks print the values above, the Swift gate is green, `check-capture-operator-only.sh`
  and `check-connection-words.sh` PASS (the latter in its pre-Task-5 form, because no view spells a
  route word), and `check-capture-toggle.sh` fails ONLY on its NS-AC8 banner pins (expected; Task 5
  moves them) — any other failing pin is a defect in this task.

### Task 4: Proxy ▸ Network Settings… menu item, `CommandMap` entry, docs

- **Satisfies:** TR-AC6 (`CommandMap` clause), TR-AC14 (menu path), spec D7 docs rows
- **Depends on:** Task 2 (the menu item calls `session.perform(connection: .openNetworkSettings)`)
- **Files:**
  - `apps/mac/Sources/Aitmproxy/App.swift` (modify — one `Button` in `CommandMenu("Proxy")`)
  - `apps/mac/Sources/AitmproxyKit/CommandMap.swift` (modify — one entry)
  - `apps/mac/docs/BRIEF.md` (modify — one token on the Proxy menu line)
  - `apps/mac/Tests/AitmproxyKitTests/CommandMapTests.swift` (modify — one expectation)
  - `apps/mac/docs/GLOSSARY.md` (modify — two rows)
  - `apps/mac/docs/STORIES.md` (modify — S-073)
- **Change:**
  - `App.swift`: a NEW group right after the first `Divider()` (before `Button("Browser")`): `Button("Network Settings…") { session.perform(connection: .openNetworkSettings) }` followed by a `Divider()`. Agreed with the system-proxy session 2026-10-31: its `Toggle("Set as System Proxy")` (⌥⌘P) goes on the line directly ABOVE this item later, so nothing moves.
    no keyboard shortcut (plan call 7 — its neighbours Certificate Authority… and Configuration…
    have none; a clash-free chord may be added later).
  - `CommandMap.swift`: in the Proxy menu, after the `"Scan"` entry (mirroring the new group),
    `E("Proxy", "Network Settings…", nil, items: one("Network Settings…", nil))`.
  - `BRIEF.md` line 46 (the `Proxy ▸` list): insert ` · Network Settings…` after `Scan` (mirroring the new group).
  - `CommandMapTests.briefParses`: add
    `#expect(verbs.contains(CommandMap.BriefVerb(menu: "Proxy", title: "Network Settings…", shortcut: nil)))`;
    `mapMatchesTheBrief` then proves the map row for free.
  - `GLOSSARY.md`: rows `| System proxy | The macOS HTTP/HTTPS proxy setting every proxy-aware app follows, regardless of Scope; off, on · <address> (this core), or on · <address>, not this core | network proxy, global proxy, PAC |`
    and `| Route | One of the two ways traffic reaches the proxy without pointing a client by hand: the system proxy (every proxy-aware app, regardless of Scope) or All Apps (in-scope hosts of every app); open or closed | path, lane (that is the Status card) |`.
  - `STORIES.md`: `### S-073 See why nothing is flowing` after S-072 — operator story, Depends
    S-072, Spec = this plan's spec, Acceptance = [unit] TR-AC3–5 words, [structural] TR-AC7–8,
    [manual] TR-AC10–14 on the real app; Status: in progress. No `[snapshot]`/`[self-test]` lines.
- **Test:** `CommandMapTests` — `briefParses` and `mapMatchesTheBrief` pass with the new row
  (`missing == []`, `extra == []`). Sandbox check: `grep -c 'Network Settings…' apps/mac/docs/BRIEF.md apps/mac/Sources/AitmproxyKit/CommandMap.swift apps/mac/Sources/Aitmproxy/App.swift`
  → `1` each.
- **Done when:** the tests pass and the Swift gate is green.

### Task 5: Words tripwire — route-word prefixes and the one-derivation rule

- **Satisfies:** TR-AC7
- **Depends on:** Task 3 (rule 3 needs `trafficRoutes` and `RouteBanner.swift` to exist; the NS-AC8 move needs the new `MainView`)
- **Files:**
  - `apps/mac/tools/check-connection-words.sh` (modify)
  - `apps/mac/tools/check-capture-toggle.sh` (modify — NS-AC8 banner pins only, spec D8)
- **Change:** spec D9, and in `check-capture-toggle.sh` the NS-AC8 block: `equals "NS-AC8 the banner is rendered exactly once"`
  counts `RouteBanner()` (→ 1) and a new `equals "NS-AC8 the old Apps banner is no longer rendered"`
  counts `AppsAttributionBanner()` in `main_body` (→ 0); `main_bcond` becomes
  `line_of "$main_body" 'if session[.]trafficRoutes[.]banner != nil [{]'`, `main_bcall` becomes
  `line_of … 'RouteBanner[(][)]'`; the two `ordered` checks keep their meaning (condition guards the
  call; call above `if session.splitView {`). NS-AC3 struct/body pins and the NS-AC8 empty-state
  pins are untouched. Header comment notes spec D8.
  - Rule 1: a second grep with an opening-quote prefix pattern,
    `prefixes='"(system proxy off|system proxy on|All Apps on|All Apps off|All Apps waiting|All Apps degraded|HTTPS is not captured|Trust the aitmproxy CA|CA trusted|trusting CA|CA trust needs)'`,
    same scan root and exclusions as `words`, same FAIL message family
    ("a view spells a route word; read it from ConnectionSummary.routes instead").
  - Rule 2: unchanged.
  - New rule 3, "one route derivation": `grep -rnE --include='*.swift' 'var[[:space:]]+trafficRoutes' Sources/Aitmproxy`
    must yield exactly one line, in `Sources/Aitmproxy/Session+Connection.swift`, and that line
    must contain `connectionSummary.routes`; `Sources/Aitmproxy/Shell/RouteBanner.swift` must exist
    (a missing file is a FAIL, as rule 2 treats the sidebar) and contain none of
    `connectionSummary|ConnectionSummary|LaneDot|LaneState`. Header comment gains the TR-AC7
    reference.
- **Test (Terminal, the Coder lists them, the orchestrator/Tester runs them):**
  1. Clean tree → `PASS check-connection-words`, exit 0.
  2. Mutation, then revert: append `Text("system proxy off — x")` inside `EmptyFlows` → exit 1,
     output names `Shell/ShellView.swift`. Same for `Text("system proxy on · x")`,
     `Text("HTTPS is not captured until the CA is trusted")`, `Text("Trust the aitmproxy CA")` and
     `Text("All Apps on, nothing in scope — add a host")` in `Shell/RouteBanner.swift`.
  3. Mutation: add `let _ = session.connectionSummary` to `RouteBanner.swift` → exit 1 (rule 2 and 3);
     the same line in `ShellView.swift` → exit 1 (rule 2).
  4. Mutation: a second `var trafficRoutes: TrafficRoutes { connectionSummary.routes }` in
     `Session+Detail.swift` → exit 1 ("defined 2 times").
  5. `check-capture-operator-only.sh` PASS unchanged; `check-capture-toggle.sh` PASS with the moved
     pins, and FAIL (mutation, reverted) when a second `RouteBanner()` or an `AppsAttributionBanner()`
     call is added to `MainView`.
- **Done when:** steps 1–5 print as stated and the tree is restored (`git status` clean of mutations).

### Task 6: Live proof on the real app (Terminal; orchestrating session or Matt)

- **Satisfies:** TR-AC9 (gates on the whole branch), TR-AC10, TR-AC11, TR-AC12, TR-AC13, TR-AC14,
  TR-AC17 (the NOT-trusted state only), TR-AC19
- **Depends on:** Tasks 1–5 merged into the branch, Swift gate green, tripwires PASS
- **Files:** none in the repo. Evidence under `/tmp/claude/route-advice/` (PNG screenshots,
  `scutil --proxy` dumps, bus replies). The Shipped section records the build each half ran on.
- **Change:** none. **HARD GATE (Matt, via the orchestrator): do NOT run `ca.install` on Matt's
  Mac as part of any proof, and do not click Install… on the CA page.** Trusting the aitm CA on his
  machine is Matt's decision and he has not given it. This task proves only the NOT-trusted state
  and its line as his Mac is today, plus `ca.status` over the bus showing `trusted: "no"`. The
  install → line-disappears path is proved only after Matt says in his own words that the CA may
  be trusted, and then only through the app's own Status step (the sibling's `.trustCA` with its
  admin prompt), never a direct verb call from a script; it is recorded in Shipped when it happens.

  Two halves. **Every `networksetup` write is Terminal-only, is preceded by
  recording the originals, and is followed by restoring them** (today both enabled services,
  "Display Ethernet" (en15, primary per `route -n get default`) and "Wi-Fi" (en0), carry Proxyman's
  `127.0.0.1:9090` for HTTP and HTTPS — research 22 §5b, `docs/research/22-macos-system-proxy-toggle.md`; verify, do not assume). `networksetup`
  from Matt's admin account prompts for nothing (research 22 §5b). The operator token is read into a shell
  variable and never printed, echoed, or pasted into a transcript.

  **Setup (both halves)**
  1. `mkdir -p /tmp/claude/route-advice`; `networksetup -listallnetworkservices > …/services.txt`;
     for each enabled service `networksetup -getwebproxy "<svc>"` and `-getsecurewebproxy "<svc>"`
     → `…/proxy-before.txt`; `scutil --proxy > …/scutil-before.txt`;
     `route -n get default | awk '/interface:/{print $2}'` → the primary interface, mapped to its
     service name via `networksetup -listnetworkserviceorder`. Expected today: `HTTPEnable : 1`,
     `HTTPProxy : 127.0.0.1`, `HTTPPort : 9090`, HTTPS the same.
  2. Restore recipe (used at the end of each half and after any abort): for each service in
     `proxy-before.txt`, `-setwebproxy "<svc>" <host> <port>` / `-setsecurewebproxy …` when it was
     enabled, else `-setwebproxystate "<svc>" off` / `-setsecurewebproxystate "<svc>" off`; then
     re-run step 1's `-get*` into `…/proxy-after.txt` and `diff proxy-before.txt proxy-after.txt`
     → empty.
  3. Bus access to the running embedded core (either half): `pid=$(pgrep -f '<bundle>/Contents/Resources/core/aitm --config')`,
     `cfg=$(ps -o command= -p "$pid" | sed -E 's/.*--config ([^ ]+).*/\1/')` (the 0600 per-launch
     config), `TOKEN=$(awk '/operator_token:/{print $2}' "$cfg" | tr -d '"')` (never echoed), bus
     port from the `bus.endpoint` file beside it. Calls go through
     `tests/e2e/aitm_e2e/bus.py`'s `BusClient(host, port, token)` (`python3 -I -c` reading
     `os.environ["TOKEN"]`), `call("scope.list")`, `call("scope.add", {...})`,
     `call("scope.remove", {...})`, `call("ca.status")` (read-only); replies saved to `…/bus-<step>.json`.
     **Never `call("ca.install", …)`.** Trap: a
     `defaults … bus.operatorToken` value overrides the config token (memory
     `aitmproxy-mac-live-proof-recipe`); the app's Settings ▸ Bus must be empty.
  4. Screenshots: `screencapture -x -l <windowID>` of the app window → `…/<half>-<step>-<page>.png`.

  **Half A — system-proxy lines on the dev bundle** (an early, fast pass; a build without the
  extension, so `routes.allApps == nil` and the Status `extensionOn` step reads "All Apps capture
  is not in this build"). Quit the installed app first (port 8080 would otherwise be taken and `L`
  would not read `127.0.0.1:8080`).
  - A1 Build: `apps/mac/build.sh --debug --replace` with `AITM_CORE_DIR` pointing at a core dir that
    holds `aitm`, `obscura` and `share/aitm/scripts` (coreless-bundle trap: build.sh skips the core
    silently). Verify `ls ~/Applications/Aitmproxy.app/Contents/Resources/core/aitm`. Launch; the
    toolbar pill reads `127.0.0.1:8080`; Status shows Core running, Bus connected.
  - A2 As found (TR-AC10, system-proxy half): Flows page shows "No flows yet" with the row
    `system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`,
    its detail `every proxy-aware app, regardless of Scope`, buttons Open Network Settings… and
    Copy Address; no All Apps row; beneath it the CA row `HTTPS is not captured until the CA is trusted`
    with its detail and no button (the dev core's CA is not trusted either; `ca.status` →
    `…/bus-A2-ca.json`, every store `trusted: "no"`). Status shows the same system-proxy line as a
    `○` step with Open Network Settings… and `○ Trust the aitmproxy CA` with no button. Nowhere
    does either page say "off" or "trusted". → `A2-flows.png`, `A2-status.png`.
  - A3 Off (TR-AC12): on every enabled service `-setwebproxystate "<svc>" off` and
    `-setsecurewebproxystate "<svc>" off`; `scutil --proxy` → `HTTPEnable : 0` (`…/scutil-A3.txt`).
    Within one second both pages read
    `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`. → `A3-*.png`.
  - A4 This core (TR-AC12): `-setwebproxy "<primary>" 127.0.0.1 8080` and `-setsecurewebproxy "<primary>" 127.0.0.1 8080`.
    Within one second the system-proxy row leaves the Flows empty state (the CA row stays; the
    generic "Point a client at …" line returns only once the CA is trusted too) and Status reads
    `✓ system proxy on · 127.0.0.1:8080` (hover →
    help `every proxy-aware app, regardless of Scope`, TR-AC14). Safari → `http://example.com/`
    with no `-x`: a flow appears. → `A4-flows-before.png`, `A4-status.png`, `A4-flows-after.png`.
  - A5 Elsewhere, HTTPS still here (TR-AC12 / D3): `-setwebproxy "<primary>" 127.0.0.1 8081`.
    Status reads `✓ system proxy on · 127.0.0.1:8080 · HTTPS only`. Then
    `-setsecurewebproxy "<primary>" 127.0.0.1 8081`: both pages read
    `system proxy on · 127.0.0.1:8081, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`.
    → `A5-https-only.png`, `A5-other.png`.
  - A6 Banner, no extension (TR-AC13 / D5 "no extension" row): with A5's state,
    `curl -x 127.0.0.1:8080 http://example.com/` twice. Flows shows the table and ONE banner line
    reading exactly `system proxy on · 127.0.0.1:8081, not this core · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (composed, spec D5), with Open Network Settings…; no other banner above or below it. → `A6-banner.png`. Set the primary
    service back to `127.0.0.1 8080` on both protocols → the banner is exactly
    `HTTPS is not captured until the CA is trusted` (TR-AC17, open route + untrusted CA). → `A6-ca-only.png`.
  - A7 Actions (TR-AC14): click Open Network Settings… on Flows (System Settings ▸ Network opens),
    Proxy ▸ Network Settings… from the menu bar (same), Copy Address → `pbpaste` prints
    `127.0.0.1:8080`. → `A7-network-settings.png`, `…/A7-pbpaste.txt`.
  - A8 Restore (setup step 2); both pages show the A2 line again → `A8-restored.png`. Quit the dev
    bundle.

  **Half B — All Apps / scope lines and the two-line banner on the installed app** (the notarized
  build containing this change installed in `/Applications`, embedded core running, All Apps on,
  extension attached — a dev build cannot activate the extension and does not count here). System
  proxy as found (Proxyman's 9090 → `.other`).
  - B1 Launch; toolbar All Apps switch on; setup step 3; `scope.list` → `[]` (`…/bus-B1.json`).
  - B2 As found (TR-AC10, full): Flows "No flows yet" with both rows —
    `system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    (Open Network Settings…, Copy Address) and `All Apps on, nothing in scope — add a host`
    (Open Scope…), each with its detail line, then the CA row `HTTPS is not captured until the CA is trusted`
    (no button; `ca.status` → `…/bus-B2-ca.json`, every store `trusted: "no"` — TR-AC17). Status:
    the same two route lines as `○` steps with the same buttons, `✓ All Apps is on` above the scope
    step, and `○ Trust the aitmproxy CA` (no button) above the first-flow step; hover → the CA
    detail. Nothing reads "trusted". → `B2-flows.png`, `B2-status.png`.
  - B3 Scope over the bus (TR-AC11): `scope.add example.com:443` (`…/bus-B3-add.json`), no app
    interaction. Within one second both pages drop the All Apps line; the system-proxy line stays;
    Status `scopeSet` reads `✓ Scope has 1 host`. `scope.remove example.com:443` → the line is back
    on both pages. → `B3-after-add-flows.png`, `B3-after-add-status.png`, `B3-after-remove-flows.png`.
  - B4 Banner (TR-AC13): scope `[]`; `curl -x 127.0.0.1:8080 http://example.com/` twice. Flows
    shows the table and ONE banner line reading
    `system proxy on · 127.0.0.1:9090, not this core · All Apps on, nothing in scope · HTTPS is not captured until the CA is trusted — set 127.0.0.1:8080 as the system proxy, or point a client at it`
    with Open Network Settings… and Open Scope…; no "No scope set" `ScopeBanner` and no "Flows
    carry no source app" line anywhere. Pinned, Domains and Apps show the same single line
    (Apps: rows present, Client column "—", exactly one banner). → `B4-flows-banner.png`,
    `B4-domains.png`, `B4-apps.png`.
    `scope.add example.com:443` → the banner is exactly `HTTPS is not captured until the CA is trusted`
    (a route is open, the CA is not trusted — TR-AC17) (`B4-ca-only-scope.png`).
    Header position (TR-AC19): on Apps with the single banner, record the column header's top edge
    (`…/B4-header-with-banner.txt`, from the screenshot's pixel row or the table header's AX frame);
    Edit ▸ Clear → no rows, `banner == nil`, no banner; record again (`…/B4-header-no-banner.txt`);
    the difference is exactly 40 pt (one `Tok.Size.Row.dense`), never 80; Undo Clear restores the
    rows and the one banner; a click at the first row's y selects row 1 and does not sort
    (`B4-row1-click.png`). `scope.remove`;
    then `-setwebproxy "<primary>" 127.0.0.1 8080` + `-setsecurewebproxy … 8080` → the same CA-only
    banner (`B4-ca-only-proxy.png`). Restore (setup step 2). The two-route "banner gone, nothing
    replaces it" clause of TR-AC13 is therefore proved on this Mac only in combination with the CA
    line; its CA-trusted form waits for Matt's decision (Shipped).
  - B5 Actions (TR-AC14): Open Scope… from the Flows empty state → Scope page; Open Network
    Settings… from the Status step → System Settings ▸ Network; hover the two route steps → help
    `every proxy-aware app, regardless of Scope` / `in-scope hosts of every app`. → `B5-*.png`.
  - B6 Restore check: `diff proxy-before.txt proxy-after.txt` empty; `scope.list` → `[]`;
    `…/B6-restored-flows.png` shows the B2 lines.
  - B7 CA fact, read-only (TR-AC17): `call("ca.status")` → `…/bus-B7-ca.json` quoted in the report
    (stores `user`/`system`: `installed`, `trusted: "no"`); the Flows and Status screenshots from B2
    and B4 are the evidence for the line, the step and the CA-only banner. **No `ca.install`, no
    Install… click, no Keychain Access change.** If Matt, in his own words, allows the CA to be
    trusted before this task runs, add B8: through the app's own Status step only (requires the
    sibling's `.trustCA`), then `ca.status` → `trusted: "yes"`, both pages read `✓ CA trusted (user
    keychain)` and the line is gone from the empty state and the banner; otherwise B8 does not exist.

  **Whole-branch gates (TR-AC9)**: Swift gate green; `apps/mac/build.sh --ne --allow-unnotarized
  --replace` log shows no warnings; the three tripwires PASS; Rust gate green.
- **Test:** the screenshots and files above exist and show the literal lines named; the Tester's
  report quotes the `scutil` dumps, the bus replies and the `diff` result.
- **Done when:** every TR-AC10–14 clause has its named file, the proxy settings are restored
  (`diff` empty), the whole-branch gates are green, and the whole-branch Tester and panel have no
  open findings.

---

## File-disjointness table

| File | T1 | T2 | T3 | T4 | T5 | T6 |
|---|---|---|---|---|---|---|
| `AitmproxyKit/SystemProxyState.swift` (new) | C | | | | | |
| `AitmproxyKit/ConnectionSummary.swift` | M | | | | | |
| `Tests/AitmproxyKitTests/SystemProxyStateTests.swift` (new) | C | | | | | |
| `Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` | M | | | | | |
| `AitmproxyKit/CATrustFacts.swift` (new) | C | | | | | |
| `AitmproxyKit/Panels/CAStatus.swift` (two additive fields) | M | | | | | |
| `Tests/AitmproxyKitTests/CATrustFactsTests.swift` (new) | C | | | | | |
| `Aitmproxy/Bus/SystemProxyReader.swift` (new) | | C | | | | |
| `Aitmproxy/Bus/BusService.swift` | | M | | | | |
| `Aitmproxy/Session.swift` | | M | | | | |
| `Aitmproxy/Session+Connection.swift` | | M | | | | |
| `Aitmproxy/Shell/RouteBanner.swift` (new) | | | C | | | |
| `Aitmproxy/Shell/ShellView.swift` (two hunks + the `EmptyFlows` call; two old banner call sites removed) | | | M | | | |
| `Aitmproxy/Panels/StatusPanel.swift` (two tokens) | | | M | | | |
| `Aitmproxy/App.swift` | | | | M | | |
| `AitmproxyKit/CommandMap.swift` | | | | M | | |
| `Tests/AitmproxyKitTests/CommandMapTests.swift` | | | | M | | |
| `apps/mac/docs/BRIEF.md` | | | | M | | |
| `apps/mac/docs/GLOSSARY.md` | | | | M | | |
| `apps/mac/docs/STORIES.md` | | | | M | | |
| `apps/mac/tools/check-connection-words.sh` | | | | | M | |
| `apps/mac/tools/check-capture-toggle.sh` (NS-AC8 banner pins) | | | | | M | |
| (no repo files; `/tmp/claude/route-advice/`) | | | | | | — |

C = create, M = modify. No file appears in two columns; Tasks 3 and 4 may run as parallel
Coders. Shared with the sibling icons plan on this branch: `Bus/BusService.swift`, `Session.swift`
(its Tasks 5/6) — sequence, never concurrent. Not touched by anyone: `CaptureAdvice.swift`,
`CaptureCapability.swift`, `Package.swift`, `UI/Tokens.swift`, `Bus/ExtensionController.swift`,
`Panels/ScopePanel.swift`, `apps/mac/Extension/**`, `crates/**`.

## Acceptance-criteria coverage

| TR-AC | Class | Task |
|---|---|---|
| 1, 2 | K | 1 |
| 3, 4, 5 | K | 1 |
| 6 | K | 1 (actions, `settingsURL`, witness list), 4 (`CommandMap`) |
| 7 | T | 5 (write + mutations), 3 (pre-form PASS), 6 (whole branch) |
| 8 | structural | 2 (CFNetwork single file, Kit imports, `Package.swift`), 3 (ShellView/StatusPanel footprint) |
| 9 | gates | every wave (Swift), 6 (release build warnings, Rust) |
| 10 | L | 6 (A2 system-proxy half on the dev bundle; B2 full on the installed app) |
| 11 | L | 6 (B3) |
| 12 | L | 6 (A3–A5, A8) |
| 13 | L | 6 (A6 no-extension row; B4 composed banner, no old banners) |
| 14 | L | 6 (A7, B5) |
| 15 | K | 1 (`CATrustFactsTests`) |
| 16 | K | 1 (`caTrust*` tests in `ConnectionSummaryTests`) |
| 17 | L | 6 (A2/A6 CA row and CA-only banner on the dev bundle; B2/B4/B7 on the installed app) — NOT-trusted state only; hard gate |
| 18 | K | 1 (`composedBanner`) |
| 19 | L | 6 (B4 header measurement, one banner on all four list pages), T (Task 5 NS-AC8 pins) |

## Plan-level calls (for Matt or the orchestrator to overturn; none blocks)

1. **TR-AC8's "StatusPanel diff is the one `.help` line" is two tokens, not one.** `StatusPanel.run`
   switches exhaustively over `ConnectionAction`, so the new case must join the "handled by
   `perform`" list. The plan treats that one-token addition as inside TR-AC8's intent; the
   spec-reviewer should read it so. (Amend TR-AC8 in the spec if you prefer the AC to say it.)
2. `ConnectionAction` gains `CaseIterable` so TR-AC6's witness list is a real `allCases ==`
   comparison instead of a hand-maintained list. Additive; the sibling's reserved cases will show up
   in `allCases` when they land, which is the point.
3. `SystemProxyState.Endpoint.address` is computed (`"\(host):\(port)"`), not stored; `Endpoint(host:port:)`
   is the memberwise init TR-AC1 uses.
4. `SystemProxyReader.read()` returns `nil` (not `.off`) when `CFNetworkCopySystemProxySettings()`
   returns nothing: the step stays hidden rather than claiming "off" from an absent dictionary.
5. `BusService` resets `session.systemProxy = nil` in `pollLoop`'s `defer`, so a session whose live
   bus ended says nothing about the system proxy (the spec's anti-goal "with the bus down") and
   the Status list returns to five steps until the next connect.
6. `EmptyFlows` takes `routes: [TrafficRoute]` as a parameter from the existing overlay call rather
   than reading the environment, so it stays a function of its inputs; it still needs the
   environment `Session` for its buttons' `perform`.
7. Proxy ▸ Network Settings… ships with no keyboard shortcut (like Certificate Authority… and
   Configuration…); `CommandMapTests` does not require one when the brief lists none.
8. Half A of the live proof runs on the `build.sh --debug` dev bundle (fast, no notarization) and is
   the system-proxy evidence for TR-AC10/12/13's no-extension rows; Half B runs on the notarized
   installed build. If a notarized build is available when Half A runs, re-run A2–A5 on it too (ten
   minutes) so all evidence sits on one build, and say which in Shipped.
9. `ca.status` is refreshed every 10th poll tick (~5 s) and at connect, not every tick: on macOS the
   verb spawns `/usr/bin/security` per store (`crates/aitm-ca/src/exec.rs`). A trust change made in
   Keychain Access or by `aitm ca install` from a terminal reaches both pages within ~5 s.
10. `CATrustFacts(status:)` is failable: nil when no store reports `"yes"` or `"no"` (the core's
    `"unknown"`), so unknown renders as unknown (no step, no line), never as not trusted. Needs two
    additive fields on `CAStatus` (`trustedScope`, `trustReported`); `CAStatus.trusted` keeps its
    meaning. The sibling may prefer a non-failable init — Q3.
11. The CA step and the CA row ship with **no button**: no `ConnectionAction` reaches the CA page
    today and `.trustCA`/`.openCAPanel` are the sibling's. The CA page stays reachable from the
    sidebar and Proxy ▸ Certificate Authority….
12. `check-capture-toggle.sh` is edited in Task 5 (NS-AC8 banner pins → `RouteBanner()`), so Task 3
    is expected to leave exactly those pins red until Task 5 lands; the waves stay as drawn (C then
    D), and the whole-branch run must be green. The `AppsAttributionBanner` struct is kept, not
    deleted, so the NS-AC3 body pins and the `CaptureAdvice.banner` tests stay untouched; deleting
    them is a later cleanup.

## Questions for Matt / the orchestrator

- **Q1 (claim).** Spec §D7 touches `Session.swift`, `Bus/BusService.swift`, `Shell/RouteBanner.swift`
  (new), `App.swift`, `AitmproxyKit/CommandMap.swift`, `apps/mac/docs/BRIEF.md` (forced by
  `CommandMapTests.mapMatchesTheBrief`), `GLOSSARY.md`, `STORIES.md` beyond the granted list. Confirm
  the claim for these, and the sequencing with the icons plan's Tasks 5/6 on `BusService.swift` /
  `Session.swift` (both plans live on this branch).
- **Q2 (evidence build).** Does the dev-bundle pass (Half A) count as the TR-AC12 evidence, or must
  A2–A5 be repeated on the notarized build (plan call 8 assumes "re-run if available")?
- **Q3 (sibling, CA init).** `CATrustFacts(status:)` is specified failable here (plan call 10).
  Confirm with the system-proxy-automation session before Task 1 runs, or it adopts whatever that
  session has already landed, provided unknown never renders as trusted or not trusted.
- **Q4 (Matt, not blocking).** The CA-trusted proof (step B8) exists only if Matt allows the aitm
  CA to be trusted on his Mac, in his own words; until then TR-AC17 is proved in its not-trusted
  form only and Shipped says so.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

(Filled at stage 7: what merged, which build each live half ran on, what was cut, follow-ups —
the sibling set-system-proxy work consuming `SystemProxyState`/`SystemProxyRoute`, and
`SCDynamicStore` notifications if the poll-tick read ever shows in a profile; whether the CA-trusted
state (B8) was proved, and on whose say-so.)
