# macOS traffic-route advice — implementation plan

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode); amended 2026-11-01 (self-approved, autonomous mode): stage-6 fix pass on docs PR #242 plus the orchestrator's gate-2/gate-5 rulings of 2026-11-01 (Review log); amended again 2026-11-01 (self-approved, autonomous mode): implementation and stage-5 Tester rulings on the shipped code (Review log, the "Tester (whole branch)" and "Architect (amendment)" rows); amended 2026-11-01, stage-6 panel (self-approved, autonomous mode): the security/quality/spec panel on PR #265 (`58724ef7..6ebc9e8f`) — one Review-log row per finding ("PR #265" rows), gate 3 stamped, the TRUSTED-CA ruling carried into every Task 6 paragraph, the shipped type shapes in Tasks 1/2b/3, the Swift gate quoted for the head commit
**Spec:** `docs/superpowers/specs/2026-10-31-mac-traffic-route-advice-design.md`
(approved 2026-10-31, amended 2026-11-01; acceptance criteria TR-AC1 … TR-AC22 — TR-AC1/2 are PR 4a's `SystemProxyState` contract, TR-AC14 deleted, TR-AC15–17 the CA-trust fact, TR-AC18–19 the one-banner-line rule, TR-AC20–22 per-host decryption on v0.5.9)
**Branch / worktree:** `feat/mac-traffic-route-advice` (the branch the implementation shipped on; earlier drafts
named it `claude/apps-attribution-8ab619`), in this worktree
(`/Users/matt/Security/aitmproxy/.claude/worktrees/apps-attribution-8ab619`), base `main 8e19c2e3`.
**PR shape:** two PRs from this branch — this traffic-route plan ships **first**; the sibling icons plan
(`2026-10-31-mac-app-icons-and-names-plan.md`) ships second and records this PR's merge SHA as its gate 4
(its Tasks 5/6 share `Session.swift` / `BusService.swift` with Tasks 2/2b here and run only after them).
Within this plan, if gate 3 slips, the CA halves may follow as a small third PR (plan call 14).

## Gates: nothing below starts until 1, 2 and 5 hold; the CA parts (and Task 2's `Session+Connection.swift` edits) also wait for 3; Task 1c for 4

1. **The fixture-removal mac PR is on `main` and this branch has rebased once onto its merge
   SHA** (the orchestrator sends it; record here: `c3a4fd37` (confirmed by the orchestrator 2026-11-01)). That PR deletes the mac app's
   fixture, sample-data, snapshot, self-test and gallery modes and modifies
   `tools/check-capture-toggle.sh`. **This plan references none of them.** A Coder who meets
   `Store.usesFixtures`, `Fixtures.`, `SelfTest`, `SnapshotScenes` or `APP_FIXTURES` in a file it
   edits leaves it alone and reports it; it never adds one. After the rebase, the `ScopeBanner`
   condition in `MainView.flows` is whatever that PR left (today it reads `!Store.usesFixtures,
   session.scopeHosts.isEmpty, case .connected = session.bus`; Task 3 removes that branch whatever
   its post-removal form, spec D8).
2. **File claims — the orchestrator's answers of 2026-11-01, recorded as fact.**
   - Granted earlier: `AitmproxyKit/ConnectionSummary.swift`; `Shell/ShellView.swift` — `EmptyFlows`,
     the one banner insertion in `MainView.flows` and the removal of the `ScopeBanner()` /
     `AppsAttributionBanner()` call sites there (spec D8) only, lines 49–62 (palette overlay) and the
     palette transition untouched; `Tests/AitmproxyKitTests/**`; `tools/check-connection-words.sh`;
     `Panels/StatusPanel.swift` where wording moves; the `Session.trafficRoutes` accessor;
     `Shell/RouteBanner.swift` (new).
   - `apps/mac/tools/check-capture-toggle.sh`: **GO**, on the fixture-removal mac SHA (that PR modifies
     the script; Task 5 moves the NS-AC8 pins to `RouteBanner()` there).
   - `Bus/BusService.swift`: **GO for one decode** of `proxy.status.decrypt` inside the existing
     `refreshProxyStatus()` (the grant read "exactly one line"; amended 2026-11-01 — the decode is change-guarded
     like the file's other per-tick writes, since an `@Observable` set notifies on equal values: four added lines,
     two statements plus a two-line comment, at `BusService.swift:234–237`, no `await`, no new verb; accepted by
     the orchestrator). **NO** `refreshCAStatus()` (CA polling is PR D's), **NO**
     `refreshSystemProxy()`, **NO** `Bus/SystemProxyReader.swift`, no `defer` reset lines.
   - `Session+Connection.swift`: **GO on PR D's merged SHA** for `.addScopeHost` in `perform(connection:)`
     and the `tunnelledFlowCount` accessor (PR D edits the same switch; sequential, never
     simultaneous). `.openNetworkSettings` is **DENIED** as a product action (Matt: system-proxy setup
     happens automatically in the app with the OS's own prompt, never by sending him to System
     Settings): the case, its title, the "Network Settings…" menu item and the CommandMap/BRIEF/GLOSSARY
     rows are removed from this plan (Task 4 removed, TR-AC14 deleted); the system-proxy entry's
     `actions` stay **empty** until PR4 fills `.setSystemProxy`.
   - `Session.swift`: `var systemProxy: SystemProxyState?` (nil; **written by PR4 only** — plan call 4)
     and `var decrypt: DecryptStatus?`. `Session.caTrust` / `caStatus` are PR D's.
   - Withdrawn with the denial, not touched: `AitmproxyKit/CommandMap.swift`, `apps/mac/docs/BRIEF.md`,
     `apps/mac/docs/GLOSSARY.md`. `App.swift`: **one token** (orchestrator GO 2026-11-01, Task 5) — `App.swift:226`
     `Button("Trust the aitmproxy CA")` → `Button(ConnectionAction.trustCA.title)`, so no view spells a route word
     under the D9 prefix rule; nothing else in the file. `apps/mac/tools/check-ca-trust-path.sh`: **GO** (2026-11-01,
     agreed with the CA-trust session, Task 5) — rule 2's allow-list gains `Shell/RouteBanner.swift` with an expect
     line. `apps/mac/docs/STORIES.md`: never touched
     (the improve-loop session owns S-073/S-074/S-080).
   - **System-proxy source** (agreed with the system-proxy session, 2026-11-01): `Session.systemProxy:
     SystemProxyState?` (nil = unknown until the first answer, never rendered as "off") is set by PR4
     from the `system_proxy` sub-object of every `proxy.status` poll (existing cadence; the core
     refreshes it ≤ 5 s and immediately after set/unset) and from the direct replies of
     `proxy.system.set`/`unset`. Wire: `proxy.status.system_proxy = { state: off|points_at_us|other|
     unsupported|needs_privilege|unknown, host, port, managed_by_us, setting, supported, detail }`.
     **PR #246 (gate 5)** ships `SystemProxyState.init?(compact: JSONValue, listenAddress: String)`
     (points_at_us → both endpoints at the listen address, other → both at host:port, off → `.off`,
     unsupported / needs_privilege / unknown / malformed → nil, `other` at our own listen address → nil,
     bare IPv6 literal without brackets → nil); PR4 adds `SystemProxyFacts` and fills
     `.setSystemProxy`/`.unsetSystemProxy`.
     The Proxy menu gets only PR4's toggle (⌥⌘P); nothing of ours.
   - **CA source** (PR D's published contract, 2026-11-01; branch `claude/ca-trust-mac`,
     `apps/mac/Sources/Aitmproxy/Session+CATrust.swift`): we read `Session.caTrust: CATrustFacts?` and
     nothing else — computed by PR D via `CATrustFacts(status:)`, nil when every store is unknown or the
     certificate does not exist, with `installing` and `needsAdmin` already applied from
     `Session.caTrustInstalling` / `Session.caTrustNeedsAdmin`; `Session.caStatus: CAStatus?` is the raw
     read-back (nil until the first answer, reset by `Session.forgetCATrust()` when the bus disconnects);
     cadence is PR D's: `BusService.pollLoop` calls `session.refreshCAStatus()` on the first tick and
     every 10th 500 ms tick (`BusService.caStatusEveryTicks = 10`), forced after `trustCA()`/`untrustCA()`.
     PR D's Kit `CATrustFacts` has fields `{trusted, scope, fingerprint, platform, installing, needsAdmin}`
     and helpers `{text, state, remedy, actions, step, quicCaveat, notTrustedLine, laneTitle, …}`; Task 1b
     consumes `text`/`actions`/`step` instead of recomputing the CA words (one vocabulary; our strings
     are the same). When this PR lands, `StatusPanel`'s interim `stepsWithCATrust` insertion and
     `CATrustRow` (PR D) are replaced by our step and row — Task 2b removes the insertion, the words
     stay. `make(…, caTrust: session.caTrust)` stays as is.
3. **CA parts only — PR D (the CA-trust session's mac PR) is on `main`** (recorded 2026-11-01, stage-6
   SP-M7: **PR #254**, this branch's base `58724ef7` carries it) and this branch has rebased onto it. Gated on it: **Task 1b** (the `make(caTrust:)`
   slot, the `.caTrust` derivation from PR D's helpers, the `.caTrusted` step and its tests), **Task 2b**
   (the `caTrust:` pass-through and the `StatusPanel` hand-over), the CA clauses of Tasks 3/5/6, and —
   because its `Session+Connection.swift` grant is on PR D's SHA — **Task 2** and everything after it.
   Not gated: Tasks 1 and 1c.
4. **Task 1c only — the claim for `AitmproxyKit/FlowSummary.swift`, `AitmproxyKit/Flow.swift`,
   `AitmproxyKit/FlowDetail.swift`, `AitmproxyKit/FlowDetail+Wire.swift` and their tests
   (`FlowSummaryTests.swift` new, `FlowRowEqualityTests.swift`, `FlowDetailWireTests.swift`): GO,
   orchestrator 2026-11-01** ("Coordinator contract for Task 1c" below). Until Task 1c is in, the
   `tunnel` → `tls` mapping is not written, `tunnelledFlowCount` stays 0 on every build, and TR-AC20 / B8
   are recorded as deferred. Nothing else waits on it.
5. **PR #246 merged, SHA `2461a300`.** The system-proxy session's PR 4a = **PR #246** (branch
   `claude/system-proxy-kit-type` off `main c8e4b6e5`, head `c8ed92f4` after its panel) ships only
   `apps/mac/Sources/AitmproxyKit/SystemProxyState.swift` + 31 tests — the type exactly as spec D2
   defines it (TR-AC1/2) plus `init?(compact:listenAddress:)` (points_at_us → both endpoints at the
   listen address, other → both at host:port, off → `.off`, unsupported / needs_privilege / unknown /
   malformed → nil, `other` at our own listen address → nil, brackets normalised in the match, bare IPv6
   literal without brackets → nil, `:::8080` rejected since the core prints `[::]:8080`), no polling, no other file. New file, so it does not wait for the fixture-removal
   mac SHA. Task 1 builds against it on `main` and calls `state.route(to: listenAddress)` for the word;
   PR4 proper keeps ownership and adds the `proxy.status.system_proxy` polling later. This plan creates
   nothing of it.

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
  `apps/mac/tools/check-capture-toggle.sh`, `apps/mac/tools/check-connection-words.sh` and
  `apps/mac/tools/check-ca-trust-path.sh` — each prints PASS. The tripwires are **bash**
  (`#!/usr/bin/env bash`); `apps/mac/tools/grid-lint.sh` is **zsh** — run it by path
  (`apps/mac/tools/grid-lint.sh`), never as `bash tools/grid-lint.sh`. The structural greps of TR-AC8 run in
  the sandbox.
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
  `ca.install` (or clicks Install… on the CA page) on his Mac. Task 6 proves the CA state **as his Mac
  has it** — since 2026-11-01 the TRUSTED rendering (spec TR-AC17 ruling: Matt trusted the CA himself
  through PR D's first-run step; `ca.status` user store `trusted: "yes"`, Status `✓ CA trusted (user
  keychain)`, no CA row or banner clause); the NOT-trusted line is proved by the Kit tests (TR-AC16) and
  shown live only on a Mac that does not trust the CA, and nobody untrusts it to recreate it. The install →
  line-disappears path is proved only after Matt says in his own words that the CA may be
  trusted, and then only through the app's own Status step (PR D's `.trustCA` with its confirm and
  admin prompts — on a not-trusted Mac the button is present on Task 6's screenshots and is **not
  clicked**), never a direct verb call from a script. `Panels/CAPanel.swift`, `AitmproxyKit/Panels/CAStatus.swift` and
  `Session+CATrust.swift` join the do-not-touch list.
- **Do-not-touch:** `apps/mac/Sources/AitmproxyKit/CaptureAdvice.swift`, `CaptureCapability.swift`,
  `AitmproxyKit/SystemProxyState.swift` and its tests (PR 4a's), `apps/mac/Package.swift`,
  `apps/mac/Sources/Aitmproxy/UI/Tokens.swift` (generated),
  `apps/mac/Sources/Aitmproxy/Bus/ExtensionController.swift`, `Panels/ScopePanel.swift`
  (`ScopeBanner`'s text), `App.swift` except Task 5's one token at `:226` (GO 2026-11-01),
  `AitmproxyKit/CommandMap.swift`, `apps/mac/docs/BRIEF.md`,
  `apps/mac/docs/GLOSSARY.md`, `apps/mac/docs/STORIES.md`, anything under `apps/mac/Extension/` or
  `crates/`. In `Shell/ShellView.swift`: lines 49–62, the `ExtensionController(` block (~99) and
  everything outside the two named hunks. In `Bus/BusService.swift`: everything but the one granted
  decode (Task 2: two statements plus a comment, change-guarded). A Coder whose task seems to need one of these **stops and reports**.
- **Stop-and-report rule.** A Coder that finds the spec wrong (a D-section that cannot be built as
  written, a signature that will not typecheck under strict concurrency) stops and reports; it does
  not redesign. One known seam is pre-decided in the plan calls (StatusPanel's exhaustive switch,
  call 1).

## Overview

Eight tasks (1, 1b, 1c, 2, 2b, 3, 5, 6 — Task 4 was removed 2026-11-01) in eight waves (A, B, C, D,
A′, B′, A″, E). Wave A is pure Kit (one task: the `TrafficRoutes` model over PR 4a's `SystemProxyState`,
the `make` extension and the whole predicate table as tests, the CA kinds declared but never produced).
Wave B wires the app target to the Kit value (`Session.systemProxy` — nil, PR4's to write —
`Session.decrypt` and the one `BusService` decode, `Session.trafficRoutes`, `tunnelledFlowCount`,
`perform(.addScopeHost)`). Wave C is the one UI task: the two surfaces (Status step help + Flows empty
state + the route banner). Wave D updates the words tripwire and moves the NS-AC8 pins, which can only
pass once `trafficRoutes` and `RouteBanner.swift` exist. Wave E is the real-app proof plus the
whole-branch Tester and panel.

| Wave | Tasks | Parallel? |
|---|---|---|
| A | Task 1 (after gate 5; system proxy, All Apps, Scope; `.caTrust` kinds declared, always nil) | — |
| B | Task 2 (after 1 **and gate 3**: its `Session+Connection.swift` grant is on PR D's SHA) | — ; not concurrent with the icons plan's Tasks 5/6 (shared `BusService.swift`, `Session.swift`) |
| C | Task 3 (after 2) | — (Task 4 removed) |
| D | Task 5 (after 3) | — |
| A′ | Task 1b (after 1 **and gate 3**) | may run beside C/D (Kit + tests only; `ConnectionSummary.swift` is Task 1's file, so 1b runs after 1 has landed, never beside it) |
| B′ | Task 2b (after 1b, 2 and 3) | — ; same shared-file rule as Task 2; edits `StatusPanel.swift` after Task 3 |
| A″ | Task 1c (gate 4 GO; independent of 1/1b/2) | yes — `Flow.swift`, `FlowSummary.swift`, `FlowDetail.swift`, `FlowDetail+Wire.swift` and their tests are touched by no other task |
| E | Task 6 (CA clauses only after 2b; B8 only after 1c), then whole-branch Tester and the three reviewers | sequential |

PR D lands before this PR by the orchestrator's registry, so in practice Waves B–E simply follow gate 3.
If PR D slips, only Tasks 1 and 1c can run; the earlier two-PR split (plan call 14) is kept as the
fallback and would need a fresh `Session+Connection.swift` grant on the pre-PR-D tree (asked then, not
assumed). The first build of this PR renders the system proxy as unknown on every machine — the
`systemProxy` step absent, no system-proxy words — until PR4 lands and writes `Session.systemProxy`.

Evidence classes: **K** Tasks 1, 1b, 1c; **T** Task 5 (run), Task 6 (whole branch); **L** Task 6. Tasks
2, 2b and 3 have no Kit test by construction (app target, SwiftUI); their proof is the TR-AC8 structural
greps, Task 6, and the diff review.

---

## Tasks

### Task 1: Kit model — `TrafficRoutes`, `make(systemProxy:tunnelledFlowCount:decrypt:)`, the predicate table (no CA derivation)

> **Amendment 2026-11-01 (system-proxy session, orchestrator ruling):** `SystemProxyState.swift` and `SystemProxyStateTests.swift` are CREATED by system-proxy PR 4a (#246, branch `claude/system-proxy-kit-type`); this task ADOPTS them as-is (fields are `let`; IPv6 brackets normalised in the match; `init?(compact: JSONValue, listenAddress:)` added) and creates neither file. Base this PR on #246's merge.

- **Satisfies:** TR-AC3 (quoted, fallback, stale list, bus not `.ok`), TR-AC4, TR-AC5, TR-AC6, TR-AC18 (non-CA cases), TR-AC21. (TR-AC1/2 are PR #246's tests — gate 5.)
- **Depends on:** **gate 5** (PR #246's `SystemProxyState.swift` on `main`, this branch rebased onto it); not gated on PR D
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify)
  - `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (modify)
  - `apps/mac/Sources/AitmproxyKit/DecryptStatus.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/DecryptStatusTests.swift` (create)
  - `apps/mac/Sources/AitmproxyKit/SystemProxyState.swift`, `Tests/AitmproxyKitTests/SystemProxyStateTests.swift`: **read-only — PR #246's**; a Coder who finds the file missing or differing from spec D2 stops and reports (gate 5 not met)
- **Change:** exactly spec D2/D2a/D3/D4/D5 **without** the `caTrust` input or derivation. Task 1
  declares `TrafficRoute.Kind.caTrust` and `TrafficRoutes.caTrust: TrafficRoute?` (always nil from this
  task's `make`) so Task 3's views compile against the full vocabulary; `GettingStartedStep.Kind.caTrusted`,
  `ConnectionAction.trustCA` and `.openCAPanel` are **PR D's** — if PR D is already on the branch, Task 1
  leaves them exactly as they are; if not, Task 1 does not add them (the listing below shows the
  post-PR-D shape); either way Task 1's `make` never emits them. `make` has no `caTrust:` parameter
  until Task 1b. Foundation only (no CFNetwork, SystemConfiguration, SwiftUI, AppKit import anywhere
  in the Kit). `SystemProxyState` / `SystemProxyRoute` are imported from PR #246's file and used
  through `state.route(to: listenAddress)` only (plan call 3 is now PR #246's shape: `Endpoint.address`
  computed, `init(host:port:)` memberwise).

  **Amendment 2026-11-01 (PR #246, agreed with the system-proxy session; the same facts are written on
  #246's branch so the two land without a content conflict):** `apps/mac/Sources/AitmproxyKit/SystemProxyState.swift`
  and `apps/mac/Tests/AitmproxyKitTests/SystemProxyStateTests.swift` are **created by PR #246** (gate 5)
  and never created here — this task adopts them. Their shape: fields are `let`, not `var`; `route(to:)`
  normalises IPv6 brackets in its host match (`[::1]` ≡ `::1`); `init?(compact:listenAddress:)` takes a
  `JSONValue` (the Kit's bus-object convention) while `init(settings:)` keeps the CFNetwork
  `[String: Any]`; mapping: `points_at_us` → both endpoints at the listen address, `other` → both at
  host:port, `off` → `.off`, `unsupported` / `needs_privilege` / `unknown` / malformed → nil, and a
  `state: "other"` whose endpoint equals our own listen address → **nil (unknown)** — the core reports
  its partial case "HTTP → us, HTTPS off" as `other` at our host:port and two endpoints cannot express
  "partly at us", so our route step shows nothing in that case until PR4's facts carry the verb's
  `state`/`detail` (spec D10 row "unknown — the core's partial case"; TR-AC2's partial-case literal).

  `ConnectionSummary.swift`:

  ```swift
  public enum ConnectionAction: Hashable, Sendable, CaseIterable {   // CaseIterable added (plan call 2)
      …existing 14 cases…, case addScopeHost          // title "Add Host…"
      // PR4's, not added here (fill the system-proxy entry's actions): setSystemProxy, unsetSystemProxy
      // PR D's, consumed here, never declared: trustCA ("Trust the aitmproxy CA"), openCAPanel
      // Denied 2026-11-01: openNetworkSettings — no case, no title, no settingsURL
  }

  public struct TrafficRoute: Hashable, Sendable {
      public enum Kind: String, Hashable, Sendable, CaseIterable { case systemProxy, allApps, scope, caTrust }
      public let kind: Kind
      public let open: Bool
      public let state: String      // STORED (stage-6 S2/Q1): the state words — "system proxy off", the quoted Scope sentence with its period, the CA line
      public let remedy: String?    // STORED: the " — " clause, nil when the line has none (every open entry, Scope, CA)
      public var line: String       // COMPUTED: state, then " — " + remedy when present; nothing ever parses a line
      public let detail: String
      public let actions: [ConnectionAction]
      public init(kind: Kind, open: Bool, state: String, remedy: String?, detail: String, actions: [ConnectionAction])
  }

  public struct TrafficRoutes: Hashable, Sendable {
      public let systemProxy: TrafficRoute?
      public let allApps: TrafficRoute?
      public let scope: TrafficRoute                                   // always present; closed iff !open (D3: !decrypt.decrypting when decrypt is present and the bus lane is .ok, else scopeHostCount == 0)
      public let caTrust: TrafficRoute?                                // nil = ca.status unread/unknown
      public let advice: [TrafficRoute]
      public let shown: [TrafficRoute]                                 // the ONE stored banner fact (ruling 2026-11-01; shipped shape, stage-6 SP-M3): D5's `shown`, in order; [] when the banner predicate is false
      public var banner: String? { shown.isEmpty ? nil : shown.map(\.state).joined(separator: " · ") }
      public var bannerAction: ConnectionAction? { shown.first { !$0.actions.isEmpty }?.actions.first }
      public var bannerDetail: String? { shown.isEmpty ? nil : shown.map(\.detail).joined(separator: " · ") }
      public var anyOpen: Bool { [systemProxy, allApps].compactMap { $0 }.contains(where: \.open) }   // routes only
      public init(systemProxy: TrafficRoute?, allApps: TrafficRoute?, scope: TrafficRoute, caTrust: TrafficRoute?, advice: [TrafficRoute], shown: [TrafficRoute])
  }

  public struct GettingStartedStep {
      public enum Kind: String, …, CaseIterable { case coreRunning, busConnected, caTrusted, systemProxy, extensionOn, scopeSet, firstFlow } // PR D's source order; steps order is make's
      public let detail: String?                                      // NEW
      public init(kind: Kind, title: String, done: Bool, action: ConnectionAction? = nil, detail: String? = nil)
  }

  public struct ConnectionSummary {
      public let routes: TrafficRoutes                                // NEW stored field
      public static func make(core:activeKind:bus:role:roleWarning:capability:captureSupported:
                              scopeHostCount:flowCount:listenAddress:coreCapture: = nil,
                              systemProxy: SystemProxyState? = nil,
                              tunnelledFlowCount: Int = 0,
                              decrypt: DecryptStatus? = nil) -> ConnectionSummary   // Task 1b inserts `caTrust: CATrustFacts? = nil` before tunnelledFlowCount
  }

  // DecryptStatus.swift — `proxy.status.decrypt` (v0.5.9+), spec D2
  public struct DecryptStatus: Hashable, Sendable {
      public var scopeHosts: Int
      public var decrypting: Bool
      public var advice: String?
      public init(scopeHosts: Int, decrypting: Bool, advice: String?)
      public init?(json: JSONValue)   // nil unless the object carries "scope_hosts" AND scope_hosts >= 0 (stage-6 S3); "decrypting" defaults to scopeHosts > 0; "advice" null → nil; empty or whitespace-only → nil (ruling 2026-11-01); a present advice has its line breaks flattened to one space and is capped at 512 characters (stage-6 S2)
  }
  ```

  Inside `make`: compute `routes` (private `routes(systemProxy:advice:activeKind:bus:scopeHostCount:flowCount:tunnelledFlowCount:decrypt:listenAddress:)`)
  **before** `steps`, and pass `routes` into `steps`. Route derivation and words are spec D3,
  verbatim — the system-proxy lines use `L` = `listenAddress` and `H:P` = the `.other` endpoint via
  `systemProxy.route(to: L)`; the closed system-proxy entries carry `actions = []` (PR4 fills
  `[.setSystemProxy]`); the All Apps open line is `"All Apps on"`; the Scope fact uses `decrypt` only
  when the bus lane's `state == .ok`; `advice` = the closed entries of `[systemProxy, allApps, scope,
  caTrust]`, in that order, **only when the bus lane's `state == .ok`**, else `[]`; `banner` and
  `bannerAction` = spec D5's predicate (`knownOpenRoute`, `closedRoutes`, the first shown entry with
  an action) and composed form.
  Steps are spec D4: `systemProxy` step omitted while `routes.systemProxy == nil`, otherwise
  `title = line`, `detail = detail`, `done = open`, `action = nil` (PR4: `.setSystemProxy` when closed);
  `extensionOn` titles become the All Apps route line for `.off`/`.awaitingApproval`/`.degraded`
  (actions unchanged: `.turnCaptureOn`/`.approveInSystemSettings`/`.openCaptureSettings`) and
  `"All Apps is on"` for `.onEmptyScope`/`.on` (detail `"in-scope hosts of every app"`);
  `scopeSet` keeps its title and action: undone `"Add a host to Scope (for now as example.com:443)"`,
  `.openScope`, detail `"Nothing is decrypted until a host is in Scope."`; done
  `"Scope: N hosts decrypted"` (`Format.count`), action nil, detail = the scope entry's detail.

> **Ruling 2026-11-01 (coordinating session, on the Task 1 coder's stop-and-report):** (1) `routes.advice` has NO
> `flowCount` dependence — it is the list of closed facts (spec D3); whether to show it is the empty-state view's
> decision (Task 3). TR-AC3's former `flows: 6 → advice == []` clause and the `predicateTable` literal
> `[.allApps]` were leftovers and now read `[.systemProxy, .scope]` / `[.scope]`. (2) Because `ConnectionAction` is
> switched exhaustively in `Session+Connection.swift` (`perform(connection:)`) and `Panels/StatusPanel.swift`
> (`run(_:)`), Task 1 is GRANTED the two one-line `case .addScopeHost:` additions there (each delegating to the
> Scope page with the add sheet, exactly what Task 2/Task 3 would write), so `swift test` builds every target
> after Task 1 alone; Tasks 2 and 3 keep ownership of everything else in those files and run after Task 1.
> (3) A third existing expectation changes: `gettingStartedStepsFollowTheFacts` pins `done.steps[3].title ==
> "Scope has 2 hosts"`, which D4 renames to `"Scope: 2 hosts decrypted"`.

  **Existing tests this changes** (update them in the same commit; they are the spec's new words):
  in `gettingStartedStepsFollowTheFacts`, `fresh.steps[2].title` becomes
  `"All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`
  and `waiting.steps[2].title` becomes
  `"All Apps waiting for approval — approve the extension in System Settings"`. The five-element
  `done` arrays stay (no `systemProxy:` → five steps).

- **Test:** the private `make(...)` helper in `ConnectionSummaryTests` gains `systemProxy: SystemProxyState? = nil`,
  `tunnelled: Int = 0` (→ `tunnelledFlowCount:`) and `decrypt: DecryptStatus? = nil`; Task 1b adds `caTrust: CATrustFacts? = nil`;

  `DecryptStatusTests.swift` (TR-AC21), literal `JSONValue` objects:
  `{"scope_hosts": 0, "decrypting": false, "advice": "Nothing is decrypted until a host is in Scope."}` → `scopeHosts == 0`, `decrypting == false`, `advice == "Nothing is decrypted until a host is in Scope."`;
  `{"scope_hosts": 2, "decrypting": true, "advice": null}` → `(2, true, nil)`; `{}` → `nil`;
  a `proxy.status`-shaped object without `decrypt` → `status["decrypt"].flatMap(DecryptStatus.init) == nil`;
  `{"scope_hosts": 1}` (no `decrypting`) → `decrypting == true` (defaults to `scopeHosts > 0`).
  **Blank advice (ruling 2026-11-01; fixed in a code commit, SHA stamped in the Review log):**
  `{"scope_hosts": 0, "decrypting": false, "advice": ""}` → `advice == nil`; `"advice": "  \n"` → `advice == nil`;
  and in `ConnectionSummaryTests`, `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: "")` →
  `routes.scope.line == "Nothing is decrypted until a host is in Scope."` (the fallback, never an empty line —
  the memberwise init bypasses the decoder, so `make`'s Scope derivation normalises the blank itself; stage-6
  SP-I1, fixed in a code commit, SHA to be stamped).
  **Bounded advice and negative count (stage-6 S2/S3; fixed in a code commit, SHA to be stamped):**
  `{"scope_hosts": 0, "decrypting": false, "advice": "line one\nline two"}` → `advice == "line one line two"`;
  an `advice` of 600 `"a"` characters → `advice?.count == 512`; the core's 47-character sentence unchanged;
  `{"scope_hosts": -1, "decrypting": false}` → `DecryptStatus(json:) == nil`.

  add a helper `both(_ host: String, _ port: Int) -> SystemProxyState` (HTTP and HTTPS at that
  endpoint, built with PR #246's `SystemProxyState(http:https:)` / `Endpoint(host:port:)`). `L = "127.0.0.1:8080"`.

  (TR-AC1/2 — `parsesTheProxiesDictionary`, incl. `"HTTPPort": "9090"` → `9090` and `"abc"` → nil, and
  `routeToTheCore` — live in PR #246's `SystemProxyStateTests.swift`; this task does not touch them and
  reports it if a literal of spec TR-AC1/2 is not pinned there.)

  `ConnectionSummaryTests.swift` additions:
  - `routesAdviceAndBanner` (TR-AC3): `make(bus: .connected("127.0.0.1:60745"), role: "operator", capability: .capturing, hosts: 0, flows: 0, systemProxy: .off).routes`:
    `advice.map(\.line) == ["system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it", "Nothing is decrypted until a host is in Scope."]`,
    `advice.map(\.kind) == [.systemProxy, .scope]`, `routes.allApps?.line == "All Apps on"`, `routes.allApps?.open == true`,
    `advice.map(\.detail) == ["every proxy-aware app, regardless of Scope", "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"]`,
    `advice[0].actions == []` (PR4 fills `.setSystemProxy`), `advice[1].actions == [.addScopeHost, .openScope]`,
    `routes.scope.state == "Nothing is decrypted until a host is in Scope."`,
    `banner == nil`, `bannerAction == nil`, `anyOpen == true`. Same with `flows: 6` → `advice.map(\.kind) == [.systemProxy, .scope]` (unchanged by rows), `banner == nil`;
    **quoted** (`core = DecryptStatus(scopeHosts: 0, decrypting: false, advice: "Nothing is decrypted until a host is in Scope.")`):
    same inputs + `decrypt: core` → `routes.scope.line == "Nothing is decrypted until a host is in Scope."`, `state == "Nothing is decrypted until a host is in Scope."`,
    `open == false`, `actions == [.addScopeHost, .openScope]`; + `flows: 6, tunnelled: 6` → `banner == "Nothing is decrypted until a host is in Scope."`;
    + `.inactive, flows: 6` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`;
    + `flows: 6, tunnelled: 6` → `bannerAction == .addScopeHost`;
    **stale list:** `decrypt: DecryptStatus(scopeHosts: 2, decrypting: true, advice: nil), hosts: 0` → `routes.scope.open == true`, `line == "Scope: 2 hosts decrypted"`, no scope entry in `advice`,
    and + `flows: 6, tunnelled: 6` → `banner == nil` (the Scope fact follows `decrypt`, not the stale list);
    **bus not `.ok`:** `decrypt: core, bus: .disconnected, hosts: 0` → `routes.scope.line == "Nothing is decrypted until a host is in Scope."` (from `scopeHostCount`; `decrypt` ignored), `advice == []`;
    `decrypt: DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil)` → `line == "Nothing is decrypted until a host is in Scope."`;
    with `flows: 6, tunnelled: 6` → `banner == "Nothing is decrypted until a host is in Scope."`;
    with `.inactive, flows: 6` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`.
    Same with `systemProxy: both("127.0.0.1", 9090), flows: 0` →
    `advice[0].line == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`
    and `advice.allSatisfy { !$0.line.contains("off") }`.
  - `predicateTable` (TR-AC4), one `make` per row, bus `.connected("x")`/`role: "operator"` unless stated:
    `.inactive, systemProxy: .off` → `routes.allApps?.line == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`, `actions == [.openCaptureSettings]`, `open == false`;
    `.pendingApproval` → `"All Apps waiting for approval — approve the extension in System Settings"`, `[.approveInSystemSettings]`;
    `.degraded("x")` → `"All Apps degraded — x"`, `[.openCaptureSettings]`;
    `.capturing, hosts: 1` → `routes.allApps?.line == "All Apps on"`, `open == true`, `actions == []`, `routes.scope.line == "Scope: 1 host decrypted"`, `routes.scope.open == true`; `hosts: 3` → `"Scope: 3 hosts decrypted"`;
    `systemProxy: SystemProxyState(http: Endpoint(host: "127.0.0.1", port: 8080), https: nil)` → `routes.systemProxy?.line == "system proxy on · 127.0.0.1:8080 · HTTP only"`, `open == true`, `actions == []`;
    `https`-only at the core → `"system proxy on · 127.0.0.1:8080 · HTTPS only"`;
    `both("127.0.0.1", 8080)` → `"system proxy on · 127.0.0.1:8080"`;
    `systemProxy: nil, .capturing, hosts: 0` → `routes.systemProxy == nil`, `advice.map(\.line) == ["Nothing is decrypted until a host is in Scope."]`;
    `supported: false, systemProxy: .off, hosts: 2, flows: 3` → `routes.allApps == nil`, `banner == "system proxy off"`, `bannerAction == nil` (no action until PR4);
    `supported: false, systemProxy: .off, hosts: 0, flows: 3` → `banner == "system proxy off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .addScopeHost`;
    `supported: false, systemProxy: nil, hosts: 0, flows: 3` → `banner == nil`; + `tunnelled: 3` → `banner == "Nothing is decrypted until a host is in Scope."`;
    **system proxy unknown, All Apps off:** `systemProxy: nil, .inactive, hosts: 0, flows: 3` → `banner == "All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`, `banner?.contains("system proxy") == false`;
    `systemProxy: nil, .inactive, hosts: 2, flows: 3` → `banner == "All Apps off"`;
    `supported: false, systemProxy: .off, hosts: 0, flows: 0` → `advice.map(\.kind) == [.systemProxy, .scope]`;
    `systemProxy: .off, .capturing, hosts: 2, flows: 3` → `banner == nil`, `anyOpen == true`;
    `both("127.0.0.1", 9090), .capturing, hosts: 2, flows: 3` → `banner == nil`;
    `both("127.0.0.1", 8080), .capturing, hosts: 0, flows: 3` → `banner == nil`, `advice.map(\.kind) == [.scope]` (All Apps is open under `.capturing`; only the Scope fact is closed);
    `bus: .disconnected, systemProxy: .off, .capturing, hosts: 0` → `advice == []`, `banner == nil`;
    `bus: .connected("x"), role: "agent", roleWarning: true, systemProxy: .off` → `advice == []` (lane not `.ok`);
    `kind: .external, bus: .connected("x"), role: "operator", .capturing, hosts: 2, systemProxy: .off` → `routes.allApps == nil`, `advice.map(\.kind) == [.systemProxy]`;
    `systemProxy: .off, .inactive, hosts: 2, flows: 3` → `banner == "system proxy off · All Apps off"`, `bannerAction == .openCaptureSettings`;
    `systemProxy: .off, .inactive, hosts: 0, flows: 3` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`;
    `both("127.0.0.1", 8080), .capturing, hosts: 0, flows: 3, tunnelled: 3` → `banner == "Nothing is decrypted until a host is in Scope."`;
    `both("127.0.0.1", 8080), .capturing, hosts: 0, flows: 3, tunnelled: 2` → `banner == nil`.
  - `stepsCarryTheRouteWords` (TR-AC5): `systemProxy: nil` → `steps.map(\.kind)` contains no `.systemProxy`;
    `systemProxy: .off` → `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .firstFlow]`,
    `steps[2].done == false`, `steps[2].title == "system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it"`,
    `steps[2].detail == "every proxy-aware app, regardless of Scope"`, `steps[2].action == nil` (PR4: `.setSystemProxy`);
    `both("127.0.0.1", 9090)` → `steps[2].title == "system proxy on · 127.0.0.1:9090, not this core — set 127.0.0.1:8080 as the system proxy, or point a client at it"`, `done == false`;
    `both("127.0.0.1", 8080)` with `core(.ready), .capturing, hosts: 2, flows: 1` → `steps[2].title == "system proxy on · 127.0.0.1:8080"`, `done == true`, `action == nil`, `allStepsDone == true`;
    `.capturing, hosts: 0` → `extensionOn.title == "All Apps is on"`, `done == true`, `detail == "in-scope hosts of every app"`, `scopeSet.title == "Add a host to Scope (for now as example.com:443)"`, `scopeSet.done == false`, `scopeSet.action == .openScope`, `scopeSet.detail == "Nothing is decrypted until a host is in Scope."`;
    `.inactive` → `extensionOn.title == "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)"`, `action == .turnCaptureOn`;
    `.pendingApproval` → the waiting line, `action == .approveInSystemSettings`;
    `.degraded("x")` → `extensionOn.title == "All Apps degraded — x"`, `action == .openCaptureSettings`;
    `.capturing, hosts: 2` → `scopeSet.title == "Scope: 2 hosts decrypted"`, `scopeSet.done == true`, `scopeSet.action == nil`, `scopeSet.detail == "Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"`; `hosts: 1` → `"Scope: 1 host decrypted"`;
    `coreRunning`, `busConnected`, `firstFlow` → `detail == nil`.
  - `addScopeHostAction` (TR-AC6): `ConnectionAction.addScopeHost.title == "Add Host…"`, `isDestructive == false`;
    `ConnectionAction.allCases == [.startCore, .restartCore, .showCoreLog, .switchToEmbedded, .reconnectBus, .openBusSettings, .turnCaptureOn, .turnCaptureOff, .openScope, .approveInSystemSettings, .uninstallExtension, .openCaptureSettings, .openBrowser, .copyListenAddress, .addScopeHost]`
    plus PR D's `.trustCA`, `.openCAPanel` wherever that PR placed them (the Coder pins the merged order; with PR D in, also
    `ConnectionAction.trustCA.title == "Trust the aitmproxy CA"`). `openNetworkSettings` (denied) and PR4's
    `setSystemProxy`/`unsetSystemProxy` are absent by construction of this literal list.

  - `composedBanner` (TR-AC18): `routes.systemProxy?.state == "system proxy off"`, `routes.systemProxy?.line.hasPrefix("system proxy off — set")` (`.off` input; the row keeps the clause, the banner never);
    `hosts: 0` → `routes.scope.state == "Nothing is decrypted until a host is in Scope."`;
    `.capturing, hosts: 0, flows: 3, tunnelled: 3, systemProxy: .off` → `banner == "Nothing is decrypted until a host is in Scope."`, `bannerAction == .addScopeHost`;
    `.inactive, hosts: 0, flows: 3, systemProxy: .off` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`;
    `.inactive, hosts: 0, flows: 3, systemProxy: nil` → `banner == "All Apps off · Nothing is decrypted until a host is in Scope."`, `bannerAction == .openCaptureSettings`;
    `.inactive, hosts: 2, flows: 3, systemProxy: .off` → `banner == "system proxy off · All Apps off"`;
    `supported: false, hosts: 2, flows: 3, systemProxy: .off` → `banner == "system proxy off"`, `bannerAction == nil`;
    `banner == nil` → `bannerAction == nil`.
    **`shown` / `bannerDetail` (ruling 2026-11-01; fixed in a code commit, SHA in the Review log):**
    `.inactive, hosts: 0, flows: 3, systemProxy: .off` → `routes.shown.map(\.kind) == [.systemProxy, .allApps, .scope]`,
    `routes.bannerDetail == "every proxy-aware app, regardless of Scope · in-scope hosts of every app · Only hosts in Scope are decrypted, on either route; every other HTTPS connection passes through as a TLS tunnel"`;
    `.capturing, hosts: 0, flows: 3, tunnelled: 3` → `shown.map(\.kind) == [.scope]`, `bannerDetail == scopeDetail`;
    `banner == nil` → `shown == []`, `bannerDetail == nil`.
- **Done when:** the new tests and the two updated expectations pass, every other existing
  `AitmproxyKitTests` suite still passes, and the Swift gate is green (Terminal, orchestrator).
  Sandbox evidence: `swiftc -parse` clean on the four files; the report lists the literal values above.

### Task 1b: Kit model — the CA fact (`make(caTrust:)`, `.caTrust` entry from PR D's helpers, the `.caTrusted` step) — GATED on gate 3

- **Satisfies:** TR-AC16, TR-AC18 (CA cases); TR-AC15 is proved by PR D
- **Depends on:** Task 1 landed; **gate 3** (PR D on `main`, this branch rebased onto it)
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/ConnectionSummary.swift` (modify — the `caTrust:` parameter and derivation)
  - `apps/mac/Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` (modify)
  - PR D's `AitmproxyKit/CATrustFacts.swift`, `AitmproxyKit/Panels/CAStatus.swift`, `Session+CATrust.swift` and PR D's tests: **read only** — a Coder who finds `CATrustFacts` missing, or its API differing from the record below (read from `claude/ca-trust-mac` `4ae616d3`), stops and reports (gate 3 not met or spec D2 to be amended first)
- **Change:** `make` gains `caTrust: CATrustFacts? = nil` (before `tunnelledFlowCount`). CA fact in `make`
  (spec D3/D4/D5): `routes.caTrust` nil when `caTrust == nil`; else `kind: .caTrust`, `open = trusted && !installing`
  (ruling 2026-11-01, spec D3: PR D's `installing` outranks `trusted`, as its `step.done` does),
  `line` = PR D's **`text`** (the one-line fact string — PR D's `state` is a `LaneState`, `remedy` a longer
  sentence; neither is used), `actions` = PR D's `actions` when closed, `[]` when open, `detail` =
  `"HTTPS on both routes"` when trusted, else `"HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`.
  PR D's helpers (`CATrustFacts.swift` 4ae616d3; `installing` wins over `trusted`, which wins over
  `needsAdmin`): `text` → `"trusting CA…"` / `"CA trusted (System keychain)"` (scope `"system"`, capital S) /
  `"CA trusted (user keychain)"` / `"CA trust needs an administrator"` / `"HTTPS is not captured until the CA is trusted"`;
  `actions` → `[]` installing, `[.openCAPanel]` trusted or needsAdmin, `[.trustCA, .openCAPanel]` otherwise;
  `step` → `GettingStartedStep(kind: .caTrusted, title: <trustCA.title for the plain not-trusted fact, else text>,
  done: state == .ok, action: done ? nil : actions.first)`. The Coder confirms these against PR D's file and
  reports any difference instead of re-wording. `advice` = the closed entries of `[systemProxy, allApps,
  scope, caTrust]` in that order (bus `.ok`). Banner per spec D5 (Task 1 already implements `knownOpenRoute`,
  `closedRoutes`, `shown`, `banner = shown.map(\.state).joined(" · ")` — **no remedy text** — and
  `bannerAction` = the first shown entry with an action); this task only lets the CA entry join `shown`
  when closed. Step `caTrusted` (PR D's `GettingStartedStep.Kind.caTrusted`) after `scopeSet`, omitted
  when `routes.caTrust == nil`; `title` and `action` are PR D's `step`'s — `.trustCA` for the plain
  not-trusted fact, **`.openCAPanel` when `needsAdmin`**, nil while `installing` or when done; `detail` =
  the route detail. PR D's nil-facts rows (`unknownStep()`, `notGeneratedStep()`) are not produced here
  (spec D4, open question 21).

- **Test:** the private `make(...)` helper gains `caTrust: CATrustFacts? = nil`. **Ruling 2026-11-01:** PR D
  declares `init?(status:)` in the struct body, so Swift synthesises no memberwise init (the earlier "built with
  PR D's memberwise init" was wrong); values are built as `try #require(CATrustFacts(status: CAStatus(fingerprint:
  "AB:CD", installed:, trusted:, platform: "macos", trustedScope:, trustReported: true)))` and `installing` /
  `needsAdmin` are then set on the `var` (the suite's `caFacts(scope:installing:needsAdmin:)` helper).
  `notTrusted` = `caFacts()`: trusted false, scope nil, fingerprint `"AB:CD"`, platform `"macos"`, installing
  false, needsAdmin false; `trustedUser` = `caFacts(scope: "user")`: trusted true, scope `"user"`, fingerprint
  `"AB:CD"`, platform `"macos"`.

  `ConnectionSummaryTests` additions for the CA fact (TR-AC16):
  - `caTrustJoinsAdviceAndSteps`: TR-AC3 inputs + `caTrust: notTrusted` → `routes.caTrust?.line == "HTTPS is not captured until the CA is trusted"` (`== notTrusted.text`),
    `routes.caTrust?.detail == "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"`,
    `routes.caTrust?.actions == [.trustCA, .openCAPanel]` (`== notTrusted.actions`), `advice.map(\.kind) == [.systemProxy, .scope, .caTrust]`, `anyOpen == true`,
    `steps.map(\.kind) == [.coreRunning, .busConnected, .systemProxy, .extensionOn, .scopeSet, .caTrusted, .firstFlow]`,
    `steps[5].title == "Trust the aitmproxy CA"`, `steps[5].done == false`, `steps[5].action == .trustCA`, `steps[5].detail == <the detail string>`;
  - `caTrustBanner`: same + `flows: 6` → `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`; same + `flows: 6, tunnelled: 6` → `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .addScopeHost`;
    same + `.inactive, flows: 6` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .openCaptureSettings`;
    same + `systemProxy: nil, .inactive, flows: 6` → `banner == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .openCaptureSettings` (the fresh install until PR4);
    `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: notTrusted` → `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`, `anyOpen == true`;
    `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: trustedUser` → `banner == nil`;
    `systemProxy: .off, .capturing, hosts: 0, flows: 3, tunnelled: 3, caTrust: trustedUser` → `banner == "Nothing is decrypted until a host is in Scope."` (no CA clause);
  - `caTrusted`: `caTrust: trustedUser` → `routes.caTrust?.line == "CA trusted (user keychain)"`, `open == true`, `detail == "HTTPS on both routes"`, `actions == []` (open: PR D's `[.openCAPanel]` is not stored), `steps` contain `.caTrusted` with `title == "CA trusted (user keychain)"`, `done == true`, `action == nil`;
    `scope: "system"` → `"CA trusted (System keychain)"` (capital S — PR D verbatim);
    `allStepsDone == true` with `core(.ready)`, `both("127.0.0.1", 8080)`, `.capturing, hosts: 2, flows: 1, caTrust: trustedUser`;
  - `caUnknownSaysNothing`: `caTrust: nil` → `routes.caTrust == nil`, no `.caTrusted` step, `advice`/`banner` carry no `"CA"` and no `"HTTPS"`;
  - `caSiblingStates`: `installing: true` → `line == "trusting CA…"`, `open == false`, `actions == []`, the step `title == "trusting CA…"`, `action == nil`;
    `scope: "user", installing: true` (an uninstall in flight) → `line == "trusting CA…"`, `open == false`, the step `done == false` (ruling 2026-11-01: `installing` outranks `trusted`);
    `needsAdmin: true` → `line == "CA trust needs an administrator"`, `open == false`, `actions == [.openCAPanel]`, the step `title == "CA trust needs an administrator"`, `action == .openCAPanel`;
    `needsAdmin: true` + `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3` → `banner == "CA trust needs an administrator"`, `bannerAction == .openCAPanel`.
  - `composedBannerWithCA` (TR-AC18, CA cases; `notTrusted`/`trustedUser` as above):
    `routes.caTrust?.state == routes.caTrust?.line` (`notTrusted`);
    `.inactive, hosts: 0, flows: 3, systemProxy: .off, caTrust: notTrusted` → `banner == "system proxy off · All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .openCaptureSettings` (fresh install with PR4);
    `.inactive, hosts: 0, flows: 3, systemProxy: nil, caTrust: notTrusted` → `banner == "All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .openCaptureSettings` (fresh install until PR4);
    `.capturing, hosts: 0, flows: 3, systemProxy: .off, caTrust: notTrusted` → `banner == "HTTPS is not captured until the CA is trusted"`, `bannerAction == .trustCA`;
    `.capturing, hosts: 0, flows: 3, tunnelled: 3, systemProxy: .off, caTrust: notTrusted` → `banner == "Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted"`, `bannerAction == .addScopeHost`;
    single-fact cases: `banner == routes.<fact>?.state` for `supported: false, .off, hosts: 2, flows: 3` (`"system proxy off"`, `bannerAction == nil`) and for `both("127.0.0.1", 8080), .capturing, hosts: 2, flows: 3, caTrust: notTrusted` (`bannerAction == .trustCA`);
    `banner == nil` → `bannerAction == nil`.

  TR-AC15 (`CATrustFacts(status:)` over literal `CAStatus(json:)` inputs — user `"yes"` → trusted/`"user"`/`"AB:CD"`;
  user `"no"` + system `"no"` → not trusted, scope nil; user `"unknown"` only → nil; no `stores` → nil; system `"yes"` +
  user `"no"` → trusted/`"system"`; `installing == false`, `needsAdmin == false` throughout) is PR D's test; this task
  does not write it and reports if PR D's tests do not pin it.

- **Done when:** the new tests pass, Task 1's tests still pass unchanged, and the Swift gate is green.

### Task 1c: Kit decoder for the #228 wire fields — `TunnelMode`/`TunnelReason`, the five row fields, `FlowDetail.tunnel` — GATED on gate 4 (own claim)

- **Satisfies:** TR-AC22; makes TR-AC20 unconditional (`tunnelledFlowCount` becomes real)
- **Depends on:** **gate 4** (GO, orchestrator 2026-11-01); independent of Tasks 1/1b/2 — file-disjoint
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/Flow.swift` (modify — `TunnelMode`, `TunnelReason`, five `FlowRow` fields, `isTunnel`, `==`)
  - `apps/mac/Sources/AitmproxyKit/FlowSummary.swift` (modify — five fields decoded, `tls` mapping, fields passed to `row(...)`)
  - `apps/mac/Sources/AitmproxyKit/FlowDetail.swift` (modify — `TunnelInfo`, `tunnel`, `passive`)
  - `apps/mac/Sources/AitmproxyKit/FlowDetail+Wire.swift` (modify — decode `meta.tunnel` / `meta.passive`)
  - `apps/mac/Tests/AitmproxyKitTests/FlowSummaryTests.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/FlowRowEqualityTests.swift` (modify — one row per new field)
  - `apps/mac/Tests/AitmproxyKitTests/FlowDetailWireTests.swift` (modify)
- **Change:** exactly spec D2 "Kit row/detail decoder". `Flow.swift`: `public enum TunnelMode: String, Hashable, Sendable { case decrypted, passthrough, failed }`;
  `public enum TunnelReason: String, Hashable, Sendable` with the eight cases `outOfScope = "out_of_scope"`, `pinned`,
  `clientRejectedCertificate = "client_rejected_certificate"`, `clientClosed = "client_closed"`, `clientTLSError = "client_tls_error"`,
  `upstreamUnreachable = "upstream_unreachable"`, `upstreamTLSFailed = "upstream_tls_failed"`, `protocolError = "protocol_error"`
  (`TunnelReason(rawValue:)` on an unknown label is nil — never a crash); `FlowRow` gains `tunnel: TunnelMode?`,
  `tunnelReason: TunnelReason?`, `tunnelBytesUp: Int64?`, `tunnelBytesDown: Int64?`, `passive: Bool` (memberwise init
  defaults nil/nil/nil/nil/false so existing call sites compile), `public var isTunnel: Bool { tunnel != nil }`, and all
  five join `==`. `FlowSummary`: the same five stored fields from `json["tunnel"]?.stringValue.flatMap(TunnelMode.init(rawValue:))`,
  `json["tunnel_reason"]…TunnelReason.init(rawValue:)`, `Self.size(json["bytes_up"])`, `Self.size(json["bytes_down"])`,
  `json["passive"]?.boolValue ?? false`; `row(seq:coreID:)` passes them through and computes `tls:` as
  `tunnel == .passthrough ? .tunnelled : tunnel == .failed ? .pinnedOrFailed : tunnel == .decrypted ? .decrypted :
  (scheme == "https" || scheme == "wss" ? .decrypted : .none)`. `inScope` untouched. `FlowDetail.swift`:
  `public struct TunnelInfo: Hashable, Sendable { mode: TunnelMode; reason: TunnelReason?; bytesUp: Int64?; bytesDown: Int64? }`,
  `public var tunnel: TunnelInfo?`, `public var passive: Bool`; `FlowDetail+Wire.swift` decodes `meta["tunnel"]`
  (`{mode, reason, bytes_up, bytes_down}`, `crates/aitm-plugins/src/detail.rs` ~355–380; a `mode` that is not one of the
  three → `tunnel = nil`) and `meta["passive"]?.boolValue ?? false`. Nothing else in these files changes; no view changes.
- **Test (`FlowSummaryTests.swift`, TR-AC22):** a literal `flow.get` object (`id`, `kind: "http"`, `scheme: "https"`,
  `authority: "example.com"`, …): `"tunnel": "passthrough"` → `summary.tunnel == .passthrough`, `row.tls == .tunnelled`,
  `row.isTunnel == true`; `"failed"` → `.failed` / `.pinnedOrFailed`; `"decrypted"` → `.decrypted` / `.decrypted`;
  `"tunnel": null` and no key → `tunnel == nil`, `isTunnel == false`, `tls == .decrypted`; `scheme: "http"`, no `tunnel` →
  `.none`; `"tunnel": "passthrough"` with `scheme: "http"` → `.tunnelled` (the wire wins). `tunnel_reason`: each of the eight
  labels → its case; `"something_new"` → nil; absent → nil. `bytes_up: 1234, bytes_down: 56` → `tunnelBytesUp == 1234`,
  `tunnelBytesDown == 56` on summary and row; null/absent → nil. `passive: true` → `true`; absent → `false`.
  `FlowRowEqualityTests`: five new rows — a row differing only in `tunnel` / `tunnelReason` / `tunnelBytesUp` /
  `tunnelBytesDown` / `passive` is `!=`. `FlowDetailWireTests`: `meta.tunnel {mode: "passthrough", reason: "out_of_scope",
  bytes_up: 1, bytes_down: 2}`, `meta.passive: false` → `detail.tunnel == TunnelInfo(mode: .passthrough, reason: .outOfScope,
  bytesUp: 1, bytesDown: 2)`, `detail.passive == false`; `meta.tunnel: null` → nil; `meta.passive` absent → `false`;
  `mode: "weird"` → `tunnel == nil`.
- **Done when:** the tests pass, every other suite still passes (the memberwise-init defaults keep them compiling), the Swift gate is green.

### Task 2: App wiring — `Session.systemProxy` (PR4's to write), `Session.decrypt` + the one `BusService` decode, `Session.trafficRoutes`, `tunnelledFlowCount`, `perform(.addScopeHost)` (no CA wiring, no reader)

- **Satisfies:** TR-AC8 (no CFNetwork anywhere; Kit import rule; the `BusService` decode footprint), the model
  half of TR-AC10(a), TR-AC11 and TR-AC13(a) (the facts reach the views within one poll)
- **Depends on:** Task 1; **gate 3** (its `Session+Connection.swift` edits are granted on PR D's merged SHA —
  PR D edits the same `perform` switch; sequential, never simultaneous); not concurrent with the icons
  plan's Tasks 5/6 (shared `BusService.swift`, `Session.swift`)
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Session.swift` (modify: two stored properties — `systemProxy`, `decrypt`)
  - `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify: **one change-guarded decode** — four added lines, ruling 2026-11-01)
  - `apps/mac/Sources/Aitmproxy/Session+Connection.swift` (modify)
  - **Not created:** `Bus/SystemProxyReader.swift` (withdrawn by the orchestrator 2026-11-01)
- **Change:**

  `Session.swift`: `var systemProxy: SystemProxyState?` — observed, nil at init, doc comment "nil =
  unknown (never rendered as off); written by the system-proxy session's PR4 from
  `proxy.status.system_proxy` and the `proxy.system.set`/`unset` replies — nothing in this app writes
  it until then" (plan call 4; if PR4 has already declared it when this task runs, leave PR4's) — and
  `var decrypt: DecryptStatus?` (observed, nil at init; "nil until the first live read or on an older
  core; `make` ignores it while the bus lane is not `.ok`"). No `caStatus`/`caTrust` here (PR D's).

  `BusService.swift`: in the existing `refreshProxyStatus()`, after the `capturing` and
  `intercept_armed` reads, one decode, change-guarded like the two reads above it (an `@Observable` set
  notifies even on an equal value, and every route surface reads `decrypt`):
  `let decrypt = status["decrypt"].flatMap(DecryptStatus.init)` then
  `if session.decrypt != decrypt { session.decrypt = decrypt }`, with a two-line comment saying why — four
  added lines, `BusService.swift:234–237` (ruling 2026-11-01; the grant's "one line" counted the decode, not
  the guard) — no new verb, no new read (`proxy.status` is already polled every tick), no `defer` reset (spec D3
  ignores a stale value by rule), no `refreshSystemProxy()`, no `refreshCAStatus()`, no `await` added
  to `pollLoop`. An older core without `decrypt` leaves it nil and the Kit falls back to `scopeHostCount`.

  `Session+Connection.swift`: `connectionSummary` passes `systemProxy: systemProxy`, `decrypt: decrypt` and
  `tunnelledFlowCount: rows.count { $0.tls == .tunnelled }` (Task 2b adds `caTrust: caTrust`) — a count
  over `FlowRow.tls`, `AitmproxyKit/Flow.swift` `TLSState.tunnelled`; it is 0 until Task 1c maps the
  wire's `tunnel` field (spec D5); new accessor, the only one of its name in the app target:

  ```swift
  /// The two automatic routes into the proxy (spec D7): what the Flows surfaces read, so no lane
  /// word reaches ShellView and the connectionSummary reader allow-list does not grow.
  var trafficRoutes: TrafficRoutes { connectionSummary.routes }
  ```

  `perform(connection:)`: `case .addScopeHost:` → `show(.scope); scopeSheetVisible = true`, returns `true`.
  PR D's `.trustCA`/`.openCAPanel` cases are already in the switch (gate 3) and are not touched. No
  `.openNetworkSettings` case (denied).

- **Test:** none in Kit by construction. Sandbox structural checks the Coder runs and quotes:
  `grep -rn CFNetworkCopySystemProxySettings apps/mac/Sources | grep -vE ':[0-9]+:[[:space:]]*///'` → **empty**
  (the second grep drops `///` doc comments: PR #246's `SystemProxyState.swift` names the function in two of
  them and calls it nowhere — ruling 2026-11-01);
  `grep -rln 'SystemProxyReader\|refreshSystemProxy' apps/mac/Sources` → empty;
  `grep -rlE '^import (CFNetwork|SystemConfiguration|SwiftUI|AppKit)' apps/mac/Sources/AitmproxyKit` → empty;
  `grep -rn 'var trafficRoutes' apps/mac/Sources/Aitmproxy` → one line, in `Session+Connection.swift`,
  containing `connectionSummary.routes`; `git diff <wave-B-base> -- apps/mac/Sources/Aitmproxy/Bus/BusService.swift`
  → four added lines, all inside `refreshProxyStatus()` (two statements + a two-line comment), no removed
  lines, containing `DecryptStatus.init` and `session.decrypt != decrypt` and no `await` (ruling 2026-11-01);
  `grep -c 'DecryptStatus' apps/mac/Sources/Aitmproxy/Bus/BusService.swift` → `1`;
  `grep -c 'var systemProxy: SystemProxyState?' apps/mac/Sources/Aitmproxy/Session.swift` → `1` and
  `grep -rn 'session.systemProxy =' apps/mac/Sources/Aitmproxy` → empty (nothing of ours writes it);
  `git diff -- apps/mac/Package.swift` → empty. Live proof is Task 6.
- **Done when:** the greps print the values above, the app target compiles (`swift build` in the
  Swift gate run), and the Swift gate is green.

### Task 2b: CA pass-through — `caTrust: caTrust` and the PR D `StatusPanel` hand-over — GATED on gate 3

- **Satisfies:** the model half of TR-AC17 (the CA fact reaches the views within one CA tick — PR D's
  cadence); TR-AC8's `"ca.status"` and `StatusPanel` clauses
- **Depends on:** Task 1b, Task 2 and Task 3 landed (it edits `StatusPanel.swift` after Task 3); not
  concurrent with the icons plan's Tasks 5/6
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Session+Connection.swift` (modify — one argument)
  - `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (modify — remove PR D's interim insertion)
  - **Not touched:** `Bus/BusService.swift` (PR D's `refreshCAStatus()` is the CA read), `Session.swift`
    (PR D's `caTrust`/`caStatus`), `Session+CATrust.swift`, `CAPanel.swift`
- **Change:**

  `Session+Connection.swift`: `connectionSummary` additionally passes `caTrust: caTrust` (PR D's
  `Session.caTrust: CATrustFacts?`, read as is — nil = unknown).

  `StatusPanel.swift` (the PR D hand-over, spec D4/D7): remove the interim `stepsWithCATrust` insertion
  (PR D inserts `session.caTrustStep` **after `busConnected`**, `StatusPanel.swift:131–136` on
  `claude/ca-trust-mac` 4ae616d3) and the `CATrustRow` call (`:91`) that PR D added so its step was
  visible before this spec — **and, with the call gone, the private `CATrustRow` struct itself and the
  `VStack` that wrapped `LaneCard` + the row under the Core card** (the card returns to the bare `LaneCard`
  with its `.frame` and `.gridProbe`; as shipped in `cb9f59be`, stage-6 SP-M4); this spec's `caTrusted` step
  (from `make`, **after `scopeSet`**) and the Flows CA row now carry the same words — the position changes,
  the words do not. PR D's two nil-facts rows
  (`CATrustFacts.unknownStep()`, `notGeneratedStep()`, produced by `Session.caTrustStep` when `ca.status`
  was read but `caTrust` is nil) leave the Getting-started list with the insertion (spec D4, open
  question 21); `Session.caTrustStep` itself and `Shell/SetupSheet.swift` (PR D's first-run sheet,
  which still reads it) are not touched. Nothing else in the file (Task 3's `.help` line and
  `.addScopeHost` case stay).

- **Test:** none in Kit by construction. Sandbox checks: `grep -c 'caTrust: caTrust' apps/mac/Sources/Aitmproxy/Session+Connection.swift`
  → `1`; `grep -rln '"ca.status"' apps/mac/Sources` → the same file set as on PR D's merged SHA (no new
  caller); `grep -rn 'ca.install' apps/mac/Sources/Aitmproxy/Shell apps/mac/Sources/Aitmproxy/Session+Connection.swift apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift`
  → empty; `grep -c 'stepsWithCATrust\|CATrustRow' apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` → `0`;
  `git diff <PR-D-SHA> -- apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` shows only that removal plus
  Task 3's `.help` line and `.addScopeHost` case.
- **Done when:** the greps print the values above, the app target compiles, the Swift gate is green.

### Task 3: The two surfaces — Status step help, Flows empty-state route rows, `RouteBanner`

- **Satisfies:** the view half of TR-AC10, TR-AC11, TR-AC12, TR-AC13, TR-AC17, TR-AC19 (Flows/Status
  buttons, help, the CA row and step with PR D's `.trustCA`, the one-banner-line rule), TR-AC8 (ShellView/StatusPanel diff footprint)
- **Depends on:** Task 2 (not 1b/2b: the views render `routes.caTrust`/`advice` whatever they hold; the
  CA row and step appear by themselves once 1b/2b land — until then PR D's interim `CATrustRow` still
  shows the CA step, and Task 2b removes it)
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Shell/RouteBanner.swift` (create)
  - `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify — two hunks only)
  - `apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` (modify — the `.help` line + one switch case; spec D7 states the whole footprint once)
- **Change:**

  `StatusPanel.swift`: in `StepRow.body`, add `.help(step.detail ?? step.title)` to the row
  (one line). In `run(_:)`, add `.addScopeHost` to the already-handled case list at
  `case .showCoreLog, .reconnectBus, .openScope, .openBrowser, .copyListenAddress, .approveInSystemSettings:`
  (exhaustive switch over the enum; plan call 1; PR D's `.trustCA`/`.openCAPanel` are already handled
  by PR D). Nothing else in the file (the PR D hand-over is Task 2b's).

  `Shell/RouteBanner.swift`:

  ```swift
  /// The one banner line above every flow list (Flows, Pinned, Domains, Apps) while flows exist and a
  /// known route is closed, every row is a tunnel with an empty Scope, or the CA is not trusted (spec D5/D8).
  struct RouteBanner: View {
      var routes: TrafficRoutes                       // stage-6 Q6: read once in MainView.flows and passed in, not re-read here
      @Environment(Session.self) private var session  // for RouteActions.run and caTrustControlLive only
      @Environment(\.openSettings) private var openSettings
      var body: some View   // renders routes.banner / bannerAction / bannerDetail; spells no route word
  }
  ```

  Renders `session.trafficRoutes.banner` (`lineLimit(1)`, `truncationMode(.tail)`,
  `Tok.Size.Row.dense` height — 28 pt, `Tokens.swift:296` — `Tok.Ink.tertiary` ink, `Space.md` horizontal
  padding, a `Rule` under it from the caller — the `ScopeBanner`/`AppsAttributionBanner` shape), `.help` =
  the full `banner` plus `routes.bannerDetail` (the shown entries' `detail`s joined with `" · "`), read from
  the model — never re-derived by walking `advice` against the banner text (ruling 2026-11-01: the first cut's
  `shownEntries` did exactly that and was struck as a second derivation; fixed in a code commit, SHA in the
  Review log) — and **one** `SmallButton(action.title)` for `session.trafficRoutes.bannerAction` (nothing when
  nil — e.g. a lone closed system-proxy fact before PR4), run by `RouteActions.run(_:session:openSettings:)`
  (one function, shared with the empty-state rows): `.trustCA` goes to `session.trustCA()` exactly as
  `StatusPanel.run` does (PR D makes `perform` return `false` for it on purpose — operator-only, like the
  capture switch; the model hides the button once trusted or while installing; shipped in Task 5's commit
  together with its `check-ca-trust-path.sh` allow-list entry — Task 3's cut had routed it through `perform`,
  a no-op), every other action through `session.perform(connection:)`; when that returns `false` and the
  action is `.openCaptureSettings` (the fresh-install button until PR4), set `session.settingsTab = .capture`
  and call `openSettings()` exactly as `AppsAttributionBanner` does (ruling 2026-11-01). The `.trustCA` button
  (banner and empty-state row) is `.disabled(!session.caTrustControlLive)`, as the Status page's was (stage-6 S1;
  fixed in a code commit, SHA to be stamped). Icon + text pairs are a `Label` (stage-6 Q9). Glyph `"network"` (a
  string literal for now — stage-6 Q10 accepted; follow-up in Shipped). The file mentions
  none of `connectionSummary`, `ConnectionSummary`, `LaneDot`, `LaneState`, `CaptureSwitch`,
  `capture.enabled`, `extensionController`, `CaptureAdvice`.

  `ShellView.swift` hunk 1 — `MainView.flows` (spec D8): remove two call sites — the
  `ScopeBanner()` branch (`} else if <scope-empty ∧ bus connected, as the rebased tree has it> {
  ScopeBanner(); Rule() }`) and the Apps block (`if session.page == .apps, session.clients.isEmpty,
  !session.rows.isEmpty { AppsAttributionBanner(); Rule() }`) — and insert, where the Apps block
  was (above `if session.splitView {`):

  ```
  let routes = session.trafficRoutes          // once per render (stage-6 Q6); EmptyFlows gets routes.advice
  if routes.banner != nil {
      RouteBanner(routes: routes)
      Rule()
  }
  ```

  No page condition: the route banner is the only banner on Flows, Pinned, Domains and Apps, and
  with nothing closed no banner renders. The `ScopeBanner` struct (`Panels/ScopePanel.swift`) and
  the `AppsAttributionBanner` struct (this file) stay, unreferenced from `MainView`; `AppsEmptyState()`
  and its condition are untouched.

  `ShellView.swift` hunk 2 — `EmptyFlows`: gains `var routes: [TrafficRoute]` and `var run: (ConnectionAction) -> Void`
  (passed from the `flowTable` overlay call as `routes: routes.advice` from the once-read value and a closure
  that calls `RouteActions.run`; plan call 6 — parameters, not the environment, so the struct is a pure
  function of its inputs: stage-6 Q6/Q7 removed the `@Environment` reads the first cut had added). Unfiltered and
  `routes` non-empty: under "No flows yet", one row per route — glyph (`"network"` for
  `.systemProxy`, `"app.badge"` for `.allApps`, `Tok.Glyph.scope` for `.scope`, `Tok.Glyph.lock` for `.caTrust`), `Text(route.line)`,
  its actions as `SmallButton`s (every action in `route.actions`: the Scope row Add Host… and Open
  Scope…, the All Apps row its one, the CA row Trust the aitmproxy CA and the CA page — PR D's
  `.openCAPanel`, which `perform` handles, and `.trustCA`, which `RouteActions.run` sends to
  `session.trustCA()` — and the system-proxy row **none** until
  PR4 fills `.setSystemProxy`), and `Text(route.detail)` beneath at
  `Tok.Typography.Size.sm`, tertiary ink — **instead of** the generic "Point a client at … or open
  the browser." line. `routes` empty: today's generic line. Filtered: unchanged. Buttons call the
  passed `run` closure, which the caller binds to `RouteActions.run` (the banner's function: `.trustCA` →
  `session.trustCA()`, the rest through `session.perform(connection:)` with the `.openCaptureSettings`
  fallback), so `EmptyFlows` reads no environment of its own (stage-6 Q7). `allowsHitTesting(false)` moves
  from the whole VStack to the text elements so the buttons stay clickable. Nothing else in the file; lines 49–62 and the `ExtensionController(` block
  byte-identical.

- **Test:** none in Kit by construction. Sandbox structural checks the Coder quotes:
  `git diff <wave-C-base> -- apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` shows hunks only
  inside `MainView.flows` and `EmptyFlows` (+ the one-argument change at the `flowTable` overlay
  call, which sits inside `flowTable`, `ShellView.swift:258` — report it as the third hunk, it is the `EmptyFlows`
  call site named in D7); `sed -n 49,62p` before and after identical;
  `grep -cE 'ExtensionController[[:space:]]*\(' …/ShellView.swift` → `1`;
  `grep -c 'ScopeBanner()' …/ShellView.swift` → `0`; `grep -c 'AppsAttributionBanner()' …/ShellView.swift` → `0`;
  `grep -c 'RouteBanner(' …/ShellView.swift` → `1` (the call is `RouteBanner(routes: routes)` after stage-6 Q6); `grep -c 'struct AppsAttributionBanner: View' …/ShellView.swift` → `1`;
  `grep -nE 'connectionSummary|ConnectionSummary|LaneDot|LaneState|CaptureSwitch|capture\.enabled|extensionController|CaptureAdvice' …/Shell/RouteBanner.swift` → empty;
  `git diff <wave-C-base> -- apps/mac/Sources/Aitmproxy/Panels/StatusPanel.swift` is the `.help` line
  and the `.addScopeHost` case, nothing else. `apps/mac/tools/grid-lint.sh` PASS
  (source check). Visual proof is Task 6's screenshots.
- **Done when:** the checks print the values above, the Swift gate is green, `check-capture-operator-only.sh`
  and `check-connection-words.sh` PASS (the latter in its pre-Task-5 form, because no view spells a
  route word), and `check-capture-toggle.sh` fails ONLY on its NS-AC8 banner pins (expected; Task 5
  moves them) — any other failing pin is a defect in this task.

### Task 4: removed 2026-11-01

The orchestrator denied `ConnectionAction.openNetworkSettings` as a product action (Matt: system-proxy
setup happens automatically in the app with the OS's own prompt, never by sending him to System
Settings). With it go the Proxy ▸ "Network Settings…" menu item, the `CommandMap`/`BRIEF.md` rows, the
`GLOSSARY.md` rows and `CommandMapTests` change this task carried; `CommandMap.swift`,
`BRIEF.md` and `GLOSSARY.md` are not touched by this plan (`App.swift` gets Task 5's one-token title change of
2026-11-01, nothing of Task 4's), and the Proxy menu gets only PR4's toggle
(⌥⌘P). `apps/mac/docs/STORIES.md` was never touched (the improve-loop session owns S-073/S-074/S-080).
Spec TR-AC14 is deleted; the task number is kept so the waves and the Review log stay readable.

### Task 5: Words tripwire — route-word prefixes and the one-derivation rule

- **Satisfies:** TR-AC7 (including its `check-ca-trust-path.sh` clause, 2026-11-01)
- **Depends on:** Task 3 (rule 3 needs `trafficRoutes` and `RouteBanner.swift` to exist; the NS-AC8 move needs the new `MainView`); gate 1 (`check-capture-toggle.sh` is granted on the fixture-removal mac SHA)
- **Files:**
  - `apps/mac/tools/check-connection-words.sh` (modify)
  - `apps/mac/tools/check-capture-toggle.sh` (modify — NS-AC8 banner pins only, spec D8; GO 2026-11-01)
  - `apps/mac/tools/check-ca-trust-path.sh` (modify — rule 2's allow-list of `.trustCA(` callers gains `Shell/RouteBanner.swift` with an expect line, header comment updated; agreed with the CA-trust session, orchestrator GO 2026-11-01)
  - `apps/mac/Sources/Aitmproxy/Shell/RouteBanner.swift` (modify — `RouteActions.run` sends `.trustCA` to `session.trustCA()`, as `StatusPanel.run` does; Task 3's cut routed it through `perform`, which PR D makes return `false` for it, so the Flows button did nothing)
  - `apps/mac/Sources/Aitmproxy/App.swift` (modify — one token at `:226`: `Button("Trust the aitmproxy CA")` → `Button(ConnectionAction.trustCA.title)`, so rule 1's new prefix `"Trust the aitmproxy CA` finds no view literal; orchestrator GO 2026-11-01)
- **Change:** spec D9, and in `check-capture-toggle.sh` the NS-AC8 block: `equals "NS-AC8 the banner is rendered exactly once"`
  counts the `RouteBanner(` call (→ 1) and a new `equals "NS-AC8 the old Apps banner is no longer rendered"`
  counts `AppsAttributionBanner()` in `main_body` (→ 0); `main_bcond` matches the banner guard and
  `main_bcall` the call — after stage-6 Q6 the guard reads the once-read value (`if routes.banner != nil {`)
  and the call is `RouteBanner(routes: routes)`, so the two patterns follow the shipped text (the fix commit
  re-runs the tripwire; its PASS line is `cargo test` exit 0, 265 test binaries ok (Terminal, rust-gate.log)); the two `ordered` checks keep their
  meaning (condition guards the call; call above `if session.splitView {`). NS-AC3 struct/body pins and the NS-AC8 empty-state
  pins are untouched. Header comment notes spec D8.
  - Rule 1: a second grep with an opening-quote prefix pattern,
    `prefixes='"(system proxy off|system proxy on|All Apps on|All Apps off|All Apps waiting|All Apps degraded|Nothing is decrypted|Scope:|HTTPS is not captured|Trust the aitmproxy CA|CA trusted|trusting CA|CA trust needs)'`,
    same scan root and exclusions as `words`, same FAIL message family
    ("a view spells a route word; read it from ConnectionSummary.routes instead") — the message names the
    rule that fired and the exclusion list is the one shared variable, not a second copy (stage-6 Q11).
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
     `Text("Nothing is decrypted until a host is in Scope.")` in `Shell/RouteBanner.swift`.
  3. Mutation: add `let _ = session.connectionSummary` to `RouteBanner.swift` → exit 1 (rule 2 and 3);
     the same line in `ShellView.swift` → exit 1 (rule 2).
  4. Mutation: a second `var trafficRoutes: TrafficRoutes { connectionSummary.routes }` in
     `Session+Detail.swift` → exit 1 ("defined 2 times").
  5. `check-capture-operator-only.sh` PASS unchanged; `check-capture-toggle.sh` PASS with the moved
     pins, and FAIL (mutation, reverted) when a second `RouteBanner()` or an `AppsAttributionBanner()`
     call is added to `MainView`.
  6. (2026-11-01) `check-ca-trust-path.sh` PASS with `Shell/RouteBanner.swift` in rule 2's allow-list (its
     expect line finds the one `.trustCA(` call), and FAIL (mutation, reverted) when a `session.trustCA()`
     call is added to `Shell/ShellView.swift`; `check-connection-words.sh` PASS with `App.swift:226` reading
     `ConnectionAction.trustCA.title`, and FAIL (mutation, reverted) when it reads `"Trust the aitmproxy CA"`
     again.
- **Done when:** steps 1–6 print as stated and the tree is restored (`git status` clean of mutations).

### Task 6: Live proof on the real app (Terminal; orchestrating session or Matt)

- **Satisfies:** TR-AC9 (gates on the whole branch), TR-AC10(a), TR-AC11, TR-AC13(a), TR-AC17 (the CA state
  as Matt's Mac has it — the TRUSTED rendering since 2026-11-01, spec TR-AC17 ruling; the not-trusted line
  is TR-AC16's Kit proof), TR-AC19, TR-AC20 (B8, once Task 1c is in). **TR-AC10(b), TR-AC12 and
  TR-AC13(b) — the system-proxy clauses — run on the first build that also contains PR4** and are
  recorded in Shipped then; on this PR's build they are "deferred to PR4", not failed.
- **Depends on:** Tasks 1–5 merged into the branch, Swift gate green, tripwires PASS; the CA clauses
  (A2/A3 CA row, B2 CA row/step, B4 CA-only banner, B7, B8's CA clause) additionally need 1b and 2b —
  without them the CA surfaces render nothing of ours (PR D's interim row still shows the step) and
  those clauses are recorded as deferred, not failed
- **Files:** none in the repo. Evidence under `/tmp/claude/route-advice/` (PNG screenshots,
  `scutil --proxy` dumps, bus replies). The Shipped section records the build each half ran on.
- **Change:** none. **HARD GATE (Matt, via the orchestrator): do NOT run `ca.install` on Matt's
  Mac as part of any proof, do not click Install… on the CA page, and do not click Trust the
  aitmproxy CA.** Trusting the aitm CA on his machine is Matt's decision alone. This task proves the CA
  state **as his Mac has it** — since 2026-11-01 the TRUSTED rendering (spec TR-AC17 ruling: Matt trusted
  the CA himself through PR D's first-run step before Half A ran; `ca.status` user store `trusted: "yes"`,
  `✓ CA trusted (user keychain)`, no CA row or banner clause — B9), with the not-trusted line proved by the
  Kit tests (TR-AC16) and shown live only on a Mac that does not trust the CA; nobody untrusts it to
  recreate that state. Had the Mac not trusted the CA, the install → line-disappears path would be proved
  only after Matt said in his own words that the CA may be trusted, and then only through the app's own
  Status step (PR D's `.trustCA` with its prompts), never a direct verb call from a script.

  Two halves. On this PR's build **nothing is flipped with `networksetup`** — the system proxy is
  unknown to the app until PR4, so there is nothing to observe. The flip recipe below is kept for the
  PR4 build; **every `networksetup` write is Terminal-only, is preceded by recording the originals,
  and is followed by restoring them** (today both enabled services, "Display Ethernet" (en15, primary
  per `route -n get default`) and "Wi-Fi" (en0), carry Proxyman's `127.0.0.1:9090` for HTTP and HTTPS —
  research 22 §5b, `docs/research/22-macos-system-proxy-toggle.md`; verify, do not assume).
  `networksetup` from Matt's admin account showed no dialog in research 22 §5b's single run (one
  observation, not a guarantee: the right's rule includes `authenticate-admin-nonshared`, so expect a
  prompt if "Require an administrator password to access system-wide settings" is on). The operator
  token is read into a shell variable and never printed, echoed, or pasted into a transcript.

  **Setup (both halves)**
  1. `mkdir -p /tmp/claude/route-advice`; `scutil --proxy > …/scutil-before.txt` (for the record; on
     this PR's build it is evidence that the app says nothing about it). On the PR4 build additionally:
     `networksetup -listallnetworkservices > …/services.txt`; for each enabled service
     `networksetup -getwebproxy "<svc>"` and `-getsecurewebproxy "<svc>"` → `…/proxy-before.txt`;
     `route -n get default | awk '/interface:/{print $2}'` → the primary interface, mapped to its
     service name via `networksetup -listnetworkserviceorder`. Expected today: `HTTPEnable : 1`,
     `HTTPProxy : 127.0.0.1`, `HTTPPort : 9090`, HTTPS the same.
  2. Restore recipe (PR4 build; used at the end of each half and after any abort): for each service in
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

  **Half A — "system-proxy step absent until PR4" on the dev bundle** (an early, fast pass; a build
  without the extension, so `routes.allApps == nil` and the Status `extensionOn` step reads "All Apps
  capture is not in this build"). Quit the installed app first (port 8080 would otherwise be taken and
  `L` would not read `127.0.0.1:8080`) — or read `L` from the toolbar pill: the criterion is that every line
  names the address the pill shows, not that it is 8080.

  **As run (ruling 2026-11-01; 12:57–13:02 PST, branch at `8a605948` = Tasks 1, 1b, 1c, 2, 2b, 3, 5):** the dev
  bundle was assembled with the session's own bundle script, not `build.sh --debug` — `/tmp/Aitmproxy-dev-attr.app`,
  a `swift build` of `apps/mac` at that SHA with an embedded release core built from the same tree (v0.5.10, #228
  per-host decryption in), isolated `APP_STORE=/tmp/attr-store`, no extension — and the installed app was **left
  running** on 8080, so **`L` = `127.0.0.1:63109`**, the dev core's ephemeral port; the toolbar pill and every line
  read that address. Evidence folder `/tmp/claude/route-advice/` (`A1-launch.png`, `A2-*.png`, `A3-*.png`,
  `A4-*.png`, `bus-A*.json`, `live-A*.txt`, `scutil-before.txt` — `HTTPEnable 0` / `HTTPSEnable 0`, Proxyman off at
  the time — and `A2-deferred-to-PR4.txt`) and the shared note `traffic-route-live-proof-half-A.md`
  (side-session-notes). What the real app showed: A2 Status — no system-proxy step, `○ All Apps capture is not in
  this build`, `○ Add a host to Scope (for now as example.com:443)` [Open Scope…], `✓ CA trusted (user keychain)`,
  no "off", no "system proxy"; A2 Flows — "No flows yet" with one row, the core sentence + Add Host… / Open
  Scope… and its detail, no CA row (the CA is trusted — TR-AC17 ruling); A3 — two plain-HTTP rows, no banner;
  Clear, `curl https://` → `CONNECT example.com:443`, `tunnel passthrough`, `tunnel_reason out_of_scope`, every row
  a tunnel → exactly ONE banner line, the core sentence + [Add Host…]; `scope.add example.com:443` over the bus →
  banner gone within one poll, Status `✓ Scope: 1 host decrypted`, `decrypt.advice null` / `scope_hosts 1`; the
  next HTTPS → a `tunnel decrypted` row plus the inner `GET https://example.com/` 200; `scope.remove` → `[]`; A4
  Add Host… from the empty state and from the banner → the Scope page with the Edit Scope sheet (the Scope page,
  a flow-list page, shows the one banner above its table — spec D8); TR-AC19 — **one banner row, not two**: the
  column header sat one row lower with the banner than without and no second banner was anywhere (the Half A
  shots were taken at an unknown scale, so they establish the count, not the 28 pt figure — the 28 pt
  measurement is Half B's B4, from the table header's AX frame or a known-scale shot; stage-6 SP-M6); no `ScopeBanner`,
  no "Flows carry no source app" anywhere. No `ca.install`, no Install… click, no Trust click, system proxy not
  touched. Half B runs on the first DMG that contains this PR.
  - A1 Build: `apps/mac/build.sh --debug --replace` with `AITM_CORE_DIR` pointing at a core dir that
    holds `aitm`, `obscura` and `share/aitm/scripts` (coreless-bundle trap: build.sh skips the core
    silently). Verify `ls ~/Applications/Aitmproxy.app/Contents/Resources/core/aitm`. Launch; the
    toolbar pill reads `127.0.0.1:8080`; Status shows Core running, Bus connected.
  - A2 Unknown system proxy (TR-AC10(a), spec D6): with Proxyman's `127.0.0.1:9090` still the real
    system proxy (`…/scutil-before.txt`), the Flows page shows "No flows yet" with the row
    `Nothing is decrypted until a host is in Scope.` (detail line; Add Host…, Open Scope…) — and, once
    2b is in, beneath it the CA row `HTTPS is not captured until the CA is trusted` with its detail and
    its buttons Trust the aitmproxy CA / the CA page, **not clicked** (`ca.status` → `…/bus-A2-ca.json`:
    every store `trusted: "no"` on a Mac that does not trust the CA; on Matt's Mac since 2026-11-01 the user store
    reads `trusted: "yes"`, the row is absent and Status reads `✓ CA trusted (user keychain)` — the TRUSTED
    rendering, spec TR-AC17 ruling; that is what A2 showed). Status: **no** system-proxy step; `○ Add a host to Scope (for now as
    example.com:443)` (Open Scope…); `○ Trust the aitmproxy CA` with its button (not clicked) once 2b is
    in. `grep -c 'system proxy' <(strings of the two screenshots' OCR or the AX dump)` is the Tester's
    choice of method; the requirement is that nowhere does either page mention the system proxy, say
    "off" or "trusted". → `A2-flows.png`, `A2-status.png`, `…/A2-deferred-to-PR4.txt` stating that
    TR-AC10(b)/12/13(b) run on the first PR4 build.
  - A3 Banner, no extension (TR-AC13(a) / D5 "no extension, system proxy unknown" row):
    `curl -x 127.0.0.1:8080 http://example.com/` twice. Flows shows the table and **no** banner (no
    known route is closed, the rows are readable) — or, once 2b is in and the CA is untrusted, exactly
    `HTTPS is not captured until the CA is trusted` with the one button Trust the aitmproxy CA (not
    clicked); no other banner above or below it. → `A3-banner.png`. Edit ▸ Clear, then
    `curl -x 127.0.0.1:8080 https://example.com/` (once Task 1c is in): every row a tunnel → the banner
    reads exactly `Nothing is decrypted until a host is in Scope.` (+ ` · HTTPS is not captured until the
    CA is trusted` with 2b) with the button Add Host… → `A3-tunnels.png`.
  - A4 Actions: Add Host… on the Flows empty state → the Scope page with its add sheet; Open Scope… →
    the Scope page; hover the All Apps / Scope steps on Status → their help. → `A4-*.png`. Quit the dev
    bundle.

  **Half B — All Apps / scope lines and the banner on the installed app** — **runs on the first DMG that
  contains this PR** (ruling 2026-11-01; Half A already covers every clause that does not need the extension) (the notarized build
  containing this change installed in `/Applications`, embedded core running, All Apps on, extension
  attached — a dev build cannot activate the extension and does not count here). System proxy unknown
  to the app (this PR's build).
  - B1 Launch; toolbar All Apps switch on; setup step 3; `scope.list` → `[]` (`…/bus-B1.json`).
  - B2 As found (TR-AC10(a), full): Flows "No flows yet" with the row `Nothing is decrypted until a host
    is in Scope.` (Add Host…, Open Scope…) and its detail line, then (with 2b) the CA row `HTTPS is not
    captured until the CA is trusted` with its detail and its buttons, not clicked (`ca.status` →
    `…/bus-B2-ca.json` — TR-AC17 as ruled 2026-11-01: on Matt's Mac the user store reads `trusted: "yes"`, so
    there is no CA row and Status reads `✓ CA trusted (user keychain)`; the not-trusted row and step appear only
    on a Mac that does not trust the CA). Status: no system-proxy step,
    `✓ All Apps is on`, `○ Add a host to Scope (for now as example.com:443)` (Open Scope…; hover → the
    scope line), and (with 2b) `○ Trust the aitmproxy CA` with its button above the first-flow step —
    PR D's interim `CATrustRow` gone, the words unchanged; hover → the CA detail. Nothing reads
    "trusted", "off" or "system proxy". → `B2-flows.png`, `B2-status.png`.
  - B3 Scope over the bus (TR-AC11): `scope.add example.com:443` (`…/bus-B3-add.json`), no app
    interaction. Within one second both pages drop the scope line; Status `scopeSet` reads `✓ Scope: 1
    host decrypted`. `scope.remove example.com:443` → the line is back on both pages. →
    `B3-after-add-flows.png`, `B3-after-add-status.png`, `B3-after-remove-flows.png`.
  - B4 Banner (TR-AC13(a), TR-AC19): scope `[]`; `curl -x 127.0.0.1:8080 http://example.com/` twice.
    Flows shows the table (plain-HTTP rows are readable and All Apps is on, so the Scope fact is not
    banner material — spec D5) and no banner — or, with 2b and the CA untrusted, ONE line reading
    `HTTPS is not captured until the CA is trusted` with the button Trust the aitmproxy CA. Then the
    operator turns the toolbar's All Apps switch OFF (real click; the one known route closed): the
    banner becomes exactly `All Apps off · Nothing is decrypted until a host is in Scope.` (with 2b:
    `All Apps off · Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted`)
    with the one button All Apps Settings…; no system-proxy words; no "No scope set" `ScopeBanner`
    and no "Flows carry no source app" line anywhere. Pinned, Domains and Apps show the same single
    line (Apps: rows present, Client column "—", exactly one banner). → `B4-flows-banner.png`,
    `B4-domains.png`, `B4-apps.png`. `scope.add example.com:443` (All Apps still off) → the Scope state
    leaves the line (`B4-no-scope-state.png`); switch All Apps back ON → the banner is gone, or is
    exactly the CA-only line (TR-AC17) (`B4-ca-only.png`).
    Header position (TR-AC19): on Apps with the single banner, record the column header's top edge
    (`…/B4-header-with-banner.txt`, from the screenshot's pixel row or the table header's AX frame);
    Edit ▸ Clear → no rows, `banner == nil`, no banner; record again (`…/B4-header-no-banner.txt`);
    the difference is exactly one `Tok.Size.Row.dense` = **28 pt** (56 px in a 2× screenshot), never
    56 pt (two stacked rows); Undo Clear restores the rows and the one banner; a click at the first
    row's y selects row 1 and does not sort (`B4-row1-click.png`). `scope.remove`. The
    "system proxy set to 127.0.0.1:8080 → system-proxy state leaves the line" clause is TR-AC13(b),
    PR4 build.
  - B5 Actions: Add Host… from the Flows empty state → the Scope page with its add sheet; Open Scope…
    → the Scope page; hover the All Apps and Scope steps → help `in-scope hosts of every app` /
    the scope line. → `B5-*.png`.
  - B6 Restore check: `scope.list` → `[]`; `…/B6-restored-flows.png` shows the B2 lines; on the PR4 build
    also `diff proxy-before.txt proxy-after.txt` empty.
  - B7 CA fact, read-only (TR-AC17): `call("ca.status")` → `…/bus-B7-ca.json` quoted in the report
    (stores `user`/`system`: `installed`, `trusted` as the keychain has it — the user store `"yes"` on Matt's Mac
    since 2026-11-01, so the pages render the TRUSTED state: `✓ CA trusted (user keychain)`, no CA row, no CA
    banner clause); the Flows and Status screenshots from B2
    and B4 are the evidence for the line, the step, the buttons present-and-unclicked and the CA-only
    banner. **No `ca.install`, no Install… click, no Trust the aitmproxy CA click, no Keychain Access
    change.**
  - B8 Per-host decryption (TR-AC20; needs Task 1c — without it write `deferred: Task 1c not in
    this build` to `…/B8-deferred.txt` and skip): the installed v0.5.9+ core, `scope.list` `[]`,
    `call("proxy.status")["decrypt"]` → `…/bus-B8-decrypt-before.json` (expected
    `{scope_hosts: 0, decrypting: false, advice: "Nothing is decrypted until a host is in Scope."}`).
    Edit ▸ Clear, then `curl -x 127.0.0.1:8080 https://example.com/` → one row, SSL column in its
    tunnel state, no body; `flow.get` of it → `…/bus-B8-row.json` with `tunnel: "passthrough"`,
    `tunnel_reason: "out_of_scope"`. Banner reads exactly `Nothing is decrypted until a host is in Scope.`
    — on Matt's Mac with the CA untrusted and 2b landed:
    `Nothing is decrypted until a host is in Scope. · HTTPS is not captured until the CA is trusted` with the one button Add Host….
    Edit ▸ Clear → the Flows empty state shows the quoted sentence as its row with Add Host… (and Open Scope…);
    Status `scopeSet` help shows it too. → `B8-tunnel-row.png`, `B8-banner.png`, `B8-empty.png`.
    `scope.add example.com:443` → within one poll the line leaves both pages, `✓ Scope: 1 host
    decrypted`, `…/bus-B8-decrypt-after.json` shows `advice: null`, `scope_hosts: 1`. Export the CA
    PEM to a file (`aitm ca export --format pem --path /tmp/claude/route-advice/ca.pem`, or the CA
    page's Export PEM… — a file write, no keychain change; the hard gate holds), then
    `curl -x 127.0.0.1:8080 --cacert /tmp/claude/route-advice/ca.pem https://example.com/` → a row
    with `tunnel: "decrypted"`, SSL column decrypted, body present (`B8-decrypted-row.png`,
    `…/bus-B8-row-decrypted.json`). `scope.remove example.com:443` → the next `curl https://` row is a
    passthrough tunnel again and the line is back (`B8-after-remove.png`). Safari's HTTPS stays
    under the hard gate (keychain trust); curl `--cacert` is the decrypted-row evidence.
  - B9 — **happened on 2026-11-01, by Matt's own hand:** he trusted the aitm CA through PR D's first-run step
    (the app's own Trust the aitmproxy CA, with its prompts) before Half A ran; no session clicked or called
    anything. The observation this step wanted — `ca.status` user store `trusted: "yes"`, Status `✓ CA trusted
    (user keychain)`, no CA line in the empty state or the banner — is Half A's A2 evidence (`bus-A2-ca.json`,
    `A2-status.png`, `A2-flows-empty.png`) and is re-read on Half B's build. Shipped records it so.

  **PR4 addendum (first build containing PR4; recorded in Shipped, not a gate for this PR):** repeat
  setup steps 1–2 in full and run TR-AC10(b) (the `.other` row/step with PR4's Set as System Proxy
  button), TR-AC12 (off → this core → 8081 → restored, with `scutil` dumps) and TR-AC13(b) (the
  composed line starting `system proxy on · 127.0.0.1:9090, not this core · All Apps off · …`, then the
  system-proxy state leaving it once the proxy points at 8080). Same evidence folder, `P-` prefix.

  **Whole-branch gates (TR-AC9)**: Swift gate green; `apps/mac/build.sh --ne --allow-unnotarized
  --replace` log shows no warnings; the three tripwires PASS; Rust gate green.

  **Gate record for the stage-6 head commit `6ebc9e8f`** (orchestrating session, Terminal,
  `/tmp/claude/attr/gate-routes.log`, header `== 6ebc9e8f Sun Nov  1 13:41:15 PST 2026`; stage-6 SP-I2):

  ```
  ✔ Test run with 624 tests in 77 suites passed after 0.922 seconds.
  ✔ Test run with 31 tests in 6 suites passed after 0.595 seconds.
  swift-test-exit=0
  PASS check-connection-words
  check-connection-words-exit=0
  PASS check-capture-operator-only (6 agent-reachable surfaces checked)
  check-capture-operator-only-exit=0
  PASS check-capture-toggle
  check-capture-toggle-exit=0
  PASS check-ca-trust-path (9 agent-reachable surfaces checked)
  check-ca-trust-path-exit=0
  PASS grid-lint
  grid-lint-exit=0
  ```

  Rust gate at `6ebc9e8f` (Terminal): `FMT_OK`, `CLIPPY_OK`; `cargo test` result quoted in the PR panel
  comment. The stage-6 fix commit re-runs the same gate; its lines are `cargo test` exit 0, 265 test binaries ok (Terminal, rust-gate.log) and
  its SHA stamped into the Review log.
- **Test:** the screenshots and files above exist and show the literal lines named; the Tester's
  report quotes the `scutil` dumps, the bus replies and (PR4 build) the `diff` result.
- **Done when:** every TR-AC10(a)/11/13(a)/17/19 clause has its named file, `A2-deferred-to-PR4.txt`
  names the deferred clauses, the proxy settings are untouched on this PR's build (restored, `diff`
  empty, on the PR4 build), the whole-branch gates are green, and the whole-branch Tester and panel
  have no open findings.

---

## File-disjointness table

| File | T1 | T1b | T2 | T2b | T3 | T5 | T6 |
|---|---|---|---|---|---|---|---|
| `AitmproxyKit/SystemProxyState.swift`, `Tests/AitmproxyKitTests/SystemProxyStateTests.swift` | — **PR #246** (gate 5); read-only here | | | | | | |
| `AitmproxyKit/DecryptStatus.swift` (new), `Tests/AitmproxyKitTests/DecryptStatusTests.swift` (new) | C | | | | | | |
| `AitmproxyKit/FlowSummary.swift`, `AitmproxyKit/Flow.swift`, `AitmproxyKit/FlowDetail.swift`, `AitmproxyKit/FlowDetail+Wire.swift`, `Tests/…/FlowSummaryTests.swift` (new), `FlowRowEqualityTests.swift`, `FlowDetailWireTests.swift` | — **Task 1c** (gate 4 GO); no other task touches them | | | | | | |
| `AitmproxyKit/ConnectionSummary.swift` | M | M (after T1 landed) | | | | | |
| `Tests/AitmproxyKitTests/ConnectionSummaryTests.swift` | M | M (after T1 landed) | | | | | |
| PR D's `CATrustFacts` (Kit), `AitmproxyKit/Panels/CAStatus.swift`, `Session+CATrust.swift`, `Panels/CAPanel.swift` | — PR D (gate 3); read-only here | | | | | | |
| `Aitmproxy/Bus/BusService.swift` (one change-guarded decode, four lines) | | | M | | | | |
| `Aitmproxy/Session.swift` (two properties) | | | M | | | | |
| `Aitmproxy/Session+Connection.swift` | | | M (on PR D's SHA) | M (after T2) | | | |
| `Aitmproxy/Shell/RouteBanner.swift` (new) | | | | | C | M (`.trustCA` → `session.trustCA()`, after T3) | |
| `Aitmproxy/Shell/ShellView.swift` (two hunks + the `EmptyFlows` call; two old banner call sites removed) | | | | | M | | |
| `Aitmproxy/Panels/StatusPanel.swift` (`.help` line + `.addScopeHost` case; PR D hand-over removal) | | | | M (after T3) | M | | |
| `apps/mac/tools/check-connection-words.sh` | | | | | | M | |
| `apps/mac/tools/check-capture-toggle.sh` (NS-AC8 banner pins; on the fixture-removal mac SHA) | | | | | | M | |
| `apps/mac/tools/check-ca-trust-path.sh` (rule 2 allow-list + expect line for `Shell/RouteBanner.swift`; GO 2026-11-01) | | | | | | M | |
| `Aitmproxy/App.swift` (one token at `:226`, `ConnectionAction.trustCA.title`; GO 2026-11-01) | | | | | | M | |
| (no repo files; `/tmp/claude/route-advice/`) | | | | | | | — |

C = create, M = modify. A file in two columns is edited by the later task only after the earlier one
has landed (T1→T1b, T2→T2b, T3→T2b, T3→T5 on `RouteBanner.swift`); no two tasks edit a file concurrently. T1b may run beside Wave
C/D. Shared with the sibling icons plan on this branch: `Bus/BusService.swift`, `Session.swift` (its
Tasks 5/6) — sequence, never concurrent; the icons PR ships second. Not touched by anyone here:
`CaptureAdvice.swift`, `CaptureCapability.swift`, `Package.swift`, `UI/Tokens.swift`,
`Bus/ExtensionController.swift`, `Panels/ScopePanel.swift`, `AitmproxyKit/CommandMap.swift`,
`apps/mac/docs/BRIEF.md`, `apps/mac/docs/GLOSSARY.md`, `apps/mac/docs/STORIES.md` (improve-loop session),
`Bus/SystemProxyReader.swift` (never created), `apps/mac/Extension/**`, `crates/**`.

## Acceptance-criteria coverage

| TR-AC | Class | Task |
|---|---|---|
| 1, 2 | K (contract) | PR #246's `SystemProxyStateTests` (gate 5); Task 1 reports if a literal is unpinned |
| 3 (quoted, fallback, stale list, bus not `.ok`), 4, 5 | K | 1 |
| 6 | K | 1 (`addScopeHost`, the `allCases` witness list) |
| 7 | T | 5 (write + mutations, incl. `check-ca-trust-path.sh` — 2026-11-01), 3 (pre-form PASS), 6 (whole branch) |
| 8 | structural | 2 (no CFNetwork — the `///`-filtered grep, Kit imports, the `BusService` decode footprint, `Package.swift`), 3 (ShellView footprint), 2b (`"ca.status"` set, StatusPanel footprint) |
| 9 | gates | every wave (Swift), 6 (release build warnings, Rust) |
| 10 | L | 6 — (a) A2 on the dev bundle, B2 on the installed app; (b) PR4 addendum |
| 11 | L | 6 (B3) |
| 12 | L | 6 — PR4 addendum only (deferred on this PR's build) |
| 13 | L | 6 — (a) A3 no-extension, B4 composed banner with All Apps off, no old banners; (b) PR4 addendum |
| 14 | — | deleted 2026-11-01 (its surviving clauses are in 10(a): A4, B5) |
| 15 | K (contract) | PR D's `CATrustFacts` tests; gate 3 |
| 16 | K | 1b (`caTrust*` tests in `ConnectionSummaryTests`) |
| 17 | L | 6 (A2/A3 on the dev bundle; B2/B4/B7 on the installed app) — the CA state as Matt's Mac has it: the TRUSTED rendering since 2026-11-01 (`✓ CA trusted (user keychain)`, no CA row or banner clause, `ca.status` user `trusted: "yes"`; spec TR-AC17 ruling); the not-trusted row/step/banner are TR-AC16's Kit proof (Task 1b) and show live only on a Mac that does not trust the CA; hard gate (no `ca.install`, no clicks) unchanged; needs 1b/2b (gate 3) |
| 18 | K | 1 (`composedBanner`), 1b (`composedBannerWithCA`) |
| 19 | L | 6 (B4 header measurement against `Tok.Size.Row.dense` = 28 pt, one banner on all four list pages), T (Task 5 NS-AC8 pins) |
| 20 | L | 6 (B8; unconditional once Task 1c is in, else recorded as deferred) |
| 21 | K | 1 (`DecryptStatusTests`, quoted/fallback cases in `routesAdviceAndBanner`) |
| 22 | K | 1c (`FlowSummaryTests`, `FlowRowEqualityTests`, `FlowDetailWireTests`) |

## Plan-level calls (for Matt or the orchestrator to overturn; none blocks)

1. **The `StatusPanel` footprint is three things, stated once in spec D7:** the `.help` line on `StepRow`
   (Task 3); `.addScopeHost` in `run(_:)`'s handled-by-`perform` list (Task 3 — the switch over
   `ConnectionAction` is exhaustive); and the removal of PR D's interim `stepsWithCATrust`/`CATrustRow`
   insertion (Task 2b). TR-AC8 says the same; the spec-reviewer should read the diff so.
2. `ConnectionAction` gains `CaseIterable` so TR-AC6's witness list is a real `allCases ==`
   comparison instead of a hand-maintained list. Additive; PR D's cases and, later, PR4's show up in
   `allCases`, which is the point.
3. `SystemProxyState.Endpoint.address` is computed (`"\(host):\(port)"`), not stored, with the
   memberwise `Endpoint(host:port:)` — now PR #246's shape; this plan declares nothing of the type.
4. `Session.systemProxy: SystemProxyState?` is **declared by Task 2 and written by no code of ours**
   (nil = unknown, never "off"); PR4 writes it. Declaring it here lets `connectionSummary` compile
   before PR4 lands; if PR4 has declared it first, Task 2 leaves PR4's. (Replaces the earlier
   `SystemProxyReader.read()` nil-vs-`.off` call: there is no reader.)
5. No disconnect resets in `BusService` (the grant is one decode, change-guarded): `make` ignores `decrypt` while the
   bus lane is not `.ok` (spec D3), and `advice`/`banner` are already empty then; the Status list
   returns to its pre-connect shape by that rule, not by a `defer`.
6. `EmptyFlows` takes `routes: [TrafficRoute]` as a parameter from the existing overlay call rather
   than reading the environment, so it stays a function of its inputs; it still needs the
   environment `Session` for its buttons' `perform`.
7. (Superseded 2026-11-01.) There is no Proxy ▸ Network Settings… item: `.openNetworkSettings` was
   denied; the Proxy menu gets only PR4's toggle (⌥⌘P).
8. Half A of the live proof runs on a dev bundle with a real core (as run 2026-11-01: the session's own bundle
   script, not `build.sh --debug`; the installed app left running, so `L` was the dev core's ephemeral
   `127.0.0.1:63109`) and is the evidence for TR-AC10(a)/13(a)'s no-extension rows; Half B runs on the first
   DMG that contains this PR. The system-proxy clauses (TR-AC10(b)/12/13(b)) run once on the first PR4 build and are
   recorded in Shipped. If a notarized build is available when Half A runs, re-run A2–A3 on it too
   so all evidence sits on one build, and say which in Shipped.
9. The CA cadence is PR D's (`BusService.caStatusEveryTicks = 10`, first tick, forced after
   `trustCA()`/`untrustCA()`); this plan adds no CA read. A trust change made in Keychain Access or by
   `aitm ca install` from a terminal reaches both pages within ~5 s through PR D's poll.
10. `CATrustFacts(status:)` is PR D's and failable (nil when every store is unknown or the certificate
    does not exist), so unknown renders as unknown (no step, no line), never as not trusted. Task 1b
    consumes PR D's `text`/`actions`/`step` helpers; if a helper's string differs from spec D2a, the
    spec is amended first and the literal follows PR D (gate 3 records the mapping).
11. The `caTrusted` step's action and the Flows CA row's primary button are PR D's `.trustCA` (title
    "Trust the aitmproxy CA", PR D's confirm and admin prompts); `.openCAPanel` is the row's second
    button; this plan declares neither. The CA page stays reachable from the sidebar and Proxy ▸
    Certificate Authority….
12. `check-capture-toggle.sh` is edited in Task 5 (NS-AC8 banner pins → `RouteBanner()`; GO on the
    fixture-removal mac SHA), so Task 3 is expected to leave exactly those pins red until Task 5
    lands; the waves stay as drawn (C then D), and the whole-branch run must be green. The
    `AppsAttributionBanner` struct is kept, not deleted, so the NS-AC3 body pins and the
    `CaptureAdvice.banner` tests stay untouched; deleting them is a later cleanup.
13. Per-host decryption (spec amendment): `routes.scope` is its own entry; All Apps is open whenever
    the extension is on (the Scope entry owns the empty-scope clause, so the composed banner never
    repeats it); `tunnelledFlowCount` is counted in `Session+Connection` from `FlowRow.tls ==
    .tunnelled` and is 0 until **Task 1c** (gate 4, GO 2026-11-01) maps the wire's `tunnel` field —
    Task 2 adds no wire parsing itself. `STORIES.md` is nobody's here: the improve-loop session owns
    S-073/S-074/S-080.
14. **Split for PR D.** Task 1 lands the system-proxy / All Apps / Scope model with the `.caTrust`
    kinds declared but never produced; Task 1b/2b add the CA slot, derivation and pass-through once
    PR D is on `main`. Because Task 2's `Session+Connection.swift` grant is on PR D's SHA, Waves B–E
    follow gate 3 in practice and the whole plan ships as one PR; the two-PR split is the fallback if
    PR D slips (a fresh grant for `Session+Connection.swift` on the pre-PR-D tree would be asked for
    then). If gate 3 is already met when Wave A starts, 1 and 1b may be one Coder sitting (same
    files, same tests).
15. `DecryptStatus` is a Kit value decoded from the `proxy.status` object `BusService` already polls,
    not a `decryptAdvice: String?` beside `scopeHostCount`: one object gives N, the flag and the
    sentence from one read (no `scope.list` for N), an older core yields nil → fallback strings,
    and the parser is a pure test. The banner text is states only (core spec D9: print the core's
    sentence verbatim, never compose); the quoted sentence keeps its period inside a composed line;
    the remedy is the one button `bannerAction`, `Add Host…` (`.addScopeHost`, new) for Scope.
16. Task 1c decodes all five #228 fields onto `FlowSummary` and `FlowRow` (and `FlowDetail.tunnel`),
    with the names agreed with the improve-loop session, so its inspector consumes our Kit names;
    this plan renders none of them beyond `tls`.

## Questions for Matt / the orchestrator

- **Q1 (claim) — resolved 2026-11-01.** The orchestrator's answers are recorded in gate 2
  (`check-capture-toggle.sh` GO; `BusService.swift` one line; `Session+Connection.swift` GO on PR D's
  SHA; `.openNetworkSettings` denied; no reader; `Session.swift` two properties; STORIES/GLOSSARY/
  BRIEF/CommandMap untouched; `App.swift` later granted one token, 2026-11-01) and gate 5 (PR #246). Sequencing with the icons plan's Tasks
  5/6 on `BusService.swift` / `Session.swift`: this PR first; the icons plan's gate 4 records it.
- **Q2 (evidence build) — as run 2026-11-01.** Half A ran on a dev bundle with a real core (Task 6 "As run";
  `L` = `127.0.0.1:63109`) and stands as the TR-AC10(a)/13(a) no-extension evidence; Half B runs on the first DMG
  that contains this PR. Still Matt's to overturn: whether the PR4 addendum (TR-AC10(b)/12/13(b)) is acceptable as
  a Shipped-section entry rather than a gate for this PR (assumed yes).
- **Q3 (PR D, CA init) — resolved 2026-11-01.** PR D's `CATrustFacts(status:)` is failable; its
  fields/helpers are recorded in gate 2. Open only in detail: which helper is the CA entry's `line`
  (`state` assumed) — confirmed when gate 3 is recorded.
- **Q4 — resolved 2026-11-01 by Matt's own action.** Matt trusted the aitm CA on his Mac himself (PR D's
  first-run step) before Task 6 ran; TR-AC17's live form is therefore the TRUSTED rendering (spec TR-AC17 ruling)
  and B9 records it. No session clicked or called anything.
- **Q5 — resolved 2026-11-01.** The core story shipped as PR #228 (v0.5.9); the `FlowSummary` →
  `.tunnelled` mapping is Task 1c here (gate 4 GO).
- **Q6 (orchestrator, gate 3).** PR D's number and merge SHA, and confirmation that its
  `CATrustFacts` helpers return spec D2a's strings (`text`: the lines; `actions`:
  `[.trustCA, .openCAPanel]` when not trusted, `[.openCAPanel]` when needs admin or trusted, `[]` when installing; `step`:
  "Trust the aitmproxy CA"); if its shape differs, spec D2a is amended first and Task 1b follows the
  merged shape.
- **Q7 (orchestrator, gate 4) — resolved 2026-11-01.** GO on the four Kit files ("Coordinator
  contract for Task 1c" below).

## Coordinator contract for Task 1c (orchestrator, 2026-11-01, GO on the four Kit files)

- Files held by this session: `AitmproxyKit/FlowSummary.swift`, `Flow.swift`, `FlowDetail.swift`,
  `FlowDetail+Wire.swift` and their tests (last written by #195 and #212; improve-loop's S-080 only
  consumes them: `Session.swift` counters region, `StatusBar.swift`, `Panels/OverviewPanel.swift`).
- Wire contract (spec `2026-10-31-per-host-decryption-design.md` D7/D9): the wire `tunnelled` mark is
  retired; `tls` derives from `tunnel` (decrypted / passthrough / failed with `tunnel_reason`); failed
  rows have `status` null, established ones 200, `duration_ms` on close; pushes arrive as `created`
  then `response`; request counters exclude tunnel rows (improve-loop owns the counters).
- Add-to-Scope is offered only when `tunnel == passthrough && tunnel_reason == out_of_scope`, or
  `passive == true`; never on `pinned`. (The per-row offer is improve-loop's inspector; the banner's
  `Add Host…` button follows the Scope fact, not a row.)
- `proxy.status.decrypt.advice` is quoted verbatim whenever present; the fallback strings are only
  for a core that lacks the field.
- Definition of ready (unchanged): real app over the real bus against a core at or after 448e75e
  (installed 0.5.9 or a dev bundle with that core): empty Scope + `curl -k` to an https host shows a
  passthrough row with reason `out_of_scope`; `scope.add` that host and the next connection shows
  decrypted; a client that rejects the MITM certificate shows failed / `client_rejected_certificate`.
  No fixture or sample-data evidence anywhere; the PR body states the live proof; the stage-6 panel
  comment (security / quality / spec + dispositions) is on the PR; then "ready <sha>" to the
  orchestrator with main merged in.

## Review log

Kept by the main session during stage 6. One row per finding. Rows dated 2026-11-01 are the stage-6
panel on docs PR #242 (range `dac90fe9..0bad920f`, merged as `7a5f8585`), fixed in the follow-up
docs PR from this branch. Rows whose Reviewer reads "Tester (whole branch)" or "Architect (amendment)" are the
2026-11-01 stage-5 Tester pass and the docs amendment pass on the shipped code (`58724ef7..e60a13e8`, commits
`ce296c83` … `e60a13e8`); a "fixed in <code commit>" disposition gets its SHA stamped by the orchestrator when the
coder's commit lands. Rows whose Task reads "PR #265" are the **stage-6 panel on the shipped code** (range
`58724ef7..6ebc9e8f`, PR #265; security PASS with 3 Minor, quality PASS with 14 Minor, spec FAIL with 2 Important
and 5 Minor); "fixed in <code commit> (SHA to be stamped)" is the one stage-6 fix commit, stamped by the
orchestrator; "accepted" rows carry the orchestrator's 2026-11-01 ruling and, where one is owed, the follow-up
named in Shipped.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| docs #242 | spec | Critical | #1 CA fact actions defined two incompatible ways ("reserved, no button" vs `[.trustCA, .openCAPanel]`) | fixed in 644b9c90: post-PR-D state everywhere — the CA entry carries PR D's `actions` (`[.trustCA, .openCAPanel]`), the `caTrusted` step's action is `.trustCA`, the CA-only banner button is `.trustCA`; every "reserved / no button" sentence removed from Non-goals, Constraints, D2, D2a, D4, D10, TR-AC6/16/17, plan Task 1b, plan call 11 |
| docs #242 | spec | Important | #2 TR-AC3 pins both `[.openScope]` and `[.addScopeHost, .openScope]` | fixed in 644b9c90: one list, `[.addScopeHost, .openScope]`; TR-AC10's button list and plan Task 1b aligned |
| docs #242 | spec | Important | #3 D10 and Task 1b carry the retired "— remedy" suffix; `advice` list lacks `scope`; Scope closed actions written two ways | fixed in 644b9c90: D10 banner cells are states only; Task 1b `advice` = `[systemProxy, allApps, scope, caTrust]`, one Scope action list, no remedy clause |
| docs #242 | spec | Important | #4 "Scope closed" derived two ways (D3 vs D5) | fixed in 644b9c90: D5 `scopeClosed ⇔ !routes.scope.open`, D2 doc and Task 1 comment aligned; the stale-list banner case added to TR-AC3 and Task 1's test |
| docs #242 | spec | Important | #5 numeric-string Port dropped from the plan, no test | fixed in 644b9c90: TR-AC1 gains `"HTTPPort": "9090"` → 9090 and `"abc"` → nil; the test lives in PR #246's suite (gate 5) and Task 1 reports if it is unpinned |
| docs #242 | spec | Important | #6 Task 4 anchors CommandMap/BRIEF on a "Scan" entry that does not exist there | superseded in 644b9c90: Task 4 removed — `.openNetworkSettings` denied by the orchestrator 2026-11-01; no CommandMap/BRIEF/GLOSSARY insertion remains |
| docs #242 | spec | Important | #7 footprint exceeds the recorded grant; gate Q1 open | fixed in 644b9c90: gate 2 records the orchestrator's answers of 2026-11-01 (`check-capture-toggle.sh` GO; `BusService.swift` one line; `Session+Connection.swift` GO on PR D's SHA; `.openNetworkSettings` denied; no reader) and gate 5 (PR #246); Q1 marked resolved |
| docs #242 | spec | Important | #8 icons plan lacks the "traffic-route PR first" gate and the BusService/Session serialisation; both plans say one PR | fixed in 644b9c90: icons plan gate 4 ("traffic-route PR merged, SHA ___; Tasks 5/6 after traffic-route Tasks 2/2b"); both plans state two PRs from this branch, traffic-route first |
| docs #242 | spec | Minor | #9 AC ordinals diverge from ids (6a/6b/15…) | fixed in 644b9c90: ordinals = ids; TR-AC15/16 moved after TR-AC14; TR-AC14 kept as a dated tombstone |
| docs #242 | spec | Minor | #10 "existing 16 cases" is 14 | fixed in 644b9c90 |
| docs #242 | spec | Minor | #11 Task 1b tests say `.caTrust` for the step kind | fixed in 644b9c90: `.caTrusted` for the step everywhere; `TrafficRoute.Kind.caTrust` unchanged |
| docs #242 | spec | Minor | #12 Task 1 both "declares" `.caTrusted` and says PR D provides it | fixed in 644b9c90: Task 1 declares the route kinds only; PR D's enum cases are left as found and never added |
| docs #242 | spec | Minor | #13 spec D7 lists STORIES.md S-073; plan says not touched | fixed in 644b9c90: STORIES.md removed from D7 and the claim list; "not touched" everywhere |
| docs #242 | spec | Minor | #14 `proxy.system.*` verbs described as future | fixed in 644b9c90: on `main` as PR #214 (`3d710ab7`); the mac toggle and `.setSystemProxy`/`.unsetSystemProxy` are PR4's |
| docs #242 | spec | Minor | #15 unreachable banner case (All Apps as highest-priority shown fact) | superseded in 644b9c90: with the system proxy unknown until PR4, All Apps is the first shown fact of the fresh install; D5 restated as `knownOpenRoute` and TR-AC18 pins `.openCaptureSettings` for it |
| docs #242 | spec | Minor | #16 RouteBanner doc comment pre-widening | fixed in 644b9c90 (spec D7, plan Task 3): every list page, the D5/D8 rule |
| docs #242 | spec | Minor | #17 stale line anchors (Session.swift post-#197; icons plan base `5eac2a5`) | fixed in 644b9c90: icons spec cites Session.swift by symbol with `main 8e19c2e3` lines; both plans' base is `main 8e19c2e3`; ShellView anchors refreshed |
| docs #242 | spec | Minor | #18 Status lines lack the 2026-11-01 amendment approval date | fixed in 644b9c90: both specs and both plans read "amended 2026-11-01 (self-approved, autonomous mode)" |
| docs #242 | spec | Minor | #19 `Endpoint.address` stored in the spec, computed in the plan | fixed in 644b9c90: computed in spec D2/D2a and plan call 3 (PR #246's shape) |
| docs #242 | quality | Important | TR-AC3 two action lists (overlaps spec #2) | fixed in 644b9c90, see spec #2 |
| docs #242 | quality | Important | CA actions "reserved" vs used (overlaps spec #1) | fixed in 644b9c90, see spec #1 |
| docs #242 | quality | Important | `.caTrust` vs `.caTrusted` step kind, six places (overlaps spec #11) | fixed in 644b9c90, see spec #11 |
| docs #242 | quality | Important | D10 remedy suffix (overlaps spec #3) | fixed in 644b9c90, see spec #3 |
| docs #242 | quality | Important | `scopeClosed` derived two ways (overlaps spec #4) | fixed in 644b9c90, see spec #4 |
| docs #242 | quality | Important | Task 4 "Scan" anchor (overlaps spec #6) | superseded in 644b9c90, see spec #6 |
| docs #242 | quality | Important | `Tok.Size.Row.dense` is 28 pt, not 40 (Tokens.swift:296); TR-AC19's "40 / never 80" cannot pass; D8's measurement uncited | fixed in 644b9c90: D5, D8, TR-AC19, plan Task 3 and B4 say 28 pt / 56 for two and cite `Tokens.swift:296`, `ScopePanel.swift:268`, `ShellView.swift:368`; D8 states only that the old banners use that token and that TR-AC19 measures the header offset against it |
| docs #242 | quality | Important | icons spec cites Session.swift:479-483 / :524-527 / :529-549 (post-#197 they moved) | fixed in 644b9c90: cited by symbol — `Session.clients` :343, `show(_:group:)` :388, `pin` :393 / `unpin` :400 / `isPinned` :408 on `main 8e19c2e3` |
| docs #242 | quality | Minor | research 21/22 H1 titles say 13/14; 22 never cites `16-system-proxy.md`; bare "research 12" points at a branch-only note | fixed in 644b9c90: titles 21/22; research 22 cites 16-system-proxy.md; the observe-lane note cited by file and branch (`12-macos-observe-only-lane.md` on `claude/heuristic-pare-835491`; on `main` 12 is the L4 parity audit) |
| docs #242 | quality | Minor | unlabelled inferences (sub-millisecond read, primary-service rule, NSNumber, Network-Settings URL, ~8 spawns/s, `exec` icon, "never prompts") | fixed in 644b9c90: the read and the URL are gone with the reader and the denial; the primary-service rule cites research 22 §2.4 as inference; NSNumber marked unverified; the spawn rate marked inference (~4/s); the `exec` icon marked unverified (icons spec D9); "never prompts" rewritten as one observation (research 22 §5b, plan Task 6) |
| docs #242 | quality | Minor | stale sentences (ScopeBanner "yields", OQ14, four base SHAs, call 13 vs Task 1c, RouteBanner comment, "PR B is not released", icons gate 1 blank) | fixed in 644b9c90: call site removed (not "yields"); OQ14 says PR #228 landed; branch base `main 8e19c2e3` everywhere (PR SHAs kept where they identify a PR); call 13 points at Task 1c; RouteBanner comment widened; "PR B is released (v0.5.9)"; icons gate 1 = `3fe92f66` |
| docs #242 | quality | Minor | numbering/ordering (AC ordinals; calls 1–11,15,16,14,13,12; Q1,Q2,Q3,Q7,Q6,Q5,Q4; Task 6 B6,B8,B7 and "B8"/"B9"; "Six tasks in five waves"; "16 cases") | fixed in 644b9c90: ordinals = ids; calls 1–16 in order; Q1–Q7 in order; Task 6 steps B1–B9 unique and ordered; "Eight tasks in eight waves"; 14 cases |
| docs #242 | quality | Minor | STORIES.md both edited (spec D7) and "not touched" (plan) | fixed in 644b9c90: not touched, everywhere |
| docs #242 | quality | Minor | StatusPanel footprint counted three ways | fixed in 644b9c90: stated once in spec D7 (`.help` line + `.addScopeHost` case + PR D hand-over); TR-AC8, Tasks 3/2b, the file table and call 1 refer to it |
| docs #242 | quality | Minor | icons plan `subItem(… mark: Monogram(text: "◎"))` vs the declared `@ViewBuilder mark: () -> Mark` | fixed in 644b9c90: `mark: { Monogram(text: "◎") }` in the icons spec D5 and plan Task 5 |
| docs #242 | quality | Minor | research 22 line citations drifted (proxy.rs:331-336 → :360; build.sh:169-205 → :241) | fixed in 644b9c90 |
| docs #242 | quality | Minor | Swift gate scratch paths differ between spec ACs and plans | fixed in 644b9c90: spec TR-AC9 = plan (`test-build-routes`); icons AI-AC23 = plan (`test-build-icons`) |
| docs #242 | spec (2nd pass) | Important | gate 2's PR #246 bullet contradicted gate 5 (`init?(compact:listenAddress:)` ships in #246) | fixed in 2ce11b30 |
| docs #242 | spec (2nd pass) | Minor | gate 5 head/test count stale (c8ed92f4 / 31 tests); Review-log rows lacked the fix SHA | fixed in 2ce11b30 |
| docs #242 | spec (2nd pass) | Minor | residual: PR #246's two listen-address vectors (bare IPv6 literal without brackets → nil; `:::8080` → nil, the core prints `[::]:8080`) missing from TR-AC2 | fixed in b57840e3: both literals added to TR-AC2 |
| docs #242 | quality (2nd pass) | Important | PR D's API mis-cited against `CATrustFacts.swift` 4ae616d3: the line helper is `text` (PR D's `state` is a `LaneState`); `needsAdmin` → `actions == [.openCAPanel]` and step action `.openCAPanel`; the string is `"CA trusted (System keychain)"`; the needs-admin line is `text`, not `remedy`; `platform: String` has no default | fixed in b57840e3: spec Constraints, D2, D2a, D3, D4, TR-AC16 and plan Task 1b quote PR D verbatim (`line` = `text`; needs-admin `[.openCAPanel]`; capital S; `platform: "macos"` in every test value; an open CA entry stores `actions = []`) |
| docs #242 | quality (2nd pass) | Minor | hand-over position unstated (PR D inserts the CA step after `busConnected`; ours sits after `scopeSet`); PR D's nil-facts rows (`unknownStep()` / `notGeneratedStep()`) undecided | fixed in b57840e3: D4 and Task 2b state the move; the nil-facts rows are dropped from the list (Architect's call, open question 21 — `make` reads `Session.caTrust` alone; the first-run sheet and CA page keep them) |
| docs #242 | quality (2nd pass) | Minor | Amendments-log preamble named only four superseded items | fixed in b57840e3: the preamble names every superseded item (predicate names, `— set …` suffix, period handling, `… — add one`, start SHA `8175eea3`, `Open Network Settings…` as a button, our own `CATrustFacts.remedy` contract) |
| docs #242 | quality (2nd pass) | Minor | Goal "the same actions" vs the All Apps route `[.openCaptureSettings]` and step `.turnCaptureOn` | fixed in b57840e3: "the same lines; each step keeps its existing action" |
| docs #242 | quality (2nd pass) | Minor | D6 "~2 s effective" (the poll is 500 ms, `refreshProxyStatus()` every tick) | fixed in b57840e3: dropped, cadence stated as the 500 ms tick |
| docs #242 | quality (2nd pass) | Minor | icons spec AI-AC11 `Overview(rows:).clients` — the type is `OverviewStats` | fixed in b57840e3 |
| docs #242 | quality (2nd pass) | Minor | `flowTable` overlay anchor "~258"/"~261" | fixed in b57840e3: `ShellView.swift:258` in spec D7 and plan Task 3 |
| all | Spec (3rd pass) | Minor | `GettingStartedStep.Kind` listing showed `caTrusted` after `scopeSet`; PR D's enum is `coreRunning, busConnected, caTrusted, extensionOn, scopeSet, firstFlow` | fixed in ad83ab78: listings use PR D's source order; the steps order stays make's |
| whole branch | Tester (whole branch) | Minor | T1 — TR-AC8's literal `grep -rln CFNetworkCopySystemProxySettings apps/mac/Sources` is non-empty on the branch: PR #246's `SystemProxyState.swift` names the function in two `///` doc comments (lines 6, 79) and calls it nowhere | fixed in docs (this commit): spec TR-AC8 and plan Task 2 read `grep -rn … \| grep -vE ':[0-9]+:[[:space:]]*///'` → empty |
| whole branch | Tester (whole branch) | Minor | T2 — the `BusService.swift` diff is four added lines (decode, change-guarded write, two-line comment), not "exactly one added line" | accepted (orchestrator 2026-11-01: the guard matches the file's other per-tick writes; an `@Observable` set notifies on equal values) + amended in docs (this commit): spec D6/D7/TR-AC8, plan gate 2, Task 2, do-not-touch, file table, call 5 |
| whole branch | Tester (whole branch) | Minor | T3 — `App.swift:226` (one token, `ConnectionAction.trustCA.title`) and `tools/check-ca-trust-path.sh` (rule 2 allow-list + expect for `RouteBanner.swift`) are edited outside the recorded claim | recorded (this commit): orchestrator GO 2026-11-01 on both; spec D7/TR-AC7, plan gate 2, Task 5, do-not-touch, file table amended |
| whole branch | Tester (whole branch) | Minor | T4 — an empty or whitespace-only `decrypt.advice` is quoted as the Scope line (a blank row / banner) instead of falling back to the sentence | fixed in e58b267a (gate at `6ebc9e8f`, `/tmp/claude/attr/gate-routes.log`: `✔ Test run with 624 tests in 77 suites passed after 0.922 seconds.`, `✔ Test run with 31 tests in 6 suites passed after 0.595 seconds.`, `swift-test-exit=0`, `check-connection-words-exit=0`, `check-capture-operator-only-exit=0`, `check-capture-toggle-exit=0`, `check-ca-trust-path-exit=0`, `grid-lint-exit=0`): a blank sentence reads as absent; tests `advice: ""` → nil (`DecryptStatusTests`) and the fallback line (`ConnectionSummaryTests`); docs: spec D2/D3/TR-AC21, plan Task 1 (this commit) |
| whole branch | Tester (whole branch) | Minor | T5 — `RouteBanner.shownEntries` re-derives the shown list by walking `advice` against the banner text: a second derivation of D5's predicate in a view (anti-goal) | fixed in e58b267a (gate at `6ebc9e8f` as quoted in the T4 row: 624 + 31 tests passed, `swift-test-exit=0`, the five tripwires exit 0): `TrafficRoutes.shown` and `bannerDetail` published by the Kit and read by `RouteBanner`; docs: spec D2/D5/D7/TR-AC18, plan Tasks 1/3 (this commit) |
| 1b | Architect (amendment) | Minor | item 1 — spec D3's CA prose said `open = trusted`; the code, D3's own table and PR D's `step.done` say `trusted && !installing` | fixed in docs (this commit): D3 prose and plan Task 1b read `open = trusted && !installing`; pinned by `caSiblingStates`, incl. the uninstall-in-flight case |
| 1b | Architect (amendment) | Minor | item 2 — plan Task 1b said test values are "built with PR D's memberwise init"; PR D's `init?(status:)` in the struct body suppresses it | fixed in docs (this commit): built via `CATrustFacts(status: CAStatus(...))`, then `installing` / `needsAdmin` set (`caFacts(scope:installing:needsAdmin:)`) |
| 2 | Architect (amendment) | Minor | item 3 — TR-AC8 CFNetwork grep literal | = Tester T1 above; fixed in docs (this commit) |
| 2 | Architect (amendment) | Minor | item 4 — `BusService` "exactly one added line" | = Tester T2 above; accepted + amended in docs (this commit) |
| 5 | Architect (amendment) | Minor | item 5 — `App.swift:226` and `check-ca-trust-path.sh` outside the claim | = Tester T3 above; recorded, orchestrator GO (this commit) |
| 3/5 | Architect (amendment) | Minor | item 6 — spec D7 said the Flows surfaces run every action through `perform`; `.trustCA` goes to `session.trustCA()` via `RouteActions.run` (PR D's `perform` returns `false` for it on purpose), as `StatusPanel.run` does; the model hides the button once trusted or while installing | fixed in docs (this commit): spec D7, plan Tasks 3 and 5 |
| 1 | Architect (amendment) | Minor | item 7 — blank `decrypt.advice` | = Tester T4 above; fixed in e58b267a |
| 1/3 | Architect (amendment) | Minor | item 8 — `TrafficRoutes.shown` / `bannerDetail` as the contract; `RouteBanner` reads them | = Tester T5 above; fixed in e58b267a |
| 6 | Architect (amendment) | Minor | item 9 — TR-AC17: the aitm CA was trusted in Matt's login keychain on 2026-11-01 by Matt himself (PR D's first-run step), so the live proof shows the TRUSTED rendering (`✓ CA trusted (user keychain)`, no CA row/banner, `ca.status` user `trusted: "yes"`) | fixed in docs (this commit): spec Goals, Constraints, TR-AC17 (hard-gate text unchanged); plan Task 6 A2/B2/B7/B9, Q4, Shipped pre-fill |
| 6 | Architect (amendment) | Minor | item 10 — Half A ran with the session's own bundle script and the installed app left running, so `L` = `127.0.0.1:63109`, not 8080; evidence `/tmp/claude/route-advice/` + shared note `traffic-route-live-proof-half-A.md`; Half B on the first DMG containing this PR | fixed in docs (this commit): plan Task 6 "As run", Half B header, call 8, Q2, Shipped pre-fill |
| all | Architect (amendment) | Minor | `tools/grid-lint.sh` is zsh; the four tripwires are bash | fixed in docs (this commit): plan Environment adaptation says which is which and to run grid-lint by path, never under `bash` |
| all | Architect (amendment) | Minor | plan header named the branch `claude/apps-attribution-8ab619`; the implementation shipped on `feat/mac-traffic-route-advice` (Architect's call to correct it) | fixed in docs (this commit) |
| PR #265 | security | Minor | S1 — the Flows trust-CA button (banner and empty-state row) is not `.disabled(!caTrustControlLive)` as the Status row's is; the downstream guard in `Session+CATrust` refuses the call, so a UX gap, not a bypass | fixed in <code commit> (SHA to be stamped): the `.trustCA` button is disabled unless `session.caTrustControlLive`; docs: spec D7, plan Task 3 (stage-6 docs pass) |
| PR #265 | security | Minor | S2 — `decrypt.advice` is unbounded, and `TrafficRoute.state` is parsed from `line` by splitting on " — " (a core sentence containing " — ", a multi-line or a huge string reaches the one-line banner, its tooltip and the Status row) | fixed in <code commit> (SHA to be stamped): `TrafficRoute` stores `state` and `remedy`, `line` is computed, nothing parses; `DecryptStatus(json:)` flattens line breaks and caps `advice` at 512 characters; docs: spec D2/D3/TR-AC21, plan Task 1 (stage-6 docs pass) |
| PR #265 | security | Minor | S3 — a negative `scope_hosts` is accepted (a malformed reply could render `Scope: -1 hosts decrypted`) | fixed in <code commit> (SHA to be stamped): `DecryptStatus(json:)` is nil on `scope_hosts < 0`; docs: spec D2/TR-AC21, plan Task 1 (stage-6 docs pass) |
| PR #265 | security | — | `unsafe` sign-off: no `unsafe` block in the range | n/a |
| PR #265 | quality | Minor | Q1 — `state` parsed from `line` | fixed in <code commit> (SHA to be stamped), as S2 |
| PR #265 | quality | Minor | Q2 — duplicate open/closed filters in `make`'s route derivation | fixed in <code commit> (SHA to be stamped): one filter |
| PR #265 | quality | Minor | Q3 — external-core `allApps == nil` carried two meanings (no extension vs external core), decided in two places | fixed in <code commit> (SHA to be stamped): decided in one place |
| PR #265 | quality | Minor | Q4 — `ScopeBanner` is a dead struct in `Panels/ScopePanel.swift` | accepted for this PR (orchestrator 2026-11-01: the file is outside this plan's claim); follow-up in Shipped: delete it |
| PR #265 | quality | Minor | Q5 — `AppsAttributionBanner` kept alive only so the NS-AC3 pins hold | accepted for this PR (orchestrator 2026-11-01: the `ShellView` grant is `EmptyFlows` + the banner insertion only); follow-up in Shipped: retarget the NS-AC3 pins at `RouteBanner`, delete the struct |
| PR #265 | quality | Minor | Q6 — three `make` evaluations per render (`MainView.flows`'s guard, `RouteBanner` and `EmptyFlows` each read `session.trafficRoutes`) | fixed in <code commit> (SHA to be stamped): routes computed once in `MainView.flows`, passed to `RouteBanner(routes:)` and `EmptyFlows(routes:run:)`; docs: spec D5/D7/D8, plan Tasks 3/5 (stage-6 docs pass) |
| PR #265 | quality | Minor | Q7 — `EmptyFlows` half-pure (routes by parameter, actions via the environment) | fixed in <code commit> (SHA to be stamped): a `run` closure parameter; docs: spec D7, plan Task 3 (stage-6 docs pass) |
| PR #265 | quality | Minor | Q8 — `?? ""` on the banner text in `RouteBanner` | fixed in <code commit> (SHA to be stamped) |
| PR #265 | quality | Minor | Q9 — icon + text built as an `HStack`, not a `Label` (apps/mac/CLAUDE.md design rule) | fixed in <code commit> (SHA to be stamped); docs: spec D7, plan Task 3 (stage-6 docs pass) |
| PR #265 | quality | Minor | Q10 — glyph string literals (`"network"`, `"app.badge"`) beside `Tok.Glyph.*` tokens | accepted for this PR (orchestrator 2026-11-01); follow-up in Shipped: `Tok.Glyph.network` / `Tok.Glyph.apps` via gen-tokens, together with the icons PR's `glyph.process` |
| PR #265 | quality | Minor | Q11 — the words tripwire's FAIL message and exclusion list duplicated between rule 1's two greps | fixed in <code commit> (SHA to be stamped); docs: plan Task 5 (stage-6 docs pass) |
| PR #265 | quality | Minor | Q12 — the grid-invariant test's oracle re-derived the shown set instead of reading `shown` | fixed in <code commit> (SHA to be stamped): the oracle is `routes.shown` |
| PR #265 | quality | Minor | Q13 — a magic step count and positional `steps[n]` indexing in the step tests | fixed in <code commit> (SHA to be stamped): steps looked up by kind |
| PR #265 | quality | Minor | Q14 — `FlowRow.tls` and `tunnel` are independent stored fields | accepted by design (orchestrator 2026-11-01): `tls` has non-tunnel sources (the scheme rule on rows without `tunnel`, every row from an older core); noted in spec D2 (stage-6 docs pass) |
| PR #265 | quality | Minor | Q15 — `Session.systemProxy` is declared but never written | accepted by design (spec D6, plan call 4): PR4 writes it; nil = unknown, never "off" |
| PR #265 | spec | Important | SP-I1 — the blank-advice rule lived only in the decoder, and the plan's memberwise `advice: ""` test was absent, so a memberwise-built `DecryptStatus` would print an empty Scope line | fixed in <code commit> (SHA to be stamped): `make`'s Scope derivation guards a blank advice and the `ConnectionSummaryTests` memberwise-`""` case is added; docs: spec D3/TR-AC21 say both layers normalise, plan Task 1 (stage-6 docs pass) |
| PR #265 | spec | Important | SP-I2 — no quoted Swift gate for the head commit in the plan | fixed in docs (stage-6 docs pass): Task 6 "Gate record for the stage-6 head commit `6ebc9e8f`" quotes `/tmp/claude/attr/gate-routes.log` — `✔ Test run with 624 tests in 77 suites passed`, `✔ Test run with 31 tests in 6 suites passed`, `swift-test-exit=0`, `check-connection-words-exit=0`, `check-capture-operator-only-exit=0`, `check-capture-toggle-exit=0`, `check-ca-trust-path-exit=0`, `grid-lint-exit=0`; the same lines sit on the e58b267a rows above; Rust gate at `6ebc9e8f`: `FMT_OK`, `CLIPPY_OK`, `cargo test` result `cargo test` exit 0, 265 test binaries ok (Terminal, rust-gate.log) |
| PR #265 | spec | Minor | SP-M3 — the `TrafficRoutes` signature in spec D2 / plan Task 1 differed from the shipped one (`banner`, `bannerAction`, `bannerDetail` are computed from `shown`; the init is `(systemProxy:allApps:scope:caTrust:advice:shown:)`) | fixed in docs (stage-6 docs pass): spec D2, D5, Left to the builder; plan Task 1 |
| PR #265 | spec | Minor | SP-M4 — the StatusPanel hand-over (`cb9f59be`) also deleted the private `CATrustRow` struct and the `VStack` wrapper around `LaneCard`, unstated in D7/TR-AC8/Task 2b | fixed in docs (stage-6 docs pass): spec D7 and TR-AC8, plan Task 2b |
| PR #265 | spec | Minor | SP-M5 — TR-AC18's `.off`-led `shown` literal (`[.systemProxy, .allApps, .scope, .caTrust]`) was not pinned by a test | fixed in <code commit> (SHA to be stamped): the test is added; spec TR-AC18 notes the pin (stage-6 docs pass) |
| PR #265 | spec | Minor | SP-M6 — Half A's header-offset numbers (≈141 px vs ≈110 px at an unknown scale) do not establish the 28 pt figure | fixed in docs (stage-6 docs pass): Task 6 "As run" reads "one banner row, not two; the 28 pt measurement is Half B's B4 (AX frame or known-scale shot)" |
| PR #265 | spec | Minor | SP-M7 — gate 3 blank; coverage row 17 and three Task 6 paragraphs still said "NOT-trusted only" against the TR-AC17 TRUSTED ruling | fixed in docs (stage-6 docs pass): gate 3 = PR #254 / `58724ef7`; the Environment hard-gate paragraph, Task 6's Satisfies and Change paragraphs and coverage row 17 aligned with the ruling (the hard-gate text — no `ca.install`, no clicks — unchanged) |

## Shipped

(Filled at stage 7: what merged, which build each live half ran on, what was cut, follow-ups —
PR4 writing `Session.systemProxy` and filling `.setSystemProxy` (the PR4 addendum of Task 6:
TR-AC10(b)/12/13(b) on the first PR4 build); whether the CA-trusted state (B9) was proved, and on
whose say-so.)

Pre-filled 2026-11-01 — facts the stage-7 entry carries forward:

- **Half A** ran 2026-11-01 12:57–13:02 PST on a dev bundle with a real core (`/tmp/Aitmproxy-dev-attr.app`: `swift build`
  of `apps/mac` at `8a605948`, embedded release core v0.5.10 from the same tree, isolated `APP_STORE`, no extension; the
  installed app left running, so `L` = `127.0.0.1:63109`). Evidence `/tmp/claude/route-advice/` and the shared note
  `traffic-route-live-proof-half-A.md`. Deferred to PR4: TR-AC10(b)/12/13(b) (`A2-deferred-to-PR4.txt`).
- **CA (B9 / TR-AC17):** the aitm CA was trusted in Matt's login keychain on 2026-11-01 by Matt himself, through PR D's
  first-run step; the live proof shows `✓ CA trusted (user keychain)`, no CA row or banner clause, `ca.status` user store
  `trusted: "yes"` (`bus-A2-ca.json`). No session ran `ca.install` or clicked anything.
- **Half B:** pending the first DMG that contains this PR (B1–B8 as written; CA clauses in their TRUSTED form).
- **Follow-ups accepted at the stage-6 panel (PR #265, 2026-11-01), each a small cleanup PR of its own:**
  1. Delete the dead `ScopeBanner` struct in `Panels/ScopePanel.swift` (quality Q4; outside this plan's claim).
  2. Retarget `check-capture-toggle.sh`'s NS-AC3 body pins at `RouteBanner` and delete the `AppsAttributionBanner`
     struct in `Shell/ShellView.swift` (quality Q5; kept here only so the pins hold — plan call 12).
  3. `Tok.Glyph.network` and `Tok.Glyph.apps` via gen-tokens, together with the icons PR's `glyph.process`, replacing the
     `"network"` / `"app.badge"` string literals in `RouteBanner.swift` (quality Q10).
  4. PR4 (system-proxy session) writes `Session.systemProxy` and fills `.setSystemProxy` (quality Q15, by design); the
     Task 6 PR4 addendum (TR-AC10(b)/12/13(b)) runs on its first build.
