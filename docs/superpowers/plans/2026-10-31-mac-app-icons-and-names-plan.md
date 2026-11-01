# macOS app icons and display names for clients — implementation plan

**Status:** approved — self-approved 2026-10-31 (Matt pre-approved this work in autonomous mode); amended 2026-11-01 (self-approved, autonomous mode): stage-6 fix pass on docs PR #242 (Review log)
**Spec:** `docs/superpowers/specs/2026-10-31-mac-app-icons-and-names-design.md`
(approved 2026-10-31, revision 2, amended 2026-11-01; acceptance criteria AI-AC1 … AI-AC24)
**Branch / worktree:** this worktree, `claude/apps-attribution-8ab619`
(`/Users/matt/Security/aitmproxy/.claude/worktrees/apps-attribution-8ab619`), base `main 8e19c2e3`
(PR #196 `5eac2a50` is the last owner of `Shell/SidebarView.swift` and `Bus/BusService.swift`; PR #197
`9776a0e6` moved `Session.swift`'s navigation enums out).
**PR shape:** two PRs from this branch — the traffic-route plan
(`2026-10-31-mac-traffic-route-advice-plan.md`) ships **first**; this plan ships second and records that
PR's merge SHA as gate 4. Its Tasks 5/6 share `Session.swift` / `Bus/BusService.swift` with the
traffic-route plan's Tasks 2/2b and run only after them, never concurrently.

## Gate: nothing below starts until gates 1–3 hold; Tasks 5/6 also wait for gate 4

1. **PR #195 `fix/ne-source-app` is on `main`** (`FlowSummary.sourceApp`, `FlowRow.client =
   ClientInfo(sourceApp:)`, `ClientInfo.displayName(forSourceApp:)`). Merge SHA: **`3fe92f66`**
   (released in v0.5.9). Every Kit task below calls `ClientInfo(sourceApp:)`; without it nothing compiles.
2. **The fixture-removal PR is on `main` and this branch has rebased once onto its SHA**
   (record: `__________`). That PR deletes the mac app's fixture and sample-data modes
   (`Store.usesFixtures`, `APP_FIXTURES`/`APP_SNAPSHOT`, the Kit `Fixtures*.swift`,
   `Snapshot*.swift`, `SnapshotScenes`, the fixture `--selftest`, `snap.sh`/`selftest.sh`, the kit
   gallery). **This plan references none of them.** Coders who find a `Fixtures.` or
   `Store.usesFixtures` reference in a file they edit leave it alone and report it; they never add one.
3. **The orchestrator session has approved the file claim** for `Shell/SidebarView.swift`,
   `Bus/BusService.swift`, `Session.swift`, `FlowTable/FlowCellView.swift` (the files PR #196 and
   the fixture-removal PR touched last).
4. **The traffic-route PR is merged** (record its merge SHA here: `__________`) and this branch's
   second PR is cut on top of it. **Tasks 5 and 6 run only after the traffic-route plan's Tasks 2/2b
   have landed** — they share `Session.swift` (traffic-route: `systemProxy`, `decrypt`) and
   `Bus/BusService.swift` (traffic-route: one `decrypt` line; PR D's `refreshCAStatus()` is also in
   that file by then) — and never concurrently with them; whichever lands second rebases onto the
   first. Tasks 1–4 and 7 do not wait for gate 4.

Before Wave A the orchestrator runs the baseline gate once on the rebased tree (Swift gate below
plus the three tripwires) so every later failure is attributable to this plan.

## Environment adaptation (every Coder reads this)

- **The Claude Bash sandbox cannot run SwiftPM** (EPERM on the module cache and `/var/folders`;
  memory `sandbox-swift-and-git-switch-quirks`). A Coder writes the test first, then the code, and
  runs only sandbox-safe checks: `swiftc -parse -module-cache-path "$TMPDIR/mc" <files>` for syntax
  (a sandbox-caused failure is not a code failure and is reported as such). The Coder's report says,
  in these words, **"sandbox: cannot run swift test — handing the gate to the orchestrating
  session"**, and lists the exact tests it expects to go red-then-green.
- **The Swift gate** is run by the orchestrating session in the Terminal panel:

  ```
  swift test --package-path apps/mac --scratch-path ~/Library/Developer/Aitmproxy/test-build-icons
  ```

  redirected to a log under `/tmp/claude/` and judged by exit code, never by a grep pipeline
  (memory `gate-exit-status-not-grep`). The orchestrator runs it after each wave, commits the wave's
  tasks once green, and quotes the output in the Tester hand-off.
- **Tripwires** (AI-AC13), also Terminal: `apps/mac/tools/check-capture-operator-only.sh`,
  `apps/mac/tools/check-capture-toggle.sh`, `apps/mac/tools/check-connection-words.sh` — each prints
  PASS. `apps/mac/tools/grid-lint.sh` is run as a source check after Task 5.
- **Rust gate** (AI-AC23; `docs/design/tokens.json` feeds `crates/aitm-tui/build.rs`, so it must
  run even though no Rust source changes): `cargo fmt --check && cargo clippy --all-targets --
  -D warnings && cargo test`, Terminal, after Task 4 lands and once on the whole branch.
- **Building the real app** (Task 8 only): `apps/mac/build.sh --ne --allow-unnotarized --replace`
  then `scripts/notarize-dmg.sh` (`docs/RELEASE.md` step 3), Terminal only; needs Matt's Developer ID
  and ASC credentials (memory `aitmproxy-release-pipeline`). Never `pkill -f obscura` globally
  (memory `aitmproxy-obscura-multisession-hazards`).
- **Test data rule.** Kit tests build their own `ClientInfo` and `FlowRow` values with literal
  strings. Row builder every Kit test uses (a private helper in each test file, not a shared
  fixture): `FlowRow(id: FlowID("<letter>"), seq: n, method: .get, scheme: "https",
  authority: "<host>", path: "/", client: <ClientInfo?>)`. If the fixture-removal PR removed the
  `coreID` default on `FlowRow.init`, pass `coreID: CoreID()` explicitly.
- **Do-not-touch:** `apps/mac/Sources/AitmproxyKit/Flow.swift`,
  `apps/mac/Sources/AitmproxyKit/FlowSummary.swift`, `apps/mac/Sources/Aitmproxy/UI/Tokens.swift` by
  hand (generated), anything under `crates/`, `apps/mac/Extension/`. A Coder whose task seems to
  need one of these **stops and reports**.
- **Stop-and-report rule.** A Coder that finds the spec wrong (a D-section that cannot be built as
  written, a signature that will not typecheck under strict concurrency without an API change) stops
  and reports; it does not redesign. The one pre-authorised exception is the `NSImage` hand-off in
  Task 4 (see that task).

## Overview

Eight tasks in four waves. Wave A is pure Kit: three file-disjoint tasks that may fan out to three
Coders at once (Tasks 2 and 3 compile only once Task 1's `ClientInfo.groupKey` exists, so the gate
runs after the whole wave). Wave B adds the token and the AppKit resolver, with the KIT.md task in
parallel. Wave C wires the two UI halves (Session + sidebar; poll loop + Client cell) in parallel,
file-disjoint. Wave D is the real-app proof plus the whole-branch Tester and panel.

| Wave | Tasks | Parallel? |
|---|---|---|
| A | Task 1 ∥ Task 2 ∥ Task 3 | yes, file-disjoint (2 and 3 code against Task 1's signatures) |
| B | Task 4 ∥ Task 7 | yes, file-disjoint |
| C | Task 5 ∥ Task 6 | yes, file-disjoint |
| D | Task 8, then whole-branch Tester and the three reviewers | sequential |

Evidence classes follow the spec: **K** Kit unit tests (Tasks 1–3), **T** tripwires (Task 5),
**L** the real installed app with real traffic (Task 8). The resolver (Task 4) and the two UI tasks
have no Kit test by construction (AppKit/SwiftUI); their proof is Task 8 plus the diff review
(AI-AC22).

---

## Tasks

### Task 1: Kit pure rules — `AppIdentifier` and the `ClientInfo` extension

- **Satisfies:** AI-AC1, AI-AC2, AI-AC3, AI-AC4, AI-AC5, AI-AC6
- **Depends on:** none (needs PR #195 on main for `ClientInfo(sourceApp:)` and
  `ClientInfo.displayName(forSourceApp:)`)
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/AppIdentifier.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/AppIdentifierTests.swift` (create)
- **Change:** exactly spec D1's Kit API, Foundation only:

  ```swift
  public enum AppIdentifier {
      public static func candidates(for identifier: String) -> [String]
      public static func trimmedAdHoc(_ identifier: String) -> String
      public static func fallbackName(for identifier: String) -> String
      public static func sanitized(_ name: String) -> String?
      public static func isServicePath(_ path: String) -> Bool
      public static func serviceLabel(_ name: String) -> String
      public static let knownUnbundled: [String: String]
      public static let ownerMap: [String: String]
  }

  public extension ClientInfo {
      var groupKey: String { bundleID ?? name }
      func withResolvedName(_ name: String) -> ClientInfo
  }
  ```

  Rules, verbatim from D1:
  - `candidates`: split on `.`; fewer than three components → `[identifier]`; else the identifier
    then every prefix with ≥ 3 components, longest first.
  - `trimmedAdHoc`: only when the identifier contains no `.`; regex `^(.+)-([0-9a-f]{16,})$`
    (lowercase hex only) → group 1; else unchanged.
  - `fallbackName`: `knownUnbundled[id] ?? ClientInfo.displayName(forSourceApp: trimmedAdHoc(id))`.
    (This composition is the plan's reading of "knownUnbundled, else trimmedAdHoc, else
    displayName"; it yields every AI-AC3 value.)
  - `sanitized`: drop scalars whose `properties.generalCategory` is `.control` or `.format` (the
    same two categories as PR B's private `withoutControlAndBidi`, repeated here because
    `Flow.swift` is not edited), trim `.whitespacesAndNewlines`, drop one trailing `.app`, keep
    the first 64 characters, nil when empty.
  - `isServicePath`: true when the path contains `/XPCServices/`, contains `.xpc/` or ends in
    `.xpc`, contains `/Contents/Library/LoginItems/`, or contains `/Helpers/`.
  - `serviceLabel`: `String(name.prefix(64)) + " (Service)"`.
  - `knownUnbundled` = `com.apple.WebKit.Networking` → `WebKit Networking`, `com.apple.WebKit.GPU`
    → `WebKit GPU`, `com.apple.WebKit.WebContent` → `WebKit WebContent`,
    `com.apple.dt.xcode_select.tool-shim-public` → `developer tool`. Nothing else.
  - `ownerMap` = `org.mozilla.plugincontainer`, `org.mozilla.firefox-gpu-helper`,
    `org.mozilla.firefox-media-plugin-helper` → `org.mozilla.firefox`. No `com.apple.WebKit.*` key.
  - `withResolvedName`: `name == self.name ? self : ClientInfo(name: name, bundleID: bundleID, pid: pid)`.
  Doc comments on `knownUnbundled` and `ownerMap` carry the D1 reasons (shared service ⇒ never a
  host app; Firefox helpers are not LS-registered).
- **Test:** `@Suite struct AppIdentifierTests` (Swift Testing, `@testable import AitmproxyKit`):
  - `candidatesWalkDottedPrefixesDownToThree` (AI-AC1): the six literal pairs of AI-AC1, e.g.
    `#expect(AppIdentifier.candidates(for: "com.google.Chrome.helper.renderer") == ["com.google.Chrome.helper.renderer", "com.google.Chrome.helper", "com.google.Chrome"])`,
    `candidates(for: "") == [""]`.
  - `trimmedAdHocDropsALinkerHexTail` (AI-AC2): all eight literals, including
    `"node-5555494418EC1BA8"` unchanged and `"com.example.x-0123456789abcdef"` unchanged.
  - `fallbackNameIsHonestForEveryUnbundledShape` (AI-AC3): all twelve literals, e.g.
    `fallbackName(for: "com.apple.WebKit.Networking") == "WebKit Networking"`,
    `fallbackName(for: "a.out") == "out"`, `fallbackName(for: "\u{202E}com.evil.app") == "app"`
    and `== ClientInfo.displayName(forSourceApp: "\u{202E}com.evil.app")`.
  - `sanitizedStripsControlFormatWhitespaceAndDotApp` (AI-AC4): the six literals plus
    `#expect(AppIdentifier.sanitized("\u{200E}Wh\u{0007}atsApp") == ClientInfo.displayName(forSourceApp: "\u{200E}Wh\u{0007}atsApp"))`
    (both equal `"WhatsApp"`).
  - `servicePathsAndLabel` (AI-AC5): the four true paths and two false paths of D1;
    `serviceLabel("Google Chrome") == "Google Chrome (Service)"`;
    `serviceLabel(String(repeating: "x", count: 70)) == String(repeating: "x", count: 64) + " (Service)"`.
  - `groupKeyAndWithResolvedName` (AI-AC6):
    `ClientInfo(sourceApp: "com.apple.Safari").groupKey == "com.apple.Safari"`;
    `ClientInfo(name: "curl").groupKey == "curl"`;
    `let c = ClientInfo(sourceApp: "com.google.Chrome.helper").withResolvedName("Google Chrome (Service)")`
    → `c.name == "Google Chrome (Service)"`, `c.monogram == "G"`,
    `c.bundleID == "com.google.Chrome.helper"`, `c.pid == nil`;
    `c.withResolvedName("Google Chrome (Service)") == c`.
  TDD: the test file first (fails to compile: `AppIdentifier` does not exist), then the source.
- **Done when:** all six tests pass under the orchestrator's Swift gate; no other file changed.

---

### Task 2: Kit grouping — `FlowGroup.clientHost`, `ClientTree`, `Pins` group mapping, `BoundedCache`

- **Satisfies:** AI-AC7, AI-AC8, AI-AC9, AI-AC10, AI-AC12
- **Depends on:** Task 1 for compilation (`groupKey`); coded in parallel against its signature.
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/FlowQuery.swift` (modify)
  - `apps/mac/Sources/AitmproxyKit/ClientTree.swift` (create)
  - `apps/mac/Sources/AitmproxyKit/Pins.swift` (modify: doc comment only)
  - `apps/mac/Tests/AitmproxyKitTests/ClientTreeTests.swift` (create)
  - `apps/mac/Tests/AitmproxyKitTests/FlowQueryTests.swift` (modify: add one `@Test`; existing
    tests untouched)
- **Change:**
  - `FlowQuery.swift`: `FlowGroup` gains `case clientHost(client: String, host: String)` (D4).
    `FlowQuery.Compiled.apply`: `.client(let key)` → `$0.client?.groupKey == key`;
    `.clientHost(let key, let host)` → `$0.client?.groupKey == key && $0.authority == host`;
    `.host` unchanged; the pins filter becomes
    `hosts.contains($0.authority) || $0.client.map { apps.contains($0.groupKey) } == true`.
  - `ClientTree.swift` (new; Foundation only):

    ```swift
    public enum ClientTree {
        public static func clients(in rows: [FlowRow]) -> [(ClientInfo, Int)]
        public static func hosts(forClient key: String, in rows: [FlowRow]) -> [(String, Int)]
    }

    public extension Pins {
        mutating func pin(_ group: FlowGroup)
        mutating func unpin(_ group: FlowGroup)
        func contains(_ group: FlowGroup) -> Bool
    }

    public struct BoundedCache<Key: Hashable, Value> {
        public init(capacity: Int)
        public subscript(key: Key) -> Value? { get set }
        public var count: Int { get }
    }
    ```

    - `clients(in:)`: today's `Session.clients` body (count per `ClientInfo` value) with the
      order **count desc, then `name` asc, then `groupKey` asc** — the third key is added here
      (plan call) so two "(Service)" rows of one owner order deterministically; rows with
      `client == nil` are skipped.
    - `hosts(forClient:in:)`: count `authority` over rows with `client?.groupKey == key`; order
      count desc, then host asc.
    - `Pins.pin`: `.host(h)` and `.clientHost(_, h)` → `pinHost(h)`; `.client(k)` → `pinApp(k)`.
      `unpin` mirrors; `contains` mirrors (`.clientHost(_, h)` ⇔ `hosts.contains(h)`).
    - `BoundedCache`: a dictionary plus an insertion-order array; setting a new key past
      `capacity` removes the oldest key first; overwriting an existing key keeps its age;
      setting `nil` removes the key and its order entry (plan call: a removal is a plain delete).
      `Sendable` when `Key` and `Value` are (conditional conformance), so the resolver can hold it
      on the main actor.
  - `Pins.swift`: the doc comment on `apps` reads "group keys (`ClientInfo.groupKey`: the
    signing identifier when the row has one, else the name)"; no code change.
- **Test:** `@Suite struct ClientTreeTests` with a private `row(_ id: String, _ seq: Int, _ host: String, _ client: ClientInfo?)`
  helper and the AI-AC7 rows:
  `A = row("A", 1, "a.example", ClientInfo(name: "Google Chrome", bundleID: "com.google.Chrome"))`,
  `B = row("B", 2, "a.example", ClientInfo(name: "Google Chrome (Service)", bundleID: "com.google.Chrome.helper"))`,
  `C = row("C", 3, "a.example", <A's client>)`,
  `D = row("D", 4, "b.example", ClientInfo(name: "Google Chrome (Service)", bundleID: "com.google.Chrome.helper.renderer"))`,
  `E = row("E", 5, "c.example", nil)`.
  - `clientsGroupByIdentifierNotName` (AI-AC7): `ClientTree.clients(in: [A, B, C, D, E])`
    → `map(\.0.groupKey) == ["com.google.Chrome", "com.google.Chrome.helper", "com.google.Chrome.helper.renderer"]`,
    `map(\.1) == [2, 1, 1]`,
    `map(\.0.name) == ["Google Chrome", "Google Chrome (Service)", "Google Chrome (Service)"]`.
  - `hostsUnderAnAppSumToItsCount` (AI-AC8): rows X1–X3 (`ClientInfo(name: "Safari", bundleID: "com.apple.Safari")`, `example.com`),
    X4 (same client, `www.apple.com`), Y1–Y2 (`ClientInfo(name: "curl", bundleID: "com.apple.curl")`, `example.com`):
    `hosts(forClient: "com.apple.Safari", in:)` → `[("example.com", 3), ("www.apple.com", 1)]`
    (compare as `map { "\($0.0):\($0.1)" } == ["example.com:3", "www.apple.com:1"]`),
    its counts sum to `clients(in:)`'s Safari count `4`;
    `hosts(forClient: "com.apple.curl", in:)` → `[("example.com", 2)]`; `hosts(forClient: "nobody", in:)` → `[]`.
  - `pinsMapGroupsToHostsAndKeys` (AI-AC10): from `Pins()`: `pin(.client("com.apple.Safari"))`
    → `apps == ["com.apple.Safari"]`, `hosts == []`;
    `pin(.clientHost(client: "com.apple.Safari", host: "example.com"))` → `hosts == ["example.com"]`, `apps` unchanged;
    `contains(.host("example.com"))`, `contains(.clientHost(client: "anything", host: "example.com"))`,
    `contains(.client("com.apple.Safari"))` all `true`; `contains(.client("Safari")) == false`;
    `unpin(.clientHost(client: "x", host: "example.com"))` → `hosts == []`; pinning
    `.client("com.apple.Safari")` again → `apps.count == 1`.
  - `boundedCacheEvictsOldestInserted` (AI-AC12): `var c = BoundedCache<String, Int>(capacity: 3)`;
    `c["a"] = 1; c["b"] = 2; c["c"] = 3; c["d"] = 4` → `c.count == 3`, `c["a"] == nil`, `c["d"] == 4`;
    then `c["b"] = 20; c["e"] = 5` → `c["c"] == nil`, `c["b"] == 20`, `c["e"] == 5`;
    `var big = BoundedCache<String, Int>(capacity: 512)`; insert `"k0"…"k599"` → `big.count == 512`,
    `big["k87"] == nil`, `big["k88"] == 88`, `big["k599"] == 599`.
  - In `FlowQueryTests.swift`, `@Test func groupsKeyOnTheIdentifier()` (AI-AC9) with the AI-AC7
    rows and `details: [:]`: `FlowQuery(group: .client("com.google.Chrome")).apply(...).map(\.id.raw) == ["A", "C"]`;
    `.client("Google Chrome")` → `[]`; `.clientHost(client: "com.google.Chrome.helper", host: "a.example")` → `["B"]`;
    `.clientHost(client: "com.google.Chrome", host: "b.example")` → `[]`; `.host("a.example")` → `["A", "B", "C"]`;
    `FlowQuery(pins: Pins(apps: ["com.google.Chrome.helper"]))` → `["B"]`;
    `FlowQuery(pins: Pins(hosts: ["c.example"]))` → `["E"]`.
  TDD: tests first (compile failure: `clientHost`, `ClientTree`, `BoundedCache` missing).
- **Done when:** the five new tests pass under the Swift gate; every existing `FlowQueryTests`
  test still passes; no other file changed.

---

### Task 3: Overview counts by group key

- **Satisfies:** AI-AC11
- **Depends on:** Task 1 for compilation (`groupKey`); coded in parallel.
- **Files:**
  - `apps/mac/Sources/AitmproxyKit/Panels/Overview.swift` (modify)
  - `apps/mac/Sources/AitmproxyKit/Panels/OverviewBreakdowns.swift` (modify)
  - `apps/mac/Sources/Aitmproxy/Panels/OverviewBreakdowns.swift` (modify)
  - `apps/mac/Tests/AitmproxyKitTests/OverviewTests.swift` (modify: add one `@Test`)
  - `apps/mac/Tests/AitmproxyKitTests/OverviewBreakdownsTests.swift` (modify: add one `@Test`)
- **Change:**
  - `OverviewStats.init`: `clients = Set(rows.compactMap { $0.client?.groupKey }).count`.
  - `OverviewBreakdowns.ClientCount` becomes
    `public struct ClientCount: Hashable, Sendable { public var key: String; public var name: String; public var count: Int; public init(key: String, name: String, count: Int) }`
    (the old two-argument init is removed; the only Kit callers are this file and the tests).
    `clients` is grouped by `groupKey` with the name taken from the first row of that key, ordered
    count desc, then name asc, then key asc (the same order as `ClientTree.clients`).
  - App view `Panels/OverviewBreakdowns.swift` "Clients" section: `ForEach(breakdowns.clients, id: \.key)`,
    label `entry.name`, `.help(entry.key)`, action `session.show(.apps, group: .client(entry.key))`,
    accessibility label unchanged in shape.
- **Test:** with the AI-AC7 rows built locally in each test file (same private helper as Task 2;
  do not share a file):
  - `OverviewTests.countsClientsByIdentifier`: `OverviewStats(rows: [A, B, C, D, E]).clients == 3`.
  - `OverviewBreakdownsTests.clientBarsAreKeyedByIdentifier`:
    `OverviewBreakdowns(rows: [A, B, C, D, E]).clients.map(\.key) == ["com.google.Chrome", "com.google.Chrome.helper", "com.google.Chrome.helper.renderer"]`,
    `.map(\.name) == ["Google Chrome", "Google Chrome (Service)", "Google Chrome (Service)"]`,
    `.map(\.count) == [2, 1, 1]`, `.clientMax == 2`.
  TDD: tests first (`ClientCount.key` does not exist → compile failure).
- **Done when:** both new tests pass under the Swift gate; existing Overview tests that survive
  the fixture-removal PR still pass; the app target compiles.

---

### Task 4: Token `glyph.process`, `AppIdentityResolver` and `ClientMark`

- **Satisfies:** D1 (app half), D2, D8, D9; proven live by AI-AC14, AI-AC17, AI-AC18, AI-AC21
  (Task 8) and by the diff review; gates AI-AC23 (`gen-tokens` leaves no diff; Rust gate).
- **Depends on:** Task 1 (`AppIdentifier`, `withResolvedName`), Task 2 (`BoundedCache`).
- **Files:**
  - `docs/design/tokens.json` (modify: one row)
  - `apps/mac/Sources/Aitmproxy/UI/Tokens.swift` (regenerate only, via `swift apps/mac/tools/gen-tokens.swift` — Terminal; the Coder edits `tokens.json` and asks the orchestrator to regenerate, or regenerates if the sandbox permits running the script)
  - `apps/mac/Sources/Aitmproxy/UI/AppIdentity.swift` (create)
- **Change:**
  - `tokens.json` `icon.glyph` table gains `"process": { "mac": "terminal", "web": "terminal", "tui": "$" }`
    (D9). Consumers: mac `gen-tokens.swift` (→ `Tok.Glyph.process`), `crates/aitm-tui/build.rs`
    (→ `glyph::PROCESS = "$"`, no test pins the count), `apps/web/src/components/Icon.tsx` already
    maps `terminal` to a Lucide icon. No other edit.
  - `UI/AppIdentity.swift`, exactly spec D1's app API:

    ```swift
    struct AppIdentity: Equatable {
        let identifier: String
        let name: String
        let icon: NSImage?
        let bundleURL: URL?
        let isService: Bool
    }

    @MainActor @Observable
    final class AppIdentityResolver {
        static let shared: AppIdentityResolver
        private(set) var version: Int
        func identity(for identifier: String) -> AppIdentity?
        func onResolve(_ identifier: String, _ body: @escaping @MainActor (AppIdentity) -> Void)
        func resolve(_ identifier: String) -> AppIdentity
        func enriched(_ client: ClientInfo) -> ClientInfo
    }

    struct ClientMark: View { let client: ClientInfo; var body: some View }
    ```

    - Storage: `BoundedCache<String, AppIdentity>(capacity: 512)` by identifier,
      `BoundedCache<String, NSImage>(capacity: 128)` by owner path, a `Set<String>` of in-flight
      identifiers, `[String: [@MainActor (AppIdentity) -> Void]]` of pending callbacks.
    - `resolve` runs D2 steps 1–8 in order, as one routine (no second path): `knownUnbundled`;
      `ownerMap[id] ?? id`; `NSWorkspace.shared.urlForApplication(withBundleIdentifier:)` over
      `AppIdentifier.candidates(for:)` (hit + matched id); owner = outermost `.app` path component
      (else the hit); `isService` = hit ≠ owner ‖ `isServicePath(hit.path)` ‖ ownerMap used ‖
      matched id ≠ id; name = first `sanitized` of `Bundle(url: owner)?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String`,
      `"CFBundleName"`, owner's last path component, then `serviceLabel` when `isService`;
      icon = `NSWorkspace.shared.icon(forFile: owner.path)` copied once per owner path with
      `size = NSSize(width: Tok.Size.icon, height: Tok.Size.icon)`, `isTemplate = false`
      (the owner-path cache is what makes two helpers of one owner share one image);
      no hit → `(fallbackName(for: id), nil, nil, false)`. `FileManager.displayName(atPath:)` is
      never called.
    - `identity(for:)`: reads `version` (so SwiftUI observation registers), returns the cached
      verdict, else — if not in flight — marks it in flight and schedules one off-main lookup
      (`Task.detached(priority: .utility)` calling a `nonisolated` lookup routine, then hopping to
      the main actor to store the verdict, bump `version`, fire and drop the callbacks). Never blocks.
    - `enriched(_:)`: `client.bundleID` nil → `client`; cached verdict → `client.withResolvedName(verdict.name)`;
      miss → schedule as above and return `client`. Never blocks.
    - `onResolve`: fires immediately if cached, else appends to the pending list for that id.
    - `ClientMark` (D5): `identity(for: client.bundleID ?? client.name)`; icon → `Image(nsImage:)
      .resizable().frame(width: Tok.Size.icon, height: Tok.Size.icon).accessibilityLabel(client.name)`;
      verdict without icon → `Image(systemName: Tok.Glyph.process).font(.system(size: Tok.Size.iconInline))
      .foregroundStyle(Tok.Ink.secondary.color)` centred in a `Tok.Size.icon` square; pending →
      `Color.clear.frame(width: Tok.Size.icon, height: Tok.Size.icon)`. No disc, no background.
    - **Pre-authorised deviation:** `NSImage` is not `Sendable`. If the hop from the detached task to
      the main actor does not typecheck under strict concurrency, wrap the verdict in a private
      `struct Handoff: @unchecked Sendable` with a comment stating the invariant (the image is created
      on the lookup thread, handed over once, and never mutated after) and name it in the Coder
      report so the Security reviewer signs it off. Nothing else is `unsafe`/`unchecked`.
- **Test:** none in the Kit (AppKit lives in the app target, which has no test target). The Coder's
  report lists the D2 table rows it walked by hand against the code (`com.apple.Safari` → Safari;
  `com.google.Chrome.helper` → owner Chrome, 5a+5b → "Google Chrome (Service)";
  `com.apple.Safari.SandboxBroker` → 5d → "Safari (Service)"; `org.mozilla.plugincontainer` → 5c;
  `com.apple.WebKit.Networking` → step 1; `com.apple.curl` → step 8). The live values are asserted in
  Task 8 (AI-AC14, 17, 18, 21).
- **Done when:** `swift apps/mac/tools/gen-tokens.swift` leaves no diff after the row is in
  (`git diff --exit-code apps/mac/Sources/Aitmproxy/UI/Tokens.swift` after a second run); the app
  target compiles under the Swift gate; the Rust gate is green (TUI build script consumed the new
  row); the Coder report names the pre-authorised wrapper if used.

---

### Task 5: Session tree state and the sidebar Apps tree

- **Satisfies:** D4 (Session), D5, D7, D10 (sidebar rows); AI-AC13 (tripwires); proven live by
  AI-AC14, AI-AC15, AI-AC19, AI-AC20 (Task 8).
- **Depends on:** Task 2 (`clientHost`, `ClientTree`, `Pins` mapping), Task 4 (`ClientMark`); **gate 4**
  (the traffic-route PR merged; its Tasks 2/2b have edited `Session.swift` — this task rebases onto them).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Session.swift` (modify)
  - `apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift` (modify; claim approved per the gate)
- **Change:**
  - `Session.swift` (D4):
    - `var expandedApps: Set<String> = []` (doc: group keys of the Apps rows showing their
      domains; session-only, never persisted).
    - `var clients: [(ClientInfo, Int)] { ClientTree.clients(in: rows) }` replaces the body.
    - `func hosts(forClient key: String) -> [(String, Int)] { ClientTree.hosts(forClient: key, in: rows) }`.
    - `func toggleExpanded(_ key: String)` (insert/remove).
    - `show(_:group:)`: after assigning, `if case .client(let k) = group { expandedApps.insert(k) }`
      and `if case .clientHost(let k, _) = group { expandedApps.insert(k) }`.
    - `pin`/`unpin`/`isPinned` become `pins.pin(group)`, `pins.unpin(group)` (then the existing
      `if self.group == group { self.group = nil }`), `pins.contains(group)`.
  - `SidebarView.swift` (D5):
    - `matches` grows to the app rule (D4, architect's call 12): an app is visible when the
      query matches its `name`, its `groupKey`, or any of `session.hosts(forClient:)` hosts.
    - Apps block: per visible `(client, count)` an **app row**: `HStack(spacing: 0)` of a chevron
      `Button` (`Image(systemName: Tok.Glyph.chevron)`, 12 pt, `Tok.Ink.tertiary`, in a 16-pt frame,
      `.rotationEffect(.degrees(expanded ? 90 : 0))` with **no** animation, action
      `session.toggleExpanded(key)`, accessibility label "Expand <name>"/"Collapse <name>") at
      leading inset `12`, then the row `Button` (`ClientMark(client:)` at inset `28`, `Space.sm`,
      title `client.name`, spacer, count) whose action is `session.show(.apps, group: .client(key))`;
      height `Tok.Size.control`; fill `Tok.Ground.active` when `session.page == .apps && session.group == .client(key)`;
      `.help(client.bundleID ?? client.name)`; `.contextMenu` Pin/Unpin App via
      `session.pin/unpin(.client(key))`; accessibility label
      `"<name>, <count> flows[, pinned], expanded|collapsed"` plus `.accessibilityAction(named:)`
      "Expand"/"Collapse".
    - Under an expanded app (or, while querying, a matching app): one **domain sub-row** per
      `session.hosts(forClient: key)` via `subItem(.clientHost(client: key, host: host), title: host, count: n, page: .apps, leadingInset: 52, mark: { Monogram(text: "◎") })`,
      `.help(host)`, context menu "Pin Host"/"Unpin Host" (the `noun` for `.clientHost` is "Host").
      **Plan call (filter):** while querying, the sub-rows shown are the hosts matching the query;
      when the app matched only by name/key, all its hosts are shown. Matt may overturn.
    - Pinned apps: `ForEach(session.pins.apps …)` keyed by the stored key; `current = session.clients.first { $0.0.groupKey == key }`;
      title `current?.0.name ?? key`, mark `ClientMark(client: current?.0 ?? ClientInfo(name: key, bundleID: key))`
      (plan call: a stale key still resolves through the one cache), count `current?.1`,
      `.help(key)`; visible when the query matches the key or the current name; not expandable.
    - `subItem` signature becomes
      `private func subItem<Mark: View>(_ group: FlowGroup, title: String, count: Int?, page: SidebarPage, leadingInset: CGFloat = 28, help: String? = nil, @ViewBuilder mark: () -> Mark) -> some View`;
      Domains rows and pinned hosts call it with `mark: { Monogram(text: "◎") }` and the default inset —
      their rendering is unchanged.
    - `AppMark` is deleted. `Monogram` stays (hosts only).
    - Insets are `12`, `28`, `52` as literals derived from `Space` where a token exists
      (`Space.md`/`Space.sm` combinations), each marked `// grid: ok` only if `grid-lint` needs it.
- **Test:** none in the Kit (SwiftUI). Source checks the orchestrator runs in the Terminal:
  the three tripwires print `PASS` (AI-AC13 — the edits add no capture control and no connection
  word), `apps/mac/tools/grid-lint.sh` prints `PASS`. Live assertions are Task 8's AI-AC15 and AI-AC19.
- **Done when:** the app target compiles under the Swift gate; all Kit tests still pass; the
  three tripwires and `grid-lint.sh` print PASS; `grep -n "AppMark\|NSRunningApplication" apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift`
  returns nothing (anti-goal: a second way to resolve).

---

### Task 6: Poll-loop enrichment and the Client cell

- **Satisfies:** D3, D6; AI-AC22 (diff shape); proven live by AI-AC17, AI-AC18, AI-AC21 (Task 8).
- **Depends on:** Task 4 (`AppIdentityResolver`, `Tok.Glyph.process`); **gate 4** (the traffic-route PR
  merged; its one `BusService.swift` line and PR D's CA polling are already in the file — this task's
  diff is still one added line on top of them).
- **Files:**
  - `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify; claim approved per the gate)
  - `apps/mac/Sources/Aitmproxy/FlowTable/FlowCellView.swift` (modify)
- **Change:**
  - `BusService.swift`: inside `pollLoop`'s nested `func scoped(_ row: FlowRow) -> FlowRow`, one
    added line before `return row`: `row.client = row.client.map(AppIdentityResolver.shared.enriched)`.
    Nothing else in the file changes — no `await`, no new call in the loop body (AI-AC22). Both
    the polled and the restored rows already pass through `scoped`.
  - `FlowCellView.swift` (D6):
    - Delete `MonogramView` (the class and its five uses). Add `let clientIcon = NSImageView()`
      (internal, not private, so a later test harness can reach it) with the monogram's constraints
      (leading `pad`, 16 × 16, label leading `6` after it for `.client`),
      `imageScaling = .scaleProportionallyUpOrDown`; `private var shownIdentifier: String?`.
    - `configure` `.client`: `let identifier = client.bundleID ?? client.name`;
      `shownIdentifier = identifier`; `clientIcon.isHidden = false`; `label.stringValue = client.name`
      in `Tok.Face.nsUI(body)`; then by `AppIdentityResolver.shared.identity(for: identifier)`:
      icon → `clientIcon.image = icon` (no tint); verdict without icon →
      `NSImage(systemSymbolName: Tok.Glyph.process, accessibilityDescription: client.name)`,
      `clientIcon.symbolConfiguration = .init(pointSize: Tok.Size.iconInline, weight: .regular)`,
      `clientIcon.contentTintColor = meta.nsColor`; pending → `clientIcon.image = nil` and
      `AppIdentityResolver.shared.onResolve(identifier) { [weak self] verdict in guard let self, self.shownIdentifier == identifier else { return }; <apply as above> }`.
      `client == nil` → `label.stringValue = Format.dash`, `clientIcon` hidden.
    - `toolTip`: `.client` → `row.client.map { $0.bundleID ?? $0.name }`.
    - `describeDrawnViews`: `clientIcon.setAccessibilityElement(!clientIcon.isHidden && clientIcon.image != nil)`,
      role `.image`, label `row.client?.name`.
    - `backgroundStyle` override and `FlowRowView.isEmphasized` stay as they are (selection must
      not template the icon or whiten the glyph).
- **Test:** none in the Kit (AppKit). The diff is the evidence for AI-AC22:
  `git diff <wave-C-base>..HEAD -- apps/mac/Sources/Aitmproxy/Bus/BusService.swift` is exactly one
  added line (plus at most a comment) and contains no `await`. Live assertions are Task 8's
  AI-AC17/18/21.
- **Done when:** the app target compiles under the Swift gate; the `BusService.swift` diff is one
  line; `grep -n "MonogramView" apps/mac/Sources` returns nothing.

---

### Task 7: Kit documentation (`design/KIT.md`)

- **Satisfies:** AI-AC24, D11
- **Depends on:** none (documents D5/D6 as specified; may run in Wave B).
- **Files:** `apps/mac/design/KIT.md` (modify)
- **Change:**
  - Rename "### Monogram (`Monogram`, `MonogramView`)" to
    "### Client mark (`ClientMark`, `FlowCellView.clientIcon`)": 16 × 16 real app icon when the
    identifier resolves to a bundle, else the `terminal` process mark (token `glyph.process`) 12 in
    the 16 frame in `Ink.secondary`, blank while a verdict is pending; the `Monogram` disc (16 × 16,
    radius 4, `Ground.raised`, one character 11/500 `Ink.secondary`) remains for host rows and
    domain sub-rows. Delete the TODO sentence "The real app icon replaces it when the client
    resolves to one. TODO (story S-…)."
  - "### Sidebar row": add the **app row** anatomy — chevron 12 in a 16 frame at inset 12 ·
    client mark 16 at inset 28 · gap 8 · name · spacer · count; domain sub-rows at inset 52 with
    the host monogram; the three insets 12 / 28 / 52 named once; "selecting an app opens it, the
    chevron toggles without selecting; no animation on the chevron".
  - "### Flow row" columns text: `Client 96 (monogram + name, ui face)` → `Client 96 (icon + name, ui face)`.
  - Remove any sentence that points at the parts gallery as the place to see these parts
    (the gallery is gone with the fixture modes; the kit page is the documentation).
- **Test:** `grep -c "TODO" apps/mac/design/KIT.md` drops by exactly one versus the base;
  `grep -n "Client mark\|glyph.process\|inset 52\|icon + name" apps/mac/design/KIT.md` shows all four.
- **Done when:** those greps hold and no other file changed.

---

### Task 8: Live proof on the installed notarized app (Terminal, orchestrator or Matt)

- **Satisfies:** AI-AC14, AI-AC15, AI-AC16, AI-AC17, AI-AC18, AI-AC19, AI-AC20, AI-AC21; the
  whole-branch gates AI-AC13, AI-AC23.
- **Depends on:** Tasks 1–7 merged into the branch and the Swift gate green on the whole branch.
- **Files:** none in the repo. Evidence lands in the PR description (screenshots, redacted bus
  output, `pins.json` contents); working files under `/tmp/claude/icons-live/`.
- **Steps (all in the Terminal panel; the sandbox cannot build, launch or script the app):**
  1. **Build and install the notarized app** from the branch head, `docs/RELEASE.md` step 3 without
     the upload: `scripts/package.sh`; `apps/mac/build.sh --ne --allow-unnotarized --replace`;
     `APP=/Applications/Aitmproxy.app ASC_ISSUER_ID=<issuer-id> scripts/notarize-dmg.sh`; mount the
     DMG and copy the stapled app over `/Applications/Aitmproxy.app`. Same-version sysex
     replacement needs no new approval (memory `aitmproxy-ne-udp-dontfrag-quic-regression`).
  2. **Launch** `/Applications/Aitmproxy.app`. Status page: note the version and build in the PR.
     Settings ▸ Capture: on. Scope: `example.com`, `www.apple.com`. Sidebar on the Flows page.
  3. **Traffic:** Safari → `https://example.com/` and `https://www.apple.com/`; a shell →
     `curl https://example.com/` twice (no `--proxy`); Google Chrome → `https://example.com/`
     (if Chrome is absent use Firefox, Slack, Signal, VS Code, WhatsApp or Zoom and name it).
     Do **not** compile or run anything else in scope yet.
  4. **AI-AC14 screenshot** `apps-tree.png`: `swift apps/mac/tools/winshot.swift Aitmproxy /tmp/claude/icons-live/apps-tree.png`
     with the Apps group showing. Record: the Apps header count; each row's mark and text
     (expected "Safari" + Safari icon, "curl" + process mark, "Google Chrome" and/or
     "Google Chrome (Service)" + Chrome icon, every row with a count and a collapsed chevron).
  5. **AI-AC15:** click the Safari row → screenshot `safari-expanded.png` (chevron turned,
     `example.com` and `www.apple.com` listed, their counts summing to Safari's; the list's Client
     cells all read "Safari"). Click `www.apple.com` under Safari → `safari-apple.png` (every row
     is Safari ∧ `www.apple.com`). Expand the Domains group and confirm `example.com` there counts
     Safari + curl + Chrome flows together → `domains-flat.png`. Click Safari's chevron alone →
     the row collapses, selection and list unchanged → `safari-collapsed.png`.
  6. **AI-AC16 bus read**, token never printed. Find the embedded core:
     `pid=$(pgrep -f '/Applications/Aitmproxy.app/Contents/Resources/core/aitm --config')`;
     `cfg=$(ps -o command= -p $pid | sed -n 's/.*--config \(.*\)$/\1/p')`;
     `bus=$(cat "$(dirname "$cfg")/bus.endpoint")` (host:port, token-free);
     `export AITM_OPERATOR_TOKEN=$(sed -n 's/^ *operator_token: *"\{0,1\}\([^"#]*\)"\{0,1\}.*/\1/p' "$cfg" | head -1)`.
     Run a short Python script saved under `/tmp/claude/icons-live/bus-read.py` that follows
     `tests/e2e/aitm_e2e/bus.py`'s wire protocol (TCP connect to `$bus`, one line
     `{"token": $AITM_OPERATOR_TOKEN}` read from the environment, `initialize`, then
     `tools/call flow.list`, then `flow.get` per id) and prints **only** `id`, `source_app`,
     `authority`/URL per flow and the count of distinct non-null `source_app` values. Paste that
     output in the PR; it must contain no token. Assert: the distinct count equals the Apps header
     count; for one flow under each Apps row the `source_app` equals that row's tooltip identifier
     (`com.apple.Safari`, `com.apple.curl`, `com.google.Chrome` / `com.google.Chrome.helper`);
     `source_app: null` flows (if any) belong to no row.
  7. **AI-AC17:** hover a Client cell on Flows → `tooltip-cell.png` (shows the identifier); hover
     the Safari app row → `tooltip-row.png`. Select a row → `selected-row.png`: its Client cell
     looks like an unselected one (no template icon, no white glyph). On the Apps drill-down,
     Client cells match the sidebar row's mark and text.
  8. **AI-AC18:** if a helper identifier appeared (`com.google.Chrome.helper*`,
     `com.apple.Safari.*`), screenshot its row beside the owner's row with its tooltip →
     `service-row.png`; else write "no helper observed" in the PR and attach step 6's output.
  9. **AI-AC19:** context-menu Pin App on Safari; context-menu Pin Host on `www.apple.com` under
     Safari → `pinned.png` (Pinned shows "Safari" with icon and count among apps; `www.apple.com`
     with `◎` among hosts). `cat ~/Library/Application\ Support/Aitmproxy/pins.json` → paste: `apps`
     contains `"com.apple.Safari"`, `hosts` contains `"www.apple.com"`. Then unpin both.
  10. **AI-AC21:** if no daemon or ad-hoc tool showed up in step 4, compile
      `/tmp/claude/icons-live/a.c` (a minimal program that opens `https://example.com/` via
      `curl`'s libcurl or `NSURLSession` — any binary named `a.out` works) and run it →
      `unbundled.png`: a row reading "out" with the process mark and tooltip `a.out`.
  11. **AI-AC20:** state in the PR that no TCC prompt appeared, that the Status page and list kept
      updating during the first resolutions (watch for a hitch while the first Chrome row appears),
      and screenshot Overview → `overview.png`: "Clients" tile equals the Apps header count, bars
      carry the same names, hovering a bar shows the identifier.
  12. **Whole-branch gates (AI-AC13, AI-AC23):** Swift gate, three tripwires, `grid-lint.sh`,
      `swift apps/mac/tools/gen-tokens.swift && git diff --exit-code apps/mac/Sources/Aitmproxy/UI/Tokens.swift`,
      Rust gate. Logs under `/tmp/claude/icons-live/gates/`.
  13. Quit the app normally (⌘Q, not `kill`), so the embedded core and obscura are reaped.
- **Done when:** every step's artefact exists under `/tmp/claude/icons-live/`, the PR description
  names each screenshot against its AI-AC, the bus output is pasted token-free, and the orchestrator
  dispatches the whole-branch Tester and the three reviewers with the Task 8 report.

---

## File-disjointness table

| File | T1 | T2 | T3 | T4 | T5 | T6 | T7 | T8 |
|---|---|---|---|---|---|---|---|---|
| `AitmproxyKit/AppIdentifier.swift` (new) | C | | | | | | | |
| `Tests/AitmproxyKitTests/AppIdentifierTests.swift` (new) | C | | | | | | | |
| `AitmproxyKit/FlowQuery.swift` | | M | | | | | | |
| `AitmproxyKit/ClientTree.swift` (new) | | C | | | | | | |
| `AitmproxyKit/Pins.swift` (doc comment) | | M | | | | | | |
| `Tests/AitmproxyKitTests/ClientTreeTests.swift` (new) | | C | | | | | | |
| `Tests/AitmproxyKitTests/FlowQueryTests.swift` | | M | | | | | | |
| `AitmproxyKit/Panels/Overview.swift` | | | M | | | | | |
| `AitmproxyKit/Panels/OverviewBreakdowns.swift` | | | M | | | | | |
| `Aitmproxy/Panels/OverviewBreakdowns.swift` | | | M | | | | | |
| `Tests/AitmproxyKitTests/OverviewTests.swift` | | | M | | | | | |
| `Tests/AitmproxyKitTests/OverviewBreakdownsTests.swift` | | | M | | | | | |
| `docs/design/tokens.json` | | | | M | | | | |
| `Aitmproxy/UI/Tokens.swift` (generated) | | | | G | | | | |
| `Aitmproxy/UI/AppIdentity.swift` (new) | | | | C | | | | |
| `Aitmproxy/Session.swift` | | | | | M | | | |
| `Aitmproxy/Shell/SidebarView.swift` | | | | | M | | | |
| `Aitmproxy/Bus/BusService.swift` | | | | | | M | | |
| `Aitmproxy/FlowTable/FlowCellView.swift` | | | | | | M | | |
| `apps/mac/design/KIT.md` | | | | | | | M | |
| (no repo files; `/tmp/claude/icons-live/`) | | | | | | | | — |

C = create, M = modify, G = regenerate. No file appears in two columns, so every wave's tasks can
run as parallel Coders. Shared with the traffic-route plan on this branch: `Session.swift` and
`Bus/BusService.swift` (its Tasks 2/2b) — that PR ships first; Tasks 5/6 here follow it (gate 4), never
concurrently. Not touched by anyone: `AitmproxyKit/Flow.swift`, `AitmproxyKit/FlowSummary.swift`,
`crates/**`, `apps/mac/Extension/**`.

## Acceptance-criteria coverage

| AI-AC | Class | Task |
|---|---|---|
| 1–6 | K | 1 |
| 7, 8, 9, 10, 12 | K | 2 |
| 11 | K | 3 |
| 13 | T | 5 (run), 8 (whole branch) |
| 14, 15, 19, 20 | L | 8 (built by 4, 5) |
| 16 | L | 8 |
| 17, 18, 21 | L | 8 (built by 4, 6) |
| 22 | review | 6 (diff), reviewers |
| 23 | gates | 4 (tokens, Rust), 8 (whole branch) |
| 24 | docs | 7 |

## Plan-level calls (for Matt to overturn if wanted; none blocks)

1. `fallbackName` is `knownUnbundled[id] ?? ClientInfo.displayName(forSourceApp: trimmedAdHoc(id))`.
2. `ClientTree.clients` and `OverviewBreakdowns.clients` order by count desc, name asc, **key asc**
   (the third key makes two "(Service)" rows of one owner deterministic).
3. `BoundedCache[key] = nil` deletes the entry and its age slot.
4. Sidebar filter while querying: sub-rows are the matching hosts; an app matched only by name or
   identifier opens to all its hosts.
5. A pinned key with no current client renders `ClientMark` over `ClientInfo(name: key, bundleID: key)`
   (one cache, no second path) with the key as title and tooltip.
6. `FlowCellView.clientIcon` is internal (not private) so a future harness can reach it.
7. Task 4's `@unchecked Sendable` hand-off wrapper is pre-authorised only for the `NSImage` hop,
   with a stated invariant and Security sign-off.

## Review log

Kept by the main session during stage 6. One row per finding.

Rows dated 2026-11-01 are the stage-6 panel on docs PR #242 (range `dac90fe9..0bad920f`, merged as
`7a5f8585`), which reviewed this plan together with the traffic-route plan; every finding is listed
in both plans' logs, fixed in the follow-up docs PR from this branch.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| docs #242 | spec | Critical | #1 (traffic-route) CA fact actions defined two incompatible ways | fixed in 644b9c90 in the traffic-route spec/plan: post-PR-D state everywhere (see that plan's log) |
| docs #242 | spec | Important | #2 (traffic-route) TR-AC3 two action lists | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Important | #3 (traffic-route) D10 remedy suffix; `advice` list; Scope actions two ways | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Important | #4 (traffic-route) "Scope closed" derived two ways | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Important | #5 (traffic-route) numeric-string Port, no test | fixed in 644b9c90 (traffic-route; the test is PR #246's) |
| docs #242 | spec | Important | #6 (traffic-route) Task 4 "Scan" anchor | superseded in 644b9c90: traffic-route Task 4 removed (`.openNetworkSettings` denied 2026-11-01) |
| docs #242 | spec | Important | #7 (traffic-route) footprint exceeds the grant | fixed in 644b9c90 (traffic-route gate 2 records the orchestrator's 2026-11-01 answers) |
| docs #242 | spec | Important | #8 this plan lacks the "traffic-route PR first" gate and the BusService/Session serialisation; both plans say "one PR" | fixed in 644b9c90: gate 4 added (traffic-route PR merged, SHA ___; Tasks 5/6 after traffic-route Tasks 2/2b); PR shape stated in both plans and the spec's Constraints |
| docs #242 | spec | Minor | #9 (traffic-route) AC ordinals ≠ ids | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #10 (traffic-route) "16 cases" is 14 | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #11 (traffic-route) `.caTrust` step kind | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #12 (traffic-route) Task 1 declares vs PR D provides | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #13 (traffic-route) STORIES.md both ways | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #14 (traffic-route) `proxy.system.*` described as future | fixed in 644b9c90 (traffic-route: PR #214) |
| docs #242 | spec | Minor | #15 (traffic-route) unreachable banner case | superseded in 644b9c90 (traffic-route D5 `knownOpenRoute`) |
| docs #242 | spec | Minor | #16 (traffic-route) RouteBanner doc comment | fixed in 644b9c90 (traffic-route) |
| docs #242 | spec | Minor | #17 stale line anchors (Session.swift post-#197 in this spec; this plan's base `5eac2a5`) | fixed in 644b9c90: spec D1/D4 cite `Session.clients` :343, `show(_:group:)` :388, `pin` :393 / `unpin` :400 / `isPinned` :408 on `main 8e19c2e3`; this plan's base is `main 8e19c2e3` |
| docs #242 | spec | Minor | #18 Status lines lack the 2026-11-01 amendment date | fixed in 644b9c90: spec and plan read "amended 2026-11-01 (self-approved, autonomous mode)" |
| docs #242 | spec | Minor | #19 (traffic-route) `Endpoint.address` stored vs computed | fixed in 644b9c90 (traffic-route; PR #246's shape) |
| docs #242 | quality | Important | (traffic-route) TR-AC3 two lists; CA reserved vs used; `.caTrust` vs `.caTrusted`; D10 remedy suffix; `scopeClosed` two ways; Task 4 "Scan" anchor | fixed / superseded in 644b9c90 (traffic-route; see spec #2/#1/#11/#3/#4/#6) |
| docs #242 | quality | Important | (traffic-route) `Tok.Size.Row.dense` is 28 pt, not 40 | fixed in 644b9c90 (traffic-route: 28 / 56, `Tokens.swift:296`) |
| docs #242 | quality | Important | this spec cites Session.swift:479-483 / :524-527 / :529-549 | fixed in 644b9c90: cited by symbol with `main 8e19c2e3` lines (see spec #17) |
| docs #242 | quality | Minor | research 21/22 H1 titles say 13/14; 22 never cites `16-system-proxy.md`; bare "research 12" | fixed in 644b9c90 (research 21/22) |
| docs #242 | quality | Minor | unlabelled inferences, incl. this spec's `exec` icon remark | fixed in 644b9c90: D9 labels it unverified; the traffic-route and research items are labelled or removed (see that plan's log) |
| docs #242 | quality | Minor | stale sentences, incl. this spec's "PR B is not released" and this plan's gate 1 blank | fixed in 644b9c90: D7 says PR B is released (v0.5.9); gate 1 = `3fe92f66`; the traffic-route items in that plan's log |
| docs #242 | quality | Minor | (traffic-route) numbering/ordering | fixed in 644b9c90 (traffic-route) |
| docs #242 | quality | Minor | (traffic-route) STORIES.md both ways | fixed in 644b9c90 (traffic-route) |
| docs #242 | quality | Minor | (traffic-route) StatusPanel footprint three ways | fixed in 644b9c90 (traffic-route) |
| docs #242 | quality | Minor | this plan's `subItem(… mark: Monogram(text: "◎"))` vs the declared `@ViewBuilder mark: () -> Mark` | fixed in 644b9c90: `mark: { Monogram(text: "◎") }` in Task 5 and spec D5 |
| docs #242 | quality | Minor | research 22 line citations drifted | fixed in 644b9c90 (research 22: proxy.rs:360, build.sh:241) |
| docs #242 | quality | Minor | Swift gate scratch paths differ between spec ACs and plans | fixed in 644b9c90: this spec's AI-AC23 = this plan's `test-build-icons`; traffic-route TR-AC9 = `test-build-routes` |
| docs #242 | spec (2nd pass) | Important | gate 2's PR #246 bullet contradicted gate 5 (`init?(compact:listenAddress:)` ships in #246) | fixed in 2ce11b30 |
| docs #242 | spec (2nd pass) | Minor | gate 5 head/test count stale (c8ed92f4 / 31 tests); Review-log rows lacked the fix SHA | fixed in 2ce11b30 |
| docs #242 | spec (2nd pass) | Minor | residual: PR #246's two listen-address vectors (bare IPv6 literal without brackets → nil; `:::8080` → nil, the core prints `[::]:8080`) missing from TR-AC2 | fixed in b57840e3: both literals added to TR-AC2 |
| docs #242 | quality (2nd pass) | Important | PR D's API mis-cited against `CATrustFacts.swift` 4ae616d3: the line helper is `text` (PR D's `state` is a `LaneState`); `needsAdmin` → `actions == [.openCAPanel]` and step action `.openCAPanel`; the string is `"CA trusted (System keychain)"`; the needs-admin line is `text`, not `remedy`; `platform: String` has no default | fixed in b57840e3 in the traffic-route spec/plan quote PR D verbatim (`line` = `text`; needs-admin `[.openCAPanel]`; capital S; `platform: "macos"` in every test value; an open CA entry stores `actions = []`) |
| docs #242 | quality (2nd pass) | Minor | hand-over position unstated (PR D inserts the CA step after `busConnected`; ours sits after `scopeSet`); PR D's nil-facts rows (`unknownStep()` / `notGeneratedStep()`) undecided | fixed in b57840e3: D4 and Task 2b state the move; the nil-facts rows are dropped from the list (Architect's call, open question 21 — `make` reads `Session.caTrust` alone; the first-run sheet and CA page keep them) |
| docs #242 | quality (2nd pass) | Minor | Amendments-log preamble named only four superseded items | fixed in b57840e3: the preamble names every superseded item (predicate names, `— set …` suffix, period handling, `… — add one`, start SHA `8175eea3`, `Open Network Settings…` as a button, our own `CATrustFacts.remedy` contract) |
| docs #242 | quality (2nd pass) | Minor | Goal "the same actions" vs the All Apps route `[.openCaptureSettings]` and step `.turnCaptureOn` | fixed in b57840e3: "the same lines; each step keeps its existing action" |
| docs #242 | quality (2nd pass) | Minor | D6 "~2 s effective" (the poll is 500 ms, `refreshProxyStatus()` every tick) | fixed in b57840e3: dropped, cadence stated as the 500 ms tick |
| docs #242 | quality (2nd pass) | Minor | icons spec AI-AC11 `Overview(rows:).clients` — the type is `OverviewStats` | fixed in b57840e3 |
| docs #242 | quality (2nd pass) | Minor | `flowTable` overlay anchor "~258"/"~261" | fixed in b57840e3: `ShellView.swift:258` in spec D7 and plan Task 3 |
| all | Spec (3rd pass) | Minor | `GettingStartedStep.Kind` listing showed `caTrusted` after `scopeSet`; PR D's enum is `coreRunning, busConnected, caTrusted, extensionOn, scopeSet, firstFlow` | fixed in ad83ab78: listings use PR D's source order; the steps order stays make's |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
