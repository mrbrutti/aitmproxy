# Architecture review — end of M1 (2026-10-27)

Read-only check-in per `improve-architecture`, before M2's eleven inspector stories (S-019…S-029).
Ratings: **Strong** = do it now · **Moderate** = worth exploring, do at the named moment · **Weak** = speculative, leave.

## Survey

- **Targets.** `AitmBusClient` (6 files, actor, no UI) ← `AitmproxyKit` (21 files, values only: no SwiftUI, no `Tok`, no main actor) ← `Aitmproxy` (28 files, `defaultIsolation(MainActor)`). Dependency direction is right. Kit is well tested (ViewerTests 631, FilterTests 550 lines); the app target has no unit tests, only the self-test's ~30 checks through a built app.
- **Sizes.** No file past 600. App: `FlowTableView` 519, `Session` 356, `InspectorView` 343, `FlowCellView` 268. Kit: `CodeExport` 565, `JSONTree` 540, `BodyKind` 519, `TextDiff` 501 (each one job, fine).
- **Hot spots (30 days).** `FlowTableView` touched in 4/4 commits; `SidebarView`, `ShellView`, `ShellToolbar`, `FlowRowView`, `BusService`, `App` 3/4. The M1 commit touched 29 Swift files, but bundled eleven stories; the honest trigger is one feature: a row verb (S-010/S-017) lives in six app files (`FlowRowActions`, `FlowTableView`, `Session`, `App`/FlowCommands, `ShellView` closures, `InterceptBar`).
- **Seams.** `FlowActions` has two real adapters (`BusService`, `FixtureActions`); `BusClient` has `FakeBusServer`. Good. No duplicated `private struct`s.
- **Smells found.** Pure logic inside the `@MainActor` `Session` (`filteredRows`, `clients`, `hosts`, verb routing) that Kit tests cannot compile; verb title/enable logic copied 3–4×; inspector tab state as view-local `@State` in two unrelated enums; `bodyLines` duplicated verbatim in `RequestPane`/`ResponsePane`; a fixture lookup hard-coded in a production view (`ResponsePane.previousResponse`); `CodeLine.id = UUID()` minted on every render; a model enum (`Density`) in a view file.

## Inspector viewers as a model  [Strong]

Files: `Inspector/InspectorView.swift` (343), `Inspector/CodeView.swift`, `Snapshot.swift`, `DesignKit/KitGallery.swift`
Signal: before a big feature (M2 adds Cookies, Set-Cookie, Timing, 11-format Body picker, JSON tree, Image, Hex/protobuf/MessagePack, SSE, Diff, Find, truncated/Load more).
Problem: `RequestTab`/`ResponseTab` are two hard-coded enums; the chosen tab is `@State` inside each pane, so `Session`, the self-test and snapshot mode cannot pick a viewer (every M2 story has a `[snap]` criterion for a specific tab, and `Snapshot` only walks `SidebarPage`/`SettingsTab`). `rawLines`/`bodyLines` build `[CodeLine]` inside views (duplicated, untestable) and mint a new `UUID` per line per render, so `ForEach` rebuilds every line on each body pass: S-021's "5 MB without blocking a frame" fails by construction. Which viewers apply is a function of `BodyKind.detect` (already in Kit) but nothing computes it.
Proposal:
```swift
// AitmproxyKit/Viewers/ViewerKind.swift
public enum ViewerKind: String, CaseIterable, Sendable { case summary, headers, cookies, query, body, json, image, hex, sse, raw, timing, connection, diff }
public struct ViewerPlan: Hashable, Sendable { public var tabs: [ViewerKind]; public var initial: ViewerKind }
extension ViewerPlan { public static func request(_ m: HTTPMessage?, state: FlowState) -> ViewerPlan
                       public static func response(_ m: HTTPMessage?) -> ViewerPlan }   // uses BodyKind.detect
// AitmproxyKit/Viewers/CodeLines.swift   (CodeLine moves here; id = line index)
public enum CodeLines { public static func raw(_ m: HTTPMessage, original: HTTPMessage?) -> [CodeLine]
                        public static func body(_ m: HTTPMessage) -> [CodeLine] }
// Aitmproxy/Inspector/InspectorState.swift
@Observable final class InspectorState { var request: ViewerKind = .raw; var response: ViewerKind = .body; var format: BodyFormat = .auto; var find: String? }
```
`Session` owns `inspector: InspectorState`; `FlowDetail` gains `reference: HTTPMessage?` (fixtures fill it; F5 later) and the `auth.shop-staging.test` check leaves `ResponsePane`.
Benefits: each M2 viewer = one Kit model (most exist) + one view file in `Inspector/Viewers/` + one `ViewerKind` case; `Snapshot` walks `ViewerKind.allCases` per pane; self-test can assert "JSON tab shows for a JSON body"; `CodeLines` gets unit tests against `Fixtures`.
Proof of same behaviour: `tools/snap.sh` apps-light/dark pixel-identical (default tabs Raw/Body unchanged); gallery PNGs (`GalleryViewerParts` uses `CodeLine`/`HeaderTable`); self-test "the inspector has the login detail"; new `CodeLinesTests` asserting today's line output for the paused login fixture, captured before step 1.
Plan: (1) `CodeLines` + `CodeLine` to Kit with index ids, panes call it [tests + snap]; (2) `ViewerKind`/`ViewerPlan` replace both tab enums, one `PaneTabs<ViewerKind>` [snap, gallery]; (3) `InspectorState` on `Session`, panes read it, `Snapshot` gains `APP_SNAPSHOT_VIEWERS`, one self-test check [self + snap]; (4) `FlowDetail.reference` replaces the fixture lookup in `ResponsePane` [snap]. Four commits, each ≤ 6 files.

## One verb table for row actions  [Strong]

Files: `FlowTable/FlowRowActions.swift` (83), `FlowTable/FlowTableView.swift` (519, `buildRowMenu`/`markMenu`/`perform`), `Session.swift` (`perform(_:on:)`, `deleteOrKill`), `App.swift` (`FlowCommands`), `Shell/InterceptBar.swift`, `Shell/ShellView.swift`
Signal: one feature in six files; the same kind of bug twice.
Problem: "Apply & Resume" vs "Resume" is computed in four places (`InterceptBar:60`, `FlowCommands:105`, `buildRowMenu:315`, `Session.perform:309`); "Kill" vs "Delete" in three. The guards drifted already: the context menu disables out-of-scope verbs and `Session.perform` refuses them, but the Flow menu's Replay, Kill and Mark call `session.replay/kill/mark` directly and skip the scope check. Three things are called `perform`. `FlowRowActions.swift` mixes the enum, an `NSTableView` subclass, a SwiftUI popover and an `NSAlert`. `MainView` threads seven closures into `FlowTableView`.
Proposal:
```swift
// AitmproxyKit/FlowVerbs.swift
public enum FlowVerb: Hashable, CaseIterable, Sendable { case resume, kill, delete, replay, edit, mark, comment, buildPoC, pinHost, copyURL, quickLook }
public struct VerbItem: Hashable, Sendable { public var verb: FlowVerb; public var title: String; public var key: String?; public var enabled: Bool; public var reason: String? }
extension FlowVerb { public func item(for row: FlowRow, pinned: Bool) -> VerbItem
                     public static func menu(for row: FlowRow, pinned: Bool) -> [VerbItem] }   // order + separators
```
`Session.perform(_ verb: FlowVerb, on: FlowID)` is the only entry (menu bar, context menu, keys, intercept bar); it owns the guards. The async runner is renamed `run(_:_:)`. `mark(_:_:)` stays separate (submenu payload).
Benefits: one place for titles, keys and enablement; `FlowCommands` becomes `ForEach(FlowVerb.menu(for: focusedRow))`; `VerbItem` is unit-tested per state (paused, complete, killed, out of scope) in Kit; `FlowRowActions.swift` splits into `FlowKeyTable.swift` + `CommentPopover.swift`.
Proof of same behaviour: new `FlowVerbTests` seeded from today's `buildRowMenu` titles/enabled per fixture row; self-test marks/comment/clear/resume checks; snapshots pixel-identical (menus are not captured); manual: Flow menu titles on the paused login and on `cdn.*` (out of scope).
Plan: (1) `FlowVerbs.swift` + tests, compiles alone; (2) `buildRowMenu` uses `FlowVerb.menu`; (3) `FlowCommands` uses it and routes through `Session.perform` (closes the scope-guard gap: one behaviour change, named in the commit); (4) `InterceptBar` titles from `VerbItem`; (5) delete `FlowRowAction`, rename `perform`→`run`, split the file. Five commits.

## Flow list query as a Kit value  [Moderate — start of M3]

Files: `Session.swift` (`filteredRows`, `visibleRows`, `clients`, `hosts`, `FlowGroup`), `SelfTest.swift`
Signal: pure logic inside a `@MainActor` store; M3's filter bar "stacks on top later" (comment at `Session:146`) and `CompiledFilter`/`FilterSubject(row, detail)` already exist in Kit.
Problem: scope/group/chip/sort filtering is only testable through the built app; every access re-filters and re-sorts (`StatusBar` reads `visibleRows` twice per render).
Proposal: `public struct FlowQuery: Hashable, Sendable { var scopeOnly: Bool; var group: FlowGroup?; var chip: ContentCategory; var filter: FilterExpression?; var sort: FlowSort; func apply(_ rows: [FlowRow], details: [FlowID: FlowDetail]) -> [FlowRow] }` with `FlowGroup` moved to Kit. `Session` holds `query` and caches `visibleRows` in `didSet` of `rows`/`query`.
Proof: self-test checks "JSON chip narrows", "Scope filters to 13", "curl narrows to 3", "capture order"; new `FlowQueryTests` over `Fixtures` asserting the same counts.
Plan: (1) `FlowQuery` + tests; (2) `Session` delegates to it; (3) cache `visibleRows`.

## Split FlowTableView.swift by concern  [Moderate — with the next table change]

Files: `FlowTable/FlowTableView.swift` (519: representable, Coordinator, `FlowColumn`, `Density`)
Signal: hottest file (4/4 commits); `Density` is read by `Session`, `SettingsView`, `FlowCommands` but lives in a view file.
Proposal: pure moves — `FlowTable/FlowColumns.swift` (`FlowColumn`, `Density`), `FlowTableView+Menus.swift` (row menu, mark menu, comment popover), `FlowTableView+Layout.swift` (column persistence). No interface change.
Proof: build; snapshots pixel-identical; self-test S-008 column-layout checks.
Plan: one commit per file (3).

## Split CodeExport into export and cURL import  [Weak — before S-043]

`Viewers/CodeExport.swift` (565) holds four generators and a 200-line cURL parser (`parseCurl`, `shellTokens`) that only M4's Compose import needs. One pure move to `Viewers/CurlImport.swift`; `CodeExportViewerTests` already cover both. Not worth a commit until S-043 touches it.

## Split Session by concern  [Weak — revisit at S-070 or when Session passes ~500 lines]

`Session.swift` (356) carries 35 stored properties across flows, selection, navigation, prefs, proxy status, panel counts and telemetry. `@Observable` tracks per property, so the 1 Hz telemetry does not re-render the shell; only `rows` (50/s in S-070) hurts: `SidebarView` recomputes `clients`/`hosts` over every row per append. Shape when the time comes: `FlowStore` (rows, details, selection, query, incremental host/client counts), `ProxyStatus` (bus, capturing, intercept, listen, scope, telemetry), `Session` (navigation, prefs, and the two above). M5's panels will show the real seams; cutting now would guess them.

## Top recommendation

**Inspector viewers as a model** (Strong), then **One verb table** (Strong). Both are four-to-five commits, each proven by the existing snapshot/self-test run plus one new Kit test suite, and both are on M2's critical path (every viewer story needs a selectable tab; the verb table is where Diff Selected, Copy as cURL and Quick Look land).

## Considered, not recommended

- **Adapters writing through `Session`.** `BusService` and `FixtureActions` both mutate `session.rows` directly. That mirrors "the bus pushed", which F4 subscriptions will make literal; keep it. Only `clear()` (rows/details/select) is duplicated across both adapters and `Session`: fold into `Session.clearLocal()` during card 2, step 5.
- **A `Prefs` wrapper** for the three `if !Store.isOverridden { UserDefaults… }` lines in `Session`: a pass-through; fails the deletion test.
- **Kit viewer models, `BusClient`, `Tokens.swift` (generated).** Deep, tested, single-entry. Leave.
- **Fifteen empty `Button {}` placeholders** (Compose, Filter bar, Palette, Rules…): story work, not structure.
