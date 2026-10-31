# Architecture review — after v0.5.4 (2026-10-31)

Check-in per `improve-architecture`, on `main` at 1854fae (v0.5.4), the day after the full-app
review (`review-2026-10-31.md`) and its three waves shipped. The 2026-10-28 review is the
baseline: its two Strong cards (Session split, FlowColumn out of the table view) are done and
stayed done; its carried card (one verb table) shipped in wave 3 (PR #186); its two "Worth
exploring" cards are re-rated below.
Ratings: **Strong** = do now · **Worth exploring** = at the named moment · **Speculative** = leave.

## Survey

- **Targets.** `AitmBusClient` (actor, 27 tests) ← `AitmproxyKit` (values only, ~350 tests)
  ← `Aitmproxy` (`defaultIsolation(MainActor)`, self-test 128 checks). Direction unchanged and
  right. Kit grew the right way this week: `VerbTable`, `ClearedFlows`, `ConnectionSummary`,
  `CaptureAdvice`, `SettingsDomain`, `BusEndpointSettings` are all values with tests.
- **Sizes.** Past 600: `Session.swift` 626 (403 after the 10-28 split; it grew back by 223
  lines in three days), `InspectorView.swift` 626, `EmbeddedCoreLaunchTests` 649,
  `ViewerTests` 631. Near it: `ExtensionController.swift` 593, `ScanPanel.swift` 590. The Kit
  viewers (500–565) do one job each and are fine.
- **Hot spots (30 days, commits touching the file).** `Session.swift` 25, `ShellView.swift` 24,
  `App.swift` 19, `SelfTest.swift` 17, `BusService.swift` 17, `SnapshotScenes.swift` 15,
  `SettingsView.swift` 14, `InspectorView.swift` 12. `Session` and `App` still change in every
  story (every story adds state to one and a menu item to the other); `SelfTest` and
  `SnapshotScenes` change with them because every check and scene is a literal in one file.
- **What grew `Session.swift` back.** Not state: the fixture *bus* (a 75-line `switch` over bus
  verb names installed as `commandRunner` inside `init`, with L4 craft/inject/scan fixtures),
  `loadFixtures` (45 lines), the L4 gate helpers (20), and the three navigation enums
  (`SidebarPage`, `InspectorLayout`, `AgentPolicy`, 110 lines) that sit above the class.
  The stored state is ~75 properties, as before.
- **Seams.** `FlowActions` has two real adapters (`BusService`, `FixtureActions`);
  `BusClient` has `FakeBusServer`; `ActiveConnectionDriver` has `LiveConnectionDriver` plus
  the Kit tests' fake. `Session.commandRunner` has a production adapter (`BusService`) and a
  test adapter that is an anonymous closure in `Session.init` — the one seam whose test half
  has no name, so `ARCHITECTURE.md` describes it as "the fixture closure in `Session.init`".
- **Drifted copies.** No duplicated `private struct` (the grep is clean). One duplicated
  function: `BusService.hostMatches(_:_:)` is `Scope.matches(_:_:)` (Kit, `Compose.swift`)
  line for line; `Session+Transfer`, `FixtureActions` and `FixtureExtras` already call the Kit
  one. (`BusService.swift` is frozen until the macOS revision-2 PR merges; carried below.)
- **Pure logic inside the main-actor store.** `Session.paletteItems(for:)` builds and ranks
  the palette (fuzzy score, literal-title-first, section order, Recent on top) in 90 lines
  that only the self-test exercises; `Session.landingPage(saved:)`, `clients`/`hosts`
  counting, `BusService.listenAddress()` (config.yaml parsing) likewise live in the app
  target where Kit tests cannot reach them.
- **Harness.** `SelfTest.runIfRequested` is one 370-line `Task` closure holding ~100 checks;
  `SelfTest+Live` is the same shape at 240. Three source-shape tripwires
  (`tools/check-*.sh`) pin file allow-lists and function bodies by name; two of them read
  `ShellView.swift`'s `MainView`, `AppsAttributionBanner` and `AppsEmptyState` bodies, so a
  move out of that file is a tripwire edit as much as a code edit.
- **Harness isolation gap (not a refactor; routed).** `Session.density`, `recentPaletteIDs`
  and `settingsTab` read `UserDefaults.standard` without the `Store.isOverridden` guard that
  `page`, `layout` and `autoSelect` have, so a snapshot or self-test run inherits the
  operator's row density, palette history and last Settings tab (the dev bundle shares the
  bundle id). Writes are guarded, reads are not. A real finding for the harness owner; fixing
  it changes snapshot output, so it is not part of a behaviour-neutral step here.
- **Deletion test.** `Session+*` extensions: still locality, not modules (no interface).
  `FixtureActions`: deleting it puts fixture behaviour into `Session` — it earns its place as
  the seam's second adapter. The fixture `commandRunner` closure fails the test the other way:
  it *is* a second adapter, hidden inside `init`, with no name to point a tripwire at.

## FixtureBus: the fixture command runner as a named adapter  [Strong — step 1]

Files: `Session.swift` (626 → ~550), new `Bus/FixtureBus.swift` (~90), `tools/check-capture-operator-only.sh`, `docs/ARCHITECTURE.md`.
Signal: a file past 600 lines; a seam with one named adapter; the hottest file.
Problem: the fixture bus is a 75-line closure inside `Session.init`, so every fixture verb
(L4 craft/inject gates, `scan.discover` scope refusal, the agent-gate JSON) edits the state
file; the capture tripwire's rule 4 ("agent-reachable surfaces reference none of the capture
glue") lists `BusService.swift` but cannot list the fixture bus, because it has no file.
Proposal: a type beside `FixtureActions`, same interface as the production runner:

```swift
/// The fixture bus: what `BusService.call` is live. Verbs the shell models act on the
/// session; the rest echo. Installed as `session.commandRunner` by `Session.init`.
final class FixtureBus {
    unowned let session: Session
    init(session: Session)
    func call(_ name: String, _ args: [String: JSONValue]) async throws -> JSONValue
}
```

`Session.init` becomes `commandRunner = { [bus = FixtureBus(session: self)] in try await bus.call($0, $1) }`;
`l4AgentGatesJSON()` moves with it (its only caller).
Benefits: the seam table gains its second named adapter (`BusService.call` / `FixtureBus.call`);
`FixtureBus.swift` joins rule 4's deny list in the same commit (it is the bus's stand-in, so
it must never mention the capture glue either — the same reason `BusService.swift` is there);
a fixture verb story stops touching `Session.swift`.
Proof of same behaviour: build clean; self-test 128/128 (every fixture verb runs through it);
`tools/check-capture-operator-only.sh` PASS with the new deny entry; light + dark snapshots
of every page compared against the pre-step bundle.
Plan: one commit.

## Session+Fixtures: the session on fixture data  [Strong — step 1]

Files: `FixtureExtras.swift` → `Session+Fixtures.swift` (54 → ~120), `Session.swift` (~550 → ~480).
Signal: the same file; one concern (fixture seeding) split across `Session.swift` and a
file whose name says "extras".
Proposal: pure move of `loadFixtures()` and `setL4Gate(_:_:)` into the renamed file (`git mv`
keeps the history), next to `loadFixtureExtras()`. `setL4Gate` is fixture-only by its own
doc comment ("the operator act `l4.agent.set` performs"), called by `AgentPanel` and the
fixture bus.
Benefits: one file answers "what does the fixture session look like"; `Session.swift` keeps
state, `init`, accessors, navigation and pins.
Proof: build; self-test (it asserts the fixture counts, in-scope counts and the Scripts
predicate); snapshots as above.
Plan: one commit.

## Navigation enums out of the state file  [Strong — step 1]

Files: `Session.swift` (~480 → ~370), new `Shell/SidebarPage.swift` (~115).
Signal: model enums above a class in the hottest file (the 10-28 review moved
`FlowColumn`/`Density` out of the table view for the same reason).
Proposal: pure move of `SidebarPage`, `InspectorLayout` and `AgentPolicy`. They are read by
`SidebarView`, `ShellToolbar`, `App`, `Snapshot`, `SelfTest`, `AgentPanel` and `KitGallery`;
none of those files change. (They cannot go to Kit: `symbol` reads `Tok.Glyph`.)
Benefits: `Session.swift` returns under 400 lines and holds one type; a sidebar-page story
edits `Shell/`.
Proof: build; self-test's S-069 menu audit (it walks `SidebarPage.allCases`); snapshots.
Plan: one commit.

## Self-test as check groups  [Worth exploring — with the next harness change]

Files: `SelfTest.swift` (510), `SelfTest+Live.swift` (239).
Signal: a 370-line function (the release optimizer gotcha), 17 commits in 30 days.
Problem: every story appends to one closure; a failing check's neighbours are the only
structure; two authors in one week edited the same closure (the review waves and the harness
session).
Proposal: `runIfRequested` becomes `for group in checkGroups { await group(session) }` over
`static let checkGroups: [(Session) async -> Void]` — one function per story area
(`checkFixtures`, `checkVerbs`, `checkFilters`, `checkClearUndo`, `checkMenus`, …), each in
`SelfTest+<Area>.swift`. No check moves or changes its text.
Proof: the PASS lines, in order, are identical before and after (`diff` of the two logs);
128/128.
Plan: three commits (groups, live groups, the shared `settle`/`check` helpers last).

## Palette ranking as a Kit value  [Worth exploring — with the next palette story]

Files: `Session+Palette.swift` (103), `Shell/CommandPalette.swift` (`PaletteItem`).
Signal: pure logic in the main-actor store that only the self-test can reach.
Proposal: `PaletteRanking.rank(_ items: [Entry], query: String, recent: [String]) -> [Entry]`
over a small `Entry { id, section, title, subtitle }` in Kit; `PaletteItem` keeps its `Kind`
(it carries closures, so it stays in the app). The literal-first, section-order,
Recent-on-top rules get literal tests; the self-test's palette check becomes a Kit test.
Not now: the next palette story (a new section or the Flows query) should pick the `Entry`
shape; doing it first would guess it.

## Split `ShellView.swift`  [Worth exploring — after the revision-2 PR merges]

Files: `Shell/ShellView.swift` (449: `ShellView`, `MainView`, five banners/empty states,
`Rule`/`VRule`, `BuildPoCTarget`).
Signal: 24 commits in 30 days, second hottest; nine types in one file.
Proposal: `Shell/MainView.swift` (page routing, flow area, panes, inspector) and
`Shell/FlowAreaStates.swift` (`CoreFailedBanner`, `AppsAttributionBanner`, `AppsEmptyState`,
`EmptyFlows`, `DropOverlay`); `ShellView.swift` keeps the window, sheets, overlays and the
live-stack wiring that rule 5 of `check-capture-operator-only.sh` counts.
Why not now: `check-capture-toggle.sh` reads `MainView`, `AppsAttributionBanner` and
`AppsEmptyState` bodies out of `ShellView.swift` by path (NS-AC3/NS-AC8, ~15 checks) and
rule 6 of the operator-only tripwire allows `restartCoreTick +=` in `ShellView.swift`
because `CoreFailedBanner` bumps it; the move is mostly a tripwire rewrite, and the
revision-2 PR is editing the neighbouring Shell files now. Do it the day that PR merges, in
one commit with the two scripts, and say so in both.

## `BusService.hostMatches` → `Scope.matches`  [Strong — after the revision-2 PR merges]

Files: `Bus/BusService.swift` (frozen today).
Signal: a drifted copy (identical today; the next scope rule change would make them differ).
Proposal: delete `hostMatches`, call `Scope.contains(row.authority, in: session.scopeHosts)`
in `pollLoop`'s `scoped(_:)`. One line, one commit, live self-test as proof (`scope.add` then
rows in scope).

## Bus poll at 500 ms with no window visible  [Worth exploring — carried]

Unchanged from the 10-28 review and the full-app review's section E: `BusService.pollLoop`
never slows. `pollInterval` is already a property; the step is a `NSApplication`
occlusion observer that sets it to 5 s when every window is occluded. Frozen file; carried.

## Inspector viewers as a model  [Worth exploring — carried]

`InspectorView.swift` is 626 (was 522). The WebSocket pane landed (S-045) without the
`ViewerKind`/`ViewerPlan` model the 10-28 review hoped it would force; the tab enums are
still two. Still the right moment is the next viewer story, not a standalone refactor.

## Session state objects (`FlowStore`, `ProxyStatus`)  [Speculative — carried]

~75 stored properties, 28 views observe `Session`. `@Observable` tracks per property, so the
cost is readability, not re-rendering. The push subscription (F4, web `/bus` PR #137 on the
core side) is still the moment a `FlowStore` with incremental host/client counts earns its
interface. Not before.

## Test hooks in the shipping app  [Speculative — carried]

`SelfTest`, `Snapshot`, `SnapshotScenes`, `FixtureBus`, `FixtureActions.clearFails`,
`Session.clearNoticeSeconds` compile into the release binary. The app target has no test
target (SwiftPM cannot test an executable target's internals without a library split), and
the self-test is how the built binary proves itself. A library split of the app target is a
milestone, not a check-in step.

## Top recommendation

The three **step 1** cards, in that order, each its own commit and each gated: FixtureBus
(the seam's second adapter gets a name and a tripwire entry), Session+Fixtures (the fixture
session in one file), navigation enums out. `Session.swift` ends near 370 lines and holds one
type; nothing changes for a user; the tripwires get stronger, not weaker. Then
**`hostMatches` → `Scope.matches`** and the **ShellView split** the day the revision-2 PR
merges, with the tripwire scripts in the same commits.

## Considered, not recommended

- **A `Prefs` helper for the six `UserDefaults.standard` `didSet` pairs on `Session`**: the
  real problem is the three unguarded reads (survey), and fixing those changes snapshot
  output — a harness fix, not a refactor. Route it; do not wrap it.
- **`Session+Clear.swift` for the Clear/Undo state and methods**: seven properties and five
  methods, landed last week, one author; splitting it now would be a fourth `Session+` file
  for a concern that may still change (the panel asked for the 8 s lapse). Revisit at 600.
- **Moving `SidebarPage` to Kit**: `symbol` reads `Tok.Glyph` (generated app tokens);
  splitting title from symbol to cross the target line buys nothing a test needs.
- **A `FixtureSession` subclass or a `Session` protocol**: fixtures are a mode of the one
  `Session`, chosen once by `Store.usesFixtures`; two types would double every view's seam.

## Step 1 status (2026-10-31)

Shipped on `claude/mac-architecture-616b30`, three commits on `main` 0f00017, one pure move
each: `FixtureBus` (Session.swift 626 → 564), `Session+Fixtures` (→ 515), navigation enums
(→ 415). Proof, before vs after:

- `swift test`: 493 Kit + 31 BusClient tests green (no test changed).
- Fixture self-test: **145 of 145** on both builds; the 145 `PASS` lines are identical except
  the timing check's measured milliseconds.
- `check-capture-operator-only.sh` PASS (9 surfaces, was 8), `check-capture-toggle.sh` PASS,
  `check-connection-words.sh` PASS, `grid-lint.sh` PASS, `check-layout.swift` PASS on every
  captured layout file.
- **Real run** (dev bundle + the repo's release core, `tools/snap-dev.sh none` with `CORE_DIR`,
  launched with an isolated `APP_STORE`, five real `curl` requests through the bound proxy
  port, `tools/winshot.swift` of the window, `/tmp/claude/live-proof.sh`): main and the branch
  show the same Apps page — Flows 5, Domains 2, Apps 0, the no-scope and no-attribution
  banners, five 200 rows, `0 / 5 rows` — and differ by 1,761 of 5.2 M pixels, all in the port
  number, the timestamps and the durations.
- Fixture snapshots: every page captured in the same run as the baseline differs by ≤ 3.4 k px
  (the window-activation chrome, as the wave-3 report measured). The full 148-file set could
  not be captured in one run today: three of four runs lost the main window partway (once with
  stray keystrokes `'yr '` typed into the sidebar field), while the untouched baseline bundle
  showed the same loss in one of its two runs — the screen is shared with sibling harnesses
  that drive the frontmost app, and a snapshot run makes itself frontmost every 0.8 s. A
  snapshot-gate that survives a shared screen (or runs on a virtual display) is a harness
  follow-up, not this step's.

Not done in step 1: the cards marked "after the revision-2 PR merges" and the harness
isolation finding (three unguarded `UserDefaults.standard` reads), routed to the orchestrator.
