# Architecture review — end of M6 (2026-10-28)

Check-in per `improve-architecture` for S-071, after M5/M6 and the S-069 audit. The M1 review
(`ARCHITECTURE-REVIEW-M1.md`) is the baseline: its card 3 (Flow list query as a Kit value) is done
(`FlowQuery`, cached `visibleRows`); cards 1 and 2 are carried below with what changed.
Ratings: **Strong** = do now · **Worth exploring** = at the named moment · **Speculative** = leave.

## Survey

- **Targets.** `AitmBusClient` (actor, 24 tests) ← `AitmproxyKit` (values only, 198 tests, 36 suites)
  ← `Aitmproxy` (`defaultIsolation(MainActor)`, self-test 105 checks). Direction unchanged and right.
  `CommandMap` (S-069) joined Kit so the brief, the menus and the tests share one list.
- **Sizes (before this pass).** `Session.swift` 809 — the only file past 600, and past the 400-line
  type rule. `FlowTableView.swift` 542 (representable + Coordinator + `FlowColumn` + `Density`),
  `InspectorView.swift` 522, Kit viewers 500–565 (one job each, fine).
- **Hot spots (30 days).** `App.swift` 9 commits, `ShellView`/`Session`/`SelfTest`/`BusService` 8,
  `ShellToolbar`/`FlowTableView` 6. `Session` and `App` change in every story because every verb
  adds state to one and a menu item to the other.
- **Seams.** `FlowActions` still has two real adapters; `BusClient` has `FakeBusServer`. The M5
  panels each own a state object (`PocPanelState`, `BrowserState`, `ActivityState`) created lazily
  by `Session`: the panel seam the M1 review hoped for appeared on its own.
- **Smells.** `Session` mixes 60 stored properties with ~45 methods across eight concerns. "Apply &
  Resume" vs "Resume" is still computed in four places (`InterceptBar`, `FlowCommands`,
  `buildRowMenu`, `Session.perform`); S-069 added `CommandMap` titles as a fifth copy, held in line
  by the self-test. `RequestTab`/`ResponseTab` are still two enums (tab state did move to
  `Session`). `BusService.call` recursed into itself (fixed in 7ce8963; see `FIXLOG.md`): a wrapper
  named after the call it wraps, inside a type whose `live()` accessor was easy to drop.
- **Deletion test.** `Session+*` extension files: deleting them puts the methods back into one
  809-line file — they earn their place as locality, not as modules (they add no interface).
  `FlowColumn`/`Density` in their own file: read by `Session`, `SettingsView`, `FlowCommands`,
  `FlowCellView`; a model enum in a view file fails locality.

## Session split by concern  [Strong — done this pass]

Files: `Session.swift` (809 → 403), new `Session+Verbs.swift` (180), `Session+Editing.swift` (69),
`Session+Filters.swift` (82), `Session+Palette.swift` (91).
Signal: a file past 600 lines and a type past 400; the hottest file.
Problem: a change to compose, filters or a row verb means scrolling one file that also holds the
telemetry counters, pins and panel states; two things are named `perform`.
Proposal: pure moves. `Session.swift` keeps every stored property, `init`, the computed accessors
(`visibleRows`, `clients`, `hosts`, `selectionSummary`), navigation/pins and `loadFixtures`. Each
extension file holds one concern's methods. Four members lose `private` so the extensions can see
them (`perform(_:_:)`, `bulk`, `parseFilterText`, `recompileFilter`, `compiledFilter`,
`savedFilterStore`, `filterExpression`'s setter).
Benefits: a verb story touches `Session+Verbs` and `App`; the state file stops churning.
Proof of same behaviour: build clean; 198 + 24 tests; self-test 105/105; `apps` light + dark
snapshots compared with `compare.swift` against the pre-pass captures (see commit).
Plan: one commit.

## FlowColumn and Density out of the table view  [Strong — done this pass]

Files: `FlowTable/FlowTableView.swift` (542 → 430), new `FlowTable/FlowColumns.swift` (112).
Signal: a model enum in a view file; the M1 card 4 said "with the next table change" — S-069 was it.
Proposal: pure move of `FlowColumn` and `Density`. No interface change.
Proof: build; snapshots as above; self-test S-008 (column layout) and S-016 (density) checks.

## One verb table for row actions  [Strong — carried, next]

Unchanged from the M1 card, now with a fifth copy of the titles in `CommandMap` and the S-069
self-test holding the menu bar to it. The shape: `FlowVerb` + `VerbItem(for:row,pinned:)` in Kit,
`Session.perform(_:on:)` the only entry, `FlowCommands` and `buildRowMenu` iterate the table.
Do it before S-041 (response-phase intercept adds "Apply & Resume" for responses) or S-045 (WS
frames add verbs), whichever lands first. Five commits as planned.

## Inspector viewers as a model  [Worth exploring — with S-045]

Half done: tab state lives on `Session` (`requestTab`/`responseTab`) and `BodyLines` is a Kit value.
Still two tab enums and `InspectorView.swift` at 522 lines. S-045 (WS frames replace the two panes
with one frame list over a viewer) is the moment to make `ViewerKind`/`ViewerPlan` real; doing it
before would guess the frame viewer's shape.

## Split FlowTableView's Coordinator menus into an extension  [Worth exploring]

`FlowTableView.swift` (430 after the move) still carries the row/mark/columns menus and the comment
popover inside the Coordinator. A `FlowTableView+Menus.swift` extension needs eight `private`
members opened up; do it with the verb table (the row menu becomes a loop over `VerbItem`).

## Session state objects (`FlowStore`, `ProxyStatus`)  [Speculative]

The M1 review's deeper cut. `@Observable` tracks per property, so the shell does not re-render on
telemetry today; F4 server push will make `rows` arrive as patches, and that is when a `FlowStore`
with incremental host/client counts pays for its interface. Not before.

## Top recommendation

**Session split by concern**, then **FlowColumn/Density out of the table view** — both pure moves,
both done in this pass, each its own commit. **One verb table** is the next Strong card and the
first thing the next verb-adding story should do.

## Considered, not recommended

- **A `MenuState` mirror for `FlowCommands`** (swift-swiftui's menu pattern): the menus already
  update because `Session` is passed into `FlowCommands` from the `App`; the S-069 self-test checks
  the titles and keys. No bug to fix.
- **Moving `BodyQuickLook` into Kit**: it is AppKit (`QLPreviewPanel`) and one file; stays in
  `Inspector/`.
- **A test target for the app module**: the self-test covers the app's wiring through the built
  binary and runs in `tools/verify.sh`; a second harness would split the checks.
