# macOS app review Wave 3 — architecture design

**Status:** Approved (autonomous mode, 2026-10-31)
**Research inputs:** `apps/mac/docs/review-2026-10-31.md` (section E "Architecture",
D2, the "Wave 3 — architecture" bullet and the stage-6 panel notes under "Waves"),
`apps/mac/docs/architecture-review-2026-10-28.md` ("Split FlowTableView's Coordinator menus",
"One verb table"), `apps/mac/docs/ARCHITECTURE.md`.

This is Swift (SwiftPM package `apps/mac`, Swift 6.2 tools, macOS 26), not Rust. Every
path below is relative to `apps/mac/` unless it starts with `docs/superpowers/`.

## Intent

The wave-1 and wave-2 review fixes left four structural debts that the review named and
deferred: the row verbs (titles, keys, enabled rules) are written six times and have already
disagreed once (B3); Clear drops every flow with no Undo (D2, rule 43); the hover-row chrome
is written three times; and the flow table scrolls horizontally whenever a side panel narrows
the pane below the columns' minimum sum. Wave 3 pays those down with one verb table in Kit,
Clear with one Undo step, one `HoverRowStyle`, and a responsive column set, without changing
a pixel of the surfaces that are already right.

## Goals

- One source of truth for every row verb: `VerbTable` in `AitmproxyKit`, consumed by the
  key table, the row context menu, the Flow menu, the intercept bar, the verb dispatcher and
  `CommandMap`. No row-verb title, list key or enabled rule is written anywhere else.
- Clear can be undone once (Edit ▸ Undo Clear, ⌘Z, or the status-bar notice), restoring the
  rows, details, selection and focused flow the app held, on fixtures and on a live bus.
- The three hover rows (`BarRow`, `HostRow`, `FlowListRow`) share one `HoverRowStyle`.
- When the pane is narrower than the visible columns' minimum sum, low-priority columns hide
  automatically (and come back when the pane widens) instead of a horizontal scroll bar; the
  user's own column choices are kept apart and persist unchanged.
- Snapshots of untouched surfaces are byte-identical before and after.

## Non-goals

- Bus poll slow-down when no window is visible (listed under wave 3 in the review; a separate
  card, not this spec).
- Any change to `Shell/ShellView.swift`, `Shell/SidebarView.swift`, `SettingsView.swift`,
  `Bus/ExtensionController.swift`, `Bus/CoreHealthState.swift` or any `Capture*` file; other
  sessions own them. The `ShellView` closures `onAction: { action, id in session.perform(action, on: id) }`
  must keep compiling unchanged.
- New verbs, new menu structure, new shortcuts. The Flow menu keeps its item order and its
  non-row items (Arm/Disarm, Resume All, Revert to Original, Add Host to Scope…, Copy as,
  Diff Selected) as they are.
- Undo for anything other than Clear. Undo of a Clear that the core performed is a restore of
  the app's view only; the core's `flow.clear` is not reversed.
- The `Session` god-model split and the "test hooks compile into the shipping app" cards
  (Speculative in the review).

## Anti-goals

- A verb table that the views then re-interpret: if a view computes a title or an enabled
  rule from `FlowRow` itself, the table has failed. Views read `VerbItem` fields and nothing
  else.
- Visual drift: a context-menu reorder, a changed title, a moved separator, or a changed row
  pixel on the `apps`, `edit-paused`, `filter-bar` or `overview` snapshots. (One exception,
  deliberate: the Flow menu gains "Edit Comment…" as the comment title when the row has a
  comment, which `CommandMap` already lists and the row menu already does.)
- An Undo that lies: a notice with "Undo" while the restore cannot survive the next bus poll,
  or a restore that silently drops the selection.
- Auto-hidden columns leaking into `columns.json`: a user who widens the window must get every
  column back without touching the header menu.
- Self-test or `swift test` counts going down; a check rewritten to pass rather than derived.

## Constraints

- Swift 6.2 strict concurrency; the app target is `@MainActor` by default, Kit is not. Kit
  types are values (`Sendable`, no SwiftUI, no `Tok`, no main actor), as `ARCHITECTURE.md`
  states. Kit tests are Swift Testing (`@Suite`, `#expect`), as `Tests/AitmproxyKitTests/`.
- Gate (replaces the Rust gate for this package): `swift test --scratch-path
  ~/Library/Developer/Aitmproxy/test-build` green; `tools/grid-lint.sh` PASS; `swift
  tools/check-layout.swift /tmp/Aitmproxy-shots-dev-<tag>/*-layout.json` PASS on every
  layout file; the in-app self-test (`--selftest`, 121 checks today) all green with the new
  checks counted.
- The Claude Bash sandbox cannot run SwiftPM; builds, tests and snapshots run through the
  Terminal panel. Snapshots for comparison are taken with `DEV_TAG=<tag> tools/snap-dev.sh
  <pages>`; the baseline for this wave is already at `/tmp/Aitmproxy-shots-dev-w3base`
  (`apps`, `edit-paused`, `filter-bar`, `overview`, `split`, `activity-log`, light + dark).
- S-069 (`SelfTest.checkMenuCoverage`) requires, for every `CommandMap` entry with
  `scope == .menu`, a menu item whose title is one of the entry's `titles` and whose key
  equivalent equals the entry's `shortcut`. Row-verb items in the Flow menu must therefore
  keep the key equivalents they print today (bare `e`, `r`, `d`, `p`; ⌘⏎; ⌘\; ⇧R; ⌘L; ⇧P).
- `CommandMapTests.mapMatchesTheBrief` holds `CommandMap.all` to `docs/BRIEF.md`; `brief` and
  `briefShortcut` strings do not change. Only the `items` titles move to the table.
- `BusService.pollLoop` rebuilds `session.rows` from `flow.list` every 500 ms and assigns it
  whenever it differs. Anything the app shows that the core no longer holds must be merged at
  that one assignment or it disappears within half a second.
- Design rules of `apps/mac/CLAUDE.md` hold: tokens only (`Tok`, `Space`), system controls,
  every action keeps its menu item and shortcut.

## Design

### 1. One verb table (Kit)

New `Sources/AitmproxyKit/VerbTable.swift`; tests `Tests/AitmproxyKitTests/VerbTableTests.swift`.
The app's `FlowRowAction` (`Sources/Aitmproxy/FlowTable/FlowRowActions.swift`) is deleted;
`FlowVerb` replaces it everywhere.

```swift
public enum FlowVerb: Hashable, Sendable {
    case resume, edit, kill, delete, replay, editAndReplay, buildPoC,
         resumeSelected, killSelected, mark(MarkColor?), comment, pinHost, copyURL, quickLook
}

public struct VerbContext: Sendable {
    public var row: FlowRow
    public var pendingEdits: Int        // Session.pendingEditCount(row.id)
    public var pinned: Bool             // Session.isPinned(.host(row.authority))
    public var selectedCount: Int       // rows selected in the list the row sits in
    public var selectedPausedCount: Int // of those, state == .paused
    public var isInterceptTarget: Bool  // Session.interceptTarget?.id == row.id
}

public enum VerbGroup: Sendable { case intercept, replay, selection, annotate, host }

public struct VerbItem: Sendable {
    public var verb: FlowVerb
    public var title: String
    public var key: String?          // the bare list key FlowKeyTable handles ("e", " ")
    public var shortcut: Shortcut?   // the menu-bar key equivalent (CommandMap's Shortcut)
    public var enabled: Bool
    public var group: VerbGroup
    public var disabledReason: String?
}

public enum VerbTable {
    public static func items(for context: VerbContext?) -> [VerbItem]
    public static func verb(forKey key: String, in items: [VerbItem]) -> FlowVerb?
    public static func titles(_ verb: FlowVerb) -> [String]
    public static var allTitles: [FlowVerb: [String]] { get }
    public static let order: [FlowVerb]                         // the surfaces' listing order
    public static func outOfScopeReason(_ authority: String) -> String
}
```
`VerbGroup` is `Int`-backed and `CaseIterable`; `VerbItem` is `Hashable`; `VerbContext` has
memberwise defaults (`pendingEdits: 0, pinned: false, selectedCount: 1, selectedPausedCount: 0,
isInterceptTarget: false`) so a test can write `VerbContext(row: paused)`.

`items(for:)` returns every verb exactly once, in `VerbTable.order` (groups contiguous; the
views put a separator at each group change):

| Group | Verb | Title | `key` | `shortcut` | Enabled iff |
|---|---|---|---|---|---|
| intercept | `.resume` | "Apply & Resume" iff `pendingEdits > 0`, else "Resume" | — | ⌘⏎ | `row.state == .paused` |
| intercept | `.edit` | "Edit Paused Request" | `e` | `e` | `row.state == .paused` |
| intercept | `.delete` | "Kill" iff state is `.paused` or `.pending`, else "Delete" | `d` | `d` | always |
| intercept | `.kill` | "Kill" | — | ⌘\ | `row.state == .paused` |
| replay | `.replay` | "Replay" | `r` | `r` | always |
| replay | `.editAndReplay` | "Edit & Replay…" | — | ⇧R | always |
| replay | `.buildPoC` | "Build PoC from Flow…" | `p` | `p` | always |
| selection | `.resumeSelected` | "Resume n Selected" (n = `selectedCount`) when `selectedCount > 1`, else "Resume Selected" | — | — | `selectedCount > 1 && selectedPausedCount > 0` |
| selection | `.killSelected` | "Kill n Selected" / "Kill Selected", same rule | — | — | same |
| annotate | `.mark(nil)` | "Mark" (a submenu the views render from `MarkColor.allCases` + "Clear Mark") | `m` | — | always |
| annotate | `.comment` | "Comment…" iff `row.comment == nil`, else "Edit Comment…" | `c` | ⌘L | always |
| host | `.pinHost` | "Unpin Host" iff `pinned`, else "Pin Host" | — | ⇧P | always |
| host | `.copyURL` | "Copy URL" | — | — | always |
| host | `.quickLook` | "Quick Look Body" | `" "` | — | always |

"Always" is still subject to the scope rule: when `row.inScope == false`, every item has
`enabled == false` and `disabledReason == "Out of scope — add \(row.authority) to scope to act"`
(the exact string `Session.perform` reports today; `VerbTable.outOfScopeReason(_:)` builds it
and the row menu's trailing note reuses it). In scope, an item a state rule turns off carries
the reason a surface can show: `.resume` / `.edit` / `.kill` "Only a paused flow can be
resumed" / "…edited" / "…killed" (the edit string is today's `lastError`), the two selection
verbs "No paused flows in the selection"; enabled items have `disabledReason == nil`; the
scope reason wins when both apply. `items(for: nil)` (no focused row) returns the default
titles ("Resume", "Delete", "Resume Selected", "Mark", "Comment…", "Pin Host", …) with every
item disabled and no reason.

`shortcut` values are exactly the `CommandMap` Flow-entry shortcuts for those verbs, so the
Flow menu built from the table satisfies S-069 by construction **(Architect's call: the
dispatch wrote only "key e" for edit; the bare key is both the list key and the menu key
equivalent today, so both fields carry it)**. `.mark`, `.quickLook`, `.copyURL` and the two
selection verbs have no menu key equivalent (Mark and Quick Look are `.inContext` in
`CommandMap`; Copy URL and the selection verbs are not in the brief).

`verb(forKey:in:)` returns the verb of the item whose `key == key`, else nil; it ignores
`enabled` (the dispatcher reports the reason). `titles(_:)` returns every title variant a
verb can show, default first: `.resume → ["Resume", "Apply & Resume"]`, `.delete → ["Delete",
"Kill"]`, `.comment → ["Comment…", "Edit Comment…"]`, `.pinHost → ["Pin Host", "Unpin
Host"]`, `.resumeSelected → ["Resume Selected"]` (count variants are not enumerated),
single-element arrays otherwise. `allTitles` is `titles(_:)` for every verb (the `.mark`
key is `.mark(nil)`).

Why Kit: every rule is a function of `FlowRow` plus five integers/booleans the session knows;
making it a value lets `VerbTableTests` pin the literal titles the six copies disagreed on.

### 2. App wiring

- **`Session+Verbs.swift`** — `perform(_ verb: FlowVerb, on id: FlowID)` is the only entry for
  a row verb. It builds the context (`verbContext(for:pane:)`, below), takes the item from the
  table, and if `enabled == false` sets `lastError = disabledReason` (nil reason → silent) and
  returns; otherwise dispatches as today (`.resume` → `applyAndResume` iff `pendingEdits > 0`
  else `resume`; `.edit` → `editPaused`; `.pinHost` from `context.pinned`; the rest unchanged).
  Helpers, all `@MainActor` on `Session`:
  `func verbContext(for id: FlowID, pane: Int = 0) -> VerbContext?` (nil when the id is not in
  `rows`; `pane == 1` reads `secondSelection`), `func verbItems(for id: FlowID?, pane: Int = 0)
  -> [VerbItem]`, `func verbItem(_ verb: FlowVerb, for id: FlowID?, pane: Int = 0) -> VerbItem`
  (falls back to the nil-context default item). The `ShellView` closures compile unchanged
  because `FlowTableView.onAction` becomes `(FlowVerb, FlowID) -> Void`.
- **`FlowRowActions.swift`** — `FlowRowAction` deleted. `FlowKeyTable.keyDown` keeps `i`
  (toggle intercept), `n` (compose) and Return (enter) as special cases; every other
  unmodified key goes through `VerbTable.verb(forKey:in: VerbTable.items(for: nil))`; Space
  still toggles Quick Look off when the panel is visible. `onVerb: ((FlowVerb) -> Void)?`.
  `CommentPopover`, `MarkColor.title`, `ClearConfirmation` stay in this file.
- **`FlowTable/FlowTableView+Menus.swift`** (new) — the Coordinator's row menu, mark submenu,
  comment popover and columns menu move here as an extension (the `private` members they need
  become internal). `buildRowMenu` iterates `VerbTable.items(for: context)` where the
  Coordinator builds the context from its own table: `selectedCount` /
  `selectedPausedCount` from `table.selectedRowIndexes`, `pendingEdits` from the existing
  closure, `pinned` from `parent.isPinned`, `isInterceptTarget` from
  `session.interceptTarget`. Rendering rules: a separator at each group change; `.mark` as a
  submenu (today's `markMenu`); the `.selection` group only when `selectedCount > 1`; `.kill`
  skipped in the row menu **(Architect's call: the row's `d` item already reads "Kill" for a
  paused or pending row; two adjacent "Kill" items would be noise — ⌘\ stays in the Flow
  menu and the bar)**; `.quickLook` rendered like any other item (new in the row menu, last
  in `.host`); after the items, when the first item has a `disabledReason` of the scope kind
  (i.e. `!row.inScope`), a separator and one disabled item titled with that reason. Each
  item's `keyEquivalent` is `item.key ?? ""` with an empty modifier mask, as today.
- **`App.swift` Flow menu** — unchanged item order and non-row items. Each row item takes
  `title`, `.keyboardShortcut` (from `shortcut`, through a small `Shortcut → KeyboardShortcut`
  helper in the app) and `.disabled(!enabled)` from `session.verbItem(_:for:)`. Resume (⌘⏎)
  and Kill (⌘\) use the intercept target's id (`session.interceptTarget?.id`); every other row
  item uses `session.focused`. Resume's action becomes `session.perform(.resume, on:
  target.id)` (the table decides Apply & Resume vs Resume; same result as today's
  `applyAndResume`). "Resume Selected"/"Kill Selected" take their title and enabled rule from
  the table, so with one row selected they are disabled (today they enable whenever the one
  selected row is paused) — accepted, it matches the row menu.
- **`Shell/InterceptBar.swift`** — the Resume title is `session.verbItem(.resume, for:
  target?.id).title`; the Edit button (full and compact) is shown iff
  `session.verbItem(.edit, for: target?.id).enabled`; Edit calls `session.perform(.edit,
  on:)`; Resume may keep `session.applyAndResume(target.id)` (with no pending edits it is a
  plain resume, the same path `perform(.resume, on:)` takes). `coreFailed` dimming stays.
- **`CommandMap.swift`** — the Flow entries for Resume, Kill, Edit Paused Request, Replay,
  Edit & Replay, Kill/Delete, Mark, Comment, Pin Host, Build PoC, Quick Look Body use
  `VerbTable.titles(_:)` for their `items` titles and the table's `shortcut` (falling back to
  the list key for the `.inContext` verbs Mark and Quick Look, which the brief writes as `m`
  and Space) for their `items` shortcut, and `listKey` from the table's `key`.
  `brief`/`briefShortcut` strings are untouched. (The "Kill…" variant disappears from `items`;
  no menu has shown it.)
- **`Session+Palette.swift`** — no row-verb titles today; nothing to change.
- **`docs/ARCHITECTURE.md`** — Kit list gains `VerbTable`; "Checks that hold the shape" says
  the verb-table refactor card is done and names the next one; the self-test count is updated
  to the real number.

Proof of no drift: `apps`, `edit-paused`, `filter-bar` snapshots (light + dark) byte-identical
to the baseline; S-069 checks green.

### 3. Clear with Undo (D2, rule 43)

- **Kit, `Sources/AitmproxyKit/ClearedFlows.swift`** **(Architect's call: Kit, so the merge
  is unit-tested)**:
  ```swift
  public struct ClearedFlows: Sendable {
      public var rows: [FlowRow]; public var details: [FlowID: FlowDetail]
      public var selection: Set<FlowID>; public var focused: FlowID?
      public var count: Int { rows.count }
      /// The restored rows first, then rows that arrived after the clear, their `seq`
      /// shifted past the restored maximum so `#` stays monotonic.
      public static func merge(restored: [FlowRow], newer: [FlowRow]) -> [FlowRow]
  }
  public struct ClearNotice: Equatable, Sendable { public var count: Int; public var text: String }
  ```
- **`Session`** — `var clearNotice: ClearNotice?` and `var restoredFlows: [FlowRow]` (rows the
  app shows that the core no longer holds), `@ObservationIgnored` snapshot of the last clear
  and the notice timer task. `clearSession(confirm:)` captures `ClearedFlows(rows, details,
  selection, focused)` synchronously before `actions.clear()`, resets `restoredFlows = []`,
  and after the clear succeeds registers one undo step on `(NSApp.keyWindow ??
  NSApp.mainWindow)?.undoManager` with action name "Clear" (Edit ▸ Undo Clear, ⌘Z) and sets
  `clearNotice = ClearNotice(count:)` (the bar's Undo calls `undoClear()`), scheduling a task that nils the
  notice after 8 s. A failed clear registers nothing and shows no notice. `undoClear()`
  restores `rows = ClearedFlows.merge(restored:, newer: rows)`, merges `details`, sets
  `selection` and `focused`, sets `restoredFlows = cleared.rows`, cancels the timer, nils
  the notice, and clears the snapshot (one step; a second ⌘Z does nothing).
  `deleteOrKill` on a finished row also removes it from `restoredFlows`.
- **`Bus/BusService.swift` `pollLoop`** — the one assignment becomes
  `let merged = ClearedFlows.merge(restored: session.restoredFlows, newer: rows); if merged !=
  session.rows { session.rows = merged }`. **(Architect's call, outside the dispatch's
  "may touch" list but not on the must-not list: without it an undone Clear is wiped by the
  next poll on a live bus, which is the anti-goal "an Undo that lies". Fallback if rejected:
  register the undo step and show "Undo" only when `Store.usesFixtures`, and say so in the
  notice.)** Known limit, documented in the code: a restored row is the app's view — Mark,
  Comment, Replay on it report the core's error as any unknown-id verb does today.
- **`Shell/StatusBar.swift`** — in the centre slot, when `clearNotice != nil`, "Cleared n
  flows — Undo" replaces the row count: `Text("Cleared \(n) flow\(n == 1 ? "" : "s")")` and a
  `Button("Undo")` in the status bar's small-button idiom (`SmallButton`), tooltip "Restore
  the cleared flows (⌘Z)". Nothing else in the bar moves; the `apps` snapshot (no notice) is
  byte-identical.
- **Self-test** (`SelfTest.swift`, after "clearing empties the session"): three new checks —
  "clear shows the notice with the count" (`clearNotice?.count == n` where n is the row count
  before the clear), "undo restores the rows, selection and focused flow" (`rows.count == n`,
  `selection == before.selection`, `focused == before.focused`), "undo dismisses the notice"
  (`clearNotice == nil`, and the undo manager has no step left). The undo is triggered through
  the undo manager the clear registered with (`Session.clearUndoManager`, the key window's or
  the session's own), so the check exercises the Edit ▸ Undo path, not a closure. Count rises
  from 121 to 124.

### 4. HoverRowStyle

`Sources/Aitmproxy/UI/HoverRowStyle.swift`: one `ButtonStyle` holding `@State hovered`,
applying in this order `.padding(.horizontal, Space.xs)`, `.frame(height: Tok.Size.Row.dense)`,
`.background(hovered ? Tok.Ground.hover.color : .clear, in: RoundedRectangle(cornerRadius:
Tok.Radius.badge))`, `.contentShape(Rectangle())`, `.onHover`, and
`.environment(\.rowHovered, hovered)` on the label. A new environment entry
`EnvironmentValues.rowHovered: Bool` (default false, `@Entry`). `BarRow` and `HostRow`
(`Panels/OverviewPanel.swift`) and `FlowListRow` (`Panels/OverviewBreakdowns.swift`) drop
their `hovered` state and the four modifiers and use `.buttonStyle(HoverRowStyle())`;
`FlowListRow`'s chevron reads `@Environment(\.rowHovered)` for its opacity. Accessibility
modifiers stay on the Button as today. Proof: `overview` snapshot byte-identical.

### 5. Responsive flow columns

- **Kit, `Sources/AitmproxyKit/ColumnLayout.swift`** gains
  ```swift
  public enum ColumnFit {
      /// Ids to hide, in `priority` order, until the visible widths plus `flexibleMin` fit `available`.
      public static func autoHidden(available: Double,
                                    columns: [(id: String, width: Double, userHidden: Bool)],
                                    flexibleMin: Double,
                                    priority: [String]) -> Set<String>
  }
  ```
  `columns` lists every column except the flexible URL column; `flexibleMin` is URL's
  minimum (200). Columns with `userHidden == true` are skipped (not counted, never returned).
  Ids not in `priority` are never hidden. The result is the shortest prefix of `priority`
  (restricted to visible columns) whose removal makes `Σ visible widths + flexibleMin ≤
  available`; when no prefix suffices, every visible priority id is returned (the table then
  scrolls, as a last resort). Tests in a new `Tests/AitmproxyKitTests/ColumnLayoutTests.swift`
  (the existing `ColumnLayoutTests` suite in `ListTests.swift` moves there).
- **App, `FlowTableView`** — `static let autoHidePriority: [FlowColumn] = [.edited, .origin,
  .ssl, .response, .request, .duration, .client]` **(Architect's call: the dispatch listed six;
  the `split` pane is ≈598 pt at 1440 wide and the six only reach a 672 pt floor, so `client`
  — whose information the Apps sidebar already carries — is the seventh; `time`, `status`,
  `dot`, `mark`, `comment` are never auto-hidden)**. `Coordinator.autoHidden: Set<FlowColumn>`
  is kept apart from the user's hidden set (`userHidden`, what `columns.json` holds).
  `applyAutoHide()` runs on clip resize and after a column toggle/reset, before
  `fitURLColumn()`: it computes the set from the clip width, sets `isHidden = userHidden ||
  autoHidden` per column, and reloads only when the set changed. `currentLayout()` persists
  `userHidden` only. The header menu shows the user's state (on/off); an auto-hidden column
  that the user has on is `.mixed` with tooltip "Hidden to fit the pane", and toggling it
  flips the user's state as today.

Proof: `activity-log` and `split` snapshots show no horizontal scroll bar and the low-priority
columns gone; `apps` (full width, 1199 pt ≥ 1096 pt minimum sum) byte-identical.

## Acceptance criteria

1. AC1: `VerbTable.items(for:)` for a paused row with `pendingEdits == 1` has `.resume` titled
   "Apply & Resume" and enabled; with `pendingEdits == 0`, "Resume" and enabled.
2. AC2: For a `.complete` row, `.resume` is disabled and `.delete` is titled "Delete"; for a
   `.pending` row `.delete` is titled "Kill".
3. AC3: For a row with `inScope == false`, every item has `enabled == false` and
   `disabledReason` containing `row.authority`.
4. AC4: With `selectedCount == 3, selectedPausedCount == 1`, `.resumeSelected` is titled
   "Resume 3 Selected" and enabled; with `selectedCount == 1` it is disabled.
5. AC5: `pinned == true` gives `.pinHost` titled "Unpin Host"; `verb(forKey: "e", in:)` is
   `.edit`, `verb(forKey: "x", in:)` is nil; `allTitles[.resume] == ["Resume", "Apply &
   Resume"]`; `items(for: nil)` has every item disabled.
6. AC6: `FlowRowAction` no longer exists; `grep -rn '"Apply & Resume"\|"Edit Paused
   Request"\|"Build PoC from Flow…"\|"Unpin Host"\|"Edit Comment…"' Sources/Aitmproxy` returns
   nothing (every row-verb title literal lives in `VerbTable.swift`); `Shell/ShellView.swift`
   is not in the diff.
7. AC7: `swift test` is green with `VerbTableTests`, `ClearedFlowsTests` and
   `ColumnLayoutTests` added; the self-test is 124 of 124 including every S-069 "menu has"
   check.
8. AC8: `apps`, `edit-paused`, `filter-bar`, `overview` light and dark PNGs are byte-identical
   (`cmp`) to `/tmp/Aitmproxy-shots-dev-w3base`.
9. AC9: In the self-test, after `clearSession` the rows are empty and `clearNotice?.count`
   equals the pre-clear row count; after `clearUndoManager?.undo()` the rows, `selection` and
   `focused` equal their pre-clear values and `clearNotice == nil`.
10. AC10: `ClearedFlows.merge(restored: R, newer: N)` returns R followed by N with each N row's
    `seq` increased by `R.map(\.seq).max()`; `merge(restored: [], newer: N) == N`.
11. AC11: On the installed or dev app with a live bus: Clear → the status bar reads "Cleared n
    flows — Undo" → Undo → the n rows are back and stay for at least 2 s (four polls); Edit ▸
    Undo reads "Undo Clear" immediately after a Clear.
12. AC12: `BarRow`, `HostRow` and `FlowListRow` contain no `onHover`, no `hovered` state and no
    `Tok.Ground.hover` reference; `HoverRowStyle.swift` is the only file in
    `Sources/Aitmproxy/Panels` + `UI` that applies `Tok.Ground.hover` to a row.
13. AC13: `ColumnFit.autoHidden` with the default widths (dot 24, seq 52, client 96, method 72,
    status 84, time 124, duration 88, request 80, response 80, ssl 40, edited 64, origin 72,
    mark 20, comment 160 user-hidden; `flexibleMin` 200; the seven-id priority) returns `[]`
    for `available: 1096`; `["edited", "origin"]` for 1000; `["edited", "origin", "ssl",
    "response", "request"]` for 800; all seven for 500; and `["origin"]` for 1000 when
    `edited` is user-hidden.
14. AC14: `activity-log` and `split` snapshots show no horizontal scroll bar in the flow list
    and no Edited/Origin/SSL column header; `apps` is byte-identical (AC8); after the change
    `columns.json` written by the dev app contains no auto-hidden id in `hidden`.
15. AC15: `tools/grid-lint.sh` PASS; `check-layout.swift` PASS on every `*-layout.json` of the
    re-captured set.

## Left to the builder

- The `Shortcut → KeyboardShortcut` helper's name and home (the app target).
- How the Coordinator stores the context closure for `isInterceptTarget` (it already holds
  `pendingEdits` as a closure set in `updateNSView`).
- The exact `@Entry` declaration for `rowHovered` and whether `HoverRowStyle` takes a
  `height` parameter (default `Tok.Size.Row.dense`) — all three rows use dense today.
- Which `Session` extension file holds `undoClear()` (`Session+Verbs.swift` is the default).
- Whether the status-bar Undo reuses `SmallButton` or a text-only button, as long as the bar's
  height and the `apps` snapshot do not change.
- Test fixture rows for `VerbTableTests` (hand-built `FlowRow`s or `Fixtures.rows` seq 50
  paused, seq 52 pending, seq 41 complete, seq 44 `inScope: false` — see `Fixtures.swift`).

## Open questions

None blocking (autonomous mode). Two calls for Matt to countersign, recorded in the Design:
the one-line `BusService.pollLoop` merge for live Undo (section 3) and `client` as the seventh
auto-hide column (section 5).
