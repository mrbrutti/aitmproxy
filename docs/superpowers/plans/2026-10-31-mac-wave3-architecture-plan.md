# macOS app review Wave 3 — architecture implementation plan

**Status:** Approved (autonomous mode, 2026-10-31)
**Spec:** `docs/superpowers/specs/2026-10-31-mac-wave3-architecture-design.md`
**Branch / worktree:** `claude/cool-engelbart-633d63` at
`/Users/matt/Security/aitmproxy/.claude/worktrees/cool-engelbart-633d63` (based on PR #180's head)

## Overview

Seven sequential tasks, one commit each, in the order the spec's design sections build on
each other: the Kit verb table (1), the app wired to it (2), Clear with Undo (3), the shared
hover style (4), the Kit column fit (5), the responsive columns (6), then docs, the full gate
and the snapshot comparison (7). Tasks 4 and 5 touch disjoint files from everything else and
could run alongside 3 or 6, but they are done in series here because one session implements
them. **Task 1 is already on the branch as `96b3da0`; Task 2 was in flight (uncommitted) when
this plan was written** — the plan records both so the Review log can cite them.

**How this plan is executed.** This is a Swift package; the Claude Bash sandbox cannot run
SwiftPM (`swift build`/`swift test` need the toolchain's sockets and caches), so every task
is implemented in the main session with builds, tests, self-test and snapshots run through
the Terminal panel — not by Coder sub-agents. Each task still follows TDD where a test
exists: write the failing Kit test or self-test check, see it fail, make it pass.

Paths are relative to `apps/mac/`. Gate, per task and at the end (spec Constraints):

```sh
swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build          # Kit + bus-client tests
DEV_TAG=w3 tools/snap-dev.sh apps,edit-paused,filter-bar,overview,split,activity-log
tools/grid-lint.sh
swift tools/check-layout.swift /tmp/Aitmproxy-shots-dev-w3/*-layout.json
APP_STORE=/tmp/Aitmproxy-selftest-w3 /tmp/Aitmproxy-dev-w3.app/Contents/MacOS/Aitmproxy-w3 --selftest
for s in apps edit-paused filter-bar overview; do for m in light dark; do
  cmp /tmp/Aitmproxy-shots-dev-w3base/$s-$m.png /tmp/Aitmproxy-shots-dev-w3/$s-$m.png && echo "same $s-$m"; done; done
```

(`tools/snap-dev.sh` builds a debug bundle at `/tmp/Aitmproxy-dev-w3.app` whose executable is
`Aitmproxy-w3`; the self-test runs against that binary with an `APP_STORE` in `/tmp`.)

## Tasks

### Task 1: Kit `VerbTable` and its tests

- **Satisfies:** AC1, AC2, AC3, AC4, AC5
- **Depends on:** none
- **Files:** `Sources/AitmproxyKit/VerbTable.swift` (create),
  `Tests/AitmproxyKitTests/VerbTableTests.swift` (create)
- **Change:** `public enum FlowVerb`, `public enum VerbGroup: Int, CaseIterable`, `public struct
  VerbContext` (memberwise init with defaults), `public struct VerbItem: Hashable`, `public enum
  VerbTable { static func items(for: VerbContext?) -> [VerbItem]; static func verb(forKey:
  String, in: [VerbItem]) -> FlowVerb?; static func titles(_: FlowVerb) -> [String]; static var
  allTitles: [FlowVerb: [String]]; static let order: [FlowVerb]; static func
  outOfScopeReason(_: String) -> String }` exactly as the spec's section 1 table (titles,
  keys, shortcuts via `Shortcut(display:)`, enabled rules, disabled reasons).
- **Test:** `VerbTableTests` (Swift Testing), with hand-built rows (`FlowRow(id:seq:method:
  scheme:authority:path:state:)`): paused + `pendingEdits: 1` → `.resume` title "Apply &
  Resume", enabled, `shortcut == Shortcut("\r", command: true)`; paused + 0 → "Resume";
  `.complete` → `.resume` disabled with reason "Only a paused flow can be resumed", `.delete`
  titled "Delete" enabled with `key == "d"` and `shortcut == Shortcut("d")`; `.pending` →
  `.delete` titled "Kill"; `inScope: false` on authority `telemetry.vendor.test` → every item
  disabled and every `disabledReason` contains "telemetry.vendor.test"; `selectedCount: 3,
  selectedPausedCount: 1` → "Resume 3 Selected" enabled, `selectedCount: 1` → disabled;
  `pinned: true` → "Unpin Host"; `verb(forKey: "e", in: items) == .edit`, `verb(forKey: "x",
  in: items) == nil`; `allTitles[.resume] == ["Resume", "Apply & Resume"]`; `items(for: nil)`
  → `allSatisfy { !$0.enabled }`; `.mark(nil)` and `.quickLook` have `shortcut == nil`,
  `.comment` has `Shortcut("l", command: true)`.
- **Done when:** `swift test` green with the new suite (ten tests). **Landed as `96b3da0`
  (`feat(mac): one verb table for row actions in Kit (VerbTable + tests)`, +256 lines).**

### Task 2: the app reads the table

- **Satisfies:** AC6, AC7 (S-069 part), AC8 (`apps`, `edit-paused`, `filter-bar`)
- **Depends on:** Task 1
- **Files:** `Sources/Aitmproxy/Session+Verbs.swift` (modify),
  `Sources/Aitmproxy/FlowTable/FlowRowActions.swift` (modify: delete `FlowRowAction`, rewrite
  `FlowKeyTable.keyDown`), `Sources/Aitmproxy/FlowTable/FlowTableView.swift` (modify: menus
  out, `onAction: (FlowVerb, FlowID) -> Void`, `Coordinator.verbContext(for: FlowRow) ->
  VerbContext`), `Sources/Aitmproxy/FlowTable/FlowTableView+Menus.swift` (create: row menu,
  mark submenu, comment popover, columns menu as a `Coordinator` extension),
  `Sources/Aitmproxy/App.swift` (modify: Flow menu row items via a private `VerbButton` view
  and a `KeyboardShortcut.init(_ shortcut: Shortcut)` helper), `Sources/Aitmproxy/Shell/
  InterceptBar.swift` (modify), `Sources/AitmproxyKit/CommandMap.swift` (modify: Flow row
  entries from `VerbTable.titles`/`items(for: nil)`), `docs/ARCHITECTURE.md` (modify: Kit
  list + "Checks that hold the shape"). NOT `Shell/ShellView.swift`.
- **Change:** on `Session`: `func verbContext(for id: FlowID, pane: Int = 0) -> VerbContext?`,
  `func verbItems(for id: FlowID?, pane: Int = 0) -> [VerbItem]`, `func verbItem(_ verb:
  FlowVerb, for id: FlowID?, pane: Int = 0) -> VerbItem`, `func perform(_ verb: FlowVerb, on id:
  FlowID)` gating on `item.enabled` and reporting `disabledReason` as `lastError`.
  `FlowKeyTable.onVerb: ((FlowVerb) -> Void)?`; `keyDown` keeps `i`/`n`/Return and routes the
  rest through `VerbTable.verb(forKey:in: VerbTable.items(for: nil))`. `buildRowMenu` iterates
  the items per spec section 2 (skip `.kill`; `.selection` only when `selectedCount > 1`;
  separator per group change; Mark submenu; trailing out-of-scope note from
  `VerbTable.outOfScopeReason`). Flow menu: each row item is `VerbButton(session:verb:target:)`
  with `.resume`/`.kill` targeting `session.interceptTarget?.id`, the rest `session.focused`;
  non-row items untouched. InterceptBar: Resume title and Edit visibility from
  `session.verbItem`. CommandMap: `verb(_:)`/`listKey(_:)` helpers.
- **Test:** build green; `swift test` green (`CommandMapTests.mapMatchesTheBrief` and
  `everyVerbWithABriefShortcutHasAMenuShortcut` still pass with items from the table); in the
  self-test every "Flow menu has …" check (S-069) is PASS, in particular "Flow menu has
  Resume / Apply & Resume", "Flow menu has Edit Paused Request", "Flow menu has Kill/Delete",
  "Flow menu has Comment…", "Flow menu has Pin Host"; `grep -rn '"Apply & Resume"\|"Edit
  Paused Request"\|"Build PoC from Flow…"\|"Unpin Host"\|"Edit Comment…"' Sources/Aitmproxy`
  prints nothing; `grep -rn FlowRowAction Sources` prints nothing; `git diff --name-only`
  does not list `Shell/ShellView.swift`; `cmp` of `apps`, `edit-paused`, `filter-bar`
  light + dark against `/tmp/Aitmproxy-shots-dev-w3base` reports no difference.
- **Done when:** the above and the self-test is 121 of 121.

### Task 3: Clear with Undo

- **Satisfies:** AC7 (`ClearedFlowsTests`, 126 of 126), AC9, AC10, AC11
- **Depends on:** Task 2 (shares `Session+Verbs.swift`)
- **Files:** `Sources/AitmproxyKit/ClearedFlows.swift` (create),
  `Tests/AitmproxyKitTests/ClearedFlowsTests.swift` (create), `Sources/Aitmproxy/Session.swift`
  (modify: `var clearNotice: ClearNotice?`, `var restoredFlows: [FlowRow] = []`,
  `@ObservationIgnored var clearedFlows: ClearedFlows?`, `@ObservationIgnored var
  clearNoticeTask: Task<Void, Never>?`, `let flowUndoManager: UndoManager`), `Sources/Aitmproxy/Session+Verbs.swift` (modify:
  `clearSession(confirm:)`, new `func undoClear()`, `deleteOrKill` also prunes
  `restoredFlows`), `Sources/Aitmproxy/Bus/BusService.swift` (modify: one assignment in
  `pollLoop`), `Sources/Aitmproxy/Shell/StatusBar.swift` (modify: centre slot),
  `Sources/Aitmproxy/SelfTest.swift` (modify: three checks after "clearing empties the
  session").
- **Change:** Kit `public struct ClearedFlows: Sendable { rows, details, selection, focused;
  var count: Int; static func merge(restored: [FlowRow], newer: [FlowRow]) -> [FlowRow] }`
  and `public struct ClearNotice: Equatable, Sendable { count: Int; text: String }`.
  `clearSession` snapshots before `actions.clear()`, and after success registers
  `undoManager.registerUndo(withTarget: self) { $0.undoClear() }` + `setActionName("Clear")` on
  `Session.flowUndoManager` (the flow list's own manager, no event grouping; `FlowKeyTable`
  returns it as its `undoManager`, so Edit ▸ Undo Clear / ⌘Z reach it while the list has focus
  and a text field keeps its typing undo) via `registerClearUndo()`, sets `clearNotice`, starts an 8 s
  `Task.sleep` that nils it. `undoClear()` as spec section 3. `pollLoop`: `let merged =
  ClearedFlows.merge(restored: session.restoredFlows, newer: rows); if merged != session.rows {
  session.rows = merged }`. StatusBar: when `session.clearNotice != nil`, the centre HStack
  shows `Text("\(notice.text) —")` + `SmallButton("Undo") { session.undoClear() }` with
  `.help("Put the cleared flows back (⌘Z)")` ahead of the row count.
- **Test:** `ClearedFlowsTests`: `merge(restored: [], newer: N) == N`; with R = fixture rows
  seq 41, 42 (max 42) and N = one row seq 1 → result count 3, `result[2].seq == 43`, result
  prefix `== R`; `ClearedFlows(rows: R, …).count == 2`. Self-test (fixtures, 17 rows, the
  seq-41 row focused at that point): "clear shows the notice with the count" →
  `session.clearNotice?.count == 17`; "undo restores the rows, selection and focused flow" →
  after `session.flowUndoManager.undo()` (the Edit ▸ Undo path), `session.rows ==
  before.rows && session.selection == before.selection && session.focused == before.focused`;
  "undo dismisses the notice and the step" → `session.clearNotice == nil && canUndo == false`. Live (AC11): on the dev bundle against a running `aitm`
  (`AITM_CONFIG=… ./target/release/aitm`, `curl -x 127.0.0.1:8080 http://127.0.0.1:8099/`
  a few times), press Clear → status bar reads "Cleared n flows — Undo" → click Undo → the n
  rows are back and still present after 2 s; Edit ▸ Undo reads "Undo Clear" after a Clear.
- **Done when:** `swift test` green, the self-test is 126 of 126, the live check passes, and
  the `apps` snapshot is still byte-identical (no notice in a snapshot).

### Task 4: `HoverRowStyle`

- **Satisfies:** AC12, AC8 (`overview`)
- **Depends on:** none (disjoint files; ordered after 3 only because one session implements)
- **Files:** `Sources/Aitmproxy/UI/HoverRowStyle.swift` (create),
  `Sources/Aitmproxy/Panels/OverviewPanel.swift` (modify `BarRow`, `HostRow`),
  `Sources/Aitmproxy/Panels/OverviewBreakdowns.swift` (modify `FlowListRow`)
- **Change:** `struct HoverRowStyle: ButtonStyle { var height: CGFloat = Tok.Size.Row.dense;
  @State private var hovered = false; func makeBody(configuration:) -> some View }` applying
  `.padding(.horizontal, Space.xs)`, `.frame(height:)`, hover background in
  `RoundedRectangle(cornerRadius: Tok.Radius.badge)`, `.contentShape(Rectangle())`,
  `.onHover`, `.environment(\.rowHovered, hovered)`; `extension EnvironmentValues { @Entry var
  rowHovered: Bool = false }`. The three rows drop `@State hovered`, `.onHover` and the four
  modifiers, use `.buttonStyle(HoverRowStyle())`; `FlowListRow` reads
  `@Environment(\.rowHovered)` for the chevron's opacity.
- **Test:** `grep -n 'onHover\|hovered\|Ground.hover' Sources/Aitmproxy/Panels/OverviewPanel.swift
  Sources/Aitmproxy/Panels/OverviewBreakdowns.swift` prints only the `rowHovered` environment
  read in `FlowListRow` (no `onHover`, no `Tok.Ground.hover`); `grep -rln 'Ground.hover'
  Sources/Aitmproxy/UI Sources/Aitmproxy/Panels` lists `UI/HoverRowStyle.swift` and
  `Panels/OverviewPanel.swift` only if the chart-tile hover at line ~231 (not a row) remains —
  acceptable, it is a tile; `cmp` of `overview-light.png` and `overview-dark.png` against the
  baseline reports no difference.
- **Done when:** build green, the two `cmp`s silent, `grid-lint` PASS.

### Task 5: Kit `ColumnFit.autoHidden`

- **Satisfies:** AC13, AC7 (`ColumnLayoutTests`)
- **Depends on:** none (disjoint files)
- **Files:** `Sources/AitmproxyKit/ColumnLayout.swift` (modify: add `ColumnFit`),
  `Tests/AitmproxyKitTests/ColumnLayoutTests.swift` (create; move the existing
  `@Suite struct ColumnLayoutTests` out of `Tests/AitmproxyKitTests/ListTests.swift` into it),
  `Tests/AitmproxyKitTests/ListTests.swift` (modify: remove the moved suite)
- **Change:** `public enum ColumnFit { public static func autoHidden(available: Double,
  columns: [(id: String, width: Double, userHidden: Bool)], flexibleMin: Double, priority:
  [String]) -> Set<String> }` per spec section 5: skip `userHidden`, hide in `priority` order
  until `Σ visible + flexibleMin ≤ available`, never an id outside `priority`, all visible
  priority ids when nothing fits.
- **Test:** a `defaults` fixture `[("dot",24,false),("seq",52,false),("client",96,false),
  ("method",72,false),("status",84,false),("time",124,false),("duration",88,false),
  ("request",80,false),("response",80,false),("ssl",40,false),("edited",64,false),
  ("origin",72,false),("comment",160,true),("mark",20,false)]`, `flexibleMin: 200`,
  `priority: ["edited","origin","ssl","response","request","duration","client"]`:
  `available: 1096` → `[]`; `1000` → `["edited","origin"]`; `800` →
  `["edited","origin","ssl","response","request"]`; `500` → all seven; `1000` with
  `edited` marked `userHidden: true` → `["origin"]`; `priority: []` and `available: 100` →
  `[]`.
- **Done when:** `swift test` green including the moved `ColumnLayoutTests`.

### Task 6: responsive flow columns

- **Satisfies:** AC14
- **Depends on:** Task 5, Task 2 (the Coordinator's menus live in `FlowTableView+Menus.swift`)
- **Files:** `Sources/Aitmproxy/FlowTable/FlowTableView.swift` (modify),
  `Sources/Aitmproxy/FlowTable/FlowTableView+Menus.swift` (modify: columns menu `.mixed`
  state), `Sources/Aitmproxy/FlowTable/FlowColumns.swift` (modify: `static let
  autoHidePriority: [FlowColumn]`)
- **Change:** `FlowColumn.autoHidePriority = [.edited, .origin, .ssl, .response, .request,
  .duration, .client]`. `Coordinator`: `var userHidden: Set<FlowColumn>` (seeded from the
  loaded layout / `defaultHidden`), `var autoHidden: Set<FlowColumn> = []`, `func
  applyAutoHide()` (clip width → `ColumnFit.autoHidden(available: clip.bounds.width, columns:
  non-URL columns as `(id, column.width, userHidden.contains)`, flexibleMin:
  FlowColumn.url.minWidth, priority: autoHidePriority.map(\.rawValue))`; sets each
  `NSTableColumn.isHidden = userHidden || autoHidden`; returns early when unchanged), called
  from `clipResized`, `toggleColumn`, `resetColumns` before `fitURLColumn()`. `toggleColumn`
  flips `userHidden`, not `isHidden` directly. `currentLayout()` writes `userHidden` only.
  Columns menu: `state = userHidden ? .off : (autoHidden ? .mixed : .on)`; `.mixed` items get
  `toolTip = "Hidden to fit the pane"`.
- **Test:** `DEV_TAG=w3 tools/snap-dev.sh apps,split,activity-log`: in `split-light.png` and
  `activity-log-light.png` the flow list shows no horizontal scroll bar and no "EDITED",
  "ORIGIN" or "SSL" header (look at the PNGs); `apps-light.png`/`apps-dark.png` `cmp`
  silent; after the dev run, `python3 -c 'import json;print(json.load(open("/tmp/Aitmproxy-dev-state-w3/columns.json"))["hidden"])'`
  prints only `comment` (or the user's set), never an auto-hidden id; `check-layout.swift`
  PASS on `split-*-layout.json` and `activity-log-*-layout.json`.
- **Done when:** the above, and widening the pane in the dev app (close the Activity panel)
  brings the hidden columns back without touching the header menu.

### Task 7: docs, full gate, snapshot comparison

- **Satisfies:** AC7, AC8, AC15 (whole-branch verification)
- **Depends on:** Tasks 1–6
- **Files:** `docs/ARCHITECTURE.md` (modify: self-test count "105" → the real count; name the
  next refactor card, e.g. bus poll when hidden / `Session` split), `apps/mac/docs/review-2026-10-31.md`
  (modify: a "Wave 3 status" paragraph, as waves 1 and 2 have), the plan's Review log (this file)
- **Change:** docs only; no source changes except fixes the gate demands.
- **Test:** the whole gate block in the Overview: `swift test` green (349 + new suites:
  `VerbTableTests` 10, `ClearedFlowsTests` ≥ 3, `ColumnLayoutTests` moved + 6);
  `grid-lint.sh` PASS; `check-layout.swift` PASS on every `*-layout.json` in
  `/tmp/Aitmproxy-shots-dev-w3`; self-test 126 of 126; the four `cmp` pairs silent; the
  `split` and `activity-log` PNGs looked at in light and dark.
- **Done when:** every command's output is quoted in the task's report and the branch is
  ready for the stage-6 panel.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 3 | security, quality, spec | Critical/Important | A failed `flow.clear` still registered Undo Clear and showed the notice (`perform` is fire-and-forget) | fixed: `clearSession` awaits `actions.clear()` in its own task and offers Undo only on success; a failure leaves `lastError` and nothing else |
| 3 | security | Important | The dropped flows and the undo step lived until the next Clear, not the 8 s the notice promised | fixed: the notice timer now releases the copy and withdraws the step (`forgetClearedFlows`); self-test check "letting the notice lapse releases the copy and the step" |
| 3 | spec | Critical | AC11 (live-bus Clear → Undo survives four polls) had no evidence | fixed: `SelfTest+Live.runLive` gains "flow.clear empties the list and offers Undo Clear" and "Undo Clear puts the flows back and they survive four polls"; run against a private `aitm` (see Shipped) |
| 2 | security, quality | Minor/Important | `perform(.mark(color))` missed the table row (only `.mark(nil)` exists) and so bypassed the scope gate; `m` popped the mark menu without a gate | fixed: `FlowVerb.tableKey`, `VerbTable.item(_:for:)` used by every lookup; the Coordinator checks the row before popping; self-test check "a mark colour on an out-of-scope row is refused with the reason" |
| 3 | security | Minor | Restored rows kept a frozen `inScope` | fixed: the poll re-scopes `restoredFlows` like polled rows |
| 3 | security, quality | Minor | Stale "Undo Clear" steps stacked on the undo manager; key-window manager could be a secondary window's | fixed: `removeAllActions(withTarget:)` before each registration; the main window's manager first |
| 1 | quality | Minor | `VerbContext.isInterceptTarget` read by no rule | fixed: removed from Kit and the spec |
| 1 | quality | Minor | `VerbTable.order` hand-duplicated the items order, test compared sets | fixed: `order` derived from `items(for: nil)`; test asserts equality |
| 1, 2 | quality | Minor | Force-unwrapped lookups in `CommandMap.verb` and `Session.verbItem` | fixed: `VerbTable.item(_:for:)`, non-optional by construction (`preconditionFailure` names the verb) |
| 2 | quality | Minor | `pane:` plumbed but never passed; bulk verbs in the split's second pane gated against pane 0 | fixed: `verbContext` and `bulk` read `focusedSelectedRows` (the focused pane's selection); `pane` parameter gone |
| 4 | quality, spec | Minor | `HoverRowStyle` added a `0.7` press-opacity literal (not a token, not in the spec) | fixed: removed; the hover fill is the feedback, as the spec lists |
| 2 | quality | Minor | Intercept bar still typed Kill's title and the three printed hints | fixed: `VerbItem.hint` (bare key as letter, chord as glyphs); the bar reads title and hint from the table |
| 6 | quality | Minor | Auto-hide threshold ignored the intercell spacing the URL fit subtracts | fixed: spacing folded into `flexibleMin`; Kit test `theFlexibleMinimumIsPartOfTheSum` |
| 2 | quality | Minor | Flow menu rebuilt the table per item; `FlowKeyTable` rebuilt it per keypress | fixed: items computed once per menu body; `VerbTable.verb(forKey:)` static map |
| 2 | quality | Minor | `KeyboardShortcut(Shortcut)` trapped on a multi-character key | fixed: failable initialiser |
| 7 | quality, spec | Important/Minor | `ARCHITECTURE.md` said 105 checks and named no next card | fixed: 126 checks; next cards named (bus poll when hidden, `Session` split) |
| 7 | spec | Important | `apps/mac/docs/review-2026-10-31.md` changed without being declared | accepted (orchestrator, 2026-10-31): the review doc is where every wave's status lives; added to Task 7's files |
| 5 | spec | Minor | `ColumnLayoutTests` suite not moved from `ListTests.swift`; AC13's own values and `priority: []` untested | fixed: suite moved; `theSpecsOwnBoundaries` tests 1000/800/500, a user-hidden comment column and an empty priority |
| 3 | spec | Minor | `ClearedFlows.merge` renumbers gap-free from the newer minimum and drops newer rows with a restored id; AC10 said "add max(R.seq)" | accepted (orchestrator): AC10 amended to the implemented rule; it is what the self-test and the live check exercise |
| 3 | spec | Minor | AC9 compared the restored selection to `[focused]` | fixed: compared to the captured pre-clear selection |
| 4 | spec | Minor | AC12's "only file that applies `Tok.Ground.hover` to a row" was false via `ScopePanel`/`ConnectionLogPanel` (pre-existing rows) | accepted (orchestrator): AC12 amended to the three rows; moving the two panels onto `HoverRowStyle` is a follow-up card |
| 5, 6 | spec | Minor | Tasks 5 and 6 share one commit; `ColumnFit.Column` struct instead of a tuple; `applyAutoHide` folded into `fitColumns` | accepted (orchestrator): the struct names its fields, one fit pass is simpler; recorded here |
| 3, 4 | spec | Minor | Unrequested additions: `wsDetails`/`l4Details` on `ClearedFlows`, `HoverChevron`, `accessibilityIdentifier("clear-notice")` | accepted (orchestrator): WebSocket and L4 details are part of what Clear drops; the chevron type is how a label reads the environment; the id is for computer-use |
| 7 | spec | Minor | `check-layout` output not kept | fixed: `/tmp/w3-check-layout.log` |
| 2, 4 | spec | Important | AC8 byte identity: the harness moves the inspector dividers between runs of one binary, and `overview` showed a hover fill on a `HostRow` in one run | accepted (orchestrator, 2026-10-31) with evidence: the same bundle launched twice is byte-identical (AE 0); baseline vs new bundle launched the same way differs by 2.5 px on `apps-light` (sub-pixel AA) and only in window-activation chrome elsewhere; the `HostRow` fill was the pointer resting on that row — a capture with the pointer parked on the menu bar shows no fill. Whole-window `cmp` across `snap-dev` runs is a harness fix (the wave-3 harness item), not this wave's |
| 3 | spec | Critical | AC11 live-bus Clear → Undo not run | fixed: `SelfTest+Live` check run against a private `aitm` (`listen 127.0.0.1:28080`, bus 29090): "flow.clear empties the list and offers Undo Clear (4 flows)" PASS, "Undo Clear puts the 4 flows back and they survive four polls (4 present)" PASS, LIVE SELFTEST PASS 22 checks |

## Shipped

Branch `claude/cool-engelbart-633d63` (on PR #180's head `0d0ef3f`), eight commits, one per plan
step plus the stage-6 fix round (`80f06d6`). Everything in the spec landed; nothing was cut.

Gate on the final head (2026-10-31): `swift test --scratch-path ~/Library/Developer/Aitmproxy/test-build`
exit 0 (new suites `VerbTableTests` 12, `ClearedFlowsTests` 5, `ColumnFitTests` 7, `ColumnLayoutTests`
moved); self-test `SELFTEST PASS 126 checks` (121 + 5: the three Clear/Undo checks, the mark-colour
scope check, the notice-lapse check); `check-layout.swift` 12 PASS / 0 other on
`/tmp/Aitmproxy-shots-dev-w3/*-layout.json` (`/tmp/w3-check-layout.log`); `grid-lint` PASS; live
self-test against a private `aitm` `LIVE SELFTEST PASS 22 checks` including the two Undo Clear
checks (`/tmp/claude-501/w3/live/live-selftest.log`). Snapshots `apps`, `overview`, `edit-paused`,
`filter-bar`, `activity-log`, `split` captured light + dark and looked at: no horizontal scroll bar
on the flow list with the Activity panel open or in split view, low-priority columns gone and back
with room, Overview rows unchanged at rest.

Follow-ups (not this wave): the bus poll still runs at 500 ms when no window is visible (review
card); `ScopePanel` and `ConnectionLogPanel` hover rows onto `HoverRowStyle`; the snapshot harness
moves the inspector dividers between runs of one binary, so whole-window `cmp` cannot gate a wave
until that drift is fixed (the wave-3 harness item); the self-test harness should park the pointer
before capturing.
