# Architecture

Three targets, one direction of dependency, and one seam per thing that can be faked.

```text
AitmBusClient  ──▶  AitmproxyKit  ──▶  Aitmproxy (the app)
actor, JSON-RPC       values only          SwiftUI + AppKit, main actor by default
```

## Targets

- **AitmBusClient** — the wire: `JSONValue`, `JSONRPC`/`LineFramer`, `BusEndpoint`
  (config.yaml or arguments), `BusClient` actor (connect, `tools/list`, `tools/call`,
  notifications), `ToolDescriptor`. No UI, no Kit. Tested against `FakeBusServer`.
- **AitmproxyKit** — everything that can be true without a window: flow models (`FlowRow`,
  `FlowDetail`, `HTTPMessage`), the list query (`FlowQuery`, `FlowSort`, `ContentCategory`,
  filters), viewers as values (`JSONTree`, `HexDump`, `TextDiff`, `CodeExport`, `BodyKind`…),
  panel models (`Panels/`), `VerbTable`
  (every row verb's title, key, shortcut and enabled rule as data), `CommandMap` (the brief's
  command map as data, its Flow rows read from `VerbTable`). No SwiftUI, no `Tok`, no main actor.
- **Aitmproxy** — the app. `Session` holds the state; its actions live in one extension file per
  concern (`Session+Verbs`, `Session+Editing`, `Session+Filters`, `Session+Palette`). The
  navigation enums (`SidebarPage`,
  `InspectorLayout`, `AgentPolicy`) are in `Shell/SidebarPage.swift`. Views are
  grouped by surface: `Shell/` (window, sidebar, toolbar, bars, sheets, palette), `FlowTable/`
  (the `NSTableView` list), `Inspector/` (panes, viewers, editor, Quick Look), `Panels/`
  (aitmproxy's own pages and their state objects), `DesignKit/` (parts), `UI/`
  (generated `Tokens.swift`, `TokenMapping`, `Grid`, `Theme`, window behaviour).

## Seams

| Seam | Production adapter | Test adapter |
| --- | --- | --- |
| `FlowActions` (every proxy action) | `BusService` (polls `flow.list`/`flow.get`, records to the activity log) | none: live only (`OfflineActions` throws `disconnected` until `BusService` is installed) |
| `Session.commandRunner` (every palette and panel command) | `BusService.call` | none: live only |
| `Session.notificationSink` (server push into the activity log) | `BusService` | none: live only |
| `BusClient` transport | loopback TCP | `FakeBusServer` |
| Panel state (`PocPanelState`, `BrowserState`, `ActivityState`) | bus commands through `Session.runCommand` | none: Kit unit tests cover the models |

## Checks that hold the shape

- Evidence of behaviour (Matt, 2026-10-31): the real app — a dev bundle with the bundled core,
  or the installed app — with real traffic and before/after window shots, plus Kit unit tests of
  pure logic and the `tools/check-*.sh` source tripwires. The fixture snapshots and the fixture
  self-test were removed on 2026-10-31: they showed fixture data working while the real app
  might not.
- The gate (`apps/mac/CLAUDE.md`): `swift test`, `grid-lint.sh` and the three `check-*.sh` tripwires,
  the dev bundle with a real core and real traffic, the live self-tests.
- Kit tests parse `docs/BRIEF.md` (`CommandMapTests`): the brief, the map and the menus stay one
  list.
- Row verbs have one entry, `Session.perform(_:on:)`, and one source, `VerbTable`: the row
  menu (`FlowTableView+Menus`), the Flow menu (`App.swift`), the intercept bar, the list's key
  handler (`FlowKeyTable`) and `CommandMap` all read it, so a title, key or enabled rule exists
  once. `VerbTableTests` hold the rules; the self-test's menu audit holds the menu bar to them.
- `docs/architecture-review-<date>.md` and `docs/review-<date>.md`: one check-in per milestone.
  The 2026-10-31 check-in named the fixture bus and put the fixture session in one file (both
  removed 2026-10-31 with the fixture modes), moved the navigation enums out of `Session.swift`,
  and made the poll's in-scope rule the Kit `Scope.matches` (its only copy); its next cards are
  the `ShellView` split and the bus poll slowing when no window is visible.
