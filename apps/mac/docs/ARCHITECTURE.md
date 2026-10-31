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
  panel models (`Panels/`), `Fixtures` (the mockup's data, also the self-test's), `VerbTable`
  (every row verb's title, key, shortcut and enabled rule as data), `CommandMap` (the brief's
  command map as data, its Flow rows read from `VerbTable`). No SwiftUI, no `Tok`, no main actor.
- **Aitmproxy** — the app. `Session` holds the state; its actions live in one extension file per
  concern (`Session+Verbs`, `Session+Editing`, `Session+Filters`, `Session+Palette`,
  `Session+Fixtures` for the fixture session). The navigation enums (`SidebarPage`,
  `InspectorLayout`, `AgentPolicy`) are in `Shell/SidebarPage.swift`. Views are
  grouped by surface: `Shell/` (window, sidebar, toolbar, bars, sheets, palette), `FlowTable/`
  (the `NSTableView` list), `Inspector/` (panes, viewers, editor, Quick Look), `Panels/`
  (aitmproxy's own pages and their state objects), `DesignKit/` (parts and the gallery), `UI/`
  (generated `Tokens.swift`, `TokenMapping`, `Grid`, `Theme`, window behaviour).

## Seams

| Seam | Production adapter | Test adapter |
| --- | --- | --- |
| `FlowActions` (every proxy action) | `BusService` (polls `flow.list`/`flow.get`, records to the activity log) | `FixtureActions` (mutates the session in place) |
| `Session.commandRunner` (every palette and panel command) | `BusService.call` | `FixtureBus.call` (`Bus/FixtureBus.swift`), installed by `Session.init` |
| `Session.notificationSink` (server push into the activity log) | `BusService` | none: fixtures push nothing, `Fixtures+Agent` seeds the log |
| `BusClient` transport | loopback TCP | `FakeBusServer` |
| Panel state (`PocPanelState`, `BrowserState`, `ActivityState`) | bus commands through `Session.runCommand` | `Fixtures+Poc/Agent/Streams` |

`Store.usesFixtures` picks the adapter at launch (`APP_FIXTURES=1`, snapshot mode, `--selftest`).

## Checks that hold the shape

- Evidence of behaviour (Matt, 2026-10-31): the real app — a dev bundle with the bundled core,
  or the installed app — with real traffic and before/after window shots, plus Kit unit tests of
  pure logic and the `tools/check-*.sh` source tripwires. Fixture snapshots and the fixture
  self-test are development aids, not proof: they show fixture data working while the real app
  may not.
- `tools/verify.sh`: unit tests, self-test (145 checks, incl. menu-bar coverage from
  `CommandMap`), snapshots light + dark, parts gallery, grid-lint.
- Kit tests parse `docs/BRIEF.md` (`CommandMapTests`): the brief, the map and the menus stay one
  list.
- Row verbs have one entry, `Session.perform(_:on:)`, and one source, `VerbTable`: the row
  menu (`FlowTableView+Menus`), the Flow menu (`App.swift`), the intercept bar, the list's key
  handler (`FlowKeyTable`) and `CommandMap` all read it, so a title, key or enabled rule exists
  once. `VerbTableTests` hold the rules; the self-test's menu audit holds the menu bar to them.
- `docs/architecture-review-<date>.md` and `docs/review-<date>.md`: one check-in per milestone.
  The 2026-10-31 check-in named the fixture bus (`FixtureBus`), put the fixture session in one
  file and moved the navigation enums out of `Session.swift`; its next cards are
  `BusService.hostMatches` → `Scope.matches` and the `ShellView` split (both after the revision-2
  PR), the self-test as check groups, and the bus poll slowing when no window is visible.
