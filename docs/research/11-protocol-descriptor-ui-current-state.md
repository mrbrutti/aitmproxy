# Protocol-descriptor UI: current state of per-protocol presentation

**Date:** 2026-10-30. **Method:** four read-only code surveys (TUI, web, macOS, core/seam/bus)
against `main` at `78b1678`, spot-checked by hand (see "Verified by hand"). Input to
`docs/superpowers/specs/2026-10-30-aitmproxy-protocol-descriptor-ui-design.md`. No code
was changed. Line numbers drift; treat them as pointers, not contracts.

## Headline

**No surface consumes `docs/design/languages/flow-kinds.json` for rendering.** It is
prose, not a machine contract, and `docs/design/languages/README.md:52-58` is wrong
when it says the TUI (`flow_kinds.rs`), web (`flow-kinds.ts`) and macOS (`FlowKind.swift`)
"build their per-kind renderers from it": none of those three files exists. Each UI
hand-writes its own closed `FlowKind` enum and branches on it. The only consumer is a
sliver of the web (`apps/web/src/panels/l4/model.ts:74-88`: `KNOWN_KINDS`,
`kindDescriptor`, `listCmd`, and only the L4 model calls them). So the milestone
**reuses the file's field vocabulary as a seed, not its consumers.**

## Verified by hand

- `find` for `flow_kinds.rs`, `FlowKind.swift`, `flow-kinds.ts` returns nothing.
- Files that mention `flow-kinds`: `apps/web/scripts/gen-langs.mjs`,
  `docs/design/languages/validate.test.mjs`, `apps/web/src/panels/l4/model.ts`,
  `apps/web/src/flows/L4FlowRow.tsx`. Nothing in `crates/` or `apps/mac/`.
- `flow.detail.messages` (named in `flow-kinds.json` for WebSocket) is referenced by no
  command, UI or test. WebSocket frames come back inside `flow.detail`.
- The TUI depends only on `aitm-bus-client` (not `aitm-core`): the UI-as-bus-client
  boundary is deliberate and any shared Rust type must live in a leaf crate.

## The three UIs, side by side

| | TUI (`crates/aitm-tui`, 19.5k LOC) | Web (`apps/web`, 18.5k LOC) | macOS (`apps/mac`, 27.4k LOC) |
|---|---|---|---|
| Kind model | closed `enum FlowKind {Http, WebSocket, L4}` (`model.rs:14`); unknown kind string maps to `Http` (`model.rs:118-120`) | two disagreeing `FlowKind` types (`model/flow.ts:7`, `panels/l4/model.ts:71`); `bus/normalize.ts:197` collapses any non-`websocket` to `http` | `enum FlowKind {http, websocket, l4}` (`Flow.swift:10`); unknown kind makes `FlowSummary.init?` return nil and the row silently vanishes (`FlowSummary.swift:43`, `BusService.swift:138`) |
| Kind branch census | ~32 sites in 7 files (`app.rs` 13, `model.rs` 6, `ui/inspector.rs` 6, `ui/flows.rs` 4) | ~25 `kind === 'websocket'` in 15 files + ~8 L4 routing sites | one exhaustive `switch` + ~15 `==` sites; a fourth case compiles silently |
| L4 code | ~1,400 LOC (`l4.rs`, `ui/l4.rs`, reducers in `app.rs`) | ~1,200 LOC (`panels/l4/*`) | ~1,100 LOC (`L4.swift`, `L4Inspector.swift`, `Session.swift` slices) |
| WebSocket code | ~70 scattered lines, reuses HTTP inspector with Body tab reinterpreted as frames | `WsFrames.tsx` + `isWs()` branches in `ResponsePane` | `WebSocketInspector.swift` (178), synthetic `HTTPMessage` to reuse body viewers |
| Scanner | `ui/scan.rs` + `ScanState` (~435 LOC), gated on `has_tool("scan.discover")` | `panels/scan/*` (~590 LOC); launch form is schema-driven, results are bespoke | `ScanPanel.swift` + `Panels/Scan.swift` (~810 LOC), same gate |
| List row model | HTTP-shaped `FlowRow`; WS and L4 as `Option` fields | `FlowSummary` is HTTP-shaped; L4 rows are a separate store appended as an unvirtualized block after the virtualized HTTP rows (`FlowList.tsx:306-312`) | fixed `FlowRow` struct (`wsFrames`, `l4: L4RowInfo?`); 15-column `FlowColumn` enum drives the persisted `columns.json` and sort keys; `NSTableView` |
| Inspector dispatch | `ui/inspector.rs` per-kind; own `ui/l4.rs` | `Shell.tsx:139` picks `L4InspectorPanel` or `Inspector` by `l4Ids` | `InspectorView.swift:17,22` root dispatch; `PaneTabs` already generic |
| Capability gates | 53 `has_tool(...)` calls; F-gates are prose toasts keyed on tool presence | ~20 ad-hoc `tools.some(name===…)` checks; stale "needs core F3/F9/M3" strings | tool-name feature detection in `Session.swift:149-153`, `BusService.swift:101` |
| Role use | displayed only | displayed only (`RoleBanner`) | displayed only (`StatusBar`) |
| Live data | polls `flow.list`+`flow.get` at 500 ms; `l4_poll` every pass; never calls `flow.subscribe` | polls (`app.ts:320-371`); L4 polled at 1.5 s; never calls `flow.subscribe` | polls at 500 ms; **L4 is not live over the bus** (`l4.flow.*` only in fixture runner, `Session.swift:299-302`); no `flow.subscribe` |
| Generic machinery already present | palette generic over `tools/list` + `ToolSchema` trait; viewers are pure `bytes → Lines` | `lib/schema-form` (JSON-Schema form), tools-driven palette, `Pane`/`Tabs` shells | `PaneTabs`, content-type-keyed body viewers, `FlowActions` protocol with bus and fixture impls |
| Tests | `snapshot.rs`, `fixture.rs`, unit tests; `cargo test` | vitest + jsdom, 41 files; `bus/mock.ts`, `bus/fixtures.ts`; CDP scripts, no Playwright | `swift test` ~318 tests; `FakeBusServer`; in-app `--selftest`; `SnapshotScenes`. Builds only in Terminal (bama) |

## Bugs and gaps the survey surfaced (not fixed here)

These matter to the milestone because a "before/after parity" claim needs a trustworthy
"before", and because a generic renderer inherits whatever the per-UI code gets wrong.

1. **macOS L4 is fixtures-only** over the live bus (`l4.flow.list/get` absent from the real
   path), so the "correct" macOS L4 presentation is not exercised live.
2. **macOS L4 rows get wrong verbs.** The Flow/row menus are kind-blind; an L4 intercept
   session maps to `.paused`, so Resume/Kill call `flow.resume`/`flow.kill` instead of
   `l4.intercept.*` (`L4.swift:195`). The TUI overloads `a`/`d`/`e` per kind by implicit
   dispatch (`selected_l4()`).
3. **Role never gates UI.** `tools/list` is not role-filtered (`server.rs:1257`); the UIs show
   `l4.agent.set` to an agent connection and the core refuses at call time
   (`is_operator_only`, `server.rs:1928`).
4. **Wire mismatches.** `tools/list` emits `confirmable: bool` (`aitm-mcp/src/schema.rs:49`);
   web `ToolDef` expects `confirm?: string`, so the palette confirm step probably never fires
   live. Push notifications say `kind:"ws"` (`server.rs:2042`) while `flow.get`/`flow.detail`
   say `"websocket"`.
5. **Web live mode.** `bootstrap` (`app.ts:497`) starts polling only when `flow.subscribe` is
   absent, but the web bridge advertises it and cannot serve it (`web/bridge.rs:207`), so a live
   list may stop updating after the first poll (unverified live).
6. **Stale gate text.** `ws.send/frame/intercept` exist in core (`aitm-plugin-wsctl`) but no UI
   uses them; "needs F9" strings remain.
7. **Filter grammar drift.** `filter.grammar.json` lists `~l4 ~tcp ~udp ~icmp`; neither TUI nor
   macOS implements them, and the web does not read the file. README claims otherwise.
8. **Viewer drift.** `flow-kinds.json` names `protobuf`, `msgpack`, `sse`, `markdown` viewers
   that exist in no UI.

## Core, seam and bus

- **Flow model.** `enum Flow {Http, WebSocket}` (`aitm-core/src/flow.rs:54`), closed, matched
  at ~45 sites in ~17 files. **L4 is not a `Flow`**: `L4Module: Plugin`
  (`aitm-proto-l4/src/module.rs:312`) owns an `L4FlowStore` and `l4.*` commands (M5 decision
  OQ1). `flow.rs` in that crate calls a unified `Flow::L4` a "blessed later follow-up". Three
  unrelated Rust `FlowKind`s exist (`aitm-core/src/store.rs:80` query filter,
  `L4FlowKind`, the TUI's).
- **Three seam shapes, none descriptive.** `ProtocolModule {id, matches, spawn}`
  (`aitm-core/src/protocol.rs:29`, acceptor-driven: HTTP, WS, passthrough); command-driven
  `Plugin` (L4); `ProtocolLanguage` (`aitm-plugin/src/language.rs:54`: Rhai host fns, PoC
  steps, serde `NamespaceCatalog`). `aitm-proto-test` is a stub `ProtocolLanguage` with no
  flows or module.
- **Bus.** MCP JSON-RPC (`aitm-mcp`): `initialize`, `tools/list`, `tools/call`, `resources/*`
  (`server.rs:1195-1265`). `initialize` returns `role` plus standard `capabilities` and nothing
  protocol-specific. `tools/list` carries `inputSchema` (derived from `ParamSchema`/`TypeDesc`),
  `confirmable`, and an optional widget overlay keyed by hard-coded tool name
  (`widgets.rs:145`), a precedent for additive per-tool UI metadata. `aitm/tests/frontends.rs`
  pins an exact 56-tool list.
- **Events.** Core `Event` is `#[non_exhaustive]`; push is `notifications/aitm/{flow,state,agent}`
  built from `flow_summary(&Flow)` (`server.rs:2030`), so push is HTTP/WS only. L4 has no events.
- **De-facto capability model.** Tool presence plus `inputSchema` property sniffing plus
  status commands (`agent.status`, `l4.agent.status`). There is no `describe`, manifest or
  capabilities message. F4/F5/F9 are exactly this.
- **Privilege and gates.** `Frontend {Cli, Mcp, Operator}`, `CallerTrust {Operator, Agent}`
  (`aitm-core/src/ctx.rs`); `McpServer::policy_decision` (`server.rs:1549`) gates only
  `Frontend::Mcp` on `AgentPolicy` × `Command::sensitivity()` (default fail-closed
  `Sensitive`); `defers_to_command_gate` (`:1900`) and `is_operator_only` (`:1928`) are
  hard-coded name lists; L4 adds `L4Guard`, `L4AgentGates` and a startup `L4Privilege` probe
  surfaced only as call-time `L4Unavailable`. `HostCallCtx` feeds `GuardHandle::permit`
  (`language.rs:124,197`). Nothing tells an operator UI that a verb will be refused for it.
- **Plugins.** No manifest. `Plugin` is `load(&mut Registry)` + `on_event`. "ui-ext" is spec
  naming only. The scanner registers only `scan.discover` (Write tier, untyped
  `Object(vec![])` result); every UI has a bespoke Scan panel gated on that tool name.
- **Existing seams worth copying.** `ProtocolLanguage`/`NamespaceCatalog` +
  `tests/api_catalog.rs` (data contributed from the protocol crate, drift guard fails when the
  catalog lags the engine); `filter.conformance.json` + `validate.test.mjs` (one fixture proves
  three surfaces identical); `lib/schema-form` (web) and the TUI palette's `ToolSchema` (forms
  from `inputSchema`).

## Sizing signal

Per-protocol presentation code today, production only: TUI ~2,000 LOC across L4/WS/Scan
plus ~32 branch sites; web ~1,900 LOC plus ~35 branch sites; macOS ~2,300 LOC plus ~15
branch sites. A descriptor-driven renderer replaces the dispatch and the L4/WS list and
inspector code; it does not replace the HTTP exchange viewer, the body viewers, the craft
editor internals or the virtualized list engines.
