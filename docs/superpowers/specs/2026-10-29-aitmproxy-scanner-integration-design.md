# Scanner operator-surface integration (MCP + web + TUI + macOS) design

**Status:** Approved (Stage 1) — 2026-10-30
**Research inputs:** `docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md`
(the scanner plugin spec — command surface, tiers, staging), the scanner plugin
Stage-1 code on branch `claude/scanner-plugin-stage1-8a18a1` (PR #67:
`crates/aitm-plugin-scanner`, `scan.discover`), the MCP/command seam
(`crates/aitm-core/src/{command,registry,plugin}.rs`, `crates/aitm-mcp/src/schema.rs`),
and read-only surveys of the three UI crates (`apps/web`, `crates/aitm-tui`,
`apps/mac`) performed 2026-10-29.

## Intent

The deterministic scanner (`aitm-plugin-scanner`) ships its capabilities as
plugin-registered `scan.*` commands that auto-expose over MCP, CLI and every UI.
Stage 1 (`scan.discover`) is in final review as PR #67; later backend stages add
`scan.passive`, `scan.inject`, `scan.report`, `scan.run`, `scan.status`. Matt
wants the scanner *fully usable* from the MCP agent interface **and** from all
three operator UIs — launch a scope-bound scan, watch crawl/injection-point
discovery, and read the findings — not merely callable as a raw CLI/palette
command. This spec is the **integration layer only**: it does not build the
scanner engine (that is the scanner plugin plan's five backend stages), it
surfaces it. It reuses the existing flow-list, inspector, findings and scope
surfaces in each UI rather than bolting on new panels, and it pins the MCP/contract
housekeeping each new `scan.*` command requires.

## Goals

- **MCP parity, verified.** Every `scan.*` command an agent can list via
  `tools/list` and call via `tools/call` with a correct JSON Schema, under the
  same deny-by-default tier + scope gate as every other command — with the
  contract test and config plumbing that keep that true as later commands land.
- **A "Scan" operator surface in each of the three UIs**, at parity: a Scan
  sidebar section/view that (a) **launches a scope-bound scan** from a
  schema-driven form, (b) shows **discovered endpoints and injection points**,
  (c) surfaces **scanner findings** through the UI's existing Findings surface,
  and (d) shows **progress** for a running scan.
- **Maximal reuse.** Crawl endpoints resolve to existing flow rows / inspector;
  injection points render in a list that reuses each UI's list/table widgets;
  findings fold into the existing `Finding` model and Findings pane; the scan's
  authorized target is bound to the existing scope surface. No new findings
  model, no new scope model, no second tool-discovery path.
- **Gating visible and honoured in the UI.** Active-injection launches
  (`scan.inject`/`scan.run`, `Sensitivity::Sensitive`) show the operator the
  scope + confirmation they are authorizing, and the operator can enable/disable
  agent-run active injection (`scanner.allow_agent_active`) through config.
- **Staged so Matt can greenlight a first stage** that ships against the
  already-merged `scan.discover` and ends shippable, with later stages tracking
  each backend scanner stage as it lands.

## Non-goals

- **Not the scanner engine.** `scan.passive`/`inject`/`report`/`run`/`status`
  are built by the scanner plugin plan (backend Stages 2-5). This spec consumes
  them; it adds no scanning logic, no payloads, no crawl/correlate code.
- **No `aitm-core` edits**, no new command, no change to the MCP schema
  derivation. The MCP side is already generic (see Design); this spec only adds
  contract-test hygiene, a config field, and `confirm_prompt` on the engine's
  Sensitive commands (owned by the backend plan, called out here as a dependency).
- **No new Findings model or Findings panel.** Scanner findings reuse each UI's
  existing `Finding`/`Severity` model and Findings surface, widened at most where
  a field is missing.
- **No live-tool allow-list.** None of the three UIs gate which live tools they
  show; `scan.*` already appears in every command palette. This spec does not add
  gating; it adds a *dedicated* surface on top of the auto-exposed commands.
- **No redesign of the scope or agent-policy model.** Scope binding reuses
  `scope.list`/`scope.add`/`scope.remove`; agent gating reuses the existing
  `Sensitivity` tiers + `AgentPolicy`.

## Anti-goals

- A UI that can **launch a scan against a host outside the authorized scope**, or
  that hides the scope the operator is authorizing. The scope the scan targets
  must be explicit at launch in every UI.
- A UI that presents **active injection as freely runnable** when the backend
  command is absent, the policy forbids it, or `scanner.allow_agent_active` is
  off — the surface must degrade (disabled + reason) exactly as other
  tool-gated controls do.
- A scan result, injection point, or finding rendered in any UI that **leaks a
  secret** (auth header, cookie, token) that passed through a scanned request.
  Redaction is the engine's job; the UI must not re-introduce the raw value from
  any field it is handed.
- Four divergent scanner UIs. The three surfaces must be at **behavioural
  parity** (same launch inputs, same result shape, same findings home); only the
  presentation idiom differs per platform.

## Constraints

- **Rust gate** for `aitm-tui` and any `crates/aitm*` change:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  Web: `tsc --noEmit && vite build` plus the web self-test. macOS:
  `swift build -c release` + `swift test` via `apps/mac/build.sh` (build/run only
  in the Terminal panel; `open`/`osascript` are sandbox-blocked).
- **UI tests are fixture/snapshot-based.** The TUI renders from
  `fixtures/bus-fixture.json` filtered by `CORE_TOOLS`
  (`crates/aitm-tui/src/lib.rs:233`, `fixture_app_core`); the macOS app seeds a
  fixed tool list via `Fixtures.tools` (`apps/mac/Sources/.../Session.swift:221`,
  `Fixtures+Tools.swift`); the web self-test drives a live bus
  (`apps/web/scripts/selftest-live.mjs`). New scanner surfaces are proven against
  these harnesses, not a live obscura browser.
- **The tool-set contract test** `crates/aitm/tests/frontends.rs` pins the exact
  `tools/list` (`EXPECTED_TOOLS`, now `[&str; 54]` with `scan.discover`). Every
  new `scan.*` command must be added there (count + name); Stage-1 already did
  this for `scan.discover`.
- **Each new `scan.*` must also be added** to the TUI `CORE_TOOLS`
  (`crates/aitm-tui/src/lib.rs`) and the macOS fixture tool list
  (`apps/mac/Sources/AitmproxyKit/Fixtures+Tools.swift`) so fixture/snapshot
  tests exercise it. The web UI needs no list change (it reads `tools/list`
  live with no fixture allow-list).
- **Availability dependency.** Each integration stage depends on the matching
  backend scanner stage being merged. Stage 1 of *this* plan depends only on
  PR #67 (`scan.discover`). A UI control for a not-yet-shipped command must
  render degraded (tool-presence gated), never broken.
- **Design tokens.** macOS views use `Tok.*`/`Palette.*`/`Space`
  (`apps/mac/.../UI/Tokens.swift`, generated — do not edit); the TUI uses the
  generated `tokens.rs` theme; the web UI uses its existing component/Icon
  vocabulary. No hard-coded colours or spacing.

## Design

### The MCP side is already generic — integration is contract + config, not code

A command auto-exposes as an MCP tool: `aitm-mcp`'s `StdSchemaDerive::to_mcp_tool`
(`crates/aitm-mcp/src/schema.rs:43`) derives `inputSchema` from any command's
`ParamSchema`/`TypeDesc` (`crates/aitm-core/src/command.rs`), and the server lists
every command in the `Registry`. `ScannerPlugin` is registered in the one proxy
builder (`crates/aitm/src/wire.rs:205`, used by both the real binary and the
`build_proxy` test harness), so `scan.discover` already appears in `tools/list`
with a derived schema and is pinned in `EXPECTED_TOOLS` (`[&str; 54]`). **No
per-command MCP code is ever needed.** Verified read-only, 2026-10-29.

Three MCP-side items remain, and each is small:

- **D-MCP1 — contract hygiene (per command).** Each later `scan.*` command bumps
  `crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS` (count + name). Owned by the
  backend scanner tasks that add each command; this spec records it as the
  acceptance surface and the integration plan's Stage-1 task re-verifies the
  whole set end-to-end.
- **D-MCP2 — operator-configurable `allow_agent_active` (gap).** Today
  `ScannerConfig::default()` is constructed inline at `wire.rs:206`, so
  `allow_agent_active` is hard-wired **off** and an operator cannot turn agent-run
  active injection on. The per-command gate (`scan.inject`/`scan.run` refuse an
  MCP caller unless the flag is set — scanner spec §Command surface) is therefore
  unreachable-on. Fix: thread a `scanner` section (at least `allow_agent_active:
  bool`, default false) through `aitm_core::config::Config` and build
  `ScannerConfig` from it at `wire.rs`, mirroring `ScopePlugin::new(cfg.scope.allow_agent_widen)`
  (`wire.rs:219`) and the `scope_add_gate_is_wired_default_off` test
  (`frontends.rs:463`). **(Architect's call:** a config field, not a new core
  type — consistent with the scanner spec's "no new core type" and the
  `scope.allow_agent_widen` precedent.) This lands in the integration stage that
  surfaces active injection (Stage 3), together with its operator toggle, because
  it is only observable once `scan.inject` exists.
- **D-MCP3 — `confirm_prompt` on Sensitive scan commands (dependency).**
  `scan.inject`/`scan.run` should return a `confirm_prompt` so human surfaces get
  the operator confirm-over-the-wire handshake (platform D4) and
  `McpTool.confirmable` is true. This is a property of the *command* (owned by the
  backend scanner tasks that add it); this spec depends on it and the UI honours
  it (the web/macOS/TUI confirm paths already read `confirm`/`CONFIRM_TOOLS`).

### Shared UX model (parity across the three UIs)

Every UI gains one **Scan** section with the same four regions, differing only in
idiom:

1. **Launch header** — a schema-driven form over the chosen `scan.*` command's
   `inputSchema` (each UI already builds forms from a tool schema generically:
   web `lib/schema-form/`, macOS `ToolDescriptor`/`PocRunForm`, TUI
   `ToolSchema::params`). The **target is bound to the authorized scope**: the
   form presents the current in-scope hosts (from `scope.list`, already loaded as
   web `proxy.scope` / macOS `session.scopeHosts` / TUI `app.scope`) and will not
   offer a launch whose target is not in scope; an "add to scope" affordance
   reuses the existing scope add path. A `running`/busy flag disables re-launch
   while a scan is in flight (reusing the Browser view's `busy`/`inflight`
   precedent: macOS `PocPanelState.running`, TUI `BrowserState.busy`, web
   `guarded()` action wrapper).

2. **Discovered endpoints** — `scan.discover`'s `endpoints` resolve to flows that
   already exist in the store (the crawl routes through the proxy). The Scan view
   lists them and **links each to its flow** in the existing flow list / inspector
   (web `app.loadDetail`, macOS `focusedRow`, TUI `ensure_detail`), rather than
   duplicating request/response rendering.

3. **Discovered injection points** — a new, scanner-specific list (query / body /
   header / cookie / path-segment / redirect per `InjectionPoint`) rendered with
   each UI's existing list/table widget (web virtual list / TanStack, macOS
   `FlowTableView` or a master-detail, TUI a cursor list + `navigate` arm). Each
   row shows location + name + a redacted example and links back to its flow.

4. **Findings** — scanner findings (`scan.report`, and the per-finding output of
   `scan.inject`/`scan.run`) fold into the **existing Findings surface** via each
   UI's `Finding`/`Severity` model, not a new panel. The TUI already folds
   `findings.list` output into `app.findings` via `BusEvent::ScriptFindings`
   (`crates/aitm-tui/src/app.rs:3131`, `Finding::from_script_json`) — the scanner
   path copies that shape (`Finding::from_scan_json` + a `BusEvent::ScanFindings`
   or reuse of the script path). Web (`mergeFindings`, `panels/findings/`) and
   macOS (`PocPanelState`, `AitmproxyKit/Panels/Findings.swift`) today source
   findings only from `poc.*`; they widen their findings source to also read the
   scanner's report/index. **(Architect's call:** reuse the `Finding` model and
   Findings pane in all three; only the *source* list widens.)

5. **Progress** — the lowest common denominator is **polling `scan.status`**: the
   TUI slow-pass poller (`crates/aitm-tui/src/bus.rs:274`) and the macOS poll loop
   (`BusService.pollLoop`) read it like `findings.list`/`flow.list`; the web UI
   reads it on its existing cadence. A streamed path (notifications /
   `flow.subscribe`-style) is **(Architect's call)** deferred to the campaign
   stage and, if added, rides each UI's existing notification channel (web push,
   macOS `notifications` AsyncStream, TUI `BusEvent::Notification`).

### View registration (where "Scan" plugs in)

Each UI already has a uniform "add a section" pattern (modelled on
`findings`/`scope`/`browser`), surveyed to exact anchors:

- **Web** (SolidJS, no router — a sidebar source + a `panel` value): five edits —
  `SidebarItem` union (`state/app.ts:25`), `Panel` type (`state/app.ts:68`),
  `setSidebar` mapping (`state/app.ts:800`), sidebar nav item (`shell/Sidebar.tsx:163`,
  gating the count on `proxy.tools.some(t => t.name === 'scan.status')` like the
  L4 item), and a `Shell.tsx` panel `<Match>` (`shell/Shell.tsx:138`) — plus a
  new `panels/ScanPanel.tsx` (+ `panels/scan/`), thin-wrapper like
  `FindingsPanel.tsx`. Scan actions join the `guarded()` action wrappers
  (`state/app.ts:787`); launch/run go through `app.call(tool, args)`
  (`state/app.ts:1034`).

- **TUI** (single `Mode` enum): add `Mode::Scan` (`src/app.rs:55`),
  `SidebarItem::Scan` + `ALL`/`label` (`src/app.rs:298`, render in
  `src/ui/sidebar.rs:148`, gate on `has_tool("scan.status")`), `Action::OpenScan`
  (`src/action.rs`, handler `src/app.rs:1612`), a keybinding + per-mode key fn
  (`src/keys.rs`), a render arm (`src/ui/mod.rs:108` → new `src/ui/scan.rs`), a
  `:scan` builtin (`src/app.rs:3751`/`run_command`), and `ScanState` fields on
  `App` (`src/app.rs:779`, init `src/app.rs:873`) with a `navigate()` arm
  (`src/app.rs:2452`) for the injection-point list. `scan.*` is already launchable
  as `:scan.discover k=v` (generic fall-through `src/app.rs:3069`) and via the
  palette (`PaletteKind::Tool`); the net-new work is the scope-bound launch
  affordance + the Scan view + folding results out of the `CallOk` default arm
  (`src/app.rs:3539`). The `l4` surface (`src/l4.rs`, `src/ui/l4.rs`, `L4State`)
  is the full worked example to copy.

- **macOS** (SwiftUI custom shell): add `SidebarPage.scan`
  (`apps/mac/Sources/Aitmproxy/Session.swift:8`, with `title`/`symbol`/
  `showsFlows=false`), a sidebar row in the "aitmproxy" group
  (`Shell/SidebarView.swift:62`, copy the `.findings` queue-count line), a
  `case .scan: ScanPanel()` in `MainView.content` (`Shell/ShellView.swift:125`),
  a Proxy-menu button + shortcut (`App.swift:196`), and a palette setup entry
  (`Session+Palette.swift:47`). A `ScanPanel`/`ScanPanelState` mirrors
  `FindingsPanel`/`PocPanelState`, held lazily on `Session` (like `poc`,
  `Session.swift:363`); launch/run go through `Session.runCommand`
  (`Session+Palette.swift:7`); progress via `ScanPanelState.running` + a
  `scan.status` read in `BusService.pollLoop`.

### Gating in the UI

- `scan.discover`/`scan.passive` are `Read`/`Write`: launchable by the operator
  and (discover) autonomously by the agent under `Auto`, always scope-gated. Their
  UI launch needs no confirm.
- `scan.inject`/`scan.run` are `Sensitive`: the Scan view's active-injection
  launch shows the scope + a confirm (honouring the command's `confirm_prompt`,
  D-MCP3) and is **disabled with a reason** when the command is absent from
  `tools/list`. The operator toggle for `scanner.allow_agent_active` (whether an
  *agent* may run active injection) lives in the config surface each UI already
  has (web/macOS/TUI config view), reading/writing the new config field (D-MCP2);
  it never changes the operator's own ability to run.

## Acceptance criteria

Mapped to integration stages so Matt can approve stage by stage. UI criteria are
proven against the fixture/snapshot harnesses (Constraints), not a live browser.

**Integration Stage 1 — MCP verified + Scan view & discover across all three UIs**
(depends on PR #67 merged)

1. **AC1:** A `tools/list` over the assembled proxy returns every shipped `scan.*`
   command, each with a non-empty JSON-Schema `inputSchema`, and
   `crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS` equals the live set (literal:
   the contract test passes with `scan.discover` present; the test is the
   verification artifact).
2. **AC2:** A `tools/call` of `scan.discover` with an in-scope target over the MCP
   frontend returns a structured object result; an out-of-scope target is refused
   (reuses the scanner's `GuardError::OutOfScope`; literal: error vs. object).
3. **AC3 (web):** A Scan section appears in the web sidebar when `tools/list`
   offers `scan.discover`, launches `scan.discover` with a scope-bound target from
   a schema form, and renders the returned `endpoints` and `injection_points`,
   each endpoint linking to its flow (self-test / component test).
4. **AC4 (TUI):** `Mode::Scan` + `SidebarItem::Scan` render in the fixture
   snapshot with `scan.discover` in `CORE_TOOLS`; launching discover populates a
   `ScanState` and the Scan view lists endpoints + injection points (snapshot +
   reducer test).
5. **AC5 (macOS):** A `SidebarPage.scan` section renders with the fixture tool
   list, launches `scan.discover` via `Session.runCommand`, and shows endpoints +
   injection points (fixture/unit test; `build.sh` gate green).
6. **AC6 (parity):** All three Scan views take the same launch inputs (a
   scope-bound target + the discover schema fields) and render the same result
   regions (endpoints linked to flows; injection-point list) — a documented
   parity checklist, each item cited to a test above.

**Integration Stage 2 — scanner findings in the existing Findings surface**
(depends on backend `scan.passive` + `scan.report`)

7. **AC7:** Scanner findings from `scan.report` fold into each UI's existing
   `Finding`/`Severity` model and Findings pane (TUI via a `from_scan_json` +
   `BusEvent::ScanFindings`; web via `mergeFindings` widened to the report source;
   macOS via `PocPanelState`/`FindingsStore` widened) — literal: a seeded report
   yields one finding row per reported finding in each UI's Findings pane, with
   severity styling, and no secret from a scanned request appears in the row
   (redaction preserved).
8. **AC8 (parity):** The Findings pane is the single home for scanner findings in
   all three UIs (no new findings panel added), proven by the parity checklist.

**Integration Stage 3 — active-injection launch + gating UX + config**
(depends on backend `scan.inject`)

9. **AC9:** `scanner.allow_agent_active` is an operator-settable config field
   (default false), threaded through `Config` into `ScannerConfig` at `wire.rs`;
   a wire-level test proves an MCP `scan.inject` is refused with the flag off and
   accepted with it on (mirrors `scope_add_gate_is_wired_default_off`), while an
   operator/CLI call always runs.
10. **AC10:** Each UI's Scan view offers an active-injection launch that shows the
    scope being authorized and a confirmation (honouring the command's
    `confirm_prompt`), is **disabled with a reason** when `scan.inject` is absent
    from `tools/list`, and exposes the `scanner.allow_agent_active` toggle in the
    config surface (per-UI test: disabled-state snapshot + a confirm-path test).

**Integration Stage 4 — campaign (`scan.run`) + progress + report export**
(depends on backend `scan.run`/`scan.status`)

11. **AC11:** Each UI launches `scan.run` as one scope-bound, confirmed campaign
    and shows live progress by reading `scan.status` on the UI's existing poll
    cadence (phase + counts + a terminal `stopped_reason`), clearing the busy flag
    on completion (per-UI test with a fixture `scan.status` sequence).
12. **AC12:** The campaign's report is reachable from each UI's Findings surface
    and exportable through the existing findings export path (web `findings/export.ts`,
    macOS Findings "Export", TUI artifact open) — literal: export produces the
    report for a seeded campaign.

## Left to the builder

- The exact visual layout of each Scan view (single panel vs. master-detail vs.
  a flow-list filter) within the reuse constraints above — provided endpoints link
  to flows, injection points use the existing list widget, and findings use the
  existing Findings pane.
- Whether discovered endpoints are shown as a filtered view of the main flow list
  or a dedicated sub-list in the Scan view (both reuse existing rendering).
- The precise `ScanState`/`ScanPanelState`/scan store field layout per UI.
- Whether Stage 4 progress stays on polling or adds a streamed notification path
  (polling is the required baseline; streaming is optional within Stage 4).
- Icon choice for the Scan sidebar item from each UI's existing icon set.

## Open questions

- **OQ1:** Should the operator toggle for `scanner.allow_agent_active` live in the
  config/settings surface (this spec's assumption) or in the Scan view's launch
  header? (Affects Stage 3 placement only.)
- **OQ2:** For Stage 4, is polling `scan.status` acceptable for progress, or does
  Matt want a streamed/subscribed progress channel in the first campaign stage?
