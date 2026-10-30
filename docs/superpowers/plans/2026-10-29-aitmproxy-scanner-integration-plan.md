# Scanner operator-surface integration implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-scanner-integration-design.md`
**Branch / worktree:** `feat/scanner-integration`

## Overview

Surface the deterministic scanner's `scan.*` commands over MCP (verify + keep the
contract true) and in all three operator UIs (web / TUI / macOS) at parity,
reusing the flow-list, inspector, findings and scope surfaces. Cut into **four
integration stages (14 tasks)**, each gated on the matching backend scanner stage
and each shippable on its own:

1. **Stage 1 (greenlight) — MCP verified + a Scan view with `scan.discover` in all
   three UIs.** Depends only on PR #67 (`scan.discover`).
2. **Stage 2 — scanner findings fold into each UI's existing Findings surface.**
   Depends on backend `scan.passive` + `scan.report`.
3. **Stage 3 — active-injection launch + gating UX + `scanner.allow_agent_active`
   config.** Depends on backend `scan.inject`.
4. **Stage 4 — `scan.run` campaign launch + live progress + report export.**
   Depends on backend `scan.run`/`scan.status`.

Within every stage the three UI tasks touch disjoint trees (`apps/web`,
`crates/aitm-tui`, `apps/mac`) and **fan out in parallel**; the one shared/core
task in a stage (T1 contract, T8 config) runs first. The longest sequential chain
is T1 → (T2|T3|T4) → T5/T6/T7 → T8 → (T9|T10|T11) → (T12|T13|T14). No task edits
`aitm-core` command/flow/event/guard types; a task that finds it must **stops and
reports** (workflow rule). Declared signatures are authoritative; private layout
and exact view composition are the builder's.

**Global constraints (every task):**

- **Gate** (Rust tasks): `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  Web tasks: `tsc --noEmit && vite build` + web self-test. macOS tasks:
  `apps/mac/build.sh` + `swift test` (Terminal panel only; `open`/`osascript`
  sandbox-blocked). **TDD:** failing test first; the report shows both runs.
- **No core edits.** New/modified UI files, the `frontends.rs` contract, fixture
  tool lists, and one `Config` field (T8) only.
- **Reuse, do not reinvent:** existing `Finding`/`Severity` model + Findings pane;
  existing scope surfaces; existing schema-driven form builders; existing
  list/table widgets. No new findings model, scope model, or tool-discovery path.
- **Parity:** the three UI tasks in a stage implement the same behaviour; each
  stage's parity AC is a checklist the orchestrator verifies across the three.

## Tasks

### Stage 1 — MCP verified + Scan view & `scan.discover` (depends: PR #67 merged)

### Task 1: MCP contract verification + fixture tool-list sync

- **Satisfies:** AC1, AC2.
- **Depends on:** none (PR #67 merged).
- **Files:** `apps/mac/Sources/AitmproxyKit/Fixtures+Tools.swift` (modify — add
  `scan.discover`); `crates/aitm/tests/frontends.rs` (verify `EXPECTED_TOOLS`
  already includes `scan.discover` and `[&str; 54]`); `crates/aitm-tui/src/lib.rs`
  (verify `scan.discover` in `CORE_TOOLS`). No web change (live `tools/list`).
- **Change:** add `"scan.discover"` to the macOS fixture tool list so fixture/
  snapshot tests see it; confirm (do not duplicate) the TUI `CORE_TOOLS` and the
  `frontends.rs` contract that #67 already set. Document the per-command checklist
  (EXPECTED_TOOLS + CORE_TOOLS + Fixtures+Tools) at the top of the plan's Review
  log for later stages.
- **Test:** `ac7_exact_tool_set` (`crates/aitm/tests/frontends.rs`) passes with the
  live set == `EXPECTED_TOOLS`; a macOS fixture test asserts `Fixtures.tools`
  contains `scan.discover`; (read-only) a `tools/call` of `scan.discover` against
  an assembled proxy returns an object for an in-scope target and errors for an
  out-of-scope one (may reuse `discover_e2e.rs` as the live proof under
  `AITM_OBSCURA`).
- **Done when:** the contract test passes, the macOS fixture test passes, the full
  gate passes.

### Task 2: web Scan view + `scan.discover` launch & results

- **Satisfies:** AC3, AC6 (web).
- **Depends on:** Task 1.
- **Files:** `apps/web/src/state/app.ts` (modify — `SidebarItem` union :25,
  `Panel` :68, `setSidebar` mapping :800, `scanDiscover` action in the `guarded()`
  wrappers :787), `apps/web/src/shell/Sidebar.tsx` (modify :163 — nav item gated
  on `proxy.tools.some(t => t.name === 'scan.discover')`), `apps/web/src/shell/Shell.tsx`
  (modify :138 — `<Match when={panel==='scan'}>`), `apps/web/src/panels/ScanPanel.tsx`
  (create), `apps/web/src/panels/scan/*` (create — launch form via
  `lib/schema-form` + `SchemaForm`, endpoints list linking to `app.loadDetail`,
  injection-point list reusing the virtual-list pattern).
- **Change:** a Scan panel that builds a launch form from the `scan.discover`
  `ToolDef.inputSchema`, binds the target to `proxy.scope` (offer in-scope hosts;
  reuse `addScope` for out-of-scope), calls `app.call('scan.discover', args)`,
  renders `endpoints` (each linking to its flow) and `injection_points`.
- **Test:** a component/self-test (`apps/web/scripts/selftest-live.mjs` extension
  or a Solid test) asserts the Scan nav item appears when the tool is offered,
  the launch form renders the schema fields, and a stubbed `scan.discover` result
  renders N endpoint rows + M injection-point rows with endpoint→flow links.
- **Done when:** the test passes, `tsc --noEmit && vite build` is clean, the web
  self-test passes.

### Task 3: TUI Scan view + `scan.discover` launch & results

- **Satisfies:** AC4, AC6 (TUI).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-tui/src/app.rs` (modify — `Mode::Scan` :55,
  `SidebarItem::Scan` :298 + `ALL`/`label`, `ScanState` fields :779 + init :873,
  `OpenScan` handler :1612, fold `scan.discover` out of the `CallOk` default arm
  :3539, `navigate()` arm :2452), `crates/aitm-tui/src/action.rs` (modify —
  `Action::OpenScan`), `crates/aitm-tui/src/keys.rs` (modify — binding + per-mode
  `fn scan`), `crates/aitm-tui/src/ui/mod.rs` (modify :108 — render arm, :8 —
  module), `crates/aitm-tui/src/ui/scan.rs` (create — render launch header +
  endpoints + injection points), `crates/aitm-tui/src/ui/sidebar.rs` (modify :148
  — Scan row gated on `has_tool("scan.discover")`), `:scan` builtin
  (`src/app.rs:3751` + `run_command`).
- **Change:** `ScanState { running: bool, target: Option<String>, endpoints:
  Vec<String>, points: Vec<InjectionPointRow>, cursor: usize, error: Option<String> }`
  (model mirrors the scanner's `endpoints`/`injection_points` JSON). Launch via the
  existing `call_tool("scan.discover", args)` with the target bound to `app.scope`
  (block + toast if out of scope, reusing `gate`/`in_scope`); set `running`, clear
  on `CallOk`. Copy the `l4` surface shape.
- **Test:** a reducer test drives `OpenScan` + a `BusEvent::CallOk{name:"scan.discover",…}`
  and asserts `ScanState.endpoints`/`points` populate and `running` clears; a
  snapshot test (`fixture_app_core`) renders `Mode::Scan` with `scan.discover` in
  `CORE_TOOLS` and asserts the sidebar Scan row + the view regions.
- **Done when:** tests pass and the full gate passes.

### Task 4: macOS Scan section + `scan.discover` launch & results

- **Satisfies:** AC5, AC6 (macOS).
- **Depends on:** Task 1.
- **Files:** `apps/mac/Sources/Aitmproxy/Session.swift` (modify — `SidebarPage.scan`
  :8 with `title`/`symbol`/`showsFlows=false`; lazy `session.scan` state :363),
  `apps/mac/Sources/Aitmproxy/Shell/SidebarView.swift` (modify :62 — Scan row in
  the "aitmproxy" group, count/enabled gated on `tools.contains{ $0.name=="scan.discover" }`),
  `apps/mac/Sources/Aitmproxy/Shell/ShellView.swift` (modify :125 — `case .scan: ScanPanel`),
  `apps/mac/Sources/Aitmproxy/App.swift` (modify :196 — Proxy-menu item + shortcut),
  `apps/mac/Sources/Aitmproxy/Session+Palette.swift` (modify :47 — setup entry),
  `apps/mac/Sources/Aitmproxy/Panels/ScanPanel.swift` (create),
  `apps/mac/Sources/AitmproxyKit/Panels/Scan.swift` (create — `ScanResult`/
  `InjectionPoint` Codable models + a `ScanForm` built from the tool schema like
  `PocRunForm`).
- **Change:** `ScanPanelState` (`@Observable`, held on `Session` like `poc`) with
  `running`, `endpoints`, `points`, `error`; launch via
  `session.runCommand("scan.discover", args)` with the target bound to
  `session.scopeHosts`; render endpoints (linking to `session.focusedRow`) +
  injection points in a master-detail. Tokens only (`Tok.*`/`Palette.*`/`Space`).
- **Test:** a `swift test` unit test decodes a fixture `scan.discover` result into
  `ScanResult` and asserts `endpoints`/`points` counts and that `ScanPanelState`
  populates; a fixture test asserts the `.scan` sidebar section is present with the
  fixture tool list.
- **Done when:** tests pass and `apps/mac/build.sh` + `swift test` are green.

### Stage 2 — scanner findings in the existing Findings surface (depends: backend `scan.passive` + `scan.report`)

### Task 5: web — scanner findings into the Findings panel

- **Satisfies:** AC7, AC8 (web).
- **Depends on:** Task 2; backend `scan.report`.
- **Files:** `apps/web/src/state/app.ts` (modify — widen `mergeFindings` :383 /
  `ProxyState.findings` :116 to also read the scanner report source),
  `apps/web/src/panels/findings/model.ts` (modify — accept scanner-sourced
  findings), `apps/web/src/panels/scan/*` (modify — a "view findings" link).
- **Change:** add a scanner findings source (from `scan.report`'s structured
  index) that maps into the existing `PocRun`/finding model consumed by
  `panels/findings/Findings.tsx`; no new panel. Redaction preserved (render only
  the fields the report provides).
- **Test:** a test feeds a stubbed `scan.report` index and asserts the Findings
  panel lists one row per reported finding with severity styling, and that no raw
  secret field is rendered.
- **Done when:** the test passes, `tsc --noEmit && vite build` clean, self-test passes.

### Task 6: TUI — scanner findings into the Findings pane

- **Satisfies:** AC7, AC8 (TUI).
- **Depends on:** Task 3; backend `scan.report`.
- **Files:** `crates/aitm-tui/src/model.rs` (modify — `Finding::from_scan_json`
  near `from_script_json` :667), `crates/aitm-tui/src/action.rs` (modify —
  `BusEvent::ScanFindings` near `BusEvent::ScriptFindings`), `crates/aitm-tui/src/app.rs`
  (modify — fold `ScanFindings` into `app.findings` like `merge_library`/
  `ScriptFindings` :3131), `crates/aitm-tui/src/bus.rs` (modify — read
  `scan.report` on the slow pass :274, gated on `has("scan.report")`).
- **Change:** parse `scan.report` output into `Finding` and merge into
  `app.findings`; the existing `Mode::Findings` pane (`src/ui/overlays.rs:386`)
  renders them unchanged.
- **Test:** a reducer test emits `BusEvent::ScanFindings` from a fixture
  `scan.report` and asserts `app.findings` gains the rows with correct `Severity`;
  the findings snapshot renders them.
- **Done when:** tests pass and the full gate passes.

### Task 7: macOS — scanner findings into the Findings panel

- **Satisfies:** AC7, AC8 (macOS).
- **Depends on:** Task 4; backend `scan.report`.
- **Files:** `apps/mac/Sources/AitmproxyKit/Panels/Findings.swift` (modify —
  decode scanner findings into `Finding` via a `fromScanReport` near
  `fromRunResult` :78), `apps/mac/Sources/Aitmproxy/Panels/FindingsPanel.swift`
  (modify — `PocPanelState.load` :30 also reads `scan.report` when
  `tools.contains{ $0.name=="scan.report" }`).
- **Change:** widen the findings source so `scan.report` findings appear in the
  existing `FindingsPanel`; reuse `Finding`/`Severity`/`FindingDetail`; no new
  panel. Redaction preserved.
- **Test:** a `swift test` decodes a fixture `scan.report` into `[Finding]` and
  asserts the panel state lists them with severity; a fixture test asserts the
  Findings panel shows scanner rows when the tool is present.
- **Done when:** tests pass and `build.sh` + `swift test` green.

### Stage 3 — active-injection launch + gating UX + config (depends: backend `scan.inject`)

### Task 8: `scanner.allow_agent_active` config plumbing + wire gate

- **Satisfies:** AC9.
- **Depends on:** backend `scan.inject` (+ its `confirm_prompt`, D-MCP3).
- **Files:** `crates/aitm-core/src/config.rs` (modify — add a `scanner` section
  with `allow_agent_active: bool` default false; this is a config value, **not** a
  new command/flow/event/guard type), `crates/aitm/src/wire.rs` (modify :205 —
  build `ScannerConfig` from `cfg.scanner.allow_agent_active` instead of
  `::default()`), `crates/aitm/tests/frontends.rs` (modify — a
  `scan_inject_gate_is_wired_default_off` test mirroring
  `scope_add_gate_is_wired_default_off` :463).
- **Change:** thread the flag through so an operator can enable agent-run active
  injection; default off preserves deny-by-default. (If `cfg.scanner` would be the
  first use of a new config sub-struct, add the minimal struct + `Default`; no core
  behavioural type changes.)
- **Test:** `scan_inject_gate_is_wired_default_off` — an MCP `scan.inject` under
  `AgentPolicy::All` is refused with `allow_agent_active=false` and accepted with
  `true`; an operator/CLI call runs in both.
- **Done when:** the test passes and the full gate passes.

### Task 9: web — active-injection launch + gating + config toggle

- **Satisfies:** AC10 (web).
- **Depends on:** Task 8.
- **Files:** `apps/web/src/panels/scan/*` (modify — an inject launch honouring the
  command `confirm`, disabled with a reason when `scan.inject` absent),
  `apps/web/src/state/app.ts` (modify — `scanInject` guarded action),
  `apps/web/src/panels/*config*` (modify — a `scanner.allow_agent_active` toggle in
  the existing config surface).
- **Change:** reuse the palette's confirm gating (`confirm`/`mutates`) for the
  Sensitive launch; the config toggle reads/writes the new field via the existing
  config command path.
- **Test:** a test asserts the inject control is disabled (with reason) when
  `scan.inject` is not in `proxy.tools`, shows a confirm when it is, and the
  config toggle round-trips.
- **Done when:** the test passes, `tsc --noEmit && vite build` clean, self-test passes.

### Task 10: TUI — active-injection launch + gating + config toggle

- **Satisfies:** AC10 (TUI).
- **Depends on:** Task 8.
- **Files:** `crates/aitm-tui/src/app.rs` + `src/ui/scan.rs` (modify — inject
  launch via `call_tool` honouring `CONFIRM_TOOLS`/confirm, disabled label when
  `!has_tool("scan.inject")`), `crates/aitm-tui/src/ui/config` surface (modify —
  show the `scanner.allow_agent_active` value, read via `config.get`).
- **Change:** the Scan view's inject action is scope-gated (`gate`/`in_scope`) and
  confirm-gated; a degraded "needs scan.inject" label when absent, matching the
  F-gap idiom.
- **Test:** a reducer/snapshot test asserts the inject control is disabled without
  the tool and prompts a confirm with it, and the config view shows the flag.
- **Done when:** tests pass and the full gate passes.

### Task 11: macOS — active-injection launch + gating + config toggle

- **Satisfies:** AC10 (macOS).
- **Depends on:** Task 8.
- **Files:** `apps/mac/Sources/Aitmproxy/Panels/ScanPanel.swift` (modify — inject
  launch with a confirm sheet honouring `confirm_prompt`, disabled when
  `scan.inject` absent), `apps/mac/Sources/Aitmproxy/Panels/*Config*`/`ConfigPanel`
  (modify — `scanner.allow_agent_active` toggle).
- **Change:** reuse the `PocSheets` confirm pattern + `session.runCommand`; the
  toggle reads/writes the config field; tokens only.
- **Test:** `swift test` asserts the inject button is disabled (with reason) absent
  the tool and enabled with it, and the config toggle round-trips in the model.
- **Done when:** tests pass and `build.sh` + `swift test` green.

### Stage 4 — campaign (`scan.run`) + progress + report export (depends: backend `scan.run`/`scan.status`)

### Task 12: web — campaign launch + `scan.status` progress + export

- **Satisfies:** AC11, AC12 (web).
- **Depends on:** Task 9.
- **Files:** `apps/web/src/panels/scan/*` (modify — `scan.run` launch + a progress
  readout polling `scan.status`), `apps/web/src/state/app.ts` (modify — poll
  `scan.status` on the existing cadence into scan state), `apps/web/src/panels/findings/export.ts`
  (reuse — report export).
- **Change:** campaign launch (confirmed, scope-bound) sets a running flag; the
  panel shows phase + counts + terminal `stopped_reason` from `scan.status`;
  completion routes findings to the Findings panel (Task 5) and offers export.
- **Test:** a test drives a fixture `scan.status` sequence and asserts the progress
  readout advances and settles, and export yields the report.
- **Done when:** the test passes, `tsc --noEmit && vite build` clean, self-test passes.

### Task 13: TUI — campaign launch + `scan.status` progress + export

- **Satisfies:** AC11, AC12 (TUI).
- **Depends on:** Task 10.
- **Files:** `crates/aitm-tui/src/bus.rs` (modify — read `scan.status` on the slow
  pass :274 → a `BusEvent::ScanStatus`), `crates/aitm-tui/src/app.rs` + `src/ui/scan.rs`
  (modify — `ScanState` progress fields + render phase/counts/`stopped_reason`;
  `scan.run` launch sets `running`), artifact-open for the report (reuse the
  findings `o` path).
- **Change:** poll-driven progress (Browser `busy` precedent); terminal state
  clears `running`; report reachable from the Findings pane.
- **Test:** a reducer test emits a `ScanStatus` sequence and asserts progress
  fields advance and `running` clears on terminal; a snapshot renders the progress.
- **Done when:** tests pass and the full gate passes.

### Task 14: macOS — campaign launch + `scan.status` progress + export

- **Satisfies:** AC11, AC12 (macOS).
- **Depends on:** Task 11.
- **Files:** `apps/mac/Sources/Aitmproxy/Bus/BusService.swift` (modify — poll
  `scan.status` in `pollLoop` when present), `apps/mac/Sources/Aitmproxy/Panels/ScanPanel.swift`
  (modify — `ScanPanelState.running`/phase/counts + progress view; `scan.run`
  launch), Findings "Export" reuse for the report.
- **Change:** poll-driven progress mirroring the `flow.list` poll; completion
  surfaces findings in `FindingsPanel` (Task 7) and offers export; tokens only.
- **Test:** `swift test` drives a fixture `scan.status` sequence and asserts the
  model's progress advances and settles, and export yields the report.
- **Done when:** tests pass and `build.sh` + `swift test` green.

## Review log

Per-command surface checklist (apply when any new `scan.*` command lands):
`crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS` (count + name) · TUI
`crates/aitm-tui/src/lib.rs` `CORE_TOOLS` · macOS
`apps/mac/Sources/AitmproxyKit/Fixtures+Tools.swift`. Web needs none (live
`tools/list`).

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
