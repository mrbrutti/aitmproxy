# aitmproxy TUI operator UI — implementation plan

**Status:** approved (design approved by Matt 2026-10-27 — `docs/design/operator-ui-foundation.md`; this plan is the TUI lead's task breakdown of that approved design, 2026-10-27)
**Spec:** `docs/design/operator-ui-foundation.md` (§2.6–§2.10(c) shell, components, degradations; §3 feature catalog, column `tui`; §4 bus contract, §4.10 `aitm-bus-client`) with `docs/design/tokens.json` and `docs/design/mockup/index.html`. Surface decisions that the foundation leaves to the builder are fixed in the shared note `ui-tui-ARCHITECTURE.md` (side-session notes folder) and restated below where a task needs them.
**Branch / worktree:** `claude/ui-tui-16e3cc` · `.claude/worktrees/ui-tui-16e3cc`

## Overview

Two crates: `crates/aitm-bus-client` (the shared Rust bus client) and
`crates/aitm-tui` (ratatui). Tasks 1–3 are the skeleton the lead built in one
pass (tokens generator, bus client, shell + viewers + fixture + snapshot); they
are done and committed. Tasks 4–7 are independent and fan out; Task 8 is the
whole-branch tester pass; Task 9 the panel review and fixes.

Global constraints (from the foundation and CLAUDE.md): the gate
`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
is green before any review; `unsafe_code = "forbid"` (workspace lint); no
change to `aitm-core` — a needed core addition is reported to the lead, not
built; features the bus does not offer degrade to a labelled "needs core
follow-up F*n*" control, never silently; every dependency is one already in
`Cargo.lock` (ratatui 0.30, crossterm 0.29, similar 2, unicode-width 0.2,
serde_json with `preserve_order`, tokio, futures, anyhow).

## Tasks

### Task 1: tokens generator (done)
- **Satisfies:** §2.10(c) "generated tokens.rs"; §2.5 glyph map.
- **Files:** `crates/aitm-tui/build.rs`, `src/tokens.rs`, `src/theme.rs`.
- **Done when:** `tokens::tests`, `theme::tests` pass (they do).

### Task 2: aitm-bus-client (done)
- **Satisfies:** §4.2 connect sequence, §4.10 Rust client.
- **Files:** `crates/aitm-bus-client/src/lib.rs`, `tests/bus_client.rs`.
- **Done when:** 9 tests pass against a fake server (they do; TCP tests run outside the sandbox).

### Task 3: TUI skeleton (done)
- **Satisfies:** §2.6 shell, §2.7 flow list / badges / filter / palette / inspector / intercept bar / compose / scope / findings / agent toggle / status bar, §2.9–2.10(c) degradations, §3 column `tui` rows marked ✓ or ◐ where the bus allows.
- **Files:** `crates/aitm-tui/src/{action,app,base64,bus,caps,clipboard,filter,fixture,keys,lib,main,model,snapshot}.rs`, `src/ui/*`, `src/viewers/*`, `fixtures/bus-fixture.json`, `docs/design/tui/main-screen.svg`.
- **Done when:** `cargo test -p aitm-tui` green (68 tests) and the fixture snapshot shows the mockup's screen (it does).

### Task 4: `aitm tui` — embed the proxy in one process
- **Satisfies:** §2.10(c) "it may also embed the proxy (`aitm tui` starts core + TUI in one process over an in-process channel) … the bus contract is unchanged either way"; Matt accepted this option.
- **Depends on:** Task 3.
- **Files:** `crates/aitm/Cargo.toml` (add `aitm-tui.workspace = true`), `crates/aitm/src/main.rs` (modify), `crates/aitm/src/tui.rs` (create, if main.rs would otherwise exceed its current shape).
- **Change:** when `argv` is exactly `["tui"]` (after the `--config` split), build the proxy as the server path does (`assemble`, services, browser launch), construct **two** `McpServer`s over the same `Arc<Registry>`/services: one served on the configured agent transport **only if it is `LoopbackTcp`** (stdio would fight the TUI for the terminal — log a warning and skip), and one wrapped as `Arc<McpServer>` whose `handle` becomes the TUI's in-process handler:
  `let handler: aitm_bus_client::InProcessHandler = Arc::new(move |line: &str| server.handle(line));`
  then `aitm_tui::run(RunOptions { transport: TransportChoice::InProcess(handler), caps: None, poll: Duration::from_millis(500) })` runs inside the existing `tokio::select!` next to `proxy.run(..)`, `proxy.run_browser(..)`, the optional `mcp.serve()` and `shutdown_signal()`; when the TUI returns (operator quit) the select ends and the browser is reaped exactly as today. `tracing` output must not paint over the TUI: when running `tui`, route the subscriber to a file (`$TMPDIR/aitm-tui.log` or `cfg`-derived) or disable it unless `RUST_LOG` is set.
- **Test:** `crates/aitm/tests/tui_embed.rs` (or a `#[cfg(test)]` module): construct the two servers over `assemble(&Config::default())`-style wiring as `main` does, drive the in-process handler through `aitm_bus_client::BusClient` (`InProcessTransport`) and assert `initialize().name == "aitmproxy"`, `tools_list()` contains `flow.list`, and `call("flow.list", {})` is an empty array — the literal contract the TUI relies on. Also a `split_config_arg`-style unit test that `["tui"]` is recognised and `["tui", "extra"]` is rejected with a usage error.
- **Done when:** both tests pass, `cargo run -p aitm -- tui` starts the TUI (manual check by the lead in the Terminal panel), and the gate passes.

### Task 5: JSON tree fold navigation
- **Satisfies:** §2.7 "JSON tree (fold, copy node, JSONPath of node, filter)" — fold and node path.
- **Depends on:** Task 3.
- **Files:** `crates/aitm-tui/src/app.rs` (the `Action::ToggleFold` arm and `InspectorState`), `crates/aitm-tui/src/viewers/json.rs`, `crates/aitm-tui/src/ui/inspector.rs` (JSON tab only).
- **Change:** `viewers::json::tree` returns, alongside the lines, the node path of each line (`Vec<Option<String>>`, `Some` for container lines) — add `pub fn tree_with_paths(..) -> Option<(Vec<Line>, Vec<Option<String>>)>` and keep `tree` as a thin wrapper. `InspectorState` gains `pub cursor_line: usize` (the highlighted line in the focused pane). `Action::ToggleFold` in `Mode::Inspector` with the Response pane on the `JSON` tab: compute the tree for the selected flow's response body, take the path at `cursor_line`, toggle it in `inspector.folds`. `Action::Up/Down` in Inspector mode move `cursor_line` (clamped to the line count) and scroll to keep it visible, instead of moving `scroll` directly. The JSON tab renders the cursor line with `theme.selection()` and shows the node path of the cursor line right-aligned on the tab row (e.g. `$.user.id`). `y` on the JSON tab copies the node path (reuse `Action::CopyUrl` → extend to "copy what the focused viewer offers": URL in Flows mode, node path on the JSON tab) via OSC 52 when `caps.osc52`.
- **Test:** in `app.rs` tests: fixture-loaded app (`crate::fixture_app(200, 50)`), select `f41` (products JSON), `Mode::Inspector`, response tab `JSON`, `cursor_line = 2` (the `"items": [` line), `ToggleFold` → `inspector.folds` contains `"$.items"`; rendering the JSON tab (via `viewers::json::tree`) then yields a line containing `[…] 2 items`; `ToggleFold` again removes it. In `json.rs` tests: `tree_with_paths` on `{"a":{"b":1}}` returns paths `[Some("$"), Some("$.a"), None, None, None]`-shaped literal expectations.
- **Done when:** tests pass and the gate passes.

### Task 6: live-bus integration test
- **Satisfies:** §4.1–4.2 (the TUI is "a bus client like the others"): prove the bus task works against the real `aitm-mcp` server, not only the fixture.
- **Depends on:** Task 3.
- **Files:** `crates/aitm/tests/tui_live_bus.rs` (create), `crates/aitm/Cargo.toml` (dev-dependency `aitm-tui`, `aitm-bus-client` if not already a dependency via Task 4 — coordinate: add them under `[dev-dependencies]` only if Task 4 has not added `aitm-tui` under `[dependencies]`; a duplicate entry is a build error).
- **Change:** start `McpServer::new(registry, McpTransport::LoopbackTcp { port: 0, token })` with services from `assemble(&Config::default())`, capture the bound port with `on_bound`, then run `aitm_tui::bus::run` with `aitm_tui::connector(TransportChoice::Tcp { addr, token })` for a few hundred milliseconds with `poll = 50ms`, collecting `BusEvent`s. Assert: the first event is `Connected { tools, .. }` with `tools` containing `flow.list`, `flow.intercept`, `request.send` and **not** `flow.detail`; a `Flows(vec![])` event arrives; sending `BusRequest::Intercept(true)` yields `CallOk { name: "flow.intercept", value: true }`; sending `BusRequest::Call { name: "nope", .. }` yields `Toast(Warn, "nope is not on this bus")`. Mark the test `#[ignore]`-free but guard the bind with the same pattern other crates use when the sandbox refuses ports (if `TcpListener::bind` fails with `PermissionDenied`, print a note and return — document that it ran green in the Terminal panel).
- **Test:** the file itself; literal expectations as above.
- **Done when:** passes in the Terminal panel (sandbox cannot bind) and the gate passes.

### Task 7: run documentation
- **Satisfies:** §2.10(c) build notes; operators need to know how to start it.
- **Depends on:** Task 4 (for the `aitm tui` paragraph).
- **Files:** `crates/aitm-tui/README.md` (create), `docs/design/operator-ui-foundation.md` is **not** edited.
- **Change:** how to run against a proxy (`aitm-tui --bus 127.0.0.1:9090 --token-file …`), embedded (`aitm tui`), with the fixture, and how to take a snapshot; the key map (copy from `keys.rs`); the filter grammar (copy from `filter.rs`); the degradations list and the "needs core follow-up F*n*" rule; the fixture file's role for the other surfaces.
- **Test:** none (docs). **Done when:** the lead has read it.

### Task 8: whole-branch tester pass
- Tester engine: coverage map of §2.7/§2.10(c)/§3 `tui` column → tests; strengthen weak tests; edge cases (empty fixture, 40×4 terminal, malformed `flow.detail`, a body that is not UTF-8, a 5 MB body in the viewers, a flow list of 5 000 rows rendering under 50 ms in `snapshot::render`).

### Task 9: panel review + fixes
- `security-reviewer`, `quality-reviewer`, `spec-reviewer` in parallel on the whole branch diff vs `main`; fixes dispatched as fix tasks; log below.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| 3 | Tester (pass 1) | Important | F1 palette popup panics on terminals shorter than ~12 rows (`overlays.rs` box not clamped to the screen) | fix task dispatched 2026-10-27 |
| 3, 5 | Tester (pass 1) | Important | F2 viewers rebuilt every frame; JSON tab builds the tree three times; a 5 MB body costs 1.1–3.3 s per frame | fix task: page bodies (1 MiB byte cap, 4 000-line cap, one tree per frame) |
| 3 | Tester (pass 1) | Important | F3 WebSocket frames unreachable: drawn only when the response is absent, but a WS flow's response is the 101 | fix task: frames on the Response Body tab for WS flows |
| 3 | Tester (pass 1) | Important | F4 `percent_decode` slices by byte offset → panic on a multibyte char after `%` (reachable from any request path) | fix task |
| 3 | Tester (pass 1) | Minor | F5 at exactly 120 columns the toolbar pill is cut into the agent toggle and the status counts collapse | fix task: drop hint clusters before counts |
| 3 | Tester (pass 1) | Minor | F6 Ctrl-K dead (`nav` maps `k` before the ctrl arm) | fix task |
| 3 | Lead | Minor | F7 line-number gutter drawn for the summary-facts fallback | fix task |
| 3 | Tester (pass 1) | Observation | O1 diff threshold is the pane width, not terminal columns | accepted by lead: the pane is what the diff has |
| 3 | Tester (pass 1) | Observation | O2 intercept bar between list and inspector (mockup) vs "above the status bar" (§2.7 text) | accepted by lead: follows the mockup |
| 3 | Tester (pass 1) | Observation | O4 `on_bus(Flows)` is O(n²), 160 ms at 5 000 flows | follow-up if it grows; fix allowed in the fix task when small |

## Shipped

(filled at integration)
