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

Manifests touched by the skeleton (Tasks 1–3): workspace `Cargo.toml` (members + path deps),
`Cargo.lock` (ratatui 0.30, crossterm 0.29, similar 2, unicode-width 0.2 and ratatui's
sub-crates), `crates/aitm-bus-client/Cargo.toml`, `crates/aitm-tui/Cargo.toml` — declared here
after the fact (spec review I5).

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

### Task 10: Browser view (decision 1, parent session 2026-10-28: build it)
- **Satisfies:** §2.7 "Browser view … TUI: URL + last screenshot as placeholder + `get_dom` text outline; navigate/eval available"; §2.9 "URL, DOM outline, last screenshot placeholder"; §3.9 Embedded browser view, tui ◐ no viewport. The six `browser.*` commands exist today; F14 (`browser.tabs`, screencast) stays a labelled follow-up.
- **Depends on:** the panel-1 fix tasks (they own `app.rs`/`ui/**` until they land).
- **Files (as shipped in 11abf71; amended after the spec review):** also `crates/aitm-tui/src/ui/bars.rs` (the `PromptKind` match is exhaustive; Browser status hints), `crates/aitm-tui/src/ui/overlays.rs` (interim stub panel removed), `crates/aitm-tui/src/ui/sidebar.rs` (label `—`), `crates/aitm-tui/tests/tester_bus_task.rs` (its always-failing fixture tool moved from `browser.navigate` to `ca.install` because the fixture now answers browser calls). Originally declared: `crates/aitm-tui/src/app.rs` (`Mode::Browser`, `BrowserState { url, dom: Option<String>, dom_outline: Vec<String>, screenshot: Option<(u32,u32,&'static str, usize)>, last_eval: Option<String>, busy: Option<&'static str> }`, actions), `crates/aitm-tui/src/ui/browser.rs` (create: URL line, screenshot placeholder `[screenshot W×H PNG · o to open]`, DOM outline, eval result, key hints), `crates/aitm-tui/src/ui/mod.rs` (dispatch), `crates/aitm-tui/src/keys.rs` (`Mode::Browser` map: `g` navigate prompt, `e` eval prompt, `d` refresh DOM, `s` screenshot, `o` open screenshot, Esc), `crates/aitm-tui/src/action.rs` (`BusRequest::Browser{Navigate(url)|Eval(expr)|GetDom|Screenshot}` or reuse `Call`), `crates/aitm-tui/src/bus.rs` (route `browser.screenshot` bytes: base64 → `CallOk` value stays; app decodes), `crates/aitm-tui/fixtures/bus-fixture.json` (fixture answers `browser.get_dom` with a small HTML document and `browser.screenshot` with a 1×1 PNG so the panel renders in tests), `crates/aitm-tui/src/fixture.rs`, README (Browser section), `crates/aitm-tui/tests/tester_components.rs` (one panel test).
- **Change:** sidebar `Browser` opens `Mode::Browser`; `:browser` too. DOM outline = tag path per element, indented, first 200 lines (a tiny tag scanner, no HTML crate: track `<tag`, skip `</`, `script`/`style` bodies, attributes `id`/`class` shown). Screenshot bytes go through `viewers::image::dimensions` for the placeholder and are kept for `o` (open via `open::body_to_temp_file`). Errors from `browser.*` (no engine) show in the panel, not only as a toast. Flows the browser produces already appear in the list with client `obscura`.
- **Test:** fixture app → `Action::OpenBrowser` → render contains `Browser`, the URL, `[screenshot 1×1 PNG`, and an outline line `html › body › h1`; `:browser.navigate url=https://x` from the panel yields `BusRequest::Call { name: "browser.navigate", .. }`; the bus `CallOk { name: "browser.get_dom" }` fills `dom_outline`.
- **Done when:** the test passes and the gate passes.

## Follow-up plan (descoped from v1 pending Matt — decisions 2 and 3, 2026-10-28)

Recorded here so the departure from the foundation is explicit (spec §0). Each item is a
labelled "not in this pass" in the README; none is faked.

| Item | Foundation ref | Note |
|---|---|---|
| Split view (two lists ≥ 160 cols, else tabbed) | §2.6, §2.9, §3.1 | `:split` toasts "not built in v1"; `SPLIT_COLS` kept for it |
| Saved filters | §3.2 | surface-local state; needs a config/state file decision shared with the GUIs |
| Match highlighting in body viewers | §3.2 | needs the filter's matched spans threaded into viewers |
| Sidebar quick filter (⌘⇧F) | §2.7, §3.2 | the sidebar is 28 cols; a filter line fits |
| Compose templates beyond GET / POST-JSON / POST-Form; Query field; body modes | §2.7, §3.5 | multipart needs a body builder |
| Message templates for edits | §3.4 | |
| WebSocket sent/received filter | §3.7 | `~ws` + direction atom |
| Setup guides text | §3.6 | content only |
| Column hide (fixed set) | §3.1 | `:columns` toggles |
| Palette recent / pinned | §2.7 | |
| Comment column; mark swatch beyond the first colour | §2.7 | |
| JSON tree: copy node value, filter, sort keys | §3.3 | |
| Kitty/sixel inline images | §2.9 | optional by design; `caps` already detects them |
| `app.rs` module split (`app/{compose,edit,palette,commands}.rs`) | quality Q3 | refactor once no fix task is in the file |
| Custom columns (one), multi-select + summary, overview dashboard text | §3.1 (F5) | need `flow.detail` data first |
| JSONPath/jq and full-text filter operators | §3.2 | body-field operators need F5 bodies; grammar to be fixed in the foundation (see note below) |
| Protobuf / MessagePack viewers, SSE event list, rendered Markdown/HTML text preview | §3.3 (F5/F4) | plain text / hex today |
| Code generator / copy as cURL, export body | §3.3 (F5) | `:curl` *imports* only |
| Response-phase intercept/edit, kill abort modes | §3.4 (F3) | labelled in the bar |
| SSL include/exclude list (F11), `ssl_insecure` toggle (F7), config view (F7) | §3.6, §3.9 | no commands today |

Filter-grammar note for the architect (spec review pass 2): for a GUI filter row to copy into
the TUI's text form the foundation must fix (1) `\/` for a literal slash inside `/re/` and the
closing `/` followed by a delimiter; (2) `(?-i)` for case-sensitive rows (TUI default `(?i)`);
(3) "equals" = `/^…$/` with regex escaping; (4) a quoting rule for literal `*`/`?`; (5) a text
form for JSONPath/jq and full-text; (6) that `~u x` is a wildcard/substring here, not mitmproxy's
regex. The README's EBNF is the current TUI behaviour.

Fix pass `645cce3` also touched `crates/aitm-tui/Cargo.toml` + `Cargo.lock` (`regex = "1"`, demanded
by I3) and added `docs/design/tui/main-screen-100x30.svg` (the narrow shell, kept on purpose).

Accepted additions (decision 4): sidebar items "All flows" and "Agent", `:curl`, Ctrl-K/Ctrl-F,
`AITM_BUS`/`AITM_BUS_TOKEN`, `--token` (marked insecure), PoC key `P` (spec erratum: §2.8's
`p` collides with pin), diff threshold by pane width, intercept bar above the inspector when it
is shown. F1 (operator identity + confirm on the wire) is owned by the M4 milestone spec; the
TUI's local y/N confirmation for `ca.install`/`ca.uninstall` is the interim guard until it lands.

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
| 1–7 | Tester (pass 1) | — | F1–F7 | fixed in 3752a5b (all six pinned tests green) |
| 3, 4 | Security (panel 1) | Important | S1 `ca.install`/`ca.uninstall` reachable from the palette with no confirmation; TUI identity is `Frontend::Mcp` until F1 | fix task A (local y/N gate); F1 priority raised with the parent session |
| 3 | Security (panel 1) | Important | S2 un-deadlined Myers diff per frame | fix task A (50 ms deadline + input caps) |
| 3 | Security (panel 1) | Minor | S3–S9 details never pruned, `--token` on argv, non-loopback `--bus`, log file mode, TCP line cap, compose width underflow, filter recursion depth | fix tasks A/B |
| 3, 4, 6 | Quality (panel 1) | Important | Q1 bus poll drops a row on a per-flow `flow.get` error; malformed `flow.detail` silent · Q2 embed tests hand-roll the wiring | fix task B |
| 1–7 | Quality (panel 1) | Minor | Q3–Q12 structure, dead code, `ToolInfo` duplicate, per-frame passes, test bounds, clipboard/-32001 handling, casts, F-labels, build.rs | fix tasks A/B; Q3's `app.rs` split deferred to a follow-up (two writers in the file now) |
| 3 | Spec (panel 1) | Critical | C1 `o` open-externally only toasts | fix task A/B (real open via `open`/`xdg-open`) |
| 3 | Spec (panel 1) | Critical | C2 Browser view absent (browser.* exist today) | **Matt**: lead recommends building it next; relabelled "not built yet" meanwhile |
| 3 | Spec (panel 1) | Critical | C3 Split view absent | **Matt**: lead recommends descoping for v1; README corrected |
| 3 | Spec (panel 1) | Critical | C4 catalog rows with no core dependency missing (saved filters, highlighting, templates, column hide, poc param/vars, YAML from disk …) | fix task A does poc `param`/`vars`/YAML-from-disk + compose templates; the rest **Matt**: build vs descope |
| 3 | Spec (panel 1) | Important | I1 F-dependent features absent silently · I2 no confirm/CA panel · I3 no regex operator · I4 additions (All flows, Agent item, :curl, Ctrl-K, env vars) · I5 undeclared manifests / mixed commit | A: I1, I2, I3 · I4 **Matt** (lead recommends accepting) · I5 fixed in this plan text; one commit per task from here |
| 1–10 | Security (panel 2) | PASS | S1–S9 verified real; 4 Minors: confine the client-side `poc_path` read (regular file, ≤ 256 KiB, `.yaml`), canonicalize `screenshot_path` before `open`, pid in the default log name + `O_NOFOLLOW`, `dry_run` bypass only when the schema declares it | final fix task |
| 1–10 | Spec (panel 2) | Important | residue §3 rows neither built, labelled nor in the follow-up table; Task 10 touched 4 undeclared files | fixed in this plan text (rows added above; Task 10 file list amended) |
| 1–10 | Spec (panel 2) | Minor | `--snapshot-core` shows a listening address today's TCP bus cannot give · WS row on the core bus prints `wss://` with an empty host and an empty Domains group · README overstates `Client = obscura` (F5) · Findings sidebar `0` where F13 is missing · README not-in-pass bullets + kitty/sixel wording · manifests in the fix pass · filter-grammar portability (architect note above) | code items → final fix task; docs items → final fix task (README); grammar → architect |
| 1–10 | Quality (panel 2) | Important | browser in-flight bookkeeping inferred from toast level/text; `inflight` never reset on disconnect (stuck "busy") | final fix task: `BusEvent::CallFailed { name, message }`, reset on Connected/Disconnected |
| 1–10 | Quality (panel 2) | Minor | key verbs as string pseudo-commands · prompt return-mode duplicated (`ScopeAdd` Esc lands in Flows) · tuples for screenshot/params · `ToolDef` decode duplicated · services wiring copied into test support · `fill_finding_yaml` blocks the loop and re-reads · one detail request bypasses `detail_failed` · `Value→text` match ×5 · 175-line browser test · paging budget constants · Q3 `app.rs` split (3 900 lines) | final fix task except: paging constants accepted as style; `app.rs` split stays in the follow-up plan, **by feature** (`app/{browser,ca,poc,compose,edit}.rs`) per the reviewer's ruling that a pre-merge behaviour-neutral split is pure risk |
| 1–10 | Tester (pass 2) | Important / Minor | P2-F1 WebSocket rows on the real bus have no URL (summary carries only `handshake`) → `wss://`, out of scope, un-actionable · P2-F2 status total `0 B` where a dash belongs | final fix task (URL from the handshake row; `Option<u64>` total); 13 regression tests in `tests/tester_pass2.rs` |
| 1–10 | Lead (gate) | Important (process) | the real-shell gate piped `cargo test` through `grep … \| tail`, so its exit status never gated the commit; `tui_live_bus` (port-binding, invisible to sandboxed coders) failed at `4dee236` after the `CallFailed` contract change | fixed in `9aaad5a` (test updated; gate now runs `cargo test > log && …` and reports `grep -c FAILED` = 0 over 88 green test binaries) |
| fix 2 | Quality (re-check) | PASS, 5 Minor | prompt `returns_to` is a static table (palette from a panel lands in Flows) · in-flight increment/decrement use different predicates · fixture loader swallows a nameless tool · `open_log_file(path, bool)` flag · cap value duplicated in text | first three fixed in the final small fix task; the two style items accepted by the lead |
| fix 2 | Security (re-check) | PASS, 2 Minor | `read_poc_yaml` stats before open (FIFO race) · Findings `o` opens any existing path the bus names | both fixed in the final small fix task (fstat on the handle; image sniff before open) |
| 3 | Spec (panel 1) | Minor | O1 diff threshold by pane width · O2 intercept bar placement · `P` vs `p` in the findings empty state · param names in bus.rs · extra key aliases · fixture advertises F-tools · manual evidence · note drift | README wording (A); acceptances for **Matt**; honest `--snapshot-core` (B); Terminal-panel evidence: `cargo run -p aitm -- --config … tui` showed two curl flows via the in-process bus; `cargo test -p aitm --test tui_live_bus` → `1 passed` in a real shell |

## Shipped

(filled at integration)
