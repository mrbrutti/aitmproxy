# DVWA tool-fixes implementation plan

**Status:** approved 2026-10-29 (orchestrator, on Matt's delegated authority — all three open decisions ruled below)
**Spec:** `docs/superpowers/specs/2026-10-29-dvwa-tool-fixes-design.md`
**Branch / worktree:** `feat/dvwa-tool-fixes` (worktree
`/Users/matt/Security/aitmproxy/.claude/worktrees/pkg57-spec-review-ff53e0`)

## Overview

T7 and T1 (the finding-recording gap) come first. T1 and T7 both live in
`aitm-poc/src/runner.rs`, so the runner tasks are sequential; the `aitm-core`
seam (Task 1) and the `aitm-findings` impl (Task 3) are independent of the
runner and of each other once Task 1 lands. The browser fixes (Tasks 8–9),
the Rhai budget (Task 10), the embedded-core core change (Task 11), and the docs
(Task 13) touch disjoint files and fan out in parallel. The Swift task (Task 12)
is built via the bama pipeline and cannot be gated by `cargo test`.

Every Rust task's **Done when** includes the full gate:
`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
(run via the Terminal panel per MEMORY: redirect `cargo test` to a log and gate
on its exit code). Port-binding tests also need the Terminal panel.

Independence map (no two parallel tasks share a file):

- **Task 1** (`aitm-core/src/ctx.rs`, `lib.rs`) — foundational; unblocks 2/3/4/5.
- **Tasks 2 → 4 → 6 → 7** are sequential (all edit `aitm-poc/src/runner.rs`).
- **Task 3** (`aitm-findings`) parallel with Tasks 2/4/6/7 once Task 1 lands.
- **Task 5** (wiring) after Tasks 1, 3, 4.
- **Task 7** (`aitm-core/src/config.rs` + `aitm-poc/src/runner.rs` + config_file parse)
  — the T3 agent-run gate; last in the runner.rs chain; `config.rs` is disjoint
  from Task 1's `ctx.rs`, so the two aitm-core edits merge clean.
- **Tasks 8 → 9** sequential (both edit `aitm-browser/src/driver.rs`), parallel
  with everything else.
- **Task 10** (`aitm-plugin-rhai`) independent/parallel.
- **Task 11** (`aitm-plugins/src/scope.rs`) independent/parallel.
- **Task 12** (Swift) after Task 11; bama pipeline, not cargo-gated.
- **Task 13** (docs) independent/parallel, no code gate.

## Tasks

### Task 1: FindingRecorder seam in aitm-core

- **Satisfies:** AC1 (and enables AC2, AC3, AC4, AC5).
- **Depends on:** none.
- **Files:** `crates/aitm-core/src/ctx.rs` (modify), `crates/aitm-core/src/lib.rs`
  (modify: re-export), `crates/aitm-core/src/ctx.rs` tests (add).
- **Change:** add `pub struct FindingDraft { title, class, severity: String,
  target, poc_ref, passed: bool, finding_capture: FlowId, flows: Vec<FlowId>,
  poc_path, screenshot_path, origin: Frontend, client_label: Option<String> }`;
  `pub trait FindingRecorder: Send + Sync { fn record(&self, draft:
  &FindingDraft, dir: &std::path::Path) -> anyhow::Result<String>; }`; add field
  `finding_recorder: Option<&'a dyn FindingRecorder>` to `CommandHost` (default
  `None` in `new`), builder `with_finding_recorder(self, &'a dyn
  FindingRecorder) -> Self`, getter `finding_recorder(&self) -> Option<&dyn
  FindingRecorder>`. Re-export `FindingDraft`, `FindingRecorder` from `lib.rs`.
- **Test:** `ctx::tests::finding_recorder_opt_in` — a `CommandHost::new(...)`
  returns `None` from `finding_recorder()`; the same host `.with_finding_recorder(&rec)`
  returns `Some`, and a trivial `rec.record(&draft, dir)` returns the literal id
  the stub produces (e.g. `"rec-1"`). Use a local stub `FindingRecorder`.
- **Done when:** the test passes and the full gate passes.

### Task 2: T1 — anchor a finding to any captured flow (PRIORITY)

- **Satisfies:** AC6, AC7.
- **Depends on:** none (independent of Task 1; sequential before Tasks 4/6 on the
  same file).
- **Files:** `crates/aitm-poc/src/runner.rs` (modify `run_inner` ~:429),
  `crates/aitm-poc/tests/script_runner.rs` (add test).
- **Change:** replace the hard `let finding_capture = finding.ok_or_else(...)?;`
  with precedence: (1) `finding` from an `http:` step if set; else (2)
  `host.store().list().last().copied()`; else (3) the existing error. Keep the
  error text `"poc.run: no HTTP flow was captured to anchor the finding"`.
- **Test:** `script_runner::script_only_poc_anchors_on_captured_flow` — a PoC
  with **no** `http:` step and one `script:` step; a stub `ScriptStepExecutor`
  that sends a request through `ctx.host.client()` (capturing a flow into the
  store) and returns `ScriptVerdict::Pass`. Assert `result` is `Ok`, and
  `result.finding_capture == store.list().last().unwrap()` (the one captured
  flow). Add a second test `no_flow_poc_errors` — a script-only PoC whose
  executor captures nothing errors with a message containing `"no HTTP flow was
  captured"`.
- **Done when:** both tests pass and the full gate passes.

### Task 3: DiskFindingRecorder in aitm-findings

- **Satisfies:** AC2.
- **Depends on:** Task 1.
- **Files:** `crates/aitm-findings/src/recorder.rs` (create),
  `crates/aitm-findings/src/lib.rs` (modify: module + re-export),
  `crates/aitm-findings/tests/recorder.rs` (create).
- **Change:** `pub struct DiskFindingRecorder;` implementing
  `aitm_core::FindingRecorder`: parse `draft.severity` (reuse the crate's
  `parse_severity`), build a `FindingRecord` (map `passed` → `Reproduction{
  passed, control_passed: None, run_at: now }`, `finding_capture`/`poc_path`/
  `screenshot_path` → `FindingArtifacts`, `origin`/`client_label`/`flows`/`title`/
  `class`/`target`/`poc_ref`), then `DiskFindingStore::new(dir).record(record)`.
- **Test:** `recorder::disk_recorder_round_trips` — in a `tempdir`, call
  `DiskFindingRecorder.record(&draft, dir)` with `title="SQLi"`,
  `severity="critical"`, `passed=true`, a fixed `finding_capture` uuid; then
  `DiskFindingStore::new(dir).get(&id)` returns a record whose `title == "SQLi"`,
  `severity == Severity::Critical`, `reproduction.passed == true`, and
  `artifacts.finding_capture` equals the uuid.
- **Done when:** the test passes and the full gate passes.

### Task 4: T7 — poc.run records a finding on pass (PRIORITY)

- **Satisfies:** AC3 (runner half), AC4, AC5.
- **Depends on:** Task 1 (seam), Task 2 (same file — sequential).
- **Files:** `crates/aitm-poc/src/runner.rs` (modify `run_inner` + the
  `poc.run` result object in `run_poc_command`), `crates/aitm-poc/tests/run.rs`
  (add test).
- **Change:** after computing `passed` and `finding_capture`, if
  `host.finding_recorder()` is `Some`, `host.config()` yields a `findings.dir`,
  and `passed`, build a `FindingDraft` (`title = poc.info.name`; `class =
  poc.info.cwe.clone().or_else(|| poc.info.tags.first().cloned()).unwrap_or(poc.id)`;
  `severity` = `poc.info.severity` as its lowercase string; `target =
  live.get("target")` stringified; `poc_ref = poc.id`; `flows =
  vec![finding_capture]`; paths from the result; `origin = host.frontend()`;
  `client_label = host.client_label()`), call `recorder.record(&draft, dir)`,
  log a failure without failing the run, and carry the returned id out of
  `run_inner` (e.g. add `recorded_id: Option<String>` to `PocRunResult`). In
  `run_poc_command`, add `obj.insert("recorded_id", ...)` only when `Some`.
- **Test:** `run::poc_run_records_finding_on_pass` — use a recording
  `FindingRecorder` double (captures the last `FindingDraft`) and a
  `CommandHost` with a config carrying a `findings.dir` and
  `.with_finding_recorder(&rec)`; run `example1` against the vulnerable target;
  assert the double received a draft with `passed == true`, `title ==
  "Reflected XSS in search 'q' parameter"`, `severity == "high"`, and
  `finding_capture == result.finding_capture`. Add
  `poc_run_no_recorder_records_nothing` (host without a recorder ⇒ double never
  called, `result.recorded_id` is `None`) and
  `poc_run_failed_records_nothing` (patched target ⇒ `passed == false`, double
  never called).
- **Done when:** the three tests pass and the full gate passes.

### Task 5: Wire the recorder into the command hosts

- **Satisfies:** AC3 (end-to-end over MCP/CLI), AC4.
- **Depends on:** Task 1, Task 3, Task 4.
- **Files:** `crates/aitm-mcp/src/server.rs` (modify `Services` ~:717 + builder +
  the `CommandHost::new(...)` site ~:1338), `crates/aitm-cli/src/dispatch.rs`
  (modify the host build), `crates/aitm/src/main.rs` (construct one
  `Arc<DiskFindingRecorder>` and pass it into the server/CLI services),
  `crates/aitm/src/tui.rs` (thread it through `Services` if that is the shared
  builder). Add an integration test under `crates/aitm-findings/tests/` or
  `crates/aitm/tests/`.
- **Change:** add `finding_recorder: Option<Arc<dyn FindingRecorder>>` to the
  server `Services` and a `with_finding_recorder` builder; call
  `.with_finding_recorder(rec.as_ref())` on the host at the build site. Same for
  the CLI host. Construct `Arc::new(DiskFindingRecorder)` in the binary and pass
  it in (always wired; persistence still gated on `findings.dir`).
- **Test:** `findings_e2e::poc_run_then_findings_list` — assemble a registry with
  `PocRunCommand`/`ScriptedPocRunCommand` + `FindingsPlugin` and a host carrying
  a temp `findings.dir` and the real `DiskFindingRecorder`; run a passing PoC via
  `poc.run`, then invoke `findings.list` and assert it returns exactly one
  summary with `poc_ref` == the PoC id and `passed == true`. (Uses the
  no-network `OkSender` pattern from `script_runner.rs`; no port binding.)
- **Done when:** the test passes and the full gate passes.

### Task 6: T2 — seed variables defaults into the script-visible bindings

- **Satisfies:** AC8, AC9.
- **Depends on:** Task 4 (same file `runner.rs` — sequential).
- **Files:** `crates/aitm-poc/src/template.rs` (add accessor),
  `crates/aitm-poc/src/runner.rs` (seed defaults in `run_inner`),
  `crates/aitm-poc/tests/script_runner.rs` (add test).
- **Change:** add `pub fn defaults(&self) -> &VarBindings` (or
  `iter_defaults()`) to `PocTemplate`. In `run_inner`, after `let mut live =
  bindings;` and `let tmpl = PocTemplate::from_poc(poc)?;`, for each
  `(name, value)` in `tmpl.defaults()`, `if live.get(name).is_none() {
  live.insert(name.clone(), value.clone()); }`.
- **Test:** `script_runner::variables_defaults_visible_to_script` — a PoC with
  `variables: [{name: marker, default: MARK}]` and a stub executor that records
  `ctx.vars.get("marker")`; run with empty `VarBindings` ⇒ executor saw
  `Some(Value::Str("MARK"))`. `variables_defaults_overridden_by_caller` — run the
  same PoC with `VarBindings::new().with("marker", Value::Str("OVERRIDE"))` ⇒
  executor saw `Some(Value::Str("OVERRIDE"))`.
- **Done when:** both tests pass and the full gate passes.

### Task 8: T5 — resolve the eval context per call

- **Satisfies:** AC10.
- **Depends on:** none (parallel with the aitm-poc/findings/rhai tasks).
- **Files:** `crates/aitm-browser/src/driver.rs` (modify `CdpSession::eval`
  ~:141), test in `crates/aitm-browser/tests/` (add; live full-stack assertion
  may be `#[ignore]`d, with a hermetic retry-logic test not needing Chromium).
- **Change:** in `CdpSession::eval`, resolve/refresh the current execution
  context before evaluating rather than reusing a cached id; on a CDP error whose
  message contains `-32601`/`Cannot find context`, re-resolve and retry once,
  returning the second result (or its error).
- **Test:** `driver::eval_retries_on_stale_context` — a hermetic test over a
  small eval seam/double that fails the first call with a
  `"-32601 Cannot find context with specified id"` error and succeeds the
  second, asserting the returned `Value` equals the second call's value (e.g.
  `Value::Int(7)`) and that it was called exactly twice. The live
  `eval_without_navigate` full-stack check is `#[ignore]`d (needs obscura).
- **Done when:** the hermetic test passes and the full gate passes.

### Task 9: T6 — click awaits the navigation it triggers

- **Satisfies:** AC11.
- **Depends on:** Task 8 (same file `driver.rs` — sequential).
- **Files:** `crates/aitm-browser/src/driver.rs` (modify `CdpSession::click`
  ~:110), test in `crates/aitm-browser/tests/` (add; live part `#[ignore]`d).
- **Change:** after the click, await the navigation it causes bounded by
  `self.nav_timeout`; if no navigation starts within a short inner bound, return
  `Ok(())` (a click that navigates nothing still succeeds). Reuse the
  `wait_for_navigation` path used by `navigate`.
- **Test:** `driver::click_no_nav_returns_within_bound` — a hermetic test proving
  the bounded-wait helper returns `Ok` promptly when no navigation event arrives
  (assert elapsed `< nav_timeout`). A live `click_then_get_dom_sees_result_page`
  full-stack check is `#[ignore]`d (needs obscura).
- **Done when:** the hermetic test passes and the full gate passes.

### Task 10: T9 — a separate budget for browser host calls

- **Satisfies:** AC12.
- **Depends on:** none (parallel).
- **Files:** `crates/aitm-plugin-rhai/src/config.rs` (add `browser_timeout` to
  `RhaiConfig` + default), `crates/aitm-plugin-rhai/src/engine.rs` (add
  `browser_timeout` to `Budget`, carry through `begin_run`/`remaining_budget`
  context or a sibling accessor), `crates/aitm-plugin-rhai/src/host_net.rs`
  (a `block_on_browser` that uses the browser budget; browser verbs call it),
  tests in `crates/aitm-plugin-rhai/tests/` or an inline `#[cfg(test)]` module.
- **Change:** `RhaiConfig::browser_timeout: Duration` (default 30s),
  `Budget::browser_timeout`, and a browser-call budget resolver (e.g.
  `remaining_browser_budget()` or a `block_on` variant taking an explicit
  budget). Route `browser.navigate/click/eval/...` host calls through the larger
  budget; keep `http.*`/`store.*`/`scope.*` on `remaining_budget()`. Preserve the
  `Timeout` abort token and the in-hook refusal of `browser.*`.
- **Test:** `budget::browser_call_uses_browser_budget` — with a `Budget` whose
  `hook_timeout` is 50ms and `browser_timeout` is 5s, a browser-path `block_on`
  over a future that completes in ~200ms returns `Ok`, while a non-browser
  `block_on` over the same future aborts with the `Timeout` token. Assert the
  literal success value (e.g. `7`) and the abort kind.
- **Done when:** the test passes and the full gate passes.

### Task 11: embedded-core-scope (core) — allow Operator to widen scope

- **Satisfies:** AC13.
- **Depends on:** none (parallel).
- **Files:** `crates/aitm-plugins/src/scope.rs` (modify `ScopeAdd::invoke`
  ~:86), `crates/aitm-plugins/tests/` (add/adjust test).
- **Change:** change the refusal guard from `host.frontend() != Frontend::Cli &&
  !self.allow_agent_widen` to `host.frontend() == Frontend::Mcp &&
  !self.allow_agent_widen`, so a present human operator (`Frontend::Operator`)
  may widen scope while an agent is still gated. Update the comment/error text to
  say "from an agent frontend". Verify the Rhai `scope.add` path (which refuses
  all PoC steps regardless) is unaffected.
- **Test:** `scope::operator_may_widen_scope` — `ScopeAdd{ allow_agent_widen:
  false }` invoked on a host with `Frontend::Operator` and a valid host returns
  `Ok` and the entry appears in `guard.list_scope()`; the same on
  `Frontend::Mcp` returns an error containing `"agent frontend"`; `Frontend::Cli`
  still succeeds.
- **Done when:** the tests pass and the full gate passes.

### Task 12: embedded-core-scope (app) — connect as operator [Swift; NOT cargo-gated]

- **Satisfies:** AC14.
- **Depends on:** Task 11 (the core must accept Operator `scope.add`).
- **Files:** `apps/mac/.../AitmproxyKit/EmbeddedCoreLaunch.swift` (modify
  `Config.yaml()` ~:201-218 to generate a second token and emit
  `mcp.operator_token`), `apps/mac/.../Bus/EmbeddedCore.swift` (hand the
  `BusEndpoint` the operator token), the embedded self-test
  `apps/mac/tools/selftest-live-embedded.sh` (update the by-design note and
  assert the Scope panel can add a host at runtime).
- **Change:** generate a distinct operator token alongside the agent token, emit
  `mcp.operator_token: <op-token>` in the generated YAML, and connect the app's
  embedded `BusEndpoint` with the operator token so it is classified
  `Frontend::Operator`. Startup config stays deny-by-default/empty (no `scope`
  block). **Alternative (note only):** instead emit `scope:\n
  allow_agent_widen: true` and keep the agent token — not recommended.
- **Test:** `swift test` for the config-generation unit (asserts the generated
  YAML contains `mcp.operator_token`) **plus** the live embedded self-test
  (`selftest-live-embedded.sh`) showing a runtime `scope.add` from the app
  succeeds. **This task cannot be gated by `cargo test`;** build and run it via
  the bama pipeline in the Terminal panel.
- **Done when:** `swift test` passes and the live embedded self-test adds a host
  at runtime through the Scope panel.

### Task 13: Authoring docs for T4 and T8 [docs only]

- **Satisfies:** AC15.
- **Depends on:** none (parallel; no code gate).
- **Files:** `docs/design/languages/README.md` (modify).
- **Change:** add a short "Browser-side authoring gotchas" subsection: (T4) in
  obscura, a synchronous `XMLHttpRequest` in `browser.eval` returns `status 0`;
  author browser POSTs as `await fetch(...)`. (T8) the `browser.click` MCP tool
  takes `selector` while the Rhai method is positional (`browser.click("…")`);
  a backslash in a Rhai string literal reaches eval'd JS mangled, so prefer
  string ops (`split`) over regex in eval'd JS.
- **Test:** none (docs). Reviewer confirms both notes are present and accurate.
- **Done when:** the subsection exists with both notes; `cargo fmt --check` still
  passes (no code changed).

### Task 7: T3 — `poc.allow_agent_run` gate for agent-driven poc.run

- **Satisfies:** AC16 (new — agent runs poc.run only behind the operator flag).
- **Depends on:** Task 6 (same file `runner.rs` — last in the chain). Config edit
  (`aitm-core/src/config.rs`) is disjoint from Task 1.
- **Ruling (orchestrator, Matt's authority):** build the gate now, deny-by-default,
  mirroring the existing `allow_agent_*` pattern (`allow_scope_add`,
  `allow_agent_authoring`, ca-install). An agent (`Frontend::Mcp`) may run `poc.run`
  **only** when the operator set the flag; `Frontend::Operator`/`Frontend::Cli`
  always may.
- **Files:** `crates/aitm-core/src/config.rs` (add `allow_agent_run: bool` to the
  `poc` config section, default `false`), `crates/aitm/src/config_file.rs` (parse it,
  default false), `crates/aitm-poc/src/runner.rs` (gate at the top of
  `run_poc_command`), `crates/aitm-poc/tests/run.rs` (add tests).
- **Change:** in `run_poc_command`, before loading/running: if
  `host.frontend() == Frontend::Mcp` and
  `!host.config().map(|c| c.poc.allow_agent_run).unwrap_or(false)`, bail with a
  message mirroring scope.add's — e.g. `"poc.run refused: running a PoC from an
  agent frontend is disabled. Set poc.allow_agent_run = true in the aitmproxy
  config to allow it, or run it from the operator/CLI."`. `Frontend::Operator` and
  `Frontend::Cli` are never gated.
- **Test:** `run::poc_run_gated_for_agent` — a host with `Frontend::Mcp` and a
  config whose `poc.allow_agent_run == false` ⇒ `poc.run` errors with a message
  containing `"agent frontend"` and **no** request is sent / no artifacts written;
  the same host with `allow_agent_run == true` runs (reuse the `OkSender` no-network
  rig) and returns `Ok`; `Frontend::Operator` and `Frontend::Cli` run regardless of
  the flag. Confirm the config default is `false` (`config::tests`).
- **Done when:** the tests pass and the full gate passes.

## Open questions / decisions for Matt

All three resolved by the orchestrator on 2026-10-29 (Matt's delegated authority):

1. **T3 — agent `poc.run`: RESOLVED → build the gate (now Task 7).** Add
   `poc.allow_agent_run` (default `false`, deny-by-default), mirroring the existing
   `allow_agent_*` pattern. Agent (`Frontend::Mcp`) may run `poc.run` only when the
   operator sets the flag; `Frontend::Operator`/`Frontend::Cli` always may. Built in
   this plan as Task 7 (not deferred).
2. **T7 record-on-pass: RESOLVED → confirmed.** `poc.run` records a `FindingRecord`
   only on a passing run; failed runs do **not** appear in `findings.list`. A
   `runs.jsonl`-only history line for all runs is a noted **future follow-up**, not
   built now.
3. **embedded-core-scope route: RESOLVED → operator-token + Task 11.** Go with the
   operator-token route (Task 12) plus letting `Frontend::Operator` widen scope
   (Task 11), **not** the blunt `allow_agent_widen: true`. Task 11 is required
   because `scope.add` today refuses `Frontend::Operator` too (scope.rs:86 gates on
   `!= Cli`) — a verified correction to the "connect as operator is enough" premise.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
