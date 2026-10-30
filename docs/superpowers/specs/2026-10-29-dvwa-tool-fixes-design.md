# DVWA tool-fixes design

**Status:** draft
**Research inputs:** `demo/dvwa-pentest/ASSESSMENT.md` and `demo/dvwa-pentest/FINDINGS.md` (branch `claude/dvwa-pentest-demo-3a741a`); `docs/research/MEMORY.md` (`aitmproxy-dvwa-assessment-findings`). Source verified in this worktree (see each fix).

## Intent

A live DVWA pentest driven over the MCP bus reproduced 12 of 13 vulnerability
classes but surfaced a cluster of sharp edges in the PoC/scripting and
browser-driving surface. The worst is a recording gap: a `poc.run` proves a vuln
but nothing durable is written, so `findings.list` and every UI stay empty
(T7), and a pure-`script:` PoC fails outright because the finding anchor is only
set by a declarative `http:` step (T1). This change fixes T7, T1, and the
smaller ergonomic defects (T2, T5, T6, T9), documents the two authoring
foot-guns (T4, T8), and re-scopes the embedded macOS core at runtime
(embedded-core-scope). It deliberately does **not** decide whether an agent may
run `poc.run` (T3) — that is Matt's call, left as a localized hook.

## Goals

- A passing `poc.run` persists a durable `FindingRecord` when a findings
  directory is configured, so `findings.list` and the UIs show it (T7).
- A pure-`script:` PoC that captures any flow and proves a vuln returns success
  with a valid finding anchor, instead of hard-erroring (T1).
- A PoC's `variables:` defaults are visible to `vars.get()` inside a `script:`
  step, with caller `--vars` still overriding them (T2).
- `browser.eval` works without a preceding `navigate` (no stale-context error)
  (T5); `browser.click` awaits the navigation it triggers (T6).
- `browser.*` host calls from Rhai get a budget large enough for their network
  I/O, without loosening the deny-by-default/abort-on-deadline posture (T9).
- The embedded macOS core can be re-scoped at runtime from the app
  (embedded-core-scope).
- Authoring docs warn about sync-XHR vs `await fetch()` (T4) and the
  cross-surface `click` param / backslash-in-eval pitfalls (T8).

## Non-goals

- Deciding or building the agent-`poc.run` gate (T3). The design only keeps
  adding it later a localized change.
- Honoring an explicit `finding(#{flow: ...})`-chosen anchor from a script over
  the newest-captured-flow fallback (T1). The fallback is correct for the common
  case; a script-chosen anchor is a later refinement.
- Recording a finding for a **failed** `poc.run` (see Design: record-on-pass).
- Re-architecting the browser driver, the CDP layer, or the scripting sandbox.
- Reproducing insecure-CAPTCHA (needs reCAPTCHA keys on the target — a
  target-config limitation, not a tool defect).

## Anti-goals

- Any path that lets an autonomous agent (`Frontend::Mcp`) persist, widen, or
  run something it cannot today without an explicit, config-gated opt-in. Every
  new capability is gated on a configured directory, a present human
  (`Frontend::Operator`/`Cli`), or left untouched.
- A `poc.run` that silently records nothing when a dir is configured, or
  silently records when none is — persistence must be observable and opt-in.
- Widening the `browser.*` budget in a way that lets a flow hook stall the proxy
  chain past its existing deadline.

## Constraints

- **Dependency direction (hard).** `aitm-findings` depends on `aitm-poc` (for
  `Severity`), so `aitm-poc` **cannot** depend on `aitm-findings`. The runner
  may not persist directly. `aitm-core` is the bottom of the graph; both crates
  depend on it, so a shared seam belongs there.
- **Deny-by-default preserved.** Persistence only when `findings.dir` is
  configured; scope widening only for a present human or an explicit config
  flag; `browser.*` refused inside a flow hook as today.
- The Rust gate (`cargo fmt --check && cargo clippy --all-targets -- -D warnings
  && cargo test`) must pass for every Rust task. Swift/embedded tasks are built
  via the bama pipeline in the Terminal panel and **cannot** be gated by
  `cargo test` (use `swift test` + the live embedded self-test).
- The flaky `rhai_e2e::script_cannot_escape_or_exceed_scope` is pre-existing and
  non-deterministic; judge a change by whether it touches Rhai, not by that
  test.

## Design

### T7 + T1 — the finding-recording seam (priority)

These interact: the `FindingRecord`'s `finding_capture` is the T1 anchor, so
they are designed together. Dependency direction:

```
  aitm-core  (bottom: CommandHost, FindingDraft, FindingRecorder trait)
     ▲   ▲
     │   └──────────────┐
  aitm-poc            aitm-findings  (impl FindingRecorder; depends on aitm-poc for Severity)
  (runner builds a      (DiskFindingRecorder → DiskFindingStore)
   FindingDraft, calls        ▲
   host.finding_recorder())   │
                          the binary (aitm/src/main.rs) constructs the recorder
                          and wires it into the command host
```

**New in `aitm-core` (`src/ctx.rs`, re-exported from `lib.rs`):**

- A neutral, protocol-free draft the runner can build without naming
  `aitm-findings`:

  ```rust
  pub struct FindingDraft {
      pub title: String,
      pub class: String,
      pub severity: String,      // "info|low|medium|high|critical"; parsed by the impl
      pub target: String,
      pub poc_ref: String,
      pub passed: bool,
      pub finding_capture: FlowId,
      pub flows: Vec<FlowId>,
      pub poc_path: String,
      pub screenshot_path: String,
      pub origin: Frontend,
      pub client_label: Option<String>,
  }
  ```

  `severity` is a `String` because `aitm-core` cannot name `aitm-poc::Severity`
  (that would invert the dependency). **(Architect's call.)**

- The seam trait, mirroring `FindingSink`/`ScriptStepExecutor`:

  ```rust
  pub trait FindingRecorder: Send + Sync {
      /// Persist `draft` under `dir`; returns the assigned id.
      fn record(&self, draft: &FindingDraft, dir: &std::path::Path) -> anyhow::Result<String>;
  }
  ```

  `dir` is passed explicitly (not held) so the recorder is stateless — the same
  reason `FindingsPlugin::store_for` reads the dir from the host at invocation
  time. **(Architect's call.)**

- `CommandHost` gains `finding_recorder: Option<&'a dyn FindingRecorder>`, a
  builder `with_finding_recorder(self, &'a dyn FindingRecorder) -> Self`, and a
  getter `finding_recorder(&self) -> Option<&dyn FindingRecorder>`. Default
  `None` (deny-by-default: no recorder wired ⇒ no persistence).

**New in `aitm-findings` (`src/recorder.rs`):** `DiskFindingRecorder` (zero
state) implementing `aitm_core::FindingRecorder`: parse `draft.severity`, map
the draft onto a `FindingRecord` (reusing `Reproduction`/`FindingArtifacts` as
`findings.record` does), and `DiskFindingStore::new(dir).record(record)`.
`control_passed` is `None` (a `poc.run` runs no patched control).
`discovered_at`/`run_at` are `now()`.

**Runner change (`aitm-poc/src/runner.rs`, `run_inner`):**

- **T1 anchor precedence** replaces the hard `finding.ok_or_else(...)` at ~:429:
  1. a declarative `http:` step's captured flow (today's behaviour), else
  2. the newest flow captured in `host.store()` during the run
     (`host.store().list().last()`), which covers a pure-`script:` PoC that
     drove `http.send` or `browser.*` (all captured into the same store), else
  3. only if the store is empty, the existing hard error
     (`"poc.run: no HTTP flow was captured to anchor the finding"`).
  **(Architect's call: newest-captured-flow over a script-chosen anchor — see
  Non-goals.)**

- **T7 record (record-on-pass).** After the verdict, if
  `host.finding_recorder()` is `Some` **and** `host.config()` yields a
  `findings.dir` **and** `result.passed`, build a `FindingDraft`
  (`title = poc.info.name`; `class = cwe` if set else first `tag` else `poc.id`
  **(Architect's call)**; `severity = poc.info.severity` as a string;
  `target = live.get("target")`; `poc_ref = poc.id`;
  `finding_capture`/`poc_path`/`screenshot_path`/`flows` from the result;
  `origin`/`client_label` from the host) and call `recorder.record(&draft,
  dir)`. A record failure is logged and does **not** fail the run (the artifacts
  still returned). The returned finding id is added to the `poc.run` result
  object as `recorded_id` (string, absent when nothing was recorded) so a caller
  and the UIs can observe it. **(Architect's call: record only on pass, so
  `findings.list` stays a list of real findings; a failed-run history line is a
  possible later addition.)**

**Wiring (the binary + frontends):** construct one `Arc<DiskFindingRecorder>`
in `aitm/src/main.rs` and thread it to the command-host builders in
`aitm-mcp/src/server.rs` (`Services` + `with_finding_recorder` on the host at
the `CommandHost::new(...)` site ~:1338) and `aitm-cli/src/dispatch.rs`. It is
always wired (stateless); persistence stays gated on `findings.dir`.

### T2 — PoC `variables:` defaults visible to `vars.get()`

`PocTemplate::from_poc` already evaluates `variables:` defaults (including DSL
defaults like `rand_text_alpha`). Expose them: add
`PocTemplate::defaults(&self) -> &VarBindings` (or an iterator) in
`template.rs`. In `run_inner`, after building `tmpl` and `live`, seed each
default into `live` **only if `live` does not already hold that key**, so
caller `target` + `--vars` still win. Both the `{{template}}` path and
`vars.get()` then read the same evaluated defaults.

### T5 — `browser.eval` stale execution context

The shared `CdpSession::eval` (`aitm-browser/src/driver.rs:141`) calls
`page.evaluate`, which can reuse a cached execution-context id and fail
`-32601 Cannot find context with specified id` when no `navigate` preceded it.
Resolve/refresh the current context per eval rather than relying on a cached id,
and on a stale-context CDP error retry the eval once after re-resolving. The fix
lives in `CdpSession` (shared by the obscura and chrome drivers), so both
engines benefit. **(Premise note: the brief pointed at `obscura.rs`; the eval
path is actually the shared `CdpSession` in `driver.rs`.)**

### T6 — `browser.click` must await the navigation it triggers

`CdpSession::click` (`driver.rs:110`) returns as soon as the element is clicked,
so a following `get_dom` reads the pre-submit page. After the click, wait for the
navigation it causes, bounded by `nav_timeout`; if no navigation occurs within a
short bound, return normally (a click that navigates nothing must still
succeed). The `BrowserDriver::click` signature (`aitm-core/src/ctx.rs`) is
unchanged.

### T9 — a larger budget for `browser.*` host calls

`host_net.rs::block_on` (~:342) uses `remaining_budget()` (the hook wall-clock
remainder, default 2s). A `browser.*` call that fetches can exceed it. Add a
separate, larger budget for browser host calls: a `browser_timeout: Duration`
on `RhaiConfig` (`config.rs`) and `Budget` (`engine.rs`), with a sane default
(**Architect's call: 30s**, matching the browser `nav_timeout` order of
magnitude). Browser host verbs use `browser_timeout`; non-browser host calls
keep `remaining_budget()`. The abort-on-deadline semantics and the refusal of
`browser.*` inside a flow hook are unchanged.

### T3 — agent `poc.run` (hook only, not decided here)

`poc.run` is `Sensitivity::Write` (`runner.rs:888`) and the `AgentPolicy` gate in
`call_tool` refuses it to `Frontend::Mcp`. This design does **not** add a gate.
It keeps the decision localized: a future `poc.allow_agent_run` flag (mirroring
`allow_agent_authoring`/`allow_scope_add`) would be a single check, and the T7
recorder already keys persistence `origin` off `host.frontend()`, so an agent
run would record correctly once allowed. See Open questions.

### embedded-core-scope — runtime re-scope of the embedded macOS core

Root cause (confirmed): the embedded core's generated config
(`AitmproxyKit … EmbeddedCoreLaunch.swift Config.yaml()` ~:201-218) emits only
`listen`/`mcp.loopback_tcp`/`browser` — no `scope` block and no
`mcp.operator_token`. The single generated token is the **agent** token, so the
app connects as `Frontend::Mcp`, and `scope.add` is refused.

**Premise correction (important):** `scope.add`
(`crates/aitm-plugins/src/scope.rs:86`) refuses **every** non-`Cli` frontend —
including `Frontend::Operator` — unless `scope.allow_agent_widen` is set. So
simply connecting the app as an operator is **not** sufficient; the core must
also let a present human operator widen scope. The fix is therefore two small
parts:

1. **Core (Rust, cargo-testable).** Let `Frontend::Operator` through
   `scope.add` (a present human), keeping `Frontend::Mcp` gated behind
   `allow_agent_widen`: change the guard from `frontend != Cli` to
   `frontend == Mcp && !allow_agent_widen`. This mirrors how the operator is
   treated as a present human elsewhere (confirm-prompt short-circuit).
2. **App (Swift, bama pipeline — not cargo-gated).** Generate a second token,
   emit `mcp.operator_token` in `Config.yaml()`, and have the embedded launch
   hand the `BusEndpoint` the **operator** token so the app connects as
   `Frontend::Operator`. The existing Scope panel then works against the
   embedded core; startup stays deny-by-default/empty.

**Cheaper alternative (one block, note only):** add `scope:\n
allow_agent_widen: true` to the generated `yaml()`. This grants widening to any
agent frontend and keeps the app as `Frontend::Mcp` — less clean than the
operator-token route; recorded here, not recommended.

The coordinator sized this as a **small wiring change** to be included as its
own task, **not** split to a separate branch.

### T4, T8 — authoring docs (no behaviour change)

Add to the authoring guide (`docs/design/languages/README.md`):

- **T4:** in obscura, a synchronous `XMLHttpRequest` in `browser.eval` returns
  `status 0` (blocked); an awaited `fetch()` works. Guidance: author browser
  POSTs as `await fetch(...)`.
- **T8:** `browser.click` the MCP tool takes `selector`; the Rhai method is
  positional (`browser.click("…")`). A backslash in a Rhai string literal
  reaches eval'd JS mangled, so a JS regex like `/x=(\d+)/` silently fails —
  prefer string ops (`split`) over regex in eval'd JS.

## Acceptance criteria

1. **AC1 (T7 seam):** `aitm-core` exposes `FindingDraft`, `FindingRecorder`, and
   `CommandHost::{with_finding_recorder, finding_recorder}`; a default
   `CommandHost` returns `None` for `finding_recorder()`, one built with a
   recorder returns `Some`.
2. **AC2 (T7 impl):** `aitm-findings::DiskFindingRecorder::record(draft, dir)`
   writes a record that `DiskFindingStore::new(dir).get(id)` reads back with the
   draft's `title`, parsed `severity`, `target`, `finding_capture`, and
   `passed`.
3. **AC3 (T7 end-to-end):** a passing `poc.run` with `findings.dir` configured
   causes `findings.list` to return one summary whose `poc_ref` is the PoC's id
   and `passed` is `true`; the `poc.run` result carries `recorded_id` equal to
   that finding's id.
4. **AC4 (T7 opt-in):** the same `poc.run` with no `findings.dir` configured
   writes nothing (`findings.list` stays empty) and the result has no
   `recorded_id`.
5. **AC5 (T7 record-on-pass):** a failing `poc.run` (dir configured) records
   nothing.
6. **AC6 (T1):** a pure-`script:` PoC (no declarative `http:` step) whose script
   step captures a flow into the store and returns `Pass` completes without
   error and its `finding_capture` equals that captured flow's id.
7. **AC7 (T1 no-flow):** a PoC that captures no flow anywhere still fails with
   the existing `"no HTTP flow was captured to anchor the finding"` error.
8. **AC8 (T2 defaults):** a PoC with a `variables:` default `marker: MARK` run
   with no `--vars` lets a `script:` step read `vars.get("marker") == "MARK"`.
9. **AC9 (T2 override):** the same PoC run with `--vars marker=OVERRIDE` lets the
   script read `vars.get("marker") == "OVERRIDE"`.
10. **AC10 (T5):** `CdpSession::eval` succeeds (no `-32601`) when invoked without
    a preceding `navigate`; on a simulated stale-context error it retries once
    and returns the value. (Live-browser test may be `#[ignore]`d; a unit test
    covers the retry logic on a seam/double.)
11. **AC11 (T6):** after a `click` that triggers a navigation, `get_dom` returns
    the post-navigation document; a `click` that navigates nothing returns within
    the bound without erroring.
12. **AC12 (T9):** a `browser.*` host call runs under `browser_timeout`, not the
    hook remainder: with `hook_timeout` small and `browser_timeout` large, a
    browser host call that takes longer than `hook_timeout` but less than
    `browser_timeout` succeeds; a non-browser host call still aborts at the hook
    budget.
13. **AC13 (embedded core):** `scope.add` from `Frontend::Operator` succeeds with
    `allow_agent_widen = false`; from `Frontend::Mcp` it is still refused unless
    `allow_agent_widen` is set.
14. **AC14 (embedded app):** the generated embedded `Config.yaml()` emits
    `mcp.operator_token` and the embedded launch connects with the operator
    token (verified by `swift test` and the live embedded self-test; **not**
    cargo-gated).
15. **AC15 (docs):** the authoring guide documents the T4 (`await fetch`) and T8
    (`click` param / backslash-in-eval) guidance.

## Left to the builder

- The exact chromiumoxide call used to resolve/refresh the eval context and to
  await the post-click navigation (CDP `Page.navigate`/`frameStoppedLoading`/
  `wait_for_navigation` details).
- The precise `Services`/builder field names used to thread the recorder.
- Test-double shapes (a recording `FindingRecorder`, a flow-inserting script
  executor), as long as they prove the literal expected values.
- The default numeric value of `browser_timeout` if 30s proves wrong in review,
  within the same order of magnitude.

## Open questions

1. **T3 — agent `poc.run`.** Should an agent (`Frontend::Mcp`) ever run
   `poc.run`, and behind which gate (a `poc.allow_agent_run` config flag
   mirroring `allow_agent_authoring`/`allow_scope_add`)? Not designed here; left
   as a localized hook. Matt's ruling needed before any agent-run work.
2. **Record-on-pass vs always (T7).** This design records only on a passing
   `poc.run`. Confirm that failed runs should *not* appear in `findings.list`
   (a separate `runs.jsonl`-only history line is possible later if wanted).
3. **embedded-core-scope route.** Confirm the operator-token route (with the
   Task that lets `Frontend::Operator` call `scope.add`) over the cheaper
   `allow_agent_widen: true` one-block alternative.
