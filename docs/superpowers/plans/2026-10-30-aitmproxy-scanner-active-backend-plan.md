# Scanner active backend implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-30-aitmproxy-scanner-active-backend-design.md`
**Branch / worktree:** `claude/scanner-plugin-scope-6fa7ad`

## Overview

Extend the **shipped** `aitm-plugin-scanner` crate (PR #67) with the five
remaining verbs for v0.6: `scan.passive` + `scan.report` (Stage 2, Read),
`scan.inject` (Stage 3, Sensitive, agent-gated, egress-confined), and `scan.run` +
`scan.status` (Stage 4). **No `aitm-core` edit** — active confinement uses the
already-shipped `CommandHost::egress_handle()`; the agent gate reads the
already-shipped `ScannerConfig.allow_agent_active`; active requests ride the
already-shipped `PipelineClient::send` → `check_active` chokepoint.

Outside the scanner crate this plan edits only: the contract lists a new tool name
breaks — `crates/aitm/tests/frontends.rs` and the `aitm-tui` family
(`crates/aitm-tui/src/lib.rs` `CORE_TOOLS`, `crates/aitm-tui/fixtures/bus-fixture.json`,
`crates/aitm-tui/tests/tester_shell.rs`); two `defers_to_command_gate` arms in
`crates/aitm-mcp/src/server.rs` with their tests (`crates/aitm-mcp/tests/mcp.rs`, new
`crates/aitm/tests/scan_agent_gate.rs`); the new e2e tests `crates/aitm/tests/inject_e2e.rs`
and `crates/aitm/tests/scan_run_e2e.rs` (T12, T13); and, in the docs task,
`crates/aitm/tests/agent_surface.rs` and `agent/PLAYBOOK.md`. Inside the crate,
`Cargo.toml` gains `tracing` (T17).

The reproduce-and-record machinery is built once, in `reproduce.rs` (T4 → T16 → T17), and
reached through `campaign::run_class` (T9), which both `scan.inject` (T8) and `scan.run`
(T10) call. Engines return typed results and never build a `Value`; every result shape is
built in `commands.rs`, which the serial chain T6 → T7 → T8 → T10 owns (two writers never
share a file). Tests that are separate files fan out at the end.

**Wave 1 (T1, T2, T3) is already on `main` at `78405c3`**; it is summarised below, not
re-dispatched. T15 and T18 amend two of its files.

## Index

Paths beginning `crates/`, `agent/` or `/` are repo-root paths (`/Cargo.lock` is the
workspace lockfile); every other path is under `crates/aitm-plugin-scanner/`. "Contract
lists" = the files in Global constraints; "policy files" = `crates/aitm-mcp/src/server.rs`,
`crates/aitm-mcp/tests/mcp.rs`, `crates/aitm/tests/scan_agent_gate.rs`.

| Task | Wave | Depends on | Files |
|---|---|---|---|
| T1 passive | 1 shipped | — | `src/passive.rs` |
| T2 checks | 1 shipped | — | `src/checks.rs` |
| T3 report | 1 shipped | — | `src/report.rs` |
| T18 class registry (+ optional 3rd class) | 2 | T2 | `src/checks.rs` |
| T5 injector, `test_support` | 2 | T2 | `src/inject.rs`, `src/test_support.rs`, `src/lib.rs` |
| T15 report target filter | 2 | T3 | `src/report.rs` |
| T4 `build_poc` | 2 | T18 (part A); final merge after T5 (`lib.rs`) | `src/reproduce.rs`, `src/discover.rs`, `src/lib.rs` |
| T16 run/record blocks | 2 | T4, T5 | `src/reproduce.rs` |
| T17 `reproduce_and_record` | 2 | T16 | `src/reproduce.rs`, `Cargo.toml`, `/Cargo.lock` |
| T6 `ScanPassive` | 3 | T1, T5 | `src/commands.rs`, `src/plugin.rs`, contract lists |
| T7 `ScanReport` | 3 | T3, T15, T6 | `src/commands.rs`, `src/plugin.rs`, contract lists |
| T9 `campaign.rs` | 3 | T5, T15, T17 | `src/campaign.rs`, `src/lib.rs` |
| T8 `ScanInject` | 4 | T5, T9, T17, T18, T7; OQ6 | `src/commands.rs`, `src/plugin.rs`, contract lists, policy files |
| T10 `ScanRun` + `ScanStatus` | 4 | T9, T8; OQ6 | `src/commands.rs`, `src/plugin.rs`, contract lists, policy files |
| T11 passive e2e | 5 | T6 | `tests/passive_e2e.rs` |
| T12 inject e2e | 5 | T8 | `crates/aitm/tests/inject_e2e.rs` |
| T13 campaign e2e | 5 | T10 | `crates/aitm/tests/scan_run_e2e.rs` |
| T14 docs | 5 | T10 | `README.md`, `tests/readme.rs`, `agent/PLAYBOOK.md` (repo root), `crates/aitm/tests/agent_surface.rs` |

**Parallel:** T18 ∥ T5 ∥ T15 first; T4 starts once T18 part A lands, and T16 once **both**
T4 and T5 have landed; T6 → T7 ∥ T9; then T8 → T10; T11–T14 all ∥. **`lib.rs` order (Wave 2):** T5 lands
its `lib.rs` lines first (`pub mod inject;` and `#[cfg(test)] mod test_support;`); T4 then
adds `pub mod reproduce;` on top — T4's other work may proceed in parallel, only its final
merge waits for T5. The `aitm-mcp` half of T8 and T10 needs no scanner
code (its test uses a stub command named after the real one) but stays in the task: it
must land in the same merge as, or after, the command-side flag check, and before the
integration plan's Task 8.

**Open question 6 gates Tasks 8 and 10.** Matt's explicit answer to the spec's Open
question 6 is needed before either is dispatched. "Add" (the recommended default) means
the arms in this plan; no answer means the arms and the `All` policy-test arms are left
out (the fail-closed choice) and the AC21 `All` arms flip.

**Global constraints (every task):**

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test` passes before review (each "Done when" cites it). Default `cargo
  test` hermetic; browser-dependent tests start with the shipped runtime guard `if
  !rig::obscura_enabled() { return; }` (`AITM_OBSCURA` is an env var, not a cargo cfg — a
  `cfg_attr` would trip `unexpected_cfgs` and never run), so on the default gate they report
  `ok` without running.
- **TDD:** failing test first; the Coder's report shows both runs.
- **No `aitm-core` edits.** Only the shipped `aitm-plugin-scanner` crate, plus the
  exhaustive list above: the contract-list edits in Tasks 6, 7, 8 and 10 (`frontends.rs`
  and the `aitm-tui` family — the precedent is PR #67 commit `38a7c35`, which did exactly
  this for `scan.discover`); the `defers_to_command_gate` arms in Tasks 8 and 10 (a policy
  list in `crates/aitm-mcp/src/server.rs`, not an `aitm-core` type) with their tests; new
  tests under `crates/aitm/tests/`; and Task 14's doc/test edits. If a task finds it must
  edit an `aitm-core` type, it **stops and reports**. It must **not** edit
  `wire.rs`/`config_file.rs` for the `allow_agent_active` flag (integration plan D-MCP2
  owns that).
- **Reproduce + record (reached through `run_class`, T9; built in T4, T16, T17).** The PoC
  runs through `aitm_poc::StdPocRunner` on `reproduce::narrowed_host(host)` (every service
  kept, finding recorder and browser dropped), never through the `poc.run` command (a
  command cannot call a command) and never on the command's own host (that would add a
  second, runner-made record). The scanner records only via `DiskFindingStore`, never
  `host.finding_recorder()`; only a passing replay is recorded; every production record
  has `control_passed: None`; a per-confirmation failure is an `unreproduced` entry,
  never a `?` out of the call.
- **No identifiable credential persists, no error text forwarded.** No credential the
  scanner can identify reaches the PoC YAML, a stored record, `runs.jsonl`, or any result
  (spec "Building the PoC" and "What is guaranteed, and what is not", AC24 including its
  labelled accepted-limit row; fixtures use the literal `abc123`), and every
  `unreproduced[].reason` is one of the constants in the spec's "Failure handling" —
  runner, templater and build-refusal text is never forwarded.
- **No unread fields.** A command struct holds only fields its `invoke` reads, and every
  non-`pub` struct field is read somewhere: an unread field fails `cargo clippy -- -D
  warnings` at the task that adds it (`ScanPassive` and `ScanReport` are unit structs;
  `ScanInject` and `ScanRun` read `cfg`; `ScanRun` and `ScanStatus` read the shared status
  slot).
- **Bounded.** One deadline per call, computed with `inject::deadline_after`; every
  injection send and every replay runs inside `inject::bounded` (`timeout(min(remaining,
  60 s))`), a rate-limit refusal goes through `inject::wait_out_rate_limit` (at most
  `MAX_RATE_LIMIT_WAITS` consecutive refusals), and a timeout counts as `time_budget` only
  when it fires at or after the deadline; remaining time and budgets use
  `saturating_duration_since` / `checked_sub` (spec Constraints, "A failed send never
  discards what was found"). `inject`'s up-front scope gate is the read-only
  `host.guard().in_scope(authority)`, which takes no rate token. Timing tests use a
  deadline of at least 200 ms against a 2–5 s slow response.
- **Shared test support (T5).** `src/test_support.rs` (`#[cfg(test)]`) holds the stub
  clients, counting recorder and temp-dir helper; later tasks only `use` it. A helper a
  later task needs that is not there is defined in that task's own test module, never
  added to the shared file.
- **Contract lists (every command-registration task: 6, 7, 8, 10).** In the same task
  that registers a command: bump `EXPECTED_TOOLS` in `crates/aitm/tests/frontends.rs`;
  add the name to `CORE_TOOLS` in `crates/aitm-tui/src/lib.rs`; add a fixture entry
  shaped like `scan.discover`'s to `crates/aitm-tui/fixtures/bus-fixture.json`; bump the
  two `tools.len()` pins in `crates/aitm-tui/tests/tester_shell.rs` (`fixture_app_core…`
  and the `fixture_app(200, 50)` assertion). Without these, `tui_live_bus.rs` and
  `tester_shell.rs` fail the workspace gate. Running counts: `EXPECTED_TOOLS` 56 → 57
  (T6) → 58 (T7) → 59 (T8) → 61 (T10); TUI pins 59 → 60 → 61 → 62 → 64. Two doc comments
  that still say "59 commands" (`crates/aitm-tui/tests/tester_shell.rs:924` and
  `crates/aitm-tui/src/lib.rs:221`) are cosmetic and no assertion reads them: T10, the last
  registration, updates both to 64; T6–T8 leave them.
- **Citations.** Code references in this plan are to `main` at `78405c3`, by file and
  symbol.
- **Extend, don't reinvent:** build on the shipped `ScannerConfig`,
  `enumerate`/`InjectionPoint`/`Location`, `crawl`/`normalize_url`/`block_on`,
  `egress_handle`, and the `aitm-poc`/`aitm-findings` seams.
- Declared signatures are authoritative; bodies and private layout are the builder's.

---

## Tasks

### Stage 2 — passive + report (Read). Satisfies AC1–AC4.

### Tasks 1–3: Wave 1, shipped on `main` at `78405c3` (not re-dispatched)

| Task | File (under `crates/aitm-plugin-scanner/src/`) | Shipped API | Satisfies | Shipped tests |
|---|---|---|---|---|
| T1 | `passive.rs` | `PassiveFinding { class, flow, location, name, evidence, severity }`, `passive_checks(&HttpFlow) -> Vec<PassiveFinding>` (reflection, security-header, cookie-flag; `evidence` never carries a value) | AC1, AC3 | `passive_flags_reflection`, `passive_flags_missing_csp`, `passive_flags_insecure_cookie`, `passive_evidence_has_no_value` (+ more) |
| T2 | `checks.rs` | `AttackMode`, `Payload`, `Evidence`, `CheckDefinition { class, locations, payloads, mode }` with `confirm`, `reflected_xss()`, `open_redirect()`, `for_class` | AC5 (definition), AC6 | `reflected_xss_confirms_on_unencoded_reflection`, `open_redirect_confirms_only_on_redirect_to_sentinel_location`, `for_class_known`, `payloads_within_configured_cap` |
| T3 | `report.rs` | `load_records(host, Option<&str>) -> Vec<FindingRecord>` (empty without `findings.dir`), `index_to_value(serde_json::Value) -> Value` | AC4 (read half) | `load_records_empty_without_dir`, `load_records_filters_by_target`, `index_to_value_maps_every_variant`, `index_to_value_maps_nested_containers` |

### Task 15: `scan.report` target filter (`report.rs`) — Wave 2, independent

- **Satisfies:** AC4 (the `target` argument), AC32 (report half).
- **Depends on:** Task 3 (shipped).
- **Files:** `crates/aitm-plugin-scanner/src/report.rs` (modify). Nothing else.
- **Change:** `FindingFilter.target` is an exact string match, so it cannot relate a
  campaign base URL (`http://t.test:8080`) to a recorded endpoint
  (`http://t.test:8080/search`). Add
  ```rust
  pub(crate) fn target_matches(filter: &str, record_target: &str) -> bool;
  ```
  and make `load_records` list with `FindingFilter::default()`, then keep a record only
  when `target` is `None` or `target_matches(target, &record.target)`. Rule (spec
  "`scan.report`"): both strings parse as absolute URLs (`url::Url`) with the same
  scheme, host and effective port (`port_or_known_default`), and the record's path
  equals the filter's path or extends it on a `/` boundary, after removing one trailing
  `/` from the filter path (so an empty or `/` filter path matches every path); query and
  fragment ignored. If the filter does not parse as an absolute URL, match only on exact
  string equality. A URL that parses but has no host (`mailto:a`, `javascript:x`), on either
  side, never matches and never panics.
- **Test:** `target_matches_table` asserts, literally, `target_matches(filter, record)`:
  (`http://t.test:8080`, `http://t.test:8080/search`) → `true`;
  (`http://t.test:8080/`, `http://t.test:8080/a/b`) → `true`;
  (`http://t.test:8080/search`, `http://t.test:8080/search`) → `true`;
  (`http://t.test:8080/search`, `http://t.test:8080/searchx`) → `false`;
  (`http://t.test:8080/search`, `http://t.test:8080/other`) → `false`;
  (`http://t.test:8080`, `http://t.test:9090/search`) → `false`;
  (`http://t.test`, `http://t.test:80/search`) → `true`;
  (`https://t.test`, `http://t.test/search`) → `false`;
  (`http://t.test:8080/search?x=1`, `http://t.test:8080/search`) → `true`;
  (`not a url`, `not a url`) → `true`; (`not a url`, `http://t.test/`) → `false`;
  hostile shapes: (`http://T.TEST:8080`, `http://t.test:8080/search`) → `true` (host
  case); (`http://t.test:8080/search/`, `http://t.test:8080/search`) → `true` and
  (`http://t.test:8080/search/`, `http://t.test:8080/search/x`) → `true` (trailing
  slash); (`http://t.test/a`, `http://t.test/a/../b`) → `false` (dot-segments resolve to
  `/b`); (`http://t.test/a`, `http://t.test/a%2Fb`) → `false` (`%2F` is not a boundary);
  (`http://u:p@t.test:8080/search`, `http://t.test:8080/search`) → `true` (userinfo
  ignored); (`http://[::1]:8080`, `http://[::1]:8080/search`) → `true` and
  (`http://[::1]:8080`, `http://[::2]:8080/search`) → `false` (IPv6).
  `load_records_matches_endpoint_records_by_base` records `http://t.test:8080/search`
  and `http://other.test:8080/search` in a temp `DiskFindingStore` and asserts
  `load_records(host, Some("http://t.test:8080"))` returns exactly the first.
  `target_matches_hostless_urls_never_match`: (`mailto:a`, `mailto:a`) → `false`,
  (`javascript:x`, `http://t.test/`) → `false`, (`http://t.test`, `mailto:a`) → `false`, none
  panics. The shipped `load_records_filters_by_target` must still pass unchanged.
- **Done when:** the three new tests pass (each shown failing first), the shipped tests still
  pass, and the full gate passes.

### Task 6: `scan.passive` command — Wave 3, serial (command chain 1/4)

- **Satisfies:** AC2, AC3, AC13 (no prompt), AC18 (contract, partial).
- **Depends on:** Task 1; Task 5 (`inject::target_flows`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanPassive`), `plugin.rs` (modify — register), `crates/aitm/tests/frontends.rs`
  (modify — `EXPECTED_TOOLS` 56 → 57, add `"scan.passive"`),
  `crates/aitm-tui/src/lib.rs` (modify — add `"scan.passive"` to `CORE_TOOLS`),
  `crates/aitm-tui/fixtures/bus-fixture.json` (modify — add a `scan.passive` entry with an
  optional `target` string property), `crates/aitm-tui/tests/tester_shell.rs` (modify —
  both pins 59 → 60).
- **Change:** `ScanPassive` (a unit struct, like `ScanReport`: `invoke` reads no config —
  the result cap is the file-private `MAX_RESULT_ITEMS` — and a never-read `cfg` field would
  fail `cargo clippy -- -D warnings` at this task's gate; `plugin.rs` registers it with
  `Arc::new(ScanPassive)`) impl `Command`: `name()=="scan.passive"`, `sensitivity()==Sensitivity::Read`,
  `confirm_prompt()==None`, `schema()` with optional `target: Str`. `invoke` runs
  `passive_checks` over `inject::target_flows(host, target)` and returns
  `passive_value(&findings)`. No `client().send`, no `browser()`. This task also writes
  two `pub(crate)` shaping helpers in `commands.rs` that `ScanRun` reuses (spec "`scan.run`"):
  ```rust
  pub(crate) fn passive_value(findings: &[crate::passive::PassiveFinding]) -> Value;
  pub(crate) fn discover_value(host: &CommandHost<'_>,
      outcome: &crate::crawl::CrawlOutcome) -> Value;
  ```
  `passive_value` is `Value::Object { "findings": Array[ {class, flow, location, name,
  evidence, severity} ] }`, every string through `aitm_core::redact::scrub_text`, the array
  capped at the file-private `MAX_RESULT_ITEMS`. `discover_value` is the result building
  of `ScanDiscover::invoke`, extracted unchanged (a pure refactor; every shipped
  `scan_discover_*` and `discover_*` test passes untouched).
- **Test:** `scan_passive_is_read` asserts `sensitivity() == Read` and
  `confirm_prompt(&empty).is_none()`. `scan_passive_issues_no_traffic` records
  `host.store().count()` before/after `invoke` and asserts it is unchanged.
  `scan_passive_finds_reflection` seeds a reflecting flow and asserts the result
  `findings` contains a `reflection` entry naming `q`. `scan_passive_redacts` (AC3) seeds
  AC3's literal fixture — `Cookie: PHPSESSID=abc123`, `Authorization: Bearer abc123`,
  `?access_token=abc123`, plus a reflected `?q=abc123` — and asserts no `abc123` anywhere in
  the result (the engine-level twin is the shipped `passive_leaks_no_secret`).
  `scan_tools_have_non_empty_input_schemas` (AC18; new, in `crates/aitm/tests/frontends.rs`;
  it iterates whatever `scan.*` tools the proxy lists, so Tasks 7, 8 and 10 do not edit it):
  over the assembled proxy's `tools/list`, every `scan.*` tool's `inputSchema` is a JSON
  object whose `properties` is a non-empty object, and it first asserts that at least
  `scan.discover` and `scan.passive` are listed (so it fails first while `scan.passive` is
  unregistered and passes once this task registers it; for Tasks 7, 8 and 10 it is a guard
  test shown passing) (`ac7_exact_tool_set` snapshots
  schemas only for `browser.*` and the operator tools). The three existing contract tests are `ac7_exact_tool_set`
  (`frontends.rs`), `tui_bus_task_runs_against_the_live_loopback_server` (`tui_live_bus.rs`)
  and `fixture_app_core_offers_exactly_the_core_tools_with_the_agent_surface_lit`
  (`tester_shell.rs`); they are shown failing first — with only the command registered,
  `tui_live_bus.rs` fails with "live tool `scan.passive` is missing from aitm_tui::CORE_TOOLS"
  and `ac7_exact_tool_set` fails on the exact set — then passing with the edits above (pins
  literally `60`, `57`). Inside the Claude sandbox `tui_live_bus.rs` takes its
  `PermissionDenied` skip path (it prints a note and returns), so that failing-first step is
  only meaningful in the Terminal panel.
- **Done when:** the tests pass, `frontends.rs`, `tui_live_bus.rs` and `tester_shell.rs`
  pass, the shipped `scan.discover` tests pass unchanged after the `discover_value`
  extraction, and the full gate passes.

### Task 7: `scan.report` command — Wave 3, serial (command chain 2/4)

- **Satisfies:** AC4, AC13 (no prompt), AC18 (contract, partial).
- **Depends on:** Task 3; Task 15 (the target filter); **Task 6** (shares
  `commands.rs`/`plugin.rs`/the contract lists).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanReport`), `plugin.rs` (modify), `crates/aitm/tests/frontends.rs` (modify —
  `EXPECTED_TOOLS` 57 → 58, add `"scan.report"`), `crates/aitm-tui/src/lib.rs` (modify —
  `CORE_TOOLS`), `crates/aitm-tui/fixtures/bus-fixture.json` (modify — a `scan.report`
  entry), `crates/aitm-tui/tests/tester_shell.rs` (modify — pins 60 → 61).
- **Change:** `ScanReport` (a unit struct) impl `Command`: `name()=="scan.report"`,
  `sensitivity()==Read`, `confirm_prompt()==None`, `schema()` optional `target`.
  `invoke` = `report_value(&report::load_records(host, target))`, where this task also
  writes the shared helper
  ```rust
  pub(crate) fn report_value(recs: &[aitm_findings::FindingRecord]) -> Value;
  ```
  = `Value::Object { "report_md": Str(render_report(recs)), "index":
  report::index_to_value(render_index(recs)) }` (arrays capped at 1024); `ScanRun` reuses it.
- **Test:** `scan_report_is_read` asserts `sensitivity() == Read` and
  `confirm_prompt(&empty).is_none()` (AC13).
  `scan_report_one_section_per_finding` writes N records to a temp
  `DiskFindingStore`, wires it via `host.config()` findings dir, and asserts
  `report_md` contains N `"## "` section headers and `index` is an `Array` of N
  objects each carrying `poc_path`/`class`/`passed`. `scan_report_target_selects_endpoint_records`
  stores a record with `target == "http://t.test:8080/search"` and asserts
  `index.len() == 1` for `{target: "http://t.test:8080"}` and `0` for
  `{target: "http://other.test:8080"}`.
- **Done when:** tests pass, the contract tests pass (pins `61`, `58`), full gate passes.

---

### Stage 3 — active injection, reproduce, record (Sensitive, gated). AC5–AC13, AC20–AC34.

### Task 4: PoC builder (`build_poc` in `reproduce.rs`) — Wave 2, reproduce chain 1/3

- **Satisfies:** AC10 (build half), AC11 and AC24 (no identifiable credential in the PoC), AC29
  (template-metacharacter half).
- **Depends on:** Task 18 part A (`registered_classes()`, and `success_assertion` owning the
  open-redirect 3xx clause); Task 5 (its `lib.rs` lines land first).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (create),
  `crates/aitm-plugin-scanner/src/discover.rs` (modify — `fn is_secret_name` becomes
  `pub(crate) fn is_secret_name`; visibility only, no behaviour change), `lib.rs` (modify —
  `pub mod reproduce;`). Nothing else; no `aitm-core` edit, no new dependency.
- **Change** (behaviour per spec "Building the PoC"; signatures are authoritative):
  ```rust
  pub struct BuiltPoc { pub poc: aitm_poc::Poc, pub bindings: aitm_poc::VarBindings }
  pub enum BuildRefused { Credential, Template }  // impl Display + std::error::Error:
      // "build refused: credential" / "build refused: template", never a value
  pub fn build_poc(attack_flow: &aitm_core::HttpFlow,
      def: &crate::checks::CheckDefinition,
      point: &crate::discover::InjectionPoint, payload: &crate::checks::Payload)
      -> Result<BuiltPoc, BuildRefused>;
  const POC_EXTRA_NEEDLES: &[&str];   // key, sig, code, pass, pw, otp, pin
  fn severity_for(class: &str) -> Option<aitm_poc::Severity>;  // keyed by the CLASS_* consts
  ```
  Real field lists, because neither type has `Default`: `PocInfo { name, severity,
  references: vec![], tags: vec![class], cwe: None, description: None, author: None,
  metadata: None }`; `Variable { name, default: None, description: <non-empty fixed
  String>, required: true }`. `build_poc` is fed the attack flow, calls
  `StdPocBuilder::default().build(attack_flow, spec)` with `success =
  def.success_assertion(payload)` unchanged, then post-processes the `Step::Http`: the
  credential placeholders, the refusals and the `scrub_text` backstop exactly as the spec
  specifies (credential match is case-insensitive after percent-decoding, over
  `discover::is_secret_name` plus `POC_EXTRA_NEEDLES`; query/form values are bound raw;
  the backstop runs on the URL, each header value and the body with the builder's own
  placeholders removed; `{{` refuses, a lone `}}` does not). `severity_for` returns `None`
  for an unmapped class and `build_poc` uses `Info` then. `StdPocBuilder::build` returns
  `anyhow::Result<Poc>` (always `Ok` today): any `Err` maps to
  `BuildRefused::Credential`, never an `unwrap`.
- **Test** (hermetic; attack flows are hand-built `HttpFlow`s with authority
  `127.0.0.1:8080`, scheme `http`; inspect the `Step::Http` fields `url`, `headers`, `body`
  and `poc.variables` directly — no YAML serialiser is needed):
  - `build_poc_reflected_xss_success_is_the_marker_word`: for `GET
    /search?q=<aitm-canary-0001>` and `def.payloads[0]`, `built.poc.success ==
    Assertion::Word { word: "<aitm-canary-0001>".into(), part: MatchPart::Body }`, the
    single `Step::Http` URL starts with `{{target}}`, and `built.bindings.get("target") ==
    Some(&Value::Str("http://127.0.0.1:8080".into()))`.
  - `build_poc_open_redirect_success_is_the_confirm_assertion`: `built.poc.success ==
    def.success_assertion(payload)`, and it is an `Assertion::All` whose first element is
    literally `Assertion::Any(vec![Status(301), Status(302), Status(303), Status(307),
    Status(308)])` and whose second is an `Assertion::Regex { part: MatchPart::Header, regex }`
    with `regex.contains("aitm-scan-sentinel")`.
  - `build_poc_info`: `poc.info.severity == Severity::Medium` for reflected-XSS and
    `Severity::Low` for open-redirect; `poc.info.tags == vec!["reflected-xss"]`;
    `poc.info.name == "reflected-xss: q"`. `severity_mapping_covers_every_registered_class`:
    `severity_for(c).is_some()` for every `c` in `registered_classes()`.
  - `build_poc_binds_the_placeholder_rows` (AC24 rows 1-9, the *Recorded* rows): for each
    row of the spec's table, the step's URL / header / body contains the placeholder and
    not the secret, the matching `Variable` has `required == true` and `default ==
    None`, and `built.bindings` holds the original raw value (`Bearer abc123` for row 3;
    `correct%20horse`, still encoded, for row 7; the decoded key `access_token` names the
    variable for row 6).
  - `build_poc_refuses_the_refused_rows` (AC24 rows 10-16): each returns
    `Err(BuildRefused::Credential)` whose `to_string()` is exactly `build refused:
    credential`; additionally a multipart body (`Content-Type: multipart/form-data;
    boundary=x`, non-empty), a `text/plain` non-empty body and a JSON-array body each return
    `Err(BuildRefused::Credential)`.
  - `build_poc_accepts_the_labelled_limit` (AC24 row 17): the nested `{"card":{"pin":"q7x9k2"},
    "q":"x"}` body builds `Ok` and the step body still contains `q7x9k2` — the documented
    undetected case (spec Open question 11), asserted so the limit stays honest.
  - `build_poc_substitutes_the_payload_in_a_body` (AC10): a form-urlencoded injection point
    (`POST`, body `q=<aitm-canary-0001>&page=1`) yields a step body containing `q={{payload}}`
    and not `<aitm-canary-0001>`; a JSON body injection point (`{"n":1,"q":"<aitm-canary-0001>"}`)
    yields a step body containing `"q":"{{payload}}"` and not the marker; in both, the
    `payload` variable's default is the raw payload text (the injector sends payloads raw —
    they are wire-safe, Task 18).
  - `build_poc_refuses_template_syntax`: a header `X-Note: {{rand_text_alpha(8)}}`, a header
    *name* `X-{{x}}`, a URL path containing `{{x}}` and a form body `a={{x}}` each return
    `Err(BuildRefused::Template)` whose text is exactly `build refused: template`; a body
    `{"a":{"b":1}}` (a lone `}}`) builds `Ok`.
  - `build_poc_sanitises_the_param_name`: a query parameter named `"a".repeat(200)` builds,
    `aitm_poc::runner::is_valid_poc_id(&poc.id)` is `true`, and `poc.info.name` starts
    with `reflected-xss: ` and contains only `[A-Za-z0-9_.: -]`.
  - `build_poc_keeps_the_payload_in_a_secret_named_point`: an injection point named
    `token` yields a URL containing `token={{payload}}`, no `token` variable, and no
    `token` entry in `bindings`.
  - `build_poc_never_panics_on_hostile_shapes`: a non-UTF-8 body, duplicate query keys,
    an invalid percent-encoding (`%zz`, a trailing `%`), a 100 000-byte parameter value and
    a 200-character header name each return `Ok` or `Err` without panicking, and every
    `Ok` has a valid PoC id.
- **Done when:** the twelve tests pass (each shown failing first) and the full gate passes.

### Task 16: reproduce building blocks (`narrowed_host`, `reproduce`, `finding_record`, `record_finding`) — Wave 2, reproduce chain 2/3

- **Satisfies:** AC22 (the runner's auto-record is inert), AC24 (in-memory binding), AC32
  (record target), AC33 (the replay is guarded), AC10 (record half).
- **Depends on:** Task 4 (same file; uses `BuiltPoc`); Task 5 (`test_support.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify). Nothing else: every
  `CommandHost` accessor and builder `narrowed_host` needs already exists
  (`crates/aitm-core/src/ctx.rs`), so there is no `aitm-core` edit.
- **Change** (behaviour per spec "Reproduce → record", "Running the PoC", "When a record is
  written", "Record target"; signatures are authoritative):
  ```rust
  pub(crate) fn narrowed_host<'a>(host: &'a aitm_core::CommandHost<'_>)
      -> aitm_core::CommandHost<'a>;
  pub async fn reproduce(host: &aitm_core::CommandHost<'_>, built: &BuiltPoc)
      -> anyhow::Result<aitm_poc::PocRunResult>;
  pub fn finding_record(host: &aitm_core::CommandHost<'_>,
      def: &crate::checks::CheckDefinition, attack_flow: &aitm_core::HttpFlow,
      poc: &aitm_poc::Poc, run: &aitm_poc::PocRunResult)
      -> aitm_findings::FindingRecord;
  pub fn record_finding(host: &aitm_core::CommandHost<'_>,
      rec: aitm_findings::FindingRecord) -> anyhow::Result<String>;
  ```
  `narrowed_host` rebuilds the host from `store()`, `client()`, `guard()` and carries
  `frontend()`, `ssrf_policy()` (cloned), `poc_dir()`, `client_label()`, `egress_handle()`
  and `config()` (cloned into a fresh `Arc` via `with_config`), with **no finding recorder
  and no browser**. `reproduce` runs `built.poc` through `aitm_poc::StdPocRunner` on
  `narrowed_host(host)` with `built.bindings`, output directory as `run_poc_command` chooses
  it; exactly one request; no `poc.allow_agent_run` gate. `finding_record` builds the record
  directly (`target` = the attack request's `scheme://authority/path`, no query, fragment or
  userinfo, through `scrub_text`, markdown-active characters `[ ] ( ) ! < > *` and backtick
  percent-encoded; `control_passed: None`; `flows = [attack_flow.id, run.finding_capture]`
  deduplicated). `record_finding` persists through `DiskFindingStore::new(dir)` from
  `findings.dir`, `Err` with no dir, and never calls `host.finding_recorder()`.
- **Test** (hermetic; uses `test_support`: a reflecting stub client that inserts its flow into
  the store and counts calls, a temp dir for `findings.dir` and one for `poc.out_dir`, the
  counting `FindingRecorder`):
  - `narrowed_host_keeps_services_and_drops_recorder`: the outer host is built with a stub
    browser (a minimal `BrowserDriver` defined in this task's test module, passed as
    `CommandHost::new(.., Some(&stub_browser))`) so that `browser().is_none()` can fail, plus `.with_frontend(Frontend::Operator)`, `.with_ssrf(SsrfPolicy { block_private:
    false, block_loopback: false, allow_if_in_scope: false })`, `.with_egress(..)`,
    `.with_config(..)` (`findings.dir = tmp`), `.with_client_label("lab")`,
    `.with_poc_dir(Some(pocdir))`, `.with_finding_recorder(&counting)`; the narrowed host has
    `frontend() == Operator`, `ssrf_policy().block_private == false`,
    `ssrf_policy().allow_if_in_scope == false`, `egress_handle().is_some()`,
    `config().unwrap().findings.dir == Some(tmp)`, `client_label() == Some("lab")`,
    `poc_dir() == Some(pocdir.as_path())`, `finding_recorder().is_none()`,
    `browser().is_none()`.
  - `reproduce_is_guarded_by_the_real_client` (AC33): host over a real
    `PipelineClient::new(store, Arc::new(StdGuard::default()) /* empty scope */, counting_sender)`
    (`counting_sender` is `test_support`'s `CountingSender`);
    `reproduce(..)` returns `Err` whose `downcast_ref::<GuardError>()` is
    `Some(&GuardError::OutOfScope("127.0.0.1:8080".into()))`, and the sender saw `0` requests.
  - `reproduce_does_not_auto_record` (AC22): outer host with `findings.dir = tmp` **and**
    `.with_finding_recorder(&counting)`; after `reproduce(..)`: `run.passed == true`,
    `run.recorded_id == None`, `counting.calls() == 0`, the stub client saw exactly `1` request.
  - `reproduce_binds_credentials_in_memory` (AC24): an attack flow carrying `Authorization:
    Bearer abc123` and `Cookie: PHPSESSID=abc123`: `run.passed == true`; the file at
    `run.poc_path` contains `{{authorization}}` and `{{cookie}}` and not `abc123`; the stub
    saw the request carry `Authorization: Bearer abc123`.
  - `finding_record_fields`: for an attack flow `GET
    http://127.0.0.1:8080/search?q=<aitm-canary-0001>` and a passing `PocRunResult`:
    `rec.target == "http://127.0.0.1:8080/search"`, `rec.class == "reflected-xss"`,
    `rec.severity == Severity::Medium`, `rec.title == "reflected-xss: q"`,
    `rec.reproduction.passed == true`, `rec.reproduction.control_passed == None`,
    `rec.flows == vec![attack_flow.id, run.finding_capture]`.
  - `finding_record_target_has_no_query`: an attack request path `/search?access_token=abc123#f`
    yields `rec.target == "http://127.0.0.1:8080/search"`, and `rec.title` and `rec.target` do
    not contain `abc123`.
  - `finding_record_target_encodes_markdown_characters`: an attack request path
    `/a[b](c)!<d>*` yields a `rec.target` containing none of `[ ] ( ) ! < > *`, each present
    as its `%XX` form; a path `/my_account` is left unchanged.
  - `record_finding_writes_one_record_and_one_runs_line`: after `record_finding(..)`,
    `DiskFindingStore::new(tmp).list(&FindingFilter::default()).len() == 1`, `runs.jsonl` has
    exactly `1` line, and `counting.calls() == 0`.
  - `record_finding_without_dir_errors`: a host with no `findings.dir` → `Err`, and no file
    is created.
- **Done when:** the nine tests pass (each shown failing first) and the full gate passes.

### Task 17: `reproduce_and_record` (`reproduce.rs`) — Wave 2, reproduce chain 3/3

- **Satisfies:** AC10, AC11, AC12 (zero budget), AC22, AC25 (unit), AC28, AC29, AC30, AC34 (vi).
- **Depends on:** Task 16 (same file); Task 5 (`inject::wait_out_rate_limit`, via Task 16).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify),
  `crates/aitm-plugin-scanner/Cargo.toml` (modify — add `tracing = { workspace = true }`,
  the crate's only new dependency, used only here for a fixed-tag `tracing::debug!` line) and
  the `/Cargo.lock` entry that follows. Nothing else.
- **Change** (behaviour per spec "One owner"; the eight steps and the constant reasons are
  defined there, not repeated here):
  ```rust
  #[derive(Debug, Clone, PartialEq)]
  pub enum ReproOutcome {
      Recorded { finding_id: String },
      Unreproduced { reason: &'static str },   // one of the spec's constants, by type
      NoFindingsDir,                           // nothing sent, nothing recorded
      BudgetExhausted,                         // nothing sent, nothing recorded
  }
  pub async fn reproduce_and_record(host: &aitm_core::CommandHost<'_>,
      def: &crate::checks::CheckDefinition, point: &crate::discover::InjectionPoint,
      payload: &crate::checks::Payload, attack_flow: &aitm_core::HttpFlow,
      budget: &mut usize, deadline: std::time::Instant) -> ReproOutcome;
  ```
  Never returns an error; the budget decrement is `checked_sub` immediately before
  `reproduce`. A refused build maps by variant (`build refused: credential` / `build refused:
  template`); a `reproduce` `Err` whose root `downcast_ref::<GuardError>()` is
  `RateLimited { retry_after }` is waited out with `inject::wait_out_rate_limit(retry_after,
  deadline)` and retried (no budget charge; `Unreproduced("time_budget")` if the deadline
  passes while waiting, `Unreproduced("replay failed")` after `MAX_RATE_LIMIT_WAITS`
  consecutive refusals), `OutOfScope` or `PrivateAddressBlocked` is `replay blocked: out of
  scope`, any other is `replay failed`; a failed record is `record failed`. The single
  `tracing::debug!` line carries only a fixed tag (the `GuardError` variant name,
  `runner_error` or `record_error`), never error text. Reached through `campaign::run_class`
  (Task 9), which wraps the call in `inject::bounded`. In the tests below `deadline` is `now
  + 60 s` unless stated (T5's `deadline_after(60 s)` helper).
- **Test** (same hermetic fixtures as Task 16; fixtures take the budget by `&mut usize`):
  - `records_once_and_decrements_budget` (AC10, AC22): reflecting stub, `findings.dir = tmp`,
    counting recorder wired, `budget = 5` → `Recorded { .. }`, `budget == 4`, the store holds
    exactly `1` record with `reproduction.passed == true` and `reproduction.control_passed ==
    None`, `counting.calls() == 0`.
  - `failed_reproduction_is_not_recorded` (AC30): a stub whose replay response does not
    reflect → `Unreproduced { .. }`, `budget == 4` from `5`, the store holds `0` records, and
    `runs.jsonl` does not exist.
  - `no_findings_dir_skips_without_sending` (AC28): a host with no `findings.dir` →
    `NoFindingsDir`, the stub saw `0` requests, `budget == 5` unchanged.
  - `zero_budget_does_not_wrap` (AC12, AC25): a configured `findings.dir` (without one the
    outcome is `NoFindingsDir`, ordered first) and `budget = 0` → `BudgetExhausted`,
    `budget == 0` afterwards, the stub saw `0` requests.
  - `build_refusal_is_isolated_and_free` (AC29): an attack flow with a header `X-Note: {{x}}`
    → `Unreproduced { reason }` with `reason == "build refused: template"`, `budget == 5`
    unchanged, the stub saw `0` requests.
  - `record_error_is_isolated` (AC29): `findings.dir` set to a path beneath a regular file
    (it cannot be created) → `Unreproduced { reason }` with `reason == "record failed"`,
    `budget == 4`.
  - `replay_error_text_never_reaches_the_reason` (AC29): a stub whose replay send fails with
    `anyhow!("boom password=hunter2 horse")` → `reason == "replay failed"`, `budget == 4`; and
    a stub failing with `GuardError::OutOfScope("h".to_string())` → `reason == "replay
    blocked: out of scope"`.
  - `replay_waits_out_rate_limit` (AC34 vi): a `Scripted` stub whose first replay call is
    `Err(GuardError::RateLimited { retry_after: 20 ms })` and whose later calls reflect,
    `findings.dir = tmp`, `budget = 5` → `Recorded { .. }`, the stub was called exactly `2`
    times, `budget == 4` (charged once), the store holds exactly `1` record; with `deadline`
    already passed the same stub yields `Unreproduced { reason: "time_budget" }`; a stub that
    answers `RateLimited { retry_after: 1 ms }` ten times in a row yields `Unreproduced {
    reason: "replay failed" }` after exactly `10` calls.
- **Done when:** the eight tests pass (each shown failing first) and the full gate passes.
  (The AC24 table is proven once, at the command level, by Task 8's
  `inject_leaks_no_credential_anywhere`.)

### Task 5: injector + correlator engine (`inject.rs`) — Wave 2, independent

- **Satisfies:** AC6 (engine), AC8 (out-of-scope), AC12 (budget), AC26 (i, ii), AC27 (inject
  half), AC34 (i–iv).
- **Depends on:** Task 2 (`CheckDefinition`); uses shipped `enumerate` + `client()`.
- **Files:** `crates/aitm-plugin-scanner/src/inject.rs` (create),
  `crates/aitm-plugin-scanner/src/test_support.rs` (create, `#[cfg(test)]`), `lib.rs` (modify
  — `pub mod inject;` and `#[cfg(test)] mod test_support;`).
- **Change** (behaviour per spec "`scan.inject`", including its send-result table and the
  Constraints time bound; signatures are authoritative):
  ```rust
  pub const MAX_CONFIRMED: usize = 1024;
  pub const MAX_RATE_LIMIT_WAITS: usize = 10;  // consecutive RateLimited waits, no send between
  #[derive(Debug)]
  pub struct InjectOutcome { pub class: String, pub tested: usize,
      pub confirmed: Vec<Confirmed>, pub skipped: usize, pub send_errors: usize,
      pub stopped_reason: Option<&'static str> }   // a fixed constant, by type
  #[derive(Debug)]
  pub struct Confirmed { pub injection_point: crate::discover::InjectionPoint,
      pub payload: crate::checks::Payload, pub evidence: String,
      pub attack_flow: aitm_core::HttpFlow }   // `send`'s flow, `response` set to None
  pub async fn inject(host: &aitm_core::CommandHost<'_>, target: &str,
      def: &crate::checks::CheckDefinition,
      points: &[crate::discover::InjectionPoint], budget: &mut usize,
      cfg: &crate::ScannerConfig, deadline: std::time::Instant)
      -> anyhow::Result<InjectOutcome>;
  pub fn target_flows(host: &aitm_core::CommandHost<'_>, target: Option<&str>)
      -> Vec<aitm_core::HttpFlow>;
  pub fn class_points(flows: &[aitm_core::HttpFlow],
      def: &crate::checks::CheckDefinition) -> Vec<crate::discover::InjectionPoint>;
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct TimedOut { pub at_deadline: bool }
  pub fn deadline_after(budget: std::time::Duration) -> std::time::Instant;
  pub async fn bounded<T>(deadline: std::time::Instant,
      fut: impl std::future::Future<Output = T>) -> Result<T, TimedOut>;
  pub async fn wait_out_rate_limit(retry_after: std::time::Duration,
      deadline: std::time::Instant) -> bool;
  ```
  `deadline_after(budget)` is `Instant::now().checked_add(budget)`, falling back to a
  far-future instant on overflow (saturating, never a panic); Tasks 8 and 9 call it instead of
  re-deriving the deadline. `bounded` runs `fut` under `tokio::time::timeout(min(remaining,
  60 s))`, `remaining = deadline.saturating_duration_since(now)`; `TimedOut.at_deadline` is true
  when the deadline had been reached when it fired (false when only the 60 s cap fired).
  `wait_out_rate_limit` sleeps `min(retry_after, remaining)` and returns `true`, or returns
  `false` without sleeping once the deadline has passed. Both are shared with `reproduce_and_record`
  (Task 17) and `run_class` (Task 9), so the time logic exists once.
  `target_flows` and `class_points` are `pub` in `pub mod inject` (the shared "stored
  flows/points for this target" API): until Tasks 6, 8 and 9 land they have no non-test caller,
  and an unused `pub(crate)` fn would warn `dead_code` and fail this task's own
  `cargo clippy -- -D warnings`.
  Gate the target host up front with the read-only `host.guard().in_scope(authority)`
  (`ScopeRateGuard::in_scope`: no rate token, permit or error budget; `authority` is
  `host:port`, the port defaulted from the scheme with a 3-line private helper copied from
  `crawl.rs`'s `guard_authority` — `crawl.rs` is not in T5's Files, so copy rather than edit) and return
  `GuardError::OutOfScope(authority.to_string())` when it is false; that is the only `Err`
  `inject` returns. (`check_active` takes a token on every call, so using it here would let a
  second swept class fail with `RateLimited` after the first drained the per-host bucket; a
  test guard that does not override `in_scope` denies every host, so test guards wrap a scoped
  `StdGuard`.) Visit the points in order, skipping a point whose endpoint key (request method
  + `scheme://authority/path` **without the query** + location + name) was already injected in
  this call (first flow wins), a point whose source flow is no longer in the store, and a
  point whose source request has a non-token method or a path with a space or control byte —
  the evicted-flow and bad-request-line skips are counted in `skipped` (the bad request line
  is never sent); the dedupe skip is not. For each remaining point, try the class payloads in order
  (≤ `per_class_payload_cap`). Before every send: if `budget.checked_sub(1)` is `None`, stop
  with `stopped_reason = Some("budget")`; if `deadline` has passed, stop with
  `Some("time_budget")`. Send the mutated `HttpRequest` (only the one targeted location
  changes, the payload substituted raw) through `host.client().send` (the guarded chokepoint
  — inserts the replay flow) inside `bounded(deadline, ..)`; decrement `budget`, build a
  `MatchContext` from the response, call `def.confirm`. **On a point's first hit push one `Confirmed` —
  `attack_flow` is the `HttpFlow` `send` returned, with `response` set to `None` — and skip
  that point's remaining payloads.** When `confirmed.len()` reaches `MAX_CONFIRMED`, stop
  with `Some("max_confirmed")`. `Confirmed` is never serialised or logged. Reproduction
  requests are not issued here. `target_flows` returns the stored `Flow::Http` flows whose
  scheme, host and effective port (`url::Url`) equal the target's, in store order (every
  flow for `None`, none for an unparseable target); `class_points` runs `enumerate` over each
  flow and keeps points whose location is in `def.locations`.
  Handling of what `send` returns, per attempt (the spec's table): a `RateLimited {
  retry_after }` refusal (nothing was sent) goes through `wait_out_rate_limit` and retries
  the same attempt without charging `budget`, and `MAX_RATE_LIMIT_WAITS` consecutive
  refusals with no successful send between stop with `Some("guard_refused")` (a guard with
  `per_host_rps = 0` answers `RateLimited { 1 s }` forever); `HostDisabled`, `OutOfScope` or
  `PrivateAddressBlocked` stops with `Some("guard_refused")` (`PipelineClient` never returns
  `PrivateAddressBlocked` — the sender's SSRF refusal is a plain error, so a target that
  resolves to a private address ends as `send_error`); a `bounded` timeout with `at_deadline`
  stops with `Some("time_budget")`; any other error, including a timeout that fired below the
  deadline, charges the attempt, increments `send_errors` (the text is never forwarded or
  logged) and continues, and five consecutive such errors stop with `Some("send_error")`. In
  every case `inject` returns `Ok` with the confirmations so far. `inject.rs` adds no
  dependency (no `tracing`).
- **`test_support.rs`** (shared by this and later tasks; no later task edits it; it starts with
  `#![allow(dead_code)]` and a one-line reason — shared helpers, each first used by a later
  task, so T5's own clippy gate does not fail on them): a flow
  builder `http_flow(method, url, headers, body) -> HttpFlow`; stub `ProxyClient`s that
  insert and return the flow they build, count their calls and expose `requests() ->
  Vec<HttpRequest>` (every request they received, in order — later tasks assert "the stub
  saw X on the replay request" through it) — `Reflect` (the body echoes the mutated value;
  `Reflect::only("q")` echoes that one parameter's value only — it reads `q` from the query,
  a form body or a top-level JSON key — which the AC24 rows with a credential-named query,
  form or JSON-body point need so that only `q` confirms), `Escape` (same,
  HTML-escaped), `Slow(d)` (sleeps `d` before answering), `SlowOnRepeat(d)` (the first request
  for a given method + `req.path` is answered at once; a later request with the same method
  and path sleeps `d`), `BigBody(len)` (a body of `len` bytes), `Scripted(queue)` (each call
  answers from a queue of serve-reflecting, serve-plain (a 200 that does not reflect — the
  "reflect, then not" case), `Err(GuardError::..)` or `Err(anyhow!(..))`); `CountingSender`
  (a counting `RequestSender`
  returning a canned reflecting response, for Task 16's real-`PipelineClient` test);
  `CountingRecorder` (a `FindingRecorder` with `calls()`); `tmp_dir() -> PathBuf` (a
  `FlowId`-suffixed directory under `std::env::temp_dir()`, so no `tempfile` dependency).
- **Test** (hermetic, stub `ProxyClient` from `test_support`; in every test `deadline` is
  `deadline_after(60 s)` and `budget` is large unless the test says otherwise):
  - `inject_confirms_on_vulnerable`: a `Reflect` stub — `confirmed.len() == 1`,
    `confirmed[0].payload.value == "<aitm-canary-0001>"`, and `confirmed[0].attack_flow.id`
    equals the id of the flow the stub returned.
  - `inject_empty_on_patched`: a stub that HTML-escapes the marker — `confirmed` is empty and
    `tested == 8`.
  - `inject_stops_a_point_after_its_first_confirmation` (AC27): a reflect-everything stub, one
    `q` point — `confirmed.len() == 1`, `tested == 1`, the stub saw exactly `1` request.
  - `inject_dedupes_repeat_captures` (AC27): two flows with the identical `GET /search?q=`
    endpoint (different ids), reflect-everything stub — `tested == 1`, `confirmed.len() == 1`,
    stub requests `== 1`.
  - `inject_dedupe_ignores_the_query`: flows `GET /search?q=a` and `GET /search?q=b` →
    `tested == 1`, `confirmed.len() == 1`; flows `GET /search?q=a` and `GET /other?q=a` →
    `tested == 2`, `confirmed.len() == 2` (a different path is a different endpoint).
  - `inject_stops_at_budget`: `budget == 1`, patched stub — `tested == 1`, `stopped_reason ==
    Some("budget")`, `budget == 0`.
  - `inject_zero_budget_sends_nothing` (AC12): `budget == 0` — `tested == 0`,
    `stopped_reason == Some("budget")`, the stub saw `0` requests, `budget == 0`.
  - `inject_out_of_scope_refused`: an empty-scope guard — the error downcasts to
    `GuardError::OutOfScope`.
  - `inject_stops_at_time_budget` (AC26 i): `deadline == deadline_after(200 ms)`, a `Slow(3 s)` stub
    that never reflects — the first send is cut off at the deadline (the test itself ends at
    about 200 ms), `tested == 1`, `stopped_reason == Some("time_budget")`.
  - `bounded_and_wait_respect_the_deadline`: `bounded(now + 200 ms, sleep(3 s))` returns
    `Err(TimedOut { at_deadline: true })`; `bounded(now + 200 ms, ready(7))` returns `Ok(7)`;
    `wait_out_rate_limit(20 ms, now + 200 ms)` returns `true` after about 20 ms and
    `wait_out_rate_limit(20 ms, now - 1 ms)` returns `false` at once;
    `deadline_after(Duration::MAX)` does not panic and is later than `now + 1 year`.
  - `inject_caps_confirmed` (AC26 ii): `1025` flows with distinct paths (`/p0` … `/p1024`,
    one `q` each, inserted in a `MemFlowStore`), reflect-everything stub, `budget == 2000` —
    `confirmed.len() == 1024`, `tested == 1024`, `stopped_reason == Some("max_confirmed")`.
  - `inject_confirmed_flows_carry_no_response`: a `BigBody(1 MiB)` reflecting stub over three
    points — every `confirmed[i].attack_flow.response.is_none()`, while the flow the stub
    inserted into the store still has `response.is_some()`.
  - `inject_keeps_confirmed_on_send_error` (AC34 i): `Scripted` over three single-point
    endpoints, the second call failing once with a transport error and every other call
    reflecting — `Ok`, `confirmed.len() == 3`, `tested == 4`, `send_errors == 1`, the stub was
    called `4` times, `stopped_reason == None`; a second case in which every call fails —
    the stub was called exactly `5` times, `confirmed` is empty, `tested == 5`,
    `stopped_reason == Some("send_error")`, and `budget` fell by `5`.
  - `inject_waits_out_rate_limit` (AC34 ii): `Scripted` whose first call is
    `Err(GuardError::RateLimited { retry_after: 20 ms })` and later calls reflect, one point,
    `budget == 5` — `confirmed.len() == 1`, the stub was called exactly `2` times,
    `tested == 1`, `budget == 4` (the refused call was not charged). A second case:
    `Scripted` answering `RateLimited { retry_after: 1 ms }` ten times in a row —
    `Ok`, `stopped_reason == Some("guard_refused")`, `tested == 0`, `confirmed` empty, the stub
    was called exactly `10` times (`MAX_RATE_LIMIT_WAITS`), `budget` unchanged.
  - `inject_stops_on_guard_refusal` (AC34 iii): two endpoints, the second call answering
    `GuardError::HostDisabled` — `Ok`, `confirmed.len() == 1`, `stopped_reason ==
    Some("guard_refused")`, the stub was called exactly `2` times.
  - `inject_skips_an_evicted_source_flow` (AC34 iv): a `Reflect` stub and two points, one whose
    `FlowId` is not in the store — `Ok`, `skipped == 1`, the other point is still injected
    (`tested == 1`).
  - `inject_skips_a_request_line_with_a_control_byte` (AC34 iv): a `Reflect` stub and two
    points, the first from a hand-built source flow whose path holds a raw `\r\n` (a space or
    other control byte behaves the same), the second normal — `Ok`, `skipped == 1`, the stub saw
    exactly `1` request, and no request in `requests()` has a control byte in its path (a path
    carrying the literal text `%0d%0a` is not a control byte and is sent as captured).
  - `target_flows_and_class_points`: a store holding flows on `http://t.test:8080` and
    `http://other.test:8080` — `target_flows(host, Some("http://t.test:8080"))` returns exactly
    the first flow's id, `None` returns both, an unparseable target returns none; for a flow
    with a `q` query parameter, a header and a cookie, `class_points(.., &reflected_xss())`
    returns only the `q` point.
- **Done when:** the eighteen tests pass (each shown failing first) and the full gate passes.

### Task 18: class registry and the one success assertion (`checks.rs`) — Wave 2, independent

- **Satisfies:** AC20 (the shipped two classes; AC20 no longer asks for a third), AC5
  (definition half).
- **Depends on:** Task 2 (shipped; it registers two classes).
- **Files:** `crates/aitm-plugin-scanner/src/checks.rs` (modify). Nothing else.
- **Part A — mandatory; Tasks 4, 8 and 9 depend on it.** Add
  ```rust
  impl CheckDefinition {
      pub fn registered_classes() -> &'static [&'static str];
  }
  ```
  `registered_classes()` lists every class `for_class` resolves, in a stable order whose
  first two entries are literally `"reflected-xss"` and `"open-redirect"` (today exactly
  those two). Move open-redirect's 3xx clause out of `confirm` and into
  `success_assertion(payload)`: for open-redirect it returns `Assertion::All(vec![
  Assertion::Any(vec![Status(301), Status(302), Status(303), Status(307), Status(308)]),
  <the existing Location regex assertion>])`, and `confirm` drops its own `300..=399` check
  and evaluates `success_assertion` unchanged (the empty-word guard stays). `confirm` is
  thereby stricter than today: `300`, `304`–`306` and `309`–`399` no longer confirm
  (fail-closed, accepted). Every class's `success_assertion` must be at least as strict as its `confirm`.
- **Part B — optional and non-blocking; no other task depends on it.** A third registered
  class, with a `pub fn <class>() -> Self` and a `for_class` arm, only if a class exists that
  `confirm(status, body, headers, payload)` can judge from **one response to one request**
  with an inert payload and no target-specific marker knowledge. None of the four remaining
  seeded classes qualifies (spec Open question 2), so part B is an optional follow-up that is
  **not dispatched** unless Matt names a class; AC20 was amended to the shipped two, so no AC
  depends on it. A third class is never added to `campaign::DEFAULT_SWEEP`.
- **Test (part A):** `registered_classes_starts_with_the_shipped_two` asserts
  `registered_classes()[0] == "reflected-xss"`, `registered_classes()[1] == "open-redirect"`
  and `registered_classes().len() >= 2`. `every_registered_class_resolves` asserts
  `for_class(c).is_some()` for each and `payloads.len() <= 25`.
  `open_redirect_success_assertion_requires_a_redirect_status` asserts the open-redirect
  `success_assertion(payload)` is an `Assertion::All` whose first element is literally
  `Assertion::Any(vec![Status(301), Status(302), Status(303), Status(307), Status(308)])` and
  whose second is `Assertion::Regex { part: MatchPart::Header, .. }`, and that the
  reflected-XSS one is `Assertion::Word { part: MatchPart::Body, .. }`.
  `confirm_matches_the_success_assertion` asserts, for a sentinel `Location`, that `confirm`
  is `Some` for statuses `301`, `302`, `303`, `307`, `308` and `None` for `300`, `304`, `399`
  and `200`, and that `confirm(..).is_some()` implies `evaluate(&success_assertion(p), &ctx)`.
  `payloads_are_wire_safe` (the property that lets the injector send payloads raw): for every
  registered class and every payload, `value` contains no byte `<= 0x20` or `0x7f` and none of
  `&`, `#`, `+`, `%`, `"`, `\` or `;`.
  **Test (part B, if dispatched):** `third_class_confirms_and_rejects` asserts, with fixtures
  the builder writes, that `confirm` is `Some` on its vulnerable response and `None` on its
  patched one.
- **Done when:** the five part-A tests pass (each shown failing first), the shipped Task 2
  tests still pass unchanged, and the full gate passes.

### Task 8: `scan.inject` command + the agent gate + confinement — Wave 4, serial (command chain 3/4)

- **Satisfies:** AC5, AC7, AC8, AC9, AC10, AC11, AC12, AC13, AC18 (partial), AC20 (class
  dispatch), AC21 (the `scan.inject` half), AC22, AC24, AC25, AC26 (iv, command level),
  AC27, AC28, AC29, AC30, AC34 (v, the `injection_point` argument; vii, empty store).
- **Depends on:** Tasks 5, 9 (`run_class`), 17, 18 (part A); **Task 7** (shares
  `commands.rs`/`plugin.rs`/the contract lists). **Needs Matt's answer to Open question 6
  before dispatch** (see the Overview).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add `ScanInject`),
  `plugin.rs` (modify — register with `self.cfg.clone()`),
  `crates/aitm/tests/frontends.rs` (modify — `EXPECTED_TOOLS` 58 → 59, add `"scan.inject"`;
  update any confirmable-tools list that fails), `crates/aitm-tui/src/lib.rs` (modify —
  `CORE_TOOLS`), `crates/aitm-tui/fixtures/bus-fixture.json` (modify — a `scan.inject` entry
  with required `target` and `class` strings and an optional `injection_point`),
  `crates/aitm-tui/tests/tester_shell.rs` (modify — pins 61 → 62),
  `crates/aitm-mcp/src/server.rs` (modify — add the one arm `"scan.inject"` to the
  `defers_to_command_gate` match, with a comment naming `scanner.allow_agent_active`, beside
  the `scope.add`/`l4.*` arms), `crates/aitm-mcp/tests/mcp.rs` (modify — add a `Sensitive`
  stub named `scan.inject` to `policy_server`, plus the policy test below),
  `crates/aitm/tests/scan_agent_gate.rs` (create — the real-command policy test; Task 10
  extends it, serially). **Shared-file note:** `server.rs`, `mcp.rs` and
  `scan_agent_gate.rs` are touched here and again by Task 10; they are why those two tasks
  stay serial.
- **Change:** `ScanInject { cfg: ScannerConfig }` impl `Command`:
  `name()=="scan.inject"`, `sensitivity()==Sensitivity::Sensitive`, `schema()` with required
  `target: Str`, `class: Str`, optional `injection_point`. `invoke`:
  1. **Agent gate:** `if !matches!(host.frontend(), Frontend::Cli | Frontend::Operator) &&
     !self.cfg.allow_agent_active { bail!("scan.inject refused: … Set
     scanner.allow_agent_active = true …") }`. (Fail-closed for a future `Frontend` variant;
     a deliberate difference from `poc.allow_agent_run`'s `== Mcp` check — spec "Agent gate
     summary".)
  2. `let _confine = host.egress_handle().map(|e| e.confine());`.
  3. `let def = CheckDefinition::for_class(class).ok_or_else(..)?` — the error lists
     `CheckDefinition::registered_classes()`. Points are `class_points(&target_flows(host,
     Some(target)), &def)`, or, when the `injection_point` argument is given, only the one
     enumerated point with that `flow` (parsed as a `FlowId`), `location` (a
     `Location::as_str` token) and non-empty `name`; a malformed object, an unknown `flow` or
     no such point is an error naming `injection_point`. `let mut budget =
     self.cfg.request_budget;` `let deadline =
     inject::deadline_after(self.cfg.time_budget);` `block_on(campaign::run_class(host,
     target, &def, &points, &mut budget, &self.cfg, deadline))`.
  4. Shape the returned `ClassRun` with the `pub(crate)` helper this task writes in
     `commands.rs`: `fold_outcomes(&ClassRun) -> ClassReport`, with `ClassReport::to_value()`
     (reused by Task 10). `ClassReport` is field for field the result object below: `{ class:
     String, tested: usize, confirmed: Vec<{ injection_point, payload, evidence, reproduced
     }>, finding_ids: Vec<String>, unreproduced: Vec<{ injection_point, reason }>,
     reproduction: Option<&'static str>, stopped_reason: Option<&'static str> }`. Per
     `outcomes[i]`: `Recorded { finding_id }` → push onto
     `finding_ids`, `reproduced: true`; `Unreproduced { reason }` → `reproduced: false` and an
     `unreproduced` entry `{injection_point{flow,location,name}, reason}`; `NoFindingsDir` →
     `reproduced: false` and `reproduction = Str("skipped: no findings.dir")`;
     `BudgetExhausted` → `reproduced: false` and an `unreproduced` entry with reason
     `"budget"`. The command never calls `host.finding_recorder()` and returns `Err` only for
     the gate, an unknown class or `injection_point`, and `inject`'s read-only up-front scope
     refusal (`GuardError::OutOfScope`).
  5. Return `Value::Object { class, tested, confirmed[{injection_point{flow,location,name},
     payload, evidence, reproduced}], finding_ids, unreproduced, reproduction (Null or the
     marker), stopped_reason }`, scrubbed, arrays capped at `MAX_RESULT_ITEMS` (1024).
  `confirm_prompt` returns `Some(..)` only for valid input, built from `def.class` (the
  registered constant, resolved through `for_class` — never the raw `class` argument) and the
  parsed origin of `target` (`scheme://host[:port]`, no userinfo, path or query), control
  characters stripped and length capped (like `l4.inject`'s prompt, which validates before it
  speaks); an unknown class or an unparseable `target` gives `None` and `invoke` returns the
  error.
  6. Policy layer: in `crates/aitm-mcp/src/server.rs`, add `"scan.inject"` to
     `defers_to_command_gate`. Default for the spec's Open question 6; if Matt answers "leave
     them out", omit this arm and flip the `All` arms of the two policy tests below.
- **Test** (hermetic; reflecting/patched stub clients; each shown failing first):
  - `scan_inject_is_sensitive` asserts `sensitivity() == Sensitive`.
    `scan_inject_confirm_prompt_some` asserts `confirm_prompt({target: "http://t.test:8080/a?x=1",
    class: "reflected-xss"})` is `Some(p)` where `p` contains `reflected-xss` and
    `http://t.test:8080` and contains neither `/a` nor `x=1`; `scan_inject_confirm_prompt_validates`
    asserts `None` for `class: "nope"` and for `target: "not a url"`, and that a `target` carrying
    a newline and 5 000 characters of path yields a `p` with no control character and under 512
    bytes.
  - `agent_refused_without_flag` builds the host with `Frontend::Mcp` and
    `ScannerConfig{ allow_agent_active: false, .. }`: the error contains
    `scanner.allow_agent_active` and the stub saw `0` requests. `agent_runs_with_flag` with
    `allow_agent_active: true`: `confirmed` is non-empty. `operator_and_cli_always_run`: with
    `Frontend::Operator` and again with `Frontend::Cli`, `allow_agent_active: false`, it runs.
  - `scan_inject_out_of_scope_refused` asserts `invoke` returns an error that downcasts to
    `GuardError::OutOfScope` (AC8; distinct from Task 5's `inject_out_of_scope_refused`).
  - `inject_confined_during_run` — a posture probe like the shipped
    `scan_discover_crawls_under_egress_confinement` — asserts `confined()` was true during the
    send and false after `invoke` returns (AC9). `scan_inject_without_egress_handle_still_runs`
    — like the shipped `scan_discover_without_egress_handle_still_crawls` — builds the host
    with no egress handle and asserts `confirmed` is non-empty (AC9's last arm).
  - `inject_unknown_class_names_registered_classes`: `class: "nope"` → the error contains
    `reflected-xss` and `open-redirect`.
  - `scan_inject_result_has_exactly_the_documented_keys` (AC5): against a reflecting stub with
    `findings.dir` set, the result object's keys are exactly `class`, `tested`, `confirmed`,
    `finding_ids`, `unreproduced`, `reproduction`, `stopped_reason`; each `confirmed` entry's
    keys are exactly `injection_point`, `payload`, `evidence`, `reproduced`; each
    `injection_point` object's keys are exactly `flow`, `location`, `name`; and a refused
    case's `unreproduced` entry has exactly `injection_point` and `reason`.
  - `scan_inject_injection_point_argument` (AC34 v): with two enumerated points, a valid
    `{flow, location: "query", name: "q"}` object injects only that point (`tested` counts one
    point); a missing `name`, a non-object value, a `flow` that is not a `FlowId`, a `flow` not
    in the store, and a `name` that matches no point each return an error containing
    `injection_point`.
  - `scan_inject_deadline_comes_from_time_budget` (AC26 iv, command level):
    `ScannerConfig { time_budget: 200 ms, .. }`, `findings.dir` set, two vulnerable points and a
    `SlowOnRepeat(3 s)` stub — the stub saw exactly `3` requests, `finding_ids` is empty, and
    both `unreproduced` entries have reason `time_budget`.
  - `scan_inject_on_an_empty_store_is_ok` (AC34 vii): an empty store (zero points) →
    `Ok`, `tested == 0`, `confirmed` empty, no panic. `scan_inject_zero_budget_command_level`
    (AC12): `ScannerConfig { request_budget: 0, .. }` with a reflecting stub →
    `tested == 0`, `stopped_reason == "budget"`, the stub saw `0` requests.
  - `inject_records_one_finding_without_control` (AC10, AC22, AC27): a reflect-everything stub
    with one `q` flow, `findings.dir = tmp`, a counting `FindingRecorder` wired: `confirmed.len()
    == 1`, `finding_ids.len() == 1`, `confirmed[0].reproduced == true`, the store holds exactly
    `1` record with `reproduction.passed == true` and `reproduction.control_passed == None`,
    `counting.calls() == 0`, the stub saw exactly `2` requests (one injection, one replay).
  - `inject_without_findings_dir_keeps_confirmed` (AC28): no `findings.dir`: `confirmed.len()
    == 1`, `finding_ids` empty, `unreproduced` empty, `reproduction == Str("skipped: no
    findings.dir")`, the stub saw exactly `1` request.
  - `inject_reproduction_error_keeps_confirmed` (AC29): two vulnerable points, the first
    captured with a header `X-Note: {{x}}`: the call returns `Ok`, `confirmed.len() == 2`,
    `finding_ids.len() == 1`, `unreproduced.len() == 1` with `reason == "build refused:
    template"`; a second case with an unwritable `findings.dir` where `reason == "record
    failed"`; a third case where the replay send fails with `anyhow!("boom password=hunter2
    horse")`, `reason == "replay failed"` and `hunter2` and `horse` appear nowhere in the
    serialised result.
  - `inject_failed_replay_is_not_recorded` (AC30): a `Scripted` stub whose first answer reflects
    (the injection request) and whose second is serve-plain (the replay): `confirmed.len() == 1`, `confirmed[0].reproduced == false`,
    `finding_ids` empty, `unreproduced.len() == 1`, the store holds `0` records.
  - `inject_budget_exhausted_skips_reproduction` (AC25): `request_budget == 1`, a configured
    `findings.dir` (without one the outcome is `NoFindingsDir`) and a reflecting
    stub: `confirmed` non-empty, `finding_ids` empty, `unreproduced.len() == 1` with reason
    `budget`, `stopped_reason == Some("budget")`, the stub saw exactly `1` request.
  - `inject_budget_n_plus_one_sends_exact_count` (AC20, AC25): two vulnerable points, a
    configured `findings.dir`, `request_budget == 3` (a class with several points stays ≤
    `request_budget`): the stub saw exactly `3` requests, `finding_ids.len() == 1`,
    `unreproduced.len() == 1`, `stopped_reason == Some("budget")`.
  - `inject_leaks_no_credential_anywhere` (AC11, AC24; the one proof of the table): for each of
    the seventeen rows of the spec's AC24 table, run `scan.inject` then `scan.report {}` with
    `findings.dir = tmp` and a `Reflect::only("q")` stub (so the credential-named query, form
    and JSON points never confirm and `confirmed.len() == 1`) and assert **unconditionally**
    the row's outcome — *Recorded* rows
    (1–9): `confirmed.len() == 1`, `finding_ids.len() == 1`, `unreproduced` empty, the PoC YAML
    at the index entry's `poc_path` contains the row's placeholder, and the stub's
    `requests()` shows the real raw value on the replay request; *Refused* rows (10–16):
    `confirmed.len() == 1`, `finding_ids` empty, `unreproduced` is exactly one entry with
    `reason == "build refused: credential"`, `<tmp>` holds no `*.yaml` and no PoC file exists.
    In every row except 17 the row's secret (`abc123`; for row 7 both `correct%20horse` and
    `horse`) is absent from all five of: the PoC YAML (where one exists), the stored finding
    YAML (`<tmp>/*.yaml`), `<tmp>/runs.jsonl`, the serialised `scan.inject` result, and the
    serialised `scan.report` result. **Row 17 is the labelled accepted limit and is inverted:**
    outcome Recorded (`finding_ids.len() == 1`), `q7x9k2` present in the PoC YAML, and absent
    from the other four surfaces.
  - `all_policy_defers_scan_inject_to_its_gate` in `crates/aitm-mcp/tests/mcp.rs` (AC21,
    membership): add `GatedCmd { name: "scan.inject", gate: |_| true }` to `policy_server`; with
    a config supplied (as `f8_script_authoring_not_auto_authorized_under_all` does), assert
    `!is_refused(call_as(&all, Frontend::Mcp, "scan.inject"))` under `AgentPolicy::All` and
    `is_refused(..)` under `AgentPolicy::Auto`. This is the repository's convention for proving
    an allow-list entry by name (`all_sensitive_honors_config_gate`, with `script.save` as the
    negative control); `aitm-mcp` has no scanner dependency, so a stub is the right level.
    Keep it even though the real-command test below also exercises the entry: the stub test
    fails independently of any scanner code.
  - `scan_inject_policy_layers` in `crates/aitm/tests/scan_agent_gate.rs` (AC21, real command,
    like `crates/aitm/tests/l4_operator_surfaces.rs`): a `Registry` with
    `ScannerPlugin::new(ScannerConfig { allow_agent_active, .. })` and an `McpServer` over stub
    services; (a) `AgentPolicy::All`, flag `false`, role `Frontend::Mcp`, `scan.inject {target,
    class}` → `isError == true`, text contains `scanner.allow_agent_active` and does **not**
    contain `not allowed to the agent under` (it reached the command's own gate); (b)
    `AgentPolicy::Auto`, flag `true` → text contains ``the agent policy is `auto` `` (refused by
    policy); (c) role `Frontend::Cli`, flag `false` → text contains neither string (a `Cli`
    connection is never policy-refused; use `Cli`, not `Operator`, because an `Operator`
    connection is offered the confirm handshake first in `run_tool`); (d) `AgentPolicy::Ask`,
    flag `false`, role `Frontend::Mcp`: with an operator connection subscribed
    (`flow.subscribe`) and the parked call approved through `agent.approve` — the same
    choreography as `ask_parks_then_approves` in `crates/aitm-mcp/tests/mcp.rs` — the result is
    `isError == true` with text containing `scanner.allow_agent_active`: the approved call ran as
    the agent and the command's own gate refused it. (The helper choreography is copied into the
    file; de-duplicating test helpers is a follow-up.)
- **Done when:** all tests pass, the contract tests (`frontends.rs`, `tui_live_bus.rs`,
  `tester_shell.rs`, pins `62`, `59`) pass, the full gate passes.

---

### Stage 4 — campaign + status. AC14–AC20, AC26 (iii, iv), AC31.

### Task 9: campaign engine (`campaign.rs`) — Wave 3, independent of the command chain

- **Satisfies:** AC16 (shared budget), AC20 (default sweep), AC26 (iii, iv), AC28 (engine),
  AC31, AC34 (viii).
- **Depends on:** Tasks 5 (`bounded`, `target_flows`, `class_points`), 15, 17 (and shipped
  `crawl`, `passive`, `checks`, `report`).
- **Files:** `crates/aitm-plugin-scanner/src/campaign.rs` (create), `lib.rs` (modify —
  `pub mod campaign;`). It does **not** touch `checks.rs`, `inject.rs` or `commands.rs`, and
  builds no `Value`: result shaping is `commands.rs`'s (Tasks 6, 7, 8, 10).
- **Change** (behaviour per spec "The replay loop" and "`scan.run`"; signatures are
  authoritative):
  ```rust
  pub const DEFAULT_SWEEP: [&str; 2] = ["reflected-xss", "open-redirect"];
  #[derive(Debug, Clone, PartialEq)]
  pub struct CampaignSummary { pub run_id: String, pub phase: String,
      pub pages_crawled: usize, pub requests_used: usize, pub request_budget: usize,
      pub confirmed_count: usize, pub stopped_reason: Option<&'static str> }
  #[derive(Debug)]
  pub struct ClassRun { pub inject: crate::inject::InjectOutcome,
      pub outcomes: Vec<crate::reproduce::ReproOutcome>,
      pub stopped_reason: Option<&'static str> }
  pub async fn run_class(host: &aitm_core::CommandHost<'_>, target: &str,
      def: &crate::checks::CheckDefinition,
      points: &[crate::discover::InjectionPoint], budget: &mut usize,
      cfg: &crate::ScannerConfig, deadline: std::time::Instant)
      -> anyhow::Result<ClassRun>;
  pub struct CampaignOutcome { pub crawl: crate::crawl::CrawlOutcome,
      pub passive: Vec<crate::passive::PassiveFinding>, pub classes: Vec<ClassRun>,
      pub records: Vec<aitm_findings::FindingRecord> }
  pub async fn run_campaign(host: &aitm_core::CommandHost<'_>, target: &str,
      active: bool, cfg: &crate::ScannerConfig)
      -> anyhow::Result<(CampaignSummary, CampaignOutcome)>;
  ```
  `run_class` calls `inject` and then, per `inject.confirmed` entry in order: after a
  `NoFindingsDir` the rest are `NoFindingsDir` with no call; at or past `deadline` it is
  `Unreproduced { reason: "time_budget" }` with no call; otherwise
  `reproduce::reproduce_and_record(host, def, &c.injection_point, &c.payload, &c.attack_flow,
  budget, deadline)` runs inside `inject::bounded(deadline, ..)`, and a timeout is
  `Unreproduced("time_budget")` when `TimedOut.at_deadline`, else `Unreproduced("replay
  failed")`. `ClassRun.stopped_reason` is the injector's, else `"budget"` or `"time_budget"`
  when a confirmation ended that way. `run_campaign` takes one `let mut budget =
  cfg.request_budget;` and one `deadline = inject::deadline_after(cfg.time_budget)`: discover
  (`crawl`, which takes no budget argument — charge `pages_crawled` against `budget` with a
  saturating subtraction when it returns), passive (`passive_checks` over
  `inject::target_flows`, before inject), inject (when `active`: each class in `DEFAULT_SWEEP`,
  in order — **the default sweep is these two classes only; an optional third class is
  never swept** — through `run_class` with the shared `&mut budget` and `deadline`), report
  (`load_records(host, Some(target))`). The campaign's `stopped_reason` is `budget`,
  `time_budget` or `guard_refused` and nothing else (discover's `no_browser`, `max_pages`,
  `max_depth`, `left_scope`, `navigation_failed`, its own `guard_refused` and a class's
  `max_confirmed`, `send_error` stay in their own results; a discover `time_budget` ends the
  campaign; the campaign's `guard_refused` comes only from the injector).
  `requests_used = cfg.request_budget.saturating_sub(budget)`; `request_budget =
  cfg.request_budget`.
- **Test** (hermetic; `test_support` stubs; a stub browser defined in this task's test module
  where noted):
  - `campaign_shares_budget` runs with `request_budget == 1` and `findings.dir` set against a
    reflecting stub (one stored `GET /search?q=` flow, no browser) and asserts the summary's
    `stopped_reason == Some("budget")` and `requests_used == 1` (the one injection; the
    replay was refused for budget).
  - `campaign_default_sweep_is_xss_and_open_redirect` (AC20): the store holds a `GET
    /search?q=` flow and a `GET /redirect?next=https://app.test/home` flow (a URL-valued
    `next`, so `enumerate` classifies it as a `Redirect` point), and an instrumented stub records the
    classes whose payloads it saw; the set, in order, is exactly `["reflected-xss",
    "open-redirect"]` (a third registered class is never swept), and `DEFAULT_SWEEP ==
    ["reflected-xss", "open-redirect"]`.
  - `campaign_dry_run_skips_inject` with `active == false` asserts `outcome.classes` is empty,
    `outcome.records` is empty, no finding is recorded, and the stub saw no injection request.
  - `campaign_inject_phase_reproduces_and_records` (AC31): a store holding one reflecting
    `GET /search?q=` flow, no browser (so discover spends no request), `findings.dir = tmp`,
    `request_budget == 3`: `outcome.classes[0].outcomes` holds one `Recorded`, the store holds
    exactly `1` record, `summary.requests_used == 2` (one injection, one replay — a missing
    decrement would read `1`), `summary.confirmed_count == 1`, `summary.stopped_reason ==
    None` while `outcome.crawl.stopped_reason == Some("no_browser")`, and `summary.request_budget
    == 3`.
  - `campaign_time_budget_stops_before_inject` (AC26 iii): the same stored reflecting flow, no
    `findings.dir`; with `time_budget == 200 ms` and a stub browser (defined in this test
    module) whose navigation sleeps 3 s, `summary.stopped_reason == Some("time_budget")`
    and the stub saw `0` injection requests; the control run, same flow, default `time_budget`
    and no browser, makes the stub see exactly `1` injection request.
  - `run_class_bounds_the_replay_loop` (AC26 iv): two vulnerable points, `deadline ==
    deadline_after(200 ms)`, `findings.dir` set, a `SlowOnRepeat(3 s)` stub — the stub saw exactly `3`
    requests (the test itself ends at about 200 ms), `outcomes` holds two `Unreproduced {
    reason: "time_budget" }`, and `stopped_reason == Some("time_budget")`.
  - `run_class_stops_calling_after_no_findings_dir` (AC28 engine): two vulnerable points, no
    `findings.dir` — `outcomes` is two `NoFindingsDir` and the stub saw exactly `2` requests
    (the injections only).
  - `campaign_survives_a_drained_rate_bucket` (AC34 viii): a real `PipelineClient` over a
    `StdGuard::new(LimitConfig { per_host_rps: 3, ..LimitConfig::default() })` scoped to the
    target host and a `CountingSender`, a store holding the reflecting `GET /search?q=` flow
    and the `GET /redirect?next=https://app.test/home` flow, `findings.dir` set, default
    `time_budget`: the crawl seed, class 1's injection and its replay use the three tokens, so
    class 2 starts with an empty bucket — `run_campaign` still returns `Ok`,
    `outcome.classes.len() == 2`, `outcome.classes[0].outcomes` is one `Recorded`, the store
    holds exactly `1` record, and `summary.stopped_reason == None`. (With a `check_active` as
    the up-front gate, class 2 would have failed the whole call with `RateLimited`.) A second
    case wraps a scoped `StdGuard` in a guard (defined in this test module) whose first
    `check_active` answers `RateLimited`: `run_class` returns `Ok`.
- **Done when:** the eight tests pass (each shown failing first) and the full gate passes.

### Task 10: `scan.run` + `scan.status` commands — Wave 4, serial (command chain 4/4)

- **Satisfies:** AC13 (`scan.run` prompts, `scan.status` does not), AC14, AC15, AC16, AC17,
  AC18 (final contract), AC21 (the `scan.run` half), AC31 (parity), AC34 (vii, empty store).
- **Depends on:** Task 9; **Task 8** (shares `commands.rs`/`plugin.rs`/the contract lists, and
  `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/mcp.rs` and
  `crates/aitm/tests/scan_agent_gate.rs`, which Task 8 created). **Needs Matt's answer to Open
  question 6 before dispatch.**
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add `ScanRun`,
  `ScanStatus`), `plugin.rs` (modify — register both; hold the status snapshot),
  `crates/aitm/tests/frontends.rs` (modify — `EXPECTED_TOOLS` 59 → 61, add `"scan.run"`,
  `"scan.status"`), `crates/aitm-tui/src/lib.rs` (modify — `CORE_TOOLS` gains both names; the "59 commands" doc
  comment at :221 becomes 64),
  `crates/aitm-tui/fixtures/bus-fixture.json` (modify — a `scan.run` entry with required
  `target` and optional `active`, and a `scan.status` entry with an optional `run_id`),
  `crates/aitm-tui/tests/tester_shell.rs` (modify — pins 62 → 64; the "59 commands" doc
  comment at :924 becomes 64),
  `crates/aitm-mcp/src/server.rs` (modify — add the one arm `"scan.run"` to the
  `defers_to_command_gate` match, next to Task 8's `"scan.inject"`),
  `crates/aitm-mcp/tests/mcp.rs` (modify — add a `Sensitive` stub named `scan.run` to
  `policy_server` and the policy test below),
  `crates/aitm/tests/scan_agent_gate.rs` (modify — add the `scan.run` arms).
- **Change:** `ScanRun { cfg: ScannerConfig, status: Arc<Mutex<Option<CampaignSummary>>> }`
  impl `Command`: `name()=="scan.run"`, `sensitivity()==Sensitive`, the same fail-closed agent
  gate as `ScanInject` and a `confirm_prompt` built the same way (validated, parsed origin
  only) but without a class (`Run an active campaign against <origin>? …`; `None` for an
  unparseable `target`), `schema()` required `target`, optional `active: Bool` (default per
  Open question 4). `invoke`: agent gate → `let _confine =
  host.egress_handle().map(|e| e.confine());` → `block_on(run_campaign(host, target, active,
  &self.cfg))` → store the summary in `self.status` **once, after the run returns** (live
  phase-boundary progress and a single-in-flight guard are the spec's Open question 7
  alternative, not v1) → shape the typed `CampaignOutcome` with the helpers Tasks 6, 7 and 8
  wrote and return `{ run_id, discover: discover_value(host, &outcome.crawl), passive:
  passive_value(&outcome.passive), inject: { classes: [fold_outcomes(c).to_value() per
  class], tested (sum), finding_ids (all), reproduction (the marker if any class set it),
  stopped_reason (the first class-level `stopped_reason`, else `Null`) }, report:
  report_value(&outcome.records), stopped_reason (the summary's) }`; with `active == false`
  the `inject` object is `classes: []`, `tested: 0`, `finding_ids: []`, `reproduction:
  Null`, `stopped_reason: Null`. `ScanStatus { status: Arc<Mutex<..>> }`: `sensitivity()==Read`,
  `confirm_prompt()==None`, `schema()` declares the optional `run_id: Str` (`aitm-mcp`
  rejects undeclared properties, `json.rs`), returns `Value::Object { run_id, phase, pages_crawled,
  requests_used, request_budget, confirmed_count, stopped_reason }` copied from the last
  completed `CampaignSummary` (its `request_budget` field is `cfg.request_budget`, so
  `ScanStatus` holds no config), or `Null`s when none. The shared `status` `Arc` is owned by
  `ScannerPlugin` and cloned into both commands in `load()`. Policy layer: add `"scan.run"` to
  `defers_to_command_gate` in `crates/aitm-mcp/src/server.rs` (default for the spec's Open
  question 6; same fallback as Task 8). `scan.run`'s inject phase already reproduces and
  records through `run_class` (Task 9), so this task adds no recording code.
- **Test:** `scan_run_is_sensitive_and_gated` asserts `sensitivity() == Sensitive`,
  `confirm_prompt(args).is_some()` and the agent refusal without the flag (error names
  `scanner.allow_agent_active`). `scan_run_runs_for_agent_with_flag` (AC14): `Frontend::Mcp`,
  `allow_agent_active: true`, a stored reflecting flow — it runs, the stub sees traffic
  (`>= 1` request) and the result has the keys `run_id`, `discover`, `passive`, `inject`,
  `report`, `stopped_reason`. `scan_run_confined` (AC15) probes `confined()` from **both** a
  stub browser (during discover) and a stub client (during inject and replay), asserts it was
  true in every phase and false after `invoke` returns. `scan_run_on_an_empty_store_is_ok`
  (AC34 vii): an empty store → `Ok`, `inject.tested == 0`, no panic. `scan_run_budget_stops`
  with a stored reflecting `GET /search?q=` flow, `request_budget == 1` and `findings.dir` set
  asserts the result `stopped_reason == "budget"` (AC16). `scan_status_is_read` asserts
  `sensitivity() == Read` and `confirm_prompt(&empty).is_none()` (AC13);
  `scan_status_reflects_last_run` runs `scan.run` then `scan.status` and asserts the status
  `run_id` matches the run's and `request_budget` equals the configured `request_budget`, and
  that `scan.status {run_id: "no-such-run"}` returns the same all-null object (never an
  error); `scan_status_is_null_before_any_run` asserts every status field is `Value::Null` on
  a fresh plugin (each shown failing first). `scan_run_parity_with_standalone_verbs` (AC31): over one
  store holding a reflecting flow, `scan.passive {target}` is called **before** `scan.run`
  (passive runs before inject, so replays are not yet in the store) and `scan.report
  {target}` **after** it (the report phase runs after recording); the `scan.run` result's
  `passive` object equals the first and its `report` object equals the second, and its
  `inject.classes[0]` has exactly the keys of a `scan.inject` result.
  - `all_policy_defers_scan_run_to_its_gate` in `crates/aitm-mcp/tests/mcp.rs` (AC21,
    membership): `GatedCmd { name: "scan.run", gate: |_| true }` in `policy_server`; with a
    config supplied, `!is_refused(..)` for `Frontend::Mcp` under `AgentPolicy::All` and
    `is_refused(..)` under `AgentPolicy::Auto`.
  - `scan_run_policy_layers` in `crates/aitm/tests/scan_agent_gate.rs` (AC21, real command): the
    same four arms as Task 8's `scan_inject_policy_layers`, for `scan.run {target}`: `All` + flag
    `false` + `Frontend::Mcp` → text contains `scanner.allow_agent_active` and not `not allowed
    to the agent under`; `Auto` + flag `true` → text contains ``the agent policy is `auto` ``;
    `Frontend::Cli` → neither string; `Ask` + flag `false` + approved parked call → text contains
    `scanner.allow_agent_active`.
- **Done when:** tests pass, the contract tests pass (`EXPECTED_TOOLS` `[&str; 61]`, TUI pins
  `64`), the full gate passes.

---

### Stage 4 (cont.) — e2e + docs. Wave 5, all independent (separate files).

### Task 11: passive hermetic e2e — Wave 5, independent

- **Satisfies:** AC2, AC3 (end-to-end).
- **Depends on:** Task 6.
- **Files:** `crates/aitm-plugin-scanner/tests/passive_e2e.rs` (create).
- **Change:** craft captured flows (no browser, no socket) mirroring the seeded
  target's reflected `q` + a missing-CSP response, insert into a `MemFlowStore`,
  run `scan.passive`. `ScanPassive` is `pub(crate)` and this test lives outside the crate's
  `src/`, so it reaches the command through the public surface exactly as `discover_e2e.rs`
  and the plugin's own unit test do: `Registry::add_plugin(Box::new(ScannerPlugin::new(..)))`
  (which runs `ScannerPlugin::load`), then `registry.command("scan.passive")`.
- **Test:** `passive_e2e_flags_seeded_issues` asserts the result `findings`
  contains both a `reflection` entry (naming `q`) and a `security-header` entry;
  `passive_e2e_no_secret` asserts a seeded `Authorization` secret never appears.
- **Done when:** tests pass and the full gate passes.

### Task 12: inject live e2e (vulnerable vs patched) — Wave 5, independent

- **Satisfies:** AC6, AC8, AC10 (end-to-end), AC22 (end-to-end), AC23, AC27 (end-to-end), AC32.
- **Depends on:** Task 8 (which follows Task 7 in the chain, so `scan.report` is registered).
- **Files:** `crates/aitm/tests/inject_e2e.rs` (create — lives in the `aitm`
  integration-test crate, beside `discover_e2e.rs`, to reach `aitm::wire::assemble`
  without a crate-graph cycle).
- **Change:** spin `aitm-testtarget` in `SeedMode::Vulnerable` and `SeedMode::Patched`
  on loopback, scope the host, capture exactly one `GET /search?q=seed` flow per target through
  the assembled proxy's `PipelineClient` (so the store holds one flow for the endpoint), and run
  `scan.inject {class: "reflected-xss"}` through it (no browser → **not** obscura-gated; it binds
  a loopback port, which the real gate/Terminal panel allows). The harness configures
  `findings.dir` to a temp dir. The vulnerable-versus-patched proof is **two separate
  `scan.inject` calls**, one per `SeedMode`; production code runs no patched-control request.
- **Test:** `inject_confirms_vulnerable_only`: the call against the vulnerable base asserts
  `confirmed.len() == 1`, `finding_ids.len() == 1` (an exact value, so neither a duplicate nor a
  silent `0 == 0` passes), the store holds exactly `1` record with `reproduction.passed == true`
  and `reproduction.control_passed == None`, and `scan.report {target: <vulnerable base URL>}`
  returns an `index` of exactly `1` entry whose `target_path` is `<vulnerable base URL>/search`
  (AC32); the call against the patched base asserts `confirmed` empty, `finding_ids` empty,
  `scan.report {target: <patched base URL>}` returns an empty `index`, and the store still holds
  exactly `1` record (AC23). `inject_e2e_does_not_double_record`: with the real
  `aitm_findings::DiskFindingRecorder` wired onto the host as `crates/aitm/src/main.rs` wires it,
  one vulnerable call leaves the findings store holding exactly `1` record and `finding_ids.len()
  == 1` (never `2`). `inject_e2e_out_of_scope` asserts an unscoped target refuses with
  `GuardError::OutOfScope`.
- **Done when:** the tests pass (loopback bind) and the full gate passes.

### Task 13: campaign + both-paths e2e — Wave 5, independent

- **Satisfies:** AC11 (whole campaign result), AC14, AC17, AC19, AC31 (end-to-end). (AC16's
  budget behaviour is asserted by Tasks 9 and 10, not here.)
- **Depends on:** Task 10.
- **Files:** `crates/aitm/tests/scan_run_e2e.rs` (create). It declares the rig's three sibling
  support modules exactly as `discover_e2e.rs:23-29` does, each with `#[allow(dead_code)]`:
  `#[path = "../../aitm-browser/tests/support/engines.rs"] mod engines;`,
  `#[path = "support/rig.rs"] mod rig;` and `#[path = "support/scripted_driver.rs"] mod
  scripted_driver;` (`rig.rs` refers to the other two by crate path).
- **Change:** (a) assemble the proxy with `ScannerPlugin` loaded, run `scan.run` against the
  seeded loopback target (with `findings.dir` configured and one captured `GET /search?q=seed`
  flow that also carries `Authorization: Bearer abc123` and `Cookie: PHPSESSID=abc123`), then
  `scan.status`; (b) re-run the M4 scripted-driver scenario (or the reduced stand-in used by
  `m4_scripted_e2e.rs`) **with `ScannerPlugin` loaded** and assert it still reproduces its
  seeded vulns (no regression, no new mandatory gate).
- **Test:** `scan_run_campaign_reports_and_status` asserts the `scan.run` result carries
  `discover`/`passive`/`inject`/`report`, that `inject.finding_ids.len() == 1` (the campaign
  reproduced and recorded its confirmation), that `inject` has exactly the keys `classes`,
  `tested`, `finding_ids`, `reproduction`, `stopped_reason`, that each entry of `inject.classes`
  has exactly the keys `class`, `tested`, `confirmed`, `finding_ids`, `unreproduced`,
  `reproduction`, `stopped_reason` (the `scan.inject` shape), that the subsequent
  `scan.status` `run_id` matches, and that `abc123` appears nowhere in the serialised
  `scan.run` result or the serialised `scan.status` result (AC11 over the whole campaign
  result). `free_form_loop_unaffected` asserts the M4 scripted driver still records its seeded
  vulns with the scanner plugin loaded (AC19).
- **Gating, stated plainly:** `scan_run_campaign_reports_and_status` uses a stored flow and no
  browser, so it is **not** obscura-gated and runs in the default gate (it binds a loopback
  port). `free_form_loop_unaffected` is browser-dependent: the M4 scripted tests return early
  when `AITM_OBSCURA` is unset (`crates/aitm/tests/m4_scripted_e2e.rs`), so on the default gate
  that arm passes without running — AC19 is verified only where `AITM_OBSCURA=1` (with
  `AITM_OBSCURA_BIN`) is set. It begins with the same runtime guard (`if
  !rig::obscura_enabled() { return; }`, as `discover_e2e.rs` and `m4_scripted_e2e.rs` do —
  `obscura_enabled()` itself prints the skip line, so the test adds no `eprintln!`); the
  printed skip line under `--nocapture` is the only visibility, and the default gate reports
  the test `ok`.
- **Done when:** the non-gated test passes in the default gate, and `free_form_loop_unaffected`
  passes under obscura.

### Task 14: operator docs — Wave 5, independent

- **Satisfies:** documentation for AC7/AC13/AC14/AC17/AC21 (no code AC).
- **Depends on:** Task 10 (final command list).
- **Files:** `crates/aitm-plugin-scanner/README.md` (create — the crate has none),
  `crates/aitm-plugin-scanner/tests/readme.rs` (create — the `docs_list_all_commands` test
  below, reading the README with `include_str!`), `agent/PLAYBOOK.md` (modify — a short `scan.*`
  note), `crates/aitm/tests/agent_surface.rs` (modify — add `"scan"` to `COMMAND_NAMESPACES`,
  `[&str; 10]` → `[&str; 11]`, so the existing playbook check validates every `scan.*` the
  PLAYBOOK names against the live surface).
- **Change:** document all six `scan.*` commands, their tiers, the `scanner.allow_agent_active`
  gate (and that the integration plan wires its operator toggle), **that an agent also needs the
  MCP agent policy set to `all` (or `ask` with an operator present) in addition to the flag — under
  the default `auto` policy it is refused whatever the flag says** (spec "MCP policy layer"), the
  default caps, that no `findings.dir` means findings are skipped with a marker, and that the
  scanner augments (never gates) the free-form path. The PLAYBOOK note names `scan.discover`,
  `scan.inject` and `scan.run` in inline code spans.
- **Test:** `docs_list_all_commands` (in `crates/aitm-plugin-scanner/tests/readme.rs`) asserts
  the README names all six `scan.*` commands (`scan.discover`, `scan.passive`, `scan.report`,
  `scan.inject`, `scan.run`, `scan.status`), the `allow_agent_active` flag, and the policy `all`
  requirement.
  `playbook_documents_scan_commands` (in `agent_surface.rs`) asserts the playbook command refs
  contain `scan.discover`, `scan.inject` and `scan.run`, and — through the existing
  `adapters_are_well_formed` check, now that `scan` is a recognised namespace — that each is a
  command the bus serves.
- **Done when:** the tests pass and the full gate passes.

---

## Independence / wave map

| Wave | Tasks | Parallel? | Shared-file bottleneck |
|---|---|---|---|
| 1 (shipped) | T1 `passive.rs`, T2 `checks.rs`, T3 `report.rs` | already on `main` | — |
| 2 | T18 `checks.rs`; T5 `inject.rs` + `test_support.rs`; T15 `report.rs`; then chain T4 → T16 → T17 (`reproduce.rs`; T4 also `discover.rs`; T17 also the crate `Cargo.toml`) | T18 ∥ T5 ∥ T15 first; T4 needs T18 part A, T16 needs both T4 and T5, T17 needs T16 | `reproduce.rs` is written by the three chain tasks → **serial**; `lib.rs` is edited by T5 (`pub mod inject;` and `#[cfg(test)] mod test_support;`, merged **first**) and then T4 (`pub mod reproduce;`, merged after T5); `checks.rs` has one writer (T18), `report.rs` one (T15); every other file is distinct |
| 3 | T6 `ScanPassive` → T7 `ScanReport`; T9 `campaign.rs` | T9 ∥ (T6→T7) | T6, T7 share `commands.rs`/`plugin.rs`/`frontends.rs` and the `aitm-tui` family (`CORE_TOOLS`, fixture, `tester_shell.rs`) → **serial**; T9 adds `pub mod campaign;` to `lib.rs` (no other writer in this wave) and never touches `commands.rs`; T6 and T9 both only *read* `inject::target_flows` (T5) |
| 4 | T8 `ScanInject` → T10 `ScanRun`+`ScanStatus` | serial; T8 needs T9 (`run_class`) | share `commands.rs`/`plugin.rs`/`frontends.rs`, the `aitm-tui` family, **`crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/mcp.rs`, `crates/aitm/tests/scan_agent_gate.rs`** (T8 adds `scan.inject`'s arm/stub/test and `fold_outcomes`; T10 adds `scan.run`'s and reuses the shaping helpers of T6, T7, T8) |
| 5 | T11, T12, T13, T14 | fully independent | distinct test/doc files (T14 alone touches `agent_surface.rs` and `agent/PLAYBOOK.md`) |

**Files outside `crates/aitm-plugin-scanner` that more than one task touches:**
`crates/aitm/tests/frontends.rs` (T6, T7, T8, T10 — the `EXPECTED_TOOLS` bump);
`crates/aitm-tui/src/lib.rs`, `crates/aitm-tui/fixtures/bus-fixture.json` and
`crates/aitm-tui/tests/tester_shell.rs` (T6, T7, T8, T10 — one `CORE_TOOLS` name, one fixture
entry and the two count pins per command; T10 adds two names); and
`crates/aitm-mcp/src/server.rs` + `crates/aitm-mcp/tests/mcp.rs` + `crates/aitm/tests/scan_agent_gate.rs`
(T8, T10 — one `defers_to_command_gate` arm and one stub/test each). Every one of those tasks is
in the serial command chain, so no two writers share a file. The `aitm-mcp` half of T8/T10 is
scanner-independent but stays in the task (it must land with or after the command-side flag
check); it must merge before the integration plan's Task 8, whose
`scan_inject_gate_is_wired_default_off` test cannot pass without the `scan.inject` entry.

**Note on `lib.rs`:** the Wave-1 `pub mod`/`pub use` lines (`passive`, `checks`, `report`) are
already on `main`. Three `pub mod` lines remain, plus one test-only line: `reproduce` (T4) and
`inject` with `#[cfg(test)] mod test_support;` (T5), both in Wave 2, and `campaign` (T9, Wave
3). Order: T5's lines merge first, T4's `pub mod reproduce;` after; T9's edit has no concurrent
writer. The engine *logic* in the new files is independent regardless.

**Note on `commands.rs` helpers:** the `pub(crate)` shaping helpers are written one per
command task and reused by T10 — `passive_value` and `discover_value` (T6), `report_value`
(T7), `fold_outcomes`/`ClassReport` (T8). They sit in the serial chain, so no two writers share
the file.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| T6-T10 | spec, quality | Important | Every command-registration task fails the workspace gate unless it also edits the `aitm-tui` `CORE_TOOLS` / `bus-fixture.json` / `tester_shell.rs` pins; the closed file list forbade it | fixed in eaef723 |
| T4, T8, T9 | spec, quality | Important | `scan.run`'s reproduce+record loop had no owner (copy-paste or silent no-record) | fixed in eaef723 (shared `reproduce_and_record`), refined in a8a7ab4 (`run_class`, typed results) |
| T4, T16 | spec, quality, security | Important | "No credential reaches the PoC file" false beyond four headers; AC24 vacuous | fixed in eaef723, redesigned in a8a7ab4 (placeholders + one `scrub_text` backstop), claim narrowed in e04ec44 / 9840323; OQ11 open |
| T5, T8 | quality | Important | One Confirmed -> one reproduction -> one record duplicates findings per point; no `findings.dir` / per-confirmation failure policy | fixed in eaef723 |
| T9, OQ2/OQ7 | quality | Important | T9 contradicted OQ2; OQ7's default contradicted T9/T10 | fixed in eaef723 |
| T5, T9 | security, spec, quality | Important | `Confirmed` retained full response bodies; replay loop not time-bounded; runner error text echoed credentials; injection send failures discarded confirmations; pre-check false refusals | fixed in a8a7ab4 |
| T13 | tester, quality | Important | `#[cfg_attr(not(AITM_OBSCURA), ignore)]` is not a cargo cfg: trips `unexpected_cfgs` and can never run | fixed in e04ec44 (runtime `rig::obscura_enabled()` guard) |
| T5 | quality | Important | `pub(crate)` helpers + shared test helpers trip `dead_code` under `-D warnings` at T5's gate | fixed in e04ec44 |
| AC18 | tester | Important | no named test / `inputSchema` assertion | fixed in e04ec44 (`scan_tools_have_non_empty_input_schemas`) |
| AC20 | tester, quality, spec | Important/Minor | `>= 3` classes cannot be met by the dispatched plan (no seeded class confirms generically) | fixed in e04ec44: AC20 amended to the shipped two; third class optional follow-up (**needs Matt's approval of the AC20 amendment**) |
| T6 | quality | Important | `ScanPassive { cfg }` field never read -> clippy fails at T6's gate | fixed in 9840323 (unit struct) |
| T5, T8, T9 | security | Important | `inject`'s up-front `check_active` returned `RateLimited` -> `Err` between swept classes, losing earlier classes' findings | fixed in 9840323 (read-only `in_scope` gate; AC34(viii)) |
| T8, T10 | security | Minor | Agent-gate posture (`defers_to_command_gate` entries) is a decision, gate must fail closed | fixed (OQ6 dispatch gate; `!matches!(Cli\|Operator)`); **Matt's explicit OQ6 answer required before T8/T10 dispatch** |
| spec/plan | all | Minor (~60) | wording, test-name/count drift, duplication, helper signatures, path conventions, deadlines in tests, derives, edge-case tests | fixed across eaef723 / a8a7ab4 / e04ec44 / 9840323 |
| T8, T10 | quality (M10) | Minor | split an early scanner-independent `aitm-mcp` task out of T8; dedupe MCP test helpers into `tests/support/` | accepted by orchestrator (autonomous mode, 2026-10-30): keeps task numbering stable and the entries must land with/after the command-side flag check; helper dedupe is a follow-up |
| spec | spec | Minor | cross-flow endpoint dedupe extends round-1 finding I4's literal wording | accepted by orchestrator (2026-10-30): matches I4's intent; recorded in Architect's call 17 / AC27 |
| T16 | spec | Minor | open-redirect statuses 300, 304-306, 309-399 can never reproduce (fail closed) | accepted by orchestrator (2026-10-30); resolved further by T18 part A moving the status clause into `success_assertion` |
| T5, spec | security, quality | Minor | `UnreproReason`/`StopReason` full enums; surfacing `send_errors`/`skipped`; aggregate retained-request-bytes cap; `Variable.default` provenance; leaked temp dirs | accepted by orchestrator (2026-10-30): `&'static str` enforces constants-only; the rest are one-line Left-to-builder notes or follow-ups |
| spec | security (r5) | Important | the "not detected" list omitted a nested JSON-quoted `"authorization":"…"` key (`scrub_text` needs `authorization` followed directly by `:`/`=`) | fixed in the final commit (spec backstop bullet, "What is guaranteed" (a), OQ11) |
| T5, T9, T17 | security (r5) | Minor | `OutOfScope` for a later swept class (operator removed scope mid-campaign) is still a hard `Err`; 10 consecutive refusals labelled `guard_refused` even when a rate bucket would eventually admit; whether a charged non-rate error resets the consecutive counter is unstated; AC34(viii) case 1 is timing-sensitive | accepted by orchestrator (2026-10-30): fail-closed and operator-initiated; the deterministic case 2 is the stronger proof; builder pins the counter reset when writing T5/T17 |
| T5, T9 | quality (r5) | Minor | skip-count wording, `guard_authority` helper provenance, `ClassRun` derive, `Reflect::only` coverage, T17 deadline wording, T6 paragraph readability | fixed in the final commit (T6 readability accepted) |
| out of range | security, quality | n/a | scope-plugin design/plan still say `control_passed == Some(false)`; integration Task 8 needs an ordering note; `findings.record` can forge a "reproduced" record; `poc.allow_agent_run` fails open on `== Mcp` | recorded in the PR description, not changed here |

Panel rounds: 1 (24204cd) spec FAIL 3I/3M, quality FAIL 7I/9M, security FAIL 1I/6M; 2 (eaef723) spec FAIL 2I, quality FAIL 4I, security FAIL 5I, tester 6 gaps; 3 (a8a7ab4) spec PASS, tester 3I, quality 2I, security 1I; 4 (e04ec44) spec PASS, tester PASS, quality 1I, security 1I; 5 (9840323) quality PASS, security 1I (nested `authorization` in the not-detected list, fixed in the final commit; a one-sentence documentation fix, not re-reviewed). Fix-task inputs: `panel-findings-round{1,2,3}.md` in the session notes folder.

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
