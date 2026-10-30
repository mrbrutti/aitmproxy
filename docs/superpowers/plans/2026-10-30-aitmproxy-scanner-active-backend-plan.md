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
`crates/aitm/tests/scan_agent_gate.rs`); and, in the docs task, `crates/aitm/tests/agent_surface.rs`
and `agent/PLAYBOOK.md`.

The reproduce-and-record machinery is built once, in `reproduce.rs`, by three serial
tasks (T4 PoC builder, T16 run/record building blocks, T17 `reproduce_and_record`),
and consumed by two callers — `scan.inject` (T8) and `scan.run`'s campaign (T9). The
crate splits into **engine library modules** (one file each → fan out) and a
**command-registration chain** (every command lives in `commands.rs`, registers in
`plugin.rs`, and bumps the contract lists — so command tasks are strictly serial among
themselves: two writers never share a file). E2e/integration tests are separate files →
fan out at the end. Tasks are grouped into **waves** the orchestrator dispatches in
parallel.

**Wave 1 (T1 `passive.rs`, T2 `checks.rs`, T3 `report.rs`, with their `pub mod` lines
in `lib.rs`) is already on `main` at `78405c3`**; their task text below is kept for
traceability and is not re-dispatched. T15 and T18 amend two of those files.

**Dependency spine (longest chains):** T4 → T16 → T17 → T9 → T10 → T13 (reproduce →
campaign → `ScanRun` → both-paths e2e); T5 → T8 → T10 (`inject.rs` → `ScanInject`);
T15 → T7 and T9; T8 also needs T17 and T18.

**Waves:**

- **Wave 1 (shipped):** T1, T2, T3.
- **Wave 2 (fan-out):** the serial chain T4 → T16 → T17 (all in `reproduce.rs`),
  alongside the independent T5 `inject.rs`, T15 `report.rs` target filter, and T18
  `checks.rs` third class. They share no file except `lib.rs` (T4 and T5 each add one
  `pub mod` line).
- **Wave 3 (serial command chain begins + campaign engine):** T6 `ScanPassive`, then
  T7 `ScanReport` (share `commands.rs`, the contract lists); T9 `campaign.rs` (engine,
  independent of the command chain, may run parallel to T6/T7).
- **Wave 4 (serial command chain continues):** T8 `ScanInject`, then T10
  `ScanRun`+`ScanStatus` (share `commands.rs`, the contract lists, `aitm-mcp`'s
  `server.rs` and `mcp.rs`, and `crates/aitm/tests/scan_agent_gate.rs`). The
  `aitm-mcp` half of each task needs no scanner code (its test uses a stub command
  named after the real one), but it stays inside the task because it must land in the
  same merge as, or after, the command-side flag check (spec Open question 6); it must
  still merge before the integration plan's Task 8.
- **Wave 5 (fan-out, independent tests/docs):** T11 passive hermetic e2e, T12 inject
  live e2e, T13 both-paths/campaign e2e, T14 docs.

**Open question 6 gates Tasks 8 and 10.** Matt's explicit answer to the spec's Open
question 6 is needed before either is dispatched. "Add" (the recommended default) means
the arms in this plan; no answer means the arms and the `All` policy-test arms are left
out (the fail-closed choice) and the AC21 `All` arms flip.

**Global constraints (every task):**

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test` passes before review (each "Done when" cites it). Default `cargo
  test` hermetic; browser-dependent tests `#[cfg_attr(not(AITM_OBSCURA), ignore)]`.
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
- **Reproduce + record (callers: Tasks 8 and 9; built in Tasks 4, 16, 17).** The PoC runs
  through `aitm_poc::StdPocRunner` on `reproduce::narrowed_host(host)` (every service
  kept, finding recorder and browser dropped), never through the `poc.run` command (a
  command cannot call a command) and never on the command's own host (that would add a
  second, runner-made record). The scanner records only via `DiskFindingStore`, never
  `host.finding_recorder()`; only a passing replay is recorded; every production record
  has `control_passed: None`; a per-confirmation failure is an `unreproduced` entry,
  never a `?` out of the call.
- **No credential persists.** No credential-named header/query/body value, `Cookie`, or
  unparameterisable credential reaches the PoC YAML, a stored record, `runs.jsonl`, or
  any result (spec "Building the PoC", AC24). Test fixtures use the literal `abc123`.
- **Contract lists (every command-registration task: 6, 7, 8, 10).** In the same task
  that registers a command: bump `EXPECTED_TOOLS` in `crates/aitm/tests/frontends.rs`;
  add the name to `CORE_TOOLS` in `crates/aitm-tui/src/lib.rs`; add a fixture entry
  shaped like `scan.discover`'s to `crates/aitm-tui/fixtures/bus-fixture.json`; bump the
  two `tools.len()` pins in `crates/aitm-tui/tests/tester_shell.rs` (`fixture_app_core…`
  and the `fixture_app(200, 50)` assertion). Without these, `tui_live_bus.rs` and
  `tester_shell.rs` fail the workspace gate. Running counts: `EXPECTED_TOOLS` 56 → 57
  (T6) → 58 (T7) → 59 (T8) → 61 (T10); TUI pins 59 → 60 → 61 → 62 → 64.
- **Citations.** Code references in this plan are to `main` at `78405c3`, by file and
  symbol.
- **Extend, don't reinvent:** build on the shipped `ScannerConfig`,
  `enumerate`/`InjectionPoint`/`Location`, `crawl`/`normalize_url`/`block_on`,
  `egress_handle`, and the `aitm-poc`/`aitm-findings` seams.
- Declared signatures are authoritative; bodies and private layout are the builder's.

---

## Tasks

### Stage 2 — passive + report (Read). Satisfies AC1–AC4.

### Task 1: passive-check library (`passive.rs`) — Wave 1, independent

- **Satisfies:** AC1 (engine), AC3 (redaction in the data model).
- **Depends on:** none (uses shipped `discover::{enumerate, Location}` + `aitm_poc`).
- **Files:** `crates/aitm-plugin-scanner/src/passive.rs` (create),
  `crates/aitm-plugin-scanner/src/lib.rs` (modify — re-export).
- **Change:**
  ```rust
  pub struct PassiveFinding { pub class: String, pub flow: aitm_core::FlowId,
      pub location: Option<crate::discover::Location>, pub name: Option<String>,
      pub evidence: String, pub severity: aitm_poc::Severity }
  pub fn passive_checks(flow: &aitm_core::HttpFlow) -> Vec<PassiveFinding>;
  ```
  Three checks: **reflection** (per `enumerate` param, `aitm_poc::matcher::evaluate`
  of `Assertion::Word { word: value, part: Body }` over the response body — a hit
  names the param, class `"reflection"`); **security-header** (missing
  `Content-Security-Policy`/`X-Content-Type-Options`/`Strict-Transport-Security`,
  class `"security-header"`); **cookie-flag** (`Set-Cookie` without
  `Secure`/`HttpOnly`, class `"cookie-flag"`). `evidence` carries only the param
  name / header name / class — **never** a param value (so a reflected secret is
  not re-leaked); add `dev-dependencies` only, no `aitm-testtarget` non-dev dep.
- **Test:** `passive_flags_reflection` builds a flow whose response body echoes
  `?q=HELLOMARKER` and asserts one finding with `class == "reflection"` and
  `name == Some("q")`. `passive_flags_missing_csp` asserts a finding with
  `class == "security-header"` for a response lacking CSP. `passive_flags_insecure_cookie`
  asserts `class == "cookie-flag"` for `Set-Cookie: sid=1` (no `Secure`).
  `passive_evidence_has_no_value` builds a reflecting flow whose param value is
  `abc123` and asserts no `PassiveFinding.evidence` contains `abc123`.
- **Done when:** the four tests pass and the full gate passes.

### Task 2: payload sets + `CheckDefinition` (`checks.rs`) — Wave 1, independent

- **Satisfies:** AC5 (payload/definition half), AC6 (correlation operator).
- **Depends on:** none (uses shipped `discover::Location` + `aitm_poc`).
- **Files:** `crates/aitm-plugin-scanner/src/checks.rs` (create), `lib.rs` (modify).
- **Change:**
  ```rust
  pub enum AttackMode { BatteringRam }
  pub struct Payload { pub value: String, pub marker: Option<String> }
  pub struct Evidence { pub payload: String, pub matched: String }
  pub struct CheckDefinition { pub class: &'static str,
      pub locations: &'static [crate::discover::Location],
      pub payloads: Vec<Payload>, pub mode: AttackMode }
  impl CheckDefinition {
      pub fn confirm(&self, status: u16, body: &str, headers: &[(String,String)],
          payload: &Payload) -> Option<Evidence>;
      pub fn reflected_xss() -> Self;   // Word{marker, Body}; locations Query,BodyParam
      pub fn open_redirect() -> Self;   // 3xx + Regex over the Location header; location Redirect
      pub fn for_class(class: &str) -> Option<Self>;
  }
  ```
  `confirm` builds the class `Assertion` and runs `aitm_poc::matcher::evaluate`
  against a `MatchContext::new(status, body)` with the headers added. Payload lists
  are inert canaries (reflected-XSS: a unique benign marker token, **not** an
  executing `<script>`; open-redirect: an off-origin sentinel host) and capped at
  `ScannerConfig::default().per_class_payload_cap`. Default set sizes per Open
  question 1 (reflected-XSS ≈ 8, open-redirect ≈ 6).
- **Test:** `reflected_xss_confirms_on_reflection` asserts `confirm` returns
  `Some(Evidence)` when the body contains the payload's marker and `None` when it
  does not. `open_redirect_confirms_on_location` asserts `Some` when the `Location`
  header points at the sentinel host and `None` when it is same-origin.
  `for_class_known` asserts `for_class("reflected-xss").is_some()` and
  `for_class("nope").is_none()`. `payloads_within_cap` asserts each definition's
  `payloads.len() <= 25`.
- **Done when:** the four tests pass and the full gate passes.

### Task 3: findings-read helper (`report.rs`) — Wave 1, independent

- **Satisfies:** AC4 (read half).
- **Depends on:** none (uses `CommandHost::config` + `aitm-findings`).
- **Files:** `crates/aitm-plugin-scanner/src/report.rs` (create), `lib.rs` (modify).
- **Change:**
  ```rust
  pub fn load_records(host: &aitm_core::CommandHost<'_>, target: Option<&str>)
      -> Vec<aitm_findings::FindingRecord>;
  pub fn index_to_value(index: serde_json::Value) -> aitm_core::Value;  // converter
  ```
  `load_records` builds `aitm_findings::DiskFindingStore::new(dir)` from
  `host.config().and_then(|c| c.findings.dir.clone())`, returning an **empty vec**
  (not an error) when no dir is configured; it lists summaries and `get`s full
  records, filtered to `target` when given (an exact-match filter; Task 15 replaces it
  with the origin-and-path rule). `index_to_value` maps `serde_json::Value` →
  `aitm_core::Value` (object/array/scalars).
- **Test:** `load_records_empty_without_dir` builds a `CommandHost` with no config
  and asserts `load_records(&host, None).is_empty()`. `index_to_value_round_trips`
  asserts `index_to_value(serde_json::json!([{"class":"x","passed":true}]))` is an
  `aitm_core::Value::Array` of one object whose `"class"` is `Value::Str("x")` and
  `"passed"` is `Value::Bool(true)`.
- **Done when:** both tests pass and the full gate passes.

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
  equals the filter's path or extends it on a `/` boundary (an empty or `/` filter path
  matches every path); query and fragment ignored. If the filter does not parse as an
  absolute URL, match only on exact string equality.
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
  (`not a url`, `not a url`) → `true`; (`not a url`, `http://t.test/`) → `false`.
  `load_records_matches_endpoint_records_by_base` records `http://t.test:8080/search`
  and `http://other.test:8080/search` in a temp `DiskFindingStore` and asserts
  `load_records(host, Some("http://t.test:8080"))` returns exactly the first. The shipped
  `load_records_filters_by_target` must still pass unchanged.
- **Done when:** both new tests pass (each shown failing first), the shipped tests still
  pass, and the full gate passes.

### Task 6: `scan.passive` command — Wave 3, serial (command chain #1)

- **Satisfies:** AC2, AC3, AC18 (contract, partial).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanPassive`), `plugin.rs` (modify — register), `crates/aitm/tests/frontends.rs`
  (modify — `EXPECTED_TOOLS` 56 → 57, add `"scan.passive"`),
  `crates/aitm-tui/src/lib.rs` (modify — add `"scan.passive"` to `CORE_TOOLS`),
  `crates/aitm-tui/fixtures/bus-fixture.json` (modify — add a `scan.passive` entry with an
  optional `target` string property), `crates/aitm-tui/tests/tester_shell.rs` (modify —
  both pins 59 → 60).
- **Change:** `ScanPassive { cfg: ScannerConfig }` impl `Command`:
  `name()=="scan.passive"`, `sensitivity()==Sensitivity::Read`,
  `confirm_prompt()==None`, `schema()` with optional `target: Str`. `invoke`
  iterates `host.store().list()` (filtered to `target` via `crawl::normalize_url`
  same-origin/in-scope when given), runs `passive_checks`, and returns
  `Value::Object { "findings": Array[ {class, flow, location, name, evidence,
  severity} ] }`, every string through `aitm_core::redact::scrub_text`. No
  `client().send`, no `browser()`.
- **Test:** `scan_passive_is_read` asserts `sensitivity() == Read` and
  `confirm_prompt(&empty).is_none()`. `scan_passive_issues_no_traffic` records
  `host.store().count()` before/after `invoke` and asserts it is unchanged.
  `scan_passive_finds_reflection` seeds a reflecting flow and asserts the result
  `findings` contains a `reflection` entry naming `q`. `scan_passive_redacts`
  seeds a flow with `Authorization: Bearer abc123` + reflected `?q=abc123` and
  asserts no `abc123` anywhere in the result. The contract tests are shown failing first
  — with only the command registered, `crates/aitm/tests/tui_live_bus.rs` fails with
  "live tool `scan.passive` is missing from aitm_tui::CORE_TOOLS" and `frontends.rs`
  fails on the exact set — then passing with the edits above (pins literally `60`, `57`).
- **Done when:** the tests pass, `frontends.rs`, `tui_live_bus.rs` and `tester_shell.rs`
  pass, and the full gate passes.

### Task 7: `scan.report` command — Wave 3, serial (command chain #2)

- **Satisfies:** AC4, AC18 (contract, partial).
- **Depends on:** Task 3; Task 15 (the target filter); **Task 6** (shares
  `commands.rs`/`plugin.rs`/the contract lists).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanReport`), `plugin.rs` (modify), `crates/aitm/tests/frontends.rs` (modify —
  `EXPECTED_TOOLS` 57 → 58, add `"scan.report"`), `crates/aitm-tui/src/lib.rs` (modify —
  `CORE_TOOLS`), `crates/aitm-tui/fixtures/bus-fixture.json` (modify — a `scan.report`
  entry), `crates/aitm-tui/tests/tester_shell.rs` (modify — pins 60 → 61).
- **Change:** `ScanReport { }` impl `Command`: `name()=="scan.report"`,
  `sensitivity()==Read`, `confirm_prompt()==None`, `schema()` optional `target`.
  `invoke` = `let recs = report::load_records(host, target);` returns
  `Value::Object { "report_md": Str(render_report(&recs)), "index":
  report::index_to_value(render_index(&recs)) }` (arrays capped at 1024).
- **Test:** `scan_report_is_read` asserts `sensitivity() == Read`.
  `scan_report_one_section_per_finding` writes N records to a temp
  `DiskFindingStore`, wires it via `host.config()` findings dir, and asserts
  `report_md` contains N `"## "` section headers and `index` is an `Array` of N
  objects each carrying `poc_path`/`class`/`passed`. `scan_report_target_selects_endpoint_records`
  stores a record with `target == "http://t.test:8080/search"` and asserts
  `index.len() == 1` for `{target: "http://t.test:8080"}` and `0` for
  `{target: "http://other.test:8080"}`.
- **Done when:** tests pass, the contract tests pass (pins `61`, `58`), full gate passes.

---

### Stage 3 — active injection, reproduce, record (Sensitive, gated). AC5–AC13, AC20–AC33.

### Task 4: PoC builder (`build_poc` in `reproduce.rs`) — Wave 2, chain #1

- **Satisfies:** AC10 (build half), AC11 and AC24 (no credential in the PoC), AC29
  (template-metacharacter half).
- **Depends on:** Task 2 (the shipped `CheckDefinition::success_assertion`, `pub(crate)`).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (create),
  `crates/aitm-plugin-scanner/src/discover.rs` (modify — change `fn is_secret_name` to
  `pub(crate) fn is_secret_name`; **no behaviour change**), `lib.rs` (modify —
  `pub mod reproduce;`). Nothing else; no `aitm-core` edit.
- **Change:**
  ```rust
  pub struct BuiltPoc { pub poc: aitm_poc::Poc, pub bindings: aitm_poc::VarBindings }
  pub fn build_poc(attack_flow: &aitm_core::HttpFlow,
      def: &crate::checks::CheckDefinition,
      point: &crate::discover::InjectionPoint, payload: &crate::checks::Payload)
      -> anyhow::Result<BuiltPoc>;
  ```
  `build_poc` is fed the **attack flow** (the flow `client().send` returned for the
  confirming request), because the builder parameterizes the concrete URL pieces of the
  flow it is given and only the attack flow contains the payload. It builds
  `aitm_poc::PocSpec { info, variables, success }`, calls
  `aitm_poc::StdPocBuilder::default().build(attack_flow, spec)`, then post-processes the
  built `Step::Http`:
  - `info` = `PocInfo { name, severity, references: vec![], tags: vec![class],
    cwe: None, description: None, author: None, metadata: None }` (`PocInfo` has no
    `Default`). `name` = `"<class>: <param>"`, `<param>` the point's name with every
    character outside `[A-Za-z0-9_.-]` replaced by `_`, truncated to 32 characters (empty
    → `param`). `severity` from a mapping local to this file: reflected-XSS `Medium`,
    open-redirect `Low`, any other class `Info` (do not add a field to `CheckDefinition`).
  - `success` = `def.success_assertion(payload)`; for open-redirect that is only the
    `Location` regex, so wrap it: `Assertion::All(vec![Assertion::Any(vec![Status(301),
    Status(302), Status(303), Status(307), Status(308)]), <the regex assertion>])` — the DSL
    has no ordering operator, and `confirm` requires a 3xx.
  - Base URL → `{{target}}`; the injected value → `{{payload}}`.
  - **Credentials.** A component is a credential when `discover::is_secret_name(name)` or
    it is a `Cookie`. For every request **header**, **query key**, and top-level
    **form-urlencoded or JSON-object body key** that is a credential, replace the value
    with a `{{var}}` placeholder, add `Variable { name, default: None, required: true, .. }`
    to `poc.variables`, and record the real value in `bindings`. Variable name = the
    component name lowercased with each character outside `[a-z0-9]` replaced by `_`
    (`X-CSRF-Token` → `x_csrf_token`), a `_2`/`_3` suffix on collision, never `target`,
    `payload` or `param`. The injection point itself is exempt (its value is the inert
    payload). `bindings` also carries `target` = the attack flow's `scheme://authority`.
  - **Refuse (`Err`, constant text, no value in it)** when a credential cannot be
    parameterised — a path parameter with a credential-like name (`;jsessionid=…`), or a
    non-empty body that is neither form-urlencoded nor a JSON object — and when any
    builder-derived string other than the placeholders it inserted (URL, header value,
    body) contains `{{` or `}}` (the templater has no escape syntax and evaluates
    non-identifier `{{expr}}` with the DSL).
- **Test** (hermetic; attack flows are hand-built `HttpFlow`s with authority
  `127.0.0.1:8080`, scheme `http`):
  - `build_poc_reflected_xss_success_is_the_marker_word`: for `GET
    /search?q=<aitm-canary-0001>` and `def.payloads[0]`, `built.poc.success ==
    Assertion::Word { word: "<aitm-canary-0001>".into(), part: MatchPart::Body }`, the
    single `Step::Http` URL starts with `{{target}}`, and `built.bindings.get("target") ==
    Some(&Value::Str("http://127.0.0.1:8080".into()))`.
  - `build_poc_open_redirect_requires_a_redirect_status`: `built.poc.success` is an
    `Assertion::All` whose first element is literally `Assertion::Any(vec![Status(301),
    Status(302), Status(303), Status(307), Status(308)])` and whose second is an
    `Assertion::Regex { part: MatchPart::Header, regex }` with `regex.contains("aitm-scan-sentinel")`.
  - `build_poc_info`: `poc.info.severity == Severity::Medium` for reflected-XSS and
    `Severity::Low` for open-redirect; `poc.info.tags == vec!["reflected-xss"]`;
    `poc.info.name == "reflected-xss: q"`.
  - `build_poc_credentials_table` (AC24): for each row — header `X-CSRF-Token: abc123` →
    `{{x_csrf_token}}`; header `X-Auth-Token: abc123` → `{{x_auth_token}}`; header
    `Authorization: Bearer abc123` → `{{authorization}}`; header `Cookie: PHPSESSID=abc123` →
    `{{cookie}}`; query `?q=<marker>&access_token=abc123` → `{{access_token}}`; form body
    `password=abc123` → `{{password}}`; JSON body `{"token":"abc123"}` → `{{token}}` —
    `serde_yaml::to_string(&built.poc)` contains the placeholder and not `abc123`, the
    matching `Variable` has `required == true` and `default == None`, and
    `built.bindings` holds the original value (`Bearer abc123` for the Authorization row).
  - `build_poc_refuses_unparameterisable_credentials`: `GET /search;jsessionid=abc123?q=<marker>`,
    a multipart body (`Content-Type: multipart/form-data; boundary=x`, non-empty), and a
    `text/plain` non-empty body each return `Err`, and the error text does not contain
    `abc123`.
  - `build_poc_refuses_template_metacharacters`: a header `X-Note: {{rand_text_alpha(8)}}`
    and a form body `a={{x}}` each return `Err`; the error text does not contain
    `rand_text_alpha`.
  - `build_poc_sanitises_the_param_name`: a query parameter named `"a".repeat(200)` builds,
    `aitm_poc::runner::is_valid_poc_id(&poc.id)` is `true`, and `poc.info.name ==
    format!("reflected-xss: {}", "a".repeat(32))`.
  - `build_poc_keeps_the_payload_in_a_secret_named_point`: an injection point named
    `token` yields a URL containing `token={{payload}}`, no `token` variable, and no
    `token` entry in `bindings`.
- **Done when:** the eight tests pass (each shown failing first) and the full gate passes.

### Task 16: reproduce building blocks (`narrowed_host`, `reproduce`, `finding_record`, `record_finding`) — Wave 2, chain #2

- **Satisfies:** AC22 (the runner's auto-record is inert), AC24 (pre-check, in-memory
  binding), AC32 (record target), AC33 (the replay is guarded), AC10 (record half).
- **Depends on:** Task 4 (same file; uses `BuiltPoc`).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify). Nothing else: every
  `CommandHost` accessor and builder `narrowed_host` needs already exists
  (`crates/aitm-core/src/ctx.rs`: `store/client/guard/browser/frontend/ssrf_policy/poc_dir/
  client_label/egress_handle/config` and `new/with_config/with_ssrf/with_egress/
  with_frontend/with_client_label/with_poc_dir`), so there is no `aitm-core` edit.
- **Change:**
  ```rust
  pub(crate) fn narrowed_host<'a>(host: &'a aitm_core::CommandHost<'_>)
      -> aitm_core::CommandHost<'a>;
  pub async fn reproduce(host: &aitm_core::CommandHost<'_>, built: &BuiltPoc,
      attack_flow: &aitm_core::HttpFlow) -> anyhow::Result<aitm_poc::PocRunResult>;
  pub fn finding_record(host: &aitm_core::CommandHost<'_>,
      def: &crate::checks::CheckDefinition, attack_flow: &aitm_core::HttpFlow,
      poc: &aitm_poc::Poc, run: &aitm_poc::PocRunResult)
      -> aitm_findings::FindingRecord;
  pub fn record_finding(host: &aitm_core::CommandHost<'_>,
      rec: aitm_findings::FindingRecord) -> anyhow::Result<String>;
  ```
  - `narrowed_host` rebuilds a `CommandHost` from `host.store()`, `host.client()`,
    `host.guard()` and carries `frontend()`, `ssrf_policy()` (cloned), `poc_dir()`,
    `client_label()`, `egress_handle()` and `config()` (`Config: Clone`, cloned into a fresh
    `Arc` via `with_config`), but attaches **no finding recorder and no browser** (the PoC
    is HTTP-only). The runner auto-records only when a recorder **and** `findings.dir` are
    present, so with no recorder `recorded_id` is `None` by construction.
  - `reproduce`: (1) serialise `built.poc` (`serde_yaml::to_string`) and return `Err` if
    the YAML contains any value in `built.bindings` other than `target`, or any `Cookie`
    pair value from `attack_flow`'s request, of **4 bytes or more** (shorter values are
    exempt — they would match arbitrary YAML); (2) run `built.poc` through
    `aitm_poc::StdPocRunner` (trait `PocRunner`) on `narrowed_host(host)` with
    `built.bindings`, output directory chosen as `run_poc_command` chooses it
    (`host.config()` `poc.out_dir`, else the temp dir). Exactly one request is sent. It
    does **not** apply the `poc.allow_agent_run` gate (that lives in `run_poc_command`; the
    PoC is scanner-built and HTTP-only, and `scanner.allow_agent_active` governs this phase).
  - `finding_record` builds the `FindingRecord` directly: `id` empty (the store derives
    it), `class = def.class`, `severity = poc.info.severity`, `title = poc.info.name`,
    `target` = the attack request's `scheme://authority/path` with no query, fragment or
    userinfo, through `scrub_text`, `origin = host.frontend()`, `client_label`,
    `poc_ref = poc.id`, `reproduction { passed: run.passed, control_passed: None, run_at:
    now }`, `artifacts` from `run`, `flows = [attack_flow.id, run.finding_capture]`
    (deduplicated, confirming request first), `notes: None`. `control_passed` is always
    `None` (a real target has no patched control; `DiskFindingRecorder` hard-codes the same).
  - `record_finding` builds `DiskFindingStore::new(dir)` from `host.config()`
    `findings.dir` and calls `FindingStore::record(rec)`; with no configured dir it returns
    `Err` (never a fabricated id). It must **never** call `host.finding_recorder()`.
- **Test** (hermetic; a stub `ProxyClient` that returns, and inserts into the store, a flow
  whose body reflects the marker, counting its calls; temp dirs for `findings.dir` and
  `poc.out_dir`; a counting `aitm_core::FindingRecorder` stub):
  - `narrowed_host_keeps_services_and_drops_recorder`: the outer host has
    `.with_frontend(Frontend::Operator)`, `.with_ssrf(SsrfPolicy { block_private: false,
    block_loopback: false, allow_if_in_scope: false })`, `.with_egress(..)`,
    `.with_config(..)` (`findings.dir = tmp`), `.with_client_label("lab")`,
    `.with_finding_recorder(&counting)`; the narrowed host has `frontend() == Operator`,
    `ssrf_policy().block_private == false`, `ssrf_policy().allow_if_in_scope == false`,
    `egress_handle().is_some()`, `config().unwrap().findings.dir == Some(tmp)`,
    `client_label() == Some("lab")`, `finding_recorder().is_none()`, `browser().is_none()`.
  - `reproduce_is_guarded_by_the_real_client` (AC33): host over a real
    `PipelineClient::new(store, Arc::new(StdGuard::default()) /* empty scope */, counting_sender)`;
    `reproduce(..)` returns `Err` whose `downcast_ref::<GuardError>()` is
    `Some(&GuardError::OutOfScope("127.0.0.1:8080".into()))`, and the sender saw `0` requests.
  - `reproduce_does_not_auto_record` (AC22): outer host with `findings.dir = tmp` **and**
    `.with_finding_recorder(&counting)`; after `reproduce(..)`: `run.passed == true`,
    `run.recorded_id == None`, `counting.calls() == 0`, the stub client saw exactly `1` request.
  - `reproduce_binds_credentials_in_memory` (AC24): an attack flow carrying `Authorization:
    Bearer abc123` and `Cookie: PHPSESSID=abc123`: `run.passed == true`; the file at
    `run.poc_path` contains `{{authorization}}` and `{{cookie}}` and not `abc123`; the stub
    saw the request carry `Authorization: Bearer abc123`.
  - `reproduce_refuses_a_poc_containing_a_credential`: a hand-built `BuiltPoc` whose step
    URL contains `abc123` and whose bindings hold `authorization = "Bearer abc123"` (a
    builder-regression stand-in) → `Err`; the stub saw `0` requests.
  - `reproduce_precheck_ignores_values_under_four_bytes`: a hand-built `BuiltPoc` binding
    `x_note = "ab"` with `ab` present in the YAML → `Ok` and `run.passed == true`.
  - `finding_record_fields`: for an attack flow `GET
    http://127.0.0.1:8080/search?q=<aitm-canary-0001>` and a passing `PocRunResult`:
    `rec.target == "http://127.0.0.1:8080/search"`, `rec.class == "reflected-xss"`,
    `rec.severity == Severity::Medium`, `rec.title == "reflected-xss: q"`,
    `rec.reproduction.passed == true`, `rec.reproduction.control_passed == None`,
    `rec.flows == vec![attack_flow.id, run.finding_capture]`.
  - `finding_record_target_has_no_query`: an attack request path `/search?access_token=abc123#f`
    yields `rec.target == "http://127.0.0.1:8080/search"`, and `rec.title` and `rec.target` do
    not contain `abc123`.
  - `record_finding_writes_one_record_and_one_runs_line`: after `record_finding(..)`,
    `DiskFindingStore::new(tmp).list(&FindingFilter::default()).len() == 1`, `runs.jsonl` has
    exactly `1` line, and `counting.calls() == 0`.
  - `record_finding_without_dir_errors`: a host with no `findings.dir` → `Err`, and no file
    is created.
- **Done when:** the ten tests pass (each shown failing first) and the full gate passes.

### Task 17: `reproduce_and_record` (`reproduce.rs`) — Wave 2, chain #3

- **Satisfies:** AC10, AC11, AC12 (zero budget), AC22, AC24 (on-disk places), AC25 (unit),
  AC28, AC29, AC30.
- **Depends on:** Task 16 (same file).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify). Nothing else.
- **Change:**
  ```rust
  pub enum ReproOutcome {
      Recorded { finding_id: String },
      Unreproduced { reason: String },   // scrubbed; nothing recorded
      NoFindingsDir,                     // nothing sent, nothing recorded
      BudgetExhausted,                   // nothing sent, nothing recorded
  }
  pub async fn reproduce_and_record(host: &aitm_core::CommandHost<'_>,
      def: &crate::checks::CheckDefinition, point: &crate::discover::InjectionPoint,
      payload: &str, attack_flow: &aitm_core::HttpFlow, budget: &mut usize)
      -> ReproOutcome;
  ```
  It never returns an error. In order: (1) no `findings.dir` in `host.config()` →
  `NoFindingsDir`; (2) `budget.checked_sub(1)` is `None` → `BudgetExhausted` (budget
  untouched, never wraps); (3) resolve `payload` (the `Confirmed.payload` string) against
  `def.payloads`, then `build_poc` — an `Err` → `Unreproduced` with the message through
  `scrub_text`; (4) decrement `*budget` by one **immediately before calling `reproduce`**,
  so a refused build costs nothing (a pre-check refusal or a run error costs one —
  conservative, a request may have been sent); (5) `reproduce` (credential pre-check, then
  the run) — an `Err` → `Unreproduced` (error text through `scrub_text`); (6) `!run.passed`
  → `Unreproduced("replay did not confirm")` and **no record** (a failed reproduction is not
  a finding: `aitm-findings` records follow a passing run); (7) `finding_record` +
  `record_finding` — an `Err` → `Unreproduced("record failed: …")` (scrubbed); (8)
  `Recorded { finding_id }`. Used by Tasks 8 and 9.
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
  - `zero_budget_does_not_wrap` (AC12, AC25): `budget = 0` → `BudgetExhausted`, `budget == 0`
    afterwards, the stub saw `0` requests.
  - `build_refusal_is_isolated_and_free` (AC29): an attack flow with a header `X-Note: {{x}}`
    → `Unreproduced { reason }` where `reason` does not contain `{{x}}`, `budget == 5`
    unchanged, the stub saw `0` requests.
  - `record_error_is_isolated` (AC29): `findings.dir` set to a path beneath a regular file
    (it cannot be created) → `Unreproduced { reason }` with `reason.starts_with("record
    failed")`, `budget == 4`.
  - `persists_no_credential_table` (AC24, three on-disk places): for each of the eight rows of
    the spec's AC24 table over a reflecting stub: when the outcome is `Recorded`, the PoC YAML at the
    record's `artifacts.poc_path`, the stored finding YAML `<findings.dir>/<id>.yaml` and
    `<findings.dir>/runs.jsonl` all lack `abc123`; for the `;jsessionid=` row the outcome is
    `Unreproduced` and `findings.dir` contains no `*.yaml`.
- **Done when:** the seven tests pass (each shown failing first) and the full gate passes.

### Task 5: injector + correlator engine (`inject.rs`) — Wave 2, independent

- **Satisfies:** AC6 (engine), AC8 (out-of-scope), AC12 (budget), AC26 (i, ii), AC27 (inject
  half).
- **Depends on:** Task 2 (`CheckDefinition`); uses shipped `enumerate` + `client()`.
- **Files:** `crates/aitm-plugin-scanner/src/inject.rs` (create), `lib.rs` (modify —
  `pub mod inject;`).
- **Change:**
  ```rust
  pub const MAX_CONFIRMED: usize = 1024;
  pub struct InjectOutcome { pub class: String, pub tested: usize,
      pub confirmed: Vec<Confirmed>, pub stopped_reason: Option<String> }
  pub struct Confirmed { pub injection_point: crate::discover::InjectionPoint,
      pub payload: String, pub evidence: String,
      pub attack_flow: aitm_core::HttpFlow }
  pub async fn inject(host: &aitm_core::CommandHost<'_>, target: &str,
      def: &crate::checks::CheckDefinition,
      points: &[crate::discover::InjectionPoint], budget: &mut usize,
      cfg: &crate::ScannerConfig) -> anyhow::Result<InjectOutcome>;
  ```
  Gate the target host up front via `host.guard().check_active(authority)?` (→
  `GuardError::OutOfScope` for an unscoped target). Visit the points in order, skipping a
  point whose endpoint key (request method + `scheme://authority/path` + location + name)
  was already injected in this call (first flow wins). For each remaining point, try the
  class payloads in order (batteringram, ≤ `per_class_payload_cap`). Before every send: if
  `budget.checked_sub(1)` is `None`, stop with `stopped_reason = Some("budget")`; if
  `cfg.time_budget` has elapsed since `inject` started, stop with
  `Some("time_budget")`. Send the mutated `HttpRequest` (only the one targeted location
  changes) through `host.client().send` (the guarded chokepoint — inserts the replay flow),
  decrement `budget`, build a `MatchContext` from the response, call `def.confirm`. **On a
  point's first hit push one `Confirmed` — `attack_flow` is the `HttpFlow` `send` returned
  — and skip that point's remaining payloads.** When `confirmed.len()` reaches
  `MAX_CONFIRMED`, stop with `Some("max_confirmed")`. `Confirmed` holds a whole captured
  request: it is never serialised or logged. Reproduction requests are not issued here; the
  caller decrements `budget` for each one (Task 17).
- **Test** (hermetic, stub `ProxyClient` that inserts and returns the flow it builds):
  - `inject_confirms_on_vulnerable`: a stub that reflects the payload marker in the body —
    `confirmed.len() == 1`, `confirmed[0].payload == "<aitm-canary-0001>"`, and
    `confirmed[0].attack_flow.id` equals the id of the flow the stub returned.
  - `inject_empty_on_patched`: a stub that HTML-escapes the marker — `confirmed` is empty and
    `tested == 8`.
  - `inject_stops_a_point_after_its_first_confirmation` (AC27): a reflect-everything stub, one
    `q` point — `confirmed.len() == 1`, `tested == 1`, the stub saw exactly `1` request.
  - `inject_dedupes_repeat_captures` (AC27): two flows with the identical `GET /search?q=`
    endpoint (different ids), reflect-everything stub — `tested == 1`, `confirmed.len() == 1`,
    stub requests `== 1`.
  - `inject_stops_at_budget`: `budget == 1`, patched stub — `tested == 1`, `stopped_reason ==
    Some("budget")`, `budget == 0`.
  - `inject_zero_budget_sends_nothing` (AC12): `budget == 0` — `tested == 0`,
    `stopped_reason == Some("budget")`, the stub saw `0` requests, `budget == 0`.
  - `inject_out_of_scope_refused`: an empty-scope guard — the error downcasts to
    `GuardError::OutOfScope`.
  - `inject_stops_at_time_budget` (AC26 i): `cfg.time_budget == 20 ms`, a stub that sleeps
    100 ms per `send` and never reflects — `tested == 1`, `stopped_reason ==
    Some("time_budget")`.
  - `inject_caps_confirmed` (AC26 ii): `1025` flows with distinct paths (`/p0` … `/p1024`,
    one `q` each, inserted in a `MemFlowStore`), reflect-everything stub, `budget == 2000` —
    `confirmed.len() == 1024`, `tested == 1024`, `stopped_reason == Some("max_confirmed")`.
- **Done when:** the nine tests pass (each shown failing first) and the full gate passes.

### Task 18: third registered class (`checks.rs`) — Wave 2, independent

- **Satisfies:** AC20 (the class registry), AC5 (definition half).
- **Depends on:** Task 2 (shipped; it registers two classes).
- **Files:** `crates/aitm-plugin-scanner/src/checks.rs` (modify). Nothing else.
- **Change:** add
  ```rust
  impl CheckDefinition {
      pub fn registered_classes() -> &'static [&'static str];
      // + one more `pub fn <class>() -> Self` and a `for_class` arm for it
  }
  ```
  `registered_classes()` lists every class `for_class` resolves, in a stable order whose
  first two entries are literally `"reflected-xss"` and `"open-redirect"`. The third class
  is the builder's choice among the four remaining seeded classes (stored-XSS, SSRF, IDOR,
  auth-bypass), under one constraint: it must be confirmable by `confirm(status, body,
  headers, payload)` from **one response to one request** with an inert payload and
  `AttackMode::BatteringRam`. If none of the four fits, **stop and report** (a spec gap);
  do not change `confirm`'s signature. Its payload set is inert and ≤
  `per_class_payload_cap`. It is **not** added to `campaign::DEFAULT_SWEEP` (Open question 2).
- **Test:** `registered_classes_lists_three_or_more` asserts `registered_classes().len() >= 3`,
  `registered_classes()[0] == "reflected-xss"` and `registered_classes()[1] == "open-redirect"`.
  `every_registered_class_resolves` asserts `for_class(c).is_some()` for each and that each
  definition's `payloads.len() <= 25`. `third_class_confirms_and_rejects` asserts, with
  fixtures the builder writes for the chosen class, that `confirm` returns `Some` on its
  vulnerable response and `None` on its patched response.
- **Done when:** the three tests pass (each shown failing first), the shipped Task 2 tests
  still pass, and the full gate passes.

### Task 8: `scan.inject` command + the agent gate + confinement — Wave 4, serial (chain #3)

- **Satisfies:** AC5, AC7, AC8, AC9, AC10, AC11, AC12, AC13, AC18 (partial), AC20 (class
  dispatch), AC21 (the `scan.inject` half), AC22, AC24, AC25, AC27, AC28, AC29, AC30.
- **Depends on:** Tasks 5, 17, 18; **Task 7** (shares `commands.rs`/`plugin.rs`/the contract
  lists). **Needs Matt's answer to Open question 6 before dispatch** (see the Overview).
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
     `CheckDefinition::registered_classes()`; enumerate points from store flows for `target`
     (or the single `injection_point` argument); `let mut budget = self.cfg.request_budget;`
     `block_on(inject(host, target, &def, &points, &mut budget, &self.cfg))`.
  4. For each `Confirmed`, in order: `block_on(reproduce::reproduce_and_record(host, &def,
     &c.injection_point, &c.payload, &c.attack_flow, &mut budget))` and fold the
     `ReproOutcome`: `Recorded { finding_id }` → push onto `finding_ids`, `reproduced: true`;
     `Unreproduced { reason }` → `reproduced: false` and an `unreproduced` entry
     `{injection_point{flow,location,name}, reason}`; `NoFindingsDir` → `reproduced: false`,
     set `reproduction = Str("skipped: no findings.dir")` and stop calling; `BudgetExhausted`
     → `reproduced: false`, an `unreproduced` entry with reason `"budget"`, `stopped_reason =
     Some("budget")`. The loop never propagates a per-confirmation failure with `?`, and the
     command never calls `host.finding_recorder()`.
  5. Return `Value::Object { class, tested, confirmed[{injection_point{flow,location,name},
     payload, evidence, reproduced}], finding_ids, unreproduced, reproduction (Null or the
     marker), stopped_reason }`, scrubbed, arrays capped at `MAX_RESULT_ITEMS` (1024).
  `confirm_prompt` returns `Some(..)`.
  6. Policy layer (Correction 2): in `crates/aitm-mcp/src/server.rs`, add `"scan.inject"` to
     `defers_to_command_gate`. Default for the spec's Open question 6; if Matt answers "leave
     them out", omit this arm and flip the `All` arms of the two policy tests below.
- **Test** (hermetic; reflecting/patched stub clients; each shown failing first):
  - `scan_inject_is_sensitive` asserts `sensitivity() == Sensitive`.
    `scan_inject_confirm_prompt_some` asserts `confirm_prompt(args).is_some()`.
  - `agent_refused_without_flag` builds the host with `Frontend::Mcp` and
    `ScannerConfig{ allow_agent_active: false, .. }`: the error contains
    `scanner.allow_agent_active` and the stub saw `0` requests. `agent_runs_with_flag` with
    `allow_agent_active: true`: `confirmed` is non-empty. `operator_and_cli_always_run`: with
    `Frontend::Operator` and again with `Frontend::Cli`, `allow_agent_active: false`, it runs.
  - `inject_out_of_scope_refused` asserts `GuardError::OutOfScope`.
  - `inject_confined_during_run` — a posture probe like the shipped
    `scan_discover_crawls_under_egress_confinement` — asserts `confined()` was true during the
    send and false after `invoke` returns (AC9).
  - `inject_unknown_class_names_registered_classes`: `class: "nope"` → the error contains
    `reflected-xss` and `open-redirect`.
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
    `finding_ids.len() == 1`, `unreproduced.len() == 1` with a `reason` that does not contain
    `{{x}}`; and a second case with an unwritable `findings.dir` where `reason` starts with
    `record failed`.
  - `inject_failed_replay_is_not_recorded` (AC30): a stub that reflects on the injection request
    but not on the replay: `confirmed.len() == 1`, `confirmed[0].reproduced == false`,
    `finding_ids` empty, `unreproduced.len() == 1`, the store holds `0` records.
  - `inject_budget_exhausted_skips_reproduction` (AC25): `request_budget == 1` with a reflecting
    stub: `confirmed` non-empty, `finding_ids` empty, `unreproduced.len() == 1` with reason
    `budget`, `stopped_reason == Some("budget")`, the stub saw exactly `1` request.
  - `inject_budget_n_plus_one_sends_exact_count` (AC25): two vulnerable points, `request_budget
    == 3`: the stub saw exactly `3` requests, `finding_ids.len() == 1`, `unreproduced.len() ==
    1`, `stopped_reason == Some("budget")`.
  - `inject_leaks_no_credential_anywhere` (AC11, AC24): for each of the eight rows of the spec's
    AC24 table, run `scan.inject` then `scan.report {}` with `findings.dir = tmp`; `abc123` is absent from
    all five of: the PoC YAML at the index entry's `poc_path`, the stored finding YAML
    (`<tmp>/*.yaml`), `<tmp>/runs.jsonl`, the serialised `scan.inject` result, and the
    serialised `scan.report` result; for the `;jsessionid=` row `finding_ids` is empty and
    `unreproduced.len() == 1`.
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

### Stage 4 — campaign + status. AC14–AC20, AC26 (iii), AC31.

### Task 9: campaign engine (`campaign.rs`) — Wave 3, independent of the command chain

- **Satisfies:** AC16 (shared budget), AC20 (default sweep), AC26 (iii), AC31.
- **Depends on:** Tasks 1, 2, 5, 15, 17 (and shipped `crawl`, `report`).
- **Files:** `crates/aitm-plugin-scanner/src/campaign.rs` (create), `lib.rs` (modify —
  `pub mod campaign;`). It does **not** touch `checks.rs` or `inject.rs`.
- **Change:**
  ```rust
  pub const DEFAULT_SWEEP: [&str; 2] = ["reflected-xss", "open-redirect"];
  pub struct CampaignSummary { pub run_id: String, pub phase: String,
      pub pages_crawled: usize, pub requests_used: usize,
      pub confirmed_count: usize, pub stopped_reason: Option<String> }
  pub async fn run_campaign(host: &aitm_core::CommandHost<'_>, target: &str,
      active: bool, cfg: &crate::ScannerConfig)
      -> anyhow::Result<(CampaignSummary, aitm_core::Value)>;
  ```
  One shared `let mut budget = cfg.request_budget;` and one campaign start time across phases:
  discover (`crawl`; it takes no budget argument, so charge `pages_crawled` against `budget`
  with a saturating subtraction when it returns), passive (`passive_checks` over captured
  flows), inject (when `active`: each class in `DEFAULT_SWEEP`, in order — **the default sweep
  is these two classes only; a third registered class is opt-in** — through
  `inject(host, target, &def, &points, &mut budget, &phase_cfg)` where `phase_cfg` is `cfg`
  cloned with `time_budget` set to the campaign's *remaining* time; then each `Confirmed`
  through `reproduce::reproduce_and_record(host, &def, &c.injection_point, &c.payload,
  &c.attack_flow, &mut budget)` with the same fold as `scan.inject` — the spec's `scan.inject`
  step 4 — so the shared `budget` is decremented by every replay), report (`load_records(host,
  Some(target))`, then `render_report`/`render_index`). Returns the summary plus a
  `Value::Object { run_id, discover, passive, inject, report, stopped_reason }` where `inject`
  is `{ classes: [<one scan.inject-shaped result per swept class>], tested, finding_ids:
  [every id], reproduction, stopped_reason }` (with `active == false`: `classes: []`, `tested:
  0`, `finding_ids: []`, `reproduction: Null`). `requests_used = cfg.request_budget - budget`.
- **Test** (hermetic; stub client, stub browser where noted):
  - `campaign_shares_budget` runs with `request_budget == 1` against a reflecting stub and
    asserts `stopped_reason == Some("budget")` and `requests_used <= 1`.
  - `campaign_default_sweep_is_xss_and_open_redirect` (AC20): the store holds a `GET
    /search?q=` flow and a `GET /redirect?next=` flow, and an instrumented stub records the
    classes whose payloads it saw; the set, in order, is exactly `["reflected-xss",
    "open-redirect"]` (a third registered class is never swept), and `DEFAULT_SWEEP ==
    ["reflected-xss", "open-redirect"]`.
  - `campaign_dry_run_skips_inject` with `active == false` asserts the `inject` phase has
    `tested == 0` and `finding_ids` empty, no finding is recorded, and the stub saw no injection
    request.
  - `campaign_inject_phase_reproduces_and_records` (AC31): a store holding one reflecting
    `GET /search?q=` flow, no browser (so discover spends no request), `findings.dir = tmp`,
    `request_budget == 3`: `inject.finding_ids.len() == 1`, the store holds exactly `1` record,
    `summary.requests_used == 2` (one injection, one replay — a missing decrement would read
    `1`), `summary.confirmed_count == 1`.
  - `campaign_time_budget_stops_before_inject` (AC26 iii): `time_budget == 50 ms` and a stub
    browser whose navigation sleeps 100 ms: `summary.stopped_reason == Some("time_budget")` and
    the stub saw `0` injection requests.
- **Done when:** the five tests pass (each shown failing first) and the full gate passes.

### Task 10: `scan.run` + `scan.status` commands — Wave 4, serial (chain #4)

- **Satisfies:** AC14, AC15, AC16, AC17, AC18 (final contract), AC21 (the `scan.run` half).
- **Depends on:** Task 9; **Task 8** (shares `commands.rs`/`plugin.rs`/the contract lists, and
  `crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/mcp.rs` and
  `crates/aitm/tests/scan_agent_gate.rs`, which Task 8 created). **Needs Matt's answer to Open
  question 6 before dispatch.**
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add `ScanRun`,
  `ScanStatus`), `plugin.rs` (modify — register both; hold the status snapshot),
  `crates/aitm/tests/frontends.rs` (modify — `EXPECTED_TOOLS` 59 → 61, add `"scan.run"`,
  `"scan.status"`), `crates/aitm-tui/src/lib.rs` (modify — `CORE_TOOLS` gains both names),
  `crates/aitm-tui/fixtures/bus-fixture.json` (modify — a `scan.run` entry with required
  `target` and optional `active`, and a `scan.status` entry with an optional `run_id`),
  `crates/aitm-tui/tests/tester_shell.rs` (modify — pins 62 → 64),
  `crates/aitm-mcp/src/server.rs` (modify — add the one arm `"scan.run"` to the
  `defers_to_command_gate` match, next to Task 8's `"scan.inject"`),
  `crates/aitm-mcp/tests/mcp.rs` (modify — add a `Sensitive` stub named `scan.run` to
  `policy_server` and the policy test below),
  `crates/aitm/tests/scan_agent_gate.rs` (modify — add the `scan.run` arms).
- **Change:** `ScanRun { cfg: ScannerConfig, status: Arc<Mutex<Option<CampaignSummary>>> }`
  impl `Command`: `name()=="scan.run"`, `sensitivity()==Sensitive`, the same fail-closed agent
  gate + `confirm_prompt` as `ScanInject`, `schema()` required `target`, optional `active: Bool`
  (default per Open question 4). `invoke`: agent gate → `let _confine =
  host.egress_handle().map(|e| e.confine());` → `block_on(run_campaign(host, target, active,
  &self.cfg))` → store the summary in `self.status` **once, after the run returns** (live
  phase-boundary progress and a single-in-flight guard are the spec's Open question 7
  alternative, not v1) → return the campaign `Value`. `ScanStatus { status: Arc<Mutex<..>> }`:
  `sensitivity()==Read`, `confirm_prompt()==None`, returns `Value::Object { run_id, phase,
  pages_crawled, requests_used, request_budget, confirmed_count, stopped_reason }` from the last
  completed snapshot (or `Null`s when none). The shared `status` `Arc` is owned by
  `ScannerPlugin` and cloned into both commands in `load()`. Policy layer (Correction 2): add
  `"scan.run"` to `defers_to_command_gate` in `crates/aitm-mcp/src/server.rs` (default for the
  spec's Open question 6; same fallback as Task 8). `scan.run`'s inject phase already
  reproduces and records through Task 17's function (Task 9), so this task adds no recording
  code.
- **Test:** `scan_run_is_sensitive_and_gated` asserts `sensitivity() == Sensitive` and the agent
  refusal without the flag (error names `scanner.allow_agent_active`). `scan_run_confined`
  asserts `confined()` during the run, released after (AC15). `scan_run_budget_stops` with
  `request_budget == 1` asserts the result `stopped_reason == "budget"` (AC16).
  `scan_status_is_read` asserts `sensitivity() == Read`; `scan_status_reflects_last_run` runs
  `scan.run` then `scan.status` and asserts the status `run_id` matches the run's;
  `scan_status_is_null_before_any_run` asserts every status field is `Value::Null` on a fresh
  plugin (each shown failing first).
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
  run `scan.passive`.
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

- **Satisfies:** AC14, AC16, AC17, AC19, AC31 (end-to-end).
- **Depends on:** Task 10.
- **Files:** `crates/aitm/tests/scan_run_e2e.rs` (create).
- **Change:** (a) assemble the proxy with `ScannerPlugin` loaded, run `scan.run` against the
  seeded loopback target (with `findings.dir` configured and one captured `GET /search?q=seed`
  flow), then `scan.status`; (b) re-run the M4 scripted-driver scenario (or the reduced stand-in
  used by `m4_scripted_e2e.rs`) **with `ScannerPlugin` loaded** and assert it still reproduces its
  seeded vulns (no regression, no new mandatory gate).
- **Test:** `scan_run_campaign_reports_and_status` asserts the `scan.run` result carries
  `discover`/`passive`/`inject`/`report`, that `inject.finding_ids.len() == 1` (the campaign
  reproduced and recorded its confirmation), that `inject` has exactly the keys `classes`,
  `tested`, `finding_ids`, `reproduction`, `stopped_reason`, that each entry of `inject.classes`
  has exactly the keys `class`, `tested`, `confirmed`, `finding_ids`, `unreproduced`,
  `reproduction`, `stopped_reason` (the `scan.inject` shape), and that the subsequent
  `scan.status` `run_id` matches. `free_form_loop_unaffected` asserts the M4 scripted driver
  still records its seeded vulns with the scanner plugin loaded. (Browser-dependent arms
  `#[cfg_attr(not(AITM_OBSCURA), ignore)]`.)
- **Done when:** the gated arms pass under obscura, the non-gated gate is green.

### Task 14: operator docs — Wave 5, independent

- **Satisfies:** documentation for AC7/AC13/AC14/AC17/AC21 (no code AC).
- **Depends on:** Task 10 (final command list).
- **Files:** `crates/aitm-plugin-scanner/README.md` (modify/create), `agent/PLAYBOOK.md` (modify —
  a short `scan.*` note), `crates/aitm/tests/agent_surface.rs` (modify — add `"scan"` to
  `COMMAND_NAMESPACES`, `[&str; 10]` → `[&str; 11]`, so the existing playbook check validates every
  `scan.*` the PLAYBOOK names against the live surface).
- **Change:** document all six `scan.*` commands, their tiers, the `scanner.allow_agent_active`
  gate (and that the integration plan wires its operator toggle), **that an agent also needs the
  MCP agent policy set to `all` (or `ask` with an operator present) in addition to the flag — under
  the default `auto` policy it is refused whatever the flag says** (spec "MCP policy layer"), the
  default caps, that no `findings.dir` means findings are skipped with a marker, and that the
  scanner augments (never gates) the free-form path. The PLAYBOOK note names `scan.discover`,
  `scan.inject` and `scan.run` in inline code spans.
- **Test:** `docs_list_all_commands` (a crate test) asserts the README names all six `scan.*`
  commands, the `allow_agent_active` flag, and the policy `all` requirement.
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
| 2 | chain T4 → T16 → T17 (`reproduce.rs`, T4 also `discover.rs`); T5 `inject.rs`; T15 `report.rs`; T18 `checks.rs` | chain ∥ T5 ∥ T15 ∥ T18 | `reproduce.rs` is written by the three chain tasks → **serial**; `lib.rs` gets one `pub mod` line each from T4 and T5 → **serialize those two one-line edits** (or pre-land both); every other file is distinct |
| 3 | T6 `ScanPassive` → T7 `ScanReport`; T9 `campaign.rs` | T9 ∥ (T6→T7) | T6, T7 share `commands.rs`/`plugin.rs`/`frontends.rs` and the `aitm-tui` family (`CORE_TOOLS`, fixture, `tester_shell.rs`) → **serial**; T9 adds `pub mod campaign;` to `lib.rs` (no other writer in this wave) |
| 4 | T8 `ScanInject` → T10 `ScanRun`+`ScanStatus` | serial | share `commands.rs`/`plugin.rs`/`frontends.rs`, the `aitm-tui` family, **`crates/aitm-mcp/src/server.rs`, `crates/aitm-mcp/tests/mcp.rs`, `crates/aitm/tests/scan_agent_gate.rs`** (T8 adds `scan.inject`'s arm/stub/test; T10 adds `scan.run`'s) |
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
already on `main`. Three `pub mod` lines remain: `reproduce` (T4) and `inject` (T5), both in Wave
2, and `campaign` (T9, Wave 3). Serialize T4's and T5's one-line edits (or have the orchestrator
pre-land both lines); T9's edit has no concurrent writer. The engine *logic* in the new files is
independent regardless.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
