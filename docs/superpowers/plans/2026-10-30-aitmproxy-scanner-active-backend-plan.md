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

The crate splits cleanly into **engine library modules** (one new file each →
fan out) and a **command-registration chain** (every command lives in
`commands.rs`, registers in `plugin.rs`, and bumps `crates/aitm/tests/frontends.rs`
`EXPECTED_TOOLS` — so command tasks are strictly serial among themselves: two
writers never share a file). E2e/integration tests are separate files → fan out at
the end. Tasks are grouped into **waves** the orchestrator dispatches in parallel.

**Dependency spine (longest chain):** T1/T2/T4 → T5 (inject engine) → T8
(ScanInject cmd, after the T6/T7 command chain) → T9 (campaign) → T10 (ScanRun/
ScanStatus cmds) → T13 (both-paths e2e).

**Waves:**

- **Wave 1 (fan-out, independent):** T1 `passive.rs`, T2 `checks.rs`,
  T3 `report.rs`.
- **Wave 2 (fan-out, independent):** T4 `reproduce.rs`, T5 `inject.rs`.
- **Wave 3 (serial command chain begins + campaign engine):** T6 `ScanPassive`,
  then T7 `ScanReport` (share `commands.rs`); T9 `campaign.rs` (engine, independent
  of the command chain, may run parallel to T6/T7).
- **Wave 4 (serial command chain continues):** T8 `ScanInject`, then T10
  `ScanRun`+`ScanStatus` (share `commands.rs`).
- **Wave 5 (fan-out, independent tests):** T11 passive hermetic e2e, T12 inject
  live e2e, T13 both-paths/campaign e2e, T14 docs.

**Global constraints (every task):**

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test` passes before review (each "Done when" cites it). Default `cargo
  test` hermetic; browser-dependent tests `#[cfg_attr(not(AITM_OBSCURA), ignore)]`.
- **TDD:** failing test first; the Coder's report shows both runs.
- **No core edits.** Only the shipped `aitm-plugin-scanner` crate, plus
  `crates/aitm/tests/frontends.rs` (contract) and new tests under
  `crates/aitm/tests/`. If a task finds it must edit an `aitm-core` type, it
  **stops and reports**. It must **not** edit `wire.rs`/`config_file.rs` for the
  `allow_agent_active` flag (integration plan D-MCP2 owns that).
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
      pub fn open_redirect() -> Self;   // Regex over the Location header; location Redirect
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
  records, filtered to `target` when given. `index_to_value` maps
  `serde_json::Value` → `aitm_core::Value` (object/array/scalars).
- **Test:** `load_records_empty_without_dir` builds a `CommandHost` with no config
  and asserts `load_records(&host, None).is_empty()`. `index_to_value_round_trips`
  asserts `index_to_value(serde_json::json!([{"class":"x","passed":true}]))` is an
  `aitm_core::Value::Array` of one object whose `"class"` is `Value::Str("x")` and
  `"passed"` is `Value::Bool(true)`.
- **Done when:** both tests pass and the full gate passes.

### Task 6: `scan.passive` command — Wave 3, serial (command chain #1)

- **Satisfies:** AC2, AC3, AC18 (contract, partial).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanPassive`), `plugin.rs` (modify — register), `crates/aitm/tests/frontends.rs`
  (modify — `EXPECTED_TOOLS` 56 → 57, add `"scan.passive"`).
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
  asserts no `abc123` anywhere in the result.
- **Done when:** the tests pass, `frontends.rs` contract passes, and the full gate
  passes.

### Task 7: `scan.report` command — Wave 3, serial (command chain #2)

- **Satisfies:** AC4, AC18 (contract, partial).
- **Depends on:** Task 3; **Task 6** (shares `commands.rs`/`plugin.rs`/`frontends.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanReport`), `plugin.rs` (modify), `crates/aitm/tests/frontends.rs` (modify —
  `EXPECTED_TOOLS` 57 → 58, add `"scan.report"`).
- **Change:** `ScanReport { }` impl `Command`: `name()=="scan.report"`,
  `sensitivity()==Read`, `confirm_prompt()==None`, `schema()` optional `target`.
  `invoke` = `let recs = report::load_records(host, target);` returns
  `Value::Object { "report_md": Str(render_report(&recs)), "index":
  report::index_to_value(render_index(&recs)) }`.
- **Test:** `scan_report_is_read` asserts `sensitivity() == Read`.
  `scan_report_one_section_per_finding` writes N records to a temp
  `DiskFindingStore`, wires it via `host.config()` findings dir, and asserts
  `report_md` contains N `"## "` section headers and `index` is an `Array` of N
  objects each carrying `poc_path`/`class`/`passed`.
- **Done when:** tests pass, contract passes, full gate passes.

---

### Stage 3 — active injection, reproduce, record (Sensitive, gated). AC5–AC13.

### Task 4: reproduce + record (`reproduce.rs`) — Wave 2, independent

- **Satisfies:** AC10 (build/record half), AC11 (record redaction).
- **Depends on:** Task 2 (`CheckDefinition`).
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (create), `lib.rs` (modify).
- **Change:**
  ```rust
  pub fn build_poc(flow: &aitm_core::HttpFlow, def: &crate::checks::CheckDefinition,
      point: &crate::discover::InjectionPoint, payload: &crate::checks::Payload)
      -> anyhow::Result<aitm_poc::Poc>;
  pub fn record_finding(host: &aitm_core::CommandHost<'_>,
      rec: aitm_findings::FindingRecord) -> anyhow::Result<String>;
  ```
  `build_poc` assembles `aitm_poc::PocSpec { info: PocInfo{ name, severity, .. },
  variables, success }` where `success` is `def`'s confirming `Assertion`, then
  `aitm_poc::StdPocBuilder::default().build(flow, spec)`. `record_finding`
  constructs `DiskFindingStore::new(dir)` from the configured `findings.dir` and
  calls `FindingStore::record(rec)` (empty dir → `Ok` no-op id or an explicit
  `bail!`, builder's call); it never copies a param value or raw header into
  `rec.title`/`rec.notes`.
- **Test:** `build_poc_sets_success_assertion` builds a PoC for `reflected_xss()`
  and asserts `poc.success` is the class's confirming `Assertion` and the step URL
  is parameterized to a `{{target}}` variable (round-trips via `aitm_poc` serde).
  `record_round_trips` writes a `FindingRecord` with `reproduction { passed: true,
  control_passed: Some(false), .. }` to a temp dir and asserts `FindingStore::get`
  returns it with those fields. `record_redacts_secret` records a finding whose
  source flow carried `Authorization: Bearer abc123` and asserts the stored
  record's `title`/`notes` contain no `abc123`.
- **Done when:** the three tests pass and the full gate passes.

### Task 5: injector + correlator engine (`inject.rs`) — Wave 2, independent

- **Satisfies:** AC6 (engine), AC8 (out-of-scope), AC12 (budget).
- **Depends on:** Task 2 (`CheckDefinition`); uses shipped `enumerate` + `client()`.
- **Files:** `crates/aitm-plugin-scanner/src/inject.rs` (create), `lib.rs` (modify).
- **Change:**
  ```rust
  pub struct InjectOutcome { pub class: String, pub tested: usize,
      pub confirmed: Vec<Confirmed>, pub stopped_reason: Option<String> }
  pub struct Confirmed { pub injection_point: crate::discover::InjectionPoint,
      pub payload: String, pub evidence: String }
  pub async fn inject(host: &aitm_core::CommandHost<'_>, target: &str,
      def: &crate::checks::CheckDefinition,
      points: &[crate::discover::InjectionPoint], budget: &mut usize,
      cfg: &crate::ScannerConfig) -> anyhow::Result<InjectOutcome>;
  ```
  Gate the target host up front via `host.guard().check_active(authority)?`
  (→ `GuardError::OutOfScope` for an unscoped target). For each applicable point ×
  payload (batteringram, ≤ `per_class_payload_cap`): craft the mutated
  `HttpRequest` (mutate only the one targeted `Location`), `host.client().send(req)`
  (the guarded chokepoint — inserts the replay flow), build a `MatchContext` from
  the response, call `def.confirm`, push `Confirmed` on a hit. Decrement `budget`
  per send; at 0 stop with `stopped_reason = Some("budget")`.
- **Test** (hermetic, stub `ProxyClient`): `inject_confirms_on_vulnerable` — a stub
  client that reflects the payload marker in the body — asserts `confirmed` is
  non-empty. `inject_empty_on_patched` — a stub that HTML-escapes/omits the marker
  — asserts `confirmed` is empty. `inject_stops_at_budget` with `budget == 1`
  asserts `tested == 1` and `stopped_reason == Some("budget")`.
  `inject_out_of_scope_refused` with an empty-scope guard asserts the error
  downcasts to `GuardError::OutOfScope`.
- **Done when:** the four tests pass and the full gate passes.

### Task 8: `scan.inject` command + the agent gate + confinement — Wave 4, serial (chain #3)

- **Satisfies:** AC5, AC7, AC8, AC9, AC10, AC11, AC12, AC13, AC18 (partial).
- **Depends on:** Tasks 4, 5; **Task 7** (shares `commands.rs`/`plugin.rs`/`frontends.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add
  `ScanInject`), `plugin.rs` (modify — register with `self.cfg.clone()`),
  `crates/aitm/tests/frontends.rs` (modify — `EXPECTED_TOOLS` 58 → 59, add
  `"scan.inject"`; update any confirmable-tools list that fails).
- **Change:** `ScanInject { cfg: ScannerConfig }` impl `Command`:
  `name()=="scan.inject"`, `sensitivity()==Sensitivity::Sensitive`,
  `schema()` with required `target: Str`, `class: Str`, optional `injection_point`.
  `invoke`:
  1. **Agent gate:** `if host.frontend() == Frontend::Mcp && !self.cfg.allow_agent_active
     { bail!("scan.inject refused: … Set scanner.allow_agent_active = true …") }`.
  2. `let _confine = host.egress_handle().map(|e| e.confine());`.
  3. `let def = CheckDefinition::for_class(class).ok_or_else(..)?;` enumerate points
     from store flows for `target`; `let mut budget = self.cfg.request_budget;`
     `block_on(inject(host, target, &def, &points, &mut budget, &self.cfg))`.
  4. For each `Confirmed`: `build_poc` + record via `reproduce::record_finding`
     (vulnerable `passed`; patched `control_passed` best-effort) → collect
     `finding_ids`.
  5. Return `Value::Object { class, tested, confirmed[{injection_point{flow,
     location,name}, payload, evidence}], finding_ids, stopped_reason }`, scrubbed.
  `confirm_prompt` returns `Some(..)`.
- **Test:** `scan_inject_is_sensitive` asserts `sensitivity() == Sensitive`.
  `scan_inject_confirm_prompt_some` asserts `confirm_prompt(args).is_some()`.
  `agent_refused_without_flag` builds the host with `Frontend::Mcp` and
  `ScannerConfig{ allow_agent_active: false, .. }` and asserts the error string
  contains `scanner.allow_agent_active`. `agent_runs_with_flag` with
  `allow_agent_active: true` asserts it reaches the engine (reflecting stub client
  → non-empty `confirmed`). `operator_always_runs` with `Frontend::Operator` and
  `allow_agent_active: false` asserts it runs. `inject_out_of_scope_refused`
  asserts `GuardError::OutOfScope`. `inject_confined_during_run` — a posture probe
  browser/stub like the shipped `scan_discover_crawls_under_egress_confinement` —
  asserts `confined()` was true during the send and false after `invoke` returns
  (AC9). `inject_result_redacts` asserts no `abc123` from an `Authorization` source
  flow in the result (AC11).
- **Done when:** all tests pass, the `frontends.rs` contract passes, the full gate
  passes.

---

### Stage 4 — campaign + status. AC14–AC20.

### Task 9: campaign engine (`campaign.rs`) — Wave 3, independent of the command chain

- **Satisfies:** AC16 (shared budget), AC20 (≥ 3 classes swept).
- **Depends on:** Tasks 1, 2, 4, 5 (and shipped `crawl`, `report`).
- **Files:** `crates/aitm-plugin-scanner/src/campaign.rs` (create), `lib.rs` (modify).
- **Change:**
  ```rust
  pub struct CampaignSummary { pub run_id: String, pub phase: String,
      pub pages_crawled: usize, pub requests_used: usize,
      pub confirmed_count: usize, pub stopped_reason: Option<String> }
  pub async fn run_campaign(host: &aitm_core::CommandHost<'_>, target: &str,
      active: bool, cfg: &crate::ScannerConfig)
      -> anyhow::Result<(CampaignSummary, aitm_core::Value)>;
  ```
  One shared `let mut budget = cfg.request_budget;` across phases: discover
  (`crawl`), passive (`passive_checks` over captured flows), inject (when `active`,
  over the default-active classes — reflected-XSS + open-redirect — decrementing the
  **same** `budget`), report (`render_report`/`render_index`). Returns the summary
  plus a `Value::Object { run_id, discover, passive, inject, report, stopped_reason }`.
  AC20: the inject phase iterates ≥ 3 registered `CheckDefinition`s (add a third
  seeded class, builder's choice from Open question 2) with batteringram; add
  `AttackMode::ClusterBomb` to `checks.rs`/`inject.rs` for multi-position classes,
  still bounded by the shared `budget`.
- **Test:** `campaign_shares_budget` runs with `request_budget == 1` against a
  reflecting stub and asserts the returned summary `stopped_reason == Some("budget")`
  and `requests_used <= 1`. `campaign_sweeps_three_classes` asserts ≥ 3 classes are
  attempted (literal count of distinct `class` values touched, via an instrumented
  stub). `campaign_dry_run_skips_inject` with `active == false` asserts the `inject`
  phase result is empty/`tested == 0` and no finding is recorded.
- **Done when:** the three tests pass and the full gate passes.

### Task 10: `scan.run` + `scan.status` commands — Wave 4, serial (chain #4)

- **Satisfies:** AC14, AC15, AC16, AC17, AC18 (final contract).
- **Depends on:** Task 9; **Task 8** (shares `commands.rs`/`plugin.rs`/`frontends.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — add `ScanRun`,
  `ScanStatus`), `plugin.rs` (modify — register both; hold the status snapshot),
  `crates/aitm/tests/frontends.rs` (modify — `EXPECTED_TOOLS` 59 → 61, add
  `"scan.run"`, `"scan.status"`).
- **Change:** `ScanRun { cfg: ScannerConfig, status: Arc<Mutex<Option<CampaignSummary>>> }`
  impl `Command`: `name()=="scan.run"`, `sensitivity()==Sensitive`, same agent gate
  + `confirm_prompt` as `ScanInject`, `schema()` required `target`, optional
  `active: Bool` (default per Open question 4). `invoke`: agent gate →
  `let _confine = host.egress_handle().map(|e| e.confine());` →
  `block_on(run_campaign(host, target, active, &self.cfg))` → store the summary in
  `self.status` → return the campaign `Value`. `ScanStatus { status: Arc<Mutex<..>> }`:
  `sensitivity()==Read`, `confirm_prompt()==None`, returns
  `Value::Object { run_id, phase, pages_crawled, requests_used, request_budget,
  confirmed_count, stopped_reason }` from the snapshot (or `Null`s when none). The
  shared `status` `Arc` is owned by `ScannerPlugin` and cloned into both commands in
  `load()`.
- **Test:** `scan_run_is_sensitive_and_gated` asserts `sensitivity() == Sensitive`
  and the agent refusal without the flag (error names `scanner.allow_agent_active`).
  `scan_run_confined` asserts `confined()` during the run, released after (AC15).
  `scan_run_budget_stops` with `request_budget == 1` asserts the result
  `stopped_reason == "budget"` (AC16). `scan_status_is_read` asserts
  `sensitivity() == Read`; `scan_status_reflects_last_run` runs `scan.run` then
  `scan.status` and asserts the status `run_id` matches the run's.
- **Done when:** tests pass, the `frontends.rs` contract passes (`[&str; 61]`),
  the full gate passes.

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

- **Satisfies:** AC6, AC8, AC10 (end-to-end).
- **Depends on:** Task 8.
- **Files:** `crates/aitm/tests/inject_e2e.rs` (create — lives in the `aitm`
  integration-test crate, beside `discover_e2e.rs`, to reach `aitm::wire::assemble`
  without a crate-graph cycle).
- **Change:** spin `aitm-testtarget` in `SeedMode::Vulnerable` and `SeedMode::Patched`
  on loopback, scope the host, and run `scan.inject {class: "reflected-xss"}`
  through the assembled proxy's `PipelineClient` (no browser → **not**
  obscura-gated; it binds a loopback port, which the real gate/Terminal panel
  allows).
- **Test:** `inject_confirms_vulnerable_only` asserts `confirmed` is non-empty
  against vulnerable and empty against patched, and a `FindingRecord` exists with
  `reproduction.passed == true` / `control_passed == Some(false)`.
  `inject_e2e_out_of_scope` asserts an unscoped target refuses with
  `GuardError::OutOfScope`.
- **Done when:** the tests pass (loopback bind) and the full gate passes.

### Task 13: campaign + both-paths e2e — Wave 5, independent

- **Satisfies:** AC14, AC16, AC17, AC19 (end-to-end).
- **Depends on:** Task 10.
- **Files:** `crates/aitm/tests/scan_run_e2e.rs` (create).
- **Change:** (a) assemble the proxy with `ScannerPlugin` loaded, run `scan.run`
  against the seeded loopback target, then `scan.status`; (b) re-run the M4
  scripted-driver scenario (or the reduced stand-in used by `m4_scripted_e2e.rs`)
  **with `ScannerPlugin` loaded** and assert it still reproduces its seeded vulns
  (no regression, no new mandatory gate).
- **Test:** `scan_run_campaign_reports_and_status` asserts the `scan.run` result
  carries `discover`/`passive`/`inject`/`report` and the subsequent `scan.status`
  `run_id` matches. `free_form_loop_unaffected` asserts the M4 scripted driver
  still records its seeded vulns with the scanner plugin loaded. (Browser-dependent
  arms `#[cfg_attr(not(AITM_OBSCURA), ignore)]`.)
- **Done when:** the gated arms pass under obscura, the non-gated gate is green.

### Task 14: operator docs — Wave 5, independent

- **Satisfies:** documentation for AC7/AC13/AC14/AC17 (no code AC).
- **Depends on:** Task 10 (final command list).
- **Files:** `crates/aitm-plugin-scanner/README.md` (modify/create) and a short
  `scan.*` note in `agent/PLAYBOOK.md`.
- **Change:** document all six `scan.*` commands, their tiers, the
  `scanner.allow_agent_active` gate (and that the integration plan wires its
  operator toggle), the default caps, and that the scanner augments (never gates)
  the free-form path.
- **Test:** `docs_list_all_commands` (a crate test) asserts the README names all
  six `scan.*` commands and the `allow_agent_active` flag.
- **Done when:** the test passes and the full gate passes.

---

## Independence / wave map

| Wave | Tasks | Parallel? | Shared-file bottleneck |
|---|---|---|---|
| 1 | T1 `passive.rs`, T2 `checks.rs`, T3 `report.rs` | fully independent | none (distinct new files; each also touches `lib.rs` re-export — **coordinate the `lib.rs` edits or serialize the one-line re-export adds**) |
| 2 | T4 `reproduce.rs`, T5 `inject.rs` | independent of each other | `lib.rs` re-export only |
| 3 | T6 `ScanPassive` → T7 `ScanReport`; T9 `campaign.rs` | T9 ∥ (T6→T7) | T6,T7 share `commands.rs`/`plugin.rs`/`frontends.rs` → **serial** |
| 4 | T8 `ScanInject` → T10 `ScanRun`+`ScanStatus` | serial | share `commands.rs`/`plugin.rs`/`frontends.rs` |
| 5 | T11, T12, T13, T14 | fully independent | distinct test/doc files |

**Note on `lib.rs`:** T1–T5 and T9 each add a one-line `pub use`/`pub mod` to
`lib.rs`. To keep two writers off one file, either (a) land a tiny pre-task that
adds all six `pub mod`/`pub use` lines up front, or (b) serialize only the `lib.rs`
touch within each wave. The orchestrator's call; the engine *logic* in the new
files is independent regardless.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
