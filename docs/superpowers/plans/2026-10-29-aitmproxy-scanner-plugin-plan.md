# Deterministic scanner plugin implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md`
**Branch / worktree:** `claude/scanner-plugin-scope-6fa7ad`

## Overview

A new `aitm-plugin-scanner` crate adds a deterministic Burp-style active scanner
as plugin-registered `scan.*` commands, with **no edit to `aitm-core`**. Work is
cut into **five independently shippable stages (20 tasks)**: (1) crawl +
injection-point discovery, read/Write, no injection; (2) passive/safe checks,
Read; (3) active injection for 1-2 classes, Sensitive + agent-gated; (4) correlate
→ PoC → findings/report; (5) broaden coverage + the `scan.run` orchestrator +
both-paths composition. Each stage ends with its own gate pass and maps onto a
block of acceptance criteria so Matt can approve stage by stage. Within a stage,
tasks that touch disjoint files are marked **(independent / fan-out)**; the rest
are sequential. The longest sequential chain is T1 → T2 → T4 → T5 (Stage 1) →
T6/T7 (Stage 2) → T9 → T10 → T11 → T12 (Stage 3) → T13 → T14 → T15 → T16 (Stage 4)
→ T17 → T18 → T19 (Stage 5).

**Global constraints (every task):**

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  passes before review (each "Done when" cites it). Default `cargo test` stays
  hermetic; browser-driven crawl/e2e tests are `#[cfg_attr(not(AITM_OBSCURA), ignore)]`.
- **TDD:** no production code without a failing test first; the Coder's report
  shows both runs.
- **No core edits.** Only a new crate, a wiring line in the `aitm` binary, and
  test-only `aitm-testtarget` extensions. If a task finds it must edit
  `aitm-core`'s `Command`/`Flow`/`Event`/guard types, it **stops and reports**.
- **Declared signatures are authoritative;** bodies and private layout are the
  builder's.
- **Reuse, do not reinvent:** correlation via `aitm_poc::matcher::evaluate`; PoC
  via `StdPocBuilder` + the existing `poc.run`; findings via `aitm-findings`;
  crawl via `CommandHost::browser()`; gating via `Sensitivity` + `StdGuard`.

## Tasks

### Stage 1 — crawl + injection-point discovery (read/Write, no injection)

Satisfies **AC1-AC4**. Ends shippable: `scan.discover` crawls and enumerates,
touches only in-scope hosts, injects nothing.

### Task 1: crate skeleton + `ScannerPlugin` + `ScannerConfig`

- **Satisfies:** foundation for AC1-AC4 (no AC proven alone).
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-scanner/Cargo.toml` (create), `crates/aitm-plugin-scanner/src/lib.rs` (create), `crates/aitm-plugin-scanner/src/config.rs` (create), `crates/aitm-plugin-scanner/src/plugin.rs` (create); add the member to the workspace root `Cargo.toml`.
- **Change:** define
  ```rust
  pub struct ScannerConfig { pub max_depth: usize, pub max_pages: usize,
      pub request_budget: usize, pub time_budget: std::time::Duration,
      pub per_class_payload_cap: usize, pub allow_agent_active: bool }
  impl Default for ScannerConfig { /* depth 3, pages 200, budget 2000,
      time 600s, payload cap 25, allow_agent_active false */ }
  pub struct ScannerPlugin { cfg: ScannerConfig }
  impl ScannerPlugin { pub fn new(cfg: ScannerConfig) -> Self }
  impl aitm_core::Plugin for ScannerPlugin {
      fn name(&self) -> &str { "scanner" }
      fn load(&mut self, reg: &mut aitm_core::Registry) { /* no commands yet */ }
  }
  ```
  Depend on `aitm-core`; no behavior beyond construction + empty `load`.
- **Test:** `scanner_config_defaults` asserts `ScannerConfig::default()` has
  `max_depth == 3`, `max_pages == 200`, `request_budget == 2000`,
  `per_class_payload_cap == 25`, `allow_agent_active == false`;
  `plugin_name_is_scanner` asserts `ScannerPlugin::new(ScannerConfig::default()).name() == "scanner"`.
- **Done when:** the tests pass and the full gate passes.

### Task 2: injection-point model + `enumerate`

- **Satisfies:** AC2 (and the data model for AC1).
- **Depends on:** Task 1.
- **Files:** `crates/aitm-plugin-scanner/src/discover.rs` (create); re-export from `lib.rs`.
- **Change:**
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum Location { Query, BodyParam, Header, Cookie, PathSegment, Redirect }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct InjectionPoint { pub flow: aitm_core::FlowId, pub location: Location,
      pub name: String, pub example: String }
  pub fn enumerate(flow: &aitm_core::HttpFlow) -> Vec<InjectionPoint>;
  ```
  Parse the request's query keys, form/JSON body keys, headers, cookies, path
  segments (flag numeric object-ids), and URL-valued params (`Redirect`). Read
  only from the passed flow — **never** call any `aitm_testtarget::manifest`.
- **Test:** `enumerate_finds_query_body_cookie_path` builds an `HttpFlow` with
  `GET /account/2/profile?q=1&next=http://x` and a `Cookie: sid=abc` header and
  asserts the returned set contains exactly `{Query "q", Redirect "next",
  PathSegment "2", Cookie "sid"}` (literal count and names);
  `enumerate_reads_no_manifest` is a source/behavior assertion that `enumerate`
  takes only `&HttpFlow` and the crate's `Cargo.toml` has **no** `aitm-testtarget`
  dependency outside `[dev-dependencies]`.
- **Done when:** tests pass and the full gate passes.

### Task 3: `aitm-testtarget` crawlable linked surface (independent / fan-out)

- **Satisfies:** test fixture for AC1/AC3 (independent of Tasks 2/4; touches only `aitm-testtarget`).
- **Depends on:** Task 1 only nominally (no shared files); **independent** of Tasks 2 and 4.
- **Files:** `crates/aitm-testtarget/src/app.rs` (modify — add an index route + links), `crates/aitm-testtarget/src/seed.rs` (modify only if a new marker is needed).
- **Change:** add a `GET /` index page that links to the existing seeded
  endpoints (`/search?q=`, `/comments`, `/fetch?url=`, `/account/1`, `/admin`,
  `/redirect?next=`) and contains one `<form>` posting to `/search`, so a crawler
  has a link/form graph. Serve the links in **both** `SeedMode`s. Do not change any
  existing route's behavior or marker.
- **Test:** `index_links_all_seeded_endpoints` requests `GET /` and asserts the
  body contains each of the six endpoint paths and one `<form` posting to
  `/search`; `existing_routes_unchanged` re-asserts one existing marker
  (`/search?q=<marker>` still reflects `REFLECTED_XSS_MARKER` in `Vulnerable`).
- **Done when:** tests pass and the full gate passes.

### Task 4: `Crawler` over the browser driver

- **Satisfies:** AC1, AC3 (crawl engine half).
- **Depends on:** Tasks 2, 3.
- **Files:** `crates/aitm-plugin-scanner/src/crawl.rs` (create); re-export from `lib.rs`.
- **Change:**
  ```rust
  pub struct CrawlOutcome { pub endpoints: Vec<String>,
      pub pages_crawled: usize, pub stopped_reason: Option<String> }
  pub async fn crawl(host: &aitm_core::CommandHost<'_>, target: &str,
      cfg: &crate::ScannerConfig) -> anyhow::Result<CrawlOutcome>;
  ```
  Breadth-first from `target`: `navigate` via `host.browser()`, `get_dom`, harvest
  links/forms, enqueue only same-origin URLs where `host.guard().in_scope(host_of(url))`
  is true, dedupe by normalized URL, stop at `max_depth`/`max_pages`/`time_budget`
  (set `stopped_reason`). Each navigation's flow is captured in `host.store()`.
- **Test** (`#[cfg_attr(not(AITM_OBSCURA), ignore)]`): `crawl_walks_in_scope_graph`
  crawls the Task 3 target and asserts `endpoints` contains the six seeded paths
  and `pages_crawled >= 6`; `crawl_skips_out_of_scope` seeds a link to an
  unscoped host and asserts it is absent from `endpoints` and `guard` recorded no
  action for it. A non-gated `crawl_respects_max_pages` unit test over a stub
  `BrowserDriver` asserts `stopped_reason == Some("max_pages")` at the cap.
- **Done when:** the gated tests pass under obscura and the non-gated gate is green.

### Task 5: `scan.discover` command + discovery e2e

- **Satisfies:** AC1, AC2, AC3, AC4.
- **Depends on:** Task 4.
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (create — `ScanDiscover`), `crates/aitm-plugin-scanner/src/plugin.rs` (modify — register it); wire `ScannerPlugin` into the `aitm` binary plugin chain (`crates/aitm/src/...` wiring).
- **Change:**
  ```rust
  struct ScanDiscover { cfg: ScannerConfig }
  impl aitm_core::Command for ScanDiscover {
      fn name(&self) -> &str { "scan.discover" }
      fn sensitivity(&self) -> aitm_core::Sensitivity { aitm_core::Sensitivity::Write }
      fn schema(&self) -> aitm_core::ParamSchema { /* target, max_depth?, max_pages? */ }
      fn invoke(&self, args, host) -> anyhow::Result<aitm_core::Value> { /* crawl + enumerate each flow */ }
  }
  ```
  Result `Value::Object { endpoints, injection_points, pages_crawled, stopped_reason }`.
- **Test:** `scan_discover_is_write` asserts `ScanDiscover.sensitivity() == Write`;
  `scan_discover_out_of_scope_refused` invokes against an unscoped target and
  asserts the error is `GuardError::OutOfScope`; an obscura-gated
  `scan_discover_end_to_end` asserts the result's `endpoints` contains the seeded
  paths and `injection_points` contains the `q` query point.
- **Done when:** the gated test passes under obscura and the non-gated gate is green.

### Stage 2 — passive/safe-check pass (Read)

Satisfies **AC5-AC6**. Ends shippable: `scan.passive` flags reflection/header/
cookie issues over captured flows, issues no traffic.

### Task 6: passive-check library reusing matchers

- **Satisfies:** AC5 (engine half).
- **Depends on:** Task 2.
- **Files:** `crates/aitm-plugin-scanner/src/passive.rs` (create).
- **Change:**
  ```rust
  pub struct PassiveFinding { pub class: String, pub flow: aitm_core::FlowId,
      pub location: Option<Location>, pub evidence: String, pub severity: aitm_poc::Severity }
  pub fn passive_checks(flow: &aitm_core::HttpFlow) -> Vec<PassiveFinding>;
  ```
  Checks: **reflection** (a request param value appears verbatim in the response
  body — via `aitm_poc::matcher::{MatchContext, evaluate}` with a `Word`
  assertion); **security-header** (missing `Content-Security-Policy`/
  `X-Content-Type-Options`/`Strict-Transport-Security`); **cookie-flag**
  (`Set-Cookie` without `Secure`/`HttpOnly`). No network calls.
- **Test:** `passive_flags_reflection` builds a flow whose response body echoes
  `?q=<marker>` and asserts a `reflection` finding naming `q`;
  `passive_flags_missing_csp` asserts a `security-header` finding for a response
  with no CSP; `passive_flags_insecure_cookie` asserts a `cookie-flag` finding for
  `Set-Cookie: sid=1` (no `Secure`).
- **Done when:** tests pass and the full gate passes.

### Task 7: `scan.passive` command

- **Satisfies:** AC5, AC6.
- **Depends on:** Task 6; Task 5 (shares `commands.rs`/`plugin.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — `ScanPassive`), `plugin.rs` (modify — register).
- **Change:** `ScanPassive` → `Sensitivity::Read`; `invoke` runs `passive_checks`
  over `host.store().query(..)` flows for `target` and returns
  `Value::Object { findings: [...] }`. Issues no `client().send`.
- **Test:** `scan_passive_is_read` asserts `sensitivity() == Read`;
  `scan_passive_issues_no_traffic` records `host.store().count()` before/after and
  asserts it is unchanged; `scan_passive_finds_reflection` seeds a reflecting flow
  in the store and asserts the result `findings` contains a `reflection` entry.
- **Done when:** tests pass and the full gate passes.

### Task 8: Stage-2 e2e over captured flows

- **Satisfies:** AC5 (end-to-end), AC6.
- **Depends on:** Task 7.
- **Files:** `crates/aitm-plugin-scanner/tests/passive_e2e.rs` (create).
- **Change:** seed the store from real captured flows against the test target
  (hermetic: craft flows, no browser needed) and run `scan.passive`.
- **Test:** `passive_e2e_flags_seeded_issues` asserts the structured result flags
  the reflected `q` param and a missing `Content-Security-Policy` header (literal
  classes `reflection` and `security-header` present).
- **Done when:** tests pass and the full gate passes.

### Stage 3 — active injection for 1-2 classes (Sensitive, gated)

Satisfies **AC7-AC10**. First classes: **reflected-XSS + open-redirect**
(Open question 1). Ends shippable: `scan.inject` confirms on vulnerable, not on
patched, and is operator-gated.

### Task 9: payload sets + `CheckDefinition` for the first classes

- **Satisfies:** AC7 (payload/definition half).
- **Depends on:** Task 2.
- **Files:** `crates/aitm-plugin-scanner/src/checks.rs` (create).
- **Change:**
  ```rust
  pub enum AttackMode { BatteringRam }       // Stage 5 adds Pitchfork, ClusterBomb
  pub struct Payload { pub value: String, pub marker: Option<String> }
  pub struct Evidence { pub payload: String, pub matched: String }
  pub struct CheckDefinition { pub class: &'static str,
      pub locations: &'static [Location], pub payloads: Vec<Payload>, pub mode: AttackMode }
  impl CheckDefinition {
      pub fn confirm(&self, resp_status: u16, body: &str, headers: &[(String,String)],
          payload: &Payload) -> Option<Evidence>;   // builds an aitm_poc::Assertion + matcher::evaluate
      pub fn reflected_xss() -> Self;
      pub fn open_redirect() -> Self;
  }
  ```
  `reflected_xss().confirm` evaluates `Assertion::Word { word: marker, part: Body }`;
  `open_redirect().confirm` evaluates a `Regex`/`Dsl` over the `Location` header.
  Payload lists are capped at `per_class_payload_cap`.
- **Test:** `reflected_xss_confirms_on_reflection` asserts `confirm` returns
  `Some(Evidence)` when the body contains the injected marker and `None`
  otherwise; `open_redirect_confirms_on_location` asserts `Some` when `Location`
  points at the attacker host and `None` when it is same-origin.
- **Done when:** tests pass and the full gate passes.

### Task 10: injector + correlator engine

- **Satisfies:** AC7, AC8 (engine half), AC10.
- **Depends on:** Tasks 5 (discovery), 9.
- **Files:** `crates/aitm-plugin-scanner/src/inject.rs` (create).
- **Change:**
  ```rust
  pub struct InjectOutcome { pub class: String, pub tested: usize,
      pub confirmed: Vec<Confirmed>, pub stopped_reason: Option<String> }
  pub struct Confirmed { pub injection_point: InjectionPoint, pub payload: String, pub evidence: String }
  pub async fn inject(host: &aitm_core::CommandHost<'_>, target: &str,
      def: &CheckDefinition, points: &[InjectionPoint], cfg: &ScannerConfig) -> anyhow::Result<InjectOutcome>;
  ```
  For each applicable point × payload (batteringram), craft the mutated request
  and send via `host.client().send(..)` (the guarded chokepoint), build a
  `MatchContext` from the response, call `def.confirm`, and collect `Confirmed`.
  Honor `request_budget` (set `stopped_reason == "budget"`) and call
  `host.guard().record_error` on transport errors.
- **Test:** `inject_confirms_on_vulnerable` (obscura/hermetic with a stub client
  returning a reflecting response) asserts `confirmed` is non-empty;
  `inject_empty_on_patched` asserts `confirmed` is empty against an escaping
  response; `inject_stops_at_budget` asserts `stopped_reason == Some("budget")`
  with `request_budget == 1`; `inject_out_of_scope_refused` asserts
  `GuardError::OutOfScope` surfaces for an unscoped target.
- **Done when:** tests pass and the full gate passes.

### Task 11: `scan.inject` command + the agent gate

- **Satisfies:** AC9 (the deny-by-default gate), AC7.
- **Depends on:** Task 10; Task 7 (shares `commands.rs`/`plugin.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — `ScanInject`), `plugin.rs` (modify — register with `cfg.allow_agent_active`).
- **Change:** `ScanInject { allow_agent_active: bool, cfg: ScannerConfig }` →
  `Sensitivity::Sensitive`. `invoke` refuses when
  `host.frontend() == Frontend::Mcp && !self.allow_agent_active` (same shape as
  `ScopeAdd`), else runs `inject` for the requested `class` and returns
  `Value::Object { class, tested, confirmed, stopped_reason }`. `confirm_prompt`
  returns a non-`None` operator question (active injection).
- **Test:** `scan_inject_is_sensitive` asserts `sensitivity() == Sensitive`;
  `agent_refused_without_flag` invokes with `Frontend::Mcp` and
  `allow_agent_active == false` and asserts a refusal error naming
  `scanner.allow_agent_active`; `agent_runs_with_flag` invokes with the flag set
  and asserts it reaches the engine; `operator_always_runs` invokes with
  `Frontend::Operator` and `allow_agent_active == false` and asserts it runs.
- **Done when:** tests pass and the full gate passes.

### Task 12: Stage-3 injection e2e (vulnerable vs patched)

- **Satisfies:** AC8 (end-to-end), AC10.
- **Depends on:** Tasks 3, 11.
- **Files:** `crates/aitm-plugin-scanner/tests/inject_e2e.rs` (create).
- **Change:** run `scan.inject {class: "reflected-xss"}` against a
  `SeedMode::Vulnerable` test target and a `SeedMode::Patched` one.
- **Test** (`#[cfg_attr(not(AITM_OBSCURA), ignore)]`):
  `inject_confirms_vulnerable_only` asserts `confirmed` is non-empty against
  vulnerable and empty against patched (literal); `inject_e2e_stays_in_scope`
  asserts an out-of-scope target refuses with `OutOfScope`.
- **Done when:** the gated test passes under obscura and the non-gated gate is green.

### Stage 4 — correlate → PoC → findings/report

Satisfies **AC11-AC13**. Ends shippable: a confirmed vuln becomes a reproduced,
recorded finding with a report.

### Task 13: PoC emit from a confirmation

- **Satisfies:** AC11 (build half).
- **Depends on:** Task 10.
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (create).
- **Change:**
  ```rust
  pub fn build_poc(flow: &aitm_core::HttpFlow, def: &CheckDefinition,
      point: &InjectionPoint, payload: &Payload) -> anyhow::Result<aitm_poc::Poc>;
  ```
  Assemble a `PocSpec { info, variables, success }` where `success` is the
  confirming `Assertion`, and call `aitm_poc::StdPocBuilder::default().build(flow, spec)`.
- **Test:** `build_poc_sets_success_assertion` asserts the returned `Poc.success`
  is the class's confirming assertion and the base URL is parameterized to a
  `{{target}}`-style variable (round-trips through `aitm_poc` serde).
- **Done when:** tests pass and the full gate passes.

### Task 14: record finding + reproduction run

- **Satisfies:** AC11 (record half), AC13.
- **Depends on:** Task 13.
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify), `crates/aitm-plugin-scanner/src/commands.rs` (modify — `scan.inject` records on confirm).
- **Change:**
  ```rust
  pub fn record_finding(store: &dyn aitm_findings::FindingStore,
      rec: aitm_findings::FindingRecord) -> anyhow::Result<String>;
  ```
  On a confirmation, run the PoC via the existing `poc.run` path against the
  vulnerable target and the patched control and build a `FindingRecord` with
  `reproduction: Reproduction { passed, control_passed }`, then
  `store.record(..)`. Relies on `FindingStore::record`'s existing redaction.
- **Test:** `record_sets_reproduction` asserts the recorded `FindingRecord` has
  `reproduction.passed == true` and `control_passed == Some(false)`;
  `record_redacts_secret` records a finding whose source flow carried an
  `Authorization` header and asserts the stored record/title contains no secret.
- **Done when:** tests pass and the full gate passes.

### Task 15: `scan.report` command

- **Satisfies:** AC12.
- **Depends on:** Task 14; Task 11 (shares `commands.rs`/`plugin.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — `ScanReport`), `plugin.rs` (modify — register).
- **Change:** `ScanReport` → `Sensitivity::Read`; `invoke` reads the findings for
  `target`, calls `aitm_findings::render_report(&records)` and
  `render_index(&records)`, and returns `Value::Object { report_md, index }`.
- **Test:** `scan_report_one_section_per_finding` records N findings and asserts
  the rendered `report_md` has N sections (each naming its class/target) and the
  `index` has N entries carrying `poc_path`; `scan_report_is_read` asserts
  `sensitivity() == Read`.
- **Done when:** tests pass and the full gate passes.

### Task 16: Stage-4 full-loop e2e

- **Satisfies:** AC11, AC12, AC13 (end-to-end).
- **Depends on:** Tasks 12, 15.
- **Files:** `crates/aitm-plugin-scanner/tests/loop_e2e.rs` (create).
- **Change:** discover → inject → confirm → build+run PoC → record → report
  against the vulnerable target + patched control.
- **Test** (`#[cfg_attr(not(AITM_OBSCURA), ignore)]`): `loop_reproduces_and_reports`
  asserts a `FindingRecord` exists with `passed == true` / `control_passed ==
  Some(false)` and `scan.report` renders one section for it; `loop_leaks_no_secret`
  asserts no secret appears in the report.
- **Done when:** the gated test passes under obscura and the non-gated gate is green.

### Stage 5 — broaden coverage + `scan.run` + both-paths

Satisfies **AC14-AC17**. Ends shippable: multi-class campaign, orchestrator, and
proof the free-form M4 loop still works with the scanner loaded.

### Task 17: broaden classes + payload modes

- **Satisfies:** AC14, AC17.
- **Depends on:** Task 10.
- **Files:** `crates/aitm-plugin-scanner/src/checks.rs` (modify), `crates/aitm-plugin-scanner/src/inject.rs` (modify).
- **Change:** add `CheckDefinition`s for the remaining already-seeded classes
  (stored-XSS, SSRF, IDOR, auth-bypass — Open question 5), and add
  `AttackMode::{Pitchfork, ClusterBomb}` to the injector, all bounded by
  `request_budget` and `per_class_payload_cap`.
- **Test:** `clusterbomb_respects_budget` asserts total `tested` ≤ `request_budget`
  for a two-position cross-product under a small budget;
  `coverage_has_at_least_three_classes` asserts ≥ 3 `CheckDefinition`s are
  registered (literal count).
- **Done when:** tests pass and the full gate passes.

### Task 18: `scan.run` campaign orchestrator + `scan.status`

- **Satisfies:** AC15, AC17.
- **Depends on:** Tasks 15, 17.
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify — `ScanRun`, `ScanStatus`), `plugin.rs` (modify — register), `crates/aitm-plugin-scanner/src/campaign.rs` (create — orchestration + budget accounting).
- **Change:** `ScanRun` → `Sensitivity::Sensitive` (+ the same `allow_agent_active`
  gate as `scan.inject`); orchestrates discover → passive → inject → report under
  one shared `request_budget`/`time_budget`, returning
  `Value::Object { discover, passive, inject, report, stopped_reason }`.
  `ScanStatus` → `Read`.
- **Test:** `scan_run_is_sensitive_and_gated` asserts `sensitivity() == Sensitive`
  and the agent refusal without the flag; `scan_run_budget_stops` asserts a tiny
  budget yields `stopped_reason == Some("budget")`;
  `scan_status_is_read` asserts `sensitivity() == Read`.
- **Done when:** tests pass and the full gate passes.

### Task 19: both-paths composition e2e

- **Satisfies:** AC16.
- **Depends on:** Tasks 16, 18.
- **Files:** `crates/aitm-plugin-scanner/tests/both_paths_e2e.rs` (create).
- **Change:** load `ScannerPlugin` into a wired registry and prove (a) the scanner
  commands are present in the `tools/list` and return structured results when
  called by an agent-role host, and (b) the M4 free-form path is unaffected —
  re-run the M4 scripted-driver scenario (or a reduced stand-in) with
  `ScannerPlugin` loaded and assert it still finds + records the seeded vulns.
- **Test:** `scanner_tools_exposed` asserts `scan.discover`/`scan.inject`/
  `scan.report` are in the registry's command list; `free_form_loop_unaffected`
  asserts the M4 scripted driver still reproduces its seeded vulns with the
  scanner plugin loaded (no regression, no new mandatory gate).
- **Done when:** the gated test passes under obscura and the non-gated gate is green.

### Task 20: operator docs + caps/gate reference (independent / fan-out)

- **Satisfies:** documentation for AC9/AC14/AC17 (no code AC).
- **Depends on:** Task 18 (for the final command list); **independent** of Task 19.
- **Files:** `crates/aitm-plugin-scanner/README.md` (create) and a short `scan.*`
  section note added to `agent/PLAYBOOK.md` describing the scanner as an optional
  tool the free-form loop may call.
- **Change:** document the six commands, their tiers, the `scanner.allow_agent_active`
  gate, and the default caps; state explicitly that the scanner augments (never
  gates) the free-form path.
- **Test:** `docs_list_all_commands` (a crate test) asserts the README names all
  six `scan.*` commands and the `allow_agent_active` flag.
- **Done when:** the test passes and the full gate passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
