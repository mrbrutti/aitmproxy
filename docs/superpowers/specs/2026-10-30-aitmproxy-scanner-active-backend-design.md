# Scanner active backend (passive / report / inject / run / status) design

**Status:** draft
**Research inputs:** `docs/research/05-synthesis.md`;
`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md` (the
authoritative scope design — command surface, tiering, the two-layer agent gate,
caps, correlation-stays-internal); `docs/superpowers/plans/2026-10-29-aitmproxy-scanner-plugin-plan.md`;
the **shipped** Stage-1 crate on `main`
(`crates/aitm-plugin-scanner/src/{lib,plugin,commands,config,crawl,discover}.rs`,
PR #67) and its Wave-1 additions (`passive.rs`, `checks.rs`, `report.rs`);
egress confinement (`crates/aitm-core/src/egress.rs`, `ctx.rs`
`CommandHost::egress_handle`, `client.rs` `PipelineClient::send`); the gate to
mirror (`crates/aitm-core/src/config.rs` `poc.allow_agent_run`,
`crates/aitm-poc/src/runner.rs` `run_poc_command`, `crates/aitm/src/config_file.rs`
`PocFile`); the reuse seams (`aitm-poc` `matcher`/`model`/`builder`/`runner`,
`aitm-findings` `record`/`report`/`store`/`recorder`); the seeded target
(`crates/aitm-testtarget/src/{app,manifest,seed}.rs`); the MCP policy layer
(`crates/aitm-mcp/src/server.rs`); and the operator-surface integration design/plan
(`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-integration-design.md`,
`…/plans/2026-10-29-aitmproxy-scanner-integration-plan.md`) whose UI tasks consume
these verbs.

Code references are to `main` at `78405c3`, by file and symbol (line numbers drift).
Two statements in the 2026-10-29 scope design/plan are superseded here: its AC11
clause `control_passed == Some(false)` (see "Reproduce → record") and its sentence
"under `All` it reaches `invoke`" (see "MCP policy layer").

## Intent

Stage 1 shipped: `scan.discover` crawls an in-scope target and enumerates
injection points, deny-by-default, scope- and budget-bound, with egress
confinement and redaction (PR #67). This design completes the deterministic
scanner's backend for a **v0.6** release (v0.5 ships discovery-only): the five
remaining `scan.*` verbs — `scan.passive`, `scan.report`, `scan.inject`,
`scan.run`, `scan.status` — built **entirely by extending the shipped
`aitm-plugin-scanner` crate**, reusing the shipped `ScannerConfig`,
`ScannerPlugin`, `enumerate`/`InjectionPoint`/`Location`, and `crawl`, and reusing
the `aitm_poc` matcher/builder/runner vocabulary and `aitm-findings` store/report —
with **no edit to `aitm-core`**. The active verbs (`scan.inject`, `scan.run`) carry
the scope design's two-layer agent gate and hold an egress-confinement token for the
whole active phase, so every byte of attack traffic stays inside the authorized
scope. We want it now because every seam is shipped and verified: the
active-request chokepoint (`PipelineClient::send` → `check_active`), the RAII
confinement handle (`CommandHost::egress_handle`), the matcher/PoC/findings crates,
and the seeded Vulnerable/Patched test target.

## Goals

- **`scan.passive {target?}`** (**Read**) evaluates passive checks — reflection,
  missing/weak security headers, insecure cookie flags — over flows **already in
  the store**, reusing `aitm_poc::matcher::evaluate`, issuing **no** new traffic,
  and returns a structured `{ findings: [...] }`.
- **`scan.report {target?}`** (**Read**) folds recorded findings into a human
  report and a machine index via `aitm_findings::{render_report, render_index}`,
  returning `{ report_md, index }`.
- **`scan.inject {target, class, injection_point?}`** (**Sensitive**) injects a
  bounded per-class payload set into discovered injection points through the single
  guarded client chokepoint (`host.client().send` → `check_active`), correlates
  internally with `matcher::evaluate` to confirm, builds a reproducible PoC via
  `StdPocBuilder`, reproduces it through `StdPocRunner` (not through the `poc.run`
  command), records one `FindingRecord` per *reproduced* confirmation, and returns
  a structured per-attempt result. First classes: **reflected-XSS + open-redirect**
  (both seeded).
- **`scan.run {target, active?}`** (**Sensitive**) orchestrates discover → passive
  → inject → report as one campaign under **one shared budget**, holding an egress
  token for the whole run, reproducing and recording through the same function as
  `scan.inject`, and returns a structured campaign summary with a `run_id`.
- **`scan.status {run_id?}`** (**Read**) returns the last completed campaign's phase
  and counters.
- **Deny-by-default, fail-closed.** `scan.inject`/`scan.run` are `Sensitive` and
  refuse every caller except the operator/CLI unless `scanner.allow_agent_active` is
  set — the analogue of `poc.allow_agent_run`, with a fail-closed check (see "Agent
  gate summary"). The `Sensitive` policy tier and the flag are independent layers,
  and the policy layer needs an explicit `defers_to_command_gate` entry per verb
  before the flag is reachable under `AgentPolicy::All` (see "MCP policy layer").
- **Scope-confined active egress.** `scan.inject`/`scan.run` hold a
  `ConfinementToken` (`CommandHost::egress_handle().map(|e| e.confine())`) across
  the whole active phase, exactly as the shipped `scan.discover` does for its
  crawl, so any browser use stays scope-confined and the token is released
  (RAII) on return, error, or unwind.
- **Resource-bounded.** Reuse the shipped `ScannerConfig` caps and the guard's
  rate / concurrency / per-host back-off (enforced inside `PipelineClient::send`).
  `scan.inject` and `scan.run` enforce the request budget, the time budget and a
  cap on confirmations; `scan.run` shares one budget across all phases.
- **One finding per vulnerable point, never a false one.** At most one
  confirmation is reproduced and recorded per (class, injection point), and only a
  replay that passes is recorded.
- **Correlation stays internal** (no `scan.correlate` verb); it is returned as
  structured evidence inside `scan.inject`/`scan.run` results.
- **UI-ready result shapes.** The verb names, argument schemas, and `Value::Object`
  result keys match what the integration plan's UI tasks (T5–T14) consume.

## Non-goals

- Not the scanner engine's Stage 1 (`scan.discover` is shipped); this design does
  not re-open crawl or enumeration except to call them.
- Not the operator UIs. The three UI surfaces (web/TUI/macOS) and the MCP
  contract/config wiring are the **integration** plan's job; this design produces
  the backend verbs and their result shapes the UI consumes, and keeps the
  workspace tool-contract tests green.
- No LLM / model call anywhere in the crate (deterministic heuristics + static
  payload sets only).
- No new matcher DSL, PoC format, findings model, scope model, rate limiter, or
  SSRF classifier — all reused unchanged.
- No out-of-band (Interactsh-style) collaborator; blind/OOB classes stay out of
  scope (scope spec §Non-goals).
- No remediation prose; findings, PoC, and structured results only.
- Follow-ups, deliberately not in v0.6: an operator-editable payload dictionary
  (nuclei-style YAML directory, e.g. `scanner.payloads_dir`) instead of Rust-literal
  payload sets; the `ClusterBomb` multi-position attack mode (only `BatteringRam`
  ships); Stage-5 breadth (more classes than the three registered); live
  phase-boundary progress and a single-in-flight guard for `scan.run` (Open question
  7); and a replay-method policy for non-idempotent requests (Open question 9).

## Anti-goals

- A scanner that **issues an active request to an out-of-scope host from any
  caller**. Every injected and replayed request goes through `host.client().send` →
  `check_active`; an out-of-scope host is refused with `GuardError::OutOfScope`.
- An **agent** running active injection with the flag off, or an active phase that
  runs with egress *unconfined* while a browser could follow a redirect/sub-resource
  off scope.
- An **unbounded** campaign: an inject pass or a `scan.run` that ignores the
  request/time budget, wraps a zero budget around, lets a tarpit target stall it
  indefinitely, or returns an unbounded result.
- A finding, report, PoC file, or structured result that **leaks a secret** (auth
  header, cookie, token, session id) that passed through a scanned request.
- Any edit to `aitm-core`'s `Command`/`Flow`/`Event`/`ProtocolModule`/guard types,
  or a parallel re-implementation of a shipped scanner type (`ScannerConfig`,
  `InjectionPoint`, `Location`, `enumerate`, `crawl`) instead of extending it.
- `scanner.allow_agent_active = true` silently doing nothing for an agent because
  the MCP policy gate was never told `scan.inject`/`scan.run` carry their own
  per-command gate (under `AgentPolicy::All` a `Sensitive` command not in
  `defers_to_command_gate` is refused by policy before its own flag is consulted;
  see Open question 6 for the posture choice).
- **More than one finding record per vulnerable point**, whether from the runner's
  auto-record plus the scanner's own, or from one reproduction per payload hit.
- **Recording a failed reproduction as a finding**: `aitm-findings` records follow a
  passing run.
- A **production** `control_passed` that claims a patched-control comparison the
  scanner cannot perform against a real target.
- One bad confirmation (a hostile request body, an unwritable findings directory)
  **aborting the call** and discarding the confirmations already found.

## Constraints

- **Language/gate:** Rust. `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test` must pass before any review (each task's "Done when"
  cites it). Default `cargo test` stays hermetic: no real browser, no live
  external network. Browser-dependent tests are `#[cfg_attr(not(AITM_OBSCURA),
  ignore)]`.
- **No `aitm-core` edits (hard).** Extend the shipped `aitm-plugin-scanner` crate and
  its registration. Reach core services only through `CommandHost` (`store()`,
  `client()`, `guard()`, `browser()`, `frontend()`, `config()`, `egress_handle()`,
  `ssrf_policy()`, `poc_dir()`, `client_label()`; **not** `finding_recorder()` — the
  scanner deliberately never records through that seam, see "Reproduce → record").
  No `CommandHost` accessor is missing: `egress_handle()` already exists and is used
  by `scan.discover`, and the narrowed host the reproduction step needs is rebuilt
  from existing accessors and builders. A task that finds it must edit an
  `aitm-core` type **stops and reports**.
- **Production edits outside the scanner crate (exhaustive list).** Both are lists,
  not `aitm-core` types:
  1. **`aitm-mcp`:** one match arm per gated verb (`scan.inject`, `scan.run`) in
     `defers_to_command_gate` (`crates/aitm-mcp/src/server.rs`), the same category
     as the existing `scope.add` entry — subject to Open question 6.
  2. **`aitm-tui`:** each registered `scan.*` name is added to `CORE_TOOLS`
     (`crates/aitm-tui/src/lib.rs`), because `crates/aitm/tests/tui_live_bus.rs`
     asserts every live tool is in it; its fixture entry
     (`crates/aitm-tui/fixtures/bus-fixture.json`) and the tool-count pins in
     `crates/aitm-tui/tests/tester_shell.rs` change with it (PR #67 did exactly this
     for `scan.discover`).
  Everything else outside the crate is a test or doc file.
- **Confinement is RAII.** `EgressConfinement::confine()` returns a
  `ConfinementToken` that holds the hold until dropped (refcounted on the shared
  `Arc`); the active phase relies on the drop, never on `set_base`.
- **Active chokepoint.** `PipelineClient::send` already calls
  `self.guard.check_active(&req.authority)?`, holds the permit across the send,
  records errors toward the host back-off, and inserts the replay flow. The
  injector and the reproduction both send through `host.client().send` and add no
  second network path; the injector additionally gates the target host up front
  (deny-by-default, like the crawl seed) so an out-of-scope target is refused before
  enumeration. A single request may take up to the sender's 60-second response
  timeout (`RESPONSE_TIMEOUT` in `crates/aitm-proto-http/src/sender.rs`), so a time
  budget can overshoot by at most one request.
- **Reuse, do not reinvent:** correlation via `aitm_poc::matcher::{MatchContext,
  evaluate}` + `Assertion`; PoC via `aitm_poc::{StdPocBuilder, PocSpec, Poc,
  PocInfo, Variable, Severity}` and run via `aitm_poc::{StdPocRunner, PocRunner,
  PocRunResult, VarBindings}`; findings via `aitm_findings::{FindingRecord,
  Reproduction, FindingArtifacts, DiskFindingStore, FindingStore, FindingFilter,
  render_report, render_index}`; redaction via `aitm_core::redact::{scrub_text,
  is_secret_key}` plus the shipped `discover` secret-name predicate.
- **Workspace contract lists.** Registering each new command changes the live
  `tools/list`. Three lists fail the workspace gate unless updated in the same task
  that registers the command: the exact-match `EXPECTED_TOOLS` in
  `crates/aitm/tests/frontends.rs` (`[&str; 56]` today), and the `aitm-tui` family
  — `CORE_TOOLS`, `bus-fixture.json` and the `tools.len()` pins in `tester_shell.rs`
  (59 today). Any other workspace list that fails because a `scan.*` name was added
  is updated in the same task.
- **Test target.** `aitm-testtarget` already serves the linked index surface and
  all six seeded classes with `SeedMode::{Vulnerable, Patched}` (reflected-XSS
  `/search?q=`, open-redirect `/redirect?next=`, stored-XSS `/comments`, SSRF
  `/fetch?url=`, IDOR `/account/{id}`, auth-bypass `/admin`). No test-target change
  is required.

## Design

**Provenance.** A closed draft (PR #84, "backend Stages 2-5 design spec", branch
`claude/scanner-backend-scope`) made three corrections that this design carries after
re-verifying each against the code at `78405c3`: (1) **true** — reproduction runs
`StdPocRunner`, not the `poc.run` command; (2) **partly true** — the MCP policy gate
needs `scan.inject`/`scan.run` in `defers_to_command_gate` under `All` and `Auto`,
but "no observable effect under any policy" overstates it (under `Ask` an approved
call reaches the command's own gate regardless), and adding the entry is a posture
choice (Open question 6); (3) **true** — `control_passed` is `None` in every
production record. Each is specified once, in place: "Reproduce → record" and "MCP
policy layer".

### Shipped ground truth this design builds on (read at `78405c3`)

| Shipped API (exact) | Where | How this design uses it |
|---|---|---|
| `ScannerConfig { max_depth, max_pages, request_budget, time_budget, per_class_payload_cap, allow_agent_active }`, `Default` = (3, 200, 2000, 600 s, 25, false) | `config.rs` | Reused as-is; the agent gate reads `allow_agent_active`; `request_budget`/`time_budget`/`per_class_payload_cap` bound inject + run. **No field added.** |
| `ScannerPlugin::new(cfg)`; `Plugin::load(&mut self, reg)` → `reg.add_command(Arc::new(..))` | `plugin.rs` | `load` extended to register the five new commands, each holding a clone of `self.cfg`. |
| `enumerate(&HttpFlow) -> Vec<InjectionPoint>`; `InjectionPoint { flow, location, name, example }`; `Location { Query, BodyParam, Header, Cookie, PathSegment, Redirect }` (redaction built in); private `is_secret_name` | `discover.rs` | The injector enumerates points from store flows exactly as `scan.discover` does; `example` is already redacted. `is_secret_name` becomes `pub(crate)` and is the one credential-name predicate (PoC builder). |
| `crawl(host, target, cfg) -> CrawlOutcome { endpoints, pages_crawled, stopped_reason }`; `normalize_url`, `block_on`; `MAX_RESULT_ITEMS = 1024` (in `commands.rs`) | `crawl.rs`, `commands.rs` | `scan.run`'s discover phase calls `crawl`; the sync commands call `block_on`; result arrays are capped at 1024 as `scan.discover` caps them. |
| `CheckDefinition { class, locations, payloads, mode }` with `confirm`, `reflected_xss()`, `open_redirect()`, `for_class`, `pub(crate) success_assertion`; two registered classes; reflected-XSS payloads are `<aitm-canary-0001>`…`<aitm-canary-0008>` | `checks.rs` | The class registry. `success_assertion` is the PoC's `success` for reflected-XSS. Gains `registered_classes()` and a third class. |
| `load_records(host, target?)` (exact-match `FindingFilter.target`, empty without `findings.dir`), `index_to_value` | `report.rs` | `scan.report`'s read half; its target filter changes (see "`scan.report`"). |
| `CommandHost::{store, client, guard, browser, frontend, config, egress_handle, ssrf_policy, poc_dir, client_label, finding_recorder}`; builders `new`, `with_config(Arc<Config>)`, `with_ssrf`, `with_egress`, `with_frontend`, `with_client_label`, `with_poc_dir`, `with_finding_recorder`; no `Registry` field; `Frontend` is `#[non_exhaustive]` (`Cli`, `Mcp`, `Operator`) | `ctx.rs` | All service access (except `finding_recorder`). `config()` yields `Option<&Config>`; `Config: Clone`. |
| `EgressConfinement::confine(self: &Arc<Self>) -> ConfinementToken` (RAII, refcounted) | `egress.rs` | Active phase: `let _confine = host.egress_handle().map(|e| e.confine());`. |
| `PipelineClient::new(store, guard, sender)`; `send` gates `check_active`, holds permit, records errors, inserts replay flow | `client.rs` | The one network path for injection and replay. |
| `Command` trait: `name`, `schema() -> ParamSchema`, `invoke(args, host) -> Result<Value>`, `sensitivity()`, `confirm_prompt(&Params) -> Option<String>`, `mutates`, `summarize` | `command.rs` | New commands implement these; `scan.inject`/`scan.run` override `confirm_prompt`. |
| `run_poc_command`'s gate: `host.frontend() == Frontend::Mcp && !config.poc.allow_agent_run` → `bail!`; `Operator`/`Cli` never gated | `aitm-poc` `runner.rs` | The shape `scanner.allow_agent_active` follows (with a fail-closed expression, see "Agent gate summary"). |
| `MatchContext::new(status, body).with_header(..)`; `evaluate(&Assertion, &MatchContext) -> bool`; `Assertion::{Status, Word{word,part}, Regex{regex,part}, Dsl, All, Any, Not}`; `MatchPart::{Body, Header, All}`; the DSL has `==`, `!=`, `&&`, `\|\|`, `!` (no ordering operators) | `aitm-poc matcher/model/dsl` | Correlation, passive checks, and the PoC's `success`. |
| `StdPocBuilder::build(&HttpFlow, PocSpec{info, variables, success}) -> Poc`; `PocInfo { name, severity, references, tags, cwe, description, author, metadata }` (no `Default`); `Variable { name, default, description, required }`; `Severity`. The builder redacts only the headers `Cookie`, `Authorization`, `Proxy-Authorization`, `X-API-Key` to required default-less `{{var}}` placeholders; URL path/query, body and every other header are carried verbatim; the PoC id is `slug(info.name)` | `aitm-poc builder/model` | PoC emit on confirm; the scanner's own hardening sits on top (see "Building the PoC"). |
| `PocRunner::run(&self, &Poc, VarBindings, &CommandHost) -> BoxFuture<Result<PocRunResult>>`; `StdPocRunner::{new, with_output_dir}`; `PocRunResult { passed, finding_capture, poc_path, screenshot_path, evaluated, recorded_id }`. `run_inner` runs `precheck` (PoC id must match `^[a-z0-9][a-z0-9-]{0,63}$`), renders `{{expr}}` placeholders (a non-identifier expression is evaluated by the DSL; an unbound identifier fails with "unknown variable"; there is **no escape syntax**), writes the YAML to a private (0700/0600) directory whether or not the run passed, and auto-records through `host.finding_recorder()` only when the run **passed** and a recorder **and** `findings.dir` are present | `runner.rs`, `template.rs` | The reproduction engine; the auto-record is the double-record hazard. |
| `FindingDraft` and `DiskFindingRecorder` (hard-codes `control_passed: None`, `notes: None`; the runner fills `class` from `poc.info.cwe`, else the first tag, else the PoC id) | `aitm-core ctx.rs`; `aitm-findings recorder.rs`; `runner.rs` | Why the scanner does not record through the runner's auto-record. |
| `FindingStore::record` redacts only `title` and `notes`; `FindingFilter::matches` compares `target` exactly; `render_report`/`render_index` count a finding "reproduced" only for `control_passed == Some(false)`; the test-target grader likewise, and matches a finding to a planted vuln by `class` and the **path** of `finding.target` | `aitm-findings store/record/report`; `aitm-testtarget grader.rs` | Record `target` rule; consequence of `control_passed: None`. |
| `findings.dir` defaults to `None`; with none, `findings.list` is empty and `findings.record` errors | `aitm-core config.rs` | Default installs have no findings directory (see "Failure handling"). |
| `policy_decision`: `(All, Sensitive) => defers_to_command_gate(name)`; `(Auto, Sensitive) => false`; `(Ask, Sensitive)` parks for operator approval, then runs the command as the agent. `defers_to_command_gate` lists `ca.install`, `ca.uninstall`, `scope.add` and the `l4.*` Sensitive verbs; `script.save` is deliberately absent | `aitm-mcp server.rs`; tests in `aitm-mcp tests/mcp.rs` | The policy layer in front of `scanner.allow_agent_active`. |
| Contract lists: `EXPECTED_TOOLS: [&str; 56]` (includes `scan.discover`) in `frontends.rs`; `CORE_TOOLS` (includes `scan.discover`), `bus-fixture.json` and the `59` pins in `tester_shell.rs`; `COMMAND_NAMESPACES` in `agent_surface.rs` lists ten namespaces and **not** `scan` | `crates/aitm/tests`, `crates/aitm-tui` | Bump targets: `EXPECTED_TOOLS` → `[&str; 61]`, TUI family → 64. |
| Seeded target: `SeedMode::{Vulnerable, Patched}`, routes incl. `/search?q=`, `/redirect?next=`, linked `/` index | `aitm-testtarget` | Confirmation pass-on-vulnerable / fail-on-patched. |

### Module layout

```
crates/aitm-plugin-scanner/src/
  passive.rs    (shipped)  PassiveFinding, passive_checks(&HttpFlow) -> Vec<PassiveFinding>
  checks.rs     (shipped; modify)  + registered_classes(), + a third registered class
  report.rs     (shipped; modify)  load_records filters by origin + path prefix
  discover.rs   (shipped; modify)  is_secret_name -> pub(crate); no behaviour change
  inject.rs     (new)  MAX_CONFIRMED, InjectOutcome, Confirmed, inject(..)
  reproduce.rs  (new)  BuiltPoc, build_poc, narrowed_host, reproduce, finding_record,
                       record_finding, ReproOutcome, reproduce_and_record
  campaign.rs   (new)  DEFAULT_SWEEP, CampaignSummary, run_campaign(..)
  commands.rs   (modify) add ScanPassive, ScanReport, ScanInject, ScanRun, ScanStatus
  plugin.rs     (modify) register the five commands
  lib.rs        (modify) pub mod reproduce; pub mod inject; pub mod campaign
```

`ScannerPlugin` continues to observe no events. Engine modules are pure library
code with their own files, so independent tasks fan out; the command structs all
live in `commands.rs` + register in `plugin.rs` + bump the contract lists, so they
form one serialized chain.

### `scan.passive` — Read, no traffic

`passive_checks(flow: &HttpFlow) -> Vec<PassiveFinding>` runs three deterministic
checks over one captured flow, reusing matchers where a match is the natural
expression:

- **reflection** — for each request param (from `enumerate`), a `Word { word:
  value, part: Body }` assertion over the response body via `evaluate`; a hit is a
  `reflection` finding naming the param. (The *value* is only used to build the
  matcher; it is never echoed into the finding — see redaction.)
- **security-header** — a missing `Content-Security-Policy`,
  `X-Content-Type-Options`, or `Strict-Transport-Security` on the response is a
  `security-header` finding.
- **cookie-flag** — a `Set-Cookie` lacking `Secure` or `HttpOnly` is a
  `cookie-flag` finding.

```
pub struct PassiveFinding { pub class: String, pub flow: FlowId,
    pub location: Option<Location>, pub name: Option<String>,
    pub evidence: String, pub severity: aitm_poc::Severity }
pub fn passive_checks(flow: &aitm_core::HttpFlow) -> Vec<PassiveFinding>;
```

`ScanPassive` (`Sensitivity::Read`) iterates `host.store().list()` filtered to
`target` (when given, same-origin/in-scope via `crawl::normalize_url`), runs
`passive_checks`, and returns `{ findings: [ {class, flow, location, name,
evidence, severity} ] }`. It calls **no** `client().send` and **no** browser —
flow count is unchanged across the call, so it runs under `AgentPolicy::ReadOnly`.
Every string in the result is passed through `scrub_text`; a finding never carries
a param *value* (only its name + the class/location), so a reflected secret is not
re-leaked. Passive findings are not persisted and do not appear in `scan.report`
(Open question 8).

### `scan.report` — Read

`report::load_records(host, target?) -> Vec<FindingRecord>` builds a
`DiskFindingStore::new(dir)` from `host.config().findings.dir` (returning an empty
list, not an error, when no dir is configured) and lists/gets the records.
`ScanReport` (`Sensitivity::Read`) returns `{ report_md: Str, index: Array }` where
`report_md = render_report(&records)` and `index` is `render_index(&records)`
**converted** from `serde_json::Value` to `aitm_core::Value` (a small local
converter; `render_index` returns serde_json). Index entries carry `poc_path`,
`target_path`, `class`, `passed`, `control_passed`, `finding_capture`,
`screenshot_path` (render_index's shape), which the UI's Findings fold consumes.

**`target` filter.** A record matches `target` when its `target` URL has the same
scheme, host and effective port as the argument and its path equals, or extends on a
`/` boundary, the argument's path (an empty or `/` path matches every path); query and
fragment are ignored on both sides, and a default port equals an absent one. An
argument that does not parse as an absolute URL matches only a record whose `target`
is exactly equal. `FindingFilter.target` is an exact string match and so cannot relate
a campaign base URL (`http://host:8080`) to a recorded endpoint
(`http://host:8080/search`); `load_records` therefore lists with an empty
`FindingFilter` and applies this rule itself. This is why the recorded `target` can be
an endpoint (see "Record target") while `scan.report {target: <campaign base>}` still
finds it.

### `scan.inject` — Sensitive, agent-gated, scope-confined

`checks.rs` defines one static definition per class:

```
pub enum AttackMode { BatteringRam }
pub struct Payload { pub value: String, pub marker: Option<String> }
pub struct Evidence { pub payload: String, pub matched: String }
pub struct CheckDefinition {
    pub class: &'static str,
    pub locations: &'static [Location],
    pub payloads: Vec<Payload>,
    pub mode: AttackMode,
}
impl CheckDefinition {
    pub fn confirm(&self, status: u16, body: &str, headers: &[(String, String)],
        payload: &Payload) -> Option<Evidence>;   // builds an Assertion + evaluate
    pub fn reflected_xss() -> Self;   // Word{ marker, Body }, locations Query/BodyParam
    pub fn open_redirect() -> Self;   // 3xx + Regex over the Location header, location Redirect
    pub fn for_class(class: &str) -> Option<Self>;
    pub fn registered_classes() -> &'static [&'static str];  // >= 3; first two are the default sweep
}
```

`registered_classes()` lists every class `for_class` resolves, in a stable order whose
first two entries are literally `"reflected-xss"` and `"open-redirect"`; the third is
the opt-in class that fills AC20 (builder's choice, see "Left to the builder").

`inject.rs`:

```
pub const MAX_CONFIRMED: usize = 1024;
pub struct InjectOutcome { pub class: String, pub tested: usize,
    pub confirmed: Vec<Confirmed>, pub stopped_reason: Option<String> }
pub struct Confirmed { pub injection_point: InjectionPoint,
    pub payload: String, pub evidence: String,
    pub attack_flow: aitm_core::HttpFlow }   // the flow `send` returned for the confirming request
pub async fn inject(host: &CommandHost<'_>, target: &str, def: &CheckDefinition,
    points: &[InjectionPoint], budget: &mut usize, cfg: &ScannerConfig)
    -> anyhow::Result<InjectOutcome>;
```

`inject` gates the target host up front (`host.guard().check_active` →
`GuardError::OutOfScope` on an unscoped target, deny-by-default). It then visits the
applicable points in order, skipping a point whose endpoint key — request method,
`scheme://authority/path`, location and name — was already injected in this call (a
repeat capture of one endpoint is one point; first flow wins). For each remaining
point it tries the class payloads in order (batteringram, capped at
`per_class_payload_cap`): before every send it stops if the budget is zero
(`stopped_reason = "budget"`, via `checked_sub`, never wrapping) or if `cfg.time_budget`
has elapsed since `inject` started (`"time_budget"`); it crafts the mutated
`HttpRequest` (only the one targeted point changes), sends it through
`host.client().send` (the one guarded chokepoint), builds a `MatchContext` from the
returned flow's response, calls `def.confirm`, and decrements the shared `budget`.
**On a point's first confirmation it records one `Confirmed` and skips that point's
remaining payloads** (a reflect-everything parameter is one finding, and the saved
payloads are saved attack traffic). It stops with `stopped_reason = "max_confirmed"`
when `confirmed.len()` reaches `MAX_CONFIRMED`. Payload *strings* are inert,
class-appropriate markers (reflected-XSS uses a benign unique canary element, not an
executing script; open-redirect uses an off-origin sentinel host under `.invalid`
compared in `Location`).

*Architect's call — `Confirmed` carries the `HttpFlow`, not its id.* The PoC is built
from the request that actually carried the payload (the benign source flow in
`injection_point.flow` does not contain it), and `send` already hands that flow back.
Carrying it removes a store re-fetch that FIFO eviction (the store keeps 50 000 flows
or 512 MiB) or `flow.clear` could turn into a missing flow in the middle of a run, and
keeps the reproduction free of store access. It holds a whole captured request, so
`Confirmed` is never serialised or logged: result objects are built field by field.

`ScanInject { cfg: ScannerConfig }` (`Sensitivity::Sensitive`):

1. **Agent gate:** at the top of `invoke`, `if !matches!(host.frontend(),
   Frontend::Cli | Frontend::Operator) && !self.cfg.allow_agent_active { bail!(
   "scan.inject refused: active injection from an agent frontend is disabled. Set
   scanner.allow_agent_active = true in the aitmproxy config to allow it, or run it
   from the operator/CLI.") }`. `Frontend::Cli` and `Frontend::Operator` are never
   gated. This is the per-command flag layer; the `Sensitive` policy tier is the
   independent upstream layer, and an agent reaches this check over MCP only if the
   policy layer lets it through (see "MCP policy layer"). **(Architect's call —
   source of the flag:** read from the plugin-owned `ScannerConfig` (shipped field),
   not from `host.config()`, because the scope design keeps `ScannerConfig`
   plugin-owned with no new `aitm_core::config::Config` field.)
2. **Confinement:** `let _confine = host.egress_handle().map(|e| e.confine());`
   before the active phase; dropped (RAII) when `invoke` returns.
3. Resolve `class` through `CheckDefinition::for_class` (an unknown class is an error
   that lists `registered_classes()`); enumerate points from the store flows for
   `target`, select those matching `def.locations` (or the single `injection_point`
   argument when given); `let mut budget = self.cfg.request_budget;`; call
   `block_on(inject(..))`.
4. For each `Confirmed`, in order, call `block_on(reproduce_and_record(host, &def,
   &c.injection_point, &c.payload, &c.attack_flow, &mut budget))` and fold the
   `ReproOutcome` (see "Reproduce → record"): `Recorded` → push the id onto
   `finding_ids`; `Unreproduced` → an `unreproduced` entry with the scrubbed reason;
   `NoFindingsDir` → set the `reproduction` marker and stop calling; `BudgetExhausted`
   → an `unreproduced` entry with reason `"budget"` and `stopped_reason = "budget"`. The
   loop never propagates a per-confirmation failure with `?`.
5. Return the result object below. All strings scrubbed; every array capped at 1024.
6. `confirm_prompt` returns `Some("Run active injection (class <class>) against
   <target>? This issues attack traffic to the authorized target.")` so human
   surfaces get the confirm handshake (integration D-MCP3).

**Result shape.**

```
{ class, tested,
  confirmed:    [ { injection_point: {flow, location, name}, payload, evidence, reproduced: Bool } ],
  finding_ids:  [ Str ],
  unreproduced: [ { injection_point: {flow, location, name}, reason: Str } ],
  reproduction: Null | Str("skipped: no findings.dir"),
  stopped_reason }
```

`confirmed` always lists every confirmation (one per point at most) and is never
reduced by a reproduction failure. With `reproduction` null, `confirmed.len() ==
finding_ids.len() + unreproduced.len()`; `reproduced` is true exactly for the
confirmations that have an id in `finding_ids`. With `reproduction` set,
`finding_ids` and `unreproduced` are empty and every `reproduced` is false.

### Reproduce → record (reuse)

`reproduce.rs`:

```
pub struct BuiltPoc { pub poc: aitm_poc::Poc, pub bindings: aitm_poc::VarBindings }
pub fn build_poc(attack_flow: &HttpFlow, def: &CheckDefinition,
    point: &InjectionPoint, payload: &Payload) -> anyhow::Result<BuiltPoc>;
pub(crate) fn narrowed_host<'a>(host: &'a CommandHost<'_>) -> CommandHost<'a>;
pub async fn reproduce(host: &CommandHost<'_>, built: &BuiltPoc,
    attack_flow: &HttpFlow) -> anyhow::Result<aitm_poc::PocRunResult>;
pub fn finding_record(host: &CommandHost<'_>, def: &CheckDefinition,
    attack_flow: &HttpFlow, poc: &aitm_poc::Poc, run: &aitm_poc::PocRunResult)
    -> aitm_findings::FindingRecord;
pub fn record_finding(host: &CommandHost<'_>, rec: aitm_findings::FindingRecord)
    -> anyhow::Result<String>;
pub enum ReproOutcome {
    Recorded { finding_id: String },   // replay passed; exactly one record written
    Unreproduced { reason: String },   // not recorded; reason is scrubbed
    NoFindingsDir,                     // no findings.dir: nothing sent, nothing recorded
    BudgetExhausted,                   // budget was zero: nothing sent, nothing recorded
}
pub async fn reproduce_and_record(host: &CommandHost<'_>, def: &CheckDefinition,
    point: &InjectionPoint, payload: &str, attack_flow: &HttpFlow,
    budget: &mut usize) -> ReproOutcome;
```

**One owner.** `reproduce_and_record` is the single function that turns a
confirmation into a (maybe) finding; both `scan.inject` and `scan.run` call it, so the
confirm → reproduce → record behaviour, its budget accounting and its failure
isolation exist once. It takes raw values (not `Confirmed`) so the reproduce engine
does not depend on the injector. It never returns an error: every per-confirmation
failure becomes `Unreproduced`. In order: (1) no `findings.dir` in `host.config()` →
`NoFindingsDir`; (2) `*budget` is zero (`checked_sub`) → `BudgetExhausted`; (3) resolve
`payload` against `def.payloads` and `build_poc` (a refusal → `Unreproduced`); (4)
decrement `*budget` by one, immediately before calling `reproduce`, so a refused build
costs nothing (a pre-check refusal or a run error costs one — conservative, since a
request may have been sent); (5) `reproduce` (its credential pre-check refusal or any
run error → `Unreproduced` with the error text through `scrub_text`); (6) `!run.passed`
→ `Unreproduced` ("replay did not confirm"), **no record**; (7) `finding_record` +
`record_finding` (an error → `Unreproduced`, "record failed: …"); (8) `Recorded`.

**Building the PoC.** `build_poc` is fed the *attack* flow, because `StdPocBuilder`
parameterizes the concrete URL pieces of the flow it is given and the benign source
flow does not contain the payload. It assembles `PocSpec { info, variables, success }`
and calls `StdPocBuilder::default().build(attack_flow, spec)`, then post-processes the
built `Step::Http`:

- `info` is `PocInfo { name, severity, references: [], tags: [class], cwe: None,
  description: None, author: None, metadata: None }`. `name` is `"<class>: <param>"`
  where `<param>` is the injection point's name with every character outside
  `[A-Za-z0-9_.-]` replaced by `_`, truncated to 32 characters (empty becomes
  `param`), so the slugged PoC id always satisfies the runner's 64-character id rule
  and a hostile parameter name cannot make `precheck` reject it. `severity` comes
  from a class-to-severity mapping local to `reproduce.rs` (the shipped
  `CheckDefinition` has no severity field; **Architect's call:** reflected-XSS →
  `Medium`, open-redirect → `Low`, any other class → `Info`).
- `success` is `CheckDefinition::success_assertion(payload)`: for reflected-XSS the
  payload's `Word { word: marker, part: Body }`; for open-redirect that assertion
  is `Regex` over the `Location` header only, so the PoC `success` is
  `All[ Any[ Status(301), Status(302), Status(303), Status(307), Status(308) ],
  <the Location regex> ]` — `confirm` requires a 3xx and the PoC must not be weaker
  than the check that confirmed it (the DSL has no ordering operator, hence the
  explicit statuses).
- The base URL becomes `{{target}}` and the injected value `{{payload}}`.
- **Credential parameterisation.** A request component is a *credential* when its
  name matches `discover::is_secret_name` (the shared `aitm_core::redact::is_secret_key`
  vocabulary plus the substrings `sid`, `jwt`, `csrf`, `session`, `auth` —
  over-matching on purpose) or it is a `Cookie`. Every credential **header**, **query
  key**, and top-level **form-urlencoded or JSON-object body key** has its value
  replaced by a required, default-less `{{var}}` placeholder (a `Variable` with
  `default: None, required: true`) and the real value is recorded in
  `BuiltPoc.bindings` for in-memory use only. Variable names are the component name
  lowercased with every character outside `[a-z0-9]` replaced by `_` (so
  `X-CSRF-Token` → `x_csrf_token`, matching the builder's own header rule), with a
  `_2`, `_3` suffix on a collision and never `target`, `payload` or `param`. The
  injection point itself is exempt: its value is the inert payload, so a point named
  `token` stays `token={{payload}}`.
- **Refusals.** `build_poc` returns `Err` (and no PoC exists) when a credential cannot
  be parameterised: a path parameter whose name is credential-like
  (`/search;jsessionid=…`), or a non-empty body that is neither form-urlencoded nor a
  JSON object (multipart, text, a JSON array). It also returns `Err` when any
  builder-derived string other than the placeholders it inserted — URL, header value,
  body — contains `{{` or `}}`: the templater has no escape syntax, an unbound
  `{{x}}` fails the run with "unknown variable", and a non-identifier `{{expr}}` is
  *evaluated by the DSL*, so captured hostile content must never become a template.
  Refusal texts are constants naming the component class, never a value.
- `bindings` carries `target` (the attack flow's `scheme://authority`) plus one entry
  per credential variable.

**What is guaranteed, and what is not.** Credential material the scanner can
identify never reaches the PoC YAML, the finding record, `runs.jsonl`, or any result:
credential-named headers, query keys, form/JSON body keys and cookies are
placeholders bound in memory only; a request whose credential cannot be parameterised
yields no PoC and no record; and `reproduce`'s pre-check refuses to run a PoC whose
serialised YAML contains any bound credential value or any `Cookie` value from the
attack request (values shorter than 4 bytes are exempt from that substring check —
they would match arbitrary YAML — and rely on the structural rule alone; Architect's
call). What is **not** detected: a secret carried in a non-credential-named parameter,
an opaque path segment, or any component the name predicate does not recognise. The
PoC is as sensitive as the captured request it was built from, which is why the
runner writes it to a private (owner-only) directory under `poc.out_dir` or the temp
dir.

**Running the PoC (Correction 1).** A command cannot invoke another command:
`CommandHost` holds no `Registry` and `Command::invoke` receives nothing else, so
there is no "call `poc.run`" primitive. The scanner does what `scan.discover` already
does with `crawl`/`enumerate` — it calls the library engine directly. `reproduce` runs
the built PoC through `aitm_poc::StdPocRunner`, the engine the `poc.run` command itself
calls (`run_poc_command`), with its output directory chosen as `run_poc_command`
chooses it (`poc.out_dir` from `host.config()`, else the system temp dir). Before
running, it serialises the PoC and returns `Err` if the YAML contains any bound
credential value or any `Cookie` value from the attack request (see above). It then
issues exactly **one** further guarded, captured request, with `bindings` handed to the
runner.

`narrowed_host(host)` rebuilds a `CommandHost` from the same borrowed `store`, `client`
and `guard` plus `frontend`, `ssrf_policy`, `poc_dir`, `client_label`, the egress handle
and a clone of the `Config` in a fresh `Arc`, and drops **only** the finding recorder
(and `browser`, since the PoC is HTTP-only). The replay is therefore enforced by
exactly the scope, rate, SSRF and egress posture of every other request, and the only
difference the runner can observe is that its auto-record has nowhere to write. It is
`pub(crate)`.

*Architect's call — the `poc.allow_agent_run` gate is not re-applied.* The PoC is
scanner-built, HTTP-only and never loaded from a caller-supplied path, so
`scanner.allow_agent_active` is the single flag governing the whole active phase
including the replay (a second flag would make `allow_agent_active = true`
insufficient for an agent with no safety gain).

**Exactly one record.** `StdPocRunner::run_inner` records a finding on its own when
the host it is handed has a wired `finding_recorder` and a configured `findings.dir`
and the run passed; the binary wires that recorder onto the MCP server and the CLI
host, so passing the command's own host to the runner would write a second record
beside the scanner's. Running on `narrowed_host` makes the runner's `recorded_id`
`None` by construction.

**When a record is written (and what it contains).** Only when `run.passed`. A
replay that does not pass writes **no** `FindingRecord`: `aitm-findings` records follow
a passing run (crate docs; the runner records only `if passed`), and a one-off
reflection that is absent on replay would otherwise show up in `render_report`'s counts
as a finding. `finding_record` builds the record directly: `class = def.class`,
`severity = poc.info.severity` (set once by `build_poc`, not looked up again),
`title = poc.info.name`, `target` per "Record target", `origin = host.frontend()`,
`client_label`, `poc_ref = poc.id`, `reproduction { passed: true, control_passed: None,
run_at: now }`, `artifacts` from the run, `flows = [attack_flow.id,
run.finding_capture]` (the confirming request first; the replay second), `notes:
None`. `record_finding` persists it via `DiskFindingStore::new(dir)` with `dir` from
`host.config().findings.dir`, and returns `Err` (never a fabricated id) when no `dir`
is configured; it never calls `host.finding_recorder()`. *Why the scanner records its
own:* the runner's draft files the finding under `poc.info.cwe`, else the first tag,
else the PoC id, so a CWE later added to the PoC metadata would silently change the
class, whereas the scanner's class strings (`reflected-xss`, `open-redirect`) are what
the test-target grader matches; and recording must work on a host with no recorder
wired. `FindingStore::record` scrubs `title` and `notes` at the store boundary; the
scanner additionally scrubs `target` (the store does not) and never puts a parameter
value or raw header into `title`.

**Record target.** `target` is the attack request's `scheme://authority/path` with no
query, fragment or userinfo, through `scrub_text` (literal:
`http://127.0.0.1:8080/search`). That satisfies every consumer: the test-target
grader matches a finding by `class` and the *path* of `target` (query ignored);
`render_index` publishes it as `target_path`; and `scan.report {target: <campaign
base>}` finds it through the origin-and-path-prefix rule above. A secret in the query
string can never reach it.

**Failure handling and `findings.dir`.** `findings.dir` defaults to `None`, so a
default install has no store to record into. In that case reproduction and recording
are **skipped**: `confirmed` is returned intact with `finding_ids: []`, `unreproduced:
[]` and `reproduction: "skipped: no findings.dir"`; no replay request is sent and no
id is fabricated. For every other per-confirmation failure (a refused build, a
refused pre-check, a runner or templater error, an unwritable store, a failed replay)
the confirmation stays in `confirmed` with `reproduced: false`, gains an `unreproduced`
entry whose reason is a constant or a `scrub_text`-scrubbed error, and the loop
continues with the next confirmation. A hostile target cannot abort a call by planting
template syntax in content the scanner captured.

**Budget.** The replay is a request like any other: it goes through the same
chokepoint (`check_active`, rate, back-off) and is counted against the shared budget
(`ScannerConfig.request_budget` is "the maximum number of requests the whole run may
issue"). A confirmation that arrives with no budget left is reported in `confirmed`
with an `unreproduced` entry (reason `budget`) and the call stops with
`stopped_reason = "budget"`. Every decrement is `checked_sub`; a zero budget never
wraps.

**`control_passed` is `None` in production (Correction 3).** The scope design's AC11
described a confirmed finding recording `control_passed == Some(false)` "on the
patched control", as if diffing against a patched variant were something `scan.inject`
does at runtime. It cannot: a real target (a client's staging site, DVWA) has no
patched control the scanner can locate. `poc.run`'s own `DiskFindingRecorder`
hard-codes `control_passed: None` for the same reason, and the only code in the tree
that computes a control run is the test harness
(`crates/aitm/tests/support/scripted_driver.rs`), which owns a separate known-patched
twin. Therefore **a production `scan.inject`/`scan.run` record always has
`control_passed: None`.** The vulnerable-versus-patched proof is a property of the
*test suite*: confirm on `SeedMode::Vulnerable`, confirm nothing on `SeedMode::Patched`,
by two separate calls, each asserted on the call's own `confirmed` list (AC6, AC23).
Known consequence, not a defect: `render_report`'s summary counts a finding as
"reproduced against a patched control" only for `Some(false)`, and the test-target
grader scores "reproduced" the same way, so scanner findings render as "no patched
control was run" and are graded "found", not "reproduced". A test of `scan.report`
must not assert a non-zero "reproduced" count for scanner records.

### `scan.run` — Sensitive, one shared budget, confined

`campaign.rs`:

```
pub const DEFAULT_SWEEP: [&str; 2] = ["reflected-xss", "open-redirect"];
pub struct CampaignSummary { pub run_id: String, pub phase: String,
    pub pages_crawled: usize, pub requests_used: usize, pub confirmed_count: usize,
    pub stopped_reason: Option<String> }
pub async fn run_campaign(host: &CommandHost<'_>, target: &str, active: bool,
    cfg: &ScannerConfig) -> anyhow::Result<(CampaignSummary, Value)>;
```

`ScanRun { cfg }` (`Sensitivity::Sensitive`, same agent gate + `confirm_prompt` as
`scan.inject`, and its own `defers_to_command_gate` entry — see "MCP policy layer")
takes a **single** `let _confine = host.egress_handle().map(|e| e.confine());` for
the whole campaign and runs, under one shared `request_budget` and one `time_budget`:
**discover** (`crawl`; because `crawl` takes no budget argument, the phase charges its
`pages_crawled` against the shared budget when it returns) → **passive**
(`passive_checks` over captured flows) → **inject** (when `active`: each class in
`DEFAULT_SWEEP` in order, through `inject` with the campaign's *remaining* time, each
confirmation through `reproduce_and_record` with the same `&mut budget` and the same
fold as `scan.inject`) → **report** (`load_records` over the target, then
`render_report`/`render_index`). It returns `{ run_id, discover, passive, inject,
report, stopped_reason }`, where `discover`, `passive` and `report` are the
corresponding verbs' result objects and `inject` is `{ classes: [ <one scan.inject
result per swept class> ], tested, finding_ids: [every id], reproduction,
stopped_reason }` (with `active == false`: `classes: []`, `tested: 0`, `finding_ids:
[]`). The shared budget means the inject phase sees the requests the discover phase
already spent and the replays it makes itself; hitting the budget stops the campaign
with `stopped_reason = "budget"`, and exhausting the time budget with
`"time_budget"`. The default sweep is exactly the two default-active classes; the
third registered class is reachable only through `scan.inject {class}` (Open question
2).

`ScanStatus { … }` (`Sensitivity::Read`) returns the plugin's last completed campaign
snapshot `{ run_id, phase, pages_crawled, requests_used, request_budget,
confirmed_count, stopped_reason }`, or nulls when none has completed. **(Architect's
call:** progress is a *snapshot* read, not a streamed channel — matches the
integration spec's polling baseline. The snapshot is held in a process-lifetime
`Mutex` owned by the plugin, stored once when `run_campaign` returns, bounded to the
last campaign; a richer multi-run registry and live phase-boundary updates are Open
question 7.)

### Agent gate summary

| | `poc.allow_agent_run` (shipped) | `scanner.allow_agent_active` (this design) |
|---|---|---|
| Tier | — (runner) | `scan.inject`/`scan.run` = `Sensitive` |
| Refuse when | `frontend()==Mcp && !flag` | `!matches!(frontend(), Cli \| Operator) && !flag` |
| Operator/CLI | never gated | never gated |
| Flag storage | `aitm_core::config::Config.poc.allow_agent_run` | plugin-owned `ScannerConfig.allow_agent_active` (no core field) |
| Error | `bail!("poc.run refused … Set poc.allow_agent_run = true …")` | `bail!("scan.inject refused … Set scanner.allow_agent_active = true …")` |
| Policy-layer reachability | `poc.run` is `Write`: `Auto` and `All` both reach `invoke`, so it needs no allow-list entry | `Sensitive`: **not** a mirror here. The precedent is `scope.add`/`ca.install`/`l4.*` — named in `defers_to_command_gate` (Open question 6) |

The refusal expression deliberately differs from the shipped one: `Frontend` is
`#[non_exhaustive]`, so `== Mcp && !flag` would let a future variant through the
gate, while `!matches!(Cli | Operator)` treats every unknown frontend as an agent.
(`poc.allow_agent_run` keeps its shipped expression; aligning it is outside this
design.)

### MCP policy layer

The first layer of the two-layer gate is `McpServer::policy_decision`
(`crates/aitm-mcp/src/server.rs`). It gates only the agent role (`Frontend::Mcp`);
`Operator` and `Cli` always pass. For a `Sensitive` command:

| Agent policy | Reaches `scan.inject`'s own flag check? | Source |
|---|---|---|
| `Auto` (the default) | **No, never** — refused outright, flag irrelevant (by design, same as `scope.add`) | `policy_decision` `(Auto, Sensitive)` |
| `All` | **Only if** `defers_to_command_gate("scan.inject")`; otherwise refused by policy before the flag is read | `policy_decision` `(All, Sensitive)`; `defers_to_command_gate` |
| `Ask` | Yes, after an operator approves the parked call; the call then runs as the agent and the flag decides. Independent of the allow-list | `run_tool` (parks, then falls through on approval); `park_for_approval` |
| `ReadOnly`, `Paused` | No | `policy_decision` |

Without an allow-list entry `scanner.allow_agent_active = true` is therefore a silent
no-op under `All`. **Default (Architect's call, Open question 6): add `"scan.inject"`
(Stage 3) and `"scan.run"` (Stage 4) to `defers_to_command_gate`**, as `scope.add`,
`ca.install` and the `l4.*` Sensitive verbs are, so that an operator who sets the
policy to `All` *and* the flag gets an agent that can run active injection, with the
two layers still independent. Operationally an agent therefore needs **both** the flag
and policy `all` (or `ask` with an operator present); under the default `auto` policy it
is refused regardless of the flag. The posture has a precedent on the other side —
`script.save` and the other script-authoring verbs are *deliberately* not listed so an
autonomous agent cannot self-authorize on a flag alone (`mcp.rs` tests
`f8_script_authoring_not_auto_authorized_under_all`, `all_sensitive_honors_config_gate`;
scripting command-surface spec AC8) — which is why this is a question for Matt rather
than a settled fact. The `defers_to_command_gate` arm must land in the same merge as,
or after, the command-side flag check; Tasks 8 and 10 add both together.

**Operator-configurability of the flag** (threading a config-file `[scanner]`
section into `ScannerConfig` at `wire.rs`, today hard-wired `::default()`) is owned
by the **integration** plan's **D-MCP2 / AC9**, which explicitly claims it. This
backend plan provides the plugin gate + its unit tests (which construct
`ScannerPlugin::new(ScannerConfig { allow_agent_active, .. })` directly) and does
**not** edit `wire.rs`/`config_file.rs` for the flag, to avoid duplicate work and
honour "no core edits". See Open question 5. The integration plan's Task 8 test
(`scan_inject_gate_is_wired_default_off`, "accepted with the flag on under
`AgentPolicy::All`") can only pass once the `defers_to_command_gate` entry has landed,
and that plan does not mention it; backend Task 8 must therefore merge before
integration Task 8.

### UI-shape reconciliation (checked against the integration design)

No blocking mismatch found. `scan.discover`'s shipped shape (`endpoints`,
`injection_points[{location,name,example}]`, `endpoint_flows`) already matches. The
new shapes satisfy the integration ACs: `scan.report.index` is exactly
`render_index`, which the UI already understands, and **only `scan.report` feeds the
Findings fold** (integration AC7) — `scan.passive` results are not persisted and reach
no Findings row (Open question 8); `scan.inject`/`scan.run` are `Sensitive` with
`confirm_prompt` (AC10, D-MCP3); `scan.status` carries `phase` + counters + terminal
`stopped_reason` for the last completed run (AC11's *live* progress is not met in v1,
Open question 7). One deliberate naming choice: the per-attempt confirmation list is
`confirmed` (not `findings`) and the recorded findings are reachable by `id`
(`finding_ids`) and through `scan.report`/the Findings pane — the UI folds findings
from the report/index, not from the raw `inject` result, so this is consistent. The
extra `unreproduced` and `reproduction` keys are additive.

## Acceptance criteria

Numbering is self-contained to this spec; the scope spec's AC it restates is noted
in brackets. AC1-AC25 keep their numbers; AC26-AC33 are appended.

**Stage 2 — passive + report (Read)**

1. **AC1:** `passive_checks(&HttpFlow)` returns a `reflection` finding naming a
   param whose value appears verbatim in the response body, a `security-header`
   finding when `Content-Security-Policy` is absent, and a `cookie-flag` finding
   for a `Set-Cookie` without `Secure` (unit test, literal classes). [scope AC5]
2. **AC2:** `scan.passive` reports `Sensitivity::Read`, issues no new traffic
   (`host.store().count()` unchanged across `invoke`), and returns
   `{ findings: [...] }` with a `reflection` entry for a seeded reflecting flow.
   [scope AC5/AC6]
3. **AC3:** No secret from a scanned request appears anywhere in a `scan.passive`
   result: a flow with `Cookie: PHPSESSID=abc123`, `Authorization: Bearer abc123`,
   `?access_token=abc123` yields no `abc123` in any finding string. [scope AC13]
4. **AC4:** `scan.report` reports `Sensitivity::Read` and returns
   `{ report_md, index }` where `render_report` has one `##` section per recorded
   finding and `index` is an array with one entry per finding carrying `poc_path`,
   `class`, and `passed`; its `target` argument selects records by the origin-and-path
   rule above. [scope AC12]

**Stage 3 — active injection, reproduce, record (Sensitive, gated)**

5. **AC5:** `scan.inject {target, class}` reports `Sensitivity::Sensitive` and
   returns `{ class, tested, confirmed, finding_ids, unreproduced, reproduction,
   stopped_reason }` with per-attempt structure. [scope AC7]
6. **AC6:** For `class = "reflected-xss"`, injection **confirms** on a
   `SeedMode::Vulnerable` response and **does not confirm** on a
   `SeedMode::Patched` response, via `matcher::evaluate` (literal: `confirmed`
   non-empty vulnerable, empty patched). [scope AC8]
7. **AC7:** An agent-frontend `scan.inject` **invoked on the command** (a host with
   `Frontend::Mcp`) is refused when `allow_agent_active == false` (error naming
   `scanner.allow_agent_active`) and runs when it is `true`; `Cli` and `Operator`
   frontends always run. This is the per-command flag layer only; whether an agent can
   reach the command over the assembled MCP server also depends on the policy layer,
   which AC21 pins ("runs when it is `true`" is not claimed for `AgentPolicy::Auto`,
   which never lets a `Sensitive` call through). [scope AC9]
8. **AC8:** `scan.inject` never issues a request to an out-of-scope host from any
   caller: an unscoped target returns `GuardError::OutOfScope`. [scope AC10]
9. **AC9:** During `scan.inject`'s active phase the attached `EgressConfinement`
   is confined (`confined() == true` observed while injecting) and is released
   (`confined() == false` with an off base) once `invoke` returns; a host with no
   posture wired still runs (literal, probe like the shipped
   `scan_discover_crawls_under_egress_confinement`). [new / S2 parity]
10. **AC10:** On a confirmation the engine builds a PoC via `StdPocBuilder` from the
    confirming request's attack flow, reproduces it through `StdPocRunner` on a
    narrowed host, and, when the replay passes, records a `FindingRecord` with
    `reproduction.passed == true` and `reproduction.control_passed == None`. The
    vulnerable-versus-patched proof is AC6 and AC23, not a production control run.
    [scope AC11, whose `control_passed == Some(false)` clause is superseded here]
11. **AC11:** No secret from a scanned request appears in the PoC YAML at
    `artifacts.poc_path`, any stored `FindingRecord` file, `runs.jsonl`, the
    `scan.report` output, or the `scan.inject` result (the AC24 table is the literal
    fixture). [scope AC13]
12. **AC12:** `scan.inject` is request-bounded: with `request_budget == 1` it stops
    with `stopped_reason == "budget"`; with `request_budget == 0` it sends no request,
    reports `tested == 0` and `stopped_reason == "budget"` (a zero budget does not
    wrap). [scope AC14/AC17]
13. **AC13:** `scan.inject.confirm_prompt(args)` is `Some(_)` (non-empty), so human
    surfaces get the confirm handshake; `scan.passive`/`scan.report`/`scan.status`
    return `None`. [integration D-MCP3]

**Stage 4 — campaign + status**

14. **AC14:** `scan.run {target}` reports `Sensitivity::Sensitive`, carries the
    same agent gate as `scan.inject` (AC7 holds for `scan.run`), and returns
    `{ run_id, discover, passive, inject, report, stopped_reason }`. [scope AC15]
15. **AC15:** `scan.run` holds a single `ConfinementToken` across the whole
    campaign (observed confined during all phases, released on return). [new]
16. **AC16:** `scan.run` enforces one shared request budget across phases: a tiny
    `request_budget` yields a campaign that stops with `stopped_reason ==
    "budget"`. [scope AC17]
17. **AC17:** `scan.status` reports `Sensitivity::Read` and returns `{ run_id,
    phase, pages_crawled, requests_used, request_budget, confirmed_count,
    stopped_reason }` for the last completed campaign (nulls before any run).
18. **AC18:** Every new `scan.*` command appears in a `tools/list` over the
    assembled proxy with a non-empty `inputSchema`; `crates/aitm/tests/frontends.rs`
    `EXPECTED_TOOLS` equals the live set (literal: `scan.{passive,report,inject,run,
    status}` present; `[&str; 61]`); and every live `scan.*` is in
    `aitm_tui::CORE_TOOLS` with a fixture entry (the fixture offers 64 tools; the
    `tester_shell.rs` pins read 64). [integration AC1 / D-MCP1]
19. **AC19:** Loading `ScannerPlugin` with the full command set leaves the M4
    free-form loop working: the M4 scripted-driver gate still passes with the
    scanner loaded, and a driver that calls `scan.discover`/`scan.inject` records
    the same findings (no new mandatory gate in front of the free-form path).
    [scope AC16]
20. **AC20:** The class registry knows ≥ 3 classes (`CheckDefinition::registered_classes().len()
    >= 3`, each resolving through `for_class`, the first two literally `["reflected-xss",
    "open-redirect"]`), each class's payload set capped at `per_class_payload_cap`; a
    multi-position class under a small budget stays ≤ `request_budget`; and `scan.run`'s
    default sweep touches exactly `["reflected-xss", "open-redirect"]`. [scope AC14]

**Criteria for the reproduce/record, policy and bounding behaviour (appended)**

21. **AC21 (policy reachability; the `scan.inject` half lands in Stage 3, the
    `scan.run` half in Stage 4):** Over a real `McpServer` whose registry carries
    `ScannerPlugin`, an MCP-role call to `scan.inject` (resp. `scan.run`) with
    `allow_agent_active == false` is refused by the **command's own** gate — the error
    text contains `scanner.allow_agent_active` and does not contain the policy-refusal
    text `not allowed to the agent under` — under `AgentPolicy::All`, and also under
    `AgentPolicy::Ask` once an operator approves the parked call. Under
    `AgentPolicy::Auto` the same call with the flag `true` is refused **by policy**
    (text contains ``the agent policy is `auto` ``). A `Cli` connection is never
    policy-refused. Separately, a stub `Sensitive` command named `scan.inject` (resp.
    `scan.run`) in the `aitm-mcp` policy-test server is **not** refused under `All` and
    **is** refused under `Auto`, proving the `defers_to_command_gate` entry by name the
    way `ca.install`/`scope.add` are proven. (These arms assume Open question 6's
    default; the `All` arms flip if Matt answers "leave them out".) [new; Correction 2]
22. **AC22 (one record per reproduced confirmation):** With a counting
    `FindingRecorder` wired onto the host and `findings.dir` configured, a reproduced
    confirmation leaves the counter at `0`, `PocRunResult.recorded_id == None`, and the
    findings store holds exactly one `FindingRecord` per reproduced confirmation (never
    two). [new; Correction 1]
23. **AC23 (control is a test property):** The vulnerable-versus-patched proof is two
    separate `scan.inject` calls: one against `SeedMode::Vulnerable` (`confirmed`
    non-empty, `finding_ids` non-empty, every stored record `passed == true` and
    `control_passed == None`) and one against `SeedMode::Patched` (`confirmed` empty,
    `finding_ids` empty, no stored record whose `target` is on the patched base's
    origin, and `scan.report {target: <patched base>}` returns an empty `index`). No
    production code path sends a patched-control request. [new; Correction 3; refines
    AC6/AC10]
24. **AC24 (no credential persists):** For each row of the literal table below, a
    reflecting target and a configured `findings.dir`, the value `abc123` is absent
    from **all five** of: the PoC YAML at `artifacts.poc_path`, the stored finding YAML,
    `runs.jsonl`, the serialised `scan.inject` result, and the serialised `scan.report`
    output (`report_md` and `index`). Rows 1-6 and 8 reproduce and record (the
    credential is bound in memory, so the replay passes) and the PoC YAML contains the
    row's placeholder; row 7 yields no PoC and no record. [new; extends AC11]

    | # | Component | Captured request fragment | Placeholder in the PoC YAML |
    |---|---|---|---|
    | 1 | header | `X-CSRF-Token: abc123` | `{{x_csrf_token}}` |
    | 2 | header | `X-Auth-Token: abc123` | `{{x_auth_token}}` |
    | 3 | header | `Authorization: Bearer abc123` | `{{authorization}}` |
    | 4 | header | `Cookie: PHPSESSID=abc123` | `{{cookie}}` |
    | 5 | query | `?q=<marker>&access_token=abc123` | `{{access_token}}` |
    | 6 | form body | `password=abc123` | `{{password}}` |
    | 7 | path parameter | `/search;jsessionid=abc123?q=<marker>` | none — `unreproduced` has one entry, `finding_ids` is empty |
    | 8 | JSON body | `{"token":"abc123"}` | `{{token}}` |
25. **AC25 (reproduction is budgeted):** With `request_budget == 1` against a
    reflecting target, `scan.inject` returns `confirmed` non-empty, `finding_ids`
    empty, one `unreproduced` entry with reason `budget`, `stopped_reason ==
    "budget"`, and the target observed exactly one request. With two vulnerable points
    and `request_budget == 3` the target observes exactly three requests,
    `finding_ids.len() == 1` and `unreproduced.len() == 1`. [new; refines AC12]
26. **AC26 (time- and fan-out-bounded):** (i) With `time_budget` of 20 ms and a
    target that takes 100 ms per response and never reflects, `scan.inject` reports
    `tested == 1` and `stopped_reason == "time_budget"`. (ii) With 1025 distinct
    reflecting single-parameter flows and a sufficient budget, `confirmed.len() ==
    1024` and `stopped_reason == "max_confirmed"`. (iii) `scan.run` hands its inject
    phase the campaign's *remaining* time: with `time_budget` of 50 ms and a discover
    phase that takes longer, the campaign reports `stopped_reason == "time_budget"` and
    the target observes no injection request. [new; Anti-goal "unbounded"]
27. **AC27 (one finding per vulnerable point):** Against a target that reflects every
    value of `q` (one captured `/search?q=` flow, or several captures of the same
    endpoint), `scan.inject {class: "reflected-xss"}` sends exactly one injection request
    and one replay (two requests), returns `confirmed.len() == 1` and `finding_ids.len()
    == 1`, and the findings store holds exactly one record. [new]
28. **AC28 (no `findings.dir`):** With no `findings.dir` configured, a reflecting target
    yields `confirmed` non-empty, `finding_ids == []`, `unreproduced == []`,
    `reproduction == "skipped: no findings.dir"`, and the target observes only the
    injection request (no replay). [new]
29. **AC29 (a failed confirmation never aborts the call):** With two vulnerable
    points, the first of whose captured request carries a header `X-Note: {{x}}`,
    `scan.inject` returns `Ok` with `confirmed.len() == 2`, `finding_ids.len() == 1` and
    `unreproduced.len() == 1` whose reason does not contain `{{x}}`; likewise when the
    findings directory cannot be written (reason begins `record failed`). [new]
30. **AC30 (a failed replay is not a finding):** When the replay does not pass (a
    target that reflects the marker on the injection request but not on replay), the
    confirmation is listed in `confirmed` with `reproduced == false` and in
    `unreproduced`; `finding_ids` is empty and the findings store holds no record (so
    `render_report` counts none). [new]
31. **AC31 (`scan.run` reproduces and records):** `scan.run` against a stored reflecting
    flow (no browser, so discover spends no request) with `request_budget == 3` returns
    an `inject` phase with `finding_ids.len() == 1`, the store holds exactly one record,
    and the summary reports `requests_used == 2` (one injection, one replay) and
    `confirmed_count == 1`. [new]
32. **AC32 (record target):** A recorded finding's `target` is the attack request's
    `scheme://authority/path` without query or fragment, scrubbed (literal:
    `http://127.0.0.1:<port>/search`); `scan.report {target: <campaign base URL>}`
    returns it with `target_path` equal to that value; `{target: <another origin>}`
    returns none. [new]
33. **AC33 (the replay is guarded):** With a real `PipelineClient` and a guard whose
    scope no longer contains the attack host, `reproduce` returns
    `GuardError::OutOfScope` and the sender observed zero requests; a `narrowed_host`
    keeps the outer host's frontend, SSRF policy, egress handle and config, and drops
    the finding recorder and browser. [new]

## Left to the builder

- Internal module layout within each new file, struct field order, and private
  helper signatures.
- The concrete inert payload strings per class (from `02-nuclei.md` vocabulary),
  within `per_class_payload_cap`; the exact `Assertion` each `confirm` builds
  (using existing `aitm_poc` operators).
- How the request is mutated per `Location` (query/body/header/cookie/path/redirect)
  from the captured flow, provided it only mutates the one targeted point.
- The `run_id` scheme and the status-snapshot storage (a `Mutex` on the plugin),
  provided `scan.status` reads the last completed campaign.
- Recording is **not** left open: it goes through `DiskFindingStore`, never
  `host.finding_recorder()`.
- The exact way `narrowed_host` rebuilds the host from the existing accessors and
  builders, and the names of the credential placeholders beyond the rule in "Building
  the PoC" (valid identifiers, unique, never `target`/`payload`/`param`).
- Whether the per-confirmation reproduction loop also checks the time deadline before
  each replay (recommended: the loop is bounded by `MAX_CONFIRMED` sequential
  replays, so the overshoot is bounded either way).
- The serde_json→`aitm_core::Value` converter for `render_index` (shipped).
- Which third seeded class fills AC20 (stored-XSS, SSRF, IDOR, or auth-bypass), under
  the constraint that it must be confirmable from one response to one request with an
  inert payload; a task that finds none of the four fits **stops and reports** (a spec
  gap), it does not widen `confirm`.

## Open questions

Only Matt can decide these; each default is the Architect's call. Where overriding a
default changes a task, the question says which.

1. **How aggressive is default active fuzzing (payload-set size per class)?**
   Default: **conservative** — reflected-XSS ≈ 8 payloads, open-redirect ≈ 6, each
   well under the shipped `per_class_payload_cap = 25`. The cap stays 25 as the
   hard ceiling an operator can raise per class; the *default* set is small to keep
   a campaign fast and low-noise. Alternative: ship the full 25-payload sets by
   default (louder, slower, more coverage).
2. **Which classes does `scan.run` sweep by default?** Default: **reflected-XSS +
   open-redirect only** (inert markers + patched controls, zero test-target work),
   plus one more registered class for AC20 that is **opt-in per `scan.inject {class}`**
   but **not** run by `scan.run`'s default sweep. AC20's registry half (≥ 3 classes
   known to `for_class`) holds either way. Alternative: `scan.run` sweeps every
   registered class by default (changes `DEFAULT_SWEEP` in Task 9).
3. **Default active-request budget for a campaign?** Default: keep the shipped
   `request_budget = 2000` and `time_budget = 600 s`. Confirm or adjust.
4. **Does `scan.run` auto-confine egress and auto-enable the active (inject)
   phase?** Default: **auto-confine = always yes** (a single RAII token for the
   whole campaign, not optional — the active phase cannot run unconfined);
   **auto-enable active = yes for an operator/CLI caller** (the point of `scan.run`
   is a full campaign, and it is already `Sensitive` + confirmed), with `active`
   defaulting to `true` but overridable to `false` for a discover+passive+report
   dry run, and an agent caller still blocked by `scanner.allow_agent_active`.
   Alternative: `scan.run` defaults `active = false` (dry run) and requires an
   explicit `active: true` to inject.
5. **Who wires operator-configurability of `scanner.allow_agent_active`?** The
   integration plan's D-MCP2/AC9 already claims threading a `[scanner]` config
   section into `ScannerConfig` at `wire.rs`. Default: **leave it to the
   integration plan**; this backend plan ships only the plugin gate + unit tests
   and does not touch `wire.rs`/`config_file.rs`. Confirm, or fold the wiring into
   this backend plan (one small `aitm`-binary task, not a core edit) if the
   integration plan should not depend on it.
6. **May an autonomous agent under `AgentPolicy::All` self-authorize active injection
   with the flag alone?** Recommended default: **yes — list `scan.inject` and
   `scan.run` in `defers_to_command_gate`**, the posture of `scope.add`, `ca.install`
   and the `l4.*` Sensitive verbs: the operator opts in twice (policy `all` **and**
   `scanner.allow_agent_active = true`), and the default `auto` policy refuses the agent
   regardless of the flag. Alternative: **leave them out**, as `script.save` is, so an
   agent's active scan can only be authorized under `Ask` with an operator present and
   the flag matters only there; then AC21's `All` arms flip (refused by policy even with
   the flag on) and Tasks 8 and 10 drop their allow-list arms. This is a posture
   choice, so **Matt's explicit answer is needed before Tasks 8 and 10 are dispatched**;
   with no answer the entries are left out (the fail-closed choice). The arm lands in the
   same merge as, or after, the command-side flag check (each task adds both).
7. **`scan.run` execution model and live progress.** Default, as planned: `scan.run`
   is synchronous (a blocking `invoke`, bounded by `time_budget`, default 600 s) and
   `scan.status` reads a snapshot stored once, after `run_campaign` returns — so a UI
   polling during a run sees the previous campaign (or nothing), and the integration
   design's AC11 *live* progress is **not** met by v1. Recorded alternative / follow-up:
   update the snapshot at each phase boundary so a concurrent `scan.status {}` is live
   and refuse a second `scan.run` while one is in flight, naming the in-flight run
   (without that guard two concurrent campaigns each assume they own the whole
   `request_budget`); or return `{run_id}` at once and work in a background task (never
   holds a connection ~10 minutes, but needs a lifecycle/cancellation story no command
   has today). Adopting either changes Tasks 9 and 10.
8. **Do passive observations reach the Findings pane?** `scan.passive` persists
   nothing, and `scan.report` renders only recorded `FindingRecord`s, so the
   integration UIs' Findings pane (which reads `scan.report`'s index) shows **zero**
   rows until `scan.inject` confirms and reproduces something. Default:
   **confirmed-only** — observations and reproduced findings are different trust
   levels, and `aitm-findings` records a finding as "a separate, explicit, gated act".
   Alternative: add an `observed` array to `scan.report`, or persist passive hits at a
   low-confidence tier.
9. **Replay policy for non-idempotent methods.** Reproduction replays the attack
   request with the method it was captured with, so a confirmed `POST`/`PUT`/`DELETE`
   injection runs its side effect twice (once injected, once replayed). Default: **no
   change** — replay whatever method was captured, as `poc.run` and `request.send`
   already would; this is surfaced, not decided. Alternatives: reproduce only
   idempotent methods (`GET`/`HEAD`/`OPTIONS`) and report the rest as `unreproduced`
   with reason `non-idempotent method`, or make it a `ScannerConfig` flag.

## Summary

This design completes the deterministic scanner's backend for v0.6 by extending the
**shipped** `aitm-plugin-scanner` crate with five verbs — `scan.passive` and
`scan.report` (Read), `scan.inject` and `scan.run` (Sensitive, agent-gated,
egress-confined), and `scan.status` (Read) — reusing the shipped `ScannerConfig`,
`enumerate`, `crawl`, and `egress_handle`, the `aitm_poc` matcher/PoC vocabulary, and
the `aitm-findings` store/report, with **no `aitm-core` edit**. Active injection rides
the single guarded client chokepoint, holds an RAII `ConfinementToken` for its whole
phase, and refuses every caller but the operator/CLI unless `scanner.allow_agent_active`
is set. Each confirmation is reproduced once through `StdPocRunner` on a recorder-less
narrowed host and recorded once through `DiskFindingStore` with `control_passed: None`,
by one function shared by `scan.inject` and `scan.run`; credentials are parameterised out
of the PoC, a failed or unrecordable replay never aborts the call and never becomes a
finding, and the policy layer needs `defers_to_command_gate` entries (Open question 6).
Thirty-three acceptance criteria map to the three stages; result shapes match what the
integration plan's UI tasks consume.

### Architect's calls made (for Matt to approve or correct)

1. Flag `scanner.allow_agent_active` read from the plugin-owned `ScannerConfig` (no new
   `aitm_core::config::Config` field).
2. The refusal expression is `!matches!(frontend, Cli | Operator) && !flag` — fail-closed
   for a future `Frontend` variant — a deliberate divergence from `poc.allow_agent_run`'s
   `== Mcp` check, which is left unchanged.
3. Active confinement uses the **existing** `CommandHost::egress_handle()`; no core
   accessor added.
4. Result shapes: `scan.passive {findings}`, `scan.report {report_md, index}`,
   `scan.inject {class, tested, confirmed[{…, reproduced}], finding_ids, unreproduced,
   reproduction, stopped_reason}`, `scan.run {run_id, discover, passive, inject{classes,
   tested, finding_ids, reproduction, stopped_reason}, report, stopped_reason}`,
   `scan.status {run_id, phase, pages_crawled, requests_used, request_budget,
   confirmed_count, stopped_reason}`.
5. Tiers: `scan.passive`/`report`/`status` = Read; `scan.inject`/`run` = Sensitive.
6. First active classes **reflected-XSS + open-redirect**; a third registered class
   (`registered_classes()`) fills AC20 and is opt-in per `scan.inject`; `scan.run`'s
   default sweep is `DEFAULT_SWEEP` (the first two).
7. `scan.status` is a last-completed-run **snapshot** (polling baseline); live progress
   and a single-in-flight guard are Open question 7, not v1.
8. Operator-configurability of the flag is left to the integration plan's D-MCP2/AC9.
9. Correlation stays internal (no `scan.correlate` verb), returned as `evidence`.
10. Contract lists: each command-registration task bumps `EXPECTED_TOOLS` (56 → 61) and
    the `aitm-tui` family (`CORE_TOOLS`, fixture, pins: 59 → 64).
11. Reproduction runs `aitm_poc::StdPocRunner` directly on a **narrowed host that keeps
    every service and a `Config` clone and drops only the finding recorder and browser**,
    so the replay is scope/SSRF/egress-confined like any request and the runner's
    auto-record is inert.
12. The scanner records through `DiskFindingStore`, never `host.finding_recorder()`; only a
    **passing** replay is recorded; the confirming flow is first in `flows`.
13. `control_passed` is `None` in every production record; the vulnerable-versus-patched
    proof is two separate calls in the e2e tests.
14. `scan.inject`/`scan.run` are added to `defers_to_command_gate` as the default for
    Open question 6, **gated on Matt's explicit answer** before Tasks 8 and 10 dispatch.
15. The replay is governed by `scanner.allow_agent_active` alone (`poc.allow_agent_run` is
    not re-applied), is counted against the shared budget, and all decrements are
    `checked_sub`.
16. `Confirmed` carries the `HttpFlow` (not an id), so no store re-fetch can fail.
17. One reproduction and record per injection point (endpoint key = method +
    `scheme://authority/path` + location + name); `inject` stops a point after its first
    confirmation and skips repeat captures of one endpoint.
18. Credential parameterisation by the scanner's own `is_secret_name` predicate (promoted to
    `pub(crate)`) over headers, query keys and form/JSON body keys; unparameterisable
    credentials (path parameters, multipart/opaque bodies) refuse the PoC; a fail-closed
    pre-check serialises the PoC and refuses on any bound credential or Cookie value (values
    under 4 bytes exempt); the guarantee is stated as exactly that, no wider.
19. Template metacharacters (`{{`, `}}`) in builder-derived content **refuse** the build —
    the templater has no escape syntax and evaluates non-identifier expressions.
20. The PoC `name` carries the class and the parameter name sanitised to `[A-Za-z0-9_.-]`,
    32 characters; severity mapping reflected-XSS → `Medium`, open-redirect → `Low`, other
    → `Info`; the open-redirect PoC `success` ANDs five redirect statuses with the
    `Location` regex.
21. Record `target` is the attack request's `scheme://authority/path` without query;
    `scan.report`'s `target` filter becomes origin-and-path-prefix (a change to the shipped
    `report.rs`, its own task).
22. With no `findings.dir`, reproduction and recording are skipped with an explicit
    `reproduction` marker; per-confirmation failures are isolated into `unreproduced`.
23. Time budget: `inject` stops at `cfg.time_budget` (`"time_budget"`, as `crawl` already
    says) and at `MAX_CONFIRMED = 1024` (`"max_confirmed"`); `scan.run` passes the inject
    phase the remaining time; discover charges `pages_crawled` against the shared budget.
24. Moved out of the blocking questions into Non-goals/follow-ups: the payload-set source.
