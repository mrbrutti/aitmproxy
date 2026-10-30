# Scanner active backend (passive / report / inject / run / status) design

**Status:** draft
**Research inputs:** `docs/research/05-synthesis.md`;
`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md` (the
authoritative scope design, **this branch's copy with the S2 amendment** — command
surface, tiering, the two-layer agent gate, caps, correlation-stays-internal);
`docs/superpowers/plans/2026-10-29-aitmproxy-scanner-plugin-plan.md` (this branch's
copy); the **shipped** Stage-1 crate on `main`
(`crates/aitm-plugin-scanner/src/{lib,plugin,commands,config,crawl,discover}.rs`,
PR #67); egress confinement (`crates/aitm-core/src/egress.rs`, `ctx.rs`
`CommandHost::egress_handle`, `client.rs` `PipelineClient::send`); the gate to
mirror (`crates/aitm-core/src/config.rs` `poc.allow_agent_run`,
`crates/aitm-poc/src/runner.rs` the `run_poc_command` gate,
`crates/aitm/src/config_file.rs` `PocFile`); the reuse seams
(`aitm-poc` `matcher`/`model`/`builder`, `aitm-findings`
`record`/`report`/`store`); the seeded target
(`crates/aitm-testtarget/src/{app,manifest,seed}.rs`); and the operator-surface
integration design/plan
(`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-integration-design.md`,
`…/plans/2026-10-29-aitmproxy-scanner-integration-plan.md`) whose UI tasks consume
these verbs; and, as the provenance of the 2026-10-30 amendment in Design, the
closed-unmerged PR #84 draft ("backend Stages 2-5 design spec", branch
`claude/scanner-backend-scope`), whose three corrections this document had not
carried over.

## Intent

Stage 1 shipped: `scan.discover` crawls an in-scope target and enumerates
injection points, deny-by-default, scope- and budget-bound, with egress
confinement and redaction (PR #67). This design completes the deterministic
scanner's backend for a **v0.6** release (v0.5 ships discovery-only): the five
remaining `scan.*` verbs — `scan.passive`, `scan.report`, `scan.inject`,
`scan.run`, `scan.status` — built **entirely by extending the shipped
`aitm-plugin-scanner` crate**, reusing the shipped `ScannerConfig`,
`ScannerPlugin`, `enumerate`/`InjectionPoint`/`Location`, and `crawl`, and reusing
the `aitm_poc` matcher/builder vocabulary and `aitm-findings` store/report — with
**no edit to `aitm-core`**. The active verbs (`scan.inject`, `scan.run`) carry the
scope design's two-layer agent gate and hold an egress-confinement token for the
whole active phase, so every byte of attack traffic stays inside the authorized
scope. We want it now because every seam is shipped and verified this session:
the active-request chokepoint (`PipelineClient::send` → `check_active`), the RAII
confinement handle (`CommandHost::egress_handle`), the matcher/PoC/findings
crates, and the seeded Vulnerable/Patched test target.

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
  command), records one `FindingRecord` per reproduction, and returns a structured
  per-attempt result. First classes: **reflected-XSS + open-redirect** (both seeded).
- **`scan.run {target, active?}`** (**Sensitive**) orchestrates discover → passive
  → inject → report as one campaign under **one shared budget**, holding an egress
  token for the whole run, and returns a structured campaign summary with a
  `run_id`.
- **`scan.status {run_id?}`** (**Read**) returns the live/last campaign's phase and
  counters.
- **Deny-by-default, mirrored exactly.** `scan.inject`/`scan.run` are `Sensitive`
  and, for an MCP/agent caller, refuse unless `scanner.allow_agent_active` is set —
  the 1:1 analogue of `poc.allow_agent_run`. Operator/CLI always run. The
  `Sensitive` policy tier and the flag are independent layers, and the policy layer
  needs an explicit `defers_to_command_gate` entry per verb before the flag is
  reachable under `AgentPolicy::All` (see Design, "MCP policy layer").
- **Scope-confined active egress.** `scan.inject`/`scan.run` hold a
  `ConfinementToken` (`CommandHost::egress_handle().map(|e| e.confine())`) across
  the whole active phase, exactly as the shipped `scan.discover` does for its
  crawl, so any browser use stays scope-confined and the token is released
  (RAII) on return, error, or unwind.
- **Resource-bounded.** Reuse the shipped `ScannerConfig` caps and the guard's
  rate / concurrency / per-host back-off (enforced inside `PipelineClient::send`).
  `scan.run` enforces one shared request/time budget across all phases.
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
  workspace tool-contract test green.
- No LLM / model call anywhere in the crate (deterministic heuristics + static
  payload sets only).
- No new matcher DSL, PoC format, findings model, scope model, rate limiter, or
  SSRF classifier — all reused unchanged.
- No out-of-band (Interactsh-style) collaborator; blind/OOB classes stay out of
  scope (scope spec §Non-goals).
- No remediation prose; findings, PoC, and structured results only.

## Anti-goals

- A scanner that **issues an active request to an out-of-scope host from any
  caller**. Every injected request goes through `host.client().send` →
  `check_active`; an out-of-scope host is refused with `GuardError::OutOfScope`.
- An **agent** running active injection with the flag off, or an active phase that
  runs with egress *unconfined* while a browser could follow a redirect/sub-resource
  off scope (the S2 exposure).
- An **unbounded** campaign: an inject pass or a `scan.run` that ignores the
  request/time budget or the per-host back-off.
- A finding, report, or structured result that **leaks a secret** (auth header,
  cookie, token) that passed through a scanned request.
- Any edit to `aitm-core`'s `Command`/`Flow`/`Event`/`ProtocolModule`/guard types,
  or a parallel re-implementation of a shipped scanner type (`ScannerConfig`,
  `InjectionPoint`, `Location`, `enumerate`, `crawl`) instead of extending it.
- `scanner.allow_agent_active = true` silently doing nothing for an agent because
  the MCP policy gate was never told `scan.inject`/`scan.run` carry their own
  per-command gate: under `AgentPolicy::All` a `Sensitive` command that is not in
  `defers_to_command_gate` is refused by policy before its own flag is consulted.
  (Added by the 2026-10-30 amendment; see Open question 6 for the posture choice.)
- **Two finding records for one confirmation.** The PoC runner auto-records a
  finding when the host it is given carries a finding recorder; the scanner records
  its own, so the runner must be handed a host with no recorder (see "Reproduce →
  record").
- A **production** `control_passed` that claims a patched-control comparison the
  scanner cannot perform against a real target (see "Reproduce → record").

## Constraints

- **Language/gate:** Rust. `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test` must pass before any review (each task's "Done when"
  cites it). Default `cargo test` stays hermetic: no real browser, no live
  external network. Browser-dependent tests are `#[cfg_attr(not(AITM_OBSCURA),
  ignore)]`.
- **No core edits (hard).** Extend the shipped `aitm-plugin-scanner` crate and its
  registration. Reach core services only through `CommandHost`
  (`store()`, `client()`, `guard()`, `browser()`, `frontend()`, `config()`,
  `egress_handle()`; **not** `finding_recorder()` — the scanner deliberately never
  records through that seam, see "Reproduce → record"). **Verified this session: no
  `CommandHost` accessor is missing** — `egress_handle()` already exists and is
  already used by `scan.discover`, so active confinement needs **no** core change;
  the narrowed host the reproduction step needs (see "Reproduce → record") is built
  from the existing accessors `store()/client()/guard()/browser()/frontend()/
  ssrf_policy()/poc_dir()/client_label()/egress_handle()`, so it needs none either.
  A task that finds it must edit an `aitm-core` type **stops and reports**.
  **The one production edit outside the scanner crate** (2026-10-30 amendment) is a
  match arm in `aitm-mcp`'s `defers_to_command_gate` per gated verb (`scan.inject`,
  `scan.run`): a policy list in `crates/aitm-mcp/src/server.rs`, not an `aitm-core`
  type, the same category as the existing `scope.add` entry.
- **Confinement is RAII.** `EgressConfinement::confine()` returns a
  `ConfinementToken` that holds the hold until dropped (refcounted on the shared
  `Arc`); the active phase relies on the drop, never on `set_base`.
- **Active chokepoint.** `PipelineClient::send` already calls
  `self.guard.check_active(&req.authority)?`, holds the permit across the send,
  records errors toward the host back-off, and inserts the replay flow. The
  injector sends through `host.client().send` and does **not** add a second network
  path; it additionally gates the target host up front (deny-by-default, like the
  crawl seed) so an out-of-scope target is refused before enumeration.
- **Reuse, do not reinvent:** correlation via `aitm_poc::matcher::{MatchContext,
  evaluate}` + `Assertion`; PoC via `aitm_poc::{StdPocBuilder, PocSpec, Poc,
  PocInfo, Variable, Severity}` and run via `aitm_poc::{StdPocRunner, PocRunner,
  PocRunResult, VarBindings}`; findings via `aitm_findings::{FindingRecord,
  Reproduction, FindingArtifacts, DiskFindingStore, FindingStore, render_report,
  render_index}`; redaction via `aitm_core::redact::{scrub_text, is_secret_key}`
  plus the shipped `discover::enumerate` redaction.
- **Workspace tool contract.** Registering each new command changes the live
  `tools/list`; the exact-match contract test `crates/aitm/tests/frontends.rs`
  (`EXPECTED_TOOLS`, currently `[&str; 56]`) must be updated (count + name) in the
  same task that registers the command, or the workspace gate fails. Any other
  workspace contract list that fails because a `scan.*` name was added is updated
  in the same task.
- **Test target.** `aitm-testtarget` already serves the linked index surface and
  all six seeded classes with `SeedMode::{Vulnerable, Patched}` (reflected-XSS
  `/search?q=`, open-redirect `/redirect?next=`, stored-XSS `/comments`, SSRF
  `/fetch?url=`, IDOR `/account/{id}`, auth-bypass `/admin`). No test-target change
  is required for the default-active classes; a new class only if Stage 4 broadens
  beyond the seeded set (it does not).

## Design

**Amendment 2026-10-30 (post-merge corrections; where it and earlier text disagree,
this amendment wins).** PR #84 ("backend Stages 2-5 design spec", branch
`claude/scanner-backend-scope`) was closed as superseded by this document, with a
comment that its three corrections and open questions were "carried over". An
integrity audit found they were not. Each correction was re-verified independently
against the code at `78405c3` rather than copied from the draft:

1. **Reproduction runs `StdPocRunner`, not the `poc.run` command** — verified
   (`ctx.rs` :132-144, `runner.rs` :466-510); one rationale clause in the draft
   ("`FindingDraft` has no scanner `class` field") was imprecise and is not repeated.
   See "Reproduce → record".
2. **The MCP policy gate needs `scan.inject`/`scan.run` in `defers_to_command_gate`**
   — verified for `AgentPolicy::All` and `Auto`, but **partly overstated** for the
   draft's "no observable effect under any policy": under `Ask` the parked call runs
   as the agent after operator approval whether or not the verb is listed. Whether to
   add the entry is also a posture choice with precedent on both sides
   (`l4.inject` listed, `script.save` deliberately not). See "MCP policy layer" and
   Open question 6.
3. **`control_passed` is a test-suite comparison, not a production field** —
   verified (`recorder.rs` :42; the only code that computes a control run is the
   test harness, `crates/aitm/tests/support/scripted_driver.rs` :586-615). See
   "Reproduce → record".

Two further gaps surfaced while verifying (1) and are recorded here, not in the
draft: the PoC the builder emits must be built from the **attack** flow, so
`Confirmed` carries it (`attack_flow`); and the builder turns credential headers into
required `{{var}}` placeholders, so the reproduction run must bind them in memory
(see "Reproduce → record"). The draft's open questions that were also dropped are
re-asked as Open questions 7-9.

### Shipped ground truth this design builds on (read 2026-10-30)

| Shipped API (exact) | Where | How this design uses it |
|---|---|---|
| `ScannerConfig { max_depth, max_pages, request_budget, time_budget, per_class_payload_cap, allow_agent_active }`, `Default` = (3, 200, 2000, 600 s, 25, false) | `config.rs` | Reused as-is; the agent gate reads `allow_agent_active`; `request_budget`/`time_budget`/`per_class_payload_cap` bound inject + run. **No field added.** |
| `ScannerPlugin::new(cfg)`; `Plugin::load(&mut self, reg)` → `reg.add_command(Arc::new(..))` | `plugin.rs` | `load` extended to register the five new commands, each holding a clone of `self.cfg`. |
| `enumerate(&HttpFlow) -> Vec<InjectionPoint>`; `InjectionPoint { flow, location, name, example }`; `Location { Query, BodyParam, Header, Cookie, PathSegment, Redirect }` (redaction built in) | `discover.rs` | The injector enumerates points from store flows exactly as `scan.discover` does; `example` is already redacted. |
| `crawl(host, target, cfg) -> CrawlOutcome { endpoints, pages_crawled, stopped_reason }`; `normalize_url`, `block_on` | `crawl.rs` | `scan.run`'s discover phase calls `crawl`; the sync commands call `block_on`. |
| `CommandHost::{store, client, guard, browser, frontend, config, egress_handle, finding_recorder}` | `ctx.rs` | All service access (except `finding_recorder`, which the scanner deliberately does not use). `egress_handle()` returns `Option<Arc<EgressConfinement>>`. |
| `EgressConfinement::confine(self: &Arc<Self>) -> ConfinementToken` (RAII, refcounted) | `egress.rs` | Active phase: `let _confine = host.egress_handle().map(|e| e.confine());`. |
| `PipelineClient::send` gates `check_active`, holds permit, records errors, inserts replay flow | `client.rs` | The injector's one network path. |
| `Command` trait: `name`, `schema() -> ParamSchema`, `invoke(args, host) -> Result<Value>`, `sensitivity() -> Sensitivity`, `confirm_prompt(&Params) -> Option<String>`, `mutates`, `summarize` | `command.rs` | New commands implement these; `scan.inject`/`scan.run` override `confirm_prompt`. |
| `poc.allow_agent_run` gate: `if host.frontend() == Frontend::Mcp && !flag { bail!(...) }`; Operator/Cli never gated | `runner.rs` ~1103 | The exact shape `scanner.allow_agent_active` mirrors. |
| `MatchContext::new(status, body).with_header(..)`; `evaluate(&Assertion, &MatchContext) -> bool`; `Assertion::{Status, Word{word,part}, Regex{regex,part}, Dsl, All, Any, Not}`; `MatchPart::{Body, Header, All}` | `aitm-poc matcher/model` | Correlation and passive checks. |
| `StdPocBuilder::build(&HttpFlow, PocSpec{info, variables, success}) -> Poc`; `PocInfo`, `Variable`, `Severity` | `aitm-poc builder/model` | PoC emit on confirm. |
| `FindingRecord { id, title, class, severity, target, discovered_at, origin, client_label, poc_ref, reproduction, artifacts, flows, notes }`; `Reproduction { passed, control_passed, run_at }`; `FindingArtifacts { finding_capture, poc_path, screenshot_path }`; `DiskFindingStore::new(dir)`; `FindingStore::{record, get, list}`; `render_report(&[FindingRecord]) -> String`; `render_index(&[FindingRecord]) -> serde_json::Value` | `aitm-findings` | Record on confirm; read back + render in `scan.report`. |
| Seeded target: `SeedMode::{Vulnerable, Patched}`, `REFLECTED_XSS_MARKER`, routes incl. `/search?q=`, `/redirect?next=`, linked `/` index | `aitm-testtarget` | Inject confirmation pass-on-vulnerable / fail-on-patched. |
| Contract: `EXPECTED_TOOLS: [&str; 56]` incl. `scan.discover`; `COMMAND_NAMESPACES` already has `scan` | `crates/aitm/tests/frontends.rs`, `agent_surface.rs` | Bump to `[&str; 61]` across the five commands. |
| `PocRunner::run(&self, &Poc, VarBindings, &CommandHost) -> BoxFuture<Result<PocRunResult>>`; `StdPocRunner::{new, with_output_dir}`; `PocRunResult { passed, finding_capture, poc_path, screenshot_path, evaluated, recorded_id }`. `run_inner` auto-records through `host.finding_recorder()` **iff** the run passed **and** a recorder is wired **and** `findings.dir` is configured. The `poc.run` command reaches it through `run_poc_command`, which also holds the `poc.allow_agent_run` gate | `crates/aitm-poc/src/runner.rs` :243-252, :466-510, :1014-1016, :1097-1162 | The reproduction step runs this engine directly (a command cannot invoke another command: `CommandHost` has no `Registry`, `ctx.rs` :132-144). |
| `FindingDraft { title, class, severity, target, poc_ref, passed, finding_capture, flows, poc_path, screenshot_path, origin, client_label }` and `DiskFindingRecorder`, which hard-codes `control_passed: None` and `notes: None`; the runner fills `class` from `poc.info.cwe`, else the first tag, else the PoC id | `crates/aitm-core/src/ctx.rs` :78-91; `crates/aitm-findings/src/recorder.rs` :30-52; `runner.rs` :477-483 | Why the scanner does **not** record through the runner's auto-record (see "Reproduce → record"). |
| `policy_decision`: `(All, Sensitive) => defers_to_command_gate(name)`; `(Auto, Sensitive) => false`; `(Ask, Sensitive)` parks for operator approval, then runs the command as the agent. `defers_to_command_gate` today lists `ca.install`, `ca.uninstall`, `scope.add` and the `l4.*` Sensitive verbs; `script.save` is deliberately absent | `crates/aitm-mcp/src/server.rs` :1549-1592, :1373-1377, :1900-1921; `crates/aitm-mcp/tests/mcp.rs` :1243-1258, :1406-1442, :1480-1506 | The policy layer in front of `scanner.allow_agent_active` (see "MCP policy layer"). |

### Module layout (new files in the shipped crate)

```
crates/aitm-plugin-scanner/src/
  passive.rs    (new)  PassiveFinding, passive_checks(&HttpFlow) -> Vec<PassiveFinding>
  checks.rs     (new)  Location-keyed CheckDefinition, Payload, Evidence, reflected_xss(), open_redirect()
  inject.rs     (new)  InjectOutcome, Confirmed, inject(host, target, def, points, cfg) -> ...
  reproduce.rs  (new)  build_poc(..), narrowed_host(..), reproduce(..), finding_record(..), record_finding(..)
  report.rs     (new)  load_records(host, target?) -> Vec<FindingRecord> (reads the configured store)
  campaign.rs   (new)  CampaignSummary, run_campaign(host, target, opts, cfg) -> ...
  commands.rs   (modify) add ScanPassive, ScanReport, ScanInject, ScanRun, ScanStatus
  plugin.rs     (modify) register the five commands
  lib.rs        (modify) re-exports
```

`ScannerPlugin` continues to observe no events. Engine modules (`passive`,
`checks`, `inject`, `reproduce`, `report`, `campaign`) are pure library code with
their own files, so independent tasks fan out; the command structs all live in
`commands.rs` + register in `plugin.rs` + bump `frontends.rs`, so they form one
serialized chain.

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
re-leaked.

### `scan.report` — Read

`report::load_records(host, target?) -> Vec<FindingRecord>` builds a
`DiskFindingStore::new(dir)` from `host.config().findings.dir` (returning an empty
list, not an error, when no dir is configured) and lists/gets the records,
filtered to `target` when given. `ScanReport` (`Sensitivity::Read`) returns
`{ report_md: Str, index: Array }` where `report_md = render_report(&records)` and
`index` is `render_index(&records)` **converted** from `serde_json::Value` to
`aitm_core::Value` (a small local converter; `render_index` returns serde_json).
Index entries carry `poc_path`, `target_path`, `class`, `passed`,
`control_passed`, `finding_capture`, `screenshot_path` (render_index's shape),
which the UI's Findings fold consumes.

### `scan.inject` — Sensitive, agent-gated, scope-confined

`checks.rs` defines one static definition per class:

```
pub enum AttackMode { BatteringRam }            // Stage-4 broaden adds ClusterBomb
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
    pub fn open_redirect() -> Self;   // Regex over the Location header, location Redirect
    pub fn for_class(class: &str) -> Option<Self>;
}
```

`inject.rs`:

```
pub struct InjectOutcome { pub class: String, pub tested: usize,
    pub confirmed: Vec<Confirmed>, pub stopped_reason: Option<String> }
pub struct Confirmed { pub injection_point: InjectionPoint,
    pub payload: String, pub evidence: String,
    pub attack_flow: aitm_core::FlowId }   // the replay flow `send` returned (2026-10-30 amendment)
pub async fn inject(host: &CommandHost<'_>, target: &str, def: &CheckDefinition,
    points: &[InjectionPoint], budget: &mut usize, cfg: &ScannerConfig)
    -> anyhow::Result<InjectOutcome>;
```

`inject` gates the target host up front (`host.guard().check_active` →
`GuardError::OutOfScope` on an unscoped target, deny-by-default), then for each
applicable point × payload (batteringram, capped at `per_class_payload_cap`)
crafts the mutated `HttpRequest`, sends it through `host.client().send` (the one
guarded chokepoint — scope/rate/back-off enforced there), builds a `MatchContext`
from the returned flow's response, calls `def.confirm`, and collects `Confirmed`.
It decrements the shared `budget`; at zero it stops with `stopped_reason =
"budget"`. Payload *strings* are inert, class-appropriate markers (reflected-XSS
uses a benign unique canary token, not an executing script; open-redirect uses an
off-origin sentinel host compared in `Location`). Each `Confirmed` carries the
`attack_flow` id of the replay flow `send` returned for the confirming request, so
the reproduction step can build its PoC from the request that actually carried the
payload (the benign source flow in `injection_point.flow` does not contain it).

`ScanInject { cfg: ScannerConfig }` (`Sensitivity::Sensitive`):

1. **Agent gate (mirrors `poc.allow_agent_run` exactly):** at the top of `invoke`,
   `if host.frontend() == Frontend::Mcp && !self.cfg.allow_agent_active { bail!(
   "scan.inject refused: active injection from an agent frontend is disabled. Set
   scanner.allow_agent_active = true in the aitmproxy config to allow it, or run it
   from the operator/CLI.") }`. `Frontend::Operator`/`Frontend::Cli` are never
   gated. This is the per-command flag layer; the `Sensitive` policy tier is the
   independent upstream layer, and an agent only reaches this check over MCP if the
   policy layer lets it through (see "MCP policy layer": under `All` that requires
   `scan.inject` in `defers_to_command_gate`; `Auto` never does).
   **(Architect's call — source of the flag:** the flag
   is read from the plugin-owned `ScannerConfig` (shipped field), not from
   `host.config()`, because the scope design keeps `ScannerConfig` plugin-owned
   with no new `aitm_core::config::Config` field. Behaviour and error shape are
   identical to `poc.allow_agent_run`; only the storage location differs.)
2. **Confinement:** `let _confine = host.egress_handle().map(|e| e.confine());`
   before the active phase; dropped (RAII) when `invoke` returns.
3. Enumerate points from the store flows for `target`, select those matching
   `def.locations` (or the single `injection_point` argument when given), call
   `block_on(inject(..))`, and on each `Confirmed` build the PoC from its
   `attack_flow`, reproduce it through `StdPocRunner` on a recorder-less narrowed
   host, and record one `FindingRecord` with `control_passed: None` (see "Reproduce →
   record"). The reproduction request is counted against the same `budget`.
4. Return `{ class, tested, confirmed: [ {injection_point: {flow, location,
   name}, payload, evidence} ], finding_ids: [id], stopped_reason }`. All strings
   scrubbed.
5. `confirm_prompt` returns `Some("Run active injection (class <class>) against
   <target>? This issues attack traffic to the authorized target.")` so human
   surfaces get the confirm handshake (integration D-MCP3).

### Reproduce → record (reuse)

`reproduce.rs` (amended 2026-10-30; the first signature is unchanged except that its
`flow` argument is now specified to be the **attack** flow):

```
pub fn build_poc(attack_flow: &HttpFlow, def: &CheckDefinition,
    point: &InjectionPoint, payload: &Payload) -> anyhow::Result<aitm_poc::Poc>;
pub fn narrowed_host<'a>(host: &'a CommandHost<'_>) -> CommandHost<'a>;
pub async fn reproduce(host: &CommandHost<'_>, poc: &aitm_poc::Poc,
    attack_flow: &HttpFlow) -> anyhow::Result<aitm_poc::PocRunResult>;
pub fn finding_record(host: &CommandHost<'_>, def: &CheckDefinition, target: &str,
    poc: &aitm_poc::Poc, run: &aitm_poc::PocRunResult)
    -> aitm_findings::FindingRecord;
pub fn record_finding(host: &CommandHost<'_>, rec: aitm_findings::FindingRecord)
    -> anyhow::Result<String>;
```

**Building the PoC.** `build_poc` is fed the *attack* flow — the replay flow
`host.client().send` returned for the confirming request, which is why `Confirmed`
carries `attack_flow` — because `StdPocBuilder` parameterizes the concrete URL pieces
of the flow it is given and the benign source flow does not contain the payload. It
assembles `PocSpec { info, variables, success }` with `success` the class's
confirming `Assertion` (same operator `confirm` evaluates) and calls
`StdPocBuilder::default().build(attack_flow, spec)`. The base URL is parameterized to
a `{{target}}` variable; credential headers (`Cookie`, `Authorization`,
`Proxy-Authorization`, `X-API-Key`) become **required** `{{var}}` placeholders with
no default (`builder.rs` :74-79, :116-141). `PocInfo.severity` comes from a
class-to-severity mapping local to `reproduce.rs` (the shipped `CheckDefinition`
carries no severity field; the values are the builder's choice).

**Running the PoC (Correction 1).** A command cannot invoke another command:
`CommandHost` holds no `Registry` (`ctx.rs` :132-144) and `Command::invoke` receives
nothing else, so there is no "call `poc.run`" primitive. The scanner does what
`scan.discover` already does with `crawl`/`enumerate` — it calls the library engine
directly. `reproduce` runs the built PoC through `aitm_poc::StdPocRunner`, the engine
the `poc.run` command itself calls (`run_poc_command`, `runner.rs` :1152-1162), with
its output directory chosen the way `run_poc_command` chooses it (`poc.out_dir` from
`host.config()`, else the system temp dir). It issues exactly **one** further guarded,
captured request. Bindings are `target` = the attack flow's `scheme://authority`,
plus, for every required credential variable the builder introduced, the matching
request-header value from the attack flow, bound **in memory only**: an unbound
placeholder fails the run with "unknown variable" (`template.rs` :115-119). The YAML
PoC the runner writes keeps the `{{placeholder}}`, so no credential reaches the PoC
file, the record, or any result.

`reproduce` takes the run's verdict at face value: the record's
`reproduction.passed` is `PocRunResult.passed`, never a hard-coded `true`. Three
consequences are **Architect's calls**: (i) the `poc.allow_agent_run` gate that
`run_poc_command` applies (`runner.rs` :1106-1117) is deliberately *not* re-applied,
because the PoC is scanner-built, HTTP-only and never loaded from a caller-supplied
path, so `scanner.allow_agent_active` is the single flag governing the whole active
phase including this request (a second flag would make `allow_agent_active = true`
insufficient for an agent without any safety gain); (ii) the reproduction request goes
through the same chokepoint (`check_active`, rate, back-off) and is **counted against
the shared `budget`** (`ScannerConfig.request_budget` is "the maximum number of
requests the whole run may issue"), so a confirmation that arrives with no budget left
is still reported in `confirmed` but is neither reproduced nor recorded and the call
stops with `stopped_reason = "budget"`; (iii) each `Confirmed` passed to `reproduce`
yields exactly one run and one record, and a run that does not pass is still recorded,
truthfully, with `passed == false` rather than dropped (a confirmed-but-unreproduced hit
is information the operator should see; the runner's own record-on-pass-only rule does
not apply because the scanner does not use the runner's recording).

**Exactly one record (the double-record hazard).** `StdPocRunner::run_inner` already
records a finding on its own when the host it is handed has a wired
`finding_recorder` and a configured `findings.dir`, on a passing run (`runner.rs`
:466-510; covered by `t7_records_finding_on_pass`, `t7_no_recorder_records_nothing`,
`t7_failed_run_records_nothing` in `crates/aitm-poc/tests/dvwa_fixes.rs`). The binary
wires the recorder onto both the MCP server and the CLI host (`server.rs` :1457-1460,
`dispatch.rs` :149, `main.rs` :301), so passing the command's own host to the runner
would write a second record beside the scanner's. `reproduce` therefore runs the PoC on
`narrowed_host(host)`: a `CommandHost` rebuilt from the same borrowed services
(`store`, `client`, `guard`, `browser`) plus `frontend`, the SSRF policy, `poc_dir`,
`client_label` and the egress handle, but with **no finding recorder and no
`Config`** (the runner reads `findings.dir` only through `config()`, so either
omission silences the auto-record; omitting both is belt and braces). The result's
`recorded_id` is then `None` by construction. Every accessor needed already exists
(`ctx.rs` :226-281), so this is not a core edit.

**Why the scanner records its own.** `FindingDraft` does have `class` and `severity`
fields, but the runner fills `class` from `poc.info.cwe`, else the first tag, else the
PoC id (`runner.rs` :477-483), so a CWE later added to the PoC metadata would silently
change the class a finding is filed under, and the scanner's class strings
(`reflected-xss`, `open-redirect`) are the ones the test-target grader matches on
(`crates/aitm-testtarget/src/manifest.rs`, `grader.rs`). The recorder also writes
`notes: None`, and recording must work on a host that has no recorder wired. So
`finding_record` builds the `FindingRecord` directly (`class = def.class`; `severity`
from the same mapping; `title = poc.info.name`; `target` scrubbed; `origin =
host.frontend()`; `client_label`; `poc_ref = poc.id`; `artifacts` and `flows` from the
`PocRunResult`; `notes: None`), and `record_finding` persists it via
`DiskFindingStore::new(dir)` from `host.config()` `findings.dir`, and **never** via
`host.finding_recorder()`. `FindingStore::record` redacts free text at the store
boundary; the scanner additionally never puts a param value or raw header into
`title`/`notes`.

**`control_passed` is `None` in production (Correction 3).** The original scanner
spec's AC11 and this document's earlier AC10 described a confirmed finding recording
`control_passed == Some(false)` "on the patched control", as if diffing against a
patched variant were something `scan.inject` does at runtime. It cannot: a real target
(a client's staging site, DVWA) has no patched control the scanner can locate.
`poc.run`'s own `DiskFindingRecorder` already reflects this — it hard-codes
`control_passed: None` because one run only ever touches one target (`recorder.rs`
:6-7, :42) — and the only code in the tree that computes a control run is a test
harness that owns a separate known-patched twin (`scripted_driver.rs` :586-615).
Therefore **a production `scan.inject`/`scan.run` confirmation always records
`control_passed: None`.** The vulnerable-versus-patched proof is a property of the
*test suite*: confirm on `SeedMode::Vulnerable`, and confirm nothing on
`SeedMode::Patched`, by two separate calls, each asserted on the call's own
`confirmed` list (AC6, AC23). Known consequence, not a defect: `render_report`'s
summary line counts a finding as "reproduced against a patched control" only for
`Some(false)` (`aitm-findings/src/report.rs` :84-91, :106-111), and the test-target
grader scores "reproduced" the same way (`grader.rs` :56), so scanner findings render
as "no patched control was run" and are graded "found", not "reproduced". A test of
`scan.report` must not assert a non-zero "reproduced" count for scanner records.

### `scan.run` — Sensitive, one shared budget, confined

`campaign.rs`:

```
pub struct CampaignSummary { pub run_id: String, pub phase: String,
    pub pages_crawled: usize, pub requests_used: usize, pub confirmed_count: usize,
    pub stopped_reason: Option<String> }
pub async fn run_campaign(host: &CommandHost<'_>, target: &str, active: bool,
    cfg: &ScannerConfig) -> anyhow::Result<(CampaignSummary, Value)>;
```

`ScanRun { cfg }` (`Sensitivity::Sensitive`, same agent gate + `confirm_prompt` as
`scan.inject`, and its own `defers_to_command_gate` entry — see "MCP policy layer";
each confirmation in its inject phase is reproduced and recorded exactly as
`scan.inject` does, with `control_passed: None`) takes a **single** `let _confine =
host.egress_handle().map(|e| e.confine());` for the whole campaign and runs, under
one shared `request_budget`
and one `time_budget`: **discover** (`crawl`) → **passive** (`passive_checks` over
captured flows) → **inject** (default-active classes, when `active`) → **report**
(`render_report`/`render_index`). It returns `{ run_id, discover, passive, inject,
report, stopped_reason }` (each phase the corresponding verb's result object), and
updates the in-plugin last-run status snapshot. The shared budget means the inject
phase sees the requests the discover phase already spent; hitting it stops the
campaign with `stopped_reason = "budget"`.

`ScanStatus { … }` (`Sensitivity::Read`) returns the plugin's last/live campaign
snapshot `{ run_id, phase, pages_crawled, requests_used, request_budget,
confirmed_count, stopped_reason }`. **(Architect's call:** progress is a
*snapshot* read, not a streamed channel — matches the integration spec's polling
baseline. The snapshot is held in a process-lifetime `Mutex`/atomic owned by the
plugin, keyed by `run_id`, bounded to the last campaign; a richer multi-run
registry is deferred.)

### Agent gate summary (the 1:1 mirror)

| | `poc.allow_agent_run` (shipped) | `scanner.allow_agent_active` (this design) |
|---|---|---|
| Tier | — (runner) | `scan.inject`/`scan.run` = `Sensitive` |
| Refuse when | `frontend()==Mcp && !flag` | `frontend()==Mcp && !flag` |
| Operator/CLI | never gated | never gated |
| Flag storage | `aitm_core::config::Config.poc.allow_agent_run` | plugin-owned `ScannerConfig.allow_agent_active` (no core field) |
| Error | `bail!("poc.run refused … Set poc.allow_agent_run = true …")` | `bail!("scan.inject refused … Set scanner.allow_agent_active = true …")` |
| Policy-layer reachability | `poc.run` is `Write`: `Auto` and `All` both reach `invoke`, so it needs no allow-list entry | `Sensitive`: **not** a 1:1 mirror here. The right precedent is `scope.add`/`ca.install`/`l4.*` — named in `defers_to_command_gate` (Open question 6) |

### MCP policy layer (amended 2026-10-30; Correction 2)

The first layer of the two-layer gate is `McpServer::policy_decision`
(`crates/aitm-mcp/src/server.rs` :1549-1592). It gates only the agent role
(`Frontend::Mcp`); `Operator` and `Cli` always pass. For a `Sensitive` command:

| Agent policy | Reaches `scan.inject`'s own flag check? | Source |
|---|---|---|
| `Auto` (the default) | **No, never** — refused outright, flag irrelevant (by design, same as `scope.add`) | :1569 |
| `All` | **Only if** `defers_to_command_gate("scan.inject")`; otherwise refused by policy before the flag is read | :1564, :1900-1921 |
| `Ask` | Yes, after an operator approves the parked call; the call then runs as the agent and the flag decides. Independent of the allow-list | :1373-1377, :1574-1580 |
| `ReadOnly`, `Paused` | No | :1581-1583 |

So without an allow-list entry `scanner.allow_agent_active = true` is a silent no-op
under `All` (the draft in PR #84 said "under any policy", which overstates it: `Ask`
works). **Default (Architect's call, Open question 6): add `"scan.inject"` (Stage 3)
and `"scan.run"` (Stage 4) to `defers_to_command_gate`**, as `scope.add`,
`ca.install` and the `l4.*` Sensitive verbs are, so that an operator who sets the
policy to `All` *and* the flag gets an agent that can run active injection, and the
two layers stay independent. Operationally an agent therefore needs **both** the
flag and policy `all` (or `ask` with an operator present); under the default `auto`
policy it is refused regardless of the flag. The posture has a precedent on the other
side — `script.save` and the other script-authoring verbs are *deliberately* not
listed so an autonomous agent cannot self-authorize on a flag alone
(`mcp.rs` :1251-1258, :1406-1442; scripting command-surface spec AC8) — which is why
this is a question for Matt rather than a settled fact.

The earlier scope design's sentence "under `All` it reaches `invoke`"
(`2026-10-29-aitmproxy-scanner-plugin-design.md`, "Two independent layers") is true
only with the entry; this section supersedes it for the backend.

**Operator-configurability of the flag** (threading a config-file `[scanner]`
section into `ScannerConfig` at `wire.rs`, today hard-wired `::default()`) is
owned by the **integration** plan's **D-MCP2 / AC9**, which explicitly claims it.
This backend plan provides the plugin gate + its unit tests (which construct
`ScannerPlugin::new(ScannerConfig { allow_agent_active, .. })` directly) and does
**not** edit `wire.rs`/`config_file.rs` for the flag, to avoid duplicate work and
honour "no core edits". See Open question 5. The integration plan's Task 8 test
(`scan_inject_gate_is_wired_default_off`, "accepted with the flag on under
`AgentPolicy::All`") can only pass once the `defers_to_command_gate` entry above has
landed, and that plan's task does not mention it; the backend Task 8 therefore must
merge before integration Task 8.

### UI-shape reconciliation (checked against the integration design)

No blocking mismatch found. `scan.discover`'s shipped shape (`endpoints`,
`injection_points[{location,name,example}]`, `endpoint_flows`) already matches.
The new shapes defined here satisfy the integration ACs: `scan.passive`/`scan.report`
feed the Findings fold (integration AC7) — `scan.report.index` is exactly
`render_index`, which the UI already understands; `scan.inject`/`scan.run` are
`Sensitive` with `confirm_prompt` (AC10, D-MCP3); `scan.status` carries
`phase` + counters + terminal `stopped_reason` (AC11). One deliberate naming
choice resolved in the backend's favour: the per-attempt confirmation list is
`confirmed` (not `findings`) and the recorded findings are reachable by `id`
(`finding_ids`) and through `scan.report`/the Findings pane — the UI folds
findings from the report/index, not from the raw `inject` result (integration
AC7 reads the report source), so this is consistent.

## Acceptance criteria

Numbering is self-contained to this spec; the scope spec's AC it restates is noted
in brackets.

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
   `class`, and `passed`. [scope AC12]

**Stage 3 — active injection, reproduce, record (Sensitive, gated)**

5. **AC5:** `scan.inject {target, class}` reports `Sensitivity::Sensitive` and
   returns `{ class, tested, confirmed, finding_ids, stopped_reason }` with
   per-attempt structure. [scope AC7]
6. **AC6:** For `class = "reflected-xss"`, injection **confirms** on a
   `SeedMode::Vulnerable` response and **does not confirm** on a
   `SeedMode::Patched` response, via `matcher::evaluate` (literal: `confirmed`
   non-empty vulnerable, empty patched). [scope AC8]
7. **AC7:** An MCP-frontend `scan.inject` **invoked on the command** (a host with
   `Frontend::Mcp`) is refused when `allow_agent_active == false` (error naming
   `scanner.allow_agent_active`) and runs when it is `true`; an `Operator`/`Cli`
   frontend always runs. *(Amended 2026-10-30: this is the per-command flag layer
   only. Whether an agent can reach the command over the assembled MCP server also
   depends on the policy layer, which AC21 pins; "runs when it is `true`" is not
   claimed for `AgentPolicy::Auto`, which never lets a `Sensitive` call through.)*
   [scope AC9]
8. **AC8:** `scan.inject` never issues a request to an out-of-scope host from any
   caller: an unscoped target returns `GuardError::OutOfScope`. [scope AC10]
9. **AC9:** During `scan.inject`'s active phase the attached `EgressConfinement`
   is confined (`confined() == true` observed while injecting) and is released
   (`confined() == false` with an off base) once `invoke` returns; a host with no
   posture wired still runs (literal, probe like the shipped
   `scan_discover_crawls_under_egress_confinement`). [new / S2 parity]
10. **AC10:** On a confirmation the engine builds a PoC via `StdPocBuilder` from the
    confirming request's attack flow, reproduces it through `StdPocRunner` on a
    narrowed host, and records a `FindingRecord` with `reproduction.passed == true`
    (the run's verdict) and `reproduction.control_passed == None`. *(Amended
    2026-10-30: the earlier `control_passed == Some(false)` required a production
    patched-control run that cannot exist against a real target; the
    vulnerable-versus-patched proof is AC6 and AC23.)* [scope AC11, whose
    `control_passed == Some(false)` clause is superseded here]
11. **AC11:** No secret from a scanned request appears in any recorded
    `FindingRecord`, in `scan.report` output, or in the `scan.inject` result
    (literal: an `Authorization: Bearer abc123` source flow yields no `abc123`).
    [scope AC13]
12. **AC12:** `scan.inject` is request-bounded: with `request_budget == 1` it stops
    with `stopped_reason == "budget"`. [scope AC14/AC17]
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
    stopped_reason }` for the last/live campaign.
18. **AC18:** Every new `scan.*` command appears in a `tools/list` over the
    assembled proxy with a non-empty `inputSchema`, and
    `crates/aitm/tests/frontends.rs` `EXPECTED_TOOLS` equals the live set
    (literal: the contract test passes with `scan.{passive,report,inject,run,
    status}` present; `[&str; 61]`). [integration AC1 / D-MCP1]
19. **AC19:** Loading `ScannerPlugin` with the full command set leaves the M4
    free-form loop working: the M4 scripted-driver gate still passes with the
    scanner loaded, and a driver that calls `scan.discover`/`scan.inject` records
    the same findings (no new mandatory gate in front of the free-form path).
    [scope AC16]
20. **AC20:** Inject coverage includes ≥ 3 vuln classes (reflected-XSS,
    open-redirect, and one more of the seeded set), each class's payload set capped
    at `per_class_payload_cap`; a multi-position class under a small budget stays
    ≤ `request_budget`. [scope AC14]

**Amendment criteria (2026-10-30; appended, so AC1-AC20 keep their numbers)**

21. **AC21 (policy reachability; the `scan.inject` half lands in Stage 3, the
    `scan.run` half in Stage 4):** Over a real `McpServer` whose registry carries
    `ScannerPlugin`, an MCP-role call to `scan.inject` (resp. `scan.run`) with
    `allow_agent_active == false` under `AgentPolicy::All` is refused by the
    **command's own** gate: the error text contains `scanner.allow_agent_active` and
    does not contain the policy-refusal text `not allowed to the agent under`. Under
    `AgentPolicy::Auto` the same call with the flag `true` is refused **by policy**
    (text contains ``the agent policy is `auto` ``). A `Cli` connection is never
    policy-refused. Separately, a stub `Sensitive` command named `scan.inject` (resp.
    `scan.run`) in the `aitm-mcp` policy-test server is **not** refused under `All`
    and **is** refused under `Auto`, proving the `defers_to_command_gate` entry by name
    the way `ca.install`/`scope.add` are proven. [new; Correction 2]
22. **AC22 (one record per reproduction):** With a counting `FindingRecorder` wired
    onto the host and `findings.dir` configured, a reproduced confirmation leaves the
    counter at `0`, `PocRunResult.recorded_id == None`, and the findings store holds
    exactly one `FindingRecord` per reproduction run (never two). [new; Correction 1]
23. **AC23 (control is a test property):** The vulnerable-versus-patched proof is two
    separate `scan.inject` calls: one against `SeedMode::Vulnerable` (`confirmed`
    non-empty, `finding_ids` non-empty, every stored record `passed == true` and
    `control_passed == None`) and one against `SeedMode::Patched` (`confirmed` empty,
    `finding_ids` empty, no stored record whose `target` is the patched base). No
    production code path sends a patched-control request. [new; Correction 3;
    refines AC6/AC10]
24. **AC24 (reproduction never persists a credential):** For a source flow carrying
    `Authorization: Bearer abc123` and `Cookie: PHPSESSID=abc123`, the reproduction
    run still passes (the credentials are bound in memory) and the YAML at
    `artifacts.poc_path` contains the placeholders `{{authorization}}` and
    `{{cookie}}` and no `abc123`. [new; extends AC11 to the PoC artifact]
25. **AC25 (reproduction is budgeted):** With `request_budget == 1` against a
    reflecting target, `scan.inject` returns `confirmed` non-empty, `finding_ids`
    empty, `stopped_reason == "budget"`, and the target observed exactly one request.
    [new; refines AC12]

## Left to the builder

- Internal module layout within each new file, struct field order, and private
  helper signatures.
- The concrete inert payload strings per class (from `02-nuclei.md` vocabulary),
  within `per_class_payload_cap`; the exact `Assertion` each `confirm` builds
  (using existing `aitm_poc` operators).
- How the request is mutated per `Location` (query/body/header/cookie/path/redirect)
  from the captured flow, provided it only mutates the one targeted point.
- The `run_id` scheme and the status-snapshot storage (a `Mutex`/atomic on the
  plugin), provided `scan.status` reads the last/live campaign.
- `scan.report` reads through `DiskFindingStore` (as `report::load_records` already
  does). Recording is **not** left open: it goes through `DiskFindingStore`, never
  `host.finding_recorder()` (see "Reproduce → record"); the earlier wording that left
  that seam as a choice is superseded because using it beside the runner's own
  auto-record is the double-record hazard.
- The exact way `narrowed_host` rebuilds the host from the existing accessors, the
  class-to-severity values in `reproduce.rs`, and which request headers the
  reproduction binds as in-memory credential variables (the set the builder turns
  into required placeholders).
- The serde_json→`aitm_core::Value` converter for `render_index`.
- Which third seeded class fills AC20 (stored-XSS, SSRF, IDOR, or auth-bypass).

## Open questions

Only Matt can decide these; each default is the Architect's call and a one-line
change if overridden.

1. **How aggressive is default active fuzzing (payload-set size per class)?**
   Default: **conservative** — reflected-XSS ≈ 8 payloads, open-redirect ≈ 6, each
   well under the shipped `per_class_payload_cap = 25`. The cap stays 25 as the
   hard ceiling an operator can raise per class; the *default* set is small to keep
   a campaign fast and low-noise. Alternative: ship the full 25-payload sets by
   default (louder, slower, more coverage).
2. **Which classes are active by default?** Default: **reflected-XSS +
   open-redirect only** (inert markers + patched controls, zero test-target work),
   plus one more seeded class for AC20 that is **opt-in per `scan.inject {class}`**
   but **not** run by `scan.run`'s default sweep. Alternative: `scan.run` sweeps
   all seeded classes by default.
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

*Added by the 2026-10-30 amendment (6 comes from verifying Correction 2; 7-9 are the
PR #84 draft's open questions that this document dropped), most consequential first:*

6. **May an autonomous agent under `AgentPolicy::All` self-authorize active injection
   with the flag alone?** Default: **yes — list `scan.inject` and `scan.run` in
   `defers_to_command_gate`**, the posture of `scope.add`, `ca.install` and the
   `l4.*` Sensitive verbs: the operator opts in twice (policy `all` **and**
   `scanner.allow_agent_active = true`), and the default `auto` policy refuses the
   agent regardless of the flag. Alternative: **leave them out**, as `script.save` is,
   so an agent's active scan can only be authorized under `Ask` with an operator
   present and the flag matters only there; then AC21's `All` arm flips (refused by
   policy even with the flag on) and Tasks 8 and 10 drop their allow-list entries.
   The choice must be deliberate either way: today's code has neither entry, which
   makes the flag a silent no-op under `All`.
7. **`scan.run` execution model and live progress.** As written `scan.run` is
   synchronous (a blocking `invoke`, bounded by `time_budget`, default 600 s) and
   `scan.status` reads a plugin-owned snapshot; but Task 10 stores the summary only
   after `run_campaign` returns, so a UI polling during a run sees the previous
   campaign (or nothing), while integration AC11 expects live phase and counts.
   Default: **stay synchronous**, update the snapshot at each phase boundary so a
   concurrent `scan.status {}` is live, and **refuse a second `scan.run` while one is
   in flight, naming the in-flight run** (otherwise two campaigns each assume they own
   the whole `request_budget`). Alternative: `scan.run` returns `{run_id}` at once and
   a background task does the work (matches "live progress" literally and never holds
   a connection ~10 minutes, but needs a lifecycle/cancellation story no command has
   today). Adopting the default changes Tasks 9 and 10; they are not amended here.
8. **Do passive observations reach the Findings pane?** `scan.passive` persists
   nothing, and `scan.report` renders only recorded `FindingRecord`s, so the
   integration UIs' Findings pane (which reads `scan.report`'s index) shows **zero**
   rows until `scan.inject` confirms something. ("UI-shape reconciliation" below says
   `scan.passive`/`scan.report` both feed the Findings fold; that holds only for
   `scan.report`.) Default: **confirmed-only** — observations and reproduced findings
   are different trust levels, and `aitm-findings` records a finding as "a separate,
   explicit, gated act" (`crates/aitm-findings/src/lib.rs` :10-12). Alternative: add
   an `observed` array to `scan.report`, or persist passive hits at a low-confidence
   tier.
9. **Payload-set source.** Default: **Rust literals** (what the shipped `checks.rs`
   already does), within `per_class_payload_cap`. Alternative: an operator-editable
   YAML directory (a `scanner.payloads_dir`), nuclei-style, so an operator can extend
   the dictionary without a rebuild — closer to the preference that scanner artifacts
   be human-editable, at the cost of a loader and schema this design does not
   otherwise need. Treated as an optional fast-follow if wanted.

## Summary

This design completes the deterministic scanner's backend for v0.6 by extending
the **shipped** `aitm-plugin-scanner` crate with five verbs — `scan.passive` and
`scan.report` (Read), `scan.inject` and `scan.run` (Sensitive, agent-gated,
egress-confined), and `scan.status` (Read) — reusing the shipped `ScannerConfig`,
`enumerate`, `crawl`, and `egress_handle`, the `aitm_poc` matcher/PoC vocabulary,
and the `aitm-findings` store/report, with **no `aitm-core` edit** (verified: the
`CommandHost::egress_handle` accessor active injection needs already exists).
Active injection rides the single guarded client chokepoint, holds an RAII
`ConfinementToken` for its whole phase, and refuses an agent caller unless
`scanner.allow_agent_active` is set — the exact shape of `poc.allow_agent_run`,
with the flag read from the plugin-owned config. Twenty-five acceptance criteria map
to the three stages (AC21-AC25 appended by the 2026-10-30 amendment); result shapes
match what the integration plan's UI tasks consume.

The 2026-10-30 amendment folds in three corrections that a closed draft (PR #84)
found and this document lost, each re-verified against the code: the reproduction step
runs `StdPocRunner` directly on a recorder-less narrowed host (a command cannot invoke
`poc.run`, and the runner would otherwise write a second finding); the MCP policy
gate needs `scan.inject`/`scan.run` in `defers_to_command_gate` or the flag is a
silent no-op under `AgentPolicy::All` (a posture choice, Open question 6); and
`control_passed` is `None` in production records because the patched-control
comparison belongs to the test suite.

### Architect's calls made (for Matt to approve or correct)

1. Flag `scanner.allow_agent_active` read from the plugin-owned `ScannerConfig`
   (no new `aitm_core::config::Config` field); behaviour/error identical to
   `poc.allow_agent_run`.
2. Active confinement uses the **existing** `CommandHost::egress_handle()` — **no
   core accessor added, no core edit** for `scan.inject`/`scan.run`.
3. Result shapes: `scan.passive {findings}`, `scan.report {report_md, index}`,
   `scan.inject {class, tested, confirmed, finding_ids, stopped_reason}`,
   `scan.run {run_id, discover, passive, inject, report, stopped_reason}`,
   `scan.status {run_id, phase, pages_crawled, requests_used, request_budget,
   confirmed_count, stopped_reason}`.
4. Tiers: `scan.passive`/`report`/`status` = Read; `scan.inject`/`run` = Sensitive.
5. First active classes **reflected-XSS + open-redirect**; a third seeded class for
   AC20 is opt-in per `scan.inject`.
6. `scan.status` is a last/live **snapshot** read (polling baseline), no streamed
   channel.
7. Operator-configurability of the flag is left to the integration plan's
   D-MCP2/AC9 (no `wire.rs`/`config_file.rs` edit here).
8. Correlation stays internal (no `scan.correlate` verb), returned as `evidence`.
9. Each command-registration task bumps `EXPECTED_TOOLS` to keep the workspace
   gate green (56 → 61).

*Added by the 2026-10-30 amendment:*

10. Reproduction runs `aitm_poc::StdPocRunner` directly (a command cannot call
    another command), with output-dir selection copied from `run_poc_command`.
11. The runner gets a **narrowed host with no finding recorder and no `Config`**, so
    its own auto-record is inert and exactly one record is written.
12. The scanner records through `DiskFindingStore`, never `host.finding_recorder()`:
    the runner's draft cannot name the scanner's class deterministically, and
    recording must work on a recorder-less host.
13. `control_passed` is `None` in every production record; the vulnerable-versus-patched
    proof lives in the e2e tests as two separate calls.
14. `scan.inject` (Task 8) and `scan.run` (Task 10) are added to
    `defers_to_command_gate` — the default for Open question 6, which Matt may flip.
15. The reproduction request is governed by `scanner.allow_agent_active` alone (the
    `poc.allow_agent_run` gate is not re-applied: the PoC is scanner-built and
    HTTP-only), is **counted against the shared budget**, and a run that does not pass
    is recorded truthfully (`passed == false`), not dropped.
16. `Confirmed` carries `attack_flow` (the PoC is built from the request that carried
    the payload), and the reproduction binds required credential variables from that
    flow **in memory only**.
17. The PoC's `PocInfo.severity` and the record's `severity` come from a
    class-to-severity mapping local to `reproduce.rs`, not a new `CheckDefinition`
    field (the shipped `checks.rs` has none).
