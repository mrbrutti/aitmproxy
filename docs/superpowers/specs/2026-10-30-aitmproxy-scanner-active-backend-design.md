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
these verbs.

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
  `StdPocBuilder`, records a `FindingRecord`, and returns a structured per-attempt
  result. First classes: **reflected-XSS + open-redirect** (both seeded).
- **`scan.run {target, active?}`** (**Sensitive**) orchestrates discover → passive
  → inject → report as one campaign under **one shared budget**, holding an egress
  token for the whole run, and returns a structured campaign summary with a
  `run_id`.
- **`scan.status {run_id?}`** (**Read**) returns the live/last campaign's phase and
  counters.
- **Deny-by-default, mirrored exactly.** `scan.inject`/`scan.run` are `Sensitive`
  and, for an MCP/agent caller, refuse unless `scanner.allow_agent_active` is set —
  the 1:1 analogue of `poc.allow_agent_run`. Operator/CLI always run. The
  `Sensitive` policy tier and the flag are independent layers.
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

## Constraints

- **Language/gate:** Rust. `cargo fmt --check && cargo clippy --all-targets -- -D
  warnings && cargo test` must pass before any review (each task's "Done when"
  cites it). Default `cargo test` stays hermetic: no real browser, no live
  external network. Browser-dependent tests are `#[cfg_attr(not(AITM_OBSCURA),
  ignore)]`.
- **No core edits (hard).** Extend the shipped `aitm-plugin-scanner` crate and its
  registration. Reach core services only through `CommandHost`
  (`store()`, `client()`, `guard()`, `browser()`, `frontend()`, `config()`,
  `egress_handle()`, `finding_recorder()`). **Verified this session: no
  `CommandHost` accessor is missing** — `egress_handle()` already exists and is
  already used by `scan.discover`, so active confinement needs **no** core change.
  A task that finds it must edit an `aitm-core` type **stops and reports**.
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
  PocInfo, Variable, Severity}`; findings via `aitm_findings::{FindingRecord,
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

### Shipped ground truth this design builds on (read 2026-10-30)

| Shipped API (exact) | Where | How this design uses it |
|---|---|---|
| `ScannerConfig { max_depth, max_pages, request_budget, time_budget, per_class_payload_cap, allow_agent_active }`, `Default` = (3, 200, 2000, 600 s, 25, false) | `config.rs` | Reused as-is; the agent gate reads `allow_agent_active`; `request_budget`/`time_budget`/`per_class_payload_cap` bound inject + run. **No field added.** |
| `ScannerPlugin::new(cfg)`; `Plugin::load(&mut self, reg)` → `reg.add_command(Arc::new(..))` | `plugin.rs` | `load` extended to register the five new commands, each holding a clone of `self.cfg`. |
| `enumerate(&HttpFlow) -> Vec<InjectionPoint>`; `InjectionPoint { flow, location, name, example }`; `Location { Query, BodyParam, Header, Cookie, PathSegment, Redirect }` (redaction built in) | `discover.rs` | The injector enumerates points from store flows exactly as `scan.discover` does; `example` is already redacted. |
| `crawl(host, target, cfg) -> CrawlOutcome { endpoints, pages_crawled, stopped_reason }`; `normalize_url`, `block_on` | `crawl.rs` | `scan.run`'s discover phase calls `crawl`; the sync commands call `block_on`. |
| `CommandHost::{store, client, guard, browser, frontend, config, egress_handle, finding_recorder}` | `ctx.rs` | All service access. `egress_handle()` returns `Option<Arc<EgressConfinement>>`. |
| `EgressConfinement::confine(self: &Arc<Self>) -> ConfinementToken` (RAII, refcounted) | `egress.rs` | Active phase: `let _confine = host.egress_handle().map(|e| e.confine());`. |
| `PipelineClient::send` gates `check_active`, holds permit, records errors, inserts replay flow | `client.rs` | The injector's one network path. |
| `Command` trait: `name`, `schema() -> ParamSchema`, `invoke(args, host) -> Result<Value>`, `sensitivity() -> Sensitivity`, `confirm_prompt(&Params) -> Option<String>`, `mutates`, `summarize` | `command.rs` | New commands implement these; `scan.inject`/`scan.run` override `confirm_prompt`. |
| `poc.allow_agent_run` gate: `if host.frontend() == Frontend::Mcp && !flag { bail!(...) }`; Operator/Cli never gated | `runner.rs` ~1103 | The exact shape `scanner.allow_agent_active` mirrors. |
| `MatchContext::new(status, body).with_header(..)`; `evaluate(&Assertion, &MatchContext) -> bool`; `Assertion::{Status, Word{word,part}, Regex{regex,part}, Dsl, All, Any, Not}`; `MatchPart::{Body, Header, All}` | `aitm-poc matcher/model` | Correlation and passive checks. |
| `StdPocBuilder::build(&HttpFlow, PocSpec{info, variables, success}) -> Poc`; `PocInfo`, `Variable`, `Severity` | `aitm-poc builder/model` | PoC emit on confirm. |
| `FindingRecord { id, title, class, severity, target, discovered_at, origin, client_label, poc_ref, reproduction, artifacts, flows, notes }`; `Reproduction { passed, control_passed, run_at }`; `FindingArtifacts { finding_capture, poc_path, screenshot_path }`; `DiskFindingStore::new(dir)`; `FindingStore::{record, get, list}`; `render_report(&[FindingRecord]) -> String`; `render_index(&[FindingRecord]) -> serde_json::Value` | `aitm-findings` | Record on confirm; read back + render in `scan.report`. |
| Seeded target: `SeedMode::{Vulnerable, Patched}`, `REFLECTED_XSS_MARKER`, routes incl. `/search?q=`, `/redirect?next=`, linked `/` index | `aitm-testtarget` | Inject confirmation pass-on-vulnerable / fail-on-patched. |
| Contract: `EXPECTED_TOOLS: [&str; 56]` incl. `scan.discover`; `COMMAND_NAMESPACES` already has `scan` | `crates/aitm/tests/frontends.rs`, `agent_surface.rs` | Bump to `[&str; 61]` across the five commands. |

### Module layout (new files in the shipped crate)

```
crates/aitm-plugin-scanner/src/
  passive.rs    (new)  PassiveFinding, passive_checks(&HttpFlow) -> Vec<PassiveFinding>
  checks.rs     (new)  Location-keyed CheckDefinition, Payload, Evidence, reflected_xss(), open_redirect()
  inject.rs     (new)  InjectOutcome, Confirmed, inject(host, target, def, points, cfg) -> ...
  reproduce.rs  (new)  build_poc(..), record_finding(..)
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
    pub payload: String, pub evidence: String }
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
off-origin sentinel host compared in `Location`).

`ScanInject { cfg: ScannerConfig }` (`Sensitivity::Sensitive`):

1. **Agent gate (mirrors `poc.allow_agent_run` exactly):** at the top of `invoke`,
   `if host.frontend() == Frontend::Mcp && !self.cfg.allow_agent_active { bail!(
   "scan.inject refused: active injection from an agent frontend is disabled. Set
   scanner.allow_agent_active = true in the aitmproxy config to allow it, or run it
   from the operator/CLI.") }`. `Frontend::Operator`/`Frontend::Cli` are never
   gated. This is the per-command flag layer; the `Sensitive` policy tier is the
   independent upstream layer. **(Architect's call — source of the flag:** the flag
   is read from the plugin-owned `ScannerConfig` (shipped field), not from
   `host.config()`, because the scope design keeps `ScannerConfig` plugin-owned
   with no new `aitm_core::config::Config` field. Behaviour and error shape are
   identical to `poc.allow_agent_run`; only the storage location differs.)
2. **Confinement:** `let _confine = host.egress_handle().map(|e| e.confine());`
   before the active phase; dropped (RAII) when `invoke` returns.
3. Enumerate points from the store flows for `target`, select those matching
   `def.locations` (or the single `injection_point` argument when given), call
   `block_on(inject(..))`, and on each `Confirmed` build + run a PoC and record a
   finding (reproduce.rs).
4. Return `{ class, tested, confirmed: [ {injection_point: {flow, location,
   name}, payload, evidence} ], finding_ids: [id], stopped_reason }`. All strings
   scrubbed.
5. `confirm_prompt` returns `Some("Run active injection (class <class>) against
   <target>? This issues attack traffic to the authorized target.")` so human
   surfaces get the confirm handshake (integration D-MCP3).

### Reproduce → record (reuse)

`reproduce.rs`:

```
pub fn build_poc(flow: &HttpFlow, def: &CheckDefinition, point: &InjectionPoint,
    payload: &Payload) -> anyhow::Result<aitm_poc::Poc>;
pub fn record_finding(host: &CommandHost<'_>, rec: aitm_findings::FindingRecord)
    -> anyhow::Result<String>;
```

`build_poc` assembles `PocSpec { info, variables, success }` with `success` the
class's confirming `Assertion` (same operator `confirm` evaluates) and calls
`StdPocBuilder::default().build(flow, spec)`; the base URL is parameterized to a
`{{target}}` variable and credential headers become required `{{var}}`
placeholders (the builder already does this). `record_finding` persists a
`FindingRecord` whose `reproduction` is built from a vulnerable run (`passed`) and
a patched-control run (`control_passed`), via `DiskFindingStore::new(dir)` from the
configured `findings.dir` (or the shipped `host.finding_recorder()` seam where a
recorder is wired). `FindingStore::record` redacts free-text at the store
boundary; the scanner additionally never puts a param value or raw header into
`title`/`notes`.

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
`scan.inject`) takes a **single** `let _confine = host.egress_handle().map(|e|
e.confine());` for the whole campaign and runs, under one shared `request_budget`
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

**Operator-configurability of the flag** (threading a config-file `[scanner]`
section into `ScannerConfig` at `wire.rs`, today hard-wired `::default()`) is
owned by the **integration** plan's **D-MCP2 / AC9**, which explicitly claims it.
This backend plan provides the plugin gate + its unit tests (which construct
`ScannerPlugin::new(ScannerConfig { allow_agent_active, .. })` directly) and does
**not** edit `wire.rs`/`config_file.rs` for the flag, to avoid duplicate work and
honour "no core edits". See Open question 5.

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
7. **AC7:** An MCP-frontend `scan.inject` is refused when
   `allow_agent_active == false` (error naming `scanner.allow_agent_active`) and
   runs when it is `true`; an `Operator`/`Cli` frontend always runs. [scope AC9]
8. **AC8:** `scan.inject` never issues a request to an out-of-scope host from any
   caller: an unscoped target returns `GuardError::OutOfScope`. [scope AC10]
9. **AC9:** During `scan.inject`'s active phase the attached `EgressConfinement`
   is confined (`confined() == true` observed while injecting) and is released
   (`confined() == false` with an off base) once `invoke` returns; a host with no
   posture wired still runs (literal, probe like the shipped
   `scan_discover_crawls_under_egress_confinement`). [new / S2 parity]
10. **AC10:** On a confirmation the engine builds a PoC via `StdPocBuilder` and
    records a `FindingRecord` with `reproduction.passed == true` and
    `reproduction.control_passed == Some(false)`. [scope AC11]
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
- Whether `scan.report` reads through `DiskFindingStore` or the shipped
  `host.finding_recorder()` seam for recording, provided records round-trip to
  `render_report`/`render_index`.
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
with the flag read from the plugin-owned config. Twenty acceptance criteria map to
the three stages; result shapes match what the integration plan's UI tasks
consume.

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
