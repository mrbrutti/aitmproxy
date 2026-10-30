# Deterministic automated-scanner plugin design

**Status:** draft
**Research inputs:** `docs/research/02-nuclei.md`, `docs/research/05-synthesis.md`,
`docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (§Goals/Non-goals,
the scanner-fitness seam analysis at ~1132-1162), `docs/superpowers/specs/2026-10-27-aitmproxy-poc-language-design.md`
(§Matcher/extractor DSL, the `Assertion`/`ExtractSource` mapping), `docs/superpowers/plans/2026-10-27-aitmproxy-m4-plan.md`
(Task 1 `Sensitivity` + the D2 policy matrix, the agent-driver Task 17, Task 15 report renderers).

## Intent

aitmproxy deliberately deferred a full automated scanner: the platform spec
(lines 48-54, 85-103, 124, 157-162) names it an *explicitly anticipated future
plugin* built on the M1 seams with **new crates only, never a core edit**, and
the fitness analysis (1132-1162) checks each scanner capability against an
existing seam and finds all sufficient as-is. This design is that plugin: a
**deterministic (AI-free) Burp-style active scanner** that crawls an in-scope
target, discovers injection points from the flow, injects payload sets per vuln
class, correlates responses to confirm a vuln, emits a reproducible PoC, records
the finding, and renders a report. It is the AI-free sibling of the M4
agent-driven loop — the same crawl → discover → inject → correlate → reproduce →
record → report shape, but driven by deterministic heuristics + payload sets
instead of an LLM. Its capabilities are **commands first**, registered through
the `Registry` so they auto-expose over MCP and CLI/UI alike, which makes the
deterministic scanner a tool the M4 agent can *task* and *compose into* its own
free-form loop. We want it now because every seam it needs already shipped
(M1-M7): the flow store, the guarded client path, the `aitm-poc` matcher/builder
vocabulary, `aitm-findings`, the browser driver, and the `Sensitivity`/scope/rate
gates.

## Goals

- A new plugin crate `aitm-plugin-scanner` that adds Burp-style active scanning
  **entirely as new crates + a wiring line**, with **no edit to `aitm-core`'s
  `Command`/`Flow`/`Event`/`ProtocolModule`/guard types** (platform anti-goal at
  line 124).
- A **commands-first** surface — `scan.discover`, `scan.passive`, `scan.inject`,
  `scan.report`, `scan.run`, `scan.status` — each a plugin-registered `Command`
  that **auto-exposes over MCP and CLI/UI** and returns **structured results**
  (typed `Value::Object`, not prose) a caller can reason over.
- The scanner is usable **three ways from one command surface**: operator-run
  (CLI/UI), agent-tasked (MCP tool call), and as a **building block the M4
  free-form agent loop calls** to get structured results and fold into its
  reasoning. The *same* `Sensitivity`/scope gate enforces deny-by-default for all
  three callers.
- **Both detection paths coexist (GOAL).** The deterministic scanner *augments*
  the existing M4 model-driven free-form loop; it is tool-callable by the agent
  and composes with that loop.
- **CRAWL** reuses the embedded browser engine (`BrowserDriver`) + the flow store
  to follow links/forms and enumerate reachable in-scope endpoints.
- **DISCOVER** injection points from the flow's request shape (query/body params,
  headers, cookies, path segments/object-ids, redirect targets) — the **same
  candidate enumeration the M4 driver does from `flow.detail`, never from a
  manifest**.
- **INJECT** payload sets per injection-point class through the existing guarded
  client path (`request.send` / `flow.replay`), bounded by caps + the rate guard.
- **CORRELATE** responses to confirm a vuln reusing the `aitm_poc` matcher /
  extractor vocabulary (`Assertion` + `matcher::evaluate`), and on confirmation
  emit a reproducible PoC via `StdPocBuilder`.
- **RECORD** confirmed findings via `aitm-findings` (`FindingStore::record`) and
  render a report via `render_report` / `render_index`.
- **Deny-by-default + scope-bound + resource-bounded** throughout: active
  injection is `Sensitive`, scope-gated, rate-limited, and caps crawl depth/
  breadth, payload counts, total request budget, and per-host error back-off.
- **Stageable**: five independently shippable stages, each with its own gate pass
  and its own acceptance criteria, so Matt can greenlight Stage 1 and stop.

## Non-goals

- **Does not replace, disable, or gate the free-form M4 loop (hard NON-GOAL).**
  The deterministic scanner never becomes a mandatory step in front of the
  agent-driven path. Loading the scanner plugin leaves the M4 loop working
  unchanged; both paths are available side by side.
- Not an AI scanner. No LLM, no model call, no provider SDK anywhere in the
  crate. All discovery/injection/triage is deterministic heuristics + static
  payload sets.
- Does not fix vulnerabilities and writes no remediation prose (platform
  Non-goal); it produces the finding, the PoC, and a structured report only.
- Does not edit `aitm-core`, any `aitm-proto-*` crate, the `aitm-poc` YAML
  language, or the `Flow`/`Event` enums. It is additive: a new crate, a wiring
  line, and (test-only) an extended `aitm-testtarget`.
- Does not add a new rate limiter, a new scope model, or a new SSRF classifier.
  It reuses `StdGuard`/`ScopeRateGuard` and the browser SSRF guards unchanged.
- Does not introduce a new matcher DSL or PoC format. It reuses
  `aitm_poc::Assertion` + the existing PoC build/run path.
- No out-of-band (Interactsh-style) collaborator in this design; blind/OOB
  classes (blind SQLi/SSRF without reflection) are out of scope until a later
  revision adds an OOB sink.

## Anti-goals

- A scanner that touches an out-of-scope host, from **any** caller. If an agent
  (or operator, or the free-form loop) can make the scanner inject outside the
  operator-authorized scope, the design has failed.
- An unbounded scan: an uncapped crawl, an unlimited payload cross-product, or a
  run that ignores the rate guard / per-host back-off is a failure even if it
  finds bugs.
- A scanner that becomes a mandatory gate in front of the free-form agent path,
  or that disables the M4 loop when loaded.
- Any change to `aitm-core` command/flow/event/guard types to host the scanner —
  the platform spec treats that as a design failure (line 124).
- A finding, report, or structured result that leaks a secret (auth header,
  token) that passed through a scanned request.

## Constraints

- **Language/gate:** Rust. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must pass before any review (each task's "Done when" cites it). Default
  `cargo test` stays hermetic: no real browser, no live network. Browser-driven
  crawl/e2e tests are gated on `AITM_OBSCURA=1` (obscura the default engine),
  matching the M4 convention.
- **No core edits (hard):** the crate registers through `Plugin::load` →
  `Registry::add_command` and reaches core services through `CommandHost`
  (`store()`, `client()`, `guard()`, `browser()`, `frontend()`, `config()`). It
  defines its own `ScannerConfig`; the `aitm` binary wiring constructs and passes
  it to `ScannerPlugin::new(...)`, exactly as `ScopePlugin::new(allow_agent_widen)`
  is constructed today — **no new field on `aitm_core::config::Config` is
  required** (Architect's call; see Design).
- **Deny-by-default + scope-bound:** active injection only ever reaches an
  in-scope host; every request goes through the single guarded client chokepoint
  (`ProxyClient::send`, which calls `check_active`). The scanner adds no second
  network path.
- **Resource bounds:** crawl depth/breadth caps, per-class payload cap, a total
  per-campaign request budget, a wall-clock budget, and reuse of the guard's
  per-host error back-off. Concrete defaults are **(Architect's call)** below.
- **Reuse, do not reinvent:** correlation uses `aitm_poc::matcher::evaluate` +
  `extract`; PoC emit uses `aitm_poc::StdPocBuilder` + the existing `poc.run`
  path; findings use `aitm_findings::{FindingStore, render_report, render_index}`;
  crawling uses `aitm_core::BrowserDriver`; gating uses `Sensitivity` + `StdGuard`.
- **External-authoring stability:** treats the public trait surface it builds on
  (`Command`, `Plugin`, `CommandHost`, `ScopeRateGuard`) as stable API.
- **Workflow:** every change travels the seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

### Verified seam inventory (ground truth — read 2026-10-29)

Each API below was read from source this session; names are exact. Two
corrections to the task brief are noted.

| Capability | Reused API (verified) | Where |
|---|---|---|
| Command tier gate | `Command::sensitivity() -> Sensitivity { Read \| Write \| Sensitive }` (fail-closed default `Sensitive`), `mutates()`, `summarize()`, `confirm_prompt()` | `aitm-core/src/command.rs` |
| Register commands | `Plugin::load(&mut self, reg: &mut Registry)` → `reg.add_command(Arc::new(..))` | `aitm-core/src/plugin.rs`, `registry.rs` |
| Caller identity gate | `CommandHost::frontend() -> Frontend { Cli, Mcp, Operator }`, `config()`, `client_label()` | `aitm-core/src/ctx.rs` |
| Agent policy | `AgentPolicy { All, Auto, Ask, ReadOnly, Paused }` (Auto refuses `Sensitive` unless its own gate allows; Operator/Cli bypass) | `aitm-core/src/agent.rs` |
| Scope/rate/back-off | `ScopeRateGuard::{check_active, in_scope, add_scope, record_error}`, `StdGuard`, `classify_host`/`HostClass`, `ssrf_check` | `aitm-core/src/guard.rs` |
| Multi-flow correlation | `FlowStore::{get, query}`, `FlowQuery { host, method, status, kind, is_replay }` | `aitm-core/src/store.rs` |
| Flow inspection shape | `flow.detail` object (request `{method,scheme,authority,path,headers,body}`, response `{status,headers,body}`) | `aitm-plugins/src/detail.rs` |
| Active request path | `request.send` (craft), `flow.replay` (reissue) — both `Write`, both go through `host.client().send(..)` | `aitm-plugins/src/{mutate,replay}.rs` |
| Browser crawl | `BrowserDriver::{navigate, click, type_text, screenshot, eval, get_dom}` via `CommandHost::browser()` | `aitm-core/src/ctx.rs`, `aitm-browser/src/driver.rs` |
| Matchers/extractors | `aitm_poc::Assertion { Status, Word{word,part}, Regex{regex,part}, Dsl, BrowserEval, All, Any, Not }`, `matcher::{MatchContext, evaluate}`, `extract::{Extractor, ExtractorKind, run_extractors, apply}` | `aitm-poc/src/{matcher,extract,model}.rs` |
| PoC emit | `PocBuilder`/`StdPocBuilder::build(&HttpFlow, PocSpec{info, variables, success}) -> Poc`; run via the existing `poc.run` command | `aitm-poc/src/{builder,runner,model}.rs` |
| Findings + report | `FindingStore::record(FindingRecord) -> String`, `DiskFindingStore`, `FindingRecord{ class, severity, target, reproduction: Reproduction{passed, control_passed}, artifacts }`, `render_report(&[FindingRecord]) -> String`, `render_index(&[FindingRecord]) -> serde_json::Value` | `aitm-findings/src/{store,record,report}.rs` |
| Seeded target | `aitm-testtarget` serves planted vulns in `SeedMode::{Vulnerable, Patched}` with inert markers; `/search`(reflected-xss), `/comments`(stored-xss), `/fetch`(ssrf), `/account/{id}`(idor), `/admin`(auth-bypass), `/redirect`(open-redirect) | `aitm-testtarget/src/{app,manifest,seed}.rs` |

**Correction 1 — crate name.** The brief proposed `crates/aitm-scanner`. The
established convention for a *standalone optional feature plugin crate* is
`aitm-plugin-<name>` (`aitm-plugin-maprules`, `-passthrough`, `-rhai`,
`-sessionio`, `-wsctl`); `aitm-plugins` is the bundled first-party set and
`aitm-plugin` is the protocol-author seam re-export. The scanner is exactly a
standalone optional feature plugin, so this design uses **`aitm-plugin-scanner`**
(Architect's call). One crate holds both the engine library and the plugin/command
layer; a split into a reusable `aitm-scan-core` is a later option if a non-plugin
consumer appears.

**Correction 2 — active-injection primitive.** The brief lists
`flow.mutate`+`resume` as an injection primitive. `flow.mutate` edits a *stored or
parked* flow and `resume` releases a *parked live interception*; neither is the
natural path for issuing fresh fuzz requests. The scanner's active path is
`request.send` (craft a mutated request from an injection point) and `flow.replay`
(reissue a captured request), both of which already funnel through the single
guarded `host.client().send(..)` chokepoint. `flow.mutate`+`resume` is not used.

### The scanner as a plugin

`ScannerPlugin` implements `aitm_core::Plugin`. `load()` registers the `scan.*`
commands into the `Registry`; it observes **no events** (discovery reads the flow
store on demand, it does not tap the event chain), which keeps it off the proxy
data path entirely. `ScannerPlugin::new(cfg: ScannerConfig)` takes the caps and
the agent-gate flag; the `aitm` binary constructs `ScannerConfig` from its config
layer and adds `ScannerPlugin` to the plugin chain — the same wiring every plugin
gets, not a core edit.

```
ScannerConfig {                      // owned by aitm-plugin-scanner
    max_depth, max_pages,            // crawl caps
    request_budget, time_budget,     // campaign caps
    per_class_payload_cap,           // payload-set bound
    allow_agent_active: bool,        // the per-command agent gate (off by default)
}
```

### Command surface (commands first; structured results)

Every command returns a typed `Value::Object`; nothing returns prose. The tier is
what enforces deny-by-default uniformly across operator/CLI, MCP agent, and the
free-form loop — **the same gate regardless of caller**.

| Command | Tier | Does | Structured result (shape) |
|---|---|---|---|
| `scan.discover {target, max_depth?, max_pages?}` | **Write** | Crawl the in-scope target via the browser + guarded client; enumerate endpoints + injection points from each flow. | `{ endpoints: [url], injection_points: [{flow, location, name, example}], pages_crawled, stopped_reason }` |
| `scan.passive {target?}` | **Read** | Evaluate passive/safe checks over already-captured flows (reflection, security-header, cookie-flag) reusing matchers; issues **no** new traffic. | `{ findings: [{class, flow, location, evidence, severity}] }` |
| `scan.inject {target, class, injection_point?}` | **Sensitive** | Inject the class's payload set into discovered points via the guarded client; correlate to confirm. | `{ class, tested, confirmed: [{injection_point, payload, evidence}], stopped_reason }` |
| `scan.report {target?}` | **Read** | Render the campaign's findings. | `{ report_md, index }` (reuses `render_report`/`render_index`) |
| `scan.run {target}` | **Sensitive** | Orchestrate discover → passive → inject → report as one bounded campaign. | `{ discover, passive, inject, report, stopped_reason }` |
| `scan.status {run_id?}` | **Read** | Progress/caps of a running or finished campaign. | `{ run_id, phase, pages_crawled, requests_used, budget, confirmed_count }` |

**Correlation is an internal engine step, not a user verb (Architect's call).**
`scan.inject` (and `scan.passive`) correlate internally via
`aitm_poc::matcher::evaluate` and return the confirmation evidence in their
structured result; a standalone `scan.correlate` command would expose an internal
step with no independent caller, so it is omitted.

### Tiering + the deny-by-default gate (the point)

Crawl + passive are a **lower tier** than active injection, exactly as required:

- `scan.passive`, `scan.report`, `scan.status` → **Read** (observation only; run
  even under `AgentPolicy::ReadOnly`).
- `scan.discover` → **Write** (it issues benign in-scope requests through the
  guarded client, like `browser.navigate`/`flow.replay`; runs autonomously under
  `Auto`, always scope/rate-gated).
- `scan.inject`, `scan.run` → **Sensitive** (active attack payloads). This is the
  operator-gated tier.

**Two independent layers gate agent-run active injection**, mirroring
`ca.install` / `scope.add` exactly:

1. **Policy tier.** Under `AgentPolicy::Auto` (the default), a `Sensitive`
   command from an agent is refused by the MCP policy gate before `invoke`. Under
   `Ask` the operator is prompted; under `All` it reaches `invoke`; `ReadOnly`/
   `Paused` refuse. `Frontend::Operator` and `Frontend::Cli` bypass the policy.
2. **Per-command flag.** Inside `invoke`, `scan.inject`/`scan.run` refuse when
   `host.frontend() == Frontend::Mcp && !cfg.allow_agent_active` — the same shape
   as `ScopeAdd` refusing `frontend() != Cli && !allow_agent_widen`. So even under
   `AgentPolicy::All`, an agent cannot run active injection unless the operator
   set `scanner.allow_agent_active`. Operator/CLI always run.

Because the tier + flag live on the command, **all three callers** (operator UI/
CLI, MCP agent task, free-form loop tool-call) are gated identically — that
uniformity is the design's safety point. Scope is enforced a third time at the
network chokepoint: every injected/crawled request passes `check_active`, so an
out-of-scope host is refused with `GuardError::OutOfScope` no matter the caller.

### Crawl

A `Crawler` drives `CommandHost::browser()` to `navigate` the target, reads the
DOM (`get_dom`) to harvest links and forms, and enqueues same-origin in-scope URLs
breadth-first up to `max_depth`/`max_pages`, deduping by normalized URL. Each
navigation's flow lands in the shared `FlowStore` (the browser routes through the
proxy), so discovery reads real captured flows. Out-of-scope / off-origin links
are dropped before fetch (checked against `guard().in_scope(host)`), so the crawl
never leaves scope. When the browser engine is unavailable (hermetic default
test), discovery can also run over flows already in the store, so the enumerator
is unit-testable without a browser.

### Discover (injection points from the flow, never a manifest)

`enumerate(flow: &HttpFlow) -> Vec<InjectionPoint>` parses the **same request
shape `flow.detail` exposes** and yields candidates:

```
InjectionPoint { flow: FlowId, location: Location, name: String, example: String }
Location = Query | BodyParam | Header | Cookie | PathSegment | Redirect
```

- `Query` — each `?k=v` key.
- `BodyParam` — each form/JSON body key.
- `Header`/`Cookie` — each request header / cookie.
- `PathSegment` — each `/seg/` segment, especially numeric object-ids (IDOR).
- `Redirect` — a parameter whose value is a URL (open-redirect/SSRF surface).

This is the M4 driver's rule verbatim: candidates come from the flow, never from
`aitm-testtarget`'s grader-only `manifest()`. A unit test asserts the enumerator
is driven only by a crafted flow and never reads any manifest.

### Inject + correlate

Per vuln class, a static `CheckDefinition`:

```
CheckDefinition {
    class: &str,                       // "reflected-xss", "open-redirect", ...
    locations: &[Location],            // where this class is injectable
    payloads: &[Payload],              // bounded static set (nuclei-style)
    confirm: fn(&InjectionPoint, &Payload, &MatchContext) -> Option<Evidence>,
}
```

`confirm` builds an `aitm_poc::Assertion` (e.g. reflected-XSS → `Word { word:
marker, part: Body }`; open-redirect → a `Regex`/`Dsl` over the `Location`
header) and runs it with `matcher::evaluate` against a `MatchContext` built from
the injected response. Payload combination follows nuclei's vocabulary: the
**default mode is `batteringram`** (one payload value per position per request),
which bounds request count; `pitchfork`/`clusterbomb` are added in Stage 5 for
multi-position classes, still capped by `request_budget`. The injector issues
each request through `request.send`/`flow.replay` (guarded client), honoring the
rate guard and recording per-host errors via `record_error` for back-off.

### Reproduce → record → report

On a confirmed injection the engine:

1. builds a parameterized PoC: `StdPocBuilder::build(&flow, PocSpec { info, variables,
   success })` with `success` the confirming `Assertion`;
2. runs it through the existing `poc.run` path against the vulnerable target and
   against a patched control, capturing `passed` and `control_passed`;
3. records a `FindingRecord` (`class`, `severity`, `target`, `reproduction:
   Reproduction { passed, control_passed }`, `artifacts`) via
   `FindingStore::record` — which already redacts secrets from free-text fields;
4. `scan.report` renders `render_report(&records)` (human markdown) +
   `render_index(&records)` (machine index), unchanged from `aitm-findings`.

### Both-paths composition

The M4 free-form loop (`agent/PLAYBOOK.md`, the scripted driver) is untouched:
loading `ScannerPlugin` only *adds* `scan.*` tools to the `tools/list`. The agent
may ignore them (pure free-form), task them directly (`scan.discover` → reason
over the structured result), or interleave them. The Stage 5 e2e proves both: the
M4 scripted-driver gate still passes with the scanner loaded, **and** a driver
that calls `scan.discover`/`scan.inject` receives structured results and records
the same findings. Nothing makes the scanner a precondition of the free-form path.

### Test target fitness

`aitm-testtarget` already hosts seeded bugs with a `SeedMode::Vulnerable` origin
and a `SeedMode::Patched` control and inert markers — exactly the shape scanner
reproduction needs (pass on vulnerable, fail on patched). It is therefore
suitable, like the M4 Vulnerable target. Two test-only extensions are required
and are the scanner's to make (not core): (a) a **crawlable linked surface** (an
index page linking the seeded endpoints + a form) so `scan.discover` has a graph
to walk — today the endpoints are not inter-linked; (b) if Stage 5 broadens to
classes not yet seeded (SQLi, command injection, LFI, header injection), new
planted-vuln + patched-control variants for them (a Matt decision — see Open
questions). The already-seeded **reflected-XSS** and **open-redirect** classes
carry safe markers and patched controls and are the natural first active classes.

## Acceptance criteria

Each is observable/testable and mapped to a stage so Matt can approve stage by
stage.

**Stage 1 — crawl + discovery (read/Write, no injection)**

1. **AC1:** `scan.discover {target}` crawls the in-scope seeded target through the
   browser + guarded client and returns a structured result whose `endpoints`
   list contains the target's linked seeded endpoints (observable against the
   extended `aitm-testtarget` crawl surface; browser-gated e2e).
2. **AC2:** The enumerator yields the expected `injection_points` (query/body/
   header/cookie/path-segment/redirect) from a crafted `HttpFlow`, driven only by
   the flow and **never reading any `manifest()`** (unit test asserts no manifest
   access; a flow with `?q=1&id=2` + a cookie yields exactly those points).
3. **AC3:** Crawl honors `max_depth`/`max_pages` and only touches in-scope hosts:
   a link to an out-of-scope host is absent from `endpoints` and no request is
   sent to it (observable: guard records no action for that host).
4. **AC4:** `scan.discover` reports `Sensitivity::Write`; every request it issues
   passes `check_active` (an out-of-scope target returns `GuardError::OutOfScope`).

**Stage 2 — passive/safe-check pass (Read)**

5. **AC5:** `scan.passive {target}` evaluates reflection, missing/weak
   security-header, and insecure-cookie-flag checks over captured flows reusing
   `aitm_poc` matchers, returning structured `findings` (observable: against
   seeded flows it flags the reflected `q` param and a missing `Content-Security-Policy`).
6. **AC6:** `scan.passive` reports `Sensitivity::Read`, issues no new network
   traffic (flow count unchanged across the call), and runs under
   `AgentPolicy::ReadOnly`.

**Stage 3 — active injection for 1-2 classes (Sensitive, gated)**

7. **AC7:** `scan.inject {target, class}` injects the class's payload set into
   discovered injection points via the guarded client and returns structured
   per-attempt results (`tested`, `confirmed`).
8. **AC8:** For the seeded class, injection **confirms** on `SeedMode::Vulnerable`
   and **does not confirm** on `SeedMode::Patched`, using `matcher::evaluate` for
   correlation (literal: `confirmed` non-empty on vulnerable, empty on patched).
9. **AC9:** `scan.inject` reports `Sensitivity::Sensitive`; an MCP-agent call is
   refused unless `scanner.allow_agent_active` is set (literal: refusal error
   without the flag, success with it); an operator/CLI call always runs.
10. **AC10:** Active injection never targets an out-of-scope host from any caller
    (literal: `GuardError::OutOfScope`).

**Stage 4 — correlate → PoC → findings/report**

11. **AC11:** On a confirmed vuln the engine builds a parameterized PoC via
    `StdPocBuilder` and runs it, recording a `FindingRecord` with
    `reproduction.passed == true` on vulnerable and `control_passed == Some(false)`
    on the patched control.
12. **AC12:** `scan.report {target}` renders a human report and a machine index
    via `render_report`/`render_index` (literal: one report section per recorded
    finding; index entries carry `poc_path`/`class`/`passed`).
13. **AC13:** A secret (e.g. an `Authorization` header) that passed through a
    scanned request never appears in a `FindingRecord`, the rendered report, or any
    structured `scan.*` result (reuses the redaction posture).

**Stage 5 — broaden coverage + both-paths**

14. **AC14:** Coverage broadens to ≥ 3 vuln classes with `batteringram` +
    `clusterbomb` payload modes, and total requests stay ≤ `request_budget`
    (literal: a run under a small budget stops at the cap).
15. **AC15:** `scan.run {target}` orchestrates discover → passive → inject →
    report as one `Sensitive`, identically-gated campaign and returns a structured
    campaign summary.
16. **AC16:** The scanner commands are invocable by operator (CLI), MCP agent, and
    the free-form loop over one surface, returning structured results; **loading
    the scanner leaves the M4 free-form loop working** (the M4 scripted-driver
    gate still passes with `ScannerPlugin` loaded, and a driver that calls
    `scan.discover`/`scan.inject` records the same findings).
17. **AC17:** Every campaign is bounded — crawl caps, per-class payload cap, total
    request budget, wall-clock budget, per-host back-off — and stops with a
    populated `stopped_reason` when a cap is hit (literal: a tiny budget yields a
    truncated run with `stopped_reason == "budget"`).

## Left to the builder

- Exact internal module layout of `aitm-plugin-scanner` (crawler/enumerator/
  injector/checks modules), struct field order, and private helper signatures.
- The precise DOM link/form harvesting technique (`get_dom` parse vs. `eval` of a
  collector script), provided it only enqueues in-scope same-origin URLs.
- The concrete payload strings per class (seeded from `02-nuclei.md` vocabulary),
  within the per-class cap.
- Where `ScannerConfig` is sourced at the wiring layer (a `[scanner]` section in
  the binary's config), provided it requires **no new `aitm_core` type field**.
- URL normalization/dedupe rules for the crawl frontier.
- The exact `Assertion` each `CheckDefinition::confirm` builds, provided it uses
  the existing `aitm_poc` operators.

## Open questions

Only Matt can decide these; defaults are the Architect's calls, each a one-line
change if overridden.

1. **Which 1-2 vuln classes for Stage 3's first active injection?** Default:
   **reflected-XSS + open-redirect** — both already seeded in `aitm-testtarget`
   with inert markers and patched controls, so Stage 3 needs no new target work.
   Starting instead with SQLi / command-injection / LFI would require adding those
   planted classes + patched controls to the target (extra Stage 3 task).
2. **Is agent-run active scanning ever allowed, or operator-only forever?**
   Default: **allowed behind an off-by-default `scanner.allow_agent_active` flag**
   (mirrors M4's `scope.allow_agent_widen` / `ca.allow_agent_install`); operator/
   CLI always allowed. Alternative: operator-only forever (drop the flag, always
   refuse from `Frontend::Mcp`).
3. **Default resource caps acceptable?** Architect's-call defaults: crawl
   `max_depth = 3`, `max_pages = 200`; `request_budget = 2000` active requests/
   campaign; `per_class_payload_cap = 25`; `time_budget = 10 min`; rate/
   concurrency/back-off inherited from `LimitConfig` (global 150 rps, per-host 50
   rps, concurrency 25, host error budget 10). Confirm or adjust.
4. **Crate name `aitm-plugin-scanner`** (correcting the brief's `aitm-scanner`) —
   confirm the `aitm-plugin-*` convention is the one to follow.
5. **Stage 5 breadth:** broaden only to already-seedable classes (reflected/
   stored XSS, open-redirect, SSRF, IDOR, auth-bypass — all planted today), or
   also to SQLi / command-injection / LFI / header-injection, which require new
   seeded target variants? Default: stay within the already-seeded classes in
   Stage 5; defer new-target classes to a follow-up.

## Summary

This specs a deterministic, AI-free Burp-style active scanner shipped as a new
`aitm-plugin-scanner` crate on aitmproxy's existing seams with **no core edits**:
it crawls an in-scope target through the browser, enumerates injection points from
the flow (never a manifest), injects bounded payload sets through the single
guarded client path, correlates with the `aitm_poc` matcher vocabulary to confirm,
emits a reproducible PoC via `StdPocBuilder`, records findings in `aitm-findings`,
and renders a report with `render_report`/`render_index`. Its capabilities are
**commands first** (`scan.discover`/`passive`/`inject`/`report`/`run`/`status`),
so they auto-expose over MCP + CLI/UI and are usable three ways — operator-run,
agent-tasked, and as a building block the M4 free-form loop composes — with the
**same `Sensitivity`/scope gate enforcing deny-by-default for every caller**:
crawl/passive are Read/Write, active injection is `Sensitive` and operator-gated,
and agent-run active injection sits behind an off-by-default
`scanner.allow_agent_active` flag plus the `Auto` policy tier. The scanner
*augments* the free-form M4 path and never replaces or gates it. Work is cut into
five independently shippable stages (17 ACs) so Stage 1 can be greenlit alone.

### Architect's calls made (for Matt to approve or correct)

1. Crate name **`aitm-plugin-scanner`** (not `aitm-scanner`), matching the
   `aitm-plugin-*` standalone-plugin convention.
2. **Commands-first surface** of six verbs; **correlation kept internal** (no
   `scan.correlate` verb) and returned as structured evidence.
3. **Tiering:** `scan.passive`/`report`/`status` = Read; `scan.discover` = Write;
   `scan.inject`/`scan.run` = Sensitive.
4. **Two-layer agent gate** for active injection: the `Sensitive` policy tier +
   an off-by-default `scanner.allow_agent_active` per-command flag, mirroring
   `ca.install`/`scope.add`.
5. **`ScannerConfig` owned by the plugin**, passed via `ScannerPlugin::new`, so no
   `aitm_core::config::Config` field is added.
6. **Active path = `request.send` / `flow.replay`**, not `flow.mutate`+`resume`
   (correcting the brief).
7. **Default caps** (depth 3, 200 pages, 2000-request budget, 25 payloads/class,
   10-min budget) and **first active classes reflected-XSS + open-redirect**.
8. **Five stages, 20 tasks**, with the test target extended (crawl surface) rather
   than any core edit.
9. **`batteringram` default payload mode** in Stage 3; `clusterbomb`/`pitchfork`
   deferred to Stage 5 under the request budget.
