# Deterministic scanner backend, Stages 2-5 design

**Status:** Draft — awaiting Matt's approval
**Research inputs:** `docs/superpowers/specs/2026-10-29-aitmproxy-scanner-plugin-design.md`
(the original five-stage scanner design; Stage 1 — `scan.discover` — is merged,
PR #67); `docs/superpowers/plans/2026-10-29-aitmproxy-scanner-plugin-plan.md`
(the original Task 1-20 breakdown, superseded for Stages 2-5 by this spec);
`docs/superpowers/specs/2026-10-29-aitmproxy-scanner-integration-design.md` +
its plan (the UI integration layer, whose Stages 2-4 consume this spec's
commands — read closely, its assumptions are load-bearing here);
`docs/superpowers/specs/2026-10-29-aitmproxy-browser-egress-confinement-design.md`
(merged — `EgressConfinement`/`ConfinementToken`, `browser.confine`); source
read 2026-10-30: `crates/aitm-plugin-scanner/src/{commands,crawl,discover,
config,plugin}.rs`, `crates/aitm-core/src/{command,ctx,egress,guard,agent,
client,config,error}.rs`, `crates/aitm-findings/src/{record,report,store,
recorder,commands}.rs`, `crates/aitm-poc/src/{matcher,builder,runner,model}.rs`,
`crates/aitm-plugins/src/scope.rs`, `crates/aitm-mcp/src/server.rs`,
`crates/aitm/src/wire.rs`, `crates/aitm/tests/frontends.rs`,
`crates/aitm-testtarget/src/app.rs`.

## Intent

Stage 1 shipped `scan.discover`: crawl + injection-point discovery, read/Write,
no injection. This spec covers everything after it — `scan.passive`,
`scan.report`, `scan.inject`, `scan.run`, `scan.status` — so the deterministic
scanner becomes a full crawl → discover → passive-check → inject → correlate →
reproduce → record → report loop, usable by an operator, an MCP agent, or the
M4 free-form loop, over the same command surface and the same deny-by-default
gate every other capability uses. The UI integration spec and plan were written
*against the assumption* that these commands exist with particular shapes
(`scan.report`'s index feeding the Findings pane, `scan.inject`'s
`confirm_prompt` and `scanner.allow_agent_active` gate, `scan.run`/`scan.status`
as a pollable campaign); this spec is written to satisfy that contract so the
four remaining integration stages can proceed without rework, while correcting
three points where the original Stage 2-5 plan's wording does not survive
contact with the code that actually shipped (noted inline as *Corrections*,
mirroring how the Stage-1 spec corrected its own brief).

Since Stage 1, two things changed the ground this spec stands on and are
assumed throughout: (1) `EgressConfinement`/`browser.confine` merged into
`aitm-core`, and `scan.discover`'s crawl already takes a confinement hold
(`host.egress_handle().map(|e| e.confine())`, `commands.rs:126`) for the
browser-driven S2 fix; (2) `scan.discover`'s result already redacts every
secret-bearing value via `aitm_core::redact::scrub_text` and
`discover::enumerate`'s per-point redaction — every command in this spec
reuses that posture rather than re-deriving it, and Integration Stage 1
(the `scan.discover` UI) is live in web/TUI/macOS (PRs #79-82).

## Goals

- `scan.passive {target?}` (Read) and `scan.report {target?}` (Read) ship,
  giving the UI integration's Stage 2 a real findings source.
- `scan.inject {target, class, injection_point?}` (Sensitive) ships with its
  `confirm_prompt`, the `scanner.allow_agent_active` config gate threaded end
  to end (config → `wire.rs` → the MCP policy gate's allow-list → the
  command's own check), and a correlate → reproduce → record pipeline that
  persists a human-readable `FindingRecord` on confirmation.
- `scan.run {target, classes?}` (Sensitive) and `scan.status {run_id?}` (Read)
  ship: one bounded, gated campaign command and a pollable progress read,
  satisfying the UI integration's Stage 4.
- Every active-injection request stays inside scope: `scan.inject`/`scan.run`
  never touch a host outside the operator's authorized scope, under any
  caller, exactly as `scan.discover` doesn't.
- Coverage broadens (Stage 5) to the vuln classes `aitm-testtarget` already
  seeds, plus `pitchfork`/`clusterbomb` payload modes, still capped by
  `request_budget`/`per_class_payload_cap`.
- The four backend stages map 1:1 onto the integration plan's four stages, so
  each backend stage, once merged, unlocks exactly one integration stage.

## Non-goals

- Re-litigating `scan.discover`/Stage 1. It is merged and unchanged by this
  spec except where a shared helper is factored out for reuse (noted in
  Design) — its behavior and ACs stand.
- An AI/LLM-driven scanner. Every check and payload set here is a static,
  reviewed, deterministic rule — same posture as Stage 1.
- A new findings model, a new matcher DSL, a new PoC format, a new scope
  model, or a new rate limiter. Stages 2-5 are additive consumers of
  `aitm-findings`, `aitm-poc`, `ScopeRateGuard`, and `CommandHost` exactly as
  they exist today.
- An out-of-band (Interactsh-style) collaborator for blind SQLi/SSRF. Deferred,
  as in the original plugin spec.
- A SQLi / command-injection / LFI class in Stage 5. `aitm-testtarget` does not
  seed them; adding them is new target work, a follow-up (Open questions).
- Any edit to `aitm-core`'s `Command`/`Flow`/`Event` enums, or the `aitm-poc`
  matcher/builder vocabulary. The one core-adjacent change this spec does
  require — a `Config` field and an MCP policy-gate allow-list entry — is a
  plain-data/list addition, the same category as `scope.allow_agent_widen` and
  the `EXPECTED_TOOLS`/`CORE_TOOLS` hygiene lists, not a type change.

## Anti-goals

- A scanner verb that touches an out-of-scope host, from any caller —
  `scan.inject`/`scan.run` included. Every crafted request goes through
  `host.client().send()` (`PipelineClient::send`, `client.rs:49`), which calls
  `guard.check_active(&req.authority)` before dialing; there is no second
  network path.
- An unbounded injection run: an unlimited payload cross-product, a run that
  ignores `request_budget`/`per_class_payload_cap`/`time_budget`, or one that
  ignores the guard's per-host error back-off.
- A finding, report, or any structured `scan.*` result that leaks a secret
  (an `Authorization` header, a cookie value, a token in a URL) that passed
  through a scanned request. Every string surfaced is run through
  `scrub_text`/the `discover` redaction posture, matching Stage 1.
- `scanner.allow_agent_active=true` silently doing nothing because the MCP
  policy gate was never told `scan.inject`/`scan.run` have their own
  per-command gate (see *Correction 2*) — a real failure mode this spec
  closes explicitly, not an edge case to leave for Matt to discover later.
- A scanner that becomes a precondition of, or disables, the M4 free-form
  loop. Loading the broader command set only adds tools to `tools/list`.
- `scan.run` silently running two overlapping campaigns against the same
  guard, each thinking it owns the whole `request_budget`.

## Constraints

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test`, hermetic by default. Browser-driven tests (anything exercising
  `scan.discover`'s crawl, directly or via `scan.run`) stay
  `#[cfg_attr(not(AITM_OBSCURA), ignore)]`, matching Stage 1.
  `scan.passive`/`scan.inject`/`scan.report`/`scan.status` need no browser —
  they operate on already-captured flows and a guarded `ProxyClient` — so
  their tests are fully hermetic, including their own confirm/deny e2e cases
  (a stub client and seeded flows suffice; no obscura gate needed for them).
- **No core type edits.** The one `aitm-core` change is a new `Config` field
  (a plain data struct, mirroring `ScopeConfig`/`PocConfig`), not a
  `Command`/`Flow`/`Event`/guard-trait change. A task that finds it needs more
  stops and reports.
- **Per-command surface checklist**, extended from the integration plan's
  Review log: every new `scan.*` command bumps `crates/aitm/tests/
  frontends.rs` `EXPECTED_TOOLS`, `crates/aitm-tui/src/lib.rs` `CORE_TOOLS`,
  and `apps/mac/Sources/AitmproxyKit/Fixtures+Tools.swift`; every new
  `Sensitive` command that carries a per-command agent-gate flag additionally
  bumps `defers_to_command_gate` in `crates/aitm-mcp/src/server.rs:1900`
  (*Correction 2* — the integration plan's Task 8 does not mention this, and
  without it the flag is unreachable under `AgentPolicy::All`; see Design).
- **Reuse, do not reinvent:** correlation via `aitm_poc::matcher::evaluate`;
  PoC build + run via `aitm_poc::{StdPocBuilder, StdPocRunner}` (*Correction
  1* on exactly which of these to call — see Design); findings via
  `aitm_findings::{FindingRecord, FindingStore, DiskFindingStore,
  render_report, render_index}`; the active chokepoint is `host.client().
  send()`, never a second HTTP path; the discover phase reuses Stage 1's
  `crawl`/`enumerate` verbatim.
- **Human-friendly artifacts.** Every PoC the scanner's reproduction step
  writes is a plain `StdPocBuilder`-built, `serde_yaml`-rendered `Poc` —
  identical in shape to an operator-built or agent-built PoC, not a
  scanner-only serialization. No Rhai is introduced by this spec (per the
  original plugin design's non-goals); whether the scanner's own payload
  *sets* should likewise be human-editable YAML (rather than Rust literals)
  is an open question (Open questions).
- **Workflow:** all seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

### Correction 1 — the reproduction step calls `StdPocRunner::run`, not the `poc.run` *command*

`CommandHost` carries no reference to the `Registry` (`ctx.rs:132`), so a
command's `invoke` cannot call another registered command by name — there is
no "invoke `poc.run`" primitive. What Stage 1's own precedent already
establishes (`crawl`/`enumerate` are plain library functions `scan.discover`
calls directly, not commands it invokes) is also the path for reproduction:
the scanner builds a `Poc` with `aitm_poc::StdPocBuilder::build(&flow,
PocSpec{info, variables, success})` and runs it with
`aitm_poc::runner::StdPocRunner::with_output_dir(cfg.poc.out_dir)
.run(&poc, bindings, host)` — the exact engine `PocRunCommand`/`poc.run`
itself calls (`runner.rs:1014`→`run_poc_command`→`StdPocRunner`). This issues
one more guarded, captured HTTP request (the canonical reproduction), writes
the YAML PoC artifact and (if any) a screenshot, and returns a
`PocRunResult{passed, finding_capture, poc_path, screenshot_path, evaluated,
recorded_id}`.

One wrinkle this creates: `StdPocRunner::run_inner` *already* auto-records a
`FindingRecord` through `host.finding_recorder()`/`FindingDraft`
(`runner.rs:470-510`) when a recorder and `findings.dir` are wired — but
`FindingDraft` has no `control_passed` field and no room for the scanner's own
`class`/severity vocabulary, so a second, richer record is also needed (see
next). To avoid writing two records for one confirmation, the `CommandHost`
the scanner hands to `StdPocRunner::run` is a narrower one built from the same
borrowed services (`CommandHost::new(host.store(), host.client(),
host.guard(), host.browser())` plus `.with_frontend(..)`/`.with_config(..)`)
**without** `.with_finding_recorder(..)` attached — `StdPocRunner`'s own
auto-record path is then inert (no recorder ⇒ `recorded_id: None`), and the
scanner performs its own, single, richer record (next section). Left to the
builder: the exact helper that builds this narrowed host.

### Correction 2 — the MCP policy gate needs `scan.inject`/`scan.run` on its allow-list, or the flag is unreachable

`scope.add`'s two-layer gate (per-command `allow_agent_widen` flag *and* the
MCP policy gate) only works because `scope.add` is named in
`defers_to_command_gate` (`crates/aitm-mcp/src/server.rs:1900`). Read the
decision table at `server.rs:1553`: under `AgentPolicy::All`, a `Sensitive`
command is allowed to reach `invoke` **only if** `defers_to_command_gate(name)`
is true; everything else is refused outright by policy before the command's
own check ever runs. Under the default `AgentPolicy::Auto`, every `Sensitive`
command is refused for the agent regardless of any per-command flag — by
design, matching `scope.add` exactly (an operator must raise the policy to
`All` or `Ask` *and* flip the per-command flag; either alone is insufficient).
So Stage 3 must add `"scan.inject"` and Stage 4 must add `"scan.run"` to
`defers_to_command_gate`'s match arms — without this, `scanner.
allow_agent_active=true` has no observable effect under any policy, which is
exactly the kind of silent-no-op the Anti-goals call out. This is not
mentioned in the integration plan's Task 8 (which only adds the `Config`
field); it belongs in this backend spec's Stage 3/4 acceptance criteria
instead.

### Correction 3 — `control_passed` is a test-suite comparison, not a production field

The original plugin spec's AC11 describes a confirmed finding recording
`reproduction.passed == true` and `control_passed == Some(false)` "on the
patched control," as if diffing against a patched variant were something
`scan.inject` does at runtime. It is not, generally: a real pentest target
(DVWA, a client's staging site) has no "patched control" the scanner can
locate and compare against. `poc.run`'s own existing `DiskFindingRecorder`
already reflects this reality — it hardcodes `control_passed: None`
(`recorder.rs:42`) because a single `poc.run` only ever runs once, against one
target. This spec keeps that posture: **a production `scan.inject`/`scan.run`
confirmation always records `control_passed: None`.** The
vulnerable-vs-patched comparison that proves the *scanner's own detection
logic* is sound (confirms on `Vulnerable`, not on `Patched`) is a property
Stage 3/5's e2e tests assert directly on `scan.inject`'s own `confirmed` list
across two separate calls (one per `SeedMode`) — it never needs to reach the
persisted record. This is a correction, not an open question: it is how
`poc.run` already behaves, and diverging from it for the scanner alone would
be an inconsistency with no realistic runtime benefit.

### `scan.passive {target?}` — Read, ephemeral, no persistence

Evaluates three deterministic checks over flows **already captured** in
`host.store()` (no `host.client()` call, no browser): for each flow matching
`target` (same-origin match as `scan.discover`'s crawl; omitted `target`
scans every captured flow up to a cap),

- **reflection** — run `discover::enumerate(flow)` to get candidate points,
  and for each point whose `example` is **not** redacted, build
  `aitm_poc::MatchContext::new(status, body)` and evaluate
  `Assertion::Word{word: example, part: Body}`; a match is a `reflection`
  finding naming the point's location/name (severity: `Medium` — an unconfirmed
  signal, not a proven XSS).
- **security-header** — flag each of `Content-Security-Policy`,
  `X-Content-Type-Options`, and (HTTPS responses only) `Strict-Transport-
  Security` missing from the response (severity: `Low`).
- **cookie-flag** — for each `Set-Cookie` response header, flag a missing
  `Secure` and/or `HttpOnly` flag by name only, never the cookie's value
  (severity: `Low`).

Every finding carries the flow id it was found in (linkable, matching the
`scan.discover` AC3 precedent — no separate `endpoint_flows` map is needed
since the flow id rides on the finding directly). Result:
`{ findings: [{class, flow, location, name, evidence, severity}],
flows_scanned, truncated }`. `scan.passive` **persists nothing** — see "Does
`scan.report` include passive observations?" below and Open questions; two
identical calls return identical output, and no call changes `findings.list`/
`scan.report`'s content. This keeps `Sensitivity::Read`'s contract
("observation only; changes no state," `command.rs:49`) literally true and
lets `scan.passive` run under `AgentPolicy::ReadOnly` without qualification.

### `scan.report {target?}` — Read, a thin render over the persisted store

`scan.report` is **exactly** `findings.list`+`findings.get`, filtered to
`target` and pre-rendered: it reads `host.config().and_then(|c| c.findings.
dir.clone())` (the same `store_for` helper `findings.*` uses,
`aitm-findings/src/commands.rs:105`) into a `DiskFindingStore`, lists+loads the
matching `FindingRecord`s, and calls `aitm_findings::render_report(&records)`
/ `render_index(&records)` unchanged. Result: `{ report_md, index, count }`.
With no `findings.dir` configured it returns an empty report (mirrors
`findings.list`'s posture — no error). It introduces no new storage and no new
rendering; it is a convenience command so a UI/agent doesn't have to compose
`findings.list` + `findings.get` + the two renderers itself.

**Does `scan.report` include `scan.passive`'s observations?** No, by this
design: `scan.report` renders only what `scan.inject`/`scan.run` have
*confirmed and persisted*. `scan.passive`'s reflection/header/cookie
observations are not proven vulnerabilities (no PoC, no reproduction run) and
are surfaced only in `scan.passive`'s own result, which the Scan view renders
in its own region — the same way `scan.discover`'s `endpoints`/
`injection_points` are *not* folded into the Findings pane either. This is a
real, consequential call (it means the integration plan's Stage 2 UI tasks,
which read `scan.report`'s index for the Findings pane, will show *zero* rows
until Stage 3 (`scan.inject`) has confirmed something — `scan.passive`'s own
findings never reach that pane). I believe this is correct (observations and
reproduced findings are different trust levels and the existing findings
module's own doctrine is "recording is a separate, explicit, gated act" —
`aitm-findings/src/lib.rs:10`), but it is flagged in Open questions because
the integration spec's Stage 2 wording ("scanner findings... fold into...")
reads as if it expected more than confirmed-only content.

### `scan.inject {target, class, injection_point?}` — Sensitive, the gated active verb

**Params:** `target: Str` (required, parsed/guarded exactly as `scan.
discover`'s seed — absolute `http(s)`, no userinfo, host checked against
scope before anything else); `class: Str` (one of the registered
`CheckDefinition`s; an unknown class errors naming the registered set);
`injection_point: {location: Str, name: Str}?` (optional — narrows to points
matching this location+name across `target`'s captured flows; omitted runs
every applicable point for the class); `max_requests: Int?` (may only *lower*
`per_class_payload_cap`/`request_budget` for this call, never raise them —
the `max_depth`/`max_pages` clamp-down pattern from `scan.discover`,
`commands.rs:99-108`).

**It does not crawl.** Candidate points come from `discover::enumerate` over
flows **already captured** for `target` (the same no-browser fallback
`crawl.rs`'s `stored_endpoints` uses) — not a fresh crawl. An operator/agent
runs `scan.discover` (or just browses) first to populate the store; `scan.run`
is the one-shot command that chains discover → inject for someone who wants
that in one call. This keeps `scan.inject`'s own cost bounded to injection
requests only and avoids quietly re-crawling inside what is supposed to be the
narrow, reviewable active-injection verb.

**Engine**, per applicable `(injection_point, payload)` pair, in the class's
`AttackMode` order (`BatteringRam` for Stage 3; `Pitchfork`/`ClusterBomb` land
in Stage 5):

1. Craft a mutated `HttpRequest` from the point's source flow (same method/
   headers/body, the point's value replaced by the payload).
2. `host.client().send(req)` — the single guarded chokepoint
   (`PipelineClient::send`): `check_active(&req.authority)` first (an
   out-of-scope target refuses with `GuardError::OutOfScope` before any
   payload reaches the wire), a 5xx or transport error counts against the
   host's error budget, and the resulting flow is captured (`is_replay:
   true`).
3. Build `aitm_poc::MatchContext` from the response and call
   `CheckDefinition::confirm` (an `Assertion` judged with `matcher::
   evaluate` — `Word{word: marker, part: Body}` for reflected-XSS, a
   `Regex`/`Dsl` over the `Location` header for open-redirect).
4. Stop at `request_budget`/`time_budget` (`stopped_reason = Some("budget")`
   / `"time_budget"`), same vocabulary as `scan.discover`.

**On each confirmation** (bounded — at most one reproduction run per distinct
confirmed `(class, injection_point)`, not per payload, so a class that
confirms on every payload variant doesn't spend the budget twice): build +
run the PoC per *Correction 1*, then persist one `aitm_findings::
FindingRecord` directly via `aitm_findings::{FindingStore, DiskFindingStore}`
— **not** through `CommandHost::finding_recorder()` — gated on `host.
config().and_then(|c| c.findings.dir.clone())` being configured (`None` ⇒ no
persistence, `confirmed[i].finding_id: null`, exactly `findings.record`'s
deny-by-default posture). The record carries `class` = the `CheckDefinition`'s
class, `severity` = its configured `aitm_poc::Severity`, `target`, `origin =
host.frontend()`, `poc_ref`/`artifacts` from the `PocRunResult`, and
`reproduction = Reproduction{passed: true, control_passed: None, run_at}`
(*Correction 3*).

**Egress confinement does not apply here.** `scan.inject` drives no browser —
every request goes through `host.client()`, already gated by `check_active`
— and the egress-confinement spec's own non-goal is explicit that confining
the active-reissue path would double-gate it
(`aitm-proto-http/src/sender.rs:163`, `confine_to_scope = false` there by
design). "Active injection stays inside scope" is satisfied by `check_active`
alone; `EgressConfinement` is a browser-egress-only concept and only matters
to `scan.run`'s *discover* phase.

**Result:** `{ class, tested, confirmed: [{injection_point, payload,
evidence, poc_path, screenshot_path, finding_id}], stopped_reason }` — every
string scrubbed, matching Stage 1.

**Gating (two layers, identical shape to `scope.add`):**

1. `Sensitivity::Sensitive`. The MCP policy gate: refused for an agent under
   the default `AgentPolicy::Auto` regardless of the flag; under `All`,
   reaches `invoke` only once `"scan.inject"` is added to
   `defers_to_command_gate` (*Correction 2*); under `Ask`, parked for
   operator approval. `Frontend::Operator`/`Frontend::Cli` always run.
2. Inside `invoke`: refuse when `host.frontend() == Frontend::Mcp &&
   !cfg.allow_agent_active` — `cfg.allow_agent_active` sourced from the new
   `Config.scanner.allow_agent_active` field (default `false`), threaded at
   `wire.rs` exactly as `cfg.scope.allow_agent_widen` feeds `ScopePlugin::
   new`.

`confirm_prompt` returns `Some(..)` summarizing the target, class, candidate
point count, and request budget being authorized — `None` only when the
target itself would already be refused (out of scope), matching the L4 inject
command's own precedent (`aitm-proto-l4/src/commands/inject.rs:74`).

### `scan.run {target, classes?}` — Sensitive, the one-shot campaign

Orchestrates **discover → passive → inject (for each class) → persisted
findings**, under one shared, monotonically-shrinking budget: each phase
receives the *remaining* `request_budget`/`max_pages`/`time_budget`, clamped
down from what the prior phase left, never raised — the discover and inject
phases are literally the same internal functions `scan.discover`/`scan.inject`
call (factored into `pub(crate) fn run_discover(..)`/`run_inject(..)` both
the single commands and `scan.run` call, so there is exactly one
implementation of each phase, not two). `scan.run`'s discover phase takes an
`EgressConfinement` hold for its duration, exactly as `scan.discover` already
does; its inject phase takes none (see above).

**Params:** `target: Str`, `classes: [Str]?` (default: every registered
class), plus the same clamp-down caps `scan.discover`/`scan.inject` accept.
**Result:** `{ run_id, discover: {..scan.discover shape..}, passive:
{..scan.passive shape..}, inject: {per-class scan.inject shapes}, report:
{report_md, index}, stopped_reason }`.

**Execution model (my call, flagged — see Open questions): synchronous.**
`scan.run`'s `invoke` runs the whole campaign and returns only once it ends
(bounded by `time_budget`, default 10 minutes) — the same blocking shape
`scan.discover`'s crawl already has, and every command already runs on its
own `spawn_blocking` thread (`crawl.rs`'s `block_on` doc, confirmed against
the binary's dispatch), so one long-running `scan.run` on one connection does
not block any other connection's commands, `scan.status` included. A shared,
plugin-owned `Mutex<Option<CampaignStatus>>` (constructed once in
`ScannerPlugin::new`, cloned into both `ScanRun` and `ScanStatus`) is
updated as `scan.run` advances through phases; `scan.status` reads it. **At
most one campaign runs at a time**: a second `scan.run` while one is in
flight is refused, naming the in-flight run — this resolves the chicken-and-
egg problem of a UI needing a `run_id` to poll before the (blocking) `scan.run`
call has returned anything (`scan.status {}` with no `run_id` always reports
the current-or-last campaign; `run_id` is an optional assertion, not a
required key) and prevents two overlapping campaigns from each assuming they
own the whole `request_budget`.

### `scan.status {run_id?}` — Read

Returns `{ run_id, target, phase: "discover"|"passive"|"inject:<class>"|
"report"|"done"|"error", pages_crawled, requests_used, request_budget,
confirmed_count, started_at, stopped_reason }` from the shared
`CampaignStatus`, or an empty/`null` shape when no campaign has run yet.
`run_id`, if given, only matches the current/last campaign (there is only
ever one) — a stale id returns `null`, not an error. `Sensitivity::Read`, runs
under `AgentPolicy::ReadOnly`.

### Why not fold "fuzz"/"correlate" into their own verbs

Affirming the original plugin design's call, now that Stages 2-4 are concrete:
correlation is an internal step of `scan.passive`'s reflection check and
`scan.inject`'s confirm step — it has no independent caller-visible use, and
the integration plan never names a `scan.correlate` consumer. "Fuzz" likewise
is not a distinct capability: payload breadth (`BatteringRam`/`Pitchfork`/
`ClusterBomb`) is a *mode* of `scan.inject`/`scan.run`, selected by the
registered `CheckDefinition`, not a user-facing verb — a bare `scan.fuzz`
would be `scan.inject` with no confirm step and no safety framing, which
would just be an unbounded-probe footgun with a different name.

### `CheckDefinition` and payload sets (Stage 3 + Stage 5)

```rust
pub struct Payload { pub value: String, pub marker: Option<String> }
pub struct Evidence { pub payload: String, pub matched: String }
pub struct CheckDefinition {
    pub class: &'static str,          // "reflected-xss", "open-redirect", ...
    pub severity: aitm_poc::Severity, // persisted-finding severity for this class
    pub locations: &'static [Location],
    pub payloads: Vec<Payload>,        // bounded by per_class_payload_cap
    pub mode: AttackMode,              // BatteringRam | Pitchfork | ClusterBomb
}
impl CheckDefinition {
    pub fn confirm(&self, ctx: &aitm_poc::MatchContext, payload: &Payload) -> Option<Evidence>;
}
```

**Stage 3 classes (my call):** `reflected-xss` and `open-redirect` — the two
`aitm-testtarget` already seeds with the simplest, most deterministic confirm
logic (body-word match; `Location`-header match), needing zero new target
work, matching the original plugin spec's choice. **Stage 5 classes:** the
remaining four `aitm-testtarget` already seeds — `stored-xss` (`/comments`),
`ssrf` (`/fetch?url=`), `idor` (`/account/{id}`), `auth-bypass` (`/admin`) —
bringing the registered set to six, plus `Pitchfork`/`ClusterBomb` modes for
the multi-position classes. Net-new classes needing new seeded-target work
(SQLi, command-injection, LFI — informed by the DVWA capstone's broader
12/13-class assessment) are **not** in Stage 5; they are a flagged follow-up
(Open questions) since they require `aitm-testtarget` changes this spec's
constraints don't authorize on their own.

**Payload sets: Rust literals (my call for v1), YAML as a flagged
alternative.** The original plugin spec's non-goal — "deterministic heuristics
+ static payload sets," reviewed, no runtime authoring — argues for `&'static
[Payload]` literals per class, which is what this spec specifies. The
project's standing rule that PoC/scripting stay human-friendly and
operator-editable (not agent-only) argues the other way: a nuclei-style
`payloads/<class>.yaml` an operator can extend without a rebuild fits that
ethos better and matches the research precedent (`02-nuclei.md`). This spec
defaults to the smaller-scope literal version and flags the YAML variant as
an optional fast-follow (Open questions) rather than committing Stage 3/5 to
building a loader+schema that isn't otherwise required.

### `Config` field (Stage 3)

```rust
// aitm-core/src/config.rs — mirrors ScopeConfig/PocConfig exactly.
#[derive(Debug, Clone, Default)]
pub struct ScannerGateConfig {
    /// Let an agent frontend (MCP) run scan.inject/scan.run. Off by default.
    pub allow_agent_active: bool,
}
// on Config: pub scanner: ScannerGateConfig,
```

`wire.rs` builds `aitm_plugin_scanner::ScannerConfig{ allow_agent_active:
cfg.scanner.allow_agent_active, ..Default::default() }` instead of
`::default()`. The type name `ScannerGateConfig` (left to the builder to
rename) is deliberately distinct from the plugin crate's own
`aitm_plugin_scanner::ScannerConfig` (budgets + the same flag) — same field
path (`cfg.scanner.allow_agent_active`) the integration plan's Task 8 already
names, different Rust type to avoid two identically-named structs across the
core/plugin boundary.

## Staging (backend Stages 2-5 → integration Stages 2-4)

| Backend stage | Ships | Unlocks |
|---|---|---|
| **Stage 2** | `scan.passive`, `scan.report` | Integration Stage 2 (findings fold) |
| **Stage 3** | `scan.inject` (+ `confirm_prompt`, the `Config` field, the `defers_to_command_gate` entry) | Integration Stage 3 (active-injection UX + gating) |
| **Stage 4** | `scan.run`, `scan.status` (+ `scan.run`'s own gate/`defers_to_command_gate` entry) | Integration Stage 4 (campaign + progress + export) |
| **Stage 5** | Broadened class coverage + `Pitchfork`/`ClusterBomb` | No new integration stage — deepens Stages 3/4's engine under the same command surface |

## Acceptance criteria

Numbered independently of the Stage-1 spec (scoped to backend Stages 2-5
only).

**Stage 2 — `scan.passive` + `scan.report` (Read)**

1. **AC1:** `scan.passive {target}` flags reflection (a non-secret request
   value echoed verbatim in the response body), a missing security header,
   and an insecure cookie flag over already-captured flows, returning
   `{findings: [{class, flow, location, name, evidence, severity}]}`
   (literal: a seeded reflecting flow + a response with no CSP header yields
   a `reflection` and a `security-header` finding).
2. **AC2:** `scan.passive` is `Sensitivity::Read`, issues no new traffic
   (`host.store().list().len()` unchanged across the call), persists nothing
   (two identical calls return identical `findings`; a subsequent
   `scan.report`/`findings.list` for the same target is unaffected), and runs
   under `AgentPolicy::ReadOnly`.
3. **AC3:** `scan.report {target}` is `Sensitivity::Read`; with no
   `findings.dir` configured it returns an empty report; with a
   previously-recorded finding for `target` it returns `{report_md, index,
   count}` via `render_report`/`render_index`, filtered to `target`.
4. **AC4:** No secret that passed through a scanned request (an
   `Authorization` header, a session cookie, a token in a query string) ever
   appears in `scan.passive`'s or `scan.report`'s result (literal: a seeded
   flow carrying `Authorization: Bearer s3cr3t` produces a result tree with
   no occurrence of `s3cr3t`).

**Stage 3 — `scan.inject` (Sensitive, gated)**

5. **AC5:** `scan.inject {target, class}` injects the class's payload set via
   `host.client().send()` into points enumerated from already-captured flows
   for `target`, returning `{class, tested, confirmed, stopped_reason}`.
6. **AC6:** For `reflected-xss` and `open-redirect`, injection confirms
   (`confirmed` non-empty) against `SeedMode::Vulnerable` and does not confirm
   (`confirmed` empty) against `SeedMode::Patched`.
7. **AC7:** `scan.inject` reports `Sensitivity::Sensitive`. Under the default
   `AgentPolicy::Auto` an MCP call is refused regardless of
   `scanner.allow_agent_active`. Under `AgentPolicy::All`, a wire-level test
   (mirroring `scope_add_gate_is_wired_default_off`) shows the call refused
   with the flag off and accepted with it on — proving both the `Config`
   plumbing *and* the `defers_to_command_gate` entry. `Frontend::Operator`/
   `Frontend::Cli` always run.
8. **AC8:** An out-of-scope `target` is refused with `GuardError::
   OutOfScope` before any payload is sent, from any caller.
9. **AC9:** On confirmation, exactly one reproduction request runs via
   `StdPocRunner` and exactly one `FindingRecord` is persisted (when
   `findings.dir` is configured) with `reproduction.passed == true`,
   `reproduction.control_passed == None`, and populated `artifacts`;
   `confirmed[i].finding_id` carries the id (`null` when no `findings.dir` is
   configured).
10. **AC10:** `scan.inject.confirm_prompt` returns a non-`None`,
    human-readable description of the target/class/budget whenever the target
    would not already be refused.
11. **AC11:** `scan.inject` never exceeds `request_budget`/
    `per_class_payload_cap` (literal: a budget of 1 yields `stopped_reason ==
    Some("budget")` and `tested <= 1`).

**Stage 4 — `scan.run` campaign + `scan.status`**

12. **AC12:** `scan.run {target}` runs discover → passive → inject (every
    registered class by default) → persisted findings under one shared,
    never-raised budget, returning `{run_id, discover, passive, inject,
    report, stopped_reason}`.
13. **AC13:** `scan.run`'s discover phase holds `EgressConfinement` for its
    duration (an out-of-scope public sub-resource/redirect is refused while
    it runs); its inject phase takes no confinement hold and relies on
    `check_active` alone.
14. **AC14:** `scan.run` is `Sensitivity::Sensitive` with the identical
    two-layer gate as `scan.inject` (same `scanner.allow_agent_active` flag,
    its own `defers_to_command_gate` entry).
15. **AC15:** While a `scan.run` call is in flight, a concurrent `scan.status
    {}` call (same or a different connection) returns the live phase/counts,
    advancing as the campaign proceeds; once the campaign ends, `scan.status`
    reports a terminal phase with the same `stopped_reason` (or `None` on a
    clean finish) the finished `scan.run` call returned.
16. **AC16:** A second `scan.run` while one is in flight is refused, naming
    the in-flight run; `scan.status` remains callable throughout.
17. **AC17:** `scan.status` is `Sensitivity::Read` and runs under
    `AgentPolicy::ReadOnly`.

**Stage 5 — broadened coverage**

18. **AC18:** `stored-xss`, `ssrf`, `idor`, and `auth-bypass` each confirm on
    `SeedMode::Vulnerable` and not on `SeedMode::Patched`; ≥ 6
    `CheckDefinition`s are registered (literal count).
19. **AC19:** `Pitchfork`/`ClusterBomb` modes stay within `request_budget`
    (literal: a two-position `ClusterBomb` class under a small budget yields
    `tested <= request_budget`).
20. **AC20:** The M4 scripted-driver gate still passes with the full Stage
    2-5 command set loaded (non-regression on the larger surface).

## Left to the builder

- Exact module layout (`passive.rs`, `inject.rs`, `checks.rs`,
  `reproduce.rs`/`record.rs`, `campaign.rs`), private helper signatures, and
  the shared-flow-match helper `scan.inject`/`scan.passive` both need
  (factored out of `scan.discover`'s existing target-parsing/guard code in
  `crawl.rs`, which is currently `pub(crate)`).
- The narrowed-`CommandHost` helper that strips the finding recorder before
  calling `StdPocRunner::run` (Correction 1).
- The exact `CampaignStatus` struct's field layout and the `phase` string
  vocabulary, beyond what Acceptance Criteria pin.
- The concrete payload strings per class (seeded from `02-nuclei.md`'s
  vocabulary), within `per_class_payload_cap`, whichever of Rust-literal or
  YAML-file storage Matt picks (Open questions).
- `PocInfo`/`Variable` field values `build_poc` sets per confirmation (name,
  tags, cwe, description) — any reasonable, human-readable choice is fine.
- The exact rename of the new `Config` field's Rust type (`ScannerGateConfig`
  is this spec's placeholder name).

## Open questions

Only Matt can decide these; my recommended default is stated for each so a
"yes" needs no further work. Most consequential first.

1. **`scan.run`'s execution model: synchronous (my default) or a
   background-task campaign?** Synchronous reuses `scan.discover`'s already-
   proven blocking shape and needs no new async-task lifecycle/cancellation
   machinery (every command already runs on its own thread, so this doesn't
   block other connections); `scan.status` reads a shared progress struct the
   blocking call updates as it proceeds. The alternative — `scan.run` returns
   `{run_id}` almost immediately and a spawned background task does the work
   — matches the integration plan's UI wording ("shows live progress...
   clearing the busy flag on completion") more literally and lets a caller's
   RPC connection never sit open for 10 minutes, at the cost of being new
   architecture for this codebase (no command currently returns before its
   work is done) and needing a cancellation/lifecycle story a disconnected
   caller can't provide. I recommend synchronous for v1 and treat async as a
   later upgrade if 10-minute-held connections prove to be a real problem in
   practice.
2. **Does a confirmed `scan.inject`/`scan.run` vuln need to be built as a
   bespoke Rust orchestrator (my default, what this spec specifies) or as a
   driving Rhai/scripted-PoC pipeline reusing `ScriptStepExecutor`?** The
   scripting tier is shaped around reproducing *one* finding (an ordered
   step list + one pass/fail assertion), not an open-ended multi-phase
   crawl/inject/budget loop; stretching it to fit would be an awkward reuse
   of a seam built for something else. I recommend keeping `scan.run` as
   plain Rust campaign glue and reserving the scripting tier for what it
   already does well (PoC reproduction, which `scan.inject`'s reproduction
   step already calls into via `StdPocRunner`).
3. **Does `scan.report` ever include `scan.passive`'s ephemeral observations,
   or only confirmed/persisted findings (my default)?** Promoting passive
   observations into the shared Findings pane is possible (e.g. persisting
   them at a low-confidence tier, or adding a second `observed` array to
   `scan.report`'s result the UIs separately render) but wasn't required by
   anything I found in the integration spec beyond its Stage 2 prose; I'd
   rather not add that surface unless you want operators to see passive
   signals outside the dedicated Scan view.
4. **Stage 3's initial class set: `reflected-xss` + `open-redirect` only (my
   default, smallest reviewable PR) or all six already-seeded classes at
   once (no extra target-side cost either way, but a larger single PR and no
   separate "already-seeded" half of Stage 5)?**
5. **Payload sets: Rust literals (my default for v1) or an operator-editable
   YAML file under a new `scanner.payloads_dir` config (more aligned with the
   project's human-friendly-scripting rule, lets an operator extend the
   dictionary without a rebuild)?**
6. **Keep `scanner.allow_agent_active` default-off with operator opt-in (my
   default, mirrors `scope.allow_agent_widen`), or should agent-run active
   injection be refused forever (no flag at all)?** Carried over from the
   original plugin spec's open question, now concrete since Stage 3 is being
   built and the integration plan's Task 8/9 already assume the flag exists.
7. **Stage 5 breadth beyond the six already-seeded classes:** stay within
   them (my default) or also commission new `aitm-testtarget` seeded+patched
   variants for SQLi/command-injection/LFI (informed by the DVWA capstone's
   broader 12/13-class assessment)? That target work is outside this spec's
   constraints as written and would need its own small spec/task if wanted
   now rather than as a later follow-up.

## Summary

This spec completes the deterministic scanner's backend: `scan.passive`
(Read, ephemeral reflection/header/cookie checks over captured flows),
`scan.report` (Read, a thin render of the persisted findings store, filtered
to a target), `scan.inject` (Sensitive, payload injection through the same
guarded `host.client()` chokepoint `scan.discover` already proved, confirming
via `aitm_poc::matcher`, reproducing via `StdPocRunner`, and recording a
`FindingRecord` directly via `aitm_findings`), and `scan.run`/`scan.status`
(Sensitive/Read, a single-campaign, budget-shared orchestrator with a
pollable, shared progress read), followed by a Stage 5 that broadens coverage
to the remaining already-seeded vuln classes and richer payload modes. It
corrects three places where the original Stage 2-5 plan doesn't survive
contact with the merged code: the reproduction step must call
`StdPocRunner::run` directly (no cross-command invocation exists), the MCP
policy gate's `defers_to_command_gate` allow-list must name `scan.inject`/
`scan.run` or `scanner.allow_agent_active` is unreachable, and
`control_passed` is a test-suite-only comparison, never a production field.
The four backend stages map 1:1 onto the integration plan's four stages.

### Calls made (for Matt to approve or correct)

1. **`scan.inject` does not crawl** — it enumerates points from already-
   captured flows for `target`; `scan.run` is the one-shot discover+inject
   command.
2. **Reproduction calls `StdPocRunner::run` directly** (Correction 1), with a
   narrowed `CommandHost` (no finding recorder attached) to avoid a duplicate,
   lower-fidelity auto-record.
3. **`scan.inject`/`scan.run` persist their own `FindingRecord` via
   `aitm_findings::FindingStore` directly**, not through `CommandHost::
   finding_recorder()` — the generic seam can't carry `control_passed`/class
   semantics.
4. **`control_passed` is always `None` in a production record** (Correction
   3) — the vulnerable-vs-patched comparison lives in the test suite only.
5. **The MCP policy gate's `defers_to_command_gate` must add `scan.inject`/
   `scan.run`** (Correction 2) — otherwise the agent gate is unreachable.
6. **`scan.report` renders only confirmed/persisted findings**, not
   `scan.passive`'s ephemeral observations (flagged, Open question 3).
7. **`scan.run` is synchronous** (blocking `invoke`, shared progress state for
   `scan.status` to poll), not a background-task campaign (flagged, Open
   question 1).
8. **A single in-flight `scan.run` at a time**, refusing a second until the
   first ends — resolves the id-before-response polling problem and prevents
   double-spending one `request_budget`.
9. **Stage 3 ships `reflected-xss` + `open-redirect` only**; Stage 5 adds the
   remaining four already-seeded classes — net-new classes (SQLi, etc.) are
   out of scope for this spec (flagged, Open question 7).
10. **Payload sets are Rust literals for v1** (flagged alternative: an
    operator-editable YAML directory, Open question 5).
11. **New `Config.scanner: ScannerGateConfig{allow_agent_active}` field**,
    distinctly named from the plugin crate's own `ScannerConfig` to avoid two
    identically-named types across the core/plugin boundary.
