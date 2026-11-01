# Scanner v2 track T1b (engine) implementation plan

**Status:** Approved (T1b session, on Matt's autonomous-approval mandate, 2026-10-31; calls B1-B30 accepted as proposed, B6/B29/B30 flagged to the coordinator)
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), sections D1 ("Registration without shared files", "Interim HTTP lane (T1b)", "Where a probe goes"), D3, D4, D5, D6, D7, D9.1 (verification of the landed `PipelineClient::send_opts`), D9.2, D9.3, D10 (agent part), D11, D12 (row T1b, "Integration-shared files"), Verification; ACs T1-1..T1-11 and T10-3.
**Contract:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1a-plan.md` (Approved, merged into this worktree at `e0464e0e`, which already contains `main` v0.5.8). Every type below is cited from the source on disk: `crates/aitm-scan-model/src/{vocab,ids,profile,point,check,job,issue,session,traits,results}.rs`, `crates/aitm-core/src/client.rs`, `crates/aitm-plugin-scanner/src/plugin.rs`, `crates/aitm/src/wire.rs`.
**Research:** `docs/research/20-scanner-v2-current-state.md` (seams), `docs/research/17-burp-style-scanner-architecture.md` §3.2 (priority formula).
**Branch / worktree:** `claude/wizardly-nightingale-441e25` in `/Users/matt/Security/aitmproxy/.claude/worktrees/wizardly-nightingale-441e25`; PR target `main`.
**Size:** one PR; nineteen tasks in seven waves.

## Overview

T1b turns the shipped three-verb scanner into the scanner v2 **engine**: a background job
model on owned handles (`JobRegistry`, `ScanServices` bound late like `LateHandles`), a
budgeted and paced `JobClient` over `ProxyClient::send_opts`, one check catalogue (native
checks from the lanes and `aitm-scan-checks-http`, Rhai checks through a new
`reg.add_check` bridge), a scheduler with Burp's priority rule, an issue store with the D6
dedupe key, PoC-hint reproduction into the existing `FindingStore`, observed-session reuse,
every `scan.*` verb of D3, a generic `notifications/aitm/job` push through a core `JobBus`
fanned out by every `McpServer`, the `scanner:` config section, and an **interim HTTP lane**
over the legacy `crawl.rs`/`discover.rs`/`inject.rs`/`checks.rs`/`passive.rs` modules so
that every T1 acceptance criterion is provable before T2 lands. It also absorbs the four
T1a panel follow-ups the orchestrator accepted on the condition that T1b does them (Task 1
and Task 6; calls B22-B24) and the six lane-track decisions the coordinator routed to T1b as
the owner of `aitm-scan-model` after T1a (`JobCtx::report_l4`/`report_session_lost`,
`L4Options.fields`, `Timing.correlated`, `CheckMeta.scope`, the run-kind seam for
protocol-language guards, the two extra integration-shared files; calls B27-B30).

Waves (tasks inside a wave touch disjoint files and fan out to parallel coders):

| Wave | Tasks | Depends on |
|---|---|---|
| 1 | Task 1 (model follow-ups: `testing`, error-code table, `CheckRegistry`, default-bodied `ProbeHost` additions), Task 2 (core `JobBus`, `CommandHost::jobs`, `send_opts` verification), Task 3 (scanner scaffold, `ScannerConfig` growth, `ScannerFile`), Task 4 (Rhai foundations: `elapsed_ms`, `with_client`, `RunKind::Check`) | none |
| 2 | Task 5 (`McpServer::with_jobs` + gate), Task 6 (profiles), Task 7 (issue store), Task 8 (`JobClient`), Task 9 (session reuse), Task 10 (catalogue + scheduler), Task 13 (Rhai `add_check` bridge + `probe.*`; needs only Tasks 1 and 4, so T3's converted scripts can start against it as early as possible) | wave 1 |
| 3 | Task 11 (PoC-hint reproduction), Task 12 (interim HTTP lane) | wave 2 |
| 4 | Task 14 (`JobRegistry`, `ScanServices`/`ScanLate`, worker) | wave 3 |
| 5 | Task 15 (`scan.*` verbs, uniform `check.<id>`, `ScannerPlugin::load`), Task 16 (legacy verbs over the job model) | Task 14 |
| 6 | Task 17 (binary wiring: `wire.rs`, `main.rs`, `tui.rs`), Task 18 (`docs/scanner.md`) | Task 15 (17); Task 15 (18, names only) |
| 7 | Task 19 (integration: merge `origin/main`, re-pin, gate, real proof) | all |

## Shared facts for every coder

- **TDD per task.** Write the named test first, run it and quote the red run (a compile
  error on a type that does not exist yet counts as red), implement, quote the green run.
- **Sandbox vs Terminal.** `cargo test -p <crate> --offline`, `cargo clippy --offline`,
  `cargo fmt --check` work in the sandbox. Anything that binds a port (the `aitm` integration
  tests, the e2e harness, the real proof) runs in the Terminal panel. Full gate from the
  worktree root before handing back:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`; quote the
  exit code, never a grep.
- **`blake3` is not in the offline registry cache** (T1a shared facts). Task 3 is the first
  task to make a crate inherit it; its coder runs `cargo fetch` in the **Terminal** once
  before the offline gate and quotes it. `tokio-util 0.7.19`, `serde_yaml 0.9.34` are cached.
- **Contract names.** Use the model crate's names exactly (`LaneKind` is the enum, `Lane` the
  trait; `ScanErrorCode` has the **nine** D3 codes; `StartResult.dry_run: Option<bool>`;
  `JobEvent` in the model is the push **event enum**, `aitm_core::JobEvent` (Task 2) is the
  bus **struct**: import the core one as `use aitm_core::JobEvent as BusJobEvent;` wherever
  both are in scope, call B21). The model traits may be extended **only with default-bodied
  methods** (Task 1 is the only task that does so).
- **Error strings.** Every verb refusal is `scan: <code>: <message>` built with
  `aitm_scan_model::scan_error(code, msg)` (Task 1); `ScanErrorCode::parse_message` must parse
  every message the engine emits (the Tester greps for a bare `scan:` prefix without a code).
- **Redaction vocabulary.** PR #199 (`claude/scanner-vocab-7d36bb`, `scrub_text_wide`) is
  **not on `origin/main`** at the time of writing (checked: `origin/main`
  `crates/aitm-core/src/redact.rs` exposes only `is_secret_key` and `scrub_text`). Every T1b
  site that scrubs text calls **one** helper, `aitm_plugin_scanner::util::scrub` (Task 3),
  which delegates to `aitm_core::redact::scrub_text` today; Task 19 flips that one line to
  `scrub_text_wide` if #199 has merged by then (and `reproduce.rs`'s `scrub_embedded` keeps
  whatever #199 made it). Excerpts in `Evidence.matched` go through `scrub` **then**
  `Evidence::excerpt`.
- **Timestamps** are epoch milliseconds via `util::now_ms()`; ids via `util::job_id()`
  (`scan-<8 hex>`) and `util::issue_id()` (`issue-<8 hex>`), both from `uuid::Uuid::new_v4()`.
- **Where state lives on disk** (D5/D6/D11), all under `cfg.findings.dir` when set, else
  memory only: `scan/jobs/<job>.json`, `scan/issues/<id>.json`, `scan/profiles/<name>.yaml`
  (`util::scan_dir(findings_dir, "jobs")` etc., Task 3).
- **Integration-shared files are not edited before Task 19**: `crates/aitm/tests/frontends.rs`
  (`EXPECTED_TOOLS`), `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS`),
  `crates/aitm-tui/fixtures/bus-fixture.json`, `crates/aitm/tests/bundled_startup.rs`,
  `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`, and (coordinator, 2026-10-31)
  `crates/aitm-plugin-rhai/src/catalog_assembly.rs::production_languages()` (T1b adds no
  language; untouched). `docs/design/languages/rhai.api.json` is on that list **across
  tracks**, but inside T1b it is edited once, by Task 13, because
  `crates/aitm-plugin-rhai/tests/api_catalog.rs` asserts a bijection between the engine's
  registered host functions and that file and the per-task gate must stay green (call B30);
  Task 19 re-verifies it against the live engine surface. Consequence for Task 4/13: `ScriptServices`
  gains **no field** (it is constructed in 17 files including two of the shared ones); the
  check registry rides on `RhaiLoader`/`ScriptTier` instead (call B9).
- **Never touch** `crates/aitm-tui/**` (except the Task 19 re-pin), `apps/**`,
  `crates/aitm-testtarget/**`, `tests/e2e/**`, `crates/aitm-poc/**`, `crates/aitm-findings/**`,
  `crates/aitm-proto-*/**`, lane crates, `scripts/bundled/**`.
- **No `unsafe`.** The scripting bridge keeps its check context in a thread-local holding
  `Arc<dyn ProbeHost>` (via the default-bodied `ProbeHost::shared()` of Task 1), never a
  borrowed pointer.
- **Caller classes.** `host.caller_is_trusted_control()` (`Frontend::Cli | Frontend::Operator`)
  is the operator; `Frontend::Mcp` is the agent. `StartedBy.frontend` is the lowercase
  `Frontend` name (`cli | mcp | operator`, T1a Task 6).

## Tasks

### Task 1: model crate follow-ups: `testing` module, error-code table, `CheckRegistry`, default-bodied `ProbeHost` additions

- **Satisfies:** T1a Review log follow-ups (Quality: token table + unit error type; Quality:
  null stubs deduplicated into a `testing` module); spec D9.3 (the `CheckRegistry` the engine
  reads); spec D2 trait extension rule ("only with default bodies"); coordinator decisions
  1-4 of 2026-10-31 (`JobCtx::report_l4`/`report_session_lost`, `L4Options.fields`,
  `Timing.correlated`, `CheckMeta.scope`), spec D8.4 (T5-3 needs the fuzzable-field surface),
  D8.2/T3-4 (`evidence.timing.correlated` read from evidence).
- **Depends on:** none.
- **Files:** `crates/aitm-scan-model/Cargo.toml` (modify: `[features] testing = []`),
  `crates/aitm-scan-model/src/lib.rs` (modify: `pub mod registry; pub use registry::*;`,
  `#[cfg(any(test, feature = "testing"))] pub mod testing;`),
  `crates/aitm-scan-model/src/vocab.rs` (modify: `ScanErrorCode` impls),
  `crates/aitm-scan-model/src/registry.rs` (create), `crates/aitm-scan-model/src/testing.rs`
  (create), `crates/aitm-scan-model/src/traits.rs` (modify: default-bodied methods on `ProbeHost`,
  `JobCtx` and `Lane`; its tests move their stubs to `testing`),
  `crates/aitm-scan-model/src/profile.rs` (modify: `L4Options.fields`),
  `crates/aitm-scan-model/src/check.rs` (modify: `Timing.correlated`, `CheckMeta.scope`),
  `crates/aitm-scan-model/fixtures/scan.checks.json` (modify: one entry gains `"scope": "origin"`
  so the fixture exercises the new key; the fixture test's pinned literals are unchanged).
- **Change:**
  1. `vocab.rs`: one table `const SCAN_ERROR_CODES: [(ScanErrorCode, &str); 9]`; `as_str`,
     `FromStr` and `parse_message` all read it. `impl FromStr for ScanErrorCode { type Err = UnknownScanErrorCode; }`
     with `pub struct UnknownScanErrorCode(pub String)` (`Debug, Clone, PartialEq, Eq`,
     `Display` = ``unknown scan error code `<token>` ``, `std::error::Error`). New
     `pub fn scan_error(code: ScanErrorCode, message: impl std::fmt::Display) -> anyhow::Error`
     producing exactly `scan: <code>: <message>`. Wire tokens unchanged; the existing
     agreement test stays green.
  2. `registry.rs`: `pub struct CheckRegistry { inner: std::sync::RwLock<Vec<Registered>> }`
     (`Default`), private `struct Registered { source: String, check: Arc<dyn Check> }`;
     `pub fn new() -> Self`; `pub fn add(&self, source: &str, check: Arc<dyn Check>) -> Result<(), DuplicateCheck>`
     (refuses an id already present from a **different** source; same source replaces);
     `pub fn replace_source(&self, source: &str, checks: Vec<Arc<dyn Check>>)`;
     `pub fn remove_source(&self, source: &str) -> usize`;
     `pub fn snapshot(&self) -> Vec<Arc<dyn Check>>` (sorted by `meta().id`);
     `pub fn len(&self) -> usize`; `pub fn is_empty(&self) -> bool`.
     `pub struct DuplicateCheck { pub id: String, pub existing_source: String }` (`Debug, Clone, PartialEq, Eq`, `Display`, `Error`).
     Module doc: a thread-safe container, no I/O; the scripting tier fills it, the engine reads it.
  3. `traits.rs`: `ProbeHost` gains, each with a default body returning `None` and a doc comment:
     `fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>>` (the job's budgeted client,
     for a script bridge to route `http.send`), `fn shared(&self) -> Option<Arc<dyn ProbeHost>>`
     (an owning handle to this host, for a bridge that must hold it in a thread-local),
     `fn captured(&self) -> Option<aitm_core::HttpFlow>` (the captured flow the point came
     from, for passive checks that must not send).
     `JobCtx` gains `fn report_l4(&self, counters: L4Counters) {}` (an L4 lane reports its
     cases/crashes/liveness/retired counters; the engine folds them into `JobStatus.l4`) and
     `fn report_session_lost(&self) {}` (a lane that detects auth loss itself; the engine sets
     `session.lost` and, under `on_lost: stop`, ends the audit with `stopped_reason: session_lost`).
     `Lane` gains `fn validate(&self, target: &ProfileTarget, profile: &ScanProfile) -> Result<(), String> { Ok(()) }`
     (a lane refuses a profile it cannot run, e.g. a packet plan naming `ipv4.src`; the engine
     maps `Err(msg)` to `scan: invalid_profile: <msg>` **before** spawning, so T5-3 is
     synchronous). Module doc gains: "T1b added `ProbeHost::{client, shared, captured}`,
     `JobCtx::{report_l4, report_session_lost}`, `Lane::validate` (all default-bodied) on 2026-10-31".
     Error-prefix convention documented on `ProbeHost::probe` and `Lane::discover`: a lane may
     return an error whose message starts with the literal `scan: session_lost: ` (probe) or
     `invalid_profile: ` (discover); the engine maps the first to the session-lost status and
     the second to `error: "scan: invalid_profile: <rest>"` on the failed job (Task 14).
  3b. `vocab.rs`: `pub enum CheckScope { Point, Node, Origin }` (`Default` = `Point`, snake_case
     tokens `point | node | origin`, `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`).
     `check.rs`: `CheckMeta` gains `#[serde(default)] pub scope: CheckScope`; `Timing` gains
     `#[serde(default)] pub correlated: bool`. `profile.rs`: `L4Options` gains
     `pub fields: Vec<String>` (default empty = the lane's full default table; the profile tree
     stays `deny_unknown_fields`; built-in profiles unchanged). Existing struct literals in the
     crate's tests gain the new fields; `testing::null_meta` sets `scope: CheckScope::Point`.
  4. `testing.rs` (`#![doc(hidden)]`-style doc "test stubs; compiled under `cfg(test)` or the
     `testing` feature"): `pub struct NullClient` (`ProxyClient`, `send` errors);
     `pub struct NullJob` with `pub fn new() -> Self` (`JobCtx`: `job_id() == "scan-1a2b3c4d"`,
     `budget_left() == 7`, `marker() == "aitm7f3a"`, `MemFlowStore`, `StdGuard`);
     `pub struct NullHost` with `pub fn new() -> Self` (`ProbeHost`: every I/O method errors,
     `budget_left() == 3`); `pub fn null_meta(id: &str) -> CheckMeta` (`class: "none"`, lanes
     `[Http]`, kinds `[Query]`, `Passive`, `Light`, `Observe`, `Info`, `Tentative`, `Native`);
     `pub struct NullCheck` with `pub fn new(meta: CheckMeta) -> Self` (`Clean`/`Tentative`,
     detail `"nothing to report"`); `pub struct NullLane` (`Http`, empty discovery, `probe_host_for` errors);
     `pub fn query_point(url: &str, name: &str) -> InsertionPoint` (`id: "p1"`, `kind: Query`,
     `method: Some("GET")`, `frequency: 1`); and a new
     `pub struct RecordingHost { .. }` with `pub fn new(status: u16, body: &str) -> Self`,
     implementing `ProbeHost` so that `probe(payload)` appends `payload.value` to an internal
     list, returns `ProbeResponse { status: Some(status), body, elapsed_ms: 1, .. }` and
     decrements a budget that starts at 16; `baseline()` returns the same canned response;
     `pub fn payloads(&self) -> Vec<String>`; `shared()` returns `Some(Arc)` when built via
     `pub fn shared_new(status, body) -> Arc<RecordingHost>`. The `traits.rs` tests import these
     from `crate::testing` instead of defining them.
- **Test:** `vocab.rs`: `unknown_code_is_a_typed_error`:
  `"nope".parse::<ScanErrorCode>().unwrap_err() == UnknownScanErrorCode("nope".into())` and its
  `to_string() == "unknown scan error code `nope`"`; `scan_error_formats_the_wire_form`:
  `scan_error(ScanErrorCode::Busy, "job scan-1a2b3c4d is running").to_string() == "scan: busy: job scan-1a2b3c4d is running"`
  and `ScanErrorCode::parse_message(&s) == Some((ScanErrorCode::Busy, "job scan-1a2b3c4d is running"))`;
  `every_code_round_trips_through_the_table`: for all nine, `code.as_str().parse::<ScanErrorCode>() == Ok(code)`.
  `registry.rs`: `add_then_snapshot_sorted_by_id` (add `b-check` from `s1`, `a-check` from `s2`
  → ids `["a-check", "b-check"]`, `len() == 2`); `duplicate_id_across_sources_is_refused`
  (`add("s3", a-check)` → `Err(DuplicateCheck { id: "a-check", existing_source: "s2" })`);
  `same_source_replaces` (`add("s2", a-check')` → `Ok`, `len() == 2`);
  `replace_source_swaps_only_that_source` (`replace_source("s2", vec![])` → ids `["b-check"]`).
  `testing.rs`: `recording_host_records_payloads` (probe `"x"` then `"y"` → `payloads() == ["x","y"]`,
  `budget_left() == 14`); `traits.rs`: `probe_host_defaults_are_none`
  (`NullHost::new().client().is_none() && shared().is_none() && captured().is_none()`),
  `job_ctx_report_defaults_are_no_ops` (`NullJob::new().report_l4(L4Counters { cases: 1, ..Default::default() })`
  and `report_session_lost()` compile and return `()`), `lane_validate_defaults_to_ok`
  (`NullLane.validate(&ProfileTarget::default(), &ScanProfile::default()) == Ok(())`), and the
  existing `traits_are_object_safe`, `dyn_check_runs_against_a_dyn_probe_host`,
  `dyn_lane_discovers_through_a_dyn_job_ctx` still pass using the `testing` stubs.
  `vocab.rs`/`check.rs`/`profile.rs`: `check_scope_defaults_to_point`
  (`serde_json::from_str::<CheckMeta>(<a meta JSON without scope>).scope == CheckScope::Point`;
  `to_string(&CheckScope::Origin) == "\"origin\""`); `timing_correlated_defaults_false`
  (`Timing` JSON without the key → `correlated == false`; with `"correlated":true` → `true`);
  `l4_fields_default_empty_and_round_trip` (`minimal_yaml` → `l4.fields.is_empty()`;
  `l4:\n  fields: [tcp.flags, raw]` → `vec!["tcp.flags", "raw"]`; every builtin still
  round-trips and `builtin("standard")` still equals the `scan.profile.get.json` fixture).
- **Done when:** `cargo test -p aitm-scan-model --offline` passes, `cargo test -p aitm-scan-model --offline --features testing`
  passes, the fixture tests are untouched and green, and the full gate passes.

### Task 2: `aitm-core`: `JobBus`/`JobEvent`, `CommandHost::jobs()`, `send_opts` verification

- **Satisfies:** spec D9.2 (core half), D9.1 verification (the `PipelineClient::send_opts`
  T1a landed is checked against D9.1 and left as is), Architect's call 4 (spec).
- **Depends on:** none.
- **Files:** `crates/aitm-core/src/jobs.rs` (create), `crates/aitm-core/src/lib.rs` (modify:
  `pub mod jobs;` + re-exports), `crates/aitm-core/src/ctx.rs` (modify: `CommandHost`),
  `crates/aitm-core/src/client.rs` (modify: **tests only**).
- **Change:**
  1. `jobs.rs`: `pub struct JobEvent { pub job: String, pub kind: String, pub event: String, pub seq: u64, pub payload: crate::value::Value }`
     (`Debug, Clone, PartialEq`); `pub const DEFAULT_JOB_BUS_CAPACITY: usize = 1024;`
     `pub struct JobBus { tx: tokio::sync::broadcast::Sender<JobEvent> }` with
     `pub fn new(capacity: usize) -> Self` (clamped to >= 1), `impl Default` (the constant),
     `pub fn publish(&self, event: JobEvent) -> usize` (receivers reached; `0` with no
     subscriber, never an error), `pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<JobEvent>`,
     `pub fn receiver_count(&self) -> usize`. Module doc: a progress channel any long-running
     command may publish to; servers render `kind`s they do not interpret (the justification
     text of D9.2, verbatim in spirit).
  2. `ctx.rs`: `CommandHost` field `jobs: Option<Arc<JobBus>>` (`None` in `new`),
     `pub fn with_jobs(mut self, jobs: Arc<JobBus>) -> Self`,
     `pub fn jobs(&self) -> Option<Arc<JobBus>>`.
  3. `lib.rs`: `pub use jobs::{JobBus, JobEvent, DEFAULT_JOB_BUS_CAPACITY};`.
  4. D9.1 verification (read `client.rs` `PipelineClient::send_opts`; it already does guard
     first with the permit held, `send_with(&req, opts.version)`, `record_error` rules,
     `is_replay = true`, `marks = opts.marks`, insert only under `RecordPolicy::Always`; `send`
     delegates): **no production change**. Add the one test the engine's pacing depends on.
- **Test:** `jobs.rs`: `publish_without_subscribers_returns_zero`
  (`JobBus::default().publish(ev) == 0`); `subscriber_receives_events_in_order` (`#[tokio::test]`:
  publish `seq` 1, 2, 3 → the receiver yields `[1, 2, 3]` and `receiver_count() == 1`);
  `capacity_is_at_least_one` (`JobBus::new(0)` then `subscribe()` + `publish` → `1`).
  `ctx.rs`: `command_host_jobs_defaults_to_none_and_with_jobs_sets_it`
  (`jobs().is_none()`; after `with_jobs(bus.clone())`, `Arc::ptr_eq(&host.jobs().unwrap(), &bus)`).
  `client.rs`: `send_opts_guard_error_is_downcastable` (authority `other.test` not in scope →
  `err.downcast_ref::<GuardError>() == Some(&GuardError::OutOfScope("other.test".into()))`;
  this is what `JobClient` relies on to see `RateLimited { retry_after }`).
- **Done when:** `cargo test -p aitm-core --offline` passes and the full gate passes.

### Task 3: scanner scaffold, `ScannerConfig` growth, `util`, `ScannerFile` in the config file

- **Satisfies:** spec D11 (`scanner:` section outside `aitm_core::Config`, `ScannerConfig`
  grows, the file feeds it), D12 row T1b (`crates/aitm/src/**` is T1b's); the module layout
  rule of T1a ("later tasks own one file each").
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-scanner/Cargo.toml` (modify), `crates/aitm-plugin-scanner/src/lib.rs`
  (modify), `crates/aitm-plugin-scanner/src/config.rs` (modify), `crates/aitm-plugin-scanner/src/util.rs`
  (create), **placeholder** modules containing only a `//!` doc line: `src/profiles.rs`,
  `src/issues.rs`, `src/client.rs`, `src/session.rs`, `src/catalogue.rs`, `src/scheduler.rs`,
  `src/reproduce_link.rs`, `src/interim_lane.rs`, `src/jobs.rs`, `src/worker.rs`, `src/verbs.rs`,
  `src/manual_check.rs` (create, all); `crates/aitm/src/config_file.rs` (modify).
- **Change:**
  1. `Cargo.toml`: add `blake3`, `tokio-util`, `serde`, `serde_yaml`, `uuid` (all `workspace = true`),
     `tokio` features gain `"sync"`; dev-dep `aitm-scan-model = { workspace = true, features = ["testing"] }`
     and `tempfile = "3"` (if not cached offline, use `std::env::temp_dir()` + a uuid subdir
     and say so). Comments name the spec section each dependency serves.
  2. `lib.rs`: `pub mod` lines for every module above and `pub use config::{Ceilings, ScannerConfig};`,
     `pub use plugin::ScannerPlugin;` (existing re-exports stay).
  3. `config.rs`: `ScannerConfig` keeps its six fields and gains
     `pub allow_agent_l4_fuzz: bool` (false), `pub max_jobs: u32` (2), `pub history: u32` (50),
     `pub check_timeout_s: u64` (60), `pub ceilings: Ceilings`, `pub default_profile: String` ("standard"),
     `pub profiles: BTreeMap<String, aitm_scan_model::ScanProfile>`, `pub findings_dir: Option<PathBuf>`
     (None; `wire.rs` copies `cfg.findings.dir`), `pub l4_allow_agent_inject: bool` (false;
     `wire.rs` copies `features.l4.allow_agent_inject`, the field at `crates/aitm-proto-l4/src/config.rs`).
     `pub struct Ceilings { pub probes: u32 (20_000), pub time_s: u64 (7_200), pub l4_cases: u32 (5_000), pub l4_bytes_per_s: u32 (1_048_576), pub ws_frame_bytes: u32 (4_194_304), pub max_issues: u32 (4_096) }`.
     Both `Debug, Clone, PartialEq` (`Eq` dropped: `ScanProfile` holds an `f32`).
  4. `util.rs`: `pub fn now_ms() -> u64`; `pub fn job_id() -> String` (`scan-` + first 8 hex of
     a v4 uuid); `pub fn issue_id() -> String` (`issue-` + 8 hex);
     `pub fn scan_dir(findings_dir: &Path, sub: &str) -> PathBuf` (`<dir>/scan/<sub>`);
     `pub fn scrub(text: &str) -> String` (delegates to `aitm_core::redact::scrub_text`; doc:
     "the one line Task 19 flips to `scrub_text_wide`"); `pub fn json_to_value(v: serde_json::Value) -> aitm_core::Value`
     (move the body of `report::index_to_value` here and make `index_to_value` call it).
  5. `config_file.rs`: `#[derive(Deserialize, Default)] #[serde(deny_unknown_fields)] struct ScannerFile { allow_agent_active: Option<bool>, allow_agent_l4_fuzz: Option<bool>, max_jobs: Option<u32>, history: Option<u32>, check_timeout_s: Option<u64>, ceilings: Option<CeilingsFile>, default_profile: Option<String>, profiles: Option<BTreeMap<String, ScanProfile>> }`,
     `struct CeilingsFile` (six `Option`s, `deny_unknown_fields`), `fn apply(self, c: &mut ScannerConfig)`;
     `ConfigFile.scanner: Option<ScannerFile>`; `Settings.scanner: ScannerConfig` (built from
     `ScannerConfig::default()` then `apply`, in `parse_settings`); module doc lists `scanner`
     beside `l4`/`macos_capture`/`system_proxy` as a section kept outside `aitm_core::Config`.
     `crates/aitm/Cargo.toml` already depends on `aitm-plugin-scanner` and `aitm-scan-model`.
- **Test:** `config.rs`: `scanner_config_defaults_grow` (`max_jobs == 2`, `history == 50`,
  `check_timeout_s == 60`, `ceilings == Ceilings { probes: 20_000, time_s: 7_200, l4_cases: 5_000, l4_bytes_per_s: 1_048_576, ws_frame_bytes: 4_194_304, max_issues: 4_096 }`,
  `default_profile == "standard"`, `profiles.is_empty()`, `!allow_agent_l4_fuzz`,
  `findings_dir.is_none()`); the existing `scanner_config_defaults` stays.
  `util.rs`: `ids_have_the_wire_shape` (`job_id()` matches `^scan-[0-9a-f]{8}$`, `issue_id()`
  matches `^issue-[0-9a-f]{8}$`, two calls differ); `scan_dir_joins_scan_then_sub`
  (`scan_dir(Path::new("/f"), "jobs") == PathBuf::from("/f/scan/jobs")`); `scrub_masks_a_token`
  (`scrub("Authorization: Bearer abc")` does not contain `abc`).
  `config_file.rs` tests: `scanner_section_feeds_scanner_config` (YAML
  `scanner:\n  allow_agent_active: true\n  max_jobs: 3\n  ceilings:\n    probes: 10\n  default_profile: light-http\n  profiles:\n    my-api:\n      name: my-api\n      lanes: [http]\n`
  → `settings.scanner.allow_agent_active`, `max_jobs == 3`, `ceilings.probes == 10`,
  `ceilings.time_s == 7_200`, `default_profile == "light-http"`,
  `profiles["my-api"].lanes == vec![LaneKind::Http]`); `scanner_section_unknown_key_is_an_error`
  (`scanner:\n  max_job: 3\n` → `Err` whose text contains `max_job`);
  `absent_scanner_section_is_default` (`settings.scanner == ScannerConfig::default()`).
- **Done when:** Terminal `cargo fetch` quoted (exit 0), `cargo test -p aitm-plugin-scanner --offline`
  and `cargo test -p aitm --lib --offline config_file` pass, `cargo metadata --offline` exits 0, full gate passes.

### Task 4: Rhai foundations: `http.send` `elapsed_ms`, `with_client` override, `RunKind::Check`, `ScriptError::CheckMeta`

- **Satisfies:** spec D9.3 (c) and (d), D4 "Timing without `sleep`" (host-measured
  `elapsed_ms`, `min(remaining, 30 s)` per probe), D4 "Missing or invalid meta is a load error
  naming the key" (the error type; the bridge is Task 13), coordinator decision 5 (the run
  kind exposed to protocol-language guards so T4's `ws.*` can refuse `on_ws_*` hooks, D8.3).
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-rhai/Cargo.toml` (modify: `aitm-scan-model = { workspace = true }`,
  `serde_json = { workspace = true }`; dev-dep `aitm-scan-model` with `features = ["testing"]`),
  `crates/aitm-plugin-rhai/src/lib.rs` (modify: `pub mod check_bridge; pub mod host_probe;`
  and re-exports `pub use engine::{probe_budget, MAX_PROBE_TIMEOUT}; pub use host_net::with_client;`),
  `crates/aitm-plugin-rhai/src/engine.rs` (modify), `crates/aitm-plugin-rhai/src/host_net.rs`
  (modify), `crates/aitm-plugin-rhai/src/error.rs` (modify),
  `crates/aitm-plugin-rhai/src/host_registry.rs` (modify: `RhaiCallSource::run_kind`),
  `crates/aitm-plugin/src/language.rs` (modify, **additive only**, on the coordinator's
  instruction of 2026-10-31; not in D12's T1b row, recorded as call B29), placeholders
  `crates/aitm-plugin-rhai/src/check_bridge.rs`, `crates/aitm-plugin-rhai/src/host_probe.rs`
  (create, doc line only), `crates/aitm-plugin-rhai/tests/check_run.rs` (create).
- **Change:**
  1. `engine.rs`: `RunKind::Check` variant; `impl Budget { pub fn for_check(base: Budget, check_timeout: Duration) -> Budget }`
     (`hook_timeout = check_timeout`, other fields from `base`);
     `pub const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(30);`
     `pub fn probe_budget() -> Option<Duration>` = `remaining_budget().map(|r| r.min(MAX_PROBE_TIMEOUT))`.
  2. `host_net.rs`: `thread_local! { static CLIENT_OVERRIDE: RefCell<Option<Arc<dyn ProxyClient>>> }`;
     `pub fn with_client<T>(client: Arc<dyn ProxyClient>, f: impl FnOnce() -> T) -> T` (sets
     the override, runs `f`, restores the previous value even on panic via a guard);
     `fn current_client(services: &ScriptServices) -> Arc<dyn ProxyClient>` (override or
     `services.client`); `send()` measures `Instant::now()` around the client call, uses
     `current_client`, and passes the measured `elapsed_ms: u32` (saturating) into
     `response_map(&flow, elapsed_ms)`, which gains the key `elapsed_ms` (`rhai::INT`). When
     `current_run() == Some(RunKind::Check)` the await budget is `probe_budget()`; otherwise
     the existing `remaining_budget()` rule is unchanged.
  2b. Run-kind seam. `crates/aitm-plugin/src/language.rs`:
     `pub enum HostRunKind { Hook, Load, Command, Check, PocStep }` (`Debug, Clone, Copy, PartialEq, Eq`);
     `HostCallContextSource` gains `fn run_kind(&self) -> Option<HostRunKind> { None }`
     (doc: "which kind of script run is calling; a guard that must refuse hooks (D8.3 `ws.*`)
     checks `Some(HostRunKind::Hook)`; `None` means the source cannot tell and the guard
     decides conservatively"); `HostCallCtx` gains `pub fn run_kind(&self) -> Option<HostRunKind>`
     delegating to its source. `host_registry.rs`: `impl HostCallContextSource for RhaiCallSource`
     overrides `run_kind` with `engine::current_run()` mapped variant-for-variant
     (`RunKind::Hook => HostRunKind::Hook`, `Load`, `Command`, `Check`, `PocStep`).
  3. `error.rs`: `ScriptError::CheckMeta { script: String, check: Option<String>, key: String, message: String }`
     with `Display` ``script `<script>`: reg.add_check `<check or ?>`: `<key>`: <message>`` and a
     help line ("every key of `CheckMeta` is required except `wants_traits`, `cwe`, `remediation`,
     `needs_baseline`; see docs/scanner.md").
- **Test** (`tests/check_run.rs`, building a `RhaiLoader` the way `tests/host_net.rs` does, with a
  stub `ProxyClient` that answers 200 and records `SendOptions`):
  `http_send_returns_elapsed_ms` (stub sleeps 20 ms; script
  `fn load(reg) { reg.add_command("t.send", "d", |args| { let r = http.send(#{ method: "GET", url: "http://ex.test/" }); r.elapsed_ms }); }`
  → the command returns `Value::Int(n)` with `20 <= n < 5000`);
  `with_client_override_routes_http_send` (stub A body `"A"`, stub B body `"B"`; the command
  returns `r.body`; invoked inside `with_client(B, || cmd.invoke(..))` → `"B"`; invoked plainly
  afterwards → `"A"`); `budget_for_check_uses_the_check_timeout`
  (`Budget::for_check(Budget::default(), Duration::from_secs(60)).hook_timeout == Duration::from_secs(60)`
  and `.max_operations == Budget::default().max_operations`); `probe_budget_is_capped_at_30s`
  (under `begin_run(RunKind::Check, Budget::for_check(Budget::default(), Duration::from_secs(120)))`,
  `probe_budget().unwrap() <= Duration::from_secs(30)` and `> Duration::from_secs(29)`);
  `check_meta_error_names_the_key` (`ScriptError::CheckMeta { script: "s".into(), check: None, key: "kinds".into(), message: "missing".into() }.to_string()` contains `` `kinds` ``);
  `run_kind_is_visible_to_a_seam_guard` (using the fake `ProtocolLanguage` + `Guarded` pattern
  of `tests/host_registry.rs`: a guard that records `ctx.run_kind()`; calling the language's
  fn from a `reg.add_command` closure records `Some(HostRunKind::Command)`, from an `on_request`
  hook `Some(HostRunKind::Hook)`, and a `HostCallCtx` over a stub source with the default
  method yields `None`).
- **Done when:** `cargo test -p aitm-plugin-rhai --offline` passes (every existing test
  untouched) and the full gate passes.

### Task 5: `aitm-mcp`: `McpServer::with_jobs`, the job dispatcher, `defers_to_command_gate` gains `scan.start`

- **Satisfies:** spec D9.2 (`aitm-mcp` half: render `notifications/aitm/job`, `fanout_state`
  semantics, role-aware, agent-muted under `paused`), D3 "Progress push", D11
  (`defers_to_command_gate` gains `scan.start`), AC T1-3 (server half), AC T1-4 (the
  `refused_agent` token must come from the command, call B6).
- **Depends on:** Task 2.
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/src/lib.rs` (modify:
  `pub use server::JOB_NOTIFICATION_METHOD;`).
- **Change:**
  1. `pub const JOB_NOTIFICATION_METHOD: &str = "notifications/aitm/job";` in `server.rs` (the
     model crate has the same literal; `aitm-mcp` does not depend on it).
  2. `McpServer` fields `jobs: Option<Arc<JobBus>>`, `job_dispatcher_spawned: AtomicBool`;
     `pub fn with_jobs(mut self, bus: Arc<JobBus>) -> Self`; `pub fn jobs(&self) -> Option<Arc<JobBus>>`.
  3. `spawn_push_dispatcher(self: &Arc<Self>)` additionally spawns, once, a loop over
     `bus.subscribe()` calling `self.push_job_event(&ev)` (`Lagged` → continue, `Closed` → break);
     the existing call sites (`serve()` and `main.rs`) therefore cover the job stream too.
  4. `pub fn push_job_event(&self, ev: &JobEvent)`: `params` = `to_json(&ev.payload)` when it
     is an object (else `{}`), then `job`, `kind`, `event`, `seq` are inserted **when absent**;
     the line is `{"jsonrpc":"2.0","method":"notifications/aitm/job","params":<params>}` fanned
     out with `self.subscriptions.fanout_state(&line, &|| self.agent_pushes_muted())`.
  5. `dispatch` builds the `CommandHost` with `.with_jobs(bus.clone())` when `self.jobs` is `Some`.
  6. `defers_to_command_gate` gains `"scan.start"` (comment: the command reads the agent
     policy and the `scanner.allow_agent_active`/`allow_agent_l4_fuzz` gates itself and answers
     with its own `scan: refused_*` code). New
     `fn defers_to_command_gate_under_auto(name: &str) -> bool { matches!(name, "scan.start") }`
     and the `policy_decision` arm `(AgentPolicy::Auto, Sensitivity::Sensitive) => defers_to_command_gate_under_auto(cmd.name())`
     (doc: a command listed here must refuse an agent itself under `auto`; the server lets it
     answer so callers get one code vocabulary; every other Sensitive command keeps today's refusal).
- **Test** (in `server.rs`'s tests module, using the existing helpers that build a server with
  services and a `ConnCtx { out: Some(sink), .. }`, subscribe via `tools/call flow.subscribe`,
  then drain the sink): `job_event_renders_as_a_job_notification` (operator connection
  subscribed; `push_job_event(&JobEvent { job: "scan-1a2b3c4d", kind: "scan", event: "progress", seq: 3, payload: Value::Object({ "status": Value::Object({ "state": Value::Str("running") }) }) })`
  → `sink.drain()` has exactly one line; parsed: `method == "notifications/aitm/job"`,
  `params.job == "scan-1a2b3c4d"`, `params.kind == "scan"`, `params.event == "progress"`,
  `params.seq == 3`, `params.status.state == "running"`); `job_payload_fields_win_over_envelope`
  (payload already carries `"seq": 9` → `params.seq == 9`); `job_lines_are_muted_for_agents_under_paused`
  (one agent and one operator connection subscribed; `agent_state.set_policy(AgentPolicy::Paused)`;
  push → agent sink `queued_len() == 0`, operator sink `1`); `with_jobs_dispatcher_delivers_published_events`
  (`#[tokio::test]`: `Arc<McpServer>` with `with_jobs(bus)`, subscribed operator sink,
  `spawn_push_dispatcher()`, `bus.publish(ev)` → within 2 s the sink holds one line whose
  `params.event == "started"`); `scan_start_is_deferred_to_its_command_gate_under_auto_and_all`
  (a test `Sensitive` command named `scan.start` whose `invoke` returns
  `Err(anyhow!("scan: refused_agent: test gate"))`; an agent `ConnCtx`; under `Auto` the
  `tools/call` result is `isError: true` with text containing `scan: refused_agent: test gate`;
  under `All` the same; a test `Sensitive` command named `l4.inject` under `Auto` is refused
  with text containing `permits no sensitive actions`); `command_host_carries_the_job_bus`
  (a test command whose `invoke` returns `Value::Bool(host.jobs().is_some())` → `true` on a
  server built `with_jobs`, `false` otherwise).
- **Done when:** `cargo test -p aitm-mcp --offline` passes (every existing gate test untouched) and the full gate passes.

### Task 6: profiles: resolve, validate, clamp, save/load YAML, list

- **Satisfies:** spec D3 (`scan.start` params `profile | profile_name | target` exactly one,
  `overrides`, `clamped`; `scan.profile.*` results), D11 (saved profiles under
  `<findings.dir>/scan/profiles/`, ceilings in config), T1a follow-up (3): nameless/targetless
  profile is `invalid_profile` (call B23).
- **Depends on:** Task 1 (`scan_error`), Task 3.
- **Files:** `crates/aitm-plugin-scanner/src/profiles.rs` (replace placeholder).
- **Change:** `pub struct Profiles { config: BTreeMap<String, ScanProfile>, saved_dir: Option<PathBuf> }`;
  `pub fn new(cfg: &ScannerConfig) -> Self` (`saved_dir = cfg.findings_dir.map(|d| scan_dir(&d, "profiles"))`);
  `pub fn list(&self) -> Vec<ProfileListEntry>` (builtins, then config, then saved; name-sorted;
  `builtin` true only for `is_builtin_name`); `pub fn get(&self, name: &str) -> anyhow::Result<ScanProfile>`
  (saved > config > builtin; else `scan: not_found: profile `<name>``);
  `pub fn save(&self, profile: &ScanProfile) -> anyhow::Result<ProfileSaveResult>` (refuses
  `invalid_profile` when: name empty, builtin name, name not matching `^[a-z0-9][a-z0-9._-]{0,63}$`,
  `validate` fails, or `saved_dir` is `None` ("`findings.dir` is not set"); writes
  `serde_yaml::to_string` to `<saved_dir>/<name>.yaml`, creating the directory);
  `pub fn delete(&self, name: &str) -> anyhow::Result<ProfileDeleteResult>` (`invalid_profile`
  for a builtin; `deleted: false` when absent);
  `pub struct StartArgs { pub profile: Option<ScanProfile>, pub profile_name: Option<String>, pub target: Option<String>, pub overrides: Option<serde_json::Value> }`;
  `pub fn resolve(&self, cfg: &ScannerConfig, args: StartArgs) -> anyhow::Result<ScanProfile>`:
  exactly one of the three selectors else `invalid_profile` ("give exactly one of `profile`,
  `profile_name`, `target`"); `target` alone → `get(&cfg.default_profile)` with
  `target.origins = [normalized origin]`; `overrides` = JSON object merged over the profile's
  JSON (objects merge recursively, scalars/arrays replace) then re-parsed as `ScanProfile`
  (a `deny_unknown_fields` error → `invalid_profile` naming the key); then `validate`.
  `pub fn normalize_origin(s: &str) -> Result<String, String>` (`http(s)://host[:port]`, no
  userinfo, path empty or `/`, lowercase host, explicit port kept, trailing slash dropped);
  `pub fn validate(p: &ScanProfile) -> Result<(), String>`: non-empty `name`; at least one
  origin or L4 target ("target has no origins and no l4 targets"); every origin normalizes;
  `lanes` non-empty; an L4 lane requires an L4 target and vice versa; every `IgnoreRule::is_valid`;
  `budget.probes >= 1`, `budget.time_s >= 1`.
  `pub fn clamp(p: &mut ScanProfile, ceilings: &Ceilings, check_timeout_ceiling_s: u64) -> Vec<Clamped>`
  for `budget.probes`, `budget.time_s`, `budget.max_issues`, `budget.check_timeout_s`,
  `l4.cases`, `l4.max_bytes_per_s`, `ws.max_frame_bytes` (field names as those dotted strings;
  `requested`/`applied` as `u64`).
- **Test:** `target_alone_uses_the_default_profile` (`resolve(StartArgs { target: Some("http://127.0.0.1:8080/".into()), .. })`
  → `name == "standard"`, `target.origins == vec!["http://127.0.0.1:8080"]`);
  `two_selectors_is_invalid_profile` (`profile` + `target` → error text starts with
  `scan: invalid_profile:`); `empty_name_or_target_is_invalid_profile`
  (`validate(&ScanProfile::default())` is `Err` containing `name`; a named profile with empty
  target is `Err` containing `target`); `clamp_reports_each_field` (probes 50_000 vs ceiling
  20_000 → `vec![Clamped { field: "budget.probes".into(), requested: 50_000, applied: 20_000 }]`
  and the profile now holds 20_000; a profile under every ceiling → empty vec);
  `override_merges_nested_and_rejects_unknown` (`{"budget":{"probes":5}}` → `budget.probes == 5`,
  `budget.time_s == 600`; `{"budgte":{"probes":5}}` → `Err` containing `budgte`);
  `save_get_list_delete_round_trip` (temp dir: `save(my-api)` → `path` ends with
  `scan/profiles/my-api.yaml`, the file text contains the line `name: my-api`, `get("my-api")`
  equals the saved profile, `list()` has an entry `name == "my-api"` with `builtin == false`,
  `delete` → `deleted == true`, again → `false`); `builtin_name_cannot_be_saved_or_deleted`
  (`save(standard)` and `delete("standard")` → `invalid_profile`); `no_findings_dir_refuses_save`
  (`Profiles::new(&ScannerConfig::default()).save(..)` → `invalid_profile` mentioning `findings.dir`);
  `normalize_origin_shapes` (`"HTTP://Example.test:8080/"` → `"http://example.test:8080"`;
  `"http://u:p@h/"` → `Err`; `"http://h/path"` → `Err`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline profiles` passes and the full gate passes.

### Task 7: issue store: dedupe key, passive consolidation, persistence, filters and cursor

- **Satisfies:** spec D6 (issue model, dedupe key, passive consolidation, confidence never
  lowers, issue files + index), D3 (`scan.issues` filters/cursor/`by_severity`, `scan.issue`,
  `scan.issue.update`, `scan.report` `issues_md`), AC T1-7 (store half).
- **Depends on:** Task 1, Task 3.
- **Files:** `crates/aitm-plugin-scanner/src/issues.rs` (replace placeholder).
- **Change:** `pub enum DedupeInput<'a> { Http { class: &'a str, scheme: &'a str, host: &'a str, port: u16, method: &'a str, path_template: &'a str, kind: InsertionKind, name: &'a str, field_path: Option<&'a str> }, Passive { class: &'a str, scheme: &'a str, host: &'a str, port: u16 }, L4 { class: &'a str, ip: &'a str, port: u16, proto: L4Transport, grammar: Option<&'a str>, field_path: Option<&'a str>, mutation_class: Option<&'a str> } }`;
  `pub fn dedupe_key(input: &DedupeInput<'_>) -> String` (blake3 hex of the variant tag and
  every field joined by `\u{1f}`, `Option` as `-`).
  `pub struct NewIssue { pub job: JobId, pub check_id: String, pub class: String, pub name: String, pub severity: Severity, pub confidence: Confidence, pub lane: LaneKind, pub target: IssueTarget, pub location: IssueLocation, pub evidence: Evidence, pub description: String, pub remediation: Option<String>, pub passive: bool }`;
  `pub enum Upsert { Created(Issue), Merged(Issue) }`;
  `pub struct IssueStore { inner: RwLock<Inner>, dir: Option<PathBuf> }` with private
  `Inner { by_key: HashMap<String, IssueId>, issues: BTreeMap<IssueId, Issue> }`;
  `pub fn new(findings_dir: Option<&Path>) -> Self` (`dir = scan_dir(d, "issues")`);
  `pub fn load(&self) -> anyhow::Result<usize>` (reads every `*.json` except `index.json`,
  rebuilds `by_key` from `index.json` when present, else from the issues' recorded `dedupe_key`
  field which the on-disk form carries in a sibling `index.json` map `key -> id`);
  `pub fn upsert(&self, new: NewIssue, now_ms: u64) -> anyhow::Result<Upsert>` (key by
  `passive`: `Passive {..}` else `Http {..}` from `location`/`target`; new key → `Issue` with
  `util::issue_id()`, `status: Open`, `first_seen = last_seen = now`, `occurrences: 1`;
  existing → `occurrences += 1`, `last_seen = now`, `confidence = max(old, new)`, `evidence`
  replaced only when `new.confidence > old.confidence`, passive: `evidence.matched` = the
  union of the paths seen, `", "`-joined, bounded by `Evidence::excerpt`); persists the file
  and `index.json` when `dir` is `Some`;
  `pub fn get(&self, id: &str) -> Option<Issue>`;
  `pub fn update_status(&self, id: &str, status: IssueStatus, note: Option<String>) -> anyhow::Result<Issue>`
  (`scan: not_found: issue `<id>``; persists);
  `pub fn set_links(&self, id: &str, poc_ref: Option<String>, finding_id: Option<String>) -> anyhow::Result<Issue>`;
  `pub struct IssueFilter { pub job: Option<String>, pub target: Option<String>, pub severity_min: Option<Severity>, pub confidence_min: Option<Confidence>, pub class: Option<String>, pub lane: Option<LaneKind>, pub status: Option<IssueStatus>, pub since_ms: Option<u64> }` (`Default`);
  `pub const MAX_ISSUE_PAGE: usize = 1024;`
  `pub fn query(&self, f: &IssueFilter, limit: usize, cursor: Option<&str>) -> anyhow::Result<IssuesResult>`
  (order: severity desc, `first_seen` asc, `id`; `cursor` is the decimal offset of the next
  item, `next_cursor` `None` at the end; `by_severity` tallies the whole filtered set;
  `limit` capped at `MAX_ISSUE_PAGE`; a non-numeric cursor is `invalid_profile`? no:
  `scan: not_found: cursor`); `pub fn for_job(&self, job: &str) -> Vec<Issue>`;
  `pub fn count(&self) -> usize`; `pub fn render_issues_md(&self, target: Option<&str>) -> String`
  (one `## <severity> <name>` section with target/location/confidence/occurrences/evidence
  payload+matched, every string through `util::scrub`; sorted like `query`).
- **Test:** `dedupe_key_is_stable_and_ignores_check_id` (same `DedupeInput::Http` twice → equal
  keys; `name: "r"` vs `"q"` → different; two `upsert`s with `check_id` `"a"` then `"b"` on the
  same point → second is `Merged` with `occurrences == 2` and `count() == 1`);
  `confidence_never_lowers_and_higher_replaces_evidence` (`Certain` then `Tentative` → stays
  `Certain`, evidence payload unchanged; `Tentative` then `Firm` → `Firm`, evidence payload is
  the new one); `passive_consolidates_per_origin` (two `passive: true` `security-header` issues
  on `/a` and `/b` of one origin → one issue, `evidence.matched == Some("/a, /b".into())`,
  `occurrences == 2`; a third on another port → a second issue);
  `query_orders_pages_and_tallies` (three issues `High`, `Low`, `Critical`; `limit 2` → page 1
  classes in order `[critical, high]`, `next_cursor == Some("2")`, `by_severity.critical == 1`;
  page 2 → `[low]`, `next_cursor == None`, same `by_severity`); `filters_apply`
  (`severity_min: High` → 2; `status: FalsePositive` → 0 then 1 after `update_status`);
  `status_update_persists_and_reloads` (temp dir: `update_status(id, FalsePositive, Some("intended"))`
  → `<dir>/scan/issues/<id>.json` text contains `"status":"false_positive"` and
  `"note":"intended"`; a fresh `IssueStore::new(Some(dir)).load() == 1` and `get(id).status == FalsePositive`
  and an upsert of the same point after reload is `Merged`); `issues_md_lists_each_issue_once_scrubbed`
  (an issue whose `evidence.payload` is `Some("sid=s3cr3t")` → the markdown contains the
  issue name once and not `s3cr3t`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline issues` passes and the full gate passes.

### Task 8: `JobClient`: budget, pacing, per-host error ladder, timing, marks, record policy, bounded awaits

- **Satisfies:** spec D1 "Where a probe goes", D5 "Budget and pacing" and "Record policy"
  (probe side), D9.1 consumer, anti-goals "flood-shaped primitive" and "probes evicting real
  captures"; AC T1-5 (budget half), T1-9 (marks).
- **Depends on:** Task 2 (`GuardError` downcast test), Task 3.
- **Files:** `crates/aitm-plugin-scanner/src/client.rs` (replace placeholder).
- **Change:** `pub const MAX_AWAIT: Duration = Duration::from_secs(30);`
  `pub const MAX_RATE_RETRIES: u32 = 8;`
  `pub enum AwaitEnd { Timeout, Deadline, Cancelled }`;
  `pub async fn bounded_await<T>(deadline: Instant, cancel: &CancellationToken, fut: impl Future<Output = T>) -> Result<T, AwaitEnd>`
  (budget `min(deadline - now, MAX_AWAIT)`; `select!` on the future, the timeout and
  `cancel.cancelled()`);
  `pub struct JobBudget { pub budget: u64, charged: AtomicU64, pub deadline: Instant, pub cancel: CancellationToken }`
  with `pub fn new(budget: u64, deadline: Instant, cancel: CancellationToken) -> Self`,
  `pub fn charge(&self, units: u32) -> bool` (atomic compare-exchange; `false` leaves the
  counter unchanged), `pub fn left(&self) -> u32`, `pub fn spent(&self) -> u64`;
  `pub struct ProbeMeter { pub sent: AtomicU64, pub errors: AtomicU64, pub timeouts: AtomicU64, pub rate_waits: AtomicU64, ladders: Mutex<HashMap<String, Ladder>> }`
  with private `Ladder { consecutive: u32, window: VecDeque<bool> }` (50 entries),
  `pub fn record(&self, host: &str, ok: bool, rules: &PerHostErrors) -> LadderState`,
  `pub fn ladder_state(&self, host: &str) -> LadderState`; `pub enum LadderState { Ok, Tripped }`;
  `pub enum ProbeRefused { Budget, Deadline, Cancelled, HostLadder(String), Guard(GuardError) }`
  (`Display` + `Error`; the text names the reason);
  `pub struct JobClient { inner: Arc<dyn ProxyClient>, job_id: String, budget: Arc<JobBudget>, meter: Arc<ProbeMeter>, record: RecordPolicy, version: VersionPolicy, per_host: PerHostErrors }`
  with `pub fn new(inner, job_id: &str, budget: Arc<JobBudget>, meter: Arc<ProbeMeter>, record: RecordProbes, version: HttpVersionPolicy, per_host: PerHostErrors) -> Self`,
  `pub fn budget(&self) -> &Arc<JobBudget>`, `pub fn meter(&self) -> &Arc<ProbeMeter>`.
  `impl ProxyClient for JobClient`: `send(req)` = `send_opts(req, SendOptions::default())`;
  `send_opts(req, opts)`: refuse when the host ladder is tripped; `charge(1)` or
  `ProbeRefused::Budget`; marks = `["scan:<job>"]` + `opts.marks` (deduped);
  `record = Always` iff the job's policy is `all` **or** `opts.record == Always` (the issue
  re-recording path), else `Never`; `version` = `opts.version` unless `Auto`, then the job's;
  loop up to `MAX_RATE_RETRIES`: `bounded_await(inner.send_opts(req.clone(), opts'))`; on
  `Err` whose `downcast_ref::<GuardError>()` is `RateLimited { retry_after }` → `rate_waits += 1`,
  `bounded_await(sleep(min(retry_after, MAX_AWAIT)))`, retry; `HostDisabled` → ladder record
  `false` and return `HostLadder`; other `Err` → `errors += 1`, ladder `false`, return the
  error; `AwaitEnd::Timeout` → `timeouts += 1`, `errors += 1`, ladder `false`; `Deadline`/`Cancelled`
  → the matching `ProbeRefused`. On `Ok(flow)`: `sent += 1`, `flow.metadata.duration = Some(elapsed)`
  (the sender leaves it `None`), ladder `status < 500`, return.
- **Test** (a stub `ProxyClient` with a programmable queue of outcomes `Ok(status) | Err(GuardError) | Err(other) | Sleep(d)`
  that records every `SendOptions` it was handed; `req_to("ex.test")` helper):
  `charges_one_unit_per_send_and_stops_at_budget` (budget 2 → two `Ok`, third `Err` whose
  text contains `budget`, stub calls `== 2`, `budget.left() == 0`);
  `marks_and_record_policy_reach_the_inner_client` (job `scan-1a2b3c4d`, policy `IssuesOnly`
  → the stub saw `marks == ["scan:scan-1a2b3c4d"]`, `record == RecordPolicy::Never`; with
  `opts.marks = ["issue:issue-9f8e7d6c"]` and `opts.record = Always` → stub saw both marks and
  `Always`; policy `All` → `Always` even with default opts);
  `rate_limited_waits_then_retries` (`Err(RateLimited { 10 ms })` then `Ok(200)` → `Ok`,
  `meter.rate_waits == 1`, stub calls `== 2`, `meter.sent == 1`);
  `host_ladder_trips_on_consecutive_5xx` (`PerHostErrors { consecutive: 3, ratio: 0.5 }`; three
  `Ok(500)` → `ladder_state("ex.test") == Tripped`; the fourth send is `Err` containing `ladder`
  and stub calls stay `3`); `ratio_rule_trips_too` (`consecutive: 100`, `ratio: 0.5`; 10 sends
  alternating `Ok(200)`/`Ok(500)` then 1 more `500` → tripped);
  `cancel_ends_a_pending_send_within_the_bound` (stub `Sleep(10 s)`; cancel after 50 ms → `Err`
  containing `cancelled` within 1 s); `deadline_bounds_the_await` (deadline `now + 100 ms`,
  stub `Sleep(10 s)` → `Err` containing `deadline` within 1 s, `meter.timeouts == 0`);
  `elapsed_is_recorded_on_the_flow` (`Sleep(15 ms)` then `Ok(200)` → `metadata.duration >= 15 ms`);
  `version_override_wins_over_the_job_policy` (job `H1`, `opts.version = H2` → stub saw `H2`;
  default opts → `H1`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline client` passes and the full gate passes.

### Task 9: session reuse: observed pick, header merge, GET/HEAD canary

- **Satisfies:** spec D7 (observed-session mode, `SessionMaterial` only in worker memory,
  header merge, canary GET/HEAD-only every 25 probes, `on_lost`), D3 `scan.session.preview`
  (names only), anti-goal "no result carries a cookie"; Architect's call 25 (spec).
- **Depends on:** Task 3.
- **Files:** `crates/aitm-plugin-scanner/src/session.rs` (replace placeholder).
- **Change:** `pub struct ObservedSession { pub material: SessionMaterial, pub profile: SessionProfile, pub canary_flow: Option<HttpFlow> }`;
  `pub fn pick_observed(store: &dyn FlowStore, origin: &str, from_flow: Option<FlowId>) -> Option<ObservedSession>`
  (candidates: `Flow::Http` with `metadata.is_replay == false` whose `scheme://authority`
  equals the normalized origin and which carry a `Cookie` header or any header whose name
  passes `crate::discover::is_secret_name`; newest by `metadata.created`; `from_flow` wins when
  it exists and matches; `material.cookies` = the `Cookie` pairs, `material.headers` = the
  secret-named headers; `profile` = `material.names(origin, Some(flow), observed_at_ms, canary)`;
  canary = `from_flow` when it is `GET`/`HEAD`, else the newest `GET`/`HEAD` candidate carrying
  the same material → `Canary::Flow { method, path, expected_status: response status }`, else
  `Canary::None`); `pub fn apply(material: &SessionMaterial, req: &mut HttpRequest)` (each
  session header set only when the request lacks that name; cookies merged by name, request's
  own cookies win, re-serialized `a=b; c=d`); `pub const CANARY_EVERY: u32 = 25;`
  `pub struct CanaryRunner { template: HttpRequest, expected_class: u16, counter: AtomicU32 }`
  with `pub fn new(flow: &HttpFlow) -> Option<Self>` (`None` unless `GET`/`HEAD`; body dropped),
  `pub fn due(&self) -> bool` (true on every 25th call), `pub async fn check(&self, client: &dyn ProxyClient) -> anyhow::Result<CanaryOutcome>`
  (sends the template via `send_opts` with `record: Never`, marks `["canary"]`; the job's
  client adds `scan:<job>`); `pub enum CanaryOutcome { Alive, Lost { status: u16 } }`
  (`Lost` when the expected class was 2 and the reply is 3xx, 401 or 403).
- **Test:** `picks_newest_captured_flow_with_a_cookie` (`MemFlowStore`: a replay flow (newer)
  with `Cookie: sid=zzz`, a captured flow with `Cookie: sid=abc; theme=dark`, a captured flow
  without cookies → the picked `profile.source_flow` is the cookie-carrying captured one,
  `profile.cookies == ["sid", "theme"]`, `profile.headers.is_empty()`, and
  `serde_json::to_string(&profile)` contains neither `abc` nor `dark`);
  `secret_header_counts_as_material` (`Authorization: Bearer t0k` → `profile.headers == ["authorization"]`);
  `apply_merges_cookies_by_name_probe_wins` (request `Cookie: sid=probe; x=1`, material
  `sid=abc, t=2` → header `== "sid=probe; x=1; t=2"`; request without `Authorization` gains it,
  with it keeps its own); `canary_requires_get_or_head` (`from_flow` is a POST carrying the
  cookie and a GET `/account` 200 exists → `canary == Canary::Flow { method: Get, path: "/account", expected_status: Some(200) }`;
  with only POSTs → `Canary::None`); `canary_due_every_25` (24 `false` then `true`, then 24
  `false`); `canary_lost_on_class_change` (stub client answering 302 → `Lost { status: 302 }`;
  answering 200 → `Alive`; the stub saw `record == Never` and a body-less request).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline session` passes and the full gate passes.

### Task 10: catalogue assembly, selectors, scheduler

- **Satisfies:** spec D4 "Native checks ... Rhai checks ... one unified catalogue",
  "Scheduling" (selection rules, priority `0.8 x exposure + 0.2 x interest`, passive then
  active, light before medium, frequent-point rule, `wants_traits`), D2 `Speed`/`Accuracy`
  mappings, D3 `scan.checks` filters and `unknown_check`; research 17 §3.2.
- **Depends on:** Task 1, Task 3.
- **Files:** `crates/aitm-plugin-scanner/src/catalogue.rs`, `crates/aitm-plugin-scanner/src/scheduler.rs`
  (replace placeholders).
- **Change (`catalogue.rs`):** `pub struct Catalogue { entries: Vec<Arc<dyn Check>> }`;
  `pub fn assemble(lanes: &[Arc<dyn Lane>], native: &[Arc<dyn Check>], scripts: &CheckRegistry) -> Catalogue`
  (lanes' `checks()` in order, then `native`, then `scripts.snapshot()`; a repeated id: the
  later entry wins with `tracing::warn!`; sorted by id); `pub fn metas(&self) -> Vec<CheckMeta>`;
  `pub fn get(&self, id: &str) -> Option<Arc<dyn Check>>`; `pub fn all(&self) -> &[Arc<dyn Check>]`;
  `pub fn filter(&self, lane: Option<LaneKind>, class: Option<&str>, origin: Option<&str>) -> Vec<CheckMeta>`
  (origin token `native | bundled | custom`); `pub enum Selector { Id(String), Class(String), Lane(LaneKind) }`
  with `pub fn parse(s: &str) -> Selector` (`lane:<token>` → `Lane`, else `Id`/`Class` decided
  against the catalogue at validation); `pub fn validate_selection(&self, sel: &CheckSelection) -> anyhow::Result<()>`
  (every include/exclude entry must name a known id, a known class, or a valid `lane:` token;
  else `scan: unknown_check: <entry>`); `pub fn selected(&self, sel: &CheckSelection) -> Vec<Arc<dyn Check>>`
  (empty include = all; excludes applied after).
- **Change (`scheduler.rs`):** `pub struct ScheduleItem { pub point: usize, pub check: Arc<dyn Check>, pub priority: f32 }`;
  `pub struct SchedulePlan { pub passive: Vec<ScheduleItem>, pub active: Vec<ScheduleItem>, pub skipped: SkippedPoints, pub frequent: HashSet<(InsertionKind, String)> }`;
  `pub fn interest(method: Option<&str>, content_type: Option<&str>, authenticated: bool) -> f32`
  (`POST|PUT|PATCH|DELETE` 0.6 else 0.3; `html|json|xml` content type +0.3; authenticated +0.1;
  clamped to 1.0); `pub fn exposure(new_points: u32, max_new_points: u32) -> f32` (ratio, 0 when max is 0);
  `pub fn priority(exposure: f32, interest: f32) -> f32` (`0.8 * exposure + 0.2 * interest`);
  `pub fn plan(points: &[InsertionPoint], nodes: &[SiteNode], checks: &[Arc<dyn Check>], profile: &ScanProfile) -> SchedulePlan`
  with these rules per (point, check): lane in `meta.lanes`; kind in `meta.kinds` and in
  `profile.audit.kinds`; `meta.intensity <= profile.intensity`; a point carrying `Session`
  is skipped unless `meta.targets_session` (counted once per point in `skipped.ignored`);
  `profile.audit.ignore` rules (all present keys match → skipped, `skipped.ignored`);
  `meta.wants_traits` must intersect the point's traits unless `profile.speed == Thorough`;
  `(kind, name)` with `frequency > profile.audit.frequent_point_threshold` admits `cost: Light`
  only (`skipped.frequent` += 1 per dropped item, the pair recorded in `frequent`);
  `meta.scope`: `Point` → one item per (point, check); `Node` → one item per (site node,
  check), attached to the node's first admissible point; `Origin` → one item per (origin =
  scheme://host:port, check), attached to the origin's first admissible point;
  `technique == Passive` → `passive` list; else `active`. `active` ordered by `cost`
  (`Light`, `Medium`, `Heavy`) then `priority` desc then point index; `passive` by point index.
  Exposure = the node's `points` count relative to the max over nodes; interest from the
  point's `method`, the node's content type (unknown → none) and `node.auth`.
  `pub fn payload_cap(speed: Speed, technique: Technique) -> u32` (`Boolean`: 2/4/8;
  `Timing`: 2/3/5; everything else: 8/25/`u32::MAX`); `pub fn repeats(accuracy: Accuracy) -> u32` (1/2/3).
- **Test:** `priority_formula_matches_research_17` (`(priority(1.0, 0.5) - 0.9).abs() < 1e-6`;
  `interest(Some("POST"), Some("application/json"), true) == 1.0`, `interest(Some("GET"), None, false) == 0.3`);
  `plan_filters_by_lane_kind_and_intensity` (checks: `http/query/light`, `ws/ws_text/light`,
  `http/query/intrusive`; one http query point; profile `medium` → `active` has exactly the
  first check); `light_before_medium_across_points` (points p0, p1; checks `L` (light cost) and
  `M` (medium cost), equal priority → `active` ids `[L@0, L@1, M@0, M@1]`);
  `frequent_point_gets_light_only` (point `frequency: 9`, threshold 8 → `M` dropped,
  `skipped.frequent == 1`, `frequent` contains `(Query, "q")`); `wants_traits_respected_unless_thorough`
  (`wants_traits: Some([Url])` vs a trait-less point → dropped at `Normal`, kept at `Thorough`);
  `session_trait_is_ignored_by_default` (point with `traits: [Session]` → nothing scheduled,
  `skipped.ignored == 1`; with `audit.ignore` emptied and `targets_session: true` → scheduled);
  `passive_items_come_first_and_separately` (a `Passive` check and a `Reflected` check → one in
  `passive`, one in `active`); `origin_and_node_scoped_checks_run_once`
  (three points on one origin across two nodes: a `scope: Origin` check yields exactly 1 item,
  a `scope: Node` check exactly 2, a `scope: Point` check 3; two origins → the origin-scoped
  check yields 2); `selectors_validate_against_the_catalogue`
  (`validate_selection(include ["lane:http", "reflected-xss", "none"])` is `Ok` with those
  ids/classes present; include `["nope"]` → `Err` text `== "scan: unknown_check: nope"`);
  `catalogue_dedupes_by_id_later_wins` (`native` and `scripts` both carry `x` → one entry, the
  script's description); `caps_and_repeats` (`payload_cap(Fast, Boolean) == 2`,
  `payload_cap(Thorough, Timing) == 5`, `payload_cap(Normal, Reflected) == 25`,
  `repeats(FewerFalsePositives) == 3`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline -- catalogue scheduler` passes and the full gate passes.

### Task 11: PoC-hint reproduction and the `FindingRecord` link

- **Satisfies:** spec D6 "Issue vs finding" (`PocHint` → `StdPocBuilder` → scrub →
  `StdPocRunner` once per issue → `record_finding` only on `reproduction.passed`, `finding_id`
  link), Architect's calls 8 and 23 (spec); AC T1-10 (engine half).
- **Depends on:** Task 7, Task 8.
- **Files:** `crates/aitm-plugin-scanner/src/reproduce_link.rs` (replace placeholder),
  `crates/aitm-plugin-scanner/src/reproduce.rs` (modify: expose
  `pub(crate) fn scrub_poc(poc: &mut Poc, request: &HttpRequest, payload: &str)` built on the
  existing private `Scrubber`, and keep `record_finding` as is).
- **Change:** `pub struct ReproductionInput<'a> { pub issue: &'a Issue, pub hint: &'a PocHint, pub probe_flow: &'a HttpFlow, pub payload: &'a str, pub meta: &'a CheckMeta, pub started_by: &'a StartedBy }`;
  `pub struct Reproduced { pub poc_ref: String, pub finding_id: Option<String>, pub passed: bool, pub control_passed: Option<bool> }`;
  `pub async fn reproduce_and_record(input: ReproductionInput<'_>, host: &CommandHost<'_>, out_dir: Option<&Path>) -> anyhow::Result<Reproduced>`:
  `PocSpec { info: PocInfo { name: issue.name, severity: issue.severity, tags: [class, "scan", job], cwe: meta.cwe.map(|c| format!("CWE-{c}")), description: Some(meta.description), .. }, variables: vec![target variable as `build_poc` declares it], success: Assertion::All(hint.assertions.clone()) }`
  → `StdPocBuilder.build(probe_flow, spec)` → `reproduce::scrub_poc(&mut poc, &probe_flow.request, payload)`
  → `StdPocRunner::with_output_dir(out_dir or std::env::temp_dir())` `.run(&poc, bindings, host)`
  **exactly once**; when `hint.control` is `Some`, a second PoC is built from a copy of the
  probe flow whose request path/body has `payload` textually replaced by `control.payload`
  (when the payload text is not present the control is skipped, `control_passed: None`),
  `success: Assertion::All(control.expect)`, run once → `control_passed = Some(result.passed)`.
  When `passed`, `reproduce::record_finding(host, FindingRecord { id: String::new() (the store
  assigns), title: issue.name, class: issue.class, severity, target: "<scheme>://<host>:<port><path>", discovered_at: now, origin: Frontend from started_by.frontend, client_label, poc_ref: run.poc_path string, reproduction: Reproduction { passed: true, control_passed, run_at: now }, artifacts: FindingArtifacts { finding_capture: run.finding_capture, poc_path, screenshot_path }, flows: evidence probe flows, notes: Some(detail) })`
  → `finding_id: Some(id)`; a failed reproduction or `record_finding` error (for example no
  `findings.dir`) yields `finding_id: None` with the reason in a `tracing::warn!`; the PoC runs
  through `host.client()` so the job's budget and marks apply.
- **Test** (temp findings dir; `CommandHost` built from `MemFlowStore`, `StdGuard` with the
  target host in scope, a stub `ProxyClient` and `Config { findings: FindingsConfig { dir: Some(dir) }, .. }`):
  `vulnerable_with_hint_records_a_finding_when_reproduction_passes` (hint
  `assertions: [Assertion::word("AITMMARK")]`, stub body contains `AITMMARK` → `passed`,
  `finding_id.is_some()`, exactly one `*.yaml` under the findings dir, `poc_ref` ends with
  `.yaml`); `failed_reproduction_records_nothing` (stub body `"clean"` → `passed == false`,
  `finding_id == None`, no file); `control_runs_once_when_given` (hint with
  `control: Some(ControlHint { payload: "benign", expect: [Assertion::Status(200)] })` → stub
  call count `== 2`, `control_passed == Some(true)`); `poc_text_is_scrubbed` (probe request
  carries `Cookie: sid=s3cr3t` and the payload → the written PoC YAML does not contain `s3cr3t`
  and does contain `{{target}}`); `no_findings_dir_yields_an_issue_only` (`Config::default()`
  → `Ok(Reproduced { finding_id: None, .. })`, not `Err`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline reproduce_link` passes and the full gate passes.

### Task 12: the interim HTTP lane over the legacy modules

- **Satisfies:** spec D1 "Interim HTTP lane (T1b)" (browser crawl, v1 points, two native
  payload classes as `Check`s with `CheckMeta` **and** `PocHint`, three passive checks), D5
  "Record policy" (crawl flows marked `scan:<job>` + `crawl` by a bounded store diff; probe
  flows held in memory, <= 16 per point), D8.1 redaction rule for `example`; ACs T1-9, T1-10
  (lane half).
- **Depends on:** Task 8, Task 9, Task 10 (`payload_cap`).
- **Files:** `crates/aitm-plugin-scanner/src/interim_lane.rs` (replace placeholder).
- **Change:** `pub struct InterimHttpLane { cfg: ScannerConfig }` with `pub fn new(cfg: ScannerConfig) -> Arc<dyn Lane>`.
  `impl Lane`: `lane() == LaneKind::Http`.
  `discover(target, job)`: for every origin in `target.origins`: when `job.profile().crawl.max_pages > 0`,
  `use_browser != Never` and `job.browser().is_some()`: build a `CommandHost` from the job's
  handles (`CommandHost::new(&*store, &*client, &*guard, browser.as_deref())`), snapshot
  `before = store.list()`, run the legacy `crate::crawl::crawl(&host, origin, &cfg')` where
  `cfg'` carries the profile's `max_depth`/`max_pages`/`time_s`, then every id in
  `store.list()` not in `before` is marked via `store.update(id, |f| { marks += "scan:<job>", "crawl" })`
  (bounded to the ids the diff produced) and `job.charge(pages_crawled)` is called. Then
  from every `Flow::Http` in the store whose request is to the origin and is **not** a replay
  (plus the crawl captures): `crate::discover::enumerate(&flow)` → `InsertionPoint { id: "<flow>:<kind>:<name>", lane: Http, kind: map(location), name, path: None, example: Some(util::scrub(example)), flow: Some(FlowRef(flow.id)), site_node: Some(node.id), traits, frequency, method: Some(method), url: Some(scheme://authority + path) }`
  with `map`: `Query→Query`, `BodyParam→BodyParam`, `Header→Header`, `Cookie→Cookie`,
  `PathSegment→PathSegment`, `Redirect→Query` **plus** `PointTrait::Url`; traits also gain
  `Session` when `discover::is_secret_name(&name)` or the kind is `Cookie` and the name is
  secret, `Number` when the example parses as an integer, `Email` on an `@`. `frequency` =
  number of distinct nodes carrying the same `(kind, name)`. Nodes: one `SiteNode` per
  `(method, scheme, host, port, path_template)` where `path_template` replaces purely numeric
  segments with `{id}`; `flows`, `params`, `points`, `auth` (= the flow carries `Cookie` or
  `Authorization`), `audited: false`. `Discovery { points, nodes }`.
  `probe_host_for(point, job)`: fetches the point's flow from `job.store()` (`Err` when
  missing) → `Box::new(InterimProbeHost { point, flow, legacy: InjectionPoint, job, baseline: OnceCell<ProbeResponse>, held: Mutex<Vec<Flow>>, shared: Weak<..> })`.
  `pub struct InterimProbeHost` implements `ProbeHost`: `probe(payload)`: value by
  `payload.mode` (`Replace` = value; `Prefix`/`Suffix` = value + example / example + value),
  `crate::inject::mutate_request(&flow.request, &legacy, &value)` (`Err` when `None`),
  `session::apply` when `job.session()` is `Some`, `job.client().send_opts(req, SendOptions { record: Never, marks: vec![], version: profile.http.version.into() })`,
  push the flow into `held` (drop the oldest beyond 16), return
  `ProbeResponse { status: Some(resp.status), headers, body (<= MAX_MATCH_BODY), elapsed_ms: metadata.duration ms, flow: Some(id), ws_frames: None, l4: None }`;
  `baseline()`: the unmodified request sent once, cached; `probe_raw(req)`: refused unless
  `req.url`'s origin equals the point's ("probe.raw is same-origin only"), else sent like a
  probe; `marker()`: `job.marker()`; `budget_left()`, `deadline()`, `cancelled()`, `profile()`
  from the job; `held_flows()`; `client()` → `Some(job.client())`; `captured()` → `Some(flow.clone())`;
  `shared()` → `None` here (the engine wraps hosts, Task 14).
  Checks (`checks()` returns all five, in this order):
  `pub struct LegacyActiveCheck { def: CheckDefinition, meta: CheckMeta }` for
  `reflected-xss` (`kinds: [Query, BodyParam]`, `Light`, `cost: Medium`, `Reflected`,
  `Severity::Medium`, `Certain`, `cwe: Some(79)`) and `open-redirect` (`kinds: [Query]`,
  `wants_traits: Some([Url])`, `Light`, `cost: Light`, `Reflected`, `Severity::Low`, `Certain`,
  `cwe: Some(601)`), both `origin: Native`, `id == class`, `description` one sentence,
  `remediation: Some(..)`. `run(point, host)`: for each payload up to
  `payload_cap(profile.speed, Reflected)`: `host.probe(&Payload { value, mode: Replace, bytes: None })`;
  `def.confirm(status, &body_text, &headers, &payload)` → `Some(evidence)` ⇒
  `Verdict { outcome: Vulnerable, confidence: Certain, evidence: Evidence { payload: Some(value), matched: Some(Evidence::excerpt(&util::scrub(&evidence.matched))), probe_flows: [flow], baseline_flow: None, .. }, detail, poc_hint: Some(PocHint { assertions: vec![def.success_assertion(&payload)], control: None }) }`
  and stop; a probe `Err` whose text names the budget/deadline/cancel → `Inconclusive`;
  otherwise `Clean` (`Tentative`). `pub struct LegacyPassiveCheck { class: &'static str, meta: CheckMeta }`
  for `reflection` (`Tentative`, `Low`), `security-header` (`Firm`, `Low`), `cookie-flag`
  (`Firm`, `Low`): `technique: Passive`, `intensity: Passive`, `kinds: InsertionKind::ALL` of
  the HTTP kinds, `cost: Light`; `run`: `host.captured()` (never a send) → `passive_checks(&flow)`
  filtered by class → first hit ⇒ `Vulnerable` with `evidence.matched = Some(request path)`,
  `probe_flows: [flow]`; none ⇒ `Clean`; `captured() == None` ⇒ `Inconclusive`.
- **Test** (`MemFlowStore` seeded with captured flows, a stub `ProxyClient`, a local
  `TestJob: JobCtx` wrapping them; `aitm_scan_model::testing` for metas):
  `discover_maps_v1_points_to_v2_kinds` (captured `GET /search?q=1&next=http://x/` and
  `GET /account/42` → a point `kind: Query, name: "q"` without `Url`, a point `name: "next"`
  with `traits` containing `Url`, nodes with `path_template` `"/search"` and `"/account/{id}"`,
  `frequency` of `("q")` `== 1`); `discover_marks_crawl_flows_and_charges` (a stub
  `BrowserDriver` whose `navigate` inserts one captured flow into the store → that flow's marks
  `== ["scan:scan-1a2b3c4d", "crawl"]`, an older pre-existing flow unmarked, `TestJob.charged() >= 1`);
  `discover_without_browser_uses_captured_flows_only` (no browser → points from the store,
  `charged() == 0`); `reflected_xss_supplies_a_poc_hint` (stub echoes the request's `q` into
  the body with `text/html` → `Vulnerable`, `confidence == Certain`, `poc_hint.is_some()`,
  `evidence.probe_flows.len() == 1`, `host.held_flows().len() >= 1`, the stub saw
  `record == Never`); `open_redirect_wants_url_and_confirms_on_location` (stub answers 302 with
  `Location` = the payload → `Vulnerable`); `clean_target_yields_clean`; `probe_raw_refuses_other_origin`
  (`Err` text contains `same-origin`); `passive_check_reads_the_captured_flow_without_sending`
  (https captured flow without `Strict-Transport-Security` → `security-header` `Vulnerable`,
  stub call count `== 0`); `held_flows_are_bounded_to_16` (20 probes → `held_flows().len() == 16`);
  `session_material_is_applied_to_probes` (`TestJob.session = Some(material sid=abc)` → the stub
  saw `Cookie` containing `sid=abc`; the returned `ProbeResponse` debug text does not contain `abc`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline interim_lane` passes, the legacy
  module tests still pass unchanged, and the full gate passes.

### Task 13: Rhai `reg.add_check` bridge, `ScriptCheck`, `probe.*` host functions

- **Satisfies:** spec D4 "Rhai checks" (meta map with `CheckMeta` wire keys, closure over the
  `point` map, verdict map or plain string → `inconclusive`, `poc_hint.matchers` in the PoC
  vocabulary, missing/invalid meta is a load error naming the key), D4 "Probe host functions",
  D9.3 (a) and (b), Rhai human-readability constraint; ACs T1-6 (custom `add_check` script,
  `kinds` error), T3-5 compatibility (old-style `add_command` scripts keep working).
- **Depends on:** Task 1 (`CheckRegistry`, `ProbeHost::shared/client`), Task 4 only (wave 2:
  T3's converted scripts compile against this bridge, so it lands independent of the engine's
  job/worker tasks).
- **Files:** `docs/design/languages/rhai.api.json` (modify: the `probe` namespace entries and
  the `http.send` signature gaining `elapsed_ms`; the one in-track edit of an integration-shared
  file, call B30), `crates/aitm-plugin-rhai/src/check_bridge.rs`, `crates/aitm-plugin-rhai/src/host_probe.rs`
  (replace placeholders), `crates/aitm-plugin-rhai/src/command.rs` (modify: `RegCollector`
  gains `checks: Vec<(rhai::Map, FnPtr)>`, `register_reg_api` gains `add_check`,
  `ScriptRegHandle` gains `with_checks(Arc<CheckRegistry>, origin: CheckOrigin)` and
  `run_load` converts collected checks), `crates/aitm-plugin-rhai/src/loader.rs` (modify:
  `checks: Arc<CheckRegistry>` field created in `new_with_languages`, `pub fn checks(&self) -> Arc<CheckRegistry>`,
  `ProbeCapability` added to the capability list), `crates/aitm-plugin-rhai/src/plugin.rs`
  (modify: `LoadedScript` carries the registry handle and its `CheckOrigin`; `run_load` calls
  `replace_source(script_name, ..)` so a reload swaps that script's checks),
  `crates/aitm-plugin-rhai/src/wire.rs` (modify: `ScriptTier.checks: Arc<CheckRegistry>` from the loader),
  `crates/aitm-plugin-rhai/src/lib.rs` (modify: re-exports `check_bridge::{ScriptCheck, meta_from_map, verdict_from_dynamic, poc_hint_from_map}`,
  `host_probe::{ProbeCapability, timing_fit, levenshtein_ratio, TimingFit}`),
  `crates/aitm-plugin-rhai/tests/check_bridge.rs` (create).
- **Change (`check_bridge.rs`):** `pub struct ScriptCheck { meta: CheckMeta, engine: Arc<Engine>, ast: Arc<AST>, func: FnPtr, options: Options, budget: Budget, script: String }`;
  `impl Check`: `meta()`; `run(point, host)` → `Box::pin(async move { ... })` whose body is
  synchronous inside `blocking(|| ..)`: `let Some(shared) = host.shared() else { return Verdict error "the engine must hand a shared probe host" }`;
  `let _run = begin_run(RunKind::Check, Budget::for_check(self.budget, Duration::from_secs(host.profile().budget.check_timeout_s)))`;
  `let _seed = seed_call_context(CallerTrust::Agent, Some(tag), source)`;
  `let _ctx = host_probe::enter(CheckCtx { host: shared, point: point.clone() })`;
  the call is wrapped in `with_client(client, || ...)` when `host.client()` is `Some`;
  `engine.call_fn_with_options(.., self.func.fn_name(), (point_map(point),))` where
  `point_map` has exactly the D4 keys `kind, name, path, url, method, example, traits`;
  result → `verdict_from_dynamic(&Dynamic) -> Verdict` (a map: `outcome` token (missing or
  unknown → `Error` with detail naming it), `confidence` token (default `Tentative`),
  `evidence: #{ payload, matched }` (matched bounded by `Evidence::excerpt`), `detail`
  (default `""`), `poc_hint` via `poc_hint_from_map`; a string → `Inconclusive` with the
  string as `detail`; anything else → `Error`); an eval error → `Verdict { outcome: Error, detail: ScriptError::from_eval(..).to_string() }`.
  `pub fn meta_from_map(map: &rhai::Map, origin: CheckOrigin) -> Result<CheckMeta, (String, String)>`:
  `Map` → `serde_json::Value` (via `dynamic_to_value` and a local `value_to_json`), `origin`
  inserted as `{"kind": ..}` by the bridge (a script-supplied `origin` is an error on key
  `origin`), `serde_json::from_value::<CheckMeta>`; a serde error is mapped to the offending
  key: `missing field `k`` → `k`; `unknown variant` / `invalid type` → the key named in the
  path (the coder walks the map's keys for the first that fails to parse into its field's type).
  Optional keys: `wants_traits`, `cwe`, `remediation`, `needs_baseline`, `targets_session`,
  `scope` (default `point`). The check's `id` is the script's declared `id` verbatim (T3
  keeps the shipped verb names by declaring `id: "sqli"` → manual verb `check.sqli`).
  `pub fn poc_hint_from_map(map: &rhai::Map) -> Result<PocHint, String>`: `matchers` (array,
  the PoC loader's matcher vocabulary: each item a map with `type: status|word|regex|dsl`
  and its payload, or `all`/`any`/`not`) → `serde_yaml::from_value::<Assertion>` of the
  **list** (which `aitm_poc` parses as `Assertion::All(items)`); `control: #{ payload, matchers }`
  → `ControlHint { payload, expect: vec![that assertion] }`.
- **Change (`host_probe.rs`):** `pub struct CheckCtx { pub host: Arc<dyn ProbeHost>, pub point: InsertionPoint }`;
  `thread_local! CHECK_CTX: RefCell<Option<CheckCtx>>`; `pub fn enter(ctx: CheckCtx) -> CheckCtxGuard`
  (restores the previous on drop); `pub struct ProbeCapability;` `impl ScriptCapability`:
  namespace `probe`, `min_api "1"`, registers `send(payload: &str) -> Map`, `baseline() -> Map`,
  `raw(req: Map) -> Map`, `marker() -> String`, `budget_left() -> INT`, `timing_fit(input: Map) -> Map`
  (`#{ correlated, slope, r }`), `levenshtein_ratio(a: &str, b: &str) -> FLOAT`; every function
  reads `CHECK_CTX` and, when absent, fails with
  ``probe.<name> is only available inside a check closure (reg.add_check); use http.send in a command``;
  `send`/`baseline`/`raw` drive the host future with `services.rt.block_on(tokio::time::timeout(probe_budget().unwrap_or(MAX_PROBE_TIMEOUT), fut))`
  and return `#{ status, headers, body, elapsed_ms, flow_id }` (`status: ()` and `flow_id: ()`
  when absent). `pub struct TimingFit { pub correlated: bool, pub slope: f32, pub r: f32 }`;
  `pub fn timing_fit(requested_s: &[f32], observed_ms: &[u32]) -> TimingFit` (least-squares
  slope of observed seconds over requested seconds, Pearson `r`; `correlated` iff
  `(1.0 - r).abs() <= 0.15 && (slope - 1.0).abs() <= 0.30` and every long-delay observation
  exceeds every short-delay observation (ZAP's alternating rule); fewer than 2 distinct
  requested values → `correlated: false`); `pub fn levenshtein_ratio(a: &str, b: &str) -> f32`
  (`1 - distance / max(len)`, `1.0` for two empty strings).
- **Test** (`tests/check_bridge.rs`, loading scripts from source the way `tests/command.rs` does;
  `aitm_scan_model::testing::RecordingHost::shared_new(200, body)` as the host; the script text
  reads as prose):
  `add_check_registers_a_script_check_with_meta` (a script declaring
  `reg.add_check(#{ id: "demo-check", name: "Demo", class: "demo", lanes: ["http"], kinds: ["query"], intensity: "light", cost: "light", technique: "reflected", severity: "low", confidence_max: "certain", description: "d" }, |point| "nothing")`
  → `loader.checks().snapshot().len() == 1`, `meta().id == "demo-check"`,
  `meta().kinds == vec![InsertionKind::Query]`, `meta().origin == CheckOrigin::Custom { path: "<source>" }`,
  `tier.checks` is the same `Arc`); `missing_kinds_is_a_load_error_naming_kinds` (the same map
  without `kinds` → `Err(ScriptError::CheckMeta { key, .. })` with `key == "kinds"` and
  `to_string()` containing `kinds`; the registry stays empty); `closure_verdict_map_round_trips`
  (closure returns `#{ outcome: "vulnerable", confidence: "certain", evidence: #{ payload: "x", matched: "y" }, detail: "d" }`
  → `verdict.outcome == Outcome::Vulnerable`, `confidence == Certain`, `evidence.payload == Some("x")`,
  `evidence.matched == Some("y")`, `detail == "d"`); `plain_string_is_inconclusive`
  (`"nothing"` → `Inconclusive`, `detail == "nothing"`, `confidence == Tentative`);
  `probe_send_reaches_the_host_and_returns_timing` (closure
  `let r = probe.send("PAY"); if r.status == 200 { "ok " + r.elapsed_ms } else { "no" }` →
  `RecordingHost.payloads() == ["PAY"]`, `detail` starts with `"ok "`); `probe_outside_a_check_is_refused`
  (a `reg.add_command` command calling `probe.marker()` → the command error text contains
  `only available inside a check`); `poc_hint_matchers_parse_the_poc_vocabulary`
  (`poc_hint: #{ matchers: [#{ type: "status", status: 200 }, #{ type: "word", word: "AITM" }] }`
  → `poc_hint == Some(PocHint { assertions: vec![Assertion::All(vec![Assertion::Status(200), Assertion::Word { word: "AITM".into(), part: MatchPart::Body }])], control: None })`);
  `timing_fit_zap_rule` (`timing_fit(&[1.0, 3.0, 1.0, 3.0], &[1050, 3100, 980, 3020])` →
  `correlated`, `r > 0.99`, `(slope - 1.0).abs() < 0.1`; `timing_fit(&[1.0, 3.0, 1.0, 3.0], &[200, 210, 190, 205])`
  → `!correlated`); `levenshtein_ratio_kitten_sitting` (`(levenshtein_ratio("kitten", "sitting") - 0.5714).abs() < 1e-3`,
  `levenshtein_ratio("", "") == 1.0`); `old_style_add_command_scripts_still_register` (load
  `scripts/bundled/active/check-sqli.rhai` from the workspace root → the registry exposes
  `check.sqli` and `loader.checks().is_empty()`); `reload_replaces_a_scripts_checks`
  (`replace_source` path: load `demo-check`, run `run_load` again with the id changed to
  `demo-check-2` → snapshot ids `["demo-check-2"]`); `scope_key_is_optional_and_parsed`
  (a meta without `scope` → `CheckScope::Point`; with `scope: "origin"` → `Origin`);
  `tests/api_catalog.rs::catalog_matches_engine_host_surface` passes with the `probe.*` entries
  added to `rhai.api.json` (quote the run).
- **Done when:** `cargo test -p aitm-plugin-rhai --offline` passes (incl. the untouched
  `tests/bundled_scripts.rs`), `cargo test -p aitm --test bundled_startup --offline` still
  passes (the fifteen `check.*` commands still register), and the full gate passes.

### Task 14: `JobRegistry`, `ScanServices`/`ScanLate`, the worker

- **Satisfies:** spec D5 (registry, owned handles bound late, start order, worker phases,
  budget and pacing, record policy re-recording, policy re-check, cancellation, persistence),
  D3 "Progress push" (coalescing <= 4/s, never for `started`/`phase`/`issue`/terminal), D1
  (engine prefers a lane crate's lane over the interim one; `lanes.skipped`), D6 (issue
  creation from verdicts, re-recording with `issue:<id>`), D7 (canary cadence, `on_lost`);
  ACs T1-1, T1-2, T1-3, T1-5, T1-7, T1-9, T1-10, T1-11 (engine halves).
- **Depends on:** Tasks 6-12 (and Task 13, already landed in wave 2, for the `ScriptCheck` impls the catalogue sees at run time).
- **Files:** `crates/aitm-plugin-scanner/src/jobs.rs`, `crates/aitm-plugin-scanner/src/worker.rs`
  (replace placeholders), `crates/aitm-plugin-scanner/src/plugin.rs` (modify: setters and
  accessors only; `load` is Task 15).
- **Change (`jobs.rs`):**
  `pub struct ScanServices { pub store: Arc<dyn FlowStore>, pub client: Arc<dyn ProxyClient>, pub guard: Arc<dyn ScopeRateGuard>, pub browser: Option<Arc<dyn BrowserDriver>>, pub egress: Option<Arc<EgressConfinement>>, pub l4: Option<Arc<aitm_proto_l4::guard::L4Guard>>, pub jobs: Arc<JobBus>, pub agent_policy: Arc<dyn Fn() -> AgentPolicy + Send + Sync>, pub rt: tokio::runtime::Handle, pub config: Arc<aitm_core::Config> }`
  (`config` carries `findings.dir` for the `CommandHost` the worker builds; the spec's
  `findings: Option<Arc<FindingStore>>` is reached through `reproduce::record_finding(host, ..)`,
  call B4). `aitm-plugin-scanner/Cargo.toml` gains `aitm-proto-l4 = { workspace = true }`
  (this task edits that manifest line; no other wave-4 task touches it).
  `pub struct ScanLate(OnceLock<ScanServices>)` with `pub fn new() -> Arc<Self>`,
  `pub fn bind(&self, services: ScanServices) -> bool`, `pub fn get(&self) -> anyhow::Result<&ScanServices>`
  (error text `scanner services are not bound; the binary binds them after the proxy is built`,
  deliberately **not** a `scan:` code: it is a wiring bug, not a caller condition),
  `pub fn is_bound(&self) -> bool`.
  `pub struct JobEntry { pub status: Arc<RwLock<JobStatus>>, pub cancel: CancellationToken, pub task: Option<JoinHandle<()>>, pub confine: Option<ConfinementToken>, pub started_by: StartedBy, pub discovery: Arc<RwLock<Discovery>>, pub origins: Vec<String>, pub is_agent: bool }`;
  `pub struct JobRegistry { inner: Mutex<HashMap<JobId, JobEntry>>, history: u32 }` with
  `pub fn new(history: u32) -> Self`, `pub fn insert(&self, entry: JobEntry)`,
  `pub fn status(&self, id: &str) -> Option<JobStatus>`, `pub fn entry_handles(&self, id: &str) -> Option<(Arc<RwLock<JobStatus>>, CancellationToken, Arc<RwLock<Discovery>>)>`,
  `pub fn list(&self, active_only: bool, limit: usize) -> Vec<JobSummary>` (newest `started_at`
  first), `pub fn cancel(&self, id: &str) -> Option<JobStatus>` (sets the token; a non-terminal
  job moves to `state: Cancelling`; idempotent), `pub fn active_count(&self) -> usize`,
  `pub fn active_origins(&self) -> HashSet<String>`, `pub fn finish(&self, id: &str)` (drops
  `confine` and `task`, prunes finished entries beyond `history`),
  `pub fn load_history(&self, dir: &Path) -> anyhow::Result<usize>` (reads `scan/jobs/*.json`
  into finished entries without tasks), `pub fn newest_for_target(&self, origin: &str) -> Option<JobId>`.
  `pub struct Engine { pub cfg: ScannerConfig, pub late: Arc<ScanLate>, pub lanes: Vec<Arc<dyn Lane>>, pub native_checks: Vec<Arc<dyn Check>>, pub script_checks: Arc<CheckRegistry>, pub interim: Arc<dyn Lane>, pub registry: JobRegistry, pub issues: Arc<IssueStore>, pub profiles: Profiles }`
  with `pub fn catalogue(&self) -> Catalogue` (assembled fresh from `lanes_for_run()`'s
  checks + `native_checks` + `script_checks.snapshot()`), `pub fn lanes_for_run(&self) -> Vec<Arc<dyn Lane>>`
  (every lane-crate lane, plus the interim lane only when no lane-crate lane has
  `LaneKind::Http`, call B2), `pub fn resolve_lanes(&self, requested: &[LaneKind]) -> (Vec<Arc<dyn Lane>>, LaneReport)`
  (`skipped` reason text `lane not available on this build`).
  `pub struct Caller { pub frontend: Frontend, pub client_label: Option<String> }` with `pub fn is_agent(&self) -> bool` (`frontend == Frontend::Mcp`).
  `pub fn map_lane_error(err: &anyhow::Error) -> LaneErrorKind` with
  `pub enum LaneErrorKind { SessionLost(String), InvalidProfile(String), Other }`: the message
  starting with the literal `scan: session_lost: ` → `SessionLost(rest)`, starting with
  `invalid_profile: ` → `InvalidProfile(rest)`, else `Other` (coordinator decision 1).
  `pub fn start(engine: &Arc<Engine>, profile: ScanProfile, caller: Caller, force_map: bool) -> anyhow::Result<StartResult>`
  in **this order** (D3/D5): (1) `force_map` → `lanes = [Http]`, `intensity = Passive`;
  `profiles::validate` → `invalid_profile`; `clamp` → `clamped`; every resolved lane's
  `lane.validate(&profile.target, &profile)` → `Err(msg)` ⇒ `scan: invalid_profile: <msg>`
  (evaluated right after step 3 has produced the `run` list, still before any spawn); (2)
  `catalogue().validate_selection(&profile.checks)` → `unknown_check`; (3) `resolve_lanes` →
  `lane_unavailable` when `run` is empty ("no requested lane is available on this build:
  <list>"); (4) scope: every origin's host via `services.guard.in_scope(host)` → `out_of_scope`;
  every L4 target via `services.l4.check(L4Action::Inject, &L4Target { interface: "*", direction: Outbound, dst, dst_port, proto })`
  when `l4` is `Some` → `out_of_scope`; (5) an L4 lane requested and (`services.l4.is_none()`
  or the caller is an agent lacking `cfg.allow_agent_l4_fuzz` **or** `cfg.l4_allow_agent_inject`)
  → `refused_l4`; (6) agent caller and (`agent_policy() == AgentPolicy::Auto` ("the agent
  policy is `auto`; an operator can switch to `all` with agent.set") or `!cfg.allow_agent_active`
  or `profile.intensity == Intrusive`) → `refused_agent`; `scan.map` jobs (`force_map`) skip
  the `allow_agent_active`/`intrusive` checks (they send no probe) but keep the policy check;
  (7) `registry.active_count() >= cfg.max_jobs` or an origin already in `active_origins()` →
  `busy`; (8) `confine = services.egress.map(|e| e.confine())`; `JobStatus { job: util::job_id(), state: Queued, phase: Queued, profile_name, targets: origins ∪ l4 "ip:port", started_by, started_at: now_ms(), probes.budget, lanes, clamped, l4: Some(..) iff an L4 lane runs, session: Some(SessionStatus::default()) iff `session.mode == Observed` }`;
  spawn `worker::run_job(engine.clone(), ctx)` on `services.rt`; `StartResult { job, status, clamped, lanes, dry_run: Some(profile.l4.dry_run) iff an L4 lane was requested }`.
- **Change (`worker.rs`):** `pub struct JobRuntime { .. }` implementing `JobCtx` (the per-job
  surface a lane sees: `client()` is the `JobClient` as `Arc<dyn ProxyClient>`, `charge` →
  `JobBudget::charge`, `marker()` → `format!("aitm{:08x}", counter)` unique per call,
  `session()`); `pub struct ArcHost(pub Arc<dyn ProbeHost>)` implementing `ProbeHost` by
  delegation with `shared() -> Some(self.0.clone())` (the engine wraps every
  `probe_host_for` result so script checks can hold it; call B10);
  `pub struct Progress { bus: Arc<JobBus>, job: JobId, seq: AtomicU64, last_progress: Mutex<Instant> }`
  with `pub const MIN_PROGRESS_INTERVAL: Duration = Duration::from_millis(250)` (= 4/s),
  `pub fn emit(&self, event: aitm_scan_model::JobEvent, status: &JobStatus, issue: Option<IssueSummary>) -> bool`
  (`Progress` lines are dropped while the interval has not elapsed; every other event is
  always sent; `seq` increments only for sent lines; the published `BusJobEvent { job, kind: "scan", event: token, seq, payload: util::json_to_value(serde_json::to_value(JobNotification {..})) }`).
  `JobRuntime` also implements `report_l4(counters)` (folds into `JobStatus.l4` taking the
  per-field maximum so counters stay monotonic) and `report_session_lost()` (sets
  `session.lost = true`; the worker loop then applies `on_lost`: `Stop` ⇒ `Done` /
  `stopped_reason: SessionLost`, `Continue` ⇒ keeps auditing). A probe or check error that
  `map_lane_error`s to `SessionLost` is treated identically.
  `pub async fn run_job(engine: Arc<Engine>, ctx: JobStart)`: phases `Crawling` (each lane's
  `discover` under `bounded_await`; an `Err` that maps to `InvalidProfile(rest)` ⇒ `Failed`
  with `error: Some(format!("scan: invalid_profile: {rest}"))`; any other `Err` ⇒ `Failed`
  with `error: Some(text)`; `crawl.pages` from the store diff count; `points.found`,
  `discovery` stored on the entry) → `Passive` (plan's `passive` items) → `Auditing` (`active`
  items; `checks.running` holds at most 8 ids; before **each** item: cancellation → `Cancelled`
  / `stopped_reason: Cancelled`; deadline → `Done` / `Time`; budget exhausted → `Done` / `Budget`;
  agent job and `agent_policy()` is `Paused | ReadOnly` → `Cancelled` / `Policy`; ladder tripped
  for the point's host → `Done` / `Errors`; canary `due()` → `check` → `Lost` ⇒ `session.lost = true`
  and `on_lost == Stop` ⇒ `Done` / `SessionLost`; `issues.total >= budget.max_issues` ⇒ `Done` / `Budget`)
  → `Reporting` (persist) → `Done`. Each item: `lane.probe_host_for(point, job)` wrapped in
  `ArcHost`, `check.run(&point, &host)` under `bounded_await(min(remaining, check_timeout_s))`;
  verdict `Vulnerable` ⇒ `issues.upsert(NewIssue { .. from point/meta/verdict, passive: technique == Passive })`;
  on `Created`: when `profile.http.record_probes == IssuesOnly` re-record `host.held_flows()`
  into the store with marks `scan:<job>`, `issue:<id>`, `is_replay: true` (the issue's
  `evidence.probe_flows` are rewritten to the new ids); emit `Issue`; when
  `confidence >= Firm` and `verdict.poc_hint.is_some()` and the lane is HTTP:
  `reproduce_link::reproduce_and_record` once with a `CommandHost` built from the services
  (`with_config`, `with_egress`, `with_frontend`, `with_client_label`) and the `JobClient` as
  its client, then `issues.set_links`. Counters are updated under the `RwLock` and are
  **monotonic** (a helper `bump(&mut u64, n)` is the only way they change). `probes` counters
  are read from the `ProbeMeter`; `points.audited` increments per point whose last item ran.
  Terminal transition: `finished_at`, `elapsed_ms`, `state`, emit `Finished | Cancelled | Failed`,
  persist `JobStatus` + the job's issues to `scan/jobs/<job>.json`, `registry.finish(id)`.
  A panic or `Err` from a lane → `Failed` with `error: Some(text)`.
- **Test** (`worker.rs`/`jobs.rs` `#[cfg(test)]`, `#[tokio::test(flavor = "multi_thread")]`,
  using the `testing` stubs plus a local `FakeLane` whose `discover` yields two query points
  and whose `checks()` are configurable `FakeCheck`s returning scripted verdicts; a stub
  `ProxyClient`; `ScanLate` bound to in-memory services; a subscriber on the `JobBus`):
  `start_returns_queued_within_the_call_and_the_job_reaches_done` (`start(..)` returns
  `state == Queued`, `status.probes.budget == 2000`; polling `registry.status(job)` reaches
  `Done` within 5 s; `stopped_reason == None`); `lane_unavailable_only_when_every_lane_is_missing`
  (engine with only `FakeLane(Http)`: profile `[Http, Ws]` → `Ok` with
  `lanes.skipped == vec![SkippedLane { lane: Ws, reason: "lane not available on this build".into() }]`
  and `lanes.run == vec![Http]`; profile `[Ws]` → `Err` text starts with `scan: lane_unavailable:`
  and the stub client was never called); `start_checks_in_d3_order`
  (out-of-scope origin **and** an unavailable-only lane → `lane_unavailable`; out-of-scope origin
  and agent without flag → `out_of_scope`; in scope, agent, policy `Auto` → `refused_agent`;
  agent, policy `All`, flag off → `refused_agent`; agent, `All`, flag on, `Intrusive` →
  `refused_agent`; agent, `All`, flag on, `Medium` → `Ok`); `busy_on_max_jobs_and_same_origin`
  (`max_jobs: 1`: second start on another origin → `scan: busy:`; `max_jobs: 2`: second start on
  the same origin → `busy`); `cancel_moves_to_cancelled_and_keeps_issues` (a `FakeCheck` that
  blocks until cancelled; `registry.cancel(job)` → status `Cancelling` at once, then `Cancelled`
  within 2 s, `stopped_reason == Some(Cancelled)`, an issue created before the cancel is still
  in `issues.for_job(job)`, the stub client receives no call after `finished_at`);
  `budget_stops_the_job` (`budget.probes: 3`, checks that each probe twice → `stopped_reason == Some(Budget)`
  and `probes.sent <= 3`); `push_lines_are_ordered_and_coalesced` (the subscriber sees
  `started` first, `finished` last, `seq` strictly increasing, at least one `issue` line when a
  check reports `Vulnerable`, and across 50 rapid `Progress` emits in one second at most 4 are
  published while a `Phase` emit in between is always published);
  `vulnerable_verdict_creates_an_issue_and_re_records_held_flows` (profile default
  `issues_only`; `FakeCheck` returns `Vulnerable` with one held flow → store `count()` increases
  by exactly 1, that flow's marks `== ["scan:<job>", "issue:<id>"]`, `is_replay`, and
  `issues.for_job(job)[0].evidence.probe_flows == [that id]`; a `Clean` verdict adds nothing);
  `two_checks_one_class_one_issue` (two `FakeCheck`s with class `demo` on the same point →
  `issues.total == 1`, `occurrences == 2`); `agent_job_stops_when_policy_pauses` (agent-started
  job; the policy closure flips to `Paused` after the first probe → `Cancelled` / `Policy`;
  an operator-started job with the same flip reaches `Done`); `terminal_status_is_persisted_and_reloaded`
  (temp dir → `scan/jobs/<job>.json` exists; a new `JobRegistry::new(50).load_history(dir) == 1`
  and `list(false, 10)[0].job == job`); `interim_lane_is_ignored_when_a_crate_lane_exists`
  (`lanes = [FakeLane(Http)]` → `lanes_for_run()` has exactly one `Http` lane and it is the
  fake; `lanes = []` → the interim); `unbound_services_is_a_plain_error`
  (`ScanLate::new().get().unwrap_err().to_string()` contains `not bound` and does not start with `scan:`);
  `lane_validate_refuses_before_spawn` (a `FakeLane` whose `validate` returns
  `Err("plan names a pinned field `ipv4.src`")` → `start` is `Err` with text
  `== "scan: invalid_profile: plan names a pinned field `ipv4.src`"`, `registry.active_count() == 0`,
  stub client never called); `discover_invalid_profile_prefix_fails_the_job`
  (`FakeLane::discover` returns `Err(anyhow!("invalid_profile: bad seed"))` → the job reaches
  `Failed` with `error == Some("scan: invalid_profile: bad seed".into())`, `stopped_reason == Some(Failed)`);
  `report_l4_folds_into_status_monotonically` (the fake lane calls
  `job.report_l4(L4Counters { cases: 10, crashes: 1, ..Default::default() })` then
  `L4Counters { cases: 5, crashes: 1, liveness_failures: 2, ..Default::default() }` → final
  `status.l4 == Some(L4Counters { cases: 10, crashes: 1, liveness_failures: 2, retired_elements: 0 })`);
  `report_session_lost_stops_or_continues_per_on_lost` (a `FakeCheck` calling
  `job.report_session_lost()` on its first run: `on_lost: Stop` ⇒ `Done` / `SessionLost` with
  `session.lost == true` and no further probe; `on_lost: Continue` ⇒ `Done` / `None` with
  `session.lost == true` and the remaining points audited; a probe `Err("scan: session_lost: canary 302")`
  behaves like the first case).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline -- jobs worker` passes and the full gate passes.

### Task 15: every `scan.*` verb, the uniform `check.<id>` command, `ScannerPlugin::load`

- **Satisfies:** spec D3 (every verb, params, results, tiers, `confirm_prompt`, error codes),
  D4 "uniform manual `check.<id>` commands" and "Tier laundering guard", D10 (agent part), D7
  `scan.session.preview`; ACs T1-4, T1-6, T1-7, T1-8 (verb halves), T1-11.
- **Depends on:** Task 14.
- **Files:** `crates/aitm-plugin-scanner/src/verbs.rs`, `crates/aitm-plugin-scanner/src/manual_check.rs`
  (replace placeholders), `crates/aitm-plugin-scanner/src/plugin.rs` (modify: `load`).
- **Change (`verbs.rs`):** one struct per verb, each holding `Arc<Engine>`, `impl Command`
  with a `ParamSchema` whose `description` reproduces the D3 row and whose `params` are typed
  (`profile: TypeDesc::Object(vec![])`, `overrides: Map(Any)`, ids `Str`, limits `Int`,
  `active_only: Bool`); results are the model types serialized with `serde_json` then
  `util::json_to_value`; `caller(host) -> Caller` from `host.frontend()`/`host.client_label()`.
  `ScanStart` (`Sensitive`; `confirm_prompt(args)` returns
  `Some("This scan sends malformed traffic to <targets> and may disrupt the target. Continue?")`
  when the resolved profile has an L4 lane or `intensity: intrusive`, else `None`; `invoke`:
  `profiles.resolve(StartArgs from args)` then `jobs::start(.., force_map: false)`);
  `ScanMap` (`Write`; same params; `force_map: true`); `ScanStatus` (`Read`; `not_found`);
  `ScanList` (`Read`; `active_only`, `limit` default `cfg.history`); `ScanCancel` (`Write`;
  `not_found`; returns the status after `registry.cancel`); `ScanIssues` (`Read`; every D3
  filter → `IssueFilter`; `limit` default 100, capped `MAX_ISSUE_PAGE`; `severity_min`/`confidence_min`
  tokens parsed with the model's serde); `ScanIssue` (`Read`; `not_found`); `ScanIssueUpdate`
  (`Write`; `status` token must be `open | confirmed | false_positive` else `invalid_profile`
  ("status must be one of ..."), `note` optional); `ScanSitemap` (`Read`; `job` or `target` →
  `registry.newest_for_target`; `limit` default 1024 capped 4096; `points` paged by a decimal
  cursor; `nodes` always complete); `ScanChecks` (`Read`; `lane`, `class`, `origin` filters);
  `ScanProfileList`, `ScanProfileGet`, `ScanProfileSave`, `ScanProfileDelete` (`Read`/`Read`/`Write`/`Write`;
  `profile` parsed from the args object via `serde_json`); `ScanSessionPreview` (`Read`;
  `session::pick_observed(store, normalize_origin(target)?, None)` → `SessionProfile`, or the
  empty profile with `canary: Canary::None` when nothing is observed).
  `pub fn register(engine: &Arc<Engine>, reg: &mut Registry)` registers all fifteen.
- **Change (`manual_check.rs`):** `pub struct ManualCheck { engine: Arc<Engine>, check: Arc<dyn Check> }`
  with `name() == format!("check.{}", meta.id)`, `Sensitivity::Sensitive`, params
  `{ url: Str (required), param: Str (required), value?: Str }`, `schema.description` =
  `"<meta.description> Manual run of catalogue check `<id>` on one query parameter."`;
  `invoke`: the url's origin must be in scope (`out_of_scope`), a synthetic
  `InsertionPoint { kind: Query, name: param, example: value or "1", url, method: GET, lane: Http, .. }`
  on a synthetic captured `HttpFlow` inserted **only in memory** (not into the store), a
  one-shot `JobRuntime` with `budget.probes = 64`, `time_s = cfg.check_timeout_s`, the
  interim lane's `probe_host_for`, `check.run` under `bounded_await`; result = the `Verdict`
  as a `Value::Object` (`poc_hint` is skipped by serde, D2). `pub fn register_all(engine, reg)`
  adds one `ManualCheck` per catalogue entry **unless** a command of that name already exists
  in `reg` from another plugin (`reg.command(name).is_some()`), in which case it is skipped
  with a `tracing::info!` (call B8: a T3-converted script that still also calls
  `add_command("check.x")` keeps its own command).
- **Change (`plugin.rs`):** `ScannerPlugin` gains `late: Arc<ScanLate>`, `script_checks: Arc<CheckRegistry>`,
  `issues: Arc<IssueStore>` built from `cfg.findings_dir`; setters `with_script_checks(Arc<CheckRegistry>)`,
  accessors `pub fn late(&self) -> Arc<ScanLate>`; `load(reg)`: builds `Arc<Engine>` (loading
  issues and job history from disk when `findings_dir` is set), `verbs::register`,
  `manual_check::register_all`, and the legacy three via `commands::register(engine, reg)`
  (Task 16 provides it; until then the shipped `ScanDiscover::new(cfg)`/`ScanPassive`/`ScanReport`
  lines stay). `pub fn engine(&self) -> Option<Arc<Engine>>` after load (tests).
- **Test** (`verbs.rs` tests: a `Registry` loaded with a `ScannerPlugin` whose `ScanLate` is
  bound to in-memory services and a `FakeLane`; `CommandHost` with `Frontend::Operator` or
  `Frontend::Mcp`): `registry_exposes_every_d3_verb_and_the_manual_checks` (the sorted
  command names that start with `scan.` are exactly
  `["scan.cancel","scan.checks","scan.discover","scan.issue","scan.issue.update","scan.issues","scan.list","scan.map","scan.passive","scan.profile.delete","scan.profile.get","scan.profile.list","scan.profile.save","scan.report","scan.session.preview","scan.sitemap","scan.start","scan.status"]`
  (18) and the names starting with `check.` are exactly
  `["check.cookie-flag","check.open-redirect","check.reflected-xss","check.reflection","check.security-header"]`);
  `start_is_sensitive_map_is_write_status_is_read` (`sensitivity()` of the three);
  `confirm_prompt_only_for_l4_or_intrusive` (`standard` target → `None`; `l4-full` profile →
  `Some(prompt)` containing `may disrupt the target`; `intensity: intrusive` → `Some`);
  `start_returns_a_start_result_immediately` (operator; `{ target }` → `Value::Object` with
  `job` matching `^scan-[0-9a-f]{8}$`, `status.state == "queued"`, `lanes.skipped` has `ws`
  for `standard`; elapsed `< 2 s`); `agent_under_auto_is_refused_agent_map_is_not`
  (`Frontend::Mcp`, policy `Auto` → `scan.start` `Err` whose text parses to
  `(RefusedAgent, _)`; `scan.map` → `Ok`; policy `All` + `allow_agent_active: true` → `Ok`);
  `status_not_found` (`scan.status { job: "scan-00000000" }` → `scan: not_found:`);
  `issue_update_round_trips` (after a vulnerable run: `scan.issue.update { id, status: "false_positive", note: "intended" }`
  → `status == "false_positive"`, `scan.issue { id }` agrees, `scan.issues { status: "false_positive" }`
  lists one); `sitemap_pages_points` (`limit: 1` → one point, `next_cursor == Some("1")`;
  second call with that cursor → the other point, `next_cursor == None`; nodes complete both times);
  `checks_lists_the_catalogue_with_filters` (`scan.checks {}` lists the five interim metas plus
  the fake's; `{ origin: "native" }` keeps them; `{ lane: "ws" }` → empty);
  `profile_verbs_round_trip` (`scan.profile.list` has 7 builtins; `save` → `get` equals →
  `delete` → `deleted: true`; `save` of `standard` → `invalid_profile`);
  `session_preview_names_only` (a captured flow with `Cookie: sid=abc` → `cookies == ["sid"]`
  and the serialized result does not contain `abc`; no flow → `canary.kind == "none"`);
  `manual_check_runs_one_check_on_a_query_point` (`check.reflected-xss { url: "http://ex.test/search", param: "q" }`
  with a stub echoing the payload → result `outcome == "vulnerable"` and the stub saw the
  payload; the store `count()` is unchanged); `manual_check_out_of_scope` (`url` on
  `other.test` → `scan: out_of_scope:`); `scan_start_is_in_the_registry_as_sensitive_even_for_passive_only`
  (`profile_name: "passive-only"` resolves and the command's `sensitivity() == Sensitive`).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline -- verbs manual_check plugin` passes and the full gate passes.

### Task 16: the legacy verbs over the job model

- **Satisfies:** spec D3 rows `scan.discover` (deprecated; `scan.map` + wait with the shipped
  `time_budget`), `scan.passive` (unchanged), `scan.report` (unchanged plus `issues_md`);
  Non-goal "Replacing `scan.discover`/`scan.passive`/`scan.report` in v2"; Architect's call 18 (spec).
- **Depends on:** Task 14.
- **Files:** `crates/aitm-plugin-scanner/src/commands.rs` (modify).
- **Change:** `pub(crate) fn register(engine: &Arc<Engine>, reg: &mut Registry)` registering
  `ScanDiscover { engine }`, `ScanPassive`, `ScanReport { engine }`. `ScanDiscover::invoke`:
  `target` required; a map profile = `builtin("map-only")` with `target.origins = [origin]`,
  `crawl.max_depth = min(cfg.max_depth, args.max_depth)`, `crawl.max_pages = min(cfg.max_pages, args.max_pages)`,
  `budget.time_s = min(cfg.time_budget, ..)`; `jobs::start(engine, profile, caller, force_map: true)`
  (a `busy` error is rephrased to the shipped sentence
  `scan.discover is already running; wait for it to finish before starting another ...`);
  then **wait**: `services.rt.block_on(async { poll registry.status every 100 ms until terminal; after cfg.time_budget cancel and wait up to 5 s })`
  (the shipped synchronous contract; blocks only this connection, as today); the result is the
  **unchanged shape** built by `discover_value_from(&Discovery, &JobStatus, store)`:
  `endpoints` (node URLs, scrubbed, capped `MAX_RESULT_ITEMS`), `injection_points`
  (`{ flow, location, name, example }` with `location` the legacy token: `Query` with the `Url`
  trait renders as `redirect`), `endpoint_flows`, `pages_crawled` (`status.crawl.pages`),
  `stopped_reason` (`None` for `Done`, else the token or `"time_budget"` when the wait cancelled
  the job); a job that ended `Failed` with an `error` returns that error text as the verb's
  `Err` (so a lane's `invalid_profile: ..` surfaces as `scan: invalid_profile: ..`, coordinator
  decision 1). Description text gains "Deprecated: use `scan.map` and poll `scan.status`."
  `ScanReport::invoke` adds `issues_md: engine.issues.render_issues_md(target)` to the result.
  `discover_value` (the shipped helper) is kept for its tests and used by `discover_value_from`.
  The `InFlightSlot` type is removed (single flight is the job model's `busy`).
- **Test:** the shipped `commands.rs` tests stay green; new: `discover_waits_for_the_map_job_and_keeps_its_shape`
  (engine with a `FakeLane` yielding two points → the result object has exactly the keys
  `endpoints, injection_points, endpoint_flows, pages_crawled, stopped_reason`, `stopped_reason == Null`,
  `injection_points[0]` has keys `flow, location, name, example`, the `Url`-trait point renders
  `location == "redirect"`, `scan.list` afterwards shows one finished job);
  `discover_time_budget_cancels_and_reports` (`cfg.time_budget = 300 ms` and a blocking
  `FakeLane` → returns within 6 s with `stopped_reason == "time_budget"`, and `scan.status` for
  that job is `cancelled`); `discover_description_says_deprecated`;
  `discover_surfaces_a_failed_jobs_error` (`FakeLane::discover` → `Err(anyhow!("invalid_profile: bad seed"))`
  ⇒ the verb returns `Err` whose text `== "scan: invalid_profile: bad seed"`); `report_gains_issues_md`
  (after one vulnerable job: `scan.report {}` has `issues_md` containing the issue name and
  `report_md` still present).
- **Done when:** `cargo test -p aitm-plugin-scanner --offline commands` passes and the full gate passes.

### Task 17: binary wiring: `wire.rs`, `main.rs`, `tui.rs`

- **Satisfies:** spec D5 "Owned handles ... bound late in `wire.rs` (the `LateHandles`
  precedent)", D9.2 ("`wire.rs`/`main.rs`/`tui.rs` hand the one bus to every server"), D11
  ("`wire.rs` feeds it from the file instead of `ScannerConfig::default()`"), D1 (the interim
  lane is registered inside the plugin, so `collect_lanes(None).len() == 0` stays); AC T1-3
  (every server pushes), T1-4 (the flag reaches the core through the config file).
- **Depends on:** Task 5, Task 13, Task 15.
- **Files:** `crates/aitm/src/wire.rs` (modify), `crates/aitm/src/main.rs` (modify),
  `crates/aitm/src/tui.rs` (modify).
- **Change:**
  1. `wire.rs`: `Features.scanner: ScannerConfig` (`Default`); `ScriptWiring.script_checks: Option<Arc<CheckRegistry>>`;
     in `assemble_with_scripts`: `let job_bus = Arc::new(JobBus::default());` a
     `scanner_cfg = features.scanner.clone()` with `findings_dir = cfg.findings.dir.clone()` and
     `l4_allow_agent_inject = features.l4.allow_agent_inject`; the `ScannerPlugin` is built as
     `ScannerPlugin::new(scanner_cfg).with_lanes(collect_lanes(..)).with_native_checks(collect_native_checks()).with_script_checks(scripts.script_checks.clone().unwrap_or_default())`,
     `let scan_late = plugin.late();`, and its `register_plugin` line **moves** to after the
     `for commands in scripts.commands` loop (comment: "the scanner's `load` registers a
     `check.<id>` command for every Rhai `add_check`, so the script tier must have loaded
     first; the scanner registers no hooks, so chain order is unaffected"; call B7).
     `Assembled` gains `pub job_bus: Arc<JobBus>` and `pub scan_late: Arc<ScanLate>`.
  2. `tui.rs`: `Services` gains `pub jobs: Arc<JobBus>`; `services(proxy, cfg, browser, log, jobs: Arc<JobBus>) -> Services`
     gains the parameter; `server(..)` adds `.with_jobs(services.jobs.clone())` (so the agent
     server, the in-process TUI server and the web bus server all carry the bus; the
     in-process TUI connection has no sink and polls, D3 "poll is truth").
  3. `main.rs`: destructure `scanner` from `Settings`; `Features { scanner, .. }`;
     `ScriptWiring { script_checks: Some(tier.checks.clone()), .. }`; destructure `job_bus`,
     `scan_late` from `Assembled`; both call sites of `tui::services(..)` pass `job_bus.clone()`;
     right after each `handles.bind_proxy(..)` (CLI branch and server path) bind
     `scan_late.bind(ScanServices { store: s.store.clone(), client: s.client.clone(), guard: s.guard.clone(), browser (the launched driver on the server path, None on the CLI path), egress: Some(s.egress.clone()), l4: assembled l4_guard.clone(), jobs: job_bus.clone(), agent_policy: Arc::new({ let st = agent_state.clone(); move || st.policy() }), rt: tokio::runtime::Handle::current(), config: Arc::new(cfg.clone()) })`.
     Nothing else changes: `bus.spawn_push_dispatcher()` (web) and `serve()` (agent) already
     spawn the job loop (Task 5).
- **Test** (`wire.rs` tests module, sandbox-safe: `assemble` binds no port):
  `skeleton_lane_slots_are_empty_today` **unchanged** (`collect_lanes(None).len() == 0`, the
  interim lane lives in the plugin); `assembled_exposes_a_job_bus_and_an_unbound_scan_late`
  (`assemble(&cfg)` → `job_bus.receiver_count() == 0`, `scan_late.is_bound() == false`,
  `scan_late.get().unwrap_err().to_string()` contains `not bound`);
  `scan_verbs_and_manual_checks_are_registered` (the registry has `scan.start`, `scan.map`,
  `scan.status`, `scan.list`, `scan.cancel`, `scan.issues`, `scan.issue`, `scan.issue.update`,
  `scan.sitemap`, `scan.checks`, `scan.profile.list`, `scan.profile.get`, `scan.profile.save`,
  `scan.profile.delete`, `scan.session.preview`, `scan.discover`, `scan.passive`, `scan.report`,
  `check.reflected-xss`, `check.open-redirect`, `check.reflection`, `check.security-header`,
  `check.cookie-flag`); `scanner_loads_after_the_script_tier` (an `assemble_with_scripts` call
  whose `ScriptWiring.plugins` holds a test `Plugin` that pushes a `NullCheck` with id
  `wired-check` into the `script_checks` registry during its `load` → the registry has
  `check.wired-check`); `scanner_config_reaches_the_plugin` (`Features { scanner: ScannerConfig { max_jobs: 7, .. } }`
  → the loaded plugin's `engine().cfg.max_jobs == 7` and `cfg.findings_dir == cfg.findings.dir`);
  the existing `assemble` tests (`assembled_ingress_dispatches_or_refuses_tcp`,
  `l4_guard_tracks_l4_enabled`, governance tests) still pass. `tui.rs`: the existing
  `attach_bound_hook_feeds_the_bound_port_to_the_l4_guard` still passes; new
  `server_carries_the_job_bus` (`server(&cfg, Stdio, &services).jobs().is_some()`).
- **Done when:** `cargo test -p aitm --lib --offline` passes in the sandbox, the Terminal
  full gate passes (port-binding tests), and `cargo run -p aitm -- --help` (or the
  equivalent no-port invocation) still starts.

### Task 18: `docs/scanner.md`

- **Satisfies:** spec D12 row T1b (`docs/scanner.md`), D11 ("the config reference ... tell the
  operator that the stream lane needs an L4 scope entry with `interface: "*"`"), research 20
  drift ("discovery is the only scanner command that exists").
- **Depends on:** Task 15 (verb names); file-disjoint from every other task.
- **Files:** `docs/scanner.md` (rewrite).
- **Change:** operator documentation, plain prose, sections: what a scan is (job model,
  push + poll); quick start (`scan.start { target }`, `scan.status`, `scan.issues`,
  `scan.cancel`); every `scan.*` verb with params, result, tier and the `scan: <code>: <message>`
  codes; the seven built-in profiles and the profile YAML (one full `standard` example);
  the `scanner:` config section with every key and default, the ceilings and clamping; gates
  (`scanner.allow_agent_active`, `scanner.allow_agent_l4_fuzz` **and** `l4.allow_agent_inject`,
  `intrusive` operator-only, the `_confirm` prompt text); the L4 hint verbatim: "the stream
  lane needs an L4 scope entry with `interface: "*"`, `direction: outbound`, the target CIDR
  and port range, and the `Inject` capability"; the catalogue (`scan.checks`, native vs
  bundled vs custom, the `check.<id>` manual commands, a complete `reg.add_check` example
  script that reads as prose, the `probe.*` functions, "no `sleep`: read `elapsed_ms`");
  issues vs findings (dedupe, confidence, `scan.issue.update`, when a `FindingRecord` is
  written); session reuse (observed mode, names only in `scan.session.preview`, the GET/HEAD
  canary); where files live under `findings.dir`; what the interim lane covers today and that
  `scan.discover` is deprecated in favour of `scan.map`; a "lanes not yet landed" note
  (`lanes.skipped`). The former "Roadmap" section is removed.
- **Test:** a doc has no unit test; the Tester checks that every verb name in the file exists
  in live `tools/list` (Task 19) and that `grep -c 'scan\.' docs/scanner.md` is `>= 18` and the
  text contains `interface: "*"` and `reg.add_check`.
- **Done when:** the file reads top to bottom without a dangling reference and `cargo fmt --check` is unaffected.

### Task 19: integration: merge `origin/main`, re-pin the contract lists, gate, real proof

- **Satisfies:** spec D12 "Integration-shared files" (the one task that edits them), spec
  Verification (real scans over the real bus against `aitm-testtarget`, independent observers),
  ACs T1-1..T1-11 and T10-3 as the whole-branch proof, AC T1-8.
- **Depends on:** every earlier task merged into `claude/wizardly-nightingale-441e25`.
- **Files:** `crates/aitm/tests/frontends.rs` (`EXPECTED_TOOLS` and its length literal),
  `crates/aitm-tui/src/lib.rs` (`CORE_TOOLS` constant only), `crates/aitm-tui/fixtures/bus-fixture.json`
  (tool entries), `crates/aitm/tests/bundled_startup.rs` (re-run; no new bundled check names
  are expected: T1b converts no script), `crates/aitm-plugin-rhai/tests/bundled_scripts.rs`
  (re-run; unchanged expected), `docs/design/languages/rhai.api.json` (re-verify against the
  live engine surface via `cargo test -p aitm-plugin-rhai --test api_catalog`; edit only if
  `main` moved the catalogue), `crates/aitm-plugin-rhai/src/catalog_assembly.rs::production_languages()`
  (re-run only; T1b adds no language), `crates/aitm-plugin-scanner/src/util.rs` (the `scrub` line, only
  if PR #199 has merged), `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1b-plan.md`
  (the Shipped notes the orchestrator fills), plus any merge-conflict hunk.
- **Steps** (Terminal for `git`, ports and the proof; sandbox for the rest):
  1. `git fetch origin && git merge origin/main` (merge, not rebase; `baseRefName == main`).
     If PR #199 is on `main`: flip `util::scrub` to `aitm_core::redact::scrub_text_wide`, keep
     `reproduce.rs`'s `scrub_embedded` on `scrub_text_wide` as #199 left it, and re-run the
     scanner tests. If PR #195's `ConnInfo` change conflicts in `client.rs`'s `loopback_conn`,
     keep `main`'s field set. Record which applied in the Shipped section.
  2. **Re-pin from live `tools/list`**: build `aitm`, boot a core (the harness's `Aitm.server`
     or `aitm --config` with a loopback-TCP bus), read `tools/list`, and set `EXPECTED_TOOLS`
     (the array length literal too), `CORE_TOOLS`, and the `bus-fixture.json` `tools` entries
     to exactly that set; the delta over `main` must be the 20 names Tasks 15/16 add
     (15 new `scan.*` + 5 `check.<id>`) plus whatever `main` added meanwhile; quote the diff.
     `cargo test -p aitm --test frontends` and `cargo test -p aitm-tui` pass.
  3. Full gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`;
     quote the final `test result:` lines and `echo $?`.
  4. **Real proof**, driven from scripts under `$TMPDIR` that import the harness library
     (`tests/e2e/aitm_e2e`: `Aitm.server`, `BusClient.operator/agent`, `Target`, `Upstream`,
     `CoreConfig`) without editing it (the T10 cells and the harness `scanner:` emitter are not
     on `main`; the `scanner:` section is appended to `CoreConfig.to_yaml()` output by the
     script itself and that is stated in the report). Observers: a **counting relay** (a
     `$TMPDIR` Python `http.server` that logs method, path and time of every request and
     forwards to the `Target`; the relay's `127.0.0.1:<port>` is the in-scope origin), the
     harness `Upstream` echo-recorder as the **out-of-scope canary host**, the findings dir on
     disk, `flow.list`/`flow.get` over the bus, and a second subscribed operator `BusClient`.
     Each proof quotes the raw bus results it asserts on:
     - P1 (T1-1): operator `scan.start { target: <relay origin> }` returns in < 2 s with
       `state ∈ {queued, running}`; `scan.status` on the same connection while it runs; reaches
       `done`; `lanes.skipped == [{ lane: ws, .. }]` (T1-11 half).
     - P2 (T1-3): the second subscribed client received `started`, >= 1 `progress`, >= 1 `issue`
       (Vulnerable target), `finished`; `seq` strictly increasing; <= 4 `progress` lines in any
       one-second window (quote the per-second histogram).
     - P3 (T1-10, T1-5 negative): with `findings.dir` set, the Vulnerable run yields issues of
       class `reflected-xss` and `open-redirect`; `scan.issue` shows `finding_id` on the
       reflected-xss issue and the `FindingRecord` YAML has `passed: true`; the Patched run
       yields zero issues and writes no record (`ls` of the findings dir quoted).
     - P4 (T1-2): a running job cancelled → `cancelled` within 5 s; the relay log shows no
       request after `finished_at` + 2 s; the canary `Upstream.received()` is empty for the whole
       run; `probes.sent <= relay request count`.
     - P5 (T1-5): an origin not in scope → `scan: out_of_scope:` and relay count `0`;
       `overrides: { budget: { probes: 50 } }` → relay count `<= 50 + crawl pages` where the
       crawl pages are counted separately in `status.crawl.pages`, and `stopped_reason == budget`.
     - P6 (T1-4): agent client under `auto` → `scan: refused_agent:`; with the appended
       `scanner:\n  allow_agent_active: true` and `agent.set all` → `scan.start` succeeds;
       `scan.map` under `auto` succeeds without the flag.
     - P7 (T1-6): `scan.checks` lists the five interim metas with every `CheckMeta` key; a custom
       `add_check` script dropped into `rhai.scripts_dir` appears after a core restart with
       `origin.kind == custom`; the same script without `kinds` makes `script.list` show a
       `last_error` naming `kinds` (or the core's stderr does). The bundled-script half of T1-6
       is provable only after T3 converts the scripts; say so.
     - P8 (T1-7): the custom script's check declares `class: reflected-xss` on `query` → after a
       Vulnerable run one issue has `occurrences == 2`; a second run merges into the same issue
       id (count unchanged, `occurrences` grows); `scan.issue.update` to `false_positive`, core
       restart, `scan.issue` still `false_positive`.
     - P9 (T1-8): live `tools/list` equals `EXPECTED_TOOLS` (the `frontends` test output quoted).
     - P10 (T1-9): after a `standard` run, every flow added to the store during the job carries
       `scan:<job>`, crawl captures also `crawl`, issue probes also `issue:<id>`; the relay count
       is far above the number of scanner flows in the store (quote both); a `curl` through the
       proxy during the job is still listed.
     - P11 (T1-11): profile `lanes: [http, ws]` runs with `skipped: [ws]` in both results;
       `lanes: [ws]` → `scan: lane_unavailable:` and relay count `0`.
     - P12 (T10-3): with the bundled catalogue loaded, plain-HTTP traffic proxied to the
       Vulnerable target (response without HSTS/CSP) and a cleartext `ws://` conversation produce
       `script.findings` entries `missing-hsts`, `missing-csp`, `ws-cleartext-transport` with no
       `scan.*` call made; the negative half uses the Patched target when it sets those headers,
       otherwise a `$TMPDIR` Python server that sets them (say which).
     Any SKIP, fixture run or "would pass" is a failure of this task's proof.
  5. `git push origin claude/wizardly-nightingale-441e25` (explicit refspec) and open the PR
     against `main` with the plan path, the gate output, the re-pin diff and the twelve proofs
     in the description; the stage-6 panel comment is added by the orchestrator before merge.
- **Test:** the commands above; the proof is their quoted output.
- **Done when:** the gate exits 0, P1-P12 are quoted with real bus results, the re-pinned
  contract tests pass, and the panel review has no open findings.

## File ownership matrix (disjointness check)

| Task | Files |
|---|---|
| 1 | `crates/aitm-scan-model/{Cargo.toml, src/lib.rs, src/vocab.rs, src/registry.rs, src/testing.rs, src/traits.rs, src/profile.rs, src/check.rs, fixtures/scan.checks.json}` |
| 2 | `crates/aitm-core/src/{jobs.rs, lib.rs, ctx.rs, client.rs (tests)}` |
| 3 | `crates/aitm-plugin-scanner/{Cargo.toml, src/lib.rs, src/config.rs, src/util.rs, src/report.rs (the `index_to_value` delegation only), placeholders src/{profiles,issues,client,session,catalogue,scheduler,reproduce_link,interim_lane,jobs,worker,verbs,manual_check}.rs}`, `crates/aitm/src/config_file.rs`, `crates/aitm/src/main.rs` (the `scanner: _,` destructure line only; Task 17 binds it) |
| 4 | `crates/aitm-plugin-rhai/{Cargo.toml, src/lib.rs, src/engine.rs, src/host_net.rs, src/error.rs, src/host_registry.rs, placeholders src/{check_bridge,host_probe}.rs, tests/check_run.rs}`, `crates/aitm-plugin/src/language.rs` (additive, call B29) |
| 5 | `crates/aitm-mcp/src/{server.rs, lib.rs}` |
| 6 | `crates/aitm-plugin-scanner/src/profiles.rs` |
| 7 | `crates/aitm-plugin-scanner/src/issues.rs` |
| 8 | `crates/aitm-plugin-scanner/src/client.rs` |
| 9 | `crates/aitm-plugin-scanner/src/session.rs` |
| 10 | `crates/aitm-plugin-scanner/src/{catalogue.rs, scheduler.rs}` |
| 11 | `crates/aitm-plugin-scanner/src/{reproduce_link.rs, reproduce.rs}` |
| 12 | `crates/aitm-plugin-scanner/src/interim_lane.rs` |
| 13 | `crates/aitm-plugin-rhai/{src/check_bridge.rs, src/host_probe.rs, src/command.rs, src/loader.rs, src/plugin.rs, src/wire.rs, src/lib.rs, tests/check_bridge.rs, tests/api_catalog.rs (the one `"probe" => "probe"` arm of `receiver_type`)}`, `docs/design/languages/rhai.api.json` (call B30; also the `http.send` signature string gains `elapsed_ms`) |
| 14 | `crates/aitm-plugin-scanner/{Cargo.toml (one dep line), src/jobs.rs, src/worker.rs, src/plugin.rs (setters)}` |
| 15 | `crates/aitm-plugin-scanner/src/{verbs.rs, manual_check.rs, plugin.rs (load)}` |
| 16 | `crates/aitm-plugin-scanner/src/commands.rs` |
| 17 | `crates/aitm/src/{wire.rs, main.rs, tui.rs}` |
| 18 | `docs/scanner.md` |
| 19 | integration-shared files (re-pin), `crates/aitm-plugin-scanner/src/util.rs` (one line, conditional), merge hunks |

**Amendments after wave 1 (orchestrator, 2026-11-01):** Task 3 also edits `report.rs` (its Change step 4 moves `index_to_value`'s body into `util::json_to_value`) and one line of `main.rs` (the exhaustive `Settings` destructure needs `scanner: _,` to compile; Task 17 replaces it with the real binding). Task 3's dev-dep `aitm-scan-model = { features = ["testing"] }` needs Task 1's feature, so on a re-run Task 3 follows Task 1. Task 1's required `CheckMeta.scope` field also touches the one `CheckMeta` literal outside the model crate (`crates/aitm-plugin-scanner/src/plugin.rs` tests), committed with Task 1.

**Amendments for Task 13 (orchestrator, 2026-11-01):** (a) `tests/api_catalog.rs::receiver_type` panics on an unmapped prefix, so Task 13 also adds the single arm `"probe" => "probe"` there (the file is T1b-owned and not on the integration-shared list; Task 19 only re-runs it). (b) `serde_yaml` is a dev-dependency only in `aitm-plugin-rhai`; `poc_hint_from_map` converts the `matchers` list with `serde_json::from_value::<aitm_poc::Assertion>` (the hand-written `Deserialize` on `Assertion` accepts the same vocabulary; the model crate's "no serde derives" remark means derives, not impls). (c) A duplicate check id reported by `CheckRegistry::add`/`replace_source` is a load error through the existing `ScriptError::CheckMeta { script, check: Some(id), key: "id", message: "check `<id>` is already registered by source `<other>`" }`; no new `ScriptError` variant. (d) The `http.send` signature string in `rhai.api.json` gains `elapsed_ms` in Task 13's edit.

**Amendments after wave 2 (orchestrator, 2026-11-01):** Task 7: `upsert` keys `passive` → `Passive`, else `location.l4.is_some()` → `L4`, else `Http` (spec D6 names the L4 tuple; the plan sentence omitted the branch); the `target` filter matches the normalized origin, the explicit `scheme://host:port` or the bare host; a colliding issue id is re-minted (bounded, `create_new`). Task 10: the catalogue registers native (lanes' `checks()`, then `native_checks`) → bundled → custom; the **first** claim on an id wins and a later duplicate is a reported `CheckConflict` exposed by `Catalogue::conflicts()` (replaces the plan's "later wins with `tracing::warn!`"; `aitm-plugin-scanner` has no `tracing` dep); Task 14/15 must surface `conflicts()` at load (log + `scan.checks` cannot hide it). `IgnoreRule.name_regex` is evaluated through `aitm_poc`'s regex assertion (no `regex` dep). `SiteNode` has no content type, so `interest()` always takes the unknown branch until a lane adds one.

**Amendment for Task 8 (orchestrator ruling, 2026-11-01, spec D5 over the plan sentence):** `JobClient::send(req)` is the probe path and sends with `record: Never`; `send_opts` forwards `Always` iff the job policy is `all` or the caller passed `opts.record == Always` (a lane's client-crawl captures, marks `scan:<job>` + `crawl`, per D5 "crawl flows are different"), else `Never`. D5's issue re-recording is a store insert of the flows the `ProbeHost` held in memory (marks `scan:<job>`, `issue:<id>`, `is_replay: true`), done by the engine, never a re-send. The interim lane's `ProbeHost` probes through `send`. The per-host ratio rule applies from `LADDER_MIN_SAMPLE = 10` outcomes (otherwise the first 5xx trips any `ratio < 1.0`); `Ladder` keeps a sticky `tripped`; `ProbeRefused` gains `Timeout { host, after }` for the 30 s bound.

**Coordinator items of 2026-11-01 (after PR #213 merged as 1f1cec42; merged here as 3dcacc1a):** (a) `ProbeHost` gains default-bodied `fn baseline_peer_addr(&self) -> Option<std::net::SocketAddr> { None }` (model crate; the interim HTTP host fills it from the baseline flow's peer when known) so T3's raw-h2 observe probe dials the validated address. (b) Task 17 keeps the `aitm_scan_checks_http::checks()` call in `wire.rs` on a single line: T3's integration commit changes it to `checks_with(ssrf_policy, guard)`. (c) Task 19 reports the re-pinned contract counts (`EXPECTED_TOOLS`, `CORE_TOOLS`, `bus-fixture.json`) to the coordinator when the PR opens; system-proxy and L4-parity moved them on main today. (e) `JobCtx` also gains default-bodied `report_session_canary(Canary)` and `report_session_browser_partial(Vec<String>)` (T2 request, 2026-11-01); Task 14's `JobCtx` impl mirrors them into `JobStatus.session.canary` / `session.browser_partial`. (d) Task 14: `JobCtx::charge(1)` is called by the HTTP lane once per browser navigation/click/submit (those are proxied captures, never client sends) and decrements the one probes budget; HTTP sends are charged only inside the `JobClient`; `crawl.pages` may count those charges when a browser is bound.

Within a wave no two tasks share a file. `crates/aitm-plugin-rhai/src/lib.rs` is edited in
wave 1 (Task 4) and wave 2 (Task 13); `crates/aitm-plugin-scanner/src/plugin.rs` in wave 4
(Task 14) and wave 5 (Task 15); `crates/aitm-plugin-scanner/Cargo.toml` in wave 1 (Task 3) and
wave 4 (Task 14); all sequential. `Cargo.lock` is a derived file every task may regenerate.

## Architect's calls in this plan (for the orchestrator/Matt to approve or correct)

- **B1 No child spec for the engine internals.** The umbrella spec fixes every externally
  observable contract (verbs, codes, push line, catalogue, job and issue models) and the T1a
  contract crate fixes every type; what remains (module layout, cursor encoding, coalescing
  implementation, ladder bookkeeping) is "left to the builder" in the spec and is pinned here
  by tests with literal values. A second spec would restate this plan.
- **B2 The interim lane lives inside `aitm-plugin-scanner`** (`interim_lane.rs`) and is
  registered by the plugin, not by `collect_lanes`, so `wire::tests::skeleton_lane_slots_are_empty_today`
  stays at `0`. `Engine::lanes_for_run()` prefers a lane-crate lane for `LaneKind::Http`; when
  `aitm_scan_http::lane()` returns `Some`, the interim lane is ignored without a code change
  (T2 then deletes it in its integration task).
- **B3 Late binding without a new shared file.** `ScanLate` (a `OnceLock<ScanServices>` owned
  by the plugin and exposed on `Assembled.scan_late`) is bound in `main.rs` beside
  `handles.bind_proxy(..)`, in both the CLI branch and the server path; `wire::assemble` alone
  leaves it unbound and the verbs then fail with a plain "not bound" error (a wiring bug, not a
  `scan:` code). `JobBus` is created in `assemble_with_scripts` and exposed on `Assembled.job_bus`.
- **B4 `ScanServices` carries `config: Arc<aitm_core::Config>` instead of `findings: Option<Arc<FindingStore>>`:**
  the worker builds a `CommandHost` from its handles for the legacy `crawl()`, the PoC runner
  and `record_finding`, all of which read `host.config().findings.dir`; `findings_dir` is also
  copied onto `ScannerConfig` for the stores.
- **B5 Thread-local check context.** It lives in `aitm-plugin-rhai/src/host_probe.rs`
  (`CHECK_CTX`, holding `Arc<dyn ProbeHost>` + the point), seeded by `ScriptCheck::run` like
  `seed_call_context`/`begin_run`; the engine wraps every lane host in `ArcHost` so
  `ProbeHost::shared()` yields the owning handle; no unsafe, no borrowed pointer.
- **B6 `refused_agent` under `auto` comes from the command.** AC T1-4 requires the code token
  under `AgentPolicy::Auto`, where today the MCP gate refuses every Sensitive command with its
  generic text. `aitm-mcp` gains `defers_to_command_gate_under_auto(name) == matches!(name, "scan.start")`
  and the `(Auto, Sensitive)` arm consults it; `scan.start` then refuses an agent itself under
  `auto` (and without the flag, and for `intrusive`). No other verb's behaviour changes; the
  L4 verbs keep today's refusal under `auto`. This widens the gate by exactly one verb that
  carries its own policy-aware gate and is worth the orchestrator's eye.
- **B7 The `ScannerPlugin` is registered after the script tier** in `assemble_with_scripts` so
  its `load` sees every Rhai `add_check` and can register the uniform `check.<id>` commands;
  it registers no hooks, so the event chain is unaffected.
- **B8 Uniform `check.<id>` commands** are registered by the scanner for every catalogue
  entry unless a command of that name already exists (a script that still calls
  `add_command("check.x")` keeps its own). A Rhai check's `id` is the script's declared `id`
  verbatim, so T3 preserves the shipped verb names (`id: "sqli"` → `check.sqli`). T1b adds five: `check.reflected-xss`,
  `check.open-redirect`, `check.reflection`, `check.security-header`, `check.cookie-flag`
  (`id == class` for the interim lane); they are re-pinned by Task 19 and replaced by T2/T3.
- **B9 The `CheckRegistry` rides on `RhaiLoader`/`ScriptTier`, not on `ScriptServices`:**
  `ScriptServices` is constructed in 17 files including two integration-shared ones, so a new
  field would force edits no task may make. `main.rs` hands `tier.checks` to the scanner
  through `ScriptWiring.script_checks`. The registry type itself lives in `aitm-scan-model`
  (`registry.rs`, a lock-protected container with no I/O).
- **B10 Default-bodied `ProbeHost` additions** (`client`, `shared`, `captured`) are the only
  trait changes; passive interim checks use `captured()` so the `passive-only`/`map-only`
  profiles send no probe.
- **B11 `scan.discover`'s wait** is bounded by the shipped `ScannerConfig.time_budget` (600 s
  default), after which the job is cancelled and the result reports `stopped_reason: "time_budget"`;
  it still blocks only its own connection, exactly as the shipped verb does.
- **B12 Cursors** are decimal offsets (`scan.issues`, `scan.sitemap`); `scan.issues` orders by
  severity desc, `first_seen` asc, id; `by_severity` tallies the whole filtered set.
- **B13 Coalescing** is time-based: a `progress` line is dropped unless 250 ms have passed since
  the last sent one; `started`, `phase`, `issue`, terminal lines are never dropped; `seq`
  counts sent lines only.
- **B14 Record policy details:** the `JobClient` records only when the job policy is `all` or
  the caller passes `record: Always` (the issue re-recording path); re-recorded flows get
  `scan:<job>` + `issue:<id>` and the issue's `probe_flows` are rewritten to the new ids.
- **B15 Per-host ladder** keeps a 50-entry window; tripped when `consecutive` failures or the
  window's failure ratio exceeds `ratio`; a trip ends the job with `stopped_reason: errors`.
- **B16 `JobBus` payload is `aitm_core::Value`** (core has no serde); the scanner converts the
  model's `JobNotification` through `serde_json` and `util::json_to_value`; the MCP server
  renders `params` from the payload object and inserts `job`/`kind`/`event`/`seq` only when absent.
- **B17 Check origin rule:** `bundled` when any path component equals `bundled`, else `custom`
  (`native` for Rust checks). T1-6 asserts presence and full metadata, not the tag.
- **B18 `confirm_required` is never emitted by the engine:** the MCP/CLI layers own the
  `_confirm` handshake through `confirm_prompt`; the code stays in the vocabulary for them.
- **B19 Interim check metadata:** `reflected-xss` `Medium`/`Certain`/CWE-79, `open-redirect`
  `Low`/`Certain`/CWE-601 with `wants_traits: [url]`, the three passive classes `Low` with
  `Firm` (headers, cookie flags) or `Tentative` (reflection). Both active classes supply a
  `PocHint` from the legacy `CheckDefinition::success_assertion`.
- **B20 Browser crawl navigations are charged** to the job budget by `pages_crawled`; the
  crawl runs only when the profile's `crawl.max_pages > 0`, `use_browser != never` and a
  browser is bound; otherwise discovery reads captured in-scope flows only.
- **B21 Name clash kept:** the model's `JobEvent` (push event enum) and the core's `JobEvent`
  (bus struct) both follow the spec; code aliases the core one as `BusJobEvent`.
- **B22 T1b is the next writer of `crates/aitm-scan-model/**`** (T1a has merged); Task 1 holds
  every model edit of this track and no other task touches that crate.
- **B23 T1a follow-ups absorbed:** (1) the `ScanErrorCode` token table and unit error type
  (Task 1); (2) the `testing` module behind `cfg(any(test, feature = "testing"))` (Task 1), used
  by the engine tests; (3) nameless/targetless profiles refused with `invalid_profile` (Task 6).
- **B24 Deferred flattening of `Issue`/`IssueSummary` and `JobStatus`/`JobSummary` stays
  deferred:** the UI tracks already consume the wire shapes and T1a's structural subset tests
  pin them; flattening would touch every consumer for no observable gain.
- **B25 Session material pick:** newest captured (non-replay) flow to the origin carrying
  `Cookie` or an `is_secret_name` header; the canary is the newest captured GET/HEAD carrying
  the same material; every 25 probes; a 2xx→3xx/401/403 class change is a loss.
- **B27 Lane feedback into the job (coordinator decision 1):** `JobCtx::report_l4` and
  `JobCtx::report_session_lost` (default no-ops) plus `Lane::validate` (default `Ok`) are the
  three default-bodied additions beyond `ProbeHost`'s; `Lane::validate` makes a lane's
  profile refusal (T5-3's pinned fields) synchronous at `scan.start`, and the error-prefix
  convention (`scan: session_lost: ` on a probe error, `invalid_profile: ` on a discover
  error) is the fallback a lane may use without the hooks. `report_l4` merges by per-field
  maximum so `JobStatus` counters never go backwards.
- **B28 Model growth for the lane tracks (coordinator decisions 2-4):** `L4Options.fields`
  (default empty), `Timing.correlated` (`#[serde(default)]`, computed once by
  `probe.timing_fit`/the native oracle, never recomputed by the engine), `CheckMeta.scope`
  (`CheckScope::{Point, Node, Origin}`, default `point`; the scheduler runs node/origin-scoped
  checks once per node/origin). All serde-default so T1a's fixtures parse unchanged.
- **B29 Run-kind seam (coordinator decision 5):** `HostRunKind` and the default-bodied
  `HostCallContextSource::run_kind()` live in `crates/aitm-plugin/src/language.rs`, a file
  outside D12's T1b row; the edit is additive and made on the coordinator's instruction (Task 4);
  `RhaiCallSource` answers from the thread-local run so T4's `ws.*` guard can refuse
  `Some(HostRunKind::Hook)`.
- **B30 `rhai.api.json` is edited by Task 13, not only by Task 19:** the `api_catalog` test
  asserts a bijection between the registered host surface and the file, so registering
  `probe.*` without the entries would fail the per-task gate. Across tracks the file stays
  integration-shared (T4 adds its `ws.*` entries after T1b merges); `production_languages()`
  is untouched by T1b. If the coordinator prefers the file edited only in the final commit,
  Task 13 moves to wave 7 and T3 waits one wave longer.
- **B26 The real proof uses `$TMPDIR` scripts over the harness library** with a counting relay
  in front of `aitm-testtarget` and the harness `Upstream` as the canary host, because the T10
  cells, the target's request-log endpoint and the harness `scanner:` emitter are not on `main`.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | Quality | Important | `CheckRegistry::replace_source` silently skips an id another source owns and returns `()` | fixed in e66189ba: returns `#[must_use] Vec<DuplicateCheck>`; Task 13 raises them as load errors |
| 3 | Quality | Minor | `ScannerConfig` struct doc still says "every field is a hard ceiling" | fixed in 5960c928 |
| 1 | Quality | Minor | `job_ctx_report_defaults_are_no_ops` asserts `() == ()` | fixed in 5960c928 |
| 1 | Quality | Minor | `RecordingHost::probe_raw` records URLs into `payloads()` | fixed in 5960c928 |
| 4 | Quality | Minor | `check_meta_error_names_the_key` uses `contains`; `run_kind` test never covers `RunKind::Check` | fixed in 5960c928 (Display pinned; the `Check` arm was already pinned by the Tester's `run_kind_maps_check_load_and_poc_step`) |
| 4 | Quality | Minor | `HostRunKind` hand-mirrors `engine::RunKind` with a variant-for-variant match | accepted by orchestrator 2026-11-01: `RunKind` is the rhai engine's own enum and the exhaustive match turns drift into a compile error; the seam enum stays in `aitm-plugin` per call B29 |
| 1 | Quality | Minor | `ScanErrorCode::as_str` indexes the table by discriminant on a test-held invariant | fixed in 5960c928 |
| 4 | Quality | Minor | `block_on_browser` doc points at `block_on_send` instead of `drive` | fixed in 5960c928 |
| 1 | Quality | Minor | `scan_error` erases the code into a string callers must re-parse | fixed in 5960c928 |
| 3 | Spec | Minor | `tempfile = "3"` dev-dep not added and the fallback not recorded | accepted by orchestrator 2026-11-01: not in the offline cache at Task 3 time; seeded from the Terminal before wave 2; Tasks 6/7 may add it or use `std::env::temp_dir()` + a uuid subdir |
| 4 | Spec | Minor | `rhai.api.json` `http.send` signature lacks `elapsed_ms` | Task 13 (in flight) updates the signature string |
| 3 | Spec | Minor | `Ceilings` derives `Eq` where the plan said `Debug, Clone, PartialEq` | accepted by orchestrator 2026-11-01: `Ceilings` holds only integers; the `Eq`-dropped reason applies to `ScannerConfig` only |
| 1-4 | Spec | Minor | Unrequested additions: `Debug` for `CheckRegistry`/`JobBus`, `Default` for `NullJob`/`NullHost` (clippy), dead `block_on` removed, seven extra tests | accepted by orchestrator 2026-11-01: each is a gate consequence or a stronger pin; none changes behaviour |
| 4 | Security | Minor | Unbounded `check_timeout_s` reaches `Instant + Duration` (panics on overflow) | fixed in 5960c928 (engine) and dd9c2217 (Task 6 clamp) |
| 3 | Security | Minor | `job_id`/`issue_id` carry 32 bits of randomness; no collision check | fixed in ec09682d (store re-mint) and 5960c928 (docs) |
| 1 | Security | Minor | `replace_source` drops a squatted id silently; registration order unpinned | fix: same as the quality Important (typed return); Task 10 registers native → bundled → custom explicitly and reports duplicates |
| 6 | Security | Note | Profile `name` must be validated before it becomes a path (`../` traversal) | routed to Task 6 (in flight) 2026-11-01 |
| 8 | Security | Note | Zero ceilings/budgets must not divide by zero or spin in the pacer | routed to Task 8 (in flight) 2026-11-01 |
| 13 | Coder (gap) | Important | Plan Task 13 Files list omitted `tests/api_catalog.rs`, whose `receiver_type` panics on the new `probe` prefix; `serde_yaml` is dev-only; no error variant named for a duplicate id | plan amended 2026-11-01 (Task 13 amendments a-d); call B30 extended to the test file |
| 1-4 | Tester | PASS | Every plan-named test present with literal values; 30 tests added (803cbdd7); `HELP_CHECK_META` omits `targets_session`/`scope` and `origin` is host-supplied | fixed in 5960c928 |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
