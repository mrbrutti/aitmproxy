# aitmproxy Milestone 3 Implementation Plan — Rhai scripting tier

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-28 by Matt) — final, option C (Rhai + rustman-style ergonomics; spec OQ10).
**Spec:** `docs/superpowers/specs/2026-10-27-aitmproxy-m3-rhai-scripting-design.md` (approved; AC-M3-1…AC-M3-12, inheriting plugin-system AC-P6–AC-P11 and PoC-language AC-L8)
**Branch / worktree:** `feat/aitmproxy-m3`, cut from `main` (M1) at stage 4; the spec, research note, and this plan are committed on `claude/m3-rhai-spec-2197df`.

**Goal:** Add the Rhai scripting tier — a new `aitm-plugin-rhai` crate that turns a `.rhai` file into a first-class, ordered-chain `Plugin`, plus the PoC `script`-step escape hatch (`Step::Script` in `aitm-poc` driven through a `ScriptStepExecutor` seam) — over the M1 seams on `main`, with `aitm-core` unchanged and every AC-M3 criterion green.

**Architecture:** One shared, sandboxed, `sync`-feature Rhai `Engine` built once; each script compiles to an `AST` and becomes its own `ScriptPlugin` registered individually (so it takes a chain position and its `halt()` short-circuits like a native plugin). Flows cross into scripts as `Arc<Mutex<FlowState>>` snapshot handles applied back after the hook (no `unsafe`); the synchronous engine reaches async guarded capabilities via `block_in_place` + a stored `Handle::block_on`, so every `http`/`browser`/`scope` call rides the existing scope/rate/SSRF guards. The PoC step reuses the same engine and host surface behind a trait that keeps `aitm-poc` Rhai-free.

**Tech Stack:** Rust; `rhai` 1.27 (feature `sync`; **not** `unchecked`/`internals`); `tokio` (multi-thread runtime, `task::block_in_place`, `runtime::Handle`); `arc-swap` (the AST reload seam); `tracing`; `anyhow`; existing `aitm-core`, `aitm-poc`, `aitm-plugins`.

## Global Constraints

Every task's requirements implicitly include these (verbatim from the spec):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` before any review. TDD: no production code without a failing test first; the Coder's report includes both runs.
- **`unsafe` stays forbidden.** The workspace sets `unsafe_code = "forbid"`; the M3 design is deliberately `unsafe`-free (shared-state handles, not raw pointers). A task that reaches for `unsafe` has mis-designed and must stop and report.
- **Engine features:** `rhai` with `sync` only. `unchecked` and `internals` must never be enabled — `unchecked` disables the very limits this tier relies on. (Engine decided: Rhai — spec OQ10, Matt 2026-10-28.)
- **Option C ergonomics (spec §2a, §5, OQ10).** Pure reads with an obvious "absent" answer are **forgiving** — `option(unset)`, `store.get(unknown)`, a `headers`/`query` read of a missing key return `""`/`null`, never aborting a hook. The flow surface is the **effect model**: edits/effects are recorded on the `FlowState` snapshot and applied after the hook, **discarded on error** (Task 8). The curated verb set stays minimal. **Guard refusals are NOT forgiven** — a scope/SSRF-denied `http.send`/`browser.*` still returns a catchable error (Task 7). Affects Tasks 3, 5, 6, 7, 11; not Task 1's `ScriptError`/`RhaiConfig`.
- **Capabilities register through the seam (spec §6a).** The `log`/`finding`/`http`/`browser`/`store`/`scope` host functions are registered as `ScriptCapability` providers, not one hard-coded block, so a future protocol/L4 crate adds its own verbs with no sandbox-core change. **L4/new-protocol verbs and the extended (packet/address-level) scope model are out of M3** (spec §7a, OQ11); M3 builds only today's capabilities behind the seam.
- **Multi-threaded runtime required.** `tokio::task::block_in_place` panics on a current-thread runtime; all script dispatch and the e2e tests run on the multi-thread flavour the proxy already uses.
- **Declared signatures are authoritative.** Types and signatures in the spec and in each task's Interfaces block are copied exactly; bodies and in-module file layout are the builder's.
- **No `aitm-core` edits.** M3 adds crates and additive `aitm-poc` members only. Script runtime errors reach the bus as `FlowError::Protocol("script: …")` (spec OQ2) — no new core variant.
- **Guards are the only way out.** Every `http`/`browser`/`scope`/`store` host call goes through the existing `ScopeRateGuard` / SSRF guard on `CommandHost`'s handles; no second network path exists in a script.
- **Dependencies:** `aitm-plugin-rhai` may add `rhai = { version = "1.27", features = ["sync"] }`, `arc-swap`, `tracing`, `anyhow`; dev-deps `tokio` (`rt-multi-thread`, `macros`), `serde_yaml` (fixtures). `aitm-poc` adds **no** new runtime dependency — the `ScriptStepExecutor` trait is defined there, its impl lives in `aitm-plugin-rhai`.
- **Hermetic tests by default.** Unit tests stand up no network, browser, or OS resource. The browser-backed e2e (Task 15) is gated behind the M2/M1 env flag (`AITM_OBSCURA=1` / `AITM_CHROME=1`) and skipped otherwise.
- **Human ergonomics is acceptance-bearing** (spec §2, §2a): examples read as a small JS-like DSL; the `ScriptError` `Display` matches the spec's pinned format exactly.
- **Git/gh run through the Terminal panel** (`run_in_terminal`), never the sandboxed shell (`CLAUDE.md`).

## Review Focus

Input classes the spec implies but no happy-path test exercises; each is pinned to a test in the owning task:

1. **A hook that throws after it already edited the flow.** A runtime error mid-hook must leave the flow **byte-for-byte unchanged** — the snapshot's pending edits and effects are discarded, not partially applied — then emit `Event::Error` and continue. Pinned in Task 8 (`errored_hook_discards_edits`).
2. **A guard refusal inside a script.** `http.send`/`browser.navigate` to an out-of-scope or private host must surface as a **catchable Rhai error** a script can `try`/`catch`, naming the host, not a host-side panic. Pinned in Task 7 (`out_of_scope_send_is_catchable`).
3. **`set_response` + `halt()` together.** The short-circuit response must be applied to the client **and** the chain halted **and** a plugin registered after the script skipped — all three. Pinned in Task 8 (`set_response_halt_short_circuits`).
4. **A slow hook vs a busy hook.** A wall-clock-slow hook (`hook_timeout`) and an operation-heavy hook (`max_operations`) must both abort, with the termination token telling them apart so the error says which. Pinned in Task 2 (`timeout_and_oplimit_abort_distinctly`).
5. **A PoC script step that returns neither `pass` nor `fail`.** Falling off the end is `Neutral`; `success`'s `step("name")` must resolve it deterministically (`"neutral"`), and an errored step to `"error"`, so a `success` DSL referencing it never panics. Pinned in Task 13 (`script_step_neutral_and_error_resolve`).

---

## Overview

One new crate, `aitm-plugin-rhai`, built bottom-up, plus two additive edits to `aitm-poc`. **Task 1** scaffolds the crate with every module declared as a stub (so no later task re-touches `lib.rs`) and the two foundational files (`error`, `config`) real. The leaf modules then fill in parallel; `plugin` → `loader` → `command` form the chain core; `poc_step` bridges to `aitm-poc`; **Task 15** adds the public re-exports and wires the binary with the ordering rule and the e2e tests.

**Parallel groups (disjoint files, after dependencies land):**

| Group | Tasks | Why disjoint |
|---|---|---|
| **P1** | 2 ∥ 3 ∥ 4 ∥ 12 | `engine.rs` ∥ `marshal.rs` ∥ `flow_state.rs` ∥ `aitm-poc/model.rs` |
| **P2** | 5 (after 3,4) ∥ 6 (after 3) ∥ 11 (after 2) | `flow_api.rs` ∥ `host_core.rs` ∥ `prelude.rs` |
| **P3** | 10 (after 9) ∥ 13 (after 12) | `command.rs` ∥ `aitm-poc/runner.rs` |

Longest sequential chain: 1 → 3 → 6 → 7 → 8 → 9 → 10 → 15 (8 tasks). The PoC side (1 → 12 → 13 → 14 → 15) and the engine side converge only at Task 15.

## Tasks

### Task 1: Crate scaffold + foundational types (`error`, `config`)

- **Satisfies:** foundation for all; AC-M3-9 (error text, partial).
- **Depends on:** none. **Independent:** starts the crate.
- **Files:** Create `crates/aitm-plugin-rhai/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/config.rs`; stub files (one doc comment each) `src/{engine,marshal,flow_state,flow_api,host_core,host_net,plugin,loader,command,prelude,poc_step}.rs` and an empty `src/prelude.rhai`. Modify root `Cargo.toml` (add member + `aitm-plugin-rhai = { path = … }`). Test: `tests/types.rs`.
- **Interfaces — Produces:**
  ```rust
  // error.rs
  pub enum ScriptError {
      Compile   { script: String, path: PathBuf, line: usize, column: usize, message: String, hint: Option<String> },
      Runtime   { script: String, hook: String, line: usize, message: String },
      Timeout   { script: String, hook: String, elapsed: Duration },
      OpLimit   { script: String, hook: String, operations: u64 },
      Denied    { script: String, hook: String, capability: String, reason: aitm_core::GuardError },
      ApiVersion{ script: String, declared: String, supported: String },
  }
  impl std::fmt::Display for ScriptError;   // the spec §8 "pinned error format"
  impl std::error::Error for ScriptError;
  // config.rs
  pub struct RhaiConfig { pub scripts: Vec<ScriptEntry>, pub limits: RhaiLimits, pub hook_timeout: Duration, pub hot_reload: bool, pub strict: bool }
  pub struct ScriptEntry { pub path: PathBuf, pub options: std::collections::BTreeMap<String, aitm_core::Value>, pub enabled: bool }
  pub struct RhaiLimits { pub max_operations: u64, pub max_call_levels: usize, pub max_expr_depth: usize, pub max_function_expr_depth: usize, pub max_string_size: usize, pub max_array_size: usize, pub max_map_size: usize, pub max_modules: usize }
  impl Default for RhaiLimits;  // 2_000_000 / 64 / 128 / 64 / 65_536 / 16_384 / 16_384 / 0
  pub struct ScriptMeta { pub name: String, pub api: String, pub path: PathBuf, pub hooks: Vec<String> }
  ```
- **Change:** `lib.rs` declares every module `pub mod …;` (stubs compile as empty). `Display` for `ScriptError` renders the three spec samples' shape (script:line:col — what; a `help:` line where a `hint`/known class exists). `ScriptEntry.enabled` defaults `true`.
- **Test:**
  - `types.rs::oplimit_display_names_script_hook_and_budget`: `ScriptError::OpLimit{script:"slow".into(),hook:"on_response".into(),operations:2_000_000}.to_string()` contains `"slow"`, `"on_response"`, and `"budget"`.
  - `types.rs::denied_display_has_help_line`: a `Denied{…capability:"browser.navigate"…}` Display contains `"browser.navigate"` and a line starting `"  help:"`.
  - `types.rs::limits_default`: `RhaiLimits::default().max_operations == 2_000_000` and `.max_modules == 0`.
  - [ ] Scaffold crate + stubs + workspace member → `cargo build -p aitm-plugin-rhai` compiles.
  - [ ] Tests → FAIL → implement `ScriptError`/`Display`/config → PASS → gate → commit `feat(rhai): aitm-plugin-rhai scaffold, ScriptError, RhaiConfig/RhaiLimits`.
- **Done when:** the workspace builds with the new member and the three tests pass.

### Task 2: Sandboxed engine (`engine.rs`)

- **Satisfies:** AC-M3-5 (ambient-deny, engine half), AC-M3-6 (budget), Review Focus #4.
- **Depends on:** Task 1. **Independent:** yes — **P1**.
- **Files:** Modify `src/engine.rs`; test `tests/engine.rs`.
- **Interfaces — Produces:**
  ```rust
  pub fn build_engine(limits: &RhaiLimits, hook_timeout: Duration) -> rhai::Engine;  // sync feature; hardened
  pub fn harden(engine: &mut rhai::Engine, limits: &RhaiLimits, hook_timeout: Duration);
  pub enum AbortKind { OpLimit, Timeout }                 // carried in the on_progress termination token
  pub fn print_sink() -> (rhai::Engine /* wired */, Arc<Mutex<Vec<String>>>);  // test helper; prod routes to tracing
  ```
- **Change:** `harden` calls `set_max_operations`, `set_max_call_levels`, `set_max_expr_depths(max_expr_depth, max_function_expr_depth)`, `set_max_string_size`, `set_max_array_size`, `set_max_map_size`, `set_max_modules(0)`; `disable_symbol("eval")`; `on_progress(move |ops| …)` returning `Some(token)` encoding `AbortKind::OpLimit` when `ops > max_operations`, else checking `Instant` elapsed vs `hook_timeout` → `AbortKind::Timeout`, else `None`; `on_print`/`on_debug` → `tracing::info!`. The start `Instant` is reset per hook by the caller (Task 8) via a shared cell the closure reads.
- **Test** (each compiles a tiny script and runs it):
  - `engine.rs::timeout_and_oplimit_abort_distinctly` (RF#4): a tight `loop {}` with `max_operations = 10_000` → `Err` whose terminated token decodes `AbortKind::OpLimit`; the same loop with huge ops but `hook_timeout = 50ms` → `Err` decoding `AbortKind::Timeout`, elapsed `< 2s`.
  - `engine.rs::eval_is_disabled`: running `eval("1+1")` → `Err` (disabled symbol).
  - `engine.rs::no_ambient_authority`: a script calling `open_file("x")` → `Err` "function not found"; a script with `import "m" as m;` → `Err` (modules capped at 0).
  - `engine.rs::print_is_captured`: `print("hi")` via `print_sink()` → the sink holds `"hi"`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(rhai): sandboxed engine — limits, op/time budget, eval off, print capture`.
- **Done when:** the four tests pass.

### Task 3: `Value` ⇄ `Dynamic` marshalling (`marshal.rs`)

- **Satisfies:** foundation (commands, host fns, PoC vars).
- **Depends on:** Task 1. **Independent:** yes — **P1**.
- **Files:** Modify `src/marshal.rs`; test `tests/marshal.rs`.
- **Interfaces — Produces:** `pub fn value_to_dynamic(v: &aitm_core::Value) -> rhai::Dynamic;` `pub fn dynamic_to_value(d: &rhai::Dynamic) -> Result<aitm_core::Value, ScriptError>;`
- **Change:** `Null↔()`, `Bool`, `Int↔i64`, `Float↔f64`, `Str↔ImmutableString`, `Bytes↔rhai::Blob`, `Array↔rhai::Array`, `Object↔rhai::Map` (`BTreeMap<SmartString,…>`), recursively. A Rhai type with no `Value` counterpart → `Err(ScriptError::Runtime{…})`.
- **Test:**
  - `marshal.rs::scalars_round_trip`: for each of `Null, Bool(true), Int(7), Float(1.5), Str("x")` → `dynamic_to_value(&value_to_dynamic(&v))? == v`.
  - `marshal.rs::bytes_map_to_blob`: `value_to_dynamic(&Value::Bytes(vec![1,2,3]))` is a Rhai blob; round-trips to `Value::Bytes(vec![1,2,3])`.
  - `marshal.rs::nested_object_round_trips`: `Object({"a":Int(1),"b":Array([Str("y")])})` round-trips equal.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the three tests pass.

### Task 4: `FlowState` snapshot / apply (`flow_state.rs`, pure)

- **Satisfies:** AC-M3-1 (apply half), AC-M3-2 (verdict half), Review Focus #1 (discard mechanism).
- **Depends on:** Task 1. **Independent:** yes — **P1**.
- **Files:** Modify `src/flow_state.rs`; test `tests/flow_state.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct FlowState { pub id: aitm_core::FlowId, pub kind: aitm_core::FlowKind, pub request: Option<RequestState>, pub response: Option<ResponseState>, pub ws_message: Option<WsMessageState>, pub marks: Vec<String>, pub comment: Option<String>, pub is_replay: bool, pub effects: Vec<FlowEffect> }
  pub struct RequestState { pub method: String, pub url: String, pub path: String, pub headers: Vec<(String,String)>, pub query: Vec<(String,String)>, pub body: Vec<u8> }
  pub struct ResponseState { pub status: u16, pub headers: Vec<(String,String)>, pub body: Vec<u8> }
  pub struct WsMessageState { pub direction: String, pub opcode: String, pub data: Vec<u8> }
  pub enum FlowEffect { SetResponse { status: u16, headers: Vec<(String,String)>, body: Vec<u8> }, Intercept, Resume, Kill, Backup, Revert, Halt, DropWsMessage }
  impl FlowState {
      pub fn snapshot(flow: &aitm_core::Flow, ev: &aitm_core::Event, max_body: usize) -> Self;
      pub fn apply_to(self, ctx: &mut aitm_core::FlowCtx<'_>) -> aitm_core::Verdict;  // returns Halt iff a Halt effect present
  }
  ```
- **Change:** `snapshot` copies the mutable surface for the event's flow (bodies materialized up to `max_body`). `apply_to` writes changed request/response fields back via `ctx.flow_mut()`, then replays `effects` in order through the matching `FlowCtx` methods (`set_response`/`intercept`/`resume`/`kill`/`backup`/`revert`; `DropWsMessage` drops the frame), returning `Verdict::Halt` iff a `Halt` effect is present, else `Continue`.
- **Test** (construct a live `HttpFlow`/`WsFlow` + a `FlowCtx` test harness — builder's call on the harness):
  - `flow_state.rs::edits_apply_back`: snapshot an `HttpFlow`; set `request.method = "PUT"`, push header `("X","1")`; `apply_to(ctx)` → `ctx.flow()` request method `"PUT"` and header present.
  - `flow_state.rs::halt_effect_maps_to_verdict`: push `FlowEffect::Halt` → `apply_to` returns `Verdict::Halt`; with no effect → `Verdict::Continue`.
  - `flow_state.rs::set_response_effect_short_circuits`: push `SetResponse{status:403,…}` → after `apply_to`, the flow carries the 403 response.
  - `flow_state.rs::ws_drop_effect`: snapshot a `WsFlow` message, push `DropWsMessage` → the frame is dropped.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the four tests pass.

### Task 5: Rhai flow handles + registration (`flow_api.rs`)

- **Satisfies:** AC-M3-1 (mutation marshalling), AC-M3-2 (`halt()`/`set_response`), Review Focus #2 (body-size cap), ergonomics §2 rule 4.
- **Depends on:** Tasks 3, 4. **Independent:** yes.
- **Files:** Modify `src/flow_api.rs`; test `tests/flow_api.rs`.
- **Interfaces — Produces:**
  ```rust
  #[derive(Clone)] pub struct ScriptFlow(pub Arc<Mutex<FlowState>>);
  #[derive(Clone)] pub struct ScriptRequest(Arc<Mutex<FlowState>>);
  #[derive(Clone)] pub struct ScriptResponse(Arc<Mutex<FlowState>>);
  #[derive(Clone)] pub struct ScriptHeaders(Arc<Mutex<FlowState>>, HeaderSide);
  #[derive(Clone)] pub struct ScriptWsMessage(Arc<Mutex<FlowState>>);
  pub fn register_flow_api(engine: &mut rhai::Engine);  // getters/setters/indexers/methods per spec §5
  ```
- **Change:** register the types with `register_type_with_name`, the properties with `register_get_set`, header index access with `register_indexer_get_set`, and the methods (`mark`, `set_response`, `intercept`, `resume`, `kill`, `backup`, `revert`, `drop`, `set_text`, `set_json`, …). `halt()`/`continue()` are globals that push/skip `FlowEffect::Halt` on the shared state. Every getter/setter locks the shared `Mutex` and reads/writes `FlowState`; the body setter truncates at `RhaiLimits::max_string_size`.
- **Test** (register on a `build_engine` engine; push a `ScriptFlow` over a seeded `FlowState`; run a script; assert the `FlowState` after):
  - `flow_api.rs::script_sets_header_both_ways`: a script doing `flow.request.headers.set("X-A","1")` and `flow.request.headers["X-B"] = "2"` → state has both headers.
  - `flow_api.rs::script_reads_and_sets_request`: `flow.request.method = "PUT"; flow.request.url` returns the seeded URL; state method `"PUT"`.
  - `flow_api.rs::set_response_then_halt`: `flow.set_response(403, #{}, "no"); halt()` → state has a `SetResponse{status:403,…}` and a `Halt` effect.
  - `flow_api.rs::ws_message_drop_and_set_text`: `msg.set_text("redacted"); msg.drop()` → ws state body `"redacted"` and a `DropWsMessage` effect.
  - `flow_api.rs::forgiving_missing_header_read` (option C): `flow.request.headers.get("Nope")` on a flow without that header → `""` (not an error); `flow.request.query["absent"]` → `""`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the five tests pass.

### Task 6: Host core — services, findings, `log`/`finding`/`option` (`host_core.rs`)

- **Satisfies:** foundation; the `finding(...)` verb (spec §3).
- **Depends on:** Tasks 1, 3. **Independent:** yes — **P2**.
- **Files:** Modify `src/host_core.rs`; test `tests/host_core.rs`.
- **Interfaces — Produces:**
  ```rust
  #[derive(Clone)] pub struct ScriptServices { pub store: Arc<dyn aitm_core::FlowStore>, pub client: Arc<dyn aitm_core::ProxyClient>, pub browser: Option<Arc<dyn aitm_core::BrowserDriver>>, pub guard: Arc<dyn aitm_core::ScopeRateGuard>, pub findings: Arc<dyn FindingSink>, pub rt: tokio::runtime::Handle }
  pub trait FindingSink: Send + Sync { fn record(&self, f: Finding); fn list(&self) -> Vec<Finding>; }
  pub struct Finding { pub name: String, pub severity: aitm_poc::Severity, pub flow: Option<aitm_core::FlowId>, pub detail: Option<String>, pub tags: Vec<String>, pub source: String, pub at: std::time::SystemTime }
  pub struct MemoryFindingSink(/* Mutex<Vec<Finding>> */);  // default + test impl
  pub struct Options(/* BTreeMap<String, aitm_core::Value> */);
  // the protocol-extensible seam (spec §6a): one namespace of verbs == one provider
  pub trait ScriptCapability: Send + Sync { fn namespace(&self) -> &str; fn min_api(&self) -> &str; fn register(&self, engine: &mut rhai::Engine, services: &ScriptServices); }
  pub struct LogCapability; pub struct FindingCapability;   // M3's first providers (log/finding/option)
  ```
- **Change:** define the `ScriptCapability` seam and ship `LogCapability`/`FindingCapability` as the first providers. `log`/`log.info`/`warn`/`error` → `tracing`; `finding(map)` parses `#{name,severity,flow_id?,detail?,tags?}` (via `dynamic_to_value`) into a `Finding{source}` and calls `findings.record`; `option(name)` returns `value_to_dynamic(options.get(name))` or `()`. Each provider's `register` wires only its own namespace; the engine builder (Task 2/9) holds a `Vec<Arc<dyn ScriptCapability>>` and registers each.
- **Test:**
  - `host_core.rs::finding_records_fields`: a script `finding(#{ name:"x", severity:"medium", tags:["a"] })` with a `MemoryFindingSink` → `list()[0].name == "x"`, `.severity == Severity::Medium`, `.tags == ["a"]`, `.source` is the script name.
  - `host_core.rs::option_reads_set_value`: `Options` holding `tag → Str("v")`; script `option("tag")` → `"v"`; unknown key → `()`.
  - `host_core.rs::log_routes_to_tracing`: `log.warn("hi")` runs without error (asserted via a `tracing` capture layer).
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the three tests pass.

### Task 7: Guarded async host functions (`host_net.rs`)

- **Satisfies:** AC-M3-7, Review Focus #2, #3 (catchable guard error).
- **Depends on:** Task 6. **Independent:** no.
- **Files:** Modify `src/host_net.rs`; test `tests/host_net.rs`.
- **Interfaces — Produces:**
  ```rust
  // each is a ScriptCapability provider (spec §6a), not a bare register fn
  pub struct HttpCapability; pub struct BrowserCapability; pub struct StoreCapability; pub struct ScopeCapability;
  // Rhai-visible: http.send(#{..})->#{..}; browser.navigate/click/type/screenshot/eval/get_dom;
  //              store.get(id)/query(#{..}); scope.add(host)/list() — signatures per spec §6.
  ```
- **Change:** each capability is a `ScriptCapability` provider whose `register` wires its namespace; each verb holds `ScriptServices`. Async ones call `services.rt.block_on(fut)` (the enclosing hook has already entered `block_in_place`); the future is the existing guarded call (`guard.check_active` → `client.send` / `browser.*`). A `GuardError` maps to `Err(Box<EvalAltResult>)` whose message names the host and reason (catchable in Rhai). `store.*` reads the store; `scope.add/list` goes through the guard.
- **Test** (`#[tokio::test(flavor = "multi_thread")]`, stub `ScopeRateGuard`/`ProxyClient`/`FlowStore`):
  - `host_net.rs::out_of_scope_send_is_catchable` (RF#2/#3): guard refuses `evil.test`; script `try { http.send(#{method:"GET",url:"http://evil.test/"}); "sent" } catch(e) { "caught:" + e }` → result starts `"caught:"` and contains `"evil.test"`.
  - `host_net.rs::in_scope_send_returns_map`: guard allows; stub client returns a flow with status 200 → script `http.send(#{method:"GET",url:"http://ok.test/"}).status` → `200`.
  - `host_net.rs::navigate_ssrf_blocked`: SSRF guard blocks `127.0.0.1` → `browser.navigate("http://127.0.0.1/")` → catchable error containing `127.0.0.1`.
  - `host_net.rs::scope_add_then_list`: `scope.add("ok.test")` then `scope.list()` contains `"ok.test"`.
  - `host_net.rs::store_get_missing_is_null` (option C): `store.get("00000000-0000-0000-0000-000000000000")` for an id not in the store → `()` (forgiving), while a guard refusal (above) still throws — forgiveness covers absence, not denial.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(rhai): guarded http/browser/store/scope host fns via block_on`.
- **Done when:** the five tests pass.

### Task 8: `ScriptPlugin` + hook dispatch (`plugin.rs`)

- **Satisfies:** AC-M3-1, AC-M3-2, AC-M3-6 (plugin half), AC-M3-12; Review Focus #1, #3.
- **Depends on:** Tasks 2, 5, 6, 7. **Independent:** no.
- **Files:** Modify `src/plugin.rs`; test `tests/plugin.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct ScriptPlugin { /* name, Arc<Engine>, arc_swap::ArcSwap<rhai::AST>, ScriptServices, Arc<Options>, RhaiConfig snapshot */ }
  impl ScriptPlugin { pub fn meta(&self) -> &ScriptMeta; pub fn reload(&self, ast: rhai::AST); }
  impl aitm_core::Plugin for ScriptPlugin { fn name(&self) -> &str; fn load(&mut self, reg: &mut aitm_core::Registry); fn on_event(&mut self, ev: &aitm_core::Event, ctx: &mut aitm_core::FlowCtx<'_>) -> aitm_core::Verdict; }
  fn hook_for(ev: &aitm_core::Event) -> Option<&'static str>;  // Event variant -> hook name
  ```
- **Change:** `on_event` maps the event to a hook name; if the AST defines it, build a `ScriptFlow` over `FlowState::snapshot(ctx.flow(), ev, max_body)`, then `tokio::task::block_in_place(|| engine.call_fn::<rhai::Dynamic>(&mut scope, &ast, hook, (sflow,)))` (the start-`Instant` cell reset first). **On `Ok`** → `FlowState::apply_to(ctx)` and return its verdict. **On `Err`** (runtime/timeout/op-limit) → **discard the FlowState unapplied**, emit `Event::Error` with `FlowError::Protocol("script: …")`, log the `ScriptError`, return `Verdict::Continue`. `load` runs the script's `load(reg)` through the command/option bridge (Task 10).
- **Test** (register a `ScriptPlugin` + a probe plugin; drive events through a chain):
  - `plugin.rs::on_request_adds_header` (AC-M3-1): a script `on_request` setting `X-Aitm` → the forwarded request carries it.
  - `plugin.rs::set_response_halt_short_circuits` (AC-M3-2, RF#3): `flow.set_response(403,…); halt()` → client sees 403, chain returns `Halt`, the probe plugin after it never runs.
  - `plugin.rs::errored_hook_discards_edits` (AC-M3-12, RF#1): a hook that sets a header then `throw "boom"` → the flow is unchanged (no header), an `Event::Error` was emitted, dispatch returned `Continue`.
  - `plugin.rs::runaway_hook_aborts` (AC-M3-6): an `on_request` with `loop {}` and `max_operations` low → aborted, `Event::Error` emitted, the harness returns within `< 2s` (no stall).
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(rhai): ScriptPlugin hook dispatch — block_in_place, snapshot/apply, error isolation`.
- **Done when:** the four tests pass.

### Task 9: Loader + validation (`loader.rs`)

- **Satisfies:** AC-M3-9; AC-M3-4 (compile-once half).
- **Depends on:** Tasks 1, 2, 8. **Independent:** no.
- **Files:** Modify `src/loader.rs`; test `tests/loader.rs`, fixtures `tests/fixtures/{tagger.rhai,broken.rhai}`.
- **Interfaces — Produces:**
  ```rust
  pub struct RhaiLoader { /* Arc<Engine>, ScriptServices, RhaiConfig */ }
  impl RhaiLoader {
      pub fn new(cfg: RhaiConfig, services: ScriptServices) -> Result<Self, ScriptError>;
      pub fn load_all(&self) -> (Vec<ScriptPlugin>, Vec<ScriptError>);
      pub fn load_one(&self, entry: &ScriptEntry) -> Result<ScriptPlugin, ScriptError>;
      pub fn validate(&self, path: &Path) -> Result<ScriptMeta, ScriptError>;
  }
  ```
- **Change:** `new` builds one shared hardened `Arc<Engine>` (Task 2) and registers the whole surface (flow API, host core, host net) once. `load_one` reads the file, `engine.compile` → `AST`, extracts `ScriptMeta` (`NAME` const or file stem; `API`; hook names present), checks `API` against the supported version (`ApiVersion` warning on mismatch), wraps in a `ScriptPlugin`. `load_all` iterates `cfg.scripts` where `enabled`; a `Compile` error is collected (skip-and-log) unless `cfg.strict`, in which case `load_all`'s error vec is returned and the caller fails fast. `validate` compiles without building a plugin.
- **Test:**
  - `loader.rs::load_all_skips_broken` (AC-M3-9): `cfg.scripts = [tagger, broken]`, `strict=false` → one `ScriptPlugin` named `"tagger"`, one `ScriptError::Compile` whose `line`/`column` are set and `script == "broken"`.
  - `loader.rs::strict_surfaces_errors`: same with `strict=true` → the returned error vec is non-empty (caller fails fast).
  - `loader.rs::validate_good_and_bad`: `validate(tagger)` → `Ok(meta)` with `meta.name == "tagger"` and `"on_request"` in `meta.hooks`; `validate(broken)` → `Err(Compile{…})`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the three tests pass.

### Task 10: Script-registered commands + options (`command.rs`)

- **Satisfies:** AC-M3-3 (Registry level).
- **Depends on:** Tasks 6, 9. **Independent:** no — **P3** with Task 13.
- **Files:** Modify `src/command.rs`; test `tests/command.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct ScriptCommand { /* name, desc, Arc<Engine>, Arc<AST>, FnPtr/name, ScriptServices */ }
  impl aitm_core::Command for ScriptCommand { fn name(&self) -> &str; fn schema(&self) -> aitm_core::ParamSchema; fn invoke(&self, args: aitm_core::Params, host: &aitm_core::CommandHost) -> anyhow::Result<aitm_core::Value>; }
  pub struct ScriptRegHandle<'a> { /* &mut Registry + collected options */ }  // what the script's load(reg) drives
  ```
- **Change:** the `load(reg)` bridge exposes `reg.add_command(name, desc, fnptr)` → constructs a `ScriptCommand` (schema: one `args` object param, `Any` result per spec §9) and `reg.add_command(Arc::new(it))`; `reg.add_option(name, default, desc)` records into `Options`. `invoke` marshals `Params`→Rhai map, `block_in_place(|| call)`, marshals the result via `dynamic_to_value`.
- **Test:**
  - `command.rs::script_command_registers_and_invokes` (AC-M3-3): load a script whose `load` does `reg.add_command("demo.ping","", |args| "pong")`; `registry.command("demo.ping")` is `Some`; `invoke(Params::empty(), &host)` → `Value::Str("pong")`.
  - `command.rs::script_option_registered`: a script registering `tag` default `"v"` → `Options` returns `"v"`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the two tests pass.

### Task 11: Bundled prelude (`prelude.rs` + `prelude.rhai`)

- **Satisfies:** spec §2a (the prelude layer).
- **Depends on:** Task 2. **Independent:** yes — **P2**.
- **Files:** Modify `src/prelude.rs`, `src/prelude.rhai`; test `tests/prelude.rs`.
- **Interfaces — Produces:** `pub const PRELUDE_SRC: &str = include_str!("prelude.rhai");` `pub fn load_prelude(engine: &rhai::Engine) -> Result<rhai::Module, ScriptError>;` and a hook the loader calls to make it globally available (`register_global_module`).
- **Change:** `prelude.rhai` holds the initial sugar — `fn ok(resp) { resp.status >= 200 && resp.status < 300 }`, `fn contains_ci(hay, needle) { hay.to_lower().contains(needle.to_lower()) }`, `fn json(m) { … }` (builder fills bodies) — plain Rhai, compiled once under the hardened engine; exposed so every script and PoC step can call it.
- **Test:**
  - `prelude.rs::prelude_compiles_hardened`: `load_prelude(&build_engine(&RhaiLimits::default(), 2s))` → `Ok`.
  - `prelude.rs::helper_callable_from_script`: with the prelude registered, a script `contains_ci("AbC", "abc")` → `true`; `ok(#{status:204})` → `true`, `ok(#{status:500})` → `false`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit.
- **Done when:** the two tests pass.

### Task 12: `aitm-poc` — `Step::Script` + `ScriptStep` (`model.rs`)

- **Satisfies:** AC-M3-11 (round-trip half).
- **Depends on:** none (different crate). **Independent:** yes — **P1**.
- **Files:** Modify `crates/aitm-poc/src/model.rs` (variant + struct + the two serde arms); test `crates/aitm-poc/tests/script_step.rs`.
- **Interfaces — Produces:** `pub struct ScriptStep { pub script: String, #[serde(default, skip_serializing_if="Option::is_none")] pub name: Option<String> }` and `Step::Script(ScriptStep)`.
- **Change:** add `Script(ScriptStep)` to the `Step` enum; in `Serialize` add the `Step::Script(s) => ("script", to_value(s))` arm; in `Deserialize` add `"script" => Ok(Step::Script(from_value(inner)?))`. (`ScriptStep` is reached as `aitm_poc::model::ScriptStep`; the crate re-export is added in Task 13 to keep `lib.rs` single-writer.)
- **Test:**
  - `script_step.rs::script_step_round_trips` (AC-M3-11): a one-step PoC YAML `steps: [ { script: { name: s, script: "return pass;" } } ]` deserializes to `Step::Script(ScriptStep{ script:"return pass;", name:Some("s") })` and re-serializes to equal YAML.
  - `script_step.rs::unknown_step_still_errors`: a step `{ frobnicate: {} }` → `Err` containing `unknown step type`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(poc): Step::Script / ScriptStep additive variant`.
- **Done when:** the two tests pass.

### Task 13: `aitm-poc` — `ScriptStepExecutor` seam + runner wiring (`runner.rs`)

- **Satisfies:** AC-M3-8 (seam half), AC-M3-11 (missing-executor error), Review Focus #5.
- **Depends on:** Task 12. **Independent:** no — **P3** with Task 10.
- **Files:** Modify `crates/aitm-poc/src/runner.rs`, `crates/aitm-poc/src/lib.rs` (re-exports for `ScriptStep` + the new runner types); `crates/aitm-poc/src/matcher.rs` (resolve `step("name")` against step results — only if `step()` is not already wired). Test: `crates/aitm-poc/tests/script_runner.rs`.
- **Interfaces — Produces:**
  ```rust
  pub trait ScriptStepExecutor: Send + Sync { fn run_step(&self, step: &crate::model::ScriptStep, ctx: &mut ScriptStepCtx<'_>) -> Result<ScriptVerdict, ScriptStepError>; }
  pub struct ScriptStepCtx<'a> { pub vars: &'a mut VarBindings, pub host: &'a CommandHost<'a>, pub step_results: &'a mut std::collections::BTreeMap<String, StepOutcome>, pub artifacts: &'a mut Vec<PathBuf> }
  pub enum ScriptVerdict { Pass, Fail, Neutral }
  pub enum StepOutcome { Matched, NotMatched, Pass, Fail, Error }
  pub struct ScriptStepError(/* message */);
  impl StdPocRunner { pub fn with_script_executor(self, exec: Arc<dyn ScriptStepExecutor>) -> Self; }
  ```
- **Change:** add an `Option<Arc<dyn ScriptStepExecutor>>` field to `StdPocRunner` (replace `#[derive(Debug)]` with a manual `Debug` printing `out_dir` + whether an executor is set; `Clone` still derives). In `run_inner`, a `Step::Script(s)` with no executor → `Err` "script steps require the Rhai runtime (wire a ScriptStepExecutor)"; with one, call `run_step`, map `ScriptVerdict`→`StepOutcome` (`Neutral→Neutral`? resolve via the map), record under `s.name` (default an index-based name). `success`'s `step("name")` resolves to the recorded `StepOutcome` string (`"pass"`/`"fail"`/`"neutral"`/`"error"`/`"matched"`).
- **Test** (a stub `ScriptStepExecutor` returning a fixed verdict):
  - `script_runner.rs::pass_verdict_satisfies_success` (AC-M3-8 seam): executor returns `Pass`; a PoC `success: [{ dsl: 'step("s") == "pass"' }]` → `result.passed == true`.
  - `script_runner.rs::fail_verdict`: executor returns `Fail` → `passed == false`.
  - `script_step_neutral_and_error_resolve` (RF#5): `Neutral` → `step("s") == "neutral"`; an executor `Err` → `step("s") == "error"`, no panic.
  - `script_runner.rs::missing_executor_errors` (AC-M3-11): no executor + a `Step::Script` → `run` returns `Err` containing `require the Rhai runtime`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(poc): ScriptStepExecutor seam, runner dispatch + step() resolution`.
- **Done when:** the four tests pass.

### Task 14: `RhaiScriptExecutor` — the PoC step impl (`poc_step.rs`)

- **Satisfies:** AC-M3-8 (impl half).
- **Depends on:** Tasks 7, 11, 13. **Independent:** no.
- **Files:** Modify `crates/aitm-plugin-rhai/src/poc_step.rs`; test `crates/aitm-plugin-rhai/tests/poc_step.rs`.
- **Interfaces — Produces:**
  ```rust
  pub struct RhaiScriptExecutor { /* Arc<Engine>, ScriptServices */ }
  impl RhaiScriptExecutor { pub fn new(engine: Arc<rhai::Engine>, services: ScriptServices) -> Self; }
  impl aitm_poc::ScriptStepExecutor for RhaiScriptExecutor { fn run_step(&self, step, ctx) -> Result<aitm_poc::ScriptVerdict, aitm_poc::ScriptStepError>; }
  #[derive(Clone)] pub struct ScriptVars(Arc<Mutex<VarBindings>>);  // vars.get / vars.set
  ```
- **Change:** compile `step.script` (cache by content hash — builder's call), build a `Scope` with a `ScriptVars` handle over `ctx.vars` and the host namespaces registered, run `eval_ast_with_scope` under `block_in_place` + budget. Interpret the returned value: the globals `pass`/`fail` map to `ScriptVerdict::Pass`/`Fail`, falling off the end → `Neutral`; a sandbox/timeout/op error → `ScriptStepError`. `vars.set` writes back through the shared `Arc<Mutex<VarBindings>>`. `browser.screenshot()` returns the screenshot **bytes** (a `Blob`) to the script; in M3 a *script step* does **not** auto-promote a screenshot to a PoC artifact file — the declarative `screenshot` step is what produces the artifact. (OQ8/Task-15 resolution, option C, Matt via orchestrator 2026-10-27: script-step screenshot-artifact promotion is a deferred follow-up; `ScriptStepCtx` and `host_net` are not changed for it. `ctx.artifacts` stays in the seam, unpopulated from scripts in M3.)
- **Test** (`multi_thread`, stub services):
  - `poc_step.rs::reads_and_sets_vars`: a step `vars.set("x", "1"); return pass;` → `ScriptVerdict::Pass` and `ctx.vars` has `x == "1"`.
  - `poc_step.rs::guarded_call_enforced`: a step calling `http.send` to an out-of-scope host (stub guard refuses) with no `try`/`catch` → `ScriptStepError` (guarded, not a panic).
  - `poc_step.rs::sandbox_denial_is_error`: a step doing a disallowed op → `ScriptStepError`.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(rhai): RhaiScriptExecutor — PoC script step over the shared engine`.
- **Done when:** the three tests pass.

### Task 15: Public surface, binary wiring, ordering, config + e2e

- **Satisfies:** AC-M3-3 (over MCP+CLI), AC-M3-4, AC-M3-5 (e2e), AC-M3-7 (e2e), AC-M3-8 (e2e), AC-M3-10; Review Focus #6.
- **Depends on:** all prior. **Independent:** no (converges the plan).
- **Files:** Modify `crates/aitm-plugin-rhai/src/lib.rs` (curated `pub use` re-exports), create `crates/aitm-plugin-rhai/src/wire.rs` (`load_scripts` convenience + `RhaiScriptExecutor` constructor from a loader); modify the `aitm` binary wiring (`crates/aitm/src/…`) and its config file handling (additive `scripts:` / `rhai:` YAML sections — landed against the M2 config form; spec OQ8); create example fixtures `crates/aitm/examples/addons/{tagger.rhai,guard-admin-writes.rhai}` and `crates/aitm/examples/poc/authed-stored-xss-notes.yaml` (the spec's worked examples, verbatim); tests `crates/aitm/tests/rhai_e2e.rs`.
- **Interfaces — Produces:** `aitm_plugin_rhai::{RhaiLoader, ScriptPlugin, ScriptServices, RhaiScriptExecutor, RhaiConfig, RhaiLimits, ScriptError, Finding, FindingSink}` (re-exports); `pub fn wire::load_scripts(cfg: RhaiConfig, services: ScriptServices) -> (Vec<ScriptPlugin>, Vec<ScriptError>)`.
- **Change:** the binary builds `ScriptServices` from the proxy's live handles (`store`/`client`/`browser`/`guard`/runtime `Handle`) + a `FindingSink`, runs the loader, and **registers plugins natives-first, then script plugins in declaration order** (config entries then `--script`), per spec §8. The same shared engine backs a `RhaiScriptExecutor` wired into the `StdPocRunner` via `with_script_executor`. Config gains `scripts:` (list of `{path, options, enabled}`) and `rhai:` (the `RhaiLimits` + `hook_timeout` + `strict`).
- **Test:**
  - `rhai_e2e.rs::chain_order_natives_then_scripts` (AC-M3-10): a native probe plugin and a script plugin registered via the wiring receive a request in declaration order; a script `halt()` stops a native plugin registered after it.
  - `rhai_e2e.rs::script_added_without_rebuild` (AC-M3-4): loading an extra `--script` entry changes observed behaviour using the already-built binary under test (no recompile in the test body).
  - `rhai_e2e.rs::script_command_over_frontends` (AC-M3-3): a script-registered `demo.ping` appears in the MCP `tools/list` enumeration and returns `"pong"` via the CLI dispatch path.
  - `rhai_e2e.rs::poc_script_step_pass_vs_patched` (AC-M3-8, `#[ignore]` unless `AITM_OBSCURA=1`/`AITM_CHROME=1`): running `authed-stored-xss-notes.yaml` via `poc.run` with the wired `RhaiScriptExecutor` returns **pass** against the bundled vulnerable target and **fail** against the patched variant.
  - `rhai_e2e.rs::script_cannot_escape_or_exceed_scope` (AC-M3-5/7): a script reading a file → sandbox error; `http.send` to an out-of-scope host → guard refusal; proxy keeps serving.
  - [ ] Tests → FAIL → implement wiring + re-exports + config + fixtures → PASS → gate → commit `feat(rhai): binary wiring, chain ordering, config, worked-example fixtures, e2e`.
- **Done when:** the hermetic e2e tests pass, the browser-gated one passes under the gate flag, and the full workspace gate is green.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

### Deferred follow-ups

- **Script-step screenshot → PoC artifact file.** Task 14 flagged, Task 15
  resolved as option C (Matt via orchestrator, 2026-10-27): in M3 a PoC `script`
  step's `browser.screenshot()` returns the screenshot bytes to the script but is
  **not** auto-promoted to a run-artifact file; the declarative `screenshot` step
  remains how a PoC produces that artifact. `ScriptStepCtx.artifacts` stays as the
  seam (unpopulated from scripts in M3). A later milestone can populate it by
  giving the browser screenshot verb a per-run artifact sink and `ScriptStepCtx`
  an output directory — deliberately deferred to avoid a late interface change to
  Task 13's `ScriptStepCtx` and a non-additive edit to Task 7's `host_net.rs` at
  convergence.
