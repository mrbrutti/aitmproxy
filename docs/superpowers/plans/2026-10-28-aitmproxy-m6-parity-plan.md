# aitmproxy Milestone 6 Implementation Plan — mitmproxy/Proxyman feature parity (five additive items)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** approved (2026-10-28 by Matt)
**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-m6-parity-design.md` (approved 2026-10-28 by Matt; §0 shared rule model, §1 F3, §2 F9, §3 F10, §4 F11, §5 Map Local/Remote, AC-R*, AC-F3.*, AC-F9.*, AC-F10.*, AC-F11.*, AC-M*). **§6 HTTP/2 and AC-H2.* are OUT OF SCOPE — deferred to M7 per Open Question 1.**
**Branch / worktree:** `feat/m6-parity`, one worktree, cut from `main`. The spec and this plan are committed on `claude/m6-parity-spec-0a023d`.

**Goal:** Close the five additive parity gaps — F3 (selective + response-phase interception + kill modes), F9 (WebSocket inject/edit/drop), F10 (sessions + HAR import/export), F11 (per-host TLS passthrough), and Map Local/Remote — additively over the existing `Flow`/`Event`/`Plugin`/`Command`/`ProtocolModule` seams on `main`, behind one shared `aitm-rules` match model, with `aitm-core` touched only where named and justified, and every in-scope AC green under the Rust gate.

**Architecture:** One new leaf crate `aitm-rules` lands first and is the only hard cross-feature dependency (F3, F9, Map reuse it). F3 extends the existing `intercept` plugin and the `mutate` command schema in place. F9/F10/F11/Map are each a new first-party plugin crate (`aitm-plugin-wsctl`, `-sessionio`, `-passthrough`, `-maprules`) registered into the existing `Registry`; two of them (`wsctl`, `passthrough`) also make a named additive change in a `aitm-proto-*` crate (the WS live-inject channel and the TLS-passthrough `ProtocolModule`). Active-egress commands (`ws.send`, Map Remote) ride the existing `ScopeRateGuard::check_active`; behaviour-changing config (passthrough list, map rules) is agent-gated by a config flag defaulting off. The binary wiring and the additive `aitm-core` `Config` fields converge in the final task so `config.rs` and `wire.rs` have a single writer.

## Global constraints

Every task's requirements implicitly include these (verbatim from the spec/WORKFLOW):

- **Gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` must pass before any review, per task. TDD: write the failing test first, watch it fail, write the minimum to pass, watch it pass. The Coder's report includes both runs.
- **`unsafe` stays forbidden.** The workspace sets `unsafe_code = "forbid"`. A task reaching for `unsafe` has mis-designed and must stop and report.
- **Additive-only core.** New behaviour is new crates/plugins/commands registered into the existing `Registry`. `Flow`/`Event`/`InterceptState`/`FlowCtx`/`Command`/`ProtocolModule`/`NextLayerHint` shapes are **reused, not changed**. The only permitted `aitm-core` edits in M6 are **additive `Config` fields** (`Config.tls`, `Config.maps`), landed in Task 14 and named there; any other core touch means the task mis-read the seam — stop and report (WORKFLOW "stop on gaps").
- **Deny-by-default, one guard.** Every command causing active egress (`ws.send`, Map Remote redirect) calls `ScopeRateGuard::check_active(authority)` and is refused (`invoke` returns `Err`, surfaced as `isError: true`) when out of scope. Agent (`Frontend::Mcp`) mutation of behaviour-changing config (`tls.passthrough.*`, `map.add`/`map.remove`) is gated by a bool defaulting **off** (`allow_agent_passthrough`, `maps.allow_agent_authoring`), mirroring `scope.allow_agent_widen`.
- **Config via YAML, `deny_unknown_fields`.** New config parses from the same YAML file and errors on an unknown key (Task 14).
- **Declared signatures are authoritative.** Types/signatures in each task's Interfaces block are copied exactly; bodies and in-module file layout are the builder's.
- **Flow types are not `serde`-derivable.** `aitm-core`'s `Flow`/`HttpFlow`/`WsFlow`/`Body` do **not** derive `Serialize`/`Deserialize` (and `Body::Streamed` cannot round-trip). The session/HAR crate defines its own serde mirror structs and converts to/from `Flow`; it never adds a derive to `aitm-core` (that would be a non-additive core edit).
- **Tests are hermetic.** Unit/integration tests register the plugin/module and drive commands through the `Registry`, standing up an in-process echo/WS/TLS server where egress is asserted. Port-binding e2e is gated/skipped where the sandbox forbids binding (`CLAUDE.md`); prefer a loopback listener the test owns.
- **Git/gh run through the Terminal panel** (`run_in_terminal`), never the sandboxed shell (`CLAUDE.md`). Commit after each task.

## Review focus

Input classes the spec implies but a happy path does not exercise; each is pinned to a test in its task:

1. **Response-phase park timing.** A response parked for edit must suspend **before the client receives the response head/body**. In `aitm-proto-http` the body is streamed to the client between the `ResponseHeaders` emit and the `Response` emit, so a `Phase::Response` rule must fire at the **`ResponseHeaders`** await point, not the `Response` one. Verified in Task 2, relied on in Task 4. (See Plan-level call 1.)
2. **A concurrent non-matching flow is untouched.** Selective interception must park *only* matching flows; a sibling request in flight must complete normally, not block behind the parked one. Pinned in Task 3 (`non_matching_flow_not_parked`).
3. **`ws.send` to an out-of-scope host.** Must be a catchable guard refusal naming the host, not a panic and not a silent send. Pinned in Task 7 (`ws_send_out_of_scope_refused`).
4. **Import never replays.** `flow.import`/`session.load` populate the store and make **zero** upstream requests; no convenience replay-on-import. Pinned in Task 8 (`import_is_passive`).
5. **Passthrough leaks nothing to MITM, and MITM still works alongside it.** A passthrough host yields the real upstream cert and no decrypted `HttpFlow`; a non-passthrough host on the same proxy is still MITM'd. Pinned in Task 11 (`passthrough_tunnels_mitm_still_decrypts`).
6. **Map Local path confinement.** A `path` escaping the configured map root is rejected at `map.add` time (not at serve time), with no file read. Pinned in Task 12 (`map_local_path_escape_rejected`).
7. **Map Remote cannot smuggle egress past scope.** A rewrite to an out-of-scope host is refused and the original request is **not** sent upstream either. Pinned in Task 13 (`map_remote_out_of_scope_refused`).

---

## Overview

Task 1 (`aitm-rules`) and Task 2 (a response-await characterization check in `aitm-proto-http`) are the foundation and run first and in parallel. Task 2 is deliberately early so a Coder confirms the response-phase park point **before** Task 4 builds on it. After Task 1, the five features fan out into five independent sub-chains that touch disjoint crates/files; Task 14 converges them in the binary wiring and the additive `Config` fields.

**Parallel groups (disjoint files; "∥" = may run as concurrent child sessions):**

| Wave | Tasks | Why disjoint |
|---|---|---|
| **W0 (start)** | 1 ∥ 2 ∥ 8 ∥ 10 | `aitm-rules` (new) ∥ `aitm-proto-http/module.rs` (test-only/additive) ∥ `aitm-plugin-sessionio` (new) ∥ `aitm-plugin-passthrough` (new) + its own types |
| **W1 (after 1; 4 also after 2)** | 3 ∥ 6 ∥ 12 ∥ 9 ∥ 11 | `aitm-plugins/intercept.rs` ∥ `aitm-plugin-wsctl` (new) ∥ `aitm-plugin-maprules` (new) ∥ `-sessionio` (after 8) ∥ `-passthrough` module (after 10) |
| **W2 (within chains)** | 4→5 (F3) · 7 (F9) · 13 (Map) | F3 sub-chain on `intercept.rs`+`mutate.rs`; 7 on `wsctl`+`aitm-proto-ws`; 13 on `maprules` |
| **W3 (convergence)** | 14 | `aitm/src/wire.rs`, `aitm/src/config_file.rs`, `aitm-core/src/config.rs` |

Longest sequential chain: 1 → 3 → 4 → 5 → 14 (five tasks). The F9 chain (1 → 6 → 7 → 14), Map chain (1 → 12 → 13 → 14), F10 chain (8 → 9 → 14) and F11 chain (10 → 11 → 14) converge only at Task 14.

**Sub-chain file ownership (so two writers never share a file):**

- F3 → `crates/aitm-plugins/src/intercept.rs` (T3, T4, T5) + `crates/aitm-plugins/src/mutate.rs` (T4 only).
- F9 → `crates/aitm-plugin-wsctl/**` (T6, T7) + `crates/aitm-proto-ws/src/module.rs` & `src/lib.rs` (T7 only).
- F10 → `crates/aitm-plugin-sessionio/**` (T8, T9).
- F11 → `crates/aitm-plugin-passthrough/**` (T10, T11).
- Map → `crates/aitm-plugin-maprules/**` (T12, T13).
- Foundation → `crates/aitm-rules/**` (T1); `crates/aitm-proto-http/**` (T2).
- Convergence → `crates/aitm/**` + `crates/aitm-core/src/config.rs` (T14 only).

---

## Tasks

### Task 1: `aitm-rules` crate — shared match model + `matches` + regex validation

- **Satisfies:** AC-R1, AC-R2 (crate half). Foundation for F3 (T3–T5), F9 (T6–T7), Map (T12–T13).
- **Depends on:** none. **Independent:** yes — **W0**. Blocks T3, T6, T12.
- **Files:** Create `crates/aitm-rules/Cargo.toml`, `crates/aitm-rules/src/lib.rs`; tests `crates/aitm-rules/tests/matches.rs`. Modify root `Cargo.toml` (add workspace member + `aitm-rules = { path = "crates/aitm-rules" }`). Depends only on `aitm-core` (for `Flow`/`WsDir`) and `regex`.
- **Interfaces — Produces** (copied from spec §0; add `compile`/validation):
  ```rust
  pub struct Rule { pub id: String, pub name: Option<String>, pub enabled: bool, pub condition: MatchCondition }
  pub struct MatchCondition { pub url: Option<UrlMatch>, pub method: Option<String>, pub host: Option<HostMatch>, pub phase: Phase, pub ws_dir: Option<aitm_core::WsDir> }
  pub enum UrlMatch { Wildcard(String), Regex(String) }
  pub enum HostMatch { Exact(String), Wildcard(String) }
  pub enum Phase { Request, Response, WsFrame, Any }
  /// Validate + pre-compile a condition (compiles any Regex once); Err on a bad pattern.
  pub struct CompiledRule { /* Rule + compiled regex */ }
  pub fn compile(rule: Rule) -> Result<CompiledRule, RuleError>;
  pub enum RuleError { BadRegex { pattern: String, message: String } }
  /// The one matcher reused everywhere. `phase`/`dir` come from the dispatching plugin.
  impl CompiledRule { pub fn matches(&self, flow: &aitm_core::Flow, phase: Phase, dir: Option<aitm_core::WsDir>) -> bool; }
  ```
- **Change:** `matches` returns `true` iff the rule is enabled, its `phase` is `Any` or equals the dispatch phase, and every present condition clause matches: `UrlMatch::Wildcard` via glob semantics over `scheme://authority/path?query` (`*` = any run), `UrlMatch::Regex` via the compiled `regex::Regex`, `method` case-insensitive exact, `HostMatch` against the authority, `ws_dir` against `dir`. `compile` rejects an invalid regex with `RuleError::BadRegex` (no panic). Regex compiled once at `compile` time, reused per event.
- **Test** (`matches.rs`):
  - `wildcard_login_matches` (AC-R1): `compile(rule with UrlMatch::Wildcard("*/login"), phase Request)`; against a flow whose path is `/api/login` → `matches(..) == true`; against `/api/logout` → `false`.
  - `regex_users_matches` (AC-R2): `UrlMatch::Regex("^/v[0-9]+/users$")` matches a flow at `/v2/users` (`true`) and not `/v2/users/1` (`false`).
  - `invalid_regex_rejected` (AC-R2): `compile(rule with UrlMatch::Regex("[unterminated"))` → `Err(RuleError::BadRegex { .. })`, **not** a panic.
  - [ ] Scaffold crate + member → `cargo build -p aitm-rules`. Tests → FAIL → implement → PASS → gate → commit `feat(rules): aitm-rules shared match model, compile + matches`.
- **Done when:** the three tests pass and the workspace builds with the new member.

### Task 2: Verify the response-phase emit/await point in `aitm-proto-http` (early risk check)

- **Satisfies:** foundation for AC-F3.2 (de-risks Task 4). Review focus #1.
- **Depends on:** none. **Independent:** yes — **W0** (touches only `aitm-proto-http`). Blocks T4.
- **Files:** Create `crates/aitm-proto-http/tests/response_park.rs`. Modify `crates/aitm-proto-http/src/module.rs` **only if** the characterization test proves the response head reaches the client before a park can suspend it (fallback additive fix; see Change).
- **Interfaces — Produces:** no new public API in the happy path (a characterization test). If a fix is needed it is a local, additive change inside `module.rs`'s response loop (no signature change, no `aitm-core` edit).
- **Change:** Stand up a loopback origin and a test plugin that calls `FlowCtx::intercept()` on `Event::ResponseHeaders`. Drive one request through `HttpModule`. Assert the client socket receives **no** response bytes until a resume fires, then receives the response. Because `Chain::dispatch` awaits the parked receiver inside `ModuleCtx::emit`, and `module.rs` awaits `ctx.emit(Event::ResponseHeaders(id))` **before** `machine.enqueue_response`/`flush` to the client, this should already hold. **If it does not**, add the missing await/suspension at the `ResponseHeaders` point in `module.rs` (additive, within this crate — never in `aitm-core`) and re-run. Document in the test which emit point (`ResponseHeaders`) is the authoritative response-park suspension point for Task 4.
- **Test** (`response_park.rs`):
  - `response_headers_park_suspends_client` (RF#1): a plugin parking on `Event::ResponseHeaders` → the client reads zero response bytes before resume; after the paired `ResumeHandle` fires, the client reads the full response. Asserts suspension happens at the `ResponseHeaders` await.
  - `response_phase_emit_is_awaited`: a plugin that records event order confirms `ResponseHeaders` is dispatched-and-awaited before the first client body byte (the module streams body between `ResponseHeaders` and `Response`).
  - [ ] Tests → FAIL or PASS as characterization → (fix in `module.rs` only if red) → gate → commit `test(proto-http): characterize response-phase park suspension point`.
- **Done when:** both tests pass, proving (or making true) that `Phase::Response` interception suspends the client at the `ResponseHeaders` emit, and the finding is recorded in the test module docstring for Task 4.

### Task 3: F3 — selective, rule-based request-phase interception (`intercept` plugin)

- **Satisfies:** AC-F3.1. Review focus #2.
- **Depends on:** Task 1. **Independent head of the F3 chain** — **W1**.
- **Files:** Modify `crates/aitm-plugins/src/intercept.rs`; test `crates/aitm-plugins/tests/intercept_rules.rs` (create). Add `aitm-rules` to `crates/aitm-plugins/Cargo.toml`.
- **Interfaces — Changes** `flow.intercept` additively (back-compatible):
  ```rust
  // flow.intercept {enabled?: bool, rules?: [Rule]} -> {enabled: bool, rules: [Rule]}
  // Shared state gains the active compiled rules:
  struct Shared { armed: Arc<AtomicBool>, parked: Mutex<HashMap<FlowId, ResumeHandle>>, rules: Mutex<Vec<aitm_rules::CompiledRule>> }
  ```
  Schema: `flow.intercept` gains an optional `rules` param (`Array(Object(..))`) and now returns an object `{enabled, rules}`. An invalid regex in a rule makes `invoke` return `Err` (`isError: true`).
- **Change:** `invoke` compiles each supplied rule via `aitm_rules::compile` (collecting a `Vec<CompiledRule>`); a compile error aborts with `Err`. `on_event`: when `armed` and `rules` is **empty**, park every `Event::Request` (today's global behaviour, unchanged). When `rules` is non-empty, park a flow only if some rule `matches(flow, Phase::Request, None)` at the request phase. Non-matching flows return `Verdict::Continue` and are never parked. (Response-phase rules are handled in Task 4; this task wires `Phase::Request`/`Phase::Any` at the request event only.)
- **Test** (`intercept_rules.rs`, driving events through a `Chain` + store harness):
  - `matching_request_parks` (AC-F3.1): arm with `rules:[{url:"*/admin", phase:"request"}]`; a request to `/admin` → its stored `InterceptState` is `Intercepted`.
  - `non_matching_flow_not_parked` (AC-F3.1, RF#2): with the same rule, a concurrent request to `/public` is **not** parked (`InterceptState` is `Observed`/`Resumed`) and dispatch returns `Continue`.
  - `global_arm_still_parks_all` (back-compat): `enabled:true` with no `rules` parks every request (unchanged).
  - `invalid_rule_regex_is_error`: `flow.intercept` with a rule carrying `UrlMatch::Regex("[bad")` → `invoke` returns `Err` (`isError: true`), rules unchanged.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(intercept): rule-based selective request interception`.
- **Done when:** the four tests pass.

### Task 4: F3 — response-phase park + `flow.mutate status` response edit

- **Satisfies:** AC-F3.2.
- **Depends on:** Task 1, Task 2 (response-park point), Task 3 (same file `intercept.rs`). **Sequential** after Task 3.
- **Files:** Modify `crates/aitm-plugins/src/intercept.rs` (response-phase parking) and `crates/aitm-plugins/src/mutate.rs` (`status` edit on a parked response); test `crates/aitm-plugins/tests/response_edit.rs` (create).
- **Interfaces — Changes:**
  ```rust
  // flow.mutate {id, edits:{method?, path?, headers?, body?, status?}} -> FlowId
  // apply_edits gains a response path; status? only valid when editing a response.
  fn apply_response_edits(resp: &mut HttpResponse, edits: &BTreeMap<String, Value>) -> anyhow::Result<()>;
  ```
- **Change:** `intercept` plugin: on `Event::ResponseHeaders` (the suspension point Task 2 pinned), if a rule `matches(flow, Phase::Response, None)` (or `Phase::Any`), back up and `FlowCtx::intercept()` to park the response before any byte reaches the client. `flow.mutate`: pick the edit target by state — if the flow is `Intercepted` and carries a `response`, edits apply to `f.response` and `status` is accepted (sets `resp.status`); otherwise edits apply to the request and a `status` key is rejected with `Err`. On resume, `aitm-proto-http`'s existing re-read of the stored response (module.rs:573) forwards the edited status/headers/body.
- **Test** (`response_edit.rs`, loopback origin + `HttpModule` + `Chain`):
  - `response_status_edited_then_resumed` (AC-F3.2): arm `flow.intercept {rules:[{phase:"response"}]}`; the flow parks at the response phase; `flow.mutate {id, edits:{status:418}}` then `flow.resume` → the client receives HTTP **418** with the edited body.
  - `status_edit_rejected_on_request_phase`: `flow.mutate {edits:{status:200}}` on a request-phase-parked (or non-parked) flow → `Err` (`status` not valid for a request).
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(intercept,mutate): response-phase park + flow.mutate status edit`.
- **Done when:** both tests pass and the client observably receives the edited status.

### Task 5: F3 — `flow.kill` abort modes (reset / 429 / 503)

- **Satisfies:** AC-F3.3.
- **Depends on:** Task 3 (same file `intercept.rs`). **Sequential** after Task 3 (independent of Task 4; order 5 after 4 to serialize `intercept.rs` writes).
- **Files:** Modify `crates/aitm-plugins/src/intercept.rs`; test `crates/aitm-plugins/tests/kill_modes.rs` (create).
- **Interfaces — Changes** `flow.kill`:
  ```rust
  // flow.kill {id: FlowId, mode?: "reset" | "429" | "503"} -> ok
  ```
  Schema gains an optional `mode` param (default `"reset"`).
- **Change:** `reset` (and default/absent) keeps `InterceptState::Killed` → client sees a reset/closed connection, no upstream (unchanged). `"429"`/`"503"` build a minimal `HttpResponse` with that status and an empty body, call `FlowCtx::set_response` (via the stored flow update) then release/resume the parked flow so `aitm-proto-http` short-circuits to the client — no upstream connection is opened. An invalid `mode` string → `Err`.
- **Test** (`kill_modes.rs`, loopback origin that counts received requests):
  - `kill_429_synthesizes_response` (AC-F3.3): park a request, `flow.kill {mode:"429"}` → client receives HTTP **429**, and the upstream request counter is **0** for that flow.
  - `kill_reset_closes_connection` (AC-F3.3): `flow.kill` with no `mode` (and `mode:"reset"`) → the client sees a closed/reset connection, upstream counter **0**.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(intercept): flow.kill reset/429/503 abort modes`.
- **Done when:** both tests pass and the upstream counter proves no egress for synthesized statuses.

### Task 6: F9 — `aitm-plugin-wsctl` crate: `ws.intercept` + `ws.frame` (parked-frame edit/drop)

- **Satisfies:** AC-F9.2.
- **Depends on:** Task 1. **Independent head of the F9 chain** — **W1**.
- **Files:** Create `crates/aitm-plugin-wsctl/Cargo.toml`, `crates/aitm-plugin-wsctl/src/lib.rs`; tests `crates/aitm-plugin-wsctl/tests/frame_intercept.rs`. Modify root `Cargo.toml`. Depends on `aitm-core`, `aitm-proto-ws`, `aitm-rules`.
- **Interfaces — Produces:**
  ```rust
  pub struct WsCtlPlugin { /* Shared: armed, Vec<CompiledRule>, parked frames */ }
  impl WsCtlPlugin { pub fn new() -> Self; }
  impl aitm_core::Plugin for WsCtlPlugin { /* registers ws.intercept, ws.frame (ws.send added in Task 7) */ }
  // ws.intercept {enabled?: bool, rules?: [Rule]} -> {enabled, rules}   # Phase::WsFrame + optional ws_dir
  // ws.frame {id: FlowId, index: int, action: "forward" | "drop", data?: Bytes, opcode?: Str} -> ok
  ```
- **Change:** `ws.intercept` compiles `Phase::WsFrame` rules (reusing `aitm_rules`). `on_event(Event::WsMessage { flow, index })`: if a rule `matches(flow, Phase::WsFrame, Some(msg.dir))`, back up and `FlowCtx::intercept()` to park the frame before it is forwarded. `ws.frame`: `forward` optionally edits the parked `WsMessage` in place (`data`/`opcode`) via the stored flow then resumes so the module forwards it; `drop` marks the frame dropped so the module does not forward it (mirrors Rhai `msg.drop()`), then resumes. `ws.frame` acts on an already-captured parked frame → **no** guard (same posture as editing a parked HTTP request).
- **Test** (`frame_intercept.rs`, in-process WS client↔`WsModule`↔echo server):
  - `frame_drop_not_delivered` (AC-F9.2): arm `ws.intercept` with a `WsFrame` rule; a matching frame parks; `ws.frame {action:"drop"}` → the peer receives it **not at all**.
  - `frame_forward_edited_delivered` (AC-F9.2): `ws.frame {action:"forward", data:"edited"}` → the peer receives a frame whose bytes are `edited`.
  - `non_matching_frame_forwarded`: a frame not matching any rule is forwarded unchanged and never parked.
  - [ ] Scaffold crate + member → build. Tests → FAIL → implement → PASS → gate → commit `feat(wsctl): aitm-plugin-wsctl — ws.intercept + ws.frame edit/drop`.
- **Done when:** the three tests pass and the crate builds as a workspace member.

### Task 7: F9 — `ws.send` live inject + the inject channel in `aitm-proto-ws`

- **Satisfies:** AC-F9.1, AC-F9.3. Review focus #3. **Flagged additive `aitm-proto-ws` change** (spec §2: "if registering that channel needs a hook the WS module does not expose, the addition is in `aitm-proto-ws`").
- **Depends on:** Task 6 (same crate `wsctl`). **Sequential** after Task 6. Also modifies `aitm-proto-ws`.
- **Files:** Modify `crates/aitm-plugin-wsctl/src/lib.rs` (add `ws.send`), `crates/aitm-proto-ws/src/module.rs` (inject-channel select branch + registration) and `crates/aitm-proto-ws/src/lib.rs` (export the registry type). Test `crates/aitm-plugin-wsctl/tests/ws_send.rs` (create). Add `aitm-proto-ws` dep already present from Task 6.
- **Interfaces — Produces** (the registry type lives in `aitm-proto-ws`; **Plan-level call 2**):
  ```rust
  // aitm-proto-ws (additive)
  pub struct InjectFrame { pub dir: aitm_core::WsDir, pub opcode: aitm_core::WsOpcode, pub data: Vec<u8> }
  pub type InjectRegistry = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<aitm_core::FlowId, tokio::sync::mpsc::UnboundedSender<InjectFrame>>>>;
  impl WsModule { pub fn with_inject_registry(self, reg: InjectRegistry) -> Self; }
  // aitm-plugin-wsctl
  // ws.send {id: FlowId, dir: "c2s"|"s2c", opcode: "text"|"binary"|"ping"|"pong"|"close", data: Bytes} -> {index: int}
  ```
- **Change:** `WsModule::drive` registers an mpsc sender under the live flow id in the shared `InjectRegistry` when the conversation opens, and removes it before `Event::WsEnd`. Its `tokio::select!` gains a third branch draining the inject receiver; a received `InjectFrame` becomes a `WsMessage { injected: true }` fed through `WsStateMachine::send_frame(to, msg)` to the correct side, and is appended to the stored `WsFlow.messages`. `ws.send` in `wsctl`: resolve the flow's authority, call `host.guard().check_active(authority)?` (refused → `Err`, `isError: true`), then look up the flow's sender in the shared registry and enqueue the frame; return `{index}` of the appended message. The plugin and the module share one `InjectRegistry` `Arc` (wired in Task 14).
- **Test** (`ws_send.rs`, in-process WS client↔`WsModule`↔echo server, stub guard):
  - `ws_send_reaches_upstream` (AC-F9.1): on a live WS flow (in scope), `ws.send {dir:"c2s", opcode:"text", data:"ping-inject"}` → the upstream echo server receives a frame whose text is `ping-inject`; the appended `WsMessage.injected == true` and the returned `index` points at it.
  - `ws_send_out_of_scope_refused` (AC-F9.3, RF#3): the stub guard refuses the flow's host → `ws.send` returns `Err` naming the host (`isError: true`), no frame is sent; after `scope.add` of that host (guard now allows) → it succeeds.
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(wsctl,proto-ws): ws.send live inject via shared inject registry, scope-guarded`.
- **Done when:** both tests pass; the injected frame is observed upstream and the guard refusal is catchable.

### Task 8: F10 — `aitm-plugin-sessionio` crate: native sessions + aitm export/import (passive)

- **Satisfies:** AC-F10.1, AC-F10.3. Review focus #4.
- **Depends on:** none. **Independent:** yes — **W0**. Head of the F10 chain.
- **Files:** Create `crates/aitm-plugin-sessionio/Cargo.toml`, `crates/aitm-plugin-sessionio/src/lib.rs`, `crates/aitm-plugin-sessionio/src/native.rs` (serde mirror + convert); tests `crates/aitm-plugin-sessionio/tests/session_roundtrip.rs`. Modify root `Cargo.toml`. Depends on `aitm-core`, `serde`, `serde_json`.
- **Interfaces — Produces:**
  ```rust
  pub struct SessionIoPlugin;
  impl aitm_core::Plugin for SessionIoPlugin { /* session.save, session.load, flow.export, flow.import */ }
  // native.rs — serde mirror (aitm-core Flow is NOT serde; mirror + From/Into):
  pub struct SessionDoc { pub schema: String /* e.g. "aitm-session/1" */, pub flows: Vec<FlowRecord> }
  pub fn to_doc(flows: &[aitm_core::Flow]) -> SessionDoc;
  pub fn from_doc(doc: &SessionDoc) -> Vec<aitm_core::Flow>;
  // session.save {path} -> {flows:int, path}; session.load {path} -> {flows:int}  # replaces the store
  // flow.export {ids?, format:"aitm", path?} -> {bytes?, path?, flows:int}         # HAR added in Task 9
  // flow.import {path?, bytes?, format:"aitm"} -> {ids:[FlowId]}                    # HAR/.flows added in Task 9
  ```
- **Change:** `native.rs` defines a full-fidelity serde mirror of `HttpFlow`/`WsFlow` (materializing `Body::Streamed`→empty, collapsing `InterceptState` to `Observed`) and converts to/from `Flow`. `session.save` writes `to_doc(store.list→get)` as JSON; `session.load` parses and **replaces** the store (`clear` then `insert` each). `flow.export {format:"aitm"}` serializes the selected (or all) flows; `flow.import {format:"aitm"}` parses and `insert`s each into the store, stamping `FlowMeta { is_replay: false, marks: ["imported"] }`. **Import/load perform no egress** — they only touch the store. `schema` tag is `"aitm-session/1"` (**Plan-level call 3**).
- **Test** (`session_roundtrip.rs`, in-memory store, stub `ProxyClient` with an egress counter):
  - `native_session_roundtrips` (AC-F10.1): seed N flows incl. one with method/URL/status/headers/body; `session.save {path}` then `session.load {path}` into a fresh store → same flow count and the chosen flow's method, URL, status, headers and body round-trip byte-for-byte.
  - `import_is_passive` (AC-F10.3, RF#4): `flow.import` (or `session.load`) → the stub client's egress counter stays at its pre-import value (zero upstream requests).
  - [ ] Scaffold crate + member → build. Tests → FAIL → implement → PASS → gate → commit `feat(sessionio): native session save/load + aitm export/import (passive)`.
- **Done when:** both tests pass and no egress is observed on import.

### Task 9: F10 — HAR 1.2 export/import + mitmproxy `.flows` import

- **Satisfies:** AC-F10.2.
- **Depends on:** Task 8 (same crate). **Sequential** after Task 8.
- **Files:** Create `crates/aitm-plugin-sessionio/src/har.rs` and `crates/aitm-plugin-sessionio/src/mitmproxy.rs`; modify `crates/aitm-plugin-sessionio/src/lib.rs` (extend `flow.export`/`flow.import` `format` enums). Test `crates/aitm-plugin-sessionio/tests/har_roundtrip.rs` (create).
- **Interfaces — Produces:**
  ```rust
  // har.rs — HAR 1.2 serde view
  pub struct Har { pub log: HarLog }                 // log.version == "1.2"
  pub fn flows_to_har(flows: &[aitm_core::Flow]) -> Har;
  pub fn har_to_flows(har: &Har) -> Vec<aitm_core::Flow>;
  // mitmproxy.rs — .flows import only
  pub fn mitmproxy_to_flows(bytes: &[u8]) -> anyhow::Result<Vec<aitm_core::Flow>>;
  // flow.export {format:"har"|"aitm", ...}; flow.import {format:"har"|"aitm"|"mitmproxy", ...}
  ```
- **Change:** `flows_to_har` maps each `HttpFlow` to a HAR `log.entries[*]` (request/response/timings) and WS messages to `_webSocketMessages`; fields HAR cannot hold are dropped on export, defaulted on import. `log.version` is the literal `"1.2"`. `mitmproxy_to_flows` reads the mitmproxy `.flows` container (import only). The `format` param on `flow.export`/`flow.import` is extended to the spec's set; HAR/`.flows` import stays passive (no egress).
- **Test** (`har_roundtrip.rs`):
  - `har_export_is_valid_1_2` (AC-F10.2): `flow.export {format:"har"}` over a seeded flow → a document that parses as HAR with `log.version == "1.2"` and whose first entry's `request.url`/`response.status` equal the exported flow's.
  - `har_import_roundtrips_url_status` (AC-F10.2): `flow.import` of that HAR → a flow with the same URL and status.
  - `mitmproxy_flows_import` : a small fixture `.flows` byte blob imports to ≥1 flow with the expected URL (fixture under `tests/fixtures/`).
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(sessionio): HAR 1.2 export/import + mitmproxy .flows import`.
- **Done when:** the three tests pass; the HAR document validates as 1.2.

### Task 10: F11 — `aitm-plugin-passthrough` crate: shared list + `tls.passthrough.*` + agent gate

- **Satisfies:** AC-F11.2.
- **Depends on:** none. **Independent:** yes — **W0**. Head of the F11 chain.
- **Files:** Create `crates/aitm-plugin-passthrough/Cargo.toml`, `crates/aitm-plugin-passthrough/src/lib.rs`, `crates/aitm-plugin-passthrough/src/list.rs` (the shared list type); tests `crates/aitm-plugin-passthrough/tests/commands.rs`. Modify root `Cargo.toml`. Depends on `aitm-core`. **Does not** touch `aitm-core/config.rs` — the plugin takes its seed + agent flag via its constructor; the `Config.tls` field lands in Task 14.
- **Interfaces — Produces:**
  ```rust
  // list.rs — the Arc-shared passthrough list the module (Task 11) also reads
  #[derive(Clone, Default)] pub struct PassthroughList(std::sync::Arc<std::sync::RwLock<Vec<String>>>);
  impl PassthroughList { pub fn contains_host(&self, host: &str) -> bool; pub fn hosts(&self) -> Vec<String>; pub fn add(&self, host: String); pub fn remove(&self, host: &str) -> bool; }
  pub struct PassthroughPlugin { /* list, allow_agent_passthrough */ }
  impl PassthroughPlugin { pub fn new(seed: Vec<String>, allow_agent_passthrough: bool) -> Self; pub fn list_handle(&self) -> PassthroughList; }
  impl aitm_core::Plugin for PassthroughPlugin { /* tls.passthrough.list / add / remove */ }
  // tls.passthrough.list {} -> {hosts:[Str]}; .add {host} -> {hosts}; .remove {host} -> {hosts}
  ```
- **Change:** `PassthroughList` is an `Arc<RwLock<Vec<String>>>` matching host or `*.wildcard`. `tls.passthrough.add`/`remove` mutate it and return the full host list; `list` returns it. Agent gate: `add`/`remove` from `host.frontend() != Frontend::Cli` with `allow_agent_passthrough == false` → `Err` (mirrors `scope.add`'s message). `new(seed, flag)` seeds the list.
- **Test** (`commands.rs`, `CommandHost` with `Frontend` set):
  - `agent_add_refused_cli_allowed` (AC-F11.2): `tls.passthrough.add {host:"pinned.example"}` from `Frontend::Mcp` with `allow_agent_passthrough=false` → `Err` (`isError: true`); from `Frontend::Cli` → `Ok`.
  - `list_reflects_add_remove` (AC-F11.2): after a CLI add then remove, `tls.passthrough.list` reflects each change.
  - [ ] Scaffold crate + member → build. Tests → FAIL → implement → PASS → gate → commit `feat(passthrough): shared list + tls.passthrough.* commands, agent-gated`.
- **Done when:** both tests pass.

### Task 11: F11 — `PassthroughModule` (`ProtocolModule`): SNI match + byte tunnel

- **Satisfies:** AC-F11.1. Review focus #5.
- **Depends on:** Task 10 (same crate; reads the shared `PassthroughList`). **Sequential** after Task 10.
- **Files:** Create `crates/aitm-plugin-passthrough/src/module.rs`; modify `crates/aitm-plugin-passthrough/src/lib.rs` (export the module). Test `crates/aitm-plugin-passthrough/tests/tunnel.rs` (create).
- **Interfaces — Produces:**
  ```rust
  pub struct PassthroughModule { /* PassthroughList */ }
  impl PassthroughModule { pub fn new(list: PassthroughList) -> Self; }
  impl aitm_core::ProtocolModule for PassthroughModule {
      fn matches(&self, hint: &aitm_core::NextLayerHint) -> bool;   // true iff SNI/CONNECT-authority is in the list
      fn spawn(&self, io: aitm_core::ByteStream, ctx: aitm_core::ModuleCtx) -> futures::future::BoxFuture<'_, anyhow::Result<()>>;
  }
  ```
- **Change:** `matches` returns `true` when `hint.client_hello_sni` (or the CONNECT authority) matches an entry in the shared list — so the module must be **registered before `HttpModule`** (the acceptor picks the first matching module via `modules.iter().find`; ordering wired in Task 14). `spawn` opens the upstream via `ModuleCtx::connect_upstream` and copies bytes both directions with **no TLS MITM** — the client completes TLS directly against the real server cert. It records a minimal tunnel flow (host, bytes up/down, no decrypted body) so a UI can show "tunnelled". Uses only the existing `ProtocolModule` seam — no `aitm-core` edit.
- **Test** (`tunnel.rs`, loopback TLS origin with its own cert + aitm CA):
  - `passthrough_tunnels_mitm_still_decrypts` (AC-F11.1, RF#5): with `pinned.example` in the list, a TLS connection to it is tunnelled — the client's TLS peer certificate is the **upstream's real cert** (issuer is **not** the aitm CA) and the store has **no decrypted `HttpFlow`** for it; a non-passthrough host over the same proxy is still MITM'd (leaf issued by the aitm CA, `HttpFlow` captured).
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(passthrough): PassthroughModule SNI-matched byte tunnel`.
- **Done when:** the test passes; passthrough yields the real cert and no decrypted flow, MITM still works alongside.

### Task 12: Map — `aitm-plugin-maprules` crate: `map.*` + Map Local + path confinement + agent gate

- **Satisfies:** AC-M1, AC-M3.
- **Depends on:** Task 1. **Independent head of the Map chain** — **W1**.
- **Files:** Create `crates/aitm-plugin-maprules/Cargo.toml`, `crates/aitm-plugin-maprules/src/lib.rs`, `crates/aitm-plugin-maprules/src/action.rs`; tests `crates/aitm-plugin-maprules/tests/map_local.rs`. Modify root `Cargo.toml`. Depends on `aitm-core`, `aitm-rules`. Takes the map root + agent flag via its constructor (the `Config.maps` field lands in Task 14).
- **Interfaces — Produces:**
  ```rust
  pub enum MapAction { Local { path: String, status: Option<u16>, headers: Vec<(String,String)> }, Remote { to: RemoteTarget } }
  pub enum RemoteTarget { Url(String), Host { authority: String, scheme: Option<String> } }
  pub struct MapRulesPlugin { /* maps: Mutex<Vec<(String, CompiledRule, MapAction)>>, map_root: PathBuf, allow_agent_authoring: bool */ }
  impl MapRulesPlugin { pub fn new(map_root: std::path::PathBuf, allow_agent_authoring: bool) -> Self; }
  impl aitm_core::Plugin for MapRulesPlugin { /* map.add, map.list, map.remove */ }
  // map.add {kind:"local"|"remote", condition: MatchCondition, action: MapAction} -> {id}
  // map.list {} -> {maps:[{id,kind,condition,action}]}; map.remove {id} -> ok
  ```
- **Change:** `map.add` compiles the condition via `aitm_rules::compile` (bad regex → `Err`), assigns a stable id, stores `(id, rule, action)`. Agent gate: `map.add`/`map.remove` from a non-CLI frontend with `allow_agent_authoring == false` → `Err`. **Map Local:** on `Event::RequestHeaders`/`Request`, if a `local` map matches, read the configured file (confined to `map_root` — the `path` is canonicalized and must stay under `map_root`, else `map.add` rejects it), build an `HttpResponse` (default status **200**, content-type inferred from extension unless `headers` override), `FlowCtx::set_response`, return `Verdict::Halt` — short-circuit, **no egress, no guard**. (Map Remote is Task 13.)
- **Test** (`map_local.rs`, loopback origin that counts requests, a fixture file):
  - `map_local_serves_file` (AC-M1): a Map Local for `*/logo.png` → a fixture → a request to `/logo.png` returns status **200** with a body equal to the fixture bytes, and the upstream counter stays **0**.
  - `map_add_agent_refused` (AC-M3): `map.add` from `Frontend::Mcp` with `allow_agent_authoring=false` → `Err` (`isError: true`); from `Frontend::Cli` → `Ok`.
  - `map_local_path_escape_rejected` (AC-M3, RF#6): `map.add` with a Local `path` resolving outside `map_root` (e.g. `../../etc/passwd`) → `Err` at add time, no file read.
  - [ ] Scaffold crate + member → build. Tests → FAIL → implement → PASS → gate → commit `feat(maprules): map.* commands + Map Local with path confinement, agent-gated`.
- **Done when:** the three tests pass.

### Task 13: Map — Map Remote rewrite + scope guard

- **Satisfies:** AC-M2. Review focus #7.
- **Depends on:** Task 12 (same crate). **Sequential** after Task 12.
- **Files:** Modify `crates/aitm-plugin-maprules/src/lib.rs` (Map Remote branch in `on_event`). Test `crates/aitm-plugin-maprules/tests/map_remote.rs` (create).
- **Interfaces — Changes:** no new public type (uses `MapAction::Remote`/`RemoteTarget` from Task 12). The plugin gains access to the guard via `FlowCtx`/the command host path — Map Remote must reach `ScopeRateGuard::check_active`; if the guard is not reachable from `FlowCtx`, the rewrite is validated against the shared guard handle the plugin holds (wired in Task 14). **Plan-level call 4** (see below).
- **Change:** on `Event::RequestHeaders`/`Request`, if a `remote` map matches, compute the rewritten `scheme`/`authority`/`path`. **Before** rewriting in place via `FlowCtx::flow_mut()`, call `check_active(rewritten_authority)`; if out of scope, **decline the mapping and do not alter the request** (so the original is not sent to the new host) and record the refusal — the deny-by-default point for Map Remote. If in scope, rewrite so the request goes upstream to the new host.
- **Test** (`map_remote.rs`, two loopback origins `old`/`new`, stub guard):
  - `map_remote_rewrites_in_scope` (AC-M2): a map rewriting `old.example` → `new.example` (in scope) → the request reaches `new.example`.
  - `map_remote_out_of_scope_refused` (AC-M2, RF#7): the same mapping with the target **not** in scope → the mapping is refused by the guard and the original request is **not** sent (neither `old` nor `new` origin receives it, or the flow errors without egress to `new`).
  - [ ] Tests → FAIL → implement → PASS → gate → commit `feat(maprules): Map Remote rewrite, scope-guarded`.
- **Done when:** both tests pass; the out-of-scope rewrite produces no egress to the new host.

### Task 14: Binary wiring — register modules/plugins, additive `Config` fields, whole-branch assembly

- **Satisfies:** end-to-end for all in-scope ACs; the named additive `aitm-core` `Config` edits (`Config.tls`, `Config.maps`).
- **Depends on:** all prior tasks. **Convergence** — **W3**.
- **Files:** Modify `crates/aitm/src/wire.rs` (register the new plugins/module, share the `InjectRegistry` and `PassthroughList`), `crates/aitm/src/config_file.rs` (parse the new YAML sections, `deny_unknown_fields`), `crates/aitm-core/src/config.rs` (**additive** `Config.tls: TlsConfig`, `Config.maps: MapsConfig`). Add the new crates to `crates/aitm/Cargo.toml`. Test `crates/aitm/tests/m6_wiring.rs` (create).
- **Interfaces — Produces** (additive `aitm-core` config, named/justified per Global constraints):
  ```rust
  // aitm-core/src/config.rs — additive
  pub struct TlsConfig { pub passthrough: Vec<String>, pub allow_agent_passthrough: bool }  // Default: [], false
  pub struct MapsConfig { pub root: Option<std::path::PathBuf>, pub allow_agent_authoring: bool } // Default: None, false
  // Config gains: pub tls: TlsConfig, pub maps: MapsConfig  (both #[serde(default)])
  ```
- **Change:** `wire.rs` registers `PassthroughModule` **before** `HttpModule` (so it wins the `matches` race), then `WsModule::with_inject_registry(reg)` sharing the same `InjectRegistry` `Arc` the `WsCtlPlugin` holds; registers `WsCtlPlugin`, `SessionIoPlugin`, `PassthroughPlugin::new(cfg.tls.passthrough, cfg.tls.allow_agent_passthrough)`, and `MapRulesPlugin::new(root, cfg.maps.allow_agent_authoring)`. `config_file.rs` parses `tls:` and `maps:` with unknown-key rejection. The additive `Config` fields default to the deny-by-default posture. This is the single writer of `config.rs`/`wire.rs`/`config_file.rs`.
- **Test** (`m6_wiring.rs`, build the assembled proxy from a config):
  - `assembles_with_all_m6_plugins`: the built `Registry` exposes `flow.intercept`, `flow.mutate`, `flow.kill`, `ws.send`, `ws.intercept`, `ws.frame`, `session.save`, `session.load`, `flow.export`, `flow.import`, `tls.passthrough.add`, `map.add` (all present in `tools/list`).
  - `passthrough_module_ordered_before_http`: with a passthrough host configured, `NextLayerHint` for that SNI selects `PassthroughModule`, not `HttpModule`.
  - `config_rejects_unknown_tls_key`: a YAML `tls:` section with an unknown key → parse error (`deny_unknown_fields`); `tls`/`maps` default to the off posture when omitted.
  - `agent_gates_default_off`: with no overrides, `tls.passthrough.add` and `map.add` from `Frontend::Mcp` are refused (defaults wired through).
  - [ ] Tests → FAIL → implement wiring + config + member deps → PASS → gate → commit `feat(aitm): wire M6 plugins/module, additive tls/maps config, whole-branch assembly`.
- **Done when:** all four tests pass and the full workspace gate is green.

---

## Plan-level calls

**All four confirmed by Matt on plan approval (2026-10-28).** Call 1 — response-phase
parking fires at `Event::ResponseHeaders` (spec §1 amended to match). Call 4 — Map
Remote reaches the guard via a constructor-injected `Arc<dyn ScopeRateGuard>`. Calls
2 and 3 stand as the builder's calls. Flagged, not silently resolved (WORKFLOW
"stop on gaps").

1. **Response-phase rules fire at the `ResponseHeaders` emit, not the `Response` emit.** Spec §1 says the intercept plugin "calls `FlowCtx::intercept()` on `Event::Response`." The current `aitm-proto-http` module streams the response head and body to the client **between** the `ResponseHeaders` emit (module.rs:572, awaited, before `enqueue_response`) and the `Response` emit (module.rs:613, after the body has already streamed). So a park on `Event::Response` is too late to edit what the client sees. Task 2 verifies this and Task 4 parks response-phase rules at `Event::ResponseHeaders`. This matches AC-F3.2 ("parked at the response phase … the client receives 418 with the edited body") but refines the spec's event name. **If Matt intends literal `Event::Response` parking** (e.g. observe-only after the client got the body), Task 2/Task 4 change accordingly.
2. **The WS inject registry lives in `aitm-proto-ws`** (spec §2 left this open: "whether the registry lives in `aitm-proto-ws` or `aitm-plugin-wsctl`"). The module owns the live connection's `select!` loop and must drain the channel, so the `InjectRegistry`/`InjectFrame` types are defined in `aitm-proto-ws` and the `wsctl` plugin shares the `Arc`. Chosen for locality of the drain point.
3. **Native session schema tag `"aitm-session/1"`** (spec "Left to the builder": native session JSON schema version tag). A single stable version string; bump on a breaking format change.
4. **Map Remote reaches the guard via a plugin-held `ScopeRateGuard` handle.** `FlowCtx` (the plugin's event handle) does not expose the guard; only `CommandHost` does. So `MapRulesPlugin` is constructed with the shared `Arc<dyn ScopeRateGuard>` (available from `Proxy::guard()`), wired in Task 14, and calls `check_active` from `on_event`. If Matt prefers Map Remote to run as a short-circuit that re-enters the guarded client path instead, Task 13 changes. **This is the one place a plugin needs a service `FlowCtx` does not carry; it is additive (constructor injection), not an `aitm-core` edit — flagged for confirmation.**

---

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
