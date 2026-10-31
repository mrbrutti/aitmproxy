# `aitm tui` agent governance implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief)
**Spec:** `docs/superpowers/specs/2026-10-30-tui-mode-governance-design.md`
**Branch / worktree:** `claude/cranky-shamir-6c9cfc` in `/Users/matt/Security/aitmproxy/.claude/worktrees/cranky-shamir-6c9cfc`, base `bd0f9b7` on `main` (PR 141; PR 145's `with_shared_governance` is already on it). Base SHA for every diff and Tester/panel dispatch: `bd0f9b7`. The spec is untracked on `bd0f9b7`; the orchestrator commits the spec and this plan before Task 1.

**Plan amendments (orchestrator, during execution; these override the text below where they differ):**

- **Base SHA is now `5ddc533`.** Current `origin/main` was merged at `4cd0d1a` after Task 1 (it carries PR 153, the fix for `web_bus_ask_split::a_malformed_approve_resolves_nothing_and_the_call_stays_parked`, which was already red on `bd0f9b7`, so `web_bus_ask_split` is 7 passed). Every `bd0f9b7..HEAD` diff in Task 4 and every Tester/panel base reads `5ddc533..HEAD`. `git show bd0f9b7:crates/aitm/src/{tui,main}.rs` stay valid, because main's changes did not touch those two files.
- **Task 2 pass B also adds `wire::tests::governance_carries_the_assemblys_own_state_and_ring`** (Task 1 Tester finding F2: `Arc::ptr_eq` on both fields of `Assembled::governance()` and its clone, then a `set_policy` round-trip). It could only compile once the temporary `#[expect(dead_code)]` was deleted.
- **The Task 2 Tester added six tests to `tui_mode_governance.rs`**, so that binary has 12 tests, not 6. Where the plan says `tui_mode_governance (6)` or `6 passed`, read 12. The Task 4 AC9 mutation expectation becomes `test result: FAILED. 5 passed; 7 failed`: FAILED = AC1, AC2, AC5, `malformed_and_empty_agent_input_is_a_protocol_error_that_is_never_audited`, `an_oversized_secret_bearing_agent_call_reaches_the_tui_trail_capped_and_redacted`, `an_operator_on_the_agent_server_resolves_what_the_tui_cannot_and_a_drop_ends_asking`, `the_streamable_http_agent_server_is_governed_by_the_same_live_state_and_ring`; ok = AC3, AC4, AC6, `the_loopback_agent_cannot_rewrite_the_policy_that_governs_it`, `a_paused_loopback_agent_still_gets_initialize_tools_list_and_ping`. The live test still fails under the mutation.

- **Stage 6 round 1 (panel on `646dd8c`) led to a fix task, and `origin/main` was merged a second time.** The base is now `711aa26` (it carries PR 161, the fix for the two `aitm-tui` token tests that were red on main and had made the full gate fail). `tui_mode_governance` now has 14 tests (the whole-branch Tester added `an_operator_token_client_governs_the_loopback_agent_and_is_recorded_as_operator`, red-set, and `a_subscribed_operator_is_still_pushed_each_agent_call_with_push_unfed`, guard). One test was renamed to `an_oversized_secret_bearing_agent_call_reaches_the_tui_trail_without_the_secret`. The AC9 mutation expectation is `test result: FAILED. 6 passed; 8 failed`: FAILED = AC1, AC2, AC5, the malformed-input test, the oversized-secret test, the operator-approval test, the streamable-HTTP test and the operator-token test; ok = AC3, AC4, AC6, the self-lift guard, the paused-handshake guard and the push-unfed guard. `Assembled` also keeps `Governance` in a private field filled at assembly (security finding F1), so the Design 2 limitation "a hand-built server can still be given a fresh state" no longer extends to `governance()`.

## Overview

`wire.rs` gains a sealed `Governance`: two `pub(crate)` `Arc`s, with `Assembled::governance()` as
its only public source. `tui::build_servers` and `tui::run` require it, and the agent arm applies it
through the existing `tui::with_shared_governance`. Four tasks, **all sequential**:

- **Task 1** lands the type, the new signatures and every caller migration with **today's** agent
  arm (parameter bound as `_governance`), plus the AC8 doctests. Behaviour is unchanged and the gate
  is clean. Committed.
- **Task 2** has two Coder passes around an orchestrator Terminal run. Pass A writes the tests and
  runs them **red** against that production code. Pass B flips the one agent arm to
  `with_shared_governance` (**green**). Committed once, green.
- **Task 3** rewrites the doc comments (AC10). Committed.
- **Task 4** is the orchestrator checkpoint: full gate, the AC9 mutation on the final head, and the
  AC11/AC12 diff checks.

Why this split, and not "Task 2 = red tests, Task 3 = switch + docs":

- Every task boundary is a committable, gate-clean state. Pass A's red tests and pass B's switch land
  in **one** commit, exactly as the sibling plan's Task 2 did, so the branch is never committed red.
- Docs are their own task, so the red-to-green diff is the production switch alone and nothing else.

Order and independence, stated once. Each task needs the previous one:

- Task 2's tests call Task 1's signatures.
- Pass B needs pass A's red run on record.
- Task 3 documents pass B's wiring.

Task 3 and pass A touch disjoint files (docs in `src/` versus two new test files), so they could fan
out in principle. Two things argue against it: they share one worktree and one cargo target dir, and
pass A's red run must compile exactly the Task 1 production code. Default: run 1, 2A, (Terminal red),
2B, (Terminal green), 3, 4 in order.

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).**
  - Builds and checks: `cargo build -p aitm --offline`, `cargo fmt -p aitm` /
    `cargo fmt --check`, `cargo clippy -p aitm --all-targets --offline -- -D warnings`, and
    `cargo test -p aitm --offline --no-run`, which compiles every test binary, socket ones
    included. The target dir is warm, so `--no-run` is fast.
  - Doctests: `cargo test -p aitm --offline --doc`.
  - Socket-free tests:
    - `cargo test -p aitm --offline --lib tui::`. It is filtered to the `tui` module because other
      lib modules are not guaranteed socket-free.
    - `cargo test -p aitm --offline --test tui_mode_governance`.
    - `cargo test -p aitm --offline --test tui_embed`. By reading, it binds nothing: its rig never
      calls `serve()`, and its doc says the sandbox cannot bind ports. It has sometimes been
      treated as a socket test, so the orchestrator also runs it in the Terminal, which is
      harmless.
    - `cargo test -p aitm --offline --test web_bus_ask_split`.
  - If cargo cannot resolve dependencies offline, stop and ask the orchestrator to run
    `cargo fetch` in the Terminal panel. Do not report a result you did not get.
- **Terminal panel (orchestrator only).**
  - Every `git` command.
  - Every test that binds a loopback socket. Each one skips with a note on `PermissionDenied`:
    `--test tui_mode_governance_live` (AC7), `--test tui_live_bus`, `--test l4_cua_tui`, and the
    `web_bus_governance` / `web_bus_roles` / `web_bus_concurrency` / `web_bus_push` /
    `discover_e2e` binaries.
  - The full gate.
  - **Socket runs use `-- --nocapture`.** cargo hides a passing test's stderr, so a skipped run
    (which returns early and passes) looks identical to a real pass without it. Every skip note
    contains the words `refuses to bind`, so `grep -c "refuses to bind" <log>` printing `0` is the
    "no skip note" evidence.
  - A Coder or Tester never claims a socket test passed or failed. It reports "compiled, NOT RUN
    (socket)", and the orchestrator supplies the output.
- **Coders do not commit.** The sandbox cannot run git, so this plan overrides step 5 of
  `coder.md`. The Coder reports the files it changed, and the orchestrator commits in the Terminal
  panel after the task's Tester passes.
  - Commit messages name the plan and task, e.g. `refactor(tui): task 1 - sealed Governance
    required by build_servers and run (plan 2026-10-30-tui-mode-governance)`.
  - Avoid any word that starts with `#`, because the terminal hook refuses it. Write "PR 145", not
    the hash form.
- **Evidence, verbatim.** Every red and green run goes into the Coder's or orchestrator's report as
  the literal command plus the literal `test ...` and `test result:` lines. Each failure also needs
  its `---- <name> stdout ----` block. "It failed as expected" is not a report.
- **Stale artifacts.** If `CARGO_TARGET_DIR` is shared with other worktrees, `touch` the edited
  sources before a red or green run. A red run on a stale binary is worthless.
- **Gate exit status, not grep.** Orchestrator gate runs redirect to a log and read `$?`. `grep`
  output is for display only.
- **Trust-gate scan trap.** `aitm-core/tests/trust_gate_scan.rs` scans the **text** of every
  `crates/*/src/**/*.rs`, including doc comments and doctests. It rejects these shapes against
  `Frontend::Mcp` / `CallerTrust::Agent`: `==` / `!=` comparisons, refutable `let` patterns, and
  `matches!`. Never write those shapes in `src`, not even in prose. The new tests live in
  `crates/aitm/tests/`, which the scan does not read.

### Symbols the rigs use (confirmed by reading on `bd0f9b7`)

These already exist and are `pub`:

- `aitm::wire::{assemble(&Config) -> anyhow::Result<Assembled>, assemble_with(&Config, &Features)
  -> anyhow::Result<Assembled>, Assembled}`, with `pub` fields `proxy`, `agent_state:
  Arc<AgentState>`, `push_tx`, `audit_ring: Arc<AuditRing>`, `l4_ingress` and others (`wire.rs`
  lines 100-140).
- `aitm::tui::{services(&Proxy, &Config, Option<Arc<dyn BrowserDriver>>, TuiLog) -> Services,
  server(&Config, McpTransport, &Services) -> McpServer, with_shared_governance(McpServer,
  &Arc<AgentState>, &Arc<AuditRing>) -> McpServer, TuiLog::Off}` (`tui.rs`).
- `aitm_mcp::{McpServer, ConnCtx}`:
  - `McpServer::handle_on(&self, &ConnCtx, &str) -> Option<String>`.
  - `McpServer::on_bound(self, impl FnOnce(SocketAddr) + Send + 'static) -> Self`.
  - `McpServer::serve(self) -> anyhow::Result<()>`.
  - `ConnCtx::new(Frontend)`, which sets `out: None`.
- `aitm_bus_client::{BusClient, TcpTransport, BusError, InProcessHandler}`:
  - `TcpTransport::connect(SocketAddr, &str)` writes the `{"token": ..}` line.
  - `BusClient::new(Box<dyn BusTransport>)`.
  - `BusClient::initialize(&str, &str) -> Result<ServerInfo, BusError>`, where `ServerInfo.role:
    Option<String>`.
  - `BusClient::call(&str, Value) -> Result<Value, BusError>`. It returns the
    `structuredContent`, or `Err(BusError::Tool(text))` on `isError: true`.
  - `InProcessHandler = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>`.
- `aitm_core::{AgentPolicy, AgentState, AuditRing, Config, Frontend, McpTransport}`:
  `AgentState::new(AgentPolicy)`, `AuditRing::default()`, `AuditRing::len()`. `Config.mcp.policy`,
  `Config.mcp.transport`, `Config.mcp.operator_token` and `Config.ca.dir` are `pub`.
- `tests/support/mod.rs`: `support::config(tag) -> Config`, which gives a unique temp CA dir.

New in Task 1: `aitm::wire::Governance` and `Assembled::governance(&self) -> Governance`.

### Claims in the spec, verified by reading on `bd0f9b7` (none false)

- **The defect.** The agent arm of `build_servers` (`tui.rs` 273-282) is
  `server(..).with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy))).with_mcp_roles(..)`, with
  no `with_audit_ring` and no `with_push`. `main.rs` 460-464 calls
  `tui::run(&cfg, &proxy, services, proxy_listener, browser_listener)`. `McpServer::serve`
  (`server.rs` 1138-1189) moves `agent_state` and `audit_ring` into the served `Arc<McpServer>`
  unchanged.
- **Callers.** The callers of `build_servers` / `assemble_services` / `tui::run` are exactly those
  the spec lists:
  - `tui.rs` (`run`) and `main.rs` 462.
  - `support/mod.rs` 36.
  - `tui_embed.rs` 46-48 and 146-147.
  - `tui_live_bus.rs` 60-61.
  - `l4_cua_tui.rs` 341-351 and 383-386.

  No other file in `crates/` or `apps/` calls them.
- **Sensitivity and refusal texts.** `flow.list` is Read; `flow.kill` is Write and its `id` is
  **required** (`intercept.rs` `id_param`); `scope.add` is Sensitive. The refusal texts come from
  `server.rs`:
  - "`flow.kill` refused: the agent policy is `readonly`" (`policy_refusal_reason`).
  - "the agent policy is `auto`, which runs read and write commands".
  - "no operator is connected to approve it" (`park_for_approval`, checked **before** any parking).
  - "the agent policy is `paused`" (`read_refusal` and `policy_refusal_reason`).
  - "only meaningful over a streaming MCP connection" (`handle_subscription` when `conn.out` is
    `None`).
  - "agent.approve: no parked request `apr_none` is awaiting approval" (`handle_approve`).

  Neither `agent.set` nor `flow.intercept` has a `confirm_prompt`, so operator calls to them return
  a result, not a `needs_confirmation` handshake.
- **What gets audited.** `call_tool` (`server.rs` 1405-1420) audits every `Done` outcome, refusals
  included, except a successful subscription verb.
  - The agent's refused `flow.subscribe` in AC1 is audited. That does not matter, because AC1 does
    not count.
  - The TUI's refused `flow.subscribe` in AC6 lands in the **TUI server's own** private ring, not
    the shared one.
- **Audit row shape.** `AuditEntry::to_value` gives `result` as `"ok"` or `{"error": text}` and
  labels `origin` as `"mcp"` for the agent role.
- **Doctests.** There are no Rust doctests in `crates/aitm/src` on `bd0f9b7`; the one fenced block,
  in `macos_capture/config.rs`, is `yaml`. So `cargo test -p aitm --doc` shows exactly the two new
  ones.
- **Two nuances the Coder must know.** Neither is a spec error.
  - (a) In the red state, the agent's `flow.kill` with no arguments passes the private `auto` gate
    (Write). It then fails argument validation (missing `id`), so the reply is a JSON-RPC `error`
    (`-32602`) with **no** `result`. AC2's red therefore shows `result.isError` absent. That is
    still the policy assertion failing: the call was not refused. Assert on the whole reply and
    print it in every message.
  - (b) The red-staged production code never reads `Governance`'s `pub(crate)` fields. The derived
    `Clone` is ignored by dead-code analysis, so rustc warns "fields `agent_state` and `audit_ring`
    are never read", and `clippy -D warnings` would fail Task 1. Task 1 therefore carries a
    temporary `#[expect(dead_code, reason = ..)]` that pass B must delete. If pass B forgets,
    `unfulfilled_lint_expectations` fails clippy, so the removal enforces itself.

### AC coverage

| AC | Task | Test or check (exact name) |
|---|---|---|
| AC1 | 2 | `a_tui_pause_refuses_the_loopback_agent_on_its_next_call` |
| AC2 | 2 | `tui_readonly_and_ask_govern_the_loopback_agent_live` |
| AC3 | 2 | `the_seeded_policy_carries_over_to_the_loopback_agent` (guard) |
| AC4 | 2 | `default_auto_still_refuses_a_sensitive_loopback_agent_call` (guard) |
| AC5 | 2 | `loopback_agent_calls_land_in_the_shared_audit_trail` |
| AC6 | 2 | `the_tui_operator_surface_stays_ungated_unrecorded_and_cannot_approve` (guard) |
| AC7 | 2 | `a_live_pause_reaches_an_open_loopback_connection_without_reconnecting` (Terminal) |
| AC8 | 1 | two doctests on `wire::Governance` (`compile_fail` + `no_run` companion); compile of every caller |
| AC9 | 2, 4 | red runs in Task 2 pass A; final-head mutation in Task 4 |
| AC10 | 3, 4 | literal greps (Task 3), spot-check and the PR 145-comment diff (Task 4) |
| AC11 | 1, 2, 4 | migrated callers green (Tasks 1, 2); unmodified-file and no-assertion-edited diffs (Task 4) |
| AC12 | 4 | full Terminal gate; `git diff --stat` on the forbidden paths |

### Calls made in this plan (Architect's calls, for Matt to correct)

1. **Four sequential tasks; Task 2 has two Coder passes.** The red tests and the green switch land
   in one commit, so the branch is never committed red. Docs are Task 3, so the red-to-green
   production diff is the switch alone.
2. **Task 1 is committed in the red-staged state** (new signatures, today's arm, `_governance`). A
   temporary `#[expect(dead_code, reason = ..)]` on `Governance` keeps it clippy-clean, and pass B
   deletes it. The expectation goes unfulfilled once the fields are read, which makes forgetting it
   a clippy failure.
3. **`Governance` uses `pub(crate)` fields** (Design 2), not `pub(crate)` accessors.
4. **AC8 gets its own red step.** Task 1 first lands `Governance` with `pub` fields, so the
   `compile_fail` doctest fails ("compiled successfully"), and only then seals it. This proves the
   doctest can detect an unsealed type.
5. **The companion doctest is `no_run`.** Running it would generate a CA in the default `ca.dir` in
   the operator's home. It has the same `use` lines and builds the same two `Arc`s as the forgery,
   so the struct literal is the only difference between the two.
6. **The AC7 agent client is `aitm_bus_client::{BusClient, TcpTransport}`**, the client the TUI
   itself uses. Its red failure shape is `Ok(Array [])`.
7. **One test per AC.** AC3 is one test with two rigs. AC1, AC2 and AC4 use the config's default
   policy; AC3, AC5 and AC6 seed one.
8. **AC7 also asserts exactly two `agent.activity` rows.** That is stricter than the spec's
   `[0]`/`[1]`: in that rig only the agent server writes the shared ring, and it receives exactly
   two tool calls.
9. **Test helpers are copied into each new file** (house style). `support::config` is reused, and
   no new `tests/support/` file is added. Each rig removes its CA dir on drop.
10. **The AC9 mutant is Task 1's committed `tui.rs`**, restored afterwards with `git checkout`. It
    is exactly "new signatures, today's arm, `_governance`". A manual two-edit fallback is given.
11. **A Tester runs after each task; the panel runs once on the whole branch**, as in the sibling
    plan. Add a panel on Task 1 if per-task review is wanted.
12. **`tui_embed` runs in the sandbox**, because by reading it binds nothing. The orchestrator also
    runs it in the Terminal.

## Tasks

### Task 1: sealed `Governance`, new signatures, every caller migrated, AC8 doctests (today's agent arm)

- **Satisfies:** AC8; AC11 (caller half: the three existing TUI test files keep passing with only
  call-site lines changed).
- **Depends on:** none.
- **Files:**
  - `crates/aitm/src/wire.rs` (modify: add `Governance`, `impl Assembled { governance }`, and the
    doctests; nothing else).
  - `crates/aitm/src/tui.rs` (modify: one import, and the signatures of `build_servers` and `run`;
    the agent arm and all docs untouched).
  - `crates/aitm/src/main.rs` (modify: the `Assembled` binding, and one argument in the
    `Mode::Tui` branch).
  - `crates/aitm/tests/support/mod.rs` (modify: `assemble_services` and its doc only).
  - `crates/aitm/tests/tui_embed.rs`, `crates/aitm/tests/tui_live_bus.rs`,
    `crates/aitm/tests/l4_cua_tui.rs` (modify: call-site and rig lines only).
- **Change:**
  - `wire.rs`, directly after `struct Assembled`:
    - `pub struct Governance`, deriving `Clone` and nothing else. Its two fields are
      `pub(crate) agent_state: Arc<AgentState>` and `pub(crate) audit_ring: Arc<AuditRing>`. It
      has no constructor, no accessor, and no other `pub` item.
    - Then `impl Assembled { pub fn governance(&self) -> Governance }`, which clones the two
      `Arc`s.
    - Doc on `Governance`. It says:
      - The type carries the core's own `AgentState` and `AuditRing`: the pair the registered
        `AgentPlugin` writes (`agent.set`) and reads (`agent.status`, `agent.activity`).
      - It is sealed; `Assembled::governance` is the only public source.
      - `tui::build_servers` and `tui::run` require it, so `aitm tui` cannot be wired without it
        or with a fresh state.
      - It carries no push sender.
    - Doc on `governance()`: it clones the two `Arc`s and is the only public source.
    - Neither doc may contain the phrase `tui-mode governance` (AC10 greps all of `src`).
  - Two doctests in the `Governance` doc, with **identical** `use` lines in this order:
    `std::sync::Arc`; `aitm::tui::{build_servers, services, TuiLog}`;
    `aitm::wire::{assemble, Governance}`; `aitm_core::{AgentPolicy, AgentState, AuditRing, Config}`.
    Both use an explicit `fn main() -> anyhow::Result<()>`, and both bind the same two locals:
    `Arc::new(AgentState::new(AgentPolicy::Auto))` and `Arc::new(AuditRing::default())`.
    - Block 1, `compile_fail`: builds `Governance { agent_state, audit_ring }` from those locals.
    - Block 2, `no_run`: uses the locals trivially (for example by dropping them), then
      `Config::default()`, `assemble(&cfg)?`, `assembled.governance()`, `services(&assembled.proxy,
      &cfg, None, TuiLog::Off)`, and `build_servers(&cfg, <services>, governance)`.

    The struct literal is the only difference between the two. Do not rely on an error-code suffix
    on `compile_fail`.
  - `tui.rs`:
    - The import becomes `use crate::wire::{Governance, Http1Sender};`.
    - New signatures:
      - `pub fn build_servers(cfg: &Config, services: Services, _governance: Governance) ->
        (Option<McpServer>, InProcessHandler)`.
      - `pub async fn run(cfg: &Config, proxy: &Proxy, services: Services, governance: Governance,
        main_listener: tokio::net::TcpListener, browser_listener: tokio::net::TcpListener) ->
        anyhow::Result<()>`. Its body passes `governance` to `build_servers`.
    - The agent arm stays **byte-for-byte as today**: `.with_agent_state(Arc::new(AgentState::new(
      cfg.mcp.policy)))`, its stale comment, and `.with_mcp_roles(..)`.
  - The temporary attribute: on the `Governance` item, add
    `#[expect(dead_code, reason = "not read until build_servers applies it to the agent arm")]`.
    - If rustc reports the expectation **unfulfilled** here, there is no warning to silence:
      delete the attribute and say so.
    - If the "never read" warning still appears, move the attribute onto the two fields.
    - Report which case occurred.
  - `main.rs`:
    - Bind `let assembled = assemble_with_scripts(..)?;`, then `let governance =
      assembled.governance();`, then destructure `let Assembled { proxy, ca, listening, agent_state,
      push_tx, audit_ring, l4_ingress, l4_guard } = assembled;`. Keep the existing comment inside
      the pattern verbatim.
    - The `Mode::Tui` branch passes `governance` as the fourth argument of `tui::run`.
    - No other line moves. The AC10 comment is Task 3.
  - `support/mod.rs`:
    - `pub fn assemble_services(cfg: &Config) -> (Proxy, Services, Governance)`. It binds
      `assemble(cfg)`, calls `.governance()` before destructuring `proxy`, and builds `services` as
      today.
    - The import gains `Governance`. Its doc says it also returns the core's `Governance` for
      `build_servers`.
  - `tui_embed.rs`: in `embed` and in `a_stdio_agent_transport_gets_no_agent_server_beside_the_tui`,
    bind `(_proxy, services, governance)` and pass `governance` to `build_servers`.
  - `tui_live_bus.rs`: the same change in `build_server`.
  - `l4_cua_tui.rs`:
    - Bind the `assemble_with(..).expect(..)` result.
    - Call `.governance()`.
    - Then destructure `let Assembled { proxy, l4_ingress, .. } = assembled;`.
    - Pass `governance` to `build_servers` at step (D).
  - No assertion in any of the three test files is edited.
- **Procedure (sandbox; paste each output):**
  1. Write everything above **except** the seal: `Governance`'s two fields are temporarily `pub`,
     and there is no `#[expect]`. `cargo build -p aitm --offline` must end `Finished`. Run
     `cargo test -p aitm --offline --doc`. **Red must show** `test result: FAILED. 1 passed; 1
     failed`. The failed test is the `- compile fail` one on `wire::Governance`, and its output says
     the test compiled successfully.
  2. Seal it: make both fields `pub(crate)` and add the `#[expect]` as described. Run
     `cargo test -p aitm --offline --doc`. It **must show** `test result: ok. 2 passed; 0 failed`,
     one line ending `- compile fail ... ok` and one ending `- compile ... ok`.
  3. `cargo fmt -p aitm`, then `cargo fmt --check` (exit 0).
     `cargo clippy -p aitm --all-targets --offline -- -D warnings` (exit 0).
     `cargo test -p aitm --offline --no-run` (ends `Finished`; every test binary compiles).
  4. `cargo test -p aitm --offline --test tui_embed`: `test result: ok. 3 passed; 0 failed`.
     `cargo test -p aitm --offline --lib tui::`: `test result: ok. 7 passed; 0 failed` (the
     seven existing `tui::tests`). `cargo test -p aitm --offline --test web_bus_ask_split`:
     `test result: ok. 7 passed; 0 failed`.
  5. Literal checks:
     - `grep -c "governance: Governance" crates/aitm/src/tui.rs` prints `2`.
     - `grep -c "_governance: Governance" crates/aitm/src/tui.rs` prints `1`.
     - `grep -c "AgentState::new(cfg.mcp.policy)" crates/aitm/src/tui.rs` prints `1` (the arm is
       untouched).
     - `grep -n "pub(crate) agent_state\|pub(crate) audit_ring" crates/aitm/src/wire.rs` prints two
       lines.
     - `grep -rn "tui-mode governance" crates/aitm/src/wire.rs` prints nothing.
- **Orchestrator (Terminal), after the Coder:** run
  `cargo test -p aitm --no-fail-fast --test tui_live_bus --test l4_cua_tui -- --nocapture > /tmp/tmg-t1-socket.log 2>&1; echo "exit=$?"; grep -E "^test result" /tmp/tmg-t1-socket.log; grep -c "refuses to bind" /tmp/tmg-t1-socket.log`.
  It **must show** `exit=0`, two `test result: ok. 1 passed; 0 failed` lines, and a skip count of
  `0`.
- **Tester (stage 5):** inputs per the dispatch contract: spec, plan, worktree, base `bd0f9b7`, head
  SHA, "Task 1", plus the orchestrator's socket log.
  - Re-run steps 2 to 5 in the sandbox and quote them.
  - Confirm that `Governance` has no `pub` field, constructor or accessor.
  - Confirm that `git diff --name-only` (run by the orchestrator) lists only the seven declared
    files.
  - Confirm that no `assert` line in the three existing test files changed.
- **Done when:** the step 1 red run and the step 2 green run are in the report, steps 3 to 5 are
  clean, and the socket log matches. The orchestrator then commits.

### Task 2: the tests, red against Task 1's production code, then the one-arm switch (AC1-AC7, AC9 red half)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6, AC7; AC9 (red half).
- **Depends on:** Task 1 committed.
- **Files:**
  - Pass A: `crates/aitm/tests/tui_mode_governance.rs` (create) and
    `crates/aitm/tests/tui_mode_governance_live.rs` (create). Nothing else.
  - Pass B: `crates/aitm/src/tui.rs` (modify: `build_servers` only) and
    `crates/aitm/src/wire.rs` (modify: delete the `#[expect]` only). No test file.
- **Pass A: `tui_mode_governance.rs`** (in-process; no sockets, no runtime; `mod support;`).
  - Constants: `AGENT_TOKEN`, `OPERATOR_TOKEN` (any distinct non-empty strings), and
    `PARK_BOUND: Duration = Duration::from_secs(5)`.
  - `struct Rig { cfg: Config, assembled: Assembled, agent: Arc<McpServer>, tui: InProcessHandler }`.
    Its `impl Drop for Rig` removes `cfg.ca.dir`.
  - `fn rig(tag: &str, policy: Option<AgentPolicy>) -> Rig`. It builds through the production path
    only:
    - `support::config(tag)`.
    - `cfg.mcp.transport = McpTransport::LoopbackTcp { port: 0, token: AGENT_TOKEN.into(),
      endpoint_file: None }`.
    - `cfg.mcp.operator_token = Some(OPERATOR_TOKEN.into())`.
    - If `Some(p)`, set `cfg.mcp.policy = p`; `None` keeps `Config::default()`'s.
    - `let assembled = aitm::wire::assemble(&cfg)`.
    - `assembled.governance()`.
    - `tui::services(&assembled.proxy, &cfg, None, TuiLog::Off)`.
    - `tui::build_servers(&cfg, services, governance)`.
    - `agent` = `Arc::new(` the `Some` arm `.expect("a loopback-TCP transport gets an agent
      server"))`.

    No builder call is added to either server (anti-goal: a hand-built rig).
  - Helpers. Names are free; shapes are fixed. Each returns or asserts on the **whole** JSON-RPC
    reply and prints it in every assertion message.
    - A `tools/call` line builder.
    - `agent_call(&Rig, &ConnCtx, name, arguments) -> Value` via `rig.agent.handle_on`.
    - `tui_call(&Rig, name, arguments) -> Value` via `(rig.tui)(&line)`.
    - `agent_call_within(&Rig, name, arguments) -> Value`. It runs the call as
      `ConnCtx::new(Frontend::Mcp)` on a detached `std::thread`, with an `Arc::clone` of the agent,
      sends the reply over `mpsc`, and does `recv_timeout(PARK_BOUND)`. On timeout it panics with
      "`<name>` did not return within 5s: the agent call parked instead of refusing".
    - `assert_ok(&Value)`: `result.isError == false`.
    - `assert_refused(&Value, &[&str])`: `result.isError == true`, and `result.content[0].text`
      contains every needle.
    - `tui_policy(&Rig) -> Value`: the TUI's `agent.status` → `structuredContent.policy`.
  - Tests (plain `#[test]`; literal values from the spec):
    - `a_tui_pause_refuses_the_loopback_agent_on_its_next_call` (AC1). Rig `None`. One agent
      `ConnCtx::new(Frontend::Mcp)` is reused throughout.
      - Agent `flow.list {}` → `assert_ok`.
      - TUI `agent.set {"policy":"paused"}` → `structuredContent.policy == "paused"`.
      - On the same ctx, `flow.list {}`, `agent.status {}` and `flow.subscribe {}` each →
        `assert_refused(.., &["the agent policy is `paused`"])`.
      - `tui_policy == "paused"`.
      - TUI `agent.set {"policy":"auto"}`, then agent `flow.list {}` → `assert_ok`.
    - `tui_readonly_and_ask_govern_the_loopback_agent_live` (AC2). Rig `None`.
      - TUI `agent.set {"policy":"readonly"}` → `structuredContent.policy == "readonly"`.
      - Agent `flow.list {}` → `assert_ok`.
      - Agent `flow.kill {}` → `assert_refused(.., &["`flow.kill` refused", "the agent policy is
        `readonly`"])`.
      - TUI `agent.set {"policy":"ask"}` → `structuredContent.policy == "ask"`.
      - `agent_call_within("scope.add", {"host":"example.com"})` →
        `assert_refused(.., &["no operator is connected to approve it"])`.
    - `the_seeded_policy_carries_over_to_the_loopback_agent` (AC3, guard).
      - Rig `Some(ReadOnly)`: the agent's **first** call, `flow.kill {}`, →
        `assert_refused(.., &["the agent policy is `readonly`"])`; `tui_policy == "readonly"`.
      - A second rig (distinct tag), `Some(Ask)`: `agent_call_within("scope.add",
        {"host":"example.com"})` → `assert_refused(.., &["no operator is connected to approve
        it"])`; `tui_policy == "ask"`.
    - `default_auto_still_refuses_a_sensitive_loopback_agent_call` (AC4, guard). Rig `None`.
      - Agent `flow.list {}` → `assert_ok`.
      - Agent `scope.add {}` → `assert_refused(.., &["the agent policy is `auto`"])`.
      - `tui_policy == "auto"`.
    - `loopback_agent_calls_land_in_the_shared_audit_trail` (AC5). Rig `Some(ReadOnly)`, fresh.
      - Agent `agent.status {}` and then agent `flow.kill {}`. Keep both replies; they are
        asserted **last**.
      - The TUI's **first** call, `agent.status {}`, →
        `structuredContent.actions_last_minute == 2`.
      - Its next call, `agent.activity {}`, → `structuredContent` is an array of **exactly** 2:
        - `[0]` has `origin == "mcp"`, `command == "agent.status"`, `result == "ok"`.
        - `[1]` has `origin == "mcp"`, `command == "flow.kill"`, and `result.error` is a string
          containing "readonly".
      - `rig.assembled.audit_ring.len() == 2`.
      - Only then: `assert_ok(status reply)` and `assert_refused(kill reply, &["readonly"])`.

      The audit assertions run first, so the red cause is the count.
    - `the_tui_operator_surface_stays_ungated_unrecorded_and_cannot_approve` (AC6, guard). Rig
      `Some(Paused)`.
      - TUI `flow.list {}` → `assert_ok` and `structuredContent == []`.
      - `tui_policy == "paused"`.
      - TUI `flow.intercept {"enabled": true}` → `assert_ok` and
        `structuredContent.enabled == true`.
      - TUI `flow.subscribe {}` → `assert_refused(.., &["only meaningful over a streaming MCP
        connection"])`.
      - TUI `agent.approve {"request_id":"apr_none","allow":true}` →
        `assert_refused(.., &["no parked request"])`.
      - `rig.assembled.audit_ring.len() == 0`.
- **Pass A: `tui_mode_governance_live.rs`** (AC7 only; `mod support;`; in the style of
  `tui_live_bus.rs`).
  - Copy `start_server` and `is_permission_denied` from `tui_live_bus.rs` (lines 66-107), with a
    5 s `STEP`.
  - Constants `AGENT_TOKEN` and `OPERATOR_TOKEN`.
  - A small guard removes `cfg.ca.dir` on drop. `assembled` stays alive to the end of the test.
  - `a_live_pause_reaches_an_open_loopback_connection_without_reconnecting`,
    `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`:
    - Build as the in-process rig does, with the config's default policy, through `assemble` →
      `governance()` → `services` → `build_servers`.
    - `start_server(agent)`. On `None`, print
      `tui_mode_governance_live: skipped — this sandbox refuses to bind 127.0.0.1:0
      (PermissionDenied); run cargo test -p aitm --test tui_mode_governance_live -- --nocapture in
      the Terminal panel`, then return. The note **must** contain `refuses to bind`.
    - One agent connection: `BusClient::new(Box::new(TcpTransport::connect(addr,
      AGENT_TOKEN)))`. `initialize("tui-mode-governance-live", "test")` gives `role.as_deref() ==
      Some("agent")`.
    - `call("flow.list", {})` → `Ok(json!([]))`.
    - TUI `agent.set {"policy":"paused"}` through the handler → `structuredContent.policy ==
      "paused"`.
    - The **same** client's `call("flow.list", {})` → `Err(BusError::Tool(t))` with `t` containing
      "the agent policy is `paused`". Any other value panics with "flow.list after agent.set paused
      on the same connection was not refused: {other:?}".
    - TUI `agent.activity {}` → an array of exactly 2:
      - `[0]` has `origin "mcp"`, `command "flow.list"`, `result "ok"`.
      - `[1]` has `origin "mcp"`, `command "flow.list"`, and `result.error` containing "paused".
    - Every await is bounded by `tokio::time::timeout(STEP, ..)`. `server_task.abort()` at the end.
- **Pass A procedure (Coder, sandbox).** Edit no file but the two above.
  1. `touch` both new files. Run
     `cargo test -p aitm --offline --test tui_mode_governance > $TMPDIR/tmg-red.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" $TMPDIR/tmg-red.log`.
     **Red must show:**
     - `exit=101` and `test result: FAILED. 3 passed; 3 failed`.
     - `ok`: the AC3, AC4 and AC6 tests.
     - `FAILED`, each for these reasons:
       - AC1: the agent's `flow.list` reply after `agent.set paused` has `"isError":false`.
       - AC2: the agent's `flow.kill` reply is a JSON-RPC `error` (code `-32602`, missing `id`)
         with no `result`, where a `readonly` refusal is expected.
       - AC5: `actions_last_minute` is `0` where `2` is expected.

     Paste the three `---- <name> stdout ----` blocks. Any other cause is a wrong test: fix the
     test, not production. Other causes include a panic in the rig, a missing agent server, or a
     timeout in `agent_call_within`.
  2. `cargo test -p aitm --offline --test tui_mode_governance_live --no-run` (ends `Finished`).
     `cargo fmt -p aitm && cargo fmt --check` (exit 0).
     `cargo clippy -p aitm --all-targets --offline -- -D warnings` (exit 0). Report "AC7 compiled,
     NOT RUN (socket)". Do not commit.
- **Red run (orchestrator, Terminal):**
  `cargo test -p aitm --test tui_mode_governance_live -- --nocapture > /tmp/tmg-live-red.log 2>&1; echo "exit=$?"; grep -E "^test result|panicked" /tmp/tmg-live-red.log; grep -c "refuses to bind" /tmp/tmg-live-red.log`.
  - It **must show** `exit=101`, `test result: FAILED. 0 passed; 1 failed`, and a panic naming the
    same-connection `flow.list` after `agent.set paused` as `Ok(Array [])`. The skip count is `0`.
  - A connect or bind error, or a panic before that assertion, sends the test back to the Coder.
    Save the log.
- **Pass B (Coder, sandbox; a second dispatch, "Task 2 pass B").** Edit exactly two places:
  - `tui.rs` `build_servers`:
    - Rename `_governance` to `governance`.
    - Replace `server(cfg, cfg.mcp.transport.clone(), &services)`, the stale five-line comment
      that begins "Not yet on `with_shared_governance`", and
      `.with_agent_state(Arc::new(AgentState::new(cfg.mcp.policy)))` with
      `with_shared_governance(server(cfg, cfg.mcp.transport.clone(), &services),
      &governance.agent_state, &governance.audit_ring)`.
    - Keep `.with_mcp_roles(cfg.mcp.operator_token.clone(), cfg.mcp.stdio_role)`.
    - The TUI-facing arm, the other comments, and `run` are untouched.
  - `wire.rs`: delete the `#[expect(dead_code, ..)]` (if Task 1 kept one).
  - Then:
    1. `touch` both source files. `cargo test -p aitm --offline --test tui_mode_governance`
       **must show** `test result: ok. 6 passed; 0 failed`.
    2. `cargo test -p aitm --offline --doc`: `2 passed`.
       `cargo test -p aitm --offline --lib tui::`: `7 passed`.
       `cargo test -p aitm --offline --test tui_embed`: `3 passed`.
       `cargo test -p aitm --offline --test web_bus_ask_split`: `7 passed`.
       `cargo test -p aitm --offline --test tui_mode_governance_live --no-run`: `Finished`.
    3. `cargo fmt --check` and `cargo clippy -p aitm --all-targets --offline -- -D warnings`, both
       exit 0.
    4. Literal checks:
       - `grep -c "AgentState::new(cfg.mcp.policy)" crates/aitm/src/tui.rs` prints `0`.
       - `grep -c "_governance: Governance" crates/aitm/src/tui.rs` prints `0`.
       - `grep -c "&governance.agent_state" crates/aitm/src/tui.rs` prints `1`.
       - `grep -c "expect(dead_code" crates/aitm/src/wire.rs` prints `0`.
       - `grep -n "Not yet on" crates/aitm/src/tui.rs` prints nothing.
- **Green run (orchestrator, Terminal):**
  - `cargo test -p aitm --test tui_mode_governance_live -- --nocapture > /tmp/tmg-live-green.log 2>&1; echo "exit=$?"; grep -E "^test result" /tmp/tmg-live-green.log; grep -c "refuses to bind" /tmp/tmg-live-green.log`.
    It **must show** `exit=0`, `test result: ok. 1 passed; 0 failed`, and `0`.
  - Then `cargo test -p aitm --no-fail-fast --test tui_live_bus --test l4_cua_tui --test tui_embed -- --nocapture > /tmp/tmg-t2-regress.log 2>&1; echo "exit=$?"; grep -E "^test result" /tmp/tmg-t2-regress.log; grep -c "refuses to bind" /tmp/tmg-t2-regress.log`.
    It **must show** `exit=0`, three `test result: ok.` lines (1, 1 and 3 passed), and `0`.
  - `git diff --stat -- crates/aitm/src` lists only `tui.rs` and `wire.rs`.
- **Tester (stage 5):** inputs as Task 1 with "Task 2", plus the three Terminal logs and pass A's
  sandbox red log.
  - Map AC1-AC7 to the seven tests.
  - Flag any assertion that would pass on a default, such as a test that never reads
    `result.isError`, or AC5/AC6 not reading `audit_ring.len()`.
  - Re-run pass B steps 1 to 4 in the sandbox.
  - The Tester may add tests **only** inside the two new files. Each added test must be declared
    red-set or guard, and its expected effect on the Task 4 mutation counts stated; the
    orchestrator updates Task 4's counts before running it.
- **Done when:** the sandbox red log (3 failed, 3 ok), the Terminal red log (AC7 failed on policy),
  the sandbox green run (6 passed), and both Terminal green logs are in the reports, and fmt and
  clippy are clean. The orchestrator then commits passes A and B as one commit.

### Task 3: doc comments state Design 2 (AC10)

- **Satisfies:** AC10.
- **Depends on:** Task 2 committed.
- **Files:**
  - `crates/aitm/src/tui.rs` (modify: doc comments and comments only).
  - `crates/aitm/src/wire.rs` (modify: the docs of `Assembled::agent_state` and
    `Assembled::audit_ring` only).
  - `crates/aitm/src/main.rs` (modify: one comment inside the `Mode::Tui` branch only).
- **Change.** Wording is free, but it must state what follows. Use plain backticks, not intra-doc
  links, for cross-module names. Never write a comparison against `Frontend::Mcp` (trust-gate
  scan). Never use the phrases `Not yet on`, `does not use it yet` or `tui-mode governance`.
  - `tui.rs` module doc:
    - The agent-facing server (loopback TCP or streamable HTTP) runs on the core's shared
      `AgentState` and `AuditRing`, which `build_servers` receives as a sealed `Governance`.
    - The TUI's in-process server is the operator, ungated by role.
    - It is deliberately **not** on the shared ring: its polling, about 220 calls a minute, would
      flood it.
  - `server()` doc: replace the last sentence, about the loopback agent "not using it yet". The
    replacement says that `build_servers` applies `with_shared_governance` to the `aitm tui`
    loopback agent server from the `Governance` it requires.
  - `build_servers` doc: it requires a `Governance`, which only `Assembled::governance` makes. The
    agent arm goes through `with_shared_governance`; the TUI-facing arm does not. The doc states
    the consequences:
    - `agent.set` from the TUI or from any operator-token client governs the agent on its next
      call.
    - `push_tx` is not fed (follow-up "tui-mode push").
    - Under `ask`, only an operator-token client subscribed on this same server can approve. The
      TUI cannot, so with only the TUI attached a Sensitive agent call is refused at once.
  - `build_servers` agent-arm comment: replace the two redundant paragraphs above the
    `McpTransport::LoopbackTcp { .. } | McpTransport::StreamableHttp { .. }` arm with one comment.
    It says the arm is agent-facing and gated, on the shared governance, with the operator/agent
    token classes.
  - `run` doc: `governance` comes from `Assembled::governance()` in `main.rs` and is passed through
    to `build_servers`.
  - `with_shared_governance` doc:
    - Name `build_servers` as a caller beside `main.rs`.
    - Say that TUI mode is **compile-enforced**, because `build_servers` cannot be called without a
      `Governance`, while the bare-`aitm` path applies it **by convention**.
    - Keep the first line ("Apply the shared agent policy and audit ring to `server`") verbatim,
      and keep the `Ask`-hub paragraph.
    - Update the residual-risk paragraph so it no longer implies that no test exercises any
      production wiring: `build_servers` is exercised by `tui_mode_governance`; `main.rs`'s
      bare-path calls are not.
  - `wire.rs` `Assembled::agent_state` and `Assembled::audit_ring` docs: keep what they say, and add
    that the `aitm tui` loopback agent server receives the same `Arc` through
    `Assembled::governance`.
  - `main.rs`: inside `if mode == Mode::Tui {`, above `tokio::select!`, add one comment. It says
    the loopback agent server is built by `tui::build_servers` on the core's shared policy and
    audit ring (the `governance` passed here), and that `push_tx` is not fed to it (follow-up
    "tui-mode push"). PR 145's comment in the `else` branch is not touched.
- **Test:** no new automated test. AC10 is grep- and review-checked. Run in the sandbox and paste:
  - `grep -n "Not yet on" crates/aitm/src/tui.rs`,
    `grep -n "does not use it yet" crates/aitm/src/tui.rs` and
    `grep -rn "tui-mode governance" crates/aitm/src` each print nothing (exit 1).
  - `sed -n '/^\/\/\/ Apply the shared agent policy/,/^pub fn with_shared_governance(/p' crates/aitm/src/tui.rs | grep -c "build_servers"`
    prints at least `1`. The same pipeline with `grep -c "convention"` prints at least `1`.
  - `grep -n "Assembled::governance" crates/aitm/src/wire.rs` shows a hit above
    `pub agent_state` and a hit above `pub audit_ring`. `grep -n "aitm tui" crates/aitm/src/wire.rs`
    likewise.
  - `sed -n '/if mode == Mode::Tui {/,/} else {/p' crates/aitm/src/main.rs | grep -c "push_tx"`
    prints at least `1`.
  - `cargo build -p aitm --offline` ends `Finished`. `cargo fmt --check` and
    `cargo clippy -p aitm --all-targets --offline -- -D warnings` exit 0.
    `cargo test -p aitm --offline --test tui_mode_governance` (6 passed) and
    `cargo test -p aitm --offline --doc` (2 passed) still pass.
- **Orchestrator (Terminal), after the Coder:**
  - `git diff -- crates/aitm/src | grep -E '^[-+][^-+]' | grep -vE '^[-+][[:space:]]*//'` prints
    nothing: only comment lines changed.
  - `git diff --name-only` lists only the three declared files.
- **Tester (stage 5):** inputs as Task 1 with "Task 3", plus the orchestrator's two outputs.
  - Re-run the greps.
  - Read each doc against Design 2 and the six consequences in Design 5. Flag any claim that is
    false of the code.
- **Done when:** every literal check prints what is stated, the reading finds no false claim, and
  the orchestrator has committed.

### Task 4: orchestrator checkpoint (Terminal panel; no Coder, no retained edits)

- **Satisfies:** AC9 (final head), AC11, AC12; spot-checks AC10.
- **Depends on:** Tasks 1-3 committed. `T1` is Task 1's commit SHA.
- **Files:** none retained. Step 2 temporarily replaces `crates/aitm/src/tui.rs` and restores it.
- **Steps and required output:**
  1. **Full gate** on the final head:
     `(cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test) > /tmp/tmg-gate.log 2>&1; echo "gate exit=$?"`
     **must print** `gate exit=0`. Then
     `grep -E "Running tests/(tui_|l4_cua_tui|web_bus_|discover_e2e)|Doc-tests aitm$|^test result" /tmp/tmg-gate.log`
     shows each binary followed by `ok`:
     - `tui_mode_governance` (6), `tui_mode_governance_live` (1), `tui_embed` (3),
       `tui_live_bus` (1), `l4_cua_tui` (1).
     - `web_bus_governance` (7), `web_bus_ask_split` (7), `web_bus_roles` (5),
       `web_bus_concurrency` (11), `web_bus_push` (10), `discover_e2e` (3).
     - `Doc-tests aitm` (2).

     `grep -c "refuses to bind" /tmp/tmg-gate.log` should print `0`. cargo captures passing tests'
     output, so this is a weak check; steps 2 and 3 are the strong ones.

     Known flake: if `rhai_e2e::script_cannot_escape_or_exceed_scope` is the only failure, re-run
     once and judge by whether this diff touches Rhai (it does not). Record it in the Review log.
  2. **AC9 mutation (final head).**
     - Apply: `git show T1:crates/aitm/src/tui.rs > crates/aitm/src/tui.rs`. This is exactly "new
       signatures, today's arm, parameter `_governance`".
     - Verify: `grep -c "_governance: Governance" crates/aitm/src/tui.rs` prints `1`, and
       `grep -c "AgentState::new(cfg.mcp.policy)" crates/aitm/src/tui.rs` prints `1`.
     - Fallback, if a later fix changed `tui.rs` so `T1`'s copy no longer compiles: make the two
       edits by hand instead. Rename the parameter to `_governance`, and replace the
       `with_shared_governance(..)` wrapping in the agent arm with `server(cfg,
       cfg.mcp.transport.clone(), &services).with_agent_state(Arc::new(AgentState::new(
       cfg.mcp.policy)))`.
     - rustc may warn that `Governance`'s fields are never read. That is expected and is not an
       error under `cargo test`.
     - Then run:
       - `cargo test -p aitm --test tui_mode_governance > /tmp/tmg-mut.log 2>&1; echo "exit=$?"; grep -E "^test |^test result" /tmp/tmg-mut.log`.
         It **must show** `exit=101` and `test result: FAILED. 3 passed; 3 failed`, with FAILED =
         AC1, AC2, AC5 and ok = AC3, AC4, AC6.
       - `cargo test -p aitm --test tui_mode_governance_live -- --nocapture > /tmp/tmg-mut-live.log 2>&1; echo "exit=$?"; grep -E "^test result|panicked" /tmp/tmg-mut-live.log; grep -c "refuses to bind" /tmp/tmg-mut-live.log`.
         It **must show** `exit=101`, `test result: FAILED. 0 passed; 1 failed`, and `0`.
     - Each failure must name the policy or audit cause: `isError:false` after `paused`; the
       unrefused `flow.kill`; `actions_last_minute` `0`; `Ok(Array [])`. None may be a compile,
       connect, or rig error.
     - If the Tester added tests, use the counts the orchestrator recorded at Task 2.
     - Restore: `git checkout -- crates/aitm/src/tui.rs && git status --short` prints nothing. Then
       re-run both commands: `exit=0` with `6 passed` and `1 passed`.
  3. **AC12 and AC11 diff checks** (explicit base SHA, since `main` moves):
     - `git diff --stat bd0f9b7..HEAD -- crates/aitm-mcp crates/aitm-core crates/aitm-tui crates/aitm-bus-client crates/aitm/src/web`
       prints nothing.
     - `git diff --stat bd0f9b7..HEAD -- crates/aitm/tests/web_bus_governance.rs crates/aitm/tests/web_bus_ask_split.rs crates/aitm/tests/web_bus_roles.rs crates/aitm/tests/web_bus_concurrency.rs crates/aitm/tests/web_bus_push.rs crates/aitm/tests/discover_e2e.rs`
       prints nothing.
     - `git diff bd0f9b7..HEAD -- crates/aitm/tests/tui_embed.rs crates/aitm/tests/tui_live_bus.rs crates/aitm/tests/l4_cua_tui.rs | grep -E '^[-+].*assert'`
       prints nothing.
     - `diff <(git show bd0f9b7:crates/aitm/src/tui.rs | sed -n '/^mod tests {/,$p') <(sed -n '/^mod tests {/,$p' crates/aitm/src/tui.rs)`
       prints nothing: the unit tests are unchanged.
     - `diff <(git show bd0f9b7:crates/aitm/src/tui.rs | sed -n '/^pub fn with_shared_governance(/,/^}/p') <(sed -n '/^pub fn with_shared_governance(/,/^}/p' crates/aitm/src/tui.rs)`
       prints nothing: the function is unchanged; only its doc moved.
     - `git diff --name-only bd0f9b7..HEAD` lists only these files, plus this plan and the spec:
       - `crates/aitm/src/main.rs`, `crates/aitm/src/tui.rs`, `crates/aitm/src/wire.rs`.
       - `crates/aitm/tests/support/mod.rs`, `crates/aitm/tests/tui_embed.rs`,
         `crates/aitm/tests/tui_live_bus.rs`, `crates/aitm/tests/l4_cua_tui.rs`.
       - `crates/aitm/tests/tui_mode_governance.rs`,
         `crates/aitm/tests/tui_mode_governance_live.rs`.
  4. **AC10 spot-check.**
     - Re-run Task 3's greps on the head.
     - `diff <(git show bd0f9b7:crates/aitm/src/main.rs | sed -n '/dedicated agent entry point/,/let mcp = tui::with_shared_governance(/p') <(sed -n '/dedicated agent entry point/,/let mcp = tui::with_shared_governance(/p' crates/aitm/src/main.rs)`
       prints nothing: PR 145's comment is unchanged.
- **Done when:** all four steps print what is stated, with the logs saved and quoted in the
  whole-branch Tester report.

## Whole-branch stage 5 and stage 6

1. **Whole-branch Tester** (after Task 4). Inputs per the dispatch contract: spec, plan, worktree,
   base `bd0f9b7`, head SHA, "whole branch", with the Task 4 logs attached. Every criterion AC1-AC12
   must map to a test or a literal check, and the Tester quotes the gate output. PASS or FAIL with
   reasons.
2. **Panel, in parallel, fresh contexts:** `security-reviewer`, `quality-reviewer`,
   `spec-reviewer`. Each gets the spec, plan, worktree, base `bd0f9b7`, head SHA, "whole branch",
   the Coders' reports, and the Tester report. Suggested focus, not a limit:
   - **Security.**
     - The `aitm tui` agent server cannot reach any command the shared gate refuses under the same
       policy.
     - The in-process operator server stays ungated and unrecorded.
     - `Governance` cannot be minted outside the crate (the doctest).
     - The `ask` behaviour change fails closed: an immediate refusal with only the TUI attached.
     - The shared ring is now also written by the TUI-mode agent server. A loopback agent can
       flood it; this is the same class as the web bridge and is filed under "audit
       signal-to-noise".
   - **Quality.**
     - The temporary `#[expect]` is gone.
     - Duplicated helpers are accepted by the spec.
     - Test determinism: bounded waits, no sleeps standing in for synchronisation.
     - Comment accuracy in `tui.rs`, `wire.rs` and `main.rs`.
   - **Spec.**
     - AC1-AC12 against the tests.
     - Nothing changed outside `crates/aitm` and the spec and plan.
     - The spec's `Status` line is untouched.
     - The PR description states all six consequences in Design 5.
3. The orchestrator records every finding and its disposition in the Review log below. Critical and
   Important findings go to a fresh Coder as a fix task; then Tester and panel run again on the fix,
   with the prior report. No merge with an open finding.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| whole branch (round 1, `646dd8c`) | spec | Important | AC12: the full gate exits non-zero because `aitm-tui` token tests were already red on main (PR 154 token drift), not caused by this diff | Resolved by merging main with PR 161's fix (`2303b15`); full gate on `02ef931` exits 0 (223 test binaries ok, 0 failed) |
| whole branch (round 1) | spec | Minor | The `Arc::ptr_eq` unit test lives in `crates/aitm/src/wire.rs`, against the spec's test-placement constraint | Accepted (orchestrator, under the autonomous-approve mode): it reads `pub(crate)` fields so it must live in the crate; `trust_gate_scan` passes; recorded as plan amendment |
| whole branch (round 1) | spec | Minor | A comment was added on the TUI-facing arm, a place Task 3 does not list | Accepted (orchestrator): accurate, restates Design 2's deliberate-ungoverned decision, comment-only |
| whole branch (round 1) | spec, quality | Minor | The malformed-input test pins aitm-mcp-owned JSON-RPC error codes | Fixed in `02ef931` (table cut to the governance core); follow-up: move the full table into aitm-mcp tests |
| whole branch (round 1) | spec | Minor | The PR description must state all six Design 5 consequences | Done in the PR body (stage 7) |
| whole branch (round 1) | security | Minor | `Governance` is sealed but `Assembled`'s `pub` fields let outside code choose what `governance()` returns | Fixed in `02ef931`: private `governance` field filled at assembly; new red-then-green unit test `governance_is_fixed_at_assembly_not_read_from_the_public_fields` |
| whole branch (round 1) | security | note (pre-existing) | `AuditEntry.client_label` and the error reason are uncapped (a 16 MiB `clientInfo.name` is cloned into every audited entry; the ring can hold about 64 GiB) | Out of scope, outside this diff; filed in the PR description under the "audit signal-to-noise" follow-up |
| whole branch (round 1) | quality | Minor | `parked.join()` is unbounded (120 s hang instead of a 5 s failure) | Fixed in `02ef931` (bounded by `PARK_BOUND`, shared spawn helper) |
| whole branch (round 1) | quality | Minor | The oversized/redacted test pins aitm-mcp redaction and cap rules | Fixed in `02ef931` (keeps one shared-ring row, origin, and no secret in the trail; renamed); follow-up: move the cap/marker assertions into aitm-mcp tests |
| whole branch (round 1) | quality | Minor | The `build_servers` doc restates aitm-mcp rules, uses change-relative wording, and says "builds its one" | Fixed in `02ef931` (trimmed to its contract) |
| whole branch (round 1) | quality | Minor | Helpers duplicated inside `tui_mode_governance.rs`; timeout messages hard-code "5s" | Fixed in `02ef931` (delegating helpers, one spawner, `{PARK_BOUND:?}`/`{STEP:?}`) |
| whole branch (round 1) | quality | Minor | Module doc lists only AC1-AC6; a stage/task banner left in source | Fixed in `02ef931` |
| whole branch (round 1) | tester | Minor | Docs say "its only source" (overstates the seal) and "allowed or refused ... land in `agent.activity`" (a successful `flow.subscribe`, a `needs_confirmation` step and protocol errors are not audited) | Fixed in `02ef931` |
| whole branch (round 2, `0978adb`) | security, quality, spec, tester | none | Round 2 verdicts: security PASS, quality PASS, spec PASS (the round-1 Important is resolved), tester PASS; no Critical or Important findings | n/a |
| whole branch (round 2) | spec | Minor | The acceptance of a unit test in `src/` named only `governance_carries_the_assemblys_own_state_and_ring` | Accepted (orchestrator): the same reason covers both `wire::tests` functions, `governance_carries_the_assemblys_own_state_and_ring` and `governance_is_fixed_at_assembly_not_read_from_the_public_fields` (`Arc::ptr_eq` on `pub(crate)` fields is only possible inside the crate) |
| whole branch (round 2) | spec | Minor | The PR body must state the six Design 5 consequences and carry the `client_label` note | Done in the PR body (checked by the orchestrator after the PR was opened) |
| whole branch (round 2) | quality | Minor | The trimmed malformed-input test no longer covers `tools/call` errors that reach `call_tool` (unknown tool, non-object `arguments`, undeclared argument) | Fixed in `332b51e` (three code-agnostic cases added: error, no `result`, ring unchanged) |
| whole branch (round 2) | quality | Minor | The oversized-secret test lost the comment on why the key order matters | Fixed in `332b51e` |
| whole branch (round 2) | quality | Minor | `wire.rs` states the "fixed at assembly, private" rule four times | Fixed in `332b51e` (stated once on the `Governance` doc) |
| whole branch (round 2) | quality | Minor | The `..` in `main.rs` drops the exhaustive-destructure check | Accepted (orchestrator) as a design consequence of the private field; `main.rs` comment reworded in `332b51e` to say any new `pub` field of `Assembled` must be named there |
| whole branch (round 2) | quality | Minor | `tui.rs` module doc lists only `flow.subscribe` as unaudited (aitm-mcp also exempts `flow.unsubscribe`); AC1, AC2, AC5 test docs lack the red-set label | Fixed in `332b51e` |
| whole branch (round 2) | security | Minor | A `Governance` from a second `assemble()` can be paired with the first assembly's `services` and reproduce the original bug (in-process only; not reachable from the network, a plugin or an MCP caller; pre-existing in round 1) | Accepted with docs narrowed in `332b51e`: the `build_servers` and `Governance` docs no longer claim "not with a fresh state" and now say the pair is not tied to the `Proxy` in `services`. Added to the spec's "what this still cannot force" list as item 4 by this entry. Structural fix (`services()` carrying the `Governance`) deliberately not done: it touches every `services()` caller including PR 145's tests |
| whole branch (round 2) | security | Minor | No test anywhere pins the 512-byte audit args-summary cap | Partly fixed in `332b51e`: one length assertion (`args.len() <= DEFAULT_ARGS_SUMMARY_CAP + 3`) restored in the oversized test; a unit test in `aitm-mcp` for `redact_args` remains a follow-up (this change may not edit `aitm-mcp`), listed in the PR description |
| whole branch (round 2) | tester | note | The trimmed tests no longer pin the exact error codes or the `<redacted>` marker | Accepted: owned by aitm-mcp (`protocol_errors` pins codes, `mcp.rs` redaction tests pin the marker); recorded as the PR follow-up |

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.

Follow-ups already named in the spec (not built here): "tui-mode push" (feed `push_tx` to the
TUI-mode agent server); "unified agent hub" (approve parked calls from the TUI); "audit
signal-to-noise" (auditing the TUI's own operator calls, ring flooding, attribution); "configurable
startup policy" (an `mcp.policy` key, env var, or flag).
