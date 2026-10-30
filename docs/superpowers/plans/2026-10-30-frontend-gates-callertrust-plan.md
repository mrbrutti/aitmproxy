# Route every agent gate through one trust predicate implementation plan

**Status:** Approved — orchestrator, 2026-10-30 (autonomous mode, as the spec)
**Orchestrator amendments (execution only, no scope change):** Tasks 2-9 run as parallel Coders in this one worktree, so (1) **no Coder runs the per-task mutation proof** (it edits `aitm-core/src/ctx.rs`, which every other Coder compiles against): the Tester runs M1/M2 once on the integrated branch, as the Verification section already specifies, and Global constraint (e) is replaced by that; (2) **Coders do not commit**: the orchestrator commits each task's files afterwards via the Terminal panel, one commit per task with the stated message; (3) a Coder touches only its task's files and, if a build or test fails in a file outside them, waits and retries rather than editing it; (4) Coders run `cargo test -p <their crate>` only; the full workspace gate runs once, on the integrated branch.
**Spec:** `docs/superpowers/specs/2026-10-30-frontend-gates-callertrust-design.md`
**Branch / worktree:** `fix/frontend-gates-callertrust`, already checked out in `/Users/matt/Security/aitmproxy/.claude/worktrees/elastic-margulis-d668fe`, stacked on open PR #101's head `312bd31` (that is why `is_trusted_control` in `aitm-mcp` and the "Adding a variant" doc note exist in this tree). Independent tasks may fan out to child branches cut from this one.

## Overview

Add one wildcard-free predicate in `aitm-core` (`CallerTrust::is_trusted_control`) with a `Frontend` and a `CommandHost` entry point (Task 1). Then migrate each deny-list gate, crate by crate, to ask it; each of Tasks 2-9 is one crate and a one-line condition (plus a few new tests where a role was never asserted), and leaves the workspace green (Tasks 2-9). Last, add the narrow source-scan guard so the shape cannot return (Task 10). **Task 1 first; Tasks 2-9 are mutually independent (disjoint files, each needs only Task 1); Task 10 last (needs 2-9).**

| Task | Crate | Files touched |
|---|---|---|
| 1 | `aitm-core` | `crates/aitm-core/src/ctx.rs` |
| 2 | `aitm-plugins` | `src/scope.rs`, `src/agent.rs`, `tests/agent_gates.rs` (new) |
| 3 | `aitm-proto-l4` | `src/commands/agent.rs`, `tests/operator_surfaces.rs` |
| 4 | `aitm-proto-l4` | `src/language.rs` |
| 5 | `aitm-findings` | `src/commands.rs`, `tests/findings.rs` |
| 6 | `aitm-poc` | `src/runner.rs`, `tests/script_command.rs` |
| 7 | `aitm-plugin-rhai` | `src/commands.rs` |
| 8 | `aitm` | `src/macos_capture/activation_gate.rs` |
| 9 | `aitm-mcp` | `src/server.rs` |
| 10 | `aitm-core` | `tests/trust_gate_scan.rs` (new), `src/ctx.rs` (one doc sentence) |

Tasks 3 and 4 share a crate but touch disjoint files. No two of Tasks 2-9 share a file. Tasks 1 and 10 both edit `ctx.rs`, so they are ordered.

WORKFLOW runs the panel after each task and once on the whole branch. Tasks 2-9 are one-line migrations; the orchestrator may run one panel over Tasks 1-9 and one on the whole branch. That is the orchestrator's call.

## Global constraints

- **Byte-for-byte behaviour.** The only code change in a migrated file is the gate condition and the `use` list. No string literal, error text, condition order or operand order changes. An agent sees the same refusal first as before. (AC17)
- **Do not reroute the Cli-only gates.** Do not edit `aitm-plugin-sessionio/src/lib.rs`, `aitm-ca/src/commands.rs`, `aitm-plugin-passthrough/src/lib.rs`, `aitm-plugin-maprules/src/lib.rs`, `aitm-plugin-rhai/src/commands.rs::confine_validate`, `aitm-mcp/src/server.rs` line ~1420 (`conn.role == Frontend::Operator`), or any label site (`role_str`, `frontend_label`, `origin_str`, `origin_from`). Operator must not newly bypass them. (AC15)
- **Unused imports are errors** (workspace lints with `-D warnings`). When a file stops naming `Frontend` (or `CallerTrust`), remove it from the `use` list. Per file: `scope.rs`, `plugins/agent.rs`, `l4/commands/agent.rs`, `findings/commands.rs`, `poc/runner.rs`: drop `Frontend`; `l4/language.rs`: drop `CallerTrust`; `rhai/commands.rs` keeps both (`confine_validate`, `CallerTrust::from` sites); `activation_gate.rs` keeps `Frontend` (parameter type); `server.rs` keeps `Frontend`.
- **No second definition of "trusted"**, and no `== CallerTrust::Agent` / `is_agent()` as a gate input. Delegate to `is_trusted_control`.
- **Wildcard-free classifiers.** `CallerTrust::from`, `CallerTrust::is_trusted_control`, `audit::origin_label` have no `_` arm.
- **TDD for a pure refactor.** A behaviour-preserving migration cannot have a failing test first. Each of Tasks 2-9 therefore: (a) first adds the **characterization test** where an Operator/Cli/Mcp assertion is missing (it passes on the old code, and the Coder's report says so); (b) runs the existing tests green as the baseline; (c) migrates; (d) runs green; (e) runs the **mutation proof** once and reverts it: in `crates/aitm-core/src/ctx.rs` set `CallerTrust::is_trusted_control` to return `true` for `Agent` (M1), confirm this task's named agent-refused tests go **red**; then return `false` for `Operator` (M2), confirm the named Operator/Cli-pass tests go **red**; `git checkout crates/aitm-core/src/ctx.rs`. The report quotes the red output. Real red-first tests exist only in Task 1 (new methods do not exist) and Task 10 (scanner does not exist).
- **Full gate before any review:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Port-binding tests need the Terminal panel (sandbox). The workspace shares build artefacts across worktrees: `touch` edited sources before a gate or a live run so stale artefacts are not reused (project memory).
- **Git via the Terminal panel only.** Commit bodies must not contain words that start with a hash character (hook quirk). Commit after each task.
- **Known flake:** see Verification. Do not "fix" it here.

## Review focus

- Operator newly bypassing a Cli-only gate, or Operator newly gated anywhere. (Tasks 2-9, AC15)
- A changed message, condition order, or operand order. (AC17)
- A wildcard in a classifier, a deny-list in the helper, or a second `match` that classifies. (Task 1)
- A removed `Frontend`/`CallerTrust` import that is still used, or one left unused. (Tasks 2-9)
- The scan test passing vacuously (wrong path, zero files). (Task 10)
- `aitm-mcp` keeping the `conn.role == Frontend::Operator` handshake untouched. (Task 9)

---

## Tasks

### Task 1: the shared predicate in `aitm-core`

- **Satisfies:** AC1, AC2, AC3, AC4, AC16 (core docs)
- **Depends on:** none
- **Files:** `crates/aitm-core/src/ctx.rs` (modify, including a new `#[cfg(test)] mod trust_tests`)
- **Change:**
  - `impl CallerTrust { pub fn is_trusted_control(self) -> bool }`: `match self` with exactly `CallerTrust::Operator => true` and `CallerTrust::Agent => false`, **no wildcard**.
  - `impl Frontend { pub fn is_trusted_control(self) -> bool }`: delegates, `CallerTrust::from(self).is_trusted_control()`. Not a second `match`.
  - `impl<'a> CommandHost<'a> { pub fn caller_is_trusted_control(&self) -> bool }`: one line over the stored `Frontend`.
  - `#[must_use]` on all three (recommended).
  - Docs, per the spec's "Documentation updates": rewrite the `Frontend` "Adding a variant" note (classify in `CallerTrust::from` and `audit::origin_label`, both wildcard-free so `aitm-core` will not build until you do; every trust gate derives from `CallerTrust::is_trusted_control` via `Frontend::is_trusted_control` / `CommandHost::caller_is_trusted_control`; if `CallerTrust` grows classify it in `is_trusted_control`; never compare a `Frontend` with `==`/`!=` to decide trust; label-only sites map an unclassified variant to the agent label with `_ =>` and are not gates; Cli-only `!= Frontend::Cli` gates gate any non-Cli variant automatically; **default a new variant to `Agent`**). Rewrite the `CallerTrust::from` doc (drop "**iff** `Frontend::Mcp`", state the table, restate the default). Mention `is_trusted_control` in the `CallerTrust` type doc. Do not yet mention the scan test (Task 10 adds that sentence). Leave `aitm-mcp`'s private helper untouched in this task; it is removed in Task 9.
- **Test (red first: does not compile until the methods exist):** in `ctx.rs`'s new test module (must be in `aitm-core/src`, because a wildcard-free `match` over the `#[non_exhaustive]` `Frontend` compiles only in-crate):
  - `caller_trust_predicate_pins_both_variants`: `CallerTrust::Operator.is_trusted_control()` is `true`; `CallerTrust::Agent.is_trusted_control()` is `false`.
  - `caller_trust_from_frontend_pins_all_three`: `assert_eq!(CallerTrust::from(Frontend::Cli), CallerTrust::Operator)`; `Frontend::Operator` => `CallerTrust::Operator`; `Frontend::Mcp` => `CallerTrust::Agent`.
  - `frontend_predicate_pins_all_three_and_matches_caller_trust`: a private `fn expected_trusted(f: Frontend) -> bool` with a **wildcard-free** `match` (`Cli | Operator => true`, `Mcp => false`) and a private wildcard-free `match` over `CallerTrust`; loop over `[Frontend::Cli, Frontend::Mcp, Frontend::Operator]` asserting `f.is_trusted_control() == expected_trusted(f)` and `== CallerTrust::from(f).is_trusted_control()`. Literals: `Cli` true, `Operator` true, `Mcp` false.
  - `command_host_caller_is_trusted_control_follows_frontend`: a `CommandHost::new(&MemFlowStore::new(), &stub_client, &StdGuard::default(), None)` never given a frontend returns `false`; `.with_frontend(Frontend::Cli)` `true`; `.with_frontend(Frontend::Operator)` `true`; `.with_frontend(Frontend::Mcp)` `false` (one host per assertion; `with_frontend` consumes the host). The existing `NoopClient` in `ctx.rs` may be reused or re-declared.
- **Done when:** `cargo test -p aitm-core` is green and the full gate passes. Commit: `refactor(core): add the shared CallerTrust::is_trusted_control predicate (Task 1)`.

### Task 2: `aitm-plugins` gates (`scope.add`, `agent.set`, `agent.approve`)

- **Satisfies:** AC5, AC6, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-plugins/src/scope.rs` (modify), `crates/aitm-plugins/src/agent.rs` (modify), `crates/aitm-plugins/tests/agent_gates.rs` (create)
- **Change:**
  - `scope.rs` (~89, `ScopeAdd::invoke`): the condition becomes `!host.caller_is_trusted_control() && !self.allow_agent_widen`; the `bail!` text is untouched. Drop `Frontend` from the `use aitm_core::{...}` list.
  - `agent.rs` (~184 `AgentSet::invoke`, ~331 `AgentApprove::invoke`): each condition becomes `!host.caller_is_trusted_control()`; texts untouched. Drop `Frontend` from the import. Refresh the two nearby comments if they say "Frontend::Mcp".
  - New `tests/agent_gates.rs`: a small helper that builds a `MemFlowStore`, a stub `ProxyClient` (bails if called, as in `control.rs`), `StdGuard::default()`, and a `CommandHost` `with_frontend(f)`.
- **Test:** (written first; passes on the old code because it characterizes it)
  - `agent_set_refuses_the_agent_and_admits_operator_and_cli`: `state = Arc::new(AgentState::new(AgentPolicy::All))`, a `Registry` with `AgentPlugin::new(state.clone())`, invoke `agent.set`:
    - `Frontend::Mcp`, `{policy: "paused"}`: `Err` whose `to_string()` equals `agent.set refused: the agent cannot change its own policy; only an operator or the human CLI may set it.`; `state.policy() == AgentPolicy::All`.
    - `Frontend::Operator`, `{policy: "paused"}`: `Ok(Value::Object)` with `"policy" => Value::Str("paused")`; `state.policy() == AgentPolicy::Paused`.
    - `Frontend::Cli`, `{policy: "readonly"}`: `Ok(Value::Object)` with `"policy" => Value::Str("readonly")`; `state.policy() == AgentPolicy::ReadOnly`.
  - `agent_approve_command_refuses_the_agent_and_lets_humans_reach_the_fallback`: invoke `agent.approve {request_id: "x", allow: true}`:
    - `Mcp`: `Err` equal to `agent.approve refused: the agent cannot approve its own requests; only an operator or the human CLI may approve a parked sensitive command.`
    - `Operator` and `Cli`: `Err` equal to `agent.approve is resolved by the MCP server against its parked-request table; it cannot be invoked in this context.`
  - Existing, unchanged and must stay green: `scope_rate.rs::scope_add_gated_from_agent_frontend`, `operator_may_widen_scope`.
  - Mutation proof (see Global constraints). M1 red: `scope_add_gated_from_agent_frontend`, `operator_may_widen_scope`, both new agent-arm assertions. M2 red: `operator_may_widen_scope`, the new Operator and Cli arms.
- **Done when:** `cargo test -p aitm-plugins` green and the full gate passes. Commit: `refactor(plugins): route scope.add, agent.set, agent.approve through the shared trust predicate (Task 2)`.

### Task 3: `aitm-proto-l4` command gates (`L4AgentGate`, `l4.agent.set`)

- **Satisfies:** AC7, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-proto-l4/src/commands/agent.rs` (modify), `crates/aitm-proto-l4/tests/operator_surfaces.rs` (modify)
- **Change:**
  - `L4AgentGate::invoke` (~68): condition becomes `!host.caller_is_trusted_control() && !self.gates.allowed(self.gate)`; the `bail!` text and the order (trust check first, then the flag) are untouched.
  - `AgentSet::invoke` (~172): condition becomes `!host.caller_is_trusted_control()`; text untouched.
  - Drop `Frontend` from the `use aitm_core::{...}` list (line ~24). Doc and comments that say "`Frontend::Mcp` caller" may be reworded to "untrusted (agent) caller"; optional.
- **Test:** (new tests written first; they pass on the old code)
  - `cli_inject_bypasses_the_agent_gate_and_reaches_the_guard` in `operator_surfaces.rs`: `registry(&cfg_with_inject_scope())` (all flags off), `l4.inject` with `inject_params("8.8.8.8", 443)` and `parts.host(Frontend::Cli)`: the error satisfies `guard_refused(&err)` (contains `out of L4 scope`) and `agent_gate_refused(&err)` is `false`.
  - `cli_may_set_l4_agent_gates`: `l4.agent.set {capability: "inject", allowed: true}` as `Frontend::Cli` returns `Ok`; `l4.agent.status` (as `Operator`) then has `gate(&status, "inject") == Some(true)`.
  - Existing, unchanged and green: `inject_agent_gate_flag_then_operator_bypass` (Mcp refused with `capability is disabled`; Operator reaches the guard), `agent_toggle_is_operator_only_and_governs_the_gate` (Mcp `l4.agent.set` refused with `the agent cannot change its own L4 gates`).
  - Mutation proof. M1 red: `inject_agent_gate_flag_then_operator_bypass`, `agent_toggle_is_operator_only_and_governs_the_gate`. M2 red: the two new Cli tests and the Operator arms of the existing two.
- **Done when:** `cargo test -p aitm-proto-l4` green and the full gate passes. Commit: `refactor(l4): route the agent flag gate and l4.agent.set through the shared trust predicate (Task 3)`.

### Task 4: `aitm-proto-l4` seam gates (`L4SeamGuard`, `L4StepHandler`)

- **Satisfies:** AC8, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-proto-l4/src/language.rs` (modify)
- **Change:** these two sites are **not in the original brief**: they are the same deny-list shape, on `CallerTrust`. `L4SeamGuard::permit` (~259) passes `!ctx.caller().is_trusted_control()` to `agent_gate_check` instead of `ctx.caller() == CallerTrust::Agent`. `L4StepHandler::run` (~654) passes `!inputs.caller.is_trusted_control()` instead of `inputs.caller == CallerTrust::Agent`. `agent_gate_check(is_agent: bool, gates, verb, gate)` keeps its signature (the parameter may be renamed, e.g. to `gated`); its body and message are untouched. Remove `CallerTrust` from `use aitm_core::{CallerTrust, Value}` if no non-doc use remains (the doc links use the full path).
- **Test:** no new test; the existing seam tests characterize both sites and must stay green: `ac4_sensitive_verb_refused_when_agent_gate_closed` (Agent refused), `ac4_operator_engine_bypasses_the_agent_gate` (Operator passes), `per_call_trust_decides_on_one_rhai_registration` (the Rhai face, `permit`), `per_call_trust_decides_on_the_native_l4_step_face` (the `l4:` step, `run`), all in `crates/aitm-proto-l4/tests/language.rs`. Cli reaches this layer as `CallerTrust::Operator` (pinned by Task 1 and `aitm-poc/tests/protocol_step.rs`, which seeds `Mcp` => agent, `Cli` and `Operator` => operator).
  - Mutation proof. M1 red: `ac4_sensitive_verb_refused_when_agent_gate_closed`, `per_call_trust_decides_on_one_rhai_registration`, `per_call_trust_decides_on_the_native_l4_step_face`. M2 red: `ac4_operator_engine_bypasses_the_agent_gate`.
- **Done when:** `cargo test -p aitm-proto-l4` green and the full gate passes. Commit: `refactor(l4): route the L4 seam agent gate through the shared trust predicate (Task 4)`.

### Task 5: `aitm-findings` gate (`findings.remove`)

- **Satisfies:** AC9, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-findings/src/commands.rs` (modify), `crates/aitm-findings/tests/findings.rs` (modify)
- **Change:** `FindingsRemove::invoke` (~525): condition becomes `!host.caller_is_trusted_control()`; text `findings.remove is operator/CLI-only` untouched. Drop `Frontend` from the import (the `origin: host.frontend()` at ~471 needs no type name).
- **Test:** (written first; passes on old code) `findings_remove_refuses_the_agent_and_admits_operator_and_cli` in `findings.rs`, using the existing `findings_reg`, `cfg_with_findings`, `unique_dir`, `call_as`, `record_id`: record two findings as `Operator` (ids `a` and `b`);
  - `Frontend::Mcp` removes `a`: `Err` whose `to_string()` equals `findings.remove is operator/CLI-only`; `dir/<a>.yaml` still exists.
  - `Frontend::Cli` removes `a`: `Ok(Value::Object(BTreeMap::new()))`; `dir/<a>.yaml` is gone.
  - `Frontend::Operator` removes `b`: `Ok(Value::Object(BTreeMap::new()))`; `dir/<b>.yaml` is gone.
  - Existing, unchanged and green: `findings_record_is_policy_gated`.
  - Mutation proof. M1 red: `findings_record_is_policy_gated`, the new test (Mcp arm). M2 red: the new test (Cli and Operator arms) and the Operator arm of `findings_record_is_policy_gated`.
- **Done when:** `cargo test -p aitm-findings` green and the full gate passes. Commit: `refactor(findings): route findings.remove through the shared trust predicate (Task 5)`.

### Task 6: `aitm-poc` gate (`poc.run`, both registrations)

- **Satisfies:** AC10, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-poc/src/runner.rs` (modify), `crates/aitm-poc/tests/script_command.rs` (modify)
- **Change:** `run_poc_command` (~1106): condition becomes `!host.caller_is_trusted_control() && !host.config().map(|c| c.poc.allow_agent_run).unwrap_or(false)` (the second operand is today's expression, moved untouched); the `bail!` text is untouched. This one function serves `PocRunCommand` and `ScriptedPocRunCommand`. Drop `Frontend` from the import at ~36. Refresh the comment at ~1103-1105.
- **Test:** (written first; passes on old code) in `script_command.rs`, generalize the helper to `fn invoke_poc_run_as(registry: &Registry, path: &Path, frontend: Frontend) -> anyhow::Result<Value>` and keep `invoke_poc_run(registry, path)` delegating with `Frontend::Cli`, so the existing tests are untouched. Add `scripted_poc_run_is_gated_for_the_agent_only` (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`), registry built with `aitm_poc::runner::register_with_executor(&mut registry, FixedExecutor::returning(ScriptVerdict::Pass))`, no config attached (so the flag is off):
  - `Frontend::Mcp`: `Err` whose `to_string()` starts with `poc.run refused: running a PoC from an agent frontend is disabled.`; the executor's `seen` length is `0`.
  - `Frontend::Operator`: `Ok` object with `"passed" => Value::Bool(true)`; executor `seen` length `1` (use a fresh executor and registry per role).
  - `Frontend::Cli`: same as Operator.
  - Existing, unchanged and green: `dvwa_fixes.rs::t3_agent_is_gated_by_default`, `t3_agent_allowed_when_flag_set`, `t3_operator_and_cli_never_gated` (plain `PocRunCommand`).
  - Mutation proof. M1 red: `t3_agent_is_gated_by_default`, the new test (Mcp arm). M2 red: `t3_operator_and_cli_never_gated`, the new test (Operator and Cli arms).
- **Done when:** `cargo test -p aitm-poc` green and the full gate passes. Commit: `refactor(poc): route the poc.run agent gate through the shared trust predicate (Task 6)`.

### Task 7: `aitm-plugin-rhai` gate (`check_agent_gate`)

- **Satisfies:** AC11, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-plugin-rhai/src/commands.rs` (modify)
- **Change:** `check_agent_gate(host: &CommandHost, allow_agent_authoring: bool) -> anyhow::Result<()>` (~268): condition becomes `!host.caller_is_trusted_control() && !allow_agent_authoring`; message untouched. **Nothing else in the file changes.** `confine_validate` (`== Frontend::Cli` => unconfined, else confined) is an allow-list of only `Cli` and stays as is; the `Frontend` and `CallerTrust` imports stay (both still used). Record in the report that `confine_validate` was inspected and is fail-closed.
- **Test:** no new test; the four existing tests already assert agent-refused plus Operator-pass plus Cli-pass and must stay green, all in `crates/aitm-plugin-rhai/tests/commands.rs`: `agent_authoring_is_refused_when_the_flag_is_off` (error contains `rhai.allow_agent_authoring` on `script.save`, `reload`, `enable`, `disable`), `agent_authoring_passes_the_gate_when_the_flag_is_on`, `cli_authoring_is_allowed_regardless_of_the_flag`, `operator_authoring_is_allowed_regardless_of_the_flag`.
  - Mutation proof. M1 red: `agent_authoring_is_refused_when_the_flag_is_off`. M2 red: `cli_authoring_is_allowed_regardless_of_the_flag`, `operator_authoring_is_allowed_regardless_of_the_flag`.
- **Done when:** `cargo test -p aitm-plugin-rhai` green and the full gate passes (judge `rhai_e2e` per Verification). Commit: `refactor(rhai): route the authoring gate through the shared trust predicate (Task 7)`.

### Task 8: `aitm` sysex activation gate

- **Satisfies:** AC12, AC15, AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm/src/macos_capture/activation_gate.rs` (modify)
- **Change:** `check_activation_caller(origin: Frontend, cfg: &SysexActivationConfig) -> Result<(), ActivationRefused>` becomes: `Ok(())` iff `origin.is_trusted_control() || cfg.allow_agent_sysex_install`, else `Err(ActivationRefused)`. Replace the doc comment's `#[non_exhaustive]`/wildcard explanation with a pointer to the shared predicate. The `Frontend` import stays (parameter type). `ActivationRefused`'s `Display` text is untouched.
- **Test:** (written first in this file's `mod tests`; passes on old code) `activation_matrix_covers_every_variant_and_flag`, six cells with default `SysexActivationConfig` as `off` and `allow_agent_sysex_install: true` as `on`:
  - `(Cli, off)` `Ok(())`; `(Cli, on)` `Ok(())`; `(Operator, off)` `Ok(())`; `(Operator, on)` `Ok(())`; `(Mcp, off)` `Err(ActivationRefused)`; `(Mcp, on)` `Ok(())`.
  - Existing, unchanged and green: unit tests `agent_refused_unless_opted_in`, `humans_always_allowed`, `default_is_deny_by_default`, `refusal_message_names_the_setting`; integration `crates/aitm/tests/macos_capture_gate.rs`.
  - Mutation proof. M1 red: `agent_refused_unless_opted_in` and the `(Mcp, off)` cell. M2 red: `humans_always_allowed` and the Cli/Operator cells.
- **Done when:** `cargo test -p aitm activation_gate` and `cargo test -p aitm --test macos_capture_gate` green and the full gate passes. Commit: `refactor(aitm): fold the sysex activation gate into the shared trust predicate (Task 8)`.

### Task 9: `aitm-mcp` replaces its private helper

- **Satisfies:** AC13, AC15, AC16 (mcp part), AC17
- **Depends on:** Task 1
- **Files:** `crates/aitm-mcp/src/server.rs` (modify)
- **Change:** delete `fn is_trusted_control(role: Frontend) -> bool` (~744, with its doc) and its unit test `is_trusted_control_allows_only_cli_and_operator` (~2217; its pin now lives in Task 1's tests). Replace the three call sites with `conn.role.is_trusted_control()`: `policy_decision` (~1569), `handle_approve` (~1705), `read_refusal` (~1733). Update every comment or doc that names the old private helper (~1359, 1385, 1564, 1730, 1954, and the removed test's banner at ~2212) to refer to `Frontend::is_trusted_control`. **Leave `conn.role == Frontend::Operator` (~1420, the D4 confirm handshake) and `role_str` (~730) untouched.** `Frontend` stays imported.
- **Test:** no new test; the existing integration tests characterize all three sites and must stay green, in `crates/aitm-mcp/tests/mcp.rs`: `agent_cannot_approve_own_request` (Mcp gets `agent cannot approve its own requests`; Operator and Cli get `no parked request \`nope\``), `agent_cannot_set_policy`, `subscribe_under_paused_refuses_only_the_agent` (Operator and Cli get a `sub_id`), `policy_matrix_for_agent`, `operator_bypasses_policy`.
  - Mutation proof. M1 red: `agent_cannot_approve_own_request`, `agent_cannot_set_policy`, `subscribe_under_paused_refuses_only_the_agent`, `policy_matrix_for_agent`. M2 red: `operator_bypasses_policy`, `subscribe_under_paused_refuses_only_the_agent` (Operator/Cli arm), `agent_cannot_approve_own_request` (non-agent arm).
- **Done when:** `cargo test -p aitm-mcp` green, `grep -n "fn is_trusted_control" crates/aitm-mcp` is empty, and the full gate passes. Commit: `refactor(mcp): use the shared Frontend::is_trusted_control and drop the private helper (Task 9)`.

### Task 10: source-scan drift guard and the closing doc sentence

- **Satisfies:** AC14, AC16, AC17
- **Depends on:** Tasks 2-9 (the scan fails until every deny-list site is migrated)
- **Files:** `crates/aitm-core/tests/trust_gate_scan.rs` (create), `crates/aitm-core/src/ctx.rs` (modify: add one sentence to the `Frontend` docs naming the scan test)
- **Change:** in `trust_gate_scan.rs` (no `Cargo.toml` change; `regex` is already a dependency of `aitm-core` if wanted):
  - `fn deny_list_hits(src: &str) -> Vec<(usize, String)>`: pure; returns `(1-based line, snippet)` for each deny-list comparison of the untrusted role. Blank `//`-to-end-of-line comments (keeping newlines so line numbers hold) before matching; matching tolerates whitespace and newlines. A hit is: `==` or `!=` followed by `Frontend::Mcp` or `CallerTrust::Agent` (any path prefix); `Frontend::Mcp` or `CallerTrust::Agent` followed by `==` or `!=`; or either name inside a `matches!(...)` (balanced parentheses).
  - `const ALLOWED: &[(&str, &str)]` (path suffix, reason): **empty**.
  - `fn rust_sources(crates_dir: &Path) -> Vec<PathBuf>`: every `*.rs` under `<crates_dir>/*/src/` recursively; `crates_dir` is `Path::new(env!("CARGO_MANIFEST_DIR")).parent()`.
  - Not scanned: `tests/` dirs and `apps/`.
- **Test:** (red first: the scanner does not exist, then the self-tests drive it)
  - `scanner_flags_every_deny_list_shape`: each of these inputs yields exactly **one** hit, and the first has line `1`:
    - `if host.frontend() == Frontend::Mcp && !flag {`
    - `if aitm_core::Frontend::Mcp != role {`
    - `if inputs.caller == CallerTrust::Agent {`
    - `if ctx.caller()\n    == CallerTrust::Agent\n{` (multi-line)
    - `let gated = matches!(host.frontend(), Frontend::Mcp);`
    - `matches!(\n    host.frontend(),\n    Frontend::Mcp | Frontend::Cli\n)` (multi-line)
    - `let is_agent = frontend == Frontend::Mcp;`
  - `scanner_ignores_legitimate_shapes`: each yields **zero** hits:
    - `Frontend::Mcp => CallerTrust::Agent,`
    - `// if host.frontend() == Frontend::Mcp {`
    - `/// the old shape was \`host.frontend() == Frontend::Mcp\``
    - `assert!(!host.caller_is_trusted_control());`
    - `if host.frontend() != Frontend::Cli && !flag {`
    - `if conn.role == Frontend::Operator {`
    - `_ => CallerTrust::Agent,`
    - `CommandHost::new(&s, &c, &g, None).with_frontend(Frontend::Mcp)`
  - `no_deny_list_gate_in_any_crate_src`: scan all sources; the hits not covered by `ALLOWED` must be empty (literal expected `[]`); the failure message lists `path:line: snippet` and says to use `host.caller_is_trusted_control()` / `Frontend::is_trusted_control()`, because a comparison against the agent role fails open when a variant is added.
  - `scan_is_not_vacuous`: at least `100` files scanned, and the list contains paths ending `aitm-mcp/src/server.rs` and `aitm-core/src/ctx.rs`.
  - Red demonstration (recorded in the report, not committed): temporarily add `fn probe(h: &CommandHost) -> bool { h.frontend() == Frontend::Mcp }` to any crate's `src`; `no_deny_list_gate_in_any_crate_src` fails naming that file and line; revert.
- **Done when:** `cargo test -p aitm-core --test trust_gate_scan` green with the empty allow-list, and the full gate passes. Commit: `test(core): add the trust-gate source scan so deny-list gates cannot return (Task 10)`.

---

## Verification (stage 5 input; no source change)

**Routing proof, whole branch (AC18).** The Tester runs each mutation once on the integrated branch, quotes the red output, and reverts with `git checkout crates/aitm-core/src/ctx.rs`:

- **M1** (agent trusted: `CallerTrust::is_trusted_control` returns `true` for `Agent`). Must go red: `aitm-core` Task 1 tests; `scope_rate.rs::{scope_add_gated_from_agent_frontend, operator_may_widen_scope}`; `agent_gates.rs` (both tests); `operator_surfaces.rs::{inject_agent_gate_flag_then_operator_bypass, agent_toggle_is_operator_only_and_governs_the_gate}`; `language.rs::{ac4_sensitive_verb_refused_when_agent_gate_closed, per_call_trust_decides_on_one_rhai_registration, per_call_trust_decides_on_the_native_l4_step_face}`; `findings.rs::{findings_record_is_policy_gated, findings_remove_refuses_the_agent_and_admits_operator_and_cli}`; `dvwa_fixes.rs::t3_agent_is_gated_by_default`; `script_command.rs::scripted_poc_run_is_gated_for_the_agent_only`; `aitm-plugin-rhai` `commands.rs::agent_authoring_is_refused_when_the_flag_is_off`; `activation_gate.rs::agent_refused_unless_opted_in`, `macos_capture_gate.rs` (agent refused); `mcp.rs::{agent_cannot_approve_own_request, agent_cannot_set_policy, subscribe_under_paused_refuses_only_the_agent, policy_matrix_for_agent}`.
- **M2** (nobody trusted: returns `false` for `Operator`). Must go red: the Operator/Cli-pass tests in the same files (`operator_may_widen_scope`, `agent_gates.rs`, the new Cli tests in `operator_surfaces.rs`, `ac4_operator_engine_bypasses_the_agent_gate`, the `findings` new test, `t3_operator_and_cli_never_gated`, the scripted poc test, `cli_authoring_is_allowed_regardless_of_the_flag`, `operator_authoring_is_allowed_regardless_of_the_flag`, `humans_always_allowed`, `operator_bypasses_policy`).
- Any gate whose agent-refused test stays green under M1 is **not routed through the helper**: Critical.

**Diff hygiene (AC15, AC17).** Reviewers check against `312bd31`: no change to the four Cli-only crates' `src`; `aitm-plugin-rhai/src/commands.rs` differs only in `check_agent_gate`; `server.rs:1420` untouched; outside comments and `#[cfg(test)]` modules, no changed line contains a string literal; `grep -rn "fn is_trusted_control(" crates` matches only `aitm-core/src/ctx.rs` (the two methods), and no private copy elsewhere.

**Full gate** (Terminal panel, because of port-binding tests), on the integrated branch before the whole-branch panel: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Redirect `cargo test` to a log and gate on its exit status, not on a grep (project memory).

**Known flake: `rhai_e2e::script_cannot_escape_or_exceed_scope`** (`crates/aitm/tests/rhai_e2e.rs`). It is non-deterministic: it fails under full `cargo test` and in isolation. Judge it by diff scope, not by a rerun. This change's only Rhai-crate edit is the one-line condition in `check_agent_gate` (Task 7), which guards `script.save/reload/enable/disable`; that test drives hook dispatch, the sandbox's denial of `open_file`, and an out-of-scope `http.send`, and calls no authoring command. So a failure there is the known flake: the Tester quotes the failing output verbatim, notes the diff does not touch hook dispatch, the sandbox or `http.send`, and does **not** count it against the gate. It does count if the failure text mentions `rhai.allow_agent_authoring`, `check_agent_gate`, or authoring, or if any test in `aitm-plugin-rhai` is red. Do not "fix" the flake in this change.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
