# Route every agent gate through one trust predicate design

**Status:** Approved — orchestrator, 2026-10-30 (autonomous mode: Matt's standing instruction to self-approve specs and plans; both open questions keep their stated default and are reported to Matt)
**Research inputs:** none new. Grounded in the source tree at `312bd31` (branch `fix/frontend-gates-callertrust`, stacked on open PR #101: `437ec31` + `312bd31`, "allow-list trusted-control roles for the agent gates"). Line numbers below are as of that commit; re-find by symbol.

## Intent

`aitm_core::Frontend` is `#[non_exhaustive]` (`Cli`, `Mcp`, `Operator`). PR #101 fixed `aitm-mcp`'s server gates, which deny-listed the agent role (`== Frontend::Mcp`) and so would have **failed open** for any variant added later. It did so with a *private* allow-list helper in `aitm-mcp`. Eight more command-level gates, two seam gates in `aitm-proto-l4`, and the macOS sysex gate still carry the same shape or their own private copy of "who is trusted". This change deletes every private definition and routes **every trust-based gate through one definition in `aitm-core`**, built on the wildcard-free `CallerTrust::from(Frontend)`, so that adding a `Frontend` variant is a compile error in `aitm-core` until someone decides its trust class, and every gate in the workspace then follows that one decision. Behaviour for today's three variants does not change by a byte.

## Goals

- One predicate decides "is this caller a present human control surface (bypasses the agent gates) or an agent (gated)". It is an **allow-list** (Operator-trust => trusted, Agent-trust => not) implemented as a wildcard-free `match` on `CallerTrust`, in `aitm-core`.
- Three entry points, all delegating to it, none a second definition: on `CallerTrust`, on `Frontend` (for `aitm-mcp`, whose `ConnCtx.role` is a `Frontend`), and on `CommandHost` (for command gates).
- Each of the ten migrated sites (list below), plus the sysex activation gate and `aitm-mcp`'s three uses, asks that predicate; no `Frontend::Mcp` or `CallerTrust::Agent` equality/`matches!` remains in any `crates/*/src/**/*.rs`.
- Adding a `Frontend` variant: `cargo build -p aitm-core` fails until `CallerTrust::from` and `audit::origin_label` classify it; adding a `CallerTrust` variant fails until `CallerTrust::is_trusted_control` does. Nothing downstream needs editing for the gates to follow.
- Every gate site has an executable assertion that an agent (`Frontend::Mcp`) is gated and that `Frontend::Operator` and `Frontend::Cli` pass; a unit test in `aitm-core` pins the predicate for all three variants.
- A narrow source-scan test keeps the deny-list shape from coming back (recommended; Architect's call, see Design).

## Non-goals

- **No behaviour change for `Cli`, `Mcp`, `Operator`.** Same refusals, same error text (byte for byte), same Operator and Cli pass-through. No new variant is added.
- **The "Cli-only" gates are not rerouted.** `aitm-plugin-sessionio` (`lib.rs:138`), `aitm-ca` (`commands.rs:~897`), `aitm-plugin-passthrough` (`lib.rs:107`), `aitm-plugin-maprules` (`lib.rs:442`) are `frontend != Frontend::Cli && !flag`. Operator is **deliberately also gated** there. They are already fail-closed (an allow-list of exactly one). Routing them through the trust predicate would make Operator bypass them, a regression.
- No change to `AgentPolicy`, `Sensitivity`, the D4 confirm handshake, `defers_to_command_gate`, any config flag, or any refusal wording.
- No removal of `#[non_exhaustive]` from `Frontend` (rejected, see Design).
- No new `Frontend` or `CallerTrust` variant, no new config knob, no new dependency.
- No change to `apps/` (mac, web), `agent/`, `scripts/`: they only display the `initialize` role echo and never decide trust.
- No migration of the six `CallerTrust::from(host.frontend())` call sites that *carry* trust into a seam (`aitm-poc` `runner.rs:412`, `aitm-plugin-rhai` `command.rs:92`, `poc_step.rs:171`, `commands.rs:561/587/609`). They are not gates and already go through the single classifier.

## Anti-goals

- **Operator newly bypassing a Cli-only gate**, or Operator newly gated at a gate it passes today. Either is a failure even if every test is green.
- **A second definition of "trusted"** anywhere (a new local helper, a copy of the match in another crate, a `_ =>` arm that classifies). Delegation to the one predicate is fine; a second `match` is not.
- **A deny-list on the agent role in the new helper** (`== CallerTrust::Agent`, `is_agent()` used as the gate input). It fails open if `CallerTrust` ever grows a variant.
- **A wildcard arm in the three classifiers** (`CallerTrust::from`, `CallerTrust::is_trusted_control`, `audit::origin_label`). The wildcard is what removes the compile-time forcing function.
- **A changed error string, a changed gate order, or a reordered condition** that alters which refusal an agent sees first.
- A drift-guard test so broad that every legitimate `== Frontend::Cli` trips it, teaching people to add allow-list entries reflexively.

## Constraints

- Rust workspace gate unchanged: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. `unsafe_code = "forbid"` stays. The workspace lints turn an unused import into an error, so each migrated file must drop `Frontend` from its `use` list when it stops using it.
- `aitm-core` is the bottom of the crate graph; the new code lives there and adds **no dependency**. (`aitm-core` already depends on `regex`, usable by its integration tests, if the scanner wants it; no `Cargo.toml` edit is needed.)
- `Frontend` is `#[non_exhaustive]`: a wildcard-free `match` over it compiles only **inside `aitm-core`**. Downstream crates (and `aitm-core`'s own `tests/` dir, which is a separate crate) must keep a wildcard arm. So exhaustive-over-`Frontend` code and its test must live in `aitm-core/src`.
- `CallerTrust` is **not** `#[non_exhaustive]`: a downstream wildcard-free `match` on it is legal and will break if it grows (for example `aitm-plugin-rhai/src/plugin.rs::trust_code`). That is a feature.
- Per-call cost is one inlined `match` on a two-variant enum: negligible against any command invocation.
- Port-binding tests in the full `cargo test` need the Terminal panel (sandbox), per `CLAUDE.md` and project memory.
- The known flake `rhai_e2e::script_cannot_escape_or_exceed_scope` (see plan, Verification) must be judged by diff scope, not by rerunning.

## Design

### The one definition (all in `crates/aitm-core/src/ctx.rs`)

Signatures only; bodies are the builder's to write within the rules stated:

- `impl CallerTrust { pub fn is_trusted_control(self) -> bool }` — the **only** definition. A `match` with exactly the arms `Operator => true` and `Agent => false`, **no wildcard**.
- `impl Frontend { pub fn is_trusted_control(self) -> bool }` — one line: `CallerTrust::from(self).is_trusted_control()`. This is the entry point for `aitm-mcp` (`conn.role`). It delegates; it is not a second `match`.
- `impl CommandHost<'_> { pub fn caller_is_trusted_control(&self) -> bool }` — one line over the stored `Frontend`. A host that was never given a frontend defaults to `Frontend::Mcp` (`CommandHost::new`, unchanged), so it is untrusted: the gated posture is preserved.

**Naming (Architect's call):** `is_trusted_control` is kept from PR #101 so the term in `server.rs` comments and tests stays meaningful. A gate then reads `if !host.caller_is_trusted_control() && !flag { bail }`.

**One entry point per level, not three definitions (Architect's call):** `Frontend::is_trusted_control` exists because `aitm-mcp` has `Frontend` values from `ConnCtx.role` at three sites and no `CommandHost`; `CallerTrust::from(role).is_trusted_control()` at each is noisier. No `CommandHost::caller_trust()` is added (nothing in this change needs the enum, and the six existing seam-feeding sites already work).

**Reason it sits on `CallerTrust` and not `Frontend`:** `CallerTrust::from` is already the wildcard-free classifier of every `Frontend`. Putting the predicate behind it means there are exactly three small exhaustive matches in the whole workspace that decide trust (`CallerTrust::from`, `CallerTrust::is_trusted_control`) or naming (`audit::origin_label`), all in one crate.

### Alternatives considered and rejected

| Alternative | Why not |
|---|---|
| Keep a per-crate private helper (status quo of #101) | N copies drift; a ninth gate re-invents the deny-list. |
| `CallerTrust::is_agent()` / `== CallerTrust::Agent` as the gate input | Deny-list; fails open if `CallerTrust` grows. (This is the shape `aitm-proto-l4/src/language.rs` has today, see below.) |
| Drop `#[non_exhaustive]` from `Frontend` so downstream matches are exhaustive | Does not catch `==`/`!=`, the actual bug class (the compiler never exhaustiveness-checks a comparison); turns the fully-covered `_ => "mcp"` arm of `aitm-findings` `origin_str` into an `unreachable_patterns` error under `-D warnings`; widens the API change for no gate benefit. |
| A `host.require_trusted_or(flag, msg) -> Result` helper that owns the refusal | Folds ten distinct error strings into a helper; the byte-for-byte rule becomes harder to review; no safety gain over a one-line condition. |

### Gate shape after migration

A flag-gated site keeps its conjunction exactly: trusted callers pass regardless of the flag; an untrusted caller passes only when the flag is on. A self-gate (no flag) refuses any untrusted caller. In words: the old `host.frontend() == Frontend::Mcp && !flag` becomes `!host.caller_is_trusted_control() && !flag`; the old unconditional `host.frontend() == Frontend::Mcp` becomes `!host.caller_is_trusted_control()`. Seam gates (`ctx.caller()` / `inputs.caller`, already a `CallerTrust`) become `!caller.is_trusted_control()`. `aitm-mcp` replaces `is_trusted_control(conn.role)` with `conn.role.is_trusted_control()`.

### Site inventory and disposition

Found by `grep` for `Frontend::`/`CallerTrust::` comparisons, `matches!`, `match` on role/origin, and `.frontend()` across `crates/`, `apps/`, `agent/`, `scripts/` (there is no `xtask`). `aitm-tui` and `aitm-cli` only construct or display roles.

**Deny-list shape, migrate:**

| # | Site (as of `312bd31`) | Gate | Disposition |
|---|---|---|---|
| 1 | `aitm-proto-l4/src/commands/agent.rs:68` | `L4AgentGate` wrapper: agent flag-gate on l4 wire verbs (`l4.allow_agent_*`) | migrate (conditional, flag) |
| 2 | `aitm-proto-l4/src/commands/agent.rs:172` | `l4.agent.set` self-gate | migrate (unconditional) |
| 3 | `aitm-plugins/src/scope.rs:89` | `scope.add` / `scope.allow_agent_widen` | migrate (flag) |
| 4 | `aitm-plugins/src/agent.rs:184` | `agent.set` self-gate | migrate (unconditional) |
| 5 | `aitm-plugins/src/agent.rs:331` | `agent.approve` command fallback | migrate (unconditional) |
| 6 | `aitm-findings/src/commands.rs:525` | `findings.remove` | migrate (unconditional) |
| 7 | `aitm-poc/src/runner.rs:1106` | `poc.run` / `poc.allow_agent_run` (shared by both registrations) | migrate (flag) |
| 8 | `aitm-plugin-rhai/src/commands.rs:268` | `check_agent_gate` / `rhai.allow_agent_authoring` | migrate (flag) |
| 9 | `aitm-proto-l4/src/language.rs:259` | `L4SeamGuard::permit`: `ctx.caller() == CallerTrust::Agent` | **not in the brief; found by the sweep.** Same deny-list shape, on `CallerTrust`. migrate |
| 10 | `aitm-proto-l4/src/language.rs:654` | `L4StepHandler::run`: `inputs.caller == CallerTrust::Agent` | **not in the brief; found by the sweep.** migrate |
| 11 | `aitm-mcp/src/server.rs:744` (`fn is_trusted_control`) and its uses at 1569 (`policy_decision`), 1705 (`handle_approve`), 1733 (`read_refusal`) | agent policy gate, `agent.approve` role check, `Paused` read gate | delete the private fn; call `Frontend::is_trusted_control` |
| 12 | `aitm/src/macos_capture/activation_gate.rs:63-67` (`check_activation_caller`) | sysex activation: own `Cli \| Operator` arm plus `_` wildcard | **fold** into the shared predicate (recommended; behaviour-identical, proved below) |

**Already fail-closed, leave byte-for-byte unchanged:**

| Site | Shape | Why it stays |
|---|---|---|
| `aitm-plugin-sessionio/src/lib.rs:138` | `!= Cli && !allow_agent_file_io` | Allow-list of one; Operator deliberately gated |
| `aitm-ca/src/commands.rs:~897` | `!= Cli && !dry_run && !allow_agent_install` | same |
| `aitm-plugin-passthrough/src/lib.rs:107` | `!= Cli && !allow_agent_passthrough` | same |
| `aitm-plugin-maprules/src/lib.rs:442` | `!= Cli && !allow_agent_authoring` | same |
| `aitm-plugin-rhai/src/commands.rs:285` (`confine_validate`) | `== Cli` => unconfined; everything else confined | **Confirmed fail-closed:** an allow-list of only `Cli`; a new variant (and today's `Operator`) is confined |
| `aitm-mcp/src/server.rs:1420` | `conn.role == Frontend::Operator` => offer the D4 confirm handshake | Allow-list of one. A variant that is not `Operator` gets no handshake and falls through to the command, but every command that offers a `confirm_prompt` is either an l4 wire verb (after this change, wrapped by the fail-closed `L4AgentGate`) or a `ca.*` command (Cli-only gate), so the property holds transitively. It is a confirmation step, not a trust gate |

**Labels and constructors, not gates, leave unchanged:**

| Site | Note |
|---|---|
| `aitm-core/src/audit.rs:107` `origin_label` | Exhaustive, wildcard-free. Stays; it is one of the three classification points |
| `aitm-mcp/src/server.rs:730` `role_str` | `Operator => "operator", _ => "agent"`: wire echo, least privilege |
| `aitm-ca/src/commands.rs:182` `frontend_label` | `Cli => "cli", _ => "mcp"`: audit label, fails toward `"mcp"`. Observation: `Operator` is logged as `"mcp"` here (see Open questions) |
| `aitm-findings/src/record.rs:129` `origin_str`, `:139` `origin_from` | Unknown future variant writes `"mcp"`; unknown stored origin string reads back as `Frontend::Mcp`. **Confirmed fine:** least privilege, and a record of unknown origin is treated as agent-originated |
| `aitm/src/config_file.rs:537`, `aitm-mcp/src/transport.rs:318`, `aitm/src/web/bridge.rs:221`, `aitm-mcp/src/http.rs:258`, `aitm-cli/src/dispatch.rs:143`, `aitm/src/tui.rs:257/430` | Construct a role from config or a token (unknown token => refused) or declare the producer. Not gates |
| `aitm-core/src/ctx.rs` `CommandHost::new` default `Frontend::Mcp` | Gated posture; keep |
| `aitm-plugin/src/language.rs:292`, `aitm-plugin-rhai` `command.rs:151`, `loader.rs:301`, `plugin.rs:135` | Default seed is `CallerTrust::Agent` (least privilege); constructions, not comparisons |
| `aitm-plugin-rhai/src/plugin.rs:123` `trust_code` | Wildcard-free over `CallerTrust`: forces a decision if `CallerTrust` grows |
| `aitm-tui/src/ui/flows.rs:315,451` | `r.origin` is a flow origin, unrelated type |
| `apps/mac`, `apps/web`, `agent/`, `scripts/` | Display the `initialize` role string only |

### Folding the sysex gate (Architect's call)

`check_activation_caller(origin, cfg)` becomes: allowed iff `origin.is_trusted_control() || cfg.allow_agent_sysex_install`, else `Err(ActivationRefused)`. Behaviour-identical on the full variant-by-flag matrix: `(Cli, off|on)`, `(Operator, off|on)` => `Ok`; `(Mcp, off)` => `Err(ActivationRefused)`; `(Mcp, on)` => `Ok`. A unit test pins all six cells. Its doc comment drops the `#[non_exhaustive]`/wildcard explanation and points at the shared predicate. This removes the only other independent definition of "trusted".

### How the fail-closed property is locked

A downstream test cannot construct a fourth `Frontend` value, so "a future variant is gated at every gate" cannot be asserted end to end. It is locked by construction plus four mechanisms:

1. **Compile-time forcing (the real lock).** `CallerTrust::from`, `CallerTrust::is_trusted_control` and `audit::origin_label` are wildcard-free. Adding a `Frontend` variant breaks `aitm-core` until the author states its trust class and its label. This is stronger than #101's silent fail-closed wildcard: a new variant cannot be left unclassified.
2. **One consumer API.** After migration no gate names a `Frontend` variant, so there is no per-gate literal to go stale. Once classified, the variant flows through all twelve sites.
3. **Unit tests in `aitm-core/src`.** A test module with an exhaustive, wildcard-free `match` over `Frontend` and over `CallerTrust` (legal only in-crate) pins the expected trust of each variant and the equality `Frontend::is_trusted_control == CallerTrust::from(..).is_trusted_control`. A fourth variant breaks this test's build too, so the pin cannot be skipped.
4. **Source-scan drift guard** (below), so the deny-list comparison cannot be reintroduced downstream where the compiler cannot see it.
5. **The documented default.** The `Frontend` docs tell the author to classify a new variant as `Agent` unless a present human is behind every connection of that kind. Classifying it `Operator` is one explicit, reviewable line in `CallerTrust::from`.

### Documentation updates

- `Frontend` "Adding a variant": classify in `CallerTrust::from` and `audit::origin_label` (both wildcard-free; `aitm-core` will not build until you do); every trust gate derives from `CallerTrust::is_trusted_control` through `Frontend::is_trusted_control` / `CommandHost::caller_is_trusted_control`, and needs no per-crate edit; if `CallerTrust` itself grows, `is_trusted_control` is the single place to classify it; never compare a `Frontend` with `==`/`!=` to decide trust (a scan test rejects it); label-only sites (`role_str`, `aitm-ca` `frontend_label`, `aitm-findings` `origin_str`) map an unclassified variant to the agent label with `_ =>` and are not gates; the Cli-only gates (`!= Frontend::Cli`) gate any non-Cli variant automatically (fail closed) and need touching only if the new variant should be treated like `Cli`. Default a new variant to `Agent`.
- `CallerTrust::from` doc: it is the one classification of every `Frontend`; delete the "**iff** `Frontend::Mcp`" phrasing, state the table, restate the default-to-`Agent` rule.
- `CallerTrust` type doc: mention `is_trusted_control` as the one predicate.

### Drift guard: recommend yes (Architect's call)

`crates/aitm-core/tests/trust_gate_scan.rs` scans every `crates/*/src/**/*.rs` (about 228 files) and fails on a deny-list comparison of the untrusted role: `==` or `!=` against `Frontend::Mcp` or `CallerTrust::Agent` (either operand order, any path prefix such as `aitm_core::Frontend::Mcp`), or either name inside a `matches!(...)`. Comments (`//`, `///`, `//!`) are blanked first; matching tolerates newlines so rustfmt line-breaking cannot hide a hit. It does **not** flag `Frontend::Cli`/`Frontend::Operator` comparisons, match arms (`Frontend::Mcp => ...`), constructions, or `!is_trusted_control(Frontend::Mcp)`. It has an `ALLOWED: &[(&str, &str)]` (path suffix, reason) list that is **empty** after this change; an entry is a reviewed exception.

Weighing it:

- **For:** the bug class is invisible to the compiler (a comparison is never exhaustiveness-checked), it shipped in ten places, and PR #101 only fixed one crate. A reviewer catching each by eye is what failed. The precedent exists: `aitm/tests/agent_surface.rs::no_provider_sdk_in_workspace` (manifest scan), `aitm-mcp/tests/widget_lint.rs` (source lint), the catalog drift guards. I did not find a drift-guard entry in `docs/research/MEMORY.md`; these are the precedents I verified in tree. Cost: one ~100-line test file, no dependency, milliseconds to run.
- **Against / brittleness:** it is a tripwire for the shape that actually shipped, not a proof. It is evadable by aliasing (`let agent = Frontend::Mcp; x == agent`, `use ... as`), by comparing a role string, or by casting. A legitimate future `== Frontend::Mcp` (for example a label formatter) trips it and needs a `match` or an `ALLOWED` entry; that friction is the point, but it is friction.
- **Mitigations:** the scanner is a pure function with its own self-tests (positive and negative vectors, so a regex edit cannot silently weaken it); a non-vacuity test asserts at least 100 files were scanned and that `aitm-mcp/src/server.rs` and `aitm-core/src/ctx.rs` are among them (a wrong path cannot pass by scanning nothing); scope is limited to the two untrusted-role names, so the six legitimate Cli-only/Operator comparisons need no allow-list entries.
- **Recommendation: yes**, as the last task so it lands green. Matt can strike that task without affecting the rest.

## Acceptance criteria

Each is observable and testable; "test" names the existing or new test that proves it. The coverage matrix under it gives the file for every gate.

1. **AC1:** `CallerTrust::Operator.is_trusted_control()` is `true` and `CallerTrust::Agent.is_trusted_control()` is `false`; the function body is a `match` with no wildcard arm. Test: new `aitm-core` unit test.
2. **AC2:** `Frontend::Cli.is_trusted_control()` is `true`, `Frontend::Operator.is_trusted_control()` is `true`, `Frontend::Mcp.is_trusted_control()` is `false`, and for each variant the value equals `CallerTrust::from(v).is_trusted_control()`. Test: new `aitm-core` unit test.
3. **AC3:** `CommandHost::caller_is_trusted_control()` is `true` for a host built `with_frontend(Frontend::Cli)` and for `with_frontend(Frontend::Operator)`, `false` for `with_frontend(Frontend::Mcp)`, and `false` for a `CommandHost::new` host never given a frontend. Test: new `aitm-core` unit test.
4. **AC4 (compile-time forcing):** the `aitm-core` unit-test module classifies every `Frontend` variant and every `CallerTrust` variant with a wildcard-free `match`, and `CallerTrust::from`, `CallerTrust::is_trusted_control`, `audit::origin_label` contain no `_` arm. Observable: those bodies contain zero `_ =>`; adding a variant to either enum breaks `cargo test -p aitm-core` at compile time.
5. **AC5 (scope.add):** with `scope.allow_agent_widen` off, `Frontend::Mcp` gets an error whose text contains `scope.allow_agent_widen`; `Frontend::Operator` and `Frontend::Cli` get `Ok(Value::Str("<host>"))` and the host lands in the guard's scope set; with the flag on, `Mcp` is admitted. Test: existing `scope_add_gated_from_agent_frontend`, `operator_may_widen_scope` (unchanged).
6. **AC6 (agent.set / agent.approve commands):** invoked directly, `agent.set` refuses `Mcp` with exactly `agent.set refused: the agent cannot change its own policy; only an operator or the human CLI may set it.` and leaves the policy unchanged; `Operator` and `Cli` succeed and change it. `agent.approve` refuses `Mcp` with exactly `agent.approve refused: the agent cannot approve its own requests; only an operator or the human CLI may approve a parked sensitive command.`; `Operator` and `Cli` reach the fallback and get `agent.approve is resolved by the MCP server against its parked-request table; it cannot be invoked in this context.` Test: new `aitm-plugins/tests/agent_gates.rs`.
7. **AC7 (l4 command gates):** with every `l4.allow_agent_*` flag off, `l4.inject` as `Mcp` is refused by the agent gate (error contains `capability is disabled`), as `Operator` and as `Cli` it passes the agent gate and is refused only by the L4 guard (error contains `out of L4 scope`); `l4.agent.set` as `Mcp` is refused with `l4.agent.set refused: the agent cannot change its own L4 gates; only an operator or the human CLI may set them.`, as `Operator` and `Cli` it succeeds and `l4.agent.status` then reports the toggled gate. Test: existing Mcp/Operator assertions in `operator_surfaces.rs`; new Cli tests there.
8. **AC8 (l4 seam gates):** an `Agent`-trust `l4.*` host fn or `l4:` PoC step with its gate closed is refused; an `Operator`-trust one passes. Cli maps to `Operator` trust (AC2 plus the `protocol_step.rs` caller tests). Test: existing `aitm-proto-l4/tests/language.rs` (`ac4_*`, `per_call_trust_*`), unchanged.
9. **AC9 (findings.remove):** `Mcp` gets exactly `findings.remove is operator/CLI-only` and the finding's YAML survives; `Operator` and `Cli` each return `Value::Object` (empty) and the YAML is gone. Test: existing `findings_record_is_policy_gated` plus a new test in `aitm-findings/tests/findings.rs` adding the Cli case.
10. **AC10 (poc.run):** with `poc.allow_agent_run` off, `Mcp` gets an error that starts `poc.run refused: running a PoC from an agent frontend is disabled.`; `Operator` and `Cli` are never gated, on **both** the plain `PocRunCommand` and the `register_with_executor` registration. Test: existing `dvwa_fixes.rs::t3_*`; new test for the scripted registration in `aitm-poc/tests/script_command.rs`.
11. **AC11 (rhai authoring):** with `rhai.allow_agent_authoring` off, `Mcp` is refused on `script.save/reload/enable/disable` with text containing `rhai.allow_agent_authoring`; `Operator` and `Cli` author freely. Test: existing `aitm-plugin-rhai/tests/commands.rs` (`agent_authoring_is_refused_when_the_flag_is_off`, `cli_authoring_is_allowed_regardless_of_the_flag`, `operator_authoring_is_allowed_regardless_of_the_flag`), unchanged.
12. **AC12 (sysex gate):** `check_activation_caller` returns `Ok` for `(Cli, off)`, `(Cli, on)`, `(Operator, off)`, `(Operator, on)`, `(Mcp, on)` and `Err(ActivationRefused)` for `(Mcp, off)`. Test: new six-cell table test in `activation_gate.rs`; existing `aitm/tests/macos_capture_gate.rs` unchanged.
13. **AC13 (MCP server):** `aitm-mcp/src/server.rs` has no `fn is_trusted_control`; the policy gate, `agent.approve` role check and `Paused` read gate call `Frontend::is_trusted_control`; behaviour is unchanged. Test: existing `agent_cannot_approve_own_request`, `agent_cannot_set_policy`, `subscribe_under_paused_refuses_only_the_agent` and the policy-matrix tests in `aitm-mcp/tests/mcp.rs`, unchanged. The private fn's unit test is removed (its pin moved to AC1/AC2).
14. **AC14 (drift guard):** `cargo test -p aitm-core --test trust_gate_scan` passes on the migrated tree with an empty allow-list; its self-tests flag every positive vector and no negative vector (vectors are in the plan); re-introducing `host.frontend() == Frontend::Mcp` in any `crates/*/src` file makes it fail with the file, line and remediation. Test: new `trust_gate_scan.rs`.
15. **AC15 (untouched sites):** `git diff 312bd31` shows **no change** to `aitm-plugin-sessionio/src/lib.rs`, `aitm-ca/src/commands.rs`, `aitm-plugin-passthrough/src/lib.rs`, `aitm-plugin-maprules/src/lib.rs`; `aitm-plugin-rhai/src/commands.rs` changes only inside `check_agent_gate` (and its import line stays); `aitm-mcp/src/server.rs:1420` (`conn.role == Frontend::Operator`) is unchanged. Their existing tests pass.
16. **AC16 (docs):** the `Frontend` "Adding a variant" note and the `CallerTrust::from` doc match the Design (no mention of an `aitm-mcp` `is_trusted_control`); `grep -rn "is_trusted_control" crates` shows definitions only in `aitm-core/src/ctx.rs` and call sites elsewhere, and no `fn is_trusted_control(` outside `aitm-core`.
17. **AC17 (no semantic drift):** in non-test source, no changed line outside a comment contains a string literal (diff-checked), so every refusal message is byte-identical; each migrated file's only code changes are the gate condition and the import list.
18. **AC18 (routing proof, verification not a committed test):** mutating `CallerTrust::is_trusted_control` to return `true` for `Agent` turns red every agent-refused test named in AC5-AC13; mutating it to return `false` for `Operator` turns red every Operator/Cli-pass test named there. The plan lists the expected-red tests.
19. **AC19 (gate):** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes. `rhai_e2e::script_cannot_escape_or_exceed_scope` is judged per the plan's flake rule, not by a rerun.

### Coverage matrix (every gate site: agent gated, Operator passes, Cli passes)

| Gate | Agent gated | Operator passes | Cli passes | Where |
|---|---|---|---|---|
| `scope.add` | existing | existing | existing | `aitm-plugins/tests/scope_rate.rs` |
| `agent.set` (command) | **new** | **new** | **new** | `aitm-plugins/tests/agent_gates.rs`; server path also in existing `mcp.rs::agent_cannot_set_policy` |
| `agent.approve` (command fallback) | **new** | **new** | **new** | same new file; server path in existing `mcp.rs::agent_cannot_approve_own_request` |
| l4 flag wrapper | existing | existing | **new** | `aitm-proto-l4/tests/operator_surfaces.rs` |
| `l4.agent.set` | existing | existing | **new** | same |
| l4 seam (`language.rs` x2) | existing (Agent) | existing (Operator trust) | via `From` (AC2) and `protocol_step.rs` | `aitm-proto-l4/tests/language.rs` |
| `findings.remove` | existing | existing | **new** | `aitm-findings/tests/findings.rs` |
| `poc.run` | existing | existing | existing | `aitm-poc/tests/dvwa_fixes.rs` (plain); **new** scripted registration in `script_command.rs` |
| rhai authoring | existing | existing | existing | `aitm-plugin-rhai/tests/commands.rs` |
| sysex activation | existing | existing | existing | unit tests + `aitm/tests/macos_capture_gate.rs`; **new** six-cell matrix |
| MCP policy / read gate / approve | existing | existing | existing | `aitm-mcp/tests/mcp.rs` |
| predicate itself | new | new | new | `aitm-core/src/ctx.rs` unit tests |

## Left to the builder

- Wording of doc comments, provided every fact in "Documentation updates" appears.
- Test helper names, whether the new `aitm-core` test module reuses or re-declares the `NoopClient` stub already in `ctx.rs`, and how the new `agent_gates.rs` builds its `CommandHost` (a small closure or helper).
- Whether to add `#[must_use]` to the three predicates (recommended) and `#[inline]`.
- Whether to rename the `is_agent: bool` parameter of `agent_gate_check` in `aitm-proto-l4/src/language.rs` (the caller now passes `!caller.is_trusted_control()`); either keep the name or rename it, but the call sites must pass the negated predicate.
- The scanner's implementation (hand-rolled scan or `regex`, which `aitm-core` already depends on), provided the vectors in the plan hold.
- Updating the comments that mention the old private `is_trusted_control` in `aitm-mcp/src/server.rs` to point at `Frontend::is_trusted_control`.
- Whether to tidy `use` lists beyond removing the now-unused `Frontend`/`CallerTrust` import.

## Open questions

Both are non-blocking observations of existing behaviour that look inconsistent. This change leaves them exactly as they are; the stated default applies unless Matt says otherwise.

1. **`script.validate { path }` confines `Operator` like an agent.** `confine_validate` exempts only `Frontend::Cli`; the doc comment says "an agent frontend", but an operator-token connection (mac/web/tui) is confined too. The `check_agent_gate` comment next to it says Operator is "deliberately exempt" for authoring. Intentional (a remote surface, file-oracle risk) or an oversight? Default: leave, behaviour unchanged.
2. **`aitm-ca`'s audit log labels `Operator` as `"mcp"`** (`frontend_label`: `Cli => "cli", _ => "mcp"`), while `audit::origin_label` and the findings store label it `"operator"`. Changing it alters audit bytes, so it is out of scope here. Want a follow-up? Default: leave.
