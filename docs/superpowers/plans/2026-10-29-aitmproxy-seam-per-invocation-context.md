# Per-invocation context for the `ProtocolLanguage` host-fn seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Thread a `rhai`-free `HostCallCtx` (per-invocation caller trust + a `NativeCallContext`-derived tag/call-source) through the seam's `HostFn` and `GuardHandle::permit`, seeded at each script/PoC invocation boundary and fail-closed when unseeded — so L4 is live-gated on the real shared production engine (retiring PR #48's build-time `agent_sourced` bool) and `log.option`/`finding` can move onto the seam.

**Architecture:** `aitm-plugin::language` gains `HostCallCtx` + `CallerTrust{Operator,Agent}` + a `HostCallContextSource` trait object; `HostFn` becomes `Fn(&HostCallCtx, &[Value])` and `GuardHandle::permit(&self, &HostCallCtx, &str)`. The `aitm-plugin-rhai` `dispatch` bridge builds `HostCallCtx` from the per-eval `NativeCallContext` tag (the only place `rhai` is touched) and fails closed if unseeded. Each invocation boundary (plugin hook dispatch, PoC runner, `script`-step executor) seeds the caller trust: a hook from the script's **authoring trust**, a PoC from the `poc.run` `CommandHost` `Frontend`. L4 drops its build-time bool and reads `ctx.caller()`; it is registered on the production engine via `build_engine_with_languages` from `wire::build`. `log.option`/`finding` migrate onto the seam using the context.

**Tech Stack:** Rust — `aitm-plugin`, `aitm-plugin-rhai`, `aitm-poc`, `aitm-proto-l4`, `aitm` (wire/binary), `aitm-core` (CallerTrust/Frontend); `rhai`; the shared `docs/design/languages/*` defs unaffected.

**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-seam-per-invocation-context-design.md` (Approved).

**Branch / worktree:** `feat/seam-call-context` off current `main` (which has the seam core #44, #46, and l4 catalogued-only #48 once merged).

## Global Constraints

- **`rhai` stays out of the seam.** `HostCallCtx`/`CallerTrust`/`HostCallContextSource` speak `aitm_core` types only; `aitm-plugin` and `aitm-poc` gain no `rhai` dep (AC8). Only `aitm-plugin-rhai`'s bridge touches `NativeCallContext`.
- **Fail-closed.** Any invocation path reaching a seam host fn without seeded context is REFUSED ("no caller context"), never defaulting to `Operator` (AC3). This is the central security property — call it out as its own verification in Tasks 2 and 3.
- **Guarded-by-construction preserved.** `register` still takes `Guarded<HostFn>` only; the `compile_fail` doc-test (an unguarded effectful registration fails to compile) must still hold (AC9); permit-before-effect order preserved.
- **Hook trust = authoring-trust; CallerTrust = `{Operator, Agent}` (Agent iff `Frontend::Mcp`)** — per the approved rulings.
- **Migrate callers then delete:** when `log.option`/`finding` move behind the seam, delete the old in-crate registration once the seam version passes.
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` + `node --test docs/design/languages/`. Loopback/privilege + port-binding tests via the Terminal panel (CLAUDE.md).

## Review Focus

- **An un-seeded eval path silently defaulting to Operator** → must be a hard refusal, tested. (Tasks 2, 3)
- **The `rhai` edge leaking into `aitm-plugin`/`aitm-poc`** → crate graph must stay acyclic and rhai-free in the seam. (Task 1)
- **`agent_sourced` left anywhere in L4 as a live gate input** → the build-time bool must be gone from the gate decision. (Task 4)
- **A hook deriving operator-trust for an agent-authored script** → authoring-trust must flow from `ScriptHandle`. (Task 3)
- **Nested host-fn calls losing the tag** → the per-eval seeding must survive nested seam calls. (Task 2)

---

## Tasks

### Task 1: `HostCallCtx` + `CallerTrust` + threaded seam signatures
**Files:** Modify `crates/aitm-plugin/src/language.rs`; add `CallerTrust` in `crates/aitm-core/src/ctx.rs` (beside `Frontend`); Test: `crates/aitm-plugin/tests/language.rs`.
**Interfaces:** `CallerTrust{Operator,Agent}` (+ `From<Frontend>`: `Agent` iff `Mcp`); `HostCallCtx<'a>{ caller: CallerTrust, ctx: &'a dyn HostCallContextSource }` with `caller()`, `tag() -> Option<Value>`, `call_source() -> &str`; `trait HostCallContextSource` (rhai-free); `type HostFn = Box<dyn Fn(&HostCallCtx, &[Value]) -> Result<Value, HostError> + Send + Sync>`; `GuardHandle::permit(&self, ctx: &HostCallCtx, fn_name: &str)`.

- [ ] Step 1: failing test — a `Guarded<HostFn>` registered through a stub registry is callable with a constructed `HostCallCtx`; `permit` sees `ctx.caller()`; `aitm-plugin` has no `rhai` dep (AC8, assert via a compile check / the crate's Cargo.toml).
- [ ] Step 2: run — FAIL. Step 3: add `CallerTrust`, `HostCallCtx`, `HostCallContextSource`, thread the two signatures; keep `Guarded`-only `register` + the `compile_fail` doc-test (AC9). Step 4: PASS; gate. Step 5: commit.

### Task 2: `dispatch` bridge threads context + fail-closed
**Files:** Modify `crates/aitm-plugin-rhai/src/host_registry.rs` (the `arity!`/`register_method` closures + `dispatch`), `crates/aitm-plugin-rhai/src/engine.rs` if needed; Test: `crates/aitm-plugin-rhai/tests/host_registry.rs`.
**Interfaces:** The `register_fn` closures capture `NativeCallContext` first; `dispatch(ctx, ns, name, args)` reads the per-eval caller trust + tag/source from `ctx.tag()`, builds a `NativeCallContext`-backed `HostCallContextSource` + `HostCallCtx`, calls `permit(&hostctx, name)?` then `(entry.f)(&hostctx, &values)?`.

- [ ] Step 1: failing tests — AC1: a seam fn reads `ctx.caller()`; one engine, two evals seeded `Agent` vs `Operator`, observes each. AC3 (FAIL-CLOSED, own verification): an eval reaching a seam fn with NO seeded context is refused with a clear "no caller context" error — never `Operator`. Nested seam call keeps the tag (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement the bridge + the `HostCallContextSource` over `NativeCallContext`; deny-by-default on a missing tag. Step 4: PASS; gate. Step 5: commit.

### Task 3: Seed caller trust at every invocation boundary
**Files:** Modify `crates/aitm-plugin-rhai/src/plugin.rs` (hook dispatch in `ScriptHost`/`ScriptPlugin`), the PoC runner (`crates/aitm-poc/src/runner.rs`) + `poc.run` command wiring, the `script`-step executor; record authoring trust on `ScriptHandle` (set at `script.save`/load, F8); Test: `crates/aitm-plugin-rhai/tests/plugin.rs`, `crates/aitm-poc/tests/*`.
**Interfaces:** Each boundary seeds the per-eval tag before evaluating: a **hook** seeds the script's authoring trust (`ScriptHandle` records agent-vs-operator at author/load time); a **PoC/`poc.run`** seeds `CallerTrust::from(host.frontend())`; a bare `script:` step inherits the enclosing PoC's trust.

- [ ] Step 1: failing tests — AC6: an agent-authored script's hook host-fn call is gated `Agent`, an operator-authored one `Operator`. AC5: an `l4:`/protocol step in a PoC run via an agent `Frontend` is `Agent`, via operator `Operator`. AC3 (own verification): a test asserts every production invocation boundary seeds the trust (no path left unseeded).
- [ ] Step 2: run — FAIL. Step 3: record authoring trust on `ScriptHandle`; seed at each boundary. Step 4: PASS; gate. Step 5: commit.
- **Checkpoint:** confirm the authoring-trust model with the L4 + M4 owners (per the spec ruling) before relying on it in Task 4.

### Task 4: L4 consumes per-call trust — live-gating via the real `wire::build` (distinct task)
**Files:** Modify `crates/aitm-proto-l4/src/language.rs` (drop `agent_sourced`; `permit`/`agent_gate_check` read `ctx.caller()`), `crates/aitm-plugin-rhai/src/wire.rs` + `crates/aitm/src/main.rs` (register `L4Language` on the production engine via `build_engine_with_languages`, threading the L4 module state / an `Arc` handle per the spec's "left to the builder"); Test: `crates/aitm-proto-l4/tests/language.rs`, an end-to-end test through the production build path.
**Interfaces:** `L4SeamGuard` carries no build-time `agent_sourced`; the gate reads the per-call `ctx.caller()`; L4 is registered live on the shared engine.
**Depends on:** Tasks 1–3.

- [ ] Step 1: failing tests — AC4: through `build_engine_with_languages` as called by the production `wire::build` (not a test-only engine), an `Agent`-trust `l4.send_recv`/`l4.inject` with its `allow_agent_*` flag OFF is refused and nothing reaches the wire; flag ON runs; `Operator`-trust runs regardless; scoped loopback confirms pass-vs-refused (loopback via the Terminal panel). Assert `agent_sourced` is gone from the gate decision (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement. Step 4: PASS; gate (Terminal panel for loopback/privilege). Step 5: commit.

### Task 5: Migrate `log.option` + `finding` onto the seam using the context (distinct task)
**Files:** Modify `crates/aitm-plugin-rhai/src/{host_core,prelude}.rs` (move `log.option`/`finding` from in-crate registration to a first-party `ProtocolLanguage`/core-namespace registration, each `Guarded`), delete the old registration; **and thread the real per-eval tag/source through `seed_call_context` at the invocation boundaries (`crates/aitm-plugin-rhai/src/plugin.rs`, the `poc.run`/`command.rs` wiring)** — the original file set was insufficient: `option`'s tag and `finding`'s source are seeded through rhai's `NativeCallContext`, not through `seed_call_context`, so dispatch can't recover them and the migration would silently regress. Test: `crates/aitm-plugin-rhai/tests/{host_core,prelude}.rs` (existing behaviour unchanged) + a boundary test that the migrated `option`/`finding` see the real tag/source.
**Interfaces:** `log.option` reads `ctx.tag()` (the script options); `finding` reads `ctx.call_source()`. Both move behind the seam, proving the context-needing (AC7) path moves. (Effectful-fn proof: migrating one effectful namespace such as `store`/`scope` is an incremental follow-up per the ruling — NOT required here.)
**Depends on:** Tasks 1–2.
**Scope amendment (architect-ratified):** the coder correctly BLOCKED on the original host_core/prelude-only file set because the per-eval tag/source are not reachable at dispatch without threading them from the eval boundary; the fix widens the file set to `plugin.rs`/`command.rs` (the same boundaries Task 3 seeds trust at) to thread the real tag/source through `seed_call_context`. No behaviour change beyond making the migration faithful.

- [ ] Step 1: failing tests — AC7: `log.option` (via `ctx.tag()`) and `finding` (via `ctx.call_source()`) run identically after moving onto the seam; the old in-crate registration is gone (not double-registered). Step 2: run — FAIL. Step 3: implement + delete old path. Step 4: PASS; gate. Step 5: commit.

### Task 6: No-regression + backward-compat
**Files:** Test-only across the touched crates; no production change beyond what Tasks 1–5 land.
**Interfaces:** AC10 — existing seam ACs (the test namespace, both drift guards, the l4 catalog + goldens) still pass; a context-ignoring host fn is still a one-line closure; AC8 (rhai-free seam) + AC9 (`compile_fail`) preserved.

- [ ] Step 1: run the full existing seam + l4 + F8 suites against the branch tip; confirm green. Step 2: add a backward-compat test that a context-ignoring host fn compiles and runs. Step 3: gate (fmt + clippy -D warnings + cargo test + node). Step 4: commit.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| 3 | Build (self) | — | Cross-restart authoring-trust default seeded `Operator` for unknown-provenance reloads (agent→operator escalation) | FIXED (dd568cc) per architect ruling — unknown provenance seeds least-privilege `Agent`; in-session operator authorship preserved |
| 5 | Build (coder) | Blocker | `option`/`finding` migration can't recover the per-eval tag/source at dispatch within the host_core/prelude-only file set — would silently regress | Architect-ratified scope amendment: thread the real tag/source through `seed_call_context` at the `plugin.rs`/`command.rs` boundaries (Task 3's seeding boundaries); no behaviour change beyond a faithful migration |
| — | Build (self) | fast-follow | Native `l4:` PoC-step handler not yet registered into the production `poc.run` runner (gate logic correct once wired) | Pre-existing, out of this build's scope; flagged for a separate follow-up PR |

Stage-6 panel on PR #63 (origin/claude/seam-call-context-3151ba):

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| all | Security | — | PASS, zero findings. Fail-closed (strict `seed.caller`, no fallback) + thread-local non-leakage (`#[must_use]` RAII `CallContextGuard`, survives early-return/`?`/panic) both verified; `agent_sourced` gone from both faces; rhai-free seam; no `unsafe` | PASS |
| all | Spec | — | PASS, all 10 ACs met+tested; both follow-ups deferred not folded in; three rulings honored | PASS |
| 3 | Quality + Spec | Minor | Four doc comments say the loader records `Operator` for a config-placed script; code correctly seeds `Agent` (loader.rs:300) — inverts the dd568cc security ruling in prose | FIX required (comment-only): plugin.rs with_authoring_trust/set_authoring_trust, command.rs with_caller, commands.rs load_one → say least-privilege `Agent` for unknown provenance |
| 4 | Spec | Minor | `aitm/src/wire.rs` + `aitm-proto-l4/src/module.rs` touched beyond Task-4's file list (the `L4Shared`/`with_shared` wiring) | Accepted — spec "left to the builder" anticipated the shared-guard wire change; recorded here |
| 1,5 | Quality | Minor | Duplicated probe-language/AdmitGuard test scaffold across 4 files; `finding_error`/`host_error` byte-identical; `VecDeque::new()` vs main's `Vec::new().into()` | Optional / no-action — builder's discretion, not gating |

## Shipped

Filled at stage 7.
