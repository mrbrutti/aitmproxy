# Per-invocation context for the `ProtocolLanguage` host-fn seam design

**Status:** Approved (orchestrator, on Matt's delegation, 2026-10-29). Stage-3 plan: `docs/superpowers/plans/2026-10-29-aitmproxy-seam-per-invocation-context.md`. All three open questions resolved to the recommended defaults (see Open questions). Not yet built.
**Directive:** Matt, 2026-10-29 — "write the spec for the seam per-invocation-context enhancement (threading Frontend/NativeCallContext into the ProtocolLanguage HostFn) that unblocks l4 live-gating and the Task-5 host-fn migration."
**Extends (amends) the seam:** `docs/superpowers/specs/2026-10-28-aitmproxy-protocol-extensible-languages-design.md` (shipped on `main`: `aitm-plugin::language` seam + `aitm-plugin-rhai` host registry). Unblocks the deferred **Task 5** (migrate `http`/`browser`/`store`/`scope` onto the seam) and the deferred **L4 live scripting wiring** (PR #48 landed l4 catalogued-only).
**Grounding (verified against `main` + the `claude/proto-l4-task6` tip):**
- `aitm-plugin/src/language.rs:103` — `pub type HostFn = Box<dyn Fn(&[Value]) -> Result<Value, HostError> + Send + Sync>;` (context-free: args only).
- `aitm-plugin/src/language.rs:95` — `ScriptHostRegistry::register(&mut self, ns, name, f: Guarded<HostFn>)`; `:141` `trait GuardHandle { fn permit(&self, fn_name: &str) -> Result<(), HostError> { /* deny-by-default */ } }`.
- `aitm-plugin-rhai/src/host_registry.rs:251` — `dispatch(ns, name, args)` marshals args → `entry.guard.permit(name)` → `(entry.f)(&values)`. The `arity!` `register_fn` closures (`:214-247`) capture **no** `NativeCallContext`.
- `aitm-plugin-rhai/src/engine.rs:201` `build_engine_with_languages` installs languages onto **one shared** `Engine`; `wire::build` (`wire.rs:57`) builds that one engine for all frontends.
- `aitm-proto-l4/src/language.rs:144,232-264` — `L4SeamGuard { agent_sourced: bool, .. }`; `permit` calls `agent_gate_check(self.agent_sourced, ..)` which returns `Ok(())` when `!agent_sourced`. `agent_sourced` is a **build-time** bool (`L4Language::new(.., agent_sourced)`, `for_catalog()` sets `false`).

## Intent

The seam's host-fn type is deliberately context-free — `Fn(&[Value]) -> Result<Value>` — which decoupled it cleanly from `rhai` and from any per-call state. Two landed pieces hit the same wall because of it:

1. **L4 live gating (PR #48, security-flagged).** An agent's in-script `l4.inject()` must be refused unless `l4.allow_agent_inject` is set — the same gate as the `l4.inject` command. The command path reads the **per-invocation** `Frontend` (agent vs operator) from `CommandHost`. A script host fn has no such context, so PR #48 approximated it with a **build-time** `agent_sourced: bool` on `L4Language`. But `wire::build` makes **one engine shared across all frontends**, so a build-time bool cannot distinguish an agent caller from an operator caller at the point of the call. The bool is correct for a test that builds a dedicated agent-sourced engine, but it **cannot be production-live**: there is no single correct value for a shared engine.

2. **Task-5 migration (deferred).** Migrating the shipped `http`/`browser`/`store`/`scope` host fns onto the seam stalled because `log.option` and `finding` need `rhai`'s `NativeCallContext` (the per-call tag / call-source), which the context-free `HostFn` cannot carry. They stay hard-wired in-crate today.

Both are the same gap: **the seam's host fn, and its guard, have no per-invocation context.** This spec threads a small, `rhai`-free **`HostCallCtx`** through `HostFn` and `GuardHandle::permit`, seeded once at each script/PoC invocation boundary and read in the `dispatch` bridge. With it, a guard gates on the live caller trust (not a build-time bool), and a host fn can reach the per-call surface the migration needs — so l4 goes production-live and the first-party namespaces can finally move behind the seam.

## Goals

- **Per-invocation caller trust reaches the guard.** `GuardHandle::permit` receives a `HostCallCtx` carrying the live **caller trust** (operator vs agent) for this call, so `L4SeamGuard` (and any protocol guard) can enforce its `allow_agent_*` flag + tier per call — identical to the command path — on the **one shared engine**, replacing the build-time `agent_sourced` bool. Deny-by-default preserved.
- **Per-invocation context reaches the host fn.** `HostFn` receives the same `HostCallCtx`, which also exposes the `NativeCallContext`-derived surface the first-party fns need (a script **tag** for `log.option`, a **call source** for `finding`) — so Task 5's migration is unblocked.
- **Seeded correctly per entry point.** The context's caller trust is sourced where the invocation actually originates: the PoC/`poc.run` path derives it from that command's `CommandHost` `Frontend`; a plugin **hook** derives it from the script tier's authoring trust (`scripts.allow_agent_authoring` — an agent-authored script's effects are gated, an operator-authored script's are not). One documented rule per entry point; no entry point left defaulting to "operator" by omission.
- **`rhai`-free seam.** `HostCallCtx` lives in `aitm-plugin::language` and speaks `aitm_core` types (`Frontend`/a caller-trust enum) + an opaque accessor for the tag/source; it does **not** leak `rhai::NativeCallContext` into `aitm-plugin`/`aitm-poc`, keeping the crate graph acyclic (the `aitm-plugin-rhai` `dispatch` bridge is the only place that touches `NativeCallContext`).
- **Backward-compatible for context-free fns.** A host fn that ignores the context stays a one-line closure; the migration is additive.

## Non-goals

- **No per-frontend engines.** The shared-engine contract (`wire::build` builds one engine) stays; the fix is per-call context, not per-call engines.
- **No new gating model.** M4 `AgentPolicy`/`Sensitivity` and each protocol's `allow_agent_*` flags are unchanged; this only makes the **script face** read the live caller trust the command face already reads.
- **No change to the `l4.*` verbs, the catalog, or the PoC `l4:` step shape.** Only the gate's input (per-call context vs build-time bool) changes; the shipped scope (one-shot verbs; capture/intercept deferred) stands.
- **No new scripting capability.** Hooks, the flow object, the sandbox, the matcher/extractor DSL — unchanged.

## Anti-goals

- **A host fn that silently runs un-gated because the context defaulted to "operator".** Every invocation path must set the caller trust explicitly; an un-seeded path is a **fail-closed** error, not an implicit operator bypass. (This is the exact failure the security reviewer flagged: a wiring that defaults the source wrong opens every Sensitive verb to agents.)
- **Leaking `rhai` into the seam traits.** `HostCallCtx` must not expose a `rhai` type; a protocol crate implementing `ProtocolLanguage` must not need a `rhai` dependency.
- **A context that lies about the caller.** The trust the guard sees must be the real trust of the live invocation, not a stale build-time snapshot — the defect this spec exists to remove.
- **Breaking the guarded-by-construction property.** The type-level `Guarded<HostFn>`-only `register` and the permit-before-effect order in `dispatch` must survive the signature change.

## Constraints

- **Additive to `aitm-plugin::language` + `aitm-plugin-rhai`; the `rhai` touch is confined to the `dispatch` bridge.** `HostFn`/`GuardHandle::permit` gain a `&HostCallCtx` parameter; `dispatch` (`host_registry.rs`) builds it from the per-eval `NativeCallContext`.
- **Per-eval seeding via `rhai`'s tag.** `rhai` exposes `NativeCallContext::tag()` (a `Dynamic` set per-eval, e.g. via `Engine::eval_*_with_scope` + a seeded engine/scope tag). The invocation boundary (the hook-dispatch in `ScriptPlugin`/`ScriptHost`, the PoC runner, the `script`-step executor) seeds the caller trust (and the tag/source handle) into the eval; `dispatch` reads it back. The `arity!` closures must be changed to capture `NativeCallContext` as their first parameter (`rhai` supports this) so `dispatch` can read the tag.
- **Caller-trust type in `aitm-core`.** Reuse `Frontend` (`aitm-core/src/ctx.rs`) or a derived `CallerTrust { Operator, Agent }`; the mapping from each entry point to it is defined here and tested.
- **Workflow & gate:** seven stages; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` + `node --test docs/design/languages/`. Loopback/privilege and port-binding tests via the Terminal panel (CLAUDE.md).
- **Migrate callers, then delete.** The deferred Task-5 migration of `http`/`browser`/`store`/`scope` + the in-crate `log.option`/`finding` move behind the seam using the new context; the old in-crate registration is deleted once each is behind the seam and its tests pass (incremental, one namespace/commit).

## Design

### The context — a `rhai`-free `HostCallCtx`

A small struct in `aitm-plugin::language`, constructed per call:

```
pub struct HostCallCtx<'a> {
    /// The live trust of this invocation: Operator (a human) or Agent (Mcp).
    caller: CallerTrust,                 // aitm_core
    /// Opaque, rhai-free accessors the first-party fns need (Task 5):
    ///  - script tag (for log.option)       -> Option<&str> / Value
    ///  - call source (for finding)          -> &str
    /// Backed in aitm-plugin-rhai by the NativeCallContext; the trait object
    /// keeps rhai out of aitm-plugin.
    ctx: &'a dyn HostCallContextSource,
}
impl HostCallCtx<'_> { pub fn caller(&self) -> CallerTrust; pub fn tag(&self) -> Option<Value>; pub fn call_source(&self) -> &str; }
```

- `CallerTrust { Operator, Agent }` derived from `Frontend` (`Agent` iff `Frontend::Mcp`).
- `HostCallContextSource` is a tiny trait `aitm-plugin-rhai` implements over the `NativeCallContext` + the seeded tag; `aitm-plugin` only sees the trait object, so no `rhai` edge.

### Threaded signatures (the additive change)

- `pub type HostFn = Box<dyn Fn(&HostCallCtx, &[Value]) -> Result<Value, HostError> + Send + Sync>;`
- `trait GuardHandle { fn permit(&self, ctx: &HostCallCtx, fn_name: &str) -> Result<(), HostError> { /* deny-by-default, now may read ctx.caller() */ } }`
- `ScriptHostRegistry::register` unchanged (still `Guarded<HostFn>`); the guarded-by-construction type-level enforcement is untouched.

### The bridge (`aitm-plugin-rhai::host_registry::dispatch`)

The `arity!` closures take `NativeCallContext` first; `dispatch(ctx: NativeCallContext, ns, name, args)`:
1. Read the per-eval **caller trust** + tag/source from `ctx.tag()` (seeded at the invocation boundary). **If absent → fail closed** (`HostError::GuardRefused`-class "no caller context"), never assume operator.
2. Build a `HostCallCtx` over a `NativeCallContext`-backed `HostCallContextSource`.
3. `entry.guard.permit(&hostctx, name)?` (permit-before-effect preserved) → `(entry.f)(&hostctx, &values)?` → marshal back.

### Seeding at each invocation boundary (the fail-closed rule)

- **PoC `<ns>:` step / `poc.run`**: the `poc.run` command has a `CommandHost` with the real `Frontend`; the PoC runner seeds `CallerTrust` from it before evaluating any protocol step. (A PoC authored and run by an agent is agent-trust; by an operator, operator-trust.)
- **Plugin hook** (`ScriptPlugin`/`ScriptHost` hook dispatch): hooks run detached from any frontend (the proxy fires them), so the trust is the **script's authoring trust** — an agent-authored script (installed while `scripts.allow_agent_authoring` was on, per F8) seeds `Agent`; an operator-authored script seeds `Operator`. (Recorded on the `ScriptHandle` at author/load time.)
- **Bare `script:` PoC step / direct eval**: inherits the enclosing PoC's trust.
- Any eval path that reaches a seam host fn without seeding → the `dispatch` fail-closed error. A test asserts every production invocation path seeds it.

### L4 consumes it (makes PR #48 live)

`L4SeamGuard` drops its `agent_sourced` bool; `permit(&self, ctx, fn_name)` calls `agent_gate_check(ctx.caller() == Agent, &self.gates, fn_name, self.gate)` — the live per-call trust. `L4Language` is registered on the production shared engine via `build_engine_with_languages` from `wire::build` (the integration this unblocks), with no build-time source. An agent-trust call to a Sensitive l4 verb with its flag off is refused; an operator-trust call runs; identical to the command path.

### First-party migration consumes it (Task 5)

`log.option` reads `ctx.tag()` (the script options) and `finding` reads `ctx.call_source()`, so they move from in-crate registration onto the seam as a first-party `ProtocolLanguage` (or the core `log`/`store`/`scope` namespaces), each guard-wrapped, deleting the old ad-hoc registration per namespace.

## Acceptance criteria

Observable via `cargo test` (+ Terminal-panel loopback for AC4).

1. **AC1 — context threads.** A test namespace host fn reads `ctx.caller()` and returns it; a script invoked with a seeded `Agent` trust observes `Agent`, with `Operator` observes `Operator` — on **one** engine, two invocations, different trust.
2. **AC2 — guard gates on live trust.** A `Guarded` host fn whose guard refuses `Agent` is refused when invoked with `Agent` trust and runs under `Operator` trust — same engine, same registration, decided per call (not at build).
3. **AC3 — fail-closed.** An eval path that reaches a seam host fn without seeded context is refused with a clear "no caller context" error; no path silently defaults to `Operator`. A test asserts every production invocation boundary seeds the trust.
4. **AC4 — l4 live-gated through the real build.** Through `build_engine_with_languages` as called by the production `wire::build` (not a test-only engine), an `Agent`-trust `l4.send_recv`/`l4.inject` with its `allow_agent_*` flag **off** is refused and nothing reaches the wire; with the flag **on** it runs; an `Operator`-trust call runs regardless; a scoped loopback target confirms pass-vs-refused (parity with the command path and M5 guard tests). `L4SeamGuard` no longer carries a build-time `agent_sourced` bool.
5. **AC5 — PoC trust sourcing.** An `l4:` step inside a PoC run via an agent-`Frontend` `poc.run` is gated as `Agent`; the same PoC run by an operator is `Operator` — asserted end-to-end through the runner.
6. **AC6 — hook trust sourcing.** An agent-authored script's hook host-fn call is gated as `Agent`; an operator-authored script's as `Operator`.
7. **AC7 — first-party migration.** `log.option` (reads `ctx.tag()`) and `finding` (reads `ctx.call_source()`) run identically after moving onto the seam; at least one of `http`/`browser`/`store`/`scope` is migrated behind the seam with its existing tests green, proving the context-needing and effectful first-party fns both move.
8. **AC8 — rhai-free seam.** `aitm-plugin` and `aitm-poc` gain no `rhai` dependency; `HostCallCtx` exposes no `rhai` type (asserted by the crate graph + a compile check).
9. **AC9 — guarded-by-construction preserved.** The `Guarded<HostFn>`-only `register` + permit-before-effect order survive the signature change; the existing `compile_fail` doc-test (an unguarded effectful registration fails to compile) still holds.
10. **AC10 — backward-compat.** The existing seam ACs (the test namespace, the drift guards, the l4 catalog) still pass; a context-ignoring host fn is still a one-line closure.

## Left to the builder

- The exact `HostCallContextSource` trait shape and how `NativeCallContext::tag()` is seeded (engine default tag vs per-eval scope vs a thread-local at the eval boundary) — pick the `rhai`-idiomatic path that survives nested calls.
- Where the script's authoring trust is recorded on `ScriptHandle` (F8 already tracks the authoring gate) and how `script.save`/`script.reload` set it.
- Whether `CallerTrust` is a new `aitm-core` enum or a direct `Frontend` reuse.
- Migration order for `http`/`browser`/`store`/`scope` (incremental; `log`/`finding` first since they are the context consumers).
- Whether the `l4` live registration in `wire::build` threads the L4 module state directly or via an `Arc` handle the host binary installs (the cross-cutting wire-API change PR #48's follow-up identified).

## Open questions

Resolved at approval (2026-10-29, orchestrator on Matt's delegation):

1. **Caller trust for a hook — authoring-trust vs ambient → DECIDED: authoring-trust.** A hook's trust is the **script's authoring trust** (agent-authored ⇒ `Agent`, operator-authored ⇒ `Operator`); hook-time effects are NOT treated as blanket operator-trust. Rationale: an agent that authored a hook must not gain operator-level l4 powers at hook time. The plan keeps "confirm with the L4 + M4 owners" as a checkpoint, but authoring-trust is the decision.
2. **One shared `CallerTrust` vs richer context → DECIDED: minimal `{Operator, Agent}` now,** derived from `Frontend` (`Agent` iff `Frontend::Mcp`). `HostCallCtx` can be extended later (e.g. operator identity for audit) without another signature change.
3. **First-party migration scope for this task → DECIDED: migrate `log.option` + `finding` only** (the two context consumers), satisfying AC7's minimum and proving both the context-needing and effectful paths move. `http`/`browser`/`store`/`scope` are incremental follow-ups, not required in this task.
