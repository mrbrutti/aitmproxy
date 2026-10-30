# L4 `l4:` PoC-step wiring into production `poc.run` design

**Status:** Approved (orchestrator, on Matt's delegation, 2026-10-29)
**Research inputs:** `docs/superpowers/plans/2026-10-29-aitmproxy-seam-per-invocation-context.md` (Review log flags this fast-follow), `docs/superpowers/specs/2026-10-29-aitmproxy-seam-per-invocation-context-design.md`, `docs/superpowers/plans/2026-10-28-aitmproxy-protocol-extensible-languages.md` (the `ProtocolLanguage` / `PocStepHandler` seam)
**Base:** `origin/main` @ `59c9050` (seam #63 and dsl #59 merged)

## Intent

The seam build (#63) made the rhai `l4.*` host-fn face production-live and gated
on live per-call trust, and the `ProtocolLanguage` seam already gives L4 a native
`l4:` PoC-step handler (`L4StepHandler`, via `L4Language::poc_step()`) that reads
`PocStepInputs::caller` and gates exactly like the rhai face. The runner
(`StdPocRunner`) already dispatches a `Step::Protocol { ns, body, extract }` to a
registered `PocStepHandler` and seeds `inputs.caller` from the `poc.run`
command's frontend (`CallerTrust::from(host.frontend())`). The one missing wire is
in production assembly: `run_poc_command` builds the runner with the script
executor but **never** threads a `PocStepRegistry`, and nothing in
`crates/aitm/src/{main.rs,wire.rs}` hands the L4 handler to `poc.run`. So an `l4:`
step in a PoC YAML run via `poc.run` today fails with "no handler registered for
protocol step `l4:`". This change threads the L4 step handler — over the **same**
shared `L4Guard` + `L4FlowStore` the rhai face and the `l4.*` command module
already share — into the production `poc.run`. It is wiring, not redesign.

## Goals

- In the shipped binary with `l4.enabled`, a PoC whose step is
  `l4: { op: send_recv | inject | craft, ... }`, run via `poc.run`, dispatches to
  the native `L4StepHandler` instead of failing with "no handler registered".
- The `l4:` step gates on the **live per-call trust** (`inputs.caller`, seeded by
  the runner from the `poc.run` `CommandHost` frontend), through the **same**
  shared `L4Guard` / `L4FlowStore` the rhai `l4.*` face and the `l4.*` command
  module use — one L4 engagement state across all three faces, no second guard,
  no build-time flag.
- An operator-frontend `l4:` step runs (reaches the backend); an agent-frontend
  (`Frontend::Mcp`) step with its `allow_agent_*` gate OFF is refused by the agent
  gate before any backend call (nothing reaches the wire); the same step with the
  gate ON runs.
- Fail-closed: a runner that reaches an `l4:` step on a host with no explicit
  frontend treats the caller as the most restrictive `CallerTrust::Agent`
  (`Frontend::Mcp` default) and, with the gate off, refuses.

## Non-goals

- No change to `L4StepHandler`'s gate logic, its verb set, its body grammar, or
  its `packet` source/extract shape. Its agent-gate is already correct against
  `inputs.caller`; this is registration only. A constructor/plumbing tweak needed
  purely to thread the shared state is in scope; a logic change is not.
- No change to the rhai `l4.*` host-fn face or to the `l4.*` command module.
- No new `l4:` verbs; no change to `poc-yaml.schema.json` / `rhai.api.json` or any
  shared language definition (the catalog already advertises the `l4:` step via
  `L4Language::catalog().poc_step`).
- Not changing the runner's HTTP finding-anchor contract. `StdPocRunner` still
  requires an HTTP flow to anchor the finding capture, so an **l4-only** PoC (no
  `http:` step) still ends with the existing "no HTTP flow was captured" error
  even though its `l4:` step now executes. Making an l4-only PoC produce a verdict
  is a separate design question (see Open questions), explicitly out of scope here.

## Anti-goals

- A second, divergent L4 guard/store for the PoC-step face — any state not shared
  with the rhai face and the command module is a failure even if tests pass.
- A build-time "agent vs operator" bool deciding the `l4:` gate instead of the
  per-call `inputs.caller`.
- An `l4:` step that reaches the wire under agent trust with the gate closed, or
  that silently no-ops / silently skips when unregistered.
- Widening the change beyond the three threading edits (runner command, assembly,
  tests). Touching L4 gate logic, the rhai face, or the command module.

## Constraints

- `#![forbid(unsafe_code)]` holds in `aitm-proto-l4`; no `unsafe` anywhere.
- Real raw-L4 send/inject needs libpcap + an L2 frame and raw privilege; the
  Claude sandbox cannot bind sockets. Hermetic proofs use a recording
  `CaptureInjectBackend` (the established `MockBackend` pattern in
  `crates/aitm-proto-l4/tests/language.rs`), so they are privilege-free and
  OS-independent. The real-wire loopback proof is `#[ignore]`, Linux-only, and
  gated on `AITM_L4_TESTS=1`, run via the Terminal panel (per `CLAUDE.md` and the
  `aitmproxy-sandbox-cargo` memory), mirroring
  `crates/aitm-proto-l4/tests/active_roundtrip.rs`.
- The library dependency graph stays acyclic: `aitm-poc` must not gain an
  `aitm-proto-l4` dependency. The runner already takes `Arc<dyn PocStepHandler>`
  through the `aitm-plugin` seam; the binary (`aitm`) is the only crate that knows
  both `aitm-poc` and `aitm-proto-l4`. `aitm-proto-l4` already dev-depends on
  `aitm-poc`, so a runner-level test may live there.
- Gate before any review:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  `node --test docs/design/languages/` is required only if a shared language
  definition changes — not expected here.

## Design

### What already exists at `59c9050` (confirmed by reading main)

- `crates/aitm-poc/src/runner.rs`: `StdPocRunner` carries
  `step_handlers: PocStepRegistry`; `with_step_handler(Arc<dyn PocStepHandler>)`
  and `with_step_handlers(PocStepRegistry)` register them. `run_inner`'s match arm
  `Step::Protocol { ns, body, extract }` looks the handler up by `ns`, errors
  `"poc.run: no handler registered for protocol step `{ns}:` ..."` when absent,
  and otherwise builds
  `PocStepInputs { vars, caller: CallerTrust::from(host.frontend()) }` and calls
  `handler.run(body, &inputs)`.
- `crates/aitm-poc/src/step_registry.rs`: `PocStepRegistry` (`new`, `register`,
  `get`, `is_empty`, `namespaces`), `Clone + Default + Debug`.
- `crates/aitm-plugin/src/language.rs`: `PocStepHandler { ns, run }`,
  `PocStepInputs { vars, caller }` (`Default` ⇒ fail-closed `CallerTrust::Agent`),
  `PocStepOutcome { sources, bindings }`.
- `crates/aitm-proto-l4/src/language.rs`: `L4Language::new(guard, backend, store)`
  holds `L4Live { guard, backend, store }` and its `poc_step()` returns
  `Some(Box::new(L4StepHandler { live }))`. `L4StepHandler::run` runs
  `agent_gate_check(inputs.caller == CallerTrust::Agent, ...)` **before** any
  backend call (`do_send_recv` / `do_inject`), so a closed agent gate refuses
  before the wire. The handler-level gate is already tested in
  `crates/aitm-proto-l4/tests/language.rs`.
- `crates/aitm/src/main.rs` (~198–218): builds
  `l4_shared = L4Shared { guard, store }` and
  `l4_language = L4Language::new(shared.guard.clone(), PcapBackend::new(), shared.store.clone())`,
  installs it on the rhai engine via `build_with_languages`, then `drop`s the
  language; `l4_shared` moves into `Features::l4_shared`.
- `crates/aitm/src/wire.rs`: `L4Shared { guard, store }`; `L4Module::with_shared`
  builds the command module over the same guard/store; `ScriptWiring { plugins,
  executor, commands }`; the `PocCommands` plugin's `load` calls
  `aitm_poc::runner::register_with_executor(reg, exec)` or `register(reg)`.
- `crates/aitm-core/src/ctx.rs`: `CommandHost::frontend()` defaults to
  `Frontend::Mcp`; `From<Frontend> for CallerTrust` maps `Mcp → Agent`,
  `Cli | Operator → Operator`. So an unseeded host is fail-closed Agent.

### The gap

`run_poc_command` (runner.rs) builds the runner and calls `with_script_executor`
but never `with_step_handlers`. `PocCommands::load` never passes a registry. So
`poc.run`'s runner always has an empty `step_handlers`, and every `l4:` step hits
the "no handler registered" error.

### The change — two threading edits plus tests

1. **Thread a `PocStepRegistry` through the `poc.run` command**
   (`crates/aitm-poc/src/runner.rs`). **(Architect's call)** Carry the registry on
   the already-stateful `ScriptedPocRunCommand`:
   - Add field `step_handlers: PocStepRegistry` to `ScriptedPocRunCommand`.
   - `ScriptedPocRunCommand::new` keeps its current signature for back-compat; add
     the real production constructor
     `ScriptedPocRunCommand::with_steps(executor: Arc<dyn ScriptStepExecutor>, step_handlers: PocStepRegistry)`.
   - Give `run_poc_command` a new parameter
     `step_handlers: &PocStepRegistry`; after `with_script_executor`, call
     `runner = runner.with_step_handlers(step_handlers.clone())` when
     `!step_handlers.is_empty()`.
   - `PocRunCommand::invoke` passes `&PocStepRegistry::new()` (empty — the
     declarative M1 command stays handler-free; `PocRunCommand` remains a unit
     struct, zero ripple).
   - Add `pub fn register_with_executor_and_steps(registry, executor, step_handlers)`;
     keep `register` and `register_with_executor` as thin wrappers (empty
     registry) for existing callers. Production calls the new function.

   Rationale for carrying it on `ScriptedPocRunCommand` rather than giving
   `PocRunCommand` a field: the production binary always builds the rhai tier and
   registers the scripted variant, so the scripted command is the one on the
   production `poc.run`. Keeping `PocRunCommand` a unit struct avoids rippling its
   many `PocRunCommand.name()` / `Arc::new(PocRunCommand)` use sites. A
   steps-without-executor deployment is not a current production path (see Left to
   the builder).

2. **Build the registry from the live L4 language and thread it from assembly**
   (`crates/aitm/src/{wire.rs,main.rs}`).
   - `wire.rs`: add field
     `pub poc_step_handlers: aitm_poc::step_registry::PocStepRegistry` to
     `ScriptWiring` (defaults empty via `#[derive(Default)]`). Add field
     `step_handlers: PocStepRegistry` to the `PocCommands` plugin; its `load`
     calls `aitm_poc::runner::register_with_executor_and_steps(reg, exec,
     self.step_handlers.clone())` when an executor is present (else the existing
     `register`/`register_with_executor`, threading the registry through a
     steps-only path only if `aitm-poc` exposes one — not required for
     production). `assemble_with_scripts` forwards `scripts.poc_step_handlers`
     into the `PocCommands` it constructs.
   - `main.rs`: **(Architect's call)** immediately before `drop(l4_language)`,
     build the registry from the **same** live language instance so it shares the
     exact `L4Live { guard, backend, store }` the rhai face uses:
     `let poc_step_handlers = { let mut r = PocStepRegistry::new(); if let Some(lang) = &l4_language { if let Some(h) = lang.poc_step() { r.register(Arc::from(h)); } } r };`
     then pass `poc_step_handlers` in the `ScriptWiring { .. }` literal. The guard
     and store are thus identical `Arc`s to those in `Features::l4_shared` and the
     `L4Module`; the backend is a fresh `PcapBackend` exactly as every other L4
     face builds its own (the backend is a stateless privilege wrapper — the
     engagement state lives in the shared guard + store). When L4 is disabled the
     registry is empty and `poc.run` is unchanged.

   `Arc::from(Box<dyn PocStepHandler>)` yields the `Arc<dyn PocStepHandler>`
   `PocStepRegistry::register` takes.

### Data flow (after the change)

`poc.run` invoked → `run_poc_command` builds `StdPocRunner`, wires the script
executor **and** `with_step_handlers(l4 registry)` → `run_inner` hits
`Step::Protocol { ns: "l4", .. }` → looks up the `l4` handler → seeds
`PocStepInputs { vars, caller: CallerTrust::from(host.frontend()) }` →
`L4StepHandler::run` runs `agent_gate_check` on `inputs.caller` over the shared
`L4Guard`, then (if admitted) the verb over the shared backend/store.

## Acceptance criteria

Each is observable through an invoked `poc.run` over a recording
`CaptureInjectBackend` (privilege-free), unless marked privilege-gated.

1. **AC1 (registration):** With `l4.enabled`, a PoC whose step is
   `l4: { op: send_recv, ... }` run via the assembled `poc.run` does **not** fail
   with `"no handler registered for protocol step `l4:`"`. (Before this change it
   does; this is the regression proof.)
2. **AC2 (operator runs):** With the `poc.run` `CommandHost` built
   `with_frontend(Frontend::Operator)` (or `Cli`), the `l4:` `send_recv`/`inject`
   step reaches the recording backend exactly once
   (`backend.injected().len() == 1`).
3. **AC3 (agent, gate off, refused — nothing on the wire):** With
   `with_frontend(Frontend::Mcp)` and the governing `allow_agent_*` flag `false`,
   the invoked `poc.run` returns an error whose message names the disabled
   capability (e.g. contains `"disabled"` and `"inject"`) and is **not** the
   "no handler registered" error, and the recording backend is untouched
   (`backend.injected().is_empty()`).
4. **AC4 (agent, gate on, runs):** With `with_frontend(Frontend::Mcp)` and the
   governing `allow_agent_*` flag `true`, the `l4:` step reaches the backend
   exactly once (`backend.injected().len() == 1`).
5. **AC5 (fail-closed / unseeded):** With a `CommandHost` that sets no frontend
   (defaults to `Frontend::Mcp` → `CallerTrust::Agent`) and the governing flag
   `false`, the invoked `poc.run` is refused by the agent gate and the backend is
   untouched.
6. **AC6 (one engagement state):** The registry handed to `poc.run` is built from
   an `L4Language` over the **same** `Arc<L4Guard>` and `Arc<dyn L4FlowStore>`
   passed in `Features::l4_shared` (and thus owned by the `l4.*` command module).
   Observable: a test constructs the assembly with one shared guard whose
   `allow_agent_*` flag drives AC3/AC4 — the `poc.run` gate honours the same
   guard the command module was built over.
7. **AC7 (scope discipline):** The diff changes only
   `crates/aitm-poc/src/runner.rs`, `crates/aitm/src/wire.rs`,
   `crates/aitm/src/main.rs`, and test/fixture files. `L4StepHandler`,
   `L4Language`'s gate logic, the rhai host-fn face, and the `l4.*` command module
   are unchanged; no `l4:` verb is added; no shared language definition changes.
8. **AC8 (gate):**
   `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
   passes. (`node --test docs/design/languages/` only if a shared def changes —
   not expected.)
9. **AC9 (real-wire loopback, privilege-gated):** On Linux with
   `AITM_L4_TESTS=1`, an `#[ignore]`d test runs an `l4:` `send_recv` step over a
   real scoped loopback through the fully assembled `poc.run` and observes the
   stimulus actually injected on the wire (skips cleanly on `L4Unavailable`). Run
   via the Terminal panel.

## Left to the builder

- Exact test-file names, helper/fixture layout, and whether the recording backend
  is duplicated per test file (matching the existing per-file `MockBackend`
  convention in `tests/language.rs`) or shared.
- Whether to also expose a steps-only `aitm-poc` registration path
  (`register_with_steps`) for a future deployment that runs `poc.run` with the L4
  native handler but **without** the rhai tier. Not a current production path
  (the binary always builds the tier); add only if trivial and it keeps the L4
  PoC-step face independent of Rhai. If skipped, say so in the plan's Shipped
  notes.
- The precise `l4:` PoC fixture body (`op`, packet layers, `dst`, `interface`,
  `success` assertion) — any valid `send_recv`/`inject` step to a scoped loopback
  target, mirroring the SYN/`synack_reply` fixture in `tests/language.rs`.
- Whether the hermetic production-assembly test lives in `crates/aitm/tests/` (it
  can drive `assemble_with_scripts` and inject a recording backend through the
  `ScriptWiring.poc_step_handlers` registry) and whether a second runner-level
  test lives in `crates/aitm-proto-l4/tests/` for a clean positive verdict via a
  stub `ProxyClient` that anchors the finding.

## Open questions — RESOLVED

1. **l4-only PoC verdict — DECIDED: keep the HTTP finding-anchor contract
   unchanged; out of scope here.** An `l4:` step composes with an `http:` anchor
   step exactly as a `script:` step does today. Making an l4-only PoC produce a
   verdict (no `http:` step) would be a separate spec; it does not block or change
   this wiring. The AC proofs therefore assert on the wire observable (recording
   backend) + error class, not on an overall l4-only verdict.

---

**Summary.** The `l4:` native PoC-step handler already exists and already gates on
`inputs.caller`; the runner already dispatches `Step::Protocol` and seeds the
caller from the `poc.run` frontend. The only missing wire is assembly:
`run_poc_command` never threads a `PocStepRegistry`, and `main.rs`/`wire.rs` never
hand it the L4 handler. This change threads the L4 step handler — built from the
live `L4Language` over the **same** shared `L4Guard`/`L4FlowStore` as the rhai
face and the command module — into production `poc.run`, so an `l4:` step gates on
live per-call trust (operator runs; agent-gate-off refused with nothing on the
wire; agent-gate-on runs; unseeded fail-closed). It touches only `runner.rs`,
`wire.rs`, `main.rs`, and tests; no gate logic, verbs, or catalog change.

**Architect's calls (approve or correct):**
1. Carry the `PocStepRegistry` on `ScriptedPocRunCommand` (the production variant),
   leaving `PocRunCommand` a unit struct; new
   `register_with_executor_and_steps` + `ScriptedPocRunCommand::with_steps`, with
   `register`/`register_with_executor` kept as empty-registry wrappers.
2. Build the registry in `main.rs` from the **same** live `l4_language` instance
   (before `drop(l4_language)`) so it shares the exact `L4Live` the rhai face uses;
   guard + store are the identical `Arc`s in `Features::l4_shared`; the backend is
   a fresh `PcapBackend` as every L4 face builds its own.
3. Fail-closed via the existing default: an unseeded `CommandHost`
   (`Frontend::Mcp` → `CallerTrust::Agent`) with the gate off is refused; no new
   fail-closed code.
4. Hermetic AC proofs assert on a recording `CaptureInjectBackend`
   (`injected()` empty vs. one) and on the error class ("disabled"/"inject" vs.
   "no handler registered"), since an l4-only PoC still ends at the HTTP
   finding-anchor error — the wire observable, not the overall verdict, is the
   security property. A real-wire positive is the privilege-gated loopback test.
5. Default on the open question: keep the HTTP finding-anchor contract; l4-only
   PoCs are not runnable to a verdict (out of scope).
