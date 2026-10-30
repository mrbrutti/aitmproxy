# L4 `l4:` PoC-step wiring into production `poc.run` implementation plan

**Status:** Approved (orchestrator, on Matt's delegation, 2026-10-29) — live for Stage 4
**Spec:** `docs/superpowers/specs/2026-10-29-aitmproxy-l4-pocstep-wiring-design.md`
**Branch / worktree:** `feat/l4-pocstep-wiring` (cut from `origin/main` @ `59c9050`)

## Overview

Three sequential tasks. Task 1 threads a `PocStepRegistry` through the `poc.run`
command in `aitm-poc` (no L4 dependency — pure seam plumbing), proven by a
unit test with a fake handler. Task 2 builds the L4 step registry from the live
`L4Language` in the binary and threads it through `ScriptWiring` into `poc.run`,
proven by a hermetic production-assembly test with a recording backend covering
AC1–AC6. Task 3 adds the privilege-gated real-wire loopback proof (AC9) and runs
the full branch gate (AC7, AC8). The tasks are sequential (2 depends on 1, 3 on
2); none are independent. Every task is test-first.

## Tasks

### Task 1: thread `PocStepRegistry` through the `poc.run` command

- **Satisfies:** foundation for AC1, AC6, AC7 (no behaviour on its own; enables
  the wire).
- **Depends on:** none.
- **Files:** `crates/aitm-poc/src/runner.rs` (modify — command structs, free
  functions, `run_poc_command`, add `#[cfg(test)]` test).
- **Change:**
  - Add field `step_handlers: PocStepRegistry` to `struct ScriptedPocRunCommand`
    (import `crate::step_registry::PocStepRegistry`).
  - Keep `ScriptedPocRunCommand::new(executor: Arc<dyn ScriptStepExecutor>) -> Self`
    (sets `step_handlers: PocStepRegistry::new()`). Add
    `pub fn with_steps(executor: Arc<dyn ScriptStepExecutor>, step_handlers: PocStepRegistry) -> Self`.
  - Change the shared body signature to
    `fn run_poc_command(args: Params, host: &CommandHost, executor: Option<&Arc<dyn ScriptStepExecutor>>, step_handlers: &PocStepRegistry) -> anyhow::Result<Value>`;
    after the `with_script_executor` block add
    `if !step_handlers.is_empty() { runner = runner.with_step_handlers(step_handlers.clone()); }`.
  - Update the three call sites:
    `PocRunCommand::invoke` → `run_poc_command(args, host, None, &PocStepRegistry::new())`;
    `ScriptedPocRunCommand::invoke` →
    `run_poc_command(args, host, Some(&self.executor), &self.step_handlers)`.
  - Add
    `pub fn register_with_executor_and_steps(registry: &mut Registry, executor: Arc<dyn ScriptStepExecutor>, step_handlers: PocStepRegistry)`
    → `registry.add_command(Arc::new(ScriptedPocRunCommand::with_steps(executor, step_handlers)));`.
    Leave `register` and `register_with_executor` as-is (the latter now constructs
    a command with an empty registry via `ScriptedPocRunCommand::new`).
- **Test:** `#[cfg(test)] fn protocol_step_dispatches_through_registered_command`
  in `runner.rs`. Define a tiny `FakeStep` implementing
  `aitm_plugin::language::PocStepHandler` with `ns() == "fake"` whose `run`
  returns `PocStepOutcome { bindings: {"fake_ran": Value::Bool(true)}, .. }`.
  Build a `PocStepRegistry`, `register(Arc::new(FakeStep))`, call
  `register_with_executor_and_steps(&mut reg, <noop executor>, registry)`, then
  invoke the registered `poc.run` on a PoC whose only step is
  `Step::Protocol { ns: "fake", body: serde_yaml::Value::Null, extract: vec![] }`
  and whose `success` is `Assertion::Status(0)` (any valid tree), with a stub
  `CommandHost`. **Expected:** the invocation does **not** return the error
  containing `"no handler registered for protocol step `fake:`"` (the fake ran).
  If a stub `CommandHost`/executor is heavier than a unit test warrants, instead
  assert at the construction layer: `register_with_executor_and_steps` followed by
  `registry.command("poc.run").is_some()` **and** a direct
  `run_poc_command(..., &registry_with_fake)` (reusing the existing test harness
  pattern from `tests/protocol_step.rs`) dispatches to the fake — literal
  expected: the returned `Value::Object`'s `evaluated` does not contain the
  no-handler message. (Builder picks the lighter of the two that still proves the
  registry reaches `run_inner`.)
- **Done when:** the test passes and
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -p aitm-poc`
  passes.

### Task 2: build the L4 step registry and thread it from assembly

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6.
- **Depends on:** Task 1.
- **Files:**
  `crates/aitm/src/wire.rs` (modify — `ScriptWiring`, `PocCommands`,
  `assemble_with_scripts`),
  `crates/aitm/src/main.rs` (modify — build registry, thread into `ScriptWiring`),
  `crates/aitm/tests/l4_pocstep_wiring.rs` (create — hermetic e2e tests),
  optionally `crates/aitm/tests/fixtures/l4_send_recv.poc.yaml` (create — or write
  the YAML to a temp file in the test).
- **Change:**
  - `wire.rs`: add
    `pub poc_step_handlers: aitm_poc::step_registry::PocStepRegistry` to
    `struct ScriptWiring` (it already `#[derive(Default)]`, so callers using
    `..ScriptWiring::default()` compile unchanged). Add field
    `step_handlers: aitm_poc::step_registry::PocStepRegistry` to `struct PocCommands`.
    In `PocCommands::load`, when `self.executor` is `Some(exec)` call
    `aitm_poc::runner::register_with_executor_and_steps(reg, exec, self.step_handlers.clone())`
    instead of `register_with_executor`; the `None` arm stays
    `aitm_poc::runner::register(reg)`. In `assemble_with_scripts`, where
    `PocCommands { executor }` is constructed, add
    `step_handlers: scripts.poc_step_handlers` (move it in; `ScriptWiring` is
    consumed by value).
  - `main.rs`: just before `drop(l4_language)` (~line 218), build
    ```
    let poc_step_handlers = {
        let mut r = aitm_poc::step_registry::PocStepRegistry::new();
        if let Some(lang) = &l4_language {
            if let Some(h) = lang.poc_step() {
                r.register(std::sync::Arc::from(h));
            }
        }
        r
    };
    ```
    and add `poc_step_handlers,` to the `ScriptWiring { .. }` literal passed to
    `assemble_with_scripts`. (The guard + store inside `l4_language` are the same
    `Arc`s as `l4_shared.guard`/`l4_shared.store`, satisfying AC6.)
- **Test:** `crates/aitm/tests/l4_pocstep_wiring.rs`. Define a file-local
  recording `MockBackend: CaptureInjectBackend` (mirror the one in
  `aitm-proto-l4/tests/language.rs`: `inject` pushes to a `Mutex<Vec<Vec<u8>>>`;
  `open_capture` returns an empty source). Helper `assemble_l4_poc_run(allow_agent_inject: bool, backend: Arc<MockBackend>) -> (Proxy, Arc<L4Guard>, Arc<dyn L4FlowStore>)`
  that builds a loopback-scoped `L4Guard` (inject-out + capture-in on `lo`, the
  `entry(...)` fixture from `tests/language.rs`), an `InMemoryL4FlowStore`, a
  `PocStepRegistry` from
  `L4Language::new(guard.clone(), backend, store.clone()).poc_step()`, and calls
  `assemble_with_scripts(&cfg, &Features { l4: l4_enabled(), l4_shared: Some(L4Shared { guard, store }), ..Default::default() }, ScriptWiring { poc_step_handlers: registry, ..Default::default() })`.
  Write a fixture PoC with a single `l4: { op: send_recv, packet: { layers: [{ ipv4: { dst: "127.0.0.1" } }, { tcp: { dst_port: 80 } }] }, interface: "lo" }` step and a
  valid `success` tree, to a temp `.poc.yaml`. Fetch
  `proxy.registry().command("poc.run")` and `invoke` it with `Params` carrying the
  temp `poc_path`, over a `CommandHost` built from the proxy's services and the
  frontend under test. Four `#[test]`s (privilege-free — the gate/record are
  observable without raw privilege):
  - `operator_runs_l4_step`: `with_frontend(Frontend::Operator)`. **Expected:**
    `backend.injected().len() == 1` (the overall `invoke` may `Err` at the HTTP
    finding anchor — assert the error, if any, is **not** the "no handler" error
    and contains `"no HTTP flow"`, and assert the backend record). (AC1, AC2)
  - `agent_gate_off_refused_nothing_on_wire`: `with_frontend(Frontend::Mcp)`,
    `allow_agent_inject = false`. **Expected:** `invoke` returns `Err`; the message
    contains `"disabled"` and `"inject"` and does **not** contain
    `"no handler registered"`; `backend.injected().is_empty()`. (AC1, AC3)
  - `agent_gate_on_runs`: `with_frontend(Frontend::Mcp)`,
    `allow_agent_inject = true`. **Expected:** `backend.injected().len() == 1`.
    (AC4)
  - `unseeded_host_is_fail_closed`: `CommandHost` with **no** `with_frontend`
    (defaults to `Frontend::Mcp` → `CallerTrust::Agent`), `allow_agent_inject =
    false`. **Expected:** `invoke` returns `Err` naming the disabled inject gate;
    `backend.injected().is_empty()`. (AC5)
  AC6 is covered structurally: all four share one `L4Guard` whose
  `allow_agent_inject` flag drives the outcomes, and that same guard is what
  `Features::l4_shared` hands the command module.
- **Done when:** the four tests pass and
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -p aitm`
  passes.

### Task 3: privilege-gated real-wire loopback proof + full branch gate

- **Satisfies:** AC9, AC7, AC8.
- **Depends on:** Task 2.
- **Files:** `crates/aitm/tests/l4_pocstep_wiring.rs` (modify — add one `#[ignore]`
  test).
- **Change:** add
  `#[test] #[ignore = "needs raw L4 privilege + Linux loopback; run with AITM_L4_TESTS=1 via the Terminal panel"] fn operator_l4_step_injects_on_real_loopback()`.
  Gate the body on `!cfg!(target_os = "macos") && std::env::var("AITM_L4_TESTS") == Ok("1")`
  (else return early, as `active_roundtrip.rs` does); build the assembly with a
  **real** `PcapBackend` (i.e. the default assembly path, L4 enabled, no injected
  mock), run the fixture `l4:` `send_recv` PoC via `poc.run` with
  `Frontend::Operator` over a scoped loopback, and on an `L4Unavailable` error
  skip cleanly (`return`). **Expected (when it runs):** the invocation proceeds
  past the agent/scope gates (no "disabled"/"out of L4 scope"/"no handler" error);
  observe the real send_recv completing (a `no_response`/`response`
  `l4_outcome`), proving the stimulus reached the wire through the assembled
  `poc.run`.
- **Done when:** the `#[ignore]` test compiles and skips cleanly under
  `cargo test -p aitm` (sandbox), and the **full branch gate** passes:
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
  The real-wire test is additionally run once on Linux with `AITM_L4_TESTS=1` via
  the Terminal panel and its output recorded. Confirm the diff is limited to
  `runner.rs`, `wire.rs`, `main.rs`, and test/fixture files (AC7).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
