# Rhai script constants in hooks implementation plan

**Status:** approved (2026-10-31, self-approved under Matt's autonomous-operation mandate)
**Spec:** `docs/superpowers/specs/2026-10-31-rhai-script-constants-in-hooks-design.md`
**Branch / worktree:** `claude/compassionate-dewdney-773b0a` (session worktree `.claude/worktrees/compassionate-dewdney-773b0a`)

## Overview

Land the failing startup-equivalent test first (Task 1), then the loader fix
(Task 2) and the three script rewrites (Task 3), which together turn it green,
then the docs (Task 4). Tasks 2, 3 and 4 touch disjoint files and may run in
parallel once Task 1 is red. Task 5 is the live verification on both builds,
the gate and the panel. This is an orchestrator-dispatched bug fix done inside
one session; the implementation is written in-session with the mechanism
already pinned to rhai source lines, and the independent check is the
three-reviewer panel.

## Tasks

### Task 1: startup-equivalent catalogue test (red first)

- **Satisfies:** AC9 (red half), AC8 (observation path)
- **Depends on:** none
- **Files:** `crates/aitm/tests/bundled_startup.rs` (create)
- **Change:** a `#[tokio::test(flavor = "multi_thread")]` per configuration
  (`l4_off`, `l4_on`) sharing a helper that: builds `RhaiConfig::default()`,
  calls `aitm::bundled::apply(&mut cfg, lookup)` with `lookup` answering
  `AITM_BUNDLED_SCRIPTS` = `<CARGO_MANIFEST_DIR>/../../scripts/bundled`;
  builds `ScriptServices` from `aitm::scripts::LateHandles::new()` exactly as
  `main.rs` does; builds the tier with
  `aitm_plugin_rhai::wire::build_with_languages(cfg, services, &languages)`
  where `languages` is empty (off) or one `aitm_proto_l4::L4Language` over
  `L4Guard::new(&L4Config { enabled: true, .. })`, `PcapBackend::new()`,
  `InMemoryL4FlowStore::new()` (on); runs `tier.host.load(&mut
  Registry::new())`; collects `tier.error_sink.last_error(name)` for every
  `tier.host.set().names()`.
- **Test:** `every_bundled_script_loads_like_startup_l4_off` /
  `_l4_on`: `tier.errors` is empty; loaded names count equals the `.rhai`
  file count on disk (49 today); the per-script error list is empty (the
  assertion message lists each `name: error`); the registry has every
  command the `active/` and `l4/` scripts register (`check.sqli`,
  `l4.recon`, … — 18 names, pinned as a literal list).
- **Done when:** the test compiles and fails on current `main` listing
  exactly the 7 scripts, with `Variable not found: …` for each (the red
  evidence in the PR), and passes after Tasks 2 and 3.

### Task 2: pin the optimizer, resolve literal constants inside functions

- **Satisfies:** AC2, AC3, AC4, AC5, AC6, AC7, AC8, AC11
- **Depends on:** none (Task 1 red is the evidence, not a dependency)
- **Files:** `crates/aitm-plugin-rhai/src/engine.rs` (modify),
  `crates/aitm-plugin-rhai/src/loader.rs` (modify),
  `crates/aitm-plugin-rhai/src/plugin.rs` (modify),
  `crates/aitm-plugin-rhai/src/command.rs` (modify),
  `crates/aitm-plugin-rhai/src/poc_step.rs` (modify),
  `crates/aitm-plugin-rhai/tests/engine.rs` (modify),
  `crates/aitm-plugin-rhai/tests/loader.rs` (modify)
- **Change:**
  - `build_engine`: `engine.set_optimization_level(OptimizationLevel::Simple)`.
  - `engine.rs`: `pub struct ScriptConstants(BTreeMap<String, Dynamic>)`
    with `pub fn of(ast: &AST) -> Self` (from
    `ast.iter_literal_variables(true, false)`); a thread-local
    `CONSTANTS: RefCell<Option<Arc<ScriptConstants>>>`;
    `pub fn enter_constants(ast: &AST) -> ConstantsGuard` (installs, the
    guard restores the previous table on drop); `fn script_constant(name:
    &str, index: usize) -> Option<Dynamic>` (`None` when `index != 0` or the
    name is not in the table); `fn install_constant_resolver(engine)` calling
    `engine.on_var(|name, index, _| Ok(script_constant(name, index)))`
    (under `#[allow(deprecated)]`: rhai flags `on_var` volatile, not
    deprecated), called from `build_engine`.
  - `plugin.rs` `call_hook`, `command.rs` `ScriptRegHandle::run_load` and
    `ScriptCommand::invoke`, `poc_step.rs` `run`: `let _constants =
    enter_constants(&ast);` beside the existing `begin_run`/seed guards.
  - `plugin.rs` `RhaiPlugin::run_load`: on `Err`, also
    `self.errors.record(&self.meta.name, err.to_string())`.
  - `loader.rs` `api_satisfies`: compare dotted integer versions
    component-wise via `fn version_parts(&str) -> Option<Vec<u32>>`, padding
    the shorter with zeros; non-numeric still exact-match (D7).
- **Test:** in `tests/loader.rs`:
  `top_level_const_is_visible_in_hooks_and_closures` (AC2, AC3, AC4) — a
  script with `const TAG = "v"`, `const PATHS = ["/a", "/b", "/c"]`, an
  `on_request` that sets header `X-Tag` to `TAG`, `X-N` to `PATHS.len()`
  and `X-Has` to `PATHS.contains("/b")`, and a `load(reg)` registering
  `probe.tag` that returns `TAG`; after `dispatch`, `X-Tag == "v"`, `X-N ==
  "3"`, `X-Has == "true"`; after `ScriptHost::load`, invoking `probe.tag`
  returns `"v"`.
  `parameter_named_like_a_const_keeps_meaning_the_parameter` (AC5) — `const
  X = 1; fn pick(X) { X }` used from `on_request` → header `"2"`.
  In `tests/engine.rs`: `script_constants_resolve_inside_functions_while_entered`
  — `f` reading `K * x + WORDS.len()` fails with `Variable not found: K`
  bare and returns `16` under `enter_constants`; `g(K)` returns its argument.
  `computed_const_is_not_visible_in_functions` (AC6) — `const Z = [1,
  2].len();` → `on_request` reading `Z` records a `last_error` containing
  `Variable not found: Z`.
  `api_satisfies_compares_versions` gains the dotted cases (AC11).
  In `tests/engine.rs`: `optimization_level_is_pinned_to_simple` (AC7).
  In `tests/loader.rs`: `failed_load_is_the_scripts_last_error` (AC8) —
  `fn load(reg) { throw "boom"; }` through `ScriptHost::load` →
  `last_error` contains `"boom"`.
- **Done when:** those tests pass, the four `check-*` scripts in Task 1's
  test no longer appear in its failure list, and the full gate passes.

### Task 3: L4 scripts resolve `l4` at call time

- **Satisfies:** AC1 (l4 half), AC9
- **Depends on:** none
- **Files:** `scripts/bundled/l4/l4-recon.rhai`,
  `scripts/bundled/l4/l4-tcp-syn-probe.rhai`,
  `scripts/bundled/l4/l4-udp-probe.rhai` (modify)
- **Change:** move each `l4.*` call sequence into a named function
  (`fn recon()`, `fn tcp_probe(dst, port, interface, timeout)`,
  `fn udp_probe(dst, port, interface, timeout)`); the closure validates
  args, then `try { <fn>(…) } catch (e) { <existing message> }`. Behaviour
  and messages otherwise unchanged. Header comment states why.
- **Test:** Task 1's `l4_off` test (load succeeds without an `l4`
  namespace) and `l4_on` (loads with it).
- **Done when:** the three scripts no longer appear in Task 1's failure list.

### Task 4: document the rules

- **Satisfies:** AC10
- **Depends on:** none
- **Files:** `site/scripting.html` (modify, Hooks section),
  `scripts/bundled/README.md` (modify, "Writing your own")
- **Change:** one short paragraph (and a four-line example) stating: a
  top-level `const` with a literal value is visible inside hooks and
  `load(reg)` closures; a computed constant is not (compute it in a
  function); a closure captures every outer name when it is created, so an
  optional namespace (`l4`) must be called from a named function.
- **Test:** none (prose); the spec reviewer checks presence.
- **Done when:** both files carry the rules.

### Task 5: live verification, gate, panel

- **Satisfies:** AC1
- **Depends on:** Tasks 1-4
- **Files:** none
- **Change:** rebuild debug and release, start each on the minimal config,
  save `startup-{debug,release}-after.log` beside the before logs; run the
  Rust gate in the Terminal; run the three reviewers in parallel.
- **Test:** `grep -c "hook 'load' failed"` is 0 in both after logs.
- **Done when:** gate green, panel PASS, PR open with the excerpts.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

(filled at stage 7)
