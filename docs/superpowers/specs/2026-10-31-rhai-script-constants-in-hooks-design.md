# Rhai script constants in hooks design

**Status:** approved (2026-10-31, self-approved under Matt's autonomous-operation mandate; orchestrator-dispatched bug fix)
**Research inputs:** rhai 1.27.0 source (`src/optimizer.rs` 889-907 and 1386-1392, `src/parser.rs` 530-560 and 3875-3905, `src/eval/stmt.rs` 920-960, `src/engine.rs` 293); startup logs `startup-{debug,release}-before.log` in the side-session notes folder.

## Intent

Seven of the 49 bundled detection scripts fail their `load(reg)` hook at
startup on every build of `aitm` (debug and release alike, measured
2026-10-31): `check-sqli`, `check-ldap-injection`, `check-nosql-injection`,
`check-sensitive-paths` with `Variable not found: <CONST>`, and `l4-recon`,
`l4-tcp-syn-probe`, `l4-udp-probe` with `Variable not found: l4`. The
operator loses 7 of the 18 shipped commands and sees it only as log noise;
the catalogue's test never ran `load`, so nothing was red. We want every
bundled script to load cleanly, scripts written the natural way (a top-level
`const` read inside a hook) to work for third parties too, and a test that
mirrors startup so this class of break cannot ship again.

## Goals

- `aitm` started on a plain config (L4 disabled) and on an L4-enabled config
  logs no `hook 'load' failed` line; all 18 `check.*` / `l4.*` commands are
  registered.
- A script's top-level literal `const` is readable inside its hook functions
  and inside closures registered from `load(reg)`, without `global::`.
- A `load(reg)` failure is visible on the operator surface (`script.list`
  `last_error`), not only in the log.
- One test loads every file under `scripts/bundled/` exactly as `aitm` does at
  startup (same tier builder, same services shape, same engine configuration)
  and fails on any compile or load error.

## Non-goals

- Making an optional protocol namespace (`l4`) exist when its layer is
  disabled. Deny-by-default stays: no `l4.*` namespace without `l4.enabled`.
- Propagating non-literal constants (`const Z = f();`) into functions. Rhai
  can only fold literal values; a computed constant stays invisible to
  functions, and the guide says so.
- Changing `rhai.strict` to cover `load` failures.
- Changing the hook calling convention (hooks keep running with an empty
  `Scope`).

## Anti-goals

- A fix that depends on Rhai's *default* optimization level. The level the
  binary uses must be pinned in our code.
- A fix that changes the meaning of a function parameter or local that
  happens to share a name with a top-level constant.
- A stub `l4` namespace installed when L4 is off, to make the capture
  succeed. It would blur the one signal scripts have that the layer is off.
- `OptimizationLevel::Full`: it evaluates functions at compile time, which
  would run host calls outside any run context.

## Constraints

- No `internals` Rhai feature (M3 spec §7); only public `AST`/`Engine` API.
- One shared hardened engine; nothing here adds ambient authority or a
  global function.
- No new dependencies.
- Debug and release builds must behave identically (they already do: rhai
  1.27 constructs every engine at `OptimizationLevel::Simple`).

## Design

**Why it breaks (measured).** Rhai functions cannot see script-level
variables. A closure captures every outer name it mentions *when it is
created*: the parser turns `|args| { … SQL_ERR … }` into an anonymous
function whose leading parameters are those names, created by evaluating
`Share(SQL_ERR); curry(fn, SQL_ERR)` in the enclosing scope. Inside
`load(reg)` that scope holds only `reg`, so the lookup raises
`Variable not found` during `load`, before any `try` inside the closure
runs. The optimizer at `Simple` can fold a *literal* constant into function
bodies and drop it from `Share` (optimizer.rs 897-907, 1388-1392), but it
only knows constants from the engine's global modules and from the `Scope`
handed to `compile_with_scope`/`optimize_ast` (1458-1476); a script's own
top-level `const`s are never in that set because the loader calls
`engine.compile(src)`. `l4` is a global-module constant only while the L4
language is installed (`l4.enabled`), so on a plain config the same capture
fails for it. The existing catalogue test compiles every script and runs the
passive hooks; it never runs `load`, and `LoadedScript::run_load` only logs a
failure.

**D1. Pin the optimization level.** `engine::build_engine` calls
`set_optimization_level(OptimizationLevel::Simple)`, rhai's default today.
Pinning it makes "a debug core and a release core compile a script
identically" a property of our engine rather than of a dependency's default.
Never `Full` (anti-goal). This is determinism only; D2 does not depend on
the optimizer.

**D2. A variable resolver answers a script's literal constants inside its
functions.** `engine::ScriptConstants::of(&ast)` reads the top-level
literal constants (`ast.iter_literal_variables(true, false)`: `const`s whose
value is a string, number, bool, char, unit, or an array/map of literals)
into a table. `engine::enter_constants(&ast)` installs that table in a
thread-local for the duration of a run (a guard restores the previous one),
and every dispatcher opens it around its evaluation: `LoadedScript::call_hook`,
`ScriptRegHandle::run_load`, `ScriptCommand::invoke`, and the PoC step
executor. `build_engine` registers an `on_var` resolver that, for a name the
parser could not bind to a local slot (`index == 0`), returns the current
table's value when the name is a constant, and `None` otherwise so Rhai's own
lookup proceeds (scope, global constants such as `http`, function pointers).
A parameter or `let` of the same name has a slot and wins; a name a closure
captured is read unindexed inside the closure body but is then a parameter
in the live scope, so the resolver also returns `None` for any name the
scope already contains. Shadowing is therefore unchanged in every shape and
no warning is needed. Rhai hands a resolver's answer back read-only, so a
mutating method on the constant inside a function is refused (`cannot be
called on constant`), as at top level; the guide says to copy it first. The resolver also covers closure
creation: `curry(fn, SQL_ERR)` resolves through it, and Rhai skips a
resolver-provided name in the capture's `Share` step (it cannot be made
shared), so `load(reg)` closures work too. Why not the optimizer: rhai's
`optimize_ast` folds a scope constant only where it is a plain value and
never as a method or index receiver (`PATHS.len()`, `MAP.key`) inside a
named function, so the natural style would still break there. Why not
`global::`: it is a different spelling, which is what the bug report is
about. **(Architect's call)** the table is rebuilt per run from the AST (a
handful of top-level statements, already re-evaluated by Rhai on each
`call_fn` with `eval_ast`); a cached table can come later if a profile asks
for it.

**D3. A failed `load(reg)` is recorded.** `LoadedScript::run_load` records the
error in the script's `ErrorSink` (the same `record` a failed hook uses), so
`script.list` reports it as `last_error` and a test can observe it. The
log line stays.

**D4. The L4 scripts resolve `l4` at call time.** Each of the three moves
its `l4.*` calls into a named top-level function and keeps the `try/catch`
in the command closure. Inside a named function `l4` is looked up when the
function runs (scope, then the engine's global modules), so with L4 off the
command answers its "is the L4 layer enabled?" message instead of failing
at load; with L4 on it works unchanged. The rule for authors: *a closure
captures every outer name when it is created; call an optional namespace
from a named function.*

**D5. Startup-equivalent test.** `crates/aitm/tests/bundled_startup.rs`
discovers the catalogue through `aitm::bundled::apply` (the real discovery,
with `AITM_BUNDLED_SCRIPTS` injected to the repo's `scripts/bundled`), builds
`ScriptServices` from `LateHandles` as `main` does, builds the tier with
`aitm_plugin_rhai::wire::build_with_languages` once with no languages (L4
off, the plain-config path) and once with a real `L4Language` (L4 on), runs
the host's `load` over a fresh `Registry`, and asserts: zero compile errors,
loaded count equals the number of `.rhai` files on disk, zero `last_error`
across every script, and every `check.*` / `l4.*` command present in the
registry.

**D6. Documentation.** The published scripting guide (`site/scripting.html`,
Hooks section) and the catalogue's "Writing your own" section state the two
rules: literal top-level constants are visible in hooks and closures
(computed ones are not); closures capture at creation, so call an optional
namespace from a named function.

**D7. The version gate reads dotted versions.** Found by D5's L4-on run:
`api_satisfies` compared only plain integers and fell back to exact string
match, so the L4 namespace's `api_version` `"0.1.0"` refused every API-`"1"`
script (all 49 bundled ones, and any M3 script) the moment `l4.enabled` was
set. The gate now compares dotted integer versions component by component
with missing components as zero (`"1"` ≥ `"0.1.0"`, `"1"` < `"1.1"`); a
version that is not dotted integers still has to match exactly
(deny-by-default for an unrecognized string). The seam spec calls
`api_version` "semver-ish, like script `const API`", and this is the numeric
rule extended to that shape. **(Architect's call)** fix the comparison rather
than relabel L4 to `"1"`: the catalogue and drift guard advertise `"0.1.0"`.

## Acceptance criteria

1. AC1: `target/debug/aitm` and `target/release/aitm` started on a plain
   config log zero `hook 'load' failed` lines (before: 7 each).
2. AC2: a script `const X = "v"; fn on_request(flow) { … X … }` loaded through
   `RhaiLoader::load_one` and dispatched through `LoadedScript::dispatch`
   observes `"v"` (hooks run with an empty `Scope`).
3. AC3: a `load(reg)` closure that reads a top-level `const` loads without
   error and, invoked as a command, returns the constant's literal value.
4. AC4: a top-level `const` array literal works inside a function as a method
   receiver (`PATHS.len()` is the literal count, `PATHS.contains("/b")` is
   true).
5. AC5: `const X = 1; fn f(X) { X }` keeps `f(2) == 2`, and a local or
   parameter a closure captures still shadows it (`fn g() { let X = 5; let c
   = || X; c.call() }` is 5, `fn h(X) { let c = || X; c.call() }` with 7 is
   7); a mutating method on a constant inside a function is refused and the
   constant is unchanged afterwards.
6. AC6: a non-literal `const` is not visible inside a function; the hook fails
   with the plain `Variable not found` error (the documented limit).
7. AC7: `build_engine(..).optimization_level()` is `OptimizationLevel::Simple`.
8. AC8: a script whose `load(reg)` throws has that error as its `ErrorSink`
   `last_error` after `ScriptHost::load`.
9. AC9: the startup-equivalent test (D5) passes with L4 off and L4 on, and
   fails when any bundled script's `load` fails (demonstrated red before D2
   and D4 land).
10. AC10: the scripting guide and the catalogue README state the two rules.
11. AC11: `api_satisfies("1", "0.1.0")` is true, `api_satisfies("0.1.0", "1")`
    and `api_satisfies("1", "1.1")` are false, `api_satisfies("beta", "1")`
    stays false; the startup-equivalent test's L4-on run compiles all 49.

## Left to the builder

- Exact wording of the doc paragraphs in D6.
- Whether the three L4 scripts share one helper shape or each keep a
  function named for the command.
- Test file layout inside `crates/aitm-plugin-rhai/tests/` for AC2-AC8.

## Open questions

None.
