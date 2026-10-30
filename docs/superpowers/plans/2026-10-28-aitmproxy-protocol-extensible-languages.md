# Protocol-extensible scripting & PoC languages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one `ProtocolLanguage` seam so any protocol crate contributes its Rhai host namespace, a native PoC step, and its completion catalog with no edit to `aitm-plugin-rhai` or `aitm-poc` — and make L4 the first consumer.

**Architecture:** New seam traits (`ProtocolLanguage`, `ScriptHostRegistry`, `PocStepHandler`, `NamespaceCatalog`) exposed via `aitm-plugin` re-exports. `aitm-plugin-rhai` lets a protocol crate inject `<ns>.*` host fns (each `Guarded`); `aitm-poc` gains one additive `Step::Protocol { ns, body }` arm dispatched to the registered handler by `ns`. Catalogs assemble the shared `docs/design/languages/*.json`. Existing `http`/`browser`/`store`/`scope` migrate onto the seam incrementally.

**Tech Stack:** Rust (`aitm-plugin`, `aitm-plugin-rhai`, `aitm-poc`, `aitm-proto-l4`), `rhai`; the shared JSON defs + the node drift-guard.

**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-protocol-extensible-languages-design.md`

**Branch / worktree:** `feat/proto-languages` (off `main`, which has `aitm-plugin-rhai`, `aitm-poc`, and the `docs/design/languages/` defs).

## Global Constraints

- **Adding a protocol edits no language crate.** A protocol's host fns + PoC step + catalog register from its own crate; `aitm-plugin-rhai`/`aitm-poc` are touched only to *provide* the seam, never per-protocol.
- **Guarded by construction.** Every registered effectful `<ns>.*` fn routes through that protocol's guard; the registry API makes an unguarded effectful registration fail to compile (`Guarded<_>` wrapper).
- **Human-readable.** Named `<ns>:` PoC steps; namespaced `<ns>.fn(...)` calls; YAML bodies hand-writable.
- **One vocabulary.** A protocol's verb names are identical in a Rhai script and its PoC step/`script` body (shared catalog).
- **Additive, semver-aware.** `Step::Protocol` is `#[non_exhaustive]`-additive; each namespace declares an `api_version`.
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

## Review Focus

- **Namespace name collision** (two crates register `l4`) → a clear registration error, not last-wins. (Task 2)
- **A protocol fn that forgets its guard** → must fail to compile (type-level), not run unguarded. (Task 2)
- **Unknown `<ns>:` PoC step** (no registered handler) → clear error at parse/run, never a silent skip. (Task 3)
- **Catalog clash** — two namespaces with a same-named fn must stay namespaced, no overwrite. (Task 4)
- **`api_version` mismatch** — a script/PoC targeting a wrong namespace version is warned/refused, not silently run. (Task 7)

---

## Tasks

### Task 1: Seam traits + a test protocol crate

**Files:** Create `crates/aitm-plugin/src/language.rs` (traits), re-export from `aitm-plugin`; create `crates/aitm-proto-test/` (a minimal test protocol crate used by later ACs); Test: `crates/aitm-plugin/tests/language.rs`.
**Interfaces:** Produces `trait ProtocolLanguage { namespace(); api_version(); register_host_fns(&mut ScriptHostRegistry); poc_step() -> Option<Box<dyn PocStepHandler>>; catalog() -> NamespaceCatalog }`; the registry/handler/catalog types as `not implemented` skeletons with exact signatures.

- [ ] Step 1: write the trait module with signatures + doc comments, bodies `unimplemented!()`; a test that the test crate's `impl ProtocolLanguage` type-checks and reports `namespace()=="test"`.
- [ ] Step 2: run — FAIL (traits absent). Step 3: define the traits + skeletons + the test crate stub. Step 4: run — PASS; gate. Step 5: commit.

### Task 2: `ScriptHostRegistry` in `aitm-plugin-rhai` + `Guarded` wrapper

**Files:** Modify `crates/aitm-plugin-rhai/src/engine.rs` / a new `src/host_registry.rs`; Test: `crates/aitm-plugin-rhai/tests/host_registry.rs`.
**Interfaces:** Consumes Task 1 traits. Produces `ScriptHostRegistry::register(ns, name, Guarded<Fn>)`; the engine calls each registered `ProtocolLanguage::register_host_fns`. `Guarded<F>` wraps a fn with its guard handle so an effectful registration without a guard does not type-check.

- [ ] Step 1: failing tests — the test crate registers `test.ping()` and a Rhai script calls it with **no edit to `aitm-plugin-rhai`** (AC1); a guarded `test.effect()` is refused when its guard refuses (AC2); registering `test` twice errors (Review Focus); an attempt to register an effectful fn without a `Guarded` wrapper fails to compile (a `trybuild`/doc-test).
- [ ] Step 2: run — FAIL. Step 3: implement the registry + `Guarded`; wire the engine to drive `register_host_fns` for each registered language. Step 4: PASS; gate. Step 5: commit.

### Task 3: `Step::Protocol` + `PocStepHandler` in `aitm-poc`

**Files:** Modify `crates/aitm-poc/src/model.rs` (`Step::Protocol { ns, body }`), `src/runner.rs` (dispatch by `ns` to a registered `PocStepHandler`), a handler registry; Test: `crates/aitm-poc/tests/protocol_step.rs`.
**Interfaces:** Consumes Task 1 `PocStepHandler`. Produces the additive `Step::Protocol` arm + runner dispatch; the handler parses its own `body` (`serde_yaml::Value`) and contributes matcher/extractor sources.

- [ ] Step 1: failing tests — a PoC with a `test:` step round-trips (YAML↔model) and runs its verb via the test handler with **no edit to the fixed `http`/`browser`/`extract`/`script` steps** (AC3); an unknown `<ns>:` step (no handler) errors clearly (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement the arm + dispatch + handler registry. Step 4: PASS; gate. Step 5: commit.

### Task 4: `NamespaceCatalog` assembly + drift-guard extension

**Files:** Create a small assembler (build step or test-time) that concatenates each registered `NamespaceCatalog` into the shape of `docs/design/languages/rhai.api.json` (`namespaces` map) and `poc-yaml.schema.json` (per-`<ns>:` step schema); extend `crates/aitm-plugin-rhai/tests/api_catalog.rs` (the drift-guard) to assert every registered namespace is present. Test: that test + `docs/design/languages/validate.test.mjs`.
**Interfaces:** Consumes Task 1 `catalog()`. Produces the per-protocol `namespaces` structure in the defs; the drift-guard covers namespaces.

- [ ] Step 1: failing tests — registering the test namespace adds its fns + `test:` step to the assembled defs without hand-editing them (AC6); the drift-guard fails if a registered namespace is missing from the catalog and passes for `http`/`browser`/`l4`/`test` (AC7); two namespaces with a same-named fn stay namespaced (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement the assembler + guard extension; update `rhai.api.json`/`poc-yaml.schema.json` to the `namespaces` shape. Step 4: PASS; gate + `node --test`. Step 5: commit.

### Task 5: Migrate `http`/`browser`/`store`/`scope` onto the seam (incremental)

**Files:** Modify `crates/aitm-plugin-rhai/src/{host_net,host_core,prelude}.rs` to register these namespaces via `ScriptHostRegistry` instead of ad-hoc injection; Test: existing `tests/host_net.rs`/`tests/host_core.rs` keep passing + a test that they now appear in `script.list`-style catalog.
**Interfaces:** No behaviour change; they become three worked examples of the seam.

- [ ] Step 1: failing/guard test — the existing host-fn behaviour is unchanged after migration (run the existing suites); the three namespaces appear in the assembled catalog.
- [ ] Step 2: run — FAIL (if any registration path changed signature). Step 3: move each onto the registry, one namespace per commit. Step 4: PASS; gate. Step 5: commit (one per namespace).

### Task 6: L4 as the first new consumer (coordinate with M5)

**Files:** Modify `crates/aitm-proto-l4/` to `impl ProtocolLanguage` — `register_host_fns` adds `l4.*` (each `L4Guard`-wrapped), `poc_step` returns the native `l4:` handler, `catalog` describes both + the `packet` matcher/extractor source; Test: `crates/aitm-proto-l4/tests/language.rs`.
**Depends on:** M5's `l4.*` verbs + `L4Guard` on `main` (M5 in flight). **Coordinate:** M5 should register `l4.*` through this seam rather than in-crate in `aitm-plugin-rhai` (flagged to the M5 sessions).
**Interfaces:** Consumes Tasks 2–4. Produces L4 first-class in both languages.
**Shipped scope (ratified 2026-10-29, PR #48):** the **one-shot** verbs only — `l4.interfaces`, `l4.craft`, `l4.scope.add`/`remove`/`list`, `l4.flow.list`/`get`, `l4.inject`, `l4.send_recv` (the AC4/5/8 reproduction workflow). The **stateful** `l4.capture.*`/`l4.intercept.*` session verbs are a tracked follow-up pending a session-scripting interaction model; `l4.agent.set` is operator-only and intentionally not a script verb. Gating mirrors the `l4.*` command path over the shared `L4Guard::agent_gates()` + `L4Guard` check (the sanctioned fallback, since script host fns carry no `CommandHost`). **Catalogued-only:** l4 ships in the catalog + is gate-proven in tests, but is NOT wired onto the live production (shared-across-frontends) engine; live use is a tracked follow-up ("L4 live scripting wiring") whose crux is deriving the gate decision from the per-invocation `Frontend` rather than the build-time `agent_sourced` bool.

- [ ] Step 1: failing tests — `l4.*` reachable in a Rhai script via the seam, each `L4Guard`-gated (AC4); the `l4:` step example from the spec round-trips and runs `send_recv` + a `packet` extractor + a `dsl` success against a scoped loopback target, refused when out of scope (AC5); the `l4.*` verb names are identical in script and `l4:` step (AC8, shared catalog).
- [ ] Step 2: run — FAIL. Step 3: implement the L4 `ProtocolLanguage` impl + `l4:` handler + packet source. Step 4: PASS; gate (loopback/privilege tests via the Terminal panel per CLAUDE.md). Step 5: commit.

### Task 7: Per-namespace `api_version`

**Files:** Modify the seam + the validate/load paths so a namespace's `api_version` is recorded and a script/PoC targeting a mismatched version is warned/refused per the script-tier `API` policy; Test: `crates/aitm-plugin-rhai/tests/host_registry.rs`.
**Interfaces:** Consumes Task 2. Produces versioned namespaces.

- [ ] Step 1: failing test — a namespace exposes `api_version`; a mismatched target is warned/refused (AC9); the default (matching) runs. Step 2: run — FAIL. Step 3: implement. Step 4: PASS; gate. Step 5: commit.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
