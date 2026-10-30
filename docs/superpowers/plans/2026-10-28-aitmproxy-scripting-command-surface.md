# Scripting command surface (F8a–F8c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the additive `aitm-plugin-rhai` commands the UI "add a plugin" panel needs — `script.list`, `script.validate{source}` + `script.save`, `script.enable`/`disable` — plus the agent gate and the `rhai.api.json` drift-guard.

**Architecture:** All new commands register through the existing `ScriptCommands` plugin (`crates/aitm-plugin-rhai/src/commands.rs`). `ScriptHandle` gains a readable `meta()` and an `enabled` flag; `RhaiLoader` gains `validate_source`. No `aitm-core` edits. Agent gating reuses M4's `sensitivity()` + `AgentPolicy` + the `scripts.allow_agent_authoring` flag.

**Tech Stack:** Rust, `aitm-plugin-rhai`, `rhai`; config in `crates/aitm`; node test for the catalog guard.

**Spec:** `docs/superpowers/specs/2026-10-28-aitmproxy-scripting-command-surface-design.md`

**Branch / worktree:** `feat/scripting-cmds` (off `main`, which has shipped `aitm-plugin-rhai` + the `docs/design/languages/` defs).

## Global Constraints

- Additive to `aitm-plugin-rhai`; **no `aitm-core` edits**. New capability = a new `Command` registered in `ScriptCommands::load`.
- Writes confined to the configured `scripts_dir`; `.rhai`-only; path-traversal rejected (as `poc.dir` confines).
- Sandbox unchanged; authoring does not widen it.
- Agent gating: `sensitivity()` = `Sensitive` for `save`/`reload`/`enable`/`disable`, `Read` for `list`/`validate`; gate = AgentPolicy (All/Ask permit Sensitive; **Auto never**) **AND** `scripts.allow_agent_authoring` (`Option<bool>`, default `false`); `Operator` never gated. (M4 spec D2/D4.)
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (Terminal panel for port-binding tests per CLAUDE.md).

## Review Focus

- **Overwrite-save** (`script.save` of an already-loaded script name) must swap the handle's hooks, not double-register or leak the old AST. (Task 4)
- **`source` over the sandbox `max_string_size`** must fail cleanly, not panic. (Task 3)
- **`validate` with both `path` and `source`, or neither** → a clear argument error, not a silent pick. (Task 3)
- **Stale `last_error`** — a script that errored, was fixed, and re-validated should not keep reporting the old error. (Task 2)
- **`disable` twice / `enable` an already-enabled script** → idempotent, no error. (Task 5)

---

## Tasks

### Task 1: `ScriptHandle` — readable meta + enabled flag

**Files:** Modify `crates/aitm-plugin-rhai/src/plugin.rs`; Test: `crates/aitm-plugin-rhai/tests/plugin.rs`.
**Interfaces:**
- Produces: `ScriptHandle::meta() -> &ScriptMeta` (expose `api`/`hooks`); `ScriptHandle::is_enabled() -> bool`, `set_enabled(bool)` backed by `AtomicBool` (default true); the `ScriptPlugin` hook dispatch skips a handle whose `is_enabled()` is false.

- [ ] Step 1: failing test — a `ScriptHandle` with `set_enabled(false)` does not fire its `on_request` hook against a dispatch; `meta()` returns the parsed api/hooks.
- [ ] Step 2: run — FAIL (`is_enabled`/`meta` absent).
- [ ] Step 3: add the `AtomicBool` + accessors; gate the hook dispatch on `is_enabled()`.
- [ ] Step 4: run — PASS; cargo gate.
- [ ] Step 5: commit.

### Task 2: F8a — `script.list {}`

**Files:** Modify `crates/aitm-plugin-rhai/src/commands.rs` (add `List` command + register in `ScriptCommands::load`); Test: `tests/commands.rs`.
**Interfaces:** Consumes Task 1 `meta()`/`is_enabled()` and the existing `ErrorSink`. Produces `script.list` → `[{name, path, api, hooks, enabled, last_error}]` (chain order).

- [ ] Step 1: failing test — two loaded scripts list with correct fields, `enabled:true`, `last_error:null`; a script whose hook raised reports its message in `last_error`; after a successful re-validate the stale error clears (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement `List` (`sensitivity()=Read`, agent-safe), reading handles + a per-script `ErrorSink` lookup. Step 4: PASS; gate. Step 5: commit.

### Task 3: F8b-1 — `RhaiLoader::validate_source` + `script.validate{source}` + `registers`

**Files:** Modify `crates/aitm-plugin-rhai/src/loader.rs` (`validate_source`, extend `extract_meta` with `registers`), `src/commands.rs` (`Validate` gains the `source` arm + `registers` in the result); Test: `tests/loader.rs`, `tests/commands.rs`.
**Interfaces:** Produces `RhaiLoader::validate_source(&self, source:&str) -> Result<ScriptMeta, ScriptError>`; `ScriptMeta` (or a validate-result struct) gains `registers:{commands:[String],options:[String]}`; `script.validate` accepts exactly one of `path`/`source`.

- [ ] Step 1: failing tests — `validate_source` compiles a valid string → meta; a syntax error → positioned `ScriptError`; `registers` lists `reg.add_command`/`add_option` names for a registering script, empty for a hook-only one; `script.validate` with both/neither of `path`/`source` errors; a `source` over `max_string_size` errors cleanly (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement (compile string on the shared engine; static AST scan for the two register calls, best-effort/empty-when-undeterminable). Step 4: PASS; gate. Step 5: commit.

### Task 4: F8b-2 — `scripts_dir` config + `script.save`

**Files:** Modify `crates/aitm-plugin-rhai/src/config.rs` (`RhaiConfig.scripts_dir: Option<PathBuf>`), `crates/aitm/src/config_file.rs` (surface it), `src/commands.rs` (`Save` command); Test: `tests/commands.rs`, `crates/aitm/tests/config_rhai.rs`.
**Interfaces:** Consumes Task 3 `validate_source` + Task 1 handle set. Produces `script.save {name, source, enable?}` → `{name, path, api, hooks, registers, restart_required}`; writes `<scripts_dir>/<name>.rhai`. **Overwrite of a loaded script** recompiles and `handle.swap`s it live; a **new name** is compiled into a `LoadedScript` and appended to the live `ScriptHost` set, so its hooks run this session with **no restart** (and `crates/aitm/src/config_file.rs` appends `scripts_dir/*.rhai` as enabled entries so it also loads next start). `restart_required` is `true` only if the script registers commands/options (the command/option `Registry` is sealed).

> **Dispatch-model note (delivered after F8's base, stacked PR):** the live-append on the new-name path is enabled by the dynamic `ScriptHost` — one plugin owning an `ArcSwap` set of `LoadedScript`s, replacing the per-script sealed plugin chain. **Option B supersedes** the interim Option A (new-name save returns `restart_required: true`, hooks join next start) that F8's base shipped. Hooks now go live for a new name too; only commands/options still need a restart.

- [ ] Step 1: failing tests — a **new-name** save writes the file and its `on_request` runs this session with **no restart** (`restart_required: false` for a hook-only script); an overwrite-save of a loaded script swaps its `on_request` live with no restart; a non-compiling `source` returns the error and writes **no file**; a `name` with `/`/`..` is rejected before any write; no `scripts_dir` → clear refusal; overwriting a loaded name swaps hooks (no double-register, Review Focus); the config scan appends `scripts_dir/*.rhai` once, deduped against declared entries; a command-registering script (new name **or** overwrite) returns `restart_required:true` while its hooks still go live.
- [ ] Step 2: run — FAIL. Step 3: implement (`name` validated to `[A-Za-z0-9_-]+`; compile-before-write; overwrite swaps the handle, new name appends a `LoadedScript` to the live set; `restart_required` tracks `registers`). `sensitivity()=Sensitive`. Step 4: PASS; gate. Step 5: commit.

### Task 5: F8c — `script.enable` / `script.disable`

**Files:** Modify `src/commands.rs` (`Enable`/`Disable`); Test: `tests/commands.rs`.
**Interfaces:** Consumes Task 1 `set_enabled`. Produces `script.enable{name}` / `script.disable{name}` → `{name, enabled}`.

- [ ] Step 1: failing tests — `disable` stops the script's mutation applying; `enable` restores it; unknown name → the `script.reload`-style "loaded: …" error; `disable` twice is idempotent (Review Focus).
- [ ] Step 2: run — FAIL. Step 3: implement (`sensitivity()=Sensitive`). Step 4: PASS; gate. Step 5: commit.

### Task 6: Agent gating — `scripts.allow_agent_authoring` + two-dimension enforcement

**Files:** Modify `crates/aitm/src/config_file.rs` (+ `aitm-plugin-rhai` `RhaiConfig`) for the flag; wire `sensitivity()` on the five commands and the gate check in each `Sensitive` command's `invoke`; Test: `tests/commands.rs` (gating matrix).
**Depends on:** M4 Task 1 (`Sensitivity`) + Task 2 (`Frontend::Operator`, `AgentPolicy`) being on `main`. **If not yet merged:** implement the flag + a local `Frontend::Cli`-vs-else check and leave a `// TODO(M4): use Sensitivity/AgentPolicy` seam, or sequence this task after the M4 merge (orchestrator's call).
**Interfaces:** Consumes the M4 identity/policy types. Produces the gate: `Sensitive` + non-`Operator`/`Cli` caller runs only when AgentPolicy permits Sensitive AND `scripts.allow_agent_authoring`.

- [ ] Step 1: failing tests (matrix) — default `Auto`: `Mcp` save/enable/disable refused regardless of flag; `All`+flag-on: allowed + audited; `All`+flag-off: refused naming the setting; `Read` (list/validate) allowed throughout; `Operator`/`Cli`: never gated.
- [ ] Step 2: run — FAIL. Step 3: implement flag + `sensitivity()` + gate. Step 4: PASS; gate. Step 5: commit.

### Task 7: `rhai.api.json` ↔ engine drift-guard

**Files:** Create `crates/aitm-plugin-rhai/tests/api_catalog.rs`; Test = itself. Satisfies UI-spec AC5.
**Interfaces:** Loads `docs/design/languages/rhai.api.json` (canonical on `main`); asserts a bijection with the engine's registered `globals`/`flow`/`msg`/`dsl` surface.

- [ ] Step 1: failing test — bijection holds against the real engine; a deliberately-added stale catalog entry (in a test fixture copy) fails it.
- [ ] Step 2: run — FAIL (until written). Step 3: implement (enumerate the engine's registered functions via the prelude/host modules; compare to the catalog). Step 4: PASS; gate. Step 5: commit.

> **Note:** when L4 adds `l4.*` host functions to the Rhai sandbox (M5 + the protocol-extensibility design), they must be added to `rhai.api.json` in the same change — this guard will fail otherwise, by design.

## Review log

| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|

## Shipped

Filled at stage 7.
