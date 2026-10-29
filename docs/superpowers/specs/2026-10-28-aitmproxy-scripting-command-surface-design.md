# Scripting command surface for UI authoring (F8a–F8c) design

**Status:** approved (2026-10-28 by Matt — both open questions resolved to recommended defaults: accept the sealed-registry restart limitation; `scripts.allow_agent_authoring` off by default). Design only; nothing here is built.
**Spec family:** extends the M3 scripting tier (`docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md`, now shipped on `main` as `crates/aitm-plugin-rhai`). Unblocks the UI "add a plugin" panel in `docs/superpowers/specs/2026-10-27-aitmproxy-ui-scripting-highlight-l4-design.md` (Part 2). Foundation F-list item **F8**.
**Grounding:** verified against `main` — `aitm-plugin-rhai` ships `script.validate { path }`, `script.reload { name }`, `findings.list { limit? }`; `RhaiLoader::{validate(path), compile(path), load_one(entry)}`, `ScriptHandle::{name, path, swap(ast)}`, `config::{ScriptEntry, ScriptMeta { name, api, path, hooks }}`; the agent gate pattern is `allow_agent_install` / `allow_agent_widen` (both `Frontend != Cli && !flag → refuse`).

## Intent

The shipped M3 bus gives an operator two script verbs — compile a file (`script.validate`) and hot-swap a loaded script's hooks (`script.reload`) — but no way to **enumerate** scripts, **author from a client without server disk access**, or **toggle** a script. The UI "add a plugin" panel (web/TUI/macOS) needs those three to let an operator author and install a Rhai plugin from the UI instead of hand-editing config and restarting. This spec defines that additive core surface — **F8a `script.list`**, **F8b `script.validate { source }` + `script.save`**, **F8c `script.enable`/`script.disable`** — plus the UI-facing catalog **drift guard** (the UI spec's AC5). All additive to `aitm-plugin-rhai`; no `aitm-core` edits.

## Goals

- **F8a — enumerate:** `script.list` returns every loaded script with its name, path, API version, hooks, enabled state, and last error, so a surface can render and manage the Scripts panel live.
- **F8b — author without disk access:** a `script.validate { source }` variant compiles an in-memory string (for the editor's continuous validation on web/remote), and `script.save { name, source }` writes a `.rhai` into a confined scripts directory and registers it, so an operator installs a plugin from the UI.
- **F8c — toggle:** `script.enable { name }` / `script.disable { name }` turn a loaded script's hooks on and off live, without a restart.
- **Agent-gated authoring:** the mutating verbs are refused to an agent (`Frontend::Mcp`) unless `scripts.allow_agent_authoring` is set; the human operator authors freely; every call is audited.
- **Drift guard:** a gate test keeps `docs/design/languages/rhai.api.json` in exact correspondence with the engine's registered host surface.

## Non-goals

- **No new scripting language surface.** Hooks, the flow object, host functions, and the sandbox are M3's; this only adds management/authoring commands over them.
- **No hot registration of new commands/options.** The registry is sealed after build (M3 constraint); a script that registers new commands/options still needs a restart to activate those. `script.reload`/`script.enable` affect **hooks** only. (See Open questions.)
- **No marketplace, dependency resolution, remote fetch, or signing.** M3's non-goals stand.
- **No change to `script.validate { path }`, `script.reload`, or `findings.list`** — those ship and stay; F8b adds a `{ source }` arm and a `registers` field, both additive.

## Anti-goals

- **A `script.save` that is a general file-write primitive.** Writes are confined to the configured scripts directory, path-traversal rejected, `.rhai`-only — exactly as `poc.run`/`poc.artifact` confine the PoC dir. A command that can write anywhere is a security failure.
- **An agent that can install or enable its own plugins silently.** Agent authoring is off by default and, when enabled, audited and surfaced for one-time approval — the `ca.install` posture.
- **A `script.list` that lies about state.** Enabled/disabled and last-error must reflect the live handles, not the config file.
- **A catalog that drifts from the engine.** If `rhai.api.json` lists a host function the sandbox does not register (or omits one it does), completion misleads the author — the drift guard must fail the build.

## Constraints

- **Additive to `aitm-plugin-rhai`; no `aitm-core` edits.** New commands register through the existing `ScriptCommands` plugin (`load(reg)` adds `Command`s); each is automatically an MCP tool and a CLI subcommand.
- **Identity & gate reuse M4 (confirmed with the M4 agent-milestone architect, 2026-10-28).** Gating reads `CommandHost::frontend()` (`Frontend::{Cli, Mcp}` today; M4 Task 2 adds `Operator`). M4's model is **two independent dimensions, both of which must pass** for an agent: (1) each command declares its own `sensitivity()` tier (M4 Task 1) — `Sensitivity::Sensitive` for the authoring verbs, `Sensitivity::Read` for list/validate; and (2) the command's own `*.allow_agent_*` config flag. The `AgentPolicy` permits `Sensitive` only under **All** (with the flag on) or **Ask** (live operator approval); the **default `Auto` never permits `Sensitive`** regardless of the flag. A human `Operator` (via `operator_token`) authors freely and is never policy-gated. The new flag `scripts.allow_agent_authoring` mirrors `allow_agent_install`/`allow_agent_widen` (config `Option<bool>`, default `false`). New agent-gated capabilities add a flag + declare their commands `Sensitive`; the policy layer is untouched. (Ref: `docs/superpowers/specs/2026-10-27-aitmproxy-m4-agent-milestone-design.md` D2/D4.)
- **Registry sealed after build.** `script.save` of a script that registers commands/options reports that a restart is needed to activate them; its hooks can still load via reload/enable.
- **Sandbox unchanged.** Authored scripts run under M3's existing sandbox (no ambient authority; guarded `http`/`browser`; operation/time budget). Authoring does not widen the sandbox.
- **Workflow & gate:** seven stages; `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Integration tests may load/validate/save/toggle test scripts and stand up a local echo server.

## Design

All three verbs are added to the existing `ScriptCommands` plugin (`crates/aitm-plugin-rhai/src/commands.rs`), built by `wire::build` over the same `RhaiLoader` + script handles it already holds.

### F8a — `script.list {}`

- **Result:** array (chain order) of `{ name, path, api, hooks: [string], enabled: bool, last_error: string | null }`.
- **Source:** `name/path` from each `Arc<ScriptHandle>`; `api/hooks` from the handle's `ScriptMeta`; `enabled` from the new enabled flag (F8c); `last_error` from the `ErrorSink` keyed by script name (most recent hook/compile error, else null).
- **Read-only** (`mutates() == false`); agent-allowed.
- **(Architect's call)** `ScriptHandle` gains a read of its `ScriptMeta` (`api`, `hooks`) — it already exposes `name()`/`path()`; expose `meta()` or the two fields so the command needs no parallel map.

### F8b — `script.validate { source }` and `script.save { name, source }`

**`script.validate` gains a `source` arm** (the `path` arm is unchanged):
- `{ path }` → compile the file (today's behaviour).
- `{ source }` → compile the string on the shared engine, registering nothing, reading no file. Result in both arms: `{ name, api, hooks, registers: { commands: [string], options: [string] } }` on success, or the positioned compile error in today's format. The new **`registers`** field reports what the script's `load(reg)` would register, so the UI shows the restart-to-activate banner for commands/options.
- **(Architect's call)** `RhaiLoader` gains `validate_source(&self, source: &str) -> Result<ScriptMeta, ScriptError>` and `extract_meta` is extended to populate `registers` (static scan of `reg.add_command`/`reg.add_option` calls in the AST, best-effort; empty when not statically determinable).
- Exactly one of `path`/`source` is required; both or neither → a clear argument error. `source` is bounded by the sandbox `max_string_size`.

**`script.save { name, source, enable?: bool }`:**
- Writes `<scripts_dir>/<name>.rhai` with `source`, where `scripts_dir` is a new confined `RhaiConfig.scripts_dir` (opt-in; `None` → `script.save` refuses with "no scripts dir configured", like `poc.run` without `poc.dir`). `name` is validated to a single path segment (`[A-Za-z0-9_-]+`); any separator or `..` is rejected before touching disk.
- Compiles before writing (reusing `validate_source`); a script that fails to compile is **not** written — the error is returned.
- **Overwrite of an already-loaded script** (a loaded script with that `name`): the file is written, recompiled, and swapped into the live handle (`script.reload` semantics), so its updated **hooks** run immediately; `restart_required` is `false` unless the script registers commands/options (`registers` non-empty), which need a restart because the registry is sealed. **A brand-new name:** the file is written, compiled, validated and persisted, but the plugin chain is sealed once built, so its hooks cannot join this session — the result is `restart_required: true` and the script loads on the next start (the config loader appends every `*.rhai` in `scripts_dir` as an enabled entry). `enable` has a live effect only on the overwrite branch; a durable disabled state for a brand-new script is out of scope. The result carries `registers` + `restart_required: bool`.
- Overwriting an existing `<name>.rhai` is allowed (it is the editor's Save); the prior version's hooks are swapped out via the handle, same as `script.reload`.
- **Result:** `{ name, path, api, hooks, registers, restart_required }`.
- **Mutating; operator-gated** (see Security).

### F8c — `script.enable { name }` / `script.disable { name }`

- Toggle a loaded script's hook dispatch. **(Architect's call)** `ScriptHandle` gains an `enabled: AtomicBool` and the plugin's hook dispatch checks it (a disabled script's hooks are skipped; its registered commands remain — they cannot be unregistered from the sealed registry, documented). `disable` does not unload; `enable` restores.
- **Result:** `{ name, enabled }`. Unknown name → the same "no loaded script named X; loaded: …" error `script.reload` already returns.
- **Mutating; operator-gated.**

### Security — agent gating (M4's two-dimension model; same primitive as `ca.install`)

- Each command declares a **`sensitivity()`** tier (M4 Task 1, per-command, no central registry): `Sensitivity::Sensitive` for `script.save`/`script.enable`/`script.disable` (and the existing `script.reload`); `Sensitivity::Read` for `script.list`/`script.validate`.
- New config `scripts.allow_agent_authoring: Option<bool>` (default `false`), surfaced in `aitm-plugin-rhai`'s `RhaiConfig` and the `aitm` config file alongside `allow_agent_install`/`allow_agent_widen`.
- For a non-CLI/non-Operator caller (`Frontend::Mcp`), a `Sensitive` command runs only when **both** pass: the `AgentPolicy` permits `Sensitive` (**All** with the flag on, or **Ask** with live approval) **and** `scripts.allow_agent_authoring` is on. The **default `Auto` refuses every `Sensitive` agent command** regardless of the flag. A human `Operator` authors freely. The refusal string names the setting, as `ca`'s does.
- Under policy **Ask**, a gated authoring request surfaces for one-time operator approval via `agent.approve` over the F4 push channel (`notifications/aitm/agent`, `event:approval_requested`) — the same primitive as `ca.install`. Every invoke is recorded in the F2 activity log.

### Drift guard (UI spec AC5)

A test in `crates/aitm-plugin-rhai/tests/api_catalog.rs` loads `docs/design/languages/rhai.api.json` and asserts a **bijection** with the engine's registered surface: every `globals`/`flow`/`msg`/`dsl` entry corresponds to a real `register_fn`/registered member in the prelude/host modules, and every registered host function appears in the catalog. A deliberately-stale entry makes it fail. This keeps the UI completion catalog honest against the shipped engine. (The catalog file is canonical on `main` via PR #8.)

## Acceptance criteria

Observable via `cargo test` (integration tests load/validate/save/toggle test scripts).

1. **AC1 — `script.list`:** With two scripts loaded, `script.list` returns both with correct `name`, `path`, `api`, `hooks`, `enabled: true`, `last_error: null`; a script whose hook raised an error reports that error in `last_error`.
2. **AC2 — validate by source:** `script.validate { source }` compiles a valid string and returns `{ name, api, hooks, registers }`; a syntax error returns the positioned compile error; neither-or-both of `path`/`source` is a clear argument error.
3. **AC3 — `registers` field:** a script whose `load` calls `reg.add_command`/`reg.add_option` reports those in `registers`; a hook-only script reports empty `registers`.
4. **AC4 — `script.save` writes + loads hooks:** `script.save { name, source }` writes `<scripts_dir>/<name>.rhai`. An **overwrite-save of an already-loaded script** runs its updated `on_request` with no restart (handle swap, reload semantics); a **brand-new script name** is written, compiled, validated and persisted and returns `restart_required: true` — its hooks join on the next start (the same sealed-chain limitation accepted for newly-registered commands/options, Open Question 1). A non-compiling `source` is refused and **no file is written**.
5. **AC5 — save confinement:** `script.save` with a `name` containing `/`, `..`, or other separators is rejected before any write; with no `scripts_dir` configured it refuses clearly.
6. **AC6 — restart signalled:** `script.save` of a script that registers a command returns `restart_required: true`; its hooks still load.
7. **AC7 — enable/disable:** `script.disable { name }` stops that script's hooks firing (observable: its mutation no longer applies); `script.enable` restores them; unknown name errors clearly.
8. **AC8 — agent gate:** under the default `Auto` policy an `Mcp` caller's `script.save`/`enable`/`disable` is refused regardless of `scripts.allow_agent_authoring`; under policy `All` with the flag on they are allowed and audited; with the flag off they are refused with a message naming the setting; `script.list`/`script.validate` (Read) are allowed throughout; an `Operator` caller is never gated.
9. **AC9 — sensitivity classification:** `sensitivity()` is `Sensitive` for `script.save`/`enable`/`disable`/`reload` and `Read` for `script.list`/`script.validate` (asserted directly).
10. **AC10 — drift guard:** `api_catalog.rs` passes against the shipped engine and fails when a catalog entry is made stale.

## Left to the builder

- The exact `registers` static-scan depth (how `reg.add_command`/`add_option` are detected in the AST) and its "empty when not determinable" fallback.
- Whether `enabled` lives on `ScriptHandle` as an `AtomicBool` or in a side map the plugin consults; the dispatch check placement.
- `scripts_dir` default (likely unset; opt-in) and whether it defaults beside `poc.dir`.
- The `ErrorSink` → per-script `last_error` lookup key.
- CLI subcommand surfacing (`aitm script list/validate/save/enable/disable`) names, consistent with `aitm script validate --path`.
- Exact audit-record shape reuse from the CA plugin's generalised audit (coordinate with M4).

## Open questions

Resolved at approval (2026-10-28, Matt):

1. **Hot command/option registration** → **accepted** the sealed-registry limitation: hooks load/reload live; a newly-saved script's commands/options need a restart, signalled by `restart_required`. Hot-registration is deferred (matches UI-spec OQ3).
2. **`scripts.allow_agent_authoring` default** → **off**, mirroring `ca.allow_agent_install`.
