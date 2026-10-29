# F8 scripting-command-surface — reconciliation against current `main`

**Date:** 2026-10-29 · **Author:** f8-ext-reconcile architect session
**Reconciles:** approved spec `docs/superpowers/specs/2026-10-28-aitmproxy-scripting-command-surface-design.md` + plan `docs/superpowers/plans/2026-10-28-aitmproxy-scripting-command-surface.md` (both live on branch `claude/ui-ext-spec-114cb7`; not yet on `main`).
**Grounded against:** `main` @ `5643292` (PR #18, M4 merge; M3/M4/M5/M6/L4 all landed).

## Verdict

**Build it — not superseded.** The three command groups the UI "add a plugin" panel needs (`script.list`, `script.validate{source}`+`script.save`, `script.enable`/`disable`) are still absent from `main`. What *has* landed is the M4 identity/policy infrastructure the spec assumed, so the agent-gating task **shrinks**: the policy layer is done; F8 only declares each command's sensitivity and adds one config flag.

## What's already built / absorbed

| Spec element | State on `main` | Note |
|---|---|---|
| `Frontend::{Cli, Mcp, Operator}` | **Landed** (`aitm-core/src/ctx.rs`) | M4 Task 2 shipped `Operator`. |
| `Sensitivity` tiers (`Read`/`Write`/`Sensitive`) | **Landed** (`aitm-core`), widely used in `aitm-plugins` | M4 Task 1. Per-command `sensitivity()`, no central registry — exactly the spec's model. |
| `AgentPolicy` (All/Auto/Ask/ReadOnly/Paused) + central gate | **Landed** (`aitm-core/src/agent.rs`; enforced in `aitm-mcp/src/server.rs:1429` with park-for-approval under `Ask`) | The two-dimension gate the spec described is **real and central**. A command only needs to declare `sensitivity()`; the dispatcher applies the policy. |
| Per-command `allow_agent_*` config flag convention | **Landed** (`maps.allow_agent_authoring`, `tls.allow_agent_passthrough`, `ca.allow_agent_install`; `check_agent_gate` helper pattern in `aitm-plugin-maprules`) | The "second dimension" (always-on config gate) F8 mirrors with `scripts.allow_agent_authoring`. |
| `ScriptHandle::meta()` | **Landed** (`aitm-plugin-rhai/src/plugin.rs:162`) | Plan Task 1's `meta()` half is **done**; only the live `enabled` toggle remains. |
| `ScriptEntry { path, options, enabled }` | **Landed** (`config.rs`) — `enabled` already a field | Config-level enable exists; a runtime `AtomicBool` on the handle for live toggle is still needed. |
| `RhaiConfig` opt-in flag pattern (`allow_scope_add`, `ssrf`) | **Landed** | Exact template for new `scripts_dir` / `allow_agent_authoring`. |
| `docs/design/languages/rhai.api.json` + `poc-yaml.schema.json` + `validate.test.mjs` | **Landed** (PR #8) | Catalog files + a **JSON-internal** drift guard exist. |
| `findings.list` | Shipped **renamed** as `script.findings` (`commands.rs:189`) | Spec AC text says `findings.list`; cosmetic — no action. |

## What's genuinely still missing (the build)

All additive to `aitm-plugin-rhai` (+ one `crates/aitm` config surface); **no `aitm-core` edits**.

1. **F8a `script.list {}`** — not present. `commands.rs` registers only `script.validate`, `script.reload`, `script.findings`.
2. **F8b `script.validate { source }`** — only the `{ path }` arm exists. Need `RhaiLoader::validate_source` + the `registers` field.
3. **F8b `script.save` + `RhaiConfig.scripts_dir`** — not present.
4. **F8c `script.enable`/`script.disable`** + live `enabled: AtomicBool` on `ScriptHandle` (and hook dispatch skipping disabled) — not present.
5. **`scripts.allow_agent_authoring`** flag + `sensitivity()` on the five mutating/read commands — not present.
6. **Engine↔`rhai.api.json` bijection drift-guard** (plan Task 7) — **partially** covered. `validate.test.mjs` checks the JSON files are internally consistent, but **no test asserts the catalog matches the engine's live registered host surface**. The Rust-side bijection test (`tests/api_catalog.rs`) is still needed.

## Adjustments to the plan for current `main`

- **Task 1:** `meta()` is already shipped — the task reduces to adding the `enabled: AtomicBool` + dispatch skip. Keep the failing-test-first shape for the toggle only.
- **Task 6 (shrinks):** Do **not** build a policy layer — it exists and is centrally enforced. The task is: (a) declare `sensitivity()` = `Sensitive` for `save`/`reload`/`enable`/`disable`, `Read` for `list`/`validate`; (b) add `scripts.allow_agent_authoring: Option<bool>` (default `false`) to `RhaiConfig` + `crates/aitm/src/config_file.rs`, mirroring `maps.allow_agent_authoring`; (c) the authoring commands check that flag as their always-on config gate (the `check_agent_gate` convention), so under `Auto` a `Sensitive` authoring command is refused unless the flag is on, and `Operator`/`Cli` are never gated. The `AgentPolicy` All/Ask behaviour comes free from the central gate. Reuse `aitm-plugin-maprules`'s `check_agent_gate` as the worked reference.
- **Task 7:** The old plan note ("when L4 adds `l4.*` host functions to the Rhai sandbox, add them to `rhai.api.json` — this guard will fail otherwise") is now **moot**: `l4.*` landed as a **bus command surface**, not a Rhai host namespace, so it is not part of the engine's scripting catalog. Scope the drift-guard to the actual registered Rhai host surface (`globals`/`flow`/`msg`/`dsl` from the prelude/host modules). See the protocol-extensibility note for the l4-vs-scripting divergence.
- **Branch:** plan says `feat/scripting-cmds` off `main`. Correct. The approved spec+plan docs must be brought onto that branch (they live on `claude/ui-ext-spec-114cb7`).

## Collision check

F8 touches **only** `aitm-plugin-rhai` `script.*` commands + `crates/aitm` config. It has **no** overlap with L4 Stage B (which touches `l4.*` commands/gates). Safe to build in parallel with L4.
