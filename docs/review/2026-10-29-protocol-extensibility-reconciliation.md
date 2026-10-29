# Protocol-extensible scripting & PoC languages — reconciliation against current `main`

**Date:** 2026-10-29 · **Author:** f8-ext-reconcile architect session
**Reconciles:** approved spec `docs/superpowers/specs/2026-10-28-aitmproxy-protocol-extensible-languages-design.md` + plan `docs/superpowers/plans/2026-10-28-aitmproxy-protocol-extensible-languages.md` (both on `claude/ui-ext-spec-114cb7`; not on `main`).
**Grounded against:** `main` @ `5643292` (M3/M4/M5/M6/L4 landed). **Coordinated with:** L4 architect session (`local_06c5c79d`) — reply received 2026-10-29, interlock agreed (see below).

## Verdict

**BUILD the seam — it is NOT superseded; it is the agreed owner of l4-in-scripting.** One factual correction from an earlier draft of this note: I first read "l4 landed as a command surface, not Rhai host fns" as *undercutting* the seam. The L4 architect confirms the opposite — **M5 deliberately skipped its Task 14 (hard-wired Rhai `l4.*`) and deferred the entire l4 scripting vocabulary to this seam by design.** So the seam is exactly as needed as the spec says; it **originates** the l4.* Rhai host fns + the `l4:` PoC step (M5's deferred work) rather than *migrating* pre-existing ones. The spec's goals and ACs stand; only the l4-consumer framing and a guard/gate interlock need recording.

## What actually landed (vs. what the spec's prose assumed)

| Spec prose | Reality on `main` | Effect on the plan |
|---|---|---|
| "M5 adds `l4.*` **host functions** [to Rhai] the same hard-wired way" and the seam **migrates** them | **False** — M5 skipped Task 14 on purpose; **no** in-crate code registers `l4.*` into `aitm-plugin-rhai` (grep empty). `l4.*` exists only as a **bus command surface** (`L4Module::load` → Registry commands + `sensitivity()` + `L4Guard`). | Plan **Task 6 originates** `l4.*` host fns + the `l4:` step from `aitm-proto-l4` through the seam (greenfield), not "migrate". `L4Guard` already exists to wrap them. |
| Seam types (`ProtocolLanguage`, `ScriptHostRegistry`, `PocStepHandler`, `NamespaceCatalog`) are new | Correct — none exist. | Plan Tasks 1–4 stand as written. |
| `http`/`browser`/`store`/`scope` are hard-coded host fns to migrate onto the seam | Correct — they remain in-crate. | Plan Task 5 stands (three worked examples). |
| PoC `Step` is fixed `http`/`browser`/`extract`/`script`; seam adds `Step::Protocol`+`l4:` | Correct — `aitm-poc/src/model.rs:75` has exactly those four, no `Step::Protocol`. | Plan Task 3 stands. |
| M4 sensitivity/policy is the gate | Correct and landed; l4.* **commands** already use it. | See interlock — the scripting path must mirror it. |

## Interlock contract with L4 (agreed 2026-10-29)

Clean split, no duplication: **I (the seam) own l4.* scripting (Rhai host namespace + `l4:` PoC step); the L4 architect owns the l4.* command-path policy** (`Command::sensitivity()` per l4-operator-surfaces §2.2, the `l4.allow_agent_{inject,capture,intercept,widen}` flags, two-dimension gating, operator confirm-over-the-wire, operator-only `l4.agent.set/status`). They meet at **`L4Guard`** and the **`allow_agent_*` flags**. The seam's l4 consumer MUST:

1. **Route every `l4.*` host fn through `L4Guard`**, deny-by-default (the spec's "no function bypasses its guard", AC2).
2. **Enforce the same gates in the scripting path as the command path** — an agent-invoked `l4.*` via a script is bound by the L4 `allow_agent_*` flags + `L4Guard`, or is operator-authored-only via F8's `scripts.allow_agent_authoring`; a script must not do what a gated agent command cannot.
3. **Name the l4 namespace/catalog verbs identically to the l4.* command names** (shared vocabulary, spec AC8) — the L4 Stage E UI's Rhai craft path + `rhai.api.json` completion light up when the seam adds the l4 namespace to the catalog.

## Sequencing (dependencies)

- **After F8 lands.** The seam reshapes `docs/design/languages/rhai.api.json` into a per-protocol `namespaces` map and extends the engine↔catalog drift-guard (`tests/api_catalog.rs`) — the same files F8 creates/reads. Build the seam **after the F8 PR merges** to avoid a catalog/drift-guard collision; the seam's Task 4 then builds on F8's Task 7.
- **L4 consumer (plan Task 6) after L4 Stage B merges.** Stage B finalizes the `l4.allow_agent_*` flag names + the per-command `sensitivity()` tiers; the seam's scripting gate must mirror them 1:1, so Task 6 lands after Stage B and after a ping to the L4 architect for the final names. Seam core (Tasks 1–3, 5, 7) does not depend on Stage B.

## Recommendation

1. **Build the seam** (spec is sound; v1 plan stands with the two amendments above recorded here — "originate, not migrate" for l4; the L4 interlock). No full re-spec needed; this note is the plan delta.
2. **Order:** F8 PR merges → build seam core (Tasks 1–5, 7) → L4 Stage B merges → build the l4 consumer (Task 6) against the final flag/sensitivity names.
3. The v1 spec/plan on `claude/ui-ext-spec-114cb7` are **confirmed, with this note as the current-main delta** (not superseded).
