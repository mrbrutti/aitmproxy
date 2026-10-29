# Protocol-extensible scripting & PoC languages — reconciliation against current `main`

**Date:** 2026-10-29 · **Author:** f8-ext-reconcile architect session
**Reconciles:** approved spec `docs/superpowers/specs/2026-10-28-aitmproxy-protocol-extensible-languages-design.md` + plan `docs/superpowers/plans/2026-10-28-aitmproxy-protocol-extensible-languages.md` (both on `claude/ui-ext-spec-114cb7`; not on `main`).
**Grounded against:** `main` @ `5643292` (M3/M4/M5/M6/L4 landed). **Coordinated with:** L4 architect session (`local_06c5c79d`).

## Verdict

**Do not build the plan as written — its central premise no longer holds. Re-spec before building.**

The spec was written on the assumption (its own words) that *"M5 adds `l4.*` **host functions** [to the Rhai scripting sandbox] the same hard-wired way"* and that the seam's job was to **migrate** those hard-coded host functions onto a `ProtocolLanguage` registration surface, with L4 as the first consumer. **That is not what landed.** The design to make extensible does not exist in the form the spec assumed, so the plan's Tasks 2, 5, and 6 have no real substrate, and its ACs (AC4 "l4.* reachable in a Rhai script", AC5 "native l4: PoC step") describe capabilities `main` never grew.

## What actually landed (vs. what the spec assumed)

| Spec assumption | Reality on `main` |
|---|---|
| `l4.*` are **Rhai host functions** registered in `aitm-plugin-rhai` | `l4.*` are a **bus command surface** — `L4Module::load` (`aitm-proto-l4/src/module.rs`) registers `l4.craft`, `l4.scope.*`, `l4.flow.*`, `l4.send_recv`, `l4.intercept.*`, `l4.interfaces` as `Registry` **Commands** (each an MCP tool + CLI subcommand + bus verb, each with its own `sensitivity()` + `L4Guard`). **`l4` is not a Rhai host namespace** — `grep` for `l4` in `aitm-plugin-rhai/src/{engine,host_net,host_core,prelude}.rs` is empty. |
| `http`/`browser`/`store`/`scope` are hard-coded host fns waiting to migrate onto the seam | True — they remain in-crate host fns in `aitm-plugin-rhai`. |
| PoC has fixed `http`/`browser`/`extract`/`script` steps, seam adds `Step::Protocol`+`l4:` | PoC `Step` enum (`aitm-poc/src/model.rs:75`) is exactly `Http`/`Browser`/`Extract`/`Script` with custom single-key serde. **No `Step::Protocol`, no `l4:` step.** L4 reproduction in a PoC is only reachable through the generic `script:` step (as M5 deferred). |
| Seam types (`ProtocolLanguage`, `ScriptHostRegistry`, `PocStepHandler`, `NamespaceCatalog`) are new | None exist. Greenfield. |
| M4 sensitivity/policy is the gate | True and landed — l4 commands already use it. The spec's "command-sensitivity model is now M4's" is confirmed; L4 owns the `l4.*` sensitivity rows. |

## The real question (Matt's directive still stands)

Matt's directive — *"our scripting language and PoC language need to support L4 as well, and it has to be expandable to all supported protocols"* — is **not satisfied** by current `main`: L4 is first-class as an **operator command surface**, but it is **not** reachable from inside a Rhai *script* or as a first-class *PoC step*. So the underlying need is real and open. But the design must be re-derived from where the code actually is:

- The old framing ("migrate hard-coded `l4.*` host fns onto a seam") is obsolete — there are no hard-coded l4 host fns to migrate.
- The new framing is: **"how does a protocol's command surface (the landed `l4.*`/future `<proto>.*` Registry commands) become callable from the scripting and PoC languages, through one growable seam, each routed through the protocol's guard."** That may reuse the command Registry + `Sensitivity` + guards that already exist, rather than inventing a parallel `ScriptHostRegistry`. It is a materially different, and likely smaller, design.

## Recommendation

1. **Build nothing against the old plan now.** Its substrate changed; shipping it would add a seam shaped for a world that didn't happen.
2. **Re-spec** (`architect`, Stage 2) once L4 Stage B settles — a revised "protocol-extensible languages v2" grounded on: l4-as-command-surface, M4 `Sensitivity`/guards as the gate, the landed `Registry`, and the real PoC `Step` model. The three resolved open questions (named per-protocol steps; incremental migration; one L7+L4 seam) and the human-friendly `l4:` example remain good north stars.
3. **Coordinate with L4 (session `local_06c5c79d`):** whether the l4 vocabulary should be surfaced into scripts/PoC at all in this cycle, and if so whether L4 Stage B or a follow-up owns it — to avoid two sessions shaping l4-in-scripting. (Message sent 2026-10-29; recommendation to be finalized on reply.)

## Status of this reconciliation

Build is **held** pending (a) L4 Stage B settling and (b) a Matt decision on re-spec vs defer. This note + the directive are the inputs for that re-spec. The approved v1 spec/plan on `claude/ui-ext-spec-114cb7` should be marked **superseded by reconciliation** rather than executed.
