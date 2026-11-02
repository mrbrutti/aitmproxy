# Web L4 parity surface — live browser run record (task C10)

**Plan:** `docs/superpowers/plans/2026-10-31-l4-parity-fixes-plan.md`, unit (c) web, Task C10.
**Spec:** `docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md` — L4PAR-AC18 (live), AC19, AC20, AC21, AC22, AC23, AC24, AC33 (web half).
**Harness:** `apps/web/scripts/cua-l4.mjs` (`npm run cua:l4`), on `live-env.mjs` + `cua-driver.mjs` (unchanged).
**Date:** 2026-11-01.
**Worktree branch:** `claude/competent-ellis-5a0f21` (unit (c) work; C1–C9b committed, latest `a93e7398`).
**HEAD at the run:** `<fill after run>` (`git rev-parse HEAD` in the worktree; the C10 commit or later).
**`aitm --version`:** `<fill after run>` (the release binary the run used: `AITM_BIN=<worktree>/target/release/aitm`).
**Host:** macOS (Darwin 27.0.0), the **unprivileged rig** of spec §6: `/dev/bpf*` is root-only, so raw capture/inject is
`needs_privilege` and in-path intercept is `unsupported_platform`. Headless Google Chrome over CDP, real input events only.

## Rule for every task (plan, Matt 2026-10-31)

No fixture, snapshot, self-test or seeded-store run counts as evidence or as a gate. Evidence here is the **live check**:
the real web UI served by a real `aitm web` spawned from the binary under test, driven by real clicks in a real browser,
with every Sensitive assertion cross-checked in the core's own audit ring (`agent.activity`) over a separate operator bus
connection — or the honest **blocked** verdict (`blocked: needs D0` / `blocked: no Linux rig`) quoting the core's reason.

## How the run is made

The Claude sandbox cannot bind ports, open sockets or launch Chrome, so the script runs in the Terminal:

```bash
cd <worktree>/apps/web
AITM_BIN=<worktree>/target/release/aitm node scripts/cua-l4.mjs 2>&1 | tee /tmp/claude/l4-rig/web-cua-l4.log; echo EXIT=${PIPESTATUS[0]}
```

The script never prints a bus token or an Operator URL (the `#t=…` fragment is redacted in every line). Exit status is
non-zero on any `FAIL`; `BLOCKED` lines are not failures. Screenshots land in `apps/web/.cua-l4-shots/` (git-ignored).

**Spawned core** (`live-env.startAitm`): `l4.enabled: true`; `l4.allow_agent_widen: false` (AC5); three config
`l4.scope` entries on `lo0` · `127.0.0.1/32` · ports `9000-9999` · direction `outbound` (the `l4Block` default), one each for
`capture` / `inject` / `intercept`; `mcp.operator_token` configured, so the browser at the Operator URL and the script's
cross-check bus are both `Frontend::Operator`; the local HTTP target and `127.0.0.1` in proxy scope so real HTTP rows exist.

## Rig facts the blocked rows quote (orchestrator's live probe of a core built from this worktree)

- `l4.capture.status` → `{available: false, code: "needs_privilege", reason: R_CAP, captures: []}` with
  **R_CAP** = `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)`
- `l4.intercept.status` → `{available: false, code: "unsupported_platform", reason: R_INT, sessions: []}` with
  **R_INT** = `in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)`
- `tools/list`: 113 tools, 25 `l4.*`; `l4.scope.add` has `confirmable: true` (main carries units (a) and (a')).
- `agent.activity {since, limit}` returns audit lines `{at, origin, client_label, connection_id, command, args, result}`;
  `result` is `"ok"` or `{error}`. Every `/bus` connection — the browser's and the script's — carries the server-minted
  `client_label` `web-bridge`; the script therefore makes **no** bus call inside the AC23 window and prints the
  `connection_id`s it saw.

The script reads both reasons from the live core and compares the UI's text to them literally; the strings above are what
the orchestrator observed and are expected to match verbatim.

## Steps and results

Each row is one `PASS` / `FAIL` / `BLOCKED` line the script prints. The orchestrator pastes the real line from the
Terminal output into the **Result** column after the run; nothing below is claimed before that.

| Step | AC | Real clicks / cross-check | Result |
|---|---|---|---|
| 01a | — | Cross-check bus `initialize` echoes `role: operator` | `<fill after run>` |
| 01b | — | Operator URL opened; status bar `bus open`; sidebar **L4** reads `on` (`l4.flow.list` advertised) | `<fill after run>` |
| 01c | AC24 | No `l4-operator-only-banner` on the Operator URL | `<fill after run>` |
| 02 | AC18 live | `tools/list` over the bus: every key of the eight `L4_ARG_BUILDERS` rows (`l4.capture.start{interface,direction}`, `l4.capture.stop{id}`, `l4.intercept.forward/drop{id}`, `l4.intercept.mutate{id,spec}`, `l4.intercept.revert{id}`, `l4.scope.add{cidr,ports,interface,direction,capability}`, `l4.flow.get{id,offset,limit}`) is in that tool's `inputSchema.properties` | `<fill after run>` |
| 03a | — | Sidebar → L4: `section[aria-label="Capture"]` + the unified grid render, not the "L4 is not enabled" fallback | `<fill after run>` |
| 03b | §1 | `l4.capture.status` answers without error (bus) | `<fill after run>` |
| 03c | §1 | `l4-capture-reason` leaves `Reading L4 availability…` once the first status reply renders | `<fill after run>` |
| 03d | AC19 | `l4-capture-start` is `disabled` | `<fill after run>` |
| 03e | AC19 | its `title` equals the core's `reason` literally (R_CAP) | `<fill after run>` |
| 03f | AC19 | `l4-capture-reason` text equals the core's `reason` literally (R_CAP) | `<fill after run>` |
| 03g | AC33 | Forced click (real mouse + dispatched `click`) on the disabled Start → `agent.activity` since the click has no `l4.capture.start` | `<fill after run>` |
| 03h | AC19 live start/stop | **blocked: needs D0** — core reason: R_CAP | `blocked: needs D0` |
| 04a | §1 | `l4.intercept.status` answers without error (bus) | `<fill after run>` |
| 04b | AC20 | `l4-intercept-limited` reads exactly `In-path intercept is not available on this core: ` + the core's `reason` (R_INT) | `<fill after run>` |
| 04c | AC20 | No `l4-forward` / `l4-mutate` / `l4-drop` / `l4-revert` element exists in the DOM | `<fill after run>` |
| 04d | AC20 live verdicts | **blocked: no Linux rig** — core reason: R_INT | `blocked: no Linux rig` |
| 05a | AC21 | 3 × `GET /api/me` through the proxy → ≥ 3 HTTP rows (`[role=row][data-id]:not([data-kind="l4"])`) under sidebar All / chip All | `<fill after run>` |
| 05b | AC21 | Chip bar labels in DOM order start `All, HTTP, HTTPS, WebSocket, TCP, UDP, L4, h1, h2` | `<fill after run>` |
| 05c | AC21 | Click chip **L4** → zero HTTP rows, empty state `No flows match` (not `No flows yet`) | `<fill after run>` |
| 05d | AC21 | `L4` is the only `aria-pressed="true"` chip | `<fill after run>` |
| 05e | AC21 | ⌘5 (`Input.dispatchKeyEvent`, metaKey, key `5`) → `TCP` is the pressed chip | `<fill after run>` |
| 05f | AC21 L4 rows under the chips | **blocked: needs D0** — core reason: R_CAP | `blocked: needs D0` |
| 06a | AC22, AC39 | `tools/list` `l4.scope.add` `confirmable: true` and `l4-scope-add-form` renders (count 1) | `<fill after run>` |
| 06 note | AC22 | "Form absent without (a')": n/a on this rig (main carries (a'); AC39 unit + the C7 tripwire cover the gate) | n/a |
| 06b | AC22 | Three `l4-scope-entry[data-source="config"]` rows | `<fill after run>` |
| 06c | AC22 | Form defaults are `127.0.0.1/32` · `lo0` · `inbound` · `capture` (headless Chrome cannot change a native `<select>` via CDP keys; only `ports` is typed) | `<fill after run>` |
| 06d | AC22 | Type `9100-9199` into `Scope ports`, click **Add L4 scope** → `[role=alertdialog][aria-label="Confirm L4 action over the wire"]` titled `Confirm L4 scope add`, prompt contains `127.0.0.1/32`, `9100-9199`, `lo0`, `inbound`, `capture` | `<fill after run>` |
| 06e | AC22 | Click **Send to wire** → dialog gone, no refusal | `<fill after run>` |
| 06f | AC22 | Within one slow poll (≤ 65 s): `l4.scope.list` (bus) and the DOM list both show the entry with `runtime` provenance beside the three `config` entries | `<fill after run>` |
| 06g | AC22 | `agent.activity` since the submit has exactly **one** `l4.scope.add` (the `needs_confirmation` step is not audited), `result: ok` | `<fill after run>` |
| 06 cleanup | — | `l4.scope.remove {id}` over the bus | `<fill after run>` |
| 07a | AC23 | Operator, L4 view, no L4 rows, toast dismissed; **60 s** with no script bus call; `agent.activity {since: t0}` → `l4.*` entries ≤ **30** (per-command histogram printed) | `<fill after run>` |
| 07b | AC23 | No counted `l4.*` entry has a `result` other than `"ok"` (no L4 polling error lines) | `<fill after run>` |
| 07c | AC23 | All counted entries share one `connection_id` (the UI's); distinct `client_label`s printed | `<fill after run>` |
| 08a | AC24 | Page re-opened at the **agent** URL (fresh `#t=` replaces the sessionStorage token) → `l4-operator-only-banner` = `L4 actions (capture, inject, scope, intercept) need the Operator URL.` | `<fill after run>` |
| 08b | AC24 | Sidebar → L4: `l4-capture-start` disabled, `title` and `l4-capture-reason` = `Operator only: reconnect with the Operator URL the core printed`, `data-operator-only="true"` | `<fill after run>` |
| 08c | AC24 | `l4-scope-add-form` renders; `l4-scope-add` disabled with that title and `data-operator-only="true"` | `<fill after run>` |
| 08d | AC24 | Forced clicks on Start and on the submit, plus Enter in the ports field → no confirm dialog | `<fill after run>` |
| 08e | AC24 | Agent panel: the four `[role=switch]` (capture/inject/intercept/widen) disabled, `data-operator-only="true"`, operator-only title; forced clicks flip no `aria-checked` | `<fill after run>` |
| 08f | AC24 | `agent.activity` since the agent page opened has **no** `l4.capture.start/stop`, `l4.inject`, `l4.scope.add`, `l4.agent.set`, `l4.intercept.forward/drop/mutate/revert` | `<fill after run>` |
| 08g | AC24 Inject / Forward / Drop / Mutate clicks | **blocked: needs D0** (need a selected L4 row) — core reason: R_CAP; the handler guards are the C9a unit evidence | `blocked: needs D0` |
| 09 | privileged click-drive | Gated on `l4.capture.status.available === true` (old bare-array shape tolerated); here **blocked: needs D0** — core reason: R_CAP | `blocked: needs D0` |
| 10a | visuals | ⋯ Appearance menu → **Dark** (real clicks) → `data-theme="dark"` | `<fill after run>` |
| 10b | visuals | The agent-URL page is dark for its screenshot | `<fill after run>` |

**Totals printed by the script:** `<fill after run>` (`N PASS · N FAIL · N BLOCKED · N notes`, exit `EXIT=`).

## Screenshots (looked at and described after the run)

Named shots (`d.shot(name)` → `apps/web/.cua-l4-shots/NN-<slug>.png`; the `NN` prefix is the run's sequence number):

| Shot | Light | Dark | What it must show (orchestrator's description) |
|---|---|---|---|
| L4 focus view, operator | `NN-l4-focus-view-operator-light.png` | `NN-l4-focus-view-operator-dark.png` | Start capture disabled with R_CAP beside it; the three config scope rows; the one intercept line with R_INT; no verdict buttons. `<fill after run>` |
| Chip bar with `L4` selected | `NN-chip-bar-l4-selected-light.png` | `NN-chip-bar-l4-selected-dark.png` | `All \| HTTP HTTPS WebSocket \| TCP UDP L4 \| h1 h2 \| …`, `L4` pressed, grid empty with `No flows match`. `<fill after run>` |
| Scope-add confirm dialog | `NN-scope-add-confirm-dialog-light.png` | `NN-scope-add-confirm-dialog-dark.png` | `Confirm L4 scope add` with the core's prompt naming the AC5 entry; Cancel / Send to wire. `<fill after run>` |
| Agent URL, disabled controls | `NN-agent-url-disabled-controls-light.png`, `NN-agent-url-agent-panel-switches-light.png` | `NN-agent-url-disabled-controls-dark.png` | The operator-only banner; Start and Add L4 scope greyed with the operator-only reason; the four switches greyed with `operator only`. `<fill after run>` |

Every step also leaves its own `NN-<step-slug>.png`.

## What this run does not prove (and why)

- **Live capture start/stop, L4 rows under the chips, inject / packet inspector / hex, the agent-URL Inject / Forward /
  Drop / Mutate clicks:** `blocked: needs D0` — the core answers R_CAP on this Mac. Nothing is faked; the privileged
  click-drive (`privilegedDrive()`) runs only where `l4.capture.status.available` is true.
- **Live in-path verdicts:** `blocked: no Linux rig` — the core answers R_INT.
- **"Form absent without (a')":** n/a on this rig (main carries (a')); the AC39 unit test and the C7 tripwire cover the gate.
- **Against an `origin/main` core** (plan C10 "Test first"): the record of that counter-run, if made, goes here:
  `<fill after run or mark not run>`.

## Points the orchestrator should confirm from the live output

These could not be determined from source in the sandbox and are where the script may need a one-line fix:

1. **⌘5 under headless Chrome on macOS** — the driver sends `key: '5'`, `code: 'Key5'`, `modifiers: 4`; the shortcut
   handler reads `e.key` with `metaKey`. If the browser swallows ⌘-digit before the page sees it, 05e fails although the
   unit test (`shortcuts.test.ts`) pins the mapping.
2. **The agent connection's `role` echo** — `asRole` accepts only `operator` / `agent`; a different echo (e.g. `mcp`)
   resolves to `null`, which the UI gates identically. 08a–08f hold either way; the printed banner text confirms it.
3. **Toast dismissal selector** `[class*="toast"][role=alert|status]` relies on the CSS-module class keeping the local
   name `toast`; if a toast overlaps a control, 07/08 clicks may land on it.
4. **Appearance menu item text** — matched `startsWith 'Dark'` on `[role=menuitemradio]`.
5. **The chip bar at 1600 px** — 05b reads only *visible* chip buttons; a clipped bar would shorten the list.
