# Web L4 parity surface — live browser run record (task C10)

**Plan:** `docs/superpowers/plans/2026-10-31-l4-parity-fixes-plan.md`, unit (c) web, Task C10.
**Spec:** `docs/superpowers/specs/2026-10-31-l4-parity-fixes-design.md` — L4PAR-AC18 (live), AC19, AC20, AC21, AC22, AC23, AC24, AC33 (web half).
**Harness:** `apps/web/scripts/cua-l4.mjs` (`npm run cua:l4`), on `live-env.mjs` + `cua-driver.mjs` (unchanged).
**Date of the run (run 1):** 2026-11-01, 18:09–18:11 PST (DST ended 2026-11-01 02:00; the machine is on PST). Its idle-window
`t0=1793585392521` is 2026-11-02 02:09:52 UTC = 18:09:52 PST (log 08 line 74).
**Worktree branch:** `claude/competent-ellis-5a0f21`.
**HEAD at the run:** `f99a4a01` (code head `a93e7398` = C1–C9b, plus the two pre-run shell fixes `7bf7f0f2`, `8b707e63`, plus the C10 script commit).
**Binary:** `target/release/aitm` built from this worktree; workspace version **0.5.10**.
**Host:** macOS (Darwin 27.0.0), the **unprivileged rig** of spec §6: `/dev/bpf*` is root-only, so raw capture/inject is
`needs_privilege` and in-path intercept is `unsupported_platform`. Headless Google Chrome over CDP, real input events only.
**Core:** spawned by `live-env.startAitm` on free ports (proxy 52981, web 52983, target 52980); 113 tools, **25 `l4.*`**;
`l4.scope.add` advertised with `confirmable: true`.
**Full redacted log (run 1):** `/tmp/claude/l4-rig/c-evidence/08-cua-l4-full-run.log` (407 lines; every step line, the histogram, the scope prompt, the 19 screenshot paths).
**Full redacted log (run 2, after the wrapper fix):** `/tmp/claude/l4-rig/c-evidence/10-cua-l4-run2-after-wrapper-fix.log` (402 lines; same
rig and binary; its idle-window `t0=1793585702085` is 2026-11-02 02:15:02 UTC = 18:15:02 PST, file written 18:16 PST).
**Full redacted log (run 3, the fix-3 script):** `/tmp/claude/l4-rig/c-evidence/11-cua-l4-run3-after-fix3.log` (410 lines; built from
`62af37a8` = unit (c) fix 3, the commit that added every-token redaction, the no-auto-PASS step wrapper, the 05f privileged
branch and step 07d; same rig; core on proxy 60010, web 60012, target 60009; its idle-window `t0=1793587936570` is
2026-11-02 02:52:16 UTC = 18:52:16 PST, file written 18:53 PST).
**Full redacted log (run 4, the fix-4 build):** `/tmp/claude/l4-rig/c-evidence/12-cua-l4-run4-after-fix4.log` (410 lines; built from
`32d92a30` = unit (c) fix 4 — store recovery keyed by call identity, per-flow load-more guard, identity stale-cancel,
`isPendingAvailability` identity-only, `formatPacketTime` placeholder for a malformed timestamp; the script itself changed
only in a comment; same rig; its idle-window `t0=1793589127177` is 2026-11-02 03:12:07 UTC = 19:12:07 PST). Summary line
`38 PASS · 0 FAIL · 5 BLOCKED · 4 notes`, `EXIT=0`; 07d read `rows=184; l4 rows=31; error rows=[]`; the five BLOCKED lines
quote the same two core reasons as runs 1–3.

**Summary line printed by the script, run 1:** `38 PASS · 0 FAIL · 5 BLOCKED · 4 notes`, `EXIT=0`.
One of the 38 PASS lines was the step-09 wrapper line (`PASS 09 privileged real-packet click-drive …`) printed after the
body had recorded only `BLOCKED 09 …`; the wrapper was fixed in the commit that filled this record (a body that records a
BLOCKED line is no longer auto-passed). **Run 2 (log 10) confirmed it:** its summary line is
`37 PASS · 0 FAIL · 5 BLOCKED · 4 notes`, `EXIT=0`, with no `PASS 09` line — the wrapper fix, 37 = run 1's 38 minus the
spurious `PASS 09`. **Run 3 (log 11), the fix-3 script, prints `38 PASS · 0 FAIL · 5 BLOCKED · 4 notes`, `EXIT=0`:**
38 = 37 + the new step 07d (the UI activity log read live, row below), still with no `PASS 09` line; its 05f line is
`BLOCKED 05f … blocked: needs D0` with the core's reason quoted, and its 4 notes are the same four explanatory notes as
runs 1 and 2 (no "no assertion ran" note). The PASS lines below are the same assertions in all three runs (the ids and
scope ids quoted are run 1's; run 3's are `conn_86a16b9578df7017-2` and scope id `22f1505c-7a9b-4bb0-b7e5-b57b26be1226`).

## Rule for every task (plan, Matt 2026-10-31)

No fixture, snapshot, self-test or seeded-store run counts as evidence or as a gate. Evidence here is the **live check**:
the real web UI served by a real `aitm web` spawned from the binary under test, driven by real clicks in a real browser,
with every Sensitive assertion cross-checked in the core's own audit ring (`agent.activity`) over a separate operator bus
connection — or the honest **blocked** verdict (`blocked: needs D0` / `blocked: no Linux rig`) quoting the core's reason.

## Pre-run smoke found two shell layout defects

Before this run, a live smoke of the L4 focus view (measured with `scripts/shot.mjs` against the real core) found two
shell layout defects that this branch's new capture section exposed; both were fixed and re-measured live before the run:

- **Fix 1 — `7bf7f0f2`:** the list pane's grid clipped the capture section at 129 px (the `L4CaptureBar` above the flow
  list was cut off).
- **Fix 2 — `8b707e63`:** the `.main` grid rows shifted when the role banner rendered; `.body` height measured 416 px before
  the fix and 862 px after.

## How the run was made

The Claude sandbox cannot bind ports, open sockets or launch Chrome, so the script ran in the Terminal:

```bash
cd <worktree>/apps/web
AITM_BIN=<worktree>/target/release/aitm node scripts/cua-l4.mjs 2>&1 | tee /tmp/claude/l4-rig/c-evidence/08-cua-l4-full-run.log; echo EXIT=${PIPESTATUS[0]}
```

The script never prints a bus token or an Operator URL (the `#t=…` fragment is redacted in every line). Exit status is
non-zero on any `FAIL`; `BLOCKED` lines are not failures. Screenshots land in `apps/web/.cua-l4-shots/` (git-ignored).

**Spawned core config** (`live-env.startAitm`): `l4.enabled: true`; `l4.allow_agent_widen: false` (AC5); three config
`l4.scope` entries on `lo0` · `127.0.0.1/32` · ports `9000-9999` · direction `outbound` (the `l4Block` default), one each for
`capture` / `inject` / `intercept`; `mcp.operator_token` configured, so the browser at the Operator URL and the script's
cross-check bus are both `Frontend::Operator` (`initialize` echoed `role=operator`); the local HTTP target and `127.0.0.1`
in proxy scope so real HTTP rows exist.

## The core's reasons, read live by the script and quoted by every BLOCKED row

- `l4.capture.status` → `{"available":false,"captures":[],"code":"needs_privilege","reason":R_CAP}` with
  **R_CAP** = `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)`
- `l4.intercept.status` → `{"available":false,"code":"unsupported_platform","reason":R_INT,"sessions":[]}` with
  **R_INT** = `in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)`
- `agent.activity {since, limit}` returned audit lines `{at, origin, client_label, connection_id, command, args, result}`.
  Every `/bus` connection — the browser's and the script's — carries the server-minted `client_label` `web-bridge`
  (`crates/aitm-core/src/audit.rs` `WEB_BRIDGE_CLIENT_LABEL`), so the script made **no** bus call inside the AC23 window
  and reported the `connection_id`s it saw: one, `conn_b65bed132a6bec00-2`, the browser's operator connection.

## Steps and results (the lines the script printed)

| Step | AC | Real clicks / cross-check | Result (from the log) |
|---|---|---|---|
| 01a | — | Cross-check bus `initialize` echoes `role: operator` | PASS — `initialize echoed role=operator` |
| 01b | — | Operator URL opened; status bar `bus open`; sidebar **L4** reads `on` | PASS — `sidebar "L4 on"; l4 tools=25` |
| 01c | AC24 | No `l4-operator-only-banner` on the Operator URL | PASS — `banner count=0` |
| 02 | AC18 live | `tools/list` over the bus: every key of the eight `L4_ARG_BUILDERS` rows is in that tool's `inputSchema.properties` | PASS — `l4.capture.start{interface,direction} l4.capture.stop{id} l4.intercept.forward{id} l4.intercept.drop{id} l4.intercept.mutate{id,spec} l4.intercept.revert{id} l4.scope.add{cidr,ports,interface,direction,capability} l4.flow.get{id,offset,limit}` |
| 03a | — | Sidebar → L4: `section[aria-label="Capture"]` + the unified grid render, not the "L4 is not enabled" fallback | PASS — `fallback=false` |
| 03b | §1 | `l4.capture.status` answers without error (bus) | PASS — `{"available":false,"captures":[],"code":"needs_privilege","reason":R_CAP}` |
| 03c | §1 | `l4-capture-reason` leaves `Reading L4 availability…` once the first status reply renders | PASS — reason text = R_CAP |
| 03d | AC19 | `l4-capture-start` is `disabled` | PASS — `disabled=true` |
| 03e | AC19 | its `title` equals the core's `reason` literally | PASS — title = R_CAP (compared literally against the live `reason`) |
| 03f | AC19 | `l4-capture-reason` text equals the core's `reason` literally | PASS — text = R_CAP |
| 03g | AC33 | Forced click (real mouse + dispatched `click`) on the disabled Start → `agent.activity` since the click has no `l4.capture.start` | PASS — `l4.capture.start entries since click=0; error toast=none` |
| 03h | AC19 live start/stop | Live Start/Stop capture | **blocked: needs D0** — core reason: `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)` |
| 04a | §1 | `l4.intercept.status` answers without error (bus) | PASS — `{"available":false,"code":"unsupported_platform","reason":R_INT,"sessions":[]}` |
| 04b | AC20 | `l4-intercept-limited` reads exactly `In-path intercept is not available on this core: ` + the core's `reason` | PASS — `line "In-path intercept is not available on this core: in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"` |
| 04c | AC20 | No `l4-forward` / `l4-mutate` / `l4-drop` / `l4-revert` element exists in the DOM | PASS — `count=0` |
| 04d | AC20 live verdicts | Live Forward/Mutate/Drop/Revert | **blocked: no Linux rig** — core reason: `in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)` |
| 05a | AC21 | 3 × `GET /api/me` through the proxy → HTTP rows under sidebar All / chip All | PASS — `http rows=3` |
| 05b | AC21 | Chip bar labels in DOM order start `All, HTTP, HTTPS, WebSocket, TCP, UDP, L4, h1, h2` | PASS — `labels=["All","HTTP","HTTPS","WebSocket","TCP","UDP","L4","h1","h2","JSON","Form","XML","JS","CSS","GraphQL","Document","Media","Other"]` |
| 05c | AC21 | Click chip **L4** → zero HTTP rows, empty state `No flows match` (not `No flows yet`) | PASS — `http rows=0; no-match=true; no-flows-yet=false; l4 rows=0` |
| 05d | AC21 | `L4` is the only `aria-pressed="true"` chip | PASS — `pressed=["L4"]` |
| 05e | AC21 | ⌘5 (`Input.dispatchKeyEvent`, metaKey, key `5`) → `TCP` is the pressed chip | PASS — `pressed=["TCP"]` |
| 05f | AC21 L4 rows under the chips | L4 rows under TCP / UDP / L4 | **blocked: needs D0** — core reason: `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)` |
| 06a | AC22, AC39 | `tools/list` `l4.scope.add` `confirmable: true` and `l4-scope-add-form` renders | PASS — `confirmable=true; form=1` |
| 06 note | AC22 | "Form absent without (a')" | NOTE — n/a on this rig (main carries (a'); AC39 unit + the C7 tripwire cover the gate) |
| 06b | AC22 | Three `l4-scope-entry[data-source="config"]` rows | PASS — `config entries in DOM=3` |
| 06c | AC22 | Form defaults are `127.0.0.1/32` · `lo0` · `inbound` · `capture` (only `ports` is typed) | PASS — `{"cidr":"127.0.0.1/32","interface":"lo0","direction":"inbound","capability":"capture"}` |
| 06d | AC22 | Type `9100-9199` into `Scope ports`, click **Add L4 scope** → the confirm dialog titled `Confirm L4 scope add` with the core's prompt | PASS — prompt: `Confirm l4.scope.add: capture scope for 127.0.0.1/32 ports 9100-9199 on lo0 (inbound), inject refused (rate 0). A runtime entry never lifts the dangerous-destination denylist.` |
| 06e | AC22 | Click **Send to wire** → dialog gone, no refusal | PASS — `dialog gone=true; refusal=none` |
| 06f | AC22 | Within one slow poll: `l4.scope.list` (bus) and the DOM list both show the entry with `runtime` provenance beside the three `config` entries | PASS — `bus=["lo0 127.0.0.1/32:9000-9999 outbound capture config","lo0 127.0.0.1/32:9000-9999 outbound inject config","lo0 127.0.0.1/32:9000-9999 outbound intercept config","lo0 127.0.0.1/32:9100-9199 inbound capture runtime"]` |
| 06g | AC22 | `agent.activity` since the submit has exactly **one** `l4.scope.add` (the `needs_confirmation` step is not audited), `result: ok` | PASS — `[{"origin":"operator","client_label":"web-bridge","connection_id":"conn_b65bed132a6bec00-2","result":"ok","args":"{\"cidr\":\"127.0.0.1/32\",\"ports\":\"9100-9199\",\"interface\":\"lo0\",\"direction\":\"inbound\",\"capability\":\"capture\"}"}]` |
| 06 cleanup | — | `l4.scope.remove {id}` over the bus | NOTE — `l4.scope.remove {id: 889779b9-87d8-4bc8-99db-44adcfd15685} ok=true; entries now=3` |
| 07a | AC23 | Operator, L4 view, no L4 rows; **60 s** with no script bus call; `agent.activity {since: t0}` → `l4.*` entries ≤ **30** | PASS — `count=17`; histogram `l4.flow.list 5, l4.capture.status 5, l4.intercept.status 5, l4.scope.list 1, l4.agent.status 1` |
| 07b | AC23 | No counted `l4.*` entry has a `result` other than `"ok"` | PASS — `all ok` |
| 07c | AC23 | All counted entries share one `connection_id`; distinct `client_label`s printed | PASS — `connection_ids=["conn_b65bed132a6bec00-2"]`; `client_label` values `["web-bridge"]` |
| 07d | AC23 (UI activity log) | After the window: sidebar → Agent, read every `section[aria-label="Activity log"] [role=row][data-seq]`, keep the `l4.*` commands (cell 2), assert none has `data-result="error"`; back to L4 | PASS (run 3, log 11 line 86) — `PASS 07d the UI activity log (Agent panel) has no l4.* entry marked error — rows=183; l4 rows=31; error rows=[]` |
| 07 note | AC23 | Browser console during the window | NOTE — `0 new browser console error(s) during the window` |
| 08a | AC24 | Page re-opened at the **agent** URL → `l4-operator-only-banner` text | PASS — `banner "L4 actions (capture, inject, scope, intercept) need the Operator URL."` |
| 08b | AC24 | Sidebar → L4: `l4-capture-start` disabled, `title` and `l4-capture-reason` are the operator-only literal, `data-operator-only="true"` | PASS — `disabled=true; title "Operator only: reconnect with the Operator URL the core printed"; data-operator-only=true; reason "Operator only: reconnect with the Operator URL the core printed"` |
| 08c | AC24 | `l4-scope-add-form` renders; `l4-scope-add` disabled with that title and `data-operator-only="true"` | PASS — `form=1; disabled=true; title "Operator only: reconnect with the Operator URL the core printed"; data-operator-only=true` |
| 08d | AC24 | Forced clicks on Start and on the submit, plus Enter in the ports field → no confirm dialog | PASS — `dialogs=0` |
| 08e | AC24 | Agent panel: the four `[role=switch]` disabled, `data-operator-only="true"`, operator-only title; forced clicks flip no `aria-checked` | PASS — capture / inject / intercept / widen each `disabled:true, op:"true", title:"Operator only: reconnect with the Operator URL the core printed", checkedBefore:"false", checkedAfter:"false"` |
| 08f | AC24 | `agent.activity` since the agent page opened has **no** `l4.capture.start/stop`, `l4.inject`, `l4.scope.add`, `l4.agent.set`, `l4.intercept.forward/drop/mutate/revert` | PASS — `none` |
| 08g | AC24 Inject / Forward / Drop / Mutate clicks | Need a selected L4 row; the handler guards are the C9a unit evidence | **blocked: needs D0** — core reason: `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)` |
| 09 | privileged click-drive | Gated on `l4.capture.status.available === true` (old bare-array shape tolerated) | **blocked: needs D0** — core reason: `no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)` (the spurious wrapper `PASS 09 …` line that followed is the wrapper defect fixed with this record) |
| 10a | visuals | ⋯ Appearance menu → **Dark** (real clicks) → `data-theme="dark"` | PASS — `data-theme=dark` |
| 10 note | visuals | The dark scope-add dialog | NOTE — `opened for the screenshot and cancelled: the needs_confirmation step is not audited and nothing was added` |
| 10b | visuals | The agent-URL page is dark for its screenshot | PASS — `data-theme=dark` |

## Screenshots (19 files under `apps/web/.cua-l4-shots/`)

Named shots:

| Shot | Light | Dark |
|---|---|---|
| L4 focus view, operator | `03-l4-focus-view-operator-light.png` | `15-l4-focus-view-operator-dark.png` |
| Chip bar with `L4` selected (zero HTTP rows, `No flows match`) | `06-chip-bar-l4-selected-light.png` | `16-chip-bar-l4-selected-dark.png` |
| Scope-add confirm dialog (`Confirm L4 scope add`, the core's prompt) | `08-scope-add-confirm-dialog-light.png` | `17-scope-add-confirm-dialog-dark.png` |
| Agent URL, disabled controls (banner, Start, Add L4 scope) | `11-agent-url-disabled-controls-light.png` | `18-agent-url-disabled-controls-dark.png` |
| Agent URL, Agent panel switches | `12-agent-url-agent-panel-switches-light.png` | — |

Per-step shots: `01-01-connect-as-operator-sidebar-l4-reads-.png`, `02-02-ac18-live-schema-every-l4-arg-builder.png`,
`04-03-ac19-ac33-start-capture-is-disabled-w.png`, `05-04-ac20-intercept-one-documented-limited.png`,
`07-05-ac21-chips-with-real-proxied-http-row.png`, `09-06-ac22-operator-l4-scope-add-through-th.png`,
`10-07-ac23-60-s-idle-as-operator-on-the-l4-.png`, `13-08-ac24-agent-url-every-sensitive-l4-con.png`,
`14-09-privileged-real-packet-click-drive-ca.png`, `19-10-dark-screenshots-theme-pinned-through.png`.

**Screenshots looked at (orchestrator).** 03 L4 focus view (light), operator: the chip bar reads All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2 | JSON …; under it the Capture section with interface lo0, a direction select at inbound, a greyed Start capture, the BPF reason line, the three config scope rows each ending in `config`, the add-scope form (cidr 127.0.0.1/32, ports placeholder `all ports`, interface lo0, direction inbound, capability capture, Add L4 scope), then the one intercept line with the macOS reason, then the empty flow list and the Request/Response inspector. 17 scope-add confirm dialog (dark): centred dialog titled `Confirm L4 scope add` with the core's prompt (`Confirm l4.scope.add: capture scope for 127.0.0.1/32 ports 9100-9199 on lo0 (inbound), inject refused (rate 0). A runtime entry never lifts the dangerous-destination denylist.`), Cancel and Send to wire buttons; three HTTP rows behind it. 11 agent URL disabled controls (light): the banner `L4 actions (capture, inject, scope, intercept) need the Operator URL.` with a lock icon replaces the operator strip; Start capture greyed with the operator-only line under it; the add-scope form present with its button greyed; the chip bar with L4 pressed and `No flows match`. 16 chip bar with L4 selected (dark): same bar, L4 pressed, zero HTTP rows.

The other named and per-step shots are listed above; this record claims nothing about their content beyond the DOM
assertions in the table.

## What this run does not prove (and why)

- **Live capture start/stop, L4 rows under the chips, inject / packet inspector / hex, the agent-URL Inject / Forward /
  Drop / Mutate clicks:** `blocked: needs D0` — the core answered R_CAP on this Mac. Nothing was faked; the privileged
  click-drive (`privilegedDrive()`) runs only where `l4.capture.status.available` is true.
- **Live in-path verdicts:** `blocked: no Linux rig` — the core answered R_INT.
- **"Form absent without (a')":** n/a on this rig (main carries (a')); the AC39 unit test and the C7 tripwire cover the gate.
- **Against an `origin/main` core** (plan C10 "Test first"): not run in this session.
