# Web L4 surface — CUA (human-path) acceptance run record

**Milestone:** L4 operator surfaces, Stage F, Task 17 / L4OPS-AC14 (+ AC18 honest degradation).
**Surface:** web (`apps/web`). **Harness:** `scripts/cua-l4.mjs` (`npm run cua:l4`).
**Base:** `feat/l4-operator-surfaces` @ `b46e427` (PR #41 unified L4 list + `main` merged in → operator identity).
**Host:** macOS (Darwin), unprivileged dev host — **no `/dev/bpf` access** (no raw capture/inject).

This is **real-clicks** evidence, not a green-unit-test substitute: a real headless Chrome driven
over CDP with real input events only (`Input.dispatchMouseEvent` / `dispatchKeyEvent` / `insertText`
— never synthetic DOM events, never app functions), clicking through the UI a real spawned `aitm web`
serves, every step cross-checked over the live `/bus`. Screenshots per step in `apps/web/.cua-l4-shots/`
(git-ignored, like `.cua-shots/`).

## Surface + identity (current branch)

- **Unified L4 surface (PR #41):** no separate L4 panel. Picking the L4 source (sidebar → L4) shows
  `L4CaptureBar` (capture controls + scope) above the **one unified flow list**; L4 sessions are rows
  in that list (`L4FlowRow`, `[role=row][data-kind="l4"]`); selecting one opens `L4InspectorPanel`
  (packet list → layer tree → craft → inject/confirm → intercept).
- **Operator identity (operator-token UX, PR #35, now on this branch):** configuring
  `mcp.operator_token` makes the server mint a fresh per-run operator **bridge** token and print
  `web UI (operator): http://…/#t=<tok>&expect=operator`. This run drives the UI **and** the bus
  cross-checks as a real `Frontend::Operator` (the F1 "web is agent-only" limitation is resolved):
  sensitive actions bypass the agent-policy gate and reach the privilege/command gate directly.

## What ran

`node scripts/cua-l4.mjs` → **10 PASS · 0 FAIL · 1 GAP · 1 SKIP** (exit 0).

Spawned core: `aitm web` with `l4.enabled: true`, `mcp.operator_token` set, a config-declared L4 scope
entry (`lo0 · 127.0.0.1/32 · inject · 100pps`), and a mixed set of per-capability agent gates
(`allow_agent_capture/inject/widen: true`, `allow_agent_intercept: false`). 22 `l4.*` commands advertised.

| Step | Real clicks / operator-bus cross-check | Result |
|---|---|---|
| 01 | Connect **as operator**; sidebar **L4** reads **"on"** (l4.* advertised) | PASS |
| 02 | Sidebar **L4** → `L4CaptureBar` (`section[aria-label="Capture"]`) + the one flow list render, not the "L4 is not enabled" fallback | PASS |
| 03a | Operator `l4.capture.status` / `l4.inject` / `l4.send_recv` **all** return a typed **`L4 unavailable: no …/dev/bpf…`** — the privilege gate (no policy refusal, no panic, no fake send) | PASS |
| 04 | Pure/read verbs: `l4.interfaces` ✓, `l4.flow.list` → `[]` ✓, `l4.craft` → `{IPv4/UDP, 33 bytes}` ✓ | PASS |
| 05a | CaptureControls shows the scope row (`… 127.0.0.1/32 … inject …`); `l4.scope.list` agrees | PASS |
| 06a | **Real operator click Start capture** → typed **"L4 unavailable"** toast; no "Capture started", no L4 row (honest privilege degradation, no fake) | PASS |
| 07 | The one flow list shows **no L4 session rows** (none can be captured unprivileged) | PASS |
| 08a | Agent panel **L4 agent capabilities**: each switch (Capture/Inject/Intercept/Widen) **reflects** `l4.agent.status` | PASS |
| 08b | **Real operator click flips the Inject gate live**; `l4.agent.status` reflects it (then reverted) | PASS |
| 10 | Hero screenshot of the live operator surface | PASS |
| 05 | **GAP** — the web surface has no add-L4-scope control (by design) | GAP |
| 09 | **SKIP (not faked)** — privileged real-packet click-drive | SKIP |

## The one remaining gate: raw-socket privilege (AC18 / CLI-first)

Every wire verb (`l4.capture.*`, `l4.inject`, `l4.send_recv`, `l4.intercept.*`) is privilege-gated
and returns a typed `L4Unavailable` on an unprivileged macOS host (`crates/aitm-proto-l4/src/module.rs`
`L4Gated`; reason `no read+write access to any /dev/bpf* device …`). This run proves that degradation
honestly, by real **operator** clicks (step 06 Start capture → typed "L4 unavailable" toast, no fake)
and operator-bus cross-checks (step 03a — capture.status/inject/send_recv all `L4Unavailable`).

Because the `L4Gated` wrapper short-circuits an unprivileged wire verb **before** its `confirm_prompt`,
even the operator gets `L4Unavailable` straight away — so the operator **confirm-over-the-wire dialog**
is itself privilege-gated (it appears only where privilege exists). And with no wire verb, no L4 flow
can enter `l4.flow.list`, so the L4 inspector (craft editor, Inject, confirm dialog, layer tree, hex,
send_recv, intercept) + out-of-scope dimming have **no session to act on by clicks** here.

## Privileged / Linux-gated steps (SKIP here — NOT faked)

The full real-packet click-drive runs where raw privilege exists — a Linux/elevated **operator** core.
It is authored in `cua-l4.mjs` as `privilegedDrive()` (gated on a runtime privilege probe): capture on
`lo` + a loopback UDP datagram → select the flow → author a `PacketSpec` → **Build** (hex) → **Inject**
→ the **confirm dialog** (destination + packet summary + scope + permit budget) → Send → packet in the
list + layer tree → `send_recv` reply → remove scope → out-of-scope session dimmed + Inject disabled.
Intercept Forward/Mutate/Drop is in-path (Linux NFQUEUE / `CAP_NET_ADMIN`) only. The full privileged
real-packet path (and the operator confirm handshake) is proven **agent-driven (MCP)** in Task 16
(`5bd2381`, `tests/acceptance_mcp.rs`); `privilegedDrive()` is the human-clicks counterpart.

## GAP — no add-L4-scope control in the web surface

`CaptureControls` **reads** the L4 scope and points at where it is granted; it never offers an
add/widen the core would refuse (its own comment). So the §4.3 CUA step "add an L4 scope entry
(confirm)" has **no web click path** — L4 scope is declared by the operator (config, or `l4.scope.add`
over an operator connection, which this run confirms works over the operator bus). This run declares it
in config and shows the surface reflecting it (step 05a). If an in-UI operator scope-add is wanted, it
is a surface follow-up.

## Harness changes (tester-only; no production/aitm-core edits)

- `apps/web/scripts/cua-driver.mjs` — the shared CDP driver (`launchChrome`, `pageHelper`, `makeDriver`),
  extracted from `cua-live.mjs` so the HTTP CUA and this L4 CUA use one harness. `cua-live.mjs` imports it.
- `apps/web/scripts/cua-l4.mjs` — this CUA (operator-driven, unified surface). `package.json`: `npm run cua:l4`.
- `apps/web/scripts/live-env.mjs` — `startAitm({ l4 })` emits an `l4:` config block; configures
  `mcp.operator_token` and parses the printed `web UI (operator): …` URL + bridge token so the CUA drives
  as operator; startup readiness now matches the current `tracing` "web UI listening" log (stderr) and the
  `web UI (agent|operator):` stdout lines.
- `apps/web/.gitignore` — `.cua-l4-shots/`.

## Notes for the orchestrator

- This record + `cua-l4.mjs` supersede the earlier (pre-PR#41 / Mcp-F1) version that an earlier merge
  (`296a728`) brought onto feat; that version targeted the retired `section[aria-label="L4"]` surface and
  is stale. The files here are rebuilt against `b46e427` and pass green.
- `cua-live.mjs` (the HTTP CUA) was not re-run on this tip; earlier on the branch it was red (proxied
  flows not rendering) independent of this work — flag for a separate look.
