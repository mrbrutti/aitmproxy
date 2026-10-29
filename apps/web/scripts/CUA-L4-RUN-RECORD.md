# Web L4 surface — CUA (human-path) acceptance run record

**Milestone:** L4 operator surfaces, Stage F, Task 17 / L4OPS-AC14 (+ AC18 honest degradation).
**Surface:** web (`apps/web`). **Harness:** `scripts/cua-l4.mjs` (`npm run cua:l4`).
**Base:** `feat/l4-operator-surfaces` @ `021793a`.
**Host:** macOS (Darwin), unprivileged dev host — **no `/dev/bpf` access** (no raw capture/inject).

This is **real-clicks** evidence, not a green-unit-test substitute: a real headless Chrome
driven over CDP with real input events only (`Input.dispatchMouseEvent` / `dispatchKeyEvent` /
`insertText` — never synthetic DOM events, never app functions), clicking through the UI a real
spawned `aitm web` serves, every step cross-checked over the live `/bus`. Screenshots per step in
`apps/web/.cua-l4-shots/` (git-ignored, like `.cua-shots/`).

## What ran

`node scripts/cua-l4.mjs` → **11 PASS · 0 FAIL · 1 GAP · 1 SKIP** (exit 0).

Spawned core: `aitm web` with `l4.enabled: true`, a config-declared L4 scope entry
(`lo0 · 127.0.0.1/32 · inject · 100pps`), and a mixed set of per-capability agent gates
(`allow_agent_capture/inject/widen: true`, `allow_agent_intercept: false`). 22 `l4.*` commands
advertised on the bus.

| Step | Real-clicks / bus cross-check | Result |
|---|---|---|
| 01 | Connect; sidebar **L4** reads **"on"** (l4.* advertised) | PASS |
| 02 | Click sidebar **L4** → `section[aria-label="L4"]` renders the live surface, **not** the "L4 is not enabled" fallback | PASS |
| 03a | `l4.capture.status` (a Read wire verb) → typed **`L4 unavailable: no read+write access to any /dev/bpf* device …`** — the privilege gate, no panic | PASS |
| 03b | `l4.inject` refused — never a silent/fake send (typed reason) | PASS |
| 04 | Pure/read verbs work: `l4.interfaces` ✓, `l4.flow.list` → `[]` ✓, `l4.craft` → `{IPv4/UDP, 33 bytes}` ✓ | PASS |
| 05a | CaptureControls shows the scope row (`… 127.0.0.1/32 … inject …`); `l4.scope.list` agrees | PASS |
| 06a | **Real click Start capture** → typed error toast; **no "Capture started", no flow row** (no fake success) | PASS |
| 07 | Union flow list honest empty state: "No flows yet. HTTP, WebSocket and L4 flows all appear here." | PASS |
| 08a | Agent panel **L4 agent capabilities**: each switch (Capture/Inject/Intercept/Widen) **reflects** `l4.agent.status` | PASS |
| 08b | Real click on the Inject switch does **not** change the gate (`l4.agent.set` is operator-only; the web bus is `Frontend::Mcp`) | PASS |
| 10 | Hero screenshot of the live surface | PASS |
| 05 | **GAP** — the web surface has no add-L4-scope control (by design) | GAP |
| 09 | **SKIP (not faked)** — privileged real-packet click-drive | SKIP |

## The two honest gates (why the full §4.3 click-path is not drivable on this host)

The web L4 inspector (craft editor, **Inject → confirm dialog**, packet list, layer tree, hex,
`send_recv`, intercept Forward/Mutate/Drop, out-of-scope dimming) needs a **selected L4 flow** in
`l4.flow.list`. On this host it cannot exist, for two independent, documented reasons:

1. **Privilege (AC18 / CLI-first).** Every wire verb (`l4.capture.*`, `l4.inject`, `l4.send_recv`,
   `l4.intercept.*`) is privilege-gated and returns a typed `L4Unavailable` on an unprivileged
   macOS host (`crates/aitm-proto-l4/src/module.rs` `L4Gated`; the probe reason is
   `no read+write access to any /dev/bpf* device …`). No wire verb ⇒ no captured/injected flow ⇒
   nothing to select ⇒ the inspector/craft/inject path has no session. This is the **required**
   honest-degradation scenario, and it is proven above by real clicks (Start capture → typed
   refusal, no fake) and bus cross-checks (`l4.capture.status` → `L4Unavailable`).

2. **Web bus identity = `Frontend::Mcp` under `AgentPolicy::Auto` (F1).** The web `/bus` bridge
   identifies every call as `Frontend::Mcp` — "the `Operator` identity is F1"
   (`crates/aitm/src/web/mod.rs:12`) — and there is no `mcp.policy` YAML key, so the policy is the
   default `Auto`. Under `Auto`, **Sensitive** commands are refused by the agent-policy gate
   *before* the per-capability/privilege gates. Consequences observed:
   - **Start capture / Inject / `l4.scope.add` / `l4.agent.set` via the web UI are refused by the
     agent-policy gate** (step 06 toast, step 05b, step 08b). Honest degradation still holds — the
     UI surfaces a typed reason and **never fakes success** — but the surfaced reason is the
     *policy* refusal, with the underlying *privilege* `L4Unavailable` reachable only on Read verbs
     (step 03) and via an agent-token/operator bus (Task 16).
   - The **operator confirm-over-the-wire dialog** (`ConfirmInject`, the heart of AC10) is offered
     only to `Frontend::Operator` (`inject.rs` `confirm_prompt`: "Only the operator role is offered
     this handshake"), so it **never reaches the web UI** on this build.

**Neither is a defect in the L4 surface itself** — the surface renders, reads the bus, reflects
scope + gates, and refuses every wire action with a typed reason (no fake). They are (1) the
intended CLI/Linux-first privilege reality and (2) the F1 web-operator-identity follow-up.

## Privileged / Linux-gated steps (SKIP here — NOT faked)

The full real-packet click-drive runs where **both** gates clear — a Linux/elevated core (raw
privilege) **and** the web operator identity (F1). It is authored in `cua-l4.mjs` as
`privilegedDrive()` (gated on a runtime privilege probe): capture on `lo` + a loopback UDP datagram
→ select the flow → author a `PacketSpec` in the craft editor → **Build** (hex preview) → **Inject**
→ **confirm dialog shows destination + packet summary + scope + permit budget** → Send → packet in
the list + layer tree → `send_recv` reply → remove scope → out-of-scope session dimmed + Inject
disabled with the scope reason. Intercept Forward/Mutate/Drop is in-path (Linux NFQUEUE /
`CAP_NET_ADMIN`) only. The **privileged bus path is already proven agent-driven (MCP)** in Task 16
(`5bd2381`, `tests/acceptance_mcp.rs`); `privilegedDrive()` is the human-clicks counterpart for a
privileged Linux host with the operator-web identity.

## GAP — no add-L4-scope control in the web surface

`CaptureControls` **reads** the L4 scope and points at where it is granted; it never offers an
add/widen the core would refuse (its own comment). So the §4.3 CUA step "add an L4 scope entry
(confirm)" has **no web click path** — L4 scope is declared by the operator (config, or
`l4.scope.add` over an *operator* connection). This run declares it in config and shows the surface
reflecting it (step 05a); runtime `l4.scope.add` over the web/bus is refused for the `Mcp` bus
(step 05b). If an in-UI operator scope-add is wanted, it is a surface follow-up tied to F1.

## Harness changes (tester-only; no production/aitm-core edits)

- `apps/web/scripts/cua-driver.mjs` (new) — the shared CDP driver (`launchChrome`, `pageHelper`,
  `makeDriver`), extracted from `cua-live.mjs` so the HTTP CUA and this L4 CUA use one harness.
- `apps/web/scripts/cua-live.mjs` — refactored to import the shared driver. **Behavior-preserving:**
  the pre-refactor version straight from `git` produces the identical pass/fail set on this build.
- `apps/web/scripts/live-env.mjs` — `startAitm({ l4 })` now emits an `l4:` config block.
- `apps/web/scripts/cua-l4.mjs` (new) — this CUA. `package.json`: `npm run cua:l4`.

## Pre-existing observation (not introduced here, not in scope)

`cua-live.mjs` (the **HTTP** CUA) is **red on this integration branch** — proxied flows never
appear in the UI (`FAIL 02 … row "/api/me"` …), and its step-11a expectation is stale (`agent.set`
is now present). The **identical failures reproduce with the original pre-refactor `cua-live.mjs`
from `git`**, so this is pre-existing branch drift, independent of the driver extraction and of the
L4 work. Flagged for the orchestrator; fixing it would touch the HTTP/core path (out of this
task's scope and the "no aitm-core edits" constraint).
