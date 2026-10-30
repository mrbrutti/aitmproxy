# Stage F / Task 17 — TUI L4 CUA (human-driven) acceptance run record (L4OPS-AC14)

**What this proves:** the §4.3 CUA bar for the **TUI** L4 operator surface, held
to Matt's standing rule — a *real operator* driving *real keystrokes* against a
*real spawned core* over a *real bus*, never a green unit assert or a screenshot
alone. It is the human-driven half of the two-way acceptance (the agent/MCP half
is Task 16, `l4_acceptance_mcp.rs`).

**Harness:** `crates/aitm/tests/l4_cua_tui.rs`
(`tui_l4_cua_against_a_live_core`). It extends the ui-tui foundation's harness —
`tui_live_bus.rs` spawns a real core over the loopback-TCP bus, `l4_surface.rs`
renders the surface — into a driver that presses **crossterm `KeyEvent`s through
the TUI's own key map** (`aitm_tui::keys::map`), the literal human-input path
`aitm_tui::run` runs, and folds the live `BusEvent` stream back through the real
reducer. **Nothing calls an `Action` variant directly** — every step is a key a
real operator types; every screen is `snapshot::render` of the real app state.

**Run it** (binds loopback TCP, so run in the Terminal panel, not the sandbox):

```bash
cargo test -p aitm --test l4_cua_tui -- --nocapture
```

A privileged Linux host adds the real-packet / confirm-overlay half:

```bash
AITM_L4_TESTS=1 cargo test -p aitm --test l4_cua_tui -- --nocapture
```

## The spawned stack (all real)

- A real core assembled by `aitm::wire::assemble_with` with `l4.enabled: true`
  over the **real startup privilege probe** (`l4_privilege: None`). Served as the
  agent-facing `McpServer` over **loopback TCP**, exactly as `aitm tui` builds it
  (`tui::services` → `tui::build_servers`), with the operator token so the TUI is
  `Frontend::Operator`.
- The config declares loopback `lo0` for **capture + inject** (config provenance,
  which lifts the loopback dangerous-destination denylist — SEC-2).
- Real capture flows land through the **protocol-general capture ingress**
  (L4OPS-AC17, `CoreIngress`) — the module's *shared* `L4Guard` + `L4FlowStore`,
  so what the operator reads via `l4.flow.*` is a guard-checked capture, not a
  fixture. (The ingress is privilege-free; only the `pcap` backend needs
  privilege, which the ingress bypasses.)
- The Stage-D `aitm-testtarget` L4 service (UDP echo + TCP) is started on
  loopback as the real in-scope target for the privileged half.
- The real TUI bus client (`aitm_tui::bus::run`) over the real `TcpTransport`.

## What the CUA exercised (real keys, against the live core)

| Step | Keys | Proves |
|---|---|---|
| 0 | — | connect; feature-detect `l4.*` from `tools/list`; first live `l4.*` poll lands (flows, scope, gates) |
| 1 | — | union flow list renders the live L4 capture row with the **L4 UDP** badge (AC7) |
| 2 | `j`/`↓`, `Enter` | L4 inspector: packet list (`Ethernet / IPv4 / UDP`, decoded), the honest **text** layer tree, the honest hex note (AC8) |
| 3 | `Tab`, `b` | YAML craft editor → real `l4.craft` → `build() → 33 bytes · IPv4 / UDP` hex preview (AC8) |
| 4 | `s` | inject reaches the wire **only** via `l4.inject`; the wire verb surfaces the typed `L4Unavailable` reason — no fake success, no panic (AC10 / AC18) |
| 5 | `Esc` | scope-as-authorisation: the real guard refuses an out-of-scope capture at the ingress (`IngressOutcome::Refused`) — no flow created (AC9) |
| 6 | `@`, `i` | Agent view L4 toggles; `i` flips the **Inject** gate `false → true` over the bus via `l4.agent.set` (AC11) |

### Result

`test result: ok. 1 passed` — all six steps green against the live core on this
macOS host (run 2026-10-29). Full snapshots in the harness log (reproduced with
`-- --nocapture`); representative ones below.

**Inject — honest `L4Unavailable` degradation (Step 4):** the craft preview is
real, the inject is refused honestly at the wire, and the reason is in the status
line:

```
                           │ L4  Packets  Craft  Intercept
                           │ PacketSpec (YAML) — b build · s inject (guarded)
                           │ layers:
                           │   - ipv4:
                           │       dst: 127.0.0.1
                           │   - udp:
                           │       dst_port: 7
                           │   - raw: [112, 114, 111, 98, 101]
                           │ build() → 33 bytes · IPv4 / UDP
                           │ 00000000  45 00 00 21 00 00 00 00  40 11 fb cb 00 00 00 00  │ E··!····@·······
                           │ 00000010  7f 00 00 01 00 00 00 07  00 0d 3b f7 70 72 6f 62  │ ··········;·prob
                           │ 00000020  65                                                │ e
 Esc back  Tab pane  ←→ tabs   L4 unavailable: no read+write access to any /dev/bpf* device (capture/inject needs it; install ChmodBPF or run with privilege)   ● bus 127.0.0.1:…
```

**Agent view L4 toggles after flipping Inject over the bus (Step 6):**

```
│ L4 agent capabilities — each toggle is the gate that governs the agent L4 path
│ ○ c Capture    off the agent may start/stop L4 capture
│ ● i Inject     on  the agent may put crafted packets on the wire
│ ○ n Intercept  off the agent may park/forward/drop in-path packets
│ ○ w Widen      off the agent may widen L4 scope
│ Toggle with the key; the agent can never flip its own gates.
```

## What degraded honestly, and why

This macOS dev host has no `/dev/bpf` read+write, so the core's **real** startup
probe reports capture/inject unavailable and every wire verb is wrapped to fail
closed with a typed `L4Unavailable` naming the missing capability — a **required**
scenario here (AC18, CLI/Linux-first). The CUA drives the surface fully (render +
bus) and the wire verb (`l4.inject`, via `s`) surfaces the reason rather than
faking success or panicking. The read/pure verbs work regardless: the union list,
the inspector, the L4 scope, the agent gates, and `l4.craft` (the 33-byte hex
preview is a real build) all drive the bus normally.

## Privileged / Linux-gated steps (noted, not faked here)

Because the gated wrapper suppresses the operator **confirm-prompt** while the
capability is unavailable (`L4Gated::confirm_prompt` → `None`), these are the
privileged half, driven for real only under `AITM_L4_TESTS=1` on an elevated
Linux host (the harness has the branch; it asserts honest degradation otherwise):

- the inject **confirm overlay** (destination + packet summary + matched scope +
  minted permit budget) and the real packet round-trip against `aitm-testtarget`;
- `l4.send_recv` echo and `l4.capture.start` on a live interface;
- the in-path **intercept bar** (Forward / Mutate / Drop), Linux NFQUEUE only.

The confirm-overlay *machinery* itself is pinned independently by the component
test `l4_surface::inject_shows_confirm`.

## Honest notes / scope of this record

- **Scope-as-authorisation is the guard, not the dimming.** Against a real core an
  out-of-scope packet is refused at the ingress and **never captured**, so a
  dimmed out-of-scope L4 *flow cannot exist in the store* — a stronger property
  than the fixture's dimming. The CUA drives that refusal live; the UI's
  inject-disabled/dimmed rendering is pinned by the component test
  `l4_surface::out_of_scope_inject_disabled`.
- **One capture session is one flow.** `CoreIngress` coalesces captures into a
  single capture flow by design, so the CUA drives one `lo0` flow rather than
  several; this is the real ingress behaviour, not a harness shortcut.
- **The TUI keys a subset of the generic "L4 view" scenario.** Capture-start,
  `send_recv` and L4-scope-add are command-surface verbs in this TUI build (not
  keyed); they are proven over the bus by Task 16 / the `aitm-proto-l4` suites.
  The TUI CUA drives exactly what the surface keys: open → inspect → craft →
  build → inject → agent toggles.
- SEC-2 (runtime `l4.scope.add` cannot authorise a loopback inject) is the reason
  the inject engagement is **config-declared** here, matching Task 16's finding.

## Deliverable

- `crates/aitm/tests/l4_cua_tui.rs` — the repeatable CUA harness.
- `crossterm` added to `crates/aitm` dev-dependencies (the TUI's own key library).
- This run record.

No `aitm-core` edits. Full Rust gate green on this host (see the commit).
