# macOS L4 operator surface — CUA (real pixel-click) acceptance run record

**Stage 5 (Testing) · L4OPS-AC14 (macOS CUA) + L4OPS-AC18 (macOS honest degradation)**
Spec: `docs/superpowers/specs/2026-10-28-aitmproxy-l4-operator-surfaces-design.md`
(§4.3 CUA, Part 7, §Resolved-decisions macOS). Plan: Task 17.
Branch base: `feat/l4-operator-surfaces` @ `021793a`. Host: macOS (this Mac). Date: 2026-10-29.

## What this proves

The M4 acceptance bar held for L4 on the macOS surface, the **human-driven (CUA)
way**: a real operator drives the built app with **real input events** —
`CGEvent` pixel clicks (`tools/cgclick.swift`) and Accessibility key events — not
the MCP bus and not in-process synthesized events. This is the sibling of the
agent-driven (MCP) acceptance in Task 16 (`crates/aitm/tests/l4_acceptance_mcp.rs`).

The surface was exercised against the app's **own embedded Session core** in two
configurations, because the macOS story is CLI/Linux-first (spec §Resolved-1):

- **Run A — capable core** (default fixtures, `l4EmbeddedCore=false`): the surface
  drives L4 fully. This stands in for AC18(c) *"pointed at a privileged core over
  the bus, drives L4 fully"* — the macOS UI renders every control and the full
  craft → confirm-over-the-wire path works. A genuinely **privileged raw-L4 core
  is Linux/elevated** and is proven on the wire, agent-side, by Task 16's MCP
  suite under `AITM_L4_TESTS` on a privileged Linux host; this Mac cannot open
  `CAP_NET_RAW`/`/dev/bpf`, so no real packets leave this host here (and none are
  faked).
- **Run B — embedded user-level core** (`APP_L4_EMBEDDED=1`, `l4EmbeddedCore=true`):
  the self-contained app's core runs as the user and **cannot** do raw L4. The
  surface still renders and the pure/read verbs work, but the wire verbs degrade
  **honestly** — the degraded banner names the Phase-2 Network/System Extension,
  and Inject is disabled. No fake success (AC18 a/b).

## How to reproduce

```bash
cd apps/mac
./build.sh                 # bama pipeline, Terminal panel; installs ~/Applications/Aitmproxy.app
tools/cua-l4.sh            # needs Accessibility + Screen-Recording for the terminal
```

`tools/cua-l4.sh` launches the real app on a `/tmp` fixture store, normalises and
resizes the window to a known origin, and drives it by pixel/key events. It
selects an L4 flow by focusing the list and walking the selection with the Down
arrow (SwiftUI's in-window AX tree is unnamed, so the pixel/key path is used, as
the foundation's `cua-clickthrough.sh` documents). Each asserted step is verified
by an AX sheet-count probe and/or a `screencapture`+`md5` region diff, and writes a
proof screenshot to `/tmp/cua-l4-*.png` (copied into this folder).

## Result — `CUA L4 ACCEPTANCE PASS` (exit 0)

```
===== RUN A — capable core (drives L4 fully) =====
PASS L4 flow selected — inspector rendered (shot a1)
PASS Craft tab opened the PacketSpec editor (shot a2)
PASS Build parsed the spec and showed the build() hex preview (shot a3)
PASS Inject opened the confirm-over-the-wire dialog (0 -> 1 sheets, shot a4)
PASS Out-of-scope L4 session rendered dimmed (shot a5)
PASS Agent panel with L4 capability toggles rendered (shot a6)
===== RUN B — embedded user-level core (honest degradation, AC18) =====
PASS Embedded core: degraded L4 surface rendered (shot b1)
PASS Embedded core: Craft build() still works (pure verb, shot b2)
PASS Embedded core: Inject is disabled — no confirm sheet, no fake success (0 -> 0)
CUA L4 ACCEPTANCE PASS
```

## Evidence, step by step (real clicks)

| Shot | What the real clicks exercised | AC |
|---|---|---|
| `cua-l4-a1-inspector.png` | L4 flow `seq60` selected in the unified flow list — the **slate/indigo `L4` badge** on rows 60/61/62; the inspector shows the **packet list** (4 pkts incl. one `injected`), the **layer tree** (`IPv4 └ UDP`), the **hex** note, and the documented-limited intercept bar. | AC7, AC8, AC12 |
| `cua-l4-a2-craft.png` | The **Craft** tab opens the human-authored `PacketSpec` (YAML) editor pre-filled with a loopback UDP spec. | AC8 |
| `cua-l4-a3-build.png` | **Build** parses the spec via `l4.craft` and shows the `build()` hex preview (`45 00 00 2e …`) + `36 B · IPv4 · UDP`. | AC8 |
| `cua-l4-a4-confirm.png` | **Inject…** opens the confirm-over-the-wire dialog: *"Inject 1× IPv4/UDP (37 B) to **127.0.0.1:9 on lo0** — **in scope lo0 127.0.0.1/32 →** · **permit budget 64 pps**. Re-send with _confirm to put it on the wire."* — destination + packet summary + scope + permit budget, all present. | AC10 |
| `cua-l4-a5-oos.png` | `seq61` (out-of-L4-scope TCP) renders **dimmed** with the **"out of L4 scope"** badge and an "out of scope" header; mutating actions disabled. | AC9 |
| `cua-l4-a6-agent.png` | The Agent panel's **L4 capability toggles reflect the gates**: Capture **ON**, Inject/Intercept/Widen **OFF** — matching the fixture `l4.allow_agent_*` gates. The activity log also shows the CUA's own `l4.craft` / `l4.inject` as **operator** actions, confirming the clicks drove the command path. | AC11 |
| `cua-l4-b1-degraded.png` | **AC18 embedded core:** the degraded banner — *"L4 wire verbs unavailable … This app's embedded core runs as you and cannot open raw sockets, /dev/bpf or NFQUEUE. A macOS Network/System Extension (Phase 2) will provide the local capture path; until then, point the app at a privileged core (Linux, elevated, or remote) over the bus to drive L4."* — while the packet list, layer tree and hex still render. | AC18 (a/b) |
| `cua-l4-b2-craft-build.png` | Embedded core: **Craft build() still works** (pure `l4.craft`, no wire). | AC18 (a) |
| `cua-l4-b3-inject-disabled.png` | Embedded core: **Inject is disabled** — clicking it opens no confirm sheet (0 → 0). The wire verb is honestly unavailable, never faked. | AC18 (b) |

## Privileged / Linux-gated steps (not run on this host)

- **send_recv echo and in-path intercept Forward/Mutate/Drop** on **real packets**
  are Linux/elevated (`CAP_NET_RAW` / `CAP_NET_ADMIN` / NFQUEUE). On macOS the
  intercept bar correctly renders **documented-limited** (visible in every shot),
  and those verbs are proven agent-side by Task 16 under `AITM_L4_TESTS` /
  `AITM_L4_INPATH` on a privileged Linux host. The macOS CUA proves the **surface,
  the guard-confirm handshake, and the honest degradation** — not raw packets on
  this Mac (none were faked).
- Pointing the macOS UI at a **real** privileged core over the bus (AC18 c, full
  drive) is Linux/elevated-gated; Run A demonstrates the identical UI path against
  a capable (fixture) core.

## Test affordance added (test-only, flagged for the panel)

The embedded-core honest-degradation UI (`L4Availability.resolve(embeddedCore:…)`,
the degraded banner, the disabled wire verbs) was already built and unit-tested
(`AitmproxyKitTests/L4Tests.swift::macos_embedded_core_degrades`). To reach that
state with **real clicks** (not a programmatic snapshot), the CUA harness needs to
launch the fixture session as the embedded core. `loadFixtures()` now reads a
single env hook:

```swift
if ProcessInfo.processInfo.environment["APP_L4_EMBEDDED"] == "1" { l4EmbeddedCore = true }
```

This is **test-only plumbing**, consistent with the file's existing `APP_*` test
hooks (`APP_FIXTURES`, `APP_SNAPSHOT`, `APP_KIT_GALLERY`, `APP_LIVE`). It changes
no default behaviour — the real connection model (core-connection) sets
`l4EmbeddedCore` from the core the app actually drives. Flagged here for the
Stage-6 panel.

## Gates

- `./build.sh` (bama pipeline, Terminal panel) — EXIT 0, no new warnings.
- `swift test` — **229 tests / 46 suites** + **24 tests / 4 suites** pass (incl.
  `L4Tests`). EXIT 0.
- Rust gate (`cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test`) — see the commit message / Stage-5 report for the recorded exit
  code (no Rust sources were touched by this task).
