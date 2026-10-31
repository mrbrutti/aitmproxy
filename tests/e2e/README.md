# aitmproxy end-to-end test suite

Real, repeatable scripts that boot a **real** `aitm` core, drive **real** traffic,
and assert on **independently-observed ground truth** — never fixtures, never
frozen expectations. This is the suite we re-run to verify the app actually works,
growing to cover every command / feature / protocol across every surface.

Design rationale, the full matrix, and the tier split are in the spec/plan:
`docs/superpowers/specs/2026-10-30-aitmproxy-e2e-real-test-framework-design.md`
and `docs/superpowers/plans/2026-10-30-aitmproxy-e2e-real-test-framework-plan.md`.

## Why this exists

The macOS app and web UI shipped broken despite all-green tests, because those
tests rendered fixtures / drove in-process models / froze their expectations; and
the live harness that should have caught it (`apps/web/scripts/selftest-live.mjs`)
drifted RED (a hard-coded 37-tool list, the wrong token under policy, frozen
"the core lacks X" assertions) and stopped being trusted. So every suite here:

1. **Real artifact** — a real `aitm` core (real proxy, bus, plugins), real traffic,
   and real clients/UIs; never an in-process model or a snapshot.
2. **Independent observer** — assert on something the tool under test does not
   control: the upstream echo-record server, a real client (`curl`, obscura), the
   real bound socket (`proxy.status`), the findings store on disk. Never "the
   panel says installed".
3. **Derived expectation** — the tool set comes from live `tools/list` reconciled
   against the Rust `EXPECTED_TOOLS` contract (`crates/aitm/tests/frontends.rs`);
   never a hard-coded count, list, or "not-yet-implemented" assertion.

## Layout

```
tests/e2e/
  run.py              the runner (discovers + runs suites, exit-code gate)
  README.md           this file
  aitm_e2e/           the shared Python harness library (import from here)
    core.py           Aitm.server(...) / Aitm.web(...) — boot a real core
    bus.py            BusClient — MCP over loopback-TCP (operator AND agent)
    config.py         CoreConfig — per-run config on DEDICATED free ports
    upstream.py       Upstream — the HTTP echo-record independent observer
    proxyutil.py      via_proxy(...) — a real client request through the proxy
  lib/
    contract.sh       exit-code + manual-pause helpers for non-Python suites
  <surface>/          one dir per surface: web, proxy, ca, poc, findings,
                      scripting, l4, core, ne, tui, ...
    test_*.py         a scenario (python3), or
    *.sh              a conformant shell/cargo suite (bash)
```

Each surface session owns its own `tests/e2e/<surface>/` dir, so additions merge
without collision. **Do not** build a second harness — reuse `aitm_e2e`.

## The contract (every suite obeys this)

A suite is a standalone executable that signals its result by **exit code**:

| exit | meaning |
|---|---|
| `0` | PASS |
| `77` | SKIP (print a one-line reason first; e.g. a missing real dependency) |
| other | FAIL |

Python suites use the helpers in `aitm_e2e` (`check`, `ok`, `fail`, `skip`,
`section`); shell suites `source tests/e2e/lib/contract.sh` (`e2e_pass`,
`e2e_skip`, `e2e_fail`, `e2e_check`, `e2e_pause`). The runner exits non-zero iff a
required suite FAILs; SKIPs are loud and never read as green.

## Tiers (tag a suite with `# e2e: tier=...`)

- **T0** — the in-process Rust suite (`cargo test`); kept, not re-implemented here.
- **T1** — this Python bus suite on a real runner (the merge gate): real core +
  real traffic + real obscura (gated on `AITM_OBSCURA=1`) + `aitm-testtarget`.
- **T2** — real-Mac GUI / sysex (macOS app, Network Extension); tag `tier=manual`
  for steps needing a human (e.g. the macOS trust-store or sysex approval clicks).
- **T3** — DVWA / blind-agent capstone; real machine, not CI-reproducible.

A `tier=manual` suite is **skipped unless** the runner is given `--manual`, in
which case it may `pause(...)` / `e2e_pause` for the operator.

## Running

Port binding / running `aitm` happens on a real shell (the Claude Terminal panel),
never the sandbox. Build the binary first (`cargo build -p aitm`).

```bash
cargo build -p aitm                         # build the core under test
python3 tests/e2e/run.py                    # run all auto suites
python3 tests/e2e/run.py web proxy          # only these surfaces
python3 tests/e2e/run.py --list             # list discovered suites
AITM_OBSCURA=1 python3 tests/e2e/run.py     # require real obscura for browser cells
python3 tests/e2e/run.py ne --manual        # include manual (human-in-the-loop) steps
```

Env: `AITM_BIN` (path to the `aitm` binary; default `target/debug/aitm`),
`AITM_OBSCURA=1` + `AITM_OBSCURA_BIN` (require/locate real obscura),
`AITM_E2E_MANUAL=1` (set by `--manual`).

## Adding a suite

1. Put `tests/e2e/<surface>/test_<flow>.py` (or a conformant `*.sh`).
2. `from aitm_e2e import ...`, `from aitm_e2e.core import Aitm`, etc.
3. Boot with `CoreConfig(... DEDICATED free ports ...)` so you never collide with
   the operator's running app (don't use the defaults 8080/8081/8082).
4. Assert on an **independent observer**, not a fixture or the proxy's own view.
5. Connect at the **right role**: `BusClient.operator(core)` or `.agent(core)`;
   assert the operator/agent asymmetry rather than stumbling into a refusal.
6. Clean up by your own child PID only (the core reaps obscura on stop) — never
   `pkill -f obscura` (it kills concurrent sessions).
7. Never log the bus token.

## Two core models: own-core (default) vs shared-core (`--shared-core`)

Most cells boot their own core per run (isolated, parallel-safe). Some cells
instead attach to a **runner-provided shared core** via env (`AITM_BUS_ADDR`,
`AITM_BUS_TOKEN`, optional `AITM_BUS_OPERATOR_TOKEN`, `AITM_PROXY_ADDR`,
`AITM_TARGET_URL`) and SKIP when it is absent — they isolate on that one core via
per-connection client labels + unique markers (e.g. `audit`, and the `proto`
edge cells). Run those with `--shared-core`, which boots one core + echo upstream
and exports that env:

```bash
python3 tests/e2e/run.py audit proto neg --shared-core   # env-model surfaces
python3 tests/e2e/run.py                                  # everything else (own-core)
```

`--shared-core` is **targeted, not blanket**: don't run it across own-core cells
that mutate global state (scope / config / sessionio) — on one shared core they
cross-contaminate. The merge gate is the default `run.py` (own-core; env-model
cells skip loudly) plus a separate `--shared-core` run over the env-model surfaces.

## Run matrix (which rig runs which surface)

Every cell is real and runnable; the capability-gated ones SKIP (77) cleanly in the
headless gate and RUN in the rig that has their dependency. Each gated cell names the
missing dep in its SKIP line.

| rig | how to run | surfaces that RUN | notes |
|---|---|---|---|
| **Headless gate** (CI/dev) | `cargo build -p aitm -p aitm-testtarget` then `run.py` | smoke, surface, request, ws, mcp, passthrough, web, scope, config, sessionio, map, start, neg, flow, proto, ca, poc, findings, scripting, `browser/test_browser_scope_ssrf` | own-core / self-booting; no external deps |
| **Headless, shared-core** | `run.py --shared-core status protocol edits audit …` | status (needs `lsof`), protocol, edits, audit, and other env-model cells | one booted core + echo upstream; env-model cells attach, else SKIP |
| **obscura rig** | `AITM_OBSCURA=1` (+ `AITM_OBSCURA_BIN`), then `run.py browser` | `browser/test_browser_navigate` (full nav + captured flow + DOM) | without obscura it SKIPs; `browser_scope_ssrf` already runs headless |
| **L4 / NE rig** | an `l4.enabled` core + a CONFIG loopback capture scope + raw-capture privilege (libpcap/BPF; macOS NE approved+enabled), exported via `AITM_BUS_ADDR`/`AITM_BUS_OPERATOR_TOKEN`/… then `run.py --shared-core l4` | l4 (both cells) | SKIPs with the precise missing piece when any is absent |
| **aitm-tui present** | `cargo build -p aitm-tui` (or it on `$PATH`/`AITM_TUI_BIN`), then `run.py tui` | tui (both cells) | drives the real `aitm-tui` in a pty; SKIPs when the binary is absent |
| **real-Mac / sysex** (T2) | on a real Mac, `run.py ne --manual` | ne, the macOS app + Network Extension | `tier=manual` steps `pause()` for the operator (trust-store / sysex approval clicks) |

The **merge gate** is the first two rows (headless own-core + headless shared-core): all
PASS or loud-SKIP, zero FAIL. The remaining rows are the live rigs that turn those SKIPs
into real PASSes where the hardware/privilege/binary exists.
