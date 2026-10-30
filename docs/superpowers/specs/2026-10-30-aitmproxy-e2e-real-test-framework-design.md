# End-to-end real-test framework design

**Status:** draft
**Research inputs:** `docs/research/05-synthesis.md`; the M4 agent-milestone spec (`docs/superpowers/specs/2026-10-27-aitmproxy-m4-agent-milestone-design.md`, the ancestor of this gate); the DVWA tool-fixes spec (`docs/superpowers/specs/2026-10-29-dvwa-tool-fixes-design.md`); the scanner active-backend spec (`docs/superpowers/specs/2026-10-30-aitmproxy-scanner-active-backend-design.md`); `docs/research/MEMORY.md`. Source verified in this worktree 2026-10-30 (see each cited file:line); current-state facts from the sibling ground-truth/UX-audit notes in the group notes folder.

## Intent

Today aitmproxy shipped a macOS app that **passed every test it had** — Swift unit tests, snapshot tests rendered with fixture data, a `/tmp` self-test, and a live-bus self-test — and was still **broken in the hands of the operator**: the embedded core was not bundled (`build.sh` silently skipped it), the app pinned to a stale external-mode `UserDefaults`, the window header showed the preferred port instead of the real bound port, `ca.install` silently failed while the CA panel's fixture hard-coded "Installed · trusted", and Settings rendered the bus port as "9,090" (locale grouping). The web UI's flow list freezes because it never subscribes and the `/bus` bridge pushes nothing. None of these are catchable by a test that renders fixtures, drives an in-process model, or asserts against frozen expectations.

Worse, the two out-of-band live harnesses that *were* meant to catch this class of bug have **drifted RED and are no longer trusted**: `apps/web/scripts/selftest-live.mjs` asserts an exact hard-coded list of 37 tools (the core now registers 67), connects as an **agent** so every `Sensitive` command is refused under the default `Auto` policy, and carries "gap" assertions that now throw because the core shipped the feature (`ws.*`, kill-modes, `agent.*`). A gate nobody trusts is not a gate.

This framework is one **real, agent-driven, end-to-end testing framework** that exercises the actual tools through **real traffic** across **all supported layers and protocols**, drives the **real UIs** through their real paths, asserts on **independently observed ground truth** (not fixtures), **derives every expectation from the live system** (so it cannot drift silently-green or stuck-red), and **replaces the drifted harnesses with one trustworthy green gate**. We want it now because the product is shipping to real operators and the current test suite is structurally blind to exactly the bugs operators hit.

## Goals

Observable outcomes:

- **One framework, prescriptive Python scenario scripts.** A Python harness library plus one script per feature/flow that drives the MCP/bus command surface against a **real running `aitm` core** producing **real traffic**, connecting as **operator and/or agent** as each command's gating requires, and asserting on real outcomes. `make e2e` (or the documented per-tier command) runs it and exits non-zero on any real failure.
- **Every feature tested for real, asserted on ground truth.** Capture appears live (a subscriber sees the flow); flow detail shows the real decrypted body (byte-equal to what the upstream received/sent); intercept→hold→edit→resume **mutates the upstream request** (confirmed by the upstream, not by the proxy's own view); replay re-hits the upstream; WS inject lands on the upstream; scope confinement refuses out-of-scope egress; `scan.discover` enumerates the seeded injection points (and `scan.inject`/`scan.run` confirm-on-vulnerable/fail-on-patched once shipped); `poc.run` reproduces (pass on vulnerable, fail on patched, three artifacts); findings persist across a restart and never carry a secret; `ca.export`/`ca.status` report real state and a **real external client trusts the CA** and completes an MITM TLS handshake; L4 capture captures real TCP/UDP flows.
- **All supported layers and protocols covered:** HTTP/1.1, HTTP/2, WebSocket, TLS MITM (L7), and L4 TCP/UDP including the macOS Network Extension path.
- **Real obscura and real clients.** The framework fetches and drives the real forked **obscura** engine (`scripts/fetch-obscura-dev.sh`, gated on `AITM_OBSCURA=1`), the hermetic `aitm-testtarget` for the reproducible gate, and real external clients (`curl`, a real browser) where they add coverage; the DVWA/bWAPP real-target capstone is a documented real-machine tier.
- **The whole command/MCP surface all three UIs share is covered, and each UI's real path is driven.** The bus surface (every registered tool) is exercised at the right role; the web UI is driven over its real `/bus` bridge; the TUI over its real bus attach; the macOS `.app` is launched for real — each with an explicit label of what is CI-headless-able vs what needs a real Mac / GUI / sysex / computer-use.
- **It supersedes the drifted harnesses.** `apps/web/scripts/selftest-live.mjs` and the drifted macOS live `.sh` harnesses are retired; their real assertions are folded into this framework; the result is one green gate plus the existing in-process Rust e2e suite it complements (not duplicates).
- **It cannot drift.** Expectations are derived from live sources (`tools/list`, command `inputSchema`, `proxy.status`), the Rust `EXPECTED_TOOLS` contract is the single tool-name source of truth, and a **coverage ledger** fails the gate when a newly registered tool has no scenario — the structural opposite of a frozen hard-coded list.

## Non-goals

- **Not a replacement for the in-process Rust `cargo test` e2e suite.** The existing hermetic Rust tests (`crates/aitm/tests/m4_scripted_e2e.rs`, `m4_grader_gate.rs`, `e2e_reflected_xss.rs`, `discover_e2e.rs`, `web_bus_roles.rs`, `tui_live_bus.rs`, `l4_acceptance_mcp.rs`, and the protocol-level `h2_mitm`/`ws_capture`/… tests) stay and remain the first gate. This framework covers the **bus / real-UI / real-client / real-browser boundary** those tests cannot reach from inside the process; it does not re-implement them in Python.
- **Not product code.** This spec adds a test framework and scenario scripts (Python + fixtures + a thin macOS test bridge if needed). It does **not** change `aitm-core`, the protocol crates, or the UIs' behaviour. If a scenario cannot assert a real outcome because a product seam is missing (e.g. no programmatic way to read the macOS app's rendered bound port), it **records a product follow-up**, it does not add the seam here.
- **Not a new scanner, PoC format, findings model, or policy model.** It drives the shipped surface. `scan.inject`/`scan.run` coverage is written against the active-backend spec's shapes but is **blocked until that backend ships** (today only `scan.discover` is registered).
- **No GitHub-hosted-CI assumption.** The Claude Bash sandbox cannot bind ports, build Swift, run Docker, or reach GitHub; "CI-headless" here means a real macOS/Linux runner driven through the Terminal panel (or a self-hosted runner), not a hosted GitHub Actions box. The split below is explicit about which tier needs what.
- **No mutation of the operator's real OS trust store or real browser profiles as a silent side effect.** The CA-trust assertions use a throwaway trust context (`curl --cacert`, `obscura --ca-cert`, a per-run browser profile) by default; the genuine OS-trust-store install (`ca.install`) is a Tier-2 real-Mac test run against a disposable/opt-in trust context, never the operator's default store without explicit opt-in.

## Anti-goals

- **A test that passes against a fixture.** If a scenario asserts on data the tool-under-test supplied to itself (a hard-coded panel value, a snapshot, the proxy's own record of what it forwarded) rather than on an independent observer (the upstream echo, a real client, the real bound socket), it has reproduced the exact failure mode that let the macOS app ship broken, and the framework has failed its purpose.
- **A frozen expectation.** Any hard-coded tool count, tool list, or "the core does not yet have X" gap-assertion reintroduces the drift that killed `selftest-live.mjs`. Expectations are derived or declared-in-one-place (the Rust contract); a changed surface changes the gate's view automatically or fails loudly with a one-line fix, never silently.
- **A gate that is green because it skipped.** A scenario whose real dependency is unavailable (no obscura, no Mac, no Docker) must **SKIP loudly with a reason and a tier label**, and the aggregate gate must distinguish "all required PASS" from "required PASS + optional SKIP". A silent skip that reads as green is a failure.
- **Wrong-role refusals read as feature failures.** A scenario that fails because it used the agent token for an operator-only command (the `selftest-live.mjs` bug) is a harness bug, not a product bug. Role selection is derived from the command's live sensitivity/gating; the operator/agent **asymmetry itself** is asserted as a positive test, not stumbled into.
- **Cross-session collateral damage.** A browser/obscura scenario that runs `pkill -f obscura` or a machine-wide `pgrep` kills or false-fails sibling Claude sessions (`[[aitmproxy-obscura-multisession-hazards]]`). Process lifecycle is scoped to the scenario's own child PIDs, always.
- **A flaky gate.** The known non-deterministic `rhai_e2e::script_cannot_escape_or_exceed_scope` flake (`[[aitmproxy-rhai-e2e-flaky]]`) and any browser timing flake must be quarantined or retried with a declared policy, never left to redden the shared gate at random.

## Constraints

- **Environment (hard).** The Claude Bash sandbox: `cargo` works offline **after** a Terminal-panel fetch; **port binding is EPERM**; `.git`/GitHub are blocked; `open`/`osascript` are blocked (`[[aitmproxy-sandbox-cargo]]`, `[[aitmproxy-sandbox-protocol-extensible]]`, CLAUDE.md). Therefore: Tier-0 Rust tests run in-sandbox (no sockets) or via Terminal; **everything that binds a port, spawns a browser, builds Swift, or touches git/gh runs through the Terminal panel** (`run_in_terminal`) on Matt's real shell. The framework's runner must assume a real shell, not the sandbox.
- **One-shot CLI cannot steer a running core (hard).** `aitm <family> <verb>` builds a **fresh empty in-process core**, runs one command, and exits; it cannot see or steer the flows of a running `aitm`/`aitm web`/`aitm tui` (ground-truth note; `crates/aitm/src/main.rs` mode dispatch). Any assertion on live flows **must** drive a UI/MCP connection over the bus against a running core — never shell out to one-shot CLI for live state. (One-shot CLI is still fine for output-shape checks and for the `!= Cli` fully-trusted commands where a running core is not involved.)
- **Role and gating are real and layered (hard).** Three gating layers, all enforced in the core (`crates/aitm-mcp/src/server.rs:1549-1592`, per-command gates in the plugins): (1) the agent-policy gate (`Read`/`Write`/`Sensitive` × `All`/`Auto`/`Ask`/`ReadOnly`/`Paused`), (2) per-command config gates (`*.allow_agent_*` agent gates and `!= Cli` fully-trusted gates), (3) the operator confirm-over-the-wire `_confirm` handshake. The default command `sensitivity()` is **fail-closed `Sensitive`** (`crates/aitm-core/src/command.rs:76`). The harness must model these to pick the right role, set the right config flags per scenario, and perform the confirm handshake — and must assert them as behaviour.
- **Hermetic reproducible gate, real-world capstone.** The merge-gating tiers use only the hermetic `aitm-testtarget` (no external network) and, where a browser is needed, real obscura gated on `AITM_OBSCURA=1`. DVWA/bWAPP (Docker/Lima, host ports, real third-party traffic) is **not CI-reproducible** and lives in a separate real-machine capstone tier.
- **Secrets and hygiene.** The framework never prints the bus/operator token into logs or assertions (`[[aitmproxy-operator-first-run-hygiene]]`); it scopes obscura cleanup to its own child PIDs; it gates the run on process exit codes, never a `grep|tail` pipeline (`[[gate-exit-status-not-grep]]`); it uses `git push origin <branch>` only when the workflow calls for it.
- **This is docs-only.** The framework described here is built later through the normal seven stages; this spec and its plan change no product code and ship as a PR of two documents for Matt's approval.

## Design

The decided parts of the *how*. Architect defaults are marked **(Architect's call)**; the genuinely-Matt decisions are in Open questions.

### D0. The one principle everything derives from

**Assert on ground truth at the real boundary, and derive every expectation from the live system.** The two failure modes this framework exists to kill are *testing a fake* and *trusting a frozen expectation*. So every scenario obeys three rules:

1. **Real artifact.** A real `aitm` core (its real proxy, bus, plugins), real traffic (a real client → the proxy → a real upstream), and — for UI coverage — the real UI binary/app, not an in-process model or a snapshot.
2. **Independent observer.** The assertion reads an observer the tool-under-test does not control: the **upstream echo server** records exactly what bytes/headers/method it received; a **real external client** (`curl`, obscura, a browser) reports whether the TLS handshake and body round-tripped; `proxy.status.address` reports the **real bound socket**; the **findings store on disk** survives a restart. Never "the panel says installed".
3. **Derived expectation.** The set of tools comes from live `tools/list` reconciled against the Rust `EXPECTED_TOOLS` contract; argument shapes come from each tool's `inputSchema`; the bound port comes from `proxy.status`. No scenario hard-codes a count, a list, or a "not-yet-implemented" assertion.

### D1. Architecture — the Python harness over the real bus

The framework is a Python package `tests/e2e/aitm_e2e/` (**(Architect's call)** on name/location; Matt confirms in Open questions) plus prescriptive scenario scripts. Python because (a) Matt asked for prescriptive Python scripts, (b) the three UIs are all clients of **one** bus so a single Python MCP client reaches the whole surface, and (c) Python unifies today's split Node (`.mjs`) + Swift (`.sh`) harnesses and orchestrates across languages (spawn the Rust core, drive `curl`, drive obscura over CDP, drive the macOS app over a bridge) in one place.

**Harness library (the reusable machinery):**

- **`CoreProcess`** — boots a real `aitm` core for a scenario with a generated per-run config: both tokens (`mcp.operator_token` + agent token), scope entries, `findings.dir`, `poc.dir`, the exact `*.allow_agent_*` flags the scenario needs, `l4.enabled` when L4 is in play, and a `--bus-endpoint-file` rendezvous so the harness learns the real bound bus address without parsing stdout for secrets. Supervises the child; on teardown kills **only its own child PID** and removes the per-run workdir. Never run bare in-sandbox (binds ports) — Terminal-panel/real-shell only.
- **`BusClient`** — a typed MCP client over the three transports (loopback-TCP, stdio, and the `/bus` WebSocket). It sends the token line, `initialize`, caches `tools/list` (names + `inputSchema` + `sensitivity` + `confirmable`), and exposes `call(tool, args, *, role)`, a subscribe/notification reader for `notifications/aitm/{flow,state,agent}`, and a `confirm(tool, args)` helper that performs the two-phase `_confirm` handshake for the operator role. Two instances per scenario where needed: one **operator**, one **agent**, so the asymmetry is testable.
- **`Upstream`** — the independent HTTP/1.1 + HTTP/2 + WebSocket **echo/record** origin (real sockets, loopback). It records every request (method, path, headers, raw body) and every WS frame it received, and serves deterministic responses, so a scenario proves "the mutated/injected/replayed thing actually reached the upstream" by reading the upstream's record, not the proxy's. (**(Architect's call)**: a small Python `hypercorn`/`aiohttp` app, or reuse `aitm-testtarget-serve` for the seeded-vuln paths and add a thin echo origin for the mutate/replay/WS/H2 assertions.)
- **`Target`** — launches `aitm-testtarget-serve --mode {vulnerable|patched} --port 0` (prints `listening http://127.0.0.1:<port>`), the seeded-vuln origin for scan/PoC/findings scenarios. Vulnerable and patched instances both available so the "pass-on-vulnerable, fail-on-patched" bar is real.
- **`Browser`** — fetches obscura via `scripts/fetch-obscura-dev.sh` if absent (honouring `AITM_OBSCURA_BIN`), drives it over CDP pointed at the proxy with `--ca-cert`, and tears down by its own child PID. Gated on `AITM_OBSCURA=1`; SKIPs loudly otherwise. Also wraps `curl --cacert` and (Tier 2) a real system browser with a per-run profile.
- **`GroundTruth`** — the assertion helpers that read the independent observers: `upstream.received(...)`, `proxy_status().address`, `findings_on_disk(dir)`, `client_trusts_ca(client, url)`, `ca_status()` vs a real trust probe.
- **`Ledger`** — the anti-drift coverage tracker (D3).

**Scenario scripts** — one per feature/flow (Matt's ask), each a small arrange→act→assert using the library, named for its matrix cell (e.g. `t1_http1_intercept_mutate_resume.py`, `t1_ws_inject.py`, `t1_ca_real_client_trust.py`, `t2_macos_embedded_core_bundle.py`). A scenario declares its **tier**, its **required capabilities** (`needs: [obscura]`, `needs: [mac-gui]`, `needs: [docker]`), and the **tools it exercises** (feeding the Ledger).

### D2. The test matrix (layers × protocols × features × surface)

Each cell names the real assertion and the independent observer. Tier in brackets: **T0** existing Rust `cargo test` (kept, referenced, not rebuilt); **T1** Python bus suite on a real runner through the Terminal panel (the merge gate); **T2** real-Mac GUI/sysex (manual/Terminal, signed off); **T3** real-target capstone (demo-grade).

| Feature / flow | Protocol(s) | Real assertion (observer) | Role | Surface | Tier |
|---|---|---|---|---|---|
| Capture appears live | H1, H2, WS, TLS | a `flow.subscribe` sees `notifications/aitm/flow` for real traffic; `flow.list` count grows (bus) | operator+agent | bus | T1 |
| Flow detail = real decrypted body | H1/H2/TLS | `flow.detail` body byte-equals what `Upstream` received/sent (upstream record) | agent | bus | T1 |
| Intercept→hold→edit→resume mutates upstream | H1, H2 | `Upstream.received` shows the **edited** method/path/headers/body (upstream record) | operator (arm) + agent | bus | T1 |
| Response-phase edit | H1 | client sees the edited response; `flow.mutate` response path (client record) | operator | bus | T1 |
| Kill (reset/503/429) | H1 | client connection reset/sees 503; `Upstream` never received it (upstream record) | agent | bus | T1 |
| Replay | H1/H2 | `Upstream` records a second identical request after `flow.replay` | agent | bus | T1 |
| Crafted request (`request.send`) | H1/H2 | in-scope reaches `Upstream`; out-of-scope refused with scope error | agent | bus | T1 |
| WebSocket inject + frame edit | WS | `Upstream` WS endpoint records the injected/edited frame | operator | bus | T1 |
| Scope confinement / SSRF guard | H1/TLS/browser | out-of-scope egress refused; obscura confined to scope (`egress.probe`/upstream never hit) | operator+agent | bus+browser | T1 |
| TLS MITM fidelity + real client trusts CA | TLS (H1/H2) | `curl --cacert <export>` and obscura `--ca-cert` complete the handshake and get the real body; `ca.status` matches a real trust probe | operator | bus+real client | T1 |
| CA install into a real OS trust store | TLS | `ca.install` then a **real system browser** trusts the MITM cert (disposable/opt-in trust context) | operator (confirm) | bus+real browser | T2 |
| `scan.discover` finds seeded injection points | H1 | discovered points/params match the seeded routes (vs the grader-only manifest, never shown to the driver) | agent | bus | T1 |
| `scan.inject`/`scan.run` confirm vulns | H1 | confirm on `Vulnerable`, not on `Patched` (when the active backend ships) | operator/agent-gated | bus | T1 (blocked until shipped) |
| PoC build+run reproduces | H1/browser | `poc.run` passes on vulnerable, fails on patched; 3 artifacts on disk | operator (or agent w/ `poc.allow_agent_run`) | bus | T1 |
| Findings persist + redact | — | `findings.record` → restart core → `findings.list` returns it; no secret (`Bearer abc123`) anywhere in the record | agent (record) + operator | bus+disk | T1 |
| L4 TCP/UDP capture + craft/inject/intercept | L4 | real UDP echo / TCP banner through `aitm-testtarget` L4 service appears in `l4.flow.list`; craft/inject/intercept round-trip | operator + agent-gated | bus | T1 |
| L4 system-wide capture via macOS NE | L4 | real system traffic captured through the Network Extension sysex path | operator | macOS NE | T2 |
| Full MCP surface coverage + role asymmetry | all | every registered tool exercised ≥once at a valid role; agent-refused/operator-allowed asymmetry asserted; `_confirm` handshake works | operator+agent | bus | T1 |
| Web UI real path + **live streaming** | H1/TLS | over the real `/bus` bridge, the flow list updates under live traffic without reload (the current freeze bug) | operator | web UI | T1 (headless browser) |
| TUI real path | H1 | `aitm-tui` attaches over the bus and reflects live flows/intercept | operator | TUI | T1 (pty) |
| macOS `.app`: embedded core bundled + launches | — | the shipped `.app` bundle **contains** a core binary and launches it; a real `curl` through the embedded proxy reaches upstream | operator | macOS app | T2 |
| macOS `.app`: real bound port in header, no stale pin, port format | — | header shows `proxy.status.address` (bound, not preferred); a stale external pin is ignored; Settings port has no locale grouping | operator | macOS app | T2 |
| macOS `.app`: real CA trust vs fixture | TLS | the CA panel reflects real `ca.status`, and `ca.install` actually installs (real trust probe), not a hard-coded "Installed · trusted" | operator | macOS app | T2 |
| DVWA / bWAPP realistic traffic + blind agent | all | the blind-agent pentest finds/repros seeded real-world vulns through real obscura against DVWA | agent | bus+browser | T3 |

Notes: H2 and WS need an origin that speaks them (the hermetic `aitm-testtarget` is HTTP/1.1-only). The harness `Upstream` provides H2 and WS echo endpoints so these cells are hermetic and reproducible. **(Architect's call.)**

### D3. The anti-drift mechanism (why this gate stays trustworthy)

The old harness drifted three ways; each has a structural fix here:

1. **No frozen tool list.** `selftest-live.mjs` froze 37 names. Instead the Ledger pulls **live `tools/list`** from the running core and reconciles it against the Rust **`EXPECTED_TOOLS`** contract (`crates/aitm/tests/frontends.rs`) — the single source of truth the coders already bump per task. The contract check asserts *live set == contract set* and *every tool has a non-empty `inputSchema`*. A new tool changes the contract (already required by `cargo test`) and the gate tracks it automatically.
2. **No wrong-role refusals.** `selftest-live.mjs` connected as agent and got `Sensitive` commands refused. Instead each scenario's role is **derived** from the tool's live `sensitivity` + known gating (D-table in agent B's catalogue): Read/Write → agent; `Sensitive`-not-deferred → operator; `!= Cli`-gated → operator **with the config flag set** or the local CLI; confirm-prompt → operator with `_confirm`. The operator/agent **asymmetry** (agent refused without the flag, operator allowed) is its own positive scenario — the exact thing `selftest-live-embedded.sh:144-187` already proves, generalized.
3. **No frozen gap-assertions.** `selftest-live.mjs` asserted "the core does not yet have ws.*/kill-modes/agent.*" and reddened when it did. Instead there are **no absence assertions**; a capability is either exercised (if registered) or its scenario SKIPs with a reason keyed off the live surface. New capability → covered by its scenario, never a red.
4. **Coverage ledger.** At the end of a tier run the Ledger asserts **every registered tool was exercised by ≥1 scenario at a valid role** (minus a small, explicitly-listed, justified exclusion set — e.g. `agent.set` exercised only in the policy scenario). A newly registered tool with no scenario **fails the gate** — the inverse of a hard-coded count: coverage is forced to track the surface, so the gate can never go green while blind to a new tool.
5. **Flake discipline.** The `rhai_e2e` flake is excluded from this framework's gate (it is a `cargo test` concern judged by whether a change touches Rhai); browser/timing steps use a declared bounded-retry policy; the aggregate result separates PASS / SKIP(reason,tier) / FAIL and gates only on required-FAIL.

### D4. The motivating-failure → assertion map (the "would have caught it" proof)

Each shipped-despite-green bug maps to a scenario whose **ground-truth observer** would have failed before release. This table is the framework's reason to exist and its first acceptance anchor.

| Shipped bug | Layer | Scenario asserts (observer) | Tier |
|---|---|---|---|
| Embedded core not bundled (`build.sh` silent skip) | build script | the shipped `.app` bundle contains a core binary **and** a `curl` through the app's embedded proxy reaches the upstream (real bundle + real proxy) | T2 |
| App pinned to stale external `UserDefaults` | Swift state | with a stale external pin present, the app still selects/launches the embedded core (real connection mode) | T2 |
| Header shows preferred not bound port | Swift UI | the header value equals `proxy.status.address` from the real core (bound socket) | T2 |
| `ca.install` silently fails; CA fixture hard-codes trusted | core + Swift fixture | `ca.status` from the real core, and a real trust probe, both report the true state; after `ca.install` a real client trusts the cert | T2 (install) / T1 (export+trust) |
| Settings port "9,090" (locale grouping) | Swift UI | the rendered port string has no grouping separators (reads back as the integer) | T2 |
| Web flow list freezes (no live streaming) | web TS + `/bus` bridge | over the real `/bus`, the flow list grows under live traffic with no reload | T1 |

### D5. Tiering, gates, and how CI-headless splits from real-Mac/manual

- **T0 — in-process Rust e2e (`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`).** Kept as-is; the first gate; runs in-sandbox (no sockets) or via Terminal. This framework **references** it, does not rebuild it.
- **T1 — Python bus suite, real runner, Terminal panel (the merge gate for bus/UI behaviour).** Boots a real core + `Upstream` + `Target` + (optionally) obscura on loopback; drives the whole bus surface, the web `/bus` path (headless browser), and the TUI (pty). Requires a real shell with port binding; obscura-dependent cells gate on `AITM_OBSCURA=1`. No Docker, no external network, no GUI. This is the one green gate that replaces `selftest-live.mjs`.
- **T2 — real-Mac GUI / sysex (signed off, not CI).** Launches the real `.app`, drives it via the app's own real-bus self-test path and, where pixels are unavoidable, computer-use (the existing `cgclick.swift` CGEvent + `osascript` AX-menu path or the app debug bridge — **(Architect's call)**: prefer a debug-bridge/`APP_LIVE` real-bus assertion over pixels wherever the value is state, not layout). Covers the macOS motivating-failure rows and the macOS NE L4 path. Run on Matt's Mac through the Terminal panel; result recorded.
- **T3 — real-target capstone (demo-grade).** DVWA (+ bWAPP if revived) on Lima/colima with real obscura; the blind-agent pentest. Not reproducible in CI; run on a real Apple-Silicon machine, signed off like AC-M4-17.

The **aggregate gate** is: T0 green **and** T1 all-required-PASS (optional cells may SKIP with reason) ⇒ mergeable; T2/T3 are release/milestone gates run and signed off separately. Every tier emits a machine-readable result (JSON) and a human summary; the runner's **exit code** is the gate (never a grep).

### D6. Supersession — one gate, nothing orphaned

- **Retire** `apps/web/scripts/selftest-live.mjs` and the drifted macOS live `.sh` harnesses (`selftest-live.sh` where its assertions are folded; keep `selftest.sh` fixture test as a fast Swift-logic check if still useful). Their **real** assertions (capture/intercept/mutate/kill/replay/PoC over the real bus; the embedded operator-vs-agent scope proof in `selftest-live-embedded.sh:144-187`) move into T1/T2 scenarios.
- **Keep and reference** the T0 Rust e2e suite and `cua-l4.mjs`'s honest-degradation idea (fold into T1/T2 L4 scenarios).
- **Document the map** from each retired harness assertion to its new scenario, so nothing is silently dropped.
- The README/`docs/` entry states plainly: the trustworthy gate is **T0 + T1**; T2/T3 are the real-Mac and capstone gates.

### D7. Hygiene and safety baked into the harness

- Never print or assert on the token value; read the bus address from `--bus-endpoint-file` (`[[aitmproxy-operator-first-run-hygiene]]`).
- Obscura/browser teardown kills **only** the scenario's own child PIDs; no `pkill -f obscura`, no machine-wide `pgrep` (`[[aitmproxy-obscura-multisession-hazards]]`).
- Each scenario is self-contained with unique ports/dirs so parallel sessions don't collide; the disk footprint is bounded (no new full `target/` per run — reuse the worktree build; `[[aitmproxy-worktree-disk-hog]]`).
- The CA-trust scenarios default to a disposable trust context; the real-OS-trust install is opt-in and uses a throwaway store/VM, never the operator's default store silently.

## Acceptance criteria

Each is observable and testable; they are the contract the framework's own plan builds against.

1. **AC1 — real-boundary capture.** A T1 scenario drives real HTTPS/1.1 traffic (real client → proxy → `Upstream`) and asserts the flow appears via a live `flow.subscribe` notification and in `flow.list`, and `flow.detail`'s decoded body **byte-equals** what `Upstream` recorded. No fixture is read.
2. **AC2 — upstream-confirmed mutation.** A T1 scenario arms intercept (operator), parks a request, `flow.mutate`s method/path/headers/body (agent), `flow.resume`s, and asserts **`Upstream.received`** shows the edited request — the proxy's own view is not the observer.
3. **AC3 — kill, replay, craft.** T1 scenarios assert: a killed flow never reaches `Upstream`; `flow.replay` produces a second recorded upstream request; an in-scope `request.send` reaches `Upstream` and an out-of-scope one is refused with a scope error.
4. **AC4 — WebSocket inject.** A T1 scenario injects a WS frame (`ws.send`, operator) and asserts the `Upstream` WS endpoint recorded it; a frame edit via `ws.frame` is reflected downstream.
5. **AC5 — HTTP/2.** A T1 scenario drives H2 traffic (client `--http2` / obscura) through the proxy and asserts capture + decrypted body + a mutate-or-replay upstream-confirmed, proving H2 MITM, not only H1.
6. **AC6 — TLS MITM + real client trusts the CA.** A T1 scenario `ca.export`s the CA, and a **real** `curl --cacert` and obscura `--ca-cert` complete the MITM TLS handshake and receive the real upstream body; `ca.status` matches an independent trust probe. (OS-trust-store `ca.install` + a real system browser is the T2 row.)
7. **AC7 — scope/SSRF confinement.** A T1 scenario asserts an out-of-scope request and an out-of-scope browser navigation are refused/confined (the out-of-scope `Upstream` records nothing), with obscura confined to scope.
8. **AC8 — scan + PoC + findings on real seeded target.** T1 scenarios: `scan.discover` against `aitm-testtarget` enumerates the seeded injection points (matched to the grader-only manifest, which the driver never reads); `poc.run` **passes on `Vulnerable`, fails on `Patched`** and emits three artifacts; `findings.record` then a **core restart** then `findings.list` returns the finding; a secret (`Authorization: Bearer abc123`) appears **nowhere** in the record. (`scan.inject`/`scan.run` cells are present but marked blocked until the active backend ships.)
9. **AC9 — L4 capture round-trip.** A T1 scenario with `l4.enabled` drives real UDP-echo and TCP-banner traffic through the `aitm-testtarget` L4 service and asserts the flows appear in `l4.flow.list`, and a craft→inject or intercept→mutate→forward round-trips (agent-gated flags set as needed, operator confirm performed).
10. **AC10 — full-surface coverage + role asymmetry + anti-drift.** The Ledger asserts the **live `tools/list` equals the Rust `EXPECTED_TOOLS` contract** and every tool has a non-empty `inputSchema`; **every registered tool is exercised by ≥1 scenario** at a valid role (minus a declared, justified exclusion list); a dedicated scenario asserts the **agent-refused / operator-allowed** asymmetry for a representative gated command and a successful `_confirm` handshake. There is **no** hard-coded tool count/list and **no** absence assertion anywhere in the framework.
11. **AC11 — web UI live streaming over the real bridge.** A T1 scenario opens the web UI over its real `/bus` bridge (headless browser), generates live traffic, and asserts the flow list **updates without reload** — i.e. it **fails today** against the current freeze bug and passes once the UI subscribes. (The scenario is the regression test for the shipped bug.)
12. **AC12 — TUI real path.** A T1 scenario attaches the real `aitm-tui` over the bus (pty) and asserts it reflects live flows and an intercept arm/disarm from real traffic.
13. **AC13 — macOS `.app` real path (the motivating failures).** T2 scenarios assert, against the **real launched `.app`**: the shipped bundle contains and launches a core and a `curl` through its embedded proxy reaches upstream (bug 1); a stale external pin is ignored (bug 2); the header shows the real bound port from `proxy.status` (bug 3); the CA panel reflects real `ca.status` and `ca.install` actually installs per a real trust probe (bug 4); the Settings port renders without locale grouping (bug 5). Each reads an independent observer, not a fixture.
14. **AC14 — macOS NE L4 path.** A T2 scenario captures real system traffic through the Network Extension sysex path once that path ships, labelled real-Mac-only.
15. **AC15 — tiered, honest, non-flaky gate.** The runner exits non-zero iff a required cell FAILs; SKIPs carry a reason + tier and never read as green; the `rhai_e2e` flake and browser timing flakes are excluded/retried per a declared policy; the gate is driven by exit code, not a grep.
16. **AC16 — supersession documented.** `selftest-live.mjs` and the drifted macOS live `.sh` harnesses are retired, every real assertion they carried is mapped to a new scenario, and the docs name **T0 + T1** as the one trustworthy green gate.
17. **AC17 — reproducibility + hygiene.** Obscura is fetched via `scripts/fetch-obscura-dev.sh` and gated on `AITM_OBSCURA=1`; the hermetic target is `aitm-testtarget`; DVWA is the T3 real-machine capstone only; the harness never prints the token, scopes cleanup to its own PIDs, and bounds disk use.

## Left to the builder

- The harness library's internal module layout and class APIs (`CoreProcess`, `BusClient`, `Upstream`, `Target`, `Browser`, `GroundTruth`, `Ledger`), the Python packaging, and the test runner (pytest vs a bespoke runner) — provided the tier labels, SKIP semantics, JSON result, and exit-code gate hold.
- The exact `Upstream` implementation (a Python H1/H2/WS echo-record app vs extending `aitm-testtarget` with an echo mode), provided it is a real socket origin and records what it received independently of the proxy.
- The per-scenario config generation (which `*.allow_agent_*` flags, scope entries, `l4.enabled`) and the role-selection table derived from live sensitivity/gating, provided it matches the three gating layers.
- The web-UI driver (headless Chrome over CDP, reusing `cua-driver.mjs`'s approach from Python, vs Playwright-Python) and the TUI pty driver details.
- The macOS T2 approach per assertion: the app's own `APP_LIVE` real-bus self-test path, a debug bridge, or CGEvent/AX computer-use — provided the observer is ground truth, not a fixture.
- The coverage-ledger exclusion list (the few tools exercised only indirectly) with a one-line justification each.
- The retry/quarantine policy numbers for browser timing steps.
- The incremental build order within the plan's waves, provided T1 lands a usable gate before T2/T3.

## Open questions

Only Matt can answer these; each carries the Architect's recommended default.

1. **v1 scope — how much ships first?** Recommended **(Architect's call)**: v1 = **T0 (reference) + the full T1 Python bus suite** covering HTTP/1.1, H2, WS, TLS MITM + real-client CA trust, intercept/mutate/resume/kill, replay, `request.send`, scope/SSRF, `scan.discover`, PoC+findings, L4 loopback, full-surface coverage + role asymmetry + the web `/bus` live-streaming regression + the TUI path. v2 = **T2** macOS `.app` real-GUI gate (the five motivating failures) + macOS NE L4. v3 = **T3** DVWA/blind-agent capstone. Confirm, or pull T2 macOS forward (it is where the shipped bugs were).
2. **What is "CI" here, and what is the merge gate?** The sandbox can't bind ports/build Swift/reach GitHub. Recommended: the merge gate is **T0 + T1 on a real macOS/Linux runner driven through the Terminal panel** (or a self-hosted runner you provide), not GitHub-hosted CI. Is there a self-hosted runner T1 should target, or is T1 run on-demand on your Mac? And should T1 block PR merge, or run nightly + pre-release?
3. **How do real obscura and target apps run reproducibly for the gate?** Recommended: **obscura via `scripts/fetch-obscura-dev.sh`** on the runner, gated on `AITM_OBSCURA=1` (needs `OBSCURA_GH_TOKEN`/`gh` for the private release — confirm the runner has it); the **hermetic `aitm-testtarget`** is the gate's origin; **DVWA/bWAPP stay T3** real-machine-only (Docker/Lima, host ports, not CI-reproducible). Confirm obscura availability on the runner and that DVWA is capstone-only.
4. **Language/placement.** Recommended: **Python** (your ask) for T1+, living in `tests/e2e/` as `aitm_e2e/` + scenario scripts + a `make e2e` target; keep T0 in Rust; do not port T0 to Python. Confirm the Python choice and the `tests/e2e/` location, or name a different home.
5. **macOS T2 automation posture.** Recommended: prefer the app's **real-bus self-test / a debug bridge** for state assertions (bound port, CA status, connection mode), reserving **computer-use (CGEvent + AX)** for genuinely visual checks (Settings port string, panel rendering). Confirm, or require full computer-use for the macOS gate.
6. **CA real-OS-trust scope.** The `ca.install` → real-system-browser-trusts-it assertion mutates a trust store. Recommended: run it T2 against a **disposable/opt-in trust context** (throwaway profile or VM), never your default store silently. Confirm the trust context you want (a VM, a dedicated test Mac, or an explicit per-run opt-in).
7. **Does the coverage ledger block, or warn, on an uncovered new tool?** Recommended: **block** (a new registered tool with no scenario fails the gate) — this is the anti-drift guarantee. Confirm, or make the first offence a warning with a grace window.

---

### Architect's calls (recorded, for Matt to approve or correct)

1. The governing principle is **ground truth at the real boundary + derived expectations**; every scenario reads an independent observer and no scenario freezes a tool list, count, or absence assertion (D0, D3).
2. **Python harness over the one bus** (Matt's ask), unifying today's split Node+Swift harnesses; `tests/e2e/aitm_e2e/` + prescriptive per-flow scripts (D1).
3. **Four tiers** with an explicit CI-headless vs real-Mac/manual split; the merge gate is **T0 + T1**; T2 (macOS GUI/sysex) and T3 (DVWA/blind-agent) are signed-off real-machine gates (D5).
4. The **`Upstream` echo-record origin** (H1/H2/WS) is the independent observer for mutate/replay/WS/H2; `aitm-testtarget` is the seeded-vuln origin; real obscura + real `curl`/browser add client-side coverage (D1, D2).
5. The **coverage ledger + live-`tools/list`-vs-Rust-`EXPECTED_TOOLS` reconciliation** is the anti-drift core; role is derived from live sensitivity/gating and the operator/agent asymmetry is a positive test (D3).
6. It **supersedes** `selftest-live.mjs` and the drifted macOS live `.sh` harnesses, mapping every real assertion forward and keeping the T0 Rust suite (D6).
7. Hygiene is in the harness: no token in logs, own-PID-only cleanup, bounded disk, disposable CA-trust context, flake quarantine (D7).
