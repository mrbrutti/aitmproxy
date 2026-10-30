# End-to-end real-test framework implementation plan

**Status:** draft
**Spec:** `docs/superpowers/specs/2026-10-30-aitmproxy-e2e-real-test-framework-design.md`
**Branch / worktree:** `feat/e2e-real-test-framework`

## Overview

The framework is a Python harness library plus prescriptive per-flow scenario scripts that drive the **real** `aitm` bus against **real** traffic and assert on **independently observed ground truth**. It builds in six waves. **Wave 0 (library)** is the foundation everything depends on and is mostly sequential. **Waves 1–3** are the T1 scenario scripts (bus features, protocol breadth, security features); each scenario is an independent file that fans out to parallel coders once the library exists (two writers never share a file — the library modules are stable by then). **Wave 4** closes the T1 gate (coverage ledger + role asymmetry + the two real-UI paths) and depends on Waves 1–3 existing (the ledger reconciles against the scenarios). **Wave 5** is the T2 real-Mac macOS gate (the five motivating failures + NE). **Wave 6** supersedes the drifted harnesses and writes the gate docs + the T3 capstone runbook.

Gate note: this framework adds **no Rust product code**, so `cargo fmt/clippy/test` stays green by construction and remains the whole-branch gate; each **Python** task's "Done when" is *the scenario runs against a real core on a real runner (Terminal panel) and asserts the real outcome, with command output shown* plus the repo Python lint (`ruff` + `black --check`, **(builder's call)** on the exact linter). Everything that binds a port / spawns a browser / builds Swift / touches git runs through the Terminal panel, never the sandbox. obscura-dependent tasks gate on `AITM_OBSCURA=1`.

## Tasks

### Task 1: Harness core — `CoreProcess` + config generation + lifecycle

- **Satisfies:** AC1 (prereq), AC17 (hygiene), AC15 (exit-code gate prereq)
- **Depends on:** none
- **Files:** `tests/e2e/aitm_e2e/__init__.py` (create), `tests/e2e/aitm_e2e/core.py` (create), `tests/e2e/aitm_e2e/config.py` (create), `tests/e2e/pyproject.toml` (create), `tests/e2e/tests/test_core_process.py` (create)
- **Change:** `CoreProcess(config: CoreConfig)` with `start()/stop()/restart()`; `CoreConfig` builder that writes a per-run YAML with both tokens (`mcp.operator_token` + agent token), `scope.entries`, `findings.dir`, `poc.dir`, per-command `*.allow_agent_*` flags, and `l4.enabled`; starts `aitm` with `--config` + `--bus-endpoint-file <path>` and reads the real bound bus address from that file (never parses the token from stdout). `stop()` kills **only** the spawned child PID and removes the per-run workdir. A `workdir` under `$TMPDIR` with unique ports/paths.
- **Test:** `test_core_process_boots_and_reports_bus` — `CoreProcess` starts a real core, the endpoint file appears with a loopback address, `stop()` leaves no child PID and removes the workdir. Literal: endpoint file parses to `127.0.0.1:<port>`, post-stop `pgrep` of the captured child PID is empty.
- **Done when:** the test passes on a real runner (Terminal panel) and the Python lint passes.

### Task 2: Harness bus client — `BusClient` (3 transports, tools cache, roles, subscribe, confirm)

- **Satisfies:** AC1, AC2 (prereq), AC10 (prereq), AC15
- **Depends on:** Task 1
- **Files:** `tests/e2e/aitm_e2e/bus.py` (create), `tests/e2e/tests/test_bus_client.py` (create)
- **Change:** `BusClient(address, token, transport)` for `loopback_tcp` | `stdio` | `ws_bridge`; `initialize()`, `tools()` (cached: name→`{inputSchema, sensitivity, confirmable}`), `call(tool, args)`, `subscribe(filter)` yielding `notifications/aitm/{flow,state,agent}`, and `confirm(tool, args)` performing the two-phase `_confirm` handshake (resend with the returned `confirm_token`). A `connect_operator()`/`connect_agent()` pair. Never logs the token.
- **Test:** `test_operator_and_agent_roles` — against a Task-1 core, an operator `BusClient` and an agent `BusClient` both `tools/list`; a `Sensitive`-not-deferred command (e.g. `proxy.pause`) succeeds for operator and is refused for agent under `Auto`. Literal: operator result ok, agent result is a policy refusal.
- **Done when:** the test passes on a real runner and lint passes.

### Task 3: Independent observer — `Upstream` echo/record origin (H1/H2/WS)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5 (the observer for all of them)
- **Depends on:** none (parallel with Tasks 1–2)
- **Files:** `tests/e2e/aitm_e2e/upstream.py` (create), `tests/e2e/tests/test_upstream.py` (create)
- **Change:** `Upstream()` a real-socket loopback origin speaking **HTTP/1.1, HTTP/2, and WebSocket** (**(builder's call)**: `hypercorn`+`aiohttp`/`websockets`, or extend `aitm-testtarget` with an echo mode — Python preferred to keep the Rust gate untouched). Records every request `(method, path, headers, raw_body)` and every WS frame received into an inspectable log; serves deterministic echo responses; exposes `received()` / `ws_received()`. Distinct in-scope and out-of-scope instances.
- **Test:** `test_upstream_records_h1_h2_ws` — a raw `curl` (H1), `curl --http2-prior-knowledge` (H2), and a WS client each hit `Upstream`; `received()`/`ws_received()` return exactly what was sent. Literal: the recorded method/path/body/frame equal the sent values.
- **Done when:** the test passes on a real runner and lint passes.

### Task 4: Real clients — `Target`, `Browser`, `GroundTruth` helpers

- **Satisfies:** AC6, AC7, AC8, AC17
- **Depends on:** Task 1
- **Files:** `tests/e2e/aitm_e2e/target.py` (create), `tests/e2e/aitm_e2e/browser.py` (create), `tests/e2e/aitm_e2e/groundtruth.py` (create), `tests/e2e/tests/test_target_and_clients.py` (create)
- **Change:** `Target(mode)` wraps `aitm-testtarget-serve --mode {vulnerable|patched} --port 0`, parses `listening http://…`. `Browser` fetches obscura via `scripts/fetch-obscura-dev.sh` if absent (honours `AITM_OBSCURA_BIN`), drives it over CDP with `--proxy`+`--ca-cert`, tears down by **own child PID only**, and wraps `curl --cacert`; gated on `AITM_OBSCURA=1` with a loud SKIP. `GroundTruth`: `proxy_status_address(bus)`, `findings_on_disk(dir)`, `client_trusts_ca(client, url)`, `ca_status(bus)` vs a real trust probe.
- **Test:** `test_target_serves_seeded_routes` (route reachable, vulnerable vs patched differ) and `test_curl_trusts_exported_ca` — `ca.export` then `curl --cacert` completes an MITM handshake to `Upstream` via the proxy. Literal: vulnerable body contains the seed marker, patched does not; curl exit 0 with the real body.
- **Done when:** both tests pass on a real runner (obscura parts SKIP without `AITM_OBSCURA=1`) and lint passes.

### Task 5: Anti-drift core — `Ledger` + runner + live-tools-vs-contract reconciliation

- **Satisfies:** AC10, AC15
- **Depends on:** Task 2
- **Files:** `tests/e2e/aitm_e2e/ledger.py` (create), `tests/e2e/aitm_e2e/runner.py` (create), `tests/e2e/aitm_e2e/tiers.py` (create), `tests/e2e/tests/test_ledger_contract.py` (create), `Makefile` (modify: add `e2e` targets) — **(builder's call)** on Makefile vs a shell entrypoint
- **Change:** `Ledger` records, per scenario, the tools it exercised and at which role; `assert_full_coverage(live_tools, exclusions)` fails if any live tool has no scenario. `reconcile_contract(live_tools, expected_tools_rs)` parses `EXPECTED_TOOLS` from `crates/aitm/tests/frontends.rs` and asserts live==contract and every tool has a non-empty `inputSchema`. The `runner` discovers scenarios, runs a tier, classifies PASS / SKIP(reason,tier) / FAIL, emits JSON + a human summary, and **exits non-zero iff a required cell FAILs**. No hard-coded tool count/list anywhere.
- **Test:** `test_live_tools_equal_contract` and `test_uncovered_tool_fails_ledger` — the live set equals the parsed contract set; injecting a fake uncovered tool name makes `assert_full_coverage` fail. Literal: reconciliation passes on the real core; the ledger raises on the fake tool.
- **Done when:** both tests pass on a real runner and lint passes.

### Task 6: T1 scenarios — capture-live, flow.detail body, intercept→mutate→resume, response edit

- **Satisfies:** AC1, AC2
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_capture_live.py` (create), `tests/e2e/scenarios/t1_flow_detail_body.py` (create), `tests/e2e/scenarios/t1_intercept_mutate_resume.py` (create), `tests/e2e/scenarios/t1_response_edit.py` (create)
- **Change:** each is an arrange→act→assert scenario using the library, declaring tier `T1`, `needs`, and tools exercised. `t1_intercept_mutate_resume`: operator arms `flow.intercept`, real client sends a POST, agent `flow.mutate`s method/path/headers/body, agent `flow.resume`s; assert **`Upstream.received`** shows the edited request. `t1_capture_live`: a `flow.subscribe` sees `notifications/aitm/flow` for real traffic and `flow.list` grows. `t1_flow_detail_body`: `flow.detail` decoded body byte-equals `Upstream` record.
- **Test:** the scenarios themselves are the tests (run via the Task-5 runner). Literal expected values: edited method/path/body equal what `Upstream` recorded; subscribed notification carries the new flow id; detail body == upstream body.
- **Done when:** all four scenarios PASS under the runner on a real runner; coverage ledger records their tools; lint passes.

### Task 7: T1 scenarios — kill, replay, crafted request + scope

- **Satisfies:** AC3
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_kill.py` (create), `tests/e2e/scenarios/t1_replay.py` (create), `tests/e2e/scenarios/t1_request_send_scope.py` (create)
- **Change:** `t1_kill`: park a flow, `flow.kill` (reset/503/429), assert the client sees the abort and `Upstream` **never recorded** the request. `t1_replay`: `flow.replay` a captured request, assert a **second** identical record at `Upstream`. `t1_request_send_scope`: an in-scope `request.send` reaches `Upstream`; an out-of-scope one is refused with a scope error (out-of-scope `Upstream` records nothing).
- **Test:** scenarios run via the runner. Literal: kill → upstream record count unchanged; replay → upstream record count +1 identical; out-of-scope send → scope-error result and zero out-of-scope records.
- **Done when:** all three PASS on a real runner; ledger updated; lint passes.

### Task 8: T1 scenarios — WebSocket inject/frame edit + HTTP/2 MITM

- **Satisfies:** AC4, AC5
- **Depends on:** Tasks 1–5 (Upstream WS+H2)
- **Files:** `tests/e2e/scenarios/t1_ws_inject.py` (create), `tests/e2e/scenarios/t1_ws_frame_edit.py` (create), `tests/e2e/scenarios/t1_h2_mitm.py` (create)
- **Change:** `t1_ws_inject`: operator `ws.send` injects a frame; assert `Upstream` WS endpoint recorded it. `t1_ws_frame_edit`: `ws.intercept` + `ws.frame` edits a live frame; assert the downstream peer sees the edit. `t1_h2_mitm`: drive H2 traffic (obscura or `curl --http2-prior-knowledge`) through the proxy; assert capture + decoded body + an upstream-confirmed mutate or replay — proving H2 MITM, not only H1.
- **Test:** scenarios via the runner. Literal: WS endpoint records the injected/edited frame; H2 flow captured with correct `:method`/`:path` and decoded body == upstream body; H2 mutate/replay confirmed at `Upstream`.
- **Done when:** PASS on a real runner (H2-via-obscura SKIPs without `AITM_OBSCURA=1` but passes via `curl --http2`); ledger updated; lint passes.

### Task 9: T1 scenarios — TLS MITM + real client trusts CA; scope/SSRF browser confinement

- **Satisfies:** AC6, AC7
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_tls_ca_real_client_trust.py` (create), `tests/e2e/scenarios/t1_scope_ssrf_confinement.py` (create)
- **Change:** `t1_tls_ca_real_client_trust`: `ca.export` the cert; `curl --cacert` and obscura `--ca-cert` complete the MITM handshake and get the real `Upstream` body; `ca.status` matches an independent trust probe. `t1_scope_ssrf_confinement`: an out-of-scope `request.send` and an out-of-scope `browser.navigate` are refused/confined (out-of-scope `Upstream` records nothing; `egress.probe` where available confirms confinement).
- **Test:** scenarios via the runner. Literal: curl/obscura exit 0 with upstream body; out-of-scope navigation refused and zero out-of-scope records.
- **Done when:** PASS on a real runner (obscura parts gate on `AITM_OBSCURA=1`); ledger updated; lint passes.

### Task 10: T1 scenarios — scan.discover, PoC pass/fail, findings persist + redact

- **Satisfies:** AC8
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_scan_discover.py` (create), `tests/e2e/scenarios/t1_poc_repro.py` (create), `tests/e2e/scenarios/t1_findings_persist_redact.py` (create), `tests/e2e/scenarios/t1_scan_inject_run.py` (create, **blocked** marker until the active backend ships)
- **Change:** `t1_scan_discover`: `scan.discover` against `Target(vulnerable)` enumerates the seeded injection points; assert they match the grader-only manifest (loaded by the scenario as grader, **never** sent to the driver connection). `t1_poc_repro`: `poc.run` passes on `vulnerable`, fails on `patched`, three artifacts on disk. `t1_findings_persist_redact`: `findings.record`, `CoreProcess.restart()`, `findings.list` returns it; assert a secret (`Authorization: Bearer abc123`) appears nowhere in the record. `t1_scan_inject_run`: written to the active-backend shapes but marked `blocked` (SKIP with reason) until `scan.inject`/`scan.run` register.
- **Test:** scenarios via the runner. Literal: discovered points == seeded set; poc pass/fail booleans + 3 artifact files; finding survives restart; `grep abc123` over the record is empty.
- **Done when:** the three active scenarios PASS on a real runner; the blocked one SKIPs with a reason; ledger updated; lint passes.

### Task 11: T1 scenarios — L4 TCP/UDP capture + craft/inject/intercept round-trip

- **Satisfies:** AC9
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_l4_capture.py` (create), `tests/e2e/scenarios/t1_l4_craft_inject.py` (create), `tests/e2e/scenarios/t1_l4_intercept.py` (create)
- **Change:** a `CoreConfig` with `l4.enabled` and the needed `l4.allow_agent_*` flags. `t1_l4_capture`: drive real UDP-echo + TCP-banner traffic through the `aitm-testtarget` L4 service; assert the flows appear in `l4.flow.list`. `t1_l4_craft_inject`: `l4.craft` → `l4.inject`/`l4.send_recv` (operator confirm) round-trips against the L4 echo. `t1_l4_intercept`: `l4.intercept.start` → `l4.intercept.mutate` → `l4.intercept.forward` (operator confirm) reflects the mutation.
- **Test:** scenarios via the runner. Literal: `l4.flow.list` contains the UDP/TCP flow with the echoed bytes; inject round-trip returns the echo; intercept forward delivers the mutated bytes.
- **Done when:** PASS on a real runner (binds L4 ports — Terminal panel only); ledger updated; lint passes.

### Task 12: T1 gate close — full-surface coverage + role asymmetry + confirm handshake

- **Satisfies:** AC10
- **Depends on:** Tasks 5–11 (the ledger needs the scenarios to exist)
- **Files:** `tests/e2e/scenarios/t1_surface_coverage.py` (create), `tests/e2e/scenarios/t1_role_asymmetry_confirm.py` (create), `tests/e2e/aitm_e2e/ledger.py` (modify: finalize exclusion list)
- **Change:** `t1_surface_coverage` runs the full T1 suite's ledger and asserts (a) live `tools/list` == parsed `EXPECTED_TOOLS` with non-empty schemas, (b) every registered tool exercised ≥once minus a declared, one-line-justified exclusion list. `t1_role_asymmetry_confirm`: for a representative gated command, assert agent-refused-without-flag / operator-allowed, and a successful operator `_confirm` handshake (e.g. `ca.install` with `dry_run` or a disposable context). Audit there is **no** hard-coded tool count/list and **no** absence assertion in the tree (a lint scenario grepping the framework for those anti-patterns).
- **Test:** scenarios via the runner. Literal: reconciliation passes; coverage complete modulo exclusions; asymmetry booleans; handshake succeeds; the anti-pattern grep finds nothing.
- **Done when:** PASS on a real runner; the whole T1 suite is a single green gate; lint passes.

### Task 13: T1 real-UI paths — web `/bus` live streaming + TUI attach

- **Satisfies:** AC11, AC12
- **Depends on:** Tasks 1–5
- **Files:** `tests/e2e/scenarios/t1_web_live_stream.py` (create), `tests/e2e/scenarios/t1_tui_live.py` (create), `tests/e2e/aitm_e2e/webui.py` (create: headless-browser driver), `tests/e2e/aitm_e2e/tui.py` (create: pty driver)
- **Change:** `t1_web_live_stream`: launch `aitm web`, open the UI over its real `/bus` bridge in a headless browser, generate live traffic, assert the flow list **updates without reload**. Because this is the current freeze bug, mark it **`xfail` (quarantined) with a linked product follow-up** so the gate stays green; it flips to a hard requirement when the UI subscribes. `t1_tui_live`: attach `aitm-tui` over the bus in a pty, generate traffic, assert the TUI reflects the live flow and an intercept arm/disarm.
- **Test:** scenarios via the runner. Literal (TUI): the pty screen shows the new flow row and the armed-intercept indicator. Literal (web): the flow count in the DOM grows without reload (currently xfail).
- **Done when:** the TUI scenario PASSes and the web scenario runs as a documented xfail on a real runner (needs a real Chrome); the product follow-up is filed; lint passes.

### Task 14: T2 macOS — embedded-core bundle + launch + connection mode

- **Satisfies:** AC13 (bugs 1, 2)
- **Depends on:** Task 2 (BusClient), Task 4 (GroundTruth); real Mac
- **Files:** `tests/e2e/scenarios/t2_macos_embedded_core.py` (create), `tests/e2e/aitm_e2e/macapp.py` (create: build/launch/quit the real `.app` via the Terminal panel; drive the app's `APP_LIVE` real-bus self-test path or a debug bridge — prefer state over pixels)
- **Change:** build + install the real `.app` (via `build.sh`/`snap-dev.sh` through the Terminal panel), launch it, and assert against the **real** running app: (bug 1) the shipped bundle **contains** a core binary and a `curl` through the app's embedded proxy reaches `Upstream`; (bug 2) with a stale external pin written to `UserDefaults`, the app still selects/launches the embedded core.
- **Test:** scenario via the runner (tier T2, `needs: [mac-gui]`). Literal: `ls` of the bundle shows the core binary; curl exit 0 through the embedded proxy; with the stale pin set, the connected bus is the embedded core's.
- **Done when:** PASS on Matt's Mac through the Terminal panel; result recorded; SKIPs loudly off-Mac.

### Task 15: T2 macOS — bound port, Settings port format, real CA trust vs fixture

- **Satisfies:** AC13 (bugs 3, 4, 5)
- **Depends on:** Task 14 (`macapp.py`); real Mac
- **Files:** `tests/e2e/scenarios/t2_macos_bound_port.py` (create), `tests/e2e/scenarios/t2_macos_settings_port_format.py` (create), `tests/e2e/scenarios/t2_macos_ca_real_trust.py` (create)
- **Change:** (bug 3) assert the app header's displayed port equals `proxy.status.address` from the real core (read via the debug bridge / rendered-value probe, not a fixture). (bug 5) assert the Settings port renders with **no locale grouping** (reads back as the integer). (bug 4) assert the CA panel reflects real `ca.status`, and `ca.install` **actually installs** per an independent trust probe against a **disposable/opt-in** trust context — never the operator's default store silently.
- **Test:** scenarios via the runner (T2). Literal: header port == bound port; Settings port string has no separators; post-`ca.install` the disposable client trusts the cert and `ca.status` shows installed/trusted truthfully.
- **Done when:** PASS on Matt's Mac through the Terminal panel; the CA test uses a disposable trust context; results recorded.

### Task 16: T2 macOS NE — system-wide L4 capture

- **Satisfies:** AC14
- **Depends on:** Task 11 (L4 scenarios), the macOS NE path shipping; real Mac + sysex
- **Files:** `tests/e2e/scenarios/t2_macos_ne_l4_capture.py` (create)
- **Change:** with the Network Extension sysex installed/approved (manual gate), generate real system traffic and assert it is captured through the NE path and appears in `l4.flow.list`. Clearly labelled real-Mac-only; SKIPs with a reason until the NE capture path ships.
- **Test:** scenario via the runner (T2, `needs: [mac-sysex]`). Literal: a known system request appears as an L4 flow.
- **Done when:** PASS on Matt's Mac with the sysex approved, or SKIPs with a reason until the path ships; recorded.

### Task 17: Supersession + gate docs + T3 capstone runbook

- **Satisfies:** AC16, AC17
- **Depends on:** Tasks 6–13 (the new scenarios the old assertions map to)
- **Files:** `apps/web/scripts/selftest-live.mjs` (delete), `apps/web/package.json` (modify: drop `selftest:live`), `apps/mac/tools/selftest-live.sh` (delete or reduce), `tests/e2e/README.md` (create: the gate — T0+T1 trustworthy, T2/T3 real-machine), `tests/e2e/SUPERSESSION.md` (create: each retired assertion → its new scenario), `tests/e2e/scenarios/t3_dvwa_capstone.md` (create: runbook), `docs/research/MEMORY.md` (modify: note the new gate)
- **Change:** delete the drifted harnesses after confirming every real assertion they carried has a mapped T1/T2 scenario (the SUPERSESSION map proves it); write the gate docs naming **T0 + T1** as the one trustworthy green gate and T2/T3 as signed-off real-machine gates; write the T3 DVWA/blind-agent capstone runbook (Lima/colima + real obscura, not CI-reproducible).
- **Test:** `test_supersession_map_complete` — every assertion listed in `SUPERSESSION.md` names an existing scenario file; `selftest:live` is gone from `package.json`. Literal: no dangling mapping; the removed script is absent.
- **Done when:** the map test passes, the drifted harnesses are removed, the docs are in place, and `cargo test` is still green (no product code changed).

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
