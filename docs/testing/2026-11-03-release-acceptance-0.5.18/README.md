# Release acceptance — v0.5.18 on Matt's installed build (2026-11-03)

Three runs of `tests/e2e/acceptance/lib/run.sh 0.5.18` by the orchestrator after the mac-first tap bump
and `brew upgrade` (app 0.5.18, CLI 0.5.18). Matt's yes: "Yes, run it" (the window half) — run A with
`ACCEPT_WINDOW=1` and the yes-list MAC-2…16 + CLI-9; run B with TUI-3/7, WEB-4/7, CLI-9 after quitting
the app for the ports, relaunched after. System proxy off before and after every run (MAC-6 set it and the
run's trap restored it).

| run | journeys | result |
|---|---|---|
| `run-20261103T173350Z` | read-only, all | no FAIL: CLI-4/5/7, MAC-1, N5 PASS; rest SKIP/BLOCKED |
| `run-20261103T185132Z` | A: mac, cli, negatives, window | **MAC-6 PASS for the first time** (Set as System Proxy applied, bypass applied, restored). MAC-1/2/3/4/9b/13 PASS (30 proxied rows attributed; Restart Core keeps Scope). **MAC-5 FAIL** ("the sheet's field did not take the focus probe") — **harness**: the cell accepted the Scope page's field (`scope-page-add-host`, same description) as the sheet and its point click did not land on a window at negative screen coordinates; reproduced read-only on the installed app by the macOS review session (`/tmp/claude/mac5-repro/repro.log`); fixed in this change (sheet by identifier `scope-add-host`, focus via `lib/ax_focus.sh`), unverified until the next window run. MAC-7 FAIL: the cell required the Getting Started title "All Apps is on", which MAC-3 saw and MAC-7 did not (the card goes once every step is done); the cell now reads the #303 lane detail (MAC-7 row amended). MAC-15 SKIP "8080 holder is nobody": see the incident below. Run A has no `report.py` output (no README/state-diff): the run was stopped after the negatives cell for the incident. N4-TUI FAIL in that cell (alternate screen entered on the free port) is the same incident; N4-WEB wrote no row. |
| `run-20261103T185941Z` | B: tui, web, cli, negatives; app quit | **TUI-2, TUI-5a, TUI-6, TUI-8, N2-TUI PASS** — the #321 fix holds on the installed build; **WEB-6a PASS** (Disarm present); WEB-1/2/3/6d/8 PASS; **CLI-1/2/3/6/7 PASS**. TUI-1 FAIL only on the `sys-proxy` / `CA trusted` pills read from the first frame (harness: now waited for). WEB-4 SKIP (`config.yaml` has no `system_proxy.bypass`); CLI-8 SKIP (harness could not hold 8082). |
| `run-20261103T192247Z` | evidence: mac (MAC-5/7/13 yes) + negatives on THIS harness | **MAC-5 PASS** — typed `example.com:80`, `httpbin.org:443` into the Edit Scope sheet (found by `scope-add-host`, focused via `lib/ax_focus.sh`), rows shown, Scope restored; **MAC-7 PASS** (lane detail attached); **MAC-13 PASS** with "back on 8080 True (holder: aitm pid 90646)"; **N4-TUI / N4-WEB PASS** behind the pid gate; N5-TUI PASS. TUI-1's pill wait is unverified until the next ports-free run. |

## Incident: the harness took 8080 from the operator's core

In run A the negatives cell ran right after the mac cell, seconds after MAC-13's Restart Core had freed
8080: N4-TUI's `aitm tui` entered its alternate screen on the free port (TSV: FAIL) and N4-WEB's `aitm web`
(pid 68521) bound 8080–8082 and published a run/cores pointer naming the operator's real config; it did not
exit on SIGTERM and was killed -9 ten seconds later (orchestrator's Terminal checks, `/tmp/claude/claims.md`
2026-11-03; the macOS review session's read-only check saw the core on `listen: 127.0.0.1:62954`). The
restarted embedded core had fallen back to that ephemeral port, so the app proxied nothing on 8080 until
the orchestrator killed the stray process and pressed Restart Core again. Harness fixes in this change:
both N4 steps refuse unless the installed core holds 8080 by pid identity, N4-WEB kills a child that
outlives the cap and records whether it died and who holds 8080 afterwards; MAC-13 waits for the
restarted core to be back on 8080 and asserts it. Product follow-ups (cards): the fallback port is
silent in the app while Set as System Proxy still points at 8080; `aitm web` does not exit on SIGTERM.

Verdict: on the amended harness MAC-5, MAC-7 and MAC-13 PASS on the installed build (evidence run); the only
row still unverified is TUI-1's pill wait (needs a ports-free run). Every product red of 0.5.16 is green on 0.5.18.
