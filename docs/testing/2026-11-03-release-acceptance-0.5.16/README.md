# Release acceptance — v0.5.16 on Matt's installed build (2026-11-03)

Three runs of `tests/e2e/acceptance/lib/run.sh 0.5.16` by the orchestrator, right after the mac-first
tap bump and `brew upgrade` (app 0.5.16, CLI 0.5.16). Matt's yes: "Yes, run it" (the window half) —
`ACCEPT_WINDOW=1`, yes-list MAC-2…16 + CLI-9 for run A, TUI-3/7 + WEB-4/7 + CLI-9 for run B with the
app quit for the ports and relaunched after. System proxy was off before and after every run.

| run | journeys | result |
|---|---|---|
| `run-20261103T144254Z` | read-only, all | no FAIL: CLI-4/5/10, CLI-7, MAC-1, MAC-9b, N5 PASS; rest SKIP/BLOCKED (window + quit needed) |
| `run-20261103T162234Z` | A: mac, cli, negatives, window | MAC-1/2/3/4/7/9b/13 PASS (Restart Core keeps Scope; 14 proxied rows attributed). **MAC-5 FAIL**: the Edit Scope sheet does not focus its Add field when Scope already has hosts (product; fix in progress, branch `claude/mac-scope-focus-bypass`); MAC-6/15 SKIP: `systemProxy.bypass` never persisted (same fix); CLI-9 SKIP: `config.yaml` has no `system_proxy.bypass` |
| `run-20261103T162722Z` | B: tui, web, cli, negatives; app quit, ports free | **CLI journey green**: CLI-1/2/3/6/7 PASS (`--version`, synopsis, ready card on stderr, no-core refusal). WEB-1/2/3/6d/8 PASS; **WEB-6a FAIL**: intercept armed but the Disarm control is not found. **TUI-1/2/5a/6 + N2-TUI FAIL** (pills `sys-proxy`/`CA trusted` and status-bar words missing, scope add leaves no audit row, armed bar not drawn, empty-state sentence missing); TUI-8 PASS. CLI-8 SKIP (harness could not hold 8082) |

Verdict: `fail` on MAC-5 (mac fix in progress), WEB-6a and the TUI cells (investigation card). Everything
Matt's first complaints were about — one-shot verbs on the running core, proxied flows carrying their
app, a quiet CLI — passes on the installed build.
