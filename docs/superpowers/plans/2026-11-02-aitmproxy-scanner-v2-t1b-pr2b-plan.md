# Scanner v2 T1b PR 2b: amendments 74 + 80 (core error budget per authority; scanner probes' 5xx answers are not upstream failures) — implementation plan

**Status:** approved 2026-11-02 by the coordinator's rulings (quoted below) under Matt's autonomous mandate; opened as a focused core PR off `main` 179bc01f right after follow-up PR 2 (#292) landed, before PR 3.
**Spec:** the umbrella spec `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md`; amendment rows 74 and 80 are pending the coordinator's docs PR (cited here as the rulings).
**Branch / worktree:** `claude/scanner-v2-t1b-pr2b` in `/Users/matt/Security/aitmproxy/.claude/worktrees/wizardly-nightingale-441e25`. Files: `crates/aitm-core/src/guard.rs`, `crates/aitm-core/src/client.rs`, `crates/aitm-core/src/ctx.rs` (the `ProxyClient` trait), `crates/aitm-plugin-scanner/src/client.rs` (one call + one test). Kept away from T5's #297 (`aitm-proto-l4`, the packet lane, the harness).

## Rulings (the spec for this PR)

- **74** — "StdGuard keyed on Authority.host without port = amendment 74, pre-existing core bug: the error budget and the disable window are keyed by normalized authority (host:port with the scheme-default port filled); the rate throttle may stay per host (one bucket per server)." Measured trigger: with amendment 40 the first job in a core runs its full 2000 probes; the vulnerable target's 5xx answers exhausted a budget shared with the patched target on the same 127.0.0.1, whose next job came back `HostDisabled` (P alone: 2000 probes / 0 errors; P after a full V: 10 errors → ladder → `stopped_reason: errors`).
- **80** — "the scanner's job client (client-sent flows from the budgeted client) opts out of the breaker's 5xx half — a 5xx answer to a scanner probe is a completed upstream exchange and must not count toward host_error_budget; real transport failures and timeouts still count and still disable the host. Proxied (operator/browser) traffic keeps today's semantics, so the change is scoped to the client path, not a global breaker redefinition." Measured trigger: `test_t3_catalogue_sweep` stopped `errors` at 941/1052 checks (67 check errors) because the default budget of 10 was exhausted by 5xx answers inside one job; `test_t3_h2_sender` and `test_t2_mutable_points` saw P probed 0 times.

## Tasks

### Task 1: error budget and disable window per `host:port` (amendment 74) — `128bfdde`
- `guard.rs`: `budget_key(authority) = host:port`; `record_error` keys on it; `is_disabled(&Authority)`: an explicit port is disabled when its own window or the host-wide window (an unported `record_error`) is live; an unported spelling is the host-wide view (disabled while any service on the host is), so the existing contract "a disabled host is not reachable under another spelling" (`tests/guard.rs`) holds. The rate throttle stays on the normalized host.
- `client.rs`: the proxy client charges the budget under the authority with the scheme's default port filled (`guard_authority`), keeps the request's own spelling for the scope/rate check (its refusal names what the request said).
- Test `guard::budget_key_tests::an_exhausted_error_budget_disables_that_authority_only`: two services on one host; one exhausted → disabled, the other served, the unported spelling refused. `tests/guard.rs` (10) unchanged and green.

### Task 2: scanner probes opt out of the 5xx half (amendment 80) — `8dbef566`
- `ctx.rs`: `ProxyClient::send_probe(req, opts)` with the default falling back to `send_opts` (a client that cannot tell cannot opt out).
- `client.rs` (core): `send_opts`/`send_probe` share `send_inner(answers_are_errors)`; a 5xx answer charges the budget only when `answers_are_errors`; an upstream failure always does.
- `aitm-plugin-scanner/src/client.rs`: `JobClient` sends every probe through `send_probe`.
- Tests: core `a_probe_s_5xx_answers_leave_the_host_enabled_but_its_transport_failures_disable_it` (N 503 answers via `send_probe` → still served; N transport failures → `HostDisabled`; N 503 via `send_opts` → `HostDisabled`); scanner `probes_go_out_through_send_probe_not_send_opts` (a counting stub).

## Acceptance (orchestrator, Terminal)
- Full workspace gate exit 0 (core change).
- Live proof under the **parallel** full run (`python3 tests/e2e/run.py scan`, the load-dependent case): `test_t3_catalogue_sweep.py` reaches 1052/1052 checks without `stopped_reason: errors`; `test_t3_h2_sender.py` and `test_t2_mutable_points.py` see P probed; counts no worse than #292's final (28 / 8 / 4 → the three core reds green).
- Panel: security, quality, spec; dispositions below; panel comment on the PR; "2b ready <sha>".

## Review log
| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
