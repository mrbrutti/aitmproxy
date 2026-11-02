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

### Task 3: the sweep cell's probe budget covers the catalogue (e2e-only; T3's cell, coordinator informed)

Live run on the fixed head 404cb613 (full parallel cells): 31 pass / 8 skip / 1 fail; `test_t3_h2_sender.py` and `test_t2_mutable_points.py` PASS under load (amendment 74 + 80 proof); `test_t3_catalogue_sweep.py` no longer stops on errors — it ends `stopped_reason: budget` at probes 2000 with 975/1052 checks done and `open-redirect` unreached, because the default 2000-probe budget is smaller than the fifteen-script catalogue. The cell now asks for `budget.probes: 8000` (ceiling 20 000) so the sweep runs its whole catalogue.

### Task 4: `scan.start` answers with the queued record as written (amendment 71c; queue-head fix)

**Files:** `crates/aitm-plugin-scanner/src/jobs.rs` (one statement moved). Main's own gate on 179bc01f failed `worker::tests::start_returns_queued_within_the_call_and_the_job_reaches_done` at `assert_eq!(started.status.state, JobState::Queued)`: `jobs::start` spawned the worker and only then read the status back for its `StartResult`, so the answer could already read `running`/`done`. Spec D5 "Start" (write `state: queued`, spawn, return): the snapshot is now taken before the spawn — a production fix, not a test relaxation, because the verbs test pins the same `state: queued` on the wire and both assert exactly the spec's promise. Sweep: no other snapshot-state assertion in the scanner's tests. Proof: the two tests ×50 default and ×50 `--test-threads=1` (log in the Review log).

## Acceptance (orchestrator, Terminal)
- Full workspace gate exit 0 (core change).
- Live proof under the **parallel** full run (`python3 tests/e2e/run.py scan`, the load-dependent case): `test_t3_catalogue_sweep.py` reaches 1052/1052 checks without `stopped_reason: errors`; `test_t3_h2_sender.py` and `test_t2_mutable_points.py` see P probed; counts no worse than #292's final (28 / 8 / 4 → the three core reds green).
- Panel: security, quality, spec; dispositions below; panel comment on the PR; "2b ready <sha>".

## Review log
| Task | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| 1 | Spec | Critical | "scheme-default port filled" had no test: removing `guard_authority` passed every test | fixed 2aa99a92: `the_budget_is_charged_under_the_scheme_default_port` (ex.test → `ex.test:443` disabled, `:8080` served; `[::1]` likewise) |
| 1 | Spec | Important | the host-wide window disabling an explicit port was untested | fixed 2aa99a92: `an_unported_disable_covers_every_port_of_the_host` |
| 1 | Spec / Quality / Security | Minor | the unported view was a `"host:"` string-prefix scan (IPv6 `::1` vs `::1:2` over-match; three spellings of the key; whole-map scan under the lock, never pruned) | fixed 2aa99a92: maps keyed on `Authority`, exact host comparison, expired windows pruned on lookup; `ipv6_authorities_are_keyed_by_host_and_port_not_by_prefix` |
| 1 | Quality | Important | `guard_authority` dropped IPv6 brackets: charged key ≠ looked-up key for every IPv6 target | fixed 2aa99a92: `Authority::to_string()` (brackets); covered by the two IPv6 cases |
| 1 | Security | Minor | the client checked the breaker under the request's spelling but charged the ported one, so an unported request was refused host-wide | fixed 2aa99a92: `check_active(&authority)` with the ported spelling; the scope refusal names `host:port` (one test pin updated) |
| 2 | Security / Quality | Minor | `LateHandles` forwarded `send_opts` but not `send_probe` (a wrapper would silently revert 80) | fixed 2aa99a92: forward added (one arm, `crates/aitm/src/scripts.rs`) |
| 2 | Quality | Minor | positional `bool` in `send_inner`; duplicated 503 sender; new tests split existing docs; discarded results in assertions | fixed 2aa99a92: `SendKind::{Proxied, Probe}`, module-level `ServerErrorSender`, docs restored, `.expect(..)` |
| 2 | Security | Minor | a probe dropped at the scanner's 30 s ceiling (`MAX_AWAIT`) before the sender's 60 s timeout never reaches `record_error`, so a tarpit is bounded by the scanner's ladder only, not the core breaker | **accepted as a follow-up (amendment candidate 81)**: the `JobClient` holds no guard; the fix is a drop-guard in `send_inner` or passing `ScanServices.guard` into the job client — a design change outside this PR's two rulings |
| 1 | Security | Minor | per-port keys multiply the three maps; `host_errors`/`disable_count` are never pruned | partly addressed 2aa99a92 (windows pruned); counters bounded by scope × ports; cap per host left as a follow-up note |
| all | Spec | Note | amendment rows 74/80 not yet in the spec on main | coordinator's docs PR |

## Shipped

PR #299 (`claude/scanner-v2-t1b-pr2b` → `main`), opened 2026-11-02 at 51fd6bf4 (+ this note); contains main 179bc01f, 8387d83e (#298) and 8fc179e4 (#297). Merge is the coordinator's.

- Gate: full workspace gate exit 0 at be73894b and 404cb613; reduced gate (fmt, clippy, workspace build, tests on core/model/scanner/rhai/aitm) exit 0 at 79a8c19e and 51fd6bf4. `target/` deleted after the runs.
- 71c proof: the two start tests ×50 default + ×50 `--test-threads=1`, 0 failures (each run checked for "2 passed").
- Live proof (parallel `run.py scan` at 51fd6bf4): 32 pass / 7 skip / 1 fail. `test_t3_h2_sender.py`, `test_t2_mutable_points.py`, `test_t2_session_reuse.py`, `test_t1_finding_link.py` PASS under load; the sweep job runs its whole catalogue (checks.done 1068, probes 2671, errors 0, stopped_reason None; on #292's build: 941/1052, stopped errors). The one red is the sweep's `open-redirect` on `/redirect`: the seeded link is `/redirect?next=/`, T2's lane tags `Url` only for `is_url` values and T3's check `wants_traits: [Url]`, so the check never runs on that point — a trait gap the early stop had masked. Coordinator's ruling: **amendment 83**, pre-existing, surfaced by this PR; the cell stays red on purpose (a red that names a real detection gap beats a green that hides it); the check fix is T1b's (T3 archived) as a tiny PR 2c or the first item of PR 3, proof = the sweep fully green under the parallel run.
- Panel: security PASS, quality FAIL → fixed, spec FAIL → fixed (tests); amendment 81 (30 s ceiling vs breaker) to PR 3; panel comment on #299.

