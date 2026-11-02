# Scanner v2 T1b follow-up 2 (amendments 38, 39, 40, 46; deterministic job tests) implementation plan

**Status:** approved 2026-11-01 by the T1b orchestrator under Matt's autonomous mandate (self-approve specs/plans). Decisions on the architect's open calls: C4 keeps "reason only when every crawl request failed" (the coordinator's wording of amendment 39; a partial failure is visible in `crawl.errors` alone); the `other` token for free-text browser-crawl failures is accepted. Amendments 38-40 are cited as "" until that docs PR is on main.
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), D4 "Scheduling", D5 (job model, budget and pacing, "degrade, do not fail"), D11 (`l4_icmp_pace_ms_min`), amendment log rows 38/39/40 and 46, all on `main` (docs PR #273 merged as 449d6d17; wording quoted below).
**Prior plan (conventions, Review log, Shipped):** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1b-plan.md` (T1b, merged as #232 = `3aa8cc67`).
**Branch / worktree:** `claude/scanner-v2-t1b-followup-2` in `/Users/matt/Security/aitmproxy/.claude/worktrees/wizardly-nightingale-441e25`, cut from `main` `7f942f9f` (contains T1b `3aa8cc67`, T3 PR 2a `2044ac52`, T5 `7f942f9f`). PR target `main`.
**Size:** one PR; seven tasks in four waves.

## Overview

Four scoped engine fixes the T3 live runs and the T5 live proof surfaced, plus one
test-hygiene fix CI forced, plus bookkeeping. Nothing here changes a verb's shape, a
wire key's meaning, or any operator decision; every status/model change is additive.

| Wave | Tasks | Depends on |
|---|---|---|
| A (parallel, disjoint files) | Task 1 (scheduler: origin items from origins), Task 2 (all-failing crawl surfaces a reason), Task 3 (ladder counts transport only), Task 4 (`icmp_pace_ms` floor clamp) | none |
| B | Task 1b (origin probe host + worker resolution of origin items) | Tasks 1 and 2 (shares `worker.rs` and `interim_lane.rs` with Task 2) |
| C | Task 5 (deterministic terminal waits) | Task 1b (last writer of `worker.rs`) |
| D | Task 6 (bookkeeping, docs wording) | all |

**The rules this plan implements** (the spec's amendment table on main, rows 38-40 and 46, landed via docs PR #273 = 449d6d17):

- **Amendment 38, D4/D8:** an origin-scoped check is scheduled once per target
  origin whether or not any insertion point was discovered there.
- **Amendment 39, D5:** every failed crawl request counts in `crawl.errors`; when a
  crawl made at least one request and all of them failed (no page fetched) the job surfaces
  it: `crawl.errors > 0` and a classified reason on the status. The job still runs its
  passive checks over captured flows (D5 "degrade, do not fail"): `state: done`,
  `stopped_reason` as the audit decides, reason visible. Where the cause is forced `h2`
  against an h1-only listener the reason is amendment 21's counted probe error
  `h2_not_negotiated`.
- **Amendment 40, D5:** the per-host error ladder counts connect/transport errors
  and per-probe timeouts (`AwaitEnd::Timeout`) only. A 5xx is an answer: returned to the
  check, counted nowhere on the ladder. `StoppedReason::Errors` and the
  `consecutive`/`ratio` thresholds keep their semantics over those failures.
- **Amendment 46 (on `main`), D11:** `scanner.ceilings.l4_icmp_pace_ms_min` (default 1000) is a
  floor; a profile `l4.icmp_pace_ms` below it is clamped **up** and reported in `clamped`.

## Shared facts for every coder

The T1b plan's "Shared facts for every coder" apply unchanged (TDD with quoted red and
green runs; `cargo test -p aitm-plugin-scanner --offline` in the sandbox; model traits
extended only with default-bodied methods; `util::scrub` for any text that could carry a
secret; never touch `crates/aitm-tui/**`, `apps/**`, `tests/e2e/**`, lane crates). Plus:

- **Coders never run git.** The orchestrator commits each task by explicit path
  (`git commit -- <files>`); never `git add -A`, never bare `cargo fmt` (run
  `rustfmt --edition 2021 <file>` on the files you touched).
- **The sandbox denies socket binds.** Every test in this plan is in-process (stub clients,
  fake lanes, duplex streams); nothing listens. Socket suites, the e2e harness and the live
  proofs run in the Terminal by the orchestrator.
- **Do not run `cargo` in this worktree before the orchestrator says the cache is warm**
  (a build was warming it when this plan was written).
- **Deterministic tests.** No test outcome may depend on a wall-clock bound. A readiness
  poll is allowed only under the 60 s safety net of Task 5 (never a measured bound) and
  only when no notification exists for the condition.
- **One writer per file at a time.** The waves above are the schedule; a coder who needs a
  file outside its task's list stops and reports.
- **Per-task gate** (sandbox): `cargo fmt --check`, `cargo clippy -p <crate> --all-targets
  --offline -- -D warnings`, `cargo test -p <crate> --offline` for each crate touched; the
  workspace gate runs in the Terminal before the panel.

## Tasks

### Task 1: scheduler: origin-scoped items are driven by the origin set, not by points

- **Satisfies:** amendment 38 (scheduler half); spec D4 "Scheduling".
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-scanner/src/scheduler.rs` (modify; the only file).
- **Change:**
  - `SchedulePlan` gains `pub origin_points: Vec<InsertionPoint>` (additive): one synthetic
    point per origin, built by a new `fn origin_point(key: &str, nodes: &[&SiteNode]) ->
    InsertionPoint` — `id: format!("origin:{key}")`, `lane: LaneKind::Http`, `kind:
    InsertionKind::PathSegment`, `name: "/"`, `path: Some("/")`, `url: Some(format!("{key}/"))`,
    `method: Some("GET")`, `flow: None`, `site_node: id of a node on that origin whose
    path_template is "/" else None`, `traits: []`, `frequency: 1`. (The kind is cosmetic:
    origin items bypass every point gate; no test may depend on it.)
  - `ScheduleItem.point` keeps its type; its doc now says an index `>= points.len()`
    addresses `origin_points[point - points.len()]`. New
    `impl SchedulePlan { pub fn point_at<'a>(&'a self, points: &'a [InsertionPoint], index:
    usize) -> Option<&'a InsertionPoint> }` resolves either.
  - `plan()` signature unchanged. New `fn origin_set(profile: &ScanProfile, points, nodes,
    by_id) -> Vec<(String, Vec<&SiteNode>)>`: the normalized `profile.target.origins`
    (`url::Url` → `scheme://host:port` with `port_or_known_default`; an unparsable origin is
    used verbatim), in profile order, then every `origin_key(point, node)` of a point that
    passes the `audit.kinds`/`audit.ignore` gates and is not already present. Deterministic
    first-seen order, no `HashSet` iteration order.
  - For every check with `meta.scope == CheckScope::Origin` and `meta.lanes` containing
    `LaneKind::Http`, one item per origin in that set, gated by `meta.intensity <=
    profile.intensity` only (no `kinds`, `wants_traits`, frequent or session gate: an
    origin is not a point). Priority `priority(exposure(max node.points on that origin,
    busiest), interest(Some("GET"), None, any node on that origin has auth))`. Passive vs
    active by technique as today. The point loop no longer claims origin slots for such
    checks (`scope_key` returns `None` for them); origin-scoped checks of other lanes keep
    today's point-derived rule unchanged.
- **Test** (`scheduler::tests`):
  - `origin_scoped_checks_run_once_per_target_origin_without_points`: zero points, zero
    nodes, `profile.target.origins = ["http://a.test:8080"]`, checks `origin.check` (scope
    Origin) and `point.check` (scope Point). Expect `ids(&plan.active) ==
    ["origin.check"]`, `plan.active[0].point == 0`, `plan.origin_points.len() == 1`,
    `plan.point_at(&[], 0).unwrap().url.as_deref() == Some("http://a.test:8080/")`, and
    `plan.point_at(&[], 0).unwrap().id == "origin:http://a.test:8080"`.
  - `origin_scoped_checks_run_once_per_origin_with_points_on_two_origins`: two points on
    `http://a.test:8080`, one on `http://b.test:8080`, target origin `a.test` only. Expect
    `count_for(&plan.active, "origin.check") == 2` (one per origin), `count_for(&plan.active,
    "point.check") == 3`, and the two origin items' indices are `3` and `4`.
  - `origin_items_ignore_point_gates_but_respect_intensity`: an origin check with
    `intensity > profile.intensity` schedules nothing; one with `kinds: [Cookie]` still
    schedules once per origin.
  - Existing `origin_and_node_scoped_checks_run_once` updated to the new indices; every
    other scheduler test unchanged and green.
- **Done when:** the four tests pass, the whole `scheduler::tests` module passes, and the
  per-task gate passes.

### Task 2: an all-failing crawl surfaces a classified reason

- **Satisfies:** amendment 39; spec D5 "degrade, do not fail".
- **Depends on:** none.
- **Files:** `crates/aitm-scan-model/src/job.rs` (modify), `crates/aitm-scan-model/src/traits.rs`
  (doc comment of `report_crawl_error` only), `crates/aitm-plugin-scanner/src/interim_crawl.rs`
  (modify), `crates/aitm-plugin-scanner/src/interim_lane.rs` (modify, `client_crawl` region
  only), `crates/aitm-plugin-scanner/src/worker.rs` (modify: `JobRuntime` fields,
  `report_crawl_error`, the crawling-phase block, `sync_counters`; nothing in the audit
  region).
- **Change:**
  - Model: `pub enum CrawlErrorKind { H2NotNegotiated, ConnectRefused, Tls, Timeout,
    Transport, Other }` (`Copy`, `Serialize/Deserialize`, `rename_all = "snake_case"`), with
    `pub fn as_str(self) -> &'static str` and `pub fn parse(s: &str) -> Option<Self>` (exact
    token match, no heuristics). `CrawlCounters` gains `pub last_error:
    Option<CrawlErrorKind>` (additive; `CrawlCounters` stays `Copy`; absent on the wire means
    none; `#[serde(skip_serializing_if = "Option::is_none")]` only if the struct already
    skips elsewhere, otherwise emit `null`). `JobStatus` and `CrawlCounters` keep
    `#[serde(default)]`, so old records still load.
  - `interim_crawl.rs`: `ClientCrawl` gains `pub failed: u32` and `pub last_error:
    Option<CrawlErrorKind>`; new `pub(crate) fn classify(err: &anyhow::Error) ->
    CrawlErrorKind` (chain text contains `h2_not_negotiated` → `H2NotNegotiated`;
    `ProbeRefused::Timeout` → `Timeout`; text contains `connection refused`/`connect` →
    `ConnectRefused`; `tls`/`certificate`/`handshake` → `Tls`; else `Transport`). The
    `continue` branch of the fetch loop now does `failed += 1; last_error = Some(classify)`.
    A `ProbeRefused` other than `Timeout` is still the crawl ending, not a failed request.
  - `interim_lane.rs::client_crawl`: for each failed request call
    `job.report_crawl_error(origin, kind.as_str())` (once per failure; the reason is the
    token, so nothing to scrub).
  - `worker.rs`: `JobRuntime` gains `last_crawl_error: Mutex<Option<CrawlErrorKind>>`;
    `report_crawl_error` stores `CrawlErrorKind::parse(reason).unwrap_or(Other)` and
    downgrades its per-call log to `debug` when the reason parses as a token (the warn line
    stays for free-text browser failures). At the end of the crawling phase (the block that
    bumps `crawl.pages`), fold `crawl.errors` and apply the rule: `if crawl.errors > 0 &&
    crawl.pages == 0 { crawl.last_error = last_crawl_error }`. `sync_counters` never clears
    `last_error`. No change to `stopped_reason` or `error`.
  - `traits.rs`: `report_crawl_error` doc: "one failed crawl request (client crawl, reason =
    a `CrawlErrorKind` token) or one crawl that failed outright (browser crawl)".
- **Test:**
  - `interim_crawl::tests::every_failed_request_is_counted_and_classified`: a stub client
    whose every send fails with `anyhow!("h2_not_negotiated: scan.test:80: alpn")` → crawl
    returns `pages == 0`, `failed == 1` (the seed; nothing else is discovered),
    `last_error == Some(H2NotNegotiated)`; a stub failing 1 of 3 (seed ok with two links,
    one link fails with "connection refused") → `pages == 2`, `failed == 1`,
    `last_error == Some(ConnectRefused)`.
  - `interim_lane::tests::a_failed_crawl_request_is_reported_once_each`: the `TestJob`
    recorder (`crawl_errors()`) holds exactly `[("http://scan.test", "h2_not_negotiated")]`
    for the all-failing stub, and one entry for the 1-of-3 stub.
  - `worker::tests::an_all_failing_crawl_surfaces_its_reason_and_the_job_still_finishes`:
    a `FakeLane` whose `discover` calls `report_crawl_error(origin, "h2_not_negotiated")`
    three times and returns no points/nodes → terminal status `state == Done`,
    `stopped_reason == None`, `error == None`, `crawl.errors == 3`, `crawl.pages == 0`,
    `crawl.last_error == Some(CrawlErrorKind::H2NotNegotiated)`.
  - `worker::tests::a_partially_failing_crawl_sets_no_reason`: one `report_crawl_error`
    plus one crawl page in the store (the `crawl_pages_count_each_page_once` harness shape)
    → `crawl.errors == 1`, `crawl.pages >= 1`, `crawl.last_error == None`.
  - `job.rs` unit: `CrawlErrorKind::parse("h2_not_negotiated") == Some(H2NotNegotiated)`,
    `parse("the browser refused the seed") == None`; a `CrawlCounters` with `last_error:
    Some(Timeout)` round-trips through JSON as `"last_error":"timeout"`, and
    `{"pages":1}` deserializes with `last_error == None`.
- **Done when:** the five tests pass; `cargo test -p aitm-scan-model --offline` and
  `-p aitm-plugin-scanner` pass; per-task gate green.

### Task 3: the per-host ladder counts transport errors and timeouts only

- **Satisfies:** amendment 40; spec D5 "Budget and pacing".
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-scanner/src/client.rs` (modify; the only file).
- **Change:** in `send_opts`, the `Ok(flow)` arm records `self.meter.record(&host, true,
  &self.per_host)` unconditionally (an answer of any status resets the consecutive run and
  is an `ok` in the ratio window); the `usable` computation goes. The transport-error,
  guard-refusal and `HostDisabled` arms and `await_end_error`'s `AwaitEnd::Timeout` arm keep
  recording `false`. Module doc bullet three and the `LADDER_MIN_SAMPLE` doc are reworded
  ("transport failures and timeouts"; "three transport errors trip on `consecutive: 3`").
  `ProbeMeter::record`'s doc states the rule in one sentence. No signature changes.
- **Test** (`client::tests`, replacing `host_ladder_trips_on_consecutive_5xx`):
  - `ten_5xx_answers_never_trip_the_ladder`: `consecutive: 3`, ten `Outcome::Ok(500)` → all
    ten sends return `Ok` with `status == 500`, `meter.sent == 10`, `meter.errors == 0`,
    `ladder_state(host) == LadderState::Ok`, and an eleventh send is still attempted.
  - `three_transport_errors_trip_the_ladder`: `consecutive: 3`, three `Outcome::Other("connect
    refused")` → the third returns the transport error, `ladder_state == Tripped`, the fourth
    send is `ProbeRefused::HostLadder` without reaching the inner client (`calls == 3`).
  - `a_5xx_answer_resets_the_transport_run`: sequence `Other, Other, Ok(503), Other, Other,
    Ok(500), Other` with `consecutive: 3` → never trips (`ladder_state == Ok` after all
    seven); then two more `Other` → tripped on the ninth.
  - `a_probe_timeout_is_a_typed_refusal` (existing) additionally asserts the timeout counted
    as one ladder failure (`consecutive: 1` trips it).
  - `ratio_rule_trips_too` / `ratio_rule_needs_ten_outcomes`: their failures become
    `Other(..)` transport errors; expected trip points unchanged.
- **Done when:** the tests pass, the whole `client::tests` module passes, per-task gate green.

### Task 4: `l4.icmp_pace_ms` is clamped up to `ceilings.l4_icmp_pace_ms_min`

- **Satisfies:** amendment 46 (engine half); spec D11.
- **Depends on:** none.
- **Files:** `crates/aitm-plugin-scanner/src/config.rs` (modify), `crates/aitm/src/config_file.rs`
  (modify), `crates/aitm-plugin-scanner/src/profiles.rs` (modify), `docs/scanner.md` (modify).
- **Change:**
  - `Ceilings` gains `pub l4_icmp_pace_ms_min: u32` (default `1000`, doc: "a floor, not a
    cap; a lower profile value is raised and reported"). `CeilingsFile` gains
    `l4_icmp_pace_ms_min: Option<u32>` and `apply` sets it. The struct literal in
    `config.rs::tests::scanner_config_defaults_grow` and the "all six ceilings" test in
    `config_file.rs` grow the field (now seven).
  - `profiles.rs`: new `fn raise_field<T: Copy + Ord + Into<u64>>(value: &mut T, floor: T,
    field: &str, clamped: &mut Vec<Clamped>)` (pushes `Clamped { field, requested, applied:
    floor }` when `*value < floor`); `clamp()` calls
    `raise_field(&mut p.l4.icmp_pace_ms, ceilings.l4_icmp_pace_ms_min, "l4.icmp_pace_ms",
    &mut clamped)` after the `l4.max_bytes_per_s` clamp. `clamp()`'s doc gains one sentence
    on the floor.
  - `docs/scanner.md`: row `| ceilings.l4_icmp_pace_ms_min | 1000 | Floor for a profile's
    l4.icmp_pace_ms: a lower value is raised to it and reported in clamped (amendment 46). |`
    after `ceilings.l4_bytes_per_s`; "leaves the other five alone" → "other six".
  - The packet lane's own `ICMP_PACE_FLOOR_MS` stays as defence in depth (its doc already
    says so); not touched.
- **Test:**
  - `profiles::tests::icmp_pace_below_the_floor_is_raised_and_reported`: `icmp_pace_ms:
    200` with default ceilings → `clamp(..) == vec![Clamped { field: "l4.icmp_pace_ms",
    requested: 200, applied: 1000 }]` and `profile.l4.icmp_pace_ms == 1000`; `1500` →
    empty `clamped`, value untouched; `1000` → untouched.
  - `profiles::tests::clamp_reports_each_field`: the "greediest" literal gains
    `icmp_pace_ms: 1` and its expected vector the corresponding entry in position order.
  - `config.rs::tests::scanner_config_defaults_grow`: `l4_icmp_pace_ms_min == 1000`.
  - `config_file.rs` tests: `scanner:\n  ceilings:\n    l4_icmp_pace_ms_min: 6\n` parses to
    `6` leaving `probes` at the default; the all-ceilings test asserts seven fields; the
    typo test still refuses `l4_icmp_pace_ms_mn`.
- **Done when:** the tests pass; `cargo test -p aitm-plugin-scanner --offline` and `cargo test
  -p aitm --offline config_file` pass; per-task gate green.

### Task 1b: the interim lane serves an origin host; the worker resolves origin items

- **Satisfies:** amendment 38 (lane and worker half).
- **Depends on:** Task 1 (`SchedulePlan::point_at`, `origin_points`), Task 2 (last writer of
  `worker.rs`/`interim_lane.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/interim_lane.rs` (modify: `probe_host_for`,
  `InterimProbeHost`), `crates/aitm-plugin-scanner/src/worker.rs` (modify: the planning block,
  `RunCtx`, `stop_now`, `run_item`, `item_done`).
- **Change:**
  - `InterimProbeHost.legacy` becomes `Option<crate::discover::Point>`; `captured()` returns
    `None` when the flow is synthesized (new `synthetic: bool` field); `probe()` with
    `legacy == None` returns `Err(anyhow!("origin host: no insertion point to inject into"))`.
  - `probe_host_for`: a point with `flow == None` whose id starts with `origin:` and whose
    `url` parses builds a host over a synthesized `HttpFlow` for `GET <url>` (HTTP/1.1,
    empty headers; the job client applies the profile's version policy and D7 session
    merge as it does for any baseline). Any other flowless point keeps today's error.
    `baseline()`, `probe_raw()`, `charge()`, `baseline_peer_addr()` work unchanged over it.
  - `worker.rs`: `RunCtx` gains `plan: &SchedulePlan`; `stop_now` and `run_item` resolve the
    point with `self.plan.point_at(self.points, item.point)`; `item_done` bumps
    `points.audited` only for `index < self.points.len()`. `points.queued` and
    `checks.scheduled` keep counting every item (origin items included).
- **Test:**
  - `interim_lane::tests::an_origin_point_gets_a_host_whose_baseline_is_get_root`: a
    `TestJob` with a recording stub client; `probe_host_for(&origin_point("http://scan.test:80"))`
    succeeds; `host.baseline().await` sends exactly one request with `method == "GET"`,
    `path == "/"`, `authority == "scan.test:80"`; `host.probe(&payload).await` is `Err`;
    `host.captured().is_none()`; a flowless point with id `q:1` still fails with the
    "carries no flow" error.
  - `worker::tests::an_origin_scoped_check_runs_on_an_origin_without_points`: `FakeLane`
    whose `discover` returns no points and a `FakeCheck` with `scope: CheckScope::Origin` →
    terminal `state == Done`, `checks.scheduled == 1`, `checks.done == 1`, `points.found ==
    0`, `points.audited == 0`, the check's `runs == 1`.
  - `worker::tests::origin_items_do_not_count_as_audited_points`: two real points plus the
    origin item → `points.audited == 2`, `checks.scheduled == 3` (one point check per point
    plus one origin item).
- **Done when:** the three tests pass; `scheduler`, `interim_lane` and `worker` modules pass;
  per-task gate green.

### Task 5: deterministic terminal waits

**Rescoped 2026-11-01 (coordinator priority request):** the production piece — a `watch` terminal signal on `JobEntry`, flipped in `JobRegistry::finish`, `JobRegistry::terminal_signal`, and the signal-based `test_support::wait_terminal`/`wait_terminal_blocking` under a 60 s `TERMINAL_NET` — ships ahead of this PR in **PR #285** (branch `claude/scanner-v2-flaky-tests`, off main 449d6d17) together with the `cancel_moves_to_cancelled_and_keeps_issues` fix and the `aitm-scan-ws` dialer test deadlines. This PR merges main after #285 lands and Task 5 then covers only what #285 did not: (a) the remaining wall-clock *measured* assertions in the four scanner test modules (`verbs.rs` `start_returns_a_start_result_immediately` `< 2 s`; `commands.rs` `discover_time_budget_cancels_and_reports` `< 6 s` with `CANCEL_GRACE` 5 s, the 5 s confinement-release poll, the 10 s `recv_timeout`) — convert to the mechanism or accept in writing; (b) the production `commands.rs::poll_until` (100 ms sleep loop behind `scan.discover`) → the terminal signal; (c) the inventory table below re-checked after the merge (every `wait_terminal(.., Duration)` is already gone in #285). The cancel test is out of this PR's scope.

- **Satisfies:** CI determinism (the `cancel_moves_to_cancelled_and_keeps_issues` 2 s failure);
  the "tests must be deterministic" convention.
- **Depends on:** Task 1b (last writer of `worker.rs`).
- **Files:** `crates/aitm-plugin-scanner/src/jobs.rs` (modify: `JobEntry`, `admit`/reload sites,
  `finish`, `test_support`, tests), `crates/aitm-plugin-scanner/src/worker.rs` (tests only),
  `crates/aitm-plugin-scanner/src/verbs.rs` (test harness wrapper only),
  `crates/aitm-plugin-scanner/src/commands.rs` (test harness wrapper and its callers only).
- **Change:**
  - Production (small): `JobEntry` gains `pub terminal: tokio::sync::watch::Sender<bool>`
    (`watch::channel(false)` at construction; an entry admitted already terminal, i.e. a
    reloaded record, starts `true`). `JobRegistry::finish` calls `send_replace(true)` before
    pruning (it is the last step of `worker::terminal`, after the status is written and
    persisted). New `pub fn terminal_signal(&self, id: &str) -> Option<watch::Receiver<bool>>`
    and `pub async fn wait_terminal(&self, id: &str) -> Option<JobStatus>` (subscribe, `wait_for(|t| *t)`,
    then `status(id)`; `None` for an unknown id). Every `JobEntry` literal (start, reload,
    tests) gains the field.
  - `test_support`: `pub(crate) const TERMINAL_NET: Duration = Duration::from_secs(60)` (a
    safety net so a hung job fails the test with its state and phase named, never the
    measured bound). `wait_terminal(registry, job)` and the harness method
    `wait_terminal(&self, job)` lose the `within` parameter: `tokio::time::timeout(TERMINAL_NET,
    registry.wait_terminal(job))`, panicking with the state/phase on expiry. `poll_terminal`
    goes. `wait_terminal_blocking` builds a current-thread runtime and `block_on`s the same
    future under the same net. Every call site drops its `Duration` argument: `worker.rs`
    26, `jobs.rs` 4 direct, `verbs.rs` 14 through its harness wrapper (`verbs.rs` 1352,
    already bound-less, now forwarding to the new helper), `commands.rs` 6 through its
    blocking wrapper (`commands.rs` 2794, which loses `within`).
  - Inventory of wall-clock waits in `worker.rs`/`jobs.rs` tests and their disposition:

    | Site | Today | Disposition |
    |---|---|---|
    | `worker.rs` 1599, 1702, 1734, 1764, 1904, 1945, 1969, 1991, 2010, 2031, 2064, 2100, 2144, 2441, 2478, 2494, 2523, 2562, 2636, 2799, 2835, 2866 | `wait_terminal(.., 5 s)` | converted in #285 (notification); re-checked after the c7575cdc merge: `grep "wait_terminal("` over `worker.rs`/`jobs.rs` shows no `Duration` argument left |
    | `worker.rs` 1651, 2728, 2761 | `wait_terminal(.., 2 s)` (the CI failure) | converted in #285; re-checked, gone |
    | `worker.rs` 2675 | `wait_terminal(.., 10 s)` (panic path) | converted in #285; re-checked, gone |
    | `worker.rs` 1638-1641 | poll `issues.for_job` under a 5 s deadline, 10 ms sleep | converted in #285 to a poll under `TERMINAL_NET`; re-checked: `grep "from_secs(2)\|from_secs(5)\|from_secs(10)"` over `worker.rs`/`jobs.rs` returns nothing |
    | `worker.rs` 1659 | `sleep(100 ms)` then "no client call after `finished_at`" | keep: a negative wait that can only miss a bug, never fail spuriously; comment says so |
    | `worker.rs` 1833 | 50 x 10 ms ticks on the injected `ProgressClock` | keep: already an injected clock, no real sleep |
    | `worker.rs` 2185 (now 2470) | `Instant::now() + 60 s` budget deadline | keep: a budget the test never reaches |
    | `jobs.rs` 2653, 2976, 3008, 3177 | `wait_terminal(.., 5 s)` | converted in #285; re-checked, gone |
    | `jobs.rs` 2170, 2185 | the helper's own 10 ms polls | removed with the helper in #285 |
    | `jobs.rs` 1481 | stub check polls `host.cancelled()` every 5 ms | keep: the fake check's blocking body (`ProbeHost` exposes a bool, not a token); it ends on cancel, not on a bound |
    | `verbs.rs` 1573 `start_returns_a_start_result_immediately` | `began.elapsed() < 2 s` | converted (this PR): the job runs `FakeCheck::blocking`, which cannot end until cancelled, so the verb answering with `terminal_signal(job)` still `false` proves it did not wait for the work; then `scan.cancel` + `wait_terminal`. No clock |
    | `commands.rs` 1550 `scan_discover_crawls_under_egress_confinement` | poll `posture.confined()` under a 5 s deadline, 10 ms sleep | converted (this PR): with the verb's wait on the terminal signal (flipped last in `finish`, after the hold drops) the release has happened when `invoke` returns; direct `assert!(!posture.confined())` |
    | `commands.rs` 1652 `overlapping_scan_is_refused_without_touching_the_browser` | `gate.entered.recv_timeout(10 s)` | net (this PR): the gate channel is the notification; the bound is `TERMINAL_NET`, documented in the test as a safety net that names the hang, never measured |
    | `commands.rs` 2986 `discover_time_budget_cancels_and_reports` | `started.elapsed() < 6 s` (300 ms budget + `CANCEL_GRACE`) | converted + net (this PR): the lane only ends on cancel, so `stopped_reason: time_budget` plus the job's `Cancelled` state is the proof the budget ended the wait; the call runs on a scoped thread under `recv_timeout(TERMINAL_NET)` which cancels the job and panics by name on expiry |
    | `commands.rs` 241 `ScanDiscover::poll_until` (production) | `status()` every 100 ms `thread::sleep` until terminal or deadline | converted (this PR) to `wait_until`: `tokio::time::timeout(within, ..)` on the registry's terminal signal, run on the engine's runtime and bridged to the synchronous verb over a `std::sync::mpsc` channel; `scan.discover`'s deadline semantics (budget, then `cancel` + `CANCEL_GRACE`) unchanged; a pruned entry (sender dropped) still answers with the last status. Red test `discover_wait_answers_on_finish_not_on_a_terminal_status`: the wait answers after `finish`, not on a terminal `state` |
- **Test** (as landed; the four names below were the pre-#285 draft and were superseded):
  - #285 shipped the signal and its test `jobs::tests::terminal_signal_flips_once_on_finish_and_reads_true_for_finished_jobs`
    (unknown id → `None`; running → `false`; a waiter wakes on `finish`; `true` after; a reloaded
    record starts `true`). The cancelled-waiter case is covered by `verbs::tests::start_returns_a_start_result_immediately`
    (cancel, then wait under `TERMINAL_NET`). `JobRegistry::wait_terminal` (`wait_for(|t| *t)` → `status(id)`)
    lands in this PR's panel fix round (quality Minor: two hand-rolled watch loops), used by `wait_until` and `test_support`.
  - This PR's converted sites: `commands::tests::discover_wait_answers_on_finish_not_on_a_terminal_status`
    (production `wait_until`), `verbs::tests::start_returns_a_start_result_immediately`,
    `commands::tests::scan_discover_crawls_under_egress_confinement`,
    `overlapping_scan_is_refused_without_touching_the_browser`, `discover_time_budget_cancels_and_reports`.
  - Static check the Tester repeats: `grep -n "from_secs(2)\|from_secs(5)\|from_secs(10)"`
    over the `#[cfg(test)]` regions of `worker.rs` and `jobs.rs` lists only the kept sites
    above (the 60 s budget deadline, and none of the converted ones).
- **Done when:** the tests above pass; `cargo test -p aitm-plugin-scanner --offline` passes
  three times in a row in the sandbox (no flake); per-task gate green.

### Task 7: `JobCtx::report_forms_submitted` feeds `crawl.forms_submitted` (amendment 53)

**Added 2026-11-01 (coordinator, amendment 53, additive; ordered right after Task 1b so T2 can un-draft #223 against a real counter).** `JobStatus.crawl.forms_submitted` exists in the model but nothing writes it: there is no `JobCtx` hook (only `report_forms_skipped` / `report_crawl_error`), and T2's lane really submits forms on real obscura (five per map on the test target), so AC T2-1's `forms_submitted >= 1` asserts a counter that cannot move.

- **Files:** `crates/aitm-scan-model/src/traits.rs` (`fn report_forms_submitted(&self, count: u32) {}` default no-op beside `report_forms_skipped`), `crates/aitm-plugin-scanner/src/worker.rs` (`JobRuntime.forms_submitted: AtomicU64`, the hook adds to it, `sync_counters` raises `crawl.forms_submitted` monotonically like `forms_skipped`), `crates/aitm-plugin-scanner/src/interim_crawl.rs` + `interim_lane.rs` (`client_crawl` region: the interim client crawl counts the forms it submits and reports them, so the interim lane feeds the counter too), `crates/aitm-plugin-scanner/src/jobs.rs` test support (`FakeLane::with_forms_submitted(n)` calling the hook from `discover`).
- **Tests (red first):** `worker::tests::reported_form_submissions_reach_the_status` — a lane reporting 3 submits yields `crawl.forms_submitted == 3` in the terminal status and in `scan.status`; `interim_crawl::tests::submitted_forms_are_counted` — the client crawl's `ClientCrawl.forms_submitted` equals the POSTs it sent (the destructive/logout skips do not count); a reload of a pre-amendment record reads 0 (serde default; already covered by `crawl_counters_additive_fields_default_to_zero`, extend if needed).
- **Done when:** the three tests are green, `cargo test -p aitm-scan-model -p aitm-plugin-scanner` green, docs/scanner.md's status field list names `crawl.forms_submitted` as written by any lane through the hook (Task 6 docs coder or this task, one writer).
- **Ownership:** runs after Task 1b (same `worker.rs`/`interim_lane.rs`), before Task 5.

### Task 10: `marker()` is fresh per call; `job_id()` is the per-job key (amendment 57)

**Added 2026-11-01 (T5's real-bus cells; T6 hit it earlier).** `JobCtx::marker()` returns a fresh token per call (right for canaries); two lanes keyed per-job state on it and silently missed every lookup.

- **Rule:** the trait documents, on `marker()`, that every call mints a new token and it must never be used as a key, and names `JobCtx::job_id()` as the stable per-job key (it already exists; if a lane needs a `&str` key with a different lifetime shape, add nothing — point at `job_id()`). The `ProbeHost::marker` docs say the same.
- **Files:** `crates/aitm-scan-model/src/traits.rs` (docs), `crates/aitm-plugin-scanner/src/worker.rs`/`interim_lane.rs` (`ProbeHost::marker` impl docs only).
- **Tests:** `worker::tests::markers_are_fresh_per_call_and_job_id_is_stable` — two `marker()` calls on one runtime differ, `job_id()` is identical across calls and equals `status.job`.
- **Ownership:** after Task 7 (worker.rs), before Task 8 (which changes `marker`'s body).

### Task 11: a check that returns `Outcome::Error` is counted, sampled and logged (amendment 58)

**Added 2026-11-01 (T5's lane was inert for an hour with `done` in 1 s, 0 cases, 0 frames and no trace).** Today the worker's `note_lane_text` drops the detail, `checks.errors` is never bumped, nothing is logged.

- **Rule:** on `Outcome::Error` the worker bumps `JobStatus.checks.errors` (add the field to `CheckCounters` if absent, additive, serde default), keeps the first 8 error details per job on an additive `JobStatus.checks.error_samples: Vec<CheckErrorSample { check, point, detail }>` (scrubbed through `util::scrub`, detail bounded like evidence excerpts; distinct `(check, detail)` pairs only), and emits one `tracing::warn!` per distinct detail kept (the first 8, never per probe), then one notice that the sample store is full; later distinct errors are counted only (panel-accepted bounded reading, spec Minor). `Outcome::Inconclusive` is unchanged.
- **Files:** `crates/aitm-scan-model/src/job.rs` (fields), `crates/aitm-plugin-scanner/src/worker.rs` (`run_item`/`item_done` region, `JobRuntime` sample store, `sync_counters`), `docs/scanner.md` status notes (Task 6 docs coder or this task — one writer).
- **Tests (red first):** `worker::tests::an_erroring_check_is_counted_sampled_and_logged` — a `FakeLane` check returning `Outcome::Error` with detail `"runner missing"` on two points → `checks.errors == 2`, `error_samples.len() == 1` (distinct), sample names the check id and the first point, detail scrubbed; a ninth distinct detail is not kept (cap 8); `scan.status` shows them; `job::tests::check_counters_additive_fields_default_to_zero` (reload without the fields → 0 / empty).
- **Ownership:** after Task 7 and Task 10 (worker.rs, model job.rs), before Task 8.

### Task 8: per-job random nonce in `util::marker` (amendment 55, security Minor from T3's 2b panel)

**Added 2026-11-01.** `util::marker(counter)` is `aitm` + an 8-hex per-job counter starting at zero, so every job's first marker is `aitm00000000`; the converted Rhai checks (ssti/cmdi/crlf/xxe/cors/header-reflection) use `probe.marker()` as their canary, so a target that knows aitmproxy can forge a Vulnerable verdict by echoing `aitm0000000N`.

- **Rule:** markers stay `aitm` + 8 hex (every pin and every script matcher keeps working), but the 8 hex mix a per-job random seed with the counter (e.g. `counter ^ seed` or a keyed hash truncated to 32 bits) so two jobs' first markers differ and a job's markers stay unique (a bijection of the counter per job; no collision within a job).
- **Files:** `crates/aitm-plugin-scanner/src/util.rs` (`marker(seed, counter)`; `marker_seed()` from `rand`/`getrandom` or `std::collections::hash_map::RandomState`-derived u32 — whatever the crate already depends on, no new dependency unless unavoidable), `worker.rs` (`JobRuntime` holds the seed; `ProbeHost::marker` uses it), `manual_check.rs` (its scratch host mints a seed per invocation), the interim lane's `ProbeHost::marker` impl if separate.
- **Tests (red first):** `util::tests::markers_keep_the_shape_and_differ_across_seeds` (regex `^aitm[0-9a-f]{8}$`; two seeds → different first markers; 1,000 counters under one seed → 1,000 distinct markers); `worker::tests::two_jobs_first_markers_differ` (two jobs on one engine, their first markers differ; the second marker of one job differs from its first).
- **Ownership:** after Task 7 (worker.rs); `util.rs` has no other writer.

### Task 9: scrub `Evidence.matched` on the Rhai bridge and the manual path (amendment 56, security Minor from T3's 2b panel)

**Added 2026-11-01.** D8.1 / amendment 16: the Rhai bridge bounds `evidence.matched` but does not scrub it, and the manual `check.<id>` path returns the verdict to the bus caller unscrubbed; the job path scrubs in `worker.rs` only.

- **Rule:** `Evidence.matched` (and `payload`) are scrubbed with `aitm_core::redact::scrub_text_wide` where the verdict is built, so both the job path and the manual path emit scrubbed evidence; the worker's scrub stays (idempotent).
- **Files:** `crates/aitm-plugin-rhai/src/check_bridge.rs` (where the verdict map becomes `Verdict`: scrub `matched`/`payload` after the excerpt bound), `crates/aitm-plugin-scanner/src/manual_check.rs` (scrub the returned verdict's evidence before `result_of`, covering native checks too).
- **Tests (red first):** `check_bridge` test: a closure returning `matched` containing `Cookie: sid=s3cr3t` and `Authorization: Bearer abc.def` yields `matched` with both values redacted and the bound still applied; `manual_check::tests::manual_verdict_evidence_is_scrubbed`: a native check whose evidence echoes a bearer token returns a redacted `matched` through `check.<id>`.
- **Ownership:** `check_bridge.rs` (aitm-plugin-rhai, T1b row) and `manual_check.rs`; no overlap with Tasks 1b/7; can run in parallel with them.

### Task 12: the manual path hands the check a shared host (amendment 62, BLOCKER from T3's 2b live run)

**Files:** `crates/aitm-plugin-scanner/src/manual_check.rs` only (orchestrator, test-first, folded in before the push).

Every manual `check.<rhai-id>` returned "the engine must hand a shared probe host to a script check (ProbeHost::shared returned none)": `manual_check.rs` ran `check.run(&point, host.as_ref())` on the lane's `Box<dyn ProbeHost>`, whose `shared()` is the trait default `None`, while the worker wraps the same host in `worker::ArcHost` (whose `shared()` is `Some`). The manual path now wraps it the same way.

- [x] Test `manual_check::tests::manual_check_hands_a_shared_host_to_the_check`: a native `needs-shared` check returns `Vulnerable`/"shared host received" when `host.shared()` is `Some` and `Error`/"ProbeHost::shared returned none" otherwise; red on the unwrapped host (left: the error text), green wrapped.

**Amendment 63 (recorded, not done here):** the interim discovery sets no `PointTrait`s, so `wants_traits` checks (path-traversal: filename, ssrf: url) run only under `speed: thorough`; T2's insertion points v2 (#223) replaces the interim discovery, so `discover.rs` is left alone.

### Task 13: `test_t3_h2_observe.py` tells pooled connections apart by the `host` header (e2e-only, consequence of amendment 38)

**Files:** `tests/e2e/scan/test_t3_h2_observe.py` only (orchestrator; D12 exception for a `tests/e2e/**` edit, T3 informed — the cell is T3's).

Live run on `c6092927` (cells17: 20 pass / 17 skip / 1 fail): the cell counted 4 raw h2 connections instead of 5. Dump of the target log (`/tmp/claude/t1b/proof/out/h2_dump.log`): all five checks ran on five raw connections (c-2…c-6), issues correct (`settings-observe`, `rapid-reset-mitigation`), `checks.done 5`, `probes.sent 9`. The cell classified any connection that carried `GET /` as the job client's pooled connection; since amendment 38 the five checks' baselines are `GET <origin>/` on the pooled connection and the raw rapid-reset probe's eight stream heads are `GET /` too (the check cuts `:path` from the origin item's URL `<origin>/`, where it used to cut `/search` from a captured point), so the rapid-reset connection was mis-filed as pooled. Fix: pooled = connections whose request rows carry a `host` header (the job client sends one on every request; a raw probe stream writes pseudo-headers only — every c-6 row has an empty header map, every c-1 row has `host`). Engine untouched.

### Task 13b: `test_t3_version_override.py` asserts the amendment-39b shape (e2e-only; the plan's live proof for 39)

**Files:** `tests/e2e/scan/test_t3_version_override.py` only (orchestrator; D12 exception, T3 informed).

The cell forces `http.version: h2` against the h1-only listener — exactly the plan's live proof for amendment 39 — but its second half encoded the superseded row 39 (`stopped_reason == "errors"`, `h2_not_negotiated` in `status.error`) and SKIPped whenever both were null, which under the coordinator's 39b ruling is forever (cells17: SKIP "pending amendment 39", `probes.errors 6, sent 0`). It now asserts 39b: `state done`, `stopped_reason` and `error` null, `crawl.errors > 0`, `crawl.pages == 0`, `crawl.last_error == "h2_not_negotiated"`, `probes.errors > 0`; the T3 half (h1 override) is unchanged. Running to its end for the first time exposed one latent assertion (cells19): it expected every handshake on the h1-only listener to negotiate `http/1.1`, but a client offering ALPN `["h2"]` only selects nothing and the target logs `none` for all three handshakes — which is what `h2_not_negotiated` names; corrected to `none` (34950db1).

### Task 14: no pre-terminal hold read in the panicking-lane test (amendment 71, test determinism; CI flake on #289)

**Files:** `crates/aitm-plugin-scanner/src/worker.rs` (one test) — orchestrator.

`a_panicking_lane_ends_the_job_failed_and_frees_the_origin` asserted `egress_confined()` right after `jobs::start`; on `flavor = "multi_thread"` the fake lane's panic can end the job and release the hold first. The assertion is dropped (comment names the race and the deterministic pin: `commands::tests::discover_wait_answers_on_finish_not_on_a_terminal_status` holds an unfinished entry and asserts the hold); the post-terminal checks stay. `grep "confined()"` over worker tests: no other pre-terminal read of that shape. Gate for this test-only hunk: sandbox `cargo clippy -p aitm-plugin-scanner --all-targets -- -D warnings` + the test ×5 + the crate once (the full Terminal gate ran on the Rust tree one test-hunk earlier, `c6092927`).

### Task 15: the engine hosts an origin item when the lane crate cannot (amendment 38 × T2's lane; after the 167e74b9 merge)

**Files:** `crates/aitm-plugin-scanner/src/worker.rs` (`run_item`), `jobs.rs` test_support (`FakeLane::refusing_flowless_points`) — orchestrator, test-first.

Merging main 167e74b9 (T2's `aitm-scan-http` takes the http slot) made `test_t3_h2_observe.py` red: no `h2-settings-observe` issue. T2's `HttpProbeHost::new` refuses a point with no source flow, so every origin item failed in `probe_host_for` and was marked `checks.done` silently (the silence follow-up 69 names). `run_item` now falls back to the engine's own origin host (`engine.interim.probe_host_for`, the synthesized `GET <origin>/`) for a flowless `origin:` item of the http lane the lane refused — engine-owned like T2's passives, so origin-scoped checks run whatever crate holds the slot. Test `an_origin_item_is_hosted_by_the_engine_when_the_lane_cannot` (red: the check never ran).

Also found on the merged build, not PR 2's, reported to the coordinator:
- `test_t3_version_override.py`: T2's crawler calls neither `report_crawl_error` nor `report_forms_submitted`, so 39b has no signal on the real lane; the cell SKIPs 77 loudly when `lane_source == crate && crawl.errors == 0` (hand-off: T2 lane wires the amendment-39/53 hooks) — coordinator: T2's hotfix `fix/t2-host-client-charge` wires 39b and 38; the SKIP stays until it lands, then the cell asserts 39b for real.
- `test_t1_finding_link`, `test_t2_mutable_points`, `test_t2_session_reuse` ("the second job in the same core sends nothing to its own target") — **amendment 74, coordinator's ruling: a focused core PR "T1b PR 2b: amendment 74 guard authority" right after "292 ready", before PR 3** (patch kept at `/tmp/claude/t1b/pr2b/`; test: two authorities on one host, one exhausted, the other served; live proof: the three cells green). Reclassified with the coordinator's facts: on main the scanner's ladder cut the first job short on 5xx, with amendment 40 it runs its full 2000 probes, so the trigger is #292 and the defect is aitm-core's: aitm-core's `StdGuard` keys throttle, error budget and disable window on `Authority.host` with the port dropped, and its client charges every upstream failure and 5xx to it; two targets on 127.0.0.1 share one budget, a full 2000-probe job exhausts it and the next job's probes are `HostDisabled` → ladder → `stopped_reason: errors`. Measured: P alone 2000/0 errors; P after a 60-probe V clean; P after a full V 10 errors, stopped. Proposed amendment: key budget + disable window by normalized authority (host:port).
- `test_t1_contract` (`scan.discover` `max_pages: 2` → `pages_crawled 4`): T2's crawlers each stop at `attempts >= limits.max_pages` (`crawl/client.rs:146`, `crawl/browser.rs:573`), so with more than one crawler per origin, or attempts counted as pages, `crawl.pages` exceeds the profile's bound (T2 lane accounting; `scan.discover` reports `status.crawl.pages` unchanged).

### Task 16: the cancel snapshot may already read `Cancelled` (amendment 71b)

**Files:** `crates/aitm-plugin-scanner/src/worker.rs` (one test). `cancel_moves_to_cancelled_and_keeps_issues` asserted `Cancelling` on the status `registry.cancel()` returns; the finaliser can have moved it to `Cancelled` first (CI on #229). Either state says the cancel took; terminal facts stay asserted after the signal. ×5 green.

### Task 13c: two more loud SKIPs for aitm-scan-http gaps surfaced by the 09108b51 merge (e2e-only)

**Files:** `tests/e2e/scan/test_t3_version_override.py`, `tests/e2e/scan/test_t1_record_policy.py` — orchestrator; coordinator's rule: a red cell that is a T2 gap SKIPs 77 naming the amendment, never fails and never reads green.

- `test_t3_version_override.py`: with T2's hook wired, the cell runs to the 39b assertions and the lane crate's `crawl_error_token` names the forced-h2 failure `connect_refused` (io-kind and `starts_with("h2_not_negotiated:")` passes before the text pass; the sender's error reaches it as a "refused" text first); the interim lane answers `h2_not_negotiated`. SKIP names the token; coordinator: **amendment 78**, T2 follow-up; the assertion stays.
- `test_t1_record_policy.py`: `aitm-scan-http` (#295 "seeds are not pages") fetches `/robots.txt` and `/sitemap.xml` through the recording client without the `crawl` mark, so they land in the store as probe rows with no `issue:<id>` — a record-policy gap in the lane (the interim lane marks every crawl fetch). SKIP only when the offenders are exactly those seed paths on a lane crate; coordinator: **amendment 79**, T2 follow-up.
- `test_t2_session_reuse.py` ("job 2 (session none) has issues on /account") — **Task 13d, measured** (`/tmp/claude/t1b/proof/out/session_dump.log`): job 2 sends no cookie to `/account` (22 requests, `cookie_names []`, all 302), so session mode `none` is honoured; its two issues are the engine's shipped passive checks (`security-header`, `reflection`) on that 302, merged across jobs via `Issue.jobs` (`jobs: [job1, job2]`). AC T2-4 is about the session-dependent reflected-xss, so the assertion is narrowed to the cell's own `reflected()` class (job 1's assertion already was). Trigger: amendment 40 lets job 2 run to `/account` where main's ladder trip cut it short. Job 2 also stops `errors` after 262 probes (amendment 74, PR 2b).

### Task 13e: version-override cell allows the ladder's early stop (amendments 38 + 40 together); core breaker finding (amendment 80 candidate)

**Files:** `tests/e2e/scan/test_t3_version_override.py` — orchestrator. After the 833a0e4d merge (T3's fifteen bundled checks on the bridge) the forced-h2-against-h1 job ends `stopped_reason: errors`: amendment 38's origin items probe `<origin>/` over h2, fail like the crawl, and amendment 40's ladder (transport errors count) stops the job — a legitimate early stop, `error` null, the 39b crawl signal intact. The cell accepts `stopped_reason ∈ {None, "errors"}`.

**Core finding (reported to the coordinator, amendment 80 candidate; PR 2b scope):** aitm-core's `host_error_budget` (default 10) counts every upstream failure AND every 5xx answer, then disables the host for a backoff window; a scan that provokes 5xx on a vulnerable target (sqli/cmdi/xxe payloads, now ×15 bundled checks) exhausts it inside one job, the proxy refuses the remaining probes (`HostDisabled`), the scanner's ladder counts the refusals and the job stops `errors` before its catalogue is done — `test_t3_catalogue_sweep.py` ("pending the error-ladder fix") and, across jobs on one host, `test_t3_h2_sender.py`/`test_t2_mutable_points.py` ("P probed: 0 requests"). Amendment 40 made the scanner's ladder tolerate 5xx; the core's breaker must do the same for scanner probes (an answered probe is not an upstream failure), or the job client must opt out of the 5xx half of the budget. Keying by authority (74) alone does not fix the single-target case.

### Task 6: bookkeeping and docs wording

- **Satisfies:** workflow stage-7 record keeping; amendment 39/40 operator docs.
- **Depends on:** Tasks 1-5 (docs only; runs last so it names final behaviour).
- **Files:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t1b-plan.md` (Shipped
  section), `docs/superpowers/plans/2026-11-01-aitmproxy-scanner-v2-t1b-followup-2-plan.md`
  (Review log and Shipped stubs, this file), `docs/scanner.md` (two sentences; Task 4 has
  finished with the file by then).
- **Change:**
  - T1b plan "Shipped": first line becomes "Merged as #232 = `3aa8cc67` (squash),
    2026-11-01; follow-up 2: PR #<n> (amendments 38/39/40/46, deterministic job tests)".
  - This plan: Review log table header present and empty; Shipped stub "Filled at
    integration".
  - `docs/scanner.md`: the `per_host_errors` comment (line 212) reads "consecutive transport
    errors or timeouts from one host trip the breaker; a 5xx is an answer"; the
    `crawl.errors` reading note (line 393) adds "and, since follow-up 2, every failed
    client-crawl request; when every request failed `crawl.last_error` names why
    (`h2_not_negotiated`, `connect_refused`, `tls`, `timeout`, `transport`, `other`)".
- **Test:** none executable; the Spec reviewer checks the three files against this plan.
- **Done when:** the three files read as above and `cargo fmt --check` is unaffected.

## File ownership matrix (disjointness check)

| File | Task 1 | Task 2 | Task 3 | Task 4 | Task 1b | Task 5 | Task 6 |
|---|---|---|---|---|---|---|---|
| `aitm-plugin-scanner/src/scheduler.rs` | W | | | | | | |
| `aitm-plugin-scanner/src/client.rs` | | | W | | | | |
| `aitm-plugin-scanner/src/interim_crawl.rs` | | W | | | | | |
| `aitm-plugin-scanner/src/interim_lane.rs` | | W (client_crawl) | | | W (probe_host_for) | | |
| `aitm-plugin-scanner/src/worker.rs` | | W (crawl phase, JobRuntime) | | | W (audit region) | W (tests) | |
| `aitm-plugin-scanner/src/jobs.rs` | | | | | | W | |
| `aitm-plugin-scanner/src/verbs.rs`, `commands.rs` | | | | | | W (tests + `commands.rs::wait_until`, the rescoped production piece) | |
| `aitm-plugin-scanner/src/config.rs`, `profiles.rs` | | | | W | | | |
| `aitm/src/config_file.rs` | | | | W | | | |
| `aitm-scan-model/src/job.rs`, `traits.rs` (doc) | | W | | | | | |
| `docs/scanner.md` | | | | W | | | W |
| the two plan files | | | | | | | W |
| Task 7 (`traits.rs` hook, `worker.rs` runtime counter, `interim_crawl.rs`/`interim_lane.rs` client_crawl, `jobs.rs` test support) | | | | | after 1b | before 5 | |

Wave A's four tasks share no file. `worker.rs` and `interim_lane.rs` are written by Task 2,
then Task 1b, then (tests only) Task 5, strictly in that order; the orchestrator dispatches
Task 1b only after Task 2's commit and Task 5 only after Task 1b's.

## Acceptance (whole branch; orchestrator, Terminal)

- Rust gate from the worktree root: `cargo fmt --check && cargo clippy --all-targets --
  -D warnings && cargo test`; judged by exit code.
- `python3 tests/e2e/run.py scan`: counts unchanged or better than `main` today
  (19 pass / 19 skip / 0 fail). The cells to watch: `test_t3_h2_observe.py`,
  `test_t3_version_override.py`, `test_t2_crawl_client.py`, `test_t1_cancel.py`.
- `cargo test -p aitm-plugin-scanner` three consecutive runs under `nice -n 19 cargo build`
  load in another Terminal tab: zero reds (Task 5's claim).
- Live proof notes, one line each in the Shipped section:
  - **38:** a driver run against the testtarget with a profile whose only target is a
    parameterless page (T3 PR 2a's live-run script); `scan.status.checks.scheduled` is at
    least the number of catalogue checks with `scope: origin` for the HTTP lane, and
    `test_t3_h2_observe.py` stays green.
  - **39:** `test_t3_version_override.py` (forced `http.version: h2` against the h1-only
    listener) or a driver run of the same shape: `crawl.errors > 0`, `crawl.last_error ==
    "h2_not_negotiated"`, `state: done`, no `error`. If the cell does not force h2 against
    an h1-only listener, the driver run is the proof and the cell is left alone (no
    `tests/e2e/**` edits in this plan).
  - **40:** unit-only. Reason: the testtarget has no 5xx-answering endpoint and the T1b
    Shipped section already lists "a live T10 cell against a 5xx target for
    `stopped_reason: errors`" as a follow-up; this plan does not add e2e cells.
  - **46:** unit-only here; the lane half was proven in the T5 live proof (PR #264).

## Architect's calls (for the coordinator/Matt to approve or correct)

- **C1.** Origin items live in `SchedulePlan.origin_points` and are addressed by an index past
  `points.len()` (additive; `ScheduleItem`'s type unchanged), instead of a new item enum.
- **C2.** The origin set is the profile's target origins plus any origin a discovered point
  belongs to; origin items bypass every point gate except intensity; only HTTP-lane
  origin-scoped checks move to the new rule (other lanes keep the point-derived one).
- **C3.** The origin host is the interim lane's `InterimProbeHost` over a synthesized `GET
  <origin>/` flow with `probe()` refused and `captured()` empty, rather than a new host type.
- **C4.** Amendment 39's reason is a closed `CrawlErrorKind` token on
  `crawl.last_error` (`Copy`, keeps `CrawlCounters: Copy`), set only when `crawl.errors > 0
  && crawl.pages == 0`; no new `JobCtx` method; the lane passes the token through the
  existing `report_crawl_error` once per failed request.
- **C5.** A 5xx answer resets the consecutive transport run (an answer means the host is up).
- **C6.** `raise_field` is a separate helper, not a direction flag on `clamp_field`.
- **C7.** The terminal notification is a `watch::Sender<bool>` on `JobEntry`, flipped in
  `JobRegistry::finish`; the test helper loses its `within` parameter so no bound survives
  at any call site; `TERMINAL_NET` is 60 s.
- **C8.** Task 3's docs wording moves to Task 6 so `docs/scanner.md` has one writer per wave.

Interplay worth knowing (not a decision): after Tasks 1, 2 and 3 together, the T3 forced-h2
scenario ends `state: done` with `crawl.errors == N`, `crawl.last_error ==
"h2_not_negotiated"`, and `stopped_reason: errors` **when** at least `consecutive` transport
errors tripped the host (the origin items then find the host tripped), else `null`.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1 | Coder (Task 1) | Note | Plan said only `origin_and_node_scoped_checks_run_once` needed new indices; in fact `scope_keys_without_nodes_fall_back_to_url_then_point` pinned the superseded rule and was re-pinned (indices `[4, 5, 6]` + origin-id assertion) | accepted by the orchestrator 2026-11-01: the old assertion encoded the rule amendment 38 replaces; committed in f4e7b90f |
| 1 | Coder (Task 1) | Note | Plan wording "`scope_key` returns `None`" would mean per-point scheduling; implemented as the point loop `continue`-ing on origin-driven HTTP checks (the only reading matching the plan's own counts) | accepted; `scope_key`'s `Origin` arm stays for non-HTTP lanes |
| 3 | Coder (Task 3) | Important (casualty) | `worker::tests::an_all_erroring_host_stops_the_job_with_stopped_reason_errors` used `answering(500)` as the host failure, which amendment 40 removes from the ladder; `StubClient` has no transport-failure mode; `jobs.rs` docs still say a 5xx is what the ladder counts | fixed in bf3526e5: `StubClient::failing` + `Harness::failing`, the test's stimulus is a transport error, `answering(5xx)` helpers removed (no caller), `jobs.rs` docs corrected; `docs/scanner.md` `per_host_errors` wording is Task 6's per C8 |
| 4 | Coder (Task 4) | Note | New ceiling placed after `l4_bytes_per_s`; "the other five" → "six" in `config_file.rs` and docs; only other `Ceilings` literal uses `..default()` | accepted; committed in c9fe6b3e |
| 2 | Coder (Task 2) | Note | Plan named full-run tests needing a `FakeLane` crawl-error hook in `jobs.rs` (Task 5's file); the coder covered the behaviour at the `JobRuntime` level and asked for the hook | orchestrator added `FakeLane::with_crawl_errors` and the two full-run tests in bf3526e5; the runtime-level tests stay |
| 5 | Orchestrator | Note | Task 5's production piece (terminal signal + signal-based waits + the cancel test) moved to PR #285 on the coordinator's priority request; this PR rebases on it | recorded above; Task 5 rescoped to the remaining measured bounds and `poll_until` |
| 1b | Coder (Task 1b) | Note | Origin items count in `points.queued`/`checks.scheduled`/`checks.done`, not in `points.audited`/`points.found`; they pass the canary/ladder gate like any item (an origin item on a tripped host yields `stopped_reason: errors`, the plan's "Interplay" paragraph) | accepted; committed in 7f52cc8a |
| 1b | Coder (Task 1b) | Note | Two more bounded `wait_terminal(.., 5 s)` call sites in `worker.rs` tests (inventory 26 → 28) and a test-only `OriginScoped` wrapper because `fake_meta` hard-codes `scope: Point` | Task 5 converts the two sites after the #285 merge and may replace the wrapper with a `FakeCheck::with_scope` builder in `jobs.rs` test support |
| 1b | Coder (Task 1b) | Note | An issue an origin-scoped check reports carries the origin item's `name: "/"`/`path: "/"` unless the verdict overrides `location` (point id on the wire `origin:<key>`); a passive origin-scoped HTTP check would get no `captured()` flow through the synthetic host (C3; no such check exists today) | accepted; the spec reviewer re-reads docs/scanner.md's amendment-38 sentence against the landed lane half |
| 7 | Coder (Task 7) | Note | Hook width: plan said `count: u32`, neighbour `report_forms_skipped` and the counter are `u64`; GET forms count in `pages` only (a GET form is a plain navigation at fetch time) | orchestrator widened the hook to `u64` before announcing it (83786472); GET-form reading accepted (amendment 53 is about submissions the target sees as POSTs) |
| 9 | Coder (Task 9) | Note | Plan bullet said scrub "after the existing excerpt bound"; spec amendment 16 says scrub, then bound; the coder followed the spec and pinned the order with a test | plan bullet corrected; `Verdict.detail` on the manual path was also unscrubbed → scrubbed in fb5cd3b8 with an assertion (`VerdictLocation.path`/`name` left: script-chosen, no response data) |
| merge | Orchestrator | Note | main a2ab31c3 (#285) merged as c7575cdc; the branch's five new bounded `wait_terminal` calls dropped their `Duration` (11eb38ec); Task 5 rescoped per the paragraph above | done |
| all | Orchestrator | Note | Wave A coders ran into each other's mid-TDD states (expected in one tree); whole-package reds during Wave A were the Task 3 casualty above, not regressions | noted |
| 5 | Coder (Task 5) | Note | No measured bound turned out to be the property: four test sites converted (blocking check + `terminal_signal` still `false`; direct hold assertion; `TERMINAL_NET` nets) and `poll_until` → `wait_until` (timeout over the terminal signal on the engine runtime, mpsc-bridged so it is correct from any caller context); zero-deadline test distinguishes "answers on the first look" without a clock | accepted; committed in df127f56 |
| 8 | Coder (Task 8) | Note | Crate has no `rand`/`getrandom`; seed = `RandomState::hash_one(nanos)` folded to `u32`, no new dependency; marker = `lowbias32(counter ^ seed)` (bijective per seed) a public bijection, so a target that has seen one marker can compute the rest of the job's — acceptable because amendment 57 pins markers as per-call canaries that are never keys (security Note: a future check relying on an unseen marker being unguessable needs a CSPRNG seed and a keyed hash); doc states the seed is not a secret and the mix is not a MAC | accepted; committed in 5503cba8 (plus the interim-lane test fake made shape-conformant) |
| 10, 11 | Coder (Tasks 10, 11) | Note | Reports accepted; committed in 11a66c51 | done |
| 12 | Coordinator (amendment 62) | Blocker | Manual `check.<rhai-id>` verbs all error: the lane host is handed unwrapped, `shared()` is `None` | fixed by the orchestrator, test-first (`manual_check_hands_a_shared_host_to_the_check`); amendment 63 recorded as a note on Task 12, no change |
| all | Tester | PASS | Every plan criterion maps to a behavioural test; 8 tests added (scheduler ×3, interim_crawl classify, interim_lane https/foreign scheme, profiles floor-from-ceilings, worker detail scrub-then-bound, model token agreement, plus the manual-path order test); scanner ×3 / model / check_bridge / aitm config_file all exit 0 | committed by path |
| all | Tester | Important | No bridge-backed (Rhai) check runs through `check.<id>` in tests, which is why amendment 62 went unseen | the Task 12 test pins the exact precondition (`shared()` is `Some`) with a native check that mirrors the bridge's refusal; a Rhai-backed manual-path test needs both plugins in one harness (`crates/aitm/tests`) — follow-up, noted for the coordinator |
| 11 | Tester | Minor | `note_check_error` stopped warning once the sample store was full: a 9th distinct detail was counted but never logged | fixed: one warn when the store fills ("further distinct errors are counted only"); warning on every unsampled distinct detail would be unbounded log volume under a flood |
| 5 | Tester | Minor | Measured bounds remain in `client.rs` (l.1242, 1285, 1456, 1694) and `crawl.rs` (l.1320) tests, untouched by this branch | out of Task 5's inventory (pre-existing, not this PR's lines); next determinism sweep |
| 9 | Tester | Minor | The Rhai bridge scrubs `evidence.matched`/`payload` but not `Verdict.detail`; harmless today (manual path scrubs `detail`, job path only reaches the scrubbed `note_check_error`) | spec call, recorded for the coordinator (candidate amendment) |
| 2 | Tester | Minor | `classify`'s `connect` arm runs before the TLS arm, so a TLS failure whose message mentions "connecting" classifies as `connect_refused`; the tester's test pins the documented order | kept; wording/ordering question for the spec reviewer |
| 7 | Tester | Trivial | `interim_crawl` test fake `marker()` returned `aitm7f3a` (not `aitm` + 8 hex) | fixed alongside |
| panel | Security | PASS (2 Minor, 3 Note) | manual path left `more[i].detail` unscrubbed; `wait_until` could starve its own timeout task on a current-thread runtime; marker seed is a public bijection; `classify` order; unhostable origin item silent | both Minors fixed in c04a5aaf (test asserts the sibling token is redacted; `recv_timeout`, timeout = not settled); marker row corrected (4d3e17a8); the two Notes are follow-ups 68/69 |
| panel | Quality | FAIL → fixed | Important: sibling `detail` unscrubbed. Minors: last-kind replay, `synthetic` flag, two `normalize_origin`s, two `JobRuntime` literals, sample `Vec` clone per sync, two hand-rolled watch loops, `as u32` marker counter, `Box::leak` in a test, `OriginScoped` wrapper, model serde test in `worker::tests` | Important + all ten Minors fixed: 580022dd (round B: per-failure kinds with test `each_failed_crawl_request_is_reported_with_its_own_kind`, `synthetic` dropped, `target_origin_key`/`url_origin_key`) and c04a5aaf (round A: `scrub_verdict`, `JobRegistry::wait_terminal`, `JobRuntime::new`, len-check, `AtomicU32`, `String` detail, `FakeCheck::with_scope`, test moved) |
| panel | Spec reviewer | Minor ×4, Note ×4 | docs warn wording; Task 11 "logged" untested; Task 5 plan text named pre-#285 tests; matrix cell stale; Shipped-line shape; last-kind replay; classify order; manual path scrubs more than Task 9 named | docs + plan wording fixed (c04a5aaf, 4d3e17a8); "logged" accepted in writing (no tracing capture in the crate); replay fixed (580022dd); classify order = follow-up 68; extra scrub accepted |
| merge | Orchestrator | Note | main 167e74b9 (#223, T2 lane) merged as 614a8b07: interim_lane.rs both sides kept; two worker tests count the three engine-shipped passives per point (3→9, 2→8) as main's own do; reduced gate exit 0; cells 21/11/6 → Task 15 + the three findings above | done |
| 2a | Coordinator (amendment 71b, chain blocker) | Flake ×3 | Five PRs red on `cancel_moves_to_cancelled_and_keeps_issues` (Cancelled vs Cancelling), `a_panicking_lane_ends_the_job_failed_and_frees_the_origin` (pre-terminal hold read), `verbs::start_returns_a_start_result_immediately` (`elapsed() < 2 s`) | Ported to main as **T1b PR 2a = #294** (test-only, off 50241686 + 04cae7c5): the same three rewrites as Tasks 5/14/16 here, hold-while-running pinned in the cancel test behind its blocking check; 200×/200× (default, `--test-threads=1`) on 7bd52e72 and 20×/20× on the merged head 7c16e623, each run checked for "3 passed" (a first loop ran zero tests: zsh does not word-split `$T`); quality PASS (2 comment Minors fixed), spec PASS (Minor: add `assert!(!h.egress_confined())` after `Cancelled` on the cancel path — to do on this branch when it drops its duplicate hunks after #294 merges; 71b spec row → coordinator's docs PR). This PR re-merges main after #294 and keeps 2a's versions |
| merge | Orchestrator | Note | main 04cae7c5 (#229 T6 stream lane) merged as 25acd796 (clean); main 90e38adc (#294 = PR 2a) merged as 3cd05ee6: the three deterministic tests take 2a's versions (this branch's Task 5/14/16 hunks were the same rewrites), and the cancel test gains the post-terminal `!egress_confined()` (2a spec Minor) | done; scanner 501 / model green in the sandbox; Terminal gate + cells on 3cd05ee6 follow |
| merge | Orchestrator | Note | main 09108b51 (#295, T2 hotfix: `HttpProbeHost` lends the client/charges/shared, 39b crawl-error tokens, hosts origin items, seeds are not pages) merged as 1d90cd2a (clean). Consequences to confirm on the cells: `test_t3_version_override.py` should now assert 39b for real (no SKIP); Task 15's engine fallback for refused origin items becomes an unused path on T2's lane (the lane hosts them itself) and stays as the guarantee for any lane crate that does not | Terminal gate + cells on 1d90cd2a |
| merge | Orchestrator | Note | main 833a0e4d (#290 T3 PR 2b: bundled HTTP checks on the bridge, A5 raw-h2 charge + peer dial with the amendment-59 fallback; #293 T10 web cell) merged as 2eb07e69; `test_t3_h2_observe.py` keeps T3's pooled-connection rule (same `host`-header semantics as Task 13; T3 landed first). Task 13c's `skip` import fixed (fd766bb1: the loud SKIP had raised NameError on cells25) | scanner 501 / bridge 30 green in the sandbox; Terminal gate + cells on 2eb07e69 |
| 14 | Coordinator (amendment 71) | Flake | `a_panicking_lane_ends_the_job_failed_and_frees_the_origin` read the hold before the terminal wait; the panic races it on multi-thread | fixed by the orchestrator: pre-terminal read dropped, property pinned race-free in `commands.rs`; no other such read in worker tests |
| panel | Spec reviewer | Important ×2 | Spec on main: row 39/D5 says an all-failing crawl ends with `stopped_reason`/`error` set; rows 53, 55–59, 62, 63 absent from the amendment log | coordinator ruling 2026-11-02: row 39b supersedes 39 — an all-failing crawl ends `done`, `stopped_reason`/`error` null, `crawl.errors > 0`, `crawl.last_error` = closed token; `stopped_reason` stays reserved for early stops (budget, cancel, session_lost); C4 wording is the spec. Rows 39b, 53, 55–59, 62, 63 land in the coordinator's docs PR right after PR 2 (pending docs PR, as 38–40 before #273) |
| panel | Security / Quality / Spec | follow-ups | Bridge does not scrub `Verdict.detail`; `classify` tests `connect` before the TLS words; an unhostable origin item counts as `checks.done` silently; no Rhai-backed `check.<id>` test | coordinator's numbering: 67 bridge scrubs `Verdict.detail` (fold into PR 3, same scrub function); 68 TLS words before `connect`; 69 unhostable origin item → `checks.skipped` + sample; 70 Rhai-backed `check.<id>` integration test in `crates/aitm/tests` (T3 may own after 2b). None in PR 2 |

## Follow-up PR 3 (not in this PR; amendment 59, T3's 2b live run)

`aitm-core/src/client.rs` builds every client-sent flow with `server_conn: None` because `RequestSender::send_with` returns only an `HttpResponse` and cannot report the peer it connected to, so no lane host can fill `baseline_peer_addr()` and the raw-h2 checks' DNS-rebinding guard (A5) never engages (T3 ships 2b with a gated name-resolution fallback + warn when the hook is `None`). PR 3: `HttpResponse` (or the sender result) gains `peer: Option<SocketAddr>`; `ProxyClient`/`send_opts` fills `server_conn.peer` from it; `HttpSender` (T3's crate) reports the connected peer; the interim lane and T2's lane fill `baseline_peer_addr()` from `server_conn.peer`. T1b owns the aitm-core half (D12), T3 the `HttpSender` hunk — the signature is agreed with T3 before coding. Tests: a client-sent flow carries the peer the sender connected to; `baseline_peer_addr()` on the interim host is `Some` after the baseline. Small, separate, right after PR 2.

Shape approved by the coordinator (2026-11-02): `HttpResponse.peer: Option<SocketAddr>` is additive (serde default, skipped when `None` — it is a wire type on `flow.get`/`flow.detail`, so additive-only); `RequestSender::send_with` sets it from the socket it actually connected to (for TLS, the TCP peer under the TLS session); `client.rs` copies it into `flow.server_conn = Some(ServerConn { peer, .. })` for every client-sent flow; the interim host reads `server_conn.peer` in `baseline_peer_addr()`; T3's `HttpSender` fills `peer` on its own responses. Tests: a client-sent flow carries the connected peer on `flow.get`/`flow.detail`; the interim host's `baseline_peer_addr()` is `None` before and `Some` after a baseline. Design note for the record: T3 keeps its `None`-branch fallback (gated name resolution + warn) as the defensive path rather than retiring it; the strict dial engages whenever the peer is known. T3 gets the field name/type when PR 2 is in panel.

Also in PR 3 (amendment 67): the Rhai bridge scrubs `Verdict.detail` (root and siblings) with the same scrub function the manual path uses.

Also in PR 3 (amendment 72): a contract test that every engine-reachable `ProbeHost` (interim, http, ws, l4 packet, l4 stream, `ArcHost`) answers `client()`, `shared()`, `captured()` and debits `charge()`; T2's host shipped defaulting all three (hotfix pending), so the Rhai-based t3 cells on the merged head show that hole, not PR 2's.

## Shipped

PR #292 (`claude/scanner-v2-t1b-followup-2`, base `main`), opened 2026-11-02 at 386e33af on the interim-lane build; the "ready" head after the T2/T6/2a/T2-hotfix/T3 main merges is the commit after this one (sent to the coordinator as "292 ready <sha>"). Merge is the coordinator's; T3's #290 and T2's #295 landed before it; PR 2b (amendments 74 + 80) opens off the tip right after.

- Gate: full workspace gate exit 0 at 64fedb5e and c6092927 (interim build); the coordinator's reduced gate exit 0 at 614a8b07, 32cadcfe, 1d90cd2a, 2eb07e69 (merged builds). `target/` deleted after the runs.
- Cells: interim build 22 / 16 / 0 (cells20). Merged build 28 / 8 / 4 (cells26, 2eb07e69): `test_t3_version_override.py` passes on the final head (Task 13e, run alone); the three remaining reds are the core breaker (amendment 80: `host_error_budget` 10 counts 5xx answers) with 74 (keyed on the bare host) — PR 2b — `test_t3_catalogue_sweep.py`, `test_t3_h2_sender.py`, `test_t2_mutable_points.py` (load-dependent; PASS in cells24–25). Loud SKIPs with the amendment named: `test_t1_record_policy.py` (79), `test_t3_version_override.py` on a lane crate without the 39 hook / with another token (78).
- Live proof 38: `checks.scheduled 5`, `points.found 2`, `points.audited 0` on the h2-observe profile; five origin-scoped checks on five raw connections (target-log dump); `test_t3_h2_observe.py` PASS on both builds (Task 13 heuristic; Task 15 engine fallback when a lane crate refuses a flowless origin item).
- Live proof 39(b): `test_t3_version_override.py` PASS (forced h2 vs h1-only: `error` null, `crawl.errors > 0`, `crawl.pages 0`, `crawl.last_error h2_not_negotiated`, `probes.errors 10`, handshakes `alpn none`, zero requests; `stopped_reason` null or the ladder's `errors` under 38 + 40).
- 40, 46: unit-only by the plan's ruling (T5's live proof covered the lane half of 46 in #264).
- Panel: security PASS, quality FAIL → fixed, spec FAIL → plan text fixed; spec rows pending the coordinator's docs PR (39b, 53, 55–59, 62, 63, 71/71b); follow-ups 67–70, 72, 73a, 74, 78, 79, 80 on the coordinator's list; the panel comment and its addendum are on #292.
