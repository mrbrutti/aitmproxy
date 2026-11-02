# Scanner v2 T1b follow-up 2 (amendments 38, 39, 40, 46; deterministic job tests) implementation plan

**Status:** approved 2026-11-01 by the T1b orchestrator under Matt's autonomous mandate (self-approve specs/plans). Decisions on the architect's open calls: C4 keeps "reason only when every crawl request failed" (the coordinator's wording of amendment 39; a partial failure is visible in `crawl.errors` alone); the `other` token for free-text browser-crawl failures is accepted. Amendments 38-40 are cited as "" until that docs PR is on main.
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-design.md` (Approved), D4 "Scheduling", D5 (job model, budget and pacing, "degrade, do not fail"), D11 (`l4_icmp_pace_ms_min`), amendment log rows 46 (on `main`) and 38/39/40 (folded by the coordinator's docs PR #273, head `0f1f8509`, wording quoted below).
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

**The rules this plan implements** (coordinator wording; spec text in PR #273):

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
    | `worker.rs` 1599, 1702, 1734, 1764, 1904, 1945, 1969, 1991, 2010, 2031, 2064, 2100, 2144, 2441, 2478, 2494, 2523, 2562, 2636, 2799, 2835, 2866 | `wait_terminal(.., 5 s)` | convert (notification) |
    | `worker.rs` 1651, 2728, 2761 | `wait_terminal(.., 2 s)` (the CI failure) | convert |
    | `worker.rs` 2675 | `wait_terminal(.., 10 s)` (panic path) | convert |
    | `worker.rs` 1638-1641 | poll `issues.for_job` under a 5 s deadline, 10 ms sleep | convert to a poll under `TERMINAL_NET` (readiness, no notification exists for "first issue recorded"; the bound is no longer measured) |
    | `worker.rs` 1659 | `sleep(100 ms)` then "no client call after `finished_at`" | keep: a negative wait that can only miss a bug, never fail spuriously; comment says so |
    | `worker.rs` 1833 | 50 x 10 ms ticks on the injected `ProgressClock` | keep: already an injected clock, no real sleep |
    | `worker.rs` 2185 | `Instant::now() + 60 s` budget deadline | keep: a budget the test never reaches |
    | `jobs.rs` 2653, 2976, 3008, 3177 | `wait_terminal(.., 5 s)` | convert |
    | `jobs.rs` 2170, 2185 | the helper's own 10 ms polls | removed with the helper |
    | `jobs.rs` 1481 | stub check polls `host.cancelled()` every 5 ms | keep: the fake check's blocking body (`ProbeHost` exposes a bool, not a token); it ends on cancel, not on a bound |
- **Test** (`jobs::tests`):
  - `wait_terminal_resolves_at_once_for_a_finished_job`: admit an entry, call `finish`, then
    `registry.wait_terminal(id).await` returns `Some(status)` without yielding (wrap in
    `tokio::time::timeout(Duration::ZERO, ..)` on a paused clock: it completes).
  - `a_cancelled_job_notifies_its_waiter`: a job on a `block_until_cancelled` check; a waiter
    task awaits `wait_terminal`; `registry.cancel(id)`; the waiter resolves with `state ==
    Cancelled`.
  - `an_unknown_job_has_no_signal`: `registry.wait_terminal("scan-00000000").await == None`.
  - `a_reloaded_record_is_already_terminal`: after `load_history`, `wait_terminal` on a
    reloaded id resolves at once.
  - Static check the Tester repeats: `grep -n "from_secs(2)\|from_secs(5)\|from_secs(10)"`
    over the `#[cfg(test)]` regions of `worker.rs` and `jobs.rs` lists only the kept sites
    above (the 60 s budget deadline, and none of the converted ones).
- **Done when:** the four tests pass; `cargo test -p aitm-plugin-scanner --offline` passes
  three times in a row in the sandbox (no flake); per-task gate green.

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
| `aitm-plugin-scanner/src/verbs.rs`, `commands.rs` | | | | | | W (tests) | |
| `aitm-plugin-scanner/src/config.rs`, `profiles.rs` | | | | W | | | |
| `aitm/src/config_file.rs` | | | | W | | | |
| `aitm-scan-model/src/job.rs`, `traits.rs` (doc) | | W | | | | | |
| `docs/scanner.md` | | | | W | | | W |
| the two plan files | | | | | | | W |

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

## Shipped

Filled at integration (stage 7): PR number and squash SHA, the four live-proof lines from
"Acceptance", anything cut, follow-ups.
