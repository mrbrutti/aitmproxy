# T7 fix round B: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows for Task 5 marked "fix round B").
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3 `started_here`, D6 hostile-core bounds, D13 error granularity, all amended 2026-11-01).
**Range reviewed:** `f157d987..51d67457` (Task 5), on top of fix round A. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding: write a test that reproduces it and fails, fix it, watch it pass. Commit as `fix(tui-scan): <finding id> <title>`. Do not fix anything not listed here. Keep the public shapes Tasks 6 to 14 rely on (`scan_call`, `scan_poll`, `on_scan_ok`, `on_scan_failed`, `JobsState::fold_status/fold_list/state_of/live`, `ScanState::set_error/clear_error`, `scan_issues_args`), adding parameters where a finding says so.

## Important

B1. **A `scan.status`/`scan.cancel` reply is folded under the body's `job`, not the tag's key** (`crates/aitm-tui/src/app.rs` `on_scan_ok`). Fold only when `status.job == tag_parts(tag).1`; otherwise record an uncoded `ScanError` for that verb with detail `reply named a different job` and fold nothing. Test (`tests/scan_v2_cadence.rs`): answer `scan.status:scan-1a2b3c4d` with `scan.status.json` whose `job` is rewritten to `scan-ffff0001`; assert `jobs.order == ["scan-1a2b3c4d"]` (the row that was polled stays as it was, nothing new appears), `jobs.full` has no `scan-ffff0001`, and `last_error.as_ref().unwrap().detail == "reply named a different job"`.

B2. **Unbounded `scan.status` fan-out per `scan.list` fold and per status-timer firing** (`crates/aitm-tui/src/app.rs` `on_scan_ok` `scan.list` arm and `scan_tick`; `crates/aitm-tui/src/scan/jobs.rs` `fold_list`, `live`; `crates/aitm-tui/src/scan/mod.rs`). Add `pub const MAX_STATUS_FOLLOWUPS: usize = 16` in `scan/mod.rs`. Per `scan.list` fold at most 16 follow-up `scan.status` requests leave the reducer; per status-timer firing at most 16, the Jobs cursor's job first, then `order` order; the rest wait for the next firing (the dedupe already skips in-flight tags). Replace `Vec::contains` membership tests in `fold_list` and `live` with a `BTreeSet` built once. Test: a `scan.list` with 40 running jobs (ids `scan-000000NN`) yields exactly 16 `scan.status` requests on fold and exactly 16 more on the next 4th tick, none duplicated.

B3. **`started_here` rule** (`crates/aitm-tui/src/scan/jobs.rs`, `crates/aitm-tui/src/app.rs`). `JobsState` gains `pub started_here: BTreeSet<JobId>`; `fold_list` keeps at the front exactly the `started_here` ids the list omits, removes from `started_here` every id the list carries, and after rebuilding `order` runs `self.full.retain(|id, _| order.contains(id))` (and the same for `summaries`); the `order` field doc states this rule. Task 12 will insert into `started_here` on a `StartResult`; for the test, insert directly. Tests: (a) `started_here = {"scan-aaaaaaaa"}` with a running `full` entry, then `scan.list.json` folded: `order == ["scan-aaaaaaaa", "scan-1a2b3c4d", "scan-55667788"]`; (b) a running `full` entry `scan-bbbbbbbb` not in `started_here`, then `scan.list.json`: it is gone from `order`, `full` and `summaries`; (c) a list that carries `scan-aaaaaaaa` removes it from `started_here`.

## Minor

B4. Push-line and `scan.list` job ids used unvalidated (`crates/aitm-tui/src/app.rs` `on_job_line`; `crates/aitm-tui/src/scan/jobs.rs` `fold_list`; `crates/aitm-tui/src/scan/mod.rs`): add `pub fn is_job_id(s: &str) -> bool` (`scan-` followed by exactly eight lowercase hex digits) and ignore any id that fails it (a push line is dropped; a list row is skipped). Test: a progress line with `job: "scan-../../x"` yields no request; `is_job_id("scan-1a2b3c4d")`, `!is_job_id("scan-1A2B3C4D")`, `!is_job_id("scan-1a2b3c4")`, `!is_job_id("")`.

B5. `scan.status {job}` request spelled out three times (`crates/aitm-tui/src/app.rs`): one `fn request_scan_status(&mut self, job: &str, out: &mut Vec<BusRequest>) -> bool` next to `request_scan_list`; the three sites call it.

B6. `on_scan_ok` repeats the parse / clear-or-set-error scaffold per verb arm (`crates/aitm-tui/src/app.rs`): `fn scan_reply<T: serde::de::DeserializeOwned>(&mut self, tag: &str, name: &str, value: &Value) -> Option<T>` that parses, clears the error for that tag on success and records the `ScanError` on failure; the arms become `if let Some(x) = self.scan_reply::<T>(..) { fold }`.

B7. `clear_error(verb)` clears a keyed verb's error on a sibling job's success (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/app.rs`): `ScanError` gains `pub tag: String`; `set_error` keys on the tag; `clear_error(tag)` clears only an error with that exact tag (a single-slot verb's tag is the verb itself, so the behaviour for those is unchanged). Test: a failed `scan.status:scan-aaaaaaaa` then a successful `scan.status:scan-bbbbbbbb` leaves `last_error` set with the first tag; a successful `scan.status:scan-aaaaaaaa` clears it.

B8. `scan_issues_args` bare `limit: 512` (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/app.rs`): `pub const ISSUES_PAGE_LIMIT: usize = 512` in `scan/mod.rs`, used by `scan_issues_args` (the body itself moves to `IssueFilters::args` in Task 7, not here).

B9. Untested Task 5 behaviours (`tests/scan_v2_cadence.rs`): add `forty_ticks_in_scan_mode_list_once` (40 `Tick`s in `Mode::Scan` give exactly one `CallTagged { tag: "scan.list", name: "scan.list", args: json!({}) }`; 40 in `Mode::Flows` give none); `open_scan_requests_the_list_once` (`OpenScan` on the five-verb v2 app gives exactly that request); `a_terminal_line_on_the_issues_tab_requests_issues` (in `Mode::Scan` with `scan.tab = Issues`, a `job.finished.json` line gives `scan.status` plus `CallTagged { tag: "scan.issues", name: "scan.issues", args: json!({"limit": 512}) }`); `disconnect_clears_pending_launch` (`launch.pending = Some(..)`, `Disconnected("x")`, `pending == None`). In `four_progress_lines_yield_one_inflight_status` count every `BusRequest::CallTagged`, not only `scan.status` ones.

B10. `fixture!` and `value()` duplicated across `tests/scan_v2_parse.rs` and `tests/scan_v2_cadence.rs`: move both into `tests/common/mod.rs` (`pub fn fixture(name: &str) -> Value` reading `concat!(env!("CARGO_MANIFEST_DIR"), "/../aitm-scan-model/fixtures/")` plus the name at runtime with `std::fs::read_to_string`, or an exported macro); both files use it. `on_notification` (`crates/aitm-tui/src/app.rs`): deserialize `JobNotification` from `&Value` instead of `params.clone()`.

## Not in this round (dispositioned elsewhere)

`fetched_at_tick: Option<u64>` and `IssueFilters::args` (Task 7); `started_here` insertion on `StartResult` (Task 12); the `summaries` read-through in the row renderer (Task 6).
