# T7 fix round D: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows for Task 7 marked "fix round D").
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D6 hostile-core bounds, issue sentence added 2026-11-01).
**When:** after fix round C, before Task 8. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding: write a test that reproduces it and fails, fix it, watch it pass. Commit as `fix(tui-scan): <finding id> <title>`. Do not fix anything not listed here.

## Important

D1. **`fetched` records that the TUI asked, not what it got, and grows without bound on unvalidated issue ids** (merged with the Task 7 quality Important: wrong detail under the cursor after moving back, stale reads surviving a filtered-out job's terminal line, a failed read blocking retries) (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/app.rs` `issue_cursor_landed`, `fold_result`, `on_job_line`):
  (1) `pub fn is_issue_id(s: &str) -> bool` in `scan/mod.rs` (`issue-` + exactly eight lowercase hex digits), mirroring `is_job_id`; an id failing it is never a tag key, a request argument or a `fetched` entry; `fold_result` drops rows whose `id` fails it; an `issue` push line whose `issue.id` fails it is still a status trigger but nothing else.
  (2) replace `fetched: BTreeSet<String>` and `detail: Option<Issue>` with `read: BTreeMap<IssueId, Issue>`: inserted on a `scan.issue` reply only (never on send); `issue_cursor_landed` sends when the cursor's id is absent from `read` and `pending_read` is `None`; `IssuesState::detail(&self) -> Option<&Issue>` looks up the cursor's id (Task 8's detail pane reads it); `forget_job(job)` is `read.retain(|_, i| i.job != job)`; `fold_result` prunes `read` to the new page's ids, so `read.len() <= list.len()`.
  (3) at most one `scan.issue` read in flight: `IssuesState.pending_read: Option<String>`; the reply (ok or failed) clears it; a failed read leaves no `read` entry; `Disconnected` clears `pending_read`.
  Tests (`tests/scan_v2_issues.rs`): a `scan.issues` page whose rows carry a 1 MiB id yields no `scan.issue` request and leaves `read` and `inflight` empty; 100 folded pages of 100 distinct valid ids leave `read.len() <= list.len()`; two cursor landings before any reply yield one `scan.issue` request; Down to the second row (reply folded) then Up to the first sends a `scan.issue` for the first and `detail().id` equals the cursor's id; with `J` on job B, job A's `finished` line drops A's `read` entries even when A's rows are filtered out; `is_issue_id("issue-9f8e7d6c")`, `!is_issue_id("issue-9F8E7D6C")`, `!is_issue_id("issue-9f8e7d6")`, `!is_issue_id("")`.

## Minor

D2. **Page limit not enforced client-side; rows rebuilt from unbounded strings every frame** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs`): `fold_result` truncates `result.issues` to `ISSUES_PAGE_LIMIT` and builds the `Vec<IssueRow>` once at fold time with `name`, `location` and `point` bounded to their caps (40/32/24 cells plus an ellipsis), stored on `IssuesState.rows`; `Columns::measure` and the renderer read `rows`, never the raw list. Test: a 1 MiB `name` renders at 200x50 with the name cell at most 40 cells wide and an ellipsis; folding a 600-row page leaves `list.len() == 512`.

D3. A `CallTaggedFailed` for `scan.issue:<id>` must leave the issue readable (`crates/aitm-tui/src/app.rs` `on_scan_failed`): clear `pending_read`, insert nothing. Test: a failed `scan.issue` then a cursor landing on the same row sends a second `scan.issue`.

## Spec panel items

D4. **A bus without `scan.issue` is never named on screen** (`crates/aitm-tui/src/ui/scan/mod.rs` `degraded()`): under V2 the Issues tab's degraded text names the first missing one of `scan.issues`, `scan.issue` (`<verb> is not on this bus`); `issue_cursor_landed` keeps the quiet `scan_poll` path (ruling: option b, plan amended). Test (`tests/scan_v2_matrix.rs` or `scan_v2_issues.rs`): tools with `scan.issues` but without `scan.issue`, Issues tab shown: the strip row ends with `scan.issue is not on this bus` and a cursor landing sends nothing.

D5. **`scan.issue` fold-under-key has no test** (`tests/scan_v2_issues.rs`): `CallTaggedOk { tag: "scan.issue:issue-9f8e7d6c", value: scan.issue.json with "id" rewritten to "issue-4c3b2a19" }` leaves `detail == None` and sets the Issues error detail `reply named a different issue`.

D6. **Three builder rules without pins** (`tests/scan_v2_issues.rs`): `S` on the Jobs tab sends nothing; `OpenScan` after `Back` from Issues sends `scan.issues`; `ScanPaneNext` (Detail focused) then `Down` sends no `scan.issue`.

## Quality panel items (Task 7)

D7. `fetched_at_tick` is write-only (`crates/aitm-tui/src/app.rs` `scan_tick`): the 20-tick Issues timer fires when `ticks - fetched_at_tick >= ISSUES_POLL_TICKS` (and re-stamps on every `scan.issues` request), replacing the modulo, so entering the tab at tick 19 does not fetch twice. Re-pin `issues_refresh_every_twenty_ticks_while_a_job_is_live` accordingly.

D8. `IssueFilters::cycle` hand-rolls four rings (`crates/aitm-tui/src/scan/issues.rs`): `const` ring slices (`[None, Some(Low), ...]`) stepped with `crate::scan::step` (C9's `Dir`); the Job arm stays a toggle.

D9. The keyed-reply arm is written twice (`crates/aitm-tui/src/app.rs`): `fn scan_reply_keyed<T: DeserializeOwned>(&mut self, tag, name, value, key: fn(&T) -> &str, other: &'static str) -> Option<T>` next to `scan_reply`; the `scan.status`/`scan.cancel` and `scan.issue` arms use it (Task 8's `scan.issue.update` will too).

D10. One tertiary text line drawn four ways (`crates/aitm-tui/src/ui/scan/mod.rs`, `ui/scan/issues.rs`, `ui/scan/jobs.rs`): `pub fn hint(theme, area, text, buf)` in `ui/scan/mod.rs` used by the filter line, both footers and `note`.

D11. `token()` re-serialises through `serde_json::Value` per cell per frame and duplicates `lane_name` (`crates/aitm-tui/src/scan/issues.rs`, `scan/jobs.rs`): `token` becomes a `&'static str` match per enum (`severity_token`, `confidence_token`, `lane_token`, `status_token`) and `lane_name` is deleted in favour of `lane_token`; `severity_header` is computed once per header line (ties in with D2's fold-time rows).

D12. The five-severity order and the `BySeverity` walk spelled three times (`crates/aitm-tui/src/scan/issues.rs`, `scan/jobs.rs`): one `pub fn severity_counts(b: &BySeverity) -> [u64; 5]` in `SEVERITY_ORDER` order used by `count_of` and `severity_segments`; `SEVERITY_LEVELS` glyphs derived from `SEVERITY_ORDER`.

D13. Tests use `contains` where the row literal is on screen (`tests/scan_v2_issues.rs`): one literal per asserted row with the measured spacing (the XSS row, the filter line `filters: S low · C firm · L http · T open`); `assert_eq!` for the request count.

D14. Doc comments that overstate (`scan/issues.rs`, `app.rs`, `ui/scan/issues.rs`): the four noted by the panel (status-update forgetting is Task 8's; widest-not-narrowest; name gives way first; `next_cursor` not cursor). Hygiene: `STATUS_MAX` const, `use aitm_poc::Severity`, `Span::styled(mark, ..)`, drop the empty `detail()` stub, `CONFIDENCE_GLYPHS` private.

## Not in this round

The TUI-wide bidi/format-character filter (`ui/text.rs`, pre-existing, flow list too): a follow-up outside this track, recorded in the Review log.
