# T7 fix round D: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows for Task 7 marked "fix round D").
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D6 hostile-core bounds, issue sentence added 2026-11-01).
**When:** after fix round C, before Task 8. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding: write a test that reproduces it and fails, fix it, watch it pass. Commit as `fix(tui-scan): <finding id> <title>`. Do not fix anything not listed here.

## Important

D1. **`fetched` and `scan.issue:*` in-flight tags grow without bound on unvalidated issue ids** (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/app.rs` `issue_cursor_landed`, `fold_result`, `on_job_line`):
  (1) `pub fn is_issue_id(s: &str) -> bool` in `scan/mod.rs` (`issue-` + exactly eight lowercase hex digits), mirroring `is_job_id`; an id failing it is never a tag key, a request argument or a `fetched` entry; `fold_result` drops rows whose `id` fails it; an `issue` push line whose `issue.id` fails it is still a status trigger but nothing else.
  (2) `fold_result` prunes `fetched` to the ids of the new page plus `detail.id`, so `fetched.len() <= list.len() + 1`.
  (3) at most one `scan.issue` read in flight: `IssuesState.pending_read: Option<String>`; `issue_cursor_landed` skips while it is `Some`; the reply (ok or failed) clears it, and `Disconnected` clears it and `fetched`.
  Tests (`tests/scan_v2_issues.rs`): a `scan.issues` page whose rows carry a 1 MiB id yields no `scan.issue` request and leaves `fetched` empty and `inflight` empty; 100 folded pages of 100 distinct valid ids leave `fetched.len() <= 1 + list.len()`; two cursor landings before any reply yield one `scan.issue` request; `is_issue_id("issue-9f8e7d6c")`, `!is_issue_id("issue-9F8E7D6C")`, `!is_issue_id("issue-9f8e7d6")`, `!is_issue_id("")`.

## Minor

D2. **Page limit not enforced client-side; rows rebuilt from unbounded strings every frame** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs`): `fold_result` truncates `result.issues` to `ISSUES_PAGE_LIMIT` and builds the `Vec<IssueRow>` once at fold time with `name`, `location` and `point` bounded to their caps (40/32/24 cells plus an ellipsis), stored on `IssuesState.rows`; `Columns::measure` and the renderer read `rows`, never the raw list. Test: a 1 MiB `name` renders at 200x50 with the name cell at most 40 cells wide and an ellipsis; folding a 600-row page leaves `list.len() == 512`.

D3. A `CallTaggedFailed` for `scan.issue:<id>` leaves the id in `fetched` so the issue is unreadable until a terminal line (`crates/aitm-tui/src/app.rs` `on_scan_failed`): remove the id from `fetched` on failure (and clear `pending_read`). Test: a failed `scan.issue` then a cursor landing on the same row sends a second `scan.issue`.

## Spec panel items

D4. **A bus without `scan.issue` is never named on screen** (`crates/aitm-tui/src/ui/scan/mod.rs` `degraded()`): under V2 the Issues tab's degraded text names the first missing one of `scan.issues`, `scan.issue` (`<verb> is not on this bus`); `issue_cursor_landed` keeps the quiet `scan_poll` path (ruling: option b, plan amended). Test (`tests/scan_v2_matrix.rs` or `scan_v2_issues.rs`): tools with `scan.issues` but without `scan.issue`, Issues tab shown: the strip row ends with `scan.issue is not on this bus` and a cursor landing sends nothing.

D5. **`scan.issue` fold-under-key has no test** (`tests/scan_v2_issues.rs`): `CallTaggedOk { tag: "scan.issue:issue-9f8e7d6c", value: scan.issue.json with "id" rewritten to "issue-4c3b2a19" }` leaves `detail == None` and sets the Issues error detail `reply named a different issue`.

D6. **Three builder rules without pins** (`tests/scan_v2_issues.rs`): `S` on the Jobs tab sends nothing; `OpenScan` after `Back` from Issues sends `scan.issues`; `ScanPaneNext` (Detail focused) then `Down` sends no `scan.issue`.

## Not in this round

The TUI-wide bidi/format-character filter (`ui/text.rs`, pre-existing, flow list too): a follow-up outside this track, recorded in the Review log.
