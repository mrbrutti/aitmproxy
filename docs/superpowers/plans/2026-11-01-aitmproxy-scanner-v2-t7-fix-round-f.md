# T7 fix round F: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round F": the Task 8 panel and the re-review of fix round E).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D11 Issues detail as amended).
**When:** after fix round E and its re-review, before Task 9. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

F1. **Flow list position** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs`): D11 orders the detail as evidence, then the probe/baseline flow list, then `poc_ref`, `finding_id`, remediation, note, occurrences and seen. Split `issue_detail_lines` into the lines before the flows and the lines after (or return a marker index), and draw the walkable flow list between them; `issue_detail_line_count` and `detail_len` follow. Test (`tests/scan_v2_issues.rs`): on the 200x50 detail the `flows` label's row index lies between the `matched` row and the `poc` row.

F2. **Placeholder wording** (`crates/aitm-tui/src/ui/scan/issues.rs`): the detail pane's empty text is `no detail read for this row` (neutral; true while a read is in flight, after a failed read and when the verb is missing). Test: the literal on screen before any `scan.issue` reply.

## Not in this round

Items the fix round E re-review adds are appended below when it reports.
