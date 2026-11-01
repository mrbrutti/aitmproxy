# T7 fix round G: findings report for the fix Coder (whole-branch structure pass)

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round G": structural residue from the fix round E+F re-reviews plus whatever Tasks 9 to 14 add).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3, D6, D11 as amended).
**When:** after Task 14 and its panel, before the whole-branch tester pass (Task 16). The fix Coder may touch only the files each finding names plus the test files that reproduce them; moves of tests between files are allowed where a finding says so.

G1. **`bound_issue`'s field list is exhaustive by hand** (`crates/aitm-tui/src/scan/issues.rs`, `tests/scan_v2_issues.rs` or `tests/scan_v2_issue_detail.rs`): add the behavioural guard test: take the fixture issue JSON, set every string leaf to 1 MiB, parse, `fold_issue`, re-serialise the `ReadIssue`'s issue and assert every string leaf is at most `4 * DETAIL_VALUE_MAX` chars (walk the JSON tree generically).

G2. **Detail-pane row arithmetic lives twice** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs`): move `DetailLayout` into `scan::issues` (pure arithmetic over model data), `detail_len()` returns `DetailLayout::of(..).total`, the view asks the model; add `first_after` so `row()`'s last arm is a single subtraction. Unit test: `DetailLayout::of(..).total == detail_len()` for the tall fixture with L4 lines and `dropped_flows > 0`.

G3. **`read`/`read_order` kept in step by hand** (`crates/aitm-tui/src/scan/issues.rs`, tests): one `ReadCache { by_id, order }` with `get`, `contains`, `insert` (cap, oldest first, the cursor's id rotated to the back when it lands), `retain`, `len`, `keys`; `IssuesState.read: ReadCache`; delete the dead `None` arm. Eviction never drops the row under the cursor (G4's edge): a landing on an already-read row moves its id to the back of the order. Test: the READ_MAX scenario with the cursor on the oldest read row keeps that row.

G4. Folded into G3.

G5. `labelled()`'s `Option<usize>` (`crates/aitm-tui/src/ui/scan/mod.rs`, `ui/scan/jobs.rs`): `label_w: usize`; Jobs passes `width(label)`.

G6. The mutation-chain overflow marker lost its count (`crates/aitm-tui/src/scan/issues.rs`): `ReadIssue.dropped: Dropped { flows: usize, mutations: usize }` set by `bound_issue`; `l4_lines` prints `... n more`; spec D3 `ReadIssue` wording follows (orchestrator).

G7. `IssuesState` Detail-view trio (`crates/aitm-tui/src/scan/issues.rs`, `app.rs`, `ui/scan/issues.rs`, tests): `DetailView { scroll: u16, flow_cursor: usize, follow_flow: bool }` with `reset()`, `scroll(..)`, `walk_flow(..)`, owned as `IssuesState.detail_view`; the three reset sites and the clamp use it.

G8. Test-file size and a lying module doc (`tests/scan_v2_issues.rs`): split the Detail-pane tests into `tests/scan_v2_issue_detail.rs`, fix both module docs; split the E10 test into its success and failure halves; the READ_MAX test replies only when a request left.

G9. Small hygiene: `fn scroll(at: &mut u16, ..)` (`app.rs`); import `OsStr`, `Path`, `truncate` and name `POC_TOAST_MAX = 80` (`app.rs`); retire the `ui::text` shim by moving the 13 view imports to `crate::text` and deleting `pub use crate::text;` (`ui/mod.rs` and the view files); `ui/scan/issues.rs` module doc mentions `follow_flow`; the Jobs `labelled()` width and `flow_line`'s `id_w` lose their spare cell (the one-cell difference deferred after round F).

## Security residuals (fix rounds E+F re-review)

G10. **`truncate` counts control characters as 0 cells while `width()` counts them as 1** (`crates/aitm-tui/src/text.rs`; `crates/aitm-tui/src/scan/issues.rs` `bound_issue`, `crates/aitm-tui/src/scan/jobs.rs` `fold_status`): strip `char::is_control` characters at fold time in one place (a `clean(s) -> String` in `text.rs` used by `bound_issue`, `fold_status` and `issue_row`), and make `truncate` charge a control char one cell (`unwrap_or(1)` for `None`) so the "at most `w` cells" contract holds for any input. Test: `width(&truncate(&"\t".repeat(1000), 8)) <= 8`; a 1 MiB tab `name` renders without shifting the other columns.

G11. **The Jobs Detail pane formats unbounded free-text fields every frame** (`crates/aitm-tui/src/scan/jobs.rs` `fold_status`): cut `error`, `started_by.frontend`, `client_label`, each `clamped[].field`, each `lanes.skipped[].reason`, each `checks.running[]` and the session canary path to `DETAIL_VALUE_MAX` cells at fold, and cap the `running`/`clamped`/`skipped` vectors at a display limit with a `+n`, mirroring `bound_issue`; fix the `fold_status` doc. Test: a status with a 1 MiB `error` renders at 200x50 and `full[job].error.chars().count() <= 4 * DETAIL_VALUE_MAX`.

G12. **Retained capacity after `truncate`; timing vectors never cut** (`crates/aitm-tui/src/scan/issues.rs` `bound_issue`): `shrink_to_fit()` after the mutation-chain and flow truncations; cut `timing.requested_s/observed_ms/baseline_ms` to `TIMING_ROWS_MAX + 1` at fold and keep the original row count in `ReadIssue.dropped` (G6's struct) so `... n more` stays right. Test: an issue with 10^6 timing samples folds to 13 rows with `dropped.timing == 999_987`.

## Task 9 coder notes

G13. `tests/scan_v2_matrix.rs` sets `sitemap.nodes` directly (bypassing the fold, so `lines` stays empty): route the v2 Site map setup through a folded `scan.sitemap` reply.

G14. Two pre-existing em dashes in legacy toast literals in `crates/aitm-tui/src/app.rs` ("Scan needs an in-scope host — ...", "Out of scope — add ..."): replace the dash with a colon; update the `scan_surface.rs` assertion if it pins the text.

## Not in this round

The TUI-wide bidi/format-character filter (follow-up outside this track).
