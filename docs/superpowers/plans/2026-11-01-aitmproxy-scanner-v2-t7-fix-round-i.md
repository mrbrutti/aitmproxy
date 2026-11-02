# T7 fix round I: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows for Task 17: security PASS with two Minor, quality FAIL with one Important and six Minor, spec PASS with three Minor).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D6 hostile-core bounds, D11 Issues detail and Site map head, D12 legacy path).
**Range reviewed:** `3efafab6..955e84c8` (the Task 17 merge, H60, H61, H84, H85, H86). The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding that changes behaviour (I2, I3) write the reproducing test first; structure items use the existing tests as the guard. Commit as `fix(tui-scan): <ids> <title>` (one commit per group is fine). Do not fix anything not listed here.

## Important

I1. **`bound_summary` copies `bound_issue`'s shared-field list** (`crates/aitm-tui/src/scan/issues.rs` `bound_summary` ~695-736 vs `bound_issue` ~758-806; quality Important). Extract `fn location_strings(loc: &mut IssueLocation) -> Vec<&mut String>` (path, path_template, name, method, field_path, ws_path, and the `l4` ip/grammar/field_path/mutation when present), `fn target_strings(t: &mut IssueTarget) -> [&mut String; 2]`, and `fn bound_jobs(jobs: &mut Vec<JobId>) -> usize` (dedupe keeping first occurrence, truncate to `DETAIL_LIST_MAX`, `shrink_to_fit`, return the dropped count); `bound_issue` and `bound_summary` list only their own fields and extend with these. Existing tests (`a_page_rows_strings_are_bounded_at_fold`, `a_page_rows_jobs_are_bounded_at_fold`, `the_job_line_is_bounded_at_fold_with_a_plus_n`, the in-file `bound_issue` tests) guard the refactor.

## Behaviour

I2. **`forget_job` keeps an issue whose `jobs` repeats the sole finder or disagrees with `job`** (`crates/aitm-tui/src/scan/issues.rs` `forget_job` ~601-606; security Minor 1 + quality Minor). The predicate is `jobs.len() == 1 && jobs[0] == job` over a cloned `jobs_or_job()`. New rule, no clone: an issue is forgotten for `job` when every listed finder is `job` (`jobs.is_empty()` then `i.job == job`, else `i.jobs.iter().all(|j| j == job)`); with I1's dedupe at fold the duplicate case also collapses. Tests (`tests/scan_v2_issue_detail.rs`): `jobs: [A, A]` is dropped on A's terminal line; `job: A, jobs: [B]` is kept on A's line and dropped on B's; the existing two-job test unchanged.

I3. **Issues page `next_cursor` stored unbounded** (`crates/aitm-tui/src/scan/issues.rs` `fold_result` ~517; security Minor 2, G16 parity). A `next_cursor` longer than `CURSOR_MAX` chars is dropped to `None` at fold (the Issues filter never sends it back yet, so no error report is needed; say so in the field doc and note the difference from the Site map's G16 path). Test (`tests/scan_v2_issues.rs`): a page whose `next_cursor` is 5000 chars leaves `next_cursor == None`; one of 10 chars is kept.

## Structure

I4. The ` +n` suffix is built three ways (`crates/aitm-tui/src/scan/jobs.rs:395` `fn more`, `jobs.rs:506` inline `format!(" +{more}")`, `crates/aitm-tui/src/scan/issues.rs` `jobs_text`): move `more(dropped: usize) -> String` to `scan/mod.rs` as `pub(crate)` and call it from all three sites.

I5. Doc comments naming removed or renamed things: `crates/aitm-tui/src/action.rs:12-14` (`CONFIRM_KEY` "and the fixture bus looks for it": drop the clause); `crates/aitm-tui/src/keys.rs:107` and `crates/aitm-tui/tests/scan_v2_profiles.rs:170` (cite `tests/scan_surface.rs`: now `tests/scan_v2_legacy.rs`); `crates/aitm-tui/tests/common/mod.rs:320` ("The 22 commands the bus served before that merge" lost its antecedent: name the merge or say "before the F5/F6/F7/F12/F13/M3 tools landed"); `crates/aitm-tui/README.md` Testing section (~383-388): add one sentence that the `scan_v2_*` suites also read the `aitm-scan-model` contract pack (wire-shape examples pinned against the engine), not a recorded fixture.

I6. `tests/scan_v2_legacy.rs:193-225` `scan_command_with_target_is_scope_gated` duplicates `tests/robustness.rs:2131-2175` and asserts loosely: keep only the legacy out-of-scope half here (robustness owns the v2-bus case and the in-scope legacy launch), pin the literal toast ``Out of scope: add `evil.example` to scope to scan it``, and read the sidebar row at `:239` with `line_with(&sidebar, "  Scan")` instead of `any(|l| l.contains("Scan"))`.

I7. `tests/scan_v2_issue_detail.rs:1046-1050`: `want` restates `jobs_text`'s formula; add `assert!(want.ends_with(", scan-00000007 +12"))` (or build `want` as a literal).

I8. Three `screen` helpers (`tests/common/mod.rs:483` fixed 200x50; `tests/scan_v2_legacy.rs:20` app-sized; `tests/scan_v2_confirm.rs:21` a pass-through to `text_of`): delete the confirm suite's wrapper and call `text_of`; in the legacy suite use `common::screen` (every `legacy_app` there is 200x50).

I9. **H40 title pin not re-homed** (spec Minor 1): add `assert!(text.contains("Findings · PoCs and runs"))` to an existing live-only test that enters `Mode::Findings` (`tests/robustness.rs` ~1232 neighbourhood, or the `P` test in `tests/scan_v2_issue_detail.rs`).

I10. `tests/tester_sysproxy.rs` `help_overlay_orders_the_s_line_and_keeps_its_footer`: move the `Resize` to the top of the loop body so the first draw follows it (readability; behaviour unchanged).

I11. `crates/aitm-tui/src/scan/sitemap.rs` `fold_result` (~247): one-line comment that an appended page naming a different job overwrites the head's job (the core's word).

## Not in this round

Spec amendments for D11 literals (`l4` line, `job` line, Site map `job` head), D3 shapes (`SitemapState.job`, `Dropped.jobs`) and the deleted-file names (orchestrator, this round, docs only). `Issue::sole_finder` in `aitm-scan-model` (shared crate; the predicate lives locally per I2). The umbrella spec's `scan.sitemap` verb row and amendment log (coordinator).
