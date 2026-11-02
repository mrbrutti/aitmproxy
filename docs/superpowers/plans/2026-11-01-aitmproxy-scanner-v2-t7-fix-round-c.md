# T7 fix round C: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round C": hygiene from the re-reviews of fix rounds A and B plus one security residual).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3, D6, D7, D11, D13 as amended 2026-11-01).
**When:** after Task 7 lands (the Task 6 panel added the Jobs items below), before Task 8. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding: write a test that reproduces it where behaviour changes (C1, C2, C6, C9, C10, C13); for pure structure changes the existing tests are the guard. Commit as `fix(tui-scan): <finding id> <title>`. Do not fix anything not listed here. Keep every public shape later tasks rely on unless a finding changes it.

## Behaviour

C1. **Outside `Mode::Scan`, push-driven unknown jobs are never pruned** (`crates/aitm-tui/src/app.rs` `on_job_line`): a job id not in `jobs.order` and not in `jobs.started_here` gets a `scan.status` request only while `self.mode == Mode::Scan`; elsewhere the line sets nothing and sends nothing (the next `scan.list` on opening the view brings it). Known jobs keep the current behaviour in every mode. Test (`tests/scan_v2_cadence.rs`): in `Mode::Flows` a `job.progress.json` line for an unknown id yields no request; after folding `scan.status.json` for that id (now known) the same line yields one `scan.status`.

C2. **Starvation past position 16 under the status cap** (`crates/aitm-tui/src/app.rs` `scan_tick`/`request_scan_statuses`, `crates/aitm-tui/src/scan/jobs.rs`): keep `MAX_STATUS_FOLLOWUPS = 16` and the cursor-first rule, but start the walk of `order` at a rotating offset (`JobsState.poll_offset: usize`, advanced by the number of jobs considered) so every live job is reached within `ceil(n / 16)` firings. Test: 40 running jobs, three firings (12 ticks) with every reply answered in between reach all 40 ids at least once.

C3. **`Disconnected` drops the confirm token only when the overlay is the current mode** (`crates/aitm-tui/src/app.rs`): take `wire_confirm` regardless of mode, toast once, and restore `wire_confirm_from` only when the mode was `WireConfirm`. Test in `tests/scan_v2_confirm.rs`: `wire_confirm = Some(..)` with `mode = Mode::Flows`, `Disconnected` leaves `wire_confirm == None` and `mode == Mode::Flows`.

## Structure

C4. `ScanError` tag is a caller convention (`crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/app.rs`): constructors take the tag and derive `verb` with `tag_parts(tag).0`: `ScanError::from_message(tag: &str, message: &str)`, `ScanError::uncoded(tag: &str, detail: impl Into<String>)` (used by `parse_result`, which takes the tag, by `missing_verb`, whose tag is the bare verb, and by the `OTHER_JOB` site); delete `tagged()`. Callers in `app.rs` (`scan_reply`, `on_scan_failed`, `scan_call`) pass the tag. The D9 wording table and `MISSING_VERB` detection are unchanged except C5.

C5. `wording()` detects the missing-verb case by `starts_with` on the detail (`crates/aitm-tui/src/scan/mod.rs`): compare with `==`; `MISSING_VERB` becomes private; `ui/scan/mod.rs` `degraded()` uses `ScanError::missing_verb(verb).wording()` and the UI helper `missing_verb` is deleted (one spelling).

C6. `live()` still chains `summaries`/`full` keys (`crates/aitm-tui/src/scan/jobs.rs`): iterate the cursor's job then `order` only; state the invariant "every key of `summaries` and `full` is in `order`" on the field docs and `debug_assert!` it at the end of `fold_list`; drop the `known` set in `fold_list` if it becomes unused. Test: after `fold_status` of an unknown job then `fold_list` omitting it, `live()` and `order` agree.

C7. `request_scan_statuses` generic over an iterator (`crates/aitm-tui/src/app.rs`): take `&[JobId]`.

C8. `tab_error` clones a `ScanError` twice per frame (`crates/aitm-tui/src/ui/scan/mod.rs`): compute once in `render`/`tab_strip` and pass `Option<&ScanError>` to `banner` and `banner_style`; the legacy Jobs arm builds its `ScanError` once there.

C9. `step(forward: bool)` (`crates/aitm-tui/src/scan/mod.rs`, call sites in `crates/aitm-tui/src/app.rs`): `pub(crate) enum Dir { Next, Prev }` as the parameter; `step_pane` maps once. Existing chip/sidebar/pane tests are the guard.

C10. Confirm overlay classifies the call family twice (`crates/aitm-tui/src/ui/scan/confirm.rs`): one `enum Family { Scan, L4 }` with `Family::of(&call) -> Family` giving title, footnote and hue; existing `scan_v2_confirm.rs` tests are the guard.

C11. `SitemapState::source(offer)` reads no state (`crates/aitm-tui/src/scan/sitemap.rs`, callers in `scan/mod.rs`): `impl From<ScanOffer> for MapSource`; callers use `MapSource::from(offer)`.

C12. `pane_rule` infers orientation from the rule width (`crates/aitm-tui/src/ui/scan/mod.rs`, and the `Panes` literals in `crates/aitm-tui/src/ui/scan/jobs.rs`, see C22): `Panes` carries `side_by_side: bool`; `pane_rule` reads it.

C13. `ScanTab::index()` is dead production code (`crates/aitm-tui/src/scan/mod.rs`): delete it and the loop of the test that asserted it (keep the `default()`/`label()` assertions).

## Tests and comments

C14. A2's test `v2_site_map_enter_opens_the_v2_nodes_first_flow` cannot fail on its `Down` assertions (`tests/scan_v2_matrix.rs`): give `sitemap.nodes` a second node and `legacy.endpoints` one entry; assert `node_cursor == 1` after `Down` and `legacy.endpoint_cursor == 0`.

C15. `tests/scan_v2_matrix.rs` still has its own `fixture!` macro: use `common::fixture`.

C16. `tests/scan_v2_cadence.rs` hand-builds the bus envelopes in nine places with helpers mid-file: `fn job_line(params: Value) -> BusEvent`, `fn list_reply(value: Value) -> BusEvent`, `fn status_reply_for(job: &str, body: Value) -> BusEvent` at the top; the B2 expectations become literal `format!("scan.status:{id}")`, not `tag_keyed`; `running_status`'s `expect` message says what it asserts.

C17. Stale binding `text` in `tests/scan_v2_parse.rs` after B10: `params`.

C18. Fix-round provenance tags in production doc comments (`crates/aitm-tui/src/scan/mod.rs`, `scan/sitemap.rs`, `scan/jobs.rs`, `ui/scan/mod.rs`, `app.rs`: the nine comments reading "(fix round A, Ax)" or "(fix round B, Bx)"): drop the tag, keep the why. Test doc comments may keep theirs.

C19. **`already <state>` is routed through the error channel** (`crates/aitm-tui/src/app.rs` `scan_cancel`, `crates/aitm-tui/src/scan/mod.rs`, `crates/aitm-tui/src/ui/scan/mod.rs`): the banner reads `scan.cancel: already done` in the error hue. Add `ScanState.notice: Option<String>` (a non-error notice, cleared by the next key or reply that changes the tab), drawn by `banner()` in `text_secondary` between the error and the refreshing states; `scan_cancel` on a terminal job sets `notice = Some(format!("already {state}"))` and records no `ScanError`. Test (`tests/scan_v2_jobs.rs` `cancel_on_a_terminal_job_is_inert`): the banner contains `already done` and not `scan.cancel:`.

C20. **Per-frame work scales with unbounded core-supplied strings** (`crates/aitm-tui/src/scan/jobs.rs` `row()`, `detail_len()`; `crates/aitm-tui/src/ui/scan/jobs.rs`): bound at row construction, not at render: `row()` joins at most the first 4 targets and truncates the joined text to 4 x `TARGETS_MAX` cells and `profile` to `PROFILE_MAX`; `detail_len()` counts lines without building their strings (a `detail_line_count(&JobStatus)` mirroring the optional lines). Test (`tests/scan_v2_jobs.rs`): a status with a 1 MiB `targets[0]` renders the Jobs tab at 200x50 with the row's targets cell at most 48 cells wide and the row text containing an ellipsis; `detail_len` equals `detail_lines().len()` for `scan.status.json`.

## Jobs tab (Task 6 panel)

C21. **The view parses the row's display text to rebuild the probe bar** (`crates/aitm-tui/src/scan/jobs.rs`, `crates/aitm-tui/src/ui/scan/jobs.rs` `probe_spans`): add `pub fn probe_fill(sent: u64, budget: u64, cells: usize) -> usize` that `probe_bar` composes from, and `JobRow.probe_fill: usize` (`JobRow::unknown` sets 0); `probe_spans` styles `BAR_FILLED.repeat(fill)` and `BAR_EMPTY.repeat(cells - fill)` with no parsing and no glyph literal. Test (`tests/scan_v2_jobs.rs` `status_renders_the_row_literals`): the row line contains `418/2000 ━━────` and `▆▆▄▄▂▂`.

C22. **`split()` re-implements the stacked branch of `panes()`** (`crates/aitm-tui/src/ui/scan/mod.rs`, `crates/aitm-tui/src/ui/scan/jobs.rs`): add `pub fn stacked(area: Rect, list_rows: u16) -> Panes` in `ui/scan/mod.rs` holding the stacked arithmetic (incl. the too-short case); `panes()`'s stacked arm calls it with 40 percent; the Jobs `split()` calls it with its content-sized rows capped by the same shared percentage; no `Panes` struct literal outside `ui/scan/mod.rs`. Existing Jobs unit tests are the guard.

C23. `severity_bar` has no production caller and `severity_spans` re-implements it (`crates/aitm-tui/src/scan/jobs.rs`, `crates/aitm-tui/src/ui/scan/jobs.rs`): one `pub fn severity_runs(b: &BySeverity, cells: usize) -> Vec<(&'static str, String)>` (label, glyph run; the zero case yields one `("", BAR_NONE.repeat(cells))`); `severity_bar` concatenates, `severity_spans` styles.

C24. `detail_lines` allocates static labels; `detail_len()` builds every line to count; model and view disagree in the no-status case (`crates/aitm-tui/src/scan/jobs.rs`, `crates/aitm-tui/src/ui/scan/jobs.rs`): `detail_lines(status) -> Vec<(&'static str, String)>`; one `JobsState::detail_text(&self) -> Vec<(&'static str, String)>` that includes the `waiting for scan.status...` placeholder when `full` is `None`, used by both `detail_len()` and the view (this also satisfies C20's counting requirement if implemented without allocating, else keep `detail_line_count`).

C25. The Jobs-detail branch of `navigate` repeats the six-arm cursor walk (`crates/aitm-tui/src/app.rs`): a private `fn walk(action: &Action, cursor: usize, len: usize, page: usize) -> usize` (clamp inside) used by both `Mode::Scan` branches; Task 8's Issues detail scroll reuses it.

C26. Local `state_text` shadows the function `state_text` (`crates/aitm-tui/src/scan/jobs.rs`): rename the local.

C27. `row_of`'s `(None, Some(status))` arm is unreachable (`crates/aitm-tui/src/scan/jobs.rs`): state the invariant `full.keys() ⊆ summaries.keys() ⊆ order` on the field docs and collapse the match (ties in with C6).

C28. Module doc says the detail's first line carries profile and targets only in the narrow layout; the code draws them always (`crates/aitm-tui/src/ui/scan/jobs.rs`): pass `cols.full` into `detail()` and draw the two cells only when the table dropped them. Test: at 200x50 the detail's first line does not repeat `standard`; at 90x40 it does (ties in with Task 14's narrow pin).

C29. `Columns::measure` sets `full = true` only so `total()` can read it; test literals `198`/`88` have no visible meaning (`crates/aitm-tui/src/ui/scan/jobs.rs`): `fn total(&self, full: bool) -> usize`; the unit test first asserts the full-row width literal (`100`).

C30. `cancel_is_sent_once_until_the_reply` reads its expected state from the fixture (`tests/scan_v2_jobs.rs`): assert the literal `cancelling`.

C31. Hygiene in `ui/scan/jobs.rs` and `scan/jobs.rs`: clamped cursor computed once in `table()` and passed down; `Span::raw(" ".repeat(GAP))` instead of cloning a `String` per row; `lane_name` private.

## Not in this round

The `summaries` read-through in the Jobs row renderer (Task 6); `IssueFilters::args` and `fetched_at_tick: Option<u64>` (Task 7); `started_here` insertion on `StartResult` (Task 12); `typed_origin` IPv6 bracketing (Task 9); the Site map `render` by `MapSource` (Task 9).
