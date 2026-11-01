# T7 fix round E: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round E": residuals from the re-reviews of fix round C, plus whatever the Task 8 panel adds before this round runs).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D3, D6, D11, D13 as amended).
**When:** after Task 8 and its panel, before Task 9. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

For each finding that changes behaviour (E1, E3) write the reproducing test first; structure items use the existing tests as the guard. Commit as `fix(tui-scan): <ids> <title>`. Do not fix anything not listed here.

## Behaviour

E1. **Jobs rows are still built at render over the raw core strings** (`crates/aitm-tui/src/scan/jobs.rs`, `crates/aitm-tui/src/ui/scan/jobs.rs`, `crates/aitm-tui/src/ui/text.rs`): bound once at fold time: `fold_status` truncates `profile_name` to `PROFILE_MAX` and each `targets` entry to `4 * TARGETS_MAX` cells in place (D6 "row strings are bounded once at fold time"), so `row()` only copies bounded text; and `ui::text::truncate` early-exits once `w` cells are consumed (walk chars until the width is spent, then decide whether anything was cut) so a call is O(w) regardless of input length. Test: a `scan.status` with a 1 MiB `targets[0]` leaves `full[job].targets[0].chars().count() <= 4 * TARGETS_MAX + 1`; `truncate(&"x".repeat(1_000_000), 10)` returns a 10-cell string (and a unit test on an early exit path if you instrument one).

E2. C2's doc bound (`crates/aitm-tui/src/scan/jobs.rs` `poll_offset`/`advance_poll` docs): state `ceil((n-1)/15)` firings while the cursor's job is live, `ceil(n/16)` otherwise.

E3. **The notice is cleared by any parsed `scan.*` reply** (`crates/aitm-tui/src/app.rs` `scan_reply`, `crates/aitm-tui/src/scan/mod.rs` field doc): ruling (a): drop the reply-clear; the notice lives until the next key (D3 says "the next key"; a background status poll must not erase `already done` before the operator reads it). Test (`tests/scan_v2_jobs.rs`): with job A done and job B running, `x` on A then a `scan.status:B` reply leaves the banner reading `already done`; `Down` clears it.

E10. **A landing suppressed while a read is pending is never retried** (`crates/aitm-tui/src/app.rs` `scan.issue` reply arm): on a successful `scan.issue` reply, if the Issues tab is shown with the List pane focused and the cursor's id differs from the reply's id and is not in `read`, run `issue_cursor_landed` once (never on a failed reply, so no retry loop). Test (`tests/scan_v2_issues.rs`): land on row 1 (read pending), Down to row 2, fold row 1's reply: exactly one `scan.issue` for row 2 leaves.

## Structure

E4. The model imports a UI module (`crates/aitm-tui/src/scan/jobs.rs` `use crate::ui::text::truncate`): move `ui/text.rs` to `src/text.rs` (`pub mod text;` in `lib.rs`), keep `pub use crate::text as text;` in `ui/mod.rs` so existing `crate::ui::text` paths compile; the model imports `crate::text::truncate`.

E5. Three public readings of one Detail pane (`crates/aitm-tui/src/scan/jobs.rs`): `detail_line_count`, `WAITING_FOR_STATUS` and `detail_lines` become private; `tests/scan_v2_jobs.rs` asserts `jobs.detail_len() == 1 + jobs.detail_text().len()` for the full and the bare state instead of calling `detail_lines`.

E6. `summaries` field doc contradicts the invariant and `row_of` (`crates/aitm-tui/src/scan/jobs.rs`): "The summary of every listed job. Every key is in `order`; an `order` id started here and not yet answered has none (`row_of` draws it as `...`)."

E7. `live()` dedupe condition reads harder than the rule (`crates/aitm-tui/src/scan/jobs.rs`): `ids.extend(under_cursor.cloned()); ids.extend(order[start..].iter().chain(&order[..start]).filter(|id| Some(*id) != under_cursor).cloned());` then the terminal `retain`.

E8. Two spellings beside each other (`crates/aitm-tui/src/app.rs` Left/Right arm `d`/`dir`; `crates/aitm-tui/src/ui/scan/jobs.rs` gap spelled twice; `crates/aitm-tui/src/ui/scan/confirm.rs` one fully qualified `Style`): derive `d` from `dir`; one `const GAP_TEXT: &str = "  "` with a const assertion against `GAP`; import `Style`.

E9. Cadence/jobs test hygiene (`tests/scan_v2_cadence.rs`, `tests/scan_v2_jobs.rs`): move `forty_running_jobs` beside `running_body`; split `rows_are_bounded_at_construction_not_at_render` into `rows_are_bounded_at_construction` and `detail_len_counts_what_detail_text_draws`.

## Not in this round

The TUI-wide bidi/format-character filter (follow-up outside this track).
