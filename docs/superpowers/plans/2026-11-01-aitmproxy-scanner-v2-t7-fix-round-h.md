# T7 fix round H: residuals from the combined re-review of fix rounds G-A, G-B and G-C

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round H").
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` as amended through 2026-11-01.
**When:** after the three re-reviews of G-C and the three of G-A+G-B have reported; one Coder for the cell items, one for the Rust items if any; then Task 16.

## Cell (`tests/e2e/tui/test_tui_scan_live.py`)

H1. A cleanup step that raises skips the work-dir removal (`run`'s `finally`): wrap each cleanup statement in its own `try/except Exception: pass` (or nest `try/finally` so `rmtree(work)` is the innermost), and run `l4_remove_quietly` before `term.stop()` so a hung TUI kill cannot keep the scope entry alive.

H2. An `l4.scope.add` whose reply is lost (a `BusError` while reading the reply, not a `ToolError`) leaves the entry on a runner core: on `BusError` only, list the scope and remove an entry whose full tuple equals the one just sent (`cidr`, `ports`, `interface`, `direction`, `capability`, runtime source); an exact-tuple match of the cell's own values is not the loose match G97 ruled out.

H3. Sample tags are the caller's expectation, not the screen (`Ctx.snap`/`Ctx.screen`, `step_t7_17`, `step_t7_19`): classify in `Ctx.snap` from the text itself (`scan` when the tab strip is present, `inspector` when the `Request\s+Headers` pane row is present, else `other`) and drop the caller-supplied tag, so a failure path can neither leak an inspector screen into the T7-20 grep nor hide a Scan-surface one.

H4. `EDITOR_HEAD_RE` matches the no-editor hint `⏎ opens the profile under the cursor` (`focus_profiles_list`): every Profiles visit without a held editor presses `Esc` from the List pane, drops to Flows and recovers with `:scan`. Detect the held editor by a label only the editor draws (the Fields block's `origins`/`lanes` rows) or exclude the hint (`\bprofile (?!under\b)[A-Za-z0-9_.-]+`); correct the comment.

H5. `TAB_MARKERS["2"]` is unused configuration: use it (wait on the Jobs footer before `row_tail` so the "Jobs row is on screen" check is tab-specific) or drop it.

H6. T7-17's `name[:20]` needle assumes 20 name cells in the Issues list (the column shrinks to `COLUMN_MIN = 8`): derive the needle from the rendered list row (text after `>` and the two glyphs, first `COLUMN_MIN` chars) and rely on the `J` pin for uniqueness; the `J` pin itself becomes a check, or `on_cursor(text, needle)` is required after `cursor_to` before the running comparison (the cancelled job's twin issue must not satisfy it).

H7. `cursor_row` re-inlines `CURSOR_ROW_RE`: give the constant the capture group and use it in both places.

H8. `harness_scan_start` catches `AttributeError, TypeError`: return `("error", ..)` when `profile` is not a dict and catch only `(ToolError, BusError)`.


## Not in this round

The harness's shared default operator token on a loopback bus and the parent env inherited by the TUI child are pre-existing harness conventions (T10).
