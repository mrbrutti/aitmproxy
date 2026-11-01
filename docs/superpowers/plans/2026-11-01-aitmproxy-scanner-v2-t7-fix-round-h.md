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


H9. **Critical.** The two line-anchored `>` cursor regexes (`CURSOR_ROW_RE`, `cursor_row`) can never match the real screen: the Scan view is drawn inside a box and the 28-column sidebar is open at 200 columns, so every row reads `<sidebar>│>standard ...` and `>` is never at column 0; `focus_profiles_list`'s poll therefore fails, `open_profile` is fatal, and T7-16 to T7-19 never run; `cursor_row()` is always `None` in T7-19. Read the mark relative to the box: take the leftmost `│>` on a row (the list pane's left edge is the box border; the Site map Points pane's `>` follows the pane rule further right, so the first match per row is the list's) and cut the capture at the pane rule / `LIST_SPAN`; one constant with the capture group used by both readers (H7). Re-check the T7-19 `node_needle` match against the capture. Prove it with an offline unit check inside the cell (a `--selftest` flag or a `__main__` guard that feeds a captured 200x50 frame literal, with sidebar and box, through `cursor_row`/`on_cursor`/`group_of`/`inspector_open`) so this class of regression is caught without a core.

H10. **Important.** The `P` fallback passes without reading the selection (`text.count(needle) >= 2` counts the name anywhere; two same-titled findings exist once both `standard` jobs record a PoC): keep the `poc` line as primary and make the fallback read the selected finding's detail head only (title before severity: `" {title}  {SEVERITY}"` from `ui/overlays.rs`, while list rows put the severity first); drop the bare count.

H11. T7-19 waits for the Site map marker before pinning the job, so the tab check rides on the job-less `scan.sitemap {}` answer: press `3`, then `J`, then wait for `f"{len(nodes)} nodes"` and treat that as the tab's marker; fail only after that wait.

Ratified builder decisions (recorded here, no change): needle prefix widths (`name[:20]` becomes the rendered-row needle of H6; `pay_needle[:20]`, `node_needle[:40]`, point name `[:16]` stay, prefixes of random-free literals are safe against the live read); `on_cursor`'s `{0,8}` glyph allowance; `pick_issue`'s 8-candidate cap; `SAMPLES_MAX = 6` and the timeouts.

## Round H cell result (2026-11-01)

Done, one commit `c34a08b0` (+565/-83); `--selftest` paints 200x50 frames from the renderer's geometry and passes 22 assertions offline; py_compile and discovery clean; the sandbox run dies at the bind denial before any claim. Premise correction: `Mode::Scan` bypasses `main_region`, so the Scan view draws no sidebar; the box border alone offsets `>` to column 1, and the reader anchors on the border column found from the tab-strip row, so it holds at any offset (the self-test covers a 28-column-sidebar variant too).

## Round H cell re-review residuals (spec lane PASS, 2026-11-01)

H12. `SITEMAP_MARKER = "{n} nodes"` is a bare substring (`"3 nodes"` matches `"13 nodes"` from the job-less answer): `SITEMAP_MARKER = " {n} nodes"` (the hint's leading pad cell) or `(?<!\d){n} nodes`; add the `n=13` negative beside the self-test's `n=4` one.

H13. T7-19 identifies the node under the cursor by prefix (`GET  /` claims `GET  /search`): match `under.startswith(node_needle(n).rstrip() + "  flows")`; in `inspector_open` require the path be followed by whitespace, `?` or end of line (`re.escape(path) + r"(?=\s|\?|$)"`). Self-test row for the root-node case.

H14. T7-18's post-`y` `row_shown` reads the id anywhere (the start toast carries it) and does not wait on the Jobs marker: `row_shown = bool(new_job) and term.wait_for(TAB_MARKERS["2"], ROW_APPEAR_S) and poll(row_tail ..)`, H5 parity.

H15. The wire-confirm overlay does not sit over the Scan view (see H18), so the T7-18 overlay sample tags `other`/`inspector` and leaves the T7-20 grep: paint a WireConfirm frame in the self-test (centered `boxed` over whatever body `ui/mod.rs` draws) and assert `surface_of`'s answer; correct the Evidence docstring ("the four tabs" only, overlays per H18); once H18 lands the sample tags `scan` by itself.

H16. H2's lost-reply path is a socket timeout (`OSError`), not a `BusError`: catch `(BusError, OSError)` on the add and run the same exact-tuple lookup; `l4_entries`/`l4_entry_by_id` treat `OSError` like `BusError`.

H17. H6's justification is off by one (`fit` renders 7 chars plus `…` at exactly `COLUMN_MIN`): make the row-name comparison ellipsis-tolerant (`cell.endswith("…") and needle.startswith(cell[:-1])`) and state the 200-column arithmetic in the comment.

## Round H cell H12-H17 result (2026-11-01)

Done, one commit `d2b3c7bf` (+197/-44); `--selftest` 30 ok (8 new rows: n=13 marker negative, root-node exact match, path matched whole, three WireConfirm bodies incl. the secret-prefix visibility beside the box, `OSError` scope read, COLUMN_MIN name cell); py_compile and discovery clean; the sandbox run dies at the bind denial before any claim. H13 uses the uncut `node_row_head` (`"{:<4} {}  flows"`) instead of the 40-cut needle (ratified: strictly more faithful). The cell is complete pending the Terminal run; the live run's core carries the `interface "*"` fix (T1b abaf5264), so the cleared-gate sub-steps run for real.

## Rust (after round G-B, one small coder)

H18. `Mode::WireConfirm` has no body arm in `ui/mod.rs` `render()` (`crates/aitm-tui/src/ui/mod.rs`): the body falls to `main_region` (Flows list and inspector), so a Scan launch confirm draws over the Flows view and the operator loses the Scan context under the box; when the selected flow carries session material its inspector shows it under the overlay. Add a `Mode::WireConfirm` arm that draws the body of `wire_confirm_from` (the Scan view when the launch came from Scan, else `main_region`) before `scan::confirm::render`. Test (`tests/scan_v2_confirm.rs`): a `needs_confirmation` on `scan.start` renders the tab strip ` 1 Profiles` under the overlay at 200x50; an L4 confirm from Flows still shows the flow list.

H19. Em dashes remain in operator-visible `app.rs` strings and in doc comments beyond G103's four (around lines 1622, 2033, 2137, 2144, 2149, 2171, 2199 and doc comments; `grep -n '—' crates/aitm-tui/src`): replace every one in the crate with a colon, comma or sentence break as the sentence wants (Matt's TUI-wide rule); update the tests that pin them. Not the `Findings — PoCs and runs` box title if a test outside this crate pins it; report it instead.

H20. **Critical (was G19, claimed by round G-A, not in the range).** `app.rs` `scan.discover` arm calls `show_legacy` unconditionally; gate it on `MapSource::from(scan_offer()) == Legacy`; test: a V2 app with a folded `scan.sitemap.json` page then a `scan.discover` reply keeps `sitemap.nodes`/`lines` and fills `legacy.endpoints`.

H21. G2's prescribed unit test: in `scan/issues.rs` the L4 mirror test folds 100 probe flows through `IssuesState::fold_issue` and asserts `DetailLayout::of(read).total == detail_len()` and `layout.row(first_after) == DetailRow::After(0)`.

Ratified from the G-A+G-B spec re-review: `ui::scan::{Hint, hints, HELP, key_text, rows, wrap, blocked_footer, launch_reason}` stay `pub` because `tests/scan_v2_layout.rs` (G88) reads `HELP`/`key_text` from outside the crate; `scroll(at, ..)` lives in `scan/mod.rs` as `pub(crate)` so `DetailView::scroll` can use it; `LaunchVerb::parse`, `ReadCache::is_empty`/`keys`, `CURSOR_TOO_LONG` and `GATE_OPEN_PROFILE` are accepted helpers.

## Core track (outside T7, relayed to the coordinator 2026-11-01)

`l4.scope.add` refuses `interface: "*"`: `crates/aitm-proto-l4/src/commands/scope.rs` `validate_interface` (`^[A-Za-z0-9._:-]{1,15}$`, landed in #218) has no `ANY_INTERFACE` branch, while `guard.rs` defines `"*"` as the entry-side wildcard and the TUI's D7 text tells the operator to add exactly that entry. Until the core accepts `"*"` the live T7-18 cleared-gate sub-steps (overlay, `y`, `n`) can only be noted as a core refusal; the cell must not paper over it with a literal interface (the guard's `interface_covers` would then demand the engine's target interface equal it).

## Not in this round

The harness's shared default operator token on a loopback bus and the parent env inherited by the TUI child are pre-existing harness conventions (T10).
