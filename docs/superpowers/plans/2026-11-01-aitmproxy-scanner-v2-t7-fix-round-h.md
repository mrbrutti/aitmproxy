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

## Cell items from the first live smoke run (abaf5264 engine, 21 of 26 ok; `/tmp/claude/t7-live-smoke2`)

H37. The `standard` job against the small target finished 182 probes in about 6 s, so `x` found the row already `done` (status-pairs.json: sample 3 reads `done`): press `x` as soon as `SAMPLES_MIN` samples exist (do not wait for a phase change; the phase assertion reads whatever the samples hold), and if the bracketing `scan.status` before `x` already reads a terminal state, launch a fresh job from the held editor and press `x` within its first second, asserting `cancelled` on that job instead; the push-count check then names the cancelled job. The T7-16 "phase changed" check stays as is (it passed live).

H38. A failing check keeps only a 700-character fragment of the screen, which is not diagnosable: `Checks.check` on a failure writes the full redacted screen to `<evidence>/fail-<n>-<step>.txt` (the detail names the file) and the failure summary lists those files; the `--selftest` gains a row that a failing check writes its file.

H39. T7-19's Site map head stayed blank after `3` then `J` while the harness's `scan.sitemap {job}` read had 1 node: before failing, the step records in the detail the tab-strip row (the banner carries any `scan.sitemap` error wording), the Jobs cursor's job id as the TUI shows it on the Jobs tab, and the harness's node count for `scan.sitemap {}` and `{job}`; it also waits for either the `{n} nodes` head or an error banner on the Site map tab, so the failure says which.

H41 (cell, after H37-H39). The self-test's Findings frame literal follows H40: `Findings · PoCs and runs`; the live `P` poll keeps matching `PoCs and runs`.

H42 (cell). A `standard` job under `crawl.use_browser: auto` with no reachable browser burns its probes without discovering points (coordinator, from T2's diagnosis; the first live run's 182 probes and zero issues): before every `s`/`m` from the held editor (T7-16, T7-17, T7-19), the cell moves the Fields cursor to the crawl `browser` field and cycles it with `e` until the Fields line reads `browser never` (the ring is auto, always, never), asserting the line; the T7-18 `l4-stream-safe` launch needs no browser. The harness's own `scan.start` comparison in T7-18 sends the same `crawl.use_browser = "never"` override.

**Cell H37-H39, H42 result (2026-11-01):** done in `8ecd6c9d` (+271/-34); `--selftest` 33 ok with mutation checks per new row; py_compile and discovery clean; the sandbox run dies at the bind denial before any claim. Decisions ratified: the "finished before `x`" path is a `note` and the fresh job carries its own check; failure screens are also Evidence samples; H39 also records `no site map yet`; the Fields pane is reached by Esc then Tab and `EDITOR_FIELDS` is copied as a reviewable tuple; the H42 line is a hard check.

## From the second live smoke run (`/tmp/claude/t7-live-smoke3`, 7 ok, 2 failed at H42)

H43 (Rust). `Mode::Prompt` opened from the Scan view draws its body as the Flows view (`ui/mod.rs` `render`): the saved failure screen shows the flow list and inspector under a `value: standard` prompt bar. Same class as H18: draw the body of the mode the prompt returns to. Test: `o` on the `standard` editor renders ` 1 Profiles` and `profile standard` under the `origin:` prompt at 200x50; a Flows prompt still shows the flow list.

H44 (cell, after H45). `set_browser_never` must not type into a stray prompt: after each `e`, if the bottom bar reads `value:` the field cursor was not on `use_browser`; press `Esc`, fail the check with the screen and stop pressing keys (the second failure screen shows `standards` typed into the prompt). After H45 the walk itself works; this is the guard.

H45 (Rust, Important). No test drives the Fields pane by keys (every profile test sets `editor.field` directly); live, `Esc`, `Tab`, `g`, `j` x12 left the field cursor on `name`. Test first: open `standard`, `Esc`, `Tab`, `Home`, `Down` x12, assert `editor.field() == UseBrowser`, `e` twice, assert the crawl line reads `browser never`; fix what it exposes (pane ring, `cursor_mut(Fields)`, key map, `e` dispatch) and report what was wrong.

H46 (cell). The second subscriber counted zero `notifications/aitm/job` lines in run 1 while T1b confirms fan-out reaches every connection holding any `flow.subscribe` (no filter, no replay, operator never muted): the `Pushes` thread must make its own state visible. Record in `push-counts.json` the total lines drained by method (`by_method`), the thread's exit reason (`stopped_by: <Type>: <text>` when an exception ended `_run`, else `stopped_by: stop()`), the subscribe reply, and the first three raw `notifications/aitm/job` params (redacted); the T7-16 push check's failure detail quotes them. The thread never exits on a single bad line (catch per message); it exits only on `stop()` or a dead socket, and a dead socket is a failing check at the end of T7-16.

T1b's engine answers (2026-11-01): a `standard` job discovers through the browser when one is bound and `crawl.use_browser != never`; on 8be3e070 a failed browser crawl did not fall back to the client crawl (fix landing: `JobStatus.crawl.errors` counts it and the client crawl stands in), which is why run 1's 182 probes found nothing. With `use_browser: never` (H42) the client crawl yields one `reflected-xss` (`xss-reflected`) issue on `/search` param `q` plus passive origin-level issues; `tests/e2e/scan/test_t1_issues.py` proves it live. Push: `notifications/aitm/job` with `params { job, kind, event, seq, status, issue? }` fans out to every connection holding any `flow.subscribe`, subscribe before `scan.start`, no replay.

## Rust (after round G-B, one small coder)

H18. `Mode::WireConfirm` has no body arm in `ui/mod.rs` `render()` (`crates/aitm-tui/src/ui/mod.rs`): the body falls to `main_region` (Flows list and inspector), so a Scan launch confirm draws over the Flows view and the operator loses the Scan context under the box; when the selected flow carries session material its inspector shows it under the overlay. Add a `Mode::WireConfirm` arm that draws the body of `wire_confirm_from` (the Scan view when the launch came from Scan, else `main_region`) before `scan::confirm::render`. Test (`tests/scan_v2_confirm.rs`): a `needs_confirmation` on `scan.start` renders the tab strip ` 1 Profiles` under the overlay at 200x50; an L4 confirm from Flows still shows the flow list.

H19. Em dashes remain in operator-visible `app.rs` strings and in doc comments beyond G103's four (around lines 1622, 2033, 2137, 2144, 2149, 2171, 2199 and doc comments; `grep -n '—' crates/aitm-tui/src`): replace every one in the crate with a colon, comma or sentence break as the sentence wants (Matt's TUI-wide rule); update the tests that pin them. Not the `Findings — PoCs and runs` box title if a test outside this crate pins it; report it instead.

H20. **Critical (was G19, claimed by round G-A, not in the range).** `app.rs` `scan.discover` arm calls `show_legacy` unconditionally; gate it on `MapSource::from(scan_offer()) == Legacy`; test: a V2 app with a folded `scan.sitemap.json` page then a `scan.discover` reply keeps `sitemap.nodes`/`lines` and fills `legacy.endpoints`.

H21. G2's prescribed unit test: in `scan/issues.rs` the L4 mirror test folds 100 probe flows through `IssuesState::fold_issue` and asserts `DetailLayout::of(read).total == detail_len()` and `layout.row(first_after) == DetailRow::After(0)`.

Ratified from the G-A+G-B spec re-review: `ui::scan::{Hint, hints, HELP, key_text, rows, wrap, blocked_footer, launch_reason}` stay `pub` because `tests/scan_v2_layout.rs` (G88) reads `HELP`/`key_text` from outside the crate; `scroll(at, ..)` lives in `scan/mod.rs` as `pub(crate)` so `DetailView::scroll` can use it; `LaunchVerb::parse`, `ReadCache::is_empty`/`keys`, `CURSOR_TOO_LONG` and `GATE_OPEN_PROFILE` are accepted helpers.

**Rust H18-H21 result (2026-11-01):** done in `c55c6695` (H18: the overlay body goes through the same mode match on `wire_confirm_from`), `99426dfd` (H19: 32 files; the 58 remaining `—` are the §2.8 missing-value glyph, ratified as foundation design, plus the `Findings — PoCs and runs` title, now H40, and the fixture's `Shop — staging` page data), `431cbbdd` (H20), `0817f035` (H21, with a mutation check); crate gate green (520 tests).

H40. The Findings overlay title `Findings — PoCs and runs` (`ui/overlays.rs`, pin in `tests/tester_components.rs`) becomes `Findings · PoCs and runs` (the middle dot is the TUI's separator everywhere else); the cell's self-test literal follows in H41 (cell).

### Rust bounds (from the G-A+G-B security re-review; same Coder as the tidy, these first)

H33. **Important.** `JobStatus.lanes.requested`/`lanes.run` are unbounded in count at fold and joined per frame in the Jobs Detail pane (`scan/jobs.rs` `bound_status`, `detail_lines`): sort, dedup and `shrink_to_fit` both in `bound_status` (four kinds at most). Test (`tests/scan_v2_jobs.rs`): a status with 100_000 `http` run lanes folds to `lanes.run == [Http]` and the detail line reads `run http` at 200x50.

H34. The wire-confirm prompt is wrapped whole every frame (`ui/scan/confirm.rs` `wrap(&c.prompt, w, usize::MAX)`; `scan/launch.rs` `WireConfirm::from_reply`): cut `prompt` to `PROMPT_MAX = 2000` cells with `clean` in `from_reply`, and pass `usize::from(inner.height)` as `max_rows`. Test: a 1 MiB prompt renders in the box with an ellipsis.

H35. Legacy `scan.discover` failure text kept unbounded and re-bounded per frame (`app.rs` `CallFailed` arm, `ui/scan/mod.rs`): store `truncate(&clean(&message), ERROR_DETAIL_MAX)` in `legacy.error`.

H36. `scan.list` has no row-count cap (`scan/jobs.rs` `fold_list`): `JOBS_MAX = 256`; `list.jobs.truncate(JOBS_MAX)` before the retain-and-order logic (started-here ids are kept in front as today). Test: a list of 100_000 ids folds to 256 rows.

(The Site map `cut` without `clean` is H22's `cut_to`.)

### Rust tidy (from the G-A+G-B quality re-review, one Coder after H18-H21)

H22. One `pub(crate) fn cut_to(s: &mut String, max: usize)` in `text.rs` (clean, then truncate when over `max`) replaces the copied closure in `bound_issue`/`bound_status` and the private `cut` fns in `profiles.rs` and `sitemap.rs`; per-site constants stay; the Profiles and Site map sites now strip control characters too (state it in the doc).

H23. `help_line_count()` is a hand-kept twin of `help_lines()` (`ui/overlays.rs`): one theme-free row table (`enum HelpRow { Heading, Key, Command, Blank, Close }`) built once, `help_lines` styles it, the count is its `len()`; delete `help_line_count`; fix the `help_box` doc (takes a `Rect`).

H24. Test scaffolding: `common::opened_minimal(tools) -> App` (the `scan.list`-only open) and `common::screen(app)`; `scan_v2_issue_detail.rs`, `scan_v2_issues.rs`, `scan_v2_sitemap.rs`, `scan_v2_jobs.rs` use them and `common::reply`/`tagged` instead of hand-built `CallTaggedOk` literals (the jobs variant presses `ScanTab(Jobs)` after).

H25. `check_tree` survives only for tests (`scan/profiles.rs`): delete it; the four tests read `app.scan.profiles.rows()` or filter `tree_nodes(..)` locally.

H26. `rows()` allocates a `Vec<&TreeNode>` per call (`scan/profiles.rs`): `fn rows(&self) -> impl Iterator<Item = &TreeNode>`, `visible_len()`, `cursor_node` as `rows().nth(tree_cursor)`; the view collects once per frame.

H27. `PendingLaunch { call: LaunchVerb, launch: Launch }` (readers write `p.launch.args`), so `send_launch` moves the `Launch` in instead of copying two fields.

H28. Key-table residue (`ui/scan/mod.rs`): `const OPEN_FLOW: Hint = ("⏎", "open flow")` used by `SITEMAP_KEYS`, `ISSUES_KEYS` and `LEGACY_SITEMAP_BAR` (no positional index); `const ISSUES_MORE: &[Hint] = &[FILTERS, RESET]` used by the macro call, `HELP` and the test.

H29. `fn wants_l4(lanes: &[LaneKind]) -> bool` used by `l4_gate` and `row_gate` (`scan/launch.rs`).

H30. `code_wording(NotFound)` returns `NOT_FOUND`; `wording()` appends `"; the list is being refreshed"` when `not_found_job().is_some()`, so the D9 sentence lives once (`scan/mod.rs`).

H31. The new `#[allow(clippy::too_many_arguments)]` on Profiles `row_line` goes: pass the row as one `(&ProfileListEntry, &str)` pair or a small `RowCtx`.

H32. Hygiene: the orphan "The row under the list cursor." doc line moves onto `cursor_entry`; use the imported `status`/`ui::scan`/`scan::launch`/`overlays` paths instead of fully qualified ones; `rows(..)` takes `buf` last like `hint`/`blocked_footer`; the G1 bound test asserts `4 * DETAIL_VALUE_MAX` (drop the `+ 1` and the misreading comment).

## Core track (outside T7, relayed to the coordinator 2026-11-01)

`l4.scope.add` refuses `interface: "*"`: `crates/aitm-proto-l4/src/commands/scope.rs` `validate_interface` (`^[A-Za-z0-9._:-]{1,15}$`, landed in #218) has no `ANY_INTERFACE` branch, while `guard.rs` defines `"*"` as the entry-side wildcard and the TUI's D7 text tells the operator to add exactly that entry. Until the core accepts `"*"` the live T7-18 cleared-gate sub-steps (overlay, `y`, `n`) can only be noted as a core refusal; the cell must not paper over it with a literal interface (the guard's `interface_covers` would then demand the engine's target interface equal it).

## Not in this round

The harness's shared default operator token on a loopback bus and the parent env inherited by the TUI child are pre-existing harness conventions (T10).
