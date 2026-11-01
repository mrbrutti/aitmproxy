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

**Rust H22-H36, H40, H43, H45 result (2026-11-01):** done, ten commits `63906899..058e72e5`; crate gate green (528 tests). H45 was not reproducible in the reducer (the key walk passes in a test driven exactly as the cell drives it); the live failure came from the cell: `type_origin` returned on the prompt bar's echo of the typed origin before Enter was processed, so the `Esc`/`Tab` walk ran against an open prompt (H49 below). Builder decisions ratified: `const fn join` in `key_table!` for compile-time bar concatenation; `OnceLock` help rows; the two `rows` locals renamed `table`; the 100_000-id `JOBS_MAX` test kept despite its 11 s.

H47 (Rust, Important). `App::toast` is unbounded and `ui/bars.rs` `status` adds centre and right widths in `u16`: a raw 1 MiB `CallFailed` message toasted whole saturates to `u16::MAX` and the add panics in debug (`bars.rs` around line 440); every `CallFailed` verb path reaches it. Bound in `App::toast`: `truncate(&clean(&text), TOAST_MAX = 400)` and `shrink_to_fit`; `status` uses saturating arithmetic. Test (`tests/fix_pass2.rs` or `tester_components.rs`): a 1 MiB toast renders at 200x50 without panic and the stored text is at most 4 * `TOAST_MAX` chars; the H35 test drops its `app.toasts.clear()` workaround.

H48 (Rust). `scan_edit` acts on the Fields cursor from any Profiles pane; D11 says "`e` or `⏎` on a field", so `e` with the editor held but the List, Origins or Checks pane focused is inert with the toast `e edits a field: Tab to the Fields pane` (ratified ruling; D11 amended). Test in `tests/scan_v2_profiles.rs`.

H49 (cell). `type_origin` (and `type_l4_target`, the `w` name prompt) must wait for the prompt to close before returning: the bottom bar no longer shows the prompt label (`origin:` / `l4 target:` / `profile name:`) and the typed value is on the Fields `origins`/`l4` line (or the save toast arrived); only then `focus_profiles_list` may press `Esc` (after H43 an `Esc` into a still-open prompt would discard the typed value). Self-test row: a frame with the prompt bar still up is "not closed".

**Rust H47-H48 result (2026-11-01):** done, `f954c766` (TOAST_MAX = 400 in `App::toast`, saturating sums in `bars.rs`; the bars overflow proven with a scratch test) and `03757f77` (`E_NEEDS_FIELDS` toast, no-editor toast keeps precedence); crate gate green (530 tests). Round H's Rust range is `0817f035..03757f77` plus H18-H21 (`c55c6695..0817f035`): final re-review over `fbdc4513..03757f77 -- crates/`.

**Cell H41, H44, H46, H49 result (2026-11-01):** done in `1293cf6c` (+467/-73); `--selftest` 44 ok with a mutation check per new row; py_compile and discovery clean; the sandbox run dies at the bind denial before any claim. Ratified: no `w` save helper exists so none was added (the reader knows `profile name:`); any Scan prompt label after `e` counts as stray; `set_browser_never` records its own check; `push-counts.json` carries the H46 record with the old counts under `by_job`; `stopped_by` null while running; `profiles_frame` `l4` default `none`. Doc-only residual: the H15 self-test row and two docstrings still call H18 pending (H51).

H51 (cell, doc-only, with the final cell look): the H15 self-test row text and the `Evidence`/`wire_confirm_over` docstrings say H18 is pending; H18 landed in `c55c6695`, so they read "the body under the overlay is the view it came from".

## Round H Rust re-review residuals

H50 (Rust). A maximal wire-confirm prompt pushes the key line out of the box (`ui/scan/confirm.rs`): wrap the prompt into `inner.height.saturating_sub(5)` rows (two header and three trailer rows) so `y confirm (re-issues with _confirm) · n / Esc cancel` is always the last drawn row; one assertion in `a_huge_prompt_is_bounded_at_fold_and_wrapped_to_the_box` that the `y confirm` line is on screen.

## Round H Rust panel residuals (quality and spec lanes, 2026-11-01)

H52 (Rust tidy, one Coder with H50, H53, H56). Quality Minors: `Resume all: {sent} resumed, {skipped} skipped (out of scope: add their hosts to scope to act)` and `host · host:port · *.wildcard (a human action)` with their three test literals; hoist the fixture read out of the `JOBS_MAX` test's loop; `App::toast` and the legacy `CallFailed` arm use `cut_to` in place (`let mut text = text.into(); cut_to(&mut text, TOAST_MAX); text.shrink_to_fit();`; `cut_to(&mut message, ERROR_DETAIL_MAX)`); `scan_edit` computes its blocker once (no-editor beats wrong-pane) with a one-line why on the remaining let-else; `MapSource` imported in `app.rs`; one `walk_to_use_browser_and_set_never(app)` helper for the two H45 tests; drop `assert_eq!(PROMPT_MAX, 2000)` and `assert_eq!(JOBS_MAX, 256)`.

H53 (Rust). `crates/aitm-tui/build.rs:54` doc comment em dash becomes a colon. (`README.md` prose is out of H19's scope; left.) H22's one-line `cut` wrappers in `profiles.rs`/`sitemap.rs` are ratified (they bind the per-site constant).

## From the third live smoke run (`/tmp/claude/t7-live-smoke4`, 29 ok, 1 noted, 3 failed)

H54 (cell). T7-19's "head or error banner" wait returned instantly on a stale banner (the T7-18 L4 launch's `lane_unavailable` wording, shown on every tab by the `last_error` fallback) before the TUI had processed `3`: snapshot the banner before `3`/`J` and treat only a banner that changed to an error wording as the error exit; wait for the `{n} nodes` head otherwise. (H56 removes the cross-tab fallback, so after it the stale wording is not on the Site map tab at all.)

H55 (cell). The engine chose the seeded `GET /search?q=<marker>` (the one reflected-xss point) as the session canary (`session reused · canary GET /search?q=...` in the Jobs detail), and a canary is not attacked, so the job audited 28 points and raised nothing: seed the session material (Cookie and Authorization) on a different path (`GET /` or `/account`) and send the `/search?q=<marker>` request without session headers; T7-20's hygiene source is the session-bearing flow. T1b's correction (2026-11-01): the canary is never excluded; the 62 ignored points were the secret-named cookie and header points on every crawled page (`audit.ignore` default `point_trait: session`), `/search?q` was audited, and the zero comes from the probe responses because the fabricated `Authorization: Bearer` rides on every probe and aitm-testtarget answers an invalid bearer as unauthenticated. Amended H55: seed the session on `GET /` with the Cookie ONLY (no Authorization anywhere), `/search?q=<marker>` without session headers; T7-20 greps the cookie value.

H56 (Rust). The banner falls back to `last_error` on tabs that hold no error of their own (Task 5 behaviour, accepted then): a refused L4 launch's wording then sits on the Jobs, Site map and Issues banners until another error replaces it, misleading the operator and the cell. D13 ruling: a tab's banner shows that tab's own error only; `last_error` stays for the toast and the tests; the Jobs tab (which has no error slot) gets one (`JobsState.error`) owned by `scan.list`/`scan.status`/`scan.cancel`. Test (`tests/scan_v2_errors.rs`): a `refused_l4` on `scan.start` shows on Profiles and not on Jobs/Site map/Issues; a `scan.list` failure shows on Jobs only.

H57 (cell). The second subscriber drained zero lines of any method while the TUI's own connection and three jobs ran (`push-counts.json`: `by_method {}`, `stopped_by: running`, `flow.subscribe` reply `{sub_id: 1}`): T1b's `tests/e2e/scan/test_t1_push.py` (`collect_push`, `subscribe`) receives the lines on this engine with the same harness, so mirror its read mechanism exactly (how it subscribes, how it reads the socket between drains, timeouts) and record in `push-counts.json` what differs if it still sees nothing; also record the TUI connection's own view (the TUI polls, so it shows no pushes) is irrelevant. Ask T1b with the file if the mirrored mechanism still counts zero.

H58 (contract, relayed to the coordinator). The engine at 8be3e070 refuses `scan.sitemap {}` with `scan: invalid_profile: give either job or target`, while the umbrella D3 declares both optional (`{ job?, target?, cursor?, limit? }`) and the TUI's D6 sends `{}` on entering the Site map tab for the all-jobs map. Either the engine accepts `{}` (all jobs) per the umbrella, or the umbrella and D6 change to "one of `job`/`target` required" and the TUI sends the Jobs cursor's job on tab entry. Until ruled, the TUI's tab-entry request fails harmlessly (the error shows on the Site map banner) and `J` works.

## Coordinator contract notes (2026-11-01)

H59 (cell). `l4_add_args` sends `inject_rate_pps` explicitly when `tools/list` declares it for `l4.scope.add` (the default 0 is the fail-closed value and the guard's refusal does not yet name the field): `inject_rate_pps: 10` so the confirmed launch can inject for real; `l4_entry_matching`'s tuple includes it when echoed.

H60 (Rust, at Task 17 after the integration merge brings the model). `Issue.location.l4 = { ip, port, proto, grammar, field_path, mutation }` arrives with T1b's final head: the Issues detail renders a `l4` line (`ip:port/proto · grammar · field_path · mutation`, each part only when present, bounded like the other detail values) when `location.l4` is `Some`; test with a fixture issue carrying it. Not doable before the model lands on main (this branch's `IssueLocation` has no `l4`).

Satisfied already: `poc_ref` not in the Findings list toasts the ref path (`POC_TOAST_MAX`), the spec's fallback.

H61 (Rust, at Task 17 with H60). Umbrella amendment 27: `scan.sitemap {}` returns the newest job's map (`not_found` when no job has run), never an all-jobs merge; when the response names the job it chose, the Site map summary head reads `<n> nodes · job <id>` and `J` pins or clears as today. Needs the response field from T1b's final head; H58 is closed by this ruling.

**Cell H51, H54, H55 (amended), H57, H59 result (2026-11-01):** done in `3dbdb13c` and `2c7c8981`; `--selftest` 48 ok with mutation checks. H57 root cause: `drain_notifications(0.5)` waits for 0.5 s of socket silence, and the TUI's polling fans an agent audit line to the subscriber every ~150 ms, so the drain returned once, after `q` (run 3's final `push-counts.json` held 2518 lines incl. 172 job lines); the thread now reads one line at a time with `wait_notification(JOB_PUSH, 1.0)` as T1b's cell does. Ratified: 1.0 s per read; `GET /` for the session seed; unreadable schema = `inject_rate_pps` not declared; `inject_rate.pps` or flat `inject_rate_pps` read from the list echo. Noticed: run 3's pushes carried `issue` events for the `standard` jobs while `scan.issues {job}` read zero; checked on run 4.

## From the fourth live smoke run (`/tmp/claude/t7-live-smoke5`, 26 ok, 1 noted, 8 failed)

H62 (cell). The `standard` job now finishes 182 probes in about a second (client crawl, no browser), too fast for T7-16's sampling and cancel: T7-16 (and its fresh cancel job) cycle the editor's `speed` field to `thorough` with `e` before `s` (asserted on the Fields line like H42), sample as soon as the row is on screen at 1.0 s spacing (the Jobs-footer wait is folded into the first sample's poll), and press `x` right after the third sample; T7-17 and T7-19 keep `standard`/`map-only`. If even `thorough` reads terminal before `x`, the note stands and the push check names the cancelled job as today.

H63 (cell). T7-19's wait is head-first: poll the full timeout for the pinned ` {n} nodes` head and record a changed error banner only if the head never comes (an engine that refuses the tab-entry `{}` request changes the banner a moment before `J`'s head lands; umbrella amendment 27 removes the refusal on the final head, but the wait must not race it).

H64 (cell). The push thread spun 32 million idle reads in run 4 and saw no job line: the harness's `_rfile.readline()` is a buffered file over a socket, and after one read timeout that reader is unreliable (an instant `OSError` on every later read, which `wait_notification` turns into an immediate `None`); T1b's `collect_push` never times out mid-read because it passes the remaining 600 s. Mirror that: `wait_notification(JOB_PUSH, timeout=PUSH_READ_S)` with `PUSH_READ_S = 600.0` (the cell's own budget), and `stop()` unblocks the thread by closing the push client's socket (the read raises `BusError`/`OSError`, the thread exits) before `join`; never read again after a timeout; count `idle_reads` only when a read actually waited; record `read` as the mechanism string. Self-test row with the scripted client: a read that raises once marks the thread dead rather than spinning. Harness note for T10 recorded in the shared folder.

**Rust H50, H52, H53, H56 result (2026-11-01):** done in `7705cf0b` (H56: `JobsState.error`, no cross-tab fallback), `c609d9fa` (H50: `PROMPT_FRAME_ROWS = 5`; the test's prompt now has spaces so it really wraps), `e4923baa` (H52), `4cf42aa6` (H53); crate gate green (532 tests). Ratified: the `scan.discover` failure toast now carries the 240-cell cut text; a `:scan <origin>` failure from the Flows view is the Profiles slot's error and reaches Jobs by toast only (D13's letter); at an inner height of 5 or less the confirm key line is clipped (accepted edge, `centered` clamps the box to 7 rows). Final Rust panel over `03757f77..4cf42aa6`.

H65 (cell). T1b's rule (2026-11-01): issues dedupe across jobs by class and location; the first finder owns the issue (`issue.job`), a later job that re-finds it emits an `issue` push (`Upsert::Merged`) but `scan.issues {job}` and `scan.status.issues` for that job show nothing; `Issue.jobs` membership lands on a later head. Until then the cell runs `step_t7_17` before `step_t7_16` on the fresh core (its job is the first finder), launches it with `speed thorough`, keeps `J` pinned to it; T7-16's jobs follow. TUI note: with `J` pinned to a later job the Issues tab is legitimately empty until `Issue.jobs` lands; the Jobs detail's `issues` count is the engine's. Run 3's `issue: 35` lines per job are now explained (re-finds of the first job's issues).

## Final Rust panel residuals (over `03757f77..4cf42aa6`)

H66 (Rust). A keyed `scan.status:<job>`/`scan.cancel:<job>` error with a code other than `not_found` has no clearing path once the job turns terminal or leaves the list (no same-tag success can come): in `JobsState::fold_list` (job dropped from `order`) and `fold_status` (job turned terminal) clear `jobs.error` and `last_error` when their tag names that job, mirroring G74. Test (`tests/scan_v2_errors.rs`): a `busy` on `scan.status:<job>`, then a `scan.list` without the job, leaves the Jobs banner `idle`. Pre-existing lifecycle; the out-of-range `browser.*`/`poc.get` raw `CallFailed` messages are a follow-up outside T7's scan items (recorded for the Review log).

H67 (Rust). `last_error` docs claim a toast reader that no longer exists (`scan/mod.rs` field and `set_error` docs, `ui/scan/mod.rs` `tab_error` doc, the test message in `scan_v2_errors.rs`): reword to "the view-wide record of the last `scan.*` failure, read by the tests only; the toast is built from the `ScanError` in `on_scan_failed`".

H68 (Rust). The tab-to-error-slot dispatch is written three times (`set_error`, `clear_error`, `tab_error`): `ScanState::error_slot(tab) -> &Option<ScanError>` and `error_slot_mut(tab)` with one exhaustive match (no `_` arm); `set_error`, `clear_error` and `tab_error` use them (Jobs keeps `legacy.or(..)`).

H69 (Rust). The H50 test proves two scenarios under one name with a shadowed `confirm`: split into `a_huge_prompt_is_bounded_once_at_fold` (the tabbed prompt, no render) and `a_prompt_wider_than_the_box_wraps_and_keeps_the_key_line_last` (the spaced prompt, the render assertions).

**Cell H62-H65 result (2026-11-01):** done in `85800f80` (+441/-163); `--selftest` 54 ok with four mutation checks. Ratified: `stop()` unblocks the 600 s read with `shutdown(SHUT_RDWR)` rather than `close()` (measured on a socketpair: `close()` waits behind the buffered reader's lock for the read's own timeout; the probe also reproduced run 4's instant `None` after one timeout); `idle_reads` counts only reads that waited 0.5 s; a `None` ends the thread with the reason recorded; `set_ring_field` generalises the Fields walk (`use_browser`, `speed`); T7-16 asserts the held editor carries the origin instead of typing it; T7-17 runs first with `speed thorough`.

## From the fifth live smoke run (`/tmp/claude/t7-live-smoke6`, 36 ok, 1 noted, 7 failed)

H70 (cell). `thorough` alone still finishes in about 2 s (278 probes): the sampled T7-16 job and its fresh cancel job also cycle `intensity` to `intrusive` (same ring walk, asserted on the Fields line), samples are taken every 0.5 s from the moment the row is on screen, and `x` goes right after the third sample; T7-17 keeps `standard` with `thorough` only.

H71 (cell). The tab markers are checked against the current footer literals (`ui/scan/mod.rs` key tables after G-B: the Issues list footer is `key_text(&[ISSUES_KEYS])`, the filter line `key_text(&[ISSUES_FILTER_KEYS])` = `S severity · C confidence · L lane · T status · J job`); fix any stale one and add a self-test row per marker painted from the Rust literal.

H72 (cell). A `StartResult` switches the Scan tab to Jobs (D7); `4` pressed before it lands is undone, which is why run 5's T7-17 saw the Jobs tab: after every launch, wait for the Jobs tab marker and the new row before pressing another tab key.

H73 (Rust). Enter on the Site map node whose row read `POST /login` opened the `GET /` flow in the inspector (run 5, `fail-7-t7-19.txt`: Inspector mode, `GET 200 OK http://127.0.0.1:61930/`, `1 / 125 rows`): the node under the cursor and the row under the cursor disagree, the G22 class (`group_nodes` permutes `nodes`, `node_lines`/`node_ranges` or the Enter arm read another order). Test first in `tests/scan_v2_sitemap.rs`: fold a two-host `scan.sitemap` reply whose reply order differs from group order, walk the Nodes cursor to the second row, press Enter, assert the opened flow id is that row's node's `flows[0]` (and the same for the Points pane's node); fix whatever the test exposes.

**Rust H66-H69, H73 result (2026-11-01):** H66 `cb2a836d` (clearing lives in `ScanState::fold_job_status`/`fold_job_list` wrappers since `JobsState` cannot reach `last_error`; `app.rs` call sites switched; a job never in `order` has not "left the list", so the D13 cadence pin holds; a list that reports the job terminal clears too), H68 `3086cfda`, H67 `ffdc6bd5`, H69 `baadb193`, H73 `b2165007` (tests only: the two-host group-order Enter tests pass on the unchanged reducer; the live mismatch was the cell's `g` race, H74). Crate gate green (540 tests). The Rust side of T7 is final at `b2165007` pending Task 16.

H74 (cell). After `g` in T7-19 the cell read the stale `>` row before Home was processed: poll until the cursor row differs from the walk's last row (or equals the group-first node) before reading `under`; the same discipline wherever a key moves the cursor and the next read depends on it.

**Cell H70-H72 result (2026-11-01):** done in `461ad9e3` (+359/-63); `--selftest` 63 ok with four mutation checks. H71 found no stale marker; the self-test now paints footers from Python mirrors of the five Rust key tables and reads the tables back from the Rust source (a renamed key fails the self-test without a core). Ratified: the landing wait lives in `launch()` with the outcome in `ctx.landed`; the Rust read-back row stays (the cell lives in-repo); self-test vocabulary values corrected to the live literals. H74 follows in the same coder's resumed run.

**Cell H74 result (2026-11-01):** done in `0fa083a0`; `--selftest` 64 ok; `press_home` waits for the cursor row to equal the walk's first recorded row (taken from the cell's own first frame, so no re-implementation of the group order); the pre-walk `g` gets a bounded change-wait. Noticed: `cursor_to` reads after fixed sleeps (a candidate if a later run overshoots a row). The cell is complete at `0fa083a0`; live run 6.

## From the sixth live smoke run (`/tmp/claude/t7-live-smoke7`, 24 ok, 3 failed; T7-17's UI-2 chain passed live through `f`)

H75 (Rust, after the Task 16 tester lands). After `f` the Issues list refetched (a status change triggers `scan.issues`) and the cursor kept its index while the rows moved, so `u` and `P` acted on another issue (`fail-1-t7-17.txt`: cursor on `Cookie without Secure or HttpOnly`, the marked `Open redirect` row elsewhere reading `false_positive`). D11 ruling: the Issues list cursor follows the issue id across folds, re-found by id like the Jobs and Site map cursors (G22); when the id is gone the index clamps as today. Test (`tests/scan_v2_issues.rs`): land on row 3, fold a refetched page where that issue sits at row 1, assert `cursor_issue().id` unchanged and `detail` still that issue's.

H76 (cell). After `f` (and after `u`) assert the cursor row's name cell is still the marked issue's before the next key (a TUI behaviour check, H75); the failure detail names the row the cursor landed on.

H77 (cell). An `intrusive` launch raises the engine's `needs_confirmation` overlay (`Confirm over the wire: scan launch`, "may disrupt the target"): `launch()` detects the overlay title after `s`/`m`, asserts it as a check ("the engine asked to confirm the intrusive launch"), presses `y`, then waits for the landing as today; `n` is never pressed there. This exercises UI-1's confirm on an HTTP job as well as T7-18's.

**Cell H76-H77 result (2026-11-01):** done in `783b4af8`; `--selftest` 67 ok with mutation checks. Ratified: the confirm check is recorded only when the overlay appears (an outright launch records nothing); the post-`f`/`u` cursor check is a 2 s hold under watch; the overlay screen is a sample, not a named file. Cell complete at `783b4af8` pending H75 on the Rust side.

**Task 16 result (2026-11-01):** PASS in `8e63ab29` (+659/-27, tests only): nine tests added (keyed-reply discipline for `scan.cancel`, `scan.issue.update`, `StartResult`; a non-D3 verb's error; banner hue; D13 refreshing-then-empty for every tab; Jobs state hue; the D11 help literals; malformed job lines ignored), eight strengthened to literals; crate gate green (549 tests). Noticed (spec-letter Minor, accepted): while a read is in flight over an empty pane the banner reads `refreshing <verb>...` and the pane shows its empty text at the same time.

**Rust H75 result (2026-11-01):** done in `dc1ad52b` (`fold_result` re-finds the cursor by id, clamp as the fallback; two tests with a mutation check); crate gate green (551 tests). The Rust tip before the integration merge is `dc1ad52b`; the cell's is `783b4af8`.

## From the seventh live smoke run (`/tmp/claude/t7-live-smoke8`, 52 ok, 3 failed; T7-16 cancel and pushes, T7-17 through `u`, T7-18 and T7-19 all passed live)

H78 (cell). `P` on an issue whose `poc_ref` the Findings panel does not list toasts `... is not in the Findings list` with the path: that is the spec's fallback (coordinator note 3) and passes as the check "`P` reported the PoC path the Findings panel does not list"; the strong branch (Findings opens on the PoC) passes as today. To make the strong branch run on the self-booted core, `CoreConfig(.., poc_dir=<work>/findings/scan/pocs)` (the field exists in `aitm_e2e/config.py`), so the Findings panel lists the scan PoCs; the plan's `CoreConfig` line gains it.

H79 (cell). The confirm overlay wraps the prompt (`... and may disrupt the` / `target. ...` on two rows), so the H77 text check must match across the box's line wrap: join the overlay's inner rows with single spaces before searching `may disrupt the target`; the T7-18 overlay check gets the same reader.

H80 (cell). Three samples at 0.5 s all read `running/audit` (the crawl phase passed before the row appeared): keep sampling at 0.5 s until the state/phase text changes or `SAMPLES_MAX = 8` is reached, and let the post-`x` `cancelled` row be the last sample for the "changed at least once" assertion (it is bracketed by status reads like the others); the three-sample minimum and the bracket assertions are unchanged.

**Cell H78-H80 result (2026-11-01):** done in `70e558a5` (+312/-55); `--selftest` 71 ok. Ratified: the post-`x` `cancelled` row is a sample only for the sampled job's own row; the fallback `P` check is recorded only when the toast is on screen; the toast's 80-cell prefix is the match limit. Gap relayed to the coordinator: `poc.list` reads only `poc.dir`'s top level while the engine writes PoCs into per-run subdirectories, so the strong `P` branch is unreachable on every UI until the core changes; the fallback toast is the passing branch. The cell is complete at `70e558a5`.

## From the eighth live smoke run (`/tmp/claude/t7-live-smoke9`, 57 ok, 1 noted, 3 failed)

The three failures share one cause: the target answers an intrusive, thorough scan in about two seconds, so the "while running" observations race the job under load (run 7 passed the sampling, run 8 the rest; every check has passed live in some run). No cell-side timing trick is reliable; the lever is a slower target. Asked the coordinator for a ruling: (a) T10 adds `aitm-testtarget-serve --latency-ms N` and `Target(mode, latency_ms=)`; the cell boots the target with 40 ms (H81, cell, once the option exists); or (b) accept the three as timing-sensitive and record per-check the run where it passed. Ruling (coordinator, 2026-11-01): (a). H81 (cell, once T10's `aitm-testtarget-serve --latency-ms N` and `Target(mode, latency_ms=None)` land): `self_boot_config`'s target boots with `latency_ms=40` so an intrusive scan takes ten seconds or more and every "while running" observation is deterministic; this is the fix for the whole "sampling races a fast job" class. Until then: merge, gate, PR with (b) stated honestly (which run proved which check and why the three race a two-second job), then the one definitive run before "ready".

**Cell H81 result (2026-11-01):** done in `b093da9b`; `--selftest` 75 ok. `slow_target_class()` picks `aitm_e2e.scan.ScanTarget` only when its signature takes `latency_ms`; `boot_seeded_target` boots `ScanTarget("vulnerable", tls=False, control=False, latency_ms=40)` or falls back to `Target("vulnerable")` with a `note` that the timing checks may race a fast job; the summary head names the latency. Ratified: plain HTTP, no TLS or control listener; the `ok` record is unconditional (a strengthening would time one GET, left for a ruling). The lever branch runs only on a tree carrying T10's harness (`aitm_e2e/scan.py` and `__init__.py`), so the latency runs check T10's `tests/e2e/aitm_e2e` out into the smoke worktree until #256 lands.

## From the latency run (`/tmp/claude/t7-live-smoke10`, 55 ok, 1 noted, 6 failed; target at 40 ms)

T7-17's "while running" observation passed with the latency; the sampled intrusive job still finished within one sample because the engine probes concurrently (`status-pairs.json`: 228 to 278 probes inside one 0.5 s window at 40 ms per response, about 100 probes/s, so about four probes in flight). H82 (cell): `TARGET_LATENCY_MS = 300` (about 13 probes/s, an intrusive scan of about 20 s and a thorough one of about 14 s), the self-test literal follows the constant; the 600 s budget holds. The fresh cancel job's landing wait (`landed False`) and the `x` on a finished job are the same two-second job; H82 covers them.

**Cell H82 result (2026-11-01):** done in `a84b8d63`; `--selftest` 76 ok; every latency literal derives from `TARGET_LATENCY_MS = 300`. The cell is complete at `a84b8d63`.

## Task 17 integration plan (after H75 and the final #232 SHA)

Main at `1bfc5621` (#244) removed the TUI's fixture and snapshot modes: `src/fixture.rs`, `src/snapshot.rs`, `fixtures/bus-fixture.json` and the tests `fix_pass2.rs`, `l4_surface.rs`, `scan_surface.rs`, `tester_bus_task.rs`, `tester_components.rs`, `tester_pass2.rs`, `tester_shell.rs` are gone; `tests/common/mod.rs` renders through `ui::render` into a `Buffer` under the same names this branch uses (`draw`, `text_of`, `line_with`, `tools`, `connect`, `toast`); new `tests/bus_task.rs`, `robustness.rs`, `perf.rs`, `cli_usage.rs`; `CORE_TOOLS` 95 / `EXPECTED_TOOLS` 92 with no fixture pin. The merge Coder: merge `origin/main` at the SHA that contains #232 (engine, model with `l4.fields`, `Issue.jobs`, `location.l4`, `scan.sitemap` `job` field); resolve `app.rs`, `lib.rs`, `ui/mod.rs`, `ui/inspector.rs`, `ui/flows.rs`, `main.rs`, `tests/common/mod.rs` (keep main's render helpers, add this branch's `fixture`, `tagged`, `reply`, `failed`, `opened_minimal`, `screen`, `opened_v2`, `legacy_app` rewritten over `connect` without the fixture module); accept the seven deletions and re-home what T7 needs live-only: the T7-15 pins (`prune_keeps_the_reserved_confirm_key`, `a_tagged_call_answers_with_the_same_tag`, the subscribe-once handshake) into `tests/bus_task.rs`, the T7-5 L4 confirm identifiers into `scan_v2_confirm.rs`, the D12 legacy one-shot tests from `scan_surface.rs` into a new `scan_v2_legacy.rs` built on `legacy_app`, the H47 toast bound test into `scan_v2_errors.rs`, the H19 wording pins where their strings still exist; drop every test that only existed to pin fixture or snapshot behaviour; then H60 (`location.l4` line), H61 (`job` on the Site map head), and the contract pins at main's counts; crate gate in the sandbox, workspace gate in the Terminal. Main at `621cbcc0` (v0.5.10) also carries #248 (TUI half of CA trust: `app.rs` +358 with `ca_trust_word()`, the scope user and a calm cancel; `model.rs` +116; `bars.rs` pill span `· {listen}{ca}{state}`; new `tests/ca_pill.rs`; `robustness.rs` +16): this branch's `app.rs`/`model.rs`/`bars.rs` edits sit in other regions (Scan arms, H19 wording, hints, prompt labels, saturating sums), so take both sides and re-run `rustfmt`; keep main's `tests/ca_pill.rs` and `robustness.rs` as they are.

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
