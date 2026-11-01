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

## Task 9 security panel

G15. `bound_point` leaves `traits` unbounded and `point_line` tokenises every trait per frame (`crates/aitm-tui/src/scan/sitemap.rs`): `dedup` and `truncate(POINT_TRAITS_MAX = 8)` at fold, and precompute each point's display line at fold (a `PointLine` twin like `NodeLine`) so the view only copies. Test: a point with 10^6 `url` traits folds to 8 and renders at 200x50.

G16. `next_cursor` is echoed back to the core unbounded (`crates/aitm-tui/src/scan/sitemap.rs` `fold_result`): if `next_cursor.len() > CURSOR_MAX = 1024` set it to `None` and record `ScanError::uncoded("scan.sitemap", "next_cursor exceeds 1024 bytes")`. Test: a 1 MiB cursor yields `next_cursor == None` and `n` sends nothing.

G17. No total cap across appended pages; quadratic fold (`crates/aitm-tui/src/scan/sitemap.rs`): `SITEMAP_TOTAL_LIMIT = 8192` nodes and points after which the fold drops `next_cursor` and the summary says `limit reached`; `order_points`/`node_points` index node ids in a `HashMap<&str, usize>` so a fold is linear. Test: 17 appended full pages leave 8192 nodes and `next_cursor == None`.

G18. `authority_parts` accepts `@`, `/`, `?`, `#` and whitespace in a host (`crates/aitm-tui/src/scan/profiles.rs`): refuse them with `ORIGIN_HOST_ERROR`; add `http://a@b` and `http://a b` to the refusal tests.

G19. On a bus offering both `scan.start` and `scan.discover` the legacy fold overwrites the v2 Site map lists (`crates/aitm-tui/src/app.rs` `scan.discover` arm, `crates/aitm-tui/src/scan/sitemap.rs`): call `show_legacy` only when `MapSource::from(scan_offer()) == Legacy`; under V2 the legacy result stays in `legacy.*` and the Site map shows v2 content. Test: a V2 app with a folded `scan.sitemap` page then a `scan.discover` reply keeps its nodes.

## Task 9 spec panel

G20 (priority). **Orphan points are dropped at fold** (`crates/aitm-tui/src/scan/sitemap.rs` `order_points`/`fold_result`): keep every point; a point whose `site_node` is `None` or names no current node sorts last (key `nodes.len()`) and is not drawn; re-run the ordering after every append so a point re-attaches when its node arrives on a later page. Update the unit test that pinned the drop. Test (`tests/scan_v2_sitemap.rs`): page 1 carries a point for `node-2` without the node; `n` appends page 2 with `node-2`; `node_points(1).len() == 1` and the point renders under that node.

G21. `authority_parts` becomes `pub(crate)` (`crates/aitm-tui/src/scan/profiles.rs`); add the one-line test that a scope entry `api.test:8443` yields `https://api.test:8443`.

## Task 9 quality panel

G22 (priority). **The Nodes cursor walks `nodes` in wire order while the pane draws `lines` in host-grouped order** (`crates/aitm-tui/src/scan/sitemap.rs`, `crates/aitm-tui/src/scan/mod.rs` `cursor_mut`, `crates/aitm-tui/src/ui/scan/sitemap.rs`): sort `nodes` into group order at fold (stable, by first-appearance `host_key`) so `lines[k].node == k` and the twin is index-for-index like Issues `rows`; drop `NodeLine.node`; on an appending fold remember the selected node's `id` and re-find it. Unit test: the interleaved four-node page, cursor 0, `Down` selects `c` (the next row on screen); with an appended page the cursor stays on the same id.

G23. Third serde-token reader; vocabulary tokens live in `issues.rs` (`crates/aitm-tui/src/scan/{issues,jobs,sitemap}.rs`, new `crates/aitm-tui/src/scan/tokens.rs`): one `scan::tokens` module with `severity_token`, `confidence_token`, `lane_token`, `status_token`, `severity_header`, `SEVERITY_ORDER`, `severity_counts` and one `pub(crate) fn wire_token<T: Serialize>(v: &T) -> String`; delete `kind_token`, `serde_name` and `profiles::token` (Task 11's view reads `profiles::token` for the tri-state glyph summary; both call sites move to `wire_token`).

G24. `point_cursor` indexes the whole list but means "within the selected node" (`crates/aitm-tui/src/scan/sitemap.rs`, `scan/mod.rs`, `ui/scan/sitemap.rs`, `app.rs`): `point_offset: usize` within the node; `cursor_mut` `(V2, Points)` returns `(&mut point_offset, node_points(node_cursor).len())`; a Nodes walk and a fold reset/clamp it; `SitemapState::selected_point() -> Option<&InsertionPoint>` used by `sitemap_selected_flow` and the view; delete `settle_point_cursor`, the sentinel and the `checked_sub`.

G25. `appending` resets on failure are dead; doc incomplete (`crates/aitm-tui/src/app.rs`, `scan/sitemap.rs`): delete both resets; doc "the mode of the last `scan.sitemap` that left; overwritten by every send, taken by the fold".

G26. Stringly-typed origin errors (`crates/aitm-tui/src/scan/profiles.rs`, callers in `app.rs`): `pub enum OriginError { Host, Port, Scheme }` with `Display` carrying today's wording; `typed_origin -> Result<String, OriginError>`; tests assert the variant.

G27. `legacy_nodes` re-implements helpers and round-trips a `FlowRef` through JSON (`crates/aitm-tui/src/scan/{sitemap,profiles}.rs`): `pub(super) fn authority_of` in `profiles.rs`; `fn default_port(scheme) -> u16` used by `host_key` and `legacy_nodes`; `fn flow_ref(id) -> Option<FlowRef>` via `FlowId::from_str` used by both legacy readers.

G28. Tab-entry fetch pairs and since-last-fetch arithmetic duplicated (`crates/aitm-tui/src/app.rs`, `scan/mod.rs`, `scan/sitemap.rs`): `fn enter_tab_reads(&mut self, tab, out)` called from `scan_tab` and `OpenScan`; one `pub(crate) fn due(last: Option<u64>, now: u64, every: u64) -> bool` in `scan/mod.rs`; `SitemapState.fetched_at_tick: Option<u64>`.

G29. View hygiene (`crates/aitm-tui/src/ui/scan/sitemap.rs`): a `Pane<'a> { cursor, focused, head, empty }` argument instead of two `too_many_arguments` allows; inline the redundant `Style` binding; build `row` after the `Head::Hint` early return.

G30. Test hygiene (`tests/scan_v2_sitemap.rs`, `scan/sitemap.rs` tests): assert the trimmed row literals (`GET  /account/{id}  flows 1 · pts 2 · ✓`, the fixed-width point rows); `assert_eq!(points.len(), SITEMAP_PAGE_LIMIT)`; name `801` as `4 * SITEMAP_VALUE_MAX + 1` (export the const); drop the dead modulo.

G31. `J` with no Jobs-cursor job refetches an unchanged query (`crates/aitm-tui/src/scan/sitemap.rs`, `app.rs`): `SitemapQuery::toggle_job(&mut self, cursor: Option<JobId>) -> bool`; refetch only when it changed. Typed and bare origins normalise port 443 differently (`scan/profiles.rs`): one `origin(scheme, host, port)` that drops the scheme's default port in both paths; test `typed_origin("https://h:443") == "https://h"`.

## Task 10 coder note

G32. `ScanState::cursor_mut`'s Checks-pane arm is dead (`crates/aitm-tui/src/scan/mod.rs`): `navigate` handles the tree itself; drop the arm (return `None` for the Checks pane) and say so in the doc.

## Task 10 quality panel

G33. `l4_target_text` cannot be read back for an IPv6 target (`crates/aitm-tui/src/scan/profiles.rs`): bracket an ip that parses as `Ipv6Addr`; round-trip test for every accepted case of `l4_target_prompt_parses`.

G34. Three identical prompt-submit arms and a fourth with a different retry rule (`crates/aitm-tui/src/app.rs`): `submit_scan_origin` returns `Result<(), String>` like its siblings and all four route through one `submit_retrying(result)` helper; the out-of-scope refusal stays close-on-refusal with a comment, host/port/scheme refusals keep the prompt open.

G35. `cycle` silently returns `false` for a field `kind()` says cycles (`crates/aitm-tui/src/scan/profiles.rs`): unit test iterating `EDITOR_FIELDS` and asserting `cycle(f)` is true for every `Cycle | Toggle` field.

G36. The check tree is rebuilt with three `String`s per node on every call, and Task 11's view rebuilds it per frame for the Checks pane and again uncollapsed for the Fields summary line (`crates/aitm-tui/src/scan/profiles.rs`, `app.rs`): cache `tree: Vec<TreeNode>` on `ProfileEditor`, rebuilt only in `fold_checks` and on collapse/expand; `TreeNode { depth, selector, kind: Lane | Class | Check }` with label and id derived; `cursor_node() -> Option<&TreeNode>`; one `clamp_tree_cursor` helper.

G37. The origin picker is rebuilt on every `Flows` sweep and can move the highlight (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): refresh only when the `Flows` fold changed the row set and an editor is open; `refresh_origins` re-finds the previously highlighted origin by value.

G38. `ConfirmCall` re-derives the tag from its own JSON (`crates/aitm-tui/src/app.rs`): `ConfirmCall.tag: Option<String>` set by `scan_delete`; `answer_confirm` routes through `scan_call` when set; delete `scan_confirm_tag`.

G39. Reducer-on-state logic in `app.rs` that belongs on the model (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): `ProfileEditor::enter_node`, `fold_node`, `saved_as`; `ProfilesState::is_builtin`, `delete_target`, `on_deleted`; the three builtin checks go through `is_builtin`.

G40. Missing-verb block copied beside `scan_call` (`crates/aitm-tui/src/app.rs`): `fn scan_verb_or_toast(&mut self, name) -> bool` used by `scan_call`, `scan_save`, `scan_delete`.

G41. Bounds constants split across two files; two inline `32`s (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): move `SAVED_NAME_MAX`/`SAVED_PATH_MAX` to `profiles.rs` (reuse `VALUE_MAX` for the path); `CHECK_LISTS_MAX = 32` with a doc line.

G42. A profile name typed into `w`'s prompt bypasses `set_text`'s trimming (`crates/aitm-tui/src/app.rs`): route through `editor.set_text(EditorField::Name, text)` and check `is_builtin_name` on the trimmed value; test the padded builtin name.

G43. Stringly-typed `set_text`/`parse_l4_target` errors (`crates/aitm-tui/src/scan/profiles.rs`): `FieldError { NotANumber(EditorField), NotText(EditorField) }`, `L4TargetError`, with `Display` carrying today's wording (rides with G26).

G44. Test hygiene in `tests/scan_v2_profiles.rs`: literals for the session line, the builtin-name toasts; `assert_eq!` for the exact `CHECKS_MAX`/`PROFILES_MAX`/`CHECKS_MAX + 2` counts; import `SELECTOR_MAX`; bound the description with `4 * VALUE_MAX`.

## Task 10 security panel

G45. **Important, priority with G20/G22.** The `scan.profile.get` reply is adopted into the editor unbounded (`crates/aitm-tui/src/app.rs` `scan.profile.get` arm; `crates/aitm-tui/src/scan/profiles.rs`): `pub fn fold_profile(tag: &str, profile: ScanProfile) -> Result<ScanProfile, ScanError>` applied before `open_editor`. The draft is echoed back on `w`/`s`, so the fold refuses rather than cuts: an uncoded `ScanError` with detail `profile exceeds bounds` when `target.origins.len() > ORIGINS_MAX (64)` or any origin is empty or over 2048 bytes, `target.l4.len() > 64`, `checks.include`/`exclude` longer than `CHECKS_MAX` or any selector fails `usable_selector`, `audit.ignore.len() > 64`, `l4.seeds.len() > 64` or any seed string over 1 MiB; `lanes` sorted and deduped. On refusal the editor stays closed, the error is recorded under the tag, and no `scan.session.preview` leaves. Test: a `scan.profile.get:standard` reply with 100_000 origins leaves `editor.is_none()`, `last_error.detail == "profile exceeds bounds"`, and no `scan.session.preview` request.

G46. `ProfileSaveResult.saved` is adopted as `loaded_from` unchecked (`crates/aitm-tui/src/app.rs` `scan.profile.save` arm): accept only when `usable_selector(&saved.saved) && saved.saved == editor.draft.name`; otherwise keep `loaded_from` and record an uncoded error `save reply named a different profile`. The delete confirm description truncates the name to `SAVED_NAME_MAX`. Test: a `saved: "other"` reply leaves `loaded_from` unchanged and the error set.

G47. Control characters pass `usable_selector` (`crates/aitm-tui/src/scan/profiles.rs`): also require `!s.chars().any(char::is_control)`; a list row or check failing it is dropped. Test: a profile named `"a\x1b[2Jb"` is absent from `profiles.list`.

G48. Canary path shown as received (`crates/aitm-tui/src/scan/profiles.rs` `fold_preview`): cut `Canary::Flow.path` at the first `?` or `#` before `cut`. Test: `path: "/account?token=abc"` renders as `/account`.

G49. Typed profile names are file-ish keys with no shape check (`crates/aitm-tui/src/app.rs` `submit_scan_profile_name`, `crates/aitm-tui/src/scan/profiles.rs` `set_text(Name)`, `crates/aitm-tui/src/ui/bars.rs` prompt label): mirror the engine's rule (T1b, relayed 2026-11-01): a saved name must match `^[a-z0-9][a-z0-9._-]{0,63}$`, lowercase only, builtin names refused. One `pub fn valid_profile_name(s: &str) -> bool` in `profiles.rs` (no regex crate: first char ascii lowercase alphanumeric, the rest ascii lowercase alphanumeric or `.`/`_`/`-`, 1..=64 bytes), used by both the `w` prompt and `set_text(Name)`; a refusal keeps the prompt open with the toast `profile name: a-z 0-9 . _ - only, lowercase, up to 64` and the `profile name:` prompt label reads `a-z 0-9 . _ - lowercase · ⏎ save as`. Never lowercase on the operator's behalf (the engine rejects uppercase outright, so `Standard` is refused, not saved as `standard`). The engine's `invalid_profile` keeps the D9 wording with the engine's detail appended, as today. Test: `../../x`, `/abs`, `.hidden`, `Standard`, a 65-byte name all refused with the prompt kept open; `team-x.v2` accepted.

## Task 10 spec panel

G50. `request_session_preview` returns early when `previews` already holds the origin (`crates/aitm-tui/src/app.rs`): drop the `contains_key` early return; the in-flight tag dedupe stops duplicates, and re-opening a profile re-reads the session (D11 as amended). Test (`tests/scan_v2_profiles.rs`): open `standard`, fold the preview, Esc, `Enter` again: a second `scan.session.preview:<origin>` request leaves.

## Task 11 security panel

G51. **Important, priority with G20/G22/G45.** `scan.profile.list` lane vectors are unbounded at fold and re-joined per row per frame (`crates/aitm-tui/src/scan/profiles.rs` `fold_list`; `crates/aitm-tui/src/ui/scan/profiles.rs` `Columns::measure`, `lanes_text`, `row_line`): in `fold_list`, `p.summary.lanes.sort(); p.summary.lanes.dedup();` per row (at most the four `LaneKind`s), and precompute each row's lanes text and the column measure at fold (a `ProfileRow { summary, lanes_text }` or a `lanes_text: String` beside the summary) so the view only copies. Test: a list reply with one row carrying 100_000 `http` lanes folds to `lanes == [Http]` and renders `http` once at 200x50; a row with `[ws, http, http]` renders `http ws`.

G52. `field_lines` clones the whole editor every frame to drive `field_text()` (`crates/aitm-tui/src/ui/scan/profiles.rs`, `crates/aitm-tui/src/scan/profiles.rs`): `ProfileEditor::text_of(&self, field: EditorField) -> String` holds today's match, `field_text()` becomes `self.text_of(self.field())`, the view calls `text_of(field)` and the clone goes. Unit test: for every `EDITOR_FIELDS` entry, `text_of(f)` equals the old probe's `field_text()`.

G53. Addendum to G45: `fold_profile` also refuses when any `target.l4[].ip` fails to parse as `IpAddr` (bracket-stripped, as `parse_l4_target` does) or `grammar` is `Some` and over `SELECTOR_MAX` bytes or carries a control character. Test: a `scan.profile.get:standard` reply with `l4: [{ip: "x".repeat(1 MiB), port: 7000}]` leaves `editor.is_none()`.

G54. Addendum to G36: the cached `TreeNode` carries its `TriState`, recomputed on toggle and on `fold_checks`, so `check_summary` and `tree_line` do no per-node scan of `include`/`exclude` per frame; `tri_state` stays for the toggle path. Test rides with G36's.

## Task 11 quality panel

G52 is raised to **priority** (the quality panel rated the per-frame editor clone Important: the copy is proportional to wire data). Also delete the `position(..).unwrap_or_default()` field lookup in `field_lines` (it printed the name for any field missing from `EDITOR_FIELDS`).

G55. Two private `wrap` functions in `ui/scan/` (`crates/aitm-tui/src/ui/scan/profiles.rs` `wrap`/`clauses`; `crates/aitm-tui/src/ui/scan/confirm.rs` `wrap` measuring `chars().count()`): move the clause-aware, width-measured `wrap` and `clauses` with their tests to `ui/scan/mod.rs` beside `hint`/`labelled`; confirm calls it with `usize::MAX` rows and keeps its `vec![""]` empty-text contract at the call site. Test: confirm's existing tests plus one wide-glyph prompt wrapped by width, not chars.

G56. The scroll-and-highlight row loop is written six times across `ui/scan/` (Profiles `list`/`origins`/`checks`, Jobs `list`, Sitemap `nodes`/`points`, Issues `list`): one `pub fn rows(buf, theme, area, total, cursor, focused, line: impl FnMut(usize) -> Line<'static>)` in `ui/scan/mod.rs` with a unit test for the scroll arithmetic (`top = cursor.saturating_sub(h - 1)`, enumerate/skip/take, selection on the cursor row while focused); rides with G29.

G57. Addendum to G36: `check_summary` builds a second uncollapsed tree per frame with `&Default::default()` hiding the `BTreeSet<String>` type; the cached tree carries every node with a `hidden` flag (or a lanes-and-classes list) so the pane and the summary read one structure; any surviving direct call writes `&BTreeSet::new()`; the doc quotes the real glyphs (`◇`, not `○`).

G58. The wildcard rule is decided in two places (`crates/aitm-tui/src/ui/scan/profiles.rs` `starts_with("*.")`; `crates/aitm-tui/src/scan/profiles.rs` `origin_choices`): `pub(crate) fn is_wildcard(entry: &str) -> bool` in `scan/profiles.rs`, used by both, so the view greys exactly what the picker skipped. Test: an entry `*` is greyed, not offered.

G59. View hygiene (`crates/aitm-tui/src/ui/scan/profiles.rs`): bind `area.width` directly where `w + 1` is the only use; one `NO_PROFILES` const for the two `"no profiles yet"` literals with a one-line why on the editor-open branch; move `EDITING_MARK` beside `BUILTIN_MARK` in `scan::profiles`; drop the duplicate `BOLD` on `name_style` or in `highlight`; one `scan::GAP`/`GAP_TEXT` pair shared with Jobs (rides with G51's precomputed `ProfileRow`); the module doc keeps the ownership and D13 rules and points at the functions instead of narrating every pane.

G60. Addendum to G44, Task 11's tests (`crates/aitm-tui/tests/scan_v2_profiles.rs`): one trimmed row literal per pane (the `standard` list row, the lanes line, the budget line, one tree row, one picker row) beside the fragment asserts; `line_with(..).unwrap_or_default()` becomes `unwrap_or_else(|| panic!(..))` naming the missing row.

## Task 12 quality panel

G61. **Important.** The D8 scope-refusal rule is copied at four sites with two wordings (`crates/aitm-tui/src/app.rs` `scan_launch_v2` origins loop, `scan_start_typed`, legacy `scan_launch` (G14's em-dash copy), `submit_scan_origin`): one `pub fn out_of_scope(scope: &[String], raw: &str) -> Option<String>` in `scan/profiles.rs` beside `typed_origin` (returns the refusal toast text `Out of scope: add \`<host>\` to scope to scan it` for an empty or uncovered host, `None` when covered), and one `App::scope_host(&mut self, raw) -> Option<String>` that toasts it; the four sites call it. The origins loop becomes `find_map` over `&draft.target.origins` with no `Vec<String>` clone (compute the failing host, then toast). Pairs with G14. Test: the four paths all produce the one literal.

G62. The legacy "already running, else `scan_launch`" guard is at four sites (`app.rs` `r`, `:scan` legacy, `s`/`m` legacy, `scan.map` fallback): move the `running` check and its toast into `scan_launch` and delete the four guards.

G63. `launch_args` and the toast's profile name decide the same precedence twice (`app.rs` `scan_launch_v2`; `scan/launch.rs` `launch_args`): `launch_args` returns `Option<Launch { args: Value, profile_name: Option<String> }>` so the request and the toast read one rule. Rides with G39.

G64. `fold_start_result`'s six Jobs writes belong on `JobsState` (`app.rs`): `JobsState::land_started(&mut self, status: JobStatus)` holding `started_here.insert`, `fold_status`, move-to-front, `cursor = 0`, `pane = List`, `detail_scroll = 0`, with a unit test for the already-listed case; `fold_start_result` keeps the D6 bounds and the toasts. Rides with G39.

G65. Jobs and Profiles draw the blocked reason with two layouts and two copies of the footer arithmetic (`ui/scan/jobs.rs`, `ui/scan/profiles.rs`): after G55, one `pub fn blocked_footer(theme, area, blocked: Option<&str>, footer: &str, buf) -> Rect` in `ui/scan/mod.rs` drawing the wrapped reason over the hint and returning the body rect; both `detail` functions call it (the Jobs copy stops cutting the actionable tail at 90 columns). The reason passed is `launch.blocked.or(scan.refused_launch().map(wording))` on both tabs (Task 13 ruling), so Jobs draws a refused launch like Profiles. Test: the D7 fragments whole at 90x40 on the Jobs tab too.

G66. `l4_gate` decides IPv6 by `contains(':')` (`scan/launch.rs`): `match first.ip.parse::<IpAddr>() { Ok(IpAddr::V6(_)) => 128, _ => 32 }` with a comment that an unparseable ip still yields a suggestion because G53 refuses it at fold.

G67. `wire_confirm_from = Mode::Scan` written at send time with no reader before the overlay arm overwrites it; the scan overlay-opening arm copies the `l4.*` one (`app.rs`): delete the dead write; `fn open_wire_confirm(&mut self, confirm: WireConfirm, from: Mode)` used by both arms; when `open_wire_confirm` replaces a confirm already on screen it toasts `<call> confirmation dropped` and, for a `scan.*` call, clears `launch.pending` (mirroring the Disconnected arm); `answer_wire_confirm(true)` clears `pending` when `scan_call` returns `false` (Task 12 security panel). Test: a scan confirm on screen, then an `l4.inject` `needs_confirmation` reply: `pending == None` and the toast; the scan arm's `map_or((name, Null))` fallback becomes `let Some(p) = pending else { set_error(uncoded(tag, "reply with no pending launch")); return }`.

G68. Stringly-typed launch verb and a stale `PendingLaunch` doc (`app.rs`, `scan/launch.rs`, `ui/scan/confirm.rs`): `pub enum LaunchVerb { Start, Map }` with `as_str()`/`Display`; `PendingLaunch.call: LaunchVerb`; `on_scan_failed` tests `pending.as_ref().is_some_and(|p| p.call.as_str() == tag)`; the doc drops `scan.discover`; `WireConfirm::is_scan()` (or `pub(crate) Family::of`) used by the reducer and the view instead of `starts_with("scan.")`.

G69. Test assertions in `tests/scan_v2_launch.rs`: delete the vacuous `contains("P")`; the clamped toast asserted as the full literal `(Level::Warn, "clamped: budget.probes 50000 -> 20000")`; the `:scan` success half uses `launch_requests(&reqs)` like the second half.

G70. Addendum to G41: `CLAMPED_MAX`/`CLAMPED_FIELD_MAX` move with `SAVED_NAME_MAX`/`SAVED_PATH_MAX` to the model with one doc line each.

## Task 12 spec panel

G71. `scan.map` is held by the UI-3 L4 gate (`crates/aitm-tui/src/app.rs` `scan_launch_v2`): the `blocked.is_some()` return applies to `scan.start` only; `scan.map` keeps the in-flight and origin-scope checks (D7 as amended: the engine forces `lanes: [http]` for a map). Test (`tests/scan_v2_launch.rs`): the L4-blocked draft with an in-scope origin gives no request on `s` and one `scan.map` on `m`.

## Task 12 security panel

G72. `StartResult.lanes.run` is joined into the start toast unbounded (`crates/aitm-tui/src/app.rs` `fold_start_result`): collect `run` into a `BTreeSet<LaneKind>` (at most the four kinds, declaration order) before joining, and `truncate` the whole start toast to `SAVED_PATH_MAX` cells. Test: a `scan.start` reply with 100_000 `http` run lanes toasts `scan-1a2b3c4d started: standard (http)`.

G73. A list-row launch of a stored profile with an L4 lane bypasses the UI-3 client gate (`crates/aitm-tui/src/app.rs` `recompute_launch_gate`, `scan_launch_v2`): with no editor open, `blocked` is computed from the Profiles cursor row's `lanes` (known from `scan.profile.list`): the first D7 text when `l4.scope.list` is absent, else `L4 launch disabled: open the profile (⏎) to check its L4 target and scope` (D7 as amended; the row carries no targets to check); recomputed when the Profiles cursor moves and when the editor closes. `s` stays inert while `blocked` is `Some`; `m` is not held (G71). Test (`tests/scan_v2_launch.rs`): no editor, cursor on a fixture row with an L4 lane, no `l4.scope.list`: the Profiles footer shows `GATE_NO_LAYER` and `s` sends nothing; with the layer present the footer names the editor; cursor on `standard`: `blocked == None` and `s` sends `{profile_name: "standard"}`.

## Task 13 coder report

G74. The `not_found` self-heal leaves its error in the Jobs banner forever (`crates/aitm-tui/src/app.rs` `on_scan_failed`, `scan.list` arm): remember the dropped job's error tag (`scan.status:<job>` or `scan.cancel:<job>`) in `ScanState.heal_pending: Option<String>` when the self-heal requests `scan.list`; on that `scan.list` success call `clear_error(&tag)` and clear the field (D13 as amended). Test (`tests/scan_v2_errors.rs`): after `not_found` on `scan.status:scan-1a2b3c4d`, folding `scan.list.json` leaves `last_error == None` and the Jobs banner without the wording.

## Task 13 spec panel

G75. `not_found` wording and the cancel branch (`crates/aitm-tui/src/scan/mod.rs` `code_wording`/`wording`; `tests/scan_v2_errors.rs`): the D9 `not_found` text keeps "; the list is being refreshed" only when the error's tag is a keyed `scan.status:<job>`/`scan.cancel:<job>` (the self-heal ran); on any other tag it reads `No longer known to the core (it may have restarted)` (D9 as amended). Tests: `not_found` on `scan.start` renders the short form; `CallTaggedFailed { tag: "scan.cancel:scan-1a2b3c4d", name: "scan.cancel", message: "scan: not_found: gone" }` drops the job from `order`, `summaries`, `full`, `started_here` and gives exactly `vec![scan.list {}]`.

## Task 13 quality panel

G76. `is_refused_launch` was inserted between `wording()`'s doc comment and its body (`crates/aitm-tui/src/scan/mod.rs`): move the block (its own doc lines plus the fn) below `wording()`'s closing brace so each method keeps its doc.

G77. `drop_scan_job` is `JobsState` logic on the reducer (`crates/aitm-tui/src/app.rs`, `crates/aitm-tui/src/scan/jobs.rs`): `JobsState::forget(&mut self, id: &str)` holds the four removals (`order`, `summaries`, `full`, `started_here`) and the cursor clamp, with a unit test (drop the cursor's job from a two-job order, the cursor clamps); `on_scan_failed` calls it. Rides with G64.

G78. The `not_found` self-heal predicate is inline in the reducer with a second `tag_parts` call (`crates/aitm-tui/src/app.rs`, `crates/aitm-tui/src/scan/mod.rs`): `ScanError::not_found_job(&self) -> Option<&str>` (Some(key) when `code == Some(NotFound)`, the verb is `scan.status`/`scan.cancel` and the tag is keyed) beside `is_refused_launch` with a mirror unit test; the arm becomes `if let Some(job) = err.not_found_job() { self.scan.jobs.forget(job); self.request_scan_list(out); }`; `verb == "scan.issue"` reads `err.verb`. G68's `LaunchVerb` also absorbs `is_refused_launch`'s `"scan.start" | "scan.map"` literal.

G79. `owning_tab`'s explicit Jobs arm equals its fallback (`crates/aitm-tui/src/scan/mod.rs`): delete the explicit arm; the doc sentence and the unit test carry the rule, with a one-line why on the fallback (Jobs reads `last_error`, so an unknown verb is never lost).

G80. Third copy of the `tagged`/`reply`/`failed`/`opened()` test scaffolding (`tests/scan_v2_errors.rs`, `tests/scan_v2_launch.rs`, `tests/scan_v2_profiles.rs`): move `tagged`, `reply`, `failed` and `opened_v2(tools: &[&str]) -> App` into `tests/common/mod.rs`; the three suites import them (G44/G60/G69 stay per-file assertion items).

G81. Test helper and doc hygiene (`tests/scan_v2_errors.rs`; `crates/aitm-tui/src/app.rs` `on_scan_failed` doc; `crates/aitm-tui/src/ui/scan/profiles.rs` footer comment): `footer_reason(text, needle)`; the two `unwrap_or_default()` in the hue assertion become `expect("the wording column")`/`expect("the theme sets a foreground")`; the `on_scan_failed` doc keeps the D9/D13 citations and the two whys (`started_here` removal, blocked-before-refused precedence) and drops the step list; the profiles footer comment likewise. G65's `blocked_footer` builds the refused `String` lazily (only when `blocked` is `None`).

## Task 13 security panel

G82. **Important, priority.** Core-controlled error `detail` is unbounded, held in four copies and walked per frame (`crates/aitm-tui/src/scan/mod.rs` `ScanError::new`/`from_message`; consumers in `app.rs` `on_scan_failed`, `ui/scan/profiles.rs` footer `wrap`, `ui/bars.rs` toast): bound at the one choke point: `pub const ERROR_DETAIL_MAX: usize = 240` cells; `ScanError::new` stores `detail` as `truncate(&detail, ERROR_DETAIL_MAX)` with control characters stripped (rides G10's `clean`) and `shrink_to_fit`, so the banner, toast, `wrap` and both clones all see bounded text. Test (`tests/scan_v2_errors.rs`): a `CallTaggedFailed` on `scan.start` with a 1 MiB detail renders at 240x50, `profiles.error.unwrap().detail.chars().count() <= 4 * ERROR_DETAIL_MAX`, and the toast text is likewise bounded.

G83. The `not_found` self-heal is a request path that is neither timer- nor key-driven (`crates/aitm-tui/src/app.rs` `on_scan_failed`, `scan.list` arm; `crates/aitm-tui/src/scan/jobs.rs` `fold_list`): a core that lists a job and answers every `scan.status` for it with `not_found` drives a reply-paced list/status ping-pong (bounded, not amplified, but a flickering row and a stream of Error toasts). Add `JobsState.healed: BTreeSet<JobId>` filled by the self-heal and cleared by the 40-tick timer's `scan.list`; `fold_list` emits no `scan.status` follow-up for a healed id, so a listed-but-not-found id is polled at most once per timer window. Slots beside G74's `heal_pending`. Test: a list carrying the job right after a `not_found` yields no `scan.status` for it; the timer-driven list does.

## Task 14 coder report

G84. The in-pane footers and the bar hints spell the same keys differently (`crates/aitm-tui/src/ui/scan/profiles.rs` `FOOTER` `w save as` vs `ui/scan/mod.rs` hint `w save`; Jobs and Issues `FOOTER` consts): with G65's `blocked_footer`, each view's footer text derives from the same key list `hints()` draws (one `(&str, &str)` table per tab in `ui/scan/mod.rs`, rendered compactly in the footer and as pairs in the bar), so a key is named once. Test: for each tab the footer's key tokens are a subset of the bar's.

## Task 14 security panel

G85. The help overlay's Scan section is cut off on any terminal under 42 rows with no way to reach it (`crates/aitm-tui/src/ui/overlays.rs` `help`, `lines_into(.., 0)`; `crates/aitm-tui/src/app.rs` help-mode keys): give the help overlay a scroll offset (`App.help_scroll: u16`, reset when the overlay opens) bound to `↑`/`↓`/`PgUp`/`PgDn`/`Home`/`End` while the overlay is shown, clamped to `lines.len() - inner.height`, with a one-row `more ↓`/`↑ more` marker at the cut edge; `lines_into` already takes the offset. Test (`tests/scan_v2_layout.rs`): at 100x30 the Scan heading is off screen until `End`/`PgDn` brings it on; at 200x50 nothing changes. Files: `overlays.rs`, `app.rs` (help keys only), the test.

G86. On a legacy bus the Profiles and Issues hints advertise keys the degraded tabs do not serve (`crates/aitm-tui/src/ui/scan/mod.rs` `hints`): when `scan_offer() == Legacy`, Profiles reads `s scan · m map · 3 site map · Esc back`, Issues reads `3 site map · Esc back`, Site map keeps `⏎ flow · Esc back` (no `n next page`/`J job`); Jobs unchanged. One row each in `hints_follow_the_tab` on `legacy_app`.

## Task 14 spec panel

G87. Layout literals weaker than the spec sentences (`crates/aitm-tui/tests/scan_v2_layout.rs`): in `narrow_frames_stack_the_detail_below_the_list` add at 90x40 `row_of(narrow, "Reflected cross-site scripting   high") > row_of(narrow, "INFO 0")` and `row_of(narrow, "profile standard") > row_of(narrow, "team-staging")` (first detail line below the last list row, T7-14's sentence); in `jobs_narrow_row_drops_profile_and_targets_into_the_detail` assert at 200x50 that a `│─` rule row exists and the detail's `JOB` line sits below it (Jobs stacks at every width).

## Task 14 quality panel

G88. **Important (test evidence).** Two assertions in `palette_and_help_name_the_surface` cannot fail (`crates/aitm-tui/tests/scan_v2_layout.rs`): the Scan heading is found by `" Scan"`, which first matches the `F / S / @` help line; the fits-the-box check (`!contains('…') && ends_with('│')`) holds for any clipped line. Fix: `row_of(&text, "│ Scan")` for the heading plus `row_of(&text, "1 2 3 4") == scan_heading + 1`; replace the box check with `line.contains(what)` against each `HELP` entry's full text (so a clipped line fails). Mutation proof in the report: deleting the heading push and lengthening the Profiles entry to 300 cells must each turn the test red.

G89. Help box height is a hand-counted literal with a wrong comment (`crates/aitm-tui/src/ui/overlays.rs` `help`): build `lines` first, then `centered(screen, 110, u16::try_from(lines.len() + 2).unwrap_or(u16::MAX))`; drop the counting comment. Rides with G85 (the scroll makes the clamp safe on small screens).

G90. Three hand-maintained homes for the same key text (`ui/scan/mod.rs` `hints`/`HELP`; `jobs.rs`, `profiles.rs`, `issues.rs` `FOOTER`/`DETAIL_FOOTER`): with G84, one `const <TAB>_KEYS: &[Hint]` per tab in `ui/scan/mod.rs`; `hints()` returns `&'static [Hint]` (bars does `.to_vec()` once), the footers and `HELP` lines are joined from the same tables, so a key is spelled once. `Hint` is used by `HELP` too or dropped; `pub(crate)` visibility for all three.

G91. Addendum to G81 and G80: `tests/scan_v2_layout.rs` `unwrap_or_default()` on the `running/audit` row and the wide header become `unwrap_or_else(|| panic!(..))` with the screen; `reply` imported from `tests/common` (G80's file list gains this file).

G92. Panel history in doc comments (`ui/scan/mod.rs` hints doc, `ui/scan/jobs.rs` legacy doc): keep the D11/D12 citations, drop the two "replaced/went with Task 14" clauses.

## Task 15 coder report (the Python cell; one file, `tests/e2e/tui/test_tui_scan_live.py`)

G93. The live cell's T7-20 grep and T7-19 point set follow the amended ACs: each screen sample is tagged with the surface it was taken on (`scan` for the four tabs and their overlays, `inspector` while a flow detail is open, `other`), the T7-20 grep covers `scan` samples only and the failure detail names the sample index and tag; after G20 lands (orphan points kept) the T7-19 comparison covers every point of the live `scan.sitemap` result, not only those attached to a listed node (drop the attached-only filter, keep the count line). Verified by `python3 -m py_compile` and the discovery dry run; the real run stays Terminal-only.

## Task 15 quality panel (the Python cell)

G94. **Important (evidence integrity).** `Checks.note` lands in `summary.txt` and the pass tally as `ok` (`tests/e2e/tui/test_tui_scan_live.py` `Checks.note`, `lines()`, the head line): three-state results (`ok`/`FAIL`/`note`), `note ` printed in `lines()` and the summary, the head line reads `PASS: <n> ok, <m> noted, 0 failed` (exit code unchanged, notes are not failures).

G95. **Important (vacuous pass).** A missing `l4-stream-safe` profile turns all of T7-18 into a passing note (`step_t7_18`): `c.check("T7-18: the Profiles list carries l4-stream-safe", False, names)` and return; the only sanctioned skip inside T7-18 stays the `l4.scope.add` refusal. The T7-18 `y` check compares the TUI outcome with the harness's own `scan.start`: `(row_shown and harness_job) or (refusals and harness_job is None)`, and on a refusal the wording's code matches the harness answer's code.

G96. Cell robustness and hygiene: `tab()` waits on a tab-specific marker (Issues footer `S severity · C confidence`, Jobs footer `x cancel · ⏎ issues of this job`, Site map `Nodes` pane title, Profiles `name  lanes`) instead of the strip text present on every tab; the T7-16 early-break predicate and the phase-change assertion use one filtered `phases` list; `host_label` uses `node.get("port") or default`; one `wait_field(read, key, want, timeout)` helper replaces the four `dict.update(..) or` waits; the three fixed sleeps (after `P`, after `J`, the node walk) become polls on the expected text; the `Esc` after re-entering Scan from the inspector runs only when the Detail pane is focused (or the row is re-selected with `cursor_to`); delete `found["state"]`, `Ctx.status_pairs`, the `reopen_scan` alias and the unreachable outer `except Fatal`.

## Task 15 security panel (the Python cell)

G97. **Important (two).** (a) The `l4.scope.add` widening is never reverted (`tests/e2e/tui/test_tui_scan_live.py` `step_t7_18`, `main` `finally`): keep the id `bus.confirm("l4.scope.add", ..)` returns (a non-empty string, else "no id") on `ctx.l4_entry_id`, match the entry in `l4.scope.list` by that id (never by "any inject entry containing 127.0.0.1"), and call `l4.scope.remove {"id": id}` best-effort in `finally` (swallow `ToolError`/`BusError`). (b) The per-run work dir with the findings store is never removed and holds the seeded session values raw: after `booted.stop()` and `tgt.stop()`, `shutil.rmtree(work, ignore_errors=True)` when the cell created it (or `tempfile.TemporaryDirectory`); the module docstring says the findings store is removed with the run.

G98. Cell hygiene from the security panel: drop `l4_flags={"allow_agent_widen": True}` (the operator confirm path skips the widen gate; the flag only opened `l4.scope.add` to the agent token), keep `l4_enabled=True`, and if a run then shows the operator refused, report it as a core bug; `redact` and `leaks` also match the first 12 hex chars of each secret (a truncated value on a pane must still be caught); the top-level exception handler prints `ev.redact(str(e))` (build `ev` before the `try`); `Pushes._run` clears `client.notifications` after each drain (the cell needs counts only). The strict T7-18 `y` comparison is G95.

## Task 15 spec panel (the Python cell)

G99. **Critical (UI-3 unproven as committed).** `cursor_to` on Profiles walks the editor's field cursor, not the list, whenever an editor is held (`tests/e2e/tui/test_tui_scan_live.py` `cursor_to`, `step_t7_18`, `step_t7_19`/`open_profile`): before every `cursor_to` on Profiles focus the List pane (press `Esc` once while `profile <name>` is on screen; `close_pane` sets `pane = List` and keeps the draft) and poll for the `>` row before walking; `cursor_to` failing is a `check(False)`, never a note (G95 already turns the missing-profile case into a failing check). Launch keys read the held editor regardless of pane, so T7-17's held-editor relaunch is unaffected.

G100. **Important (five).** (a) The two "opens in the inspector" checks match the flow `path` anywhere on screen (`/` is everywhere): require an inspector-only marker (`Request`/`Response` pane titles) plus `<method> <path>` from `flow.get`, and assert `1 Profiles` is gone. (b) T7-17 reads `issues[0]`: poll until an issue whose `check_id`/`class` contains `reflected-xss` (else one with both `evidence.payload` and `probe_flows`) exists while the job is running; the payload and probe-flow sub-steps are checks, not notes. (c) `P` asserts only that the Findings panel opened: also assert the `>` row carries the issue name or the `poc_ref` file stem. (d) The `y` comparison (G95) derives the expected branch from the harness answer: a job requires the row; `scan: refused_l4` requires the `L4 refused` wording; `scan: lane_unavailable` requires `No requested lane can run on this core`; anything else fails with both answers; `refusals` are snapshotted before `y` and a pre-existing wording does not count. (e) `group_of` reads whole screen rows and the detail head (same row as the filter line) defeats it: evaluate over the list pane span only, or locate the row by its `>`/glyph prefix.

G101. Minor: the three unlisted skip paths (incomplete runner env, no `aitm` binary, missing ground-truth verbs) become: runner env incomplete and no `aitm` binary stay skips (ratified: both are capability gates of the same kind as the plan's three); a V2 core lacking `scan.sitemap`/`scan.issues`/`scan.issue` FAILs the step that needs the verb instead of skipping the run. T7-19 opens the node under the `>` row after `g` and looks up that node's `flows[0]` in the live reply (the TUI renders in host-group order). `tab()` waits on tab-specific markers (G96). Ratified builder decisions (recorded in the Review log): only T7-16's view/editor open are `Fatal` and `step_t7_20` always runs; the harness `scan.start` comparison runs after `y` and both jobs are cancelled before `n`; `HOME`/`XDG_CONFIG_HOME` point at the work dir and `AITM_*`, `RUST_LOG`, `COLUMNS`, `LINES` are stripped from the TUI's env; 0600 token file unlinked in `finally`; `SKIP: <reason>` format; `J` on Site map relies on the query starting with no job.

## Dispatch (2026-11-01, after Task 14 lands)

Round G runs as two fix Coders in sequence in the one worktree, each committing by explicit path as `fix(tui-scan): G<ids> <title>` with reproducing tests first for every behaviour item, followed by one combined panel over both ranges.

**Round G-A (behaviour, bounds, security, spec rulings)**, first, while the Task 14 panel runs: G10, G11, G12, G13, G14, G15, G16, G17, G18, G19, G20, G21, G22, G31, G33, G35, G36, G37, G42, G45, G46, G47, G48, G49, G50, G51, G52, G53, G54, G57, G61, G66, G67, G71, G72, G73, G74, G75, G82, G83. Priority order inside the round: G82, G45 (+G53), G51, G52, G20, G22, G61 (+G14), then the rest by number.

**Round G-A result (2026-11-01):** done, 14 commits `0665f147..36ca1095`, crate gate green (fmt 0, clippy 0, 496 tests). Public shapes G-B must build on: `JobsState.full` values are `ReadStatus` (Deref to `JobStatus`, `dropped: StatusDropped`); `TreeNode { depth, kind: NodeKind, selector, state: TriState, hidden }` with `label()`/`id()` methods, cached on `ProfileEditor.tree`, `ProfilesState::rows()` and `cursor_node() -> Option<&TreeNode>`; `NodeLine.node` is gone and `SitemapState.point_lines`/`node_ranges` are built at fold; `SitemapState::fold_result` returns `Option<ScanError>`; `issue_detail_lines`/`detail_line_count` take `&ReadIssue`; `ReadIssue.dropped_timing` beside `dropped_flows` (G6 folds both into `Dropped`); `ProfilesState.lanes_text`/`widest`; `ProfileEditor::text_of(field)`; `App::scope_host`/`profiles::out_of_scope`; `open_wire_confirm(confirm, from)`; `ScanState.heal_pending`, `JobsState.healed`; `text::clean`. Two items G-A noticed go to G-B as G102 and G103.

G102. `JobStatus.targets` is bounded per string but not in count (`crates/aitm-tui/src/scan/jobs.rs` `bound_status`): keep at most `DETAIL_LIST_MAX` targets, the row shows the first with `+n`.

G103. Four em dashes remain in operator-visible `app.rs` toasts outside the Scan items (the WebSocket `Out of scope — unknown host`, the compose `Out of scope — add ... to send`, the `l4_toggle_gate` toast, the `flow.detail ... malformed reply —` toast): replace each with a colon, as G14 did; the TUI-wide rule is Matt's.

**Round G-B (structure, hygiene, tests)**, after G-A is committed: G1, G2, G3, G5, G6, G7, G8, G9, G23, G24, G25, G26, G27, G28, G29, G30, G32, G34, G38, G39, G40, G41, G43, G44, G55, G56, G58, G59, G60, G62, G63, G64, G65, G68, G69, G70, G76, G77, G78, G79, G80, G81, G84, G85, G86, G87, G88, G89, G90, G91, G92, G88 first in G-B (test evidence). The Python cell items are NOT in G-B. (appended below as G84+ before G-B is dispatched).

**Round G-C (the Python cell, `tests/e2e/tui/test_tui_scan_live.py` only)**, in parallel with G-B (disjoint file): G93, G94, G95, G96, G97, G98, G99, G100, G101, in the order G99, G95, G100, G94, G97, then the rest. Verified by `python3 -m py_compile`, the discovery dry run, and a sandbox run that must reach the capability skip or die at the socket-bind denial before any claim; the real run stays the orchestrator's in the Terminal.

**Round G-B result (2026-11-01):** done, ten commits `802d5228..fbdc4513`, all 53 items, crate gate green (fmt 0, clippy 0, 517 tests), mutation proofs for G88 and G58 quoted. Combined re-review of G-A+G-B over `6df3ce4b..fbdc4513 -- crates/`.

**Round G-C result (2026-11-01):** done, one commit `e32e7275` (+449/-234); py_compile and discovery clean; the sandbox run dies at the socket-bind denial before any claim; work-dir cleanup verified. Re-review of the cell runs beside G-B.

Each Coder may touch only the files its items name plus the test files that reproduce them; neither touches `CORE_TOOLS`, `fixtures/bus-fixture.json`, nor `docs/**`.

## Not in this round

The TUI-wide bidi/format-character filter (follow-up outside this track).
