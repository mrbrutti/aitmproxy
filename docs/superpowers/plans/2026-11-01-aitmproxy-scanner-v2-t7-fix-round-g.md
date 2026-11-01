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

G23. Third serde-token reader; vocabulary tokens live in `issues.rs` (`crates/aitm-tui/src/scan/{issues,jobs,sitemap}.rs`, new `crates/aitm-tui/src/scan/tokens.rs`): one `scan::tokens` module with `severity_token`, `confidence_token`, `lane_token`, `status_token`, `severity_header`, `SEVERITY_ORDER`, `severity_counts` and one `pub(crate) fn wire_token<T: Serialize>(v: &T) -> String`; delete `kind_token`, `token`, `serde_name`; the Profiles check tree (Tasks 10/11) uses it.

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

G36. The check tree is rebuilt with three `String`s per node on every call (`crates/aitm-tui/src/scan/profiles.rs`, `app.rs`): cache `tree: Vec<TreeNode>` on `ProfileEditor`, rebuilt only in `fold_checks` and on collapse/expand; `TreeNode { depth, selector, kind: Lane | Class | Check }` with label and id derived; `cursor_node() -> Option<&TreeNode>`; one `clamp_tree_cursor` helper.

G37. The origin picker is rebuilt on every `Flows` sweep and can move the highlight (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): refresh only when the `Flows` fold changed the row set and an editor is open; `refresh_origins` re-finds the previously highlighted origin by value.

G38. `ConfirmCall` re-derives the tag from its own JSON (`crates/aitm-tui/src/app.rs`): `ConfirmCall.tag: Option<String>` set by `scan_delete`; `answer_confirm` routes through `scan_call` when set; delete `scan_confirm_tag`.

G39. Reducer-on-state logic in `app.rs` that belongs on the model (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): `ProfileEditor::enter_node`, `fold_node`, `saved_as`; `ProfilesState::is_builtin`, `delete_target`, `on_deleted`; the three builtin checks go through `is_builtin`.

G40. Missing-verb block copied beside `scan_call` (`crates/aitm-tui/src/app.rs`): `fn scan_verb_or_toast(&mut self, name) -> bool` used by `scan_call`, `scan_save`, `scan_delete`.

G41. Bounds constants split across two files; two inline `32`s (`crates/aitm-tui/src/app.rs`, `scan/profiles.rs`): move `SAVED_NAME_MAX`/`SAVED_PATH_MAX` to `profiles.rs` (reuse `VALUE_MAX` for the path); `CHECK_LISTS_MAX = 32` with a doc line.

G42. A profile name typed into `w`'s prompt bypasses `set_text`'s trimming (`crates/aitm-tui/src/app.rs`): route through `editor.set_text(EditorField::Name, text)` and check `is_builtin_name` on the trimmed value; test the padded builtin name.

G43. Stringly-typed `set_text`/`parse_l4_target` errors (`crates/aitm-tui/src/scan/profiles.rs`): `FieldError { NotANumber(EditorField), NotText(EditorField) }`, `L4TargetError`, with `Display` carrying today's wording (rides with G26).

G44. Test hygiene in `tests/scan_v2_profiles.rs`: literals for the session line, the builtin-name toasts; `assert_eq!` for the exact `CHECKS_MAX`/`PROFILES_MAX`/`CHECKS_MAX + 2` counts; import `SELECTOR_MAX`; bound the description with `4 * VALUE_MAX`.

## Not in this round

The TUI-wide bidi/format-character filter (follow-up outside this track).
