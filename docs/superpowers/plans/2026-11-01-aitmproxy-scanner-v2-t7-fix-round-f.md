# T7 fix round F: findings report for the fix Coder

**Plan:** `docs/superpowers/plans/2026-10-31-aitmproxy-scanner-v2-t7-tui-plan.md` (Review log rows marked "fix round F": the Task 8 panel and the re-review of fix round E).
**Spec:** `docs/superpowers/specs/2026-10-31-aitmproxy-scanner-v2-tui-scan-surface-design.md` (D11 Issues detail as amended).
**When:** after fix round E and its re-review, before Task 9. The fix Coder may touch only the files each finding names plus the test file that reproduces it.

F1. **Flow list position** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs`): D11 orders the detail as evidence, then the probe/baseline flow list, then `poc_ref`, `finding_id`, remediation, note, occurrences and seen. Split `issue_detail_lines` into the lines before the flows and the lines after (or return a marker index), and draw the walkable flow list between them; `issue_detail_line_count` and `detail_len` follow. Test (`tests/scan_v2_issues.rs`): on the 200x50 detail the `flows` label's row index lies between the `matched` row and the `poc` row.

F2. **Placeholder wording** (`crates/aitm-tui/src/ui/scan/issues.rs`): the detail pane's empty text is `no detail read for this row` (neutral; true while a read is in flight, after a failed read and when the verb is missing). Test: the literal on screen before any `scan.issue` reply.

F3. **Degenerate `poc_ref` matches an unrelated finding** (`crates/aitm-tui/src/app.rs` `scan_open_poc`): a `poc_ref` that is empty after `trim()` counts as "no PoC"; match the ref against the finding's file stem or file name (`Path::new(&f.poc_path).file_stem() == Some(ref)` or `file_name` equal to `<ref>.yaml`/`<ref>.yml`) rather than substring; keep the title-equality arm. Test (`tests/scan_v2_issues.rs`): refs `""`, `"/"`, `".yaml"` each toast and never switch; `poc-3b1c` still finds `/pocs/poc-3b1c.yaml`.

F4. **Per-frame work over wire strings not covered by E19** (`crates/aitm-tui/src/scan/issues.rs` `fold_issue`, `crates/aitm-tui/src/ui/scan/issues.rs` `detail()`, `crates/aitm-tui/src/app.rs` `scan_open_poc` toast): at insert time bound every rendered string (`name`, `class`, `check_id`, `target.*`, `location.*` including `l4`, `poc_ref`, `finding_id`, `l4.seed_id`, `scope_entry`, `sent_hex`, each `mutation_chain` entry, and `mutation_chain.truncate(MUTATIONS_MAX + 1)`); add `FLOWS_MAX = 64` applied to `evidence.probe_flows` at insert with the dropped count rendered as `... n more`; in `detail()` build only the visible window of flow lines (`skip(top).take(body_h)`); the `P` toast cuts `poc_ref` to 80 cells. Test: an issue with 100 000 probe flows folds to 64 kept plus a `... 99936 more` line and renders at 200x50.

F5. **Head line verdict is forgeable by a name containing three spaces** (`crates/aitm-tui/src/scan/issues.rs`, `crates/aitm-tui/src/ui/scan/issues.rs` `head_line`): return the head as structured parts (name, severity, confidence, status) and style the verdict from `issue.severity` directly, no string split. Test: a name `"Debug marker   critical · certain · confirmed"` renders with the real severity hue on the verdict cell only.

F6. **`flow_cursor` not clamped when an update shrinks the flow list** (`crates/aitm-tui/src/scan/issues.rs` `fold_issue`): clamp `flow_cursor` to `flow_refs_len - 1` after replacing the issue. Test: cursor on flow 3 of 3, an update with one probe flow, `Enter` opens that flow.

## Not in this round

Items the fix round E re-review adds are appended below when it reports.
