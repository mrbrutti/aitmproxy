# scrub_text nested-pair leak implementation plan

**Status:** approved (2026-11-01, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-11-01-scrub-text-nested-pair-leak-design.md` (approved 2026-11-01, committed `bdd231db`)
**Branch / worktree:** `claude/heuristic-panini-828774`, in the NESTED directory
`/Users/matt/Security/aitmproxy/.claude/worktrees/heuristic-panini-828774/wt` (called `WT` below).
**The parent directory of `WT` is not a git worktree and resolves to the main checkout: never run git or
cargo there; `cd` to `WT` or use `git -C <WT>`, and use absolute paths for every file.** Base SHA for every
diff and every Tester or panel dispatch: `61a35571` (`origin/main` when the branch was cut; the spec is
`bdd231db` on top, the plan lands on top of that; both are docs, so `git diff --stat 61a35571 HEAD -- crates`
is empty at the start of Task 1). Called `BASE` below. It changes only if the orchestrator merges `origin/main`
before the panel (Integration notes); then the Tester and the panel get the new merge-base.

## Overview

Nine tasks, in five waves. **Wave 1** (parallel, disjoint files): Task 1 pins `scrub_text` with the `[guard]`
rows of AC4 to AC7 in core, Task 2 pins `scrub_embedded` with AC17 in the scanner, Task 6 adds the `[red]`
aitm-poc test (AC21). **Wave 2** writes the other `[red]` tests, every one watched failing on the unchanged
production core: Task 3 then Task 4 (core, one file, in order; Task 4 is AC11, the named edits of existing wide
tests, the renames and the one deletion), in parallel with Task 5 (scanner: AC15, AC16, AC18, the AC19 edits, the
ten removed corpus rows, the two doc edits). **Wave 3**, Task 7, alone: the rule (R1 to R4, the third `Reading`
value, the doc list of Design 7 items 1 to 6) turns every red test green. **Wave 4**, Task 8: the Stage 5
Tester (whole branch, mutants M1 to M8, gate). **Wave 5**, Task 9: the Stage 6 panel, whose security reviewer
runs the out-of-tree differential of Design 9.

Production code changes in exactly one task (Task 7), in one file. Tasks 1 to 6 touch tests (and, in Task 5,
two doc comments), so every red run of Waves 1 and 2 is taken against a core that is byte-identical to `BASE`
and is therefore deterministic, even though Coders share one worktree.

### Execution order (read this before dispatching)

| Task | Wave | Depends on | Files (all under `crates/`) | Parallel with |
|---|---|---|---|---|
| 1 core pin `[guard]` | 1 | none | `aitm-core/src/redact.rs` (tests, append) | 2, 6 |
| 2 scanner pin `[guard]` | 1 | none | `aitm-plugin-scanner/src/reproduce.rs` (tests, append) | 1, 6 |
| 6 poc test `[red]` | 1 | none | `aitm-poc/tests/builder.rs` (append) | 1, 2, then 3, 4, 5 |
| 3 core `[red]` tests | 2 | 1 committed | `aitm-core/src/redact.rs` (tests, append) | 5, 6 |
| 4 core AC11 edits `[red]` | 2 | 3 committed | `aitm-core/src/redact.rs` (tests, edits) | 5, 6 |
| 5 scanner `[red]` tests, edits, docs | 2 | 2 committed | `aitm-plugin-scanner/src/reproduce.rs` | 3, 4, 6 |
| 7 core rule and docs | 3 | 4, 5, 6 committed | `aitm-core/src/redact.rs` (production and docs only) | none |
| 8 Tester | 4 | 7 committed | test modules of the three files; scratch outside the repo | none |
| 9 panel | 5 | 8 PASS | none (read-only; scratch outside the repo) | the three reviewers |

**Strictly ordered:** 1 then 3 then 4 then 7 (one file, `redact.rs`); 2 then 5 (one file, `reproduce.rs`); 4, 5
and 6 all before 7; 7, 8, 9 in that order. **Independent (may fan out):** 1, 2 and 6 with each other; 5 with
3 and 4; 6 with everything before 7. One writer per file, one Coder per task, all in `WT`, each committing its
own task by explicit path when done.

**Why Task 7 waits for 5 and 6, although they only go green after it.** A red run on a scanner or poc test is
evidence only if the core under it is the unchanged `BASE` core. The scanner and aitm-poc crates compile
`aitm-core` from the same tree, so Task 7 must not start until Tasks 5 and 6 have recorded their red runs and
committed. Tasks 3 and 4 edit only the `#[cfg(test)]` module of `redact.rs`, which dependent crates never
compile, so they do not disturb the red runs of Tasks 5 and 6. (A transient parse error in `redact.rs`'s test
module while another Coder is mid-edit would stop a dependent crate's build: wait a minute and re-run; never
touch `redact.rs` from Task 2, 5 or 6.) The faster alternative, a child session on its own worktree for Task 7
branched from the Wave 2 commits, is possible under WORKFLOW stage 4 but then Tasks 5 and 6 get their green run
only after the merge back; not recommended here.

**Commit and SHA hand-off.** The orchestrator keeps this table and puts the SHAs in each dispatch.

| SHA | Commit | Red or green | Must be an ancestor of HEAD before |
|---|---|---|---|
| `S1` | Task 1 | green | Task 3 |
| `S2` | Task 2 | green | Task 5 |
| `S6` | Task 6 | red: 1 test of `builder.rs` | Task 7 |
| `S3` | Task 3 | red: 7 named core tests | Task 4 |
| `S4` | Task 4 | red: 11 named core tests | Task 7 |
| `S5` | Task 5 | red: 4 named scanner tests | Task 7 |
| `S7` | Task 7 | green, whole branch | Task 8 |
| `S8` | Tester's last commit (or `S7` if it adds none) | green | Task 9 (the panel's head) |

The branch is red by design from the first red commit (`S6`, `S3`, `S4`, `S5`, in any order) until `S7`; each
red commit's failing set is named exactly in its task, and nothing else may fail. `main` carries one commit per pull
request (squash merges), so the red window never reaches it. Task 7 starts with a check that all of `S4`, `S5`,
`S6` (and so `S1`, `S2`, `S3`) are ancestors of `HEAD` (`git -C WT merge-base --is-ancestor <sha> HEAD` exits 0
for each) and that the core production code is still `BASE`'s (the hunk-start check in Task 7).

### Preflight (orchestrator, before dispatching Wave 1)

1. `git -C WT rev-parse --show-toplevel` prints `WT` and `git -C WT branch --show-current` prints
   `claude/heuristic-panini-828774`.
2. `git -C WT diff --stat 61a35571 HEAD -- crates` prints nothing.
3. No live session is changing the three files. **At plan time I scanned** every worktree of `git worktree
   list` (31) with `git -C <path> diff --name-only 61a35571...HEAD -- crates/aitm-core/src/redact.rs
   crates/aitm-plugin-scanner/src/reproduce.rs crates/aitm-poc/tests/builder.rs` and `git -C <path> status
   --short -- <the same three paths>`: nothing was printed for any worktree, and `git diff --name-only 61a35571
   origin/main -- <the three paths>` printed nothing (the local `origin/main` was `58724ef7`, not fetched).
   Repeat both at dispatch; the window must stay short.
4. Baselines, from the sandbox in `WT` (proves cargo works offline here; if not, run `cargo fetch` in the
   Terminal panel): `cargo test -p aitm-core --offline --lib redact::tests` prints `test result: ok. 54
   passed`; `cargo test -p aitm-plugin-scanner --offline --lib` prints `197 passed`; `cargo test -p aitm-poc
   --offline --test builder` prints `23 passed`. (I measured 54, 197 and 23 in scratch copies of `BASE`.)
5. `rustfmt --edition 2021 --check <file>` exits 0 for each of the three files (it did at plan time).

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).** `cargo build`, `cargo clippy`, every test that binds no
  socket, `rustfmt`, and local git on the explicit paths of the task: `git -C WT status --short`, `git -C WT
  diff`, `git -C WT show`, `git -C WT archive`, `git -C WT commit`. Shell variables and the working directory do
  not persist between Bash calls: write the literal `WT` path in each command. If the sandbox refuses a git
  write, stop and report; do not work around it.
- **Sandbox cannot bind sockets.** These fail on `BASE` and after, for that reason only (each panics with `bind
  ... Operation not permitted`, so the cause does not depend on the change; I saw the `aitm-poc` ones on a scratch
  copy of `BASE` and all three crates' on a scratch copy with the new rule), and are reported "NOT RUN (socket)",
  never as a pass or a failure of the task: `aitm-core` lib `proxy::tests::acceptor_attaches_the_scope_guard_to_the_module_ctx`;
  `aitm-poc` `tests/run.rs` (`pass_vs_patched`, `run_honors_out_dir_and_artifact_reads_it_back`,
  `extract_binds_variable_for_a_later_assertion`, `three_artifacts`, `http_step_out_of_scope_is_refused`) and
  `tests/target.rs` (`reflects_vs_escapes`); `aitm-plugins` `tests/kill_modes.rs` (`kill_429_synthesizes_response`,
  `kill_reset_closes_connection`) and `tests/response_edit.rs` (`response_status_edited_then_resumed`). So the
  per-package sandbox gate for aitm-poc is `--test builder`, not the whole package.
- **Terminal panel (orchestrator only).** `git fetch`, `git push origin claude/heuristic-panini-828774`
  (explicit refspec, **never a bare `git push`**), `gh`, `cargo fetch`, and the **workspace gate**, run
  detached so a vanished terminal tab loses nothing and read from the log by its exit status, never by a grep:
  `cd /Users/matt/Security/aitmproxy/.claude/worktrees/heuristic-panini-828774/wt && nohup bash -c 'cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast; echo "gate-exit=$?"' > "/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_ee73bb50-38b3-4011-be40-9e8688764e8f/gate-<head7>.log" 2>&1 &`
  then `tail -n 5` of that log: it must end with `gate-exit=0`. The workspace run includes `aitm-mcp` and the
  socket suites. Known flakes (judge by whether the change touches them, re-run alone, compare on `main`):
  `rhai_e2e`'s scope test, and the TUI 5000-flows, `web_bus_write_deadline` and rhai budget tests at load average
  above 60. Keep Terminal command lines short; a long compound git line is mangled (put it in a script file
  under the notes folder and run `bash <file>`). Never write a word that begins with a hash sign in a commit
  message, PR title or body (the terminal hook refuses it): write "PR 199".
- **Commits.** The Coder commits at the end of its task, by explicit path, in one call:
  `git -C <WT> commit -m "<subject>" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" -- <paths>`. Never
  `git add -A` or `git add .`, never `git commit -a`. The index is shared with the other Coders of the wave, so
  audit the result: `git -C <WT> show --stat --format=%H HEAD` lists exactly the task's files. Run `rustfmt
  --edition 2021 <file>` on your own file only; never `cargo fmt`.
- **No `git stash`** (the stack is shared with every worktree and session). To set work aside, finish the step.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other worktrees, `touch` the edited source
  file before each red or green run so cargo does not reuse a stale artifact. A red run on a stale binary is
  worthless.
- **Gate per task** (sandbox, from `WT`; per package because the other Coders' files may be mid-edit):
  green tasks (1, 2, 7): `rustfmt --edition 2021 --check <own file>` exits 0;
  `cargo clippy -p <crate> --all-targets --offline -- -D warnings` exits 0; `cargo test -p <crate> --offline
  --no-fail-fast` shows no failure outside the socket list above. **Red tasks (3, 4, 5, 6)** differ in one
  way: the test run shows exactly the failing set the task names and nothing else; fmt and clippy must still
  pass.
- **Evidence, verbatim.** Every red and green run in a report is the literal command and the literal output
  lines the task names. "It failed as expected" is not a report. The Coder's report is, in order: the task; the
  red output; the green output (or, for a red task, the red output only); the gate output; the commit hash;
  files changed; anything noticed and not changed (`coder.md`).

### Code constraints for every task

- Touch only the files the task declares. No new dependency, no `Cargo.toml` or `Cargo.lock` change, no `lib.rs`
  change, no new `pub` item, no changed public signature. No `unsafe`, and no line you add may contain the word
  `unsafe`, even in a comment.
- **Banned in every comment, doc and string you add** (Tasks 4 and 7 and the AC24 grep check them; the grep
  covers `redact.rs` and the scanner `src`): `reads a pair on one line`, `one line by the wide`, `line break as a
  boundary`, `three declared`, `skip_pair_blanks`, `by construction` (say "on well-formed input"), and the
  phrases the 2026-10-31 panel banned, which `BASE` does not contain: `only knows`, `widened locally`, `needle
  layer`, `two vocabularies`, `vocabulary consolidation`, `stays until`, `scanner's copy`, `cannot diverge`,
  `cannot disagree`, `in nothing else`, `narrower list`, `only two differences`, `the only ones whose`,
  `one-scan`, `before the scanner stopped`, `Pins taken before`, `before PR 171 none`. In the body of
  `mask_secret_pairs` the word `reading` may appear only in the three code lines of AC14 (Task 7).
- No code in a doc comment longer than a signature. **No raw invisible or non-ASCII whitespace or letter in a
  test source**: write `\u{a0}`, `\u{c}`, `\u{2028}` and the like as escapes. Large-string assertions use
  `assert!(a == b, "short message")`, never `assert_eq!`, so a failure never prints megabytes (house style in
  `redact.rs`); small tables use the existing `mismatches`, `mismatches_wide` and `embedded_mismatches` helpers.
- **A pin or a red test is never made to pass by editing its expected value.** The expected values in this plan
  are the spec's; if the rule of Task 7 produces something else, Task 7's Coder stops and reports.
- **Existing tests are edited only as Tasks 4 and 5 name them.** A Coder that finds any other existing test, or
  any row of `RECORDED_SCRUB_TEXT` (core) or of `RECORDED_SCRUB_EMBEDDED` outside the ten named in Task 5,
  failing or needing an edit **stops and reports**; it does not edit, move or drop the row.
- Test names are exact. A Coder may add rows to a table, never remove or weaken one, and adds no extra test
  function (the counts below depend on that). Private test helpers are not tests.

### Symbols the tasks use (confirmed by reading `BASE`)

- `crates/aitm-core/src/redact.rs` (2475 lines; `#[cfg(test)]` at 511): private `SECRET_KEY_NEEDLES`,
  `SECRET_KEY_SEGMENTS`, `patterns()`, `is_secret_lower`, `contains_segment_word`; `enum Reading { Standard,
  Wide }` (216-223, `#[derive(Clone, Copy, PartialEq, Eq)]`); `is_key_byte`, `run_end`, `is_ascii_blank`,
  `blank_len`, `skip_blanks` (282), `skip_pair_blanks(text: &str, mut i: usize, reading: Reading) -> usize`
  (291-314, doc included), `ends_value`, `unquoted_value_end`, `is_opening_quote`, `closing_quote`,
  `is_host_port`; `fn mask_secret_pairs(text: &str, reading: Reading) -> String` (392-509: doc 392-423, body
  424-509; `skip_pair_blanks` is called at 448 and 473); public `is_secret_key`, `is_secret_key_wide`,
  `scrub_text` (164), `scrub_text_wide` (208, body `mask_secret_pairs(&scrub_text(text), Reading::Wide)`).
  Test helpers: `mismatches` (518) and `mismatches_wide` (1617), both `fn(&[(&str, &str)]) -> Vec<(&str,
  &str, String)>`; `RECORDED_SCRUB_TEXT: &[(&str, &str, bool)]` (1225-1596, 183 rows),
  `NESTED_UNDER_A_WIDE_ONLY_KEY` (2094), `LINE_BREAK_IS_A_BOUNDARY` (2118), `corpus_inputs()` (2216), the last
  test `scrub_text_wide_stays_linear_on_line_break_shapes` (2435-2474), the module's closing brace (2475).
- `crates/aitm-plugin-scanner/src/reproduce.rs` (2373 lines; `#[cfg(test)]` at 483): private `fn
  scrub_embedded(text: &str) -> String` (376, body `scrub_text_wide(&strip_userinfo(text))`, doc 364-375);
  test helpers `flow_with_query(path: &str) -> HttpFlow` (541), `flow_with(method, path, headers: &[(&str,
  &str)], body: Option<&str>) -> HttpFlow` (546), `point(flow, location, name, example) -> InjectionPoint`,
  `http_step(&Poc)`, `header_of`, `embedded_mismatches(rows: &[(&str, &str)]) -> Vec<(&str, &str, String)>`
  (1560); `RECORDED_SCRUB_EMBEDDED: &[(&str, &str)]` (1683-2024, 162 rows, the `(xii)` group at 1995-2023);
  `scrub_embedded_matches_the_recorded_pipeline_output` (2030), `scrub_embedded_deliberate_changes_are_exactly_these`
  (2060), `build_poc_masks_a_nested_standard_pair_under_a_wide_only_key` (2286-2372, the last test; module's
  closing brace 2373). `use crate::checks::{CheckDefinition, ...}`, `Location`, `build_poc`, `serde_json` are in scope
  in `mod tests` (the neighbouring tests use them).
- `crates/aitm-poc/tests/builder.rs` (824 lines): helpers `flow_with(path: &str, body: Body) -> HttpFlow` (185),
  `basic_spec() -> PocSpec` (217), `http_step(&Poc) -> &HttpStep` (247); `use aitm_poc::builder::{PocBuilder,
  PocSpec, StdPocBuilder}`; the last test is `build_drops_credential_in_duplicate_json_key` (806). The comment at
  line 647 ("the shared `scrub_text` set lacks jwt/sid") is stale and is **not** touched (a later docs sweep).

### Counts (the tasks check these)

| After | `redact::tests` | `cargo test -p aitm-core --lib redact` | scanner lib | aitm-poc `--test builder` | Failing set |
|---|---|---|---|---|---|
| `BASE` | 54 | 56 | 197 | 23 | none |
| Task 1 | 58 | 60 | 197 | 23 | none |
| Task 2 | 58 | 60 | 198 | 23 | none |
| Task 6 | | | | 24 | `build_masks_a_credential_nested_under_a_secret_parent_on_every_surface` |
| Task 3 | 65 | 67 | | | 7 core tests (Task 3) |
| Task 4 | 64 | 66 | | | 11 core tests (Task 4) |
| Task 5 | | | 201 | | 4 scanner tests (Task 5) |
| Task 7 and after | 64 | 66 | 201 | 24 | none |

(The extra two in the `lib redact` filter are the `tunnel` tests that match the name. The spec says 63 and 65:
see spec gap 1.)

### AC coverage

| AC | Task | Test or check (exact name) |
|---|---|---|
| AC1 | 3 | `redact::tests::scrub_text_masks_a_credential_nested_under_a_secret_parent` |
| AC2 | 3 | `redact::tests::scrub_text_masks_a_nested_credential_in_every_separator_and_quote_form` |
| AC3 | 3 | `redact::tests::scrub_text_reads_every_pair_of_a_chain_of_secret_keys` |
| AC4 | 1 | `redact::tests::scrub_text_keeps_the_output_it_had_when_no_secret_pair_starts_inside_a_masked_value` |
| AC5 | 1 | `redact::tests::scrub_text_masks_a_value_that_looks_like_a_pair_under_a_secret_parent` |
| AC6 | 1 | `redact::tests::scrub_text_masks_a_padded_base64_credential_on_the_next_line` |
| AC6b | 3 | `redact::tests::scrub_text_masks_a_padded_base64_credential_under_a_nested_pair` |
| AC7 | 1 | `redact::tests::scrub_text_does_not_read_the_closing_quote_of_a_masked_value_as_an_opener` |
| AC8 | 3 | `redact::tests::scrub_text_stays_linear_on_nested_pair_shapes` |
| AC9 | 3 | `redact::tests::scrub_text_wide_masks_a_next_line_credential_under_a_wide_only_parent` |
| AC10 | 3 | `redact::tests::scrub_text_wide_masks_a_wide_only_pair_nested_under_a_standard_parent` |
| AC11 | 4 | the four edited tests of Task 4 (`scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key`, `scrub_text_wide_reads_a_pair_across_a_line_break`, `scrub_text_wide_reads_a_pair_across_a_line_break_beside_non_ascii_spaces`, `scrub_text_wide_stays_linear_on_line_break_shapes`) and the deletion |
| AC12 | 1 (start), 4, 7, 8 | every other existing test unedited: the diff checks of Tasks 1, 4, 7 |
| AC13 | 8 | mutants M1 to M8 |
| AC14 | 7, 8 | the two greps and the diff checks of Task 7 |
| AC15 | 5 | `reproduce::tests::scrub_embedded_nested_pair_changes_are_exactly_these` |
| AC16 | 5 | `reproduce::tests::scrub_embedded_masks_a_nested_credential_under_a_secret_or_a_wide_only_parent` |
| AC17 | 2 | `reproduce::tests::scrub_embedded_keeps_the_output_it_had_for_a_value_that_looks_like_a_pair` |
| AC18 | 5 | `reproduce::tests::build_poc_masks_a_credential_nested_under_a_secret_parent` |
| AC19 | 5 | `reproduce::tests::build_poc_masks_a_nested_standard_pair_under_a_wide_only_key` (edited) |
| AC20 | 5, 7, 8 | the other scanner tests unedited, `crawl.rs` and `commands.rs` empty diff |
| AC21 | 6 | `builder::build_masks_a_credential_nested_under_a_secret_parent_on_every_surface` |
| AC22 | 7, 8 | the suites of `aitm-findings`, `aitm-scan-checks-http`, `aitm-scan-ws`, `aitm-plugins`, `aitm-poc`, `aitm-core`; `aitm-mcp` in the Terminal |
| AC23 | 9 | the security reviewer's differential report |
| AC24 | 4, 7, 8 | the docs grep and the full gate |

### Architect's calls in this plan (for Matt to correct)

1. Red tests are written and watched failing on the unchanged core before the rule exists (the brief's order),
   not after it (the order the spec's "Left to the builder" suggests). The branch is red between the first red
   commit and Task 7; every red set is named; the squash merge hides it.
2. Task 4 (AC11) is its own task, with a step list, because it is the one place an existing test is edited.
3. AC17, the one `[guard]` of the scanner, is Task 2 (a second pin), not part of Task 5.
4. Names the spec leaves to the builder are fixed here so the Tester's mutant anchors are exact: the third
   `Reading` value is `FirstOfWide`; the shared helper that runs the two regex passes is `fn apply_patterns(text:
   &str) -> String`; the new local is `masked_to`; the renamed const is `PAIR_ACROSS_A_LINE_BREAK`; the shared
   test generator is `fn padded_credentials() -> Vec<(&'static str, String)>`. A Coder may rename only by reporting it.
5. AC6 and AC6b are two tests (a `[guard]` and a `[red]` cannot be one test across two tasks), so the counts are
   64 and 66, not the spec's 63 and 65.
6. The Task 1 bite check runs in a throwaway crate outside the repo (a copy of `redact.rs` needs only `regex`),
   not by editing production code in the shared worktree, which would corrupt the other Coders' red runs.
7. Task 5 adds one assertion beyond the spec: no input of the AC15 table is still in `RECORDED_SCRUB_EMBEDDED`.
8. The Tester copies the 2026-10-31 and 2026-11-01 differential tools into the notes folder (step 0 of Task 8).

### Spec gaps found while planning (the spec is not edited; the orchestrator decides)

1. **Test counts.** The spec says 63 `redact::tests` and 65 for the filter after the change. It lists eleven new core
   tests (AC1 to AC10 with AC6b) and deletes one: 54 + 11 - 1 = **64**, and 66 for the filter. The spec's 63 and 65
   are the counts of the Architect's scratch file, which merges AC6 and AC6b into one test. The mutant
   counts of AC13 (M4 "nine red", which names AC6b) agree with the split.
2. **AC19 "three expectations edited"** names four values: the JSON `note` and `list`, the form `note`, the untyped body.
3. **Design 7 item 7 omits stale comments.** Renaming and deleting the AC11 tests leaves the doc comment of the
   deleted test attached to the next test, a section comment that names "the helper at its boundaries", and doc
   and inline comments that describe the old boundary. AC24's grep matches `redact.rs:2291` ("one line by the
   wide"), so at least that doc must change. Task 4 names every comment to rewrite; comment text only.
4. **The Architect's scratch file is not the final shape.** `/tmp/claude-501/nested-scratch/redact_final_pristine.rs`
   keeps `skip_pair_blanks` (two equal arms), calls the third value `StdNested`, merges AC6 and AC6b, and leaves an
   orphaned doc comment. It is a reference for the shape of R1 to R4, not the target; the spec governs.
5. **AC14's "adds no `pub`"** is ambiguous for a diff full of the word in comments; Task 7 checks added lines
   that begin with `pub` after blanks.
6. **AC13 M5 needs the deleted function back.** With `skip_pair_blanks` deleted, "the wide scan stops at a line
   break again" means re-adding a helper in the scratch copy; Task 8 says how.
7. **The sandbox cannot run all the suites AC22 names**: the socket failures listed under "Where each command
   runs" (one in `aitm-core`, six in `aitm-poc`, three in `aitm-plugins`; the spec names only the first) are unrelated
   to the change; the workspace gate in the Terminal is their evidence.

## Tasks

### Task 1: pin `scrub_text` on the unchanged tree (core, `[guard]`)

- **Satisfies:** AC4, AC5, AC6; AC7; the start of AC12 (no existing line is changed).
- **Depends on:** none. **Parallel with:** Tasks 2, 6. **Dispatch inputs:** spec path, plan path, `WT`, task 1,
  `BASE`.
- **Files:** `crates/aitm-core/src/redact.rs` (modify, inside `mod tests` only: append after the last test
  `scrub_text_wide_stays_linear_on_line_break_shapes` and before the module's closing brace).
- **Start check:** `git -C WT rev-parse --show-toplevel` prints `WT`; `git -C WT diff --stat 61a35571 HEAD --
  crates` prints nothing.
- **Change (tests and one helper only):**
  - private helper (not a test) `fn padded_credentials() -> Vec<(&'static str, String)>`: 5,000 pairs `(parent,
    credential)` from an in-test xorshift64 generator with no dependency, seeded `0x9E37_79B9_7F4A_7C15` (shifts
    13, 7, 17); a credential is 4 to 43 characters of `A-Za-z0-9` followed by `=` or `==`; the parent is one of
    `token`, `password`, `secret`, `session`, `auth`, `api_key`, chosen by the generator. Task 3 reuses it.
  - four tests, exact names, each a `[guard]`: it passes on the unmodified code, rows copied from the spec:
    1. `scrub_text_keeps_the_output_it_had_when_no_secret_pair_starts_inside_a_masked_value` (AC4): the 14 rows of
       spec AC4 through `mismatches`. First and last rows: `auth:\n  password=hunter2` gives `auth:\n  [redacted]`;
       `password:\n  hunter2` gives `password:\n  [redacted]`. Others include `auth:\n  user: bob` gives `auth:\n
       [redacted] bob`, `auth:\n  sessionKey: abc123` gives `auth:\n  [redacted] abc123`, `Authorization:\n  password:
       hunter2` gives `Authorization:\n  [redacted]`.
    2. `scrub_text_masks_a_value_that_looks_like_a_pair_under_a_secret_parent` (AC5): the 15 rows of spec Design 5
       hazard 1 (spec AC5) through `mismatches`, each giving `<parent>:<layout>[redacted]`. First and last: `token:\n
       YWJj=` gives `token:\n  [redacted]`; `api_key:\n  Key=AAA=:` gives `api_key:\n  [redacted]`; and `token:\n
       AApwdBB==\n  other: 1` gives `token:\n  [redacted]\n  other: 1`.
    3. `scrub_text_masks_a_padded_base64_credential_on_the_next_line` (AC6): for every pair of `padded_credentials()`,
       `scrub_text("{parent}:\n  {credential}")` equals `{parent}:\n  [redacted]` (message carries the input with
       `{input:?}`); assert 5,000 pairs were checked.
    4. `scrub_text_does_not_read_the_closing_quote_of_a_masked_value_as_an_opener` (AC7): the five rows of spec AC7
       through `mismatches`: `token="sid: " tail="x"`, `token="sid:" tail="x"` and `token="a sid:" tail="x"` give
       `token="[redacted]" tail="x"`; `x=1&token='auth='&y="z"` gives `x=1&token='[redacted]'&y="z"`;
       `x=1&token="sid:\t"\ny=2` gives `x=1&token="[redacted]"\ny=2`.
- **Red:** none; these are pins, written and run on the unmodified code. **Bite check, in a throwaway crate
  outside the repo, never by editing production code in `WT`:** `SCRATCH="$TMPDIR/nested-pin-bite"`; create a
  crate there with edition 2021 and one dependency, `regex = "1"`, whose `src/lib.rs` is the single line `pub mod
  redact;` and whose `src/redact.rs` is a copy of your edited `redact.rs`; `CARGO_TARGET_DIR="$SCRATCH/target"
  cargo test --offline --lib` (no lock file is needed offline; a fresh build takes seconds) prints `58 passed`.
  Then, in the copy only, make the `Reading::Standard` arm of `skip_pair_blanks` call `skip_pair_blanks(text, i,
  Reading::Wide)` (a revert of the PR 171 next-line rule): at least the AC4, AC5 and AC6 tests must be red (I
  measured 10 red of 58: the three, `scrub_text_masks_a_value_on_the_next_line`,
  `scrub_text_reads_every_ascii_whitespace_as_blank`, `scrub_text_is_unchanged_on_the_recorded_corpus`, and four
  wide tests); AC7 stays green (it is not about line breaks: its bite is mutant M2 in Task 8). Paste the red
  names, then `rm -rf "$SCRATCH"`.
- **Green (paste):** `cargo test -p aitm-core --offline --lib redact::tests` prints `test result: ok. 58 passed`;
  `cargo test -p aitm-core --offline --lib redact` prints `test result: ok. 60 passed`.
- **Checks (paste each output):**
  - `git -C WT diff -U0 61a35571 -- crates/aitm-core/src/redact.rs | grep -E '^-' | grep -vE '^---' | wc -l`
    prints `0` (only additions: AC12's start).
  - `git -C WT diff -U0 61a35571 -- crates/aitm-core/src/redact.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p' | sort
    -n | head -1` prints a number at least `511` (nothing but test code).
  - `git -C WT diff --stat 61a35571 -- crates/aitm-core` names only `crates/aitm-core/src/redact.rs`.
- **Gate (sandbox):** `rustfmt --edition 2021 <redact.rs>` then `--check` exits 0; `cargo clippy -p aitm-core
  --all-targets --offline -- -D warnings` exits 0; `cargo test -p aitm-core --offline --no-fail-fast` fails only
  `proxy::tests::acceptor_attaches_the_scope_guard_to_the_module_ctx` (NOT RUN (socket)).
- **Commit:** `test(redact): task 1, pin scrub_text on the nested-pair guard rows (plan
  2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-core/src/redact.rs`. Report `S1`.
- **Done when:** the bite-check names, the green runs, the three checks and the gate are quoted and the commit is made.

### Task 2: pin `scrub_embedded` on the unchanged tree (scanner, `[guard]`)

- **Satisfies:** AC17.
- **Depends on:** none. **Parallel with:** Tasks 1, 6. **Dispatch inputs:** spec path, plan path, `WT`, task 2, `BASE`.
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` (modify, inside `mod tests` only: append after the last
  test `build_poc_masks_a_nested_standard_pair_under_a_wide_only_key`, before the module's closing brace).
- **Change:** one test, `scrub_embedded_keeps_the_output_it_had_for_a_value_that_looks_like_a_pair` (AC17), through the
  existing `embedded_mismatches` (no new helper). Eight rows: `token:\n  YWJj=`, `password:\n  s3cr:et`, `token:\n
  AApwdBB=`, `password:\n  sid:abc`, `password:\n  user:pass`, `token:\n  dXNlcjpwYXNz` each give `<parent>:\n
  [redacted]` (so `token:\n  [redacted]`, `password:\n  [redacted]`); `auth:\n  user: bob` gives `auth:\n  [redacted]
  bob`; `auth:\n  creds:\n    password: hunter2` gives `auth:\n  [redacted]\n    password: [redacted]`. (I ran all
  eight on the new rule in a scratch copy: identical; they must be identical on the old tree, and you record
  that by running them there.)
- **Red:** none (`[guard]`). **Bite check:** temporarily make `scrub_embedded` return `text.to_string()` (the one
  production line, 377), run `cargo test -p aitm-plugin-scanner --offline --lib scrub_embedded_keeps_the_output`:
  it must fail with the rows `token:\n  YWJj=` and the others in the mismatch list. Restore the line by hand (do not
  restore from git: your tests are uncommitted) and paste the check below proving it.
- **Green (paste):** `cargo test -p aitm-plugin-scanner --offline --lib scrub_embedded_keeps_the_output_it_had_for_a_value_that_looks_like_a_pair`
  prints `test result: ok. 1 passed`; `cargo test -p aitm-plugin-scanner --offline --lib` prints `test result: ok.
  198 passed`.
- **Checks (paste each output):**
  - `git -C WT diff -U0 61a35571 -- crates/aitm-plugin-scanner/src/reproduce.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p'
    | sort -n | head -1` prints a number at least `483` (the bite check left no production edit).
  - `git -C WT diff -U0 61a35571 -- crates/aitm-plugin-scanner/src/reproduce.rs | grep -E '^-' | grep -vE '^---' | wc -l` prints `0`.
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `reproduce.rs` exits 0; `cargo clippy -p
  aitm-plugin-scanner --all-targets --offline -- -D warnings` exits 0; the scanner test run above.
- **Commit:** `test(scanner): task 2, pin scrub_embedded on values that look like a pair (plan
  2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-plugin-scanner/src/reproduce.rs`.
  Report `S2`.
- **Done when:** the bite-check failure, the green runs, the checks and the gate are quoted and the commit is made.

### Task 6: the aitm-poc builder test (`[red]`)

- **Satisfies:** AC21.
- **Depends on:** none. **Parallel with:** every task before Task 7. **Dispatch inputs:** spec path, plan path, `WT`,
  task 6, `BASE`.
- **Files:** `crates/aitm-poc/tests/builder.rs` (modify: append one test after `build_drops_credential_in_duplicate_json_key`).
  The stale comment at line 647 stays untouched.
- **Change:** one test, `build_masks_a_credential_nested_under_a_secret_parent_on_every_surface`, through the real
  `StdPocBuilder.build(&flow, basic_spec())` and `flow_with(path, Body)`; each surface is a separate flow, each
  output read with `http_step(&poc)`:
  - url: path `/go?q=hello&note=auth:\n  password: URLPW1` (a real line break in the string) gives the step `url`
    `{{target}}/go?{{param}}=hello&note=auth:\n  [redacted] [redacted]`;
  - JSON: body `{"note":"auth:\n  password: JSONPW2","list":["credentials:\r\n\tsecret: JSONSEC9"]}` (raw string,
    so `\n` is the two characters; JSON decodes it) gives, once parsed with `serde_json`, the value `{"note":
    "auth:\n  [redacted] [redacted]", "list": ["credentials:\r\n\t[redacted] [redacted]"]}`;
  - form: body `note=auth:\n  password: FORMPW3&page=2` gives `note=auth:\n  [redacted] [redacted]&page=2`;
  - text: body `auth:\n  password: RAWPW4` gives `auth:\n  [redacted] [redacted]`.
  None of `URLPW1`, `JSONPW2`, `JSONSEC9`, `FORMPW3`, `RAWPW4` is in `serde_json::to_string(&poc)` for its surface.
  (All four outputs are the ones I measured on the new rule in a scratch copy; on the unchanged core each surface
  keeps its canary, for example the url reads `...&note=auth:\n  [redacted] URLPW1`.)
- **Red (paste):** `cargo test -p aitm-poc --offline --test builder` prints `test result: FAILED. 23 passed; 1
  failed` and names exactly `build_masks_a_credential_nested_under_a_secret_parent_on_every_surface`; quote the
  first assertion's left and right values (the url surface: the canary `URLPW1` is in the left value).
- **Green:** none in this task (it goes green in Task 7).
- **Checks (paste each output):** `git -C WT diff -U0 61a35571 -- crates/aitm-poc | grep -E '^-' | grep -vE '^---' |
  wc -l` prints `0`; `git -C WT diff --stat 61a35571 -- crates/aitm-poc` names only `crates/aitm-poc/tests/builder.rs`.
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `builder.rs` exits 0; `cargo clippy -p aitm-poc
  --all-targets --offline -- -D warnings` exits 0; the red run above is the test run (`tests/run.rs` and
  `tests/target.rs` are NOT RUN (socket)).
- **Commit:** `test(poc): task 6, a credential nested under a secret parent on every surface (red; plan
  2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-poc/tests/builder.rs`. Report `S6`.
- **Done when:** the red run, the checks and the gate are quoted and the commit is made.

### Task 3: the new core `[red]` tests

- **Satisfies:** AC1, AC2, AC3, AC6b, AC8, AC9, AC10.
- **Depends on:** Task 1 committed (`S1` an ancestor of HEAD; same file; it reuses `padded_credentials`).
  **Parallel with:** Tasks 5, 6. **Dispatch inputs:** spec path, plan path, `WT`, task 3, `S1`.
- **Files:** `crates/aitm-core/src/redact.rs` (modify, inside `mod tests`: append after Task 1's tests).
- **Change:** seven tests, exact names; rows are the spec's, outputs are the new outputs (the spec's AC text and
  Design 6 are the authority). Use `mismatches` for the standard reading and `mismatches_wide` for the wide:
  1. `scrub_text_masks_a_credential_nested_under_a_secret_parent` (AC1): for each parent in `auth`, `credentials`,
     `secret`, `token`, `session`, `cookie`, `password`, `sid`, `jwt`, `csrf`, `api_key` (in that order) and each
     layout in `"\n  "`, `"\r\n  "`, `"\n\t"`, `"\r  "`, `"\u{c}  "`, `"\n    "`: `{parent}:{layout}password: hunter2` gives
     `{parent}:{layout}[redacted] [redacted]` (66 rows); plus `token:\r\n\tsid: S1` gives `token:\r\n\t[redacted]
     [redacted]` and `session:\n  csrf: C9` gives `session:\n  [redacted] [redacted]`. Assert at least 68 rows.
  2. `scrub_text_masks_a_nested_credential_in_every_separator_and_quote_form` (AC2): the seven rows of spec AC2, from
     `"auth":\n  "password": "x"` giving `"auth":\n  "[redacted]": "[redacted]"` to `auth:\n\n\n\n\n  password: x`
     giving `auth:\n\n\n\n\n  [redacted] [redacted]`.
  3. `scrub_text_reads_every_pair_of_a_chain_of_secret_keys` (AC3): rows 11 to 16 of spec Design 6, new outputs, from
     `token:\n  sid:\n  password: hunter2` giving `token:\n  [redacted]\n  [redacted] [redacted]` to `sid:\nsid:\nsid:\n` giving
     `sid:\n[redacted]\n[redacted]\n`.
  4. `scrub_text_masks_a_padded_base64_credential_under_a_nested_pair` (AC6b): for every pair of `padded_credentials()`
     (the parent is ignored), `scrub_text("auth:\n  password:\n    {credential}")` equals `auth:\n  [redacted]\n    [redacted]`.
  5. `scrub_text_stays_linear_on_nested_pair_shapes` (AC8), `assert!` on `==` with a short message per family:
     `"auth:\n  password: x\n".repeat(50_000)` gives `"auth:\n  [redacted] [redacted]\n".repeat(50_000)`;
     `"sid:\n".repeat(100_000)` gives `"sid:\n".to_string() + &"[redacted]\n".repeat(99_999)`;
     `"password:\n password:\n".repeat(50_000)` gives `"password:\n [redacted]\n".to_string() + &"[redacted]\n
     [redacted]\n".repeat(49_999)`; `format!("auth:{}  password: x", "\n".repeat(1 << 19))` gives `format!("auth:{}  [redacted]
     [redacted]", ...)` with the same breaks; `format!("token=\"{}\"", "a=".repeat(1 << 20))` gives `token="[redacted]"`;
     `format!("{}x\"", "sid:\"".repeat(200_000))` gives `sid:"[redacted]"`; `"token=\"sid: \" tail=\"x\" ".repeat(100_000)`
     gives `"token=\"[redacted]\" tail=\"x\" ".repeat(100_000)`. Keep every family at 1 MiB or more; the builder may shrink a
     repeat count only if a debug-build run is slow, never below 1 MiB. The test finishing is the check.
  6. `scrub_text_wide_masks_a_next_line_credential_under_a_wide_only_parent` (AC9, `mismatches_wide`): the seven rows of
     spec AC9, from `userSession:\n  S3SS10N9` giving `userSession:\n  [redacted]` to `sidebar\n:v` giving `sidebar\n:[redacted]`.
  7. `scrub_text_wide_masks_a_wide_only_pair_nested_under_a_standard_parent` (AC10, `mismatches_wide`): the four rows of
     spec AC10: `auth:\n  sessionKey: abc123` gives `auth:\n  [redacted] [redacted]`; `auth: sessionKey: abc123` gives `auth:
     [redacted] [redacted]`; `jwt:\n\tsidebar :  "Q"` gives `jwt:\n\t[redacted] :  "[redacted]"`; `Credentials:\n\tjwt:\n\tsidebar
     :  "Q"` gives `Credentials:\n\t[redacted]\n\t[redacted] :  "[redacted]"`.
- **Red (paste):** `touch` the file, then `cargo test -p aitm-core --offline --lib redact` prints `test result: FAILED. 60
  passed; 7 failed` (65 `redact::tests` plus the 2 `tunnel` tests; 58 + 2 pass), and the seven failing names are
  **exactly** the seven above. For each, quote its first bad row or its panic message; on the unchanged core the
  first bad row reads (input, expected, actual): AC1 `auth:\n  password: hunter2`, `auth:\n  [redacted] [redacted]`,
  `auth:\n  [redacted] hunter2`; AC2 `"auth":\n  "password": "x"` with actual `"auth":\n  "[redacted]": "x"`; AC3
  `token:\n  sid:\n  password: hunter2` with actual `token:\n  [redacted]\n  password: [redacted]`; AC9
  `userSession:\n  S3SS10N9` with actual the input unchanged; AC10 `auth:\n  sessionKey: abc123` with actual `auth:\n
  [redacted] abc123`. AC6b and AC8 fail on their first assertion (AC6b: the credential is left in the clear after
  `auth:\n  [redacted]\n    `). If any other test fails, stop and report.
- **Green:** none in this task (it goes green in Task 7).
- **Checks (paste each output):** the three checks of Task 1 (no removed line; hunk-start at least `511`; `git diff
  --stat 61a35571 -- crates/aitm-core` names only `redact.rs`), run on the cumulative diff since `BASE`.
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `redact.rs` exits 0; `cargo clippy -p aitm-core
  --all-targets --offline -- -D warnings` exits 0; the red run above.
- **Commit:** `test(redact): task 3, failing tests for the nested-pair leak (red by design; plan
  2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-core/src/redact.rs`. Report `S3`.
- **Done when:** the red run with the seven names, the checks and the gate are quoted and the commit is made.

### Task 4: AC11, the named edits of existing wide tests, the renames, the one deletion (core)

- **Satisfies:** AC11, the AC24 grep for the tests, and AC12 (nothing else changes).
- **Depends on:** Task 3 committed (same file). **Parallel with:** Tasks 5, 6. **Dispatch inputs:** spec path, plan
  path, `WT`, task 4, `S3`.
- **Files:** `crates/aitm-core/src/redact.rs` (modify, inside `mod tests`). Line numbers below are `BASE`'s and
  are still right at the start of this task (Tasks 1 and 3 only appended after line 2474); anchor by name if
  they drift.
- **Step list (do these and only these; the order is the order of the file):**
  1. **`NESTED_UNDER_A_WIDE_ONLY_KEY`** (2094 to 2113). Edit the output column of rows 1 to 4 and nothing else:
     | # | input (unchanged) | new output |
     |---|---|---|
     | 1 | `authentication:\n  password: hunter2` | `authentication:\n  [redacted] [redacted]` |
     | 2 | `author:\n  token: abc123` | `author:\n  [redacted] [redacted]` |
     | 3 | `sessions:\n  jwt: J1` | `sessions:\n  [redacted] [redacted]` |
     | 4 | `sidebar:\n    api_key: K1` | `sidebar:\n    [redacted] [redacted]` |
     Rows 5 to 9 (`authentication: {password: hunter2}`, `sidebar=sid="C1"`, `author=password='C2'`,
     `inside=x?sid\t=\tC9`, `Auths:Pwd: C`) stay byte for byte. Comment-only: the section comment at 2088
     ("The wide scrub is the standard scan, then the wide scan over its output") and the const doc at 2090 to 2093
     ("with the output of the old two-scan pipeline ... the standard scan runs first so that the nested pair is
     already masked") say what the rows now show: the parent takes the child's label as its value and the child
     masks its own; rows 5 to 9 are one-line shapes the rule leaves as they were.
  2. **`LINE_BREAK_IS_A_BOUNDARY`** (2118 to 2131): rename to `PAIR_ACROSS_A_LINE_BREAK` at its definition, in
     `scrub_text_wide_keeps_a_line_break_as_a_boundary` (2206) and in `corpus_inputs` (2221), three places and no
     others. Rows 1 to 7 get these outputs:
     | # | input (unchanged) | new output |
     |---|---|---|
     | 1 | `side:\nSid2':C` | `side:\n[redacted]':[redacted]` |
     | 2 | `authentication:\n  sessionKey: abc123` | `authentication:\n  [redacted] [redacted]` |
     | 3 | `bsid:\rSIDE:'C` | `bsid:\r[redacted]'[redacted]` |
     | 4 | `author:\nJohn` | `author:\n[redacted]` |
     | 5 | `sidebar:\r\nv` | `sidebar:\r\n[redacted]` |
     | 6 | `sidebar\n:v` | `sidebar\n:[redacted]` |
     | 7 | `sidebar=\u{c}v` | `sidebar=\u{c}[redacted]` |
     Row 8 (`sid:\nabc` gives `sid:\n[redacted]`) and the comment above it stay. Comment-only: the const doc at
     2115 to 2117 ("a pair is read on one line, so a line break leaves a wide-only key without a value") says the
     wide scrub reads across a line break and a pair that begins inside a masked value.
  3. **Rename the test** `scrub_text_wide_keeps_a_line_break_as_a_boundary` to
     `scrub_text_wide_reads_a_pair_across_a_line_break`; its body (`mismatches_wide(PAIR_ACROSS_A_LINE_BREAK)` and the
     assert) is otherwise untouched.
  4. **Delete** `skip_pair_blanks_leaves_only_the_three_line_breaks_to_the_wide_reading` together with its doc comment
     (the `/// The blank rule on the helper itself, at its boundaries.` block at 2225 to 2231, the `#[test]`, the
     function to its closing brace at 2289) and the blank line after it. The doc block must not be left behind
     (it would attach to the next test). Comment-only: the section comment at 2210 to 2212 ("the helper at its
     boundaries, a pair read on one line beside non-ASCII spaces") loses the helper and says a pair read across a
     line break beside non-ASCII spaces.
  5. **`scrub_text_wide_reads_a_pair_on_one_line_beside_non_ascii_spaces`** (2291 to 2343): rename to
     `scrub_text_wide_reads_a_pair_across_a_line_break_beside_non_ascii_spaces`. Of its ten rows exactly these six
     change (input unchanged):
     | # | input | new output |
     |---|---|---|
     | 1 | `sidebar:\u{a0}\nJohn` | `sidebar:\u{a0}\n[redacted]` |
     | 2 | `author\u{a0}\n:John` | `author\u{a0}\n:[redacted]` |
     | 3 | `author\u{c}=John` | `author\u{c}=[redacted]` |
     | 4 | `sidebar:\n\u{a0}sessionKey: abc123` | `sidebar:\n\u{a0}[redacted] [redacted]` |
     | 5 | `authentication:\u{2009}\r\n\u{2009}jwt:\u{a0}J1` | `authentication:\u{2009}\r\n\u{2009}[redacted]\u{a0}[redacted]` |
     | 9 | `authentication:\r\n  password: hunter2` | `authentication:\r\n  [redacted] [redacted]` |
     The other four rows (`sid\u{a0}\n\u{a0}:\u{a0}\n\u{a0}abc`, `jwt:\u{2028}\u{c}J1`, `sid\u{c}=abc`, `X-Authority:
     example.com\r\nX-Sid: S1\r\n`) and the JSON-escaped-newline check after the table (2334 to 2342) stay byte for
     byte. Comment-only: the doc at 2291 to 2295 (this is the line the AC24 grep matches) and the inline comments
     at 2299 to 2300 and 2304 to 2305 describe the new behaviour (a line break is read across; a key on the next
     line after a non-ASCII space is masked as the value of the wide-only key above it).
  6. **`scrub_text_wide_stays_linear_on_line_break_shapes`** (2435 to 2474): five of its six assertions change, the
     `repeat` counts and inputs do not:
     | # | input (unchanged) | new expected value |
     |---|---|---|
     | 1 | `"author:\n".repeat(1 << 17)` | `"author:\n".to_string() + &"[redacted]\n".repeat((1 << 17) - 1)` |
     | 2 | `"authentication:\n  sessionKey: x\n".repeat(50_000)` | `"authentication:\n  [redacted] [redacted]\n".repeat(50_000)` |
     | 3 | `"authentication:\n  password: x\n".repeat(50_000)` | `"authentication:\n  [redacted] [redacted]\n".repeat(50_000)` |
     | 4 | `"sid:\n".repeat(100_000)` | `"sid:\n".to_string() + &"[redacted]\n".repeat(99_999)` |
     | 5 | `format!("sidebar{breaks}=v")`, `breaks` = `"\n".repeat(1 << 19)` | `format!("sidebar{breaks}=[redacted]")` |
     Assertion 6 (`sid{breaks}=v` gives `sid{breaks}=[redacted]`) stays byte for byte. Update the five assertion
     messages and the comments at 2436 to 2437, 2444, 2456 to 2457 and 2464 to 2465 so none states the old behaviour.
  7. **Nothing else.** No other test, helper, const, row or comment of the file changes. `RECORDED_SCRUB_TEXT` is
     untouched. If any other existing test fails in the red run below, or any row not listed here seems to need an
     edit: **stop and report** with the test name and the actual output.
- **Red (paste):** `touch` the file, then `cargo test -p aitm-core --offline --lib redact::tests` prints `test result:
  FAILED. 53 passed; 11 failed` (64 tests), and the eleven names are **exactly** Task 3's seven plus
  `scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key`, `scrub_text_wide_reads_a_pair_across_a_line_break`,
  `scrub_text_wide_reads_a_pair_across_a_line_break_beside_non_ascii_spaces` and
  `scrub_text_wide_stays_linear_on_line_break_shapes`. Quote each of those four's first bad row or panic. On the
  unchanged core they read (input, expected, actual): `authentication:\n  password: hunter2`, `authentication:\n
  [redacted] [redacted]`, `authentication:\n  password: [redacted]`; `side:\nSid2':C`, `side:\n[redacted]':[redacted]`,
  `side:\nSid2':[redacted]`; `sidebar:\u{a0}\nJohn`, `sidebar:\u{a0}\n[redacted]`, the input unchanged; and the linear
  test's first changed assertion panics.
- **Green:** none in this task (Task 7).
- **Checks (paste each output):**
  - `git -C WT diff -U0 61a35571 -- crates/aitm-core/src/redact.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p' | sort -n
    | head -1` prints a number at least `2088` (nothing before the nesting section changed: `RECORDED_SCRUB_TEXT` and
    the 40-odd earlier tests are untouched).
  - Names, from git (the recipe prints 54 on `BASE`): `git -C WT show 61a35571:crates/aitm-core/src/redact.rs | awk
    '/^    #\[test\]/ {t=1; next} t && /^    fn / {match($0,/fn [A-Za-z0-9_]+/); print substr($0,RSTART+3,RLENGTH-3);
    t=0}' | sort > "$TMPDIR/core-names-before.txt"`, the same on `redact.rs` of the worktree into `...-after.txt`;
    `wc -l` prints `54` for the before list and `64` for the after list; `comm -23 before after` prints exactly the three
    removed names (`scrub_text_wide_keeps_a_line_break_as_a_boundary`,
    `scrub_text_wide_reads_a_pair_on_one_line_beside_non_ascii_spaces`,
    `skip_pair_blanks_leaves_only_the_three_line_breaks_to_the_wide_reading`); `comm -13 before after` prints exactly
    thirteen names: Task 1's four, Task 3's seven, and the two renames.
  - `grep -n "LINE_BREAK_IS_A_BOUNDARY" crates/aitm-core/src/redact.rs` prints nothing; `grep -c
    PAIR_ACROSS_A_LINE_BREAK crates/aitm-core/src/redact.rs` prints at least `3`.
  - The AC24 grep, `grep -nE "reads a pair on one line|one line by the wide|line break as a boundary|three declared|skip_pair_blanks"
    crates/aitm-core/src/redact.rs`, printed 14 lines on `BASE` (production 31, 185, 297, 301, 398, 406, 448, 473;
    test 2233, 2267, 2268, 2287, 2288, 2291) and now prints **exactly the eight production lines** (Task 7 removes them).
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `redact.rs` exits 0; `cargo clippy -p aitm-core
  --all-targets --offline -- -D warnings` exits 0 (the deleted test leaves no dead code: `skip_pair_blanks` is
  still used by production until Task 7); the red run above.
- **Commit:** `test(redact): task 4, AC11: the named wide-test edits, two renames, one deletion (red by design;
  plan 2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-core/src/redact.rs`. Report `S4`.
- **Done when:** the red run with the eleven names, the four first-bad-rows, every check and the gate are quoted and
  the commit is made.

### Task 5: the scanner `[red]` tests, the row edits, the two doc edits

- **Satisfies:** AC15, AC16, AC18, AC19, the docs items 8 and 9 of Design 7, and AC20 (nothing else changes).
- **Depends on:** Task 2 committed (same file; `S2` an ancestor). **Parallel with:** Tasks 3, 4, 6. **Dispatch inputs:**
  spec path, plan path, `WT`, task 5, `S2`.
- **Files:** `crates/aitm-plugin-scanner/src/reproduce.rs` only. `crawl.rs`, `commands.rs`, `discover.rs`,
  every `Cargo.toml` and `Cargo.lock` stay untouched.
- **Change, in this order (tests first):**
  1. Append three tests after the last test of `mod tests` (Task 2's), using the existing `embedded_mismatches`,
     `flow_with_query`, `flow_with`, `point`, `http_step`:
     - `scrub_embedded_nested_pair_changes_are_exactly_these` (AC15): ten rows, each `(input, new output)` with the old
       output in a comment of the form `// old pipeline at 15009b2: <old output>` (written without a banned phrase),
       asserted through `embedded_mismatches` (a mismatch list, so one red run shows every old output), `rows.len() >=
       10`, and one assertion that no input of the table is still an input of `RECORDED_SCRUB_EMBEDDED` (call 7):
       | # | input | new output | old output (comment) |
       |---|---|---|---|
       | 1 | `authentication:\n  password: hunter2` | `authentication:\n  [redacted] [redacted]` | `authentication:\n  password: [redacted]` |
       | 2 | `author:\n  token: abc123` | `author:\n  [redacted] [redacted]` | `author:\n  token: [redacted]` |
       | 3 | `sessions:\n  jwt: J1` | `sessions:\n  [redacted] [redacted]` | `sessions:\n  jwt: [redacted]` |
       | 4 | `sidebar:\n    api_key: K1` | `sidebar:\n    [redacted] [redacted]` | `sidebar:\n    api_key: [redacted]` |
       | 5 | `authentication:\n  sessionKey: abc123` | `authentication:\n  [redacted] [redacted]` | `authentication:\n  sessionKey: [redacted]` |
       | 6 | `side:\nSid2':C` | `side:\n[redacted]':[redacted]` | `side:\nSid2':[redacted]` |
       | 7 | `bsid:\rSIDE:'C` | `bsid:\r[redacted]'[redacted]` | `bsid:\rSIDE:'[redacted]` |
       | 8 | `author:\nJohn` | `author:\n[redacted]` | unchanged |
       | 9 | `sidebar\n:v` | `sidebar\n:[redacted]` | unchanged |
       | 10 | `sidebar=\u{c}v` | `sidebar=\u{c}[redacted]` | unchanged |
     - `scrub_embedded_masks_a_nested_credential_under_a_secret_or_a_wide_only_parent` (AC16), `embedded_mismatches`:
       `auth:\n  password: hunter2` gives `auth:\n  [redacted] [redacted]`; `credentials:\r\n\tsecret: S1` gives
       `credentials:\r\n\t[redacted] [redacted]`; `auth:\n  sessionKey: abc123` gives `auth:\n  [redacted] [redacted]`;
       `userSession:\n  S3SS10N9` gives `userSession:\n  [redacted]`; `sidebar:\nS3SS10N9` gives `sidebar:\n[redacted]`;
       `see http://u:pw@host/x\nauth:\n  password: hunter2` gives `see http://host/x\nauth:\n  [redacted] [redacted]`.
     - `build_poc_masks_a_credential_nested_under_a_secret_parent` (AC18), through the real `build_poc` with
       `CheckDefinition::reflected_xss()` and its first payload, injection point `q`:
       url (`flow_with_query`, path `/go?q=hello&note=auth%3A%0A%20%20password%3A%20URLPW1`) gives the step `url`
       `{{target}}/go?q=%3Caitm-canary-0001%3E&note=auth%3A%0A++%5Bredacted%5D+%5Bredacted%5D`; JSON body (`Content-Type:
       application/json`, raw string `{"note":"auth:\n  password: JSONPW2","list":["credentials:\r\n\tsecret:
       JSONSEC9"]}`) gives, parsed, `{"note": "auth:\n  [redacted] [redacted]", "list": ["credentials:\r\n\t[redacted]
       [redacted]"]}`; form body (`application/x-www-form-urlencoded`, `note=auth%3A%0A++password%3A+FORMPW3&page=2`)
       gives `note=auth%3A%0A++%5Bredacted%5D+%5Bredacted%5D&page=2`; a body with no content type, `auth:\n  password:
       RAWPW4`, gives `auth:\n  [redacted] [redacted]`. None of the five canaries (`URLPW1`, `JSONPW2`, `JSONSEC9`,
       `FORMPW3`, `RAWPW4`) is in `serde_json::to_string(&poc)` of its surface. (All outputs measured on the new rule
       in a scratch copy.)
  2. **Edit the existing `build_poc_masks_a_nested_standard_pair_under_a_wide_only_key` (AC19): four values, no other
     line.** The JSON `note` expectation becomes `authentication:\n  [redacted] [redacted]` and its `list` becomes
     `["author:\n  [redacted] [redacted]"]`; the form `note` becomes `authentication:\n  [redacted] [redacted]`; the
     untyped body expectation becomes `authentication:\n  [redacted] [redacted]`. The `memo` leaf, the `X-Note` header, the
     canaries, the truncated-JSON case and the test's doc stay.
  3. **Remove ten rows from `RECORDED_SCRUB_EMBEDDED`** (the `(xii)` group, `BASE` 1995 to 2023): exactly the inputs of
     rows 1 to 10 of the AC15 table (the old outputs are the recorded ones above). Rewrite the comment above the group
     (1995 to 1996, "a line break or form feed beside the separator of a wide-only key" goes) so it says the group is
     a standard-secret pair nested under a wide-only parent on one line, the shapes the nested-pair rule leaves as
     they were. **Five rows of that group stay byte for byte:** `authentication: {password: hunter2}`,
     `sidebar=sid="C1"`, `author=password='C2'`, `inside=x?sid\t=\tC9`, `Auths:Pwd: C`. The corpus goes from 162 to 152 rows (the
     `>= 80` assertion and the distinct-input assertion stay). **If any other row would need to change, stop and
     report.** The doc of `scrub_embedded_matches_the_recorded_pipeline_output` keeps saying "the recorded output of the
     old two-scan pipeline at `15009b2`" (true of the rows that stay).
  4. **Doc of `scrub_embedded`** (364 to 375, spec Design 7 item 8): replace "it runs core's one pair scan twice, first with
     the standard reading and then with the wide one" with a description that the two scans differ in the key test
     inside a masked value (the first scan judges a key run that begins inside a value it masked by the wide
     vocabulary), and that a pair that begins inside a masked value, and a line break beside a separator, are read.
     Keep the userinfo sentence and the sentence that this scrub and `is_secret_name` judge a key by the same
     predicate. No banned phrase, no code beyond a signature.
- **Red (paste):** `touch` `reproduce.rs` (never `redact.rs`: this Coder does not touch it), then
  `cargo test -p aitm-plugin-scanner --offline --lib` prints `test result: FAILED. 197 passed; 4 failed` (201 tests), and
  the four names are **exactly** `reproduce::tests::scrub_embedded_nested_pair_changes_are_exactly_these`,
  `reproduce::tests::scrub_embedded_masks_a_nested_credential_under_a_secret_or_a_wide_only_parent`,
  `reproduce::tests::build_poc_masks_a_credential_nested_under_a_secret_parent` and
  `reproduce::tests::build_poc_masks_a_nested_standard_pair_under_a_wide_only_key`. Paste AC15's mismatch list: all ten rows,
  each `actual` equal to its old output in the table (a difference stops the Coder: spec gap). Also paste that
  `scrub_embedded_matches_the_recorded_pipeline_output` and `scrub_embedded_deliberate_changes_are_exactly_these` are
  `ok`. Any other failing test: stop and report.
- **Green:** none in this task (Task 7).
- **Checks (paste each output):**
  - Hunk starts below 483 are only the `scrub_embedded` doc: `git -C WT diff -U0 61a35571 --
    crates/aitm-plugin-scanner/src/reproduce.rs | grep '^@@'`; say which hunk is the doc (old start 364 to 375) and that
    every other hunk starts at 483 or later.
  - Names from git, per file (the recipe prints 45 on `BASE` for `reproduce.rs`): before 45; after 49 (Task 2's one and
    this task's three); `comm -13` prints exactly four names; `comm -23` prints nothing.
  - `git -C WT diff --stat 61a35571 -- crates/aitm-plugin-scanner` names only `reproduce.rs`; `git -C WT diff --stat 61a35571 --
    crates/aitm-plugin-scanner/src/crawl.rs crates/aitm-plugin-scanner/src/commands.rs` prints nothing.
  - Rows: `RECORDED_SCRUB_EMBEDDED` has 152 rows (162 on `BASE`; count the top-level row lines between the const's
    `= &[` and its closing `];`, with the same count run on `git -C WT show 61a35571:<file>` printing 162, so the method is
    proven). Then show that none of the ten inputs of the AC15 table is still in the const and that the five kept `(xii)`
    rows (`authentication: {password: hunter2}`, `sidebar=sid="C1"`, `author=password='C2'`, `inside=x?sid\t=\tC9`,
    `Auths:Pwd: C`) are, for example by `git -C WT diff -U0 61a35571 -- crates/aitm-plugin-scanner/src/reproduce.rs` showing
    those ten rows (and only rows of the `(xii)` group, plus the comment) as removed lines.
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `reproduce.rs` exits 0; `cargo clippy -p
  aitm-plugin-scanner --all-targets --offline -- -D warnings` exits 0; the red run above.
- **Commit:** `test(scanner): task 5, nested-pair rows, four edited expectations, ten rows moved out of the recorded
  corpus (red by design; plan 2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path
  `crates/aitm-plugin-scanner/src/reproduce.rs`. Report `S5`.
- **Done when:** the red run with the four names, the AC15 mismatch list, the checks and the gate are quoted and the
  commit is made.

### Task 7: the rule (R1 to R4), the third `Reading` value, the docs (core production)

- **Satisfies:** AC1 to AC3, AC6b, AC8 to AC12 (green), AC14, the AC24 grep; and, by effect, AC15, AC16, AC18, AC19 and AC21
  going green.
- **Depends on:** Tasks 4, 5 and 6 committed (`S4`, `S5`, `S6` ancestors; so `S1` to `S3` too). **Alone in the worktree.**
  **Dispatch inputs:** spec path, plan path, `WT`, task 7, `S4`, `S5`, `S6`.
- **Files:** `crates/aitm-core/src/redact.rs` (production code and docs; **no edit to `mod tests`**).
- **Start checks (paste each):** `git -C WT merge-base --is-ancestor <S4|S5|S6> HEAD` exits 0 for each; core production is
  still `BASE`'s: `git -C WT diff -U0 61a35571 -- crates/aitm-core/src/redact.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p' |
  sort -n | head -1` prints at least `511` *before* your first edit; and the baseline red run
  `cargo test -p aitm-core --offline --lib redact::tests` prints `53 passed; 11 failed` (Task 4's red set).
- **Change (signatures and edit regions; spec Design 2, 3 and 7 are the authority; names are this plan's call 4):**
  - `enum Reading` (private, 216 to 223): add the variant `FirstOfWide`. Variant docs: `Standard` is [`is_secret_key`], a
    host:port is exempt; `Wide` is [`is_secret_key_wide`], nothing is exempt; `FirstOfWide` judges a key run that
    begins inside a value the scan just masked by [`is_secret_key_wide`] and every other key run by
    [`is_secret_key`], with the standard host:port exemption. All three skip every whitespace character beside a
    separator.
  - **Delete** `fn skip_pair_blanks(text: &str, mut i: usize, reading: Reading) -> usize` and its doc (291 to 314). Its
    two call sites in `mask_secret_pairs` (448, 473) call `skip_blanks(text, j)`. `skip_blanks` and its doc stay.
  - add private `fn apply_patterns(text: &str) -> String`: the two regex passes of `patterns()` in order (the loop that
    is now the first lines of `scrub_text`). `pub fn scrub_text(text: &str) -> String` becomes `mask_secret_pairs(&apply_patterns(text),
    Reading::Standard)`. `pub fn scrub_text_wide(text: &str) -> String` becomes `mask_secret_pairs` with `Reading::Wide` over
    `mask_secret_pairs` with `Reading::FirstOfWide` over `apply_patterns(text)`. No signature of a public item changes.
  - `fn mask_secret_pairs(text: &str, reading: Reading) -> String` keeps its signature. Edits to the body (anchors are
    `BASE` lines; do them in the step order below):
    - a new local `masked_to: usize`, initially `0`, beside `copied` (429 to 431);
    - **R2'**, right after `j += 1;` that follows `let separator = bytes[j];` (452 to 453) and before the vocabulary is
      consulted: if `j < copied`, `continue` (the scan goes on after the key run, as for a non-secret key). It changes no output;
      it only keeps a long masked value full of nested keys from costing one lowercase allocation each;
    - **R3**, the key test (458 to 461): three arms. `Standard` is `is_secret_key(key)`; `Wide` is `is_secret_key_wide(key)`;
      `FirstOfWide` is `is_secret_key_wide(key)` when `key_start < copied` and `is_secret_key(key)` otherwise;
    - the host:port exemption (465) applies to every reading except `Wide` (`reading != Reading::Wide`), the rest of its
      condition unchanged;
    - **R2**, right after the second blank skip (473) and before the opening-quote handling: if `j < masked_to`, `continue`
      (no value, no closing-quote search);
    - **R1**, the tail of a masked pair (502 to 505): `copied = value_end` stays; `masked_to` becomes `value_end` plus one when
      `closer.is_some()` (the closing quote is part of the masked text) and `value_end` otherwise; and the scan resumes at
      **`value_start`**, not `value_end` (`i = value_start`).
    - The word `reading` appears in no comment inside the body (AC14).
  - **Docs (spec Design 7 items 1 to 6; check each off in the report):** (1) the module doc 16 to 35: the first scan of the wide
    scrub reads like `scrub_text`'s except that a key run inside a value it has masked is judged by the wide reading, the
    second is the wide scan, they share every blank, value and quote rule, and differ in the key test, the host:port
    exemption and the key test inside a masked value; delete the `\n`, `\r`, `\x0c` sentences and the `author:\nJohn` /
    `sid:\nabc` pair; say a pair that begins inside a masked value is read. (2) the `scrub_text` doc 131 to 163: add that a
    secret pair that begins inside a value just masked is read too (`auth:\n  password: hunter2` masks `hunter2`), what stays
    (`auth:\n  user: bob` keeps `bob`; a value that looks like a pair stays masked whole), and that an empty value is left
    alone; keep the host:port paragraph. (3) the `scrub_text_wide` doc 172 to 207: rewrite per Design 2 and 3; remove "does not
    skip `\n`, `\r` or `\x0c`", "reads a pair on one line", the credential-on-the-next-line paragraph and the four-shape residual
    sentence (replace with the malformed-quote residual of spec Residual risks 3); say "masks everything `scrub_text` masks on
    well-formed input"; replace the timing sentence with "linear" and the bound Design 9 I4 checks (each doubling of the
    input costs at most 3.0 times the time, measured out of tree at 1 to 8 MiB), which Task 9 confirms. (4) the `Reading` docs:
    three variants and what each reads. (5) `skip_pair_blanks` and its doc are gone. (6) the `mask_secret_pairs` doc 392 to 423:
    `reading` is consulted in exactly two places (the key test with its in-region variant, and the host:port exemption); the
    scan resumes at a masked value's start; R2 and R2'; the linearity paragraph of spec Design 2 replaces "successful searches
    never overlap". No banned phrase; no code beyond a signature in a doc.
- **Step order, each step followed by `touch` and `cargo test -p aitm-core --offline --lib redact::tests` with the count pasted
  (these counts are measured; a different count stops the Coder):**
  | Step | Edit | Result |
  |---|---|---|
  | 0 | none (start) | `53 passed; 11 failed` |
  | A | R4: delete `skip_pair_blanks`, call `skip_blanks` | `55 passed; 9 failed` (AC9 and `scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key` go green) |
  | B | the `masked_to` local and its assignment from R1, R2', R2 (no output changes yet: `i` still resumes at `value_end`) | `55 passed; 9 failed` (same nine) |
  | C | `FirstOfWide`, R3, the host:port condition, `apply_patterns`, the new `scrub_text_wide` | `55 passed; 9 failed` (same nine) |
  | D | R1: `i = value_start` | `64 passed; 0 failed` |
  Step D before step B panics on `text[copied..value_start]` (mutant M1): do not reorder.
  The nine after step A are AC1, AC2, AC3, AC6b, AC8, AC10 and the three AC11 tests `scrub_text_wide_reads_a_pair_across_a_line_break`,
  `..._beside_non_ascii_spaces`, `scrub_text_wide_stays_linear_on_line_break_shapes`.
- **Green (paste):** `cargo test -p aitm-core --offline --lib redact` prints `test result: ok. 66 passed`;
  `cargo test -p aitm-plugin-scanner --offline --lib` prints `test result: ok. 201 passed` (AC15, AC16, AC18, AC19 green, the
  recorded corpus green); `cargo test -p aitm-poc --offline --test builder` prints `test result: ok. 24 passed`.
- **Checks (paste each output):**
  - AC14: `grep -n skip_pair_blanks crates/aitm-core/src/redact.rs` prints nothing; `sed -n '/^fn mask_secret_pairs/,/^}/p'
    crates/aitm-core/src/redact.rs | grep -c reading` prints `3` (the signature, the key test, the host:port exemption: name each
    line). I ran this on the intended shape in a scratch copy and got `3`.
  - AC24, docs: `grep -rnE "reads a pair on one line|one line by the wide|line break as a boundary|three declared|skip_pair_blanks"
    crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src` prints nothing (eight lines before this task); the banned-phrase grep
    of "Code constraints" (the 2026-10-31 phrases plus `by construction`) prints nothing over the same paths.
  - This task touched production and docs only, never `mod tests`: `git -C WT diff -U0 <S4> -- crates/aitm-core/src/redact.rs | sed -n
    's/^@@ -\([0-9][0-9]*\).*/\1/p' | sort -n | tail -1` prints a number below `511` (`S4` is the last commit that touched
    `redact.rs`; its `#[cfg(test)]` is still at line 511, so every hunk of this task starts above it).
  - No `unsafe`, no new public item: `git -C WT diff -U0 61a35571 -- crates | grep -E '^\+.*unsafe'` prints nothing; `git -C WT diff
    -U0 61a35571 -- crates | grep -E '^\+[[:space:]]*pub[ (]'` prints nothing; `git -C WT diff --stat 61a35571 -- '*.toml' Cargo.lock`
    prints nothing; `git -C WT diff --stat 61a35571 -- crates` names exactly `crates/aitm-core/src/redact.rs`,
    `crates/aitm-plugin-scanner/src/reproduce.rs` and `crates/aitm-poc/tests/builder.rs`.
  - Blast radius, each `test result: ok` with 0 failed (or only the socket failures of "Where each command runs", named):
    `cargo test -p aitm-findings -p aitm-scan-checks-http -p aitm-scan-ws -p aitm-plugins -p aitm-scan-model --offline --no-fail-fast`.
    (On the scratch rule I measured: `aitm-scan-ws` 192, `aitm-scan-checks-http` 73 and every integration binary green; the only failures
    were the three `aitm-plugins` socket tests.)
  - Core and scanner in one run: `cargo test -p aitm-core -p aitm-plugin-scanner --offline --no-fail-fast` fails only
    `proxy::tests::acceptor_attaches_the_scope_guard_to_the_module_ctx` (NOT RUN (socket)); aitm-poc is covered by `--test builder`
    above.
- **Gate (sandbox):** `rustfmt --edition 2021` then `--check` on `redact.rs` exits 0; `cargo clippy -p aitm-core -p aitm-plugin-scanner -p
  aitm-poc --all-targets --offline -- -D warnings` exits 0; the runs above.
- **Commit:** `fix(redact): read a secret pair that begins inside a masked value; the wide scrub reads across line breaks (plan
  2026-11-01-scrub-text-nested-pair-leak)`, with the trailer; path `crates/aitm-core/src/redact.rs`. Report `S7`.
- **Done when:** the four step counts, the three green runs, every check and the gate are quoted, Design 7 items 1 to 6 are listed as
  done, and the commit is made. If a Coder aborts on a content-policy fallback (this is redaction code) the orchestrator retries with
  another model; the plan does not change.

### Task 8 (Stage 5): Tester, whole branch

- **Satisfies:** AC12, AC13, AC14, AC20, AC22, AC24, and the coverage map for every AC.
- **Depends on:** Task 7 committed (`S7`). **Files:** tests only (the `#[cfg(test)]` modules of the three files); scratch copies
  and tool copies outside the repo. Never change production code in the branch. **Dispatch inputs:** spec path, plan path, `WT`, base
  `61a35571` (or the post-merge merge-base), head `S7`, "whole branch", the Coder reports of Tasks 1 to 7.
- **Work:**
  0. **Preserve the differential tools** (the originals are in `/tmp`, which may be cleared). With `DT="/Users/matt/Library/Application
     Support/Claude-3p/side-session-notes/local_ee73bb50-38b3-4011-be40-9e8688764e8f/diff-tools"`:
     `mkdir -p "$DT" && tar -C /tmp/claude-501 -cf - --exclude='nested-scratch/base' --exclude='nested-scratch/target-lab'
     --exclude='nested-scratch/spec-copy' --exclude='nested-scratch/lab/target' --exclude='__pycache__' nested-scratch
     svc-diff-tools svc-diff-tools-r2 | tar -C "$DT" -xf -`. (I rehearsed it: 139 files, 3.3 MB.) Check with `find "$DT" -type f | wc -l`
     and `cmp` of `svc-diff-tools-r2/difftool_r2.py`, `nested-scratch/gen2.py` and `svc-diff-tools/runner-src/diffrun.rs` against the originals;
     if an original is already gone, say so and use what exists. Say that the scripts hold absolute `/tmp/claude-501/...` paths
     (`grep -rn '/tmp/claude-501' "$DT"`) that Task 9's reviewer repoints in its own scratch copy. Do not edit the originals.
  1. **Coverage map** for AC1 to AC24 as a table (criterion, test, status) from "AC coverage" above, with the counts of the "Counts" table
     checked: `redact::tests` 64, filter 66, scanner 201, `builder.rs` 24. A criterion with no test is a finding.
  2. **Test quality.** Read every new and edited test. Flag a test that would pass if the rule returned a default or a no-op: AC1 and AC2
     must fail if the child value is left, AC4 and AC5 must fail on approach A, AC8's families must be at 1 MiB or more, AC15's table
     must hold ten rows, no test pins a leak. **Tests only; every size in a test you add is a literal or a constant and is clamped
     (at most `1 << 21` bytes) before any `repeat`, `with_capacity` or `vec!`; never an allocation sized from a value you
     have not bounded.** Suggested additions (the Tester decides): every char-boundary prefix of the AC1, AC2, AC3 inputs through
     `scrub_text`, `scrub_text_wide` and `scrub_embedded` never panics (the slice in `mask_secret_pairs` is the hazard M1 shows);
     the empty string; a key at the very end of the text (`auth:\n  password:` gives `auth:\n  [redacted]`); a nested pair whose value
     is non-ASCII (`auth:\n  password: \u{e9}t\u{e9}`); a closing quote followed by a multi-byte character (`token="sid:"\u{e9}`). Commit added
     tests separately as `test(<area>): tester, <what>` by explicit path, before the mutants, so the tree is clean.
  3. **Mutants (AC13), in a scratch copy of the head, never in the branch.** `SCRATCH="$TMPDIR/nestfix-mutants"`; `git -C WT archive <head> |
     tar -x -C "$SCRATCH"`; `CARGO_TARGET_DIR="$SCRATCH/target"`, `cargo test --offline`, never the worktree's target directory.
     Keep a pristine copy of `redact.rs`. For each mutant: apply the edit, save `diff -u pristine mutated` as `Mn.diff`, run `cargo test
     -p aitm-core --offline --lib redact::tests` (and `cargo test -p aitm-plugin-scanner --offline --lib` and `cargo test -p aitm-poc
     --offline --test builder`, recorded as information), record the red names, then **restore byte for byte**: `cp` the pristine copy back
     and prove it with `cmp -s` and equal `shasum -a 256`, then run once more green. Adapt the one-line edit to the code as built, keeping its
     meaning. The Architect measured the table below on the scratch rule (`/tmp/claude-501/nested-scratch/runmutants.py`, now also in `$DT`,
     holds the anchor strings; its anchors need adapting because the scratch file keeps `skip_pair_blanks`):
     | Mutant | Edit in the scratch copy | Tests that must go red (measured) |
     |---|---|---|
     | M1 | delete R2' and R2 (the two `continue` guards on `j < copied` and `j < masked_to`), keep `masked_to` | at least 16 red; a slice panic (`text[copied..value_start]`) among the failures |
     | M2 | `masked_to` is `value_end` for a quoted value too (the closing quote is not covered) | exactly one: AC7 `scrub_text_does_not_read_the_closing_quote_of_a_masked_value_as_an_opener` |
     | M3 | `FirstOfWide` never uses the wide test inside a masked value (always `is_secret_key`) | exactly one: AC10 `scrub_text_wide_masks_a_wide_only_pair_nested_under_a_standard_parent` |
     | M4 | resume at `value_end` again (`i = value_end`) | exactly nine: AC1, AC2, AC3, AC6b, AC8, AC10 and the three AC11 tests (`scrub_text_wide_reads_a_pair_across_a_line_break`, `..._beside_non_ascii_spaces`, `scrub_text_wide_stays_linear_on_line_break_shapes`) |
     | M5 | the wide scan stops at `\n`, `\r`, `\x0c` beside a separator again: in the scratch copy re-add a helper with the body of the deleted function (`git -C WT show 61a35571:crates/aitm-core/src/redact.rs`, lines 301 to 314, the `Wide` arm) and use it at both skips when the reading is `Wide` | exactly five: AC9 and four of AC11 (`scrub_text_wide_masks_a_standard_pair_nested_under_a_wide_only_key`, `scrub_text_wide_reads_a_pair_across_a_line_break`, `..._beside_non_ascii_spaces`, `scrub_text_wide_stays_linear_on_line_break_shapes`) |
     | M6 | no host:port exemption (the condition never holds) | exactly four: `scrub_text_does_not_mask_a_host_port`, `scrub_text_exempts_only_a_dotted_key_with_a_one_to_five_digit_port`, `scrub_text_is_unchanged_on_the_recorded_corpus`, `scrub_text_stays_linear_on_oversized_inputs_of_other_shapes` |
     | M7 | `Standard` also uses the wide test for a key run that begins inside a masked value | exactly one: AC4 `scrub_text_keeps_the_output_it_had_when_no_secret_pair_starts_inside_a_masked_value` |
     | M8 | remove R2' only | **none red: survives by design** (it changes no output); record it, with the red count 0, as "not a finding"; the timing run of Design 9 I4 is its check |
     A mutant that leaves a listed test green, or reddens an unlisted test of `redact::tests`, is a finding: strengthen the test (or report
     the surprise), commit separately, re-run. The branch is proven untouched by `git -C WT status --short` printing nothing and `git -C WT
     diff <head> --stat` printing nothing, before and after the mutant runs.
  4. **Structural checks**, re-run from scratch with the literal outputs of Tasks 1 to 7: the AC14 greps (`grep -n skip_pair_blanks`
     prints nothing; the `reading` count prints `3`), the AC24 docs grep (prints nothing) and the banned-phrase grep, no `unsafe`, no added
     `pub`, no `Cargo.toml` or `Cargo.lock` change, `crawl.rs` and `commands.rs` empty diff, `git diff --stat 61a35571 -- crates` names exactly
     the three files, no edit under `docs/superpowers/` except this plan and its spec, the test-name recipes of Tasks 4 and 5 (core 54 to 64,
     `reproduce.rs` 45 to 49, `builder.rs` 23 to 24).
  5. **The gate.** Sandbox from `WT`: `cargo clippy --all-targets --offline -- -D warnings` for `-p aitm-core -p aitm-plugin-scanner -p
     aitm-poc`, `rustfmt --edition 2021 --check` on the three files, and `cargo test --offline --no-fail-fast -p aitm-core -p
     aitm-plugin-scanner -p aitm-findings -p aitm-scan-checks-http -p aitm-scan-ws -p aitm-plugins -p aitm-scan-model` plus `-p aitm-poc --test
     builder`, pasted verbatim, with each socket failure named "NOT RUN (socket)". The orchestrator then runs the workspace gate in the Terminal
     (detached, log, `gate-exit=`; see "Where each command runs") and pastes the tail: it must end with `gate-exit=0`.
- **Report:** the coverage table; the tests added or rewritten and why; each mutant's patch, red set and restored green (with the `cmp` result);
  the gate output verbatim; the diff-tools copy listing; PASS or FAIL.
- **Done when:** every AC has a passing test or review check, M1 to M7 are killed as listed, M8 is recorded as surviving by design, the workspace
  gate prints `gate-exit=0`, and the verdict is PASS.

### Task 9 (Stage 6): panel on the whole branch, with the out-of-tree differential

- **Satisfies:** AC23, the AC14 and AC24 review items, and the panel gate of WORKFLOW stage 6.
- **Depends on:** Task 8 PASS (head `S8`). **Files:** none. Reviewers are read-only on this branch and never edit it; they write only into scratch
  copies outside the repo and the worktree, and return their report as the final message in `docs/superpowers/REVIEW-TEMPLATE.md` form; the
  orchestrator records every finding.
- **Dispatch:** to each of the three reviewers in parallel, fresh context: spec path, plan path, `WT`, base `61a35571` (or the post-merge
  merge-base), head `S8`, "whole branch", the Coder reports (Tasks 1 to 7), the Tester report, and no prior review report (a re-run after a fix
  gets the prior report).
- **Spec reviewer:** AC1 to AC24 against the diff and the tests, as a requirement-to-evidence table. Specifically: the four edited tests of AC11,
  the two renames, the one deletion, and nothing else changed in an existing test (read the diff of every existing test; the comment rewrites of
  Task 4 are comment text only); `RECORDED_SCRUB_TEXT` has an empty diff; `RECORDED_SCRUB_EMBEDDED` lost exactly the ten rows of AC15 and its
  five F1 rows and the `>= 80` assertion stay; AC19 edited exactly four values; Design 7 items 1 to 9 are done and the "Statements this spec
  supersedes" (the 2026-10-31 spec and plan) are not edited (`git diff --stat 61a35571 -- docs` names only this plan and spec); Design 12's
  "Not touched" list is respected; the counts (64, 66, 201, 24) and the spec's "63 and 65" noted as spec gap 1; the three Open questions'
  defaults stand (the PR must flag them for Matt).
- **Quality reviewer:** the seam is one scan function with a reading parameter used in exactly the AC14 places; no logic duplicated between
  the readings (the three-arm key test is the only fork) and `apply_patterns` shared; one lowercase allocation per candidate (R2' skips a nested key
  inside a masked value before the vocabulary is consulted); doc accuracy and no overclaim (the Design 7 list, "on well-formed input", the I4
  wording against the measured times); test hygiene (escapes, `assert!` on large strings, the deterministic seeded generator with no dependency,
  `padded_credentials` shared by AC6 and AC6b, no dead code, no leftover bite-check or recorder code, the rename of the const and the two tests
  consistent, rewritten comments accurate); naming (`FirstOfWide`, `masked_to`, `apply_patterns`).
- **Security reviewer:** reading the diff for a panic or a char-boundary fault (the slice `text[copied..value_start]`, `masked_to` plus one after
  an ASCII quote, `i = value_start`); the claim that nothing the old output masked is exposed on well-formed input (the invariant behind Design 5);
  every row of Design 6 rated; the callers (Design 1 item 5) see no API change; the corpora hold only fake canaries; and **the differential,
  AC23**, below. Severity rules: an I1 violation on well-formed input (no malformed-quote trigger), an I2 leak on the unmutated nested alphabet or a
  panic is **Critical** and is spec-shaped (Fix-task protocol 4: to the Architect, not a Coder); a violation that holds a malformed-quote trigger
  and is within spec Residual risks 3 is **Minor** (recorded, grouped by family, not pinned by any test); a growth above 3.0 times per doubling or a
  time above 20 times the old tree's at 8 MiB is **Important**.
- **The differential (Design 9), built out of tree, per the spec's description.** Reuse the copies in the notes folder `diff-tools/` (from Task 8);
  rebuild from the spec's description if they are gone.
  1. **Scratch trees**, never inside the repo or `WT`: `SCRATCH="$TMPDIR/nestfix-diff"`; old tree `git -C WT archive 61a35571 | tar -x -C
     "$SCRATCH/old"`, new tree `git -C WT archive <head> | tar -x -C "$SCRATCH/new"`; record the full SHAs (`git rev-parse`) of both and the method.
  2. **A wrapper and one runner, scratch only, identical source in both trees:** in each tree's `crates/aitm-plugin-scanner/src/reproduce.rs` one
     `#[doc(hidden)] pub fn scrub_embedded_for_diff(text: &str) -> String` that calls the private `scrub_embedded`; one example in
     `crates/aitm-plugin-scanner/examples/` that reads one JSON string per stdin line and writes one JSON result per line, with the modes `text`
     (`scrub_text`), `textwide` (`scrub_text_wide`), `embedded`, `key` (`is_secret_key`), `keywide` (`is_secret_key_wide`), a `time-<mode>` variant
     (best of three, nanoseconds), and a panic reported as `{"panic":1}`. Start from `diffrun.rs` and `diffrun_new.rs` in `svc-diff-tools/runner-src/`
     (the base tree already has the wide functions, so one source serves both). Build with `CARGO_TARGET_DIR="$SCRATCH/target-old"` and
     `"$SCRATCH/target-new"`, `cargo build --release --offline -p aitm-plugin-scanner --example <runner>`; check `df -h` first; if the
     sandbox cannot, the orchestrator builds it in the Terminal panel.
  3. **Generators and checkers, reused:** `svc-diff-tools-r2/difftool_r2.py` (alphabets `aligned`, `full`, `soup`, `dc`, `nest`),
     `nested-scratch/gen2.py` (nested shapes with a known governing key per canary, and the mutating variant `gen2m`), `diff3.py` (the harness),
     `trig.py` (TRIG), `minimize.py`, `timing.py`, `mkvariants.py` and `runmutants.py` (for the controls). Repoint their absolute paths in the copy
     in your scratch; run with `python3 -I`. Every secret value is a unique alphanumeric canary; the generators avoid the `Authorization` and
     `bearer` keys (spec Residual risks 8).
  4. **Counts and seeds:** at least 4,000,000 inputs in all, at least 1,000,000 on each of `aligned`, `full` and `nested` (`gen2` and `gen2m`), at
     least 500,000 on each of `soup` and `dc`. Start with the seeds `nestfix-aligned-20261101`, `nestfix-full-20261101`, `nestfix-soup-20261101`,
     `nestfix-dc-20261101`, `nestfix-nest-20261101`, `nestfix-gen2-20261101`, `nestfix-gen2m-20261101`, `nestfix-b64-20261101`; add more.
  5. **Invariants and what the report must show** (spec Design 9, with the Architect's measurements for orientation):
     - **I1** raw: every canary absent from `old(x)` is absent from `new(x)` for `scrub_text`, `scrub_text_wide`, `scrub_embedded`: zero on `aligned`,
       `dc`, `nest` and unmutated nested; on `full`, `soup` and the mutated alphabet each violation holds a malformed-quote trigger and is minimised to a
       family; ownership-aware I1' is 0 on unmutated nested and at most 5 per 1,000,000 on mutated, each a minimal malformed-quote reproducer.
     - **I2** completeness: on unmutated nested every canary whose governing key is secret under the reading is masked by `new(x)`: zero (old: 61,992
       and 89,302 leaking inputs of 300,000).
     - **I3** byte equality outside the trigger: TRIG (and TRIG-W for the wide functions) as in `trig.py`: at least 1,000,000 non-trigger inputs per
       function with zero differences, and no changed input without a TRIG match.
     - **I4** robustness and linear time: no panic or char-boundary fault; for each hostile family of AC8 plus `author:\n` repeated,
       `authentication:\n  sessionKey: x\n` repeated and a megabyte newline run after a wide-only key, the time at 2, 4 and 8 MiB is at most 3.0 times
       the time at the previous size (best of three) and at 8 MiB at most 20 times the old tree's; state the sizes used and report 1, 2, 4, 8 MiB.
       This is also the check of the doc wording of Task 7 and of M8 (R2').
     - **I5** superset: every canary absent from `scrub_text(x)` is absent from `scrub_text_wide(x)`: zero on `aligned`, `nest`, `dc` and nested; on `full`
       and `soup` each violation holds a malformed-quote trigger.
     - **I6** hazard 1 at scale: at least 1,000,000 random base64 credentials (6 to 40 random bytes, standard and URL-safe alphabets, padded and not) in
       `{p}:{layout}<credential>` for p in token, password, secret, session, auth, api_key, cookie and layouts `\n  `, `\r\n    `, `=\n\t`, `:\n`: zero left in
       the clear by `scrub_text`, `scrub_text_wide` and `scrub_embedded`; and under a nested pair (`auth:\n  password:\n    <credential>`) zero.
  6. **Positive controls, before the big run; one that does not fire invalidates the run:** (a) the old tree on the nested alphabet reports I2 leaks
     within its first 1,000 inputs (measured 41,598 of 200,000); (b) the M4 tree (Task 8's patch, the fix reverted) reports them too; (c) the A-secret
     mutant (`mkvariants.py`'s `a_secret`) reports I1 violations within the first 100,000 nested inputs and fails the hazard-1 rows; (d) the M3 tree
     reports wide I1 violations on the `aligned` and nested alphabets; (e) the M5 tree reports wide I2 leaks.
  7. **Report (AC23):** the tools and scratch layout, the seeds, the counts per alphabet, I1 (raw and ownership-aware), I2, I3 with the TRIG check, I4
     with the timings at 1, 2, 4 and 8 MiB, I5, I6, the positive controls firing, every violation minimised and grouped by family (each within Residual
     risks 3), and the cleanup of the scratch trees (`rm -rf "$SCRATCH"`, said in the report).
- **Done when:** three reports are in, every finding is in the Review log, no Critical or Important finding is open, and each Minor is fixed or accepted by
  Matt in writing in the Review log.

### Fix-task protocol

Applies to any finding from the Tester or the panel.

1. The orchestrator records every finding in the Review log (one row each) with its severity.
2. **Critical and Important** go to a fresh Coder as a fix task: input is the findings report (not a task number), the spec path, the plan path, `WT`. For
   each finding the Coder writes a test that reproduces it and fails, fixes it, watches it pass, and commits as `fix(<area>): <finding title>`. It touches
   only the files the findings name, fixes nothing else, and pastes the red and green runs. The per-package gate must pass.
3. Then the Tester and the panel run again on the fix, with the prior report in hand, and **the differential is re-run if the fix touches `redact.rs` or the
   scanner scrub path**.
4. **Spec-shaped findings go to the Architect first, not to a Coder**: an I1 violation on well-formed input, an I2 leak on the unmutated nested alphabet, a Design 6 row
   that is wrong, a counterexample to the rule, a leak not covered by Residual risks, or a measured cost above the spec's bound. The Architect amends the spec and the plan
   and the orchestrator approves before any Coder builds it. The alternatives the spec names (keep the wide boundary, or the churn-free variant) are Matt's, through the three
   Open questions, and are never taken as a fix.
5. **Minor** findings are fixed in a fix task, or accepted by Matt in writing in the Review log with the reason. The branch merges only when the final panel has no open finding.
6. A Coder or Tester that finds the spec or plan wrong stops and reports the exact sentence; it does not redesign. The Architect owns every edit to `docs/superpowers/specs/` and
   `docs/superpowers/plans/`, except the plan's Status line, Review log and Shipped section, which the orchestrator owns.

### Integration notes (Stage 7, orchestrator)

- **Before the panel, merge `origin/main` again** (the `ccd_host` `sync_with_base_branch` tool, or `git fetch origin` then `git merge origin/main` in the Terminal) and re-run the workspace
  gate: CI tests the branch plus current `main`, so a sibling's new test appended to `reproduce.rs` or `builder.rs` can fail only there. `main` moves often. Re-check
  `git log origin/main -- crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src/reproduce.rs crates/aitm-poc/tests/builder.rs` (at plan time the last commit on all three was `5f89b2fc`, PR 199)
  and `git worktree list` for live sessions touching those files (the scan of Preflight 3). If the merge moves any of the three files or the base, give the Tester and the panel the new
  merge-base and re-run both.
- **Terminal-only steps:** `git push origin claude/heuristic-panini-828774` (explicit refspec; never a bare `git push`); `gh pr create --base main --head claude/heuristic-panini-828774 --title "<title>"
  --body-file <file>`; titles and bodies never begin a word with a hash sign (write "PR 199"). Before `gh pr merge`, confirm `baseRefName` is `main` (`gh pr view <n> --json baseRefName`).
- **The panel comment is posted on the PR** (REVIEW-TEMPLATE, the three reports) with every finding's disposition from the Review log below. The PR is ready only with the stage-6 panel comment and
  dispositions, the gate, and the real runs the body cites.
- **The PR body cites only completed real runs and says what was not run:** the sandbox runs of each task, the workspace gate with its `gate-exit=0` log, the Tester's mutant results and the security
  reviewer's differential (counts, seeds). It says that no live end-to-end through a running `aitm` was run (none exists for the PoC path), that the socket-bound suites ran only in the Terminal, and it flags
  the three Open questions' defaults for Matt: closing the wide next-line leak (17 named core rows, 10 scanner rows and four expectations change; `author:\nJohn` masks `John` in a PoC), accepting label churn in
  chains of secret keys, and leaving non-secret children readable (`auth:\n  user: bob`).
- Keep the notes-folder `diff-tools/` copy until the PR merges; copy it to a durable place only if Matt wants the tooling kept.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7 (orchestrator).

Follow-ups known now (record and finalise at stage 7):

1. **The durable-audit sibling** (`claude/durable-audit-462ca8`, not on `main`; adds `crates/aitm-core/src/redact_strict.rs`, which runs `scrub_text` as its first pass): its docs say "`scrub_text` itself,
   unchanged", which is true of the API and no longer of the outputs on nested shapes; it needs a doc touch when it rebases. Its `redact_strict` suite (28), its `redact_strict` lib tests (11) and its
   `audit` lib tests (46) passed over the new `redact.rs` in the Architect's scratch copy; re-run them at its rebase.
2. **PR 199's hand-over items that stay open:** (a) the `commands.rs` pin that its free-text calls stay on the standard reading (tests only, in `commands.rs`'s own test module; the surviving mutants (i) and (i2)
   of PR 199); (b) the stale "lacks jwt/sid" comments in `crates/aitm-poc/tests/builder.rs` (line 647 on `BASE`), a later docs sweep: this branch appends to that file and leaves them.
3. **The `Authorization` regex pass** can eat a key that ends its line and orphan the next-line value (spec Residual risks 8, pre-existing): a separate spec.
4. **Residual risks of this change** to keep visible: a non-secret child keeps its value (`auth:\n  user: bob`), malformed quotes (spec Residual risks 3, measured 5 of 300,000 raw on the malformed alphabet),
   label churn in chains, and the same-line prose over-redaction (`token: auth: expired` masks `expired`).
5. **The three Open questions' defaults, for Matt** (they stand unless he reverses them): (1) drop the wide line-break boundary (the alternative keeps it and leaves 11,487 of 300,000 nested inputs with a
   next-line leak); (2) accept label churn in chains of secret keys (the churn-free variant exposes pair-shaped credentials the old output masked); (3) a secret parent does not mask its non-secret children.
6. **The differential tooling** (the 2026-10-31 and 2026-11-01 generators, runners and harnesses) lives in the notes folder `diff-tools/` and, until cleared, `/tmp/claude-501`; copy it into the repo only if
   the tooling should be kept.
