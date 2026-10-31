# Scanner vocabulary consolidation implementation plan

**Status:** approved (2026-10-31, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-10-31-scanner-vocab-consolidation-design.md`
**Branch / worktree:** `claude/scanner-vocab-7d36bb` in
`/Users/matt/Security/aitmproxy/.claude/worktrees/scanner-vocab-7d36bb`. The session worktree is the
plan worktree. Base SHA for every diff and every Tester/panel dispatch: `15009b2` (the spec was
committed on top as `2febff0`, and the plan will be committed on top of that; both are docs, so
`git diff --stat 15009b2 HEAD -- crates` is empty at the start of Task 1A and must be confirmed).
The base changes only if the orchestrator rebases onto `main` before the panel.

## Overview

Six units of work. **Task 1A** (core) and **Task 1B** (scanner) pin today's behaviour with tests that
pass on the unmodified production code, and touch disjoint files. **Task 2** adds the wide reading
and the private seam to core. **Task 3** swaps the scanner onto it, deletes the scanner's list and
second scan, fixes the stale docs, adds the DC-row test and does the one rename. **Task 4** is the
Stage 5 Tester (whole branch, mutants, gate). **Task 5** is the Stage 6 panel, whose security
reviewer runs the out-of-tree differential.

### Execution order (read this before dispatching)

**Execute strictly sequentially: 1A, then 1B, then 2, then 3, then 4, then 5. One writer per file,
one Coder per task, each in this worktree, each committing when its task is done.** Two reasons
beyond file conflicts:

1. Task 2 edits `redact.rs`, the same file as Task 1A, and Task 3 edits the same scanner files as
   Task 1B. They are not independent of each other.
2. Task 1B records the old `scrub_embedded` by running it. It must run before Task 2 lands, so the
   recording is made against production code that is byte-identical to `15009b2`, not against a
   core that has been refactored (even if AC8 says the refactor is invisible). Task 1A and 1B must
   both be committed before Task 2 starts.

What the dependency table allows in principle (1A with 1B; 2 with 1B) is not used: all tasks share
one git index, one `target/` directory and one cargo lock.

**Before dispatching Task 1A (orchestrator):**

1. `git worktree list`, and check that no other live session is changing `crates/aitm-core/src/redact.rs`,
   `crates/aitm-plugin-scanner/src/reproduce.rs` or `crates/aitm-plugin-scanner/src/discover.rs`
   (spec Design 11 did not verify branch by branch). **At plan time I did:** a three-dot scan
   (`git diff --name-only 15009b2...<HEAD of each worktree> -- <the three files>`) over every
   worktree printed nothing, no worktree had uncommitted changes to them, and `git diff --name-only
   15009b2 main -- <the three files>` printed nothing. Repeat it at dispatch: it takes a minute and
   the window must stay short.
2. `git diff --stat 15009b2 HEAD -- crates` prints nothing.
3. `cargo test -p aitm-core --lib redact` prints `test result: ok. 32 passed` and `cargo test -p
   aitm-plugin-scanner` prints `test result: ok. 178 passed` (proves cargo works offline here; if not,
   run `cargo fetch` in the Terminal panel).

| Task | Depends on | Files (all under `crates/`) | Could overlap (not used) |
|---|---|---|---|
| 1A | none | `aitm-core/src/redact.rs` (tests only) | 1B |
| 1B | none | `aitm-plugin-scanner/src/discover.rs`, `aitm-plugin-scanner/src/reproduce.rs` (tests only) | 1A, 2 |
| 2 | 1A, 1B committed | `aitm-core/src/redact.rs` | 1B |
| 3 | 1B, 2 | `aitm-plugin-scanner/src/discover.rs`, `aitm-plugin-scanner/src/reproduce.rs` | none |
| 4 (Tester) | 3 | the `#[cfg(test)]` modules of those three files; scratch copies outside the repo | none |
| 5 (panel) | 4 | none (read-only on the branch; scratch copies outside the repo) | none |

Every task leaves the workspace compiling, formatted, and green for the per-task gate.

### Tester and panel cadence: a deliberate deviation from WORKFLOW

WORKFLOW stages 5 and 6 say the Tester and the panel run after each task and once more on the whole
branch. **This plan runs the Coder's gate after every task, and the Tester and the three-reviewer
panel once, on the whole branch, after Task 3 (base `15009b2`).** Reasons:

- Tasks 1A and 1B add `#[cfg(test)]` code only. The Coder's evidence proves it mechanically (the
  smallest old-start line of any hunk is at or after the `#[cfg(test)]` line), so there is no
  production diff for a reviewer to read.
- Task 2 adds two `pub fn`s that nothing calls yet and changes the private scan only through a
  parameter whose `Standard` arm must reproduce today's output byte for byte. AC8 (recorded on the
  unmodified tree), the 32 existing tests, AC9, AC10 and the blast-radius runs prove that at the
  Coder's gate, and no consumer (audit ring, findings, MCP, scanner free text) can see a change.
- Nothing is merged or deployed between tasks, so nothing a per-task panel would catch can ship, and
  the whole-branch panel reads Task 2's diff as part of the branch.
- The one security-relevant behaviour change (DC1 to DC6) lands in Task 3, and the panel's main
  instrument, the differential of AC24, needs the finished pipeline: it cannot run on Tasks 1 and 2.

The cost: a seam defect in Task 2 is found one task late, after Task 3 has built on it. Task 2's
gate therefore includes the blast-radius runs and the AC19 count, and the orchestrator may run the
Tester alone (no panel) after Task 2 at no cost to the plan. If the orchestrator wants the strict
reading of WORKFLOW anyway, the per-task base is the previous task's commit and the head is the
task's commit; the Task 4 and Task 5 inputs below then narrow to that range.

### Where each command runs (read this before dispatching)

- **Bash sandbox (Coder and Tester sub-agents).** `cargo build`, `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings`, every test that binds no socket, and local git:
  `git add <exact files>`, `git commit`, `git log`, `git diff`, `git show`, `git archive`. `cargo`
  works offline once dependencies are fetched; if it cannot resolve dependencies, stop and ask the
  orchestrator to run `cargo fetch` in the Terminal panel. If the sandbox refuses a git write, stop
  and report; do not work around it.
- **Terminal panel (orchestrator only).** `git push origin claude/scanner-vocab-7d36bb` (**never a
  bare `git push`**: it also pushes a stale local `main`), `git fetch`, `gh`, `cargo fetch`, the
  `aitm-mcp` suite and any other test that binds a port, and the final full gate. A Coder or Tester
  that sees a test fail only because the sandbox refuses a loopback bind reports "NOT RUN (socket)",
  never a pass or a fail. Do not write a `#`-leading word in a commit message (the terminal hook
  refuses it): write "PR 171", not the hash form.
- **Commits.** The Coder commits at the end of its task, as `coder.md` step 5 says. Message form: `test(redact): task 1A, pin scrub_text on the recorded corpus (plan
  2026-10-31-scanner-vocab-consolidation)`, ending with the trailer line
  `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Stage files by exact path; never
  `git add -A`.
- **No `git stash`.** The stash stack is shared with every other worktree and session. To set work
  aside, make a WIP commit and `git reset` it back out yourself, or finish the step first.
- **Gate per task** (Bash sandbox, from the worktree root):
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -p aitm-core -p aitm-plugin-scanner`.
  The full workspace gate and the port-binding suites run once, at the end, in the Terminal panel,
  redirected to a log and gated on exit status (see Task 4). `aitm-rhai`'s e2e
  `script_cannot_escape_or_exceed_scope` is a known non-deterministic flake: judge it by whether the
  change touches Rhai (this one does not), not by an isolated rerun.
- **Stale target directories.** If `CARGO_TARGET_DIR` is shared with other worktrees, `touch` the
  edited source files before every red or green run so cargo does not reuse a stale artifact. A red
  run on a stale binary is worthless.
- **Evidence, verbatim.** Every red and green run in a report is the literal command and the literal
  output lines named in the task. "It failed as expected" is not a report.
- **Two-step red for tasks that add API.** A test that names a symbol that does not exist yet fails to
  compile: that is a legitimate first red (quote the compiler line naming the missing item). Then add
  the signature with the old behaviour so it compiles, and quote the assertion-level failure.

### Code constraints for every task

- Touch only the files the task declares. No new dependency, no `Cargo.toml` or `Cargo.lock` change,
  no `lib.rs` change, no new struct field, no changed existing signature. No `unsafe`, and no line
  you add may contain the word `unsafe`, even in a comment (AC18 checks by grep).
- **Banned words in every comment and doc you add** (AC17 and AC20 grep the scanner and core
  sources, tests and comments included): `EXTRA_SECRET_NEEDLES`, `redact_needle_pairs`,
  `names_a_secret`, `ends_value` (in the scanner), `closing_quote` (in the scanner), `is_key_byte`
  (in the scanner), `only knows`, `widened locally`, `needle layer`, `two vocabularies`,
  `vocabulary consolidation`, `stays until`, `scanner's copy`, and the phrase "none is in" followed
  by `scrub_text`. Describe the old pipeline as "the old pipeline" or "the old two-scan pipeline".
- No code in a doc comment longer than a signature. No raw invisible or non-ASCII whitespace
  character in a test source: write `\u{a0}`, `\u{b}`, `\u{2028}` and the like as escapes, so the
  corpus is reviewable. (A green run on the old tree proves an escape is byte-identical.)
- Large-string assertions use `assert!(a == b, "short message")`, not `assert_eq!`, so a failure does
  not print megabytes (house style in `redact.rs`).
- An existing test is never edited, except the five edits listed in spec Design 8, which are all in
  Task 3. A red existing test stops the Coder and goes back to the Architect.
- Test names in the AC coverage table are exact. A Coder may add rows to a table, never remove or
  weaken one, and adds no extra test function (the expected test counts below depend on that).
  Fixed counts: `cargo test -p aitm-core --lib redact` is 32 at the start, 33 after Task 1A, 41 after
  Task 2; the scanner suite is 178 at the start, 182 after Task 1B, 183 after Task 3.

### Symbols the tasks use (confirmed by reading on `15009b2`)

- `crates/aitm-core/src/redact.rs`: private `SECRET_KEY_NEEDLES`, `SECRET_KEY_SEGMENTS` (`["sid",
  "jwt", "csrf", "session", "auth"]`), `patterns()`, `is_key_byte`, `run_end`, `is_ascii_blank`,
  `blank_len`, `skip_blanks`, `ends_value`, `unquoted_value_end`, `is_opening_quote`,
  `closing_quote`, `is_host_port`, `fn mask_secret_pairs(text: &str) -> String` (the only caller is
  `scrub_text`); public `is_secret_key(key: &str) -> bool` and `scrub_text(text: &str) -> String`.
  The `#[cfg(test)]` line is at 374; the test helper `mismatches(rows: &[(&str, &str)]) ->
  Vec<(&str, &str, String)>` runs `scrub_text` and returns the rows that differ. `lib.rs` has
  `pub mod redact;` and re-exports nothing from it.
- `crates/aitm-plugin-scanner/src/discover.rs` (`#[cfg(test)]` at 266): `pub(crate) const
  EXTRA_SECRET_NEEDLES`, `pub(crate) fn is_secret_name(name: &str) -> bool` (four call sites: one in
  `enumerate`, three in `reproduce::Scrubber`), `REDACTED`, `enumerate`. Test helpers
  `captured(path: &str, headers: HeaderMap) -> HttpFlow`, `example_of(points, location, name) ->
  String`.
- `crates/aitm-plugin-scanner/src/reproduce.rs` (`#[cfg(test)]` at 613): private `fn
  scrub_embedded(text: &str) -> String` (about line 379), the block to delete at about 383 to 508
  (`is_key_byte`, `ends_value`, `names_a_secret`, `redact_needle_pairs`, `closing_quote`), `fn
  origin_and_path` right after it. Imports: `use aitm_core::redact::scrub_text;` and `use
  crate::discover::{is_secret_name, InjectionPoint, EXTRA_SECRET_NEEDLES};`. Test helpers
  `flow_with(method, path, headers: &[(&str, &str)], body: Option<&str>) -> HttpFlow`,
  `flow_with_query`, `point(flow, location, name, example) -> InjectionPoint`, `http_step(&Poc)`,
  `header_of`. `crawl.rs` has `pub(crate) fn strip_userinfo(text: &str) -> String`.
- The scanner crate has unit tests only (one test binary, 178 tests, `crates/aitm-plugin-scanner/src`),
  depends on `aitm-core`, has no `regex`, and gets none.

### Claims traced by reading, not run

I did not run old code while planning. These come from reading `15009b2`, and each is checked by a
run in the task that names it:

- **Baselines measured:** `cargo test -p aitm-plugin-scanner` is 178 passed; `cargo test -p
  aitm-core --lib redact` is 32 passed; the AC17 grep prints 21 lines on `15009b2`; the AC20 grep
  prints 9 lines (4 in `redact.rs`, 1 in `discover.rs`, 4 in `reproduce.rs`).
- **The eight AC15 inputs, old and new** (Rust escapes shown). "Old" is derived by tracing the two
  passes of the old pipeline (core's `scrub_text`, then the scanner's second scan); "new" is the
  spec's value, which I also traced through the one core scan with the wide reading:

  | DC | input | old pipeline (traced) | new (spec AC15) |
  |---|---|---|---|
  | DC1 | `xsidéy=v` | `xsidéy=v` (unchanged) | `xsidéy=[redacted]` |
  | DC2 | `author:\nJohn` | `author:\nJohn` (unchanged) | `author:\n[redacted]` |
  | DC2 | `sidebar\u{a0}:\u{a0}v` | `sidebar\u{a0}:\u{a0}v` (unchanged) | `sidebar\u{a0}:\u{a0}[redacted]` |
  | DC3 | `token.example.com:8443/x` | `token.example.com:8443/x` (unchanged) | `token.example.com:[redacted]` |
  | DC4 | `sidebar='abc def token='S3'` | `sidebar='[redacted]'[redacted]'` | `sidebar='[redacted]'` |
  | DC5 | `sid=abc\u{a0}def` | `sid=[redacted]` | `sid=[redacted]\u{a0}def` |
  | DC5 | `sidebar=abc\u{b}def` | `sidebar=[redacted]` | `sidebar=[redacted]\u{b}def` |
  | DC6 | `sid='abc def token='S3` | `sid='[redacted]'[redacted]` | `sid='[redacted] def token='[redacted]` |

  Task 1B and Task 3 each run the old code over these eight inputs. **If either run's output differs
  from the "old pipeline" column, stop and report with both outputs: it is a spec gap** (spec Design
  5 says a mismatch stops the Coder).
- **Core's own scan (`scrub_text`) on the same inputs**, for Task 1A's anchor rows: `author:\nJohn`,
  `xsidéy=v`, `sidebar\u{a0}:\u{a0}v` and `token.example.com:8443/x` come back unchanged;
  `sid=abc\u{a0}def` is `sid=[redacted]\u{a0}def`; `sidebar='abc def token='S3'` is
  `sidebar='abc def token='[redacted]'`; `sid='abc def token='S3` is `sid='[redacted] def
  token='[redacted]`. The recorder's output is authoritative; a difference stops the Coder.

### AC coverage

| AC | Task | Test or check (exact name) |
|---|---|---|
| AC1 | 2 | `redact::tests::is_secret_key_wide_reads_the_segment_words_as_substrings` |
| AC2 | 2 | `redact::tests::is_secret_key_wide_is_a_superset_of_is_secret_key` |
| AC3 | 2 | `redact::tests::is_secret_key_wide_names_every_segment_word` |
| AC4 | 2 | `redact::tests::scrub_text_wide_and_is_secret_key_wide_share_one_vocabulary` |
| AC5 | 2 | `redact::tests::scrub_text_wide_masks_a_wide_only_pair_as_a_standard_pair` |
| AC6 | 2 | `redact::tests::scrub_text_wide_does_not_exempt_a_host_port` (paired guard: existing `scrub_text_does_not_mask_a_host_port`) |
| AC7 | 2 | `redact::tests::scrub_text_wide_survives_hostile_inputs_and_stays_linear` |
| AC8 | 1A | `redact::tests::scrub_text_is_unchanged_on_the_recorded_corpus` |
| AC9 | 2 | `redact::tests::scrub_text_wide_agrees_with_scrub_text_when_nothing_wide_applies` |
| AC10 | 1A (start), 2 (check), 4 | the 32 existing `redact` tests unedited; diff checks in Tasks 2 and 4 |
| AC11 | 1B | `discover::tests::enumerate_redacts_a_wide_only_parameter_name` |
| AC12 | 1B | `reproduce::tests::build_poc_placeholders_a_wide_only_parameter` |
| AC13 | 1B | `reproduce::tests::scrub_embedded_and_is_secret_name_agree_on_every_key` |
| AC14 | 1B | `reproduce::tests::scrub_embedded_matches_the_recorded_pipeline_output` |
| AC15 | 3 | `reproduce::tests::scrub_embedded_deliberate_changes_are_exactly_these` |
| AC16 | 3, 4 | the 178 existing scanner tests; name diff before and after |
| AC17 | 3 | grep checks and the `scrub_embedded` body check |
| AC18 | 3, 4 | `git diff` checks |
| AC19 | 2 (count), 5 | the `reading` use count; review of the diff |
| AC20 | 2 (core), 3 (scanner), 5 | grep checks; Design 9 checklist; review of the diff |
| AC21 | 2 (poc, findings, plugins), 4 (all, `aitm-mcp` in the Terminal) | suites unedited |
| AC22 | 4 | the full Rust gate |
| AC23 | 4 | mutants (a), (b), (c), (d) |
| AC24 | 5 | the security reviewer's differential report |

### Architect's calls in this plan (for Matt to correct)

1. Task 1 is two tasks, 1A (core) and 1B (scanner), run one after the other.
2. Corpora are recorded with a throwaway `#[ignore]` recorder test that prints Rust source rows; the
   recorder is deleted before the commit. What proves a row is a recorded output is that the
   committed test is green on the unmodified production code.
3. **AC4 and AC13 carry a literal expected column**, not only the agreement check (see gap 2 below).
4. **Mutants run in a scratch copy, not in the branch** (see gap 1 below).
5. Tester and panel run once, on the whole branch, after Task 3 (justified above).
6. Each pin task ends with one bite check: a one-line temporary mutation of the old production code
   shows the new pins go red, then is reverted and proven reverted by a diff check.
7. The AC8 corpus has a third column, `reading_agnostic`, so AC9 can select its rows mechanically.
8. The reading parameter of `mask_secret_pairs` is named `reading`, so AC19's count is a grep.
9. The differential is at least 3,000,000 inputs, of which at least 1,000,000 are on the aligned
   alphabet and at least 1,000,000 on the full alphabet; the rest is the reviewer's choice.
10. Keep `is_secret_name` as the one-line delegate (the spec's default).

### Spec gaps found while planning (the spec is not edited; the orchestrator decides)

1. **AC23 against `tester.md`.** AC23 has the Tester mutate production code and revert by hand;
   `tester.md` says the Tester never changes production code. This plan resolves it by mutating a
   scratch copy of the branch outside the worktree, so the branch is never mutated and both rules
   hold. If the orchestrator prefers in-place mutation, say so and amend Task 4.
2. **AC23(a) cannot be met by AC4 and AC13 as written.** Both compare two things that, after the
   swap, derive from the one predicate `is_secret_key_wide` (AC4: the predicate against
   `scrub_text_wide`; AC13: `is_secret_name` against `scrub_embedded`). Mutating that predicate moves
   both sides equally, so both tests stay green. This plan adds a literal expected value to each row
   (AC4, AC13) so a mutation makes them red; AC1, AC3, AC5, AC7, AC11, AC12 and AC14 also catch (a).
3. **AC9's row filter is not mechanical** ("no wide-only key and no dotted key before `:digit`").
   The plan adds a boolean third column to the AC8 corpus, set by the Coder by that rule; a wrong
   flag shows up as a red AC9 row in Task 2 and is fixed by correcting the flag, never the output.
4. **The dispatch contract gives a Coder no prior reports**, but Design 7 step 2 has AC15 written
   against old outputs "recorded by Task 1". The plan carries the traced old outputs in the table
   above and has Task 3's own red run (against still-unmodified production code) re-record them.
5. **AC16's "before" list cannot come from `--list` at the end**, because Task 1B adds four tests.
   The plan gives a recipe that reads the names out of `git show 15009b2:<file>` (it prints 178 names,
   identical to `cargo test -- --list` on `15009b2`; I ran both).
6. **Design 7 I3's timing sentence is ambiguous** ("at most 3x the time of a 1 MiB baseline per
   doubling"). Task 5 asks the reviewer to state which reading they used and the measured times.

## Tasks

### Task 1A: pin `scrub_text` on the recorded corpus (core, old tree)

- **Satisfies:** AC8; the guard half of AC10 (nothing at or after `#[cfg(test)]` is removed).
- **Depends on:** none. Starts from a tree whose `crates/` equals `15009b2`.
- **Files:** `crates/aitm-core/src/redact.rs` (modify, inside `mod tests` only).
- **Change:** append to `mod tests`, after the last test, with a header comment saying the rows are
  recorded outputs of `scrub_text` at `15009b2`:
  - `const RECORDED_SCRUB_TEXT: &[(&str, &str, bool)]`: `(input, recorded_output,
    reading_agnostic)`. The flag is `true` unless the input has a key that contains a segment word as
    a substring but is not a whole-segment or needle secret (a wide-only key: `author`, `sidebar`,
    `xsidéy`, ...), or a dotted key directly before `:` and a digit. Spec AC9 reads it.
  - the test `fn scrub_text_is_unchanged_on_the_recorded_corpus()`: first `assert!(
    RECORDED_SCRUB_TEXT.len() >= 60, ..)`, then run every row through the existing `mismatches`
    helper (map each row to its first two columns) and assert the mismatch list is empty, so one
    failure shows every bad row.
  - a **temporary** recorder `#[test] #[ignore] fn record_scrub_text_corpus()` that takes a list of
    `(input, flag)` pairs, runs `scrub_text` on each, and prints each row as a Rust source line using
    `{:?}` for both strings. Delete it before committing.
- **Rows (at least 60 in all; each family at least the minimum).** Inputs are chosen by the Coder,
  outputs are only ever what the recorder prints:
  1. wide-only lookalike keys, each in each framing: at least 7 keys from {`author`, `authority`,
     `authenticated`, `inside`, `side`, `sidebar`, `subsidiary`, `sessions`, `userSession`,
     `X-Authority`} by at least 4 framings from {`k=v`, `k: v`, `"k":"v"`, `k:\nJohn`,
     `k\u{a0}:\u{a0}v`, `k='a b'`}: at least 28 rows, all `reading_agnostic = false`. Must include
     `author:\nJohn`, `sidebar\u{a0}:\u{a0}v`, `subsidiary='a b'`;
  2. a standard key (`sid`, `password`, `token`) with a vertical tab (`\u{b}`) and with a no-break
     space (`\u{a0}`) inside an unquoted value: at least 6 rows; must include `sid=abc\u{a0}def`;
  3. the DC4 and DC6 shapes with `sid` and with `password`: exactly these four rows at least,
     `sid='abc def token='S3'` and `password='abc def token='S3'` (closed), `sid='abc def token='S3`
     and `password='abc def token='S3` (unclosed);
  4. host:port forms: at least 8 rows (the forms in `scrub_text_exempts_only_a_dotted_key_with_a_one_
     to_five_digit_port`, plus `token.example.com:8443/x`, `sid:12345`, `https://auth.example.com:8443/login`);
     the dotted-key-before-`:digit` rows are `reading_agnostic = false`;
  5. non-ASCII-glued keys: at least 6 rows; must include `xsidéy=v`, `sidébar=x`, `é-sid=ABC`,
     `café=latte`;
  6. `Authorization` and `Bearer` lines: at least 6 rows;
  7. short hostile strings: at least 10 rows (empty, `=`, `:`, a lone `'`, a lone `"`, a lone `\`,
     `sid=`, `sid='`, `sid="\`, a lone `\u{a0}`).
- **Recording procedure (paste it into the report).** (1) Write the input list into the recorder.
  (2) `touch crates/aitm-core/src/redact.rs`, then `cargo test -p aitm-core --lib redact::tests::record_scrub_text_corpus -- --ignored --nocapture`
  and paste the printed rows into the const verbatim. If a character prints raw and invisible,
  rewrite it as a `\u{..}` escape and let the green run prove it. (3) Delete the recorder. (4) The
  anchor rows in "Claims traced by reading" must appear in the output as stated; a difference stops
  the Coder.
- **Red:** none. This is a `[guard]`: it must pass on the unmodified code, and is written and run
  there. **Bite check instead:** temporarily change `SECRET_KEY_SEGMENTS` to the empty slice, run the
  test, and paste its failure (it must list rows containing `sid=`); then restore the line by hand.
- **Green (paste):** `cargo test -p aitm-core --lib redact::tests::scrub_text_is_unchanged_on_the_recorded_corpus`
  prints `test result: ok. 1 passed`; then `cargo test -p aitm-core --lib redact` prints
  `test result: ok. 33 passed`, with the 32 original tests unedited.
- **Checks (paste each output):**
  - `git diff -U0 15009b2 -- crates/aitm-core/src/redact.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p' | sort -n | head -1`
    prints a number that is at least `374` (no production line changed, including by the bite check).
  - `git diff --stat 15009b2 -- crates` names only `crates/aitm-core/src/redact.rs`.
- **Done when:** the recorder output, the bite-check failure, the green runs and the two checks are
  quoted, the per-task gate passes, and the commit is made (`git add crates/aitm-core/src/redact.rs`).

### Task 1B: pin the scanner's name decisions and `scrub_embedded` (scanner, old tree)

- **Satisfies:** AC11, AC12, AC13, AC14.
- **Depends on:** none in code; **must run after 1A is committed and before Task 2** (see Execution order).
- **Files:** `crates/aitm-plugin-scanner/src/discover.rs` (modify, `mod tests` only),
  `crates/aitm-plugin-scanner/src/reproduce.rs` (modify, `mod tests` only).
- **Change and tests.** All four tests are `[guard]`: written first, green on the unmodified code.
  - `discover::tests::enumerate_redacts_a_wide_only_parameter_name` (AC11): a flow built with the
    existing `captured` helper for `/x?subsidiary=acme&author=bob&sidebar=1&page=2` gives example
    `REDACTED` (`<redacted>`) for `subsidiary`, `author` and `sidebar`, and `2` for `page`.
  - `reproduce::tests::build_poc_placeholders_a_wide_only_parameter` (AC12): a GET
    `/search?q=hello&author=ALICE` (`flow_with`, injection point `q` as in the neighbouring tests,
    `CheckDefinition::reflected_xss()`) built through `build_poc` has `author={{author}}` in the step
    URL, declares a variable named `author` with `required == true`, and the serialized PoC does not
    contain `ALICE`.
  - `reproduce::tests::scrub_embedded_and_is_secret_name_agree_on_every_key` (AC13): a table of
    `(key, is_secret)` with **at least 40 ASCII keys** made only of ASCII alphanumerics and `_ . -`:
    the 10 wide-only keys of Task 1A family 1 plus `Author` and `rhai.allow_agent_authoring` (12,
    `true`); the five words `sid`, `jwt`, `csrf`, `session`, `auth` (`true`); the 14 needles
    `Authorization`, `token`, `password`, `passwd`, `pwd`, `secret`, `cookie`, `api_key`, `apikey`,
    `api-key`, `bearer`, `credential`, `sessionid`, `phpsessid` (`true`); whole-segment keys `x-auth`,
    `_csrf`, `connect.sid`, `ASP.NET_SessionId` (`true`); and at least 12 non-secret keys `path`,
    `host`, `body`, `note`, `method`, `page`, `q`, `username`, `next`, `Content-Type`, `Referer`,
    `Content-Length` (`false`). For every row assert **both** `is_secret_name(key) == is_secret` and
    `(scrub_embedded("{key}=VALUE9") != "{key}=VALUE9") == is_secret` (the literal column is call 3;
    spec gap 2). ASCII only: `xsidéy` is DC1, where the two disagree today. Collect every bad row and
    assert the list is empty.
  - `reproduce::tests::scrub_embedded_matches_the_recorded_pipeline_output` (AC14):
    `const RECORDED_SCRUB_EMBEDDED: &[(&str, &str)]`, **at least 80 rows** of `(input, output)`
    recorded from the old `scrub_embedded`, asserted row by row with the list of bad rows in the
    message. Spot rows that must be in it (all certain, from existing tests):
    `subsidiary=acme` to `subsidiary=[redacted]`; `go to http://user:pw@host/p?x=1` to `go to
    http://host/p?x=1`; `sid="abc&x=1` to `sid="[redacted]&x=1`; `{"sid":"a\"b c","n":1}` to
    `{"sid":"[redacted]","n":1}`; and `auth.example.com:8443` to `auth.example.com:[redacted]` (traced:
    the old pipeline masks a host:port for any key holding one of the five words). Families, each at
    least the minimum: (i) **every string that reaches `scrub_embedded` in the existing
    `scrub_embedded_*` and `build_poc_scrubs_*` tests**, harvested as below; (ii) quotes and escapes,
    8; (iii) pairs nested in a non-secret key's value (`next=/cb?sid=S1`, `next=/cb?author=S1&x=1`,
    and kin), 6; (iv) URL userinfo (`http://user:pw@host/p?sid=S1`, `//auth:pw@host/x`), 6; (v) empty
    values, 6; (vi) `Authorization` and `Bearer`, 6; (vii) `Referer`-shaped values given directly,
    4; (viii) percent-decoded values as `scrub_decoded` hands them over (`/cb?sid=NEXTSID&jwt=NEXTJWT`),
    6; (ix) host:port rows for the five words, 6; (x) malformed families that stay clear of DC4,
    DC5 and DC6, 10.
  - **DC screen.** A row whose old output the new pipeline will change is not allowed in this table
    (it belongs to AC15). Keep out of it: a non-ASCII character glued to a key that holds a segment
    word; a newline or Unicode whitespace around the separator of a wide-only key; a needle-only
    dotted key (`token.example.com`) directly before `:` and digits; a quoted value of a five-word or
    wide-only key that holds an opener-shaped quote (a quote right after `=` or `:` and before a
    value character); a vertical tab or non-ASCII whitespace inside an unquoted value of such a key;
    an unclosed quote followed by an opener-shaped quote for such a key. (A five-word key with a
    newline after the separator, `sid:\nabc`, is fine: it behaved the standard way already.)
- **Harvest (for family i; paste the harvested list into the report).** Before adding the AC14 test,
  put `eprintln!("HARVEST {text:?}");` as the first statement of `scrub_embedded` (a temporary
  production edit), run `cargo test -p aitm-plugin-scanner -- scrub_embedded build_poc_scrubs --test-threads=1 --nocapture`,
  collect the distinct `HARVEST` strings, **then remove that line**. The harvest also picks up
  default header values; keep them, more rows are fine.
- **Recording.** As in Task 1A: a temporary `#[test] #[ignore]` recorder prints `({input:?},
  {output:?}),` rows from the old `scrub_embedded`; paste them verbatim; delete the recorder. In the
  same recorder run, also run the eight AC15 inputs of "Claims traced by reading" and **paste their
  outputs**; compare each with the "old pipeline" column: a mismatch stops the Coder (spec gap).
- **Red:** none (guards). **Bite check:** temporarily change `EXTRA_SECRET_NEEDLES` in `discover.rs`
  to the empty slice and run the scanner suite: paste the failing test names. At least the four new
  tests and `scrub_embedded_leaves_innocent_text_and_empty_values_alone` must be red. Restore by hand.
- **Green (paste):** `cargo test -p aitm-plugin-scanner -- enumerate_redacts_a_wide_only_parameter_name build_poc_placeholders_a_wide_only_parameter scrub_embedded_and_is_secret_name_agree_on_every_key scrub_embedded_matches_the_recorded_pipeline_output`
  prints `test result: ok. 4 passed`; then `cargo test -p aitm-plugin-scanner` prints `test result: ok.
  182 passed`.
- **Checks (paste each output):**
  - `git diff -U0 15009b2 -- crates/aitm-plugin-scanner/src/reproduce.rs | sed -n 's/^@@ -\([0-9][0-9]*\).*/\1/p' | sort -n | head -1`
    prints a number at least `613`; the same for `discover.rs` prints a number at least `266`
    (no production line changed, including by the harvest and the bite check).
  - `git diff --stat 15009b2 -- crates` names only `discover.rs` and `reproduce.rs` of the scanner.
  - `grep -rnwE "EXTRA_SECRET_NEEDLES|redact_needle_pairs|names_a_secret|ends_value|closing_quote|is_key_byte" crates/aitm-plugin-scanner/src | wc -l`
    still prints `21` (your comments add no banned word).
- **Done when:** the harvest, the recorder output, the eight DC-input outputs, the bite-check
  failures, the green runs and the checks are quoted, the gate passes, and the commit is made
  (`git add` the two files by path).

### Task 2: core's wide reading, the private seam, and the core docs

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6, AC7, AC9, AC10 (check), AC19 (count), the core items
  of AC20, the blast-radius half of AC21.
- **Depends on:** 1A and 1B committed.
- **Files:** `crates/aitm-core/src/redact.rs` (modify).
- **Change (signatures only; spec Design 2 to 4 and 9 are the authority):**
  - add `pub fn is_secret_key_wide(key: &str) -> bool`: true when `is_secret_key(key)`, or the
    ASCII-lowercased key contains any `SECRET_KEY_SEGMENTS` word as a substring. One lowercase
    allocation per call. Documented as for decisions where a false positive costs nothing and a miss
    leaks (a shareable PoC, an injection-point example), and never for MCP argument keys, audit
    summaries or text a human reads, because `authority` is a real argument key.
  - add `pub fn scrub_text_wide(text: &str) -> String`: `scrub_text` with the pair pass judging keys
    by `is_secret_key_wide` and **no host:port exemption**. Same two regex passes first. Its doc says
    it over-redacts by design, names the one difference from `scrub_text`, and says everything else
    (value rule, quotes, whitespace, nested pairs) is shared.
  - private seam, names are the builder's except the parameter, which is called `reading`: a private
    two-variant `Reading` (`Standard`, `Wide`); `fn scrub_with(text: &str, reading: Reading) ->
    String` (the two regex passes, then the scan); `fn mask_secret_pairs(text: &str, reading:
    Reading) -> String`; a private helper for the substring test over `SECRET_KEY_SEGMENTS` on an
    already lowercased string. `scrub_text` and `scrub_text_wide` are thin entry points over
    `scrub_with`. **`reading` is read in exactly two places in `mask_secret_pairs`:** the secret test
    of a key run (`is_secret_key` for `Standard`, `is_secret_key_wide` for `Wide`) and the host:port
    exemption (applied for `Standard`, never for `Wide`). It is not read anywhere that decides where
    a key run, blank, separator, value or closing quote starts or ends. Do not use the word `reading`
    in a comment inside the body of `mask_secret_pairs`.
  - `is_secret_key` and `scrub_text` keep their signatures and, byte for byte, their output. Share
    the lowercase body with the new function if you like; AC2, AC8 and the 32 untouched tests pin it.
  - **Docs (spec Design 9 items 1 to 5; check each off in the report):** (1) delete the two `//`
    pointer comments above `ends_value` and above `closing_quote` (their `///` docs stay unedited);
    (2) the module doc: one list, two readings, `scrub_text` and `scrub_text_wide` named, "so the two
    cannot diverge" extended to the wide reading; (3) the `SECRET_KEY_SEGMENTS` doc: the same words
    are what the wide reading matches as substrings; (4) the `scrub_text` doc: one sentence pointing
    to `scrub_text_wide` for the over-matching reading (the host:port paragraph stays); (5) the
    `mask_secret_pairs` doc: the reading parameter is consulted in exactly two places. No banned word.
- **Tests (written first)**, in `mod tests`, with the literal values of the spec. Where a table row
  has a literal expected value, the test asserts that value and also the agreement the spec names.
  - `is_secret_key_wide_reads_the_segment_words_as_substrings` (AC1): `is_secret_key_wide` true and
    `is_secret_key` false for `author`, `authority`, `authenticated`, `inside`, `side`, `sidebar`,
    `subsidiary`, `sessions`, `Author`, `X-Authority`, `rhai.allow_agent_authoring`, `userSession`;
    both true for `sid`, `X-CSRF`, `connect.sid`, `PHPSESSID`, `Authorization`; both false for `path`,
    `host`, `body`, `note`, `method`, `page`, `q`, `username`, `next`, `Content-Type`, `Referer`.
    Collect bad keys and assert the list is empty.
  - `is_secret_key_wide_is_a_superset_of_is_secret_key` (AC2): over the union of the key lists in the
    existing `is_secret_key_covers_the_session_and_auth_family`, `is_secret_key_leaves_lookalikes_alone`
    and `secret_keys_matched_as_substring_case_insensitively`, the 14 needles spelled out, and the
    non-secret keys of AC1: `is_secret_key(k)` implies `is_secret_key_wide(k)`.
  - `is_secret_key_wide_names_every_segment_word` (AC3): the literal list `["sid", "jwt", "csrf",
    "session", "auth"]` (not read from the const: a dropped word must fail), each as the bare word,
    upper case, `x-{w}-y` and `my{w}2`: all true.
  - `scrub_text_wide_and_is_secret_key_wide_share_one_vocabulary` (AC4): a table of `(key,
    expected_wide)`: the 38 keys of the existing `scrub_text_and_is_secret_key_share_one_vocabulary`
    plus the wide-only keys of AC1. Expected `true` for every key except `path`, `host`, `body`,
    `note`, `method`, which are `false`. For each key assert `is_secret_key_wide(key) == expected` and
    `(scrub_text_wide("{key}=VALUE9") != "{key}=VALUE9") == expected`.
  - `scrub_text_wide_masks_a_wide_only_pair_as_a_standard_pair` (AC5), exact rows:
    `author=bob&page=2` to `author=[redacted]&page=2`; `{"subsidiary":"a b","n":1}` to
    `{"subsidiary":"[redacted]","n":1}`; `sidebar='x y' z=1` to `sidebar='[redacted]' z=1`;
    `author:\n  John` to `author:\n  [redacted]`; `sidebar=abc\u{a0}def` to
    `sidebar=[redacted]\u{a0}def`; `sidebar='abc def token='S3'` to `sidebar='[redacted]'`;
    `{"sidebar":"YWJj=","user":"bob"}` to `{"sidebar":"[redacted]","user":"bob"}`;
    `next=/cb?sidebar=S1` to `next=/cb?sidebar=[redacted]`; `sidebar=&x=1` unchanged.
  - `scrub_text_wide_does_not_exempt_a_host_port` (AC6): `auth.example.com:8443` to
    `auth.example.com:[redacted]`; `https://auth.example.com:8443/login` to
    `https://auth.example.com:[redacted]`; `token.example.com:8443/x` to
    `token.example.com:[redacted]`; `sid:12345` to `sid:[redacted]`. The paired guard,
    `scrub_text_does_not_mask_a_host_port`, is untouched and stays green.
  - `scrub_text_wide_survives_hostile_inputs_and_stays_linear` (AC7), `assert!` on `==`:
    `"sidebar=".repeat(1 << 19)` is `sidebar=[redacted]`; `"sidebar=\"x ".repeat(150_000)` is
    `"sidebar=\"[redacted] ".repeat(150_000)`; `"sidebar='x sidebar=\"x ".repeat(75_000)` is
    `"sidebar='[redacted] sidebar=\"[redacted] ".repeat(75_000)`; `"author.x:1 ".repeat(300_000)` is
    `"author.x:[redacted] ".repeat(300_000)`; a 1 MiB run of `é` and of `\u{a0}`, and `"sidébar=x
    ".repeat(100_000)`, return without panic. The test finishing is the check.
  - `scrub_text_wide_agrees_with_scrub_text_when_nothing_wide_applies` (AC9): for every row of
    `RECORDED_SCRUB_TEXT` with the third column `true`, `scrub_text_wide(input) == scrub_text(input)`;
    assert at least 25 rows were checked, and list every disagreeing input.
- **Red, three steps (paste each).** (1) Tests only: `cargo test -p aitm-core --lib redact` fails to
  compile; quote the `error[E0425]` lines naming `is_secret_key_wide` and `scrub_text_wide`. (2) Add
  both functions as stubs with the old behaviour (`is_secret_key_wide` returns `is_secret_key(key)`,
  `scrub_text_wide` returns `scrub_text(text)`): it now compiles, and the **failing set must be
  exactly** AC1, AC3, AC4, AC5, AC6, AC7 (quote each failure's first bad row). AC2 and AC9 pass on
  the stubs (they are properties the stubs satisfy; they were red only at step 1): say so. (3) Implement.
- **Green (paste):** `cargo test -p aitm-core --lib redact` prints `test result: ok. 41 passed`.
- **Checks (paste each output):**
  - AC10, tests untouched. Use temp files: process substitution (`<( )`) is refused by the sandbox
    and the pipeline would then print a false `0`.
    `git show 15009b2:crates/aitm-core/src/redact.rs | sed -n '/^#\[cfg(test)\]/,$p' > "$TMPDIR/redact-tests-before.rs"`,
    `sed -n '/^#\[cfg(test)\]/,$p' crates/aitm-core/src/redact.rs > "$TMPDIR/redact-tests-after.rs"`,
    then `wc -l < "$TMPDIR/redact-tests-before.rs"` prints `704` (proves the extract is not empty) and
    `diff "$TMPDIR/redact-tests-before.rs" "$TMPDIR/redact-tests-after.rs" | grep -c '^<'` prints `0`
    (no line of the original test module is removed or changed; `>` lines are the additions). If
    `diff` prints an error, the check did not run.
  - AC10, API: `git diff -U0 15009b2 -- crates/aitm-core/src/redact.rs | grep -E '^[-+][[:space:]]*pub '`
    prints exactly two lines: `+pub fn is_secret_key_wide(key: &str) -> bool {` and `+pub fn
    scrub_text_wide(text: &str) -> String {`. `git diff 15009b2 -- crates/aitm-core/src/lib.rs` is empty.
  - AC19: `sed -n '/^fn mask_secret_pairs/,/^}/p' crates/aitm-core/src/redact.rs | grep -n reading`
    prints exactly three lines: the signature and the two uses. Name each line in the report; if a use
    is split over two lines and the count differs, say which lines are the two uses.
  - AC20, core part: `grep -nE "only knows|widened locally|needle layer|two vocabularies|none is in .scrub_text|vocabulary consolidation|stays until|scanner's copy" crates/aitm-core/src/redact.rs`
    prints nothing.
  - Blast radius, each prints `test result: ok` with 0 failed: `cargo test -p aitm-poc`,
    `cargo test -p aitm-findings`, `cargo test -p aitm-plugins`, `cargo test -p aitm-plugin-scanner`
    (182 passed). `cargo test -p aitm-core` is in the per-task gate, so `trust_gate_scan` and
    `classifier_wildcard_free` run.
- **Done when:** the three red outputs, the green output and every check are quoted, the Design 9
  items 1 to 5 are listed as done, the gate passes, `git diff --stat 15009b2 -- crates` shows
  `redact.rs` (core) and the two scanner files of Task 1B only, and the commit is made.

### Task 3: scanner swap, deletions, stale-doc fixes, DC rows, one rename

- **Satisfies:** AC15, AC16, AC17, AC18, AC20 (scanner part), and AC11 to AC14 staying green unedited.
- **Depends on:** 1B and 2.
- **Files:** `crates/aitm-plugin-scanner/src/discover.rs` (modify),
  `crates/aitm-plugin-scanner/src/reproduce.rs` (modify). `crawl.rs`, `commands.rs`, every
  `Cargo.toml` and `Cargo.lock` stay untouched.
- **Step order (test first).** (1) Write the AC15 test. (2) Run it against the still-unmodified
  production code and paste the red run. (3) Do the swap. (4) Do the docs and the test edits.
- **Change:**
  - `discover.rs`: delete `EXTRA_SECRET_NEEDLES` and its doc. `pub(crate) fn is_secret_name(name:
    &str) -> bool` keeps its signature and visibility and becomes a one-line delegate to
    `aitm_core::redact::is_secret_key_wide`; change the import accordingly and drop any import that is
    now unused. Rewrite its doc: a delegate, "so `reproduce`'s PoC scrubber masks exactly the names
    `enumerate` redacts". Module doc (spec Design 9 item 9): "widened locally by `is_secret_name`..."
    becomes the wide reading in core.
  - `reproduce.rs`: imports become `use aitm_core::redact::{scrub_text, scrub_text_wide};` and
    `use crate::discover::{is_secret_name, InjectionPoint};` (`scrub_text` stays: `scrub_url` uses it).
    `fn scrub_embedded(text: &str) -> String` becomes the single expression
    `scrub_text_wide(&strip_userinfo(text))`. Delete `is_key_byte`, `ends_value`, `names_a_secret`,
    `redact_needle_pairs` and `closing_quote` (about lines 383 to 508) and their docs; `origin_and_path`
    and everything after stay. Rewrite the module doc (~17 to 22) and the `scrub_embedded` doc (~362
    to 381) per spec Design 9 items 6 and 7 (URL userinfo stripped, then `scrub_text_wide`; the
    three-step description and the claim about `scrub_text` alone are false and go).
  - **Tests edited, the complete list (spec Design 8; nothing else existing changes):**
    `scrub_embedded_covers_every_extra_secret_needle` is renamed `scrub_embedded_covers_every_segment_word`
    and iterates the literal `["sid", "jwt", "csrf", "session", "auth"]`, with the same three
    assertions per word (`is_secret_name(word)`; `scrub_embedded("x_{word}_y=V1&z=2") ==
    "x_{word}_y=[redacted]&z=2"`; `scrub_embedded("{WORD}: V1") == "{WORD}: [redacted]"`) and a doc
    comment that drops "built from the very slice". Comment-only edits: the doc of
    `build_poc_drops_the_referer_query_and_leaks_no_session_id` (~1315, history wording, "before PR
    171 none of these names was in the shared set"); the doc of
    `build_poc_scrubs_session_ids_embedded_in_a_non_secret_header` (~1372, "the embedded-value scrub on
    its own"); the inline comment in `scrub_embedded_masks_every_shared_vocabulary_name` (~1510, one
    scan, one list); the doc of `enumerate_redacts_common_auth_parameter_names` (`discover.rs` ~537,
    reword, no assertion change).
- **Test (written first):** `reproduce::tests::scrub_embedded_deliberate_changes_are_exactly_these`
  (AC15): the eight rows of the "new (spec AC15)" column in "Claims traced by reading", collected into
  one mismatch list `(input, expected, actual)` and asserted empty, so one red run shows all eight
  old outputs. Each row has a comment `// old pipeline: <old output> (DCn)` using the recorded old
  output, written without any banned word.
- **Red (paste):** `cargo test -p aitm-plugin-scanner -- scrub_embedded_deliberate_changes_are_exactly_these`
  fails with all eight rows in the mismatch list, and each `actual` equals the "old pipeline" column.
  A difference stops the Coder. Also paste, on the unmodified code: the AC17 grep with `| wc -l`
  printing `21`, and the AC20 grep printing the five scanner lines (`discover.rs` once, `reproduce.rs`
  four times; core's four are already gone after Task 2).
- **Green (paste):** the AC15 test passes; `cargo test -p aitm-plugin-scanner` prints `test result: ok.
  183 passed`, with AC11 to AC14 and every pre-existing test green. If an AC14 row is red: a row whose
  new output fits one of DC1 to DC6 moves to the AC15 table with its old output in a comment and is
  listed in the report; a row that fits none **stops the Coder** (spec gap, not a row to move or
  drop).
- **Checks (paste each output):**
  - AC17: `grep -rnwE "EXTRA_SECRET_NEEDLES|redact_needle_pairs|names_a_secret|ends_value|closing_quote|is_key_byte" crates/aitm-plugin-scanner/src`
    prints nothing. No word list in non-test scanner code:
    `for f in discover reproduce; do t=$(grep -n '^#\[cfg(test)\]' crates/aitm-plugin-scanner/src/$f.rs | cut -d: -f1); grep -n '"jwt"\|"csrf"\|"session"' crates/aitm-plugin-scanner/src/$f.rs | awk -F: -v t=$t '$1<t'; done`
    prints nothing. `sed -n '/^fn scrub_embedded/,/^}/p' crates/aitm-plugin-scanner/src/reproduce.rs`
    prints exactly three lines: the signature, `    scrub_text_wide(&strip_userinfo(text))`, and `}`.
  - AC16, names: the before list is read out of git, so it excludes Task 1B's additions:
    `for f in $(git ls-tree -r --name-only 15009b2 crates/aitm-plugin-scanner/src); do git show 15009b2:$f | awk '/#\[(tokio::)?test/ {t=1; next} t && /^[ \t]*(async )?fn / {match($0,/fn [A-Za-z0-9_]+/); print substr($0,RSTART+3,RLENGTH-3); t=0}'; done | sort > "$TMPDIR/scanner-names-before.txt"; wc -l < "$TMPDIR/scanner-names-before.txt"`
    prints `178`. After: `cargo test -p aitm-plugin-scanner -- --list 2>/dev/null | grep ': test$' | sed 's/: test$//; s/.*:://' | sort > "$TMPDIR/scanner-names-after.txt"; wc -l < "$TMPDIR/scanner-names-after.txt"`
    prints `183`. `comm -23 "$TMPDIR/scanner-names-before.txt" "$TMPDIR/scanner-names-after.txt"` prints exactly
    `scrub_embedded_covers_every_extra_secret_needle`. `comm -13` prints exactly six names:
    `build_poc_placeholders_a_wide_only_parameter`, `enumerate_redacts_a_wide_only_parameter_name`,
    `scrub_embedded_and_is_secret_name_agree_on_every_key`, `scrub_embedded_covers_every_segment_word`,
    `scrub_embedded_deliberate_changes_are_exactly_these`, `scrub_embedded_matches_the_recorded_pipeline_output`.
  - AC18: `git diff 15009b2 --stat -- crates/aitm-plugin-scanner/src/crawl.rs crates/aitm-plugin-scanner/src/commands.rs`
    prints nothing; `git diff 15009b2 -- '*.toml' Cargo.lock` prints nothing;
    `git diff 15009b2 -- crates | grep -E '^\+.*unsafe'` prints nothing; `cargo test -p aitm-plugin-scanner`
    already passes `crawl` and `commands` tests unedited.
  - AC20: `grep -rnE "only knows|widened locally|needle layer|two vocabularies|none is in .scrub_text|vocabulary consolidation|stays until|scanner's copy" crates/aitm-core/src/redact.rs crates/aitm-plugin-scanner/src`
    prints nothing, and each of Design 9 items 6 to 10 is listed as done.
  - Callers: `grep -rln "scrub_text_wide\|is_secret_key_wide" crates` prints exactly
    `crates/aitm-core/src/redact.rs`, `crates/aitm-plugin-scanner/src/discover.rs`,
    `crates/aitm-plugin-scanner/src/reproduce.rs`.
  - `git diff --stat 15009b2 -- crates` names only `redact.rs` (core), `discover.rs` and `reproduce.rs`.
- **Done when:** the red run, the green runs and every check are quoted, the per-task gate passes, and
  the commit is made (`git add` the two files by path).

### Task 4 (Stage 5): Tester, whole branch

- **Satisfies:** AC10, AC16, AC18, AC21, AC22, AC23 (and the coverage map for every AC).
- **Depends on:** Task 3 committed.
- **Files:** tests only: the `#[cfg(test)]` modules of `crates/aitm-core/src/redact.rs`,
  `crates/aitm-plugin-scanner/src/discover.rs`, `crates/aitm-plugin-scanner/src/reproduce.rs`.
  Scratch copies live outside the repo (below). Never change production code in the branch.
- **Dispatch:** spec path, plan path, worktree path, base `15009b2`, head (the Task 3 commit),
  "whole branch", and the Coder reports of Tasks 1A, 1B, 2, 3.
- **Work:**
  1. **Coverage map** for AC1 to AC24 as a table (criterion, test, status), using the AC coverage
     table above. A criterion with no test is a finding.
  2. **Test quality.** Read every new test. Flag a test that would pass if the implementation
     returned a default. Rewrite it or add a stronger one. Add edge cases within the three files:
     non-ASCII at a boundary of `scrub_text_wide`, `scrub_embedded` with `//auth:pw@host/x` (userinfo
     stripped first), a key at the very end of the text, an empty string. Commit added tests
     separately as `test(<area>): tester, <what>`.
  3. **Mutants (AC23), in a scratch copy, never in the branch** (spec gap 1). Set
     `SCRATCH="$TMPDIR/svc-mutants"`, create it, and run `git archive <head> | tar -x -C "$SCRATCH"` (a path outside
     the repo and outside the worktree), and build with `CARGO_TARGET_DIR="$SCRATCH/target"` and
     `cargo test --offline`, never sharing the worktree's target directory. Keep a pristine copy of
     each file you mutate. For each mutant: save `diff -u pristine mutated`, run `cargo test -p
     aitm-core --lib redact` and `cargo test -p aitm-plugin-scanner`, record the red test names, then
     restore the file by `cp` from the pristine copy and run once more to show it is green. Adapt the
     one-line mutation to the code as built, keeping its meaning:

     | Mutant | Edit in the scratch copy | Tests that must go red |
     |---|---|---|
     | (a) | `is_secret_key_wide` returns `is_secret_key(key)` and nothing else | AC1, AC3, AC4, AC5, AC7, AC11, AC12, AC13, AC14, AC15, and the existing `scrub_embedded_leaves_innocent_text_and_empty_values_alone` (AC2, AC6 and AC9 stay green: they hold for the standard reading too) |
     | (b) | the wide reading applies the host:port exemption too | AC6, AC7, AC14, AC15 |
     | (c) | `scrub_text` runs the scan with the wide reading | AC8, the existing `scrub_text_leaves_lookalike_pairs_alone`, the existing `scrub_text_and_is_secret_key_share_one_vocabulary` |
     | (d1) to (d5) | drop one word at a time (`sid`, `jwt`, `csrf`, `session`, `auth`) from the substring check of the wide reading | AC3 for every word; name the other red tests per word |

     A mutant that leaves a listed test green is a finding (weak test): strengthen it and re-run. The
     branch is proven untouched by `git status --short` printing nothing and `git diff <head> --stat`
     printing nothing, both before and after the mutant runs (commit the Tester's own added tests
     before starting the mutants, so the tree is clean).
  4. **Structural checks** with the literal expected outputs of Task 2 (AC10, AC19, AC20 core) and
     Task 3 (AC16, AC17, AC18, AC20, callers), re-run from scratch.
  5. **The gate.** Sandbox, from the worktree: `cargo fmt --check && cargo clippy --all-targets -- -D warnings`
     and `cargo test -p aitm-core -p aitm-plugin-scanner -p aitm-poc -p aitm-findings -p aitm-plugins`,
     pasted verbatim, with any port-binding failure reported "NOT RUN (socket)". The orchestrator then
     runs in the Terminal panel, redirected to a log and gated on exit status (never on a grep):
     `( cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test ) > "$LOG" 2>&1; echo "exit=$?"`
     which must print `exit=0` (judge the known `aitm-rhai` flake by whether Rhai is touched: it is
     not), and `cargo test -p aitm-mcp` in the Terminal for AC21.
- **Report:** the coverage table; the added or rewritten tests and why; each mutant's patch, red set
  and restored green; the gate output verbatim; PASS or FAIL.
- **Done when:** every AC has a passing test or review check, every mutant is killed as listed, the
  gate prints `exit=0`, and the verdict is PASS.

### Task 5 (Stage 6): panel on the whole branch, with the out-of-tree differential

- **Satisfies:** AC19, AC20 (reading the diff), AC24, and the panel gate of WORKFLOW stage 6.
- **Depends on:** Task 4 PASS.
- **Files:** none. Reviewers are read-only on this branch and **never edit it**. They write only into
  scratch copies outside the repo and outside the worktree, and return their report as the final
  message in `docs/superpowers/REVIEW-TEMPLATE.md` form; the orchestrator records every finding.
- **Dispatch:** to each of the three reviewers in parallel, with fresh context: spec path, plan path,
  worktree path, base `15009b2`, head SHA, "whole branch", the Coder reports (1A, 1B, 2, 3), the
  Tester report, and no prior review report.
- **Spec reviewer:** AC1 to AC24 against the diff and the tests; Design 8 (the five edited tests are
  the only existing tests touched; AC16) and Design 9 (all ten items); every DC1 to DC6 has a row in
  AC15 and none changed an existing assertion; the AC14 corpus holds no row that DC1 to DC6 change;
  the Tester's extra tests are tests only.
- **Quality reviewer:** the seam is one scan with a two-use parameter (AC19, by reading the diff);
  no logic duplicated between the two readings; one lowercase allocation per candidate; doc accuracy
  and no overclaim; test hygiene (readable corpora, escapes not raw characters, `assert!` on large
  strings, no dead code, no leftover recorder or harvest line); the rename and the five comment edits.
- **Security reviewer:** DC5 and DC6 (the two changes that leave more in the clear) rated Critical,
  Important or Minor, with a stated exposure; `scrub_text` and `is_secret_key` byte-for-byte
  unchanged (AC8, AC10); the wide functions are public (spec Residual risk 5) and called only from the
  scanner (the callers check of Task 3); hostile-input linearity; the corpora hold only fake
  canaries; and **the differential (AC24)** below.
- **The differential, built out of tree from the old tree (AC24).**
  1. **Scratch checkouts, never inside the repo or this worktree.** Pick `SCRATCH="$TMPDIR/svc-diff"`.
     Old tree: `git worktree add --detach "$SCRATCH/old" 15009b2` (the orchestrator runs this in the
     Terminal panel if the sandbox refuses), or, with no `.git` writes at all,
     `mkdir -p "$SCRATCH/old" && git archive 15009b2 | tar -x -C "$SCRATCH/old"`. New tree: `git archive <head> | tar -x -C "$SCRATCH/new"`.
     Record in the report which method was used and the output of `git rev-parse 15009b2` (the full
     SHA the old tree was cut from), and that the new tree was cut from the head under review.
  2. **A wrapper and a runner in each scratch copy only** (neither is ever copied to the branch): in
     `crates/aitm-plugin-scanner/src/reproduce.rs` of each scratch tree, one `#[doc(hidden)] pub fn`
     taking `&str` and returning `String` that calls the private `scrub_embedded`; and in
     `crates/aitm-plugin-scanner/examples/` one example that reads one JSON-encoded string per line
     from stdin and writes the JSON-encoded result per line to stdout (`serde_json` is already a
     dependency of the scanner, so no manifest changes). The runner source is identical in both trees.
  3. **Build each with its own target directory:**
     `CARGO_TARGET_DIR="$SCRATCH/target-old" cargo build --release --offline -p aitm-plugin-scanner --example <runner>`
     and the same for `new`. These are full builds in fresh target directories: check `df -h` first
     (worktree targets are large) and, if `$TMPDIR` is too small, the orchestrator runs the
     differential in the Terminal panel. **Delete `$SCRATCH` when done** (`git worktree remove --force`
     and `git worktree prune` if a worktree was used, then `rm -rf`), and say so in the report.
  4. **A seeded, chunked generator and a lock-step checker** (Python is fine; run it with `python3 -I`):
     generate a chunk of inputs from a seed, pipe it through both runners, compare the two output
     streams line by line, apply the invariants, discard the chunk. Every secret value in an input is a
     unique canary token, so leaks are counted exactly.
  5. **Alphabets and invariants are the spec's Design 7 item 3, verbatim:** the aligned alphabet,
     I1 (no regression), I2 (equality, byte for byte, on the aligned alphabet), I3 (full alphabet: no
     panic, no char-boundary error, linear time, and every canary `new` leaves while `old` masked is in
     an input holding a vertical tab, a non-ASCII whitespace character, or an unclosed or unmatched
     quote). **Counts:** at least 3,000,000 inputs in all; at least 1,000,000 on the aligned alphabet
     and at least 1,000,000 on the full alphabet; the rest at the reviewer's choice (for example inputs
     built around each of DC1 to DC6). For I3's timing, time the new runner on hostile inputs at 1, 2, 4
     and 8 MiB, state which reading of "3x ... per doubling" was used (spec gap 6), and report the times.
  6. **Positive controls, before the big run.** (a) Run the eight AC15 inputs through both runners:
     old and new must equal the two columns of "Claims traced by reading", which also proves the
     wiring. (b) Build a mutant-(a) tree from the Tester's scratch patch (`is_secret_key_wide` returns
     `is_secret_key` only) and point the checker at it: it must report I1 and I2 violations within the
     first 100,000 aligned inputs. A checker that cannot find a known violation proves nothing.
  7. **Report (AC24):** the tool and scratch layout, the seeds, the input counts per alphabet, the
     counts of I1, I2 and I3 results, the timing table, the positive-control results, the cleanup, and
     every violation classified (a code defect, or a counterexample showing the spec's table wrong,
     which is a finding against the spec). Zero violations, or each classified.
- **Done when:** three reports are in, every finding is in the Review log, and no Critical or
  Important finding is open. A Minor is fixed or accepted by Matt in writing in the Review log.

### Fix-task protocol

Applies to any finding from the Tester or the panel.

1. The orchestrator records every finding in the Review log (one row each) with its severity.
2. **Critical and Important** go to a fresh Coder as a fix task: input is the findings report (not a
   task number), the spec path, the plan path, the worktree path. For each finding the Coder writes a
   test that reproduces it and fails, fixes it, watches it pass, and commits as `fix(<area>): <finding
   title>`. It touches only the files the findings name, fixes nothing else, and pastes the red and
   green runs. The per-task gate must pass.
3. Then the Tester and the panel run again on the fix, with the prior report in hand, and the
   differential is re-run if the fix touches `redact.rs` or the scanner scrub path.
4. **Spec-shaped findings go to the Architect first, not to a Coder.** In particular: if the security
   panel rates DC5 or DC6 Important, the spec's named fallback (one branch confined to the wide
   reading) reintroduces a second value rule and changes the AC list, so the Architect amends the spec
   and plan, and the orchestrator approves, before any Coder builds it. A counterexample that shows a
   spec table wrong is handled the same way.
5. **Minor** findings are fixed in a fix task, or accepted by Matt in writing in the Review log with the
   reason. The branch merges only when the final panel has no open finding.
6. A Coder or Tester that finds the spec or plan wrong stops and reports the exact sentence; it does not
   redesign. The Architect owns every edit to `docs/superpowers/specs/` and `docs/superpowers/plans/`,
   except the plan's Status line, Review log and Shipped section, which the orchestrator owns.

### Integration notes (Stage 7, orchestrator)

Before the panel, rebase on `main` (fetch in the Terminal panel) and re-run the gate: CI tests the
branch plus current `main`, so a sibling's new test appended to `reproduce.rs` can fail only there.
Check `git worktree list` before dispatching Task 1A for any live session touching `redact.rs`,
`reproduce.rs` or `discover.rs` (spec Design 11), and keep the window short. If a rebase moves the
base, give the new merge-base to the Tester and the panel. Push with
`git push origin claude/scanner-vocab-7d36bb` (Terminal panel). Before `gh pr merge`, confirm
`baseRefName` is `main`.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
