# neg/nonexistent-flow marks implementation plan

**Status:** approved (2026-10-31 by Matt via the delegating orchestrator, autonomous-approve mode); amended 2026-10-31 by the orchestrator (self-approved) after panel review: Task 2 (F4 edit type, F5, one copy per run, AC4 base), Task 3 added, Review log and Shipped filled
**Spec:** `docs/superpowers/specs/2026-10-31-neg-nonexistent-flow-marks-design.md`
**Branch / worktree:** `claude/sleepy-goldwasser-9ec645` (base `main` f979040, after PR #172 and #156 merged; failure first seen on 840e520) in `/Users/matt/Security/aitmproxy/.claude/worktrees/sleepy-goldwasser-9ec645`

## Overview

Three sequential tasks (Task 3 was added after the first panel review); none is independent (Task 2 reads Task 1's file, Task 3 edits it). Task 1 (Coder)
edits the single test file; its helper behaviour is proven in the sandbox with a
no-port Python check. Task 2 (Tester) runs the real e2e and the four fault
injections. All port-binding runs go through the Terminal panel (`run_in_terminal`,
Matt's real shell; the Bash sandbox cannot bind ports), from the worktree root so
`run.py` uses this worktree's `target/debug`. Run each command on its own, log to a
file, and judge by exit status, not a grep pipeline. If the Tester cannot reach the
Terminal, the orchestrator runs the listed commands and hands back the raw output.
No Rust changes, so the Rust gate is not required (spec AC5).

Stage 6: Task 2 commits nothing (throwaway files are deleted), so the branch diff
is Task 1's plus Task 3's. The three reviewers ran in parallel after Task 2 (round 1) and again after Task 3 and
its wording follow-up (round 2), each with the prior reports as input; stage not skipped.

## Tasks

### Task 1: harden the marks assertion

- **Satisfies:** AC2 (new side), AC4, AC5, AC6; enables AC1, AC3, AC7
- **Depends on:** none
- **Step 0 (orchestrator, Terminal, before the Coder starts):** with `AITM_NO_BUNDLED_SCRIPTS` unset, `cargo build -p aitm -p aitm-testtarget`, then `python3 tests/e2e/run.py --shared-core neg`. Expected: `neg/test_nonexistent_flow_error` FAIL at `flow.detail of the REAL flow is byte-identical: no mark/comment/mutation landed elsewhere`. If it passes (race), rerun up to 3 times. Paste the output under Shipped (AC2 red).
- **Files:** `tests/e2e/neg/test_nonexistent_flow_error.py` (modify; nothing else)
- **Change:**
  - Module constant `BARRAGE_MARK = "e2e-missing"`, beside the other constants (near `FLOOD_N`). The `flow.mark` entry of `MISSING_ID_CALLS` uses `[BARRAGE_MARK]`.
  - `def marks_of(detail: Any) -> List[str]`: returns `detail["meta"]["marks"]`; calls `fail("flow.detail has no meta.marks list: ...")` if `detail`, `meta`, or `marks` is missing or not the right type.
  - `def without_marks(detail: Dict[str, Any]) -> Dict[str, Any]`: deep copy with only `meta.marks` removed; never mutates its argument.
  - In `main()`: right after the existing `detail_before` check, `marks_before = marks_of(detail_before)`. Replace the single check at the `detail_after == detail_before` line with three `check` calls in this order, using the spec's fixed prefixes (checks (i) and (ii) end with `(marks <before> -> <after>)`; check 1 ends with `(differs in: <keys>)` after Task 3):
    1. `without_marks(detail_after) == without_marks(detail_before)`
    2. `BARRAGE_MARK not in marks_after`
    3. `set(marks_before) <= set(marks_after)`
  - Header docstring, the "byte-identical before/after (no mark, no comment, no mutation ...)" clause: rewrite per spec Design 4.
  - Do not edit `entries = activity_since(...)` or anything below the `ground truth: the audit ring` section (PR #172).
- **Test:** (write first, run it, watch it fail, then pass; no ports needed) from `tests/e2e/neg`: `python3 -c "import test_nonexistent_flow_error as t; ..."` asserting:
  - `t.BARRAGE_MARK == "e2e-missing"`
  - `t.without_marks({"meta": {"marks": ["a"], "comment": None}, "edited": False}) == {"meta": {"comment": None}, "edited": False}`
  - the dict passed in still has `["meta"]["marks"] == ["a"]` afterwards
  - `t.marks_of({"meta": {"marks": ["a", "b"]}}) == ["a", "b"]`
  - some `MISSING_ID_CALLS` entry is `flow.mark` and its lambda returns `{"id": "x", "marks": [t.BARRAGE_MARK]}` for id `"x"`
  Before the edit these raise `AttributeError`; after, all hold. Also `python3 -m py_compile` passes, and `grep -c -E 'missing-nosniff|version-disclosure' <file>` prints `0`.
- **Done when:** the check above passes (output shown, red then green), py_compile passes, `git diff --stat` shows only this file, and the Coder's report lists that the real-core run was not possible in the sandbox.

### Task 2: real-core verification and fault injection

- **Satisfies:** AC1, AC2 (green side), AC3, AC4, AC7
- **Depends on:** Task 1
- **Files:** throwaway `tests/e2e/neg/test_zz_inject_leak_mark.py`, `..._wipe_mark.py`, `..._leak_comment.py`, `..._leak_mutation.py`, and (after Task 3, spec AC8) `..._store_leak.py` (create, run, delete; never committed)
- **Change:** each copy is the final test plus one inserted block immediately before `detail_after = rd.call("flow.detail", ...)`, acting on `real_id` over a Write-capable connection: F1 `flow.mark` with `[BARRAGE_MARK]`; F2 a sentinel `flow.mark` inserted before `detail_before`, then after the barrage `flow.mark` with a list not containing the sentinel or `BARRAGE_MARK`; F3 `flow.comment` with text `"injected"`; F4 `flow.mutate` with a request header edit `{"headers": {"x-e2e-injected": "1"}}` (a response `status` edit is refused on a completed flow; Tester's call, it must change `flow.detail`).
- **Test (literal expectations, run in the Terminal):**
  - AC1: `python3 tests/e2e/run.py --shared-core web audit neg` -> exit 0; `neg/test_nonexistent_flow_error` PASS; no SKIP for `audit`/`neg`.
  - AC7: `python3 tests/e2e/run.py --shared-core neg` three times, exit 0 each.
  - AC3: each copy in its OWN `python3 tests/e2e/run.py --shared-core neg --jobs 1` invocation with only that copy present (the store-wide scan of Task 3 reads every flow on the shared core, so a leftover label from one copy would trip the real test and the others): each copy exits 1 with `[FAIL]` starting `the barrage's mark label 'e2e-missing' is absent from the REAL flow's marks` (F1), `marks only grew: every mark present before the barrage is still present` (F2), `flow.detail of the REAL flow is byte-identical apart from meta.marks` (F3, F4); the real test still PASSes in the same run; F5 (spec AC8) fails with `no flow in the store carries the barrage's mark label`.
  - AC4: delete the copies, then `git status --short` and `git diff --stat f979040` (the branch base; the local `main` ref is stale) list only the test, the spec, and the plan.
- **Done when:** the report quotes the raw output of every command above, including the four `[FAIL]` lines, and the throwaway files are gone.

### Task 3: panel fix task (added after the first panel review)

- **Satisfies:** AC8; closes the first panel's Minors (see Review log)
- **Depends on:** Task 1, Task 2
- **Input:** the findings report `/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_66678338-65d2-4823-a414-e59ffd702b90/panel1-findings.md` (instead of a task number); spec Design 6 and AC8.
- **Files:** `tests/e2e/neg/test_nonexistent_flow_error.py` only.
- **Done when:** py_compile passes; the vocabulary grep prints 0; no new `time.sleep`; the Tester regenerates the injection copies (F1 to F4 unchanged, plus F5 for AC8) and the orchestrator re-runs AC1, AC3, AC7 in the Terminal; the panel runs again on the fix with the first reports in hand.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| 1-2 | Quality | Minor | (ii) is vacuous when `marks_before` is empty and the file does not say so; the green line over-claims; its only proof of life was in deleted copies | Fixed in 6594460 (comment at `marks_before`, `ok` note) and re-fixed in the round-2 follow-up (note became a suffix on the 'marks only grew' message, comment names the check by its message); wipe proof recorded in Shipped (F2) |
| 1-2 | Quality | Minor | Check 1's failure shows the marks delta, not the field that differed; `delta` on all three messages; `:` instead of ` -- ` | Fixed in 6594460: check 1 names the differing keys; marks delta only on (i)/(ii) as `marks_delta`; ` -- ` idiom |
| 1-2 | Quality | Minor | Header bullet run-on | Fixed in 6594460, then split into two sub-bullets in the round-2 follow-up |
| 1-2 | Quality | Minor | Same rationale in five places | Fixed in 6594460: trimmed to header, `marks_of` docstring, the `marks_before` comment |
| 1-2 | Quality | Minor | `BARRAGE_MARK` splits the flood constants; long comment | Fixed in 6594460: moved to the wire-vocabulary group, shortened (comment now says it is reserved) |
| 1-2 | Quality | Minor | Spec Rejected list starts at (b); PR #172 note goes stale | Fixed in 6594460 (spec: chosen (a) labelled; note reduced to a do-not-touch line) |
| 1-2 | Quality | Minor | Check (ii) has no committed proof of life | Accepted by Matt 2026-10-31 (autonomous-approve mode, via the orchestrator): a committed wipe test would make the cell a writer (spec option (d), rejected); F2 evidence is in Shipped and the file says the check is a tripwire |
| 1-2 | Security | Minor | Check (i) reads only the control flow though the message says "elsewhere" | Fixed in 6594460: store-wide scan of the `flow.table` rows already fetched (spec Design 6/AC8); F5 injection proves it |
| 1-2 | Security | Minor | (ii) is a tripwire that is vacuous in practice | Same fix as the Quality vacuity finding |
| 1-2 | Spec | Minor | AC4's literal `git diff --stat main` uses the stale local `main` | Fixed in 6594460 (spec AC4) and in the round-2 follow-up (plan Task 2) |
| 1-2 | Spec | Minor | Approved spec/plan amended after approval; Tester improvised the F4 edit first | Recorded here: F4 is a request header edit because a response `status` edit is refused on a completed flow (`mutate.rs:217-227`); the spec/plan were corrected in 299b5e9; both Status lines now list the amendments and who made them |
| 1-2 | Spec | Minor | Evidence logs live outside the repo | Fixed in 6594460: key lines pasted into Shipped |
| 3 | Security | Minor | "ANY flow in the store" is really every LISTED flow (`flow.table` omits flows captured during a capture pause, `store.rs`); also raised by the Tester | Fixed in the round-2 follow-up: header, scan message, spec Design 6 and Goals say "listed" and name the limit |
| 3 | Quality | Minor | Comment refers to "(ii)"/"F2", labels that exist only in the spec | Fixed in the round-2 follow-up: names the check by its message, cites spec AC3 |
| 3 | Quality | Minor | Vacuity note printed before the check it qualifies; the green line carried no caveat | Fixed in the round-2 follow-up: caveat is a suffix on the same message |
| 3 | Quality | Minor | Header sub-bullet held two rules; "no flow was added" is not asserted | Fixed in the round-2 follow-up: two sub-bullets; the clause says what is asserted |
| 3 | Quality | Minor | `e2e-missing` is reserved by convention only | Fixed in the round-2 follow-up: constant comment says it is reserved |
| 3 | Quality, Spec | Minor | Plan Task 2/Overview contradicted the amended spec; spec example `differs in:` wrong; mis-wrapped paragraphs | Fixed in the round-2 follow-up (spec and plan text) |
| 3 | Spec | Minor | Amendment record incomplete; no approver named | Fixed in the round-2 follow-up: Status lines list every amended section; amendments are the orchestrator's, self-approved in autonomous-approve mode |
| 3 | Spec | Minor | Commit 6594460 mixes spec/plan edits into the test commit | Recorded: the Coder edited only the test; the orchestrator wrote every spec and plan hunk (Design 3/5/6, AC8, Review log, Shipped) |

## Shipped

What shipped: `tests/e2e/neg/test_nonexistent_flow_error.py` now compares `flow.detail` byte-identically apart from `meta.marks`, checks marks on their own (the barrage's label absent from the real flow, earlier marks never wiped), and scans the whole `flow.table` read for the barrage's label (Design 6). No production code, catalogue, runner, or Rust changed, so the Rust gate was not required. PR #172 (the `entries = activity_since(op or rd, ...)` line) had already merged; the branch was fast-forwarded onto it (base f979040), so there was no merge.

Evidence, from real runs in Matt's Terminal on a core with the bundled catalogue ON (`AITM_NO_BUNDLED_SCRIPTS` unset; binaries built with `cargo build -p aitm -p aitm-testtarget` on f979040). Full logs: `side-session-notes/local_66678338-.../` (`step0-red.log`, `r2-*.log`).

AC2 red (original test on f979040, `python3 tests/e2e/run.py --shared-core neg`):

```
[FAIL] flow.detail of the REAL flow is byte-identical: no mark/comment/mutation landed elsewhere
e2e summary: 4 pass, 0 skip, 1 fail
  FAIL neg/test_nonexistent_flow_error.py (exit 1)
```

AC1 (`python3 tests/e2e/run.py --shared-core web audit neg`, final test, sha256 cbf33b13...): `e2e summary: 14 pass, 0 skip, 0 fail`, `exit=0` (no SKIP of audit or neg; neg/test_nonexistent_flow_error.py PASS).

AC7 (`python3 tests/e2e/run.py --shared-core neg`, three consecutive runs on the final test): each `e2e summary: 5 pass, 0 skip, 0 fail`, `exit=0`.

AC3 and AC8 (each throwaway copy run alone: `python3 tests/e2e/run.py --shared-core neg --jobs 1`, exit 1, the real test PASS in the same run). F4 is a request header edit because a response `status` edit is refused on a completed flow (`crates/aitm-plugins/src/mutate.rs:217-227`):

```
F1 [FAIL] the barrage's mark label 'e2e-missing' is absent from the REAL flow's marks -- no flow.mark landed on it (marks [] -> ['e2e-missing'])
F2 [FAIL] marks only grew: every mark present before the barrage is still present -- none was replaced or wiped (marks ['e2e-sentinel'] -> ['e2e-other'])
F3 [FAIL] flow.detail of the REAL flow is byte-identical apart from meta.marks -- no comment or mutation landed on it (differs in: meta.comment)
F4 [FAIL] flow.detail of the REAL flow is byte-identical apart from meta.marks -- no comment or mutation landed on it (differs in: edited, meta.edited, request)
F5 [FAIL] no flow in the store carries the barrage's mark label 'e2e-missing' -- no flow.mark landed on any listed flow (scanned 4 flows; carriers: ['475a10d4-ce7b-466f-bfcf-af9be5cf196d'])
```

In F5 the checks before the scan print `[ok]` while the real flow's marks grew `[] -> ['missing-nosniff', 'version-disclosure']`, so detector marks are tolerated and a leak to another listed flow is not. The scan covers listed flows only: `flow.table` omits flows captured while capture is paused (`crates/aitm-core/src/store.rs`).

Known limit: the 'marks only grew' check is vacuous when `marks_before` is empty (the common live case); the test says so in a suffix on that check's own message, and F2 is the proof that it binds when marks exist.

Follow-ups: none required. The first panel's `merge_plugin_edits` aside (a `flow.mutate` landing between the hook snapshot and the write-back would be overwritten, `crates/aitm-core/src/chain.rs`) is production behaviour outside this change; worth a separate look if mutation durability matters.
