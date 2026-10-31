# neg/nonexistent-flow marks implementation plan

**Status:** approved (2026-10-31 by Matt via the delegating orchestrator, autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-10-31-neg-nonexistent-flow-marks-design.md`
**Branch / worktree:** `claude/sleepy-goldwasser-9ec645` (base `main` f979040, after PR #172 and #156 merged; failure first seen on 840e520) in `/Users/matt/Security/aitmproxy/.claude/worktrees/sleepy-goldwasser-9ec645`

## Overview

Two sequential tasks; none is independent (Task 2 reads Task 1's file). Task 1 (Coder)
edits the single test file; its helper behaviour is proven in the sandbox with a
no-port Python check. Task 2 (Tester) runs the real e2e and the four fault
injections. All port-binding runs go through the Terminal panel (`run_in_terminal`,
Matt's real shell; the Bash sandbox cannot bind ports), from the worktree root so
`run.py` uses this worktree's `target/debug`. Run each command on its own, log to a
file, and judge by exit status, not a grep pipeline. If the Tester cannot reach the
Terminal, the orchestrator runs the listed commands and hands back the raw output.
No Rust changes, so the Rust gate is not required (spec AC5).

Stage 6: Task 2 commits nothing (throwaway files are deleted), so the Task 1 diff
is the whole-branch diff; the three reviewers run once, in parallel, on that head,
with Task 2's report as an input (Architect's call; stage not skipped).

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
  - In `main()`: right after the existing `detail_before` check, `marks_before = marks_of(detail_before)`. Replace the single check at the `detail_after == detail_before` line with three `check` calls in this order, using the spec's fixed prefixes (each message ends with `(marks <before> -> <after>)` or the equivalent lists):
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
- **Files:** throwaway `tests/e2e/neg/test_zz_inject_leak_mark.py`, `..._wipe_mark.py`, `..._leak_comment.py`, `..._leak_mutation.py` (create, run, delete; never committed)
- **Change:** each copy is the final test plus one inserted block immediately before `detail_after = rd.call("flow.detail", ...)`, acting on `real_id` over a Write-capable connection: F1 `flow.mark` with `[BARRAGE_MARK]`; F2 a sentinel `flow.mark` inserted before `detail_before`, then after the barrage `flow.mark` with a list not containing the sentinel or `BARRAGE_MARK`; F3 `flow.comment` with text `"injected"`; F4 `flow.mutate` with a response edit (e.g. `{"status": 418}`; Tester's call, it must change `flow.detail`).
- **Test (literal expectations, run in the Terminal):**
  - AC1: `python3 tests/e2e/run.py --shared-core web audit neg` -> exit 0; `neg/test_nonexistent_flow_error` PASS; no SKIP for `audit`/`neg`.
  - AC7: `python3 tests/e2e/run.py --shared-core neg` three times, exit 0 each.
  - AC3: `python3 tests/e2e/run.py --shared-core neg` with the four copies present: each copy exits 1 with `[FAIL]` starting `the barrage's mark label 'e2e-missing' is absent from the REAL flow's marks` (F1), `marks only grew: every mark present before the barrage is still present` (F2), `flow.detail of the REAL flow is byte-identical apart from meta.marks` (F3, F4); the real test still PASSes in the same run. The four runs are independent of each other and may run together.
  - AC4: delete the copies, then `git status --short` and `git diff --stat main` list only the test, the spec, and the plan.
- **Done when:** the report quotes the raw output of every command above, including the four `[FAIL]` lines, and the throwaway files are gone.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7. Record here, verbatim: the Step 0 red output (AC2), the AC1 and three AC7 run summaries, and the four AC3 `[FAIL]` lines. PR #172 (the `entries = activity_since(op or rd, ...)` line) merged before this work started; the branch was fast-forwarded onto it, so there is no merge to do.
