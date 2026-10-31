# neg/nonexistent-flow test: tolerate detector marks, still catch leaks

**Status:** approved (2026-10-31 by Matt via the delegating orchestrator, autonomous-approve mode); amended 2026-10-31 after panel review (Design 6, AC8, F4 edit type)
**Research inputs:** none. The root cause was established in the orchestrating session (below); source cited inline.

## Intent

`python3 tests/e2e/run.py --shared-core web audit neg` is red on `main` (840e520)
in `tests/e2e/neg/test_nonexistent_flow_error.py`, at the check "flow.detail of the
REAL flow is byte-identical". Cause: PR #169's bundled Rhai passive-detector
catalogue (`scripts/bundled/http/*.rhai`, default-loaded by
`crates/aitm/src/bundled.rs`, opt-out `AITM_NO_BUNDLED_SCRIPTS`) runs as
`on_response` hooks. `merge_plugin_edits` (`crates/aitm-core/src/chain.rs`) UNIONS
the marks they add into the live flow after the response is stored, so detectors
add marks (e.g. `missing-nosniff`, `version-disclosure`) shortly after the control
flow first shows a status in `flow.table`. The test takes `detail_before` before
they land; the only differing field is `meta.marks` (`[]` -> `[missing-nosniff,
version-disclosure]`). The missing-id barrage changes nothing; the test's
whole-detail comparison is now too coarse. Production behaviour must not change.

## Goals

- The test passes on a core with the catalogue ON (the production default), every time.
- It still fails if a missing-id command leaks a mark, comment, mutation, or
  intercept change onto the real flow, or wipes its marks.
- It also fails if the barrage's mark label lands on ANY flow in the store (a
  missing id that falls back to some other flow), not just the control flow.

## Non-goals

- No change to the catalogue, `chain.rs`, `bundled.rs`, `run.py`, or any file outside the one test.
- No "detectors finished" signal, no polling, no new sleeps.
- No change to the other checks in the test (origin ground truth, audit ring, flood, parity).

## Anti-goals

- Weakening the test until it is green: dropping the detail comparison, excluding
  more than `meta.marks`, or ignoring marks altogether.
- Coupling the test to the catalogue's mark vocabulary or timing.
- Hiding the catalogue from the suite so a real catalogue/suite interaction goes unseen.

## Constraints

- Only `tests/e2e/neg/test_nonexistent_flow_error.py` changes (code plus its header docstring). Python stdlib and the existing `aitm_e2e` helpers only.
- Do not touch the line `entries = activity_since(op or rd, t0_ms)` or anything from the `ground truth: the audit ring` section down (PR #172 owns it).
- The test keeps its runner contract (a core the runner booted; SKIP when unset).

## Design

Facts relied on: detector and `merge_plugin_edits` changes to marks are only ever
additions; `flow.mark` REPLACES the whole mark list (`crates/aitm-plugins/src/meta.rs`);
`flow.detail` exposes `meta.marks`, `meta.comment`, `meta.edited`, top-level `edited`
and `intercept` (`crates/aitm-plugins/src/detail.rs`).

1. **Compare detail minus `meta.marks`.** `flow.detail` before and after must be
   deep-equal with ONLY `meta.marks` removed from both copies (inputs not mutated).
   Everything else (comment, edited, intercept, request, response, `is_replay`,
   timings) stays strictly compared. Both copies must actually carry a `meta.marks`
   list; if not, fail loudly so a renamed field cannot turn the filter into a no-op.
2. **Check marks on their own, with no detector vocabulary and no timing.**
   (i) The barrage's own label must not be in `marks_after`. Today it is the literal
   `"e2e-missing"` inside the `flow.mark` entry of `MISSING_ID_CALLS`; hoist it into
   one named module constant used by both that entry and the assertion, so they
   cannot drift apart. (ii) `marks_before` must be a subset of `marks_after`.
   Both are race-free because detector marks are monotonic additions: a leaked
   `flow.mark` would surface the label (i) or drop earlier marks (ii).
3. **Failure messages name what differed.** Checks (i) and (ii) print the marks
   diff (`before -> after`); check 1 prints the names of the differing keys
   (`differs in: comment, meta.edited`), because a marks diff there would point at
   the wrong field. Order of checks: detail-minus-marks, then (i), then (ii). Message prefixes are fixed here so evidence is greppable (the builder may
   append detail after them):
   - `flow.detail of the REAL flow is byte-identical apart from meta.marks`
   - `the barrage's mark label 'e2e-missing' is absent from the REAL flow's marks`
   - `marks only grew: every mark present before the barrage is still present`
4. **Docstring.** The header sentence "byte-identical before/after (no mark, no
   comment, no mutation ...)" is rewritten to state the marks rule: byte-identical
   apart from `meta.marks`; marks may only grow and must not carry the barrage's label.
5. **Known limit (Architect's call, accepted).** If `marks_before` is empty (the
   race went the other way), (ii) is trivially true; (i) and the rest-of-detail
   comparison still bind. The wipe case is therefore only provable deterministically
   under fault injection (AC3 seeds a sentinel mark first). The test says so in
   its own text: a comment at `marks_before`, and an `ok` note on a run where (ii)
   is vacuous, so a green line is not read as a wipe proof.
6. **Store-wide label scan (added after panel review).** Checks 1 and (i) read only
   the control flow, so a missing id that fell back to some OTHER flow would pass.
   After the existing `tagged` check, assert that no row of the same `flow.table`
   read carries `BARRAGE_MARK` in its `marks` (the literal is used by no other
   test, so a concurrent suite cannot trip it). `flow.table` rows list every stored
   flow's `marks` (`crates/aitm-plugins/src/capture.rs`); the control flow's row must
   carry a `marks` list or the test fails loudly. Prefix:
   `no flow in the store carries the barrage's mark label`.

**Chosen: (a)**, compare detail minus marks and check marks separately (Design 1 to 6). **Rejected.** (b) `AITM_NO_BUNDLED_SCRIPTS` in `run.py::_boot_shared_core`: it moves
every shared-core suite off the production default, hides catalogue/suite
interactions, and this test (contract: "a core the runner booted") would still fail
against any core with the catalogue on. (c) Poll marks until stable before taking
`detail_before`: there is no authoritative "detectors done" signal, so a late mark
still flakes, and it adds fixed sleeps. (c) could optionally complement this later;
it is not needed. (d) Seed a sentinel mark in the test itself to make (ii) never
vacuous (Architect's call): it turns a read-only cell into a writer and changes the
control flow. Rejected for this fix; AC3 covers the wipe case instead.

## Acceptance criteria

1. AC1: with `AITM_NO_BUNDLED_SCRIPTS` unset, `cargo build -p aitm -p aitm-testtarget` then `python3 tests/e2e/run.py --shared-core web audit neg` exits 0 and none of `audit`/`neg` is SKIP.
2. AC2: red-first. On the same kind of core, the ORIGINAL test (base f979040, failing since 840e520) exits 1 at the `byte-identical` check; the new test exits 0.
3. AC3: fault injection (temporary, uncommitted throwaway copies of the final test that act on the REAL flow id after the barrage, before `detail_after`). Each copy runs in its OWN `run.py --shared-core neg --jobs 1` invocation with only that copy present: the store-wide scan (Design 6) reads every flow in the shared core, so one copy's leftover label would trip the real test and the other copies. Each exits 1 at the named check, with a `[FAIL]` line starting with the named prefix:
   - F1 leaked barrage mark (`flow.mark` with the barrage label): prefix (i).
   - F2 wiped mark (seed a sentinel mark before `detail_before`; after the barrage `flow.mark` with a different list): prefix (ii).
   - F3 leaked comment (`flow.comment`): prefix of check 1.
   - F4 leaked mutation (`flow.mutate` with a request header edit; a response `status` edit is refused on a completed flow, `crates/aitm-plugins/src/mutate.rs`): prefix of check 1.
4. AC4: `git diff --stat <branch base, f979040>` (not the stale local `main`) lists only the test, this spec, and the plan; nothing under `crates/`, `scripts/`, or `tests/e2e/run.py`; no throwaway file remains.
5. AC5: `python3 -m py_compile tests/e2e/neg/test_nonexistent_flow_error.py` passes. No Rust changed, so the Rust gate (`cargo fmt/clippy/test`) is not required; the e2e build in AC1 is the only cargo step.
6. AC6: the test file contains none of `missing-nosniff`, `version-disclosure` (`grep -c` is 0) and adds no `time.sleep` or polling loop beyond the existing `SETTLE_S` sleep.
7. AC7: three consecutive `python3 tests/e2e/run.py --shared-core neg` runs are green (the fix does not trade one race for another).
8. AC8: fault injection F5 (a throwaway copy that, after the barrage, marks a DIFFERENT flow, one the copy itself sends through the proxy, with `BARRAGE_MARK`): exits 1 with a `[FAIL]` starting `no flow in the store carries the barrage's mark label`, while checks 1, (i), (ii) and the `tagged` check pass in that run.

## Left to the builder

Wording after the fixed message prefixes; whether the marks lists are rendered with `repr` or `json.dumps`. The constant and helper names are the plan's (`BARRAGE_MARK`, `marks_of`, `without_marks`); the Tester's throwaway injection copies depend on them, so rename only with a note in the report.

## Open questions

None.
