# Review: <reviewer: security | quality | spec>

**Range:** `<base-sha>..<head-sha>`
**Plan task(s):** `docs/superpowers/plans/...` task N
**Verdict:** PASS | FAIL (FAIL if any Critical or Important; Minors are
listed for the orchestrator to fix or get accepted before merge)

## Findings

### [Critical | Important | Minor] <one-line title>

- **Where:** `path/file.rs:line`
- **What:** the defect in one sentence.
- **Failure:** concrete input or state, then the wrong outcome.
- **Basis:** the spec/plan sentence or rule this rests on (spec reviewer: quote it).
- **Fix:** what to change.

(repeat per finding, most severe first)

## Checked and clean

What you looked at and found acceptable, so the orchestrator knows coverage.

## unsafe sign-off (security reviewer only)

| `unsafe` block (file:line) | Stated invariant | Verified? |
|---|---|---|

## Requirement-to-evidence (spec reviewer only)

| Requirement / AC | Where satisfied | Test | Status |
|---|---|---|---|
