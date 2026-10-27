# <Topic> implementation plan

**Status:** draft | approved (YYYY-MM-DD by Matt) | shipped (YYYY-MM-DD)
**Spec:** `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`
**Branch / worktree:** `feat/<topic>`

## Overview

Two or three sentences on the shape of the implementation and the order of
work. Which tasks are independent (can fan out) and which are sequential.

## Tasks

### Task N: <short name>

- **Satisfies:** AC1, AC3
- **Depends on:** Task M (or none)
- **Files:** `src/...` (create), `src/...` (modify), `tests/...` (create)
- **Change:** exact types, functions, and signatures to add or alter.
- **Test:** test name, what it calls, and the literal expected value.
- **Done when:** the test passes and the full gate passes.

(repeat per task)

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
