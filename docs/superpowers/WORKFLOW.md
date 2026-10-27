# aitmproxy development workflow

Every change to aitmproxy travels these seven stages in order. No stage is
skipped, however small the change. The main session orchestrates; the work is
done by the engines in `.claude/agents/` running as sub-agents or child sessions.

## The engines

| Engine | File | Stage | Reads | Writes |
|---|---|---|---|---|
| Researcher | `researcher.md` | 1 | Web, upstream sources, `docs/` | `docs/research/` only |
| Architect | `architect.md` | 2, 3 | `docs/`, source tree | `docs/superpowers/specs/`, `docs/superpowers/plans/` |
| Coder | `coder.md` | 4 | Plan task, spec, source | Source and tests for its one task |
| Tester | `tester.md` | 5 | Spec, plan, source, tests | Tests only; a report |
| Security reviewer | `security-reviewer.md` | 6 | The diff, spec, plan | A findings report |
| Quality reviewer | `quality-reviewer.md` | 6 | The diff, spec, plan | A findings report |
| Spec reviewer | `spec-reviewer.md` | 6 | The diff, spec, plan | A findings report |

An engine never does another engine's job. A Coder that finds a spec gap stops
and reports it; it does not redesign.

## The seven stages

### 1. Research
Researcher gathers what we need to know about a problem, library, or protocol.
Output: a note in `docs/research/` with sources cited and an index entry in
`docs/research/README.md`. Matt reads it; research has no approval gate.
Research is read-only on code.

### 2. Spec
Architect, driven by `superpowers:brainstorming`, writes
`docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` from the spec template.
**Gate: Matt approves the spec.** Nothing downstream starts before that.

### 3. Implementation plan
Architect, driven by `superpowers:writing-plans`, writes
`docs/superpowers/plans/YYYY-MM-DD-<topic>-plan.md` from the plan template.
Each task is small, names its files and signatures, and states the test that
proves it. **Gate: Matt approves the plan.**

### 4. Implementation
Driven by `superpowers:subagent-driven-development` and
`superpowers:using-git-worktrees`:

- One feature branch (`feat/<topic>`) and one worktree per plan.
- A fresh Coder sub-agent per task, run in that worktree. Independent tasks
  that touch disjoint files may fan out to child sessions, each on a branch
  cut from the plan branch in its own worktree, merged back into the plan
  branch when its panel review passes. Two writers never share a file.
- Every task is test-driven (`superpowers:test-driven-development`): write the
  failing test, run it and watch it fail, write the minimum code to pass, run
  it and watch it pass, refactor. No production code without a failing test
  first. The Coder's report includes both test runs.
- Commit after each task.

### 5. Testing
Tester runs after each task (that task's criteria) and once on the whole
branch (every criterion). It checks that every acceptance criterion maps to a
test, strengthens weak tests, and runs the full gate:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The report quotes actual command output. A summary without output is not a
report (`superpowers:verification-before-completion`).

### 6. Panel review
The three reviewers run **in parallel** on the diff, each with a fresh context
and the spec and plan as reference, using the review findings template.
Findings are rated:

- **Critical**: must be fixed before anything else.
- **Important**: must be fixed before the change moves on.
- **Minor**: fixed, or accepted by Matt in writing in the plan.

Fixes are dispatched to a fresh Coder as a **fix task** whose input is the
findings report; then Tester and the panel run again on the fix, with the
prior report in hand. The panel runs after each task, and once more on the
whole branch before integration. Reviewers return their report as their
final message; the orchestrator records every finding and its disposition in
the plan's **Review log**.

### 7. Integration
Driven by `superpowers:finishing-a-development-branch`. Only a branch whose
final panel review has **no open findings** merges to `main`: Critical and
Important fixed, Minor fixed or accepted by Matt in the Review log. The main
session fills the plan's **Shipped** section.

## Rules at every stage

- **Delegate by default.** The main session plans, dispatches, and verifies.
  It does not write code or docs itself when an engine can. The exceptions it
  owns: spec and plan `Status` lines, the plan's Review log and Shipped
  sections.
- **Fresh context per task.** Engines receive exactly the inputs in the
  dispatch contract below, never the orchestrator's history.
- **Evidence before claims.** Nothing is "done", "passing", or "fixed" until
  the command was run and its output shown.
- **Rust gates.** `cargo fmt`, `clippy` with warnings denied, and `cargo test`
  must all pass before any review. `unsafe` requires a `// SAFETY:` comment
  stating the invariant and a signed-off entry in the Security reviewer's
  report.
- **Stop on gaps.** An engine that finds the spec or plan wrong stops and
  reports instead of improvising.

## Dispatch contract

What the orchestrator hands each engine. Nothing less, nothing more.

| Engine | Inputs |
|---|---|
| Researcher | The question; related research paths |
| Architect | Research paths (stage 2); approved spec path (stage 3) |
| Coder | Spec path, plan path, task number, worktree path. For a fix task: the findings report instead of a task number |
| Tester | Spec path, plan path, worktree path, base and head SHA, task number(s) or "whole branch" |
| Each reviewer | Spec path, plan path, worktree path, base and head SHA, task number(s), the Coder's report, any prior review report for this range |

## Experiments

An experiment proves or disproves an approach before we commit to it.

- It runs in a **separate session with its own worktree**, on a branch named
  `experiment/<topic>`. The experiment session is not an engine: it builds
  the spike itself and writes the write-up itself.
- Its brief is a question, not a spec. It skips stages 2 to 7. Tests are
  optional. It is throwaway.
- Its code is **never merged**. The result is written up with the experiment
  template as `docs/research/experiments/YYYY-MM-DD-<topic>.md` and, if
  adopted, folded into a spec.
- The real implementation then goes through all seven stages from scratch.

## Document map

| What | Where |
|---|---|
| Research notes | `docs/research/NN-<topic>.md` |
| Experiment write-ups | `docs/research/experiments/YYYY-MM-DD-<topic>.md` |
| Specs | `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` |
| Plans | `docs/superpowers/plans/YYYY-MM-DD-<topic>-plan.md` |
| Templates | `TEMPLATE.md` in each of the above folders; review template in `docs/superpowers/REVIEW-TEMPLATE.md` |
| Engines | `.claude/agents/<engine>.md` |
