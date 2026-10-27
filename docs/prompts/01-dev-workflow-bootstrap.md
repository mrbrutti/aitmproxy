# Prompt: Build the aitmproxy development workflow

Paste everything below the line into a main session.

---

## Context

You are working on **aitmproxy**, a Rust intercepting-proxy platform for authorized
security testing, at `/Users/matt/Security/aitmproxy`.

- Research notes live in `docs/research/` (still being written by other sessions).
- Design docs (specs) live in `docs/superpowers/specs/`.
- Nothing is built until its spec is approved by me.

Research is still in progress. This task does **not** depend on it and must not
wait for it. It is process work only: do not write any product code.

## Goal

Create the development workflow this project will follow from now on. It has
two parts:

1. A set of **dedicated agent engines**, each with one job.
2. A written **workflow** that every piece of code must go through, from idea
   to merged change.

## Part 1: Agent engines

Define one agent per role as a file under `.claude/agents/` (project level).
Each file states the role's job, what it may read and write, what it must
produce, and what it must never do.

| Engine | Job | Produces |
|---|---|---|
| **Researcher** | Investigates prior art, libraries, protocols, docs. Read-only on source code. | Notes in `docs/research/` with sources cited. |
| **Architect** | Turns approved research into a spec, then turns an approved spec into an implementation plan broken into small, independently testable tasks. | Specs in `docs/superpowers/specs/`, plans in `docs/superpowers/plans/`. |
| **Coder** | Implements exactly one plan task at a time, test-first, in its own worktree. | Code plus the tests that drove it. |
| **Tester** | Writes and strengthens tests, checks that every acceptance criterion in the spec has a test, runs the suite, reports results with real output. | Test code and a pass/fail report with evidence. |
| **Review panel** | Three reviewers that run on every change: **Security** (vulnerabilities, unsafe Rust, injection, TLS and parsing mistakes), **Quality** (bad code, duplication, poor structure, missing error handling), **Spec compliance** (does the change do what the spec and plan say, no more, no less). | A findings report per reviewer. Every finding is fixed or explicitly accepted by me. |

## Part 2: The workflow

Write it as `docs/superpowers/WORKFLOW.md`. It is the rulebook; keep it short
enough that every session reads it.

The stages, in order, with no skipping:

1. **Research.** Researcher gathers what we need to know. Output reviewed by me.
2. **Spec.** Architect writes the design doc. **I approve it** before anything else happens.
3. **Implementation plan.** Architect breaks the spec into small tasks, each with its own tests and acceptance criteria. **I approve the plan.**
4. **Implementation.** One task at a time, using **test-driven development**: write the failing test, watch it fail, write the minimum code to pass, refactor. No production code without a failing test first.
5. **Testing.** Tester verifies coverage of every acceptance criterion and runs the full suite. Results are reported with actual command output, never a summary claim.
6. **Panel review.** All three reviewers run on the change. Findings are resolved before the change moves on.
7. **Integration.** Only after steps 4 to 6 pass does the change merge.

Rules that apply at every stage:

- **Delegate by default.** The main session orchestrates. Actual work goes to
  sub-agents or child sessions whenever possible. Independent tasks run in
  parallel.
- **Isolation.** Every implementation task runs in its own git worktree, in its
  own session where practical. Two writers never touch the same files.
- **Experiments and spikes.** We may run experiments to prove an approach
  before committing to it. An experiment always runs in a **separate session
  with its own worktree**. Its code is throwaway: it is never merged. Its result
  is written up in `docs/research/` or folded into the spec, and the real
  implementation then goes through the full workflow above.
- **Evidence before claims.** No step is "done" until its verification command
  has been run and the output shown.
- **Every change is reviewed.** No exceptions for small changes.

## Part 3: Templates

Create templates the engines fill in so output is consistent:

- Spec template (`docs/superpowers/specs/TEMPLATE.md`)
- Implementation plan template (`docs/superpowers/plans/TEMPLATE.md`)
- Review findings template (one format shared by all three reviewers)
- Experiment write-up template (`docs/research/EXPERIMENT-TEMPLATE.md`)

## Part 4: Wire it in

Create or update the project `CLAUDE.md` so every new session reads
`docs/superpowers/WORKFLOW.md` and knows which engine to dispatch for which stage.

## How to do this task

- Follow the workflow while building it: present me the proposed
  `WORKFLOW.md` and engine list for approval **before** writing the agent files
  and templates.
- Reuse the installed `superpowers` and `pstack` skills where they already cover
  a stage (brainstorming, writing-plans, test-driven-development,
  subagent-driven-development, requesting-code-review, using-git-worktrees,
  verification-before-completion). Reference them from the workflow instead of
  rewriting them.
- Use sub-agents to draft the engine files in parallel once the design is approved.

## Constraints

- No product code in this task.
- The sandbox blocks writes to `.claude/skills/` and `.claude/hooks/` in this
  project and blocks `git init` and GitHub network. If something needs those,
  write the file content and the exact command for me to run myself.
- Keep every document concise. A rule nobody reads is not a rule.

## Done when

- `.claude/agents/` has one file per engine listed above (seven files: researcher,
  architect, coder, tester, security-reviewer, quality-reviewer, spec-reviewer).
- `docs/superpowers/WORKFLOW.md` exists and I have approved it.
- All four templates exist.
- `CLAUDE.md` points new sessions at the workflow.
- You have shown me a short walkthrough of how one feature would travel through
  all seven stages using these files.
