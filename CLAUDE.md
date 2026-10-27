# aitmproxy

Rust intercepting-proxy platform for authorized security testing. Research is
in `docs/research/` (start with `05-synthesis.md`); durable project facts are in
`docs/research/MEMORY.md`.

## How we work

Read `docs/superpowers/WORKFLOW.md` before doing anything. Every change goes
through its seven stages: research, spec, plan, implementation, testing,
panel review, integration. Matt approves specs and plans. Nothing is built
without an approved spec and plan.

The main session orchestrates and dispatches; the engines in `.claude/agents/`
do the work as sub-agents or child sessions:

| Stage | Dispatch |
|---|---|
| 1 Research | `researcher` |
| 2 Spec, 3 Plan | `architect` |
| 4 Implementation | `coder`, one fresh agent per plan task, in the plan's worktree |
| 5 Testing | `tester` |
| 6 Panel review | `security-reviewer`, `quality-reviewer`, `spec-reviewer` in parallel |
| 7 Integration | main session, via `superpowers:finishing-a-development-branch` |

Give each engine exactly the inputs in the workflow's **dispatch contract**
(spec, plan, worktree, SHAs, task number, prior reports), never session history.

Templates: `docs/superpowers/specs/TEMPLATE.md`, `docs/superpowers/plans/TEMPLATE.md`,
`docs/superpowers/REVIEW-TEMPLATE.md`, `docs/research/experiments/TEMPLATE.md`.

Experiments run in a separate session and worktree on `experiment/<topic>`,
are never merged, and are written up in `docs/research/experiments/`.

## Rust gate

Must pass before any review:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

## Environment

The Claude Bash sandbox cannot create `.git` or reach GitHub. Run every `git`
and `gh` command through the Terminal panel (`run_in_terminal`), which runs in
Matt's real shell outside the sandbox. The remote is HTTPS, authenticated via
`gh auth setup-git` as `mrbrutti`. Details in `docs/research/MEMORY.md`.
