# Release acceptance index

One row per release the operator-journey acceptance ran on (spec
`docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md` §D10). The
verdict word is the spec's D1 word: `pass` clears the tap bump; `incomplete` and `fail` do not.
Counts are the sums of each report's Summary table over every journey (SKIP and BLOCKED are never
green). Kept by hand from each run's `README.md`.

| Version | Date (UTC) | Run | PASS | FAIL | SKIP | BLOCKED | Verdict | Report |
|---|---|---|---|---|---|---|---|---|
| 0.5.10 | 2026-11-01 | read-only half (no yes, no window, no hand) | 5 | 4 | 42 | 3 | `fail` — CLI-1/2 (#271), CLI-4/5 (`claude/cli-oneshot-live-core`), MAC-9b (missing feature); the rest `incomplete` | [2026-11-01-release-acceptance-0.5.10](2026-11-01-release-acceptance-0.5.10/README.md) |
| 0.5.11 | 2026-11-02 | run 1, read-only half | 7 | 3 | 41 | 4 | `fail` — CLI-4/5 (`claude/cli-oneshot-live-core`), MAC-9b (missing feature); the rest `incomplete` | [2026-11-02-release-acceptance-0.5.11](2026-11-02-release-acceptance-0.5.11/README.md) |
| 0.5.11 | 2026-11-02 | run 2, read-only half on the fixed runner (`6765dee0`): CLI 2/3/7/0, MAC 1/1/16/5, NEG 3/0/2/0, TUI 0/0/14/0, WEB 0/0/17/0 | 6 | 4 | 56 | 5 | `fail` — CLI-4/5/10 (`claude/cli-oneshot-live-core`), MAC-9b (missing feature: proxied-flow attribution); the rest `incomplete` pending the window half | [2026-11-02-release-acceptance-0.5.11 § Run 2](2026-11-02-release-acceptance-0.5.11/README.md#run-2--read-only-half-re-run-on-the-fixed-runner-2026-11-02-0300z-run-2-readonly-6765dee0) |
| 0.5.11 | 2026-11-02 | run 3, read-only half, runner 84e22c4f | 6 | 4 | 48 | 5 | `fail` — CLI-4/5/10 (`claude/cli-oneshot-live-core`), MAC-9b (missing feature); 7 N/A; the rest `incomplete` | [2026-11-02-release-acceptance-0.5.11](2026-11-02-release-acceptance-0.5.11/README.md) |
