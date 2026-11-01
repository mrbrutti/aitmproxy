# T8 web Scan surface: live proof, 2026-11-01

Real run, not a fixture: `node apps/web/scripts/scan-live.mjs` drove the real web UI (this branch at
`eb379134`, `apps/web/dist` embedded) served by a real `aitm web` core built from T1b's engine head
`ca852f71` (PR #232), against `aitm-testtarget-serve --mode vulnerable`, in headless Chrome over CDP with
real input events only, with a second operator bus connection as the witness. Every rendered value was
cross-checked against concurrent `scan.status` / `scan.issues` / `scan.sitemap` reads.

Result: **26 PASS · 0 FAIL · 1 GAP** (exit 0). The GAP is step 8b: the L4 confirm dialog showed the
core's prompt verbatim and `_confirm` was sent, and the core answered `lane_unavailable` because this core
has no L4 lane built; the UI rendered that refusal. Two NOTEs by design: the PoC ref falls back to the
toast (`poc.list` is non-recursive on this core; spec Open question 2), and the browser crawl had no
obscura so the client crawl stood in.

Files: one screenshot per step (`NN-*.png`), the witness bus transcript (`bus-transcript.jsonl`; the
single-use confirm tokens and URL fragments are scrubbed), and the step log with the `--json` summary
(`scan-live.log`). Nothing here came from the fixture pack.

## Re-run after merging main `e12b3e20` (6b812662)

Main's #247 rewrote `apps/web/src/panels/l4/inject.ts`, which the launch handshake imports, so the proof
was re-run on the merged head against the same `ca852f71` engine: **26 PASS · 0 FAIL · 1 GAP** (the same
8b GAP). Step log: `scan-live-after-main-merge.log`. Web gate on the merged head: typecheck 0, vitest
870/870, build 0.
