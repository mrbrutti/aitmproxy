# S-086 / MS-AC9 — live proof, 2026-11-01 (same run as S-085)

Jobs tab frames paired with harness `scan.status` reads over the bus at the same instants (`ac9-harness-*.log`).

- `01-standard-running-164.png` — job 1 (`standard`): Running · Auditing, probes 164 / 2000, points 477 / 485,
  4 issues on the bar, Cancel Scan live; the harness read a second later: 197 probes, done (the standard job
  finished in 2.96 s on this target).
- `02…` `03…` `04…` — job 2 (`standard` edited to Speed Thorough, 12.2 s): frames at probes 213 → 426 → done 661,
  with harness reads 268 → 482 → 661 bracketing them (`ac9-harness-job2.log`): the counter rises across three
  distinct values and the phase word goes Auditing → Done.
- `05-before-cancel.png` / `06-cancelled.png` — job 3: Running at 235 probes, Cancel Scan clicked at 07:39:56,
  harness `scan.status` at 07:39:59 reads `cancelled`, `stopped_reason: cancelled`, 292 probes; the row and the
  detail read "Cancelled · standard" / "Cancelled · Done · 0:04" with the same 292 / 2000
  (`ac9-harness-job3-cancel.log`).

Engine note for T1b: `elapsed_ms` is reported as 0 while a job runs (only set at the end), so the row's elapsed
reads 0:00 until done.

## Second run (engine abaf5264, external core)
`07-abaf5264-running-227.png` (Running · Auditing, 227 probes with the harness at 227 → 285 done), `08-abaf5264-before-cancel.png`
(207 probes running), `09-abaf5264-cancelled.png` (Cancel clicked 08:01:10 → `cancelled` at 08:01:13, 248 probes in row and
harness); `ac9-harness-abaf5264.log`.

## Third run (core built from main 3aa8cc67 after T1b landed, embedded; PR head merged with that main)
Dev bundle of the merged tree, embedded core from main (proxy 127.0.0.1:59027), testtarget `vulnerable` on 8097
seeded in `scope.json`. `standard` edited to Speed Thorough → Start Scan → job `scan-e6b8d1df`.
`10-main-3aa8cc67-done-282.png` — the row reads "Done · standard · 127.0.0.1:8097 · probes 282 / 2000 · points 482 / 485
audited", the detail "Done · Done · 0:07" with probes 282 / 2,000, rate waits 140, by lane http 282, crawl pages 29,
points found 485 / audited 482, checks 1484 / 1484, issues 6 (medium 2, low 4; certain 3 firm 2 tentative 1),
lanes HTTP, WebSocket. The harness `scan.status` read beside the frame (`ac9-harness-main-3aa8cc67.log`) gives the
same numbers: `done`, `elapsed_ms 7782`, `sent 282`, `audited 482`, `found 485`, `low 4 medium 2`.
Main's engine is faster than T1b's: the Thorough job on this target finished in 7.8 s, before the first window
read (winshot took ~20 s per frame on this run), so no running or Cancelled frame was caught here; the three
earlier runs above hold those. `elapsed_ms` now reads 0:07 for the finished job (T1b's 0:00 note above no longer applies).
