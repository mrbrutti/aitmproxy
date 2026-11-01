# S-081 / MS-AC9 — live proof, 2026-11-01 (same run as S-080)

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
