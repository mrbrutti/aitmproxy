# S-082 / MS-AC10 — live proof, 2026-11-01 (same run as S-080)

- `01-issues-grouped.png` — Issues tab after the jobs: MEDIUM 2 / LOW 4, the harness `scan.issues` tally is
  `{medium: 2, low: 4}` with the same six issues (`scan-issues-harness.json`); they appeared with no click
  (the 2 s poll while a job runs).
- `02-issue-detail.png` — `scan.issue` detail: where, description, remediation, evidence payload and match
  (`<aitm-canary-0001>`), the probe flow row, status control.
- `03-probe-flow-in-inspector.png` — Open Flow on the probe flow: the Apps page with the flow selected,
  request `GET /search?q=%3Caitm-canary-0001%3E` and the response body carrying the marker.
- `04-false-positive.png` — Status set to False positive; the harness `scan.issue {id}` returns
  `false_positive` (`ac10-harness.log`).

Not exercised on this core: Open PoC. None of the six issues carries a `poc_ref` because the embedded core has
no `findings.dir`, so the engine writes no PoC / finding; the button is therefore absent (one Open PoC when
`poc_ref` is set). The resolver is unit-tested (`pocRefResolvesToAListedPath`).
