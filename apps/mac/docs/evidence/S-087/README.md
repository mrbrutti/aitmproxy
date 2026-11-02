# S-087 / MS-AC10 — live proof, 2026-11-01 (same run as S-085)

- `01-issues-grouped.png` — Issues tab after the jobs: MEDIUM 2 / LOW 4, the harness `scan.issues` tally is
  `{medium: 2, low: 4}` with the same six issues (`scan-issues-harness.json`); they appeared with no click
  (the 2 s poll while a job runs).
- `02-issue-detail.png` — `scan.issue` detail: where, description, remediation, evidence payload and match
  (`<aitm-canary-0001>`), the probe flow row, status control.
- `03-probe-flow-in-inspector.png` — Open Flow on the probe flow: the Apps page with the flow selected,
  request `GET /search?q=%3Caitm-canary-0001%3E` and the response body carrying the marker.
- `04-false-positive.png` — Status set to False positive; the harness `scan.issue {id}` returns
  `false_positive` (`ac10-harness.log`).

## Second run (engine abaf5264, external core with `findings.dir`)

- `05-abaf5264-issues-grouped.png` — the same grouping on the abaf5264 core (MEDIUM 2 / LOW 4 = harness).
- `06-abaf5264-issue-detail-with-poc.png`, `07-abaf5264-issue-with-poc-ref.png` — with `findings.dir` set the
  engine reproduced the XSS and wrote a PoC: the issue carries `poc_ref` (the PoC file's absolute path) and
  `finding_id` (`reflected-xss-c388095c`); the detail shows the Open PoC button and "Finding <id>".
- `08-abaf5264-open-poc-fallback.png` — Open PoC: the resolver now matches an absolute `poc_ref` by path equality
  (fixed from this run: the first version matched only a bare name), but the core's `poc.list` returns `[]`
  (it does not list `<findings.dir>/scan/pocs/…`), so the Findings page has nothing to select and the status bar
  shows the spec's fallback "PoC <path> is not in this app's findings list". Engine/contract gap for T1b:
  `poc.list` should include the scanner's PoCs (or `scan.issue` should carry a finding the Findings page lists).

## Third run (core built from main 3aa8cc67, embedded)
`09-main-3aa8cc67-issues-6.png` — Issues tab after job `scan-e6b8d1df` on the testtarget: "Issues 6" in the tab,
groups Medium 2 (Reflected cross-site scripting on GET /search q and GET /greet name, certain) and Low 4 (Missing
security header sec-ch-ua firm, Reflected parameter value /search q tentative, Cookie without Secure or HttpOnly
/lang set firm, Open redirect /redirect next certain); the harness `scan.status` for the same job reports
`issues {low 4, medium 2}` (`../S-086/ac9-harness-main-3aa8cc67.log`).
