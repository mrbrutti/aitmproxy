# S-079 evidence — the flow list follows the capture on every page

Dev bundle `Aitmproxy-dev-il` with an embedded release core built from main, Flows page, intercept
armed from the Flow menu, `curl -x <proxy>` as the client against `python3 -m http.server`.

Before (main 345bedd), one process, 2026-11-01 ~19:01:
- `before-apps-page-updates.png` — Apps page: Resume All, 4 s later every row reads 404 (control).
- `before-flows-new-row-missing-4s.png` — Flows page: a curl parked 4 s earlier (bar "1 paused …/d", sidebar Flows 4) and the list still shows three rows.
- `before-flows-resume-not-drawn-4s.png` — Flows page: 4 s after Resume All the bar is clear, the status bar says "0 / 4 rows", the list still shows three rows.

After (this PR), 2026-10-31 19:20–19:21 PDT, one process, each frame distinct (a third request is parked at +10 s so the late frame differs from the earlier one):
- Flows page: `after-flows-1-parked.png` (19:20:33, `/flows-a` parked), `after-flows-2-resume-plus-2s.png` (19:20:39, two seconds after Flow ▸ Resume: row 1 reads 404 · 5.00 s · 460 B with the Edited pencil, row 2 `/flows-b` Paused already drawn), `after-flows-3-at-12s-third-park.png` (19:20:50, row 3 `/flows-c` Paused appears). No page switch.
- Apps page, same sequence: `after-apps-1-parked.png` (19:21:00), `after-apps-2-resume-plus-2s.png` (19:21:05, `/apps-a` 404 + pencil, `/apps-b` Paused), `after-apps-3-at-12s-third-park.png` (19:21:16, `/apps-c` appears).
- The live self-test additionally pins the mechanism: a warm `visibleRows` cache must still register the dependency on `rows` and on `details` (`withObservationTracking`), checked against a real request and a real `flow.detail`.
