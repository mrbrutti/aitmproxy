# S-079 evidence — the flow list follows the capture on every page

Dev bundle `Aitmproxy-dev-il` with an embedded release core built from main, Flows page, intercept
armed from the Flow menu, `curl -x <proxy>` as the client against `python3 -m http.server`.

Before (main 345bedd), one process, 2026-11-01 ~19:01:
- `before-apps-page-updates.png` — Apps page: Resume All, 4 s later every row reads 404 (control).
- `before-flows-new-row-missing-4s.png` — Flows page: a curl parked 4 s earlier (bar "1 paused …/d", sidebar Flows 4) and the list still shows three rows.
- `before-flows-resume-not-drawn-4s.png` — Flows page: 4 s after Resume All the bar is clear, the status bar says "0 / 4 rows", the list still shows three rows.

After (this PR), 2026-11-01 19:06:
- `after-flows-parked-190626.png` — 19:06:26: the first curl parks and its row appears.
- `after-flows-resume-2s-190630.png` — 19:06:30, two seconds after Flow ▸ Resume: row 1 reads 404 · 3.84 s · 460 B with the Edited pencil, and the second curl's row (`/b`, Paused) is already drawn; no page switch.
- `after-flows-12s-190641.png` — 19:06:41: unchanged, nothing lagging.
