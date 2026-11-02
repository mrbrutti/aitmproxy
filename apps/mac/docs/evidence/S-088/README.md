# S-088 / MS-AC13 — live proof, 2026-11-01 (same run as S-085)

- `01-sitemap-tree.png` — Site map tab seeded with the newest job (`scan-ac5a0fcc`): one origin
  `http://127.0.0.1:8097`, 30 nodes with path templates (`/account/{id}`, `/profile/{id}`, …), points per node.
- `scan-sitemap-harness.log` — the harness `scan.sitemap {job}` read: the same 30 nodes, templates and point
  counts (e.g. `/` 120, `/api/profile` 75, `/account/{id}` 86), 1024 points on the first page.
- `02-node-insertion-points.png` — `GET /account/{id}` selected: 56 insertion points with kind badge, name,
  traits, example verbatim and ×frequency.

Engine note for T1b: `scan.sitemap` without `job` or `target` is refused (`invalid_profile: give either job or
target`); the app always sends the selected job, and its "All jobs" choice would hit that refusal.

## Second run (engine abaf5264)
`03-abaf5264-sitemap.png`: the same 30 nodes from the harness `scan.sitemap {job}` read (`ac9-harness-abaf5264.log` in S-086 lists the templates).
