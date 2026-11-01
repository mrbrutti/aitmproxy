# S-084 / MS-AC14 live proof — legacy `scan.discover` path (2026-11-01)

Real `.app` (debug dev bundle `/tmp/Aitmproxy-dev-t9.app`, built from this branch by `tools/snap-dev.sh`, launched
live with `APP_STORE` in /tmp and no fixtures), its embedded core = `target/release/aitm` built from this branch
(main v0.5.8 + T1a; it lists `scan.discover` and not `scan.start`), `obscura` borrowed from the installed 0.5.8
bundle, and `aitm-testtarget-serve --mode vulnerable --port 8097` as the target. The target host was persisted in
the store's `scope.json` before launch so the core's launch config seeded the scope (the browser engine's
private-network flag is frozen at core launch from the seed scope; a host added over the bus after launch leaves
the crawl at `navigation_failed`, which the first run showed).

- `01-legacy-form-live.png` — the Scan page shows the legacy one-shot form (the core lacks `scan.start`), target
  seeded from scope.
- `02-legacy-crawl-result-live.png` — one Scan click: 12 endpoints · 152 injection points · 12 pages, selected point
  opens its flow; the core's `flow.list` held 14 flows at the capture instant.
- `core-config-redacted.yaml` — the embedded core's per-launch config with the tokens redacted.

Driver: `/tmp/claude/t9-live.sh` (up / relaunch / shot / bus / down), window shots by pid via `tools/winshot.swift`,
clicks via the guarded click helper. No snapshot scene, no fixture data.

## After the fake-data removal merge (main 621cbcc0 / v0.5.10, 2026-11-01)

The keystone PR (#249, live-only app) touched `Panels/ScanPanel.swift` (the fixture load hook went) and Kit
`Panels/Scan.swift` (the fixture result went); the merge resolved both toward live-only with no Scan view change
beyond those deletions. Re-proof of the touched path on the merged tree: the dev bundle built with main's
`NO_LAUNCH=1 tools/snap-dev.sh`, its embedded core = `aitm` built from main at that point (lists `scan.discover`,
no `scan.start`), the target in the store's `scope.json`, testtarget vulnerable on 8097.

- `03-after-keystone-merge-legacy-form.png` — the Scan page still renders the legacy form.
- `04-after-keystone-merge-crawl-result.png` — one Scan: 29 endpoints · 384 injection points · 29 pages;
  `flow.list` held 41 flows. Gate on the merged tree: swift test 651 + 31 green (the surface tests now carry their
  own scope and tool stand-ins), grid-lint PASS, the three tripwires PASS.
