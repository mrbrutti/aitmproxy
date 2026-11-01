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
