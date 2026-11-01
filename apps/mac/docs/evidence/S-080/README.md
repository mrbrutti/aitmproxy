# S-080 / MS-AC9 (launch half) + MS-AC11 — live proof, 2026-11-01

Real `.app` (dev bundle `/tmp/Aitmproxy-dev-t9.app` built from this branch by `tools/snap-dev.sh`, launched live
with `APP_STORE` in /tmp, no fixtures), embedded core = `aitm` built from T1b's engine SHA 6c1f6d99 (PR #232;
`tools-list-names.txt` is that core's `tools/list`: `scan.start`, `scan.status`, `scan.cancel`, `scan.issues`,
`scan.sitemap`, `scan.profile.*`, `flow.subscribe` …), `obscura` from the installed bundle, target
`aitm-testtarget-serve --mode vulnerable --port 8097` (T10 seeds), the target persisted in the store's
`scope.json` before launch. Clicks are guarded real input events; window shots by pid.

- `01-profiles-live.png` — Profiles tab from `scan.profile.list` (seven builtins) and the check tree from
  `scan.checks`; `standard` selected; Start Scan disabled with "Choose at least one in-scope origin."
- `02-origin-added.png` — the origin added from the in-scope host menu; Start Scan enabled.
- `03-l4-profile-start-disabled.png` — `l4-stream-safe` selected: Start Scan disabled with the L4 scope hint
  verbatim (MS-AC11, "without an L4 scope the launch is disabled with the reason").
- `04-intrusive-ready.png` — `standard` edited to Intensity Intrusive ("Edited builtin — …").
- `05-confirm-sheet.png` — Start Scan → the engine's `needs_confirmation` prompt rendered verbatim in the sheet
  ("This scan sends malformed traffic to http://127.0.0.1:8097 and may disrupt the target. Continue?"); the
  footer's Start Scan is disabled behind it.
- `06-after-cancel.png` — Cancel: no job started (`scan.list` unchanged, three jobs) and the core's audit ring
  gained no `scan.start` row (`ac11-harness.log`; the handshake step itself is not audited by design).
- `07-confirmed-job.png` — Start Scan again → Start Scan in the sheet → `scan.start` re-sent with `_confirm`:
  a fourth job (`scan-75753bf2`, Running · Passive) and a fourth `scan.start` audit row from `aitm-mac`,
  origin operator, result ok.
- `core-config-redacted.yaml` — the embedded core's per-launch config, tokens redacted.

Note: the engine proof used an Intrusive launch for the handshake. The L4 half of the sheet needs an L4-enabled
core with an Inject scope entry, which the app's embedded config does not carry; the gate half (disabled with the
hint) is proven above.
