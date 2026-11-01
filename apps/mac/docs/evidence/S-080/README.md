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

## L4-lane half (second run, engine abaf5264, external core)

Because the app's embedded core has no L4, this half ran the same `.app` against an external core built from T1b
abaf5264 (`external-core-config-redacted.yaml`: `l4.enabled: true`, `findings.dir`, the target in scope; the app
connected as operator via `APP_LIVE=1 AITM_CONFIG=…`), with the test target's nine L4 speakers up
(`--l4 --control-port 8098`). Over the bus (operator-confirmed `_confirm` handshake, see `ac11-l4-harness.log`):
an inject L4 scope entry `cidr 127.0.0.1/32, interface "*", direction outbound, capability inject` (the
`interface: "*"` acceptance abaf5264 adds), and a saved copy of `l4-stream-safe` named `l4proof` whose
`target.l4` is the target's TLV speaker.

- `11-external-core-profiles-with-saved-l4proof.png` — the saved profile listed beside the builtins.
- `08-l4-lane-profile-enabled.png` — `l4proof` selected: L4 stream lane, target `127.0.0.1:56657/tcp`, Start Scan
  enabled now that an Inject entry exists.
- `09-l4-lane-confirm-sheet.png` — Start Scan → the engine's L4 prompt verbatim ("This scan sends malformed
  traffic to 127.0.0.1:56657 and may disrupt the target. Continue?"); Cancel → no job (`scan.list` empty).
- `10-l4-lane-engine-refusal-code.png` — Start Scan in the sheet → the confirmed call reached the engine, which
  refused: `no requested lane is available on this build: l4_stream` with the code `lane_unavailable` beside it
  in the footer (this engine build carries no L4 stream lane; the audit shows one `scan.start` from `aitm-mac`
  with that error). The handshake and the D9 error rendering are proven; a running L4 job needs a build with the
  lane.
- `tools-list-names-abaf5264.txt` — that core's verbs (`l4.scope.*`, every `scan.*`, `flow.subscribe`).
