# Release acceptance — 0.5.16 on the installed build (2026-11-03T16:23Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.16/run-20261103T162234Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `MAC-2,MAC-3,MAC-4,MAC-5,MAC-6,MAC-7,MAC-8,MAC-9a,MAC-9b,MAC-10,MAC-11,MAC-12,MAC-13,MAC-14,MAC-15,MAC-16,CLI-9`  ·  **manual:** 0  ·  **window:** 1

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| CLI-4 | PASS | reports the running core (aitm pid 52405) |  |  |
| CLI-5 | PASS | the running core lists it | scope.list contains acceptance-cli5.invalid |  |
| N4-CLI | PASS | error: cannot start: the proxy port 127.0.0.1:8080 is already in use; 0 loader lines on stdout first |  | regression after #271 (loader noise) |
| CLI-9 | SKIP | bypass list absent in config.yaml system_proxy.bypass (none); add the operator's tooling there first — status read (exit 0: "managed_by_us": false "state": "off" ); set/unset not run | proxy.system.status over the bus: {"bypass_default":["localhost","127.0.0.1","::1","*.local","169.254/16"],"detail":"HTTP and HTTPS off","effective":{"bypass":["*.local","169.254/16"],"http":{"enabled":false,"host":"","port":0},"https |  |
| CLI-10 | PASS | the one-shot lists the running core's 14 flow(s) | flow.table ids: 14 |  |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 0 loader lines before the JSON | ca.status over the bus agrees | regression after #271 (loader noise) |
| CLI-1 | SKIP | port 8080 held by aitm pid 76513; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-2 | SKIP | port 8080 held by aitm pid 76513; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-3 | SKIP | port 8080 held by aitm pid 76513; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-6 | SKIP | port 8080 held by aitm pid 76513; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-8 | SKIP | port 8080 held by aitm pid 76513; the no-core half needs 8080, 8081 and 8082 free |  |  |

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| N3-MAC | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |
| N4-MAC | SKIP | needs a plain 8080 listener before launch — yes (it blocks his app's core) |  |  |
| N5-MAC | SKIP | hand: Settings ▸ Bus field |  |  |
| MAC-1 | PASS | app running (bundle 0.5.16); embedded core pid 52405 listening 127.0.0.1:8080 version 0.5.16; lane words: 'running' True, 'connected' True, 'operator ·' True | proxy.status.listening True, version 0.5.16; start marker in audit: True |  |
| MAC-2 | PASS | first-run sheet not shown (already dismissed or every row done); recorded as such |  |  |
| MAC-3 | PASS | Status page words present: ['system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.', 'All Apps is on']; missing: [] | scope.list ['wikipedia.org']; capture True/attached; system proxy off |  |
| MAC-4 | PASS | rows exist: banner case applies | flow.table rows 14 |  |
| N2-MAC | SKIP | not the N2 state: scope 1 host(s), system proxy off, All Apps True |  |  |
| MAC-5 | **FAIL** | the sheet's field did not take the focus probe (typed '1' not read back); refusing to type into an unknown target |  |  |
| MAC-6 | SKIP | bypass list absent in the app's Settings ▸ Proxy Bypass hosts (defaults key systemProxy.bypass never written: the field shows the app's recommended default, but the D2 reading is the stored key — save the field once in Settings); add the operator's tooling there first |  |  |
| MAC-7 | PASS | All Apps already on at start; Status page shows 'All Apps is on': True | capture.status enabled True feeder listening provider attached handed off {'tcp': 0, 'udp': 0} |  |
| MAC-8 | BLOCKED | needs MAC-5 and a route (MAC-6 or MAC-7) |  |  |
| MAC-9a | BLOCKED | no extension-captured rows (All Apps on but Scope empty → the extension claims nothing) | capture.status flows_handed_off {'tcp': 0, 'udp': 0} |  |
| MAC-9b | PASS | 14 proxied rows, 14 carry a source_app → Apps sidebar shows them | flow.table source_app null ×0 |  |
| MAC-10 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-11 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-12 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-13 | PASS | new core pid 76513; Scope rows kept True; stale failed banner present False | scope.list before ['wikipedia.org'] after ['wikipedia.org'] |  |
| N1-MAC | SKIP | needs --manual (a hand watches the restart) — the restart itself ran as MAC-13 |  |  |
| MAC-14 | SKIP | All Apps was already on at start (operator's state) — not turned off by the run |  |  |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) |  |  |
| MAC-16 | SKIP | the app was already running at start; not quit by the run (Matt's app) |  |  |

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-CLI | N/A | the one-shot refusal is CLI-6's row (no separate step on this surface) |  |  |
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:51289 refused the token line (unauthorized) |  |
| N4-TUI | PASS | panel before any screen, exit 1 | 8080 held by aitm pid 76513 |  |
| N4-WEB | PASS | panel, exit 1, no card first | 8080 held by aitm pid 76513 |  |

## Journey TUI

not run

## Journey WEB

not run

## Restore proof

```
23c23
< <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 52588 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-52405-70a720fe3828ba1817f553ca759f53d0/ready-70a720fe3828ba1817f553ca759f53d0.ready
---
> <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 51287 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-76513-202df2c39fc1c6c7848e1420a21dcee4/ready-202df2c39fc1c6c7848e1420a21dcee4.ready
29c29
< aitm    52405 matt   13u  IPv4 0x6c32a265bdfdbbc9      0t0  TCP 127.0.0.1:<port> (LISTEN)
---
> aitm    76513 matt   13u  IPv4 0x4c160d8f57af7744      0t0  TCP 127.0.0.1:<port> (LISTEN)
121c121
< <ls> 52405.json
---
> <ls> 76513.json
125,129c125,129
< {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_ad34ba4a477a74aa-4","command":"scope.add","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
< {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_ad34ba4a477a74aa-6","command":"scope.remove","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
< {"at":<ms>,"marker":"start","pid":58991,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"marker":"start","pid":59279,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"marker":"start","pid":59285,"schema":1,"stream":"control","version":"0.5.16"}
---
> {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_ad34ba4a477a74aa-18","command":"scope.remove","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
> {"at":<ms>,"marker":"start","pid":76166,"schema":1,"stream":"control","version":"0.5.16"}
> {"at":<ms>,"marker":"start","pid":76513,"schema":1,"stream":"control","version":"0.5.16"}
> {"at":<ms>,"marker":"start","pid":76562,"schema":1,"stream":"control","version":"0.5.16"}
> {"at":<ms>,"marker":"start","pid":76567,"schema":1,"stream":"control","version":"0.5.16"}
152a153
> <ls> 33C687F3-A22E-481B-947A-1BC0B908B4FA
201d201
< <ls> ECEB3A32-56A0-43E6-B6A1-DB32F0D1FE08
212a213
> /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
261d261
< /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 5 | 0 | 7 | 0 | 0 | 0 |
| MAC | 7 | 1 | 10 | 5 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |

**Verdict:** `fail` — a performed step FAILed — blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

| Host | State | Cell |
|---|---|---|
| acceptance-cli5.invalid | removed | cli |

`kept` and `failed` rows are for Matt to remove by hand; `removed` rows were taken out through the same surface that added them.
