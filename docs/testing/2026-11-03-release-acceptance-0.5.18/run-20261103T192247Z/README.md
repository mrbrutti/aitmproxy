# Release acceptance — 0.5.18 on the installed build (2026-11-03T19:23Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.18/run-20261103T192247Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `MAC-5,MAC-7,MAC-13`  ·  **manual:** 0  ·  **window:** 1

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

not run

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| N3-MAC | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |
| N4-MAC | SKIP | needs a plain 8080 listener before launch — yes (it blocks his app's core) |  |  |
| N5-MAC | SKIP | hand: Settings ▸ Bus field |  |  |
| MAC-1 | PASS | app running (bundle 0.5.18); embedded core pid 71655 listening 127.0.0.1:8080 version 0.5.18; lane words: 'running' True, 'connected' True, 'operator ·' True | proxy.status.listening True, version 0.5.18; start marker in audit: True |  |
| MAC-2 | PASS | first-run sheet not shown (already dismissed or every row done); recorded as such |  |  |
| MAC-3 | PASS | Status page words present: ['system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.', 'All Apps is on']; missing: [] | scope.list ['wikipedia.org']; capture True/attached; system proxy off |  |
| MAC-4 | PASS | rows exist: banner case applies | flow.table rows 2 |  |
| N2-MAC | SKIP | not the N2 state: scope 1 host(s), system proxy off, All Apps True |  |  |
| MAC-5 | PASS | typed ['example.com:80', 'httpbin.org:443']; rows shown ['example.com:80', 'httpbin.org:443']; pending words []; status-bar error False | scope.list now ['wikipedia.org', 'example.com:80', 'httpbin.org:443']; audit scope.add ok since start: 2 |  |
| MAC-6 | SKIP | needs Matt's yes (ACCEPT_YES=MAC-6) and the window |  |  |
| MAC-7 | PASS | All Apps already on at start; Status page shows the All Apps lane as attached: True | capture.status enabled True feeder listening provider attached handed off {'tcp': 0, 'udp': 0} |  |
| MAC-8 | SKIP | needs a hand: Safari visits http://example.com/ and https://httpbin.org/get |  |  |
| MAC-9a | BLOCKED | no extension-captured rows (All Apps on but Scope empty → the extension claims nothing) | capture.status flows_handed_off {'tcp': 0, 'udp': 0} |  |
| MAC-9b | PASS | 2 proxied rows, 2 carry a source_app → Apps sidebar shows them | flow.table source_app null ×0 |  |
| MAC-10 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-11 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-12 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-13 | PASS | new core pid 90646; Scope rows kept True; back on 8080 True (holder: aitm pid 90646); stale failed banner present False | scope.list before ['wikipedia.org', 'example.com:80', 'httpbin.org:443'] after ['wikipedia.org', 'example.com:80', 'httpbin.org:443'] |  |
| N1-MAC | SKIP | needs --manual (a hand watches the restart) — the restart itself ran as MAC-13 |  |  |
| MAC-14 | SKIP | All Apps was already on at start (operator's state) — not turned off by the run |  |  |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) |  |  |
| MAC-16 | SKIP | the app was already running at start; not quit by the run (Matt's app) |  |  |

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-CLI | N/A | the one-shot refusal is CLI-6's row (no separate step on this surface) |  |  |
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:51060 refused the token line (unauthorized) |  |
| N4-TUI | PASS | panel before any screen, exit 1 | 8080 held by aitm pid 90646 |  |
| N4-WEB | PASS | panel, exit 1, no card first | 8080 before aitm pid 90646; after aitm pid 90646 |  |

## Journey TUI

not run

## Journey WEB

not run

## Restore proof

```
24d23
< <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 64114 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-71655-9fe432e28886a0da68e00e230aae477b/ready-9fe432e28886a0da68e00e230aae477b.ready
25a25
> <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 51058 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-90646-ee38d68fcda0d9ae04ae5851a5659082/ready-ee38d68fcda0d9ae04ae5851a5659082.ready
30c30
< aitm    71655 matt   13u  IPv4 0xa7954c3800e04879      0t0  TCP 127.0.0.1:<port> (LISTEN)
---
> aitm    90646 matt   13u  IPv4 0xf391ea8ea58d6d47      0t0  TCP 127.0.0.1:<port> (LISTEN)
124c124
< <ls> 71655.json
---
> <ls> 90646.json
128,132c128,132
< {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_54181af9d7a27081-1","command":"flow.intercept","args":"{\"enabled\":true}","result":"ok"}
< {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_54181af9d7a27081-1","command":"flow.intercept","args":"{\"enabled\":false}","result":"ok"}
< {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_54181af9d7a27081-1","command":"scope.remove","args":"{\"host\":\"example.com\"}","result":"ok"}
< {"at":<ms>,"marker":"start","pid":71010,"schema":1,"stream":"control","version":"0.5.18"}
< {"at":<ms>,"marker":"start","pid":71655,"schema":1,"stream":"control","version":"0.5.18"}
---
> {"at":<ms>,"origin":"operator","client_label":"aitm-mac","connection_id":"conn_3feaba486b1948cf-1","command":"scope.add","args":"{\"host\":\"example.com:80\"}","result":"ok"}
> {"at":<ms>,"origin":"operator","client_label":"aitm-mac","connection_id":"conn_3feaba486b1948cf-1","command":"scope.add","args":"{\"host\":\"httpbin.org:443\"}","result":"ok"}
> {"at":<ms>,"marker":"start","pid":90646,"schema":1,"stream":"control","version":"0.5.18"}
> {"at":<ms>,"marker":"start","pid":90945,"schema":1,"stream":"control","version":"0.5.18"}
> {"at":<ms>,"marker":"start","pid":90956,"schema":1,"stream":"control","version":"0.5.18"}
172d171
< <ls> 73E387CB-0E44-44B1-B41B-BCC382328AB5
198a198
> <ls> A52D5045-AA9D-48BD-BE51-5883915AD90C
239d238
< /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
264a264
> /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| MAC | 8 | 0 | 11 | 4 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |

**Verdict:** `incomplete` — no FAIL, but SKIP/BLOCKED steps remain (a yes, a hand or a free port was missing) — not green; run them or Matt accepts the gap in writing.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

| Host | State | Cell |
|---|---|---|
| example.com:80 | failed (no 'Remove example.com:80 from Scope' button on the Scope page: [stderr] 1362:1412: execution error: no button titled or described "Remove examp; remove by hand) | mac |
| httpbin.org:443 | failed (no 'Remove httpbin.org:443 from Scope' button on the Scope page: [stderr] 1362:1412: execution error: no button titled or described "Remove httpb; remove by hand) | mac |

`kept` and `failed` rows are for Matt to remove by hand; `removed` rows were taken out through the same surface that added them.
