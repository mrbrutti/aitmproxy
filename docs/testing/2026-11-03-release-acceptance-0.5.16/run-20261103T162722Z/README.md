# Release acceptance — 0.5.16 on the installed build (2026-11-03T16:28Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.16/run-20261103T162722Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `TUI-3,TUI-7,WEB-4,WEB-7,CLI-9`  ·  **manual:** 0  ·  **window:** 1

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| CLI-4 | SKIP | no core on 8080; the live-core half needs the app's embedded core up |  |  |
| CLI-5 | SKIP | no core on 8080; the live-core half needs the app's embedded core up |  |  |
| CLI-9 | SKIP | no core on 8080; the live-core half needs the app's embedded core up |  |  |
| CLI-10 | SKIP | no core on 8080; the live-core half needs the app's embedded core up |  |  |
| N4-CLI | SKIP | no core on 8080; the live-core half needs the app's embedded core up |  |  |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 0 loader lines before the JSON | ca.status over the bus agrees | regression after #271 (loader noise) |
| CLI-1 | PASS | aitm 0.5.16 |  |  |
| CLI-2 | PASS | exit 0, synopsis on stdout (tui, web, operator-token listed) |  |  |
| CLI-3 | PASS | ready card on stderr, stdout empty: aitmproxy 0.5.16 config /Users/matt/Library/Application Support/aitmproxy/config.yaml CA loaded · /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt p |  |  |
| CLI-6 | PASS | refused, exit 1: error: no running core found |  |  |
| CLI-8 | SKIP | could not hold 8082 with a plain listener (holder: ); not starting aitm web against a live port |  |  |

## Journey MAC

not run

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-CLI | N/A | the one-shot refusal is CLI-6's row (no separate step on this surface) |  |  |
| N5-TUI | SKIP | the app's embedded core is not running (8080 not held by it) |  |  |
| N4-TUI | SKIP | the app's embedded core is not running (8080 not held by it) |  |  |
| N4-WEB | SKIP | the app's embedded core is not running (8080 not held by it) |  |  |

## Journey TUI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| TUI-1 | **FAIL** | missing ['sys-proxy', 'CA trusted']; no-flows line exact False — observed `(no 'No flows yet' line)`; status bar `bus … · operator` False; startup toast False; screen head: ›•‹ aitmproxy 0.5.16 |  |  |
| TUI-2 | **FAIL** | prompt True, hint False, toast True, listed True, in-scope count None, audit scope.add ok 0 | [{"at": 1793723247449, "marker": "start", "pid": 78408, "schema": 1, "stream": "control", "version": "0.5.16"}] |  |
| N2-TUI | **FAIL** | pill `· sys-proxy off` but the flows pane does not show the empty-state sentence |  |  |
| TUI-3 | SKIP | bypass list absent in config.yaml system_proxy.bypass (none); add it through the surface's Settings first |  |  |
| TUI-4 | BLOCKED | TUI-3 did not set the route |  |  |
| TUI-5b | BLOCKED | TUI-3 | no route / no hand: park and resume cannot be judged |  |
| TUI-5a | **FAIL** | armed bar False; toast `Intercept disarmed` True | bus truth: audit only |  |
| TUI-6 | **FAIL** | prompt True, hint False, cancelled False, ca-audit rows 0 |  |  |
| TUI-7 | SKIP | nothing to restore (TUI-3 did not set it) |  |  |
| TUI-8 | PASS | exit 0, no child left, scutil unchanged | audit: last entries from this pid |  |
| TUI-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| TUI-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-TUI | N/A | aitm tui owns its core on 0.5.10; the app's restart is seen only from aitm-tui --bus |  |  |
| N3-TUI | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Journey WEB

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| WEB-1 | PASS | card lines 16 on stderr (0 loader lines; stdout 0 lines); Web UI line: True, Proxy line: True, Browser line (SSRF-filtered): True, Bus ready: True, stdout empty: True, Scope line (Scope empty): True; Operator line present; config scope empty True; /healthz {"ok":true} |  |  |
| WEB-4 | SKIP | bypass list absent in config.yaml system_proxy.bypass (none); add it through Settings first |  |  |
| WEB-2 | PASS | banner true; pill "aitmproxyv0.5.16WorkingPinnedSaved0AllApps0Domains0aitmproxyScope0ScanFindings0Browser1 tabScripts49 activeL4offAgent0/min⌘⇧Faitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trustedAgent0Operator session — sensitive commands are enabled.AllHTTPHTTPSWebSocketTCPUDPL4h1h2JS |  |  |
| WEB-3 | PASS | host example.com; empty-state before true; row listed true; status "1 host in scope"; toast "" | audit scope.add entries since start: 1 |  |
| N2-WEB | PASS | pill "sys-proxy off"; empty grid words true; rows 1 (zero rows is correct here) |  |  |
| WEB-4 | SKIP | needs Matt's yes (ACCEPT_YES=WEB-4) | scutil: not 8080; ExceptionsList carries the tooling False; identical to before: True |  |
| WEB-5 | BLOCKED | WEB-4 did not set the route | judged from the page (grid rows) by the mjs; the web cell has no bus client |  |
| WEB-6a | **FAIL** | status bar "aitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trusted · intercept armed"; Disarm false; Rules… true |  |  |
| WEB-6b | BLOCKED | WEB-4 |  |  |
| WEB-6c | BLOCKED | WEB-6b |  |  |
| WEB-6d | PASS | bar gone true |  |  |
| WEB-7 | SKIP | nothing to restore (WEB-4 did not run) | scutil: not 8080; ExceptionsList carries the tooling False; identical to before: True |  |
| N5-WEB | PASS | banner verbatim |  |  |
| WEB-8 | PASS | exit 0; ports free True; scutil identical True; run/cores pointers left [] | audit: no proxy.system.set left unmatched |  |
| WEB-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| WEB-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-WEB | N/A | aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7) |  |  |
| N3-WEB | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Restore proof

```
121,125c121,125
< {"at":<ms>,"marker":"start","pid":76166,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"marker":"start","pid":76513,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"marker":"start","pid":76562,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"marker":"start","pid":76567,"schema":1,"stream":"control","version":"0.5.16"}
< {"at":<ms>,"origin":"operator","client_label":"aitm-mac","connection_id":"conn_ddca1fed9fb6a232-1","command":"scan.sitemap","args":"{}","result":{"error":"scan: not_found: no scan job has run yet"}}
---
> {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_01ecd2833fbf8621-1","command":"scope.add","args":"{\"host\":\"example.com\"}","result":"ok"}
> {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_01ecd2833fbf8621-1","command":"flow.intercept","args":"{\"enabled\":true}","result":"ok"}
> {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_01ecd2833fbf8621-1","command":"flow.intercept","args":"{\"enabled\":false}","result":"ok"}
> {"at":<ms>,"origin":"operator","client_label":"web-bridge","connection_id":"conn_01ecd2833fbf8621-1","command":"scope.remove","args":"{\"host\":\"example.com\"}","result":"ok"}
> {"at":<ms>,"marker":"start","pid":78766,"schema":1,"stream":"control","version":"0.5.16"}
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 5 | 0 | 7 | 0 | 0 | 0 |
| NEGATIVES | 0 | 0 | 3 | 0 | 0 | 1 |
| TUI | 1 | 5 | 3 | 2 | 0 | 3 |
| WEB | 7 | 1 | 4 | 3 | 0 | 3 |

**Verdict:** `fail` — a performed step FAILed — blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

| Host | State | Cell |
|---|---|---|
| example.com | removed | tui |
| example.com | removed | web |

`kept` and `failed` rows are for Matt to remove by hand; `removed` rows were taken out through the same surface that added them.
