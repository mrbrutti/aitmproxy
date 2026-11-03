# Release acceptance — 0.5.18 on the installed build (2026-11-03T17:34Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.18/run-20261103T173350Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `(none)`  ·  **manual:** 0  ·  **window:** 0

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| CLI-4 | PASS | reports the running core (aitm pid 53844) |  |  |
| CLI-5 | PASS | the running core lists it | scope.list contains acceptance-cli5.invalid |  |
| N4-CLI | PASS | error: cannot start: the proxy port 127.0.0.1:8080 is already in use; 0 loader lines on stdout first |  | regression after #271 (loader noise) |
| CLI-9 | SKIP | status read (exit 0: "managed_by_us": false "state": "off" ); set/unset need Matt's yes (ACCEPT_YES=CLI-9) | proxy.system.status over the bus: {"bypass_default":["localhost","127.0.0.1","::1","*.local","169.254/16"],"detail":"HTTP and HTTPS off","effective":{"bypass":["*.local","169.254/16"],"http":{"enabled":false,"host":"","port":0},"https |  |
| CLI-10 | BLOCKED | MAC-8: the running core has no flows to compare against |  |  |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 0 loader lines before the JSON | ca.status over the bus agrees | regression after #271 (loader noise) |
| CLI-1 | SKIP | port 8080 held by aitm pid 53844; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-2 | SKIP | port 8080 held by aitm pid 53844; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-3 | SKIP | port 8080 held by aitm pid 53844; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-6 | SKIP | port 8080 held by aitm pid 53844; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-8 | SKIP | port 8080 held by aitm pid 53844; the no-core half needs 8080, 8081 and 8082 free |  |  |

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| N3-MAC | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |
| N4-MAC | SKIP | needs a plain 8080 listener before launch — yes (it blocks his app's core) |  |  |
| N5-MAC | SKIP | hand: Settings ▸ Bus field |  |  |
| MAC-1 | PASS | app running (bundle 0.5.18); embedded core pid 53844 listening 127.0.0.1:8080 version 0.5.18 | proxy.status.listening True, version 0.5.18; start marker in audit: True |  |
| MAC-2 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| MAC-3 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| MAC-4 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| N2-MAC | SKIP | needs the window (judged from the MAC-3 read) |  |  |
| MAC-5 | SKIP | needs the window (ACCEPT_WINDOW=1): types into the Edit Scope sheet; hosts ('example.com:80', 'httpbin.org:443') |  |  |
| MAC-6 | SKIP | needs Matt's yes (ACCEPT_YES=MAC-6) and the window |  |  |
| MAC-7 | SKIP | All Apps already on at start; needs the window to read 'All Apps is on' on the Status page | capture.status enabled True feeder listening provider attached handed off {'tcp': 0, 'udp': 0} |  |
| MAC-8 | BLOCKED | needs MAC-5 and a route (MAC-6 or MAC-7) |  |  |
| MAC-9a | BLOCKED | no extension-captured rows (All Apps on but Scope empty → the extension claims nothing) | capture.status flows_handed_off {'tcp': 0, 'udp': 0} |  |
| MAC-9b | BLOCKED | no proxied rows to judge |  |  |
| MAC-10 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-11 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-12 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-13 | SKIP | needs the window (ACCEPT_WINDOW=1): Proxy ▸ Restart Core; Scope must survive |  |  |
| N1-MAC | SKIP | needs the window and --manual (Restart Core, then an add within ~1 s after a focus re-probe) |  |  |
| MAC-14 | SKIP | All Apps was already on at start (operator's state) — not turned off by the run |  |  |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) |  |  |
| MAC-16 | SKIP | the app was already running at start; not quit by the run (Matt's app) |  |  |

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-CLI | N/A | the one-shot refusal is CLI-6's row (no separate step on this surface) |  |  |
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:51257 refused the token line (unauthorized) |  |
| N4-TUI | PASS | panel before any screen, exit 1 | 8080 held by aitm pid 53844 |  |
| N4-WEB | PASS | panel, exit 1, no card first | 8080 held by aitm pid 53844 |  |

## Journey TUI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| TUI-1 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-2 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-3 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-4 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5a | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5b | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-6 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-7 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-8 | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| N2-TUI | SKIP | port 8080 held by aitm pid 53844; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| TUI-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-TUI | N/A | aitm tui owns its core on 0.5.10; the app's restart is seen only from aitm-tui --bus |  |  |
| N3-TUI | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Journey WEB

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| WEB-1 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-2 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-3 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-4 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-5 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6a | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6b | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6c | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6d | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-7 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| N2-WEB | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| N5-WEB | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-8 | SKIP | port 8080 held by aitm pid 53844; aitm web needs the default ports (quit the app first) |  |  |
| WEB-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| WEB-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-WEB | N/A | aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7) |  |  |
| N3-WEB | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Restore proof

```
127,131c127,131
< {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_8abd40a1b597ebad-6","command":"scope.remove","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
< {"at":<ms>,"marker":"start","pid":23699,"schema":1,"stream":"control","version":"0.5.17"}
< {"at":<ms>,"marker":"start","pid":23901,"schema":1,"stream":"control","version":"0.5.17"}
< {"at":<ms>,"marker":"start","pid":23906,"schema":1,"stream":"control","version":"0.5.17"}
< {"at":<ms>,"marker":"start","pid":53844,"schema":1,"stream":"control","version":"0.5.18"}
---
> {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_67b1a90f94181752-4","command":"scope.add","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
> {"at":<ms>,"origin":"operator","client_label":"aitm-cli","connection_id":"conn_67b1a90f94181752-6","command":"scope.remove","args":"{\"host\":\"acceptance-cli5.invalid\"}","result":"ok"}
> {"at":<ms>,"marker":"start","pid":54682,"schema":1,"stream":"control","version":"0.5.18"}
> {"at":<ms>,"marker":"start","pid":54894,"schema":1,"stream":"control","version":"0.5.18"}
> {"at":<ms>,"marker":"start","pid":54899,"schema":1,"stream":"control","version":"0.5.18"}
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 4 | 0 | 7 | 1 | 0 | 0 |
| MAC | 1 | 0 | 16 | 6 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |
| TUI | 0 | 0 | 11 | 0 | 0 | 3 |
| WEB | 0 | 0 | 14 | 0 | 0 | 3 |

**Verdict:** `incomplete` — no FAIL, but SKIP/BLOCKED steps remain (a yes, a hand or a free port was missing) — not green; run them or Matt accepts the gap in writing.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

| Host | State | Cell |
|---|---|---|
| acceptance-cli5.invalid | removed | cli |

`kept` and `failed` rows are for Matt to remove by hand; `removed` rows were taken out through the same surface that added them.
