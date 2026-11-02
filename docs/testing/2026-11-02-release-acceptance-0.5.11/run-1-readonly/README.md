# Release acceptance — 0.5.10-dry on the installed build (2026-11-02T02:26Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.10-dry` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run:** `(none)`  ·  **manual:** 0

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-4 | FAIL | a core runs on 8080 (aitm pid 79160) but the one-shot printed "listening": false, "version": "0.5.10" (its own in-process state) | running core: proxy.status.listening true | claude/cli-oneshot-live-core |
| CLI-5 | FAIL | exit 0, printed 'acceptance-cli5.invalid' but the running core's scope.list does not contain it (false success) | scope.list ==scope.list["example.com:443","www.apple.com:443","httpbin.org:443"]==proxy.status | claude/cli-oneshot-live-core |
| N4-CLI | PASS | Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.; 98 loader lines on stdout first |  | log noise: PR #271 |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 98 loader lines before the JSON | ca.status over the bus agrees | log noise: PR #271 |
| CLI-1 | SKIP | port 8080 held by aitm pid 79160; the no-core half needs the ports free |  |  |
| CLI-2 | SKIP | port 8080 held by aitm pid 79160; the no-core half needs the ports free |  |  |
| CLI-3 | SKIP | port 8080 held by aitm pid 79160; the no-core half needs the ports free |  |  |
| CLI-6 | SKIP | port 8080 held by aitm pid 79160; the no-core half needs the ports free |  |  |
| CLI-8 | SKIP | port 8080 held by aitm pid 79160; the no-core half needs the ports free |  |  |

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-1 | PASS | app running (bundle 0.5.11); embedded core pid 79160 listening 127.0.0.1:8080 version 0.5.11 | proxy.status.listening True, version 0.5.11; start marker in audit: True |  |
| MAC-2 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['example.com:443', 'www.apple.com:443', 'httpbin.org:443']; capture enabled True provider attached; system proxy off |  |
| MAC-3 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['example.com:443', 'www.apple.com:443', 'httpbin.org:443']; capture enabled True provider attached; system proxy off |  |
| MAC-4 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['example.com:443', 'www.apple.com:443', 'httpbin.org:443']; capture enabled True provider attached; system proxy off |  |
| MAC-5 | SKIP | needs the window and a hand (types into the Edit Scope sheet); hosts example.com:80, httpbin.org:443 |  |  |
| MAC-6 | SKIP | needs Matt's yes (ACCEPT_YES=MAC-6) and the window |  |  |
| MAC-7 | PASS | All Apps already on at start (capability capturing, provider attached); Status word expected 'All Apps is on' | capture.status enabled True feeder listening handed off {'tcp': 5, 'udp': 0} |  |
| MAC-8 | BLOCKED | needs MAC-5 and a route (MAC-6 or MAC-7) |  |  |
| MAC-9a | PASS | 9 extension rows, source_app set on 9; group name per spec: WebKit Networking vs Safari (two Kit tables) | source_apps ['com.apple.Safari', 'com.apple.curl'] |  |
| MAC-9b | FAIL | 5 proxied rows, 0 carry a source_app → Apps sidebar shows NOTHING for them | flow.table source_app null ×5 | missing feature: attribution for proxied flows (session core-name-the-client-app) |
| MAC-10 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-11 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-12 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-13 | SKIP | needs the window and ACCEPT_YES=MAC-13 (restarts his core; Scope must survive) |  |  |
| MAC-14 | SKIP | All Apps was already on at start (operator's state) — not turned off by the run |  |  |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) |  |  |
| MAC-16 | SKIP | the app was already running at start; not quit by the run (Matt's app) |  |  |

## Journey TUI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| TUI-1 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-2 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-3 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-4 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-6 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-7 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-8 | SKIP | port 8080 held by aitm pid 79160; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-9 | SKIP | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| TUI-10 | SKIP | no Apps view on this surface on 0.5.10 |  |  |

## Journey WEB

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| WEB-1 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-2 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-3 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-4 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-5 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6a | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6b | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6c | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6d | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-7 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-8 | SKIP | port 8080 held by aitm pid 79160; aitm web needs the default ports (quit the app first) |  |  |
| WEB-9 | SKIP | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| WEB-10 | SKIP | no Apps view on this surface on 0.5.10 |  |  |

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:53156 refused the token line (unauthorized) |  |

## Restore proof

```
132c132
< written to /tmp/claude/acceptance/0.5.10-dry/state-before.txt
---
> written to /tmp/claude/acceptance/0.5.10-dry/state-after.txt
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED |
|---|---|---|---|---|
| CLI | 2 | 2 | 5 | 0 |
| MAC | 3 | 1 | 9 | 4 |
| TUI | 0 | 0 | 10 | 0 |
| WEB | 0 | 0 | 13 | 0 |
| NEGATIVES | 1 | 0 | 0 | 0 |

**Verdict:** blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.

## Leftovers

(fill in: Scope hosts added by the run, files left on the Mac)
