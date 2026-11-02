# Release acceptance — 0.5.12 on the installed build (2026-11-02T06:11Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.12/run-20261102T061134Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `(none)`  ·  **manual:** 0  ·  **window:** 0

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| CLI-4 | **FAIL** | a core runs on 8080 (aitm pid 90396) but the one-shot printed "listening": false, "version": "0.5.12" (its own in-process state) | running core: proxy.status.listening true | claude/cli-oneshot-live-core |
| CLI-5 | **FAIL** | exit 0, printed 'acceptance-cli5.invalid' but the running core's scope.list does not contain it (false success; nothing to remove) | scope.list ["wikipedia.org"] | claude/cli-oneshot-live-core |
| N4-CLI | PASS | Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.; 0 loader lines on stdout first |  | log noise: PR #271 |
| CLI-9 | SKIP | status read (exit 0: "managed_by_us": false "state": "off" ); set/unset need Matt's yes (ACCEPT_YES=CLI-9) | proxy.system.status over the bus: {"bypass_default":["localhost","127.0.0.1","::1","*.local","169.254/16"],"detail":"HTTP and HTTPS off","effective":{"bypass":["*.local","169.254/16"],"http":{"enabled":false,"host":"","port":0},"https |  |
| CLI-10 | **FAIL** | exit 0; the running core has 3 flow(s), the one-shot's output matches 0 of their ids: [] | flow.table ids: 3 | claude/cli-oneshot-live-core |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 0 loader lines before the JSON | ca.status over the bus agrees | log noise: PR #271 |
| CLI-1 | SKIP | port 8080 held by aitm pid 90396; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-2 | SKIP | port 8080 held by aitm pid 90396; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-3 | SKIP | port 8080 held by aitm pid 90396; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-6 | SKIP | port 8080 held by aitm pid 90396; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-8 | SKIP | port 8080 held by aitm pid 90396; the no-core half needs 8080, 8081 and 8082 free |  |  |

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| N3-MAC | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |
| N4-MAC | SKIP | needs a plain 8080 listener before launch — yes (it blocks his app's core) |  |  |
| N5-MAC | SKIP | hand: Settings ▸ Bus field |  |  |
| MAC-1 | PASS | app running (bundle 0.5.12); embedded core pid 90396 listening 127.0.0.1:8080 version 0.5.12 | proxy.status.listening True, version 0.5.12; start marker in audit: True |  |
| MAC-2 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| MAC-3 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| MAC-4 | SKIP | needs the display-lock window (ACCEPT_WINDOW=1) to open the page and read it; expected words for the current state: system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core. | All Apps is on | scope.list ['wikipedia.org']; capture enabled True provider attached; system proxy off |  |
| N2-MAC | SKIP | needs the window (judged from the MAC-3 read) |  |  |
| MAC-5 | SKIP | needs the window (ACCEPT_WINDOW=1): types into the Edit Scope sheet; hosts ('example.com:80', 'httpbin.org:443') |  |  |
| MAC-6 | SKIP | needs Matt's yes (ACCEPT_YES=MAC-6) and the window |  |  |
| MAC-7 | SKIP | All Apps already on at start; needs the window to read 'All Apps is on' on the Status page | capture.status enabled True feeder listening provider attached handed off {'tcp': 0, 'udp': 0} |  |
| MAC-8 | BLOCKED | needs MAC-5 and a route (MAC-6 or MAC-7) |  |  |
| MAC-9a | BLOCKED | no extension-captured rows (All Apps on but Scope empty → the extension claims nothing) | capture.status flows_handed_off {'tcp': 0, 'udp': 0} |  |
| MAC-9b | PASS | 3 proxied rows, 3 carry a source_app → Apps sidebar shows them | flow.table source_app null ×0 |  |
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
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:55470 refused the token line (unauthorized) |  |
| N4-TUI | PASS | panel before any screen, exit 1 | 8080 held by aitm pid 90396 |  |
| N4-WEB | PASS | panel, exit 1, no card first | 8080 held by aitm pid 90396 |  |

## Journey TUI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| TUI-1 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-2 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-3 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-4 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5a | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5b | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-6 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-7 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-8 | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| N2-TUI | SKIP | port 8080 held by aitm pid 90396; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| TUI-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-TUI | N/A | aitm tui owns its core on 0.5.10; the app's restart is seen only from aitm-tui --bus |  |  |
| N3-TUI | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Journey WEB

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| WEB-1 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-2 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-3 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-4 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-5 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6a | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6b | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6c | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6d | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-7 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| N2-WEB | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| N5-WEB | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-8 | SKIP | port 8080 held by aitm pid 90396; aitm web needs the default ports (quit the app first) |  |  |
| WEB-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| WEB-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-WEB | N/A | aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7) |  |  |
| N3-WEB | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Restore proof

```
114,116d113
< {"at":<ms>,"origin":"operator","client_label":"aitm-tui","connection_id":"conn_dee75332ebdfedd2-3","command":"scan.start","args":"{\"profile\":{\"name\":\"l4-stream-safe\",\"target\":{\"origins\":[],\"l4\":[{\"ip\":\"127.0.0.1\",\"port\":58855,\"proto\":\"tcp\",\"grammar\":null}]},\"lanes\"
< {"at":<ms>,"origin":"operator","client_label":"aitm-e2e-scan-witness","connection_id":"conn_dee75332ebdfedd2-1","command":"scan.start","args":"{\"profile\":{\"accuracy\":\"normal\",\"audit\":{\"frequent_point_threshold\":8,\"ignore\":[{\"kind\":null,\"name_regex\":null,\"trait\":\"session\"
< {"at":<ms>,"origin":"operator","client_label":"aitm-tui","connection_id":"conn_dee75332ebdfedd2-3","command":"scan.map","args":"{\"profile\":{\"name\":\"map-only\",\"target\":{\"origins\":[\"http://127.0.0.1:<port>\"],\"l4\":[]},\"lanes\":[\"http\"],\"intensity\":\"passive\",\"speed\":\"norm
118a116,118
> {"at":<ms>,"marker":"start","pid":3247,"schema":1,"stream":"control","version":"0.5.12"}
> {"at":<ms>,"marker":"start","pid":3741,"schema":1,"stream":"control","version":"0.5.12"}
> {"at":<ms>,"marker":"start","pid":3755,"schema":1,"stream":"control","version":"0.5.12"}
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 2 | 3 | 7 | 0 | 0 | 0 |
| MAC | 2 | 0 | 16 | 5 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |
| TUI | 0 | 0 | 11 | 0 | 0 | 3 |
| WEB | 0 | 0 | 14 | 0 | 0 | 3 |

**Verdict:** `fail` — a performed step FAILed — blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

No Scope host was added by the run (or none is recorded). Log files stay under the run folder.

## Orchestrator note (read-only half, 2026-11-02 06:11Z, installed 0.5.12)

Run by the orchestrator from the main checkout right after the tap bump and `brew upgrade`
(app 0.5.12 pid 90325, embedded core pid 90396 on 8080; CLI 0.5.12). Verdict `fail` on
CLI-4/5/10 only — the one-shot verbs still act in-process (fix: cli-oneshot-live-core, R14,
next release). **MAC-9b PASS**: 3 proxied rows, 3 with `source_app` — the proxied-client
attribution (#283) is proven on the installed build. TUI/WEB/CLI no-core cells SKIP because
the installed app holds 8080 (quit/relaunch not approved). MAC-9a BLOCKED (Scope empty; no
extension rows). Window half not run (display lock not requested for 0.5.12).
