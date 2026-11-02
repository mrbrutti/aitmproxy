# Release acceptance — 0.5.11 on the installed build (2026-11-02T04:01Z)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Raw outputs: `/tmp/claude/acceptance/0.5.11/run-20261102T035800Z` (state-before.txt, state-after.txt, bus-truth-*.txt, <journey>.out).

**Yes-list for this run (as given to the runner; quote Matt's words by hand):** `MAC-2,MAC-3,MAC-4,MAC-5,MAC-6,MAC-7,MAC-8,MAC-9a,MAC-9b,MAC-10,MAC-11,MAC-12,MAC-13,MAC-14,MAC-15,MAC-16`  ·  **manual:** 1  ·  **window:** 1

_Starting state (D2): fill in from `state-before.txt` by hand._

## Journey CLI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| CLI-4 | **FAIL** | a core runs on 8080 (aitm pid 46605) but the one-shot printed "listening": false, "version": "0.5.11" (its own in-process state) | running core: proxy.status.listening true | claude/cli-oneshot-live-core |
| CLI-5 | **FAIL** | exit 0, printed 'acceptance-cli5.invalid' but the running core's scope.list does not contain it (false success; nothing to remove) | scope.list ["wikipedia.org"] | claude/cli-oneshot-live-core |
| N4-CLI | PASS | Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.; 98 loader lines on stdout first |  | log noise: PR #271 |
| CLI-9 | SKIP | status read (exit 0: "managed_by_us": false "state": "off" ); set/unset need Matt's yes (ACCEPT_YES=CLI-9) | proxy.system.status over the bus: {"bypass_default":["localhost","127.0.0.1","::1","*.local","169.254/16"],"detail":"HTTP and HTTPS off","effective":{"bypass":["*.local","169.254/16"],"http":{"enabled":false,"host":"","port":0},"https |  |
| CLI-10 | **FAIL** | exit 0; the running core has 6 flow(s), the one-shot's output matches 0 of their ids: [] | flow.table ids: 6 | claude/cli-oneshot-live-core |
| CLI-7 | PASS | user installed=present trusted=yes (keychain has 1 aitmproxy cert); 98 loader lines before the JSON | ca.status over the bus agrees | log noise: PR #271 |
| CLI-1 | SKIP | port 8080 held by aitm pid 70510; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-2 | SKIP | port 8080 held by aitm pid 70510; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-3 | SKIP | port 8080 held by aitm pid 70510; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-6 | SKIP | port 8080 held by aitm pid 70510; the no-core half needs 8080, 8081 and 8082 free |  |  |
| CLI-8 | SKIP | port 8080 held by aitm pid 70510; the no-core half needs 8080, 8081 and 8082 free |  |  |

## Journey MAC

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-0 | SKIP | release run only; brew upgrade is Matt's |  |  |
| N3-MAC | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |
| N4-MAC | SKIP | needs a plain 8080 listener before launch — yes (it blocks his app's core) |  |  |
| N5-MAC | SKIP | hand: Settings ▸ Bus field |  |  |
| MAC-1 | PASS | app running (bundle 0.5.11); embedded core pid 46605 listening 127.0.0.1:8080 version 0.5.11; lane words: 'running' True, 'connected' True, 'operator ·' True | proxy.status.listening True, version 0.5.11; start marker in audit: True |  |
| MAC-2 | PASS | first-run sheet not shown (already dismissed or every row done); recorded as such |  |  |
| MAC-3 | PASS | Status page words present: ['system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.', 'All Apps is on']; missing: [] | scope.list ['wikipedia.org']; capture True/attached; system proxy off |  |
| MAC-4 | PASS | rows exist: banner case applies | flow.table rows 6 |  |
| N2-MAC | SKIP | not the N2 state: scope 1 host(s), system proxy off, All Apps True |  |  |
| MAC-5 | **FAIL** | the sheet's field did not take the focus probe (typed '1' not read back); refusing to type into an unknown target |  |  |
| MAC-6 | SKIP | bypass list absent in the app's Settings ▸ Proxy Bypass hosts (defaults key systemProxy.bypass never written: the field shows the app's recommended default, but the D2 reading is the stored key — save the field once in Settings); add the operator's tooling there first |  |  |
| MAC-7 | PASS | All Apps already on at start; Status page shows 'All Apps is on': True | capture.status enabled True feeder listening provider attached handed off {'tcp': 0, 'udp': 0} |  |
| MAC-8 | BLOCKED | needs MAC-5 and a route (MAC-6 or MAC-7) |  |  |
| MAC-9a | BLOCKED | no extension-captured rows (All Apps on but Scope empty → the extension claims nothing) | capture.status flows_handed_off {'tcp': 0, 'udp': 0} |  |
| MAC-9b | **FAIL** | 6 proxied rows, 0 carry a source_app → Apps sidebar shows NOTHING for them | flow.table source_app null ×6 | missing feature: attribution for proxied flows (session core-name-the-client-app) |
| MAC-10 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-11 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-12 | BLOCKED | needs MAC-8 rows, the window and a hand (reload in Safari) |  |  |
| MAC-13 | PASS | new core pid 70510; Scope rows kept True; stale failed banner present False | scope.list before ['wikipedia.org'] after ['wikipedia.org'] |  |
| N1-MAC | SKIP | the Edit Scope sheet did not open / take focus before the restart; no add attempted |  |  |
| MAC-14 | SKIP | All Apps was already on at start (operator's state) — not turned off by the run |  |  |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) |  |  |
| MAC-16 | SKIP | the app was already running at start; not quit by the run (Matt's app) |  |  |

## Journey NEGATIVES

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| N5-CLI | N/A | the one-shot refusal is CLI-6's row (no separate step on this surface) |  |  |
| N5-TUI | PASS | exact refusal sentence shown; TUI stays open with the message | core 127.0.0.1:58767 refused the token line (unauthorized) |  |
| N4-TUI | PASS | panel before any screen, exit 1 | 8080 held by aitm pid 70510 |  |
| N4-WEB | PASS | panel, exit 1, no card first | 8080 held by aitm pid 70510 |  |

## Journey TUI

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| TUI-1 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-2 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-3 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-4 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5a | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-5b | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-6 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-7 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-8 | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| N2-TUI | SKIP | port 8080 held by aitm pid 70510; aitm tui needs the default ports (quit the app first) |  |  |
| TUI-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| TUI-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-TUI | N/A | aitm tui owns its core on 0.5.10; the app's restart is seen only from aitm-tui --bus |  |  |
| N3-TUI | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Journey WEB

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| WEB-1 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-2 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-3 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-4 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-5 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6a | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6b | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6c | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-6d | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-7 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| N2-WEB | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| N5-WEB | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-8 | SKIP | port 8080 held by aitm pid 70510; aitm web needs the default ports (quit the app first) |  |  |
| WEB-9 | N/A | no All Apps control on this surface |  | UIs pending (per-host decryption decision) |
| WEB-10 | N/A | no Apps view on this surface on 0.5.10 |  |  |
| N1-WEB | N/A | aitm web owns its core: a core restart under an open tab is not performable here (words pinned in D7) |  |  |
| N3-WEB | SKIP | CA stays trusted (un-trusting is Matt's yes; words read from source) |  |  |

## Restore proof

```
23,24c23
< <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 57608 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-46605-dd3c90c4e6fde921414ee45c154e22d1/ready-dd3c90c4e6fde921414ee45c154e22d1.ready
< <pid> /opt/homebrew/bin/rustfmt /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/build.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/src/lib.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/src/main.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/agent_surface.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/audit_durable_connection_id.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/audit_log_binary.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/audit_log_config.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/audit_log_redaction.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/audit_log_wiring.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/bundled_startup.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/ca_frontends.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/config_file.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/config_rhai.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/discover_e2e.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/e2e_reflected_xss.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/findings_surface.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/frontends.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/intercept_url_rules_mcp.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/job_notification_method.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/l4_acceptance_mcp.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/l4_cua_tui.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/l4_operator_surfaces.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/l4_pocstep_wiring.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/l4_wiring.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m4_browser_capture.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m4_grader_gate.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m4_live_acceptance.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m4_scripted_e2e.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m4_sensitivity.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/m6_wiring.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_adapter.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_availability.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_capability.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_gate.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_listener.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_capture_no_key.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/macos_ne_feeder_loopback.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/no_bypass.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/no_stdout_tracing.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/obscura_mitm.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/operator_token_dispatch.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/rhai_e2e.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/rule_token_consistency.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/shutdown.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/soak.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/synopsis_groups.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/synopsis_groups_l4.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/sysproxy_config.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/sysproxy_contract.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/sysproxy_watchdog_dispatch.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/tui_embed.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/tui_live_bus.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/tui_mode_governance.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/tui_mode_governance_live.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_ask_split.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_audit_identity.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_audit_label.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_concurrency.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_governance.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_push.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_roles.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/web_bus_write_deadline.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/wiring.rs /Users/matt/Security/aitmproxy/.claude/worktrees/cli-ux-terminal-reporting-64b09b/crates/aitm/tests/wiring_m2.rs --edition 2021 --check
---
> <pid> /Applications/Aitmproxy.app/Contents/Resources/core/obscura serve --host 127.0.0.1 --port 58765 --proxy http://127.0.0.1:<port> --ca-cert /Users/matt/Library/Application Support/aitmproxy/ca/ca.crt --ready-file /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T/aitm-obscura-70510-94765498c68bd9ca896744a06aef7f7c/ready-94765498c68bd9ca896744a06aef7f7c.ready
29c28
< aitm    46605 matt   12u  IPv4 0x28a0e9f2451ed91c      0t0  TCP 127.0.0.1:<port> (LISTEN)
---
> aitm    70510 matt   12u  IPv4 0xf73fc633b79a7386      0t0  TCP 127.0.0.1:<port> (LISTEN)
113,116d111
< {"at":<ms>,"marker":"start","pid":99077,"schema":1,"stream":"control","version":"0.5.11"}
< {"at":<ms>,"marker":"start","pid":46585,"schema":1,"stream":"control","version":"0.5.11"}
< {"at":<ms>,"marker":"start","pid":46605,"schema":1,"stream":"control","version":"0.5.11"}
< {"at":<ms>,"origin":"operator","client_label":"aitm-mac","connection_id":"conn_b193be7595b6e4b7-1","command":"scope.add","args":"{\"host\":\"wikipedia.org\"}","result":"ok"}
117a113,116
> {"at":<ms>,"marker":"start","pid":60359,"schema":1,"stream":"control","version":"0.5.11"}
> {"at":<ms>,"marker":"start","pid":70510,"schema":1,"stream":"control","version":"0.5.11"}
> {"at":<ms>,"marker":"start","pid":71190,"schema":1,"stream":"control","version":"0.5.11"}
> {"at":<ms>,"marker":"start","pid":71241,"schema":1,"stream":"control","version":"0.5.11"}
134d132
< <ls> 21C2D26C-E27C-480F-8B6B-EA7EF41C2B55
139a138
> <ls> 570615FE-8800-4800-BCC2-963B0B3FF54E
157d155
< /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
161a160
> /var/folders/0t/zkzp_fls4cx5nvx_7zhbw7580000gn/T//aitm-embedded-core/<uuid>/  bus.endpoint=127.0.0.1:<port>  listen="127.0.0.1:<port>"
```

## Summary

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 2 | 3 | 7 | 0 | 0 | 0 |
| MAC | 6 | 2 | 10 | 5 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |
| TUI | 0 | 0 | 11 | 0 | 0 | 3 |
| WEB | 0 | 0 | 14 | 0 | 0 | 3 |

**Verdict:** `fail` — a performed step FAILed — blocks the tap bump until every FAIL has an owner in a shipped release or Matt's written acceptance.

_Explains state (open / merged, unreleased / missing feature with its card): fill in by hand per FAIL._

## Leftovers

No Scope host was added by the run (or none is recorded). Log files stay under the run folder.
