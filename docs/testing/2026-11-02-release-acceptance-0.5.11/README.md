# Release acceptance — 0.5.11 on Matt's installed build

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Release under test: the `/Applications/Aitmproxy.app` 0.5.11 bundle the release pipeline built,
signed, notarized and installed with `build.sh --replace` (byte-identical to the DMG the cask
wraps; orchestrator, 2026-11-02). The CLI stays 0.5.10 (`/opt/homebrew/bin/aitm`) until the tap
bump this acceptance gates, so the CLI journey below is the 0.5.10 CLI against the 0.5.11 core.
The 0.5.10 record (02:06Z readings on the 0.5.10 core) is in
`../2026-11-01-release-acceptance-0.5.10/`.

## Run 1 — read-only half, 2026-11-02 02:25Z (`run-1-readonly/`)

`tests/e2e/acceptance/lib/run.sh` with no yes-list, no window, no `--manual`: nothing on the Mac
was changed. Verdict **fail** (exit 1): CLI-4, CLI-5, MAC-9b.

### Starting state (spec D2) — `run-1-readonly/state-before.txt`

| Reading | Value |
|---|---|
| App | running, pid 79149; embedded core pid 79160, `proxy.status.version` **0.5.11**, listen `127.0.0.1:8080`, bus `127.0.0.1:…` from its per-launch config |
| CLI | 0.5.10 |
| System proxy | off (`HTTPEnable 0`, `HTTPSEnable 0`); both services carry Proxyman's `127.0.0.1:9090` disabled |
| CA | trusted, login keychain (`B2D8E780…`); System keychain none |
| All Apps | on: `capture.status` capability `approved_attached`, feeder listening, provider attached, `flows_handed_off.tcp 5` |
| Scope | `example.com:443`, `www.apple.com:443`, `httpbin.org:443` (added by the attribution session's checklist under the display lock, not by Matt) |
| Bus mode | embedded, operator |
| Bypass (mac Settings) | not read on this run (precondition for MAC-6; the next run reads it) |

### Steps

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-4 `aitm proxy status` | **FAIL** | the 0.5.10 one-shot printed its own in-process `"listening": false`, `"version": "0.5.10"` while the 0.5.11 core listened on 8080 | running core `listening true`, version 0.5.11 | `claude/cli-oneshot-live-core` (queued behind #271) |
| CLI-5 `aitm scope add --host acceptance-cli5.invalid` | **FAIL** | exit 0, printed the host (the false success) | running core's `scope.list` unchanged: `["example.com:443","www.apple.com:443","httpbin.org:443"]` | same |
| CLI-7 `aitm ca status` | PASS | `user installed=present trusted=yes`; 98 loader lines on stdout first | `ca.status` over the bus agrees | log noise: #271 |
| N4-CLI `aitm web` while 8080 held | PASS | `Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.` + holder + remedy + `lsof` line; no card first | — | log noise: #271 |
| CLI-1/2/3/6/8 | SKIP | port 8080 held by the app's core (no-core half) | — | expected FAIL for CLI-1/2/3 on the 0.5.10 CLI (#271) |
| MAC-1 | PASS | app running, bundle 0.5.11, core 0.5.11 pid 79160 | `listening true`; `start` marker for pid 79160 in the audit | — |
| MAC-2/3/4 | SKIP | need the display-lock window to open the page; expected words for this state: "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." · "All Apps is on" · Scope step done (3 hosts) | as above | — |
| MAC-5 | SKIP | needs the window and a hand | — | — |
| MAC-6 | SKIP | needs Matt's yes | — | — |
| MAC-7 | PASS | All Apps already on, attached; expected lane "on" (Scope not empty) | `capture.status enabled true, listening, attached` | — |
| MAC-8 | BLOCKED | MAC-5 / route not exercised by this run | — | — |
| MAC-9a | **PASS** | 9 extension-captured rows all carry `source_app` (`com.apple.Safari`, `com.apple.curl`), `capture_interface macos-ne`, CONNECT rows `tunnel decrypted` — the first proof that Apps attribution works through the extension on this build | `flow.table` | — |
| MAC-9b | **FAIL** | 5 proxied rows (Firefox pointed at 8080 by hand) carry no `source_app`; one is `CONNECT httpbin.org:443 failed client_rejected_certificate` | `flow.table source_app null ×5` | missing feature: attribution for proxied flows (session core-name-the-client-app) |
| MAC-10/11/12 | BLOCKED | MAC-8 | — | — |
| MAC-13 | SKIP | needs the window and ACCEPT_YES=MAC-13 | — | — |
| MAC-14 | SKIP | All Apps was on at start; the run does not turn the operator's capture off | — | — |
| MAC-15 | SKIP | nothing to restore | — | — |
| MAC-16 | SKIP | the app was running at start; not quit by this run | — | — |
| AX read of the window (read-only) | observation | Flows page: 260 nodes, rows readable (`https://push.services.mozilla.com:443 — CONNECT 200 …`), `3 hosts in scope`; **no route banner**, correct per the banner rule (All Apps on, Scope filled, CA trusted) — `run-1-readonly/MAC-ax-initial.txt` | — | — |
| N5-TUI | PASS | `aitm-tui --bus <app bus> --token-file <wrong>`: `bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)`, retries stop | the core answered the token line with `unauthorized` | — |
| TUI-1…10, WEB-1…10 | SKIP | port 8080 held by the app's core; TUI-9/10 and WEB-9/10 are n/a on these surfaces | — | — |

### Restore proof

No `yes` step ran. `state-before` == `state-after` (timestamps/pids excluded): identical
(`run-1-readonly/state-diff.txt`). Secret grep over the run folder: none.

### Summary (run 1)

| Journey | PASS | FAIL | SKIP | BLOCKED |
|---|---|---|---|---|
| CLI | 2 | 2 | 5 | 0 |
| MAC | 3 | 1 | 10 | 4 |
| TUI | 0 | 0 | 10 | 0 |
| WEB | 0 | 0 | 13 | 0 |
| Negatives | 2 | 0 | 3 | 0 |

**Verdict after run 1: `fail`** on CLI-4/CLI-5 (one-shots vs the running core; fix queued on
`claude/cli-oneshot-live-core`) and MAC-9b (proxied-flow attribution; being built). CLI-1/2 are
the 0.5.10 CLI's known `--version`/`--help` defect (#271). Everything else is `incomplete`:
the window half (MAC-2…6, 8, 10…15; TUI; WEB) follows as run 2 in this folder once the display
lock and Matt's yes-list arrive.

### Leftovers

None. The run added no Scope host (CLI-5's host never reached the core). The three hosts in
Scope belong to the attribution session's checklist.

## Run 2 — window half

Pending: display lock after the attribution session's Task 8; yes-list requested from Matt
(MAC-1/16 quit + relaunch, MAC-6/15, MAC-7/14 not needed while All Apps is on, Safari visits,
TUI-3/7 and WEB-4/7 system-proxy flips). Scope hosts added by run 2 are removed at its end
unless Matt says keep, and listed either way.
