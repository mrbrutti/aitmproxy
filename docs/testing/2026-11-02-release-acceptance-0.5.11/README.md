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

## Run 2 — read-only half re-run on the fixed runner, 2026-11-02 03:00Z (`run-2-readonly-6765dee0/`)

Same installed build, after the stage-6 panel's fix round (runner at `6765dee0`). The app had
been relaunched again (core pid 16734, still 0.5.11) and Scope was **empty** again (the
attribution session's checklist had finished and cleaned up), so the extension claimed nothing.
Verdict **fail** (exit 1): CLI-4, CLI-5, CLI-10, MAC-9b. Every spec step id now has a row
(`run-2-readonly-6765dee0/README.md` is the runner's own skeleton; `run.log` the full transcript).

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-4 | **FAIL** | one-shot `"listening": false`, `"version": "0.5.10"` beside the running 0.5.11 core | `listening true` | `claude/cli-oneshot-live-core` (open) |
| CLI-5 | **FAIL** | exit 0, host echoed; running core's `scope.list` stays `[]`; nothing to remove | `scope.list []` | same |
| CLI-9 `aitm proxy system status` | SKIP (status read) | `"state": "off"`, `"managed_by_us": false` — agrees with `scutil`; `set`/`unset` need Matt's yes | `proxy.system.status state off` | — |
| CLI-10 `aitm flow list` | **FAIL** | exit 0, `[]` from its own in-process core while the running core has 5 flows | `flow.table` 5 rows | same as CLI-4 |
| CLI-7, N4-CLI | PASS | as run 1 | — | log noise: #271 |
| CLI-0 | SKIP | release run only; brew upgrade is Matt's | — | — |
| CLI-1/2/3/6/8 | SKIP | ports held by the app's core | — | #271 expected FAIL for 1/2/3 |
| MAC-1 | PASS | bundle 0.5.11, core 0.5.11 pid 16734 | `listening true`, start marker present | — |
| MAC-0, N3/N4/N5-MAC | SKIP | release-run only; CA stays trusted; plain 8080 listener needs a yes; Settings ▸ Bus is a hand | — | — |
| MAC-2/3/4, N2-MAC, MAC-5, MAC-7, MAC-13, N1-MAC | SKIP | need the window (MAC-7 now reads the word "All Apps is on" on the page instead of passing from the bus) | `capture.status` on, attached | N1: #274 merged after the tag, unreleased |
| MAC-6, MAC-15, MAC-14, MAC-16 | SKIP | yes / nothing to restore / not quit | — | — |
| MAC-8, MAC-10/11/12 | BLOCKED | MAC-5 and a route | — | — |
| MAC-9a | BLOCKED | no extension-captured rows this time: All Apps on but Scope empty → the extension claims nothing (run 1 saw 9 attributed rows while Scope had hosts) | `capture.status flows_handed_off` unchanged | — |
| MAC-9b | **FAIL** | 5 proxied rows, 0 with `source_app` | `flow.table source_app null ×5` | missing feature (core-name-the-client-app) |
| N5-TUI | PASS | exact refusal sentence; TUI stays open | — | — |
| N4-TUI | PASS | `aitm tui` on the held port: `cannot start: the proxy port 127.0.0.1:8080 is already in use.` before any screen, exit 1, no alternate screen | 8080 held by the app's core | — |
| N4-WEB | PASS | `aitm web`: same panel, exit 1, no card first | — | — |
| N5-CLI, N5-WEB | SKIP | CLI-6's refusal; judged in the web cell when `aitm web` runs | — | — |
| TUI-1…8, 5a/5b, N1/N2/N3-TUI, TUI-9/10 | SKIP | port 8080 held; n/a rows | — | — |
| WEB-1…8, 6a–d, N1/N2/N3/N5-WEB, WEB-9/10 | SKIP | port 8080 held; n/a rows | — | — |

Restore proof: `state-before.txt` == `state-after.txt` (volatile columns stripped): identical.
Secret leak check: 2 known secret values from the embedded core's config + token shapes: none.
Leftovers: none (no host reached any core).

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR |
|---|---|---|---|---|---|
| CLI | 2 | 3 | 7 | 0 | 0 |
| MAC | 1 | 1 | 16 | 5 | 0 |
| NEGATIVES | 3 | 0 | 2 | 0 | 0 |
| TUI | 0 | 0 | 14 | 0 | 0 |
| WEB | 0 | 0 | 17 | 0 | 0 |

**Verdict after run 2: `fail`** — owners: `claude/cli-oneshot-live-core` (CLI-4/5/10), #271 (CLI-1/2 when
the ports are free; log noise now), proxied-flow attribution (MAC-9b). Everything else `incomplete`
pending the window half.

## Run 3 — read-only half on the panel-2-fixed runner, 2026-11-02 03:26Z (`run-3-readonly-84e22c4f/`)

Same build and state as run 2 (core pid 16734, Scope empty, 8 proxied Firefox rows now). Same
verdict **fail**: CLI-4, CLI-5, CLI-10, MAC-9b; N4-CLI/N4-TUI/N4-WEB/N5-TUI PASS; the n/a steps now
read `N/A` (TUI-9/10, WEB-9/10, N1-TUI, N1-WEB, N5-CLI) and no longer hold the verdict; the
negatives cell is PASS. Restore diff identical; secret grep knew 2 values (collected at start and
end); `.secrets` shredded. This is the runner the PR ships.

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 2 | 3 | 7 | 0 | 0 | 0 |
| MAC | 1 | 1 | 16 | 5 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |
| TUI | 0 | 0 | 11 | 0 | 0 | 3 |
| WEB | 0 | 0 | 14 | 0 | 0 | 3 |

## Run 4 — read-only half on the final runner, 2026-11-02 03:35Z (`run-4-readonly-c3e55bee/`)

The app's core had been restarted again (pid 98224, 0.5.11, no flows yet, Scope empty), so MAC-9a and
MAC-9b are BLOCKED this time (nothing to judge) and the mac cell is SKIP; CLI-4/5/10 FAIL as before;
N4-CLI/TUI/WEB and N5-TUI PASS; verdict **fail**. The restore diff is NOT empty this run and the cause
is the harness's own CLI launches: every `aitm` the CLI journey and the N4 cells start (one-shots, the
refused `aitm web`/`aitm tui`) writes a `start` marker into the operator's shared `audit.jsonl`, so the
audit-tail section of `state-after.txt` shows three new `{"marker":"start",…,"version":"0.5.11"}` lines
and the tail has rolled past the attribution session's `scope.remove` entries. No proxy, CA, Scope,
capture or extension reading changed. `.secrets` did not exist after the run (never written: the web
cell did not run). Secret grep: 2 values known at start and end, none found.

## Run 5 — the window half, 2026-11-02 03:58–04:12Z (`run-5-window-c3e55bee/`)

Display lock granted by the orchestrator; Matt's yes, verbatim relayed: "Yes, all MAC steps"
(`ACCEPT_YES=MAC-2…MAC-16`, `ACCEPT_WINDOW=1`, `--manual`). Quit/relaunch of his app was **not**
approved, so TUI-3/7 and WEB-4/7 stayed SKIP. Runner at `c3e55bee` (main after #278), run from the
main checkout. The CLI had become 0.5.11 (formula bumped) by this run.

Starting state: app pid 98179, core pid 46605 (0.5.11) on 8080, All Apps on and attached, system
proxy off (Proxyman's 9090 disabled on both services), CA trusted, Scope `["wikipedia.org"]`
(someone else's), Safari running, Settings ▸ Proxy "Bypass hosts" key **never saved**.

| # | Result | Observed on the real window | Bus truth | Explains |
|---|---|---|---|---|
| MAC-1 | PASS | lane words "running", "connected", "operator ·" present | `listening true`, version 0.5.11 | — |
| MAC-2 | PASS | first-run sheet not shown (already dismissed or every row done) — recorded | `ca.status user trusted yes` | — |
| MAC-3 | **PASS** | Status page shows exactly "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." and "All Apps is on" (`MAC-3-ax.txt`) | scope 1 host, capture on/attached, system proxy off | — |
| MAC-4 | PASS | rows exist → banner case; no banner is correct (All Apps on, Scope filled, CA trusted) | `flow.table` 6 rows | — |
| N2-MAC | SKIP | not the N2 state (a route is open: All Apps on) | — | — |
| MAC-5 | **FAIL** | Proxy ▸ Scope… opened the Edit Scope sheet on the first press and the field "Host to add to scope" exists, but the **focused element is the sheet itself**, not the field; the probe digit was not read back and the cell refused to type into an unknown target. Diagnosis (`MAC-5-diagnosis.txt`): three probes, two attempts to set focus through accessibility (System Events cannot filter `entire contents`, and SwiftUI exposes no settable focus on the field). The field auto-focuses only when Scope is empty. | `scope.list` unchanged `["wikipedia.org"]` | product UX: the Add field should take focus whenever the sheet opens (card for the mac session); harness: click the field's AX bounds with a CGEvent before typing |
| MAC-6 | SKIP | `bypass list absent in the app's Settings ▸ Proxy Bypass hosts`: the `systemProxy.bypass` key was never saved, so the run could not read back the bypass the app would pass and refused to flip (spec MAC-6 precondition) | `proxy.system.status state off` | Matt saves the field once (it shows the recommended default) to unblock MAC-6/15 |
| MAC-7 | **PASS** | "All Apps is on" read on the Status page | `capture.status enabled true, attached` | — |
| MAC-8 | BLOCKED | MAC-5 (no host added; the Safari leg did not run) | — | — |
| MAC-9a | BLOCKED | no extension-captured rows (Scope has only `wikipedia.org`, no traffic to it) | `flows_handed_off.tcp 0` | — |
| MAC-9b | **FAIL** | 6 proxied rows, 0 with `source_app` → Apps sidebar shows nothing for them | `flow.table source_app null ×6` | missing feature (core-name-the-client-app) |
| MAC-10/11/12 | BLOCKED | MAC-8 | — | — |
| MAC-13 | **PASS** | Proxy ▸ Restart Core: new core pid 70510, Scope rows kept, no stale "Embedded core failed — not capturing" banner (`MAC-13-ax.txt`) | `scope.list` before == after `["wikipedia.org"]`, `listening true` | — |
| N1-MAC | SKIP | the Edit Scope sheet did not take focus before the restart; no add attempted (same root cause as MAC-5) | — | #274 is in this build |
| MAC-14 | SKIP | All Apps was on at start (operator's state); the run never turns his capture off | — | — |
| MAC-15 | SKIP | nothing to restore (MAC-6 did not set it) | — | — |
| MAC-16 | SKIP | the app was running at start; not quit by the run | — | — |
| MAC-0, N3/N4/N5-MAC | SKIP | release-run only; CA stays trusted; plain 8080 listener needs a yes; Settings ▸ Bus is a hand | — | — |
| CLI-4/5/10 | **FAIL** | as runs 1–4, now on the 0.5.11 CLI | running core `listening true`, `scope.list` unchanged, 6 flows vs `[]` | `claude/cli-oneshot-live-core` |
| CLI-7, N4-CLI, N4-TUI, N4-WEB, N5-TUI | PASS | as before | — | — |
| TUI-*, WEB-* | SKIP / N/A | ports held (quit not approved); n/a rows | — | — |

Restore proof: `state-before` vs `state-after` (volatile columns stripped) differs only by MAC-13's core
restart (pid 46605 → 70510, its obscura child, the new per-launch dir), the harness's own CLI start
markers in the shared audit tail, and a sibling session's `rustfmt` process line. System proxy, CA,
extension, Scope, defaults: unchanged. Leftovers: none (no host added; three probe digits typed into a
sheet with no focused field, nothing submitted; the sheet was dismissed with Esc at the end).
Secret grep: 4 values known (both cores' tokens, before and after the restart), none found.

| Journey | PASS | FAIL | SKIP | BLOCKED | ERROR | N/A |
|---|---|---|---|---|---|---|
| CLI | 2 | 3 | 7 | 0 | 0 | 0 |
| MAC | 6 | 2 | 10 | 5 | 0 | 0 |
| NEGATIVES | 3 | 0 | 0 | 0 | 0 | 1 |
| TUI | 0 | 0 | 11 | 0 | 0 | 3 |
| WEB | 0 | 0 | 14 | 0 | 0 | 3 |

**Verdict after run 5: `fail`** — CLI-4/5/10 (`claude/cli-oneshot-live-core`), MAC-9b (proxied-flow
attribution), MAC-5 (Edit Scope field not focused when Scope is non-empty; also blocks the Safari /
intercept legs). First window-half PASSes on the installed build: MAC-3 (the Status words), MAC-7,
MAC-13 (Restart Core keeps Scope, no stale banner). Unblocking the rest: Matt saves the Bypass hosts
field once (MAC-6/15), the mac session fixes the sheet focus or the harness clicks the field, and the
quit/relaunch yes for the TUI and web halves.
