# Release acceptance — 0.5.10 on Matt's installed build (2026-11-01/02)

Spec: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md`.
Everything here was read from Matt's Mac as it was, through the installed binaries, with the
operator's real HOME and data dir. Nothing was pre-set. Every bus reading went over the running
core's operator bus with the token read from its per-launch config and never printed.

**Status of this run:** the read-only half is done (state, bus truth, CLI journey). The MAC, TUI
and WEB journeys and every `yes` step wait for the orchestrator's display-lock window and Matt's
yes-list (spec Open questions 1–2). Their rows below are `SKIP needs Matt's yes` / `SKIP needs a
hand` until then and will be filled in the same folder.

## Versions and starting state (spec D2) — `state-before.txt`

| Reading | Value |
|---|---|
| macOS | 27.0 (26A428), 2026-11-02T02:06Z |
| App bundle `CFBundleShortVersionString` | **0.5.11** (`/Applications/Aitmproxy.app`, bundled core dated Nov 1 18:02) |
| Running embedded core `proxy.status.version` | **0.5.10** (pid 78375, `--config …/aitm-embedded-core/C52A8B52-…/config.yaml`, listen `127.0.0.1:8080`, bus `127.0.0.1:58409`) |
| CLI | `/opt/homebrew/bin/aitm` → `Cellar/aitm/0.5.10`; `brew list --versions` failed in the Terminal shell (not investigated) |
| App running | yes (pid 16190), with its embedded core and `Resources/core/obscura` (pid 78382, proxy `127.0.0.1:8083`) |
| Default ports | 8080 held by the app's core; 8081/8082 free; 9090 free (Proxyman quit) |
| System proxy | `scutil --proxy`: `HTTPEnable 0`, `HTTPSEnable 0`, exceptions `*.local`, `169.254/16`. Both services (`Wi-Fi`, `Display Ethernet`) carry Proxyman's `127.0.0.1:9090` **disabled** |
| CA trust | login keychain: one "aitmproxy root CA", SHA-1 `B2D8E780FF3AB71F71F8544A1D7A8B64DDC5A485`; System keychain: none |
| Network extension | `com.mrbrutti.aitmproxy.ne (0.5.10/202611011041) [activated enabled]`; eight older copies "terminated waiting to uninstall on reboot", incl. a 0.5.10/202611011427 |
| Data dir | `~/Library/Application Support/aitmproxy/`: **no `config.yaml`**, `ca/`, `audit.jsonl` + `audit.agent.jsonl` + `audit.reads.jsonl`, `ca-audit.jsonl`, `columns.json`, `findings.json`, `rules.json`, `logs/`, `system-proxy-watchdog.log`; **no `system-proxy-state.json`** |
| App defaults | `bus.activeKind = embedded`, `bus.expectedRole = agent`, `bus.fromConfig = 1`, `capture.enabled = 1`, `proxy.preferredPort = 8080`, `settings.tab = capture` |
| Embedded-core temp dirs | 17 per-launch dirs under `$TMPDIR/aitm-embedded-core/`; only 5 hold a `bus.endpoint`; only `C52A8B52-…` listens on 8080 (the others are sibling sessions' dev bundles on ephemeral ports) |

**Observations on the start state (not steps):**
- O1. The app bundle says 0.5.11 but its running core answers 0.5.10, and the audit log holds
  `start` markers with `"version":"0.5.11"` from other pids (70489, 75355). A dev build was
  installed over `/Applications` by a sibling session's `build.sh`, or the bundle plist is ahead of
  the core. **The run therefore accepts "the app Matt has installed", versions as read.** The
  orchestrator should confirm which 0.5.11 artefact this is before the 0.5.11 acceptance.
- O2. The durable audit file in the data dir is shared by every core that uses the default data
  dir, including sibling sessions' dev cores (entries labelled `aitm-mac` from the live self-test
  at 18:04, `l4d-operator-reader`). Bus truth from the audit tail must be matched by `pid`/
  connection, not taken as the installed core's alone. Trap for the runner (D9).
- O3. Something on the Mac is already proxying through 8080 with the system proxy off: Firefox
  rows (`push.services.mozilla.com:443`, `merino…`, `ads.mozilla.org`, `incoming.telemetry…`,
  `aus5…`) as `CONNECT … 200`, `tunnel: passthrough`, `tunnel_reason: out_of_scope`,
  `source_app: null`. Firefox has its own proxy setting pointed at 127.0.0.1:8080. That is the
  per-host decryption behaving as specified (nothing in Scope → every tunnel passes through), and
  it is also the reason the Apps sidebar is empty: a proxied flow carries no `source_app`.

## Bus truth before any step — `bus-truth-before.txt`

```
scope.list            []
proxy.status          listening true · address 127.0.0.1:8080 · capturing true · flows 16 ·
                      intercept_armed false · paused 0 · version 0.5.10 ·
                      decrypt {scope_hosts 0, decrypting false,
                               advice "Nothing is decrypted until a host is in Scope."} ·
                      system_proxy {state off, managed_by_us false, setting false, supported true,
                                    detail "HTTP and HTTPS off"}
capture.status        capability approved_attached · enabled true · feeder listening ·
                      provider attached (team 995PCLM9KH, attached_at 1793581101765) ·
                      flows_handed_off {tcp 0, udp 0} · scope_entries 0
proxy.system.status   state off · mechanism networksetup · ours 127.0.0.1:8080 · both services
                      http/https disabled at 127.0.0.1:9090 · state_file …/system-proxy-state.json
                      (absent on disk) · watchdog_pid null
flow.table            16 rows, all Firefox CONNECTs, passthrough/out_of_scope or failed/client_closed,
                      source_app null, capture_interface null
ca.status             user {installed present, trusted yes}, system {absent, no}
```

So on this Mac at 02:06Z: capture is **on and attached but has claimed nothing** (empty Scope),
the system proxy is **off**, the CA is **trusted**, and the only traffic reaching the core is a
browser the operator pointed at the port by hand. The 0.5.10 app's Status page words for this
state are the MAC-3 words of the spec; MAC-3 is still to be read on the real window (window pending).

## Journey CLI (spec D6) — `cli-journey.txt`, `CLI-*.txt`

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| CLI-1 `aitm --version` | **FAIL** | exit 1; **98 INFO lines on stdout** (49 `aitm_plugin_rhai::loader loaded script` + 49 `aitm::scripts script loaded into the host`); stderr 189 lines: `` expected a command before flags, got `--version` `` + the full usage | — | PR #271 (W1 terminal reporting: one-line `--version`, exit 0, logs to a 0600 file) |
| CLI-2 `aitm --help` | **FAIL** | same shape: 98 stdout log lines, exit 1, `` expected a command before flags, got `--help` `` | — | PR #271 |
| CLI-3 bare `aitm` ready card | SKIP | port 8080 held by the app's embedded core; needs the app quit (Open question 2) | — | — |
| CLI-4 `aitm proxy status` with the app's core running | **FAIL** | the one-shot built its **own** in-process proxy and printed `"listening": false`, `"version": "0.5.10"` while a core listened on 8080 (pid 78375) | running core: `listening true` | `claude/cli-oneshot-live-core` (one-shots act on the running core or refuse) |
| CLI-5 `aitm scope add --host acceptance-cli5.invalid` with the app's core running | **FAIL** (the false success Matt hit) | exit 0, printed `acceptance-cli5.invalid` after 49 log lines | running core's `scope.list` **still `[]`** (`bus-truth-after-cli.txt`); no `scope.add` with `origin: cli` in the audit | `claude/cli-oneshot-live-core` |
| CLI-6 `aitm scope add` with no core | SKIP | a core is running; the no-core case needs the app quit | — | — |
| CLI-7 `aitm ca status` | PASS (with a note) | `stores.user {installed present, trusted yes}` — agrees with the keychain; but 49 log lines precede the JSON on stdout | `ca.status` over the bus: identical | log noise: PR #271 |
| CLI-8 `aitm web` on a held 8082 | SKIP | needs the ports free | — | — |
| N4-CLI `aitm web` while 8080 is held | PASS | exit 1, stderr: `Error: cannot start: the proxy port 127.0.0.1:8080 is already in use.` / `It is most likely held by another running `aitm`, the aitmproxy macOS app's embedded core, or another program.` / `Free it, or set `listen:` to another address in …/config.yaml.` / `Find the holder with:  lsof -nP -iTCP:8080 -sTCP:LISTEN`; no card printed first; 98 log lines on stdout before it | — | log noise: PR #271 |

CLI: PASS 2 · FAIL 3 · SKIP 3. Every FAIL has an owner; none is new.

## Journey MAC (spec D3)

| # | Result | Observed | Bus truth | Explains |
|---|---|---|---|---|
| MAC-1 | PASS (already running) | app pid 16190; core pid 78375 | `listening true`, `version 0.5.10`, `start` marker present | — |
| MAC-2 first-run sheet | SKIP needs the window | the sheet shows once per store; read whether it is still due from the window | `ca.status.user.trusted yes` → row 2 must read "CA trusted (user keychain)" | — |
| MAC-3 Status words | SKIP needs the window | expected for this state: "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core.", "All Apps is on", "Add a host to Scope (for now as example.com:443)", CA step done, "Set aitmproxy as the system proxy, or open the browser" | as above | — |
| MAC-4 Flows empty | n/a | 16 rows exist (O3); the banner case applies instead: expected "system proxy off · Nothing is decrypted until a host is in Scope." with button "Set as System Proxy" | `flow.table` 16 rows all passthrough | — |
| MAC-5 add host on the Scope page | SKIP needs the window (hand on his app) | — | — | — |
| MAC-6 Set as System Proxy | SKIP needs Matt's yes | — | — | — |
| MAC-7 Capture All Apps | already on (`capture.enabled 1`, provider attached) — the step becomes "verify the words for on, nothing in scope": lane "on, nothing in scope", remedy "Add a host to Scope (for now as example.com:443); nothing is captured until then" | SKIP needs the window to read | `capture.status enabled true, attached, 0 handed off` | — |
| MAC-8 real browser rows | SKIP needs MAC-5/6 | — | — | — |
| MAC-9b Apps sidebar, proxied flows | **FAIL (missing feature), read from the bus** | every one of the 16 flows is proxied with `source_app: null`, so the sidebar can show no app; this is Matt's "NOTHING is there". With All Apps on, extension-captured flows would carry `source_app`, but nothing is in Scope so the extension claims nothing (`flows_handed_off 0`) | `flow.table`: `source_app null` ×16, `capture_interface null` ×16 | missing feature: attribution for proxied flows (session core-name-the-client-app); plus the empty Scope (operator state, words in MAC-3/7) |
| MAC-10…16 | SKIP needs the window / Matt's yes | — | — | — |

## Journey TUI (spec D4), Journey WEB (spec D5)

SKIP `port 8080 held by Aitmproxy.app's embedded core` (Open question 2). Both will run in the
window if Matt allows quitting and relaunching the app; otherwise their words stay checked only
as the N4 startup refusal, which the CLI journey already proved (`N4-CLI`).

## Negative paths (spec D7)

| # | Surface | Result | Observed | Explains |
|---|---|---|---|---|
| N1 core restarting during an add | MAC | SKIP needs the window | — | S-081 / PR #274 |
| N2 no route, host in Scope | all | not reproducible without MAC-5 | the inverse state is live now: route (Firefox) without Scope → passthrough rows, `advice` set | — |
| N3 untrusted CA | all | SKIP `CA stays trusted` (not requested) | words read from source in the spec | — |
| N4 port held | CLI | PASS (above) | — | — |
| N5 wrong token | all | SKIP | — | — |

## Runner dry run at 02:25Z — the state had changed under the run (evidence moved to `../2026-11-02-release-acceptance-0.5.11/run-1-readonly/`)

`tests/e2e/acceptance/lib/run.sh 0.5.10-dry` with no yes-list and no window, read-only. Between
the 02:06Z readings above and this run the app was **relaunched by the orchestrator as the 0.5.11 release build** (core pid
78375 → 79160, `proxy.status.version` **0.5.11**), three hosts were added to Scope by the attribution session's checklist
(`example.com:443`, `www.apple.com:443`, `httpbin.org:443`) and traffic went through the
extension. This is why D2 reads the state first and why nothing here is "arranged".

| Cell | Result | What it showed |
|---|---|---|
| cli-livecore | FAIL | CLI-4 FAIL (one-shot `listening: false` beside a core on 8080); CLI-5 FAIL (host echoed, running core's `scope.list` unchanged); N4-CLI PASS; CLI-7 PASS |
| mac | FAIL | MAC-1 PASS (bundle 0.5.11, core 0.5.11 pid 79160); MAC-7 PASS (All Apps already on, attached, `flows_handed_off.tcp 5`); **MAC-9a PASS**: 9 extension rows all carry `source_app` (`com.apple.Safari`, `com.apple.curl`, `capture_interface macos-ne`, `tunnel decrypted`) — so with a host in Scope and All Apps on, the Apps sidebar does get its app; **MAC-9b FAIL**: 5 proxied rows (Firefox → 8080) carry no `source_app`, and one is `CONNECT httpbin.org:443 … failed / client_rejected_certificate` (a client with its own trust store); MAC-2/3/4/5/6/13 SKIP (window / yes); MAC-8/10/11/12 BLOCKED |
| mac AX read (`../2026-11-02-release-acceptance-0.5.11/run-1-readonly/MAC-ax-initial.txt`, read-only, no press) | observation | the window was on the Flows page: 260 accessibility nodes, flow rows readable (`https://push.services.mozilla.com:443 — CONNECT 200 …`), sidebar `3 hosts in scope`, one `out of scope` mark; **no route banner** — correct per the spec's banner rule (All Apps is on, so the closed system proxy is not named; Scope has hosts; CA trusted). SwiftUI buttons expose no title through AX (only "button"), so button labels are checked via the menu titles (`ax_texts.sh menu Proxy`), not the toolbar |
| n5 | PASS | `aitm-tui --bus <app bus> --token-file <wrong>` shows the exact sentence `bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)` and stops retrying |
| tui, web, cli-nocore | SKIP | `port 8080 held by aitm pid 79160` (the app's core) |
| restore diff | identical | no `yes` step ran |
| secret grep | none | — |
| verdict | **FAIL** (exit 1) | CLI-4, CLI-5, MAC-9b |

So Matt's "Apps sidebar shows NOTHING" has two halves on his Mac: (1) extension-captured
flows ARE attributed once a host is in Scope and All Apps is on (MAC-9a PASS on the 0.5.11 core,
`com.apple.Safari` rows); (2) every flow that reaches the core through the system proxy or a
browser's own proxy setting is unattributed (MAC-9b FAIL, missing feature). On the morning of
2026-11-01 his Scope was empty, so half (1) produced nothing either — the Status words for that
state are the MAC-3 words, still to be read on the window.

## Restore proof

No `yes` step has run; nothing was changed. `state-after.txt` will be taken after the window and
diffed here. The only writes so far: this run's bus reads (`agent.activity` shows them as
`aitm-e2e`, origin operator) and the CLI-5 one-shot, which changed nothing in the running core
and left no state file (the one-shot's in-process core minted nothing: `ca/` unchanged).

## Summary (so far)

| Journey | PASS | FAIL | SKIP | BLOCKED |
|---|---|---|---|---|
| CLI | 2 | 3 | 3 | 0 |
| MAC (dry run, 0.5.11 core) | 3 | 1 | 10 | 4 |
| TUI | 0 | 0 | 8 | 0 |
| WEB | 0 | 0 | 8 | 0 |
| Negatives | 2 | 0 | 3 | 0 |

**Verdict so far: `fail` — 0.5.10 fails the acceptance on the CLI journey (CLI-1/2/4/5) and on
proxied-flow Apps attribution (MAC-9b); the rest is `incomplete` (window and yes-list pending).** Owners: PR #271 (CLI-1, CLI-2, log noise in CLI-7/N4), the
`claude/cli-oneshot-live-core` PR (CLI-4, CLI-5), the proxied-flow attribution feature (MAC-9b).
The release-blocking question for 0.5.11 is whether those three are in it.

## Leftovers

None on the Mac. `/tmp/claude/acceptance/` holds the raw outputs (no tokens; checked by grep).
