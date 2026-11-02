# Release acceptance: the operator's journeys on the installed build

**Status:** draft (self-approvable under Matt's autonomous mode once the spec-reviewer and quality-reviewer verdicts are on the PR; Matt's yes is still required for every machine-state step of every run)
**Research inputs:**
- Matt, 2026-11-01, verbatim: "just because you add them it does not mean they are working." / "the problem is you have not test things end to end correctly for almost anything and now all of these things are showing up" / "I am still yet to see apps showing up in the Apps sidebar for example NOTHING is there".
- `docs/superpowers/specs/2026-10-31-mac-traffic-route-advice-design.md` (the route words), `2026-10-31-system-proxy-automation-design.md` §D12 (the pill words), `2026-10-31-macos-status-page-and-first-run-design.md`, `2026-10-31-ne-no-scope-honest-state-design.md`, `2026-11-01-mac-bus-reconnect-ownership-design.md`, `2026-11-01-cli-terminal-reporting-design.md`, `2026-11-01-cli-oneshot-live-core-design.md` (on branch `claude/cli-oneshot-live-core`), `2026-10-30-aitmproxy-e2e-real-test-framework-design.md`.
- Source survey of `c65ed0f2` (2026-11-01) for every string quoted below: `apps/mac/Sources/AitmproxyKit/{ConnectionSummary,SetupWords,CATrustFacts,CaptureAdvice,Compose}.swift`, `apps/mac/Sources/Aitmproxy/{App,SettingsView}.swift`, `apps/mac/Sources/Aitmproxy/Shell/{SetupSheet,RouteBanner,InterceptBar,StatusBar,ShellView}.swift`, `apps/mac/Sources/Aitmproxy/Panels/{ScopePanel,ScopeSheet,StatusPanel}.swift`, `crates/aitm-tui/src/{ui/bars.rs,ui/flows.rs,ui/overlays.rs,model.rs,app.rs,bus.rs,main.rs}`, `apps/web/src/{shell/*,panels/scope/*,flows/FlowList.tsx,bus/*}`, `crates/aitm/src/{main.rs,web/mod.rs,tui.rs}`, `crates/aitm-cli/src/dispatch.rs`, `crates/aitm-plugins/src/{control,scope,capture,intercept}.rs`, `crates/aitm-sysproxy/src/plugin.rs`, `crates/aitm-ca/src/commands.rs`, `crates/aitm/tests/frontends.rs` (`EXPECTED_TOOLS`).
- Live facts about Matt's Mac in the project memory: CA trusted in the login keychain since 2026-11-01; `/dev/bpf*` root-only; Proxyman owns `127.0.0.1:9090` when it runs; services `Wi-Fi` and `Display Ethernet`; installed cask + formula are both 0.5.10 (`/Applications/Aitmproxy.app`, `/opt/homebrew/bin/aitm`); the app's data dir is `~/Library/Application Support/aitmproxy/` (config.yaml, ca/, audit.jsonl, audit.agent.jsonl, audit.reads.jsonl, system-proxy-state.json).

## Intent

Every PR this week carried a "live proof", and every proof was a slice on a dev bundle with
pre-arranged state: a core already up, a host already in Scope, traffic already routed. Nobody
walked the operator's whole path on the installed app, so on Matt's 0.5.10 the Scope page kept a
failed add listed with no error, `aitm scope add` printed success without reaching the running
core, no TUI confirm ever completed, a host in Scope produced no rows because nothing routed
traffic and the UI did not say so, and the Apps sidebar stayed empty. This spec defines the
**release acceptance**: the operator's journey on each of the four surfaces, run on the build
Matt actually installed, from the state his Mac is actually in, before every tap bump. A step
that fails blocks the release until it is fixed or Matt accepts it in writing in the report.

## Goals

- One checklist per surface (macOS app, TUI, web UI, CLI) whose steps are the operator's own
  actions in order, each with the exact words the surface must show and the bus truth that must
  agree with them.
- Every run starts from the operator's real state, read and recorded first, and ends with that
  state restored and re-read.
- Every failing step is reported with the bus truth beside it and the open PR or missing feature
  that explains it, so the orchestrator can gate the tap bump on the list.
- The negative paths an operator meets in practice (core restarting during an add, no route into
  the proxy, untrusted CA, no core for a one-shot, port held) have their words pinned per surface.
- A runner under `tests/e2e/acceptance/` the orchestrator invokes once per release; every step a
  machine cannot do without Matt's hand is an honest SKIP with the reason, never a green.

## Non-goals

- Replacing per-PR live proofs or the `tests/e2e` merge gate; this runs in addition, on the
  installed build, not on `target/debug`.
- Testing dev bundles, fixtures, snapshots or sample data (all removed; `docs/superpowers/specs/2026-10-31-remove-fake-data-ui-modes-design.md`).
- Scanner, PoC, findings, scripting, agent policy and L4 journeys. They have their own suites.
  This spec covers the operator's capture journey only.
- Fixing the defects it finds. Each finding points at the PR or feature that owns it.

## Anti-goals

- A run that pre-sets anything: a host added over the bus "to save time", a core started with a
  test config, the system proxy set by script before the app's own button is pressed. The journey
  is the operator's, through the operator's controls.
- A green that hides a hand step. A step the harness could not perform is SKIP with the reason.
- Any machine-state change without Matt's explicit yes for that run, relayed by the orchestrator;
  silence is never go. Any such change without a recorded before-state and an armed restore.
- The operator token in any log, report, screenshot caption or message.
- A report that says "works" without quoting what the surface showed and what the bus answered.

## Constraints

- **Installed build only.** The app is `/Applications/Aitmproxy.app` (bundle id
  `com.mrbrutti.aitmproxy`, extension `com.mrbrutti.aitmproxy.ne`); the CLI is
  `/opt/homebrew/bin/aitm`. The report names both versions as read from `Info.plist`
  `CFBundleShortVersionString` and `proxy.status.version`.
- **One core at a time on the default ports.** The app's embedded core, `aitm tui`, `aitm web` and
  bare `aitm` all serve the operator's `config.yaml` listen address (8080/8081/8082). Surfaces run
  one after another; a surface whose ports are held by another surface's core is SKIP with
  `port <n> held by <holder>` (found with `lsof -nP -iTCP:<port> -sTCP:LISTEN`), never started on
  a different port.
- **Machine-state steps** (set/restore the system proxy, turn All Apps capture on/off, trust or
  untrust the CA, quit or launch Matt's app, kill a core) run only inside a window the
  orchestrator opens with the display lock and Matt's yes for that run. Each window announces
  start and end, is as short as the step allows (≤ 20 s for a system-proxy flip), records the
  before-state in the same script that writes, arms an EXIT trap that restores, and diffs
  before/after. Bypass for the operator's own tooling is always on
  (`*.anthropic.com`, `api.anthropic.com`, `claude.ai`, `*.claude.ai`, `github.com`,
  `*.githubusercontent.com`, loopback and `.local`).
- **Read-only probes** (`scutil --proxy`, `networksetup -getwebproxy <svc>`,
  `security find-certificate -a -c aitmproxy`, `systemextensionsctl list`, `lsof`, reading the
  data dir and the embedded core's per-launch config) need no yes and run before and after every
  journey. The sandboxed Bash sees an empty `scutil --proxy` dictionary and cannot `ps`/`pgrep`;
  probes run from the Terminal panel.
- **Bus truth** is read over the real operator bus: the embedded core's `bus.endpoint` +
  `operator_token` from its per-launch `$(getconf DARWIN_USER_TEMP_DIR)/aitm-embedded-core/<uuid>/config.yaml`
  (identify the child by its own command line, never "the newest config in the temp dir"), or
  `--bus-endpoint-file` + the config's `mcp.operator_token` for a terminal core. The client is
  `tests/e2e/aitm_e2e/bus.py` (token line, then newline-delimited JSON-RPC). The token is read
  into a variable and never echoed.
- **Driving the UIs:** the mac app through System Events menu presses and CGEvent keystrokes
  while it is frontmost (probe focus with one harmless character first; `pbcopy`+⌘V for text the
  keyboard cannot type; `screencapture -l <win>` in a background loop for transient states), the
  TUI through a Python pty with `TIOCSWINSZ` set before the first read and the cell-diff stream
  replayed into a grid, the web UI through a real browser (Safari or Chrome by hand; Playwright
  Chromium when automated). Never AppleScript `keystroke` without `set frontmost to true`.
- **Safari hosts:** a host that advertises Alt-Svc h3 may bypass TCP capture; the journey's host
  is plain `http://example.com/` for the first row and `https://httpbin.org/get` for the
  decrypted row (both non-h3 as of 2026-11-01). The host entered on the Scope page is written
  the way each surface accepts it today: `example.com:80` / `httpbin.org:443` on the mac app
  (its placeholder says `host:443 or host:80 (for now)`), bare hosts on the TUI, web and CLI.
- **Repeatable.** The same checklist runs on 0.5.10 today and on every later release; the report
  folder name carries the version. A step's words may change between releases only through a spec
  that this spec then cites; the acceptance quotes the current words.
- **Sandbox:** `git`, `gh`, port binds, `open`, `osascript` and the Terminal-only tools run from the
  Terminal panel with logs under `/tmp/claude/acceptance/`; nothing in the repo tree is executed
  from inside a downloaded directory.

## Design

### D1. Vocabulary

- **Journey**: the ordered steps of one surface, from the operator's real starting state to the
  restored state. Four journeys: `MAC`, `TUI`, `WEB`, `CLI`.
- **Step**: one operator action with (a) the action, (b) the words the surface must show,
  (c) the bus truth that must agree, (d) who can perform it: `auto` (the harness), `hand` (Matt or
  the orchestrator's window), `yes` (a machine-state change: needs Matt's yes for this run).
- **Result** per step: `PASS` (words and bus truth both as specified), `FAIL` (either differs;
  the report quotes both), `SKIP <reason>` (not performed: no window, no yes, port held, or a
  missing dependency), `BLOCKED <step>` (an earlier step failed and this one cannot be reached).
  A `SKIP` is never counted as green; the release summary lists them.
- **Bus truth**: the six readings taken beside every step that changes state and at every FAIL:
  `scope.list`, `proxy.status`, `capture.status`, `proxy.system.status`, `flow.table`, and the
  tail of the durable audit (`<data dir>/audit.jsonl`, plus `audit.agent.jsonl`).
- **Explains**: the open PR, merged-but-unreleased PR, or missing feature that owns a FAIL,
  by number or spec path. A FAIL with no owner is a new defect and gets a card.

### D2. Starting state, read first (every journey)

Before the first action, the run records (read-only, Terminal):

| Reading | Command / source | Why |
|---|---|---|
| Installed versions | `defaults read /Applications/Aitmproxy.app/Contents/Info.plist CFBundleShortVersionString`; `brew list --versions aitm aitmproxy` | the report is per release |
| App running? | `pgrep -fl 'Aitmproxy.app/Contents/MacOS'`; its embedded core by `pgrep -f 'Aitmproxy.app/Contents/Resources/core/aitm'` | whether launch is the first step or the app is already up |
| Ports | `lsof -nP -iTCP:8080 -iTCP:8081 -iTCP:8082 -sTCP:LISTEN` | who holds the defaults |
| System proxy | `scutil --proxy`; `networksetup -getwebproxy` / `-getsecurewebproxy` for `Wi-Fi` and `Display Ethernet` | the before-state the restore must reproduce |
| CA trust | `security find-certificate -a -c aitmproxy -Z login.keychain-db` (and the System keychain) | first-run row 2 must read this back |
| Extension | `systemextensionsctl list` filtered on `com.mrbrutti.aitmproxy.ne` | All Apps state |
| Data dir | `ls -la ~/Library/Application\ Support/aitmproxy/`; `scope:` section of `config.yaml`; `system-proxy-state.json` present? | persisted scope, watchdog state |
| Capture state | `defaults read com.mrbrutti.aitmproxy` keys that exist (`capture.enabled`, `proxy.setSystemProxyAtLaunch`, first-run flags) | what the app will do at launch |

The journey proceeds from whatever this shows. If the app is already running, `MAC-1` is
"already running" and recorded as such; if a host is already in Scope, `MAC-5` adds a second host
and the report says so. Nothing is reset to make the journey cleaner.

### D3. Journey MAC — the macOS app

Surface facts (survey of `c65ed0f2`): the first-run sheet has three rows (system proxy, CA, Scope)
and **no capture row**; there is **no Capture menu**, "Capture All Apps" is the last item of the
Proxy menu; app attribution exists **only** for flows the extension hands off (`source_app`),
a proxied flow carries none.

| # | Who | Action | The surface must show (verbatim) | Bus truth |
|---|---|---|---|---|
| MAC-1 | hand/yes if the app is not running | Launch `/Applications/Aitmproxy.app` from Finder or `open -a Aitmproxy` (Terminal). If already running: record and continue. | Status lane cards: Core "running", Bus "connected as operator". No red banner. | `proxy.status.listening == true`, `address` = the config's listen, `version` = the installed version. Audit `start` marker with that `version`. |
| MAC-2 | auto (read) | First-run sheet, if shown | Title "Set up aitmproxy on this Mac". Row 1 "Set aitmproxy as the system proxy" with the route line (MAC-6 words) and button "Set as System Proxy". Row 2 "Trust the aitmproxy CA" whose fact is **read back from the keychain**: "CA trusted (user keychain)" on Matt's Mac today; "HTTPS is not captured until the CA is trusted" when not trusted, with the button "Trust the aitmproxy CA". Row 3 caption "Nothing is decrypted until a host is in Scope" with "Open Scope…". Footer "Not Now" (or "Done" when all three are done). If the sheet is not shown (already dismissed with "Don't ask again", or every row done) the report says which. | `ca.status.stores.user.trusted == "yes"` must agree with row 2; `proxy.system.status.state` with row 1; `scope.list` with row 3. |
| MAC-3 | auto | Proxy ▸ Status (⌘0) | "Getting started" list in the order Core, Bus, System proxy, All Apps, Scope, CA, First flow. With nothing routed and an empty Scope: "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." (button "Set as System Proxy"); "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)" (button "Capture All Apps"); "Add a host to Scope (for now as example.com:443)" (button "Open Scope…"); CA step omitted or done when trusted; "Set aitmproxy as the system proxy, or open the browser". | `proxy.system.status.state == "off"`, `capture.status.enabled == false`, `scope.list == []`, `proxy.status.decrypt.advice == "Nothing is decrypted until a host is in Scope."` |
| MAC-4 | auto | Flows page, empty | "No flows yet" with one row per closed route carrying the full line and its button(s) (the MAC-3 words). | `flow.table.flows == []` |
| MAC-5 | auto | Proxy ▸ Scope… (⇧⌘O), then on the page the Edit Scope sheet: type `example.com:80` (then `httpbin.org:443`) into the field with placeholder "host:443 or host:80 (for now), host:port or *.wildcard:port", press "Add" (⌘⏎) | The host appears as a normal row (not tertiary "pending") within one poll (≤ 2 s). Status bar shows no "add to scope:" error. Overview/sidebar Scope count rises. | `scope.list` contains the entry; audit has one `scope.add` with `origin: operator`, `result: "ok"`. Persisted: after MAC-13's restart, `scope.list` still contains it (spec 2026-10-31-macos-scope-persistence). |
| MAC-6 | **yes** | Proxy ▸ "Set as System Proxy" (⌥⌘P) — or the first-run row 1 / Status button | Status step becomes "system proxy on · 127.0.0.1:8080"; menu item title flips to "Restore System Proxy"; Flows banner no longer names the system proxy. `scutil --proxy` shows `HTTPEnable 1`, `HTTPSEnable 1`, `HTTPProxy 127.0.0.1`, `HTTPPort 8080` and the bypass list. | `proxy.system.status` = `{state: "points_at_us", managed_by_us: true}`; `proxy.status.system_proxy.state == "points_at_us"`; audit `proxy.system.set` ok; `system-proxy-state.json` written (0600). |
| MAC-7 | **yes** | Proxy ▸ "Capture All Apps" (⌃⌘A) | Status All Apps step "All Apps is on"; lane card "on" (or "on, nothing in scope" before MAC-5). If macOS asks: "All Apps waiting for approval — approve the extension in System Settings" and the Apps empty state "Waiting for approval". | `capture.status` = `{enabled: true, feeder.state: "listening", provider.state: "attached"}`; `systemextensionsctl list` shows `[activated enabled]`. |
| MAC-8 | hand | In Safari (or Chrome), open `http://example.com/` then `https://httpbin.org/get` | Flows rows: `GET http://example.com/ 200` and `GET https://httpbin.org/get 200` with tunnel "decrypted" (not "passthrough"); a `CONNECT` row for httpbin. Sidebar Flows/Domains counts rise. No banner about the CA. | `flow.table` rows with `authority` = the hosts, `status 200`, `tunnel == "decrypted"`, `tunnel_reason == null`; a row from the extension carries `capture_interface == "macos-ne"` and `source_app` (`com.apple.WebKit.Networking` → shown as "Safari"), a proxied row carries `source_app == null`. |
| MAC-9 | auto | Apps sidebar | With All Apps on: a group for the browser ("Safari" or "Google Chrome") with its flow count. With only the system proxy routing (All Apps off): **today** the sidebar shows no app and the table shows the rows with an empty client column; the empty state "No app attribution yet" appears only when there are no flows at all. The required end state (not in 0.5.10): a proxied flow is attributed to its client app too (session core-name-the-client-app; `Explains` names it). | `flow.table` rows: `source_app` non-null for every row that should appear under an app. |
| MAC-10 | auto | Flow ▸ "Arm Intercept" (`i`) with the flow list focused; reload `http://example.com/` in the browser | Intercept bar "Intercept armed — every request pauses here" then "1 paused  GET http://example.com/"; buttons "Resume"/"Apply & Resume", "Edit", "Resume All", Kill menu, "Rules…", "Disarm". Toolbar " · intercept armed". The browser tab spins. | `proxy.status.intercept_armed == true`; `flow.table` row `state == "intercepted"`, `status == null`; `proxy.status.paused == 1`. |
| MAC-11 | auto | "Resume" (⌘⏎) | Row shows `200`; bar back to "Intercept armed — every request pauses here"; the browser page loads. | row `state == "resumed"`, `status 200`; audit `flow.resume` ok. |
| MAC-12 | auto | Flow ▸ "Disarm Intercept" (`i`) | Bar gone; toolbar without "intercept armed". | `intercept_armed == false`. |
| MAC-13 | auto | Proxy ▸ "Restart Core" (⌃⇧⌘R) | Core lane "starting…" then "running"; Bus "connected as operator"; **no** stale "Embedded core failed — not capturing" banner once the core is back; the Scope rows are still listed (persisted and re-pushed); the system proxy is still "on · 127.0.0.1:8080" (or restored and re-set, both acceptable; the report says which). Every verb works after the restart (spec 2026-11-01-mac-bus-reconnect-ownership). | New `start` audit marker; `scope.list` unchanged; `proxy.system.status.state == "points_at_us"`; `proxy.status` answers. |
| MAC-14 | **yes** | Proxy ▸ "Stop Capturing All Apps" (⌃⌘A) | All Apps step back to "All Apps off — …"; lane "all apps off". | `capture.status.enabled == false`, `feeder.state == "off"`. |
| MAC-15 | **yes** | Proxy ▸ "Restore System Proxy" (⌥⌘P) | Step "system proxy off — Set as System Proxy so …" (or the previous owner, e.g. "system proxy on · 127.0.0.1:9090, not this core — Another app owns the system proxy. …" when Proxyman owned it); menu title back to "Set as System Proxy". `scutil --proxy` equals the D2 reading byte for byte. | `proxy.system.status` = `{state: <before>, managed_by_us: false}`; audit `proxy.system.unset` ok with `restored` naming both services. |
| MAC-16 | hand (only if MAC-1 launched it) | Quit the app (⌘Q) | The embedded core and obscura exit with it (no orphan with parent 1). `scutil --proxy` still equals the D2 reading. Nothing of the operator's remains changed except the Scope hosts added in MAC-5, which the report lists for Matt to remove (or removes on his yes). | no `aitm` process from the bundle path remains; the data dir's `system-proxy-state.json` says restored or is gone. |

### D4. Journey TUI — `aitm tui`

Surface facts: `aitm tui` takes no arguments and always runs its own embedded core on the
operator's config (`crates/aitm/src/tui.rs`); the standalone `aitm-tui --bus host:port
--token-file p` attaches to a running core. The acceptance runs `aitm tui` as the operator
would. Both journeys need the default ports free, so this journey runs with the app quit
(MAC-16) or is SKIP `port 8080 held by Aitmproxy.app's embedded core`.

| # | Who | Action | The surface must show | Bus truth |
|---|---|---|---|---|
| TUI-1 | auto (pty, 180×45) | `aitm tui` | Alternate screen drawn (a 0×0 pty draws nothing — set `TIOCSWINSZ` first). Toolbar pill `● aitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trusted`; status bar `bus … · operator`; flows pane "No flows yet — point a client at 127.0.0.1:8080 or open the browser."; toast "embedded proxy · set RUST_LOG to write a log file" (or the log path). | the core's `--bus-endpoint-file` is not written by `aitm tui` (in-process transport): bus truth is read from the TUI's own screen plus the audit file; `proxy.status` over the bus is SKIP `aitm tui serves no loopback bus on 0.5.10` until the operator-bus-default-on work lands (Explains: `claude/cli-oneshot-live-core`). |
| TUI-2 | auto | `S` (Scope), `a`, type `example.com`, Enter | Prompt `scope add:` with hint `host · host:port · *.wildcard — a human action`; toast `Scope + example.com`; panel lists the host; status bar ` · 1 in scope`. Before: ` Scope is empty — every flow is dimmed and read-only. Press a to add a host.` | audit `scope.add` ok (origin operator). |
| TUI-3 | **yes** | `s` (system proxy toggle) | Pill `· sys-proxy setting…` then `· sys-proxy → us` (the §D12 pill word). `scutil --proxy` points at 127.0.0.1:8080. | audit `proxy.system.set` ok; state file written. |
| TUI-4 | hand | Safari visits `http://example.com/` and `https://httpbin.org/get` | Two rows in the flows pane with `200`; status bar row count rises. | audit shows no error; the pane shows `GET example.com /` and `GET httpbin.org /get`. |
| TUI-5 | auto | `i`, Safari reload of example.com, `a` (resume), `i` | ` ⏸ Intercept armed — every request pauses here` → ` ⏸ 1 paused  GET http://example.com/` with `[a Resume] [A Resume all] [d Kill · …] [e Edit] [i Disarm]` → toast `Resumed` → toast `Intercept disarmed`. | — |
| TUI-6 | auto | `:` palette, a confirm-bearing verb (e.g. `ca install` dry run is not confirmable; use the CA panel's `i` then `n`) | Prompt ` confirm: ca.install — … [y/N] `, hint `y runs it · n / Esc cancels`; `n` → toast `CA trust cancelled`. (PR #263 fixes the over-the-wire `_confirm` prune for `l4.*`; the acceptance pins only the local confirm on this release and records #263 under Explains.) | no `ca.install` in `ca-audit.jsonl` from this run. |
| TUI-7 | **yes** | `s` again | Pill `· sys-proxy setting…` then `· sys-proxy off` (or the previous owner `· sys-proxy → 127.0.0.1:9090`). `scutil --proxy` equals the D2 reading. | audit `proxy.system.unset` ok. |
| TUI-8 | auto | `q` | Exit 0; the terminal restored (no alternate screen left); no `aitm` child remains; `scutil --proxy` unchanged. | — |

### D5. Journey WEB — `aitm web` in a real browser

| # | Who | Action | The surface must show | Bus truth |
|---|---|---|---|---|
| WEB-1 | auto | `aitm web` in the Terminal (ports free, else SKIP naming the holder) | The ready card: `aitm web` between two 60-char rules; `Web UI     http://127.0.0.1:8082/#t=…`; `Operator   http://127.0.0.1:8082/#t=…&expect=operator` **only if** `mcp.operator_token` is set in the operator's config (the report says whether it was; if absent the operator journey is BLOCKED and Explains = "operator-token generate is a manual step on 0.5.10"); `Proxy      127.0.0.1:8080`; `Browser    127.0.0.1:8081  (SSRF-filtered)`; `Bus        ready`; `Scope      Nothing is decrypted until a host is in Scope.` while Scope is empty. Nothing from the Rhai loader on stdout. | `/healthz` → `{"ok":true}`. |
| WEB-2 | hand (Safari/Chrome) or auto (Playwright Chromium) | Open the Operator URL | Banner "Operator session — sensitive commands are enabled."; toolbar pill `aitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trusted`; status bar `bus 127.0.0.1:8082` with tooltip `bus open`; flows grid "No flows yet — point a client at 127.0.0.1:8080 or open the browser." | — |
| WEB-3 | auto | Sidebar "Scope" → input `Add host to scope`, type `example.com`, Enter | Row in table "Hosts in scope"; status bar `1 host in scope`; no toast `scope: …`. Before: "No hosts in scope — add the hosts you are authorised to test." | `scope.list` contains it (read over the web `/bus` as operator or the loopback bus if configured). |
| WEB-4 | **yes** | Toolbar pill menu → "Set as system proxy" | Pill `· sys-proxy setting…` → `· sys-proxy → us`. `scutil --proxy` points at us. | `proxy.system.set` audit ok. |
| WEB-5 | hand | A second real browser (Safari) visits `http://example.com/` and `https://httpbin.org/get` | Rows in the Flows grid with `200`; Domains count rises. (The web UI's own tab is on loopback 8082 and bypasses the proxy; the visited pages must come from another tab/browser.) | — |
| WEB-6 | auto | Intercept bar: `i`, reload in Safari, "Resume" (⌘⏎), "Disarm" | "Intercept armed — every request pauses here" → "1 paused" → row "Paused" → row `200` → bar gone. | — |
| WEB-7 | **yes** | Pill menu → restore (the same item, now reading the restore state) | Pill `· sys-proxy off` (or previous owner). `scutil --proxy` equals D2. | `proxy.system.unset` ok. |
| WEB-8 | auto | `Ctrl-C` in the Terminal | Exit, ports released, system proxy unchanged. Core restart while the tab is open (negative N1 below): the status dot goes amber and the tab latches `bus token expired` with tooltip `token expired — reopen the URL printed by \`aitm web\`` unless `AITM_WEB_TOKEN` is fixed. | — |

### D6. Journey CLI — startup card and one-shot verbs

Surface facts on 0.5.10: bare `aitm` prints **no** ready card, only `tracing` INFO lines (98 Rhai
loader lines, on **stdout**); `aitm --version` and `aitm --help` build the whole proxy, then fail
with `` expected a command before flags, got `--version` `` + usage, exit 1; one-shot verbs run in
a fresh in-process proxy and never reach a running core. PR #271 (W1 terminal reporting) and the
`claude/cli-oneshot-live-core` PR change all of this; the acceptance pins the **required** words
from their specs and records 0.5.10's actual output as FAIL with those Explains.

| # | Who | Action | Required (spec words) | 0.5.10 actual (expected FAIL) |
|---|---|---|---|---|
| CLI-1 | auto | `aitm --version` | One line `aitm <version>`, exit 0, nothing else on either stream (AC-W1 in 2026-11-01-cli-terminal-reporting-design). | 98 INFO lines on stdout + usage on stderr, exit 1. Explains: #271. |
| CLI-2 | auto | `aitm --help` | Synopsis panel listing the 19 groups incl. `tui`, `web`, `operator-token`; exit 0. | as CLI-1. Explains: #271. |
| CLI-3 | auto (ports free) | bare `aitm`, 10 s, then `Ctrl-C` | The W1 ready card: proxy address, bus address, CA state ("CA trusted"), transport, Scope advice; log lines to the 0600 log file, not the terminal; orderly exit summary. | only tracing on stdout; no card; no CA line. Explains: #271. |
| CLI-4 | auto | `aitm proxy status` while the app's core runs | Acts on the **running** core: `listening: true`, its address, its version — or refuses with the exact panel when none runs (`no running core found` wording per the one-shot spec). | prints its own in-process `listening: false`. Explains: `claude/cli-oneshot-live-core`. |
| CLI-5 | auto | `aitm scope add --host example.com` while the app's core runs; then `scope.list` over the app's bus | The host appears in the running core's `scope.list`; audit `scope.add` with `origin: cli`. | prints `example.com`, exit 0, running core unchanged (**the false success Matt hit**). Explains: `claude/cli-oneshot-live-core`. |
| CLI-6 | auto | `aitm scope add --host example.com` with **no** core running | Refusal panel naming the fix (`aitm` to start one), exit 1; never a success line. | prints `example.com`, exit 0 (no-op). Explains: same. |
| CLI-7 | auto | `aitm ca status` | JSON with `stores.user.trusted: "yes"` on Matt's Mac; `aitm ca install` (not run; `--yes` never passed) would prompt. | PASS expected (read-only). |
| CLI-8 | auto | `aitm web` with 8082 held by another `aitm web` | `cannot start: web UI port 127.0.0.1:8082 is already in use.` + the holder sentence + `Find the holder with:  lsof -nP -iTCP:8082 -sTCP:LISTEN`, exit 1, no success line before it. | PASS expected. |

### D7. Negative paths, per surface

| # | Situation | MAC must show | TUI must show | WEB must show | CLI must show |
|---|---|---|---|---|---|
| N1 | Core restarting while the operator adds a host (Proxy ▸ Restart Core, then Add within 300 ms; capture by `screencapture -l` loop) | The pending row is cleared or the add is re-sent after the restart; if it failed, the row is **removed** and an error names it: status bar "add to scope: <bus error>" — today the row stays tertiary "pending" for ever with no page error (S-081; Explains: PR #274 / 2026-11-01-mac-bus-reconnect-ownership). | toast `bus: <why>`, pill `bus disconnected`, status `bus down · retrying`; after reconnect the add prompt still works. | dot amber; `bus token expired` latch with the tooltip above unless `AITM_WEB_TOKEN` is fixed; toast `scope: bus not connected` on an add while down. | one-shot refuses with the no-core panel (required), never a success. |
| N2 | No route: a host in Scope, system proxy off, All Apps off, Safari visits it | Flows empty state rows "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." and "All Apps off — turn it on …"; once rows exist, the banner joins the closed entries with " · " and offers one button ("Set as System Proxy" first). Zero rows is **correct** here; the words are what is judged. | pill `· sys-proxy off`; flows pane empty state. | pill `· sys-proxy off`; empty grid words. | card `Scope` line absent (host in scope) and a sys-proxy word in the W1 card (required). |
| N3 | Untrusted CA (only if Matt un-trusts it for the run — **yes**; otherwise read the words from source and mark SKIP `CA stays trusted`) | First-run row 2 and Status step "Trust the aitmproxy CA" with button of the same name; tooltip "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"; HTTPS rows show tunnel "failed" / `client_rejected_certificate`. | pill `· CA untrusted`. | pill `· CA untrusted`. | `aitm ca status` → `trusted: "no"`; W1 card "CA untrusted" (required). |
| N4 | Port held (another `aitm` on 8080) | Core lane "failed" + banner "Embedded core failed — not capturing" with "Show Log" / "Restart Core"; the log names the port. | `cannot start: proxy port 127.0.0.1:8080 is already in use.` panel before any screen. | same panel. | same panel; exit 1. |
| N5 | Wrong/absent operator token | Bus lane "bus failed" with remedy "Paste the operator token in Settings ▸ Bus, then reconnect". | `bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)`. | banner "Expected operator access, but this session connected as agent. Sensitive commands will be refused." | one-shot refusal (required). |

### D8. The report

`docs/testing/<YYYY-MM-DD>-release-acceptance-<version>/README.md`, one per release run:

1. Header: versions (app, CLI), macOS version, date, who pressed what (Matt / orchestrator window /
   harness), the D2 starting-state table, the yes-list (which `yes` steps Matt approved, verbatim).
2. One table per journey: `# | Result | Observed (quoted) | Bus truth (quoted JSON, token
   redacted) | Explains`. Screenshots and pty grids as files beside it (`MAC-08.png`,
   `TUI-05.txt`), named by step.
3. Negative paths table in the same shape.
4. Restore proof: the D2 readings taken again, diffed, `identical` or the diff.
5. Summary: counts of PASS / FAIL / SKIP / BLOCKED per journey; the release verdict
   (`blocks the tap bump` while any FAIL has no Matt-accepted disposition); the list of Explains
   with their state (open / merged, unreleased / missing feature with its card).
6. Leftovers: anything the run left on the Mac (Scope hosts, log files) for Matt to remove.

### D9. The runner (`tests/e2e/acceptance/`)

- `run.sh <version>` (bash, Terminal) is the one command. It creates
  `/tmp/claude/acceptance/<version>/`, runs `preflight.sh` (D2 readings → `state-before.txt`),
  then each journey cell in order `cli`, `mac`, `tui`, `web` (CLI first because it needs no
  display; mac before tui/web because its core holds the ports until the app quits), then
  `preflight.sh` again → `state-after.txt` and a diff, then `report.py` which writes the D8
  README skeleton with every step's result filled in and the `Observed`/`Bus truth` cells quoted.
- Cells follow the `tests/e2e` contract (exit 0/77/other; `# e2e: tier=manual` where a hand is
  needed; `AITM_E2E_MANUAL=1` lets them `pause()` for the operator). They reuse `aitm_e2e.bus`,
  `aitm_e2e.proxyutil` and the TUI pty helpers; a new `aitm_e2e/installed.py` finds the installed
  app's embedded core (bundle-path `pgrep`, `--config` → `operator_token` + `bus.endpoint`) and
  the installed CLI (`/opt/homebrew/bin/aitm`), and reads the six bus truths into one dict.
- `yes` steps are performed only when the cell is given `ACCEPT_YES=<step-ids>` listing the step
  ids Matt approved for this run (e.g. `ACCEPT_YES=MAC-6,MAC-7,MAC-14,MAC-15`); any `yes` step not
  listed is SKIP `needs Matt's yes`. The runner prints the yes-list into the report header.
- `hand` steps print the instruction and `pause()`; without `--manual` they are SKIP `needs a hand`.
- Each `yes` cell records the before-state, arms a trap that restores (system proxy: `proxy.system.unset`
  over the bus, then `networksetup -setwebproxystate <svc> off` / `-setsecurewebproxystate <svc> off`
  per service if anything we set is still on), refuses to start if the port it needs is busy, and
  diffs after. Windows are announced on stdout with timestamps.
- mac driving: `tools/acceptance/menu.sh "<Menu>" "<Item>"` (System Events, `set frontmost to true` first),
  `tools/acceptance/keypress.swift` (CGEvent, refuses unless the app is frontmost), `screencapture -l <win>`
  loop for N1. tui: `tui_pty.py` with `TIOCSWINSZ` and the grid replayer. web: Playwright Chromium
  (`apps/web/scripts/` has the CDP driver; Safari stays a hand step).
- Nothing in the runner starts a core on a non-default port, seeds Scope over the bus, or edits the
  operator's config. The only writes are the `yes` steps through the surfaces' own controls.

### D10. Ownership and cadence

- The orchestrator runs `tests/e2e/acceptance/run.sh <version>` after installing each release on
  Matt's Mac and before the tap bump; the report PR is docs-only and goes to it as `ready <sha>`.
- A FAIL with an `Explains` that is merged and in the release under test is a regression: blocks.
- A FAIL whose `Explains` is an open PR blocks until that PR is in a release or Matt writes an
  acceptance in the report ("ship 0.5.11 with CLI-5 failing; fixed in 0.5.12").
- Every release's report is kept; the summary table across releases lives in
  `docs/testing/release-acceptance-index.md` (one row per version: date, PASS/FAIL/SKIP counts,
  verdict, report link).

## Acceptance criteria

1. AC1: `docs/superpowers/specs/2026-11-01-release-acceptance-operator-journeys-design.md` (this
   file) lists, for each of MAC, TUI, WEB, CLI, every step from the operator's real starting state
   to the restored state, each with the verbatim words and the bus truth (D3–D6).
2. AC2: Every string quoted in D3–D7 exists in the source at the SHA the spec names, or is marked
   "required" with the spec that defines it; the spec-reviewer checks a sample of ten.
3. AC3: The negative paths N1–N5 are pinned per surface with words (D7); a surface that has no
   word today is marked with its Explains, never left blank.
4. AC4: The first report `docs/testing/2026-11-01-release-acceptance-0.5.10/README.md` exists in
   the D8 shape, with the D2 before-table, a result for every step (PASS/FAIL/SKIP/BLOCKED), bus
   truth quoted beside every FAIL, an Explains for every FAIL, a restore diff, and the yes-list.
5. AC5: On 0.5.10 the report records at least these as FAIL with the named Explains: CLI-1/2/3
   (#271), CLI-4/5/6 (`claude/cli-oneshot-live-core`), N1-MAC (S-081 / #274), MAC-9 proxied
   attribution (missing feature). If any of them passes on 0.5.10 the report says why (e.g. a
   PR that reached the release).
6. AC6: The runner `tests/e2e/acceptance/run.sh <version>` exists, runs the four journeys in the
   D9 order, performs no `yes` step whose id is not in `ACCEPT_YES`, prints a SKIP line with a
   reason for every unperformed step, exits non-zero iff a performed step FAILed, and writes the
   D8 README skeleton with every step's result.
7. AC7: `tests/e2e/acceptance/preflight.sh` records every D2 reading before and after; the runner
   diffs them and the diff is in the report.
8. AC8: No cell binds a non-default port for a journey core, writes Scope over the bus, edits
   `config.yaml`, or prints a token (a grep for the token value over `/tmp/claude/acceptance/`
   and the report is part of `run.sh` and fails the run on a hit).
9. AC9: Every `yes` cell records before-state, arms a restore trap, refuses to start on a busy
   port, and diffs after; `scutil --proxy` before == after is asserted by the cell itself.
10. AC10: `python3 tests/e2e/run.py --list` discovers the acceptance cells as `tier=manual`, so the
    merge gate skips them loudly and never runs a `yes` step in CI.

## Left to the builder

- File names and layout under `tests/e2e/acceptance/` beyond `run.sh`, `preflight.sh`,
  `report.py`, one cell per journey, and `aitm_e2e/installed.py`.
- Whether the mac cell drives menus via `osascript` files or a small Swift helper; both must set
  frontmost first and refuse otherwise.
- The grid replayer's exact escape coverage (`H`/`f`, `J`, `K`, `A–D`, `G`, `d`, `\r`, `\n` at
  minimum, per the TUI pty memory).
- Screenshot format and scale (the 1440×900 window at 2× is fine).
- Whether the report's cross-release index is generated by `report.py` or kept by hand.

## Open questions

Only Matt can answer these; defaults in force until he does.

1. **Which `yes` steps for the 0.5.10 run today?** Default: ask for MAC-6/7/14/15 (system proxy
   and All Apps through the app, ≤ 60 s each window) and TUI-3/7, WEB-4/7 (system proxy only);
   N3 (un-trusting the CA) is **not** requested — its words are read from source and marked SKIP.
2. **May the run quit and relaunch his app (MAC-1/MAC-16) so the TUI and web journeys get the
   default ports?** Default: ask once per run; without it TUI and WEB are SKIP `port 8080 held by
   Aitmproxy.app's embedded core` and their words are checked only as far as the ready card /
   startup (which fails on the port anyway, and that output is itself pinned as N4).
3. **Should the Scope hosts added by the run (`example.com`, `httpbin.org`) be removed at the end?**
   Default: left in place and listed under Leftovers, because removing them is a Sensitive verb on
   his core; Matt may say "remove them" and the run then does so through the same surface.
