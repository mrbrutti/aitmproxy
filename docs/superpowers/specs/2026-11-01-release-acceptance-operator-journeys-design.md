# Release acceptance: the operator's journeys on the installed build

**Status:** approved 2026-11-02 (self-approved under Matt's autonomous mode after the stage-2 spec-reviewer and quality-reviewer passes; findings and dispositions in the Review log at the end). Matt's yes is still required for every machine-state step of every run.
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
  start and end, is ≤ 20 s per system-proxy flip and ≤ 60 s in all including the probes, records
  the before-state in the same script that writes, arms an EXIT trap that **replays the recorded
  per-service before-state** (never a blanket "off"), and diffs before/after.
- **Bypass is a precondition, not a promise.** The core's `proxy.system.set` takes the bypass the
  surface passes: the mac app passes its Settings ▸ Proxy "Bypass hosts" field, the TUI and web
  pass the operator's `system_proxy.bypass` from `config.yaml`, and the runner may edit neither.
  So D2 reads both; a `yes` flip runs only when the reading contains the operator's own tooling
  (`*.anthropic.com`, `api.anthropic.com`, `claude.ai`, `*.claude.ai`, `github.com`,
  `*.githubusercontent.com`, loopback, `*.local`), and after the flip the cell asserts
  `scutil --proxy` `ExceptionsList` contains them or restores at once and records FAIL
  `bypass not applied`. Without the reading the flip is SKIP `bypass list absent in <where>`; the
  report asks Matt to add it through the surface's own Settings.
- **Secrets.** The operator token, the agent token, the web UI bearer value (`#t=…`),
  `AITM_WEB_TOKEN`, and the embedded core's `operator_token` line are secrets. The report quotes
  the web card as `#t=<redacted>`; D2 extracts the `scope:` and `system_proxy:` blocks of
  `config.yaml` and never copies the file; `run.sh` greps the run folder and the report for every
  secret value it knows and fails the run on a hit.
- **Read-only probes** (`scutil --proxy`, `networksetup -getwebproxy <svc>`,
  `security find-certificate -a -c aitmproxy`, `systemextensionsctl list`, `lsof`, reading the
  data dir and the embedded core's per-launch config) need no yes and run before and after every
  journey. The sandboxed Bash sees an empty `scutil --proxy` dictionary and cannot `ps`/`pgrep`;
  probes run from the Terminal panel. The `pgrep` probes are read-only and target the installed
  bundle path; no probe ever feeds a `kill` (sibling sessions run dev bundles on this Mac).
- **Bus truth** is read over the real operator bus: the embedded core's `bus.endpoint` +
  `operator_token` from its per-launch `$(getconf DARWIN_USER_TEMP_DIR)/aitm-embedded-core/<uuid>/config.yaml`
  (identify the child by its own command line, never "the newest config in the temp dir"), or
  `--bus-endpoint-file` + the config's `mcp.operator_token` for a terminal core. The client is
  `tests/e2e/aitm_e2e/bus.py` (token line, then newline-delimited JSON-RPC). The token is read
  into a variable and never echoed.
- **Driving the UIs:** the mac app through System Events menu presses, keystrokes and clicks
  while it is frontmost (probe focus with one harmless character first; `pbcopy`+⌘V for text the
  keyboard cannot type; `screencapture -l <win>` in a background loop for transient states), the
  TUI through a Python pty with `TIOCSWINSZ` set before the first read and the cell-diff stream
  replayed into a grid, the web UI through a real browser (Safari or Chrome by hand; Google Chrome
  over CDP when automated). Never AppleScript `keystroke` without `set frontmost to true`. Window
  frames for N1 come from `screencapture -x -o -R <window bounds>` (bounds read through
  accessibility; System Events exposes no CGWindowID).
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
- **Result** per step: `PASS` (words and bus truth both as specified; where a surface has no
  bus of its own the PASS line names the observer used: `PASS (bus truth: audit only)`), `FAIL`
  (either differs; the report quotes both), `SKIP <reason>` (not performed: no window, no yes,
  port held, missing dependency, or not applicable on this surface), `BLOCKED <step>` (a step
  this one depends on FAILed, was SKIPped or BLOCKED, so this one cannot be judged). Dependencies:
  MAC-8 ← MAC-5 and (MAC-6 or MAC-7); MAC-9a ← MAC-7 and MAC-8; MAC-9b ← MAC-6 and MAC-8;
  MAC-10/11/12 ← MAC-8; MAC-14 ← MAC-7; MAC-15 ← MAC-6; TUI-4/5 ← TUI-2 and TUI-3; TUI-7 ← TUI-3;
  WEB-5/6 ← WEB-3 and WEB-4; WEB-7 ← WEB-4; CLI-4/5/N4 ← a running core; CLI-3/6/8 ← free ports;
  CLI-10 ← MAC-8. Neither `SKIP` nor `BLOCKED` is ever counted as green. A sixth result, `N/A`,
  marks a step that does not exist on that surface or build (TUI-9/10, WEB-9/10, N1-TUI, N1-WEB,
  N5-CLI); it is listed, never performed, and does not hold the verdict at `incomplete`.
- **Run verdict**: `pass` (every step PASS or N/A with at least one performed PASS, or FAIL with Matt's written acceptance), `fail`
  (a performed step FAILed without one), `incomplete` (no FAIL, but a step is SKIP or BLOCKED for
  want of a yes, a hand or a free port), `error` (a cell crashed or was killed by the watchdog; the
  machine state is re-read and restored regardless). Only `pass` clears the tap bump; `run.sh`
  exits 0 / 1 / 77 / 2.
- **Bus truth**: the six readings taken beside every step that changes state and at every FAIL:
  `scope.list`, `proxy.status`, `capture.status`, `proxy.system.status`, `flow.table`, and the
  tail of the durable audit (`<data dir>/audit.jsonl`, plus `audit.agent.jsonl`; CA actions in
  `<data dir>/ca-audit.jsonl`). The audit files are shared by every core on the default data dir,
  sibling sessions' dev cores included: entries are matched by `pid`/`connection_id`, never "the
  tail is this core's".
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
| Data dir | `ls -la ~/Library/Application\ Support/aitmproxy/`; the `scope:` and `system_proxy:` blocks of `config.yaml` (never the whole file); `system-proxy-state.json` present? | persisted scope, bypass list, watchdog state |
| Bypass (mac) | `defaults read com.mrbrutti.aitmproxy` Settings ▸ Proxy "Bypass hosts" key | the precondition for MAC-6 |
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
| MAC-0 | **yes** (changes the Mac; only on a release run) | `brew upgrade --cask aitmproxy` (and `brew upgrade aitm` for CLI-0); relaunch | Versions read back equal the release; after launch: Scope list unchanged from D2, CA trust unchanged, no stale `system-proxy-state.json` left claiming a proxy we no longer set, the extension re-approval prompt (if any) is worded as MAC-7's "waiting for approval" step. | `proxy.status.version` == the release; `scope.list` == D2; `ca.status` == D2; `proxy.system.status.managed_by_us == false`. |
| MAC-1 | hand/yes if the app is not running | Launch `/Applications/Aitmproxy.app` from Finder or `open -a Aitmproxy` (Terminal). If already running: record and continue. | Status lane cards: Core "running"; Bus lane word "connected" with detail "operator · <bus address>" (the word "connected as <role>" is the role-**warning** lane, with remedy "Paste the operator token in Settings ▸ Bus, then reconnect" — a FAIL here). No red banner. | `proxy.status.listening == true`, `address` = the config's listen, `version` = the installed version. Audit `start` marker with that `version`. |
| MAC-2 | auto (read) | First-run sheet, if shown | Title "Set up aitmproxy on this Mac". Row 1 "Set aitmproxy as the system proxy" with the route line (MAC-6 words) and button "Set as System Proxy". Row 2 "Trust the aitmproxy CA" whose fact is **read back from the keychain**: "CA trusted (user keychain)" on Matt's Mac today; "HTTPS is not captured until the CA is trusted" when not trusted, with the button "Trust the aitmproxy CA". Row 3 caption "Nothing is decrypted until a host is in Scope" with "Open Scope…". Footer "Not Now" (or "Done" when all three are done). If the sheet is not shown (already dismissed with "Don't ask again", or every row done) the report says which. | `ca.status.stores.user.trusted == "yes"` must agree with row 2; `proxy.system.status.state` with row 1; `scope.list` with row 3. |
| MAC-3 | auto | Proxy ▸ Status (⌘0) | "Getting started" list in the order Core, Bus, System proxy, All Apps, Scope, CA, First flow. With nothing routed and an empty Scope: "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." (button "Set as System Proxy"); "All Apps off — turn it on to capture every app's traffic (macOS asks you to approve its extension)" (button "Capture All Apps"); "Add a host to Scope (for now as example.com:443)" (button "Open Scope…"); CA step omitted or done when trusted; "Set aitmproxy as the system proxy, or open the browser". | `proxy.system.status.state == "off"`, `capture.status.enabled == false`, `scope.list == []`, `proxy.status.decrypt.advice == "Nothing is decrypted until a host is in Scope."` |
| MAC-4 | auto | Flows page, empty | "No flows yet" with one row per closed route carrying the full line and its button(s) (the MAC-3 words). | `flow.table.flows == []` |
| MAC-5 | auto | Proxy ▸ Scope… (⇧⌘O), then on the page the Edit Scope sheet: type `example.com:80` (then `httpbin.org:443`) into the field with placeholder "host:443 or host:80 (for now), host:port or *.wildcard:port", press "Add" (⌘⏎) | The host appears as a normal row (not tertiary "pending") within one poll (≤ 2 s). Status bar shows no "add to scope:" error. Overview/sidebar Scope count rises. | `scope.list` contains the entry; audit has one `scope.add` with `origin: operator`, `result: "ok"`. Persisted: after MAC-13's restart, `scope.list` still contains it (spec 2026-10-31-macos-scope-persistence). |
| MAC-6 | **yes** (precondition: the Settings ▸ Proxy "Bypass hosts" key is set and carries the operator's tooling; an unset key means the app would pass its own default, which the run cannot read back, so the step is SKIP `bypass list absent in the app's Settings` until Matt saves the field once) | Proxy ▸ "Set as System Proxy" (⌥⌘P) — or the first-run row 1 / Status button | Status step becomes "system proxy on · 127.0.0.1:8080"; menu item title flips to "Restore System Proxy"; Flows banner no longer names the system proxy. `scutil --proxy` shows `HTTPEnable 1`, `HTTPSEnable 1`, `HTTPProxy 127.0.0.1`, `HTTPPort 8080` and the bypass list. | `proxy.system.status` = `{state: "points_at_us", managed_by_us: true}`; `proxy.status.system_proxy.state == "points_at_us"`; audit `proxy.system.set` ok; `system-proxy-state.json` written (0600). |
| MAC-7 | **yes** | Proxy ▸ "Capture All Apps" (⌃⌘A) | Status All Apps step "All Apps is on"; lane card "on" (or "on, nothing in scope" before MAC-5). If macOS asks: "All Apps waiting for approval — approve the extension in System Settings" and the Apps empty state "Waiting for approval". | `capture.status` = `{enabled: true, feeder.state: "listening", provider.state: "attached"}`; `systemextensionsctl list` shows `[activated enabled]`. |
| MAC-8 | hand | In Safari (or Chrome), open `http://example.com/` then `https://httpbin.org/get` | Flows rows: `GET http://example.com/ 200` and `GET https://httpbin.org/get 200` with tunnel "decrypted" (not "passthrough"); a `CONNECT` row for httpbin. Sidebar Flows/Domains counts rise. No banner about the CA. | `flow.table` rows with `authority` = the hosts, `status 200`, `tunnel == "decrypted"`, `tunnel_reason == null`; a row from the extension carries `capture_interface == "macos-ne"` and a `source_app`; a proxied row carries `source_app == null`. |
| MAC-9a | auto (depends on MAC-7) | Apps sidebar, extension-captured flows | A group for the browser with its flow count. The group name for Safari's `com.apple.WebKit.Networking` is **"WebKit Networking"** at `c65ed0f2` (`AppIdentifier.knownUnbundled`, "a shared service is never a host app"); the flow row's client label for the same id is "Safari" (`ClientInfo.knownSourceApps`). The two Kit tables disagree; the acceptance quotes both and the mac-app-icons-and-names spec decides which wins. Chrome shows "Google Chrome". | `flow.table`: `source_app` non-null and `capture_interface == "macos-ne"` for those rows. |
| MAC-9b | auto (depends on MAC-6) | Apps sidebar, proxied flows (system proxy only, All Apps off or Scope empty for the extension) | **Required:** the proxied flow is attributed to its client app and grouped. **0.5.10:** no app is shown and the table has an empty client column; the empty state "No app attribution yet" appears only when there are no flows at all. Expected FAIL on 0.5.10 (Matt's "NOTHING is there"); Explains: missing feature, session core-name-the-client-app. | `flow.table` rows: `source_app == null` on every proxied row. |
| MAC-10 | auto | Flow ▸ "Arm Intercept" (`i`) with the flow list focused; reload `http://example.com/` in the browser | Intercept bar "Intercept armed — every request pauses here" then "1 paused" beside the target text `"\(method) \(url)"` (`InterceptBar.targetText`, plus " · N edits pending" when edits exist), i.e. `1 paused` / `GET http://example.com/`; buttons "Resume"/"Apply & Resume", "Edit", "Resume All", Kill menu, "Rules…", "Disarm". Toolbar " · intercept armed". The browser tab spins. | `proxy.status.intercept_armed == true`; `flow.table` row `state == "intercepted"`, `status == null`; `proxy.status.paused == 1`. |
| MAC-11 | auto | "Resume" (⌘⏎) | Row shows `200`; bar back to "Intercept armed — every request pauses here"; the browser page loads. | row `state == "resumed"`, `status 200`; audit `flow.resume` ok. |
| MAC-12 | auto | Flow ▸ "Disarm Intercept" (`i`) | Bar gone; toolbar without "intercept armed". | `intercept_armed == false`. |
| MAC-13 | auto | Proxy ▸ "Restart Core" (⌃⇧⌘R) | Core lane "starting…" then "running"; Bus lane "connected" / "operator · <bus address>"; **no** stale "Embedded core failed — not capturing" banner once the core is back; the Scope rows are still listed (persisted and re-pushed); the system proxy is still "on · 127.0.0.1:8080" (or restored and re-set, both acceptable; the report says which). Every verb works after the restart (spec 2026-11-01-mac-bus-reconnect-ownership). | New `start` audit marker; `scope.list` unchanged; `proxy.system.status.state == "points_at_us"`; `proxy.status` answers. |
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
| TUI-1 | auto (pty, 180×45) | `aitm tui` | Alternate screen drawn (a 0×0 pty draws nothing — set `TIOCSWINSZ` first). Toolbar pill `● aitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trusted`; status bar `bus … · operator`; flows pane "No flows yet — point a client at 127.0.0.1:8080 or open the browser."; toast "embedded proxy · set RUST_LOG to write a log file" (or the log path). | `aitm tui` on 0.5.10 uses the in-process transport and serves no loopback bus, so the independent observer for every TUI step is the **durable audit** (`audit.jsonl` entries from this pid: the `start` marker, then each verb) plus `scutil`/the real client; TUI results read `PASS (bus truth: audit only)`. `proxy.status` over a bus is SKIP `aitm tui serves no loopback bus on 0.5.10` (Explains: `claude/cli-oneshot-live-core`, operator bus default-on). |
| TUI-2 | auto | `S` (Scope), `a`, type `example.com`, Enter | Prompt `scope add:` with hint `host · host:port · *.wildcard — a human action`; toast `Scope + example.com`; panel lists the host; status bar ` · 1 in scope`. Before: ` Scope is empty — every flow is dimmed and read-only. Press a to add a host.` | audit `scope.add` ok (origin operator). |
| TUI-3 | **yes** | `s` (system proxy toggle) | Pill `· sys-proxy setting…` then `· sys-proxy → us` (the §D12 pill word). `scutil --proxy` points at 127.0.0.1:8080. | audit `proxy.system.set` ok; state file written. |
| TUI-4 | hand | Safari visits `http://example.com/` and `https://httpbin.org/get` | Two rows in the flows pane with `200`, drawn as normal (in-scope) rows, not dimmed; the httpbin row is the decrypted `GET`, not only a `CONNECT`; status bar row count rises. | the real client got 200 through the proxy; audit shows no error; the pane shows `GET example.com /` and `GET httpbin.org /get` (a `CONNECT`-only row for httpbin = FAIL: passthrough, not decrypted). |
| TUI-5 | auto | `i`, Safari reload of example.com, `a` (resume), `i` | ` ⏸ Intercept armed — every request pauses here` → ` ⏸ 1 paused  GET http://example.com/` with `[a Resume] [A Resume all] [d Kill · abort mode: reset (429/503 need F3)] [e Edit] [i Disarm]` → toast `Resumed` → toast `Intercept disarmed`. | — |
| TUI-6 | auto | Open the CA panel, press `i` (install), then `n` | Prompt ` confirm: ca.install — … [y/N] `, hint `y runs it · n / Esc cancels`; `n` → toast `CA trust cancelled`. (PR #263 fixes the over-the-wire `_confirm` prune for `l4.*`; the acceptance pins only the local confirm on this release and records #263 under Explains.) | no `ca.install` in `<data dir>/ca-audit.jsonl` from this run. |
| TUI-7 | **yes** | `s` again | Pill `· sys-proxy setting…` then `· sys-proxy off` (or the previous owner `· sys-proxy → 127.0.0.1:9090`). `scutil --proxy` equals the D2 reading. | audit `proxy.system.unset` ok. |
| TUI-8 | auto | `q` | Exit 0; the terminal restored (no alternate screen left); no `aitm` child remains (`pgrep` exit 1 = none; amended 2026-11-02: the cell once read `sh()`'s `[stderr]` marker for that exit as a leftover); `scutil --proxy` unchanged. | audit: the process's last entries, no `proxy.system.set` left unmatched by an `unset`. |
| TUI-9 | n/a | Capture All Apps | SKIP `no All Apps control on this surface` (the extension is the mac app's; Explains: UIs pending for per-host decryption / capture, memory aitmproxy-per-host-decryption-decision). | — |
| TUI-10 | n/a | Apps view | SKIP `no Apps view on this surface` on 0.5.10 (the sidebar lists "Apps" but groups only extension-attributed flows; none exist without the mac app). | — |

### D5. Journey WEB — `aitm web` in a real browser

| # | Who | Action | The surface must show | Bus truth |
|---|---|---|---|---|
| WEB-1 | auto | `aitm web` in the Terminal (ports free, else SKIP naming the holder) | The ready card **on stderr** (wave 1 G1/D13: every human line is on stderr, stdout stays free; amended 2026-11-02 — the cell runs `aitm web` over pipes, so it sees the plain `Label: value` form: no pill line, no rules; on a TTY wave 1's rich form is the `● aitmproxy · listening …` pill line plus 14-column rows — 0.5.10's two 60-char rules are gone): `Web UI     http://127.0.0.1:8082/#t=<redacted>`; `Operator   http://127.0.0.1:8082/#t=<redacted>&expect=operator` **only if** `mcp.operator_token` is set in the operator's config (the report says whether it was; if absent the operator journey is BLOCKED and Explains = "operator-token generate is a manual step on 0.5.10"); `Proxy      127.0.0.1:8080`; `Browser    127.0.0.1:8081  (SSRF-filtered)`; `Bus        ready`; `Scope      Nothing is decrypted until a host is in Scope.` while Scope is empty. Nothing from the Rhai loader on stdout. | `/healthz` → `{"ok":true}`. |
| WEB-2 | hand (Safari/Chrome) or auto (Playwright Chromium) | Open the Operator URL | Banner "Operator session — sensitive commands are enabled."; toolbar pill `aitmproxy · listening 127.0.0.1:8080 · sys-proxy off · CA trusted`; status bar `bus 127.0.0.1:8082` with tooltip `bus open`; flows grid "No flows yet — point a client at 127.0.0.1:8080 or open the browser." | — |
| WEB-3 | auto | Sidebar "Scope" → input `Add host to scope`, type `example.com`, Enter | Row in table "Hosts in scope"; status bar `1 host in scope`; no toast `scope: …`. Before: "No hosts in scope — add the hosts you are authorised to test." | `scope.list` contains it (read over the web `/bus` as operator or the loopback bus if configured). |
| WEB-4 | **yes** | Toolbar pill menu → "Set as system proxy" | Pill `· sys-proxy setting…` → `· sys-proxy → us`. `scutil --proxy` points at us. | `proxy.system.set` audit ok. |
| WEB-5 | hand | A second real browser (Safari) visits `http://example.com/` and `https://httpbin.org/get` | Rows in the Flows grid with `200`, the httpbin row a decrypted `GET` (tunnel column "decrypted", not "passthrough"); Domains count rises. (The web UI's own tab is on loopback 8082 and bypasses the proxy; the visited pages must come from another tab/browser.) | over the web `/bus` as operator: `flow.table` rows for both hosts, `status 200`, `tunnel == "decrypted"`, `tunnel_reason == null`. |
| WEB-6a | auto | `i` (arm) | "Intercept armed — every request pauses here", buttons `Disarm` and `Rules…`. | `proxy.status.intercept_armed == true`. |
| WEB-6b | auto | reload example.com in Safari | "1 paused", the row shows `Paused`; `Resume`/`Apply & Resume` enabled. | `flow.table` row `state == "intercepted"`, `proxy.status.paused == 1`. |
| WEB-6c | auto | "Resume" (⌘⏎) | row `200`; bar back to "Intercept armed — every request pauses here". | row `state == "resumed"`, `status 200`. |
| WEB-6d | auto | "Disarm" | bar gone. | `intercept_armed == false`. |
| WEB-7 | **yes** | Pill menu → restore (the same item, now reading the restore state) | Pill `· sys-proxy off` (or previous owner). `scutil --proxy` equals D2. | `proxy.system.unset` ok. |
| WEB-8 | auto | `Ctrl-C` in the Terminal | Exit, ports released, system proxy unchanged. Core restart while the tab is open (negative N1 below): the status dot goes amber and the tab latches `bus token expired` with tooltip `token expired — reopen the URL printed by \`aitm web\`` unless `AITM_WEB_TOKEN` is fixed. | `lsof` shows 8080/8081/8082 free; `scutil --proxy` == D2; audit: no `proxy.system.set` left unmatched. |
| WEB-9 | n/a | Capture All Apps | SKIP `no All Apps control on this surface` (same Explains as TUI-9). | — |
| WEB-10 | n/a | Apps view | SKIP `no Apps view on this surface` on 0.5.10. | — |

### D6. Journey CLI — startup card and one-shot verbs

Surface facts on 0.5.10 (amended 2026-11-02 for 0.5.13+: wave 1's card is on **stderr**, stdout empty; the cells read it there): bare `aitm` prints **no** ready card, only `tracing` INFO lines (98 Rhai
loader lines, on **stdout**); `aitm --version` and `aitm --help` build the whole proxy, then fail
with `` expected a command before flags, got `--version` `` + usage, exit 1; one-shot verbs run in
a fresh in-process proxy and never reach a running core. PR #271 (W1 terminal reporting) and the
`claude/cli-oneshot-live-core` PR change all of this; the acceptance pins the **required** words
from their specs and records 0.5.10's actual output as FAIL with those Explains. The CLI journey
has two preconditions, so it runs as two cells: `cli-livecore` (CLI-4, CLI-5, CLI-7, CLI-9, CLI-10,
N4-CLI) while the app's embedded core holds 8080, and `cli-nocore` (CLI-1, CLI-2, CLI-3, CLI-6,
CLI-8) when the default ports are free (after MAC-16 / TUI-8 / WEB-8).

| # | Who | Action | Required (spec words) | 0.5.10 actual (expected FAIL) |
|---|---|---|---|---|
| CLI-1 | auto | `aitm --version` | One line `aitm <version>`, exit 0, nothing else on either stream (AC-W1 in 2026-11-01-cli-terminal-reporting-design). | 98 INFO lines on stdout + usage on stderr, exit 1. Explains: #271. |
| CLI-2 | auto | `aitm --help` | Synopsis panel listing the 19 groups incl. `tui`, `web`, `operator-token`; exit 0. | as CLI-1. Explains: #271. |
| CLI-3 | auto (ports free) | bare `aitm`, 10 s, then `Ctrl-C` | The W1 ready card **on stderr**, plain form on the cell's pipe (`Proxy: …`, `Bus: …`, `Scope: …`; the CA word reaches stderr as the `CA trusted` phase line, or as the `CA: untrusted · aitm ca install` row — the card prints a CA row only when untrusted); **stdout empty** — bare `aitm`'s stdout is the stdio MCP transport's JSON-RPC channel (wave 1 G1/D13; amended 2026-11-02); log lines to the 0600 log file, not the terminal; orderly exit summary. | only tracing on stdout; no card; no CA line. Explains: #271. |
| CLI-4 | auto | `aitm proxy status` while the app's core runs | Acts on the **running** core: `listening: true`, its address, its version — or refuses with the exact panel when none runs (`no running core found` wording per the one-shot spec). | prints its own in-process `listening: false`. Explains: `claude/cli-oneshot-live-core`. |
| CLI-5 | auto | `aitm scope add --host example.com` while the app's core runs; then `scope.list` over the app's bus | The host appears in the running core's `scope.list`; audit `scope.add` with `origin: cli`. | prints `example.com`, exit 0, running core unchanged (**the false success Matt hit**). Explains: `claude/cli-oneshot-live-core`. |
| CLI-6 | auto | `aitm scope add --host example.com` with **no** core running | Refusal panel naming the fix (`aitm` to start one), exit 1; never a success line. | prints `example.com`, exit 0 (no-op). Explains: same. |
| CLI-7 | auto | `aitm ca status` | JSON with `stores.user.trusted: "yes"` on Matt's Mac; `aitm ca install` (not run; `--yes` never passed) would prompt. | PASS expected (read-only). |
| CLI-8 | auto (ports free) | `aitm web` with 8082 held by a **plain listener** (`python3 -m http.server 8082 --bind 127.0.0.1`; another `aitm web` would hold 8080 first and the proxy-port panel would be reached instead) | Wave 1's M2 panel for the web UI port (amended 2026-11-02 with row N4; the previous literals were 0.5.10's): `cannot start: the web UI port 127.0.0.1:8082 is already in use` (no trailing period) + `It is most likely held by another running \`aitm\`, the aitmproxy macOS app's embedded core, or another program.` + the remedy line + the holder command as the fix line — `fix: lsof -nP -iTCP:8082 -sTCP:LISTEN` on a pipe, `▸ lsof -nP -iTCP:8082 -sTCP:LISTEN` on a TTY — on stderr, exit 1, no success line before it. The plain listener is the one socket the harness opens on a default port; it is not a core. | PASS expected. |
| CLI-0 | **yes** (release run only) | `brew upgrade aitm`; `aitm --version` | the new version on one line | `proxy.status.version` of the next core started equals it. |
| CLI-9 | **yes** | `aitm proxy system status` (read, always), then `set`, then `unset` against the running core; `unset` is not run when `set` refused honestly (nothing was set) | `status` describes the running core's view (`state`, `managed_by_us`); `set` either acts on the running core (`scutil --proxy` points at 127.0.0.1:8080 with the bypass list) or refuses with the no-core / needs-running-core sentence (`proxy.system.set needs a running core: use the app, the TUI or the web UI, or start aitm with \`system_proxy.auto: true\`` is 0.5.10's one-shot refusal and is honest); `unset` restores the D2 state byte for byte. Never a success line while `scutil` is unchanged. | `proxy.system.status` over the bus before/after each; audit `proxy.system.set`/`unset` with `origin: cli`. 0.5.10: `set` refuses (honest), `unset` "works" in-process (restores nothing if nothing was set) — Explains for the live-core requirement: `claude/cli-oneshot-live-core`. |
| CLI-10 | auto (after MAC-8) | `aitm flow list` / `aitm flow table` against the running core | the running core's rows (the MAC-8 hosts) | `flow.table` over the bus has the same ids. 0.5.10: prints `[]` from its own in-process core — expected FAIL, Explains `claude/cli-oneshot-live-core`. |

### D7. Negative paths, per surface

| # | Situation | MAC must show | TUI must show | WEB must show | CLI must show |
|---|---|---|---|---|---|
| N1 | Core restarting while the operator adds a host (Proxy ▸ Restart Core, then Add within 300 ms; capture by `screencapture -l` loop) | The pending row is cleared or the add is re-sent after the restart; if it failed, the row is **removed** and an error names it: status bar "add to scope: <bus error>" — today the row stays tertiary "pending" for ever with no page error (S-081; Explains: PR #274 / 2026-11-01-mac-bus-reconnect-ownership). | toast `bus: <why>`, pill `bus disconnected`, status `bus down · retrying`; after reconnect the add prompt still works. | dot amber; `bus token expired` latch with the tooltip above unless `AITM_WEB_TOKEN` is fixed; toast `scope: bus not connected` on an add while down. | one-shot refuses with the no-core panel (required), never a success. |
| N2 | No route: a host in Scope, system proxy off, All Apps off, Safari visits it | Flows empty state rows "system proxy off — Set as System Proxy so Safari and other proxy-aware apps use the core." and "All Apps off — turn it on …"; once rows exist, the banner joins the closed entries with " · " and offers one button ("Set as System Proxy" first). Zero rows is **correct** here; the words are what is judged. | pill `· sys-proxy off`; flows pane empty state. | pill `· sys-proxy off`; empty grid words. | card `Scope` line absent (host in scope) and a sys-proxy word in the W1 card (required). |
| N3 | Untrusted CA (only if Matt un-trusts it for the run — **yes**; otherwise read the words from source and mark SKIP `CA stays trusted`) | First-run row 2 and Status step "Trust the aitmproxy CA" with button of the same name; tooltip "HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then"; HTTPS rows show tunnel "failed" / `client_rejected_certificate`. | pill `· CA untrusted`. | pill `· CA untrusted`. | `aitm ca status` → `trusted: "no"`; W1 card "CA untrusted" (required). |
| N4 | Port held (the app's embedded core on 8080, or a plain listener for the mac case) | Core lane "failed" + banner "Embedded core failed — not capturing" with "Show Log" / "Restart Core"; the log names the port. | Wave 1's M2 panel (amended 2026-11-02 for 0.5.13+; the previous cell literals were 0.5.10's): `cannot start: the proxy port 127.0.0.1:8080 is already in use` (no trailing period) + `It is most likely held by another running \`aitm\`, the aitmproxy macOS app's embedded core, or another program.` + `Free it, or set \`listen:\` to another address in <config path>.` + the holder command as the panel's fix line — `fix: lsof -nP -iTCP:8080 -sTCP:LISTEN` on a pipe, `▸ lsof -nP -iTCP:8080 -sTCP:LISTEN` on a TTY, where the why sentences wrap at the terminal's width (80 in M2's drawing) — on stderr, before any screen; exit 1. | same panel. | same panel; exit 1. |
| N5 | Wrong/absent operator token | Bus lane "bus failed" with remedy "Paste the operator token in Settings ▸ Bus, then reconnect". | `bus refused the token: it matched neither the agent nor the operator token (check the token you supplied)`. | banner "Expected operator access, but this session connected as agent. Sensitive commands will be refused." | one-shot refusal (required). |

Where each negative is observed (its cell):

| # | Cell / when | Who |
|---|---|---|
| N1 | `mac`, between MAC-5 and MAC-13 (Restart Core, then the Add pasted right after a one-digit focus re-probe, so it lands while the core is down — within ~1 s of the press; `screencapture -R <window bounds>` loop at ~4 fps started just before); `web` WEB-8 note; TUI N1 is the app's restart seen from `aitm-tui --bus` only, SKIP on 0.5.10 (`aitm tui` owns its core) | auto |
| N2 | falls out of MAC-5 before MAC-6/7, TUI-2 before TUI-3, WEB-3 before WEB-4: the words are read at that moment | auto |
| N3 | words read from source; SKIP `CA stays trusted` unless Matt asks for the un-trust (`yes`) | yes |
| N4 | `cli-livecore` (N4-CLI) and the `tui`/`web` start while the app holds 8080; mac case needs a plain 8080 listener before launch (`yes`: it blocks his app's core) | auto / yes |
| N5 | `n5` cell: `aitm-tui --bus <app bus> --token-file <wrong>` (N5-TUI) and the `aitm tui`/`aitm web` startup refusals on the held port (N4-TUI, N4-WEB); N5-WEB in the `web` cell after WEB-7 (a tab opened with the agent token and `&expect=operator`: it needs `aitm web` up, which the `n5` cell cannot have while the app holds 8080); N5-MAC the Settings ▸ Bus field (hand); N5-CLI is CLI-6's refusal (N/A) | auto / hand |

### D8. The report

`docs/testing/<YYYY-MM-DD>-release-acceptance-<version>/README.md`, one per release run:

1. Header: versions (app, CLI), macOS version, date, who pressed what (Matt / orchestrator window /
   harness), the D2 starting-state table, the yes-list (which `yes` steps Matt approved, verbatim).
2. One table per journey: `# | Result | Observed (quoted) | Bus truth (quoted JSON, token
   redacted) | Explains`. Pty grids and quoted text as files beside it (`TUI-05.txt`), named by
   step. Screenshots stay under `/tmp/claude/acceptance/<version>/` (or a release asset); at most
   one downscaled PNG per journey is committed.
3. Negative paths table in the same shape.
4. Restore proof: the D2 readings taken again, diffed, `identical` or the diff.
5. Summary: counts of PASS / FAIL / SKIP / BLOCKED per journey; the release verdict
   (`blocks the tap bump` while any FAIL has no Matt-accepted disposition); the list of Explains
   with their state (open / merged, unreleased / missing feature with its card).
6. Leftovers: anything the run left on the Mac (Scope hosts, log files) for Matt to remove.

### D9. The runner (`tests/e2e/acceptance/`)

- Layout: the cells are `tests/e2e/acceptance/test_<journey>.py` tagged `# e2e: tier=manual`
  (so `run.py --list` shows them and the merge gate skips them loudly); the runner and every
  helper live in `tests/e2e/acceptance/lib/` (`run.sh`, `preflight.sh`, `cli_journey.sh`,
  `bus_truth.py`, `report.py`, the mac menu/keypress helpers, the pty grid replayer), which
  `run.py` never walks. The cells are driven by `run.sh`, not by `run.py`; they never read
  `AITM_BIN`, and `run.sh` unsets `AITM_AUDIT_LOG` so a journey core keeps its durable audit (the
  TUI's only observer). Shared code goes to `aitm_e2e/installed.py` (find the installed app's
  core by its command line; read the six truths; redact).
- `lib/run.sh <version>` (bash, Terminal) is the one command. It creates
  `/tmp/claude/acceptance/<version>/`, runs `preflight.sh` (D2 readings → `state-before.txt`) and
  `bus_truth.py --embedded`, then the cells in order `cli-livecore`, `mac`, `tui`, `web`,
  `cli-nocore` (the live-core half first because the app usually runs; the no-core half last,
  after the app has quit and the ports are free), then `preflight.sh` again → `state-after.txt`
  and a diff, the secret grep, then `report.py`, which writes the D8 README skeleton from each
  cell's `<journey>-steps.tsv` (`id · result · observed · bus truth · explains`).
- Cells follow the `tests/e2e` contract (exit 0/77/other; `# e2e: tier=manual` where a hand is
  needed; `AITM_E2E_MANUAL=1` lets them `pause()` for the operator). They reuse `aitm_e2e.bus`,
  `aitm_e2e.proxyutil` and the TUI pty helpers; a new `aitm_e2e/installed.py` finds the installed
  app's embedded core (bundle-path `pgrep`, `--config` → `operator_token` + `bus.endpoint`) and
  the installed CLI (`/opt/homebrew/bin/aitm`), and reads the six bus truths into one dict.
- `yes` steps are performed only when the cell is given `ACCEPT_YES=<step-ids>` listing the step
  ids Matt approved for this run (e.g. `ACCEPT_YES=MAC-6,MAC-7,MAC-14,MAC-15`); any `yes` step not
  listed is SKIP `needs Matt's yes`. The runner prints the yes-list into the report header.
- `hand` steps print the instruction and `pause()`; without `--manual` they are SKIP `needs a hand`.
- Each `yes` cell records the before-state, arms a trap that restores by **replaying the recorded
  per-service state** (first `proxy.system.unset` over the bus; if `scutil --proxy` still differs
  from D2, `networksetup -setwebproxy <svc> <host> <port>` / `-setsecurewebproxy …` and
  `-set(secure)webproxystate <svc> on|off` exactly as recorded for `Wi-Fi` and `Display Ethernet`),
  checks the bypass precondition before writing (CLI-9 included), and diffs after. Start steps
  (TUI-1, WEB-1, CLI-3) refuse when any of 8080/8081/8082 is busy; MAC `yes` steps require that the holder of 8080 is the
  app's embedded core (bundle-path `pgrep`). Windows are announced on stdout with timestamps.
- mac driving: `lib/menu.sh "<Menu>" "<Item>"` (System Events, `set frontmost to true` first),
  `lib/type.sh` (pbcopy + ⌘V, probe first), `lib/click.sh "<description>" ["<identifier>"]` (locates
  the text field through accessibility right before EACH of two clicks 0.9 s apart, frontmost first,
  and refuses if the field is gone or moved — no stale coordinates) used on the Edit Scope field
  before the focus probe — the sheet does not focus its field when Scope already has hosts (run 5,
  MAC-5); the field is located by accessibility identifier when the app exposes one (`scope-add-host`
  once the mac fix lands), else by its description "Host to add to scope"; `screencapture -R` loop
  for N1. tui: `aitm_e2e/tui_pty.py` (extracted from `tests/e2e/tui/test_tui_flows_render.py`:
  `TIOCSWINSZ` and the grid replayer; a plan task, not an existing module). web: Playwright
  Chromium (`apps/web/scripts/` has the CDP driver; Safari stays a hand step).
- Nothing in the runner starts a core on a non-default port, seeds Scope over the bus, or edits the
  operator's config. The only writes are the `yes` steps through the surfaces' own controls.
- Pointer files (`claude/cli-oneshot-live-core`, after #271): every serving `aitm` writes
  `<data dir>/run/cores/<pid>.json` (0600, no token) and a serving first run mints
  `mcp.operator_token` into the config. The runner does **not** set `AITM_RUN_DIR`: the journey
  cores are the operator's own (`aitm tui`, `aitm web` on his config), their pointers are the real
  behaviour, and a one-shot must find them. D2 lists `run/cores/` before and after; a pointer left
  behind by a journey core after a clean exit is a FAIL of that journey's stop step.

### D10. Ownership and cadence

- The orchestrator runs `tests/e2e/acceptance/run.sh <version>` after installing each release on
  Matt's Mac and before the tap bump; the report PR is docs-only and goes to it as `ready <sha>`.
- The tap bump needs the run verdict `pass`. `incomplete` (SKIP/BLOCKED steps for want of a yes,
  a hand or free ports) does not clear it: the missing steps are run, or Matt accepts the gap in
  writing in the report.
- A FAIL with an `Explains` that is merged and in the release under test is a regression: blocks.
- A FAIL whose `Explains` is an open PR blocks until that PR is in a release or Matt writes an
  acceptance in the report ("ship 0.5.11 with CLI-5 failing; fixed in 0.5.12").
- Every release's report is kept; the summary table across releases lives in
  `docs/testing/release-acceptance-index.md` (one row per version: date, PASS/FAIL/SKIP counts,
  verdict, report link).

### D11. Words re-surveyed for the 0.5.11 release (`92a15af2`)

The strings in D3–D7 were read at `c65ed0f2`. The 0.5.11 release tag `92a15af2` adds #272 (Apps
sidebar tree, UI half) and the site/version chores; #274 (S-081: a Scope add that misses the core
says so and lands after a restart) is on `main` after the tag and **not** in 0.5.11.

- MAC-9a on 0.5.11: an Apps row per app, titled with `ClientInfo.name` (Safari's
  `com.apple.Safari` → "Safari"; a bare `com.apple.WebKit.Networking` → "WebKit Networking"),
  its count, a chevron whose accessibility label is "Expand <app>" / "Collapse <app>", and under
  it one domain sub-row per host the app talked to (counts sum to the app's). Context menu:
  "Pin App" / "Unpin App". Selecting the app or a domain opens the domains; the chevron closes
  them. The dry run on the 0.5.11 core saw `source_app == "com.apple.Safari"` on the extension
  rows, so the group is "Safari" there.
- N1 on 0.5.11: the pre-#274 behaviour (pending row kept, error only in the status bar) is the
  expected FAIL; Explains = #274, merged after the tag, unreleased.
- Everything else in D3–D7 is unchanged between `c65ed0f2` and `92a15af2` (`git diff --stat` of
  `apps/mac/Sources`, `crates/aitm/src`, `crates/aitm-tui`, `apps/web/src`: only #272's four
  Swift files).

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
   (#271), CLI-4/5/6/10 (`claude/cli-oneshot-live-core`), N1-MAC (S-081 / #274), MAC-9b proxied
   attribution (missing feature). If any of them passes on 0.5.10 the report says why (e.g. a
   PR that reached the release).
6. AC6: The runner `tests/e2e/acceptance/lib/run.sh <version>` exists, runs the cells in the D9
   order (`cli-livecore`, `mac`, `tui`, `web`, `cli-nocore`, plus the negatives where D7 places
   them), performs no `yes` step whose id is not in `ACCEPT_YES`, prints a SKIP line with a reason
   for every unperformed step, exits 1 iff a performed step FAILed, 77 when the verdict is
   `incomplete`, 0 only for `pass`, and writes the D8 README skeleton with every step's result.
7. AC7: `tests/e2e/acceptance/lib/preflight.sh` records every D2 reading before and after; the
   runner diffs them and the diff is in the report.
8. AC8: No cell starts a journey core on a non-default port, writes Scope over the bus, edits
   `config.yaml`, or prints a secret; `run.sh` greps the run folder and the report for every
   secret value it knows (operator token, agent token, web `#t=` values, `AITM_WEB_TOKEN`) and
   for token-shaped strings, and fails the run on a hit. CLI-8's plain 8082 listener is the one
   allowed socket.
9. AC9: Every `yes` cell records the before-state, checks the bypass precondition, arms a trap
   that replays the recorded per-service state, and diffs after; `scutil --proxy` before == after
   is asserted by the cell itself. Start steps refuse on a busy port.
10. AC10: `python3 tests/e2e/run.py --list` discovers exactly the acceptance cells
    (`test_*.py`, `tier=manual`) and no helper, so the merge gate skips them loudly and never
    runs a `yes` step or a helper in CI.

## Left to the builder

- File names under `tests/e2e/acceptance/lib/` beyond `run.sh`, `preflight.sh`, `report.py`,
  `cli_journey.sh`, `bus_truth.py`; one cell per journey; `aitm_e2e/installed.py`.
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
3. ~~Should the Scope hosts added by the run be removed at the end?~~ Decided by the orchestrator
   2026-11-02: hosts the run adds are **removed at the end** through the same surface (the Scope
   page's "Remove from Scope", the TUI's `:scope rm <host>` palette command — it names the host,
   where `d` removes the row under a cursor the pty grid cannot see —, the web row's remove
   button), unless Matt says keep;
   they are listed in the report either way. Hosts that were in Scope before the run are never
   touched.

## Review log

Stage-2 panel on `f4eb2187` (spec-reviewer + quality-reviewer, 2026-11-02; docs-only rule).
Dispositions by the acceptance session under Matt's autonomous mode.

| # | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| S1 | spec | Critical | Four strings paraphrased: Bus lane "connected as operator" is the warning lane; CLI-8/N4 lack "the"; Safari group is "WebKit Networking" at `c65ed0f2` | Fixed (MAC-1/13, CLI-8, N4, MAC-9a) |
| S2 | spec | Critical | `run.py` would discover `run.sh`/`preflight.sh` as suites | Fixed: helpers in `lib/`, AC10 "and no helper" |
| S3 | spec | Important | CLI order vs preconditions | Fixed: `cli-livecore` / `cli-nocore` cells (D6, D9, AC6) |
| S4 | spec | Important | N2–N5 have no cell | Fixed: D7 "where each negative is observed" |
| S5 | spec | Important | install/upgrade absent | Fixed: MAC-0, CLI-0 (`yes`, release runs only) |
| S6 | spec | Important | TUI-4/WEB-5 accept `200` without the decrypted marker | Fixed |
| S7 | spec | Important | CLI journey lacks route/rows/restore | Fixed: CLI-9, CLI-10 |
| S8 | spec | Important | `preflight.sh` built before approval | Accepted: the read-only state reader was needed to run Stage 2 the same day; it lands with this spec's approval through the same PR and the Stage 3 panel |
| S9 | spec | Important | TUI/WEB silent on All Apps / Apps | Fixed: TUI-9/10, WEB-9/10 as `SKIP n/a` with Explains |
| S10–12 | spec | Minor | Kill hint elided; MAC-10 target text; D2 `pgrep` | Fixed (all three) |
| Q1 | quality | Important | CLI cell ordering | = S3, fixed |
| Q2 | quality | Important | CLI-8 unreachable with an `aitm web` holder | Fixed: plain 8082 listener |
| Q3 | quality | Important | BLOCKED undefined for skipped predecessors | Fixed: D1 dependencies + redefinition |
| Q4 | quality | Important | All-SKIP run exits 0 | Fixed: `incomplete` verdict, exit 77 (D1, D10, AC6) |
| Q5 | quality | Important | Restore trap sets "off" | Fixed: replays the recorded per-service state (Constraints, D9, AC9) |
| Q6 | quality | Important | Bypass "always on" cannot be kept | Fixed: bypass is a D2 reading and a precondition |
| Q7 | quality | Important | Only the operator token redacted | Fixed: Secrets constraint, WEB-1 `<redacted>`, AC8 |
| Q8 | quality | Important | No bus truth for WEB-5/6/8; TUI observes itself | Fixed: WEB rows filled; TUI result kind `(bus truth: audit only)` |
| Q9 | quality | Important | MAC-9 two verdicts | Fixed: MAC-9a / MAC-9b |
| Q10 | quality | Important | D9 layout vs `run.py` (discovery, `AITM_BIN`, `AITM_AUDIT_LOG=off`) | Fixed: `lib/`, cells driven by `run.sh`, `AITM_AUDIT_LOG` unset |
| Q11 | quality | Minor | Strings duplicated across steps instead of a string table | Accepted as written: the step tables are the reading order an operator follows; the runner's assertion module is the single machine-readable table and cites step ids |
| Q12–Q17 | quality | Minor | TUI-6 two key paths + `ca-audit.jsonl` path; window length twice; busy-port refusal attached to `yes` cells; helpers under `tools/`; WEB-6 bundled; PNGs in the repo | Fixed (all six) |
| Q18 | quality | Minor | untracked `preflight.sh` | = S8 |

Stage-6 panel 2 on the fix round `e1583c75..6765dee0` (security, quality, spec; 2026-11-02):

| # | Reviewer | Severity | Finding | Disposition |
|---|---|---|---|---|
| Q2-1 | quality | Important | backgrounded cell gets `/dev/null` stdin: `--manual` pauses die | Fixed: `<&0` on the cell |
| Q2-2 | quality | Important | watchdog SIGTERM skips Python `finally` (restore, cleanup) | Fixed: `exit_on_term()` turns SIGTERM into `SystemExit(2)` in every cell; node child killed in the outer `finally` |
| S2-1 | spec | Important | CLI-9 `set` without the bypass precondition; substring bypass check | Fixed: `config_bypass` precondition, `bypass_applied`, FAIL `bypass not applied` |
| S2-2 | spec | Important | secret values collected only at the end (app may have quit); web `#t=` never added | Fixed: collected at start and end; the web cell writes its bearer values to a 0600 `.secrets` file the grep reads and deletes |
| S2-3 | spec | Important | 0.5.10 README lacks CLI-0/9/10, MAC-0, MAC-9a, per-surface N2/N4 rows | Fixed in the report |
| Q2/S2 Minor | both | Minor | N5-WEB written by two cells; `N/A` result for n/a steps (spec gap); ERROR precedence; SKIP detail grep; report.py failure silent; watchdog sleep leftover; `tooling_mentioned` helper; `find_embedded_core` OSError; index run-2 row; `:scope rm` / `-R` frames / ax_press / N5-WEB placement need spec sentences; `mac_bypass_ok` key; CLI-3 checks 8080 only; AX label assumptions (Apps sidebar title, combined Scope row) to verify on the window | All fixed or amended above (D1 `N/A`, D7 N5 row, Open q3, Constraints, D9); AX labels: `ax_press --prefix` fallback implemented, verification deferred to the window half (run 4) |

Stage-6 panel 3 on the fix round `6765dee0..84e22c4f` (2026-11-02): spec PASS with three Minors (Review-log
wording about AX verification; stale "300 ms" strings in the mac cell; `pass` needs one performed PASS) — all
fixed in the same commit. Quality FAIL on one Important — `config_scope_entries` parsed `scope:` as a bare
list while the core's shape is `scope: { entries: [...], allow_agent_widen }` (the pre-existing-host guard
would have been inert on a real config) — fixed: one `_block_list(top, sub)` walker for `scope.entries` and
`system_proxy.bypass`, tests rewritten to the core's shape incl. the inline form and the sibling key; Minors
fixed in the same commit (CLI cell's `run()` uses the SIGINT-reset shim run.sh uses, since bash 3.2 cannot undo
the async SIGINT-ignore with `trap - INT`; N1 SKIP text names the probe digit; `py_installed` no longer swallows
stderr). Security FAIL on one Important — the web cell's `.secrets` file outlived an interrupted run and every
standalone run — fixed: destroyed on EXIT/INT/TERM, read and destroyed the moment the web cell returns, never
written outside `run.sh` (APFS does not overwrite blocks, so the honest claim is "0600, deleted"); Minors fixed:
the ERROR-path restore compares to the cell's own start reading and prints the diff before replaying; N1 sends
nothing when the focus probe is not seen (a blind paste could reach Settings' persisting bypass field).

Run 5 follow-up (2026-11-02): MAC-5 failed because the Edit Scope sheet does not focus its field when
Scope is non-empty and System Events cannot set focus on a SwiftUI text field; the harness now clicks the
field's accessibility bounds before the probe (`lib/click.sh`, `installed.field_center`), identifier first,
description fallback; the product fix (focus the Add field whenever the sheet opens, plus an accessibility
identifier) is carded for the mac session.

Stage-6 panel on PR #281 (`82e495f3..d7e6b63c`, 2026-11-02): security FAIL on one Important (a raw-coordinate
click with no re-check of the target before the second click) → fixed: `click.sh` takes the field's
description/identifier and re-locates it through accessibility before each click, refusing on gone/moved;
quality FAIL on one Important (MAC-5/N1 failure texts claimed a probe that never ran) → fixed: one message per
gate (click refused vs probe not seen); spec FAIL on one Important (the N1 re-probe gained the click and broke
the ~1 s timing) → fixed: the click is pre-restart only. Minors fixed: empty/negative-coordinate guard (moot:
no coordinates on argv), identifier cross-checked against the description, float/zero/garbage tests, module-level
import, Constraints wording. Accepted: the five-script refusal preamble stays duplicated (a `guard.sh` is a
follow-up, not this PR).
