# What aitmproxy does differently (live, 2026-10-31)

Comparison of Proxyman ([FLOWS.md](FLOWS.md), [BUNDLE.md](BUNDLE.md)) with a
**live** aitmproxy run, never with fixtures:

- Dev bundle `/tmp/Aitmproxy-dev-pmref.app` built from this branch
  (main `c8cf56a5`, v0.5.8 merged) with `DEV_TAG=pmref CORE_DIR=<repo>/target/release tools/snap-dev.sh none`,
  launched as `APP_STORE=/tmp/pmref-store …/Aitmproxy-pmref`; embedded core
  pid 57260 listening on `127.0.0.1:8080` (proxy), `8083` (browser), `54562`
  (bus), config under `$TMPDIR/aitm-embedded-core/F19C3B88-…/config.yaml`
  with **no scope block**.
- Traffic: `curl -x 127.0.0.1:8080` ×3 `http://example.com/` (200),
  `-k https://example.com/` (200), strict `https://httpbin.org/get`
  (`curl: (60) SSL certificate problem: unable to get local issuer
  certificate`, no row), `http://httpbin.org/get` (200),
  `-k https://proxyman.com/` (200); then four unsolicited
  `detectportal.firefox.com` requests from a Firefox profile that points at
  127.0.0.1:8080 on its own. `scutil --proxy`: `HTTPEnable : 0`,
  `HTTPSEnable : 0` throughout (the app never touched the system proxy).
- Window driven with real input (`tools/cgclick.swift`, System Events menu
  presses) and captured with `tools/winshot.swift`; shots in
  `shots/aitmproxy-live-2026-10-31/` (numbers 4 and 10 were duplicates or
  failed captures and were dropped; `10b-front` is the Settings window,
  520×229, captured by window id). The Settings ▸ Proxy / All Apps tabs
  were not captured: the Terminal tab that had launched the app vanished and
  took the process with it before that step (General tab captured).

Reference rule (Matt): copy Proxyman's **flow and information density**,
keep our look.

Pointer IDs: `STORIES.md` reserves S-073 to S-078 for the Proxyman
capture-flow stories (STORIES.md, S-079 note); their drafts live in the
orchestrator session's shared note `proxyman-capture-flow-gaps.md`, **not in
this tree**, and S-080 is a draft ID from the same note. The per-host
decryption decision is Matt's (2026-10-31), recorded in the project memory
`aitmproxy-per-host-decryption-decision`; the core half is in progress in the
session "Core: per-host decryption" (branch `claude/youthful-kapitsa-c196d6`).
Where a row says *drafted* the story is not yet merged. Severity: **gap** (Proxyman does it, we do not), **diff**
(both do it, differently, by design or not), **ours** (we do it, Proxyman
does not).

## 1. Getting traffic in

| # | Proxyman | aitmproxy live | Kind | Pointer |
|---|---|---|---|---|
| 1.1 | Launch → `Auto Override System Proxy Settings at Launch` on by default; status badge `Proxy Overridden`; helper sheet with admin prompt once | Launch → listens on 127.0.0.1:8080, system proxy untouched (`HTTPEnable : 0`); the Proxy switch records on/paused, it does not set the system proxy; no helper | **gap** | BRIEF "Shape" says loopback only; GLOSSARY "Proxy" = the listener. The system-proxy automation session (PR #214, `aitm-sysproxy`, `proxy.system.*`) is the fix; the app needs the Proxyman words: one switch that overrides, a badge that says so, a revert on quit and on crash (BUNDLE §3.4) |
| 1.2 | Helper install sheet: four-line checklist, `(Required Root Privileges)`, macOS Authorization dialog, Login Items follow-up on macOS 13+ | nothing equivalent; the only privileged piece is the extension | **gap** | design the sheet from FLOWS §1.3; the admin prompt sentence is the right description string, ours must be as plain |
| 1.3 | `No HTTP Traffic?` alert after a silent start, with `Install Helper Tool` / `Later` / `Don't ask again` | Status page `Getting started` list: `Core is running ✓`, `Bus connected ✓`, `All Apps capture is not in this build ○`, `Add a host to Scope (for now as example.com:443) ○ Open Scope…`, `10 flows captured ✓` | **diff** | ours is calmer and always visible (S-072); keep it, but add the one remedy Proxyman names when zero flows arrive after N seconds: turn on the system proxy |
| 1.4 | Listening pill `● Proxyman \| Listening on 192.168.1.89:9090` (LAN address, so devices can connect) | pill `● aitmproxy · 127.0.0.1:8080 ● no extension` | **diff** | S-077 drafted, not in tree ("Listening on"); the LAN address matters only once we bind beyond loopback (BRIEF: not in v1) |
| 1.5 | Network Extension: Settings toggle `Enable Network Extension` → `Install and Enable` → named macOS steps → `Network Extension is capturing HTTP and HTTPS from all apps on this Mac.`; NE and system proxy mutually exclusive, said in one sentence | toolbar `All Apps` switch (disabled in this build: `This build has no extension — Install the signed Aitmproxy app; its extension is built in`); Status lane `ALL APPS ● no extension` | **diff** | the words are ours (GLOSSARY "All Apps"); the state machine should name every macOS step as Proxyman does (FLOWS §5.2–5.4, 5.7) and state the NE-vs-system-proxy rule once the system proxy exists |

## 2. Apps, Domains, attribution

| # | Proxyman | aitmproxy live | Kind | Pointer |
|---|---|---|---|---|
| 2.1 | `Client` column shows a real icon + name for every flow, including plain proxied ones, without the extension (libproc PID lookup, BUNDLE §4b; confirmed live 2026-11-01 with the extension off and Pro-locked: twelve named apps, SCREENS.md shot 34) | `CLIENT —` on all 10 rows; Apps page banner `Flows carry no source app yet, so this page cannot group them.`; Overview `CLIENTS No app attribution`; inspector shows only `client 127.0.0.1:54701` | **gap** | the attribution session (PR #195 `source_app`) wires the extension's metadata; the proxied-flow half needs the libproc lookup on `client` port → PID → bundle (core or app side). S-013 acceptance says icon when `bundleID` resolves |
| 2.2 | `Apps (2)` expands to app rows, each expanding to the domains that app talked to | `Apps 0`; no sub-rows | **gap** (follows 2.1) | S-013 |
| 2.3 | `Domains (5)` flat, disclosure to paths | `Domains 4` with host sub-rows and counts (`detectpor…irefox.com 4`, `example.com 4`, `httpbin.org 1`, `proxyman.com 1`), no path disclosure | **diff** | S-075 drafted, not in tree |
| 2.4 | `Favorites ▸ Pinned, Saved (1)` | `Pinned 0`; no Saved | **gap** | S-066 / core F10 |
| 2.5 | Sidebar filter `Filter (⌘⇧F)` at the bottom with `+` | `Filter ⌘⇧F` at the bottom | same | — |

## 3. Flow list and HTTPS

| # | Proxyman | aitmproxy live | Kind | Pointer |
|---|---|---|---|---|
| 3.1 | Columns `# URL Client Method Status Time Duration Request Response SSL Edited Tools Comment` | `# URL CLIENT METHOD STATUS TIME DURATION REQUEST RESPONSE SSL EDITED ORIGIN` | **diff** | ours lacks `Tools` and `Comment`, has `Origin` (agent vs operator, ours by design); `Request` reads `0 B` for a GET where Proxyman shows the header bytes (`160 bytes`) |
| 3.2 | Undecrypted HTTPS is a visible `CONNECT` row: Status `200` / `999` / amber `Active`, no padlock; Response pane offers `Enable only this domain (⌥⏎)` / `Enable all domains from "<app>"` | With an empty scope **everything was decrypted** (`https://example.com/` and `https://proxyman.com/` are `GET 200` rows with an open padlock, `in scope`); strict curl's refused handshake left **no row at all** | **gap** | Matt's per-host decision (2026-10-31): decrypt only Scope hosts, every other CONNECT a tunnel row, inline `Add <host> to Scope (⌥⏎)`; stories S-073/S-074/S-080 drafted, not in tree; core work in the per-host decryption session. The banner `No scope set — every host is read-only until you add one` currently means read-only *actions*, not read-only *bytes* (S-049's state) |
| 3.3 | Chip bar `All \| HTTP HTTPS WebSocket \| JSON … Other \| 1xx 2xx 3xx 4xx 5xx \| <saved filter> ‹` | `All \| HTTP HTTPS WebSocket \| TCP UDP L4 \| h1 h2 \| JSON Form XML JS CSS GraphQL Document Media Other \| Filters ▾` | **diff** | no status-class chips, saved filters behind `Filters` (S-076 drafted, not in tree); `TCP UDP L4` and `h1 h2` are ours |
| 3.4 | Status bar `Clear · Filter · Auto Select · 1/8 rows selected · • 177 MB ↑ 2 KB/s ↓ 7 KB/s · Proxy Overridden / Breakpoint` | `Clear · Filter · Auto-select · 1/10 rows · ↑ 0 B/s ↓ 33 B/s` | **diff** | same shape; no memory figure (Settings ▸ Appearance option in Proxyman), no override/breakpoint badge (BRIEF: connection state lives only in the toolbar cluster, by design) |
| 3.5 | Row selection: inspector strip `POST · 200 OK · URL`; Request `Header Query Body Raw Summary +`; Response `Header Body Raw Treeview +`; `+` = Custom Previewer sheet (JSON, Treeview, Form, Multipart, HTML, HTML Webview, CSS, JS, XML, Images, Hex, Protobuf, MessagePack, M3U8, Comment, Summary, Code Generator, GraphQL, Timeline Chart; SSE, OpenAI) | strip `GET · 200 OK · URL · ⧉ · HTTP/2 · h2 · req 0 B · resp 577 B · 21 ms · client 127.0.0.1:54701 · in scope`; Request `Headers Cookies Query Body Raw Summary Timing Connection`; Response `Headers Set-Cookie Body Raw JSON Diff ⌄ · Rendered · HTML ▾ · 🔍` | **diff** | ours fixes the tab set and puts the facts in the strip (denser, good); Proxyman lets the operator add viewers per panel; SSE / Protobuf / MessagePack / Hex exist in STORIES M2 (S-024, S-025) |
| 3.6 | `Time` to the millisecond, `Duration` in ms, sizes `160 bytes` / `20.5 KB` | `22:59:40.216`, `212 ms`, `0 B` / `577 B` / `334 KB` | same | — |

## 4. Certificate authority

| # | Proxyman | aitmproxy live | Kind | Pointer |
|---|---|---|---|---|
| 4.1 | Settings ▸ General block `Proxyman CA (not installed) · Generate new… · More`; menu `Certificate ▸ Install Certificate on this Mac…` with Automatic (`Install & Trust Certificate`, admin password) and Manual tabs; states `Installed & Trusted` / `Installed, but not Trusted!` / `Not installed` | page `Certificate Authority`: `Not installed` badge, SHA-256, Subject `aitmproxy root CA`, Path `~/Library/Application Support/aitmproxy/ca/ca.crt`, `Export PEM… Export DER… Install…`, `Agent may install No`, setup text for iOS / Android / Browsers / Terminal | **diff** | ours has the facts Proxyman hides; it lacks the **trusted-but-not-installed / installed-but-not-trusted** distinction and the one-click admin-prompt install from first run (memory `aitmproxy-ca-trust-root-cause`: the untrusted CA is why Safari shows nothing through the extension). S-058 is done but first-run must lead here |
| 4.2 | CA served by the proxy at `http://cert.proxyman.io` for devices | Export PEM + AirDrop text | **gap** | small: serve `/ca.pem` on the listener (core) |

## 5. Settings and agent

| # | Proxyman | aitmproxy live | Kind | Pointer |
|---|---|---|---|---|
| 5.1 | Settings sidebar `App (General, Appearance, Privacy) · Integrations (MCP, GitHub, Tools) · Advanced (Network Extension BETA, Advanced) · Proxyman (Workspace, Products)`; General: `Port Number 9090`, `Auto Override System Proxy Settings at Launch`, `Auto Start Recording Traffic at Launch`, `Use HTTP/2`, `Advanced Proxy Setting…`, CA block | tabs `General (Row density Dense (28 pt), Auto-select new flows) · Bus · Proxy · All Apps · Appearance` | **diff** | the launch behaviours (override at launch, record at launch) have no home yet; they belong in Proxy once 1.1 lands |
| 5.2 | Settings ▸ MCP `Enable MCP Server`, `Redact Sensitive Data Before Sending to AI`; stdio `mcp-server` binary in the bundle; ~90 tools incl. `set_system_proxy`, `install_network_extension`, `install_certificate` | toolbar `Agent` switch (Allow All Tools / Read-only / Paused), Agent page, Activity log; bus verbs gated operator/agent with sealed governance | **ours** | keep the gate; add the read-side verbs Proxyman has (`get_system_proxy_status`, `get_network_extension_status`, `get_certificate_status`, `get_traffic_overview`, `get_flow_timing`) so an agent can diagnose "no traffic" (BUNDLE §7) |
| 5.3 | Scripting (JS), Map Local/Remote, Breakpoint, Block/Allow lists, DNS spoofing, Throttle, Reverse proxy as rule folders | Scope, Scan, Findings, Browser, Scripts (Rhai), Agent | **ours / Later** | BRIEF "Not in version one" |

## 6. Prompts and privilege, side by side

| Step | Proxyman asks macOS for | aitmproxy today |
|---|---|---|
| System proxy | admin password once (helper install) | nothing; feature absent in the app (PR #214 adds the core verbs) |
| CA trust | admin password (Automatic) or Keychain Access (Manual) | `Install…` runs `aitm ca install` with the proxy's confirmation text; trust prompt is macOS's |
| Every app's traffic | Login Items & Extensions approval + network-configuration `Allow` (+ restart) | the same two approvals through the notarized build (`All Apps`); this dev build has no extension |
| Agent | nothing | nothing |

Nothing in either product needs a Terminal; Proxyman documents one optional
`sudo … --install-privileged-components` for scripted installs.

## 7. Three things to take first

1. **Per-host decryption + tunnel rows** (3.2): the only place our live run
   is *less* honest than Proxyman — a refused handshake vanished, and an empty
   scope decrypted everything. Already decided (memory
   `aitmproxy-per-host-decryption-decision`); stories S-073/S-074/S-080 are
   drafts in the shared note, the core session is running.
2. **Client attribution for proxied flows** (2.1): libproc lookup, no
   extension needed, unlocks Apps rows, `Enable all domains from "<app>"`
   and the Overview's Clients panel.
3. **System proxy as a first-run step with the helper's words** (1.1–1.3):
   the override switch, the `Proxy Overridden` badge, revert on quit and on
   crash, and the `No traffic?` nudge pointing at it.
