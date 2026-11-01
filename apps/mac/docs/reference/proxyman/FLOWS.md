# Proxyman operator flows, step by step

Companion to [BUNDLE.md](BUNDLE.md). Every quoted string is Proxyman's own,
taken from one of four sources, marked per line:

- **[strings]** the English string tables in
  `Proxyman.app/Contents/Resources/en.lproj/*.strings` (`Preferences.strings`,
  `Localizable.strings`, `Certificates.strings`, …) and `strings -a` on the
  binaries;
- **[video]** the 25 s demo `capture-http-https-demo-2026.mp4`
  (3524×2028, 60 fps), 12 frames at 0.5 fps in `/tmp/claude/proxyman/frames/`
  (a sibling session fetched it; the sandbox cannot reach assets.proxyman.com);
- **[docs]** proxyman.com pages `/docs/basic-features/proxy-setting-tool`,
  `/docs/basic-features/ssl-proxying`, `/docs/advanced-features/network-extension`,
  `/docs/advanced-features/mcp`, `/docs/debug-devices/macos`, `/network-extension`
  and the home page;
- **[Matt]** what Matt observed on his Mac on 2026-10-31 (Proxyman 26.3.0,
  macOS 27.0) and relayed through the orchestrator session.

Proxyman was **not** launched by this session (its "Auto Override System Proxy
Settings at Launch" default routed every new Claude session through
127.0.0.1:9090 tonight). A screen index with our own shots waits in
[SCREENS.md](SCREENS.md) for a run Matt starts himself with that checkbox off.

## 0. The model in one paragraph

Launch → the proxy listens on `:9090` and, by default, **overrides the macOS
system proxy at once** (through the helper if installed, else `networksetup`)
→ every proxy-aware app's traffic appears, grouped by **app** (icon + name)
and by **domain** → HTTPS shows as an opaque `CONNECT` row until the operator
**enables SSL Proxying for that domain or that app** (one click in the
Response pane, `⌥⏎`) → apps that ignore the proxy are reached by turning on
the **Network Extension** (macOS 26, Pro), which replaces the system proxy →
quitting reverts the proxy; a crash is reverted by the helper.

## 1. First launch

1. **The window opens listening.** Toolbar pill: `● Proxyman | Listening on
   192.168.1.89:9090` [video] / `Proxyman | Listening on 10.9.8.151:9090`
   [Matt]. Format strings `Listening on %@` and `Listening on port %@`
   [strings]; the address is the LAN IP of the primary interface
   (ProxymanCore watches `kSCDynamicStorePropNetPrimaryInterface`, see
   BUNDLE §10; `defaults` keeps `lastKnownIPAddressCurrentNetwork`).
2. **Auto override.** Settings ▸ General ▸ `Auto Override System Proxy
   Settings at Launch` [strings, Matt] with the help text `Override your
   System Proxy Settings in Wi-Fi -> Details… -> Proxies tab.` [strings].
   It is on by default; without the helper the override goes through
   `networksetup` and the sheet below warns about it.
3. **The helper sheet** (first launch, and again when the helper is
   outdated: `New version of Proxy Helper Tool (%@)` [strings]):
   - Title `Install Proxy Helper Tool`, subtitle `Version 1.7.0` [Matt]
     (`PMHelperToolVersion = 1.7.0` in the helper's Info.plist, BUNDLE §3.1).
   - Checklist [strings `Preferences.strings`, Matt]:
     `Auto Override HTTP/HTTPS Proxy with high performance`
     · `Graceful Revert the Proxy if the app is crashed unexpectedly`
     · `Persist and Restore to your previous Proxy setting`
     · `Comply with new macOS 13 Ventura Requirements for Helper Tool`.
   - Warning line: `Your HTTP/HTTPS Proxy is currently overridden by
     `networksetup` CLI. It works, but slow!` [strings, Matt].
   - Button `Install Helper Tool (Required Root Privileges)` [Matt]
     (`Install Helper Tool` + `(Required Root Privileges)` [strings]).
   - Secondary copy elsewhere: `Proxyman Helper Tool requires your permission
     to help you override/revert HTTP Proxy with ease.`, `Proxy Helper tool
     is better performance than using networksetup CLI` [strings].
   - **macOS prompt:** the SMJobBless Authorization dialog. Its sentence is
     the app's registered right description `Proxyman is trying to override
     Proxy config in System Preferences.` [strings in the helper]; the
     operator types an administrator password once. On macOS 13+ a second
     surface follows: Login Items. The app detects it
     (`Helper Tool Status: Need Allow in System Setting`,
     `Required your permission to properly work in Login Items`) and offers
     `Open Login Items` / `Open Login Items & Extensions` [strings]; docs:
     System Settings ▸ General ▸ Login Items (& Extensions) ▸ find Proxyman ▸
     ON [docs]. A stale entry is cleared with `sfltool resetbtm` + restart
     [docs].
   - Skippable: `Later` [strings]; later from Settings ▸ Advanced ▸ `Proxy
     Helper Tool:` row with `Install Helper Tool` [strings] and status words
     `Installed & Trusted` / `Not installed` [strings].
   - Install from the command line, for scripted setups [docs]:
     `sudo /Applications/Proxyman.app/Contents/MacOS/proxyman --install-privileged-components`.
4. **The "no traffic" nudge** (a timer after launch when nothing arrived)
   [Matt, strings]: alert `No HTTP Traffic?` · body `It seems that Proxyman
   could not capture any HTTP Traffic, Install the Helper Tool will fix it.`
   (string table: `It seems that Proxyman could not capture any HTTP
   Traffic, (title) the Helper Tool will fix it.`) · buttons `Don't ask
   again` / `Install Helper Tool` / `Later` [Matt]. The suppression logic is
   logged in the binary: `[HelperToolSuggestion] Skip because Helper Tool is
   already installed!` / `… Skip because there is traffic!` / `… Skip because
   the user ask for it!` / `… Skip because user manually turns off the
   Override Proxy!` [strings].
5. **Status bar** (bottom of the window) [video, Matt]: left buttons `Clear`
   · `Filter` · `Auto Select`; centre `1/8 rows selected` (`%d/%d rows
   selected`, `0 rows selected` [strings]); right `• 177 MB ↑ 2 KB/s ↓ 7 KB/s`
   (Settings ▸ Appearance `Status Bar: Show Resource Usage in Bottom Bar`,
   `Include memory usage and upload/download speed.` [strings]) and badges:
   `Proxy Overridden` [Matt, strings] (tooltip `System Proxy is Overridden by
   Proxyman (%@) (Toggle by: ⌥⌘O)`, `Overridden by Proxyman Helper Tool` /
   `Your current HTTP/HTTPS Proxy is overridden by networksetup CLI.`
   [strings]) and `Breakpoint` while a breakpoint is armed [video].
6. **Quit.** `Restore the Previous HTTP/HTTPS Proxy When Proxyman Closes`,
   help `Requires an installed Proxy Helper Tool. Restores the proxy
   configuration that was active before Proxyman.` [strings]; `Show Alert on
   Quit` [strings]. The 1.6.0 helper fixed `PAC URL doesn't restore properly
   when closing Proxyman` [strings, docs].

## 2. The main window

Layout [video f001]: sidebar | toolbar / chip bar / flow list / inspector,
status bar across the bottom. No connection state anywhere but the pill and
the status-bar badge.

- **Toolbar** [video]: left `⏸` (pause recording), `✎` (Compose), `🗑`
  (Clear); centre pill `● Proxyman | Listening on 192.168.1.89:9090`; right
  account circle, `⌘` (command palette), three layout glyphs (sidebar /
  bottom inspector / right inspector).
- **Chip bar** [video, Matt]: `All | HTTP HTTPS WebSocket | JSON Form XML JS
  CSS GraphQL Document Media Other | 1xx 2xx 3xx 4xx 5xx | slack: client.counts…
  ‹ ⋯`. The last chip is a saved filter; `‹` scrolls the overflow; `⋯` at the
  far right. Matt's build showed `h1 h2 ›` after the content types.
- **Sidebar** [video, Matt, strings]:
  `Favorites` ▸ `Pinned`, `Saved 1` ·
  `All` ▸ `Apps 2` (one row per app with its **real icon** and display name:
  `Proxyman`, `iStat Menus Menubar` [video]; `Codex (Service)`,
  `dataaccessd` [Matt]; each expands to the domains that app talked to) ·
  `Domains 5` (flat hosts; a disclosure where there are sub-paths). Strings:
  `Favorites`, `Pinned`, `(Saved)`, `Apps`, `Domains`, `All Apps`, `Pin to
  Favorites`, `Pin this domain to the Pinned folder.`, `Add domain/client
  (⌘+K)`, `Add new domains or apps into Source Panel (Left Panel)`, `Filter
  specific domains or app in the Source Panel (Left Panel)`. Bottom: `+` and
  `Filter (⌘⇧F)`. Matt also saw `Capture ▸ Overview` at the top.
- **Flow list columns** [video, Matt]: `●` state dot · `#` · `URL` · `Client`
  (icon + name) · `Method` (pill) · `Status` (pill) · `Time` (`10:59:38.064`)
  · `Duration` (`519 ms`) · `Request` (`160 bytes`) · `Response` (`2 bytes`)
  · `SSL` (open padlock when decrypted) · `Edited` (✓) · `Tools`
  (`Scripting` + icon) · `Comment`. Strings: `Client`, `Duration`,
  `Duration (ms)`, `Duration (exact)`, `Edited`, `Comment`.
- **Undecrypted HTTPS rows** [video f001 rows 6–8, Matt]: Method `CONNECT`,
  URL `https://ip.istatmenus.app`, Status `200` (green) once the tunnel
  closed, `999` (grey) when it failed or never answered, amber `Active`
  while open [Matt; string `Active`, `Inactive`]; Request/Response `–`; no
  padlock; the dot grey. Every connection is a row, decrypted or not.
- **Inspector** [video f001–f012]: strip `POST` pill · `200 OK` pill · URL.
  Request tabs `Header Query Body Raw Summary +`; Response tabs `Header Body
  Raw Treeview +`. `+` opens the `Custom Previewer Tab` sheet (`Custom Body
  Previewer Tabs — Display Request/Response Body with different formats.`)
  with a checkbox per format for each panel: JSON, JSON Treeview, Form
  URL-Encoded, Multipart/form-data, HTML, HTML Webview, CSS, Javascript,
  XML, Images, Hex, Protobuf, MessagePack (msgpack), M3U8 (HLS), Comment,
  Summary, Code Generator, GraphQL, Timeline Chart `NEW` (request side);
  SSE (Server-Sent Event), OpenAI (Auto-merge conte…) (response side);
  `Auto beautify the minified content — Only apply to HTML, CSS and JS`;
  `+ Add Custom Tabs`. The JSON tab adds a `JSON Path` field
  (`e.g. $.users[0].name (⌘⇧F)`) with `Save`.

## 3. Capture HTTPS: SSL Proxying

1. Select an opaque `CONNECT` row. The Response pane shows a lock and
   `HTTPS Response — This HTTPS response is encrypted. Enable SSL Proxying to
   see the content.` [Matt; string `Enable SSL Proxying to see the content.`]
   with two buttons: **`Enable only this domain (⌥⏎)`** (primary) and
   **`Enable all domains from "<app>"`** [Matt, strings; format `Enable all
   domains from "%@"`]. Help texts [strings]: `Adds the current request's
   host to SSL Proxying, so Proxyman can decrypt and show future HTTPS
   response bodies for this domain.` / `Adds every HTTPS host used by "%@"
   to SSL Proxying, so Proxyman can decrypt and show response bodies from
   that app.`
2. Same verbs elsewhere: row and sidebar context menus `Enable SSL Proxying`
   / `Disable SSL Proxying` [docs, strings]; `Enable SSL Proxying for This
   Domain` [strings]; menu `SSL Proxying List…` (`⌘⌥P`) [docs, strings] with
   **Include** (`Define Clients or Domains (wildcard) that Proxyman will
   decrypt their HTTPS Request/Response.`) and **Exclude** (`DO NOT Decrypt
   HTTPS in below list. Useful to exclude some domains/apps from the Include
   List`) [strings]; wildcards `*`, `*.domain.com`, `v?.domain.com` [docs].
3. The **next** connection to that host is decrypted; the existing tunnel row
   stays as it was. (Proxyman restarts nothing.)
4. If the client rejects the certificate, the row becomes an error and the
   inspector explains: `Proxyman could not securely establish the SSL
   Connection with your client. It seems that you haven't installed & trusted
   the certificate on your device or unknown reasons. Click the
   "Troubleshooting" button to find a solution.` [strings]; also `Client SSL
   Handshake Failed`, `The runtime closed the HTTPS tunnel before sending a
   request. It may have rejected the Proxyman CA.`, `If the Proxyman CA is
   trusted but only this app/domain fails, certificate pinning is likely.`
   [strings].
5. Settings ▸ General ▸ `Use HTTP/2` [Matt] (`Proxyman prefer using HTTP/2 or
   fallback to HTTP/1.1`, `HTTP/2 preferred` [strings]) and `Advanced Proxy
   Setting…` [Matt, strings].

**macOS prompts:** none. SSL Proxying is an in-app list; the prompts belong
to the CA step below.

## 4. The certificate authority

Settings ▸ General (bottom block) [Matt]: `Proxyman CA (not installed)` ·
`Generate new…` · `More` (strings `Proxyman CA`, `Generate new Proxyman CA`,
`Generate new...`, `%@ (not installed)`).

Menu `Certificate` ▸ `Install Certificate on this Mac…` [docs, strings] opens
a sheet with two tabs [docs]:

- **Automatic** (recommended): `Install & Trust Certificate` → macOS asks for
  the Mac password ("for root privileges" [docs]); then the button reads
  `Installed & Trusted` [docs, strings]. Mechanism: `security add-trusted-cert
  -r trustRoot …` through AppleScript `with administrator privileges`
  (BUNDLE §6). Settings label for the same thing: `Automatically Trust
  Proxyman Certificate in your Keychain Access (Require root privileges)`
  [strings].
- **Manual**: `Generate and Add…` adds the CA to the keychain untrusted, no
  password; macOS may ask which keychain (`Make sure you Select System or
  Login Keychains.` [strings]); then `1. Open "Keychain Access" app ->
  Search "Proxyman CA" -> Double-click to Open` · `2. Select "Always Trust"
  -> Close this Windows & Save` [strings] (Keychain Access asks for the
  login password when saving trust); status becomes `Installed and Trusted`
  [docs, strings].

Status words shown in the sheet, Settings and the inspector [strings]:
`Installed & Trusted!` · `Installed, but not Trusted!` · `Not installed` ·
`Certificate Expired!` · `Proxyman CA hasn't been trusted yet!` ·
`Proxyman CA is trusted!` · `Root Certificate Removed` (`The Proxyman Root
Certificate has been removed from your Keychain. SSL Proxying will not work
until you install a new certificate.`).

Other targets, same menu [strings]: `Install Certificate on iOS` (device /
simulator), `… on Android`, `… on Firefox Browsers…` (`Firefox uses its own
certificate store, so trusting Proxyman in macOS Keychain is not enough.`),
`… on Java VMs`, `Root Certificate as PEM/DER/P12...`, `Add Custom
Certificates…`, `Reset All`. Devices fetch the CA from the proxy itself at
`http://cert.proxyman.io` / `http://proxy.man/ssl` [strings].

Gate: `Require Trusted Proxyman Certificate in Keychain Access` — `Proxyman
won't prompt the Mac Setup Guide Window if the certificate is not properly
trusted in Keychain Access for domain/app SSL Proxying` [strings].

**macOS prompts:** administrator password (Automatic), or keychain choice +
Keychain Access trust change (Manual). Never a Terminal.

## 5. Capture every app: Network Extension (Beta)

Settings sidebar [Matt]: `App` (General, Appearance, Privacy) · `Integrations`
(MCP, GitHub, Tools) · `Advanced` (`Network Extension BETA`, Advanced) ·
`Proxyman` (Workspace, Products).

1. Settings ▸ Network Extension ▸ toggle `Enable Network Extension` → button
   `Install and Enable` (`Install the network extension included with
   Proxyman.`) [docs, strings]. Also from the status bar at the top of the
   main window [docs]. Preconditions in the UI copy: `Network Extension
   capture requires macOS 26 or later.`, `Network Extension installation and
   capture require Proxyman Pro.` / `Buy Pro to unlock Network Extension
   capture.`, `Network Extension is not available on the Setapp version`,
   `Open a Proxyman window and start the proxy before enabling Network
   Extension capture.` [strings].
2. **macOS prompt 1** (system extension approval): state `Network Extension
   is waiting for approval` [strings]; instruction `In General → Login Items
   & Extensions, scroll down to Extensions, choose By Category, click ⓘ next
   to Network Extensions, then turn on Proxyman.` [strings]; buttons `Open
   Login Items & Extensions`, `Open Privacy & Security` [strings].
3. **macOS prompt 2** (network configuration): "When macOS asks to add the
   network configuration, click **Allow**." [docs] (the transparent-proxy
   configuration appears under VPN & Filters).
4. Possibly **a restart**: `Network Extension needs a restart`, `Restart your
   Mac to finish`, `Restart Proxyman` [strings]; `Please restart Proxyman to
   apply all the changes…` [strings].
5. Running: `Network Extension is on`, `Network Extension is capturing HTTP
   and HTTPS from all apps on this Mac.`, `Capturing all apps`, `Capturing
   HTTP and HTTPS from local applications.` [strings, docs]. The system proxy
   is **turned off** while it runs: `Network Extension and the system proxy
   can't run at the same time. Turning on Network Extension turns off the
   system proxy.`, `Network Extension (Beta) is on, so the macOS proxy is
   off. Click for details and settings.`, `Proxyman is not capturing traffic
   from this Mac: the macOS proxy stays off while Network Extension is on.`
   [strings].
6. Apps already running must be restarted to be captured [docs]; strings
   `Restart %@ Required`, `Restart Google Chrome Required`, `Restart Firefox
   Required`.
7. Failure words [strings]: `Network Extension couldn't start capture`,
   `Another copy of Proxyman replaced the Network Extension. Quit the other
   copy, then turn Network Extension on again.`, `A Network Extension
   operation is already in progress. Read status and complete any macOS
   approval first.`, `Enable the Proxyman VPN / Network Extension in System
   Settings to resume capture.`, `Quit the app or VPN using the proxy port,
   then restart Proxyman.`
8. Off / uninstall: toggle off to stop (`Network Extension is disabled`);
   Settings ▸ Network Extension ▸ Uninstall → confirm → `Enter your Mac
   password if asked` → removes the configuration, `restart your Mac if
   requested` [docs]; strings `Remove Network Extension configuration`,
   `Remove the Network Extension from this Mac.`, `Network Extension cannot
   be uninstalled in its current state. Read status first.`

What it adds: apps that ignore the proxy (curl without `--proxy`, daemons such
as `dataaccessd` [Matt]) appear under Apps with their icon, because the
transparent proxy provider delivers the source app with every flow (BUNDLE
§4). HTTPS still needs the CA and SSL Proxying; QUIC is not decrypted [docs].

## 6. The agent path: MCP

Settings ▸ MCP: `Enable MCP Server`, `Redact Sensitive Data Before Sending to
AI` (`Automatically redact sensitive information before sending to AI
tools.`) [docs, strings]. Client setup is one command [docs]:
`claude mcp add proxyman --transport stdio -- "/Applications/Proxyman.app/Contents/MacOS/mcp-server"`.
The stdio binary forwards to the app over a loopback bridge with a 0600 token
file; when the app is closed: `Proxyman is not running, MCP is stopped, or MCP
has been disabled by your organization. Open Proxyman Settings > MCP to check
its status.` [strings]. Verbs: BUNDLE §7. The agent can also do the
privileged steps (`set_system_proxy`, `install_network_extension`,
`install_certificate`) and gets the same macOS prompts the operator would.

**macOS prompts:** none for MCP itself.

## 7. Compose, breakpoint, repeat (for completeness)

Toolbar `✎` → Compose; row menu `Repeat`, `Edit and Repeat`, `Breakpoint`,
`Map Local`, `Tools ▸ Scripting` [video Tools column, strings]; a
`Breakpoint` badge sits at the right of the status bar while armed [video].
`Highlight & Comment` (`Color the matching flows and add a comment, so they
stand out in the main table.`), `Add Comment…` [strings]. `Hide Apple Traffic
from iOS Simulators` [strings].

## 8. Prompt inventory

| Step | Who asks | Exact words the operator sees |
|---|---|---|
| Install helper | macOS Authorization dialog | "Proxyman is trying to override Proxy config in System Preferences." + admin password |
| Helper on macOS 13+ | System Settings ▸ Login Items | Proxyman toggle; app says `Need Allow in System Setting`, button `Open Login Items` |
| Override proxy (helper installed) | nobody | status badge `Proxy Overridden` |
| Override proxy (no helper) | nobody; `networksetup` runs as the user | sheet warns `… overridden by `networksetup` CLI. It works, but slow!` |
| CA Automatic | macOS admin password dialog | from `do shell script … with administrator privileges` |
| CA Manual | keychain chooser, then Keychain Access | `Make sure you Select System or Login Keychains.`, `Always Trust` |
| Network Extension install | System Settings ▸ Login Items & Extensions ▸ Network Extensions | `… click ⓘ next to Network Extensions, then turn on Proxyman.` |
| Network Extension config | macOS network-configuration sheet | `Allow` |
| Network Extension, sometimes | macOS | restart (`Restart your Mac to finish`) |
| Network Extension uninstall | macOS | `Enter your Mac password if asked` |
| Terminal / Chrome automatic setup | macOS Automation permission | `Please grant Proxyman permission to automate Terminal in System Settings -> Privacy & Security -> Automation.` |
| SSL Proxying, MCP, CLI | nobody | in-app only |

Never: `sudo` in a Terminal (the only documented `sudo` is the optional
`--install-privileged-components` for scripted installs), a copied command,
a manual plist or keychain edit.
