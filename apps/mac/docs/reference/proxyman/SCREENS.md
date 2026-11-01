# Proxyman screen index

Captured 2026-11-01 from Proxyman 26.3.0 (trial) on Matt's Mac. Matt launched
it himself (pid 24090, 08:53); this session only took screenshots
(`apps/mac/tools/winshot.swift`, 2× PNGs of the 1800×1130 pt window) and
clicked inside Proxyman (`tools/cgclick.swift`, System Events menu presses)
under the orchestrator's display lock. No setting was changed, no privileged
prompt approved, Proxyman was not quit. Shots live in `shots/proxyman/`;
earlier material is in `shots/demo-video/` (three frames of the public demo)
and `shots/aitmproxy-live-2026-10-31/` (our own app, see [DELTA.md](DELTA.md)).

System proxy during the pass (`scutil --proxy`): at 08:53, right after
launch, `HTTPEnable 1 / HTTPSEnable 1 → 127.0.0.1:9090` and the status bar
badge `Proxy Overridden`; by 08:55 the review session read
`HTTPEnable 0 / HTTPSEnable 0` and the badge was gone (Matt turned the
override off, ⌥⌘O or Settings). The end-of-pass reading is in §6.

## 1. Main window

| Shot | State | What it shows |
|---|---|---|
| `01-main-apps-connect-active.png` | 08:53, first second after launch, row 1 selected | Toolbar: `⏸ ✎ 🗑`, pill `● Proxyman \| Listening on 10.9.8.151:9090`, yellow `! TRIAL VERSION`, account, `⌘`, four layout glyphs. Chip bar `All \| HTTP HTTPS WebSocket \| JSON Form XML JS CSS GraphQL Document Media Other \| h1 h2 ›`. Sidebar `Capture ▸ Overview · Favorites ▸ Pinned, Saved · All ▸ Apps 5 (System, Codex (Service), exchangesyncd, itunescloudd, Google Chrome, each with its icon) · Domains 5`. Six `CONNECT` rows, Status amber `Active`, Client icon + name, Time to the ms, Request/Response/SSL `–`. Inspector strip `CONNECT · ACTIVE · https://api.apple-cloudkit.com`; Request tabs `Header Query Body Raw ≡ +` with `Host / Proxy-Connection / Connection`; Response pane: lock, `HTTPS Response`, `This HTTPS response is encrypted. Enable SSL Proxying to see the content.`, **`Enable only this domain (⌥⏎)`** (blue), `or`, **`Enable all domains from "System"`**. Status bar `🗑 Clear · ≡ Filter · Auto Select · 1/6 rows selected · • 158 MB ↑ 595 KB/s ↓ 39 KB/s · Proxy Overridden`. |
| `02-main-after-20s.png` | 09:5x, window inactive, Matt selected the app `Codex (Service)` in the sidebar | Window title becomes the selected app's name; list filtered to that app's one row; Apps count `8` (`codex`, `Claude Helper`, `Proxyman` joined, each with its real icon); Domains `9`; Request tabs gained `Summary` and `Connection Log`; User-Agent of the Codex service is Chrome's; Response pane now offers `Enable all domains from "Codex (Service)"`; **no `Proxy Overridden` badge** in the status bar (`• 165 MB ↑ 26 KB/s ↓ 45 KB/s`). |

## 2. Menu bar, exact words (read through Accessibility, nothing opened)

`Proxyman`: About Proxyman · Buy Proxyman Pro… · Settings… · Check for Updates… · Change Logs… · Services · Hide Proxyman · Hide Others · Show All · Quit Proxyman · Quit and Keep Windows
`File`: New Session · New Folder · New Domain or App · Open… · Open Recent · Convert · Save Session… · Close · Close All
`Edit`: Undo · Redo · Cut · Copy · Copy as cURL · Paste · Duplicate · Delete · Select All · Focus on URL · Find · AutoFill · Start Dictation… · Emoji & Symbols
`View`: Filter Domain or App · Filter Current View · Show Command Palette · Auto Select the Latest Request · Toggle Source List Panel · Toggle Split View · Toggle Dock to Bottom Window · Toggle Dock to Right Window · Toggle Console Log in Scripting · Detach Content Windows · Select Next Tab · Select Previous Tab · Show Toolbar · Enter Full Screen
`Flow`: Repeat · Edit and Repeat... · Enable SSL Proxying for This Domain · Save Requests · Export ▸ (as Proxyman Log · as HAR (HTTP Archive) · as CSV · Publish to Gist...) · Add Comment... · Highlight ▸ (Red · Yellow · Green · Blue · Purple · Gray · Strikethrough · Reset) · Clear Session · Delete · Delete All
`Tools`: Toggle Recording · SSL Proxying List… · Compose Request… · Breakpoint ▸ (Rules… · Breakpoints… · Breakpoint Templates…) · Map Local… · Map Remote… · Block List… · Allow List… · No Caching · Protobuf… · Network Conditions… · TLS Key Logging… · Customize Previewer Tab… · Customize Columns… · Customize Toolbar… · Custom Previewer Tab… · Enable/Disable Tools ▸ (Breakpoint · Map Local · Map Remote · Block List · Allow List · Network Conditions · Scripting · SSL Proxying List · DNS Spoofing) · Import / Export Settings ▸ (Export (Backup)… · Import) · Proxy Settings ▸ (**Override macOS Proxy** · Bypass Proxy Settings… · Access Control… · Use External Proxy · External Proxy Settings… · SOCKS Proxy Settings…) · Reverse Proxy… · DNS Spoofing…
`Diff`: Open Diff View… · Add selected items to Diff Pool… · Left Side · Right Side
`Scripting`: Script List… · Beautify · Save and Activate
`Certificate`: Install Certificate on this Mac… · Install Certificate on iOS ▸ (Physical Devices… · Simulators… · watchOS or tvOS… · with Atlantis…) · Install Certificate on Android ▸ (Physical Devices… · Emulators…) · Install Certificate on Java VMs ▸ (Run Script...) · Install Certificate on Developments ▸ (NextJS (fetch)… · HTTP Clients… · Electron App… · Docker… · React Native… · Flutter… · Python… · Ruby… · NodeJS… · VPN…) · Install Certificate on Firefox Browsers… · Add Custom Certificates… · Export ▸ (Private Key... · Root Certificate as P12... · Root Certificate as PEM... · Root Certificate as DER...) · Reset all Proxyman Certificates
`Setup`: Automatic Setup… · Manual Setup…
`Window`: Stay On Top · Minimize · Minimize All · Zoom · Zoom All · Fill · Center · Move & Resize · Full Screen Tile · Bring All to Front · Arrange in Front · Remove Window from Set · <window title>
`Help`: Getting Started · Homepage… · Twitter… · Github… · Technical Documents… · Command Line… · Install 'proxyman-cli' Command in PATH · Send Private Message… · Report Bug?… · Copy Debug Info… · Lost Data?… · Troubleshooting · Advanced

Reading for aitmproxy: the override lives under Tools ▸ Proxy Settings ▸
Override macOS Proxy (⌥⌘O), SSL Proxying has three homes (Flow menu, Tools
menu, Response pane), and every certificate target is one menu.

## 3. Main window after the click pass

| Shot | What it shows |
|---|---|
| `03-sidebar-domains-expanded.png` | `Domains 9` expanded: one row per host with a disclosure glyph, hosts truncated in the middle; list filtered to the selected app |
| `04-sidebar-apps-expanded.png` | `System` and `Codex (Service)` expanded to the domains each talked to (`api.apple-cloudkit.com`, `chat.openai.com`); `codex` selected in the sidebar → window title `codex`, two rows |
| `05-row-codex-connect-200-selected.png` | a closed tunnel: `CONNECT` · green `200` · `Duration 360 ms`; Response pane `Enable only this domain (⌥⏎)` / `Enable all domains from "codex"` |
| `06-overview.png` | Overview page: `Live capture · Started 08:53:01 · 7m 20s`; cards `Requests 11 (1 in progress)`, `Data Transferred 2.02 KB`, `Errors 0`, `Average Duration –`, `Apps 8 (9 domains)`; charts Requests, Bandwidth, Status Codes, Top Apps (by data, with icons), Top Domains, Slowest Requests, `+ Add Chart (Response Times, Content Types, Errors by Domain…)`; `Share ▾` |
| `08-main-all-rows-200.png` | eleven rows after the tunnels closed: `Duration` in `ms`/`min`, every Client with icon, Status `200` green or `Active` amber |
| `23-main-reopened-new-session.png` | the main window right after a Reopen: a fresh session (one row), `Proxy Overridden` back in the status bar (see §5) |
| `34-main-final.png` | end of pass: `Apps 12` (`System, Mail, Claude Helper, Codex (Service), codex, trustd, Google Chrome, searchpartyuseragent, exchangesyncd, cloudd, nsurlsessiond, dataaccessd`), `Domains 10`, `1/33 rows selected`, `Proxy Overridden`. **Network Extension off and Pro-locked** (shot 30), so every one of these clients was named from the plain proxy connection (BUNDLE §4b). |

## 4. Panels and sheets (menu items, each closed with its own close button or Escape)

| Shot | Menu item | Words on screen |
|---|---|---|
| `07-ssl-proxying-list.png` | Tools ▸ SSL Proxying List… (⌘⌥P) | `☑ Enable SSL Proxying Tool`, `Define Clients or Domains (wildcard) that Proxyman will decrypt their HTTPS Request/Response.`, tabs `Include List` / `Exclude List`, `Intercept & Decrypt HTTPS in below list`, `Filter (⌘F)`, column `Name`, empty-state `⌘N: Add new apps` / `⇧⌘N: Add custom Domains / Wildcards`, `+ −`, `More ▾`, `Bypass Proxy Setting…`, `?` |
| `21-compose.png` | Tools ▸ Compose Request… | window `Compose`: method pill + `Enter URL/Paste cURL here (CMD + K)`, `SEND ⌘⏎`; Request `Header Query Body Raw Summary Connection Log`, `New Key… / New Value…`; Response `No Response Data`; footer `Template ▾ History ▾ ⋯` |
| `09-breakpoint-rules.png` | Tools ▸ Breakpoint ▸ Rules… | `☐ Enable Breakpoint Tool`, `Modify the Request/Response on the fly. Support URL, Method, Status Code, Headers, and Body.`, `Each request is checked against the rules from top to bottom, stopping when a match is found.`, columns `Name Method Matching Rule Request Response`, `Click "+" or ⌘N to add new entry`, `New: ⌘N Edit: ⌘⏎ Delete: ⌘⌫ Duplicate: ⌘D Toggle: ␣`, `New Folder`, `Show enabled`, `Filter`, `Templates…`, `More ▾` |
| `10-map-local.png` | Tools ▸ Map Local… | same shell: `Map a Response with a Local File or Directory. Support Status Code, Headers and Body.`, columns `… Map from` |
| `11-bypass-proxy-settings.png` | Tools ▸ Proxy Settings ▸ Bypass Proxy Settings… | `Bypass Proxy Settings for these List & Domain:` `dns.google,one.one.one.one,beacons.gvt2.com,beacons2.gvt2.com,ocsp.digicert.com`, `Support Wildcard (* and ?); Separate by Comma.`, `Reset to Default`, amber **`Helper Tool is not installed!`**, `Cancel`, `Done` (disabled: nothing changed) |
| `12-install-certificate-sheet.png` | Certificate ▸ Install Certificate on this Mac… | `Mac Setup Guide`, tabs `Automatic` / `Manual`; `Install and Trust Proxyman CA Certificate in Keychain Access`, `By installing and trusting Proxyman CA Certificate, Proxyman can decrypt encrypted traffic on the fly and enable to see raw HTTPS requests and responses`, blue **`Install & Trust`**, `(Require root privileges)`, `?` — not clicked |
| `13-automatic-setup.png` | Setup ▸ Automatic Setup… | `1-click to automatically set up HTTP Proxy & Certificate on a variety of dev environments`, `Capture HTTP(s) traffic from NodeJS, Python, Ruby, Terminal or Web Browser, etc`, `Safe. Work on your current session, not affect your OS`; `Terminal App` (`Use Apple Terminal ▾ and Open New Terminal… PRO`), `Web Browsers` (`Google Chrome… ▾`), `ElectronJS App` (`Select ElectronJS App…`), `How does it work?`, `Troubleshooting` |
| `14-manual-setup.png` | Setup ▸ Manual Setup… | `Terminal app` steps `1. Open your favorites Terminal app` · `2. Copy & Paste the following command line to your Terminal app` (`<🔒 Proxyman License is required to unlock PRO feature>`) · `3. Done ✅ Start your server or run scripts on your Terminal.` |
| `15-script-list.png` | Scripting ▸ Script List… | `☐ Enable Scripting Tool`, `Modify the Request or Response automatically with Javascript. Support URL, Status Code, Header, Method, and Body.`, `Advance ▾` |
| `17-protobuf.png` | Tools ▸ Protobuf… | `Protobuf Mapping Rules`, `Define Protobuf Message Type for each Protobuf Requests/Responses.`, columns `URL Method Payload Encoding Message Type`, `Protobuf Schema…` |
| `18-network-conditions.png` | Tools ▸ Network Conditions… | `☐ Enable Network Conditions`, `Simulate Network Conditions with various Preset Profiles. Useful to test with slow networks.`, orange `Only 1 Rule can be activated at once.`, columns `Enabled Name Status Host Network Profile` |
| `19-customize-columns.png` | Tools ▸ Customize Columns… | `Custom Header Columns — Get Headers, Query, JSON Body Value and display it as a Column.`; Request: Content-Type, Authorization, User-Agent, Accept, Accept-Language, Origin, Referer, Cookie, Cache-Control, Content-Length; Response: Content-Type, Cache-Control, Content-Encoding, Content-Length, ETag, Last-Modified, Location, Server, Set-Cookie, Access-Control-Allow-Origin, Vary; `How to use?` |

Not captured: the ⌘K palette (an overlay the window capture missed), Help ▸ Getting Started (opens the browser), the row context menu (the Flow menu carries the same verbs), the helper install sheet (it had been dismissed before the pass; its words are in FLOWS §1.3 and in Settings ▸ Advanced below).

## 5. Settings (⌘,), every tab

| Shot | Tab | Words on screen |
|---|---|---|
| `24-settings-general.png` | App ▸ General | `Content Layout: ◉ Vertical ○ Horizontal — Request and Response panels in Vertical or Horizontal Layout.`; `Menu Bar: ☑ Show Proxyman Icon on Menu Bar`; `Truncation Style: Tail ▾`; `Port Number: 9090`; **`☑ Auto Override System Proxy Settings at Launch`** `Override your System Proxy Settings in Wi-Fi -> Details… -> Proxies tab.`; `☑ Auto Start Recording Traffic at Launch — Record HTTP/HTTPS Traffic and display on the main table view.`; `☐ Use HTTP/2 — Proxyman prefer using HTTP/2 or fallback to HTTP/1.1`; `Advanced Proxy Setting…`; `App Behavior: ☑ Show Alert on Quit ☑ Show Update Notification at Launch`; `App Language: English ▾`; certificate image, **`Proxyman CA (not installed)`**, `Not Valid Before: –`, `Not Valid After: –`, `Generate new…`, `More ▾` |
| `25-settings-appearance.png` | App ▸ Appearance | `Font Size: 12`, `Tab Width: 2 Spaces PRO`, `☑ Use Monospaced Font — Apply to all tabs in the Request and Response Panel and the main table.`; `Body Tab: ☑ Word Wrap ☐ Show Invisibles ☐ Show Minimap PRO ☐ Scroll Beyond The Last Line PRO`; `Status Bar:` colour dots `PRO`; `Other: ☐ Alternative Rows Background Colors PRO ☑ Show Resource Usage in Bottom Bar — Include memory usage and upload/download speed.`; `Time Format: ☑ Use 24-Hour Time ☐ Display Full Time Format`; `App Theme: System / Light / Dark ✓`; `Proxyman Dock Icon: On Earth ✓ / On Mars 🔒 / Space Candy 🔒 / Classic 🔒`; `Restore Defaults` |
| `26-settings-privacy.png` | App ▸ Privacy | `Analytics: ☑ Share analytics with Proxyman`, `Crash Report: ☑ Share crash report with Proxyman`, `Powered by Sentry`, `Privacy Policy ↗` (both on by default) |
| `27-settings-mcp.png` | Integrations ▸ MCP `NEW` | `MCP Server`: `☐ Enable MCP Server` (disabled, 🔒 Pro) `Start a local HTTP server for Model Context Protocol (MCP) communication with AI tools like Claude.`, `⊗ Stopped`; `MCP Configuration` tabs `Claude Code / Codex / Manual`, `codex mcp add proxyman -- "/Applications/Proxyman.app/Contents/MacOS/mcp-server"`, `Copy`, `Run this command in Terminal to add Proxyman MCP to Codex.`; `Privacy: ☑ Redact Sensitive Data Before Sending to AI — Automatically redact sensitive information before sending to AI tools.`; `About MCP Integration: MCP (Model Context Protocol) allows AI assistants like Claude to interact with Proxyman. The AI can read captured HTTP traffic, create debugging rules (Map Local, Map Remote, Breakpoints), and help analyze network issues.`, `Learn more about MCP`, `Skill` |
| `28-settings-github.png` | Integrations ▸ GitHub | `Gist Permission: ⚠ Not Authorized Yet!`, `Authorize… PRO`, `Publish as: ◉ Private Gist ○ Public Gist ☑ Automatic redact sensitive headers`, `After Publish: ☑ Open Gist with default Web Browser ☐ Copy Gist URL to clipboard`, `Advanced: Manage Access` |
| `29-settings-tools.png` | Integrations ▸ Tools | `Copy: Default Copy Format cURL ▾`, `☑ Add --proxy to Copied Commands`, `☐ Preserve Original Request Headers`; `Replay & Diagnostics: ☐ Use No-Cache on Repeated Requests`, `☐ Append Proxyman Headers — Add diagnostic HTTP headers to messages handled by Map Local, Map Remote, and Scripting.` |
| `30-settings-network-extension.png` | Advanced ▸ Network Extension `BETA` | `Enable Network Extension` toggle (off, disabled), `✅ Capture HTTP and HTTPS traffic from your Mac, including apps that ignore proxy settings.`, `✅ No per-app proxy setup required.`, `Network Extension captures traffic at the system level, so it also catches apps that ignore proxy settings.`, `ⓘ Network Extension and the system proxy can't run at the same time. Turning on Network Extension turns off the system proxy.`, banner `Unlock Network Extension with Pro — Buy Pro to capture traffic from apps that ignore proxy settings.` `Buy Pro` |
| `31-settings-advanced.png` | Advanced ▸ Advanced | `System Proxy — Proxy Helper Tool: ⚠ Not Installed`, **`Your current HTTP/HTTPS Proxy is overridden by networksetup CLI.`**, `Install`, `?`, `☐ Restore the Previous HTTP/HTTPS Proxy When Proxyman Closes` (disabled) `Requires an installed Proxy Helper Tool. Restores the proxy configuration that was active before Proxyman.`; `Capture: ☑ Hide Apple Traffic from iOS Simulators`, `☑ Automatically Remove Older Requests Edit… — Remove older requests when memory exceeds 4 GB, at most once every 5 minutes.` |
| `32-settings-workspace.png` | Proxyman ▸ Workspace `NEW` | `Team Workspace — Collaborate with your team by sharing Proxyman logs and debugging sessions.`, `Login to Workspace`, `Available for Team Subscription only`, features Share Logs, Team Collaboration, Team License, Secure Access, Sync Settings `Soon` |
| `33-settings-products.png` | Proxyman ▸ Products | Proxyman for macOS / iOS / Android `NEW` / Windows / Linux; Other Products: `TCP Viewer — A lightweight Wireshark alternative for viewing TCP connections and identifying which apps are talking over the network.`, `TinyShield — A lightweight firewall that helps monitor and block outbound network connections.` |

## 6. System proxy readings and one incident

| When | `scutil --proxy` | Status bar |
|---|---|---|
| 08:53 launch by Matt | `HTTPEnable 1 / HTTPSEnable 1 → 127.0.0.1:9090` | `Proxy Overridden` |
| 08:55 (review session's read) | `0 / 0` | badge gone (shot 02) |
| 09:09 after the Reopen below | `1 / 1 → 9090` | `Proxy Overridden` (shots 23, 34) |
| 09:12 end of pass | `1 / 1 → 9090` | `Proxy Overridden` |

Incident: the panel pass closed each panel with "the close button of the
front window"; once the front window was the main window, so the pass closed
Proxyman's main window (process kept running, no quit, no data written). It
was brought back with an AppleScript `reopen` (what a Dock click does).
Proxyman treated the new session window as a launch and **re-applied the
system-proxy override**, because `Auto Override System Proxy Settings at
Launch` is still checked (shot 24). No Proxyman setting was changed by the
pass; the `Done` button of the Bypass panel stayed disabled and only `Cancel`
or close buttons were pressed. Lesson for our own harness: close panels by
name, never by index.

Reading for aitmproxy: "override at launch" in Proxyman means "whenever a
session window appears", and without the helper the revert on quit is
**disabled** (shot 31). Our system-proxy feature must revert on window
close as well as on quit, and must say so in one sentence where Proxyman
hides it behind a greyed checkbox.

## Checklist used for the pass

Main window
- [ ] main window, empty session (first second after launch)
- [ ] main window with traffic, Apps expanded (real icons), one app expanded to its domains
- [ ] Domains expanded, a host with a path disclosure
- [ ] a `CONNECT` row selected: Response pane with `Enable only this domain (⌥⏎)` / `Enable all domains from "<app>"`
- [ ] a decrypted row selected: Header / Body / Raw / Treeview; `+` → Custom Previewer Tab sheet
- [ ] chip bar overflow (`‹` / `›`), a saved-filter chip
- [ ] status bar with `Proxy Overridden` and `Breakpoint` badges
- [ ] row context menu; sidebar app row context menu (`Enable SSL Proxying`, `Pin to Favorites`)
- [ ] `⌘K` command palette
- [ ] layout glyphs: inspector right / bottom / hidden

Sheets and dialogs
- [ ] `Install Proxy Helper Tool / Version 1.7.0` sheet (do **not** click Install)
- [ ] `No HTTP Traffic?` alert (appears on its own after a silent start)
- [ ] `SSL Proxying List…` (⌘⌥P), Include / Exclude tabs
- [ ] Certificate ▸ `Install Certificate on this Mac…`, Automatic and Manual tabs (do **not** click Install & Trust)
- [ ] Compose window; Breakpoint rule editor; Map Local editor

Settings (⌘,)
- [ ] App ▸ General (`Port Number`, `Auto Override System Proxy Settings at Launch`, `Auto Start Recording Traffic at Launch`, `Use HTTP/2`, `Advanced Proxy Setting…`, `Proxyman CA` block)
- [ ] App ▸ Appearance (`Menu Bar: Show Proxyman Icon on Menu Bar`, `Status Bar`)
- [ ] App ▸ Privacy
- [ ] Integrations ▸ MCP (`Enable MCP Server`, `Redact Sensitive Data…`), GitHub, Tools
- [ ] Advanced ▸ Network Extension BETA (`Enable Network Extension`, do **not** click Install and Enable), Advanced (`Proxy Helper Tool:` row)
- [ ] Proxyman ▸ Workspace, Products

Menus
- [ ] every menu-bar menu dropped down (File, Edit, View, Tools, Certificate, Window, Help …)
- [ ] the menu-bar extra, if `Show Proxyman Icon on Menu Bar` is on

Rules for the pass: read-only. Never change a persistent Proxyman setting,
never install the helper, the CA or the extension, never leave Proxyman
running with the override on when done. One shot per state, ≤ 2 MB, named
`NN-<screen>-<state>.png` under `shots/proxyman/`.
