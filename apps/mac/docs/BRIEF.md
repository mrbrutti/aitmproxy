# Aitmproxy

The native macOS operator surface of aitmproxy, an intercepting proxy for authorized security testing: one operator (Matt) watches, inspects and steers live traffic while an AI agent works over MCP under his supervision. Bundle `com.mrbrutti.aitmproxy`. Foundation: `docs/design/operator-ui-foundation.md` (approved 2026-10-28), `tokens.json`, `mockup/index.html`.

## Replaces
mitmproxy's console and Proxyman, for this workflow: the flow list, the intercept/edit/resume loop and the compose sheet are theirs; the scope, PoC, browser and agent panels are ours.

## Main jobs
1. Watch and inspect live flows: dense list, Request | Response inspector, body viewers.
2. Intercept, edit and resume (or kill) a paused request; set breakpoint rules.
3. Compose and repeat requests; import cURL.
4. Run and review PoCs: findings, YAML, capture, screenshot, assertions.
5. Supervise the agent (policy, activity log, one-time approvals) and the scope (what is authorised).

## Data
Flows live in the proxy and are never persisted by the app; the app is a bus client (`flow.*`, `request.send`, `scope.*`, `poc.*`, `browser.*`, `ca.*`, later `agent.*`).
- FlowRow / FlowDetail: what `flow.get` and (F5) `flow.detail` return; cached in memory for the session only.
- Pins: hosts and apps pinned to Working.
- Saved filters: name, FilterStack (rows + AND/OR), expression text.
- Compose history: sent `RequestEdits`, newest first, capped.
- Layout: column order/widths/hidden, inspector layout, sidebar width, density, settings tab.
- Bus settings: from `config.yaml` or host/port/token file.

## Shape
Sidebar window, macOS 26 or later. Connects to a local `aitm` over loopback TCP (JSON-RPC/MCP, token line first); may later spawn `aitm` itself. Needs the network: loopback only. No accounts. App-local state in `~/Library/Application Support/Aitmproxy/`.

## System hooks
⌘K command palette (built from `tools/list`); menu bar commands with shortcuts for every action; drag-and-drop import of HAR/flows (later); Shortcuts and CLI (later).

## Reference
Proxyman (native dashboard for dark and density, WebUI for light and semantics) and mitmproxy's single-key verbs and filter expressions.

## Look
Own parts per the foundation: flat panels, Proxyman density (28 px mono rows), blue accent, amber intercept, teal agent; data in SF Mono, chrome in SF Pro; colour on data, not chrome; the armed-intercept bar is the only saturated fill. Two rules from Matt (2026-10-27 evening) override the foundation where they conflict:
- **Flat minimal icons.** Monochrome SF Symbols everywhere; no glass capsules, chrome, bevels or tinted discs. The window toolbar hides its shared background.
- **Editorial restraint.** Typography-forward hierarchy (tracked small caps for groups, 16/600 pane titles), generous whitespace, hue only on data, calm chrome and empty states. The flow list alone stays dense.

## Design plan
- **Archetype.** Sidebar window: sidebar | toolbar / chip bar / flow list / intercept bar / inspector, status bar across the bottom. Layouts: inspector below (default), right, detached window, split view. Sheets for compose, scope, rules and PoC; side panel for the activity log; floating palette.
- **Information architecture.** Groups by the operator's jobs; the brand row is the product mark only. Connection state has one home, the toolbar's connection cluster — the pill (core dot + address; click → Status page, also ⌘0) and the Proxy and Capture switches — and appears nowhere else (not the sidebar, not the status bar). *Traffic* (the main work window): Flows, Apps (one sub-item per client), Domains (one per host), Pinned (hosts/apps), Connections, Overview. *Testing*: Scope, Scan, Findings, Browser. *Automation*: Scripts, Agent. Status (core, bus and capture extension with their controls and the getting-started list) is the landing page on a fresh install, then the last page; Saved returns under Traffic once the core can save. Counts only on queues (Scope, Findings, paused) and flow groups. Settings: General, Bus, Proxy, Capture, Appearance.
- **Command map.** Menu ▸ action — shortcut (list key in parentheses where the foundation gives one).
  File ▸ Compose Request… — ⌘N (`n`) · Import… — ⌘O · Export Selection… — ⌘E · Save Session — ⌘S · Clear Session — ⌘⌫.
  Flow ▸ Arm/Disarm Intercept — `i` · Resume / Apply & Resume — ⌘⏎ · Resume All — ⌥⌘⏎ · Kill… — ⌘\ · Edit Paused Request — `e` · Revert to Original — ⌘Z (in editor) · Replay — `r` · Edit & Replay — ⇧R · Kill/Delete — `d` · Mark — `m` · Comment… — ⌘L (`c`) · Pin Host — ⇧P · Build PoC from Flow… — `p` · Add Host to Scope… — ⇧S · Copy as cURL / httpie / Python / fetch — ⇧⌘C · Diff Selected — ⌘D · Quick Look Body — Space · Focus Inspector — ⏎.
  View ▸ Filter Bar — ⌘F · Sidebar Filter — ⇧⌘F · Command Palette — ⌘K · Find in Body — ⌥⌘F · Chips — ⌘1…⌘9 · Inspector Below / Right / Detached / Split View — ⌘⌥1…4 · Toggle Sidebar — ⌃⌘S · Pause/Resume Proxy — ⇧⌘R · Auto-select — ⇧⌘A · Density — Dense/Default/Comfortable.
  Agent ▸ Allow All Tools / Read-only / Paused — radio · Activity Log… — ⇧⌘L · Approve Pending Request — ⌥⏎.
  Proxy ▸ Status — ⌘0 · Scope… — ⇧⌘O · Breakpoint Rules… — ⇧⌘B · Trust the aitmproxy CA — ⌃⌘T · Set as / Restore System Proxy — ⌥⌘P · Certificate Authority… · Configuration… · Browser — ⇧⌘W · Core Log… — ⌃⌘L · Reconnect Bus — ⌃⌘R · Restart Core — ⌃⇧⌘R · Capture / Stop Capturing All Apps — ⌃⌘A.
  Every action also lives in the palette and (where it acts on a row) in the row's context menu.
- **Empty states** (frame kept, trade's words, no illustration). Flow list: "No flows yet — point a client at 127.0.0.1:8080 or open the browser." / filtered: "No flows match — clear the chip or the filter." Intercept bar armed: "Intercept armed — every request pauses here" / "Nothing paused." Inspector: "Nothing selected — select a flow to inspect it, or press ↑ ↓." Findings: "No findings — build a PoC from any flow with p." Scope: "No hosts in scope — add one to authorise testing; everything stays read-only until then." Pinned: "Nothing pinned — press ⇧P on a row." Saved: "No saved sessions." Browser: "No tabs — open a page with ⌘T." Scripts: "No scripts loaded." Agent/Activity log: "No agent connected" / "No activity yet." Bus: "bus offline — start aitm or set the address in Settings ▸ Bus."
- **Feeling.** Calm, precise, in control. No entrance motion; keyboard actions never animate; new rows land without animation; the only pulse is the armed-intercept dot (off under Reduce Motion).

## Not in version one
- Remote or web bus (F15): loopback only.
- Team, sharing, accounts, sync, analytics.
- Script editor beyond a list with enable toggles, unless F8 lands.
- Network-Extension capture; iOS/Android device capture beyond setup text.
- Custom columns from headers/JSON paths; Map Local/Remote/Block/Throttle forms.
