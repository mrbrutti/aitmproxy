# Proxyman reference screenshots — measured

Factual notes for the lead. Proxyman is not installed here; every shot below
came from proxyman.com / assets.proxyman.com / download.proxyman.com (official
hosts only). All measurements were taken with
`~/.claude/skills/design-from-app/scripts/measure.swift` (`info`, `hline`,
`vline`, `rows`, `cols`, `crop`). Colours are recorded only as *which role is
coloured*; Proxyman's orange is not ours (ours: `../../docs/design/tokens.json`).

Files live in `design/reference/`. Everything was converted to PNG (the sources
are JPEG/WebP, so expect a few steps of colour drift; sizes are unaffected).

## 0. How to read the numbers (scale calibration)

Proxyman's docs images are downscaled before upload, so `px / 2` is **not**
points for most of them. Each shot was calibrated against a macOS constant that
appears in it: the traffic-light centre spacing, which is **23.25 pt** on
macOS 26+ (measured on our own snapshot `docs/shots/apps-dark.png`, which is a
true 2x capture: red/yellow/green centres at 25.75 / 48.75 / 72.25 pt, Ø 14).
Where no traffic lights are visible, the standard 14 pt checkbox was used.

| Shot | traffic-light spacing (px/2) | factor to true pt |
|---|---|---|
| dashboard-home-dark | 23.0 | **1.00** (true scale) |
| dashboard-docs-hero-dark | 23.5 | 1.00 |
| scripting-dark | 23.0 | 1.00 |
| filter-bar-dark | n/a — checkbox = 14.0 | **1.00** |
| breakpoint-rules-dark | 22.8 | 1.02 |
| map-local-dark | 22.4 | 1.04 |
| breakpoint-editor(-raw)-dark, compose-dark | 22.0 | 1.06 |
| toolbar-dark | 19.8 | 1.17 |
| dashboard-dark, split-view-dark, command-palette-dark, dashboard-tahoe-crop | 19.0 | **1.22** |
| command-palette-v6-dark | 15.6 | 1.49 (marketing, layout only) |
| connection-log-dark, previewer-tabs-dark | none | unknown — content only |

Cross-check: the true-scale home shot gives a 24 pt flow row; the docs main
window gives 19.8 × 1.22 = 24.2; the filter-bar shot (checkbox-calibrated)
gives 24.0. Mono row text: 6.8 pt advance in both true-scale shots → 11 pt.
"True pt" below means `(px/2) × factor`, rounded to the nearest 0.5.

## 1. Screenshot inventory

| File | Source URL | px | pt (px/2) | factor | Theme | Shows |
|---|---|---|---|---|---|---|
| `dashboard-home-dark.png` | https://assets.proxyman.com/images/proxyman_dashboard_v6_dark.webp | 3168×1974 | 1584×987 | 1.00 | dark | Homepage hero: full main window (sidebar, flow list w/ zebra rows, selected row, summary strip, Request Raw / Response JSON body viewers, status bar). **Primary dashboard reference.** |
| `dashboard-dark.png` | https://proxyman.com/docs/assets/proxyman-main-window.jpg | 2600×1758 | 1300×879 | 1.22 | dark | Docs "main window" (v26, has *Capture › Overview* sidebar item, h1/h2 chips, JSON Path row, 50:50 Request/Response). **Primary inspector reference.** |
| `dashboard-docs-hero-dark.png` | https://proxyman.com/docs/assets/new_dashboard_macOS_26.jpg | 3756×2336 | 1878×1168 | 1.00 | dark | Docs index hero with marketing headline; shows Query tab as key:value table, long-URL summary strip wrapping to 3 lines, `Proxy Overridden` status pill. |
| `dashboard-tahoe-crop-dark.png` | https://download.proxyman.com/screenshots/6.0.0/new_ui_macOS_26.jpg | 1648×1014 | 824×507 | 1.22 | dark | Zoomed crop of the Tahoe toolbar + sidebar + first columns (marketing arrows). |
| `breakpoint-rules-dark.png` | https://proxyman.com/docs/assets/Screenshot%202026-06-28%20at%2019.24.05.jpg | 2764×1708 | 1382×854 | 1.02 | dark | "Breakpoint rules" window with the rule-edit sheet open (marketing headline on top). |
| `breakpoint-editor-dark.png` | https://proxyman.com/docs/assets/proxyman-breakpoint-window-edit-request.jpg | 2600×1747 | 1300×873.5 | 1.06 | dark | "Breakpoint" window paused on a POST; Header tab as editable key/value table; 3-button bar. |
| `breakpoint-editor-raw-dark.png` | https://proxyman.com/docs/assets/proxyman-breakpoint-raw-tab.jpg | 2600×1747 | 1300×873.5 | 1.06 | dark | Same window, Raw tab (editable HTTP message, validity line, Load from File / Templates). |
| `compose-dark.png` | https://proxyman.com/docs/assets/proxyman-compose-json-body.jpg | 2600×1686 | 1300×843 | 1.06 | dark | Compose window, POST with JSON body, 201 response, SEND button, Template/History bar. |
| `scripting-dark.png` | https://proxyman.com/docs/assets/proxyman-script-editor.jpg | 2486×1641 | 1243×820.5 | 1.00 | dark | Script Editor (v26): matching-rule card, Run on, editor + console, bottom bar with Templates. |
| `scripting-home-dark.png` | https://assets.proxyman.com/assets/images/home-2026/scripting.webp | 2718×1968 | 1359×984 | ~1.0 | dark | Older Script Editor (Snippet Code button) with marketing annotation; same layout. |
| `map-local-dark.png` | https://proxyman.com/docs/assets/proxyman-map-local-editor.jpg | 2332×1687 | 1166×843.5 | 1.04 | dark | Map Local Editor: rule card + Advanced Settings + Map To (Local File / Local Directory) + HTTP-message editor. |
| `filter-bar-dark.png` | https://proxyman.com/docs/assets/proxyman-multiple-filters.jpg | 2564×699 | 1282×349.5 | 1.00 | dark | Chip bar + two stacked filters + shortcut legend + filtered list. **True scale; best for column widths.** |
| `command-palette-dark.png` | https://proxyman.com/docs/assets/proxyman-command-palette.jpg | 2600×1758 | 1300×879 | 1.22 | dark | Command Palette over the main window; background shows the multi-select **Summary / Average Timing / Waterfall** view (dimmed). |
| `command-palette-v6-dark.png` | https://download.proxyman.com/screenshots/6.0.0/command_palette.jpg | 2400×1781 | 1200×890.5 | 1.49 | dark | v6 palette (orange selection) with marketing arrows. |
| `split-view-dark.png` | https://proxyman.com/docs/assets/proxyman-split-view.jpg | 2600×1758 | 1300×879 | 1.22 | dark | Split View: tab strip, two panes each with list + summary + Request/Response header tables + own status bar. |
| `toolbar-dark.png` | https://proxyman.com/docs/assets/proxyman-toolbar-layout-buttons.jpg | 2600×214 | 1300×107 | 1.17 | dark | Toolbar strip only (traffic lights, sidebar toggle, pause, compose/clear, listening pill, account, ⌘, four layout buttons). |
| `connection-log-dark.png` | https://proxyman.com/docs/assets/connection-log.png | 1276×1362 | 638×681 | ? | dark | Request › Connection Log tab (curl-style TLS/DNS log, coloured tokens). |
| `previewer-tabs-dark.png` | https://proxyman.com/docs/assets/proxyman-custom-previewer-tab-window.jpg | 1158×1651 | 579×825.5 | ? | dark | "Custom Body Previewer Tabs" popover: Request/Response checkbox columns (incl. Timing NEW, Connection Log NEW). |

### Not found (say so, do not substitute)

- **Light mode**: no light-mode macOS screenshot exists on proxyman.com, docs, or
  download.proxyman.com. Every official shot is dark. `inspector-light.png`,
  `filter-bar-light.png` therefore do not exist. (The foundation already takes
  the light register from the WebUI, not the native app.)
- **Overview dashboard** (26.2.0) and **redesigned Timing view / waterfall**:
  the only images are on the GitHub release page
  (https://github.com/ProxymanApp/Proxyman/releases/tag/26.2.0) as
  `private-user-images.githubusercontent.com` signed URLs that expire in 300 s —
  not an official Proxyman host, so not downloaded. The changelog page carries
  no images for 26.x. The only glimpse is the dimmed background of
  `command-palette-dark.png`: a "2 Requests Selected" summary with *Requests /
  Received / Errors* stat tiles, an **Average Timing** stacked bar with rows
  Queued · DNS lookup · Connecting · TLS handshake · Request sent · Waiting for
  server · Downloading, a **Slowest Requests** list, and a **Waterfall** chart
  (GET /users/1 437 ms, GET /users/2 224 ms) with a legend "Connection &
  upload · Waiting for server · Downloading". No per-request Timing tab shot.
- **Dedicated inspector-only shot**: none; inspector numbers below come from
  `dashboard-dark.png` and `dashboard-home-dark.png`.
- `docs.proxyman.com` 301-redirects to `proxyman.com/docs/`; it is the same site.

## 2. Main dashboard (`dashboard-home-dark.png`, true scale; cross-checked with `dashboard-dark.png` × 1.22)

Window ≈ 1461 × 874 pt (home) / ≈ 1425 × 912 pt (docs). Three regions:
sidebar · flow list over inspector · (toolbar above, status bar below).

### Shell bands (true pt)

| Band | Proxyman | note |
|---|---|---|
| toolbar | **44** (home 39→81 = 42 + hairline; docs 36 × 1.22 = 44; toolbar crop 37 × 1.17 = 43) | Tahoe glass toolbar; title bar and toolbar are one row |
| content-type chip bar | **44** (home 81→126; docs 36 × 1.22) | chips 20 tall, selected = rounded-rect raised fill (radius ≈ 5, not a pill), 13 pt text; groups separated by 1 pt vertical rules: `All \| HTTP HTTPS WebSocket \| JSON Form XML JS CSS GraphQL Document Media Other \| h1 h2 \| 1xx…5xx ›`; `⊜` filter toggle at far right |
| column header | **27–28** (home 126→153.5; filter shot 169.5→197) | 13 pt UI face, grey; 0.5 pt vertical column rules; sort indicator on `#`/`ID` |
| flow row pitch | **24** (home 167/191/215…; filter 198/222/246/270; docs 19.8 × 1.22) | **zebra**: alternating two surface tones, no hairline separators; selected row = full saturated accent fill with white text, 23 tall inside the 24 pitch |
| status dot | **10** (filter 10; docs 8.5 × 1.22) | column ≈ 28 wide, dot centred |
| summary strip (`GET · 200 OK · URL`) | **35** (home 408→442; docs 28.5 × 1.22 = 34.8) | pills 18 tall (GET pill 75 wide, `200 OK` 85 wide, 6 gap), URL 13 pt mono, host plain / path coloured; wraps to 3 lines for long URLs (docs-hero shot) |
| tab bar | **30** (home 443→474; docs 24.5 × 1.22) | pane title 13 pt **bold**, tabs 13 pt regular, active tab coloured text, **no underline**, `+` after tabs, `⊜` at right; Response side adds a `JSON ⌄` format popup |
| JSON Path / jq row (Body tab only) | 26 (docs 21 × 1.22) | `JSON Path ⌄` popup · 🔍 field · `Save` |
| body viewer | — | 12 pt mono, **18 pt line pitch**, line-number gutter ≈ 40 incl. fold chevrons |
| status bar | **34** (home 877.5→911.5; docs 27.5 × 1.22 = 33.5) | left: three small bordered buttons `Clear` `Filter` `Auto Select` (13 pt, ≈ 24 tall); centre `1/56 rows selected`; right `· 196 MB ↑ 6 KB/s ↓ 3 KB/s` (12 pt) and optional `Proxy Overridden` pill |
| sidebar | **247** (home) / **225** (docs 184 × 1.22) — user-resizable | translucent tint; section headers `Capture`, `Favorites`, `All` (small grey); rows 24 pitch, 13 pt, selection pill 24 tall full-width; counts right-aligned; bottom `+` and `Filter (⌥⌘F)` field |
| sidebar row pitch | **24** | |
| Request \| Response split | **50 : 50** (docs 491.5 : 490) | home shot 46 : 54 (user-dragged); 1 pt dark divider |

### Columns (left edges of header text, true pt from the list's left edge; filter-bar shot, cross-checked with docs × 1.22 and home)

| col | start | width | content |
|---|---|---|---|
| ● (dot) | 0 | 28 | 10 pt dot: green done, amber active, red error |
| `#` | 36 | 42 | right-aligned id, mono 11 |
| URL | 78 | 353–390 (flex) | full URL, mono 11, truncates with … |
| Client | 465 | 143–190 | 16 pt app icon + name (UI face 13) |
| Method | 608 | 74 | 18 pt tinted pill, 11 pt bold mono caps |
| Status | 682 | 77 | 18 pt tinted pill (`200` green, `404` red, `Active` amber) |
| Time | 759 | 93 | `10:13:19.317` mono 11 |
| Duration | 851 | 79 | `244 ms` / `2.41 s`, right-aligned |
| Request | 930 | 73 | `120 bytes` / `–` |
| Response | 1002 | 73 | `751 bytes` / `7,9 KB` |
| SSL | 1075 | 31 | open-padlock glyph |
| Edited | 1106 | 46 | pencil glyph when modified |
| Tools | 1152 | 35 | tool glyph |

(`dashboard-docs-hero` shows an older column set with `Status` as text
`Completed` and a separate `Code` column; v26 merges them into the `Status` pill.)

### Text sizes (derived per `measuring.md`: same word measured in both images)

| Role | Proxyman | method |
|---|---|---|
| flow-row data (URL, time, sizes) | **11 pt mono** | glyph advance 6.8 pt over 22/33-char URLs in two true-scale shots; asc+desc band 11 |
| column header | **13 pt UI** | `Client` cap height 9.0 (SF Pro cap = 0.705 em) |
| pane title `Request` | **13 pt bold** | word width 50.5 vs ours 61 at 16/600 → 13.2; band 12 (R→q) |
| tabs `Header Query Body …` | **13 pt** | `Header` width 40.5, cap 9 |
| sidebar labels | 13 pt | band 12–12.5 for `Proxyman`/`Domains` |
| body viewer code | 12 pt mono, 18 pt lines | digit height 8.5–9, pitch 18 |
| badge text | ≈ 11 pt bold mono | inside 18 pt pill |
| status bar | 13 pt buttons, 12 pt meta | `Clear` band 10.5 |

### Toolbar contents (`toolbar-dark.png`)

Sidebar column (tinted) holds traffic lights + sidebar toggle. Main: `⏸`
(single glass button) · `[✎ 🗑]` grouped · centred listening pill
`● Proxyman | Listening on 192.168.64.4:9090` (≈ 28 tall, pill radius, green
dot) · right: `👤` · `⌘` (palette) · group of four layout buttons (split view,
detach, horizontal, vertical). Buttons ≈ 36 round glass.

## 3. Breakpoint rules window + edit sheet (`breakpoint-rules-dark.png`, ×1.02)

- Window ≈ 1300 × 690: title `Breakpoint rules`; `☑ Enable Breakpoint Tool` +
  two 13 pt grey description lines; rules table with columns
  `Name (☑ + name) | Method | Matching Rule ("Wildcard: https://…") | Request ☐ | Response ☑`,
  header at 234, row pitch **24**, zebra; shortcut legend line
  `New: ⌘N  Edit: ⌘↩  Delete: ⌘⌫  Duplicate: ⌘D  Toggle: ␣` (12 pt grey);
  bottom bar: `[+ −] [New Folder] [?]` … `[🔍 Filter] [Templates…] [More ⌄]`.
- Sheet: **788 × 274**, radius ≈ 12, label column right-aligned 138 wide,
  field column 631. Fields top→bottom (row pitch ≈ 30):
  1. `Name:` text field 22 tall (focused, accent ring)
  2. `Matching Rule:` text field
  3. `[GET ⌄] [Use Wildcard ⌄]  Support wildcard * and ?.  Test your Rule` (link)
  4. `☐ Include all subpaths of this URL ⓘ`
  5. `Set Flag [● Purple ⌄]`
  6. `Breakpoint: ☐ Request  ☑ Response` + helper line
     "Start the breakpoint for out-going request or in-coming response."
  7. Buttons right-aligned: `Cancel` (96 × 25) · `Done (⌘↩)` (100 × 25, accent fill)

## 4. Breakpoint editor window (`breakpoint-editor-dark.png`, `-raw`, ×1.06)

Window ≈ 1380 × 880. Vertical layout (true pt):

| Band | height | content |
|---|---|---|
| title bar | 30 | `Breakpoint` |
| paused-request table header | 28 | `# · URL · Client · Method · Status · Code · Time · Duration · Request · Response · Query Name` |
| table rows | 19.5 pitch (18.5 × 1.06), zebra; paused row 24 highlighted | row shows green `↑` arrow, `POST` pill, `Active` badge |
| rules bar | 37 | left `[Manage Rules]`; right `[⊟ layout]` `[More ⌄]` |
| URL strip | 44 | `POST https://httpbin.proxyman.app/anything/v1/users?page=1` mono 14-ish, host/path coloured, share icon right |
| tab bar | 30 | `Request` · `Header` Query Body Auth \| Raw Summary Connection Log · `⊜` |
| key/value header | 27 | `Key \| Value`, key column ≈ 22 % of width |
| key/value rows | **24.5** pitch | `☑` (18 pt accent checkbox) · key mono 12 · value mono 12 · `🗑` right; trailing `New Key… / New Value…` placeholder row |
| button bar | 37 | left `[→ Continue Original ⌄]` 183 × 25, `[⊗ Drop Connection ⌄]` 148 × 25; right `[▶ Apply & Execute ⌄]` 159 × 25 (split buttons with `⌄` menus) |

Raw tab: status line `● Valid Request HTTP Message` (green dot) with
`[Load from File…] [Templates ⌄]` right, then a line-numbered editor
(12 pt mono, ≈ 18.5 line pitch; method/version/header names coloured).

## 5. Compose (`compose-dark.png`, ×1.06)

Window ≈ 1380 × 800. Title `Compose: https://…`. Top row **31** tall:
`POST` (coloured) + URL mono, right: share icon · `✓ 201 Created` (green) ·
`⏱ 283 ms` · `[SEND ⌘↩]` accent button ≈ 104 × 26. Panes **56 : 44**
(Request 650 : Response 513 in shot pt): Request tabs `Header Query Body | Raw
Summary Connection Log GraphQL · ⊜`; Response tabs `Header Body Raw | Treeview +`
with `JSON ⌄ ⊜` and a `jq ⌄ 🔍 … Save` filter row (≈ 26). Editors 12 pt mono,
≈ 18 line pitch. Bottom bar **37**: `[Template ⌄] [History ⌄] [⋯]`.

## 6. Script editor (`scripting-dark.png`, true scale)

Window **1118 × 695** (content). `Matching Rule` label 13; raised card
92→314 (222 tall): `Name:` field 24 tall, `URL:` field 24, then
`[POST ⌄] [Use Wildcard ⌄]  Support wildcard * and ?.  Test your Rule`,
`☐ Include all subpaths of this URL ⓘ`, `Set Flag [None ⌄]`; form row pitch
≈ 31–34. Below the card: `Run Script on: ☑ Request ☑ Response | ☐ Run as Mock
API  Hint: Use Proxyman MCP to generate Scripts faster!` then
`● Saved and Active!` (green dot). Editor 387→724 (337 tall) with line
numbers, 12 pt mono, 18 line pitch; **editor : console = 72 : 28**
(804 : 312); console shows `Empty Console / Use console.log() to log events`.
Bottom bar **32**: `[More ⌄] [Beautify (⌘B)] [{} Templates] [Use \`npm install\`]`
… `[Save & Activate ⌘S]`; console side `[👁 ⌄]` … `[🗑] [⊟]`.
(`scripting-home-dark.png` is the pre-26 variant: `Snippet Code` instead of
`Templates`, no MCP hint; otherwise identical.)

## 7. Map Local editor (`map-local-dark.png`, ×1.04)

Window ≈ 1213 × 875. Same matching-rule card as the script editor plus a
hairline and `Advanced Settings: Delay Response: [No Delay ⌄]`. Then `Map To`
label, centred segmented control `[Local File | Local Directory]` (accent on
active), card: `☑ Enable Local File`, `File: /Users/Shared/Demo/user.json`,
`● Map Response with HTTP Message format (Saved)`, HTTP-message editor with
line numbers (status line `HTTP/1.1 200 OK` coloured). Bottom:
`[Select Local File]  Accept HTTP Message Format or Local File [?]` …
`[⚙ ⌄] [Save ⌘S]`.

## 8. Filter bar (`filter-bar-dark.png`, true scale)

Chip bar as §2 (here also shows `h1 h2 | 1xx 2xx 3xx 4xx 5xx ‹` and `⊜`).
Filter block **≈ 80 tall** for two filters + legend, rows **24–25** pitch:
`☑ (14) [Field popup 163 wide: URL ⌄] [Operator popup 143 wide: Contains ⌄]
[🔍 value field … ⊗] [−] [+]`; popups 22 tall (standard). Third line:
`[AND all filters ⌄]` (125 wide) + legend `Show: ⌘F  New: ⌘N  Remove: ⇧⌘N
Up: ⌘↑  Down: ⌘↓  On/Off: ⌘B  Hide: ESC` (12 pt grey) + `[Save]` right.
Then column header 27.5 and 24 pt rows; selected row = full accent fill
(blue in v26 shots, orange in v6).

## 9. Command palette (`command-palette-dark.png` ×1.22; `-v6` for colour)

Panel **≈ 620 wide × 745 tall**, top edge ≈ 70 below window top, radius ≈ 12,
window behind dimmed. Search field ≈ 53 tall (`🔍 simulator … ⊗`); tag chip
row 25 tall pills (`iOS Android Setup Guide Debugging Tools Web Browser Backend
Frontend Node…`, horizontally scrolling); result cards: 40 pt icon tile · title
13 bold · 12 pt description (2 lines) · two small tag pills · `☆` right;
selected card **112** tall with tint + 1 pt accent border, others **96**,
pitch ≈ 105. v6: selected card and selected tag chip carry the accent.

## 10. Split view (`split-view-dark.png`, ×1.22)

Under the chip bar a **tab strip ≈ 28** tall: `‹ ›` then tabs `Apps |
httpbin.proxyman.app | httpbin.proxyman.app` (segments ≈ 160–265 wide, active
lighter) and `+`. Two panes **50 : 50** (488 : 490); the active pane has a
1 pt accent border. Each pane: list with `# · URL · Client` only, summary
strip, `Request | Response` side by side as **key : value header tables**
(header 27, rows 24 pitch, long values wrap), and its own status bar
(`🗑 Clear  ≡ Filter  Auto Select · 1/14 rows selected · 213 MB ↑ 0 KB/s ↓ 0 KB/s`).

## 11. Connection log / previewer tabs (content only, scale unknown)

- Connection Log tab: curl-style `*`/`>` lines with line numbers; hosts/IPs in
  accent, TLS handshake steps bold, warnings in the warning hue, request line
  method in green and version in red.
- Custom Body Previewer Tabs popover: two checkbox columns (Request / Response)
  — JSON, JSON Treeview, Form URL-Encoded, Multipart/form-data, HTML, HTML
  Webview, CSS, Javascript, XML, Images, Hex, Protobuf, MessagePack, M3U8
  (HLS), Comment, Summary, Connection Log *NEW*, Code Generator, GraphQL,
  Timing *NEW* | … SSE, OpenAI (auto-merge); `☑ Auto beautify the minified
  content`; `[? ] … [+ Add Custom Tabs]`.

## 12. Our build, measured the same way (`docs/shots/apps-dark.png`, 1440 × 900, true 2x)

| Band | foundation §2.4 | ours (measured) | Proxyman (true) |
|---|---|---|---|
| toolbar | 44 | **52.5** (system Tahoe toolbar) | 44 |
| chip bar | 36 | 35 | **44** |
| column header | 28 | 27 | 27–28 |
| flow row | 28 dense | 28 | **24** (zebra, no rules) |
| summary strip | 40 | 40 | **35** |
| tab bar | 36 | 35 | **30** |
| intercept bar | 40 | 40 | n/a (separate Breakpoint window) |
| status bar | 28 | 27.5 | **34** |
| sidebar | 240 | 240 | 225–247 |
| sidebar row | — | 28 | **24** |
| status dot | 8 | 9 | 10 |
| badge | 18 | 18 | 18 |
| row data text | 13 mono | ≈ 13–14 mono (advance 8.2) | **11 mono** |
| column header text | 12 | 12 (cap 8) | **13** |
| pane title | 16 / 600 | 16 / 600 (`Request` 61 wide) | **13 bold** (50.5 wide) |
| tabs | 13 | 13 | 13 |
| body code | 13 / 20 | 13 / 20 | 12 / 18 |
| Request \| Response | 50:50 | 50:50 | 50:50 |

## 13. Differences from our build worth closing (facts only; the lead decides)

Ordered by how far they move the look.

1. **Row density.** Proxyman's flow list is 24 pt rows with 11 pt mono data and
   zebra striping; ours is 28 pt with 13 pt mono and hairline separators
   (foundation "dense 28"). The sidebar follows the same 24 pt pitch (ours 28).
   Proxyman's 24 is denser than our *dense* setting.
2. **Inspector chrome is shorter.** Summary strip 35 (ours 40), tab bar 30
   (ours 36), pane title 13 bold (ours 16 semibold), body code 12/18 (ours
   13/20). Tabs have no underline; the active tab is only coloured text.
3. **Status bar is taller, chip bar is taller.** Status bar 34 with bordered
   `Clear / Filter / Auto Select` buttons (ours 28, text buttons); chip bar 44
   with 20 pt rounded-rect chips (ours 36, pills). Column header 28 matches.
4. **Toolbar.** Proxyman renders 44 (matches the foundation); ours renders
   52.5 because the Tahoe system toolbar sets its own height.
5. **Column header text is 13 pt, not 12,** and the header carries 0.5 pt
   vertical column rules; the `Client` cell is an app icon + name in the UI
   face, and `Status` is an 18 pt pill (`200`, `404`, `Active`), not plain text.
6. **Selected row** is a full saturated accent fill with white text (we use a
   quiet tint by decision — foundation §2.1; not a bug, noting the contrast).
7. **Breakpoint is a separate window**, not an inline bar: paused-request table
   + editable key/value table (24.5 pt rows, accent checkboxes, trash per row)
   + a 37 pt bar with three split buttons (`Continue Original`, `Drop
   Connection`, `Apply & Execute`). The *rules* live in a second window with a
   788 × 274 sheet whose field order is Name → Matching Rule → Method/Wildcard
   → subpaths → Set Flag → Request/Response. Our intercept bar + "editing"
   inspector mode is a different pattern.
8. **Filter bar** is a stacked block (≈ 80 tall for two rows, 24–25 row pitch,
   popups 163 / 143 wide, `AND all filters` popup, shortcut legend, `Save`);
   ours currently shows only a `Filters ⌄` affordance in the chip bar.
9. **Scripting / Map Local dialogs** share one matching-rule card (Name, URL,
   method + wildcard popups, subpaths, flag) with 24 pt fields and ≈ 31 pt
   row pitch; editor:console is 72:28 with a 32 pt bottom bar. Ours have no
   equivalent yet (M3), but the foundation §2.6 script-editor description
   matches this layout.
10. **Not verifiable from the web**: the Overview dashboard, the per-request
    Timing tab, and any light-mode native screen. Only the multi-select
    Summary/Waterfall is partially visible (dimmed) behind the command palette.
