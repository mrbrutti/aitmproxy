# aitmproxy operator-UI foundation

**Status:** draft for Matt's approval, 2026-10-27. Design only; nothing here is built.
**Companions:** [`tokens.json`](tokens.json) (the values), [`mockup/index.html`](mockup/index.html) (the primary screen, open it in a browser).
**Scope:** the shared foundation that the three human-operator surfaces — the native macOS app, the web UI, and the terminal UI — each implement. They share one feature set, one look within each platform's limits, and one way of talking to the proxy. This document is the single source of truth for all three; a surface that departs from it says so in its own spec.

Sections: 1 Principles · 2 Design language · 3 Feature catalog · 4 Command-bus contract · 5 Core follow-ups · 6 Open questions for Matt · A Proxyman recent features.

---

## 1. Principles

1. **One bus, three faces.** Every surface is a client of the command bus, exactly as the MCP agent is (platform spec: "frontends are clients of the core"). A surface never reaches into the core; if it needs something the bus does not offer, that is a core follow-up (§5), not a side channel.
2. **Proxyman's look, aitmproxy's identity.** Layout, density, badges, chip filters, the Request | Response split, the status bar: copied from Proxyman (its WebUI for the light register, its native dashboard for the dark one). What is ours: a blue accent instead of Proxyman's orange, an **amber** intercept state that cannot be missed, a **teal** agent presence, and the PoC/scope/browser/agent panels no proxy has.
3. **Colour goes on data, not chrome.** Method, status, severity and syntax carry hue. Chrome is neutral; the accent touches the active tab, the focus ring, the selection tint and the product mark (≈3% of pixels). The one exception is the armed-intercept bar: a saturated amber fill, because a paused request is the one state an operator must never overlook.
4. **The human and the agent share the controls, visibly.** Every agent-originated action (a replay, a mutation, a PoC run, a scope change) is marked in teal in the flow list and the activity log, and the operator can pause the agent with one toggle. Neither party acts invisibly.
5. **Dense, monospaced data; quiet, system-font chrome.** URLs, headers, bodies, times, sizes, ids: monospace, 13px, 28px rows. Labels, titles, controls: the platform's text face. The TUI keeps the same hierarchy with bold/dim.
6. **Degrade honestly.** A feature a platform cannot carry (an inline image in a terminal) is shown as what it is — a sized placeholder with an "open externally" action — never silently dropped. §3 marks every limit.

---

## 2. Design language

### 2.1 What we take from each reference

| Reference | Register | We copy | We change |
|---|---|---|---|
| Proxyman native dashboard (dark, macOS) | **Dark mode, density** | Three regions (sidebar / flow table / inspector); status-dot column; `#` + URL + Client + Method + Status + Time + Duration + Request + Response + SSL + Edited columns; content-type chip bar; the `GET · 200 OK · URL` summary strip over a side-by-side Request \| Response; pane title + plain tabs + `+`; Monaco-style body viewer with line numbers and fold chevrons; `Clear / Filter / Auto Select` status bar with row count and throughput; centred "Listening on host:port" pill | Selection: Proxyman fills the row with saturated orange; we use a quiet accent tint (the WebUI's and the app-screen study's convention). Orange → blue accent. |
| Proxyman WebUI / Workspace viewer (light) | **Light mode, semantics** | Off-white page, white surface, hairline rules; semantic **method badges** (blue GET, green POST, amber PUT, red DELETE); status text coloured by class; URL host in ink and path in the accent; blue underlined active tab; `N rows` meta chip; key : value header tables | Two-line card rows become the *narrow* layout only; the desktop default stays Proxyman-native dense rows. |
| Proxyman Script Editor (dark) | **Rule/script dialogs** | Matching rule form (name, URL, method, wildcard/regex, "Test your rule", subpaths, flag); "Run on ☑ Request ☑ Response ☐ Mock"; "● Saved and Active"; editor + right-hand console; bottom bar `Beautify · Snippets · Save & Activate ⌘S`; shortcuts printed in labels | Language is Rhai (M3), not JS; the console shows the plugin chain's log for that script. |
| mitmproxy console | **TUI idioms** | `:` command line; single-key verbs (`i` intercept filter, `e` edit, `r` replay, `d` delete, `m` mark, `n` new); filter expression language; flow list → flow view → edit; intercepted rows highlighted | Colours from our tokens' ANSI map; the inspector's tab vocabulary matches ours, not mitmproxy's. |

### 2.2 Palette

Values live in [`tokens.json`](tokens.json) (`color.*`); this is the reading guide. Every text tier holds ≥ 4.5:1 on its surface in both modes.

**Neutrals**

| Role | Light | Dark | Used for |
|---|---|---|---|
| page | `#F7F8FA` | `#161618` | window ground behind panels |
| surface | `#FFFFFF` | `#1E1E20` | the flow table, inspector panes, sidebar |
| raised | `#F3F4F6` | `#262628` | chips, wells, status bar, group headers |
| active | `#E8EEFB` | `#2B3344` | selected row / selected sidebar item (accent tint, never the full accent) |
| hover | `#F3F4F6` | `#232325` | hover; never moves selection |
| border | `#E5E7EB` | `#2E2E31` | panel edges, splitters, the rule under tab bars |
| rule | `#F0F1F3` | `#252527` | row separators (one step lighter than border) |
| control | `#D1D5DB` | `#45454A` | input/select/outlined-button borders |
| text.primary | `#111827` | `#E6E6E8` | hosts, header names, values, titles |
| text.secondary | `#4B5563` | `#B4B4B8` | column headers, labels, times |
| text.tertiary | `#616A78` | `#8E8E93` | placeholders, meta (the floor: 4.7:1 on raised) |
| text.link | `#1D4ED8` | `#7DB2F8` | URL path, links (accent's deep shade in light so it holds on the selected tint) |

**Hues — each has one job**

| Role | Light | Dark | ANSI | Job |
|---|---|---|---|---|
| **accent** | `#2563EB` | `#60A5FA` | blue | active tab, focus ring, selection tint, URL path, product mark. From the WebUI's tab blue. |
| **intercept** | `#D97706` | `#F5A524` | yellow | armed-intercept bar fill, paused rows, the `Active`/pending dot. Proxyman's amber; mitmproxy's highlighted intercepted row. |
| **agent** | `#0D9488` | `#2DD4BF` | cyan | the Agent toggle, the left-edge tick on agent-originated flows, agent entries in the activity log. Shared with nothing else. |
| method.get | `#1D4ED8` on `#DBEAFE` | `#93C5FD` on `#1E2A44` | blue | |
| method.post | `#15803D` on `#DCFCE7` | `#86EFAC` on `#14322A` | green | |
| method.put | `#B45309` on `#FEF3C7` | `#FCD34D` on `#3A2E12` | yellow | |
| method.patch | `#C2410C` on `#FFEDD5` | `#FDBA74` on `#3B2516` | yellow | |
| method.delete | `#B91C1C` on `#FEE2E2` | `#FCA5A5` on `#3B1C1C` | red | |
| method.head/options/connect | grey pair | grey pair | white | |
| method.ws | `#6D28D9` on `#EDE9FE` | `#C4B5FD` on `#2E2550` | magenta | WebSocket flows and `101` |
| status 1xx / 2xx / 3xx / 4xx / 5xx | violet / green / sky / amber / red | same hues, lifted | magenta / green / cyan / yellow / red | status text + the row's leading dot |
| status.pending | `#B45309` text · dot = intercept | `#F5A524` | yellow | in flight; same hue family as intercept on purpose: both mean "not finished". Text uses the deep shade (4.5:1); the dot is a graphic and uses `intercept.base` |
| status.killed | grey + strikethrough | | white | |
| severity critical/high/medium/low/info | red-900 / red / amber / blue / grey pairs | | | PoC findings |
| syntax key/string/number/boolean/punct | rose / amber / green / violet / grey | | | body viewers, header tables |

Rules: a badge is tint background + deep text, 18px tall, 4px radius, 11px/600 mono. Saturated fill with on-colour text appears **only** on the armed-intercept bar and a `Resume` primary button inside it. No gradients, no glass, no shadows on anything that rests; shadows only on menus, popovers, the palette and sheets.

### 2.3 Typography

Two faces, each with one job (`typography.*`):

- **UI face** — the platform's text face: SF Pro on macOS, Inter/system-ui on the web, the terminal font in the TUI. Labels, titles, sidebar, controls, dialogs.
- **Data face** — monospace: SF Mono on macOS, `ui-monospace`/JetBrains Mono on the web. Every URL, header, body, time, duration, size, id, method and status badge. This is Proxyman-native's decision and it is what makes the table scan.

Scale (six sizes): **11** badges, line numbers · **12** column headers, labels, status bar · **13** dense body: flow rows, header tables, code · **14** comfortable body, sidebar, form controls · **16** pane titles · **20** the one screen title. Weights 400 / 500 (active tab, selected item, badges) / 600 (pane titles, status code, h1). Tabular figures on every number. Code line-height 1.55 (13 → 20px). The TUI maps weight → bold, tertiary → dim, selection → reverse video in the accent.

### 2.4 Spacing, shell dimensions, density

4px base: 4 / 8 / 12 / 16 / 20 / 24 / 32. One gutter per screen (12px inside panes, 16px in dialogs).

| Part | Height / width |
|---|---|
| toolbar | 44 |
| content-type chip bar | 36 |
| column header | 28 |
| flow row | **28 dense (default)** · 32 default · 40 comfortable · 64 two-line card (narrow/web viewer) |
| inspector summary strip (`GET · 200 OK · URL`) | 40 |
| tab bar | 36 |
| intercept bar | 40 |
| status bar | 28 |
| sidebar | 240 (200–320) |
| controls | 28 in bars · 32 in dialogs |
| badge | 18 |
| status dot | 8 |

Density is one setting that moves row pitch, cell padding and body size together (dense 28/13, default 32/13, comfortable 40/14). Radii: badge 4, control 6, panel 8, floating 10, pill 999 (only the listening pill and chip filters). TUI: one line per row, 28 columns for the sidebar.

### 2.5 Iconography

Outline, 1.5px stroke, one set per platform: **SF Symbols** on macOS, **Lucide** on the web (the closest open geometry to SF Symbols), a fixed **Unicode glyph** per role in the TUI. The role → glyph table is `icon.glyph` in tokens.json; a new icon is added there first. Icons are grey (`text.secondary`), 16px in bars, 12px inline, never in a tinted circle. Client/app icons (the `Client` column, sidebar apps) are the real app icons on macOS and a neutral monogram disc elsewhere.

**Product mark.** Two chevrons facing a dot — `›•‹`, the thing in the middle — drawn as a 16px glyph in the accent, with the wordmark `aitmproxy` in the UI face at 500. Sits top-left of the sidebar; the TUI prints it as text.

### 2.6 The shell (the primary screen)

```
┌ sidebar 240 ┬──────────────────────────────────────────────────────────────┐
│ ›•‹ aitmproxy │ ⏺ ▢ 🗑   [● aitmproxy · listening 127.0.0.1:8080 · HTTP/2]  [Agent ●] ⌘K ▯▯ │ toolbar 44
│               ├──────────────────────────────────────────────────────────────┤
│ Working       │ All | HTTP HTTPS WebSocket | JSON Form XML JS CSS GraphQL …  │ chip bar 36
│  ▸ Pinned     ├──────────────────────────────────────────────────────────────┤
│  ▸ Saved      │ ● # URL                 Client  Method Status Time Dur Req Resp SSL │ header 28
│ All           │ ● 50 https://api.…/login  curl  POST  200   11:05 2.4s 1.2k 518 🔓 │ rows 28
│  ▸ Apps   8   │ ◐ 51 https://api.…/users  Chrome GET   —     11:05 …              │
│  ▸ Domains 29 │ ┃ 52 …                                (agent tick, teal)         │
│  ▸ Scope   3  ├──────────────────────────────────────────────────────────────┤
│  ▸ Findings 2 │ ✋ Intercept armed · 2 paused   [Resume ⌘⏎] [Resume all] [Kill ⌘\] [Disarm] │ intercept 40
│               ├──────────────────────────────┬───────────────────────────────┤
│               │ [POST] [200 OK] https://api.example.com/api/auth/login       ⧉ │ summary 40
│               ├ Request  Headers Query Body Raw ⊕ ┬ Response Headers Body Raw JSON ⊕ │ tabs 36
│               │ 1 POST /api/auth/login HTTP/2 │ 1 {                            │
│               │ 2 host: api.example.com       │ 2   "token": "…"               │
│ 🔍 Filter ⌘⇧F │ …                             │ …                              │ body viewers
├───────────────┴──────────────────────────────┴───────────────────────────────┤
│ Clear  Filter  Auto-select        1 / 56 rows · 2 paused        196 MB ↑6 ↓3 KB/s │ status 28
└──────────────────────────────────────────────────────────────────────────────┘
```

**Layouts** (as Proxyman): *Horizontal* (inspector below the list, the default above), *Vertical* (inspector right), *Detached* (inspector in its own window — macOS/web only), *Split view* (two lists in one tab, each with its own filters and selection, one live capture). The TUI has horizontal and vertical only, and swaps the inspector in full-screen with `Enter`/`Esc` on narrow terminals.

**Sidebar groups.** *Working*: Pinned (hosts/apps the operator pinned — "working-session pinning"), Saved (sessions). *All*: Apps, Domains. *aitmproxy*: **Scope** (the authorised hosts, with count — selecting it filters to in-scope), **Findings** (PoC results, with count), **Browser** (the embedded obscura tab list), **Scripts** (Rhai plugins, with active count). Counts sit only on groups that are queues (Findings, Scope, paused flows).

### 2.7 Component vocabulary

Each component: anatomy → states → keyboard. The bus commands behind it are in §4.

**Toolbar.** Left: record/pause (toggle capture), compose, clear. Centre: the **listening pill** — `● aitmproxy · 127.0.0.1:8080 · HTTP/2`; the dot is green when listening, grey when paused, amber while intercept is armed. Right: the **Agent toggle** (§2.7 ↓), command palette (⌘K), layout switcher, sidebar toggle. The TUI shows the pill as the first line and the toggles as `:` commands.

**Content-type chip bar.** `All | HTTP HTTPS WebSocket | h1 h2 | JSON Form XML JS CSS GraphQL Document Media Other`. One chip active (raised fill, 500 weight); the others plain `text.secondary`. Chips are a quick filter layered under the filter bar's expressions. `⌘1…9` select.

**Flow list.** Columns (reorderable, hideable, resizable; Proxyman's set + ours): `●` status dot · `#` · URL (host in ink, path in accent, query dimmed) · Client · Method badge · Status badge/text · Time · Duration · Request size · Response size · SSL (open padlock = MITM'd, closed = tunnelled/not decrypted, warning = pinned/failed) · Edited (pencil when mutated) · **Origin** (teal `agent` tick when the flow was produced by the agent: replay, request.send, poc.run) · Comment · Mark colour. Rows: 28px, mono data, no zebra, 1px `rule` separators. **States:** normal; *selected* (`active` fill — never the accent); *hover* (`hover` fill, no selection change); *pending* (amber dot, grey `—` status); *intercepted/paused* (amber dot, amber left edge 2px, `Paused` badge in the Status column); *killed* (grey, URL struck through); *replay* (`↻` after `#`); *out of scope* (whole row at `text.tertiary` — see scope-as-authorisation); *marked* (6px colour swatch left of `#`, 11 colours as Proxyman). Group by host or app via the sidebar; sort by any column; multi-select for bulk (resume all, kill, export, diff). **Keyboard:** `↑↓` move, `Enter` focus inspector, `i` arm/disarm intercept, `e` edit (opens mutate on a paused flow), `r` replay, `n` compose, `d` kill/delete, `m` mark, `c` comment, `p` pin host, `⌘F` filter bar, `⌘⇧F` sidebar filter, `⌘K` palette, `Space` quick-look body.

**Method & status badges.** Method: tinted pill, 11/600 uppercase mono (`GET` blue, `POST` green, `PUT` amber, `PATCH` orange, `DELETE` red, `HEAD/OPTIONS/CONNECT` grey, `WS` violet). Status: the code in class colour as text in the list (`200`), as a tinted pill in the summary strip (`200 OK`). `Paused` (amber) and `Killed` (grey) are status badges too.

**Filter bar & search.** Proxyman's stacked-filter model: up to N rows, each `Field · Operator · Value`, combined AND/OR; fields = URL, Host, Path, Query, Method, Status, Request header, Response header, Request body, Response body, Content-type, Client, Duration, Size, Colour, Comment, Origin (human/agent), Scope (in/out), WebSocket direction. Operators = contains, equals, wildcard, **regex**, **JSONPath/jq** (body fields), **full-text**. Saved filters by name. Matches highlighted in body viewers. The TUI exposes the same model as a mitmproxy-style expression (`~u login & ~m POST & ~s 200`) and the GUIs show that expression as the row's "advanced" view, so a filter copies between surfaces as text.

**Command palette** (`⌘K` / `:` in the TUI). Fuzzy search over every bus command (by name and description, from `tools/list`), flows (by URL), and setup actions (install CA, add scope, open browser). Recent and pinned at the top. Floating panel, radius 10, shadow `floating`, 160ms scale-from-0.97 — **except** keyboard open/close, which does not animate.

**Inspector.** *Summary strip* (40px): method pill, status pill, full URL (mono), copy button, right-aligned: duration, sizes, protocol, TLS/ALPN. *Two panes* side by side: **Request** · Headers · Cookies · Query · Body · Raw · Summary · Timing · **Connection** | **Response** · Headers · Set-Cookie · Body · Raw · JSON/Tree · **Diff** · `+` (custom previewer). Pane title 16/600, tabs plain 13, the active tab in the accent with a 2px underline on the shared 1px rule. Header tabs are two-column key : value tables (mono lowercase names in `syntax.key`). *Body viewers*: pretty/syntax-highlighted (JSON, XML, HTML, JS, CSS, form, multipart), **JSON tree** (fold, copy node, JSONPath of node, filter), **image** (with metadata), **hex** (offset · bytes · ASCII), **protobuf** (raw decode or with `.proto`), **MessagePack**, **SSE/streaming** (event list), **Markdown rendered**, **diff** (two flows, side-by-side or unified), **raw** (exact bytes, editable while paused). Large bodies stream in pages; `truncated` (FlowMeta) shows a notice chip. TUI: all but image (shows `[image 1200×800 PNG · o to open]`); diff falls back to unified under 120 columns.

**Intercept / breakpoint bar.** The one saturated element. Hidden when disarmed. Armed with nothing paused: 40px bar in `intercept.tint` with `intercept.deep` text: `✋ Intercept armed — every request pauses here · [Disarm] · Rules…`. Armed with paused flows: `intercept.base` fill, on-colour text, `✋ 2 paused` + the oldest paused flow's method+URL + actions: **Resume ⌘⏎** (primary, inverse), **Resume all**, **Kill ⌘\** (with abort mode: reset connection · 429 · 503), **Edit e** (opens the paused request in the body viewers as editable; `Apply & Resume` sends `flow.mutate` then `flow.resume`), **Disarm**. Selecting a paused row in the list targets the bar's actions at it. Dot pulses 1200ms (stops under reduced motion). *Rules…* opens the breakpoint rules sheet (Proxyman form: name, URL wildcard/regex, method, request/response phase, flag) — needs core follow-up F3. TUI: the bar is one line above the status bar in yellow reverse video.

**Compose / repeat.** Sheet (macOS/web) or full-screen form (TUI): method · URL · Headers (bulk edit) · Query · Body (raw/JSON/form/multipart) · Send. Templates: Empty, GET, POST JSON, POST Form, Multipart, WebSocket, **Import cURL** (paste auto-parses). History of sent composes. *Repeat* (`r`) replays a captured flow unchanged; *Edit & repeat* opens compose prefilled. Result opens as a new flow with `↻` and, if the agent sent it, the teal tick.

**Scope panel (scope-as-authorisation).** Sidebar group + a sheet. Entries: `host`, `host:port`, `*.wildcard`, with the rate-limit/back-off config shown read-only beside them. Out-of-scope flows are visible but dimmed and every mutating action on them is disabled with the tooltip "Out of scope — add `host` to scope to act". Adding to scope is a human action that the agent cannot perform unless config allows (mirrors `ca.allow_agent_install`). The flow list's `Scope` sidebar item filters to in-scope.

**PoC panel (Findings).** List of PoC runs (title · severity pill · target · passed/failed · when · origin). Detail: the YAML (syntax-highlighted, editable, `Save`), the **finding capture** (opens that flow in the inspector), the **screenshot** (inline image; TUI: placeholder + open), the per-assertion table (`assertion · ✓/✗`), **Run again** (`poc.run` with editable `target`/`vars`), **Export** (YAML + PNG + HAR of the capture). *Build PoC from flow* is a row action (`poc.build`: name, parameter) and a palette command.

**Browser view (embedded obscura).** A tab per page; toolbar: URL field, back/forward/reload, screenshot, `Eval…`, `DOM`. The viewport is a live screenshot stream on macOS/web (CDP screencast or periodic `browser.screenshot`); click/type are relayed via `browser.click`/`browser.type`. Flows the browser generates are tagged with the browser's client id in the `Client` column (`obscura`). TUI: URL + last screenshot as placeholder + `get_dom` text outline; navigate/eval available.

**Script editor (Rhai, M3).** Modelled on Proxyman's: left = *Matching rule* (name, URL wildcard/regex, method, subpaths, flag) + *Run on* ☑ Request ☑ Response ☐ WebSocket + status `● Saved and active`; centre = editor with line numbers; right = console (that script's log); bottom bar `Beautify · Snippets · Save & Activate ⌘S`. Scripts list in the sidebar with enable toggles. Bus commands are an M3 deliverable (§5 F8).

**Agent toggle.** Toolbar control, right of the listening pill: `[⚙ Agent ●]` teal when the agent may act, grey when paused; a count badge of agent actions in the last minute. Click → menu: *Allow all tools* · *Read-only* (list/get/status only) · *Paused* (every `tools/call` from MCP returns "paused by operator") · *Activity log…*. The **activity log** is a side panel listing every command invocation from any frontend (`time · origin · command · args summary · result`), agent rows in teal. This is also where confirmations surface: a gated command the agent requests (e.g. `ca.install`) appears as a request the human can approve once. Needs core follow-up F1/F2.

**Status bar.** Left: `Clear · Filter · Auto-select` (small raised buttons). Centre: `1 / 56 rows · 2 paused · 3 in scope`. Right: `196 MB ↑ 6 KB/s ↓ 3 KB/s` and the connection state to the bus (`● bus 127.0.0.1:9090`).

**Dialogs.** Sheets on macOS, centred modals on web (radius 10, `floating` shadow, 220ms), full-screen forms in the TUI. One primary button (inverse fill), keyboard hints printed on buttons (`Add ⌘⏎`).

### 2.8 Interaction rules

- Hover never moves selection; only click/keys do. Selection fill is `active`, never the accent.
- Keyboard-initiated actions never animate (palette, tab switch, row navigation). Everything else: press 120ms scale(0.97); hover 100ms; popovers 160ms from scale 0.97 at the trigger; sheets 220ms; `ease-out: cubic-bezier(.23,1,.32,1)`. New flows append with **no** animation. `prefers-reduced-motion` drops travel, keeps opacity.
- Every list keeps its header in view; a full list states its total; new flows do not steal selection unless *Auto-select* is on.
- Empty states keep the frame and say the trade's words: "No flows yet — point a client at 127.0.0.1:8080 or open the browser." "Nothing paused." "No findings — build a PoC from any flow with `p`."
- Loading: final layout with grey bars at real size; no shimmer; no layout shift when data lands. Errors inside the block that failed, with "last good" time and Retry.
- Zero prints as zero; missing as a grey dash; a real `0 B` body is `0 B`.

### 2.9 Per-platform mapping

| | macOS (SwiftUI/AppKit) | Web (browser) | TUI (terminal) |
|---|---|---|---|
| **Stack (Matt's constraints)** | **Fully native Swift/SwiftUI**; AppKit where SwiftUI cannot hold the density (the flow table). No web view, no Electron. | **Runs everywhere, native-grade fidelity and snappiness**; stack recommendation in §2.10, not locked. | **Rust, ratatui**; one binary for macOS and Linux. |
| Tokens | `Tokens.swift` generated from tokens.json; `Color(light:dark:)`; accent follows the system accent unless Multicolor | `tokens.css` generated; `:root` + `[data-theme=dark]`; `prefers-color-scheme` default | ratatui `Style` table; truecolor → dark hex, else `tui` ANSI name; bold/dim/reverse for hierarchy |
| UI face / data face | SF Pro / SF Mono | Inter (self-hosted) / ui-monospace, JetBrains Mono | terminal font / same |
| Icons | SF Symbols | Lucide SVG sprite | `icon.glyph.tui` |
| Shell | NSSplitView-backed three regions; toolbar is the window toolbar; sheets | CSS grid; same regions; modals | one screen; sidebar collapsible with `b`; inspector swaps to full screen on narrow terminals |
| Images / screenshots | inline | inline | placeholder + `o` opens externally (kitty/sixel graphics if the terminal advertises them — optional) |
| Browser view | live screencast | live screencast | URL, DOM outline, last screenshot placeholder |
| Split view | yes | yes | two lists side by side ≥ 160 cols, else tabbed |
| Detached inspector | yes | yes (new window) | no |
| Drag & drop import | yes | yes | `:import <path>` |
| Clipboard | yes | yes (secure context) | OSC 52 if the terminal allows |
| Command palette | ⌘K floating | ⌘K floating | `:` prompt + fuzzy popup |
| Mouse | yes | yes | optional |
| Remote bus | loopback or network | network only (via the web bridge, §4.9) | loopback or network |

### 2.10 Implementation targets per surface

Matt's constraints (2026-10-27): the macOS app is **fully native Swift/SwiftUI**; the TUI is **Rust/ratatui and cross-platform** (Linux and macOS); the web UI **runs everywhere and must match the native app's fidelity, polish and snappiness**. One tokens file and one component vocabulary translate to all three as follows; where a translation cannot be faithful, the surface degrades the way §2.9 says, never silently.

**(a) macOS — Swift/SwiftUI, AppKit-backed where density demands.**
- Tokens: a generated `Tokens.swift` (`Color(light:dark:)` per colour token, with the Increase-Contrast variants; `Font` per size/weight; `CGFloat` per space/size/radius; `Animation` per motion token). Accent follows the Mac's system accent unless it is Multicolor, then the brand blue (HIG).
- Flow list: an `NSTableView` wrapped for SwiftUI (`NSViewRepresentable`) — SwiftUI `Table` cannot hold 28px rows at 50 appends/s without hitching; everything else (sidebar, inspector tabs, bars, sheets) is SwiftUI. Split regions via `NSSplitViewController` or `HSplitView` with persisted widths.
- Body viewers: a `NSTextView`-based code view with our syntax tokens (or a thin wrapper over a Swift CodeMirror-class editor if one proves faster); JSON tree as `OutlineGroup`; images native; diff via a two-column text view.
- Icons: SF Symbols by the glyph map. App icons for the Client column from the resolved process (core resolves peer → pid; the app maps pid → `NSRunningApplication` icon).
- Window chrome follows macOS 26 (Liquid Glass toolbar); the inside of every panel stays flat per §2.2.

**(b) Web — runs everywhere, native-grade.** The bar is: 28px rows appending at 50/s with no jank, sub-16ms tab switches, a body viewer that opens a 5 MB JSON without freezing, cold load under ~300 KB gzipped. *Recommendation (a suggestion for Matt, not locked):*
- **SolidJS + TypeScript** — fine-grained reactivity with no virtual-DOM diff, so a flow-list row updates in place when its response arrives; ~7 KB runtime. (Svelte 5 is the equivalent alternative; React would need heavy memoisation to hit the same frame budget.)
- **Virtualised flow list** (TanStack Virtual) rendering only the visible 30–40 rows; column layout via CSS grid with `contain: strict` on rows.
- **CodeMirror 6** for body/raw viewers — incremental parsing, viewport-only rendering, ~150 KB; it is what makes a 5 MB body scroll. (Proxyman uses Monaco; Monaco is 2–3 MB and single-threaded on load.)
- **Tokens as CSS custom properties** (generated `tokens.css`), the data face as a self-hosted JetBrains Mono (SF Mono where present via `ui-monospace`), Lucide SVG sprite for icons, `@starting-style` and `transform/opacity`-only motion per §2.8.
- **Delivery**: a Vite build embedded as static assets in the `aitm` binary and served by `aitm web` (§4.9), with the WebSocket bridge on the same origin; no separate deploy. Works offline against a local proxy and remotely against a TLS bus.
- *Alternative considered:* a Rust/WASM front end (Leptos/Dioxus) sharing the Rust bus client with the TUI — one language, but WASM bundles start at ~1 MB and there is no CodeMirror-class editor in that ecosystem; not recommended for v1.

**(c) TUI — Rust, ratatui, macOS + Linux.**
- Tokens: a generated `tokens.rs` of ratatui `Style`s; truecolor terminals use the dark hex set, 256/16-colour terminals the `tui` ANSI names; weight → bold, tertiary → dim, selection → reverse in the accent. Size/space tokens collapse to cells (one line per row; sidebar 28 cols).
- Shell: the §2.6 regions as ratatui layouts; `b` toggles the sidebar; below 120 columns the inspector takes the whole screen on `Enter` and returns on `Esc`.
- **Degradations, by design**: no inline images (screenshots/image bodies show `[image W×H type · o to open]`, kitty/sixel graphics only if the terminal advertises them); no browser viewport (URL + DOM outline + last-screenshot placeholder; navigate/eval still work); diff is unified under 120 cols; split view needs ≥ 160 cols; no drag-and-drop (`:import <path>`); clipboard via OSC 52 where allowed; mouse optional, keyboard complete.
- Client column: core resolves peer → process on both OSes (macOS `libproc`, Linux `/proc/net/tcp` + `/proc/*/fd`), so the TUI shows the process name on Linux too.
- Build: a `crates/aitm-tui` binary that is a bus client like the others; it may also *embed* the proxy (`aitm tui` starts core + TUI in one process over an in-process channel) so a single binary works on a Linux box with no second process — the bus contract is unchanged either way.

Shared across all three: one `aitm-bus-client` contract (§4.10) so the three clients make identical calls, and one fixture file of recorded bus traffic used by all three surfaces' UI tests so a screen renders the same data on every platform.

---

## 3. Feature catalog

The shared feature set every surface implements. **Source**: m = mitmproxy, P = Proxyman, a = aitmproxy's own. **Bus**: ✓ = served by today's command set; **F*n*** = needs core follow-up *n* (§5); M3 = part of the scripting milestone in flight. **Platform**: ✓ full · ◐ limited (note) · — not possible.

### 3.1 Capture & flow list

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Live flow list, newest at bottom, auto-scroll with *Auto-select* | m P | F4 | ✓ | ✓ | ✓ | today only by polling `flow.list`+`flow.get`; F4 adds push |
| Columns: dot, #, URL, Client, Method, Status, Time, Duration, Req/Resp size, SSL, Edited, Origin, Comment, Mark; reorder/hide/resize; sort | P a | F5 | ✓ | ✓ | ◐ fixed set, hide only | sizes/timing/conn need F5 detail |
| Custom columns from a header or a JSON-body path | P | F5 | ✓ | ✓ | ◐ one | P 6.17 |
| Group by host (Domains) / by client app (Apps) | P | ✓ | ✓ | ✓ | ✓ | client app = `ConnInfo.peer` + process lookup (mac only resolves app icon) |
| Working-session **pinning** (pin hosts/apps to the top) | P a | local | ✓ | ✓ | ✓ | surface-local state, synced via saved session |
| Highlight (11 mark colours) + strikethrough | P m | F6 | ✓ | ✓ | ◐ 8 colours | `FlowMeta.marks` exists; no command |
| Per-flow **comment** (⌘L) + Comment column | P m | F6 | ✓ | ✓ | ✓ | `FlowMeta.comment` exists; no command |
| Pause/resume capture (record toggle) | P | F7 | ✓ | ✓ | ✓ | no command today |
| Clear session; cleanup old flows | P m | F7 | ✓ | ✓ | ✓ | `max_flows` config exists; no clear command |
| Multi-select + summary (count, total size, combined timing) | P | F5 | ✓ | ✓ | ✓ | |
| **Split view**: two lists, own filters/selection, one capture | P | ✓ | ✓ | ✓ | ◐ ≥160 cols | |
| Layouts: horizontal / vertical / detached inspector; tabs | P | ✓ | ✓ | ✓ | ◐ h/v only | |
| Overview dashboard (per-session stats: hosts, codes, sizes, timing) | P | F5 | ✓ | ✓ | ✓ text | P 26.2 |
| Connection log (CONNECT, TLS, ALPN, SNI, errors) | P m | F5 | ✓ | ✓ | ✓ | `ConnInfo` has sni/alpn/tls |
| Out-of-scope flows dimmed; actions on them disabled | a | ✓ | ✓ | ✓ | ✓ | scope.list vs authority |

### 3.2 Filtering & search

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Content-type chip bar (All/HTTP/HTTPS/WS/h1/h2/JSON/Form/XML/JS/CSS/GraphQL/Doc/Media/Other) | P | F5 | ✓ | ✓ | ✓ | needs content-type from detail |
| Stacked filters, AND/OR, fields in §2.7; wildcard, **regex**, **JSONPath/jq**, **full-text** | P m | F5 (client-side) | ✓ | ✓ | ✓ expression | server-side `flow.list {filter}` is F4's optional param |
| mitmproxy filter expressions as the portable text form | m | — | ✓ advanced view | ✓ | ✓ native | |
| Saved filters | P | local | ✓ | ✓ | ✓ | |
| Match highlighting in body viewers | P | — | ✓ | ✓ | ✓ | |
| Sidebar quick filter (⌘⇧F) | P | — | ✓ | ✓ | ✓ | |
| **Command palette** (commands, flows, setup) | P m | ✓ `tools/list` | ✓ | ✓ | ✓ `:` | |

### 3.3 Inspector & body viewers

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Summary strip: method, status, URL, copy, duration, sizes, protocol, TLS | P | F5 | ✓ | ✓ | ✓ | |
| Request tabs: Headers, Cookies, Query, Body, Raw, Summary, Timing, Connection | P m | F5 | ✓ | ✓ | ✓ | |
| Response tabs: Headers, Set-Cookie, Body, Raw, JSON/Tree, Diff, `+` custom | P | F5 | ✓ | ✓ | ✓ | |
| Syntax-highlighted pretty view (JSON, XML, HTML, JS, CSS, form, multipart) | P m | F5 | ✓ | ✓ | ✓ | |
| **JSON tree** (fold, copy node, node path, filter, sort keys) | P | F5 | ✓ | ✓ | ✓ | |
| **Image** viewer + metadata | P | F5 | ✓ | ✓ | — placeholder + open | |
| **Hex** viewer | P m | F5 | ✓ | ✓ | ✓ | |
| **Protobuf** (raw / with .proto), **MessagePack** | P | F5 | ✓ | ✓ | ✓ | decoding client-side |
| SSE / streaming event list; OpenAI-style merged stream | P | F4 F5 | ✓ | ✓ | ✓ | |
| Rendered Markdown / HTML preview | P | F5 | ✓ | ✓ | ◐ text | |
| **Diff** two flows (side-by-side / unified, export patch) | P | F5 | ✓ | ✓ | ◐ unified <120 cols | |
| Large bodies paged; `truncated` notice | a | F5 | ✓ | ✓ | ✓ | |
| Timing waterfall (DNS, connect, TLS, wait, download) | P | F5 | ✓ | ✓ | ✓ text bars | needs per-phase timestamps in core (F5) |
| Code generator / **copy as cURL** (+ others) | P | F5 | ✓ | ✓ | ✓ | client-side from detail |
| Open body with external editor / export body | P | F5 | ✓ | ✓ | ✓ | |

### 3.4 Intercept & edit

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Arm/disarm intercept (all requests) | m a | ✓ `flow.intercept` | ✓ | ✓ | ✓ | |
| Intercept bar: paused count, oldest paused, Resume / Resume all / Kill / Edit / Disarm | P m a | ✓ `flow.resume` `flow.kill` | ✓ | ✓ | ✓ | |
| Edit paused request (method, path, headers, body) then **Apply & Resume** | P m | ✓ `flow.mutate` + `flow.resume` | ✓ | ✓ | ✓ | |
| Raw-message edit of a paused request | P | ✓ (body as bytes) | ✓ | ✓ | ✓ | |
| Breakpoint **rules** (URL wildcard/regex, method, phase, flag) instead of all-or-nothing | P m | F3 | ✓ | ✓ | ✓ | |
| **Response-phase** interception and edit (status, headers, body) | P m | F3 | ✓ | ✓ | ✓ | core only parks `Event::Request` today |
| Kill with abort mode (reset / 429 / 503) | P | F3 | ✓ | ✓ | ✓ | `flow.kill` resets today |
| Edited flag column + revert to original (backup) | m P | F5 | ✓ | ✓ | ✓ | `InterceptState::Intercepted{backup}` exists |
| Message templates for edits | P | local | ✓ | ✓ | ✓ | |

### 3.5 Compose, repeat, import/export

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Compose request (method, URL, headers, query, body; templates) | P m | ✓ `request.send` | ✓ | ✓ | ✓ | guarded by scope/rate |
| **Import cURL** (paste → compose) | P | ✓ | ✓ | ✓ | ✓ | |
| Repeat / Edit & repeat | P m | ✓ `flow.replay` | ✓ | ✓ | ✓ | |
| Compose history | P | local | ✓ | ✓ | ✓ | |
| WebSocket compose / send frame | P | F9 | ✓ | ✓ | ✓ | |
| Import: HAR 1.2, mitmproxy flows, Proxyman log, Charles | P m | F10 | ✓ | ✓ | `:import` | |
| Export: HAR, flows, CSV, cURL batch, Postman/OpenAPI, PoC bundle | P a | F10 | ✓ | ✓ | ✓ | |
| Save / load session; saved folders | P m | F10 | ✓ | ✓ | ✓ | |

### 3.6 SSL / CA

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| SSL column: decrypted / tunnelled / pinned-or-failed | P m | F5 | ✓ | ✓ | ✓ | from `ConnInfo.tls` + error |
| CA status, export (PEM/DER), install, uninstall, audit log | a | ✓ `ca.*` | ✓ | ✓ | ✓ | install/uninstall confirm via `confirm_prompt`; agent gated by `ca.allow_agent_install` |
| SSL include/exclude list (which hosts to MITM) | P m | F11 | ✓ | ✓ | ✓ | |
| `ssl_insecure` upstream toggle | a | F7 | ✓ | ✓ | ✓ | config exists |
| Setup guides: iOS/Android/browser/terminal env | P | — | ✓ | ✓ | ✓ text | content only |

### 3.7 WebSocket

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| WS flow with frame list (dir, opcode, length, data, time, injected) | P m | F5 | ✓ | ✓ | ✓ | `WsFlow.messages` |
| Realtime frame stream | P m | F4 | ✓ | ✓ | ✓ | |
| Frame viewers: text, JSON/tree, hex, protobuf | P | F5 | ✓ | ✓ | ✓ | |
| Filter sent/received | P | — | ✓ | ✓ | ✓ | |
| Intercept / edit / drop / inject frames | P m | F9 | ✓ | ✓ | ✓ | M3 Rhai `onWebsocket` is the scripted path |

### 3.8 Scripting & plugins (M3 Rhai tier)

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| Script list with enable toggle, status, errors | P m | F8/M3 | ✓ | ✓ | ✓ | |
| Script editor (matching rule, run-on phases, editor, console, Save & Activate) | P | F8/M3 | ✓ | ✓ | ✓ editor is external (`$EDITOR`) | |
| Snippets / templates | P | local | ✓ | ✓ | ✓ | |
| Plugin chain view (ordered, per-plugin verdicts) | m a | F8 | ✓ | ✓ | ✓ | |
| Map local / Map remote / Block list / Allow list / No-cache / Throttle | P | future (scripts first) | ✓ | ✓ | ✓ | shipped as bundled Rhai scripts with a form UI; dedicated commands later |

### 3.9 aitmproxy's own

| Feature | Source | Bus | mac | web | tui | Notes |
|---|---|---|---|---|---|---|
| **Scope as authorisation**: list/add/remove; dim + disable out-of-scope; agent cannot widen scope unless configured | a | ✓ `scope.add/list`, F12 remove | ✓ | ✓ | ✓ | |
| Rate limit / back-off / error-budget readout per host | a | F5 | ✓ | ✓ | ✓ | `LimitConfig` exists |
| **PoC panel**: findings list, YAML, finding capture, screenshot, assertions, run again, export | a | ✓ `poc.build/run`, F13 artifacts | ✓ | ✓ | ◐ no inline image | |
| Build PoC from flow (row action) | a | ✓ `poc.build` | ✓ | ✓ | ✓ | |
| **Embedded browser view** (obscura): tabs, URL, navigate, click, type, eval, DOM, screenshot | a | ✓ `browser.*`, F14 screencast | ✓ | ✓ | ◐ no viewport | |
| **Agent (MCP) toggle**: all / read-only / paused; activity log; one-time approvals | a | **F1 F2** | ✓ | ✓ | ✓ | |
| Origin column + teal tick on agent-originated flows | a | F2 | ✓ | ✓ | ✓ | |
| Activity log of every command from every frontend | a | F2 | ✓ | ✓ | ✓ | |
| Config view (YAML, env overrides, engine) | a | F7 | ✓ | ✓ | ✓ | |
| Remote management (web/TUI against a remote proxy) | a | F15 | — n/a | ✓ | ✓ | |

---

## 4. Command-bus integration contract

### 4.1 What exists today (verified in `crates/aitm-mcp`, `aitm-core`)

- **Protocol**: JSON-RPC 2.0, MCP revision `2025-06-18`, newline-delimited JSON. Methods: `initialize`, `ping`, `tools/list`, `tools/call`; incoming `notifications/*` are accepted and ignored. The server **never pushes** — strictly request/response.
- **Transports** (`McpTransport`): `Stdio`; `LoopbackTcp { port, token }` — binds `127.0.0.1:port`, and **the first line of every connection must be** `{"token":"<token>"}` or the connection is refused with `-32001 UNAUTHORIZED`. Port `0` picks a free port; `on_bound` reports it.
- **Commands**: every capability is a `Command` (`name`, `schema() -> ParamSchema {description, params: [ParamDef{name, ty: TypeDesc, required, description}], result: TypeDesc}`, `invoke`, `confirm_prompt(args) -> Option<String>`). `tools/list` returns one tool per registered command with JSON Schema derived from `TypeDesc` (`Bool Int Float Str Bytes FlowId Array Object Map Any`; `Bytes` crosses as base64).
- **Call result**: `{"content":[{"type":"text","text":"<json>"}], "structuredContent": <json>, "isError": false}`; a command failure is `isError: true` with the message (not a protocol error). `-32602` for an unknown tool or malformed arguments.
- **Frontend identity**: `CommandHost::with_frontend(Frontend::{Cli, Mcp})`. `Mcp` means "an agent is here": gated commands rely on config flags, never a prompt. `Cli` asks via a `Confirmer`.
- **The 22 commands** (M2): `flow.list` `flow.get` `flow.intercept` `flow.resume` `flow.kill` `flow.mutate` `flow.replay` · `request.send` · `scope.add` `scope.list` · `browser.navigate` `browser.click` `browser.type` `browser.screenshot` `browser.eval` `browser.get_dom` · `poc.build` `poc.run` · `ca.export` `ca.status` `ca.install` `ca.uninstall`.

### 4.2 How a surface connects

1. Read the bus address and token from the running proxy's config (`mcp.transport`), or from a `--bus host:port --token-file` argument; the macOS app may also spawn `aitm` itself and read `on_bound`.
2. Open the TCP connection, write the token line, then `initialize` (send `clientInfo: {name: "aitm-mac" | "aitm-web" | "aitm-tui", version}` so the activity log can name the origin — see F2).
3. `tools/list` once; **build the command palette and every form from the schemas** (`ParamDef.description` is the field's help text; `required` drives validation; `FlowId` fields become flow pickers; `Bytes` become file/hex inputs). A surface never hard-codes a command's parameters — new commands appear in the palette automatically.
4. If a command's `confirm_prompt(args)` is non-`None` for the arguments about to be sent, the surface shows that text as a confirmation (the human-frontend contract). The bus does not expose `confirm_prompt` over the wire today → F1 adds a `confirm` field to `tools/list` entries and a `Frontend::Operator` identity so the core can return "needs confirmation" instead of refusing.
5. Keep one connection for calls and (after F4) one subscription stream; reconnect with back-off; show bus state in the status bar.

### 4.3 The command set, grouped by UI concern

| Command | Params → result | Drives |
|---|---|---|
| `flow.list` | `{}` → `[FlowId]` oldest first | flow list ids (today the whole list every poll) |
| `flow.get` | `{id}` → summary `{id, kind: http\|websocket, intercept, is_replay, method, scheme, authority, path, status?, request_bytes?, response_bytes?, handshake?, messages?}` | a row's cells. **No headers, body, timing, conn or metadata** → F5 |
| `flow.intercept` | `{enabled?: bool}` → `bool` | arm/disarm; parks **every request** while armed |
| `flow.resume` | `{id}` → ok | the bar's Resume |
| `flow.kill` | `{id}` → ok | Kill (connection reset) |
| `flow.mutate` | `{id, edits: {method?, path?, headers?, body?}}` → ok | Edit → Apply |
| `flow.replay` | `{id}` → new FlowId | Repeat |
| `request.send` | crafted request (see schema) → new FlowId | Compose; guarded by scope + rate limits |
| `scope.add` / `scope.list` | `{host}` / `{}` → entries | Scope panel |
| `browser.navigate/click/type/eval/get_dom/screenshot` | per schema → text / png bytes | Browser view |
| `poc.build` | `{flow_id, name, param}` → PoC YAML path | Build PoC from flow |
| `poc.run` | `{poc_path, target, vars?}` → `{passed, finding_capture: FlowId, poc_path, screenshot_path, evaluated: [{assertion, matched}]}` | Findings panel; `finding_capture` opens in the inspector |
| `ca.status/export/install/uninstall` | per schema; install/uninstall have `confirm_prompt` and the MCP gate `ca.allow_agent_install` | CA panel / setup |

### 4.4 Live flow list — polling today, subscription after F4

Today: a surface polls `flow.list` (ids) on a timer, diffs against what it has, and `flow.get`s new ids. Acceptable for the first TUI spike; not for 50 flows/s.

Proposed (F4): `flow.subscribe {filter?, since?}` → subscription id; the server then writes unsolicited JSON-RPC notifications on the same connection:

```
notifications/aitm/flow     {"event":"created|request|response|ws_message|intercepted|released|killed|mutated|meta","id":"…","summary":{…}}
notifications/aitm/agent    {"origin":"mcp|cli|mac|web|tui","command":"flow.replay","args":{…},"result":"ok|error","at":"…"}
notifications/aitm/state    {"listening":true,"intercept_armed":true,"paused":2,"agent":"all|readonly|paused","throughput":{"up":6144,"down":3072}}
```

`flow.unsubscribe {sub}`. The transport already writes newline-delimited messages, so this is additive. For the web UI, the browser cannot open raw TCP: F15 adds a WebSocket bridge that relays these lines verbatim.

### 4.5 Intercept → edit → resume (sequence)

```
operator ──flow.intercept{enabled:true}──▶ core arms (InterceptPlugin.armed)
client   ──request──▶ core: backup(), park as pausable future, InterceptState::Intercepted{backup, resume}
core     ──notif flow{event:intercepted}──▶ every subscribed surface: amber dot, bar shows "1 paused"
operator  edits in the body viewer ──flow.mutate{id, edits}──▶ core applies to the parked request
operator ──flow.resume{id}──▶ core fires ResumeHandle; request continues to upstream; state Resumed; Edited flag on
   or    ──flow.kill{id}──▶ client sees a reset; state Killed; row greyed + struck
```

The agent follows the identical path over MCP; the only difference is the origin tag in the activity log.

### 4.6 Compose / repeat

`request.send` runs through the proxy's guarded client (scope + rate guard), so a compose to an out-of-scope host fails with the guard's error — the surface pre-checks against `scope.list` and disables Send with the reason. The result is a new flow (is_replay / origin tag) that appears via the subscription like any other.

### 4.7 PoC artifacts

`poc.run` returns three handles: a `FlowId` (always in the store — open it), and two **server-side file paths** (YAML, PNG). A loopback surface reads them from disk; a remote/web surface cannot → F13: `poc.artifact {path}` → bytes (confined to the PoC out-dir), or serve them through the web bridge. `poc.build` writes the YAML under `poc.dir` when configured; the surface shows the path and opens the YAML in the editor.

### 4.8 The agent on/off toggle (F1, F2)

Not in the command surface today; the only control is the config transport. Proposal, small and additive in `aitm-core` + `aitm-mcp`:

- **State** on the core: `AgentPolicy { All, ReadOnly, Paused }`, default `All` (or from config `mcp.policy`).
- **Commands** (registered by a tiny `AgentPlugin`): `agent.status {}` → `{policy, actions_last_minute, connected_clients}`; `agent.set {policy}` → policy. `agent.set` carries `confirm_prompt` = none for humans, and **is itself refused when the caller's frontend is `Mcp`** — the agent cannot un-pause itself.
- **Enforcement** in `McpServer::call_tool`: before `invoke`, if `policy == Paused` → tool error `"agent paused by operator"`; if `ReadOnly` and the command is not in the read-only set (`flow.list`, `flow.get`, `scope.list`, `ca.status`, `agent.status`, `browser.get_dom`, `browser.screenshot`) → the same refusal. Read-only-ness is declared by the command (`fn mutates(&self) -> bool`, default true) so the set is not hard-coded in the server.
- **Identity** (`Frontend`): add `Operator { client: String }` for the three human surfaces (they connect over the same MCP transport but are not agents), so `confirm_prompt` applies to them and the activity log can name them. The MCP transport trusts the `initialize.clientInfo.name` only to label; policy keys off the **connection's declared role**, set by a second token class in config (`mcp.operator_token` vs `mcp.agent_token`) so an agent cannot claim to be an operator.
- **Audit**: every `invoke` from any frontend appends `{at, origin, command, args, result}` to an in-memory ring (and the JSONL audit log the CA plugin already keeps, generalised) → surfaced as the activity log and the `notifications/aitm/agent` stream.

### 4.9 Remote and web management (F15)

Loopback TCP + token is right for a local desktop/TUI. For the web UI and remote TUI: `McpTransport::Tcp { bind, token, tls: {cert, key} }` (network listener, TLS required off-loopback) and an `aitm web` subcommand that serves the static web UI and a **WebSocket bridge** (`/bus`) relaying newline-delimited JSON-RPC lines to the local bus, authenticated by the same token in the first WS message. The bridge is dumb; all policy stays in the core.

### 4.10 Clients per surface (implementation targets)

| Surface | Client | Transport | Notes |
|---|---|---|---|
| macOS (Swift/SwiftUI) | `AitmBusClient` Swift package: `NWConnection` over loopback TCP (or network TLS), newline-delimited JSON-RPC, `Codable` models generated from `tools/list` schemas at build time plus a dynamic path for unknown commands | loopback TCP today; TLS TCP after F15 | May spawn `aitm` itself and read `on_bound`; subscribes (F4) on a second connection |
| Web (TS, recommended SolidJS) | `aitm-bus-client` TypeScript package over **WebSocket** to `aitm web`'s `/bus` bridge; same JSON-RPC lines; `tools/list` → runtime form generation | WS bridge (F15); same-origin | Reconnect with back-off; the bridge is dumb, all policy in core |
| TUI (Rust/ratatui) | `aitm-bus-client` Rust crate (shared with any future Rust surface), `tokio` TCP; in-process channel when the TUI embeds the proxy | loopback TCP or TLS TCP (F15); in-process | Linux + macOS |

All three send `initialize.clientInfo.name` (`aitm-mac` / `aitm-web` / `aitm-tui`) and connect with the **operator** token class (F1), so the core treats them as `Frontend::Operator` and the activity log names them.

---

## 5. Core follow-ups (Rust side) — ordered by how much UI they unblock

| # | Follow-up | Unblocks | Size |
|---|---|---|---|
| **F1** | `agent.status` / `agent.set {policy}` + `AgentPolicy` enforcement in `call_tool` + `Command::mutates()` + `Frontend::Operator` + operator/agent token classes | the agent toggle; human confirmations over the bus | S–M |
| **F2** | Command invocation audit ring + `notifications/aitm/agent` | activity log; Origin column; teal ticks | S |
| **F3** | `flow.intercept {enabled, rules?: [{url, method?, phase: request\|response, flag?}]}`; response-phase parking; `flow.kill {id, mode: reset\|429\|503}` | breakpoint rules, response edit, abort modes | M |
| **F4** | `flow.subscribe/unsubscribe` + server push on both transports (+ `flow.list {since?, filter?, limit?}`) | the live list, WS realtime, SSE | M |
| **F5** | `flow.detail {id, body: none\|inline\|range}` → headers, bodies (base64/paged), `ConnInfo`, `FlowMeta`, timing phases, WS frames, backup (original) | the inspector, every body viewer, columns, SSL column, diff, timing | M |
| **F6** | `flow.mark {id, marks}` / `flow.comment {id, text}` | highlight + comment | S |
| **F7** | `proxy.status/pause/resume`, `flow.clear`, `config.get` | record toggle, clear, config view | S |
| **F8** | M3: `script.list/get/set/enable/disable`, plugin chain readout — coordinate with the m3 sessions | script editor & plugin view | M (M3) |
| **F9** | `ws.send {id, dir, opcode, data}`; frame-level intercept | WS compose/inject | M |
| **F10** | `session.save/load`, `flow.export {ids, format}` / `flow.import` (HAR, mitmproxy, Proxyman, Charles) | import/export/sessions | M |
| **F11** | `tls.passthrough.list/add/remove` (SSL include/exclude) | SSL list | S |
| **F12** | `scope.remove`; `scope.add` gate for `Frontend::Mcp` (`scope.allow_agent_widen`, default off) | scope as authorisation | S |
| **F13** | `poc.list`, `poc.get`, `poc.artifact {path}` → bytes (confined) | PoC panel remote; findings list | S |
| **F14** | `browser.tabs`, `browser.screencast` (push frames) | live browser view | M |
| **F15** | network TCP transport with TLS + `aitm web` static host + WS bridge | web UI, remote TUI | M |

F1, F2, F4, F5 are the critical path for any of the three surfaces; F3 and F6 make the intercept bar and flow list feature-complete to Proxyman. Each is additive to the `Command`/`Registry` model and fits the existing seven-stage workflow as its own spec + plan.

---

## 6. Open questions for Matt

1. **Accent.** I propose Proxyman-WebUI blue (`#2563EB` / `#60A5FA`) as the single accent, keeping amber for intercept and teal for the agent. Alternative: keep Proxyman-native's orange (then intercept must move to another hue, which weakens "amber = paused" from both Proxyman and mitmproxy). Blue, or something of our own?
2. **Selection fill.** Proxyman-native fills the selected row with saturated orange; the WebUI and the dashboard study use a quiet tint. I chose the tint. OK, or do you want the loud native row?
3. **"The feature Proxyman now has."** Candidates from the changelog (Appendix A), most likely first: **MCP server** (6.4, Jan 2026; v3 in 6.8 — Codex/Claude Code/Cursor control Proxyman; they also ship a `SKILL.md`), **Network Extension** (26.1, Oct 10 2026 — capture every app without proxy settings), **Split View** (26.0), **HTTP/2 capture** (26.0), **Overview Dashboard + Timing view** (26.2, Oct 18), **`onWebsocket()` scripting** (26.1–26.3), **Command Palette** (6.0), **Team Workspace / share log online** (6.4–6.5). Which did you mean? If MCP: §4.8's toggle is our answer, plus we already *are* an MCP server — the difference is we let the agent drive 100%.
4. **Agent policy default.** `All` (agent acts freely until paused) or `ReadOnly` (human promotes it)? I lean `All` for a tool whose premise is agent-driven testing, with the toggle one click away.
5. **Web UI hosting.** `aitm web` built into the binary (my proposal, §4.9) vs. a separate static bundle pointed at a bus URL?
6. **Client app resolution** (the `Client` column): I now propose the core resolves peer → process on macOS (`libproc`) and Linux (`/proc`), so every surface gets the process name and the Mac app adds the icon; the web UI shows what the core gives it. OK to add that to F5?
7. **Density default**: 28px rows (Proxyman) or 32?
8. **Mark colours**: Proxyman's 11 macOS system colours, or a smaller set that survives the TUI's 8?
9. **Web stack**: §2.10(b) recommends SolidJS + TypeScript, TanStack Virtual, CodeMirror 6, Vite, embedded in the binary behind `aitm web`. Accept as the starting point, or do you have a stack you want?
10. **TUI embedding**: should `aitm tui` be able to start the proxy in-process (one binary on a Linux box), in addition to connecting to a running one?

---

## Appendix A — Proxyman recent features (changelog, read 2026-10-27)

| Version · date | Headline additions |
|---|---|
| 26.3.0 · 2026-10-26 | `onWebsocket()` edit/drop/send; "Modify WebSocket Messages" rule; toolbar themes |
| 26.2.0 · 2026-10-18 | **Overview Dashboard**; redesigned Timing view; script templates; `get_traffic_overview` MCP tool |
| 26.1.0 · 2026-10-10 | **Network Extension (Beta)** — capture all apps; `onWebsocket()`; MCP/CLI rule folders |
| 26.0.0 · 2026-09-21 | **HTTP/2 capture**; **Split View** (Pro); Connection Log tab |
| 6.17.0 · 2026-09-07 | Custom columns from JSON; settings redesign; JSONPath/jq autocomplete |
| 6.16.0 · 2026-08-24 | Codex/OpenAPI plugin marketplace; "Proxyman AI skills"; MCP toggle via CLI |
| 6.15 – 6.9 · Apr–Aug 2026 | iOS Simulator groups; MCP knows CLI; QUERY method; colour flags from tools; raw tab in breakpoints; GraphQL rule matching; WS protobuf; `require()` in scripts; WebSocket Compose; custom throttling |
| 6.8.0 · 2026-04-05 | MCP v3: rule management, certificate & terminal, export; rendered Markdown |
| 6.7.0 · 2026-03-17 | MCP v2; Electron support; Map Remote folders; Charles `.chlz` import; saved JSON filters |
| 6.4.0 · 2026-01-19 | **MCP server** (Claude Code / Cursor); **Team Workspace**; settings sync |
| 6.0.0 · 2025-10-21 | **Command Palette**; macOS 26 redesign |
| 5.24 – 5.19 · Apr–Sep 2025 | jq filter; compose history; block list; new scripting editor; SSE + OpenAI tab; WS rewrite; one-click browser capture |

Proxyman's MCP exposes ~40 tools (read: `get_flows`, `get_flow_detail`, `filter_flows`, `generate_code`…; write: `create_breakpoint`, `create_map_local`, `create_scripting_rule`, `enable_ssl_proxying`…; `toggle_recording`, `clear_session`, `install_certificate`), binds `127.0.0.1` with a `0600` token file, redacts secrets before sending to the AI, and has a single *Enable MCP Server* toggle in Settings — no per-tool or pause control. Ours (§4.8) adds the pause/read-only policy and the audit trail.
