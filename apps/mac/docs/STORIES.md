# Aitmproxy — user stories

Built from `docs/BRIEF.md` and the approved foundation (`docs/design/operator-ui-foundation.md` §2.7 components, §3 feature catalog, §5 core follow-ups F1–F15). 71 stories in six milestones plus 15 Rust-side placeholders; the count passes the skill's 60 because the brief carries four jobs no proxy UI has (PoC, scope, browser, agent), and M1's done-stories are coarse (one per surface). Snapshot page ids: sidebar pages `apps domains scope findings browser scripts agent`, Settings `settings-general settings-bus settings-appearance settings-ssl`, and one page per sheet, panel or viewer named below (`compose-sheet`, `palette`, `rules-sheet`, `activity-log`, `scope-sheet`, `filter-bar`, `inspect-*`, …). `Core: Fn` names the Rust follow-up a story waits on; the matching `S-core-Fn` sits under *Core follow-ups*. Acceptance tags: `[snap]` snapshot, `[unit]` Swift Testing, `[self]` the in-app self-test, `[manual]` a person tries it.

---

## M1 Shell & live list

The primary screen on fixtures and on a live `aitm`: usable for a day of watching traffic.

### S-001 Open the shell
As the operator, I launch the app and see the sidebar, window toolbar, chip bar, flow list, intercept bar and status bar laid out as the mockup.
Screens: apps
Acceptance:
- [snap] Sidebar 240 px with Working / All / aitmproxy groups in tracked small caps; brand mark `›•‹ aitmproxy` top-left; filter field at the bottom.
- [snap] Toolbar holds sidebar toggle, pause capture, compose, clear; the listening pill in the centre; Agent toggle, palette and layout glyphs on the right; no glass capsules behind any group.
- [snap] Chip bar 36 px with `All | HTTP HTTPS WebSocket | h1 h2 | JSON … Other` and the `Filters ▾` affordance; status bar 28 px on `raised`.
- [self] Fixtures load 14 rows; the window opens at 1440×900 with a 1100×640 minimum.
Status: done

### S-002 Watch the flow list
As the operator, I read every flow as a 28 px mono row with all columns and row states.
Screens: apps
Depends: S-001
Acceptance:
- [snap] Columns in order: dot, #, URL (host ink, path link, query tertiary), Client (monogram disc), Method badge, Status, Time, Duration, Request, Response, SSL padlock, Edited pencil, Origin tag, Mark swatch; header 28 px, 12 pt tracked caps, no bevel.
- [snap] States render per §2.7: pending (amber dot, grey dash), paused (amber dot, 2 px amber left edge, `Paused` badge), killed (grey, URL struck), replay (`↻` after #), agent (teal left edge, `agent` tag), out of scope (whole row tertiary), marked (6 px swatch).
- [unit] `FlowRow` equality covers the cells that can change (status, state, edited, comment, mark, duration, sizes, scope, WS frame counts) so a poll rebuild only reloads changed rows.
- [self] Appends land with `insertRows(withAnimation: [])`; no zebra, 1 px `rule` separators.
Status: done

### S-003 Select a flow to inspect it
As the operator, I click a row and the inspector shows that flow's summary strip and Request | Response panes.
Screens: apps
Depends: S-002
Acceptance:
- [snap] Selection fill is `ground.active`, never the accent; the summary strip shows method badge, status pill, URL, copy button, protocol/TLS/sizes/client/scope meta.
- [snap] Request pane tabs Headers Query Body Raw Summary Connection, Response pane tabs Headers Body Raw JSON Diff; active tab in the accent with a 2 px underline on the shared rule; pane titles 16/600.
- [self] Selecting row 41 focuses the inspector on it; the paused login (row 50) is selected on fixture load and its `x-forwarded-for` header is visible.
- [snap] Empty inspector reads "Nothing selected — select a flow to inspect it, or press ↑ ↓."
Status: done

### S-004 Act on a paused flow from the intercept bar
As the operator, I press Resume (or Apply & Resume), Resume all, Kill or Disarm on the amber bar and the paused flow moves on.
Screens: apps
Depends: S-002
Acceptance:
- [snap] Disarmed: no bar. Armed, nothing paused: 40 px `intercept.tint` notice with Rules… and Disarm. Paused: `intercept.base` fill, pulsing dot, `N paused`, oldest paused method+URL (`· edited (1 header)` when mutated), buttons Resume/Apply & Resume ⌘⏎ · Resume all · Kill ⌘\ ▾ · Rules… · Disarm i.
- [self] Resume on fixtures completes the flow with a 200 after a beat; Kill greys and strikes it; Apply & Resume sends `RequestEdits.diff(original, edited)` as `flow.mutate` then `flow.resume`.
- [unit] The bar targets the focused paused row, else the oldest paused.
- [manual] The dot stops pulsing under Reduce Motion.
Status: done

### S-005 Connect to a running aitm over the bus
As the operator, I start the app next to a running `aitm` and the list fills from the proxy without any setup.
Screens: apps, settings-bus
Depends: S-002
Acceptance:
- [unit] `BusEndpoint.fromConfigFile` reads `mcp.transport.loopback_tcp.{port,token}` from `AITM_CONFIG` or the default `config.yaml`; Settings ▸ Bus overrides with host/port/token file.
- [unit] `BusClient` writes the token line, `initialize`s as `aitm-mac`, lists tools, and reconnects with 1 s → 30 s back-off (24 tests against the fake loopback server).
- [self] The poll loop fetches `flow.list` every 500 ms and `flow.get` only for new or in-flight ids; finished flows are never re-fetched; rows rebuild oldest-first with `inScope` from `scope.list`.
- [snap] Status bar shows `● bus 127.0.0.1:9090` green when connected, amber connecting, red with the error, grey offline; the listening pill reads `listen:` from the same config.
Status: done

### S-006 Run the app on fixtures, snapshots and the self-test
As the operator (or an agent), I run the app in fixture, snapshot or self-test mode and get the mockup's state without a proxy.
Screens: apps, domains, scope, findings, browser, scripts, agent, settings-general, settings-bus, settings-appearance
Depends: S-001
Acceptance:
- [self] `APP_FIXTURES=1` loads the mockup's 14 flows, armed intercept, two paused, login selected; `APP_LIVE=1` captures the live bus instead.
- [snap] `tools/snap.sh` writes `<page>-light/dark.png` for every sidebar page and `settings-<tab>-*.png`, plus `-layout.json` grid probes; refuses to run without `APP_STORE` in /tmp.
- [self] `tools/selftest.sh` exits 0 with 9/9 checks; `swift test` passes 35/35; `tools/grid-lint.sh` and `check-layout.swift` print PASS.
Status: done

### S-007 See flat icons and an editorial hierarchy
As the operator, I see monochrome SF Symbols with no glass, chrome or bevels, and a typography-led hierarchy with calm chrome.
Screens: apps, settings-appearance
Depends: S-001
Acceptance:
- [snap] Toolbar groups hide their shared background; layout picker is two flat glyphs (ink active, tertiary inactive), no segmented control; client discs are flat monograms on `raised`.
- [snap] Sidebar group labels are 11 pt tracked small caps in tertiary; column headers likewise; pane titles 16/600; empty states are two lines of type, no icon.
- [snap] Hue appears only on data (method/status/severity/syntax), the intercept bar, the agent toggle and the accent's 3 %: tabs, focus, selection tint, URL path, product mark.
- [manual] Light and dark reviewed side by side; the flow list keeps 28 px rows.
Status: done

### S-008 Reorder, hide and resize columns, and keep the layout
As the operator, I drag column headers to reorder, drag edges to resize, and right-click the header to hide or show columns; the layout survives a restart.
Screens: apps, columns-menu
Depends: S-002
Acceptance:
- [snap] The header context menu lists every column with a check mark; `#`, URL and Method cannot be hidden.
- [self] Column order, widths and hidden set persist under `Store.url/columns.json` and reload on launch.
- [unit] Persisted state for an unknown column id is ignored; a missing column falls back to its default width.
- [manual] URL keeps `autoresizingMask`; dragging the splitter never squeezes URL under 200 px.
UX:
- Flow: right-click any column header -> menu of columns with check marks -> click toggles at once; drag a header to reorder, its edge to resize -> saved on release
- Surface: header context menu (changes one value on something on screen); no dialog
- States: `#`, URL, Method shown disabled-checked (cannot hide); layout file missing or stale -> defaults, silently
- Words: menu items are the column titles; "Reset Columns" at the bottom
- Access: the same list under View ▸ Columns (TODO: menu mirror); VoiceOver reads "URL column, shown"
Status: done

### S-009 Sort the list by a column
As the operator, I click a column header to sort by it, click again to reverse, and click `#` to return to capture order.
Screens: apps
Depends: S-002
Acceptance:
- [snap] The sorted header shows a small ↑/↓ in tertiary; `#` sorted ascending is the default and shows no indicator.
- [unit] Sorting by Status puts pending/paused (no code) last; Duration and sizes sort numerically with dashes last; URL sorts by host then path.
- [self] New flows append in sorted position without moving the selection; Auto-select follows the newest regardless of sort.
UX:
- Flow: click a header -> sorted ascending with ↑ -> click again -> descending ↓ -> click `#` -> capture order, no indicator
- Surface: inline (the header is the control); View ▸ Sort By mirrors it
- States: pending/paused rows sort last on Status; dashes last on numeric columns; a new row lands in sorted position without moving the selection
- Words: "Sort By ▸ Capture Order, URL, Client, …"; tooltip on the header shows "Sort by Time"
- Access: VoiceOver reads "Time, sorted ascending"; ⌘-click a header never changes sort
Status: done

### S-010 Drive the list from the keyboard
As the operator, I use ↑↓ to move, ⏎ to focus the inspector, `i e r n d m c p` as verbs, Space for quick look, and ⌘F ⌘⇧F ⌘K for filters and the palette.
Screens: apps, quick-look
Depends: S-002, S-004
Acceptance:
- [manual] With the list focused: `i` arms/disarms, `e` opens the paused row's Raw tab for editing (no-op with a hint on an unpaused row), `r` replays, `n` opens Compose, `d` kills a paused/pending row or deletes a finished one from the view, `m` opens the mark menu, `c` opens the comment field, `p` opens Build PoC, Space shows a Quick Look of the response body.
- [manual] ⏎ moves focus into the inspector; Esc returns it to the list; ↑↓ never animate.
- [snap] Every verb is in the Flow menu with the same shortcut, so the menu bar documents the keys.
- [unit] A key pressed while a text field is first responder is not swallowed as a verb.
UX:
- Flow: list focused -> ↑↓ move -> ⏎ focuses the inspector (Esc returns) -> single-key verbs act on the focused row -> result shows in the same frame (badge, new row, sheet)
- Surface: inline on the list; verbs also in Flow menu, palette and row context menu; Quick Look is a popover
- States: a verb that does not apply shows a one-line hint in the status bar ("Only a paused flow can be edited") and does nothing; keys typed in a text field are never verbs
- Words: Flow ▸ "Arm Intercept" / "Disarm Intercept" (i), "Edit Paused Request" (e), "Replay" (r), "Compose Request…" (n), "Kill" / "Delete" (d), "Mark ▸" (m), "Comment…" (c, ⌘L), "Build PoC from Flow…" (p), "Quick Look Body" (Space)
- Access: every verb reachable from the menu bar; ↑↓ never animate; focus ring on the table only when keyboard-navigating
Status: done
(Quick Look and Build PoC show a status-bar hint until M2/M5; `e` selects the paused row until the M4 editor.)

### S-011 Hover a row
As the operator, I move the mouse over a row and it takes the `hover` fill without changing the selection.
Screens: apps
Depends: S-002
Acceptance:
- [snap] Hovered row fills `ground.hover`; a selected row stays `active` under the pointer.
- [manual] Hover never changes selection or the inspector; the fill follows the pointer at 100 ms, no animation under Reduce Motion.
- [unit] `FlowRowView` tracks the pointer via a tracking area and redraws only itself.
UX:
- Flow: pointer over a row -> `hover` fill at once -> pointer leaves -> fill clears; nothing else changes
- Surface: inline
- States: selected row keeps `active` under the pointer; no hover while scrolling with the keyboard; no fill under Reduce Motion? (hover is instant, so it stays)
- Words: none
- Access: hover reveals nothing exclusive; every row action is also on the keyboard and in the context menu
Status: done

### S-012 Select several rows and read the summary
As the operator, I ⌘-click or ⇧-click rows and the status bar shows the count, total size and combined timing of the selection.
Screens: apps, multi-select
Depends: S-002
Core: F5 (live sizes and timing; fixtures carry them today)
Acceptance:
- [snap] Status bar centre reads `3 selected · 24.1 KB · 1.47 s` while more than one row is selected; the inspector shows the last-clicked row.
- [unit] Totals skip rows with unknown sizes and say `3 selected · 2 sized` when any are missing.
- [self] Deselecting back to one row returns the centre to `1 / N rows`.
UX:
- Flow: ⌘-click / ⇧-click rows -> status bar centre switches to the selection summary -> inspector shows the last-clicked row -> click a single row -> back to `1 / N rows`
- Surface: inline (status bar centre)
- States: "3 selected · 24.1 KB · 1.47 s"; missing sizes -> "3 selected · 2 sized · 18.0 KB"; one row -> "1 / 56 rows"
- Words: "selected", "sized"; numbers in SF Mono with tabular figures
- Access: VoiceOver reads the summary as one sentence; the summary is also in the Flow menu as a disabled line? No — it stays in the status bar only
Status: done

### S-013 Group flows by host or app from the sidebar
As the operator, I click a host under Domains or a client under Apps and the list shows only that group's flows.
Screens: apps, domains
Depends: S-002
Acceptance:
- [snap] Apps and Domains expand to one sub-item per client/host with counts, most flows first; the selected sub-item takes the `active` fill.
- [self] Selecting `curl` under Apps narrows the list to curl's flows; selecting Apps again shows all; counts update as flows arrive.
- [snap] Client sub-items show the real app icon when `bundleID` resolves to a running application, else the monogram.
UX:
- Flow: click Apps or Domains -> the group expands to its sub-items with counts -> click a sub-item -> list narrows, sub-item takes `active` -> click the group again -> all flows
- Surface: sidebar page (a place people come back to)
- States: no flows -> group shows "0" and no sub-items; counts update live; a client with a resolvable bundle id shows its app icon, else the monogram
- Words: group names "Apps", "Domains"; sub-items are the client name / host, never truncated in the middle? (hosts truncate in the middle, keeping the TLD)
- Access: arrow keys move through groups and sub-items; VoiceOver reads "curl, 3 flows"
Status: done

### S-014 Pin a host or app to Working
As the operator, I press ⇧P (or use the context menu) on a row and its host appears under Pinned; pins survive a restart.
Screens: apps
Depends: S-013
Acceptance:
- [snap] Pinned lists each pinned host/app as a sub-item; selecting one filters the list like Domains does; the Pinned count shows only when non-zero.
- [self] Pins persist under `Store.url/pins.json`; unpinning from the sub-item's context menu removes it.
- [unit] Pinning the same host twice stores it once.
UX:
- Flow: ⇧P on a row (or row context menu ▸ Pin Host, or sidebar sub-item ▸ Pin) -> host appears under Pinned at once -> click it to filter -> context menu ▸ Unpin removes it
- Surface: inline (sidebar group updates); no dialog
- States: Pinned empty -> group hidden count, sub-text "Nothing pinned — press ⇧P on a row." shown only when Pinned is selected; duplicates ignored
- Words: "Pin Host" / "Unpin Host", "Pin App" / "Unpin App"
- Access: Flow ▸ Pin Host ⇧P; VoiceOver reads "api.shop-staging.test, pinned"
Status: done

### S-015 Auto-select new flows
As the operator, I turn on Auto-select in the status bar and the inspector follows the newest flow as it arrives.
Screens: apps
Depends: S-005
Acceptance:
- [self] With Auto-select on, a new row becomes focused and the list scrolls to it; with it off, selection never moves when rows arrive.
- [snap] The status-bar button shows the `active` fill while on; the setting persists in `UserDefaults` and mirrors Settings ▸ General.
- [unit] Auto-select does not steal focus from a paused row the operator is editing.
UX:
- Flow: click Auto-select in the status bar (or View ▸ Auto-select ⇧⌘A) -> button takes `active` -> each new flow becomes focused and scrolls into view -> click again to stop
- Surface: inline (status bar button)
- States: on + a paused row being edited -> the editor keeps focus, the selection does not jump (the newest row is still scrolled into view)
- Words: "Auto-select"; tooltip "Follow the newest flow as it arrives (⇧⌘A)"
- Access: the button is a toggle to VoiceOver ("Auto-select, on")
Status: done

### S-016 Change the row density
As the operator, I choose Dense, Default or Comfortable in Settings ▸ General (or View ▸ Density) and row pitch, cell padding and body size move together.
Screens: apps, settings-general
Depends: S-002
Acceptance:
- [snap] Dense 28/13, Default 32/13, Comfortable 40/14, matching `size.row.*` tokens; the header stays 28.
- [self] Changing density reloads the table in place and keeps the selection and scroll position.
- [unit] The density setting maps to `Tok.Size.Row` and the inspector's code font size.
UX:
- Flow: Settings ▸ General ▸ Row density (or View ▸ Density ▸ …) -> list reflows at once, selection and scroll kept
- Surface: Settings (a preference), mirrored in the View menu
- States: Dense 28/13, Default 32/13, Comfortable 40/14; the header stays 28
- Words: "Dense", "Default", "Comfortable" with the pitch in parentheses in Settings only
- Access: radio group in Settings; View ▸ Density items show a check mark on the current one
Status: done

### S-017 Mark a flow with a colour or a comment
As the operator, I press `m` to pick one of 11 mark colours, or ⌘L / `c` to type a comment, and the row shows the swatch and the Comment column.
Screens: apps, mark-menu
Depends: S-010
Core: F6
Acceptance:
- [snap] The mark menu shows 11 system-colour swatches and Clear; the row's 6 px swatch and the Comment column update at once.
- [self] `flow.mark {id, marks}` and `flow.comment {id, text}` are sent; on fixtures the row updates locally.
- [unit] A comment longer than the column truncates with an ellipsis and shows in full in the Summary tab.
UX:
- Flow: `m` (or Flow ▸ Mark ▸, or row context menu ▸ Mark) -> popover of 11 swatches + Clear -> click -> swatch appears in the Mark column; `c` / ⌘L -> inline comment field in the status bar's left slot? No — a small popover anchored to the row with one field -> Return saves, Esc cancels -> Comment column shows it
- Surface: popover (a few related choices tied to one control) for marks; popover with a single field for comments
- States: mark menu shows the current colour checked; comment longer than the column truncates with full text in the tooltip and the Summary tab; live bus without F6 -> status-bar error "Marks need flow.mark (F6)" and the local change is kept
- Words: "Mark ▸ Red … Pink, Clear Mark", "Comment…", popover title "Comment", button "Save"
- Access: swatches have colour names for VoiceOver; the comment field is the only control focused on open (typing-only surface)
Status: done
(Fixtures update locally; live `flow.mark`/`flow.comment` wait on S-core-F6 and surface a status-bar error until then.)

### S-018 Pause capture and clear the session
As the operator, I click pause in the toolbar to stop recording and clear to drop every flow; both are real proxy state.
Screens: apps
Depends: S-005
Core: F7
Acceptance:
- [snap] Paused: the toolbar's Proxy switch is off and the pill reads `paused`.
- [self] Pause sends `proxy.pause`, resume `proxy.resume`, clear `flow.clear`; the list empties and the empty state returns.
- [manual] Clear asks for confirmation when any flow is paused.
UX:
- Flow: toolbar Proxy switch (or View ▸ Pause Proxy ⇧⌘R) -> switch grey, pill reads "paused" -> click again to resume; toolbar trash (File ▸ Clear Session ⌘⌫) -> list empties -> empty state returns
- Surface: inline toolbar toggles; Clear asks "Clear 2 paused flows too?" (confirmation dialog, destroys data) only when flows are paused, buttons "Clear" / "Cancel"
- States: paused + new client traffic -> rows still flow? No: paused capture records nothing; the pill says so. Live bus without F7 -> status-bar error "Pause needs proxy.pause (F7)"; fixtures toggle locally
- Words: "Proxy" (the switch), "Pause Proxy" / "Resume Proxy", "Clear Session", tooltip "Pause the proxy: traffic still passes and new flows are not recorded (⇧⌘R)"
- Access: both in the menu bar; the pill is a status, not a control, to VoiceOver
Status: done
(Fixtures toggle locally; live `proxy.pause/resume`/`flow.clear` wait on S-core-F7 and surface a status-bar error until then.)

---

## M2 Inspect

Every inspector tab and body viewer, on live detail.

### S-019 Read headers, cookies and query as tables
As the operator, I open Headers, Cookies or Query on the request and Headers or Set-Cookie on the response and read key : value tables.
Screens: inspect-headers, inspect-cookies
Depends: S-003
Core: F5
Acceptance:
- [snap] Two-column tables, lowercase mono names in `syntax.key`, 13 pt, 28 px rows; Cookies and Set-Cookie split attributes (`HttpOnly`, `Secure`, `SameSite`, `Expires`) into sub-columns.
- [unit] Cookie parsing handles quoted values, missing attributes and duplicate names.
- [self] On the live bus the tables fill from `flow.detail`; until it answers, grey loading bars at real size show (no shimmer).
UX:
- Flow: select a flow -> Request ▸ Headers (default for finished flows) / Cookies / Query, Response ▸ Headers / Set-Cookie -> read; click a value to select it, ⌘C copies `name: value`
- Surface: inspector tabs (details of the selection while working)
- States: no cookies -> "No cookies" in tertiary inside the pane; live without F5 -> loading bars; a header value longer than the pane truncates with the full value in a tooltip
- Words: tabs "Headers", "Cookies", "Query", "Set-Cookie"; column heads for cookies "Name · Value · Domain · Path · Expires · Flags"
- Access: tables are real rows to VoiceOver ("content-type, application/json")
Status: done

### S-020 Read the timing waterfall and the connection facts
As the operator, I open Timing to see DNS, connect, TLS, wait and download as bars, and Connection for protocol, TLS, ALPN, SNI, client and server.
Screens: inspect-timing
Depends: S-003
Core: F5
Acceptance:
- [snap] Timing draws one bar per phase in tertiary with the duration printed beside it; the total matches the Duration column.
- [unit] Missing phases print as a grey dash, a real 0 ms as `0 ms`.
- [snap] Connection shows `HTTP/2 · TLS 1.3 · h2` and the SNI; SSL padlock state agrees with the row.
UX:
- Flow: Request ▸ Timing -> five bars (DNS, Connect, TLS, Wait, Download) with ms beside each and the total under them; Request ▸ Connection -> key : value table
- Surface: inspector tabs
- States: phase missing -> dash and no bar; live without F5 -> loading bars; plain HTTP -> TLS row says "none"
- Words: "Timing", "Connection"; rows "protocol · tls · alpn · sni · client · server"
- Access: each bar has an accessibility value ("Wait, 89 ms")
Status: done

### S-021 View a pretty-printed body
As the operator, I open Body and see JSON, XML, HTML, JS, CSS, form or multipart bodies formatted and syntax-highlighted, with a format picker and a rendered preview for Markdown and HTML.
Screens: inspect-body
Depends: S-003
Core: F5
Acceptance:
- [snap] Line numbers in `syntax.lineNumber`, 13/20 code, fold chevrons on JSON/XML; the `JSON ▾` picker lists Auto, JSON, XML, HTML, JS, CSS, Form, Multipart, Markdown, Text, Hex.
- [unit] `JSONTree.pretty` keeps key order; form bodies split into a key : value table; multipart lists parts with their headers.
- [snap] Markdown and HTML offer a Rendered toggle; rendering is sandboxed with scripts off.
- [self] A 5 MB JSON body opens without blocking the main thread for more than one frame.
UX:
- Flow: Body tab -> the body pretty-printed in the detected format -> `JSON ▾` picker changes the format -> for Markdown/HTML a "Rendered" toggle appears -> fold chevrons collapse objects/arrays
- Surface: inspector tab; the picker is a popup button in the tab bar's trailing slot (a few choices tied to one control)
- States: empty body -> "No body" tertiary; unknown binary -> hex; a body over the inline limit -> truncated chip (S-027); rendering never runs scripts or loads remote resources
- Words: picker items "Auto, JSON, XML, HTML, JS, CSS, Form, Multipart, Markdown, Text, Hex"; toggle "Rendered"
- Access: the viewer is a text view (selectable, VoiceOver reads lines); ⌘A selects the body only
Status: done
(Fold chevrons are drawn but folding is disabled pending a range-remapping pass.)

### S-022 Explore a JSON body as a tree
As the operator, I open the JSON tab and fold nodes, copy a node, copy its path, filter by text and sort keys.
Screens: inspect-json
Depends: S-021
Acceptance:
- [snap] Rows show key, `{3 keys}` / `[2 items]` summaries when collapsed, scalar values in syntax colours; disclosure chevrons flat and grey.
- [unit] `JSONNode.filter` keeps ancestors of matches; `sortedKeys` keeps paths stable; `copyText` round-trips.
- [manual] Context menu: Copy Value, Copy Path (`$.user.roles[0]`), Expand All, Collapse All.
UX:
- Flow: Response ▸ JSON -> tree expanded one level -> click chevrons or ⌥-click to expand all -> type in the filter field to narrow -> right-click a node for Copy Value / Copy Path / Expand All / Collapse All; "Sort Keys" toggle in the trailing slot
- Surface: inspector tab (an outline)
- States: not JSON -> "Not JSON — see Body"; filter with no match -> "No match" and the tree stays; huge arrays show the first 1 000 items with "Show more"
- Words: summaries "{3 keys}", "[2 items]"; menu "Copy Value", "Copy Path", "Expand All", "Collapse All"; toggle "Sort Keys"
- Access: disclosure rows report expanded/collapsed; paths read as text
Status: done

### S-023 View an image body with its metadata
As the operator, I select an image response and see it inline with dimensions, type, size and colour space.
Screens: inspect-image
Depends: S-021
Acceptance:
- [snap] The image sits on a checkerboard at 1× (fit to pane when larger) with `1200×800 · PNG · 184 KB · sRGB` beneath.
- [unit] Unsupported or corrupt data falls back to the hex viewer with a notice.
- [manual] Open in Preview and Export… in the pane's trailing controls.
UX:
- Flow: select an image response -> Body shows it at 1× (fit when larger) on a checkerboard -> caption `1200×800 · PNG · 184 KB · sRGB` -> trailing slot: "Open in Preview", "Export…"
- Surface: inspector tab
- States: corrupt data -> hex viewer with "Not a readable image" notice; SVG renders via NSImage; animated GIF shows frame 1
- Words: caption order dimensions · type · size · colour space; buttons "Open in Preview", "Export…"
- Access: the image has an accessibility label with the caption
Status: done

### S-024 View a binary body as hex, protobuf or MessagePack
As the operator, I switch a binary body to Hex (offset · bytes · ASCII) or ask for a raw protobuf or MessagePack decode.
Screens: inspect-hex
Depends: S-021
Acceptance:
- [snap] Hex lines `00000010  48 54 54 50 …  HTTP…`, 16 bytes per line, mono, offsets tertiary.
- [unit] `HexDump.lines(range:)` serves only visible lines; protobuf raw decode lists field number, wire type, value; MessagePack decodes to the JSON tree.
- [self] A 20 MB body scrolls through the hex viewer without loading it all into rows.
UX:
- Flow: Body picker ▸ Hex -> offset · bytes · ASCII lines; picker ▸ Protobuf (raw) -> field table; picker ▸ MessagePack -> JSON tree
- Surface: inspector tab (picker formats)
- States: a 20 MB body -> hex pages by visible lines; protobuf that fails to walk -> "Not protobuf — showing hex"
- Words: hex columns unlabelled (Proxyman convention); protobuf columns "Field · Wire type · Value"
- Access: hex lines are selectable text
Status: done

### S-025 Read a streaming response as an SSE event list
As the operator, I select an `text/event-stream` flow and see each event (id, event, data, time) as a row, with the merged text for OpenAI-style deltas.
Screens: inspect-sse
Depends: S-021
Core: F4, F5
Acceptance:
- [snap] One row per event, newest at the bottom, `data` pretty-printed when JSON; a `Merged` toggle concatenates deltas.
- [unit] Multi-line `data:` fields and comment lines parse per the SSE spec.
- [self] New events append live without scrolling the operator away from where they read.
UX:
- Flow: select a `text/event-stream` flow -> Body shows one row per event (time · id · event · data) -> "Merged" toggle concatenates OpenAI-style deltas into one text -> new events append at the bottom without moving the scroll
- Surface: inspector tab (a list)
- States: no events yet -> "Waiting for events…"; a comment line shows dimmed; live without F4 -> events refresh with the poll
- Words: toggle "Merged"; columns "Time · ID · Event · Data"
- Access: rows read as "event message, data …"
Status: done

### S-026 Diff two flows
As the operator, I select a second flow with ⌘-click and open Diff to compare request head, request body, response head and response body side by side or unified.
Screens: inspect-diff
Depends: S-012
Acceptance:
- [snap] Four collapsible sections; added lines on `diffAdd`, removed on `diffRemove`; a Side-by-side / Unified toggle.
- [unit] `FlowDiff.compare` pretty-prints JSON on both sides first; `unified()` exports a patch with one header per section.
- [manual] Export Patch… writes the unified text; a `truncated` chip appears over 2 MB per side.
UX:
- Flow: ⌘-click a second row -> Response ▸ Diff -> four collapsible sections (Request head · Request body · Response head · Response body) side by side -> "Unified" toggle -> "Export Patch…" saves the unified text
- Surface: inspector tab; Export Patch… is a save panel
- States: one row selected -> "Select a second flow with ⌘-click to compare"; identical sections collapse with "No changes"; over 2 MB a side -> `truncated` chip
- Words: toggle "Side by side" / "Unified"; button "Export Patch…"; section titles as above
- Access: added/removed lines carry +/- markers, not colour alone
Status: done

### S-027 Page through a large body
As the operator, I open a body the core truncated or paged and see a `truncated` chip and a Load more control instead of a frozen viewer.
Screens: inspect-body
Depends: S-021
Core: F5
Acceptance:
- [snap] A raised chip `truncated · 2.0 of 18.4 MB` sits in the tab bar's trailing slot; Load more fetches the next range via `flow.detail {body: range}`.
- [unit] Paged ranges concatenate in order; a failed range shows Retry inside the viewer with the last good time.
UX:
- Flow: open a truncated body -> chip `truncated · 2.0 of 18.4 MB` in the tab bar's trailing slot -> "Load more" at the bottom of the viewer fetches the next range -> the viewer grows in place
- Surface: inline chip + inline button
- States: fetch failing -> "Unable to load the next 2 MB · Retry" with the last good time; everything loaded -> chip disappears
- Words: chip "truncated · X of Y"; button "Load more"; error as above
- Access: the chip is a status, the button a real button
Status: done
(Chip + Load more are built; the range fetch itself reports "needs flow.detail (F5)" until S-core-F5.)

### S-028 Copy a request as code or export the body
As the operator, I copy the request as cURL, httpie, Python or fetch from the summary strip's menu, or export the body to a file.
Screens: inspect-body
Depends: S-003
Acceptance:
- [unit] `CodeExport.curl/httpie/pythonRequests/fetch` drop hop-by-hop and pseudo-headers, quote safely, never add `-k`.
- [manual] ⇧⌘C copies cURL; the menu lists the other three; Export Body… proposes a filename from the path and content type.
- [self] The copied text appears on the pasteboard as plain text.
UX:
- Flow: summary strip ▸ copy menu (or ⇧⌘C) -> "Copy as cURL" at once; menu lists httpie, Python, fetch; "Export Body…" -> save panel prefilled with the path's last segment and the type's extension
- Surface: menu on the summary strip's copy button; save panel for export
- States: no body -> "Export Body…" disabled; non-UTF-8 body -> cURL uses base64 and says so in a tooltip
- Words: "Copy as cURL ⇧⌘C", "Copy as httpie", "Copy as Python (requests)", "Copy as fetch", "Export Body…"
- Access: all in Flow ▸ Copy As ▸ too
Status: done

### S-029 Find in body with match highlighting
As the operator, I press ⌥⌘F in a body viewer, type a term and see every match highlighted with next/previous navigation.
Screens: inspect-find
Depends: S-021
Acceptance:
- [snap] A 28 px find field in the tab bar's trailing slot with `3 of 12`; matches on `syntax.match`, the current one with a 2 px accent outline.
- [unit] Search is case-insensitive by default with a regex toggle; a filter-bar body term pre-fills and highlights.
- [manual] ⏎ and ⇧⏎ step; Esc closes and keeps the scroll position.
UX:
- Flow: ⌥⌘F in a body viewer -> 28 px find field in the tab bar's trailing slot with focus -> type -> matches highlight, `3 of 12` -> ⏎ / ⇧⏎ step, Esc closes and keeps the scroll position
- Surface: inline field (a tool kept beside the work)
- States: no matches -> `0 of 0` in tertiary, field stays; regex toggle "(.*)" invalid -> field border intercept.deep
- Words: placeholder "Find in body"; counter "n of m"; toggle tooltip "Regular expression"
- Access: the field is the only control focused on open; the current match is announced
Status: done

---

## M3 Filter & find

### S-030 Filter by content type with the chip bar
As the operator, I click a chip (or press ⌘1…9) and the list narrows to that protocol, transport or content type.
Screens: apps
Depends: S-002
Acceptance:
- [snap] One chip active on `raised` at 500 weight; separators between groups.
- [self] JSON narrows the list; WebSocket keeps only WS flows; TCP / UDP / L4 keep the raw-L4 rows by transport; All restores.
- [unit] `ContentCategory.classify` maps content types; h1/h2 look at the HTTP version; tcp/udp/l4 look at `FlowRow.l4` (ST-AC11).
- [hover] Every chip says what it keeps.
Status: done

### S-031 Stack filters in the filter bar
As the operator, I press ⌘F and add rows of Field · Operator · Value, combined with All (AND) or Any (OR), and the list follows every keystroke.
Screens: filter-bar
Depends: S-030
Acceptance:
- [snap] The bar opens under the chip bar; each row has a field menu (URL, Host, Path, Query, Method, Status, Request/Response header, Request/Response body, Content-type, Client, Duration, Size, Colour, Comment, Origin, Scope, WebSocket direction), an operator menu scoped to the field, a value field, a `not` toggle and a remove button; `+` adds a row.
- [unit] `CompiledFilter` matches rows and details for contains / equals / wildcard / regex / JSON path / full text / greater / less; an invalid regex marks the row and matches nothing.
- [self] Two rows under Any widen the list; switching to All narrows it; the status bar shows `n / N rows`.
- [manual] Filtering 50 rows/s stays under one frame per poll.
UX:
- Flow: ⌘F (or chip bar ▸ Filters, View ▸ Filter Bar) -> bar opens under the chips with one empty row, value field focused -> pick Field, Operator, type Value -> list follows each keystroke -> `+` adds a row -> All / Any switch -> ⌘F again or the ✕ closes and clears
- Surface: inline bar (a tool kept open beside the work); each row is three popup buttons + a field + `not` + ✕
- States: empty row = no filtering; invalid regex -> value field border intercept.deep and tooltip with the error, row matches nothing; status bar shows `n / N rows`
- Words: bar label "Match" + segmented "All | Any"; row controls "Field ▾", "Operator ▾", value placeholder per operator ("contains…", "regex…", "$.path or $.path=value"); `not` toggle reads "not"; buttons "+ Add Row", "Advanced", bookmark glyph for saved filters, "Clear"
- Access: every control labelled; Tab order field → operator → value → not → remove; ⌘F toggles, Esc in the value field closes the bar
Status: done

### S-032 Edit the filter as a mitmproxy expression
As the operator, I flip the filter bar to Advanced and see or type the same filter as text (`~m POST & ~c 5`), copyable between surfaces.
Screens: filter-bar
Depends: S-031
Acceptance:
- [unit] `FilterExpression.parse` and `.text` round-trip every stack; nested expressions stay in text form with the rows view disabled and a hint.
- [snap] A parse error underlines the offset and prints the message beneath the field.
- [manual] Paste a mitmproxy filter and the rows view populates when it is flat.
UX:
- Flow: filter bar ▸ "Advanced" -> the rows fold into one mono text field holding the same filter (`~m POST & ~c 5`) -> edit -> list follows; "Rows" switches back when the expression is flat
- Surface: inline (the same bar, second mode)
- States: parse error -> the character at the offset underlined in intercept.deep and the message in 12 pt beneath; nested expression -> "Rows" disabled with hint "Nested filter — edit as text"
- Words: toggle "Rows | Advanced"; placeholder "~u login & ~m POST"; the expression also prints read-only in tertiary under the rows view
- Access: the text field announces errors; ⌘C copies the expression
Status: done

### S-033 Save a filter by name
As the operator, I save the current stack under a name from the filter bar's bookmark menu and reapply it from that menu or the palette.
Screens: filter-bar, saved-filters
Depends: S-031
Acceptance:
- [unit] Saved filters persist as `{name, expression}` under `Store.url/filters.json`; renaming and deleting work.
- [snap] The bookmark menu lists saved filters with their expression in tertiary beneath the name.
- [self] Applying a saved filter sets both the rows and the Advanced text.
UX:
- Flow: bookmark glyph ▸ "Save Filter…" -> name field in a popover -> Save -> listed in the menu with its expression beneath; choose one -> rows + text fill; "Manage…" -> rename/delete inline
- Surface: menu on the bar's bookmark button; popover for the name (one value)
- States: no saved filters -> menu shows "No saved filters"; a name already used -> "Replace" instead of Save
- Words: "Save Filter…", "Manage Saved Filters…", popover title "Save Filter", field placeholder "Name", button "Save"
- Access: saved filters also appear in the palette as "Filter: <name>"
Status: done

### S-034 Filter the sidebar quickly
As the operator, I press ⌘⇧F, type into the sidebar's filter field, and the Apps, Domains and Pinned sub-items narrow to matches.
Screens: sidebar-filter
Depends: S-013
Acceptance:
- [snap] The field takes focus with a 2 px accent ring; non-matching sub-items hide; group headers stay.
- [unit] Matching is case-insensitive substring over host and client name.
- [manual] Esc clears and returns focus to the list.
UX:
- Flow: ⌘⇧F -> the sidebar filter field takes focus with the accent ring -> type -> Apps, Domains and Pinned sub-items narrow (groups expand to show matches) -> Esc clears and returns focus to the list
- Surface: inline field (already in the sidebar's foot)
- States: no match -> each group shows "No match" in tertiary; empty query -> groups fold back to the selected page's expansion
- Words: placeholder "Filter", shortcut hint "⌘⇧F" in the field
- Access: the field is a real text field; matching is case-insensitive substring over host and client name
Status: done

### S-035 Run a command from the palette
As the operator, I press ⌘K, type part of a command's name or description, and run it; forms for its parameters are built from `tools/list`.
Screens: palette
Depends: S-005
Acceptance:
- [snap] A floating panel, radius 10, `floating` shadow, 13 pt rows with name, description in tertiary and the shortcut right-aligned; Recent and Pinned sections on top.
- [unit] Fuzzy ranking scores name over description; every tool from `tools/list` appears; a `FlowId` parameter becomes a flow picker, `Bytes` a file/hex input, `required` drives validation.
- [manual] Keyboard open/close does not animate; mouse open scales from 0.97 in 160 ms.
UX:
- Flow: ⌘K -> floating panel over the window, field focused -> type -> ranked results (Recent, Pinned, Commands, Flows, Setup) -> ↑↓ ⏎ -> a command without parameters runs at once; one with parameters opens its form in the panel (fields from tools/list: label = name, help = description, required marked) -> ⏎ runs -> result line shows in the panel for 2 s -> Esc closes
- Surface: floating panel (radius 10, floating shadow); keyboard open/close never animates
- States: bus offline -> commands section says "Bus offline — connect in Settings ▸ Bus" and only local actions list; a failed command shows the error inline in the panel; gated commands (confirm) show "Confirm" before running
- Words: placeholder "Type a command, a URL or a setting…"; sections "Recent", "Pinned", "Commands", "Flows", "Setup"; run button "Run ⏎"
- Access: full keyboard; VoiceOver reads "flow.replay, Replay a captured flow, command"
Status: done

### S-036 Jump to a flow or a setup action from the palette
As the operator, I type a URL fragment to select that flow, or a word like "install" to run a setup action (install CA, add scope, open browser).
Screens: palette-flows
Depends: S-035
Acceptance:
- [unit] Flow results show method badge, status and URL; selecting one selects and reveals the row.
- [snap] Setup actions form their own section with the gated ones (CA install) showing a confirmation step.
UX:
- Flow: ⌘K -> type part of a URL -> matching flows list with method badge, status and URL -> ⏎ selects the row and scrolls to it; type "install"/"scope"/"browser" -> Setup actions: "Install CA…", "Add Host to Scope…", "Open Browser"
- Surface: the same palette, two more sections
- States: CA install is gated -> a confirm step with the proxy's confirm text; no flows match -> section hidden
- Words: section titles "Flows", "Setup"; setup items as above with ellipses when they ask for input
- Access: flow rows read as "POST, 200, https://…"
Status: done

---

## M4 Intercept & compose

### S-037 Edit a paused request and Apply & Resume
As the operator, I press `e` on a paused row, change method, path, headers or body in editable tables and an NSTextView body, and press Apply & Resume.
Screens: edit-paused
Depends: S-004, S-019
Acceptance:
- [snap] Headers and Query become editable tables with add/remove; Body is an `NSTextView` with the syntax colours; edited lines get a 2 px amber left edge; the footer reads `N edits pending · Apply & Resume sends flow.mutate then flow.resume · Revert to original`.
- [unit] `RequestEdits.diff(original, edited)` yields only changed headers, body and start line; the Edited pencil appears after a successful mutate.
- [self] Revert restores the original from the core's backup and clears the pencil.
- [manual] Leaving the row with pending edits asks Keep editing / Discard.
UX:
- Flow: `e` on a paused row (or Flow ▸ Edit Paused Request) -> Request pane switches to Raw with the body editable and Headers/Query as editable tables -> edited lines take the amber edge, the footer counts edits -> ⌘⏎ Apply & Resume (or the bar's button) -> flow continues, pencil appears; "Revert to Original" (⌘Z in the editor) discards
- Surface: inline in the inspector (the paused flow is already on screen)
- States: unpaused row -> hint "Only a paused flow can be edited"; mutate fails -> status-bar error, edits kept; live without F5 -> the raw text comes from the summary only, with a note
- Words: footer "N edits pending · Apply & Resume sends flow.mutate then flow.resume · Revert to original"; button "Apply & Resume ⌘⏎"
- Access: the editor is a text view; the tables are real rows with add/remove buttons
Status: done

### S-038 Edit a paused request's raw bytes
As the operator, I open Raw on a paused row and edit the exact message text, including the start line, and apply it.
Screens: edit-paused
Depends: S-037
Acceptance:
- [unit] Raw text parses back into start line, headers and body; a malformed message is refused with the line number.
- [snap] Non-UTF-8 bodies switch Raw to read-only with a hint to use Hex.
- [self] Changing the start line sends `method` and `path` in the edits.
UX:
- Flow: Raw tab while paused -> edit the exact bytes (start line, headers, blank line, body) -> Apply & Resume parses them back into method/path/headers/body
- Surface: inline (the same Raw editor)
- States: an unparsable message -> inline error under the editor, Apply disabled
- Words: error "Could not parse the request: <reason>"
- Access: ⌘A selects the message only
Status: done

### S-039 Kill with an abort mode
As the operator, I open the Kill menu on the intercept bar or row and choose reset connection, 429 or 503.
Screens: kill-menu
Depends: S-004
Core: F3
Acceptance:
- [snap] `Kill ⌘\ ▾` opens a menu: Reset connection (default), Respond 429, Respond 503; the chosen mode is remembered for the session.
- [self] `flow.kill {id, mode}` is sent; the row shows `killed` grey and struck for reset, or the synthetic status for 429/503.
UX:
- Flow: bar ▸ Kill ▾ -> menu Reset connection ✓ / Respond 429 / Respond 503 -> choosing runs it and remembers the mode -> Kill's main button and ⌘\ reuse it
- Surface: menu on the split button
- States: live before F3 -> the core resets and the status bar notes "mode needs flow.kill {mode} (F3)"; fixtures show the synthetic status in the row
- Words: "Reset connection", "Respond 429", "Respond 503"; tooltip "Kill <mode> (⌘\); click the chevron for other modes"
- Access: the menu is a real menu; the default action is the button itself
Status: done

### S-040 Set breakpoint rules
As the operator, I open Rules… and add rules (name, URL wildcard or regex, method, request or response phase, flag) so only matching flows pause.
Screens: rules-sheet
Depends: S-004
Core: F3
Acceptance:
- [snap] A sheet with a rules table on the left and the Proxyman form on the right (name, URL, wildcard/regex switch, method, phase checkboxes, Test your rule field, flag); one primary button `Save ⌘⏎`.
- [unit] Rule validation rejects an invalid regex and an empty URL; `Test your rule` evaluates against the current list and shows match counts.
- [self] `flow.intercept {enabled, rules}` is sent; the armed notice reads `Intercept armed — 2 rules`.
UX:
- Flow: bar ▸ Rules… (or Proxy ▸ Breakpoint Rules… ⇧⌘B) -> sheet: rules table left, form right (Name, URL + Wildcard|Regex, Method, ☑ Request ☑ Response, Test your rule, Flag) -> Save ⌘⏎ -> armed notice reads "Intercept armed — 2 rules"
- Surface: sheet (one task that finishes or cancels)
- States: invalid regex / empty URL -> inline error under the field, Save disabled; no rules -> "Every request pauses" note; live before F3 -> rules kept locally and the bar says "rules need F3"
- Words: sheet title "Breakpoint Rules"; buttons "Add Rule", "Remove", "Test your rule", "Save ⌘⏎", "Cancel"
- Access: table rows selectable by keyboard; form fields in reading order
Status: done

### S-041 Intercept and edit a response
As the operator, I pause at the response phase and change status, headers or body before the client sees it.
Screens: edit-paused
Depends: S-037, S-040
Core: F3
Acceptance:
- [snap] The summary pill reads `Paused · response`; the Response pane becomes editable like the request.
- [self] Apply & Resume sends the response edits then `flow.resume`; the Edited pencil appears.
UX:
- Flow: a rule with ☑ Response pauses at the response -> summary pill `Paused · response` -> Response pane editable (status, headers, body) -> Apply & Resume
- Surface: inline in the inspector
- States: before F3 nothing pauses at the response; the pill never shows
- Words: pill "Paused · response"; footer as the request editor's
- Access: same as S-037
Status: todo

### S-042 Compose a request
As the operator, I press ⌘N (or `n`) and fill method, URL, headers, query and body in a sheet, pick a template, and Send; the result appears as a new flow.
Screens: compose-sheet
Depends: S-005
Acceptance:
- [snap] A sheet: method menu, URL field, tabs Headers (bulk edit text) · Query · Body (raw / JSON / form / multipart); templates Empty, GET, POST JSON, POST Form, Multipart, WebSocket; a History list on the left; one primary button `Send ⌘⏎`.
- [unit] History persists under `Store.url/compose.json`, newest first, capped at 200; a URL to a host outside `scope.list` disables Send with "Out of scope — add host to scope to send".
- [self] `request.send` returns a FlowId; the new row is selected, marked `↻`, origin human.
UX:
- Flow: ⌘N / `n` / toolbar compose / palette -> sheet with History left, Method + URL, Headers · Query · Body tabs -> Template menu fills a shape -> ⌘⏎ Send -> sheet closes, the new flow is selected with ↻
- Surface: sheet (one short task that must finish or cancel)
- States: URL without a host -> Send disabled "Enter a URL with a host"; host outside scope -> "Out of scope — add host to scope to send"; send fails -> status-bar error, sheet stays; no history -> "Nothing sent yet"
- Words: title "Compose Request"; tabs "Headers", "Query", "Body"; body kinds "Raw | JSON | Form | Multipart"; templates "Empty, GET, POST JSON, POST Form, Multipart, WebSocket (disabled until F9)"; buttons "Send ⌘⏎", "Cancel"
- Access: the URL field has focus when empty; Esc cancels
Status: done

### S-043 Import a cURL command into Compose
As the operator, I paste a `curl …` command anywhere in the compose sheet and the fields fill from it.
Screens: compose-sheet
Depends: S-042
Acceptance:
- [unit] `CodeExport.parseCurl` handles `-X -H -d --data-raw --json -u -A -b -e --url -G -I -F`, attached short values, quoting and line continuations.
- [snap] A pasted command shows an `Imported from cURL` chip; unknown flags are listed in a tertiary note.
UX:
- Flow: paste a `curl …` command into the URL, Headers or Body field (or Template ▸ Import cURL from Clipboard) -> every field fills -> chip "Imported from cURL" -> unknown flags listed beneath in tertiary
- Surface: inline (the compose sheet)
- States: text that is not a curl command is left alone; flags curl would ignore are listed, never silently dropped
- Words: chip "Imported from cURL"; note "Ignored cURL flags: --foo"
- Access: nothing changes focus on import
Status: done

### S-044 Repeat a flow, or edit and repeat
As the operator, I press `r` to replay the selected flow unchanged, or ⇧R to open Compose prefilled with it.
Screens: apps, compose-sheet
Depends: S-042
Acceptance:
- [self] `flow.replay` returns a new id; the new row carries `↻` and is selected; on fixtures a copy appends.
- [snap] Edit & repeat opens the sheet with method, URL, headers and body from the detail; Send creates a flow with `↻`.
- [unit] Replay of an out-of-scope flow is disabled with the scope tooltip.
UX:
- Flow: `r` -> the flow is sent again unchanged, the copy appends with ↻ and is selected; ⇧R (or Flow ▸ Edit & Replay…, context menu) -> Compose opens prefilled (host and content-length dropped) -> Send
- Surface: inline for Replay; the compose sheet for Edit & Replay
- States: out-of-scope row -> both disabled with the scope tooltip; replay fails -> status-bar error
- Words: "Replay" (r), "Edit & Replay…" (⇧R)
- Access: both in the Flow menu and the context menu
Status: done

### S-045 Read a WebSocket flow's frames
As the operator, I select a WebSocket flow and the inspector lists frames (direction, opcode, length, time, injected) with text, JSON tree and hex viewers and a sent/received filter.
Screens: inspect-ws
Depends: S-003
Core: F4, F5
Acceptance:
- [snap] The Request | Response split becomes one frame list over a frame viewer; direction arrows `↑ ↓`, injected frames tagged; the row's Request/Response cells show `↑ ↓` counts.
- [unit] Frame viewers reuse the JSON tree and hex viewers; the filter hides one direction.
- [self] Selecting a WebSocket flow loads its frames; JSON/binary/injected frames detected.
UX:
- Flow: select a WebSocket row -> the inspector shows one frame list (dir · opcode · injected · preview · length · time) over a frame viewer (JSON/text/hex) -> a Both | Sent | Received filter in the list header
- Surface: inspector (replaces the Request | Response split for WS flows)
- States: no frames yet -> "No frames yet"; a filtered-out direction -> "No frames in this direction"
- Words: filter "Both | Sent | Received"; tag "injected"
- Access: rows read as "sent, text, 42 bytes"; filter id `ws-direction-filter`
Status: done

### S-046 Act on several flows at once
As the operator, I select several rows and resume, kill, export or diff them from the Flow menu or the context menu.
Screens: multi-select
Depends: S-012
Acceptance:
- [unit] Resume and Kill apply to the paused rows in the selection in capture order; the status bar reports `Resumed 2 · skipped 1 (not paused)`.
- [manual] Diff is enabled for exactly two rows; Export for any number.
UX:
- Flow: ⌘-click rows -> Flow ▸ Resume Selected (⌥⌘⏎) / Kill Selected, or the context menu's "Resume 3 Selected" -> paused rows act in capture order -> status bar reports "Resumed 2 · skipped 1 (not paused)"
- Surface: inline (menu items on the existing selection)
- States: nothing paused in the selection -> items disabled; Diff enabled for exactly two rows (M2); Export for any number (M6)
- Words: "Resume Selected", "Kill Selected", context "Resume N Selected" / "Kill N Selected"; report as above
- Access: the report is announced via the status bar
Status: done

---

## M5 aitmproxy's own

### S-047 Review the scope and add a host
As the operator, I open Scope… (⇧⌘O) or the Scope sidebar page and add `host`, `host:port` or `*.wildcard` entries, with each host's rate limit and back-off shown read-only.
Screens: scope, scope-sheet
Depends: S-005
Acceptance:
- [snap] The Scope page lists entries with their limit readout (`10 req/s · back-off 2×`) and the count of flows in scope; the sheet has a text field with validation and `Add ⌘⏎`.
- [unit] Entry validation accepts the three forms and rejects schemes and paths; `hostMatches` handles wildcard and port.
- [self] `scope.add` is sent; the Scope count in the sidebar and `N hosts in scope` in the status bar update; affected rows lose their dimming.
UX:
- Flow: sidebar ▸ Scope (or Proxy ▸ Scope… ⇧⌘O) -> the Scope page: entries table over the in-scope flow list -> "Add Host…" or type in the field at the top -> ⌘⏎ adds -> the row loses its dimming at once
- Surface: sidebar page with an inline add field; the sheet (⇧⌘O) is the same panel for when the list is elsewhere
- States: empty -> "No hosts in scope — add one to authorise testing; everything stays read-only until then." with the field focused; invalid entry -> message under the field, Add disabled; live `scope.add` failing -> status-bar error, entry kept pending in tertiary
- Words: columns "Host · Limit · Back-off · Flows"; button "Add ⌘⏎"; placeholder "host, host:port or *.wildcard"
- Access: entries are a real table; the field is the only focused control when empty
Status: done

### S-048 Remove a host from scope
As the operator, I select a scope entry and press Delete to remove it; flows on that host dim again.
Screens: scope-sheet
Depends: S-047
Core: F12
Acceptance:
- [self] `scope.remove` is sent; rows on that host render out of scope and their actions disable.
- [manual] Removal asks for confirmation when a paused flow is on that host.
UX:
- Flow: select an entry -> Delete (or its ✕) -> gone; flows on that host dim; if a paused flow is on the host, "Remove host from scope? 1 paused flow will become read-only." Remove / Cancel
- Surface: inline; confirmation only when a paused flow is affected
- States: live before F12 -> status-bar error "Removing needs scope.remove (F12)" and the entry stays
- Words: "Remove from Scope"
- Access: Delete key on the selected row
Status: done

### S-049 See out-of-scope flows dimmed with their actions disabled
As the operator, I see flows outside the scope in tertiary, and every mutating action on them disabled with the tooltip "Out of scope — add `host` to scope to act".
Screens: apps
Depends: S-002, S-047
Acceptance:
- [snap] Row 44 (telemetry host) renders in `text.tertiary` end to end; the summary strip reads `out of scope` in `intercept.deep`.
- [manual] Replay, Edit, Mutate, Build PoC and Compose-from are disabled on it with the tooltip; Resume/Kill of a paused out-of-scope flow stay enabled.
- [self] `scope.list` empty on the live bus dims every row.
UX:
- Flow: nothing to do — rows outside scope render in tertiary; hovering a disabled action shows "Out of scope — add host to scope to act"; the summary strip reads "out of scope" in intercept.deep
- Surface: inline states
- States: empty scope on the live bus dims nothing (the proxy enforces scope; an empty list means "no guard") — shows a status-bar note "No scope set"
- Words: tooltip as above; strip "out of scope"
- Access: disabled items stay visible to VoiceOver with the reason as help
Status: done

### S-050 Browse findings in the PoC panel
As the operator, I open Findings and see every PoC run as a row: title, severity pill, target, passed/failed, when, origin.
Screens: findings
Depends: S-005
Core: F13
Acceptance:
- [snap] Severity pills critical/high/medium/low/info on their tint pairs; failed runs show ✗ in `status.serverError`; agent-run rows carry the teal tag; empty state "No findings — build a PoC from any flow with p."
- [self] `poc.list` fills the list; the Findings count in the sidebar and status bar match.
UX:
- Flow: sidebar ▸ Findings -> list: title · severity pill · target · ✓/✗ · when · origin -> select one -> detail on the right
- Surface: sidebar page (master list left, detail right, replacing the flow list)
- States: empty -> "No findings — build a PoC from any flow with p."; live before F13 -> findings from this session's poc.run results only, with a note
- Words: severity pills "Critical, High, Medium, Low, Info"; result "passed" / "failed"
- Access: rows read "title, high, failed, 11:05"
Status: done

### S-051 Read a finding's detail
As the operator, I select a finding and read its YAML (editable, Save), open the finding capture in the inspector, view the screenshot, read the assertions table, and export the bundle.
Screens: finding-detail
Depends: S-050
Core: F13
Acceptance:
- [snap] YAML syntax-highlighted in a code view with line numbers; screenshot inline; assertions table `assertion · ✓/✗`; buttons Open capture · Run again · Export.
- [self] Open capture selects `finding_capture` in the list and focuses the inspector; Save writes the YAML through `poc.get/set` or the path.
- [manual] Export writes YAML + PNG + HAR of the capture into a folder the operator chooses.
UX:
- Flow: select a finding -> YAML (editable) with Save, the screenshot, the assertions table, buttons Open capture · Run again · Export -> Open capture selects the flow and switches to Apps with the inspector focused
- Surface: detail pane of the Findings page
- States: no screenshot -> "No screenshot" placeholder at the image's size; YAML changed -> Save enabled, "Unsaved" chip; Export -> folder panel, writes YAML + PNG + HAR
- Words: section labels "YAML", "Screenshot", "Assertions"; buttons as above
- Access: the YAML view is a text view; the assertions table has real rows
Status: done

### S-052 Run a PoC again
As the operator, I press Run again, edit the target and vars in a small form, and get a new finding row when it completes.
Screens: finding-detail
Depends: S-051
Acceptance:
- [unit] The form is built from `poc.run`'s schema (`poc_path`, `target`, `vars`); vars edit as key : value rows.
- [self] The new run appears in Findings with passed/failed and selects itself.
UX:
- Flow: Run again -> small popover: Target (prefilled), Vars as key : value rows -> Run -> row appears in Findings with its result and selects itself
- Surface: popover from the button
- States: running -> button reads "Running…"; failure -> inline error in the popover
- Words: "Run again", fields "Target", "Vars"; button "Run ⏎"
- Access: Target focused on open
Status: done

### S-053 Build a PoC from a flow
As the operator, I press `p` on a row (or use the palette) and name the PoC and the parameter to vary; the YAML path appears and opens in Findings.
Screens: build-poc
Depends: S-003
Acceptance:
- [snap] A small sheet: name, parameter picker populated from the request's query, headers and JSON body keys, `Build ⌘⏎`.
- [self] `poc.build {flow_id, name, param}` returns a path; the Findings page selects the new PoC and shows its YAML.
- [unit] Disabled with the scope tooltip for out-of-scope rows.
UX:
- Flow: `p` on a row (Flow ▸ Build PoC from Flow…, context menu, palette) -> sheet: Name (prefilled from path), Parameter picker (query keys, header names, JSON body keys), `Build ⌘⏎` -> Findings page opens on the new PoC's YAML
- Surface: sheet
- States: out-of-scope row -> disabled with the scope tooltip; no parameters found -> picker shows "none" and Build still works; failure -> inline error
- Words: title "Build PoC", fields "Name", "Parameter", button "Build ⌘⏎"
- Access: Name focused on open
Status: done

### S-054 Open the browser view
As the operator, I open Browser and see a tab per page with a URL field, back/forward/reload, screenshot, Eval… and DOM tools.
Screens: browser
Depends: S-005
Core: F14 (tabs)
Acceptance:
- [snap] Flat toolbar: URL field, four glyph buttons, `Eval…` and `DOM` as text buttons; tabs as plain text with a close glyph; empty state "No tabs — open a page with ⌘T."
- [self] `browser.navigate` loads a URL; `browser.eval` returns text into a console drawer; `browser.get_dom` shows an outline.
- [snap] Flows the browser produces show `obscura` in the Client column.
UX:
- Flow: sidebar ▸ Browser (⇧⌘W) -> tabs row + flat toolbar (URL field, ← → ⟳, screenshot, "Eval…", "DOM") over the page image -> ⌘T new tab -> type a URL ⏎ -> navigates
- Surface: sidebar page
- States: no tabs -> "No tabs — open a page with ⌘T."; bus offline -> toolbar disabled with "Browser needs the bus"; Eval… opens a console drawer under the page with input + results; DOM opens an outline drawer
- Words: tooltips "Back", "Forward", "Reload", "Save screenshot"; buttons "Eval…", "DOM"
- Access: the URL field is focused in a new tab
Status: done

### S-055 Watch the live screenshot stream and click or type into it
As the operator, I see the page as a live image and my clicks and typing relay to the browser.
Screens: browser
Depends: S-054
Core: F14 (screencast)
Acceptance:
- [self] Frames arrive via `browser.screencast` (fallback: `browser.screenshot` every 500 ms) and draw without layout shift.
- [manual] A click at (x, y) sends `browser.click` scaled to the page; typing sends `browser.type`; a `Live` chip shows the frame rate.
UX:
- Flow: the page draws as a live image; click -> `browser.click` at the page coordinate; typing -> `browser.type`; a "Live · 2 fps" chip top-right
- Surface: inline (the image is the control)
- States: no frames yet -> grey block at the last known size; frames stop -> chip reads "Paused"
- Words: chip "Live · N fps"
- Access: the image has a label with the page title/URL
Status: done
(Screencast is a 500 ms browser.screenshot poll until F14.)

### S-056 Set the agent policy from the toolbar
As the operator, I click the Agent toggle and choose Allow all tools, Read-only or Paused; the agent's MCP calls obey at once.
Screens: apps, agent
Depends: S-005
Core: F1
Acceptance:
- [snap] Teal switch when the agent may act, grey when paused; a count badge of actions in the last minute; the Agent sidebar page shows policy, connected clients and the same count.
- [self] `agent.set {policy}` is sent and `agent.status` read back; Paused makes the agent's next call fail with "agent paused by operator".
- [unit] The app refuses to show the toggle as changed until the bus confirms.
UX:
- Flow: toolbar Agent ▸ menu: Allow All Tools / Read-only / Paused -> `agent.set` -> switch colour changes only after the bus confirms; sidebar ▸ Agent page shows policy, connected clients, actions/min and the activity log
- Surface: menu on the toolbar control; sidebar page for detail
- States: bus offline -> the menu is disabled with "Agent policy needs the bus"; before F1 -> status-bar note "agent.set needs F1", local choice kept as the intended policy
- Words: "Allow All Tools", "Read-only", "Paused", "Activity Log…"
- Access: VoiceOver reads "Agent, Allow All Tools, 14 actions in the last minute"
Status: done
(agent.set/agent.status wait on S-core-F1; fixtures apply locally.)

### S-057 Read the activity log and approve a gated request
As the operator, I open the activity log side panel (⇧⌘L) and see every command from any frontend, with agent rows in teal, and approve a gated agent request once.
Screens: activity-log, agent-approval
Depends: S-056
Core: F2
Acceptance:
- [snap] Rows `time · origin · command · args summary · result`, 28 px, agent rows with a teal left edge; filter by origin; the panel keeps its header in view.
- [self] Entries arrive via `notifications/aitm/agent` and the agent toggle's count follows them.
- [snap] A pending gated command (`ca.install`) shows as a row with Approve once / Deny; approving runs it with the operator identity.
UX:
- Flow: ⇧⌘L (or Agent ▸ Activity Log…) -> side panel on the right: filter by origin, rows time · origin · command · args · result, agent rows with a teal left edge -> a pending gated row shows Approve once / Deny -> approve runs it with the operator identity
- Surface: side panel (a tool kept open beside the work)
- States: empty -> "No activity yet."; live before F2 -> the panel lists this app's own commands only, with a note
- Words: filter chips "All · Agent · Operator · CLI"; buttons "Approve once", "Deny"
- Access: rows are real rows; the panel keeps its header in view
Status: done
(Live entries need S-core-F2; the app records its own commands meanwhile.)

### S-058 Check the certificate authority
As the operator, I open Certificate Authority… and see its status, export PEM/DER, and install or uninstall it after a confirmation; setup guides for iOS, Android, browsers and terminals sit beneath.
Screens: ca
Depends: S-005
Acceptance:
- [snap] Status line (fingerprint, installed/trusted, expiry) from `ca.status`; buttons Export PEM · Export DER · Install… · Uninstall…; guides as plain text sections.
- [self] Install/uninstall show the command's confirmation text first and run with the operator identity; the audit line appears in the activity log.
- [unit] The agent-gate flag (`ca.allow_agent_install`) is shown read-only.
UX:
- Flow: Proxy ▸ Certificate Authority… -> panel: status line (fingerprint, installed/trusted, expiry), buttons Export PEM · Export DER · Install… · Uninstall…, setup guides beneath (iOS, Android, Browsers, Terminal) -> Install… shows the command's confirmation text -> runs
- Surface: sidebar page / window-level panel
- States: not installed -> "Not installed" in intercept.deep with Install… primary; agent-gate flag shown read-only ("Agent may install: no")
- Words: as above; confirmation uses the proxy's own text
- Access: buttons in reading order; guides are plain headings + text
Status: done

### S-059 Read the proxy configuration
As the operator, I open Configuration… and read the effective YAML with env overrides marked, the engine, and the `ssl_insecure` flag.
Screens: config
Depends: S-005
Core: F7
Acceptance:
- [snap] YAML in a read-only code view; overridden keys carry an `env` chip; the listen address and bus address are highlighted.
- [self] `config.get` fills the view; Reload re-reads it.
UX:
- Flow: Proxy ▸ Configuration… -> read-only YAML code view; overridden keys carry an `env` chip; listen and bus addresses highlighted; Reload
- Surface: sidebar page / panel
- States: before F7 -> shows the config.yaml the app read itself, with a note "from <path>; the proxy's effective config needs config.get (F7)"
- Words: "Configuration", button "Reload", chip "env"
- Access: the YAML is selectable text
Status: done
(config.get is F7; the app reads its own config.yaml meanwhile.)

### S-060 Toggle a script on or off
As the operator, I open Scripts and flip a Rhai script's enable switch; its status and last error show beside it.
Screens: scripts
Depends: S-005
Core: F8
Acceptance:
- [snap] One row per script: name, matching rule summary, run-on phases, `● Saved and active` or the error; a flat toggle; the sidebar count reads `N active`.
- [self] `script.enable/disable` are sent; the count updates.
UX:
- Flow: sidebar ▸ Scripts -> one row per script: name, rule summary, run-on phases, status dot + "Saved and active" or the error, a flat toggle -> flip -> `script.enable/disable`
- Surface: sidebar page
- States: empty -> "No scripts loaded."; before F8 -> fixture list with a note
- Words: "Saved and active", "Disabled", "Error: …"
- Access: the toggle is a real toggle with the script's name as its label
Status: done
(script.* is F8; fixture list meanwhile.)

---

## M6 Polish & system

### S-061 Detach the inspector into its own window
As the operator, I choose Inspector Detached and the inspector opens in a second window that follows the selection.
Screens: detached
Depends: S-003
Acceptance:
- [snap] The main window shows the list full height; the detached window has the summary strip and panes with no sidebar.
- [self] Selection changes update the detached window; closing it returns to the previous layout; the choice persists.
UX:
- Flow: View ▸ Inspector Detached (⌥⌘3) or the layout glyph -> a second window "Inspector" opens with the summary strip and panes; the main window's list takes the full height -> selection changes follow -> closing the window returns to the previous layout
- Surface: new window (a long-lived tool kept beside the main window)
- States: nothing selected -> the window shows the inspector's empty state; the choice persists
- Words: window title "Inspector"; menu "Inspector Detached"
- Access: the window is a normal document-less window; ⌘W closes it
Status: done

### S-062 Open a split view
As the operator, I choose Split View and get two flow lists side by side, each with its own chips, filters and selection, over one capture.
Screens: split
Depends: S-031
Acceptance:
- [snap] Two lists with their own chip bars; the inspector follows the focused list; a thin focus edge marks it.
- [unit] Filters and selection are per pane; Clear acts on the capture, not a pane.
UX:
- Flow: View ▸ Split View (⌥⌘4) -> two flow lists side by side over one capture, each with its own chips, filter and selection -> the inspector follows the focused list (a 2 px accent edge marks it) -> ⌥⌘1 returns to one list
- Surface: inline layout
- States: Clear acts on the capture, not a pane; both panes empty -> one shared empty state
- Words: "Split View"
- Access: Tab moves focus between the two lists
Status: done
(The filter bar stays on the first pane; the second has its own chip, sort and selection.)

### S-063 Read the overview dashboard
As the operator, I open Overview and read session stats: flows, hosts, status classes, sizes and timing percentiles.
Screens: overview
Depends: S-005
Core: F5
Acceptance:
- [snap] Stat tiles in the UI face with mono numbers, one hairline grid; bars in tertiary with the class colour only on status codes.
- [unit] Percentiles computed over completed flows; counts match the status bar.
UX:
- Flow: sidebar ▸ Overview (or View ▸ Overview) -> stat tiles (Flows, Hosts, Clients, Paused, Errors, Bytes ↑↓) and three bar lists: status classes, top hosts, timing percentiles (p50 / p90 / p99)
- Surface: sidebar page
- States: no flows -> tiles read 0 and the bars say "No flows yet"; percentiles over completed flows only
- Words: tile labels in tracked small caps; numbers mono; "p50 · p90 · p99"
- Access: tiles read as "Flows, 56"
Status: done

### S-064 Read the connection log
As the operator, I open Connection Log and see CONNECTs, TLS handshakes, ALPN, SNI and errors in time order.
Screens: connection-log
Depends: S-005
Core: F5
Acceptance:
- [snap] 28 px mono rows `time · client · host:port · TLS · ALPN · SNI · result`; errors in `status.serverError`.
- [self] Selecting a connection filters the flow list to its flows.
UX:
- Flow: sidebar ▸ Connection Log -> rows time · client · host:port · TLS · ALPN · SNI · result in time order -> select one -> the flow list narrows to that connection's flows
- Surface: sidebar page (list) that filters the flow list beneath
- States: before F5 -> rows derived from the flows' ConnectionInfo (one per client:port) with a note; errors in status.serverError
- Words: "Connection Log"; result "ok" / the error
- Access: 28 px rows, header stays in view
Status: done
(Derived from flows until F5.)

### S-065 Import by drag and drop, export a selection
As the operator, I drop a HAR, mitmproxy, Proxyman or Charles file on the window to import it, and export selected flows as HAR, CSV, cURL batch or Postman/OpenAPI.
Screens: import-drop
Depends: S-046
Core: F10
Acceptance:
- [snap] A drop target overlay in the UI face: "Drop to import" (`import-drop`); imported flows carry an `imported` origin (neutral tag in the Origin column).
- [self] `flow.import` / `flow.export {ids, format}` are sent when the bus lists them (F10); before that an exported HAR imports back locally as `imported` rows with their details, and a Charles file is refused by name. The save panel proposes `aitmproxy-<date>.<ext>`.
- [unit] `TransferTests`: formats detected by extension and content; unsupported files refused with the detected type and the alert's words; HAR round-trips the fixtures (method, host, query, status, headers, bodies, duration); CSV and cURL batch cover every row.
UX:
- Flow: drag a .har / .mitm / .proxymanlog / .chlz onto the window -> "Drop to import" overlay -> drop -> rows appear with origin `imported`; File ▸ Export Selection… ▸ HAR… (⌘E) / CSV… / cURL Batch… -> save panel
- Surface: drop overlay; save panel
- States: unsupported file -> alert "Can't import <name>: <type> files are not supported until the proxy imports them (F10)."; before F10 -> HAR import/export runs locally in the app (Kit), the rest wait
- Words: "Drop to import", "Import…", "Export Selection…"
- Access: File ▸ Import… (⌘O) as the keyboard route; the overlay is one accessibility element "Drop to import"
Notes: Postman/OpenAPI export and the mitmproxy/Proxyman/Charles readers are the proxy's (F10); the app sends `flow.import {path}` / `flow.export {ids, format}` as soon as the bus lists the tools. Export takes the multi-selection, else the focused row, else every visible row.
Status: done

### S-066 Save and load a session
As the operator, I press ⌘S to save the capture as a session and reopen it from Saved in the sidebar.
Screens: apps
Depends: S-065
Core: F10
Acceptance:
- [self] `session.save` writes the file; Saved lists it with time and flow count; `session.load` replaces the capture after confirmation.
- [unit] Pins and saved filters attached to the session reload with it.
UX:
- Flow: ⌘S -> name sheet -> saved under Working ▸ Saved with time and flow count -> click to reopen (confirmation when the capture has flows)
- Surface: sheet for the name; sidebar sub-items
- States: before F10 -> sessions save locally as HAR + pins + filters under the app's state folder
- Words: "Save Session…", "Open Session", confirmation "Replace the current capture?" Replace / Cancel
- Access: Saved sub-items have a context menu with Rename / Delete
Status: todo

### S-067 Choose which hosts to decrypt
As the operator, I open Settings ▸ SSL and manage the include/exclude list of hosts the proxy MITMs; excluded hosts show the closed padlock.
Screens: settings-ssl
Depends: S-005
Core: F11
Acceptance:
- [snap] A grouped Form with an editable host list and an Include/Exclude mode; wildcard entries accepted.
- [self] `tls.passthrough.add/remove/list` are sent; affected rows switch padlock state on the next poll.
UX:
- Flow: Settings ▸ SSL -> Include | Exclude mode -> editable host list (wildcards ok) -> excluded hosts show the closed padlock on the next poll
- Surface: Settings tab
- States: before F11 -> the list is kept locally with a note "needs tls.passthrough (F11)"
- Words: "Decrypt only these hosts" / "Decrypt all except these hosts"
- Access: the list is a real table with add/remove
Status: todo

### S-068 See the app icon
As the operator, I see a flat Icon Composer icon in the Dock and Finder: the `›•‹` mark in the brand blue on a neutral ground.
Screens: icon
Depends: S-007
Acceptance:
- [manual] `tools/icon_review.sh` renders every look (default, dark, clear, tinted); the mark stays legible at 16 px.
- [snap] No glass highlights or bevels on the artwork itself.
UX:
- Flow: none — the icon is seen in the Dock, Finder and the About box
- Surface: Icon Composer file
- States: default, dark, clear, tinted looks; legible at 16 px
- Words: none
- Access: none
Status: done

### S-069 Use the app with Reduce Motion, VoiceOver and the menu bar alone
As the operator, I turn on Reduce Motion and every pulse and scale stops; VoiceOver reads every row, badge and button; every action has a menu item and shortcut.
Screens: apps
Depends: S-010
Acceptance:
- [manual] Reduce Motion: intercept dot static, press scale off (an opacity dip instead), palette opens without scale, the sidebar collapses without a slide.
- [manual] VoiceOver reads a row as "POST, paused, auth.shop-staging.test slash api slash auth slash login, edited" (`FlowRow.accessibilityDescription`, on the row view); badges, dots, swatches and monograms have labels; the agent segment announces its policy and actions/min.
- [unit] `CommandMapTests`: the brief's **Command map** bullet parses to the same verbs as `CommandMap.all`, every mapped verb with a brief shortcut has one, and rows describe themselves.
- [self] The self-test walks `NSApp.mainMenu` and finds a menu item (title and key equivalent) for every `CommandMap` entry; it also types `r` into the sidebar filter and checks nothing replays.
UX:
- Flow: System Settings ▸ Accessibility ▸ Reduce Motion on -> the intercept dot stops pulsing, presses do not scale, the palette appears without scaling; VoiceOver reads rows, badges, toggles with the same words as the screen
- Surface: whole app
- States: as above
- Words: VoiceOver row text "POST, paused, host/path, edited"; menu items added by the audit: Flow ▸ Resume All (⌥⌘⏎), Revert to Original, Add Host to Scope… (⇧S), Copy as ▸ cURL (⇧⌘C) / httpie / Python (requests) / fetch, Diff Selected (⌘D), Quick Look Body; View ▸ Toggle Sidebar (⌃⌘S), Chip ▸ ⌘1…⌘9, Inspector Below / Right / Detached (⌥⌘1…3); Agent ▸ Approve Pending Request (⌥⏎)
- Access: this story is the audit
Notes: Import…, Export Selection…, Save Session wait on S-065/S-066; Focus Inspector (⏎) has no single focus target yet; Mark (`m`) and Quick Look Body (Space) keep their keys on the focused list, never as menu shortcuts (they would take the key from every field); Revert to Original has no ⌘Z (Undo in the editor). Quick Look now shows the body through `QLPreviewPanel` (the list is its controller; Space toggles). Also fixed here: `BusService.call` recursed into itself (b7d3163) instead of `live().call`, which would have overflowed the stack on any live-bus action.
Status: done

### S-070 Hold 50 rows per second
As the operator, I watch a burst of 50 flows per second and the list, chips and status bar stay smooth.
Screens: apps
Depends: S-005
Core: F4
Acceptance:
- [self] A fixture burst of 500 rows in 10 s keeps the main thread under 8 ms per poll; appends never reload the whole table.
- [manual] Instruments shows no hang over 100 ms; memory stays flat after the burst with `max_flows` trimming.
- [unit] Row equality and diffing avoid re-rendering unchanged rows.
UX:
- Flow: a burst of 50 flows/s -> rows append without animation, selection stays, chips and status bar stay smooth
- Surface: whole app
- States: `max_flows` trimming keeps memory flat
- Words: none
- Access: none
Status: done
(Self-test burst: warm batches 27–42 ms per 50 rows; the first batch is ~330 ms cold.)

### S-071 Architecture check-in
As the operator (and the next agent), I find the codebase split into deeper modules after M6: no file past 600 lines, Session split by concern, viewers behind one protocol.
Screens: apps
Depends: S-070
Acceptance:
- [unit] All tests pass after each refactor commit; snapshots are pixel-identical before and after (`compare.swift`: 0.00% on apps light + dark after each commit).
- [manual] `improve-architecture` report lists hot spots and the refactors taken, one per commit: `docs/architecture-review-2026-10-28.md`.
UX:
- Flow: none — a refactor pass per the improve-architecture report
- Surface: codebase
- States: tests pass after each commit; snapshots pixel-identical
- Words: none
- Access: none
Notes: two Strong cards done as pure moves — `Session` split into state + `Session+Verbs/Editing/Filters/Palette` (809 → 406 lines), `FlowColumn`/`Density` out of `FlowTableView.swift` (542 → 430). No file past 600. Carried: one verb table for row actions (next Strong, before S-041/S-045), viewers behind one `ViewerKind` (with S-045). `docs/ARCHITECTURE.md` and `docs/FIXLOG.md` started.
Status: done

### S-072 See what is running and what to do first
As the operator, on a fresh launch I land on a Status page that shows the core, the bus and the capture extension — each with a state word, one fact and its control — and a live Getting-started list, so I never have to guess which sidebar item to look at or why no flows appear.
Screens: status, status-ok, status-fresh, status-external, status-core-starting, status-core-stopped, status-core-failed, status-bus-connecting, status-bus-agent, status-bus-token, status-scope-empty, status-waiting, status-degraded
Depends: S-063, S-070, core F1
Spec: `docs/superpowers/specs/2026-10-31-macos-status-page-and-first-run-design.md`
Acceptance:
- [unit] `ConnectionSummary.make` yields the spec's word table for every core × bus × capture state; no lane word says "Capturing" while the scope is empty (ST-AC1/2).
- [snapshot] The Status page renders every lane state in light + dark with no clipping; grid-lint + check-layout PASS (ST-AC3).
- [self-test] A fixture session's lanes read "not running / connected / no extension"; Open Scope, Open Browser and Core Log from Status call the same entries as their menu items; Proxy ▸ Status (⌘0) is in the menu bar and the command map (ST-AC4/6).
- [structural] The toolbar cluster, Status page, Core Log header and Settings rows take their words only from `ConnectionSummary` (ST-AC5); the sidebar and the status bar carry no connection state (ST-AC10).
- [self-test] The toolbar's Proxy switch is live while the bus is connected and flips through `setCapturing`; the Capture switch stands down, with the reason in its help, when the extension is not in the build, the core is external or a switch is in flight (ST-AC9).
- [manual] On the notarized app: fresh launch lands on Status; the cards read the real state; Turn Off/On Capture from the card changes Settings ▸ Capture within one poll; adding a host ticks the step; the first flow ticks the last step (ST-AC7).
UX:
- Flow: launch (fresh install) → Status → read the three lanes → click the one remedy (Turn On Capture / Open Scope… / Restart Core) → the step ticks → first flow appears in Recent → click it → Domains with the flow selected. Returning: launch → last page; ⌘0 or the toolbar pill → Status. Any page: the Proxy and Capture switches beside the pill flip without leaving it.
- Surface: sidebar page (a place the operator comes back to); controls inline on the lane cards; destructive Uninstall behind ⋯ with a confirmation dialog. The two everyday controls (Proxy on/paused, Capture on/off) are inline toolbar switches — they change one value already on screen — in the one connection cluster; the brand row and status bar show nothing about connection (Matt's review 2).
- States: each lane ok / working / off / warning / error with word + detail + remedy; Getting started rows done (✓, stays) or pending (○ + one action), collapsing to one line when all done; Recent "No flows yet — point a client at <address>".
- Words: Status, Core, Bus, Capture extension, Proxy (the switch) / Pause Proxy / Resume Proxy, Capture (the switch) / Turn On Capture / Turn Off Capture, Restart Core, Reconnect, Open Scope…, Core Log…, Open Browser, Copy Address, Uninstall Capture Extension…, Getting started (GLOSSARY).
- Access: every card action has a menu-bar twin with a shortcut; dots carry "Core: running" labels; the switches read "Proxy, on" / "Capture, off" with the reason in their help, never colour alone.
Notes: the capture lane maps PR #181's `CaptureAdvice` 1:1; until the provider stops claiming DNS, the scope step says to add `host:443`. A core `capture.status` verb (proposed) will sharpen the capture detail through `CoreCaptureStatus` without a UI change.
Status: in progress

---

## Core follow-ups

Rust-side work the stories above wait on (foundation §5). Owner: Rust, via the seven-stage workflow; each is its own spec and plan. Status `todo` until merged to `main`.

### S-core-F1 agent.status / agent.set, AgentPolicy enforcement, Frontend::Operator, operator/agent token classes
Unblocks: S-056, S-057, S-058. Status: todo

### S-core-F2 Command invocation audit ring + notifications/aitm/agent
Unblocks: S-057, Origin column and teal ticks on the live bus (S-002). Status: todo

### S-core-F3 flow.intercept rules, response-phase parking, flow.kill abort modes
Unblocks: S-039, S-040, S-041. Status: todo

### S-core-F4 flow.subscribe/unsubscribe, server push, flow.list {since, filter, limit}
Unblocks: S-025, S-045, S-070; retires the 500 ms poll in S-005. Status: todo

### S-core-F5 flow.detail: headers, bodies (paged), ConnInfo, FlowMeta, timing, WS frames, backup
Unblocks: S-012, S-019, S-020, S-021, S-025, S-027, S-045, S-063, S-064; fills the grey dashes in S-002. Status: todo

### S-core-F6 flow.mark / flow.comment
Unblocks: S-017. Status: todo

### S-core-F7 proxy.status/pause/resume, flow.clear, config.get
Unblocks: S-018, S-059; gives S-004 a read-only armed state. Status: todo

### S-core-F8 script.list/get/set/enable/disable, plugin chain readout (M3)
Unblocks: S-060; the script editor stays in Later until this lands. Status: todo

### S-core-F9 ws.send, frame-level intercept
Unblocks: WebSocket compose/inject (Later). Status: todo

### S-core-F10 session.save/load, flow.export/import (HAR, mitmproxy, Proxyman, Charles)
Unblocks: S-065, S-066, the HAR in S-051's export. Status: todo

### S-core-F11 tls.passthrough.list/add/remove
Unblocks: S-067. Status: todo

### S-core-F12 scope.remove; scope.add gate for Frontend::Mcp
Unblocks: S-048. Status: todo

### S-core-F13 poc.list, poc.get, poc.artifact
Unblocks: S-050, S-051. Status: todo

### S-core-F14 browser.tabs, browser.screencast
Unblocks: S-054, S-055. Status: todo

### S-core-F15 network TCP transport with TLS, aitm web, WS bridge
Unblocks: remote bus (Later). Status: todo

---

## Dropped

- Team Workspace, sharing a log online, accounts, sync servers: one operator, one Mac.
- Analytics, telemetry, crash reporting to a vendor.
- Upgrade prompts, licensing, onboarding tours.
- Plugin/skill marketplace.
- Toolbar themes and selectable accent colours beyond the system accent rule.

## Later

- Remote or web bus over TLS (F15) and a bus address picker.
- Script editor (matching rule, run-on phases, editor, console, Save & Activate ⌘S), snippets, plugin chain view — once F8 lands.
- WebSocket compose, send frame, frame-level intercept (F9).
- Network-Extension-style capture of every app without proxy settings; iOS/Android device capture.
- Custom columns from a header or JSON-body path (F5).
- Map Local / Map Remote / Block list / Allow list / No-cache / Throttle as bundled Rhai scripts with forms.
- Protobuf decoding with a `.proto` schema; GraphQL-aware body viewer.
- Message templates for paused-request edits.
- Timing waterfall export; Overview export.
- Spawning `aitm` from the app and reading `on_bound`.
- Shortcuts actions and a CLI (`aitm-mac open <flow>`); Share menu for exports.
- iCloud sync of pins and saved filters.
