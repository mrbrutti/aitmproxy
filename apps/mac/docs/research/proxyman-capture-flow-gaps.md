# Proxyman's capture flow vs ours — gap analysis and story drafts

Date: 2026-11-01. Sources: the demo `capture-http-https-demo-2026.mp4` (12 frames at 0.5 fps), proxyman.com (home, `/network-extension`, `/docs/basic-features/ssl-proxying`), Matt's Proxyman screenshots relayed by the macOS review session, and our own app observed LIVE today (dev bundle `Aitmproxy-dev-il`, embedded core built from main 9dba3d9f, real curl traffic). No fixture data anywhere in this note.

Reference rule (Matt): copy the **flow and the information density**, keep our look (flat monochrome icons, editorial restraint, tokens). Naming decided today: the system-wide capture switch is **All Apps**, the listener switch is **Proxy**.

## 1. Proxyman's capture flow, step by step

1. **Launch → listening.** The toolbar pill reads `● Proxyman | Listening on 192.168.1.89:9090` (green dot, LAN address, port). Toolbar: pause, compose, clear on the left; account, ⌘ palette, three layout glyphs on the right. Nothing else.
2. **Traffic appears per app.** Sidebar, top to bottom: `Favorites ▸ Pinned, Saved (1)`; `All ▸ Apps (2)` with one row per process — real app icon + display name (`Proxyman`, `iStat Menus Menubar`), each expandable to the domains that app talked to; `Domains (5)` flat, one row per host with a disclosure when it has sub-paths. Counts are live. Filter field at the bottom with `⌘⇧F`.
3. **The list is dense and complete.** Columns: dot, `#`, URL, Client (icon + name), Method, Status, Time (ms), Duration, Request, Response, SSL (padlock), Edited (✓), Tools (`Scripting` + icon when a tool touched the flow), Comment. Chip bar: `All | HTTP HTTPS WebSocket | JSON Form XML JS CSS GraphQL Document Media Other | 1xx 2xx 3xx 4xx 5xx | <saved filter chip> ‹ ⋯` — status-class chips and saved-filter chips sit in the same bar, overflow scrolls behind `‹`.
4. **Undecrypted HTTPS is visible, not hidden.** A host without SSL proxying shows as a row with Method `CONNECT`, Status `200` once the tunnel closed (grey `999` / amber `Active` while open or failed), Time to the millisecond, Duration only once closed, Request/Response `—`, no padlock. Selecting it shows a lock in the Response pane: *“HTTPS Response — This HTTPS response is encrypted. Enable SSL Proxying to see the content.”* with two buttons: **Enable only this domain (⌥⏎)** (primary) and **Enable all domains from "<app>"**. The same verbs are in the row's and the sidebar item's context menus (`Enable SSL Proxying` / `Disable SSL Proxying`); `⌘⌥P` opens the SSL Proxying List (Include / Exclude, by app, by domain, wildcards `*`, `*.domain.com`, `v?.domain.com`).
5. **Select → inspect.** Strip: method pill, `200 OK` pill, URL. Request tabs `Header Query Body Raw Summary +`, Response tabs `Header Body Raw Treeview +`; `+` adds custom previewer tabs (JSON, HTML webview, Protobuf, MessagePack, SSE, …) chosen in a sheet; the JSON tab has a JSONPath filter bar with Save.
6. **Act.** Breakpoint / Map Local / Repeat / Compose from the row menu or the Tools column; a `Breakpoint` badge sits at the far right of the status bar while armed. Status bar: `Clear`, `Filter`, `Auto Select` buttons; centre `1/8 rows selected`; right `• 305 MB ↑ 1 KB/s ↓ 1 KB/s`; a `Proxy Overridden` badge when another tool took the system proxy.
7. **System-wide capture.** Settings ▸ Network Extension ▸ `Enable Network Extension` → `Install and Enable` → macOS approval → restart apps that were already running. Apps that ignore the system proxy (curl without `--proxy`) then appear under Apps with their icon.

## 2. What we do today (observed live, 2026-11-01)

| Area | Proxyman | aitmproxy (live) | Gap |
|---|---|---|---|
| Listening pill | `Proxyman \| Listening on 192.168.1.89:9090` | `● aitmproxy · 127.0.0.1:64822 · intercept armed ● no extension` (pill shows the loopback address; no "Listening on" verb) | wording; LAN address only matters once devices connect |
| Sidebar groups | Favorites (Pinned, Saved) / All (Apps n, Domains n) | TRAFFIC: Flows n, Apps n, Domains n, Pinned n, Connection Log, Overview; TESTING: Scope, Scan, Findings, Browser; AUTOMATION: Scripts, Agent | our three groups are richer (Testing/Automation are ours alone) but Apps and Domains do not expand to sub-rows until flows carry a client; Saved does not exist (S-066, core F10 is now on the bus) |
| Apps rows | real app icon + display name, expandable to that app's domains | `Flows carry no source app yet, so this page cannot group them.` banner; Client column `—` | owned by the attribution session (PR B); nothing for us until it lands |
| Domains rows | flat hosts with counts, disclosure to paths | hosts with counts under Domains (works); no disclosure | small story: per-host disclosure to paths, counts live |
| Chip bar | protocol \| content type \| status class \| saved filters, `‹` overflow | `All \| HTTP HTTPS WebSocket \| TCP UDP L4 \| h1 h2 \| JSON … Other` + `Filters ▾` | no status-class chips, saved filters live behind Filters, no overflow affordance |
| Columns | + Tools, Comment | #, URL, Client, Method, Status, Time, Duration, Request, Response, SSL, Edited, Origin (+ Mark swatch) | Comment exists only as a column? (we have comment on the row, S-017) — check; Tools column: we show agent/edited, not "Scripting" |
| Undecrypted HTTPS | CONNECT row + inline "Enable SSL Proxying" | **we decrypt every host** the client trusts us for, scope or not: `curl -k https://example.com` through the proxy with an EMPTY scope → row `GET https://example.com/ 200` with a padlock, body readable. A client that refuses our CA (`curl` without `-k`, exit 60) leaves **no row at all**. The scope banner reads `No scope set — every host is read-only until you add one`; scope gates *actions*, not decryption | two gaps: (a) a failed TLS handshake / passthrough tunnel is invisible (Proxyman shows `CONNECT` + failure); (b) our Scope is "where the operator may act", not "what gets decrypted" — the inline *Add <host> to Scope (⌥⏎)* affordance is the equivalent of their *Enable only this domain*, and it belongs in the inspector where the operator is looking |
| Status bar | Clear / Filter / Auto Select · `1/8 rows selected` · `305 MB ↑ ↓` · Breakpoint badge | Clear / Filter / Auto-select · `0 / 3 rows` · `↑ 0 B/s ↓ 82.8 KB/s` (memory figure missing live; present on fixtures only — F-gap) · no armed badge (the pill carries `intercept armed`) | memory figure is fixture-only today; the armed word is in the pill (our one connection home) — fine |
| Inspector tabs | `+` custom previewer tabs, JSONPath bar | fixed tab sets (Request: Headers Cookies Query Body Raw Summary Timing Connection; Response: Headers Set-Cookie Body Raw JSON Diff) | later; our Diff/Timing/Connection are extras they lack |

## 3. Story drafts — per-host decryption, aligned to the shipped core (#228, 448e75e; spec `docs/superpowers/specs/2026-10-31-per-host-decryption-design.md` D5/D7/D8/D9)

Matt, verbatim: "Switch to per-host decryption like Proxyman: decrypt only hosts in scope, passthrough the rest, with inline Add to Scope." Scope now means **the hosts whose traffic is decrypted and may be acted on; everything else passes through as a tunnel**. Every acceptance line is `[live]`: a dev bundle with a v0.5.9+ core, real curl / Safari, screenshots in `docs/evidence/<story>/`. Land in STORIES.md/GLOSSARY.md once claims open (after the fake-data removal mac PR).

### Wire contract the mac app consumes (D7, all keys always present on `flow.table` rows, `flow.get`, pushes; `flow.detail` carries them as `meta.tunnel {mode, reason, bytes_up, bytes_down}` and `meta.passive`)
| key | values |
|---|---|
| `tunnel` | `decrypted` \| `passthrough` \| `failed` \| `null` (not a tunnel row) |
| `tunnel_reason` | passthrough: `out_of_scope` \| `pinned`; failed: `client_rejected_certificate` \| `client_closed` \| `client_tls_error` \| `upstream_unreachable` \| `upstream_tls_failed` \| `protocol_error`; else `null` |
| `bytes_up` / `bytes_down` | ints for a closed passthrough tunnel; else `null` |
| `passive` | bool: plain HTTP to an out-of-scope host, observed only |
| `proxy.status.decrypt` | `{scope_hosts, decrypting, advice}`; `advice` is exactly `Nothing is decrypted until a host is in Scope.` while `scope_hosts == 0`, else `null` — printed verbatim, never composed |
A tunnel row: `method == CONNECT`, `scheme https`, `authority host:port`, `path ""`, `status 200` once established (`null` for failed), `duration_ms null` while open, `intercept observed`. Pushes: `created` then `response`. A tunnel row is terminal once `duration` is set.

### Shared vocabulary (mac-attribution / system-proxy-auto, 2026-10-31; ship verbatim)
- Scope state: the core's `advice` sentence `Nothing is decrypted until a host is in Scope.` — the banner's remedy (`add one` / `Add Host…`) is the action, not part of the sentence; Status step title `Add a host to Scope` (action `Open Scope…`); done form `Scope: N hosts decrypted` (N = `scope_hosts`).
- System proxy: `system proxy off — set 127.0.0.1:8080 as the system proxy, or point a client at it`.
- CA: `HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then`.

### S-080 Scope decides what is decrypted (counters + words; the Kit decode of the five D7 fields is mac-attribution's traffic-route amendment, which lands first — S-080 consumes the agreed Kit names (confirmed by mac-attribution 2026-11-01, matching the core's TunnelMode/TunnelReason) — `TunnelMode` {decrypted, passthrough, failed}, `TunnelReason` {outOfScope, pinned, clientRejectedCertificate, clientClosed, clientTLSError, upstreamUnreachable, upstreamTLSFailed, protocolError} — as `FlowRow.tunnel`, `.tunnelReason`, `.tunnelBytesUp`, `.tunnelBytesDown`, `.passive`, derived `.isTunnel`, and `FlowDetail.tunnel: TunnelInfo? {mode, reason, bytesUp, bytesDown}` + `.passive` (all five in `FlowRow ==`; `inScope` stays the scope-list rule — S-080 dims/excludes passive and out-of-scope rows itself; `tls` derived: passthrough → .tunnelled, failed → .pinnedOrFailed, decrypted → .decrypted) and does not touch FlowSummary/FlowDetail/FlowDetail+Wire/Flow.swift — attribution's claim; its PR lands after the fixture-removal SHA and CA-trust PR D)
As the operator, only hosts in Scope are decrypted; every other HTTPS connection is a tunnel row I can see but not read, and the app's numbers and words say so.
Screens: apps
Depends: S-047; core #228
Acceptance:
- [unit] (mac-attribution's unit, consumed here) `FlowRow` carries `tunnel`, `tunnelReason`, `tunnelBytesUp`, `tunnelBytesDown`, `passive`, all in `FlowRow ==`; `tls` derives from `tunnel`; `passive == true` renders as out of scope (dimmed, actions disabled) as S-049 does today.
- [unit] Request counters exclude rows with `tunnel != nil`: sidebar Flows count, status bar `N rows`, Overview totals, the `3 selected · …` summary; Domains/Apps count distinct hosts (a decrypted tunnel row and its inner rows share `authority`, never double-counted).
- [live] Empty Scope, `curl -k https://example.com/` through the dev bundle's core: the client receives the real server chain, the list shows one `CONNECT example.com:443` row (`passthrough`, closed padlock, bytes up/down and duration once closed), no `GET`, nothing readable; the status bar says `0 rows` of requests while the Flows sidebar count still lists the tunnel under Domains.
- [live] Add `example.com` to Scope; the next `curl -k https://example.com/` is a decrypted `CONNECT` row (open padlock) plus its inner `GET … 200` with a body; the earlier passthrough row is unchanged.
- [live] `proxy.status.decrypt.advice` is shown verbatim where the app speaks about decryption (the route banner — mac-attribution's — the Status page's scope step, the empty state of the flow list), and `decrypting == false` reads "nothing is decrypted"; the sentence disappears when `scope_hosts > 0`.
- [live] Safari with the system proxy set and an empty Scope: tunnels only, one per host:port, Domains lists their hosts; with the CA untrusted the rows are `failed · client_rejected_certificate` (see S-074).
- GLOSSARY: `Scope` → "the hosts whose traffic is decrypted and may be acted on; everything else passes through as a tunnel"; `In scope / Out of scope` → "decrypted / passed through (a tunnel) or passive (plain HTTP, observed only)". S-067 (Settings ▸ SSL include/exclude list) is dropped: Scope is that list. S-049's tooltip becomes "Not decrypted — add `host` to Scope".
Files: Session counters (Session.swift `clients`/`domains` region, StatusBar, Overview, selection summary), GLOSSARY, STORIES. Not Kit decoders (attribution).

### S-074 Tunnels and refused handshakes are rows
As the operator, I see every CONNECT a client opened through the proxy — decrypted, passed through, or failed — so a pinned app or a client that rejects our CA is visible instead of silent.
Screens: apps
Depends: S-080
Acceptance:
- [live] A passthrough tunnel row reads: dot amber while open (`duration_ms == null`) and green when closed, `#`, URL `host:443` (no path), Client, Method `CONNECT`, Status `tunnel` while open and `200` once closed, Time to the ms, Duration once closed, Request/Response = `bytes_up`/`bytes_down` once closed (`—` before), SSL closed padlock, dimmed like an out-of-scope row; the inspector's strip pill reads `Tunnel · passthrough`, the panes are replaced by the S-073 panel.
- [live] A decrypted tunnel row: open padlock, Status `200`, Request/Response `—`, not dimmed; its inner requests are their own rows as today; the strip pill reads `Tunnel · decrypted`.
- [live] A failed tunnel (`curl https://host/` without `-k` while the host IS in Scope → exit 60): Status `failed` in the error colour, SSL warning glyph, strip pill `Tunnel · failed`, and the inspector says the reason in words: `client_rejected_certificate` → `TLS handshake failed — the client did not accept the aitmproxy CA. HTTPS is not captured until the CA is trusted — browsers using QUIC load directly until then` + button `Certificate Authority…` (Proxy ▸ Certificate Authority…); `client_closed` → `The client closed the connection before the tunnel was established`; `client_tls_error` → `The client's TLS handshake failed`; `upstream_unreachable` → `<host> could not be reached`; `upstream_tls_failed` → `The TLS handshake with <host> failed`; `protocol_error` → `Not a TLS connection — aitmproxy tunnels TLS only`.
- [live] `~state tunnel` / `~state failed` filter the list to those rows; the `HTTPS` chip includes tunnels; VoiceOver reads `CONNECT host:443, tunnel, passed through, 12 KB up, 48 KB down`.
Files: FlowTable/FlowCellView + FlowColumns (status words, bytes), Kit FlowRow+Accessibility, Kit FilterMatching (`~state`), Inspector/InspectorView (strip pill, tunnel inspector), docs.

### S-073 Add a host to Scope from the inspector (⌥⏎)
As the operator, when I select a passthrough tunnel or a passive plain-HTTP row, the inspector tells me it is not decrypted where I am looking and offers to add its host — or every host this client talked to — to Scope.
Screens: apps
Depends: S-080, S-074
Acceptance:
- [live] Offered exactly when `tunnel == passthrough && tunnel_reason == out_of_scope`, or `passive == true`; never when `tunnel_reason == pinned` (that panel reads `<host> is pinned — TLS passthrough keeps it undecrypted` with no Add button; the action is `tls.passthrough.remove`, agent-gated, not offered here). The host is the host part of `authority` (port stripped, IPv6 brackets kept).
- [live] On a passthrough row the panes are replaced by a flat lock glyph and `HTTPS is not decrypted — add <host> to Scope to see the content`, with **Add <host> to Scope (⌥⏎)** (primary) and, when the flow carries a client (attribution, PR #195; All Apps on for Mac-app clients), **Add every host <client> talks to**; hidden when there is no client. On a passive row the same panel sits above the readable request pane with `Plain HTTP to <host>, outside Scope — observed only`.
- [live] Pressing ⌥⏎ (or the button) sends `scope.add {host}` on the operator connection (the same entry as Scope… and Add Host to Scope… ⇧S); on success the panel reads `Added — new connections to <host> are decrypted; this tunnel stays as it is`, the sidebar Scope count moves within a poll, the row does not change, and the next curl to that host appears as a decrypted `CONNECT` + inner `GET`.
- [live] As agent (role, not operator) the buttons are hidden and the text stays.
- [live] Flow ▸ Add Host to Scope gains the ⌥⏎ equivalent while a tunnel/passive row is focused; the command map, palette and VoiceOver (panel text, then the buttons) carry it.
Files: Inspector/InspectorView (TunnelInspector), Session+Verbs (`addScope` exists; add-all-for-client), Kit VerbTable (`.addToScope`), CommandMap, docs.

### S-075 Domains with paths, counts live — unchanged.
### S-076 Status-class and saved-filter chips with overflow — unchanged.
### S-077 Listening pill says what it listens on — after mac-attribution's traffic-route PR.
### S-078 Raw editor keeps up with typing — CLOSED 2026-11-01, not a bug
Reproduced on a dev bundle built from main 621cbcc0 (v0.5.10) with a real core: a parked request (header line, 30 characters) and a parked response (status line rewritten after 13 fast deletes, then a new header), both typed by System Events `keystroke` at full speed with no per-key delay — the text arrived verbatim ("HTTP/1.1 203 Non-Authoritative", "X-Aitm-Edited: 1", "2 edits pending"), and a trace on both reload paths (`CodeTextView.updateNSView` → `load`, and the draft `onChange` re-render) fired zero times while typing. The "scramble" seen on 2026-10-31 was the harness: the click that was meant to focus the editor landed elsewhere, so the keystrokes went to another responder. Evidence: notes folder `s078-typing-not-a-bug/`. No code change; the story is withdrawn.
## 4. Evidence
- `/tmp/claude/proxyman/frames/f001–f012.png` (Proxyman demo frames, not committed).
- Ours, live: `/tmp/claude/mac-il/gui3/1-connect-empty-scope.png` (three decrypted rows with empty scope), `/tmp/claude/mac-il/gui3/2-row-selected.png` (no row for the refused handshake; list sorted by the header click). To be moved under `docs/evidence/` with the stories that use them.
