# Operator capability catalog & parity/gap analysis

What an operator must be able to do with aitmproxy, measured against **Proxyman**
and mitmproxy, mapped to our core command surface, the mac app's coverage, and
our L4 roadmap. The guiding contract: **an operator must be able to intercept,
review and edit any request / response / WebSocket frame (and eventually any L4
stream) that travels through the core.**

Scope: normal engineering / debugging capabilities (mitmproxy / Proxyman class).
Security-testing extras (PoC, scope-as-authorization, agent policy) are ours on
top. Sources: core command survey + Proxyman docs survey, both 2026-10-28, after
the operator-commands merge (PR #6, `tools/list` = 34).

## Status legend

- **✅ live** — works today against a running `aitm` over the bus (verified by the live self-test).
- **🟡 app-ready, core-blocked** — the mac UI is built; waits on a named core item.
- **🧩 planned** — story exists, not built.
- **⛔ not in v1** — deliberately deferred (`docs/BRIEF.md`).
- **— none** — no support anywhere yet.

## Headline gaps found by live testing (2026-10-28)

1. **Review + edit live traffic — FIXED.** `flow.get` is summary-only; the inspector
   now fetches **`flow.detail`** (F5, merged) on selection, so request/response
   headers, cookies and bodies render and a paused request is editable. Verified
   end to end (`tools/selftest-live.sh`).
2. **Operator vs agent identity (F1) — in progress.** The MCP server treated every
   bus client as `Frontend::Mcp`, so the operator app was an *agent*; the F12 gate
   then refused `scope.add`. The `Frontend::Operator` type has landed; per-connection
   wiring (server assigning Operator vs Agent by token class) is a dependent M4 task.
   Interim: `scope.allow_agent_widen: true` in the aitm config (verified).
3. **`flow.kill` forwards like resume — FIXED (PR #7).** A killed parked flow is now
   dropped and the client sees a closed connection. Verified with
   `APP_LIVE_STRICT=1`: "flow.kill denies the client a response (curl exit 52,
   row killed)".

## Verification & CUA automation coverage boundary

The operator workflow is verified two ways, both repeatable:
- **Agent-driven (MCP bus)** — `tools/selftest-live.sh` (21 checks): intercept →
  `flow.detail` review → edit a paused request → resume, plus mark/comment,
  pause/clear, kill (strict), activity log.
- **Human UI (computer-use)** — `tools/cua-ne-drive.sh` on the dev bundle (the fixture-session click-through `cua-clickthrough.sh` was removed 2026-10-31), with `tools/cgclick.swift`,
  two layers, both real input events:
  - **Pixel path (no Accessibility tree):** normalize the window to a known origin,
    then **CGEvent-click computed row pixels**; selection is verified by
    screenshotting the inspector region and confirming it changed (`screencapture`
    + `md5`, across rows 3/8/1). This clicks pixels, so it has no SwiftUI-AX
    limitation and selects any rendered element. Proof shots: `/tmp/cua-row*.png`.
  - **Menu path:** real Accessibility menu-bar clicks (Resume, Build PoC opens a sheet).
- **Deterministic human-input** — the in-app self-test's menu audit (every action
  has a menu item + shortcut) and key-event checks.

**CUA automation coverage boundary (now closed for selection):** The **coordinate
path** (screenshot → compute pixel → CGEvent click) does not touch the AX tree, so
it reliably selects any rendered row — the pixel gate verifies this with a
`screencapture`+`md5` inspector-region diff across three distinct rows (green every
run). That is the deterministic coverage.

Stable `.accessibilityIdentifier`s are set on the key views — flow rows
(`flow-row-<i>-seq<n>`), the inspector URL (`inspector-url`), the Raw editor
(`raw-request-editor`), the edit-status (`edit-status`), and the Resume/Edit
buttons — for VoiceOver and for XCUITest. Note: **AppleScript / System Events does
not surface SwiftUI's `AXIdentifier`** (verified — reads return NOTFOUND), and the
NSTableView AX descent is timing-sensitive, so the scripted *read-back* uses the
screenshot diff rather than by-identifier AX reads. A fully by-identifier
deterministic UI test would be an **XCUITest** target (which does read these
identifiers); the end-to-end "an edit reaches the client" assertion already lives
in the agent `tools/selftest-live.sh` (edit → `flow.mutate` → `flow.resume`).

## 1. Our core command surface (post-merge, 34 tools)

Live and verified unless noted. Summary from the core survey + the merged `tools/list`.

| Area | Commands | Notes |
|---|---|---|
| flow / capture | `flow.list`, `flow.get`, **`flow.detail {id, body: none\|inline\|range, offset?, length?}`** | detail returns request/response (headers `[[k,v]]`, base64 bodies), `client_conn`/`server_conn`, `meta`, `intercept`, `edited`; WS → `handshake`+`messages` |
| flow / intercept | `flow.intercept {enabled?}`, `flow.resume {id}`, `flow.kill {id}` | global arm, request-phase only (rules + response-phase + kill modes = F3); kill currently forwards (gap) |
| flow / mutate | `flow.mutate {id, edits}`, `request.send {…}`, `flow.replay {id}` | edit a parked request; craft/replay |
| flow / meta | `flow.mark {id, marks}`, `flow.comment {id, text}`, `flow.clear` | F6 + clear, live |
| scope | `scope.add {host}`, `scope.list` | `scope.add` gated to operator; `allow_agent_widen` opt-in (F1/F12) |
| proxy / config | `proxy.status`, `proxy.pause`, `proxy.resume`, `config.get` | F7, live |
| browser | `browser.navigate/click/type/screenshot/eval/get_dom` | embedded obscura (SSRF+scope guarded) |
| poc | `poc.build`, `poc.run`, `poc.list`, `poc.get`, `findings.list` | F13, live |
| ca | `ca.status/export/install/uninstall` | agent-gated install |
| scripts | (rhai plugin chain; `script.*` command surface = F8) | M3 rhai engine merged; operator script CRUD still F8 |

Not yet on the bus: `flow.subscribe` (F4 live push), `ws.send` (F9),
`session.save/load` + `flow.export/import` (F10), `tls.passthrough.*` (F11),
`scope.remove` (F12), `agent.status/set` (F1).

## 2. Protocol coverage

| Protocol | Status | Note |
|---|---|---|
| HTTP/1.1 | ✅ full MITM | CONNECT tunnel, TLS MITM with on-the-fly leaf cert, chunked, 100-continue, 101 upgrade |
| WebSocket | ✅ captured + viewed | Text/Binary/Close/Ping/Pong/Continuation, reassembly, masking; frames in `flow.detail` `messages`, shown in the inspector (S-045). Inject/edit = F9 |
| HTTP/2 | — stub | `H2` enum exists but never produced; ALPN pinned to http/1.1. (Proxyman shipped h2 in 26.0.0 — a real gap) |
| gRPC / protobuf | — none in core | client-side body viewers only |
| TCP / L4 raw | — none | no passthrough/tunnel-only; L4 is M5 |

## 3. mac app coverage (post-merge)

| Capability | Status | Note |
|---|---|---|
| Flow list: columns, sort, density, chips, stacked filters, saved filters, ⌘K palette, search | ✅ live | — |
| **Inspector: Headers, Query, Cookies, Body (JSON/tree/form/XML/image/hex/protobuf/msgpack/SSE/raw), Set-Cookie, Timing, Connection, Diff** | ✅ **live now** | `flow.detail` fetched on selection (`Session+Detail.swift`, `FlowDetail+Wire.swift`) |
| Compose request + history; Edit & Replay; Replay | ✅ live | — |
| Arm/disarm intercept; Resume/Resume All; Kill | ✅ live | kill modes + rules = F3; kill-forwards gap |
| **Edit a paused request (Raw + headers) → Apply & Resume** | ✅ **live now** | detail provides the content; `flow.mutate`+`flow.resume` |
| Intercept & edit a **response** | 🧩 planned (S-041) | F3 response-phase |
| **WebSocket frame list + viewers (read)** | ✅ **live now** | S-045: frame stream (dir/opcode/length/time/injected) over JSON/text/hex viewers + Sent/Received/Both filter (`WebSocketInspector.swift`); fed by `flow.detail` `messages` (`WSDetail`) |
| WebSocket frame inject/edit | 🧩 planned | inject/edit = F9 |
| Mark (colors) + Comment | ✅ live | F6 |
| Scope page/sheet/banner | ✅ live (add/list) | needs `allow_agent_widen` until F1; remove = F12 |
| Findings / Build / Run PoC; remote findings | ✅ live | F13 |
| Embedded Browser | ✅ live | screencast/tabs = F14 |
| Agent policy + Activity log | 🟡 app-ready | F1 + F2 |
| Scripts page | 🟡 app-ready | F8 command surface |
| Certificate Authority | ✅ live | — |
| Configuration | ✅ live | `config.get` (F7) |
| Overview, Connection Log | ✅ (derived) | richer = F4 |
| Pause/Resume proxy (the toolbar's Proxy switch); Clear session | ✅ live | F7 |
| Import/Export (HAR, CSV, cURL) + drop | ✅ app-side | full formats/sessions = F10 |

## 4. Proxyman parity matrix

Proxyman's documented feature set (left) against our status. `~` = partial.

### Capture & proxying
| Proxyman | Ours |
|---|---|
| System/per-app proxy, helper, bypass list | ✅ loopback proxy + scope (deny-by-default); no system-proxy auto-set/helper (⛔ v1) |
| HTTP/1.1, HTTP/2, WebSocket, SSE, SOCKS5 | HTTP/1.1 ✅, WebSocket ✅ (SSE viewer ✅); HTTP/2 — (stub); SOCKS5 — |
| System-wide Network Extension, remote devices, simulators, runtime auto-setup | — (⛔ v1; loopback only, F15 for remote) |
| Reverse proxy, external/upstream proxy, DNS spoofing | — (not planned v1) |
| gRPC/protobuf, QUIC/HTTP3 | — (protobuf = client viewer only); QUIC — |

### TLS / certificates
| Proxyman | Ours |
|---|---|
| Root CA install/trust, status, reset | ✅ `ca.status/export/install/uninstall` + CA page |
| SSL proxying include/exclude per host/app | 🧩 `tls.passthrough.*` = F11 (S-067) |
| Custom root/server/client certs, TLS key logging | — (not v1) |

### Flow list & navigation
| Proxyman | Ours |
|---|---|
| Sidebar by app/domain; pinned; tabs; split view | ✅ Apps/Domains, Pinned/Saved, Split View (tabs ⛔ v1) |
| Columns (custom from headers/JSON), sort, resize, reorder | ✅ built-in columns, sort, reorder, persist; custom-from-header columns ⛔ v1 |
| Filter bar (primary + secondary + operators), multiple + saved filters, highlight | ✅ chips + stacked filters + Advanced expr + saved filters + ⌘K (match highlight ~) |
| Color + comment (11 colors), strikethrough | ✅ 11 marks + comment (F6 live) |
| Auto-follow, command palette, customizable toolbar | ✅ auto-select, ⌘K palette (toolbar fixed) |
| Overview dashboard, timing/charts | ✅ Overview + Connection Log; per-phase timing ~ (detail has duration; phase waterfall = F5 timing extension) |

### Inspector / viewers
| Proxyman | Ours |
|---|---|
| Header, Cookies, Set-Cookie, Auth, Query, Body, Raw, Form, Multipart, Summary, Connection, Comment | ✅ all present (Auth folded into Headers); Multipart ~ |
| Body: JSON, Tree, XML, HTML, form, image, Hex, MessagePack, SSE, GraphQL, protobuf | ✅ JSON/Tree/XML/image/Hex/MessagePack/SSE/protobuf/raw; HTML-render ~, GraphQL ~ |
| Body search/replace, open-in-editor, export body | ✅ find; export body ✅; open-in-editor ⛔ |
| JSONPath / jq filtering, custom previewer tabs | ~ (JSON tree + find); jq/JSONPath ⛔ v1; custom tabs ⛔ |
| Code generator (cURL/HTTPie/Python/fetch/…19) | ✅ cURL/HTTPie/Python/fetch (4 of 19) |
| Copy as (URL/cURL/headers/body/…) | ✅ Copy URL / cURL / httpie / Python / fetch |
| Diff two flows | ✅ Diff tab (two selected) |
| Quick preview (base64/JWT/timestamp decode) | ~ (Quick Look body); decoders ⛔ v1 |

### Intercept / modify
| Proxyman | Ours |
|---|---|
| Breakpoint: pause + edit request (scheme/host/path/method/headers/query/body) | ✅ live (`flow.detail`+`flow.mutate`) |
| Breakpoint: pause + edit response (status/headers/body) | 🧩 S-041 / F3 |
| Breakpoint rules (URL/regex/GraphQL), req/resp checkboxes | 🧩 Rules sheet built; core rules = F3 |
| Raw editor, disable-header, reset to original, templates | ✅ Raw editable + revert (templates ⛔ v1). Header *removal* needs a core `flow.mutate` removal form — the UI disables the delete ✕ and warns rather than silently no-op (FIXLOG 2026-10-28) |
| Drop/abort modes (reset/429/503) | ✅ kill drops (closed connection, PR #7); 429/503 modes = F3 |
| WebSocket breakpoint + compose/inject | 🧩 S-045 + F9 |
| Map Local, Map Remote, Rewrite, Scripting | ⛔ v1 (Map Local/Remote/Rewrite); scripting = rhai (M3) + F8 surface |
| Block/Allow list, No-Caching, Throttling | ⛔ v1 (rate-limit exists in core config) |

### Compose / replay
| Proxyman | Ours |
|---|---|
| Repeat / Edit & Repeat / Compose (templates, history, timeout) | ✅ Compose + history + Edit & Replay + Replay (`request.send`/`flow.replay`) |
| WebSocket compose | 🧩 F9 |

### Sessions / import-export / collaboration
| Proxyman | Ours |
|---|---|
| Save/open session | 🧩 S-066 / F10 |
| Import HAR/Charles/Proxyman; export HAR/CSV/cURL/Postman/OpenAPI/Gist | ✅ app-side HAR import + HAR/CSV/cURL export + drop; other formats + core `flow.import/export` = F10 |
| Team workspace / share-online | ⛔ v1 |

### Automation
| Proxyman | Ours |
|---|---|
| CLI (rules/toggles/export-log) | ✅ `aitm` CLI over the same registry |
| MCP server for agents (~70 actions) | ✅ our bus **is** MCP; agent policy + audit = F1/F2 |

## 5. L4 (layer-4 / raw TCP) — M5

No L4 in core today. When it lands, the same contract applies to raw streams; the
app needs a `stream` flow kind, a hex+text stream inspector, byte-level
intercept/edit, per-host TLS passthrough-vs-MITM (F11), and protocol detection.
The UI flow model and viewers are designed to extend from HTTP flows to streams.

## 6. Top priorities to reach the contract

1. **F1 operator frontend/token** — so operator UIs aren't treated as agents (unblocks scope + any operator-gated command without the config opt-in).
2. **F3 response-phase intercept + rules + kill modes** — edit responses, breakpoint rules, 429/503 kill modes. (`flow.kill` drop fixed in PR #7.)
3. **F9 WebSocket frame inject/edit** — reading frames shipped (S-045); inject/edit still needs F9.
4. **F10 sessions + import/export**, **F11 tls.passthrough**, **F4 live push**.
5. **HTTP/2** in core (Proxyman has it; we have a stub).
