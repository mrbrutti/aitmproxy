---
name: aitmproxy-rendering
description: Present aitmproxy MCP tool output cleanly in a text-only host such as Claude Code, which sees the tool's structuredContent JSON and renders no widget. Use whenever you call an aitmproxy tool (flow.table, flow.detail, findings.list, findings.get, proxy.status, scope.list, poc.run) and must show the result to the operator. Teaches turning structuredContent into tight markdown tables with short text badges for HTTP method, status class and finding severity, matching the widget palette.
---

# aitmproxy rendering (text hosts)

aitmproxy ships rich widgets that render in ChatGPT and Claude Desktop / claude.ai.
**Claude Code renders no widget** — on a successful call it shows the tool's
`structuredContent` (a JSON object), not the `content` text block. So in Claude
Code you must read `structuredContent` yourself and format it. This is operator
output for an **authorized** security engagement; keep it factual, no filler.

## The rule

Turn `structuredContent` into a tight markdown **table** (one row per flow /
finding), and convey method, status and severity as short **text badges** — the
widgets colour these; in text you label them. The colours live in
`docs/design/tokens.json`; in rich hosts the widgets apply them, in text hosts use
the concise labels below (optionally a leading emoji). Do not paste raw JSON.

### Three badge families (names from the palette)

- **Method** (`color.method.*`): GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS,
  CONNECT, WS. Render as the bare uppercase method, e.g. `GET`, `POST`, `WS`.
- **Status** (`color.status.*`): classify by first digit — 1xx informational,
  2xx success, 3xx redirect, 4xx clientError, 5xx serverError; plus `pending`
  (parked/in-flight) and `killed`. Render the code with a short tag, e.g.
  `200 ok`, `302 ->`, `403 client-err`, `500 srv-err`, `— pending`, `× killed`.
- **Severity** (`color.severity.*`): critical, high, medium, low, info. Render as
  the word, optionally `🔴 critical` / `🟠 high` / `🟡 medium` / `🔵 low` /
  `⚪ info`.

Keep URLs/ids in backticks (`` `authority` ``, `` `id` ``) so they stay copyable.

## Before / after

### flow.table — `{flows:[{id,kind,method,authority,path,status,duration_ms,state,marks}]}`

Instead of dumping the array, render:

| id | method | host | path | status | ms | state |
|----|--------|------|------|--------|----|-------|
| `3f2a` | GET | `api.example.com` | `/v1/users` | 200 ok | 48 | done |
| `3f2b` | POST | `api.example.com` | `/v1/login` | 302 -> | 91 | done |
| `3f2c` | WS | `api.example.com` | `/socket` | — pending | — | parked |

### findings.list — array (or `{findings:[…]}`) of `{id,title,class,severity,target,when}`

| id | severity | title | class | target |
|----|----------|-------|-------|--------|
| `F-01` | 🔴 critical | SQLi in login | sqli | `api.example.com` |
| `F-02` | 🟡 medium | Missing CSRF token | csrf | `app.example.com` |

### proxy.status — `{listening,address,intercept_armed,paused,capturing,flows}`

Render one compact line, not JSON:

> Proxy **listening** on `127.0.0.1:8080` · intercept **armed** · paused 2 ·
> capturing · 134 flows.

## flow.detail

`flow.detail` returns headers, bodies, connection info, timing and edit state for
one flow. Present it as sections — a request line + a short headers table, a
response line + headers table, and bodies in fenced code blocks (truncate large
bodies; request a range via `flow.detail --body range --offset --length`). Note
any edit state so the operator sees a mutated or parked flow.

Accept both shapes defensively: findings/scope results may arrive as a top-level
array or object-wrapped (`{findings:[…]}` / `{entries:[…]}`).
