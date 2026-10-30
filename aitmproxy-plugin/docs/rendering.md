# Rendering

Every host talks to the same MCP server and receives the same tool results. What
differs is presentation: **MCP Apps widgets** in ChatGPT and Claude Desktop /
claude.ai, and **text** in Claude Code. The server always returns
`structuredContent` so both paths work from one shape.

## Rich hosts — MCP Apps widgets

In **ChatGPT** and **Claude Desktop / claude.ai**, a successful tool call renders
an interactive widget in an iframe. Each widget is a self-contained HTML document
with inlined style and script (no external assets, CSP-clean) and is coloured from
`docs/design/tokens.json` — compiled to CSS custom properties, with correct light
and dark themes (the widget reads `window.openai.theme` / `openai:set_globals`,
falling back to `prefers-color-scheme`).

### The seven widget families

| Widget | Tool(s) | Shows |
|--------|---------|-------|
| **flows** | `flow.table` | the capture list — one row per flow (method, host, path, status, timing, state, marks) |
| **flow-detail** | `flow.detail` | one flow: request/response lines, header tables, syntax-coloured bodies, edit state |
| **findings** | `findings.list` | recorded findings — one row each (severity, title, class, target) |
| **finding-detail** | `findings.get` | one finding in full, with its evidence and linked flow |
| **scope** | `scope.list` | in-scope hosts and TLS passthrough entries |
| **poc-result** | `poc.run` | a PoC run outcome and its reproduction |
| **proxy-status** | `proxy.status` | listening address, intercept/pause/capture state, flow count |

Each widget maps the tool's `structuredContent` directly to its view and never
builds HTML from flow-derived strings (method, URL, headers, bodies, marks,
finding text are written as text nodes — never `innerHTML`/`eval`).

## Text hosts — Claude Code

**Claude Code renders no widget.** On success it receives `structuredContent`
(a JSON object), not the `content` text block. The bundled **`aitmproxy-rendering`
skill** teaches it to turn that into tight markdown **tables** with short text
**badges**, matching the widget palette (named colours or emoji, since Claude Code
cannot show CSS). Do not paste raw JSON.

## Palette groups (from `docs/design/tokens.json`)

The widgets colour these groups; the text skill labels them. The badge groups:

- **`color.method.*`** — HTTP method badge (tint background + deep text): `get`
  (blue), `post` (green), `put`/`patch` (amber), `delete` (red),
  `head`/`options`/`connect` (grey), `ws` (violet). In text: the bare uppercase
  method (`GET`, `POST`, `WS`).
- **`color.status.*`** — status class by first digit: `informational` (1xx),
  `success` (2xx), `redirect` (3xx), `clientError` (4xx), `serverError` (5xx),
  plus `pending` and `killed`. In text: the code plus a short tag
  (`200 ok`, `302 ->`, `403 client-err`, `500 srv-err`, `— pending`, `× killed`).
- **`color.severity.*`** — finding severity pill (tint + deep text): `critical`,
  `high` (red), `medium` (amber), `low` (blue), `info` (grey). In text: the word,
  optionally `🔴 critical` / `🟠 high` / `🟡 medium` / `🔵 low` / `⚪ info`.

Supporting groups the widgets draw: **`color.mark.*`** (the 11 flow mark
colours), **`color.syntax.*`** (body-viewer JSON/XML/headers colouring),
**`color.intercept.*`** (amber — the armed-intercept state), **`color.agent.*`**
(teal — agent-originated flows), **`color.l4.*`** (slate/indigo — L4 flows), and
the ground/line/text/accent groups for chrome. Typography uses two families —
`typography.family.ui` for labels and `typography.family.data` (monospace) for
every URL, header, body, time, size and id.

For the exact before/after text layout (flow table, findings list, proxy status,
flow detail), see the `aitmproxy-rendering` skill in
`aitmproxy-plugin/skills/aitmproxy-rendering/SKILL.md`.
