# aitmproxy-plugin (MCP Apps rich UI + ChatGPT connectivity) design

**Status:** Approved by Matt (orchestrator, autonomous mode) 2026-10-29
**Research inputs:** `docs/research/08-chatgpt-apps-sdk.md` (authoritative contract),
`docs/research/plugin-design-inputs.md`, `docs/research/mcp-tool-catalog.txt`,
`docs/research/palette-dump.txt`, `docs/design/tokens.json`. Source read:
`crates/aitm-mcp/src/{server.rs,schema.rs,render.rs,transport.rs,lib.rs}`,
`crates/aitm-core/src/{config.rs,flow.rs}`,
`crates/aitm-plugins/src/{capture.rs,scope.rs,control.rs}`,
`crates/aitm-findings/src/commands.rs`, `crates/aitm-poc/src/library.rs`.

> Where this spec and `08-chatgpt-apps-sdk.md` disagree, 08 wins. Where 08 marks a
> fact "unverified"/"undocumented", this spec treats it as a **manual verification
> item** (acceptance group (b)), never an automated gate.

## Intent

Ship a marketplace plugin, **aitmproxy-plugin**, that drives aitmproxy's existing
MCP server and renders its output as rich, palette-correct UI in ChatGPT (Apps
SDK / MCP Apps) and in Claude (claude.ai, Claude Desktop), while staying clean
text in Claude Code — plus the additive MCP-server changes that make that
rendering and ChatGPT connectivity possible. The repo ends properly documented,
with the plugin installable and testable from one tree. We want it now because the
blind-agentic-pentest demo and the broader operator story both benefit from a
one-command, richly-rendered MCP surface across both major agent hosts.

## Goals

- A single top-level `aitmproxy-plugin/` package carries both a Claude plugin
  (`.claude-plugin/`) and an OpenAI Agent-Plugins manifest (root `plugin.json` +
  `mcp.json`), sharing one `skills/` tree.
- The aitm MCP server serves MCP Apps widgets: `resources/list` + `resources/read`
  return `ui://aitm/<widget>` templates with mime `text/html;profile=mcp-app`;
  `initialize` additionally advertises a `resources` capability.
- A curated set of read-only tools (plus one new `flow.table` data tool) carry the
  additive `_meta`, `outputSchema`, and annotations that make them render as
  widgets, with zero change to any existing tool's name, description, inputSchema,
  `content`, or `structuredContent`.
- Seven widget families render the operator workflow (flows table, flow detail,
  findings list, finding detail, scope, PoC result, proxy status), all coloured
  from `tokens.json`, in both light and dark.
- A config-selected **streamable-HTTP** MCP transport exists alongside stdio and
  loopback-TCP, with a required token, Origin allowlist, DNS-rebinding
  protection, loopback-default bind, and a written threat model.
- Shared skills and commands teach the authorized-testing workflow, teach Claude
  Code to render `structuredContent` as markdown badges/tables, and mirror the
  mock's actions. Docs cover install+test for Claude Desktop, Claude Code, and
  ChatGPT; a generated tool reference; a rendering guide; and a new repo README.
- The Rust gate (`cargo fmt --check && cargo clippy --all-targets -- -D warnings
  && cargo test`) passes.

## Non-goals

- Changing any existing tool's name/description/inputSchema/`content`/
  `structuredContent`, or `flow.list`'s ids-only result.
- Capability gating of `_meta` (attaching UI only when the client advertises
  `io.modelcontextprotocol/ui`). Out for v1 — aitm `initialize` is stateless;
  attach UI unconditionally on widget tools. Noted as a follow-up.
- OAuth 2.1, mTLS proxy, or public ChatGPT submission itself. We make the server
  *submittable* and document the path; we do not run submission.
- Serving the legacy `text/html+skybridge` mime or a second `+skybridge` resource
  (direction B). Not shipped in v1; revisited only if the manual ChatGPT test
  fails (open decision 1).
- `widgetState`/`setWidgetState` persistence, follow-up messages, display-mode
  negotiation beyond `inline`, file APIs, checkout, PiP.
- Any change to web/tui/mac consumers of the command bus.
- L4/WebSocket-specific widgets (the families cover HTTP + findings + PoC + proxy
  status; L4 and WS reuse the flow detail/table shapes via `kind`).

## Anti-goals

- A widget that executes attacker-controlled flow bytes: any header name/value,
  URL, or body rendered via `innerHTML`/`eval`/inline event handlers. Captured
  traffic is attacker-controlled; widgets must write it with `textContent` only.
  This is a failure even if it "looks right".
- An HTTP transport that binds a non-loopback interface by default, or serves
  without a token, or answers a cross-origin / rebound request. This exposes a
  MITM proxy control plane; a default-open one is a failure regardless of tests.
- A change that makes Claude Code output noisier (extra tools in the list it must
  reason over, `ui://` resources polluting `@`-completion, or model-visible
  `structuredContent` growth).
- Divergent duplicate skill content between the Claude and OpenAI trees (two
  sources of truth). Skills are shared.
- Secrets or tokens printed to logs/stdout by the new transport (honours the
  operator-first-run hygiene rule).

## Constraints

- **Additive-only server contract.** The ~70 existing tools keep byte-identical
  name/description/inputSchema and byte-identical `content`/`structuredContent`
  results. Only the curated widget tools and the new `flow.table` gain
  `_meta`/`outputSchema`/`annotations` in their `tools/list` entry; `tools/call`
  results are unchanged for all tools (no result `_meta` in v1 — see Design D).
- **MCP revision.** Server declares `protocolVersion` `2025-06-18`
  (`server.rs:PROTOCOL_VERSION`); keep it. That revision types `structuredContent`
  and `outputSchema` as **object**; two widget tools return arrays (see Design D).
- **Transport parity.** stdio (default, no token, `Frontend::Mcp`) and
  loopback-TCP (token, role by token class) keep working unchanged; HTTP is a
  third `McpTransport` variant.
- **Palette is the single source of truth.** Widget CSS derives from
  `docs/design/tokens.json` (light+dark); no hand-picked hexes.
- **CSP.** Widgets are fully self-contained (JS+CSS inlined). Default MCP Apps CSP
  (deny network, inline scripts/styles allowed); declared `connectDomains`/
  `resourceDomains` are empty. No external fonts/scripts/images beyond `data:`.
- **Size.** Each widget HTML stays well under the known hard limits (Secure MCP
  Tunnel 10 MiB/req, Claude Code 16 MiB SSE, claude.ai ~150 k-char result
  spill). Target: each widget HTML < 100 KiB; `flow.table` `structuredContent`
  bounded (Design E).
- **Rust gate** applies to every server/transport/tool change. `unsafe` requires a
  `// SAFETY:` comment and security sign-off (none expected here).
- **Authorized-testing framing** in all user-facing skill/command/doc text.
- **No network at build/validate time** beyond what `claude plugin validate` and a
  local widget build need; the sandbox cannot bind ports or reach GitHub (manual
  steps run in the Terminal panel).

## Design

### A. Widget contract and `_meta` placement (per 08 §3.2–3.4)

Three placements, exactly as 08's three tables:

1. **Tool descriptor `_meta`** (in each widget tool's `tools/list` entry):
   - `ui.resourceUri` (string, `ui://aitm/<widget>`) — standard, preferred.
   - `openai/outputTemplate` (same `ui://` string) — ChatGPT alias.
   - `openai/toolInvocation/invoking` and `.../invoked` — each **≤ 64 chars**.
   - Plus sibling (not in `_meta`) `annotations` (`readOnlyHint`,
     `destructiveHint`, `openWorldHint`; all three required) and `outputSchema`.
2. **Resource `_meta`** (on the `resources/list` entry and the `resources/read`
   `contents[]` item): `ui.csp` `{connectDomains:[],resourceDomains:[]}` plus
   legacy `openai/widgetCSP` `{connect_domains:[],resource_domains:[]}`;
   `ui.domain` and `openai/widgetDomain` (origin string, Design H); `ui.prefersBorder`
   (bool); `openai/ui` `{availableDisplayModes:["inline"]}`.
3. **Result `_meta`** (on `tools/call`): **none in v1.** All render data travels in
   the unchanged `structuredContent`; adding result `_meta` would be the one place
   we could regress an existing tool's result, so we do not. (Follow-up only.)

`ui.resourceUri` placement is on the tool descriptor only (08 §3.2: "Only the
render tool should include `_meta.ui.resourceUri`"), never on the `tools/call`
result.

### B. `resources/*` and `initialize` capability (W2)

- `initialize` result `capabilities` becomes `{"tools":{}, "resources":{}}`
  (`server.rs` dispatch `"initialize"` arm). The non-standard top-level `role`
  echo and `serverInfo` stay. **(Architect's call)** also advertise the MCP Apps
  extension id under `capabilities.extensions`:
  `{"io.modelcontextprotocol/ui": {"mimeTypes":["text/html;profile=mcp-app"]}}`.
  Additive; clients that don't know it ignore it (08 §3.3 says the server "must
  also advertise `resources`"; the extension advert is belt-and-braces and is what
  direction C would later gate on).
- New dispatch arms in `server.rs`:
  - `"resources/list"` → `{"resources":[ <one entry per widget> ]}`. Each entry:
    `{uri, name, title, description, mimeType:"text/html;profile=mcp-app", _meta:{…resource meta…}}`.
  - `"resources/read"` with `params.uri` → `{"contents":[{uri, mimeType, text:"<!DOCTYPE html>…", _meta:{…}}]}`.
    Unknown/malformed `uri` → `RpcError(INVALID_PARAMS, "unknown resource <uri>")`.
- The widget templates are compile-time assets. **(Architect's call)** a new module
  `crates/aitm-mcp/src/widgets.rs` exposes:
  - `pub struct Widget { pub uri: &'static str, pub name: &'static str, pub title: &'static str, pub description: &'static str, pub prefers_border: bool, pub html: &'static str }`
  - `pub fn widgets() -> &'static [Widget]` — the registry of all seven widgets.
  - `pub const RESOURCE_MIME: &str = "text/html;profile=mcp-app";`
  - `pub fn resource_meta(w: &Widget) -> serde_json::Value` — builds the resource
    `_meta` (both `ui.*` and legacy `openai/*` keys).
  Each `html` is `include_str!`-ed from `crates/aitm-mcp/widgets/<widget>.html`
  (built in W5). The module is the single seam W2 and W5 share.
- `resources/*` is served regardless of transport and role (read-only; the
  templates contain no data). `tools/call` for non-widget tools is unchanged.

### C. Widget tool set and the render-direction decision (direction D)

**Decision (Architect's call): annotate select existing read-only tools, do not
add parallel render tools.** Rationale: it adds exactly one new tool (`flow.table`,
which fills a genuine data gap), keeps the ~70-tool list from doubling (Claude Code
tool-search cost, 08 §3.7), spares the model the data-vs-render tool choice, and
`_meta.ui`/`outputSchema`/`annotations` are additive and ignored by text-only
clients (08 §3.7: Claude Code hides `ui://` resources and shows `structuredContent`
regardless). The only cost is review surface on the annotated tools, which the
security reviewer already scrutinises.

Seven widget templates, referenced by eight tools (one new):

| Widget `ui://aitm/<widget>` | Tool(s) | Existing result type | Palette groups |
|---|---|---|---|
| `flows.html` | `flow.table` (NEW, W4) | object `{flows:[…]}` | method.*, status.*, mark.*, intercept.*, agent.* |
| `flow-detail.html` | `flow.detail` | object | method.*, status.*, syntax.* |
| `findings.html` | `findings.list` | **array** | severity.* |
| `finding-detail.html` | `findings.get` | object | severity.*, syntax.* |
| `scope.html` | `scope.list` (+ widget bridge call to `tls.passthrough.list`) | **array** | accent.* |
| `poc-result.html` | `poc.run`, `poc.get` | object | severity.*, status.* |
| `proxy-status.html` | `proxy.status` | object | status.*, intercept.*, agent.*, l4.* |

- **Annotations** on each widget tool: all are `readOnlyHint:true,
  destructiveHint:false, openWorldHint:false` **except `poc.run`**, which is
  `readOnlyHint:false, destructiveHint:false, openWorldHint:true` (it executes a
  PoC against a target). `poc.run` is the one non-read-only widget tool; it is
  included because it produces the result the "PoC result" mock shows. Flagged in
  Open decisions.
- **`outputSchema`** derived from each command's declared `result` `TypeDesc` via
  the existing `schema::type_schema` (W3). Object-result tools get a `type:"object"`
  schema; `findings.list` and `scope.list` get `type:"array"` schemas. The
  `structuredContent` stays the unchanged array for those two (open decision 2).
- **Scope widget / tls passthrough:** the scope widget's primary tool is
  `scope.list`; it issues a secondary MCP Apps bridge call
  (`app.callServerTool`/`window.openai.callTool`) to `tls.passthrough.list` and
  renders both sections. `tls.passthrough.list` therefore carries
  `ui.visibility:["model","app"]` and the legacy `openai/widgetAccessible:true` so
  the widget may call it; it gets no `ui.resourceUri` (it is a data source, not a
  render tool). It keeps `readOnlyHint:true`.
- **Invocation strings** (≤ 64 chars), e.g. `flow.table` → invoking "Fetching
  flows", invoked "Flows ready"; exact strings Left to the builder within the
  limit.

### D. `_meta`/annotations/outputSchema derivation (W3)

The existing `StdSchemaDerive::to_mcp_tool` and `McpTool::to_json`
(`schema.rs`) stay byte-identical for non-widget tools. Add an additive overlay:

- Extend `McpTool` with `pub ui: Option<WidgetMeta>`, default `None`, where
  `WidgetMeta { resource_uri: &'static str, invoking: &'static str, invoked: &'static str, read_only: bool, destructive: bool, open_world: bool, widget_accessible: bool }`.
- `McpTool::to_json` appends `annotations`, `outputSchema`, and `_meta` **only
  when `ui` is `Some`** (and `widget_accessible`-only tools like
  `tls.passthrough.list` get `_meta.ui.visibility` + `annotations` + `outputSchema`
  but no `resourceUri`). When `ui` is `None`, `to_json` output is unchanged.
- A lookup `pub fn widget_meta_for(tool_name: &str) -> Option<WidgetMeta>` (in
  `widgets.rs` or `schema.rs`) maps the eight tool names (plus
  `tls.passthrough.list`) to their overlay. `tools/list` in `server.rs` consults it
  when building each tool's JSON.
- `outputSchema` comes from `type_schema(&cmd.schema().result)` for the tool's
  command; the derivation is shared, not hand-written per tool.
- No result `_meta` (Design A3). Claude-Code `structuredContent`-precedence (08
  §3.7) is accepted as-is: we do **not** mutate `structuredContent` to add a
  `summary` field (would change the exact machine value; breaks the additive
  constraint). Claude Code clean output is instead delivered by the rendering
  **skill** (W8), which turns `structuredContent` into markdown.

### E. New `flow.table` data tool (W4)

A new read-only command in `crates/aitm-plugins/src/capture.rs`, registered by
`CapturePlugin` (same place as `FlowList`):

- `struct FlowTable; impl Command for FlowTable` — `name()` = `"flow.table"`,
  `sensitivity()` = `Sensitivity::Read`.
- `schema()`: description "Per-flow summaries for a flows table: method, URL,
  status, duration, state, and marks, oldest first. Read-only."; **no params**;
  `result: TypeDesc::Object(vec![ ParamDef{ name:"flows", ty: TypeDesc::Array(Box::new(TypeDesc::Object(row_fields()))), required:true, … } ])`.
- Each row object: `{ id: FlowId, kind: Str, method: Str?, authority: Str?,
  path: Str?, status: Int?, duration_ms: Int?, state: Str, marks: Array(Str) }`.
  `state` = `flow.intercept.label()`; `duration_ms` from `FlowMeta.duration`
  (`None` → null); `marks` from `FlowMeta.marks`; HTTP fields from the request
  (null for WebSocket rows, which still report `id/kind/state/marks`). Reuses the
  existing per-flow shape conventions from `capture.rs::summarize`.
- `invoke`: iterate `host.store().list()` oldest-first, build one row per flow,
  return `Value::Object({"flows": Value::Array(rows)})`. **Bounded:** cap at the
  store's visible set (same as `flow.list`); no bodies, no headers (keeps
  `structuredContent` small and model-safe).
- `flow.list` is **unchanged** (ids only). `flow.table` is purely additive, so
  web/tui/mac/CLI are untouched.
- The `flows.html` widget reads `toolOutput.flows`.

### F. Streamable-HTTP MCP transport + threat model (W1)

**Config (W1a, `crates/aitm-core/src/config.rs`).** New variant:

```
McpTransport::StreamableHttp {
    bind: SocketAddr,            // default 127.0.0.1:8084 (Architect's call; 8080/8081/8082 taken)
    token: String,               // REQUIRED, non-empty; Bearer on every request
    allowed_origins: Vec<String>,// exact Origin header allowlist; empty = no cross-origin allowed
    path: String,                // default "/mcp"
}
```

**Transport (W1b, new `crates/aitm-mcp/src/http.rs`).** Built on `hyper = "1"`
(features `server`,`http1`) + `hyper-util` + `http-body-util`, pinned in
`crates/aitm-mcp/Cargo.toml` (same pattern as `aitm-testtarget`). A
`pub struct StreamableHttp { … }` with `pub async fn bind(cfg) -> Result<Self>`,
`pub fn local_addr(&self) -> SocketAddr`, and
`pub async fn serve(self, server: Arc<McpServer>) -> Result<()>`. One endpoint at
`path`:

- **POST** `path`: body is one JSON-RPC message (or a batch); dispatched through
  the existing `McpServer::handle_on` with a `ConnCtx` of role **`Frontend::Mcp`**
  (same agent role as stdio/loopback). Response `Content-Type: application/json`
  for a single reply; `text/event-stream` only if/when a call needs to stream
  (v1 may answer all calls as single JSON — streaming SSE Left to the builder but
  the GET stream below must exist for server→client notifications).
- **GET** `path`: opens a `text/event-stream` the server writes notifications to
  (the push-sink lane, mirroring `serve_lines`' writer task). Required because MCP
  Streamable HTTP delivers `notifications/aitm/*` over this channel.
- **Guards, checked before any dispatch, in this order (fail closed):**
  1. **Auth:** `Authorization: Bearer <token>` must equal the configured token
     (constant-time compare). Missing/empty/wrong → `401`, no body echoing the
     token. A request with no token is never dispatched.
  2. **Origin allowlist (DNS-rebinding defence, part 1):** if an `Origin` header is
     present, it must be in `allowed_origins`; otherwise `403`. Empty allowlist
     means any present `Origin` is rejected (same-origin/no-Origin tools still
     work).
  3. **Host check (DNS-rebinding defence, part 2):** the `Host` header must be a
     loopback literal (`127.0.0.1[:port]`, `[::1][:port]`, `localhost[:port]`) or
     an explicitly allowlisted host; otherwise `403`. Blocks a rebound DNS name
     resolving to loopback.
  4. Method/path: anything but `POST`/`GET` on `path` → `405`/`404`.
- **Bind:** loopback by default; binding another interface requires the operator to
  set `bind` explicitly (config/CLI) — there is no "bind all" default and no code
  path that widens it implicitly.
- **Hygiene:** never log the token or the Bearer header; the startup line goes to
  **stderr** and says only `"MCP streamable HTTP listening on <addr><path>"`
  (operator-first-run rule). Reuse the endpoint-file rendezvous pattern
  (`LoopbackTcp`) to publish `host:port` (never the token) when an `endpoint_file`
  is configured — Left to the builder whether to thread one through in v1.
- **Threat-model note (W1c, lands in the server threat doc / README security
  section, W10):** this endpoint exposes a MITM proxy *control plane* — reading
  captured traffic, replaying, mutating, running PoCs — over a network socket.
  Document: token is the only authN; loopback-default; Origin+Host guards are the
  only DNS-rebinding defence; no TLS (operator must front it with a tunnel/HTTPS
  for any non-loopback use); binding non-loopback is an operator decision with a
  stated blast radius; the security reviewer must sign this off.
- stdio and loopback-TCP paths are untouched; `McpServer::handle_on` is the shared
  dispatch for all three.

### G. Widget bundles and palette CSS (W5)

- Source lives under `crates/aitm-mcp/widgets/`: one `<widget>.html` per family,
  each a complete HTML5 document with **inlined** `<style>` and `<script
  type="module">` (no external assets; CSP-clean). `include_str!` into `widgets.rs`
  (W2).
- **CSS from tokens.** A build step **(Architect's call)** `crates/aitm-mcp/widgets/build.(mjs|sh)`
  reads `docs/design/tokens.json` and emits `crates/aitm-mcp/widgets/tokens.css`
  as CSS custom properties with `:root` (light) and
  `@media (prefers-color-scheme: dark)` / `[data-theme="dark"]` (dark) blocks —
  e.g. `--color-method-get-fg`, `--color-method-get-bg`, `--color-severity-high-fg`,
  `--font-data`. Each widget `<style>` `@import`-equivalent is inlined (the
  generator inlines `tokens.css` into each widget at build, or each widget pastes
  the `:root` block) so the shipped HTML is self-contained. The generated CSS is
  committed so the Rust build never needs Node; regenerating is a documented
  developer step. Widgets must not contain literal hexes — a test greps for `#` +
  6 hex in the committed HTML and fails if found outside the generated token block.
- **Theme:** each widget reads `window.openai.theme` when present and listens for
  `openai:set_globals`; otherwise falls back to `prefers-color-scheme`. It sets
  `data-theme` on `<html>` accordingly. Both light and dark must be correct.
- **Bridge:** each widget uses the standard MCP Apps `App` bridge (inlined
  `@modelcontextprotocol/ext-apps` build, or a minimal hand-written `postMessage`
  client) for `ontoolresult`/`callServerTool`, and feature-detects `window.openai`
  for ChatGPT extras (08 §3.4: "Feature-detect each extension"). Handlers check
  `event.source === window.parent` and `jsonrpc === "2.0"`.
- **Safety (anti-goal enforcement):** all flow-derived strings (method, URL,
  header names/values, body, marks, finding text) are written with `textContent`
  or safe DOM construction — **never** `innerHTML`, `eval`, `new Function`, or
  inline `on*` handlers. A test greps each widget for `innerHTML`/`eval`/
  `new Function` and fails if present (body syntax colouring tokenises then appends
  text nodes; it never builds HTML strings from input).
- **Widgets are independently buildable** (one file each) so W5 fans out per
  widget once the W2/W3 contract (URIs, `structuredContent` shapes, outputSchema)
  is fixed.

### H. Plugin package: one repo, two manifests (direction G, W6/W7)

New top-level dir `aitmproxy-plugin/`.

**Claude (W6):**
- `aitmproxy-plugin/.claude-plugin/plugin.json` — `name:"aitmproxy"` (kebab, not a
  reserved name), `version`, `description`, `author{name:"Matt …"}`, `homepage`,
  `license`, `keywords`, `skills` pointing at the shared `skills/` (default layout;
  `commands/` auto-discovered).
- `aitmproxy-plugin/.claude-plugin/marketplace.json` — `name` (e.g.
  `"aitmproxy-marketplace"`, not reserved), `owner`, `plugins:[{name:"aitmproxy",
  source:"."}]`. **Entry `name` == manifest `name`** (08 §3.8) so the install id
  resolves.
- `aitmproxy-plugin/.mcp.json` — wire `aitm` over **stdio**:
  `{"mcpServers":{"aitm":{"command":"${AITM_BIN:-aitm}","args":["mcp"],"env":{}}}}`
  **(Architect's call)** — command via env with a sane default (`aitm` on PATH).
  The exact subcommand/args that start the stdio MCP server are Left to the builder
  to match `aitm`'s CLI (the catalog shows `aitm <command>`; the stdio MCP entry
  point must be confirmed against `aitm --help`/main).
- `commands/` and `skills/` at plugin root (shared tree, Design I/J).

**OpenAI Agent-Plugins (W7):**
- `aitmproxy-plugin/plugin.json` (root) — `$schema`
  `https://agent-plugins.org/schemas/1.0.0/plugin.schema.json`, `name`, `version`,
  `description`, and `extensions.com.openai` (interface/onboardingSkill pointing at
  the overview skill). Auto-discovers `skills/<name>/SKILL.md`.
- `aitmproxy-plugin/mcp.json` (no leading dot) — for local/dev: `type:"stdio"`,
  `command`/`args` using `${PLUGIN_ROOT}` where a path is needed, default `aitm` on
  PATH; for the remote/submission path a sibling documented block uses
  `type:"streamable-http"`, `url:"https://<host>/mcp"`. **(Architect's call)** ship
  the stdio form as the committed default and document the HTTP swap in W10 (public
  submission needs a stable HTTPS endpoint, not a local one — 08 §3.9).
- Shared `skills/` is the same tree both manifests reference. `commands/` is
  Claude-only (OpenAI converts commands to skills; we do not duplicate them —
  the OpenAI tree relies on skills for the same actions).
- Hooks: **none** (OpenAI public submission rejects hooks; avoid them entirely).

Placeholder-origin note: `ui.domain`/`openai/widgetDomain` is set to a single
constant origin string **(Architect's call)** `aitmproxy.widget` placeholder in
`widgets.rs`, to be replaced with the real per-plugin domain at submission time
(08 §3.3: default is a sandbox origin under `oaiusercontent.com`; a real unique
domain is required only for submission). Documented as a submission step.

### I. Skills (shared, W8) — `aitmproxy-plugin/skills/<name>/SKILL.md`

- `overview` — teaches the whole MCP-driven workflow (scope → capture →
  intercept/mutate → replay → findings/poc), framed for **authorized security
  testing only**, listing the key tools per stage. Also the OpenAI
  `onboardingSkill`.
- `rendering` — teaches a **text-only** host (Claude Code) to turn
  `structuredContent` into markdown: tables for `flow.table`/`findings.list`;
  method/status/severity **badges** mapped to the palette (named colours/emoji or
  backticked labels, since Claude Code cannot show CSS); how to read
  `flow.detail` headers/bodies. Explicitly notes that on success Claude Code sees
  `structuredContent`, not `content` text (08 §3.7).
- Focused per-domain skills **(Architect's call)**: `flows`, `intercept`,
  `findings-poc`, `scope-tls` — short references for each tool cluster. Count/split
  Left to the builder; content must stay within Claude Code's 4,096-char
  loaded-description trim where it matters.

### J. Commands (Claude, W9) — `aitmproxy-plugin/commands/<name>.md`

Mirror the mock: `fetch-flows`, `explain-request`, `generate-curl`, `map-remote`,
plus `triage`, `scope`, `findings`, `intercept`. Each is a prompt that drives the
MCP tools (e.g. `fetch-flows` calls `flow.table`; `explain-request`/`generate-curl`
call `flow.detail`; `map-remote` calls `map.add`). Authorized-testing framing in
each. These are agent-side text transforms, not widgets.

### K. Docs (W10)

- `aitmproxy-plugin/README.md` — orients the plugin, install+test for all three
  hosts:
  - **Claude Desktop** (stdio): add via `claude_desktop_config.json` or the plugin;
    widgets render.
  - **Claude Code** (stdio, text): `claude plugin marketplace add
    ./aitmproxy-plugin` → `claude plugin install aitmproxy@aitmproxy-marketplace`;
    text rendering via the `rendering` skill.
  - **ChatGPT** (dev mode): Secure MCP Tunnel wrapping the stdio server for local
    test, and the streamable-HTTP transport for a real/submission endpoint
    (`http://127.0.0.1:8084/mcp`), with the MCP Inspector check and the
    `chatgpt.com` add-server flow (08 §3.9).
- `aitmproxy-plugin/docs/tool-reference.md` — **generated** from the registry.
  **(Architect's call)** a small generator (`aitm`'s own help, or a
  `crates/aitm-mcp` example/bin that walks the registry) emits name/description/
  params/result per tool; committed output + a documented regen command. Left to
  the builder whether the generator is a Rust `--bin`/example or a script over
  `aitm` CLI output.
- `aitmproxy-plugin/docs/rendering.md` — the rendering guide (palette mapping,
  widget families, how each `structuredContent` shape maps to a widget).
- **Top-level repo `README.md`** (none exists today) — orients the whole repo and
  points at `aitmproxy-plugin/` and the MCP server. **(Architect's call)** keep it
  short; link to `docs/` and the plugin.
- The HTTP transport **threat-model note** (W1c) lands here (README security
  section or a dedicated `aitmproxy-plugin/docs/security.md`).

### Workstreams and dependency edges (for the plan's fan-out)

| WS | Scope | Primary files (touch-set) |
|---|---|---|
| **W1** | Streamable-HTTP transport + config + threat note | `crates/aitm-core/src/config.rs` (enum); NEW `crates/aitm-mcp/src/http.rs`; `crates/aitm-mcp/src/lib.rs` (mod+export); `crates/aitm-mcp/Cargo.toml`; `crates/aitm/src/main.rs` (wire the variant) |
| **W2** | `resources/*` + `initialize` capability + widgets module | `crates/aitm-mcp/src/server.rs` (dispatch arms, capabilities); NEW `crates/aitm-mcp/src/widgets.rs`; `crates/aitm-mcp/src/lib.rs` |
| **W3** | Tool-descriptor `_meta`/`outputSchema`/`annotations` overlay | `crates/aitm-mcp/src/schema.rs` (McpTool overlay, to_json); `crates/aitm-mcp/src/server.rs` (tools/list consults overlay) |
| **W4** | `flow.table` tool | `crates/aitm-plugins/src/capture.rs` |
| **W5** | Widget HTML bundles + palette CSS build (per widget) | `crates/aitm-mcp/widgets/*.html`, `.../tokens.css`, `.../build.*` |
| **W6** | Claude manifests + `.mcp.json` | `aitmproxy-plugin/.claude-plugin/*`, `aitmproxy-plugin/.mcp.json` |
| **W7** | OpenAI manifest | `aitmproxy-plugin/plugin.json`, `aitmproxy-plugin/mcp.json` |
| **W8** | Skills (shared) | `aitmproxy-plugin/skills/**` |
| **W9** | Commands (Claude) | `aitmproxy-plugin/commands/*.md` |
| **W10** | Docs + README + tool-reference generator | `aitmproxy-plugin/README.md`, `aitmproxy-plugin/docs/*`, top-level `README.md`, generator |
| **W11** | Protocol + plugin-validate test harness | `crates/aitm-mcp/tests/*`, `crates/aitm-plugins/tests/*`, a widget-lint test, a `claude plugin validate` doc-step |

**Dependency edges:**
- W2, W3 both edit `crates/aitm-mcp/src/server.rs` → **must serialize or split by
  arm**: W2 owns the `initialize`/`resources/*` arms and `widgets.rs`; W3 owns the
  `tools/list` arm and `schema.rs`. If one file, order W2 then W3.
- W3 depends on **W4** (needs `flow.table` registered to overlay it) and on **W2**
  (needs `widget_meta_for`/the `ui://` URIs from `widgets.rs`). Order: W4 →
  W2 → W3.
- **W5** depends on the widget contract fixed by **W2** (URIs, mime, resource meta)
  and **W3/W4** (the exact `structuredContent`/`outputSchema` shapes). Within W5,
  each widget HTML is independent and fans out.
- **W1** is independent of W2–W5 (disjoint files except the shared `lib.rs` mod
  list and `main.rs` wiring — coordinate those two touch-points). Can run in
  parallel with W2–W5.
- **W6, W7, W8, W9** are mutually independent (disjoint files under
  `aitmproxy-plugin/`) and depend only on tool/widget **names** being final
  (after W2–W4), not on their implementation. Can fan out together.
- **W10** depends on the final tool set (W4) and the install story (W1, W6, W7);
  write last or in parallel with a late draft.
- **W11** depends on the thing each test targets: protocol tests after W1/W2/W3/W4;
  widget-lint after W5; validate-step after W6/W7. Fans out per target.

## Acceptance criteria

### (a) Automated — Rust/MCP protocol, tool shape, transport, widget-lint

1. **AC1** `initialize` result `capabilities` contains both `tools` and
   `resources` (and the `io.modelcontextprotocol/ui` extension entry), and still
   contains the existing top-level `role` and `serverInfo`. Test asserts the JSON.
2. **AC2** `resources/list` returns exactly seven entries, each with
   `mimeType=="text/html;profile=mcp-app"`, a `ui://aitm/<widget>` `uri`, and
   resource `_meta` carrying `ui.csp` + `openai/widgetCSP` (empty domain arrays),
   `ui.domain`/`openai/widgetDomain`, `ui.prefersBorder`, `openai/ui.availableDisplayModes==["inline"]`.
3. **AC3** `resources/read` for each of the seven `ui://aitm/*` URIs returns
   `contents[0].mimeType=="text/html;profile=mcp-app"` and a `text` beginning
   `<!DOCTYPE html>`; an unknown URI returns a JSON-RPC error with code
   `INVALID_PARAMS`.
4. **AC4** `tools/list`: the eight widget tools and `tls.passthrough.list` carry
   the expected `_meta` — widget tools have `_meta.ui.resourceUri` ==
   `openai/outputTemplate` == the mapped `ui://aitm/<widget>`, and
   `openai/toolInvocation/invoking`/`invoked` each ≤ 64 chars;
   `tls.passthrough.list` has `_meta.ui.visibility==["model","app"]` (and legacy
   `openai/widgetAccessible==true`) and **no** `resourceUri`.
5. **AC5** Each widget tool's entry has `annotations` with all three of
   `readOnlyHint`/`destructiveHint`/`openWorldHint` present; every widget tool is
   `readOnlyHint:true` except `poc.run` (`readOnlyHint:false, openWorldHint:true`);
   and an `outputSchema` whose `type` matches the command's `result` (`object` for
   all except `findings.list`/`scope.list`, which are `array`).
6. **AC6** **No regression:** for every tool **not** in the widget set, its
   `tools/list` entry is byte-identical to the pre-change output (snapshot test
   over the full `tools/list`, diff limited to the widget tools +
   `tls.passthrough.list` + the new `flow.table`). No tool's `tools/call` result
   gains `_meta`.
7. **AC7** `flow.table` exists, is `Sensitivity::Read`, takes no params, and
   returns `structuredContent` shaped `{"flows":[{id,kind,method?,authority?,
   path?,status?,duration_ms?,state,marks}…]}`. With two captured flows (one HTTP
   GET→200, one WebSocket), the result has `flows.len()==2`, the HTTP row has
   `method=="GET"`, `status==200`, `state=="observed"`, and the WS row has
   `kind=="websocket"`. `flow.list` output is unchanged (ids only).
8. **AC8** HTTP transport — **auth:** a `POST /mcp` with no/invalid `Authorization:
   Bearer` returns `401` and is never dispatched; a correct token is accepted.
9. **AC9** HTTP transport — **Origin:** a `POST /mcp` carrying an `Origin` not in
   `allowed_origins` returns `403`; an allowlisted Origin (or no Origin) is
   accepted.
10. **AC10** HTTP transport — **rebinding/Host:** a `POST /mcp` with a `Host`
    header that is neither loopback nor allowlisted returns `403`.
11. **AC11** HTTP transport — **bind default:** with a default config the listener
    binds a loopback address (`127.0.0.1`); binding elsewhere requires an explicit
    `bind`. Test asserts `local_addr().ip().is_loopback()`.
12. **AC12** HTTP transport — **end-to-end:** an authorized, same-origin
    `initialize` + `tools/list` + `resources/read` over POST returns the same
    results AC1–AC3 assert over stdio.
13. **AC13** stdio and loopback-TCP transports still pass their existing tests
    unchanged (regression guard).
14. **AC14** **Widget-lint:** every committed `crates/aitm-mcp/widgets/*.html`
    contains **no** `innerHTML`, `eval`, `new Function`, or inline `on*=` handler,
    and **no** literal 6-digit hex colour outside the generated token block (colours
    come from CSS custom properties / `tokens.css`).
15. **AC15** The full Rust gate passes:
    `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

### (b) Manual — Matt only (verification items, not merge blockers)

These resolve 08's open questions 1–5/11/12 and cannot run in the sandbox (no port
binding to a real host, no ChatGPT/Claude account, no `open`). Each is a checklist
item in the plan's Shipped section, not a gate:

- **MV1** In ChatGPT dev mode, add the server (Secure MCP Tunnel over the stdio
  server, then the HTTP transport) and confirm each widget renders richly and
  light/dark track the host theme (08 OQ 1, 4, 11).
- **MV2** In Claude Desktop / claude.ai, add the stdio server and confirm the same
  widgets render; in Claude Code confirm clean text output and that `ui://`
  resources do not pollute `@`-completion (08 OQ 10).
- **MV3** Confirm ChatGPT accepts `text/html;profile=mcp-app` (and whether it still
  needs `text/html+skybridge`); if it rejects object-less/array `structuredContent`
  or `outputSchema` on `findings.list`/`scope.list`, trigger the open-decision-2
  fallback (08 OQ 1, 3; §3.6).
- **MV4** Confirm no client rejects `_meta` keys with `/` in the name segment and
  that unknown `_meta` is ignored by Claude Code (08 OQ 8).
- **MV5** Run `claude plugin validate ./aitmproxy-plugin` in the Terminal panel and
  confirm "Validation passed"; install and list the plugin locally.
- **MV6** Security reviewer signs off the HTTP transport threat model before any
  non-loopback use.

## Left to the builder

- Exact `openai/toolInvocation` invoking/invoked strings per tool (≤ 64 chars).
- Whether the token→CSS generator is Node or shell, and the committed `tokens.css`
  layout, provided the Rust build needs no Node and AC14 holds.
- Whether `flow.table` rows include a `comment`/`truncated` field (additive to the
  row object); keep the required set from AC7.
- The precise `aitm` subcommand/args that start the stdio MCP server in the two
  `.mcp.json`/`mcp.json` files (confirm against the CLI).
- The number/split of focused per-domain skills and the exact command prompt text.
- Whether the tool-reference generator is a Rust `--bin`/example or a CLI-output
  script; and whether the HTTP transport threads an `endpoint_file`.
- Whether POST answers stream as SSE in v1 or always single-JSON (GET SSE lane
  must exist for notifications regardless).
- The marketplace `name` string and plugin `author`/`homepage`/`license` values.

## Open design decisions

Posture items I would flag, with recommendation. None blocks approval; listed most
important first.

1. **HTTP transport exposes a MITM control plane (posture 4).** I agree it should
   ship now but recommend it default to **loopback + token + empty Origin
   allowlist**, with non-loopback bind gated behind an explicit operator action and
   a startup warning, and **no TLS in-process** (operator fronts it with a
   tunnel/HTTPS). If you want in-process TLS or an OAuth path in v1, say so — it is
   currently out of scope and would be a large addition.
2. **Array `structuredContent` on `findings.list`/`scope.list` (posture 3 + 5).**
   These two widget tools return top-level arrays, which violate the 2025-06-18
   object typing ChatGPT expects and may reject (08 §3.6). My recommendation:
   attach the widgets anyway with `type:"array"` `outputSchema`, keep the arrays
   unchanged (no breaking change), and if the ChatGPT manual test (MV3) fails, add
   object-wrapping render tools `findings.table`/`scope.summary` as a fast-follow
   (the widgets already read both shapes). The alternative — adding those two tools
   now — contradicts posture 3's "one new data tool" and I did not take it. Confirm
   you accept the array-first approach with a documented fallback.
3. **`poc.run` is the one non-read-only widget tool (posture 2 + 5).** Posture 2
   says annotate *read-only* tools; posture 5 lists "PoC result" from
   `poc.run`/`poc.get`. I attached the poc-result widget to both and annotated
   `poc.run` `readOnlyHint:false, openWorldHint:true`. If you would rather keep all
   widget tools strictly read-only, drop `poc.run` and render PoC results only from
   `poc.get` (loses the live-run result view). Recommend keeping `poc.run`.
4. **Render direction D — annotate existing vs new render tools (posture 2).** I
   chose **annotate existing read-only tools** (plus the one `flow.table`). If you
   prefer OpenAI's strict data/render split (new `*.render` tools beside the data
   tools), that roughly doubles the widget-adjacent tool count and adds Claude Code
   list noise; I recommend against it.
5. **No result `_meta`, no `structuredContent` mutation (posture, 08 §3.7).** To
   keep existing results byte-identical I put *no* data in result `_meta` and do
   **not** add a `summary` field to `structuredContent`; Claude Code cleanliness
   comes from the rendering skill. If you want richer Claude-Code transcripts at the
   cost of changing the machine value, that is a deliberate contract change to
   approve separately.

## Open questions

None. (08's unresolved items are tracked as manual verification items MV1–MV6 and
open design decisions 1–5, not as approval blockers.)
