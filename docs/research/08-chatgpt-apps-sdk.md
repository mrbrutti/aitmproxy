# 08 — ChatGPT Apps SDK / MCP Apps, Claude rendering, and plugin packaging

Researcher note, stage 1. All sources read on **2026-10-29** unless a row says
otherwise. Nothing here is a design decision; candidates are marked as such.

> Numbering: `08-l4-packet-rust.md` already holds number 08 (the index also has
> two 07s and two 10s). The filename here was fixed by the requester, so there is
> no file collision, only a duplicate number.

## 1. Question

What exact MCP contract (tool/resource/result `_meta`, resource mime type,
runtime bridge, CSP, transports, packaging) must aitmproxy's Rust MCP server and a
dual-target "aitmproxy-plugin" follow so tool results render as rich UI in
ChatGPT and as clean output in Claude (claude.ai, Claude Desktop, Claude Code)?

## 2. Short answer

ChatGPT's Apps SDK is now documented as "plugins" built on MCP Apps. Current
contract: tool `_meta.ui.resourceUri` (alias `openai/outputTemplate`), a
`ui://` resource served as `text/html;profile=mcp-app` with inline HTML, and
`structuredContent` feeding the widget. Claude.ai and Claude Desktop render the
same MCP Apps UI; Claude Code renders nothing and shows its model
`structuredContent` JSON instead of `content` text. ChatGPT needs streamable
HTTP (public HTTPS or Secure MCP Tunnel); aitm today speaks only stdio and
loopback TCP.

## 3. Findings

### 3.0 Headline corrections to assumptions in the brief

These differ from what the request, and `plugin-design-inputs.md`, assumed.

1. **The skybridge mime is legacy in the docs.** Current OpenAI docs and the MCP
   Apps spec use `text/html;profile=mcp-app`. `text/html+skybridge` survives only
   in older sources. Whether ChatGPT still accepts it is not stated anywhere I
   could read (see 3.2, Open questions).
2. **Claude does render custom MCP UI.** claude.ai, Claude Desktop (and mobile,
   Cowork) host MCP Apps. Only Claude Code does not (3.7). So "Claude = text
   only" is false for two of three Claude surfaces.
3. **`openai/locale` is a client-to-server key, not a server-declared one.**
   `openai/resultCanProduceWidget` is not in the current official docs at all.
   `sendFollowupTurn` appears in no source I read.
4. **Claude Code prefers `structuredContent` over `content` text** on success
   (3.7). That changes the value of the readable text aitm renders today.
5. **ChatGPT needs a remote streamable-HTTP endpoint.** aitm-mcp has stdio and
   loopback-TCP only (3.9).

### 3.1 Docs landscape and naming (as of 2026-10-29)

- OpenAI's Apps SDK docs have been folded into a "Plugins" doc set. The page
  index lists Build / Concepts / Deploy / Guides / Reference, a
  `Reference (ChatGPT-specific UI extensions and metadata)` page, and a
  `Submit your Claude Code plugin to OpenAI` guide.
  Source: https://developers.openai.com/plugins (read 2026-10-29).
- Some `/apps-sdk/...` URLs still serve content and now reflect the new text
  (e.g. https://developers.openai.com/apps-sdk/build/chatgpt-ui described MCP
  Apps equivalents and pointed to `/plugins/reference`).
- OpenAI states the direction: "The compatibility aliases remain available for
  existing integrations. New UI should use the shared fields and bridge methods."
  Source: https://developers.openai.com/apps-sdk/mcp-apps-in-chatgpt.
- MCP Apps = MCP extension SEP-1865, **status Stable, dated 2026-01-26**,
  extension id `io.modelcontextprotocol/ui`.
  Source: https://raw.githubusercontent.com/modelcontextprotocol/ext-apps/main/specification/2026-01-26/apps.mdx.

### 3.2 Declaring a rich UI for a tool (ChatGPT) — exact keys and placement

Placement summary (from the OpenAI reference, which has three tables):

| Where | Object | What goes there |
|---|---|---|
| `tools/list` entry | tool descriptor `_meta` | UI link, visibility, status strings |
| `resources/list` entry and `resources/read` `contents[]` item | resource `_meta` | CSP, domain, border, description, display modes |
| `tools/call` result | result `_meta` | widget-only data, hidden from the model |

Source: https://developers.openai.com/plugins/reference (read 2026-10-29).

**Tool descriptor `_meta`**

| Key (exact string) | Value type | Status / notes |
|---|---|---|
| `ui.resourceUri` (i.e. `_meta: {ui: {resourceUri}}`) | string, `ui://` URI | Standard; "Preferred". |
| `openai/outputTemplate` | string, `ui://` URI | "ChatGPT alias for `resourceUri`"; ChatGPT "also honors" it. |
| `ui.visibility` | string[] of `"model"`/`"app"` | Default `["model","app"]`. App-only tools are hidden from the model. |
| `openai/widgetAccessible` | boolean | Default `false`. **Legacy**; prefer `ui.visibility`. Gates `callTool` from the widget. |
| `openai/visibility` | `"public"`/`"private"` | Default `public`. Legacy. |
| `openai/toolInvocation/invoking` | string, **<= 64 chars** | Status text while running. No MCP Apps equivalent ("Not yet implemented" in the migration table). |
| `openai/toolInvocation/invoked` | string, **<= 64 chars** | Status text after completion. Same. |
| `openai/profile` | boolean (only `true` counts) | Marks the read-only "who am I" tool. |
| `openai/fileParams` | string[] | Input fields that receive file objects. |
| `securitySchemes` | array | Back-compat mirror for `_meta`-only clients. |

Annotations: "`readOnlyHint`, `destructiveHint`, and `openWorldHint` are
required. `idempotentHint` is optional." Declare `outputSchema` "for any tool
that returns `structuredContent`". Source: same reference page.

**Resource `_meta`** (on the resource and on the `resources/read` contents item)

| Key | Type | Notes |
|---|---|---|
| `ui.csp` | `{connectDomains, resourceDomains, frameDomains?}` (string[]) | Standard. MCP spec adds `baseUriDomains`. |
| `openai/widgetCSP` | `{connect_domains, resource_domains, frame_domains?, redirect_domains?}` | **Legacy snake_case.** `redirect_domains` is OpenAI-only and "still required" for `openExternal` targets even when `ui.csp` is used. |
| `ui.domain` / `openai/widgetDomain` | string (origin) | "Required for plugin submission with UI, unique per plugin." Default is a sandbox origin under `oaiusercontent.com`. |
| `ui.prefersBorder` / `openai/widgetPrefersBorder` | boolean | |
| `openai/widgetDescription` | string | Summary shown to the model when the component loads. No MCP Apps equivalent. |
| `openai/ui` | `{availableDisplayModes: string[]}` | Values `inline`, `fullscreen`, `pip`. |

**Result `_meta`** (on `tools/call` result)

- Whole object is "sent only to the component, hidden from the model"; it arrives
  as `window.openai.toolResponseMetadata` (3.4).
- `openai/widgetSessionId`: set by the **host**, a stable id for the mounted
  widget instance.
- `mcp/www_authenticate`: on error results, triggers OAuth.

**`_meta` keys the client sends to the server** (not server-declared)

- `openai/locale`: BCP 47, sent "on initialize and tool calls". Older clients may
  send `webplus/i18n`.
- `openai/userAgent` (hint only), `openai/userLocation` (coarse),
  `openai/subject`, `openai/session`, `openai/organization` (anonymised ids).
- "Servers should not use the hints for authorization and must tolerate their
  absence."

**Not in current official docs**

- `openai/resultCanProduceWidget`: absent from the OpenAI reference, the plugin
  docs, and the MCP Apps migration page. It appears only in third-party code
  (Vercel Next.js template, xmcp, the OpenAI-Apps-Handbook), usually set to `true`
  beside `openai/widgetAccessible`. No documented effect.
  Sources: https://vercel.com/templates/next.js/chatgpt-app-with-next-js,
  https://xmcp.dev/docs/integrations/openai (via search results, not opened).
  **Treat as unverified; I could not establish what it does.**

**Legacy placement evidence.** OpenAI's `pizzaz_server_python` example (repo
`main`, read 2026-10-29) attached `openai/outputTemplate`,
`openai/toolInvocation/invoking`, `openai/toolInvocation/invoked`,
`openai/widgetAccessible` to the Tool, Resource, ResourceTemplate and
`TextResourceContents`, and attached only the two `toolInvocation` keys to the
`CallToolResult` `_meta`. In issue #90 a commenter (frozenabe, not identified as a maintainer) says
metadata belongs on the tool definition, not the response; another commenter
notes the official Kanban example puts `openai/outputTemplate` only on the tool.
Sources: https://raw.githubusercontent.com/openai/openai-apps-sdk-examples/main/pizzaz_server_python/main.py,
https://github.com/openai/openai-apps-sdk-examples/issues/90.

**Data-tool / render-tool split.** OpenAI recommends: "data tools return
`structuredContent` with no template, and render tools carry
`_meta.ui.resourceUri`"; "Only the render tool should include
`_meta.ui.resourceUri`". Sources: https://developers.openai.com/plugins/build/chatgpt-ui,
https://developers.openai.com/apps-sdk/mcp-apps-in-chatgpt.

### 3.3 Serving the UI template resource

- **Mime type (current):** `text/html;profile=mcp-app`. OpenAI reference example
  and the MCP Apps spec both use it. The SDK constant `RESOURCE_MIME_TYPE`
  (`@modelcontextprotocol/ext-apps/server`) equals it.
  Sources: https://developers.openai.com/plugins/reference,
  https://github.com/modelcontextprotocol/ext-apps/blob/main/src/server/index.ts.
- **Mime type (legacy):** `text/html+skybridge`. Still the constant in
  `openai-apps-sdk-examples` `main` (`pizzaz_server_python/main.py`,
  `kitchen_sink_server_node/src/server.ts`). The MCP Apps migration table maps it
  to `text/html;profile=mcp-app`.
  Source: https://apps.extensions.modelcontextprotocol.io/api/documents/Migrate_OpenAI_App.html.
- **Does ChatGPT still accept the legacy mime?** Not stated. The migration page
  says it "does not say that ChatGPT still accepts the legacy `openai/*` keys or
  the `text/html+skybridge` MIME type." Draft (unmerged, as of the page read)
  ext-apps PR #172 registers a second resource at `<uri>+skybridge` with mime
  `text/html+skybridge` for OpenAI. https://github.com/modelcontextprotocol/ext-apps/pull/172.
- **URI:** `ui://` scheme. Examples: `ui://widget/todo.html` (OpenAI quickstart),
  `ui://widget/pizza-map.html` (examples repo), `ui://quickstart/dice` (Claude
  quickstart). The URI "acts as a cache key": publish a new URI for breaking
  changes. Backward-compatible HTML changes at the same URI propagate with
  caching "up to one hour". Sources: chatgpt-ui page; app-review page
  https://developers.openai.com/plugins/deploy/app-review.
- **Content:** returned by `resources/read` as `text` or base64 `blob`; "must be a
  valid HTML5 document" (MCP Apps spec).
- **Inline vs referenced assets:**
  - OpenAI quickstart (vanilla): HTML read from a file and returned as `text`;
    for React, "run a build ... then inline the compiled assets into the HTML
    template" (https://developers.openai.com/plugins/build/app-quickstart.md).
  - Claude quickstart: "serve the client script from your own origin, or bundle
    it into the HTML, and list only that origin in `resourceDomains`"; its demo
    loads `App` from unpkg and therefore needs
    `_meta.ui.csp.resourceDomains: ['https://unpkg.com']`.
  - Both therefore support external scripts only through declared CSP origins.
    A fully inlined document needs no CSP entries (MCP Apps default is "deny
    everything", scripts/styles inline allowed).
- **Size limit on the HTML:** **none documented** in any OpenAI, MCP, or Claude
  page I read. Adjacent hard limits that bound it in practice: Secure MCP Tunnel
  10 MiB per serialized request/response; Claude Code remote response 16 MiB per
  JSON body/event (3.7, 3.9).

Minimal server-side wire shapes (assembled from the OpenAI and Claude quickstarts;
not copied from one source):

```jsonc
// tools/list entry
{ "name": "flow.list", "title": "List flows", "description": "...",
  "inputSchema": {"type":"object","properties":{}},
  "outputSchema": {"type":"object", "properties": {"flows": {"type":"array"}}},
  "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
  "_meta": { "ui": {"resourceUri": "ui://aitm/flows.html"},
             "openai/outputTemplate": "ui://aitm/flows.html",      // optional alias
             "openai/toolInvocation/invoking": "Fetching flows",   // <= 64 chars
             "openai/toolInvocation/invoked":  "Flows ready" } }

// resources/read result
{ "contents": [ { "uri": "ui://aitm/flows.html",
                  "mimeType": "text/html;profile=mcp-app",
                  "text": "<!DOCTYPE html>...",
                  "_meta": { "ui": { "prefersBorder": true,
                                     "csp": {"connectDomains": [], "resourceDomains": []} } } } ] }

// tools/call result
{ "content": [{"type":"text","text":"..."}],
  "structuredContent": { "flows": [ ... ] },
  "_meta": { "anything-widget-only": true } }
```

Server capability: the OpenAI and Claude flows both read tools via `tools/list`
and the UI via `resources/read`, so the server must also advertise
`resources` (aitm's `initialize` advertises only `{"tools": {}}`, 3.9).

### 3.4 The runtime inside the widget iframe

Two layers. Use the MCP Apps bridge where an equivalent exists; `window.openai`
for ChatGPT-only extras (OpenAI: "Feature-detect each extension ... Avoid
branching on a host or product name").

**MCP Apps bridge (standard; JSON-RPC 2.0 over `postMessage`).** From the spec
and OpenAI quickstart:

| Message | Direction | Notes |
|---|---|---|
| `ui/initialize` (request) | view -> host | Must include `appCapabilities` (`tools`, `availableDisplayModes`, `experimental`). Result: `protocolVersion`, `hostCapabilities`, `hostInfo`, `hostContext`. OpenAI quickstart uses protocolVersion `"2026-01-26"`. |
| `ui/notifications/initialized` | view -> host | Host sends nothing until it arrives. |
| `ui/notifications/tool-input` | host -> view | Complete args (`params.arguments`). May be late for approval-gated tools. |
| `ui/notifications/tool-input-partial` | host -> view | Optional, best effort. |
| `ui/notifications/tool-result` | host -> view | A `CallToolResult` (`params.structuredContent`, `params.content`, `params._meta`). |
| `tools/call` | view -> host | `{name, arguments}`; result has `structuredContent`. |
| `ui/message` | view -> host | `{role, content}`; follow-up message. |
| `ui/update-model-context` | view -> host | Overwrites model-visible context. |
| `ui/request-display-mode` | view -> host | `inline`/`fullscreen`/`pip`; host returns resulting mode. |
| `ui/open-link`, `ui/notifications/size-changed`, `ui/notifications/host-context-changed`, `ui/resource-teardown`, `ui/notifications/tool-cancelled` | various | Per spec. |

Handlers must check `event.source === window.parent` and `jsonrpc === "2.0"`.
Sources: spec (3.1), https://developers.openai.com/plugins/build/chatgpt-ui.md,
https://developers.openai.com/plugins/build/app-quickstart.md.

**`window.openai` (ChatGPT extension).** Names from the OpenAI reference; types
from OpenAI's `src/types.ts` in `openai-apps-sdk-examples` `main` (read
2026-10-29), which may lag the prose docs.

| Member | Shape |
|---|---|
| `toolInput` | `ToolInput` (default `UnknownObject`) — call arguments |
| `toolOutput` | `ToolOutput \| null` — your `structuredContent`; "the model reads it verbatim, so keep it concise" |
| `toolResponseMetadata` | `ToolResponseMetadata \| null` — widget-only; carries `status`, `call_tool_result`, `mcp_tool_result` (full envelope incl. hidden `_meta`) per the reference |
| `widgetState` | `WidgetState \| null` — persisted UI snapshot |
| `setWidgetState(state)` | prose docs: "stores a snapshot synchronously"; `types.ts`: `(state) => Promise<void>`. **Conflict between sources.** Structured form `{modelContent, privateContent, imageIds}` is shown for image UIs. |
| `callTool(name, args)` | `(name: string, args: Record<string, unknown>) => Promise<CallToolResponse>`; `types.ts`: `CallToolResponse = { result: string }`. The prose reference "does not specify the return shape". The MCP Apps `tools/call` returns `result.structuredContent`. |
| `sendFollowUpMessage({prompt, scrollToBottom?})` | `Promise<void>`; `scrollToBottom` defaults `true`. (Spelled `sendFollowUpMessage` in the reference and types; the MCPJam blog prose also writes `sendFollowupMessage`. **`sendFollowupTurn` found nowhere.**) |
| `requestDisplayMode({mode})` | `Promise<{mode}>`; host may change or reject; modes `"pip" \| "inline" \| "fullscreen"` |
| `requestModal(...)` (`types.ts`: `{title?, params?}` -> `Promise<unknown>`; reference: `{params, template}`), `requestClose()`, `notifyIntrinsicHeight(h)`, `openExternal({href, redirectUrl?})`, `setOpenInAppUrl({href})` | `types.ts` types `openExternal` as `{href}` returning `void`; the reference adds `redirectUrl` (ChatGPT appends `?redirectUrl=...` unless `false`). |
| `uploadFile`, `selectFiles`, `getFileDownloadUrl`, `requestCheckout` | file APIs; checkout is "private beta" |
| `theme` | `"light" \| "dark"` |
| `displayMode` | `"pip" \| "inline" \| "fullscreen"` |
| `maxHeight` | `number` |
| `safeArea` | `{ insets: {top, bottom, left, right: number} }` |
| `userAgent` | `{ device: {type: "mobile"\|"tablet"\|"desktop"\|"unknown"}, capabilities: {hover: boolean, touch: boolean} }` |
| `locale` | `string` (BCP 47); host mirrors it to `document.documentElement.lang` |
| `view?` | `{mode?: string, params?: object}` |

Global-change event: `openai:set_globals`, a `CustomEvent` whose `detail.globals`
is `Partial<OpenAiGlobals>` (`SET_GLOBALS_EVENT_TYPE = "openai:set_globals"` in
`types.ts`). Approval-gated tools may leave `toolInput` `null` until
`ui/notifications/tool-input` arrives.

Mapping to the standard bridge (from the MCP Apps migration page):
`theme/locale/displayMode/userAgent` -> `app.getHostContext()?.…`;
`maxHeight` -> `getHostContext()?.viewport?.maxHeight`;
`safeArea` -> `safeAreaInsets`; `toolOutput` -> `app.ontoolresult`
`params.structuredContent`; `toolResponseMetadata` -> `params._meta`;
`callTool` -> `app.callServerTool({name, arguments})`;
`sendFollowUpMessage` -> `app.sendMessage({role, content})`;
`widgetState/setWidgetState` -> **no equivalent** ("use localStorage or
server-side state"; but OpenAI says do not use `localStorage` for core state).
Source: https://apps.extensions.modelcontextprotocol.io/api/documents/Migrate_OpenAI_App.html.

Minimal widget skeleton against the standard bridge, adapted from the Claude
quickstart (host-neutral; the same code runs in Claude and ChatGPT per Claude's
"Register tools and resources once for every host"):

```html
<script type="module">
  import { App } from "@modelcontextprotocol/ext-apps";   // or inline the bundle
  const app = new App({ name: "aitm flows", version: "1.0.0" });
  app.ontoolresult = ({ structuredContent }) => render(structuredContent);
  await app.connect();            // handlers first, then connect
</script>
```

### 3.5 CSP and sandbox constraints

- ChatGPT: declare `connectDomains` (API requests), `resourceDomains` (scripts,
  styles, images, other assets), optional `frameDomains`. "Nested frames are
  blocked by default." "Keep allowlists narrow." "Plugin review checks declared
  policy against UI behavior." Embedding an editor/admin UI needs a
  registrable-domain match with the MCP server plus justification.
  Source: https://developers.openai.com/plugins/build/chatgpt-ui.md.
- MCP Apps spec: no `csp` means "restrictive default": deny by default, inline +
  self-hosted scripts/styles allowed, self and `data:` images/media allowed,
  network connections blocked; hosts "must not allow undeclared domains"; CSP
  must block `object-src`. Web hosts "must use a sandbox proxy on a different
  origin, with `allow-scripts` and `allow-same-origin`".
- The exact iframe `sandbox` attribute values used by ChatGPT are **not
  documented** in any OpenAI page I read.
- Claude: "All external origins are blocked by default"; `frameDomains` "is
  restricted in Claude pending security review"; on mobile Claude uses a native
  WebView, not an iframe.
  Source: https://claude.com/docs/connectors/building/mcp-apps/design-guidelines.
- Host-provided untrusted-input rule: OpenAI says "Treat `structuredContent` as
  untrusted input." For aitm this is load-bearing: flow bodies and headers are
  attacker-controlled, so widgets must write them with `textContent`, never
  `innerHTML` (candidate requirement, not a decision).
- Fonts: the MCP Apps default says self/`data:` "images and media"; fonts are not
  mentioned. Whether `data:` fonts load under the default is **unverified**.

### 3.6 `structuredContent` vs component data, and size limits

- ChatGPT: `structuredContent` -> `window.openai.toolOutput` and
  `ui/notifications/tool-result` `params.structuredContent`. It and `content`
  "appear in the transcript and reach the model". Result `_meta` goes "only to
  the component".
  Candidate use: keep `structuredContent` concise; put presentation-only bulk
  (colours, precomputed rows) in result `_meta`.
- MCP spec (2025-06-18, the revision aitm declares): `CallToolResult.structuredContent`
  is typed `{ [key: string]: unknown }` (an **object**) and `outputSchema.type`
  is `"object"`. The later revision (2026-07-28) allows "any JSON value" and an
  array `outputSchema`. Spec text, both: "a tool that returns structured content
  SHOULD also return the serialized JSON in a TextContent block".
  Sources: https://modelcontextprotocol.io/specification/2025-06-18/schema,
  https://modelcontextprotocol.io/specification/latest/server/tools.md.
  Repo fact: `flow.list` returns a top-level JSON **array** as
  `structuredContent` (crates/aitm-plugins/src/capture.rs `FlowList::invoke`
  returns `Value::Array`), so it is outside the 2025-06-18 type.
- ChatGPT result size limit: **none documented** (searched `llms-full.txt` first
  200k chars, reference, mcp-server, chatgpt-ui pages).
- Claude limits (documented):
  - claude.ai / Claude Desktop: when a result exceeds ~150,000 characters and the
    code-execution sandbox is active, Claude writes it to the sandbox filesystem
    and "your app receives a pointer to the stored file rather than the
    structured content" (so the widget never hydrates).
    https://claude.com/docs/connectors/building/mcp-apps/troubleshooting.md.
  - Claude Code: warns above 10,000 tokens; default cap 25,000 tokens
    (`MAX_MCP_OUTPUT_TOKENS`); successful text results over 50,000 characters are
    saved to a file; a tool may raise its own threshold with
    `_meta["anthropic/maxResultSizeChars"]` on its `tools/list` entry, "up to a
    hard ceiling of 500,000 characters"; HTTP/SSE responses over 16 MiB fail;
    error text over ~11,000 chars keeps first and last 5,000.
    https://code.claude.com/docs/en/mcp (read 2026-10-29).
  - Agent SDK (search-result summary only; page not opened): structuredContent
    over 1,048,576 JSON chars is left off `tool_use_result`
    (`structuredContentOmitted: true`).

### 3.7 Claude side: what is rendered, what is honoured, what is ignored

**Which surfaces render custom MCP UI**

| Surface | MCP Apps UI | Evidence |
|---|---|---|
| claude.ai (web), Claude Desktop | Yes | MCP overview: "currently supported by Claude, Claude Desktop, VS Code GitHub Copilot, Microsoft 365 Copilot, Goose, Postman, MCPJam, Archestra.AI". Claude docs: "interactive UI that your MCP server renders inside a Claude conversation". Claude asks permission: "Allow" / "Always allow". |
| Claude mobile | Yes (native WebView; connector must be added on web/desktop first) | Claude design guidelines |
| Claude Code (CLI) | **No** | Claude quickstart: "Claude Code calls the tool as text and doesn't render the UI." |
| Claude Desktop **Code tab** | Widget mounts but gets no `structuredContent` | GitHub issue anthropics/claude-code #103809, opened 2026-10-20, **open**, no maintainer comment on the page. Single-reporter claim; treat as unconfirmed. |

Sources: https://modelcontextprotocol.io/extensions/apps/overview,
https://claude.com/docs/connectors/building/mcp-apps/quickstart,
https://claude.com/docs/connectors/building/mcp-apps/getting-started,
https://github.com/anthropics/claude-code/issues/103809.

(The MCP client-matrix page rendered with empty cells in my fetch, so I did not
use it.)

**Which `_meta` hints Claude honours** (documented):

- `_meta.ui.resourceUri` (tool), and the helper also writes the legacy flat key
  `_meta["ui/resourceUri"]` (shown in Claude quickstart output).
- Resource `_meta.ui`: `csp` (`connectDomains`, `resourceDomains`,
  `baseUriDomains`; `frameDomains` restricted), `prefersBorder`, `domain`.
- `ui.domain` for Claude = first 32 hex chars of SHA-256 of the **full connector
  URL** + `.claudemcpcontent.com`. "The connector is a local stdio server: local
  connectors have no URL to hash, so `ui.domain` isn't available for them."
- Claude Code-specific tool `_meta`: `anthropic/maxResultSizeChars` (number),
  `anthropic/requiresUserInteraction` (JSON `true` only; forces the permission
  prompt every call), `anthropic/alwaysLoad` (bool; tool-search deferral).
  Source: https://code.claude.com/docs/en/mcp.
- Claude Code also trims server instructions and loaded-upfront tool
  descriptions at 4,096 chars, and tool-search-loaded descriptions at 16,384
  (override `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH`); with tool search on,
  "Only tool names and server instructions load at session start". Relevant to a
  ~70-tool server.
- Claude Code hides UI resources from its resource list: entries with a `ui://`
  URI or the `text/html;profile=mcp-app` media type "don't appear in the `@`
  suggestions or in the resource list tool's results"; reading by URI still works.

**No documented reading of `openai/*` keys by Claude.** None of the Claude docs
mention `openai/outputTemplate`, `openai/toolInvocation/*` or
`text/html+skybridge`. Absence of mention is not proof of ignoring.

**Are unknown `_meta` keys safely ignored?**

- The MCP spec says `_meta` "is reserved by MCP to allow clients and servers to
  attach additional metadata to their interactions" (2025-11-25 `basic/index`),
  and specifies key format: optional reverse-DNS prefix ending in `/`, then a
  name; prefixes whose second label is `modelcontextprotocol` or `mcp` are
  reserved. Schema: `Result` and `Tool` have `_meta?: { [key: string]: unknown }`,
  and `Result`/`CallToolResult` also carry `[key: string]: unknown`
  (2025-06-18 schema). Source: spec pages listed in Sources.
- **I found no sentence in the spec pages I read that says "clients MUST/SHOULD
  ignore unknown `_meta` keys".** The evidence is indirect: the open
  `unknown`-valued schema; extension negotiation text ("If one party supports an
  extension but the other does not, the supporting party MUST either revert to
  core protocol behavior or reject the request", 2026-07-28 versioning page); the
  MCP Apps rule "If a host doesn't support MCP Apps, the tool behaves as a
  standard, text-only tool"; and Claude's own statement that after adding
  `_meta.ui` and a `structuredContent` result "Claude Code still works with the
  server after these edits, as a text-only client".
- Key-format nit: `openai/toolInvocation/invoking` has a `/` inside the *name*
  segment, but the spec's name rule allows only alphanumerics, `-`, `_`, `.`. I
  found no client that rejects such keys; this is spec pedantry, not an observed
  failure. Flagged as unverified risk.
- aitm already ships a non-standard tool-descriptor field (`confirmable`,
  crates/aitm-mcp/src/schema.rs `McpTool::to_json`) without reported breakage
  in this repo (not independently tested here).

**Claude Code and `structuredContent` (critical for "clean output in Claude").**

- Claude's own quickstart: "because the tool now returns `structuredContent`, the
  `tool_result` Claude receives is that JSON object as a string ... rather than
  your `content` text." Source: https://claude.com/docs/connectors/building/mcp-apps/quickstart.
- Agent SDK docs (via search summary; page not opened): "When structuredContent
  is set, Claude receives the JSON plus any image or resource blocks from
  content." https://code.claude.com/docs/en/agent-sdk/custom-tools.
- GitHub issue anthropics/claude-code #103396 (opened 2026-10-19, **open**):
  with both present "Claude Code forwards only `structuredContent` to the model";
  regression since 2.0.21, observed through 2.1.299. The reporter cites an
  earlier issue (#9962) where a team member said preferring it was intentional;
  that quote is the reporter's account. Another commenter says the same drop
  occurs on claude.ai web via a custom connector, so the claim that claude.ai
  differs is **disputed**. A proposed `"toolResultPreference": "content"`
  `.mcp.json` setting appears only as a feature request; I found no evidence it
  exists. https://github.com/anthropics/claude-code/issues/103396.
- Issue #103809 describes the same replacement as "Claude Code replaces `content`
  with `JSON.stringify(structuredContent)`".
- Error results (`isError: true`): Claude Code docs say "Claude receives the
  result's text as the tool's error message" (https://code.claude.com/docs/en/mcp).
- Consequence for aitm's current server (crates/aitm-mcp/src/server.rs ~1381-1392,
  render.rs): the pretty-printed `content[0].text` and one-line summary are, per
  the above, not what Claude Code's model sees on success; it sees compact
  `structuredContent`. They remain visible to hosts that read `content`.

### 3.8 Claude Code plugin and marketplace format

Docs moved: `docs.claude.com` pages now live at `code.claude.com/docs/en/...` and
`claude.com/docs/...`. All below read 2026-10-29.

**`.claude-plugin/plugin.json`** (https://code.claude.com/docs/en/plugins-reference)

- The manifest is optional; without it, components load from the standard
  layout. **`name` is the only required key** (kebab-case; no spaces, `@`, `:`,
  path separators). Every component is namespaced under it (`/<plugin>:<skill>`).
- `claude plugin validate` warns on a non-kebab `name`, or missing `version`,
  `description`, `author`. Names starting `claude-`, `anthropic-`,
  `anthropics-`, `cc-plugin-` or equal to `claude`, `anthropic`, `claude-code`,
  etc. are errors; `aitmproxy` and `aitmproxy-plugin` are not affected.
- Fields: `$schema`, `name`, `displayName`, `version` (string, not checked as
  semver; setting it pins users to that version until changed), `description`,
  `author{name,email?,url?}`, `homepage` (must parse as URL), `repository`,
  `license`, `keywords`, `metadata`, directory-listing fields (`icon`,
  `documentationUrl`, `supportUrl`, `privacyPolicyUrl`, `termsOfServiceUrl`,
  ignored at load), `defaultEnabled`, `dependencies`, `settings`, `userConfig`,
  `channels`, and component keys `skills`, `commands`, `agents`, `hooks`,
  `mcpServers`, `lspServers`, `outputStyles`, `workflows`, `experimental.*`.
- Unknown top-level keys are stripped (plugin still loads; `validate` warns).
  Unknown keys inside `userConfig`/`channels`/`lspServers`/`monitors` entries are
  errors.
- Component paths: relative to plugin root, **must start with `./`**, must exist,
  must not contain `..`.
- Standard layout (defaults): `skills/<name>/SKILL.md`, `commands/*.md` ("Prefer
  `skills/` for new plugins"), `agents/*.md`, `hooks/hooks.json`, `.mcp.json`,
  `.lsp.json`, `output-styles/`, `bin/`, `settings.json`. Put everything except
  `plugin.json` outside `.claude-plugin/`. A `CLAUDE.md` at plugin root is **not
  loaded**.
- `skills` adds to the default `skills/`; `commands`/`agents` replace their
  default dirs when set; `hooks`/`mcpServers`/`lspServers` merge with defaults.

**MCP servers in a plugin** (same page, and https://code.claude.com/docs/en/mcp)

- Either `.mcp.json` at plugin root or inline `mcpServers` in `plugin.json`
  (value: `.json` path, `.mcpb`/`.dxt` bundle, inline map, or array). `.mcp.json`
  loads first, later same-named servers replace earlier. Servers start
  automatically when the plugin is enabled.
- stdio schema (from the docs' plugin example):

```json
{
  "mcpServers": {
    "aitmproxy": {
      "command": "${CLAUDE_PLUGIN_ROOT}/servers/db-server",
      "args": ["--config", "${CLAUDE_PLUGIN_ROOT}/config.json"],
      "env": { "DB_URL": "${DB_URL}" }
    }
  }
}
```

  (The key `aitmproxy` and the file name are placeholders; the shape is the
  documented one. Docs example uses `database-tools` and shows no `type` for
  stdio.)
- `type` values: `http` (alias `streamable-http`), `sse` (deprecated), `ws`,
  `stdio`; "An entry with a `url` but no `type` is treated as stdio and skipped
  with an error." Optional per-server `timeout` (ms). Expansion `${VAR}` and
  `${VAR:-default}` applies to `command`, `args`, `env`, `url`, `headers`; an
  unset variable with no default loads literally and warns.
- Path variables: `${CLAUDE_PLUGIN_ROOT}` (changes on update; do not write state
  there), `${CLAUDE_PLUGIN_DATA}` (`~/.claude/plugins/data/<id>/`, kept across
  updates), `${CLAUDE_PROJECT_DIR}`. Not present in Bash-tool commands.
- Tool name inside Claude Code: `mcp__plugin_<plugin-name>_<server-name>__<tool>`
  (characters outside `A-Za-z0-9_-` become `_`). Hook matchers must use the full
  name. Whole-name limit: a 128-character error exists (errors page link).
- `claude plugin validate` checks MCP entries (requires Claude Code v2.1.281+).
- `userConfig` values: `${user_config.KEY}` substitute in MCP config; sensitive
  values go to the platform credential store.

**`.claude-plugin/marketplace.json`**
(https://code.claude.com/docs/en/plugins/marketplace-reference.md)

- Path: `.claude-plugin/marketplace.json`; the directory containing
  `.claude-plugin/` is the marketplace root and relative `source`s resolve from
  it, not from `.claude-plugin/`.
- Required: `name` (letters, digits, `.`, `_`, `-`; start alnum; reserved names
  include `claude-code-marketplace`, `claude-plugins-official`,
  `anthropic-marketplace`, `inline`, `builtin`, `github`, `npm`, `claudeai-*`
  prefix, etc.), `owner{name, email?, url?}`, `plugins[]`.
- Optional: `$schema`, `description` (validate warns if missing), `version`,
  `metadata.description`, `metadata.version`, `metadata.pluginRoot`,
  `forceRemoveDeletedPlugins`, `allowCrossMarketplaceDependenciesOn`, `renames`.
- Plugin entry: required `name` (letters, digits, `.`, `_`, `-`) and `source`;
  optional `description`, `version`, `category`, `tags`, `strict` (default
  `true`), `relevance`, `dependencies`, `defaultEnabled`, `displayName`,
  `metadata`, plus any `plugin.json` field. Entry `mcpServers` only applies when
  the plugin has no `plugin.json`.
- `source`: relative path string starting `./` (no `..`; `"."` = root) or object
  with `source` = `github` (`repo`,`ref`,`sha`), `url`, `git-subdir`
  (`url`,`path`), `npm`, `archive` (`url`,`sha256`), `command`.
- **Keep the entry `name` equal to the manifest `name`**: install id is
  `<entry-name>@<marketplace>`; a mismatch yields `Plugin "<manifest-name>" not
  found in marketplace`.
- Minimal valid example (doc's, trimmed):

```json
{
  "name": "my-marketplace",
  "description": "Plugins for my team",
  "owner": { "name": "Your Name" },
  "plugins": [
    { "name": "my-first-plugin",
      "source": "./plugins/my-first-plugin",
      "description": "A greeting plugin to learn the basics" }
  ]
}
```

**Install locally** (https://code.claude.com/docs/en/plugins/create-marketplace.md,
https://code.claude.com/docs/en/plugins/install.md)

```text
claude plugin validate ./my-marketplace            # prints: Validation passed
claude plugin marketplace add ./my-marketplace     # or in-session: /plugin marketplace add ./my-marketplace
claude plugin install my-first-plugin@my-marketplace
claude plugin list
```

- In a session `/plugin install name@marketplace` opens the details panel to
  choose a scope (user / project / local); the shell form installs immediately
  (user scope default; `--scope project|local`).
- A relative path with a leading `./` or `../` is required for local paths
  ("Claude Code reads a bare `name/name` as a GitHub repository").
- With a local relative-path marketplace, edits to plugin files take effect "at
  the next session start or when you run `/reload-plugins`, with no change to the
  plugin's `version`". Hosted copies are cached and follow `version`.
- Non-interactive (`claude -p`): `/plugin` is unavailable; use `claude plugin ...`.
  One-session load without a marketplace: `--plugin-dir`.
- Added in the docs with version gates worth recording: marketplace add+install
  in one command needs v2.1.275/v2.1.292 (shell); `metadata.pluginRoot` v2.1.239;
  MCP validation v2.1.281.

**Cross-vendor packaging facts that bear on a single dual-target repo**

- OpenAI's "Agent Plugins" portable format: root `plugin.json` with `$schema`
  `https://agent-plugins.org/schemas/1.0.0/plugin.schema.json`, required
  `name`, `version`, `description`; `skills/<name>/SKILL.md` auto-discovered;
  optional root `mcp.json` (no leading dot) with `type` (e.g. `"streamable-http"`)
  and `url`, or for local servers `type: "stdio"`, `command`, `args`, `cwd`,
  placeholder `${PLUGIN_ROOT}` (Claude's is `${CLAUDE_PLUGIN_ROOT}`). OpenAI
  settings live under `extensions.com.openai` (`interface`, `onboardingSkill`,
  `apps`, `hooks`, `review`, `publication`). Legacy: `.codex-plugin/plugin.json`
  + `.mcp.json`. https://developers.openai.com/plugins/build/plugins.md (summary
  via fetch; JSON examples not quoted verbatim by the fetch tool).
- OpenAI marketplace file locations: `$REPO_ROOT/.agents/plugins/marketplace.json`,
  `~/.agents/plugins/marketplace.json`, and "Legacy-compatible:
  `$REPO_ROOT/.claude-plugin/marketplace.json`"; entry fields `name`, `source`
  (`local`/`url`/`git-subdir`/`npm`), `policy`, `category`. Local install via
  `codex plugin marketplace add ./local-marketplace-root`.
- OpenAI's own guide for Claude plugins
  (https://developers.openai.com/plugins/guides/submit-claude-plugin.md):
  `.claude-plugin/plugin.json` is converted to `.codex-plugin/plugin.json`;
  `commands/` and `agents/` "Convert to skills"; `.claude-plugin/marketplace.json`
  "Don't rely on it"; `.mcp.json`/`mcpServers` excluded from skills-only uploads
  ("In the remote path, submit the endpoint directly"); `hooks/` removed before
  public submission; `${user_config.*}` "Not run or expanded"; `.mcpb` not
  accepted; "Claude marketplace listings and approvals don't transfer".
- Common ground: both use `skills/<name>/SKILL.md` (agentskills.io standard).

### 3.9 Running and testing against ChatGPT; submission

**Current state of aitm's MCP server** (this worktree, commit 9d04a8e):

- `crates/aitm-mcp/Cargo.toml`: "stdio and loopback-TCP transports" only.
  `src/lib.rs`: newline-delimited JSON over stdio, or loopback TCP requiring a
  token. **No streamable HTTP.**
- `server.rs` `initialize` returns `protocolVersion: "2025-06-18"` (const at
  line 46), `capabilities: {"tools": {}}`, plus a non-standard top-level `role`.
  Handled methods: `initialize`, `ping`, `tools/list`, `tools/call`,
  `notifications/*`. **No `resources/*`.**
- `tools/list` entries: `{name, description, inputSchema, confirmable}`. No
  `title`, `annotations`, `outputSchema`, or `_meta`.
- Success result: `{content:[{type:"text",text}], structuredContent, isError:false}`
  (`server.rs` ~1388-1392); text is `render_content` (summary + pretty JSON).

**What ChatGPT needs**

- Transport: "The server must expose streamable HTTP, typically at `/mcp`." The
  OpenAI page does not mention SSE (older example code used `SSEServerTransport`).
  https://developers.openai.com/plugins/build/mcp-server.
- Add a server for development (https://developers.openai.com/plugins/deploy/connect-chatgpt.md):
  1. Optional: expose via public HTTPS ("a development tunnel ... can serve local
     testing") or Secure MCP Tunnel; confirm streamable HTTP at `/mcp`.
  2. Inspect: `npx @modelcontextprotocol/inspector@latest`, transport Streamable
     HTTP, URL e.g. `http://localhost:8787/mcp`.
  3. In ChatGPT: https://chatgpt.com/plugins -> plus -> "Add custom MCP server" ->
     name/description -> "Connection": public URL incl. `/mcp`, or "Tunnel" +
     `tunnel_id` -> configure auth, accept risk warning ("I understand and want to
     continue") -> "Create as a plugin" -> review tools.
  4. In a new conversation type `@` and pick the plugin. After server changes,
     "Refresh" the connection, then start a new conversation.
  5. ngrok: `ngrok http <port>`, add `https://<sub>.ngrok.app/mcp`
     (https://developers.openai.com/plugins/build/app-quickstart.md; the examples
     README adds `MCP_ALLOWED_HOSTS`/`MCP_ALLOWED_ORIGINS` for the Python SDK's
     DNS-rebinding protection).
- **Secure MCP Tunnel** (https://developers.openai.com/api/docs/guides/secure-mcp-tunnels):
  OpenAI-hosted endpoint plus a local `tunnel-client`; supports "a developer
  machine"; can wrap a stdio server directly:
  `tunnel-client init --sample sample_mcp_stdio_local --profile local-stdio --tunnel-id <id> --mcp-command "python /path/to/server.py"`
  then `tunnel-client run --profile local-stdio`. Limits: 600 MCP requests/min per
  tunnel and app, 10 MiB per serialized request/response, 120 s deadline, 1,000
  pending requests. "Does not support public plugin distribution." Needs a
  Platform API key and Tunnels Read/Manage/Use permissions; the tunnel must be
  associated with the ChatGPT workspace. OAuth server is not tunneled.
- **Developer-mode eligibility: sources conflict and I could not read the primary
  help article** (both help.openai.com URLs returned HTTP 403; the
  developers.openai.com developer-mode guide returned 404). A web search summary
  reports: OpenAI developer guide lists Pro, Plus, Business, Enterprise,
  Education (UI path Settings -> Apps -> Advanced settings -> Developer mode);
  the Help Center restricts full MCP write support to Business/Enterprise/Edu with
  admin/owner control; third-party notes dispute Plus. The UI labels have also
  been renamed repeatedly (connectors -> apps -> plugins). Treat as **unverified**.
- Auth: the add-server flow has an authentication step (I did not see its
  option list); the *submission portal* supports no-auth, OAuth, or mixed (see
  below). OpenAI says to use OAuth 2.1 "for user-authenticated plugins", and mTLS via OpenAI-managed proxy
  for private servers; server must "never rely on the model" for authorization.

**Public submission** (https://developers.openai.com/plugins/deploy/submission.md,
https://developers.openai.com/plugins/deploy/app-review,
https://developers.openai.com/plugins/deploy/desktop-only.md):

- Portal: https://platform.openai.com/plugins -> "Upload new or existing
  plugin". Needs organization Owner or "Apps Management Write", and individual or
  business identity verification (`api.apps.write`/`api.apps.read`).
- Package: ZIP. If it uses MCP, the MCP server must be in the **initial** ZIP.
  Manifest/listing: `name` (<= 64 chars, lowercase letters/numbers/single
  hyphens), `version` (semver), `description` (<= 4000), `displayName` and
  `shortDescription` (each <= 30), `longDescription` (<= 4000), `developerName`
  (<= 80), `category`, `capabilities`; `websiteURL`, `supportURL`,
  `privacyPolicyURL`, `termsOfServiceURL` all HTTPS and all required for an MCP
  plugin; `logo` and `composerIcon` square >= 48x48, PNG/JPEG/WebP/SVG <= 5 MiB.
  Formats: root `plugin.json` with `extensions.com.openai` (Agent Plugins) or
  `.codex-plugin/plugin.json`. ZIPs with `apps`/`.app.json` or lifecycle hooks
  "can't currently be submitted".
- MCP: one server per plugin; stable public HTTPS endpoint; "You are not using a
  local or testing endpoint". Domain verification: serve the portal's exact token
  as **plain text** at `https://<host>/.well-known/openai-apps-challenge`.
  Portal supports no auth, OAuth, mixed; **not** API-key/bearer; public
  submissions with nonempty server `headers` are rejected; OAuth client secret
  entered in the portal, not in `mcp.json`.
- Scan imports names, titles, descriptions, schemas, security schemes, `_meta`,
  annotations, linked UI resource metadata incl. CSP, and server `instructions`.
  Annotation justifications "don't override the annotations". If the server
  returns UI, "define a CSP that allows the exact domains the component fetches
  from"; provide screenshots only if there is UI.
- Review: five positive and three negative test cases (each with prompt,
  `tools_triggered`, `expected_behavior`), a reviewer-accessible video, release
  notes, a demo account without MFA. Rejection reasons include outputs with
  "extraneous information" or personal identifiers, undisclosed user data
  ("personal data, telemetry, internal IDs, timestamps, logs, or secrets"), and
  annotation mismatches. EU-data-residency projects cannot submit MCP plugins.
  Changing the MCP server origin requires a new plugin. OpenAI rescans daily;
  new tools stay unavailable until approved.
- **Local/stdio servers:** "Local MCP submissions are limited to approved
  partners" (allowlist via OpenAI representative); desktop-only plugins install
  only from the ChatGPT desktop app, are mentionable only in locally-run threads,
  declare `mcp.json` with `type: "stdio"`, `command`, `args`, `cwd`
  (`${PLUGIN_ROOT}`). The page does not say whether UI widgets render for local
  servers.

## 4. Candidate directions (for the Architect; none is a decision)

**A. Standards-first MCP Apps, one template per widget.**
Tool `_meta.ui.resourceUri` + resource `text/html;profile=mcp-app` + inline HTML
speaking the standard `App` bridge. Works per docs in ChatGPT and Claude
(claude.ai/Desktop/mobile); Claude Code falls back to text. Add
`openai/outputTemplate` and `openai/toolInvocation/*` only as ChatGPT extras.
Trade-offs: no `widgetState` on the standard path; ChatGPT-only keys add surface
area for review; depends on ChatGPT honoring `ui.resourceUri` (OpenAI documents
that it does).

**B. Also serve the legacy skybridge variant.** Register a second resource with
`text/html+skybridge` (cf. ext-apps PR #172's `+skybridge` URI suffix) for older
ChatGPT builds. Trade-offs: doubles resources and CSP/cache surface; no evidence
today that ChatGPT still needs it, and no evidence it is removed. Resolve with a
live test first (Open question 1).

**C. Capability-gated `_meta`.** Attach `ui` metadata only when the client's
`initialize` advertises `io.modelcontextprotocol/ui` with
`mimeTypes: ["text/html;profile=mcp-app"]` in `capabilities.extensions` (the
MCP Apps spec tells servers to check). Pro: text-only clients get a clean tool
list. Con: needs per-connection context in `ConnCtx` (aitm's `initialize` is
stateless today); unverified that ChatGPT and Claude send the capability; spec
2026-07-28 moves it to per-request `_meta`.

**D. Render-tool split vs. annotate-everything.** (i) Keep the ~70 existing tools
unchanged (no `_meta.ui`) and add a few new read-only render tools (the
design-inputs note already proposes a bulk flow summary) — matches OpenAI's
recommended "data tool / render tool" pattern; keeps most tools text-clean for
Claude Code; cost: the model must choose the render tool. (ii) Put
`_meta.ui.resourceUri` on existing tools — widgets on every call; cost: more
review surface, UI for tools that return arrays/scalars.

**E. Claude Code output quality given `structuredContent` wins.** Options:
(i) leave as is (Claude Code model sees compact JSON; summary text lost);
(ii) additively include the one-line summary inside `structuredContent`
(e.g. a `summary` field) — keeps old fields byte-identical but changes the
"exact machine value" the repo contract describes; (iii) wrap array results in
objects (`flow.list` -> `{ids:[...]}`) to satisfy 2025-06-18 `structuredContent`
typing and ChatGPT `toolOutput` — a breaking shape change for web/tui/mac
consumers; (iv) declare `outputSchema` per tool (ChatGPT requires it for
`structuredContent` tools; Claude Code only if clients validate). Each trades
contract stability against rendering quality. The "do not change existing
shapes" constraint in `plugin-design-inputs.md` conflicts with (ii)/(iii) and
should be a deliberate Architect call.

**F. ChatGPT connectivity.** (i) Add a streamable-HTTP transport to `aitm-mcp`
(auth, DNS-rebinding/Origin checks, public HTTPS in front) — required for
public submission, and the biggest change; exposes a proxy control plane over the
network, so threat-model it. (ii) Dev/test only: Secure MCP Tunnel with
`--mcp-command` wrapping the existing stdio server — no Rust transport change,
private, but not for public distribution and still needs `resources/*`,
`outputSchema`, annotations. (iii) Desktop-only plugin (local stdio `mcp.json`) —
requires OpenAI partner allowlisting; widget rendering for local servers is
undocumented. A MITM tool returning captured traffic also collides with review
rules on "extraneous information"/personal identifiers.

**G. One repo, two manifests.** Claude layout (`.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json`, `.mcp.json`, `skills/`, optional
`commands/`) plus an OpenAI Agent-Plugins manifest (root `plugin.json` with
`extensions.com.openai`, `mcp.json`, shared `skills/`). Shared: `skills/<name>/SKILL.md`.
Differences to manage: `.mcp.json` vs `mcp.json`, `${CLAUDE_PLUGIN_ROOT}` vs
`${PLUGIN_ROOT}`, manifest location, `commands/` (Claude-only; OpenAI converts
to skills), hooks not accepted by OpenAI public submission. The Claude marketplace
path also happens to be an OpenAI "legacy-compatible" marketplace location.

## 5. Open questions (could not answer from sources)

1. Does ChatGPT currently accept `text/html+skybridge`, and does it *require*
   `text/html;profile=mcp-app`? Official docs show only the latter; none state
   the former's fate. Needs a live test.
2. Does ChatGPT advertise `io.modelcontextprotocol/ui` in `initialize`
   capabilities? Does Claude Desktop / claude.ai? Does Claude Code? (Needed for
   direction C.) No source read states it.
3. Maximum HTML resource size and maximum `structuredContent` size in ChatGPT:
   undocumented in every OpenAI page read (the 480k-char `llms-full.txt` was read
   only to ~200k chars).
4. ChatGPT iframe `sandbox` attribute values: undocumented.
5. Meaning of `openai/resultCanProduceWidget`: undocumented officially.
6. `setWidgetState` sync vs async, and `callTool` return shape: OpenAI prose and
   `types.ts` disagree/are silent. `sendFollowupTurn` not found.
7. Developer-mode plan eligibility and exact current menu path: primary help
   article returned 403; the developer guide 404.
8. Whether any client rejects `_meta` keys with `/` in the name segment
   (`openai/toolInvocation/invoking`), and whether any client rejects unknown
   `_meta` at all (none observed).
9. Claude Code's `structuredContent` precedence: documented in Claude's
   quickstart and corroborated by open issues, but no maintainer statement on
   whether it is stable; `toolResultPreference` is unconfirmed.
10. Whether Claude Desktop renders MCP Apps for a custom *stdio* server: Claude's
    docs show example stdio servers running in Claude Desktop (via
    `claude_desktop_config.json`) and also state `ui.domain` is unavailable for
    stdio. A custom stdio UI server was not tested.
11. Whether `data:` fonts load under the MCP Apps default CSP.
12. Whether widgets render for local (desktop-only) servers in the ChatGPT
    desktop app.
13. aitm-side: what `ConnCtx` can know about the client at `tools/list` time
    (relevant to direction C) — not researched.

## 6. Sources

OpenAI (all read 2026-10-29):
- https://developers.openai.com/plugins (doc index)
- https://developers.openai.com/plugins/reference (`_meta` tables, `window.openai`)
- https://developers.openai.com/plugins/build/mcp-server (+ `.md`)
- https://developers.openai.com/plugins/build/chatgpt-ui (+ `.md`)
- https://developers.openai.com/plugins/build/app-quickstart.md
- https://developers.openai.com/plugins/build/plugins.md (package format; via fetch summary)
- https://developers.openai.com/plugins/deploy/connect-chatgpt.md
- https://developers.openai.com/plugins/deploy/submission.md and
  https://developers.openai.com/apps-sdk/deploy/submission
- https://developers.openai.com/plugins/deploy/app-review
- https://developers.openai.com/plugins/deploy/desktop-only.md
- https://developers.openai.com/plugins/guides/submit-claude-plugin.md
- https://developers.openai.com/plugins/llms-full.txt (first ~200k of 480k chars)
- https://developers.openai.com/apps-sdk/mcp-apps-in-chatgpt
- https://developers.openai.com/apps-sdk/reference and `/apps-sdk/build/mcp-server`,
  `/apps-sdk/build/chatgpt-ui` (earlier fetches of the redirected pages)
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- https://github.com/openai/openai-apps-sdk-examples (README, `pizzaz_server_python/main.py`,
  `kitchen_sink_server_node/src/server.ts`, `src/types.ts`, issue #90)
- Not readable: https://help.openai.com/en/articles/12584461-... (403),
  https://developers.openai.com/api/docs/guides/developer-mode (404),
  developers.openai.com/plugins/build/package (404), web.archive.org (blocked),
  `curl` to developers.openai.com (sandbox denied; WebFetch used instead).

MCP:
- https://modelcontextprotocol.io/extensions/apps/overview
- https://raw.githubusercontent.com/modelcontextprotocol/ext-apps/main/specification/2026-01-26/apps.mdx
- https://github.com/modelcontextprotocol/ext-apps/blob/main/src/server/index.ts
- https://github.com/modelcontextprotocol/ext-apps/pull/172 (draft, OpenAI compat)
- https://apps.extensions.modelcontextprotocol.io/api/documents/Migrate_OpenAI_App.html
- https://modelcontextprotocol.io/extensions/client-matrix.md (cells empty in fetch; unused)
- https://modelcontextprotocol.io/specification/latest/basic/index.md (revision 2026-07-28)
- https://modelcontextprotocol.io/specification/latest/basic/versioning.md
- https://modelcontextprotocol.io/specification/latest/server/tools.md
- https://modelcontextprotocol.io/specification/2025-11-25/basic/index.md
- https://modelcontextprotocol.io/specification/2025-06-18/schema

Anthropic / Claude:
- https://claude.com/docs/connectors/building/mcp-apps/quickstart
- https://claude.com/docs/connectors/building/mcp-apps/getting-started
- https://claude.com/docs/connectors/building/mcp-apps/design-guidelines
- https://claude.com/docs/connectors/building/mcp-apps/troubleshooting.md
- https://code.claude.com/docs/en/mcp (first 100k chars via summary, remainder
  from saved text)
- https://code.claude.com/docs/en/plugins-reference
- https://code.claude.com/docs/en/plugin-marketplaces and
  https://code.claude.com/docs/en/plugins/marketplace-reference.md
- https://code.claude.com/docs/en/plugins/install.md
- https://code.claude.com/docs/en/agent-sdk/custom-tools (search summary only)
- https://github.com/anthropics/claude-code/issues/103396 and /103809

Repo files read:
- crates/aitm-mcp/src/server.rs (lines ~46, 1163-1200, 1365-1400),
  crates/aitm-mcp/src/schema.rs, crates/aitm-mcp/src/render.rs,
  crates/aitm-mcp/Cargo.toml, crates/aitm-mcp/src/lib.rs,
  crates/aitm-plugins/src/capture.rs (`FlowList`),
  docs/research/plugin-design-inputs.md, docs/research/mcp-tool-catalog.txt (head)

Search-result-only claims (not opened, flagged inline): Vercel template / xmcp /
Handbook use of `openai/resultCanProduceWidget`; Agent SDK `structuredContent`
behaviour and 1,048,576-char cutoff; Claude Code `isError` handling per issue
#86032; developer-mode plan eligibility.
