# aitmproxy-plugin — design inputs (for the architect)

Grounding gathered from the current tree for the spec of a marketplace plugin
("aitmproxy-plugin") that works for BOTH Claude and ChatGPT, drives the existing
MCP server, and renders output nicely. Matt authorized improving the MCP output.

## Sources in this worktree
- `docs/research/mcp-tool-catalog.txt` — the full `aitm --help`: every MCP tool
  (dot-form name on the wire, space-form in the CLI), its description and params.
- `docs/research/palette-dump.txt` — color + font tokens from `docs/design/tokens.json`
  (the single source of truth; web CSS + mac Tokens.swift are generated from it).
- `docs/research/08-chatgpt-apps-sdk.md` — the Apps SDK + MCP `_meta` contract
  (produced by the researcher).

## Current MCP server shape (crates/aitm-mcp/src/server.rs)
- JSON-RPC methods handled: `initialize`, `ping`, `tools/list`, `tools/call`.
  `initialize` advertises capabilities `{"tools": {}}` only (server.rs ~1171).
  There is NO `resources/*` handler today.
- `tools/list` (server.rs ~1176): each registered command → `StdSchemaDerive.to_mcp_tool(cmd).to_json()`
  (crates/aitm-mcp/src/schema.rs). Tool JSON = {name, description, inputSchema, confirmable}.
  No `_meta`.
- `tools/call` success (server.rs ~1386): result = {content:[{type:"text",text}], structuredContent, isError:false}.
  `structuredContent` is the exact machine value; `content[0].text` is a readable
  render (crates/aitm-mcp/src/render.rs: optional one-line summary + pretty JSON).
  No `_meta`.
- Transport default: stdio, no token, role = Mcp (crates/aitm-core/src/config.rs:316).
  So a plugin wires `aitm` as a stdio MCP server with no auth. (The other transport
  is loopback-TCP with a token.)

## Where the MCP improvements plug in (for ChatGPT Apps SDK widgets)
1. `initialize` capabilities: add `"resources": {}`.
2. Add `resources/list` + `resources/read` returning the widget HTML templates
   (mimeType per Apps SDK; `ui://aitm/<widget>` URIs). Templates inline their JS/CSS;
   CSS colors come from tokens.json (both light/dark).
3. `tools/list`: attach per-tool `_meta` (e.g. `openai/outputTemplate`, invocation
   strings, widgetAccessible) for the tools that have a widget.
4. `tools/call` result: optionally attach result `_meta` (outputTemplate, widget
   state). `structuredContent` already carries the data the widget renders.
   MCP `_meta` is reserved/extensible; non-OpenAI clients (Claude) ignore unknown
   keys — confirm in 08-*.md — so this must NOT change existing text/structuredContent.

## Table-output gap (decision for the spec)
The mock shows a one-shot flows table (method, url, status, duration). But
`flow.list` returns IDS ONLY; `flow.get` summarizes one; `flow.detail` is full.
Rendering a table today = N+1 calls. Options:
  (a) Add a bulk summary — a new read-only tool (e.g. `flow.table`/`flow.summaries`)
      or an optional `detail=summary` mode on `flow.list` — returning per-flow
      {id, method, authority/url, status, duration_ms, state, marks}. Prefer a NEW
      tool or an additive optional field so web/tui/mac consumers are untouched.
  (b) Skill-only: instruct the agent to list then detail each (slow, chatty).
Recommend (a): one additive read-only summary tool, which both the ChatGPT flows
widget and the Claude rendering skill consume.

## Proposed widget families (ChatGPT) / render templates (Claude skill)
Map tool output → one visual. Colors from palette groups in parentheses.
- Flows table        ← bulk flow summary (color.method.*, color.status.*)
- Request/flow detail← flow.detail (color.method.*, color.status.*, color.syntax.* for headers/body)
- Findings list      ← findings.list (color.severity.*)
- Finding detail     ← findings.get (color.severity.*)
- Scope              ← scope.list, tls.passthrough.list (color.accent.*)
- PoC result         ← poc.run / poc.get (color.severity.*, color.status.*)
- Proxy status       ← proxy.status (color.status.*, color.intercept.*, color.agent.*)
Agent-side text transforms (commands/skills, not widgets): Explain Request,
Generate cURL, Create Map Remote — mirror the mock's tabs.

## Claude plugin package (docs.claude.com — confirm in 08-*.md)
Layout under a new top-level dir `aitmproxy-plugin/`:
- `.claude-plugin/marketplace.json` → plugins: [{name:"aitmproxy", source:"./plugins/aitmproxy"}]
- `plugins/aitmproxy/.claude-plugin/plugin.json` (name, version, description, author, skills path)
- `plugins/aitmproxy/.mcp.json` — wire `aitm` over stdio (command configurable via env; default on PATH)
- `skills/` — overview (how to drive the MCP: scope → capture → intercept/mutate →
  replay → findings/poc; authorized-testing framing), rendering (structuredContent →
  markdown tables + method/status/severity badges mapped to palette), plus focused
  per-domain references.
- `commands/` — fetch-flows, explain-request, generate-curl, map-remote, triage,
  intercept, scope, findings.
Install/test locally: `/plugin marketplace add ./aitmproxy-plugin` then `/plugin install aitmproxy`.

## Hard constraints
- Do NOT change existing `content`/`structuredContent` shapes or tool names
  (web/tui/mac/CLI all consume them). ChatGPT support is ADDITIVE `_meta` + resources.
- Rust gate applies to any server change: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- Authorized-security-testing framing in all user-facing skill/command text.
