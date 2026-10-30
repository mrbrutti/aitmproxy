# aitmproxy plugin

A plugin that drives **aitmproxy** — a Rust intercepting proxy for **authorized
security testing** — over MCP. Point it at traffic you are authorized to test,
then capture, inspect, intercept and mutate, replay or craft requests, and turn a
finding into a reproducible proof-of-concept, all from your AI host.

The same MCP server backs every host; only the presentation differs:

- **ChatGPT** and **Claude Desktop / claude.ai** render the rich **MCP Apps
  widgets** (the flow table, flow detail, findings, scope, PoC result and proxy
  status), coloured from the shared design tokens.
- **Claude Code** is text-only — it sees each tool's `structuredContent` and the
  bundled `aitmproxy-rendering` skill turns that into clean markdown tables with
  method / status / severity badges. No widget is drawn there, and none is needed.

> **Authorized engagements only.** Active tools (`flow.replay`, `request.send`,
> `ws.send`, `poc.run`, `scan.discover`, `browser.*`) send real traffic and are
> scope-gated. Operate only
> against targets covered by a written engagement you are authorized to test.

## Package layout

One directory, two manifests — one tree of shared skills and commands:

```
aitmproxy-plugin/
  .claude-plugin/
    plugin.json          # Claude plugin manifest
    marketplace.json     # Claude marketplace entry (name == plugin name)
  .mcp.json              # Claude: wire `aitm` over stdio
  plugin.json            # OpenAI Agent-Plugins manifest (extensions.com.openai)
  mcp.json               # OpenAI: stdio transport (+ documented HTTP swap)
  skills/                # shared across both hosts
    aitmproxy-overview/        # the whole workflow; OpenAI onboardingSkill
    aitmproxy-rendering/       # text-host rendering (Claude Code)
    aitmproxy-flows-triage/
    aitmproxy-intercept-mutate/
    aitmproxy-findings-poc/
  commands/              # Claude slash commands (agent-side prompts)
    fetch-flows.md  explain-request.md  generate-curl.md  map-remote.md
    triage.md  scope.md  findings.md  intercept.md
  docs/
    install.md           # per-host install + test
    rendering.md         # palette + widget-family guide
    security.md          # streamable-HTTP transport threat model
    tool-reference.md    # generated tool catalog
```

The Claude manifest lives under `.claude-plugin/`; the OpenAI manifest is the
root `plugin.json` / `mcp.json`. Both point at the **same** `skills/` tree.
`commands/` is Claude-only (OpenAI hosts drive the same actions through skills).

## Prerequisite: `aitm` on PATH

The plugin launches the proxy's own binary as its MCP server. Install `aitm` so
it is on your `PATH`:

```bash
brew tap mrbrutti/aitmproxy && brew install aitm   # Apple Silicon macOS; public tap, no token
# or build from source (repo root), then put target/release/aitm on PATH
# (or `cargo install --path crates/aitm`):
cargo build --release
```

Linux users install the `.deb` / `.rpm` from the release page; see the repo's
`INSTALL.md`. To check it is on `PATH`, run `aitm config get` (a one-shot command
that prints the redacted config; there is no `aitm --version`).

Bare **`aitm`** serves the **stdio MCP** server (this is the default transport;
there is no `aitm mcp` subcommand). The same invocation also starts the
intercepting proxy listening on `127.0.0.1:8080`. Both manifests launch `aitm`
with no subcommand.

## Quick install and test

- **Claude Code** — `/plugin marketplace add ./aitmproxy-plugin` then
  `/plugin install aitmproxy`. Output renders as text via the
  `aitmproxy-rendering` skill.
- **Claude Desktop / claude.ai** — add the stdio MCP server (command `aitm`);
  the widgets render.
- **ChatGPT** (developer mode) — for local testing wrap the stdio `aitm` command
  in OpenAI's Secure MCP Tunnel; for a real/submittable endpoint run the
  streamable-HTTP transport (opt-in in `config.yaml`; the endpoint is then
  `http://127.0.0.1:8084/mcp`).

Full step-by-step for all three hosts, including the HTTP config snippet, is in
[`docs/install.md`](docs/install.md). Validate the Claude package with
`claude plugin validate ./aitmproxy-plugin`.

## Read next

- [`docs/install.md`](docs/install.md) — per-host install and test.
- [`docs/rendering.md`](docs/rendering.md) — how output renders (widgets + text).
- [`docs/security.md`](docs/security.md) — the HTTP-transport threat model. Read
  this before exposing the server beyond loopback.
- [`docs/tool-reference.md`](docs/tool-reference.md) — the full tool catalog.
