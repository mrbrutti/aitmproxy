# Install and test

How to install the aitmproxy plugin in each of its three hosts and confirm it
works. Everything here assumes an **authorized** engagement: the active tools
send real traffic and are scope-gated.

## Prerequisite — `aitm` on PATH

Every host launches the proxy's own binary as the MCP server, so `aitm` must be
on your `PATH` first:

```bash
cargo build --release          # from the repo root
cargo install --path crates/aitm   # or copy target/release/aitm onto PATH
aitm --version
```

Bare **`aitm`** (no subcommand) serves the **stdio MCP** server and is the
default transport. The same invocation also starts the intercepting proxy on
`127.0.0.1:8080`.

---

## 1. Claude Code (stdio, text rendering)

```
/plugin marketplace add ./aitmproxy-plugin
/plugin install aitmproxy
```

The first command registers the local marketplace (`.claude-plugin/marketplace.json`,
named `aitmproxy`); the second installs the plugin from it. Claude Code speaks to
`aitm` over **stdio** (`.mcp.json`).

Claude Code draws **no widgets** — on a successful call it receives the tool's
`structuredContent`. The bundled `aitmproxy-rendering` skill turns that into
markdown tables with method / status / severity badges. See
[`rendering.md`](rendering.md).

Validate the package before installing:

```bash
claude plugin validate ./aitmproxy-plugin
```

Quick test: ask Claude Code to call `proxy.status`, then `flow.table`. You should
get a one-line status and a flow table, not raw JSON.

---

## 2. Claude Desktop / claude.ai (stdio, widgets render)

Add the stdio MCP server so the host launches `aitm`. In
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aitmproxy": {
      "command": "aitm",
      "args": [],
      "env": {}
    }
  }
}
```

Restart the host. On a successful tool call the **MCP Apps widgets** render — the
flow table, flow detail, findings, scope, PoC result and proxy status, coloured
from the design tokens. See [`rendering.md`](rendering.md).

Quick test: ask for the flow table; you should see the interactive flows widget.

---

## 3. ChatGPT (developer mode)

ChatGPT has two paths: a local path for development and a hosted path for a real
or submittable connector.

### Local test — Secure MCP Tunnel over stdio

Use OpenAI's **Secure MCP Tunnel** to wrap the local stdio `aitm` command and
expose it to ChatGPT developer mode. This keeps the committed default transport
(stdio) and needs no HTTP listener. Point the tunnel at the `aitm` command (no
subcommand) and add the resulting server in ChatGPT developer mode.

### Real / submittable endpoint — streamable-HTTP transport

For a stable endpoint (a hosted connector or submission) run aitmproxy's
**streamable-HTTP** transport instead of stdio. Enable it in the aitmproxy
config:

```toml
transport = { streamable_http = { bind = "127.0.0.1:8084", token = "<bearer>", allowed_origins = [], path = "/mcp" } }
```

Defaults: `bind` = `127.0.0.1:8084`, `path` = `/mcp`, `allowed_origins` = empty
(no cross-origin). **`token` is required** and non-empty — it is the Bearer
credential on every request, and the only authentication the endpoint has. The
endpoint is then `http://127.0.0.1:8084/mcp`.

> stdio (bare `aitm`) remains the **default** transport. The streamable-HTTP
> listener is opt-in and only runs when this config block is present.

Steps:

1. Start `aitm` with the config above. The startup line on **stderr** reads
   `MCP streamable HTTP listening on 127.0.0.1:8084/mcp` (the token is never
   logged).
2. Verify with the **MCP Inspector** against `http://127.0.0.1:8084/mcp`, sending
   `Authorization: Bearer <token>`. You should complete `initialize` and list the
   tools.
3. In ChatGPT (developer mode), **add the server** at `chatgpt.com` using the
   endpoint URL and the Bearer token.

The endpoint binds **loopback only** by default, has **no in-process TLS**, and
exposes a MITM proxy control plane. Before binding anything other than loopback,
read [`security.md`](security.md) — a non-loopback bind must be fronted by a
tunnel or HTTPS and signed off by a security reviewer.

## Targeting a specific `aitm` build (connecting the MCP)

The plugin's Claude MCP server runs `${AITM_BIN:-aitm}`: by default it launches
`aitm` from your `PATH`, but you can point it at any build without editing the
plugin by setting the `AITM_BIN` environment variable before starting the client:

```bash
export AITM_BIN=/absolute/path/to/aitm   # e.g. a dev build: target/debug/aitm
```

Claude expands `${VAR:-default}` in `.mcp.json`, so an unset `AITM_BIN` falls
back to `aitm` on `PATH`. Use this when the released `aitm` (Homebrew tap
`mrbrutti/homebrew-aitmproxy`) predates a feature you need, or to test a local
build. Confirm the build has the plugin's MCP surface with:

```bash
aitm --help   # the output lists `flow table` when the build includes it
```

The OpenAI `mcp.json` uses a bare `aitm` command (OpenAI does not document
`${VAR:-default}` expansion); there, put the desired `aitm` first on `PATH`.
