# Install and test

How to install the aitmproxy plugin in each of its three hosts and confirm it
works. Everything here assumes an **authorized** engagement: the active tools
send real traffic and are scope-gated.

## Prerequisite — `aitm` on PATH

Every host launches the proxy's own binary as the MCP server, so `aitm` must be
on your `PATH` first:

```bash
brew tap mrbrutti/aitmproxy && brew install aitm   # Apple Silicon macOS; public tap, no token
# or from source, at the repo root:
cargo build --release
cargo install --path crates/aitm   # or copy target/release/aitm onto PATH
```

On Linux use the `.deb` / `.rpm` from the release page (see the repo's
`INSTALL.md`). Check that `aitm` resolves with `aitm config get`, a one-shot
command that prints the redacted config. (There is no `aitm --version`.)

Bare **`aitm`** (no subcommand) serves the **stdio MCP** server and is the
default transport; there is no `aitm mcp` subcommand. The same invocation also
starts the intercepting proxy on `127.0.0.1:8080`.

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
config file, `config.yaml` (macOS: `~/Library/Application Support/aitmproxy/config.yaml`;
Linux: `~/.config/aitmproxy/config.yaml`; or pass `--config <path>` / set
`AITM_CONFIG`):

```yaml
mcp:
  transport:
    streamable_http:
      bind: 127.0.0.1:8084
      token: "<bearer>"
      # allowed_origins: []     # optional; exact Origin allowlist
      # path: /mcp              # optional; the default
```

`bind` and `token` are required. `allowed_origins` defaults to empty (no
cross-origin requests) and `path` to `/mcp`. **`token` must be non-empty** — it is
the Bearer credential on every request, and the only authentication the endpoint
has. With the block above the endpoint is `http://127.0.0.1:8084/mcp`.

> stdio (bare `aitm`) remains the **default** transport. The streamable-HTTP
> listener is opt-in and only runs when this block is present; the config selects
> exactly one MCP transport, so with it set the MCP server speaks HTTP, not stdio.

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
build. `aitm --help` is not a real flag — the CLI answers
`expected a command before flags` — but it prints its command listing to stderr,
which is how to confirm a build has the plugin's MCP surface:

```bash
aitm --help 2>&1 | grep 'flow table'   # present when the build includes flow.table
```

The OpenAI `mcp.json` uses a bare `aitm` command (OpenAI does not document
`${VAR:-default}` expansion); there, put the desired `aitm` first on `PATH`.
