# aitmproxy

A Rust intercepting-proxy platform for **authorized security testing**. aitmproxy
captures HTTP and WebSocket traffic that flows through it, lets you park and edit
live requests and responses, replay or craft requests through a guarded client,
and turn a finding into a reproducible proof-of-concept. It is built to be driven
by an AI agent over MCP as well as by a human operator through its UIs.

> **Authorized engagements only.** The active tools send real traffic and are
> scope-gated. Operate aitmproxy solely against targets covered by a written
> engagement you are authorized to test.

## Repository layout

A Cargo workspace of focused crates under `crates/`, plus operator UIs under
`apps/` and the MCP plugin package at the root:

- **Core & proxy** — `aitm-core` (config, flow store, proxy engine), the protocol
  crates `aitm-proto-http`, `aitm-proto-ws`, `aitm-proto-l4`, `aitm-proto-test`,
  and `aitm-rules` / `aitm-ca` (CA and TLS).
- **Plugins & scripting** — `aitm-plugin`, `aitm-plugins`, and the plugin crates
  `aitm-plugin-rhai`, `aitm-plugin-maprules`, `aitm-plugin-passthrough`,
  `aitm-plugin-wsctl`, `aitm-plugin-sessionio`.
- **Findings & PoC** — `aitm-poc`, `aitm-findings`.
- **MCP server** — `aitm-mcp` (the tool registry, the MCP Apps widgets, and the
  stdio / loopback-TCP / streamable-HTTP transports).
- **Binary & UIs** — `aitm` (the `aitm` binary), `aitm-cli`, `aitm-tui`,
  `aitm-browser`, `aitm-bus-client`, `aitm-testtarget`. The macOS and web
  operator UIs live under `apps/mac` and `apps/web`.

## Build

```bash
cargo build                                        # whole workspace
cargo build --release                              # release binary
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The release binary is `target/release/aitm`. Put it on your `PATH` (or
`cargo install --path crates/aitm`). Bare **`aitm`** serves the **stdio MCP**
server and starts the intercepting proxy on `127.0.0.1:8080`.

## MCP server and the plugin

aitmproxy exposes its whole workflow — scope, capture, intercept/mutate, replay,
findings/PoC — over MCP (`crates/aitm-mcp`). The **[`aitmproxy-plugin/`](aitmproxy-plugin/)**
package wires that server into AI hosts: rich MCP Apps widgets in ChatGPT and
Claude Desktop / claude.ai, and clean text in Claude Code. Start at
[`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md); the transport threat
model is in [`aitmproxy-plugin/docs/security.md`](aitmproxy-plugin/docs/security.md).

## Documentation

Project research, design and process live in [`docs/`](docs/) — start with
`docs/research/05-synthesis.md` and `docs/research/MEMORY.md` for durable project
facts, and `docs/design/` for the operator-UI design tokens. Contributor workflow
and conventions are in [`CLAUDE.md`](CLAUDE.md).
