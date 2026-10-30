# aitmproxy

A Rust, high-performance, memory-safe **intercepting-proxy platform for
authorized security testing**. A thin pluggable core (mitmproxy-style) carries a
declarative vulnerability check/reproduction engine (nuclei-style), an embedded
headless browser with a computer-use driver (Playwright/CUA-style), and an
**MCP interface so an AI agent can drive 100% of the tool** — the same commands a
human operator runs. HTTP/1.1 and HTTP/2, WebSocket, and raw **L4 (TCP/UDP)
packet** interception are all live.

> **Authorized engagements only.** aitmproxy is deny-by-default and strictly
> scope-bound — it will not touch a host you have not explicitly put in scope —
> and its active tools send real traffic. Operate it solely against targets
> covered by a written engagement you are authorized to test.

See [INSTALL.md](INSTALL.md) to install, or [Build](#build) below.

---

## What it does

- **Intercept, inspect, and modify live traffic** — HTTP/1.1, HTTP/2,
  WebSocket, and raw L4 (TCP/UDP) flows, through one uniform flow model with
  intercept / resume / kill / mutate / replay.
- **Man-in-the-middle TLS** with an on-the-fly CA. Export, inspect, install, and
  uninstall the CA from the CLI or an agent (`ca.*`).
- **Drive an embedded browser** — the bundled [obscura](#the-obscura-browser)
  engine proxies through aitmproxy with the CA already trusted; navigate, click,
  type, screenshot, read the DOM, and eval over a CDP-backed driver
  (`browser.*`), with an optional [scope-confined egress mode](#the-obscura-browser).
- **Script the proxy** in [Rhai](#scripting) — rewrite requests and responses,
  drive flows, and write PoCs, all behind a deny-by-default capability sandbox.
  Rhai *and* PoC YAML are written to be human-readable, not agent-only.
- **Build and run reproducible checks** — the nuclei-style
  [PoC / check engine](#poc--check-engine) turns a captured flow into a
  declarative PoC (YAML), runs it, and records **findings** (`poc.*`,
  `findings.*`).
- **Discover the attack surface automatically** — the deterministic
  [automated scanner](docs/scanner.md) crawls an in-scope target and discovers
  injection points (`scan.discover`), augmenting an AI operator's own free-form
  detection.
- **Three UIs over one core** — a [web UI](#user-interfaces), a terminal UI, and
  a native macOS app. Each is just a client of the core; none of them *is* the
  core.
- **Everything over MCP** — every operator command is auto-exposed as an MCP
  tool, so an AI agent can run the whole platform. The
  [`aitmproxy-plugin/`](#mcp-server-and-the-plugin) package wires that into AI
  hosts with rich MCP Apps widgets.

## Architecture

aitmproxy follows one spine throughout: **a thin core, and everything else is a
plugin or a client.**

- **Thin core (`aitm-core`).** Accepts connections, runs sans-IO protocol state
  machines, holds the flow store, and emits typed events to an ordered plugin
  chain with halt/short-circuit semantics. It also owns the deny-by-default
  **scope + rate guard** every action passes through.
- **Protocol modules are plugins.** `aitm-proto-http` (HTTP/1.1 + HTTP/2),
  `aitm-proto-ws` (WebSocket), and `aitm-proto-l4` (TCP/UDP packet) each plug in
  behind one `ProtocolModule` seam. The seam is **protocol-extensible** — new
  protocols (and eventually more L4 surface) register through the same guards,
  with no change to the core.
- **Features are plugins.** Scripting, mapping rules, session I/O, WebSocket
  control, findings, the PoC engine, and the automated scanner are all plugins
  that register **commands**.
- **Frontends are clients.** The CLI, the MCP server, the web UI, the TUI, and
  the macOS app all drive the core by invoking the same registered commands. A
  command maps 1:1 from `scope.add` to `aitm scope add` (CLI) to the `scope.add`
  MCP tool.

Because of this, adding a command exposes it everywhere at once — CLI, MCP, and
every UI — with the same scope, sensitivity, and confirmation rules.

### Repository layout

A Cargo workspace of focused crates under `crates/`, operator UIs under `apps/`,
and the MCP plugin package at the root:

- **Core & proxy** — `aitm-core` (config, flow store, proxy engine), the
  protocol crates `aitm-proto-http`, `aitm-proto-ws`, `aitm-proto-l4`,
  `aitm-proto-test`, and `aitm-rules` / `aitm-ca` (CA and TLS).
- **Plugins & scripting** — `aitm-plugin`, `aitm-plugins`, and the plugin crates
  `aitm-plugin-rhai`, `aitm-plugin-maprules`, `aitm-plugin-passthrough`,
  `aitm-plugin-wsctl`, `aitm-plugin-sessionio`, and `aitm-plugin-scanner`.
- **Findings & PoC** — `aitm-poc`, `aitm-findings`.
- **MCP server** — `aitm-mcp` (the tool registry, the MCP Apps widgets, and the
  stdio / loopback-TCP / streamable-HTTP transports).
- **Binary & UIs** — `aitm` (the `aitm` binary), `aitm-cli`, `aitm-tui`,
  `aitm-browser`, `aitm-bus-client`, `aitm-testtarget`. The macOS and web
  operator UIs live under `apps/mac` and `apps/web`.

### The command surface

Every capability is a registered command, grouped by family. A representative
selection:

| Family | Commands | What it covers |
|---|---|---|
| Flows | `flow.list` `flow.detail` `flow.intercept` `flow.mutate` `flow.replay` `flow.resume` `flow.kill` `flow.mark` `flow.comment` `flow.export` `flow.import` `flow.subscribe` | Inspect, pause, modify, replay, and stream HTTP/WS flows |
| Requests | `request.send` | Craft and send an arbitrary request |
| WebSocket | `ws.intercept` `ws.frame` `ws.send` | Intercept and inject WS frames |
| Proxy | `proxy.status` `proxy.pause` `proxy.resume` | Control the accept loop |
| Scope | `scope.add` `scope.list` `scope.remove` | The in-scope allow-list (deny-by-default) |
| TLS | `tls.passthrough.add` `tls.passthrough.list` `tls.passthrough.remove` | Bypass MITM for named hosts |
| CA | `ca.export` `ca.status` `ca.install` `ca.uninstall` | Manage the MITM CA (agent install is gated) |
| Browser | `browser.navigate` `browser.click` `browser.type` `browser.get_dom` `browser.screenshot` `browser.eval` | Drive the embedded obscura browser |
| Mapping | `map.add` `map.list` `map.remove` | Static map/redirect rules |
| Scripting | `script.reload` `script.validate` | Manage Rhai scripts |
| PoC / findings | `poc.build` `poc.run` `poc.get` `poc.list` `poc.artifact` `findings.list` | Build, run, and record reproducible checks |
| Scanner | `scan.discover` | Crawl an in-scope target and discover injection points — see [docs/scanner.md](docs/scanner.md) |
| Agent | `agent.set` `agent.status` `agent.activity` `agent.approve` | Agent control and the operator approval gate |
| Session | `session.save` `session.load` | Persist and restore a working session |
| L4 | `l4.capture.start` `l4.intercept.start` `l4.craft` `l4.inject` `l4.send_recv` `l4.flow.list` `l4.scope.add` … | Raw TCP/UDP capture, interception, and packet crafting |

Run `aitm <family> <verb> --help` for the exact parameters of any command, or
list the MCP tools from any connected client.

## MCP server and the plugin

aitmproxy exposes its whole workflow — scope, capture, intercept/mutate, replay,
scan, findings/PoC — over MCP (`aitm-mcp`), served over **stdio**, **loopback
TCP**, or **streamable HTTP**. The
[`aitmproxy-plugin/`](aitmproxy-plugin/) package wires that server into AI hosts:
rich MCP Apps widgets in ChatGPT and Claude Desktop / claude.ai, and clean text
in Claude Code. Start at
[`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md); the transport threat
model is in
[`aitmproxy-plugin/docs/security.md`](aitmproxy-plugin/docs/security.md).

## Scripting

aitmproxy embeds [Rhai](https://rhai.rs) for rewriting traffic and writing PoCs.
Scripts run behind a **deny-by-default capability sandbox**: a script reaches the
network, the flow store, or the host only through capabilities it is explicitly
granted, and never outside the configured scope. The sandbox/capability model is
designed to expand for new MITM protocols (and eventually L4) behind the same
guards.

Both the Rhai surface **and** the PoC YAML format are a deliberate design
requirement to stay human-friendly to read and write — not a format only an
agent emits. The canonical, machine-checked catalogs of the scripting surface
live in [`docs/design/languages/`](docs/design/languages) — `rhai.api.json` (the
registered Rhai host surface) and `poc-yaml.schema.json` (the PoC document
structure) — and the shipped engine is asserted against them in CI.

## PoC / check engine

The nuclei-style engine (`aitm-poc`, `aitm-findings`) turns a captured flow into
a declarative, reproducible **PoC** (`poc.build`), runs it (`poc.run`), and
records a **finding** when it fires. PoCs are human-readable YAML with
request/matcher/extractor steps, and can drive HTTP, the browser, scripting, and
native L4 steps. Results and artifacts are retrievable (`poc.get`,
`poc.artifact`, `poc.list`) and findings are listed with `findings.list`.

## The obscura browser

aitmproxy ships an embedded headless browser engine, **obscura** (an aitmproxy
fork of Chromium), driven in-process over CDP behind the same `browser.*`
command surface. It launches with aitmproxy as its upstream and the MITM CA
already trusted, so an agent can log in, click through a flow, and capture the
resulting traffic — all in scope, all through the proxy. The browser-facing
listener also has an optional **scope-confined egress mode**
(`confine_egress_to_scope`): when on, it refuses an out-of-scope *public* host
rather than relaying it, which keeps a crawl or a browser-driven campaign inside
scope.

obscura is a separate artifact, not produced by `cargo build`. It is bundled for
you in the shipping paths:

- The **macOS app** and the **Linux `.deb`/`.rpm`** bundle and manage it.
- `scripts/package.sh` builds a release `aitm` and bundles the matching `obscura`
  beside it in the tarball.
- For a plain dev checkout, `scripts/fetch-obscura-dev.sh` downloads the matching
  `obscura` and drops it next to the `target/debug` and `target/release`
  binaries, so `cargo run -p aitm` finds it.

See [INSTALL.md](INSTALL.md#building-from-source-cargo--bare-binary) for the full
discovery order.

## User interfaces

All three UIs are clients of one core and show the same flows, scope, scanner
results, and commands:

- **Web UI** — `aitm web` serves the embedded web UI with a `/bus` bridge.
- **Terminal UI** — `aitm tui` runs the proxy with the terminal operator UI in
  the same process; `aitm-tui` is the standalone detached TUI that connects to a
  running core.
- **macOS app** — a native app that bundles and manages its own embedded core
  and obscura, or points at an external core you run yourself. See
  [INSTALL.md](INSTALL.md).

Each UI has a **Scan** view that launches `scan.discover` and shows the
discovered endpoints and injection points, with rows that link back to the flow
they came from.

## Install

See **[INSTALL.md](INSTALL.md)** for the full matrix. In brief:

- **macOS app:** `brew install --cask mrbrutti/aitmproxy/aitmproxy` — a
  self-contained `Aitmproxy.app` with an embedded core and obscura.
- **CLI / headless core (macOS):** `brew install mrbrutti/aitmproxy/aitm`.
- **Linux:** native `.deb` or `.rpm` for **x86_64** and **aarch64** from the
  release page (`sudo apt install ./aitm-<ver>-<arch>.deb` /
  `sudo dnf install ./aitm-<ver>-<arch>.rpm`), or the `-<triple>.tar.gz` tarball.
- **From source:** `cargo build` (see below).

Releases ship Linux `.deb`/`.rpm`/tarball for x86_64 and aarch64, a macOS arm64
tarball, and a signed, notarized `Aitmproxy.dmg`. **Windows is not supported.**

## Build

```bash
cargo build                                        # whole workspace
cargo build --release                              # release binary
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The release binary is `target/release/aitm` (or `cargo install --path
crates/aitm`). A bare `cargo build` produces **only** `aitm` — not the obscura
browser engine. The proxy runs fine without it, but the browser commands need
obscura reachable; the quickest path in a dev checkout is
`scripts/fetch-obscura-dev.sh` (see [The obscura browser](#the-obscura-browser)).

## Quick start

```bash
# 1. Generate an operator token (CLI-only; no agent can run this).
aitm operator-token generate

# 2. Put a host in scope — nothing is proxied until you do.
aitm scope add --host example.test

# 3. Trust the MITM CA (export it, or install it).
aitm ca export

# 4. Run the proxy with a UI.
aitm web          # web UI
aitm tui          # terminal UI
aitm              # headless proxy + stdio MCP server
```

Point your client (or the embedded browser) at the proxy, and flows for in-scope
hosts appear in whichever UI you launched. From there, intercept and mutate
flows, discover the attack surface with the scanner, build a PoC from a flow, or
let an agent drive the whole thing over MCP.

## Documentation

- [INSTALL.md](INSTALL.md) — install on macOS and Linux, build from source,
  point the app at an external core.
- [docs/scanner.md](docs/scanner.md) — the automated scanner (`scan.discover`).
- [`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md) — the MCP plugin for
  ChatGPT, Claude Desktop / claude.ai, and Claude Code.
- [docs/design/languages/](docs/design/languages) — canonical Rhai and PoC-YAML
  scripting catalogs (`rhai.api.json`, `poc-yaml.schema.json`).
- [docs/RELEASE.md](docs/RELEASE.md) — the release runbook.
- Project research, design, and process live in [`docs/`](docs/) (start with
  `docs/research/05-synthesis.md` and `docs/research/MEMORY.md`); contributor
  conventions are in [CLAUDE.md](CLAUDE.md).

## License

Licensed under either of MIT or the Apache License, Version 2.0
(`MIT OR Apache-2.0`) at your option.
