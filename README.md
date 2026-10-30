# aitmproxy

**Intercept anything — by hand or by agent.**

aitmproxy is an intercepting-proxy platform for authorized security testing. It
captures, intercepts, edits, replays and reproduces traffic across four layers of
the wire — HTTP/1.1, HTTP/2, WebSocket and raw L4 (TCP/UDP) — from one core that
an operator and an AI agent drive with the same commands. Written in memory-safe
Rust; runs on macOS and Linux.

![release](https://img.shields.io/badge/release-v0.5.0-555?style=flat-square)
![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-555?style=flat-square)
![platforms](https://img.shields.io/badge/platforms-macOS%20%C2%B7%20Linux-555?style=flat-square)

![The aitmproxy web UI with interception armed](site/assets/web-dark.png)

> **Authorized engagements only.** aitmproxy is deny-by-default and strictly
> scope-bound — it will not touch a host you have not explicitly put in scope —
> and its active tools send real traffic. Operate it solely against systems you
> own or are covered by a written engagement to test.

[Install](#install) · [Quick start](#quick-start) · [What it does](#what-it-does) ·
[Agents over MCP](#agents-over-mcp) · [Architecture](#architecture) ·
[Documentation](#documentation)

---

## Two operators, one core

Every action in aitmproxy is a registered command. A person runs it from the CLI
or a UI; an AI agent calls the very same command over MCP. There is no second API
for agents and no hidden menu for humans, and every call lands in one audit log
with the operator named.

A command maps one-to-one across surfaces: `scope.add` is `aitm scope add` on the
CLI and the `scope.add` MCP tool. Hold a request, edit it, let it go:

```text
flow.intercept({ enabled: true })                         // arm: matching flows are held
flow.mutate({ id: 41, edits: { body: '{"qty":999}' } })   // edit the held request
flow.resume({ id: 41 })                                   // release it, as edited
```

A flow moves through a short lifecycle — **observed** (recorded and forwarded),
**intercepted** (held, readable, editable), then **resumed** or **killed**. Adding
a command to the core exposes it on the CLI, over MCP and in every UI at once,
under the same scope, sensitivity and confirmation rules.

## What it does

### Four layers of the wire

| Layer | What you can do |
|---|---|
| **HTTP/1.1** | Hold requests and responses, edit method, URL, headers and body, replay, compose, and map to a local file or another upstream. |
| **HTTP/2** | Negotiated over ALPN and decrypted with the local CA. Each multiplexed stream is an ordinary flow you can hold and edit. |
| **WebSocket** | Every frame in both directions. Hold one, change it, or inject a frame toward either side. |
| **Raw L4 (TCP/UDP)** | Capture segments, craft and inject packets, send and receive, and — where the host allows — hold and edit bytes in the path. |

All four share one flow model, one command surface and one scripting API, so a
new protocol needs no new language. TLS is terminated with a CA generated on your
machine; hosts that pin certificates can be excluded with TLS passthrough.

**L4 platform support, stated plainly.** Live-wire L4 runs today on a privileged
`aitm` core, Linux first: capture and inject need `CAP_NET_RAW`, and in-path
hold-and-edit uses NFQUEUE with `CAP_NET_ADMIN`. `l4.enabled` defaults to off, and
without privilege the wire commands return a typed `L4Unavailable` rather than
failing silently. The macOS app's embedded core degrades the same way; a macOS
Network Extension capture path for the app is in progress and is not part of
v0.5.0.

### Embedded browser

aitmproxy bundles a headless browser engine, **obscura** — a Rust engine
embedding V8 and speaking CDP — behind the same `browser.*` commands. It starts
with aitmproxy as its upstream and the MITM CA already trusted, so an agent or an
operator can log in, click through a flow, take the screenshot that proves a
finding, and capture the resulting traffic, all in scope and all through the
proxy. An optional **scope-confined egress mode** (`confine_egress_to_scope`)
refuses out-of-scope public hosts rather than relaying them, which keeps a crawl
or browser-driven campaign inside the engagement.

obscura is a separate artifact, not produced by `cargo build`. The macOS app, the
Linux `.deb`/`.rpm` and the release tarballs bundle it; see [Build](#build) for a
source checkout.

### Automated scanner

`scan.discover` drives the embedded browser to crawl an authorized, in-scope
target breadth-first, then reads the captured flows back to enumerate **injection
points** — query and body parameters, headers, cookies, path segments. It is
deterministic and AI-free, deny-by-default (an out-of-scope target is refused
before the crawler opens a page), and returns the endpoints found, the injection
points, pages crawled and why it stopped. Endpoint and injection-point rows link
back to the flow they came from.

```bash
aitm scan discover --target https://staging.example.com/ --max_depth 2 --max_pages 50
```

**What shipped in v0.5.0 is discovery.** It reads and enumerates; it never
injects or mutates. Active fuzzing, injection and campaigns build on the same
seam and are roadmap, not present features. Details in
[docs/scanner.md](docs/scanner.md).

### Scripting and reproducible PoCs

**Rhai plugins** see each flow as it passes and can edit it, answer it, or record
a finding. They run in a sandbox that starts with nothing: a header declares the
capabilities a plugin needs, and anything undeclared is denied — no network, no
shell, no path outside a declared directory. The same guards apply whether a
person or an agent loaded the plugin.

**PoCs** are declarative YAML — a few steps, a few matchers and a success
condition — so a finding can be re-run next week and diffed like code. Steps can
drive HTTP, the browser, replay, WebSocket and native L4. A run records a
**finding** when it succeeds, and a PoC can sit in CI as a regression test.

```yaml
id: reflected-xss-search-q
info:
  name: Reflected XSS in search 'q' parameter
  severity: high

variables:
  - name: target
    required: true

steps:
  - http:
      method: GET
      url: "{{target}}/search?q=x"
      matchers:
        - type: status
          status: 200

success:
  all:
    - type: status
      status: 200
```

Both languages are written to be read and written by people first and agents
second. Their canonical, machine-checked catalogs — `rhai.api.json` and
`poc-yaml.schema.json` — live in [`docs/design/languages/`](docs/design/languages)
and the shipped engine is asserted against them in CI.

### And the rest of the proxy

- **Intercept rules** by method, host, path, header or body; arm and disarm live.
- **Replay and compose** — resend any flow with changes, or build a request from
  scratch; each replay is a new flow linked to the original.
- **Map rules** to answer a request from a file or redirect it to another
  upstream.
- **Sessions and HAR** — save and reload a capture; import and export HAR.
- **Certificate management** — export, inspect, install and uninstall the CA
  (`ca.*`). An agent can export and check status; installing is gated behind a
  human.

## Three surfaces, one core

The web UI, the terminal UI and the native macOS app are all clients of the core.
They show the same flows, scope, scanner results and commands, and each has a
**Scan** view that launches `scan.discover`. None of them is the core.

| Terminal | macOS |
|---|---|
| ![The terminal UI](site/assets/tui.png) | ![The macOS app](site/assets/mac-dark.png) |

- **Web UI** — `aitm web` serves the embedded SolidJS UI on `127.0.0.1:8082`.
- **Terminal UI** — `aitm tui` runs the proxy and a ratatui interface in one
  process, and it works over SSH. `aitm-tui` is the standalone UI that attaches
  to a running core.
- **macOS app** — a native SwiftUI app, signed and notarized, that bundles and
  manages its own core and obscura, or attaches to an external core you run. See
  [INSTALL.md](INSTALL.md#pointing-the-app-at-an-external-core).

## Agents over MCP

aitmproxy is an MCP server (`aitm-mcp`): every command is exposed to an agent
under the same name and shape, over **stdio**, **loopback TCP** or **streamable
HTTP**. Launching `aitm` with no arguments serves MCP over stdio.

```bash
claude mcp add aitmproxy -- aitm
```

For Claude Desktop, add `{"mcpServers": {"aitmproxy": {"command": "aitm"}}}` to
`claude_desktop_config.json`. Hosts that reach a URL rather than launch a command
use the token-guarded loopback or streamable-HTTP transport.

An agent gets the agent command set by default. The sensitive verbs — installing
the CA, widening scope, running a PoC — stay off until you opt in, and the
operator token (`aitm operator-token generate`) is CLI-only: no agent can run it.

The [`aitmproxy-plugin/`](aitmproxy-plugin/) package wires the server into AI
hosts, with rich MCP Apps widgets in ChatGPT and Claude Desktop / claude.ai and
clean text in Claude Code. Start at
[`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md); the transport threat
model is in [`aitmproxy-plugin/docs/security.md`](aitmproxy-plugin/docs/security.md).

## Install

aitmproxy supports macOS (Apple Silicon) and Linux (x86_64 and aarch64). **Windows
is not supported.** The Homebrew tap and the release binaries are public; no
account or token is needed.

**macOS**

```bash
brew tap mrbrutti/aitmproxy
brew install aitm                  # CLI, web UI, terminal UI, MCP server
brew install --cask aitmproxy      # the native macOS app (self-contained)
```

The formula is the `aitm` core; the cask is the app, which bundles its own core
and does not need the formula.

**Linux**

Download a package from the
[release page](https://github.com/mrbrutti/homebrew-aitmproxy/releases/latest),
then install it. Packages place `aitm` and `aitm-tui` on your `PATH` with obscura
beside them.

```bash
sudo apt install ./aitm-0.5.0-amd64.deb     # Debian / Ubuntu
sudo dnf install ./aitm-0.5.0-x86_64.rpm    # Fedora / RHEL
```

The release also ships `aitm-<version>-<target>.tar.gz` for Linux and macOS, and
a signed, notarized `Aitmproxy-<version>.dmg`.

**Cargo**

```bash
cargo install --git https://github.com/mrbrutti/aitmproxy aitm
```

Cargo builds only `aitm`; see [Build](#build) for obscura. The source repository
is private, so this needs git credentials with access to it.

To point the app at an external core, or to see how `aitm` finds obscura, read
[INSTALL.md](INSTALL.md).

## Quick start

```bash
# 1. Put a host in scope. Nothing is proxied until you do.
aitm scope add --host example.test

# 2. Trust the local CA. It asks first; `aitm ca export` writes a PEM for other devices.
aitm ca install

# 3. Run the proxy with a UI.
aitm web          # proxy on 127.0.0.1:8080, web UI on 127.0.0.1:8082
aitm tui          # or the terminal UI
aitm              # or headless: proxy plus the stdio MCP server
```

Point a browser, simulator or client at `127.0.0.1:8080` and flows for in-scope
hosts appear in whichever UI you launched. From there, hold and edit a flow,
discover the attack surface, build a PoC from a captured request, or hand the
whole thing to an agent.

## Architecture

One spine throughout: **a thin core, and everything else is a plugin or a
client.**

- **Thin core (`aitm-core`).** Accepts connections, runs sans-IO protocol state
  machines, holds the flow store, and emits typed events to an ordered plugin
  chain with halt and short-circuit semantics. It owns the deny-by-default
  **scope and rate guard** that every action passes through.
- **Protocol modules are plugins.** `aitm-proto-http` (HTTP/1.1 and HTTP/2),
  `aitm-proto-ws` and `aitm-proto-l4` plug in behind one `ProtocolModule` seam.
  The seam is protocol-extensible: new protocols register through the same
  guards with no change to the core.
- **Features are plugins.** Scripting, map rules, session I/O, WebSocket control,
  findings, the PoC engine and the scanner each register commands.
- **Frontends are clients.** The CLI, the MCP server, the web UI, the TUI and the
  macOS app all drive the core by invoking registered commands.

### Repository layout

A Cargo workspace of focused crates under `crates/`, operator UIs under `apps/`,
and the MCP plugin package at the root.

- **Core and proxy** — `aitm-core`, the protocol crates `aitm-proto-http`,
  `aitm-proto-ws`, `aitm-proto-l4` and `aitm-proto-test`, plus `aitm-rules` and
  `aitm-ca`.
- **Plugins and scripting** — `aitm-plugin`, `aitm-plugins`, and
  `aitm-plugin-rhai`, `-maprules`, `-passthrough`, `-wsctl`, `-sessionio` and
  `-scanner`.
- **Findings and PoC** — `aitm-poc`, `aitm-findings`.
- **MCP** — `aitm-mcp`: the tool registry, the MCP Apps widgets and the stdio,
  loopback-TCP and streamable-HTTP transports.
- **Binary and UIs** — `aitm`, `aitm-cli`, `aitm-tui`, `aitm-browser`,
  `aitm-bus-client`, `aitm-testtarget`; the macOS and web UIs live in `apps/mac`
  and `apps/web`.

### The command surface

A representative selection, grouped by family. Run `aitm <family> <verb> --help`
for exact parameters, or list the MCP tools from any connected client.

| Family | Commands | What it covers |
|---|---|---|
| Flows | `flow.list` `flow.detail` `flow.intercept` `flow.mutate` `flow.replay` `flow.resume` `flow.kill` `flow.mark` `flow.comment` `flow.export` `flow.import` `flow.subscribe` | Inspect, pause, modify, replay and stream HTTP and WebSocket flows |
| Requests | `request.send` | Craft and send an arbitrary request |
| WebSocket | `ws.intercept` `ws.frame` `ws.send` | Intercept and inject frames |
| Proxy | `proxy.status` `proxy.pause` `proxy.resume` | Control the accept loop |
| Scope | `scope.add` `scope.list` `scope.remove` | The in-scope allow-list (deny-by-default) |
| TLS | `tls.passthrough.add` `tls.passthrough.list` `tls.passthrough.remove` | Bypass MITM for named hosts |
| CA | `ca.export` `ca.status` `ca.install` `ca.uninstall` | Manage the MITM CA (agent install is gated) |
| Browser | `browser.navigate` `browser.click` `browser.type` `browser.get_dom` `browser.screenshot` `browser.eval` | Drive the embedded browser |
| Mapping | `map.add` `map.list` `map.remove` | Map and redirect rules |
| Scripting | `script.reload` `script.validate` | Manage Rhai scripts |
| PoC and findings | `poc.build` `poc.run` `poc.get` `poc.list` `poc.artifact` `findings.list` | Build, run and record reproducible checks |
| Scanner | `scan.discover` | Crawl an in-scope target and discover injection points |
| Agent | `agent.set` `agent.status` `agent.activity` `agent.approve` | Agent control and the operator approval gate |
| Session | `session.save` `session.load` | Persist and restore a working session |
| L4 | `l4.capture.start` `l4.intercept.start` `l4.craft` `l4.inject` `l4.send_recv` `l4.flow.list` `l4.scope.add` … | Raw TCP and UDP capture, interception and packet crafting |

## Build

```bash
cargo build                                        # whole workspace
cargo build --release                              # release binary
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

The release binary is `target/release/aitm`, or `cargo install --path crates/aitm`.
A bare `cargo build` produces **only** `aitm`, not obscura. The proxy runs
without it, but the browser commands (and so the scanner) need obscura reachable.
In a dev checkout, `scripts/fetch-obscura-dev.sh` downloads the matching build
beside `target/debug` and `target/release`; `scripts/package.sh` builds a release
`aitm` and bundles obscura next to it. The discovery order is in
[INSTALL.md](INSTALL.md#building-from-source-cargo--bare-binary).

## Built to be trusted on the wire

- **No `unsafe` Rust** anywhere in the workspace.
- **~31,000 requests per second**, sustained on a single instance with flat
  memory.
- **Deny-by-default** at every layer: scope, scripting capabilities, agent
  privileges and the scanner each refuse before they act.
- **One audit log** of every command, its arguments and its effect, whichever
  operator issued it.

## Documentation

- [INSTALL.md](INSTALL.md) — install on macOS and Linux, build from source, point
  the app at an external core.
- [docs/scanner.md](docs/scanner.md) — the automated scanner (`scan.discover`).
- [`aitmproxy-plugin/README.md`](aitmproxy-plugin/README.md) — the MCP plugin for
  ChatGPT, Claude Desktop / claude.ai and Claude Code.
- [docs/design/languages/](docs/design/languages) — the canonical Rhai and
  PoC-YAML catalogs.
- [docs/RELEASE.md](docs/RELEASE.md) — the release runbook.
- Research, design and process live in [`docs/`](docs/) — start with
  `docs/research/05-synthesis.md` and `docs/research/MEMORY.md`. Contributor
  conventions are in [CLAUDE.md](CLAUDE.md).

## License

Licensed under either of MIT or the Apache License, Version 2.0
(`MIT OR Apache-2.0`) at your option.
