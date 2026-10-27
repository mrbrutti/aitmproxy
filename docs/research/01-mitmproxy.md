# mitmproxy — architecture reference

Sources: github.com/mitmproxy/mitmproxy, docs.mitmproxy.org (addons/examples,
api/events, concepts/how-mitmproxy-works), deepwiki.com/mitmproxy/mitmproxy.

## 1. Core architecture (core vs UIs, master/addon/event-hook model)

- One shared Python package (`mitmproxy/`) holds the proxy engine; the three
  frontends are thin layers over it: **mitmproxy** (interactive TUI/console),
  **mitmweb** (web UI, React frontend in `web/`), **mitmdump** (headless CLI,
  "tcpdump for HTTP").
- Central object is the **Master**: owns the asyncio **event loop**, the proxy
  server, and an **AddonManager**. Each UI is its own Master subclass that adds
  UI-specific addons on top of the same core.
- Everything above raw I/O is an **addon**. Even built-in features (interception,
  flow storage, replay, filtering, dumping, the UIs' view logic) are addons. The
  AddonManager holds an ordered **chain**; each lifecycle event is dispatched to
  every addon in order. An addon can raise `AddonHalt` to stop propagation. This
  "the platform is just a host for addons" pattern is the key thing to adapt: a
  thin core that emits typed events, with all behavior (including first-party
  features) implemented as pluggable handlers.
- The modern proxy core is a **sans-IO state machine** (pure protocol logic, no
  sockets) driven by the async layer — very relevant for Rust: maps cleanly to a
  `no-IO` protocol crate + async runtime (tokio).

## 2. Addon/plugin system

- Addons are Python classes (or module-level functions) whose method names match
  event hooks; a script exposes an `addons = [...]` list. Loaded via `-s script.py`.
- Lifecycle hooks: `load(loader)` (register options + commands), `configure(updated)`,
  `running()`, `done()`.
- Options: declared in `load` via `loader.add_option(...)`, set with `--set k=v`,
  read through `ctx.options`; `configure` validates (raise `OptionsError`).
- Addons also register **commands** (`@command.command`) callable from UI/other
  addons, **content views**, and **I/O** hooks. `ctx` gives access to the running
  master. Hooks can be `async`, or `@concurrent` to run in a thread (a blocking
  hook otherwise stalls the flow).
- Event hooks (full set):
  - **HTTP:** `requestheaders`, `request`, `responseheaders`, `response`, `error`,
    plus CONNECT: `http_connect`, `http_connect_upstream`, `http_connected`,
    `http_connect_error`.
  - **WebSocket:** `websocket_start`, `websocket_message`, `websocket_end`.
  - **TCP:** `tcp_start`, `tcp_message`, `tcp_end`, `tcp_error`. UDP mirrors these.
  - **DNS:** `dns_request`, `dns_response`, `dns_error`.
  - **Connection:** `client_connected`/`client_disconnected`,
    `server_connect`/`server_connected`/`server_disconnected`/`server_connect_error`.
  - **TLS:** `tls_clienthello`, `tls_start_client`/`tls_start_server`,
    `tls_established_*`, `tls_failed_*`; QUIC `quic_start_*`; SOCKS5 `socks5_auth`;
    advanced `next_layer`, `update(flows)`.

## 3. Flow model

- Base `Flow` = a container for one logical conversation; subtypes `HTTPFlow`
  (request/response pair), `TCPFlow`/`UDPFlow` (list of `messages`, newest
  `flow.messages[-1]`), `DNSFlow`, plus a `WebSocketData` attached to the
  originating HTTPFlow.
- Every flow carries `client_conn`, `server_conn`, `error`, `id`, `marked`,
  `comment`, `metadata`, `is_replay`, `live`, and interception state
  (`intercepted`, `_resume_event`, `_backup`). Flow type is derived from the class.

## 4. Interception / modify

- Mutation is just editing the flow object inside a hook (change
  `flow.request`/`flow.response`, inject/rewrite `flow.messages[-1]`).
  `backup()`/`revert()`/`modified()` track changes; `kill()` drops a flow;
  short-circuit a response by setting `flow.response` in `request`.
- Hard interactive interception: `flow.intercept()` pauses the flow,
  `flow.wait_for_resume()`, then `flow.resume()` (driven by UI or a command).
  This pause/resume + resume-event is the mechanism the TUI/web use for manual
  edit-and-forward.

## 5. TLS interception

- Ships a built-in **CA** generated on first run; the user must install/trust it
  on the client. Per-connection it does **upstream cert sniffing**: lets the
  client handshake proceed until SNI arrives, connects upstream with that SNI,
  reads the real cert's CN + SANs, then **mints a dummy leaf cert** copying
  CN/SANs, signs it with the CA, and resumes the client handshake. Transparent
  mode detects a ClientHello on any port and recovers the original destination
  from the OS (platform-specific modules / routing layer).

## 6. Strengths & pain points

- **Strengths:** the addon-everything model (extremely extensible, uniform),
  sans-IO protocol core (testable), broad protocol coverage (HTTP/1,2,3/QUIC, WS,
  raw TCP/UDP, DNS), three UIs on one engine, scriptable flows with clean
  intercept/resume.
- **Pain points:** Python performance/throughput and memory on high-volume or
  large-body traffic (a major reason to do aitmproxy in Rust); blocking addon
  hooks can stall flows unless made async/concurrent; HTTP/2 and TLS edge cases;
  CA trust UX friction; the sans-IO + async-layer split has a steep learning curve.

## Patterns worth adapting for a Rust pluggable-interface design

- Thin core that only emits **typed events** + a flow store; implement first-party
  features as the first addons.
- **sans-IO protocol state machines** (pure, synchronous) separated from the tokio
  I/O/driver layer.
- An **ordered handler chain** with explicit halt/short-circuit semantics; async
  handlers with an escape hatch for CPU/blocking work (`spawn_blocking`).
- A single **Flow** enum/trait (HTTP/WS/TCP/UDP/DNS) with uniform
  intercept/resume/kill/backup; interception as a pausable future.
- Frontends (TUI, web, headless dump) as separate binaries/masters over one core
  crate.
- Options/commands registered by plugins, not hardcoded; stable event names as
  the plugin API boundary.
