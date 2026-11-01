---
name: aitmproxy-overview
description: Drive aitmproxy — the intercepting HTTP/WebSocket proxy for AUTHORIZED security testing — end to end over MCP. Use when the user wants to inspect captured web traffic, intercept and mutate live requests or responses, replay or craft requests, or build reproducible PoCs and record findings against an engagement they are authorized to test. Explains the capture → intercept → replay → findings workflow, names the key MCP tools per stage, the scope gating and agent policy, the raw L4 (TCP/UDP) packet family and its status/scope/gate rules when the core enables it, and how output renders across hosts.
---

# aitmproxy overview

aitmproxy is a Rust intercepting proxy for **authorized** security testing. It
captures HTTP and WebSocket traffic that flows through it, lets you park and edit
live requests/responses, replay or craft requests through a guarded client, and
turn a finding into a reproducible PoC and a recorded result. You drive all of it
over MCP with the tools below.

## Authorized use only

Operate aitmproxy only against targets covered by a written engagement you are
authorized to test. Active tools (`flow.replay`, `request.send`, `ws.send`,
`poc.run`) send real traffic and are **scope-gated**: egress is refused unless the
target host is in the active scope (`scope.list` / `scope.add`). Narrowing scope
is always allowed; widening from an agent frontend is refused unless the operator
enabled it. Never use these tools to reach systems outside your authorization.

### Agent policy — the operator's governor

`agent.status` reports the current policy; only the operator can change it with
`agent.set --policy <all|auto|ask|readonly|paused>`:

- `all` — every agent call runs (still subject to scope, rate, SSRF and the
  per-command config opt-ins below);
- `auto` — read and write tools run; Sensitive tools (`scope.add`, `ca.install`,
  `script.save`, …) are refused unless their own config opt-in allows them;
- `ask` — read and write tools run; a Sensitive tool parks for operator
  `agent.approve`;
- `readonly` — only read-only tools run;
- `paused` — the agent runs nothing.

Some tools are also gated by a config opt-in the operator must have set, whatever
the policy: `scope.allow_agent_widen` (`scope.add`), `tls.allow_agent_passthrough`,
`maps.allow_agent_authoring` (`map.add`/`map.remove`), `ca.allow_agent_install`
(`ca.install`/`ca.uninstall`) and `poc.allow_agent_run` (`poc.run`).

The agent cannot change its own policy or approve its own requests. Check
`agent.status` first and respect a restrictive policy instead of working around it.

## The workflow and its tools

1. **Scope first.** `scope.list` to see what is in bounds; `scope.add` /
   `scope.remove` to adjust (narrowing always allowed). `tls.passthrough.list`
   shows hosts tunnelled without decryption.
2. **Capture.** `flow.table` for a rendered/tabular overview of captured flows;
   `flow.list` for raw ids; `flow.detail --id` for one flow's headers, bodies,
   timing and edit state. `flow.subscribe` streams live flows. `proxy.status`
   shows listening state, armed interception, paused count and flow count.
3. **Intercept & mutate.** `flow.intercept` arms parking (global, or by rules);
   a parked flow waits for `flow.resume` (forward, possibly mutated) or
   `flow.kill` (reset / 429 / 503). `flow.mutate` edits a flow's request (or the
   response when parked at the response phase). WebSockets: `ws.intercept`,
   `ws.frame` (forward/edit/drop a parked frame), `ws.send` (inject a frame).
4. **Replay & craft.** `flow.replay --id` reissues a captured request;
   `request.send` crafts a new request through the guarded client. Both are
   active egress and scope-gated.
5. **Findings & PoC.** `poc.build --flow_id` turns a flow into a parameterized
   YAML PoC; `poc.run --poc_path` runs it with no agent and emits artifacts;
   `findings.record` writes a human-readable finding after a passing run.
   `findings.list` / `findings.get` review recorded findings.

## Triage & housekeeping

`flow.mark` and `flow.comment` annotate flows; `flow.export` emits native JSON or
HAR; `flow.clear` drops completed flows; `proxy.pause` / `proxy.resume` hide or
show new captures.

`scan.discover --target <url>` crawls an in-scope target through the embedded
browser and returns the reachable endpoints and the injection points seen in
captured requests. It is **discovery only** — it never fuzzes or injects.

## L4 (raw TCP/UDP)

A core started with `l4.enabled: true` in `config.yaml` also registers the
`l4.*` family: raw packet capture, crafting and injection, send/receive, and
(Linux only) in-path packet interception. Without that line the verbs are not in
`tools/list`; only the three bundled Rhai scripts `l4.recon`, `l4.tcp_probe` and
`l4.udp_probe` are, and they need the module to do anything. The family is
deny-by-default and gated separately from the HTTP tools. What an agent must know:

**Ask the status verbs first.** `l4.capture.status` and `l4.intercept.status`
always answer (never `L4 unavailable`) with `{available, code, reason,
captures|sessions}`:

- `available` (bool): the capability works on this core right now.
- `code`: `available`, or one of `needs_privilege` (the platform supports it but
  this process lacks the privilege: read+write `/dev/bpf*` on macOS, `CAP_NET_RAW`
  on Linux, `CAP_NET_ADMIN` for intercept), `unsupported_platform` (no backend on
  this OS: in-path intercept on macOS and on everything but Linux; capture
  outside macOS and Linux) or `not_configured` (supported and privileged, but the
  config has no `l4.intercept` block).
- `reason`: the exact text the gated verbs would return after `L4 unavailable: `;
  null when available.
- `captures` (running capture flow ids) or `sessions` (intercept sessions with
  their parked counts); `[]` when unavailable.

When `available` is false, report the `code` and `reason` to the user and stop;
`l4.capture.start` / `l4.intercept.start` return that same reason as an error.
Re-read the status verbs instead of remembering them: privilege can change while
the core runs.

**Scope and the agent gates.** L4 scope is separate from HTTP scope.
`l4.scope.list` shows the entries, each with `source: config | runtime`; scope is
normally declared in `config.yaml`. A runtime `l4.scope.add` from an agent is refused
(`runtime L4 scope widening is disabled; declare scope in the l4.scope config
…`) unless the operator opened the Widen gate with
`l4.agent.set {capability: widen, allowed: true}`. The operator adds scope
without the Widen gate: an operator (or CLI) `l4.scope.add` is a confirmed
call (`confirmable: true` in `tools/list`; the core answers
`needs_confirmation` with a prompt summarising the entry, and the operator
re-issues it with `_confirm`); the entry is stored with `source: runtime` and
never lifts the dangerous-destination denylist. An agent is never offered that
handshake, so ask the operator to add the entry (or to open the Widen gate).
Narrowing with `l4.scope.remove` is never Widen-gated (agent policy still
applies). Four per-capability gates govern the
agent path: `inject`, `capture`, `intercept` and `widen`. `l4.agent.status`
reads them; only the operator can flip them with `l4.agent.set`. The agent can
never open its own gates; respect a closed one.

**Capture and read packets.** `l4.capture.start {interface, direction?}`
(Capture gate) returns a capture flow id; `l4.capture.stop {id}` ends it.
`l4.flow.list` lists every L4 flow id, oldest first. `l4.flow.get {id, offset?,
limit?}` returns the flow header (`kind`, `started_at`, `proto`, `src`, `dst`,
`src_port`, `dst_port`, `packet_count`, the total) and a window of packets.
`limit` defaults to 256 and is clamped to 4096; pass `limit: 0` when listing
(header only, `packets: []`) and fetch a window only to inspect one flow. Each
packet carries `dir`, `length`, `injected`, `layers`, `timestamp` (epoch ms),
`proto`, `src`, `dst`, `src_port`, `dst_port` and, when you may see them,
`bytes` (the on-wire frame as padded base64). The bytes rule is per packet: the
operator and the CLI always get `bytes`; an agent gets `bytes` for a captured
packet (`injected: false`) only while its Capture gate is open, and for an
injected packet (`injected: true`) only while its Inject gate is open. A packet
you may not read keeps every other field and simply has no `bytes` key; a
missing key is not an empty packet. One reply carries at most 4 MiB of raw
bytes; when that cuts the window short the reply has `truncated: true` and
`next_offset`. To read a whole flow keep advancing `offset` until it reaches
`packet_count`; `truncated`/`next_offset` only mark a window the byte budget
cut short. The core excludes its own listener ports (proxy, bus, web UI, MCP)
on loopback from every L4 recorder, so operator bus traffic never appears in a
capture.

**Craft, inject, send/recv.** `l4.interfaces` lists the capture-capable
interfaces. `l4.craft {spec}` is pure: it builds bytes and a summary with no
privilege and no wire. `l4.inject {spec, dst, interface, port?, count?}` (Inject
gate; scope, dangerous-destination denylist and rate caps apply) and
`l4.send_recv {spec, dst, interface, port?, timeout_ms?, expect?}` (the agent's
**Inject gate only**; the guard additionally needs an Inject and a Capture
*scope* entry for the interface, scope, not gates; bounded by `timeout_ms`;
returns `flow_id` and an `outcome` classification, not the payload) are
**active egress**. Read the reply with `l4.flow.get {id: <flow_id>}`; the reply
is a captured packet, so an agent sees its `bytes` only while its Capture gate
is open. Apply the same authorization discipline as for `request.send`.

**In-path intercept (Linux NFQUEUE only).** `l4.intercept.*` parks live packets
in a kernel queue for a verdict. It exists only on Linux with `CAP_NET_ADMIN`
and an `l4.intercept` config block; on macOS `l4.intercept.status` reports
`unsupported_platform` and nothing in this paragraph applies.
`l4.intercept.start {interface, direction?, queue_num?}` (Intercept gate, needs
an `Intercept` scope entry) returns a session flow id; `l4.intercept.stop {flow}`
ends the session and forwards whatever is still parked. `l4.intercept.list
{flow?}` returns the parked packets in arrival order, oldest first, each
`{id, flow, state: parked | mutated, dir, length, layers, parked_at}`. The
verdict verbs `l4.intercept.forward {id}`, `l4.intercept.drop {id}`,
`l4.intercept.mutate {id, spec | bytes}` and `l4.intercept.revert {id}` take the
**parked id** (the `id` of an `l4.intercept.list` entry), never the session's
flow id. Work the oldest first: a parked packet is live traffic waiting on you.
Parked packets are captured packets, so an agent sees their `bytes` in
`l4.flow.get` only with its Capture gate open.

## How output renders

Rich hosts (ChatGPT, Claude Desktop / claude.ai) render interactive widgets for
tools like `flow.table`, `findings.list` and `proxy.status`. **Claude Code is
text-only**: it shows the tool's `structuredContent` JSON and renders no widget.
When you are in a text host, use the **aitmproxy-rendering** skill to turn that
JSON into clean markdown tables with method/status/severity labels.
