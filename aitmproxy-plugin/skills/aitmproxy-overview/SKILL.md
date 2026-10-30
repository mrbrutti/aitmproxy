---
name: aitmproxy-overview
description: Drive aitmproxy — the intercepting HTTP/WebSocket proxy for AUTHORIZED security testing — end to end over MCP. Use when the user wants to inspect captured web traffic, intercept and mutate live requests or responses, replay or craft requests, or build reproducible PoCs and record findings against an engagement they are authorized to test. Explains the capture → intercept → replay → findings workflow, names the key MCP tools per stage, the scope gating and agent policy, and how output renders across hosts.
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

- `all` / `auto` — the agent may run tools (auto parks nothing extra);
- `ask` — Sensitive tools park for operator `agent.approve`;
- `readonly` — only read-only tools run;
- `paused` — the agent runs nothing.

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

## How output renders

Rich hosts (ChatGPT, Claude Desktop / claude.ai) render interactive widgets for
tools like `flow.table`, `findings.list` and `proxy.status`. **Claude Code is
text-only**: it shows the tool's `structuredContent` JSON and renders no widget.
When you are in a text host, use the **aitmproxy-rendering** skill to turn that
JSON into clean markdown tables with method/status/severity labels.
