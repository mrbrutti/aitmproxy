---
name: aitmproxy-intercept-mutate
description: Intercept and mutate live traffic in aitmproxy during an AUTHORIZED security test. Use when the user wants to park in-flight HTTP requests or responses and edit them, tamper WebSocket frames, replay or craft requests, or drop/kill a connection. Covers arming interception (flow.intercept, ws.intercept), editing parked flows (flow.mutate, flow.resume, flow.kill, ws.frame, ws.send), active egress (flow.replay, request.send) and the scope gating that guards it.
---

# aitmproxy intercept & mutate

Manipulate live traffic on your **authorized** engagement: park a request or
response, edit it, forward or drop it, tamper WebSocket frames, and replay or
craft requests. Editing a parked flow is passive; anything that reaches upstream
is **active egress** and **scope-gated** (refused unless the host is in
`scope.list`). Respect the current `agent.status` policy — under `ask`, Sensitive
tools park for operator `agent.approve`; under `readonly`/`paused` they do not run.

## Arm interception

- **`flow.intercept [--enabled true|false] [--rules <json-array>]`** arms (default)
  or disarms parking. With no rules every request is parked (global arm); with
  rules only a request matching a rule at its phase is parked. A parked flow waits.
  A rule is an object with optional fields: `phase` (`request` default, `response`,
  `ws_frame`, `any`), `url` (a `*` wildcard string, or `{wildcard}` / `{regex}`),
  `method`, `host` (an exact authority string, or `{exact}` / `{wildcard}`),
  `ws_dir` (`c2s` / `s2c`), plus `id`, `name`, `enabled`. For example
  `rules: [{ "method": "POST", "url": "*/api/cart/*" }]`. How `url` matches:
  - Subject: the pattern is matched against the full URL
    (`scheme://host[:port]/path?query`) and against the path alone; either
    may match. Omit `url` to match any URL.
  - Wildcard: `*` matches any run, every other character is literal, and
    matching is case-insensitive. With a `*` the pattern must match the
    whole URL or the whole path (write `*httpbin.org*`, not `*httpbin.org`);
    without `*` it matches as a substring. A wildcard starting with `/`
    matches the path only, while `*/x*` can also match a host that starts
    with `x`, so add a `host` clause when the path is meant.
  - Regex: searched, case-insensitive; `(?-i)` opts out.
  - Limits: more than 256 rules, a pattern over 4096 bytes, an empty `url`
    pattern or an invalid regex rejects the whole call and leaves the active
    rules unchanged.
- **`ws.intercept [--enabled] [--rules]`** does the same for WebSocket frames
  (Phase::WsFrame): which live frames are parked for `ws.frame`.

Check `proxy.status` (`intercept_armed`, `paused` count) to see what is parked.

## Edit a parked flow

- **`flow.mutate --id --edits <json-object>`** edits in place. Edits apply to the
  **request** (method, path, headers, body); when the flow is parked at the
  **response** phase they apply to the response and `status` is valid. Use this to
  tamper a parameter, inject a payload, or rewrite a response for testing.
- **`flow.resume --id`** releases the (possibly mutated) flow so it is forwarded.
- **`flow.kill --id [--mode reset|429|503]`** aborts it: `reset` (default) drops
  it so the client sees a reset/closed connection; `429`/`503` answers the client
  with that status and an empty body and makes **no upstream request**.

## WebSocket frames

- **`ws.frame --id --index --action <...> [--data] [--opcode]`** acts on a parked
  frame: forward it (optionally editing data/opcode first) or drop it so the peer
  never receives it.
- **`ws.send --id --dir --opcode --data`** composes and injects a new frame onto a
  live conversation. **Active egress** — refused unless the flow's host is in scope.

## Replay & craft (active egress, scope-gated)

- **`flow.replay --id`** reissues a captured HTTP request through the proxy's
  guarded client and returns the new flow's id. Use it to re-trigger a response or
  confirm a behaviour before mutating.
- **`request.send --authority <host> [--method] [--scheme] [--path] [--headers] [--body]`**
  crafts a request from scratch through the guarded client and returns the captured
  flow's id. Use it to probe an endpoint directly.

Because `flow.replay`, `request.send` and `ws.send` emit real traffic, confirm the
target host is in the authorized scope first (`scope.list`); add it only if your
engagement covers it (`scope.add`, operator-gated from an agent frontend). `flow.kill`
with `429`/`503` gives the client an explicit status instead of a dropped
connection.

Once you have a working manipulation, capture it reproducibly with
**aitmproxy-findings-poc**.
