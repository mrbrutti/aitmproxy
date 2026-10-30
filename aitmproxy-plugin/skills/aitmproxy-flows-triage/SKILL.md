---
name: aitmproxy-flows-triage
description: Find and triage captured traffic in aitmproxy during an AUTHORIZED security test. Use when the user wants to list, filter, inspect, annotate or export captured HTTP/WebSocket flows — browse with flow.table, drill into one with flow.detail, mark and comment interesting flows, subscribe to live traffic, and export to native JSON or HAR. Covers flow.table vs flow.detail, filtering, marks/comments, and export/HAR.
---

# aitmproxy flows & triage

Find and triage the traffic aitmproxy captured for your **authorized** engagement.
All tools here are passive (read / annotate / export) — no upstream requests.

## Browse vs. drill in

- **`flow.table`** — the overview: one row per captured flow (id, kind, method,
  authority, path, status, duration, state, marks). Use it to scan and pick. In a
  rich host it renders as a widget; in Claude Code format it with the
  **aitmproxy-rendering** skill.
- **`flow.list`** — just the ids, oldest first, when you need raw ids to iterate.
- **`flow.detail --id <flow-id>`** — everything for one flow: request/response
  headers, bodies, connection info, timing, edit state. Control the body with
  `--body <none|inline|range>` (default inline) and `--offset`/`--length` to page
  through a large body instead of pulling it whole.
- **`flow.get --id`** — a one-line summary (kind, request line, status, state).

## Filtering & live capture

- **`flow.subscribe [--filter <json-object>] [--since <flow-id>]`** streams
  matching flows as notifications on the connection (returns a `sub_id`);
  **`flow.unsubscribe --sub_id`** cancels it. Use a filter to watch only the hosts
  or methods you care about.
- **`proxy.status`** shows listening state, whether intercept is armed, the
  paused-flow count, capturing state and visible flow count.
- **`proxy.pause` / `proxy.resume`** hide or re-show new flows (traffic still
  passes; paused captures stay reachable by id until eviction). **`flow.clear`**
  removes completed flows to reclaim history (in-flight/intercepted are kept).

## Annotate

- **`flow.mark --id --marks <json-array>`** sets a flow's highlight marks (e.g.
  colour names); an empty array clears them. Use marks to triage a working set.
- **`flow.comment --id --text`** attaches a free-text note; empty string clears it.

## Export

- **`flow.export [--ids <json-array>] [--format <aitm|har>] [--path]`** exports
  selected flows (or the whole store) as native `aitm` JSON or HAR 1.2 — returns
  bytes, or writes to `path`. Use HAR to hand evidence to other tools.
- **`flow.import [--path|--bytes] [--format]`** pulls flows back in (native,
  HAR, or mitmproxy `.flows`), marked `imported`. Passive: never replays.
- **`session.save --path` / `session.load --path`** persist or restore the whole
  flow store as a native session file (load is passive, no upstream requests).

## Triage flow

Scan `flow.table` → `flow.mark` the candidates → `flow.detail` each to confirm →
`flow.comment` your notes → `flow.export` the evidence. When a flow looks
exploitable, hand off to **aitmproxy-intercept-mutate** (to manipulate it live) or
**aitmproxy-findings-poc** (to build a reproducible PoC). Keep all activity within
the authorized scope.
