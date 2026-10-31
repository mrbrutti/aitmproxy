# Web UI adopts `/bus` push design

**Status:** approved 2026-10-30 (self-approved by the orchestrator under Matt's standing autonomous-approval instruction; R1, R2 and R4 stay open to veto). Body amended 2026-10-30 by the orchestrator under the same instruction, after the first real run and two panel rounds (the amendments are marked inline; no Architect ratification was sought).
**Research inputs:** none new. Builds on `docs/superpowers/specs/2026-10-30-web-bus-push-design.md` (PR #137, whose Design D7 names this change) and PR #124's poll loop. Reads: `apps/web/src/{bus/ws.ts, bus/types.ts, bus/mock.ts, bus/normalize.ts, state/app.ts, state/app.polling.test.ts, panels/agent/activity.ts, panels/agent/ActivityLog.tsx, shell/StatusBar.tsx}`, `crates/aitm-mcp/src/{server.rs, transport.rs}`, `crates/aitm/src/web/bridge.rs`, `crates/aitm-core/src/audit.rs`, `crates/aitm-plugins/src/{agent.rs, detail.rs}`, `tests/e2e/web/`.

## Intent

PR #137 made `flow.subscribe` work over the web `/bus` bridge, but the UI never calls it: it still polls `flow.list` every 500 ms (PR #124). This change makes the UI subscribe on every connection and receive live capture by server push, keeping #124's poll loop as the heartbeat and the fallback. Three client problems stand between "the server can push" and "the UI can safely consume it": a flow push is sparse and must not be written over a rich row; the `{lagged:true}` state line must not be applied; and every finished tool call, including the UI's own polling, now comes back as an audit line that would flood the Activity panel. This spec also settles a fourth thing found in recon: the audit lines the server sends do not match the type the UI declares for them, and the Activity panel already mis-renders them when it reads them through `agent.activity`.

## Goals

- A flow captured while a healthy subscription is live appears in the list within one coalescing window (100 ms) plus one `flow.detail` round trip, without waiting for a poll tick.
- With flow pushes arriving, the loop makes no `flow.list` call between its 10 s heartbeats; the heartbeat and the `backlog` rule still run; `proxy.polling` stays truthful.
- A refused, failing, or silent `flow.subscribe` never fails the connection: the UI behaves exactly as it does today (polling).
- A push never regresses a row: `startedAt`, `scheme`, sizes, timings, `kind` and `seq` of a polled row survive any push for it.
- `{lagged:true}` resyncs the list and is never applied to the proxy state.
- The Activity panel shows the operator's deliberate actions and all agent activity, not the UI's own polling, and shows server-shaped lines correctly (time, origin, result, args, error reason) whether they arrive by push or by `agent.activity`.
- The before/after call rate on `/bus` is measured against a real browser and recorded.

## Non-goals

- **Server changes.** Nothing under `crates/` changes. Two server gaps found in recon are follow-ups, not part of this work (R2, R4).
- **Idle load.** With no traffic the loop still polls every 500 ms (R1). That is #124's guard working as designed, not a defect here.
- Live WebSocket message counters. A known WS row keeps the counts from its first fetch, exactly as under polling today.
- Propagating a `flow.clear` made by another client. The server never pushes `cleared` and the poll never prunes; unchanged.
- A server state push (`push_state` still has no caller), an approval UI for `ask`-policy parking, the L4 poll in `state/context.tsx`, any status-bar change, the mac app, the TUI.
- Editing `tests/e2e/web/test_bus_live_stream.py` or `test_bus_poll_reflects_traffic.py`. Their docstrings are stale after #137; the e2e owner flips the canary to a hard fail. This change adds a new contract test beside them instead.

## Anti-goals

- A frozen list when push dies quietly. The heartbeat and the freshness gate are what prevent a repeat of the #124 freeze; weakening either is a failure.
- A row that goes backwards: an older reply landing after a newer one, a ghost row after `flow.clear`, a push summary written over a rich row.
- An Activity log that is mostly the UI talking to itself, or one that hides an agent action.
- A subscription failure that surfaces as a connection error, a toast, or a reconnect loop.
- Counting audit lines, state lines or the `lagged` marker as proof that the flow stream is alive.
- A second fetch path that drifts from `pollOnce`: one helper does the fetching for both.

## Constraints

- Client only (`apps/web`). The Rust gate is untouched; the web gate is `cd apps/web && npm run typecheck && npx vitest run && npm run build`. No new dependency.
- Existing `state/app.polling.test.ts` cases keep passing with their bodies unchanged (only where the harness is imported from may move).
- The bridge runs frames concurrently, at most `MAX_IN_FLIGHT = 16` per connection (`crates/aitm/src/web/bridge.rs:94`, `:273-285`, `:300-309`), and the browser sends each JSON-RPC line as its own frame (`ws.ts:83-86`). Requests are therefore **not** executed in send order; only an awaited reply orders two requests.
- The server's per-connection notification lane holds 4096 lines, then drops the oldest and sends `{lagged:true}` (`server.rs:32`, `:207-238`, `:308-315`). The audit ring holds 4096 entries (`audit.rs:25`).
- Security: flow pushes carry less than `flow.get`. The audit stream a subscriber now receives over `/bus` is the WEB server's, which records every operator- and agent-role call made over the bridge (command, redacted args, scrubbed error reason) and pushes it to subscribers of any role (PR #137 behaviour); `agent.activity` reads a different ring (the primary's), so this is not the same data it returns today. Role-filtering that stream is a server follow-up.

## Wire facts the design rests on

| Fact | Where |
|---|---|
| A flow push is `{event, id, summary}`; the HTTP summary is `{id, kind:"http", method, authority, path, status}`; a WebSocket summary is `{id, kind:"ws", handshake, messages}` | `server.rs:2149-2166`, labels `:2133-2145` |
| `flow.detail` reports `kind:"websocket"` (the UI's `toSummary` maps only that spelling, anything else becomes `http`) | `detail.rs:179`, `bus/normalize.ts:197` |
| The server pushes no `cleared` event and no state event except the `lagged` marker | `server.rs:1017-1038`, `:1042` (no caller), `:308-315` |
| `flow.subscribe` is handled before policy; refused only for a non-trusted role under `Paused`; an unknown tool is a JSON-RPC error | `server.rs:1441-1446`, `:1812-1823`, `:1454-1461` |
| A successful `flow.subscribe` is not audited; a refusal is; an unknown-tool RPC error is not | `server.rs:1405-1420` |
| Every other finished `tools/call` is audited, and the entry is pushed to every subscribed connection of any role | `server.rs:1587-1626`, `:1632-1640`, `:519-529` |
| The audit line is `{at:int ms, origin:"cli"\|"mcp"\|"operator", client_label:string\|null, command, args:string, result:"ok"\|{error}}` | `audit.rs:73-117` |
| `args` is a redacted JSON rendering capped at 512 bytes | `audit.rs:30`, `:88` |
| An operator-role subscriber also gets `notifications/aitm/agent {event:"approval_requested", command, args_summary, prompt, request_id}`, which has no `origin`, `at` or `result` | `server.rs:1758-1778` |
| The bridge builds one immutable `Arc<ConnCtx>` with `client_label: None`; only the TCP/stdio path copies `initialize.clientInfo.name` onto the connection | `bridge.rs:251-257`, `transport.rs:82-86`, `server.rs:81-93` |
| So an audit line for a call made over `/bus` has `client_label: null`, not `"aitm-web"` | derived from the two rows above |
| The real core has `agent.activity {since?, limit?}` (oldest first, whole ring) and `agent.status` returns `{policy, actions_last_minute, connected_clients}` with **no** `log` | `agent.rs:129-143`, `:208-283` |
| In production the web server is built without the primary's `agent_state`, so it never parks `ask` calls | `main.rs:425-442` |

## Design

**D1. Subscribe in `ws.ts` on every open, awaited before the bus is marked open. (Architect's call: unconditional, swallowed, timed out.)** In `sock.onopen`, after the `initialize` reply and `notifications/initialized` and before `setState('open')`/`settleReady()` (`ws.ts:152-172`), send `tools/call {name:'flow.subscribe', arguments:{}}` through the internal `request`, not `client.call` (which awaits `ready` and would deadlock). The reply is awaited, not fired and forgotten, because frames run concurrently (Constraints): only a reply proves the subscription exists before the bootstrap `flow.list` is sent, so no event can fall between the snapshot and the stream. Events captured in that gap arrive both ways and are idempotent by id.
- *Unconditional, not gated on `tools/list`.* The catalogue is fetched lazily after open (`ws.ts:209-215`); gating would put a second round trip and a cache dependency into the handshake. An older core answers an unknown-tool RPC error, which is unaudited (`server.rs:1405-1407`) and swallowed. Liveness is decided by observed pushes (D5), never by advertisement, as #124 requires.
- *Failure never fails the connection.* An `isError` result, a JSON-RPC error, or no reply within `subscribeTimeoutMs` (default 3000, an option so tests can shorten it) is swallowed: the bus opens, `lastError` stays null, polling covers it. The timeout stops a server that swallows unknown calls from bricking the handshake.
- *A dead socket is not opened.* If the socket closed or the user closed the bus while the subscribe was pending, the continuation returns without `setState('open')`; `onclose` has already scheduled the reconnect, whose `onopen` subscribes again.
- *Handlers are isolated* (amended after review round 1): each notification handler runs in its own try/catch in `onMessage`, so one throwing handler cannot skip the other handlers or the rest of a batched frame (which may carry the subscribe reply or a `flow.list` reply).
- *Notifications that arrive before the subscribe reply* reach handlers as usual (`ws.ts:117-120`; web-bus-push spec D6).

**D2. The subscribe outcome is not surfaced. (Architect's call.)** No new `BusClient` member, no store field, no status-bar change. `proxy.polling` means "open and no fresh flow push" (`app.ts:424-425`); a refused subscribe, an idle subscription and a dead push all leave it `true`, which is the truth in each case (the loop is the live source). Nothing in the UI reads the flag today (`StatusBar.tsx` shows only the bus address and state), so a refusal shows nothing: no toast, no colour change. A refused subscribe is retried only on the next reconnect; a policy change mid-connection is covered by polling.

**D3. A flow push is a trigger, never data. (Architect's call on every number.)** For a real bus (`bus.address !== 'fixtures'`, the same test `bootstrap` uses at `app.ts:605`), `onFlowEvent` stops calling `upsert(toSummary(n.summary, ...))` (`app.ts:269-283`). It queues the id; a coalescer fetches and upserts. The summary is ignored entirely.
- **Per event:** `cleared` clears the store, drops the pending set and bumps a clear epoch (so a reply still in flight is discarded, no ghost row). `ws_message` on a known flow is ignored (a chatty WebSocket would refetch an O(messages) detail ten times a second; live counters are a non-goal); on an unknown id it queues. Every other event queues the id. `response|mutated|meta|released|killed` also keep today's immediate work: drop the cached `details[id]` and reload the selected inspector detail (`app.ts:277-281`). `recomputePaused()` runs after the flush applies, and only when the flush carried `intercepted|released|killed`.
- **Coalescing:** a throttle, not a debounce. The first queued id arms one `PUSH_COALESCE_MS = 100` timer; later events for queued ids add nothing; the timer is not re-armed by traffic, so latency is bounded. At fire time the pending ids (insertion order = first-notification order = capture order) are taken and removed, so an event that arrives while their fetch is in flight re-queues and is refetched after it. One flush runs at a time; the next timer is armed when it finishes.
- **One shared fetcher.** `pollOnce` and the flush both call one helper that does what `pollOnce` does today inline (`app.ts:385-401`): `flow.detail {id, body:'none'}`, or `flow.get {id}` when the catalogue has no `flow.detail`; failures `.catch` to null and set `failedAt`; success clears it; rows are upserted inside one `batch`. The helper takes the id list, a per-id `seq` function and a wave size. `pollOnce` keeps its behaviour exactly (its ids, its `ids.indexOf(id)+1`, its single wave, so `peak.detail === 200` still holds), with one addition after review round 1: a reply that does not carry the requested id (an empty object, another flow's row) is a failed read for push AND poll (`failedAt` set, no row), so a ghost row `''` cannot appear. The clear epoch is captured once per `fetchRows` call, so a `flow.clear` stops every later wave of the same call.
- **Rules the flush adds on top:**
  - Skip ids held by `failedAt` (`FAILED_RETRY_MS`, `app.ts:349`); the hold-off is shared with the poll.
  - At most `PUSH_FETCH_WAVE = 16` `flow.detail` calls in flight, in waves, the same number as the bridge's `MAX_IN_FLIGHT`; each wave is applied in one `batch` in id order.
  - At most `PUSH_MAX_PENDING = 256` distinct pending ids. Beyond that the surplus is dropped and `backlog = true` is set, so the poll (capped at 200 per poll, oldest first, `app.ts:342`) reconciles; the 200-per-poll spirit is kept and memory stays bounded.
  - **Ordering and `seq`.** New ids are upserted in notification order, with `seq = entries.length + 1` taken at apply time (inside the batch, so consecutive new ids get consecutive numbers whatever order the replies came back in). A known id keeps its existing `seq`. This equals the poll's `ids.indexOf(id)+1` while the UI holds the capture order contiguously; any drift (a backlog gap) is repaired by the poll's pending re-reads, as today.
  - **Stale replies lose.** The helper stamps each fetch with a ticket per id; a reply applies only if no newer fetch for that id was issued since. Two concurrent fetchers (the poll's heartbeat and a flush) can no longer land out of order.
  - The flush runs only while `bus.state() === 'open'` and the catalogue is loaded (`toolsLoaded`); otherwise the pending set is dropped (not open: the reconnect resync in D5 covers it) or the flush is retried on the next timer (no catalogue yet: `flow.get` would give a thinner row than the poll's `flow.detail`).
- **Fixtures bus unchanged. (Architect's call.)** The mock's notifications carry complete, correctly-spelled summaries (`mock.ts:67-70`, `:279-280`) and the dev UI and perf harness rely on the synchronous path; for `fixtures` the old direct-apply path stays.

**D4. What `lastFlowPushAt` means.** Only a well-formed `notifications/aitm/flow` message advances it (amended after review round 1: the payload must be an object with a string `event` and a string `id`; anything else is ignored entirely) (`app.ts:315-316`), including ones that are ignored (`ws_message`) or that queue nothing; agent lines, state lines and the `lagged` marker never do. `lastStatePushAt` is advanced only by a *complete* state payload (D8). A flow notification whose payload is not an object with a string `event` and a string `id` is ignored entirely (after review round 1): it advances no clock and reaches no handler logic.

**D5. The poll loop is unchanged in spirit.** The tick still runs `pollOnce` when `backlog || !isFresh(lastFlowPushAt) || now - lastPollAt >= 10 s` (`app.ts:451`) and `pollStatus` every 2 s unless state is fresh (`:454`). Consequences, stated so nobody is surprised:
- *Healthy push under traffic:* no `flow.list` between heartbeats; `flow.detail` is called per coalesced id by the flush, not by the poll's re-reads.
- *Idle, subscription confirmed, no traffic:* `lastFlowPushAt` never advances, so the loop keeps polling at 500 ms. A confirmed subscription cannot be told from a dispatcher that is not fed (the web-bus-push D1 trap) until a push arrives, and #124's guard exists to refuse that guess. **Idle load is unchanged by this work (R1).**
- *Push goes quiet:* after 10 s without a flow notification the loop returns to 500 ms (the existing test `resumes polling after 10 s without a flow notification` stays).
- *Reconnect:* when the bus becomes `open`, reset both push clocks, clear `failedAt` and drop the pending set, so the next tick takes a fresh snapshot even if a push was fresh 2 s before the outage. Without this, flows captured during a short outage stay missing until the 10 s heartbeat. (Architect's call: found in recon, same family as problem 1.)
- *`lagged`:* (amended: handled only while the bus is `open`, a poll started into a connecting bus would park on `ready` and stall the loop) do not apply it; do not advance any clock; reset `lastFlowPushAt` so push is distrusted until the next flow notification; run `pollOnce` now (not on the next tick), single-flight with exactly one trailing poll if the marker arrives while a poll is running. No audit catch-up (amendment, see D7). `pollStatus` is not needed: the server pushes no state, so nothing in the status was dropped, and the 2 s status poll keeps its cadence (a `lagged` line today advances `lastStatePushAt` and backs it off to 10 s, `app.ts:320`, `:454`; that stops).
- *`proxy.polling`* keeps its #124 definition. It is `false` only while flow pushes are fresh.

**D6. Reconcile the audit line with the UI model. (Architect's call.)** One function, `toAgentEntry(raw): AgentNotification | null` in `bus/normalize.ts`, maps both the server shape and the fixture bus's model shape to the model the log already renders, so `ActivityLog`, `atMs` and the existing `activity.test.ts` stay as they are.

| Field | Server sends | UI type says today | What happens today | Model after |
|---|---|---|---|---|
| `at` | integer epoch ms | ISO `string` | `Date.parse(1730000000000)` is `NaN`, the time cell shows a dash (`activity.ts:91-94`, `ActivityLog.tsx:86`) | ISO string converted from ms |
| `origin` | `"cli"\|"mcp"\|"operator"` | `'mcp'\|'cli'\|'mac'\|'web'\|'tui'` | `operator` prints as text; `mcp` gets the agent badge | union gains `'operator'` |
| `client_label` | string or null | absent | not shown | `clientLabel?: string \| null` |
| `args` | JSON string, redacted | `unknown` (an object in the mock) | `summarizeArgs(string)` shows a JSON-quoted string with escaped quotes | parsed to an object when it is valid JSON, else the raw string |
| `result` | `"ok"` or `{error: reason}` | `'ok'\|'error'` | the Errors chip misses it (`e.result === 'error'` is false for an object, `activity.ts:68-69`), `data-result="[object Object]"`, no reason in the tooltip (`ActivityLog.tsx:101`) | `'ok'\|'error'` plus `detail` = the reason |

Strings are bounded (amended after review round 1): `clientLabel` is cut to 128 characters, `detail` to 2048, and a string `args` to 2048 BEFORE it is parsed (a longer value then simply stays text), because the 500-entry cap bounds the count, not the size.

A line with an `event` field (`approval_requested`), without a string `command`, or without a string `origin` is not an audit entry (amended: the implementers made `origin` required because the model type requires it and the server always sends it; an unrecognised or missing `result` is shown as `'error'`, never hidden): `toAgentEntry` returns null and the store ignores it (no approval UI exists; R4). The real `agent.status` carries no `log` (`agent.rs:129-143`), so the fallback at `app.ts:541` is dead on a real core; the real snapshot is `agent.activity`, which the store calls with no `limit` and replaces the log with, uncapped (`app.ts:545-550`), and which already contains the UI's own polling on a core that serves it. **Amendment (measured 2026-10-30, real `aitm web`):** over `aitm web` the `agent.activity` ring is EMPTY: the web server is a second `McpServer` whose own ring records the UI's calls and pushes them, but `AgentActivity` reads the primary server's ring (`crates/aitm/src/main.rs:429` attaches it only to the primary). So on `aitm web` the Activity panel is fed by push alone, the flood is new with push, and the filter below covers the PUSH path only (the snapshot is normalized and capped, never filtered, see the D7 third amendment). The server gap is a follow-up, out of scope.

**D7. The Activity flood rule. (Architect's call.)** Drop a line iff **all** hold:
1. `result === 'ok'` (a failing poll is signal and is kept);
2. `command` is in `UI_BACKGROUND_READS`, the exact set of reads the UI issues on timers or in bulk refreshes: `flow.list`, `flow.detail` (ONLY with `args.body === 'none'`, the poll's exact shape; a `flow.detail` that asks for bodies is a content read and is kept), `proxy.status`, `agent.status`, `agent.activity`, `scope.list`, `poc.list`, `l4.flow.list`, `l4.flow.get`, `l4.scope.list`, `l4.capture.status`, `l4.agent.status`, `l4.intercept.status`, `l4.intercept.list`, `browser.tabs`, `browser.screenshot`. (Amended after review round 2: `flow.get` is out of the set, it reads a whole flow and the UI only calls it as the fallback poll against a core that has no `flow.detail`, which a pushing core always has; `l4.flow.get` stays IN, the L4 store polls it per session every 1.5 s (`state/context.tsx:17`, `panels/l4/store.ts:68`); 16 commands.)
3. it is ours: `clientLabel == null` and `origin` equals this connection's own origin (`bus.role()`: `operator` maps to `operator`, `agent` maps to `mcp`; an unknown role matches nothing by origin).

Rejected: *drop every line from our label* (hides the operator's own `flow.kill`, `scope.add`, `agent.set`, the actions the panel exists to show, and the label is null today anyway); *coalesce or cap only* (at the idle rate of about 2.5 calls/s a 500-entry cap is gone in 200 s, under traffic in seconds, so real rows are buried however the cap is tuned).

What stays: every non-read command from anyone; every error; every non-null-label line and every line of another origin (over `/bus` no client is labelled, whatever `clientInfo.name` it sends: the bridge never copies it onto the connection); other frontends' reads (the mac app's `aitm-mac` polling is another frontend's activity, shown as today). What goes: this UI's successful background reads (with `flow.detail` only in its `body:'none'` poll shape, so an operator's inspector click, which asks for bodies, stays visible). The corner this cannot separate: another `/bus` client on the same token and role (an agent on `aitm web`'s default agent token, say) looks like this UI, so its successful background reads from that set are dropped from the push-fed log; every write and every error is kept regardless, and a content read (`flow.get`, a `flow.detail` with bodies) is kept. Exact own-ness needs the server to stamp a connection id on audit lines (R2 follow-up); naming the client does not help, because the bridge ignores `clientInfo`.

The same intake serves the live push and the `agent.activity` snapshot: normalize, drop noise (push path only), append (push) or replace (snapshot), then keep the newest `ACTIVITY_CAP = 500`. The cap now counts only what is shown, so it stays meaningful; the snapshot is capped too (it is not today). **Amendment (orchestrator, 2026-10-30):** the dedupe tail and the `lagged` audit catch-up (`agent.activity {since}`) are CUT. Over `aitm web` the ring they would read is empty (D6 amendment), so the catch-up could only ever return nothing there, and nothing else needs the dedupe. **Third amendment (security review round 1, 2026-10-30):** the `clientLabel === 'aitm-web'` clause is REMOVED (a self-declared `initialize.clientInfo.name` can be forged by an agent to hide its reads from the operator's Activity log, and no legitimate bridge line carries it: bridge audit lines have `client_label: null`), and the noise filter applies to the PUSH path only, never to the `agent.activity` / `agent.status.log` snapshot (that is the primary server's ring: it holds other transports' calls and never this UI's). Residual, accepted and documented: a second `/bus` client under the same token and role is indistinguishable from this UI on the push path, so its background reads are hidden while its writes and errors are kept. Exact own-ness needs the server to stamp a connection id on audit lines (follow-up). Do not "tighten" the rule to a client-declared label. **Second amendment:** a snapshot that keeps zero entries (empty ring, or everything dropped as noise) leaves the live log untouched; only a snapshot with at least one kept entry replaces it. Without this, every `refreshSide` (a scope edit, a PoC run) would wipe the push-fed log with the empty `aitm web` snapshot. **Fourth amendment (security review round 2):** a `{lagged:true}` marker appends one synthetic Activity row (origin `operator`, command `audit-log`, result `error`, detail saying that the push stream lagged and audit lines may be missing from this log) so the operator can see the gap; recovery of the lost lines stays a server follow-up. A lag can drop audit lines from the live log; that is accepted and recorded as a follow-up together with the server gap (the web server's ring must back `agent.activity`).

**D8. State notifications are validated. (Architect's call.)** `onState` applies a payload only if `listening` and `intercept_armed` are booleans; anything else (the `lagged` marker, a future partial push) writes nothing and advances no clock. Today the marker sets `listening`, `armed` and `agent` to `undefined`, which in a Solid store deletes the property, and zeroes throughput and memory (`app.ts:285-298`).

**D9. Measurement.** Method, not code, so the result is reproducible and honest:
- *Instrument (amended after the first real run):* every audited call is pushed as a `notifications/aitm/agent` line with `origin` and `at` (`audit.rs:73-101`) to every subscriber, so the measuring script counts the lines its own subscription receives. It does NOT read the ring: over `aitm web` `agent.activity` returns `[]` (D6 amendment, `main.rs:429`). A small Node script (`apps/web/scripts/bus-load.mjs`, same style as `bus-probe.mjs`, global `WebSocket`) is a **separate** bus connection; it calls nothing but `flow.subscribe` (and one `flow.list` after the windows for the size line). Both the UI and the script reach the core as bridge connections with `client_label: null` (R2), so the script attributes calls by `origin` (`--ui-origin`, default `mcp` because `aitm web`'s default token is the agent token) and, because it makes no `agent.activity` call during a window, has nothing of its own to exclude. It counts the audit lines its subscription receives, and the flow vs audit notification rates a subscriber is sent.
- *Windows:* idle (page open, no traffic, 30 s) and traffic (default 20 req/s for 30 s through the proxy to a loopback origin the script starts, store seeded to at least 500 flows so `flow.list` has a real cost). 30 s at the traffic rate stays under the subscriber lane's 4096 lines; the script warns if its own subscription lags.
- *A/B with two binaries.* `apps/web/dist` is embedded into `aitm` at compile time (`crates/aitm/build.rs`), so each variant is a build of the UI followed by a build of `aitm`, copied aside: `aitm-before` from this branch's starting commit (taken before Task 1 lands), `aitm-after` from the finished branch. Each is run alone as `aitm web --listen 127.0.0.1:8082 --token T --no-open` and measured at its own printed URL. (Serving a second UI build through `vite preview` is not an option: the bridge refuses an `Origin` whose authority differs from `Host` (`bridge.rs:515-540`), and the repo's proxy sets `changeOrigin: true`.) The shared cargo target dir can hand back a stale embed, so touch `crates/aitm/build.rs` before each build. A real browser only has to hold the page open; the preview browser tools or any browser will do.
- *Reported:* UI calls/s by command, idle and traffic, before and after; `flow.list` result size (ids and bytes) at the end, since the payload scales with the store; subscriber notifications/s by kind.
- *Result goes* to `docs/superpowers/web-ui-bus-push-measurement.md` and the PR body.
- *Expected, stated up front so a surprise is a finding:* `flow.list` falls from about 2/s to the heartbeat (about 0.1/s) under traffic; `flow.detail` per new flow stays within a factor of about 2 of before (one or two refetches per flow against the poll's discovery plus pending re-reads); idle is unchanged; total calls/s under traffic may not fall, the win is the list scan, its payload, and latency.

**D10. Comments and docs.** The comment above the poll loop (`app.ts:329-337`) says nothing calls `flow.subscribe` and the bridge pushes nothing; it is rewritten. The header of `app.polling.test.ts` keeps the regression story and adds one line pointing at the push tests.

## Acceptance criteria

Each is verified by the named test; case names are the `it(...)` titles (underscored here for readability, written as sentences in the files). The plan maps each to its task.

*Connection (`apps/web/src/bus/ws.test.ts`)*

1. AC1: On every open the client sends, after `initialize` and `notifications/initialized`, `tools/call {name:'flow.subscribe', arguments:{}}`, and the bus is not `open` (and `ready` waiters are not released) until that call settles. `subscribes_after_initialized_and_before_open`.
2. AC2: Each reconnect subscribes again on its new socket before opening. `resubscribes_on_every_reconnect`.
3. AC3: A subscribe that returns `isError`, a JSON-RPC error, or never answers still opens the bus, with `lastError() === null` and no reconnect. `a_refused_subscribe_still_opens`, `an_unknown_tool_error_still_opens`, `a_silent_subscribe_times_out_and_opens`.
4. AC4: A socket that closes (or a user `close()`) while the subscribe is pending is never marked open; the reconnect subscribes again. `a_socket_that_closes_during_subscribe_is_not_marked_open`.
5. AC5: A notification that arrives before the subscribe reply reaches the handlers. `notifications_before_the_subscribe_reply_reach_handlers`.

*Push as trigger (`apps/web/src/state/app.push.test.ts`)*

6. AC6: A push for an unknown id causes exactly one `flow.detail {id:'f_1', body:'none'}` within 150 ms and no `flow.list`; the row is `kind:'http'`, `method:'GET'`, `authority:'cdn.shop-staging.test'`, `path:'/assets/app.css'`, `status:304`. `a_flow_push_for_a_new_flow_is_refetched_via_flow_detail`.
7. AC7: A sparse push (`kind:'ws'`, no times, no sizes) for a row already loaded by the poll leaves the row deep-equal to what it was, `seq` included. `a_sparse_push_does_not_overwrite_a_rich_row`.
8. AC8: Five events for one id in one window make one `flow.detail`; an event arriving while that id's fetch is in flight is refetched after it. `events_for_one_flow_within_the_window_make_one_detail_call`, `an_event_during_an_in_flight_fetch_is_refetched_after_it`.
9. AC9: Three new ids land in notification order with `seq` 1, 2, 3 even when their replies return in reverse; a known id keeps its `seq`. `new_flows_land_in_notification_order_even_if_replies_reorder`, `a_known_flow_keeps_its_seq`.
10. AC10: The shared fetcher's rules hold for push: a flow whose detail fails is not retried inside `FAILED_RETRY_MS` and is retried after; a 100-id burst never has more than 16 `flow.detail` in flight and all 100 rows arrive; 300 distinct ids exceed the pending cap and the poll delivers the rest; with no `flow.detail` in the catalogue `flow.get` is used. `a_push_for_an_unreadable_flow_is_held_off_then_retried`, `a_burst_of_pushes_never_has_more_than_16_detail_calls_in_flight`, `overflowing_the_pending_cap_hands_the_rest_to_the_poll`, `falls_back_to_flow_get_without_the_flow_detail_tool`.
11. AC11: A reply that was issued earlier never overwrites one issued later; `cleared` drops pending ids and discards a fetch already in flight. `an_older_reply_never_overwrites_a_newer_one`, `a_cleared_event_drops_pending_and_in_flight_fetches`.
12. AC12: Post-event behaviour is kept: a `response` push on the selected flow drops its cached detail and reloads it (a `flow.detail {id}` without `body`); an `intercepted` push puts the id in `proxy.pausedIds` after the refetch and a `released` push removes it. `a_response_push_invalidates_cached_detail_and_reloads_the_selected_flow`, `an_intercepted_push_marks_the_flow_paused_after_the_refetch`, `a_released_push_clears_the_paused_mark`.
13. AC13: `ws_message` on a known flow makes no call; on an unknown id it does. `ws_message_pushes_refetch_only_unknown_flows`.
14. AC14: On the `fixtures` bus a push is applied directly with no `flow.detail`. `the_fixtures_bus_still_applies_the_summary_directly`.
15. AC15: The flush makes no call while the bus is not open and waits for the tool catalogue. `a_flush_does_nothing_while_the_bus_is_not_open`, `a_flush_waits_for_the_tool_catalogue`.
16. AC16: With a new flow captured and pushed every second for 25 s, `flow.list` is called at most 3 times (the heartbeats) and `proxy.polling` is `false`. `with_healthy_push_flow_list_runs_only_on_the_heartbeat`. The existing `push-capable bus stays cheap` cases in `app.polling.test.ts` keep passing unchanged.

*Resync (`apps/web/src/state/app.resync.test.ts`)*

17. AC17: `{lagged:true}` triggers a `flow.list` within 50 ms (not on the next tick), leaves `proxy.listening === true`, `proxy.armed === false`, `proxy.agent === 'all'`, does not slow the status poll (still 3 or 4 `proxy.status` calls in 8 s), makes the next tick poll even if a flow push was fresh, and a marker arriving during a running poll causes exactly one trailing poll. `lagged_triggers_an_immediate_flow_list_and_is_never_applied`, `lagged_does_not_back_the_status_poll_off`, `lagged_distrusts_push_freshness_until_the_next_flow_push`, `lagged_during_a_poll_schedules_one_trailing_poll`.
18. AC18: A state payload without boolean `listening` and `intercept_armed` writes nothing. `a_partial_state_payload_writes_nothing`.
19. AC19: Agent lines and state lines for 8 s do not make the flow stream fresh (`flow.list` keeps the 500 ms cadence, `proxy.polling` stays `true`). `agent_and_state_notifications_do_not_make_the_flow_stream_fresh`.
20. AC20: After a reconnect the next tick takes a snapshot even though a flow push was fresh before the outage, and a flow held by `failedAt` is retried. `a_reconnect_resnapshots_even_when_push_was_fresh`, `a_reconnect_forgets_held_failures`.

*Audit lines*

21. AC21 (`bus/normalize.test.ts`): `toAgentEntry({at:1730000000000, origin:'mcp', client_label:'claude-code', command:'flow.replay', args:'{"id":"f_1"}', result:'ok'})` equals `{at:'2024-10-27T03:33:20.000Z', origin:'mcp', clientLabel:'claude-code', command:'flow.replay', args:{id:'f_1'}, result:'ok'}`; `result:{error:'refused: x'}` gives `result:'error'`, `detail:'refused: x'`; a non-JSON `args` string stays a string; a fixture-model entry passes through; an `approval_requested` line and a line without a `command` give `null`. `toAgentEntry_maps_the_server_shape`, `toAgentEntry_maps_an_error_result`, `toAgentEntry_keeps_unparseable_args_as_text`, `toAgentEntry_accepts_the_fixture_model`, `toAgentEntry_rejects_non_audit_lines`.
22. AC22 (`bus/noise.test.ts`; the rule moved out of `panels/agent/` after review round 1, the view logic stays in `panels/agent/activity.ts`): `isUiPollNoise` is true for an `ok` `flow.list` with `clientLabel: null` and `origin` equal to the own origin, and false for ANY non-null label including `'aitm-web'` (amended: a self-declared label is forgeable); false for `flow.kill` from our origin, for an errored `flow.list`, for `flow.list` labelled `claude-code`, for an `mcp` `flow.list` when our origin is `operator`, and when our origin is unknown and the label is null. `isUiPollNoise_matrix`, `ownOriginOf_maps_roles`, plus the literal 17-member pin.
23. AC23 (`state/app.activity.test.ts`): a pushed server-shaped line becomes one retained entry with the normalized fields; 200 own `flow.list` lines retain 0 entries while one operator `flow.kill` and one `mcp` `flow.replay` retain 2; 600 distinct kept lines leave exactly 500, the newest; an `approval_requested` line is ignored; the `agent.activity` snapshot is normalized and capped to the newest 500 but NOT noise-filtered; an empty snapshot, or one whose lines all normalize to nothing, leaves the live log untouched. (Amended: the dedupe and `lagged` catch-up cases are cut, the zero-entry rule and push-only filtering are added, see D7.) `a_pushed_audit_line_is_normalized`, `the_uis_own_polling_is_dropped_but_actions_and_agent_lines_are_kept`, `the_log_is_capped_at_500_newest`, `an_approval_request_line_is_ignored`, `the_snapshot_is_normalized_and_capped_but_not_filtered`, `an_empty_snapshot_does_not_wipe_the_pushed_log`, `a_snapshot_of_only_non_audit_lines_does_not_wipe_the_pushed_log`.

*Real core and measurement*

24. AC24 (`tests/e2e/web/test_bus_push_ui_contract.py`, `python3 tests/e2e/run.py web` against a built `target/debug/aitm`): over the real `/bus`, `flow.subscribe` returns an integer `sub_id`; real proxied traffic yields a `notifications/aitm/flow` whose `summary` has exactly the keys `id, kind, method, authority, path, status`; `flow.detail {id, body:'none'}` for that id returns `kind:'http'` with `request`, `client_conn`, `meta`; a following `flow.list` call produces a `notifications/aitm/agent` with integer `at`, `origin:'mcp'`, `client_label: null`, `command:'flow.list'`, string `args`, `result:'ok'`; and no agent line names `flow.subscribe`. Pins the facts D3, D6, D7 rest on; if the server later labels bridge connections, it fails and D7 is revisited.
25. AC25 (`docs/superpowers/web-ui-bus-push-measurement.md`): exists with the before/after tables in D9 and the method; under traffic the after-build UI's `flow.list` rate is at most 0.3/s; idle is reported as unchanged; the note's headline is quoted in the PR body.
26. AC26: `cd apps/web && npm run typecheck && npx vitest run && npm run build` pass; every case in `app.polling.test.ts` passes with its body unchanged.

## Left to the builder

- Names, locations and shapes of internal helpers and constants in `app.ts` beyond those named here; whether the reconnect reset is a `createEffect(on(bus.state, ...))` or another hook on the same transition.
- How the shared fetcher stamps tickets and the clear epoch.
- The exact `UI_BACKGROUND_READS` container type.
- Test-double structure in the shared test kit, provided the existing polling cases keep their bodies.
- The script's flags and output format beyond the reported quantities in D9.

## Risks and the defaults chosen

- **R1. Idle is not reduced.** The freshness gate cannot trust a quiet subscription. *Default: accept; report it.* Follow-up worth its own spec if the measurement says it matters: a latch that trusts a push proven once on this connection through silence, falls back to 500 ms when a heartbeat poll finds a flow the push missed, and resets on reconnect.
- **R2. The bridge does not label its connections** (`bridge.rs:251-257`), so the UI's audit lines carry `client_label: null` and own-ness is inferred from origin plus command (D7). *Default: ship the inference; pin it with AC24.* Follow-up (server): stamp a server-assigned connection id on audit lines so the UI can drop exactly its own background reads. Do NOT copy `initialize.clientInfo.name` onto the bridge connection and trust it: a client-declared name is forgeable (D7 third amendment).
- **R3. Push may issue more `flow.detail` calls than the poll for slow flows** (one per coalescing window with activity). *Default: 100 ms window, measured in D9; if `flow.detail` per new flow exceeds 2.5, raise the window to 250 ms in a follow-up commit, not a redesign.*
- **R4. An operator-role UI now receives `approval_requested` lines and the UI has no approval handler.** Today this is dormant: the web server never parks (`main.rs:425-442`). If the web server ever shares the primary's `agent_state` under `ask`, an agent call would park for up to 120 s (`server.rs:57`) with nobody able to answer in the web UI. *Default: ignore the line (D6); flag for the approval-UI work.*
- **R5. A background tab throttles timers**, so a flush can be late by a second or more; pending ids are bounded at 256 and the poll reconciles. *Default: accept.*
- **R6. `seq = entries.length + 1` can drift from the core's position after a backlog gap.** The poll's pending re-reads repair it, as they do today. *Default: accept.*
- **R7. Subscribing adds up to 3 s to a connect against a server that swallows unknown calls.** *Default: accept; it only applies to a misbehaving server.*
- **R8. One flusher at a time means a `flow.detail` reply that never arrives holds later pushes until the socket closes** (`bus.call` has no per-call timeout). The poll is a separate path and keeps the list advancing at heartbeat cadence, so the list cannot freeze. *Default: accept; add a per-wave timeout only if the measurement or a field report shows stuck replies.*
- **R9. The audit echo adds one notification per UI call** (about 250 bytes). Unavoidable without a server filter; dropped cheaply on arrival (D7). *Default: accept; the measurement reports it.*

## Open questions

None. Every decision above has a default; R1, R2 and R4 are the ones to veto if wrong.

## Architect's calls, for approval

1. Unconditional `flow.subscribe`, awaited before open, swallowed on any failure, 3 s timeout, no surfaced status.
2. Push is a trigger for real buses; the `fixtures` bus keeps direct apply.
3. 100 ms throttle (not debounce), one flusher, waves of 16, 256 pending cap that falls back to the poll.
4. New ids take `seq = entries.length + 1` in notification order; known ids keep `seq`; stale replies lose by ticket; `cleared` bumps an epoch.
5. `ws_message` on a known flow is ignored.
6. Freshness gate unchanged: idle is not reduced; reconnect and `lagged` reset freshness.
7. `lagged`: resync with `pollOnce`, not `pollStatus` (amended: no audit catch-up, see D7).
8. Partial state payloads are ignored.
9. One `toAgentEntry` normalizer for push and snapshot; `at` stays an ISO string in the model.
10. Flood rule D7, applied to the push path only (amended after the security review: never to the snapshot, no label clause); cap 500 after filtering; no dedupe tail; a snapshot keeping zero entries leaves the live log alone.
11. `approval_requested` is ignored.
12. Measurement from the notification stream a separate-connection script subscribes to (the web ring is empty) and a two-binary A/B (never vite preview); result in a docs note and the PR body.
13. The two existing e2e web files are left alone; a new contract test is added.
