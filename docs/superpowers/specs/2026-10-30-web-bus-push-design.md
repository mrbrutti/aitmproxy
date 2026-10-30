# Web `/bus` push (`flow.subscribe` over the bridge) design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode, per the lead session's brief)
**Research inputs:** none new. Reads `crates/aitm-mcp/src/{server,transport}.rs` (the `NotificationSink`, `serve_lines`), `crates/aitm/src/web/bridge.rs` (PR #103's concurrent relay), `crates/aitm/src/main.rs` (web wiring), `tests/e2e/web/test_bus_live_stream.py` (the canary).

## Intent

`flow.subscribe` over the web `/bus` bridge is refused today: the bridge builds a fresh `ConnCtx::new(role)` (conn_id 0, `out: None`) for every frame, so there is no push sink and no stable connection to attach a subscription to. The shipped UI therefore has to poll `flow.list`. This change gives every authenticated bridge connection one stable `ConnCtx` with a bounded `NotificationSink`, and drains that sink onto the websocket, so subscriptions work over `/bus` exactly as they do over loopback TCP. It also has to make the web bridge's `McpServer` actually receive core events, which today it does not (see Design D1).

## Goals

- A `/bus` connection that sends `flow.subscribe` receives `notifications/aitm/flow` frames as flows are captured, interleaved with ordinary replies on the same socket.
- Every property of the PR #103 relay is kept: token auth first, role per connection, at most `MAX_IN_FLIGHT` (16) frames in flight, 256-line frame cap, bounded close handshake, 16 MiB frame cap, replies within a frame in line order.
- Per-connection push memory is bounded (the sink's notification lane, `push_capacity`, default 4096 lines, drop-oldest plus a `lagged` marker); a client that stops reading cannot grow it.
- A connection's subscriptions are removed when it ends, on every exit path, including a frame still running when the connection drops.
- Pushes respect roles: an agent-role connection never receives operator-only notifications (`approval_requested`).
- The e2e canary `tests/e2e/web/test_bus_live_stream.py` flips from SKIP to PASS against a real `aitm web`.

## Non-goals

- No change to who can run what: no policy, role, scope, or command-gating change; `flow.subscribe` stays a `Read` command refused for the agent role only under `Paused`.
- No web UI change in this PR (see Design D7). The UI keeps polling.
- No state-push producer: `McpServer::push_state` still has no caller; this change does not add one.
- No write timeout on slow websocket clients beyond the existing bounds (accepted residual, see Constraints).
- No change to the TCP, stdio, or streamable-HTTP transports' behaviour.

## Anti-goals

- A bridge that pushes nothing because the web `McpServer` is not fed (the trap in D1).
- A subscription that outlives its connection, including via the late-`flow.subscribe` race (D4).
- A second, parallel notification path (the bridge reuses `NotificationSink`, `Subscriptions`, `ConnCtx`, not a copy).
- Replies reordered within a frame, or any reply dropped.

## Constraints

- Memory: the notification lane is bounded by `McpServer::push_capacity()` (drop-oldest). The reply path is unchanged: at most `MAX_IN_FLIGHT x MAX_LINES_PER_FRAME` replies are held, and the loop's `ws.send(..).await` is the backpressure.
- A client that never reads pins only its own task and a bounded sink, the same exposure as before for pipelined requests. Accepted; a write timeout is a follow-up if wanted.
- Security: pushes reach only a connection that authenticated and subscribed. Cross-role fan-out stays exactly as `Subscriptions::{fanout_flow, fanout_state, fanout_role}` define it.
- `confirm_tokens` bind `{conn_id, command, fingerprint}`. Today every bridge connection shares `conn_id` 0, so an operator confirm token minted on one web connection is redeemable from any other. A unique `conn_id` per connection tightens this (a `_confirm` two-step must now stay on one connection). Call it out in the PR.
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`. Socket tests bind loopback; the Bash sandbox cannot, so they run in the Terminal panel.

## Design

**D1. The web server must be fed (decided, found during recon).** `main.rs` builds the web bridge's `McpServer` as a *second* server (`tui::server(..)`, "`serve` consumes the first") with no `.with_push(..)`. The push dispatcher (the `tokio::spawn` loop that turns core `Event`s into `notifications/aitm/flow` and fans them to subscriptions) lives inside `McpServer::serve`, which only the primary server runs, and each server owns its own `Subscriptions` registry. So bridge subscriptions would sit in a registry nothing ever feeds. Fix: extract the dispatcher spawn into `pub fn spawn_push_dispatcher(self: &Arc<Self>)` (a no-op without a push sender; `serve` calls it, so there is one code path), build the web server `.with_push(push_tx.clone())`, and call `spawn_push_dispatcher()` on it in `main.rs`. Each server subscribes to the broadcast with its own receiver. The primary's registry is untouched, so agent `Ask` parking, which asks the primary's registry whether an operator is subscribed, is unaffected by web connections.

**D2. One `ConnCtx` per bridge connection.** After a token classifies, build `Arc<ConnCtx>` with `role`, `conn_id = mcp.next_conn_id()`, `out = Some(NotificationSink::new(mcp.push_capacity()))`, `client_label = None` (unchanged). Every frame task receives a clone of the `Arc`; `handle_on(&ctx, line)` is unchanged. Nothing is minted before auth.

**D3. Drain arm.** The relay `select!` gains a third arm, `_ = sink.wait()`, which drains the sink and sends each line as one text frame. Replies keep going straight to `ws.send` from the frame-done arm in line order; the sink's reply lane is unused by the bridge, so notifications never sit behind replies and replies are never queued twice. `Notify` stores a permit, so a push while another arm is mid-`send` is not lost. The arm is not gated on `MAX_IN_FLIGHT`, so pushes flow even while the read arm is paused at the cap. `select!` chooses among ready arms at random, so neither replies nor pushes starve the other. The `lagged` marker (`notifications/aitm/state {lagged:true}`) is emitted by `drain` as for TCP.

**D4. Teardown on every exit path.** A guard created right after auth runs, in this order, `sink.close()` then `mcp.drop_connection(conn_id)` when `relay` returns by any path (client close, error, refusal, a panicked frame), so the close handshake's bounded drain does not keep subscriptions alive indefinitely. Because frames are detached and can outlive the connection (a blocking `invoke` cannot be cancelled), a frame can run `flow.subscribe` *after* teardown. So `NotificationSink` gains `is_closed()`, and `Subscriptions::add` refuses (returns `None`, surfaced as a tool error) when the sink is closed, checked under the registry lock. Close-before-drop plus check-under-lock means a late subscribe is either refused or removed by the already-pending `drop_connection`.

**D5. Roles.** Fan-out is unchanged: flow events go to every matching subscription of any role (as over TCP); state lines to every subscribed connection; `approval_requested` only to `Operator`-role subscriptions (`fanout_role`). Over the bridge an agent-token connection is `Frontend::Mcp`, so it never receives operator-only lines.

**D6. Replies and notifications interleave; subscribe-reply ordering.** A notification can arrive before the reply carrying its `sub_id`. Clients correlate replies by JSON-RPC `id` and must not assume the subscribe reply comes first (same as TCP).

**D7. UI (decided: not in this PR).** Two client problems make adopting push a separate change that must land after PR #124 (which rewrites `bootstrap` and the poll loop in `state/app.ts` and is still open): (a) the server's push `summary` is sparse (`{id, kind, method, authority, path, status}`, with `kind:"ws"` where the UI expects `websocket`), and `upsert(toSummary(..))` of it over a rich polled row resets `startedAt`, `scheme`, sizes, and timings; (b) the `{lagged:true}` state line fed to `onState` sets `listening/armed/agent` to `undefined`. Adoption needs "treat a flow push as a trigger to refetch via `flow.detail`" and "on `lagged`, resync, do not apply". That is not small, and it conflicts with #124's app.ts. Follow-up, after #124 merges. The e2e canary subscribes itself, so it does not need the UI.

**D8. Docs.** Update the `bridge.rs` module doc (push, one ctx per connection) and the `main.rs` comment on the web server.

## Acceptance criteria

1. AC1: A bridge connection that sends `flow.subscribe {}` gets `{sub_id}` (no "only meaningful over a streaming MCP connection" error), and a later `notifications/aitm/flow` for a stored flow arrives on that socket with `params.id` equal to the flow id.
2. AC2: With a notification stream flowing, replies still arrive, in line order within a frame, and a slow `test.sleep`/`test.block` reply does not stop pushes (and pushes do not stop replies).
3. AC3: After the client disconnects (socket dropped or Close), the connection's subscriptions are gone: an agent `Ask`-policy Sensitive call made afterwards is refused immediately with the "no operator is connected" reason instead of parking, when the dropped connection was the only operator subscriber.
4. AC4: A frame still running at disconnect that then runs `flow.subscribe` registers no subscription (late-subscribe race): same observable as AC3.
5. AC5: A client that subscribes and stops reading while more than `push_capacity` large flow events are pushed: the server does not buffer them all; when the client resumes reading it receives fewer lines than were pushed, a `notifications/aitm/state {lagged:true}` marker, and the newest event.
6. AC6: With an operator and an agent connection both subscribed, an agent `Ask`-policy Sensitive call produces `notifications/aitm/agent {event:"approval_requested"}` on the operator connection only; the agent connection never receives it; `agent.approve` from the operator connection resolves it.
7. AC7: Every PR #103 property still holds (`web_bus_concurrency` tests pass unchanged), and `web_bus_roles` passes unchanged.
8. AC8: `NotificationSink::is_closed()` is true after `close()`; `Subscriptions::add` on a closed sink registers nothing (unit tests in `aitm-mcp`).
9. AC9: `McpServer::spawn_push_dispatcher` delivers a broadcast `Event` as a flow notification to a subscriber of that server (test without `serve`), and `serve` still does (existing push tests pass).
10. AC10: Against a built `target/debug/aitm`, `python3 tests/e2e/run.py web` flips `test_bus_live_stream.py` from SKIP to PASS.

## Left to the builder

- Test-helper structure and names; how the two-role server and the Sensitive test command are built.
- Whether `ConnGuard` is a struct with `Drop` or a scope guard, and the exact `refuse`/`close` ordering relative to teardown, provided teardown happens on every path.
- The error text for a refused late subscribe.

## Open questions

None. The UI follow-up (D7) is proposed, not decided here.
