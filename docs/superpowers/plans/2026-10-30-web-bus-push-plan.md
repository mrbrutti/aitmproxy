# Web `/bus` push implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's autonomous-approve mode)
**Spec:** `docs/superpowers/specs/2026-10-30-web-bus-push-design.md`
**Branch / worktree:** `feat/web-bus-push` (cut from `origin/fix/web-bus-concurrent-frames`, PR #103, because #103 is still open and rewrote `bridge.rs`) in `/Users/matt/Security/aitmproxy/.claude/worktrees/objective-taussig-ce3b7f`

## Overview

Two coder tasks, sequential (Task 2 uses Task 1's API). Task 1 is the `aitm-mcp` prerequisites (a closed-sink check on subscribe, a reusable push-dispatcher spawn) and its unit tests; they bind no ports, so the coder runs red and green itself. Task 2 is the bridge change, the `main.rs` wiring, and the real-socket tests in `crates/aitm/tests/web_bus_push.rs`. The Bash sandbox cannot bind loopback, so the socket tests run in the Terminal panel: the coder writes and compiles them (`cargo test --no-run`), and the orchestrator shows red (pre-change `bridge.rs`) then green in the Terminal. Then Tester (gate + criterion map), the 3-reviewer panel, and the e2e canary run against a real `aitm`.

No `apps/web` change (spec D7), so the web gate is not part of this PR.

## Tasks

### Task 1: aitm-mcp prerequisites

- **Satisfies:** AC8, AC9 (and the foundation for AC3/AC4)
- **Depends on:** none
- **Files:** `crates/aitm-mcp/src/server.rs` (modify; unit tests in its `mod tests`, or `crates/aitm-mcp/tests/` where the existing push tests live)
- **Change:**
  - `NotificationSink::is_closed(&self) -> bool` (the `closed` flag, `Ordering::Relaxed` like its siblings).
  - `Subscriptions::add(..) -> Option<u64>`: under the registry lock, return `None` without registering when `sink.is_closed()`. `McpServer::subscribe` maps `None` to `tool_error("flow.subscribe refused: this connection is closed")`; `since` replay must not run for a refused subscribe.
  - `pub fn spawn_push_dispatcher(self: &Arc<Self>)`: move the dispatcher `tokio::spawn` block out of `serve` verbatim (subscribe to `push_tx`, `push_flow_event` per event, skip on `Lagged`, stop on `Closed`); no-op when `push_tx` is `None`. `serve` calls it where the block was. Re-export nothing new; it is a method.
  - Document both new items; note on `spawn_push_dispatcher` that a server driven without `serve` (the web bridge) must call it, and that calling it twice would double-deliver.
- **Test:** (write first, watch each fail, then pass)
  - `sink_is_closed_after_close`: `NotificationSink::new(4)`, `is_closed()` is `false`, `close()`, `is_closed()` is `true`.
  - `subscribe_on_a_closed_sink_is_refused_and_registers_nothing`: a `ConnCtx` whose `out` sink is already closed calls `flow.subscribe`; the result has `isError: true`; then `push_flow_event` for a stored flow leaves `sink.queued_len() == 0`.
  - `subscribe_on_an_open_sink_still_works` (regression): same with an open sink returns `{sub_id}` and a pushed flow lands in the sink.
  - `spawn_push_dispatcher_delivers_a_broadcast_event`: `McpServer::new(..).with_services(..).with_push(tx)` in an `Arc`, `spawn_push_dispatcher()`, subscribe through a `ConnCtx` with a sink, `tx.send(Event::..)` for a stored flow, wait (bounded) until `sink.queued_len() == 1` and the drained line has `method == "notifications/aitm/flow"`. Reuse the existing push test's event/flow construction.
- **Done when:** the four tests pass, the existing `aitm-mcp` push/transport tests pass, and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp` is clean.

### Task 2: bridge push, wiring, real-socket tests

- **Satisfies:** AC1-AC7
- **Depends on:** Task 1
- **Files:** `crates/aitm/src/web/bridge.rs` (modify), `crates/aitm/src/main.rs` (modify, web wiring only), `crates/aitm/tests/web_bus_push.rs` (create)
- **Change:**
  - `bridge.rs`: after auth, build `let sink = NotificationSink::new(state.mcp.push_capacity())`, `let conn = Arc::new(ConnCtx { role, client_label: None, conn_id: state.mcp.next_conn_id(), out: Some(sink.clone()) })`, and a `ConnGuard { mcp, conn_id, sink }` whose `Drop` calls `sink.close()` then `mcp.drop_connection(conn_id)`. `dispatch_frame` takes `Arc<ConnCtx>` instead of building `ConnCtx::new(role)` per frame. Add the third `select!` arm `_ = sink.wait()` that `for line in sink.drain()` sends `Message::text(line)` (errors end the connection like any send). The arm is unconditional (not gated by `MAX_IN_FLIGHT`). Replies keep going straight to `ws.send` from the frame-done arm. Keep every PR #103 property; update the module doc comment (push, one ctx per connection, why replies bypass the sink, pushes are bounded by `push_capacity`, a notification may precede its subscribe reply).
  - `main.rs`: the web server (`let bus = tui::server(..)`) gets `.with_push(push_tx.clone())`, is wrapped in `Arc::new`, and `spawn_push_dispatcher()` is called on it before it goes into `WebState`. The primary server's `.with_push(push_tx)` becomes `.with_push(push_tx.clone())` if ordering requires it. Update the adjacent comment ("a second McpServer ... driven by the bridge's `handle` calls") to say it is also fed the core event stream.
  - Touch nothing else (no policy/role change; do not share `agent_state` with the web server, which is a separate pre-existing finding).
- **Test:** `crates/aitm/tests/web_bus_push.rs`, hermetic like `web_bus_concurrency.rs` (copy its harness approach: `assemble_with_scripts`, `McpServer::new(..).with_services(..)`, `WebState`, `web::serve` on `127.0.0.1:0`, a `TestCommands` plugin). Each test names its AC:
  - `subscribe_over_bus_then_a_flow_push_arrives` (AC1): connect with the agent token, send `flow.subscribe {}`, assert the reply is `{sub_id}`; insert a flow into the store and `mcp.push_flow_event(&ev)` (hold an `Arc<McpServer>` in the test); assert a text frame with `method == "notifications/aitm/flow"` and `params.id == <flow id>`.
  - `pushes_flow_through_the_real_broadcast_dispatcher` (AC1/AC9 at the wiring level): build the server `.with_push(tx)`, call `spawn_push_dispatcher()`, send an `Event` on `tx`, assert the push arrives over the socket. This is the contract `main.rs` relies on.
  - `replies_stay_in_order_while_pushes_flow` (AC2): subscribe, then in a loop push events from a task while sending a multi-line frame (`test.tick` x N plus `flow.list`) and assert the N replies arrive in line order, with pushes interleaved and none lost (below capacity); and a parked `test.block` reply does not stop pushes arriving.
  - `disconnect_drops_the_subscription` (AC3): operator-token connection subscribes, is dropped; then an agent call (via `mcp.handle_on(&ConnCtx::agent(), ..)` or an agent bridge connection) to a `Sensitive` test command under `AgentPolicy::Ask` is refused promptly with the "no operator is connected" reason, not parked. Control: with the operator connection still open the same call parks (assert it is still pending after a short wait, then approve or let `with_approval_timeout(short)` expire).
  - `a_frame_still_running_at_disconnect_cannot_resubscribe` (AC4): one frame `[test.block, flow.subscribe]` from an operator connection; drop the client while `test.block` is parked; release it; the subscribe runs after teardown; afterwards the same Ask-policy probe as above is refused promptly.
  - `a_non_reading_subscriber_is_bounded_and_lags` (AC5): `with_push_capacity(16)`; a stored flow with a ~4 KiB path; subscribe; the client stops reading; push several thousand events (enough to exceed loopback socket buffers); then resume reading until a final distinctively-pathed event arrives; assert received count < pushed count, a `{lagged:true}` state line was seen, and the final event arrived.
  - `agent_role_never_gets_operator_only_pushes` (AC6): operator and agent connections both subscribe; the agent connection (agent token) calls the Sensitive test command under Ask, which parks; the operator connection receives `notifications/aitm/agent` with `event == "approval_requested"`; the agent connection receives no such frame within a bounded wait (it may receive flow pushes); the operator calls `agent.approve {request_id, allow:false}` and the parked agent call returns `isError`.
  - `existing` `web_bus_concurrency` and `web_bus_roles` must pass unchanged.
- **Done when:** the new tests fail on the pre-change `bridge.rs` (orchestrator shows red in the Terminal) and pass with it (green), `web_bus_concurrency` and `web_bus_roles` still pass, and the full gate passes. The coder cannot bind sockets: it writes the tests, runs `cargo test --no-run -p aitm --test web_bus_push` and `cargo clippy --all-targets -- -D warnings`, and states plainly which tests it could not run.

### Task 3: e2e canary and verification (orchestrator, Terminal panel)

- **Satisfies:** AC10
- **Depends on:** Task 2
- **Files:** none (reads `tests/e2e/web/test_bus_live_stream.py`; the e2e framework is owned by another session, which is told the PR number so it can make the canary a hard fail)
- **Change:** build `target/debug/aitm`, run `python3 tests/e2e/run.py web`, confirm SKIP flips to PASS.
- **Done when:** the run's output is recorded in the notes folder and quoted in the PR.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
