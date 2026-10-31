# Bus hardening implementation plan

**Status:** Approved 2026-10-30 (self-approved under Matt's autonomous-approve mode; flagged in the PR body)
**Spec:** `docs/superpowers/specs/2026-10-30-bus-hardening-design.md`
**Branch / worktree:** `claude/vibrant-proskuriakova-e98cfd` in `/Users/matt/Security/aitmproxy/.claude/worktrees/vibrant-proskuriakova-e98cfd` (the PR #137 follow-up; currently at 492b3aa, rebased onto `main` once #137 squash-merges). Independent tasks may fan out to child branches cut from it.

## Overview

Seven tasks. Task 1 (a tiny `McpServer` seam) gates the two deadline tasks. Tasks 2 and 3 are pure test refactors and gate the tasks that would otherwise copy the harness a fourth time. Everything else is a different file from its siblings.

| Wave | Tasks (run in parallel) | Files they own (disjoint within a wave) |
|---|---|---|
| 1 | Task 1, Task 2, Task 3 | T1 `aitm-mcp/src/{server,lib}.rs`; T2 `aitm-mcp/tests/mcp.rs`; T3 `aitm/tests/support/web_bus.rs` (new) + `web_bus_push.rs` |
| 2 | Task 4 (after 3), Task 5 (after 1 and 2), Task 6 (after 1), Task 7 (after 1 and 3) | T4 `web_bus_{concurrency,roles}.rs`; T5 `server.rs` + `mcp.rs`; T6 `transport.rs` + `aitm-mcp/Cargo.toml`; T7 `bridge.rs` + `support/web_bus.rs` (additive) + `web_bus_write_deadline.rs` (new) |

Sequential fallback order: 1, 2, 3, 5, 6, 4, 7. Hard edges: T5 after T1 (both own `server.rs`) and after T2 (both own `mcp.rs`); T6 and T7 need T1's `write_timeout()`; T7 needs T3's module; T4 needs T3's module. T4 must not edit `support/web_bus.rs` (T7 does); if T4 finds the module lacks something, that is a plan gap: stop and report.

Verification notes for every task:
- The Coder cannot bind sockets. It writes the Terminal-marked tests, runs `cargo test --no-run` for the affected crate and `cargo clippy --all-targets -- -D warnings`, and says plainly which tests it could not run. The orchestrator shows red then green in the Terminal panel. Duplex and unit tests are run by the Coder in the sandbox.
- "No red phase" below means a pure refactor: the proof is the `--list` name list before and after (capture it before the first edit) plus unchanged assertions.
- Panel and Tester run per task, then once on the whole branch. Optional regression check by the orchestrator: `python3 tests/e2e/run.py web` against a built `target/debug/aitm`.

## Tasks

### Task 1: write-timeout seam on `McpServer`

- **Satisfies:** AC7
- **Depends on:** none
- **Files:** `crates/aitm-mcp/src/server.rs` (modify), `crates/aitm-mcp/src/lib.rs` (modify, re-export)
- **Change:**
  - `pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);` after `DEFAULT_PUSH_CAPACITY`, documented: per send/write, the clock stops when the socket accepts the frame, not when the peer reads it.
  - A `write_timeout: Duration` field on `McpServer`, defaulted in `McpServer::new` and carried in **both** the destructure and the rebuilt struct inside `serve(self)` (it destructures every field, so the compiler will point at it).
  - `pub fn with_write_timeout(mut self, timeout: Duration) -> Self` storing `timeout.max(Duration::from_millis(1))`, and `pub fn write_timeout(&self) -> Duration`.
  - `lib.rs`: add `DEFAULT_WRITE_TIMEOUT` to the `pub use server::{..}` list.
- **Test:** in `server.rs` `mod tests`, written first (red = compile error, no such methods).
  - `write_timeout_defaults_to_30_seconds`: `McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio).write_timeout()` equals `Duration::from_secs(30)`, and `DEFAULT_WRITE_TIMEOUT` equals `Duration::from_secs(30)`.
  - `with_write_timeout_sets_it_and_clamps_zero`: `with_write_timeout(Duration::from_secs(7)).write_timeout()` equals `Duration::from_secs(7)`; `with_write_timeout(Duration::ZERO).write_timeout()` equals `Duration::from_millis(1)`.
- **Done when:** both pass and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp --lib` is clean.

### Task 2: one push-server builder in `mcp.rs`

- **Satisfies:** AC19 (builder and `sub_id_of` clauses, 73 tests)
- **Depends on:** none
- **Files:** `crates/aitm-mcp/tests/mcp.rs` (modify)
- **Change:**
  - Add `fn push_server_with(transport: McpTransport, store: Arc<MemFlowStore>, capacity: Option<usize>, push: Option<broadcast::Sender<Event>>) -> McpServer` beside `push_registry`: `McpServer::new(push_registry(), transport)` with `with_agent_state(ungated())` and `with_services(store, Arc::new(StubClient), Arc::new(StdGuard::default()), None)`, then `with_push_capacity` if `capacity` is `Some`, `with_push` if `push` is `Some`.
  - `push_server(store, capacity) -> Arc<McpServer>` keeps its signature (13 call sites) and becomes `Arc::new(push_server_with(McpTransport::Stdio, store, Some(capacity), None))`.
  - The three inline copies use it: `spawn_push_dispatcher_delivers_a_broadcast_event` and `spawn_push_dispatcher_twice_delivers_each_event_once` with `(Stdio, store.clone(), None, Some(tx.clone()))` in an `Arc`; `serve_still_spawns_the_push_dispatcher` with the `LoopbackTcp { port: 0, token: "tok".into(), endpoint_file: None }` transport, unwrapped (it consumes the server).
  - Route the "reply carries a `sub_id`" assertions through `sub_id_of(&reply)` in `subscribe_on_an_open_sink_still_works`, `since_replay_is_bounded_by_the_sink_and_flags_lag`, `spawn_push_dispatcher_delivers_a_broadcast_event`, `serve_still_spawns_the_push_dispatcher`, `subscribe_pushes_created_on_new_flow`, `unsubscribe_stops_push`. The condition asserted (a `u64` `sub_id` is present) is unchanged. Leave the two sites in the `Paused` policy test and the `Ask` section's helper alone.
- **Test:** no red phase (refactor). Before editing: `cargo test -p aitm-mcp --test mcp -- --list` saved (73 tests). After: identical names, and `rg -n "push_registry\(\)" crates/aitm-mcp/tests/mcp.rs` has exactly two matches (the definition and its use in `push_server_with`); `rg -n '"sub_id"\]' crates/aitm-mcp/tests/mcp.rs` matches only inside `sub_id_of` and the two left-alone sites.
- **Done when:** the list is identical, `cargo test -p aitm-mcp --test mcp` is green (Terminal for `serve_still_spawns_the_push_dispatcher`), and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings` is clean.

### Task 3: shared `/bus` harness; convert `web_bus_push.rs`

- **Satisfies:** AC17, AC18 (push file)
- **Depends on:** none
- **Files:** `crates/aitm/tests/support/web_bus.rs` (create), `crates/aitm/tests/web_bus_push.rs` (modify)
- **Change:** create `support/web_bus.rs` holding the **union** of the three `web_bus_*` files' helpers, so Task 4 can consume it without editing it. All `pub`:
  - consts `AGENT_TOKEN`, `OPERATOR_TOKEN`, `TIMEOUT` (10 s), `FAST` (5 s), `QUIET` (500 ms), `SETTLE` (200 ms), `APPROVAL_TIMEOUT` (1 s), `BLOCK_LIMIT` (30 s), `NO_OPERATOR`, `PARKED_TIMED_OUT` (values and texts exactly as in `web_bus_push.rs`); `fn temp_ca_dir(tag: &str) -> PathBuf`; `struct UnusedClient`.
  - `Parking` (with both the `entered` and `completed` counters), `Release`, and the commands `test.block`, `test.sleep`, `test.tick`, `test.panic`, `test.sensitive` behind `TestCommands` (`new`, `release_guard`, `ticks`, `sensitive_runs`, `Plugin` impl; `parking` stays reachable as in the files today).
  - `pub struct ServerOptions { pub policy: AgentPolicy, pub approval_timeout: Duration, pub push_capacity: Option<usize>, pub dispatcher: bool, pub operator_token: Option<String> }` with `Default` giving `Auto`, `APPROVAL_TIMEOUT`, `None`, `false`, `Some(OPERATOR_TOKEN.to_owned())`; `pub struct Server { pub addr, pub mcp: Arc<McpServer>, pub store: Arc<dyn FlowStore>, pub push_tx: broadcast::Sender<Event>, .. }` aborting its task on drop; `pub async fn start(tag: &str, commands: &TestCommands, opts: ServerOptions) -> Server`.
  - `pub type Ws`, `ws_connect(&Server) -> Ws`, `try_ws_connect(&Server) -> Result<Ws, WsError>`, `send_text`, `next_frame`, `recv_text`, `recv_json`, `recv_within`, `recv_until`, `recv_until_collecting`, `drain_for`, `Drained` and `drain_until_end`, `stream_ends_within`, `call_line`, `call_line_with`, `open_bus(&Server, token: &str, role: &str) -> Ws`, `open_agent`, `open_operator`, `subscribe(&mut Ws) -> u64`, `wait_until`, `Probe`, `probe_ask_gate(&Arc<McpServer>) -> Probe`, `assert_refused_without_operator(&Probe)`, `http_flow(authority: &str, path: &str) -> Flow`, `push_flow(&Server, path: &str) -> FlowId`.
  - Where the three copies differ in strictness, take the strictest behaviour every current test satisfies, or leave a local variant in that file.
  - `web_bus_push.rs`: add `#[path = "support/web_bus.rs"] #[allow(dead_code)] mod web_bus;` (the `rig.rs` convention in `discover_e2e.rs`), delete the moved items, import what the tests use, keep `SUBSCRIBE_ID` and anything used only there. No test body changes.
- **Test:** no red phase (refactor). Before editing: `cargo test -p aitm --test web_bus_push -- --list` saved (10 names). After: identical. `git diff -U0` over `web_bus_push.rs` shows no changed line inside a test function. `rg -n "^struct UnusedClient|^fn temp_ca_dir|^struct Parking|^struct Release|^async fn next_frame|^async fn recv_until\b" crates/aitm/tests/web_bus_push.rs` matches nothing.
- **Done when:** `cargo test -p aitm --test web_bus_push --no-run` compiles and the 10 tests pass in the Terminal; `cargo fmt --check && cargo clippy -p aitm --all-targets -- -D warnings` is clean.

### Task 4: convert `web_bus_concurrency.rs` and `web_bus_roles.rs`

- **Satisfies:** AC17, AC18
- **Depends on:** Task 3
- **Files:** `crates/aitm/tests/web_bus_concurrency.rs` (modify), `crates/aitm/tests/web_bus_roles.rs` (modify). Not `support/web_bus.rs`.
- **Change:** include the module as in Task 3; delete the duplicated harness. Keep file-local thin wrappers with the old signatures so no test body changes: in `web_bus_concurrency.rs` `start(tag: &str, commands: &TestCommands) -> Server` (delegating with `operator_token: None`, as the file has today) and `open_bus(&Server) -> Ws` (agent token); in `web_bus_roles.rs` `start(tag: &str, operator: Option<&str>) -> Server` (delegating with `operator_token: operator.map(str::to_owned)` and a fresh `TestCommands`) and `ws_connect(&Server) -> Result<Ws, WsError>`. Concurrency-only items (`MAX_LINES_PER_FRAME`, `token_line`, `call_frame`, `expect_answered_in_order`) stay local.
- **Test:** no red phase (refactor). Before editing, save `--list` for both: 11 and 5 names. After: identical, bodies untouched by the `git diff -U0` check. Run at this task's commit with `bridge.rs` unchanged from #137, so the refactored files act as the oracle they were meant to be.
- **Done when:** both files pass in the Terminal at this commit; greps in AC18 match nothing in either file; fmt and clippy clean.

### Task 5: total registry bound and `HashSet` fan-out

- **Satisfies:** AC1, AC2, AC3, AC4, AC5, AC6
- **Depends on:** Task 1, Task 2
- **Files:** `crates/aitm-mcp/src/server.rs` (modify; unit tests in its `mod tests`), `crates/aitm-mcp/tests/mcp.rs` (modify: two tests)
- **Change:**
  - `const MAX_SUBS_TOTAL: usize = 4096;` beside `MAX_SUBS_PER_CONN`, with `const _: () = assert!(MAX_SUBS_TOTAL >= MAX_SUBS_PER_CONN);`, documented (registry size drives fan-out cost; per `McpServer`); the `MAX_SUBS_PER_CONN` doc points at it.
  - `enum SubscribeRefused { Closed, TooMany, TableFull }`. `Subscriptions::add` keeps its signature `(&self, conn_id: u64, role: Frontend, sink: NotificationSink, filter: FlowFilter) -> Result<u64, SubscribeRefused>` and, after the existing `Closed` and `TooMany` checks and under the same lock, returns `TableFull` when `st.subs.len() >= MAX_SUBS_TOTAL`. Update its doc with the precedence.
  - `McpServer::subscribe`: new match arm turning `TableFull` into `tool_error` with exactly `flow.subscribe refused: the server's subscription table is full (max {MAX_SUBS_TOTAL} across all connections); try again later`. Update `subscribe`'s doc and the comment in `call_tool` that lists the refusal reasons.
  - `fanout_flow`, `fanout_state`, `fanout_role`: `seen` becomes `HashSet<u64>` (import it with `VecDeque`). In `fanout_flow` and `fanout_role` the connection is inserted only after the filter or role test has passed, never before.
- **Test:**
  - `server.rs` `mod tests` (private registry access; a local helper fills the registry with 128 connections x 32 subscriptions, each on its own `NotificationSink::new(4)` and `FlowFilter::default()`), written first; red is a compile error (`TableFull`, `MAX_SUBS_TOTAL` missing):
    - `the_table_cap_refuses_another_connection`: `MAX_SUBS_TOTAL == 4096`; all 4096 adds are `Ok`; the add for connection 129 equals `Err(SubscribeRefused::TableFull)`; the registry still holds 4096.
    - `refusal_precedence_is_closed_then_per_connection_then_table`: on the full registry a closed sink gives `Err(Closed)`, connection 1 (holding 32) gives `Err(TooMany)`, a fresh open connection gives `Err(TableFull)`.
    - `unsubscribe_frees_exactly_one_table_slot`: `remove` of one of connection 1's subscriptions returns `true`; then one add by connection 129 is `Ok` and the next by connection 130 is `Err(TableFull)`.
    - `ending_a_connection_frees_its_table_slots`: `drop_connection(1)`; then 32 adds by connection 129 are `Ok`, and a 33rd by it is `Err(TooMany)`.
    - `a_full_table_refuses_flow_subscribe_with_its_own_text`: an `McpServer` over an empty `Registry` whose `subscriptions` field is pre-filled to the cap with other connection ids; a fresh `ConnCtx` for `Frontend::Operator` with `conn_id = srv.next_conn_id()` and a sink; `handle_on` of a `tools/call flow.subscribe {}` returns `result.isError == true`, `result.content[0].text == "flow.subscribe refused: the server's subscription table is full (max 4096 across all connections); try again later"`, and no `result.structuredContent`.
    - `fanout_state_reaches_every_connection_once_at_the_table_cap`: 4096 connections with one subscription each; after one `fanout_state`, every sink has `queued_len() == 1`.
    - `fanout_role_reaches_only_that_role_once_per_connection`: 10 `Operator` and 10 `Mcp` connections with 3 subscriptions each; after `fanout_role(Frontend::Operator, ..)` every operator sink has `queued_len() == 1` and every agent sink `0`.
  - `mcp.rs`, using `push_server`, `conn_over`, `subscribe_on`, `http_flow`, `sub_id_of`, written and run **against the current `Vec` code first** (characterization: they must be green before the change):
    - `a_connection_with_many_matching_subscriptions_gets_one_push`: one connection with 32 `{}` subscriptions and another with 3; one `push_flow_event`; each sink `queued_len() == 1` and the line's `params.id` is the flow id.
    - `a_non_matching_subscription_does_not_mask_a_matching_one`: one connection, first subscription `{"filter": {"host": "other.example"}}`, second `{}`; a flow for `example.com:443` gives `queued_len() == 1`.
  - Mutation check (shown once, then reverted): insert into `seen` before the filter test in `fanout_flow`; `a_non_matching_subscription_does_not_mask_a_matching_one` must go red. AC6: `rg -n "seen: Vec" crates/aitm-mcp/src/server.rs` matches 3 before, 0 after.
- **Done when:** all of the above pass, the existing `the_33rd_subscribe_is_refused_while_another_connection_still_subscribes` and `unsubscribe_frees_a_subscription_slot` still pass, and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp` is clean.

### Task 6: write deadline on the line transport (TCP and stdio)

- **Satisfies:** AC14, AC15, AC16
- **Depends on:** Task 1
- **Files:** `crates/aitm-mcp/src/transport.rs` (modify; tests in its `mod tests`), `crates/aitm-mcp/Cargo.toml` (modify: add `"time"` to `tokio`'s regular `features`; the library has never used `tokio::time`)
- **Change:**
  - `async fn write_loop<W>(writer: W, sink: NotificationSink, write_timeout: Duration) -> anyhow::Result<()>` with `W: AsyncWrite + Unpin + Send`: each `write_all` and the `flush` run under `tokio::time::timeout(write_timeout, ..)`; expiry returns an error whose text starts `write timed out after`.
  - `serve_lines` reads `server.write_timeout()` once and passes it. When the writer task ends in an error before the read loop ends, the read loop is abandoned: `server.drop_connection(conn.conn_id)`, `sink.close()`, and the writer's error is returned. A writer that ends cleanly, or a read loop that ends first, behaves as today. A `JoinHandle` cannot be awaited again after it completes. Update the `serve_lines` doc.
- **Test:** in `transport.rs` `mod tests`, with a local helper building `McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio).with_write_timeout(deadline)` and padded pushes via `server.push_state(json!({"seq": i, "pad": "p".repeat(4096)}))`.
  - `a_stopped_line_reader_ends_the_connection_after_the_write_deadline` (sandbox): `duplex(256)`, deadline 200 ms, `ConnCtx::new(Frontend::Operator)` with an injected `NotificationSink::new(64)`. The client sends a `flow.subscribe` line, reads exactly one line (a reply with a `sub_id`), then `push_state` x 16, and neither reads nor closes. `tokio::time::timeout(5 s, task)` resolves to an `Err` whose text contains `write timed out`; `sink.is_closed()` is `true`; with `before = sink.queued_len()`, one more `push_state` leaves `sink.queued_len() == before`. Red before the change: `serve_lines` never returns and the 5 s bound fails.
  - `a_slow_line_reader_is_not_disconnected` (sandbox): same setup, 100 pushes tagged `seq` 0 to 99; the client reads a line per 5 ms and sees `seq` 0..99 in order; then `task.is_finished()` is `false`; the client closes and the task ends.
  - `a_stopped_tcp_client_is_disconnected_by_the_write_deadline` (Terminal): `LoopbackTcp::bind(0, "tok".into(), None)`, `serve` spawned with a 1 s-deadline server; the client is a `TcpSocket` with `set_recv_buffer_size(4096)` before connect, sends the token line and a `flow.subscribe`, reads the reply, then the test pushes 4096 padded lines (16 MiB, exactly the default sink capacity, so every byte is attempted), waits 2 s, and reads to EOF under `timeout(15 s)`. Expected: EOF reached, bytes received less than 4096 x 4096. Red before the change: the read never reaches EOF and the 15 s bound fails.
- **Done when:** the three tests pass (the third in the Terminal), existing `aitm-mcp` transport, push and slow-subscriber tests pass, and `cargo fmt --check && cargo clippy -p aitm-mcp --all-targets -- -D warnings && cargo test -p aitm-mcp` is clean.

### Task 7: write deadline on the web bridge, with real-socket tests

- **Satisfies:** AC8, AC9, AC10, AC11, AC12, AC13
- **Depends on:** Task 1, Task 3
- **Files:** `crates/aitm/src/web/bridge.rs` (modify), `crates/aitm/tests/support/web_bus.rs` (modify, additive only), `crates/aitm/tests/web_bus_write_deadline.rs` (create)
- **Change:**
  - `bridge.rs`: `async fn send_within<S>(ws: &mut WebSocketStream<S>, msg: Message, limit: Duration) -> anyhow::Result<()> where S: AsyncRead + AsyncWrite + Unpin`, wrapping the send in `tokio::time::timeout(limit, ..)`; expiry returns an error containing `timed out after`. `relay` reads `let write_timeout = state.mcp.write_timeout()` once after authentication and uses `send_within` at the frame-done reply arm and the drain arm; an error returns from `relay`, so `ConnGuard` runs. Do not touch the pre-auth `UNAUTHORIZED_REPLY` send or `close_within`. Update the module doc (the deadline; "a push send fails" is now bounded) and the doc that mentions a Close being noticed.
  - `support/web_bus.rs` (additive): `ServerOptions.write_timeout: Option<Duration>` (applied with `with_write_timeout`) and `ServerOptions.send_buffer: Option<u32>` (when set, the listener is built with `TcpSocket::set_send_buffer_size` before `bind` and `listen`), both defaulting to `None`; a `test.blob` command (`Read`, returns a string of `BLOB_BYTES = 1 << 20` bytes) registered by `TestCommands`.
  - New test file includes the module as in Task 3 and keeps a local `async fn open_stopped(server: &Server, token: &str, role: &str) -> Ws`: a `TcpSocket` with `set_recv_buffer_size(4096)` set before `connect`, upgraded with `tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(stream))`, then token, `initialize`, role check, as `open_bus` does; and `wait_until_no_operator(server: &Server, bound: Duration) -> Probe` polling `probe_ask_gate` until its text contains `NO_OPERATOR`.
  - Shared test constants: `TEST_WRITE_TIMEOUT = 1 s`, `PUSHES = 4096` with a 4 KiB path (16 MiB), `send_buffer: Some(4096)`, `policy: AgentPolicy::Ask`. Each test is `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`.
- **Test:**
  - `bridge.rs` `mod tests` (sandbox; uses the existing `socket_pair()` duplex of 64 KiB), written first, red = compile error: `send_within_gives_up_on_a_stalled_peer`: a 1 MiB `Message::text` to a client that never reads with a 50 ms limit returns `Err` whose text contains `timed out`, within `timeout(2 s)`. `send_within_delivers_to_a_live_peer`: the same message with a client reading it and a 5 s limit returns `Ok(())` and the client receives all 1 MiB.
  - `web_bus_write_deadline.rs` (Terminal). Red = run against the pre-change `bridge.rs` with Task 1 and the support additions in place:
    - `a_stopped_operator_is_disconnected_by_the_write_deadline` (AC9): `open_stopped` as operator, `subscribe`, push `PUSHES` events, stop reading. `wait_until_no_operator(&server, TEST_WRITE_TIMEOUT + 5 s)` returns a probe for which `assert_refused_without_operator` holds (text contains `no operator is connected to approve it`, elapsed under `APPROVAL_TIMEOUT`); then `stream_ends_within(&mut ws, FAST)` is `true`; `commands.sensitive_runs() == 0`. Pre-change red: `wait_until_no_operator` runs out of bound.
    - `a_stopped_reader_of_large_replies_is_disconnected_by_the_write_deadline` (AC10): operator subscribed, then one frame of 16 `test.blob` lines, no reads; same assertions. Pre-change red: same.
    - `a_stopped_agent_is_disconnected_by_the_write_deadline` (AC11): agent subscribed, pump, stop; `stream_ends_within(&mut ws, TEST_WRITE_TIMEOUT + 5 s)` is `true` once the test resumes reading after waiting `TEST_WRITE_TIMEOUT + 1 s`. Pre-change red: the stream never ends.
    - `a_stopped_operator_is_still_connected_before_the_default_deadline` (AC12): `write_timeout: None` (the 30 s default), same stop and pump, sleep 3 s; `probe_ask_gate` parks (still pending after `SETTLE`) and then returns text containing `PARKED_TIMED_OUT`. Green before and after: it is the control that shows the bound in AC9 is the configured deadline.
    - `a_slow_but_live_reader_is_not_disconnected` (AC13): agent, `push_capacity: Some(16)`, 1 s deadline, 1024 pushes of the 4 KiB path then one `/final`; the client sleeps 10 ms per frame until the `/final` event arrives within `TIMEOUT`; a following `flow.list` call returns `isError == false`. Green before and after: it guards against a deadline that is too aggressive.
- **Done when:** the unit tests pass in the sandbox; the five socket tests pass in the Terminal and AC9 to AC11 are shown red against the pre-change bridge; `web_bus_push`, `web_bus_concurrency` and `web_bus_roles` still pass (the AC5 push test stalls its client briefly, far under 30 s); `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|

## Shipped

What merged, what was cut, follow-ups. Filled at stage 7.
