# Bus hardening design: total subscription bound, write deadline, test-support extraction

**Status:** Approved 2026-10-30 (self-approved under Matt's autonomous-approve mode; flagged in the PR body)
**Research inputs:** none new. This is the follow-up to PR #137 (web `/bus` push): it closes the Minors that the security and quality panel accepted in the Review log of `docs/superpowers/plans/2026-10-30-web-bus-push-plan.md`. Reads `crates/aitm-mcp/src/{server,transport}.rs`, `crates/aitm/src/web/bridge.rs`, `crates/aitm/tests/web_bus_{concurrency,roles,push}.rs`, `crates/aitm/tests/support/`, `crates/aitm-mcp/tests/mcp.rs`.

## Intent

#137 let a `/bus` connection subscribe and receive pushes. Its panel accepted three follow-ups: (1) the 32-per-connection subscription cap is bypassable by opening many connections, and fan-out de-dups connections with a `Vec`, so each event costs O(subscriptions x connections) under the registry lock; (2) a subscribed peer that stops reading holds its task, its subscriptions and, for an operator, `any_role(Operator)` until the kernel fails the write, because no write is bounded; (3) the `/bus` test harness is copied into three files and the push-server builder three times in `mcp.rs`. This change does those three things and nothing else.

## Goals

- The registry holds at most 4096 subscriptions across all connections. At that limit another subscribe is refused with its own tool error; unsubscribing or ending a connection frees slots.
- Fan-out (flow events, state pushes, the per-tool-call audit line, operator-only lines) costs O(subscriptions) under the lock and delivers exactly what it delivers today: once per matching connection.
- A peer that stops reading is disconnected within the write deadline after its socket buffers fill. Its subscriptions are removed and `any_role(Operator)` stops being pinned. This holds on the web bridge (both send sites) and on the line transport (TCP and stdio).
- A peer that is slow but still reading is not disconnected.
- The `/bus` harness is defined once, `mcp.rs` builds push servers through one helper, no test is removed or weakened, and the test counts are unchanged (26 in the three `aitm` files, 73 in `mcp.rs` before new tests).

## Non-goals

- No change to the audit-stream fan-out scope: `notifications/aitm/agent`, `push_agent` and `agent.activity` role scoping stay as they are (a separate decision for Matt).
- No web listener connection cap. See the known residual in the Threat/Failure model.
- `ConnGuard` stays in `aitm`; it is not moved into `aitm-mcp`.
- No config-file, CLI or env surface for the new limits. `MAX_SUBS_TOTAL` is a constant; the write deadline has a default and a builder method, nothing more.
- No change to the streamable-HTTP transport, role/policy/scope gating, or the wire protocol apart from the new refusal text and connections ending at the deadline.
- No idle-connection liveness (ping/pong or TCP keepalive). The deadline only fires while the server is writing.
- No change to the pre-auth path or to `close_within` in `bridge.rs`.

## Anti-goals

- A deadline that fires on an idle connection, or on a reader that is slow but making progress.
- A deadline that ends the connection but leaves its subscriptions, or leaves the line transport's read loop parked on a live socket.
- A deadline or fan-out test that is a timing benchmark and flakes on a loaded machine.
- A "table full" refusal that reads like the per-connection one, or one surfaced differently from it.
- An extraction that weakens a test: a test body edited, a helper made more lenient than the strictest copy it replaces, a test dropped or renamed.

## Constraints

- No new dependency. `tokio::net::TcpSocket` and `tokio::time` are already available to `aitm`. `aitm-mcp`'s library has never used `tokio::time`, so its regular `tokio` features gain `time`.
- Memory and CPU: one `HashSet<u64>` per fan-out call (no allocation until the first insert); one timer per send or write. Both are negligible next to the send.
- Sandbox: unit tests and the `tokio::io::duplex` tests run in the Bash sandbox. Tests that bind loopback (the bridge tests, the TCP test) run in the Terminal panel; the Coder compiles them and says which it could not run.
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

## Design

**D1. Total registry bound.** `const MAX_SUBS_TOTAL: usize = 4096` in `server.rs` beside `MAX_SUBS_PER_CONN`, with a const assertion that it is at least the per-connection cap. `Subscriptions::add` checks, under the one registry lock and in this order: the sink is closed (`Closed`); the connection already holds `MAX_SUBS_PER_CONN` (`TooMany`); the registry already holds `MAX_SUBS_TOTAL` (new `SubscribeRefused::TableFull`). **(Architect's call)** Precedence is closed, then per-connection, then table: the per-connection cause is the one the client controls and can fix, and it keeps today's texts and tests unchanged whatever the global load. `McpServer::subscribe` maps `TableFull` to `tool_error`, in the same shape as the `TooMany` arm: text `flow.subscribe refused: the server's subscription table is full (max 4096 across all connections); try again later`, `isError: true`, no `sub_id`, and no `since` replay (the refusal returns before it). It is audited like every other refused subscribe by the existing path; the comment in `call_tool` that lists the refusal reasons gains it. 4096 is 128 connections at the per-connection cap, far above real use (a TUI, a web UI, a Mac app, a few agents); registry memory at the cap is under 10 MiB (each entry holds at most two 1 KiB filter strings). The cap is per `McpServer`: `aitm web` runs two servers (primary and web), so the process-wide figure is 2 x 4096.

**D2. Fan-out de-dup.** `fanout_flow`, `fanout_state` and `fanout_role` replace `seen: Vec<u64>` and `contains` with a `HashSet<u64>` and `insert`. The trap: in `fanout_flow` (filter) and `fanout_role` (role) the connection is inserted only after the subscription passes its test. Inserting first would let a non-matching subscription mask a later matching one on the same connection, a silent missed delivery. Why it matters at the cap: worst case is 4096 connections with one subscription each, which with a `Vec` is about 8.4 million comparisons per event under the lock, and `push_agent` does the same for every finished tool call; a `HashSet` makes it 4096 inserts. Tested behaviourally plus one mechanical check (AC5, AC6); there is no timing assertion.

**D3. Write deadline.**
- **Value (Architect's call):** `pub const DEFAULT_WRITE_TIMEOUT: Duration = 30 s` in `server.rs`, re-exported next to `DEFAULT_PUSH_CAPACITY`. It is 3x the 10 s handshake budget and 6x the 5 s close drain; it lets one 16 MiB frame finish at about 0.53 MiB/s (4.3 Mbit/s), far below any loopback or LAN reader; and it is short enough that a dead peer is gone in well under a minute after its buffers fill.
- **Semantics:** the budget is per send (one websocket frame) or per `write_all`/`flush` call. The clock starts when the send starts and stops when the socket has accepted the frame, not when the peer reads it.
- **Seam (Architect's call):** `McpServer::with_write_timeout(Duration)` (stored clamped to at least 1 ms) and `McpServer::write_timeout() -> Duration`, the same shape as `with_push_capacity`/`push_capacity`. The bridge already reads `state.mcp.push_capacity()` and `serve_lines` already reads `server.push_capacity()`, so one setting serves both transports, and a test lowers it without touching `WebState` (five struct literals, including `main.rs`) and without an env var. `serve(self)` destructures and rebuilds `McpServer` field by field, so the new field is added in both places.
- **Bridge:** a private `send_within` wraps `ws.send(..)` in `tokio::time::timeout(write_timeout, ..)` and is used at both post-auth send sites, the frame-done reply arm and the drain arm. Expiry returns an error from `relay`; the existing `ConnGuard` then closes the sink and drops the subscriptions. No Close handshake is attempted: a peer that is not reading cannot answer it, and `close_within` would spend up to 5 s more. Frames still in flight are detached, as on any other exit. The error reaches `run`'s existing `debug!` line; no new log, and nothing token-bearing. The pre-auth `UNAUTHORIZED_REPLY` send is left alone: 80 bytes into an empty socket buffer cannot block.
- **Line transport:** `write_loop` wraps each `write_all` and the `flush` in the same deadline and returns an error on expiry; `serve_lines` passes it `server.write_timeout()`. **(Architect's call)** This alone is not enough. `serve_lines` parks its read loop in `read_line` while a live peer is not reading, and it only drops the connection's subscriptions after that loop ends, so a writer that dies on the deadline would leave the connection and its subscriptions in place (a stopped-but-open TCP client never sends EOF). So when the writer ends in an error before the read loop does, `serve_lines` abandons the read loop, drops the subscriptions, closes the sink and returns that error. A writer that ends cleanly keeps today's behaviour.
- **stdio (Architect's call, flagged):** the stdio connection shares `serve_lines`, so a parent that stops reading our stdout for 30 s while we write ends the stdio connection, which ends a stdio-driven process the way stdin EOF does today. That is the same "peer is gone" judgment as for a socket.
- **Slow-but-live trade-off:** the deadline detects a peer that stops reading, not one that reads slowly. A reader that frees room for each frame within 30 s is never cut, even if it is a trickle; that is indistinguishable from a slow link, and such a peer pins only its own task and a bounded sink, no worse than before this change. A reader that stalls for more than 30 s with full buffers is cut: a browser tab frozen or paused in a debugger. That is acceptable, since the web client reconnects with back-off (`apps/web/src/bus/ws.ts`) and the `lagged` contract already tells it to resync. Replies in flight at expiry are lost, as on any disconnect.

**D4. How the real-socket tests make a never-reading client fill the buffers.** A "stopped" client is a client that never polls its socket after setup. To make the kernel buffers small, the client socket is built with `TcpSocket::new_v4()`, `set_recv_buffer_size(4096)` and `connect`, then upgraded with `tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(stream))`, which yields the same `Ws` type the helpers already use. The server's listener is built with `TcpSocket`, `set_send_buffer_size(4096)`, `bind`, `listen`; accepted sockets inherit it. Both are belt and braces: even if a platform ignores or clamps them, loopback autotuning holds well under 10 MiB while the tests push 16 MiB (the existing AC5 test relies on the same margin with 20 MiB). The server side gets `with_write_timeout(1 s)`.
- Drain arm: subscribe, stop reading, push 4096 flow events with a 4 KiB path each (16 MiB, below the 4096-line sink cap so nothing is dropped and the bridge really attempts every byte).
- Reply arm: a new in-process command `test.blob` returns a 1 MiB string; the stopped operator sends one frame of 16 `test.blob` lines (16 MiB of replies).
- Assertions never read byte counts from the kernel. Disconnect is observed two ways: the registry (an `Ask`-policy `test.sensitive` probe is refused at once with "no operator is connected", the existing `probe_ask_gate` technique, polled until it flips) and the socket (once the test resumes reading, the stream ends: buffered bytes, then end/reset).
- Non-flakiness comes from margins, not tuning: the registry must flip within `1 s + 5 s` (5x slack on a 1 s timer); the control with the 30 s default is still subscribed after 3 s (10x); the slow reader pauses 10 ms per frame against a 1 s deadline (100x); pushes exceed buffers by at least 16x. Total real time per test is about 2 to 4 s.
- The line transport has fast deterministic twins over `tokio::io::duplex(256)` (a write blocks exactly like a stopped socket) that run in the sandbox, plus one real loopback TCP test.

**D5. Test-support extraction in `aitm` (and why changing the older files is now acceptable).** New `crates/aitm/tests/support/web_bus.rs`, included by each `web_bus_*` test file the way `rig.rs` and `scripted_driver.rs` are (`#[path = "support/web_bus.rs"] #[allow(dead_code)] mod web_bus;`), not through `support/mod.rs`. It holds the union of the three files' helpers: tokens and timeout constants, `temp_ca_dir`, `UnusedClient`, `Parking`/`Release`, the test commands (`test.block`, `test.sleep`, `test.tick`, `test.panic`, `test.sensitive`) and `TestCommands`, `ServerOptions`/`Server`/`start`, `http_flow`/`push_flow`, `Ws` and the connect/send/receive/drain helpers, `open_bus` and friends, `subscribe`, `wait_until`, and the `Ask` probe. #137's AC7 required `web_bus_concurrency` and `web_bus_roles` to pass unchanged so that a green run was independent evidence that the push change, which rewrote the bridge's per-connection state, had not altered PR #103's behaviour: the oracle must not change in the same commit as the thing it checks. That PR has merged, so the oracle did its job, and this is the follow-up AC7 deferred. The oracle is still protected: (a) the extraction commits touch no production file, and the Tester runs the refactored files against the unchanged `bridge.rs` before the deadline change lands; (b) each file keeps a thin file-local wrapper with its old signature (`start`, `open_bus`), so every test body is byte-identical and the diff touches only harness items, imports and the `mod` line; (c) the test names and counts are identical (11 + 5 + 10 = 26), compared with `--list` before and after; (d) optional mutation spot-checks (below). Where the copies differ in strictness the shared helper takes the strictest behaviour that every current test satisfies, or the file keeps its local variant; never the more lenient. One token pair is shared: the tests assert on roles and behaviour, never on the token values.

**D6. Test-support in `aitm-mcp` (Architect's call, deviating from the brief's example path).** There is no `aitm-mcp/tests/support/` today, every copy of the push-server builder is inside `mcp.rs`, and the fixtures it needs (`StubClient`, `ungated`, `http_flow`, `CaptureCmd`, `is_refused`) are used by 60-plus other tests in that file. A new support module would have a single consumer and would force those fixtures to move with it. So the dedupe is one parameterised `push_server_with` builder inside `mcp.rs`'s push section, which `push_server` and the three inline copies use, and every "the reply carries a `sub_id`" assertion in that section goes through `sub_id_of`. If Matt prefers a `support/mod.rs`, the same helper moves there mechanically.

**D7. Docs.** Update the `bridge.rs` module doc (the write deadline, and that "a push send fails" is now bounded by it), the `serve_lines` doc, and the doc of `MAX_SUBS_PER_CONN` (point at the total cap). The web-bus-push spec is left as history; this spec supersedes its non-goal "no write timeout".

## Threat/Failure model

| Bound | Defends against | Does not defend against |
|---|---|---|
| `MAX_SUBS_PER_CONN` (32, existing) | One authenticated connection inflating the registry | Many connections |
| `MAX_SUBS_TOTAL` (4096, new) | A token-holder opening many connections to inflate registry size, and with it the lock-hold time of every flow event, state push and audit fan-out; registry memory (< 10 MiB) | See residuals below |
| `HashSet` de-dup | The O(subs x connections) amplification at the cap (CPU under the lock) | Nothing is bounded by it; it changes cost, not delivery |
| Write deadline (30 s) | A peer that stops reading while the server writes: pinned task, FD, subscriptions, a ghost operator keeping `any_role(Operator)` true so agent `Ask` calls park instead of refusing | Residuals below |

Known residuals, accepted:
- **Connection count.** No web listener cap. `MAX_SUBS_TOTAL` is meaningful without one: fan-out cost follows the number of subscriptions, and a connection with none is not in the registry. What stays unbounded is connections themselves (tasks, FDs, each with an idle bounded sink); in practice the process FD limit is the bound. Follow-up if wanted.
- **Starvation.** A token-holder (the lower-privilege agent token included) can fill the 4096 slots and make later subscribes, the operator UI's included, fail until it disconnects. The UI still works by polling. No role reservation in this change (flagged, call 9).
- **Per-server caps.** The web and primary servers each have a registry, so the process-wide bound is 2 x 4096; connections with one subscription each still cost O(connections) per audit line (bounded by the FD limit).
- **Trickle readers** that free just enough room per frame are never cut (D3).
- **Idle ghosts.** A half-open peer with no traffic is never written to, so the deadline never fires and an idle subscribed operator stays registered until some write fails. Liveness pings are a separate feature.
- **Refusal audit.** A refused subscribe is audited and fanned to subscribers once per connection, as for the per-connection refusal today; unchanged.

Failure behaviour at expiry: the connection is dropped without a Close frame, replies in flight are lost (as on any disconnect; the effect of a command that already ran stays), logging is `debug` only.

## Acceptance criteria

Test names are the contract; file locations are in the plan. "Terminal" marks tests that bind loopback.

**Registry bound**
1. AC1: `MAX_SUBS_TOTAL` is 4096. With 128 connections holding 32 subscriptions each (4096; all 4096 adds succeed), `Subscriptions::add` for a 129th connection returns `Err(SubscribeRefused::TableFull)` and the registry still holds 4096. Test `the_table_cap_refuses_another_connection`.
2. AC2: With the registry full, a closed sink gets `Err(Closed)`, a connection holding 32 gets `Err(TooMany)`, and a connection holding fewer than 32 gets `Err(TableFull)`. Test `refusal_precedence_is_closed_then_per_connection_then_table`.
3. AC3: With the registry full, `remove` of one subscription lets exactly one more `add` succeed and the next gets `TableFull`; `drop_connection` of a connection holding 32 lets 32 adds succeed. Tests `unsubscribe_frees_exactly_one_table_slot`, `ending_a_connection_frees_its_table_slots`.
4. AC4: With the registry full, `flow.subscribe` through `handle_on` returns `isError: true`, content text exactly `flow.subscribe refused: the server's subscription table is full (max 4096 across all connections); try again later`, and no `structuredContent`. Test `a_full_table_refuses_flow_subscribe_with_its_own_text`.
5. AC5: Fan-out still delivers once per connection: a connection with 32 matching subscriptions gets 1 push; a connection whose first subscription does not match and whose second does gets 1 push; `fanout_state` with 4096 connections of one subscription each reaches each exactly once; `fanout_role(Operator, ..)` reaches only operator connections, once each, with 3 subscriptions per connection. Tests `a_connection_with_many_matching_subscriptions_gets_one_push`, `a_non_matching_subscription_does_not_mask_a_matching_one`, `fanout_state_reaches_every_connection_once_at_the_table_cap`, `fanout_role_reaches_only_that_role_once_per_connection`.
6. AC6 (mechanical, not a test): `rg -n "seen: Vec" crates/aitm-mcp/src/server.rs` matches nothing; the three fan-out functions use `HashSet<u64>`.

**Write deadline**
7. AC7: `McpServer::new(..).write_timeout()` equals `Duration::from_secs(30)` and `DEFAULT_WRITE_TIMEOUT` equals it; `.with_write_timeout(Duration::from_secs(7))` reads back 7 s; `.with_write_timeout(Duration::ZERO)` reads back 1 ms. Tests `write_timeout_defaults_to_30_seconds`, `with_write_timeout_sets_it_and_clamps_zero`.
8. AC8: `send_within` returns `Err` (message contains "timed out") within 2 s for a 50 ms limit when the peer never reads a 1 MiB message over a 64 KiB duplex, and returns `Ok` with the full text delivered when the peer reads. Tests `send_within_gives_up_on_a_stalled_peer`, `send_within_delivers_to_a_live_peer`.
9. AC9 (Terminal): an operator that subscribes and then never reads, while 16 MiB of flow pushes are sent, is disconnected: the `Ask` probe is refused immediately with "no operator is connected to approve it" within 6 s of the pump, and the client's stream then ends. Test `a_stopped_operator_is_disconnected_by_the_write_deadline`.
10. AC10 (Terminal): an operator that subscribes, sends one frame of 16 `test.blob` lines and never reads is disconnected the same way (the reply send site). Test `a_stopped_reader_of_large_replies_is_disconnected_by_the_write_deadline`.
11. AC11 (Terminal): an agent-token connection that subscribes and never reads has its stream end within the same bound. Test `a_stopped_agent_is_disconnected_by_the_write_deadline`.
12. AC12 (Terminal): control. The same stopped operator on a server with the default 30 s deadline is still subscribed 3 s after the pump: the `Ask` probe parks and then times out with the parked reason, not the no-operator reason. Test `a_stopped_operator_is_still_connected_before_the_default_deadline`.
13. AC13 (Terminal): a reader that sleeps 10 ms between frames, against a 1 s deadline and a 16-line sink, is not disconnected: the final distinctive event arrives and a later `flow.list` call gets `isError: false`. Test `a_slow_but_live_reader_is_not_disconnected`.
14. AC14: over `duplex(256)` with a 200 ms deadline, a client that subscribes, then neither reads nor closes, while state pushes of 4 KiB are sent: `serve_lines` returns `Err` whose text contains "write timed out" within 5 s, the injected sink `is_closed()`, and a push after the return leaves `queued_len()` unchanged. Test `a_stopped_line_reader_ends_the_connection_after_the_write_deadline`.
15. AC15: over the same duplex, a client that reads one line per 5 ms receives all 100 pushed state lines in order and `serve_lines` has not finished. Test `a_slow_line_reader_is_not_disconnected`.
16. AC16 (Terminal): a real loopback TCP client (4096-byte receive buffer) that subscribes and stops reading, against a `LoopbackTcp` server with a 1 s deadline and 16 MiB of 4 KiB state pushes (4096 lines): after waiting 2 s and then resuming reading, the client reaches EOF within 15 s having received fewer bytes than were pushed. Test `a_stopped_tcp_client_is_disconnected_by_the_write_deadline`.

**Test support**
17. AC17: `cargo test -p aitm --test web_bus_concurrency --test web_bus_roles --test web_bus_push -- --list` prints the same 26 test names (11, 5, 10) before and after the extraction, all pass, and `git diff -U0` over the three files shows no changed line inside a test function. Verified at the extraction commits (production code untouched) and at head.
18. AC18: each shared harness item is defined once, in `support/web_bus.rs`: `rg -n "^struct UnusedClient|^fn temp_ca_dir|^struct Parking|^struct Release|^async fn next_frame|^async fn recv_until\b" crates/aitm/tests/web_bus_*.rs` matches nothing. (Thin wrappers that keep an old signature, such as `start`, `open_bus`, or `ws_connect` returning a `Result`, may stay local.)
19. AC19: `mcp.rs` has 73 tests before and after the dedupe (75 at head, after AC5's two); `rg -n "push_registry\(\)" crates/aitm-mcp/tests/mcp.rs` has exactly two matches (the definition and its one use inside `push_server_with`); `rg -n '"sub_id"\]' crates/aitm-mcp/tests/mcp.rs` matches only inside `sub_id_of` and the two pre-existing sites outside the push section (the `Paused` policy test and the `Ask` section's helper).

**Gate**
20. AC20: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes, with the Terminal-marked tests run in the Terminal panel.

Optional mutation spot-checks for the Tester, each expected to turn the named test red and then be reverted: `MAX_LINES_PER_FRAME` +1 in `bridge.rs` (`a_frame_over_the_line_cap_closes_the_connection_and_runs_nothing`); `classify_token` returning `Operator` for the agent token (`agent_bridge_token_runs_as_agent`); removing `drop_connection` from `ConnGuard::drop` (`disconnect_drops_the_subscription`); inserting into `seen` before the filter test in `fanout_flow` (`a_non_matching_subscription_does_not_mask_a_matching_one`); removing the `timeout` at either bridge send site (AC9 or AC10).

## Left to the builder

- Names and signatures of file-local helpers; whether `send_within` is generic over the stream (as `close_within` is) or fixed to `Ws`; the exact error text of a write timeout, provided it contains "timed out" on the bridge and "write timed out" on the line transport.
- How `serve_lines` observes the writer ending (a `select!` over the writer's join handle, a signal from the writer task, or another structure). A `JoinHandle` cannot be polled again after it completes, so do not await it twice.
- The shape of `ServerOptions` additions, provided they use struct-update syntax at call sites so additive fields cannot break the extracted files.
- Whether `test.blob` is 1 MiB with 16 lines or a different split, provided the replies total at least 16 MiB after result rendering and the frame stays within 256 lines.
- How the stopped client is built, provided its receive buffer is set before connect.

## Architect's calls

1. `MAX_SUBS_TOTAL = 4096`, per `McpServer`. 2. Precedence closed, then per-connection, then table. 3. New `SubscribeRefused::TableFull` and the text in D1. 4. `DEFAULT_WRITE_TIMEOUT = 30 s`, per send, no config surface. 5. The seam is `McpServer::with_write_timeout`, not a `WebState` field. 6. The line transport applies to stdio too. 7. Expiry is a hard drop with no Close handshake, logged at `debug`. 8. `serve_lines` abandons its read loop when the writer dies on an error. 9. No Operator reservation in the total cap. 10. The pre-auth refusal send is not wrapped. 11. Test deadline 1 s, client `SO_RCVBUF` 4096, listener `SO_SNDBUF` 4096, 16 MiB pumps, `test.blob`. 12. `web_bus.rs` is included by `#[path]` like `rig.rs`; file-local wrappers keep test bodies byte-identical; one shared token pair. 13. No `aitm-mcp` support module; one `push_server_with` in `mcp.rs`. 14. A grep plus characterization tests instead of a timing check for the HashSet change.

## Open questions

None blocking. Two calls with a security or product flavour are flagged for Matt in the PR body, each with a default and a one-line way to flip: call 9 (reserve part of the total cap for the Operator role, so an agent token cannot starve the operator UI of subscriptions) and call 6 (exempt stdio from the deadline, so a stalled stdio parent never ends the stdio connection).
