# Bus write-buffer bound design

**Status:** Approved 2026-10-30 by the orchestrator under Matt's autonomous-approve delegation (flagged in the PR body for Matt's review). Written against the bus-hardening head `e35a421`; re-check against `main` after that PR merges, before any implementation.
**Research inputs:** side-session notes, outside the repo, so their facts are restated in Evidence: `bus-hardening-preexisting-preauth-findings.md` and the FOLLOW-UP section of `bus-hardening-panel-round1.md` (both in `/Users/matt/Library/Application Support/Claude-3p/side-session-notes/local_442560dc-64f0-46e9-b1dc-1eebb93b3f88/`). Code read at the bus-hardening head `e35a421` (branch `claude/vibrant-proskuriakova-e98cfd`, assumed merged to `main` before this is built): `crates/aitm/src/web/{bridge,http,mod}.rs`, `crates/aitm-mcp/src/{transport,server,http,render,json,lib}.rs`, `crates/aitm/tests/support/web_bus.rs`, `crates/aitm/tests/web_bus_write_deadline.rs`, and that branch's `docs/superpowers/specs/2026-10-30-bus-hardening-design.md`. Also read: `crates/aitm-core/src/{config,store,command}.rs`, `crates/aitm-plugin-sessionio/src/{lib,native}.rs`, `crates/aitm-plugins/src/{capture,detail}.rs`, the cargo-registry sources of tungstenite 0.28.0, tokio-tungstenite 0.28.0 and hyper 1.11.1, and the first-line writers in `apps/web/src/bus/ws.ts`, `apps/mac/Sources/AitmBusClient/BusClient.swift`, `crates/aitm-bus-client/src/lib.rs`, `tests/e2e/aitm_e2e/{bus,ws}.py`. Measurements come from throwaway programs under `$TMPDIR` (never in the repo); see Evidence.

## Intent

The `/bus` bridge builds its websocket with `WebSocketConfig::default()`, which leaves the write buffer unbounded. tungstenite answers every Ping with a Pong inside `read()`; when the socket is full it keeps the Pong in a user-space `Vec`. A peer that sends Pings and never reads therefore grows server memory in step with the bytes it sends (measured: 3,000,000 Pings, 374.79 MiB sent, 508.14 MiB live heap). It works before authentication, for the handshake window, and after it, with no time limit, for anyone holding the agent token. The bus-hardening write deadline cannot see it, because the Pong is buffered, not blocked on, so no send is outstanding. This spec closes it by making the bridge **drain each Pong under the existing deadlines**, not by capping the buffer: a cap cannot sit below the largest legitimate reply, and that reply is orders of magnitude larger than any useful cap. Three more pre-existing pre-auth items in the same two files ride along: an unparsed-first-line size bound, a deadline on the TCP bus's first-line read, and a drop guard on `serve_lines`.

## Goals

- A peer that sends Pings and stops reading holds O(1) server heap and is disconnected: before authentication by the end of the handshake window, after it within the write deadline.
- A client that reads gets its Pongs exactly as today; no budget, rate limit or cap is added that a keepalive could trip.
- No reply or push is refused, truncated or delayed by anything this change adds, whatever its size.
- A pre-auth first line over a bound derived from the configured tokens is refused before it is parsed, on the web bridge and the TCP bus; the TCP read itself never buffers more than that bound.
- The TCP bus's pre-auth first-line read ends at the same deadline as the web bridge's, from one definition.
- `serve_lines` tears its connection down when its future is dropped, not only when it returns.
- The per-connection worst-case memory, pre- and post-auth, is stated with numbers and tested through observable byte counts.

## Non-goals

- **A write-buffer cap** (`max_write_buffer_size`). Rejected with evidence, not deferred (Design 2).
- **A ping or control-frame budget or rate limit.** Rejected (Design 2).
- **Audit-stream role scoping** (`push_agent` / `agent.activity`). Unchanged.
- **A web listener connection cap.** The security reviewer's recommended next hardening item; a separate follow-up, **"web listener connection cap"**. Design 8 says how this spec's bounds compose with it. This spec does not add it.
- **Moving `ConnGuard` into `aitm-mcp`.** Unchanged. The `serve_lines` guard (Design 6) is a third private copy of the same two-line teardown (`bridge.rs`, `http.rs` SSE, now `transport.rs`); unifying them is that separate item.
- **A reply byte budget and `flow.export` streaming.** Evidence E2 shows replies are unbounded in bytes (a single-flow export of a default-maximum body is about 442 MiB). Bounding them is product-shaped; named follow-up **"reply byte budget"**. Calls for Matt, 1.
- **A write deadline on the streamable-HTTP transport** (POST responses and the SSE lane). Evidence E4; named follow-up **"HTTP write deadline"**.
- **A pre-auth read-side cap on the web bridge.** The library reserves the claimed frame length (up to 16 MiB) before a peer sends payload, and the bridge cannot lower the limit after authentication (E1). Named follow-up **"pre-auth read bound"**; needs a tokio-tungstenite that exposes `set_config` or a custom pre-auth reader.
- Changing `MAX_MESSAGE_BYTES`, `WebSocketConfig` at all, `write_buffer_size`, or the tungstenite / tokio-tungstenite versions.
- A config key, flag or env var for the new pre-auth timeout or first-line bound. A builder method on `McpServer`, like `with_write_timeout`, is all there is.
- Idle-connection liveness (bridge-initiated Ping, TCP keepalive). The deadlines fire only while the server writes or flushes.

## Anti-goals

- A cap below the largest legitimate single reply. It refuses that reply on a healthy, reading peer (E1, measured), which is a worse failure than the one fixed.
- A fix that bounds memory but leaves the Ping-only peer connected forever. A cap alone does exactly that (E1, measured).
- A budget or rate limit on Pings that a legitimate keepalive could trip.
- A test that passes on timing alone, or only over `tokio::io::duplex` while the real `hyper` upgrade plus TCP path behaves differently. The duplex tests are fast proofs; the socket tests are the end-to-end proof.
- Any `unsafe` (the workspace is `unsafe_code = "forbid"`), including a counting allocator in a test.
- A fix to `bridge.rs` only. The TCP bus has its own pre-auth gaps and gets its own fixes here.

## Constraints

- No dependency changes. `Cargo.lock` is unchanged; tungstenite and tokio-tungstenite stay at 0.28.0. No tokio `test-util` feature (nothing in the workspace uses it).
- `unsafe_code = "forbid"` is workspace-wide. Memory is therefore asserted through observable byte counts (bytes a flooding peer could push before the server stopped consuming), not an allocator.
- Hot path: one `flush` call after a Ping frame, and a length comparison on a first line. No cost on data frames.
- Behaviour that must not change: replies and pushes are sent as today (`send_within`, `write_timeout`), unauthenticated peers still get the same bad-token refusal, the token-line shape accepted is unchanged for any line within the bound.
- Sandbox: `tokio::io::duplex` tests and unit tests run in the Bash sandbox. Tests that bind loopback (the harness `start`, `LoopbackTcp`) need the Terminal panel; the sandbox's `EPERM` on bind was reconfirmed while writing this spec. The Coder says which it could not run.
- Gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

## Evidence

All measurements: release build, tungstenite 0.28.0 and tokio-tungstenite 0.28.0 from `Cargo.lock`, server end `WebSocketStream::from_raw_socket(.., Role::Server, ..)` over `tokio::io::duplex(4096)`, config as `bridge::run` builds it (`max_message_size` and `max_frame_size` 16 MiB), the client end never read. Ping frames carry 125 bytes of payload (131 bytes on the wire, 127-byte Pong). A counting global allocator (in the throwaway only) read live heap.

### E1. tungstenite 0.28.0 semantics (read in `protocol/mod.rs`, `protocol/frame/mod.rs`; confirmed by the measurements below)

- Defaults: `write_buffer_size` 128 KiB, `max_write_buffer_size` `usize::MAX`, `max_message_size` 64 MiB, `max_frame_size` 16 MiB. The write side enforces neither of the last two (a 20 MiB frame was sent under a 16 MiB `max_frame_size`).
- `read()`: a Ping calls `set_additional(Pong)`; the next `read()` call runs `flush`, which moves the Pong into the codec's `out_buffer` (`FrameCodec::buffer_frame`) and tries the socket. On `WouldBlock` it keeps reading ("If blocked continue reading, but try again later") and the bytes stay in `out_buffer`. Each Ping read adds at most 127 bytes; nothing bounds the total. `Vec` doubling makes the measured heap about the next power of two above the Pong bytes (3,000,000 x 127 B = 363 MiB of Pongs, 508 MiB of heap).
- `buffer_frame` refuses with `WriteBufferFull` when `frame.len() + out_buffer.len() > max_write_buffer_size`. `frame.len()` is header plus payload, and the test ignores whether the socket is healthy: **a single frame larger than the cap is refused on an empty buffer and a reading peer.** `max_write_buffer_size` must exceed `write_buffer_size` or `assert_valid` panics.
- For an automatic Pong, `_write` catches `WriteBufferFull`, puts the Pong back in `additional_send` and carries on. **`read()` never returns it**, so a cap bounds memory but never ends the connection of a Ping-only peer. The error reaches the caller only for frames the caller sent.
- Only Ping (and a peer Close, answered once) uses `additional_send`; Ping is the only unbounded producer. After our own Close is queued a Ping is not answered (`state.is_active()`), so `close_within`'s drain loop cannot grow the buffer.
- `set_config` exists on `WebSocket` and reaches the codec, but tokio-tungstenite 0.28.0's `WebSocketStream` exposes `get_config` only and keeps its `inner` private. A smaller pre-auth cap cannot be applied and then relaxed. Rebuilding the stream after authentication would lose the codec's read-ahead (`from_partially_read` needs bytes the codec holds privately), and real clients pipeline the token frame and `initialize`.
- tokio-tungstenite: `poll_flush` turns `WouldBlock` into `Pending`, so `SinkExt::flush` under `tokio::time::timeout` is a faithful "has the socket taken what I owe it" probe. hyper 1.11.1's `Upgraded::poll_write` forwards straight to the socket and adds no buffer, so the duplex behaviour carries over to the real upgrade, with the kernel's socket buffers as the only extra capacity.

### E1 measurements

| Run | Result |
|---|---|
| Default config, 300,000 Pings (37.48 MiB) | server saw all, no error, live heap +63.65 MiB |
| Default config, 3,000,000 Pings (393,000,000 bytes = 374.79 MiB) | server saw all, no error, live heap +508.14 MiB (peak 508.27) in 0.68 to 0.95 s; the peer's writes were accepted for **all 393,000,000 bytes** |
| `max_write_buffer_size` 256 KiB, 3,000,000 Pings | server saw all, **connection still up, `next()` never errored**, live heap +0.57 MiB (peak 0.82) |
| Flush each Ping under 200 ms, 3,000,000 Pings | server saw 33, flush timed out after 202 ms, live heap +0.26 MiB (peak 0.26); the peer's writes were accepted for **12,288 bytes (12 KiB)** of the 393,000,000, then failed |
| Flush each Ping, 50,000 Pings from a client that **reads** | all 50,000 Pongs received, payloads echoed in order, 45 ms, peak heap +0.02 MiB |
| Cap 1 MiB, text of 1,048,476 bytes (frame 1,048,486) to a draining peer | `Ok` |
| Cap 1 MiB, text of exactly 1 MiB, and of 2 MiB, to a draining peer | `Err(WriteBufferFull)` both |
| No cap, 20 MiB send to a draining peer | `Ok`; peak heap +20 MiB (the codec copies the frame), **20.13 MiB retained afterwards** (`out_buffer` never shrinks) |
| 14-byte frame header claiming 16 MiB, then silence | live heap +15.88 MiB (reserved at header parse; resident only as payload arrives) |
| `serde_json::from_str::<Value>` of a 16 MiB `[0,0,...]` line | peak extra heap 256.00 MiB |

### E2. The largest legitimate single reply

Replies are not capped anywhere on the bus: `render_content` (`aitm-mcp/src/render.rs`) pretty-prints the whole value; `call_tool` returns it as `structuredContent` and again as `content[0].text`, so the value is on the wire twice; `Value::Bytes` becomes base64 (`json::to_json`, x4/3). The write side enforces no size (E1). What bounds the data is the core:

- `flow.detail {id, body: inline}`: request and response bodies, each capped by `limits.max_body_bytes` (default 10 MiB, `aitm-core/src/config.rs`; an operator can raise it in the config file with no upper bound). Default-config maximum: 2 x 4/3 x (10 + 10) MiB, about **53.3 MiB** (computed).
- `flow.export` with no `path` (any frontend that may call it; it is unclassified, so `Sensitive`: operator always, agent under `all` or after approval) returns the whole store, or the `ids`, as one `Bytes` value in the native format (`serde_json::to_vec_pretty` of `SessionDoc`, a body is `Bytes(Vec<u8>)`, so one JSON array element per byte). Measured with the real `to_doc` and `to_vec_pretty`: a flow with a 1 MiB response body is a 16.6 MiB document; base64 22.1 MiB; **the reply carries it twice, about 44.2 MiB**. A 4 MiB body measured 66.3 MiB and 176.8 MiB. So one flow with a default-maximum 10 MiB body is about **442 MiB** (linear extrapolation), and a store at its default 512 MiB budget (`DEFAULT_MAX_FLOW_BYTES`; `0` means unbounded) is on the order of **22 GiB**.
- Other bulk verbs (`flow.table`, `flow.list`, `agent.activity` up to 4096 entries, `scan.report`, `browser.screenshot`) were not sized. The point is settled by the two above, the larger of which has no bound in code.

Conclusion: no fixed cap fits. Any `max_write_buffer_size` that lets `flow.export` through is above a gigabyte and bounds nothing; any smaller one refuses legitimate replies (E1). Nothing in this spec constrains reply size.

### E3. The TCP bus (`aitm-mcp/src/transport.rs`)

- `serve_connection` reads the first line with `read_message`, which allows up to `MAX_MESSAGE_BYTES` (16 MiB) into a `String`, then `classify_token` runs `serde_json::from_str::<Value>` on all of it. No deadline wraps the read, so a silent loopback peer pins a task and an fd forever.
- `serve_lines` spawns its writer task and runs teardown (close the sink, `drop_connection`, join the writer) as straight-line code after the read/writer race. A cancelled or unwound future skips it: the detached writer keeps the socket's write half, the connection's subscriptions stay registered, and the peer gets no EOF (the writer ends only when a later write fails).
- The bad-token refusal writes about 80 bytes to a connection to which the server has sent nothing, so it cannot block; the TCP bus has no Pong equivalent.

### E4. The other transports: is there a buffer of the same class (output growing with bytes the peer sends, with no request/reply pacing)?

- **Line transport (stdio, loopback TCP): no.** Every output line is a reply to a request line or a push, both through `NotificationSink`. The reply lane backpressures the reader at `DEFAULT_REPLY_HIGH_WATER` (1024 replies), the notification lane holds 4096 lines (drop-oldest), and the write deadline ends a peer that stops reading. The residual is **bytes**: both bounds are counts, so queued replies are bounded by 1024 (plus the batch the blocked writer already drained) times the reply size.
- **Web bridge, replies:** up to `MAX_IN_FLIGHT` (16) frames of up to `MAX_LINES_PER_FRAME` (256) lines, each reply held until its frame completes: 4096 replies, each unbounded in bytes. Same residual, same follow-up.
- **Streamable HTTP, POST:** one buffered reply per connection (hyper serves one request at a time per connection), at most `MAX_CONCURRENT_CONNECTIONS` (1024) connections. No write deadline: a client that sends a request and never reads pins its task and its reply. Not the Pong class (nothing grows with unsolicited bytes); a named follow-up.
- **Streamable HTTP, SSE:** `mpsc::channel(1)` plus the 4096-line sink; a stopped client blocks the writer in `tx.send` indefinitely. Bounded, no deadline. Same follow-up.
- Verified by reading `aitm-mcp`'s code, not by running a stopped client against each transport. That hyper handles one request at a time per HTTP/1 connection is from its documented server model; its source was not read for this.

### E5. The first line the clients actually send

| Writer | Bytes |
|---|---|
| Web UI, `apps/web/src/bus/ws.ts` | `{"token":"<t>"}` + `\n`, compact |
| macOS app, `BusClient.swift`; Rust client, `aitm-bus-client` | compact, `\n` |
| e2e harness, `tests/e2e/aitm_e2e/bus.py`, `ws.py` (`json.dumps`) | `{"token": "<t>"}` with a space, `\n` |

Generated tokens are 64 hex characters (`generate_token`, `generate_operator_token`), so a first line is 76 to 77 bytes. A user-supplied `--token`, `AITM_WEB_TOKEN` or `mcp.operator_token` can be any non-empty length, so a fixed constant could lock one out; the bound is derived from the configured tokens (Design 4).

### E6. Which clients send Pings

None of the first-party clients does: a browser's `WebSocket` API cannot send a Ping, the e2e `ws.py` only answers them, the Swift app speaks TCP. The Ping path is exercised by third-party RFC 6455 clients that keep a connection alive. The bridge never sends Pings itself.

## Design

### 1. Drain each Pong under a deadline (Architect's call: the decision this spec exists to make)

In `bridge.rs`, next to `send_within`, a private `async fn flush_within<S>(ws: &mut WebSocketStream<S>, limit: Duration) -> anyhow::Result<()>` with `S: AsyncRead + AsyncWrite + Unpin`. It runs `ws.flush()` under `tokio::time::timeout(limit, ..)`; expiry is an error whose text contains `timed out after` (the same marker `send_within` uses); a transport error passes through. It is called from the two places that read Pings:

- **Post-authentication:** the read arm's `Message::Ping(_)` branch awaits `flush_within(&mut ws, write_timeout)` before the loop selects again. On error `relay` returns it; `ConnGuard` runs as on every exit; no Close is attempted (a peer that is not reading cannot answer one), the same disposition as a `send_within` expiry.
- **Pre-authentication:** the token loop's ping/pong branch (today `Some(Ok(_)) => continue`) gains a `Message::Ping(_)` branch that awaits `flush_within` with the time left until the handshake deadline (`deadline - now`), and on error returns it without a Close. The handshake deadline stays absolute, so a flood cannot extend it, and a stalled flood ends no later than it.

**Why this is bounded by construction.** `read()` queues at most one Pong per frame it reads and moves it into `out_buffer` on the next `read()` call. The loop does not call `ws.next()` again until the flush returns, so at most one Pong is ever outstanding, whatever the peer sends. The measured result (E1) is flat heap, 33 Pings consumed, and a stop at the deadline. The frames the peer keeps sending queue in the kernel's socket buffers, which are bounded and are not the process heap.

**What it costs a reading client:** nothing. A flush with room in the socket returns at once (50,000 Pings, 50,000 Pongs, in order, 45 ms). While a flush waits the loop is not servicing frames or pushes; that is the same stall `send_within` already imposes, and it only lasts while the peer is not reading.

`WebSocketConfig` is not touched. The read arm's `debug!("websocket ping/pong")` stays; the `Pong` branch does nothing new.

### 2. Alternatives considered, and why each lost

| Option | Verdict, with evidence |
|---|---|
| (a) Set `max_write_buffer_size` | Memory is bounded (0.57 MiB measured) but the peer is **never disconnected**: the automatic Pong's `WriteBufferFull` is swallowed inside tungstenite (E1), so a post-auth Ping-only peer stays connected indefinitely. The cap must also be at least the largest legitimate frame, which is a gigabyte or more (E2), so it would bound nothing; set lower, it refuses legitimate replies on a reading peer (measured). It also panics unless larger than `write_buffer_size`. Rejected. |
| (a') A smaller cap pre-auth than post-auth via `set_config` | Not available: tokio-tungstenite 0.28.0 does not expose `set_config`, and rebuilding the stream after authentication loses read-ahead the real clients depend on (E1). Rejected. |
| (b) Ping budget (close after N Pings, or a rate limit) | A heuristic with a false-positive risk for a legitimate keepalive, and it does not bound memory by itself (one Ping per second still grows the buffer without limit against a full socket). The reading-flood cost it would limit is no worse than a flood of JSON-RPC `ping` requests an authenticated peer can already send. Rejected. |
| (c) Drain each Pong under a deadline | Bounded by construction, disconnects exactly the peer that is not reading, uses the deadlines that already exist, adds no limit a client can trip. Chosen. |
| (d) Do not answer Pings, or close on the first Ping | tungstenite always queues the Pong (no config switch), and refusing Pings breaks RFC 6455 clients. Rejected. |

A cap is not added as defence in depth either: with Design 1 in place `out_buffer` holds one frame being sent plus at most one Pong, so a cap would only ever fire on a legitimate reply.

### 3. Worst-case memory per connection, with numbers

Write side (the class this spec closes):

| | Before | After |
|---|---|---|
| Pre-auth | unbounded: about 1.36 bytes of heap per byte sent (508.14 MiB for 374.79 MiB), for the 10 s handshake window | at most one Pong (127 bytes) and the codec's fixed buffers: **+0.26 MiB** measured after a 3,000,000-Ping flood; the flood ends by the handshake deadline |
| Post-auth | unbounded in size and time, any token holder | the same one Pong; the flood ends within `write_timeout` (30 s by default) of the first Pong the socket would not take |

Post-auth, independent of Pings and unchanged: the reply or push being sent (transiently twice: the `Message` and the codec's copy, 20 MiB measured for a 20 MiB frame), and `out_buffer` capacity retained for the connection's life at the largest frame ever sent (20.13 MiB measured after one 20 MiB send; the library does not shrink it). The reply-sized terms in E4 (4096 in-flight replies on the web bridge; 1024 queued replies plus the writer's batch on the line transports) are not changed here.

Read side before authentication, unchanged here: up to 16 MiB of reserved frame (15.88 MiB measured for a 14-byte header; resident only as the peer sends the payload) plus one assembled fragmented message of up to 16 MiB (by reading `IncompleteMessage`, not measured); that is at most about 32 MiB allocated per connection and about 1:1 with bytes the peer actually sent. The 256 MiB parse spike (E1) goes to zero (Design 4). On the TCP bus the pre-auth read goes from 16 MiB to `limit + 2` bytes (770 for 64-hex tokens).

### 4. Pre-auth first-line bound (folded-in item 1)

- **Helper (Architect's call):** `pub fn auth_line_limit(agent: &str, operator: Option<&str>) -> usize` in `aitm-mcp/src/transport.rs`, `8 * (longest configured token, in bytes) + 256`. The 8 covers the worst JSON expansion of a byte (`\u00XX`, 6 bytes) with room; the 256 covers `{"token":""}`, whitespace and the line ending. For two 64-hex tokens it is **768**. It is derived, not a constant, so no legal token is locked out; a 4 KiB constant would be arbitrary and could still lock out a long `--token`. `bridge.rs` imports it from `aitm_mcp::transport` (both are public).
- **Web bridge:** the guard sits in `bridge.rs`'s `classify_token`, before either `token_line_matches` call (today up to two full parses of the same line). The first non-empty line, as `lines_of` already trims it, longer than `auth_line_limit(&state.agent_token, operator)` is not parsed and resolves to `None`, so the existing bad-token refusal (`refuse_unauthorized`) runs. The library has already received the frame; this removes the parse amplification only (Design 3 states the residual).
- **TCP bus:** `serve_connection` reads the first line through a variant of `read_message` that takes its own limit and never buffers more than `limit + 2` bytes (the line, `\r`, `\n`); a first line that is not complete within that is a bad token. `classify_token` also checks the trimmed length before parsing, so the two checks agree. The refusal is the existing `unauthorized` line and shutdown.
- **Unchanged:** the token-line shape (exactly one key, `token`, a string) and the constant-time comparison. Over-limit means refused, never truncated.

### 5. Pre-auth timeout, one definition (folded-in item 2)

- **Where the constant lives (Architect's call):** on `McpServer`, next to the write deadline: `pub const DEFAULT_PRE_AUTH_TIMEOUT: Duration` (10 s, re-exported from `lib.rs` beside `DEFAULT_WRITE_TIMEOUT`), `McpServer::with_pre_auth_timeout(Duration) -> Self` (clamped to at least 1 ms, like `with_write_timeout`) and `McpServer::pre_auth_timeout() -> Duration`. Both transports already hold the `McpServer` they serve. The bridge's private `HANDSHAKE_TIMEOUT` goes away: `relay` reads `state.mcp.pre_auth_timeout()` once when the connection starts, so the web value is still 10 s. Tests lower it without touching `WebState` or the transports. `McpServer::serve` destructures the struct and rebuilds it field by field (the trap the write deadline hit), so the new field is added in both places. `CLOSE_DRAIN_TIMEOUT` (5 s) stays in `bridge.rs`: it is web-only.
- **TCP bus:** `serve_connection` wraps the whole first-line read in `tokio::time::timeout(server.pre_auth_timeout(), ..)`. The budget is absolute, so a peer that drips one byte at a time cannot extend it. Expiry drops the connection (no reply: a peer that sent nothing is owed nothing) and returns an error that the accept loop already logs at debug. The deadline covers only the first line; an authenticated idle connection is never timed.

### 6. A drop guard on `serve_lines` (folded-in item 3; Architect's call: include)

Include, because the change is local to a file this spec already edits, has a deterministic red/green test, and the harm, while unreachable today (nothing aborts a connection task and no panic source was found in `read_loop`), is a leaked task, socket write half and subscription set with no EOF to the peer. A private guard in `transport.rs` holding the server, `conn_id` and the sink does, in `Drop`, exactly the two calls teardown already makes, in the same order (close the sink, then `drop_connection`). `serve_lines` creates it once `conn_id` is known and drops it explicitly at today's teardown point, so the order relative to joining the writer is unchanged; if the future is dropped or unwinds earlier, `Drop` runs the same two calls and the writer, seeing its sink closed, drains and exits and releases the socket half.

### 7. What this does not fix, so the PR can say it plainly

Pre-auth read-side memory on the web bridge (about 32 MiB allocated per connection, 1:1 with attacker bytes), reply byte volume on every transport (E2, E4), the HTTP transport's missing write deadline, idle connections, and the missing listener connection cap. Each is a named follow-up above; none is made worse.

### 8. How the bounds compose with the missing connection cap

Every figure in Design 3 is per connection, and the listeners (`web::http::serve_until`, `LoopbackTcp::serve`) accept without limit, so the process-wide figure is N times the per-connection one with N limited only by the fd limit. This spec removes the term that was **amplifying and unbounded in time** (heap growing with sent bytes, indefinitely post-auth) and leaves terms that are 1:1 with attacker bytes and end with the connection. The follow-up cap multiplies what is left: C connections give at most about C x 32 MiB pre-auth allocated, held at most about 35 s each on the web bridge in the worst case (15 s header read, 10 s token window, up to 10 s of refusal and close drain), and C x the reply terms post-auth. That follow-up is the recommended next item after this one, and its value should be chosen against these figures.

### 9. Test seams and harness

- `relay`, `refuse` and `close` in `bridge.rs` become generic over `S: AsyncRead + AsyncWrite + Unpin` (they hard-code the hyper `Upgraded` type; `send_within`, `close_within` and `refuse_unauthorized` already are generic). Production still instantiates them with `TokioIo<Upgraded>`. That lets the whole loop run over `tokio::io::duplex` in a unit test with a `WebState` built in-process, so the Ping behaviour has a sandbox-runnable proof of the real loop, not only of the helper.
- `serve_connection` is made testable over `duplex` if that costs nothing on the hot path (`tokio::io::split` takes a lock `TcpStream::into_split` does not); otherwise its tests are real-loopback and go to the Terminal panel.
- `crates/aitm/tests/support/web_bus.rs` gains `ServerOptions` fields for the pre-auth timeout and for `SO_RCVBUF` on the listener (the harness already sets `SO_SNDBUF`), and `test.blob` takes an optional `bytes` argument (default 1 MiB, so every current caller is unchanged). Additive only; existing suites run unmodified.

## Acceptance criteria

`[duplex]` runs in the sandbox. `[socket]` binds loopback and needs the Terminal panel. "Flood" means 64 MiB of Ping frames with 125-byte payloads (131 bytes each), written by a peer that never reads. "Accepted bytes" is the count of those bytes the peer's writes completed before they failed, stalled or finished; it is the memory proxy, because until the fix the server reads and buffers everything it is sent (about 1.36 bytes of heap per byte, E1) and after it the server stops reading, so accepted bytes are bounded by kernel and codec buffers. **RED** below means: the seams of Design 5 and 9 exist, the fix does not, and the test fails on the stated assertion rather than on a compile error.

1. **AC1** `[duplex]` **Post-auth flood ends and is bounded.** In `bridge.rs`'s test module: an authenticated agent connection (`relay` over `duplex(4096)`, `write_timeout` 100 ms) is flooded and never read. `relay` returns `Err` whose text contains `timed out after` within 5 s, and accepted bytes are under 1 MiB (the same shape measured 12 KiB over `duplex(4096)`, E1; the bound is generous so a loaded machine cannot flake it). **RED** on the bus-hardening head: `relay` never returns, the peer's writes all complete (64 MiB accepted), and the outer timeout fails the test.
2. **AC2** `[duplex]` **Pre-auth flood ends and is bounded.** As AC1 with no token sent and `pre_auth_timeout` 100 ms: `relay` returns `Err` (flush expiry, not an authentication-timeout Close) within 5 s, accepted bytes under 1 MiB. **RED** likewise: the loop `continue`s on every Ping and the peer's flood is accepted whole.
3. **AC3** `[socket]` **Real-socket flood, both phases** (new `crates/aitm/tests/web_bus_write_buffer.rs`, extending the `web_bus_write_deadline.rs` harness: client `SO_RCVBUF` 4096 via `open_stopped`-style setup, listener `SO_SNDBUF` and `SO_RCVBUF` 4096). (a) Post-auth: an operator that subscribes, then floods and never reads, has accepted bytes under 8 MiB, its stream ends within `write_timeout` (1 s) plus 5 s, and the `Ask` probe then reports `NO_OPERATOR` (the guard ran and the subscription is gone). (b) Pre-auth: a peer that upgrades, sends no token and floods has accepted bytes under 8 MiB and its stream ends within `pre_auth_timeout` (1 s) plus 5 s. **RED** on the bus-hardening head in both: 64 MiB accepted, the operator stays subscribed. The 8 MiB bound is at least 8 times below the flood and well above any kernel buffering at 4 KiB buffers.
4. **AC4** `[duplex + socket]` **A keepalive Ping is unaffected (guard; passes before and after).** A reading client sends a Ping with a distinct payload every 100 ms for 3 s while issuing `flow.list` calls, authenticated; every Pong echoes its payload within 5 s and every call is answered. Pre-auth: five Pings are each answered, then a token on the same connection authenticates. Pins "no budget a normal keepalive could trip" and the reading-client row of E1.
5. **AC5** `[socket]` **A legitimate large reply still goes through (guard).** `test.blob {bytes: 27 MiB}` (a reply of about 54 MiB, above the default-config `flow.detail` maximum of 53.3 MiB in E2) to a reading client whose own `max_message_size` and `max_frame_size` are raised to 64 MiB or more (tungstenite's client defaults would reject it), arrives intact: reply length and the blob's last byte checked. No maximum is settled because E2 shows none exists in code; 54 MiB is the default-config `flow.detail` maximum rounded up. Passes before and after; its job is to fail if anyone later sets a write-buffer cap below a legitimate reply (AC11).
6. **AC6** `[unit]` **First line over the bound is refused unparsed.** In `bridge.rs` and `transport.rs` tests, for `classify_token` on each: (a) `{"token":"<valid 64 hex>"` followed by 5,000 spaces then `}`, which parses to a valid token today, is refused (`None`); **RED** today (it authenticates). (b) Accepted as before: `{"token":"<t>"}`, `{"token": "<t>"}`, either with leading/trailing spaces and `\r\n`, for both the agent and the operator token (the exact shapes in E5); and a 40-byte token of control characters, whose compact JSON line is 252 bytes (`\u00XX` per byte plus the 12 framing bytes), is accepted (within `8 x 40 + 256`). (c) `auth_line_limit` of two 64-hex tokens is exactly 768; of a 1,000-byte token it is 8,256. (d) The TCP first-line reader, given 1 MiB with no newline, returns an error having buffered at most `limit + 2` bytes. **RED** today: the helper does not exist and the reader takes 16 MiB.
7. **AC7** `[socket]` **Over the wire, web and TCP.** A first line of the AC6(a) shape gets the `unauthorized` refusal and the connection closes; the shapes in AC6(b) authenticate as agent and operator.
8. **AC8** `[socket]` **TCP pre-auth deadline** (in `transport.rs` tests, real loopback; `[duplex]` instead if `serve_connection` is made generic). With `pre_auth_timeout` 100 ms: (a) a connection that sends nothing reaches EOF within 100 ms plus 2 s; (b) one that drips one byte every 20 ms with no newline reaches EOF at the same absolute deadline (activity does not extend it); (c) guard: a client that sends a valid token at 50 ms authenticates, and its idle connection is still open after 300 ms (the deadline is pre-auth only). **RED** today for (a) and (b): the connection stays open and the test's EOF wait fails.
9. **AC9** `[duplex]` **`serve_lines` tears down on cancellation** (in `transport.rs` tests, `serve_over_tiny_pipe` style, but with a client that keeps reading so the writer is idle and not parked in a write). After `flow.subscribe`, `task.abort()` and awaiting the cancelled join: `sink.is_closed()` is true, and after a further `push_padded` the client's next read within 2 s is EOF, never the pushed line (the subscription is gone and the writer exited and released its half). **RED** today: the sink stays open, the subscription still feeds the live sink, so the pushed line arrives and there is no EOF.
10. **AC10** `[unit]` **Pre-auth timeout seam.** `McpServer::pre_auth_timeout()` defaults to 10 s (`DEFAULT_PRE_AUTH_TIMEOUT`), `with_pre_auth_timeout` stores what it is given and clamps zero to 1 ms (mirroring the existing `write_timeout` tests), and AC2 and AC8 reach their deadlines only through it. `bridge.rs` has no `HANDSHAKE_TIMEOUT` constant of its own.
11. **AC11** **Mutation checks** (the Tester runs each once and records red then green): delete the post-auth flush, AC1 and AC3(a) fail on the accepted-bytes or never-returns assertion; delete the pre-auth flush, AC2 and AC3(b) fail; delete the length guard, AC6(a) and AC7 fail; delete the TCP timeout, AC8(a) and (b) fail; delete the drop guard, AC9 fails; set `WebSocketConfig::max_write_buffer_size` to 16 MiB (above `write_buffer_size`), AC5 fails with `WriteBufferFull`. Each failure has the stated assertion as its cause, not a compile or connect error.
12. **AC12** Review-checked, not machine-enforced: the `bridge.rs` module and `relay` docs describe the Pong drain and no longer name `HANDSHAKE_TIMEOUT`; `McpServer::write_timeout`'s doc says it also bounds the Pong flush; the `serve_lines` doc says teardown runs on cancellation; a comment at the two Ping sites says why the flush must finish before the next `ws.next()`.
13. **AC13** The Rust gate passes; no `unsafe` is added; `Cargo.lock` is unchanged; `web_bus_roles.rs`, `web_bus_concurrency.rs`, `web_bus_push.rs` and `web_bus_write_deadline.rs` pass unmodified (the harness change is additive); nothing under `crates/aitm-core` changes.

## Left to the builder

- The helper's exact name and the split of `relay`'s pre-auth phase into its own generic function, if that makes AC2 cleaner.
- Whether `serve_connection` becomes generic (AC8's level follows), and whether the over-limit TCP refusal reuses the existing refusal write.
- Whether `auth_line_limit` takes token lengths or the tokens, and how `WebState` hands the operator token to it.
- Log levels and wording (debug, in the style of the existing drops; never a token or a line's content).
- Test names, whether the duplex tests live in the module tests or a new integration file, and the flood and frame sizes, provided the stated bounds (accepted bytes at least 8x below the flood, the 54 MiB reply) are kept.
- How the flood writer builds frames (a pre-built buffer with an all-zero mask key is enough).

## Open questions

Calls for Matt. All non-blocking; each has a default and nothing in this spec waits on them.

1. **`flow.export` reply size.** A single-flow native export of a default-maximum body is about 442 MiB on the wire, the whole default store about 22 GiB (E2, measured expansion 44x), with the value sent twice, and the bridge holds each frame twice while it sends it (measured for a 20 MiB frame). Any operator (or an agent under `all`) can request it over `/bus` today. Should it be limited, streamed or refused above N? **Default: not decided here**; this spec deliberately constrains no reply size, and the follow-up "reply byte budget" owns the question.
2. **TCP pre-auth deadline of 10 s.** It matches the web bridge. A person typing a token by hand into `nc` has 10 s. **Default: 10 s**; one builder call to change.
3. **No allocator-based memory test.** The workspace forbids `unsafe`, so memory is asserted through accepted bytes. **Default: accept**; the heap numbers in E1 are the one-off measurement.
