# HTTP/1 path hardening implementation plan

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's standing autonomous-mode instruction)
**Spec:** `docs/superpowers/specs/2026-10-30-http1-path-hardening-design.md`
**Branch / worktree:** `fix/http1-path-hardening` in
`/Users/matt/Security/aitmproxy/.claude/worktrees/pbb-sec-review-1c8088`, cut from
`origin/fix/proxy-stale-upstream-keepalive` (PR #108). Open the PR against that branch
until #108 merges, then retarget `main`.

## Overview

Three pre-existing defects in the HTTP/1 proxy path, each fixed test-first: Task 1
bounds the origin TLS handshake, Tasks 2 and 3 stop a stray response in the same
upstream read from reaching the client, Task 4 makes a cleartext `CONNECT` tunnel dial
the `CONNECT` target. Task 5 adds loopback integration tests in one new file, Task 6
is the whole-branch tester pass. `h2.rs`, `translate.rs`, `sender.rs` and everything in
`aitm-core` are not touched.

**Base SHA** for diffs and the AC22/AC23 checks: the branch HEAD immediately before
Task 1's commit (currently `ec263e1` plus the spec and plan commits). Record the
actual SHA in the Review log when Task 1 is dispatched.

**Files touched, and what that means for scheduling**

| Task | Files | Shares a file with |
|---|---|---|
| T1 | `crates/aitm-proto-http/src/module.rs` | T3, T4 |
| T2 | `crates/aitm-proto-http/src/sansio.rs`, `crates/aitm-proto-http/tests/sansio.rs` | none |
| T3 | `crates/aitm-proto-http/src/module.rs` | T1, T4 |
| T4 | `crates/aitm-proto-http/src/module.rs` | T1, T3 |
| T5 | `crates/aitm-proto-http/tests/http1_hardening.rs` (new) | none |
| T6 | tests only, if it must strengthen any | none |

**Independent (may fan out):** T1 and T2 touch disjoint files and have no logical
dependency; run them in parallel (two coders, T2 in a child worktree on a branch cut
from this one, merged back when its panel passes), or one after the other if
preferred.

**Serial, one coder at a time in this worktree:** T1, then T3, then T4, because all three
edit `module.rs` (T3 and T4 edit the same region of `serve`). T3 also needs T2 merged
first (it relies on the machine leaving surplus bytes in its buffer). T2 alone does
NOT close the poisoning hole: the surplus then sits in the buffer and is parsed as the
answer to the next request on a live upstream. T3 completes it, so never release T2
without T3. T5 needs T1 to T4. T6 is last.

```
T1 (module.rs) ----+
                    +--> T3 (module.rs) --> T4 (module.rs) --> T5 (new test file) --> T6
T2 (sansio.rs) ----+
```

**Execution notes (every task).**

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must pass before any review. The workspace gate includes tests that bind ports, so the
  full gate runs in the Terminal panel. Inside the Bash sandbox run the socket-free
  subset while developing: `cargo test -p aitm-proto-http --lib`,
  `cargo test -p aitm-proto-http --test sansio`,
  `cargo fmt --check`, `cargo clippy -p aitm-proto-http --all-targets -- -D warnings`.
- **Stale artifacts:** when worktrees share a `CARGO_TARGET_DIR`, `touch` every crate
  source before a gate or a live test so cargo does not reuse another worktree's
  artifacts: `find crates -name '*.rs' -exec touch {} +`.
- **Terminal panel only:** every `git` and `gh` command; the whole of
  `crates/aitm-proto-http/tests/http1_hardening.rs` (Task 5); the existing integration
  files that bind loopback ports (`tests/stale_upstream.rs`, `tests/https_capture.rs`,
  `tests/response_park.rs`, `tests/h2_*.rs`, `tests/sender.rs`) and the cross-crate
  suites named in AC21; the full workspace gate. Gate a commit on the exit status of a
  `cargo test` redirected to a log, not on a `grep | tail` pipeline. The Terminal tool
  refuses command words that begin with `#`, so keep `#[...]` out of commit bodies. Push
  with an explicit refspec (`git push origin fix/http1-path-hardening`).
- **Red evidence:** each task's Coder report quotes the failing run and the passing run
  (`superpowers:test-driven-development`). The sandbox-runnable unit tests in Tasks 1 to 4
  are the authoritative red-to-green record; Task 5's loopback tests are corroboration.
- **Commits:** one commit per task, message `fix(proto-http): <what> (plan: http1-hardening)`.
- **Known flake:** `rhai_e2e::script_cannot_escape_or_exceed_scope` is a non-deterministic
  flake unrelated to this work. Judge it by whether the change touches Rhai (it does not),
  not by an isolated re-run.

## Tasks

### Task 1: Bound the upstream TLS handshake (Defect 3)

- **Satisfies:** AC1, AC2, AC3, AC4, AC5 (AC6 is proved by Task 5)
- **Depends on:** none. Independent of Task 2.
- **Files:** `crates/aitm-proto-http/src/module.rs` (modify: production code and `mod tests`)
- **Change:**
  - Constant next to `READ_TIMEOUT`: `const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = READ_TIMEOUT;`
    with a doc comment naming it the bound on the origin handshake.
  - New field on `HttpModule`: `tls_handshake_timeout: std::time::Duration`, set to
    `TLS_HANDSHAKE_TIMEOUT` in `with_ca_config` (so `new` and `with_ca` get it).
  - New builder: `pub fn with_tls_handshake_timeout(mut self, within: std::time::Duration) -> Self`
    (doc: bounds the TLS handshake to an origin; not yet wired to config).
  - New shared helper on `HttpModule`:
    `async fn tls_handshake<IO>(&self, alpn: &[Vec<u8>], server_name: ServerName<'static>, io: IO, authority: &str) -> Result<tokio_rustls::client::TlsStream<IO>> where IO: AsyncRead + AsyncWrite + Unpin`.
    It builds `TlsConnector::from(self.upstream_tls_alpn(alpn)?)`, awaits
    `connect(server_name, io)` under `tokio::time::timeout(self.tls_handshake_timeout, ..)`.
    On timeout it returns `anyhow!("TLS to upstream {authority} timed out after {:?}", self.tls_handshake_timeout)`.
    On a handshake error it returns the error with context `format!("TLS to upstream {authority}")`
    (today's context, unchanged).
  - `HttpModule::mitm`: replace the inline `TlsConnector::from(..).connect(..).with_context(..)`
    with `self.tls_handshake(&client_alpn, server_name.clone(), tcp, &target.authority()).await?`.
  - `Reconnect::connect`: replace its inline handshake with
    `self.module.tls_handshake(&[b"http/1.1".to_vec()], self.server_name.clone(), tcp, &self.authority).await?`.
    The ALPN check after it stays as is. A timeout fails the request; nothing is dialled
    afterwards.
  - Do not touch `LazyConfigAcceptor` or `into_stream` (client side, out of scope), `h2.rs`,
    or `aitm-core`.
- **Test (all in `module.rs` `mod tests`, sandbox-runnable, no sockets).** Add a helper
  `fn stalled_pair() -> (ByteStream, DuplexStream)` returning our end boxed and the origin
  end (hold the origin end for the whole test; dropping it would be an EOF, not a stall).
  Every stall test wraps its call in `tokio::time::timeout(Duration::from_secs(5), ..)`
  with `.expect("the handshake was never bounded")` so an unbounded handshake fails the
  test instead of hanging.
  - `tls_handshake_gives_up_on_an_origin_that_never_answers`: module =
    `HttpModule::new().with_insecure(true).with_tls_handshake_timeout(Duration::from_millis(50))`;
    call `tls_handshake(&[b"http/1.1".to_vec()], ServerName::try_from("origin.test").expect("name"), io, "origin.test:8443")`
    on the stalled stream. Expect `Err`, and `err.to_string()` ==
    `"TLS to upstream origin.test:8443 timed out after 50ms"`.
  - `tls_handshake_failure_keeps_its_context`: peer end dropped before the call. Expect
    `Err` with `err.to_string()` == `"TLS to upstream origin.test:8443"`.
  - `tls_handshake_succeeds_against_a_live_origin`: `tokio::join!` the helper against
    `TlsAcceptor::from(server_config(&[])).accept(..)` over `duplex(64 * 1024)`; both `Ok`.
  - `a_new_module_bounds_the_upstream_handshake_at_the_read_timeout`:
    `assert_eq!(HttpModule::new().tls_handshake_timeout, READ_TIMEOUT)` (30 s).
  - `mitm_gives_up_on_an_origin_that_stalls_the_upstream_handshake`: `ctx_with(vec![stalled our end])`;
    spawn a task running a real `TlsConnector` handshake (config from
    `HttpModule::new().with_insecure(true).upstream_tls_alpn(&[b"http/1.1".to_vec()])`,
    name `origin.test`) over the client end of a second `duplex(64 * 1024)`, so the proxy
    side receives a real ClientHello; call
    `module.mitm(Prefixed::new(Box::pin(proxy_side)), ctx, unknown_peer(), Some(Target { host: "origin.test".into(), port: 8443, addr: origin_addr() }))`
    with the 50 ms module. Expect `Err` with `to_string()` ==
    `"TLS to upstream origin.test:8443 timed out after 50ms"`, and the dial log ==
    `vec![("origin.test:8443".to_string(), origin_addr())]`.
  - `reconnect_gives_up_on_an_origin_that_stalls_the_handshake`: connector holding one
    stalled stream; `reconnect_to(&module).connect(&ctx)` with the 50 ms module. Expect
    `to_string()` == `"TLS to upstream origin.test:8443 timed out after 50ms"` and exactly
    one entry in the dial log.
  - `serve_fails_the_request_when_the_tls_reconnect_handshake_stalls`: like
    `serve_fails_the_request_when_the_tls_reconnect_is_refused` (first upstream is
    `tls_pair()` whose origin answers `"first"` then closes), but the connector hands out a
    stalled stream for the reconnect and the module has the 50 ms bound. Expect
    `first == "first"`, `served` is `Err` with `to_string()` ==
    `"TLS to upstream origin.test:8443 timed out after 50ms"`, the client reads zero bytes
    for the second request, and the dial log == `vec![("origin.test:8443".to_string(), origin_addr())]`
    (one dial, no cleartext fallback).
  - **Red protocol (the helper does not exist yet, so a bare red would be a compile
    error):** (1) write the tests; (2) add the constant, field, builder and
    `tls_handshake` with NO timeout (the body just awaits the handshake and adds the
    context) and switch both call sites, so everything compiles; (3) run
    `cargo test -p aitm-proto-http --lib -- tls_handshake mitm_gives_up reconnect_gives_up serve_fails_the_request_when_the_tls_reconnect_handshake_stalls a_new_module_bounds`
    and paste the output: the four stall tests fail with "the handshake was never bounded",
    the other three pass; (4) add the `timeout` and the timeout message; (5) re-run and
    paste: all pass.
- **Done when:** the tests above pass, every existing `module.rs` test still passes
  (`cargo test -p aitm-proto-http --lib`), `cargo fmt --check` and
  `cargo clippy -p aitm-proto-http --all-targets -- -D warnings` are clean, and the full
  gate passes in the Terminal panel.

### Task 2: The machine leaves surplus server bytes unparsed (Defect 2, machine half)

- **Satisfies:** AC7, AC8, AC9, AC14 (machine level)
- **Depends on:** none. Independent of Task 1.
- **Files:** `crates/aitm-proto-http/src/sansio.rs` (modify), `crates/aitm-proto-http/tests/sansio.rs` (modify)
- **Change:** in `Http1Machine::on_server_bytes`, `Phase::Head` arm, after the existing
  `let id = self.current_flow()?;` and before `take_head`: if the client reader is not in
  `Phase::Waiting`, stop the loop without parsing. If `self.server.buf.len()` exceeds
  `MAX_HEAD_BYTES` at that point, return `Err` (`bail!` with a message naming the cap). The
  `current_flow()?` error for response bytes before any request is kept and still runs
  first. Update the doc comments on `Phase::Waiting`/`take_leftover` to say server bytes are
  also left unparsed while no request awaits a response. No signature changes; no change to
  `finish_response`, the 101 branch, framing selection, or `short_circuit_done`.
- **Test (`tests/sansio.rs`, sandbox-runnable).** Add a small helper
  `fn exchange(request: &[u8]) -> (Http1Machine, FlowId)` that feeds the request on
  `Side::Client` and returns the machine and the flow id from the first event.
  *Step 1: characterization tests that must PASS on the current code and keep passing*
  (write them first and run them against the unmodified machine to prove they pin today's
  behaviour); each asserts the exact events and `take_leftover(Side::Server)`:
  - `head_response_completes_without_a_body`: request `HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n`,
    server `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n` gives
    `[ResponseHeaders(id), ResponseComplete(id)]`, leftover empty.
  - `not_modified_response_completes_without_a_body` (`304 Not Modified`, `Content-Length: 5`) and
    `no_content_response_completes_without_a_body` (`204 No Content`): same events, leftover empty.
  - `chunked_response_streams_and_completes`: `GET`, server
    `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwxyz\r\n0\r\n\r\n` gives
    `[ResponseHeaders(id), ResponseBodyChunk{flow: id, bytes: b"wxyz"}, ResponseComplete(id)]`.
  - `close_delimited_response_completes_at_eof`: server `HTTP/1.1 200 OK\r\n\r\nbody` gives
    `[ResponseHeaders(id), ResponseBodyChunk{flow: id, bytes: b"body"}]`, then
    `on_eof(Side::Server)` gives `[ResponseComplete(id)]`.
  - `interim_continue_is_skipped_before_the_final_response`: server
    `HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok` gives
    `[ResponseHeaders(id), ResponseBodyChunk{flow: id, bytes: b"ok"}, ResponseComplete(id)]`
    and `response().unwrap().status == 200`.
  - `switching_protocols_leaves_the_following_bytes_for_the_next_protocol`: request
    `GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`,
    server `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nWSDATA`
    gives `[ResponseHeaders(id), ResponseComplete(id)]`, `is_upgraded()` is true, and
    `take_leftover(Side::Server) == b"WSDATA".to_vec()`.
  - `a_pipelined_request_is_parsed_after_the_first_response`: feed
    `GET /1 HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\n\r\n` on the client:
    events are `[RequestHeaders(id1), RequestComplete(id1)]` only. Server
    `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok` completes. Then
    `on_bytes(Side::Client, b"")` gives `[RequestHeaders(id2), RequestComplete(id2)]` with
    `id2 != id1`; a second server response completes with `id2`.
  - `a_response_before_any_request_is_an_error`: new machine,
    `on_bytes(Side::Server, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")` is `Err`.
  - `a_partial_second_head_in_the_same_read_stays_buffered`: `GET`, server
    `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit` + `HTTP/1.1 500 Injected\r\nX-Junk: `
    gives the three events for the first response and
    `take_leftover(Side::Server) == b"HTTP/1.1 500 Injected\r\nX-Junk: ".to_vec()`.
  - `unsolicited_server_bytes_beyond_the_head_cap_are_an_error`: complete one exchange, then
    `on_bytes(Side::Server, &vec![b'x'; 64 * 1024 + 1])` is `Err`. It passes today because
    the head parser enforces the cap; it fails against a guard that forgets the cap.

  *Step 2: the failing tests (RED on the current code):*
  - `a_second_complete_response_in_the_same_read_is_left_unparsed`: `GET`, one call with
    `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit` followed by
    `HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON`. Expect exactly
    `[ResponseHeaders(id), ResponseBodyChunk{flow: id, bytes: b"legit"}, ResponseComplete(id)]`;
    `response().unwrap().headers.get("content-length") == Some("5")`;
    `take_leftover(Side::Server) == b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON".to_vec()`.
    Today: six events and a `Content-Length: 6` response.
  - `a_response_after_the_exchange_completed_is_not_parsed`: complete one exchange, then
    `on_bytes(Side::Server, b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON")` returns
    `Ok(vec![])` and `take_leftover(Side::Server)` returns those exact bytes.
  - `a_response_while_the_request_body_is_arriving_waits_for_the_request`: client
    `POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab` gives
    `[RequestHeaders(id), RequestBodyChunk{flow: id, bytes: b"ab"}]`; server
    `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n` returns `Ok(vec![])`; client `cd` gives
    `[RequestBodyChunk{flow: id, bytes: b"cd"}, RequestComplete(id)]`; then
    `on_bytes(Side::Server, b"")` gives `[ResponseHeaders(id), ResponseComplete(id)]` (the
    parked response is released once the request is complete).

  Run `cargo test -p aitm-proto-http --test sansio`; paste the run showing the three RED
  tests failing and every characterization test passing, then the run after the guard with
  everything passing.
- **Done when:** all of the above pass, the existing `tests/sansio.rs` and in-file
  `sansio.rs` unit tests still pass, fmt and clippy are clean, and the full gate passes in
  the Terminal panel.

### Task 3: Surplus bytes after a completed response taint the upstream (Defect 2, module half)

- **Satisfies:** AC10, AC11, AC12 (AC13 follows from Task 2 and is proved in Task 5)
- **Depends on:** Task 2 (machine guard) and Task 1 (same file, serial).
- **Files:** `crates/aitm-proto-http/src/module.rs` (modify: `serve`, plus `mod tests`)
- **Change:** in `serve`:
  - New local outside the main loop, next to `current_authority`: a `bool` (`upstream_tainted`),
    false initially.
  - After the response loop and after the `machine.is_upgraded()` block (which returns on a
    101 and still hands `take_leftover(Side::Server)` to the next protocol), and before the
    `request_close || response_close` check: `let surplus = machine.take_leftover(Side::Server);`.
    If `surplus` is non-empty: one `tracing::warn!` carrying the upstream authority
    (`current_authority`) and `surplus.len()` and a fixed message such as "origin sent bytes
    after a completed response; discarding them and replacing the upstream connection"; never
    the bytes. Drop the bytes and set `upstream_tainted = true`.
  - The existing stale check `if upstream.as_mut().is_some_and(upstream_is_stale)` becomes
    "`upstream_tainted` or (`upstream` is Some and `upstream_is_stale`)". Inside that branch,
    after the replacement is done, set `upstream_tainted = false`. The rest of the branch
    (`upstream = None`, `take_leftover`, the `Reconnect` / https-bail / cleartext arms) is
    unchanged and is what makes the replacement fail closed.
  - **Must not:** set `upstream = None` at the detection point. In a TLS tunnel the next
    request would skip `Reconnect` and fall into the ordinary connect step, which dials in
    cleartext.
  - Do not emit `Event::Error`, do not touch the flow's marks or stored response, do not
    close the client connection.
- **Test (`module.rs` `mod tests`, sandbox-runnable).** New test-only helpers:
  `struct RecordingSink { events: Mutex<Vec<Event>> }` implementing `EventSink` (records every
  event, returns `Verdict::Continue`); `fn ctx_recording(streams: Vec<ByteStream>) -> (ModuleCtx, DialLog, Arc<RecordingSink>)`;
  `async fn client_get_keep(io: &mut DuplexStream, pending: &mut Vec<u8>, target: &str, host: &str) -> String`
  (like `client_get`, but bytes read past the response stay in `pending` and `pending` is
  consumed first, so a forwarded stray response cannot be silently dropped);
  `const STRAY_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON";`;
  `async fn origin_serve_trailing_after_first<S>(io: S, bodies: Vec<&'static str>, trailer: &'static str)`
  (answers each of `bodies` in order with a keep-alive 200, appends `trailer` to the FIRST
  response's single write only, then holds the connection open until the proxy hangs up).
  `Body` has no `PartialEq`: compare with `matches!(body, Body::Bytes(ref b) if b == b"legit")`.
  - `serve_does_not_forward_a_second_response_read_with_the_first` (RED today): connector
    holds two in-memory upstreams; origin 1 =
    `origin_serve_trailing(origin1_end, vec!["legit"], STRAY_RESPONSE, false)`, origin 2 =
    `origin_serve(origin2_end, vec!["second"], false)`; `Conn::plain(unknown_peer(), None)`.
    With `pending = Vec::new()`: `client_get_keep(.., "http://127.0.0.1:8080/one", "127.0.0.1:8080")`
    returns `"legit"` and `pending` is empty; `.../two` returns `"second"` and `pending` is
    empty. After the client hangs up and `serve` returns `Ok`: the dial log is
    `[dial("127.0.0.1:8080", "127.0.0.1:8080"), dial("127.0.0.1:8080", "127.0.0.1:8080")]`;
    the recorded events number 8, with exactly 2 `Event::ResponseHeaders`, exactly 2
    `Event::Response` and 0 `Event::Error`; the stored flow with path `/one` has response
    status 200, header `content-length` `"5"` and body `Body::Bytes(b"legit")`. Today the
    test fails at the first `pending` assertion (the stray response was forwarded behind
    the legitimate one), or, if the client happened to read response 1 before the stray
    was written, request 2 returns `"POISON"` instead of `"second"`. Either way it is red;
    after the fix nothing extra is ever written, so green is deterministic.
  - `serve_does_not_glue_a_stray_head_fragment_onto_the_next_response_on_a_live_upstream`
    (RED today): origin 1 = `origin_serve_trailing_after_first(origin1_end, vec!["first", "second"], INJECTED_HEAD)`
    (stays open and would answer request 2), origin 2 = `origin_serve(origin2_end, vec!["second"], false)`.
    `client_get_keep` for `/one` returns `"first"`; for `/two` it returns `"second"` (the
    helper's status assert requires 200) and the dial log has two entries. Today request 2
    rides origin 1's live connection and the parsed head carries status 500 from
    `INJECTED_HEAD`, so the helper's status assert fails.
  - `serve_reconnects_over_tls_after_a_stray_response`: `tunnel_conn()`, first upstream
    `tls_pair()` whose origin is `origin_serve_trailing(first_server, vec!["legit"], STRAY_RESPONSE, false)`,
    one reconnect stream (as in `serve_redoes_the_tls_connection_when_the_origin_closed_it`)
    with `reconnect_to(&module)`. Expect `"legit"` with `pending` empty, then `"second"`
    from the reconnect, and the dial log exactly `[("origin.test:8443", origin_addr())]`
    (one dial, the reconnect).
  - `serve_fails_closed_for_a_tainted_tls_upstream_without_a_reconnect`: `tunnel_conn()`,
    `reconnect = None`, first upstream an in-memory stream whose origin is
    `origin_serve_trailing(.., vec!["legit"], STRAY_RESPONSE, false)`. First request returns
    `"legit"`; the second request makes `serve` return `Err` with `to_string()` ==
    `"upstream TLS connection closed and cannot be re-established"`, the client reads zero
    further bytes, and the dial log is empty (nothing dialled, in particular not in cleartext).
  - The three existing `serve_drops_response_bytes_left_over_*` tests and
    `serve_reuses_a_live_upstream_without_redialing` must pass unchanged.
  - Red run (before the `serve` change, with Task 2's guard in): paste the first two tests
    failing and the rest passing; then green.
- **Done when:** the tests pass, all existing `module.rs` tests pass, fmt and clippy are
  clean, and the full gate passes in the Terminal panel.

### Task 4: A cleartext tunnel dials the CONNECT target (Defect 1)

- **Satisfies:** AC15 (unit), AC16, AC17, AC18, AC19, AC20
- **Depends on:** Task 3 (same file and the same region of `serve`; serial).
- **Files:** `crates/aitm-proto-http/src/module.rs` (modify: `Conn`, `drive`, `mitm`, `serve`, `mod tests`)
- **Change:**
  - `Conn` gains `pub(crate) tunnel_addr: Option<SocketAddr>` (doc: where `tunnel_authority`
    resolved to when the tunnel was opened). It is set together with `tunnel_authority`
    and `h2.rs` is not touched (it only reads `Conn`).
  - `Conn::plain` becomes `fn plain(peer: SocketAddr, tunnel: Option<(String, SocketAddr)>) -> Self`
    (the tuple is the authority and its resolved address; sets both fields). Existing
    `Conn::plain(unknown_peer(), None)` call sites keep compiling.
  - `HttpModule::drive`: `Conn::plain(peer, Some((target.authority(), target.addr)))` in the
    cleartext-tunnel arm.
  - `HttpModule::mitm`: the `Conn` literal gains `tunnel_addr: Some(target.addr)`.
  - `serve`: delete the `redial` variable and the `None if conn.tunnel_authority.is_some() => redial = ..`
    arm. In the connect step: when `conn.tunnel_authority` and `conn.tunnel_addr` are both Some,
    skip `Target::resolve` and call `ctx.connect_upstream(&tunnel_authority, tunnel_addr)`,
    recording `current_authority = Some(tunnel_authority)`; otherwise resolve
    `request.authority` with default port 80 and dial it, exactly as today. The
    `needs_connect` rule for non-tunnel connections (`current != request.authority`) is
    unchanged. When a request's authority differs from the tunnel target (compared
    case-insensitively with default port 80 applied; a small private `fn` is fine), emit one
    `tracing::debug!` naming both. `record_server_conn` is unchanged, so `server_conn.peer`
    records the dialled address. Update the doc comments on `Conn` and `serve` to say a
    tunnel's route is its `CONNECT` target.
  - Test helpers: `tunnel_conn()` gets `tunnel_addr: Some(origin_addr())`; the one existing
    `Conn::plain(unknown_peer(), Some("127.0.0.1:8080".to_string()))` call (in
    `serve_redials_a_cleartext_tunnel_to_the_origin_it_was_opened_to`) becomes
    `Conn::plain(unknown_peer(), Some(("127.0.0.1:8080".to_string(), "127.0.0.1:8080".parse().expect("addr"))))`;
    its assertions do not change.
- **Test (`module.rs` `mod tests`, sandbox-runnable).** New test-only helpers:
  `struct RewriteSink { store: Arc<MemFlowStore>, to: &'static str }` implementing `EventSink`
  (on `Event::Request(id)` it updates the stored flow's `request.authority` and its `host`
  header to `to`; returns `Verdict::Continue`), a ctx constructor that shares the store with
  that sink, and a raw-request client helper that sends a request with no `Host` header.
  **Red protocol:** write the first four tests below against the CURRENT API
  (`Conn::plain(unknown_peer(), Some("127.0.0.1:8080".to_string()))`) so they compile; run
  and paste the RED output; then make the `Conn` change, update the call sites, and paste the
  GREEN run.
  - `serve_dials_the_connect_target_not_the_host_header_in_a_cleartext_tunnel` (RED today):
    tunnel to `127.0.0.1:8080`; origin serves `["first"]`; `client_get(.., "/one", "127.0.0.1:9090")`
    returns `"first"`; dial log == `[dial("127.0.0.1:8080", "127.0.0.1:8080")]`. Today the
    log is `[("127.0.0.1:9090", 127.0.0.1:9090)]`.
  - `serve_keeps_one_tunnel_connection_for_requests_naming_different_hosts` (RED today):
    `/one` with `Host: 127.0.0.1:9090` then `/two` with `Host: 127.0.0.1:7070`; bodies
    `"first"` and `"second"` from the one origin; dial log has exactly one entry,
    `dial("127.0.0.1:8080", "127.0.0.1:8080")`.
  - `serve_records_the_host_authority_and_the_tunnel_peer_on_the_flow` (RED today): after the
    first test's exchange, the stored flow for `/one` has `request.authority == "127.0.0.1:9090"`
    and `server_conn.map(|c| c.peer) == Some("127.0.0.1:8080".parse().unwrap())`.
  - `a_plugin_authority_rewrite_does_not_retarget_a_cleartext_tunnel` (RED today): with the
    `RewriteSink` rewriting to `127.0.0.1:9090`, a request with `Host: 127.0.0.1:8080` in a
    tunnel to `127.0.0.1:8080` is dialled at `dial("127.0.0.1:8080", "127.0.0.1:8080")`;
    the stored flow's `request.authority == "127.0.0.1:9090"`.
  - `serve_records_the_tunnel_authority_for_a_request_without_a_host` (passes before and
    after): a raw `GET /x HTTP/1.1\r\n\r\n` in the tunnel is answered `"first"` and the
    stored flow's `request.authority == "127.0.0.1:8080"`.
  - `serve_dials_an_ipv6_literal_tunnel_at_the_recorded_address` (passes before and after;
    guards the pinned-address design): tunnel authority `"::1:8080"` (the string
    `Target::authority()` produces for `[::1]:8080`), address `[::1]:8080`, request
    `Host: [::1]:8080`; the dialled address in the log is `"[::1]:8080".parse::<SocketAddr>()`.
    The authority string is not asserted (it is the pre-existing F3 form).
  - Must still pass unchanged: `serve_redials_a_cleartext_tunnel_to_the_origin_it_was_opened_to`
    (dial log `[dial("127.0.0.1:8080", "127.0.0.1:8080"), dial("127.0.0.1:8080", "127.0.0.1:8080")]`),
    `serve_replaces_an_upstream_the_origin_closed`,
    `serve_drops_response_bytes_left_over_when_the_authority_changes` (dials
    `127.0.0.1:8080` then `127.0.0.1:9090`, proving the non-tunnel path still follows the
    request authority), and the TLS-tunnel tests.
- **Done when:** the tests pass, `git grep -n "redial" crates/aitm-proto-http/src/module.rs`
  matches only test names and comments, `git grep -n "TcpStream::connect" crates/aitm-proto-http/src/module.rs`
  prints nothing, all existing tests pass, fmt and clippy are clean, and the full gate
  passes in the Terminal panel.

### Task 5: Loopback integration tests

- **Satisfies:** AC6, AC13, and the loopback halves of AC10, AC11, AC12, AC15
- **Depends on:** Tasks 1 to 4.
- **Files:** `crates/aitm-proto-http/tests/http1_hardening.rs` (create). No other file.
- **Change:** a new integration test file, header comment stating that it binds loopback
  ports and runs in the Terminal panel. Copy the minimal helpers from `tests/stale_upstream.rs`
  rather than refactoring it: `provider`, `temp_dir`, `free_port`, `header_value`, `read_head`,
  `spawn_tls_origin` (adapted), `Client` with `get`, `connect_tunnel`, `tls_client`. Differences:
  - `run_proxy(tls_handshake_timeout: Option<Duration>) -> (SocketAddr, String, Arc<dyn FlowStore>)`:
    as `stale_upstream.rs`, but the module is
    `HttpModule::with_ca(ca).with_insecure(true)` plus
    `.with_tls_handshake_timeout(d)` when given, and the store comes from `proxy.store()`
    taken before `proxy` moves into the spawned task.
  - A scripted cleartext/TLS origin whose per-connection behaviour is an enum: `Normal`
    (keep-alive `200`, body `conn={n} path={path}`), `StrayAfterFirst(&'static str)` (the
    FIRST response on each connection is written together with the given trailer in a
    single `write_all`, then the connection keeps serving), and a separate stall origin that
    accepts a TCP connection, never reads or writes, and records when its peer closes.
  - `wait_for_flows(store, n)`: poll up to 5 s until the store holds `n` HTTP flows whose
    response body is `Body::Bytes` (a response can reach the client before the store
    holds its final body).
  - Constants `STRAY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON"` and
    `FRAGMENT: &str = "HTTP/1.1 500 Injected\r\nX-Junk: "`.
- **Test.** All Terminal panel only. Residual non-determinism, accepted: if the kernel
  split the origin's single write, the stray would arrive in a later read and PR #108's
  probe would already discard it, so a test could pass without the fix; the sandbox unit
  tests in Tasks 2 and 3 are the authoritative proof.
  - `a_cleartext_tunnel_dials_the_connect_target_not_the_host_header` (AC15, AC17): two
    cleartext `Normal` origins A and B; `CONNECT A`; `GET /one` with `Host: <B>` returns
    `(200, "conn=1 path=/one")`; `A.accepted() == 1`, `B.accepted() == 0`; a second request
    with `Host: <B>` returns `(200, "conn=1 path=/two")` (same connection). The stored flow
    for `/one` has `request.authority == B.addr.to_string()` and `server_conn.peer == A.addr`.
  - `a_stray_response_in_the_same_read_is_not_forwarded` (AC10, AC11): cleartext
    `StrayAfterFirst(STRAY)` origin, forward-proxy requests (`GET http://<host>/one`).
    First `get` returns `(200, "conn=1 path=/one")` and `client.buf.is_empty()`; second
    returns `(200, "conn=2 path=/two")` and `client.buf.is_empty()`; `origin.accepted() == 2`;
    after `wait_for_flows(store, 2)` neither stored body contains `POISON`.
  - `a_stray_response_in_the_same_read_is_not_forwarded_through_a_tls_tunnel` (AC12): the same
    through `tls_client`; `accepted() == 2` (the reconnect), bodies `conn=1 path=/one` and
    `conn=2 path=/two`.
  - `a_stray_head_fragment_does_not_corrupt_the_next_response` (AC11): `StrayAfterFirst(FRAGMENT)`
    cleartext origin that keeps serving; request 2 returns `(200, "conn=2 path=/two")`
    (a corrupted head would give status 500), `accepted() == 2`.
  - `the_replay_sender_returns_only_the_first_of_two_responses` (AC13): a raw `TcpListener`
    origin reads the request head, writes `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit` +
    `STRAY` in one write, then shuts down. `Http1Sender::new().send(&request)` (scheme `http`,
    authority the origin's `127.0.0.1:port`, path `/`) returns status 200, header
    `content-length` `"5"` and `Body::Bytes(b"legit")`. Today the body is `legitPOISON` and the
    head is the stray's.
  - `the_proxy_gives_up_on_an_origin_that_stalls_the_tls_handshake` (AC6): proxy with a
    300 ms bound; stall origin; client `CONNECT`s to it, gets `200`, then attempts a TLS
    handshake with the proxy under `tokio::time::timeout(5 s)`. Expect the handshake to fail
    (EOF or reset) with elapsed time between 250 ms and 5 s, and the stall origin to have
    observed its peer close within 5 s. Today the client's handshake does not fail before
    the 5 s guard. (Compile-time red before Task 1: `with_tls_handshake_timeout` does not exist.)
  - **Red evidence** for this file: copy only the new test file into a scratch worktree at
    the Base SHA, run it there in the Terminal panel, and paste the failures (the tests that
    need the new builder will not compile at Base; for those paste the compile error and
    run the rest). Then paste the green run on the branch.
  - Also run, in the Terminal panel, the existing `cargo test -p aitm-proto-http` integration
    files and paste the result: nothing here may regress them.
- **Done when:** all six tests pass on the branch, fmt and clippy are clean, and the full
  gate passes in the Terminal panel.

### Task 6: Whole-branch tester pass

- **Satisfies:** AC21, AC22, AC23, AC24 (and confirms every other AC maps to a test)
- **Depends on:** Tasks 1 to 5.
- **Files:** none expected; the Tester may add or strengthen tests only.
- **Change:** run as the Tester engine (spec, plan, worktree, base and head SHA, "whole
  branch"). Touch every crate source first (`find crates -name '*.rs' -exec touch {} +`).
  Then, quoting actual output:
  - the full gate in the Terminal panel: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
    (exit status gated, output to a log);
  - the named cross-crate suites from AC21: `cargo test -p aitm-proto-ws`,
    `-p aitm-plugin-wsctl`, `-p aitm-plugins`, `-p aitm-plugin-passthrough`,
    `-p aitm-plugin-maprules`;
  - AC22: `git diff <base>..HEAD --stat` shows no change under `crates/aitm-core/` and none
    to `crates/aitm-proto-http/src/{h2,translate,sender}.rs`, and
    `grep -n "TcpStream::connect" crates/aitm-proto-http/src/module.rs` prints nothing;
  - AC23: `git diff <base>..HEAD --stat -- Cargo.toml Cargo.lock 'crates/*/Cargo.toml'` prints nothing;
  - a table mapping AC1 to AC24 to the test that proves each, flagging any AC with only a
    weak or indirect test, and strengthening it.
- **Test:** the table above, with the literal command outputs; every AC has a passing test.
- **Done when:** the report is accepted, and the panel (security, quality, spec reviewers in
  parallel, on the whole branch) has no open findings.

## Review log

Kept by the main session during stage 6. One row per finding.

| Task | Reviewer | Severity | Finding | Disposition (fixed in <sha> / accepted by Matt YYYY-MM-DD, reason) |
|---|---|---|---|---|
| T6 (tester) | Tester | Minor | The first full-gate run (at 691bbce, no --no-fail-fast) stopped on `aitm-tui` `five_thousand_flows_ingest_and_render_within_bounds` (354 ms vs a 250 ms bound, machine load average 77 to 85). `aitm-tui` does not depend on `aitm-proto-http`; the same binary passed 3 of 3 re-runs at 37 to 46 ms. | Not a defect of this change. Re-run with `--no-fail-fast` at lower load: GATE fmt=0 clippy=0 test=0 at d602635, dc623c3 and 066e6d5. |
| T6 (tester) | Tester | Minor | Weak tests: the head cap was pinned at one point only (a `>=` or per-read mutation passed), the taint-flag clear was untested, AC17's Host-equals-target clause was untested. | fixed in 45cb7c6 (16 tests added; about 9 production mutations each caught by a discriminating test). |
| T4 (tester) | Tester | Minor | In `serve`, a tunnel with an authority but no resolved address fell back to dialling the request Host (the Defect 1 behaviour). Unreachable today. | fixed in d602635 (explicit match; that state refuses to dial; test `serve_refuses_a_tunnel_that_has_no_resolved_address`; spec AC25). |
| T3 (tester) | Tester | Minor | The surplus `warn` fired even when the connection was closing anyway, and its text ("replacing the upstream") was then false. | fixed in d602635 (surplus handling moved after the close check; two tests pin it with a log-capture subscriber). Deviation from spec Defect 2 item 2 and plan Task 3 ("before the close check"): accepted by the orchestrator under Matt's standing autonomous-mode instruction (2026-10-30); the spec text was amended (call 13). |
| T4 (tester) | Tester | Minor | `differs_from_tunnel_target` misreports IPv6-literal tunnels (the authority string drops its brackets, F3). | Accepted: it affects log lines only; documented on the helper and in the spec (F3). Fix belongs with F3. |
| whole | Security | Minor | S1: the debug mismatch log printed `request.authority`, which can carry URL userinfo (`http://user:secret@x/`). | fixed in e6af25b (logs the tunnel authority only; test `serve_keeps_a_request_target_userinfo_out_of_the_log`). Spec text amended (call 12). |
| whole | Security | Minor | S2: challenge to Architect's call 4: a Map Remote rewrite is silently ignored in a cleartext tunnel (it used to retarget the first request). | Routing decision stands (call 4, follow-up F2). Visibility added: one `warn` per request, tunnel authority only, in e6af25b; narrowed to cleartext tunnels in 9789c86 after round 2 (the comparison assumes port 80, so it mis-reported HTTPS tunnels). Accepted by the orchestrator (2026-10-30, standing instruction). |
| whole | Security | Minor | S3: the parked-bytes cap `bail!` in `sansio.rs` discards the events built in the same call; safe only while `READ_CHUNK` is below `MAX_HEAD_BYTES`. | fixed in e6af25b (compile-time assert; `MAX_HEAD_BYTES` is now `pub(crate)`). The assert was verified to break the build when `READ_CHUNK` is raised. `sender.rs` has its own `READ_CHUNK` without the assert: follow-up F7. |
| whole | Security | Minor | S4: no test drove a tunnel through `SsrfConnector`, the absolute-form route, or the log field sets. | fixed in e6af25b and dc623c3 (loopback test through `Proxy::run_browser`, red with src restored to 5be99be; absolute-form unit test; the capture subscriber records every field). Spec AC26. |
| whole | Quality | Minor | Q1: plan, AC, task and stage numbers in test comments. | fixed in e6af25b, dc623c3. Two labels ("Task 5", "Task 4") in module.rs predate the branch (332fa6db): not ours, left. |
| whole | Quality | Minor | Q2: `Conn.tunnel_authority` and `tunnel_addr` are two Options encoding one fact, which needs an unreachable arm and tests. | Deferred: one `tunnel: Option<Tunnel>` needs `h2.rs`, which this change must not touch. Recorded as F7 for the serve_h2 follow-up. |
| whole | Quality | Minor | Q3: extract the connect-step `match` into a `route_for` fn. | Accepted (optional, cheap but not needed); left. |
| whole | Quality | Minor | Q4: three tests cannot fail on a plausible regression or duplicate another. | fixed in e6af25b (dropped; the cap invariant is now a compile-time assert). |
| whole | Quality | Minor | Q5: duplicated test scaffolding. | Partly fixed in e6af25b (`ctx_with_sink`, `STALL_GUARD`, `get_request`, `serve_requests_keep`); the remaining `Connection: close` duplication accepted (2026-10-30). |
| whole | Quality | Minor | Q6: helpers copied across six integration-test files; `mod tests` is about 60 percent of `module.rs`. | Deferred: `tests/common` and moving `mod tests` into a submodule are a mechanical follow-up (F7). |
| whole | Quality | Minor | Q7: brittle message pins, doc gaps, comment volume. | fixed in e6af25b and 9789c86 (level + exact field set + a distinguishing phrase; the AC1 timeout text stays exact). |
| whole | Spec | Minor | SP1: surplus handling after the close check contradicts spec Defect 2 item 2 and plan Task 3 wording. | Accepted and recorded (see the T3 row); spec amended in 066e6d5. |
| whole | Spec | Minor | SP2: the fail-closed arm was not in the plan. | Accepted: spec Goal 1 requires it and the plan text was the error; now AC25. |
| whole | Spec | Minor | SP3: AC17's "field-for-field" clause asserted on a subset of fields. | fixed in e6af25b (version, headers, intercept, marks asserted). |
| whole | Spec | Minor | SP4: AC20's test used a Host equal to the recorded address, so a Host-derived dial would also pass. | fixed in e6af25b (Host `[::1]:9090`). |
| round 2 | Spec | Important | A second `warn` (Map Remote rewrite ignored in a tunnel) contradicted the spec's "only the unsolicited-response event logs at warn" and was unrecorded; it also applied to TLS tunnels, where the port-80 default misreports a portless same-host rewrite. | fixed in 9789c86 (cleartext tunnels only; test `serve_does_not_warn_about_map_remote_inside_a_tls_tunnel`, red first) and 066e6d5 (spec Constraints and calls 11 to 17 amended). Round 3 spec confirmation below. |
| round 2 | Security | Minor | The surplus-warn test was loosened to a substring match, so a regression interpolating the origin's bytes into the message would pass. | fixed in 9789c86 (distinctive token asserted absent from every captured event as text and as decimal bytes; the check was shown to fail under both a `{surplus:?}` and a `from_utf8_lossy` regression). |
| round 2 | Quality | Minor | M1 (the `map-remote` string is copied a second time, in `module.rs`), M7 (residual scaffolding). | Deferred to F7 (needs `h2.rs`); M7 accepted. |
| round 2 | Quality | Minor | M2 (message-pin policy, quoted literals), M3 (helpers after first use), M4 (assert comment off by one), M5 (private intra-doc link), M6 (`map_remote` bound far from its use). | fixed in 9789c86. |
| round 3 | Spec | Minor | Confirmation PASS (the round-2 Important finding closed, both round-2 Minors closed). Four wording drifts between spec and code: the `current_authority` parenthetical, the debug log described as per request (it fires when a dial is made), the cap sentence off by one, AC18 and "Left to the builder" missing the TLS-silence test and the AC25 substring. | fixed in the docs commit after 066e6d5 (spec wording only). |

## Shipped

Stage 7 (merge to `main`) is Matt's. The branch is `fix/http1-path-hardening`, opened as a PR stacked on PR #108 (base `fix/proxy-stale-upstream-keepalive`); retarget to `main` once #108 merges.

What shipped on the branch: the three fixes (T1 to T4), 16 tester-added tests, the loopback file `tests/http1_hardening.rs` (7 tests), and the spec amendments after the panel. Gate at the head: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test --no-fail-fast` all exit 0.

Follow-ups, none done here: the `serve_h2` stale-upstream fix (a separate spec, plan and PR stacked on this one, about five tasks; see the spec's scoping section), and adjacent findings F1 (unbounded client-side pre-serve I/O), F2 (Map Remote in h1 tunnels), F3 (`Target::authority()` IPv6 brackets), F4 (no `Event::Error` for a failed first dial or reconnect), F6 (a pre-existing credential-to-log path in the resolve error and the accept-loop `warn`) and F7 (maintenance debts: one shared `map-remote` constant, the `sender.rs` `READ_CHUNK` assert, one `Tunnel` struct instead of two Options, `tests/common`).
