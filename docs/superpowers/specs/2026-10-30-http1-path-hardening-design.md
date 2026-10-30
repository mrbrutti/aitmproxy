# HTTP/1 path hardening design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's standing autonomous-mode instruction; Matt can reverse any Architect's call in the index below); amended 2026-10-30 after the Stage 6 panel (see the plan's Review log)
**Research inputs:** `docs/research/05-synthesis.md`, `docs/research/MEMORY.md`.
Code read for this spec, at `ec263e1` on `fix/http1-path-hardening` (cut from
`origin/fix/proxy-stale-upstream-keepalive`, PR #108, because `Reconnect`,
`upstream_is_stale` and the redial logic exist only there):
`crates/aitm-proto-http/src/{module,sansio,h2,translate,sender}.rs`,
`crates/aitm-proto-http/tests/{stale_upstream,sansio,sender,h2_mitm}.rs`,
`crates/aitm-core/src/{proxy,guard,authority}.rs`,
`crates/aitm-plugin-maprules/src/lib.rs`, and the vendored `h2` 0.4.19 sources.
Origin of the three defects: the Stage 6 security review of PR #108. All three
pre-date that PR; none is introduced by it.
Amended after the Stage 6 panel (2026-10-30) so the text matches what was built:
Architect's calls 11 to 17, AC25 and AC26, and F6 and F7 are new; Defect 2's
surplus handling now runs after the close check (call 13, which supersedes the
earlier wording); the quiet-logs constraint, Defect 1's logging text and the test
strategy are updated to match. No earlier decision is reversed except where call 13
says so.

## Intent

The stale-upstream work (PR #108) made the HTTP/1 proxy path reconnect to origins
that closed a kept-alive socket. Reviewing it turned up three older defects in the
same path (`crates/aitm-proto-http/src/module.rs` and `src/sansio.rs`): a cleartext
`CONNECT` tunnel dials whatever the first inner request's `Host` header names
instead of the `CONNECT` target; a complete stray response that arrives in the same
upstream read as the end of a legitimate one is parsed, stored, run through the
plugin chain and forwarded to the client; and the TLS handshake to the origin has no
time bound, so a hostile origin that accepts and stalls pins the connection task.
This change fixes all three, each reproduced by a failing test first, without
changing behaviour for well-behaved traffic and without touching the scope/SSRF
guard. It also scopes (does not fix) the same stale-connection exposure in
`serve_h2`.

## Goals

- In a cleartext `CONNECT` tunnel, every dial (first connect and every redial) goes
  to the address the `CONNECT` target resolved to when the tunnel was opened. The
  inner request's `Host` (or absolute-form authority) never chooses the upstream.
- A response that follows a completed response in the same upstream read is never
  parsed as a new response: it is not stored, not emitted through the plugin chain,
  not forwarded. The legitimate response is delivered in full and unchanged.
- Bytes an origin leaves behind after a completed response (a stray complete
  response, a partial head, anything) mark that upstream connection untrusted; the
  next request on the client connection gets a replacement upstream.
- Both upstream TLS handshakes (`HttpModule::mitm` and `Reconnect::connect`) are
  bounded by one shared helper and one constant (30 s). A timeout fails the
  connection or request exactly as a handshake failure does, with a message naming
  the authority.
- Each defect has a sandbox-runnable red-to-green test (no sockets) and a loopback
  integration test (Terminal panel).
- A written scoping of the `serve_h2` stale-upstream exposure, with a recommendation.

## Non-goals

- Fixing `serve_h2` (scoping only; `h2.rs` is not touched).
- Bounding the CLIENT-side handshake or any other client-side pre-serve read (see
  Adjacent findings F1).
- Retrying a request on a fresh upstream after a failure (no request retry anywhere).
- Making Map Remote work inside h1 tunnels (F2).
- Changing `Event`, `FlowError`, flow fields, plugin APIs, config, or the MCP/UI surface.
- Changing `Target::authority()` formatting for IPv6 literals (F3).

## Anti-goals

- Loosening any guard. Every upstream dial stays on `ctx.connect_upstream` (the
  `UpstreamConnector` seam: `SsrfConnector` / `PassiveConnector`), which this change
  does not edit. No new `TcpStream::connect`, no new dial path, and a TLS tunnel must
  never fall back to cleartext.
- Changing any recorded flow field for well-behaved traffic. A flow captured before
  and after this change from the same well-behaved exchange is field-for-field the
  same (`request.authority` included).
- New dependencies, new crate features, or new dev-dependency features (in
  particular no `tokio` `test-util`). New public API is limited to one builder
  method, `HttpModule::with_tls_handshake_timeout`.
- Failing a legitimate response because a different, unsolicited one followed it.
- Logging attacker-controlled bytes. Log byte counts and authorities, never content;
  and where a tunnel's authority will do, log that, not the request's own (client
  text, which can carry URL userinfo).

## Constraints

- No behaviour change for well-behaved traffic: keep-alive reuse, multi-request
  tunnels, pipelined client requests, `Content-Length` / chunked / close-delimited
  bodies, HEAD / 204 / 304, interim `100`, and the 101 upgrade handoff all behave as
  today (AC9, AC14, AC21).
- Sandbox: no port binding. Every red-to-green proof a Coder must show is
  sandbox-runnable (in-memory `DuplexStream` plus the existing `StubConnector`).
  Loopback tests run only in the Terminal panel.
- Quiet default logs: this change adds two `warn` sites and one `debug` site, and
  each names at most an authority and a count, never content. The `warn` sites are
  (1) an unsolicited response from an origin (the upstream authority and the byte
  count only) and (2) once per request, a Map Remote rewrite that is ignored inside
  a CLEARTEXT `CONNECT` tunnel (the tunnel authority only). The second is gated on a
  cleartext tunnel (`conn.scheme == "http"`) for two reasons: a TLS h1 tunnel keeps
  its pre-existing silent ignore (F2), and the Host-versus-tunnel comparison assumes
  default port 80, which would misreport a portless same-host rewrite inside an
  HTTPS tunnel (Architect's call 11). The `debug` site is a `Host`-versus-tunnel
  mismatch; it names the tunnel authority only (call 12).
- Rust gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- `unsafe` is forbidden workspace-wide; none is needed.
- Only `module.rs`, `sansio.rs`, their tests, and one new test file change. `h2.rs`,
  `translate.rs`, `sender.rs`, and everything in `aitm-core` are untouched.

## Design

### Defect 1: cleartext CONNECT tunnel dials the wrong target

**What happens today (from reading the source).** `HttpModule::drive` resolves the
`CONNECT` authority (`Target::resolve(&authority, 443)`), answers `200`, sees a
non-TLS first byte, and builds `Conn::plain(peer, Some(target.authority()))`. The
resolved address is thrown away; only the authority string is kept, as
`Conn.tunnel_authority`. `serve` then starts with `upstream = None`, so
`needs_connect` is true and it dials `Target::resolve(&dial, 80)` with
`dial = redial.unwrap_or(request.authority)`. `request.authority` is the `Host`
header (or the authority of an absolute-form target). So the first inner request's
`Host` picks the upstream for the whole tunnel; later requests reuse that
connection (`needs_connect` is false for a tunnel with a live upstream). A client can
therefore retarget a tunnel with request 1's `Host`, and even without ill intent a
`Host` that omits the port sends `CONNECT host:8080` traffic to `host:80`.

**Not a guard bypass.** The connector still checks the (authority, address) it is
handed. But the pair it is handed is Host-derived, so scope matching, the SSRF
policy's `authority` input, flow metadata and the redial target all disagree with
what the `CONNECT` said. The TLS tunnel paths already dial the `CONNECT` target
(`mitm` uses `target`), and the h2 path is pinned to it and tested as such
(`tests/h2_mitm.rs`, `normal_h2_request_reuses_pinned_upstream`); only the
cleartext tunnel diverges.

**Decision: dial the `CONNECT` target (Architect's call).** In a tunnel, the
route is the `CONNECT` target. The inner `Host` is a header the client sent; it is
forwarded untouched and never consulted for routing.

- *Alternative rejected: require `Host` to equal the `CONNECT` target and refuse
  otherwise.* It breaks well-behaved traffic: omitted default ports (`Host: x` for
  `CONNECT x:80`), case, trailing dot, IP versus name, domain fronting. Comparing
  after normalisation is still wrong for fronting and virtual hosting, where a
  differing `Host` is legitimate.
- *Alternative rejected: keep dialling the `Host` but check its address equals the
  `CONNECT` address.* DNS-dependent, still lets a client pick another name on the same
  address, and more code for a weaker rule.
- *Deferred alternative: honour a genuine Map Remote rewrite in the tunnel the way h2
  does (the `map-remote` mark).* It is a feature, not hardening, and would be
  inconsistent with the TLS h1 tunnel, which ignores it today. See F2.

**The address is pinned, not re-resolved (Architect's call).** The cleartext tunnel
dials the exact address `drive` resolved when it opened the tunnel, through
`ctx.connect_upstream(tunnel_authority, tunnel_addr)`: the same (authority, address)
pair `mitm` hands the connector for TLS tunnels, and the same "resolved once, never
re-resolved" rule `Reconnect` documents. Two reasons beyond symmetry. First, the
alternative (re-running `Target::resolve` on `tunnel_authority`) breaks IPv6-literal
tunnels: `Target::authority()` formats a bracketed `[::1]:8080` as `::1:8080`
(F3), and `split_host_port` cannot parse that back. Second, it saves a DNS lookup per
redial. `Conn` therefore gains `tunnel_addr: Option<SocketAddr>`, set together with
`tunnel_authority`. `h2.rs` only reads `Conn`, so it is unaffected.

**What the stored flow records (Architect's call).** `HttpRequest.authority` keeps
today's value: the `Host` header (or absolute-form authority), falling back to the
tunnel authority when the request has none. The flow's `server_conn.peer` already
records the address the traffic went to (set by `record_server_conn`), so a flow
whose `Host` differs from its destination is visible in the data. Reasons: every
consumer of `request.authority` (the host filter in `store.rs`, MCP `host_eq`, rule
matching in `aitm-rules`, scanner URL building, PoC builders, replay's
`check_active`) treats it as the application-level target, which for virtual hosting
and fronting is the `Host`; recording the tunnel authority instead would change
flows for well-behaved traffic whenever `Host` omits a default port, which is an
anti-goal. h2 already records the client's `:authority` while dialling the pinned
origin, so this makes h1 cleartext consistent with h2. One consequence, stated so it
is not a surprise: `flow.replay` re-sends to the recorded authority, so replaying a
mismatched-`Host` flow goes to the `Host`, through the scope guard, not to the
tunnel target. When a request's authority differs from the tunnel target (compared
case-insensitively with default port 80 applied), the proxy logs one `tracing::debug!`
naming the tunnel authority only (Architect's call 12). The request's own authority is
client text, and an absolute-form target keeps its URL userinfo in `request.authority`
(`http://user:secret@x/`), so logging it would put credentials in a log
(`serve_keeps_a_request_target_userinfo_out_of_the_log` pins it). No `warn` for
the mismatch itself: fronting is normal.

**Consequence for Map Remote and plugin rewrites (Architect's call).** A plugin
that rewrites `request.authority` (Map Remote does: it sets `authority`, `scheme`,
`path`, and the `Host` header, and marks the flow) behaves as follows.

| Connection | Before | After |
|---|---|---|
| Cleartext forward proxy (no `CONNECT`) | dials the rewritten authority; redials when it changes | unchanged (intended) |
| Cleartext `CONNECT` tunnel | the FIRST request of the tunnel dials the rewritten authority (by accident); later requests ride that connection and are ignored | ignored: the dial is always the `CONNECT` target. Routing unchanged, now visible: one `warn` per request names the tunnel authority |
| TLS h1 tunnel | ignored; the rewritten `Host` header is sent to the pinned origin | unchanged (still silent, F2) |
| TLS h2 tunnel | second upstream only for a genuine `map-remote` mark | unchanged |

Nothing in the repository depends on the changed row: `crates/aitm-plugin-maprules/tests/map_remote.rs` drives the plugin without a proxy, `tests/h2_mitm.rs` covers h2 only, and no test sends Map Remote traffic over an h1 tunnel or forward proxy. The user-visible effect is that a Map Remote rule matching cleartext traffic inside a `CONNECT` tunnel (for example `CONNECT host:80`) stops retargeting that tunnel's first request. That behaviour was already half-working (first request only), is now consistent with the TLS h1 tunnel, and is listed as follow-up F2. If Matt prefers to keep it working, the alternative above is about 15 lines and changes nothing else in this design.

So that the ignored rewrite is not lost silently, `serve` logs one `tracing::warn!` per request when, inside a cleartext tunnel, the flow carries the `map-remote` mark and its authority differs from the tunnel target (Architect's call 11). The `warn` names the tunnel authority only, never the request's (call 12). It is gated on a cleartext tunnel (`conn.scheme == "http"`), which is the only row whose behaviour changed: the TLS h1 tunnel keeps its pre-existing silent ignore (F2), and the comparison assumes default port 80, so in an HTTPS tunnel it would misreport a portless same-host rewrite. The `warn` only reports; the route is chosen separately and is the `CONNECT` target either way.

**The non-tunnel path is unchanged (anti-regression, AC19).** With `tunnel_authority`
None (cleartext forward proxy: absolute-form target or `Host`), the dial is the
request's authority, and a change of authority between requests still replaces the
connection. That is the intended semantics there.

**A tunnel with no resolved address refuses to dial (Architect's call 14, AC25).** In
`serve`'s connect step a tunnel that has an authority but no resolved address returns
an error (`tunnel has no resolved CONNECT address; refusing to dial the request Host`)
and dials nothing. Falling through to the request's `Host` would be the route Goal 1
forbids, so the arm fails closed. The state is unreachable today: `Conn::plain` and
`mitm` set `tunnel_authority` and `tunnel_addr` together. The arm exists so that a later
edit that breaks the pairing fails closed instead of routing by `Host` without anyone
noticing.

**Simplification.** With a tunnel's route fixed, the `redial` variable and its
`None if conn.tunnel_authority.is_some()` arm in the stale-upstream branch of `serve`
are redundant and are removed; a cleartext tunnel with no upstream simply flows into
the ordinary connect step, which dials the tunnel target. The existing test
`serve_redials_a_cleartext_tunnel_to_the_origin_it_was_opened_to` keeps its
assertions (only its `Conn` construction changes) and still proves the redial case.
`current_authority` stays (it drives the non-tunnel authority-change check and the
debug log).

### Defect 2: a stray response in the same upstream read is forwarded

**What happens today.** In `Http1Machine::on_server_bytes`, `finish_response`
returns the server reader to `Phase::Head` and the client reader to `Phase::Head`.
If the same `on_bytes` call still holds bytes, the `Phase::Head` arm parses them as a
new response, because `current_flow()` only checks that some flow ever existed, so it
returns the stale flow id. The machine then returns one `Vec` of events containing
the legitimate response's events followed by the stray response's
(`ResponseHeaders`, body chunks, `ResponseComplete`, all carrying the old flow id).
`serve`'s response loop iterates every event of that batch even after `done = true`,
and its `ResponseHeaders` arm has no "a request is outstanding" guard. Effects:

1. the stray head overwrites the flow's stored response, and its body overwrites the
   captured body;
2. the plugin chain sees a second `ResponseHeaders` and `Response` for the same flow;
3. the stray response is forwarded to the client. With a client connection shared
   across origins (a cleartext forward proxy) that is response-queue poisoning;
4. a stray PARTIAL head (no blank line yet) stays in `server.buf`; on a live upstream
   the next response is appended to it, and the origin chooses that response's status
   line and first headers. `take_leftover(Side::Server)` runs only on the discard and
   `needs_connect` paths, so a still-open, same-authority upstream is exposed;
5. `Http1Sender` (replay, `request.send`, the scanner) drives the same machine and has
   the same exposure: it returns the stray head with the bodies concatenated.

PR #108's `upstream_is_stale` probe already covers bytes that arrive BETWEEN requests;
this defect is the same-read case, which the probe cannot see.

**Decision: guard in the machine, handle surplus in `serve` (Architect's call).**

1. **Machine guard (`sansio.rs`).** `Http1Machine::on_server_bytes` parses a response
   head only while a request is complete and unanswered, that is, while the client
   reader is in `Phase::Waiting`. In any other state the server bytes stay in the
   server buffer, unparsed, and the loop stops. The pre-existing error for response
   bytes before any request ever arrived (`current_flow()?`) is kept, and is checked
   first. A parked buffer is capped at `MAX_HEAD_BYTES`: beyond it `on_bytes`
   returns `Err` (a driver that keeps feeding unsolicited bytes cannot grow it
   without bound; the same class of bug `short_circuit_done` was added for). That `Err`
must never fire on the surplus behind a legitimate response, because the caller's
`on_bytes(...)?` would drop the whole `Vec`, tail included. The surplus is part of one
socket read, so the cap is safe exactly while a read is smaller than the cap. A
compile-time assert in `module.rs` encodes that invariant:
`const _: () = assert!(READ_CHUNK < crate::sansio::MAX_HEAD_BYTES)` (`MAX_HEAD_BYTES`
is now `pub(crate)`). A later change to either constant that breaks the invariant
fails the build instead of failing connections at run time (Architect's call 15). The 101
   path is untouched: after a 101 both readers are `Phase::Upgraded`, the server
   reader never reaches `Phase::Head`, and `take_leftover` still hands the bytes
   after the 101 head to the next protocol. Interim `1xx` (non-101) responses are
   skipped inside the same loop while the request is still outstanding, so they pass
   the guard. HEAD / 204 / 304 / `Content-Length` / chunked / close-delimited framings
   are unchanged: the guard only decides whether a head is parsed at all, never how.
   A pipelined client request already parked in the client buffer is unaffected: the
   client reader is `Waiting` for request 1, and request 2 is parsed after
   `finish_response` and the next `on_bytes(Side::Client, ..)`.
2. **Surplus handling (`serve`).** After the response loop ends, the connection is
   not upgraded, and the `Connection: close` check has passed, `serve` takes the server
   buffer (`machine.take_leftover(Side::Server)`). If it is non-empty, an origin sent
   something after a completed response on a connection that stays open. `serve` logs
   one `tracing::warn!` (the upstream authority and the byte count only), discards the
   bytes, and marks the upstream connection `tainted`. The legitimate response has
   already been forwarded in full and is not touched. The stray bytes never reach the
   client, the store, or the plugin chain.
   **Surplus on a closing connection is dropped silently (Architect's call 13).**
   Surplus handling runs AFTER the `Connection: close` check, so when the request or
   the response closes the connection anyway, the surplus bytes are dropped with the
   connection: no `warn`, no taint, nothing is replaced. This supersedes the earlier
   wording of this item, under which surplus handling ran before the close check. The
   reason is that the `warn` says the upstream is being replaced, which would be false
   on a connection that is ending, and that a `warn` per closing connection breaks the
   quiet-logs constraint. The intent is unchanged: the stray never reaches the client,
   the store or the plugin chain on either path (AC10).
3. **A tainted upstream is replaced through the existing stale path.** The check that
   today reads "upstream is Some and `upstream_is_stale`" becomes "`tainted`, or
   upstream is Some and stale". Replacement then behaves exactly as for a closed
   upstream: a TLS tunnel reconnects through `Reconnect` (so the scope/SSRF guard
   applies again); a TLS connection with no `Reconnect` fails the request with
   "upstream TLS connection closed and cannot be re-established" and dials nothing; a
   cleartext connection dials normally. **Pitfall (must not be done):** do not set
   `upstream = None` directly at the point of detection. In a TLS tunnel that would
   skip the `Reconnect` branch, and the next request would fall into the ordinary
   connect step and be sent in CLEARTEXT to the origin's TLS port. Routing through the
   stale path is what makes the replacement fail closed.
4. **The client connection stays open (Architect's call; contradicts the brief's
   lean).** The brief leaned to closing the client connection like `Connection: close`.
   Not done, because the stray never reaches the client, so the client's framing is
   intact and nothing is gained by punishing it, and because three existing PR #108
   tests (`serve_drops_response_bytes_left_over_*`) assert that the client connection
   stays usable after an origin leaves bytes behind. The origin pays the cost: it
   loses its keep-alive connection and the proxy redials.
5. **`Event::Error` is not emitted, and the flow is not marked (Architect's call).**
   The flow completed correctly; `Event::Response` has already been emitted for it.
   Consumers read `Event::Error` as a failed flow (the MCP notification label for it
   is `killed`; plugins' `on_error` hooks fire), which would mislabel a flow that
   delivered its response. `FlowMeta.marks` is owned by operators and plugins; the
   protocol module writes none today. The operator-visible signal is the `warn` log.

*Alternatives rejected.* (a) `on_server_bytes` returns `Err` on a stray head: the
caller's `on_bytes(...)?` drops the whole `Vec`, losing the already-parsed legitimate
tail. (b) A guard only in `serve` that stops iterating events after `done`: the
machine has already consumed the stray bytes and overwritten `self.response`, a stray
fragment is invisible, and `Http1Sender` stays exposed. (c) Closing the client
connection: see item 4.

**Known consequence.** Any non-empty surplus taints the upstream, including a bare
`CRLF` some old servers append to a body (the same one-byte rule the PR #108 probe
uses). Such an origin used to fail the NEXT request on a kept-alive connection (the
CRLF was glued to the next head, giving "malformed status line"); it now works, at the
price of a fresh upstream connection per request and one `warn` line each time (on a
connection that stays open; a closing one is silent, item 2).

### Defect 3: no timeout on the TLS handshake to the origin

**What happens today.** `HttpModule::mitm` and `Reconnect::connect` await
`TlsConnector::connect` with no bound. Only the TCP connect is bounded (`dial()` in
`aitm-core/src/proxy.rs`, 30 s). A hostile origin that completes the TCP handshake
and then never answers the ClientHello pins the connection task (and, for a
reconnect, the client's request) indefinitely. (`Http1Sender` is already bounded: its
whole exchange, handshake included, sits under `RESPONSE_TIMEOUT`.)

**Decision (all Architect's calls).**

- One shared helper: `async fn tls_handshake<IO>(&self, alpn: &[Vec<u8>], server_name: ServerName<'static>, io: IO, authority: &str) -> Result<tokio_rustls::client::TlsStream<IO>>`
  on `HttpModule` (`IO: AsyncRead + AsyncWrite + Unpin`). It builds the connector
  from `upstream_tls_alpn(alpn)`, runs the handshake under `tokio::time::timeout`, and
  is the only place either call site awaits an upstream handshake. `mitm` passes the
  client's ALPN offer; `Reconnect::connect` passes `http/1.1`.
- One constant: `const TLS_HANDSHAKE_TIMEOUT: Duration = READ_TIMEOUT;` (30 s), next
  to `READ_TIMEOUT`. A named alias keeps the intent readable and mirrors h2's
  `wire()`, which bounds its cross-origin TLS handshake with `READ_TIMEOUT`. No config
  key. Worst case a connection can now wait 30 s for the TCP dial plus 30 s for the
  handshake, the same as the h2 path.
- Injectable for tests: `HttpModule` stores the bound in a field, defaulting to the
  constant, with `pub fn with_tls_handshake_timeout(mut self, within: Duration) -> Self`.
  This mirrors h2's `wire_within`, and it is needed because `tokio`'s `test-util`
  (paused time) is not enabled for this crate's tests and enabling it would be a
  `Cargo.toml` change. The test peer is a `DuplexStream` that never answers, so the
  outcome is deterministic; only the 50 ms wait is wall-clock.
- Error message: on timeout, `TLS to upstream {authority} timed out after {within:?}`
  (for 30 s: `... timed out after 30s`). A handshake that fails for any other reason
  keeps today's context, `TLS to upstream {authority}`. Both start with the existing
  prefix and name the authority (`host:port`).
- A timeout surfaces exactly as a handshake failure: `mitm` returns the error and
  the connection ends before any flow exists (so no `Event::Error`, as today);
  `Reconnect::connect` returns it, `serve` propagates it with `?` as the request's
  error, the client receives no bytes, and nothing is dialled afterwards: never a
  cleartext fallback. Dropping the timed-out future closes the upstream socket.

### Test strategy (red to green)

Every defect gets (a) sandbox-runnable unit tests (in-memory streams) that carry the
red/green evidence, and (b) a loopback integration test in a new file
`crates/aitm-proto-http/tests/http1_hardening.rs`, copying the helper pattern of
`tests/stale_upstream.rs` (no refactor of that file), run in the Terminal panel.
Existing in-memory helpers in `module.rs` `mod tests` are reused: `StubConnector`,
`ctx_with`, `tunnel_conn`, `origin_serve` / `origin_serve_trailing`, `client_get`,
`reconnect_to`, `tls_pair`. New helpers are test-only: a buffer-preserving client
read (the existing `client_get` discards bytes read past one response, which would
hide a forwarded stray response), a recording `EventSink`, a rewriting `EventSink`,
and a log-capture `tracing::Subscriber` that the `warn` and `debug` tests install
(AC10, AC18). It is hand-written in `mod tests` against the `tracing` crate the
crate already depends on, so there is no new dependency and no `tracing-subscriber`.

- Defect 1: a `Host` that differs from the tunnel target; the first dial is
  `("127.0.0.1:8080", 127.0.0.1:8080)`. Red today: `("127.0.0.1:9090", ...)`.
- Defect 1, the guard (loopback, added after the panel, call 16): the unit tests
  above hand the module a stub connector, so they prove what `serve` passes to the
  connector, not what the real guard does with it. The loopback test
  `the_guard_judges_a_cleartext_tunnel_by_its_connect_target_not_the_host_header`
  closes that gap through `Proxy::run_browser`, the SSRF-guarded listener (AC26): a
  tunnel to an out-of-scope loopback origin is refused even when `Host` names an
  in-scope one, and the reverse is admitted. In the refusal case neither origin
  accepts a connection, so the test cannot pass because the dial went elsewhere.
- Defect 2: the machine returns exactly three events and leaves the stray bytes in
  the buffer; `serve` forwards exactly the legitimate bytes and emits one
  `ResponseHeaders` and one `Response`. Red today: six events and a poisoned client.
- Defect 3: a stalled `DuplexStream` peer with a 50 ms bound. Red today: the
  handshake is never bounded and the test's outer 5 s guard fires. The Coder first
  adds the helper with no bound so the tests compile and fail behaviourally, then adds
  the bound (Task 1 spells this out).

## Acceptance criteria

Defect 3 (upstream TLS handshake)

1. AC1: With `HttpModule::new().with_insecure(true).with_tls_handshake_timeout(50ms)` and a peer that never answers, `tls_handshake(...)` returns `Err` whose `to_string()` is exactly `TLS to upstream origin.test:8443 timed out after 50ms`.
2. AC2: A handshake that fails promptly (peer dropped) returns `Err` whose `to_string()` is exactly `TLS to upstream origin.test:8443`; a handshake against a live TLS acceptor succeeds.
3. AC3: `HttpModule::mitm` over in-memory streams, with a stalled upstream and a 50 ms bound, returns `Err` with the AC1 message and calls the connector exactly once.
4. AC4: `Reconnect::connect` with a stalled peer returns the AC1 message after exactly one connector call, and `serve` with a stale TLS upstream and a stalled reconnect returns `Err` with that message, writes zero bytes to the client for the failed request, and dials exactly once (no cleartext dial).
5. AC5: `HttpModule::new()` has a handshake bound equal to `READ_TIMEOUT` (30 s); the existing reconnect tests still pass unchanged in behaviour.
6. AC6 (loopback): through a real proxy built with a 300 ms bound, a client that sends `CONNECT` to an origin that accepts TCP and never answers TLS sees its own TLS handshake with the proxy fail, no sooner than 250 ms and within 5 s, and the origin observes the proxy closing the connection within 5 s.

Defect 2 (stray response)

7. AC7: After `GET`, feeding the machine `HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit` followed in the same call by `HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON` returns exactly `[ResponseHeaders(id), ResponseBodyChunk{id, "legit"}, ResponseComplete(id)]`; `response()` has `Content-Length: 5`; `take_leftover(Side::Server)` returns exactly the second response's bytes. The same holds when the second response is only a partial head.
8. AC8: With no request awaiting a response (after a completed exchange, or while the request body is still arriving) `on_bytes(Side::Server, ..)` returns no events and buffers the bytes; more than `MAX_HEAD_BYTES` of them returns `Err`; response bytes before any request ever arrived still return `Err`.
9. AC9: At machine level these still produce exactly their current events and an empty leftover: HEAD with `Content-Length`, 204, 304, `Content-Length`, chunked, close-delimited plus `on_eof`, interim `100` then `200`, 101 with bytes behind it, and a pipelined second request after the first response.
10. AC10: `serve`, with an origin that writes a legitimate response and a complete stray response in one write: a buffer-preserving client reads exactly the legitimate response and has no further bytes pending; the recording sink saw exactly one `ResponseHeaders` and one `Response` for that flow and no `Event::Error`; the stored flow's response is status 200, `Body::Bytes("legit")`, `Content-Length: 5`. This holds whether or not the connection stays open. On a connection that stays open, surplus bytes log exactly one `warn` carrying the authority and the byte count and nothing else, and taint the upstream (`serve_warns_once_when_surplus_replaces_the_upstream_of_an_open_connection`). On a connection that closes anyway (`Connection: close` on the request or the response) the surplus is dropped with no `warn` and no taint (`serve_does_not_warn_about_surplus_when_the_connection_closes_anyway`); call 13.
11. AC11: On that same keep-alive client connection the next request is answered by a replacement upstream: the connector is called twice with the same authority, and the client reads exactly the second origin's response. With a stray partial head left on a LIVE upstream (origin still open, same authority) the next response is status 200 from the replacement, not a response with the injected status line.
12. AC12: In a TLS tunnel the replacement goes through `Reconnect` (exactly one connector call, never cleartext); with no `Reconnect`, the next request fails with `upstream TLS connection closed and cannot be re-established`, writes nothing to the client, and dials nothing.
13. AC13 (loopback): `Http1Sender::send` against an origin that writes a complete response and a second complete response in one write returns the first response only: status 200, `Body::Bytes("legit")`.
14. AC14: A 101 upgrade is unchanged: bytes read after the 101 head are returned by `take_leftover` and reach the next protocol (machine test; `aitm-proto-ws` and `aitm-plugin-wsctl` suites pass).

Defect 1 (tunnel target)

15. AC15: In a cleartext tunnel opened to `127.0.0.1:8080`, a first request with `Host: 127.0.0.1:9090` dials exactly `("127.0.0.1:8080", 127.0.0.1:8080)` and is answered by that origin (unit). Over loopback, with a `CONNECT` target origin A and a different `Host` origin B, A accepts one connection and B accepts none.
16. AC16: Two requests in one tunnel naming different `Host`s share one upstream connection (one dial); after the origin closes it, the redial goes to the tunnel target (`serve_redials_a_cleartext_tunnel_to_the_origin_it_was_opened_to` passes with its assertions unchanged).
17. AC17: For a request in a tunnel the stored flow has `request.authority` equal to the `Host` value (the tunnel authority when the request has no `Host`) and `server_conn.peer` equal to the tunnel address. For a request whose `Host` equals the tunnel target the stored flow is field-for-field what it was before this change.
18. AC18: A plugin that rewrites `request.authority` and `Host` during `Event::Request` does not retarget a cleartext tunnel: the dial is still the tunnel target, and the stored flow keeps the rewritten authority. When the flow carries the `map-remote` mark and the rewritten authority differs from the tunnel target, exactly one `warn` is logged for the request, whose only field is the tunnel authority (the rewritten authority and any userinfo in it never appear); a request that is unmarked, or whose rewrite names the tunnel target, logs none (call 11).
19. AC19: Outside a tunnel (`tunnel_authority` None) the dial is still the request's authority, and a change of authority between requests still replaces the connection (the existing tests `serve_replaces_an_upstream_the_origin_closed` and `serve_drops_response_bytes_left_over_when_the_authority_changes` pass unchanged).
20. AC20: A tunnel opened to an IPv6 literal dials the resolved address recorded at `CONNECT` time (`[::1]:8080` in the test), with no re-parse of the authority string.

Cross-cutting

21. AC21: Well-behaved traffic is unchanged: `cargo test -p aitm-proto-http` (every unit test and every file in `tests/`), plus `aitm-proto-ws` (`ws_capture`), `aitm-plugin-wsctl` (`frame_intercept`), `aitm-plugins` (`response_edit`, `kill_modes`), `aitm-plugin-passthrough` (`tunnel`) and `aitm-plugin-maprules` pass.
22. AC22: The guard is untouched. `git diff <base>..HEAD --stat` lists no change under `crates/aitm-core/`, no change to `h2.rs`, `translate.rs` or `sender.rs`; and `grep -n "TcpStream::connect" crates/aitm-proto-http/src/module.rs` prints nothing (every dial still goes through `ctx.connect_upstream`).
23. AC23: No new dependencies: `git diff <base>..HEAD --stat -- Cargo.toml Cargo.lock 'crates/*/Cargo.toml'` prints nothing.
24. AC24: The Rust gate exits 0: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.

Added after the Stage 6 panel

25. AC25: `serve`, given a `Conn` whose `tunnel_authority` is set and whose `tunnel_addr` is `None`, refuses to dial: it returns `Err` whose message contains `no resolved CONNECT address`, writes zero bytes to the client, and the connector's dial log is empty even though an origin is on offer for the request's `Host` (`serve_refuses_a_tunnel_that_has_no_resolved_address`, `module.rs`; call 14).
26. AC26 (loopback): through the SSRF-guarded listener (`Proxy::run_browser`) with scope naming exactly one loopback origin A, a cleartext `CONNECT` to the out-of-scope loopback origin B whose request says `Host: <A>` is refused (the client sees the connection close, not a hang) and neither A nor B accepts a connection; a `CONNECT` to A whose request says `Host: <B>` is answered by A and B still accepts none. This proves the guard judges the `CONNECT` target, not the `Host` (`the_guard_judges_a_cleartext_tunnel_by_its_connect_target_not_the_host_header`, `tests/http1_hardening.rs`; call 16).

## Adjacent findings (not in this change)

Found while reading; each is a candidate follow-up, none is fixed here.

- **F1. All client-side pre-serve I/O is unbounded, not only the handshake.**
  `LazyConfigAcceptor::new(..).await` and `start.into_stream(..).await` in `mitm`,
  `Prefixed::peek(8)`, `read_head` (the `CONNECT` head) and `peek(1)` in `drive`, and
  the first `stream.peek` in `handle_conn` (`aitm-core/src/proxy.rs`) have no timeout.
  A client that connects and goes quiet pins a task (slowloris). `Target::resolve`'s
  `lookup_host` is unbounded too. Only `serve`'s reads (`READ_TIMEOUT`) and the
  upstream TCP dial are bounded. The brief scoped this change to the origin handshake.
- **F2. Map Remote does not work in h1 tunnels.** In a TLS h1 tunnel the plugin's
  rewritten `Host` header is sent to the pinned origin, and the rewritten authority
  is ignored for routing. After this change the cleartext tunnel behaves the same.
  h2 handles it correctly (a second upstream behind the `map-remote` mark). A fix
  would mirror h2.
- **F3. `Target::authority()` drops IPv6 brackets.** A `CONNECT [::1]:8443` gives
  `tunnel_authority` and the connector's `authority` argument the form `::1:8443`,
  which `Authority::parse_with_default` reads as the host `::1:8443` with no port
  and `split_host_port` cannot parse (scope matching and the SSRF guard's host
  classification see a garbled host). This change
  routes around it for the cleartext dial by pinning the address; the string itself is
  unchanged. The same lost brackets make the Host-versus-tunnel comparison misreport an
  IPv6-literal tunnel; that affects only the `debug` mismatch line and, for a request
  carrying the `map-remote` mark, the Map Remote `warn`, never the route.
- **F4. A failed first dial or reconnect in `serve` emits no `Event::Error`.** The
  flow was inserted and `RequestHeaders` and `Request` were emitted, then `?`
  propagates the connect error; the response loop does emit `Event::Error`. The flow
  is left without a response or an error. Same for the new handshake timeout, to keep
  parity with a handshake failure.
- **F5. `serve_h2` stale upstream** (next section).
- **F6. Errors from `Target::resolve` / `split_host_port` embed the raw client
  authority, and it is logged.** `split_host_port` formats the authority it could not
  parse with `{authority:?}`, and `Target::resolve` formats the host it split from it,
  including any URL userinfo. `handle_conn` logs the resulting error at `warn`
  (`aitm-core` `proxy.rs`, near line 139, "connection handler ended with an error"). A
  pre-existing credential-to-log path, not part of this change: Defect 1's `debug` log
  avoids adding a second one (call 12).
- **F7. Maintenance debts.** (a) The `map-remote` mark string exists in three
  places (`aitm-plugin-maprules`, `h2.rs`, `module.rs`) and should be one shared
  constant when `h2.rs` is next touched. (b) `sender.rs` has its own 16 KiB
  `READ_CHUNK` feeding the same machine, without the cap assert of call 15. (c)
  `Conn.tunnel_authority` and `tunnel_addr` are two `Option`s encoding one fact (a
  tunnel and where it goes) and should become one `tunnel: Option<Tunnel>` in the
  `serve_h2` follow-up, since `h2.rs` reads `tunnel_authority`; this change does not
  touch `h2.rs`. (d) The `mod tests` block is about 60% of `module.rs`, and test
  helpers are copied across six integration-test files; a `tests/common` module is a
  follow-up.

## Scoping: the `serve_h2` stale-upstream exposure

Not part of this change; `h2.rs` is not touched. PR #108 fixed h1 only (comment in
`mitm`, "an h2 upstream gets no stale-connection probe or reconnect"). Everything
below is from reading `h2.rs` and `h2` 0.4.19; the first test of the follow-up should
reproduce it before any fix.

**How the upstream is held.** `serve_h2` handshakes ONE upstream h2 connection,
spawns the `Connection` driver future on its own task (which only logs if it ends
with an error), and keeps the cloneable `SendRequest` as `Upstreams.pinned`. Every
stream task clones it. It is never replaced. Cross-origin (Map Remote) upstreams are
cached in `Upstreams.extra`, keyed by authority, and are never evicted.

**Failure scenario.** The origin closes the connection (idle timeout, or a TCP close)
or sends GOAWAY (graceful shutdown, maximum connection age) while the client's h2
connection to the proxy is idle. The client connection is not torn down by that:
`serve_h2` only ends it after 30 s with no accepted stream and none in flight, and
each new stream resets that timer. In `h2` 0.4.19 a GOAWAY frame or EOF sets the
connection's `conn_error` (`recv_go_away` and `recv_eof` in `proto/streams/streams.rs`),
and `SendRequest::poll_ready` / `ready()` return that error (`poll_pending_open` calls
`ensure_no_conn_error`). So the next client stream reaches `send_req.ready()` in
`drive_stream`, gets `Err`, and `stream_task` returns `upstream h2 not ready`: it emits
`Event::Error` for that flow and drops the `SendResponse`, so the client sees a reset
stream and no response. Because `pinned` is never replaced, EVERY later stream on that
client connection fails the same way until the client opens a new connection, which a
client that keeps retrying on the same connection never does. A second exposure in
the same place: a dead entry in `extra` is returned forever for its authority and
counts against `MAX_EXTRA_UPSTREAMS` (8), so enough stale cross-origin upstreams make
the pool refuse new targets.

**Smallest viable fix.** (1) Make the pinned handle replaceable: hold it behind a
`tokio::sync::Mutex` together with a generation number (the `tokio` `sync` feature is
already enabled). (2) Before `send_request`, poll `poll_ready` once without blocking
(`futures::future::poll_fn(..).now_or_never()`; no I/O poll is involved, so no
cooperative-budget trap like the h1 probe's). `Some(Err)` means dead. `None` means
at the concurrency limit: continue to the existing bounded `ready()` wait. An `Err`
from that wait also triggers a replacement, which is safe to retry once because no
byte of the request has been sent. (3) Replace by `ctx.connect_upstream(authority,
addr)` (scope and SSRF applied again, as `Upstreams::open` already does), the shared
`tls_handshake` helper from this change with the existing h2-ALPN config, a check that
ALPN is `h2` (fail closed otherwise), the existing bounded `h2` handshake, and a new
driver task. The tunnel's authority, resolved address and server name are already on
`Conn` (`tunnel_authority`, the new `tunnel_addr`, `server_conn.sni`). (4) Refresh the
`server_conn` record for flows on the replacement, as `record_server_conn` does in h1.
(5) Apply the same liveness check to `extra`, evicting dead entries.

**State and pitfalls.**

- *Single flight.* Many concurrent streams see the same dead handle. A stream that
  fails records the generation it used; under the lock, if the generation has moved,
  it reuses the new handle, otherwise it replaces and bumps it. Without this, N
  streams run N handshakes. The lock is held across one handshake, which the shared
  helper bounds at 30 s.
- *In-flight streams.* Do not abort the old driver task: streams already open keep
  their `SendRequest` clone and finish on it. The old connection closes itself when
  its last stream ends.
- *GOAWAY semantics.* After GOAWAY with last-stream-id N, streams with id <= N are
  processed normally; only new streams need the replacement. `h2` errors locally
  initiated streams above N with the remote GOAWAY error; the origin did not process
  them, so retrying exactly those is safe, but request retry is a separate decision
  (non-goal here; for h2 it should be limited to "provably unprocessed": `ready()`
  failed before sending, `REFUSED_STREAM`, or id above the GOAWAY's last-stream-id).
- *Never fall back* to a different protocol or cleartext on a failed replacement; the
  stream fails.
- *TLS session reuse and ALPN.* The replacement must negotiate `h2` again; a server
  that now answers `http/1.1` cannot be bridged to an h2 client.

**Tests it needs.** In-memory `h2` client/server pairs over `DuplexStream` for the
unit level (dead-handle detection; single flight with N concurrent streams; a stream
in flight across a GOAWAY completing while a new one opens a new connection); and
loopback tests in the style of `tests/h2_mitm.rs` (`spawn_counting_origin`,
`connect_h2`, `h2_get_with_authority`, `spawn_closing_origin`): origin closes after the
first response then a second request succeeds with `connections == 2`; origin sends
GOAWAY(NO_ERROR) then closes; a refused replacement (guard) fails the stream closed;
a replacement that negotiates `http/1.1` fails closed; a stalled replacement
handshake is bounded; the `extra` cache evicts a dead entry.

**Size.** About five tasks over three files (`h2.rs`, a small hand-off in `module.rs`
that gives `serve_h2` the connection facts and exposes the shared handshake helper
to the sibling module, and one new test file). The work is medium: the logic is
small, the concurrency design is the risk. That hand-off is also the moment to fold
`Conn`'s `tunnel_authority` and `tunnel_addr` into one `tunnel: Option<Tunnel>` (F7),
because `h2.rs` is the other reader of `tunnel_authority`.

**Recommendation: a separate spec, plan and PR, stacked on this one, started soon.**
It needs this change's `tls_handshake` helper and `Conn.tunnel_addr`, but it has its
own design questions (retry policy after GOAWAY, `extra` eviction, per-connection
versus per-stream replacement) and a different risk profile (concurrency), and
folding it in would bury this change's three narrow fixes in a larger panel review.
It is an availability defect, not a guard hole, but it is likely the most common
user-visible symptom of the three, because browsers negotiate h2 for most HTTPS
sites.

## Left to the builder

- Exact names of test helpers and tests (the plan names the ones the acceptance
  criteria depend on; names are otherwise free).
- The exact shape of the `Conn` change, provided `tunnel_authority` and `tunnel_addr`
  are set together, `h2.rs` is not touched, and `Conn::plain(peer, None)` call sites
  keep compiling.
- The name and storage of the "tainted" flag, and the wording of the `warn`, `debug`
  and error strings other than the timeout message fixed in AC1.
- Whether to add a small `fn` for the Host-versus-tunnel comparison, or inline it.
- Whether the shared handshake helper lives as a method on `HttpModule` or a free
  function taking the timeout, provided the field and
  `with_tls_handshake_timeout` exist as specified.

## Open questions

None. Every decision above that Matt could reasonably reverse is marked
**(Architect's call)** and indexed below.

## Index of Architect's calls

1. Defect 1: dial the `CONNECT` target; `Host` is never routing input in a tunnel; do not require `Host == CONNECT target`.
2. Defect 1: pin the resolved address (`Conn.tunnel_addr`) instead of re-resolving.
3. Defect 1: `HttpRequest.authority` keeps the `Host` value; `server_conn.peer` shows the destination; one `debug` log on mismatch.
4. Defect 1: Map Remote / plugin authority rewrites no longer retarget a cleartext tunnel (changes the first-request-only accident; follow-up F2). Alternative on request: honour the `map-remote` mark.
5. Defect 2: guard in the machine (parse a response head only while a request awaits one) plus surplus handling in `serve`; cap on the parked buffer.
6. Defect 2: a tainted upstream is replaced through the existing stale path; never set `upstream = None` directly.
7. Defect 2: do NOT close the client connection (departs from the brief's lean, to keep three existing tests and spare the client).
8. Defect 2: no `Event::Error`, no flow mark; `warn` log only.
9. Defect 3: `TLS_HANDSHAKE_TIMEOUT = READ_TIMEOUT` (30 s), one shared `tls_handshake` helper, injectable through the new `with_tls_handshake_timeout`, message `TLS to upstream {authority} timed out after {within:?}`.
10. h2: separate PR, stacked on this one, started soon; adjacent findings F1 to F4 deferred.

Added after the Stage 6 panel:

11. Logging: a Map Remote rewrite ignored inside a CLEARTEXT `CONNECT` tunnel logs one `warn` per request (tunnel authority only), gated on `conn.scheme == "http"` so a TLS h1 tunnel stays silent (F2) and the port-80 comparison is not misapplied to HTTPS. The quiet-logs constraint is now two `warn` sites and one `debug` site. Routing is unchanged.
12. Logging: the Host-versus-tunnel `debug` log names the tunnel authority only, never the request's, because an absolute-form target keeps URL userinfo in `request.authority`.
13. Defect 2: surplus handling runs after the `Connection: close` check; on a closing connection the surplus is dropped silently (no `warn`, no taint). Supersedes the earlier wording of Defect 2 item 2. AC10 to AC12 keep their intent.
14. Defect 1: a tunnel with an authority but no resolved address refuses to dial instead of falling back to `Host` (unreachable today; AC25).
15. Defect 2: a compile-time assert, `READ_CHUNK < sansio::MAX_HEAD_BYTES`, encodes the invariant under which the parked-bytes cap cannot drop a legitimate response tail (`MAX_HEAD_BYTES` becomes `pub(crate)`).
16. Test strategy: a loopback test through the SSRF-guarded listener proves the guard judges the `CONNECT` target (AC26); the log-capture helper is test-only, written on the existing `tracing` dependency.
17. Deferred to the `serve_h2` follow-up: folding `Conn`'s two tunnel `Option`s into one `Tunnel`, and the other maintenance debts (F7); the pre-existing authority-in-error logging path (F6) is recorded, not fixed.
