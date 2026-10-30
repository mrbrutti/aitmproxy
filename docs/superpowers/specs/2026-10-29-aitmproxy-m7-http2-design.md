# aitmproxy M7 — HTTP/2 MITM design

**Status:** approved (2026-10-29 by Matt — approved the spec and directed proceeding to the Stage-3 plan, accepting each Open-Question recommendation below)
**Research inputs:** `docs/superpowers/specs/2026-10-28-aitmproxy-m6-parity-design.md` (§6 HTTP/2 stub, §0 rule-match model, the deny-by-default capability table), `docs/research/03-rust-proxy-stack.md` (§HTTP stack: `h2`/`hyper`, multiplexing correlation), `docs/research/01-mitmproxy.md` (HTTP/2 + TLS edge-case note), `docs/superpowers/specs/2026-10-27-aitmproxy-platform-design.md` (Flow/Event/ProtocolModule core types), `docs/superpowers/specs/2026-10-27-aitmproxy-plugin-system-design.md` (additive module/command seam). Source read: `crates/aitm-proto-http/src/{module.rs,sansio.rs,sender.rs}`, `crates/aitm-core/src/{flow.rs,event.rs,protocol.rs,ctx.rs,chain.rs,config.rs}`, `crates/aitm-proto-ws/src/module.rs`.

## Intent

aitmproxy intercepts, edits, kills, replays, maps and passes through HTTP/1.1,
HTTPS and WebSocket today, but it speaks **only HTTP/1.1 on the wire**: both the
client-facing (forged-leaf) and upstream TLS configs pin ALPN to `http/1.1`
(`module.rs` `upstream_tls()` line 155, `impersonating_config()` line 169), so a
modern site that would negotiate `h2` is forced down to h1 or — for an `h2`-only
endpoint — breaks. M6 deliberately split HTTP/2 into its own milestone (M6 §6)
because it is the one **L**/High-risk parity gap: deep protocol work (HPACK, flow
control, stream multiplexing, GOAWAY/RST) with a conformance surface unlike the
five additive command/plugin items. M7 adds HTTP/2 MITM so that an `h2` flow is
captured, shown and acted on **exactly like an h1 flow** — same `Flow::Http`, same
`Event` sequence, so every operator and agent capability built in M3–M6
(intercept/edit/kill/replay, Map Local/Remote, rules, sessions/HAR, passthrough)
works on `h2` with no per-protocol special-casing downstream.

## Goals

- **ALPN negotiation.** The client-facing and upstream TLS handshakes offer `h2`
  (and still `http/1.1`), instead of pinning `http/1.1`. An `h2`-capable client
  talking to an `h2`-capable server is intercepted over HTTP/2 end to end; either
  side lacking `h2` falls back to the existing h1 path with no regression.
- **h2 capture as ordinary flows.** Each HTTP/2 **stream** becomes one
  `HttpFlow` (`version: HttpVersion::H2`, `ConnInfo.alpn = Some("h2")`), emitting
  the same `RequestHeaders → Request → ResponseHeaders → Response` events as h1, so
  the three UIs and the bus render it as an HTTP flow with no new variant.
- **Stream multiplexing.** Many concurrent streams on one connection produce many
  distinct, concurrent flows. Parking (intercepting) one stream must not stall the
  others, the connection, or HTTP/2 control traffic (PING/SETTINGS/WINDOW_UPDATE).
- **Same operator/agent capabilities on h2.** `flow.intercept` rules, response-phase
  park + `flow.mutate` (incl. `status`), `flow.kill` modes, `flow.replay`, Map
  Local / Map Remote, the shared `aitm-rules` match model, sessions/HAR and TLS
  passthrough all apply to `h2` flows unchanged, because they operate on
  `Flow`/`Event`, not on the wire protocol.
- **Bounded memory under multiplexed load.** Per-message body caps
  (`LimitConfig.max_body_bytes`) are honoured per stream exactly as in h1, and the
  number of concurrently buffered streams is bounded (a max-concurrent-streams
  setting) so a client opening thousands of streams cannot exhaust memory.
- **Library-backed protocol engine.** HPACK, flow control, WINDOW_UPDATE,
  RST_STREAM, GOAWAY, SETTINGS and prioritization are delegated to the vetted `h2`
  crate (the same engine `hyper` uses), not hand-rolled.

## Non-goals

- **No h2 ↔ h1 cross-version bridging in v1.** aitmproxy **mirrors** the version:
  it presents the client the same protocol the upstream negotiated (see Design §1),
  so the common path is h2↔h2 or h1↔h1 and never h2-client↔h1-upstream. Full
  cross-version translation (client `h2`, upstream `h1`) is an explicit Open
  Question, not built here.
- **No HTTP/2 cleartext (h2c).** Only `h2` negotiated via ALPN over TLS. Prior-
  knowledge h2c and the `Upgrade: h2c` dance are out of scope (and the acceptor
  does not sniff the h2 preface).
- **No HTTP/3 / QUIC, no gRPC semantic decode.** Out of scope for M7 (as for M6).
  gRPC rides h2 and is captured as h2 flows with binary bodies; decoding protobuf
  is not M7.
- **No server push.** Push is disabled in both directions (Design §5); aitmproxy
  does not capture or forward `PUSH_PROMISE` streams.
- **No new operator-UI work.** The UIs already key on `HttpVersion`/`ConnInfo.alpn`
  and render any `Flow::Http`; M7 delivers only the core wire capability. No UI
  change is required for an h2 flow to appear and be actionable.
- **No change to the h1 path's behaviour.** The existing `serve()` loop, sans-IO
  `Http1Machine`, replay sender and WebSocket upgrade path keep working byte-for-
  byte; M7 is additive alongside them.
- **No re-prioritization.** Stream priority is left to the `h2` engine's scheduler;
  aitmproxy neither reads nor rewrites priority.

## Anti-goals

- **Forking the Flow/Event model.** If an h2 stream needs a new `Flow` variant, a
  new `Event` set, or makes intercept/mutate/plugins behave differently from h1,
  the "same surface" goal has failed and every downstream consumer (three UIs, bus,
  every M3–M6 plugin) must special-case h2. The whole milestone exists to avoid
  this.
- **A head-of-line stall.** If parking one intercepted stream (its `emit().await`)
  blocks the connection's frame loop, other streams freeze and the `h2` flow-control
  windows deadlock. A multiplexed protocol driven as if it were sequential is a
  failure even if a single-stream test passes.
- **Unbounded memory.** An h2 peer can open streams far faster than an h1 client can
  pipeline requests. No per-stream cap, or no limit on concurrent in-flight streams,
  turns one connection into an OOM.
- **A conformance veneer that smuggles illegal headers.** Forwarding h1 hop-by-hop
  headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Upgrade`, …) into an
  h2 frame, or a malformed pseudo-header set, produces a `PROTOCOL_ERROR` and drops
  the flow. h2 framing rules (RFC 9113 §8.2.2) must be honoured on encode.
- **Bypassing the guards on h2.** Map Remote redirects, replay and any active egress
  from an h2 flow go through the same `ScopeRateGuard`/SSRF path as h1. An h2 flow is
  not a loophole around scope.
- **Regressing h1.** Offering `h2` in ALPN must never break an h1-only client or
  server; the fallback must be exercised, not assumed.

## Constraints

- **Rust gate:** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  must pass before any review. Any `unsafe` needs a `// SAFETY:` comment and a
  Security-reviewer sign-off (none is expected — the `h2` crate is safe Rust).
- **Additive core.** `Flow`/`HttpFlow`/`HttpRequest`/`HttpResponse`/`Event`/
  `InterceptState`/`FlowCtx`/`ConnInfo` are **reused, not changed**:
  `HttpVersion::H2` already exists (`flow.rs:151`); `ConnInfo.alpn` already exists;
  `Event` is `#[non_exhaustive]` and the existing variants carry h2 unchanged. The
  work lands **inside `aitm-proto-http`** (a new `h2` arm in the `HttpModule`), not
  in `aitm-core`. Any genuinely unavoidable `aitm-core` touch is named and justified
  in Design (none is currently foreseen).
- **Dependency:** add the **`h2` crate** (`h2` 0.4.x, the hyper HTTP/2 engine) and
  the **`http` crate** (`http` 1.x, for the `Request`/`Response`/`HeaderMap`/
  pseudo-header types `h2` speaks) to `crates/aitm-proto-http/Cargo.toml`, pinned
  there like the existing TLS deps (sibling-session convention, proto-http STATUS
  note). No new TLS or async stack: `h2` runs over the already-decrypted
  `tokio-rustls` streams. `rustls`/`tokio-rustls` stay at 0.23/0.26; ALPN config is
  a field change, not a version bump.
- **Performance / memory (platform hard requirement).** Response bodies stream
  (never fully buffered) exactly as h1; request bodies and the captured response
  copy are capped at `LimitConfig.max_body_bytes` per stream; concurrent in-flight
  streams per connection are capped (new `LimitConfig.max_concurrent_streams`,
  Design §4). HPACK dynamic-table size and max header-list size are bounded via the
  `h2` builder so a compression-bomb header block is refused, not buffered.
- **Deny-by-default, guards reused.** h2 flows inherit every existing guard: Map
  Remote and replay from an h2 flow call `ScopeRateGuard::check_active`; passthrough
  hosts never reach the h2 arm; the agent gates (`maps.allow_agent_authoring`,
  `scope.allow_agent_widen`, …) are unchanged. M7 adds **no new command** and **no
  new config gate** beyond the two limit knobs — the capability surface is the M3–M6
  one, now reachable over h2.
- **Config via YAML**, `deny_unknown_fields`: the new `LimitConfig` fields parse from
  the same file and default to safe values, so an existing config keeps working.
- **Workflow:** M7 travels all seven stages in `docs/superpowers/WORKFLOW.md`.

## Design

HTTP/2 is added as a **second protocol arm inside the existing `HttpModule`**, not
a new module and not a change to `aitm-core`. The `HttpModule` already owns TLS
MITM, the CA, upstream connection and the plugin-chain plumbing; M7 teaches its
`mitm()` path to negotiate ALPN and, when both sides land on `h2`, drive the
connection with a new `serve_h2()` built on the `h2` crate instead of the h1
`serve()` loop. Both arms emit the identical `Flow::Http` + `Event` sequence, so
everything above the wire is protocol-agnostic.

### 1. ALPN negotiation — mirror the upstream's choice **(Architect's call)**

Today `mitm()` reads the ClientHello (for SNI), connects upstream with ALPN pinned
to `http/1.1`, mints a leaf, and finishes the client handshake with ALPN pinned to
`http/1.1`. M7 changes the ALPN offered on both handshakes and records what was
negotiated.

The chosen policy is **mirror**: the client is offered exactly the protocol the
upstream agreed to, so the two decrypted streams always speak the *same* version
and no cross-version bridge is needed in v1.

Sequence in `mitm()`:

1. **Read client ALPN offer** from the ClientHello. `rustls`'s
   `ClientHello::alpn()` yields the client's ALPN list (e.g. `[h2, http/1.1]`); an
   absent list is treated as `[http/1.1]`. This is available at the same point SNI
   is read (`module.rs:221`).
2. **Connect upstream offering the client's list** (in the client's preference
   order). The upstream `ClientConfig.alpn_protocols` must become **per-connection**
   (today it is a cached `OnceLock` pinned to `http/1.1`): either rebuild the client
   config per connection or cache the two shapes. After the handshake, read the
   negotiated protocol via `TlsStream::get_ref().1.alpn_protocol()` → `P ∈ {h2,
   http/1.1}` (absent ⇒ `http/1.1`).
3. **Mint the leaf** as today (unchanged).
4. **Finish the client handshake offering only `[P]`**, so the client ends up on
   `P` too. `impersonating_config()` gains the negotiated protocol as a parameter
   and sets `alpn_protocols = vec![P]`.
5. **Record `P`** in both `ConnInfo.alpn` (client and server) — `"h2"` or
   `"http/1.1"`.
6. **Branch:** if `P == h2`, call `serve_h2(client_tls, upstream_tls, conn, …)`;
   otherwise the existing `serve(...)` (h1) runs verbatim.

Why mirror rather than always-h2 or full bridging: mirror makes the common case
(h2↔h2, h1↔h1) require only one translation — h2 frames ↔ the `HttpRequest`/
`HttpResponse` model — and **eliminates the h2↔h1 translation matrix** the M6 stub
worried about. It cannot force h2 onto an h1-only client (a known footgun) and
cannot break an h2-only upstream. The only capability mirror forgoes is normalising
a mixed pair to one version, which no operator has asked for. Full bridging is
Open Question 1.

Edge cases: an h2-only upstream with an h1-only client ends with the client on h1
and the upstream on h2 — mirror cannot satisfy both, so this specific pair **does**
need a bridge or a clean failure. v1 behaviour: **fail the connection with a logged
error** (rare; an h1-only client against an h2-only origin is already broken without
a proxy). Flagged in Open Question 1.

### 2. The h2 connection driver (`serve_h2`) — concurrency is the core decision

The h1 `serve()` loop is strictly **one exchange at a time** (`Phase::Waiting`,
keep-alive), and critically **`ctx.emit(...).await` blocks until the flow is
resumed** when a plugin parks it (`chain.rs:83` awaits the resume receiver). That
sequential, block-on-park shape is correct for h1 and **fatal for h2**: an h2
connection multiplexes concurrent streams and must keep servicing connection-level
frames (SETTINGS, PING, WINDOW_UPDATE) even while one stream is parked at a
breakpoint.

**Decision: drive each accepted h2 stream as its own spawned task.** The `h2` crate
splits the two concerns cleanly:

- **Connection halves** own all framing, HPACK, flow control and control frames and
  are polled continuously:
  - client-facing: `h2::server::handshake(client_tls)` → a `server::Connection`
    that yields `(http::Request<RecvStream>, server::SendResponse)` per inbound
    stream.
  - upstream-facing: `h2::client::handshake(upstream_tls)` → `(SendRequest,
    client::Connection)`; the `Connection` future is spawned and polled to drive
    I/O, and the cloneable `SendRequest` handle opens upstream streams concurrently.
- **Per-stream task:** for each accepted client stream, spawn a task that runs the
  full flow lifecycle below. Because the lifecycle's `emit().await` lives in its own
  task, parking stream A suspends only A's task; the connection future and every
  other stream keep running. This is the one architectural property the whole
  milestone depends on.

Per-stream lifecycle (mirrors the h1 ordering so the Event sequence is identical):

1. Translate the inbound `http::Request` head into an `HttpRequest`
   (`version: H2`, pseudo-headers → `method`/`scheme`/`authority`/`path`,
   regular headers → `HeaderMap`), insert a `Flow::Http` (`id` fresh), and
   `emit(Event::RequestHeaders(id))`.
2. Drain the request `RecvStream` body chunk by chunk into a buffer **capped at
   `max_body_bytes`** (over the cap ⇒ `RST_STREAM`/413-equivalent and mark
   `truncated`, as h1 does), releasing flow-control capacity as consumed. Set the
   captured body, then `emit(Event::Request(id))` — this is the request-phase
   breakpoint; the chain may park, mutate, short-circuit (`set_response`) or kill.
3. Act on the post-dispatch flow state, same `match` as h1 `serve()`:
   `InterceptState::Killed` ⇒ `RST_STREAM` (see §6 kill modes); `flow.response`
   set ⇒ short-circuit (`send_response` without touching upstream — this is how Map
   Local and `flow.kill {429|503}` work); otherwise forward.
4. Forward: open an upstream stream via `SendRequest::send_request` with the
   (possibly mutated) head and stream the request body; receive the upstream
   `http::Response`, build `HttpResponse` (`version: H2`, `:status` → `status`),
   stage it, `emit(Event::ResponseHeaders(id))` — the **response-phase breakpoint**
   (park/edit/`status` all work here as in M6 F3).
5. Stream the response body: `send_response(...)` to the client, then pump upstream
   `RecvStream` chunks to the client `SendStream`, capturing a capped copy, honouring
   flow control in both directions. On completion set the captured body and
   `emit(Event::Response(id))`.

Trailers (h2 HEADERS after DATA) are forwarded transparently when present; they are
not represented in the editable model (left to the builder — pass-through default).

`GOAWAY` from either side tears the connection down gracefully: stop accepting new
streams, let in-flight stream tasks finish, then close. A connection-level `h2`
error maps to `Event::Error` on any still-open flow and drops the connection.

### 3. Why the h2 arm sits at `serve`, not behind the sans-IO `HttpStateMachine` trait

The M6 §6 stub sketched "an h2 arm behind the existing `HttpStateMachine` seam (the
`h2` crate)". Reading the code, that phrasing does not hold and the spec corrects
it: `HttpStateMachine` is a **sans-IO** trait (`on_bytes`/`poll_outbound`,
`sansio.rs:18`) that deliberately owns no I/O. HTTP/2 flow control is inseparable
from I/O — the receiver advertises window capacity as it *actually consumes* bytes,
so the protocol engine must own reads and writes. The `h2` crate is therefore an
**I/O-driving** engine (`handshake(io)` takes an `AsyncRead + AsyncWrite`), not a
sans-IO byte pump, and cannot be wrapped behind `on_bytes`/`poll_outbound` without
fighting its windowing. The honest seam is **one level up**: `HttpModule::mitm()`
branches on negotiated ALPN to either the sans-IO h1 `serve()` or the h2-crate-
driven `serve_h2()`. The `HttpStateMachine` trait is untouched and keeps serving
h1 (and the replay sender). This is a deliberate refinement of the stub, recorded
here so the planner and reviewers expect it.

### 4. Flow control, limits and bounded memory

Flow control, WINDOW_UPDATE and prioritization are **delegated to the `h2`
crate**; aitmproxy does not implement windowing and does not re-prioritize. The
proxy's job is to bound resources:

- **Per-message body cap:** each stream's request buffer and captured response copy
  are capped at `LimitConfig.max_body_bytes`, identical to h1 (`module.rs:406`,
  `:582`). Response bodies always stream to the client; only the captured *copy* is
  capped/truncated.
- **Concurrent streams:** set `h2`'s `SETTINGS_MAX_CONCURRENT_STREAMS` on the
  server side from a new **`LimitConfig.max_concurrent_streams`** (default e.g.
  128) so a client cannot open unbounded parallel streams. This is the one new
  config knob M7 needs; it defaults safely and parses additively.
- **Header-block bounds:** cap the HPACK decoder's max header-list size and dynamic-
  table size via the `h2` builder, so a compression-bomb HEADERS block is rejected
  rather than buffered. (Exact values left to the builder; must be finite.)
- **Idle/timeout:** reuse the existing read-timeout posture; an idle h2 connection
  is torn down like an idle h1 one.

### 5. Server push — disabled both directions **(Architect's call)**

v1 **disables HTTP/2 server push**: set `enable_push(false)` on the client-facing
`server::Builder` (the client is told the proxy accepts no pushes to forward) and
do not accept pushed streams from upstream (`SendRequest` without reserving push /
ignore `PUSH_PROMISE`). Rationale: push is effectively dead (Chrome removed support
in 2022; most origins never push), capturing a pushed stream as an unsolicited flow
has no operator story yet, and mirroring a push through the breakpoint/mutate
pipeline is disproportionate risk for M7. Disabling it is spec-conformant (push is
optional) and keeps the flow model one-request-one-stream. Re-enabling push capture
is a future milestone if a real target needs it.

### 6. How every M3–M6 capability applies to h2 (unchanged by construction)

Because an h2 stream becomes an ordinary `Flow::Http` emitting the ordinary `Event`
sequence, the plugins and commands built in M3–M6 act on h2 flows **without
modification**. What M7 must verify (not re-build):

- **Intercept rules + response park + `flow.mutate` (M6 F3):** the intercept plugin
  matches `aitm-rules` on each `Event` and calls `FlowCtx::intercept()` to park;
  in `serve_h2` the park suspends only that stream's task (§2). Response-phase park
  fires at `Event::ResponseHeaders`, which `serve_h2` emits **before** any response
  byte reaches the client (step 4), so an edited status/headers/body reaches the
  client — the same guarantee h1 gives.
- **`flow.kill` modes (M6 F3):** `reset` ⇒ **`RST_STREAM`** on that stream (h2's
  precise analogue of an h1 connection reset, and strictly better — it kills one
  stream, not the whole connection); `429`/`503` ⇒ short-circuit `send_response`
  with that status (no upstream stream opened). The kill path reads the same
  `InterceptState::Killed` / `flow.response` state as h1.
- **`flow.mutate`:** edits the staged `HttpRequest`/`HttpResponse` in the store via
  `FlowCtx::flow_mut()`; `serve_h2` encodes the mutated head into the h2 stream,
  **stripping h1-only hop-by-hop headers** (`Connection`, `Transfer-Encoding`,
  `Keep-Alive`, `Upgrade`, `Proxy-*`) that are illegal in h2 (RFC 9113 §8.2.2), as
  the h2 encoder requires.
- **Map Local (M6):** on the request-phase match the maprules plugin sets a
  response; `serve_h2` sees `flow.response` and short-circuits — same code path as a
  short-circuit reply. No upstream stream opened.
- **Map Remote (M6):** the plugin rewrites authority/scheme/path and calls
  `ScopeRateGuard::check_active` on the new authority; `serve_h2` opens the upstream
  stream to the rewritten target. **Caveat:** an h2 connection is pinned to one
  `:authority`/origin; a Map Remote redirect to a *different* host over the *same*
  h2 connection means opening a **second upstream connection** for that stream
  (TLS+h2 handshake to the new origin), not reusing the pinned one. `serve_h2` must
  support a per-stream upstream distinct from the connection's default origin. This
  is the one place Map Remote on h2 is more than "the h1 path, but h2" — called out
  for the planner.
- **Replay (`flow.replay` / `request.send`):** the existing `Http1Sender` reissues
  a request over **h1** regardless of the captured flow's version; a replayed h2
  flow is re-sent over h1 and captured as an h1 replay flow. v1 keeps this (a replay
  is a fresh request and most origins accept h1); preserving h2 on replay is Open
  Question 2.
- **Sessions / HAR (M6 F10):** serialization is a serde view over `Flow`; `H2`
  round-trips as a `HttpVersion` value and HAR records `httpVersion: "HTTP/2"`. No
  change beyond the version tag mapping.
- **TLS passthrough (M6 F11):** a passthrough host is tunnelled before TLS MITM, so
  it never reaches ALPN or the h2 arm — the client speaks h2 directly to the origin
  and aitmproxy captures nothing for it. No interaction; stated so no one adds one.
- **WebSocket:** WS-over-h2 (RFC 8441 `:protocol` CONNECT / Extended CONNECT) is
  **out of scope** (Non-goals); h1 WebSocket upgrade is untouched.

### 7. Deny-by-default / capability model (h2 delta)

| Capability on an h2 flow | Egress? | Guard | Agent gate |
|---|---|---|---|
| intercept rules, response park, `flow.mutate` (incl. `status`) | no | none (edits a captured flow) | n/a |
| `flow.kill {reset}` ⇒ RST_STREAM; `{429\|503}` ⇒ short-circuit | no | none | n/a |
| Map Local (h2 short-circuit) | no | none; path confined to map root | `maps.allow_agent_authoring` |
| Map Remote (h2, may open a 2nd upstream) | **yes** | `ScopeRateGuard::check_active` on rewritten host | `maps.allow_agent_authoring` |
| `flow.replay` of an h2 flow (re-sent over h1) | **yes** | existing replay guard | n/a |
| session/HAR of h2 flows | no | n/a | existing `session_io` gates |

M7 introduces **no new command and no new agent gate** — only `h2` on the wire plus
two bounding limits (`max_concurrent_streams`, header-block caps). Every active path
reuses the one `ScopeRateGuard`; every passive path (edit-of-captured, short-
circuit, session I/O) is ungated exactly as in h1.

## Acceptance criteria

Each is observable via `cargo test`. Integration tests stand up a local `h2` origin
(the `h2` crate's server) behind a forged-leaf TLS listener and drive an `h2`
client through the proxy; literal expected values are given where load-bearing.

1. **AC-H2.1 (ALPN + capture):** an `h2`-capable client through the proxy to an
   `h2`-capable origin negotiates `h2` on **both** hops — the captured `HttpFlow`
   has `request.version == HttpVersion::H2` and both `ConnInfo.alpn == Some("h2")` —
   and the response body round-trips byte-for-byte to the client.
2. **AC-H2.2 (h1 fallback, no regression):** the same client against an
   **h1-only** origin negotiates `http/1.1` end to end (captured flow
   `version == Http11`, `alpn == Some("http/1.1")`), and an **h1-only** client
   against an `h2`-capable origin is served over h1 — i.e. offering `h2` in ALPN
   breaks neither party.
3. **AC-H2.3 (multiplexing ⇒ distinct flows):** a client that opens **three
   concurrent streams** on one h2 connection produces **three** distinct `HttpFlow`s
   with distinct `FlowId`s, each with its own request/response, all completing.
4. **AC-H2.4 (no head-of-line stall under intercept):** with an intercept rule
   matching stream A, A parks (`InterceptState::Intercepted`) while concurrent
   streams B and C on the **same connection complete normally**; after `flow.resume`
   of A, A completes too. (Proves per-stream tasking: parking one stream does not
   freeze the connection.)
5. **AC-H2.5 (intercept + mutate on h2):** an h2 request parked at the request phase
   can have a header added via `flow.mutate` and the **origin receives the edited
   header**; an h2 flow parked at the **response** phase can have its status changed
   to **418** via `flow.mutate {edits:{status:418}}` and, after `flow.resume`, the
   client receives h2 `:status 418` with the edited body.
6. **AC-H2.6 (kill as RST_STREAM):** `flow.kill {mode:"reset"}` on a parked h2
   stream makes the client observe that **stream** reset (RST_STREAM) while the
   connection stays usable for other streams; `flow.kill {mode:"429"}` delivers h2
   `:status 429` and opens **no** upstream stream (origin records zero requests for
   that flow).
7. **AC-H2.7 (Map Local on h2):** a Map Local mapping for `*/logo.png` → a fixture
   makes an h2 request to `/logo.png` return `:status 200` with a body equal to the
   fixture bytes and **no** upstream stream opened.
8. **AC-H2.8 (Map Remote on h2 is scope-gated):** a Map Remote mapping rewriting
   `old.example` → `new.example` (in scope) causes the h2 request to reach
   `new.example` (opening a second upstream as needed); the same mapping to a target
   **not in scope** is refused by `ScopeRateGuard` and the original is not sent.
9. **AC-H2.9 (hop-by-hop stripped on encode):** forwarding an h2 request/response
   whose model carries an h1-only `Connection`/`Transfer-Encoding` header (e.g.
   injected by `flow.mutate`) produces a **valid** h2 frame (the illegal headers are
   dropped) rather than a `PROTOCOL_ERROR`/dropped stream.
10. **AC-H2.10 (bounded memory):** a client opening more than
    `max_concurrent_streams` streams is held to that bound (excess streams are
    refused/queued by the `h2` settings, not all buffered), and an h2 response body
    over `max_body_bytes` is streamed to the client in full while the **stored copy
    is truncated** and the flow marked `truncated` — matching h1.
11. **AC-H2.11 (session/HAR round-trip):** an h2 flow saved via `session.save` and
    reloaded restores `version == H2`; `flow.export {format:"har"}` records
    `httpVersion` as `"HTTP/2"` for that entry.

## Left to the builder

- Exact `serve_h2` module layout within `aitm-proto-http` (e.g. a new `h2.rs`
  alongside `module.rs`), and whether request/response head translation to/from the
  `http` crate types lives in a shared helper.
- The `h2` and `http` crate patch versions, and the exact `h2::server::Builder` /
  `client::Builder` tuning (initial window sizes, max frame size, max header-list
  size, HPACK table size) within the finite bounds §4 requires.
- The default value of `LimitConfig.max_concurrent_streams` and the header-block
  caps (any safe finite defaults).
- Whether the per-connection upstream `ClientConfig` is rebuilt per connection or a
  small cache of {`[h2,http/1.1]`} vs {`[http/1.1]`} ALPN shapes is kept.
- How trailers are represented when captured (pass-through is the default; a model
  field is out of scope).
- The precise mapping of an h2 connection-level error to `Event::Error` and the
  GOAWAY-drain bookkeeping for in-flight streams.
- Whether Map Remote's second-upstream (different-origin) connection is pooled or
  opened per stream.
- The `HttpVersion::H2` ↔ HAR `httpVersion` / native-session tag strings.

## Open questions

*(Resolved on approval, 2026-10-29 by Matt — approved the spec and directed proceeding to the Stage-3 plan, accepting each recommendation below.)*

1. **h2 ↔ h1 cross-version bridging — resolved: mirror, fail-closed (a).** v1 **mirrors** the version (client gets what
   upstream negotiated), so the only unsatisfiable pair is *h1-only client ↔
   h2-only upstream*, which v1 **fails with a logged error**. Options: (a) accept
   the fail-closed behaviour for v1 (recommended — the pair is already broken
   without a proxy and is vanishingly rare); (b) build the full h2↔h1 translation
   matrix so the proxy can always bridge any pair. **(a)** keeps M7 to one
   translation surface (frames ↔ model); **(b)** is a materially larger, higher-risk
   build. **Recommend (a).** Matt to confirm.
2. **Replay version — resolved: h1 replay (a).** v1 replays an h2 flow over **h1** (the existing
   `Http1Sender`), capturing an h1 replay flow. Options: (a) keep h1 replay for v1
   (recommended — a replay is a fresh request; most origins accept h1; no new
   sender); (b) add an h2 replay path so a replayed h2 flow is re-sent over h2.
   **Recommend (a)**, with (b) as a follow-up if an origin rejects h1 replays. Matt
   to confirm.
3. **Library choice — resolved: the `h2` crate.** The design is built on the **`h2` crate** (+
   `http`), not hand-rolled and not the full `hyper` stack, because it is the vetted
   engine `hyper` itself uses, runs directly over our decrypted `tokio-rustls`
   streams, and exposes per-stream request/response handles that fit the
   intercept/mutate pipeline. Hand-rolling HPACK + flow control + multiplexing would
   be a large, high-risk conformance effort for no control we need; the full `hyper`
   server/client stack would fight the existing `ProtocolModule` seam and the
   sans-IO h1 machine. **Recommend the `h2` crate.** Matt to confirm before the
   dependency lands.
4. **Server push — resolved: disabled both directions.** v1 **disables** push both directions (§5). Confirm this is
   acceptable (recommended), versus capturing pushed streams as flows (a future
   milestone). Matt to confirm.
