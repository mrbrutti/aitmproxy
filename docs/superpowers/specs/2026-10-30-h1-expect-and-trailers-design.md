# HTTP/1 `Expect: 100-continue` and chunked-trailer conformance design

**Status:** approved (2026-10-30, self-approved by the orchestrating session under Matt's standing autonomous-mode instruction; Matt can reverse any Architect's call in the index). Amended 2026-10-30 after the Stage 6 panel: Architect's calls 21 to 28, AC34, AC35 and F9 are new; the two e2e scripts are verified for real against a core built from this branch but are NOT landed by this change (call 27; their owner session lands them test-only after the merge). Base note: the branch is rebased onto `main` plus the re-landed HTTP/1 hardening (PR 133); where the text says `fix/http1-path-hardening` or PR 129 as the base, read `main`.
**Research inputs:** none new in `docs/research/` (`docs/research/MEMORY.md` for the
project facts). The acceptance tests are the two real-traffic e2e scripts
`tests/e2e/proto/test_h1_100_continue.py` and `tests/e2e/proto/test_chunked_trailers.py`
(untracked in the main checkout, `/Users/matt/Security/aitmproxy/tests/e2e/proto/`; another
session owns them and lands them test-only after this change merges, so they are run
against this branch and never added to it, Architect's call 27)
and their baseline run on this branch's head, quoted in the criteria below.
Code read for this spec, at `2884ec0` on `fix/http1-conformance` (cut from
`fix/http1-path-hardening`, PR #129, which is stacked on PR #108):
`crates/aitm-proto-http/src/{module,sansio,sender,h2,translate}.rs`,
`crates/aitm-proto-http/tests/{sansio,sender,http1_hardening,response_park}.rs`,
`crates/aitm-core/src/{flow,header,client}.rs`,
`crates/aitm-plugins/src/{detail,intercept}.rs`,
`crates/aitm-plugin-sessionio/src/{native,har,mitmproxy}.rs`, and the vendored `h2`
0.4.19 `src/server.rs`. Origin of the two defects: the real-traffic e2e suite; the
baseline run fails exactly those two scripts and nothing else in the `proto` cell.

**Amended after the Stage 6 panel (2026-10-30).** The text below was brought in line with
what was built and reviewed. What changed, so a reader of the earlier version can find it:
(1) the two e2e scripts are run for real against this branch but are not added to it (Intent,
Goals, Constraints, Test strategy, AC1, AC13, AC32, calls 19 and 27); (2) two new criteria, AC34
(the flow store charges trailers to its byte budget) and AC35 (a typed `Event::Error` for an
origin response the machine refuses), both appended so no criterion was renumbered; (3)
`crates/aitm-core` is no longer `flow.rs` alone (AC30, Constraints); (4) four deviations the
build made are recorded in "Deviations accepted at review" (calls 21 to 24); (5) the writer
wording of Bug 2 item 5 now follows item 2, the `F4` cross-reference in item 4 is corrected,
and F9 is new. Calls 21 to 28 are the additions to the index.

RFC points this spec leans on, written from memory (no network in the sandbox) and
NOT verified against the RFC text; the Coder and reviewers should check them before
quoting section numbers anywhere durable:

- RFC 9110 section 10.1.1 (Expect): an origin server and a proxy that receive an
  HTTP/1.1 head with a `100-continue` expectation and content to follow MUST NOT wait
  for the content before answering; a server MAY omit the 100 if content has already
  arrived or the framing says there is none; a server MUST ignore the expectation in an
  HTTP/1.0 request; the proxy-specific wording (my recollection of RFC 7231 section
  5.1.1, carried into 9110) says a proxy either answers with a final status or begins
  forwarding the request to the next hop, and MAY generate the 100 itself only when it
  believes the next hop is HTTP/1.0. Comparison of expectation tokens is case-insensitive;
  `Expect` is a list. An unknown expectation MAY be answered 417.
- RFC 9110 section 15.2: a client MUST be able to parse one or more 1xx responses before
  the final response, even when it does not expect one.
- RFC 9112 section 7.1.2 (chunked trailer section grammar): `last-chunk`, then zero or
  more field lines, then a blank line.
- RFC 9110 sections 6.5.1 and 6.5.2: trailer fields ought to be processed and stored
  apart from the header section; a recipient MUST NOT merge a trailer field into the
  header section unless that field's definition permits it; a sender MUST NOT generate a
  trailer field unless the field's definition permits trailers; the categories that
  cannot work as trailers are framing, routing, authentication, request modifiers,
  response controls and payload processing. The brief for this change cites the
  enumerated list at 9110 section 6.5.2; my recollection is that the enumerated list is
  RFC 7230 section 4.1.2 and that 9110 keeps only the categories as prose. Either way
  the concrete deny-set in this spec is OUR expansion of those categories (Architect's
  call 12), not a list the RFC publishes.
- Other servers, from memory: mitmproxy answers a `100-continue` head itself and drops
  the `Expect` header when it forwards, and keeps trailers on a separate attribute of the
  message; Go's HTTP/2 transport honours `Expect: 100-continue`.

## Intent

The real-traffic e2e suite found two HTTP/1 conformance bugs in `serve`
(`crates/aitm-proto-http/src/module.rs`) and the sans-IO machine
(`crates/aitm-proto-http/src/sansio.rs`), the same path as the HTTP/1 hardening change.
First, a client that sends `Expect: 100-continue` and withholds the body until the
server answers stalls: `serve` gathers the whole request body before it forwards
anything and never answers the expectation, so a strict client waits (curl gives up
after 1 s and sends anyway). Second, a chunked response with a trailer section is
decoded correctly but the trailers are consumed and discarded: the proxy forwards
`Trailer: x-checksum-sha256, x-e2e-trailer, server-timing` in the head and then ends the
body with a bare `0\r\n\r\n`, so the declared fields never arrive, and the captured flow
shows no trailers at all. This change answers the expectation at head time, forwards and
captures the trailers, and proves both with the two e2e scripts, run unchanged against a
core built from this branch (the scripts land separately, test-only, after this change
merges, so they are not added here), without changing behaviour for traffic that has
neither an expectation nor trailers and without touching the scope/SSRF guard. It also
keeps the new field inside the flow store's byte budget (AC34) and reports an origin
response the machine refuses, including a bad trailer section, to event consumers as a
typed `Event::Error` (AC35).

## Goals

- A strict client's `Expect: 100-continue` head receives `HTTP/1.1 100 Continue` before
  it sends any body byte, from the proxy, without waiting for the content, over the
  forward-proxy path, a cleartext `CONNECT` tunnel and the TLS MITM h1 path.
- That interim is written exactly once per request, before the body is read and before
  any plugin dispatch that can park the flow. No 1xx ever becomes the stored response,
  reaches the client twice, or leaks into the next exchange on the connection.
- The origin still receives the request exactly as the client sent it (the `Expect`
  header untouched, head and body in one write). An origin's own optional 100 is
  skipped, as today.
- Every trailer field an origin sends after a chunked response body reaches the client
  intact and in order, except fields in the forbidden categories (call 12), which are
  withheld from the wire only.
- The captured flow exposes the trailers separately from the headers, in
  `HttpResponse.trailers` and as `response.trailers` in `flow.detail`, for proxied flows
  and for `request.send` / replay flows. They are never merged into `response.headers`.
- Trailer parsing is bounded (16 KiB, 64 fields) and fails closed.
- Captured trailers count against the flow store's byte budget like headers do, so a hostile
  origin cannot grow the store past it through trailers (AC34).
- A response the machine refuses while it is read from the origin, a malformed or over-cap
  trailer section included, reaches event consumers as one `Event::Error` in fixed words;
  the client still sees the connection end without a terminator (AC35).
- The framing of the next exchange on a keep-alive connection stays exactly right.
- Both e2e scripts, run unchanged against a real core built from this branch, pass (they are
  run, not added to the branch), and every behaviour has a sandbox-runnable unit test.

## Non-goals

- HTTP/2. `serve_h2` is driven by the `h2` crate directly, does no Expect handling and
  drops trailers today (the M7 plan accepted both as follow-ups). Both stay as they are;
  only a one-line field initialiser is forced on `h2.rs` and `translate.rs` (Design,
  Bug 2 item 9). See Adjacent findings F1.
- Request-side trailers: a chunked request with a trailer section is still re-framed
  with `Content-Length` and its trailers are neither forwarded nor captured. See call 15
  for what is lost.
- Generating `417 Expectation Failed` for an unknown expectation (call 5).
- Answering with a final status for any early reason other than a declared body larger
  than the configured cap (call 6).
- Showing trailers in the TUI, web UI or mac app, exposing them to Rhai scripts or
  PoC steps, the passive scanner, HAR export, or the mitmproxy importer. The data is
  there for those follow-ups; none of them reads it yet.
- Editing trailers: no plugin, command or `flow.mutate` surface authors or changes
  `HttpResponse.trailers`. It is a capture field.
- Negotiating on `TE: trailers` (call 13).
- Fixing the suspected terminator bug for HEAD / 204 / 304 responses whose head says
  `Transfer-Encoding: chunked` (Adjacent findings F2).
- Retrying, buffering policy, streaming the request to the origin before the body
  arrives, or any change to when `Event::Request` is emitted.
- Emitting `Event::Error` for a failed first dial or reconnect. That is the hardening spec's
  F4 and it stands; AC35 covers only a machine error while an origin response is read.
- Landing the two e2e scripts in this repository on this branch (Architect's call 27).

## Anti-goals

- Merging a trailer field into `response.headers` on any path (capture, replay, edit,
  re-encode). A hostile origin must not be able to put a framing, routing or
  authentication field into the structure the rest of the system re-encodes and
  analyses as headers.
- A trailer section that lets origin-controlled bytes choose framing, routing or
  authentication state on the client wire.
- Writing the 100 for an HTTP/1.0 request, for a request with no content, for a request
  whose body already arrived with the head, twice for one request, or after the body.
- A trailer parser that buffers or loops without bound.
- Any change to what is stored, rendered or persisted for a flow that has no trailers
  and no expectation: its stored response, its `flow.detail` JSON and its native
  session JSON are byte-identical to today's.
- Loosening the guard. Every upstream dial stays on `ctx.connect_upstream`; no new dial
  path; nothing in `crates/aitm-core/src/{guard,proxy,authority,egress}.rs` changes.
- New dependencies, new crate features, `unsafe`, or new public API beyond the one data
  field the model decision needs and the persistence mirror of it (call 18).
- Logging attacker-controlled bytes: no trailer name or value in any log line, and none in an
  `Event::Error` (its text is fixed, AC35).

## Constraints

- Memory: the trailer capture of one response is bounded at 16 KiB and 64 fields, by the
  same limits that bound parsing. A response with no trailers allocates nothing extra
  (`HeaderMap::new()` is an empty `Vec`). The flow store's resident-byte estimate counts
  them like headers (AC34), because with `max_flows = 0` that estimate is the store's only
  bound.
- No behaviour change for well-behaved traffic: keep-alive reuse, `Content-Length`,
  close-delimited and chunked-without-trailers bodies, HEAD / 204 / 304, the 101 handoff,
  the stale-upstream replacement, the surplus handling, tunnels and the oversized 413
  all behave as today (AC29).
- Sandbox: no port binding. Every red-to-green proof is sandbox-runnable (in-memory
  `DuplexStream` plus the existing `StubConnector` and `RecordingSink`). The loopback
  file and the e2e runs happen only in Matt's Terminal panel.
- Quiet default logs: this change adds one `debug` site (a count of trailer fields not
  forwarded, never a name or value) and no `info`, `warn` or `error` site.
- Rust gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`.
- `unsafe` is forbidden workspace-wide; none is needed.
- Files that change: the two `aitm-proto-http` sources (`module.rs`, `sansio.rs`) and
  their tests; `sender.rs` (tests only); in `aitm-core`, `src/flow.rs` (one field, and the
  `large_enum_variant` allowance of call 21), `src/store.rs` (`flow_size` counts the
  trailers, AC34) and `tests/store.rs` (the AC34 tests; `tests/store_control.rs` gains only a
  test-literal initialiser); `crates/aitm-plugins/src/detail.rs`;
  `crates/aitm-plugin-sessionio/src/native.rs` (and `har.rs`, `mitmproxy.rs` for a comment
  each); one new loopback test file; and, mechanically, every file that builds an
  `HttpResponse` by struct literal (the ripple table below: 35 files in 9 crates when
  counted at `2884ec0`, 42 literals in 36 files on the rebased tree). The two e2e scripts
  are not in this list: they are run against the branch, not added to it (call 27).

## Design

### Bug 1: `Expect: 100-continue`

**What happens today (from reading the source).** `serve`'s request loop
(`module.rs`, "Request: gather head + body") feeds client bytes to the machine and acts
on its events. On `RequestHeaders` it inserts the head-only flow into the store and
emits `Event::RequestHeaders`; body chunks accumulate in a local buffer; nothing is
written to the client until the whole request is complete, the plugin chain has run
(`Event::Request`) and the origin has answered. The machine never looks at `Expect`.
A client that waits for `100 Continue` therefore waits until its own patience runs out
(curl: 1 s), or until `READ_TIMEOUT` (30 s) drops the connection. The e2e baseline shows
exactly this: "nothing arrived in 2.005s", the strict flow's `duration_ms` is 2009, and
every other check of the script already passes (the final `302`, keep-alive, the capture
facts, the origin seeing the body exactly once, the eager client in a tunnel).

The machine records every accepted request as `HttpVersion::Http11`, even when the
request line says `HTTP/1.0` (`parse_request` collapses it), so the version token must
be read at parse time to honour "never for HTTP/1.0".

**Decision: the machine decides, `serve` writes, at head time (Architect's call 1, 3, 8).**
`Http1Machine` computes, when it parses a request head, whether an unanswered
`100-continue` expectation is pending, and exposes two crate-private methods:
`expects_continue(&self) -> bool` and `enqueue_continue(&mut self)`. The second queues
the 25 bytes `HTTP/1.1 100 Continue\r\n\r\n` for the client and clears the pending flag,
so a second call queues nothing: "exactly once" is enforced in the machine, not by
`serve`'s discipline. No new `HttpSansIoEvent` variant is added (it would break every
exhaustive `match` and the `PartialEq` derive for no gain), and no new public API.

A deliberate, stated deviation from the proxy-specific RFC wording (as I recall it, see the
list above): a proxy should either answer with a final status or begin forwarding the request
to the next hop, and may generate the 100 itself only for an HTTP/1.0 next hop. This proxy
cannot begin forwarding before the body arrives, by design: `Event::Request`, the plugin chain,
interception and mutation all need the complete request, and the origin is dialled only after
that. So it generates the 100 itself, as the acceptance script requires ("an immediate 100 or a
final status, never waiting for the content") and as other buffering proxies do (mitmproxy, from
memory). The consequence is the one the RFC warns about and the origin-forwarding rule below
covers: the origin may later see an `Expect` whose 100 the proxy already gave.

The expectation is pending iff all of these hold at the moment the head is parsed:

1. the request line's version token is not `HTTP/1.0` (every other accepted `HTTP/1.x`
   counts as 1.1 or later; the machine already rejects non-`HTTP/1.` versions);
2. some `Expect` field line, split on commas, has a member that equals `100-continue`
   after trimming, ASCII case-insensitively (the field may repeat and may be a list;
   `foo, 100-Continue` and two `Expect` lines both match; `100-continue-ish` and
   `100-continue;x=1` do not);
3. the framing says content follows: `Content-Length` greater than 0, or chunked (a
   `Content-Length: 0` or an absent length is "no content": RFC allows omitting the 100);
4. no content byte was buffered with the head (`client.buf` is empty after the head is
   taken). If any content already arrived the 100 is pointless (RFC: MAY omit), so the
   eager client (head and body in one write, as curl sends after its patience runs out)
   gets none. A 100 sent anyway because TCP happened to split head and body is harmless
   (RFC 9110 15.2: clients parse unexpected 1xx), so the rule needs no timing logic.

**Where it is written, and why before the dispatch (Architect's call 1).** In
`serve`'s `RequestHeaders` arm: insert the flow, then, if `expects_continue()`,
`enqueue_continue()` and flush, then `ctx.emit(Event::RequestHeaders(id))`. The order
insert, write, emit matters:

| Option | Effect | Verdict |
|---|---|---|
| write after `emit(RequestHeaders)` | A plugin that parks the flow at `RequestHeaders` (any plugin may call `FlowCtx::intercept()` there; the built-in intercept plugin parks at `Event::Request` and `Event::ResponseHeaders`, not here) leaves a strict client waiting for as long as the park lasts, with no timeout on the park | rejected |
| write before the flow is inserted | Same effect for the client; the head-only flow is invisible to `flow.table` for a few microseconds longer. No gain | rejected |
| insert, write, emit | The client is unblocked before any plugin runs, and the head-only flow is already in the store by the time the client sees the 100 | chosen |

Plugin kill and short-circuit can never precede the 100, and need not: `serve` acts on
a plugin's kill, short-circuit or edit only after `Event::Request`, which needs the
complete body; the built-in intercept parks at that same point. So a flow parked for
review has already been told to continue, has already sent its body, and waits for its
final response, which is what a breakpoint means. A kill after the 100 drops the
connection (the client sees `100` then a close), the same observable result as a kill
without it. `serve` discards the verdict of `emit(Event::RequestHeaders)`, so a kill or a
park at that event has no effect until `Event::Request`, after the whole body; a client
already told to continue therefore uploads up to `max_body` (10 MiB by default) first.
The scope guard behaves the same way: it runs at dial time, after the body, so a client
aimed at a blocked authority is also told to continue before it is refused (noted by the
Stage 5 tester). An eager client, which sends its body unasked, has always behaved so.

A failed write of the interim means the client went away: `serve` returns `Ok(())`
quietly, like the existing "client finished mid-request" exit, instead of an error that
the accept loop would log (call 2).

**What is forwarded upstream: `Expect` untouched (Architect's call 4).** `serve`
buffers the whole request (the plugin chain needs it complete), then writes head and
body to the origin in one `write_all`. The `Expect` header is forwarded exactly as the
client sent it (and as a plugin left it). Reasons: (1) fidelity: this is a security
testing proxy, an origin's reaction to `Expect` (including a `417`) is evidence, and the
only header rewrites the proxy does today exist for framing correctness; (2) RFC 9110
10.1.1 tells an intermediary to forward the expectation, not to consume it; (3) the
origin gets head and body together, so an origin that honours the expectation sees the
content already there (RFC: it MAY omit the 100) and one that sends a 100 anyway sends
an interim the machine already skips. The cost: an origin that answers every `Expect`
with `417` will `417` even though the proxy satisfied the client's expectation. That is
the origin's real behaviour, faithfully forwarded; mitmproxy's strip-on-forward would
hide it. Stripping is a one-line follow-up if Matt prefers robustness to fidelity.

The e2e script's capture check needs the stored request to keep `expect: 100-continue`.
It does, under either choice, because the store holds the request as received; forwarding
untouched also keeps the bytes the origin saw equal to the stored request.

**The origin's own 100 cannot desynchronise the connection (confirmed by reading
`on_server_bytes`).** The server reader parses heads in a loop; a non-101 `1xx` head is
consumed by `take_head` and skipped (`continue`), leaving the reader in `Phase::Head`
and the client reader in `Phase::Waiting`; the next head, in the same read or a later
one, is the final response and is parsed normally. The request is already fully
written, so the client reader is `Waiting` and the previous change's guard (parse a head
only while a request awaits one) admits the interim. Several interims in a row are
skipped the same way. A `100` that carries a body, or arrives after the final response,
is not skipped: the former fails as a malformed head, the latter is surplus and taints
the upstream (the hardening change's rules, unchanged). No `ResponseHeaders` or
`Response` event is produced for an interim, so the store never holds one. The proxy's
own 100 is the only 1xx the client receives.

**CONNECT tunnels (Architect's call 1).** Cleartext tunnels and the TLS MITM h1 path
both run `serve`, with `client` the plain or TLS stream to the client, so both get the
same behaviour with no extra code. The `CONNECT` request itself is parsed in `drive`
before `serve` and has no content.

**Unknown expectations (Architect's call 5).** Left as today: no interim, no `417` from
us, the head is forwarded after the body, the origin answers. RFC lets a server answer
`417` (a MAY); the proxy has no business deciding which expectations an origin can meet.
A list such as `100-continue, foo` gets the 100 for the member the proxy understands and
is forwarded untouched, so the origin may still `417` it. Residual, stated plainly: a
client that withholds its body for an unknown expectation waits until its own patience
or `READ_TIMEOUT` (30 s, then the connection is dropped). Answering `417` early would fix
that; it is not done.

**The oversized body (Architect's call 6): included, because it is the reason Expect
exists and it is about six lines.** When an expectation is pending and the head declares
a `Content-Length` larger than the configured cap (`max_body`), `serve` sets
`request_oversized` instead of writing the 100. It reads that declared length with the
machine's own `content_length` parser (`sansio::content_length`, made crate-visible;
Architect's call 24), so the early refusal and the framing the machine applies cannot
disagree. The existing oversize branch then writes
the `413` and closes, and the strict client, which never sent a byte of content, never
uploads it. Chunked uploads declare no length and cannot be refused early; they get the
100 and the existing cap enforcement as the body arrives. A request WITHOUT a pending
expectation is untouched: it is still read until the cap, then refused. Known limit: the
413 is written by the existing branch, after the `RequestHeaders` dispatch returns, so a
plugin that parks `RequestHeaders` delays it; the 100 path has no such dependency.

**The reissue sender (confirmed, no production change).** `request.send` and
`flow.replay` run `Http1Sender::send`, whose `drive` primes the machine with the whole
request (head and `Content-Length` body in one buffer, so no expectation is pending),
queues the request with `enqueue_request`, writes head and body in one write and reads.
A captured flow's `Expect` header is kept (`prepare` drops only `Host` and `Connection`).
If the origin sends `100 Continue` before the final response the machine skips it, so
the returned `HttpResponse` is the final one. `drive` never writes to a client, so
`enqueue_continue` is never called there. Pinned by a characterization test (AC11).

**HTTP/2 (Architect's call 7, correcting the brief).** Out of scope, but not because
"hyper/h2 handle it": `serve_h2` drives the `h2` crate directly (no hyper), reads the
whole request body in `stream_task` / `drive_stream`, and has no Expect handling. The
stall therefore exists on h2 for clients that wait for a 100 (Go's h2 transport does;
curl does not use Expect on h2). The vendored `h2` 0.4.19 has
`SendResponse::send_informational`, so the follow-up is small. See F1.

**Capture facts.** The stored request keeps the `expect` header and the full body; the
stored response is the final status; no 1xx is stored; `server_conn`, `duration_ms` and
`intercept=observed` are as today. The e2e script checks all of these and they already
pass; the change must keep them passing.

### Bug 2: chunked response trailers

**What happens today (from reading the source).** `step_chunked`'s `ChunkPhase::Trailers`
arm loops `take_line(buf, MAX_HEAD_BYTES)` and drops each line ("Trailer fields are
consumed and dropped") until the blank line. Two corrections to the brief follow from
that code: the per-line cap in this phase is `MAX_HEAD_BYTES` (64 KiB), not
`MAX_CHUNK_LINE_BYTES` (1 KiB, which applies only to chunk-size lines), and nothing caps
the NUMBER of lines, so a hostile origin or client can make the machine consume trailer
lines for as long as it keeps sending them (no memory growth, since each line is dropped,
but no bound on work). The forwarded head carries `Trailer: ...` verbatim, but
`Http1Machine::enqueue_body_end`, the only writer `serve` uses for the end of a chunked
body, always writes the fixed `0\r\n\r\n`, so declared fields are dropped on the wire. The stored response has no place
for them: `HttpResponse` has `status`, `version`, `headers`, `body`, `timestamp`, and
`flow.detail` renders `body`, `body_size`, `body_truncated`, `headers`, `status`,
`version`. The reissue path (`Http1Sender::drive`) drives the same machine and returns
`..head`, so it loses the trailers at the same point.

**1. Where trailers live: a separate field, `HttpResponse.trailers: HeaderMap`
(Architect's call 9).**

| Option | For | Against | Verdict |
|---|---|---|---|
| Merge into `response.headers` | Zero ripple; visible everywhere | RFC 9110 6.5.1 forbids merging unless the field's definition permits it. `encode_message` re-encodes `headers` (a merged `Content-Length` or `Transfer-Encoding` from a hostile origin lands in any re-encode: a plugin-edited response at `ResponseHeaders`, a short-circuit); `flow.mutate` and the passive scanner treat `headers` as the head the client saw, so a trailing `Set-Cookie` or `Content-Security-Policy` would feed findings the browser never evaluated; HAR export would present trailers as headers; operators could not tell the two apart | rejected |
| `FlowMeta` field | About one literal site (`native.rs`'s full `FlowMeta` literal; the rest use `..Default::default()`) | Not bookkeeping; and `RequestSender::send` returns `HttpResponse`, so the replay path (required outcome b) would need the trait's return type changed instead, which ripples into the real sender and the test stub implementations in `aitm-plugins`, `aitm-findings` and `aitm-poc`, so nothing is saved | rejected |
| Side table keyed by `FlowId` in `FlowStore` | No struct change | New trait method on every `FlowStore` implementation; trailers detached from the response they belong to | rejected |
| `HttpResponse.trailers: HeaderMap` | Travels with the response through the store, the replay path, plugins and persistence; `HeaderMap` already validates names and values and keeps order and duplicates; mitmproxy (from memory) also keeps trailers on the message, apart from headers | The struct-literal ripple below | chosen |

`HttpResponse` has no serde derive (`aitm-core` is deliberately serde-free; the session
format uses a mirror in `aitm-plugin-sessionio`), so the brief's
`#[serde(default, skip_serializing_if = ...)]` belongs on that mirror, not on the model.

**The ripple, counted.** Adding a public field to `HttpResponse` breaks every struct
literal that does not use struct-update syntax. A grep for `HttpResponse {` (function
signatures aside) finds 44 lines at `2884ec0`: one is `impl ResponseBytes for HttpResponse`
in `maprules/tests/map_local.rs` (not a construction), 3 use struct-update syntax and
compile unchanged, and 40 need the new field:

| Class | Sites | Where |
|---|---|---|
| Literal that needs `trailers: HeaderMap::new()` | 40, in 35 files, in 9 crates | below |
| Literal that uses `..head` / `..` (compiles unchanged) | 3 | `h2.rs:524`, `module.rs:850`, `sender.rs:298` |
| Destructuring patterns that would break | 0 | none found |

Of the 40, 10 are production code (`sansio.rs:674` `parse_response`; `translate.rs:79`;
`h2.rs:416`; `module.rs:1059` `oversized_response`; `intercept.rs:434` synthetic abort
response; `maprules/src/lib.rs:430`; `rhai/src/flow_state.rs:185` script-built response;
`sessionio` `native.rs:259`, `har.rs:268`, `mitmproxy.rs:229`), 3 are inside in-file
`#[cfg(test)]` modules (`sansio.rs:1048`, `translate.rs:206`, `scanner/src/passive.rs:236`)
and 27 are in `tests/` directories. Per crate: `aitm-core` 2 (both tests), `aitm-findings`
1 (test), `aitm-plugin-maprules` 1, `aitm-plugin-rhai` 7, `aitm-plugin-scanner` 1,
`aitm-plugin-sessionio` 6, `aitm-plugins` 9, `aitm-poc` 6 (all tests), `aitm-proto-http`
7. Every edit is one line and compiler-guided, and none changes behaviour. The
consumers that need a decision rather than a line are listed in the next paragraph.
These figures are as counted at `2884ec0`. On the rebased tree (base `4eb6cb5`) the sweep
counted 42 literals in 36 files in the same 9 crates; the two extra literals are in
`aitm-plugin-scanner/src/inject.rs`.

Consumers of the response model, and what each does with the new field:

- `flow.detail` renderer: `crates/aitm-plugins/src/detail.rs` (the brief said
  `crates/aitm`; the renderer is not there). It renders the field (item 7).
- Native session save and load (`aitm-plugin-sessionio` `native.rs`): carried (item 7).
- HAR export (HAR 1.2 has no trailers field) and the mitmproxy importer: the field is
  empty on import and not written on export. A documented drop, not a silent one.
- `flow.mutate` (`aitm-plugins/src/mutate.rs`), the Rhai `flow_state` view and write-back,
  Rhai `http.send`'s result map (`host_net.rs`), the passive scanner, `aitm-poc`:
  none reads or writes trailers; they keep working on `headers` and `body`. Exposing
  trailers to scripts and the scanner is a follow-up.
- TUI, web UI, mac app: JSON consumers of `flow.detail`. The TUI (`model.rs`) and the web
  client (`bus/normalize.ts`) read named keys from an untyped record and ignore the rest;
  the mac app decodes with Swift `Codable`, which ignores unknown keys by default
  (`FlowDetailWireTests.swift` is the test to re-run; the Tester confirms). The only
  `deny_unknown_fields` in the Rust tree are on config structs. None of them displays
  trailers yet.
- There is no descriptor crate in the tree to update.

**Matt should be told before this is built.** The change itself is mechanical, additive and
behaviour-neutral, but it touches 35 files in 9 crates (36 on the rebased tree) outside the crate this change is
about, and any parallel branch that adds an `HttpResponse { ... }` literal will fail to
compile after a merge until it adds one line. The plan isolates the sweep as one early
commit (Task 3) so it can be split into its own PR on request.

**2. Capture everything the origin sent; withhold the forbidden categories from the wire
only (Architect's call 11, 12).** The captured `trailers` hold every field the origin
sent, in wire order with duplicates kept, within the caps (item 4). Operators want the
evidence: a hostile origin sending `Content-Length: 0` as a trailer is a finding, and the
e2e script's own premise is that discarding what the origin sent is not capturing. The
capture is inert (no code path writes it to a wire), so keeping the forbidden fields in
it is safe. The wire is different: the writer (`enqueue_body_end_with_trailers`) owns the
policy and skips every field whose name is in the deny-set, matched ASCII
case-insensitively as a whole name. It also re-checks the name and value are valid; they
always are, because the `HeaderMap` only accepts pairs through `try_set` / `set`, which
validate (see item 5), so this is defence in depth, as `header.rs` documents.

The deny-set (37 names). Categories are RFC 9110 section 6.5.1's; the enumerated names
are our expansion, taken from the field groups RFC 7231 / 9110 define for each category:

| Category | Names withheld from the wire |
|---|---|
| Message framing | `transfer-encoding`, `content-length` |
| Routing | `host` |
| Request modifiers (controls and conditionals) | `cache-control`, `expect`, `max-forwards`, `pragma`, `range`, `te`, `if-match`, `if-none-match`, `if-modified-since`, `if-unmodified-since`, `if-range` |
| Authentication | `authorization`, `proxy-authorization`, `www-authenticate`, `proxy-authenticate`, `authentication-info`, `proxy-authentication-info`, `cookie`, `set-cookie` |
| Response control data | `age`, `date`, `expires`, `location`, `retry-after`, `vary`, `warning` (and `cache-control`, already above) |
| Payload processing | `content-encoding`, `content-type`, `content-range`, `trailer` |
| Connection management (hop-by-hop; meaningless after the body) | `connection`, `keep-alive`, `proxy-connection`, `upgrade` |

It is a deny-list, not an allow-list, because the fields whose definitions permit trailers
are open-ended (`x-*`, `server-timing`, `digest`, `content-digest`, ...) and a proxy cannot
maintain that list. Residual risk, stated: a field outside the list whose semantics need
header-time evaluation passes through. It reaches a client that must, per RFC, process
trailers separately from headers, so it cannot change the framing, routing or
authentication the client already decided. A client that wrongly treats trailers as headers
is not covered by that argument; F9 names the fields it could still be reached by, an
accepted residual (call 28). The set lives in one `const` in `sansio.rs`.
The count of withheld fields is returned to `serve`, which logs it once at `debug`,
never a name or value (Constraints).

**3. When trailers are forwarded: whenever the response is chunk-forwarded, not only for
`TE: trailers` clients (Architect's call 13).** `serve` forwards the origin's trailers
when it frames the client-bound body as chunked (`forward_chunks` and the machine's
`OutFraming::Chunked`). It does not consult the client's `TE`. Reasons: (a) it keeps the
wire truthful with the least machinery. The head already forwarded the origin's `Trailer:`
header; forwarding the fields it announced makes that header true, whereas "only with
`TE: trailers`" would need the already-written `Trailer:` header rewritten or stripped for
other clients, which is exactly the framing lie the e2e script flags, produced the other
way round. (b) Every HTTP/1.1 chunked decoder must parse the trailer section to find the
end of the message, and RFC 9110 6.5.1 only says a server SHOULD NOT generate trailers it
considers essential when the client did not send `TE: trailers`; an intermediary
forwarding what the origin sent is not generating them. (c) The request's `TE` and
`Connection: TE` are already forwarded to the origin untouched (the e2e log confirms the
origin sees `TE: trailers`), so an origin that respects `TE` already decided. The
declared-but-withheld case (an origin that lists a forbidden field in `Trailer:`) is the
origin's own protocol violation and `Trailer:` is a hint, not a promise.
Not forwarded, by construction: a response whose body a plugin replaced (framed with
`Content-Length`, `forward_chunks` false), `Content-Length` and close-delimited
responses, and HEAD / 204 / 304 (no trailer section exists).

**4. Bounds (Architect's call 14).** One accumulator per reader holds the parsed fields
and the bytes consumed. The section is capped at `MAX_TRAILER_BYTES = 16 * 1024` (the sum
of every field line's length plus its CRLF, the terminating blank line not counted) and
`MAX_TRAILER_FIELDS = 64`. Crossing either, or an unterminated partial line longer than
the byte cap, makes `on_bytes` return `Err`, exactly as a head over its cap does. The
numbers: real trailers are digests, timings and signatures of tens to a few hundred
bytes; Apache's default limits (from memory) are 100 fields and 8 KiB per line; 16 KiB and 64 are
generous for any legitimate use and a quarter of the 64 KiB head cap. The capture is
bounded by the same limits, so no separate capture cap exists. What `serve` does with the
`Err`: it first emits `Event::Error { flow, kind: FlowError::Upstream("malformed response
from upstream") }` for the flow (AC35; fixed words, never the machine's error text and never
a trailer byte, because the machine's own text can quote the origin), then returns the
machine's error, the connection ends, the client has received the
body chunks but never the terminator, so it sees an incomplete chunked message, which
is the honest signal, never a `0\r\n\r\n` that claims success. If the head, the body and the
over-cap section all arrive in ONE read, `on_bytes` returns `Err` for that whole read, so the
events built in it are dropped and the client receives nothing before the close; that is
fail-closed too, and the `Event::Error` is emitted the same way. Event consumers (the
scanner, findings, Rhai hooks) learn of a response only through events, so without that
event a refused response was invisible to them. The error event closes the response-parse
half of the gap this spec first attributed to "F4 of the hardening spec"; that F4's own text
covers only a failed first dial or reconnect, which still emits no `Event::Error` and still
stands (a non-goal here).

Field syntax uses the same rules as heads: the accumulator calls one helper extracted
from `parse_headers` (name is a token, no whitespace, value has no control byte, through
`HeaderMap::try_set`; invalid is an error, never a silent drop, because the head code's
own comment explains dropping can desynchronise). The section is UTF-8 like a head. A
trailer line that starts with SP or HT (obs-fold) is rejected, which RFC 9112 5.2 lets a
proxy do. Heads keep their exact current behaviour.

**5. Writing: CRLF injection is impossible by construction.** The terminator for a
chunk-framed body becomes `0\r\n`, then `name: value\r\n` for each field not in the
deny-set, then `\r\n`. With no fields it is the same `0\r\n\r\n` as today, byte for byte.
Header names and values reach the `HeaderMap` only through `try_set` (the parser) or
`set` (which calls it and drops an invalid pair); the map's storage is private. So a
stored name or value cannot contain CR, LF, NUL or any control byte, and a name is a
token. `encode_message` does not re-validate headers as it writes them (it relies on that
invariant, although `header.rs` calls the encoder a last line of defence); the trailer
writer does not copy that: it follows item 2, re-checking every name and value on write
(defence in depth) and applying the deny filter. A test pins that a trailer
value with a control byte fails the parse.

**6. The machine API and event shape (Architect's call 10): no new event, no change to
`Event`, the plugin API or any signature; trailers ride on the machine's own response
model.** When the server reader finishes a chunked body, the machine moves the parsed
fields into its current `HttpResponse.trailers` (the one `Http1Machine::response()`
returns) just before it produces `ResponseComplete`. The events a chunked response yields
are therefore unchanged (`ResponseHeaders`, `ResponseBodyChunk`..., `ResponseComplete`),
so every existing test that asserts an exact event vector keeps passing, and the model
type `HeaderMap` (which has no `PartialEq`, so could not sit in the `PartialEq` event enum
anyway) is not forced into the enum. `serve` reads `machine.response()` at
`ResponseComplete`; `Http1Sender::drive` already returns `..head` from `machine.response()`,
so the reissue path gets the trailers with no production change. A new crate-private
`enqueue_body_end_with_trailers(&mut self, to: Side, trailers: &HeaderMap) -> usize`
writes the terminator and returns how many fields it did not write (denied, or all of
them when the body is not chunk-framed); the existing public `enqueue_body_end(to)` calls
it with an empty map and keeps its signature and behaviour. Decision rejected: a
`ResponseTrailers` event before `ResponseComplete` (public enum change, forces
`Vec<(String, String)>` payloads, adds an arm to every `match`), and trailers on
`ResponseComplete` (changes a variant every test destructures).

**7. Plugins, the bus and persistence.**

- Event ordering for plugins. `ResponseHeaders` arrives first (the store holds the head,
  `trailers` empty, body `Streamed`; `serve` clears `trailers` on the stored head in the
  `ResponseHeaders` arm, because a whole response that arrives in one read has already
  parsed its trailer section into the machine's `response()` by the time that event is
  handled, and without the clearing a plugin would see trailers before `Event::Response`.
  Architect's call 22); body chunks stream; at `ResponseComplete` `serve`
  writes the terminator, then updates the stored response (body, `trailers`, truncation,
  duration), then emits `Event::Response`. A plugin therefore sees the trailers in the
  stored flow from `Event::Response` on. There is no event for them mid-stream and the
  plugin API is unchanged. A plugin cannot influence the forwarded trailers: edits at
  `Event::Response` come after the wire write, and `serve` overwrites the stored response's
  `trailers` with the origin's at completion. A response a plugin answered itself
  (short-circuit, Map Local) is fully buffered and `Content-Length` framed, so its
  `trailers` are never written.
- A plugin that replaced the streamed body at `ResponseHeaders` gets no origin trailers on
  the wire (`forward_chunks` is false; the replacement is `Content-Length` framed). The
  capture still holds the origin's trailers, consistent with how the capture already holds
  the origin's body in that case.
- Store accounting (Architect's call 25). The flow store's `flow_size` charges a response's
  `trailers` like its `headers` (AC34). Trailers arrive on a store `update`, so the update's
  size delta counts them and can trigger byte eviction. This matters because a store with
  `max_flows = 0` has the byte budget as its only bound, and a hostile origin can attach up
  to 16 KiB and 64 fields to every response; uncounted, those would grow the store without
  limit.
- `flow.detail`: `response.trailers` is an array of `[name, value]` pairs in wire order,
  the same shape as `headers`, present only when the response has at least one captured
  trailer (Architect's call 17). A response without trailers renders exactly today's six
  keys (`body`, `body_size`, `body_truncated`, `headers`, `status`, `version`). This
  satisfies the e2e script, which accepts a `response.trailers` list of pairs. The
  `request.send` flow is stored from the `HttpResponse` the sender returns, so it renders
  the same way.
- Native sessions (`RespRec`): a `trailers: Vec<(String, String)>` field with
  `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so a flow without trailers
  serialises byte-identically and an old document loads with none. Without it a saved and
  reloaded session would silently lose exactly the evidence this change adds (Architect's
  call 18; it is the first thing to cut if Matt wants a smaller change, and the schema tag
  `aitm-session/1` needs no bump for an additive optional field).

**8. Request-side trailers: a non-goal (Architect's call 15).** The same `step_chunked`
parses a chunked REQUEST's trailer section. Today a request's trailer lines are dropped
and the request is re-framed with `Content-Length`; that stays. What is lost, stated
plainly: a client that depends on request trailers (for example S3-style signed streaming
uploads with a trailing checksum, or gRPC-style end markers) has them dropped on the way
to the origin, and the capture shows none, as today. Making request trailers work needs
`HttpRequest.trailers` (about 57 struct-literal lines against 40 here), a forwarding rule for
re-framing, and a decision about conflicts with `Content-Length`; nothing consumes them
today. Because the parser is shared, the caps and the field-syntax check now also apply to
request trailer sections, a tightening for a hostile client only; well-formed request
trailers are accepted and dropped as before.

**9. h2 (Architect's call 16).** The model change forces exactly one thing on h2: a
`trailers: HeaderMap::new()` in the response literal at `h2.rs:416` and in
`translate.rs`'s `response_from_h2` (plus the `translate.rs` test literal). Nothing else in
`h2.rs` or `translate.rs` changes. h2 continues to drop trailers (the M7 plan's accepted
follow-up), `h2_response_from` ignores the field, and h2 flows have empty `trailers`.

**10. Unchanged cases.** `Content-Length`, close-delimited, HEAD / 204 / 304 and 101
responses have no trailer section and produce no trailers. A chunked response with no
trailer fields ends with exactly `0\r\n\r\n` as before.

### Test strategy (red to green)

Every behaviour gets sandbox-runnable unit tests (in-memory streams) that carry the
red/green evidence; a loopback file and the two e2e scripts corroborate in the Terminal
panel. The e2e scripts are run, not committed (call 27).

- Bug 1: the machine matrix (in-file `sansio.rs` tests, since the methods are
  crate-private) is written first against stub methods so it compiles and fails
  behaviourally. The `serve` tests use the existing helpers (`ctx_with`, `ctx_recording`,
  `client_send_keep`, `tunnel_conn`, `cleartext_tunnel_conn`, `capture_events`) plus a
  few test-only ones: an origin that records the raw request bytes and replies in
  segments, a sink that parks `Event::RequestHeaders` on a `tokio::sync::Notify`, and a
  head reader that returns `None` after a bound. Red today: the client's wait for the
  100 times out.
- Bug 2: the model field comes first (after Bug 1) as a mechanical sweep proved by `cargo check
  --workspace --all-targets`. The machine tests (`tests/sansio.rs`) assert on
  `response().trailers` through the public API; the sender tests drive `drive` over a
  `DuplexStream` in an in-file module in `sender.rs`; the writer and deny-set are tested
  in-file in `sansio.rs`; `serve` is tested for the exact forwarded bytes, the store, the
  keep-alive follow-up, the logs and the typed `Event::Error` of a refused response
  (AC35); the store's byte accounting is tested in `aitm-core`'s `tests/store.rs`
  (AC34). Red today: empty `trailers`, a bare `0\r\n\r\n`.
- Loopback (`tests/h1_conformance.rs`, Terminal panel only): a strict client over real
  sockets, a cleartext tunnel with an eager client, trailers end to end, and the cap.
- E2E (Terminal panel only): the two scripts, run unchanged and for real against a core
  built from this branch, with the e2e fanout harness (`run_all.py --boot`, with
  `--no-build`, and `AITM_BIN` / `AITM_TESTTARGET_BIN` pointing at the `aitm` and
  `aitm-testtarget` binaries built from this worktree). The scripts and the harness
  stay outside the branch; the evidence is the runner's exit status and its
  per-script `PASS` lines. They land, test-only, in the owning session's PR after this
  change merges.

## Acceptance criteria

Bug 1: `Expect: 100-continue`

1. AC1 (e2e): `tests/e2e/proto/test_h1_100_continue.py`, run unchanged and for real against a
   core built from this branch (the plan's Task 9: the fanout harness, `--boot --no-build`,
   with `AITM_BIN` and `AITM_TESTTARGET_BIN` set; the script is not added to the branch),
   exits 0: the runner prints `PASS proto/test_h1_100_continue.py` and the script's output
   has no `[FAIL]` line. The exit status is the proof; the lines quoted next are what the
   script prints when its output is shown (the runner itself prints only `PASS` or `FAIL`
   per script). The baseline's single defect, "the proxy answered the 100-continue expectation within 2.0s
   (nothing arrived in 2.005s; ...)", becomes a passing line reading "the proxy answered
   `HTTP/1.1 100 Continue` N ms after the head, before any body byte was sent" with N well
   below 2000, and the verdict line is "Expect: 100-continue handled and captured correctly
   (strict + eager, N-byte bodies)". Every other check in the baseline output keeps passing,
   in particular "strict: final status 302 Found -> /comments", "no 1xx leaked into the next
   exchange on the connection (interims=[])", "eager: at most one interim and only a 100",
   the store checks ("captured response status is the FINAL 302, never the interim 100",
   "the client's `expect: 100-continue` header is in the captured request") and "origin lists
   the strict upload's comment exactly once".
2. AC2: `serve`, given a head with `Expect: 100-continue` and `Content-Length: 5` and no
   body, writes exactly `HTTP/1.1 100 Continue\r\n\r\n` (25 bytes) to the client before any
   body byte is sent; after the client then sends `hello` the client reads the origin's final
   response `HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok` and nothing else
   (`serve_answers_a_100_continue_expectation_before_the_body_arrives`).
3. AC3: The interim is written once. With the body arriving in two writes the client reads
   exactly one `100 Continue` in total; at machine level `enqueue_continue` queues the 25
   bytes once and a second call queues nothing, and a following request without `Expect` has
   no pending expectation.
4. AC4: The interim reaches the client while `Event::RequestHeaders` is still parked in a
   plugin: with a sink whose `emit(Event::RequestHeaders)` waits on a `Notify` the test fires
   only after reading the 100, the client reads the 100 before the notify fires
   (`serve_sends_the_interim_before_the_request_headers_event_returns`).
5. AC5: No interim is written, and the request completes normally, when (a) the body arrived
   with the head, (b) the request line says `HTTP/1.0`, (c) the head declares `Content-Length:
   0` or no length, (d) `Expect` has no `100-continue` member (`Expect: bogus` is forwarded
   to the origin untouched, a `417` from the origin reaches the client as sent, and the proxy
   generates none).
6. AC6: `Expect: 100-Continue`, `expect: foo, 100-continue` and two field lines (`Expect: foo`
   then `Expect: 100-continue`) each get the 100; `Expect: 100-continue-ish` and
   `Expect: 100-continue;x=1` do not.
7. AC7: The origin receives the request with its `Expect` header unchanged and the whole body,
   in one write: `POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello`
   (the machine re-appends `Content-Length` last, as for any buffered body). When the origin
   answers `HTTP/1.1 100 Continue\r\n\r\n` followed by `HTTP/1.1 302 Found\r\nLocation:
   /c\r\nContent-Length: 0\r\n\r\n`, in one write and, separately, in two writes, the client
   reads exactly one 100 (the proxy's) then the 302; the recording sink saw exactly one
   `ResponseHeaders`, one `Response` and no `Error`; and the next request on the same client
   connection gets its plain answer with no byte left over.
8. AC8: The stored flow keeps the request header `expect: 100-continue` and the full request
   body, and its response is status 302 with no 1xx stored.
9. AC9: With the cap set to 4 bytes, a head with `Expect: 100-continue` and `Content-Length: 10`
   gets a `413` as its first and only response (no 100), the client never sends the body, the
   connection is closed, the stored flow has `truncated` set, and nothing is dialled. The same
   request without `Expect`, whose client sends its 10 bytes, is still refused with the same
   `413` after the cap is crossed (unchanged).
10. AC10: The interim is also written in a TLS-MITM-shaped connection (`tunnel_conn()` with an
    already handshaken upstream) and in a cleartext `CONNECT` tunnel
    (`cleartext_tunnel_conn`), both through `serve`.
11. AC11: `Http1Sender`'s `drive` over a `DuplexStream`, given a request that carries `Expect:
    100-continue` and a body, writes head and body together (the origin reads both without
    having sent a 100) and, when the origin answers `100 Continue` then `302 Found`, returns
    status 302, headers `Location: /c`, and no 1xx anywhere (a characterization test that
    passes before and after).
12. AC12: At machine level (`expects_continue`): HTTP/1.1 + `Expect: 100-continue` +
    `Content-Length: 5` + no body is true; the same with `hello` in the same call is false;
    the same on `HTTP/1.0` is false; `Content-Length: 0` and no length are false; chunked with
    no body bytes is true and with a chunk is false; an unrelated expectation is false; the
    events for each of these requests are the same as for the request without `Expect`.

Bug 2: chunked trailers

13. AC13 (e2e): `tests/e2e/proto/test_chunked_trailers.py`, run the same way (unchanged, against
    a core built from this branch, not added to it), exits 0: the runner prints `PASS
    proto/test_chunked_trailers.py` and the script's output has no `[!!]` line and no `[FAIL]`
    line. The exit status is the proof, as for AC1. The baseline's 21 problem lines (3 declared-but-dropped and
    3 not-forwarded for each of responses 1 and 3, and 3 not-visible-over-the-bus for each of
    the `first`, `again` and `send` flows) all disappear: the last check reads "trailer
    fidelity: every trailer field the origin sent reaches the client intact and is visible over
    the bus (0 problem(s))". Every other check keeps passing, in particular the
    exact-consumption checks ("after response 1 the socket held NO stray bytes (0)", "response 2
    on the same connection is the intact plain body", "the proxy kept the client connection open
    across all three exchanges") and the body byte-identity checks (including the decoy
    terminator).
14. AC14: After `GET`, the machine fed `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer:
    X-A, X-B\r\n\r\n4\r\nwxyz\r\n0\r\nX-A: 1\r\nx-b: two words\r\nX-A: 3\r\n\r\n` yields exactly
    `[ResponseHeaders(id), ResponseBodyChunk{id, "wxyz"}, ResponseComplete(id)]`;
    `response().trailers` is exactly `[("X-A","1"), ("x-b","two words"), ("X-A","3")]` (order,
    case and the duplicate kept); `response().headers` has no `x-a` and still has `trailer` =
    `X-A, X-B`; `take_leftover(Side::Server)` is empty; and the machine then completes a second
    exchange. A response with no trailer fields yields an empty `trailers` and the same events
    as before.
15. AC15: The same bytes fed one byte at a time, and split at every position after the zero
    chunk's size line, give the same events (concatenated) and the same trailers.
16. AC16: Caps, each failing closed with `Err` from `on_bytes`: 64 fields is accepted and 65 is
    `Err`; a section of exactly 16384 bytes (sum of line lengths plus CRLFs) is accepted and
    16385 is `Err`; an unterminated partial line over 16384 bytes is `Err`; and a stream of
    `a: b\r\n` lines is refused at the 65th line, and an endless stream of 1 KiB lines at
    the line that crosses 16384 bytes, whatever the read sizes: it is never consumed forever.
    Through `serve`, a response with 65 trailer fields, whose head and first chunk the origin
    wrote before the trailer section, returns `Err` mentioning the trailer limit, and the client
    has received the head and the body chunk but not `0\r\n`, then sees EOF; the one
    `Event::Error` this scenario also produces is AC35's, asserted by AC35's own test.
17. AC17: A trailer line with a control byte in its value, a name containing a space or a
    non-token byte, no colon, or a leading space or tab is `Err`; none is silently dropped.
18. AC18: `serve` forwards the origin's allowed trailers: for an origin response `HTTP/1.1 200
    OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum:
    abc\r\nx-e2e: m1\r\n\r\n` (in one write, and with the trailer fields in a later write) the
    client reads exactly `HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding:
    chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum: abc\r\nx-e2e: m1\r\n\r\n`. With no trailer fields
    the terminator is exactly `0\r\n\r\n`.
19. AC19: Every one of the 37 names in the deny-set, in lower case and in upper case, is
    withheld from the wire: for each, a response whose only trailers are that field plus
    `x-ok: 1` ends with `0\r\nx-ok: 1\r\n\r\n`, and the writer reports one field withheld.
    Through `serve`, a response with trailers `Content-Length: 0`, `Host: evil.test`,
    `Set-Cookie: s=1`, `Authorization: Bearer x`, `X-Keep: yes`, `Location: /x` ends on the
    wire with `0\r\nX-Keep: yes\r\n\r\n`, while the stored `response.trailers` holds all six in
    order and `response.headers` holds none of them.
20. AC20: A plugin that replaces the streamed body at `ResponseHeaders` with `Body::Bytes` gets
    a `Content-Length` framed response with no trailers on the wire, and the stored
    `response.trailers` still holds the origin's.
21. AC21: Keep-alive: on one client connection, a chunked response whose trailer fields arrive in
    a later read than the zero chunk, then a plain `Content-Length` request, both complete with
    nothing left over, in `serve` and in the machine.
22. AC22: At `Event::Response` the stored flow's `response.trailers` already holds the origin's
    trailers (a sink that reads the store at `Event::Response`), and `response.headers` is the
    origin's head unchanged.
23. AC23: With `tracing` capture at TRACE level, a response whose trailer name and value both
    contain a distinctive token yields no captured event whose message or fields contain it; a
    response with a withheld field yields exactly one new `debug` event carrying only a count,
    and a response whose trailers are all forwarded yields none.
24. AC24: `Http1Sender`'s `drive` over a `DuplexStream` against a chunked-with-trailers origin
    (trailers in one write, and in a later write) returns an `HttpResponse` whose `trailers` are
    the origin's, in order, with the body intact and `headers` unmerged; and a section over a cap
    is `Err`.
25. AC25: `flow.detail` for a flow whose response has trailers `[("X-Checksum-SHA256","abc"),
    ("Server-Timing","origin;dur=1")]` has `response.trailers` equal to the array of those two
    `[name, value]` pairs; for a flow without trailers the `response` object's keys are exactly
    `body`, `body_size`, `body_truncated`, `headers`, `status`, `version`.
26. AC26: A native session round trip restores the trailers (including a repeated name, in
    order); the saved JSON of a flow without trailers contains no `trailers` key, and a document
    saved before this change loads with empty trailers.
27. AC27: h2 is unchanged: the `h2_mitm`, `h2_limits` suites pass, `response_from_h2(..).trailers`
    is empty, and the diff of `h2.rs` and `translate.rs` is exactly the one-line initialisers
    (`h2.rs:416`, `translate.rs:79`), the `translate.rs` test literal and the two tests that pin them in `translate.rs`'s `mod tests`.
28. AC28: A chunked request with trailers (`0\r\nX-T: 1\r\n\r\n`) yields the same events as
    today and the machine then parses the next request; a request trailer section over the caps
    or with an invalid line is `Err`.

Cross-cutting

29. AC29: Well-behaved traffic is unchanged: `cargo test -p aitm-proto-http` (every unit test and
    every file in `tests/`, including the 68 lib tests and 27 `tests/sansio.rs` tests that exist
    at the base, unchanged), and the suites that build an `HttpResponse`: `aitm-core`,
    `aitm-findings`, `aitm-plugins` (`detail`, `capture`, `mutate`, `replay`, `control`, `meta`,
    `scope_rate`), `aitm-plugin-sessionio`, `aitm-plugin-maprules`, `aitm-plugin-rhai`,
    `aitm-plugin-scanner`, `aitm-poc` all pass. A flow with no trailers and no expectation has
    the same stored response, `flow.detail` JSON and session JSON as before.
30. AC30: The guard and every dial path are untouched. `git diff <base>..HEAD --stat -- crates/aitm-core`
    lists only `src/flow.rs`, `src/store.rs` (the AC34 `flow_size` change), `tests/store.rs` and
    `tests/store_control.rs` (so nothing in
    `guard.rs`, `proxy.rs`, `authority.rs`, `egress.rs` or `ctx.rs`); `grep -c 'connect_upstream('
    crates/aitm-proto-http/src/module.rs` still prints 3; `grep -c 'TcpStream::connect'
    crates/aitm-proto-http/src/module.rs` prints 0; `sender.rs` has no production-code change.
31. AC31: No new dependencies: `git diff <base>..HEAD --stat -- Cargo.toml Cargo.lock
    'crates/*/Cargo.toml'` prints nothing.
32. AC32: The loopback file `crates/aitm-proto-http/tests/h1_conformance.rs` passes in the Terminal
    panel (its six tests), and no file under `tests/e2e/` is in `git diff <base>..HEAD --stat`.
    The criterion's earlier first clause, the two e2e scripts byte-identical to the main
    checkout's copies, is not a criterion of this branch: it moves to the landing PR of the session
    that owns the scripts, where the `shasum -a 256` comparison happens (call 27).
33. AC33: The Rust gate exits 0: `cargo fmt --check && cargo clippy --all-targets -- -D warnings
    && cargo test --no-fail-fast`.

Added after the Stage 6 panel (appended, nothing renumbered)

34. AC34: The flow store charges a response's `trailers` to its resident-byte estimate exactly as
    it charges the response's `headers` (the sum of every pair's name length and value length):
    `flow_size` in `crates/aitm-core/src/store.rs`. Reason: with `max_flows = 0`
    (`MemFlowStore::with_limits(0, budget)`) the byte budget is the store's only bound, and a
    hostile origin can attach up to 16 KiB and 64 fields of trailers to every response, which
    would otherwise be uncounted (call 25). Tests in `crates/aitm-core/tests/store.rs`: (a) a
    flow whose response carries trailers `[("X-Sum", "abc"), ("x-sum", "def")]` has
    `resident_bytes()` at least 16 greater (5 + 3 + 5 + 3 bytes of field text) than the same flow
    with no trailers; (b) the same pairs as trailers on one flow and as headers on another give
    equal `resident_bytes()` (together with (a), this pins the charge as exactly the headers'
    charge); (c) trailers written by `update`, as `serve` writes them at `Event::Response`, count
    and can trigger byte eviction: with `MemFlowStore::with_limits(10_000, 10_000)`, 20 terminal
    flows each updated to gain a trailer of 1000 bytes of field text leave `resident_bytes()` at
    most 10_000 and fewer than 20 flows listed (the count cap is never reached, so the byte
    budget is what evicts).
35. AC35: When the machine returns an error while `serve` reads an origin response (a malformed
    head or framing, or a malformed or over-cap trailer section), `serve` emits exactly one
    `Event::Error { flow, kind: FlowError::Upstream("malformed response from upstream") }` for
    that flow before the connection ends, so event consumers (the scanner, findings, Rhai
    hooks) see the failed response (call 26). The text is fixed: never the machine error's text,
    never a trailer name or value. Client-visible behaviour is unchanged: the connection ends,
    the client never receives a terminator, and `serve` still returns the machine's own error
    to its caller (the `trailer` message of AC16). Tests in `module.rs`, for an origin that
    sends a 65-field trailer section (a) in a write after the head and first chunk and (b) in
    one write with the head and the chunk: the recording sink holds exactly one `Event::Error`
    for the flow and it equals `FlowError::Upstream("malformed response from upstream".to_string())`,
    holds no `Event::Response` for it, and no trailer field name appears in the `Debug` text of any
    event the sink saw. One match arm serves every machine error on the response read, so no
    separate malformed-head test is required. This closes the response-parse half of the gap
    this spec first attributed to the hardening spec's F4; a failed first dial or reconnect
    still emits no `Event::Error` (a non-goal here).

## Adjacent findings (not in this change)

Found while reading; each is a candidate follow-up, none is fixed here.

- **F1. h2 has neither Expect handling nor trailers.** `serve_h2` reads the whole request
  body before forwarding and never answers an expectation, so a client that honours
  `Expect` over h2 (Go's transport) stalls like the h1 client did; the vendored `h2` 0.4.19
  has `SendResponse::send_informational`, so the fix is small. h2 trailers are dropped (M7
  accepted follow-up); with this change's field the capture half is a few lines, the
  forward half needs the `h2` crate's trailer send API.
- **F2. Suspected: a bodiless response whose head says `Transfer-Encoding: chunked` is
  followed by a stray `0\r\n\r\n`.** From reading `serve`, not reproduced. For a HEAD, 204 or
  304 response the machine's framing is `None` and it completes immediately, but `serve`
  forwards the head with the origin's `Transfer-Encoding: chunked` (a streamed body keeps its
  head's framing) and then calls `enqueue_body_end`, which writes `0\r\n\r\n` for a
  chunk-framed body. Some origins do send `Transfer-Encoding: chunked` on HEAD responses. The
  extra bytes would sit in front of the client's next response. This change leaves it as it
  is (a no-trailer terminator is byte-identical to today's); the first test of a follow-up
  should reproduce it. The Stage 5 tester and the Stage 6 panel re-noticed it on the built
  code: a HEAD, 204 or 304 response whose head mis-declares `Transfer-Encoding: chunked`
  still gets the stray `0\r\n\r\n`, unchanged by this work.
- **F3. Request-side trailers** (call 15): `HttpRequest.trailers` and a re-framing rule.
- **F4. Unknown expectations** (call 5): an early `417` would unblock clients that wait.
- **F5. Strip-versus-forward `Expect`** (call 4): revisit if an origin that answers every
  `Expect` with `417` is met in practice.
- **F6. Trailers are invisible to scripts and the scanner** (Rhai `flow_state`, `http.send`
  result, passive checks, PoC): read `response.trailers` when a use appears.
- **F7. Trailer display** in the TUI, web UI and mac app.
- **F8. `h2.rs` literal sites**: the model sweep touches `h2.rs`, which the hardening change
  left alone; fold that into the `serve_h2` follow-up's diff when it lands.
- **F9. The deny-set's residual (accepted, call 28).** A deny-list cannot name every field
  that needs header-time evaluation. These names are not in the 37 and can still be forwarded
  as trailers to a client that wrongly treats trailers as headers: `set-cookie2`,
  `content-disposition`, `content-security-policy`, `strict-transport-security`, `alt-svc`,
  `link`, `refresh`, `content-location`, `clear-site-data`. A client that follows RFC 9110
  6.5.1 and processes trailers apart from headers is not affected, and the capture and the
  store never merge a trailer into `headers` regardless. Adding them to the set is optional
  hardening for later: one `const` edit and its table test (the list would then be 46).

## Left to the builder

- Exact names of test helpers and tests (the plan names the ones the acceptance criteria
  depend on; names are otherwise free).
- How the machine reads the request version token (a second return value from
  `parse_request`, or a small helper over the request line), provided heads parse exactly as
  today and `HttpVersion::Http11` stays what the model records.
- The name and shape of the trailer accumulator, and the name of the helper extracted from
  `parse_headers`, provided heads behave exactly as today.
- The wording of the one new `debug` message and of the trailer-limit errors, other than the
  substring `trailer` in the limit errors (AC16) and that no name or value appears in a log.
- Whether the deny-set `const` is a slice scanned linearly or a sorted array, provided the
  match is ASCII case-insensitive on the whole name and the 37 names are exactly those listed.
- How the early-`413` check reads the declared `Content-Length`, provided the machine already
  rejected a malformed or conflicting value before the `RequestHeaders` event and the pending
  expectation is the only trigger. Decided at review: it reuses the machine's `content_length`
  parser (call 24), not a second parser in `serve`.

## Open questions

None. Every decision above that Matt could reasonably reverse is marked
**(Architect's call)** and indexed below. The one item Matt should hear about before the
build, because it widens the footprint rather than because it is undecided, is the model
field's ripple (35 files in 9 crates, 36 on the rebased tree; mechanical).

## Deviations accepted at review

Four places where the build differs from what this spec or the plan said, accepted at the
Stage 6 panel and recorded as further Architect's calls so Matt can reverse any of them.

- **Call 21: `#[allow(clippy::large_enum_variant)]` on `aitm_core::Flow` and on
  `aitm-plugin-sessionio`'s `FlowRecord`.** The 24-byte `trailers` field takes the `Http`
  variant to 224 bytes, over clippy's 200-byte threshold for the difference between the two
  variants. `FlowRecord` is the session format's mirror of `Flow`, so it gets the same
  allowance and the same reason in a comment. Rejected: boxing `Flow::Http`, which ripples
  through every use of the variant in the workspace; boxing only the new field, which saves
  16 bytes and does not clear the threshold.
- **Call 22: the `ResponseHeaders` arm of `serve` clears `trailers` on the stored head.** It
  is what spec Bug 2 item 7 already implies (the store holds the head with `trailers` empty
  until `Event::Response`); the build made it explicit because a whole response arriving in one
  read has the trailers on the machine's `response()` before the `ResponseHeaders` event is
  handled. It is the reason a plugin still sees no trailers until `Event::Response` in that case.
- **Call 23: Task 2 removed the dead-code allowance Task 1 added.** Task 1 introduced
  `expects_continue` and `enqueue_continue` before anything called them, so they carried a
  temporary `allow(dead_code)`; Task 2, their first caller, removed it. No allowance remains.
- **Call 24: the early-`413` decision reuses the machine's `content_length` parser.** Task 2
  first read the declared length with a small parser of its own in `module.rs`; the fix task
  replaced it with `sansio::content_length`, now crate-visible, so the refusal and the framing
  agree by construction. A source change in the panel's fix task.

## Index of Architect's calls

1. Bug 1: the interim is written in `serve`'s `RequestHeaders` arm, after the flow insert and before `Event::RequestHeaders` is emitted, so a parked flow cannot stall the client; kill and short-circuit are decided after the body anyway.
2. Bug 1: a failed write of the interim ends `serve` quietly with `Ok(())`.
3. Bug 1: the eligibility rule: version not `HTTP/1.0`, a `100-continue` list member (case-insensitive, whole token), content follows by framing, and no content byte buffered with the head.
4. Bug 1: `Expect` is forwarded to the origin untouched; the origin's own 100 is skipped by the machine (confirmed safe for keep-alive). Departs from mitmproxy's strip-on-forward for fidelity.
5. Bug 1: unknown expectations are left as today: no interim, no `417` from us.
6. Bug 1: include the early `413` for a declared `Content-Length` over the cap when the expectation is pending.
7. Bug 1: h2 is out of scope, with the correction that `serve_h2` does not delegate to hyper and the stall exists there (F1).
8. Bug 1: two crate-private machine methods (`expects_continue`, `enqueue_continue`); no new event, no new public API.
9. Bug 2: trailers live in a new `HttpResponse.trailers: HeaderMap`, never merged into `headers`; ripple of 40 literals in 35 files in 9 crates at `2884ec0` (42 in 36 on the rebased tree), isolated in one early task.
10. Bug 2: trailers ride on the machine's own `response()`; no new event, no change to `Event`, the plugin API or any existing signature.
11. Bug 2: capture every field the origin sent (within the caps); withhold forbidden fields from the wire only.
12. Bug 2: the 37-name deny-set, a deny-list expanding RFC 9110 6.5.1's categories, matched case-insensitively, enforced in the writer.
13. Bug 2: forward trailers whenever the response is chunk-forwarded, not only to `TE: trailers` clients.
14. Bug 2: caps of 16 KiB and 64 fields, fail closed; field syntax checked like heads; an obs-fold line is rejected.
15. Bug 2: request-side trailers are a non-goal; the caps and syntax check apply to them too.
16. Bug 2: h2 gets one-line field initialisers and otherwise stays as it is.
17. Bug 2: `flow.detail` renders `response.trailers` as `[name, value]` pairs, only when non-empty.
18. Bug 2: native session persistence of trailers is in scope (additive optional field); the first item to cut.
19. Test strategy: sandbox unit tests carry red to green; a loopback file and the two e2e scripts, run unchanged against a core built from the branch (not copied into it, call 27), corroborate in the Terminal panel; the e2e scripts only become a guard in-repo once the harness `tests/e2e/aitm_e2e` is on the base of the PR that lands them.
20. Logging: one new `debug` site (a count of withheld trailer fields); never a name or value.

Added after the Stage 6 panel:

21. Deviation accepted: `#[allow(clippy::large_enum_variant)]` on `aitm_core::Flow` and `aitm-plugin-sessionio`'s `FlowRecord` (the `trailers` field takes the `Http` variant to 224 bytes); boxing rejected.
22. Deviation accepted: `serve` clears `trailers` on the stored head in the `ResponseHeaders` arm, so a whole response arriving in one read still shows no trailers to plugins until `Event::Response`.
23. Deviation accepted: Task 2 removed the temporary dead-code allowance Task 1 added to the two new machine methods.
24. Deviation accepted: the early-`413` decision reuses the machine's `content_length` parser (made crate-visible) instead of a parser of its own in `serve`.
25. The flow store's `flow_size` counts a response's `trailers` like its headers (AC34), because with `max_flows = 0` the byte budget is the only bound and a hostile origin controls up to 16 KiB and 64 fields per response.
26. A machine error while an origin response is read emits one `Event::Error` with `FlowError::Upstream("malformed response from upstream")`, fixed words, before the connection ends (AC35); client-visible behaviour is unchanged.
27. The two e2e scripts are run for real against a core built from this branch and are not added to it: another session owns them and lands them test-only after this change merges. AC1 and AC13 rest on that run's exit status; AC32's checksum clause moves to the landing PR. Supersedes the "copied unchanged" half of call 19.
28. The deny-set's residual (F9) is accepted: names outside the 37 can still reach a client that wrongly treats trailers as headers; adding them is optional later hardening.
