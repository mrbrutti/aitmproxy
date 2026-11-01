# 14 — Active WebSocket scanning and an HTTP/2 request sender

## Question

How should aitmproxy (1) actively scan captured WebSocket endpoints — opening
its own WS connections to replay mutated messages, the way Burp's WebSocket
tooling and ZAP's add-on do — and (2) add an HTTP/2-capable request sender to
its active scanner, including h2-specific vulnerability checks?

## Short answer

Neither Burp nor ZAP auto-scans WebSocket messages the way they scan HTTP;
both leave it to manual Repeater/Intruder-style replay or extensions
(SocketSleuth, WS Turbo Intruder). aitmproxy should do the same: add a
**`WsDialer`** (`tokio-tungstenite` 0.28 client, replaying the captured
handshake minus `Sec-WebSocket-Key`/`Accept`) that opens its own connection
and fuzzes insertion points inside a captured frame's text/JSON fields, kept
out of the live `InjectRegistry` entirely. For HTTP/2, add an **`H2Sender`**
implementing the existing `RequestSender` trait using the `h2` 0.4 client
exactly as `h2.rs`'s outbound path already does, selected per-authority by an
ALPN probe mirroring `module.rs`'s existing offer/negotiate logic. H2 checks
should be oracle-based and observe-only for anything DoS-adjacent (desync and
pseudo-header abuse are the safe, testable classes; Rapid Reset and
flow-control abuse are detect-only).

## Findings

### 1. How Burp and ZAP handle WebSockets

- Burp has no built-in "Scan WebSocket messages" feature comparable to its
  HTTP Scanner. Proxy → WebSockets history sends a message to Repeater, where
  the pencil icon lets you attach to, clone, or reconnect a WebSocket
  connection and edit the handshake before connecting (Host/port/HTTPS/custom
  headers) (read 2026-10-31,
  https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages,
  https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/websockets/manipulating-websocket-handshakes).
  Repeater's insertion-point/"Scan selected insertion point" and Intruder's
  `§...§` markers are HTTP-request features; the docs do not extend them to
  WebSocket frames (read 2026-10-31,
  https://portswigger.net/burp/documentation/desktop/testing-workflow/scanner-manual-testing).
  Burp's own WebSocket-testing guidance (XSS/SQLi/XXE via message content,
  OAST for blind issues) is manual: intercept, edit, replay (read 2026-10-31,
  https://portswigger.net/web-security/websockets).
- The gap is filled by extensions built on Burp's Montoya API (which exposed
  WebSocket hooks for the first time on 2022-10-27): Snyk's **SocketSleuth**
  adds a dedicated WS history/match-and-replace/Intruder-like fuzzer, and
  **WebSocket Turbo Intruder** fuzzes messages with custom scripts (read
  2026-10-31,
  https://labs.snyk.io/resources/socketsleuth-improving-security-testing-for-websocket-applications/).
- ZAP's WebSocket add-on intercepts, breakpoints, and **passively** scans
  every frame via scripts (default rules: Base64 Disclosure, Credit Card
  Number, Private Address Disclosure, Username Disclosure, etc.), but its
  maintainer confirmed (2022, user-group thread) that active fuzzing of
  WebSocket messages is a **manual** Fuzzer-pane workflow, not an automated
  active scan, and binary payloads (e.g. RSocket) aren't fuzzable (read
  2026-10-31, https://www.zaproxy.org/docs/desktop/addons/websockets/,
  https://www.zaproxy.org/docs/desktop/addons/websockets/pscanrules/,
  https://groups.google.com/g/zaproxy-users/c/nA1FLEMVWZQ).
- **Correction to the brief's premise:** there is no evidence of a native
  "Scan WebSocket" feature in Burp 2020+/2023 comparable to HTTP active scan;
  this is third-party/extension territory in both tools. aitmproxy building
  one natively would be ahead of both, not catching up.
- Handshake replay mechanics (Burp "clone and reconnect"): the new connection
  is built from the original handshake request with edits, then a fresh
  WebSocket upgrade is performed — i.e. a real new TCP+TLS+HTTP Upgrade, not a
  frame replayed onto the old socket. The docs do not enumerate exactly which
  headers are stripped/regenerated (unverified beyond "Sec-WebSocket-Key" is
  handshake-specific and must be regenerated for a fresh connection, which is
  a WebSocket-protocol fact, not a Burp-specific one — RFC 6455 requires a
  fresh client-generated key per handshake).

### 2. WS vulnerability classes and safe active checks

| Class | Technique | Oracle | Safe payload / bound |
|---|---|---|---|
| Cross-site WebSocket hijacking (CSWSH) | Reconnect the handshake with a cross-origin `Origin` header (and without the session's CSRF token, if any) and see if the server still completes the upgrade and serves the authenticated feed | 101 response + server sends/accepts authenticated data despite the foreign Origin | No payload; only header substitution. Non-destructive. |
| Auth bypass on upgrade | Reconnect with cookies/auth headers stripped or replaced with another (in-scope, consented) low-priv identity's | Upgrade still succeeds / privileged data returned | Handshake-only; no frame traffic needed |
| Input injection (XSS/SQLi/cmdi in message fields) | Send a copy of a captured message with one JSON/text field replaced by a marked probe (e.g. `<script>`, `' OR '1'='1`, OAST canary token) | Reflected probe in a later message to another client, a DB error string, or an out-of-band callback | Use inert/canary payloads (OAST domain, not a live exploit); keep message shape/field types intact so the server doesn't just reject malformed JSON |
| DoS via oversized/fragmented frames | Send one frame modestly over a plausible size (e.g. 2x the largest observed legitimate frame, capped absolutely) or a short fragmented sequence | Connection reset, latency spike, or error response vs. silent accept | Bounded size cap and a single attempt, never a flood — non-destructive variant only |
| Subprotocol/extension negotiation issues | Request a subprotocol/extension the server didn't offer, or omit `Sec-WebSocket-Protocol` the client normally sends, and see what the server negotiates back | Server accepts an unrequested/unexpected protocol, or downgrades silently | Header-only; no data frames |
| permessage-deflate compression oracle (CRIME/BREACH-style) | If the server negotiated `permessage-deflate`, send attacker-influenced + secret-adjacent content across messages and compare compressed sizes | Size correlates with guessed-secret correctness | Requires care — classic compression-oracle technique; should be an opt-in, documented check, not default-on, since it needs many requests |

General source for the vulnerability taxonomy: PortSwigger's WebSocket
security testing page (CSWSH, input-based flaws, handshake tampering) (read
2026-10-31, https://portswigger.net/web-security/websockets). The DoS,
subprotocol, and compression-oracle entries are this note's own synthesis
from WebSocket protocol semantics (RFC 6455 framing/extension-negotiation and
RFC 7692 permessage-deflate) — **mark these two as not sourced from a named
scanner**, only from protocol-level reasoning; verify against a live target
during spec/experiment before shipping a default-on check.

### 3. A Rust WS dialer

`tokio-tungstenite` 0.28 is already a dependency of `aitm-proto-ws`,
`aitm-plugin-wsctl`, and `aitm` (`crates/aitm-proto-ws/Cargo.toml`,
`crates/aitm-plugin-wsctl/Cargo.toml`, `crates/aitm/Cargo.toml` — read
2026-10-31 from the repo). Verified client API (docs.rs, read 2026-10-31,
https://docs.rs/tokio-tungstenite/0.28.0/tokio_tungstenite/):

```rust
pub async fn client_async_tls_with_config<R, S>(
    request: R,
    stream: S,
    config: Option<WebSocketConfig>,
    connector: Option<Connector>,
) -> Result<(WebSocketStream<MaybeTlsStream<S>>, Response), Error>
where
    R: IntoClientRequest + Unpin,
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin,
    MaybeTlsStream<S>: Unpin;
```

`Connector` selects `native-tls` vs `rustls` (the crate's `Connector::Rustls`
variant plumbs a `rustls::ClientConfig`, matching the rest of the codebase's
rustls-only posture — `aitm-proto-http` and `aitm-proto-ws` already depend on
`rustls`/`tokio-rustls`). To replay a captured handshake, build the request
via `IntoClientRequest` (on a `Uri` it auto-generates `Host`,
`Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, and
a fresh `Sec-WebSocket-Key`), then copy over from the captured `HttpFlow`'s
request headers everything except: `Host` (regenerated for the dial target),
`Connection`/`Upgrade` (regenerated), `Sec-WebSocket-Key` (must be freshly
random per RFC 6455 — reusing the captured key is itself a protocol
violation some servers will reject), `Sec-WebSocket-Accept` (response-only,
never sent by a client), and `Sec-WebSocket-Version` (regenerated). Keep:
`Cookie`, `Origin` (unless deliberately mutated for a CSWSH check),
`Authorization`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`, and any
custom app headers. This header-copy/strip rule is this note's synthesis from
RFC 6455 semantics plus the crate's documented `IntoClientRequest` behavior
(community guidance confirms the pattern of calling `into_client_request()`
then mutating `headers_mut()` — read 2026-10-31,
https://users.rust-lang.org/t/custom-header-connect-async-tokio-tungstenite/100973
— **this forum source is not authoritative; verify against `tungstenite`'s
own `client.rs` before relying on exact behavior**). Ping/pong/close handling
and timeouts are not itself documented on the crate's landing page; the
existing in-proxy `WsFrameMachine`/`WsSansIoEvent` sans-IO coder in
`aitm-proto-ws` already implements opcode handling and could plausibly drive
a dialed connection's frame logic too, but this needs an architect decision,
not research. **Unverified**: exact `WebSocketConfig` field names/defaults
for the 0.28 line, and whether `client_async_tls_with_config` needs
`Connector::Rustls` built from the same `CryptoProvider` the rest of the code
shares (`aitm-proto-http`'s `Http1Sender` builds its own
`rustls::ClientConfig` per sender instance — the same pattern likely applies
here, but was not directly confirmed on docs.rs for tungstenite's `Connector`
constructor signature).

### 4. HTTP/2 client in Rust

The proxy already drives an **outbound** h2 client exactly where a scanner's
sender belongs: `crates/aitm-proto-http/src/h2.rs`'s `Upstreams::open` dials
TCP, TLS-connects with ALPN mirrored to `h2`, then:

```rust
let (send_req, up_conn) = h2::client::Builder::new()
    .enable_push(false)
    .max_header_list_size(MAX_HEADER_LIST_SIZE)
    .header_table_size(HEADER_TABLE_SIZE)
    .handshake::<_, Bytes>(tls)
    .await?;
tokio::spawn(async move { let _ = up_conn.await; });
```

(read 2026-10-31, `crates/aitm-proto-http/src/h2.rs` lines ~269–318). This is
the same `h2::client::handshake` the docs.rs API confirms
(`pub async fn handshake<T>(io: T) -> Result<(SendRequest<Bytes>,
Connection<T, Bytes>), Error> where T: AsyncRead + AsyncWrite + Unpin` — read
2026-10-31, https://docs.rs/h2/0.4.12/h2/client/fn.handshake.html), and
`SendRequest::send_request` is `fn send_request(&mut self, request:
Request<()>, end_of_stream: bool) -> Result<(ResponseFuture, SendStream<B>),
Error>` (read 2026-10-31,
https://docs.rs/h2/0.4.12/h2/client/struct.SendRequest.html). An `H2Sender`
implementing `RequestSender` (`crates/aitm-core/src/client.rs`) needs only to
reuse this pattern on a dial-per-request (or small pooled) basis and convert
`aitm_core::HttpRequest`/`HeaderMap` to/from `http::Request`/`http::Response`
— the inbound h2 path's `crate::translate` module already does this
conversion for the proxy's own pass-through and is the obvious reference,
though it was not read line-by-line here (its existence and purpose are
named in `h2.rs`'s module docs, `use crate::translate;`).

ALPN selection for outbound dials already has a working pattern in
`crates/aitm-proto-http/src/module.rs`: it offers `alpn_protocols =
[b"h2", b"http/1.1"]` to the upstream, reads back the negotiated protocol via
`.alpn()`, and branches (`if negotiated == b"h2" { ... }`) to run either the
h2 driver or the h1 path (read 2026-10-31,
`crates/aitm-proto-http/src/module.rs` lines ~196–401, matched via grep).
`Http1Sender::client_config` currently **hard-codes**
`cfg.alpn_protocols = vec![b"http/1.1".to_vec()]` (read 2026-10-31,
`crates/aitm-proto-http/src/sender.rs`) — this is exactly the seam the
Architect needs to touch: a protocol-agnostic sender front-end should offer
both and select `Http1Sender` or `H2Sender` by the negotiated ALPN byte
string, exactly mirroring `module.rs`'s existing inbound logic.

h2c ("prior knowledge" cleartext HTTP/2, used when a target's `http://`
origin is known out-of-band to speak h2 without TLS/ALPN) is a distinct code
path neither `h2.rs` nor `sender.rs` currently implements (both are
TLS-ALPN-gated); the `h2` crate crate supports it via the same
`handshake(io)` call over a plain TCP stream, but aitmproxy has no existing
reference for it — **unverified in this codebase, flag for the spec.**

`hyper` 1.x's `hyper::client::conn::http2` module wraps `h2` with its own
`handshake`/`SendRequest`/`Connection`/`Builder` types, requires the
`client`+`http2` (+`http1` or `http2`) Cargo features, and lists `h2` ^0.4.14
as its backing dependency (read 2026-10-31,
https://docs.rs/hyper/1/hyper/client/conn/http2/index.html). aitmproxy
already depends on `hyper` 1.x in several crates (`aitm-mcp`, `aitm-poc`,
`aitm-testtarget`, `aitm`) but **not** in `aitm-proto-http`, which talks to
`h2` and `http` directly — using `hyper`'s wrapper instead of raw `h2` here
would be a net-new dependency in that crate for no evident gain, since the
existing inbound h2 path already proves the raw-`h2` pattern works.
**Unverified**: exact `hyper::client::conn::http2::handshake` signature (the
docs.rs page fetched here did not render it).

### 5. h2-specific checks, safety, and oracles

Primary source: James Kettle/PortSwigger, "HTTP/2: The Sequel is Always
Worse" (read 2026-10-31, https://portswigger.net/research/http2, whitepaper
at https://portswigger.net/kb/papers/rfekn2uv/http2whitepaper.pdf).

| Check | Mechanism | Safety / oracle |
|---|---|---|
| **H2.CL** downgrade desync | Front-end is h2; probe whether a back-end that the front-end downgrades to h1 trusts an attacker-supplied `Content-Length` that disagrees with the h2 stream's real body length | Safe as a single off-by-a-few-bytes probe against a *scoped* target with a **detection-only** technique (timing/response-count anomaly on a harmless extra byte), never a live second-request smuggle; the real exploit needs two sequential requests and should be gated as "confirm only with explicit operator opt-in" |
| **H2.TE** | Send a `transfer-encoding: chunked` header over h2 (legal to send as a plain header value, even though no entity uses it to frame an h2 body) and see if a downgrading back-end honors it | Same detect-then-confirm split as H2.CL |
| CRLF / header value injection | Attempt to set a header value containing `\r\n` through the raw `h2`/`http` API (the `http` crate's `HeaderValue` normally rejects this — the check is "does our own client allow it," and separately, "does the target's downgrade path interpret a byte sequence that looks like a split header") | Mostly a client-library correctness check; against a live target, only send fully `http`-crate-valid header values (the crate itself is the safety backstop) and look for anomalous back-end behavior, not a working secondary request |
| Header **name** injection | Same idea for the header name, which Atlassian's first H2.TE hotfix missed (blocked CRLF in values but not names) per Kettle's paper | Detection-only; the `http` crate's `HeaderName` validation is again the practical backstop |
| `:path`/`:authority` pseudo-header desync | Send unusual-but-spec-legal pseudo-header values (e.g. a `:path` containing an encoded space or a `:authority` that disagrees with a `Host` header, if one is also sent) and compare how front-end vs. back-end routing diverges | Oracle is routing/caching divergence (different response/content for the "same" request); bounded to a handful of probe variants, not a flood |
| Pseudo-header validation | Send a request missing a mandatory pseudo-header, a duplicate pseudo-header, or a pseudo-header after a regular header (illegal per RFC 9113 §8.3) and record whether the server/front-end rejects it (`RST_STREAM`, 400) or tolerates it | Purely observational; one malformed stream per probe, not traffic generation |
| Downgrade detection (front-end h2 → back-end h1) | Infer from response headers/behavior (e.g. a header that only an h1 intermediary would add/strip, or a timing signature) that a hop downgraded | Observe-only; no special request needed beyond the H2.CL/H2.TE probes above |
| Settings/flow-control abuse | Observe the server's advertised `SETTINGS_MAX_CONCURRENT_STREAMS`/initial window and whether it enforces them, without actually exhausting them | **Observe-only**, per the brief: read values, do not open streams up to the limit |
| Rapid Reset (CVE-2023-44487) | Detection-only: open a small, bounded number of streams and immediately `RST_STREAM` each (well under any reasonable threshold, e.g. single digits) and see whether the server (a) keeps the connection open past a sane reset count or (b) sends `GOAWAY`/closes — i.e., confirm the server *has* a reset-rate mitigation, never attempt to exhaust it | Mitigation references: Cloudflare's post describes reset-counting and reset-to-completion-ratio defenses and common concurrent-stream defaults (nginx 128, Go 250) (read 2026-10-31, https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/); Red Hat's advisory corroborates (read 2026-10-31, https://access.redhat.com/security/cve/cve-2023-44487). A scanner should send at most a handful of reset pairs and stop — never attempt to reproduce an actual DoS |

### 6. Choosing protocol version per target

`module.rs`'s inbound TLS path already proves the pattern: offer ALPN
`[b"h2", b"http/1.1"]`, read back `.alpn()`, branch on the negotiated value
(`crates/aitm-proto-http/src/module.rs`, read 2026-10-31). A sender-side
chooser should do the same for an outbound reissue/scan dial: TLS-connect
once with both protocols offered, inspect the negotiated ALPN, and dispatch
to `H2Sender` or `Http1Sender`. Caching per-authority (so repeated scanner
requests to the same host skip a second ALPN probe) and an operator override
(force h1 or h2 regardless of ALPN, needed for h2c and for testing a
downgrade hypothesis deliberately) are both natural extensions of the
existing `RequestSender` seam — not evidenced in current code, so these are
candidate directions, not confirmed behavior.

## Candidate directions

1. **`WsDialer`** — a new type in `aitm-proto-ws` (or a new
   `aitm-plugin-wsscan`), independent of `InjectRegistry` (which only reaches
   a *live, currently relayed* flow — confirmed from `module.rs`: entries are
   inserted in `drive()` only while a conversation's `select!` loop runs and
   removed before `WsEnd`). The dialer opens its own `tokio-tungstenite`
   connection using a replayed-and-stripped handshake (§3 above), drives it
   with its own ping/pong/close handling, and records results as a new
   (`is_replay`-flagged, mirroring `Http1Sender`'s pattern) `WsFlow`. The
   insertion-point model: parse each captured message's `data` as UTF-8/JSON
   where possible, enumerate string/number leaf fields as insertion points
   (mirroring Burp/ZAP's manual field-level tampering, since neither tool
   does this automatically either — §1), and substitute one probe per field
   per dial, non-destructively bounding concurrency and total messages sent.
   Trade-off: a dialer needs its own handshake-replay and framing logic
   somewhat duplicated from `WsModule`'s `drive()` — worth asking whether the
   sans-IO `WsFrameMachine` can be shared.

2. **`H2Sender`** implementing `RequestSender` in `aitm-proto-http`, built on
   the already-proven `h2::client::handshake` + `send_request` pattern from
   `h2.rs`'s outbound path, converting via (likely) the existing
   `crate::translate` module. Paired with a thin protocol-chooser (ALPN probe
   + per-authority cache + operator override) that currently doesn't exist —
   `Http1Sender` hard-codes `http/1.1` ALPN today. Trade-off: raw `h2` (match
   the existing in-repo pattern, zero new deps) vs. `hyper::client::conn::http2`
   (higher-level, but a new dependency in a crate that currently avoids
   hyper, for a wrapper whose exact API this research could not confirm).

3. **h2 check list**: ship H2.CL/H2.TE/pseudo-header/CRLF-injection as
   *detect-and-report*, Rapid Reset and flow-control as *strict
   observe-only* with a hard cap on streams/resets sent, per the safety
   table in §5. This matches the brief's instruction and the core project's
   general posture (bounded, non-destructive) seen elsewhere in the codebase
   (e.g. `MAX_EXTRA_UPSTREAMS`, `MAX_HEADER_LIST_SIZE` caps in `h2.rs`).

## Open questions

- Exact `WebSocketConfig`/`Connector` constructor signatures for
  `tokio-tungstenite` 0.28 (not rendered by the docs.rs page fetched here) —
  needs a direct source read or `cargo doc --open` locally before the spec
  locks the dialer's API.
- Whether `crate::translate` in `aitm-proto-http` already has an
  `HttpRequest ⇄ http::Request` conversion generic enough to reuse for a
  client-side `H2Sender`, or whether it's wired only for the inbound/server
  path — not read in this pass.
- Whether h2c (cleartext, prior-knowledge) support is in scope for the first
  version of `H2Sender`, given no code precedent exists for it here.
- Whether the compression-oracle (permessage-deflate) WS check belongs in a
  first cut at all, given its payload-volume and false-positive risk — this
  note found no evidence either Burp or ZAP ship it even as an extension.
- How Repeater's "clone and reconnect" exactly decides which headers to keep
  vs. regenerate was not documented by PortSwigger in enough detail to cite
  directly; the header-copy rule above is this note's RFC 6455-based
  synthesis, not a confirmed Burp behavior.

## Sources

- https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages (read 2026-10-31)
- https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/websockets/manipulating-websocket-handshakes (read 2026-10-31)
- https://portswigger.net/burp/documentation/desktop/testing-workflow/scanner-manual-testing (read 2026-10-31)
- https://portswigger.net/web-security/websockets (read 2026-10-31)
- https://labs.snyk.io/resources/socketsleuth-improving-security-testing-for-websocket-applications/ (read 2026-10-31)
- https://www.zaproxy.org/docs/desktop/addons/websockets/ (read 2026-10-31)
- https://www.zaproxy.org/docs/desktop/addons/websockets/pscanrules/ (read 2026-10-31)
- https://groups.google.com/g/zaproxy-users/c/nA1FLEMVWZQ (read 2026-10-31)
- https://docs.rs/tokio-tungstenite/0.28.0/tokio_tungstenite/ (read 2026-10-31)
- https://docs.rs/tokio-tungstenite/0.28.0/tokio_tungstenite/fn.client_async_tls_with_config.html (read 2026-10-31)
- https://users.rust-lang.org/t/custom-header-connect-async-tokio-tungstenite/100973 (read 2026-10-31, community source, not authoritative)
- https://docs.rs/h2/0.4.12/h2/client/fn.handshake.html (read 2026-10-31)
- https://docs.rs/h2/0.4.12/h2/client/struct.SendRequest.html (read 2026-10-31)
- https://docs.rs/hyper/1/hyper/client/conn/http2/index.html (read 2026-10-31)
- https://portswigger.net/research/http2 and https://portswigger.net/kb/papers/rfekn2uv/http2whitepaper.pdf (read 2026-10-31)
- https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/ (read 2026-10-31)
- https://access.redhat.com/security/cve/cve-2023-44487 (read 2026-10-31)
- `crates/aitm-proto-ws/src/module.rs`, `crates/aitm-plugin-wsctl/src/lib.rs`, `crates/aitm-proto-http/src/sender.rs`, `crates/aitm-proto-http/src/h2.rs`, `crates/aitm-core/src/client.rs`, `crates/aitm-core/src/flow.rs`, `crates/aitm-proto-http/src/module.rs`, and the relevant `Cargo.toml` files (read 2026-10-31, in-repo)
- `docs/research/03-rust-proxy-stack.md` (read 2026-10-31, in-repo)
