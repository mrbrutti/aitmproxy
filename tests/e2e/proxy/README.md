# L7 proxy end-to-end tests

Black-box proof that aitmproxy's L7 proxy works against **real traffic**: a real
`aitm` binary MITMing real clients (curl, a stdlib RFC6455 WebSocket client, a node
HTTP/2 client) talking to real upstream servers. Every claim is checked twice —
once on what the client observed, once on what the proxy captured on its MCP bus
(the decrypted flow). These found and now guard a real hang bug (`flow.kill
mode=429|503`, see below).

These suites run on the shared `aitm_e2e` harness and runner (`tests/e2e/`): the
core boot (`Aitm.server`), the bus (`BusClient.operator`/`.agent`), and the plain
HTTP/1.1 echo-record `Upstream` observer all come from the shared lib. The things
the shared lib does not yet carry — a TLS-MITM curl client (ALPN), a raw RFC6455
WebSocket client, and TLS / HTTP-2 / gzip / chunked upstreams — live in
[`_clients.py`](_clients.py), which this surface owns. (They are slated to move
into `aitm_e2e.tls` / `aitm_e2e.ws`; this file shrinks to re-exports when they do.)

## Running

```bash
cargo build -p aitm                        # build target/debug/aitm first
python3 tests/e2e/run.py proxy             # run the whole proxy surface
python3 tests/e2e/proxy/test_http2.py      # or a single scenario directly
```

Each scenario boots its own `aitm` on dedicated free loopback ports (no collision
with a running app or sibling sessions) and signals its result by exit code
(`0` pass, `77` skip, else fail). They bind ports, so run them in a real shell, not
a sandbox. Requirements per scenario are declared with `# e2e: needs=...` and the
suite SKIPs (loudly) if a real dependency is missing: `curl` with HTTP/2
(`curl --version` shows `nghttp2`), `openssl`, and `node` (the HTTP/2 upstream;
Python stdlib has no h2 server).

## What each scenario proves

- **test_http_tls_capture.py** — a plain HTTP/1.1 request reaches the upstream (its
  own record) and is captured on the bus; an HTTPS request is MITM'd (curl trusts
  the aitm leaf, gets the real body) and the proxy captured the DECRYPTED request
  and response; a gzip response is forwarded intact and captured decodably; a
  chunked response is reassembled on both the client and the proxy.
- **test_http2.py** — h2 end to end (upstream and client both on h2, decrypted
  capture); no downgrade surprise either way (an http/1.1-only client is served
  http/1.1, mirrored to the upstream); an intercepted h2 request is mutated and the
  edit reaches the upstream.
- **test_websocket.py** — the upgrade is proxied and handed off; frames both
  directions are captured; `ws.send` s2c reaches the client; `ws.send` c2s reaches
  the server (confirmed by the server's own record), and injected frames are
  recorded on the flow.
- **test_intercept_replay.py** — request-phase park → rewrite path/headers/body →
  resume, with the UPSTREAM record confirming the mutation crossed the proxy;
  response-phase park → rewrite status/body → resume, with the CLIENT receiving the
  edit; `flow.replay` re-issues and captures; `request.send` captures and is
  scope-gated; `flow.kill mode=503` fails the client request with 503.
- **test_intercept_url_rules.py** — a breakpoint rule whose `url` names a host or
  a scheme (`*127.0.0.1:<port>*`, `http://…/scheme*`, a `^http://` regex, a
  star-less substring) parks a real request on a real core: the UPSTREAM record is
  empty while the flow is parked and has the request after `flow.resume`; a rule
  naming another host leaves the request unpaused (`observed`, 200).
- **test_per_host_decryption.py** — Scope is the decryption list, on a real core
  booted with an EMPTY scope: an HTTPS request to an out-of-scope origin is
  tunnelled, not decrypted (`curl --cacert <aitm ca>` fails to verify because the
  client saw the ORIGIN's own cert; `curl -k` gets the origin's marker) and the bus
  holds one `CONNECT` row per connection (one after the first curl, two after the
  second), all `tunnel == "passthrough"`, `tunnel_reason == "out_of_scope"`,
  status 200, `bytes_up`/`bytes_down` > 0, `duration_ms` set once the client
  closed — never a decrypted `GET` row;
  `scope.add` flips the NEXT connection live (a `decrypted` CONNECT row plus a
  `GET` row with `passive == false`; the earlier passthrough row is untouched);
  `scope.remove` flips it back (a new `passthrough` row, no new `GET`); a client
  that refuses the aitm CA on an in-scope host is a `CONNECT` row with
  `tunnel == "failed"`, `tunnel_reason == "client_rejected_certificate"`, status
  null and `duration_ms` set; plain HTTP to an out-of-scope origin is captured
  with `passive == true` and an armed breakpoint rule naming it does NOT park it
  (the UPSTREAM record has the request at once, `proxy.status.paused == 0`), while
  after `scope.add` the same request IS parked until `flow.resume` and its row has
  `passive == false`; `proxy.status.decrypt` reads back `decrypting false` with
  the exact advice sentence on the empty scope and `decrypting true`, `advice`
  null, after `scope.add`; a `flow.subscribe` on the operator connection receives
  the passthrough row as `created` then `response`, both carrying
  `tunnel == "passthrough"`.

## The kill-503 regression

`flow.kill {mode:"429"|"503"}` on a parked request used to hang keep-alive HTTP/1
clients: the synthesized abort response went out with no `Content-Length` and no
`Transfer-Encoding`, so the client waited forever for a body end that never came.
Fixed in `aitm-plugins` `set_short_circuit` (now sets `Content-Length: 0`);
`test_intercept_replay.py` guards it (was a client hang, now 503). Deeper encoder
hardening (frame *every* empty response) is flagged to the `http1-path-hardening`
owner.

## Config extension

`_clients.ProxyConfig` subclasses the shared `CoreConfig` to add `ssl_insecure`
(trust the self-signed upstream) and a per-run `ca_dir` (so `curl --cacert` has a
deterministic `ca.crt`). These two knobs are expected to move onto `CoreConfig`
when the TLS client helper lands in `aitm_e2e.tls`.
