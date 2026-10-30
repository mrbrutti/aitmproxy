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
