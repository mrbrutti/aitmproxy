# L7 proxy end-to-end tests

Black-box proof that aitmproxy's L7 proxy works against **real traffic**: a real
`aitm` binary MITMing real clients (curl, a stdlib RFC6455 WebSocket client, a
node HTTP/2 client) talking to real upstream servers. Every claim is checked
twice — once on what the client observed, once on what the proxy captured on its
MCP bus (the decrypted flow). These found and now guard a real hang bug
(`flow.kill mode=429|503`, see below).

Why real traffic: green fixture/snapshot tests have let broken builds ship. These
tests exercise the shipping binary end to end, so a regression shows up here.

## Running

Each script boots its own `aitm` on dedicated free loopback ports (it will not
collide with a running app or sibling sessions) and exits non-zero on any failed
check. They bind ports, so run them in a real shell, not a sandbox.

```bash
cargo build -p aitm                     # build target/debug/aitm first
python3 tests/e2e/proxy/http_tls_capture.py   # HTTP/1.1 + HTTPS (TLS MITM) + gzip/chunked
python3 tests/e2e/proxy/http2_capture.py      # HTTP/2 (needs node) capture + mutate + no-downgrade
python3 tests/e2e/proxy/websocket.py          # WebSocket frames both ways + ws.send injection
python3 tests/e2e/proxy/intercept_replay.py   # intercept/mutate/resume + replay + request.send + kill
```

Requirements: `curl` with HTTP/2 (`curl --version` shows `nghttp2`), `openssl`
(upstream cert), and `node` (the HTTP/2 upstream; Python stdlib has no h2 server).
No Python packages — stdlib only.

## What each script proves

- **http_tls_capture.py** — a plain HTTP/1.1 request is captured with the right
  method/status/headers/body; an HTTPS request is MITM'd (curl trusts the aitm
  leaf, gets the real body) and the proxy captured the DECRYPTED request and
  response; a gzip response is forwarded intact and captured decodably; a chunked
  response is reassembled on both the client and the proxy.
- **http2_capture.py** — h2 end to end (upstream and client both on h2, captured
  decrypted); no downgrade surprise either way (an http/1.1-only client is served
  http/1.1, mirrored to the upstream); an intercepted h2 request is mutated and
  the edit reaches the upstream.
- **websocket.py** — the upgrade is proxied and handed off; frames both
  directions are captured; `ws.send` s2c reaches the client; `ws.send` c2s reaches
  the server (confirmed by the server's own record), and injected frames are
  recorded on the flow.
- **intercept_replay.py** — request-phase park → rewrite path/headers/body →
  resume, with the UPSTREAM echo confirming the mutation crossed the proxy;
  response-phase park → rewrite status/body → resume, with the CLIENT receiving
  the edit; `flow.replay` re-issues and captures; `request.send` captures and is
  scope-gated; `flow.kill mode=503` fails the client request with 503.

## The driver

`_harness.py` boots `aitm` (writing a config with a loopback proxy and an MCP
bus), connects to the bus as the **operator** (presenting `mcp.operator_token`,
the way the web/TUI/macOS operator does, so sensitive commands like intercept and
kill run), stands up the upstream echo servers, and exposes ground-truth helpers
(`find_flow`, `flow_detail`). `h2_upstream.mjs` is a node HTTP/2 + HTTP/1.1
echo-record origin.

## Alignment with the shared runner

The shared `tests/e2e/` runner and `aitm_e2e` library (PR #110) land separately.
Once it is on `main`, these scenarios should be ported to
`tests/e2e/proxy/test_*.py` on `aitm_e2e` (reusing its `Aitm`/`BusClient`/
`Upstream`), keeping the real curl / RFC6455-WS / h2 clients here that the shared
`via_proxy` helper does not cover (TLS-MITM ALPN, WebSocket frame injection).
Until then these scripts are self-contained and named so the shared runner's
`test_*.py` glob skips them.
