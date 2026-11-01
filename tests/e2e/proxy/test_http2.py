#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=node needs=curl
"""HTTP/2 over TLS: capture, mutation, and no protocol-downgrade surprise.

A real node HTTP/2 (+ HTTP/1.1) upstream, a real curl client, a real aitm between.
  - curl --http2 negotiates h2 with the proxy AND the proxy negotiates h2 with the
    upstream (the echo reports the upstream ALPN); the decrypted flow is captured;
  - an http/1.1-only client is served http/1.1 end to end, not forced onto h2;
  - an intercepted h2 request is mutated and the mutation reaches the upstream.
"""
import json
import sys
import threading
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

import _clients as c  # noqa: E402


def main() -> int:
    if not c.have("curl"):
        skip("curl is required for the TLS/ALPN client")
    if not c.have("node"):
        skip("node is required for the real HTTP/2 upstream")
    if not c.have("openssl"):
        skip("openssl is required to mint the upstream certificate")

    work = tempfile.mkdtemp(prefix="proxy-e2e-h2-")
    crt, key = c.upstream_cert(work)
    h2_port = free_port()
    h2_proc = c.start_h2_upstream(crt, key, h2_port)
    h2_auth = f"127.0.0.1:{h2_port}"
    ca_dir = c.new_ca_dir()
    core = None
    bus = None
    try:
        section("boot: real aitm + real node HTTP/2 upstream (dual-protocol)")
        cfg = c.ProxyConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[h2_auth, "127.0.0.1"],
            ca_dir=ca_dir,
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        proxy = f"http://127.0.0.1:{cfg.proxy_port}"
        base = ["--cacert", c.ca_cert(ca_dir), "-x", proxy]
        ok(f"proxy {proxy}, h2 upstream {h2_auth}")

        section("h2 end to end: both sides on HTTP/2, decrypted capture")
        rc, out, err = c.curl([*base, "--http2", f"https://{h2_auth}/h2get"])
        echoed = json.loads(out) if rc == 0 and out else {}
        check(rc == 0 and echoed.get("path") == "/h2get" and echoed.get("alpn") == "h2",
              f"upstream received the request over HTTP/2 (ALPN h2) "
              f"(rc={rc} alpn={echoed.get('alpn')} err={err[:160]})")
        rc2, ver, _ = c.curl_http_version([*base, "--http2", f"https://{h2_auth}/h2ver"])
        check(rc2 == 0 and ver == "2",
              f"curl spoke HTTP/2 to the proxy (client side is h2) (http_version={ver})")
        d = c.detail(bus, c.find_flow(bus, path="/h2get"))
        check(d and d["request"]["path"] == "/h2get" and b'"/h2get"' in c.resp_body(d),
              "proxy captured the decrypted h2 request/response")

        section("no downgrade surprise: a 1.1-only client stays on http/1.1")
        rc3, ver3, err3 = c.curl_http_version([*base, "--http1.1", f"https://{h2_auth}/oneone"])
        check(rc3 == 0 and ver3 == "1.1",
              f"an http/1.1 client is served http/1.1 end to end (http_version={ver3} err={err3[:120]})")
        rc4, out4, _ = c.curl([*base, "--http1.1", f"https://{h2_auth}/oneone-body"])
        e4 = json.loads(out4) if rc4 == 0 and out4 else {}
        check(rc4 == 0 and e4.get("alpn") in ("http/1.1", None, False),
              f"upstream saw http/1.1 for the 1.1 client (mirrored, not forced to h2) "
              f"(alpn={e4.get('alpn')})")

        section("h2 intercept -> mutate -> resume reaches the upstream")
        armed = bus.call("flow.intercept", {"enabled": True,
                         "rules": [{"phase": "request", "url": "*/h2mutate*"}]})
        check(isinstance(armed, dict) and armed.get("enabled") is True, "flow.intercept armed")
        result = {}

        def paused():
            result["rc"], result["out"], result["err"] = c.curl(
                [*base, "--http2", "-H", "x-orig: client", f"https://{h2_auth}/h2mutate"], timeout=30)

        t = threading.Thread(target=paused)
        t.start()
        pid = c.wait_for(lambda: c.find_flow(
            bus, pred=lambda s: s.get("intercept") == "intercepted"
            and "h2mutate" in (s.get("path") or "")), tries=150, delay=0.1)
        check(pid is not None, "the h2 request parks under intercept")
        bus.call("flow.mutate", {"id": pid, "edits": {"headers": {"x-injected": "by-operator"}}})
        bus.call("flow.resume", {"id": pid})
        t.join(timeout=20)
        echoed = {}
        try:
            echoed = json.loads(result.get("out", b""))
        except Exception:  # noqa: BLE001
            pass
        check(result.get("rc") == 0
              and echoed.get("headers", {}).get("x-injected") == "by-operator",
              f"the upstream received the MUTATED h2 header "
              f"(rc={result.get('rc')} err={result.get('err', '')[:120]})")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        h2_proc.terminate()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
