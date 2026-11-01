#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=curl
"""HTTP/1.1 and HTTPS (TLS MITM) capture, with gzip and chunked bodies.

Real curl through a real aitm, asserted at both boundaries:
  - a plain HTTP/1.1 request reaches the upstream (its own record) and is captured
    on the bus with the right method/status/path and the real response body;
  - an HTTPS request is MITM'd (curl trusts the aitm leaf, gets the real body) AND
    the proxy captured the DECRYPTED request and response;
  - a gzip response is forwarded intact and captured decodably;
  - a chunked response is reassembled on both the client and the proxy.
"""
import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

import _clients as c  # noqa: E402


def main() -> int:
    if not c.have("curl"):
        skip("curl is required for the TLS/ALPN client")
    if not c.have("openssl"):
        skip("openssl is required to mint the upstream certificate")

    work = tempfile.mkdtemp(prefix="proxy-e2e-tls-")
    crt, key = c.upstream_cert(work)
    up = Upstream().start()                      # plain HTTP/1.1 observer
    https_srv, https_port = c.start_https_echo(crt, key)
    https_auth = f"127.0.0.1:{https_port}"
    ca_dir = c.new_ca_dir()
    core = None
    bus = None
    try:
        section("boot: real aitm (ssl_insecure, per-run CA) + plain + TLS upstreams")
        cfg = c.ProxyConfig(
            proxy_port=free_port(),
            scope_entries=[up.authority, https_auth, "127.0.0.1"],
            ca_dir=ca_dir,
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        proxy = f"http://127.0.0.1:{cfg.proxy_port}"
        ca = c.ca_cert(ca_dir)
        ok(f"proxy {proxy}, bus {core.bus_addr}, ca {ca}")

        section("plain HTTP/1.1: capture at both boundaries")
        rc, out, err = c.curl(["-x", proxy, "-H", "x-probe: plain", f"{up.base}/first"])
        check(rc == 0, f"curl reached the upstream through the proxy (rc={rc} err={err[:160]})")
        rec = [r for r in up.received if r["path"] == "/first"]
        check(rec and rec[0]["headers"].get("x-probe") == "plain",
              "upstream RECORDED the request with its header (it really went through)")
        fid = c.find_flow(bus, path="/first")
        d = c.detail(bus, fid) if fid else None
        check(d and d["request"]["method"] == "GET" and d["response"]["status"] == 200,
              "proxy captured method=GET status=200 for /first")

        section("HTTPS: TLS MITM really decrypts")
        rc, out, err = c.curl(["--cacert", ca, "-x", proxy, "-H", "x-probe: tls",
                               f"https://{https_auth}/secure"])
        echoed = json.loads(out) if rc == 0 and out else {}
        check(rc == 0 and echoed.get("path") == "/secure",
              f"curl completed the MITM'd TLS handshake and got the body "
              f"(rc={rc} err={err[:160]})")
        fid = c.find_flow(bus, path="/secure")
        d = c.detail(bus, fid) if fid else None
        check(d and d["client_conn"]["tls"] is True
              and c.req_headers(d).get("x-probe") == "tls",
              "proxy captured the DECRYPTED request (tls=true, header visible)")
        check(d and b'"x-probe": "tls"' in c.resp_body(d),
              "proxy captured the DECRYPTED response body")

        section("HTTPS POST: the decrypted request body is captured")
        rc, out, err = c.curl(["--cacert", ca, "-x", proxy, "-X", "POST",
                               "--data-binary", "secret-payload-42", f"https://{https_auth}/post"])
        echoed = json.loads(out) if rc == 0 and out else {}
        check(rc == 0 and echoed.get("body") == "secret-payload-42",
              "upstream received the POST body through the MITM")
        fid = c.find_flow(bus, path="/post")
        d = c.detail(bus, fid) if fid else None
        check(d and c.req_body(d) == b"secret-payload-42",
              "proxy captured the DECRYPTED request body")

        section("gzip + chunked: forwarded intact, captured decodably")
        rc, out, err = c.curl(["--cacert", ca, "-x", proxy, "--compressed",
                               f"https://{https_auth}/gzip"])
        decoded = json.loads(out) if rc == 0 and out else {}
        check(rc == 0 and decoded.get("path") == "/gzip",
              "curl --compressed decoded the forwarded gzip body")
        d = c.detail(bus, c.find_flow(bus, path="/gzip"))
        cap = c.resp_body(d) if d else b""
        gz_ok = False
        try:
            gz_ok = b'"/gzip"' in gzip.decompress(cap)
        except Exception:  # noqa: BLE001
            gz_ok = False
        check(d and c.resp_headers(d).get("content-encoding") == "gzip" and gz_ok,
              "proxy captured the gzip body intact (content-encoding preserved, decodes)")

        rc, out, err = c.curl(["--cacert", ca, "-x", proxy, f"https://{https_auth}/chunked"])
        decoded = json.loads(out) if rc == 0 and out else {}
        check(rc == 0 and decoded.get("path") == "/chunked",
              "curl reassembled the chunked body correctly")
        d = c.detail(bus, c.find_flow(bus, path="/chunked"))
        ok_json = False
        try:
            ok_json = json.loads(c.resp_body(d)).get("path") == "/chunked"
        except Exception:  # noqa: BLE001
            ok_json = False
        check(ok_json, "proxy captured the reassembled chunked body (no chunk framing left)")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        https_srv.shutdown()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
