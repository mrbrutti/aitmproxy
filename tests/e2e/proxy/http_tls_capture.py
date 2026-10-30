#!/usr/bin/env python3
"""HTTP/1.1 and HTTPS (TLS MITM) capture, with gzip and chunked bodies.

Proves, against a real aitm and real curl:
  - a plain HTTP/1.1 request is captured with the right method/status/headers/body;
  - an HTTPS request is MITM'd: curl trusts the aitm leaf, gets the upstream's
    real response, AND the proxy captured the DECRYPTED request and response;
  - a gzip response is forwarded intact and captured decodably;
  - a chunked response is reassembled correctly on both the client and the proxy.
"""
import json
import gzip
import hashlib
import sys

import _harness as h


def main():
    work = h.tempfile.mkdtemp(prefix="proxy-e2e-tls-")
    crt, key = h.upstream_cert(work)
    http_srv, http_port = h.start_http_echo()
    https_srv, https_port = h.start_https_echo(crt, key)
    http_auth = f"127.0.0.1:{http_port}"
    https_auth = f"127.0.0.1:{https_port}"

    with h.Rig([http_auth, https_auth]) as rig:
        ca = rig.ca_cert()

        # 1. plain HTTP/1.1 capture
        rc, out, err = h.curl(["-x", f"http://{rig.proxy}",
                               "-H", "x-probe: plain",
                               f"http://{http_auth}/first"])
        echoed = json.loads(out) if rc == 0 and out else {}
        h.check("plain HTTP/1.1: curl reaches the upstream through the proxy",
                rc == 0 and echoed.get("path") == "/first" and echoed["headers"].get("x-probe") == "plain",
                f"rc={rc} err={err[:200]} out={out[:200]}")
        fid = h.find_flow(rig.bus, path="/first")
        d = h.flow_detail(rig.bus, fid) if fid else None
        h.check("plain HTTP/1.1: proxy captured method/status/path",
                d and d["request"]["method"] == "GET" and d["response"]["status"] == 200
                and d["request"]["path"] == "/first",
                str(d)[:200] if d else "no flow")
        h.check("plain HTTP/1.1: captured request header + response body",
                d and h.req_headers(d).get("x-probe") == "plain"
                and b'"x-probe": "plain"' in h.resp_body_bytes(d),
                str(d)[:300] if d else "no flow")

        # 2. HTTPS TLS MITM: curl trusts the aitm leaf and gets the real body
        rc, out, err = h.curl(["--cacert", ca, "-x", f"http://{rig.proxy}",
                               "-H", "x-probe: tls",
                               f"https://{https_auth}/secure"])
        echoed = json.loads(out) if rc == 0 and out else {}
        h.check("HTTPS: curl completes the MITM'd TLS handshake and gets the body",
                rc == 0 and echoed.get("path") == "/secure",
                f"rc={rc} err={err[:200]} out={out[:200]}\n{rig.log_tail(15)}")
        fid = h.find_flow(rig.bus, path="/secure")
        d = h.flow_detail(rig.bus, fid) if fid else None
        h.check("HTTPS: proxy DECRYPTED and captured the request",
                d and d["request"]["path"] == "/secure" and d["client_conn"]["tls"] is True
                and h.req_headers(d).get("x-probe") == "tls",
                str(d)[:300] if d else "no flow")
        h.check("HTTPS: proxy DECRYPTED and captured the response body",
                d and b'"x-probe": "tls"' in h.resp_body_bytes(d),
                h.resp_body_bytes(d)[:200] if d else "no flow")

        # 3. HTTPS POST with a body: the decrypted request body is captured
        rc, out, err = h.curl(["--cacert", ca, "-x", f"http://{rig.proxy}",
                               "-X", "POST", "--data-binary", "secret-payload-42",
                               f"https://{https_auth}/post"])
        echoed = json.loads(out) if rc == 0 and out else {}
        h.check("HTTPS POST: upstream received the body through the MITM",
                rc == 0 and echoed.get("body") == "secret-payload-42",
                f"rc={rc} out={out[:200]}")
        fid = h.find_flow(rig.bus, path="/post")
        d = h.flow_detail(rig.bus, fid) if fid else None
        h.check("HTTPS POST: proxy captured the DECRYPTED request body",
                d and h.req_body_bytes(d) == b"secret-payload-42",
                h.req_body_bytes(d)[:80] if d else "no flow")

        # 4. gzip response: forwarded intact + captured decodably
        rc, out, err = h.curl(["--cacert", ca, "-x", f"http://{rig.proxy}", "--compressed",
                               f"https://{https_auth}/gzip"])
        decoded = json.loads(out) if rc == 0 and out else {}
        h.check("gzip: curl --compressed decodes the forwarded body",
                rc == 0 and decoded.get("path") == "/gzip",
                f"rc={rc} out={out[:160]}")
        fid = h.find_flow(rig.bus, path="/gzip")
        d = h.flow_detail(rig.bus, fid) if fid else None
        cap = h.resp_body_bytes(d) if d else b""
        enc = h.resp_headers(d).get("content-encoding") if d else None
        # the captured body should still be the gzip stream and decode to the echo
        gz_ok = False
        try:
            gz_ok = b'"/gzip"' in gzip.decompress(cap)
        except Exception:  # noqa: BLE001
            gz_ok = False
        h.check("gzip: proxy captured the gzip body intact (content-encoding preserved)",
                enc == "gzip" and gz_ok, f"enc={enc} len={len(cap)}")

        # 5. chunked response: reassembled on both sides
        rc, out, err = h.curl(["--cacert", ca, "-x", f"http://{rig.proxy}",
                               f"https://{https_auth}/chunked"])
        decoded = json.loads(out) if rc == 0 and out else {}
        h.check("chunked: curl reassembles the chunked body correctly",
                rc == 0 and decoded.get("path") == "/chunked",
                f"rc={rc} out={out[:160]}")
        fid = h.find_flow(rig.bus, path="/chunked")
        d = h.flow_detail(rig.bus, fid) if fid else None
        body = h.resp_body_bytes(d) if d else b""
        ok_json = False
        try:
            ok_json = json.loads(body).get("path") == "/chunked"
        except Exception:  # noqa: BLE001
            ok_json = False
        h.check("chunked: proxy captured the reassembled body (no chunk framing left)",
                ok_json, body[:160])

    h.done()


if __name__ == "__main__":
    main()
