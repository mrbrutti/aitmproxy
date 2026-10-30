#!/usr/bin/env python3
"""HTTP/2 over TLS: capture, mutation, and no protocol-downgrade surprise.

A real node HTTP/2 upstream, a real curl client, a real aitm in between.
  - curl --http2 negotiates h2 with the proxy AND the proxy negotiates h2 with
    the upstream (the echo reports the upstream's ALPN) — the proxy captures the
    decrypted h2 request/response;
  - a client that offers only http/1.1 is served http/1.1 end to end, not forced
    onto h2 (no downgrade/upgrade surprise);
  - an intercepted h2 request can be mutated and the mutation reaches the upstream.
"""
import json
import sys

import _harness as h


def http_version(args):
    rc, out, err = h.curl(args + ["-o", "/dev/null", "-w", "%{http_version}"])
    return rc, out.decode().strip(), err


def main():
    work = h.tempfile.mkdtemp(prefix="proxy-e2e-h2-")
    crt, key = h.upstream_cert(work)
    h2_port = h.free_port()
    h2_proc = h.start_h2_upstream(crt, key, h2_port)
    h2_auth = f"127.0.0.1:{h2_port}"

    try:
        with h.Rig([h2_auth]) as rig:
            ca = rig.ca_cert()
            base = ["--cacert", ca, "-x", f"http://{rig.proxy}"]

            # 1. end-to-end h2: body + both-side protocol
            rc, out, err = h.curl(base + ["--http2", f"https://{h2_auth}/h2get"])
            echoed = json.loads(out) if rc == 0 and out else {}
            h.check("h2: upstream received the request over HTTP/2 (ALPN h2)",
                    rc == 0 and echoed.get("path") == "/h2get" and echoed.get("alpn") == "h2",
                    f"rc={rc} alpn={echoed.get('alpn')} err={err[:200]}\n{rig.log_tail(15)}")
            rc2, ver, _ = http_version(base + ["--http2", f"https://{h2_auth}/h2ver"])
            h.check("h2: curl spoke HTTP/2 to the proxy (client side is h2, no downgrade)",
                    rc2 == 0 and ver == "2", f"rc={rc2} http_version={ver}")

            fid = h.find_flow(rig.bus, path="/h2get")
            d = h.flow_detail(rig.bus, fid) if fid else None
            h.check("h2: proxy captured the decrypted h2 request/response",
                    d and d["request"]["path"] == "/h2get"
                    and b'"/h2get"' in h.resp_body_bytes(d),
                    str(d)[:200] if d else "no flow")

            # 2. no-downgrade the other way: a 1.1-only client stays on 1.1
            rc3, ver3, err3 = http_version(base + ["--http1.1", f"https://{h2_auth}/oneone"])
            h.check("no-downgrade: an http/1.1 client is served http/1.1 end to end",
                    rc3 == 0 and ver3 == "1.1", f"rc={rc3} http_version={ver3} err={err3[:160]}")
            # the upstream echo for that request must report it negotiated http/1.1
            rc4, out4, _ = h.curl(base + ["--http1.1", f"https://{h2_auth}/oneone-body"])
            e4 = json.loads(out4) if rc4 == 0 and out4 else {}
            h.check("no-downgrade: upstream saw http/1.1 for the 1.1 client (mirrored, not forced to h2)",
                    rc4 == 0 and e4.get("alpn") in ("http/1.1", None, False),
                    f"alpn={e4.get('alpn')}")

            # 3. intercept + mutate an h2 request; the mutation reaches the upstream
            ok, armed = rig.bus.call("flow.intercept", enabled=True,
                                     rules=[{"phase": "request", "url": "*/h2mutate*"}])
            h.check("h2: flow.intercept arms (operator)",
                    ok and (armed is True or (isinstance(armed, dict) and armed.get("enabled") is True)),
                    str(armed))
            result = {}

            def paused():
                rc, out, err = h.curl(base + ["--http2",
                                      "-H", "x-orig: client",
                                      f"https://{h2_auth}/h2mutate"], timeout=30)
                result["rc"], result["out"], result["err"] = rc, out, err
            import threading
            t = threading.Thread(target=paused)
            t.start()
            pid = h.wait_for(lambda: h.find_flow(
                rig.bus, pred=lambda s: s.get("intercept") == "intercepted"
                and "h2mutate" in (s.get("path") or ""), tries=120, delay=0.1))
            h.check("h2: the request parks under intercept", pid is not None,
                    rig.log_tail(10))
            if pid:
                ok, _ = rig.bus.call("flow.mutate", id=pid,
                                     edits={"headers": {"x-injected": "by-operator"}})
                h.check("h2: flow.mutate edits the parked h2 request", ok, str(_))
                ok, _ = rig.bus.call("flow.resume", id=pid)
                h.check("h2: flow.resume releases it", ok, str(_))
            t.join(timeout=20)
            echoed = {}
            try:
                echoed = json.loads(result.get("out", b""))
            except Exception:  # noqa: BLE001
                pass
            h.check("h2: the upstream received the MUTATED header (edit reached the origin)",
                    result.get("rc") == 0 and echoed.get("headers", {}).get("x-injected") == "by-operator",
                    f"rc={result.get('rc')} err={result.get('err','')[:160]} hdrs={list(echoed.get('headers',{}).keys())[:12]}")

        h.done()
    finally:
        h2_proc.terminate()


if __name__ == "__main__":
    main()
