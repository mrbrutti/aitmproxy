#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""web/web_flow_detail -- the web UI's flow detail shows the REAL request/response
headers and the body of a flow the proxy actually carried, over the `/bus` bridge.

The inspector (apps/web/src/state/app.ts loadDetail -> bus/normalize.ts toDetail) is
one call, `flow.detail {id}`, over the `/bus` bridge `aitm web` serves: headers as
[name, value] pairs, bodies as base64 `body` beside `body_size`. This test drives two
real flows through the REAL proxy to its own seeded aitm-testtarget and checks what
the inspector fetches over /bus against what the real client sent and received, and
against the loopback bus's own view of the same id -- never a fixture:

  * GET  /search?q=<tag> with an X-E2E-Marker header: the captured request carries the
    header verbatim; the captured status, content-type and every end-to-end response
    header are the ones the client got; the captured body is byte-for-byte the HTML the
    client read (the testtarget's own rendering of <tag>);
  * POST /comments?t=<tag> with a form body: the captured request body is the exact
    bytes sent; the captured 302 carries the Location the client saw, with no body.

Converted from the dead _lib/mcp draft harness onto the canonical aitm_e2e lib: it
self-boots `aitm web` + a seeded Target on free ports (loopback bus pinned, since
aitm web has no --bus-endpoint-file), reads flow.detail over the real /bus bridge
(the inspector's own transport) AND over the loopback bus (the witness), and asserts
they agree. An http target means plaintext capture (client_conn.tls=false); the
https/TLS-MITM path is exercised by proto/test_tls_sni_alpn + the passthrough suite.
Soft-assertion battery; exit 0 pass / 1 fail / 77 skip.
"""
from __future__ import annotations

import base64
import http.client
import ssl
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402

# Framing and hop-by-hop headers legitimately differ between the upstream leg the
# core records and the client leg; everything else must reach the client untouched.
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length"}
BODY_WAIT = 10.0  # a body still streaming is `null`; the client has already read it all

_failures: list[str] = []


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:200]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


class Got:
    """What the real client observed: status, headers (lower-cased names), body bytes."""

    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body


def fetch(proxy_addr, url, method="GET", headers=None, body=None, cadata=None, timeout=20.0):
    """One real request THROUGH the proxy. http: absolute-URI proxy form. https: a CONNECT
    tunnel, then TLS to whatever leaf the proxy presents, verified against `cadata` only."""
    u = urllib.parse.urlsplit(url)
    phost, _, pport = proxy_addr.rpartition(":")
    hdrs_ = {"Host": u.netloc, **(headers or {})}
    if u.scheme == "https":
        ctx = ssl.create_default_context(cadata=cadata) if cadata else ssl._create_unverified_context()  # noqa: SLF001
        conn = http.client.HTTPSConnection(phost, int(pport), timeout=timeout, context=ctx)
        conn.set_tunnel(u.hostname, u.port or 443)
        target = u.path + (f"?{u.query}" if u.query else "")
    else:
        conn = http.client.HTTPConnection(phost, int(pport), timeout=timeout)
        target = url
    try:
        conn.request(method, target, body=body, headers=hdrs_)
        r = conn.getresponse()
        return Got(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
    finally:
        conn.close()


def hdrs(msg):
    """`flow.detail` headers as the inspector reads them (normalize.ts headersOf): a list of
    [name, value] string pairs. Returns {lower-name: value}, or None when the shape is off."""
    raw = (msg or {}).get("headers")
    if not isinstance(raw, list) or not all(
        isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in raw
    ):
        return None
    return {n.lower(): v for n, v in raw}


def body_bytes(msg):
    raw = (msg or {}).get("body")
    return base64.b64decode(raw) if isinstance(raw, str) else None


def wait_detail(client, fid, timeout=BODY_WAIT):
    """`flow.detail {id}` -- the inspector's exact call -- once the response is stored. A
    200 streams its body after the head, so we wait for the body; a bodyless response
    (e.g. a 302) is complete the moment its status lands."""
    deadline = time.monotonic() + timeout
    d = {}
    while time.monotonic() < deadline:
        d = client.call("flow.detail", {"id": fid})
        resp = d.get("response") or {}
        if resp.get("status") is not None and (resp.get("status") != 200 or resp.get("body") is not None):
            return d
        time.sleep(0.2)
    return d


def wait_for_flow(bus, pred, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in bus.call("flow.table").get("flows", []):
            if pred(row):
                return row
        time.sleep(0.15)
    fail(f"the loopback bus never listed a flow matching our marker within {timeout:.0f}s")
    raise AssertionError("unreachable")


def check_flow(label, shown, core, got, method, scheme, authority, path, sent_hdrs, sent_body, named):
    """`shown` is what the inspector fetched over /bus; `core` the loopback bus's view of the
    same id; `got` what the real client observed; `named` a response header a human reads."""
    req, resp = shown.get("request") or {}, shown.get("response") or {}
    ident = (shown.get("kind"), req.get("method"), req.get("scheme"), req.get("authority"), req.get("path"))
    expect(ident == ("http", method, scheme, authority, path), f"{label}: detail is the flow we sent", ident)

    rh, sh = hdrs(req), hdrs(resp)
    expect(rh is not None and sh is not None,
           f"{label}: request + response headers are [name, value] pairs (what the inspector renders)",
           (req.get("headers"), resp.get("headers")))
    rh, sh = rh or {}, sh or {}
    missing = {k: rh.get(k.lower()) for k, v in sent_hdrs.items() if rh.get(k.lower()) != v}
    expect(not missing and rh.get("host") == authority, f"{label}: request headers show exactly what the client sent",
           missing or {"host": rh.get("host")})
    rb = body_bytes(req)
    expect((rb or b"") == sent_body and (req.get("body_size") or 0) == len(sent_body),
           f"{label}: request body is the exact {len(sent_body)} bytes sent",
           (rb[:80] if rb is not None else rb, req.get("body_size")))

    expect(resp.get("status") == got.status, f"{label}: response status is the client's ({got.status})", resp.get("status"))
    e2e = {k: v for k, v in sh.items() if k not in HOP_BY_HOP}
    mismatch = {k: (v, got.headers.get(k)) for k, v in e2e.items() if got.headers.get(k) != v}
    expect(bool(e2e) and not mismatch, f"{label}: every end-to-end response header shown is one the client received",
           mismatch or e2e)
    expect(sh.get(named) is not None and sh.get(named) == got.headers.get(named), f"{label}: {named} shown is the client's",
           (sh.get(named), got.headers.get(named)))
    body = body_bytes(resp)
    expect((body or b"") == (got.body or b"") and (resp.get("body_size") or 0) == len(got.body or b""),
           f"{label}: response body is byte-for-byte the {len(got.body)} bytes the client read",
           (body[:80] if body is not None else body, resp.get("body_size")))

    tls = (shown.get("client_conn") or {}).get("tls")
    expect(isinstance(tls, bool) and tls == (scheme == "https"),
           f"{label}: client_conn.tls reports {'TLS MITM' if scheme == 'https' else 'plaintext'}", tls)
    if core is not shown:
        same = (shown.get("request"), shown.get("response")) == (core.get("request"), core.get("response"))
        expect(same, f"{label}: the bridge's detail equals the core's own over the loopback bus", "request/response differ")


def main() -> int:
    tgt = Target("vulnerable")  # http seeded origin: /search reflects q, /comments 302+stores
    core = bus = ui = None
    try:
        section("boot: aitm web + seeded target; witness on the loopback bus, inspector over /bus")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         bus_port=free_port(), scope_entries=[tgt.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        target = tgt.base.rstrip("/")
        u = urllib.parse.urlsplit(target)
        scheme, authority = u.scheme, u.netloc
        proxy_addr = f"127.0.0.1:{cfg.proxy_port}"

        bus = BusClient("127.0.0.1", cfg.bus_port, cfg.agent_token, client_name="aitm-e2e-witness").connect()
        expect("flow.detail" in bus.tool_names(), "the core registers flow.detail (the inspector's call)")
        ui = WsBusClient("127.0.0.1", core.web_port, cfg.agent_token, client_name="aitm-web").connect()
        names = {t["name"] for t in ui.tools()}
        expect("flow.detail" in names, "bridge: tools/list over /bus advertises flow.detail", sorted(names)[:12])
        how = f"the web /bus bridge at 127.0.0.1:{core.web_port}"

        tag = f"wfd-{uuid.uuid4().hex[:8]}"
        get_path = f"/search?q={tag}"
        post_path = f"/comments?t={tag}"  # the testtarget ignores the query; it is how the flow is found
        get_hdrs = {"X-E2E-Marker": tag}
        post_hdrs = {"X-E2E-Marker": tag, "Content-Type": "application/x-www-form-urlencoded"}
        post_body = f"comment={tag}".encode()

        section("real traffic through the proxy (the client's view is the ground truth)")
        g = fetch(proxy_addr, target + get_path, headers=get_hdrs)
        p = fetch(proxy_addr, target + post_path, "POST", headers=post_hdrs, body=post_body)
        expect(g.status == 200 and tag.encode() in g.body, "proxy: GET /search answered 200 with the marker rendered by the target", (g.status, g.body[:120]))
        expect(300 <= p.status < 400 and bool(p.headers.get("location")), "proxy: POST /comments answered a redirect with Location", (p.status, p.headers.get("location")))

        get_row = wait_for_flow(bus, lambda f: tag in (f.get("path") or "") and f.get("method") == "GET")
        post_row = wait_for_flow(bus, lambda f: tag in (f.get("path") or "") and f.get("method") == "POST")

        section(f"flow.detail over {how} vs the loopback bus (they must agree, both matching the client)")
        for label, fid, got, method, path, sent_hdrs_, sent_body_, named in (
            ("GET", get_row["id"], g, "GET", get_path, get_hdrs, b"", "content-type"),
            ("POST", post_row["id"], p, "POST", post_path, post_hdrs, post_body, "location"),
        ):
            corev = wait_detail(bus, fid)
            shown = wait_detail(ui, fid)
            check_flow(label, shown, corev, got, method, scheme, authority, path, sent_hdrs_, sent_body_, named)
    finally:
        for c in (bus, ui):
            if c:
                c.close()
        if core:
            core.stop()
        tgt.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: flow detail over the /bus bridge showed the real headers + plaintext bodies, matching the client and the loopback bus")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
