#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy
"""Basic HTTP/1.1 capture, end-to-end, asserted on ground truth at both boundaries.

A real external client sends a request THROUGH the real proxy to a real upstream
echo-record origin. We assert (a) the upstream RECORDED the request (it really
went through the proxy), and (b) the core CAPTURED the flow with the real response
body visible over the bus (flow.list + flow.detail) — neither side is a fixture.
"""

import base64
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

MARKER = "aitm-e2e-upstream"


def flow_ids(result) -> list:
    if isinstance(result, dict):
        for key in ("flows", "ids", "items"):
            if key in result:
                result = result[key]
                break
    if isinstance(result, list):
        out = []
        for item in result:
            if isinstance(item, dict):
                out.append(item.get("id", item))
            else:
                out.append(item)
        return out
    return []


def main() -> int:
    up = Upstream().start()
    core = None
    bus = None
    try:
        section("boot: real upstream + real aitm core (dedicated ports, upstream in scope)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[up.authority, "127.0.0.1"],
        )
        core = Aitm.server(cfg)
        ok(f"proxy on 127.0.0.1:{cfg.proxy_port}, bus on {core.bus_addr}, upstream {up.base}")

        section("act: a real client sends an HTTP request through the proxy")
        url = f"{up.base}/echo?x=hello"
        resp = via_proxy(cfg.proxy_port, "GET", url)
        check(resp.status == 200, f"client got {resp.status} through the proxy (expected 200)")
        check(MARKER in resp.text, "response body round-tripped from the upstream")

        section("ground truth A: the upstream RECORDED the request (it went through)")
        got = [r for r in up.received if r["path"].startswith("/echo")]
        check(len(got) >= 1, f"upstream recorded the GET /echo request ({len(got)} hit(s))")
        if got:
            check(got[0]["method"] == "GET", f"recorded method is GET (was {got[0]['method']})")

        section("ground truth B: the core CAPTURED the flow (bus, real decrypted body)")
        bus = BusClient.agent(core)
        ids = []
        deadline = time.time() + 5
        while time.time() < deadline:
            ids = flow_ids(bus.call("flow.list"))
            if ids:
                break
            time.sleep(0.2)
        check(len(ids) >= 1, f"flow.list shows the captured flow ({len(ids)} flow(s))")
        if not ids:
            fail("no flow captured — cannot inspect detail")
        detail = bus.call("flow.detail", {"id": ids[-1], "body": "inline"})
        req = detail.get("request", {})
        resp = detail.get("response", {})
        check(req.get("path", "").startswith("/echo"),
              f"flow.detail request path is /echo (was {req.get('path')!r})")
        check(resp.get("status") == 200,
              f"flow.detail response status is 200 (was {resp.get('status')!r})")
        # Bodies come back base64-encoded; decode and match the real upstream body.
        body_b64 = resp.get("body") or ""
        decoded = base64.b64decode(body_b64).decode("utf-8", "replace") if body_b64 else ""
        check(MARKER in decoded,
              "flow.detail response body (base64-decoded) is the real upstream body")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
