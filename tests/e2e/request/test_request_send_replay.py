#!/usr/bin/env python3
# e2e: tier=T1 surface=request
"""`request.send` crafts an HTTP request, re-issues it THROUGH the proxy's guarded
client, and captures a brand-new flow carrying the REAL upstream response.

Ground truth, never fixtures:

  1. INDEPENDENT OBSERVER — the crafted request reaches the real upstream. We read
     the echo-record origin's OWN log (`Upstream.received`), not the proxy's view of
     what it forwarded, and match the exact crafted method / path / header / body.
  2. A GENUINELY NEW FLOW — the id `request.send` returns was absent from the flow
     store before the call and present after it (we diff `flow.list`).
  3. THE REAL RESPONSE — `flow.detail` on the new id carries status 200 and a body
     that, decoded, is the upstream's OWN deterministic echo (observed_by +
     round-tripped path/body). That ties the captured response to the live origin,
     not to any frozen expectation.
  4. THE GUARD IS REAL — the same call to an out-of-scope authority is REFUSED,
     proving the capture crossed the real scope/rate chokepoint, not a bypass.

Boots a real `aitm` core (proxy + MCP bus) and a real loopback upstream; asserts
over the MCP bus as the operator. No fixtures, no mocks, no frozen bytes.
"""
import base64
import json
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402


def flow_ids(result) -> set:
    """The ids in a flow.list result, whatever envelope the surface uses."""
    if isinstance(result, dict):
        for key in ("flows", "ids", "items"):
            if key in result:
                result = result[key]
                break
    if isinstance(result, list):
        return {i.get("id", i) if isinstance(i, dict) else i for i in result}
    return set()


def wait_for(fn, tries: int = 80, delay: float = 0.1):
    for _ in range(tries):
        v = fn()
        if v:
            return v
        time.sleep(delay)
    return None


def req_header(detail: dict, name: str) -> str | None:
    for k, v in detail.get("request", {}).get("headers", []):
        if k.lower() == name.lower():
            return v
    return None


def main() -> int:
    up = Upstream().start()
    core = None
    bus = None
    try:
        section("boot: real aitm core + real loopback echo-record upstream (in scope)")
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            # The upstream IP literal + authority in scope lifts the loopback SSRF
            # guard exactly as the browser connector / flow.replay path requires.
            scope_entries=[up.authority, "127.0.0.1"],
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        tools = bus.tool_names()
        if "request.send" not in tools:
            skip(f"request.send not registered by this core (tools={len(tools)})")
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, upstream {up.base}, request.send present")

        # A nonce makes every assertion unambiguous: this exact request, this run.
        nonce = secrets.token_hex(8)
        crafted = {
            "authority": up.authority,
            "method": "POST",
            "path": f"/replay-target?probe={nonce}",
            "headers": {"x-aitm-e2e": nonce},
            "body": f"crafted-body-{nonce}",
        }

        section("baseline: capture the flow store before the send")
        before = flow_ids(bus.call("flow.list"))
        ok(f"{len(before)} flow(s) captured before request.send")

        section("act: request.send crafts the request and re-issues it through the proxy")
        new_id = bus.call("request.send", crafted)
        check(isinstance(new_id, str) and new_id, f"request.send returned a flow id ({new_id!r})")
        check(new_id not in before, f"the returned flow id is NEW, not a pre-existing flow ({new_id})")

        section("ground truth #1: the independent upstream recorded the crafted request")
        rec = wait_for(lambda: next(
            (r for r in up.received
             if r["method"] == crafted["method"]
             and r["path"] == crafted["path"]), None))
        if not rec:
            fail(f"the upstream never recorded the crafted request "
                 f"(path={crafted['path']!r}); received={up.received!r}")
        check(rec["headers"].get("x-aitm-e2e") == nonce,
              "the crafted header reached the real upstream (observer's own record)")
        check(rec["body"] == crafted["body"],
              f"the crafted body reached the real upstream (body={rec['body']!r})")

        section("ground truth #2: a new flow was captured with the REAL response")
        detail = wait_for(lambda: bus.call("flow.detail", {"id": new_id, "body": "inline"}))
        if not isinstance(detail, dict):
            fail(f"flow.detail returned no object for the captured flow ({detail!r})")
        check(detail.get("kind") == "http", "the captured flow is an HTTP flow")
        check(detail["request"]["method"] == crafted["method"]
              and detail["request"]["path"] == crafted["path"]
              and detail["request"]["authority"] == up.authority,
              "the captured request matches what request.send crafted")
        check(req_header(detail, "x-aitm-e2e") == nonce,
              "the captured request carries the crafted header")

        resp = detail.get("response")
        check(isinstance(resp, dict), "the captured flow carries a response (not parked/empty)")
        check(resp.get("status") == 200, f"the captured response status is the real 200 ({resp.get('status')})")

        # The response body must BE the live upstream's deterministic echo, decoded
        # from the bus base64 — this is what makes it the real response, not a fixture.
        echo = json.loads(base64.b64decode(resp.get("body") or b""))
        check(echo.get("observed_by") == "aitm-e2e-upstream",
              "the captured response body is the live upstream's own echo")
        check(echo.get("path") == crafted["path"] and echo.get("body") == crafted["body"],
              "the echoed response round-trips the crafted path+body (response ties to this request)")

        section("ground truth #3: the new flow is now in the store")
        after = flow_ids(bus.call("flow.list"))
        check(new_id in after, f"the captured flow is listed in flow.list ({new_id})")
        check(after - before, "flow.list grew by at least the new flow")

        section("ground truth #4: the same send out of scope is REFUSED by the real guard")
        status, msg = bus.try_call("request.send", {"authority": "blocked.invalid", "path": "/"})
        check(status == "error",
              f"request.send to an out-of-scope authority is refused by the proxy guard ({msg!r})")
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
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
