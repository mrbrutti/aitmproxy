#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""Future guard: the web /bus bridge should PUSH live flow events to a subscriber.

Note on the shipped un-freeze: PR #124 fixed the user-visible freeze CLIENT-SIDE
(apps/web polls flow.list) — guarded here by test_bus_poll_reflects_traffic.py —
NOT by adding push to the bridge. So flow.subscribe over /bus is still refused and
this canary stays a loud SKIP. Push-over-bridge (a per-connection NotificationSink
drained onto the WS) is a separate, larger change on top of PR #103 (the
concurrent-frames rewrite of the /bus relay loop). This canary drives the real
/bus WebSocket the way a push-capable UI would — subscribe, generate traffic,
expect a `notifications/aitm/flow` push — and auto-flips from SKIP to PASS the
moment that lands; flip the SKIP to fail() then to make it a hard guard.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402


def main() -> int:
    up = Upstream().start()
    core = None
    ws = None
    try:
        section("boot aitm web + upstream (upstream in scope)")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        ok(f"aitm web on :{core.web_port}, proxy :{cfg.proxy_port}, upstream {up.base}")

        section("subscribe to flows over the REAL /bus WebSocket bridge (as the UI should)")
        ws = WsBusClient.web_agent(core)
        try:
            sub = ws.call("flow.subscribe", {})
        except ToolError as e:
            # Push-over-bridge gap: the /bus bridge connection carries no push sink,
            # so the core refuses to subscribe, reproduced at the real boundary with
            # the core's own error. The shipped un-freeze (PR #124) is client-side
            # polling (see test_bus_poll_reflects_traffic), not push.
            skip(f"DESIGN GAP (push-over-bridge): the /bus bridge rejects flow.subscribe — {e} "
                 "Shipped un-freeze is client-side polling (PR #124); push-over-bridge is a "
                 "separate change on PR #103. Flip this SKIP to fail() when the bridge gains a sink.")
        ok(f"flow.subscribe over /bus succeeded: {sub}")

        section("generate real traffic, then wait for a LIVE push")
        resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}/echo?x=stream")
        check(resp.status == 200, f"traffic through the proxy returned {resp.status}")
        note = ws.wait_notification("notifications/aitm/flow", timeout=8)
        if note:
            ok(f"/bus pushed a live flow notification: {note.get('method')}")
            ok("web live-streaming works over /bus — regression guarded")
        else:
            skip("KNOWN BUG (F4 web /bus freeze): /bus accepted flow.subscribe but pushed no "
                 "notifications/aitm/flow within 8s under live traffic. Flip this SKIP to "
                 "fail() once the /bus push path works.")
    finally:
        if ws:
            ws.close()
        if core:
            core.stop()
        up.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
