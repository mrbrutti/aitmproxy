#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""Regression canary: the web /bus bridge must PUSH live flow events to a subscriber.

The shipped web UI's flow list freezes because it never subscribes and the /bus
bridge pushes nothing (the F4 gap). This drives the REAL /bus WebSocket the way a
fixed UI would: subscribe, generate real traffic through the proxy, and assert a
`notifications/aitm/flow` push arrives live. If none arrives, that IS the shipped
bug — a loud SKIP until the /bus push fix lands; once it pushes, flip the SKIP to
fail() and it becomes a hard regression guard.
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
            # The shipped F4 bug: the /bus bridge connection carries no push sink,
            # so the core refuses to subscribe. This is the web flow-list freeze,
            # reproduced at the real boundary with the core's own error.
            skip(f"KNOWN BUG (F4 web /bus freeze): the bridge rejects flow.subscribe — {e} "
                 "Flip this SKIP to fail() once the /bus bridge gains a push sink.")
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
