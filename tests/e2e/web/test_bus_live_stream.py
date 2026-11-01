#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""Regression guard: the web /bus bridge PUSHES live flow events to a subscriber.

PR #137 wired a per-connection NotificationSink onto the /bus WebSocket (on top of
PR #103's concurrent-frames relay loop and PR #124's client-side un-freeze), so a
/bus connection can flow.subscribe and then receive `notifications/aitm/flow`
pushes live. This canary drives the real /bus WebSocket the way a push-capable UI
does — subscribe, generate traffic, expect a push — and HARD-FAILS if either step
regresses: the main.rs wiring that feeds the web server's own subscription registry
is guarded only by this test, so a SKIP here would hide a regression.

PR #137 also delivers `notifications/aitm/agent` (audit) on a subscribed /bus
connection for each finished tool call; this canary filters by method, so that is
harmless here. Limits it added: 32 subscriptions per connection, filter values at
most 1024 bytes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
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
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        ok(f"aitm web on :{core.web_port}, proxy :{cfg.proxy_port}, upstream {up.base}")

        section("subscribe to flows over the REAL /bus WebSocket bridge (as the UI should)")
        ws = WsBusClient.web_agent(core)
        try:
            sub = ws.call("flow.subscribe", {})
        except ToolError as e:
            # PR #137 gave each /bus bridge connection a NotificationSink, so the core
            # must accept flow.subscribe here. A refusal is a regression of exactly that
            # wiring (reproduced at the real boundary with the core's own error).
            fail(f"REGRESSION (push-over-bridge): the /bus bridge refused flow.subscribe — {e} "
                 "PR #137 wired a per-connection NotificationSink onto the /bus WebSocket; a "
                 "refusal here means that wiring regressed.")
        ok(f"flow.subscribe over /bus succeeded: {sub}")

        section("generate real traffic, then wait for a LIVE push")
        resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}/echo?x=stream")
        check(resp.status == 200, f"traffic through the proxy returned {resp.status}")
        note = ws.wait_notification("notifications/aitm/flow", timeout=8)
        if note:
            ok(f"/bus pushed a live flow notification: {note.get('method')}")
            ok("web live-streaming works over /bus — regression guarded")
        else:
            fail("REGRESSION (F4 web /bus push): /bus accepted flow.subscribe but pushed no "
                 "notifications/aitm/flow within 8s under live traffic. PR #137 made this push "
                 "path live; no push here means it regressed.")
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
