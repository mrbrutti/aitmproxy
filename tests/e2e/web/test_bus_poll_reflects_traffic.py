#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""Hard guard for the shipped web un-freeze (PR #124, client-side polling).

The fixed web UI keeps its flow list live by POLLING flow.list over the real /bus
(the bridge has no push sink — see test_bus_live_stream for the push-over-bridge
gap). This guards the data layer that polling depends on: over /bus, flow.list
must REFLECT new traffic. If this ever regresses, the client poll can't un-freeze
the list no matter what the UI does. Ground truth: the flow id set grows after
real traffic through the proxy.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402


def flow_ids(result) -> list:
    if isinstance(result, dict):
        for key in ("flows", "ids", "items"):
            if key in result:
                result = result[key]
                break
    if isinstance(result, list):
        return [i.get("id", i) if isinstance(i, dict) else i for i in result]
    return []


def poll_until_grows(ws, baseline: int, timeout: float = 6.0) -> list:
    """Poll flow.list over /bus the way the fixed UI does, until the id set grows."""
    deadline = time.time() + timeout
    ids = flow_ids(ws.call("flow.list"))
    while len(ids) <= baseline and time.time() < deadline:
        time.sleep(0.25)
        ids = flow_ids(ws.call("flow.list"))
    return ids


def main() -> int:
    up = Upstream().start()
    core = None
    ws = None
    try:
        section("boot aitm web + upstream (upstream in scope)")
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=[up.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        ws = WsBusClient.web_agent(core)
        base = flow_ids(ws.call("flow.list"))
        ok(f"baseline flow.list over /bus: {len(base)} flow(s)")

        section("real traffic #1 -> flow.list over /bus reflects it (what the client poll reads)")
        via_proxy(cfg.proxy_port, "GET", f"{up.base}/echo?x=poll1")
        ids1 = poll_until_grows(ws, len(base))
        check(len(ids1) > len(base), f"flow.list grew after traffic ({len(base)} -> {len(ids1)})")

        section("real traffic #2 -> flow.list keeps reflecting new flows")
        via_proxy(cfg.proxy_port, "GET", f"{up.base}/echo?x=poll2")
        ids2 = poll_until_grows(ws, len(ids1))
        check(len(ids2) > len(ids1), f"flow.list grew again ({len(ids1)} -> {len(ids2)})")
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
