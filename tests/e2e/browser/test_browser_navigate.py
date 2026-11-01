#!/usr/bin/env python3
# e2e: tier=T1 surface=browser needs=obscura
"""browser/browser_navigate -- `browser.navigate` drives the embedded obscura engine to
a URL, and the navigation is CAPTURED by the proxy.

Ground truth, never fixtures: we tell the browser (and nothing else) to load a URL
carrying a unique marker, then prove on the core's own flow store that a real GET for
that exact URL rode the proxy and got the real upstream page back (flow.table row +
flow.detail with the decrypted body), and on the browser's own rendered DOM that
obscura actually loaded it.

Capability gate (headless vs live rig): a real obscura engine must be configured on the
core (discovered beside the aitm binary, or via AITM_OBSCURA_BIN, inherited from the
environment this process runs in). Without it the core still starts and `browser.*`
errors "no browser is configured" -> this cell SKIPs (77), naming the missing dep --
UNLESS AITM_OBSCURA=1 asserts it must be there, in which case the absence is a FAIL.
So it skips cleanly in the headless gate and RUNS in the obscura-equipped live rig.

Converted from the dead _lib/mcp draft harness onto aitm_e2e: self-boots its own core +
seeded Target on free ports (the Target's exact host:port is in scope, as the SSRF guard
requires). Soft-assertion battery; exit 0 pass / 1 fail / 77 skip.
"""
from __future__ import annotations

import base64
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402

CAPTURE_BUDGET = 20.0  # seconds for the navigation's flow to land in the store
NO_BROWSER_HINTS = ("no browser is configured", "obscura", "was not found", "no browser")

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


def wait_for_row(bus, pred, timeout):
    deadline = time.monotonic() + timeout
    while True:
        for row in bus.call("flow.table").get("flows", []):
            if pred(row):
                return row
        if time.monotonic() > deadline:
            return None
        time.sleep(0.25)


def decode_body(msg) -> bytes:
    raw = (msg or {}).get("body")
    return base64.b64decode(raw) if isinstance(raw, str) and raw else b""


def main() -> int:
    tgt = Target("vulnerable")  # /search renders "Results for <q>"
    core = agent = None
    try:
        section("boot: aitm core + seeded target (obscura discovered from env / sibling if present)")
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[tgt.authority, "127.0.0.1"], allow_agent_widen=True)
        core = Aitm.server(cfg)
        agent = BusClient.agent(core)
        if "browser.navigate" not in agent.tool_names():
            skip("this core registers no browser.* tools (built without the browser feature)")
        target = tgt.base.rstrip("/")
        authority = tgt.authority
        tag = f"nav-{uuid.uuid4().hex[:8]}"
        path = f"/search?q={tag}"
        url = target + path

        section("drive the real browser (only obscura is ever told this URL)")
        st, nav = agent.try_call("browser.navigate", {"url": url})
        if st != "ok":
            msg = str(nav)
            if any(h in msg.lower() for h in NO_BROWSER_HINTS):
                if os.environ.get("AITM_OBSCURA") == "1":
                    fail(f"AITM_OBSCURA=1 but the core has no browser engine: {msg[:200]}")
                skip(f"no embedded browser on this core (obscura absent): {msg[:160]}")
            fail(f"browser.navigate refused: {msg[:300]}")
        expect((nav.get("final_url") or "").startswith(url), "navigate landed on the requested URL", nav)
        expect(nav.get("status") == 200, "navigate saw the upstream's 200", nav.get("status"))

        section("ground truth (proxy side): the store holds a real GET for exactly that URL")
        row = wait_for_row(agent, lambda r: tag in (r.get("path") or ""), CAPTURE_BUDGET)
        if row is None:
            fail("no captured flow carried the marker; obscura did not go through the proxy")
        expect((row.get("kind"), row.get("method"), row.get("authority"), row.get("path"), row.get("status"))
               == ("http", "GET", authority, path, 200),
               "captured flow is the browser's request line and real status", row)
        d = agent.call("flow.detail", {"id": row["id"], "body": "inline"})
        body = decode_body(d.get("response"))
        expect(f"Results for {tag}".encode() in body, "captured response body is the real upstream page", body[:160])

        section("the browser's own view agrees: obscura rendered that page, not the proxy alone")
        st, dom = agent.try_call("browser.get_dom", {})
        expect(st == "ok" and tag in str(dom), "obscura's rendered DOM carries the marker", str(dom)[:160])
    finally:
        if agent:
            agent.close()
        if core:
            core.stop()
        tgt.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: browser.navigate drove obscura to the URL; the navigation was captured by the proxy and rendered in the DOM")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
