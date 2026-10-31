#!/usr/bin/env python3
# e2e: tier=T1 surface=web
"""web/web_flows_live_stream -- the web UI's flow list keeps updating LIVE over the
/bus bridge: new flows reach the UI's socket as they arrive, with no freeze after
the initial load.

The web operator UI (apps/web) talks to `aitm web` over ONE WebSocket, GET /bus
(crates/aitm/src/web/bridge.rs): the bridge token as the first text frame, then
newline-delimited JSON-RPC exactly as on the loopback bus. Its bootstrap
(apps/web/src/state/app.ts `bootstrap`) loads the list once with `flow.list`, then
  * if `tools/list` advertises `flow.subscribe` it NEVER polls again and relies on
    pushed `notifications/aitm/flow` lines on that socket (push mode), else
  * it polls `flow.list` + `flow.detail {body: none}` every 500 ms (poll mode).
A list that loads and then never changes is the bug this test exists to catch.

This script IS that client. It does the UI's bootstrap against the real bridge,
pushes REAL requests through the REAL proxy to the REAL target, spaced out so the
list must wake up again each time, and asserts on ground truth:
  1. each new flow reaches the UI's /bus socket within LIVE_BUDGET -- as a push
     with no further request from us (push mode) or via the UI's own 500 ms poll
     (poll mode) -- carrying the real method, authority, path and upstream status;
  2. the id the UI received is the id of the flow the core captured, read back
     over the loopback MCP bus (a different listener on the same core);
  3. the same socket still answers afterwards and lists every live flow.

Boots its OWN `aitm web` + echo-record upstream on free ports by default (the
aitm_e2e convention); OR attaches to a runner-provided `aitm web` when the full env
contract below is set. Runner contract (all optional — absent any, it self-boots):
  AITM_BUS_ADDR, AITM_BUS_TOKEN   the loopback-TCP bus + agent token (the witness)
  AITM_PROXY_ADDR                 the proxy listener real traffic goes through
  AITM_TARGET_URL                 the seeded aitm-testtarget (`/search` reflects `q`)
  AITM_WEB_ADDR                   host:port of `aitm web --listen` (UI + /bus);
                                  AITM_WEB_LISTEN, the env the core reads, also works
  AITM_WEB_TOKEN                  the bridge token (`aitm web --token`), the `#t=`
                                  the UI itself connects with
Parallel-safe: flows are found by a unique marker in the path; nothing is mutated.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402

FLOW_NOTE = "notifications/aitm/flow"
LIVE_BUDGET = 5.0  # seconds a new flow may take to reach the UI's socket
GAP = 1.5  # quiet seconds between flows: the list must wake up again each time
FLOWS = 3
TRUTH_TIMEOUT = 15.0  # the loopback bus must show the captured flow within this


class Bridge(WsBusClient):
    """The UI's /bus connection; remembers the role `initialize` echoed."""

    role: str | None = None

    def initialize(self) -> dict:
        result = super().initialize()
        self.role = result.get("role")
        return result


def env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def hostport(addr: str) -> tuple[str, int]:
    host, _, port = addr.strip().rpartition(":")
    if not host or not port.isdigit():
        fail(f"expected host:port, got {addr!r}")
    return host.strip("[]"), int(port)


def next_flow_event(ui: Bridge, pred, timeout: float):
    """Params of the next `notifications/aitm/flow` on the UI's socket satisfying
    ``pred`` (earlier-stashed lines first, in arrival order); None if none arrives
    within ``timeout``. Nothing is sent: a push must come on its own."""
    deadline = time.monotonic() + timeout
    while True:
        while ui.notifications:
            m = ui.notifications.pop(0)
            if m.get("method") == FLOW_NOTE and pred(m.get("params") or {}):
                return m["params"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        got = ui.wait_notification(FLOW_NOTE, timeout=remaining)
        if got is None:
            return None
        if pred(got.get("params") or {}):
            return got["params"]


def poll_like_the_ui(ui: Bridge, tag: str, known: set, timeout: float):
    """The UI's fallback tick (app.ts `pollOnce`): `flow.list` over /bus, then
    `flow.detail {body: none}` for every id not seen yet, every 500 ms; the found
    row is re-read until its response landed, as the UI re-polls pending rows.
    Returns ``(id, detail)`` of the flow carrying ``tag`` or ``(None, None)``."""
    deadline = time.monotonic() + timeout
    while True:
        for fid in ui.call("flow.list"):
            if fid in known:
                continue
            known.add(fid)
            d = ui.call("flow.detail", {"id": fid, "body": "none"})
            if tag not in ((d.get("request") or {}).get("path") or ""):
                continue
            while d.get("response") is None and time.monotonic() < deadline:
                time.sleep(0.1)
                d = ui.call("flow.detail", {"id": fid, "body": "none"})
            return fid, d
        if time.monotonic() > deadline:
            return None, None
        time.sleep(0.5)


def wait_row(bus: BusClient, pred, timeout: float) -> dict:
    """Ground truth: poll `flow.table` on the loopback bus until a completed row
    (status present) satisfies ``pred``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in bus.call("flow.table").get("flows", []):
            if row.get("status") is not None and pred(row):
                return row
        time.sleep(0.1)
    fail(f"the loopback bus never listed the captured flow within {timeout:.0f}s")
    raise AssertionError("unreachable")


def main() -> None:
    # Prefer a runner-provided `aitm web` (env-model); otherwise boot our OWN `aitm web`
    # + echo-record upstream on dedicated free ports (the aitm_e2e convention), so this
    # cell runs under a plain `run.py web` with no web-runner mode required. The web
    # bridge's agent token is the `aitm web --token` value, i.e. cfg.agent_token.
    web_addr = env("AITM_WEB_ADDR", "AITM_WEB_LISTEN")
    web_token = env("AITM_WEB_TOKEN")
    attach = bool(web_addr and web_token and env("AITM_BUS_ADDR")
                  and env("AITM_PROXY_ADDR") and env("AITM_TARGET_URL"))
    aitm = None
    up = None
    clients: list = []
    try:
        if attach:
            bus_host, bus_port = hostport(env("AITM_BUS_ADDR"))
            bus_token = env("AITM_BUS_TOKEN")
            _, proxy_port = hostport(env("AITM_PROXY_ADDR"))
            target = env("AITM_TARGET_URL").rstrip("/")
            web_host, web_port = hostport(web_addr)
        else:
            # `aitm web` is not launched with --bus-endpoint-file, so pin the loopback
            # bus to a known free port (bus_port=0 would be ephemeral and unknowable);
            # the witness BusClient connects there while the UI uses the /bus bridge.
            up = Upstream().start()
            cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                             bus_port=free_port(), scope_entries=[up.authority, "127.0.0.1"])
            aitm = Aitm.web(cfg)
            bus_host, bus_port = "127.0.0.1", cfg.bus_port
            bus_token = cfg.agent_token
            proxy_port = cfg.proxy_port
            target = up.base
            web_host, web_port = "127.0.0.1", aitm.web_port
            web_token = cfg.agent_token
            web_addr = f"{web_host}:{web_port}"
        authority = urlparse(target).netloc
        if not target.startswith("http://") or not authority:
            fail(f"the target must be a plain http:// URL for this proxy-form client, got {target!r}")

        section("connect: loopback bus (witness) + web /bus bridge (the UI)")
        try:
            core = BusClient(bus_host, bus_port, bus_token, client_name="aitm-e2e-witness").connect()
        except (BusError, OSError) as e:
            fail(f"cannot connect to the loopback bus at {bus_host}:{bus_port}: {e}")
        clients.append(core)
        try:
            ui = Bridge(web_host, web_port, web_token, client_name="aitm-web").connect()
        except (BusError, OSError) as e:
            fail(f"cannot open the web /bus bridge at {web_addr}: {e}")
        clients.append(ui)
        check(ui.role in ("agent", "operator"), f"GET /bus upgraded, token accepted, initialize echoed role {ui.role!r}")
        check(
            ui.call("proxy.status").get("address") == core.call("proxy.status").get("address"),
            "bridge and loopback bus report the same proxy",
        )

        section("the UI's bootstrap over /bus: tools/list, one flow.list")
        names = {t["name"] for t in ui.tools()}
        check({"flow.list", "flow.detail"} <= names, "tools/list over /bus advertises flow.list + flow.detail")
        known = set(ui.call("flow.list"))  # the one-time load
        push = "flow.subscribe" in names  # advertised => the UI never polls again
        sub_note = "not advertised"
        if push:
            st, sub = ui.try_call("flow.subscribe", {})  # what a subscribing UI would send on this socket
            sub_note = f"flow.subscribe over /bus -> {sub if st == 'ok' else 'REFUSED: ' + str(sub)[:160]}"
        ok(f"{len(known)} flows loaded; mode = {'push' if push else 'poll'} ({sub_note})")

        arrivals: list[float] = []
        seen_ids: list[str] = []
        for i in range(1, FLOWS + 1):
            if i > 1:
                time.sleep(GAP)
            tag = f"livestream-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            path = f"/search?q={tag}"
            section(f"flow {i}/{FLOWS}: real GET through the proxy, then watch the UI's socket")
            sent = time.monotonic()
            resp = via_proxy(proxy_port, "GET", target + path)
            check(resp.status == 200 and tag in resp.text, f"target answered 200 through the proxy with the marker reflected (status {resp.status})")

            if push:
                in_path = lambda p, t=tag: t in ((p.get("summary") or {}).get("path") or "")  # noqa: E731
                ev = next_flow_event(ui, in_path, LIVE_BUDGET)
                latency = time.monotonic() - sent
                check(
                    ev is not None,
                    f"pushed to the UI over /bus within {LIVE_BUDGET:.0f}s with no request from us -- "
                    f"no {FLOW_NOTE} arrived ({sub_note}); the UI does not poll when flow.subscribe is "
                    f"advertised, so its flow list froze after load",
                )
                done = ev if ev.get("event") == "response" and (ev.get("summary") or {}).get("status") == 200 else next_flow_event(
                    ui, lambda p: in_path(p) and p.get("event") == "response" and (p.get("summary") or {}).get("status") == 200, LIVE_BUDGET
                )
                latency = time.monotonic() - sent
                check(done is not None, f"the response event (status 200) reached the UI (first event was {ev.get('event')!r})")
                fid, s = ev["id"], done["summary"]
                got = (s.get("kind"), s.get("method"), s.get("authority"), s.get("path"), s.get("status"))
                check(got == ("http", "GET", authority, path, 200), f"pushed summary is the real request: {got}")
                ok(f"live push arrived {latency:.2f}s after the request")
            else:
                fid, d = poll_like_the_ui(ui, tag, known, LIVE_BUDGET)
                latency = time.monotonic() - sent
                check(fid is not None, f"visible to the UI's 500 ms poll over /bus within {LIVE_BUDGET:.0f}s -- the flow never appeared in flow.list")
                req, res = d.get("request") or {}, d.get("response") or {}
                got = (req.get("method"), req.get("authority"), req.get("path"), res.get("status"))
                check(got == ("GET", authority, path, 200), f"polled detail is the real request and its real status: {got}")
                ok(f"poll surfaced the flow {latency:.2f}s after the request")

            row = wait_row(core, lambda r: tag in (r.get("path") or ""), TRUTH_TIMEOUT)
            check(row["id"] == fid, f"the id the UI received ({fid}) is the captured flow's id on the loopback bus ({row['id']})")
            arrivals.append(latency)
            seen_ids.append(fid)

        section("no freeze: the same /bus socket still answers and lists every live flow")
        st, listed = ui.try_call("flow.list")
        check(st == "ok" and all(i in listed for i in seen_ids), f"flow.list over /bus after the stream -> {st}, {len(listed) if st == 'ok' else listed}")
        check(all(a < LIVE_BUDGET for a in arrivals), f"every live update arrived within {LIVE_BUDGET:.0f}s: {[f'{a:.2f}s' for a in arrivals]}")
        print(
            f"PASS: web flow list live over /bus at {web_addr} ({'push' if push else 'poll'} mode, "
            f"{FLOWS} flows, arrivals {[f'{a:.2f}s' for a in arrivals]})",
            flush=True,
        )
    finally:
        for c in clients:
            c.close()
        if aitm is not None:
            aitm.stop()
        if up is not None:
            up.stop()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except (ToolError, BusError) as e:
        fail(f"bus: {e}")
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
