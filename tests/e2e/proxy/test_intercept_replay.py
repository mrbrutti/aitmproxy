#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=curl
"""Interception, mutation, replay, request.send and kill, with the upstream's own
record confirming each mutation actually crossed the proxy.

  - request-phase: park -> rewrite path/headers/body -> resume; the UPSTREAM record
    proves it received the mutated request;
  - response-phase: park -> rewrite status/body -> resume; the CLIENT receives the
    edited response, not the upstream's original;
  - flow.replay re-issues a captured flow and captures a new one;
  - request.send issues a new request (scope-gated) and captures it;
  - flow.kill mode=503 fails the client request with 503 (regression for the
    keep-alive hang fixed in set_short_circuit).
"""
import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

import _clients as c  # noqa: E402


def curl_bg(args, timeout=30):
    res = {}

    def run():
        res["rc"], res["out"], res["err"] = c.curl(args, timeout=timeout)
    t = threading.Thread(target=run)
    t.start()
    return t, res


def park(bus, needle):
    return c.wait_for(lambda: c.find_flow(
        bus, pred=lambda s: s.get("intercept") == "intercepted"
        and needle in (s.get("path") or "")), tries=150, delay=0.1)


def main() -> int:
    if not c.have("curl"):
        skip("curl is required for the client")

    up = Upstream().start()
    core = None
    bus = None
    try:
        section("boot: real aitm + plain HTTP/1.1 upstream observer (in scope)")
        cfg = c.ProxyConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[up.authority, "127.0.0.1"],
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        proxy = ["-x", f"http://127.0.0.1:{cfg.proxy_port}"]
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, upstream {up.base}")

        section("request-phase intercept -> mutate -> resume (upstream record confirms)")
        bus.call("flow.intercept", {"enabled": True, "rules": [{"phase": "request", "url": "*/orig*"}]})
        t, res = curl_bg(proxy + ["-X", "POST", "--data-binary", "client-body",
                                  "-H", "x-orig: client", f"{up.base}/orig"])
        pid = park(bus, "orig")
        check(pid is not None, "request parks under intercept")
        bus.call("flow.mutate", {"id": pid, "edits": {
            "path": "/mutated", "headers": {"x-edit": "operator"}, "body": "operator-body"}})
        bus.call("flow.resume", {"id": pid})
        t.join(timeout=20)
        rec = [r for r in up.received if r["path"] == "/mutated"]
        check(rec and rec[0]["headers"].get("x-edit") == "operator"
              and rec[0]["body"] == "operator-body",
              f"request mutation reached the UPSTREAM (path/header/body rewritten) (rec={rec[:1]})")
        bus.call("flow.intercept", {"enabled": False})

        section("response-phase intercept -> mutate -> resume (client gets the edit)")
        bus.call("flow.intercept", {"enabled": True, "rules": [{"phase": "response", "url": "*/resp*"}]})
        t, res = curl_bg(proxy + ["-w", "\n%{http_code}", f"{up.base}/resp"])
        pid = park(bus, "resp")
        check(pid is not None, "response parks under intercept")
        bus.call("flow.mutate", {"id": pid, "edits": {"status": 418, "body": "edited-by-operator"}})
        bus.call("flow.resume", {"id": pid})
        t.join(timeout=20)
        out = res.get("out", b"").decode("utf-8", "replace")
        body, _, code = out.rpartition("\n")
        check(code.strip() == "418" and body == "edited-by-operator",
              f"response mutation reached the CLIENT (edited status+body) (code={code!r} body={body!r})")
        bus.call("flow.intercept", {"enabled": False})

        section("flow.replay re-issues and captures a new flow")
        c.curl(proxy + ["-H", "x-replay: seed", f"{up.base}/toreplay"])
        seed = c.find_flow(bus, path="/toreplay")
        check(seed is not None, "a seed flow exists to replay")
        new_id = bus.call("flow.replay", {"id": seed})
        check(isinstance(new_id, str) and new_id != seed, f"flow.replay returned a new flow id ({new_id})")
        d = c.wait_for(lambda: c.detail(bus, new_id))
        check(d and d["request"]["path"] == "/toreplay" and d["response"]["status"] == 200,
              "flow.replay captured a new flow that hit the upstream")

        section("request.send: in scope captures; out of scope refused")
        sent = bus.call("request.send", {"authority": up.authority, "method": "POST",
                        "path": "/sent", "headers": {"x-sent": "yes"}, "body": "sent-body"})
        check(isinstance(sent, str), f"request.send in scope returned a flow id ({sent})")
        d = c.detail(bus, sent)
        check(d and d["request"]["path"] == "/sent" and d["response"]["status"] == 200,
              "request.send captured the request+response")
        status, _ = bus.try_call("request.send", {"authority": "blocked.invalid", "path": "/"})
        check(status == "error", "request.send out of scope is refused")

        section("flow.kill mode=503 fails the client with 503 (keep-alive hang regression)")
        bus.call("flow.intercept", {"enabled": True, "rules": [{"phase": "request", "url": "*/killme*"}]})
        t, res = curl_bg(proxy + ["-o", "/dev/null", "-w", "%{http_code}", f"{up.base}/killme"], timeout=15)
        pid = park(bus, "killme")
        check(pid is not None, "the request to kill parks under intercept")
        bus.call("flow.kill", {"id": pid, "mode": "503"})
        t.join(timeout=12)
        code = res.get("out", b"").decode().strip()
        check(code == "503",
              f"flow.kill mode=503: the client sees 503 (not a hang) (code={code!r} rc={res.get('rc')})")
        bus.call("flow.intercept", {"enabled": False})
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
