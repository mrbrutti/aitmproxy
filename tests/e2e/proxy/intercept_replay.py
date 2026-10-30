#!/usr/bin/env python3
"""Interception, mutation, replay, request.send and kill — with upstream echo
confirming the mutation actually crossed the proxy.

  - request-phase: park a request, rewrite path/headers/body, resume; the UPSTREAM
    echo proves it received the mutated request;
  - response-phase: park a response, rewrite status/body, resume; the CLIENT
    receives the edited response, not the upstream's original;
  - flow.replay re-issues a captured flow and captures a new one;
  - request.send issues a new request (scope-gated) and captures it;
  - flow.kill on a parked flow fails the client request with the chosen status.
"""
import json
import threading

import _harness as h


def curl_bg(args, timeout=30):
    res = {}

    def run():
        res["rc"], res["out"], res["err"] = h.curl(args, timeout=timeout)
    t = threading.Thread(target=run)
    t.start()
    return t, res


def park(bus, url_contains):
    return h.wait_for(lambda: h.find_flow(
        bus, pred=lambda s: s.get("intercept") == "intercepted"
        and url_contains in (s.get("path") or ""), tries=150, delay=0.1))


def main():
    http_srv, http_port = h.start_http_echo()
    auth = f"127.0.0.1:{http_port}"

    with h.Rig([auth]) as rig:
        proxy = ["-x", f"http://{rig.proxy}"]

        # 1. request-phase intercept -> mutate -> resume; upstream echo confirms
        ok, _ = rig.bus.call("flow.intercept", enabled=True,
                             rules=[{"phase": "request", "url": "*/orig*"}])
        h.check("intercept arms (request phase)", ok, str(_))
        t, res = curl_bg(proxy + ["-X", "POST", "--data-binary", "client-body",
                                  "-H", "x-orig: client", f"http://{auth}/orig"])
        pid = park(rig.bus, "orig")
        h.check("request parks under intercept", pid is not None, rig.log_tail(10))
        if pid:
            ok, _ = rig.bus.call("flow.mutate", id=pid, edits={
                "path": "/mutated", "headers": {"x-edit": "operator"}, "body": "operator-body"})
            h.check("flow.mutate edits the parked request", ok, str(_))
            rig.bus.call("flow.resume", id=pid)
        t.join(timeout=20)
        echoed = {}
        try:
            echoed = json.loads(res.get("out", b""))
        except Exception:  # noqa: BLE001
            pass
        h.check("request mutation reached the UPSTREAM (path/header/body rewritten)",
                echoed.get("path") == "/mutated"
                and echoed.get("headers", {}).get("x-edit") == "operator"
                and echoed.get("body") == "operator-body",
                f"echoed={str(echoed)[:220]} err={res.get('err','')[:120]}")
        rig.bus.call("flow.intercept", enabled=False)

        # 2. response-phase intercept -> mutate -> resume; client gets the edit
        ok, _ = rig.bus.call("flow.intercept", enabled=True,
                             rules=[{"phase": "response", "url": "*/resp*"}])
        h.check("intercept arms (response phase)", ok, str(_))
        t, res = curl_bg(proxy + ["-w", "\n%{http_code}", f"http://{auth}/resp"])
        pid = park(rig.bus, "resp")
        h.check("response parks under intercept", pid is not None, rig.log_tail(10))
        if pid:
            ok, _ = rig.bus.call("flow.mutate", id=pid,
                                 edits={"status": 418, "body": "edited-by-operator"})
            h.check("flow.mutate edits the parked response (status+body)", ok, str(_))
            rig.bus.call("flow.resume", id=pid)
        t.join(timeout=20)
        out = res.get("out", b"").decode("utf-8", "replace")
        body, _, code = out.rpartition("\n")
        h.check("response mutation reached the CLIENT (edited status+body, not the origin's)",
                code.strip() == "418" and body == "edited-by-operator",
                f"code={code!r} body={body!r}")
        rig.bus.call("flow.intercept", enabled=False)

        # 3. flow.replay re-issues a captured flow
        rc, out, err = h.curl(proxy + ["-H", "x-replay: seed", f"http://{auth}/toreplay"])
        seed = h.find_flow(rig.bus, path="/toreplay")
        h.check("a seed flow exists to replay", seed is not None)
        ok, new_id = rig.bus.call("flow.replay", id=seed)
        h.check("flow.replay returns a new flow id", ok and isinstance(new_id, str) and new_id != seed,
                str(new_id))
        # the replay is a second captured hit on the same path
        replayed = h.wait_for(lambda: new_id if h.flow_detail(rig.bus, new_id) else None)
        d = h.flow_detail(rig.bus, new_id) if replayed else None
        h.check("flow.replay captured a new flow that hit the upstream",
                d and d["request"]["path"] == "/toreplay" and d["response"]["status"] == 200,
                str(d)[:200] if d else "no replay flow")

        # 4. request.send: in scope captures; out of scope refused
        ok, sent = rig.bus.call("request.send", authority=auth, method="POST",
                                path="/sent", headers={"x-sent": "yes"}, body="sent-body")
        h.check("request.send in scope returns a flow id", ok and isinstance(sent, str), str(sent))
        d = h.flow_detail(rig.bus, sent) if ok and isinstance(sent, str) else None
        h.check("request.send captured the request+response",
                d and d["request"]["path"] == "/sent" and d["response"]["status"] == 200,
                str(d)[:200] if d else "no flow")
        ok2, refused = rig.bus.call("request.send", authority="blocked.invalid", path="/")
        h.check("request.send out of scope is refused", not ok2, str(refused)[:160])

        # 5. flow.kill on a parked flow fails the client request
        ok, _ = rig.bus.call("flow.intercept", enabled=True,
                             rules=[{"phase": "request", "url": "*/killme*"}])
        t, res = curl_bg(proxy + ["-s", "-o", "/dev/null", "-w", "%{http_code}",
                                  f"http://{auth}/killme"])
        pid = park(rig.bus, "killme")
        h.check("request to kill parks under intercept", pid is not None)
        if pid:
            ok, _ = rig.bus.call("flow.kill", id=pid, mode="503")
            h.check("flow.kill accepted", ok, str(_))
        t.join(timeout=20)
        code = res.get("out", b"").decode().strip()
        h.check("flow.kill: the client sees the chosen failure status (503)",
                code == "503", f"code={code!r} err={res.get('err','')[:120]}")
        rig.bus.call("flow.intercept", enabled=False)

    h.done()


if __name__ == "__main__":
    main()
