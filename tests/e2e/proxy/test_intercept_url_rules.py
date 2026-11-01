#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy needs=curl
"""Breakpoint rules whose `url` pattern names a host or a scheme arm on a real core.

The `url` clause is matched against the full request URL
(`scheme://authority/path?query`) and against the path alone, so a pattern an
operator writes from the URL bar pauses the flow it names. Each positive round
arms one rule, sends a real `curl` through the proxy, sees the flow parked
(`intercept == "intercepted"`) while the upstream's own record is still empty,
resumes it, and reads the request off the upstream's record:

  - a host-bearing wildcard   `*127.0.0.1:<port>*`;
  - a scheme-bearing wildcard `http://127.0.0.1:<port>/scheme*`;
  - a `^http://`-anchored regex;
  - a star-less substring     `127.0.0.1:<port>/sub`.

The negative round arms a rule naming another host and shows the request is not
paused: curl completes with 200 within a bounded wait and the captured flow stays
`observed`.
"""
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


def park(bus, path):
    return c.wait_for(lambda: c.find_flow(
        bus, pred=lambda s: s.get("intercept") == "intercepted"
        and s.get("path") == path), tries=150, delay=0.1)


def disarm(bus):
    bus.call("flow.intercept", {"enabled": False, "rules": []})


def positive_round(bus, up, proxy, title, rule, path):
    section(f"{title}: rule {rule!r} parks {path}")
    bus.call("flow.intercept", {"enabled": True, "rules": [rule]})
    t, res = curl_bg(proxy + ["-o", "/dev/null", "-w", "%{http_code}", f"{up.base}{path}"])
    pid = park(bus, path)
    check(pid is not None, f"the request to {path} parks under the rule")
    check(not [r for r in up.received if r["path"] == path],
          "the upstream has not seen the request while it is parked")
    bus.call("flow.resume", {"id": pid})
    t.join(timeout=20)
    code = res.get("out", b"").decode("utf-8", "replace").strip()
    check(code == "200", f"flow.resume lets curl finish with 200 (code={code!r} rc={res.get('rc')})")
    rec = [r for r in up.received if r["path"] == path]
    check(len(rec) == 1 and rec[0]["method"] == "GET",
          f"the UPSTREAM's own record has GET {path} after the resume (rec={rec[:1]})")
    disarm(bus)


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

        positive_round(bus, up, proxy, "host-bearing wildcard",
                       {"url": f"*127.0.0.1:{up.port}*"}, "/hostrule")
        positive_round(bus, up, proxy, "scheme-bearing wildcard",
                       {"url": f"http://127.0.0.1:{up.port}/scheme*"}, "/schemerule")
        positive_round(bus, up, proxy, "scheme-anchored regex",
                       {"url": {"regex": f"^http://127\\.0\\.0\\.1:{up.port}/re"}}, "/rerule")
        positive_round(bus, up, proxy, "star-less substring",
                       {"url": f"127.0.0.1:{up.port}/sub"}, "/substr")

        section("negative: a rule naming another host does not pause the request")
        bus.call("flow.intercept", {"enabled": True, "rules": [{"url": "*nomatch.invalid*"}]})
        rc, out, err = c.curl(proxy + ["-m", "15", "-o", "/dev/null", "-w", "%{http_code}",
                                       f"{up.base}/negative"], timeout=20)
        code = out.decode("utf-8", "replace").strip()
        check(code == "200", f"curl to /negative completes with 200 unpaused (code={code!r} rc={rc})")
        fid = c.find_flow(bus, path="/negative")
        check(fid is not None, "the /negative flow was captured")
        state = bus.call("flow.get", {"id": fid}).get("intercept")
        check(state == "observed", f"the /negative flow was never intercepted (intercept={state!r})")
        rec = [r for r in up.received if r["path"] == "/negative"]
        check(len(rec) == 1, "the UPSTREAM's own record has GET /negative")
        disarm(bus)
    finally:
        if bus:
            bus.try_call("flow.intercept", {"enabled": False, "rules": []})
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
