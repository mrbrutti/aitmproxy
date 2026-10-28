#!/usr/bin/env python3
"""bus-agent-check — drive a live aitm core over its MCP loopback bus the way an
agent does, exercising every command the operator UIs rely on, and report what
works and what does not.

Usage:
    scripts/bus-agent-check.py                 # starts its own `aitm` on free ports
    scripts/bus-agent-check.py --bus 127.0.0.1:19090 --token T --proxy 127.0.0.1:18080 --echo 127.0.0.1:18888

Stdlib only. Must run in a real shell (binds ports). Exit status = failed checks.
A local echo server (returns the request's headers as JSON) stands in for the
upstream so the check is deterministic and offline.
"""
import argparse, base64, json, os, socket, subprocess, sys, tempfile, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("ok   " if cond else "FAIL ") + name + (f"   — {detail}" if detail and not cond else ""))
    return bool(cond)


class Echo(BaseHTTPRequestHandler):
    def do_any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        out = json.dumps({"method": self.command, "path": self.path,
                          "headers": {k.lower(): v for k, v in self.headers.items()},
                          "body": body}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_any
    def log_message(self, *a): pass


class Bus:
    """Newline-delimited JSON-RPC over loopback TCP with the token line first."""
    def __init__(self, host, port, token):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.f = self.sock.makefile("rwb")
        self.f.write((json.dumps({"token": token}) + "\n").encode()); self.f.flush()
        self.n = 0

    def rpc(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}
        self.f.write((json.dumps(msg) + "\n").encode()); self.f.flush()
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("bus closed")
            reply = json.loads(line)
            if reply.get("id") == self.n:
                if "error" in reply:
                    raise RuntimeError(f"rpc {reply['error']['code']}: {reply['error']['message']}")
                return reply["result"]

    def call(self, tool, **args):
        """tools/call → (ok, value_or_message)."""
        r = self.rpc("tools/call", {"name": tool, "arguments": args})
        text = r.get("content", [{}])[0].get("text", "")
        if r.get("isError"):
            return False, text
        return True, r.get("structuredContent", text)


def via_proxy(proxy, url, headers=None, timeout=10):
    handler = urllib.request.ProxyHandler({"http": f"http://{proxy}"})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers=headers or {})
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bus"); ap.add_argument("--token"); ap.add_argument("--proxy"); ap.add_argument("--echo")
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="bus-agent-check-")
    pocdir = os.path.join(work, "pocs"); os.makedirs(os.path.join(pocdir, "out"))
    server = None
    if a.echo:
        echo_host, echo_port = a.echo.split(":"); echo_port = int(echo_port)
    else:
        echo_host, echo_port = "127.0.0.1", 28888
        httpd = HTTPServer((echo_host, echo_port), Echo)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    echo = f"{echo_host}:{echo_port}"

    if a.bus:
        bus_host, bus_port = a.bus.split(":"); token = a.token; proxy = a.proxy
    else:
        bus_host, bus_port, token, proxy = "127.0.0.1", "29090", "agent-check-token", "127.0.0.1:28080"
        cfg = os.path.join(work, "aitm.yaml")
        with open(cfg, "w") as f:
            f.write(f"""listen: {proxy}
browser:
  proxy_addr: 127.0.0.1:28081
mcp:
  transport:
    loopback_tcp:
      port: {bus_port}
      token: {token}
scope:
  entries: ["{echo}"]
poc:
  dir: {pocdir}
  out_dir: {pocdir}/out
""")
        subprocess.run(["cargo", "build", "-q", "-p", "aitm"], cwd=ROOT, check=True)
        server = subprocess.Popen([os.path.join(ROOT, "target/debug/aitm"), "--config", cfg],
                                  stdout=open(os.path.join(work, "server.log"), "w"), stderr=subprocess.STDOUT)
        time.sleep(1.5)

    try:
        bus = Bus(bus_host, int(bus_port), token)
        info = bus.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "bus-agent-check", "version": "0"}})
        check("initialize names the server", info.get("serverInfo", {}).get("name") == "aitmproxy", str(info))
        tools = {t["name"] for t in bus.rpc("tools/list")["tools"]}
        expected = {"flow.list", "flow.get", "flow.detail", "flow.intercept", "flow.resume", "flow.kill", "flow.mutate",
                    "flow.replay", "request.send", "scope.add", "scope.list", "scope.remove", "browser.navigate",
                    "browser.click", "browser.type", "browser.screenshot", "browser.eval", "browser.get_dom",
                    "poc.build", "poc.run", "poc.list", "poc.get", "poc.artifact", "ca.export", "ca.status",
                    "ca.install", "ca.uninstall", "proxy.status", "proxy.pause", "proxy.resume", "flow.clear", "config.get",
                    "flow.mark", "flow.comment"}
        check("tools/list has the 34 operator commands (plus M3 extras)", expected <= tools, f"missing {sorted(expected - tools)}")
        for extra in sorted(tools - expected):
            print(f"note  extra tool on the bus: {extra}")

        # proxy.status (F7)
        ok, st = bus.call("proxy.status")
        check("proxy.status: listening + address", ok and st.get("listening") is True and st.get("address") == proxy, str(st))

        # real traffic through the proxy, then flow.list / flow.get / flow.detail (F5)
        status, echoed = via_proxy(proxy, f"http://{echo}/first", {"x-agent": "one"})
        check("a request through the proxy reaches the upstream", status == 200 and echoed["headers"].get("x-agent") == "one")
        ok, ids = bus.call("flow.list")
        check("flow.list lists it", ok and len(ids) >= 1, str(ids))
        fid = ids[-1]
        ok, summary = bus.call("flow.get", id=fid)
        check("flow.get summary", ok and summary.get("method") == "GET" and summary.get("status") == 200 and summary.get("path") == "/first", str(summary))
        ok, d = bus.call("flow.detail", id=fid)
        req_h = dict((k.lower(), v) for k, v in d.get("request", {}).get("headers", [])) if ok else {}
        body = base64.b64decode(d["response"]["body"]).decode() if ok and d.get("response", {}).get("body") else ""
        check("flow.detail: request headers as [[k,v]] incl. x-agent", ok and req_h.get("x-agent") == "one", str(d)[:300])
        check("flow.detail: response body is base64 JSON from the upstream", '"x-agent": "one"' in body, body[:200])
        check("flow.detail: meta.created + duration_ms + client_conn.peer", ok and d["meta"].get("created") and d["meta"].get("duration_ms") is not None and d["client_conn"].get("peer"), str(d.get("meta")))
        ok, d_none = bus.call("flow.detail", id=fid, body="none")
        check("flow.detail body=none keeps body_size", ok and d_none["response"]["body"] is None and d_none["response"]["body_size"] > 0, str(d_none.get("response"))[:200])

        # mark + comment (F6)
        ok, marks = bus.call("flow.mark", id=fid, marks=["red"])
        ok2, d2 = bus.call("flow.detail", id=fid, body="none")
        check("flow.mark then flow.detail shows the mark", ok and ok2 and d2["meta"]["marks"] == ["red"], str(d2.get("meta")))
        ok, _ = bus.call("flow.comment", id=fid, text="agent says hi")
        ok2, d2 = bus.call("flow.detail", id=fid, body="none")
        check("flow.comment then flow.detail shows the comment", ok and ok2 and d2["meta"]["comment"] == "agent says hi", str(d2.get("meta")))

        # intercept → mutate → resume with a real paused request
        ok, armed = bus.call("flow.intercept", enabled=True)
        check("flow.intercept arms", ok and armed is True, str(armed))
        result = {}
        def paused_request():
            try:
                result["resp"] = via_proxy(proxy, f"http://{echo}/paused", {"x-live": "before"}, timeout=30)
            except Exception as e:  # noqa: BLE001
                result["err"] = str(e)
        t = threading.Thread(target=paused_request); t.start()
        paused_id = None
        for _ in range(40):
            ok, ids = bus.call("flow.list")
            for i in ids:
                ok, s = bus.call("flow.get", id=i)
                if ok and s.get("intercept") == "intercepted":
                    paused_id = i
            if paused_id: break
            time.sleep(0.25)
        check("the next request is parked (flow.get intercept=intercepted)", paused_id is not None)
        ok, st = bus.call("proxy.status")
        check("proxy.status.paused counts it", ok and st.get("paused") == 1 and st.get("intercept_armed") is True, str(st))
        if paused_id:
            ok, _ = bus.call("flow.mutate", id=paused_id, edits={"headers": {"x-edited-by": "bus-agent-check"}})
            check("flow.mutate adds a header to the parked request", ok, str(_))
            ok, _ = bus.call("flow.resume", id=paused_id)
            check("flow.resume releases it", ok, str(_))
            t.join(timeout=15)
            resp = result.get("resp")
            check("the client got the upstream's echo with the edited header", resp and resp[1]["headers"].get("x-edited-by") == "bus-agent-check", str(result)[:300])
            ok, d3 = bus.call("flow.detail", id=paused_id, body="none")
            check("flow.detail reports edited=true and intercept=resumed", ok and d3.get("edited") is True and d3.get("intercept") == "resumed", str(d3)[:200])
        ok, armed = bus.call("flow.intercept", enabled=False)
        check("flow.intercept disarms", ok and armed is False)

        # replay + request.send (guarded by scope)
        ok, new_id = bus.call("flow.replay", id=fid)
        check("flow.replay returns a new flow id", ok and isinstance(new_id, str) and new_id != fid, str(new_id))
        ok, sent = bus.call("request.send", authority=echo, method="POST", path="/sent", headers={"x-sent": "yes"}, body="hello")
        check("request.send in scope returns a flow id", ok and isinstance(sent, str), str(sent))
        ok, refused = bus.call("request.send", authority="example.invalid", path="/")
        check("request.send out of scope is refused", not ok, str(refused))

        # scope (F12): an agent may not widen scope by default; narrowing is allowed
        ok, msg = bus.call("scope.add", host="added.test")
        check("scope.add from the agent is refused (scope.allow_agent_widen off)", not ok, str(msg)[:160])
        ok2, entries = bus.call("scope.list")
        check("scope.list shows the configured entry", ok2 and echo in entries, str(entries))
        ok3, removed = bus.call("scope.remove", host="never-added.test")
        check("scope.remove of an absent entry returns false", ok3 and removed is False, str(removed))

        # pause / resume capture + clear (F7)
        ok, c = bus.call("proxy.pause")
        check("proxy.pause returns capturing=false", ok and c.get("capturing") is False, str(c))
        ok, c = bus.call("proxy.resume")
        check("proxy.resume returns capturing=true", ok and c.get("capturing") is True, str(c))
        ok, cfg = bus.call("config.get")
        check("config.get is redacted and has listen", ok and cfg.get("listen") == proxy and "token" not in json.dumps(cfg), str(cfg)[:200])
        check("config.get exposes poc_dir (surfaces need it to save poc.build output)", ok and cfg.get("poc_dir") == pocdir, str(cfg.get("poc_dir")))

        # PoC: build (returns YAML text today) → save under poc.dir → run → list/get/artifact (F13)
        ok, yaml_text = bus.call("poc.build", flow_id=fid, name="agent check", param="q")
        check("poc.build returns a PoC", ok and isinstance(yaml_text, str) and yaml_text, str(yaml_text)[:120])
        is_path = ok and isinstance(yaml_text, str) and "\n" not in yaml_text and yaml_text.endswith((".yaml", ".yml"))
        check("poc.build returns a path under poc.dir (foundation §4.3)", is_path, "returns YAML text; the surface must write the file itself")
        poc_path = yaml_text if is_path else os.path.join(pocdir, "agent-check.yaml")
        if ok and not is_path:
            with open(poc_path, "w") as f: f.write(yaml_text)
        ok, run = bus.call("poc.run", poc_path=poc_path, target=f"http://{echo}")
        check("poc.run executes the saved PoC", ok and "passed" in run and run.get("finding_capture"), str(run)[:300])
        ok, lst = bus.call("poc.list")
        check("poc.list lists the PoC file", ok and any(e.get("poc_path") == poc_path for e in lst), str(lst)[:200])
        ok, got = bus.call("poc.get", poc_path=poc_path)
        check("poc.get returns the YAML", ok and got.get("yaml", "").startswith(("id:", "name:", "info:", "version:")) or (ok and "yaml" in got), str(got)[:200])
        shot = run.get("screenshot_path") if isinstance(run, dict) else None
        if shot:
            ok, bytes_b64 = bus.call("poc.artifact", path=shot)
            check("poc.artifact serves the screenshot", ok and isinstance(bytes_b64, str) and len(bytes_b64) > 0, str(bytes_b64)[:80])
        else:
            print("note  poc.run produced no screenshot_path (no browser engine) — poc.artifact not exercised")

        # browser.* — an engine may not be available; report honestly
        ok, dom = bus.call("browser.get_dom")
        print("note  browser.get_dom:", "ok" if ok else f"unavailable — {str(dom)[:100]}")

        # flow.clear last
        ok, cl = bus.call("flow.clear")
        ok2, after = bus.call("flow.list")
        check("flow.clear removes completed flows", ok and cl.get("cleared", 0) >= 1 and ok2 and len(after) < len(ids) + 3, str(cl))

        # ca.* read-only
        ok, ca = bus.call("ca.status")
        check("ca.status answers", ok and isinstance(ca, dict), str(ca)[:120])
        ok, inst = bus.call("ca.install")
        check("ca.install from an agent is refused by default (ca.allow_agent_install off)", not ok, str(inst)[:160])
    finally:
        if server:
            server.terminate()
            try: server.wait(timeout=5)
            except Exception: server.kill()  # noqa: BLE001

    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)} ok, {len(fails)} failed; work dir {work}")
    sys.exit(len(fails))


if __name__ == "__main__":
    main()
