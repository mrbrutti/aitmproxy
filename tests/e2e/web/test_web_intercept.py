#!/usr/bin/env python3
# e2e: tier=T1 surface=web serial
"""web/web_intercept -- arming and resuming interception works over the web `/bus`
bridge, proven on GROUND TRUTH (never a fixture).

`aitm web` serves the operator UI over ONE WebSocket, GET /bus: the first text frame
is the {"token":...} line, then newline-delimited JSON-RPC rides text frames into the
SAME live core the proxy runs in. This test drives intercept over that real bridge and
holds every claim to the loopback MCP bus (a different listener on the same core) as
the independent witness, to the real client blocked on the wire, and to the seeded
testtarget's own answer:

  * flow.intercept sent over /bus ARMS the real proxy (the loopback witness reports
    intercept_armed=true; both listeners report the same proxy);
  * a REAL GET through the proxy carrying our marker PARKS: its flow.table row is
    state=intercepted with no status (over /bus AND the loopback bus), flow.detail over
    /bus has no response, and the client thread is still blocked after a grace period;
  * flow.resume over /bus RELEASES it -- the blocked client receives the testtarget's
    own 200 with the marker reflected, the stored flow ends state=resumed/status 200,
    and the response body read back over /bus carries the marker;
  * disarming over /bus is visible on the loopback bus, and always runs (cleanup).

flow.intercept is Sensitive, so the agent bridge token is refused it; arming uses the
operator BRIDGE token `aitm web` prints on startup. flow.resume is Write, so the agent
bridge can release the hold (the UI's own path), falling back to the operator.

Converted from the dead _lib/mcp draft harness onto aitm_e2e: self-boots `aitm web` +
a seeded Target on free ports (loopback bus pinned), opens agent + operator /bus
bridges (the operator token parsed from aitm web's own output), and witnesses on the
loopback bus. flow.intercept arms a GLOBAL mode (serial). Exit 0 pass / 1 fail / 77 skip.
"""
from __future__ import annotations

import base64
import re
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.target import Target  # noqa: E402
from aitm_e2e.ws import WsBusClient  # noqa: E402

HOLD_GRACE_S = 1.5  # a loopback GET normally round-trips in milliseconds

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


class Bridge(WsBusClient):
    """A /bus bridge connection that remembers the role its initialize echoed."""

    role = None

    def initialize(self):
        result = super().initialize()
        self.role = result.get("role")
        return result


def open_bridge(host, port, token, name, clients):
    try:
        b = Bridge(host, port, token, client_name=name).connect()
    except Exception as e:  # noqa: BLE001 -- a dead bridge is a failure, not a skip
        fail(f"cannot open the web /bus bridge at {host}:{port}: {e}")
    clients.append(b)
    return b


def operator_bridge_token(core, timeout=10.0):
    """`aitm web` prints a fresh operator BRIDGE token on startup
    (`web UI (operator): http://.../#t=<tok>&expect=operator`). Parse it from the
    core's own captured output."""
    pat = re.compile(r"t=([^&\s]+)&expect=operator")
    deadline = time.time() + timeout
    while time.time() < deadline:
        for text in (core.stdout_text(), core.stderr_text()):
            m = pat.search(text or "")
            if m:
                return m.group(1)
        time.sleep(0.2)
    return None


def wait_row(client, match, timeout=25.0):
    deadline = time.monotonic() + timeout
    rows: list = []
    while time.monotonic() < deadline:
        rows = client.call("flow.table").get("flows", [])
        for row in rows:
            if match(row):
                return row
        time.sleep(0.15)
    print(f"note: no matching flow.table row within {timeout}s; last rows: "
          f"{[(r.get('method'), r.get('path'), r.get('state')) for r in rows[-6:]]}", flush=True)
    return None


def decode_body(msg) -> bytes:
    raw = (msg or {}).get("body")
    return base64.b64decode(raw) if isinstance(raw, str) and raw else b""


def main() -> int:
    tgt = Target("vulnerable")  # /search reflects q raw into its HTML
    core = witness = ui = op = ctl = None
    clients: list = []
    fid = None
    resumed = False
    try:
        section("boot: aitm web + seeded target; agent + operator /bus bridges + loopback witness")
        cfg = CoreConfig(proxy_port=free_port(), bus_port=free_port(), scope_entries=[tgt.authority, "127.0.0.1"])
        core = Aitm.web(cfg)
        web_host, web_port = "127.0.0.1", core.web_port
        target = tgt.base.rstrip("/")
        tag = f"webhold-{uuid.uuid4().hex[:8]}"  # ours alone: flows are shared on a live core
        url = f"{target}/search?q={tag}"
        rule = {"id": tag, "name": "e2e web intercept", "phase": "request", "url": f"*{tag}*"}

        witness = BusClient(web_host, cfg.bus_port, cfg.agent_token, client_name="aitm-e2e-witness").connect()
        clients.append(witness)
        for tool in ("flow.intercept", "flow.resume", "flow.table", "flow.get", "flow.detail", "proxy.status"):
            expect(tool in witness.tool_names(), f"the core registers {tool}")
        ui = open_bridge(web_host, web_port, cfg.agent_token, "aitm-e2e-web-agent", clients)
        expect(ui.role == "agent", f"agent bridge handshake resolves role=agent (got {ui.role!r})", ui.role)
        expect({"flow.intercept", "flow.resume"} <= set(ui.tool_names()),
               "bridge advertises flow.intercept + flow.resume", sorted(ui.tool_names())[:12])
        expect(ui.call("proxy.status").get("address") == witness.call("proxy.status").get("address"),
               "bridge and loopback bus report the SAME proxy (one core)")

        op_token = operator_bridge_token(core)
        if not op_token:
            fail(f"could not parse the operator bridge token from aitm web output; "
                 f"stdout head {core.stdout_text()[:200]!r} stderr head {core.stderr_text()[:200]!r}")
        op = open_bridge(web_host, web_port, op_token, "aitm-e2e-web-operator", clients)
        ctl = op
        expect(op.role == "operator", f"operator bridge token resolves role=operator (got {op.role!r})", op.role)

        section("arm flow.intercept over /bus as the operator (the agent bridge is Sensitive-gated)")
        st, refused = ui.try_call("flow.intercept", {"enabled": True, "rules": [rule]})
        expect(st == "error", "the AGENT bridge is refused flow.intercept (Sensitive) over /bus", refused)
        armed = op.confirm("flow.intercept", {"enabled": True, "rules": [rule]})
        expect(isinstance(armed, dict) and armed.get("enabled") is True
               and [r.get("id") for r in armed.get("rules", [])] == [tag],
               "flow.intercept over /bus (operator) armed exactly our rule", armed)
        expect(witness.call("proxy.status").get("intercept_armed") is True, "loopback bus witness sees intercept_armed=true")

        section("a real GET through the proxy is PARKED, not answered")
        box: list = []

        def _get():
            try:
                box.append(via_proxy(cfg.proxy_port, "GET", url, timeout=90))
            except Exception as e:  # noqa: BLE001 -- surfaced by the checks below
                box.append(e)

        client = threading.Thread(target=_get, daemon=True)
        client.start()
        row = wait_row(ui, lambda f: tag in (f.get("path") or "") and f.get("state") == "intercepted")
        if row is None:
            fail("the marked GET never parked as seen over /bus (flow.table never showed state=intercepted)")
        fid = row["id"]
        expect(row.get("status") is None, "parked flow row (over /bus) has no response status yet", row)
        expect(witness.call("flow.get", {"id": fid}).get("intercept") == "intercepted",
               "loopback bus witness shows the same flow intercepted", fid)
        expect(ui.call("flow.detail", {"id": fid, "body": "none"}).get("response") is None,
               "flow.detail over /bus has no response while parked", fid)
        time.sleep(HOLD_GRACE_S)
        expect(client.is_alive() and not box, f"client is still blocked after {HOLD_GRACE_S}s (a real hold)", box)

        section("resume over /bus: the client gets the target's real answer")
        st, res = ui.try_call("flow.resume", {"id": fid})  # Write: the agent bridge may release
        if st == "ok":
            resume_role = "agent"
        else:
            print(f"note: agent bridge refused flow.resume: {str(res)[:120]}; resuming over the operator bridge", flush=True)
            res, resume_role = op.call("flow.resume", {"id": fid}), "operator"
        resumed = True
        expect(res == "resumed", f"flow.resume over /bus ({resume_role}) answered 'resumed'", res)
        client.join(30)
        resp = box[0] if box else None
        got = resp is not None and not isinstance(resp, Exception)
        expect(got and resp.status == 200, "blocked client received a 200 after resume", resp)
        if got:
            expect(tag in resp.text, "response is the testtarget's own (marker reflected -> upstream really ran)", resp.text[:160])

        done = wait_row(witness, lambda f: f.get("id") == fid and f.get("status") is not None)
        expect(done is not None and done.get("state") == "resumed" and done.get("status") == 200,
               "loopback bus witness: flow ends state=resumed status=200", done)
        detail = ui.call("flow.detail", {"id": fid})
        body = decode_body(detail.get("response"))
        expect(tag.encode() in body, "captured response body (read back over /bus) carries the marker", body[:160])
        expect(detail.get("intercept") == "resumed", "flow.detail over /bus reports intercept=resumed", detail.get("intercept"))

        section("disarm over /bus, proven on the loopback bus")
        off = op.confirm("flow.intercept", {"enabled": False, "rules": []})
        expect(isinstance(off, dict) and off.get("enabled") is False and off.get("rules") == [],
               "disarmed over /bus (empty rule set)", off)
        expect(witness.call("proxy.status").get("intercept_armed") is False, "loopback bus witness sees intercept_armed=false")
    finally:
        if ctl is not None:
            try:
                ctl.try_call("flow.intercept", {"enabled": False, "rules": []})  # never leave the global arm behind
            except Exception:  # noqa: BLE001
                pass
        killer = ctl or witness
        if fid is not None and not resumed and killer is not None:
            try:
                killer.try_call("flow.kill", {"id": fid})  # never leave our flow parked
            except Exception:  # noqa: BLE001
                pass
        for c in clients:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        if core:
            core.stop()
        tgt.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: the web /bus bridge armed (operator), parked, resumed and disarmed a real flow on the live core")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
