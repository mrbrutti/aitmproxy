#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 serial needs=l4
"""l4/l4_scope_self_exclusion -- L4 scope CONFINES a capture, and the core's own loopback
control-plane traffic stays OUT of it (no capture loop).

The sibling l4_capture_flow proves the positive half (an in-scope packet IS captured). This
proves the negative, deny-by-default half on the SAME real bus and real wire, on GROUND
TRUTH -- the packet counts the core recorded (l4.flow.get), an independent upstream's own
request log, and the scope-compiled BPF filter -- never a fixture:
  * CONFINEMENT: dozens of real loopback packets on OUT-of-scope ports (an HTTP upstream we
    own + UDP to a closed port) -- the upstream's log proves they happened, packet_count
    proves none were recorded.
  * NO CAPTURE LOOP: hammering the command bus itself (dozens of l4.flow.list round trips) --
    the core's own control-plane loopback traffic, out of scope -- is not swept up.
  * STILL LIVE: before + after the burst, in-scope traffic grows the capture (so "did not
    grow during the burst" is confinement, not a dead capture).

Capability gate (headless vs live rig), each a precise SKIP (77): an l4-enabled runner core,
an operator token, a CONFIG loopback capture scope NARROWED to a port range (so an out-of-
scope loopback port exists), and raw-capture privilege (libpcap/BPF; macOS NE). Converted
from the dead _lib/mcp draft harness onto aitm_e2e: env-model (AITM_BUS_ADDR +
AITM_BUS_OPERATOR_TOKEN [+ AITM_PROXY_ADDR / AITM_TARGET_URL]); never boots its own l4 core.
Soft-assertion battery; exit 0/1/77. serial: a privileged global sniff -- run it alone.
"""
from __future__ import annotations

import http.client
import http.server
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402

UNAVAILABLE_HINTS = (
    "unavailable", "pcap", "privilege", "permission", "approve the extension",
    "not permitted", "no such device", "operation not permitted",
)
OOS_ROUNDS = 30
BUS_ROUNDS = 40
OOS_TOLERANCE = 4

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


def confirm_call(bus, name, args):
    try:
        return True, bus.confirm(name, args)
    except (ToolError, BusError) as e:
        return False, str(e)


class Upstream:
    """A real, independent HTTP upstream on a random loopback port, recording the path of
    every request -- the ground-truth observer that the out-of-scope traffic really happened."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                owner.requests.append(self.path)
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                pass

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host, self.port = self._srv.server_address[0], self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def is_loopback_v4_cidr(cidr: str) -> bool:
    return cidr.split("/", 1)[0].strip().startswith("127.")


def parse_ports(spec: str):
    lo, _, hi = spec.partition("-")
    return int(lo), int(hi)


def in_any(port: int, ranges) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)


def port_of(addr: str) -> int:
    return int(addr.rsplit(":", 1)[1])


def packet_count(op, flow_id: str) -> int:
    return op.call("l4.flow.get", {"id": flow_id}).get("packet_count", 0)


def http_direct(host: str, port: int, path: str, timeout: float = 5.0) -> int:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    if not (bus_addr and op_token):
        skip("no runner-provided L4 core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN from an "
             "l4-enabled rig (l4.capture.* is operator-gated and raw capture needs NE/root)")
    bh, _, bp = bus_addr.rpartition(":")
    core = SimpleNamespace(bus_addr=(bh or "127.0.0.1", int(bp)),
                           cfg=SimpleNamespace(agent_token=os.environ.get("AITM_BUS_TOKEN", ""), operator_token=op_token))
    proxy_addr = os.environ.get("AITM_PROXY_ADDR")
    proxy_port = port_of(proxy_addr) if proxy_addr else None
    target_url = os.environ.get("AITM_TARGET_URL") or None

    op = None
    flow_id = None
    upstream = None
    try:
        op = BusClient.operator(core)
        need = ("l4.scope.list", "l4.capture.start", "l4.capture.stop", "l4.flow.get", "l4.flow.list")
        missing = [t for t in need if t not in set(op.tool_names())]
        if missing:
            skip(f"the L4 module is not enabled on this core (missing {missing}); l4.* is opt-in + "
                 "feature-compiled -- run this in the L4/NE rig")

        section("the in-scope target comes from the CONFIG-declared loopback capture scope")
        scope = op.call("l4.scope.list")
        loop_caps = [e for e in scope if e.get("capability") == "capture" and is_loopback_v4_cidr(e.get("cidr", ""))]
        if not loop_caps:
            skip("no CONFIG-declared loopback capture scope. Declare an l4.scope capture entry covering "
                 "127.0.0.1 (only Config provenance lifts the loopback denylist).")
        iface = loop_caps[0]["interface"]
        direction = loop_caps[0].get("direction", "inbound")
        in_ranges = [parse_ports(e.get("ports", "0-65535")) for e in loop_caps if e["interface"] == iface]
        if any(lo == 0 and hi == 65535 for lo, hi in in_ranges):
            skip("the loopback capture scope covers all ports (0-65535); no out-of-scope loopback port "
                 "exists to demonstrate confinement. Narrow the l4.scope capture entry to a port range.")

        bus_port = port_of(bus_addr)
        target_in_scope = False
        tgt_port = None
        if target_url:
            tgt = urllib.parse.urlsplit(target_url)
            tgt_port = tgt.port or (443 if tgt.scheme == "https" else 80)
            target_in_scope = (tgt.hostname or "").startswith("127.") and in_any(tgt_port, in_ranges)
        in_probe_port = in_ranges[0][0]

        expect(not in_any(bus_port, in_ranges), "the command-bus port is outside the capture scope", bus_port)
        if proxy_port is not None:
            expect(not in_any(proxy_port, in_ranges), "the proxy port is outside the capture scope", proxy_port)

        for _ in range(6):
            cand = Upstream()
            if not in_any(cand.port, in_ranges):
                upstream = cand
                break
            cand.close()
        if upstream is None:
            skip("could not bind an out-of-scope loopback upstream (every random port landed in scope)")
        oos_http_port = upstream.port
        reserved = {bus_port, proxy_port, tgt_port, oos_http_port}
        oos_udp_port = next(p for p in range(40000, 40100) if not in_any(p, in_ranges) and p not in reserved)
        tag = f"l4conf-{uuid.uuid4().hex[:8]}"

        section("start the real, scope-filtered capture (privileged; SKIPs if unreachable)")
        ok_s, started = confirm_call(op, "l4.capture.start", {"interface": iface, "direction": direction})
        if not ok_s:
            msg = str(started)
            if any(h in msg.lower() for h in UNAVAILABLE_HINTS):
                skip(f"L4 capture is not available here: {msg[:200]}. Raw capture needs libpcap/BPF "
                     "privilege; on macOS approve + enable the Network/System Extension first.")
            fail(f"l4.capture.start was refused unexpectedly (not an availability skip): {msg[:300]}")
        flow_id = started.get("flow_id") if isinstance(started, dict) else None
        if not flow_id:
            fail(f"l4.capture.start returned no flow id: {started!r}")

        bpf = op.call("l4.flow.get", {"id": flow_id}).get("filter")
        print(f"note: iface={iface!r} direction={direction!r} in_ranges={in_ranges} oos_http={oos_http_port} "
              f"oos_udp={oos_udp_port} bus={bus_port} filter={bpf!r}", flush=True)

        def whole_port(p):
            return bpf is not None and re.search(rf"(?<!\d){p}(?!\d)", bpf) is not None

        section("the scope compiled a narrowed BPF boundary (ground truth, before a packet moves)")
        expect(bool(bpf), "the capture compiled a narrowed BPF filter", bpf)
        expect(bool(bpf) and "127." in bpf, "the BPF filter confines to loopback", bpf)
        expect(not whole_port(oos_http_port), "the BPF filter does not name the out-of-scope upstream port", bpf)
        expect(not whole_port(bus_port), "the BPF filter does not name the command-bus port", bpf)

        def send_inscope(n: int) -> None:
            for i in range(n):
                if target_in_scope and proxy_port:
                    try:
                        via_proxy(proxy_port, "GET", f"{target_url}/?{tag}-in-{i}", timeout=10)
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    try:
                        s.connect(("127.0.0.1", in_probe_port))
                    except OSError:
                        pass
                    finally:
                        s.close()

        def wait_grow(base: int, timeout: float = 20.0):
            deadline = time.monotonic() + timeout
            while True:
                send_inscope(4)
                detail = op.call("l4.flow.get", {"id": flow_id})
                if detail.get("packet_count", 0) > base or time.monotonic() >= deadline:
                    return detail

        section("LIVE control: real in-scope traffic grows the capture")
        base0 = packet_count(op, flow_id)
        d1 = wait_grow(base0)
        c1 = d1.get("packet_count", 0)
        if c1 <= base0:
            skip(f"the capture opened but recorded no in-scope packets on {iface!r}/{direction!r}; loopback "
                 "capture is likely unavailable here (privilege, or direction mismatch). Nothing to confine against.")
        expect(c1 > base0, "the capture records in-scope traffic (it is live)", (base0, c1))
        ip_or_tcp = any(any(layer in p.get("layers", []) for layer in ("IPv4", "IPv6", "TCP")) for p in d1.get("packets", []))
        expect(ip_or_tcp, "captured in-scope packets decoded a real IP/TCP layer", [p.get("layers") for p in d1.get("packets", [])[:6]])

        section("the OUT-OF-SCOPE + OWN-traffic burst -- NONE of it may be captured")
        time.sleep(1.0)
        c_settle = packet_count(op, flow_id)
        echo_before = len(upstream.requests)
        for i in range(OOS_ROUNDS):
            try:
                http_direct(upstream.host, oos_http_port, f"/oos-direct?{tag}-{i}")
            except OSError:
                pass
        proxied = 0
        if proxy_port:
            for i in range(OOS_ROUNDS):
                try:
                    via_proxy(proxy_port, "GET", upstream.url(f"/oos-proxy?{tag}-{i}"), timeout=10)
                    proxied += 1
                except Exception:  # noqa: BLE001
                    pass
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(10):
            try:
                udp.sendto(b"aitm-l4-oos-udp", ("127.0.0.1", oos_udp_port))
            except OSError:
                pass
        udp.close()
        for _ in range(BUS_ROUNDS):
            op.call("l4.flow.list")
        time.sleep(1.0)
        c_oos = packet_count(op, flow_id)
        oos_growth = c_oos - c_settle
        echo_got = len(upstream.requests) - echo_before
        print(f"note: out-of-scope burst: upstream received {echo_got} real requests (direct {OOS_ROUNDS} + "
              f"proxied {proxied}), {BUS_ROUNDS} bus round trips; capture grew by {oos_growth}", flush=True)

        expect(echo_got >= OOS_ROUNDS, "the out-of-scope upstream really received the traffic", echo_got)
        expect(oos_growth <= OOS_TOLERANCE,
               "out-of-scope and the core's own loopback traffic are not captured (no capture loop)",
               {"grew_by": oos_growth, "settle": c_settle, "after": c_oos, "tolerance": OOS_TOLERANCE})

        section("still live: in-scope traffic grows the capture again (so the burst was confinement)")
        c2 = wait_grow(c_oos).get("packet_count", 0)
        expect(c2 > c_oos, "the capture is still live -- in-scope traffic grows it again", (c_oos, c2))
    finally:
        if op is not None and flow_id is not None:
            try:
                op.try_call("l4.capture.stop", {"id": flow_id})
            except Exception:  # noqa: BLE001
                pass
        if upstream is not None:
            upstream.close()
        if op is not None:
            op.close()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: L4 scope confined the capture -- in-scope traffic recorded, out-of-scope + the core's own bus traffic excluded")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
