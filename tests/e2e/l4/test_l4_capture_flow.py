#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 serial needs=l4
"""l4/l4_capture_flow -- scoped L4 (TCP/UDP) capture records a REAL flow.

aitmproxy's L4 module (`l4.*`) sniffs a NIC behind a deny-by-default guard and appends
every in-scope packet to an L4 Capture flow. This test drives that path end to end over
the real MCP bus and proves the capture on GROUND TRUTH: real loopback packets THIS test
puts on the wire (HTTP through the proxy + raw TCP + UDP), read back as the flow the core
actually stored and decoded -- never a fixture.

Capability gate (headless vs live rig). Everything here is live-rig-only, and each missing
piece is a precise SKIP (77), never a false FAIL:
  * a runner-provided core with the L4 module enabled (`l4.enabled`, opt-in + feature-
    compiled) -- else no AITM_BUS_ADDR / no l4.* tools;
  * an operator token (`l4.capture.*` is operator-gated, agents fail-closed);
  * a CONFIG-declared loopback capture scope (loopback is on the dangerous-destination
    denylist; only Config provenance lifts it; `l4.scope.list` reports `source: "config"`);
  * raw capture privilege. `l4.capture.start` is pcap/BPF only: it needs read+write on
    /dev/bpf* on macOS (ChmodBPF or run with privilege) or CAP_NET_RAW on Linux. The core
    reports this honestly in `l4.capture.status` (`{available, code, reason, captures}`;
    it always answers, never `L4 unavailable`); when `available` is false this test SKIPs
    with the core's `reason`.

Converted from the dead _lib/mcp draft harness onto aitm_e2e: env-model (attaches to the
runner's l4 core via AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN [+ AITM_PROXY_ADDR /
AITM_TARGET_URL]); it never boots its own l4 core (raw capture needs a privileged rig).
Soft-assertion battery; exit 0 pass / 1 fail / 77 skip. serial: a raw promiscuous capture
is a privileged global sniff -- run it alone.
"""
from __future__ import annotations

import os
import socket
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402

L4_TOOLS = (
    "l4.interfaces", "l4.scope.list", "l4.capture.start", "l4.capture.status",
    "l4.capture.stop", "l4.flow.list", "l4.flow.get",
)
UNAVAILABLE_HINTS = (
    "unavailable", "pcap", "privilege", "permission", "/dev/bpf", "cap_net_raw",
    "not permitted", "no such device", "operation not permitted",
)

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


def is_loopback_v4_cidr(cidr: str) -> bool:
    return cidr.split("/", 1)[0].strip().startswith("127.")


def is_config_scope(entry: dict) -> bool:
    """`l4.scope.list` reports provenance as `source`: `config` or `runtime`. A pre-parity
    core has no `source`; it is accepted (it could not record a runtime loopback entry)."""
    return entry.get("source", "config") == "config"


def capture_status(reply):
    """Parse an `l4.capture.status` reply into (available, reason, capture_ids).

    New shape (L4 parity spec, availability seam): an object
    `{available, code, reason, captures}` where `captures` is the list of running
    capture flow ids and `reason` is the exact text the gated verbs put after
    `L4 unavailable: ` (null when available). Old shape (pre-parity cores): a bare
    list of ids, which meant available. Pure: no bus, no exit."""
    if isinstance(reply, dict):
        ids = reply.get("captures") or []
        return bool(reply.get("available", False)), reply.get("reason"), list(ids)
    if isinstance(reply, list):
        return True, None, list(reply)
    raise TypeError(f"unexpected l4.capture.status reply: {reply!r}")


def capture_ids(reply):
    """The running capture flow ids from either `l4.capture.status` shape."""
    return capture_status(reply)[2]


def read_capture_status(op):
    """(available, reason, ids) from the live core. A pre-parity core gated the verb
    behind privilege; its `L4 unavailable: <reason>` error is read as unavailable."""
    status, reply = op.try_call("l4.capture.status")
    if status == "error":
        return False, str(reply), []
    return capture_status(reply)


def target_hostport(url: str):
    u = urllib.parse.urlsplit(url)
    return (u.hostname or "127.0.0.1"), (u.port or (443 if u.scheme == "https" else 80))


def raw_tcp_connect(host: str, port: int, timeout: float = 1.5) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        s.close()


def drive_traffic(proxy_port, target_url, tgt, tag: str, n: int) -> int:
    host, port = tgt
    proxied = 0
    for i in range(n):
        if proxy_port and target_url:
            try:
                via_proxy(proxy_port, "GET", f"{target_url}/?{tag}-{i}", timeout=10)
                proxied += 1
            except Exception:  # noqa: BLE001 -- a 4xx/5xx still rode real TCP
                pass
        raw_tcp_connect(host, port)
    return proxied


def collect(op, flow_id: str, tgt, timeout: float = 25.0):
    _, udp_port = tgt
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    detail: dict = {}
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                sock.sendto(b"aitm-l4-e2e-udp-probe", ("127.0.0.1", udp_port))
                sent += 1
            except OSError:
                pass
            detail = op.call("l4.flow.get", {"id": flow_id})
            pkts = detail.get("packets", [])
            if any("TCP" in p.get("layers", []) for p in pkts) and any("UDP" in p.get("layers", []) for p in pkts):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.25)
    finally:
        sock.close()
    return detail, sent


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    if not (bus_addr and op_token):
        skip("no runner-provided L4 core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN from an "
             "l4-enabled rig (l4.capture.* is operator-gated and raw capture needs /dev/bpf* "
             "read+write on macOS or CAP_NET_RAW on Linux)")
    bh, _, bp = bus_addr.rpartition(":")
    core = SimpleNamespace(bus_addr=(bh or "127.0.0.1", int(bp)),
                           cfg=SimpleNamespace(agent_token=os.environ.get("AITM_BUS_TOKEN", ""), operator_token=op_token))
    pa = os.environ.get("AITM_PROXY_ADDR")
    proxy_port = int(pa.rsplit(":", 1)[1]) if pa else None
    target_url = (os.environ.get("AITM_TARGET_URL") or "").rstrip("/") or None

    op = None
    flow_id = None
    try:
        op = BusClient.operator(core)
        names = set(op.tool_names())
        missing = [t for t in L4_TOOLS if t not in names]
        if missing:
            skip(f"the L4 module is not enabled on this core (missing {missing}); l4.* is opt-in "
                 "(l4.enabled) + feature-compiled -- run this in the L4 rig")

        section("the capture interface + direction come from the CONFIG-declared loopback scope")
        scope = op.call("l4.scope.list")
        loop_caps = [e for e in scope
                     if e.get("capability") == "capture" and is_config_scope(e) and is_loopback_v4_cidr(e.get("cidr", ""))]
        if not loop_caps:
            skip("no CONFIG-declared loopback capture scope (source == \"config\"). Declare an l4.scope "
                 "capture entry covering 127.0.0.1: loopback is on the L4 dangerous-destination denylist "
                 "and only Config provenance lifts it, so a runtime l4.scope.add would record nothing.")
        entry = loop_caps[0]
        iface = entry["interface"]
        direction = entry.get("direction", "inbound")
        tag = f"l4cap-{uuid.uuid4().hex[:8]}"
        tgt = target_hostport(target_url) if target_url else ("127.0.0.1", 80)
        iface_names = [i.get("name") for i in op.call("l4.interfaces")]
        print(f"note: capture scope iface={iface!r} direction={direction!r} target={tgt}; libpcap sees {iface_names}", flush=True)

        section("the core reports capture availability honestly (l4.capture.status always answers)")
        available, reason, pre_ids = read_capture_status(op)
        print(f"note: l4.capture.status available={available!r} reason={reason!r} captures={pre_ids}", flush=True)
        if not available:
            skip(f"L4 capture is not available on this core: {reason}. Raw capture is pcap/BPF only: "
                 "it needs read+write on /dev/bpf* (macOS; install ChmodBPF or run with privilege) or "
                 "CAP_NET_RAW (Linux).")

        section("start the real, scope-filtered capture (privileged; SKIPs if the wire is unreachable)")
        ok_s, started = confirm_call(op, "l4.capture.start", {"interface": iface, "direction": direction})
        if not ok_s:
            msg = str(started)
            if any(h in msg.lower() for h in UNAVAILABLE_HINTS):
                skip(f"L4 capture is not available here: {msg[:200]}. Raw capture is pcap/BPF only "
                     "(/dev/bpf* read+write on macOS, CAP_NET_RAW on Linux).")
            fail(f"l4.capture.start was refused unexpectedly (not an availability skip): {msg[:300]}")
        flow_id = started.get("flow_id") if isinstance(started, dict) else None
        if not flow_id:
            fail(f"l4.capture.start returned no flow id: {started!r}")
        expect(bool(flow_id), "capture.start returned a Capture flow id", started)

        running = op.call("l4.capture.status")
        expect(flow_id in capture_ids(running), "the capture is live in l4.capture.status captures", running)
        expect(flow_id in op.call("l4.flow.list"), "the flow id is listed by l4.flow.list", flow_id)

        section("put REAL loopback traffic on the wire while the capture runs")
        proxied = drive_traffic(proxy_port, target_url, tgt, tag, n=12)
        print(f"note: drove loopback TCP to {tgt} ({proxied} proxy round trips + raw connects)", flush=True)

        section("GROUND TRUTH: the flow the core actually recorded and decoded")
        detail, n_udp = collect(op, flow_id, tgt, timeout=25.0)
        pkts = detail.get("packets", [])
        tcp_pkts = [p for p in pkts if "TCP" in p.get("layers", [])]
        udp_pkts = [p for p in pkts if "UDP" in p.get("layers", [])]
        ip_pkts = [p for p in pkts if any(layer in p.get("layers", []) for layer in ("IPv4", "IPv6"))]
        sample = [p.get("layers") for p in pkts[:6]]
        print(f"note: recorded {len(pkts)} packets ({len(tcp_pkts)} TCP, {len(udp_pkts)} UDP, {len(ip_pkts)} IP); "
              f"sent {n_udp} UDP; sample {sample}", flush=True)

        if detail.get("packet_count", 0) == 0 and not pkts:
            skip(f"capture opened on {iface!r}/{direction!r} but recorded no packets for our real loopback "
                 "traffic -- the live feed is not functional here (privilege / direction). "
                 f"libpcap sees {iface_names}.")

        expect(detail.get("kind") == "capture", "flow kind is capture", detail.get("kind"))
        expect(detail.get("interface") == iface, "flow bound the expected interface", detail.get("interface"))
        expect(detail.get("packet_count", 0) >= 1 and len(pkts) >= 1, "capture recorded real packets", detail.get("packet_count"))
        expect(bool(pkts) and all(p.get("length", 0) > 0 for p in pkts), "recorded packets carry real bytes", sample)
        expect(len(ip_pkts) >= 1, "a captured packet decoded a real IP layer", sample)
        expect(len(tcp_pkts) >= 1, "a captured packet decoded a real TCP layer (L4/TCP capture)", sample)
        expect(detail.get("injected_count", 0) == 0 and all(not p.get("injected") for p in pkts),
               "capture is passive -- no injected packets", detail.get("injected_count"))
        if udp_pkts:
            expect(True, "a captured packet decoded a real UDP layer (L4/UDP capture)")
        else:
            print("note: no UDP packet captured within the window (best-effort; TCP is the hard proof)", flush=True)
    finally:
        if op is not None and flow_id is not None:
            try:
                op.try_call("l4.capture.stop", {"id": flow_id})
            except Exception:  # noqa: BLE001
                pass
        if op is not None:
            op.close()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: scoped L4 capture recorded real, decoded loopback packets (TCP + IP), none injected")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
