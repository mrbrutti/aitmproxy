#!/usr/bin/env python3
# e2e: tier=T1 surface=l4 serial needs=l4
"""l4/l4_parity_priv -- the blocked-aware PRIVILEGED L4 walk (plan task A9, spec §6).

The walk prepared in the rig's walk4.py, as a real e2e cell: capture lo0 -> real HTTP (via the
proxy), raw TCP and UDP loopback traffic -> `l4.flow.get` shows the spec-§2 packet fields ->
craft + inject to the UDP echo -> `l4.send_recv` gets the echo -> an out-of-scope inject is
refused. Ground truth is the core's recorded flow against the traffic THIS script put on the
wire and the UDP echo replies it received -- never a fixture. It proves the "[D0]" halves:

  * AC1 live: every captured packet carries `bytes` (base64 of `length` bytes), `timestamp`
    (epoch ms), `proto`, `src`, `dst`, `src_port`, `dst_port`; a UDP packet to the echo port
    and a TCP packet to the HTTP port are among them.
  * AC2 live: `limit: 0` returns no packets and the total `packet_count`; `offset/limit`
    returns exactly that window (`offset` echoed); `truncated` is a bool and `next_offset`
    is null when not truncated.
  * AC35 live: an agent read of the same flow has every field but no `bytes` key (Capture
    gate closed).
  * AC34 live: the capture never records the bus connection this check itself makes: no
    packet with src_port or dst_port equal to the bus port (nor the proxy port), and the
    compiled BPF filter carries `not port <bus port>`.
  * AC8/AC1 inject: `l4.craft` + `l4.inject` to 127.0.0.1:<echo> records a craft flow with
    `injected: true`; `l4.send_recv` correlates the echo's reply; an inject to an
    out-of-scope port is refused by the guard.

Blocked-aware: the first step reads `l4.capture.status`; when `available` is false it prints
`blocked: needs approval: <the core's reason>` and exits 77 (the honest verdict on this Mac, where
/dev/bpf* is root-only). Every later step that hits the privilege wall SKIPs the same way.

Env model (like the sibling l4 cells): AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN (+ AITM_BUS_TOKEN
for the agent read, + AITM_PROXY_ADDR for the proxied HTTP rows). The traffic recipe mirrors
the rig: `python3 -m http.server` on AITM_L4_HTTP_PORT (default 9099) and the UDP echo on
AITM_L4_UDP_ECHO_PORT (default 9053), both inside the config scope 127.0.0.1/32 9000-9999 on
lo0. Tokens are never printed. Soft-assertion battery; exit 0 / 1 / 77. serial: a privileged
raw capture -- run it alone.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402

NEED_TOOLS = (
    "l4.scope.list", "l4.capture.status", "l4.capture.start", "l4.capture.stop", "l4.flow.get",
    "l4.flow.list", "l4.craft", "l4.inject", "l4.send_recv", "l4.agent.status",
)
UNAVAILABLE_HINTS = (
    "l4 unavailable", "pcap", "privilege", "permission", "/dev/bpf", "cap_net_raw",
    "not permitted", "operation not permitted",
)
UNAVAILABLE_PREFIX = "L4 unavailable: "
PROTOS = ("TCP", "UDP", "ICMP", "ICMPv6")
PACKET_KEYS = ("dir", "length", "injected", "layers", "timestamp", "proto", "src", "dst", "src_port", "dst_port")
FLOW_KEYS = ("id", "kind", "interface", "started_at", "proto", "src", "dst", "src_port", "dst_port",
             "packet_count", "injected_count", "offset", "truncated", "packets")
DEFAULT_LIMIT = 256
PAGE = 1024
OUT_OF_SCOPE_PORT = 7777
INJECT_SRC_PORT = 40000

_failures: list[str] = []
_skipped: list[str] = []


def expect(cond, msg: str, detail="") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {str(detail)[:300]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def skipped_check(msg: str, why: str) -> None:
    print(f"  [skipped] {msg}   -- {why}", flush=True)
    _skipped.append(msg)


def redact_bytes(value):
    """`value` with every `bytes` key replaced by its decoded length: packet bytes are
    never printed (a loopback capture may hold the core's own traffic; the log is not
    where they belong)."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "bytes" and isinstance(v, str):
                try:
                    out[k] = f"<{len(base64.b64decode(v))} bytes>"
                except (ValueError, TypeError):
                    out[k] = "<bytes>"
            else:
                out[k] = redact_bytes(v)
        return out
    if isinstance(value, list):
        return [redact_bytes(v) for v in value]
    return value


def show(label: str, value) -> None:
    print(f"note: {label} = {json.dumps(redact_bytes(value), default=str, sort_keys=True)[:500]}", flush=True)


def blocked(reason) -> None:
    """The honest verdict while capture needs approval (`l4.capture.status.reason`): print it
    bare (for the plan's grep) and SKIP with it."""
    line = f"blocked: needs approval: {reason}"
    print(line, flush=True)
    skip(line)


def confirm_call(bus, name, args):
    try:
        return True, bus.confirm(name, args)
    except (ToolError, BusError) as e:
        return False, str(e)


# ---- pure helpers (no bus, no exit; exercised with literal inputs) --------------------

def capture_status(reply):
    """(available, reason, capture_ids) from an `l4.capture.status` reply: the spec-§1
    object, or (older cores) a bare list meaning available."""
    if isinstance(reply, dict):
        return bool(reply.get("available", False)), reply.get("reason"), list(reply.get("captures") or [])
    if isinstance(reply, list):
        return True, None, list(reply)
    raise TypeError(f"unexpected l4.capture.status reply: {reply!r}")


def unavailable_reason(error_text: str):
    """The text after `L4 unavailable: ` in a gated verb's error, or None."""
    i = error_text.find(UNAVAILABLE_PREFIX)
    return error_text[i + len(UNAVAILABLE_PREFIX):] if i >= 0 else None


def looks_unavailable(error_text: str) -> bool:
    t = error_text.lower()
    return any(h in t for h in UNAVAILABLE_HINTS)


def port_of(addr: str) -> int:
    return int(addr.rsplit(":", 1)[1])


def packet_shape_errors(pkt, with_bytes: bool, now_ms=None) -> list[str]:
    """Why `pkt` is NOT a spec-§2 packet object; `[]` when it is. With `with_bytes` the
    `bytes` key must be padded base64 decoding to exactly `length` bytes; without it the
    key must be ABSENT (AC35). `timestamp` is epoch ms within a day of `now_ms` when given."""
    if not isinstance(pkt, dict):
        return [f"packet is {type(pkt).__name__}, not an object"]
    errs = [f"missing {k}" for k in PACKET_KEYS if k not in pkt]
    if pkt.get("dir") not in ("inbound", "outbound"):
        errs.append(f"dir {pkt.get('dir')!r}")
    length = pkt.get("length")
    if not (isinstance(length, int) and length > 0):
        errs.append(f"length {length!r}")
    if not isinstance(pkt.get("injected"), bool):
        errs.append(f"injected {pkt.get('injected')!r}")
    if not isinstance(pkt.get("layers"), list):
        errs.append(f"layers {pkt.get('layers')!r}")
    ts = pkt.get("timestamp")
    if not (isinstance(ts, int) and ts > 0):
        errs.append(f"timestamp {ts!r} (epoch ms expected)")
    elif now_ms is not None and abs(now_ms - ts) > 86_400_000:
        errs.append(f"timestamp {ts} is more than a day from now ({now_ms})")
    proto = pkt.get("proto")
    if proto is not None and proto not in PROTOS:
        errs.append(f"proto {proto!r}")
    for k in ("src", "dst"):
        v = pkt.get(k)
        if v is not None and not isinstance(v, str):
            errs.append(f"{k} {v!r}")
    for k in ("src_port", "dst_port"):
        v = pkt.get(k)
        if v is not None and not (isinstance(v, int) and 0 <= v <= 65535):
            errs.append(f"{k} {v!r}")
    if with_bytes:
        b = pkt.get("bytes")
        if not isinstance(b, str):
            errs.append(f"bytes {type(b).__name__} (base64 string expected)")
        else:
            try:
                raw = base64.b64decode(b, validate=True)
            except (ValueError, TypeError):
                errs.append("bytes is not valid padded base64")
            else:
                if isinstance(length, int) and len(raw) != length:
                    errs.append(f"bytes decodes to {len(raw)} bytes, length says {length}")
    elif "bytes" in pkt:
        errs.append("bytes present for a caller that must not see them")
    return errs


def flow_shape_errors(flow) -> list[str]:
    if not isinstance(flow, dict):
        return [f"flow is {type(flow).__name__}, not an object"]
    errs = [f"missing {k}" for k in FLOW_KEYS if k not in flow]
    if "next_offset" not in flow:
        errs.append("missing next_offset")
    if not (isinstance(flow.get("started_at"), int) and flow.get("started_at") > 0):
        errs.append(f"started_at {flow.get('started_at')!r}")
    if not isinstance(flow.get("truncated"), bool):
        errs.append(f"truncated {flow.get('truncated')!r}")
    if flow.get("truncated") is False and flow.get("next_offset") is not None:
        errs.append(f"next_offset {flow.get('next_offset')!r} while not truncated")
    if flow.get("truncated") is True and not isinstance(flow.get("next_offset"), int):
        errs.append(f"next_offset {flow.get('next_offset')!r} while truncated")
    return errs


def touches_port(pkt: dict, port: int) -> bool:
    return pkt.get("src_port") == port or pkt.get("dst_port") == port


def self_traffic(packets, ports) -> list[dict]:
    """The packets whose src_port or dst_port is one of the core's own listener `ports`
    (AC34: must be empty for a capture that ran while this script talked to the bus)."""
    return [p for p in packets if any(touches_port(p, port) for port in ports if port is not None)]


def packets_to(packets, proto: str, dst_port: int) -> list[dict]:
    return [p for p in packets if p.get("proto") == proto and p.get("dst_port") == dst_port]


def window_errors(full: list[dict], win: dict, offset: int, limit: int) -> list[str]:
    """`win` (an `l4.flow.get {offset, limit}` reply) must echo `offset` and carry exactly
    `full[offset:offset+limit]` by (timestamp, length, bytes); `full` is an earlier
    default-window read of the same append-only log, so a prefix comparison is exact."""
    errs = []
    if win.get("offset") != offset:
        errs.append(f"offset echoed as {win.get('offset')!r}, asked {offset}")
    got = win.get("packets")
    if not isinstance(got, list):
        return errs + [f"packets {got!r}"]
    want = full[offset:offset + limit]
    key = lambda p: (p.get("timestamp"), p.get("length"), p.get("bytes"))  # noqa: E731
    if len(got) > limit:
        errs.append(f"{len(got)} packets for limit {limit}")
    n = min(len(got), len(want))
    if [key(p) for p in got[:n]] != [key(p) for p in want[:n]]:
        errs.append(f"window differs from the earlier read's slice [{offset}:{offset + limit}]")
    if len(got) < len(want):
        errs.append(f"window has {len(got)} packets, the earlier read had {len(want)} there")
    return errs


def udp_spec(src_port: int, dst_port: int, payload: bytes) -> dict:
    return {"layers": [
        {"ipv4": {"src": "127.0.0.1", "dst": "127.0.0.1"}},
        {"udp": {"src_port": src_port, "dst_port": dst_port}},
        {"raw": list(payload)},
    ]}


_SELF_EXCLUSION = re.compile(
    r"(?:^|\band\s+)not\s+(?:port\s+(\d+)|\(((?:port\s+\d+\s+or\s+)*port\s+\d+)\))\s*$")


def bpf_excluded_ports(bpf) -> list[int]:
    """The ports in the self-exclusion clause spec §2.1 ANDs onto a loopback capture's BPF
    filter: a trailing `not port P` (one self port) or `not (port A or port B ...)` (several,
    ascending). `[]` when the filter has no such clause. (A substring test for
    `not port <bus>` misses the multi-port form, which is what a real core with proxy,
    browser, bus and web listeners compiles.)"""
    if not isinstance(bpf, str):
        return []
    m = _SELF_EXCLUSION.search(bpf.strip())
    if not m:
        return []
    if m.group(1):
        return [int(m.group(1))]
    return [int(p) for p in re.findall(r"port\s+(\d+)", m.group(2))]


def scope_covers_port(entry: dict, port: int) -> bool:
    """Whether an `l4.scope.list` entry's `ports` (`lo-hi`) covers `port`."""
    lo, _, hi = str(entry.get("ports", "0-65535")).partition("-")
    try:
        return int(lo) <= port <= int(hi or lo)
    except ValueError:
        return False


def is_loopback_v4_cidr(cidr: str) -> bool:
    return cidr.split("/", 1)[0].strip().startswith("127.")


# ---- traffic ----------------------------------------------------------------------------

def drive_http(proxy_port, http_port: int, tag: str, n: int) -> tuple[int, int]:
    """n proxied GETs to the HTTP target (when a proxy is given) and n raw TCP connects.
    Returns (proxied round trips, raw connects that completed the handshake)."""
    proxied = connected = 0
    for i in range(n):
        if proxy_port:
            try:
                via_proxy(proxy_port, "GET", f"http://127.0.0.1:{http_port}/?{tag}-{i}", timeout=5)
                proxied += 1
            except Exception as e:  # noqa: BLE001 -- a refused upstream still rode real TCP
                print(f"note: proxied GET {i} failed: {str(e)[:120]}", flush=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect(("127.0.0.1", http_port))
            connected += 1
        except OSError as e:
            print(f"note: raw TCP connect {i} to {http_port}: {e}", flush=True)
        finally:
            s.close()
    return proxied, connected


def drive_udp_echo(echo_port: int, tag: str, n: int) -> tuple[int, int]:
    """n datagrams to the UDP echo; returns (sent, echoes received) -- the echoes are the
    independent observer that the datagrams really reached a listener."""
    sent = got = 0
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1.0)
    try:
        for i in range(n):
            msg = f"{tag}-udp-{i}".encode()
            try:
                u.sendto(msg, ("127.0.0.1", echo_port))
                sent += 1
                data, _ = u.recvfrom(2048)
                if msg in data:
                    got += 1
            except OSError:
                pass
    finally:
        u.close()
    return sent, got


def read_all_packets(op, flow_id: str, max_pages: int = 16) -> list[dict]:
    out: list[dict] = []
    offset = 0
    for _ in range(max_pages):
        d = op.call("l4.flow.get", {"id": flow_id, "offset": offset, "limit": PAGE})
        pk = d.get("packets", [])
        out.extend(pk)
        if d.get("truncated") and isinstance(d.get("next_offset"), int):
            offset = d["next_offset"]
            continue
        if len(pk) < PAGE:
            break
        offset += len(pk)
    return out


def wait_for(op, flow_id: str, http_port: int, echo_port: int, timeout: float):
    deadline = time.monotonic() + timeout
    while True:
        d = op.call("l4.flow.get", {"id": flow_id})
        pk = d.get("packets", [])
        if packets_to(pk, "TCP", http_port) and packets_to(pk, "UDP", echo_port):
            return d
        if time.monotonic() >= deadline:
            return d
        time.sleep(0.3)


def main() -> int:
    bus_addr = os.environ.get("AITM_BUS_ADDR")
    op_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN")
    agent_token = os.environ.get("AITM_BUS_TOKEN", "")
    if not (bus_addr and op_token):
        skip("no runner-provided L4 core: set AITM_BUS_ADDR + AITM_BUS_OPERATOR_TOKEN from an "
             "l4-enabled rig (l4.capture.* is operator-gated and raw capture needs /dev/bpf* "
             "read+write on macOS or CAP_NET_RAW on Linux)")
    bh, _, bp = bus_addr.rpartition(":")
    core = SimpleNamespace(bus_addr=(bh or "127.0.0.1", int(bp)),
                           cfg=SimpleNamespace(agent_token=agent_token, operator_token=op_token))
    bus_port = int(bp)
    pa = os.environ.get("AITM_PROXY_ADDR")
    proxy_port = port_of(pa) if pa else None
    http_port = int(os.environ.get("AITM_L4_HTTP_PORT", "9099"))
    echo_port = int(os.environ.get("AITM_L4_UDP_ECHO_PORT", "9053"))
    tag = f"l4parity-{uuid.uuid4().hex[:8]}"

    op = agent = None
    flow_id = None
    try:
        op = BusClient.operator(core)
        names = set(op.tool_names())
        missing = [t for t in NEED_TOOLS if t not in names]
        if missing:
            skip(f"the L4 module is not enabled on this core (missing {missing}); l4.enabled is opt-in "
                 "+ feature-compiled -- run this in the L4 rig")

        section("the capture binds the CONFIG-declared loopback scope")
        scope = op.call("l4.scope.list")
        loop_caps = [e for e in scope if e.get("capability") == "capture"
                     and e.get("source", "config") == "config" and is_loopback_v4_cidr(e.get("cidr", ""))]
        if not loop_caps:
            skip("no CONFIG-declared loopback capture scope (source == \"config\"); declare the rig's "
                 "l4.scope entries (lo0 127.0.0.1/32 9000-9999 capture/inject/intercept)")
        iface = loop_caps[0]["interface"]
        direction = loop_caps[0].get("direction", "inbound")
        print(f"note: iface={iface!r} direction={direction!r} http={http_port} echo={echo_port} "
              f"bus_port={bus_port} proxy_port={proxy_port}", flush=True)

        section("step 0: l4.capture.status decides blocked-or-walk")
        st, rep = op.try_call("l4.capture.status")
        show("l4.capture.status", rep)
        if st == "error":
            blocked(unavailable_reason(str(rep)) or str(rep))
        available, reason, pre_ids = capture_status(rep)
        if not available:
            blocked(reason)
        ok("capture is available on this core; the privileged walk runs")

        section("step 1: start the real lo0 capture")
        ok_s, started = confirm_call(op, "l4.capture.start", {"interface": iface, "direction": direction})
        if not ok_s:
            if looks_unavailable(str(started)):
                blocked(unavailable_reason(str(started)) or str(started))
            fail(f"l4.capture.start was refused unexpectedly: {str(started)[:300]}")
        flow_id = started.get("flow_id") if isinstance(started, dict) else None
        if not flow_id:
            fail(f"l4.capture.start returned no flow id: {started!r}")
        expect(flow_id in capture_status(op.call("l4.capture.status"))[2], "the capture is listed as running", flow_id)
        head = op.call("l4.flow.get", {"id": flow_id, "limit": 0})
        bpf = head.get("filter")
        print(f"note: capture flow {flow_id} filter={bpf!r}", flush=True)
        excluded = bpf_excluded_ports(bpf)
        expect(bus_port in excluded, "the compiled BPF filter excludes the bus port (AC34 self-exclusion)", bpf)
        if proxy_port:
            expect(proxy_port in excluded, "the compiled BPF filter excludes the proxy port (AC34 self-exclusion)", bpf)

        section("step 2: real HTTP (via the proxy), raw TCP and UDP-echo traffic while the capture runs")
        proxied, connected = drive_http(proxy_port, http_port, tag, n=3)
        udp_sent, echoes = drive_udp_echo(echo_port, tag, n=5)
        print(f"note: proxied={proxied} raw_tcp_connected={connected} udp_sent={udp_sent} echoes={echoes}", flush=True)
        expect(connected >= 1, f"the HTTP target on 127.0.0.1:{http_port} accepted a real TCP connection", connected)
        expect(echoes >= 1, f"the UDP echo on 127.0.0.1:{echo_port} really echoed our datagrams", echoes)
        if proxy_port:
            expect(proxied >= 1, "at least one GET rode the proxy to the HTTP target", proxied)

        section("step 3: l4.flow.get shows the spec §2 fields per packet (AC1 live)")
        detail = wait_for(op, flow_id, http_port, echo_port, timeout=20.0)
        pkts = detail.get("packets", [])
        total = detail.get("packet_count", 0)
        now_ms = int(time.time() * 1000)
        print(f"note: packet_count={total} window={len(pkts)} first={redact_bytes(pkts[:1])}", flush=True)
        if total == 0:
            skip(f"capture opened on {iface!r}/{direction!r} but recorded nothing for our real loopback "
                 "traffic -- the live feed is not functional here (privilege / direction)")
        ferrs = flow_shape_errors(detail)
        expect(not ferrs, "the flow object has the §2 flow fields (started_at, addresses, offset, truncated)", ferrs)
        expect(detail.get("kind") == "capture" and detail.get("interface") == iface, "kind capture on the scoped interface",
               (detail.get("kind"), detail.get("interface")))
        bad = [(i, e) for i, p in enumerate(pkts) for e in [packet_shape_errors(p, True, now_ms)] if e]
        expect(not bad, "every packet carries bytes, timestamp, proto, src, dst, src_port, dst_port", bad[:3])
        udp_to_echo = packets_to(pkts, "UDP", echo_port)
        tcp_to_http = packets_to(pkts, "TCP", http_port)
        expect(bool(udp_to_echo), f"a captured UDP packet is addressed to the echo port {echo_port}", [p.get("dst_port") for p in pkts[:8]])
        expect(bool(tcp_to_http), f"a captured TCP packet is addressed to the HTTP port {http_port}", [p.get("dst_port") for p in pkts[:8]])
        if udp_to_echo:
            p0 = udp_to_echo[0]
            raw = base64.b64decode(p0.get("bytes", ""))
            expect(p0.get("src") == "127.0.0.1" and p0.get("dst") == "127.0.0.1", "the UDP packet is 127.0.0.1 -> 127.0.0.1", (p0.get("src"), p0.get("dst")))
            expect(tag.encode() in raw, "the UDP packet's bytes carry this run's payload tag", f"{len(raw)} bytes")
        expect(len(pkts) <= DEFAULT_LIMIT, f"the default window holds at most {DEFAULT_LIMIT} packets", len(pkts))

        section("step 4: the bounded window (AC2 live)")
        zero = op.call("l4.flow.get", {"id": flow_id, "limit": 0})
        expect(zero.get("packets") == [] and zero.get("packet_count", -1) >= total and zero.get("offset") == 0,
               "limit: 0 returns no packets and the total packet_count", {k: zero.get(k) for k in ("offset", "packet_count", "packets")})
        if len(pkts) >= 3:
            win = op.call("l4.flow.get", {"id": flow_id, "offset": 1, "limit": 2})
            werrs = window_errors(pkts, win, 1, 2)
            expect(not werrs, "offset 1, limit 2 returns exactly that slice with offset echoed", werrs)
        else:
            skipped_check("offset/limit slice", f"only {len(pkts)} packets captured")
        expect(detail.get("truncated") is False and detail.get("next_offset") is None,
               "a small window is not truncated (truncated false, next_offset null)",
               (detail.get("truncated"), detail.get("next_offset")))

        section("step 5: AC34 -- the capture never recorded this script's own bus connection")
        if not scope_covers_port(loop_caps[0], bus_port):
            skipped_check("AC34 packet-level drop is discriminating here",
                          f"the config capture scope ports {loop_caps[0].get('ports')!r} do not cover the bus "
                          f"port {bus_port}, so scope alone keeps the bus out of this capture; the BPF "
                          "exclusion check in step 1 and the unit tests are the proof of self-exclusion")
        all_pkts = read_all_packets(op, flow_id)
        own = self_traffic(all_pkts, (bus_port, proxy_port))
        print(f"note: scanned {len(all_pkts)} packets for ports {(bus_port, proxy_port)}", flush=True)
        expect(len(all_pkts) >= len(pkts), "the full log was read back through offset paging", len(all_pkts))
        expect(not own, f"no packet has src_port or dst_port == the bus port {bus_port} (or the proxy port)",
               [(p.get("src_port"), p.get("dst_port")) for p in own[:5]])

        section("step 6: AC35 -- an agent read of the same flow has no bytes")
        if agent_token:
            agent = BusClient.agent(core)
            gates = op.call("l4.agent.status")
            st_a, rep_a = agent.try_call("l4.flow.get", {"id": flow_id, "limit": 5})
            expect(st_a == "ok", "the agent can read l4.flow.get (read verb)", rep_a)
            if st_a == "ok":
                apk = rep_a.get("packets", [])
                if gates.get("capture") is True:
                    skipped_check("agent packets have no bytes", "the agent Capture gate is OPEN on this core; bytes are allowed")
                else:
                    abad = [e for p in apk for e in [packet_shape_errors(p, False, now_ms)] if e]
                    expect(bool(apk) and not abad, "agent packets carry every §2 field but no bytes key", abad[:3])
        else:
            skipped_check("agent l4.flow.get has no bytes", "AITM_BUS_TOKEN not set")

        section("step 7: craft + inject a UDP datagram to the echo (in scope)")
        payload = f"{tag}-inject".encode()
        spec = udp_spec(INJECT_SRC_PORT, echo_port, payload)
        crafted = op.call("l4.craft", {"spec": spec})
        show("l4.craft", {k: crafted.get(k) for k in ("length", "summary")})
        clen = crafted.get("length")
        expect(isinstance(clen, int) and clen == 20 + 8 + len(payload), "l4.craft builds the IPv4/UDP datagram (length = 28 + payload)", clen)
        expect(isinstance(crafted.get("bytes"), str) and len(base64.b64decode(crafted["bytes"])) == clen,
               "l4.craft bytes are base64 of `length` bytes")
        ok_i, inj = confirm_call(op, "l4.inject", {"spec": spec, "dst": "127.0.0.1", "port": echo_port,
                                                   "interface": iface, "count": 1})
        show("l4.inject", inj)
        if not ok_i and looks_unavailable(str(inj)):
            blocked(unavailable_reason(str(inj)) or str(inj))
        expect(ok_i and inj.get("sent") == 1, "l4.inject sent 1 datagram", inj)
        inj_flow = inj.get("flow_id") if ok_i and isinstance(inj, dict) else None
        if inj_flow:
            g = op.call("l4.flow.get", {"id": inj_flow})
            ipk = g.get("packets", [])
            expect(g.get("kind") == "craft" and g.get("injected_count") == 1, "the inject flow is a craft flow with injected_count 1",
                   (g.get("kind"), g.get("injected_count")))
            expect(bool(ipk) and ipk[0].get("injected") is True and ipk[0].get("proto") == "UDP"
                   and ipk[0].get("dst_port") == echo_port and ipk[0].get("src_port") == INJECT_SRC_PORT,
                   f"the recorded packet is injected: true, UDP {INJECT_SRC_PORT} -> {echo_port}", redact_bytes(ipk[:1]))
            expect(not [e for p in ipk for e in [packet_shape_errors(p, True, now_ms)] if e], "the injected packet carries the §2 fields")

        section("step 8: l4.send_recv gets the echo's reply")
        ok_r, sr = confirm_call(op, "l4.send_recv", {"spec": spec, "dst": "127.0.0.1", "port": echo_port,
                                                     "interface": iface, "timeout_ms": 2000})
        show("l4.send_recv", sr)
        if not ok_r and looks_unavailable(str(sr)):
            blocked(unavailable_reason(str(sr)) or str(sr))
        outcome = sr.get("outcome", {}) if ok_r and isinstance(sr, dict) else {}
        expect(ok_r and outcome.get("kind") in ("response", "responses"),
               "send_recv correlated the echo's reply (outcome response/responses)", outcome)
        if ok_r and isinstance(sr.get("flow_id"), str):
            sg = op.call("l4.flow.get", {"id": sr["flow_id"]})
            expect(sg.get("kind") == "send_recv" and sg.get("injected_count") == 1, "the send_recv flow records the stimulus as injected",
                   (sg.get("kind"), sg.get("injected_count")))

        section("step 9: an out-of-scope inject is refused by the guard")
        bad_spec = udp_spec(INJECT_SRC_PORT, OUT_OF_SCOPE_PORT, b"\x01")
        ok_b, refusal = confirm_call(op, "l4.inject", {"spec": bad_spec, "dst": "127.0.0.1", "port": OUT_OF_SCOPE_PORT,
                                                       "interface": iface})
        show("out-of-scope l4.inject", refusal)
        expect(not ok_b, f"l4.inject to 127.0.0.1:{OUT_OF_SCOPE_PORT} is refused", refusal)
        expect(not ok_b and ("out of L4 scope" in str(refusal) or "denylist" in str(refusal) or "capability" in str(refusal)),
               "the refusal names the scope/denylist (guard), not a transport failure", str(refusal)[-240:])
        if ok_r and isinstance(sr, dict) and isinstance(sr.get("flow_id"), str):
            expect(sr["flow_id"] in op.call("l4.flow.list"), "l4.flow.list carries the walk's flows")
        else:
            skipped_check("l4.flow.list carries the walk's flows", "send_recv did not run (no flow id to look for)")
    finally:
        if op is not None and flow_id is not None:
            try:
                op.try_call("l4.capture.stop", {"id": flow_id})
            except Exception:  # noqa: BLE001
                pass
        for c in (agent, op):
            if c is not None:
                c.close()

    if _skipped:
        print(f"note: {len(_skipped)} check(s) reported as skipped (see [skipped] lines)", flush=True)
    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:8]))
    ok("PASS: privileged L4 walk -- capture fields, window, self-exclusion, agent bytes, inject, send_recv, scope refusal")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
