#!/usr/bin/env python3
# e2e: tier=T1 surface=status needs=lsof
"""`proxy.status` tells the truth: the address it reports is the socket the KERNEL
shows bound by the very process that answered, and its counts move with REAL
traffic the kernel can see in flight.

What the command is (crates/aitm-plugins/src/control.rs; Sensitivity::Read, no
params): {listening, address, intercept_armed, capturing, paused, flows, version}.
`address` is the configured listen address and `listening` the real serving flag;
`flows` is the store's visible count -- a flow is inserted the moment its request
head is parsed (crates/aitm-proto-http/src/module.rs, `RequestHeaders`), so a
request still waiting on its origin already counts; `paused` is the parked
(intercepted) count; `version` the workspace version. The TUI pill, the web
sidebar, the mac app and every agent trust this one call to learn where the proxy
is and how much it holds. This test proves it against observers the command does
not control:

  KERNEL   lsof, calibrated first on this process's OWN bus connection (and a
           free-port negative control) so a blind observer can never pass: the
           reported address is in LISTEN, owned by exactly one process, an `aitm`,
           and that PID is the PID that owns the bus listener we are talking to --
           the answer comes from the process that holds the socket. It agrees with
           AITM_PROXY_ADDR when the runner states one.
  TRAFFIC  N real GETs sent by a real client TO THE REPORTED ADDRESS (not to the
           env) reach a recording echo origin -- its own record is the ground
           truth -- come back 200, and `flows` grows by at least N with all N ids
           in `flow.list`; a stable read has `flows == len(flow.list)` exactly.
  INFLIGHT K requests to a HOLDING origin (it records each arrival, then withholds
           the response): while held, lsof shows OUR K client connections
           ESTABLISHED on the aitm PID at the proxy port -- matched by our own
           local ports, so a shared core's other traffic cannot inflate or hide
           the count -- plus exactly K connections from the aitm PID to the
           origin, and `flows` already counts them (flow.table rows, status null).
           After release: K x 200, the connections leave ESTABLISHED, the rows
           carry 200, and `flows` keeps them.
  CONSIST  `version` equals the `serverInfo.version` the same process gave at
           `initialize`; the operator (when a token is given) sees the same
           listening / address / version as the agent.

Core: the one the runner provides (AITM_BUS_ADDR, AITM_BUS_TOKEN; optional
AITM_BUS_OPERATOR_TOKEN, AITM_PROXY_ADDR). Nothing is booted here; without that
contract, or without a usable lsof, the test SKIPs (77) loudly. Shared-core safe:
unique per-run markers, our own origins on random ports, kernel matching by our own
socket ports. The only state touched is capture, and only if the runner left it
paused and an operator token allows resuming it. Tokens are never printed.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)
STATUS_KEYS = {
    "listening": bool, "address": str, "intercept_armed": bool, "capturing": bool,
    "paused": int, "flows": int, "version": str,
}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
WILDCARD_HOSTS = {"0.0.0.0", "::", "*"}
UPSTREAM_MARKER = "aitm-e2e-upstream"  # aitm_e2e.upstream's echo body
N_PLAIN = 5          # completed requests for the `flows` delta
K_HELD = 3           # requests held in flight for the kernel count
HOLD_MAX = 20.0      # the origin releases by itself after this (proxy timeouts are 30s+)
LSOF_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# a soft-assertion battery: every failed expectation prints, the run goes on (and
# cleans up), exit code 1 iff anything failed. Preconditions use check()/fail().

_failures: list[str] = []
_secrets: list[str] = []


def scrub(x: object) -> str:
    s = str(x)
    for t in _secrets:
        if t:
            s = s.replace(t, "<token>")
    return s


def expect(cond: object, msg: str, detail: object = "") -> bool:
    if cond:
        ok(msg)
        return True
    line = f"  [FAIL] {msg}"
    if detail != "":
        line += f"   -- {scrub(detail)[:600]}"
    print(line, flush=True)
    _failures.append(msg)
    return False


def is_type(v: object, t: type) -> bool:
    if t is int:
        return isinstance(v, int) and not isinstance(v, bool)
    return isinstance(v, t)


def hostport(raw: object) -> tuple[str, int]:
    host, sep, port = str(raw).strip().rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"not host:port: {raw!r}")
    return host.strip("[]"), int(port)


def wait_until(pred, timeout: float, step: float = 0.1) -> bool:
    deadline = time.time() + timeout
    while True:
        if pred():
            return True
        if time.time() > deadline:
            return False
        time.sleep(step)


def unbound_port() -> int:
    """A port nobody listens on, for the lsof negative control."""
    try:
        return free_port()
    except OSError:  # binding forbidden here; any random high port will do
        return random.randint(40000, 60000)


def process_name(pid: int) -> str:
    try:
        r = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True, timeout=20)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------------------
# the kernel observer: TCP sockets as lsof reports them


class Lsof:
    def __init__(self) -> None:
        self.bin = shutil.which("lsof") or ("/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else None)

    def sockets(self, *selectors: str):
        """[{pid, cmd, name}] for the TCP sockets matching ALL `selectors`; [] when
        nothing matched (lsof exit 1); None when lsof itself failed."""
        r = subprocess.run([self.bin, "-nP", "-a", *selectors, "-F", "pcn"],
                           capture_output=True, text=True, timeout=LSOF_TIMEOUT)
        if r.returncode not in (0, 1):
            return None
        out: list[dict] = []
        pid, cmd = None, ""
        for line in r.stdout.splitlines():
            tag, val = line[:1], line[1:]
            if tag == "p" and val.isdigit():
                pid, cmd = int(val), ""
            elif tag == "c":
                cmd = val
            elif tag == "n" and pid is not None:
                out.append({"pid": pid, "cmd": cmd, "name": val})
        return out

    def listeners(self, port: int):
        return self.sockets(f"-iTCP:{port}", "-sTCP:LISTEN")

    def established(self, pid: int, port: int):
        return self.sockets("-p", str(pid), f"-iTCP:{port}", "-sTCP:ESTABLISHED")


def ends(name: str) -> tuple[tuple[str, int] | None, tuple[str, int] | None]:
    """(local, foreign) of an lsof name like `127.0.0.1:80->127.0.0.1:5`; a LISTEN
    name has no foreign end."""
    local, _, foreign = name.partition("->")

    def parse(s: str):
        try:
            return hostport(s)
        except ValueError:
            return None

    return parse(local), (parse(foreign) if foreign else None)


def local_port(entry: dict):
    loc, _ = ends(entry["name"])
    return loc[1] if loc else None


def foreign_port(entry: dict):
    _, far = ends(entry["name"])
    return far[1] if far else None


def listen_matches(entry: dict, host: str, port: int) -> bool:
    loc, _ = ends(entry["name"])
    if not loc or loc[1] != port:
        return False
    if host in WILDCARD_HOSTS:
        return loc[0] in WILDCARD_HOSTS
    return loc[0] == host or (host == "localhost" and loc[0] == "127.0.0.1")


def peer_ports(entries, port: int) -> set[int]:
    """Foreign ports of the ESTABLISHED sockets whose LOCAL port is `port`."""
    return {foreign_port(e) for e in (entries or []) if local_port(e) == port and foreign_port(e) is not None}


# ---------------------------------------------------------------------------
# the holding origin + raw held clients (the in-flight leg)


class HoldOrigin:
    """A loopback HTTP/1.1 origin that RECORDS each arrival, then WITHHOLDS its
    response until release() (or HOLD_MAX), so a request stays in flight through
    the proxy exactly as long as the test needs to look at the kernel."""

    def __init__(self) -> None:
        self.port = free_port()
        self._release = threading.Event()
        self._lock = threading.Lock()
        self._paths: list[str] = []
        origin = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                with origin._lock:
                    origin._paths.append(self.path)
                origin._release.wait(HOLD_MAX)
                body = json.dumps({"observed_by": "aitm-e2e-hold-origin", "path": self.path}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def base(self) -> str:
        return f"http://{self.authority}"

    def arrived(self, tag: str) -> int:
        with self._lock:
            return sum(1 for p in self._paths if tag in p)

    def release(self) -> None:
        self._release.set()

    def start(self) -> "HoldOrigin":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._release.set()
        self._server.shutdown()
        self._server.server_close()


class HeldRequest:
    """One raw client connection with a request sent and its response NOT yet read:
    the kernel sees it ESTABLISHED at the proxy for as long as the origin holds."""

    def __init__(self, dial: str, port: int, url: str, authority: str) -> None:
        self.sock = socket.create_connection((dial, port), timeout=HOLD_MAX + 15)
        self.local_port = self.sock.getsockname()[1]
        self.sock.sendall(f"GET {url} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode())

    def finish(self) -> int:
        resp = http.client.HTTPResponse(self.sock, method="GET")
        resp.begin()
        resp.read()
        self.close()
        return resp.status

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# bus helpers


def status(bus: BusClient) -> dict:
    s = bus.call("proxy.status")
    if not isinstance(s, dict):
        fail(f"proxy.status did not answer an object: {str(s)[:120]!r}")
    return s


def rows_with(bus: BusClient, tag: str) -> list[dict]:
    return [r for r in bus.call("flow.table")["flows"] if tag in (r.get("path") or "")]


def wait_rows(bus: BusClient, tag: str, n: int, *, done: bool, timeout: float = 10.0) -> list[dict]:
    def ready() -> bool:
        rows = rows_with(bus, tag)
        return len(rows) >= n and (not done or all(r.get("status") is not None for r in rows))
    wait_until(ready, timeout)
    return rows_with(bus, tag)


def stable_snapshot(bus: BusClient, tries: int = 8):
    """(flows, flow.list) read while nothing moved between two proxy.status reads,
    so the equality is judged on one consistent instant even on a busy shared
    core; else (a, flow.list, b) with a < b for a bounds check."""
    a = b = None
    ids: list = []
    for _ in range(tries):
        a = status(bus)["flows"]
        ids = bus.call("flow.list")
        b = status(bus)["flows"]
        if a == b:
            return "stable", a, ids, b
    return "moving", a, ids, b


# ---------------------------------------------------------------------------


def main() -> int:
    addr = os.environ.get(ENV_BUS_ADDR, "").strip()
    token = os.environ.get(ENV_BUS_TOKEN, "")
    if not (addr and token):
        skip(f"no runner-provided core: {ENV_BUS_ADDR} + {ENV_BUS_TOKEN} must name the live bus (this test boots nothing)")
    _secrets.append(token)
    op_token = os.environ.get(ENV_OP_TOKEN) or None
    if op_token:
        _secrets.append(op_token)
    try:
        bus_host, bus_port = hostport(addr)
    except ValueError:
        fail(f"{ENV_BUS_ADDR} must be host:port (got {addr!r})")
    core = SimpleNamespace(bus_addr=(bus_host, bus_port),
                           cfg=SimpleNamespace(agent_token=token, operator_token=op_token))
    lsof = Lsof()
    if not lsof.bin:
        skip("lsof is not installed: the kernel observer this test asserts against is missing")
    run = secrets.token_hex(4)
    me = os.getpid()

    agent = op = None
    plain = origin = None
    held: list[HeldRequest] = []
    try:
        # ---------------------------------------------------------------
        section("arrange: attach to the runner's core; calibrate the kernel observer on our OWN bus connection")
        agent = BusClient.agent(core)
        server_info = (agent.initialize() or {}).get("serverInfo") or {}
        names = set(agent.tool_names())
        for need in ("proxy.status", "flow.list", "flow.table"):
            check(need in names, f"the live core registers {need} ({len(names)} tools)")
        our_port = agent._sock.getsockname()[1]  # the socket BusClient opened to the bus
        seen = lsof.established(me, bus_port)
        if seen is None:
            skip("lsof cannot enumerate sockets in this environment (it failed even on our own process)")
        if not any(local_port(e) == our_port and foreign_port(e) == bus_port for e in seen):
            skip(f"lsof does not show this process's own bus connection (:{our_port}->:{bus_port}); "
                 f"the kernel observer is unusable here ({[e['name'] for e in seen][:4]})")
        ok(f"lsof calibrated: it sees our own bus connection 127.0.0.1:{our_port}->{bus_host}:{bus_port} on PID {me}")
        ctrl = unbound_port()
        none = lsof.listeners(ctrl)
        check(none == [], f"negative control: no LISTEN on the unbound port {ctrl} (the observer discriminates; got {none})")

        # ---------------------------------------------------------------
        section("proxy.status: the shape, then the reported address against the kernel")
        s0 = status(agent)
        for key, ty in STATUS_KEYS.items():
            expect(is_type(s0.get(key), ty), f"{key} is a {ty.__name__} ({scrub(repr(s0.get(key)))})")
        expect(s0.get("listening") is True, "listening is true on a serving core", s0)
        try:
            host, port = hostport(s0.get("address"))
        except ValueError:
            fail(f"proxy.status.address is not host:port: {s0.get('address')!r}")
        dial = "127.0.0.1" if host in LOOPBACK_HOSTS | WILDCARD_HOSTS else host
        check(dial == "127.0.0.1",
              f"the reported listen host {host!r} is loopback/wildcard, dialable at 127.0.0.1 (the e2e runner contract)")
        env_proxy = os.environ.get(ENV_PROXY_ADDR)
        if env_proxy:
            expect(hostport(env_proxy) == (host, port),
                   f"the reported address {host}:{port} is the runner's {ENV_PROXY_ADDR} ({env_proxy})")
        else:
            ok(f"{ENV_PROXY_ADDR} not set: the env cross-check is not run (the kernel is the judge)")

        lis = lsof.listeners(port)
        check(lis is not None, f"lsof enumerated the LISTEN sockets on port {port}")
        matching = [e for e in lis if listen_matches(e, host, port)]
        check(len(matching) >= 1,
              f"the kernel shows a LISTEN socket at the reported address {host}:{port} (port {port} listeners: {[e['name'] for e in lis]})")
        pids = sorted({e["pid"] for e in matching})
        check(len(pids) == 1, f"exactly one process owns that LISTEN socket (PIDs {pids})")
        proxy_pid = pids[0]
        comm = process_name(proxy_pid)
        expect("aitm" in os.path.basename(comm) or "aitm" in matching[0]["cmd"],
               f"its owner PID {proxy_pid} is an aitm process (ps comm {comm or '?'!r}, lsof cmd {matching[0]['cmd']!r})")
        bus_owners = sorted({e["pid"] for e in (lsof.listeners(bus_port) or []) if local_port(e) == bus_port})
        expect(bus_owners == [proxy_pid],
               f"the bus we asked ({bus_host}:{bus_port}) is owned by the SAME PID {proxy_pid}: the answer comes from the "
               f"process that holds the proxy socket (bus owners {bus_owners})")

        if s0.get("intercept_armed") is True:
            ok("NOTE: intercept is ARMED on the runner's core; unattended traffic may park (a parked request shows up as a timeout below)")
        if s0.get("capturing") is False:
            if not op_token:
                skip("capture is PAUSED on the runner's core and no operator token is given to resume it: counts cannot move")
            op = BusClient.operator(core)
            r = op.call("proxy.resume")
            check(isinstance(r, dict) and r.get("capturing") is True, "NOTE: capture was paused on the runner's core; resumed as operator so counts can move")

        # ---------------------------------------------------------------
        section(f"traffic: {N_PLAIN} real GETs by a real client TO THE REPORTED ADDRESS reach a recording origin; flows counts them")
        plain = Upstream().start()
        tag = f"ps-{run}"
        flows_before = status(agent)["flows"]
        codes = []
        for i in range(N_PLAIN):
            r = via_proxy(port, "GET", f"{plain.base}/status?i={i}&t={tag}")
            codes.append(r.status)
            if UPSTREAM_MARKER not in r.text:
                expect(False, f"GET {i}: the body is the origin's own echo", r.text[:120])
        check(codes == [200] * N_PLAIN, f"all {N_PLAIN} GETs through {dial}:{port} answered 200 ({codes})")
        recorded = [q for q in plain.received if tag in q["path"]]
        check(len(recorded) == N_PLAIN,
              f"ground truth: the origin RECORDED exactly {N_PLAIN} requests carrying our tag ({len(recorded)}): the reported address is the live proxy")
        rows = wait_rows(agent, tag, N_PLAIN, done=True)
        ids = [r["id"] for r in rows]
        check(len(ids) == N_PLAIN and all(r.get("status") == 200 for r in rows),
              f"the core captured our {N_PLAIN} flows, each with the origin's 200 ({[(r.get('method'), r.get('status')) for r in rows]})")
        flows_after = status(agent)["flows"]
        expect(flows_after >= flows_before + N_PLAIN,
               f"proxy.status.flows grew by at least {N_PLAIN}: {flows_before} -> {flows_after}")
        kind, a, listed, b = stable_snapshot(agent)
        check(isinstance(listed, list), "flow.list answers a list")
        expect(set(ids) <= set(listed), f"all {N_PLAIN} of our ids are in flow.list", sorted(set(ids) - set(listed)))
        if kind == "stable":
            expect(a == len(listed), f"stable read: proxy.status.flows == len(flow.list) exactly ({a} == {len(listed)})")
        else:
            expect(a <= len(listed) <= b,
                   f"busy shared core (flows moved {a} -> {b} during the read): len(flow.list) = {len(listed)} lies within the bracket")

        # ---------------------------------------------------------------
        section(f"in flight: {K_HELD} requests HELD at the origin -- the kernel shows OUR live connections on the aitm PID while flows counts them")
        origin = HoldOrigin().start()
        htag = f"hold-{run}"
        flows_pre_hold = status(agent)["flows"]
        held = [HeldRequest(dial, port, f"{origin.base}/hold?i={i}&t={htag}", origin.authority) for i in range(K_HELD)]
        ours = sorted(h.local_port for h in held)
        check(wait_until(lambda: origin.arrived(htag) >= K_HELD, 15.0),
              f"the origin saw all {K_HELD} requests ARRIVE and is holding them (they are in flight through the proxy): {origin.arrived(htag)}/{K_HELD}")
        est = lsof.established(proxy_pid, port)
        check(est is not None, f"lsof enumerated PID {proxy_pid}'s ESTABLISHED sockets at the proxy port")
        peers = peer_ports(est, port)
        expect(set(ours) <= peers,
               f"every one of OUR {K_HELD} client connections (local ports {ours}) is ESTABLISHED on the aitm PID at :{port} "
               f"(the kernel sees {len(peers)} peer(s) there in total)", sorted(peers)[:12])
        up = [e for e in (lsof.established(proxy_pid, origin.port) or []) if foreign_port(e) == origin.port]
        expect(len(up) == K_HELD,
               f"the aitm PID holds exactly {K_HELD} upstream connections to the holding origin :{origin.port} (got {len(up)})",
               [e["name"] for e in up])
        st_held = status(agent)
        hrows = wait_rows(agent, htag, K_HELD, done=False, timeout=5.0)
        expect(len(hrows) == K_HELD and all(r.get("status") is None for r in hrows),
               f"flow.table shows our {K_HELD} flows IN FLIGHT (status null) while the kernel shows their connections",
               [(r.get("path"), r.get("status")) for r in hrows])
        expect(st_held["flows"] >= flows_pre_hold + K_HELD,
               f"proxy.status.flows already counts the in-flight flows: {flows_pre_hold} -> {st_held['flows']}")
        expect(st_held.get("listening") is True and st_held.get("address") == s0.get("address"),
               "listening/address are unchanged under load", st_held)

        origin.release()
        codes = [h.finish() for h in held]
        check(codes == [200] * K_HELD, f"after release every held request completed 200 ({codes})")
        gone = wait_until(lambda: not (set(ours) & peer_ports(lsof.established(proxy_pid, port), port)), 10.0)
        expect(gone, "our connections left ESTABLISHED on the aitm PID once finished (the kernel count went back down)")
        hrows = wait_rows(agent, htag, K_HELD, done=True)
        expect(len(hrows) == K_HELD and all(r.get("status") == 200 for r in hrows),
               "the same rows now carry the origin's 200", [(r.get("path"), r.get("status")) for r in hrows])
        st_done = status(agent)
        expect(st_done["flows"] >= flows_pre_hold + K_HELD,
               f"completed flows stay counted: flows {st_done['flows']} >= {flows_pre_hold} + {K_HELD}")

        # ---------------------------------------------------------------
        section("consistency: version matches the handshake; paused is a count; the operator sees the same")
        v = s0.get("version")
        expect(isinstance(v, str) and bool(v) and v[0].isdigit(), f"version is a real version string ({v!r})")
        expect(v == server_info.get("version"),
               f"proxy.status.version == initialize serverInfo.version of the same process ({v!r} vs {server_info.get('version')!r})")
        expect(is_type(s0.get("paused"), int) and s0["paused"] >= 0, f"paused is a non-negative count ({s0.get('paused')!r})")
        if op_token:
            op = op or BusClient.operator(core)
            so = status(op)
            expect((so.get("listening"), so.get("address"), so.get("version")) == (True, s0.get("address"), v),
                   "the OPERATOR sees the same listening / address / version (a Read command has no per-role view)", so)
        else:
            ok("no operator token from the runner: operator parity not run")
    finally:
        if origin:
            origin.release()
        for h in held:
            h.close()
        for b in (op, agent):
            if b:
                b.close()
        for srv in (origin, plain):
            if srv:
                srv.stop()

    if _failures:
        fail(f"{len(_failures)} expectation(s) failed: " + "; ".join(_failures[:6]))
    ok("PASS: proxy.status reports the address the kernel shows bound by the answering aitm PID, and counts that "
       "move with real traffic the kernel sees in flight")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except PermissionError as e:
        skip(f"this environment forbids binding/connecting loopback sockets ({e}); run from a real shell")
    except Exception as e:  # noqa: BLE001 -- surface attach/bus failures as a FAIL with context
        fail(f"{type(e).__name__}: {scrub(e)}")
