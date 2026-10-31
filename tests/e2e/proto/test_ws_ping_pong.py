#!/usr/bin/env python3
# e2e: tier=T1 surface=proto
"""WebSocket ping/pong control frames PASS THROUGH the proxy, and data frames STILL
CAPTURE — end to end, on ground truth at both boundaries, never fixtures.

A real RFC 6455 client speaks THROUGH the real aitm proxy to a real ws:// origin
that RECORDS every frame it receives (the independent observer). Control frames
are the frames a relay is most tempted to swallow, answer itself, or re-order, so
every claim is checked three ways — what the client sent/received, what the ORIGIN
recorded, what the BUS captured — and the three records must agree byte-exact:

  A. client ping -> pong with the IDENTICAL payload; the ORIGIN received the ping
     (the proxy relayed it rather than answering on the origin's behalf); data
     frames still round-trip after it; an EMPTY (0-byte) ping; a MAX (125-byte,
     non-UTF-8) ping; an unsolicited heartbeat pong draws no reply; a binary data
     frame with all 256 byte values; ping+text+ping in ONE TCP write relayed as
     three frames in order. Bus: exactly N frames, c2s capture == what the client
     sent, s2c capture == what the client received (opcode + payload), control
     frames sit in wire order among the data frames, every length matches, nothing
     is flagged injected; flow.get agrees with flow.detail.
  B. SERVER-initiated ping reaches the client byte-exact; the client's pong reaches
     the origin. Bus: s2c ping + c2s pong captured with their payloads.
  C. a ping INTERLEAVED inside a fragmented text message (RFC 6455 5.4): the ping is
     answered first (not held behind the fragments), the message arrives whole, and
     the bus captures the ping in wire position + the message as ONE complete frame.
  D. INJECTED pings via `ws.send` (operator; scope-gated): a c2s ping reaches the
     origin and its pong relays back to the client; an s2c ping reaches the client
     and the client's pong relays to the origin. Bus: injected=true on the pings,
     injected=false on the observed replies, all in wire order. The AGENT is refused
     ws.send (Sensitive) under the default policy.
  E. an OVERSIZED (126-byte) ping is a protocol violation (RFC 6455 5.5): the proxy
     fails the connection, nothing is forwarded to the origin, no pong is
     synthesised, and the bus records only the data round-trip.

Runner contract (environment; this test never boots a core of its own):
  AITM_BUS_ADDR            host:port of the loopback MCP bus
  AITM_BUS_TOKEN           the agent token (never printed)
  AITM_PROXY_ADDR          host:port of the proxy listener
  AITM_BUS_OPERATOR_TOKEN  optional: the operator token (section D needs it)
Flows are shared with parallel tests, so every lookup goes through a per-run
unique path marker — never "the last flow". Binds loopback ports for the origin:
run from a real shell, not the Claude sandbox. Exit 0 pass / 1 fail / 77 skip.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import secrets
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402

WAIT = 10.0          # seconds for any single ground-truth observation
QUIET = 0.75         # how long "no reply" must stay quiet to count as no reply
RUN = secrets.token_hex(6)  # per-run marker; flows may be shared with parallel tests
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
OPNAME = {OP_TEXT: "text", OP_BINARY: "binary", OP_CLOSE: "close", OP_PING: "ping", OP_PONG: "pong"}
C2S, S2C = "client_to_server", "server_to_client"


# ---------------------------------------------------------------------------
# RFC 6455 framing (pure stdlib; used by both the client and the origin)
# ---------------------------------------------------------------------------
def ws_encode(opcode: int, payload: bytes, mask: bool, fin: bool = True) -> bytes:
    out = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        out.append(mbit | n)
    elif n < 65536:
        out.append(mbit | 126)
        out += struct.pack("!H", n)
    else:
        out.append(mbit | 127)
        out += struct.pack("!Q", n)
    if mask:
        key = os.urandom(4)
        out += key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    else:
        out += payload
    return bytes(out)


class SockReader:
    """Buffered reads over a raw socket. NOT socket.makefile(): its SocketIO poisons
    itself after one read timeout (every later read raises "cannot read from timed
    out object"), and this test deliberately waits for silence mid-conversation. A
    timeout here propagates with the buffer intact, so the reader stays usable."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self) -> bool:
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def readline(self) -> bytes:
        while b"\n" not in self.buf:
            if not self._fill():
                out = bytes(self.buf)
                self.buf.clear()
                return out
        i = self.buf.index(b"\n") + 1
        out = bytes(self.buf[:i])
        del self.buf[:i]
        return out

    def exact(self, n: int):
        """Exactly n bytes, or None if the peer ended the stream before n arrived."""
        while len(self.buf) < n:
            if not self._fill():
                return None
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def ws_read_frame(rd: SockReader):
    """One raw frame -> (fin, opcode, payload); (None, None, None) at EOF."""
    h = rd.exact(2)
    if h is None:
        return None, None, None
    fin = bool(h[0] & 0x80)
    opcode = h[0] & 0x0F
    masked = bool(h[1] & 0x80)
    n = h[1] & 0x7F
    if n == 126:
        ext = rd.exact(2)
        if ext is None:
            return None, None, None
        n = struct.unpack("!H", ext)[0]
    elif n == 127:
        ext = rd.exact(8)
        if ext is None:
            return None, None, None
        n = struct.unpack("!Q", ext)[0]
    key = None
    if masked:
        key = rd.exact(4)
        if key is None:
            return None, None, None
    payload = rd.exact(n)
    if payload is None:
        return None, None, None
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


class MsgReader:
    """Reads complete MESSAGES: data frames are reassembled across continuation
    frames (control frames may be interleaved and are returned the moment they
    complete), so the reader is agnostic to whether a relay coalesces fragments."""

    def __init__(self, rd):
        self.rd = rd
        self.partial = None  # (opcode, bytes) of a fragmented data message in progress

    def read(self):
        """-> (opname, payload); (None, None) at EOF."""
        while True:
            fin, opcode, payload = ws_read_frame(self.rd)
            if opcode is None:
                return None, None
            if opcode == OP_CONT:
                if self.partial is None:
                    raise ValueError("continuation frame without a message in progress")
                op, data = self.partial
                data += payload
                if fin:
                    self.partial = None
                    return OPNAME[op], data
                self.partial = (op, data)
                continue
            if opcode in (OP_TEXT, OP_BINARY):
                if fin:
                    return OPNAME[opcode], payload
                if self.partial is not None:
                    raise ValueError("new data frame while a fragmented message is in progress")
                self.partial = (opcode, payload)
                continue
            if opcode not in OPNAME:
                raise ValueError(f"reserved opcode {opcode:#x}")
            return OPNAME[opcode], payload


def close_payload(code: int, reason: str) -> bytes:
    return struct.pack("!H", code) + reason.encode("utf-8")


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def close_quietly(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):
        sock.close()


# ---------------------------------------------------------------------------
# the independent observer: a real ws:// origin that RECORDS every frame it gets
# ---------------------------------------------------------------------------
class OriginConn:
    def __init__(self, path: str):
        self.path = path
        self._frames: list[tuple[str, bytes]] = []  # (opname, payload), wire order
        self.close = None          # (code, reason) of a close frame it received
        self.eof = False           # the proxy ended the upstream connection
        self.done = threading.Event()
        self.lock = threading.Lock()

    def add(self, op: str, payload: bytes) -> None:
        with self.lock:
            self._frames.append((op, payload))

    def frames(self) -> list[tuple[str, bytes]]:
        with self.lock:
            return list(self._frames)


class WsOrigin:
    """Per the RFC: answers every ping with a pong carrying the IDENTICAL payload,
    echoes text as `echo:<text>`, echoes binary unchanged, records pongs, replies
    to close. If the handshake path carries `?server_ping=<hex>` it ALSO pings the
    client right after the first data echo (the server-initiated case)."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.conns: list[OriginConn] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    def conn_for(self, marker: str):
        with self.lock:
            for c in self.conns:
                if marker in c.path:
                    return c
        return None

    def wait_conn(self, marker: str, pred, timeout: float = WAIT):
        deadline = time.time() + timeout
        while time.time() < deadline:
            c = self.conn_for(marker)
            if c is not None and pred(c):
                return c
            time.sleep(0.05)
        return self.conn_for(marker)

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, sock: socket.socket):
        sock.settimeout(60)
        rd = SockReader(sock)
        rec = None
        try:
            request_line = rd.readline().decode("latin1").strip()
            words = request_line.split(" ")
            target = words[1] if len(words) > 1 else "/"
            parts = urlsplit(target)
            path = parts.path + (("?" + parts.query) if parts.query else "")
            qs = parse_qs(parts.query)
            key = None
            while True:
                line = rd.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip().decode()
            rec = OriginConn(path)
            with self.lock:
                self.conns.append(rec)
            if key is None:
                sock.sendall(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                return
            sock.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n").encode())
            server_ping = qs.get("server_ping", [None])[0]
            server_ping = bytes.fromhex(server_ping) if server_ping is not None else None
            reader = MsgReader(rd)
            while True:
                op, payload = reader.read()
                if op is None:
                    rec.eof = True
                    return
                rec.add(op, payload)
                if op == "text":
                    sock.sendall(ws_encode(OP_TEXT, b"echo:" + payload, mask=False))
                elif op == "binary":
                    sock.sendall(ws_encode(OP_BINARY, payload, mask=False))
                elif op == "ping":
                    sock.sendall(ws_encode(OP_PONG, payload, mask=False))
                elif op == "close":
                    rec.close = parse_close(payload)
                    with contextlib.suppress(OSError):
                        sock.sendall(ws_encode(OP_CLOSE, payload[:2], mask=False))
                    return
                # "pong": record only — a pong never draws a reply.
                if op in ("text", "binary") and server_ping is not None:
                    sock.sendall(ws_encode(OP_PING, server_ping, mask=False))
                    server_ping = None
        except (OSError, ValueError):
            if rec is not None:
                rec.eof = True
        finally:
            if rec is not None:
                rec.done.set()
            close_quietly(sock)

    def stop(self):
        with contextlib.suppress(OSError):
            self.srv.close()


def parse_close(payload: bytes):
    if len(payload) < 2:
        return None, ""
    return struct.unpack("!H", payload[:2])[0], payload[2:].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# a real WebSocket client speaking THROUGH the aitm proxy (absolute-form upgrade)
# ---------------------------------------------------------------------------
class ProxiedWs:
    def __init__(self, proxy_host: str, proxy_port: int, origin_authority: str, path: str):
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=WAIT)
        self.rd = SockReader(self.sock)
        self.reader = MsgReader(self.rd)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET http://{origin_authority}{path} HTTP/1.1\r\n"
            f"Host: {origin_authority}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        status = self.rd.readline().decode("latin1").strip()
        headers = {}
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, _, v = line.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        if " 101 " not in f" {status} ":
            raise RuntimeError(f"ws upgrade through the proxy failed: {status!r}")
        if headers.get("sec-websocket-accept") != ws_accept(key):
            raise RuntimeError(f"proxy returned a wrong Sec-WebSocket-Accept: {headers!r}")

    def send(self, opcode: int, payload: bytes, fin: bool = True):
        self.sock.sendall(ws_encode(opcode, payload, mask=True, fin=fin))

    def send_raw(self, data: bytes):
        """Several frames in ONE TCP write (the relay must split and order them)."""
        self.sock.sendall(data)

    def recv(self, timeout: float = WAIT):
        """(opname, payload); (None, None) at EOF/reset; ('timeout', None) on no data.
        A timeout leaves the SockReader buffer intact: the connection stays usable."""
        self.sock.settimeout(timeout)
        try:
            return self.reader.read()
        except (socket.timeout, TimeoutError):
            return "timeout", None
        except OSError:
            return None, None

    def wait_eof(self, timeout: float = WAIT):
        """Read until the proxy ends the connection. Returns (reached_eof, frames)."""
        frames = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            op, payload = self.recv(max(0.1, deadline - time.time()))
            if op is None:
                return True, frames
            if op == "timeout":
                return False, frames
            frames.append((op, payload))
        return False, frames

    def close(self):
        close_quietly(self.sock)


# ---------------------------------------------------------------------------
# bus ground truth (polling: capture lands a beat after the client sees bytes)
# ---------------------------------------------------------------------------
def flow_ids(result) -> list:
    if isinstance(result, dict):
        for k in ("flows", "ids", "items"):
            if k in result:
                result = result[k]
                break
    if isinstance(result, list):
        return [i.get("id", i) if isinstance(i, dict) else i for i in result]
    return []


class FlowFinder:
    """Find THIS test's flows by marker among flows possibly shared with others.
    `kind`, `path` and `handshake` never change once a flow exists, so each id's
    summary is cached; only an HTTP flow still awaiting its 101 is re-fetched."""

    def __init__(self, bus: BusClient):
        self.bus = bus
        self.cache: dict = {}

    def _summary(self, fid):
        s = self.cache.get(fid)
        if s is None or (s.get("kind") == "http" and s.get("status") is None):
            s = self.bus.call("flow.get", {"id": fid})
            if not isinstance(s, dict):
                return None
            self.cache[fid] = s
        return s

    def _newest_first(self):
        for fid in reversed(flow_ids(self.bus.call("flow.list"))):
            s = self._summary(fid)
            if s is not None:
                yield fid, s

    def handshake(self, marker: str, timeout: float = WAIT):
        """The HTTP upgrade flow whose path carries `marker` and whose status is 101."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for fid, s in self._newest_first():
                if (s.get("kind") == "http" and marker in (s.get("path") or "")
                        and s.get("status") == 101):
                    return fid, s
            time.sleep(0.1)
        return None, None

    def websocket(self, handshake_id: str, timeout: float = WAIT):
        """The websocket flow spawned from `handshake_id`."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for fid, s in self._newest_first():
                if s.get("kind") == "websocket" and s.get("handshake") == handshake_id:
                    return fid
            time.sleep(0.1)
        return None

    def ws_flow(self, marker: str):
        """handshake-then-websocket lookup with the two bus checks every section makes."""
        hs, hs_sum = self.handshake(marker)
        check(hs is not None, f"bus: handshake flow captured with status 101 for {marker}")
        ws_id = self.websocket(hs)
        check(ws_id is not None, "bus: websocket flow spawned from that handshake")
        return hs_sum, ws_id


def detail(bus: BusClient, fid: str) -> dict:
    d = bus.call("flow.detail", {"id": fid, "body": "inline"})
    return d if isinstance(d, dict) else {}


def wait_messages(bus: BusClient, fid: str, pred, timeout: float = WAIT) -> list:
    deadline = time.time() + timeout
    msgs: list = []
    while time.time() < deadline:
        msgs = detail(bus, fid).get("messages") or []
        if pred(msgs):
            return msgs
        time.sleep(0.1)
    return msgs


def msg_data(m: dict) -> bytes:
    data = m.get("data")
    return base64.b64decode(data) if isinstance(data, str) and data else b""


def wire(msgs: list) -> list:
    return [(m.get("dir"), m.get("opcode")) for m in msgs]


def by_dir(msgs: list, d: str) -> list:
    """[(opcode, payload)] of the captured frames travelling in direction `d`."""
    return [(m.get("opcode"), msg_data(m)) for m in msgs if m.get("dir") == d]


def index_of(msgs: list, d: str, op: str, payload: bytes) -> int:
    for i, m in enumerate(msgs):
        if m.get("dir") == d and m.get("opcode") == op and msg_data(m) == payload:
            return i
    return -1


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


def short(frames) -> str:
    """A readable rendering of [(op, payload)] for failure messages."""
    return repr([(op, p if len(p) <= 24 else p[:12] + b"..." + p[-6:]) for op, p in frames])


# ---------------------------------------------------------------------------
# the core under test: the one the runner provides via env (never our own)
# ---------------------------------------------------------------------------
def _hostport(addr: str) -> tuple[str, int]:
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"malformed host:port {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


class Rig:
    REQUIRED = ("AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_PROXY_ADDR")

    def __init__(self):
        missing = [k for k in self.REQUIRED if not os.environ.get(k)]
        if missing:
            skip(f"no runner-provided core: {' '.join(missing)} unset (see tests/e2e/README.md)")
        self.bus_addr = _hostport(os.environ["AITM_BUS_ADDR"])
        self.proxy_host, self.proxy_port = _hostport(os.environ["AITM_PROXY_ADDR"])
        self._agent_token = os.environ["AITM_BUS_TOKEN"]
        self._operator_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None

    @property
    def has_operator(self) -> bool:
        return self._operator_token is not None

    def agent(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._agent_token, client_name="aitm-e2e-ws-pingpong-agent").connect()

    def operator(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._operator_token,
                         client_name="aitm-e2e-ws-pingpong-operator").connect()


# ---------------------------------------------------------------------------
def main() -> int:
    rig = Rig()  # skips (77) before any socket is opened when the runner gave us no core
    origin = WsOrigin()
    agent = None
    operator = None
    scoped = False
    clients: list[ProxiedWs] = []
    try:
        section("arrange: real recording ws:// origin + the runner's real core")
        ok(f"origin {origin.authority}; proxy {rig.proxy_host}:{rig.proxy_port}; "
           f"bus {rig.bus_addr[0]}:{rig.bus_addr[1]} (runner-provided)")
        agent = rig.agent()
        ok("agent bus connection initialized")
        if rig.has_operator:
            operator = rig.operator()
            ok("operator bus connection initialized")
            # Active egress (ws.send) is scope-gated; passive relay/capture is not.
            operator.call("scope.add", {"host": origin.authority})
            scoped = True
            ok("origin added to scope for the injected-ping checks")
        else:
            note("no AITM_BUS_OPERATOR_TOKEN: section D (ws.send injected pings) is skipped")
        finder = FlowFinder(agent)

        def open_ws(path: str) -> ProxiedWs:
            ws = ProxiedWs(rig.proxy_host, rig.proxy_port, origin.authority, path)
            clients.append(ws)
            return ws

        def finish(ws: ProxiedWs, what: str) -> None:
            """Close politely so the proxy tears the relay down and nothing lingers."""
            ws.send(OP_CLOSE, close_payload(1000, "done"))
            eof, _ = ws.wait_eof()
            check(eof, f"{what}: proxy tore the connection down after our close")

        # ------------------------------------------------------------------ A
        section("A. client pings pass through (origin answers, proxy relays) and data still captures")
        marker_a = f"/ws-pingpong-e2e/{RUN}/a"
        ws_a = open_ws(marker_a)
        ok("upgrade (101) proxied; Sec-WebSocket-Accept matches our key")
        sent: list[tuple[str, bytes]] = []  # every c2s frame, in the order we sent it
        got: list[tuple[str, bytes]] = []   # every s2c frame, in the order we received it

        def xchg(ws, opcode: int, payload: bytes, want: tuple, what: str) -> None:
            ws.send(opcode, payload)
            sent.append((OPNAME[opcode], payload))
            r = ws.recv()
            if r[0] not in (None, "timeout"):
                got.append(r)
            check(r == want, f"{what} (got {short([r]) if r[0] not in (None, 'timeout') else r!r})")

        t1 = f"hello-{RUN}".encode()
        xchg(ws_a, OP_TEXT, t1, ("text", b"echo:" + t1), "data relay is live: text round-trip through the proxy")

        p1 = f"ping-{RUN}".encode()
        xchg(ws_a, OP_PING, p1, ("pong", p1),
             "client PING -> PONG with the IDENTICAL payload (RFC 6455 5.5.3)")
        conn_a = origin.wait_conn(marker_a, lambda c: ("ping", p1) in c.frames())
        n_ping = conn_a.frames().count(("ping", p1)) if conn_a else 0
        check(n_ping == 1,
              f"ORIGIN received that ping exactly once — the proxy RELAYED it rather than answering "
              f"on the origin's behalf (origin saw it {n_ping}x)")

        t2 = f"after-{RUN}".encode()
        xchg(ws_a, OP_TEXT, t2, ("text", b"echo:" + t2), "data frames still flow after the control exchange")

        xchg(ws_a, OP_PING, b"", ("pong", b""), "EMPTY ping (0-byte payload) -> empty pong")

        p125 = bytes((i * 7 + 3) & 0xFF for i in range(125))  # max control payload, non-UTF-8
        xchg(ws_a, OP_PING, p125, ("pong", p125), "MAX-size ping (125 bytes, non-UTF-8) -> identical 125-byte pong")

        hb = f"hb-{RUN}".encode()
        ws_a.send(OP_PONG, hb)
        sent.append(("pong", hb))
        r = ws_a.recv(QUIET)
        check(r == ("timeout", None),
              f"unsolicited client PONG (RFC 5.5.3 heartbeat) draws NO reply within {QUIET}s (got {r!r})")
        conn_a = origin.wait_conn(marker_a, lambda c: ("pong", hb) in c.frames())
        check(conn_a is not None and ("pong", hb) in conn_a.frames(),
              "ORIGIN received the unsolicited pong (relayed, not swallowed)")

        binary = bytes(range(256))
        xchg(ws_a, OP_BINARY, binary, ("binary", binary),
             "BINARY data frame with all 256 byte values round-trips byte-exact")

        b1, bt, b2 = f"burst1-{RUN}".encode(), f"burst-text-{RUN}".encode(), f"burst2-{RUN}".encode()
        ws_a.send_raw(ws_encode(OP_PING, b1, True) + ws_encode(OP_TEXT, bt, True) + ws_encode(OP_PING, b2, True))
        sent += [("ping", b1), ("text", bt), ("ping", b2)]
        replies = [ws_a.recv() for _ in range(3)]
        got += [r for r in replies if r[0] not in (None, "timeout")]
        check(replies == [("pong", b1), ("text", b"echo:" + bt), ("pong", b2)],
              f"ping+text+ping in ONE TCP write is relayed as three frames IN ORDER (got {short(got[-3:])})")

        conn_a = origin.wait_conn(marker_a, lambda c: len(c.frames()) >= len(sent))
        origin_a = conn_a.frames() if conn_a else []
        check(origin_a == sent,
              f"ORIGIN's record == exactly what the client sent — {len(sent)} frames, opcode+payload, wire "
              f"order, no proxy-originated control frames (origin saw {short(origin_a)})")

        hs_sum, ws_id_a = finder.ws_flow(marker_a)
        check((hs_sum or {}).get("authority") == origin.authority,
              f"bus: handshake authority is the origin (was {(hs_sum or {}).get('authority')!r})")
        n_a = len(sent) + len(got)
        msgs_a = wait_messages(agent, ws_id_a, lambda ms: len(ms) >= n_a)
        check(len(msgs_a) == n_a,
              f"bus: exactly {n_a} frames captured (sent {len(sent)} + received {len(got)}); was {len(msgs_a)}")
        check(by_dir(msgs_a, C2S) == sent,
              "bus: c2s capture == what the client SENT (opcode+payload byte-exact, wire order) — "
              "control AND data frames")
        check(by_dir(msgs_a, S2C) == got,
              "bus: s2c capture == what the client RECEIVED (opcode+payload byte-exact, wire order)")
        pings = [m for m in msgs_a if m.get("opcode") == "ping"]
        pongs = [m for m in msgs_a if m.get("opcode") == "pong"]
        check(len(pings) == 5 and all(m.get("dir") == C2S for m in pings),
              f"bus: 5 ping frames captured, all client_to_server (was {len(pings)})")
        check(len(pongs) == 6 and sum(1 for m in pongs if m.get("dir") == S2C) == 5
              and sum(1 for m in pongs if m.get("dir") == C2S) == 1,
              f"bus: 6 pong frames captured — 5 origin replies s2c + the 1 unsolicited c2s (was {len(pongs)})")
        check(all(m.get("length") == len(msg_data(m)) for m in msgs_a),
              "bus: every frame's `length` equals its captured payload length")
        empty = [m for m in pings if msg_data(m) == b""]
        check(len(empty) == 1 and empty[0].get("length") == 0,
              "bus: the empty ping is captured with length 0 and empty data")
        check(any(msg_data(m) == p125 and m.get("length") == 125 for m in pings),
              "bus: the 125-byte non-UTF-8 ping is captured byte-exact with length 125")
        check(all(m.get("injected") is False for m in msgs_a),
              "bus: nothing on this flow is flagged injected (all observed on the wire)")
        seq = [(C2S, "text"), (S2C, "text"), (C2S, "ping"), (S2C, "pong"), (C2S, "text"), (S2C, "text"),
               (C2S, "ping"), (S2C, "pong"), (C2S, "ping"), (S2C, "pong"), (C2S, "pong"),
               (C2S, "binary"), (S2C, "binary")]
        check(wire(msgs_a)[:len(seq)] == seq,
              f"bus: wire order of the sequential exchange is exact — control frames sit in wire order "
              f"among the data frames (was {wire(msgs_a)[:len(seq)]!r})")
        for req, rep in ((("ping", b1), ("pong", b1)), (("text", bt), ("text", b"echo:" + bt)),
                         (("ping", b2), ("pong", b2))):
            i, j = index_of(msgs_a, C2S, *req), index_of(msgs_a, S2C, *rep)
            check(0 <= i < j, f"bus: burst {req[0]} {req[1]!r} (idx {i}) precedes its reply (idx {j})")
        summ = agent.call("flow.get", {"id": ws_id_a})
        n_get = summ.get("messages") if isinstance(summ, dict) else summ
        check(n_get == n_a, f"bus: flow.get reports {n_a} messages, agreeing with flow.detail (was {n_get!r})")
        finish(ws_a, "A")

        # ------------------------------------------------------------------ B
        section("B. SERVER-initiated ping reaches the client; the client's pong reaches the origin")
        sp = f"srv-ping-{RUN}".encode()
        marker_b = f"/ws-pingpong-e2e/{RUN}/b"
        ws_b = open_ws(f"{marker_b}?server_ping={sp.hex()}")
        tb = f"hi-b-{RUN}".encode()
        ws_b.send(OP_TEXT, tb)
        r1, r2 = ws_b.recv(), ws_b.recv()
        check(r1 == ("text", b"echo:" + tb), f"echo arrives first (got {r1!r})")
        check(r2 == ("ping", sp), f"CLIENT received the ORIGIN's ping byte-exact — s2c control frame passed through (got {r2!r})")
        ws_b.send(OP_PONG, sp)
        conn_b = origin.wait_conn(marker_b, lambda c: ("pong", sp) in c.frames())
        origin_b = conn_b.frames() if conn_b else []
        check(origin_b == [("text", tb), ("pong", sp)],
              f"ORIGIN received the client's pong with the identical payload — its ping was answered end "
              f"to end (origin saw {short(origin_b)})")
        _, ws_id_b = finder.ws_flow(marker_b)
        msgs_b = wait_messages(agent, ws_id_b, lambda ms: len(ms) >= 4)
        check(len(msgs_b) == 4, f"bus: exactly 4 frames captured (was {len(msgs_b)})")
        check(wire(msgs_b) == [(C2S, "text"), (S2C, "text"), (S2C, "ping"), (C2S, "pong")],
              f"bus: wire order text c2s, echo s2c, PING s2c, PONG c2s (was {wire(msgs_b)!r})")
        check(by_dir(msgs_b, S2C) == [("text", b"echo:" + tb), ("ping", sp)]
              and by_dir(msgs_b, C2S) == [("text", tb), ("pong", sp)],
              "bus: the server ping and the client pong are captured with their exact payloads")
        check(all(m.get("injected") is False for m in msgs_b), "bus: nothing flagged injected")
        finish(ws_b, "B")

        # ------------------------------------------------------------------ C
        section("C. a ping INTERLEAVED inside a fragmented text message (RFC 6455 5.4)")
        marker_c = f"/ws-pingpong-e2e/{RUN}/c"
        ws_c = open_ws(marker_c)
        f1, f2, mid = f"frag-{RUN}-part1|".encode(), b"part2", f"mid-{RUN}".encode()
        ws_c.send_raw(ws_encode(OP_TEXT, f1, True, fin=False)
                      + ws_encode(OP_PING, mid, True)
                      + ws_encode(OP_CONT, f2, True, fin=True))
        r1, r2 = ws_c.recv(), ws_c.recv()
        check(r1 == ("pong", mid),
              f"the interleaved ping is answered FIRST — not held behind the fragmented message (got {r1!r})")
        check(r2 == ("text", b"echo:" + f1 + f2),
              f"the fragmented text arrives at the origin whole and echoes complete (got {r2!r})")
        conn_c = origin.wait_conn(marker_c, lambda c: len(c.frames()) >= 2)
        origin_c = conn_c.frames() if conn_c else []
        check(origin_c == [("ping", mid), ("text", f1 + f2)],
              f"ORIGIN saw the ping BEFORE the complete message, and the message as one whole text "
              f"(origin saw {short(origin_c)})")
        _, ws_id_c = finder.ws_flow(marker_c)
        msgs_c = wait_messages(agent, ws_id_c, lambda ms: len(ms) >= 4)
        check(len(msgs_c) == 4, f"bus: exactly 4 frames captured — no partial fragments recorded (was {len(msgs_c)})")
        check(by_dir(msgs_c, C2S) == [("ping", mid), ("text", f1 + f2)],
              f"bus: c2s = ping in wire position, then the fragmented message as ONE complete text frame "
              f"(was {short(by_dir(msgs_c, C2S))})")
        check(by_dir(msgs_c, S2C) == [("pong", mid), ("text", b"echo:" + f1 + f2)],
              f"bus: s2c = pong, then the complete echo (was {short(by_dir(msgs_c, S2C))})")
        check(index_of(msgs_c, C2S, "ping", mid) < index_of(msgs_c, S2C, "pong", mid)
              and index_of(msgs_c, C2S, "text", f1 + f2) < index_of(msgs_c, S2C, "text", b"echo:" + f1 + f2),
              f"bus: each frame precedes its reply in wire order (was {wire(msgs_c)!r})")
        finish(ws_c, "C")

        # ------------------------------------------------------------------ D
        section("D. INJECTED pings via ws.send (operator, scope-gated) cross in both directions")
        if operator is None:
            note("skipped: ws.send needs the operator connection (no AITM_BUS_OPERATOR_TOKEN)")
        else:
            marker_d = f"/ws-pingpong-e2e/{RUN}/d"
            ws_d = open_ws(marker_d)
            td = f"hi-d-{RUN}".encode()
            ws_d.send(OP_TEXT, td)
            r = ws_d.recv()
            check(r == ("text", b"echo:" + td), "relay is live")
            _, ws_id_d = finder.ws_flow(marker_d)
            wait_messages(agent, ws_id_d, lambda ms: len(ms) >= 2)

            inj1 = f"inj-c2s-{RUN}".encode()
            policy = agent.call("agent.status")
            policy = policy.get("policy") if isinstance(policy, dict) else None
            # ws.send inherits the Command trait's fail-closed `Sensitive` tier: refused
            # for the agent under auto/readonly/paused, and under `all` too (it has no
            # per-command agent gate). Only `ask` PARKS the call for approval, which
            # would block this client — so that one policy is not asserted.
            if policy in ("auto", "readonly", "paused", "all"):
                status, msg = agent.try_call("ws.send", {"id": ws_id_d, "dir": "c2s", "opcode": "ping",
                                                         "data": b64(inj1)})
                check(status == "error",
                      f"policy asymmetry: the AGENT is refused ws.send under policy {policy!r} ({msg[:120]!r})")
                conn_d = origin.conn_for(marker_d)
                check(conn_d is not None and ("ping", inj1) not in conn_d.frames(),
                      "ORIGIN received nothing from the refused agent call")
            else:
                note(f"agent policy is {policy!r}: agent-refusal asymmetry not asserted")

            res = operator.call("ws.send", {"id": ws_id_d, "dir": "c2s", "opcode": "ping", "data": b64(inj1)})
            check(isinstance(res, dict) and res.get("index") == 2,
                  f"operator ws.send c2s PING accepted; injected frame index is 2 (was {res!r})")
            r = ws_d.recv()
            check(r == ("pong", inj1),
                  f"CLIENT received the ORIGIN's pong to the INJECTED ping — it reached the origin and the "
                  f"reply relayed back (got {r!r})")
            conn_d = origin.wait_conn(marker_d, lambda c: ("ping", inj1) in c.frames())
            n_inj = conn_d.frames().count(("ping", inj1)) if conn_d else 0
            check(n_inj == 1, f"ORIGIN received the injected ping exactly once (saw it {n_inj}x)")

            inj2 = f"inj-s2c-{RUN}".encode()
            res2 = operator.call("ws.send", {"id": ws_id_d, "dir": "s2c", "opcode": "ping", "data": b64(inj2)})
            check(isinstance(res2, dict) and res2.get("index") == 4,
                  f"operator ws.send s2c PING accepted; injected frame index is 4 (was {res2!r})")
            r = ws_d.recv()
            check(r == ("ping", inj2), f"CLIENT received the INJECTED s2c ping byte-exact (got {r!r})")
            ws_d.send(OP_PONG, inj2)
            conn_d = origin.wait_conn(marker_d, lambda c: ("pong", inj2) in c.frames())
            check(conn_d is not None and ("pong", inj2) in conn_d.frames(),
                  "ORIGIN received the client's pong reply to the injected ping (relayed c2s)")

            msgs_d = wait_messages(agent, ws_id_d, lambda ms: len(ms) >= 6)
            check(len(msgs_d) == 6, f"bus: exactly 6 frames captured (was {len(msgs_d)})")
            shape = [(m.get("dir"), m.get("opcode"), msg_data(m), m.get("injected")) for m in msgs_d]
            want = [(C2S, "text", td, False), (S2C, "text", b"echo:" + td, False),
                    (C2S, "ping", inj1, True), (S2C, "pong", inj1, False),
                    (S2C, "ping", inj2, True), (C2S, "pong", inj2, False)]
            check(shape == want,
                  f"bus: injected pings flagged injected=true, their observed replies injected=false, all "
                  f"payloads exact, in wire order (was {shape!r})")
            finish(ws_d, "D")

        # ------------------------------------------------------------------ E
        section("E. an OVERSIZED (126-byte) ping is a protocol violation: fail the connection, forward nothing")
        marker_e = f"/ws-pingpong-e2e/{RUN}/e"
        ws_e = open_ws(marker_e)
        te = f"hi-e-{RUN}".encode()
        ws_e.send(OP_TEXT, te)
        r = ws_e.recv()
        check(r == ("text", b"echo:" + te), "relay is live")
        conn_e = origin.wait_conn(marker_e, lambda c: len(c.frames()) >= 1)
        ws_e.send(OP_PING, bytes(126))
        eof, extra = ws_e.wait_eof()
        check(eof, f"proxy FAILED the connection on a 126-byte ping (RFC 6455 5.5: control payload <= 125) "
                   f"— client reached EOF/reset (extra frames={short(extra)})")
        check(not any(op == "pong" for op, _ in extra), "no pong was synthesised for the malformed ping")
        conn_e = origin.wait_conn(marker_e, lambda c: c.eof or c.close is not None)
        origin_e = conn_e.frames() if conn_e else None
        check(origin_e == [("text", te)],
              f"ORIGIN never received the oversized ping — nothing malformed was forwarded (origin saw "
              f"{short(origin_e or [])})")
        check(conn_e is not None and (conn_e.eof or conn_e.close is not None),
              "ORIGIN side was torn down too (no half-open relay left behind)")
        _, ws_id_e = finder.ws_flow(marker_e)
        msgs_e = wait_messages(agent, ws_id_e, lambda ms: len(ms) >= 2)
        check(wire(msgs_e) == [(C2S, "text"), (S2C, "text")],
              f"bus: only the data round-trip is captured; no malformed control frame recorded "
              f"(was {wire(msgs_e)!r})")
    finally:
        for c in clients:
            c.close()
        with contextlib.suppress(Exception):
            if scoped and operator is not None:
                operator.call("scope.remove", {"host": origin.authority})
        for b in (agent, operator):
            if b is not None:
                b.close()
        origin.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
