#!/usr/bin/env python3
# e2e: tier=T1 surface=ws
"""Closing a WebSocket is captured with the CORRECT close code (and reason) — end to
end, on ground truth at both boundaries, never fixtures.

A real RFC 6455 client speaks THROUGH the real aitm proxy to a real ws:// origin
that RECORDS what it receives (the independent observer). A close frame carries a
2-byte big-endian status code plus a UTF-8 reason; a relay that synthesised 1000,
dropped the reason, truncated the payload or lost the frame would fail here. Every
claim is checked at both ends — what the peer really received, what the bus
captured — and the two records must agree byte-exact:

  A. CLIENT-initiated close 4001 + reason: the ORIGIN receives (4001, reason); the
     client reaches EOF (the proxy tears the tunnel down); bus: exactly one close
     frame, client_to_server, injected=false, code 4001, reason, length ==
     2+len(reason), LAST in wire order after the text round-trip; flow.get says 3
     messages; the live `notifications/aitm/flow` stream ends the flow with a
     `killed` push reporting 3 messages; `ws.send` onto the closed flow is REFUSED
     as closed — the core knows the conversation ended.
  B. SERVER-initiated close 1001 + reason: the CLIENT receives (1001, reason)
     byte-exact, then EOF; the origin side is torn down too; bus: one close,
     server_to_client, code 1001, reason.
  C. EMPTY close (no status code; RFC 6455 5.5.1 allows a 0-byte payload): the
     origin receives an empty close; bus: captured with length 0 and NO code —
     nothing synthesised (no 1000, no 1005).
  D. MAX-length close: a 123-byte reason (125-byte payload, the control-frame
     limit) with code 4999 reaches the origin and is captured whole.
  E. INJECTED close via `ws.send` (operator, scope-gated) 4002 + reason: ws.send
     returns index 2; the client receives (4002, reason); the client's RFC close
     reply (4002, "ack") reaches the origin; bus: TWO close frames — s2c
     injected=true (4002, reason) then c2s injected=false (4002, "ack"). Policy
     asymmetry: the AGENT is refused ws.send (Sensitive) and nothing reaches the
     client.

Runner contract (environment; this test never boots a core of its own):
  AITM_BUS_ADDR            host:port of the loopback MCP bus
  AITM_BUS_TOKEN           the agent token (never printed)
  AITM_PROXY_ADDR          host:port of the proxy listener
  AITM_BUS_OPERATOR_TOKEN  optional: the operator token (A's post-close refusal
                           and section E need it; without it they are noted)
Flows are shared with parallel tests, so every lookup goes through a per-run
unique path marker — never "the last flow". Binds a loopback port for the origin:
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
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402

WAIT = 10.0          # seconds for any single ground-truth observation
QUIET = 0.75         # how long "nothing arrives" must stay quiet to count
RUN = secrets.token_hex(6)  # per-run marker; flows may be shared with parallel tests
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
FLOW_NOTE = "notifications/aitm/flow"

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

    def __init__(self, rd: SockReader):
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


def parse_close(payload: bytes):
    """(code, reason) of a close payload; (None, '') for an empty payload."""
    if len(payload) < 2:
        return None, ""
    return struct.unpack("!H", payload[:2])[0], payload[2:].decode("utf-8", "replace")


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def close_quietly(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):
        sock.close()


# ---------------------------------------------------------------------------
# the independent observer: a real ws:// origin that RECORDS what it receives
# ---------------------------------------------------------------------------
class OriginConn:
    def __init__(self, path: str):
        self.path = path
        self.texts: list[bytes] = []
        self.close_raw = None      # the raw payload of the close frame it received
        self.close = None          # (code, reason) parsed from that payload
        self.eof = False           # the proxy ended the upstream connection
        self.done = threading.Event()


class WsOrigin:
    """Echoes `echo:<text>` for every text frame and answers pings. If the handshake
    path carries `?server_close=<code>&reason=<r>` it ALSO sends close(code, reason)
    right after the first echo (the server-initiated case) and keeps reading, so
    `eof` records whether the proxy tore the upstream side down. A client close is
    answered with the same code (RFC 6455 5.5.1) and recorded raw."""

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
            server_close = qs.get("server_close", [None])[0]
            reason = qs.get("reason", [""])[0]
            reader = MsgReader(rd)
            while True:
                op, payload = reader.read()
                if op is None:
                    rec.eof = True
                    return
                if op == "text":
                    rec.texts.append(payload)
                    sock.sendall(ws_encode(OP_TEXT, b"echo:" + payload, mask=False))
                    if server_close is not None:
                        sock.sendall(ws_encode(OP_CLOSE, close_payload(int(server_close), reason),
                                               mask=False))
                        server_close = None
                elif op == "ping":
                    sock.sendall(ws_encode(OP_PONG, payload, mask=False))
                elif op == "close":
                    rec.close_raw = payload
                    rec.close = parse_close(payload)
                    with contextlib.suppress(OSError):
                        sock.sendall(ws_encode(OP_CLOSE, payload[:2], mask=False))
                    return
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

    def send(self, opcode: int, payload: bytes):
        self.sock.sendall(ws_encode(opcode, payload, mask=True))

    def recv(self, timeout: float = WAIT):
        """(opname, payload); (None, None) at EOF/reset; ('timeout', None) on no data.
        A timeout leaves the SockReader buffer intact: the connection stays usable."""
        self.sock.settimeout(timeout)
        try:
            return self.reader.read()
        except TimeoutError:
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
class FlowFinder:
    """Find THIS test's flows by marker among flows possibly shared with others.

    One `flow.table` call lists every flow with its request line; the upgrade flow
    is the `http` row carrying the marker with status 101. A `websocket` row has
    no request line, so its `handshake` link comes from `flow.get` — fetched once
    per id and cached (it never changes)."""

    def __init__(self, bus: BusClient):
        self.bus = bus
        self.ws_handshake: dict = {}

    def rows(self) -> list:
        r = self.bus.call("flow.table")
        rows = r.get("flows") if isinstance(r, dict) else None
        return [x for x in (rows or []) if isinstance(x, dict)]

    def handshake(self, marker: str, timeout: float = WAIT):
        """The HTTP upgrade flow whose path carries `marker` and whose status is 101."""
        deadline = time.time() + timeout
        while True:
            for row in reversed(self.rows()):
                if (row.get("kind") == "http" and marker in (row.get("path") or "")
                        and row.get("status") == 101):
                    return row.get("id"), row
            if time.time() > deadline:
                return None, None
            time.sleep(0.1)

    def websocket(self, handshake_id, timeout: float = WAIT):
        """The websocket flow spawned from `handshake_id`."""
        if handshake_id is None:
            return None
        deadline = time.time() + timeout
        while True:
            for row in reversed(self.rows()):
                if row.get("kind") != "websocket":
                    continue
                fid = row.get("id")
                if fid not in self.ws_handshake:
                    try:
                        s = self.bus.call("flow.get", {"id": fid})
                    except ToolError:
                        s = None
                    self.ws_handshake[fid] = s.get("handshake") if isinstance(s, dict) else None
                if self.ws_handshake[fid] == handshake_id:
                    return fid
            if time.time() > deadline:
                return None
            time.sleep(0.1)

    def ws_flow(self, marker: str):
        """handshake-then-websocket lookup with the two bus checks every section makes."""
        hs, hs_row = self.handshake(marker)
        check(hs is not None, f"bus: handshake flow captured with status 101 for {marker}")
        ws_id = self.websocket(hs)
        check(ws_id is not None, "bus: websocket flow spawned from that handshake")
        return hs_row or {}, ws_id


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


def has_close(msgs: list) -> bool:
    return any(m.get("opcode") == "close" for m in msgs)


def msg_data(m: dict) -> bytes:
    data = m.get("data")
    return base64.b64decode(data) if isinstance(data, str) and data else b""


def closes(msgs: list) -> list:
    """[(dir, code, reason, injected, length)] for every captured close frame."""
    out = []
    for m in msgs:
        if m.get("opcode") == "close":
            code, reason = parse_close(msg_data(m))
            out.append((m.get("dir"), code, reason, bool(m.get("injected")), m.get("length")))
    return out


def wire(msgs: list) -> list:
    return [(m.get("dir"), m.get("opcode")) for m in msgs]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def wait_flow_push(bus: BusClient, fid: str, pred, timeout: float = WAIT):
    """The next `notifications/aitm/flow` push about `fid` satisfying `pred(params)`.
    Pushes about other flows (parallel tests share the core) are consumed and
    ignored; already-stashed notifications are checked first."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = bus.wait_notification(FLOW_NOTE, timeout=max(0.1, deadline - time.time()))
        if m is None:
            return None
        bus.notifications = [n for n in bus.notifications if n is not m]
        p = m.get("params") or {}
        if p.get("id") == fid and pred(p):
            return p
    return None


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


# ---------------------------------------------------------------------------
# the core under test: the one the runner provides via env (never our own)
# ---------------------------------------------------------------------------
def _hostport(addr: str) -> tuple:
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
        return BusClient(host, port, self._agent_token, client_name="aitm-e2e-ws-close-agent").connect()

    def operator(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._operator_token,
                         client_name="aitm-e2e-ws-close-operator").connect()


# ---------------------------------------------------------------------------
def main() -> int:
    rig = Rig()  # skips (77) before any socket is opened when the runner gave us no core
    origin = WsOrigin()
    agent = None
    operator = None
    bus = None
    scoped = False
    sub_id = None
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
            ok("origin added to scope for the active (ws.send) checks")
        else:
            note("no AITM_BUS_OPERATOR_TOKEN: the ws.send checks (post-close refusal, injected close) are noted, not asserted")

        # Reads go through the agent (the canonical MCP role). A core whose agent
        # policy refuses even reads falls back to the operator for reads, else SKIPs.
        status, st = agent.try_call("agent.status")
        policy = st.get("policy") if status == "ok" and isinstance(st, dict) else None
        bus = agent
        if status == "error":
            if operator is None:
                skip(f"the agent connection cannot read ({st[:120]}) and no operator token is set")
            bus = operator
            note(f"agent reads refused ({st[:100]!r}); reading flows via the operator instead")
        ok(f"agent policy is {policy!r}")
        sub = bus.call("flow.subscribe", {})
        sub_id = sub.get("sub_id") if isinstance(sub, dict) else None
        check(sub_id is not None, f"subscribed to live flow notifications (sub_id={sub_id!r})")
        finder = FlowFinder(bus)

        def open_ws(path: str) -> ProxiedWs:
            ws = ProxiedWs(rig.proxy_host, rig.proxy_port, origin.authority, path)
            clients.append(ws)
            return ws

        def client_close(tag: str, payload: bytes, want: tuple, what: str) -> str:
            """Open a conversation, round-trip a text frame, send `payload` as the
            CLIENT's close, and assert the three records agree. Returns the ws flow id."""
            marker = f"/ws-close-e2e/{RUN}/{tag}"
            ws = open_ws(marker)
            text = f"ping-{tag}-{RUN}".encode()
            ws.send(OP_TEXT, text)
            r = ws.recv()
            check(r == ("text", b"echo:" + text),
                  f"{tag}: relay is live — text round-trip through the proxy (got {r!r})")
            ws.send(OP_CLOSE, payload)
            conn = origin.wait_conn(marker, lambda c: c.close_raw is not None or c.eof)
            got_raw = getattr(conn, "close_raw", None)
            check(got_raw == payload,
                  f"{tag}: ORIGIN received the close payload byte-exact — {what} "
                  f"(origin saw {got_raw!r}, eof={getattr(conn, 'eof', None)})")
            check(conn is not None and conn.close == want,
                  f"{tag}: origin parsed it as (code, reason) == {want!r} (was {getattr(conn, 'close', None)!r})")
            eof, extra = ws.wait_eof()
            check(eof, f"{tag}: proxy ended the CLIENT connection after the close (eof={eof}, extra={extra!r})")
            check(all(op == "close" for op, _ in extra),
                  f"{tag}: no data frames reached the client after its close (extra={extra!r})")

            hs_row, ws_id = finder.ws_flow(marker)
            check(hs_row.get("authority") == origin.authority,
                  f"{tag}: bus: handshake authority is the origin (was {hs_row.get('authority')!r})")
            msgs = wait_messages(bus, ws_id, has_close)
            cl = closes(msgs)
            check(len(cl) == 1, f"{tag}: bus: exactly ONE close frame captured (got {cl!r})")
            d, code, reason, injected, length = cl[0] if cl else (None, None, None, None, None)
            check((code, reason) == want,
                  f"{tag}: bus: close CODE + REASON captured as {want!r} (was {(code, reason)!r})")
            check(d == C2S, f"{tag}: bus: close direction is client_to_server (was {d!r})")
            check(injected is False, f"{tag}: bus: the observed close is not flagged injected")
            check(length == len(payload),
                  f"{tag}: bus: close frame length is {len(payload)} (was {length!r})")
            raw = [msg_data(m) for m in msgs if m.get("opcode") == "close"]
            check(raw == [payload], f"{tag}: bus: close payload captured byte-exact (was {raw!r})")
            check(wire(msgs) == [(C2S, "text"), (S2C, "text"), (C2S, "close")],
                  f"{tag}: bus: wire order text c2s, echo s2c, close c2s — close LAST (was {wire(msgs)!r})")
            summ = bus.call("flow.get", {"id": ws_id})
            n = summ.get("messages") if isinstance(summ, dict) else summ
            check(n == 3, f"{tag}: bus: flow.get reports 3 messages after the close (was {n!r})")
            return ws_id

        # ------------------------------------------------------------------ A
        section("A. client-initiated close 4001 + reason: forwarded intact, captured with code+reason")
        reason_a = f"e2e-a-{RUN}"
        ws_id_a = client_close("a", close_payload(4001, reason_a), (4001, reason_a), "code 4001 + reason")
        push = wait_flow_push(bus, ws_id_a, lambda p: p.get("event") == "killed")
        n_push = (push.get("summary") or {}).get("messages") if push else None
        check(push is not None and n_push == 3,
              f"bus: the live stream ended this flow with a `killed` push reporting 3 messages "
              f"(event={push.get('event') if push else None!r}, messages={n_push!r})")
        if operator is not None:
            status, msg = operator.try_call("ws.send", {
                "id": ws_id_a, "dir": "s2c", "opcode": "text", "data": b64(b"late")})
            check(status == "error" and "closed" in msg,
                  f"ws.send onto the CLOSED flow is refused as closed — the core knows it ended "
                  f"(got {status}: {msg[:160]!r})")
        else:
            note("no operator: the post-close ws.send refusal is not asserted")

        # ------------------------------------------------------------------ B
        section("B. server-initiated close 1001 + reason: forwarded to the client intact, captured s2c")
        reason_b = f"srv-b-{RUN}"
        marker_b = f"/ws-close-e2e/{RUN}/b"
        ws_b = open_ws(f"{marker_b}?server_close=1001&reason={reason_b}")
        tb = f"bye-b-{RUN}".encode()
        ws_b.send(OP_TEXT, tb)
        r1 = ws_b.recv()
        check(r1 == ("text", b"echo:" + tb), f"echo arrived before the server close (got {r1!r})")
        r2 = ws_b.recv()
        parsed = parse_close(r2[1]) if r2[0] == "close" else None
        check(r2 == ("close", close_payload(1001, reason_b)),
              f"CLIENT received the server's close (1001, {reason_b!r}) byte-exact (got op={r2[0]!r} parsed={parsed!r})")
        eof, extra = ws_b.wait_eof()
        check(eof, f"proxy ended the client connection after the server close (eof={eof}, extra={extra!r})")
        check(extra == [], f"nothing followed the close on the client side (extra={extra!r})")
        conn_b = origin.wait_conn(marker_b, lambda c: c.eof or c.close_raw is not None)
        check(conn_b is not None and conn_b.eof,
              f"ORIGIN side was torn down too (EOF) — no half-open relay left behind "
              f"(eof={getattr(conn_b, 'eof', None)}, close={getattr(conn_b, 'close', None)!r})")
        check(conn_b is not None and conn_b.texts == [tb],
              f"ORIGIN saw exactly the one text frame (saw {getattr(conn_b, 'texts', None)!r})")

        hs_row, ws_id_b = finder.ws_flow(marker_b)
        msgs_b = wait_messages(bus, ws_id_b, has_close)
        cl_b = closes(msgs_b)
        check(len(cl_b) == 1, f"bus: exactly ONE close frame captured (got {cl_b!r})")
        d, code, reason, injected, length = cl_b[0] if cl_b else (None, None, None, None, None)
        check((code, reason) == (1001, reason_b),
              f"bus: close CODE + REASON captured as (1001, {reason_b!r}) (was {(code, reason)!r})")
        check(d == S2C, f"bus: close direction is server_to_client (was {d!r})")
        check(injected is False, "bus: the observed close is not flagged injected")
        check(length == 2 + len(reason_b.encode()),
              f"bus: close frame length is 2+len(reason) = {2 + len(reason_b.encode())} (was {length!r})")
        check(wire(msgs_b) == [(C2S, "text"), (S2C, "text"), (S2C, "close")],
              f"bus: wire order text c2s, echo s2c, close s2c (was {wire(msgs_b)!r})")

        # ------------------------------------------------------------------ C
        section("C. EMPTY close (no status code): captured with length 0 and no code synthesised")
        client_close("c", b"", (None, ""), "a 0-byte close carries no status code")

        # ------------------------------------------------------------------ D
        section("D. MAX-length close: 123-byte reason (125-byte payload) + code 4999 captured whole")
        reason_d = f"d-{RUN}-".ljust(123, "x")
        assert len(reason_d.encode()) == 123
        client_close("d", close_payload(4999, reason_d), (4999, reason_d), "code 4999 + 123-byte reason")

        # ------------------------------------------------------------------ E
        section("E. INJECTED close via ws.send 4002 + reason: reaches the client; the reply close is captured")
        if operator is None:
            note("skipped: ws.send needs the operator connection (no AITM_BUS_OPERATOR_TOKEN)")
        else:
            marker_e = f"/ws-close-e2e/{RUN}/e"
            reason_e = f"inj-e-{RUN}"
            ws_e = open_ws(marker_e)
            te = f"ping-e-{RUN}".encode()
            ws_e.send(OP_TEXT, te)
            r = ws_e.recv()
            check(r == ("text", b"echo:" + te), f"relay is live (got {r!r})")
            _, ws_id_e = finder.ws_flow(marker_e)
            wait_messages(bus, ws_id_e, lambda ms: len(ms) >= 2)
            inj = close_payload(4002, reason_e)

            # Under `ask` a Sensitive agent call would PARK for operator approval
            # (and block this test), so the refusal asymmetry is asserted only under
            # the policies that refuse outright.
            if policy in ("auto", "readonly", "paused"):
                status, msg = agent.try_call("ws.send", {
                    "id": ws_id_e, "dir": "s2c", "opcode": "close", "data": b64(inj)})
                check(status == "error",
                      f"policy asymmetry: the AGENT is refused ws.send under policy {policy!r} ({msg[:120]!r})")
                r = ws_e.recv(QUIET)
                check(r == ("timeout", None),
                      f"nothing reached the CLIENT from the refused agent call within {QUIET}s (got {r!r})")
            else:
                note(f"agent policy is {policy!r}: agent-refusal asymmetry not asserted")

            res = operator.call("ws.send", {"id": ws_id_e, "dir": "s2c", "opcode": "close", "data": b64(inj)})
            check(isinstance(res, dict) and res.get("index") == 2,
                  f"operator ws.send accepted; injected frame index is 2 (was {res!r})")
            r = ws_e.recv()
            parsed = parse_close(r[1]) if r[0] == "close" else None
            check(r == ("close", inj),
                  f"CLIENT received the injected close (4002, {reason_e!r}) byte-exact (got op={r[0]!r} parsed={parsed!r})")
            ws_e.send(OP_CLOSE, close_payload(4002, "ack"))
            conn_e = origin.wait_conn(marker_e, lambda c: c.close_raw is not None or c.eof)
            check(conn_e is not None and conn_e.close == (4002, "ack"),
                  f"ORIGIN received the client's reply close (4002, 'ack') "
                  f"(origin saw {getattr(conn_e, 'close', None)!r}, eof={getattr(conn_e, 'eof', None)})")
            eof, extra = ws_e.wait_eof()
            check(eof, f"proxy ended the client connection after the reply close (extra={extra!r})")

            msgs_e = wait_messages(bus, ws_id_e,
                                   lambda ms: sum(1 for m in ms if m.get("opcode") == "close") >= 2)
            cl_e = closes(msgs_e)
            check(len(cl_e) == 2, f"bus: TWO close frames captured — injected + reply (got {cl_e!r})")
            if len(cl_e) == 2:
                check(cl_e[0] == (S2C, 4002, reason_e, True, len(inj)),
                      f"bus: first close is the INJECTED s2c (4002, reason) flagged injected=true "
                      f"with length {len(inj)} (was {cl_e[0]!r})")
                check(cl_e[1] == (C2S, 4002, "ack", False, 5),
                      f"bus: second close is the client's observed reply (4002, 'ack') injected=false (was {cl_e[1]!r})")
            check(wire(msgs_e) == [(C2S, "text"), (S2C, "text"), (S2C, "close"), (C2S, "close")],
                  f"bus: wire order text, echo, injected close, reply close (was {wire(msgs_e)!r})")
            summ = bus.call("flow.get", {"id": ws_id_e})
            n = summ.get("messages") if isinstance(summ, dict) else summ
            check(n == 4, f"bus: flow.get reports 4 messages (was {n!r})")
    finally:
        for c in clients:
            c.close()
        with contextlib.suppress(Exception):
            if bus is not None and sub_id is not None:
                bus.call("flow.unsubscribe", {"sub_id": sub_id})
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
