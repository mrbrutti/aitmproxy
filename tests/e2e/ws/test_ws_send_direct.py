#!/usr/bin/env python3
# e2e: tier=T1 surface=ws
"""`ws.send` injects a live WebSocket frame and THE PEER receives it (echo-confirmed).

Real traffic, real proxy, real bus — never fixtures. A real RFC 6455 client speaks
THROUGH the aitm proxy to a real ws:// origin that ECHOES `echo:<text>` and RECORDS
every text frame it received (the independent observer). We then drive the tool
under test, `ws.send {dir:"c2s", opcode:"text", data}`, as the OPERATOR, injecting
a brand-new text frame towards the upstream, and prove — three independent ways —
that the frame actually left the proxy and the peer actually got it:

  1. GROUND TRUTH at the peer: the origin's own record (`conn.texts`) contains the
     exact injected payload — a byte the proxy does not control. The proxy could
     claim "injected" all it likes; this is the upstream saying "I received it".
  2. ECHO round-trip: the client reads back `echo:<payload>` — the origin only emits
     that after receiving the injected frame, so the client seeing it is end-to-end
     proof the frame traversed proxy -> origin -> proxy -> client.
  3. BUS capture: the flow's messages carry the injected frame flagged
     `injected:true`, dir `client_to_server`, opcode `text`, data == payload, at the
     `index` `ws.send` returned.

Negative control: `ws.send` onto a bogus flow id is refused (no live inject
channel), so (1)+(2) cannot be an accident of a pre-existing echo.

Core: uses the one the runner provides via env (AITM_BUS_ADDR host:port,
AITM_BUS_TOKEN agent token, AITM_PROXY_ADDR host:port, AITM_BUS_OPERATOR_TOKEN);
when that env is absent (the plain `python3 tests/e2e/run.py ws` runner) it boots
its own real core via aitm_e2e.core.Aitm on dedicated free ports, so the test is
never vacuous. `ws.send` is active egress (scope-gated) and needs the OPERATOR
role, so without an operator token the test SKIPs loudly. Flows may be shared with
parallel tests, so every lookup goes through a per-run unique path marker — never
"the last flow". Binds loopback ports: run from a real shell, not the Claude
sandbox. Exit 0 pass / 1 fail / 77 skip. Tokens are never printed.
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
import uuid
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

WAIT = 10.0  # seconds for any single ground-truth observation
RUN = secrets.token_hex(6)  # per-run marker; flows may be shared with parallel tests
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_TEXT, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x8, 0x9, 0xA


# ---------------------------------------------------------------------------
# RFC 6455 framing (pure stdlib; exercised in both the client and the origin)
# ---------------------------------------------------------------------------
def ws_encode(opcode: int, payload: bytes, mask: bool) -> bytes:
    out = bytearray([0x80 | opcode])
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


def ws_read_frame(rd):
    """One frame from a buffered reader -> (opcode, payload); (None, None) at EOF."""
    b0 = rd.read(1)
    if not b0:
        return None, None
    opcode = b0[0] & 0x0F
    b1 = rd.read(1)
    if not b1:
        return None, None
    masked = b1[0] & 0x80
    n = b1[0] & 0x7F
    if n == 126:
        n = struct.unpack("!H", rd.read(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", rd.read(8))[0]
    key = rd.read(4) if masked else None
    payload = b""
    while len(payload) < n:
        chunk = rd.read(n - len(payload))
        if not chunk:
            return None, None
        payload += chunk
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def close_quietly(*objs) -> None:
    """Close a buffered reader BEFORE its socket: the reader holds an io-ref on the
    socket, and socket.close() alone would leave the fd open (no EOF for the peer)."""
    for o in objs:
        with contextlib.suppress(OSError, ValueError):
            if isinstance(o, socket.socket):
                with contextlib.suppress(OSError):
                    o.shutdown(socket.SHUT_RDWR)
            o.close()


# ---------------------------------------------------------------------------
# the independent observer: a real ws:// origin that ECHOES + RECORDS text frames
# ---------------------------------------------------------------------------
class OriginConn:
    def __init__(self, path: str):
        self.path = path
        self.texts: list[str] = []   # every text payload THIS origin actually received
        self.eof = False
        self.done = threading.Event()


class WsOrigin:
    """For every text frame it RECEIVES it appends the payload to `texts` (the
    independent record) and sends `echo:<text>` back. Records per connection, keyed
    by the handshake path so a test finds only its own (marker) connection."""

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
        rd = sock.makefile("rb")
        rec = None
        try:
            request_line = rd.readline().decode("latin1").strip()
            words = request_line.split(" ")
            target = words[1] if len(words) > 1 else "/"
            parts = urlsplit(target)
            path = parts.path + (("?" + parts.query) if parts.query else "")
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
            while True:
                opcode, payload = ws_read_frame(rd)
                if opcode is None:
                    rec.eof = True
                    return
                if opcode == OP_TEXT:
                    rec.texts.append(payload.decode("utf-8", "replace"))
                    sock.sendall(ws_encode(OP_TEXT, b"echo:" + payload, mask=False))
                elif opcode == OP_PING:
                    sock.sendall(ws_encode(OP_PONG, payload, mask=False))
                elif opcode == OP_CLOSE:
                    with contextlib.suppress(OSError):
                        sock.sendall(ws_encode(OP_CLOSE, payload[:2], mask=False))
                    return
        except (OSError, ValueError):
            if rec is not None:
                rec.eof = True
        finally:
            if rec is not None:
                rec.done.set()
            close_quietly(rd, sock)

    def stop(self):
        with contextlib.suppress(OSError):
            self.srv.close()


# ---------------------------------------------------------------------------
# a real WebSocket client speaking THROUGH the aitm proxy (absolute-form upgrade)
# ---------------------------------------------------------------------------
class ProxiedWs:
    def __init__(self, proxy_host: str, proxy_port: int, origin_authority: str, path: str):
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=WAIT)
        self.rd = self.sock.makefile("rb")
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

    def send_text(self, text: str):
        self.sock.sendall(ws_encode(OP_TEXT, text.encode(), mask=True))

    def recv(self, timeout: float = WAIT):
        """(opcode, payload); (None, None) at EOF; ('timeout', None) on no data."""
        self.sock.settimeout(timeout)
        try:
            return ws_read_frame(self.rd)
        except socket.timeout:
            return "timeout", None
        except OSError:
            return None, None

    def recv_text(self, want: bytes, timeout: float = WAIT):
        """Read frames until a text frame carries `want` (skipping ping/pong); the
        payload if seen, else None. Lets us ignore interleaved control frames."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            op, payload = self.recv(max(0.1, deadline - time.time()))
            if op in (None, "timeout"):
                return None
            if op == OP_TEXT and payload == want:
                return payload
        return None

    def close(self):
        close_quietly(self.rd, self.sock)


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
    """Find THIS test's flows by marker among flows possibly shared with others."""

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
        deadline = time.time() + timeout
        while time.time() < deadline:
            for fid, s in self._newest_first():
                if (s.get("kind") == "http" and marker in (s.get("path") or "")
                        and s.get("status") == 101):
                    return fid, s
            time.sleep(0.1)
        return None, None

    def websocket(self, handshake_id: str, timeout: float = WAIT):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for fid, s in self._newest_first():
                if s.get("kind") == "websocket" and s.get("handshake") == handshake_id:
                    return fid
            time.sleep(0.1)
        return None


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


# ---------------------------------------------------------------------------
# the core under test: the runner's (env) or our own (boot)
# ---------------------------------------------------------------------------
class Rig:
    def __init__(self):
        self.core = None
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 0
        self.bus_addr = None
        self._agent_token = None
        self._operator_token = None
        self.shared = False

    @classmethod
    def from_env_or_boot(cls, origin_authority: str) -> "Rig":
        self = cls()
        bus = os.environ.get("AITM_BUS_ADDR")
        tok = os.environ.get("AITM_BUS_TOKEN")
        proxy = os.environ.get("AITM_PROXY_ADDR")
        if bus and tok and proxy:
            host, _, port = bus.rpartition(":")
            self.bus_addr = (host or "127.0.0.1", int(port))
            phost, _, pport = proxy.rpartition(":")
            self.proxy_host, self.proxy_port = (phost or "127.0.0.1"), int(pport)
            self._agent_token = tok
            self._operator_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None
            self.shared = True
            return self
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[origin_authority, "127.0.0.1"],
        )
        try:
            self.core = Aitm.server(cfg)
        except FileNotFoundError as e:
            skip(f"no runner core in env (AITM_BUS_ADDR/AITM_BUS_TOKEN/AITM_PROXY_ADDR) and {e}")
        self.proxy_port = cfg.proxy_port
        self.bus_addr = self.core.bus_addr
        self._agent_token = cfg.agent_token
        self._operator_token = cfg.operator_token
        return self

    @property
    def has_operator(self) -> bool:
        return self._operator_token is not None

    def agent(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._agent_token, client_name="aitm-e2e-ws-send-agent").connect()

    def operator(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._operator_token,
                         client_name="aitm-e2e-ws-send-operator").connect()

    def stop(self):
        if self.core:
            self.core.stop()


# ---------------------------------------------------------------------------
def main() -> int:
    origin = WsOrigin()
    rig = None
    agent = None
    operator = None
    scoped = False
    client = None
    try:
        section("arrange: real ws:// echo+record origin + the real core, as OPERATOR")
        rig = Rig.from_env_or_boot(origin.authority)
        ok(f"origin {origin.authority}; proxy {rig.proxy_host}:{rig.proxy_port}; "
           f"bus {rig.bus_addr[0]}:{rig.bus_addr[1]} ({'runner-provided' if rig.shared else 'booted'})")
        if not rig.has_operator:
            skip("ws.send is operator-gated active egress and no operator token is available "
                 "(set AITM_BUS_OPERATOR_TOKEN, or run standalone so the test boots its own core)")
        agent = rig.agent()
        operator = rig.operator()
        ok("agent + operator bus connections initialized")
        if rig.shared:
            # Active egress (ws.send) is scope-gated; a runner-shared core may not
            # already have our ephemeral origin in scope, so add it (operator-only).
            operator.call("scope.add", {"host": origin.authority})
            scoped = True
            ok("origin added to scope for the active (ws.send) injection")

        finder = FlowFinder(agent)

        section("establish a live WebSocket conversation THROUGH the proxy")
        marker = f"/ws-send-e2e/{RUN}"
        client = ProxiedWs(rig.proxy_host, rig.proxy_port, origin.authority, marker)
        ok("upgrade (101) proxied; Sec-WebSocket-Accept matches our key")
        # Prime the relay so the live inject channel exists and the echo of the
        # priming frame is captured (making the injected frame's index deterministic).
        client.send_text(f"prime-{RUN}")
        op, payload = client.recv()
        check(op == OP_TEXT and payload == f"echo:prime-{RUN}".encode(),
              f"relay is live: priming text round-trips through the proxy (op={op} payload={payload!r})")

        hs_id, hs_sum = finder.handshake(marker)
        check(hs_id is not None, f"bus: handshake flow captured with status 101 for {marker}")
        check((hs_sum or {}).get("authority") == origin.authority,
              f"bus: handshake authority is the origin (was {(hs_sum or {}).get('authority')!r})")
        ws_id = finder.websocket(hs_id)
        check(ws_id is not None, "bus: websocket flow spawned from that handshake")
        # Wait until both priming frames (c2s text + s2c echo) are captured so the
        # injected frame's index == 2 is deterministic.
        wait_messages(agent, ws_id, lambda ms: len(ms) >= 2)

        section("negative control: ws.send onto a NON-EXISTENT flow id is refused (no live channel)")
        # A well-formed UUID (so it passes param validation) that is not in the store,
        # proving the positive asserts below cannot be an accident of a pre-existing echo.
        bogus = str(uuid.uuid4())
        status, msg = operator.try_call("ws.send", {
            "id": bogus, "dir": "c2s", "opcode": "text",
            "data": base64.b64encode(b"nope").decode()})
        check(status == "error" and ("no flow" in msg or "no live" in msg or "closed" in msg),
              f"ws.send onto a non-existent flow is rejected as having no live channel "
              f"({status}: {msg[:140]!r})")

        section("ACT: ws.send injects a c2s text frame onto the live socket")
        injected_text = f"INJECTED-{RUN}"
        before = len(origin.conn_for(marker).texts)
        res = operator.call("ws.send", {
            "id": ws_id, "dir": "c2s", "opcode": "text",
            "data": base64.b64encode(injected_text.encode()).decode()})
        check(isinstance(res, dict) and res.get("index") == 2,
              f"ws.send accepted; appended injected frame index is 2 (was {res!r})")

        section("ASSERT 1 — GROUND TRUTH at the peer: the origin actually received it")
        conn = origin.wait_conn(marker, lambda c: injected_text in c.texts)
        texts = list(conn.texts) if conn is not None else []
        check(injected_text in texts,
              f"ORIGIN's own record contains the injected text {injected_text!r} — "
              f"the peer received the injected frame (origin saw {texts!r})")
        check(len(texts) == before + 1,
              f"exactly ONE new text frame reached the origin via injection "
              f"(before={before}, after={len(texts)})")

        section("ASSERT 2 — ECHO round-trip: the client reads back echo:<payload>")
        echoed = client.recv_text(b"echo:" + injected_text.encode())
        check(echoed == b"echo:" + injected_text.encode(),
              f"client received echo of the injected frame — full proxy->origin->proxy->client "
              f"round-trip (got {echoed!r})")

        section("ASSERT 3 — BUS capture: the injected frame is recorded, flagged injected")
        msgs = wait_messages(agent, ws_id,
                             lambda ms: any(m.get("injected") and m.get("opcode") == "text" for m in ms))
        inj = [m for m in msgs if m.get("injected") and m.get("opcode") == "text"]
        check(len(inj) == 1, f"bus: exactly ONE injected text frame captured (got {len(inj)})")
        if inj:
            m = inj[0]
            check(m.get("dir") == "client_to_server",
                  f"bus: injected frame direction is client_to_server (was {m.get('dir')!r})")
            check(msg_data(m) == injected_text.encode(),
                  f"bus: injected frame data is the exact payload (was {msg_data(m)!r})")
            idx = msgs.index(m)
            check(idx == 2, f"bus: injected frame is at index 2, matching ws.send's return (was {idx})")
            check(m.get("opcode") == "text", f"bus: injected frame opcode is text (was {m.get('opcode')!r})")
    finally:
        if client is not None:
            client.close()
        with contextlib.suppress(Exception):
            if scoped and operator is not None:
                operator.call("scope.remove", {"host": origin.authority})
        for b in (agent, operator):
            if b is not None:
                b.close()
        if rig is not None:
            rig.stop()
        origin.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
