#!/usr/bin/env python3
# e2e: tier=T1 surface=sessionio
"""sessionio/test_session_export_import -- flows the REAL proxy captured from REAL
traffic, exported with `flow.export` and re-imported with `flow.import`, come back
identical. Every comparison is against the live store's own `flow.detail` of a flow
that real traffic produced THIS run -- never a fixture, never a frozen document.

Ground truth. Every byte compared here was produced by something real this run and
was observed INDEPENDENTLY of the sessionio plugin: the echo-record upstream
(`aitm_e2e.upstream.Upstream`) records a GET carrying duplicate headers, a POST with
a 256-byte NON-UTF-8 binary body + marker, and a POST form; a local WebSocket echo
origin records a text and a binary frame and echoes them; when the runner exposes
the seeded testtarget (AITM_TARGET_URL) a reflected `GET /search?q=<marker>` and a
`POST /comments` (real 302, the comment really stored) join the set. The proxy
captures all of it (HTTP flows, the 101 handshake flow, the websocket flow). Each
marker is unique per run, so flows are found by marker in the path -- never by
position or count.

What is proven (operator connection; see "roles"):

  A. `flow.export {ids, format: aitm}` returns an `aitm-session/1` document whose
     records equal `flow.detail` of each captured flow: request line + version,
     headers (order AND duplicates), request body bytes, response status/version/
     headers/body bytes, marks/comment/is_replay/truncated/edited, the created
     timestamp to the nanosecond, the duration, the client connection (peer/sni/
     alpn/tls/established) and, for the websocket flow, the handshake link and
     every frame (dir/opcode/bytes/injected).
  B. Re-importing that document with FRESH ids (`flow.import {bytes}`) returns
     exactly those ids; each imported flow's `flow.detail` equals the captured one
     in every field but the id, the added `imported` mark and the `observed`
     intercept state; the imported ws flow links to the imported handshake flow;
     the `flow.table` rows agree; the ORIGINALS are untouched; the import was
     PASSIVE (neither upstream saw a new request/frame, the testtarget's comment
     store did not grow); and export(import(export(x))) == export(x) record for
     record, only the `imported` mark differing.
  C. HAR 1.2 interchange: the HAR export carries method/url/httpVersion/headers,
     bodies as UTF-8 text or base64 (the binary body), status/content and the ws
     frames as `_webSocketMessages`; importing that HAR back yields fresh flows
     whose request line, version, headers, bodies, status and ws frames equal the
     captured ones.
  D. Fail-closed gates, each with the proof that the refusal changed nothing: the
     AGENT's `flow.import`/`flow.export` are refused at the policy gate (the four
     sessionio commands carry the fail-closed `Sensitive` class; under `auto`/`all`/
     `readonly`/`paused` they are refused, under `ask` they would park, so that
     check is skipped) and the refused import inserted no flow; a host-path
     `flow.export`/`flow.import`/`session.save` from any BUS connection is refused
     unless `session_io.allow_agent_file_io` is on and no file appears (when the
     rig opted in, the file on disk is checked to equal the bytes export and the
     path import/save are verified instead).
  E. A VERBATIM re-import (same ids) returns the document's own ids and replaces
     each flow in place -- stored once, data identical, marks + `imported`.
  F. Validation really runs: an unknown id, neither bytes nor path, a foreign
     schema tag, a mitmproxy export (import-only), an unknown format, undecodable
     bytes -- each a clear tool error.

Roles. `session.save`/`session.load`/`flow.export`/`flow.import` do not override
`Command::sensitivity`, so they carry the fail-closed default `Sensitive` and the
MCP policy gate refuses the AGENT token even the passive in-memory `bytes` form
under the default `auto` policy; the OPERATOR token (a human, never policy-gated)
drives the round-trip. SKIP (77) without an operator token, or when the core does
not expose flow.export/flow.import.

Core: the one the runner provides via env (AITM_BUS_ADDR, AITM_BUS_TOKEN,
AITM_PROXY_ADDR, AITM_BUS_OPERATOR_TOKEN, optional AITM_TARGET_URL); without that
contract it boots a dedicated core on free ports like every aitm_e2e suite.
Parallel-safe against a shared core: imports only ADD flows (part E rewrites only
this run's own flows with identical data); `session.load` (replaces the whole
store) is deliberately never called; no scope change (all traffic is passive
capture, no active command is used); the only files live in a private tmpdir.
"""

from __future__ import annotations

import base64
import calendar
import contextlib
import hashlib
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

WAIT = 15.0
TAG = f"sessio-{os.getpid()}-{secrets.token_hex(4)}"
SCHEMA = "aitm-session/1"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA
FORM_CT = "application/x-www-form-urlencoded"
UPSTREAM_MARK = b"aitm-e2e-upstream"  # what aitm_e2e.upstream.Upstream puts in every body
DOC_VERSION = {"http11": "HTTP/1.1", "h2": "HTTP/2"}  # native VersionRec -> flow.detail label
HAR_DIR = {"client_to_server": "send", "server_to_client": "receive"}
HAR_OP = {"text": 1, "binary": 2, "close": 8, "ping": 9, "pong": 10}
RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$"
)

FAILS: list = []
CHECKS = [0]


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


def expect(cond, msg: str, detail="") -> bool:
    """A SOFT check: a miss is printed and recorded but the scenario keeps going,
    so one run shows every mismatch; main() fails the suite if any was recorded.
    (`check` from the harness hard-fails on the first miss; used for preconditions.)"""
    CHECKS[0] += 1
    if cond:
        ok(msg)
        return True
    tail = f"  -- {str(detail)[:700]}" if detail != "" else ""
    print(f"  [FAIL] {msg}{tail}", flush=True)
    FAILS.append(msg)
    return False


# ---------------------------------------------------------------------------
# pure helpers: encodings and comparisons
# ---------------------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text) -> bytes | None:
    """A base64 field of flow.detail (body / ws data) -> bytes; None when absent."""
    return None if text is None else base64.b64decode(text)


def hv(msg: dict, name: str) -> list:
    """All values of header `name` (case-insensitive) in a flow.detail message,
    whose headers are `[[name, value], ...]` in wire order."""
    want = name.lower()
    return [v for k, v in (msg or {}).get("headers", []) if k.lower() == want]


def rfc3339_ns(s) -> tuple | None:
    """A flow.detail RFC 3339 timestamp (any fraction length, Z or offset) ->
    (secs_since_epoch, nanos). None when malformed/absent."""
    m = RFC3339.match(s or "")
    if not m:
        return None
    y, mo, d, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
    nanos = int((m.group(7) or "").ljust(9, "0"))
    secs = calendar.timegm((y, mo, d, hh, mm, ss))
    if m.group(8) != "Z":
        sign = 1 if m.group(8)[0] == "+" else -1
        oh, om = m.group(8)[1:].split(":")
        secs -= sign * (int(oh) * 3600 + int(om) * 60)
    return secs, nanos


def systime(st) -> tuple | None:
    """A serde `SystemTime` {secs_since_epoch, nanos_since_epoch} -> (secs, nanos)."""
    if not isinstance(st, dict):
        return None
    return st.get("secs_since_epoch"), st.get("nanos_since_epoch")


def duration_ms(d) -> int | None:
    """A serde `Duration` {secs, nanos} -> whole milliseconds (as flow.detail reports)."""
    if not isinstance(d, dict):
        return None
    return d["secs"] * 1000 + d["nanos"] // 1_000_000


def doc_body(b) -> bytes:
    """A native BodyRec (`"empty"` | {"bytes": [..]}) -> bytes."""
    if b == "empty":
        return b""
    if isinstance(b, dict) and "bytes" in b:
        return bytes(b["bytes"])
    raise ValueError(f"unexpected native body record {b!r}")


def har_body(x) -> bytes:
    """A HAR postData / content -> bytes (b'' when absent or empty)."""
    if not x or not x.get("text"):
        return b""
    return base64.b64decode(x["text"]) if x.get("encoding") == "base64" else x["text"].encode("utf-8")


def strip_volatile(detail: dict, id_map: dict | None = None) -> dict:
    """A flow.detail minus exactly what an import is specified to change: the id
    (fresh ids), the marks (`imported` is added) and the intercept state (always
    `observed` after import). For a websocket detail the handshake link is mapped
    through `id_map`. EVERYTHING else must be identical."""
    d = json.loads(json.dumps(detail))
    d.pop("id", None)
    d.pop("intercept", None)
    (d.get("meta") or {}).pop("marks", None)
    if id_map and d.get("kind") == "websocket":
        d["handshake"] = id_map.get(d.get("handshake"), d.get("handshake"))
    return d


def first_diff(a, b, path="$") -> str | None:
    """The first point where two JSON values differ, as a readable path; None if equal."""
    if type(a) is not type(b):
        return f"{path}: {str(a)[:80]!r} != {str(b)[:80]!r}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k}: present on one side only"
            r = first_diff(a[k], b[k], f"{path}.{k}")
            if r:
                return r
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: len {len(a)} != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            r = first_diff(x, y, f"{path}[{i}]")
            if r:
                return r
        return None
    return None if a == b else f"{path}: {str(a)[:80]!r} != {str(b)[:80]!r}"


def frames_of(detail: dict) -> list:
    """(dir, opcode, bytes) of every message of a websocket flow.detail."""
    return [(m["dir"], m["opcode"], b64d(m.get("data"))) for m in detail.get("messages") or []]


def frames_full(detail: dict) -> list:
    """(dir, opcode, bytes, injected) of every message of a websocket flow.detail."""
    return [(m["dir"], m["opcode"], b64d(m.get("data")), m["injected"]) for m in detail.get("messages") or []]


def sans_marks(rec: dict) -> dict:
    r = json.loads(json.dumps(rec))
    (r.get("metadata") or {}).pop("marks", None)
    return r


# ---------------------------------------------------------------------------
# a real HTTP client through the proxy that can send DUPLICATE header names
# ---------------------------------------------------------------------------
def http_via_proxy(proxy: tuple, method: str, url: str, pairs=(), body: bytes | None = None,
                   timeout: float = WAIT):
    """One real HTTP/1.1 request through the proxy in absolute-URI form (what a
    browser configured with aitm as its HTTP proxy sends). `pairs` are header
    (name, value) tuples sent as separate lines, so a duplicate name really goes on
    the wire twice. Returns (status, [(name, value), ...], body_bytes)."""
    u = urlsplit(url)
    conn = http.client.HTTPConnection(proxy[0], proxy[1], timeout=timeout)
    try:
        conn.putrequest(method, url, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", u.netloc)
        for k, v in pairs:
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, list(resp.getheaders()), data
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# RFC 6455 framing + a real ws:// echo origin (independent observer) + a client
# speaking through the proxy (same shape as tests/e2e/ws; each suite is standalone)
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
    for o in objs:
        with contextlib.suppress(OSError, ValueError):
            if isinstance(o, socket.socket):
                with contextlib.suppress(OSError):
                    o.shutdown(socket.SHUT_RDWR)
            o.close()


class OriginConn:
    def __init__(self, path: str):
        self.path = path
        self.frames: list = []  # (opcode, payload) of every data frame received
        self.done = threading.Event()


class WsOrigin:
    """A real ws:// origin: echoes every text/binary frame with the SAME opcode,
    pongs pings, answers close; records the data frames each connection delivered."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.conns: list = []
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

    def frame_count(self) -> int:
        with self.lock:
            return sum(len(c.frames) for c in self.conns)

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
            words = rd.readline().decode("latin1").strip().split(" ")
            parts = urlsplit(words[1] if len(words) > 1 else "/")
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
                    return
                if opcode in (OP_TEXT, OP_BINARY):
                    rec.frames.append((opcode, payload))
                    sock.sendall(ws_encode(opcode, payload, mask=False))
                elif opcode == OP_PING:
                    sock.sendall(ws_encode(OP_PONG, payload, mask=False))
                elif opcode == OP_CLOSE:
                    with contextlib.suppress(OSError):
                        sock.sendall(ws_encode(OP_CLOSE, payload[:2], mask=False))
                    return
        except (OSError, ValueError):
            pass
        finally:
            if rec is not None:
                rec.done.set()
            close_quietly(rd, sock)

    def stop(self):
        with contextlib.suppress(OSError):
            self.srv.close()


class ProxiedWs:
    """A real WebSocket client upgrading THROUGH the aitm proxy (absolute-form)."""

    def __init__(self, proxy_host: str, proxy_port: int, origin_authority: str, path: str):
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=WAIT)
        self.rd = self.sock.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET http://{origin_authority}{path} HTTP/1.1\r\n"
            f"Host: {origin_authority}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        status = self.rd.readline().decode("latin1").strip()
        headers = {}
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, _, v = line.decode("latin1").partition(":")
            headers[k.strip().lower()] = v.strip()
        self.status = status
        if " 101 " not in f" {status} ":
            raise RuntimeError(f"ws upgrade through the proxy failed: {status!r}")
        if headers.get("sec-websocket-accept") != ws_accept(key):
            raise RuntimeError(f"proxy returned a wrong Sec-WebSocket-Accept: {headers!r}")

    def send(self, opcode: int, payload: bytes) -> None:
        self.sock.sendall(ws_encode(opcode, payload, mask=True))

    def recv(self, timeout: float = WAIT):
        """(opcode, payload); (None, None) at EOF; ('timeout', None) on no data."""
        self.sock.settimeout(timeout)
        try:
            return ws_read_frame(self.rd)
        except socket.timeout:
            return "timeout", None
        except OSError:
            return None, None

    def close(self) -> None:
        """Orderly close: send close(1000), read until the peer's close or EOF."""
        with contextlib.suppress(OSError):
            self.sock.sendall(ws_encode(OP_CLOSE, struct.pack("!H", 1000), mask=True))
        deadline = time.time() + 5.0
        while time.time() < deadline:
            op, _ = self.recv(max(0.1, deadline - time.time()))
            if op is None or op == OP_CLOSE or op == "timeout":
                break
        close_quietly(self.rd, self.sock)


# ---------------------------------------------------------------------------
# bus helpers
# ---------------------------------------------------------------------------
def flow_ids(bus: BusClient) -> list:
    res = bus.call("flow.list")
    if isinstance(res, dict):
        for key in ("flows", "ids", "items"):
            if key in res:
                res = res[key]
                break
    if not isinstance(res, list):
        return []
    return [i.get("id", i) if isinstance(i, dict) else i for i in res]


def table(bus: BusClient) -> list:
    return bus.call("flow.table")["flows"]


def detail(bus: BusClient, fid: str) -> dict:
    return bus.call("flow.detail", {"id": fid, "body": "inline"})


def wait_flow(bus: BusClient, method: str, path: str, timeout: float = WAIT) -> str:
    """The id of the COMPLETED flow with this exact method + path (our marker is in
    the path, so this is ours even on a shared core)."""
    deadline = time.time() + timeout
    while True:
        for row in table(bus):
            if row.get("method") == method and row.get("path") == path and row.get("status") is not None:
                return row["id"]
        if time.time() > deadline:
            seen = [f"{r.get('method')} {r.get('authority')}{r.get('path')} -> {r.get('status')}" for r in table(bus)[-8:]]
            fail(f"no completed {method} {path} flow within {timeout}s; last rows: {seen}")
        time.sleep(0.1)


def find_ws_flow(bus: BusClient, handshake_id: str, timeout: float = WAIT) -> str:
    """The websocket flow whose flow.get `handshake` is our handshake flow. Table
    rows carry no handshake id, so each websocket row is resolved once."""
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        for row in table(bus):
            if row.get("kind") != "websocket" or row["id"] in seen:
                continue
            seen.add(row["id"])
            if bus.call("flow.get", {"id": row["id"]}).get("handshake") == handshake_id:
                return row["id"]
        time.sleep(0.2)
    fail(f"no websocket flow linked to handshake {handshake_id} within {timeout}s")


def settled_detail(bus: BusClient, fid: str, timeout: float = WAIT) -> dict:
    """flow.detail once the flow stopped changing (two consecutive identical reads
    and, for HTTP, a buffered response body), so the export is compared against a
    snapshot the store will not move under us."""
    deadline = time.time() + timeout
    prev = detail(bus, fid)
    while time.time() < deadline:
        time.sleep(0.25)
        cur = detail(bus, fid)
        resp = cur.get("response")
        complete = cur.get("kind") != "http" or (isinstance(resp, dict) and resp.get("body") is not None)
        if cur == prev and complete:
            return cur
        prev = cur
    return prev


def refused(bus: BusClient, name: str, args: dict | None):
    """The error text when the call is refused/fails (tool error or JSON-RPC error);
    None when it succeeded."""
    try:
        bus.call(name, args or {})
    except ToolError as e:
        return str(e)
    except BusError as e:
        return f"rpc: {e}"
    return None


class Rig:
    """The core under test: the runner's (env contract) or one booted here."""

    def __init__(self):
        self.core = None
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 0
        self.bus_addr = None
        self._agent_token = None
        self._operator_token = None
        self.shared = False

    @classmethod
    def from_env_or_boot(cls, scope_entries: list) -> "Rig":
        self = cls()
        bus = os.environ.get("AITM_BUS_ADDR")
        tok = os.environ.get("AITM_BUS_TOKEN")
        proxy = os.environ.get("AITM_PROXY_ADDR")
        if bus and tok and proxy:
            host, _, port = bus.rpartition(":")
            self.bus_addr = (host.strip("[]") or "127.0.0.1", int(port))
            phost, _, pport = proxy.rpartition(":")
            self.proxy_host, self.proxy_port = (phost.strip("[]") or "127.0.0.1"), int(pport)
            self._agent_token = tok
            self._operator_token = os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None
            self.shared = True
            return self
        cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                         scope_entries=list(scope_entries) + ["127.0.0.1"])
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
        return BusClient(host, port, self._agent_token, client_name="aitm-e2e-sessionio-agent").connect()

    def operator(self) -> BusClient:
        host, port = self.bus_addr
        return BusClient(host, port, self._operator_token, client_name="aitm-e2e-sessionio-operator").connect()

    def stop(self):
        if self.core:
            self.core.stop()


# ---------------------------------------------------------------------------
def main() -> int:
    up = Upstream().start()
    origin = WsOrigin()
    tmpdir = tempfile.mkdtemp(prefix="aitm-e2e-sessionio-")
    rig = op = agent = None
    try:
        section("arrange: echo-record upstream + ws echo origin + a real aitm core, operator AND agent")
        rig = Rig.from_env_or_boot([up.authority, origin.authority])
        if not rig.has_operator:
            skip("flow.export/flow.import carry the fail-closed Sensitive class: the OPERATOR "
                 "token is required (AITM_BUS_OPERATOR_TOKEN unset)")
        op = rig.operator()
        agent = rig.agent()
        names = set(op.tool_names())
        for need in ("flow.export", "flow.import"):
            if need not in names:
                skip(f"the core does not expose {need} (sessionio plugin not wired)")
        for need in ("flow.table", "flow.detail", "flow.get", "flow.list"):
            check(need in names, f"the core exposes {need}")
        has_save = "session.save" in names
        target = (os.environ.get("AITM_TARGET_URL") or "").rstrip("/") or None
        pp = (rig.proxy_host, rig.proxy_port)
        ok(f"{'attached to the runner core' if rig.shared else 'booted a dedicated core'} at bus {rig.bus_addr}, "
           f"proxy {pp[0]}:{pp[1]}; upstream {up.authority}; ws origin {origin.authority}; marker {TAG}")

        # ------------------------------------------------------------------
        section("act: real traffic through the proxy, each flow carrying the marker in its path")
        get_path = f"/get?t={TAG}"
        st, _, body = http_via_proxy(pp, "GET", up.base + get_path,
                                     [("X-E2E-Tag", TAG), ("X-E2E-Dup", "one"), ("X-E2E-Dup", "two")])
        check(st == 200 and UPSTREAM_MARK in body, f"GET {get_path} (duplicate headers) through the proxy: {st}, upstream body round-tripped")

        blob = bytes(range(256)) + TAG.encode()  # 0x80..0xff make it NON-UTF-8
        blob_path = f"/blob?t={TAG}"
        st, _, body = http_via_proxy(pp, "POST", up.base + blob_path,
                                     [("Content-Type", "application/octet-stream"), ("X-E2E-Tag", TAG)], blob)
        check(st == 200 and UPSTREAM_MARK in body, f"POST {blob_path} (256-byte binary body) through the proxy: {st}")

        form = urlencode({"comment": f"{TAG}-comment"}).encode()
        form_path = f"/form?t={TAG}"
        st, _, body = http_via_proxy(pp, "POST", up.base + form_path, [("Content-Type", FORM_CT)], form)
        check(st == 200 and UPSTREAM_MARK in body, f"POST {form_path} (form body) through the proxy: {st}")

        recorded = [(q["method"], q["path"]) for q in up.received]
        check(recorded == [("GET", get_path), ("POST", blob_path), ("POST", form_path)],
              f"the upstream RECORDED exactly our three requests, in order (got {recorded})")
        check(up.received[1]["body"].encode("latin1") == blob, "the upstream received the binary blob byte-for-byte")

        stored_count = None
        search_path = comments_path = None
        if target:
            search_path = f"/search?q={TAG}"
            st, _, body = http_via_proxy(pp, "GET", target + search_path, [("X-E2E-Tag", TAG)])
            check(st == 200 and f"Results for {TAG}".encode() in body,
                  f"GET testtarget{search_path}: {st}, the marker is reflected by the real upstream")
            comments_path = f"/comments?t={TAG}"
            cform = urlencode({"comment": f"{TAG}-stored"}).encode()
            st, hdrs, _ = http_via_proxy(pp, "POST", target + comments_path, [("Content-Type", FORM_CT)], cform)
            loc = {k.lower(): v for k, v in hdrs}.get("location")
            check(st == 302 and loc == "/comments", f"POST testtarget{comments_path}: {st} -> {loc}")

            def stored_count():
                s, _, b = http_via_proxy(pp, "GET", target + "/comments")
                return b.decode("utf-8", "replace").count(f"<li>{TAG}-stored</li>") if s == 200 else -1

            check(stored_count() == 1, "the testtarget stored the comment exactly once (the POST really arrived)")
        else:
            note("AITM_TARGET_URL not set: the seeded-testtarget flows (reflected GET, 302 POST) are left out")

        chat_path = f"/chat?t={TAG}"
        text_msg = f"hello {TAG}".encode()
        bin_msg = b"\x00\x01\xfe\xff" + TAG.encode()
        ws = ProxiedWs(rig.proxy_host, rig.proxy_port, origin.authority, chat_path)
        ws.send(OP_TEXT, text_msg)
        ws.send(OP_BINARY, bin_msg)
        got = [ws.recv(), ws.recv()]
        check(got == [(OP_TEXT, text_msg), (OP_BINARY, bin_msg)],
              f"the ws origin echoed the text and binary frames back through the proxy (got {got!r:.120})")
        ws.close()
        conn = origin.wait_conn(TAG, lambda c: c.done.is_set())
        check(conn is not None and conn.frames == [(OP_TEXT, text_msg), (OP_BINARY, bin_msg)],
              "the ws origin RECORDED exactly our two frames (text, binary)")

        # ------------------------------------------------------------------
        section("ground truth: the captured flows, settled, read back over the bus")
        get_id = wait_flow(op, "GET", get_path)
        blob_id = wait_flow(op, "POST", blob_path)
        form_id = wait_flow(op, "POST", form_path)
        ids = [get_id, blob_id, form_id]
        labels = {get_id: "GET dup-headers", blob_id: "POST binary", form_id: "POST form"}
        if target:
            search_id = wait_flow(op, "GET", search_path)
            comments_id = wait_flow(op, "POST", comments_path)
            ids += [search_id, comments_id]
            labels.update({search_id: "GET /search", comments_id: "POST /comments 302"})
        hs_id = wait_flow(op, "GET", chat_path)
        ws_id = find_ws_flow(op, hs_id)
        ids += [hs_id, ws_id]
        labels.update({hs_id: "GET ws upgrade", ws_id: "websocket"})
        check(len(set(ids)) == len(ids), f"{len(ids)} distinct captured flows: {ids}")

        orig = {fid: settled_detail(op, fid) for fid in ids}
        rows0 = {r["id"]: r for r in table(op) if r["id"] in set(ids)}
        check(len(rows0) == len(ids), "flow.table has a row for every captured flow")

        g = orig[get_id]
        expect(hv(g["request"], "x-e2e-dup") == ["one", "two"],
               "captured GET keeps both duplicate X-E2E-Dup headers, in wire order", g["request"]["headers"])
        expect(b64d(orig[blob_id]["request"]["body"]) == blob,
               "captured POST request body == the 256-byte binary blob + marker", orig[blob_id]["request"].get("body_size"))
        expect(b64d(orig[form_id]["request"]["body"]) == form, "captured form POST body == the form bytes")
        expect(orig[blob_id]["response"]["status"] == 200 and UPSTREAM_MARK in (b64d(orig[blob_id]["response"]["body"]) or b""),
               "captured response body is the upstream's own echo (status 200)")
        if target:
            expect(f"Results for {TAG}".encode() in (b64d(orig[search_id]["response"]["body"]) or b""),
                   "captured /search response body carries the reflected marker")
            c = orig[comments_id]
            expect(c["response"]["status"] == 302 and hv(c["response"], "location") == ["/comments"]
                   and b64d(c["response"]["body"]) == b"",
                   "captured /comments POST: 302, Location /comments, empty body", c["response"])
        expect(orig[hs_id]["response"]["status"] == 101, "captured ws handshake flow: status 101", orig[hs_id]["response"])
        w = orig[ws_id]
        wf = frames_of(w)
        expect(all(f in wf for f in [("client_to_server", "text", text_msg), ("client_to_server", "binary", bin_msg),
                                     ("server_to_client", "text", text_msg), ("server_to_client", "binary", bin_msg)]),
               "captured websocket flow holds the text + binary frames in BOTH directions", wf)
        expect(w.get("kind") == "websocket" and w.get("handshake") == hs_id,
               "captured websocket flow links to the handshake flow", (w.get("kind"), w.get("handshake")))

        # ------------------------------------------------------------------
        section("A. flow.export (native aitm, bytes): the document equals the captured flows field for field")
        out = op.confirm("flow.export", {"ids": ids, "format": "aitm"})
        check(isinstance(out, dict) and isinstance(out.get("bytes"), str) and out.get("flows") == len(ids) and "path" not in out,
              f"flow.export returned base64 bytes and flows={out.get('flows') if isinstance(out, dict) else out!r} (expected {len(ids)}, no path)")
        raw = base64.b64decode(out["bytes"])
        doc = json.loads(raw)
        expect(doc.get("schema") == SCHEMA, f"document schema is {SCHEMA}", doc.get("schema"))
        recs = doc.get("flows") or []
        expect([r.get("id") for r in recs] == ids, "document holds exactly the requested flows, in request order",
               [r.get("id") for r in recs])
        by_id = {r.get("id"): r for r in recs}
        for fid in ids:
            lab, d, rec = labels[fid], orig[fid], by_id.get(fid)
            if rec is None:
                expect(False, f"[{lab}] record present in the document")
                continue
            if d["kind"] == "http":
                rq, dq = rec["request"], d["request"]
                expect(rec.get("kind") == "http"
                       and (rq["method"], rq["scheme"], rq["authority"], rq["path"]) == (dq["method"], dq["scheme"], dq["authority"], dq["path"])
                       and DOC_VERSION.get(rq["version"]) == dq["version"],
                       f"[{lab}] native request line + version == captured",
                       ((rq["method"], rq["scheme"], rq["authority"], rq["path"], rq["version"]), (dq["method"], dq["scheme"], dq["authority"], dq["path"], dq["version"])))
                expect([list(h) for h in rq["headers"]] == dq["headers"],
                       f"[{lab}] native request headers == captured (order and duplicates)", first_diff([list(h) for h in rq["headers"]], dq["headers"]))
                expect(doc_body(rq["body"]) == b64d(dq["body"]), f"[{lab}] native request body == captured bytes",
                       (len(doc_body(rq["body"])), dq.get("body_size")))
                rs, ds = rec["response"], d["response"]
                expect(rs is not None and rs["status"] == ds["status"] and DOC_VERSION.get(rs["version"]) == ds["version"]
                       and [list(h) for h in rs["headers"]] == ds["headers"] and doc_body(rs["body"]) == b64d(ds["body"]),
                       f"[{lab}] native response status/version/headers/body == captured",
                       first_diff({"s": rs["status"], "v": DOC_VERSION.get(rs["version"]), "h": [list(h) for h in rs["headers"]], "b": len(doc_body(rs["body"]))},
                                  {"s": ds["status"], "v": ds["version"], "h": ds["headers"], "b": len(b64d(ds["body"]) or b"")}) if rs else "no response record")
            else:
                expect(rec.get("kind") == "web_socket" and rec.get("handshake") == d["handshake"],
                       f"[{lab}] native record is a web_socket record linked to the same handshake", (rec.get("kind"), rec.get("handshake")))
                doc_frames = [(m["dir"], m["opcode"], bytes(m["data"]), m["injected"]) for m in rec["messages"]]
                expect(doc_frames == frames_full(d), f"[{lab}] native frames == captured (dir, opcode, bytes, injected)",
                       first_diff([list(map(str, f)) for f in doc_frames], [list(map(str, f)) for f in frames_full(d)]))
                expect([systime(m["timestamp"]) for m in rec["messages"]] == [rfc3339_ns(m["timestamp"]) for m in d["messages"]],
                       f"[{lab}] native frame timestamps == captured, to the nanosecond")
            meta, md = rec["metadata"], d["meta"]
            expect((meta["marks"], meta["comment"], meta["is_replay"], meta["truncated"], meta["edited"])
                   == (md["marks"], md["comment"], md["is_replay"], md["truncated"], md["edited"]),
                   f"[{lab}] native metadata (marks, comment, is_replay, truncated, edited) == captured", (meta, md))
            expect(systime(meta["created"]) == rfc3339_ns(md["created"]),
                   f"[{lab}] native created timestamp == captured, to the nanosecond", (meta["created"], md["created"]))
            expect(duration_ms(meta.get("duration")) == md.get("duration_ms"),
                   f"[{lab}] native duration == captured duration_ms", (meta.get("duration"), md.get("duration_ms")))
            cc, dc = rec["client_conn"], d["client_conn"]
            expect((cc["peer"], cc["sni"], cc["alpn"], cc["tls"], systime(cc["established"]))
                   == (dc["peer"], dc["sni"], dc["alpn"], dc["tls"], rfc3339_ns(dc["established"])),
                   f"[{lab}] native client_conn (peer, sni, alpn, tls, established) == captured", (cc, dc))
            sc, dsc = rec.get("server_conn"), d.get("server_conn")
            expect((sc is None) == (dsc is None) and (sc is None or (sc["peer"], sc["tls"], systime(sc["established"])) == (dsc["peer"], dsc["tls"], rfc3339_ns(dsc["established"]))),
                   f"[{lab}] native server_conn == captured", (sc, dsc))

        # ------------------------------------------------------------------
        section("B. flow.import (fresh ids): identical flows appear, originals untouched, import passive, re-export idempotent")
        fresh = {fid: str(uuid.uuid4()) for fid in ids}
        doc2 = json.loads(raw)
        for rec in doc2["flows"]:
            rec["id"] = fresh[rec["id"]]
            if rec.get("kind") == "web_socket":
                rec["handshake"] = fresh.get(rec["handshake"], rec["handshake"])
        bytes2 = json.dumps(doc2).encode()
        before = (len(up.received), origin.frame_count(), stored_count() if stored_count else None)

        res = op.confirm("flow.import", {"bytes": b64(bytes2), "format": "aitm"})
        new_ids = res.get("ids") if isinstance(res, dict) else None
        check(isinstance(new_ids, list) and len(new_ids) == len(ids), f"flow.import returned {len(ids)} ids (got {res!r:.200})")
        expect(new_ids == [fresh[f] for f in ids], "flow.import returns the document's ids, in document order", (new_ids, [fresh[f] for f in ids]))
        listed = set(flow_ids(op))
        expect(all(n in listed for n in new_ids), "every imported flow is listed by flow.list", [n for n in new_ids if n not in listed])

        imported = {fid: detail(op, fresh[fid]) for fid in ids}
        for fid in ids:
            lab, d1, d2 = labels[fid], orig[fid], imported[fid]
            expect(strip_volatile(d2) == strip_volatile(d1, fresh),
                   f"[{lab}] imported flow.detail == captured flow.detail in every field but id/marks/intercept",
                   first_diff(strip_volatile(d2), strip_volatile(d1, fresh)))
            expect(d2["meta"]["marks"] == d1["meta"]["marks"] + ["imported"],
                   f"[{lab}] imported marks == captured marks + `imported`", (d2["meta"]["marks"], d1["meta"]["marks"]))
            expect(d2.get("intercept") == "observed" and d2["meta"]["is_replay"] is False,
                   f"[{lab}] imported flow is `observed` and not a replay", (d2.get("intercept"), d2["meta"]["is_replay"]))
        expect(imported[ws_id].get("handshake") == fresh[hs_id],
               "imported websocket flow links to the IMPORTED handshake flow", (imported[ws_id].get("handshake"), fresh[hs_id]))

        rows = {r["id"]: r for r in table(op)}
        for fid in ids:
            lab, r1, r2 = labels[fid], rows0.get(fid) or {}, rows.get(fresh[fid]) or {}
            expect(bool(r2) and all(r2.get(k) == r1.get(k) for k in ("kind", "method", "authority", "path", "status"))
                   and "imported" in (r2.get("marks") or []),
                   f"[{lab}] flow.table row of the import == original row (kind/method/authority/path/status) + `imported` mark", (r1, r2))
        for fid in ids:
            now = detail(op, fid)
            expect(now == orig[fid], f"[{labels[fid]}] original flow is untouched by the import (no `imported` mark, same data)",
                   first_diff(now, orig[fid]))

        after = (len(up.received), origin.frame_count(), stored_count() if stored_count else None)
        expect(after == before, "the import was PASSIVE: no new upstream request, no new ws frame, the comment store did not grow",
               (before, after))

        out3 = op.confirm("flow.export", {"ids": new_ids, "format": "aitm"})
        doc3 = json.loads(base64.b64decode(out3["bytes"]))
        expect([sans_marks(r) for r in doc3["flows"]] == [sans_marks(r) for r in doc2["flows"]],
               "export(import(export(flows))) == export(flows) record for record (only the `imported` mark may differ)",
               first_diff([sans_marks(r) for r in doc3["flows"]], [sans_marks(r) for r in doc2["flows"]]))
        expect([r["metadata"]["marks"] for r in doc3["flows"]] == [r["metadata"]["marks"] + ["imported"] for r in doc2["flows"]],
               "re-exported marks == document marks + `imported`")

        # ------------------------------------------------------------------
        section("C. HAR 1.2 interchange: export carries the data, import brings it back")
        har_out = op.confirm("flow.export", {"ids": ids, "format": "har"})
        check(isinstance(har_out, dict) and isinstance(har_out.get("bytes"), str), "HAR export returned bytes")
        har = json.loads(base64.b64decode(har_out["bytes"]))
        log = har.get("log") or {}
        entries = log.get("entries") or []
        expect(log.get("version") == "1.2" and (log.get("creator") or {}).get("name") == "aitmproxy" and len(entries) == len(ids),
               f"HAR log: version 1.2, creator aitmproxy, {len(ids)} entries", (log.get("version"), log.get("creator"), len(entries)))
        for fid, e in zip(ids, entries):
            lab, d = labels[fid], orig[fid]
            if d["kind"] == "http":
                rq, rs = d["request"], d["response"]
                er, es = e["request"], e["response"]
                expect(er["method"] == rq["method"] and er["url"] == f'{rq["scheme"]}://{rq["authority"]}{rq["path"]}'
                       and er["httpVersion"] == rq["version"] and [[h["name"], h["value"]] for h in er["headers"]] == rq["headers"],
                       f"[{lab}] HAR request: method/url/httpVersion/headers == captured",
                       first_diff({"m": er["method"], "u": er["url"], "v": er["httpVersion"], "h": [[h["name"], h["value"]] for h in er["headers"]]},
                                  {"m": rq["method"], "u": f'{rq["scheme"]}://{rq["authority"]}{rq["path"]}', "v": rq["version"], "h": rq["headers"]}))
                expect(har_body(er.get("postData")) == b64d(rq["body"]), f"[{lab}] HAR postData decodes to the captured request body",
                       (er.get("postData") or {}).get("encoding"))
                expect(es["status"] == rs["status"] and es["httpVersion"] == rs["version"]
                       and [[h["name"], h["value"]] for h in es["headers"]] == rs["headers"]
                       and har_body(es["content"]) == b64d(rs["body"]) and es["content"]["size"] == len(b64d(rs["body"]) or b""),
                       f"[{lab}] HAR response: status/httpVersion/headers/content == captured",
                       first_diff({"s": es["status"], "v": es["httpVersion"], "h": [[h["name"], h["value"]] for h in es["headers"]], "n": es["content"]["size"]},
                                  {"s": rs["status"], "v": rs["version"], "h": rs["headers"], "n": len(b64d(rs["body"]) or b"")}))
                expect("_webSocketMessages" not in e, f"[{lab}] HAR entry has no _webSocketMessages")
            else:
                msgs = e.get("_webSocketMessages") or []
                expect([(m["type"], m["opcode"], base64.b64decode(m["data"]), m.get("_injected", False)) for m in msgs]
                       == [(HAR_DIR[m["dir"]], HAR_OP[m["opcode"]], b64d(m["data"]), m["injected"]) for m in d["messages"]],
                       f"[{lab}] HAR _webSocketMessages == captured frames (type/opcode/base64 data/_injected)", len(msgs))
                expect(e["response"]["status"] == 101 and e["request"]["method"] == "GET",
                       f"[{lab}] HAR ws entry is a synthesized 101 upgrade", (e["request"]["method"], e["response"]["status"]))
        blob_entry = entries[ids.index(blob_id)] if len(entries) == len(ids) else {}
        expect(((blob_entry.get("request") or {}).get("postData") or {}).get("encoding") == "base64",
               "HAR encodes the non-UTF-8 binary request body as base64 (`encoding: base64`)",
               (blob_entry.get("request") or {}).get("postData"))
        form_entry = entries[ids.index(form_id)] if len(entries) == len(ids) else {}
        expect(((form_entry.get("request") or {}).get("postData") or {}).get("text") == form.decode()
               and "encoding" not in ((form_entry.get("request") or {}).get("postData") or {}),
               "HAR keeps the UTF-8 form body as plain text", (form_entry.get("request") or {}).get("postData"))

        res_har = op.confirm("flow.import", {"bytes": har_out["bytes"], "format": "har"})
        har_ids = res_har.get("ids") if isinstance(res_har, dict) else None
        check(isinstance(har_ids, list) and len(har_ids) == len(ids), f"HAR import returned {len(ids)} ids (got {res_har!r:.200})")
        expect(len(set(har_ids)) == len(har_ids) and not (set(har_ids) & (set(ids) | set(new_ids))),
               "HAR import minted fresh ids (HAR carries none), colliding with nothing", har_ids)
        for fid, hid in zip(ids, har_ids):
            lab, d, h = labels[fid], orig[fid], detail(op, hid)
            if d["kind"] == "http":
                rq, rs, hq, hs = d["request"], d["response"], h["request"], h["response"]
                expect((hq["method"], hq["scheme"], hq["authority"], hq["path"], hq["version"], hq["headers"], b64d(hq["body"]))
                       == (rq["method"], rq["scheme"], rq["authority"], rq["path"], rq["version"], rq["headers"], b64d(rq["body"])),
                       f"[{lab}] HAR round-trip: request line/version/headers/body == captured",
                       first_diff({k: hq[k] for k in ("method", "scheme", "authority", "path", "version", "headers", "body")},
                                  {k: rq[k] for k in ("method", "scheme", "authority", "path", "version", "headers", "body")}))
                expect(hs is not None and (hs["status"], hs["version"], hs["headers"], b64d(hs["body"])) == (rs["status"], rs["version"], rs["headers"], b64d(rs["body"])),
                       f"[{lab}] HAR round-trip: response status/version/headers/body == captured",
                       first_diff({k: hs[k] for k in ("status", "version", "headers", "body")} if hs else None,
                                  {k: rs[k] for k in ("status", "version", "headers", "body")}))
            else:
                expect(h.get("kind") == "websocket" and frames_full(h) == frames_full(d),
                       f"[{lab}] HAR round-trip: ws frames (dir/opcode/bytes/injected) == captured",
                       first_diff([list(map(str, f)) for f in frames_full(h)], [list(map(str, f)) for f in frames_full(d)]))
            expect(h["meta"]["marks"] == ["imported"] and h["meta"]["is_replay"] is False and h.get("intercept") == "observed",
                   f"[{lab}] HAR-imported flow is marked `imported`, not a replay, observed", h["meta"])

        # ------------------------------------------------------------------
        section("D. fail-closed gates, and the proof a refusal changed nothing")
        policy = None
        if "agent.status" in set(agent.tool_names()):
            kind, st = agent.try_call("agent.status")
            policy = st.get("policy") if kind == "ok" and isinstance(st, dict) else None
        probe = json.loads(raw)
        probe_ids = {}
        for rec in probe["flows"]:
            nid = str(uuid.uuid4())
            probe_ids[rec["id"]] = nid
            rec["id"] = nid
        for rec in probe["flows"]:
            if rec.get("kind") == "web_socket":
                rec["handshake"] = probe_ids.get(rec["handshake"], rec["handshake"])
        if policy == "ask":
            note("agent policy is `ask`: a Sensitive agent call would PARK for operator approval; agent refusal checks not run")
        else:
            msg = refused(agent, "flow.import", {"bytes": b64(json.dumps(probe).encode()), "format": "aitm"})
            expect(msg is not None, f"agent flow.import (even passive bytes) is refused at the policy gate (policy={policy})", msg)
            expect(not (set(probe_ids.values()) & set(flow_ids(op))), "the refused agent import inserted NO flow",
                   sorted(set(probe_ids.values()) & set(flow_ids(op))))
            msg = refused(agent, "flow.export", {"ids": ids, "format": "aitm"})
            expect(msg is not None, f"agent flow.export is refused at the policy gate (policy={policy})", msg)
            if has_save:
                msg = refused(agent, "session.save", {"path": os.path.join(tmpdir, "agent-session.json")})
                expect(msg is not None and not os.path.exists(os.path.join(tmpdir, "agent-session.json")),
                       "agent session.save is refused and writes nothing", msg)

        path_out = os.path.join(tmpdir, "export.aitm.json")
        kind, val = op.try_call("flow.export", {"ids": ids, "format": "aitm", "path": path_out})
        if kind == "error":
            expect("allow_agent_file_io" in val, "operator flow.export to a HOST PATH is refused and names session_io.allow_agent_file_io", val)
            expect(not os.path.exists(path_out), "the refused path export wrote no file", path_out)
            kind_i, val_i = op.try_call("flow.import", {"path": path_out, "format": "aitm"})
            expect(kind_i == "error" and "allow_agent_file_io" in str(val_i), "flow.import from a host path is refused the same way", val_i)
            if has_save:
                spath = os.path.join(tmpdir, "session.json")
                kind_s, val_s = op.try_call("session.save", {"path": spath})
                expect(kind_s == "error" and "allow_agent_file_io" in str(val_s) and not os.path.exists(spath),
                       "session.save to a host path is refused the same way and writes nothing", val_s)
            note("session_io.allow_agent_file_io is OFF on this core (the default): host-path I/O verified as refused; "
                 "the in-memory bytes form carried the round-trip")
        else:
            expect(isinstance(val, dict) and val.get("path") == path_out and val.get("flows") == len(ids),
                   "path export reports the path written and the flow count", val)
            with open(path_out, "rb") as fh:
                on_disk = json.load(fh)
            expect(on_disk == doc, "the file on disk == the bytes export, record for record", first_diff(on_disk, doc))
            path_in = os.path.join(tmpdir, "import.aitm.json")
            fresh_p = {fid: str(uuid.uuid4()) for fid in ids}
            doc_p = json.loads(raw)
            for rec in doc_p["flows"]:
                rec["id"] = fresh_p[rec["id"]]
                if rec.get("kind") == "web_socket":
                    rec["handshake"] = fresh_p.get(rec["handshake"], rec["handshake"])
            with open(path_in, "w", encoding="utf-8") as fh:
                json.dump(doc_p, fh)
            res_p = op.confirm("flow.import", {"path": path_in, "format": "aitm"})
            expect(isinstance(res_p, dict) and res_p.get("ids") == [fresh_p[f] for f in ids],
                   "flow.import from the host path returns the file's ids", res_p)
            if isinstance(res_p, dict) and res_p.get("ids"):
                expect(all(strip_volatile(detail(op, fresh_p[f])) == strip_volatile(orig[f], fresh_p) for f in ids),
                       "every path-imported flow == the captured flow (but id/marks/intercept)")
            if has_save:
                spath = os.path.join(tmpdir, "session.json")
                sres = op.confirm("session.save", {"path": spath})
                with open(spath, "rb") as fh:
                    sdoc = json.load(fh)
                srecs = {r.get("id"): r for r in sdoc.get("flows") or []}
                expect(sdoc.get("schema") == SCHEMA and isinstance(sres, dict) and sres.get("flows") == len(sdoc.get("flows") or [])
                       and all(srecs.get(f) == by_id[f] for f in ids),
                       "session.save wrote the whole store; our flows' records are identical to the native export", sres)
            note("session_io.allow_agent_file_io is ON for this core: host-path export/import/save verified")

        # ------------------------------------------------------------------
        section("E. verbatim re-import (same ids): the document's ids come back and each flow is replaced in place")
        res_v = op.confirm("flow.import", {"bytes": out["bytes"], "format": "aitm"})
        expect(isinstance(res_v, dict) and res_v.get("ids") == ids,
               "verbatim re-import returns the document's OWN ids (ids are preserved, not minted)", res_v)
        all_ids = flow_ids(op)
        expect(all(all_ids.count(f) == 1 for f in ids),
               "each preserved id is stored exactly once (replaced in place, never duplicated)", [(f, all_ids.count(f)) for f in ids])
        for fid in ids:
            lab, d = labels[fid], detail(op, fid)
            expect(strip_volatile(d) == strip_volatile(orig[fid]),
                   f"[{lab}] re-imported flow (same id): data identical to the capture", first_diff(strip_volatile(d), strip_volatile(orig[fid])))
            expect(d["meta"]["marks"] == orig[fid]["meta"]["marks"] + ["imported"],
                   f"[{lab}] re-imported flow (same id): marks == captured marks + `imported`", d["meta"]["marks"])

        # ------------------------------------------------------------------
        section("F. validation really runs (each a clear tool error, nothing inserted)")
        bogus = str(uuid.uuid4())
        msg = refused(op, "flow.export", {"ids": [bogus], "format": "aitm"})
        expect(msg is not None and bogus in msg, "flow.export of an unknown id is refused, naming the id", msg)
        msg = refused(op, "flow.import", {})
        expect(msg is not None and "bytes" in msg and "path" in msg, "flow.import with neither bytes nor path is refused", msg)
        msg = refused(op, "flow.import", {"bytes": b64(b'{"schema":"aitm-session/999","flows":[]}'), "format": "aitm"})
        expect(msg is not None and "schema" in msg, "a foreign schema tag is refused up front", msg)
        msg = refused(op, "flow.export", {"ids": ids, "format": "mitmproxy"})
        expect(msg is not None and "import-only" in msg, "a mitmproxy export is refused (import-only format)", msg)
        msg = refused(op, "flow.import", {"bytes": b64(bytes2), "format": "bogus"})
        expect(msg is not None and "unknown format" in msg, "an unknown format is refused", msg)
        msg = refused(op, "flow.import", {"bytes": b64(b"\x00not a document"), "format": "aitm"})
        expect(msg is not None, "undecodable native bytes are refused", msg)
        expect(len(flow_ids(op)) == len(all_ids), "the refused imports inserted nothing (flow count unchanged)",
               (len(all_ids), len(flow_ids(op))))

        # ------------------------------------------------------------------
        section("verdict")
        if FAILS:
            fail(f"{len(FAILS)} of {CHECKS[0]} checks failed: " + " | ".join(FAILS[:8]) + (" | ..." if len(FAILS) > 8 else ""))
        ok(f"all {CHECKS[0]} checks passed: {len(ids)} captured flows round-tripped natively (fresh ids and verbatim) and via HAR, "
           f"the gates refused, the import was passive")
        return 0
    finally:
        for b in (op, agent):
            if b:
                b.close()
        origin.stop()
        up.stop()
        if rig:
            rig.stop()
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
