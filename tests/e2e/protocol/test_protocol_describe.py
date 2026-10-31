#!/usr/bin/env python3
# e2e: tier=T1 surface=protocol
"""protocol/test_protocol_describe -- the protocol surface the core ADVERTISES is the
protocol surface the core really HAS. Nothing stale, nothing hardcoded, nothing
claimed that cannot be driven.

What the core reports about its protocols comes from up to three places, and this
test cross-examines every one of them against REAL traffic:

  1. `tools/list` namespaces -- `flow.*`/`request.send` (HTTP), `ws.*` (WebSocket),
     `tls.passthrough.*` (TLS passthrough control), `l4.*` (L4, registered only when
     the operator opted in with `l4.enabled`). This is the availability surface every
     UI consumes today (`has_tool`). The expected per-protocol command set is DERIVED
     at runtime from the Rust sources (the `fn name()` literals of each protocol
     crate) -- never a frozen count or list in this file.
  2. The flow store's `kind` vocabulary (`flow.table` / `flow.get` / `flow.detail`).
  3. `protocol.describe` / `protocol.availability` (the descriptor milestone, spec
     docs/superpowers/specs/2026-10-30-aitmproxy-protocol-descriptor-ui-design.md).
     Absent on a core that predates the milestone; the moment either appears this
     test asserts on it: every protocol described must be one this test PROVES
     live, `describe` must agree with the live tool surface, `availability` must be
     fail-closed across roles and honour `if_revision`.

Ground truth, never fixtures:
  * HTTP/1.1: a real client request through the proxy (absolute-form AND inside a
    CONNECT tunnel) to the seeded aitm-testtarget (or, without one, to a harness
    `Upstream` echo-record origin); the client's 200 + reflected marker, then the
    captured `kind: http` flow whose decoded body carries the same marker.
  * WebSocket: a real RFC 6455 session through the proxy's CONNECT tunnel to an echo
    origin THIS test owns (it records every frame it receives); the 101 handshake
    flow, the linked `kind: websocket` flow, and its frames byte-equal to the wire.
  * TLS passthrough control is wired and tier-gated: the agent is refused by the
    Sensitive-tier policy gate (never "unknown tool"); the operator gets `{hosts: [...]}`.
  * L4: if `l4.*` is advertised, the crate's whole command set is live and the
    read-tier verbs answer (ok, or an honest tool error -- never "unknown tool"); if
    it is not advertised, `l4.capture.status` is really unknown to the core.
  * Role parity: operator and agent see the identical tool registry.

Runner contract (a core the RUNNER provides; this test never boots one):
  AITM_BUS_ADDR            host:port of the loopback MCP bus        (required)
  AITM_BUS_TOKEN           the agent token                           (required)
  AITM_PROXY_ADDR          host:port of the proxy listener           (required)
  AITM_TARGET_URL          base URL of the seeded aitm-testtarget    (optional;
                           else a harness Upstream echo origin is used)
  AITM_BUS_OPERATOR_TOKEN  the operator token (role-parity sections) (optional)
Missing required env -> exit 77 with the reason. Tokens are never printed. Binds
loopback ports for the origins it owns: run from a real shell, not the sandbox.

Parallel-safe: flows are found by this test's own unique markers; no global core
state is touched (no scope/intercept/pause/clear). Exit 0 pass / 1 fail / 77 skip.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import socket
import struct
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import SKIP_EXIT, check, fail, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

ENV_BUS_ADDR = "AITM_BUS_ADDR"
ENV_BUS_TOKEN = "AITM_BUS_TOKEN"
ENV_BUS_OPERATOR_TOKEN = "AITM_BUS_OPERATOR_TOKEN"
ENV_PROXY_ADDR = "AITM_PROXY_ADDR"
ENV_TARGET_URL = "AITM_TARGET_URL"

# protocol id -> (tool-name prefix that advertises it, Rust crate whose `fn name()`
# literals define its command set). The crate is the SOURCE OF TRUTH for "all of
# the protocol's commands are live"; nothing here is a count or a frozen list.
PROTOCOL_SURFACES = {
    "ws": ("ws.", "aitm-plugin-wsctl"),
    "tls_passthrough": ("tls.passthrough.", "aitm-plugin-passthrough"),
    "l4": ("l4.", "aitm-proto-l4"),
}
# Flow-store vocabulary (crates/aitm-plugins/src/capture.rs: "`http` or `websocket`").
KIND_HTTP, KIND_WS = "http", "websocket"
# Spellings a descriptor may use for the protocols this test can PROVE live: the
# ProtocolModule ids (`http`, `ws`, `passthrough`), the L4 plugin, and the flow-store /
# UI-facing names. Anything else described is a claim nothing here can drive.
WS_IDS = {"ws", "websocket"}
PROVABLE_IDS = {"http", "passthrough", "tls", "tls_passthrough", "l4"} | WS_IDS

NAME_RE = re.compile(r'fn name\(&self\)\s*->\s*&(?:\'static\s+)?str\s*\{\s*"([a-z0-9_.]+)"', re.S)
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA
WAIT = 12.0  # seconds for any single ground-truth observation over the bus


# ---------------------------------------------------------------------------
# the runner-provided core, shaped so BusClient.agent(core)/.operator(core) work


def _hostport(name: str) -> tuple[str, int]:
    raw = os.environ.get(name, "")
    host, sep, port = raw.rpartition(":")
    if not sep or not port.isdigit():
        skip(f"{name} must be host:port (got {raw!r}); no runner-provided core")
    return (host.strip("[]") or "127.0.0.1"), int(port)


class EnvCore:
    """The core the runner booted, described by the env contract above."""

    def __init__(self):
        missing = [n for n in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR) if not os.environ.get(n)]
        if missing:
            skip(f"no runner-provided core: {', '.join(missing)} unset (exit {SKIP_EXIT})")
        self.bus_addr = _hostport(ENV_BUS_ADDR)
        self.proxy_host, self.proxy_port = _hostport(ENV_PROXY_ADDR)
        self.target_url = (os.environ.get(ENV_TARGET_URL) or "").rstrip("/") or None
        op = os.environ.get(ENV_BUS_OPERATOR_TOKEN, "")
        self.has_operator = bool(op)
        self.cfg = CoreConfig(
            proxy_port=self.proxy_port,
            agent_token=os.environ[ENV_BUS_TOKEN],
            operator_token=op,
        )


def unique(prefix: str) -> str:
    return f"{prefix}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


def b64(value) -> bytes:
    return base64.b64decode(value) if isinstance(value, str) and value else b""


# ---------------------------------------------------------------------------
# source of truth: the command names each protocol crate defines


def source_tool_names(crate: str, prefix: str) -> set[str] | None:
    """Every dotted `fn name() -> &str { "<prefix>..." }` literal under crates/<crate>/src,
    or None when the sources are not beside the test (then only live checks run)."""
    src = Path(repo_root()) / "crates" / crate / "src"
    if not src.is_dir():
        return None
    names: set[str] = set()
    for p in src.rglob("*.rs"):
        names.update(NAME_RE.findall(p.read_text(encoding="utf-8", errors="replace")))
    return {n for n in names if n.startswith(prefix)}


# ---------------------------------------------------------------------------
# real traffic helpers (stdlib only)


def http_get_absolute(phost: str, pport: int, url: str) -> tuple[int, bytes]:
    """Absolute-form GET through a proxy that is not on 127.0.0.1 (via_proxy's twin)."""
    u = urlsplit(url)
    conn = http.client.HTTPConnection(phost, pport, timeout=15)
    try:
        conn.request("GET", url, headers={"Host": u.netloc})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def http_get_via_connect(phost: str, pport: int, url: str) -> tuple[int, bytes]:
    """Cleartext HTTP/1.1 inside a CONNECT tunnel through the proxy (the second
    forward-proxy entry path, distinct from the absolute-form request)."""
    u = urlsplit(url)
    host, port = u.hostname, u.port or 80
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    conn = http.client.HTTPConnection(phost, pport, timeout=15)
    conn.set_tunnel(host, port)
    try:
        conn.request("GET", path, headers={"Host": f"{host}:{port}"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _read_until(sock: socket.socket, buf: bytes, marker: bytes) -> tuple[bytes, bytes]:
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed while reading an HTTP head")
        buf += chunk
        if len(buf) > 65536:
            raise RuntimeError("HTTP head too large")
    i = buf.index(marker) + len(marker)
    return buf[:i], buf[i:]


def _read_exact(sock: socket.socket, buf: bytes, n: int) -> tuple[bytes, bytes]:
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed mid-frame")
        buf += chunk
    return buf[:n], buf[n:]


def ws_frame(opcode: int, payload: bytes, *, mask: bool) -> bytes:
    b0 = 0x80 | opcode
    m = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        head = bytes([b0, m | n])
    elif n < 65536:
        head = bytes([b0, m | 126]) + struct.pack("!H", n)
    else:
        head = bytes([b0, m | 127]) + struct.pack("!Q", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_read_frame(sock: socket.socket, buf: bytes) -> tuple[int, bytes, bytes]:
    head, buf = _read_exact(sock, buf, 2)
    opcode, masked, n = head[0] & 0x0F, bool(head[1] & 0x80), head[1] & 0x7F
    if n == 126:
        ext, buf = _read_exact(sock, buf, 2)
        n = struct.unpack("!H", ext)[0]
    elif n == 127:
        ext, buf = _read_exact(sock, buf, 8)
        n = struct.unpack("!Q", ext)[0]
    key = b""
    if masked:
        key, buf = _read_exact(sock, buf, 4)
    payload, buf = _read_exact(sock, buf, n)
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, payload, buf


def _head_lines(head: bytes) -> list[str]:
    return head.decode("latin-1").split("\r\n")


def _headers(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in lines:
        if ":" in ln:
            k, v = ln.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _bind_or_skip(what: str, bind):
    """Bind a loopback port for an origin this test owns, or SKIP loudly: the Claude
    sandbox refuses local binds, and a test that cannot observe its origin proves nothing."""
    try:
        return bind()
    except PermissionError as e:
        skip(f"cannot bind a loopback port for {what} ({e}); run this suite from a real shell")


class WsEchoUpstream:
    """The independent observer for WebSocket: a real RFC 6455 echo server on a
    random loopback port that RECORDS every data frame it receives, so the test can
    assert what really reached the origin after the proxy relayed it."""

    def __init__(self):
        self.received: list[tuple[int, bytes]] = []
        self.handshakes: list[dict[str, str]] = []
        self._lock = threading.Lock()
        self._stop = False
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _bind_or_skip("the WebSocket echo origin", lambda: self._lsock.bind(("127.0.0.1", 0)))
        self._lsock.listen(8)
        self.port = self._lsock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _accept(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(20)
            head, buf = _read_until(conn, b"", b"\r\n\r\n")
            lines = _head_lines(head)
            hdrs = _headers(lines[1:])
            hdrs["_request_line"] = lines[0]
            with self._lock:
                self.handshakes.append(hdrs)
            key = hdrs.get("sec-websocket-key")
            if not key or hdrs.get("upgrade", "").lower() != "websocket":
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            conn.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode()
            )
            while True:
                opcode, payload, buf = ws_read_frame(conn, buf)
                if opcode in (OP_TEXT, OP_BINARY):
                    with self._lock:
                        self.received.append((opcode, payload))
                    conn.sendall(ws_frame(opcode, payload, mask=False))
                elif opcode == OP_PING:
                    conn.sendall(ws_frame(OP_PONG, payload, mask=False))
                elif opcode == OP_CLOSE:
                    conn.sendall(ws_frame(OP_CLOSE, payload[:2], mask=False))
                    return
        except (OSError, RuntimeError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def snapshot(self) -> list[tuple[int, bytes]]:
        with self._lock:
            return list(self.received)

    def stop(self) -> None:
        self._stop = True
        try:
            self._lsock.close()
        except OSError:
            pass


class WsThroughProxy:
    """A WebSocket client reaching ws://host:port/path the way a browser behind an
    HTTP proxy does: CONNECT tunnel to the proxy, then the upgrade inside it."""

    def __init__(self, phost: str, pport: int, authority: str, path: str, timeout: float = 15.0):
        self.sock = socket.create_connection((phost, pport), timeout=timeout)
        self.sock.settimeout(timeout)
        self.sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        head, buf = _read_until(self.sock, b"", b"\r\n\r\n")
        self.connect_status = int(_head_lines(head)[0].split(" ")[1])
        if self.connect_status != 200:
            raise RuntimeError(f"CONNECT {authority} -> {self.connect_status}")
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\n"
             f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
        )
        head, buf = _read_until(self.sock, buf, b"\r\n\r\n")
        lines = _head_lines(head)
        self.upgrade_status = int(lines[0].split(" ")[1])
        want = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.accept_ok = _headers(lines[1:]).get("sec-websocket-accept") == want
        self._buf = buf

    def send_text(self, text: str) -> None:
        self.sock.sendall(ws_frame(OP_TEXT, text.encode(), mask=True))

    def recv(self) -> tuple[int, bytes]:
        while True:
            opcode, payload, self._buf = ws_read_frame(self.sock, self._buf)
            if opcode == OP_PING:
                self.sock.sendall(ws_frame(OP_PONG, payload, mask=True))
                continue
            if opcode == OP_PONG:
                continue
            return opcode, payload

    def close(self) -> None:
        try:
            self.sock.sendall(ws_frame(OP_CLOSE, struct.pack("!H", 1000), mask=True))
            self.sock.settimeout(2)
            ws_read_frame(self.sock, self._buf)
        except (OSError, RuntimeError):
            pass
        finally:
            try:
                self.sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# bus helpers


def rows(bus: BusClient) -> list[dict]:
    r = bus.call("flow.table")
    return r.get("flows", []) if isinstance(r, dict) else []


def wait_rows(bus: BusClient, pred, timeout: float = WAIT) -> list[dict]:
    deadline = time.time() + timeout
    while True:
        hits = [r for r in rows(bus) if pred(r)]
        if hits or time.time() >= deadline:
            return hits
        time.sleep(0.15)


def ws_flow_for_handshake(bus: BusClient, handshake_id: str, timeout: float = WAIT) -> dict | None:
    """The `websocket` flow whose `flow.get` links `handshake` to our 101 flow. Table
    rows carry no handshake id (and parallel tests add their own ws rows), so each
    websocket row is resolved once through flow.get."""
    deadline = time.time() + timeout
    seen: set[str] = set()
    while time.time() < deadline:
        for row in rows(bus):
            if row.get("kind") != KIND_WS or row["id"] in seen:
                continue
            seen.add(row["id"])
            summary = bus.call("flow.get", {"id": row["id"]})
            if isinstance(summary, dict) and summary.get("handshake") == handshake_id:
                return summary
        time.sleep(0.15)
    return None


def call_outcome(bus: BusClient, name: str, args: dict | None = None) -> tuple[str, object]:
    """('ok', result) / ('tool_error', text) / ('rpc_error', text): the three distinct
    shapes a tools/call can take, kept apart on purpose. A `tool_error` is a command
    that RAN (e.g. the agent policy refused it: wired, gated); an `rpc_error` naming
    an unknown tool is a phantom advertisement."""
    try:
        return "ok", bus.call(name, args or {})
    except ToolError as e:
        return "tool_error", str(e)
    except BusError as e:
        return "rpc_error", str(e)


def rpc_outcome(bus: BusClient, name: str, args: dict | None = None) -> tuple[str, str]:
    kind, value = call_outcome(bus, name, args)
    return kind, str(value)[:200]


def is_hosts_list(value) -> bool:
    return isinstance(value, dict) and isinstance(value.get("hosts"), list)


def described_ids(value) -> set[str]:
    """Protocol ids from a describe-style result: a list of ids; a list of objects
    with `id`/`name`/`protocol`; an object keyed by protocol id; or an object holding
    any of those under `protocols` / `descriptors` / `supported` / `available`."""
    ids: set[str] = set()
    if isinstance(value, dict):
        for key in ("protocols", "descriptors", "supported", "available"):
            if key in value:
                inner = value[key]
                if isinstance(inner, dict) and inner and all(isinstance(v, dict) for v in inner.values()):
                    return {k.lower() for k in inner}  # {http: {...}, websocket: {...}}
                return described_ids(inner)
        for key in ("id", "name", "protocol"):
            if isinstance(value.get(key), str):
                ids.add(value[key].lower())
                break
        return ids
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                ids.add(item.lower())
            else:
                ids |= described_ids(item)
    return ids


def enabled_actions(value, path: str = "") -> dict[str, bool]:
    """Every `{..., enabled: bool}` object inside an availability result, keyed by its
    own id (`id`/`action`/`name`) or, failing that, the key path that led to it."""
    out: dict[str, bool] = {}
    if isinstance(value, dict):
        if isinstance(value.get("enabled"), bool):
            label = next((value[k] for k in ("id", "action", "name") if isinstance(value.get(k), str)), path)
            out[str(label)] = value["enabled"]
        for k, v in value.items():
            out.update(enabled_actions(v, f"{path}/{k}" if path else str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(enabled_actions(v, f"{path}[{i}]"))
    return out


# ---------------------------------------------------------------------------


def main() -> int:
    core = EnvCore()
    echo = WsEchoUpstream()  # bind first: a sandbox without port binding skips here, loudly
    fallback: Upstream | None = None
    if core.target_url is None:
        fallback = _bind_or_skip("the HTTP echo-record origin", lambda: Upstream().start())
    target_url = core.target_url or fallback.base
    target_authority = urlsplit(target_url).netloc
    bus = None
    op = None
    try:
        section("preflight: the runner-provided core is alive and really serving")
        bus = BusClient.agent(core)
        info = bus.initialize()
        check(info.get("serverInfo", {}).get("name") == "aitmproxy",
              f"bus serverInfo.name is aitmproxy (was {info.get('serverInfo')!r})")
        check(info.get("role") == "agent", f"this connection resolved to role agent (was {info.get('role')!r})")
        st = bus.call("proxy.status")
        check(st.get("listening") is True, f"proxy.status.listening is true (was {st.get('listening')!r})")
        addr = str(st.get("address") or "")
        check(addr.rsplit(":", 1)[-1] == str(core.proxy_port),
              f"proxy.status.address port is the listener we push traffic through ({addr} vs :{core.proxy_port})")
        ok(f"HTTP origin: {target_authority} ({'seeded aitm-testtarget' if core.target_url else 'harness Upstream echo-record'})")

        section("what the core advertises: protocol namespaces in the live tools/list")
        tools = bus.tools()
        names = {t["name"] for t in tools}
        check(any(n.startswith("flow.") for n in names) and "request.send" in names,
              "HTTP surface advertised (flow.* + request.send)")
        live: dict[str, set[str]] = {
            pid: {n for n in names if n.startswith(prefix)} for pid, (prefix, _) in PROTOCOL_SURFACES.items()
        }
        for pid, (prefix, crate) in PROTOCOL_SURFACES.items():
            expected = source_tool_names(crate, prefix)
            if expected is None:
                ok(f"{pid}: live {prefix}* = {sorted(live[pid]) or 'none'} (crate sources not beside the test; "
                   "set-equality against the Rust source skipped)")
                continue
            check(len(expected) > 0, f"{pid}: derived {len(expected)} {prefix}* command names from crates/{crate}/src")
            if pid == "l4":
                # Opt-in protocol: all-or-nothing. A partial set is exactly a stale registry.
                check(live[pid] in (set(), expected),
                      f"l4 surface is all-or-nothing vs the crate (live-only: {sorted(live[pid] - expected)}, "
                      f"missing: {sorted(expected - live[pid])})")
                ok(f"l4: {'ENABLED, ' + str(len(live[pid])) + ' commands live' if live[pid] else 'not enabled on this core'}")
            else:
                check(live[pid] == expected,
                      f"{pid}: live {prefix}* equals the crate's command set (live-only: "
                      f"{sorted(live[pid] - expected)}, missing: {sorted(expected - live[pid])})")
        ws_advertised = bool(live["ws"])
        l4_advertised = bool(live["l4"])
        bad_schema = [t["name"] for t in tools
                      if t["name"].split(".")[0] in ("ws", "tls", "l4") and not isinstance(t.get("inputSchema"), dict)]
        check(not bad_schema, f"every protocol tool carries a real inputSchema (bad: {bad_schema})")

        section("ground truth HTTP/1.1: real requests through the proxy, captured as kind=http")
        m_abs, m_tun = unique("abs"), unique("tun")
        url_abs = f"{target_url}/search?q={m_abs}"
        if core.proxy_host in ("127.0.0.1", "localhost"):
            r = via_proxy(core.proxy_port, "GET", url_abs)
            status_abs, body_abs = r.status, r.body
        else:
            status_abs, body_abs = http_get_absolute(core.proxy_host, core.proxy_port, url_abs)
        check(status_abs == 200, f"client got {status_abs} for GET /search through the proxy (expected 200)")
        check(m_abs.encode() in body_abs, "the origin really reflected our marker in the body the client saw")
        status_tun, body_tun = http_get_via_connect(core.proxy_host, core.proxy_port,
                                                    f"{target_url}/preview?msg={m_tun}")
        check(status_tun == 200, f"client got {status_tun} for GET /preview inside a CONNECT tunnel (expected 200)")
        check(m_tun.encode() in body_tun, "the tunnelled response body carries our marker too")
        if fallback is not None:
            seen_paths = [r["path"] for r in fallback.received]
            check(any(m_abs in p for p in seen_paths) and any(m_tun in p for p in seen_paths),
                  "the origin itself recorded both requests (they went THROUGH the proxy)")

        hit_abs = wait_rows(bus, lambda f: m_abs in (f.get("path") or "") and f.get("status") is not None)
        hit_tun = wait_rows(bus, lambda f: m_tun in (f.get("path") or "") and f.get("status") is not None)
        check(len(hit_abs) == 1, f"exactly one captured flow carries the absolute-form marker ({len(hit_abs)})")
        check(len(hit_tun) == 1, f"exactly one captured flow carries the CONNECT-tunnel marker ({len(hit_tun)})")
        for label, hit in (("absolute-form", hit_abs), ("CONNECT-tunnel", hit_tun)):
            row = hit[0]
            check(row.get("kind") == KIND_HTTP, f"{label} flow has kind=http (was {row.get('kind')!r})")
            check(row.get("status") == 200 and row.get("authority") == target_authority,
                  f"{label} flow is 200 from {target_authority} (was {row.get('status')} {row.get('authority')})")
        detail = bus.call("flow.detail", {"id": hit_abs[0]["id"], "body": "inline"})
        check(detail.get("kind") == KIND_HTTP, "flow.detail kind=http")
        check(detail.get("request", {}).get("scheme") == "http", "flow.detail request.scheme is http")
        check(m_abs.encode() in b64((detail.get("response") or {}).get("body")),
              "flow.detail response body (base64-decoded) is the real reflected body")

        section("ground truth WebSocket: a real RFC 6455 session through the proxy, captured as kind=websocket")
        check(ws_advertised, "ws.* is advertised (the WsModule is wired unconditionally in the binary)")
        m_ws = unique("ws")
        payload = f"hello-{m_ws}"
        ws = WsThroughProxy(core.proxy_host, core.proxy_port, echo.authority, f"/chat?t={m_ws}")
        try:
            check(ws.upgrade_status == 101 and ws.accept_ok,
                  f"upgrade completed through the proxy with a valid Sec-WebSocket-Accept (status {ws.upgrade_status})")
            ws.send_text(payload)
            opcode, data = ws.recv()
            check((opcode, data) == (OP_TEXT, payload.encode()), "text frame echoed back through the proxy intact")
        finally:
            ws.close()
        check(echo.snapshot() == [(OP_TEXT, payload.encode())],
              f"the origin itself recorded exactly our one text frame ({echo.snapshot()!r})")
        check(any(m_ws in h.get("_request_line", "") for h in echo.handshakes),
              "the origin saw the upgrade request with our marker (it went through the proxy)")
        hs = wait_rows(bus, lambda f: m_ws in (f.get("path") or "") and f.get("status") is not None)
        check(len(hs) == 1 and hs[0].get("kind") == KIND_HTTP and hs[0].get("status") == 101,
              f"the handshake is captured as ONE kind=http flow with status 101 ({[(h.get('kind'), h.get('status')) for h in hs]})")
        wsf = ws_flow_for_handshake(bus, hs[0]["id"])
        check(wsf is not None, "a kind=websocket flow links to our handshake flow")
        wdetail = bus.call("flow.detail", {"id": wsf["id"], "body": "inline"})
        msgs = wdetail.get("messages") or []
        check(wdetail.get("kind") == KIND_WS and wdetail.get("handshake") == hs[0]["id"],
              "flow.detail kind=websocket and handshake points at our 101 flow")
        c2s = [b64(m.get("data")) for m in msgs if m.get("dir") == "client_to_server" and m.get("opcode") == "text"]
        s2c = [b64(m.get("data")) for m in msgs if m.get("dir") == "server_to_client" and m.get("opcode") == "text"]
        check(c2s == [payload.encode()], f"client->server frame captured byte-equal to the wire ({c2s!r})")
        check(s2c == [payload.encode()], f"server->client echo captured byte-equal to the wire ({s2c!r})")
        check(all(m.get("injected") is False for m in msgs), "no captured frame is marked injected")

        section("ground truth TLS passthrough control: tls.passthrough.* is wired AND gated by tier")
        # Neither passthrough nor wsctl overrides Command::sensitivity, so these commands
        # sit in the fail-closed default tier (Sensitive, crates/aitm-core/src/command.rs):
        # under the default `auto` agent policy the agent is REFUSED (the gate ran -> a
        # tool error), never answered "unknown tool" (that would be a phantom entry).
        tls_kind, tls_value = call_outcome(bus, "tls.passthrough.list")
        check(tls_kind != "rpc_error",
              f"tls.passthrough.list is a real command for the agent (got {tls_kind}: {str(tls_value)[:120]})")
        agent_hosts = None
        if tls_kind == "ok":
            check(is_hosts_list(tls_value),
                  f"agent's tls.passthrough.list answers {{hosts: [...]}} (got {str(tls_value)[:120]})")
            agent_hosts = tls_value.get("hosts")
            ok("the agent policy on this core permits the Sensitive tier (answered)")
        else:
            check("refused" in str(tls_value).lower(),
                  f"agent is refused tls.passthrough.list by the policy gate (Sensitive tier): {str(tls_value)[:160]}")

        section("ground truth L4: advertised iff really wired")
        if l4_advertised:
            for verb in ("l4.capture.status", "l4.interfaces"):
                kind, text = rpc_outcome(bus, verb)
                check(kind != "rpc_error", f"{verb} is a real command (not unknown tool): {text[:120]}")
                ok(f"{verb} -> {kind}: {text[:120]}")
        else:
            kind, text = rpc_outcome(bus, "l4.capture.status")
            check(kind == "rpc_error" and "unknown tool" in text,
                  f"with no l4.* advertised, l4.capture.status is really unknown to the core (got {kind}: {text[:120]})")

        section("the flow store speaks only the advertised protocols")
        allowed = {KIND_HTTP} | ({KIND_WS} if ws_advertised else set())
        observed = {r.get("kind") for r in rows(bus)}
        check(observed <= allowed, f"every flow kind is an advertised protocol (observed {sorted(map(str, observed))}, allowed {sorted(allowed)})")
        check({KIND_HTTP, KIND_WS} <= observed, f"both kinds this test produced are in the store ({sorted(map(str, observed))})")

        section("role parity: operator and agent see the same protocol surface")
        if not core.has_operator:
            ok(f"{ENV_BUS_OPERATOR_TOKEN} not provided; operator parity not asserted")
        else:
            op = BusClient.operator(core)
            op_names = set(op.tool_names())
            check(op_names == names,
                  f"tools/list is identical for operator and agent (operator-only: {sorted(op_names - names)}, "
                  f"agent-only: {sorted(names - op_names)})")
            op_lst = op.call("tls.passthrough.list")
            check(is_hosts_list(op_lst),
                  f"operator's tls.passthrough.list answers {{hosts: [...]}} (got {str(op_lst)[:120]})")
            if agent_hosts is not None:
                check(op_lst.get("hosts") == agent_hosts, "operator and agent see the same passthrough host list")

        section("protocol.describe / protocol.availability: asserted the moment the core grows them")
        describe_tools = sorted(n for n in names if n.split(".", 1)[0] in ("protocol", "protocols"))
        desc_name = next((n for n in describe_tools if n.endswith(".describe")), None)
        avail_name = next((n for n in describe_tools if n.endswith(".availability")), None)
        if not describe_tools:
            ok("this core predates the descriptor milestone (no protocol.*/protocols.* tool): its protocol "
               "availability surface IS tools/list, which was just proven against real traffic")
        for name in describe_tools:
            kind, text = rpc_outcome(bus, name)
            check(kind == "ok", f"{name} answers for an agent (got {kind}: {text[:120]})")
        if desc_name:
            described = bus.call(desc_name)
            ids = described_ids(described)
            check(bool(ids), f"{desc_name} reports at least one protocol id (got {str(described)[:160]})")
            check("http" in ids, f"{desc_name} describes http (got {sorted(ids)})")
            check(bool(ids & WS_IDS) == ws_advertised,
                  f"{desc_name} describes WebSocket iff ws.* is live (got {sorted(ids)}, live={ws_advertised})")
            check(ids <= PROVABLE_IDS,
                  f"{desc_name} describes nothing this test cannot drive for real (unprovable: {sorted(ids - PROVABLE_IDS)})")
            if l4_advertised:
                check("l4" in ids, f"l4.* is live, so {desc_name} must describe l4 (got {sorted(ids)})")
            elif "l4" in ids:
                # Compiled in but not enabled on this core: legitimate only if an
                # availability surface exists to say so (checked below).
                check(avail_name is not None,
                      f"{desc_name} describes l4 while no l4.* tool is registered; without {desc_name.rsplit('.', 1)[0]}"
                      ".availability that is a stale claim")
            if isinstance(described, dict):
                for key in ("schema_version", "vocab_version"):
                    if key in described:
                        check(described[key] not in (None, ""), f"{desc_name}.{key} is set ({described[key]!r})")
            if op:
                check(op.call(desc_name) == described, f"{desc_name} is static: identical for operator and agent")
        if avail_name:
            avail = bus.call(avail_name)
            check(isinstance(avail, dict), f"{avail_name} answers an object (got {type(avail).__name__})")
            enabled = enabled_actions(avail)
            av_ids = described_ids(avail)
            ok(f"{avail_name}: {len(enabled)} action(s) reported, {sum(enabled.values())} enabled for the agent; "
               f"protocols {sorted(av_ids) or 'n/a'}")
            if not l4_advertised:
                l4_on = sorted(a for a, on in enabled.items() if on and a.lower().startswith("l4"))
                check(not l4_on, f"no l4 action is enabled while l4.* is not registered (enabled: {l4_on})")
            if av_ids:
                check(av_ids <= PROVABLE_IDS,
                      f"{avail_name} names only protocols this test can prove (unprovable: {sorted(av_ids - PROVABLE_IDS)})")
            rev = avail.get("revision")
            if rev is not None:
                again = bus.call(avail_name, {"if_revision": rev})
                check(isinstance(again, dict) and again.get("unchanged") is True and again.get("revision") == rev,
                      f"{avail_name} {{if_revision}} answers unchanged=true with the same revision (got {str(again)[:120]})")
            if op:
                op_avail = op.call(avail_name)
                op_enabled = enabled_actions(op_avail)
                lost = sorted(a for a, on in enabled.items() if on and not op_enabled.get(a, False))
                check(not lost, f"fail-closed across roles: every action enabled for the agent is enabled for the operator "
                                f"(agent-only: {lost})")
    finally:
        if op:
            op.close()
        if bus:
            bus.close()
        echo.stop()
        if fallback is not None:
            fallback.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
