"""Proxy-surface clients and upstreams the shared aitm_e2e lib does not (yet) carry.

The shared `aitm_e2e` lib covers boot (Aitm), the bus (BusClient), a plain
HTTP/1.1 echo-record `Upstream`, and the urllib `via_proxy` client. The L7 proxy
surface needs more than urllib can do: a TLS-MITM client that drives ALPN
(curl --http2 / --http1.1 + the aitm CA), a raw RFC6455 WebSocket client that can
exercise ws.send injection, and TLS / HTTP-2 / gzip / chunked upstreams. Those
live here, in a file this surface owns.

Dedup note: these two client families (TLS/curl, RFC6455 WS) are slated to move
into aitm_e2e.tls and aitm_e2e.ws; when they land this file shrinks to re-exports.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import gzip
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aitm_e2e.config import CoreConfig

PROXY_DIR = os.path.dirname(os.path.abspath(__file__))
H2_UPSTREAM_JS = os.path.join(PROXY_DIR, "h2_upstream.mjs")


# ---------------------------------------------------------------------------
# config: add ssl_insecure (trust the self-signed upstream) and a per-run CA dir
# (so curl --cacert has a deterministic cert). aitm writes <ca_dir>/ca.crt on boot.
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class ProxyConfig(CoreConfig):
    ssl_insecure: bool = True
    ca_dir: str | None = None

    def to_yaml(self) -> str:
        base = super().to_yaml()
        extra: list[str] = []
        if self.ssl_insecure:
            extra.append("ssl_insecure: true")
        if self.ca_dir:
            extra.append("ca:")
            extra.append(f'  dir: "{self.ca_dir}"')
        if not extra:
            return base
        return base + "\n".join(extra) + "\n"


def new_ca_dir() -> str:
    return tempfile.mkdtemp(prefix="aitm-e2e-ca-")


def ca_cert(ca_dir: str) -> str:
    return os.path.join(ca_dir, "ca.crt")


# ---------------------------------------------------------------------------
# upstream TLS certificate (self-signed; aitm trusts any upstream cert under
# ssl_insecure, so only the handshake has to succeed)
# ---------------------------------------------------------------------------
def upstream_cert(work: str) -> tuple[str, str]:
    key = os.path.join(work, "upstream.key")
    crt = os.path.join(work, "upstream.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return crt, key


# ---------------------------------------------------------------------------
# echo upstreams (plain + TLS), with gzip + chunked paths
# ---------------------------------------------------------------------------
class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _payload(self) -> bytes:
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        return json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }).encode()

    def do_any(self):
        payload = self._payload()
        path = self.path.split("?", 1)[0]
        if path == "/gzip":
            gz = gzip.compress(payload)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-encoding", "gzip")
            self.send_header("content-length", str(len(gz)))
            self.end_headers()
            self.wfile.write(gz)
            return
        if path == "/chunked":
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for piece in (payload[:7], payload[7:20], payload[20:]):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_any


def start_https_echo(crt: str, key: str):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------
def curl(args, timeout: float = 20):
    """Run curl, return (returncode, stdout_bytes, stderr_text)."""
    p = subprocess.run(["curl", "-sS", *args], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def curl_http_version(args, timeout: float = 20):
    rc, out, err = curl([*args, "-o", "/dev/null", "-w", "%{http_version}"], timeout=timeout)
    return rc, out.decode().strip(), err


def have(tool: str) -> bool:
    from shutil import which
    return which(tool) is not None


# ---------------------------------------------------------------------------
# node HTTP/2 + HTTP/1.1 upstream (node ships a real http2 server; stdlib doesn't)
# ---------------------------------------------------------------------------
def start_h2_upstream(crt: str, key: str, port: int):
    proc = subprocess.Popen(["node", H2_UPSTREAM_JS, crt, key, str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(100):
        line = proc.stdout.readline()
        if b"listening" in line:
            return proc
        if proc.poll() is not None:
            raise RuntimeError("h2 upstream exited: " + line.decode("utf-8", "replace"))
    raise RuntimeError("h2 upstream did not come up")


# ---------------------------------------------------------------------------
# minimal RFC6455 WebSocket client + echo origin (plain ws:// through the proxy)
# ---------------------------------------------------------------------------
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _mask(payload: bytes) -> bytes:
    key = os.urandom(4)
    return key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_encode(opcode: int, payload: bytes, mask: bool = True) -> bytes:
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
    out += _mask(payload) if mask else payload
    return bytes(out)


def ws_read_frame(rd):
    b0 = rd.read(1)
    if not b0:
        return None, None
    opcode = b0[0] & 0x0F
    b1 = rd.read(1)[0]
    masked = b1 & 0x80
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack("!H", rd.read(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", rd.read(8))[0]
    key = rd.read(4) if masked else None
    payload = b""
    while len(payload) < n:
        chunk = rd.read(n - len(payload))
        if not chunk:
            break
        payload += chunk
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


class WsClient:
    """A WebSocket client that connects THROUGH the aitm http proxy to a plain
    ws:// origin, using the absolute-form request target an HTTP proxy expects."""

    def __init__(self, proxy_host, proxy_port, origin_host, origin_port, path="/"):
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
        self.rd = self.sock.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode()
        target = f"http://{origin_host}:{origin_port}{path}"
        req = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {origin_host}:{origin_port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        status = self.rd.readline().decode().strip()
        if "101" not in status:
            raise RuntimeError(f"ws upgrade failed: {status!r} {self.rd.read(400)!r}")
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break

    def send_text(self, text: str):
        self.sock.sendall(ws_encode(0x1, text.encode(), mask=True))

    def recv(self, timeout: float = 5):
        self.sock.settimeout(timeout)
        return ws_read_frame(self.rd)

    def close(self):
        with contextlib.suppress(Exception):
            self.sock.sendall(ws_encode(0x8, b"", mask=True))
        with contextlib.suppress(Exception):
            self.sock.close()


class WsEchoServer:
    """A plain ws:// echo origin. On a text frame it replies `echo:<payload>`, so a
    client-to-server injection is observable (the server bounces it back). It also
    records received payloads in .received as an independent observer."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.received: list[str] = []
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        rd = conn.makefile("rb")
        rd.readline()  # request line
        key = None
        while True:
            line = rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode()
        conn.sendall(
            ("HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n").encode())
        while True:
            opcode, payload = ws_read_frame(rd)
            if opcode is None or opcode == 0x8:
                with contextlib.suppress(Exception):
                    conn.close()
                return
            if opcode == 0x1:
                self.received.append(payload.decode("utf-8", "replace"))
                conn.sendall(ws_encode(0x1, b"echo:" + payload, mask=False))

    def stop(self):
        with contextlib.suppress(Exception):
            self.srv.close()


# ---------------------------------------------------------------------------
# bus ground-truth helpers (over aitm_e2e BusClient)
# ---------------------------------------------------------------------------
def _flow_ids(result) -> list:
    if isinstance(result, dict):
        for key in ("flows", "ids", "items"):
            if key in result:
                result = result[key]
                break
    if isinstance(result, list):
        return [i.get("id", i) if isinstance(i, dict) else i for i in result]
    return []


def find_flow(bus, path=None, kind=None, pred=None, tries=120, delay=0.05):
    """Poll flow.list/flow.get until a flow matching the criteria appears; return
    its id. Capture lands a beat after the client sees the body, so ground-truth
    lookups must poll rather than read once."""
    for _ in range(tries):
        ok, ids = bus.try_call("flow.list")
        if ok:
            for fid in reversed(_flow_ids(ids)):
                ok2, s = bus.try_call("flow.get", {"id": fid})
                if not ok2 or not isinstance(s, dict):
                    continue
                if path is not None and s.get("path") != path:
                    continue
                if kind is not None and s.get("kind") != kind:
                    continue
                if pred is not None and not pred(s):
                    continue
                return fid
        time.sleep(delay)
    return None


def detail(bus, fid, body="inline"):
    ok, d = bus.try_call("flow.detail", {"id": fid, "body": body})
    return d if ok and isinstance(d, dict) else None


def req_headers(d) -> dict:
    return {k.lower(): v for k, v in d.get("request", {}).get("headers", [])}


def resp_headers(d) -> dict:
    return {k.lower(): v for k, v in d.get("response", {}).get("headers", [])}


def _b64(v) -> bytes:
    return base64.b64decode(v) if v else b""


def resp_body(d) -> bytes:
    return _b64(d.get("response", {}).get("body"))


def req_body(d) -> bytes:
    return _b64(d.get("request", {}).get("body"))


def wait_for(fn, tries=80, delay=0.1):
    for _ in range(tries):
        v = fn()
        if v:
            return v
        time.sleep(delay)
    return None
