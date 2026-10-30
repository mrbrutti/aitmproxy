"""Shared harness for the aitmproxy L7 proxy end-to-end tests.

These tests prove the proxy against REAL traffic: a real `aitm` binary MITMing
real clients (curl, a stdlib WebSocket client, a node HTTP/2 client) talking to
real upstream servers, with every claim checked twice — once on what the client
observed, and once on what the proxy captured on its MCP bus (the decrypted
flow). Stdlib only on the Python side; the HTTP/2 upstream is a short node
script (node ships a real `http2` server, Python stdlib does not).

Run each protocol script directly (it boots its own `aitm`); exit status is the
number of failed checks. The scripts bind loopback ports, so they must run in a
real shell, not the sandbox.
"""

import base64
import contextlib
import gzip
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
AITM = os.environ.get("AITM_BIN", os.path.join(ROOT, "target", "debug", "aitm"))

RESULTS = []


def check(name, cond, detail=""):
    ok = bool(cond)
    RESULTS.append((name, ok, detail))
    line = ("ok   " if ok else "FAIL ") + name
    if detail and not ok:
        line += f"   — {detail}"
    print(line, flush=True)
    return ok


def done():
    fails = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(fails)} ok, {len(fails)} failed", flush=True)
    sys.exit(len(fails))


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# upstream certificate (self-signed; aitm trusts any upstream cert with
# ssl_insecure, so only the handshake has to succeed)
# ---------------------------------------------------------------------------
def upstream_cert(work):
    key = os.path.join(work, "upstream.key")
    crt = os.path.join(work, "upstream.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return crt, key


# ---------------------------------------------------------------------------
# upstream echo server (plain HTTP/1.1 and HTTPS), with gzip + chunked paths
# ---------------------------------------------------------------------------
class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _echo_payload(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        return json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }).encode()

    def do_any(self):
        payload = self._echo_payload()
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
            # three deliberately uneven chunks
            for piece in (payload[:7], payload[7:20], payload[20:]):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        if path.startswith("/status/"):
            code = int(path.rsplit("/", 1)[1])
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_any


def start_http_echo():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def start_https_echo(crt, key):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# MCP bus (operator trust: present the operator token so sensitive commands
# — intercept, pause, clear — run the way the web/TUI operator drives them)
# ---------------------------------------------------------------------------
class Bus:
    def __init__(self, host, port, token):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.f = self.sock.makefile("rwb")
        self.f.write((json.dumps({"token": token}) + "\n").encode())
        self.f.flush()
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "proxy-e2e", "version": "0"}})

    def rpc(self, method, params=None):
        self.n += 1
        msg = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}
        self.f.write((json.dumps(msg) + "\n").encode())
        self.f.flush()
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("bus closed")
            reply = json.loads(line)
            if reply.get("id") == self.n:
                if "error" in reply:
                    raise RuntimeError(f"rpc {reply['error']['code']}: {reply['error']['message']}")
                return reply["result"]

    def call(self, tool, **args):
        r = self.rpc("tools/call", {"name": tool, "arguments": args})
        text = r.get("content", [{}])[0].get("text", "")
        if r.get("isError"):
            return False, text
        return True, r.get("structuredContent", text)

    def close(self):
        with contextlib.suppress(Exception):
            self.sock.close()


# ---------------------------------------------------------------------------
# the aitm process + its config
# ---------------------------------------------------------------------------
class Rig:
    """Boot a real aitm with a loopback proxy, an operator MCP bus, and the given
    upstream authorities in scope. Use as a context manager."""

    def __init__(self, scope_authorities, extra_config=""):
        self.work = tempfile.mkdtemp(prefix="proxy-e2e-")
        self.proxy_port = free_port()
        self.bus_port = free_port()
        self.browser_port = free_port()
        self.op_token = "o" * 64
        self.agent_token = "a" * 64
        self.proxy = f"127.0.0.1:{self.proxy_port}"
        self.ca_dir = os.path.join(self.work, "ca")
        entries = "\n".join(f'    - "{a}"' for a in scope_authorities)
        self.cfg = os.path.join(self.work, "aitm.yaml")
        with open(self.cfg, "w") as f:
            f.write(f"""listen: {self.proxy}
ssl_insecure: true
ca:
  dir: {self.ca_dir}
browser:
  proxy_addr: 127.0.0.1:{self.browser_port}
scope:
  entries:
{entries}
mcp:
  transport:
    loopback_tcp:
      port: {self.bus_port}
      token: "{self.agent_token}"
  operator_token: "{self.op_token}"
{extra_config}""")
        self.proc = None
        self.bus = None

    def __enter__(self):
        logf = open(os.path.join(self.work, "aitm.log"), "w")
        self.logf = logf
        self.proc = subprocess.Popen([AITM, "--config", self.cfg],
                                     stdout=logf, stderr=subprocess.STDOUT)
        # wait for the proxy port to accept
        for _ in range(100):
            if self.proc.poll() is not None:
                raise RuntimeError(f"aitm exited early; see {logf.name}")
            with contextlib.suppress(OSError):
                socket.create_connection(("127.0.0.1", self.proxy_port), timeout=0.3).close()
                break
            time.sleep(0.1)
        self.bus = Bus("127.0.0.1", self.bus_port, self.op_token)
        return self

    def __exit__(self, *exc):
        if self.bus:
            self.bus.close()
        if self.proc:
            self.proc.terminate()
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=5)
            if self.proc.poll() is None:
                self.proc.kill()
        self.logf.close()

    def ca_cert(self):
        return os.path.join(self.ca_dir, "ca.crt")

    def log_tail(self, n=40):
        with contextlib.suppress(Exception):
            with open(os.path.join(self.work, "aitm.log")) as f:
                return "".join(f.readlines()[-n:])
        return ""


# ---------------------------------------------------------------------------
# flow helpers over the bus
# ---------------------------------------------------------------------------
def wait_for(fn, tries=60, delay=0.1):
    for _ in range(tries):
        v = fn()
        if v:
            return v
        time.sleep(delay)
    return None


def find_flow(bus, path=None, kind=None, pred=None, tries=80, delay=0.05):
    """Retry flow.list/flow.get until a flow matching the criteria appears, and
    return its id. Capture lands in the store a beat after the client sees the
    body, so ground-truth lookups must poll rather than read once."""
    for _ in range(tries):
        ok, ids = bus.call("flow.list")
        if ok and isinstance(ids, list):
            for fid in reversed(ids):
                ok2, s = bus.call("flow.get", id=fid)
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


def flow_detail(bus, fid, body="inline"):
    ok, d = bus.call("flow.detail", id=fid, body=body)
    return d if ok else None


def req_headers(detail):
    return {k.lower(): v for k, v in detail.get("request", {}).get("headers", [])}


def resp_headers(detail):
    return {k.lower(): v for k, v in detail.get("response", {}).get("headers", [])}


def resp_body_bytes(detail):
    b = detail.get("response", {}).get("body")
    return base64.b64decode(b) if b else b""


def req_body_bytes(detail):
    b = detail.get("request", {}).get("body")
    return base64.b64decode(b) if b else b""


# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------
def curl(args, timeout=20):
    """Run curl, return (returncode, stdout_bytes, stderr_text)."""
    p = subprocess.run(["curl", "-sS", *args], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# minimal RFC6455 WebSocket client (speaks to the aitm proxy over plain TCP;
# plain ws:// is proxied as an absolute-form GET the proxy upgrades + hands off)
# ---------------------------------------------------------------------------
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _mask(payload):
    key = os.urandom(4)
    return key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_encode(opcode, payload, mask=True):
    b0 = 0x80 | opcode
    n = len(payload)
    out = bytearray([b0])
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
        out += _mask(payload)
    else:
        out += payload
    return bytes(out)


def ws_read_frame(rd):
    """Read one frame from a buffered reader. Returns (opcode, payload)."""
    b0 = rd.read(1)
    if not b0:
        return None, None
    b0 = b0[0]
    opcode = b0 & 0x0F
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
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        status = self.rd.readline().decode().strip()
        if "101" not in status:
            rest = self.rd.read(400)
            raise RuntimeError(f"ws upgrade failed: {status!r} {rest!r}")
        # drain the rest of the response headers
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break

    def send_text(self, text):
        self.sock.sendall(ws_encode(0x1, text.encode(), mask=True))

    def recv(self, timeout=5):
        self.sock.settimeout(timeout)
        return ws_read_frame(self.rd)

    def close(self):
        with contextlib.suppress(Exception):
            self.sock.sendall(ws_encode(0x8, b"", mask=True))
        with contextlib.suppress(Exception):
            self.sock.close()


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


class WsEchoServer:
    """A plain ws:// echo origin. On a text frame it replies `echo:<payload>` so a
    client-to-server injection is observable (the server bounces it back)."""

    def __init__(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.received = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        rd = conn.makefile("rb")
        reqline = rd.readline()
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
# node HTTP/2 upstream (node ships a real http2 server; python stdlib doesn't)
# ---------------------------------------------------------------------------
H2_UPSTREAM_JS = os.path.join(os.path.dirname(__file__), "h2_upstream.mjs")


def start_h2_upstream(crt, key, port):
    proc = subprocess.Popen(["node", H2_UPSTREAM_JS, crt, key, str(port)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # wait for the "listening" line
    for _ in range(100):
        line = proc.stdout.readline()
        if b"listening" in line:
            return proc
        if proc.poll() is not None:
            raise RuntimeError("h2 upstream exited: " + line.decode("utf-8", "replace"))
    raise RuntimeError("h2 upstream did not come up")
