"""TLS-MITM client helpers: a real curl driver (ALPN via --http2/--http1.1,
trusting the aitm CA), self-signed upstream certs, and TLS/gzip/chunked echo
origins. Folded in from the proxy surface's _clients.py so every surface shares
one implementation.

The MITM CA: aitm writes `<cfg.ca_dir>/ca.crt` on boot; CoreConfig gives each run
its own ca_dir, so `ca_cert(core)` is deterministic and never touches the
operator's real trust store. To trust a self-signed UPSTREAM, set
`CoreConfig.ssl_insecure = True`.
"""

from __future__ import annotations

import gzip
import json
import os
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from shutil import which


def have(tool: str) -> bool:
    return which(tool) is not None


def new_ca_dir() -> str:
    return tempfile.mkdtemp(prefix="aitm-e2e-ca-")


def ca_cert(core_or_dir) -> str:
    """Path to the MITM CA cert aitm wrote on boot. Accepts an Aitm core (reads
    core.cfg.ca_dir) or a ca_dir string."""
    ca_dir = getattr(getattr(core_or_dir, "cfg", None), "ca_dir", None) or core_or_dir
    return os.path.join(ca_dir, "ca.crt")


def curl(args, timeout: float = 20):
    """Run curl, return (returncode, stdout_bytes, stderr_text)."""
    p = subprocess.run(["curl", "-sS", *args], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def curl_http_version(args, timeout: float = 20):
    """Return (rc, negotiated_http_version, stderr) — for the ALPN / no-downgrade
    assertions. e.g. args=['--http2', '--cacert', ca, '-x', proxy, url]."""
    rc, out, err = curl([*args, "-o", "/dev/null", "-w", "%{http_version}"], timeout=timeout)
    return rc, out.decode().strip(), err


def upstream_cert(work: str) -> tuple[str, str]:
    """A self-signed cert/key for a loopback TLS upstream (CN/SAN 127.0.0.1)."""
    key = os.path.join(work, "upstream.key")
    crt = os.path.join(work, "upstream.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return crt, key


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
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
    """A TLS HTTP/1.1 echo origin (plus /gzip and /chunked). Returns (server, port)."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
