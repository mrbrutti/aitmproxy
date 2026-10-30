"""The independent observer: a real HTTP/1.1 upstream that RECORDS what it received.

A scenario proves "the mutated/replayed/injected request actually reached the
upstream" by reading Upstream.received — the origin's own record — not the proxy's
view of what it forwarded. That independence is the whole point of the framework.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import free_port


class _Recorder:
    def __init__(self):
        self.received: list[dict] = []
        self.lock = threading.Lock()

    def record(self, method, path, headers, body):
        with self.lock:
            self.received.append({
                "method": method,
                "path": path,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body": body,
            })


def _make_handler(rec: _Recorder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass  # keep the test output clean

        def _read_body(self) -> bytes:
            n = int(self.headers.get("content-length") or 0)
            return self.rfile.read(n) if n else b""

        def _handle(self):
            body = self._read_body()
            rec.record(self.command, self.path, self.headers, body.decode("latin1"))
            # Deterministic echo so a scenario can byte-compare the captured body.
            payload = json.dumps({
                "observed_by": "aitm-e2e-upstream",
                "method": self.command,
                "path": self.path,
                "body": body.decode("latin1"),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_DELETE = _handle

    return Handler


class Upstream:
    """A loopback HTTP/1.1 echo-record origin. Start, read .received, stop."""

    def __init__(self):
        self.port = free_port()
        self.rec = _Recorder()
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _make_handler(self.rec))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def received(self) -> list[dict]:
        with self.rec.lock:
            return list(self.rec.received)

    def start(self) -> "Upstream":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "Upstream":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
