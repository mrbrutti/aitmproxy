#!/usr/bin/env python3
# e2e: tier=T1 surface=passthrough needs=openssl
"""TLS passthrough: a configured host is tunnelled byte-for-byte, never MITM'd.

Proves F11 on a REAL `aitm` core with REAL TLS traffic, asserting on GROUND TRUTH
the proxy cannot fabricate — never a fixture:

  - the host is CONFIGURED for passthrough (`tls.passthrough` seed, read back over
    the bus with `tls.passthrough.list`);
  - the connection is TUNNELLED, not MITM'd: a client CONNECTing the passthrough
    host completes its TLS handshake against the ORIGIN'S OWN self-signed cert
    (the exact DER we minted), reads the origin's unique body marker, and a client
    that trusts ONLY the aitm CA is REJECTED by that host (the leaf was never
    minted by aitm) — so the proxy never terminated TLS;
  - it is FLAGGED as passthrough: `flow.table` holds a `CONNECT` row marked
    `tunnelled` for the host and NO decrypted request flow leaked for it;
  - CONTRAST (so "not MITM'd" is meaningful): a non-passthrough host on the SAME
    proxy IS MITM'd — the client sees a CA-minted leaf (not the origin cert) and
    the decrypted `GET /secret` is captured.

The passthrough feature needs a TLS origin that presents its own certificate, so
(like the canonical Rust test crates/aitm-plugin-passthrough/tests/tunnel.rs) this
spawns a dedicated loopback TLS origin as the independent observer; aitm-testtarget
serves plain HTTP and cannot exercise a pinned-cert tunnel.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shutil import which

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

ORIGIN_MARKER = "passthrough-e2e-origin-7f3a"
SECRET_PATH = "/secret"


# --------------------------------------------------------------------------
# config: CoreConfig + ssl_insecure (aitm trusts the self-signed origin when it
# MITMs the contrast host), a per-run CA dir (aitm writes <dir>/ca.crt on boot),
# and the tls.passthrough seed under test.
# --------------------------------------------------------------------------
@dataclasses.dataclass
class PassthroughConfig(CoreConfig):
    ssl_insecure: bool = True
    ca_dir: str | None = None
    passthrough_hosts: list = dataclasses.field(default_factory=list)

    def to_yaml(self) -> str:
        # The base CoreConfig.to_yaml now emits ssl_insecure and the ca: block itself
        # (CoreConfig gained those fields), so only the tls.passthrough seed is unique
        # here — re-emitting ssl_insecure/ca would produce a duplicate YAML key and the
        # core would refuse to start ("duplicate field `ssl_insecure`").
        base = super().to_yaml()
        if not self.passthrough_hosts:
            return base
        extra = ["tls:", "  passthrough:"]
        extra.extend(f'    - "{h}"' for h in self.passthrough_hosts)
        return base + "\n".join(extra) + "\n"


# --------------------------------------------------------------------------
# a loopback TLS origin presenting its OWN self-signed cert (the independent
# observer): every GET echoes a unique marker + the path it received.
# --------------------------------------------------------------------------
class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):  # keep test output clean
        pass

    def do_GET(self):
        payload = json.dumps(
            {"origin": ORIGIN_MARKER, "method": self.command, "path": self.path}
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(payload)


def _mint_origin_cert(work: str) -> tuple[str, str]:
    key = os.path.join(work, "origin.key")
    crt = os.path.join(work, "origin.crt")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return crt, key


def _resolve_first(host: str) -> tuple[int, str]:
    """The first (family, address) the system resolver returns for `host` — the
    exact one the core's `lookup_host(host).next()` will dial, so we bind the origin
    there (on macOS `localhost` resolves to ::1 before 127.0.0.1)."""
    fam, _type, _proto, _canon, sa = socket.getaddrinfo(
        host, 0, type=socket.SOCK_STREAM)[0]
    return fam, sa[0]


def _start_tls_origin(crt: str, key: str, family: int, address: str):
    if family == socket.AF_INET6:
        class _Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6
    else:
        _Server = ThreadingHTTPServer
    srv = _Server((address, 0), _OriginHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# --------------------------------------------------------------------------
# a raw client: CONNECT through the proxy, then drive TLS directly on the tunnel.
# --------------------------------------------------------------------------
def _connect(proxy_port: int, authority: str, timeout: float = 15.0):
    """Open a CONNECT tunnel through the proxy; return (socket, reply_head)."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    reply = b""
    while b"\r\n\r\n" not in reply:
        chunk = sock.recv(256)
        if not chunk:
            break
        reply += chunk
    return sock, reply.decode("latin1")


def _tls_fetch(sock, sni: str, ctx: ssl.SSLContext, path: str = SECRET_PATH):
    """Finish TLS over an opened tunnel; return (peer_cert_der, response_bytes)."""
    tls = ctx.wrap_socket(sock, server_hostname=sni)
    der = tls.getpeercert(binary_form=True)
    tls.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode()
    )
    data = b""
    while True:
        try:
            chunk = tls.recv(4096)
        except ssl.SSLError:
            break
        if not chunk:
            break
        data += chunk
    with contextlib.suppress(OSError):
        tls.close()
    return der, data


def _accept_any_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _ca_only_ctx(ca_path: str) -> ssl.SSLContext:
    """A client that trusts ONLY the aitm CA: a successful handshake proves the
    leaf was minted by that CA (the host was MITM'd)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_path)
    return ctx


# --------------------------------------------------------------------------
# flow.table ground-truth helpers over the operator bus.
# --------------------------------------------------------------------------
def _host_of(authority) -> str:
    if not authority:
        return ""
    return str(authority).rsplit(":", 1)[0].lower()


def _rows(bus) -> list:
    status, res = bus.try_call("flow.table")
    if status != "ok" or not isinstance(res, dict):
        return []
    return res.get("flows", []) or []


def _poll_row(bus, pred, tries: int = 160, delay: float = 0.05):
    for _ in range(tries):
        for r in _rows(bus):
            if pred(r):
                return r
        time.sleep(delay)
    return None


def _wait_file(path: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    if not which("openssl"):
        skip("openssl is required to mint the TLS origin certificate")

    work = tempfile.mkdtemp(prefix="passthrough-e2e-")
    ca_dir = tempfile.mkdtemp(prefix="passthrough-e2e-ca-")
    crt, key = _mint_origin_cert(work)
    origin_der = ssl.PEM_cert_to_DER_cert(Path(crt).read_text())

    # Two loopback TLS origins sharing one cert: the passthrough origin bound where
    # `localhost` resolves (so the core's tunnel dial reaches it), and the MITM
    # contrast origin on 127.0.0.1. Distinct host NAMES ("localhost" vs "127.0.0.1")
    # let the host-keyed passthrough list cover one but not the other.
    pass_family, pass_addr = _resolve_first("localhost")
    pass_srv, pass_port = _start_tls_origin(crt, key, pass_family, pass_addr)
    mitm_srv, mitm_port = _start_tls_origin(crt, key, socket.AF_INET, "127.0.0.1")

    pass_authority = f"localhost:{pass_port}"        # on the passthrough list
    mitm_authority = f"127.0.0.1:{mitm_port}"        # NOT on the list -> MITM'd

    core = None
    bus = None
    try:
        section("boot: real aitm with localhost on the TLS passthrough list")
        cfg = PassthroughConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=["localhost", mitm_authority, "127.0.0.1"],
            ca_dir=ca_dir,
            passthrough_hosts=["localhost"],
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        proxy_port = cfg.proxy_port
        ca_path = os.path.join(ca_dir, "ca.crt")
        if not _wait_file(ca_path):
            fail("aitm did not write its CA cert; cannot run the TLS contrast")
        ok(f"proxy 127.0.0.1:{proxy_port}, bus {core.bus_addr}, ca {ca_path}")

        section("configured: the host is on the passthrough list (read over the bus)")
        listed = bus.call("tls.passthrough.list")
        hosts = listed.get("hosts", []) if isinstance(listed, dict) else []
        check("localhost" in hosts,
              f"tls.passthrough.list reports the configured host (hosts={hosts})")

        section("tunnelled: the client sees the ORIGIN's real cert, not a MITM leaf")
        sock, reply = _connect(proxy_port, pass_authority)
        check(reply.startswith("HTTP/1.1 200"),
              f"proxy accepted CONNECT for the passthrough host (reply={reply!r})")
        der, body = _tls_fetch(sock, "localhost", _accept_any_ctx())
        check(der == origin_der,
              "passthrough client completed TLS against the ORIGIN's own cert "
              "(exact DER match) — the proxy never terminated TLS")
        check(ORIGIN_MARKER.encode() in body and f'"{SECRET_PATH}"'.encode() in body,
              "the tunnelled request reached the real origin and got its own "
              f"response body (marker + path, body={body[-120:]!r})")

        section("tunnelled: a CA-only client is REJECTED by the passthrough host")
        rejected = False
        try:
            sock2, _ = _connect(proxy_port, pass_authority)
            _tls_fetch(sock2, "localhost", _ca_only_ctx(ca_path))
        except ssl.SSLError:
            rejected = True
        check(rejected,
              "a client trusting only the aitm CA cannot verify the passthrough "
              "host — it is the origin's own cert, so aitm never MITM'd it")

        section("flagged: a CONNECT row marked `tunnelled`, no decrypted flow leaked")
        marker = _poll_row(
            bus,
            lambda r: r.get("kind") == "http"
            and r.get("method") == "CONNECT"
            and "tunnelled" in (r.get("marks") or [])
            and _host_of(r.get("authority")) == "localhost",
        )
        check(marker is not None,
              f"flow.table has a CONNECT row flagged `tunnelled` for the host "
              f"(row={marker})")
        leaked = any(
            r.get("method") == "GET"
            and r.get("path") == SECRET_PATH
            and _host_of(r.get("authority")) == "localhost"
            for r in _rows(bus)
        )
        check(not leaked,
              "no decrypted request flow was captured for the passthrough host "
              "(the proxy saw only tunnelled bytes)")

        section("contrast: a non-passthrough host on the SAME proxy IS MITM'd")
        sock3, reply3 = _connect(proxy_port, mitm_authority)
        check(reply3.startswith("HTTP/1.1 200"),
              f"proxy accepted CONNECT for the MITM host (reply={reply3!r})")
        der3, body3 = _tls_fetch(sock3, "127.0.0.1", _ca_only_ctx(ca_path))
        check(der3 != origin_der,
              "MITM client saw a CA-minted leaf, NOT the origin's cert "
              "(the aitm CA signed it)")
        check(ORIGIN_MARKER.encode() in body3,
              "the MITM'd request still reached the real origin (end to end)")
        decrypted = _poll_row(
            bus,
            lambda r: r.get("method") == "GET"
            and r.get("path") == SECRET_PATH
            and _host_of(r.get("authority")) == "127.0.0.1",
        )
        check(decrypted is not None,
              "the non-passthrough host IS decrypted and captured — so the "
              "passthrough host's missing decrypted flow is meaningful")
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        pass_srv.shutdown()
        mitm_srv.shutdown()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
