#!/usr/bin/env python3
# e2e: tier=T1 surface=proto
"""TLS MITM negotiates the correct SNI and ALPN, and the captured flow records the
negotiated protocol — end to end, on ground truth at THREE independent boundaries,
never fixtures, never frozen expectations.

A real HTTP client (`curl --http2`, i.e. nghttp2) drives a real HTTPS request
THROUGH the real aitm proxy (CONNECT + TLS, the MITM path) to a real TLS origin
THIS test owns and that RECORDS, from the TLS handshake itself, the SNI it was sent
and the ALPN it negotiated (the independent observer). The proxy's ALPN "mirror"
(crates/aitm-proto-http/src/module.rs) offers the upstream exactly what the client
offered and mirrors back whatever the upstream picks, so the *same* `curl --http2`
lands on different protocols purely because the two origins advertise different
ALPN — which is the whole point:

  Case h2   — the origin offers {h2, http/1.1}; the handshake settles on h2, the
              proxy drives HTTP/2 both ways (serve_h2), and the flow is HTTP/2.
  Case h1   — the origin offers only {http/1.1}; the same client is mirrored down
              to HTTP/1.1, and the flow is HTTP/1.1.

For each case four witnesses that the tool under test does not jointly control must
agree, or the test fails:
  1. the CLIENT — curl's own `%{http_version}` (2 vs 1.1) and `%{http_code}` (200);
  2. the ORIGIN — the SNI + negotiated ALPN it recorded at TLS-handshake time, and
     the body it served (which states its own view of the negotiation);
  3. the FLOW the bus captured (`flow.detail`): scheme=https, request/response
     `version`, and BOTH `client_conn` (proxy<-client leg) and `server_conn`
     (proxy->origin leg) carrying tls=true, sni, and the negotiated alpn;
  4. the two cases DISAGREE on the protocol while sharing one client — proving the
     recorded alpn is really negotiated, not a constant.

The origin serves a genuine, if minimal, HTTP/2 connection (RFC 9113 preface +
SETTINGS, then a `:status 200` HEADERS via HPACK static index 8 and a DATA frame),
validated against nghttp2, so the h2 flow truly completes rather than erroring.

Core: the one the runner provides via env (AITM_BUS_ADDR, AITM_BUS_TOKEN,
AITM_PROXY_ADDR; optional AITM_BUS_OPERATOR_TOKEN) *when* it reports
ssl_insecure=true — a self-signed loopback origin can only be MITM'd by a core that
does not verify the upstream leaf. Otherwise this suite boots its OWN dedicated core
(free ports, ssl_insecure=true, a private store), so it always really runs rather
than skipping. Flows are found by this run's unique path marker; no global state is
touched. Binds loopback ports (incl. IPv6 ::1, where `localhost` resolves first) and
runs curl: run from a real shell, not the Claude sandbox. Exit 0 pass / 1 fail /
77 skip. The bus token is never printed.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

ENV_BUS_ADDR, ENV_BUS_TOKEN = "AITM_BUS_ADDR", "AITM_BUS_TOKEN"
ENV_OP_TOKEN, ENV_PROXY_ADDR = "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR"

# A throwaway self-signed loopback leaf (CN=localhost, SAN localhost/127.0.0.1/::1),
# valid to 2126. It is NEVER trusted by anyone: the proxy runs ssl_insecure and curl
# runs -k, so the client's trust decision is removed from what this test asserts
# (SNI/ALPN/the captured flow are observed independently of it). It only lets the
# origin terminate TLS so a real handshake — SNI + ALPN — actually happens.
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIUOBTk7dpWKgX8kIT6+I7aOfI3NzEwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAzMDIzMDQxMFoYDzIxMjYx
MDA2MjMwNDEwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC8aFLarDKaiIftRU4DxDs46bUx6oDMf3UG6CIS4+CC
pCrWZtbeOT/nqxhEIcwFgSHAEqX/C4IZiCAL6UBTcClBpMuf7O+hS2WOwxzmH4al
CLnOv0rsEFJw0b2jW1sWyJCT4qGX+IS669X6GR6a0zTpabuOFRoyYk6pu1Jwd1TU
qbDBcy7WhDi51KB2k9BdyX24TwQjWu3w1yxgZmqMvC5vDXSI8vSHkoRjHQpW+FUQ
TqYLCNc0M6KdC5N2Q4nmsF7KNvOpcE/JYPKBj8uSKjdH+bXlGmqkT7K/d64RB3Rf
WKbzrR2XJzLvX1ctC/3eNglUb0DUY4M+49YLwdYGanZ1AgMBAAGjYDBeMB0GA1Ud
DgQWBBSTlgFrMMgF7OUECnj6xwoKV79DlDAPBgNVHRMBAf8EBTADAQH/MCwGA1Ud
EQQlMCOCCWxvY2FsaG9zdIcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG
9w0BAQsFAAOCAQEAIYq8v0pvfie4UWz9Vy5TxT7UZMEQoTNL/wMmdjKS0rkcB9SR
D8ODSe79V/y0M1LXeOaYbJegCy5FojjtMUiG1EPCYsEO8hp8phUs3JVKijIxYlJ5
gO8XXD3BFxygHrQJjhW4HankSTk/+LHyJLdJbCyW5RupPhnOYhJAiYlUjCJGiDP4
x15c97QPXLq+SeGWFKM3GesJ0KmvVvqu1PK3vWxSjn5I3ZR4j+AkcWVlcZZw+1dY
HJQQHWXGNW9JLZLI4m4HfMUgJ05nkGj11aCICpFjzLqh6X4AGmkkg7kGeZnCs7A9
SBxWErvhAaOFfkV1du1/U4oxuDeQQhV1MW0wyQ==
-----END CERTIFICATE-----
"""
KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8aFLarDKaiIft
RU4DxDs46bUx6oDMf3UG6CIS4+CCpCrWZtbeOT/nqxhEIcwFgSHAEqX/C4IZiCAL
6UBTcClBpMuf7O+hS2WOwxzmH4alCLnOv0rsEFJw0b2jW1sWyJCT4qGX+IS669X6
GR6a0zTpabuOFRoyYk6pu1Jwd1TUqbDBcy7WhDi51KB2k9BdyX24TwQjWu3w1yxg
ZmqMvC5vDXSI8vSHkoRjHQpW+FUQTqYLCNc0M6KdC5N2Q4nmsF7KNvOpcE/JYPKB
j8uSKjdH+bXlGmqkT7K/d64RB3RfWKbzrR2XJzLvX1ctC/3eNglUb0DUY4M+49YL
wdYGanZ1AgMBAAECggEABY+VX8uUqXJS2Lz37YKINkjSRp6OSKWRFbAaTrEXz6NQ
JF3gBP/EPsPnsR3HliNWlK24OovjaM+CFU1AJHZQsWr6G5v0WAVlV6OzTFOCjN0c
vC5x4//N/x3MWXBOgvX5K8mU+BWnYpZSuCavpuWJpUNaps9BTlq6dFC0FopfIEZe
MIbMOYp5nEm2wkocPNc9ElR+F8Au03smqA3NdJFb2GaHprrzeWWwuCHvEZHcho4X
1fIrqufplAArQJKTRZ+B0LIR/dmUss7StYrGD1LtEWFWbscHIgLHkquD9fCm5U8v
I0KKAtxiZe9TUbYwOChStAOP10iQGMN7JYf+oOzeAQKBgQD2DpFSDlblqsPw0pAM
kC75TUQY0dazjfjL+TYBUHXRdq45Ms7rkJ8pRthoV8BMBflqcKDg/Mz1Z2lZbnES
fMWrINEz24gIBBloUqmkBKrnLIHGhI2QRmWYJucTTS0TahQ6HLi8r5G5QnrrbXW/
E2Uvb+MJ/ILLzkCttP6HpOIu9QKBgQDEBWEURy4ZNhBqSpEKN6Ms6B9gdLpehE+a
FBqNAgX9GIbAh5oxPWFzqXAxIMFw9u27Lcs6Uez8t2jjPwhwmACRqo9CQ2X63uKr
Fr+P9dTYKXGE3jeibHvqUZJrBC4WO3Ggyujqth9jk1eSY2hJVYe6Coo0Qs2yXh7p
j72useN5gQKBgQDcRmJWITwt0tgiyX3noVRMHp2t0nzwtVJb2Dg+qPcwk5yY3CFd
xVSXMTMfBh/Cbz6/ySBdCjO6Jd+sDjDvqf+TmYdvc0KuWm0cdZQkn4EX/0IWpCfP
VxYwRfNr1hVaYgbFl1zSniJIxXkhNhbI/eYBt5p7IDE/nt9MItISQMuz2QKBgDQ4
RqNzTvmSaI8YbEkvhz3oXKuCjT+uudIPNv+HoXbKeOODfHVPp817PxMnacEhVzW9
Pl28A4lThxK68RGlvMkRifaaI+nQRMxVVBUS5W/sonxGAsY3Zk+HCZ2O0IRFs8Cl
LaWRfQ027GZoKxkWOwE525WOkmPJJS0NiPeoFjSBAoGBAKdAjlpC+mE7gBbJtX6J
l5L7+Cfc7pRCrjn+ZA1LwbGVMmGc0PMeAS9uN38VALWWeWjKdfbd1xyLQgIgEGpz
X5rcjhQZDIQXSsjl3vYKrwOAZDFyK78paRbLzu+dKmsjDQFMUbdiRs6kGOUOjkDx
ebpn4UdPYBa3LlD1GgvEBCJg
-----END PRIVATE KEY-----
"""

# ---------------------------------------------------------------------------
# A minimal, real HTTP/2 server frame layer (RFC 9113), validated against nghttp2.
# Only enough to complete the h2 connection preface + one GET -> 200, so the proxy's
# h2 upstream leg (crates/aitm-proto-http/src/h2.rs) really completes and the flow is
# captured as HTTP/2 rather than erroring.
# ---------------------------------------------------------------------------
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
F_DATA, F_HEADERS, F_SETTINGS, F_PING, F_GOAWAY = 0x0, 0x1, 0x4, 0x6, 0x7
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (OSError, ssl.SSLError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _send_frame(sock, ftype, flags, sid, payload=b""):
    hdr = len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + (sid & 0x7FFFFFFF).to_bytes(4, "big")
    sock.sendall(hdr + payload)


def serve_h2_once(sock, body):
    """Read the client preface, send our SETTINGS, ACK theirs/answer PINGs, then
    answer the first client stream with `:status 200` (HPACK static index 8 => 0x88)
    plus one DATA frame carrying `body` with END_STREAM. Returns True once answered."""
    if _recv_exactly(sock, len(H2_PREFACE)) != H2_PREFACE:
        return False
    _send_frame(sock, F_SETTINGS, 0, 0)  # our server connection preface (empty SETTINGS)
    responded = False
    while True:
        hdr = _recv_exactly(sock, 9)
        if hdr is None:
            return responded
        length = int.from_bytes(hdr[0:3], "big")
        ftype, flags = hdr[3], hdr[4]
        sid = int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF
        payload = _recv_exactly(sock, length) if length else b""
        if length and payload is None:
            return responded
        if ftype == F_SETTINGS and not (flags & FLAG_ACK):
            _send_frame(sock, F_SETTINGS, FLAG_ACK, 0)
        elif ftype == F_PING and not (flags & FLAG_ACK):
            _send_frame(sock, F_PING, FLAG_ACK, 0, payload)
        elif ftype == F_HEADERS and not responded:
            _send_frame(sock, F_HEADERS, FLAG_END_HEADERS, sid, b"\x88")
            _send_frame(sock, F_DATA, FLAG_END_STREAM, sid, body)
            responded = True
        elif ftype == F_GOAWAY:
            return responded


def serve_h1_once(sock, body):
    """One HTTP/1.1 request -> a fixed 200 JSON response (Connection: close)."""
    rd = sock.makefile("rb")
    if not rd.readline():
        return False
    while True:
        line = rd.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    sock.sendall(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
        b"content-length: " + str(len(body)).encode() + b"\r\nconnection: close\r\n\r\n" + body
    )
    return True


# ---------------------------------------------------------------------------
# The independent observer: a loopback TLS origin that records the SNI + ALPN it
# negotiated at handshake time, then serves h2 or http/1.1 per that ALPN.
# ---------------------------------------------------------------------------
class TlsRecordingOrigin:
    def __init__(self, cert_path: str, key_path: str, alpn_offer: list[str]):
        self.alpn_offer = alpn_offer
        self.records: list[dict] = []   # {sni, alpn} per accepted connection (ground truth)
        self.lock = threading.Lock()
        self._sni: dict[int, str | None] = {}
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.ctx.set_alpn_protocols(alpn_offer)
        self.ctx.sni_callback = self._sni_cb
        self.port, self._socks = self._dual_bind()
        for s in self._socks:
            threading.Thread(target=self._accept, args=(s,), daemon=True).start()

    @property
    def authority(self) -> str:
        return f"localhost:{self.port}"

    def recorded(self) -> list[dict]:
        with self.lock:
            return list(self.records)

    def _sni_cb(self, sslobj, server_name, _ctx):
        with self.lock:
            self._sni[id(sslobj)] = server_name

    @staticmethod
    def _dual_bind():
        """Bind the SAME port on ::1 AND 127.0.0.1 (loopback only). `localhost`
        resolves to ::1 first on macOS, and the proxy connects to the first address,
        so the IPv6 bind is what actually gets hit; binding both stays correct
        whatever the host's resolver order is."""
        for _ in range(64):
            port = free_port()
            socks: list[socket.socket] = []
            try:
                for fam, addr in ((socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")):
                    s = socket.socket(fam, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if fam == socket.AF_INET6:
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    s.bind((addr, port))
                    s.listen(16)
                    socks.append(s)
                return port, socks
            except OSError:
                for s in socks:
                    s.close()
        raise RuntimeError("could not bind a loopback port on both ::1 and 127.0.0.1")

    def _accept(self, srv):
        while True:
            try:
                raw, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        raw.settimeout(30)
        try:
            tls = self.ctx.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        except OSError:
            raw.close()
            return
        try:
            tls.do_handshake()
        except (OSError, ssl.SSLError):
            with self.lock:
                self._sni.pop(id(tls), None)
            try:
                tls.close()
            except OSError:
                pass
            return
        with self.lock:
            sni = self._sni.pop(id(tls), None)
        alpn = tls.selected_alpn_protocol()
        with self.lock:
            self.records.append({"sni": sni, "alpn": alpn})
        # The body states the origin's own view of the negotiation, so the proxy's
        # captured response body can be tied back to this independent observer.
        body = json.dumps({"origin": "aitm-e2e-tls", "alpn": alpn, "sni": sni}).encode()
        try:
            if alpn == "h2":
                serve_h2_once(tls, body)
            else:
                serve_h1_once(tls, body)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def stop(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# a real client: curl --http2 THROUGH the proxy (CONNECT + TLS, the MITM path)
# ---------------------------------------------------------------------------
def curl_has_http2() -> bool:
    try:
        out = subprocess.run(["curl", "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0 and "HTTP2" in out.stdout


def curl_via_proxy(proxy_host: str, proxy_port: int, upstream_port: int, path: str):
    """GET https://localhost:<upstream_port><path> via the aitm proxy, offering ALPN
    {h2,http/1.1} (--http2). Returns (rc, body, http_version, http_code, stderr).
    -k removes curl's own trust decision from the assertions (SNI/ALPN/flow are
    observed independently); SNI is still sent because the host is a name."""
    cmd = [
        "curl", "-sS", "-k", "--http2", "--max-time", "30",
        "-x", f"http://{proxy_host}:{proxy_port}",
        f"https://localhost:{upstream_port}{path}",
        "-w", "\n%{http_version} %{http_code}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    body, _, wline = r.stdout.rpartition("\n")
    version, _, code = wline.strip().partition(" ")
    return r.returncode, body, version, code.strip(), r.stderr


# ---------------------------------------------------------------------------
# the core under test: the runner's (if ssl_insecure) or a dedicated one we boot
# ---------------------------------------------------------------------------
def _hostport(addr: str):
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"malformed host:port {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


def _attached_core():
    addr, tok, proxy = (os.environ.get(k) for k in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR))
    if not (addr and tok and proxy):
        return None
    host, port = _hostport(addr)
    phost, pport = _hostport(proxy)
    cfg = SimpleNamespace(agent_token=tok, operator_token=os.environ.get(ENV_OP_TOKEN) or None,
                          proxy_port=pport)
    return SimpleNamespace(bus_addr=(host, port), cfg=cfg, proxy_host=phost,
                           stop=lambda: None)


def _core_is_insecure(core) -> bool:
    """True iff the core reports ssl_insecure=true — the precondition for MITMing a
    self-signed loopback origin (otherwise the upstream leaf fails verification)."""
    b = None
    try:
        b = BusClient.agent(core)
        doc = b.call("config.get")
        return isinstance(doc, dict) and doc.get("ssl_insecure") is True
    except Exception:  # noqa: BLE001
        return False
    finally:
        if b is not None:
            b.close()


def obtain_core():
    """(core, booted, ca_tmp). Attach to the runner's core only when it can MITM a
    self-signed upstream (ssl_insecure); otherwise boot our own so the suite always
    exercises the feature rather than skipping."""
    attached = _attached_core()
    if attached is not None and _core_is_insecure(attached):
        return attached, False, None
    ca_tmp = tempfile.mkdtemp(prefix="aitm-e2e-tls-ca-")
    ca_dir = os.path.join(ca_tmp, "ca")
    # ssl_insecure + the per-run ca dir are first-class CoreConfig fields now (the base
    # to_yaml emits them); set them directly rather than appending, which used to
    # duplicate the `ca` / `ssl_insecure` keys once the base started emitting them and
    # made the core refuse to start ("duplicate field `ca`").
    cfg = CoreConfig(proxy_port=free_port(), browser_proxy_port=free_port(),
                     scope_entries=["localhost", "127.0.0.1"],
                     ssl_insecure=True, ca_dir=ca_dir)
    core = Aitm.server(cfg)
    core.proxy_host = "127.0.0.1"
    return core, True, ca_tmp


# ---------------------------------------------------------------------------
# bus ground truth
# ---------------------------------------------------------------------------
def wait_flow_id(bus, marker: str, timeout: float = 20.0) -> str:
    """The id of the completed (status 200) HTTP flow whose path carries `marker`."""
    deadline = time.time() + timeout
    while True:
        rows = bus.call("flow.table").get("flows") or []
        for row in rows:
            if (row.get("kind") == "http" and marker in (row.get("path") or "")
                    and row.get("status") == 200):
                return row["id"]
        if time.time() > deadline:
            seen = [f"{r.get('method')} {r.get('authority')}{r.get('path')} -> {r.get('status')}"
                    for r in rows[-8:]]
            fail(f"no completed HTTP flow carrying {marker!r} within {timeout}s; last rows: {seen}")
        time.sleep(0.15)


def conn_view(detail: dict, side: str) -> dict:
    c = detail.get(side)
    return c if isinstance(c, dict) else {}


def body_json(detail: dict, section_key: str):
    obj = detail.get(section_key) or {}
    data = obj.get("body")
    if not isinstance(data, str) or not data:
        return None
    try:
        return json.loads(base64.b64decode(data))
    except (ValueError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
def main() -> int:
    if not curl_has_http2():
        skip("curl with HTTP2 support is required (the real h2 client); not found")

    certdir = tempfile.mkdtemp(prefix="aitm-e2e-tls-cert-")
    cert_path = os.path.join(certdir, "cert.pem")
    key_path = os.path.join(certdir, "key.pem")
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(CERT_PEM)
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(KEY_PEM)
    os.chmod(key_path, 0o600)

    run = uuid.uuid4().hex[:10]
    # The ALPN "mirror" means the SAME client offer resolves differently per origin:
    cases = [
        {"label": "h2", "offer": ["h2", "http/1.1"], "want_alpn": "h2",
         "want_version": "HTTP/2", "want_http_version": "2"},
        {"label": "h1", "offer": ["http/1.1"], "want_alpn": "http/1.1",
         "want_version": "HTTP/1.1", "want_http_version": "1.1"},
    ]

    origins: list[TlsRecordingOrigin] = []
    core = None
    booted = False
    ca_tmp = None
    bus = None
    try:
        section("arrange: real TLS origins (recording SNI+ALPN) + a real MITM-capable core")
        for c in cases:
            c["origin"] = TlsRecordingOrigin(cert_path, key_path, c["offer"])
            origins.append(c["origin"])
            ok(f"origin[{c['label']}] on {c['origin'].authority} offering ALPN {c['offer']}")
        core, booted, ca_tmp = obtain_core()
        proxy_host = getattr(core, "proxy_host", "127.0.0.1")
        proxy_port = core.cfg.proxy_port
        if booted:
            ok(f"booted a dedicated core (ssl_insecure): proxy {proxy_host}:{proxy_port}, bus {core.bus_addr}")
        else:
            ok(f"attached to the runner's core (ssl_insecure=true): proxy {proxy_host}:{proxy_port}")
        bus = BusClient.agent(core)
        for need in ("flow.table", "flow.detail"):
            check(need in set(bus.tool_names()), f"the core exposes {need}")

        for c in cases:
            label, origin = c["label"], c["origin"]
            want_alpn = c["want_alpn"]
            want_version = c["want_version"]
            marker = f"/tls-{label}-{run}"
            section(f"case {label}: curl --http2 through the proxy to an ALPN-{c['offer']} origin")

            rc, cbody, http_version, http_code, cerr = curl_via_proxy(
                proxy_host, proxy_port, origin.port, marker)
            check(rc == 0, f"[{label}] curl through the proxy succeeded (rc={rc}; stderr={cerr.strip()[:200]!r})")

            # ---- witness 1: the CLIENT (curl's own negotiated protocol + status) ----
            check(http_code == "200",
                  f"[{label}] client sees HTTP 200 (got {http_code!r})")
            check(http_version == c["want_http_version"],
                  f"[{label}] client negotiated HTTP/{c['want_http_version']} "
                  f"(curl %{{http_version}}={http_version!r})")
            try:
                client_doc = json.loads(cbody)
            except ValueError:
                client_doc = None
            check(isinstance(client_doc, dict) and client_doc.get("alpn") == want_alpn,
                  f"[{label}] the body the client received is the origin's, self-reporting alpn={want_alpn!r} "
                  f"(got {client_doc!r})")

            # ---- witness 2: the ORIGIN (SNI + ALPN it recorded at handshake time) ----
            deadline = time.time() + 10.0
            rec = None
            while time.time() < deadline:
                for r in origin.recorded():
                    if r.get("alpn") == want_alpn:
                        rec = r
                        break
                if rec:
                    break
                time.sleep(0.1)
            check(rec is not None,
                  f"[{label}] the origin recorded a TLS handshake negotiating ALPN {want_alpn!r} "
                  f"(records={origin.recorded()})")
            check(rec is not None and rec.get("sni") == "localhost",
                  f"[{label}] the origin was sent SNI 'localhost' by the proxy (got {(rec or {}).get('sni')!r})")

            # ---- witness 3: the captured FLOW (flow.detail over the bus) ----
            fid = wait_flow_id(bus, marker)
            detail = bus.call("flow.detail", {"id": fid, "body": "inline"})
            check(isinstance(detail, dict) and detail.get("kind") == "http",
                  f"[{label}] flow.detail returns the HTTP flow {fid}")
            req = detail.get("request") or {}
            resp = detail.get("response") or {}
            check(req.get("scheme") == "https",
                  f"[{label}] flow records scheme=https (TLS MITM), got {req.get('scheme')!r}")
            check(req.get("authority") == origin.authority,
                  f"[{label}] flow authority is the origin {origin.authority} (got {req.get('authority')!r})")
            check(req.get("version") == want_version,
                  f"[{label}] flow REQUEST version is {want_version} (got {req.get('version')!r})")
            check(resp.get("status") == 200 and resp.get("version") == want_version,
                  f"[{label}] flow RESPONSE is 200 / {want_version} (got {resp.get('status')!r} "
                  f"/ {resp.get('version')!r})")

            cc = conn_view(detail, "client_conn")
            sc = conn_view(detail, "server_conn")
            check(cc.get("tls") is True and sc.get("tls") is True,
                  f"[{label}] both legs are TLS (client_conn.tls={cc.get('tls')!r}, "
                  f"server_conn.tls={sc.get('tls')!r})")
            check(cc.get("alpn") == want_alpn,
                  f"[{label}] client_conn.alpn (proxy<-client leg) == {want_alpn!r} (got {cc.get('alpn')!r})")
            check(sc.get("alpn") == want_alpn,
                  f"[{label}] server_conn.alpn (proxy->origin leg) == {want_alpn!r} (got {sc.get('alpn')!r})")
            check(cc.get("sni") == "localhost",
                  f"[{label}] client_conn.sni == 'localhost' (the client's ClientHello SNI; got {cc.get('sni')!r})")
            check(sc.get("sni") == "localhost",
                  f"[{label}] server_conn.sni == 'localhost' (the SNI the proxy sent upstream; got {sc.get('sni')!r})")
            flow_doc = body_json(detail, "response")
            check(isinstance(flow_doc, dict) and flow_doc.get("alpn") == want_alpn,
                  f"[{label}] the flow's captured response body is the origin's, alpn={want_alpn!r} "
                  f"(got {flow_doc!r})")

            # ---- witness 4 (per case): the four views agree on the negotiated ALPN ----
            check(rec is not None
                  and rec.get("alpn") == cc.get("alpn") == sc.get("alpn")
                  == (client_doc or {}).get("alpn") == (flow_doc or {}).get("alpn") == want_alpn,
                  f"[{label}] origin, client_conn, server_conn, client body and flow body ALL agree "
                  f"the negotiated ALPN is {want_alpn!r}")
            c["flow_version"] = req.get("version")
            c["flow_alpn"] = sc.get("alpn")

        # ---- witness 4 (across cases): one client, two outcomes -> it's negotiated ----
        section("mirror: the SAME client offer, two origins, two protocols -> ALPN is really negotiated")
        h2c, h1c = cases[0], cases[1]
        check(h2c["flow_alpn"] == "h2" and h1c["flow_alpn"] == "http/1.1"
              and h2c["flow_version"] == "HTTP/2" and h1c["flow_version"] == "HTTP/1.1",
              f"the only difference was the origins' ALPN offer, yet the flows recorded "
              f"{h2c['flow_version']}/{h2c['flow_alpn']} vs {h1c['flow_version']}/{h1c['flow_alpn']} — "
              f"the recorded protocol tracks the real negotiation, not a constant")
    finally:
        if bus is not None:
            bus.close()
        if core is not None and booted:
            core.stop()
        for o in origins:
            o.stop()
        shutil.rmtree(certdir, ignore_errors=True)
        if ca_tmp:
            shutil.rmtree(ca_tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
