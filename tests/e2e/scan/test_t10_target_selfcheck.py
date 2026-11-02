#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=http
"""The seeded target is the proving ground it claims to be (T10 spec S2, S5, S6;
parent AC T10-1), observed on the target's OWN control log and on curl's own
negotiated HTTP version. No core, no `scan.*` verb: this cell PASSes on a build
without the scanner engine (its ledger file is `calls: []`).

What it proves, Vulnerable (V) next to Patched (P), both booted with `--l4`:
  - the five D1 stdout lines were parsed (`base`, `tls_base`, `tls_h1_base`,
    `control`) and `/services` lists the fifteen D2 names with the D5 grammars
  - TLS ALPN: `curl --http2` on the TLS listener negotiates `2`, `--http1.1`
    negotiates `1.1`, the h1-only listener negotiates `1.1` under `--http2`; the
    control log then holds `tls_handshake` entries with those ALPNs and `request`
    entries with `version` h2/h1 and `conn_req_index == 1`
  - one seed per D3 class, then EVERY remaining D3 row (the `SEEDS` table, 21 rows
    plus the stored-XSS round trip), answers on V with the row's literal signal
    and on P with the row's patched answer; the timing rows (`SLEEP(2)`,
    `;sleep 2`) take >= 2 s on V and < 1 s on P
  - S3: five `curl --http2` requests in one invocation ride ONE h2 connection: one
    `/log/conns` row on `tls` with `alpn h2` and `requests == 5`, and the five
    `request` entries carry `conn_req_index` 1..5 on that `conn_id`
  - S4 `/ws` (raw RFC 6455 client, no proxy): V upgrades a foreign `Origin` (101,
    hello `anonymous`) and echoes `<i>` raw; after `POST /login` the hello is
    `alice`; a header declaring 1 048 577 bytes is closed with 1009 and logged; P
    answers 403 to the foreign `Origin`, 401 without a session, and with the
    session cookie upgrades (hello `alice`) and escapes `<i>`; `/log/ws` holds each
    handshake under the client's own `Sec-WebSocket-Key` with `cookie_names`
  - all nine D5 speakers (the `SPEAKERS` table, bytes mirrored from the crate's
    `speakers_live.rs`): on V the trigger closes with no bytes (UDP: no reply), the
    service is refused / silent within 2 s, still down at +4 s, answers liveness
    again by +6 s and logs exactly one `downtime` row with
    `up_at_ms - down_at_ms == 5000`; on P the same trigger gets the row's reply
    (MQTT: a bare close) and the service never goes down; the nine V windows run
    concurrently so the whole cell stays under ~25 s
  - S6: `/manifest`, `/manifest.yaml` and `/<seed id>` for all 28 manifest ids are
    404 on the target AND on the control origin (the manifest is never served)
  - the control log never stores a `cookie` key or the session value; a request
    carrying `session=` logs `cookie_names == ["session"]` + a 16-hex hash

SKIPs 77 only when `aitm-testtarget-serve` or an HTTP/2-capable `curl` is missing.
Binds loopback ports: run from a real shell, not the Claude sandbox. Exit 0 pass /
1 fail / 77 skip. This cell handles no token.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.scan import ScanTarget, boot_target, split_addr, until  # noqa: E402
from aitm_e2e.tls import curl, curl_http_version, have  # noqa: E402
from aitm_e2e.ws import ws_encode, ws_read_frame  # noqa: E402

RUN = secrets.token_hex(4)
MARK = f"<t-{RUN}>"                      # a raw-vs-escaped reflection marker
MARK_ESC = f"&lt;t-{RUN}&gt;"
SESSION_RE = re.compile(r"^session=([0-9a-f]{32});")
HEX16_RE = re.compile(r"^[0-9a-f]{16}$")

# D2 `/services` names (4 HTTP/control + the nine D5 speakers + the legacy two)
# and the D5 grammar of each L4 row (`None` = HTTP/control row or legacy, no grammar).
EXPECTED_SERVICES: dict[str, str | None] = {
    "http": None, "tls": None, "tls_h1": None, "control": None,
    "l4-tlv-crash": "tlv", "l4-dns-fault": "dns", "l4-udp-payload-crash": "raw",
    "l4-resp": "resp", "l4-memcached": "memcached", "l4-modbus": "modbus",
    "l4-mqtt": "mqtt", "l4-smtp": "smtp", "l4-ftp": "ftp",
    "l4-udp-echo": None, "l4-tcp-service": None,
}
EXPECTED_ALPN = {"http": ["http/1.1"], "tls": ["h2", "http/1.1"], "tls_h1": ["http/1.1"]}

# Every manifest id (crates/aitm-testtarget/src/manifest.rs: the 25 `seed_index()`
# routes + the three passive rows). S6: `/<id>` is 404 on both origins -- the
# cell cannot read the never-served manifest, so the list is pinned here.
MANIFEST_IDS = (
    "reflected-xss-search-q", "stored-xss-comments", "ssrf-fetch-preview", "idor-account",
    "auth-bypass-admin-role", "open-redirect-next", "sqli-error-products-id",
    "sqli-boolean-items-id", "sqli-time-orders-id", "cmdi-ping-host", "ssti-greet-name",
    "traversal-static-file", "xxe-order-name", "crlf-lang-set", "nosqli-json-login",
    "ldapi-ldap-user", "header-reflection-whoami", "cookie-reflection-prefs",
    "nested-json-reflection-profile", "multipart-reflection-upload", "path-segment-docs-slug",
    "path-filename-files", "auth-only-account-tab", "ws-cswsh", "ws-input-reflection",
    "missing-hsts", "missing-csp", "missing-nosniff",
)
assert len(MANIFEST_IDS) == 28

# S4 / D4 literals (child spec; mirrored from crates/aitm-testtarget/tests/scan_http.rs).
WS_HELLO_ANON = '{"type":"hello","user":"anonymous"}'
WS_HELLO_ALICE = '{"type":"hello","user":"alice"}'
WS_ECHO_REQ = '{"type":"echo","msg":"<i>"}'
WS_ECHO_V = '{"type":"echo","msg":"<i>","html":"<b><i></b>"}'
WS_ECHO_P = '{"type":"echo","msg":"&lt;i&gt;","html":"<b>&lt;i&gt;</b>"}'
WS_MAX_FRAME = 1_048_576
FOREIGN_ORIGIN = "http://evil.example"

CRASH_WINDOW_MS = 5000
LONG_LINE = b"a" * 4096 + b"\r\n"        # past every line cap (1024 / 2048)
MQTT_CONNECT = bytes.fromhex("100c00044d5154540402003c0000")
MQTT_CONNACK = bytes.fromhex("20020000")
MQTT_DISCONNECT = bytes.fromhex("e000")
DNS_QUERY = bytes.fromhex("123401000001000000000000076578616d706c65047465737400000100 01".replace(" ", ""))
DNS_ANSWER = bytes.fromhex("123481800001000100000000076578616d706c6504746573740000010001c00c000100010000003c00047f000001")
DNS_ROOT_QUERY = bytes.fromhex("0001010000010000000000000000010001")
DNS_ROOT_ANSWER = bytes.fromhex("0001818000010001000000000000010001c00c000100010000003c00047f000001")
MODBUS_READ = bytes.fromhex("000100000006010300000001")
MODBUS_REPLY = bytes.fromhex("0001000000050103020000")

# The nine D5 speakers, bytes copied from `crates/aitm-testtarget/tests/speakers_live.rs`
# `cases()`: benign and liveness exchanges, the Vulnerable trigger, and the Patched
# reply to that trigger (`None`: the protocol has no error reply, the speaker just
# closes). `banner`: what the speaker writes first on connect.
SPEAKERS = (
    dict(service="l4-tlv-crash", proto="tcp", banner=b"",
         benign=bytes.fromhex("0003616263"), benign_expect=bytes.fromhex("0003616263"),
         liveness=bytes.fromhex("0000"), liveness_expect=bytes.fromhex("0000"),
         trigger=bytes.fromhex("ffff"), p_reply=bytes.fromhex("0003455252")),
    dict(service="l4-dns-fault", proto="udp", banner=b"",
         benign=DNS_QUERY, benign_expect=DNS_ANSWER,
         liveness=DNS_ROOT_QUERY, liveness_expect=DNS_ROOT_ANSWER,
         trigger=bytes.fromhex("1234010000010000000000003f6162"),
         p_reply=bytes.fromhex("123481810000000000000000")),
    dict(service="l4-udp-payload-crash", proto="udp", banner=b"",
         benign=b"abc", benign_expect=b"abc", liveness=b"abc", liveness_expect=b"abc",
         trigger=bytes.fromhex("deadbeef00000000"), p_reply=bytes.fromhex("deadbeef00000000")),
    dict(service="l4-resp", proto="tcp", banner=b"",
         benign=b"*1\r\n$4\r\nPING\r\n", benign_expect=b"+PONG\r\n",
         liveness=b"PING\r\n", liveness_expect=b"+PONG\r\n",
         trigger=b"*1\r\n$2000000\r\n", p_reply=b"-ERR Protocol error: invalid bulk length\r\n"),
    dict(service="l4-memcached", proto="tcp", banner=b"",
         benign=b"version\r\n", benign_expect=b"VERSION 1.6.0-aitm\r\n",
         liveness=b"version\r\n", liveness_expect=b"VERSION 1.6.0-aitm\r\n",
         trigger=LONG_LINE, p_reply=b"CLIENT_ERROR line too long\r\n"),
    dict(service="l4-modbus", proto="tcp", banner=b"",
         benign=MODBUS_READ, benign_expect=MODBUS_REPLY,
         liveness=MODBUS_READ, liveness_expect=MODBUS_REPLY,
         trigger=bytes.fromhex("000300000105010300000001"), p_reply=bytes.fromhex("000300000003018303")),
    dict(service="l4-mqtt", proto="tcp", banner=b"",
         benign=MQTT_CONNECT, benign_expect=MQTT_CONNACK,
         liveness=MQTT_CONNECT + MQTT_DISCONNECT, liveness_expect=MQTT_CONNACK,
         trigger=bytes.fromhex("30ffffffff7f"), p_reply=None),
    dict(service="l4-smtp", proto="tcp", banner=b"220 target.test ESMTP aitm\r\n",
         benign=b"EHLO x\r\n", benign_expect=b"250 target.test\r\n",
         liveness=b"NOOP\r\n", liveness_expect=b"250 OK\r\n",
         trigger=LONG_LINE, p_reply=b"500 line too long\r\n"),
    dict(service="l4-ftp", proto="tcp", banner=b"220 aitm ftp\r\n",
         benign=b"USER a\r\n", benign_expect=b"331 password required\r\n",
         liveness=b"NOOP\r\n", liveness_expect=b"200 ok\r\n",
         trigger=LONG_LINE, p_reply=b"500 line too long\r\n"),
)


# ---------------------------------------------------------------------------
# a plain HTTP/1.1 client that never follows redirects and returns the headers
# ---------------------------------------------------------------------------
def http1(base: str, method: str, path: str, headers: dict | None = None,
          body: bytes | None = None, timeout: float = 10.0):
    """(status, [(lower-name, value)...], body) for one request to `base` (http://host:port)."""
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, [(k.lower(), v) for k, v in resp.getheaders()], data
    finally:
        conn.close()


def header(headers: list, name: str) -> str | None:
    for k, v in headers:
        if k == name:
            return v
    return None


def text(body: bytes) -> str:
    return body.decode("utf-8", "replace")


def addr_of(target: ScanTarget, name: str) -> tuple[str, int]:
    return split_addr(str(target.service(name)["addr"]))


# ---------------------------------------------------------------------------
# L4 speaker primitives (raw sockets; the speaker's own bytes are the oracle)
# ---------------------------------------------------------------------------
def recv_exact(sock, want: int) -> bytes:
    """Read `want` bytes or until EOF / the socket timeout."""
    got = b""
    try:
        while len(got) < want:
            chunk = sock.recv(want - len(got))
            if not chunk:
                break
            got += chunk
    except socket.timeout:
        pass
    return got


def tcp_open(addr: tuple[str, int], banner: bytes, timeout: float):
    s = socket.create_connection(addr, timeout=timeout)
    s.settimeout(timeout)
    if banner:
        got = recv_exact(s, len(banner))
        if got != banner:
            s.close()
            raise AssertionError(f"banner {got!r} != {banner!r}")
    return s


def udp_exchange(addr: tuple[str, int], payload: bytes, timeout: float = 0.5) -> bytes | None:
    """One datagram out, the first datagram back (None when nothing answers in `timeout`)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, addr)
        try:
            return s.recvfrom(65535)[0]
        except socket.timeout:
            return None


def exchange(row: dict, addr: tuple[str, int], payload: bytes, want: int, timeout: float = 3.0) -> bytes | None:
    """Connect (TCP) or send (UDP), write `payload`, read `want` bytes back."""
    if row["proto"] == "udp":
        return udp_exchange(addr, payload, timeout=min(timeout, 1.0))
    with tcp_open(addr, row["banner"], timeout) as s:
        s.sendall(payload)
        return recv_exact(s, want)


def tcp_trigger(row: dict, addr: tuple[str, int], timeout: float = 3.0) -> tuple[bytes, bool]:
    """Send the trigger on a fresh connection; (bytes read back before EOF, saw_eof)."""
    with tcp_open(addr, row["banner"], timeout) as s:
        s.sendall(row["trigger"])
        got = b""
        eof = False
        try:
            while len(got) < 256:
                chunk = s.recv(256 - len(got))
                if not chunk:
                    eof = True
                    break
                got += chunk
        except socket.timeout:
            pass
        return got, eof


def is_down(row: dict, addr: tuple[str, int]) -> bool:
    """TCP: the connect is refused. UDP: the liveness datagram goes unanswered."""
    if row["proto"] == "udp":
        return udp_exchange(addr, row["liveness"]) is None
    return connect_refused(addr)


def wait_liveness(row: dict, addr: tuple[str, int], until_t: float) -> bool:
    """Poll the liveness exchange until it answers the row's bytes or `until_t` (monotonic) passes."""
    while time.monotonic() < until_t:
        try:
            if exchange(row, addr, row["liveness"], len(row["liveness_expect"]), timeout=1.0) == row["liveness_expect"]:
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def connect_refused(addr: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(addr, timeout=1.0):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def wait_down(row: dict, addr: tuple[str, int], within: float) -> float | None:
    """Seconds until the service is first seen down, or None if it stayed up for `within`."""
    t0 = time.monotonic()
    if until(lambda: is_down(row, addr), within, interval=0.02):
        return time.monotonic() - t0
    return None


# ---------------------------------------------------------------------------
def curl_supports_h2() -> bool:
    try:
        p = subprocess.run(["curl", "-V"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "HTTP2" in p.stdout


def boot(mode: str) -> ScanTarget:
    return boot_target(mode, l4=True)


# ---------------------------------------------------------------------------
def check_process_shape(t: ScanTarget) -> None:
    m = t.mode
    check(bool(t.base) and t.base.startswith("http://127.0.0.1:"),
          f"{m}: `listening` line parsed -> base {t.base}")
    check(bool(t.tls_base) and t.tls_base.startswith("https://127.0.0.1:"),
          f"{m}: `tls` line parsed -> tls_base {t.tls_base}")
    check(bool(t.tls_h1_base) and t.tls_h1_base.startswith("https://127.0.0.1:"),
          f"{m}: `tls_h1` line parsed -> tls_h1_base {t.tls_h1_base}")
    check(bool(t.control) and t.control.startswith("http://127.0.0.1:"),
          f"{m}: `control` line parsed -> control {t.control}")
    check(len({t.base, t.tls_base, t.tls_h1_base, t.control}) == 4,
          f"{m}: the four listeners are four distinct ports")
    rows = t.services()
    by_name = {r.get("name"): r for r in rows}
    check(set(by_name) == set(EXPECTED_SERVICES),
          f"{m}: /services names == the fifteen D2 names (got {sorted(by_name)})")
    grammars = {n: r.get("grammar") for n, r in by_name.items()}
    check(grammars == EXPECTED_SERVICES,
          f"{m}: /services grammars match D5 (got {grammars})")
    roles = {n: r.get("role") for n, r in by_name.items()}
    want_roles = {n: ("control" if n == "control" else "http" if n in ("http", "tls", "tls_h1") else "l4")
                  for n in EXPECTED_SERVICES}
    check(roles == want_roles, f"{m}: /services roles are http|control|l4 per D2 (got {roles})")
    alpns = {n: by_name[n].get("alpn") for n in EXPECTED_ALPN}
    check(alpns == EXPECTED_ALPN, f"{m}: /services ALPN lists per D1 (got {alpns})")
    check(all(str(r.get("addr", "")).startswith("127.0.0.1:") for r in rows),
          f"{m}: every service binds 127.0.0.1")
    check(by_name["http"]["addr"] == t.authority and by_name["tls"]["addr"] == t.tls_authority
          and by_name["tls_h1"]["addr"] == t.tls_h1_authority,
          f"{m}: /services http/tls/tls_h1 addrs equal the stdout authorities")


def check_alpn(t: ScanTarget) -> None:
    m = t.mode
    seq0 = t.logs.reset()
    for args, url, want in (
        (["-k", "--http2"], t.tls_base + "/", "2"),
        (["-k", "--http1.1"], t.tls_base + "/", "1.1"),
        (["-k", "--http2"], t.tls_h1_base + "/", "1.1"),
    ):
        rc, ver, err = curl_http_version([*args, url])
        check(rc == 0 and ver == want,
              f"{m}: curl {' '.join(args)} {url} negotiated HTTP {ver!r} "
              f"(want {want!r}; rc={rc} {err.strip()[:120]})")
    # The target writes its log entries after the bytes left its socket: wait for the
    # three handshakes instead of sleeping a fixed 200 ms.
    until(lambda: len([e for e in t.logs.http()
                       if int(e.get("seq", 0)) > seq0 and e.get("kind") == "tls_handshake"]) >= 3, 3.0)
    entries = [e for e in t.logs.http() if int(e.get("seq", 0)) > seq0]
    hs_tls = sorted(e.get("alpn") for e in entries
                    if e.get("kind") == "tls_handshake" and e.get("listener") == "tls")
    hs_h1 = [e.get("alpn") for e in entries
             if e.get("kind") == "tls_handshake" and e.get("listener") == "tls_h1"]
    check(hs_tls == ["h2", "http/1.1"],
          f"{m}: /log/http tls_handshake on `tls` has alpn h2 + http/1.1 (got {hs_tls})")
    check(hs_h1 == ["http/1.1"],
          f"{m}: /log/http tls_handshake on `tls_h1` has alpn http/1.1 (got {hs_h1})")
    reqs = [e for e in entries if e.get("kind") == "request" and e.get("path") == "/"]
    seen = sorted((e.get("listener"), e.get("version")) for e in reqs)
    check(seen == [("tls", "h1"), ("tls", "h2"), ("tls_h1", "h1")],
          f"{m}: /log/http request versions per listener are tls:h2, tls:h1, tls_h1:h1 (got {seen})")
    check(bool(reqs) and all(e.get("conn_req_index") == 1 for e in reqs),
          f"{m}: every curl request is conn_req_index 1 on its own connection "
          f"(got {[e.get('conn_req_index') for e in reqs]})")
    check(len({e.get("conn_id") for e in reqs}) == 3,
          f"{m}: the three requests arrived on three distinct connections")


def do_login(base: str) -> str | None:
    """POST the fixture credentials; return the 32-hex session value or None."""
    status, h, _ = http1(base, "POST", "/login",
                         headers={"content-type": "application/x-www-form-urlencoded"},
                         body=b"user=alice&pass=wonderland")
    sc = header(h, "set-cookie") or ""
    m = SESSION_RE.match(sc)
    # Never print the cookie value: only the status and the attribute names.
    shape = ("session=<32 hex>" if m else "no session= match") + "".join(
        "; " + a.strip().split("=", 1)[0] for a in sc.split(";")[1:] if a.strip())
    check(status == 302 and m is not None,
          f"login: POST /login mints a 32-hex session cookie (status {status}, set-cookie shape {shape!r})")
    return m.group(1) if m else None


def check_seeds(v: ScanTarget, p: ScanTarget) -> None:
    """One seed per D3 class, V's literal signal beside P's patched answer."""
    nosqli_marker = "NOSQLI-LOGIN-MARKER-4b1d"
    traversal_marker = "root:x:0:0"

    section("ssti `/greet?name={{7*7}}`: V evaluates, P reflects the raw template")
    sv, _, bv = http1(v.base, "GET", "/greet?name=%7B%7B7*7%7D%7D")
    sp, _, bp = http1(p.base, "GET", "/greet?name=%7B%7B7*7%7D%7D")
    check(sv == 200 and text(bv) == "<h1>Hello 49</h1>", f"V: <h1>Hello 49</h1> (got {sv} {text(bv)!r})")
    check(sp == 200 and text(bp) == "<h1>Hello {{7*7}}</h1>",
          f"P: raw, never evaluated (got {sp} {text(bp)!r})")

    section("sqli `/products?id=1'`: V leaks `SQL syntax error near`, P answers 400 `invalid id`")
    sv, _, bv = http1(v.base, "GET", "/products?id=1%27")
    sp, _, bp = http1(p.base, "GET", "/products?id=1%27")
    check(sv == 500 and "SQL syntax error near" in text(bv), f"V: 500 + SQL error (got {sv} {text(bv)!r})")
    check(sp == 400 and text(bp) == "invalid id", f"P: 400 `invalid id` (got {sp} {text(bp)!r})")

    section("crlf `/lang?set=en%0d%0aX-Injected:%201`: V grows an `x-injected` header, P does not")
    sv, hv, _ = http1(v.base, "GET", "/lang?set=en%0d%0aX-Injected:%201")
    sp, hp, _ = http1(p.base, "GET", "/lang?set=en%0d%0aX-Injected:%201")
    check(sv == 200 and header(hv, "x-injected") == "1",
          f"V: x-injected: 1 present (got {sv} {header(hv, 'x-injected')!r})")
    check(sp == 200 and header(hp, "x-injected") is None,
          f"P: no x-injected header (got {sp} {header(hp, 'x-injected')!r})")

    section("nosqli `POST /api/login` with `{\"$ne\":\"\"}`: V returns the marker, P rejects the non-string")
    body = json.dumps({"username": "alice", "password": {"$ne": ""}}).encode()
    sv, _, bv = http1(v.base, "POST", "/api/login", headers={"content-type": "application/json"}, body=body)
    sp, _, bp = http1(p.base, "POST", "/api/login", headers={"content-type": "application/json"}, body=body)
    check(sv == 200 and nosqli_marker in text(bv), f"V: 200 + {nosqli_marker} (got {sv} {text(bv)!r})")
    check(sp == 400 and text(bp) == '{"error":"password must be a string"}',
          f"P: 400 password-must-be-a-string (got {sp} {text(bp)!r})")

    section("path-traversal `/static?file=../../etc/passwd`: V serves /etc/passwd, P answers 400")
    sv, hdrv, bv = http1(v.base, "GET", "/static?file=../../etc/passwd")
    sp, _, bp = http1(p.base, "GET", "/static?file=../../etc/passwd")
    check(sv == 200 and traversal_marker in text(bv) and (header(hdrv, "content-type") or "").startswith("text/plain"),
          f"V: 200 text/plain + {traversal_marker} (got {sv} {header(hdrv, 'content-type')!r} {text(bv)!r})")
    check(sp == 400, f"P: 400, no file served (got {sp} {text(bp)!r})")

    section("header-reflection `/whoami` User-Agent + X-Forwarded-For: V reflects raw, P escapes")
    hdrs = {"user-agent": MARK, "x-forwarded-for": MARK}
    sv, _, bv = http1(v.base, "GET", "/whoami", headers=hdrs)
    sp, _, bp = http1(p.base, "GET", "/whoami", headers=hdrs)
    check(sv == 200 and f"<p>agent: {MARK}</p><p>from: {MARK}</p>" in text(bv),
          f"V: raw User-Agent and X-Forwarded-For reflected (got {text(bv)!r})")
    check(sp == 200 and text(bp).count(MARK_ESC) == 2 and MARK not in text(bp),
          f"P: both headers HTML-escaped (got {text(bp)!r})")

    section("session gate `/account?tab=`: reachable only with the login cookie; V raw, P escapes")
    tab = urllib.parse.quote(MARK, safe="")
    sv_nocookie, hv_nc, _ = http1(v.base, "GET", f"/account?tab={tab}")
    check(sv_nocookie == 302 and (header(hv_nc, "location") or "") == "/login",
          f"no cookie -> 302 /login (got {sv_nocookie} {header(hv_nc, 'location')!r})")
    v_cookie = do_login(v.base)
    p_cookie = do_login(p.base)
    sv, _, bv = http1(v.base, "GET", f"/account?tab={tab}", headers={"cookie": f"session={v_cookie}"})
    sp, _, bp = http1(p.base, "GET", f"/account?tab={tab}", headers={"cookie": f"session={p_cookie}"})
    check(sv == 200 and f"<h2>Account: {MARK}</h2>" == text(bv),
          f"V: authenticated reflection is raw (got {sv} {text(bv)!r})")
    check(sp == 200 and MARK_ESC in text(bp) and MARK not in text(bp),
          f"P: authenticated reflection is escaped (got {sp} {text(bp)!r})")

    section("passive headers on `/`: P adds HSTS/CSP/nosniff, V has none")
    _, hv, _ = http1(v.base, "GET", "/")
    _, hp, _ = http1(p.base, "GET", "/")
    passive = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
    }
    for name, value in passive.items():
        check(header(hv, name) is None, f"V: `{name}` absent (got {header(hv, name)!r})")
        check(header(hp, name) == value, f"P: `{name}: {value}` (got {header(hp, name)!r})")


# The remaining D3 seed rows (`check_seeds` above covers one per class plus the
# session gate and the passive headers). Markers are the crate's `seed.rs` constants;
# the literal shapes are the spec's D3 table. A row is (name, method, path, headers,
# body, V predicate, P predicate); predicates see (status, headers, text, elapsed s).
CMDI_MARKER = "uid=0(root) gid=0(root)"
TRAVERSAL_MARKER = "root:x:0:0:root:/root:/bin/bash"
LDAPI_ALL_USERS_MARKER = "LDAP-ALL-USERS-MARKER-77c2"
SSRF_MARKER = "SSRF-INTERNAL-METADATA-9d4e"
IDOR_MARKER = "IDOR-ACCOUNT2-SECRET-5a8b"
AUTH_BYPASS_MARKER = "ADMIN-AREA-MARKER-c6f0"
REDIRECT_TARGET = "https://redirect-marker-e2d9.example/"
XXE_BODY = (b'<?xml version="1.0"?><!DOCTYPE order [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
            b'<order id="7"><name>&e;</name></order>')
MULTIPART_BOUNDARY = "e2eBoundary7f3a"
MULTIPART_BODY = (
    f"--{MULTIPART_BOUNDARY}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{MARK}.txt"\r\n'
    "Content-Type: text/plain\r\n\r\nx\r\n"
    f"--{MULTIPART_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="note"\r\n\r\n'
    f"{MARK}\r\n"
    f"--{MULTIPART_BOUNDARY}--\r\n"
).encode()
Q = lambda v: urllib.parse.quote(v, safe="")  # noqa: E731


def escaped(t: str) -> bool:
    """P's answer: the marker HTML-escaped and never raw."""
    return MARK_ESC in t and MARK not in t


SEEDS = (
    ("sqli-boolean true", "GET", "/items?id=" + Q("1 AND 1=1"), None, None,
     lambda st, h, t, dt: st == 200 and "<p>items: 1</p>" in t,
     lambda st, h, t, dt: st == 400 and t == "invalid id"),
    ("sqli-boolean false", "GET", "/items?id=" + Q("1 AND 1=2"), None, None,
     lambda st, h, t, dt: st == 200 and "<p>items: 0</p>" in t,
     lambda st, h, t, dt: st == 400 and t == "invalid id"),
    ("sqli-boolean or-all", "GET", "/items?id=" + Q("1 OR 1=1"), None, None,
     lambda st, h, t, dt: st == 200 and "<p>items: 5</p>" in t,
     lambda st, h, t, dt: st == 400),
    ("sqli-time base", "GET", "/orders?id=1", None, None,
     lambda st, h, t, dt: st == 200 and t == "<p>order 1</p>" and dt < 1.0,
     lambda st, h, t, dt: st == 200 and t == "<p>order 1</p>" and dt < 1.0),
    ("sqli-time SLEEP(2)", "GET", "/orders?id=" + Q("1 AND SLEEP(2)"), None, None,
     lambda st, h, t, dt: st == 200 and t.startswith("<p>order ") and dt >= 2.0,
     lambda st, h, t, dt: st == 400 and t == "invalid id" and dt < 1.0),
    ("cmdi ;id", "GET", "/ping?host=" + Q("localhost;id"), None, None,
     lambda st, h, t, dt: st == 200 and CMDI_MARKER in t,
     lambda st, h, t, dt: st == 400 and t == "invalid host"),
    ("cmdi ;sleep 2", "GET", "/ping?host=" + Q("localhost;sleep 2"), None, None,
     lambda st, h, t, dt: st == 200 and dt >= 2.0,
     lambda st, h, t, dt: st == 400 and dt < 1.0),
    # The bundled Rhai cmdi check's probe shape: a split marker only execution
    # reassembles (amendment 64). The raw `echo AAA` must not appear in V's body.
    ("cmdi ;echo marker", "GET", "/ping?host=" + Q("localhost;echo AAABBB"), None, None,
     lambda st, h, t, dt: st == 200 and "\nAAABBB</pre>" in t and "echo AAA" not in t,
     lambda st, h, t, dt: st == 400 and t == "invalid host"),
    ("xxe", "POST", "/xml", {"content-type": "text/xml"}, XXE_BODY,
     lambda st, h, t, dt: st == 200 and TRAVERSAL_MARKER in t,
     lambda st, h, t, dt: st == 400 and t == "DTD not allowed"),
    ("ldapi wildcard", "GET", "/ldap?user=" + Q("*"), None, None,
     lambda st, h, t, dt: st == 200 and LDAPI_ALL_USERS_MARKER in t,
     lambda st, h, t, dt: st == 200 and t == "<p>no entries</p>"),
    ("ldapi filter break", "GET", "/ldap?user=" + Q("a)(uid=*"), None, None,
     lambda st, h, t, dt: st == 500 and "Bad search filter" in t,
     lambda st, h, t, dt: st == 200 and t == "<p>no entries</p>"),
    ("cookie-reflection /prefs", "GET", "/prefs", {"cookie": f"theme={MARK}"}, None,
     lambda st, h, t, dt: st == 200 and f'<body class="{MARK}">' in t,
     lambda st, h, t, dt: st == 200 and escaped(t)),
    ("nested-json /api/profile", "POST", "/api/profile", {"content-type": "application/json"},
     json.dumps({"profile": {"address": {"city": MARK}}}).encode(),
     lambda st, h, t, dt: st == 200 and f'<div class="city">{MARK}</div>' in t,
     lambda st, h, t, dt: st == 200 and escaped(t)),
    ("multipart /upload", "POST", "/upload",
     {"content-type": f"multipart/form-data; boundary={MULTIPART_BOUNDARY}"}, MULTIPART_BODY,
     lambda st, h, t, dt: st == 200 and t == f"<p>uploaded {MARK}.txt (1 bytes): {MARK}</p>",
     lambda st, h, t, dt: st == 200 and escaped(t) and "(1 bytes)" in t),
    ("path-segment /docs/", "GET", "/docs/" + Q(MARK), None, None,
     lambda st, h, t, dt: st == 200 and t == f"<h1>Doc: {MARK}</h1>",
     lambda st, h, t, dt: st == 200 and escaped(t)),
    ("path-filename /files/", "GET", "/files/" + Q(MARK) + ".txt", None, None,
     lambda st, h, t, dt: st == 200 and t == f"<p>file {MARK}.txt</p>",
     lambda st, h, t, dt: st == 200 and escaped(t)),
    ("open-redirect", "GET", "/redirect?next=" + Q(REDIRECT_TARGET), None, None,
     lambda st, h, t, dt: st in (301, 302, 303, 307) and header(h, "location") == REDIRECT_TARGET,
     lambda st, h, t, dt: st in (301, 302, 303, 307) and header(h, "location") == "/"),
    ("ssrf /fetch metadata", "GET", "/fetch?url=" + Q("http://169.254.169.254/"), None, None,
     lambda st, h, t, dt: st == 200 and SSRF_MARKER in t,
     lambda st, h, t, dt: st == 403 and SSRF_MARKER not in t),
    ("idor /account/2", "GET", "/account/2", None, None,
     lambda st, h, t, dt: st == 200 and IDOR_MARKER in t,
     lambda st, h, t, dt: st == 403 and IDOR_MARKER not in t),
    ("auth-bypass /admin X-Role", "GET", "/admin", {"x-role": "admin"}, None,
     lambda st, h, t, dt: st == 200 and AUTH_BYPASS_MARKER in t,
     lambda st, h, t, dt: st == 403 and AUTH_BYPASS_MARKER not in t),
    ("reflected-xss /search", "GET", "/search?q=" + Q(MARK), None, None,
     lambda st, h, t, dt: st == 200 and f"<h1>Results for {MARK}</h1>" in t,
     lambda st, h, t, dt: st == 200 and escaped(t)),
)


def timed(base: str, method: str, path: str, headers, body):
    t0 = time.monotonic()
    st, h, b = http1(base, method, path, headers=headers, body=body, timeout=15.0)
    return st, h, text(b), time.monotonic() - t0


def check_seed_rows(v: ScanTarget, p: ScanTarget) -> None:
    """Every remaining D3 row: V's literal signal beside P's patched answer."""
    section(f"the remaining {len(SEEDS)} D3 seed rows, V's signal beside P's patched answer")
    for name, method, path, headers, body, v_ok, p_ok in SEEDS:
        sv, hv, tv, dv = timed(v.base, method, path, headers, body)
        sp, hp, tp, dp = timed(p.base, method, path, headers, body)
        check(v_ok(sv, hv, tv, dv), f"V {name}: {sv} {tv[:90]!r} ({dv:.2f} s)")
        check(p_ok(sp, hp, tp, dp), f"P {name}: {sp} {tp[:90]!r} ({dp:.2f} s)")

    section("stored-xss: POST /comments then GET /comments, V raw, P escaped")
    for mode, t in (("V", v), ("P", p)):
        st, h, _ = http1(t.base, "POST", "/comments",
                         headers={"content-type": "application/x-www-form-urlencoded"},
                         body=("comment=" + Q(MARK)).encode())
        check(st in (301, 302, 303) and header(h, "location") == "/comments",
              f"{mode}: POST /comments redirects to /comments (got {st} {header(h, 'location')!r})")
        st, _, b = http1(t.base, "GET", "/comments")
        want = f"<li>{MARK}</li>" in text(b) if mode == "V" else escaped(text(b))
        check(st == 200 and want, f"{mode}: GET /comments shows the comment {'raw' if mode == 'V' else 'escaped'} "
                                  f"(got {st} {text(b)[:90]!r})")


def speaker_vulnerable(t: ScanTarget, row: dict) -> list[tuple[bool, str]]:
    """S5, Vulnerable half for one speaker: benign, liveness, trigger closes with no
    bytes, down within 2 s, still down at +4 s, back by +6 s, one 5000 ms downtime row.
    Returns (passed, message) pairs; the caller turns them into checks (a thread
    must not call `check`, whose `sys.exit` would only end the thread)."""
    name = row["service"]
    out: list[tuple[bool, str]] = []
    try:
        addr = addr_of(t, name)
        got = exchange(row, addr, row["benign"], len(row["benign_expect"]))
        out.append((got == row["benign_expect"],
                    f"V {name}: benign {row['benign'][:16].hex()} -> {row['benign_expect'][:16].hex()} "
                    f"(got {(got or b'')[:16].hex()})"))
        got = exchange(row, addr, row["liveness"], len(row["liveness_expect"]))
        out.append((got == row["liveness_expect"],
                    f"V {name}: liveness answers {row['liveness_expect'][:16].hex()} (got {(got or b'')[:16].hex()})"))
        before = len(t.logs.downtime(name))
        t_trig = time.monotonic()
        if row["proto"] == "udp":
            reply = udp_exchange(addr, row["trigger"])
            out.append((reply is None, f"V {name}: the trigger datagram draws no reply (got {(reply or b'').hex()!r})"))
        else:
            bytes_back, eof = tcp_trigger(row, addr)
            out.append((bytes_back == b"" and eof,
                        f"V {name}: the trigger closes the connection with no bytes (got {bytes_back.hex()!r}, eof={eof})"))
        down_at = wait_down(row, addr, 2.0)
        out.append((down_at is not None, f"V {name}: down within 2 s of the trigger (seen at {down_at})"))
        time.sleep(max(0.0, t_trig + 4.0 - time.monotonic()))
        out.append((is_down(row, addr), f"V {name}: still down at +4 s (inside the 5 s window)"))
        up = wait_liveness(row, addr, t_trig + 6.0)
        out.append((up, f"V {name}: liveness answers again by +6 s (the window closed)"))
        dt = t.logs.downtime(name)
        out.append((len(dt) == before + 1, f"V {name}: exactly one new `downtime` row (had {before}, now {len(dt)})"))
        if dt:
            window = int(dt[-1].get("up_at_ms", 0)) - int(dt[-1].get("down_at_ms", 0))
            out.append((window == CRASH_WINDOW_MS, f"V {name}: up_at_ms - down_at_ms == {CRASH_WINDOW_MS} (got {window})"))
    except Exception as e:  # noqa: BLE001  (reported as a failed check, never swallowed)
        out.append((False, f"V {name}: {type(e).__name__}: {e}"))
    return out


def speaker_patched(t: ScanTarget, row: dict) -> list[tuple[bool, str]]:
    """S5, Patched half: benign still works, the trigger gets the row's reply and the
    connection closes (UDP: the reply datagram), the service never goes down."""
    name = row["service"]
    out: list[tuple[bool, str]] = []
    try:
        addr = addr_of(t, name)
        got = exchange(row, addr, row["benign"], len(row["benign_expect"]))
        out.append((got == row["benign_expect"], f"P {name}: benign exchange unchanged (got {(got or b'')[:16].hex()})"))
        before = len(t.logs.downtime(name))
        want = row["p_reply"] or b""
        if row["proto"] == "udp":
            reply = udp_exchange(addr, row["trigger"], timeout=1.0)
            out.append((reply == want, f"P {name}: the trigger is answered {want.hex()} (got {(reply or b'').hex()!r})"))
        else:
            bytes_back, eof = tcp_trigger(row, addr)
            label = want.hex() if want else "nothing (the protocol has no error reply)"
            out.append((bytes_back == want and eof,
                        f"P {name}: the trigger gets {label} then the close (got {bytes_back!r}, eof={eof})"))
        out.append((not is_down(row, addr), f"P {name}: the service stays up (the next exchange succeeds)"))
        dt = t.logs.downtime(name)
        out.append((len(dt) == before, f"P {name}: no downtime row (had {before}, now {len(dt)})"))
    except Exception as e:  # noqa: BLE001
        out.append((False, f"P {name}: {type(e).__name__}: {e}"))
    return out


def run_concurrently(fn, t: ScanTarget) -> list[list[tuple[bool, str]]]:
    """`fn(t, row)` for every SPEAKERS row at once; results in table order."""
    results: list[list[tuple[bool, str]]] = [[] for _ in SPEAKERS]

    def worker(i: int, row: dict) -> None:
        results[i] = fn(t, row)

    threads = [threading.Thread(target=worker, args=(i, row), name=row["service"], daemon=True)
               for i, row in enumerate(SPEAKERS)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=30.0)
    for i, th in enumerate(threads):
        if th.is_alive():
            results[i].append((False, f"{SPEAKERS[i]['service']}: the check did not finish within 30 s"))
    return results


def check_speakers(v: ScanTarget, p: ScanTarget) -> None:
    """All nine D5 speakers, the nine Vulnerable crash windows run concurrently."""
    t0 = time.monotonic()
    v_results = run_concurrently(speaker_vulnerable, v)
    p_results = run_concurrently(speaker_patched, p)
    elapsed = time.monotonic() - t0
    failed = [m for rows in v_results + p_results for passed, m in rows if not passed]
    for rows in v_results + p_results:
        for passed, m in rows:
            if passed:
                ok(m)
    for m in failed:
        print(f"  [FAIL] {m}", flush=True)
    check(not failed, f"all nine speakers: V trigger -> 5 s window, P trigger -> the row's reply "
                      f"({len(failed)} failing assertion(s), {elapsed:.1f} s)")


def check_h2_conn_counter(t: ScanTarget) -> None:
    """S3: five requests over one h2 connection -> one `/log/conns` row with
    `requests: 5` and `conn_req_index` 1..5 on `version: "h2"` request entries.
    curl reuses the connection for every URL of one invocation."""
    m = t.mode
    seq0 = t.logs.reset()
    url = t.tls_base + "/preview?msg=x"
    rc, out, err = curl(["-k", "--http2", "-w", "%{http_version}\n", *(["-o", "/dev/null", url] * 5)])
    versions = out.decode("utf-8", "replace").split()
    check(rc == 0 and versions == ["2"] * 5,
          f"{m}: five curl --http2 requests in one invocation all negotiated HTTP/2 "
          f"(rc={rc} versions={versions} {err.strip()[:120]})")
    until(lambda: len([e for e in t.logs.http() if int(e.get("seq", 0)) > seq0
                       and e.get("kind") == "request" and e.get("path") == "/preview"]) >= 5, 3.0)
    entries = [e for e in t.logs.http() if int(e.get("seq", 0)) > seq0]
    reqs = sorted((e for e in entries if e.get("kind") == "request" and e.get("path") == "/preview"),
                  key=lambda e: int(e.get("seq", 0)))
    check(len(reqs) == 5, f"{m}: the target logged exactly five /preview requests (got {len(reqs)})")
    conn_ids = {e.get("conn_id") for e in reqs}
    check(len(conn_ids) == 1, f"{m}: all five requests share one conn_id (got {sorted(map(str, conn_ids))})")
    check([e.get("conn_req_index") for e in reqs] == [1, 2, 3, 4, 5],
          f"{m}: conn_req_index runs 1..5 on that connection (got {[e.get('conn_req_index') for e in reqs]})")
    check(all(e.get("version") == "h2" and e.get("listener") == "tls" and e.get("status") == 200
              and e.get("query") == "msg=x" for e in reqs),
          f"{m}: every entry is version h2, listener tls, status 200, query msg=x "
          f"(got {[(e.get('version'), e.get('listener'), e.get('status'), e.get('query')) for e in reqs]})")
    hs = [e.get("alpn") for e in entries if e.get("kind") == "tls_handshake"]
    check(hs == ["h2"], f"{m}: exactly one TLS handshake (alpn h2) for the five requests (got {hs})")
    conn_id = next(iter(conn_ids), None)
    rows = [c for c in t.logs.conns() if c.get("conn_id") == conn_id]
    check(len(rows) == 1 and rows[0].get("listener") == "tls" and rows[0].get("alpn") == "h2",
          f"{m}: /log/conns has one row for {conn_id} on listener tls with alpn h2 (got {rows})")
    check(bool(rows) and rows[0].get("requests") == 5,
          f"{m}: /log/conns row requests == 5 (got {rows[0].get('requests') if rows else None})")
    check(isinstance(conn_id, str) and conn_id.startswith("c-") and len(conn_id) == 10,
          f"{m}: conn_id is `c-<8 hex>` (got {conn_id!r})")


# ---------------------------------------------------------------------------
# a raw RFC 6455 client straight to the target (no proxy); the frame codec is
# the harness's (aitm_e2e.ws), the handshake is written here so the cell owns
# the Sec-WebSocket-Key it later looks up in /log/ws.
# ---------------------------------------------------------------------------
def ws_connect(base: str, key: str, headers: dict | None = None, timeout: float = 5.0):
    """Upgrade `GET /ws` on `base`; returns (status, headers, body, sock, rd). On a
    non-101 answer the body is read and the socket closed."""
    u = urllib.parse.urlsplit(base)
    sock = socket.create_connection((u.hostname, u.port), timeout=timeout)
    rd = sock.makefile("rb")
    lines = ["GET /ws HTTP/1.1", f"Host: {u.netloc}", "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
    status_line = rd.readline().decode("latin1").strip()
    parts = status_line.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    hdrs: dict[str, str] = {}
    while True:
        line = rd.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, val = line.decode("latin1").partition(":")
        hdrs[k.strip().lower()] = val.strip()
    body = b""
    if status != 101:
        n = int(hdrs.get("content-length") or 0)
        try:
            body = rd.read(n) if n else rd.read()
        except (OSError, ValueError):
            body = b""
        sock.close()
    return status, hdrs, body, sock, rd


def ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def ws_send_text(sock, text: str) -> None:
    sock.sendall(ws_encode(0x1, text.encode("utf-8"), mask=True))


def ws_read_text(rd) -> str | None:
    opcode, payload = ws_read_frame(rd)
    return payload.decode("utf-8", "replace") if opcode == 0x1 and payload is not None else None


def ws_close(sock) -> None:
    try:
        sock.sendall(ws_encode(0x8, struct.pack("!H", 1000), mask=True))
    except OSError:
        pass
    sock.close()


def ws_oversize_header(declared: int) -> bytes:
    """FIN|Binary, MASK|127, a 64-bit length, a mask key and NO payload bytes: the
    server must refuse on the header alone (close 1009)."""
    return bytes([0x82, 0xFF]) + struct.pack("!Q", declared) + os.urandom(4)


def ws_log_entry(t: ScanTarget, pred, timeout: float = 3.0) -> dict:
    """The first `/log/ws` entry matching `pred`, polled for up to `timeout` s ({} if none)."""
    def find():
        return next((e for e in t.logs.ws() if pred(e)), None)
    return until(find, timeout) or {}


def ws_handshake_entry(t: ScanTarget, key: str) -> dict:
    return ws_log_entry(t, lambda e: e.get("kind") == "handshake" and e.get("sec_websocket_key") == key)


def ws_close_entry(t: ScanTarget, conn_id: str | None) -> dict:
    if not conn_id:
        return {}
    return ws_log_entry(t, lambda e: e.get("kind") == "close" and e.get("conn_id") == conn_id)


def check_ws(v: ScanTarget, p: ScanTarget) -> None:
    """S4 / D4, mirrored from crates/aitm-testtarget/tests/scan_http.rs::ws_round_trip_v_and_p."""
    section("S4 /ws on V: foreign Origin upgrades, hello anonymous, raw echo")
    k1 = ws_key()
    st, _, body, sock, rd = ws_connect(v.base, k1, {"Origin": FOREIGN_ORIGIN})
    check(st == 101, f"V: /ws with Origin {FOREIGN_ORIGIN} -> 101 (got {st} {text(body)[:80]!r})")
    if st == 101:
        hello = ws_read_text(rd)
        check(hello == WS_HELLO_ANON, f"V: hello frame is {WS_HELLO_ANON} (got {hello!r})")
        ws_send_text(sock, WS_ECHO_REQ)
        echo = ws_read_text(rd)
        check(echo == WS_ECHO_V, f"V: echo of <i> is raw (got {echo!r})")
        ws_close(sock)

    section("S4 /ws on V: after POST /login the hello names alice")
    v_cookie = do_login(v.base)
    k2 = ws_key()
    st, _, body, sock, rd = ws_connect(v.base, k2, {"Cookie": f"session={v_cookie}"})
    check(st == 101, f"V: /ws with the login cookie and no Origin -> 101 (got {st})")
    if st == 101:
        hello = ws_read_text(rd)
        check(hello == WS_HELLO_ALICE, f"V: hello frame is {WS_HELLO_ALICE} (got {hello!r})")
        ws_close(sock)

    section("S4 /ws on V: a 1 048 577-byte frame header is refused with close 1009")
    k3 = ws_key()
    st, _, body, sock, rd = ws_connect(v.base, k3)
    check(st == 101, f"V: plain /ws upgrade -> 101 (got {st})")
    close_code = None
    if st == 101:
        hello = ws_read_text(rd)
        check(hello == WS_HELLO_ANON, f"V: hello before the oversize frame (got {hello!r})")
        sock.sendall(ws_oversize_header(WS_MAX_FRAME + 1))
        try:
            opcode, payload = ws_read_frame(rd)
        except OSError:
            opcode, payload = None, None
        if opcode == 0x8 and payload and len(payload) >= 2:
            close_code = struct.unpack("!H", payload[:2])[0]
        check(opcode == 0x8 and close_code == 1009,
              f"V: the server answered the header with a close frame, code 1009 (got opcode {opcode} code {close_code})")
        sock.close()

    section("S4 /log/ws on V: each handshake under the client's own key, cookie redacted, 1009 logged")
    hs1 = ws_handshake_entry(v, k1)
    check(hs1.get("accepted") is True and hs1.get("status") == 101 and hs1.get("origin") == FOREIGN_ORIGIN,
          f"V: handshake {k1[:6]}.. logged accepted/101 with origin {FOREIGN_ORIGIN} "
          f"(got accepted={hs1.get('accepted')!r} status={hs1.get('status')!r} origin={hs1.get('origin')!r})")
    check(hs1.get("cookie_names") == [], f"V: the anonymous handshake logs cookie_names == [] (got {hs1.get('cookie_names')!r})")
    hs2 = ws_handshake_entry(v, k2)
    check(hs2.get("cookie_names") == ["session"] and hs2.get("session_valid") is True and hs2.get("accepted") is True,
          f"V: the logged-in handshake logs cookie_names == ['session'], session_valid, accepted "
          f"(got {hs2.get('cookie_names')!r} / {hs2.get('session_valid')!r} / {hs2.get('accepted')!r})")
    raw = json.dumps(v.logs.ws())
    check(bool(v_cookie) and v_cookie not in raw, "V: the raw session id never appears anywhere in /log/ws")
    hs3 = ws_handshake_entry(v, k3)
    close_entry = ws_close_entry(v, hs3.get("conn_id"))
    check(close_entry.get("code") == 1009,
          f"V: /log/ws holds a `close` entry with code 1009 for the oversize connection (got {close_entry or None})")

    section("S4 /ws on P: foreign Origin 403, no session 401, session cookie upgrades + escapes")
    k4 = ws_key()
    st, _, body, _, _ = ws_connect(p.base, k4, {"Origin": FOREIGN_ORIGIN})
    check(st == 403 and text(body) == "<p>forbidden origin</p>",
          f"P: /ws with Origin {FOREIGN_ORIGIN} -> 403 <p>forbidden origin</p> (got {st} {text(body)[:60]!r})")
    k5 = ws_key()
    st, _, body, _, _ = ws_connect(p.base, k5)
    check(st == 401 and text(body) == "<p>login required</p>",
          f"P: /ws with no Origin and no cookie -> 401 <p>login required</p> (got {st} {text(body)[:60]!r})")
    p_cookie = do_login(p.base)
    k6 = ws_key()
    st, _, body, sock, rd = ws_connect(p.base, k6, {"Cookie": f"session={p_cookie}"})
    check(st == 101, f"P: /ws with the login cookie and no Origin -> 101 (got {st} {text(body)[:60]!r})")
    if st == 101:
        hello = ws_read_text(rd)
        check(hello == WS_HELLO_ALICE, f"P: hello frame is {WS_HELLO_ALICE} (got {hello!r})")
        ws_send_text(sock, WS_ECHO_REQ)
        echo = ws_read_text(rd)
        check(echo == WS_ECHO_P, f"P: echo of <i> is HTML-escaped (got {echo!r})")
        ws_close(sock)
    hs4, hs5, hs6 = ws_handshake_entry(p, k4), ws_handshake_entry(p, k5), ws_handshake_entry(p, k6)
    check(hs4.get("accepted") is False and hs4.get("status") == 403,
          f"P: the foreign-Origin handshake is logged accepted False / 403 (got {hs4.get('accepted')!r} / {hs4.get('status')!r})")
    check(hs5.get("accepted") is False and hs5.get("status") == 401 and hs5.get("session_valid") is False,
          f"P: the no-session handshake is logged accepted False / 401 (got {hs5.get('accepted')!r} / {hs5.get('status')!r})")
    check(hs6.get("accepted") is True and hs6.get("status") == 101 and hs6.get("cookie_names") == ["session"],
          f"P: the logged-in handshake is accepted / 101 with cookie_names ['session'] "
          f"(got {hs6.get('accepted')!r} / {hs6.get('status')!r} / {hs6.get('cookie_names')!r})")
    check(bool(p_cookie) and p_cookie not in json.dumps(p.logs.ws()), "P: the raw session id never appears in /log/ws")


def check_manifest_404(v: ScanTarget, p: ScanTarget) -> None:
    """S6: the manifest and every seed id are 404 on the target AND the control origin."""
    for t in (v, p):
        for origin_name, base in (("target", t.base), ("control", t.control)):
            for path in ("/manifest", "/manifest.yaml"):
                s, _, _ = http1(base, "GET", path)
                check(s == 404, f"{t.mode}/{origin_name}: GET {path} is 404 (got {s})")
            not_404 = {}
            for sid in MANIFEST_IDS:
                s, _, _ = http1(base, "GET", "/" + sid)
                if s != 404:
                    not_404[sid] = s
            check(not not_404,
                  f"{t.mode}/{origin_name}: GET /<id> is 404 for all {len(MANIFEST_IDS)} manifest ids "
                  f"(non-404: {not_404 or 'none'})")


def check_cookie_redaction(v: ScanTarget) -> None:
    seq0 = v.logs.reset()
    secret = f"s3cr3t{RUN}"
    http1(v.base, "GET", "/", headers={"cookie": f"session={secret}"})

    def logged():
        return [e for e in v.logs.http()
                if e.get("kind") == "request" and e.get("path") == "/" and int(e.get("seq", 0)) > seq0]
    reqs = until(logged, 3.0) or []
    check(len(reqs) == 1, f"one `/` request logged after the reset (got {len(reqs)})")
    entry = reqs[0]
    check(entry.get("cookie_names") == ["session"],
          f"cookie_names == ['session'] (got {entry.get('cookie_names')!r})")
    check("cookie" not in {k.lower() for k in (entry.get("headers") or {})},
          f"no `cookie` key is stored in the entry's headers (got {sorted(entry.get('headers') or {})})")
    sha = entry.get("cookie_sha256")
    check(isinstance(sha, str) and HEX16_RE.match(sha) is not None,
          f"cookie_sha256 is 16 hex chars (got {sha!r})")
    raw = json.dumps(v.logs.http())
    check(secret not in raw, "the raw session value never appears anywhere in /log/http")


def main() -> int:
    if not have("curl"):
        skip("curl not found: the ALPN assertions need curl's own negotiated HTTP version")
    if not curl_supports_h2():
        skip("curl lacks HTTP/2 support (no `HTTP2` in `curl -V`): cannot negotiate h2")
    v = boot("vulnerable")
    p = boot("patched")
    try:
        section("the five D1 stdout lines and the fifteen D2 /services rows")
        check_process_shape(v)
        check_process_shape(p)
        section("TLS ALPN per listener, read back from the control log")
        check_alpn(v)
        check_alpn(p)
        section("S3: five requests on one h2 connection are one /log/conns row with requests 5")
        check_h2_conn_counter(v)
        check_seeds(v, p)
        check_seed_rows(v, p)
        check_ws(v, p)
        section("the nine D5 speakers: the 5 s crash window (V) vs the protocol-error reply (P)")
        check_speakers(v, p)
        section("S6: `/manifest`, `/manifest.yaml` and every seed id are 404 on the target and the control origin")
        check_manifest_404(v, p)
        section("the control log redacts `cookie` to names + a 16-hex hash")
        check_cookie_redaction(v)
    finally:
        v.stop()
        p.stop()
    ok("T10 self-check: the seeded target serves every class, ALPN, the h2 counter, /ws, the crash window, "
       "the unserved manifest and redaction as pinned")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
