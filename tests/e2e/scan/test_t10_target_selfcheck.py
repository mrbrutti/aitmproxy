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
  - one seed per D3 class answers on V with the row's literal signal and on P
    with the row's patched answer (the rows are the child spec's D3 table)
  - the TLV speaker (D5): V closes on the trigger frame, refuses connects, is back
    inside the 5 s window and logs one `downtime` row with
    `up_at_ms - down_at_ms == 5000`; P answers `00 03 45 52 52` and never goes down
  - `/manifest` and `/manifest.yaml` are 404 on both origins
  - the control log never stores a `cookie` key or the session value; a request
    carrying `session=` logs `cookie_names == ["session"]` + a 16-hex hash

SKIPs 77 only when `aitm-testtarget-serve` or an HTTP/2-capable `curl` is missing.
Binds loopback ports: run from a real shell, not the Claude sandbox. Exit 0 pass /
1 fail / 77 skip. This cell handles no token.
"""

from __future__ import annotations

import http.client
import json
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.scan import ScanTarget  # noqa: E402
from aitm_e2e.tls import curl_http_version, have  # noqa: E402

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

TLV_SERVICE = "l4-tlv-crash"
TLV_BENIGN = bytes.fromhex("0003616263")   # len 3 + "abc" -> echoed (D5 benign exchange)
TLV_LIVENESS = bytes.fromhex("0000")       # D5 liveness: `00 00` -> `00 00`
TLV_TRIGGER = bytes.fromhex("ffff")        # declared len 65535 > 4096: the D5 trigger
TLV_P_REPLY = bytes.fromhex("0003455252")  # D5 P reply (`ERR` frame), then close
CRASH_WINDOW_MS = 5000


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
    host, _, port = str(target.service(name)["addr"]).rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# TLV speaker primitives (raw sockets; the speaker's own bytes are the oracle)
# ---------------------------------------------------------------------------
def tlv_exchange(addr: tuple[str, int], payload: bytes, want: int, timeout: float = 3.0) -> bytes:
    """Connect, send `payload`, read up to `want` bytes (or EOF), close."""
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(payload)
        got = b""
        while len(got) < want:
            chunk = s.recv(want - len(got))
            if not chunk:
                break
            got += chunk
        return got


def tlv_send_trigger(addr: tuple[str, int], timeout: float = 3.0) -> tuple[bytes, bool]:
    """Send the trigger frame on a fresh connection; return (bytes read back, saw_eof)."""
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(TLV_TRIGGER)
        got = b""
        eof = False
        try:
            while len(got) < 64:
                chunk = s.recv(64 - len(got))
                if not chunk:
                    eof = True
                    break
                got += chunk
        except socket.timeout:
            pass
        return got, eof


def connect_refused(addr: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(addr, timeout=1.0):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def wait_refused(addr: tuple[str, int], within: float) -> float | None:
    """Seconds until the first refused connect, or None if none was refused within `within`."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < within:
        if connect_refused(addr):
            return time.monotonic() - t0
        time.sleep(0.02)
    return None


def wait_liveness(addr: tuple[str, int], until: float) -> bool:
    """Poll the liveness exchange until it answers `00 00` or `until` (monotonic) passes."""
    while time.monotonic() < until:
        try:
            if tlv_exchange(addr, TLV_LIVENESS, 2, timeout=1.0) == TLV_LIVENESS:
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


# ---------------------------------------------------------------------------
def curl_supports_h2() -> bool:
    try:
        p = subprocess.run(["curl", "-V"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "HTTP2" in p.stdout


def boot(mode: str) -> ScanTarget:
    try:
        return ScanTarget(mode, l4=True)
    except FileNotFoundError as e:
        skip(str(e))
    raise AssertionError("unreachable")


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
    time.sleep(0.2)  # the target writes its log entries after the bytes left its socket
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
    check(status == 302 and m is not None,
          f"login: POST /login mints a 32-hex session cookie (status {status}, set-cookie {sc!r})")
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

    section("header-reflection `/whoami` User-Agent: V reflects raw, P escapes")
    sv, _, bv = http1(v.base, "GET", "/whoami", headers={"user-agent": MARK})
    sp, _, bp = http1(p.base, "GET", "/whoami", headers={"user-agent": MARK})
    check(sv == 200 and f"<p>agent: {MARK}</p>" in text(bv), f"V: raw User-Agent reflected (got {text(bv)!r})")
    check(sp == 200 and MARK_ESC in text(bp) and MARK not in text(bp),
          f"P: User-Agent HTML-escaped (got {text(bp)!r})")

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


def check_tlv_vulnerable(v: ScanTarget) -> None:
    addr = addr_of(v, TLV_SERVICE)
    check(tlv_exchange(addr, TLV_BENIGN, 5) == TLV_BENIGN,
          "V tlv: benign `00 03 61 62 63` echoes back")
    check(tlv_exchange(addr, TLV_LIVENESS, 2) == TLV_LIVENESS, "V tlv: liveness `00 00` -> `00 00`")
    before = len(v.logs.downtime(TLV_SERVICE))
    got, _ = tlv_send_trigger(addr)
    check(got == b"", f"V tlv: the `FF FF` trigger draws no reply, the connection closes (got {got.hex()!r})")
    refused_at = wait_refused(addr, 0.5)
    check(refused_at is not None,
          f"V tlv: connects are refused within 500 ms of the trigger (saw refusal at {refused_at})")
    up = wait_liveness(addr, time.monotonic() + 6.0)
    check(up, "V tlv: the benign liveness answers again within 6 s (the window closed)")
    dt = v.logs.downtime(TLV_SERVICE)
    check(len(dt) == before + 1, f"V tlv: exactly one new `downtime` row (had {before}, now {len(dt)})")
    window = int(dt[-1].get("up_at_ms", 0)) - int(dt[-1].get("down_at_ms", 0))
    check(window == CRASH_WINDOW_MS, f"V tlv: up_at_ms - down_at_ms == 5000 (got {window})")


def check_tlv_patched(p: ScanTarget) -> None:
    addr = addr_of(p, TLV_SERVICE)
    check(tlv_exchange(addr, TLV_BENIGN, 5) == TLV_BENIGN, "P tlv: benign echo still works")
    got, _ = tlv_send_trigger(addr)
    check(got == TLV_P_REPLY, f"P tlv: the `FF FF` trigger is answered `00 03 45 52 52` (got {got.hex()!r})")
    check(not connect_refused(addr), "P tlv: the listener stays up (the next connect succeeds)")
    check(p.logs.downtime(TLV_SERVICE) == [], f"P tlv: no downtime (got {p.logs.downtime(TLV_SERVICE)})")


def check_manifest_404(v: ScanTarget, p: ScanTarget) -> None:
    for t in (v, p):
        for path in ("/manifest", "/manifest.yaml"):
            s, _, _ = http1(t.base, "GET", path)
            check(s == 404, f"{t.mode}: GET {path} is 404 (got {s})")


def check_cookie_redaction(v: ScanTarget) -> None:
    seq0 = v.logs.reset()
    secret = f"s3cr3t{RUN}"
    http1(v.base, "GET", "/", headers={"cookie": f"session={secret}"})
    time.sleep(0.2)
    reqs = [e for e in v.logs.http()
            if e.get("kind") == "request" and e.get("path") == "/" and int(e.get("seq", 0)) > seq0]
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
        check_seeds(v, p)
        section("the TLV speaker's 5 s crash window (V) vs the protocol-error reply (P)")
        check_tlv_vulnerable(v)
        check_tlv_patched(p)
        section("`/manifest` and `/manifest.yaml` are 404 on both origins")
        check_manifest_404(v, p)
        section("the control log redacts `cookie` to names + a 16-hex hash")
        check_cookie_redaction(v)
    finally:
        v.stop()
        p.stop()
    ok("T10 self-check: the seeded target serves every class, ALPN, the crash window and redaction as pinned")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
