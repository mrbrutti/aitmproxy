#!/usr/bin/env python3
# e2e: tier=T1 surface=proto
"""proto/test_h1_100_continue -- an HTTP/1.1 `Expect: 100-continue` POST through the
proxy is HANDLED (the client's expectation is answered, the whole body reaches the
origin once, the connection stays usable) and CAPTURED (one flow, the FINAL status,
the exact body, the Expect header) -- proven on ground truth, never fixtures.

The hard case is the STRICT client (RFC 9110 s10.1.1): it sends the head with
`Expect: 100-continue` and WITHHOLDS the body until the server answers. The RFC's
rule for the server -- and a proxy IS the client's server -- is a MUST: "send an
immediate 100 (Continue) response ... MUST NOT wait for the request content". curl,
the most common Expect client (it adds the header to every upload over 1 MiB), waits
1 s and then sends anyway. So a proxy that never answers costs every such upload a
full second of stall; one that answers a final status before the body has refused a
valid upload. (At the time of writing the h1 module buffers the whole request before
forwarding and emits no interim itself -- `crates/aitm-proto-http/src/module.rs`
`serve()` -- so a strict client stalls; this suite reports that as a defect and still
verifies everything else about the exchange.)

Ground truth (never fixtures):
  * the bytes a REAL raw-socket client receives from the REAL proxy: whether an
    interim `100 Continue` (or anything) arrives before the body is sent, within
    CONTINUE_DEADLINE_S; the final status line (302 Found -> /comments, the origin's
    real answer, NEVER a 1xx); clean framing (no stray bytes); and that the SAME
    connection then serves a plain keep-alive GET with no 1xx leaking into it (which
    would prove the proxy desynchronised the connection after the Expect exchange);
  * the ORIGIN (aitm-testtarget, read DIRECTLY, not through the proxy): the comment
    carried by the LAST bytes of a 256 KiB body is listed exactly once -- the whole
    body arrived, intact, once;
  * the store, as the AGENT: exactly one flow per marker; flow.detail has
    method/path/authority/version, the `expect: 100-continue` and `content-length`
    request headers as sent, body_size == len(body) and the inline body sha256-equal
    to the bytes sent, response.status == 302 (the final, never the interim), the
    origin's `location`, intercept=observed, meta.truncated=false, a real server_conn
    and a duration; flow.get and flow.table agree;
  * the same for an EAGER client (head + body in one write, the way curl sends after
    its patience runs out) inside a cleartext CONNECT tunnel: the proxy may omit the
    100 there (RFC: "MAY omit ... if it has already received some or all of the
    content") but must still deliver the 302 and capture it correctly.

Every property is a soft check that records a defect and keeps going, so one run
reports everything wrong with Expect handling; the suite exits 1 iff any defect was
recorded. Preconditions (env, the read tools, the origin reachable directly AND
through the proxy) are hard.

Runner contract (environment; this test never boots a core of its own):
  AITM_BUS_ADDR   host:port of the loopback MCP bus
  AITM_BUS_TOKEN  the agent token (never printed)
  AITM_PROXY_ADDR host:port of the proxy listener
  AITM_TARGET_URL base URL of the seeded aitm-testtarget (vulnerable or patched)
Missing -> exit 77 with the reason. Parallel-safe: unique markers, no global state.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import select
import socket
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402

# RFC 9110 s10.1.1 says "immediate"; curl's own patience (expect100timeout) is 1 s.
# Twice that is generous: a proxy slower than this has already stalled every curl
# upload for the full second.
CONTINUE_DEADLINE_S = 2.0
FINAL_DEADLINE_S = 20.0  # the final response after the body is on the wire
FLOW_WAIT_S = 10.0  # how long a completed flow may take to show in flow.table
BODY_PAD_BYTES = 256 * 1024  # a real upload-sized body; the marker is its LAST bytes
FORM = "application/x-www-form-urlencoded"
UA = "aitm-e2e/h1_100_continue"

DEFECTS: List[str] = []


def verify(cond: bool, msg: str) -> bool:
    """A soft check: [ok] or [FAIL] + recorded; the run continues so every Expect
    property is reported at once. The verdict at the end fails the suite."""
    if cond:
        ok(msg)
    else:
        print(f"  [FAIL] {msg}", flush=True)
        DEFECTS.append(msg)
    return cond


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


# --- the runner-provided core -------------------------------------------------


def _hostport(addr: str) -> Tuple[str, int]:
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"malformed host:port {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


class _Cfg:
    def __init__(self, agent_token: str, operator_token: Optional[str]):
        self.agent_token = agent_token
        self.operator_token = operator_token


class EnvCore:
    """The core the runner already booted, shaped like aitm_e2e.core.Aitm (bus_addr +
    cfg.agent_token) so BusClient.agent(core) works unchanged."""

    REQUIRED = ("AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_PROXY_ADDR", "AITM_TARGET_URL")

    def __init__(self) -> None:
        missing = [k for k in self.REQUIRED if not os.environ.get(k)]
        if missing:
            skip(f"no runner-provided core: {' '.join(missing)} unset (see tests/e2e/README.md)")
        self.bus_addr = _hostport(os.environ["AITM_BUS_ADDR"])
        self.cfg = _Cfg(os.environ["AITM_BUS_TOKEN"], os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None)
        self.proxy_host, self.proxy_port = _hostport(os.environ["AITM_PROXY_ADDR"])
        self.target_url = os.environ["AITM_TARGET_URL"].rstrip("/")
        netloc = urllib.parse.urlparse(self.target_url).netloc
        if not netloc:
            fail(f"AITM_TARGET_URL is not a URL: {self.target_url!r}")
        self.target_host, self.target_port = _hostport(netloc if ":" in netloc else netloc + ":80")
        self.target_authority = f"{self.target_host}:{self.target_port}"


# --- raw HTTP/1.1 on a socket (the client IS the ground truth) -------------------


@dataclass
class Final:
    status: int
    line: str
    headers: List[Tuple[str, str]]
    interims: List[int] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        return _header(self.headers, name)


def _header(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    name = name.lower()
    for k, v in headers:
        if k == name:
            return v
    return None


def _recv_more(sock: socket.socket, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("deadline passed while reading from the proxy")
    sock.settimeout(remaining)
    chunk = sock.recv(65536)
    if not chunk:
        raise EOFError("the proxy closed the connection")
    return chunk


def _recv_head(
    sock: socket.socket, buf: bytes, deadline: float, on_tick: Optional[Callable[[float], None]] = None
) -> Tuple[Optional[bytes], bytes]:
    """Read until a CRLFCRLF-terminated head is buffered. (head, rest), or (None, buf)
    when the deadline passes with no complete head. `on_tick` runs every poll slice."""
    start = time.monotonic()
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, buf
        readable, _, _ = select.select([sock], [], [], min(remaining, 0.1))
        if on_tick:
            on_tick(time.monotonic() - start)
        if not readable:
            continue
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("the proxy closed the connection before a response head")
        buf += chunk
        if len(buf) > 1 << 20:
            raise RuntimeError("response head exceeds 1 MiB")
    i = buf.index(b"\r\n\r\n") + 4
    return buf[:i], buf[i:]


def _parse_head(head: bytes) -> Tuple[int, str, List[Tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit():
        raise ValueError(f"malformed status line {status_line!r}")
    headers: List[Tuple[str, str]] = []
    for ln in lines[1:]:
        if not ln:
            continue
        name, _, value = ln.partition(":")
        headers.append((name.strip().lower(), value.strip()))
    return int(parts[1]), status_line, headers


def _read_final(sock: socket.socket, buf: bytes, deadline: float) -> Tuple[Final, bytes]:
    """Read response heads until a FINAL (non-1xx) one; interim 1xx heads are
    collected on the result (a 101 is final: it switches protocols)."""
    interims: List[int] = []
    while True:
        head, buf = _recv_head(sock, buf, deadline)
        if head is None:
            raise TimeoutError(f"no final response head within the deadline (interims so far {interims})")
        status, line, headers = _parse_head(head)
        if 100 <= status < 200 and status != 101:
            interims.append(status)
            continue
        return Final(status, line, headers, interims), buf


def _read_body(sock: socket.socket, buf: bytes, headers: List[Tuple[str, str]], deadline: float) -> Tuple[bytes, bytes]:
    """The framed response body (Content-Length or chunked). (body, leftover)."""
    te = _header(headers, "transfer-encoding") or ""
    if "chunked" in te.lower():
        body = b""
        while True:
            while b"\r\n" not in buf:
                buf += _recv_more(sock, deadline)
            line, buf = buf.split(b"\r\n", 1)
            size = int(line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while True:  # trailer section ends with an empty line
                    while b"\r\n" not in buf:
                        buf += _recv_more(sock, deadline)
                    ln, buf = buf.split(b"\r\n", 1)
                    if ln == b"":
                        return body, buf
            while len(buf) < size + 2:
                buf += _recv_more(sock, deadline)
            body += buf[:size]
            buf = buf[size + 2:]
    n = int(_header(headers, "content-length") or 0)
    while len(buf) < n:
        buf += _recv_more(sock, deadline)
    return buf[:n], buf[n:]


def _exchange(sock: socket.socket, request: bytes, buf: bytes, deadline: float) -> Tuple[Final, bytes, bytes]:
    """Send one plain request and read its final response + framed body."""
    sock.sendall(request)
    final, buf = _read_final(sock, buf, deadline)
    body, buf = _read_body(sock, buf, final.headers, deadline)
    return final, body, buf


def post_head(target: str, host: str, marker: str, body_len: int) -> bytes:
    """An absolute-form (forward-proxy) POST head carrying the 100-continue expectation."""
    return (
        f"POST {target}/comments?e2e={marker} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {FORM}\r\n"
        f"Content-Length: {body_len}\r\n"
        "Expect: 100-continue\r\n"
        f"User-Agent: {UA}\r\n"
        "\r\n"
    ).encode()


def form_body(marker: str) -> bytes:
    # The marker is the LAST field: a body that arrives short or torn loses it.
    return b"pad=" + b"a" * BODY_PAD_BYTES + f"&comment={marker}".encode()


# --- bus helpers --------------------------------------------------------------


def table_rows(bus: BusClient) -> List[dict]:
    t = bus.call("flow.table")
    rows = t.get("flows", []) if isinstance(t, dict) else (t or [])
    return [r for r in rows if isinstance(r, dict)]


def rows_for(bus: BusClient, path: str) -> List[dict]:
    return [r for r in table_rows(bus) if r.get("path") == path]


def wait_rows(bus: BusClient, path: str, pred: Callable[[dict], bool], timeout: float) -> List[dict]:
    deadline = time.monotonic() + timeout
    while True:
        rows = rows_for(bus, path)
        if any(pred(r) for r in rows):
            return rows
        if time.monotonic() >= deadline:
            return rows
        time.sleep(0.1)


def hdr(pairs, name: str) -> Optional[str]:
    """First value of `name` in a flow.detail headers array ([[name, value], ...])."""
    for p in pairs or []:
        if isinstance(p, (list, tuple)) and len(p) == 2 and str(p[0]).lower() == name:
            return str(p[1])
    return None


def b64(value) -> bytes:
    return base64.b64decode(value) if isinstance(value, str) and value else b""


def inspect_flow(agent: BusClient, label: str, path: str, core: EnvCore, sent: bytes, status: int) -> Optional[str]:
    """Cross-examine the one flow for `path` through flow.table, flow.detail and
    flow.get. Returns the flow id (None when no completed flow exists)."""
    rows = wait_rows(agent, path, lambda r: r.get("status") is not None, FLOW_WAIT_S)
    done = [r for r in rows if r.get("status") is not None]
    if not verify(len(rows) == 1 and len(done) == 1, f"{label}: exactly ONE flow for {path} and it completed (rows={rows!r})"):
        if not done:
            return None
    row = done[-1]
    fid = row["id"]
    verify(row.get("state") == "observed" and row.get("status") == status, f"{label}: flow.table row state=observed status={status} ({row!r})")

    d = agent.call("flow.detail", {"id": fid, "body": "inline"})
    req, resp = d.get("request") or {}, d.get("response")
    verify(d.get("kind") == "http" and req.get("method") == "POST" and req.get("path") == path,
           f"{label}: flow.detail is the http POST {path} (kind={d.get('kind')!r} method={req.get('method')!r} path={req.get('path')!r})")
    verify(req.get("authority") == core.target_authority and req.get("version") == "HTTP/1.1",
           f"{label}: request authority={req.get('authority')!r} version={req.get('version')!r}")
    verify((hdr(req.get("headers"), "expect") or "").lower() == "100-continue",
           f"{label}: the client's `expect: 100-continue` header is in the captured request ({hdr(req.get('headers'), 'expect')!r})")
    verify(hdr(req.get("headers"), "content-length") == str(len(sent)),
           f"{label}: captured content-length is {len(sent)} ({hdr(req.get('headers'), 'content-length')!r})")
    verify(req.get("body_size") == len(sent) and req.get("body_truncated") is False,
           f"{label}: request body_size={req.get('body_size')!r} (sent {len(sent)}), body_truncated={req.get('body_truncated')!r}")
    got = b64(req.get("body"))
    verify(hashlib.sha256(got).hexdigest() == hashlib.sha256(sent).hexdigest(),
           f"{label}: captured request body is byte-identical to the {len(sent)} bytes sent (got {len(got)} bytes)")
    resp_status = resp.get("status") if isinstance(resp, dict) else resp
    verify(isinstance(resp, dict) and resp.get("status") == status,
           f"{label}: captured response status is the FINAL {status}, never the interim 100 ({resp_status!r})")
    if isinstance(resp, dict):
        verify(hdr(resp.get("headers"), "location") == "/comments" and resp.get("body_size") == 0,
               f"{label}: captured response is the origin's redirect (location={hdr(resp.get('headers'), 'location')!r}, body_size={resp.get('body_size')!r})")
    verify(d.get("intercept") == "observed" and (d.get("meta") or {}).get("truncated") is False,
           f"{label}: intercept={d.get('intercept')!r}, meta.truncated={(d.get('meta') or {}).get('truncated')!r}")
    sc = d.get("server_conn")
    verify(isinstance(sc, dict) and str(sc.get("peer", "")).endswith(f":{core.target_port}"),
           f"{label}: server_conn is the real origin socket ({sc!r})")
    verify(isinstance((d.get("meta") or {}).get("duration_ms"), int),
           f"{label}: meta.duration_ms recorded ({(d.get('meta') or {}).get('duration_ms')!r})")
    g = agent.call("flow.get", {"id": fid})
    verify(g.get("status") == status and g.get("method") == "POST" and g.get("intercept") == "observed",
           f"{label}: flow.get agrees (status={g.get('status')!r} method={g.get('method')!r} intercept={g.get('intercept')!r})")
    return fid


def origin_get(core: EnvCore, path: str) -> Tuple[int, str]:
    """Read the origin DIRECTLY (no proxy): the independent observer."""
    conn = http.client.HTTPConnection(core.target_host, core.target_port, timeout=10)
    try:
        conn.request("GET", path, headers={"Host": core.target_authority})
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


# --- the scenario -------------------------------------------------------------


def main() -> int:
    core = EnvCore()
    run = f"h1c{uuid.uuid4().hex[:10]}"
    m_strict, m_ka, m_eager = f"{run}-strict", f"{run}-keepalive", f"{run}-eager"
    path_strict, path_eager = f"/comments?e2e={m_strict}", f"/comments?e2e={m_eager}"
    body_strict, body_eager = form_body(m_strict), form_body(m_eager)
    proxy = (core.proxy_host, core.proxy_port)

    agent = BusClient.agent(core)
    sock: Optional[socket.socket] = None
    tunnel: Optional[socket.socket] = None
    try:
        section("preflight: the runner's core, its read tools, and the origin (direct)")
        names = set(agent.tool_names())
        need = ["flow.table", "flow.detail", "flow.get"]
        missing = [n for n in need if n not in names]
        check(not missing, f"live tools/list registers {need} (missing: {missing or 'none'})")
        st, _ = origin_get(core, "/")
        check(st == 200, f"origin {core.target_url} answers GET / directly ({st})")
        ok(f"proxy {core.proxy_host}:{core.proxy_port}; origin {core.target_authority}; run {run}; body {len(body_strict)} bytes")

        section("control: a plain GET through the proxy (precondition), then a second on the same connection")
        s = socket.create_connection(proxy, timeout=FINAL_DEADLINE_S)
        buf = b""
        req1 = f"GET {core.target_url}/?e2e={run}-ctl1 HTTP/1.1\r\nHost: {core.target_authority}\r\nUser-Agent: {UA}\r\n\r\n".encode()
        try:
            f1, body1, buf = _exchange(s, req1, buf, time.monotonic() + FINAL_DEADLINE_S)
        except (OSError, EOFError, TimeoutError, ValueError, RuntimeError) as e:
            fail(f"precondition: a plain GET {core.target_url}/ through the proxy got no response ({type(e).__name__}: {e})")
        check(f1.status == 200 and b"aitm test target" in body1,
              f"precondition: a plain GET through the proxy reaches the origin and relays its page (status {f1.status})")
        keepalive_ok = False
        try:
            req2 = f"GET {core.target_url}/?e2e={run}-ctl2 HTTP/1.1\r\nHost: {core.target_authority}\r\nUser-Agent: {UA}\r\n\r\n".encode()
            f2, _, buf = _exchange(s, req2, buf, time.monotonic() + FINAL_DEADLINE_S)
            keepalive_ok = f2.status == 200
        except (OSError, EOFError, TimeoutError, ValueError, RuntimeError) as e:
            note(f"a second plain GET on the same connection did not survive ({type(e).__name__}: {e})")
        finally:
            s.close()
        if keepalive_ok:
            ok("a second plain GET on the same client connection answered 200: the proxy keeps client connections alive")
        else:
            note("plain keep-alive did not survive on this core; keep-alive AFTER the Expect exchange is reported, not judged")

        section("act 1: STRICT client -- head with Expect: 100-continue, body WITHHELD until answered")
        sock = socket.create_connection(proxy, timeout=FINAL_DEADLINE_S)
        buf = b""
        head_row: Optional[dict] = None
        polled = {"done": False}

        def on_tick(elapsed: float) -> None:
            # While the client waits, is the head alone already a flow in the store?
            nonlocal head_row
            if not polled["done"] and elapsed >= 0.5:
                polled["done"] = True
                rows = rows_for(agent, path_strict)
                head_row = rows[-1] if rows else None

        t_head = time.monotonic()
        sock.sendall(post_head(core.target_url, core.target_authority, m_strict, len(body_strict)))
        closed_early: Optional[str] = None
        try:
            first, buf = _recv_head(sock, buf, t_head + CONTINUE_DEADLINE_S, on_tick)
        except (EOFError, ConnectionError) as e:
            first, closed_early = None, f"{type(e).__name__}: {e}"
        waited = time.monotonic() - t_head
        early_final: Optional[Final] = None
        if closed_early:
            verify(False, f"the proxy dropped the connection {waited * 1000:.1f} ms after an Expect: 100-continue head, before any body was sent ({closed_early})")
            early_final = Final(0, "<connection dropped>", [])
        elif first is None:
            verify(False, f"the proxy answered the 100-continue expectation within {CONTINUE_DEADLINE_S:.1f}s (nothing arrived in {waited:.3f}s; "
                          "RFC 9110 s10.1.1: MUST send 100 Continue or a final status immediately, MUST NOT wait for the content; "
                          "curl waits only 1 s before sending anyway)")
        else:
            status, line, first_headers = _parse_head(first)
            if status == 100:
                verify(True, f"the proxy answered `{line}` {waited * 1000:.1f} ms after the head, before any body byte was sent")
            elif 100 < status < 200 and status != 101:
                verify(False, f"the proxy answered an interim `{line}` instead of 100 Continue ({waited * 1000:.1f} ms)")
            else:
                early_final = Final(status, line, first_headers)
                verify(False, f"the proxy answered a FINAL `{line}` before the body of a valid POST was sent ({waited * 1000:.1f} ms): the upload was refused")
        # Informational only (a design choice, not part of the Expect contract): does
        # the store already show the head-only flow while the client waits?
        if polled["done"]:
            if head_row is not None and head_row.get("status") is None:
                note("while the client waited, the head alone was already a flow in the store (status null): a UI sees the upload in progress")
            else:
                note(f"while the client waited, the store did not yet show a head-only flow ({head_row!r}); not judged")
        else:
            note("the proxy answered before 0.5 s; the head-only store observation did not run")

        strict_final: Optional[Final] = early_final
        strict_sent = False
        if early_final is None:
            if first is None:
                note("sending the body anyway (curl semantics after its patience runs out)")
            t_body = time.monotonic()
            sock.sendall(body_strict)
            strict_sent = True
            strict_final, buf = _read_final(sock, buf, t_body + FINAL_DEADLINE_S)
            resp_body, buf = _read_body(sock, buf, strict_final.headers, time.monotonic() + FINAL_DEADLINE_S)
            ok(f"final `{strict_final.line}` {(time.monotonic() - t_body) * 1000:.1f} ms after the body; interims seen after the body: {strict_final.interims}")
            verify(strict_final.status == 302 and strict_final.header("location") == "/comments",
                   f"strict: final status 302 Found -> /comments (got {strict_final.status}, location={strict_final.header('location')!r})")
            verify(resp_body == b"" and (strict_final.header("content-length") in ("0", None)),
                   f"strict: the redirect's framed body is empty ({len(resp_body)} bytes, content-length={strict_final.header('content-length')!r})")
            verify(buf == b"", f"strict: no stray bytes after the framed final response ({buf[:80]!r})")
            if first is None:
                note(f"interims relayed after the body: {strict_final.interims} (a late 100 is permitted here; none is too)")

            section("act 2: the SAME client connection must still serve a plain keep-alive GET")
            conn_hdr = (strict_final.header("connection") or "").lower()
            if "close" in conn_hdr:
                note(f"the final response announced `connection: {conn_hdr}`; the proxy may close, keep-alive is not judged")
            else:
                try:
                    req = f"GET {core.target_url}/comments?e2e={m_ka} HTTP/1.1\r\nHost: {core.target_authority}\r\nUser-Agent: {UA}\r\n\r\n".encode()
                    ka_final, ka_body, buf = _exchange(sock, req, buf, time.monotonic() + FINAL_DEADLINE_S)
                    verify(ka_final.status == 200, f"keep-alive GET after the Expect exchange answered {ka_final.status} (expected 200)")
                    verify(ka_final.interims == [], f"no 1xx leaked into the next exchange on the connection (interims={ka_final.interims})")
                    verify(f"<li>{m_strict}</li>" in ka_body.decode("utf-8", "replace"),
                           "the GET (via the proxy) lists the comment the strict POST carried")
                    verify(buf == b"", f"no stray bytes after the keep-alive response ({buf[:80]!r})")
                except (EOFError, TimeoutError, OSError) as e:
                    if keepalive_ok:
                        verify(False, f"the proxy dropped the client connection after the Expect exchange without `connection: close` ({type(e).__name__}: {e}) -- plain keep-alive works on this core")
                    else:
                        note(f"keep-alive after Expect did not survive ({type(e).__name__}: {e}); plain keep-alive did not either, so not judged")
        else:
            note("skipping the body and the keep-alive follow-up: the proxy already answered with a final status")

        section("act 3: EAGER client inside a CONNECT tunnel -- Expect header, head + body in one write")
        tunnel = socket.create_connection(proxy, timeout=FINAL_DEADLINE_S)
        tbuf = b""
        connect = f"CONNECT {core.target_authority} HTTP/1.1\r\nHost: {core.target_authority}\r\n\r\n".encode()
        tunnel.sendall(connect)
        c_final, tbuf = _read_final(tunnel, tbuf, time.monotonic() + FINAL_DEADLINE_S)
        check(c_final.status == 200, f"CONNECT {core.target_authority} through the proxy answered {c_final.status}")
        eager_head = (
            f"POST {path_eager} HTTP/1.1\r\nHost: {core.target_authority}\r\nContent-Type: {FORM}\r\n"
            f"Content-Length: {len(body_eager)}\r\nExpect: 100-continue\r\nUser-Agent: {UA}\r\n\r\n"
        ).encode()
        t_eager = time.monotonic()
        tunnel.sendall(eager_head + body_eager)
        e_final, tbuf = _read_final(tunnel, tbuf, t_eager + FINAL_DEADLINE_S)
        e_body, tbuf = _read_body(tunnel, tbuf, e_final.headers, time.monotonic() + FINAL_DEADLINE_S)
        ok(f"eager: final `{e_final.line}` in {(time.monotonic() - t_eager) * 1000:.1f} ms; interims: {e_final.interims}")
        verify(e_final.status == 302 and e_final.header("location") == "/comments",
               f"eager: final status 302 -> /comments (got {e_final.status}, location={e_final.header('location')!r})")
        verify(e_body == b"" and tbuf == b"", f"eager: empty redirect body and no stray bytes ({len(e_body)} body bytes, leftover {tbuf[:80]!r})")
        verify(all(s == 100 for s in e_final.interims) and len(e_final.interims) <= 1,
               f"eager: at most one interim and only a 100 ({e_final.interims})")

        section("ground truth: the store, as the agent (flow.table / flow.detail / flow.get)")
        if strict_sent and strict_final is not None:
            inspect_flow(agent, "strict", path_strict, core, body_strict, strict_final.status)
        else:
            rows = rows_for(agent, path_strict)
            verify(False, f"strict: the POST never completed through the proxy; store rows for it: {rows!r}")
        inspect_flow(agent, "eager", path_eager, core, body_eager, e_final.status)
        ka_rows = rows_for(agent, f"/comments?e2e={m_ka}")
        if ka_rows:
            verify(ka_rows[-1].get("status") == 200 and ka_rows[-1].get("method") == "GET",
                   f"keep-alive GET captured as its own flow with status 200 ({ka_rows[-1]!r})")

        section("ground truth: the ORIGIN lists each upload's comment exactly once (read directly)")
        st, html = origin_get(core, "/comments")
        check(st == 200, f"origin GET /comments (direct) answered {st}")
        n_strict, n_eager = html.count(f"<li>{m_strict}</li>"), html.count(f"<li>{m_eager}</li>")
        verify(n_strict == 1, f"origin lists the strict upload's comment exactly once ({n_strict}x) -- the LAST bytes of the {len(body_strict)}-byte body arrived, once")
        verify(n_eager == 1, f"origin lists the eager upload's comment exactly once ({n_eager}x)")
        verify(html.count(run) == n_strict + n_eager,
               f"no other trace of this run at the origin: no duplicated or torn upload (run id appears {html.count(run)}x, comments {n_strict + n_eager})")

        section("verdict")
        if DEFECTS:
            print(f"  {len(DEFECTS)} defect(s) in Expect: 100-continue handling:", flush=True)
            for d in DEFECTS:
                print(f"    - {d}", flush=True)
            fail(f"{len(DEFECTS)} defect(s); see the list above")
        ok(f"Expect: 100-continue handled and captured correctly (strict + eager, {len(body_strict)}-byte bodies)")
    finally:
        for s in (sock, tunnel):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        agent.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
