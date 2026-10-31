#!/usr/bin/env python3
# e2e: tier=T1 surface=proto
"""proto/test_chunked_trailers -- a chunked HTTP/1.1 response WITH a trailer section
is decoded, forwarded and captured correctly by a REAL aitm core: every body byte,
the framing on the client wire, the connection after it, and what became of the
trailer fields themselves.

Why this cell exists: `Transfer-Encoding: chunked` + trailers is the one HTTP/1.1
body shape where a proxy can look right and be wrong. A decoder that pattern-matches
`0\\r\\n\\r\\n` truncates on a decoy; one that forgets the trailer section leaves the
trailer lines in the upstream buffer, where they are read as the START of the next
response on that kept-alive connection (desync); one that re-frames the head but not
the body smuggles. The core's parser is sans-IO (crates/aitm-proto-http/src/sansio.rs,
`step_chunked`) and is driven both by the proxy (module.rs, capture-while-streaming)
and by the reissue sender (sender.rs, `request.send`); this suite drives both for real.

What is proved, on GROUND TRUTH (never a fixture, never the proxy's own view):

  origin   a REAL HTTP/1.1 upstream this script runs on a raw socket. It RECORDS
           every request (and the upstream connection it arrived on) and answers
           `/chunked/...` with a chunked body built to break lazy decoders: a 1-byte
           chunk, a chunk with a chunk extension, a chunk whose data CONTAINS the
           bytes `\\r\\n0\\r\\n\\r\\n` (a decoy terminator), an UPPERCASE-hex 40 000-byte
           chunk (> the proxy's 16 KiB read size), a 128 KiB chunk written in pieces
           with pauses (chunk data spans many socket reads), then `0\\r\\n`, a pause,
           three trailer fields, and the empty line. The body is derived from a
           per-run marker (printed), so every byte is known here and compared
           byte-for-byte.

  client   a REAL HTTP/1.1 client on ONE raw keep-alive socket to the proxy
           listener (absolute-form, `TE: trailers`), sending THREE requests in
           sequence: chunked -> plain (Content-Length) -> chunked. Responses 1 and 3
           must decode to the origin body exactly, with NOTHING left over on the
           socket after each; response 2 must arrive intact on the SAME client
           connection, served over the SAME upstream connection (the origin's own
           record says which) -- the only way that holds is if the proxy consumed
           the trailer section exactly.

  bus      the agent role over the real MCP bus: flow.table rows for exactly the
           flows this script sent, flow.get, flow.detail with the inline body
           (base64) byte-equal to the origin body, body_size, body_truncated,
           meta.truncated, a `range` slice, request/response headers as sent, and
           server_conn naming the real origin socket.

  reissue  `request.send` (the Http1Sender path) against the same origin: the
           origin records exactly one reissued request and the captured flow's
           body is byte-identical. Needs the origin in scope (see below); when it
           cannot be, the leg is reported as not run.

  trailers asserted LAST so every other piece of evidence prints first. HARD: any
           trailer field that IS forwarded to the client is byte-identical to what
           the origin sent, and no field the origin never sent appears (a desync
           symptom). HARD BY DEFAULT since PR #150 (the core now forwards chunked
           trailers to the client and exposes them as response.trailers over the
           bus): the fields MUST reach the `TE: trailers` client and be visible on
           the bus, so a silent regression to dropping them FAILS the suite. RFC 9112
           s7.1.2 still permits an intermediary to discard trailers, so a core that
           deliberately does is not wrong -- set AITM_E2E_STRICT_TRAILERS=0 to
           downgrade trailer propagation back to observed (printed, not judged).

Scope: on the default posture the passive forward-proxy path reaches a loopback
origin without scope (verified live), while the ACTIVE path (`request.send`, via the
guarded `ProxyClient`) refuses an out-of-scope authority, and a confined posture
(`confine_egress_to_scope`) or the SSRF guard (aitm-core guard.rs) can refuse the
passive dial too. So this suite first PROVES reachability with a plain request
through the proxy; if the core refuses the loopback origin it widens scope for
`127.0.0.1:<this port only>` (operator confirm if AITM_BUS_OPERATOR_TOKEN is set,
else an agent `scope.add`, which the agent policy / allow_agent_widen may refuse),
removes the entry again at the end, and exits 77 with the reason when neither is
possible. The reissue leg widens the same way and is reported as not run when it
cannot.

Every protocol property is a soft check that records a defect and keeps going, so
one run reports everything wrong with chunked+trailer handling; the suite exits 1
iff a defect was recorded. Preconditions (env, tools, reachability) are hard.

Runner contract (environment; this suite never boots a core of its own):
  AITM_BUS_ADDR            host:port of the loopback MCP bus
  AITM_BUS_TOKEN           the agent token (never printed)
  AITM_PROXY_ADDR          host:port of the proxy listener
  AITM_BUS_OPERATOR_TOKEN  optional; lets the suite widen scope as the operator
  AITM_E2E_STRICT_TRAILERS optional; `0` downgrades trailer propagation to observed (hard by default)
Missing -> exit 77 with the reason. Parallel-safe: random origin port, unique
marker, only this run's scope entry touched, no global core state otherwise.
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient, BusError, ToolError  # noqa: E402

ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)
ENV_STRICT = "AITM_E2E_STRICT_TRAILERS"
IO_TIMEOUT_S = 20.0
BUS_WAIT_S = 15.0
SEND_WAIT_S = 25.0
WIDEN_WAIT_S = 5.0  # an agent scope.add parked under the Ask policy with no operator
END_MARK = b"<END-OF-BODY>"
DECOY = b"\r\n0\r\n\r\n"  # a chunk terminator INSIDE chunk data
UA = "aitm-e2e/chunked_trailers"

DEFECTS: List[str] = []


def verify(cond: bool, msg: str) -> bool:
    """A soft check: [ok] or [FAIL] + recorded; the run continues so every property
    is reported at once. The verdict at the end fails the suite."""
    if cond:
        ok(msg)
    else:
        print(f"  [FAIL] {msg}", flush=True)
        DEFECTS.append(msg)
    return cond


def note(msg: str) -> None:
    print(f"  [note] {msg}", flush=True)


def observe(cond: bool, msg: str) -> bool:
    """Report a property without judging it (strict mode turns it into verify)."""
    if cond:
        ok(msg)
    else:
        note(f"NOT: {msg} (observed, not judged; {ENV_STRICT}=0 downgraded it)")
    return cond


# ---- the core: provided by the runner (env) --------------------------------------

def _hostport(addr: str) -> Tuple[str, int]:
    host, sep, port = addr.strip().rpartition(":")
    if not sep or not port.isdigit():
        fail(f"malformed host:port {addr!r}")
    return (host.strip("[]") or "127.0.0.1"), int(port)


def env_core():
    """The core the runner already booted, shaped like aitm_e2e.core.Aitm (bus_addr +
    cfg.agent_token / cfg.operator_token) so BusClient.agent/operator work unchanged."""
    missing = [k for k in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR) if not os.environ.get(k)]
    if missing:
        skip(f"no runner-provided core: {' '.join(missing)} unset; this suite never boots its own "
             f"(see tests/e2e/README.md)")
    host, port = _hostport(os.environ[ENV_BUS_ADDR])
    proxy_host, proxy_port = _hostport(os.environ[ENV_PROXY_ADDR])
    cfg = SimpleNamespace(agent_token=os.environ[ENV_BUS_TOKEN],
                          operator_token=os.environ.get(ENV_OP_TOKEN) or None)
    return SimpleNamespace(bus_addr=(host, port), cfg=cfg, proxy_host=proxy_host, proxy_port=proxy_port)


# ---- the origin: a real HTTP/1.1 upstream that answers chunked WITH trailers -------

class ChunkedOrigin:
    """Loopback HTTP/1.1 origin on a raw socket. Keep-alive per connection, honours
    `Connection: close`, RECORDS every request with the connection it came on (the
    independent observer), and answers `/chunked/...` with `chunks` + `trailers`,
    `/plain/...` with a Content-Length body, anything else 404."""

    def __init__(self, marker: str, chunks: List[Tuple[str, bytes]], trailers: List[Tuple[str, str]]):
        self.marker = marker
        self.chunks = chunks
        self.trailers = trailers
        self.plain_body = f"plain-ok:{marker}".encode()
        self.received: List[dict] = []
        self.lock = threading.Lock()
        self._conns = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept, name="chunked-origin", daemon=True)

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    def start(self) -> "ChunkedOrigin":
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def recorded(self, path: str) -> List[dict]:
        with self.lock:
            return [r for r in self.received if r["path"] == path]

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with self.lock:
                self._conns += 1
                cid = self._conns
            threading.Thread(target=self._serve, args=(conn, cid), daemon=True).start()

    def _serve(self, conn: socket.socket, cid: int) -> None:
        conn.settimeout(IO_TIMEOUT_S)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    data = conn.recv(65536)
                    if not data:
                        return
                    buf += data
                head, buf = buf.split(b"\r\n\r\n", 1)
                lines = head.decode("latin1").split("\r\n")
                parts = lines[0].split(" ")
                if len(parts) != 3:
                    return
                method, target, _version = parts
                headers: dict = {}
                for ln in lines[1:]:
                    name, _, value = ln.partition(":")
                    headers.setdefault(name.strip().lower(), []).append(value.strip())
                length = int((headers.get("content-length") or ["0"])[0])
                while len(buf) < length:
                    data = conn.recv(65536)
                    if not data:
                        return
                    buf += data
                buf = buf[length:]
                if target.startswith("/"):
                    path = target
                else:  # absolute-form reached the origin: keep path+query
                    u = urlsplit(target)
                    path = u.path + (f"?{u.query}" if u.query else "")
                close = any("close" in v.lower() for v in headers.get("connection", []))
                with self.lock:
                    self.received.append({
                        "method": method, "path": path, "headers": headers, "conn": cid, "close": close,
                    })
                if path.startswith("/chunked/"):
                    self._send_chunked(conn)
                elif path.startswith("/plain/"):
                    self._send_plain(conn, 200, "OK", "text/plain", self.plain_body)
                else:
                    self._send_plain(conn, 404, "Not Found", "text/plain", b"no such route")
                if close:
                    return
        except (OSError, ValueError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send_plain(self, conn: socket.socket, status: int, reason: str, ctype: str, body: bytes) -> None:
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"X-Origin-Marker: {self.marker}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
        ).encode()
        conn.sendall(head + body)

    def _send_chunked(self, conn: socket.socket) -> None:
        declared = ", ".join(name for name, _ in self.trailers)
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"X-Origin-Marker: {self.marker}\r\n"
            f"Trailer: {declared}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ).encode()
        conn.sendall(head)
        time.sleep(0.01)  # the head in its own segment; the body follows in later reads
        for size_line, data in self.chunks:
            conn.sendall(size_line.encode() + b"\r\n")
            for i in range(0, len(data), 20_000):  # pieces: chunk data spans socket reads
                conn.sendall(data[i:i + 20_000])
                time.sleep(0.002)
            conn.sendall(b"\r\n")
        time.sleep(0.01)
        conn.sendall(b"0\r\n")
        time.sleep(0.02)  # the trailer section arrives in a LATER read than the zero chunk
        for name, value in self.trailers:
            conn.sendall(f"{name}: {value}\r\n".encode())
        conn.sendall(b"\r\n")


def build_chunks(marker: str) -> List[Tuple[str, bytes]]:
    """The chunked body, as (chunk-size line, data) pairs. Deterministic from the
    marker (printed), so a failure is reproducible byte for byte."""
    rnd = random.Random(f"aitm-e2e-chunked-trailers:{marker}")
    return [
        ("1", rnd.randbytes(1)),                        # a 1-byte chunk
        ("f;e2e=ext", rnd.randbytes(15)),               # lowercase hex + a chunk extension
        ("40", DECOY + rnd.randbytes(64 - len(DECOY))),  # data CONTAINING a decoy terminator
        ("9C40", rnd.randbytes(40_000)),                # UPPERCASE hex, > the proxy's 16 KiB read
        ("20000", rnd.randbytes(131_072)),              # 128 KiB, written in pieces with pauses
        (format(len(END_MARK), "x"), END_MARK),         # a recognisable tail for the range probe
    ]


# ---- the client: one raw keep-alive socket to the proxy ----------------------------

class WireResponse:
    def __init__(self) -> None:
        self.version = ""
        self.status = 0
        self.reason = ""
        self.headers: List[Tuple[str, str]] = []
        self.body = b""
        self.trailers: List[Tuple[str, str]] = []
        self.framing = ""  # chunked | length | close
        self.chunk_count = 0

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def header_count(self, name: str) -> int:
        return sum(1 for k, _ in self.headers if k.lower() == name.lower())


class RawProxyClient:
    """A real HTTP/1.1 client speaking to the proxy listener in absolute-form on
    one socket, with its own chunked decoder that KEEPS the trailer section."""

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=IO_TIMEOUT_S)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        self.eof = False

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, method: str, url: str, headers: List[Tuple[str, str]]) -> None:
        lines = [f"{method} {url} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    def _fill(self) -> bool:
        data = self.sock.recv(65536)
        if not data:
            self.eof = True
            return False
        self.buf += data
        return True

    def _read_until(self, delim: bytes, what: str) -> bytes:
        while True:
            i = self.buf.find(delim)
            if i >= 0:
                out, self.buf = self.buf[:i], self.buf[i + len(delim):]
                return out
            if not self._fill():
                raise EOFError(f"connection closed by the proxy while reading {what} "
                               f"({len(self.buf)} byte(s) buffered)")

    def _read_exact(self, n: int, what: str) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                raise EOFError(f"connection closed by the proxy while reading {what} "
                               f"({len(self.buf)}/{n} bytes)")
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_response(self) -> WireResponse:
        r = WireResponse()
        head = self._read_until(b"\r\n\r\n", "the response head").decode("latin1")
        lines = head.split("\r\n")
        first = lines[0].split(" ", 2)
        if len(first) < 2 or not first[1].isdigit():
            raise ValueError(f"malformed status line {lines[0]!r}")
        r.version, r.status = first[0], int(first[1])
        r.reason = first[2] if len(first) == 3 else ""
        for ln in lines[1:]:
            name, _, value = ln.partition(":")
            r.headers.append((name.strip(), value.strip()))
        te = r.header("transfer-encoding")
        cl = r.header("content-length")
        if te is not None and te.split(",")[-1].strip().lower() == "chunked":
            r.framing = "chunked"
            while True:
                size_line = self._read_until(b"\r\n", "a chunk-size line").decode("latin1")
                size = int(size_line.split(";", 1)[0].strip(), 16)
                if size == 0:
                    break
                r.body += self._read_exact(size, f"chunk data ({size} bytes)")
                r.chunk_count += 1
                crlf = self._read_exact(2, "the CRLF after chunk data")
                if crlf != b"\r\n":
                    raise ValueError(f"chunk data not followed by CRLF (got {crlf!r})")
            while True:
                line = self._read_until(b"\r\n", "the trailer section")
                if line == b"":
                    break
                name, _, value = line.decode("latin1").partition(":")
                r.trailers.append((name.strip(), value.strip()))
        elif cl is not None:
            r.framing = "length"
            r.body = self._read_exact(int(cl), "a Content-Length body")
        else:
            r.framing = "close"
            while self._fill():
                pass
            r.body, self.buf = self.buf, b""
        return r


def probe_via_proxy(core, url: str, authority: str) -> Tuple[Optional[WireResponse], str]:
    """One plain GET through the proxy on a throwaway connection. (response, '') or
    (None, why) when the proxy refused/dropped it (the SSRF/scope guard drops the
    client connection before any response byte)."""
    c: Optional[RawProxyClient] = None
    try:
        c = RawProxyClient(core.proxy_host, core.proxy_port)
        c.send("GET", url, [("Host", authority), ("User-Agent", UA), ("Connection", "close")])
        return c.read_response(), ""
    except (EOFError, ValueError, OSError) as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        if c:
            c.close()


# ---- scope: widen for this origin only, and give it back -----------------------------

class ScopeLease:
    """Adds `127.0.0.1:<port>` (this run's origin only) to the core's scope through
    whichever role can, and removes it again. Operator first (a human-equivalent
    authorisation), else the agent when the core opted in (allow_agent_widen)."""

    def __init__(self, core):
        self.core = core
        self.bus: Optional[BusClient] = None
        self.how = ""
        self.entry: Optional[str] = None
        self.refusals: List[str] = []

    def widen(self, entry: str) -> Optional[str]:
        if self.entry:
            return self.how
        if self.core.cfg.operator_token:
            op = None
            try:
                op = BusClient.operator(self.core)
                op.confirm("scope.add", {"host": entry})
                self.bus, self.how, self.entry = op, "operator scope.add", entry
                return self.how
            except (ToolError, BusError, OSError) as e:
                if op:
                    op.close()
                self.refusals.append(f"operator scope.add: {e}")
        w = None
        try:
            w = BusClient.agent(self.core)
            w._set_read_timeout(WIDEN_WAIT_S)  # an Ask-policy park must not hang the suite
            w.call("scope.add", {"host": entry})
            w._restore_read_timeout()
            self.bus, self.how, self.entry = w, "agent scope.add (scope.allow_agent_widen)", entry
            return self.how
        except (ToolError, BusError) as e:
            self.refusals.append(f"agent scope.add: {e}")
        except (socket.timeout, TimeoutError, OSError):
            self.refusals.append(f"agent scope.add: no answer in {WIDEN_WAIT_S:.0f}s "
                                 "(parked for an absent operator under the Ask policy?)")
        if w:
            w.close()
        return None

    def release(self) -> None:
        if not self.bus or not self.entry:
            return
        try:
            if self.how.startswith("operator"):
                self.bus.confirm("scope.remove", {"host": self.entry})
            else:
                self.bus.try_call("scope.remove", {"host": self.entry})
        except (ToolError, BusError, OSError):
            pass
        finally:
            self.bus.close()
            self.bus = None


# ---- bus helpers ------------------------------------------------------------------

def table_rows(bus: BusClient) -> List[dict]:
    t = bus.call("flow.table")
    rows = t.get("flows", []) if isinstance(t, dict) else (t or [])
    return [r for r in rows if isinstance(r, dict)]


def rows_for_paths(bus: BusClient, paths: List[str]) -> List[dict]:
    want = set(paths)
    return [r for r in table_rows(bus) if r.get("path") in want]


def wait_rows(bus: BusClient, paths: List[str], timeout: float) -> Tuple[dict, List[dict]]:
    """(path -> completed row) for every path that completed within `timeout`, plus
    every row for these paths as last seen."""
    deadline = time.monotonic() + timeout
    while True:
        rows = rows_for_paths(bus, paths)
        done = {r["path"]: r for r in rows if r.get("status") is not None}
        if all(p in done for p in paths) or time.monotonic() >= deadline:
            return done, rows
        time.sleep(0.1)


def body_bytes(msg: dict) -> Optional[bytes]:
    b = msg.get("body")
    if b is None:
        return None
    return base64.b64decode(b)


def header_pairs(msg: dict) -> List[Tuple[str, str]]:
    out = []
    for pair in msg.get("headers") or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            out.append((str(pair[0]).lower(), str(pair[1])))
    return out


def visible_fields(resp: dict) -> List[Tuple[str, str]]:
    """Every (name, value) a bus client can see on a captured response: the header
    list plus a `trailers` field in any reasonable shape, if the core emits one."""
    out = header_pairs(resp)
    tr = resp.get("trailers")
    if isinstance(tr, list):
        for item in tr:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((str(item[0]).lower(), str(item[1])))
            elif isinstance(item, dict) and "name" in item:
                out.append((str(item["name"]).lower(), str(item.get("value", ""))))
    elif isinstance(tr, dict):
        for k, v in tr.items():
            out.append((str(k).lower(), str(v)))
    return out


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---- the scenario -----------------------------------------------------------------

def main() -> int:
    core = env_core()
    strict = os.environ.get(ENV_STRICT, "1") != "0"  # trailer propagation hard by default (PR #150); =0 downgrades to observed
    judge = verify if strict else observe
    marker = f"ct-{uuid.uuid4().hex[:12]}"
    chunks = build_chunks(marker)
    body = b"".join(data for _, data in chunks)
    digest = sha(body)
    trailers = [
        ("X-Checksum-SHA256", digest),
        ("X-E2E-Trailer", marker),
        ("Server-Timing", "origin;dur=1"),
    ]
    origin = ChunkedOrigin(marker, chunks, trailers).start()
    p_pre, p_first, p_plain, p_again, p_send = (
        f"/plain/{marker}/preflight", f"/chunked/{marker}/first", f"/plain/{marker}/keepalive",
        f"/chunked/{marker}/again", f"/chunked/{marker}/reissue",
    )
    main_paths = [p_first, p_plain, p_again]
    url = lambda p: f"http://{origin.authority}{p}"  # noqa: E731
    common = [("Host", origin.authority), ("TE", "trailers"), ("Connection", "TE"), ("User-Agent", UA)]

    scope = ScopeLease(core)
    agent: Optional[BusClient] = None
    client: Optional[RawProxyClient] = None
    try:
        section("preflight: the runner's core, its read tools, and the origin reachable THROUGH the proxy")
        ok(f"runner core: bus {core.bus_addr[0]}:{core.bus_addr[1]}, proxy {core.proxy_host}:{core.proxy_port}, "
           f"operator token {'present' if core.cfg.operator_token else 'absent'}, strict trailers={'on' if strict else 'off'}")
        ok(f"origin {origin.authority}: {len(chunks)} chunks = {len(body)} bytes, sha256 {digest[:16]}.., "
           f"{len(trailers)} trailer fields; marker {marker}")
        agent = BusClient.agent(core)
        names = set(agent.tool_names())
        need = ["flow.table", "flow.get", "flow.detail"]
        missing = [n for n in need if n not in names]
        check(not missing, f"live tools/list registers {need} (missing: {missing or 'none'})")

        pre, why = probe_via_proxy(core, url(p_pre), origin.authority)
        if pre is None or pre.status != 200:
            note(f"plain GET {p_pre} through the proxy did not succeed "
                 f"({why or f'status {pre.status}'}); this core's scope/SSRF posture refuses the unscoped loopback origin")
            how = scope.widen(origin.authority)
            if how is None:
                skip(f"the core refuses the loopback origin {origin.authority} and this suite cannot widen scope "
                     f"({'; '.join(scope.refusals)}); set {ENV_OP_TOKEN} or scope.allow_agent_widen")
            ok(f"scope widened for {origin.authority} via {how}")
            pre, why = probe_via_proxy(core, url(p_pre), origin.authority)
            if pre is None or pre.status != 200:
                skip(f"the loopback origin {origin.authority} is still unreachable through the proxy after "
                     f"{how} ({why or f'status {pre.status}'})")
        check(pre.body == origin.plain_body, f"preflight GET {p_pre} through the proxy returned the origin's body "
                                              f"({pre.status}, {len(pre.body)} bytes)")
        check(len(origin.recorded(p_pre)) == 1, "the origin recorded the preflight request exactly once")

        section("act: ONE keep-alive client socket through the proxy: chunked -> plain -> chunked")
        client = RawProxyClient(core.proxy_host, core.proxy_port)
        wire: dict = {}
        leftover: dict = {}
        reconnects = 0
        for label, p in (("response 1", p_first), ("response 2", p_plain), ("response 3", p_again)):
            if client.eof:
                reconnects += 1
                client.close()
                client = RawProxyClient(core.proxy_host, core.proxy_port)
            try:
                client.send("GET", url(p), common)
                w = client.read_response()
            except (EOFError, ValueError, OSError) as e:
                verify(False, f"{label} ({p}): the proxy did not deliver a well-formed response ({type(e).__name__}: {e})")
                client.eof = True
                continue
            wire[p], leftover[p] = w, len(client.buf)
            extra = f", {len(w.trailers)} trailer field(s) on the wire" if w.framing == "chunked" else ""
            ok(f"{label}: {w.status} {w.reason}, framing={w.framing}, {len(w.body)} bytes in {w.chunk_count} chunk(s){extra}")
        w1, w2, w3 = wire.get(p_first), wire.get(p_plain), wire.get(p_again)

        section("ground truth A: the origin's own record")
        for p in main_paths:
            got = origin.recorded(p)
            verify(len(got) == 1 and got[0]["method"] == "GET",
                   f"origin recorded GET {p} exactly once ({len(got)}x{', method ' + got[0]['method'] if got else ''})")
        conns = sorted({r["conn"] for p in main_paths for r in origin.recorded(p)})
        if reconnects == 0:
            verify(len(conns) == 1,
                   f"the origin served all three requests over ONE upstream connection {conns}: the proxy reused it, "
                   f"so the trailer section had to be consumed exactly for request 2 to parse")
        else:
            note(f"client reconnected {reconnects}x; upstream connection reuse {conns} is reported, not judged")
        te_seen = (origin.recorded(p_first) or [{}])[0].get("headers", {}).get("te")
        note(f"the client's `TE: trailers` reached the origin as {te_seen}")

        section("ground truth B: the client wire -- framing integrity and the body, byte for byte")
        for label, p in (("response 1", p_first), ("response 3", p_again)):
            w = wire.get(p)
            if w is None:
                verify(False, f"{label}: no response to compare")
                continue
            te, cl = w.header("transfer-encoding"), w.header("content-length")
            verify(w.status == 200, f"{label}: status 200 (was {w.status})")
            verify(not (te is not None and cl is not None),
                   f"{label}: never BOTH Transfer-Encoding and Content-Length (te={te!r}, cl={cl!r})")
            verify(w.header_count("transfer-encoding") <= 1 and w.header_count("content-length") <= 1,
                   f"{label}: at most one framing header of each kind")
            if w.framing == "chunked":
                verify(te is not None and te.strip().lower() == "chunked",
                       f"{label}: the one coding on the wire is exactly `chunked` (was {te!r})")
            else:
                note(f"{label}: the proxy re-framed the body as {w.framing}")
            verify(len(w.body) == len(body), f"{label}: body length {len(w.body)} == origin {len(body)}")
            verify(w.body == body, f"{label}: body byte-identical to what the origin sent (sha256 {sha(w.body)[:16]}..)")
            verify(DECOY in w.body, f"{label}: the decoy terminator inside chunk data survived (size-driven decode)")
            verify(w.body.endswith(END_MARK), f"{label}: body ends with the origin's tail marker")
            verify(w.header("x-origin-marker") == marker, f"{label}: X-Origin-Marker forwarded ({w.header('x-origin-marker')!r})")
            verify(w.header("content-type") == "application/octet-stream",
                   f"{label}: Content-Type forwarded ({w.header('content-type')!r})")
            verify(leftover.get(p, -1) == 0,
                   f"{label}: NO stray bytes on the socket after the framed response ({leftover.get(p)}): "
                   f"the trailer section was consumed exactly, nothing leaked into the next exchange")
        if w2 is not None:
            verify(w2.status == 200 and w2.body == origin.plain_body,
                   f"response 2 on the same connection is the intact plain body ({w2.status}, {len(w2.body)} bytes) -- no desync")
            verify(w2.framing == "length", f"response 2 kept Content-Length framing (was {w2.framing})")
            verify(w2.header("x-origin-marker") == marker, "response 2: X-Origin-Marker forwarded")
            verify(leftover.get(p_plain, -1) == 0, f"after response 2 the socket held NO stray bytes ({leftover.get(p_plain)})")
        verify(reconnects == 0 and client is not None and not client.eof,
               f"the proxy kept the client connection open across all three exchanges (reconnects={reconnects})")

        section("ground truth C: the bus -- flow.table / flow.get / flow.detail agree with the wire")
        done, rows = wait_rows(agent, main_paths, BUS_WAIT_S)
        verify(all(p in done for p in main_paths),
               f"flow.table shows a completed row for each of {main_paths} within {BUS_WAIT_S:.0f}s "
               f"(seen: {[(r.get('path'), r.get('status')) for r in rows]})")
        verify(len(rows) == 3, f"flow.table holds exactly the 3 flows this socket sent ({len(rows)})")
        verify([r.get("path") for r in rows] == main_paths,
               f"flow.table lists them oldest first in send order ({[r.get('path') for r in rows]})")
        for p in main_paths:
            r = done.get(p)
            if r is None:
                continue
            verify(r.get("status") == 200 and r.get("method") == "GET" and r.get("authority") == origin.authority,
                   f"row {p}: GET {r.get('authority')} -> {r.get('status')}")
            verify(r.get("state") == "observed" and r.get("duration_ms") is not None,
                   f"row {p}: state={r.get('state')!r}, duration_ms={r.get('duration_ms')!r} (completed, not intercepted)")
        details: dict = {}
        for p in (p_first, p_again):
            r = done.get(p)
            if r is None:
                continue
            fid = r["id"]
            g = agent.call("flow.get", {"id": fid})
            verify(g.get("status") == 200 and g.get("path") == p and g.get("method") == "GET",
                   f"flow.get {fid[:8]}..: {g.get('method')} {g.get('path')} -> {g.get('status')}")
            d = agent.call("flow.detail", {"id": fid, "body": "inline"})
            details[p] = d
            resp, req = d.get("response") or {}, d.get("request") or {}
            verify(d.get("kind") == "http" and resp.get("status") == 200,
                   f"flow.detail {p}: kind={d.get('kind')!r}, response status {resp.get('status')}")
            verify(resp.get("version") == "HTTP/1.1" and req.get("version") == "HTTP/1.1",
                   f"flow.detail {p}: versions request={req.get('version')!r} response={resp.get('version')!r}")
            captured = body_bytes(resp)
            verify(captured is not None, f"flow.detail {p}: inline response body present (not null/streaming)")
            captured = captured or b""
            verify(resp.get("body_size") == len(body) and len(captured) == len(body),
                   f"flow.detail {p}: body_size {resp.get('body_size')} and inline bytes {len(captured)} == {len(body)}")
            verify(resp.get("body_truncated") is False and (d.get("meta") or {}).get("truncated") is False,
                   f"flow.detail {p}: body_truncated={resp.get('body_truncated')!r}, meta.truncated={(d.get('meta') or {}).get('truncated')!r}")
            verify(captured == body, f"flow.detail {p}: captured body byte-identical to the origin body (sha256 {sha(captured)[:16]}..)")
            verify(DECOY in captured, f"flow.detail {p}: the decoy terminator survived in the capture")
            hp = header_pairs(resp)
            verify(("x-origin-marker", marker) in hp, f"flow.detail {p}: response header X-Origin-Marker captured")
            verify(("content-type", "application/octet-stream") in hp, f"flow.detail {p}: Content-Type captured")
            verify(("te", "trailers") in header_pairs(req), f"flow.detail {p}: the client's `TE: trailers` request header captured")
            verify(req.get("method") == "GET" and req.get("path") == p and req.get("authority") == origin.authority,
                   f"flow.detail {p}: request line captured as sent ({req.get('method')} {req.get('authority')}{req.get('path')})")
            sc = d.get("server_conn")
            verify(isinstance(sc, dict) and str(sc.get("peer", "")) == origin.authority,
                   f"flow.detail {p}: server_conn is the real origin socket ({sc.get('peer') if isinstance(sc, dict) else sc!r})")
            tail = agent.call("flow.detail", {"id": fid, "body": "range",
                                              "offset": len(body) - len(END_MARK), "length": len(END_MARK)})
            tail_bytes = body_bytes(tail.get("response") or {}) or b""
            verify(tail_bytes == END_MARK,
                   f"flow.detail {p}: body range [{len(body) - len(END_MARK)}, +{len(END_MARK)}) is the tail marker ({tail_bytes!r})")
        r2 = done.get(p_plain)
        if r2 is not None:
            d2 = agent.call("flow.detail", {"id": r2["id"], "body": "inline"})
            resp2 = d2.get("response") or {}
            verify(body_bytes(resp2) == origin.plain_body and resp2.get("body_size") == len(origin.plain_body),
                   f"flow.detail {p_plain}: the plain body after the trailer'd response captured intact "
                   f"({resp2.get('body_size')} bytes)")
            verify(("content-length", str(len(origin.plain_body))) in header_pairs(resp2),
                   f"flow.detail {p_plain}: Content-Length header captured as the origin sent it")

        section("ground truth D: request.send (the reissue path) decodes the same origin")
        send_detail: Optional[dict] = None
        if "request.send" not in names:
            note("request.send not on this core's tool surface; leg not run")
        else:
            args = {"authority": origin.authority, "path": p_send, "headers": {"TE": "trailers", "User-Agent": UA}}
            st, res = agent.try_call("request.send", args)
            if st != "ok" and "scope" in str(res).lower() and scope.entry is None:
                how = scope.widen(origin.authority)
                if how:
                    ok(f"scope widened for the active path via {how}")
                    st, res = agent.try_call("request.send", args)
            if st != "ok":
                note(f"request.send leg NOT run: {res}" + (f" ({'; '.join(scope.refusals)})" if scope.refusals else ""))
            else:
                sid = res if isinstance(res, str) else (res or {}).get("id") or (res or {}).get("result")
                verify(isinstance(sid, str) and len(sid) > 0, f"request.send returned a flow id ({sid!r})")
                deadline = time.monotonic() + SEND_WAIT_S
                sresp: dict = {}
                while isinstance(sid, str) and sid:
                    send_detail = agent.call("flow.detail", {"id": sid, "body": "inline"})
                    sresp = send_detail.get("response") or {}
                    if sresp.get("body") is not None or time.monotonic() > deadline:
                        break
                    time.sleep(0.1)
                got = origin.recorded(p_send)
                verify(len(got) == 1, f"origin recorded the reissued GET {p_send} exactly once ({len(got)}x)")
                if got:
                    verify(got[0]["headers"].get("te") == ["trailers"],
                           f"the reissued request carried the crafted TE header ({got[0]['headers'].get('te')})")
                sbody = body_bytes(sresp) or b""
                verify(sresp.get("status") == 200, f"request.send flow: status {sresp.get('status')}")
                verify(sbody == body and sresp.get("body_size") == len(body),
                       f"request.send flow: decoded body byte-identical to the origin ({len(sbody)} bytes, "
                       f"body_size {sresp.get('body_size')})")
                verify(sresp.get("body_truncated") is False, "request.send flow: not truncated")
                verify(DECOY in sbody, "request.send flow: the decoy terminator survived the sender's decode")
                if send_detail is not None:
                    verify((send_detail.get("meta") or {}).get("is_replay") is not None,
                           f"request.send flow: meta present (is_replay={(send_detail.get('meta') or {}).get('is_replay')!r})")

        section(f"trailer fidelity ({'STRICT: required' if strict else 'observed; hard only for integrity'}) -- last, so all evidence is on record")
        origin_names = {n.lower() for n, _ in trailers}
        for label, p in (("response 1", p_first), ("response 3", p_again)):
            w = wire.get(p)
            if w is None:
                continue
            declared = [t.strip().lower() for t in (w.header("trailer") or "").split(",") if t.strip()]
            got = {k.lower(): v for k, v in w.trailers}
            note(f"{label}: wire `Trailer:` header {'declares ' + str(declared) if declared else 'absent'}; "
                 f"trailer section carried {sorted(got) or 'nothing'}")
            # HARD: whatever was forwarded is exactly what the origin sent, and nothing else.
            for name, value in trailers:
                if name.lower() in got:
                    verify(got[name.lower()] == value, f"{label}: forwarded trailer {name} unaltered in transit")
            unknown = sorted(set(got) - origin_names)
            verify(not unknown, f"{label}: no trailer field the origin never sent ({unknown or 'none'}; a desync symptom)")
            # OBSERVED (strict: required): propagation to a `TE: trailers` client.
            forwarded = [n for n, _ in trailers if n.lower() in got]
            judge(len(forwarded) == len(trailers),
                  f"{label}: all {len(trailers)} origin trailer fields reached the `TE: trailers` client (forwarded: {forwarded})")
            if declared:
                judge(all(d in got for d in declared),
                      f"{label}: every field named in the forwarded `Trailer:` header arrived in the trailer section "
                      f"(declared-but-dropped: {[d for d in declared if d not in got]})")
        bus_views = [(p, details[p]) for p in (p_first, p_again) if p in details]
        if send_detail is not None:
            bus_views.append((p_send, send_detail))
        for p, d in bus_views:
            resp = d.get("response") or {}
            fields = visible_fields(resp)
            seen = {k for k, _ in fields}
            note(f"flow.detail {p}: response keys {sorted(resp.keys())}; trailer names visible over the bus: "
                 f"{sorted(n for n in origin_names if n in seen) or 'none'}")
            judge(all((n.lower(), v) in fields for n, v in trailers),
                  f"flow.detail {p}: the origin's trailer fields are visible over the bus "
                  f"(as response.trailers or merged into response.headers, RFC 9110 s6.5.1)")

        section("verdict")
        if DEFECTS:
            print(f"  {len(DEFECTS)} defect(s) in chunked+trailer handling:", flush=True)
            for d in DEFECTS:
                print(f"    - {d}", flush=True)
            fail(f"{len(DEFECTS)} defect(s); see the list above")
        ok(f"chunked response with trailers decoded, forwarded and captured correctly "
           f"({len(body)} bytes, {len(chunks)} chunks, {len(trailers)} trailer fields; marker {marker})")
    finally:
        if client:
            client.close()
        scope.release()
        if agent:
            agent.close()
        origin.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
