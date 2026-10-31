#!/usr/bin/env python3
# e2e: tier=T1 surface=proto needs=openssl
"""proto/test_http2_multiplex -- many concurrent HTTP/2 streams on ONE connection
through the real proxy are each captured correctly: every stream its own flow,
every byte attributed to the right stream, nothing serialised, nothing mixed up.

How the proxy speaks h2 -- read from crates/aitm-proto-http/src/module.rs and h2.rs,
not assumed: ONLY through the TLS ALPN mirror. The client CONNECTs, offers `h2` in
its ClientHello, the proxy dials the upstream over TLS offering the same list, and
when the upstream picks `h2` the proxy runs `serve_h2`: one h2 connection facing the
client, ONE pinned h2 connection facing the upstream, one `Flow::Http` with
`version: H2` per stream, each stream driven by its own task. There is no h2c, and
the seeded aitm-testtarget is HTTP/1-only, so this suite brings BOTH ends itself in
pure-stdlib Python (no `h2`/`hpack`/`httpx`; nothing to install):

  upstream  a real TLS origin (self-signed, SAN IP:127.0.0.1, ALPN `h2` only) with
            its own HTTP/2 framing + HPACK (static + dynamic table + Huffman, the
            same code table the proxy's `h2` crate encodes with). It RECORDS every
            TCP connection and every stream (headers, body, completion order) and
            HOLDS every response until ALL expected requests have completed on that
            connection -- the barrier. A proxy that ran streams one at a time would
            never satisfy it: the first stream would wait on a response that only
            ships after the last stream, the barrier would time out, and this test
            would fail with the precise count of streams that did arrive.

  client    one TCP connection -> CONNECT -> TLS (the MITM leaf is VERIFIED against
            the CA the core exports over `ca.export`, hostname check on, like a real
            browser) -> ALPN h2 -> HTTP/2 preface. It opens every stream's HEADERS
            before sending a single body byte, interleaves the request bodies
            round-robin, sends END_STREAM in REVERSE order, cancels one extra sibling
            stream with RST_STREAM mid-burst, and after the burst sends one more
            request on the SAME connection to prove it survived. Bodies include an
            EMPTY body, and a 96 KiB body that exceeds the 64 KiB initial h2 flow
            control window (so the proxy must grant WINDOW_UPDATEs or deadlock); the
            upstream answers one stream with a 96 KiB body and one with an empty one.

What is proved, on GROUND TRUTH (never a fixture, never only the proxy's own view):

  wire      the client got every response, status 200, on the right stream, no
            RST_STREAM / GOAWAY; each response body is byte-identical to what the
            upstream RECORDED SENDING for that stream; each response's
            `x-e2e-req-sha256` equals the SHA-256 of the body the client sent on
            that stream (the upstream's receipt, echoed), so request bytes went to
            the right stream too.
  upstream  exactly ONE TCP connection from the proxy, ALPN h2, carrying ALL N
            streams; the barrier held (all N complete before any response went
            out); every request header and body the client sent arrived verbatim
            on the stream the upstream attributes to it; the cancelled stream never
            arrived (the proxy forwards a request only once its body is complete).
  bus       a live `flow.subscribe` (opened BEFORE traffic, narrowed to this
            upstream) shows ALL N `created` and `request` events BEFORE the first
            `response` event -- the proxy had N streams open at once; the cancelled
            stream is `created` then `killed`, never `response`.
  store     `flow.table` has exactly N + 2 rows for this upstream (N streams, the
            cancelled one with no status, the tail); `flow.detail` of every stream
            flow has `request.version` and `response.version` `HTTP/2`, `client_conn
            .alpn`/`server_conn.alpn` `h2`, the request body base64-equal to what
            the client sent, the response body base64-equal to what the upstream
            sent, the per-stream headers in both directions, no truncation; every
            flow's `client_conn.peer` IS the client socket's own local address (one
            connection carried them all); `server_conn.peer` is the upstream; and
            the N flows' lifetimes OVERLAP: max(created) <= min(created + duration)
            -- the proxy's own clock agrees they were concurrent.

Core: attaches to the core the runner provides via env (AITM_BUS_ADDR,
AITM_BUS_TOKEN, AITM_PROXY_ADDR, optional AITM_BUS_OPERATOR_TOKEN). This suite
never boots its own core: without the contract it SKIPs (77) and says so. The core
MUST run with `ssl_insecure: true` -- the proxy verifies upstream certificates
against the webpki roots otherwise and would (correctly) refuse the self-signed h2
origin; a verifying core is reported as a loud SKIP naming the knob. The upstream's
port is random and every marker is unique per run, so nothing here collides with
suites sharing the core; no scope or config is changed (the passive listener dials
CONNECT targets freely, crates/aitm-core/src/proxy.rs `PassiveConnector`).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402

# ---- the shape of the burst ------------------------------------------------------

N_STREAMS = 8            # concurrent streams in the burst (clamped to the proxy's cap)
REQ_CHUNKS = 4           # each request body is sent in this many interleaved pieces
RESP_CHUNKS = 3          # each response body is sent in this many interleaved pieces
BIG = 96 * 1024          # a body larger than the 65 535-byte initial h2 window
BIG_REQ_STREAM = 3       # the stream whose REQUEST body is BIG
BIG_RESP_STREAM = 5      # the stream whose RESPONSE body is BIG
EMPTY_STREAM = 0         # the stream with an EMPTY request AND an EMPTY response
BARRIER_TIMEOUT = 20.0   # the upstream waits this long for all N requests
CLIENT_DEADLINE = 45.0   # the client waits this long for all N responses
FLOW_NOTE = "notifications/aitm/flow"

ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_OP_TOKEN, ENV_PROXY_ADDR = (
    "AITM_BUS_ADDR", "AITM_BUS_TOKEN", "AITM_BUS_OPERATOR_TOKEN", "AITM_PROXY_ADDR",
)


def env_core():
    """The core the runner booted, described in the environment; SKIP without it."""
    missing = [k for k in (ENV_BUS_ADDR, ENV_BUS_TOKEN, ENV_PROXY_ADDR) if not os.environ.get(k)]
    if missing:
        skip(f"no runner-provided core: {' '.join(missing)} unset; this suite never boots its own "
             f"core (see tests/e2e/README.md)")
    host, port = os.environ[ENV_BUS_ADDR].rsplit(":", 1)
    phost, pport = os.environ[ENV_PROXY_ADDR].rsplit(":", 1)
    cfg = SimpleNamespace(agent_token=os.environ[ENV_BUS_TOKEN],
                          operator_token=os.environ.get(ENV_OP_TOKEN) or None,
                          proxy_port=int(pport))
    return SimpleNamespace(bus_addr=(host.strip("[]"), int(port)),
                           proxy_host=phost.strip("[]") or "127.0.0.1", cfg=cfg)


# ==================================================================================
# HPACK (RFC 7541): a full decoder (static + dynamic table, Huffman) for what the
# proxy's `h2` crate sends us, and a minimal encoder (literals, never indexed, raw
# strings) for what we send it. The Huffman table below is the `h2` crate's own
# ENCODE_TABLE (src/hpack/huffman/table.rs), i.e. RFC 7541 Appendix B.
# ==================================================================================

STATIC_TABLE: list[tuple[bytes, bytes]] = [
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"), (b":path", b"/"),
    (b":path", b"/index.html"), (b":scheme", b"http"), (b":scheme", b"https"),
    (b":status", b"200"), (b":status", b"204"), (b":status", b"206"), (b":status", b"304"),
    (b":status", b"400"), (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""), (b"accept-ranges", b""),
    (b"accept", b""), (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""), (b"content-disposition", b""),
    (b"content-encoding", b""), (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""), (b"content-type", b""), (b"cookie", b""),
    (b"date", b""), (b"etag", b""), (b"expect", b""), (b"expires", b""), (b"from", b""),
    (b"host", b""), (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""), (b"link", b""),
    (b"location", b""), (b"max-forwards", b""), (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""), (b"range", b""), (b"referer", b""), (b"refresh", b""),
    (b"retry-after", b""), (b"server", b""), (b"set-cookie", b""),
    (b"strict-transport-security", b""), (b"transfer-encoding", b""), (b"user-agent", b""),
    (b"vary", b""), (b"via", b""), (b"www-authenticate", b""),
]
assert len(STATIC_TABLE) == 61
STATIC_NAME_INDEX: dict[bytes, int] = {}
for _i, (_n, _v) in enumerate(STATIC_TABLE, 1):
    STATIC_NAME_INDEX.setdefault(_n, _i)

# (bit length, code) for symbols 0..255 and EOS (256).
HUFF = [
    (13,0x1ff8),(23,0x7fffd8),(28,0xfffffe2),(28,0xfffffe3),(28,0xfffffe4),(28,0xfffffe5),
    (28,0xfffffe6),(28,0xfffffe7),(28,0xfffffe8),(24,0xffffea),(30,0x3ffffffc),(28,0xfffffe9),
    (28,0xfffffea),(30,0x3ffffffd),(28,0xfffffeb),(28,0xfffffec),(28,0xfffffed),(28,0xfffffee),
    (28,0xfffffef),(28,0xffffff0),(28,0xffffff1),(28,0xffffff2),(30,0x3ffffffe),(28,0xffffff3),
    (28,0xffffff4),(28,0xffffff5),(28,0xffffff6),(28,0xffffff7),(28,0xffffff8),(28,0xffffff9),
    (28,0xffffffa),(28,0xffffffb),(6,0x14),(10,0x3f8),(10,0x3f9),(12,0xffa),(13,0x1ff9),
    (6,0x15),(8,0xf8),(11,0x7fa),(10,0x3fa),(10,0x3fb),(8,0xf9),(11,0x7fb),(8,0xfa),(6,0x16),
    (6,0x17),(6,0x18),(5,0x0),(5,0x1),(5,0x2),(6,0x19),(6,0x1a),(6,0x1b),(6,0x1c),(6,0x1d),
    (6,0x1e),(6,0x1f),(7,0x5c),(8,0xfb),(15,0x7ffc),(6,0x20),(12,0xffb),(10,0x3fc),(13,0x1ffa),
    (6,0x21),(7,0x5d),(7,0x5e),(7,0x5f),(7,0x60),(7,0x61),(7,0x62),(7,0x63),(7,0x64),(7,0x65),
    (7,0x66),(7,0x67),(7,0x68),(7,0x69),(7,0x6a),(7,0x6b),(7,0x6c),(7,0x6d),(7,0x6e),(7,0x6f),
    (7,0x70),(7,0x71),(7,0x72),(8,0xfc),(7,0x73),(8,0xfd),(13,0x1ffb),(19,0x7fff0),(13,0x1ffc),
    (14,0x3ffc),(6,0x22),(15,0x7ffd),(5,0x3),(6,0x23),(5,0x4),(6,0x24),(5,0x5),(6,0x25),
    (6,0x26),(6,0x27),(5,0x6),(7,0x74),(7,0x75),(6,0x28),(6,0x29),(6,0x2a),(5,0x7),(6,0x2b),
    (7,0x76),(6,0x2c),(5,0x8),(5,0x9),(6,0x2d),(7,0x77),(7,0x78),(7,0x79),(7,0x7a),(7,0x7b),
    (15,0x7ffe),(11,0x7fc),(14,0x3ffd),(13,0x1ffd),(28,0xffffffc),(20,0xfffe6),(22,0x3fffd2),
    (20,0xfffe7),(20,0xfffe8),(22,0x3fffd3),(22,0x3fffd4),(22,0x3fffd5),(23,0x7fffd9),
    (22,0x3fffd6),(23,0x7fffda),(23,0x7fffdb),(23,0x7fffdc),(23,0x7fffdd),(23,0x7fffde),
    (24,0xffffeb),(23,0x7fffdf),(24,0xffffec),(24,0xffffed),(22,0x3fffd7),(23,0x7fffe0),
    (24,0xffffee),(23,0x7fffe1),(23,0x7fffe2),(23,0x7fffe3),(23,0x7fffe4),(21,0x1fffdc),
    (22,0x3fffd8),(23,0x7fffe5),(22,0x3fffd9),(23,0x7fffe6),(23,0x7fffe7),(24,0xffffef),
    (22,0x3fffda),(21,0x1fffdd),(20,0xfffe9),(22,0x3fffdb),(22,0x3fffdc),(23,0x7fffe8),
    (23,0x7fffe9),(21,0x1fffde),(23,0x7fffea),(22,0x3fffdd),(22,0x3fffde),(24,0xfffff0),
    (21,0x1fffdf),(22,0x3fffdf),(23,0x7fffeb),(23,0x7fffec),(21,0x1fffe0),(21,0x1fffe1),
    (22,0x3fffe0),(21,0x1fffe2),(23,0x7fffed),(22,0x3fffe1),(23,0x7fffee),(23,0x7fffef),
    (20,0xfffea),(22,0x3fffe2),(22,0x3fffe3),(22,0x3fffe4),(23,0x7ffff0),(22,0x3fffe5),
    (22,0x3fffe6),(23,0x7ffff1),(26,0x3ffffe0),(26,0x3ffffe1),(20,0xfffeb),(19,0x7fff1),
    (22,0x3fffe7),(23,0x7ffff2),(22,0x3fffe8),(25,0x1ffffec),(26,0x3ffffe2),(26,0x3ffffe3),
    (26,0x3ffffe4),(27,0x7ffffde),(27,0x7ffffdf),(26,0x3ffffe5),(24,0xfffff1),(25,0x1ffffed),
    (19,0x7fff2),(21,0x1fffe3),(26,0x3ffffe6),(27,0x7ffffe0),(27,0x7ffffe1),(26,0x3ffffe7),
    (27,0x7ffffe2),(24,0xfffff2),(21,0x1fffe4),(21,0x1fffe5),(26,0x3ffffe8),(26,0x3ffffe9),
    (28,0xffffffd),(27,0x7ffffe3),(27,0x7ffffe4),(27,0x7ffffe5),(20,0xfffec),(24,0xfffff3),
    (20,0xfffed),(21,0x1fffe6),(22,0x3fffe9),(21,0x1fffe7),(21,0x1fffe8),(23,0x7ffff3),
    (22,0x3fffea),(22,0x3fffeb),(25,0x1ffffee),(25,0x1ffffef),(24,0xfffff4),(24,0xfffff5),
    (26,0x3ffffea),(23,0x7ffff4),(26,0x3ffffeb),(27,0x7ffffe6),(26,0x3ffffec),(26,0x3ffffed),
    (27,0x7ffffe7),(27,0x7ffffe8),(27,0x7ffffe9),(27,0x7ffffea),(27,0x7ffffeb),(28,0xffffffe),
    (27,0x7ffffec),(27,0x7ffffed),(27,0x7ffffee),(27,0x7ffffef),(27,0x7fffff0),(26,0x3ffffee),
    (30,0x3fffffff),
]
assert len(HUFF) == 257
_HUFF_DECODE: dict[int, dict[int, int]] = {}
for _sym, (_bits, _code) in enumerate(HUFF):
    _HUFF_DECODE.setdefault(_bits, {})[_code] = _sym
_HUFF_LENS = sorted(_HUFF_DECODE)


class HpackError(Exception):
    pass


def huffman_decode(raw: bytes) -> bytes:
    out = bytearray()
    acc = 0
    nbits = 0
    for byte in raw:
        acc = (acc << 8) | byte
        nbits += 8
        while True:
            hit = False
            for length in _HUFF_LENS:
                if length > nbits:
                    break
                code = (acc >> (nbits - length)) & ((1 << length) - 1)
                sym = _HUFF_DECODE[length].get(code)
                if sym is not None:
                    if sym == 256:
                        raise HpackError("EOS inside a Huffman string")
                    out.append(sym)
                    nbits -= length
                    acc &= (1 << nbits) - 1
                    hit = True
                    break
            if not hit:
                break
    if nbits > 7 or (nbits and acc != (1 << nbits) - 1):
        raise HpackError(f"bad Huffman padding ({nbits} bits left: {acc:b})")
    return bytes(out)


def decode_int(data: bytes, i: int, prefix: int) -> tuple[int, int]:
    mask = (1 << prefix) - 1
    v = data[i] & mask
    i += 1
    if v < mask:
        return v, i
    m = 0
    while True:
        b = data[i]
        i += 1
        v += (b & 0x7F) << m
        m += 7
        if not b & 0x80:
            return v, i


def decode_string(data: bytes, i: int) -> tuple[bytes, int]:
    huff = bool(data[i] & 0x80)
    length, i = decode_int(data, i, 7)
    raw = bytes(data[i:i + length])
    if len(raw) != length:
        raise HpackError("string literal runs past the header block")
    return (huffman_decode(raw) if huff else raw), i + length


class HpackDecoder:
    def __init__(self, max_size: int = 4096):
        self.dynamic: list[tuple[bytes, bytes]] = []   # most recent first
        self.max_size = max_size
        self.size = 0

    def _evict(self) -> None:
        while self.size > self.max_size and self.dynamic:
            n, v = self.dynamic.pop()
            self.size -= len(n) + len(v) + 32

    def _add(self, name: bytes, value: bytes) -> None:
        self.dynamic.insert(0, (name, value))
        self.size += len(name) + len(value) + 32
        self._evict()

    def _entry(self, idx: int) -> tuple[bytes, bytes]:
        if idx <= 0:
            raise HpackError("index 0")
        if idx <= len(STATIC_TABLE):
            return STATIC_TABLE[idx - 1]
        d = idx - len(STATIC_TABLE) - 1
        if d < len(self.dynamic):
            return self.dynamic[d]
        raise HpackError(f"index {idx} beyond the dynamic table ({len(self.dynamic)} entries)")

    def _name(self, data: bytes, i: int, idx: int) -> tuple[bytes, int]:
        if idx:
            return self._entry(idx)[0], i
        return decode_string(data, i)

    def decode(self, data: bytes) -> list[tuple[bytes, bytes]]:
        out: list[tuple[bytes, bytes]] = []
        i = 0
        while i < len(data):
            b = data[i]
            if b & 0x80:                       # indexed header field
                idx, i = decode_int(data, i, 7)
                out.append(self._entry(idx))
            elif b & 0x40:                     # literal with incremental indexing
                idx, i = decode_int(data, i, 6)
                name, i = self._name(data, i, idx)
                value, i = decode_string(data, i)
                self._add(name, value)
                out.append((name, value))
            elif b & 0x20:                     # dynamic table size update
                size, i = decode_int(data, i, 5)
                self.max_size = size
                self._evict()
            else:                              # literal without indexing / never indexed
                idx, i = decode_int(data, i, 4)
                name, i = self._name(data, i, idx)
                value, i = decode_string(data, i)
                out.append((name, value))
        return out


def encode_int(v: int, prefix: int, first: int = 0) -> bytes:
    mask = (1 << prefix) - 1
    if v < mask:
        return bytes([first | v])
    out = bytearray([first | mask])
    v -= mask
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def hpack_encode(headers: list[tuple[bytes, bytes]]) -> bytes:
    """Literal-without-indexing, raw strings; names indexed from the static table
    when it has them. Valid for any peer, and keeps our encoder stateless."""
    out = bytearray()
    for name, value in headers:
        idx = STATIC_NAME_INDEX.get(name)
        if idx:
            out += encode_int(idx, 4, 0x00)
        else:
            out += b"\x00" + encode_int(len(name), 7) + name
        out += encode_int(len(value), 7) + value
    return bytes(out)


# ==================================================================================
# HTTP/2 framing (RFC 9113) and a peer that keeps the connection honest: SETTINGS
# acks, PING acks, flow-control windows on both sides, CONTINUATION, padding.
# ==================================================================================

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
(F_DATA, F_HEADERS, F_PRIORITY, F_RST_STREAM, F_SETTINGS, F_PUSH_PROMISE, F_PING, F_GOAWAY,
 F_WINDOW_UPDATE, F_CONTINUATION) = range(10)
FRAME_NAMES = ["DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING",
               "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"]
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20
(S_HEADER_TABLE_SIZE, S_ENABLE_PUSH, S_MAX_CONCURRENT_STREAMS, S_INITIAL_WINDOW_SIZE,
 S_MAX_FRAME_SIZE, S_MAX_HEADER_LIST_SIZE) = range(1, 7)
ERR_CANCEL = 0x8
DEFAULT_WINDOW = 65535
BIG_WINDOW = 1 << 20


class H2Error(Exception):
    pass


class H2Closed(H2Error):
    pass


def frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack(">I", sid & 0x7FFFFFFF) + payload)


def settings_payload(values: dict[int, int]) -> bytes:
    return b"".join(struct.pack(">HI", k, v) for k, v in values.items())


def split_chunks(data: bytes, n: int) -> list[bytes]:
    """`data` in `n` near-equal pieces (empty pieces when `data` is short/empty)."""
    return [data[len(data) * i // n: len(data) * (i + 1) // n] for i in range(n)]


def read_exact(sock, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise H2Closed("peer closed the connection")
        buf += chunk
    return buf


@dataclass
class StreamState:
    headers: list[tuple[bytes, bytes]] | None = None
    trailers: list[tuple[bytes, bytes]] | None = None
    body: bytearray = field(default_factory=bytearray)
    end_stream: bool = False
    rst: int | None = None
    data_frames: int = 0
    headers_seq: int | None = None     # frame-log position of the HEADERS frame
    end_seq: int | None = None         # frame-log position of END_STREAM

    def header(self, name: bytes) -> bytes | None:
        for n, v in self.headers or []:
            if n == name:
                return v
        return None


class H2Peer:
    """One end of an h2 connection over `sock` (a TLS socket). Single-threaded:
    the owner calls pump()/send_*() from one thread."""

    def __init__(self, sock, label: str):
        self.sock = sock
        self.label = label
        self.buf = bytearray()
        self.dec = HpackDecoder()
        self.peer_settings: dict[int, int] = {}
        self.settings_frames = 0
        self.settings_acked = False
        self.peer_initial_window = DEFAULT_WINDOW
        self.peer_max_frame_size = 16384
        self.conn_send_window = DEFAULT_WINDOW
        self.stream_send_window: dict[int, int] = {}
        self.streams: dict[int, StreamState] = {}
        self.goaway: tuple[int, int, bytes] | None = None
        self.pings = 0
        self.push_promises = 0
        self.window_updates = 0
        self.log: list[tuple[int, int, int, int]] = []   # (type, sid, flags, len), arrival order
        self.seq = 0
        self._cont: tuple[int, int, bytearray] | None = None

    # ---- sending ----------------------------------------------------------------

    def send(self, raw: bytes) -> None:
        self.sock.settimeout(30)
        self.sock.sendall(raw)

    def send_headers(self, sid: int, headers: list[tuple[bytes, bytes]], end_stream: bool) -> None:
        flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
        self.streams.setdefault(sid, StreamState())
        self.stream_send_window.setdefault(sid, self.peer_initial_window)
        self.send(frame(F_HEADERS, flags, sid, hpack_encode(headers)))

    def send_data(self, sid: int, data: bytes, end_stream: bool, wait: float = 20.0) -> None:
        """DATA honouring the peer's connection + stream windows and max frame size;
        pumps frames while waiting for WINDOW_UPDATE. END_STREAM rides the last
        piece (or an empty frame when `data` is empty)."""
        self.stream_send_window.setdefault(sid, self.peer_initial_window)
        if not data:
            if end_stream:
                self.send(frame(F_DATA, FLAG_END_STREAM, sid, b""))
            return
        off = 0
        deadline = time.time() + wait
        while off < len(data):
            allowed = min(len(data) - off, self.peer_max_frame_size,
                          self.conn_send_window, self.stream_send_window[sid])
            if allowed <= 0:
                if time.time() > deadline:
                    raise H2Error(f"{self.label}: flow-control window never opened for stream {sid} "
                                  f"(conn {self.conn_send_window}, stream {self.stream_send_window[sid]})")
                self.pump(0.25)
                continue
            piece = data[off:off + allowed]
            off += allowed
            last = end_stream and off == len(data)
            self.send(frame(F_DATA, FLAG_END_STREAM if last else 0, sid, piece))
            self.conn_send_window -= allowed
            self.stream_send_window[sid] -= allowed

    def send_rst(self, sid: int, code: int) -> None:
        self.send(frame(F_RST_STREAM, 0, sid, struct.pack(">I", code)))

    def send_goaway(self, last_sid: int, code: int = 0) -> None:
        self.send(frame(F_GOAWAY, 0, 0, struct.pack(">II", last_sid, code)))

    def send_window_update(self, sid: int, inc: int) -> None:
        if inc > 0:
            self.send(frame(F_WINDOW_UPDATE, 0, sid, struct.pack(">I", inc)))

    # ---- receiving --------------------------------------------------------------

    def pump(self, timeout: float) -> int:
        """Handle every complete frame already buffered; otherwise read once (up to
        `timeout`) and handle what arrived. Returns the number of frames handled."""
        n = self._drain()
        if n:
            return n
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(65536)
        except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
            return 0
        if not chunk:
            raise H2Closed(f"{self.label}: peer closed the connection")
        self.buf += chunk
        return self._drain()

    def _drain(self) -> int:
        handled = 0
        while len(self.buf) >= 9:
            length = int.from_bytes(self.buf[:3], "big")
            if len(self.buf) < 9 + length:
                break
            ftype, flags = self.buf[3], self.buf[4]
            sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
            payload = bytes(self.buf[9:9 + length])
            del self.buf[:9 + length]
            self.log.append((ftype, sid, flags, length))
            self.seq += 1
            self._handle(ftype, flags, sid, payload)
            handled += 1
        return handled

    def _handle(self, ftype: int, flags: int, sid: int, payload: bytes) -> None:
        if ftype == F_SETTINGS:
            if flags & FLAG_ACK:
                self.settings_acked = True
                return
            for i in range(0, len(payload) - 5, 6):
                ident, val = struct.unpack(">HI", payload[i:i + 6])
                self.peer_settings[ident] = val
                if ident == S_INITIAL_WINDOW_SIZE:
                    delta = val - self.peer_initial_window
                    self.peer_initial_window = val
                    for s in self.stream_send_window:
                        self.stream_send_window[s] += delta
                elif ident == S_MAX_FRAME_SIZE:
                    self.peer_max_frame_size = val
            self.settings_frames += 1
            self.send(frame(F_SETTINGS, FLAG_ACK, 0, b""))
        elif ftype == F_PING:
            if not flags & FLAG_ACK:
                self.pings += 1
                self.send(frame(F_PING, FLAG_ACK, 0, payload))
        elif ftype == F_WINDOW_UPDATE:
            inc = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
            self.window_updates += 1
            if sid == 0:
                self.conn_send_window += inc
            else:
                self.stream_send_window[sid] = self.stream_send_window.get(sid, self.peer_initial_window) + inc
        elif ftype == F_HEADERS:
            p = payload
            if flags & FLAG_PADDED:
                p = p[1:len(p) - p[0]]
            if flags & FLAG_PRIORITY:
                p = p[5:]
            if flags & FLAG_END_HEADERS:
                self._header_block(sid, flags, bytes(p))
            else:
                self._cont = (sid, flags, bytearray(p))
        elif ftype == F_CONTINUATION:
            if not self._cont or self._cont[0] != sid:
                raise H2Error(f"{self.label}: CONTINUATION without a HEADERS on stream {sid}")
            self._cont[2].extend(payload)
            if flags & FLAG_END_HEADERS:
                sid0, flags0, block = self._cont
                self._cont = None
                self._header_block(sid0, flags0, bytes(block))
        elif ftype == F_DATA:
            st = self.streams.setdefault(sid, StreamState())
            p = payload
            if flags & FLAG_PADDED:
                p = p[1:len(p) - p[0]]
            st.body += p
            st.data_frames += 1
            if len(payload):
                # Return the window promptly: connection always, stream while open.
                self.send_window_update(0, len(payload))
                if not flags & FLAG_END_STREAM:
                    self.send_window_update(sid, len(payload))
            if flags & FLAG_END_STREAM:
                st.end_stream = True
                st.end_seq = self.seq
        elif ftype == F_RST_STREAM:
            st = self.streams.setdefault(sid, StreamState())
            st.rst = struct.unpack(">I", payload[:4])[0]
        elif ftype == F_GOAWAY:
            last, code = struct.unpack(">II", payload[:8])
            self.goaway = (last & 0x7FFFFFFF, code, payload[8:])
        elif ftype == F_PUSH_PROMISE:
            self.push_promises += 1
        # PRIORITY and unknown frame types are ignored, as the RFC asks.

    def _header_block(self, sid: int, flags: int, block: bytes) -> None:
        fields = self.dec.decode(block)
        st = self.streams.setdefault(sid, StreamState())
        if st.headers is None:
            st.headers = fields
            st.headers_seq = self.seq
        else:
            st.trailers = fields
        if flags & FLAG_END_STREAM:
            st.end_stream = True
            st.end_seq = self.seq


# ==================================================================================
# The independent observer: an h2-over-TLS origin with a barrier.
# ==================================================================================

@dataclass
class ConnRecord:
    index: int
    peer: tuple
    alpn: str | None = None
    tls_version: str | None = None
    h2: H2Peer | None = None
    barrier_ok: bool | None = None
    seen_at_barrier: int = 0
    barrier_wait: float = 0.0
    request_order: list[int] = field(default_factory=list)   # upstream sids by completion
    response_order: list[int] = field(default_factory=list)  # the order HEADERS were sent
    end_order: list[int] = field(default_factory=list)       # the order END_STREAM was sent
    sent: dict[int, bytes] = field(default_factory=dict)      # upstream sid -> response body
    stream_k: dict[int, str] = field(default_factory=dict)    # upstream sid -> x-e2e-stream
    error: str | None = None
    responded: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)


def make_self_signed(workdir: str) -> tuple[str, str]:
    """A throwaway RSA cert for 127.0.0.1 via the openssl CLI (OpenSSL or LibreSSL);
    SKIP when there is none."""
    exe = shutil.which("openssl") or ("/usr/bin/openssl" if os.path.exists("/usr/bin/openssl") else None)
    if not exe:
        skip("no `openssl` binary to mint the upstream's self-signed TLS certificate")
    cnf = os.path.join(workdir, "openssl.cnf")
    with open(cnf, "w", encoding="utf-8") as f:
        f.write("[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                "[dn]\nCN = aitm-e2e-h2-upstream\n"
                "[ext]\nsubjectAltName = IP:127.0.0.1\nbasicConstraints = CA:FALSE\n")
    cert, key = os.path.join(workdir, "cert.pem"), os.path.join(workdir, "key.pem")
    r = subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", cert, "-days", "2", "-config", cnf],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    if r.returncode != 0 or not os.path.exists(cert):
        skip(f"openssl could not mint the upstream certificate: {r.stderr.strip()[-200:]}")
    return cert, key


class H2Upstream:
    """Loopback TLS origin, ALPN `h2` only. One thread per accepted connection; each
    records everything and HOLDS all responses until `expected` requests completed
    on that connection (or BARRIER_TIMEOUT), then answers them scrambled and
    interleaved; later streams (the tail) are answered at once."""

    def __init__(self, certfile: str, keyfile: str, tag: str):
        self.tag = tag
        self.port = free_port()
        self.expected = 0
        self.response_filler: dict[str, int] = {}
        self.conns: list[ConnRecord] = []
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._ctx.set_alpn_protocols(["h2"])
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", self.port))
        self._listener.listen(16)
        self._listener.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    @property
    def authority(self) -> str:
        return f"127.0.0.1:{self.port}"

    def start(self) -> "H2Upstream":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _complete(self, peer: H2Peer) -> list[int]:
        return [sid for sid, st in peer.streams.items()
                if st.headers is not None and st.end_stream and st.rst is None]

    def _serve(self, raw: socket.socket, addr) -> None:
        rec = ConnRecord(index=len(self.conns) + 1, peer=addr)
        self.conns.append(rec)
        tls = None
        try:
            tls = self._ctx.wrap_socket(raw, server_side=True)
            rec.alpn = tls.selected_alpn_protocol()
            rec.tls_version = tls.version()
            peer = H2Peer(tls, f"upstream#{rec.index}")
            rec.h2 = peer
            if read_exact(tls, len(PREFACE), 10) != PREFACE:
                raise H2Error("the proxy did not send the HTTP/2 connection preface")
            peer.send(frame(F_SETTINGS, 0, 0, settings_payload({
                S_INITIAL_WINDOW_SIZE: BIG_WINDOW, S_MAX_CONCURRENT_STREAMS: 256,
                S_MAX_HEADER_LIST_SIZE: 1 << 16}))
                + frame(F_WINDOW_UPDATE, 0, 0, struct.pack(">I", BIG_WINDOW - DEFAULT_WINDOW)))

            # Phase 1 -- the barrier: wait until every expected request is complete.
            t0 = time.time()
            while time.time() - t0 < BARRIER_TIMEOUT:
                done = self._complete(peer)
                if self.expected and len(done) >= self.expected:
                    break
                if peer.goaway:
                    break
                peer.pump(0.25)
            done = self._complete(peer)
            rec.barrier_wait = time.time() - t0
            rec.seen_at_barrier = len(done)
            rec.barrier_ok = bool(self.expected) and len(done) >= self.expected
            rec.request_order = sorted(done, key=lambda s: peer.streams[s].end_seq or 0)

            # Phase 2 -- answer the barrier set, scrambled and interleaved.
            self._respond(rec, peer, rec.request_order, rec.barrier_ok)
            rec.responded.set()

            # Phase 3 -- anything that completes later (the tail) is answered at once.
            served = set(done)
            idle = time.time() + 30
            while time.time() < idle:
                peer.pump(0.5)
                new = [s for s in self._complete(peer) if s not in served]
                if new:
                    self._respond(rec, peer, new, True)
                    served |= set(new)
                    idle = time.time() + 30
                elif peer.goaway:
                    break
        except H2Closed:
            pass
        except Exception as e:  # noqa: BLE001 -- recorded, asserted on by the test
            rec.error = f"{type(e).__name__}: {e}"
        finally:
            rec.responded.set()
            rec.done.set()
            for s in (tls, raw):
                try:
                    s.close()
                except OSError:
                    pass

    def _respond(self, rec: ConnRecord, peer: H2Peer, sids: list[int], barrier_ok: bool) -> None:
        order = sorted(sids, reverse=True)
        rot = len(order) // 3
        order = order[rot:] + order[:rot]
        payloads: dict[int, bytes] = {}
        for sid in order:
            st = peer.streams[sid]
            k = (st.header(b"x-e2e-stream") or b"?").decode("latin1")
            body = bytes(st.body)
            sha = hashlib.sha256(body).hexdigest()
            filler_len = self.response_filler.get(k, 2048)
            if filler_len == 0:
                payload = b""
            else:
                seed = hashlib.sha256(f"{self.tag}|resp|{k}|{sid}".encode()).hexdigest()
                filler = (seed * (filler_len // len(seed) + 1))[:filler_len]
                payload = json.dumps({"observed_by": "aitm-e2e-h2-upstream", "stream": k,
                                      "upstream_stream_id": sid, "conn": rec.index,
                                      "path": (st.header(b":path") or b"").decode("latin1"),
                                      "req_sha256": sha, "req_len": len(body),
                                      "filler": filler}).encode()
            payloads[sid] = payload
            rec.sent[sid] = payload
            rec.stream_k[sid] = k
            peer.send_headers(sid, [
                (b":status", b"200"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
                (b"x-e2e-stream", k.encode("latin1")),
                (b"x-e2e-upstream-stream-id", str(sid).encode()),
                (b"x-e2e-upstream-conn", str(rec.index).encode()),
                (b"x-e2e-req-sha256", sha.encode()),
                (b"x-e2e-req-len", str(len(body)).encode()),
                (b"x-e2e-barrier", b"ok" if barrier_ok else b"timeout"),
                (b"x-e2e-barrier-seen", str(rec.seen_at_barrier).encode()),
            ], end_stream=False)
        rec.response_order.extend(order)
        chunks = {sid: split_chunks(payloads[sid], RESP_CHUNKS) for sid in order}
        for c in range(RESP_CHUNKS):
            for sid in order:
                if chunks[sid][c]:
                    peer.send_data(sid, chunks[sid][c], end_stream=False)
        end_order = order[::2] + order[1::2]
        for sid in end_order:
            peer.send_data(sid, b"", end_stream=True)
        rec.end_order.extend(end_order)


# ==================================================================================
# The client: one connection through the proxy, many streams.
# ==================================================================================

class H2Session:
    def __init__(self, proxy_host: str, proxy_port: int, authority: str, ca_pem: str | None):
        self.proxy = (proxy_host, proxy_port)
        self.authority = authority
        self.ca_pem = ca_pem
        self.raw: socket.socket | None = None
        self.tls: ssl.SSLSocket | None = None
        self.peer: H2Peer | None = None
        self.connect_status = ""
        self.alpn = None
        self.tls_version = None
        self.local_addr: tuple | None = None
        self.leaf: dict | None = None

    def open(self) -> int | None:
        """CONNECT, TLS (verifying the MITM leaf against the core's CA when we have
        it), ALPN h2, preface + SETTINGS; wait for the proxy's SETTINGS. Returns the
        proxy's advertised SETTINGS_MAX_CONCURRENT_STREAMS (None if unset)."""
        self.raw = socket.create_connection(self.proxy, timeout=30)
        self.raw.sendall(f"CONNECT {self.authority} HTTP/1.1\r\nHost: {self.authority}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            b = self.raw.recv(1)
            if not b:
                raise H2Error("the proxy closed the connection during CONNECT")
            head += b
            if len(head) > 8192:
                raise H2Error("CONNECT response head too long")
        self.connect_status = head.split(b"\r\n", 1)[0].decode("latin1")
        if not self.connect_status.startswith("HTTP/1.1 200"):
            raise H2Error(f"CONNECT refused: {self.connect_status!r}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ca_pem:
            ctx.load_verify_locations(cadata=self.ca_pem)   # check_hostname + CERT_REQUIRED stay on
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.tls = ctx.wrap_socket(self.raw, server_hostname="127.0.0.1")
        self.alpn = self.tls.selected_alpn_protocol()
        self.tls_version = self.tls.version()
        self.local_addr = self.tls.getsockname()
        self.leaf = self.tls.getpeercert() if self.ca_pem else None
        if self.alpn != "h2":
            raise H2Error(f"the proxy negotiated ALPN {self.alpn!r}, not h2")
        self.peer = H2Peer(self.tls, "client")
        self.peer.send(PREFACE + frame(F_SETTINGS, 0, 0, settings_payload({
            S_ENABLE_PUSH: 0, S_INITIAL_WINDOW_SIZE: BIG_WINDOW, S_MAX_CONCURRENT_STREAMS: 100,
            S_MAX_FRAME_SIZE: 16384, S_MAX_HEADER_LIST_SIZE: 1 << 16}))
            + frame(F_WINDOW_UPDATE, 0, 0, struct.pack(">I", BIG_WINDOW - DEFAULT_WINDOW)))
        deadline = time.time() + 10
        while self.peer.settings_frames == 0 and time.time() < deadline:
            self.peer.pump(0.5)
            if self.peer.goaway:
                raise H2Error(f"GOAWAY during the handshake: {self.peer.goaway}")
        if self.peer.settings_frames == 0:
            raise H2Error("the proxy never sent its SETTINGS frame")
        return self.peer.peer_settings.get(S_MAX_CONCURRENT_STREAMS)

    def burst(self, plan) -> None:
        """Open every stream, interleave the bodies, cancel the extra sibling,
        END_STREAM in reverse, then wait for all N responses."""
        p = self.peer
        assert p is not None
        for r in plan.concurrent:
            p.send_headers(r.sid, r.headers, end_stream=False)
        p.send_headers(plan.cancel.sid, plan.cancel.headers, end_stream=False)
        half = plan.cancel.body[: len(plan.cancel.body) // 2]
        p.send_data(plan.cancel.sid, half, end_stream=False)
        chunks = {r.sid: split_chunks(r.body, REQ_CHUNKS) for r in plan.concurrent}
        for c in range(REQ_CHUNKS):
            for r in plan.concurrent:
                if chunks[r.sid][c]:
                    p.send_data(r.sid, chunks[r.sid][c], end_stream=False)
        p.send_rst(plan.cancel.sid, ERR_CANCEL)        # the sibling dies mid-burst
        for r in reversed(plan.concurrent):
            p.send_data(r.sid, b"", end_stream=True)   # completion in REVERSE order
        self._await([r.sid for r in plan.concurrent], CLIENT_DEADLINE)

    def tail(self, req) -> None:
        p = self.peer
        assert p is not None
        p.send_headers(req.sid, req.headers, end_stream=False)
        p.send_data(req.sid, req.body, end_stream=True)
        self._await([req.sid], 20.0)

    def _await(self, sids: list[int], timeout: float) -> None:
        p = self.peer
        assert p is not None
        deadline = time.time() + timeout
        while time.time() < deadline:
            pending = [s for s in sids if not (p.streams[s].end_stream or p.streams[s].rst is not None)]
            if not pending or p.goaway:
                return
            p.pump(0.5)

    def close(self) -> None:
        try:
            if self.peer:
                self.peer.send_goaway(max(self.peer.streams, default=0))
        except Exception:  # noqa: BLE001
            pass
        for s in (self.tls, self.raw):
            try:
                if s:
                    s.close()
            except OSError:
                pass


def build_plan(tag: str, authority: str, n: int):
    """The requests: n concurrent streams (sids 1,3,5,...), one to cancel, one tail."""
    def req(k: str, sid: int, size: int | None):
        nonce = secrets.token_hex(8)
        if size == 0:
            body = b""
        else:
            seed = hashlib.sha256(f"{tag}|req|{k}|{nonce}".encode()).hexdigest()
            filler_len = size if size is not None else 1536
            filler = (seed * (filler_len // len(seed) + 1))[:filler_len]
            body = json.dumps({"stream": k, "tag": tag, "nonce": nonce, "filler": filler}).encode()
        path = f"/mux/{k}?t={tag}"
        headers = [
            (b":method", b"POST"), (b":scheme", b"https"), (b":authority", authority.encode()),
            (b":path", path.encode()),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-e2e-stream", k.encode()), (b"x-e2e-tag", tag.encode()),
            (b"user-agent", b"aitm-e2e-h2-mux/1"),
        ]
        return SimpleNamespace(k=k, sid=sid, path=path, headers=headers, body=body)

    concurrent = []
    for i in range(n):
        size = 0 if i == EMPTY_STREAM else BIG if i == BIG_REQ_STREAM else None
        concurrent.append(req(str(i), 2 * i + 1, size))
    cancel = req("cancel", 2 * n + 1, None)
    tail = req("tail", 2 * n + 3, None)
    return SimpleNamespace(concurrent=concurrent, cancel=cancel, tail=tail)


# ==================================================================================
# Bus helpers
# ==================================================================================

def collect_quiet(bus: BusClient, quiet: float = 1.5, max_wait: float = 20.0) -> list[dict]:
    """params of every flow notification on `bus` until `quiet` seconds pass with none."""
    out = [m.get("params") or {} for m in bus.notifications
           if m.get("id") is None and m.get("method") == FLOW_NOTE]
    bus.notifications.clear()
    deadline = time.time() + max_wait
    while time.time() < deadline:
        bus._set_read_timeout(quiet)
        try:
            m = bus._recv()
        except (socket.timeout, TimeoutError):
            break
        finally:
            bus._restore_read_timeout()
        if m.get("id") is None and m.get("method") == FLOW_NOTE:
            out.append(m.get("params") or {})
    return out


def header_value(headers, name: str) -> str | None:
    """A header value from flow.detail's `[[name, value], ...]` (case-insensitive)."""
    for pair in headers or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).lower() == name:
            return str(pair[1])
    return None


def b64(s) -> bytes:
    return base64.b64decode(s) if s else b""


def ts(s: str) -> float:
    s = re.sub(r"\.(\d{6})\d+", r".\1", s).replace("Z", "+00:00")
    return dt.datetime.fromisoformat(s).timestamp()


def our_rows(bus: BusClient, authority: str) -> list[dict]:
    rows = bus.call("flow.table")
    rows = rows.get("flows", rows) if isinstance(rows, dict) else rows
    return [r for r in rows if r.get("authority") == authority and str(r.get("path", "")).startswith("/mux/")]


# ==================================================================================

def main() -> int:
    tag = f"h2mux-{os.getpid()}-{secrets.token_hex(4)}"
    workdir = tempfile.mkdtemp(prefix="aitm-e2e-h2-")
    upstream = None
    bus = sub = None
    session = None
    try:
        section("arrange: the runner's core, which must be able to MITM a lab TLS origin")
        core = env_core()
        bus = BusClient.agent(core)
        names = set(bus.tool_names())
        for need in ("config.get", "flow.table", "flow.detail", "flow.get", "flow.list", "flow.subscribe"):
            check(need in names, f"the core exposes {need}")
        cfgv = bus.call("config.get")
        insecure = isinstance(cfgv, dict) and cfgv.get("ssl_insecure") is True
        if not insecure:
            skip(f"the runner's core runs ssl_insecure={cfgv.get('ssl_insecure') if isinstance(cfgv, dict) else '?'}: "
                 f"it verifies upstream certificates against the webpki roots and would refuse the "
                 f"self-signed h2 origin this suite needs -- boot it with `ssl_insecure: true`")
        ok(f"attached to the core at {core.bus_addr}; proxy {core.proxy_host}:{core.cfg.proxy_port}; ssl_insecure=true")
        max_body = (cfgv.get("limits") or {}).get("max_body_bytes") if isinstance(cfgv, dict) else None
        if isinstance(max_body, int) and max_body < BIG:
            fail(f"limits.max_body_bytes={max_body} is below this suite's {BIG}-byte stream body")

        section("arrange: a self-signed h2-over-TLS upstream (the independent observer)")
        cert, key = make_self_signed(workdir)
        upstream = H2Upstream(cert, key, tag).start()
        upstream.response_filler = {str(BIG_RESP_STREAM): BIG, str(EMPTY_STREAM): 0}
        ok(f"upstream {upstream.authority}: TLS, ALPN h2 only, records every connection and stream, "
           f"holds all responses until every expected request has completed")

        section("arrange: the core's CA via ca.export, so the client VERIFIES the MITM leaf")
        # ca.export is Sensitive: the operator may always run it; the agent only under
        # an `all`/`ask` policy. A refusal is a role fact, not a multiplexing fact, so
        # it degrades to an unverified TLS client and says so.
        ca_pem, ca_src, ca_why = None, None, "this core has no ca.export"
        if "ca.export" in names:
            attempts = []
            if core.cfg.operator_token:
                op = BusClient.operator(core)
                try:
                    attempts.append(("operator", op.try_call("ca.export", {"format": "pem"})))
                finally:
                    op.close()
            attempts.append(("agent", bus.try_call("ca.export", {"format": "pem"})))
            for role, (st, res) in attempts:
                if st == "ok" and isinstance(res, dict) and isinstance(res.get("certificate"), str):
                    ca_pem, ca_src = res["certificate"], role
                    check("BEGIN CERTIFICATE" in ca_pem,
                          f"ca.export ({role}) returned the root CA as PEM (sha256 "
                          f"{str(res.get('fingerprint_sha256', '?'))[:23]}...)")
                    break
                ca_why = f"ca.export refused for {role}: {str(res)[:90]}"
        if not ca_pem:
            ok(f"{ca_why}; the client will not verify the MITM leaf (CERT_NONE)")

        section("arrange: a live flow.subscribe narrowed to our upstream, opened BEFORE any traffic")
        sub = BusClient.agent(core)
        r = sub.call("flow.subscribe", {"filter": {"host": upstream.authority}})
        check(isinstance(r, dict) and "sub_id" in r, f"subscribed to live flow events for {upstream.authority} ({r})")

        section("act: ONE connection -> CONNECT -> TLS (verified) -> ALPN h2 -> preface + SETTINGS")
        session = H2Session(core.proxy_host, core.cfg.proxy_port, upstream.authority, ca_pem)
        cap = session.open()
        ok(f"CONNECT answered {session.connect_status!r}; {session.tls_version}; ALPN {session.alpn}; "
           f"client socket {session.local_addr[0]}:{session.local_addr[1]}")
        if ca_pem:
            subj = dict(x[0] for x in (session.leaf or {}).get("subject", ()))
            sans = [v for t, v in (session.leaf or {}).get("subjectAltName", ()) if t == "IP Address"]
            ok(f"the MITM leaf verified against the CA exported by the {ca_src}, hostname check on "
               f"(CN={subj.get('commonName')!r}, IP SANs {sans})")
        check(isinstance(session.peer.peer_settings.get(S_MAX_CONCURRENT_STREAMS, 0), int),
              f"the proxy's SETTINGS: {{{', '.join(f'{k}={v}' for k, v in sorted(session.peer.peer_settings.items()))}}}")
        n = N_STREAMS if cap is None else min(N_STREAMS, cap)
        check(n >= 2, f"the proxy allows {cap} concurrent streams; this burst opens {n}")
        plan = build_plan(tag, upstream.authority, n)
        upstream.expected = n

        section(f"act: {n} streams opened before any body byte, bodies interleaved ({REQ_CHUNKS} pieces each, "
                f"one {BIG // 1024} KiB, one empty), sibling stream cancelled mid-burst, END_STREAM in reverse")
        t_burst = time.time()
        session.burst(plan)
        burst_s = time.time() - t_burst
        ok(f"burst finished in {burst_s:.2f}s: {sum(len(r.body) for r in plan.concurrent)} request bytes out, "
           f"{sum(len(session.peer.streams[r.sid].body) for r in plan.concurrent)} response bytes in")

        section("act: one more request on the SAME connection after the burst (it must have survived)")
        session.tail(plan.tail)
        tail_st = session.peer.streams[plan.tail.sid]
        check(tail_st.end_stream and tail_st.rst is None and tail_st.header(b":status") == b"200",
              f"the tail request completed on the same connection (status {tail_st.header(b':status')!r}, "
              f"{len(tail_st.body)} bytes)")

        # Let the upstream settle its records, then stop talking.
        for rec in upstream.conns:
            rec.responded.wait(5)
        session.close()

        # ---------------------------------------------------------------------------
        section("ground truth A (wire): every stream answered on the right stream, nothing reset")
        p = session.peer
        check(p.goaway is None, f"no GOAWAY from the proxy (got {p.goaway})")
        check(p.push_promises == 0, "no PUSH_PROMISE from the proxy")
        rsts = {s: st.rst for s, st in p.streams.items() if st.rst is not None and s != plan.cancel.sid}
        check(not rsts, f"no RST_STREAM on any of our streams (got {rsts})")
        incomplete = [r.k for r in plan.concurrent if not p.streams[r.sid].end_stream]
        check(not incomplete, f"all {n} responses completed (missing: {incomplete})")
        if incomplete:
            fail("cannot continue without every response")
        for r in plan.concurrent:
            st = p.streams[r.sid]
            status = st.header(b":status")
            k_hdr = (st.header(b"x-e2e-stream") or b"").decode("latin1")
            barrier = (st.header(b"x-e2e-barrier") or b"").decode("latin1")
            sha_hdr = (st.header(b"x-e2e-req-sha256") or b"").decode("latin1")
            want_sha = hashlib.sha256(r.body).hexdigest()
            check(status == b"200" and k_hdr == r.k,
                  f"stream {r.sid} (k={r.k}): status {status!r}, response names stream {k_hdr!r}")
            check(sha_hdr == want_sha,
                  f"stream {r.sid}: the upstream echoed SHA-256 of OUR {len(r.body)}-byte body for this stream "
                  f"({sha_hdr[:12]}... == {want_sha[:12]}...)")
            check(barrier == "ok", f"stream {r.sid}: response was released by the barrier "
                                   f"(x-e2e-barrier={barrier!r}, seen={st.header(b'x-e2e-barrier-seen')!r})")
        conn_total = sum(len(p.streams[r.sid].body) for r in plan.concurrent)
        ok(f"{conn_total} response bytes over one connection; the proxy sent {p.window_updates} WINDOW_UPDATEs, "
           f"{p.pings} PINGs")
        big_in = p.streams[plan.concurrent[BIG_RESP_STREAM].sid] if BIG_RESP_STREAM < n else None
        if big_in:
            check(len(big_in.body) > DEFAULT_WINDOW and big_in.data_frames >= 2,
                  f"the {len(big_in.body)}-byte response exceeded the initial window and arrived in "
                  f"{big_in.data_frames} DATA frames (flow control worked)")
        data_log = [sid for t, sid, fl, ln in p.log if t == F_DATA and ln > 0]
        switches = sum(1 for a, b in zip(data_log, data_log[1:]) if a != b)
        first_end = next((i for i, (t, sid, fl, ln) in enumerate(p.log)
                          if t in (F_DATA, F_HEADERS) and fl & FLAG_END_STREAM), None)
        opened_before_end = len({sid for i, (t, sid, fl, ln) in enumerate(p.log)
                                 if t == F_HEADERS and (first_end is None or i < first_end)})
        ok(f"interleaving seen by the client: {len(data_log)} DATA frames with {switches} stream switches; "
           f"{opened_before_end} response heads arrived before the first END_STREAM")

        # ---------------------------------------------------------------------------
        section("ground truth B (upstream): ONE connection, ALL streams, barrier held, bytes verbatim")
        check(len(upstream.conns) == 1,
              f"the proxy opened exactly one upstream connection (got {len(upstream.conns)}: "
              f"{[(c.index, c.peer, c.alpn, c.error) for c in upstream.conns]})")
        rec = upstream.conns[0]
        check(rec.error is None, f"the upstream connection ran clean (error: {rec.error})")
        check(rec.alpn == "h2", f"the proxy negotiated ALPN h2 towards the upstream ({rec.alpn}, {rec.tls_version})")
        check(rec.barrier_ok is True and rec.seen_at_barrier == n,
              f"the barrier held: {rec.seen_at_barrier}/{n} requests complete on this connection before any "
              f"response went out (waited {rec.barrier_wait:.2f}s)")
        up = rec.h2
        by_k = {}
        for sid, st in up.streams.items():
            k = (st.header(b"x-e2e-stream") or b"").decode("latin1")
            if k:
                by_k.setdefault(k, []).append(sid)
        check(all(len(v) == 1 for v in by_k.values()),
              f"each stream marker arrived on exactly one upstream stream ({ {k: v for k, v in by_k.items() if len(v) != 1} })")
        check("cancel" not in by_k,
              "the cancelled sibling stream NEVER reached the upstream (its body never completed)")
        for r in plan.concurrent:
            sids = by_k.get(r.k, [])
            if len(sids) != 1:
                fail(f"stream k={r.k} not found at the upstream (sids {sids})")
            st = up.streams[sids[0]]
            got = {name: value for name, value in st.headers}
            check(got.get(b":method") == b"POST" and got.get(b":scheme") == b"https"
                  and got.get(b":path") == r.path.encode() and got.get(b":authority") == upstream.authority.encode(),
                  f"k={r.k} -> upstream stream {sids[0]}: :method/:scheme/:path/:authority as the client sent them")
            check(bytes(st.body) == r.body,
                  f"k={r.k}: the {len(r.body)}-byte request body reached the upstream byte-for-byte")
            missing = [name for name, _ in r.headers
                       if not name.startswith(b":") and got.get(name) != dict(r.headers)[name]]
            check(not missing, f"k={r.k}: every request header reached the upstream verbatim (missing/changed: {missing})")
            check(bytes(p.streams[r.sid].body) == rec.sent[sids[0]],
                  f"k={r.k}: the client received EXACTLY the {len(rec.sent[sids[0]])} bytes the upstream sent on stream {sids[0]}")
        ok(f"upstream completion order (sids): {rec.request_order}; response order {rec.response_order}; "
           f"END_STREAM order {rec.end_order}")
        tail_sids = by_k.get("tail", [])
        check(len(tail_sids) == 1 and bytes(up.streams[tail_sids[0]].body) == plan.tail.body
              and bytes(tail_st.body) == rec.sent.get(tail_sids[0]),
              "the tail request/response also round-tripped exactly on the same upstream connection")

        # ---------------------------------------------------------------------------
        section("ground truth C (bus, live): all N created + request events BEFORE the first response")
        events = collect_quiet(sub)
        ours = [e for e in events if (e.get("summary") or {}).get("authority") == upstream.authority
                and str((e.get("summary") or {}).get("path", "")).startswith("/mux/")]
        by_path = {}
        for e in ours:
            by_path.setdefault(e["summary"]["path"], []).append(e.get("event"))
        conc_paths = {r.path for r in plan.concurrent}
        created = [e for e in ours if e.get("event") == "created"]
        check(len({e["id"] for e in created}) == n + 2 and len(created) == n + 2,
              f"exactly one `created` per flow: {len(created)} for {n} streams + cancel + tail")
        first_resp = next((i for i, e in enumerate(ours) if e.get("event") == "response"), None)
        last_created = max((i for i, e in enumerate(ours)
                            if e.get("event") == "created" and e["summary"]["path"] in conc_paths), default=None)
        last_request = max((i for i, e in enumerate(ours)
                            if e.get("event") == "request" and e["summary"]["path"] in conc_paths), default=None)
        check(first_resp is not None and last_created is not None and last_created < first_resp,
              f"all {n} streams were `created` before the first `response` (last created at #{last_created}, "
              f"first response at #{first_resp})")
        check(last_request is not None and first_resp is not None and last_request < first_resp,
              f"all {n} request bodies completed (`request`) before the first `response` (#{last_request} < #{first_resp})")
        cancel_events = by_path.get(plan.cancel.path, [])
        check(cancel_events[:1] == ["created"] and "killed" in cancel_events and "response" not in cancel_events,
              f"the cancelled stream: created -> killed, never a response ({cancel_events})")
        id_by_path = {e["summary"]["path"]: e["id"] for e in created}

        # ---------------------------------------------------------------------------
        section("ground truth D (store): flow.table / flow.detail, every field, every byte, one connection")
        deadline = time.time() + 15
        rows = []
        while time.time() < deadline:
            rows = our_rows(bus, upstream.authority)
            done_rows = [r for r in rows if r.get("status") == 200]
            if len(rows) >= n + 2 and len(done_rows) >= n + 1:
                break
            time.sleep(0.2)
        check(len(rows) == n + 2, f"flow.table has exactly {n + 2} rows for {upstream.authority} (got {len(rows)})")
        row_by_path = {r["path"]: r for r in rows}
        for r in plan.concurrent + [plan.tail]:
            row = row_by_path.get(r.path, {})
            check(row.get("method") == "POST" and row.get("status") == 200,
                  f"flow.table row for {r.path.split('?')[0]}: POST, status {row.get('status')}")
        crow = row_by_path.get(plan.cancel.path, {})
        check(crow.get("status") is None, f"flow.table row for the cancelled stream has no status ({crow.get('status')})")
        listed = bus.call("flow.list")
        check(set(id_by_path.values()) <= set(listed), "every flow id the live events announced is in flow.list")
        check(all(row_by_path[r.path]["id"] == id_by_path[r.path] for r in plan.concurrent),
              "flow.table ids agree with the live `created` events, path by path")

        peers, established, windows = set(), set(), []
        for r in plan.concurrent + [plan.tail]:
            fid = row_by_path[r.path]["id"]
            d = bus.call("flow.detail", {"id": fid, "body": "inline"})
            req, resp = d.get("request") or {}, d.get("response") or {}
            cc, sc = d.get("client_conn") or {}, d.get("server_conn") or {}
            label = f"k={r.k}"
            check(d.get("kind") == "http" and req.get("version") == "HTTP/2" and resp.get("version") == "HTTP/2",
                  f"{label}: request.version={req.get('version')} response.version={resp.get('version')}")
            check(req.get("method") == "POST" and req.get("scheme") == "https"
                  and req.get("authority") == upstream.authority and req.get("path") == r.path,
                  f"{label}: request line POST https://{req.get('authority')}{str(req.get('path')).split('?')[0]}")
            check(header_value(req.get("headers"), "x-e2e-stream") == r.k
                  and header_value(req.get("headers"), "x-e2e-tag") == tag
                  and header_value(req.get("headers"), "content-type") == "application/json",
                  f"{label}: captured request headers carry x-e2e-stream={r.k}, our tag, content-type")
            check(b64(req.get("body")) == r.body and req.get("body_size") == len(r.body)
                  and req.get("body_truncated") is False,
                  f"{label}: captured request body == the {len(r.body)} bytes the client sent (base64-decoded)")
            sid_u = by_k[r.k][0]
            check(resp.get("status") == 200 and header_value(resp.get("headers"), "x-e2e-stream") == r.k
                  and header_value(resp.get("headers"), "x-e2e-upstream-stream-id") == str(sid_u),
                  f"{label}: captured response: 200, names stream {r.k}, upstream stream {sid_u}")
            check(b64(resp.get("body")) == rec.sent[sid_u] and resp.get("body_size") == len(rec.sent[sid_u])
                  and resp.get("body_truncated") is False,
                  f"{label}: captured response body == the {len(rec.sent[sid_u])} bytes the upstream sent")
            check(cc.get("alpn") == "h2" and cc.get("tls") is True and sc.get("alpn") == "h2" and sc.get("tls") is True,
                  f"{label}: client_conn alpn={cc.get('alpn')} tls={cc.get('tls')}; server_conn alpn={sc.get('alpn')} tls={sc.get('tls')}")
            check(sc.get("peer") == upstream.authority and sc.get("sni") == "127.0.0.1",
                  f"{label}: server_conn.peer={sc.get('peer')} sni={sc.get('sni')}")
            check((d.get("meta") or {}).get("truncated") is False and d.get("intercept") == "observed",
                  f"{label}: not truncated, intercept={d.get('intercept')}")
            peers.add(cc.get("peer"))
            established.add(cc.get("established"))
            if r is not plan.tail:
                meta = d.get("meta") or {}
                if meta.get("created") and isinstance(meta.get("duration_ms"), int):
                    c0 = ts(meta["created"])
                    windows.append((r.k, c0, c0 + meta["duration_ms"] / 1000.0))
        want_peer = f"{session.local_addr[0]}:{session.local_addr[1]}"
        check(peers == {want_peer},
              f"every flow's client_conn.peer is the client socket's own address {want_peer} -- one connection "
              f"carried all {n + 1} flows (got {sorted(peers)})")
        check(len(established) == 1, f"every flow shares one client_conn.established ({established})")
        check(len(windows) == n, f"meta.created + duration_ms present on all {n} stream flows ({len(windows)})")
        if windows:
            last_open = max(w[1] for w in windows)
            first_close = min(w[2] for w in windows)
            check(last_open <= first_close + 0.002,
                  f"the proxy's own clock: the LAST stream was created {(first_close - last_open) * 1000:.1f} ms "
                  f"before the FIRST stream finished -- all {n} flows were open at once")

        cdet = bus.call("flow.detail", {"id": crow["id"], "body": "none"})
        check(cdet.get("response") is None and (cdet.get("request") or {}).get("version") == "HTTP/2",
              f"the cancelled stream's flow: HTTP/2 request, no response (intercept={cdet.get('intercept')})")
        big_row = row_by_path[plan.concurrent[BIG_REQ_STREAM].path] if BIG_REQ_STREAM < n else None
        if big_row:
            ok(f"the {BIG}-byte request body (k={BIG_REQ_STREAM}) and the {BIG}-byte response body "
               f"(k={BIG_RESP_STREAM}) both captured whole; empty bodies on k={EMPTY_STREAM} captured as empty")
    finally:
        if session:
            session.close()
        for b in (sub, bus):
            if b:
                b.close()
        if upstream:
            upstream.stop()
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
