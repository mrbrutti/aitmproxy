"""A minimal RFC 6455 WebSocket MCP client over the `aitm web` /bus bridge.

The web UI talks to the core over a WebSocket at ws://<web>/bus: the first text
frame is the {"token":...} line, then newline-delimited JSON-RPC rides text
frames. This client reuses BusClient's JSON-RPC logic and overrides only the
transport primitives, so BusClient's public surface is unchanged (additive).

Pure stdlib (no websocket-client dependency). Text frames + ping/pong only.
"""

from __future__ import annotations

import base64
import os
import socket
import struct

from .bus import BusClient, BusError


class WsBusClient(BusClient):
    def __init__(self, host: str, port: int, token: str, *,
                 client_name: str = "aitm-e2e-web", path: str = "/bus"):
        super().__init__(host, port, token, client_name=client_name)
        self._path = path
        self._lines: list[str] = []  # complete JSON-RPC objects ready to parse
        self._frame_tail = b""       # bytes read past the HTTP upgrade response

    @classmethod
    def web_agent(cls, core, **kw) -> "WsBusClient":
        """Connect to `aitm web`'s /bus as the AGENT (the --token value)."""
        return cls("127.0.0.1", core.web_port, core.cfg.agent_token,
                   client_name="aitm-e2e-web-agent", **kw).connect()

    @classmethod
    def web_operator(cls, core, bridge_token: str, **kw) -> "WsBusClient":
        """Connect as OPERATOR using the fresh per-run operator BRIDGE token that
        `aitm web` prints to stdout (never the mcp.operator_token secret)."""
        return cls("127.0.0.1", core.web_port, bridge_token,
                   client_name="aitm-e2e-web-operator", **kw).connect()

    def connect(self) -> "WsBusClient":
        self._sock = socket.create_connection((self.host, self.port), timeout=20)
        self._sock.settimeout(20)
        self._ws_handshake()
        self._send({"token": self._token})
        self.initialize()
        return self

    # --- WebSocket handshake + framing -----------------------------------

    def _ws_handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {self._path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Origin: http://{self.host}:{self.port}\r\n"
            "\r\n"
        )
        self._sock.sendall(req.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self._sock.recv(1024)
            if not chunk:
                raise BusError("ws: connection closed during handshake")
            data += chunk
        status_line = data.split(b"\r\n", 1)[0].decode("latin1")
        if "101" not in status_line:
            raise BusError(f"ws: upgrade refused: {status_line!r}")
        self._frame_tail = data.split(b"\r\n\r\n", 1)[1]

    def _write_line(self, text: str) -> None:
        self._sock.sendall(self._encode_frame((text + "\n").encode("utf-8")))

    def _read_line(self) -> str:
        # A /bus frame carries one or more newline-separated JSON objects; the last
        # may have no trailing newline. Split each frame into ready objects rather
        # than requiring a terminator (which would hang on a single-object frame).
        while not self._lines:
            text = self._read_frame_text()
            self._lines.extend(p for p in text.split("\n") if p.strip())
        return self._lines.pop(0)

    def _read_frame_text(self) -> str:
        while True:
            opcode, payload = self._read_frame()
            if opcode == 0x8:  # close
                raise BusError("ws: server sent close")
            if opcode == 0x9:  # ping -> pong
                self._sock.sendall(self._encode_frame(payload, opcode=0xA))
                continue
            if opcode == 0xA:  # pong
                continue
            return payload.decode("utf-8", "replace")

    def _read_frame(self):
        h = self._recv_n(2)
        b1 = h[1]
        opcode = h[0] & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_n(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_n(8))[0]
        mask = self._recv_n(4) if masked else None
        payload = self._recv_n(length) if length else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def _recv_n(self, n: int) -> bytes:
        out = b""
        if self._frame_tail:
            take = self._frame_tail[:n]
            out += take
            self._frame_tail = self._frame_tail[len(take):]
        while len(out) < n:
            chunk = self._sock.recv(n - len(out))
            if not chunk:
                raise BusError("ws: connection closed")
            out += chunk
        return out

    @staticmethod
    def _encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
        b = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            b.append(0x80 | n)
        elif n < 65536:
            b.append(0x80 | 126)
            b += struct.pack(">H", n)
        else:
            b.append(0x80 | 127)
            b += struct.pack(">Q", n)
        mask = os.urandom(4)
        b += mask
        b += bytes(p ^ mask[i % 4] for i, p in enumerate(payload))
        return bytes(b)

    def _set_read_timeout(self, seconds: float) -> None:
        if self._sock:
            self._sock.settimeout(seconds)

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
