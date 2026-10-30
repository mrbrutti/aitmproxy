"""A minimal MCP bus client over the loopback-TCP transport (pure stdlib).

Wire protocol (verified in crates/aitm-mcp/src/transport.rs):
  1. connect TCP to the bound bus address
  2. send ONE line: {"token": "<t>"}      (operator token -> Operator role,
     agent token -> Mcp role, unknown -> one `unauthorized` line then close)
  3. newline-delimited JSON-RPC: initialize, tools/list, tools/call, ...

The role a BusClient gets is decided purely by which token it presents, so a
scenario drives the same core as operator AND agent to assert the real gating.
"""

from __future__ import annotations

import json
import socket

PROTOCOL_VERSION = "2025-06-18"


class BusError(RuntimeError):
    pass


class ToolError(RuntimeError):
    """A tools/call that returned isError (e.g. a policy refusal). The message is
    the tool's own error text, so a scenario can assert on it."""


class BusClient:
    def __init__(self, host: str, port: int, token: str, *, client_name: str = "aitm-e2e"):
        self.host = host
        self.port = port
        self._token = token
        self._client_name = client_name
        self._sock: socket.socket | None = None
        self._rfile = None
        self._id = 0
        self.notifications: list[dict] = []

    @classmethod
    def operator(cls, core, **kw) -> "BusClient":
        host, port = core.bus_addr
        return cls(host, port, core.cfg.operator_token, client_name="aitm-e2e-operator", **kw).connect()

    @classmethod
    def agent(cls, core, **kw) -> "BusClient":
        host, port = core.bus_addr
        return cls(host, port, core.cfg.agent_token, client_name="aitm-e2e-agent", **kw).connect()

    def connect(self) -> "BusClient":
        self._sock = socket.create_connection((self.host, self.port), timeout=20)
        self._sock.settimeout(20)
        self._rfile = self._sock.makefile("r", encoding="utf-8", newline="\n")
        self._send({"token": self._token})
        self.initialize()
        return self

    def initialize(self) -> dict:
        return self.rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": self._client_name, "version": "0"},
        })

    def tools(self) -> list[dict]:
        return self.rpc("tools/list", {}).get("tools", [])

    def tool_names(self) -> list[str]:
        return [t["name"] for t in self.tools()]

    def call(self, name: str, arguments: dict | None = None):
        """Invoke a tool. Raises ToolError on isError (with the tool's message).
        Returns structuredContent when present, else the parsed text content."""
        r = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if r.get("isError"):
            text = ""
            content = r.get("content") or []
            if content and isinstance(content[0], dict):
                text = content[0].get("text", "")
            raise ToolError(f"{name}: {text or 'error'}")
        if "structuredContent" in r:
            return r["structuredContent"]
        content = r.get("content") or []
        text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    def try_call(self, name: str, arguments: dict | None = None):
        """Like call() but returns ('ok', result) or ('error', message) instead of
        raising — for asserting that a gated call is REFUSED for a role."""
        try:
            return ("ok", self.call(name, arguments))
        except ToolError as e:
            return ("error", str(e))

    def confirm(self, name: str, arguments: dict | None = None):
        """Operator two-phase confirm handshake (M4 D4): call a confirm-prompt
        command; if it returns {status: needs_confirmation, confirm_token}, re-send
        with the reserved `_confirm` argument. Returns the final result.

        Use from an operator BusClient for ca.install/uninstall, l4.inject, etc."""
        args = dict(arguments or {})
        r = self.call(name, args)
        if isinstance(r, dict) and r.get("status") == "needs_confirmation":
            token = r.get("confirm_token")
            if not token:
                raise BusError(f"{name}: needs_confirmation without a confirm_token")
            args["_confirm"] = token
            return self.call(name, args)
        return r

    # ---- JSON-RPC plumbing ----------------------------------------------

    def rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        mid = self._id
        self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        while True:
            msg = self._recv()
            if msg.get("id") == mid:
                if "error" in msg:
                    raise BusError(f"rpc {method}: {json.dumps(msg['error'])}")
                return msg.get("result", {})
            # Anything else is a server-initiated notification; stash it.
            self.notifications.append(msg)

    def drain_notifications(self, timeout: float = 1.0) -> list[dict]:
        """Read any pending server-pushed notification lines (non-blocking-ish)."""
        assert self._sock
        got: list[dict] = []
        self._sock.settimeout(timeout)
        try:
            while True:
                got.append(self._recv())
        except (socket.timeout, OSError):
            pass
        finally:
            self._sock.settimeout(20)
        self.notifications.extend(got)
        return got

    def _send(self, obj: dict) -> None:
        assert self._sock
        self._sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def _recv(self) -> dict:
        assert self._rfile
        line = self._rfile.readline()
        if not line:
            raise BusError("bus connection closed by the core")
        return json.loads(line)

    def close(self) -> None:
        try:
            if self._rfile:
                self._rfile.close()
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "BusClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
