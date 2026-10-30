#!/usr/bin/env python3
"""Minimal MCP bus client for driving aitmproxy over its loopback-TCP bus.

The whole blind assessment is driven through this: it performs the token
handshake, the MCP `initialize`, then one or more `tools/call` requests, and
prints each result as JSON so the agent can read the live evidence.

Usage:
  mcpcli.py <tool> '<json-args>'          # single call
  mcpcli.py --batch calls.jsonl           # one {"tool":..,"args":..} per line
  mcpcli.py --list                         # tools/list
All calls in one invocation share ONE bus connection (and the one shared
obscura browser session persists across invocations too).
"""
import json
import os
import socket
import sys
import time

ENDPOINT_FILE = "/Users/matt/Security/aitmproxy/.claude/worktrees/blind-pentest-bwapp-542fcf/bwapp-assessment/bus.endpoint"
AGENT_TOKEN = "f53c2ce661e3992b2824b9d24aed6b899155c4a790056007"
OPERATOR_TOKEN = "064a8a192406bb42a9413881659b2d4e37a70b3698aa508d"
# Default role is the autonomous agent; set AITM_ROLE=operator for operator-gated calls.
TOKEN = OPERATOR_TOKEN if os.environ.get("AITM_ROLE") == "operator" else AGENT_TOKEN
TIMEOUT = 120.0


class Bus:
    def __init__(self, token=None):
        host, port = open(ENDPOINT_FILE).read().strip().rsplit(":", 1)
        self.sock = socket.create_connection((host, int(port)), timeout=TIMEOUT)
        self.sock.settimeout(TIMEOUT)
        self.buf = b""
        self._id = 0
        self._send({"token": token or TOKEN})
        self.rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "blind-pentest-agent", "version": "1.0"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _readline(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("bus closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()

    def rpc(self, method, params):
        self._id += 1
        rid = self._id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            msg = json.loads(self._readline())
            if msg.get("id") == rid:
                return msg
        raise RuntimeError("timeout waiting for id %d" % rid)

    def call(self, tool, args):
        return self.rpc("tools/call", {"name": tool, "arguments": args or {}})


def main():
    a = sys.argv[1:]
    bus = Bus()
    if a and a[0] == "--list":
        r = bus.rpc("tools/list", {})
        tools = [t["name"] for t in r.get("result", {}).get("tools", [])]
        print(json.dumps(tools, indent=2))
        return
    if a and a[0] == "--batch":
        for line in open(a[1]):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            spec = json.loads(line)
            r = bus.call(spec["tool"], spec.get("args", {}))
            print("=== %s %s" % (spec["tool"], json.dumps(spec.get("args", {}))))
            print(json.dumps(r.get("result", r.get("error")), indent=2))
            print()
        return
    tool = a[0]
    args = json.loads(a[1]) if len(a) > 1 else {}
    r = bus.call(tool, args)
    print(json.dumps(r.get("result", r.get("error")), indent=2))


if __name__ == "__main__":
    main()
