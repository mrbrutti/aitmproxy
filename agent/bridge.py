#!/usr/bin/env python3
"""Stdio <-> loopback-TCP bridge for the aitmproxy MCP bus.

A standard MCP client (Claude, Codex, a generic client) speaks newline-delimited
JSON-RPC over the stdio transport. aitmproxy's loopback-TCP transport is also
newline-delimited JSON-RPC, but it gates the connection on a one-line token
handshake: the first line must be `{"token": "<agent-token>"}`. This script is
the thin shim between the two — it is a transport bridge, not an agent and not an
SDK: it opens a TCP connection to the running bus, sends the token line read from
a file, and then relays stdin->socket and socket->stdout line for line.

The operator starts `aitm` with `mcp.transport: {loopback_tcp: {port, token}}` and
writes the same token into the token file (mode 0600). Nothing here embeds the
token or prints it.

Usage:
    bridge.py --host 127.0.0.1 --port 8084 --token-file ~/.config/aitm/agent.token

It is pure standard library (no dependencies) and takes no input but its flags, so
a harness can spawn it directly as its MCP server command.
"""

import argparse
import json
import socket
import sys
import threading


def _relay(src, dst):
    """Copy bytes from src to dst until src closes, then half-close dst."""
    try:
        while True:
            chunk = src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            dst.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            dst.close()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="aitmproxy MCP stdio<->TCP bridge")
    parser.add_argument("--host", default="127.0.0.1", help="loopback bus host")
    parser.add_argument("--port", type=int, required=True, help="loopback bus port")
    parser.add_argument(
        "--token-file",
        required=True,
        help="file holding the agent token (first-line handshake)",
    )
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print(f"bridge: refusing non-loopback host {args.host!r}", file=sys.stderr)
        return 2

    try:
        with open(args.token_file, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError as exc:
        print(f"bridge: cannot read token file: {exc}", file=sys.stderr)
        return 2
    if not token:
        print("bridge: token file is empty", file=sys.stderr)
        return 2

    try:
        sock = socket.create_connection((args.host, args.port))
    except OSError as exc:
        print(f"bridge: cannot reach the bus at {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    # The token handshake line, JSON-encoded without leaking it to any stream but
    # the socket. json.dumps keeps the quoting correct for odd tokens.
    sock.sendall((json.dumps({"token": token}) + "\n").encode("utf-8"))

    sock_r = sock.makefile("rb")
    sock_w = sock.makefile("wb")
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    up = threading.Thread(target=_relay, args=(stdin, sock_w), daemon=True)
    down = threading.Thread(target=_relay, args=(sock_r, stdout), daemon=True)
    up.start()
    down.start()
    # The bus closing the connection (down finishes) ends the session.
    down.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
