#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
"""AC T4-2: seeded Cross-Site WebSocket Hijacking is found on V (`ws-cswsh`, `certain`)
and not on P; the dialer regenerated `Sec-WebSocket-Key` and kept the `Cookie`.

Real, never a fixture: the cell logs in to each target (`POST /login`
user=alice&pass=wonderland -> `Set-Cookie: session=<32 hex>`), then holds a real
authenticated `/ws` conversation THROUGH the aitm proxy with a legitimate `Origin`
and the session cookie, recording its own `Sec-WebSocket-Key` K. A `scan.start`
with `lanes: ["ws"]` runs the CSWSH check, which re-dials with a FOREIGN `Origin`
and the captured cookie.

- On V (`/ws` accepts any `Origin`): an issue `class == "ws-cswsh"`, `confidence ==
  "certain"`; and the target's own WS handshake log (the independent observer) has a
  lane handshake whose `origin` is not V's own origin, whose `sec_websocket_key`
  differs from K (the dialer regenerated it), that kept the session cookie
  (`"session" in cookie_names`), and that was `accepted == True`.
- On P (`/ws` rejects a foreign `Origin`): no `ws-cswsh` issue, and every foreign-origin
  handshake entry is `accepted == False`, `status == 403`.

SKIP 77 when: the scanner verbs are absent, or the `ws` lane has no `scan.checks`
entry on this build (the ws lane is not on `main`).

Binds loopback ports (proxy, two targets): run from a real shell, not the sandbox.
Exit 0 pass / 1 fail / 77 skip. Tokens are never printed.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import secrets
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, BusError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    WS_CSWSH_CLASS,
    ScanTarget,
    issues,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)
from aitm_e2e.ws import WsClient  # noqa: E402

RUN = secrets.token_hex(6)
FOREIGN_ORIGIN = "http://evil.example"


def _authority_parts(authority: str) -> tuple[str, int]:
    host, port = authority.rsplit(":", 1)
    return host, int(port)


def _login(authority: str) -> str:
    """`POST /login` with the seeded credentials; return the `session` cookie id."""
    host, port = _authority_parts(authority)
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("POST", "/login", body="user=alice&pass=wonderland",
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        setc = resp.getheader("Set-Cookie") or ""
        resp.read()
    finally:
        conn.close()
    if "session=" not in setc:
        raise RuntimeError(f"login did not set a session cookie: {setc!r}")
    return setc.split("session=", 1)[1].split(";", 1)[0]


class _WsClientWithHeaders(WsClient):
    """A `WsClient` that adds `Origin` and `Cookie` to the proxied upgrade, and keeps
    the `Sec-WebSocket-Key` it sent so the cell can compare it to the lane's dials."""

    def __init__(self, proxy_host, proxy_port, origin_host, origin_port, path="/",
                 *, cookie: str | None = None, origin: str | None = None):
        self.sent_key = base64.b64encode(os.urandom(16)).decode()
        self.sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
        self.rd = self.sock.makefile("rb")
        target = f"http://{origin_host}:{origin_port}{path}"
        lines = [
            f"GET {target} HTTP/1.1",
            f"Host: {origin_host}:{origin_port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {self.sent_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if origin is not None:
            lines.append(f"Origin: {origin}")
        if cookie is not None:
            lines.append(f"Cookie: {cookie}")
        req = "\r\n".join(lines) + "\r\n\r\n"
        self.sock.sendall(req.encode())
        status = self.rd.readline().decode().strip()
        if "101" not in status:
            raise BusError(f"ws upgrade failed: {status!r} {self.rd.read(400)!r}")
        while True:
            line = self.rd.readline()
            if line in (b"\r\n", b"\n", b""):
                break


def _authed_conversation(proxy_port: int, authority: str, cookie: str) -> str:
    """Hold one authenticated echo conversation through the proxy; return the sent key."""
    host, port = _authority_parts(authority)
    origin = f"http://{authority}"
    client = _WsClientWithHeaders("127.0.0.1", proxy_port, host, port, "/ws",
                                  cookie=f"session={cookie}", origin=origin)
    try:
        _opcode, hello = client.recv()
        try:
            user = json.loads((hello or b"").decode("utf-8")).get("user")
        except (ValueError, AttributeError):
            user = None
        check(user == "alice", f"authenticated baseline hello names the logged-in user ({user!r})")
        client.send_text(json.dumps({"type": "chat", "msg": f"auth-{RUN}"}))
        client.recv()
    finally:
        client.close()
    return client.sent_key


def _ws_handshakes_since(target: ScanTarget, seq0: int) -> list[dict]:
    return [e for e in target.logs.ws()
            if e.get("kind") == "handshake" and int(e.get("seq", 0)) > seq0]


def main() -> int:
    section("AC T4-2: CSWSH found on V (ws-cswsh, certain), not on P; key regenerated, cookie kept")
    with ScanTarget("vulnerable") as v, ScanTarget("patched") as p:
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[v.authority, p.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.issues")
            require_lane(op, "ws")

            section("V: authenticated baseline conversation, then the ws-lane job")
            v_cookie = _login(v.authority)
            v_key = _authed_conversation(core.cfg.proxy_port, v.authority, v_cookie)
            v_origin = f"http://{v.authority}"
            v_seq0 = v.logs.reset()
            v_job = start_job(op, "operator",
                              profile={"name": f"e2e-t4-cswsh-v-{RUN}",
                                       "target": {"origins": [v.base]},
                                       "lanes": ["ws"]})["job"]
            wait_terminal(op, "operator", v_job)
            v_cswsh = [i for i in issues(op, "operator", job=v_job) if i.get("class") == WS_CSWSH_CLASS]
            check(len(v_cswsh) >= 1, f"V: a {WS_CSWSH_CLASS} issue was raised ({len(v_cswsh)})")
            check(all(i.get("confidence") == "certain" for i in v_cswsh),
                  f"V: the {WS_CSWSH_CLASS} issue(s) are confidence == certain")

            section("V: the target's own handshake log proves the regenerated key + kept cookie")
            v_hs = _ws_handshakes_since(v, v_seq0)
            lane_hs = [e for e in v_hs
                       if e.get("origin") and e.get("origin") != v_origin
                       and e.get("sec_websocket_key") != v_key
                       and "session" in (e.get("cookie_names") or [])
                       and e.get("accepted") is True]
            check(len(lane_hs) >= 1,
                  "V: a lane handshake used a foreign Origin, a key != the captured one, "
                  f"kept the session cookie, and was accepted ({len(lane_hs)} of {len(v_hs)})")

            section("P: the same dial is rejected (403) and no ws-cswsh issue is raised")
            p_cookie = _login(p.authority)
            _authed_conversation(core.cfg.proxy_port, p.authority, p_cookie)
            p_origin = f"http://{p.authority}"
            p_seq0 = p.logs.reset()
            p_job = start_job(op, "operator",
                              profile={"name": f"e2e-t4-cswsh-p-{RUN}",
                                       "target": {"origins": [p.base]},
                                       "lanes": ["ws"]})["job"]
            wait_terminal(op, "operator", p_job)
            p_cswsh = [i for i in issues(op, "operator", job=p_job) if i.get("class") == WS_CSWSH_CLASS]
            check(len(p_cswsh) == 0,
                  f"P: no {WS_CSWSH_CLASS} issue (patched rejects the foreign Origin) ({len(p_cswsh)})")
            p_foreign = [e for e in _ws_handshakes_since(p, p_seq0)
                         if e.get("origin") and e.get("origin") != p_origin]
            check(len(p_foreign) >= 1, f"P: the lane attempted a foreign-origin dial ({len(p_foreign)})")
            check(all(e.get("accepted") is False and e.get("status") == 403 for e in p_foreign),
                  "P: every foreign-origin handshake was accepted == False, status == 403")
            ok("AC T4-2 proven on both targets' own WS handshake logs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
