#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
"""AC T4-3: seeded reflected injection in the `msg` field is found on V
(`ws-input-reflection`) and not on P; `ws-oversize-frame` sends exactly one frame
of `2 x max observed`, capped.

Real, never a fixture: a stdlib RFC 6455 client holds a real `/ws` conversation
THROUGH the aitm proxy sending `{"type":"echo","msg":<L bytes>}`, so the core
captures a client->server text frame whose `msg` is a reflection point. A
`scan.start` with `lanes: ["ws"]` then audits it.

- On V (`/ws` reflects `msg` unencoded): an issue with `class == "ws-input-reflection"`.
- On P (`/ws` HTML-escapes it): no `ws-input-reflection` issue.
- Oversize: the independent observer is the target's own frame log — among the lane's
  client->server frames (seq > the post-conversation reset), EXACTLY ONE has
  `len == 2 * max_observed`, where `max_observed` is the largest `in` frame length
  the cell itself produced (read from the log before the reset). The `ws-oversize-frame`
  check contributes at most one issue per job.

SKIP 77 when: the scanner verbs are absent, or the `ws` lane has no `scan.checks`
entry on this build (the ws lane is not on `main`).

P's `/ws` requires a valid session to upgrade, so the cell logs in to P first.

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
    ScanTarget,
    issues,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)
from aitm_e2e.ws import WsClient  # noqa: E402

RUN = secrets.token_hex(6)
MSG_LEN = 200  # the `msg` field length L the cell injects


def _authority_parts(authority: str) -> tuple[str, int]:
    host, port = authority.rsplit(":", 1)
    return host, int(port)


def _login(authority: str) -> str:
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
    """A `WsClient` that adds `Cookie` to the proxied upgrade (P requires a session)."""

    def __init__(self, proxy_host, proxy_port, origin_host, origin_port, path="/",
                 *, cookie: str | None = None):
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


def _echo(client) -> None:
    """Read the hello, send one `{"type":"echo","msg":<L bytes>}`, read the reply."""
    client.recv()  # hello
    marker = f"<b>reflect-{RUN}</b>"
    pad = "A" * max(0, MSG_LEN - len(marker))
    client.send_text(json.dumps({"type": "echo", "msg": marker + pad}))
    client.recv()


def _max_in_frame_len(target: ScanTarget) -> int:
    lens = [int(f.get("len", 0)) for f in target.logs.ws()
            if f.get("kind") == "frame" and f.get("dir") == "in"]
    if not lens:
        raise RuntimeError("no client->server frames were logged for the conversation")
    return max(lens)


def main() -> int:
    section("AC T4-3: ws-input-reflection on V not P; one ws-oversize-frame at 2x max")
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

            section("V: conversation, measure max observed in-frame, then audit")
            vhost, vport = _authority_parts(v.authority)
            vc = WsClient("127.0.0.1", core.cfg.proxy_port, vhost, vport, "/ws")
            try:
                _echo(vc)
            finally:
                vc.close()
            v_max = _max_in_frame_len(v)
            check(v_max > 0, f"V: the cell's largest client->server frame is {v_max} bytes")
            v_seq0 = v.logs.reset()
            v_job = start_job(op, "operator",
                              profile={"name": f"e2e-t4-inj-v-{RUN}",
                                       "target": {"origins": [v.base]},
                                       "lanes": ["ws"]})["job"]
            wait_terminal(op, "operator", v_job)
            v_issues = issues(op, "operator", job=v_job)
            v_refl = [i for i in v_issues if i.get("class") == "ws-input-reflection"]
            check(len(v_refl) >= 1, f"V: a ws-input-reflection issue was raised ({len(v_refl)})")

            section("V: exactly one lane frame at 2 x max observed (capped)")
            lane_in = [f for f in v.logs.ws()
                       if f.get("kind") == "frame" and f.get("dir") == "in"
                       and int(f.get("seq", 0)) > v_seq0]
            oversize = [f for f in lane_in if int(f.get("len", 0)) == 2 * v_max]
            check(len(oversize) == 1,
                  f"exactly one lane in-frame has len == 2*{v_max} == {2 * v_max} "
                  f"({len(oversize)} of {len(lane_in)} lane frames)")
            v_oversize_issues = [i for i in v_issues if "ws-oversize-frame" in (i.get("check_id") or "")]
            check(len(v_oversize_issues) <= 1,
                  f"ws-oversize-frame contributes at most one issue per job ({len(v_oversize_issues)})")

            section("P: HTML-escaped, so no ws-input-reflection")
            p_cookie = _login(p.authority)
            phost, pport = _authority_parts(p.authority)
            pc = _WsClientWithHeaders("127.0.0.1", core.cfg.proxy_port, phost, pport, "/ws",
                                      cookie=f"session={p_cookie}")
            try:
                _echo(pc)
            finally:
                pc.close()
            p.logs.reset()
            p_job = start_job(op, "operator",
                              profile={"name": f"e2e-t4-inj-p-{RUN}",
                                       "target": {"origins": [p.base]},
                                       "lanes": ["ws"]})["job"]
            wait_terminal(op, "operator", p_job)
            p_refl = [i for i in issues(op, "operator", job=p_job) if i.get("class") == "ws-input-reflection"]
            check(len(p_refl) == 0, f"P: no ws-input-reflection issue (reflection is escaped) ({len(p_refl)})")
            ok("AC T4-3 proven on V and P and the target's own frame log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
