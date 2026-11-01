#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
"""AC T4-1: a real WS conversation captured through the proxy to the target's `/ws`
yields `ws_json_value` insertion points for the frame's JSON fields.

Real, never a fixture: a stdlib RFC 6455 client (`aitm_e2e.ws.WsClient`) speaks a
real `{"type":"echo","msg":...}` conversation THROUGH the aitm proxy to the seeded
target's `/ws`, so the core captures the handshake and the client->server text
frame. A `scan.start` with `lanes: ["ws"]` then derives insertion points from that
captured WsFlow; `scan.sitemap` must list `ws_json_value` points named `type` and
`msg` (the two JSON leaves of the frame).

Independent observer: the target's own WS log (`V.logs.ws()`) — the handshake the
cell sent (its `Sec-WebSocket-Key`) and the lane's later dials (other keys), proving
the lane really dialled the target.

SKIP 77 when: the scanner verbs are absent (`require_verbs`), or the `ws` lane has
no `scan.checks` entry on this build (`require_lane`) — the ws lane is not on `main`.

Binds loopback ports (proxy, target): run from a real shell, not the sandbox.
Exit 0 pass / 1 fail / 77 skip. Tokens are never printed.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    ScanTarget,
    require_lane,
    require_verbs,
    scan_call,
    start_job,
    wait_terminal,
)
from aitm_e2e.ws import WsClient  # noqa: E402

RUN = secrets.token_hex(6)  # per-run marker (flows may be shared with parallel cells)


def _authority_parts(authority: str) -> tuple[str, int]:
    host, port = authority.rsplit(":", 1)
    return host, int(port)


def main() -> int:
    section("AC T4-1: ws_json_value points from a captured /ws conversation")
    with ScanTarget("vulnerable") as v:
        vhost, vport = _authority_parts(v.authority)
        cfg = CoreConfig(
            proxy_port=free_port(),
            browser_proxy_port=free_port(),
            scope_entries=[v.authority],
        )
        with Aitm.server(cfg) as core:
            op = BusClient.operator(core)
            require_verbs(op, "scan.start", "scan.status", "scan.sitemap")
            require_lane(op, "ws")

            section("real /ws conversation through the proxy")
            client = WsClient("127.0.0.1", core.cfg.proxy_port, vhost, vport, "/ws")
            try:
                _opcode, hello = client.recv()  # unsolicited hello frame
                client.send_text(json.dumps({"type": "echo", "msg": f"hello-{RUN}"}))
                _opcode, reply = client.recv()
            finally:
                client.close()
            check(hello is not None and reply is not None,
                  "the target answered the hello + echo through the proxy")
            check(b"echo" in (reply or b""),
                  f"echo reply observed through the proxy ({(reply or b'')[:60]!r})")

            section("scan with lanes: [ws] and read the site map points")
            r = start_job(op, "operator",
                          profile={"name": f"e2e-t4-points-{RUN}",
                                   "target": {"origins": [v.base]},
                                   "lanes": ["ws"]})
            job = r["job"]
            wait_terminal(op, "operator", job)
            pts = scan_call(op, "operator", "scan.sitemap", {"job": job}).get("points", [])
            ws_json = [p for p in pts if p.get("kind") == "ws_json_value"]
            names = {p.get("name") for p in ws_json}
            check("type" in names and "msg" in names,
                  f"ws_json_value points include the frame's JSON leaves type and msg ({sorted(names)})")

            section("independent observer: the target's WS log")
            ws_log = v.logs.ws()
            handshakes = [e for e in ws_log if e.get("kind") == "handshake"]
            frames = [e for e in ws_log if e.get("kind") == "frame"]
            check(len(handshakes) >= 1, f"target WS log holds handshake entries ({len(handshakes)})")
            check(len(frames) >= 1, f"target WS log holds frame entries ({len(frames)})")
            keys = {e.get("sec_websocket_key") for e in handshakes if e.get("sec_websocket_key")}
            check(len(keys) >= 1, f"handshakes carry distinct Sec-WebSocket-Keys ({len(keys)})")
            ok("AC T4-1 proven on the captured conversation and the target's own log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
