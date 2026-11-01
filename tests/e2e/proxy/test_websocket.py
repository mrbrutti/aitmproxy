#!/usr/bin/env python3
# e2e: tier=T1 surface=proxy
"""WebSocket through the proxy: frame capture both directions + live injection.

A real ws:// echo origin, a real RFC6455 client speaking through the aitm proxy.
  - the upgrade is proxied and both the client->server and server->client frames
    are captured on the bus;
  - ws.send s2c injects a frame delivered to the CLIENT;
  - ws.send c2s injects a frame delivered to the SERVER (proven by the server
    echoing it back AND by the server's own received-log), and injected frames are
    recorded on the flow.
"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402

import _clients as c  # noqa: E402


def msg_text(m) -> str:
    data = m.get("data")
    if isinstance(data, str):
        try:
            return base64.b64decode(data).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return data
    return ""


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def main() -> int:
    ws = c.WsEchoServer()
    core = None
    bus = None
    try:
        section("boot: real aitm + real ws:// echo origin (in scope)")
        cfg = c.ProxyConfig(
            proxy_port=free_port(),
            scope_entries=[ws.authority, "127.0.0.1"],
        )
        core = Aitm.server(cfg)
        bus = BusClient.operator(core)
        ok(f"proxy 127.0.0.1:{cfg.proxy_port}, ws origin {ws.authority}")

        section("upgrade + frames both directions")
        client = c.WsClient("127.0.0.1", cfg.proxy_port, "127.0.0.1", ws.port, "/chat")
        ok("upgrade handshake (101) proxied and handed off")
        client.send_text("hello")
        op, payload = client.recv()
        check(op == 0x1 and payload == b"echo:hello",
              f"server->client frame delivered to the client (op={op} payload={payload!r})")

        wsid = c.wait_for(lambda: c.find_flow(bus, kind="websocket"))
        check(wsid is not None, "proxy recorded a WebSocket flow")
        d = c.detail(bus, wsid)
        pairs = [(m.get("dir"), msg_text(m)) for m in (d.get("messages", []) if d else [])]
        check(("client_to_server", "hello") in pairs
              and ("server_to_client", "echo:hello") in pairs,
              f"both directions captured on the bus (pairs={pairs})")

        section("ws.send injection: delivered to client (s2c) and server (c2s)")
        bus.call("ws.send", {"id": wsid, "dir": "s2c", "opcode": "text", "data": b64("inj-s2c")})
        op, payload = client.recv()
        check(op == 0x1 and payload == b"inj-s2c",
              f"ws.send s2c reaches the CLIENT (payload={payload!r})")

        bus.call("ws.send", {"id": wsid, "dir": "c2s", "opcode": "text", "data": b64("inj-c2s")})
        op, payload = client.recv()
        check(op == 0x1 and payload == b"echo:inj-c2s",
              f"ws.send c2s reaches the SERVER, which echoes it back (payload={payload!r})")
        check("inj-c2s" in ws.received,
              f"the server's own log shows the injected payload (received={ws.received})")

        d = c.detail(bus, wsid)
        injected = [(m.get("dir"), msg_text(m)) for m in d.get("messages", []) if m.get("injected")]
        check(("server_to_client", "inj-s2c") in injected
              and ("client_to_server", "inj-c2s") in injected,
              f"both injected frames recorded on the flow (injected={injected})")
        client.close()
    finally:
        if bus:
            bus.close()
        if core:
            core.stop()
        ws.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
