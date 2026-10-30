#!/usr/bin/env python3
"""WebSocket through the proxy: frame capture both directions + live injection.

A real ws:// echo origin, a real RFC6455 client speaking through the aitm proxy.
  - the upgrade is proxied and both the client->server and server->client frames
    are captured on the bus;
  - ws.send s2c injects a frame that is delivered to the CLIENT;
  - ws.send c2s injects a frame that is delivered to the SERVER (proven by the
    server echoing it back, and by the server's own received-log).
"""
import base64

import _harness as h


def msg_text(m):
    data = m.get("data")
    if isinstance(data, str):
        try:
            return base64.b64decode(data).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return data
    return ""


def main():
    ws = h.WsEchoServer()
    ws_auth = f"127.0.0.1:{ws.port}"

    with h.Rig([ws_auth]) as rig:
        try:
            client = h.WsClient("127.0.0.1", rig.proxy_port, "127.0.0.1", ws.port, "/chat")
            upgraded = True
        except Exception as e:  # noqa: BLE001
            upgraded = False
            h.check("ws: upgrade handshake (101) is proxied and handed off", False,
                    f"{e}\n{rig.log_tail(20)}")
            h.done()
            return
        h.check("ws: upgrade handshake (101) is proxied and handed off", upgraded)

        # 1. real frames both directions
        client.send_text("hello")
        op, payload = client.recv()
        h.check("ws: server->client frame is delivered to the client",
                op == 0x1 and payload == b"echo:hello", f"op={op} payload={payload!r}")

        wsid = h.wait_for(lambda: h.find_flow(rig.bus, kind="websocket"))
        h.check("ws: proxy recorded a WebSocket flow", wsid is not None, rig.log_tail(10))
        d = h.flow_detail(rig.bus, wsid) if wsid else None
        msgs = d.get("messages", []) if d else []
        pairs = [(m.get("dir"), msg_text(m)) for m in msgs]
        h.check("ws: both directions captured on the bus (client 'hello', server 'echo:hello')",
                ("client_to_server", "hello") in pairs
                and ("server_to_client", "echo:hello") in pairs,
                str(pairs)[:300])

        def b64(s):
            return base64.b64encode(s.encode()).decode()

        # 2. ws.send s2c: injected frame delivered to the client
        ok, r = rig.bus.call("ws.send", id=wsid, dir="s2c", opcode="text", data=b64("inj-s2c"))
        h.check("ws.send s2c is accepted", ok, str(r))
        op, payload = client.recv()
        h.check("ws.send s2c: the injected frame reaches the CLIENT",
                op == 0x1 and payload == b"inj-s2c", f"op={op} payload={payload!r}")

        # 3. ws.send c2s: injected frame delivered to the server (it echoes back)
        ok, r = rig.bus.call("ws.send", id=wsid, dir="c2s", opcode="text", data=b64("inj-c2s"))
        h.check("ws.send c2s is accepted", ok, str(r))
        op, payload = client.recv()
        h.check("ws.send c2s: the injected frame reaches the SERVER (echoed back to client)",
                op == 0x1 and payload == b"echo:inj-c2s", f"op={op} payload={payload!r}")
        h.check("ws.send c2s: the server's own log shows it received the injected payload",
                "inj-c2s" in ws.received, str(ws.received))

        # 4. the injected frames are captured too (injected flag set)
        d = h.flow_detail(rig.bus, wsid)
        injected = [(m.get("dir"), msg_text(m)) for m in d.get("messages", []) if m.get("injected")]
        h.check("ws: both injected frames are recorded on the flow (injected=true)",
                ("server_to_client", "inj-s2c") in injected
                and ("client_to_server", "inj-c2s") in injected,
                str(injected)[:300])

        client.close()

    ws.stop()
    h.done()


if __name__ == "__main__":
    main()
