#!/usr/bin/env python3
# e2e: tier=T1 surface=scripting
"""Rhai scripting runs for real against live traffic, with deny-by-default guards.

Scripts load at boot from rhai.scripts_dir (no MCP needed for hooks to fire).
Independent observers: a real curl through the proxy (the request edit reaches the
seeded upstream's /admin logic; the response edit reaches the client) and the bus
result of a script-registered command. Proves on_request + on_response_headers mutate
live traffic on the wire, a ScriptCommand is operator-callable and agent-refused
(script commands default to Sensitive), and deny-by-default refuses filesystem +
out-of-scope http.send.
"""
import os
import sys
import tempfile
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))
sys.path.insert(0, str(E2E / "lib"))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from seeded import TestTarget, curl_code  # noqa: E402

# on_request mutates before upstream; on_response_headers mutates before the client
# (the response is streamed, so on_response_headers -- not the post-complete
# on_response -- is the response mutation point).
HOOK = """const NAME = "hook-proof";
const API = "1";
fn on_request(flow) {
    flow.request.headers.set("X-Role", "admin");
}
fn on_response_headers(flow) {
    flow.response.headers.set("X-Aitm-Hook", "respproof");
}
"""
CMD = """const NAME = "cmd-proof";
const API = "1";
fn load(reg) {
    reg.add_command("demo.ping", "liveness check", |args| "pong");
    reg.add_command("demo.fs", "denied: filesystem read", |args| open_file("/etc/passwd"));
    reg.add_command("demo.send", "denied: out-of-scope send", |args|
        http.send(#{ method: "GET", url: "http://evil.test/" }));
}
"""


def main() -> None:
    with TestTarget("vulnerable") as target:
        scripts_dir = tempfile.mkdtemp(prefix="aitm-e2e-rhai-")
        Path(scripts_dir, "hook-proof.rhai").write_text(HOOK)
        Path(scripts_dir, "cmd-proof.rhai").write_text(CMD)
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[target.host()],
                         rhai_scripts_dir=scripts_dir)
        with Aitm.server(cfg) as core:
            proxy = f"http://127.0.0.1:{cfg.proxy_port}"

            section("hooks mutate live traffic in both directions")
            hdr_file = os.path.join(scripts_dir, "resp-hdrs.txt")
            rc, code, body = curl_code(["-x", proxy, "-D", hdr_file, f"{target.base_url}/admin"])
            check(rc == 0 and "ADMIN-AREA-MARKER-c6f0" in body,
                  "on_request injected X-Role:admin -> the upstream granted /admin (request edit on the wire)")
            hdrs = open(hdr_file).read() if os.path.exists(hdr_file) else ""
            check("x-aitm-hook: respproof" in hdrs.lower(),
                  "on_response_headers added a header the client received (response edit on the wire)")

            section("ScriptCommand registered, callable, and gated")
            op = BusClient.operator(core)
            agent = BusClient.agent(core)
            check("demo.ping" in set(op.tool_names()), "reg.add_command registered demo.ping")
            pong = op.call("demo.ping")
            check(pong == "pong" or "pong" in str(pong), f"operator demo.ping -> pong ({pong!r})")
            status, _ = agent.try_call("demo.ping")
            check(status == "error", "agent demo.ping is refused (script commands are Sensitive)")

            section("deny-by-default guards hold")
            status, msg = op.try_call("demo.fs")
            check(status == "error" and ("open_file" in msg or "not found" in msg.lower()),
                  f"filesystem read is denied ({msg[:70]})")
            status, msg = op.try_call("demo.send")
            low = msg.lower()
            check(status == "error" and any(k in low for k in ("denied", "scope", "evil.test", "not found")),
                  f"out-of-scope http.send is denied ({msg[:90]})")

            ok("scripting hooks + ScriptCommand + deny-by-default verified")


if __name__ == "__main__":
    main()
