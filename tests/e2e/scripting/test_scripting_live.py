#!/usr/bin/env python3
"""T1: Rhai scripting runs for real against live traffic, with deny-by-default guards.

Scripts are loaded at boot from rhai.scripts_dir (no MCP needed for hooks to fire).
Independent observers: a real curl response body rewritten by an on_response hook,
and the bus result of a script-registered command. Proves:
  * an on_response hook rewrites a live response the client receives;
  * a ScriptCommand (reg.add_command) is callable by an operator and REFUSED for an
    agent (script commands default to Sensitive -> operator/CLI only);
  * deny-by-default: an unregistered capability (filesystem open_file) and an
    out-of-scope http.send are both refused.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from harness import Harness, Reporter, curl  # noqa: E402

# on_request mutates the request before it goes upstream; on_response_headers
# mutates the response before it reaches the client (the response is streamed, so
# on_response_headers -- not the post-complete on_response -- is the mutation point).
HOOK = """\
const NAME = "hook-proof";
const API = "1";
fn on_request(flow) {
    flow.request.headers.set("X-Role", "admin");
}
fn on_response_headers(flow) {
    flow.response.headers.set("X-Aitm-Hook", "respproof");
}
"""

CMD = """\
const NAME = "cmd-proof";
const API = "1";
fn load(reg) {
    reg.add_command("demo.ping", "liveness check", |args| "pong");
    reg.add_command("demo.fs", "denied: filesystem read", |args| open_file("/etc/passwd"));
    reg.add_command("demo.send", "denied: out-of-scope send", |args|
        http.send(#{ method: "GET", url: "http://evil.test/" }));
}
"""


def main() -> int:
    r = Reporter("t1_scripting_live")
    with Harness("scripting", scripts={"hook-proof.rhai": HOOK, "cmd-proof.rhai": CMD}) as h:
        target = h.start_testtarget("vulnerable")
        h.scope_hosts = [target.split("://", 1)[1]]
        h.start_aitm()

        # --- hooks fire on live traffic, mutating both directions ---------- #
        # /admin returns the admin marker ONLY if the upstream saw X-Role: admin,
        # which the on_request hook injects -> proves request mutation on the wire.
        hdrs = h.root / "resp-hdrs.txt"
        code, http, body = curl(f"{target}/admin", proxy=h.proxy_url(), extra=["-D", str(hdrs)])
        r.check("hook_request_edit_reaches_upstream",
                code == 0 and "ADMIN-AREA-MARKER-c6f0" in body,
                f"exit={code} http={http} body={body[:80]!r}")
        # The on_response_headers hook adds a response header the client receives.
        hdr_text = hdrs.read_text() if hdrs.exists() else ""
        r.check("hook_response_edit_reaches_client",
                "x-aitm-hook: respproof" in hdr_text.lower(),
                f"response headers missing the hook's edit: {hdr_text[:160]!r}")

        op = h.mcp("operator"); op.initialize()
        agent = h.mcp("agent"); agent.initialize()

        # --- ScriptCommand registered + callable + gated ------------------- #
        tools = op.tools()
        r.check("script_command_registered", "demo.ping" in tools,
                f"demo.* in tools: {sorted(t for t in tools if t.startswith('demo.'))}")
        sc, is_err, text = op.call("demo.ping")
        r.check("script_command_operator", (not is_err) and (sc == "pong" or "pong" in (text or "")),
                f"isError={is_err} sc={sc!r} text={text[:80]!r}")
        sc, ag_err, ag_text = agent.call("demo.ping")
        r.check("script_command_agent_refused", ag_err,
                f"agent should be refused (script commands are Sensitive): isError={ag_err}")

        # --- deny-by-default guards ---------------------------------------- #
        sc, fs_err, fs_text = op.call("demo.fs")
        r.check("deny_filesystem", fs_err and ("open_file" in fs_text or "not found" in fs_text.lower()),
                f"filesystem read should be denied: isError={fs_err} text={fs_text[:120]!r}")
        sc, send_err, send_text = op.call("demo.send")
        low = send_text.lower()
        r.check("deny_out_of_scope_send", send_err and
                ("denied" in low or "scope" in low or "evil.test" in low or "not found" in low),
                f"out-of-scope http.send should be denied: isError={send_err} text={send_text[:160]!r}")

        op.close(); agent.close()
    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
