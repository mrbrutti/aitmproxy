#!/usr/bin/env python3
"""T1: the Rhai response-mutation contract, proven on the wire against live traffic.

Two boot-loaded scripts, path-scoped so they never collide:

  * rewrite.rhai mutates the response in on_response_headers (the response
    breakpoint, before the body streams) -> the client receives the rewritten
    body. Proves a mutation in the CORRECT hook reaches the client on the wire.

  * late.rhai tries to mutate the response in on_response (which fires AFTER the
    response has been forwarded) -> the client never sees the attempted value AND
    the attempt is reported loudly: script.list's last_error for `late` names
    on_response_headers. Proves the wrong hook is REFUSED, not a silent no-op.

on_response is observe-only by design: the response is already on the wire there.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from harness import Harness, Reporter, curl  # noqa: E402

REWRITTEN = "REWRITTEN-BY-ON-RESPONSE-HEADERS-ohdr42"
TAMPERED = "LATE-TAMPERED-SHOULD-NEVER-REACH-CLIENT"

# on_response_headers is THE response-mutation hook: it fires before the body
# streams, so replacing flow.response.body here reaches the client.
REWRITE = f"""\
const NAME = "rewrite";
const API = "1";
fn on_response_headers(flow) {{
    if flow.request.path.contains("/search") {{
        flow.response.body = "{REWRITTEN}";
    }}
}}
"""

# on_response fires post-forward: a response write here cannot reach the client.
# The setter refuses it loudly (a caught-able error naming on_response_headers),
# so the edit is dropped and the failure is recorded as the script's last_error.
LATE = f"""\
const NAME = "late";
const API = "1";
fn on_response(flow) {{
    if flow.request.path.ends_with("/") {{
        flow.response.body = "{TAMPERED}";
    }}
}}
"""


def script_last_error(op, name):
    """The `last_error` script.list reports for the named script (or None).

    script.list returns the exact machine value -- a JSON array of
    {name, path, api, hooks, enabled, last_error} objects -- so `sc` is a list.
    """
    sc, is_err, _ = op.call("script.list")
    if is_err or not isinstance(sc, list):
        return None
    for s in sc:
        if isinstance(s, dict) and s.get("name") == name:
            return s.get("last_error")
    return None


def main() -> int:
    r = Reporter("t1_on_response_contract")
    with Harness("scripting", scripts={"rewrite.rhai": REWRITE, "late.rhai": LATE}) as h:
        target = h.start_testtarget("vulnerable")
        h.scope_hosts = [target.split("://", 1)[1]]
        h.start_aitm()

        # --- correct hook: on_response_headers rewrite reaches the client ----- #
        code, http, body = curl(f"{target}/search?q=hello", proxy=h.proxy_url())
        r.check("on_response_headers_rewrite_reaches_client",
                code == 0 and http == 200 and body.strip() == REWRITTEN,
                f"exit={code} http={http} body={body[:120]!r}")

        # --- wrong hook: on_response attempt does NOT reach the client -------- #
        # Sanity check of pre-existing behaviour: the on_response edit never
        # reached the client even before this fix (that was the silent no-op), so
        # this alone does not prove the refusal -- the loud-signal check below
        # (script.list last_error) is what discriminates "refused" from "silent".
        code, http, body = curl(f"{target}/", proxy=h.proxy_url())
        r.check("on_response_attempt_not_on_the_wire",
                code == 0 and http == 200 and TAMPERED not in body,
                f"the on_response edit must not reach the client: exit={code} http={http} "
                f"body_has_tampered={TAMPERED in body}")

        # --- wrong hook: the attempt is LOUD, not a silent no-op -------------- #
        op = h.mcp("operator"); op.initialize()
        # on_response fires after the response is forwarded, so the client (curl)
        # returns before the hook runs; poll script.list for the recorded error.
        last_error = None
        deadline = time.time() + 5
        while time.time() < deadline:
            last_error = script_last_error(op, "late")
            if last_error:
                break
            time.sleep(0.1)
        r.check("on_response_refusal_is_reported_loudly",
                bool(last_error) and "on_response_headers" in last_error,
                f"script.list last_error for `late` should name the right hook: {last_error!r}")
        op.close()

    return r.finish()


if __name__ == "__main__":
    sys.exit(main())
