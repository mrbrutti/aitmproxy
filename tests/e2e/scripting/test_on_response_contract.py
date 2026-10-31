#!/usr/bin/env python3
# e2e: tier=T1 surface=scripting
"""The Rhai response-mutation contract (PR #136), proven on the wire against live traffic.

on_response_headers is THE response-mutation hook: it fires at the response breakpoint
BEFORE the body streams, so a write there reaches the client. on_response fires AFTER the
response has been forwarded, so it is observe-only by design -- a write there cannot reach
the client and is refused LOUDLY (a catchable error naming on_response_headers), never a
silent post-forward no-op. This cell asserts BOTH halves on ground truth (a real curl
through the proxy + the seeded target's own bytes + script.list's recorded last_error):

  rewrite.rhai   on_response_headers write on /search  -> the client receives REWRITTEN
                 (a mutation in the CORRECT hook reaches the client on the wire);
  late.rhai      on_response WRITE on /                 -> the client never sees TAMPERED,
                 the response bytes are byte-identical to what the origin served (the
                 write did NOT apply post-forward), AND script.list's last_error for
                 `late` names on_response_headers (the error really fired -- loud, not
                 silent);
  observe.rhai   on_response READ-ONLY on /lookup       -> runs clean (no last_error) and
                 the response passes through downstream unchanged.

Converted from the dead tests/e2e/lib/harness.py draft onto aitm_e2e (matching
scripting/test_scripting_live.py): boots its own core with rhai.scripts_dir auto-load +
a seeded TestTarget. Exit 0 pass / 1 fail / 77 skip.
"""
import sys
import tempfile
import time
from pathlib import Path

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))
sys.path.insert(0, str(E2E / "lib"))

from aitm_e2e import check, fail, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient, ToolError  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from seeded import TestTarget, curl_code  # noqa: E402

REWRITTEN = "REWRITTEN-BY-ON-RESPONSE-HEADERS-ohdr42"
TAMPERED = "LATE-TAMPERED-SHOULD-NEVER-REACH-CLIENT"

# on_response_headers fires before the body streams, so replacing flow.response.body
# here reaches the client.
REWRITE = f"""\
const NAME = "rewrite";
const API = "1";
fn on_response_headers(flow) {{
    if flow.request.path.contains("/search") {{
        flow.response.body = "{REWRITTEN}";
    }}
}}
"""

# on_response fires post-forward: a response WRITE here cannot reach the client. The
# setter refuses it loudly (a catchable error naming on_response_headers), so the edit
# is dropped and the failure is recorded as the script's last_error.
LATE = f"""\
const NAME = "late";
const API = "1";
fn on_response(flow) {{
    if flow.request.path == "/" {{
        flow.response.body = "{TAMPERED}";
    }}
}}
"""

# on_response READ-ONLY: reading the response in the post-forward hook is allowed and
# must run clean (no last_error), leaving the response untouched downstream.
OBSERVE = """\
const NAME = "observe";
const API = "1";
fn on_response(flow) {
    if flow.request.path.contains("/lookup") {
        let _seen = flow.response.status;
    }
}
"""


def script_last_error(op, name):
    """The `last_error` script.list reports for the named script (or None). script.list
    answers a JSON array of {name, path, api, hooks, enabled, last_error} objects."""
    try:
        sc = op.call("script.list")
    except ToolError:
        return None
    if not isinstance(sc, list):
        return None
    for s in sc:
        if isinstance(s, dict) and s.get("name") == name:
            return s.get("last_error")
    return None


def body_of(args):
    """curl body only (rc + body), raising the rc into view for the caller."""
    rc, code, body = curl_code(args)
    return rc, code, body


def main() -> None:
    with TestTarget("vulnerable") as target:
        scripts_dir = tempfile.mkdtemp(prefix="aitm-e2e-rhai-")
        Path(scripts_dir, "rewrite.rhai").write_text(REWRITE)
        Path(scripts_dir, "late.rhai").write_text(LATE)
        Path(scripts_dir, "observe.rhai").write_text(OBSERVE)
        cfg = CoreConfig(proxy_port=free_port(), scope_entries=[target.host()],
                         rhai_scripts_dir=scripts_dir)
        with Aitm.server(cfg) as core:
            proxy = f"http://127.0.0.1:{cfg.proxy_port}"

            section("correct hook: on_response_headers rewrite reaches the client")
            rc, code, body = body_of(["-x", proxy, f"{target.base_url}/search?q=hello"])
            check(rc == 0 and code == 200 and body.strip() == REWRITTEN,
                  f"on_response_headers rewrite reaches the client on /search "
                  f"(rc={rc} code={code} body={body[:120]!r})")

            section("wrong hook: an on_response WRITE is refused -- not on the wire, bytes untouched")
            # the origin's own bytes for / (direct, no proxy, no scripts): the baseline.
            rcd, coded, direct = body_of([f"{target.base_url}/"])
            check(rcd == 0 and coded == 200, f"baseline: direct GET / off the origin answered 200 (rc={rcd} code={coded})")
            rc, code, body = body_of(["-x", proxy, f"{target.base_url}/"])
            check(rc == 0 and code == 200, f"GET / through the proxy answered 200 (rc={rc} code={code})")
            check(TAMPERED not in body, f"the on_response write never reached the client ({TAMPERED!r} absent)")
            check(body == direct,
                  "the response bytes are byte-identical to what the origin served (the post-forward write did NOT apply)")

            section("wrong hook: the refusal is LOUD -- script.list records the error naming on_response_headers")
            op = BusClient.operator(core)
            # on_response fires after curl has its bytes, so poll script.list for the recorded error.
            last_error = None
            deadline = time.time() + 5
            while time.time() < deadline:
                last_error = script_last_error(op, "late")
                if last_error:
                    break
                time.sleep(0.1)
            check(bool(last_error) and "on_response_headers" in str(last_error),
                  f"script.list last_error for `late` names on_response_headers -- the error really fired "
                  f"({last_error!r})")

            section("observe-only on_response: runs clean (no last_error) and the response is unchanged")
            rcd, _, direct_lookup = body_of([f"{target.base_url}/lookup?host=example.com"])
            rc, code, body = body_of(["-x", proxy, f"{target.base_url}/lookup?host=example.com"])
            check(rc == 0 and code == 200 and body == direct_lookup,
                  f"observe-only on_response left the /lookup response unchanged downstream (rc={rc} code={code})")
            # it read, never wrote: no error recorded for `observe`.
            obs_err = script_last_error(op, "observe")
            check(not obs_err, f"observe-only on_response recorded no error (last_error={obs_err!r})")
            op.close()

            ok("on_response contract verified: on_response_headers mutates, on_response write is refused loudly "
               "(bytes untouched), observe-only on_response runs clean")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        fail(f"{type(e).__name__}: {e}")
