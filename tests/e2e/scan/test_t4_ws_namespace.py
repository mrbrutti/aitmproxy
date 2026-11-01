#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
"""AC T4-4: a Rhai command using `ws.dial/send/recv/close` round-trips a frame to the
in-scope target, is refused (`OutOfScope`) for an out-of-scope URL, and may open at
most 4 handles.

Real, never a fixture: the cell writes a human-readable `e2e-ws.rhai` into the
core's `rhai_scripts_dir`, so a real `aitm` core loads two custom commands over the
`ws` Rhai namespace. `e2e.ws_probe` dials the seeded target's `/ws` through the
scope guard, sends one echo frame, and returns the reply frames; `e2e.ws_many`
opens five handles to exercise the 4-handle cap.

- `e2e.ws_probe {url: ws://<V>/ws}` -> a result naming the echoed frame (`type` /
  `echo`), and the target's own WS log (the independent observer) shows the probe's
  handshake and frames.
- `e2e.ws_probe {url: ws://<Canary>/ws}` -> refused with `OutOfScope`; the Canary
  (an out-of-scope loopback listener) records ZERO hits — the scope guard stopped the
  dial before it left.
- `e2e.ws_many {url: ws://<V>/ws}` -> an error (the fifth dial refused) or a result
  naming the 4-handle cap; either way the target's own WS log, reset just before the
  call, shows exactly four handshakes: four dials reached the target and the fifth
  never did. (An error for any OTHER reason -- a script fault, a scope refusal -- would
  leave fewer than four handshakes and fail here instead of passing as "the cap".)

SKIP 77 when: the `ws` lane / namespace is not live on this build (`require_lane`).

Binds loopback ports (proxy, target, canary): run from a real shell, not the sandbox.
Exit 0 pass / 1 fail / 77 skip. Tokens are never printed.
"""

from __future__ import annotations

import json
import secrets
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, free_port, ok, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.scan import (  # noqa: E402
    Canary,
    boot_target,
    require_lane,
)

RUN = secrets.token_hex(6)
# The cap message must tie the number 4 to the word "handle", so a stray "4"
# anywhere in a payload cannot pass for proof of the 4-handle cap.
CAP_RE = re.compile(r"\b4\b.*handle|handle.*\b4\b", re.I)

# Human-readable ws-namespace script: one command that round-trips a frame, one that
# opens five handles to exercise the 4-handle cap. `const API = "1"` declares the
# ProtocolLanguage api_version (D8.3), matching tests/e2e/scripting/test_scripting_live.py.
E2E_WS_RHAI = r'''const API = "1";
fn load(reg) {
    reg.add_command("e2e.ws_probe", "Round-trip one echo frame", |args| {
        let h = ws.dial(#{ url: args.url });
        ws.send(h, "{\"type\":\"echo\",\"msg\":\"ping\"}");
        let r = ws.recv(h, 1500);
        ws.close(h);
        r
    });
    reg.add_command("e2e.ws_many", "Open five handles", |args| {
        let hs = [];
        for i in 0..5 {
            hs.push(ws.dial(#{ url: args.url }));
        }
        "opened five"
    });
}
'''


def main() -> int:
    work = tempfile.mkdtemp(prefix="aitm-e2e-t4-ws-")
    try:
        section("AC T4-4: ws Rhai namespace round-trips in scope, refuses out of scope, caps handles")
        with boot_target("vulnerable") as v, Canary() as canary:
            scripts_dir = Path(work) / "scripts"
            scripts_dir.mkdir()
            (scripts_dir / "e2e-ws.rhai").write_text(E2E_WS_RHAI, encoding="utf-8")
            cfg = CoreConfig(
                proxy_port=free_port(),
                browser_proxy_port=free_port(),
                scope_entries=[v.authority],  # the Canary is deliberately NOT in scope
                rhai_scripts_dir=str(scripts_dir),
            )
            with Aitm.server(cfg) as core:
                op = BusClient.operator(core)
                require_lane(op, "ws")
                check("e2e.ws_probe" in set(op.tool_names()),
                      "the ws-namespace script registered e2e.ws_probe")

                section("in-scope round-trip")
                res = op.call("e2e.ws_probe", {"url": f"ws://{v.authority}/ws"})
                blob = res if isinstance(res, str) else json.dumps(res)
                check("echo" in blob and "type" in blob,
                      f"e2e.ws_probe returned the echoed frame ({blob[:80]!r})")
                ws_log = v.logs.ws()
                check(any(e.get("kind") == "handshake" for e in ws_log)
                      and any(e.get("kind") == "frame" for e in ws_log),
                      "the target's WS log shows the probe's handshake and frames")

                section("out-of-scope dial is refused, the canary is never hit")
                status, payload = op.try_call("e2e.ws_probe", {"url": f"ws://{canary.authority}/ws"})
                check(status == "error" and "OutOfScope" in str(payload),
                      f"an out-of-scope ws.dial is refused with OutOfScope ({str(payload)[:80]!r})")
                check(canary.hits == [], f"the out-of-scope canary recorded zero hits ({len(canary.hits)})")

                section("the 4-handle cap holds")
                seq_many = v.logs.reset()  # every WS entry from here is ws_many's
                status, payload = op.try_call("e2e.ws_many", {"url": f"ws://{v.authority}/ws"})
                if status == "error":
                    check("OutOfScope" not in str(payload),
                          f"the ws_many error is not a scope refusal ({str(payload)[:80]!r})")
                    check("handle" in str(payload).lower(),
                          f"the fifth dial failed on the HANDLE cap, and the error says so "
                          f"({str(payload)[:120]!r})")
                else:
                    check(CAP_RE.search(str(payload)) is not None,
                          f"e2e.ws_many's result names the 4-handle cap ({str(payload)[:120]!r})")
                many_hs = [e for e in v.logs.ws()
                           if e.get("kind") == "handshake" and int(e.get("seq", 0)) > seq_many]
                check(len(many_hs) == 4,
                      f"the target's own log shows exactly 4 handshakes for the five dials: "
                      f"four handles opened, the fifth was refused before it left (got {len(many_hs)})")
                check(all(e.get("accepted") is True for e in many_hs),
                      f"every one of the four dials was accepted by the target "
                      f"({[e.get('status') for e in many_hs]})")
                ok("AC T4-4 proven on the target's WS log and the out-of-scope canary")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
