#!/usr/bin/env python3
# e2e: tier=T1 surface=scan needs=ws
# Integration-shared edit, sanctioned by the coordinator (2026-11-01): the reflection
# issue class is T4's shipped `ws-input-reflection` (crates/aitm-scan-ws/src/checks/
# reflection.rs) and the oversize check is id+class `ws-oversize-frame`
# (checks/oversize.rs); `ws-injection` is retired.
"""AC T4-3: seeded reflected injection in the `msg` field is found on V
(`ws-input-reflection`) and not on P; `ws-oversize-frame` sends exactly one frame per WS point
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
  check (`check_id == "ws-oversize-frame"`, class `ws-oversize-frame`, severity `info`)
  contributes at most one issue per job.

SKIP 77 when: the scanner verbs are absent, or the `ws` lane has no `scan.checks`
entry on this build (the ws lane is not on `main`).

P's `/ws` requires a valid session to upgrade, so the cell logs in to P first.

Binds loopback ports (proxy, two targets): run from a real shell, not the sandbox.
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
    WS_OVERSIZE_CHECK_ID,
    WS_REFLECTION_CLASS,
    WsClientWithHeaders,
    boot_target,
    issues,
    login,
    require_lane,
    require_verbs,
    start_job,
    wait_terminal,
)
from aitm_e2e.ws import WsClient  # noqa: E402

RUN = secrets.token_hex(6)
JOB_TIMEOUT = 600.0
MSG_LEN = 200  # the `msg` field length L the cell injects


def _authority_parts(authority: str) -> tuple[str, int]:
    host, port = authority.rsplit(":", 1)
    return host, int(port)


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
    with boot_target("vulnerable") as v, boot_target("patched") as p:
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
            v_final = wait_terminal(op, "operator", v_job, timeout=JOB_TIMEOUT)
            check(v_final.get("state") == "done",
                  f"V: the ws job finished done (state={v_final.get('state')!r}, "
                  f"stopped_reason={v_final.get('stopped_reason')!r})")
            v_issues = issues(op, "operator", job=v_job)
            v_refl = [i for i in v_issues if i.get("class") == WS_REFLECTION_CLASS]
            check(len(v_refl) >= 1, f"V: a {WS_REFLECTION_CLASS} issue was raised ({len(v_refl)})")

            section("V: one lane frame at 2 x max observed per WS point (capped)")
            # T4's lane sends the oversize frame once per insertion point by
            # design (one conversation per point), so the count is the number of
            # WS points the job audited, not one per job (integration-shared cell
            # edit by T1b, 2026-11-01, on the coordinator's ruling).
            n_points = int(((v_final.get("points") or {}).get("audited")) or 0)
            check(n_points >= 1, f"V: the ws job audited {n_points} WS point(s)")
            lane_in = [f for f in v.logs.ws()
                       if f.get("kind") == "frame" and f.get("dir") == "in"
                       and int(f.get("seq", 0)) > v_seq0]
            oversize = [f for f in lane_in if int(f.get("len", 0)) == 2 * v_max]
            check(len(oversize) == n_points,
                  f"one lane in-frame per WS point has len == 2*{v_max} == {2 * v_max} "
                  f"({len(oversize)} of {len(lane_in)} lane frames; {n_points} point(s))")
            v_oversize_issues = [i for i in v_issues if i.get("check_id") == WS_OVERSIZE_CHECK_ID]
            check(1 <= len(v_oversize_issues) <= n_points,
                  f"{WS_OVERSIZE_CHECK_ID} contributes at most one issue per WS point "
                  f"({len(v_oversize_issues)} issue(s), {n_points} point(s))")

            section("P: HTML-escaped, so no ws-input-reflection")
            p_cookie = login(f"http://{p.authority}")
            phost, pport = _authority_parts(p.authority)
            pc = WsClientWithHeaders("127.0.0.1", core.cfg.proxy_port, phost, pport, "/ws",
                                     extra_headers={"Cookie": f"session={p_cookie}"})
            try:
                _echo(pc)
            finally:
                pc.close()
            p.logs.reset()
            p_job = start_job(op, "operator",
                              profile={"name": f"e2e-t4-inj-p-{RUN}",
                                       "target": {"origins": [p.base]},
                                       "lanes": ["ws"]})["job"]
            p_final = wait_terminal(op, "operator", p_job, timeout=JOB_TIMEOUT)
            check(p_final.get("state") == "done",
                  f"P: the ws job finished done (state={p_final.get('state')!r}, "
                  f"stopped_reason={p_final.get('stopped_reason')!r})")
            p_refl = [i for i in issues(op, "operator", job=p_job)
                      if i.get("class") == WS_REFLECTION_CLASS]
            check(len(p_refl) == 0,
                  f"P: no {WS_REFLECTION_CLASS} issue (reflection is escaped) ({len(p_refl)})")
            ok("AC T4-3 proven on V and P and the target's own frame log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
